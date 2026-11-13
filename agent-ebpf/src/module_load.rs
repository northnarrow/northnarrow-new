//! Module-load BPF-LSM hooks (BUG-034) — kernel-module / rootkit-LKM
//! detection at the load chokepoint.
//!
//! Lot 285: the two kernel module-load paths are JUDGED here, by the file
//! (`northnarrow_common::module_judge`: the verdicts, tested on the host):
//! a `finit_module` of a file the agent's trust map does not vouch for, and
//! an `init_module` of a buffer, are refused (`-EPERM`) outside a signed
//! trusted-installer window when the agent armed the deny mode; the record
//! mode lets them through and records them; until the agent filled the map
//! nothing is judged. Each load is recorded with the verdict. A third
//! program, [`module_write_observe`] (`file_open`), keeps the write history
//! of the module files in the running kernel's tree that the agent reads
//! to tell a package transaction's write from any other.
//!
//! The two load hooks:
//!
//! | Hook | Syscall | What it gives |
//! |---|---|---|
//! | `kernel_read_file` (id = READING_MODULE, or 7.0's READING_MODULE_COMPRESSED) | `finit_module(2)` (modern) | `struct file*` → **source path** + loader |
//! | `kernel_load_data` (id = LOADING_MODULE) | `init_module(2)` (legacy buffer) | loader only (no file, no path) |
//!
//! Why a load hook, not more file-watching: FIM-008 watches a `.ko`
//! appearing on disk (evaded by a `/tmp` drop) and R011 watches the
//! insmod/modprobe *exec* (evaded by a direct `finit_module(2)`). The
//! LOAD itself is the one chokepoint a rootkit cannot avoid. Each load
//! emits one [`ModuleLoadRaw`] on [`MODULE_LOAD_EVENTS`].
//!
//! STAGE 1b (this commit): the `kernel_read_file` hook resolves the
//! source `.ko` path via a bounded `d_parent` walk, and both hooks
//! capture the loader's `parent_is_kthread` (the non-forgeable R011
//! exemption signal) + `parent_comm`. The userland rule (stage 2)
//! consumes the ring; a temporary log-drain in the multiplexer surfaces
//! the resolved path for this commit's VM verification.
//!
//! ## Path capture (verifier-friendly fixed-slot scheme)
//!
//! `bpf_d_path` is avoided: it needs a BTF-typed `struct path*` arg and
//! `security_kernel_read_file` may not be on the kernel's
//! `btf_allowlist_d_path` — two ways to fail. Instead we walk
//! `file → f_path.dentry` up the `d_parent` chain on RAW pointers via
//! `bpf_probe_read_kernel` (no allowlist, no BTF-id requirement), writing
//! each component leaf→root into a FIXED 32-byte slot of `path`
//! (`MODULE_PATH_SLOTS` × `MODULE_PATH_SLOT_LEN` = 512). Fixed slot
//! offsets keep the verifier's bounds-tracking trivial — no running
//! offset. `path_len` carries the slot COUNT; userland reverses the
//! slots to rebuild the path (`/lib/modules/<rel>` legit vs `/tmp` etc.).

use aya_ebpf::{
    cty::{c_int, c_void},
    helpers::{
        bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_get_current_task,
        bpf_get_current_uid_gid, bpf_ktime_get_ns, bpf_probe_read_kernel,
        bpf_probe_read_kernel_str_bytes, generated,
    },
    macros::{lsm, map},
    maps::{Array, HashMap, LruHashMap, RingBuf},
    programs::LsmContext,
};

use northnarrow_common::module_judge::{
    conf_slot, finit_verdict, init_verdict, mode, module_file_name, read_id, reads_module_file,
    refuses, write_step, FileFacts,
    ModuleTrust, MODULE_PKG_IMAGES_MAX, MODULE_PKG_SCRIPTS_MAX, MODULE_TRUST_MAX,
    MODULE_WRITES_MAX, NAME_TAIL, WALK_HOPS,
};
use northnarrow_common::wire::{
    InodeKey, ModuleLoadRaw, MODULE_LOAD_FINIT, MODULE_LOAD_INIT, MODULE_PATH_TOO_DEEP,
    MODULE_PATH_UNREADABLE,
};

use crate::btf_offsets::{
    DENTRY_D_INODE_OFFSET, DENTRY_D_NAME_OFFSET, DENTRY_D_PARENT_OFFSET, FILE_F_INODE_OFFSET,
    FILE_F_MODE_OFFSET, FILE_F_PATH_OFFSET, INODE_I_CTIME_NSEC_OFFSET, INODE_I_CTIME_SEC_OFFSET,
    INODE_I_MODE_OFFSET, INODE_I_SIZE_OFFSET, INODE_I_UID_OFFSET, MM_STRUCT_EXE_FILE_OFFSET,
    PATH_DENTRY_OFFSET, PF_KTHREAD, QSTR_LEN_OFFSET, QSTR_NAME_OFFSET, TASK_STRUCT_COMM_OFFSET,
    TASK_STRUCT_FLAGS_OFFSET, TASK_STRUCT_MM_OFFSET, TASK_STRUCT_REAL_PARENT_OFFSET,
    TASK_STRUCT_TGID_OFFSET,
};

/// `enum kernel_load_data_id::LOADING_MODULE` (`common::module_judge::read_id`;
/// lot 303: the boot checks every id against the kernel's BTF and leaves
/// these hooks out where one differs).
const LOADING_MODULE: c_int = read_id::LOADING_MODULE as c_int;
/// `READING_KEXEC_IMAGE` / `LOADING_KEXEC_IMAGE`: the same value in both
/// enums, on every kernel the agent supports (include/linux/kernel_read_file.h).
const KEXEC_IMAGE: c_int = read_id::KEXEC_IMAGE as c_int;
/// Linux `EPERM`.
const EPERM: c_int = 1;
/// `FMODE_WRITE` / `FMODE_CREATED` (include/linux/fs.h; the latter since
/// 4.19: this open created the file).
const FMODE_WRITE: u32 = 0x2;
const FMODE_CREATED: u32 = 0x10_0000;

/// Path captured as up to 16 leaf→root components, each in a fixed
/// 32-byte slot of `ModuleLoadRaw.path` (16 × 32 = 512 = MODULE_PATH_LEN).
/// Audit `abi-modpath-1`: 8 slots dropped the `/usr/lib/modules` prefix
/// of every module nested ≥10 deep (~20% of a stock 6.8 tree).
const MODULE_PATH_SLOTS: usize = 16;
const MODULE_PATH_SLOT_LEN: usize = 32;

/// Kernel `comm` length — `ModuleLoadRaw.parent_comm` is `[u8; 16]`.
const COMM_LEN: usize = 16;

/// Module-load observations (see file-level docs for the no-pin /
/// reattach-fresh rationale). 64 KiB ≈ ~115 [`ModuleLoadRaw`] (568 B).
#[map]
pub static MODULE_LOAD_EVENTS: RingBuf = RingBuf::with_byte_size(64 * 1024, 0);

/// Lot 285: the judge's mode and the running kernel's module tree
/// (`module_judge::conf_slot`), written by the agent: zero (not judged)
/// until it filled [`MODULE_TRUST`].
#[map]
pub static MODULE_CONF: Array<u64> = Array::with_max_entries(conf_slot::SLOTS, 0);

/// Lot 285: the module files the agent vouches for, by `InodeKey`, with the
/// change time and size it verified each at.
#[map]
pub static MODULE_TRUST: HashMap<InodeKey, ModuleTrust> =
    HashMap::with_max_entries(MODULE_TRUST_MAX, 0);

/// Lot 285: the package managers' images (`InodeKey` of each executable),
/// written by the agent: a writer with one of them in its lineage, run as
/// root, writes inside a package transaction.
#[map]
pub static MODULE_PKG_IMAGES: HashMap<InodeKey, u32> =
    HashMap::with_max_entries(MODULE_PKG_IMAGES_MAX, 0);

/// Lot 285 (the coordinator's matrix): the processes whose last exec ran a
/// package manager's `#!` script by its own file — `/usr/bin/dnf`,
/// `dnf-3`, `yum`, Python programs whose image (`mm->exe_file`) is the
/// interpreter's — by thread group, with the `mm` that exec made: the
/// write history's lineage counts such a process as a package manager
/// while that image runs ([`nn_module_note_exec`], from
/// `sched_process_exec`, with the file the exec sensor's first binfmt pass
/// read). An exec of the interpreter itself (`python3 /usr/bin/dnf`) is
/// not one.
#[map]
pub static MODULE_PKG_SCRIPTS: LruHashMap<u32, u64> =
    LruHashMap::with_max_entries(MODULE_PKG_SCRIPTS_MAX, 0);

/// Lot 285: the write history of the module files in the running kernel's
/// tree and of the inodes in [`MODULE_TRUST`] (`module_judge::write_flag`).
/// An inode evicted has no history: the agent does not vouch for its
/// writes (fail closed).
#[map]
pub static MODULE_WRITES: LruHashMap<InodeKey, u32> =
    LruHashMap::with_max_entries(MODULE_WRITES_MAX, 0);

/// Lot 285: bumped at every write the history records, which the agent
/// polls to look at the tree again at once.
#[map]
pub static MODULE_WRITE_GEN: Array<u64> = Array::with_max_entries(1, 0);

#[inline(always)]
fn conf(slot: u32) -> u64 {
    match MODULE_CONF.get(slot) {
        Some(v) => *v,
        None => 0,
    }
}

#[inline(always)]
unsafe fn peek_u64(src: *const u8) -> u64 {
    let mut v = core::mem::MaybeUninit::<u64>::uninit();
    let _ = generated::bpf_probe_read_kernel(v.as_mut_ptr() as *mut c_void, 8, src as *const c_void);
    v.assume_init()
}

#[inline(always)]
unsafe fn peek_u32(src: *const u8) -> u32 {
    let mut v = core::mem::MaybeUninit::<u32>::uninit();
    let _ = generated::bpf_probe_read_kernel(v.as_mut_ptr() as *mut c_void, 4, src as *const c_void);
    v.assume_init()
}

#[inline(always)]
unsafe fn peek_u16(src: *const u8) -> u16 {
    let mut v = core::mem::MaybeUninit::<u16>::uninit();
    let _ = generated::bpf_probe_read_kernel(v.as_mut_ptr() as *mut c_void, 2, src as *const c_void);
    v.assume_init()
}

/// What the judge reads of `inode`. An offset this kernel lacks leaves a
/// value no trusted entry matches (uid `u32::MAX`, change time `i64::MIN`):
/// fail closed — the agent never arms the deny mode then.
#[inline(always)]
unsafe fn facts_of(inode: *const u8) -> FileFacts {
    let mut f = FileFacts {
        uid: u32::MAX,
        mode: 0,
        ctime_sec: i64::MIN,
        ctime_nsec: 0,
        size: -1,
    };
    if inode.is_null() {
        return f;
    }
    if let Some(o) = off_opt!(INODE_I_UID_OFFSET) {
        f.uid = peek_u32(inode.add(o & 0xffff));
    }
    f.mode = u32::from(peek_u16(inode.add(off!(INODE_I_MODE_OFFSET) & 0xffff)));
    f.size = peek_u64(inode.add(off!(INODE_I_SIZE_OFFSET) & 0xffff)) as i64;
    if let (Some(a), Some(b)) = (off_opt!(INODE_I_CTIME_SEC_OFFSET), off_opt!(INODE_I_CTIME_NSEC_OFFSET)) {
        f.ctime_sec = peek_u64(inode.add(a & 0xffff)) as i64;
        f.ctime_nsec = peek_u32(inode.add(b & 0xffff));
    }
    f
}

/// The judged file of a `finit_module` load.
struct Judged {
    verdict: u8,
    key: InodeKey,
    facts: FileFacts,
    trust_flags: u32,
}

/// Lot 285: judge the file `file` a `finit_module` reads.
#[inline(always)]
unsafe fn judge_file(file: *const u8) -> Judged {
    let m = conf(conf_slot::MODE);
    let inode = crate::open_sensor::read_ptr(file.add(off!(FILE_F_INODE_OFFSET) & 0xffff));
    let key = crate::open_sensor::key_of(inode);
    let facts = facts_of(inode);
    let entry = if inode.is_null() { None } else { MODULE_TRUST.get(&key) };
    let trust_flags = match entry {
        Some(e) => e.flags,
        None => 0,
    };
    let window = m != mode::NOT_READY && crate::inode_protect::override_active();
    Judged {
        verdict: finit_verdict(entry, &facts, window, m),
        key,
        facts,
        trust_flags,
    }
}

#[lsm(hook = "kernel_read_file")]
pub fn module_read_file_observe(ctx: LsmContext) -> i32 {
    unsafe { try_read_file(&ctx) }
}

#[inline(always)]
unsafe fn try_read_file(ctx: &LsmContext) -> i32 {
    // kernel_read_file(struct file *file, enum kernel_read_file_id id, bool contents)
    let id: c_int = ctx.arg(1);
    if id == KEXEC_IMAGE {
        return deny_kexec(id);
    }
    // Lot 303: `READING_MODULE`, or 7.0's `READING_MODULE_COMPRESSED` (a
    // `finit_module` the kernel decompresses: every `.ko.zst` kmod loads on
    // Ubuntu 26.04), judged by the file alike.
    if !reads_module_file(id as u32) {
        return 0;
    }
    let file: *const c_void = ctx.arg(0);
    let j = judge_file(file as *const u8);
    emit_module_load(MODULE_LOAD_FINIT, file, &j);
    if refuses(j.verdict) {
        -EPERM
    } else {
        0
    }
}

#[lsm(hook = "kernel_load_data")]
pub fn module_load_data_observe(ctx: LsmContext) -> i32 {
    unsafe { try_load_data(&ctx) }
}

#[inline(always)]
unsafe fn try_load_data(ctx: &LsmContext) -> i32 {
    // kernel_load_data(enum kernel_load_data_id id, bool contents)
    let id: c_int = ctx.arg(0);
    if id == KEXEC_IMAGE {
        return deny_kexec(id);
    }
    if id != LOADING_MODULE {
        return 0;
    }
    // Legacy init_module buffer load — no file, so no path and nothing to
    // trust: lot 285, refused outside a window in the deny mode.
    let m = conf(conf_slot::MODE);
    let window = m != mode::NOT_READY && crate::inode_protect::override_active();
    let j = Judged {
        verdict: init_verdict(window, m),
        key: InodeKey { dev: 0, ino: 0 },
        facts: FileFacts::default(),
        trust_flags: 0,
    };
    emit_module_load(MODULE_LOAD_INIT, core::ptr::null(), &j);
    if refuses(j.verdict) {
        -EPERM
    } else {
        0
    }
}

/// Review 82: refuse a kexec kernel image (`kexec_file_load` reads it
/// through `kernel_read_file`, `kexec_load` passes it through
/// `kernel_load_data`) unless the trusted-installer window is open. A
/// loaded image let root reboot at once into a kernel without the agent
/// (AlmaLinux 9: `kexec -l` succeeded with the agent running). The refusal
/// is an anti-tamper denial (NN-L-AT-001). kdump's crash kernel is loaded
/// at boot, before the agent starts (its unit is ordered after
/// `kdump.service`); a later reload needs the window. Lot 341: a host-wide
/// deny ([`crate::host_deny`]) — under the start's `alpha` profile (the
/// `alpha` profile) the image loads, signed "would deny".
#[inline(always)]
unsafe fn deny_kexec(id: c_int) -> i32 {
    if crate::inode_protect::override_active() {
        return 0;
    }
    let (refuse, op) = crate::host_deny::judge(northnarrow_common::wire::FS_OP_KEXEC);
    crate::inode_protect::emit_task_denial(op, id as u64, 0);
    if refuse {
        -EPERM
    } else {
        0
    }
}

/// Best-effort record of the load and its verdict. Dropped (and counted) if
/// the ring is full: the verdict never depends on the record.
#[inline(always)]
unsafe fn emit_module_load(method: u8, file: *const c_void, j: &Judged) {
    let mut entry = match MODULE_LOAD_EVENTS.reserve::<ModuleLoadRaw>(0) {
        Some(e) => e,
        None => {
            crate::drops::bump(northnarrow_common::ring_drops::ring_slot::MODULE_LOAD);
            return;
        }
    };
    let raw: *mut ModuleLoadRaw = entry.as_mut_ptr();
    // Zero the whole slot first so `_pad` + any unwritten path slots
    // stay deterministic (a `bytemuck::Pod` requirement userland-side).
    crate::zero::zero(raw);
    (*raw).timestamp_ns = bpf_ktime_get_ns();
    (*raw).loader_pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    (*raw).loader_uid = (bpf_get_current_uid_gid() & 0xFFFF_FFFF) as u32;
    (*raw).method = method;
    (*raw).verdict = j.verdict;
    (*raw).file_dev = j.key.dev;
    (*raw).file_ino = j.key.ino;
    (*raw).ctime_sec = j.facts.ctime_sec;
    (*raw).ctime_nsec = j.facts.ctime_nsec;
    (*raw).file_uid = j.facts.uid;
    (*raw).file_mode = j.facts.mode;
    (*raw).file_size = j.facts.size;
    (*raw).trust_flags = j.trust_flags;
    if let Ok(comm) = bpf_get_current_comm() {
        (*raw).loader_comm = comm;
    }
    fill_parent(raw);
    if method == MODULE_LOAD_FINIT && !file.is_null() {
        // file → f_path.dentry (the source .ko's leaf dentry).
        let dentry_slot = (file as *const u8)
            .add((off!(FILE_F_PATH_OFFSET) + off!(PATH_DENTRY_OFFSET)) & 0xffff)
            as *const *const u8;
        if let Ok(leaf) = bpf_probe_read_kernel::<*const u8>(dentry_slot) {
            if !leaf.is_null() {
                let (n, truncated, top) = walk_components(leaf, (*raw).path.as_mut_ptr());
                (*raw).path_len = n as u16;
                (*raw).path_truncated = truncated;
                // External audit PROC-005: the filesystem root the walk
                // reached, which userland maps to its mount point.
                if !top.is_null() {
                    let root = crate::open_sensor::key_of(crate::open_sensor::read_ptr(
                        top.add(off!(DENTRY_D_INODE_OFFSET)),
                    ));
                    (*raw).root_dev = root.dev;
                    (*raw).root_ino = root.ino;
                }
            }
        }
    }
    entry.submit(0);
}

/// Walk the `d_parent` chain from `leaf`, writing each component name
/// leaf→root into a FIXED 32-byte slot of `dst`. The slot offset comes
/// from a `match` on the iteration index → a constant per iteration, so
/// the verifier sees in-bounds writes into the 512-byte `path` field
/// with no running-offset reasoning. Returns `(slots written, truncated)`
/// where `truncated` is the wire's [`ModuleLoadRaw::path_truncated`]: 0 the
/// root dentry was reached, [`MODULE_PATH_TOO_DEEP`] every slot was used
/// before it (deeper than any module directory), [`MODULE_PATH_UNREADABLE`]
/// a read failed (prefix unknown). Fails SAFE — a failed probe stops the
/// walk (short/empty path, never garbage).
#[inline(always)]
unsafe fn walk_components(leaf: *const u8, dst: *mut u8) -> (usize, u8, *const u8) {
    let mut dentry = leaf;
    let mut n: usize = 0;
    let mut reached_root = false;
    let mut top: *const u8 = core::ptr::null();
    let mut failed = false;
    for i in 0..MODULE_PATH_SLOTS {
        if dentry.is_null() {
            failed = true;
            break;
        }
        let off = match i {
            0 => 0,
            1 => 32,
            2 => 64,
            3 => 96,
            4 => 128,
            5 => 160,
            6 => 192,
            7 => 224,
            8 => 256,
            9 => 288,
            10 => 320,
            11 => 352,
            12 => 384,
            13 => 416,
            14 => 448,
            15 => 480,
            _ => break,
        };
        // dentry->d_name.name (struct qstr → const u8*).
        let name_pp =
            dentry.add(off!(DENTRY_D_NAME_OFFSET) + off!(QSTR_NAME_OFFSET)) as *const *const u8;
        match bpf_probe_read_kernel::<*const u8>(name_pp) {
            Ok(name_ptr) if !name_ptr.is_null() => {
                let slot = core::slice::from_raw_parts_mut(dst.add(off), MODULE_PATH_SLOT_LEN);
                if bpf_probe_read_kernel_str_bytes(name_ptr, slot).is_err() {
                    failed = true;
                }
            }
            _ => failed = true,
        }
        n = i + 1;
        // Step to the parent; stop at the root (d_parent == self) or a
        // failed/null read. Only `d_parent == self` means "root reached";
        // a failed read counts as truncated too (prefix unknown).
        match bpf_probe_read_kernel::<*const u8>(dentry.add(off!(DENTRY_D_PARENT_OFFSET)) as *const *const u8) {
            Ok(p) if !p.is_null() && p != dentry => dentry = p,
            Ok(p) if p == dentry => {
                reached_root = true;
                top = dentry;
                break;
            }
            _ => {
                failed = true;
                break;
            }
        }
    }
    // External audit PROC-004: the two causes are told apart. Every slot
    // used without reaching the root is a path deeper than any module
    // directory — the loader chose that depth, it cannot make the load
    // unverifiable.
    let code = if failed {
        MODULE_PATH_UNREADABLE
    } else if reached_root {
        0
    } else {
        MODULE_PATH_TOO_DEEP
    };
    (n, code, if failed { core::ptr::null() } else { top })
}

/// Read the loader's real-parent `comm` + `PF_KTHREAD` flag into `raw`.
/// PF_KTHREAD is non-forgeable from userspace (kernel-set on kthread
/// creation) — the same R011 exemption signal for kernel-driven boot
/// hardware-probe loads. Fails SAFE: a failed probe leaves
/// `parent_is_kthread = 0`, which the rule treats as "userspace parent"
/// (fire path), never a silent exemption.
#[inline(always)]
unsafe fn fill_parent(raw: *mut ModuleLoadRaw) {
    let task = bpf_get_current_task() as *const u8;
    if task.is_null() {
        return;
    }
    let parent = match bpf_probe_read_kernel::<*const u8>(
        task.add(off!(TASK_STRUCT_REAL_PARENT_OFFSET)) as *const *const u8,
    ) {
        Ok(p) if !p.is_null() => p,
        _ => return,
    };
    let comm_slot = core::slice::from_raw_parts_mut((*raw).parent_comm.as_mut_ptr(), COMM_LEN);
    let _ = bpf_probe_read_kernel_str_bytes(parent.add(off!(TASK_STRUCT_COMM_OFFSET)), comm_slot);
    if let Ok(flags) =
        bpf_probe_read_kernel::<u32>(parent.add(off!(TASK_STRUCT_FLAGS_OFFSET)) as *const u32)
    {
        if flags & PF_KTHREAD != 0 {
            (*raw).parent_is_kthread = 1;
        }
    }
}

/// Lot 285: the write history of the module files in the running kernel's
/// tree. Observe only (always 0). Every write-open of a file whose name is
/// a module's ([`module_file_name`], the name's last bytes) under the tree
/// ([`MODULE_CONF`]'s root, within [`WALK_HOPS`] ancestors), and of any
/// inode in [`MODULE_TRUST`] whatever name opens it (a hard link), steps
/// its history ([`write_step`]): created inside a package transaction, or
/// not. The agent reads the history to vouch for a file changed since boot.
#[lsm(hook = "file_open")]
pub fn module_write_observe(ctx: LsmContext) -> i32 {
    unsafe { try_write_open(&ctx) };
    0
}

#[inline(always)]
unsafe fn try_write_open(ctx: &LsmContext) {
    let file: *const u8 = ctx.arg(0);
    if file.is_null() {
        return;
    }
    let fmode = peek_u32(file.add(off!(FILE_F_MODE_OFFSET) & 0xffff));
    if fmode & FMODE_WRITE == 0 {
        return;
    }
    if conf(conf_slot::TREE_DEV) == 0 {
        return;
    }
    let inode = crate::open_sensor::read_ptr(file.add(off!(FILE_F_INODE_OFFSET) & 0xffff));
    if inode.is_null() {
        return;
    }
    let key = crate::open_sensor::key_of(inode);
    if MODULE_TRUST.get(&key).is_none() {
        let dentry = crate::open_sensor::read_ptr(
            file.add((off!(FILE_F_PATH_OFFSET) + off!(PATH_DENTRY_OFFSET)) & 0xffff),
        );
        if dentry.is_null() || !module_named(dentry) || nn_module_under_tree(dentry as u64) == 0 {
            return;
        }
    }
    let pkg = nn_module_pkg_lineage(bpf_get_current_task()) != 0;
    let prev = MODULE_WRITES.get(&key).copied();
    let next = write_step(prev, fmode & FMODE_CREATED != 0, pkg);
    let _ = MODULE_WRITES.insert(&key, &next, 0);
    if let Some(g) = MODULE_WRITE_GEN.get_ptr_mut(0) {
        *g = (*g).wrapping_add(1);
    }
}

/// The dentry's name ends like a module file's: its last
/// [`NAME_TAIL`]` - 1` bytes read (with their NUL) and judged by
/// [`module_file_name`].
#[inline(always)]
unsafe fn module_named(dentry: *const u8) -> bool {
    let qstr = dentry.add(off!(DENTRY_D_NAME_OFFSET));
    let len = peek_u32(qstr.add(off!(QSTR_LEN_OFFSET))) as usize;
    let name = crate::open_sensor::read_ptr(qstr.add(off!(QSTR_NAME_OFFSET)));
    if name.is_null() {
        return false;
    }
    let start = if len > NAME_TAIL - 1 { (len - (NAME_TAIL - 1)) & 0xfff } else { 0 };
    let mut tail = [0u8; NAME_TAIL];
    if bpf_probe_read_kernel_str_bytes(name.add(start), &mut tail).is_err() {
        return false;
    }
    module_file_name(&tail)
}

/// Lot 285: 1 when the directory above `dentry` (within [`WALK_HOPS`]) is
/// the running kernel's module tree ([`MODULE_CONF`]'s root). A global
/// function: the verifier checks its loop once.
#[no_mangle]
#[inline(never)]
pub extern "C" fn nn_module_under_tree(dentry: u64) -> u64 {
    unsafe { u64::from(under_tree(dentry as *const u8)) }
}

#[inline(always)]
unsafe fn under_tree(leaf: *const u8) -> bool {
    let dev = conf(conf_slot::TREE_DEV);
    let ino = conf(conf_slot::TREE_INO);
    if dev == 0 || leaf.is_null() {
        return false;
    }
    let mut d = peek_u64(leaf.add(off!(DENTRY_D_PARENT_OFFSET))) as *const u8;
    for _ in 0..WALK_HOPS {
        if d.is_null() {
            return false;
        }
        let k = crate::open_sensor::key_of(peek_u64(d.add(off!(DENTRY_D_INODE_OFFSET))) as *const u8);
        if k.dev == dev && k.ino == ino {
            return true;
        }
        let up = peek_u64(d.add(off!(DENTRY_D_PARENT_OFFSET))) as *const u8;
        if up.is_null() || up == d {
            return false;
        }
        d = up;
    }
    false
}

/// Lot 285: 1 when the current task runs as root and it, or an ancestor
/// within [`WALK_HOPS`], runs a package manager's image
/// ([`MODULE_PKG_IMAGES`]), or a package manager's `#!` script
/// ([`MODULE_PKG_SCRIPTS`]): a write inside a package transaction, read in
/// the kernel at the write — no exit can race it. A global function.
#[no_mangle]
#[inline(never)]
pub extern "C" fn nn_module_pkg_lineage(task: u64) -> u64 {
    unsafe { u64::from(pkg_lineage(task as *const u8)) }
}

#[inline(always)]
unsafe fn pkg_lineage(task: *const u8) -> bool {
    if bpf_get_current_uid_gid() as u32 != 0 {
        return false;
    }
    let mut t = task;
    for _ in 0..WALK_HOPS {
        if t.is_null() {
            return false;
        }
        let mm = peek_u64(t.add(off!(TASK_STRUCT_MM_OFFSET))) as *const u8;
        if !mm.is_null() {
            let exe = peek_u64(mm.add(off!(MM_STRUCT_EXE_FILE_OFFSET))) as *const u8;
            if !exe.is_null() {
                let inode = peek_u64(exe.add(off!(FILE_F_INODE_OFFSET))) as *const u8;
                if !inode.is_null() {
                    let k = crate::open_sensor::key_of(inode);
                    if MODULE_PKG_IMAGES.get(&k).is_some() {
                        return true;
                    }
                }
            }
            // a package manager's `#!` script, its image the interpreter's
            let tgid = peek_u32(t.add(off!(TASK_STRUCT_TGID_OFFSET)));
            if let Some(m) = MODULE_PKG_SCRIPTS.get(&tgid) {
                if *m == mm as u64 {
                    return true;
                }
            }
        }
        let up = peek_u64(t.add(off!(TASK_STRUCT_REAL_PARENT_OFFSET))) as *const u8;
        if up.is_null() || up == t || peek_u32(up.add(off!(TASK_STRUCT_TGID_OFFSET))) <= 1 {
            return false;
        }
        t = up;
    }
    false
}

/// Lot 285 (the coordinator's matrix): after a successful exec
/// (`sched_process_exec`), `dev`/`ino` the file the exec named (the exec
/// sensor's first binfmt pass, `bprm->file`: a `#!` script's own file, not
/// its interpreter): when it is a package manager's ([`MODULE_PKG_IMAGES`],
/// the agent's `(dev, ino)` of `/usr/bin/dnf`, `dnf-3`, `yum`, …), the
/// task's thread group is noted with its new `mm` ([`MODULE_PKG_SCRIPTS`]).
/// A global function (scalars only): the verifier checks it once, on its
/// own. 1 when noted.
#[no_mangle]
#[inline(never)]
pub extern "C" fn nn_module_note_exec(task: u64, dev: u64, ino: u64) -> u64 {
    unsafe { note_exec(task as *const u8, dev, ino) }
}

#[inline(always)]
unsafe fn note_exec(task: *const u8, dev: u64, ino: u64) -> u64 {
    if task.is_null() || (dev == 0 && ino == 0) {
        return 0;
    }
    if MODULE_PKG_IMAGES.get(&InodeKey { dev, ino }).is_none() {
        return 0;
    }
    let tgid = peek_u32(task.add(off!(TASK_STRUCT_TGID_OFFSET)));
    let mm = peek_u64(task.add(off!(TASK_STRUCT_MM_OFFSET)));
    if mm == 0 {
        return 0;
    }
    let _ = MODULE_PKG_SCRIPTS.insert(&tgid, &mm, 0);
    1
}
