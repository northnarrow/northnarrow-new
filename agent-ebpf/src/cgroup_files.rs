//! Lot 273b — writes that stop the agent without a signal, refused at the
//! write-open (`file_open`) and at the write itself (`file_permission`, for
//! a descriptor opened before the inode was protected):
//!
//! * a resource file of a protected unit's cgroup or of an ancestor slice
//!   (`memory.max`, `cpu.max`, `pids.max`, …: [`northnarrow_common::cgroup_limits`])
//!   — protected by name under a directory registered with
//!   `FS_PROTECT_LIMIT_DIR`, so a file that appears later (a controller
//!   enabled after the registration) is covered too. Refused to every
//!   caller outside the agent's family but PID 1; PID 1 (systemd realising
//!   the unit, `systemctl set-property`) may put back the value the file
//!   held at the registration ([`LIMIT_VALUES`], or the kernel's default
//!   for a file that appeared later), read from the `write(2)` that
//!   carries it;
//! * a cgroup v1 hierarchy, on a host whose systemd runs the unified one
//!   only ([`CGROUP_POLICY`]): a root could mount the v1 `freezer`, move the
//!   agent there through the v1 `cgroup.procs` (which checks no inode the
//!   move guard sees) and freeze it;
//! * a protected process's `oom_score_adj` / `oom_adj`: `1000` makes it the
//!   OOM killer's first choice, whose SIGKILL no `task_kill` hook sees.
//!
//! * (lot 280b) the switches that blind the sensors outside the sysctls:
//!   `/sys/kernel/debug/kprobes/enabled` (debugfs: 0 disarms every kprobe)
//!   and `/sys/kernel/security/lockdown` (securityfs: a raise to
//!   `confidentiality` takes the kernel-memory helpers from the BPF
//!   programs loaded after it) — every write refused, found by the
//!   filesystem and the names ([`refuse_switch`]).
//!
//! Outside a signed trusted-installer window only, like every deny.

use aya_ebpf::{
    cty::c_void,
    helpers::{bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_probe_read_kernel, generated},
    macros::map,
    maps::{Array, HashMap},
};
use northnarrow_common::cgroup_limits::{
    default_value, init_write_lets_through, limit_kind, regs_are_the_writes, special_fs,
    strip_newline, switch_file_op, sysctl_kind, word_mask, LimitValue, SpecialFs, LIMIT_NAME_MAX,
    LIMIT_NONE, LIMIT_TEXT_MAX, SYSCTL_NONE,
};
use northnarrow_common::sysctl_judge::{record_dev, sysctl_write_verdict, SysctlVerdict};
use northnarrow_common::wire::{
    InodeKey, CGROUP_POLICY_V1_REFUSE, FS_OP_CGROUP_LIMIT, FS_OP_CGROUP_V1, FS_OP_OOM_ADJ,
    FS_OP_SYSCTL, FS_OP_SYSCTL_OPT_OUT, FS_PROTECT_LIMIT_DIR,
};

use crate::btf_offsets::{
    DENTRY_D_INODE_OFFSET, DENTRY_D_NAME_OFFSET, DENTRY_D_PARENT_OFFSET, FILE_F_PATH_OFFSET,
    CGROUP_ROOT_OFFSET, CGROUP_ROOT_SUBSYS_MASK_OFFSET, INODE_I_PRIVATE_OFFSET, INODE_I_SB_OFFSET,
    KERNFS_NODE_ID_OFFSET, KERNFS_NODE_NAME_OFFSET, KERNFS_NODE_PARENT_OFFSET,
    KERNFS_NODE_PRIV_OFFSET, KERNFS_ROOT_KN_OFFSET, KERNFS_SUPER_INFO_ROOT_OFFSET,
    PATH_DENTRY_OFFSET, SUPER_BLOCK_S_FS_INFO_OFFSET, PID_TASKS_OFFSET, PROC_INODE_PID_OFFSET,
    PROC_INODE_VFS_INODE_OFFSET, PT_REGS_DX_OFFSET, PT_REGS_ORIG_AX_OFFSET, PT_REGS_SI_OFFSET,
    QSTR_LEN_OFFSET, QSTR_NAME_OFFSET, SUPER_BLOCK_S_MAGIC_OFFSET, TASK_STRUCT_FLAGS_OFFSET,
    TASK_STRUCT_PID_LINKS_OFFSET, TASK_STRUCT_TGID_OFFSET,
};

/// The value each protected resource file held when the agent registered
/// its cgroup (`northnarrow_common::cgroup_limits::limit_value`): the one
/// write PID 1 may make. A file without an entry has the kernel's default
/// for its kind. Pinned by name, like `PROTECTED_INODES`.
#[map]
pub static LIMIT_VALUES: HashMap<InodeKey, LimitValue> = HashMap::pinned(512, 0);

/// `[0]`: `CGROUP_POLICY_*` bits written by the agent at its attach
/// (`CGROUP_POLICY_V1_REFUSE`). Pinned by name.
#[map]
pub static CGROUP_POLICY: Array<u32> = Array::pinned(1, 0);

/// Where the write is judged: at the open (`file_open`) or at a write
/// (`file_permission`).
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Phase {
    Open,
    Write,
}

/// `__NR_write` and `__NR_pwrite64` on x86-64: the calls whose buffer and
/// count are the second and third arguments.
const NR_WRITE: u64 = 1;
const NR_PWRITE64: u64 = 18;

/// `true` when the write of `file` (whose inode is `inode`) must be
/// refused; the refusal is signed here. `hook` is the caller's
/// `DENY_FAIL_OPEN` slot.
#[inline(always)]
pub(crate) unsafe fn refuse_write(
    file: *const c_void,
    inode: *const c_void,
    hook: u32,
    phase: Phase,
) -> bool {
    if inode.is_null() {
        return false;
    }
    let sb = match bpf_probe_read_kernel::<*const c_void>(
        (inode as *const u8).add(off!(INODE_I_SB_OFFSET)) as *const *const c_void,
    ) {
        Ok(p) if !p.is_null() => p,
        _ => {
            crate::fail_open::bump(hook);
            return false;
        }
    };
    let magic = match bpf_probe_read_kernel::<u64>(
        (sb as *const u8).add(off!(SUPER_BLOCK_S_MAGIC_OFFSET)) as *const u64,
    ) {
        Ok(m) => m,
        Err(_) => {
            crate::fail_open::bump(hook);
            return false;
        }
    };
    // the classification is the shared module's (the host's tests judge it)
    match special_fs(magic) {
        Some(SpecialFs::Cgroup2) => refuse_limit(file, inode, hook, phase),
        Some(SpecialFs::CgroupV1) => refuse_v1(inode, hook, phase),
        Some(SpecialFs::Proc) => {
            refuse_sysctl(file, inode, hook, phase) || refuse_oom_adj(file, inode, phase)
        }
        Some(fs @ (SpecialFs::Debugfs | SpecialFs::Securityfs)) => refuse_switch(file, inode, fs, phase),
        None => false,
    }
}

/// Lot 280b: a write of `kprobes/enabled` on debugfs or of `lockdown` on
/// securityfs (`northnarrow_common::cgroup_limits::switch_file_op`, by the
/// file's name and its directory's), refused outside the agent's family
/// and a window whatever it carries — at the write-open and at the write
/// (a descriptor opened inside a window). The decision needs no read
/// beyond the names: an inode that cannot be read is signed as `0:0`, and
/// refused all the same (fail closed); a name that cannot be read is no
/// switch's.
#[inline(always)]
unsafe fn refuse_switch(file: *const c_void, inode: *const c_void, fs: SpecialFs, phase: Phase) -> bool {
    let Some(dentry) = file_dentry(file) else {
        return false;
    };
    let Some(name) = dentry_name_words(dentry) else {
        return false;
    };
    let parent = match bpf_probe_read_kernel::<*const c_void>(
        (dentry as *const u8).add(off!(DENTRY_D_PARENT_OFFSET)) as *const *const c_void,
    ) {
        Ok(p) if !p.is_null() => dentry_name_words(p).unwrap_or((0, [0; 3])),
        _ => (0, [0; 3]),
    };
    let op = switch_file_op(fs, name, parent);
    if op == 0 {
        return false;
    }
    if caller_may((bpf_get_current_pid_tgid() >> 32) as u32) {
        return false;
    }
    let key = crate::inode_protect::read_inode_key(inode).unwrap_or(InodeKey { dev: 0, ino: 0 });
    // Lot 341: a host-wide deny (`crate::host_deny`)
    let (refuse, op) = crate::host_deny::judge(op);
    sign(phase, op, key);
    refuse
}

/// The dentry of `file` (`file->f_path.dentry`).
#[inline(always)]
unsafe fn file_dentry(file: *const c_void) -> Option<*const c_void> {
    let p = bpf_probe_read_kernel::<*const c_void>(
        (file as *const u8).add(off!(FILE_F_PATH_OFFSET) + off!(PATH_DENTRY_OFFSET))
            as *const *const c_void,
    )
    .ok()?;
    (!p.is_null()).then_some(p)
}

/// The name of `dentry` as [`northnarrow_common::cgroup_limits::name_words`]
/// packs it: `(len, words)`, `None` for a name longer than
/// [`LIMIT_NAME_MAX`] or one that cannot be read.
#[inline(always)]
unsafe fn dentry_name_words(dentry: *const c_void) -> Option<(usize, [u64; 3])> {
    let qstr = (dentry as *const u8).add(off!(DENTRY_D_NAME_OFFSET));
    let len = bpf_probe_read_kernel::<u32>(qstr.add(off!(QSTR_LEN_OFFSET)) as *const u32).ok()?
        as usize;
    if len == 0 || len > LIMIT_NAME_MAX {
        return None;
    }
    let name = bpf_probe_read_kernel::<*const u8>(qstr.add(off!(QSTR_NAME_OFFSET)) as *const *const u8)
        .ok()?;
    if name.is_null() {
        return None;
    }
    // A short name lives in the dentry's inline array, whose size is larger
    // than the three words read: the bytes past the name are cleared.
    let raw = bpf_probe_read_kernel::<[u64; 3]>(name as *const [u64; 3]).ok()?;
    Some((
        len,
        [
            raw[0] & word_mask(len, 0),
            raw[1] & word_mask(len, 1),
            raw[2] & word_mask(len, 2),
        ],
    ))
}

/// The caller outside the agent's family and outside a window: the only
/// one a refusal is for.
#[inline(always)]
fn caller_may(caller: u32) -> bool {
    crate::task_kill::is_exempt_pid(caller) || crate::inode_protect::override_active()
}

/// The review of #490 (B): what the kernfs node behind a cgroup v2
/// `inode` says of it — its name, packed as [`dentry_name_words`] packs a
/// dentry's, and its directory's inode number (`kernfs_ino()`: the
/// parent node's `id`). A handle-opened file (`open_by_handle_at` after
/// its dentry was dropped) has a disconnected dentry, named `/` and its own
/// parent; its node has neither changed.
enum Node {
    /// `(len, words, the directory's inode number)`.
    Read(usize, [u64; 3], u64),
    /// A name the resource files cannot have (empty, longer than
    /// [`LIMIT_NAME_MAX`]).
    NotALimit,
    /// The kernel's BTF lacks one of the optional offsets: the dentry is
    /// read instead (a signed degradation).
    NoOffsets,
    /// A pointer could not be read: a counted fail-open.
    Unreadable,
}

#[inline(always)]
unsafe fn kernfs_node_of(inode: *const c_void) -> Node {
    let (Some(private), Some(name_off), Some(parent_off), Some(id_off)) = (
        off_opt!(INODE_I_PRIVATE_OFFSET),
        off_opt!(KERNFS_NODE_NAME_OFFSET),
        off_opt!(KERNFS_NODE_PARENT_OFFSET),
        off_opt!(KERNFS_NODE_ID_OFFSET),
    ) else {
        return Node::NoOffsets;
    };
    let kn = match bpf_probe_read_kernel::<*const u8>((inode as *const u8).add(private) as *const *const u8) {
        Ok(p) if !p.is_null() => p,
        _ => return Node::Unreadable,
    };
    let name = match bpf_probe_read_kernel::<*const u8>(kn.add(name_off) as *const *const u8) {
        Ok(p) if !p.is_null() => p,
        _ => return Node::Unreadable,
    };
    // Up to its NUL into three zeroed words (never past the string): the
    // words `northnarrow_common::cgroup_limits::name_words` packs.
    let mut w = [0u64; 3];
    let n = generated::bpf_probe_read_kernel_str(w.as_mut_ptr() as *mut c_void, 24, name as *const c_void);
    if n <= 1 {
        return Node::NotALimit;
    }
    let len = (n - 1) as usize;
    if len > LIMIT_NAME_MAX {
        return Node::NotALimit;
    }
    let parent = match bpf_probe_read_kernel::<*const u8>(kn.add(parent_off) as *const *const u8) {
        Ok(p) if !p.is_null() => p,
        _ => return Node::Unreadable,
    };
    match bpf_probe_read_kernel::<u64>(parent.add(id_off) as *const u64) {
        Ok(id) => Node::Read(len, w, id),
        Err(_) => Node::Unreadable,
    }
}

/// The kind and the directory's key of the resource file `file` from its
/// dentry — where the kernel's BTF lacks the kernfs offsets (a file opened
/// through a handle goes through then: a signed degradation). `None`: not
/// a resource file's name, or unreadable (counted as a fail-open).
#[inline(always)]
unsafe fn dentry_name_and_dir(file: *const c_void, hook: u32) -> Option<(u8, InodeKey)> {
    let dentry = file_dentry(file)?;
    let (len, words) = dentry_name_words(dentry)?;
    let kind = limit_kind(len, words);
    if kind == LIMIT_NONE {
        return None;
    }
    let parent = match bpf_probe_read_kernel::<*const c_void>(
        (dentry as *const u8).add(off!(DENTRY_D_PARENT_OFFSET)) as *const *const c_void,
    ) {
        Ok(p) if !p.is_null() => p,
        _ => {
            crate::fail_open::bump(hook);
            return None;
        }
    };
    let dir = match bpf_probe_read_kernel::<*const c_void>(
        (parent as *const u8).add(off!(DENTRY_D_INODE_OFFSET)) as *const *const c_void,
    ) {
        Ok(p) if !p.is_null() => p,
        _ => {
            crate::fail_open::bump(hook);
            return None;
        }
    };
    let Some(dir_key) = crate::inode_protect::read_inode_key(dir) else {
        crate::fail_open::bump(hook);
        return None;
    };
    Some((kind, dir_key))
}

/// A resource file of a protected cgroup: [`refuse_write`]'s cgroup v2
/// half. The file is one when its inode holds a registered value
/// ([`LIMIT_VALUES`]), or when its kernfs node's name is a resource file's
/// and its parent node's directory is registered with
/// `FS_PROTECT_LIMIT_DIR` — the node, not the dentry, which a file opened
/// through a handle may have disconnected (the review of #490, B).
#[inline(always)]
unsafe fn refuse_limit(file: *const c_void, inode: *const c_void, hook: u32, phase: Phase) -> bool {
    let Some(key) = crate::inode_protect::read_inode_key(inode) else {
        crate::fail_open::bump(hook);
        return false;
    };
    let registered = LIMIT_VALUES.get(&key).copied();
    let (kind, dir_key) = match kernfs_node_of(inode) {
        Node::Read(len, words, dir_ino) => (
            limit_kind(len, words),
            InodeKey {
                dev: key.dev,
                ino: dir_ino,
            },
        ),
        Node::NotALimit => (LIMIT_NONE, InodeKey { dev: 0, ino: 0 }),
        Node::NoOffsets => match dentry_name_and_dir(file, hook) {
            Some(found) => found,
            None => (LIMIT_NONE, InodeKey { dev: 0, ino: 0 }),
        },
        Node::Unreadable => {
            crate::fail_open::bump(hook);
            (LIMIT_NONE, InodeKey { dev: 0, ino: 0 })
        }
    };
    if registered.is_none() {
        if kind == LIMIT_NONE {
            return false;
        }
        // Its directory: a protected unit's or slice's?
        match crate::inode_protect::PROTECTED_INODES.get(&dir_key) {
            Some(f) if *f & FS_PROTECT_LIMIT_DIR != 0 => {}
            _ => return false,
        }
    }
    let caller = (bpf_get_current_pid_tgid() >> 32) as u32;
    if caller_may(caller) {
        return false;
    }
    if caller == 1 {
        // systemd realising the unit or applying a `set-property`: the
        // open is let through, the value judged at the write.
        if phase == Phase::Open {
            return false;
        }
        let expected = match registered {
            Some(v) => Some(v),
            None => default_value(kind),
        };
        // the decision is the shared module's (the host's tests judge it)
        if init_write_lets_through(expected, written_value()) {
            return false;
        }
    }
    sign(phase, FS_OP_CGROUP_LIMIT, key);
    true
}

/// The bytes the current `write(2)` / `pwrite64(2)` carries, zero past
/// its count (as `northnarrow_common::cgroup_limits::limit_value` packs a
/// text); `None` when they cannot be read — another call, more than
/// `LIMIT_TEXT_MAX` bytes, another architecture: PID 1's write is then
/// refused.
#[inline(always)]
pub(crate) unsafe fn written_value() -> Option<LimitValue> {
    written_bytes().map(|(v, n)| strip_newline(v, n as usize))
}

/// [`written_value`]'s bytes and count, the newline kept.
#[inline(always)]
unsafe fn written_bytes() -> Option<(LimitValue, u32)> {
    let si = off_opt!(PT_REGS_SI_OFFSET)?;
    let dx = off_opt!(PT_REGS_DX_OFFSET)?;
    let ax = off_opt!(PT_REGS_ORIG_AX_OFFSET)?;
    if si > 0xff || dx > 0xff || ax > 0xff {
        return None;
    }
    let task = generated::bpf_get_current_task_btf();
    // the review of #497 (D2): an io-wq worker carries another write's
    // registers, a kernel thread has none of its own — unread (refused)
    let flags = bpf_probe_read_kernel::<u32>(
        (task as *const u8).add(off!(TASK_STRUCT_FLAGS_OFFSET)) as *const u32,
    )
    .ok()?;
    if !regs_are_the_writes(flags) {
        return None;
    }
    let regs = generated::bpf_task_pt_regs(task) as *const u8;
    if regs.is_null() {
        return None;
    }
    let nr = bpf_probe_read_kernel::<u64>(regs.add(ax) as *const u64).ok()?;
    if nr != NR_WRITE && nr != NR_PWRITE64 {
        return None;
    }
    let buf = bpf_probe_read_kernel::<u64>(regs.add(si) as *const u64).ok()?;
    let count = bpf_probe_read_kernel::<u64>(regs.add(dx) as *const u64).ok()?;
    // A value and systemd's newline: at most LIMIT_TEXT_MAX + 1 bytes.
    if count == 0 || count > LIMIT_TEXT_MAX as u64 + 1 {
        return None;
    }
    let mut value: LimitValue = [0u64; 4];
    // Bounded for the verifier: 1 to 32 bytes into the 32 of `value`.
    let n = (count as u32) & 63;
    if n == 0 || n > 32 {
        return None;
    }
    if generated::bpf_probe_read_user(value.as_mut_ptr() as *mut c_void, n, buf as *const c_void)
        != 0
    {
        return None;
    }
    Some((value, n))
}

/// Lot 273c (the review of #490): whether the cgroup v1 hierarchy of
/// `inode` binds a controller — `sb->s_fs_info` (kernfs) → `root` → `kn` →
/// `priv` (its root cgroup) → `root` → `subsys_mask`. A named hierarchy
/// (`name=systemd`, an old container's systemd on a v2 host) binds none:
/// it can move and freeze nothing. `None` without the optional offsets or
/// on a read that fails: the write is judged as a controller's then.
#[inline(always)]
unsafe fn v1_binds_a_controller(inode: *const c_void) -> Option<bool> {
    let fs_info = off_opt!(SUPER_BLOCK_S_FS_INFO_OFFSET)?;
    let si_root = off_opt!(KERNFS_SUPER_INFO_ROOT_OFFSET)?;
    let root_kn = off_opt!(KERNFS_ROOT_KN_OFFSET)?;
    let kn_priv = off_opt!(KERNFS_NODE_PRIV_OFFSET)?;
    let cg_root = off_opt!(CGROUP_ROOT_OFFSET)?;
    let mask_off = off_opt!(CGROUP_ROOT_SUBSYS_MASK_OFFSET)?;
    let sb = bpf_probe_read_kernel::<*const u8>((inode as *const u8).add(off!(INODE_I_SB_OFFSET)) as *const *const u8).ok()?;
    let p = |base: *const u8, off: usize| -> Option<*const u8> {
        if base.is_null() {
            return None;
        }
        let v = bpf_probe_read_kernel::<*const u8>(base.add(off) as *const *const u8).ok()?;
        (!v.is_null()).then_some(v)
    };
    let info = p(sb, fs_info)?;
    let kroot = p(info, si_root)?;
    let kn = p(kroot, root_kn)?;
    let cgrp = p(kn, kn_priv)?;
    let root = p(cgrp, cg_root)?;
    let mask = bpf_probe_read_kernel::<u32>(root.add(mask_off) as *const u32).ok()?;
    Some(mask != 0)
}

/// Lot 273c: the v1 files that move a process (`cgroup.procs`, `tasks`)
/// or freeze it (`freezer.state`), by the kernfs node's name; `None`
/// without the node's offsets or when the name cannot be read.
#[inline(always)]
unsafe fn v1_moves_or_freezes(inode: *const c_void) -> Option<bool> {
    let private = off_opt!(INODE_I_PRIVATE_OFFSET)?;
    let name_off = off_opt!(KERNFS_NODE_NAME_OFFSET)?;
    let kn = bpf_probe_read_kernel::<*const u8>((inode as *const u8).add(private) as *const *const u8).ok()?;
    if kn.is_null() {
        return None;
    }
    let name = bpf_probe_read_kernel::<*const u8>(kn.add(name_off) as *const *const u8).ok()?;
    if name.is_null() {
        return None;
    }
    let mut w = [0u64; 3];
    let n = generated::bpf_probe_read_kernel_str(w.as_mut_ptr() as *mut c_void, 24, name as *const c_void);
    if n <= 1 {
        return None;
    }
    const PROCS: [u64; 3] = northnarrow_common::cgroup_limits::name_words(b"cgroup.procs");
    const TASKS: [u64; 3] = northnarrow_common::cgroup_limits::name_words(b"tasks");
    const FREEZER: [u64; 3] = northnarrow_common::cgroup_limits::name_words(b"freezer.state");
    let is = |x: [u64; 3]| w[0] == x[0] && w[1] == x[1] && w[2] == x[2];
    Some(is(PROCS) || is(TASKS) || is(FREEZER))
}

/// A cgroup v1 hierarchy: [`refuse_write`]'s v1 half. Lot 273c (the review
/// of #490): refused only where it can move or freeze a process — a
/// hierarchy that binds a controller, its `cgroup.procs`, `tasks` and
/// `freezer.state`; a named hierarchy and the other files are let through
/// (both judged as refusable when the kernel's BTF lacks what tells them).
#[inline(always)]
unsafe fn refuse_v1(inode: *const c_void, hook: u32, phase: Phase) -> bool {
    match CGROUP_POLICY.get(0) {
        Some(p) if *p & CGROUP_POLICY_V1_REFUSE != 0 => {}
        _ => return false,
    }
    let caller = (bpf_get_current_pid_tgid() >> 32) as u32;
    if caller_may(caller) {
        return false;
    }
    if v1_binds_a_controller(inode) == Some(false) {
        return false;
    }
    if v1_moves_or_freezes(inode) == Some(false) {
        return false;
    }
    let Some(key) = crate::inode_protect::read_inode_key(inode) else {
        crate::fail_open::bump(hook);
        return false;
    };
    // Lot 341: a host-wide deny (`crate::host_deny`)
    let (refuse, op) = crate::host_deny::judge(FS_OP_CGROUP_V1);
    sign(phase, op, key);
    refuse
}

/// Lot 273d (the review of #492): a write of a guarded global sysctl
/// (`/proc/sys/vm/overcommit_*`, `max_map_count`, `kernel/pid_max`,
/// `threads-max`, `sched_rt_runtime_us`, and `kernel/ftrace_enabled` — R1
/// of the external review of 04/11: 0 silences the BPF trampolines, these
/// programs' own among them, on 6.0 to 7.2; by name: no other procfs file
/// is named so) is refused outside a window when its value aborts or
/// starves the agent, and `ftrace_enabled` whatever it carries (unread:
/// nothing for a second thread to race) — the verdict is the shared
/// module's (`sysctl_write_refused`), for the seven others
/// (`sysctl_write_harmful`), judged on the bytes the write carries; an
/// unread write is refused. The open is let through (judged at the
/// write); a value that harms nothing (a raised limit, overcommit 0 or 1)
/// goes through: the operator's tuning stays possible, every tuning inside
/// a window. Lot 280a: and a value the signed per-sysctl opt-out allows
/// (`crate::sysctl_guard::SYSCTL_OPTOUT`, `sysctl_write_verdict`); what
/// this lets through is judged again on the kernel's copy by
/// `crate::sysctl_guard` where that program is attached (a second thread
/// may have changed the bytes read here).
#[inline(always)]
unsafe fn refuse_sysctl(file: *const c_void, inode: *const c_void, hook: u32, phase: Phase) -> bool {
    if phase == Phase::Open {
        return false;
    }
    let Some(dentry) = file_dentry(file) else {
        return false;
    };
    let Some((len, words)) = dentry_name_words(dentry) else {
        return false;
    };
    let kind = sysctl_kind(len, words);
    if kind == SYSCTL_NONE {
        return false;
    }
    let caller = (bpf_get_current_pid_tgid() >> 32) as u32;
    // the shared verdict: the caller's identity first (the agent's own
    // restore, a window), then `ftrace_enabled` refused unread, the
    // others by the bytes the write carries — lot 280a: and the signed
    // opt-out's range let through (the RT period's bytes read only when a
    // range names it)
    let (verdict, v) = sysctl_write_verdict(
        kind,
        caller_may(caller),
        crate::sysctl_guard::opt_out(kind),
        || written_value(),
    );
    match verdict {
        SysctlVerdict::Allow => return false,
        // the opt-out's write recorded once: by the cgroup/sysctl program,
        // on the kernel's copy, when this boot attached it; else here (an
        // opted-out write is one whose value was read)
        SysctlVerdict::OptedOut => {
            if !crate::sysctl_guard::kernel_judge_attached() {
                crate::inode_protect::emit_sysctl_record(
                    FS_OP_SYSCTL_OPT_OUT,
                    InodeKey {
                        dev: record_dev(kind, true),
                        ino: v as u64,
                    },
                    caller,
                    bpf_get_current_comm().unwrap_or([0u8; 16]),
                    false,
                );
            }
            return false;
        }
        SysctlVerdict::Refuse => {}
    }
    // Lot 341: a host-wide deny (`crate::host_deny`). Let through under the
    // observe-only gate, its "would deny" signed once: by the cgroup/sysctl
    // program, on the kernel's copy, when this boot attached it (as an
    // opt-out's write); else here.
    let (refuse, op) = crate::host_deny::judge(FS_OP_SYSCTL);
    if !refuse && crate::sysctl_guard::kernel_judge_attached() {
        return false;
    }
    let Some(key) = crate::inode_protect::read_inode_key(inode) else {
        crate::fail_open::bump(hook);
        return false;
    };
    sign(phase, op, key);
    refuse
}

/// `oom_score_adj` / `oom_adj` of a protected process: [`refuse_write`]'s
/// procfs half. Not armed without the proc offsets (the agent signs that
/// degradation); a read that fails is not a fail-open of the hook: the
/// file is then no protected process's.
#[inline(always)]
unsafe fn refuse_oom_adj(file: *const c_void, inode: *const c_void, phase: Phase) -> bool {
    let Some(dentry) = file_dentry(file) else {
        return false;
    };
    let Some((len, words)) = dentry_name_words(dentry) else {
        return false;
    };
    // "oom_score_adj" (13 bytes) or "oom_adj" (7).
    const OOM_SCORE_ADJ: [u64; 3] = northnarrow_common::cgroup_limits::name_words(b"oom_score_adj");
    const OOM_ADJ: [u64; 3] = northnarrow_common::cgroup_limits::name_words(b"oom_adj");
    let named = (len == 13 && words[0] == OOM_SCORE_ADJ[0] && words[1] == OOM_SCORE_ADJ[1])
        || (len == 7 && words[0] == OOM_ADJ[0]);
    if !named {
        return false;
    }
    let Some(tgid) = proc_file_tgid(inode) else {
        return false;
    };
    if !crate::task_kill::is_protected_pid(tgid) {
        return false;
    }
    let caller = (bpf_get_current_pid_tgid() >> 32) as u32;
    if caller_may(caller) {
        return false;
    }
    let _ = phase;
    crate::inode_protect::emit_task_denial(FS_OP_OOM_ADJ, 0, tgid);
    true
}

/// The tgid of the process a `/proc/<pid>/…` (or `/proc/<pid>/task/<tid>/…`)
/// file belongs to: `proc_inode->pid`'s task, and that task's tgid.
#[inline(always)]
unsafe fn proc_file_tgid(inode: *const c_void) -> Option<u32> {
    let vfs = off_opt!(PROC_INODE_VFS_INODE_OFFSET)?;
    let pid_off = off_opt!(PROC_INODE_PID_OFFSET)?;
    let tasks = off_opt!(PID_TASKS_OFFSET)?;
    let links = off_opt!(TASK_STRUCT_PID_LINKS_OFFSET)?;
    // Bounded, as `inode_dev::stat_dev` explains: the verifier refuses an
    // unbounded offset on a BTF-typed pointer.
    if vfs > 0xffff || pid_off > 0xffff || links > 0xffff {
        return None;
    }
    let proc_inode = (inode as *const u8).wrapping_sub(vfs);
    let pid = bpf_probe_read_kernel::<*const u8>(proc_inode.wrapping_add(pid_off) as *const *const u8)
        .ok()?;
    if pid.is_null() {
        return None;
    }
    // `pid->tasks[PIDTYPE_PID].first`: the task's `pid_links[PIDTYPE_PID]`.
    let node = bpf_probe_read_kernel::<*const u8>(pid.add(tasks) as *const *const u8).ok()?;
    if node.is_null() {
        return None;
    }
    let task = node.wrapping_sub(links);
    bpf_probe_read_kernel::<u32>(task.add(off!(TASK_STRUCT_TGID_OFFSET)) as *const u32).ok()
}

/// Sign a refusal: at the open once per attempt, at a write rate-limited
/// per caller (a loop of writes on one descriptor is one record a second).
#[inline(always)]
fn sign(phase: Phase, operation: u8, key: InodeKey) {
    match phase {
        // Lot 341: a "would deny" refuses nothing — its open and its writes
        // go on: one record a caller and operation a second (the dedup)
        Phase::Open if northnarrow_common::wire::is_would_deny(operation) => {
            crate::inode_protect::emit_limited(operation, key)
        }
        // Lot 293 (BUG37): behind the attempt budget.
        Phase::Open => crate::inode_protect::emit_attempt(operation, key),
        Phase::Write => crate::inode_protect::emit_limited(operation, key),
    }
}
