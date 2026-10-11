//! BPF self-defence (Tappa 10.8; external review 2026-10-10: "the BPF
//! ecosystem is both the agent's tool and the attacker's").
//!
//! Two LSM hooks, available since 5.7:
//!
//! * `bpf_map(struct bpf_map *map, fmode_t fmode)` — every time a process
//!   obtains a map handle (by id, by pinned path, by fd inheritance). If
//!   the map is one of the agent's own ([`OWN_BPF_IDS`], filled by
//!   userland after load), the caller is not a protected pid and the
//!   handle is writable: **deny** (`-EPERM`) and record an anti-tamper
//!   denial (`FS_OP_BPF_MAP`, map id in `target_ino`) in enforce mode;
//!   in observe mode allow and emit a `foreign_map_write` record. Read
//!   handles are left alone (`bpftool map dump` keeps working; the pid
//!   list is not a secret, its integrity is).
//! * `bpf(int cmd, union bpf_attr *attr, unsigned int size)` — the
//!   syscall itself, observe-only: program load, map create, attach,
//!   link create / update / detach, `*_GET_FD_BY_ID` on the agent's own
//!   object ids, pinned-object open, BTF load by any non-protected
//!   process become `BpfSyscallRaw` records (the baseline of who drives
//!   BPF on this host). Nothing is denied here in this version: legitimate
//!   tooling (systemd, container runtimes, Cilium) loads and detaches BPF
//!   programs, and a blanket deny would break the host; the rules score
//!   the shape and the operator allowlist exempts known tooling.
//!
//! Mode ([`BPF_DEFENSE_MODE`][0]): 1 = enforce, 0 = observe. Test builds
//! and `NN_BPF_DEFENSE_OBSERVE=1` run in observe mode — the lab fixtures
//! unprotect pids through `bpftool map delete`, which enforce mode denies
//! by design.

use aya_ebpf::{
    cty::{c_int, c_void},
    helpers::{
        bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_get_current_task,
        bpf_get_current_uid_gid, bpf_ktime_get_ns, bpf_probe_read_kernel,
    },
    macros::{lsm, map},
    maps::{Array, HashMap, LruHashMap, RingBuf},
    programs::LsmContext,
};
use northnarrow_common::ring_drops::ring_slot;
use northnarrow_common::wire::{
    BpfSyscallRaw, FsProtectDenialRaw, BPF_CMD_FOREIGN_GET_FD, BPF_CMD_FOREIGN_MAP_WRITE,
    FS_OP_BPF_MAP,
};

use crate::btf_offsets::{
    BPF_MAP_ID_OFFSET, FILE_F_INODE_OFFSET, INODE_I_INO_OFFSET, INODE_I_SB_OFFSET,
    MM_STRUCT_EXE_FILE_OFFSET, SUPER_BLOCK_S_DEV_OFFSET, TASK_STRUCT_MM_OFFSET,
};
use northnarrow_common::wire::InodeKey;

const EPERM: c_int = 1;
/// `FMODE_WRITE` (include/linux/fs.h).
const FMODE_WRITE: u32 = 0x2;

/// uapi `enum bpf_cmd` values the observer reports.
const BPF_MAP_CREATE: c_int = 0;
const BPF_PROG_LOAD: c_int = 5;
const BPF_OBJ_PIN: c_int = 6;
const BPF_OBJ_GET: c_int = 7;
const BPF_PROG_ATTACH: c_int = 8;
const BPF_PROG_DETACH: c_int = 9;
const BPF_PROG_GET_FD_BY_ID: c_int = 13;
const BPF_MAP_GET_FD_BY_ID: c_int = 14;
const BPF_BTF_LOAD: c_int = 18;
const BPF_LINK_CREATE: c_int = 28;
const BPF_LINK_UPDATE: c_int = 29;
const BPF_LINK_GET_FD_BY_ID: c_int = 31;
const BPF_LINK_DETACH: c_int = 34;

/// Object kinds in [`OWN_BPF_IDS`] values (written by userland: 1 = map,
/// 2 = program, 3 = link). The hooks only test membership.
#[allow(dead_code)]
pub const OWN_KIND_MAP: u8 = 1;
#[allow(dead_code)]
pub const OWN_KIND_PROG: u8 = 2;
#[allow(dead_code)]
pub const OWN_KIND_LINK: u8 = 3;

/// Ids of the agent's own maps, programs and links (value = kind). Filled
/// by userland right after load/attach; per boot, not pinned.
#[map]
pub static OWN_BPF_IDS: HashMap<u32, u8> = HashMap::with_max_entries(256, 0);

/// Slot 0: 1 = enforce (deny), 0 = observe.
#[map]
pub static BPF_DEFENSE_MODE: Array<u32> = Array::with_max_entries(1, 0);

/// `(dev, ino)` of the agent's own binaries (agent, watchdog, nn-admin),
/// registered by userland at boot. A caller running one of them is exempt
/// from the map guard even before it is a protected pid: the watchdog
/// registers itself in PROTECTED_PIDS right after start, and the binaries
/// are inode-protected so a copy elsewhere has another inode.
#[map]
pub static OWN_EXE_INODES: HashMap<InodeKey, u8> = HashMap::with_max_entries(8, 0);

/// `bpf()` observations to userland.
#[map]
pub static BPF_SYSCALL_EVENTS: RingBuf = RingBuf::with_byte_size(64 * 1024, 0);

/// Dedup of observations keyed by `(pid << 32 | cmd)`: `bpftool prog list`
/// alone issues one GET_FD_BY_ID per program and per map on the host; one
/// record per pid per command per second is plenty for the baseline.
#[repr(C)]
#[derive(Copy, Clone)]
pub struct SeenState {
    pub last_cmd: u32,
    pub _pad: u32,
    pub last_emit_ns: u64,
}

#[map]
pub static BPF_SYSCALL_SEEN: LruHashMap<u64, SeenState> = LruHashMap::with_max_entries(2048, 0);

/// Minimum interval between two records of the same command by the same pid.
const DEDUP_NS: u64 = 1_000_000_000;

/// True when `(pid, cmd)` should be reported now (first time, or more than
/// [`DEDUP_NS`] since the last record of that pair).
#[inline(always)]
fn should_report(pid: u32, cmd: u32) -> bool {
    let now = unsafe { bpf_ktime_get_ns() };
    let key = ((pid as u64) << 32) | cmd as u64;
    match BPF_SYSCALL_SEEN.get_ptr_mut(&key) {
        Some(st) => unsafe {
            let due = now.wrapping_sub((*st).last_emit_ns) >= DEDUP_NS;
            if due {
                (*st).last_emit_ns = now;
            }
            due
        },
        None => {
            let st = SeenState {
                last_cmd: cmd,
                _pad: 0,
                last_emit_ns: now,
            };
            let _ = BPF_SYSCALL_SEEN.insert(&key, &st, 0);
            true
        }
    }
}

#[inline(always)]
fn enforce() -> bool {
    match BPF_DEFENSE_MODE.get(0) {
        Some(v) => *v == 1,
        None => false,
    }
}

#[inline(always)]
fn caller_is_protected() -> bool {
    let tgid = (bpf_get_current_pid_tgid() >> 32) as u32;
    unsafe { crate::task_kill::PROTECTED_PIDS.get(&tgid).is_some() }
}

#[inline(always)]
fn is_own(id: u32) -> bool {
    unsafe { OWN_BPF_IDS.get(&id).is_some() }
}

/// `(dev, ino)` of the current task's executable (`current->mm->exe_file->f_inode`).
#[inline(always)]
unsafe fn caller_exe_key() -> Option<InodeKey> {
    let task = bpf_get_current_task() as *const u8;
    if task.is_null() {
        return None;
    }
    let mm = bpf_probe_read_kernel::<*const u8>(task.add(off!(TASK_STRUCT_MM_OFFSET)) as *const *const u8).ok()?;
    if mm.is_null() {
        return None;
    }
    let file = bpf_probe_read_kernel::<*const u8>(mm.add(off!(MM_STRUCT_EXE_FILE_OFFSET)) as *const *const u8).ok()?;
    if file.is_null() {
        return None;
    }
    let inode = bpf_probe_read_kernel::<*const u8>(file.add(off!(FILE_F_INODE_OFFSET)) as *const *const u8).ok()?;
    if inode.is_null() {
        return None;
    }
    let sb = bpf_probe_read_kernel::<*const u8>(inode.add(off!(INODE_I_SB_OFFSET)) as *const *const u8).ok()?;
    if sb.is_null() {
        return None;
    }
    let dev = bpf_probe_read_kernel::<u32>(sb.add(off!(SUPER_BLOCK_S_DEV_OFFSET)) as *const u32).ok()?;
    let ino = bpf_probe_read_kernel::<u64>(inode.add(off!(INODE_I_INO_OFFSET)) as *const u64).ok()?;
    Some(InodeKey {
        dev: dev as u64,
        ino,
    })
}

#[inline(always)]
fn caller_exe_is_own() -> bool {
    match unsafe { caller_exe_key() } {
        Some(k) => unsafe { OWN_EXE_INODES.get(&k).is_some() },
        None => false,
    }
}

#[lsm(hook = "bpf_map")]
pub fn bpf_map_guard(ctx: LsmContext) -> i32 {
    unsafe { try_bpf_map_guard(&ctx) }
}

#[inline(always)]
unsafe fn try_bpf_map_guard(ctx: &LsmContext) -> i32 {
    let map: *const c_void = ctx.arg(0);
    if map.is_null() {
        return 0;
    }
    let fmode: u32 = ctx.arg(1);
    if fmode & FMODE_WRITE == 0 {
        return 0;
    }
    let id_slot = (map as *const u8).add(off!(BPF_MAP_ID_OFFSET)) as *const u32;
    let id = match bpf_probe_read_kernel::<u32>(id_slot) {
        Ok(v) => v,
        Err(_) => return 0,
    };
    if !is_own(id) || caller_is_protected() || caller_exe_is_own() {
        return 0;
    }
    if enforce() {
        emit_denial(id);
        return -EPERM;
    }
    emit_syscall(BPF_CMD_FOREIGN_MAP_WRITE, id);
    0
}

#[lsm(hook = "bpf")]
pub fn bpf_syscall_observe(ctx: LsmContext) -> i32 {
    unsafe { try_bpf_syscall_observe(&ctx) }
}

#[inline(always)]
unsafe fn try_bpf_syscall_observe(ctx: &LsmContext) -> i32 {
    let cmd: c_int = ctx.arg(0);
    let attr: *const c_void = ctx.arg(1);
    // Only the commands worth a record; the hot ones (MAP_LOOKUP/UPDATE
    // from bpftool, OBJ_GET_INFO, PROG_RUN) are not reported.
    let interesting = matches!(
        cmd,
        BPF_MAP_CREATE
            | BPF_PROG_LOAD
            | BPF_OBJ_PIN
            | BPF_OBJ_GET
            | BPF_PROG_ATTACH
            | BPF_PROG_DETACH
            | BPF_PROG_GET_FD_BY_ID
            | BPF_MAP_GET_FD_BY_ID
            | BPF_BTF_LOAD
            | BPF_LINK_CREATE
            | BPF_LINK_UPDATE
            | BPF_LINK_GET_FD_BY_ID
            | BPF_LINK_DETACH
    );
    if !interesting || caller_is_protected() {
        return 0;
    }
    // bpf_attr is uapi-stable: the first u32 of the union is prog_type
    // (PROG_LOAD), map_type (MAP_CREATE), target_fd (PROG_ATTACH /
    // LINK_CREATE — attach_type sits at +8), start_id / prog_id / map_id /
    // link_id (*_GET_FD_BY_ID).
    let mut arg: u32 = 0;
    if !attr.is_null() {
        let off: usize = match cmd {
            BPF_PROG_ATTACH | BPF_LINK_CREATE => 8,
            _ => 0,
        };
        if let Ok(v) = bpf_probe_read_kernel::<u32>((attr as *const u8).add(off) as *const u32) {
            arg = v;
        }
    }
    // A handle to one of the agent's own MAPS or LINKS taken by id: the
    // shape of `bpftool map update id N` / `bpftool link detach id N`.
    // Program handles are not reported (`bpftool prog list` takes one per
    // program and a prog fd cannot modify the agent); the map hook decides
    // the deny on the write path.
    let foreign_handle =
        matches!(cmd, BPF_MAP_GET_FD_BY_ID | BPF_LINK_GET_FD_BY_ID) && is_own(arg);
    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    let report_cmd = if foreign_handle {
        BPF_CMD_FOREIGN_GET_FD
    } else {
        cmd as u32
    };
    if should_report(pid, report_cmd) {
        emit_syscall(report_cmd, arg);
    }
    0
}

#[inline(always)]
fn emit_syscall(cmd: u32, arg: u32) {
    let mut entry = match BPF_SYSCALL_EVENTS.reserve::<BpfSyscallRaw>(0) {
        Some(e) => e,
        None => {
            crate::drops::bump(ring_slot::BPF);
            return;
        }
    };
    let raw_ptr: *mut BpfSyscallRaw = entry.as_mut_ptr();
    unsafe {
        crate::zero::zero(raw_ptr);
        (*raw_ptr).timestamp_ns = bpf_ktime_get_ns();
        let pid_tgid = bpf_get_current_pid_tgid();
        (*raw_ptr).pid = (pid_tgid >> 32) as u32;
        (*raw_ptr).uid = (bpf_get_current_uid_gid() & 0xFFFF_FFFF) as u32;
        if let Ok(comm) = bpf_get_current_comm() {
            (*raw_ptr).comm = comm;
        }
        (*raw_ptr).cmd = cmd;
        (*raw_ptr).arg = arg;
    }
    entry.submit(0);
}

/// Anti-tamper denial record on the shared `FS_PROTECT_EVENTS` ring:
/// userland treats it like any other denial (`FS_OP_BPF_MAP`, map id in
/// `target_ino`).
#[inline(always)]
fn emit_denial(map_id: u32) {
    let mut entry = match crate::inode_protect::FS_PROTECT_EVENTS.reserve::<FsProtectDenialRaw>(0)
    {
        Some(e) => e,
        None => {
            crate::drops::bump(ring_slot::FS_PROTECT);
            return;
        }
    };
    let raw_ptr: *mut FsProtectDenialRaw = entry.as_mut_ptr();
    unsafe {
        crate::zero::zero(raw_ptr);
        (*raw_ptr).timestamp_ns = bpf_ktime_get_ns();
        let pid_tgid = bpf_get_current_pid_tgid();
        (*raw_ptr).attacker_pid = (pid_tgid >> 32) as u32;
        (*raw_ptr).attacker_uid = (bpf_get_current_uid_gid() & 0xFFFF_FFFF) as u32;
        (*raw_ptr).target_dev = 0;
        (*raw_ptr).target_ino = map_id as u64;
        (*raw_ptr).operation = FS_OP_BPF_MAP;
        if let Ok(comm) = bpf_get_current_comm() {
            (*raw_ptr).attacker_comm = comm;
        }
    }
    entry.submit(0);
}
