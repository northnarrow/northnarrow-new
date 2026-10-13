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
        bpf_get_current_uid_gid, bpf_ktime_get_ns, bpf_probe_read_kernel, bpf_probe_read_user_str_bytes,
    },
    macros::{lsm, map, raw_tracepoint},
    maps::{Array, HashMap, LruHashMap, RingBuf, PerCpuArray},
    programs::{LsmContext, RawTracePointContext},
};
use northnarrow_common::ring_drops::ring_slot;
use northnarrow_common::wire::{
    BpfSyscallRaw, FsProtectDenialRaw, BPF_CMD_FOREIGN_GET_FD, BPF_CMD_FOREIGN_MAP_WRITE, FS_OP_BPF_LINK,
    FS_OP_BPF_MAP,
};

use crate::btf_offsets::{
    BPF_MAP_ID_OFFSET, FILE_F_INODE_OFFSET, INODE_I_INO_OFFSET, INODE_I_SB_OFFSET,
    MM_STRUCT_EXE_FILE_OFFSET, SUPER_BLOCK_S_DEV_OFFSET, TASK_STRUCT_MM_OFFSET,
    TASK_STRUCT_START_TIME_OFFSET,
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
pub const OWN_KIND_MAP: u8 = 1;
#[allow(dead_code)]
pub const OWN_KIND_PROG: u8 = 2;
pub const OWN_KIND_LINK: u8 = 3;

/// Fixed-width key of [`OWN_PIN_NAMES`]: the final path component of a
/// pin, NUL-padded. Our link pins are `link_<hook>` (≤ 25 bytes).
pub const PIN_NAME_LEN: usize = 32;

/// Pathname buffer for `OBJ_GET` (power of two: indexes are masked).
const PATH_BUF_LEN: usize = 256;


/// Per-CPU scratch for the `OBJ_GET` pathname. A 256-byte stack array
/// lowers to a `memset` subprogram, which the 5.15 verifier rejects (see
/// `zero.rs`); map memory needs no zeroing — only the first `n` bytes the
/// helper wrote are ever read.
#[map]
static OBJ_GET_PATH_SCRATCH: PerCpuArray<[u8; PATH_BUF_LEN]> = PerCpuArray::with_max_entries(1, 0);

/// Final path components of the agent's own LINK pins (value =
/// [`OWN_KIND_LINK`]), written by userland after the pins exist. `OBJ_GET`
/// on one of them by a foreign process is the pinned-path route to
/// `bpftool link detach`; the id route is [`OWN_BPF_IDS`]. Matching the
/// last component (not a prefix) also covers relative paths, symlinks and
/// `..` — bpffs has no hard links and the pins cannot be renamed.
#[map]
pub static OWN_PIN_NAMES: HashMap<[u8; PIN_NAME_LEN], u8> = HashMap::with_max_entries(64, 0);

/// The agent's own maps, programs and links. Key = `(kind << 32) | id`
/// ([`own_key`]): map, program and link ids are three independent kernel
/// id spaces, so the same number routinely names one map AND one program
/// AND one link — keyed by id alone, the later registration overwrote the
/// earlier and some own maps were not recognised (lab: 66 registrations,
/// 48 entries). Value = kind (kept for bpftool readability). Filled by
/// userland right after load/attach; per boot, not pinned.
#[map]
pub static OWN_BPF_IDS: HashMap<u64, u8> = HashMap::with_max_entries(256, 0);

/// Key of [`OWN_BPF_IDS`] (mirrored in userland `anti_tamper::bpf_defense`).
#[inline(always)]
pub fn own_key(kind: u8, id: u32) -> u64 {
    ((kind as u64) << 32) | id as u64
}

/// Slot 0: 1 = enforce (deny), 0 = observe.
#[map]
pub static BPF_DEFENSE_MODE: Array<u32> = Array::with_max_entries(1, 0);

/// `(dev, ino)` of the agent's own binaries, registered by userland at
/// boot, valued by role ([`ROLE_WATCHDOG`], [`ROLE_AGENT`]). External audit
/// EBPF-002: running one of them is no longer an exemption by itself —
/// root can start either binary with `LD_PRELOAD` or under `ptrace` and run
/// its own code inside. See [`fresh_instance_may_load`]. `nn-admin` is not
/// registered: it talks to the agent through its socket.
#[map]
pub static OWN_EXE_INODES: HashMap<InodeKey, u8> = HashMap::with_max_entries(8, 0);

/// Roles in [`OWN_EXE_INODES`] and slots of [`ROLE_TGIDS`] (slot = role - 1).
pub const ROLE_WATCHDOG: u8 = 1;
pub const ROLE_AGENT: u8 = 2;

/// External audit EBPF-002: the tgid of the live watchdog (slot 0) and
/// agent (slot 1), written by each once it is a protected pid, zeroed by
/// [`role_exit`] when that process exits. Pinned by name: the guard of an
/// agent that died is still attached (pinned link) when its successor
/// loads, and reads this to know the role is vacant.
#[map]
pub static ROLE_TGIDS: Array<u32> = Array::pinned(2, 0);

/// How long after its start a fresh agent or watchdog may take write
/// handles before it is a protected pid (the agent registers itself in
/// well under a second; generous for a loaded host).
const FRESH_INSTANCE_NS: u64 = 60_000_000_000;

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

/// Map, program and link ids live in three separate kernel id spaces, so
/// the kind MUST be part of the test: a foreign map whose id equals one of
/// our program ids is not ours.
#[inline(always)]
fn is_own_kind(id: u32, kind: u8) -> bool {
    unsafe { OWN_BPF_IDS.get(&own_key(kind, id)).is_some() }
}

/// `OBJ_GET` whose pathname's final component is one of the agent's own
/// LINK pins. `attr` is the kernel copy of `bpf_attr`; the first field of
/// the `OBJ_GET` variant is the user pointer to the pathname.
///
/// Verifier budget (5.15): the string is read once only to learn its
/// length `n`, then the LAST [`PIN_NAME_LEN`] bytes are read again from
/// user memory into the head of the scratch buffer — our pin names are
/// shorter than that, so a final component that is ours lies entirely in
/// the window. Every map index is then a loop counter in `0..32`: no
/// subtraction reaches a map access (`n - 32` gave "R4 min value is
/// negative" on 5.15), no 256-byte scan (minutes of verification), no
/// stack array (memset subprogram).
#[inline(always)]
unsafe fn obj_get_names_own_link(attr: *const c_void) -> bool {
    let user_ptr = match bpf_probe_read_kernel::<u64>(attr as *const u64) {
        Ok(p) => p,
        Err(_) => return false,
    };
    if user_ptr == 0 {
        return false;
    }
    let buf: *mut [u8; PATH_BUF_LEN] = match OBJ_GET_PATH_SCRATCH.get_ptr_mut(0) {
        Some(p) => p,
        None => return false,
    };
    // pass 1: length only. A path that does not fit the buffer (truncated
    // read: PATH_BUF_LEN - 1 bytes, the NUL takes the last slot) is not
    // matched: scanning PATH_MAX in chunks blew the 5.15 state budget
    // ("BPF program is too large"), and a link fd cannot detach or update
    // an LSM link anyway — this check is defence in depth behind the pin
    // protection (review entry 39).
    let n = match bpf_probe_read_user_str_bytes(user_ptr as *const u8, &mut *buf) {
        Ok(s) => s.len(),
        Err(_) => return false,
    };
    if n == 0 || n >= PATH_BUF_LEN - 1 {
        return false;
    }
    // pass 2: the last PIN_NAME_LEN bytes plus the terminator (user-pointer
    // arithmetic is a plain scalar add for the verifier)
    let win_ptr: u64 = if n > PIN_NAME_LEN {
        user_ptr + (n - PIN_NAME_LEN) as u64
    } else {
        user_ptr
    };
    let win: &mut [u8] = core::slice::from_raw_parts_mut(buf as *mut u8, PIN_NAME_LEN + 1);
    let m = match bpf_probe_read_user_str_bytes(win_ptr as *const u8, win) {
        Ok(s) => s.len(),
        Err(_) => return false,
    };
    if m == 0 || m > PIN_NAME_LEN {
        return false;
    }
    // last '/' inside the window → the final component starts after it
    let mut start: usize = 0;
    let mut j: usize = 0;
    while j < PIN_NAME_LEN {
        if j >= m {
            break;
        }
        if (*buf)[j] == b'/' {
            start = j + 1;
        }
        j += 1;
    }
    // `[0u8; 32]` would lower to a memset subprogram: zero with volatile
    // stores (see zero.rs), then fill.
    let mut key = core::mem::MaybeUninit::<[u8; PIN_NAME_LEN]>::uninit();
    let kp = key.as_mut_ptr() as *mut u8;
    let mut z: usize = 0;
    while z < PIN_NAME_LEN {
        core::ptr::write_volatile(kp.add(z), 0u8);
        z += 1;
    }
    let mut len: usize = 0;
    let mut k: usize = 0;
    while k < PIN_NAME_LEN {
        let idx = start + k;
        if idx >= m || idx >= PIN_NAME_LEN {
            break;
        }
        core::ptr::write_volatile(kp.add(k), (*buf)[idx]);
        len += 1;
        k += 1;
    }
    // empty (trailing '/') or as long as the key: not one of ours
    if len == 0 || len >= PIN_NAME_LEN {
        return false;
    }
    let key = key.assume_init();
    match OWN_PIN_NAMES.get(&key) {
        Some(kind) => *kind == OWN_KIND_LINK,
        None => false,
    }
}

/// `(dev, ino)` of the calling task's executable (`mm->exe_file`).
#[inline(always)]
pub(crate) unsafe fn caller_exe_key() -> Option<InodeKey> {
    task_exe_key(bpf_get_current_task() as *const u8)
}

/// External audit EBPF-002: `task` runs the agent's or the watchdog's
/// binary — protected from `ptrace` before it is a protected pid, so a
/// freshly started instance cannot be injected into.
#[inline(always)]
pub(crate) unsafe fn task_runs_own_binary(task: *const u8) -> bool {
    match task_exe_key(task) {
        Some(k) => OWN_EXE_INODES.get(&k).is_some(),
        None => false,
    }
}

/// `(dev, ino)` of `task`'s executable (`mm->exe_file`); `None` for a
/// kernel thread (no `mm`).
#[inline(always)]
unsafe fn task_exe_key(task: *const u8) -> Option<InodeKey> {
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
    let dev = crate::inode_dev::stat_dev(inode, sb, dev);
    let ino = bpf_probe_read_kernel::<u64>(inode.add(off!(INODE_I_INO_OFFSET)) as *const u64).ok()?;
    Some(InodeKey {
        dev: dev as u64,
        ino,
    })
}

/// Role of the calling task's executable (0: not one of ours).
#[inline(always)]
fn caller_role() -> u8 {
    match unsafe { caller_exe_key() } {
        Some(k) => unsafe { OWN_EXE_INODES.get(&k).copied().unwrap_or(0) },
        None => 0,
    }
}

/// External audit EBPF-002: a process that runs the agent's (or the
/// watchdog's) binary may take write handles on the agent's maps before
/// it is a protected pid only while no live process holds that role —
/// the successor of one that exited, which must open the pinned maps to
/// register itself — and only in its first minute. A second instance
/// started beside the live one, `LD_PRELOAD` or not, gets nothing.
///
/// Only the main thread qualifies (both binaries open the pinned maps
/// there before they register): its `start_time` is the process's, while
/// a thread created later is always "fresh" and would keep the window
/// open for as long as the process cares to spawn threads.
#[inline(always)]
fn fresh_instance_may_load() -> bool {
    let pid_tgid = bpf_get_current_pid_tgid();
    if (pid_tgid >> 32) as u32 != pid_tgid as u32 {
        return false;
    }
    let role = caller_role();
    if role != ROLE_AGENT && role != ROLE_WATCHDOG {
        return false;
    }
    let vacant = match ROLE_TGIDS.get((role - 1) as u32) {
        Some(t) => *t == 0,
        None => false,
    };
    if !vacant {
        return false;
    }
    let task = unsafe { bpf_get_current_task() } as *const u8;
    if task.is_null() {
        return false;
    }
    let start = match unsafe {
        bpf_probe_read_kernel::<u64>(task.add(off!(TASK_STRUCT_START_TIME_OFFSET)) as *const u64)
    } {
        Ok(v) => v,
        Err(_) => return false,
    };
    unsafe { bpf_ktime_get_ns() }.saturating_sub(start) < FRESH_INSTANCE_NS
}

/// `sched_process_exit` (raw tracepoint): when the group leader of the
/// live agent or watchdog exits, its role is vacant ([`ROLE_TGIDS`]). The
/// link is pinned by userland, so it keeps firing after the agent that
/// attached it has released its own objects (a clean exit drops them
/// before the process ends) or died.
#[raw_tracepoint(tracepoint = "sched_process_exit")]
pub fn role_exit(_ctx: RawTracePointContext) -> i32 {
    let pid_tgid = bpf_get_current_pid_tgid();
    let tgid = (pid_tgid >> 32) as u32;
    if tgid != pid_tgid as u32 {
        return 0; // a thread, not the process
    }
    let mut slot = 0u32;
    while slot < 2 {
        if let Some(t) = ROLE_TGIDS.get_ptr_mut(slot) {
            if unsafe { *t } == tgid {
                unsafe { *t = 0 };
            }
        }
        slot += 1;
    }
    0
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
    if !is_own_kind(id, OWN_KIND_MAP) || caller_is_protected() || fresh_instance_may_load() {
        return 0;
    }
    if enforce() {
        emit_denial(FS_OP_BPF_MAP, id);
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
    let own_map_handle = cmd == BPF_MAP_GET_FD_BY_ID && is_own_kind(arg, OWN_KIND_MAP);
    let own_link_handle = cmd == BPF_LINK_GET_FD_BY_ID && is_own_kind(arg, OWN_KIND_LINK);
    let own_link_pin = cmd == BPF_OBJ_GET && !attr.is_null() && obj_get_names_own_link(attr);
    // Second half of the self-defence: a link handle is the only thing
    // that can DETACH or UPDATE one of our LSM hooks (`bpftool link detach
    // id N` / `… pinned <path>`), so in enforce mode a foreign process
    // never gets one — by id or through the pin. Map handles are decided
    // on the write path by the `bpf_map` guard; program handles are
    // harmless and stay allowed (`bpftool prog show` keeps working).
    // External audit EBPF-002: no exemption by executable — a link handle
    // is taken only once the agent is a protected pid.
    if (own_link_handle || own_link_pin) && enforce() {
        emit_denial(FS_OP_BPF_LINK, if own_link_handle { arg } else { 0 });
        return -EPERM;
    }
    let foreign_handle = own_map_handle || own_link_handle || own_link_pin;
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
fn emit_denial(operation: u8, object_id: u32) {
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
        (*raw_ptr).target_ino = object_id as u64;
        (*raw_ptr).operation = operation;
        if let Ok(comm) = bpf_get_current_comm() {
            (*raw_ptr).attacker_comm = comm;
        }
    }
    entry.submit(0);
}
