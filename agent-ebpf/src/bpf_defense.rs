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
//!   syscall itself: program load, map create, attach, link create /
//!   update / detach, `*_GET_FD_BY_ID` on the agent's own object ids,
//!   pinned-object open, BTF load by any non-protected process become
//!   `BpfSyscallRaw` records (the baseline of who drives BPF on this
//!   host; the commands are `northnarrow_common::bpf_cmd::observed`, the
//!   numbers that crate's only copy, lab PR 215). Third-party BPF is not
//!   denied: legitimate tooling (systemd, container runtimes, Cilium)
//!   loads and detaches BPF programs, and a blanket deny would break the
//!   host; the rules score the shape and the operator allowlist exempts
//!   known tooling. In enforce mode this hook refuses a handle on one of
//!   the agent's own LINKS (by id, `LINK_GET_FD_BY_ID`, or through a pin,
//!   `OBJ_GET`) and a `LINK_DETACH` / `LINK_UPDATE` of one of them. The
//!   enumeration (`*_GET_NEXT_ID`) gives no handle and is let through.
//!
//!   Lot 280b: and an attach of a `cgroup/sysctl` program to the ROOT
//!   cgroup (`PROG_ATTACH` / `LINK_CREATE`, the target descriptor the
//!   cgroup v2 root) outside a trusted-installer window — after the
//!   agent's sysctl judge it would run after it and could rewrite the value
//!   judged; a target that cannot be read is refused too (that attach type
//!   only: fail closed).
//!
//!   Lot 290: foreign BPF. Outside a trusted-installer window, a caller
//!   outside the family (and not a fresh instance of ours) gets `EPERM` on
//!   a `BPF_PROG_LOAD` of a type that can rewrite user memory, override a
//!   kernel function's return, signal a process or replace a hook
//!   (`northnarrow_common::bpf_prog_class::denied_by_default`: kprobe,
//!   tracing, LSM, extension, struct_ops) unless the signed per-loader
//!   opt-out names its executable and the type ([`BPF_LOADER_OPTOUT`]);
//!   on a handle on one of the agent's maps or programs by id
//!   (`*_GET_FD_BY_ID`) and on `BPF_OBJ_GET` of a path under the agent's
//!   pin directories (`/sys/fs/bpf/northnarrow*`). The two attach and load
//!   refusals (this one and lot 280b's root `cgroup/sysctl` attach) hold in
//!   every mode — the observe mode relaxes only the guard of the agent's
//!   own objects, which the lab's fixtures reach with `bpftool`. A load the
//!   hook lets through marks its thread ([`crate::bpf_census`]) so the
//!   `bpf_prog` hook records the new program's id: the cross-view's "seen".
//! * `bpf_prog(struct bpf_prog *prog)` (lot 290) — every program handle
//!   (the load's own, by id, through any path): a handle on one of the
//!   agent's programs outside a window refused (enforce mode); the
//!   program a load just made recorded as seen.
//! * `bpf_map` (lot 290): a READ handle on one of the agent's maps is
//!   refused outside a window too (enforce mode) — a program cannot be
//!   loaded against a map it cannot get a descriptor of (lot 281's
//!   residual); a write handle stays refused in a window as before.
//!
//! A read either hook needs that fails is a fail-open, counted in
//! `DENY_FAIL_OPEN` (`crate::fail_open`, lab PR 215).
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
    macros::{kprobe, lsm, map, raw_tracepoint},
    maps::{Array, HashMap, LruHashMap, RingBuf},
    programs::{LsmContext, ProbeContext, RawTracePointContext},
};
use northnarrow_common::bpf_cmd::{
    attach_target_offset, judges_attach_target, observed, BPF_LINK_CREATE, BPF_LINK_DETACH,
    BPF_LINK_GET_FD_BY_ID, BPF_LINK_UPDATE, BPF_MAP_GET_FD_BY_ID, BPF_OBJ_GET, BPF_PROG_ATTACH,
    BPF_PROG_GET_FD_BY_ID, BPF_PROG_LOAD, BPF_RAW_TRACEPOINT_OPEN,
};
use northnarrow_common::bpf_prog_class::{
    call_key, denied_by_default, judged_for_every_type, opt_out_refuses_attach, type_bit,
    CALIB_MAX_INSNS, CALIB_NONE, CALL_TARGETS, CONTENT_CALL, CONTENT_CONF_SLOTS,
    CONTENT_EVERY_TYPE_SLOT, CONTENT_FMOD_RET, CONTENT_LOCKDOWN_SLOT, CONTENT_MAX_INSNS,
    CONTENT_STAGE_HANDLE, CONTENT_STAGE_LOAD, CONTENT_STAGE_OFF, CONTENT_UNJUDGED, INSN_CALL,
    PROG_LOAD_ATTACH_TYPE_OFFSET,
};
use northnarrow_common::cgroup_limits::{special_fs, SpecialFs};
use northnarrow_common::fail_open::hook as fail_open_hook;
use northnarrow_common::ring_drops::ring_slot;
use northnarrow_common::wire::exe::TaskKey;
use northnarrow_common::wire::{
    BpfSyscallRaw, BPF_CMD_FOREIGN_GET_FD, BPF_CMD_FOREIGN_MAP_WRITE, FS_OP_BPF_HANDLE,
    FS_OP_BPF_LINK, FS_OP_BPF_MAP, FS_OP_BPF_PROG_OPT_OUT, FS_OP_BPF_PROG_TYPE, FS_OP_SYSCTL_ROOT_ATTACH,
};

use crate::btf_offsets::{
    BPF_LINK_ID_OFFSET, BPF_MAP_ID_OFFSET, BPF_PROG_AUX_ID_OFFSET, BPF_PROG_AUX_OFFSET,
    BPF_PROG_INSNSI_OFFSET, BPF_PROG_LEN_OFFSET, BPF_PROG_TYPE_OFFSET, FDTABLE_FD_OFFSET, FDTABLE_MAX_FDS_OFFSET,
    FILES_STRUCT_FDT_OFFSET, FILE_F_INODE_OFFSET, FILE_PRIVATE_DATA_OFFSET, INODE_I_INO_OFFSET,
    INODE_I_SB_OFFSET, MM_STRUCT_EXE_FILE_OFFSET, SUPER_BLOCK_S_DEV_OFFSET, SUPER_BLOCK_S_MAGIC_OFFSET,
    TASK_STRUCT_FILES_OFFSET, TASK_STRUCT_MM_OFFSET, TASK_STRUCT_START_TIME_OFFSET,
};
use northnarrow_common::wire::{InodeKey, PIN_NAME_HASH_PRIME, PIN_NAME_HASH_SEED};

const EPERM: c_int = 1;
/// `FMODE_WRITE` (include/linux/fs.h).
const FMODE_WRITE: u32 = 0x2;

// The uapi `enum bpf_cmd` numbers come from `northnarrow_common::bpf_cmd`
// (lab PR 215): the copy here had `BPF_LINK_GET_FD_BY_ID = 31`, which is
// `BPF_LINK_GET_NEXT_ID` — handles by id on the agent's links were granted
// unrecorded, and `bpftool link list`'s enumeration was refused.

/// Object kinds in [`OWN_BPF_IDS`] values (written by userland: 1 = map,
/// 2 = program, 3 = link). The hooks only test membership.
pub const OWN_KIND_MAP: u8 = 1;
pub const OWN_KIND_PROG: u8 = 2;
pub const OWN_KIND_LINK: u8 = 3;

/// The window of an `OBJ_GET` path read for its final component: our link
/// pins are `link_<hook>` (≤ 25 bytes).
pub const PIN_NAME_LEN: usize = 32;

/// Pathname buffer for `OBJ_GET` (power of two: indexes are masked).
const PATH_BUF_LEN: usize = 256;


/// The `OBJ_GET` pathname's buffer: the calling task's own entry, made and
/// removed by [`nn_obj_get_own_link`]. A 256-byte stack array lowers to a
/// `memset` subprogram, which the 5.15 verifier rejects (see `zero.rs`).
/// Lot 322: it was a per-CPU buffer, read twice around helper calls by a
/// program that runs preemptible (`crate::task_scratch`): another task's
/// `OBJ_GET` on the same CPU could rewrite the name between the reads.
#[map]
static OBJ_GET_PATH_SCRATCH: HashMap<TaskKey, [u8; PATH_BUF_LEN]> =
    HashMap::with_max_entries(crate::task_scratch::TASK_SCRATCH_CAP, 0);

/// Final path components of the agent's own LINK pins, hashed
/// (`northnarrow_common::wire::pin_name_hash`; value = [`OWN_KIND_LINK`]),
/// written by userland after the pins exist. `OBJ_GET` on one of them by a
/// foreign process is the pinned-path route to a link handle; the id route
/// is [`OWN_BPF_IDS`]. Matching the last component (not a prefix) covers
/// relative paths and `..`; a symlink with another name does not match —
/// external audit EBPF-010: what a link handle could do (detach, update) is
/// denied by the link it names in `try_bpf_syscall_observe`.
#[map]
pub static OWN_PIN_NAMES: HashMap<u64, u8> = HashMap::with_max_entries(64, 0);

/// The agent's own maps, programs and links. Key = `(kind << 32) | id`
/// ([`own_key`]): map, program and link ids are three independent kernel
/// id spaces, so the same number routinely names one map AND one program
/// AND one link — keyed by id alone, the later registration overwrote the
/// earlier and some own maps were not recognised (lab: 66 registrations,
/// 48 entries). Value = kind (kept for bpftool readability). Filled by
/// userland right after load/attach; per boot, not pinned. Lot 290: 1024
/// entries — the object's maps, programs and links were within ten of the
/// 256 it had (the lab's first start of this lot: `E2BIG` at the 257th, the
/// start refused); `xtask/tests/foreign_bpf.rs` keeps it at twice the
/// object's maps and programs.
#[map]
pub static OWN_BPF_IDS: HashMap<u64, u8> = HashMap::with_max_entries(OWN_IDS_CAPACITY, 0);

/// [`OWN_BPF_IDS`]' capacity.
pub const OWN_IDS_CAPACITY: u32 = 1024;

/// Key of [`OWN_BPF_IDS`] (mirrored in userland `anti_tamper::bpf_defense`).
#[inline(always)]
pub fn own_key(kind: u8, id: u32) -> u64 {
    ((kind as u64) << 32) | id as u64
}

/// Lot 290: the signed per-loader opt-out (`bpf-loader-allow`): the
/// `(dev, ino)` of a loader's executable → the mask of the refused types
/// it may load outside a window (`bpf_prog_class::type_bit`). Written by
/// the agent from a policy whose signature it verified, at its start and
/// when a signed policy is set; pinned by name so the policy's writer
/// reaches it through the pin root.
#[map]
pub static BPF_LOADER_OPTOUT: HashMap<InodeKey, u32> = HashMap::pinned(64, 0);

/// Slot 0: 1 = enforce (deny), 0 = observe.
#[map]
pub static BPF_DEFENSE_MODE: Array<u32> = Array::with_max_entries(1, 0);

/// Lot 345 (the re-check of #550, point 1 (ii)): the content judge's
/// configuration, written by the agent for the running kernel and frozen
/// before the guard is attached — slot 0 the stage
/// (`bpf_prog_class::CONTENT_STAGE_*`: 0 none, 1 at `bpf_prog_load`, 2 at
/// `bpf_prog`), slots 1 to 9 the call targets
/// (`bpf_prog_class::CALL_TARGETS`), then the lockdown reason
/// (`CONTENT_LOCKDOWN_SLOT`) and the count of kfunc targets read in a load
/// of every type (`CONTENT_EVERY_TYPE_SLOT`, the review of #553).
#[map]
pub static PROG_CONTENT_CONF: Array<u32> = Array::with_max_entries(CONTENT_CONF_SLOTS, 0);

/// Lot 345: the calibration the agent asks while it loads one of its
/// calibration programs (`bpf_prog_class::CALIB_*`; 0 none), before 6.9.
#[map]
pub static PROG_CONTENT_CALIB: Array<u32> = Array::with_max_entries(1, 0);

/// Lot 345: what [`nn_calibrate`] read of a calibration program — by
/// instruction, a helper call's `imm`, 0 for any other instruction. The
/// agent zeroes it before each calibration and reads it after.
#[map]
pub static PROG_CONTENT_SEEN: Array<u32> = Array::with_max_entries(CALIB_MAX_INSNS, 0);

/// Lot 345 (the CI of #553: 5.15 processed 950,584 instructions for the
/// `bpf_prog` hook with seven compares an instruction): the call keys of
/// the judge's targets (`bpf_prog_class::target_key`) → their slot plus
/// one, written by the agent with the configuration and frozen. One lookup
/// an instruction.
#[map]
pub static PROG_CONTENT_KEYS: HashMap<u64, u32> = HashMap::with_max_entries(CALL_TARGETS as u32, 0);

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

/// The caller is the agent or the watchdog (R14a: exempt; a worker is
/// not, and gets none of the agent's BPF objects).
#[inline(always)]
fn caller_is_exempt() -> bool {
    let tgid = (bpf_get_current_pid_tgid() >> 32) as u32;
    crate::task_kill::is_exempt_pid(tgid)
}

/// Map, program and link ids live in three separate kernel id spaces, so
/// the kind MUST be part of the test: a foreign map whose id equals one of
/// our program ids is not ours.
#[inline(always)]
fn is_own_kind(id: u32, kind: u8) -> bool {
    unsafe { OWN_BPF_IDS.get(&own_key(kind, id)).is_some() }
}

/// The agent's pin root (`DEFAULT_BPFFS_ROOT` in userland), with the
/// trailing slash: a truncated `OBJ_GET` path under it counts as ours.
const PIN_ROOT: &[u8; 24] = b"/sys/fs/bpf/northnarrow/";

/// Lot 290: the prefix every pin directory of the agent's shares — the pin
/// root and the directories kept beside it (`northnarrow-cgroup-join-v*`,
/// `northnarrow-sysctl`, `northnarrow-module-writes`). `BPF_OBJ_GET` of a
/// path that starts with it is refused to a foreign caller outside a
/// window. A path that reaches a pin otherwise (relative, `..`, a symlink,
/// a bind mount of the bpffs) is judged on the object it opens: the
/// `bpf_map` and `bpf_prog` hooks refuse a handle on the agent's maps and
/// programs, the link-name match below the agent's link pins.
const PIN_DIRS_PREFIX: &[u8; 23] = b"/sys/fs/bpf/northnarrow";

/// [`nn_link_id_of_fd`]: the fd names no link here (out of range,
/// closed, not a link) — the kernel refuses the command itself.
const LINK_NONE: u64 = u64::MAX;
/// [`nn_link_id_of_fd`]: the link could not be read (an optional offset
/// absent on this kernel, a failed read) — the hook cannot decide (lab PR
/// 215: a fail-open, counted).
const LINK_UNREADABLE: u64 = u64::MAX - 1;

/// [`link_id_of_fd`] as a global BPF function (exported, never inlined,
/// scalar argument): the verifier checks it once, on its own, and the hook
/// sees one unknown return value — the link id, [`LINK_NONE`] or
/// [`LINK_UNREADABLE`]. Inlined, its six optional offsets multiplied the
/// hook's states.
#[no_mangle]
#[inline(never)]
pub extern "C" fn nn_link_id_of_fd(fd: u64) -> u64 {
    match unsafe { link_id_of_fd(fd as u32) } {
        Ok(Some(id)) => u64::from(id),
        Ok(None) => LINK_NONE,
        Err(()) => LINK_UNREADABLE,
    }
}

/// External audit EBPF-010: the id of the BPF link `fd` names in the
/// caller's file table (`task->files->fdt->fd[fd]->private_data`).
/// `Ok(None)`: the fd is out of range or closed, or the file has no
/// private data — nothing the kernel would detach. `Err`: a read failed or
/// an optional offset is absent on this kernel (lab PR 215: the deny
/// cannot decide). The file is not checked to be a link: ids are unique,
/// so another link never matches one of ours, and a non-link fd fails in
/// the kernel whatever is read here.
#[inline(always)]
unsafe fn link_id_of_fd(fd: u32) -> Result<Option<u32>, ()> {
    let o_files = off_opt!(TASK_STRUCT_FILES_OFFSET).ok_or(())?;
    let o_fdt = off_opt!(FILES_STRUCT_FDT_OFFSET).ok_or(())?;
    let o_max = off_opt!(FDTABLE_MAX_FDS_OFFSET).ok_or(())?;
    let o_fd = off_opt!(FDTABLE_FD_OFFSET).ok_or(())?;
    let o_priv = off_opt!(FILE_PRIVATE_DATA_OFFSET).ok_or(())?;
    let o_id = off_opt!(BPF_LINK_ID_OFFSET).ok_or(())?;
    let task = bpf_get_current_task() as *const u8;
    if task.is_null() {
        return Err(());
    }
    let files = bpf_probe_read_kernel::<u64>(task.add(o_files) as *const u64).map_err(|_| ())?;
    if files == 0 {
        return Ok(None);
    }
    let fdt = bpf_probe_read_kernel::<u64>((files as *const u8).add(o_fdt) as *const u64)
        .map_err(|_| ())?;
    if fdt == 0 {
        return Err(());
    }
    let max = bpf_probe_read_kernel::<u32>((fdt as *const u8).add(o_max) as *const u32)
        .map_err(|_| ())?;
    if fd >= max {
        return Ok(None);
    }
    let arr = bpf_probe_read_kernel::<u64>((fdt as *const u8).add(o_fd) as *const u64)
        .map_err(|_| ())?;
    if arr == 0 {
        return Err(());
    }
    let file = bpf_probe_read_kernel::<u64>((arr + 8 * fd as u64) as *const u64).map_err(|_| ())?;
    if file == 0 {
        return Ok(None);
    }
    let link = bpf_probe_read_kernel::<u64>((file as *const u8).add(o_priv) as *const u64)
        .map_err(|_| ())?;
    if link == 0 {
        return Ok(None);
    }
    bpf_probe_read_kernel::<u32>((link as *const u8).add(o_id) as *const u32)
        .map(Some)
        .map_err(|_| ())
}

/// [`nn_fd_is_root_cgroup`]: the descriptor names no cgroup v2 root (out
/// of range, closed, another file).
const ROOT_NO: u64 = 0;
/// [`nn_fd_is_root_cgroup`]: the cgroup v2 hierarchy's root (its kernfs
/// inode 1).
const ROOT_YES: u64 = 1;
/// [`nn_fd_is_root_cgroup`]: the file could not be read.
const ROOT_UNREADABLE: u64 = 2;

/// Lot 280b: [`fd_is_root_cgroup`] as a global BPF function (exported,
/// never inlined, scalar argument), as [`nn_link_id_of_fd`]: checked once,
/// on its own. [`ROOT_NO`], [`ROOT_YES`], [`ROOT_UNREADABLE`].
#[no_mangle]
#[inline(never)]
pub extern "C" fn nn_fd_is_root_cgroup(fd: u64) -> u64 {
    match unsafe { fd_is_root_cgroup(fd as u32) } {
        Ok(true) => ROOT_YES,
        Ok(false) => ROOT_NO,
        Err(()) => ROOT_UNREADABLE,
    }
}

/// Lot 280b: whether `fd` in the caller's file table is the root cgroup's
/// directory — a file of a cgroup v2 superblock whose inode is 1 (the
/// kernel names the default hierarchy's root so; a cgroup namespace's top
/// is another node). `Ok(false)`: out of range, closed, another file.
#[inline(always)]
unsafe fn fd_is_root_cgroup(fd: u32) -> Result<bool, ()> {
    let o_files = off_opt!(TASK_STRUCT_FILES_OFFSET).ok_or(())?;
    let o_fdt = off_opt!(FILES_STRUCT_FDT_OFFSET).ok_or(())?;
    let o_max = off_opt!(FDTABLE_MAX_FDS_OFFSET).ok_or(())?;
    let o_fd = off_opt!(FDTABLE_FD_OFFSET).ok_or(())?;
    let task = bpf_get_current_task() as *const u8;
    if task.is_null() {
        return Err(());
    }
    let files = bpf_probe_read_kernel::<u64>(task.add(o_files) as *const u64).map_err(|_| ())?;
    if files == 0 {
        return Ok(false);
    }
    let fdt = bpf_probe_read_kernel::<u64>((files as *const u8).add(o_fdt) as *const u64)
        .map_err(|_| ())?;
    if fdt == 0 {
        return Err(());
    }
    let max = bpf_probe_read_kernel::<u32>((fdt as *const u8).add(o_max) as *const u32)
        .map_err(|_| ())?;
    if fd >= max {
        return Ok(false);
    }
    let arr = bpf_probe_read_kernel::<u64>((fdt as *const u8).add(o_fd) as *const u64)
        .map_err(|_| ())?;
    if arr == 0 {
        return Err(());
    }
    let file = bpf_probe_read_kernel::<u64>((arr + 8 * fd as u64) as *const u64).map_err(|_| ())?;
    if file == 0 {
        return Ok(false);
    }
    let inode = bpf_probe_read_kernel::<u64>((file as *const u8).add(off!(FILE_F_INODE_OFFSET)) as *const u64)
        .map_err(|_| ())?;
    if inode == 0 {
        return Err(());
    }
    let sb = bpf_probe_read_kernel::<u64>((inode as *const u8).add(off!(INODE_I_SB_OFFSET)) as *const u64)
        .map_err(|_| ())?;
    if sb == 0 {
        return Err(());
    }
    let magic = bpf_probe_read_kernel::<u64>((sb as *const u8).add(off!(SUPER_BLOCK_S_MAGIC_OFFSET)) as *const u64)
        .map_err(|_| ())?;
    if !matches!(special_fs(magic), Some(SpecialFs::Cgroup2)) {
        return Ok(false);
    }
    let ino = bpf_probe_read_kernel::<u64>((inode as *const u8).add(off!(INODE_I_INO_OFFSET)) as *const u64)
        .map_err(|_| ())?;
    Ok(ino == ROOT_CGROUP_INO)
}

/// The kernel's inode number of the cgroup v2 hierarchy's root.
const ROOT_CGROUP_INO: u64 = 1;

/// [`nn_obj_get_own_link`]: the path names one of the agent's link pins.
const PIN_OWN: u64 = 1;
/// [`nn_obj_get_own_link`]: the path could not be read from the caller's
/// memory (lab PR 215: the name check cannot decide, a fail-open counted;
/// the kernel may still read it later, after a page fault this program
/// cannot take).
const PIN_UNREADABLE: u64 = 2;
/// Lot 290 ([`nn_obj_get_own_link`]): the path starts with
/// [`PIN_DIRS_PREFIX`] and its last component is not one of the agent's
/// link pins.
const PIN_UNDER_DIRS: u64 = 3;

/// [`obj_get_names_own_link`] as a global BPF function (exported, never
/// inlined, scalar argument): the verifier checks its loops once, on its
/// own. Inlined, they multiplied with the rest of the hook past the
/// million-instruction budget once the detach/update deny was added (lab,
/// 6.8: "BPF program is too large"). 0: not ours, [`PIN_OWN`],
/// [`PIN_UNREADABLE`], [`PIN_UNDER_DIRS`] (lot 290).
#[no_mangle]
#[inline(never)]
pub extern "C" fn nn_obj_get_own_link(user_ptr: u64) -> u64 {
    unsafe {
        let key = crate::task_scratch::key_of(bpf_get_current_task() as *const u8);
        let buf = match crate::task_scratch::make(&OBJ_GET_PATH_SCRATCH, &key) {
            Some(b) => b,
            None => return PIN_UNREADABLE,
        };
        let r = match obj_get_names_own_link(user_ptr, buf) {
            Ok(v) => v,
            Err(()) => PIN_UNREADABLE,
        };
        let _ = OBJ_GET_PATH_SCRATCH.remove(&key);
        r
    }
}

/// `OBJ_GET` whose pathname's final component is one of the agent's own
/// LINK pins ([`PIN_OWN`]), or (lot 290) whose path starts with
/// [`PIN_DIRS_PREFIX`] ([`PIN_UNDER_DIRS`]), else 0. `user_ptr` is the
/// first field of the `OBJ_GET` variant of the kernel's copy of
/// `bpf_attr`: the user pointer to the pathname.
///
/// Verifier budget (5.15): the string is read once only to learn its
/// length `n` (and, lot 290, its head is compared with the prefix there,
/// before the second read overwrites it), then the LAST [`PIN_NAME_LEN`]
/// bytes are read again from user memory into the head of the scratch
/// buffer — our pin names are shorter than that, so a final component that
/// is ours lies entirely in the window. Every map index is then a loop
/// counter in `0..32`: no subtraction reaches a map access (`n - 32` gave
/// "R4 min value is negative" on 5.15), no 256-byte scan (minutes of
/// verification), no stack array (memset subprogram).
#[inline(always)]
unsafe fn obj_get_names_own_link(user_ptr: u64, buf: *mut [u8; PATH_BUF_LEN]) -> Result<u64, ()> {
    if user_ptr == 0 {
        return Ok(0);
    }
    // pass 1: length only. A path that does not fit the buffer (truncated
    // read: PATH_BUF_LEN - 1 bytes, the NUL takes the last slot) is not
    // matched: scanning PATH_MAX in chunks blew the 5.15 state budget
    // ("BPF program is too large"), and a link fd cannot detach or update
    // an LSM link anyway — this check is defence in depth behind the pin
    // protection (review entry 39).
    let n = match bpf_probe_read_user_str_bytes(user_ptr as *const u8, &mut *buf) {
        Ok(s) => s.len(),
        Err(_) => return Err(()),
    };
    if n == 0 {
        return Ok(0);
    }
    // Lot 290: the head against the pin directories' prefix, now (the
    // second pass writes the head of the same buffer).
    let mut under = n >= PIN_DIRS_PREFIX.len();
    let mut k: usize = 0;
    while k < PIN_DIRS_PREFIX.len() {
        if (*buf)[k] != PIN_DIRS_PREFIX[k] {
            under = false;
            break;
        }
        k += 1;
    }
    let other: u64 = if under { PIN_UNDER_DIRS } else { 0 };
    // External audit EBPF-010: a path that does not fit the buffer is not
    // let through when it starts at the agent's pin root — padding a pin's
    // path past the buffer (`/sys/fs/bpf/northnarrow/./././…/link_task_kill`)
    // took a link handle in enforce mode. Nothing of a third party lives
    // under that root. (A symlink or a rewritten buffer still gets past a
    // check on the caller's string: the guarantee is the detach/update deny
    // in `try_bpf_syscall_observe`.)
    if n >= PATH_BUF_LEN - 1 {
        let mut i: usize = 0;
        while i < PIN_ROOT.len() {
            if (*buf)[i] != PIN_ROOT[i] {
                return Ok(other);
            }
            i += 1;
        }
        return Ok(PIN_OWN);
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
        Err(_) => return Err(()),
    };
    if m == 0 || m > PIN_NAME_LEN {
        return Ok(other);
    }
    // External audit EBPF-010: the final component, hashed in one pass —
    // the hash restarts after every '/'. An empty component (trailing '/')
    // hashes to the seed and a window with no '/' to 32 bytes, neither of
    // which is one of our names.
    let mut h: u64 = PIN_NAME_HASH_SEED;
    let mut j: usize = 0;
    while j < PIN_NAME_LEN {
        if j >= m {
            break;
        }
        let c = (*buf)[j];
        if c == b'/' {
            h = PIN_NAME_HASH_SEED;
        } else {
            h = (h ^ c as u64).wrapping_mul(PIN_NAME_HASH_PRIME);
        }
        j += 1;
    }
    Ok(match OWN_PIN_NAMES.get(&h) {
        Some(kind) if *kind == OWN_KIND_LINK => PIN_OWN,
        _ => other,
    })
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
    let write = fmode & FMODE_WRITE != 0;
    // Lot 290: a read handle is judged too, but only in enforce mode and
    // outside a window — the rest of the read path is left alone.
    if !write && (!enforce() || crate::inode_protect::override_active()) {
        return 0;
    }
    let id_slot = (map as *const u8).add(off!(BPF_MAP_ID_OFFSET)) as *const u32;
    let id = match bpf_probe_read_kernel::<u32>(id_slot) {
        Ok(v) => v,
        Err(_) => {
            // Lab PR 215: a handle the guard could not judge.
            crate::fail_open::bump(fail_open_hook::BPF_MAP);
            return 0;
        }
    };
    if !is_own_kind(id, OWN_KIND_MAP) || caller_is_exempt() || fresh_instance_may_load() {
        return 0;
    }
    if !write {
        // Lot 290: a read handle on one of the agent's maps, through any
        // path (a bind mount of the bpffs, a relative path, a symlink): a
        // program is loaded against a map only through a descriptor of it
        // (lot 281's residual).
        emit_denial_kind(FS_OP_BPF_HANDLE, OWN_KIND_MAP, id);
        return -EPERM;
    }
    if enforce() {
        emit_denial(FS_OP_BPF_MAP, id);
        return -EPERM;
    }
    emit_syscall(BPF_CMD_FOREIGN_MAP_WRITE, id);
    0
}

/// Lot 290: the id of program `prog` (`prog->aux->id`), `None` when a read
/// fails.
#[inline(always)]
pub(crate) unsafe fn prog_id_of(prog: *const c_void) -> Option<u32> {
    let aux = bpf_probe_read_kernel::<u64>((prog as *const u8).add(off!(BPF_PROG_AUX_OFFSET)) as *const u64).ok()?;
    if aux == 0 {
        return None;
    }
    bpf_probe_read_kernel::<u32>((aux as *const u8).add(off!(BPF_PROG_AUX_ID_OFFSET)) as *const u32).ok()
}

/// Lot 290: `bpf_prog(struct bpf_prog *prog)` — every new program handle:
/// the one a load returns, one by id, one through a path. The program a
/// load the `bpf` hook let through just made is recorded as seen
/// ([`crate::bpf_census::mark_seen`]); a handle on one of the agent's own
/// programs by a caller outside the family, outside a window, is refused
/// (enforce mode) — an `freplace` of one of its functions needs one, as an
/// attach of it elsewhere does.
#[lsm(hook = "bpf_prog")]
pub fn bpf_prog_guard(ctx: LsmContext) -> i32 {
    unsafe { try_bpf_prog_guard(&ctx) }
}

#[inline(always)]
unsafe fn try_bpf_prog_guard(ctx: &LsmContext) -> i32 {
    let prog: *const c_void = ctx.arg(0);
    if prog.is_null() {
        return 0;
    }
    let loading = crate::bpf_census::take_load_mark();
    let id = match prog_id_of(prog) {
        Some(id) => id,
        None => {
            crate::fail_open::bump(fail_open_hook::BPF);
            return 0;
        }
    };
    // Lot 345: before 6.9 the content is judged here, once verified, on
    // every handle a foreign caller takes — the load's, and one by id or
    // path (the load's program has an id before its descriptor: a second
    // thread could take it by id in between). The agent's own programs
    // (some signal) are the own-object guard's, below. No kfunc before 6.9:
    // the types refused by default only.
    if content_stage() == CONTENT_STAGE_HANDLE && !is_own_kind(id, OWN_KIND_PROG) {
        if let Some((why, ty)) = content_refusal(prog, false) {
            emit_denial_kind(FS_OP_BPF_PROG_TYPE, why, ty);
            return -EPERM;
        }
    }
    // Lot 345: one of the agent's calibration programs, loaded while it
    // asks for a calibration (before 6.9)
    if loading && calibration_armed() && (caller_is_exempt() || fresh_instance_may_load()) {
        if let Some(addr) = ptr_scalar(prog) {
            nn_calibrate(addr);
        }
    }
    if loading {
        crate::bpf_census::mark_seen(id, prog);
        return 0;
    }
    if !is_own_kind(id, OWN_KIND_PROG) || caller_is_exempt() || fresh_instance_may_load() {
        return 0;
    }
    if enforce() && !crate::inode_protect::override_active() {
        emit_denial_kind(FS_OP_BPF_HANDLE, OWN_KIND_PROG, id);
        return -EPERM;
    }
    0
}

/// Lot 345 (the re-check of #550, point 1 (ii)): `bpf_prog_load(struct
/// bpf_prog *prog, union bpf_attr *attr, …)`, 6.9 and later — called with
/// the kernel's copy of the instructions, before the verifier runs: the
/// content of a foreign load is judged here (helper ids as written), and a
/// program refused here never gets an id. Attached only where the kernel
/// has the hook; before 6.9 the `bpf_prog` hook judges.
///
/// The review of #553 (F1): a foreign load of EVERY type is read for the
/// signalling kfuncs this kernel has (`bpf_send_signal_task`, 6.13+; the
/// `bpf_task_work_schedule_*`, 6.18+) — a `syscall` program run by
/// `BPF_PROG_RUN`, an XDP or tc one, which any root loads with no opt-out,
/// signalled the agent past its `task_kill` hook. One scan per load, none
/// per packet; none at all where the kernel has no such kfunc.
#[lsm(hook = "bpf_prog_load")]
pub fn bpf_prog_load_guard(ctx: LsmContext) -> i32 {
    unsafe { try_bpf_prog_load_guard(&ctx) }
}

#[inline(always)]
unsafe fn try_bpf_prog_load_guard(ctx: &LsmContext) -> i32 {
    if content_stage() != CONTENT_STAGE_LOAD {
        return 0;
    }
    let prog: *const c_void = ctx.arg(0);
    if prog.is_null() {
        return 0;
    }
    if let Some((why, ty)) = content_refusal(prog, every_type_armed()) {
        emit_denial_kind(FS_OP_BPF_PROG_TYPE, why, ty);
        return -EPERM;
    }
    0
}

/// The review of #553 (F1): this kernel has kfunc targets, read in a load
/// of every type ([`CONTENT_EVERY_TYPE_SLOT`]).
#[inline(always)]
fn every_type_armed() -> bool {
    match PROG_CONTENT_CONF.get(CONTENT_EVERY_TYPE_SLOT) {
        Some(n) => *n != 0,
        None => false,
    }
}

/// Lot 345: the agent asks for a calibration ([`PROG_CONTENT_CALIB`]).
#[inline(always)]
fn calibration_armed() -> bool {
    match PROG_CONTENT_CALIB.get(0) {
        Some(k) => *k != CALIB_NONE,
        None => false,
    }
}

/// Lot 345 (before 6.9): the verified `imm` of each helper call of the
/// agent's calibration program at `prog` (its address) — the helper's
/// address less `__bpf_call_base`, which the agent cannot read from
/// `kallsyms` — recorded by instruction in [`PROG_CONTENT_SEEN`] (0 for
/// any other); the agent takes them in order. A global BPF function,
/// verified once.
#[no_mangle]
#[inline(never)]
pub extern "C" fn nn_calibrate(prog: u64) -> u64 {
    let (Some(len_off), Some(insns_off)) = (off_opt!(BPF_PROG_LEN_OFFSET), off_opt!(BPF_PROG_INSNSI_OFFSET))
    else {
        return 0;
    };
    let len = match unsafe { bpf_probe_read_kernel::<u32>((prog + len_off as u64) as *const u32) } {
        Ok(v) => v,
        Err(_) => return 0,
    };
    let insns = prog + insns_off as u64;
    let mut i: u32 = 0;
    while i < CALIB_MAX_INSNS {
        if i >= len {
            break;
        }
        let insn = match unsafe { bpf_probe_read_kernel::<u64>((insns + i as u64 * 8) as *const u64) } {
            Ok(v) => v,
            Err(_) => return 0,
        };
        let call = insn as u8 == INSN_CALL && (insn >> 12) & 0xf == 0;
        if let Some(p) = PROG_CONTENT_SEEN.get_ptr_mut(i) {
            unsafe { *p = if call { (insn >> 32) as u32 } else { 0 } };
        }
        i += 1;
    }
    1
}

/// Lot 345: the calibration programs — loaded by the agent, verified, read
/// by [`calibrate`] and unloaded; never attached, so the signal (0: none)
/// is never sent. Each calls its helpers in the order of
/// `bpf_prog_class::calibration_slot`, and nothing else.
#[kprobe]
pub fn nn_calib_signals(_ctx: ProbeContext) -> u32 {
    unsafe {
        let _ = aya_ebpf::helpers::generated::bpf_send_signal(0);
        let _ = aya_ebpf::helpers::generated::bpf_send_signal_thread(0);
    }
    0
}

/// Lot 345: [`nn_calib_signals`]' for the return override (a kernel built
/// without `CONFIG_BPF_KPROBE_OVERRIDE` refuses it: nothing to find).
#[kprobe]
pub fn nn_calib_override(ctx: ProbeContext) -> u32 {
    unsafe {
        let _ = aya_ebpf::helpers::generated::bpf_override_return(ctx.regs, 0);
    }
    0
}

/// Lot 345 (before 6.9): `locked_down(enum lockdown_reason what)` — the
/// verifier asks it with `LOCKDOWN_BPF_WRITE_USER` when a program calls
/// `bpf_probe_write_user`, the one target the agent cannot calibrate. A
/// foreign caller outside a window is refused there (in every mode, as the
/// type is), and the verifier refuses the program; any other reason is not
/// this hook's. Attached only where the content is judged at the handle.
#[lsm(hook = "locked_down")]
pub fn bpf_write_user_guard(ctx: LsmContext) -> i32 {
    unsafe { try_bpf_write_user_guard(&ctx) }
}

#[inline(always)]
unsafe fn try_bpf_write_user_guard(ctx: &LsmContext) -> i32 {
    let want = match PROG_CONTENT_CONF.get(CONTENT_LOCKDOWN_SLOT) {
        Some(v) => *v,
        None => 0,
    };
    let what = ctx.arg::<c_int>(0) as u32;
    if want == 0
        || what != want
        || caller_is_exempt()
        || crate::inode_protect::override_active()
        || fresh_instance_may_load()
    {
        return 0;
    }
    // the slot of bpf_probe_write_user; the type is not known here
    emit_denial_kind(FS_OP_BPF_PROG_TYPE, CONTENT_CALL, 0);
    -EPERM
}

/// Lot 345: the stage the agent armed ([`PROG_CONTENT_CONF`] slot 0).
#[inline(always)]
fn content_stage() -> u32 {
    match PROG_CONTENT_CONF.get(0) {
        Some(v) => *v,
        None => 0,
    }
}

/// Lot 345: why `prog`'s content refuses it to the caller, with its type —
/// a program of a type refused by default (one only the signed per-loader
/// opt-out lets a foreign caller load) that calls a helper or a kfunc of
/// `bpf_prog_class::FORBIDDEN_HELPERS` / `FORBIDDEN_KFUNCS`, or that cannot
/// be read whole (longer than `CONTENT_MAX_INSNS`, a failed read): refused
/// in every mode, as the type itself is. The review of #553 (F1): with
/// `every_type` (the load stage, on a kernel with such a kfunc), a program
/// of any other type that calls one of the kfuncs too — or cannot be read
/// whole. The family, a fresh instance of ours and a trusted-installer
/// window load anything (the agent's own programs signal); `None` then,
/// and for every other program.
#[inline(always)]
unsafe fn content_refusal(prog: *const c_void, every_type: bool) -> Option<(u8, u32)> {
    let ty = bpf_probe_read_kernel::<u32>((prog as *const u8).add(off!(BPF_PROG_TYPE_OFFSET)) as *const u32)
        .ok()?;
    let kfuncs_only = !denied_by_default(ty);
    if (kfuncs_only && !every_type)
        || caller_is_exempt()
        || crate::inode_protect::override_active()
        || fresh_instance_may_load()
    {
        return None;
    }
    // the lab's first round (6.8): the hook's `struct bpf_prog *` is a
    // BTF pointer to the verifier, which a global function does not take
    // ("R1 is not a scalar") — its address is passed as a plain number
    let Some(addr) = ptr_scalar(prog) else {
        return Some((CONTENT_UNJUDGED, ty));
    };
    match nn_prog_forbidden_call(addr, kfuncs_only as u64) {
        SCAN_CLEAN => None,
        hit if hit <= CALL_TARGETS as u64 => Some((CONTENT_CALL + (hit - 1) as u8, ty)),
        _ => Some((CONTENT_UNJUDGED, ty)),
    }
}

/// Lot 345: `p`'s address as a plain number, copied through the stack by
/// `bpf_probe_read_kernel` (whose result the verifier types as a scalar):
/// a global BPF function takes scalars only, and a hook's argument is a BTF
/// pointer to the verifier, `as u64` or not.
#[inline(always)]
unsafe fn ptr_scalar(p: *const c_void) -> Option<u64> {
    let v: u64 = p as u64;
    bpf_probe_read_kernel::<u64>(&v as *const u64).ok()
}

/// Lot 345: [`nn_prog_forbidden_call`] found no forbidden call.
const SCAN_CLEAN: u64 = 0;
/// Lot 345: … could not read the program whole.
const SCAN_UNJUDGED: u64 = u64::MAX;
/// Lot 345: the fan-out of the scan's four levels — 32 instructions a
/// chunk, 32 chunks a block, 32 blocks a span, 32 spans a program: 32⁴ =
/// `CONTENT_MAX_INSNS`. Four global functions, each verified once on its own
/// (the CI of #553: one level of 256 and two of 64 cost 5.15's verifier
/// 950,584 instructions).
const SCAN_FAN: u64 = 32;

/// Lot 345: the first forbidden call of the program at `prog` (a `struct
/// bpf_prog`'s address): its target's slot plus one, [`SCAN_CLEAN`] or
/// [`SCAN_UNJUDGED`]. A global BPF function (exported, never inlined,
/// scalar argument). The review of #553 (F1): `kfuncs_only` (not 0), a
/// call of a kfunc target only ([`judged_for_every_type`]) — a type let
/// through by default.
#[no_mangle]
#[inline(never)]
pub extern "C" fn nn_prog_forbidden_call(prog: u64, kfuncs_only: u64) -> u64 {
    let (Some(len_off), Some(insns_off)) = (off_opt!(BPF_PROG_LEN_OFFSET), off_opt!(BPF_PROG_INSNSI_OFFSET))
    else {
        return SCAN_UNJUDGED;
    };
    let len = match unsafe { bpf_probe_read_kernel::<u32>((prog + len_off as u64) as *const u32) } {
        Ok(v) => v as u64,
        Err(_) => return SCAN_UNJUDGED,
    };
    if len > CONTENT_MAX_INSNS as u64 {
        return SCAN_UNJUDGED;
    }
    let insns = prog + insns_off as u64;
    let mut k: u64 = 0;
    while k < SCAN_FAN {
        let from = k * SCAN_FAN * SCAN_FAN * SCAN_FAN;
        if from >= len {
            break;
        }
        let r = nn_scan_span(insns, from, len, kfuncs_only);
        if r != SCAN_CLEAN {
            return r;
        }
        k += 1;
    }
    SCAN_CLEAN
}

/// Lot 345: [`nn_prog_forbidden_call`] over the [`SCAN_FAN`] blocks from
/// instruction `from`.
#[no_mangle]
#[inline(never)]
pub extern "C" fn nn_scan_span(insns: u64, from: u64, len: u64, kfuncs_only: u64) -> u64 {
    let mut k: u64 = 0;
    while k < SCAN_FAN {
        let at = from + k * SCAN_FAN * SCAN_FAN;
        if at >= len {
            break;
        }
        let r = nn_scan_block(insns, at, len, kfuncs_only);
        if r != SCAN_CLEAN {
            return r;
        }
        k += 1;
    }
    SCAN_CLEAN
}

/// Lot 345: … over the [`SCAN_FAN`] chunks from instruction `from`.
#[no_mangle]
#[inline(never)]
pub extern "C" fn nn_scan_block(insns: u64, from: u64, len: u64, kfuncs_only: u64) -> u64 {
    let mut k: u64 = 0;
    while k < SCAN_FAN {
        let at = from + k * SCAN_FAN;
        if at >= len {
            break;
        }
        let r = nn_scan_chunk(insns, at, len, kfuncs_only);
        if r != SCAN_CLEAN {
            return r;
        }
        k += 1;
    }
    SCAN_CLEAN
}

/// Lot 345: … over the [`SCAN_FAN`] instructions from `from` (to `len`):
/// each one's call key looked up in [`PROG_CONTENT_KEYS`] (with
/// `kfuncs_only`, a kfunc target's only).
#[no_mangle]
#[inline(never)]
pub extern "C" fn nn_scan_chunk(insns: u64, from: u64, len: u64, kfuncs_only: u64) -> u64 {
    let mut j: u64 = 0;
    while j < SCAN_FAN {
        let i = from + j;
        if i >= len {
            break;
        }
        let insn = match unsafe { bpf_probe_read_kernel::<u64>((insns + i * 8) as *const u64) } {
            Ok(v) => v,
            Err(_) => return SCAN_UNJUDGED,
        };
        if let Some(slot) = unsafe { PROG_CONTENT_KEYS.get(&call_key(insn)) } {
            if kfuncs_only == 0 || judged_for_every_type(*slot) {
                return *slot as u64;
            }
        }
        j += 1;
    }
    SCAN_CLEAN
}

#[lsm(hook = "bpf")]
pub fn bpf_syscall_observe(ctx: LsmContext) -> i32 {
    unsafe { try_bpf_syscall_observe(&ctx) }
}

/// Lot 290 ([`nn_loader_opted_out`]): the caller's executable and the type
/// are in the signed per-loader opt-out.
const LOADER_OPTED_OUT: u64 = 1;
/// Lot 290: the dedup key's command of an opt-out's record (one a second
/// per loader and type, the type in its low byte).
const OPT_OUT_REPORT: u32 = 0xFFFF_0100;

/// Lot 290: whether the signed per-loader opt-out ([`BPF_LOADER_OPTOUT`])
/// names the caller's executable, by device and inode, with
/// `prog_type`'s bit. A global BPF function (exported, never inlined,
/// scalar argument): checked once, on its own, like the others here.
///
/// The review of #553 (F4): none is honoured while the content judge is
/// off (its stage not armed: a failed calibration, a configuration not
/// written) — fail closed: an opted-out loader would otherwise get back the
/// signalling helpers, the return override and `bpf_probe_write_user`.
#[no_mangle]
#[inline(never)]
pub extern "C" fn nn_loader_opted_out(prog_type: u64) -> u64 {
    let bit = type_bit(prog_type as u32);
    if bit == 0 || content_stage() == CONTENT_STAGE_OFF {
        return 0;
    }
    match unsafe { caller_exe_key() } {
        Some(k) => match unsafe { BPF_LOADER_OPTOUT.get(&k) } {
            Some(mask) if *mask & bit != 0 => LOADER_OPTED_OUT,
            _ => 0,
        },
        None => 0,
    }
}

#[inline(always)]
unsafe fn try_bpf_syscall_observe(ctx: &LsmContext) -> i32 {
    let cmd = ctx.arg::<c_int>(0) as u32;
    let attr: *const c_void = ctx.arg(1);
    // Only the commands worth a record (`bpf_cmd::observed`); the hot ones
    // (MAP_LOOKUP/UPDATE from bpftool, OBJ_GET_INFO, PROG_RUN) and the
    // `*_GET_NEXT_ID` enumerations, which give no handle, are not reported.
    if !observed(cmd) {
        return 0;
    }
    if caller_is_exempt() {
        // Lot 290: the family's loads are seen too — a program the agent
        // loads after its registration of its own objects is never "unseen"
        if cmd == BPF_PROG_LOAD {
            crate::bpf_census::mark_load();
        }
        return 0;
    }
    // bpf_attr is uapi-stable: the first u32 of the union is prog_type
    // (PROG_LOAD), map_type (MAP_CREATE), target_fd (PROG_ATTACH /
    // LINK_CREATE — attach_type sits at +8), start_id / prog_id / map_id /
    // link_id (*_GET_FD_BY_ID).
    // Lab PR 215: the commands whose argument decides a deny here (a link
    // handle by id, a detach or update of one of our links); for them an
    // unreadable argument is a fail-open, counted. Lot 290: and a load's
    // type, a map's or a program's handle by id.
    let decides = matches!(
        cmd,
        BPF_LINK_GET_FD_BY_ID
            | BPF_LINK_DETACH
            | BPF_LINK_UPDATE
            | BPF_PROG_LOAD
            | BPF_MAP_GET_FD_BY_ID
            | BPF_PROG_GET_FD_BY_ID
    );
    let mut arg: u32 = 0;
    if !attr.is_null() {
        let off: usize = match cmd {
            BPF_PROG_ATTACH | BPF_LINK_CREATE => 8,
            // Lot 293 (external bug hunt BUG05): `raw_tracepoint.prog_fd`
            // after the name's pointer.
            BPF_RAW_TRACEPOINT_OPEN => 8,
            _ => 0,
        };
        match bpf_probe_read_kernel::<u32>((attr as *const u8).add(off) as *const u32) {
            Ok(v) => arg = v,
            Err(_) => {
                if decides {
                    crate::fail_open::bump(fail_open_hook::BPF);
                }
            }
        }
    }
    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    // Lot 290: a program type that can rewrite user memory, override a
    // kernel function's return, signal a process or take a hook's place
    // (kprobe, tracepoint, perf_event, raw_tracepoint and its writable
    // form, tracing, struct_ops, extension, LSM), loaded by a caller
    // outside the family (returned above) outside a window — refused, in
    // every mode, unless the signed per-loader opt-out names the caller's
    // executable and the type (let through, recorded once a second). A
    // fresh agent or watchdog before it is a protected pid loads its own.
    // A load let through marks its thread: the `bpf_prog` hook records the
    // program it makes as seen (the cross-view).
    if cmd == BPF_PROG_LOAD {
        if denied_by_default(arg)
            && !crate::inode_protect::override_active()
            && !fresh_instance_may_load()
        {
            if nn_loader_opted_out(u64::from(arg)) != LOADER_OPTED_OUT {
                emit_denial(FS_OP_BPF_PROG_TYPE, arg);
                return -EPERM;
            }
            // Lot 345 (the re-check of #550, N2): the opt-out never covers
            // an fmod_ret — it overrides the return of any `security_*`
            // function, and an allowed loader made `security_file_open`
            // fail for the agent (the kernel's copy of the attr: an
            // unreadable attach type is refused too)
            let refused_attach = match bpf_probe_read_kernel::<u32>(
                (attr as *const u8).add(PROG_LOAD_ATTACH_TYPE_OFFSET) as *const u32,
            ) {
                Ok(eat) => opt_out_refuses_attach(eat),
                Err(_) => true,
            };
            if refused_attach {
                emit_denial_kind(FS_OP_BPF_PROG_TYPE, CONTENT_FMOD_RET, arg);
                return -EPERM;
            }
            if should_report(pid, OPT_OUT_REPORT | (arg & 0xff)) {
                emit_denial(FS_OP_BPF_PROG_OPT_OUT, arg);
            }
        }
        crate::bpf_census::mark_load();
    } else if matches!(cmd, BPF_PROG_GET_FD_BY_ID | BPF_OBJ_GET) {
        // a handle the `bpf_prog` hook may see: not a load
        crate::bpf_census::clear_load_mark();
    }
    // A handle to one of the agent's own MAPS or LINKS taken by id: the
    // shape of `bpftool map update id N` / `bpftool link show id N` /
    // `bpftool link detach id N` (and of each NorthNarrow entry `bpftool
    // link list` reaches: it takes a handle by id on every link it prints).
    // Lot 290: and its PROGRAMS (`bpftool prog show id N`; an `freplace`
    // of one of its functions needs a handle on it).
    let own_map_handle = cmd == BPF_MAP_GET_FD_BY_ID && is_own_kind(arg, OWN_KIND_MAP);
    let own_prog_handle = cmd == BPF_PROG_GET_FD_BY_ID && is_own_kind(arg, OWN_KIND_PROG);
    let own_link_handle = cmd == BPF_LINK_GET_FD_BY_ID && is_own_kind(arg, OWN_KIND_LINK);
    let pin = if cmd == BPF_OBJ_GET && !attr.is_null() {
        match bpf_probe_read_kernel::<u64>(attr as *const u64) {
            Ok(p) => nn_obj_get_own_link(p),
            Err(_) => PIN_UNREADABLE,
        }
    } else {
        0
    };
    if pin == PIN_UNREADABLE {
        crate::fail_open::bump(fail_open_hook::BPF);
    }
    let own_link_pin = pin == PIN_OWN;
    let own_dir_pin = pin == PIN_UNDER_DIRS;
    // Second half of the self-defence: a link handle is the only thing
    // that can DETACH or UPDATE one of our LSM hooks (`bpftool link detach
    // id N` / `… pinned <path>`), so in enforce mode a foreign process
    // never gets one — by id or through the pin.
    // External audit EBPF-002: no exemption by executable — a link handle
    // is taken only once the agent is a protected pid.
    if (own_link_handle || own_link_pin) && enforce() {
        emit_denial(FS_OP_BPF_LINK, if own_link_handle { arg } else { 0 });
        return -EPERM;
    }
    // Lot 290: a handle on one of the agent's maps or programs by id, or
    // anything under its pin directories, outside a window (enforce mode):
    // a program cannot be loaded against a map it has no descriptor of,
    // nor replace a function of a program it has none of. The `bpf_map`
    // and `bpf_prog` hooks judge the object a path reaches otherwise.
    if (own_map_handle || own_prog_handle || own_dir_pin)
        && enforce()
        && !crate::inode_protect::override_active()
        && !fresh_instance_may_load()
    {
        let kind = if own_map_handle {
            OWN_KIND_MAP
        } else if own_prog_handle {
            OWN_KIND_PROG
        } else {
            0
        };
        emit_denial_kind(FS_OP_BPF_HANDLE, kind, if kind == 0 { 0 } else { arg });
        return -EPERM;
    }
    // External audit EBPF-010: whatever gave the handle (a pin reached
    // through a symlink, or a buffer rewritten after the name check), a
    // foreign process neither detaches nor replaces one of the agent's
    // links. The kernels the agent supports refuse both on its link types
    // anyway (tracing, raw tracepoint and perf links have no .detach /
    // .update_prog: EOPNOTSUPP / EINVAL in the lab); this keeps it so on a
    // kernel that adds them. `arg` is the link fd for both commands.
    if matches!(cmd, BPF_LINK_DETACH | BPF_LINK_UPDATE) && enforce() {
        let id = nn_link_id_of_fd(u64::from(arg));
        if id == LINK_UNREADABLE {
            crate::fail_open::bump(fail_open_hook::BPF);
        } else if id <= u64::from(u32::MAX) && is_own_kind(id as u32, OWN_KIND_LINK) {
            emit_denial(FS_OP_BPF_LINK, id as u32);
            return -EPERM;
        }
    }
    // Lot 280b: a cgroup/sysctl program attached to the root cgroup outside
    // a window (the family returned above; a fresh agent before it is a
    // protected pid may attach its judge) — refused, signed. `arg` is the
    // attach type for both commands; the target is read only for them.
    // Lot 290: in every mode (it held in enforce mode only).
    if judges_attach_target(cmd, arg)
        && !crate::inode_protect::override_active()
        && !fresh_instance_may_load()
    {
        let target = match attach_target_offset(cmd) {
            Some(off) if !attr.is_null() => {
                bpf_probe_read_kernel::<u32>((attr as *const u8).add(off) as *const u32).ok()
            }
            _ => None,
        };
        let root = match target {
            Some(fd) => nn_fd_is_root_cgroup(u64::from(fd)),
            None => ROOT_UNREADABLE,
        };
        if root != ROOT_NO {
            emit_denial(FS_OP_SYSCTL_ROOT_ATTACH, arg);
            return -EPERM;
        }
    }
    let foreign_handle =
        own_map_handle || own_prog_handle || own_link_handle || own_link_pin || own_dir_pin;
    let report_cmd = if foreign_handle {
        BPF_CMD_FOREIGN_GET_FD
    } else {
        cmd
    };
    // Lot 290: one record a second per loader and program TYPE (a loader
    // of several types records each).
    let dedup = if cmd == BPF_PROG_LOAD {
        cmd | ((arg & 0xff) << 8)
    } else {
        report_cmd
    };
    if should_report(pid, dedup) {
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
    emit_denial_kind(operation, 0, object_id)
}

/// [`emit_denial`] with the object's kind in `target_dev` (lot 290:
/// `FS_OP_BPF_HANDLE`).
///
/// Lot 318 (external bug hunt BUG37, the residue of lot 293): behind the
/// per-attempt budget, through `crate::inode_protect::emit_attempt` — the
/// same record, the same ring. It wrote the ring itself, with no budget: a
/// root loop of `BPF_MAP_GET_FD_BY_ID` on one of the agent's maps filled
/// the `fs_protect` ring (64 KiB in the object, 256 KiB as the agent loads
/// it: `FS_PROTECT_RING_BYTES`), and the record of a refused `kill` or
/// ptrace was lost with it. A refusal over the budget is counted in
/// `RING_DROPS` (`ring_slot::DENIAL_RATE`: signed, telemetry loss past the
/// threshold); the deny never depends on the record. The deny self-test's
/// refusals stay outside the budget, as every other attempt's. Lot 318
/// (the review of #545, F1): the guard's non-decisive kinds (a handle, a
/// refused program type, a root attach, an opt-out's record) spend a budget
/// of their own (`minor_denial_rate`), never the decisive refusals'.
#[inline(always)]
fn emit_denial_kind(operation: u8, kind: u8, object_id: u32) {
    crate::inode_protect::emit_attempt(
        operation,
        InodeKey {
            dev: kind as u64,
            ino: object_id as u64,
        },
    );
}
