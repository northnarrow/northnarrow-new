//! Lot 277 — the processes not started in the cgroup they run in.
//!
//! The per-rule policy may exempt an actor from a rule by its cgroup or
//! its systemd unit (`nn_core::decision::rule_policy`). A cgroup's members
//! are not all what started there: a root writes its own pid into an
//! exempt service's `cgroup.procs`, or starts a child in it with
//! `clone3(CLONE_INTO_CGROUP)`, and is then "in" the service. These
//! programs mark such a process in [`CGROUP_JOINED`] — by thread-group id,
//! with its leader's start time — and every process it forks after it;
//! the agent applies no exemption by cgroup or unit to a marked process
//! (`nn_linux::cgroup_join`). What is not marked is systemd's placement
//! ([`northnarrow_common::cgroup_join::placement`]): a move PID 1 makes,
//! and the move a child of PID 1 makes of itself before it ran any program
//! of its own.
//!
//! * [`cgroup_join_src`] (fexit `cgroup_procs_write_start`): for a thread
//!   moving itself, the cgroup it is in before the move — so a move that
//!   changes nothing (systemd 255's executor moving itself after PID 1
//!   did, 256+'s after `CLONE_INTO_CGROUP`) is no move; a move of another
//!   thread of the writer's process is one (the review of #494, B1). Every
//!   migration runs under `cgroup_mutex`, from the lookup to the attach:
//!   one slot.
//! * [`cgroup_join_mark`] (tracepoint `cgroup_attach_task`, BTF): the
//!   completed move — marked unless systemd's placement; signed
//!   ([`FS_OP_CGROUP_JOIN`], rate-limited) when the destination is a
//!   cgroup an exemption names ([`CGROUP_EXEMPT_NAMES`]: the path's hash,
//!   or one of its components').
//! * [`cgroup_join_born`] (fentry `cgroup_post_fork`): a child started by
//!   `clone3(CLONE_INTO_CGROUP)` by anyone but PID 1 — marked before it
//!   runs.
//! * [`cgroup_join_fork`] (tracepoint `sched_process_fork`, BTF): a new
//!   process forked by a marked one is marked, before it runs.
//! * [`cgroup_join_exit`] (tracepoint `sched_process_exit`, BTF): the mark
//!   goes when the thread group's last thread exits (`signal->live` 0).
//!
//! The agent's family (the agent, the watchdog) moves processes into its
//! own containment cgroups, which no exemption may name: not marked.

use core::intrinsics::{atomic_xadd, AtomicOrdering};

use aya_ebpf::{
    helpers::{bpf_get_current_pid_tgid, bpf_get_current_task, bpf_probe_read_kernel, generated},
    macros::{btf_tracepoint, fentry, fexit, map},
    maps::{Array, HashMap, PerCpuArray},
    programs::{BtfTracePointContext, FEntryContext, FExitContext},
    EbpfContext,
};
use northnarrow_common::btf_offsets::CGROUP_MOVE_RET_ARG;
use northnarrow_common::cgroup_join::{
    fnv_step, lost_slot, noop, pack, path_read, placement, Move, PathRead, CLONE_INTO_CGROUP,
    EXEMPT_NAMES_ENTRIES, FNV_OFFSET, HOW_BORN_INTO, HOW_INHERITED, HOW_MOVED, JOINED_ENTRIES,
    LOST_WORDS, NAME_CGROUP, NAME_UNIT, PATH_READ, STAT_INHERITED, STAT_INTO_EXEMPT, STAT_LOST,
    STAT_ROOTS, STAT_SLOTS,
};
use northnarrow_common::wire::{InodeKey, FS_OP_CGROUP_JOIN};

use crate::btf_offsets::{
    KERNEL_CLONE_ARGS_FLAGS_OFFSET, MM_STRUCT_EXE_FILE_OFFSET, SIGNAL_STRUCT_LIVE_OFFSET,
    TASK_STRUCT_GROUP_LEADER_OFFSET, TASK_STRUCT_MM_OFFSET, TASK_STRUCT_REAL_PARENT_OFFSET,
    TASK_STRUCT_SIGNAL_OFFSET, TASK_STRUCT_START_TIME_OFFSET, TASK_STRUCT_TGID_OFFSET,
};

/// `BPF_F_NO_PREALLOC`: an entry allocated at each mark.
const BPF_F_NO_PREALLOC: u32 = 1;

/// The marked thread groups: tgid → `[its leader's start time, pack(how,
/// by whom)]`. Pinned with the programs' links: the marks outlive an agent
/// restart, and are kept while no agent runs. Sized by the agent at its
/// load to the host's `pid_max` / `threads-max` (the review of #494, D2),
/// an entry allocated per mark; a mark it cannot take (an allocation that
/// failed) puts the group in [`CGROUP_JOIN_LOST`].
#[map]
pub static CGROUP_JOINED: HashMap<u32, [u64; 2]> =
    HashMap::pinned(JOINED_ENTRIES, BPF_F_NO_PREALLOC);

/// The review of #494, D2: the thread groups whose mark could not be taken
/// — one bit per possible tgid, preallocated (512 KiB), so setting one
/// never fails. Passed on at a fork like a mark, cleared with the group's
/// last thread: that tree, and only it, is "not known" to the agent.
#[map]
pub static CGROUP_JOIN_LOST: Array<u64> = Array::pinned(LOST_WORDS, 0);

/// The tracker's counters ([`northnarrow_common::cgroup_join`]'s `STAT_*`).
/// Pinned with the marks.
#[map]
pub static CGROUP_JOIN_STATS: Array<u64> = Array::pinned(STAT_SLOTS, 0);

/// The names the per-rule policy's exemptions by cgroup or unit give
/// (FNV-1a of a cgroup path, or of a unit's name) → `NAME_CGROUP` /
/// `NAME_UNIT` bits. Key 0: any such exemption is in force. Written by the
/// agent at its start and at every policy change.
#[map]
pub static CGROUP_EXEMPT_NAMES: HashMap<u64, u8> = HashMap::with_max_entries(EXEMPT_NAMES_ENTRIES, 0);

/// The write in progress (`cgroup_mutex` serialises them): `[pid_tgid of a
/// thread moving itself, its cgroup id before the move]`, `[0, 0]` for a
/// move of any other task (the review of #494, B1: another thread of the
/// writer's process included).
#[map]
static CGROUP_JOIN_SRC: Array<[u64; 2]> = Array::with_max_entries(1, 0);

/// The destination path of the move being judged.
#[map]
static CGROUP_JOIN_PATH: PerCpuArray<[u8; PATH_READ]> = PerCpuArray::with_max_entries(1, 0);

/// The largest `-errno` an `ERR_PTR` carries (include/linux/err.h).
const MAX_ERRNO: u64 = 4095;

#[inline(always)]
fn count(slot: u32) {
    if let Some(v) = CGROUP_JOIN_STATS.get_ptr_mut(slot) {
        // SAFETY: a slot of the array, a plain counter.
        unsafe { *v += 1 };
    }
}

#[inline(always)]
unsafe fn rd_u64(addr: u64) -> Option<u64> {
    bpf_probe_read_kernel::<u64>(addr as *const u64).ok()
}

#[inline(always)]
unsafe fn rd_u32(addr: u64) -> Option<u32> {
    bpf_probe_read_kernel::<u32>(addr as *const u32).ok()
}

#[inline(always)]
unsafe fn tgid_of(task: u64) -> Option<u32> {
    rd_u32(task + off!(TASK_STRUCT_TGID_OFFSET) as u64)
}

/// The start time of `task`'s thread-group leader.
#[inline(always)]
unsafe fn leader_start(task: u64) -> Option<u64> {
    let leader = rd_u64(task + off!(TASK_STRUCT_GROUP_LEADER_OFFSET) as u64)?;
    if leader == 0 {
        return None;
    }
    rd_u64(leader + off!(TASK_STRUCT_START_TIME_OFFSET) as u64)
}

#[inline(always)]
unsafe fn exe_file(task: u64) -> Option<u64> {
    let mm = rd_u64(task + off!(TASK_STRUCT_MM_OFFSET) as u64)?;
    if mm == 0 {
        return None;
    }
    rd_u64(mm + off!(MM_STRUCT_EXE_FILE_OFFSET) as u64).filter(|f| *f != 0)
}

#[inline(always)]
fn family(tgid: u32) -> bool {
    crate::task_kill::is_exempt_pid(tgid)
}

/// The group's word in [`CGROUP_JOIN_LOST`] and its bit.
#[inline(always)]
fn lost_word(tgid: u32) -> Option<(*mut u64, u64)> {
    let (word, bit) = lost_slot(tgid)?;
    Some((CGROUP_JOIN_LOST.get_ptr_mut(word)?, bit))
}

/// `*w & bit`, read once (an aligned 8-byte load is single-copy atomic;
/// the BPF backend selects no atomic load on the default CPU).
#[inline(always)]
unsafe fn has(w: *mut u64, bit: u64) -> bool {
    core::ptr::read_volatile(w) & bit != 0
}

/// `*w += v`, atomically (BPF_XADD on every kernel and CPU version; its
/// result unused).
#[inline(always)]
unsafe fn xadd(w: *mut u64, v: u64) {
    let _ = atomic_xadd::<u64, u64, { AtomicOrdering::Relaxed }>(w, v);
}

/// The group is "not known": its mark could not be taken. Counted; its bit
/// set. One event sets a group's bit at a time — its fork, then its moves
/// under `cgroup_mutex` — so the test before the add holds; the add is
/// atomic for the other groups' bits of the word.
#[inline(always)]
fn lose(tgid: u32) {
    count(STAT_LOST);
    if let Some((w, bit)) = lost_word(tgid) {
        // SAFETY: a word of a preallocated array map.
        unsafe {
            if !has(w, bit) {
                xadd(w, bit);
            }
        }
    }
}

#[inline(always)]
fn is_lost(tgid: u32) -> bool {
    // SAFETY: a word of a preallocated array map.
    lost_word(tgid).is_some_and(|(w, bit)| unsafe { has(w, bit) })
}

/// The group's bit cleared (its last thread exits).
#[inline(always)]
fn found(tgid: u32) {
    if let Some((w, bit)) = lost_word(tgid) {
        // SAFETY: a word of a preallocated array map.
        unsafe {
            if has(w, bit) {
                xadd(w, bit.wrapping_neg());
            }
        }
    }
}

#[inline(always)]
fn mark(tgid: u32, start: u64, how: u8, by: u32) -> bool {
    let rec = [start, pack(how, by)];
    if CGROUP_JOINED.insert(&tgid, &rec, 0).is_err() {
        lose(tgid);
        return false;
    }
    true
}

/// `struct task_struct *cgroup_procs_write_start(char *buf, bool
/// threadgroup, <lock state> *)` returned: for a process moving itself,
/// the cgroup it is in now (the move's source). The return value is the
/// context's fourth slot, as for the move guard (`cgroup_guard.rs`).
#[fexit(function = "cgroup_procs_write_start")]
pub fn cgroup_join_src(ctx: FExitContext) -> i32 {
    unsafe { try_src(&ctx) };
    0
}

#[inline(always)]
unsafe fn try_src(ctx: &FExitContext) {
    let Some(slot) = CGROUP_JOIN_SRC.get_ptr_mut(0) else {
        return;
    };
    // SAFETY: the one slot, written under `cgroup_mutex`.
    *slot = [0, 0];
    let args = ctx.as_ptr() as *const u64;
    let Ok(task) = bpf_probe_read_kernel::<u64>(args.add(CGROUP_MOVE_RET_ARG)) else {
        return;
    };
    if task == 0 || task >= 0u64.wrapping_sub(MAX_ERRNO) {
        return;
    }
    // The review of #494, B1: the writing thread itself, not another thread
    // of its process (its own cgroup is not the moved task's then).
    if task == bpf_get_current_task() {
        *slot = [bpf_get_current_pid_tgid(), generated::bpf_get_current_cgroup_id()];
    }
}

/// `cgroup_attach_task(struct cgroup *dst_cgrp, const char *path, struct
/// task_struct *task, bool threadgroup)`: a move that went through — the
/// task (the leader for `cgroup.procs`) is in `dst_cgrp`, whose path the
/// kernel computed for the tracepoint.
#[btf_tracepoint(function = "cgroup_attach_task")]
pub fn cgroup_join_mark(ctx: BtfTracePointContext) -> i32 {
    unsafe { try_mark(&ctx) };
    0
}

#[inline(always)]
unsafe fn try_mark(ctx: &BtfTracePointContext) {
    let path: u64 = ctx.arg(1);
    let task: u64 = ctx.arg(2);
    if task == 0 {
        return;
    }
    let pid_tgid = bpf_get_current_pid_tgid();
    let writer = (pid_tgid >> 32) as u32;
    if family(writer) {
        return;
    }
    let Some(moved) = tgid_of(task) else {
        count(STAT_LOST);
        return;
    };
    let Some(start) = leader_start(task) else {
        lose(moved);
        return;
    };
    // The review of #494, B1: no move only for the writing thread moving
    // itself to where it was (`common::cgroup_join::noop`).
    let (src_this_write, src_id) = match CGROUP_JOIN_SRC.get(0) {
        Some(src) => (src[0] == pid_tgid, src[1]),
        None => (false, 0),
    };
    let unchanged = noop(
        task == bpf_get_current_task(),
        src_this_write,
        src_id,
        generated::bpf_get_current_cgroup_id(),
    );
    let parent = rd_u64(task + off!(TASK_STRUCT_REAL_PARENT_OFFSET) as u64).unwrap_or(0);
    let parent_tgid = if parent == 0 {
        0
    } else {
        tgid_of(parent).unwrap_or(0)
    };
    // Still its parent's image: the same `struct file` in both `mm`s (a
    // fork shares it; an exec, or PR_SET_MM_EXE_FILE, makes another).
    let pre_exec = parent_tgid == 1
        && match (exe_file(task), exe_file(parent)) {
            (Some(a), Some(b)) => a == b,
            _ => false,
        };
    match placement(writer, moved, parent_tgid, pre_exec, unchanged) {
        Move::Placement | Move::NoOp => return,
        Move::Mark => {}
    }
    if mark(moved, start, HOW_MOVED, writer) {
        count(STAT_ROOTS);
    }
    if let Some(hash) = exempt_destination(path) {
        count(STAT_INTO_EXEMPT);
        crate::inode_protect::emit_limited(
            FS_OP_CGROUP_JOIN,
            InodeKey {
                dev: hash,
                ino: u64::from(moved),
            },
        );
    }
}

/// The hash of the exemption name the destination `path` matches —
/// `common::cgroup_join::match_destination`'s walk: the whole path a
/// `cgroup` exemption gives, else the last component a `unit` exemption
/// gives — `Some(0)` for a path unread or cut at [`PATH_READ`] bytes while
/// any such exemption is in force, `None` otherwise. The loop keeps no
/// counter and branches on no value it knows: the 5.15 verifier's states
/// stay a few per byte (lot 277's lab: a component length counted per byte
/// took it past a million instructions).
#[inline(always)]
unsafe fn exempt_destination(path: u64) -> Option<u64> {
    let any = CGROUP_EXEMPT_NAMES.get(&0).is_some();
    if !any || path == 0 {
        return None;
    }
    let buf = CGROUP_JOIN_PATH.get_ptr_mut(0)?;
    let n = generated::bpf_probe_read_kernel_str(
        buf as *mut _,
        PATH_READ as u32,
        path as *const _,
    );
    // The review of #494, D1: a full buffer is a cut path (the helper
    // writes its NUL in the last byte).
    match path_read(n) {
        PathRead::Unread | PathRead::Cut => return Some(0),
        PathRead::Whole => {}
    }
    let mut full = FNV_OFFSET;
    let mut comp = FNV_OFFSET;
    let mut hit = 0u64;
    for i in 0..PATH_READ {
        // SAFETY: `i` < PATH_READ, the buffer's length.
        let b = (*buf)[i];
        if b == 0 {
            break;
        }
        full = fnv_step(full, b);
        if b == b'/' {
            if is_name(comp, NAME_UNIT) {
                hit = comp;
            }
            comp = FNV_OFFSET;
        } else {
            comp = fnv_step(comp, b);
        }
    }
    if is_name(comp, NAME_UNIT) {
        hit = comp;
    }
    if is_name(full, NAME_CGROUP) {
        return Some(full);
    }
    (hit != 0).then_some(hit)
}

/// `hash` is a name of the policy's of `kind`.
#[inline(always)]
unsafe fn is_name(hash: u64, kind: u8) -> bool {
    CGROUP_EXEMPT_NAMES
        .get(&hash)
        .is_some_and(|k| *k & kind != 0)
}

/// `void cgroup_post_fork(struct task_struct *child, struct
/// kernel_clone_args *kargs)`: a child started in a cgroup of its forker's
/// choosing (`CLONE_INTO_CGROUP`) by anyone but PID 1 is marked; it has
/// not run yet.
#[fentry(function = "cgroup_post_fork")]
pub fn cgroup_join_born(ctx: FEntryContext) -> i32 {
    unsafe { try_born(&ctx) };
    0
}

#[inline(always)]
unsafe fn try_born(ctx: &FEntryContext) {
    let child: u64 = ctx.arg(0);
    let kargs: u64 = ctx.arg(1);
    if child == 0 || kargs == 0 {
        return;
    }
    let Some(flags) = rd_u64(kargs + off!(KERNEL_CLONE_ARGS_FLAGS_OFFSET) as u64) else {
        count(STAT_LOST);
        return;
    };
    if flags & CLONE_INTO_CGROUP == 0 {
        return;
    }
    let forker = (bpf_get_current_pid_tgid() >> 32) as u32;
    if forker == 1 || family(forker) {
        return;
    }
    let Some(tgid) = tgid_of(child) else {
        count(STAT_LOST);
        return;
    };
    // A thread placed in a threaded cgroup is its process's: not a new
    // process.
    if tgid == forker {
        return;
    }
    let Some(start) = rd_u64(child + off!(TASK_STRUCT_START_TIME_OFFSET) as u64) else {
        lose(tgid);
        return;
    };
    if mark(tgid, start, HOW_BORN_INTO, forker) {
        count(STAT_ROOTS);
    }
}

/// `sched_process_fork(struct task_struct *parent, struct task_struct
/// *child)`: a new process forked by a marked one is marked, before it
/// runs (the tracepoint comes before the child's first wake-up).
#[btf_tracepoint(function = "sched_process_fork")]
pub fn cgroup_join_fork(ctx: BtfTracePointContext) -> i32 {
    unsafe { try_fork(&ctx) };
    0
}

#[inline(always)]
unsafe fn try_fork(ctx: &BtfTracePointContext) {
    let parent: u64 = ctx.arg(0);
    let child: u64 = ctx.arg(1);
    if parent == 0 || child == 0 {
        return;
    }
    let Some(ptgid) = tgid_of(parent) else {
        return;
    };
    // The mark is this process's, not a dead one's at the same tgid.
    let marked = match CGROUP_JOINED.get(&ptgid) {
        Some(rec) => leader_start(parent) == Some(rec[0]),
        None => false,
    };
    // The review of #494, D2: a group not known passes that on too.
    let lost = is_lost(ptgid);
    if !marked && !lost {
        return;
    }
    let Some(ctgid) = tgid_of(child) else {
        count(STAT_LOST);
        return;
    };
    if ctgid == ptgid {
        return;
    }
    if lost {
        lose(ctgid);
        return;
    }
    let Some(start) = rd_u64(child + off!(TASK_STRUCT_START_TIME_OFFSET) as u64) else {
        lose(ctgid);
        return;
    };
    if mark(ctgid, start, HOW_INHERITED, ptgid) {
        count(STAT_INHERITED);
    }
}

/// `sched_process_exit(struct task_struct *p, …)`: the mark goes with the
/// thread group's last thread (`signal->live`, decremented before the
/// tracepoint, is 0) — not with its leader, which may exit first.
#[btf_tracepoint(function = "sched_process_exit")]
pub fn cgroup_join_exit(ctx: BtfTracePointContext) -> i32 {
    unsafe { try_exit(&ctx) };
    0
}

#[inline(always)]
unsafe fn try_exit(ctx: &BtfTracePointContext) {
    let task: u64 = ctx.arg(0);
    if task == 0 {
        return;
    }
    let Some(tgid) = tgid_of(task) else {
        return;
    };
    let marked = CGROUP_JOINED.get(&tgid).is_some();
    if !marked && !is_lost(tgid) {
        return;
    }
    let Some(signal) = rd_u64(task + off!(TASK_STRUCT_SIGNAL_OFFSET) as u64) else {
        return;
    };
    if signal == 0 {
        return;
    }
    if rd_u32(signal + off!(SIGNAL_STRUCT_LIVE_OFFSET) as u64) == Some(0) {
        if marked {
            let _ = CGROUP_JOINED.remove(&tgid);
        }
        found(tgid);
    }
}
