//! Lot 310 (the re-check of #539, N2): who forked a process, for its first
//! exec.
//!
//! The kernel keeps no "parent at fork": `real_parent` follows a reparent,
//! so an orphan a webshell double-forked has PID 1 (or a subreaper) for its
//! parent by the time it executes `sh -c`. [`fork_parent_record`] (BTF
//! tracepoint `sched_process_fork`) records, for each new task, the thread
//! group that forked it and the task's start time, keyed by the
//! `task_struct` address (stable across `de_thread`); the exec record
//! ([`take`], called by `sched_process_exec`) carries it as `fork_ppid` for
//! the task's first exec after that fork and marks it used — a later exec, a
//! task the map evicted (LRU) or one forked before the agent carries 0, "not
//! known". `fork_ppid` is the forker's tgid in the initial pid namespace:
//! `1` is the host's PID 1.
//!
//! The re-check 4 of #539: the decision is
//! [`northnarrow_common::fork_record::on_exec`] (tested there). An exec of
//! a verified `systemd-executor` ([`EXECUTOR_IDS`], by the identity the LSM
//! exec hook read) leaves the record unused, so the unit's own program —
//! the next exec of the same process — carries the forker too, decided
//! here at the exec (the agent's former carry raced its `/proc` read). A
//! record is removed at its process's exit ([`fork_parent_forget`]): a
//! flood of `fork` + `_exit` no longer fills the map, and a missing record
//! is a real loss (`FORK_RECORD_LOST` counts no later exec any more).

use aya_ebpf::{
    helpers::{bpf_get_current_task, bpf_probe_read_kernel},
    macros::{btf_tracepoint, map, tracepoint},
    maps::{Array, HashMap, LruHashMap},
    programs::{BtfTracePointContext, TracePointContext},
};
use northnarrow_common::fork_record::{counts_as_lost, on_exec, OnExec, EXECUTOR_IDS_MAX};
use northnarrow_common::ring_drops::ring_slot;
use northnarrow_common::wire::InodeKey;

use crate::btf_offsets::{
    TASK_STRUCT_GROUP_LEADER_OFFSET, TASK_STRUCT_REAL_PARENT_OFFSET, TASK_STRUCT_START_TIME_OFFSET, TASK_STRUCT_TGID_OFFSET,
};

/// One task's fork: the forker's thread-group id, whether an exec used the
/// record (the re-check 4: kept, not removed, so a later exec is told from a
/// lost record), and the task's own start time (the record of an earlier
/// task at the same address is not this one's). 16 bytes.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ForkParent {
    pub parent_tgid: u32,
    pub used: u32,
    pub start: u64,
}

/// `task_struct` address → [`ForkParent`]. LRU: a fork always gets its
/// record; a process that never executes (a worker) is evicted in time. A
/// unit's fork is followed by its exec within milliseconds. Processes only
/// (re-check 3, decision 2: a thread is no fork of a process — a flood of
/// `pthread_create` no longer evicts the records), 65,536 of them: room
/// for the forks between a unit's fork and its exec many times over.
#[map]
static FORK_PARENTS: LruHashMap<u64, ForkParent> = LruHashMap::with_max_entries(65536, 0);

/// When the agent attached the record (`CLOCK_MONOTONIC` ns, the tasks'
/// start-time clock), written once by userland: an exec of a process that
/// started after it and finds no record lost it to the LRU
/// (`ring_slot::FORK_RECORD_LOST`, counted and signed).
#[map]
static FORK_PARENT_SINCE: Array<u64> = Array::with_max_entries(1, 0);

/// The re-check 4 of #539: the verified identities of systemd's executor
/// (the kernel's `(dev, ino)`, as the LSM exec hook reads `bprm->file`):
/// the packaged file's and the copies PID 1 holds, written by the agent at
/// its start and at each 10 s re-read. An exec of one leaves its process's
/// fork record to the next exec.
#[map]
static EXECUTOR_IDS: HashMap<InodeKey, u32> = HashMap::with_max_entries(EXECUTOR_IDS_MAX, 0);

/// `sched_process_fork(struct task_struct *parent, struct task_struct
/// *child)`: the child's forker (`parent` is the task that called
/// `fork`/`clone`, also with `CLONE_PARENT`, whose `real_parent` is not it).
#[btf_tracepoint(function = "sched_process_fork")]
pub fn fork_parent_record(ctx: BtfTracePointContext) -> i32 {
    let parent: *const u8 = unsafe { ctx.arg(0) };
    let child: *const u8 = unsafe { ctx.arg(1) };
    if parent.is_null() || child.is_null() {
        return 0;
    }
    let Ok(parent_tgid) = (unsafe {
        bpf_probe_read_kernel::<u32>(parent.add(off!(TASK_STRUCT_TGID_OFFSET)) as *const _)
    }) else {
        return 0;
    };
    // a thread (`CLONE_THREAD`: the forker's own thread group) is no
    // process's fork
    let Ok(child_tgid) = (unsafe {
        bpf_probe_read_kernel::<u32>(child.add(off!(TASK_STRUCT_TGID_OFFSET)) as *const _)
    }) else {
        return 0;
    };
    if child_tgid == parent_tgid {
        return 0;
    }
    let Ok(start) = (unsafe {
        bpf_probe_read_kernel::<u64>(child.add(off!(TASK_STRUCT_START_TIME_OFFSET)) as *const _)
    }) else {
        return 0;
    };
    let rec = ForkParent {
        parent_tgid,
        used: 0,
        start,
    };
    let _ = FORK_PARENTS.insert(&(child as u64), &rec, 0);
    0
}

/// `sched_process_exit` (the exiting task is the current one): its fork
/// record goes (a thread's exit finds none).
#[tracepoint]
pub fn fork_parent_forget(_ctx: TracePointContext) -> u32 {
    let task = unsafe { bpf_get_current_task() };
    let _ = FORK_PARENTS.remove(&task);
    0
}

/// The forker of `task` (started at `start`) for this exec, whose file is
/// `(dev, ino)` (`(0, 0)`: not known, tracepoint mode):
/// [`northnarrow_common::fork_record::on_exec`]. 0 when not known.
#[inline(always)]
pub fn take(task: *const u8, start: u64, dev: u64, ino: u64) -> u32 {
    let key = task as u64;
    let Some(rec) = FORK_PARENTS.get_ptr_mut(&key) else {
        lost(OnExec::Missing, start);
        return 0;
    };
    let (rec_start, used, forker) = unsafe { ((*rec).start, (*rec).used != 0, (*rec).parent_tgid) };
    let executor =
        (dev != 0 || ino != 0) && unsafe { EXECUTOR_IDS.get(&InodeKey { dev, ino }) }.is_some();
    let outcome = on_exec(Some((rec_start, used)), start, executor);
    match outcome {
        OnExec::Stale => {
            let _ = FORK_PARENTS.remove(&key);
            lost(outcome, start);
        }
        OnExec::First { keep: false } => unsafe { (*rec).used = 1 },
        _ => {}
    }
    outcome.fork_ppid(forker)
}

/// Lot 340: a process's fork record while it has executed nothing since
/// its fork: the forker's tgid and the process's own start.
#[derive(Clone, Copy)]
pub struct Unexecuted {
    pub ppid: u32,
    pub start: u64,
}

/// Lot 340: the unexecuted fork record of the thread group whose leader is
/// `leader` — the leader's `FORK_PARENTS` entry, unused, its start the
/// leader's (an earlier task at the same address is not this one).
#[inline(always)]
fn unexecuted_of(leader: *const u8) -> Option<Unexecuted> {
    if leader.is_null() {
        return None;
    }
    let start =
        unsafe { bpf_probe_read_kernel::<u64>(leader.add(off!(TASK_STRUCT_START_TIME_OFFSET)) as *const _) }.ok()?;
    match unsafe { FORK_PARENTS.get(&(leader as u64)) } {
        Some(rec) if rec.used == 0 && rec.start == start && rec.parent_tgid != 0 => Some(Unexecuted {
            ppid: rec.parent_tgid,
            start,
        }),
        _ => None,
    }
}

/// `task`'s thread-group leader.
#[inline(always)]
fn leader_of(task: *const u8) -> *const u8 {
    if task.is_null() {
        return core::ptr::null();
    }
    unsafe { bpf_probe_read_kernel::<*const u8>(task.add(off!(TASK_STRUCT_GROUP_LEADER_OFFSET)) as *const _) }
        .unwrap_or(core::ptr::null())
}

/// Lot 340: the current process's fork record when it has executed nothing
/// since its fork, and its forker's when that one has not either — two
/// levels: rsync's receiver is a fork of its generator, itself a fork of
/// rsync (the exec). A thread writing for the process reads its leader's
/// record (a thread is no fork of its own); the forker is the leader's
/// `real_parent` only while it still is the recorded forker (a reparented
/// process's parent is its reaper). `None`: no record (forked before the
/// agent, evicted, the record not attached), or an exec used it — that
/// exec's record named the forker. The open sensor carries them in its
/// record: a writer that never executes has no exec record, and the lineage
/// read it from `/proc` only, lost once it (or its forker) exited.
#[inline(always)]
pub fn unexecuted_forks() -> (Option<Unexecuted>, Option<Unexecuted>) {
    let task = unsafe { bpf_get_current_task() } as *const u8;
    let leader = leader_of(task);
    let Some(own) = unexecuted_of(leader) else {
        return (None, None);
    };
    let parent = match unsafe {
        bpf_probe_read_kernel::<*const u8>(leader.add(off!(TASK_STRUCT_REAL_PARENT_OFFSET)) as *const _)
    } {
        Ok(p) => leader_of(p),
        Err(_) => core::ptr::null(),
    };
    if parent.is_null() {
        return (Some(own), None);
    }
    let tgid = unsafe { bpf_probe_read_kernel::<u32>(parent.add(off!(TASK_STRUCT_TGID_OFFSET)) as *const _) };
    if tgid != Ok(own.ppid) {
        return (Some(own), None);
    }
    (Some(own), unexecuted_of(parent))
}

/// A process the record should hold (started after it was attached) that
/// it does not: counted (`FORK_RECORD_LOST`).
#[inline(always)]
fn lost(outcome: OnExec, start: u64) {
    let since = FORK_PARENT_SINCE.get(0).copied().unwrap_or(0);
    if counts_as_lost(outcome, start, since) {
        crate::drops::bump(ring_slot::FORK_RECORD_LOST);
    }
}
