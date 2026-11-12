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
//! the task's first exec after that fork and removes it — a later exec, a
//! task the map evicted (LRU) or one forked before the agent carries 0, "not
//! known". `fork_ppid` is the forker's tgid in the initial pid namespace:
//! `1` is the host's PID 1.

use aya_ebpf::{
    helpers::bpf_probe_read_kernel,
    macros::{btf_tracepoint, map},
    maps::LruHashMap,
    programs::BtfTracePointContext,
};

use crate::btf_offsets::{TASK_STRUCT_START_TIME_OFFSET, TASK_STRUCT_TGID_OFFSET};

/// One task's fork: the forker's thread-group id, and the task's own start
/// time (the record of an earlier task at the same address is not this
/// one's). 16 bytes.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ForkParent {
    pub parent_tgid: u32,
    pub _pad: u32,
    pub start: u64,
}

/// `task_struct` address → [`ForkParent`]. LRU: a fork always gets its
/// record; a task that never executes (a worker) is evicted in time. A
/// unit's fork is followed by its exec within milliseconds.
#[map]
static FORK_PARENTS: LruHashMap<u64, ForkParent> = LruHashMap::with_max_entries(16384, 0);

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
    let Ok(start) = (unsafe {
        bpf_probe_read_kernel::<u64>(child.add(off!(TASK_STRUCT_START_TIME_OFFSET)) as *const _)
    }) else {
        return 0;
    };
    let rec = ForkParent {
        parent_tgid,
        _pad: 0,
        start,
    };
    let _ = FORK_PARENTS.insert(&(child as u64), &rec, 0);
    0
}

/// The forker of `task` (started at `start`) when this is its first exec
/// since the fork, then forgotten; 0 when not known.
#[inline(always)]
pub fn take(task: *const u8, start: u64) -> u32 {
    let key = task as u64;
    let found = match unsafe { FORK_PARENTS.get(&key) } {
        Some(r) if r.start == start => r.parent_tgid,
        Some(_) => 0,
        None => return 0,
    };
    let _ = FORK_PARENTS.remove(&key);
    found
}
