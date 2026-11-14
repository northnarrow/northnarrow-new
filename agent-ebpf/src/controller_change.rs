//! Lot 348 — a controller change's scheduling check, the writing
//! thread's.
//!
//! A write of a cgroup v2 `cgroup.subtree_control` enables or disables a
//! controller for a cgroup's children; the kernel then re-homes every task
//! of the subtree in its own cgroup (`cgroup_update_dfl_csses`: no task
//! changes cgroup). Before 6.5 the cpuset controller's `cpuset_can_attach`
//! asks `security_task_setscheduler` of each such task — the agent's
//! threads among them, whose CPUs and nodes nothing changes (a new cpuset
//! inherits its parent's; from 6.5 the kernel asks only when they change).
//! The scheduling deny (`task_limits::task_setscheduler_deny`) refused it:
//! on 5.15 `+cpuset` could never be enabled above the agent's unit, and
//! systemd, runc and containerd-shim retried at every container start
//! (NN-L-AT-001 `sched`, High, three or four per start). [`cgroup_subtree_mark`]
//! marks the writing thread for the write's length; the deny lets through
//! only that thread's check ([`in_controller_change`]). Another thread's
//! `sched_setaffinity` / `sched_setscheduler` / `sched_setattr` of the
//! agent, or a write of `/proc/<pid>/timerslack_ns`, is refused as before.

use aya_ebpf::{
    helpers::{bpf_get_current_pid_tgid, bpf_ktime_get_ns},
    macros::{fentry, map},
    maps::HashMap,
    programs::FEntryContext,
};

/// Lot 348: capacity of [`SUBTREE_WRITES`] — the threads inside a
/// `cgroup.subtree_control` write at once (the marks are made before the
/// write takes `cgroup_mutex`). An insert past it marks nothing: the
/// thread's controller change is judged as before (refused where it reaches
/// a protected process) — never an eviction.
const SUBTREE_WRITE_ENTRIES: u32 = 64;

/// Lot 348: a mark older than this is no write in progress (defence in
/// depth: a mark whose end was not seen, `kernel.ftrace_enabled=0` set
/// inside a window between the two programs). A controller change migrates
/// the subtree's tasks in milliseconds.
const SUBTREE_WRITE_TTL_NS: u64 = 5_000_000_000;

/// Lot 348: the writing thread (`pid_tgid`) inside a write of a cgroup v2
/// `cgroup.subtree_control` → the ktime of the write's start. Made by
/// [`cgroup_subtree_mark`], dropped by
/// [`crate::cgroup_guard::cgroup_move_clear`] at the end of the write; read
/// by the scheduling deny ([`in_controller_change`]). Not pinned, as the
/// move guard's stash.
#[map]
pub(crate) static SUBTREE_WRITES: HashMap<u64, u64> = HashMap::with_max_entries(SUBTREE_WRITE_ENTRIES, 0);

/// `ssize_t cgroup_subtree_control_write(struct kernfs_open_file *, char *,
/// size_t, loff_t)`: the writing thread marked for the write's length. The
/// end of the write drops the mark ([`crate::cgroup_guard::cgroup_move_clear`],
/// fexit of `cgroup_file_write`, which calls this function through its
/// `write` pointer: never inlined).
#[fentry(function = "cgroup_subtree_control_write")]
pub fn cgroup_subtree_mark(_ctx: FEntryContext) -> i32 {
    let pid_tgid = bpf_get_current_pid_tgid();
    // SAFETY: a helper with no argument.
    let now = unsafe { bpf_ktime_get_ns() };
    // Full: nothing marked (the change judged as before).
    let _ = SUBTREE_WRITES.insert(&pid_tgid, &now, 0);
    0
}

/// Lot 348: the current thread is inside a `cgroup.subtree_control` write
/// it began less than [`SUBTREE_WRITE_TTL_NS`] ago — a scheduling check it
/// reaches is the kernel's own, of a task its controller change re-homes in
/// its own cgroup ([`cgroup_subtree_mark`]). Another thread's
/// `sched_setaffinity` or `sched_setscheduler` is never one: the mark is
/// the writing thread's.
#[inline(always)]
pub(crate) fn in_controller_change() -> bool {
    let pid_tgid = bpf_get_current_pid_tgid();
    // SAFETY: a lookup of the marks' map; a helper with no argument.
    match unsafe { SUBTREE_WRITES.get(&pid_tgid) } {
        Some(t) => unsafe { bpf_ktime_get_ns() }.wrapping_sub(*t) < SUBTREE_WRITE_TTL_NS,
        None => false,
    }
}
