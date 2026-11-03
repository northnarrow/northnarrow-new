//! Lot 273c (the review of #490) — another process's change of a protected
//! process's resource limits, scheduling, nice value or I/O priority,
//! refused outside a signed trusted-installer window:
//!
//! * `task_setrlimit` — `prlimit(2)` (`prlimit --pid`): an `RLIMIT_CPU`
//!   below what the agent has used is a SIGKILL from the kernel, which no
//!   `task_kill` hook sees; a small `RLIMIT_AS` / `RLIMIT_DATA` aborts its
//!   next allocation, `RLIMIT_NOFILE=0` or `RLIMIT_MEMLOCK=0` breaks it.
//!   Between two root processes the kernel checks no capability;
//! * `task_setscheduler` — `sched_setscheduler`, `sched_setattr`,
//!   `sched_setaffinity` (and `/proc/<pid>/timerslack_ns`): `SCHED_IDLE`,
//!   or one CPU a real-time hog owns, starves it;
//! * `task_setnice` — `setpriority` (`renice +19`);
//! * `task_setioprio` — `ioprio_set` (`ionice -c 3`).
//!
//! The target is protected (`PROTECTED_PIDS`, or a process running the
//! agent's binary before it registers, as the ptrace hook treats it); the
//! caller is not exempt and is not the target itself — a process sets its
//! own limits and priorities (the agent's workers do), systemd sets a
//! service's in the child before its exec, before the pid is protected.
//! A refusal is signed, rate-limited like a signal.

use aya_ebpf::{
    cty::{c_int, c_void},
    helpers::{bpf_get_current_pid_tgid, bpf_probe_read_kernel},
    macros::lsm,
    programs::LsmContext,
};
use northnarrow_common::fail_open::hook;
use northnarrow_common::wire::{FS_OP_IOPRIO, FS_OP_NICE, FS_OP_RLIMIT, FS_OP_SCHED};

use crate::btf_offsets::TASK_STRUCT_TGID_OFFSET;

/// Linux `EPERM`; LSM hooks return `-errno` to deny.
const EPERM: c_int = 1;

/// `true` when the change of `task` by the current process must be
/// refused (and signs it): `task` protected, the caller neither exempt nor
/// `task` itself, no window open. A target that cannot be read is let
/// through and counted in `hook`'s fail-open slot.
#[inline(always)]
pub(crate) unsafe fn refuse_task_change(task: *const c_void, op: u8, detail: u64, hook: u32) -> bool {
    if task.is_null() {
        return false;
    }
    let tgid = match bpf_probe_read_kernel::<u32>(
        (task as *const u8).add(off!(TASK_STRUCT_TGID_OFFSET)) as *const u32,
    ) {
        Ok(t) => t,
        Err(_) => {
            crate::fail_open::bump(hook);
            return false;
        }
    };
    if !crate::task_kill::is_protected_pid(tgid)
        && !crate::bpf_defense::task_runs_own_binary(task as *const u8)
    {
        return false;
    }
    let caller = (bpf_get_current_pid_tgid() >> 32) as u32;
    if caller == tgid
        || crate::task_kill::is_exempt_pid(caller)
        || crate::inode_protect::override_active()
    {
        return false;
    }
    crate::inode_protect::emit_task_denial(op, detail, tgid);
    true
}

/// `int task_setrlimit(struct task_struct *p, unsigned int resource,
/// struct rlimit *new_rlim)`.
#[lsm(hook = "task_setrlimit")]
pub fn task_setrlimit_deny(ctx: LsmContext) -> i32 {
    unsafe {
        let task: *const c_void = ctx.arg(0);
        let resource: u32 = ctx.arg(1);
        if refuse_task_change(task, FS_OP_RLIMIT, resource as u64, hook::TASK_SETRLIMIT) {
            return -EPERM;
        }
    }
    0
}

/// `int task_setscheduler(struct task_struct *p)`.
#[lsm(hook = "task_setscheduler")]
pub fn task_setscheduler_deny(ctx: LsmContext) -> i32 {
    unsafe {
        let task: *const c_void = ctx.arg(0);
        if refuse_task_change(task, FS_OP_SCHED, 0, hook::TASK_SETSCHEDULER) {
            return -EPERM;
        }
    }
    0
}

/// `int task_setnice(struct task_struct *p, int nice)`.
#[lsm(hook = "task_setnice")]
pub fn task_setnice_deny(ctx: LsmContext) -> i32 {
    unsafe {
        let task: *const c_void = ctx.arg(0);
        let nice: c_int = ctx.arg(1);
        if refuse_task_change(task, FS_OP_NICE, nice as i64 as u64, hook::TASK_SETNICE) {
            return -EPERM;
        }
    }
    0
}

/// `int task_setioprio(struct task_struct *p, int ioprio)`.
#[lsm(hook = "task_setioprio")]
pub fn task_setioprio_deny(ctx: LsmContext) -> i32 {
    unsafe {
        let task: *const c_void = ctx.arg(0);
        let ioprio: c_int = ctx.arg(1);
        if refuse_task_change(task, FS_OP_IOPRIO, ioprio as u32 as u64, hook::TASK_SETIOPRIO) {
            return -EPERM;
        }
    }
    0
}
