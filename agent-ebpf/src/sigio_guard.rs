//! Lot 293 (external bug hunt BUG14) — `file_send_sigiotask` LSM hook: a
//! signal through a file's owner, refused to a protected process.
//!
//! A file's owner (`F_SETOWN`, `F_SETOWN_EX` with a thread, a process or a
//! process group, `FIOSETOWN`/`SIOCSPGRP` on a socket) receives a signal
//! when the file is ready for I/O (`O_ASYNC`/`FIOASYNC`: SIGIO, or the
//! signal `F_SETSIG` chose — SIGKILL included), when a lease breaks, at a
//! dnotify event, or at out-of-band data (SIGURG). The kernel delivers it
//! from `send_sigio_to_task` / `send_sigurg_to_task`, which ask
//! `sigio_perm()` — the owner's credentials (euid 0 passes) and this LSM
//! hook — and never `security_task_kill`: until this lot, root killed the
//! agent and the watchdog with `fcntl(F_SETOWN, <agent>)`, `O_ASYNC` and one
//! write into a pipe, with no refusal and no record (the default action of
//! SIGIO is to terminate).
//!
//! Policy: towards a protected process (`PROTECTED_PIDS`: the agent, the
//! watchdog, a worker) every such signal is refused, whoever raised it —
//! the hook runs in the context of the process whose I/O completed, which
//! for a socket may be any process a softirq interrupted, so neither the
//! caller nor an exemption by caller tells anything (a "self" or "family"
//! exemption would let an attacker's socket, armed on the agent, be fired
//! by the agent's own write to it). The agent and the watchdog never arm
//! `O_ASYNC` themselves (`xtask/tests/self_defense.rs` reads the tree).
//!
//! The one exception is the signed trusted-installer window's signal grant
//! (`KILL_GRANT`, the stop signals SIGTERM, SIGCONT and SIGKILL until the
//! window ends, under this boot's session nonce): inside it root may already
//! stop the agent with `systemctl kill`, which PID 1 relays, so letting the
//! same signals through this path widens nothing. The plain SIGIO, SIGURG
//! and every other signal stay refused inside a window too. PID 1 is not
//! asked for: this path has no sender to compare.
//!
//! A refusal is signed (`FS_OP_SIGIO`: the target tgid, the signal as it
//! would have been delivered), rate-limited like a refused `kill`. The
//! event's pid is the process whose I/O raised the signal, not necessarily
//! the one that armed it: the posture records it, ENGAGED, and never makes
//! it a COMBAT offender.

use aya_ebpf::{
    cty::{c_int, c_void},
    helpers::bpf_probe_read_kernel,
    macros::lsm,
    programs::LsmContext,
};
use northnarrow_common::fail_open::hook;
use northnarrow_common::wire::{sigio_signal, FS_OP_SIGIO};

use crate::btf_offsets::TASK_STRUCT_TGID_OFFSET;

/// Linux `EPERM`; LSM hooks return `-errno` to deny.
const EPERM: c_int = 1;

/// `int file_send_sigiotask(struct task_struct *tsk, struct fown_struct
/// *fown, int sig)`: `tsk` the task the signal is for (a thread of the
/// owner, or each task of the owning process group in turn), `sig` the
/// owner's `F_SETSIG` signal — 0 for the plain SIGIO — or SIGURG.
#[lsm(hook = "file_send_sigiotask")]
pub fn file_send_sigiotask_deny(ctx: LsmContext) -> i32 {
    unsafe { try_file_send_sigiotask(&ctx) }
}

#[inline(always)]
unsafe fn try_file_send_sigiotask(ctx: &LsmContext) -> i32 {
    let task: *const c_void = ctx.arg(0);
    if task.is_null() {
        return 0;
    }
    let tgid = match bpf_probe_read_kernel::<u32>(
        (task as *const u8).add(off!(TASK_STRUCT_TGID_OFFSET)) as *const u32,
    ) {
        Ok(t) => t,
        Err(_) => {
            // the target cannot be told: let through, counted
            crate::fail_open::bump(hook::FILE_SEND_SIGIOTASK);
            return 0;
        }
    };
    if !crate::task_kill::is_protected_pid(tgid) {
        return 0;
    }
    let sig: c_int = ctx.arg(2);
    let delivered = sigio_signal(sig);
    if crate::task_kill::kill_grant_allows(delivered) {
        return 0;
    }
    crate::inode_protect::emit_task_denial(FS_OP_SIGIO, delivered as u32 as u64, tgid);
    -EPERM
}
