//! Lot 341 (the alpha profile; the coordinator's decision of 13/11): the
//! HOST-WIDE denies under the start's no-enforcement gate.
//!
//! The alpha promises a tester it never breaks anything on the machine.
//! The guards that refuse a THIRD-PARTY tool something on the host — a
//! foreign tracing, LSM or extension BPF program's load (`bpftrace`, BCC,
//! another EDR, a monitoring agent), a `cgroup/sysctl` program on the root
//! cgroup, the kprobes and lockdown switches, a kexec image, the sysctl
//! guard, a cgroup v1 write, a ptrace attach of PID 1 — go to observe under
//! the observe-only gate (`alpha`, `--detect-only`, `NN_DETECT_ONLY`): the
//! action goes through and its record carries
//! `northnarrow_common::wire::FS_OP_WOULD_DENY` ("would deny"). The guards
//! that protect the AGENT itself (a kill or ptrace of the agent, its
//! watchdog or a worker; a write, rename or unlink of its files, units and
//! pins; a handle on, a write of, a detach or replacement of its BPF
//! programs, maps and links) never read this switch: they hold under every
//! profile. A foreign program that would target the agent's programs or
//! maps needs a descriptor of one, which those guards refuse.
//!
//! Every host-wide deny decides through [`judge`] (or [`judge_no_task`]
//! where the program has no task helpers); `xtask/tests/host_deny.rs`
//! keeps every deny site of this object either routed here or listed as
//! the agent's self-protection, each with its reason.

use aya_ebpf::{macros::map, maps::Array};
use northnarrow_common::wire::{FS_OP_WOULD_DENY, HOST_DENY_OBSERVE};

/// `[0]`: `HOST_DENY_ENFORCE` (0, the map's zero: an agent that could not
/// write it enforces) or `HOST_DENY_OBSERVE`, written by the agent from the
/// start's resolved gate right after the object loads, before any program
/// attaches, then frozen (no descriptor writes it again, the agent's
/// included). Per load, never pinned: each start's programs read the mode
/// of that start.
#[map]
pub static HOST_DENY_MODE: Array<u32> = Array::with_max_entries(1, 0);

/// Whether this start's gate leaves the host-wide denies in observe.
#[inline(always)]
fn observes() -> bool {
    matches!(HOST_DENY_MODE.get(0), Some(m) if *m == HOST_DENY_OBSERVE)
}

/// A host-wide deny of `operation`: `(refuse, the code to sign)` —
/// `(true, operation)` when the start enforces, `(false, operation |
/// FS_OP_WOULD_DENY)` under the observe-only gate. The deny self-test's
/// child (lot 302: the agent's own probe, which proves the hook judges) is
/// refused under every profile.
#[inline(always)]
pub(crate) fn judge(operation: u8) -> (bool, u8) {
    if observes() && !crate::inode_protect::caller_is_self_test() {
        (false, operation | FS_OP_WOULD_DENY)
    } else {
        (true, operation)
    }
}

/// [`judge`] for the `cgroup/sysctl` program, whose 5.15 helpers include
/// no `bpf_get_current_pid_tgid` (the self-test writes no sysctl).
#[inline(always)]
pub(crate) fn judge_no_task(operation: u8) -> (bool, u8) {
    if observes() {
        (false, operation | FS_OP_WOULD_DENY)
    } else {
        (true, operation)
    }
}
