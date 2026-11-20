//! Lot 376 (the review of #583, F3: R004 Critical at a reboot of Ubuntu
//! 24.04 — `comm=9`, `exe=/proc/self/fd/9`, `ppid=1`, systemd's executor
//! launching an early unit): the exec record (`sched_process_exec`) is
//! attached AFTER the exec sensor (`exec_check_lsm` on
//! `bprm_check_security`, or its `sys_enter_execve` fallback).
//!
//! In LSM mode the post-exec record takes the executed file's identity from
//! the LSM program's handoff (`EXEC_HANDOFF`). The record was attached
//! first, the LSM program after the openat tracepoint: every exec between
//! the two attaches — the agent's start, at a boot the moment systemd
//! launches its units — had no identity. A short-lived one, gone before the
//! pump read its `/proc`, fell into R004's path heuristic, and the
//! executor's `fexecve` of `/proc/self/fd/N` is that path: Critical, a kill.
//! With the sensor attached first, an exec the record sees has passed the
//! LSM hook. This ratchet keeps the order in the multiplexer's start.

mod support;

use support::repo_root;

const MULTIPLEXER: &str = "crates/nn-linux/src/sensors/multiplexer.rs";

/// The first byte offset of `needle` in `code`, or a failure naming it.
fn at(code: &str, needle: &str) -> usize {
    let found: Vec<usize> = code.match_indices(needle).map(|(i, _)| i).collect();
    assert_eq!(
        found.len(),
        1,
        "{MULTIPLEXER}: expected exactly one `{needle}`, found {}",
        found.len()
    );
    found[0]
}

#[test]
fn the_exec_record_is_attached_after_the_exec_sensor() {
    let code = std::fs::read_to_string(repo_root().join(MULTIPLEXER)).expect("the multiplexer");
    let sensor = at(&code, "crate::sensors::exe_identity::attach(");
    let record = at(&code, "attach_exec_tracepoint(&mut ebpf, &attach_points)?;");
    assert!(
        sensor < record,
        "{MULTIPLEXER}: `sched_process_exec` (attach_exec_tracepoint) is attached before the \
         exec sensor (exe_identity::attach) — every exec between the two has no LSM identity \
         (the review of #583, F3)"
    );
    // the fork record before both: an exec's first since its fork carries
    // its forker only when the fork was recorded
    let fork = at(&code, "attach_fork_parent(&mut ebpf);");
    assert!(
        fork < sensor,
        "{MULTIPLEXER}: the fork record is attached after the exec sensor"
    );
}
