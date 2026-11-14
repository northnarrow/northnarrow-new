//! The review of #555 (F5) — the exec sensor marks every argv it cannot read
//! whole.
//!
//! The sensor reads at most `ARGV_LEN - 1` bytes of a process's argv block
//! (the verifier's bound on the slice). It marked the record cut
//! (`spawn_trunc::ARGV`) only for a block over `ARGV_LEN`: a block of
//! exactly `ARGV_LEN` bytes lost its last NUL unmarked — a whole argument
//! when the last one is empty, and the argv looked complete without it.
//! The read and its mark come from one shared function,
//! `northnarrow_common::wire::argv_read`, whose unit test pins the edge;
//! this checks the sensor uses it and keeps no bound of its own.

mod support;

use std::fs;

use support::{repo_root, strip_comments};

#[test]
fn the_exec_sensor_reads_and_marks_argv_through_the_shared_bound() {
    let rel = "agent-ebpf/src/main.rs";
    let code = strip_comments(
        &fs::read_to_string(repo_root().join(rel)).unwrap_or_else(|e| panic!("{rel}: {e}")),
    );
    assert_eq!(
        code.matches("wire::argv_read(arg_end - arg_start)").count(),
        1,
        "{rel}: the argv block's read length and cut mark come from argv_read"
    );
    for own in ["len > ARGV_LEN", "len >= ARGV_LEN", "len = ARGV_LEN - 1"] {
        assert!(!code.contains(own), "{rel}: a bound of its own: {own:?}");
    }
}
