//! Lab follow-up (lab PR 188): `nn-admin status | grep -m1 …` exited 134.
//! Rust ignores SIGPIPE, so a write to a pipe whose reader has gone fails
//! with EPIPE, and std's `println!` panics on it (`panic = "abort"` in the
//! release profile; 101 and the panic message in this test build). nn-admin
//! now ends quietly with 141 (128 + SIGPIPE) — never 0, never a panic.
//! Runs unprivileged: `host-check` reads the host, `audit read` a file.

use std::process::{Command, Output, Stdio};

const EXIT_CLOSED_PIPE: i32 = 141;

/// Run nn-admin with `args`, its stdout (or its stderr) a pipe whose read
/// end is already closed.
fn run_into_a_closed_pipe(args: &[&str], close_stderr: bool) -> Output {
    let (reader, writer) = std::io::pipe().expect("pipe");
    drop(reader);
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_nn-admin"));
    cmd.args(args).stdin(Stdio::null());
    if close_stderr {
        cmd.stdout(Stdio::null()).stderr(writer);
    } else {
        cmd.stdout(writer).stderr(Stdio::piped());
    }
    cmd.spawn()
        .expect("spawn nn-admin")
        .wait_with_output()
        .expect("wait for nn-admin")
}

fn assert_ended_quietly(out: &Output, what: &str) {
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(!stderr.contains("panicked"), "{what}: {stderr}");
    assert!(!stderr.contains("Broken pipe"), "{what}: {stderr}");
    assert_eq!(
        out.status.code(),
        Some(EXIT_CLOSED_PIPE),
        "{what}: {:?}, stderr: {stderr}",
        out.status
    );
}

/// `println!` / `print!`: the table and the JSON of `host-check`.
#[test]
fn host_check_into_a_closed_pipe_exits_141_without_a_panic() {
    assert_ended_quietly(
        &run_into_a_closed_pipe(&["host-check"], false),
        "host-check",
    );
    assert_ended_quietly(
        &run_into_a_closed_pipe(&["host-check", "--json"], false),
        "host-check --json",
    );
}

/// `writeln!` on a locked stdout in the library (`audit read`), and the
/// summary `eprintln!` with stderr closed.
#[test]
fn audit_read_into_a_closed_pipe_exits_141_without_a_panic() {
    let dir = tempfile::tempdir().unwrap();
    let key =
        northnarrow_agent::audit::AgentSigningKey::load_or_bootstrap(&dir.path().join("agent.key"))
            .unwrap();
    let log_path = dir.path().join("audit.log");
    let mut log = northnarrow_agent::audit::AuditLog::open(&log_path, key, [0u8; 16]).unwrap();
    for n in 0..3 {
        log.append(northnarrow_agent::combat::reconcile::draft(
            &northnarrow_agent::combat::reconcile::StaleChain::TornDown { rules_removed: n },
        ))
        .unwrap();
    }
    drop(log);
    let path = log_path.to_str().unwrap();
    assert_ended_quietly(
        &run_into_a_closed_pipe(&["audit", "read", "--path", path], false),
        "audit read",
    );
    assert_ended_quietly(
        &run_into_a_closed_pipe(&["audit", "read", "--path", path, "--json"], false),
        "audit read --json",
    );
    // stdout fine, stderr (the summary line) closed
    assert_ended_quietly(
        &run_into_a_closed_pipe(&["audit", "read", "--path", path], true),
        "audit read, stderr closed",
    );
    // and with nothing closed, the command is unchanged
    let out = Command::new(env!("CARGO_BIN_EXE_nn-admin"))
        .args(["audit", "read", "--path", path])
        .output()
        .unwrap();
    assert!(out.status.success(), "{out:?}");
    assert_eq!(String::from_utf8_lossy(&out.stdout).lines().count(), 3);
    assert!(String::from_utf8_lossy(&out.stderr).contains("audit: 3 entries read"));
}
