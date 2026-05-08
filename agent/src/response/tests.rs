//! Integration-flavoured tests for the response executor that live
//! inside the crate (so they can exercise both the public API and the
//! internal `kill::` helpers without going through `tests/`).
//!
//! Pure tests run unconditionally. Privileged tests (need to actually
//! kill processes) are `#[ignore]`d and only run with sudo:
//!
//! ```sh
//! cargo test -p northnarrow-agent --release --lib -- --ignored --nocapture
//! ```

use std::time::Duration;

use common::ResponseAction;

use super::{ExecutionOutcome, Executor};

#[test]
fn executor_protected_set_includes_init_and_self() {
    let exec = Executor::new();
    let p = exec.protected();
    assert!(p.contains(&0));
    assert!(p.contains(&1));
    assert!(p.contains(&2));
    assert!(p.contains(&std::process::id()));
}

#[test]
fn execute_log_action_is_a_noop_refusal() {
    let exec = Executor::new();
    let report = exec.execute(ResponseAction::Log, 12345);
    match report.primary {
        ExecutionOutcome::Refused { pid: 12345, reason } => assert!(reason.contains("Log action")),
        other => panic!("unexpected outcome: {other:?}"),
    }
    assert!(report.additional.is_empty());
}

#[test]
fn execute_dispatches_new_actions_via_dry_run() {
    // Tappa 5: every action now has an implementation. With
    // dry_run = true the executor returns the success outcome
    // for each one without touching nft / cgroup / fs.
    let config = super::ExecutorConfig {
        dry_run: true,
        ..super::ExecutorConfig::default()
    };
    let exec = Executor::with_config(config);

    let pid = 12345;
    match exec.execute(ResponseAction::BlockOutbound, pid).primary {
        ExecutionOutcome::Blocked { pid: p } => assert_eq!(p, pid),
        other => panic!("BlockOutbound → {other:?}"),
    }
    match exec
        .execute(ResponseAction::FullNetworkIsolation, 0)
        .primary
    {
        ExecutionOutcome::NetworkIsolated => (),
        other => panic!("FullNetworkIsolation → {other:?}"),
    }
    match exec.execute(ResponseAction::Quarantine, pid).primary {
        // /proc/12345/exe almost certainly doesn't exist; that's
        // fine, the dispatch path is what we're testing.
        ExecutionOutcome::AlreadyGone { pid: p } => assert_eq!(p, pid),
        ExecutionOutcome::Quarantined { .. } => {} // possible if pid is real
        other => panic!("Quarantine → {other:?}"),
    }
    match exec.execute(ResponseAction::ThrottleProcess, pid).primary {
        ExecutionOutcome::Throttled {
            pid: p,
            cpu_max_pct,
            io_weight,
        } => {
            assert_eq!(p, pid);
            assert_eq!(cpu_max_pct, 10);
            assert_eq!(io_weight, 10);
        }
        other => panic!("ThrottleProcess → {other:?}"),
    }
}

#[test]
fn execute_refuses_pid_below_protection_floor() {
    let exec = Executor::new();
    // PID 50 is below the floor (100) — must be refused even with a
    // Kill action.
    let report = exec.execute(ResponseAction::KillProcess, 50);
    match report.primary {
        ExecutionOutcome::Refused { pid: 50, reason } => {
            assert!(reason.contains("protection floor"), "{reason}")
        }
        other => panic!("unexpected: {other:?}"),
    }
}

#[test]
fn execute_kill_on_nonexistent_pid_returns_already_gone() {
    let exec = Executor::new();
    let report = exec.execute(ResponseAction::KillProcess, 999_999_997);
    assert!(
        matches!(
            report.primary,
            ExecutionOutcome::AlreadyGone { pid: 999_999_997 }
        ),
        "{:?}",
        report.primary
    );
    assert!(report.additional.is_empty());
}

// ---------------------------------------------------------------
// Privileged integration tests — need root or CAP_KILL. They live
// here (in the lib's #[cfg(test)] module) so they can use the same
// crate-internal types as the unit tests above.
// ---------------------------------------------------------------

#[test]
#[ignore = "requires permission to kill arbitrary processes (root or CAP_KILL)"]
fn kills_a_real_long_running_process() {
    let mut child = std::process::Command::new("/bin/sleep")
        .arg("60")
        .spawn()
        .expect("spawn /bin/sleep");
    let pid = child.id();
    // Give the kernel a moment to register the process.
    std::thread::sleep(Duration::from_millis(50));

    let exec = Executor::new();
    let report = exec.execute(ResponseAction::KillProcess, pid);
    assert!(
        matches!(report.primary, ExecutionOutcome::Killed { pid: p } if p == pid),
        "{:?}",
        report.primary
    );

    // Reap and confirm the child died from a signal, not natural exit.
    let status = child.wait().expect("wait child");
    use std::os::unix::process::ExitStatusExt;
    assert_eq!(status.signal(), Some(libc::SIGKILL));
}

#[test]
#[ignore = "requires permission to kill arbitrary processes (root or CAP_KILL)"]
fn kills_an_already_dead_process_reports_already_gone() {
    // /bin/true exits immediately; by the time we call kill, the
    // process is reaped (we wait() on it first).
    let mut child = std::process::Command::new("/bin/true")
        .spawn()
        .expect("spawn /bin/true");
    let pid = child.id();
    let _ = child.wait();
    std::thread::sleep(Duration::from_millis(50));

    let exec = Executor::new();
    let report = exec.execute(ResponseAction::KillProcess, pid);
    assert!(
        matches!(report.primary, ExecutionOutcome::AlreadyGone { pid: p } if p == pid),
        "{:?}",
        report.primary
    );
}

#[test]
#[ignore = "requires permission to kill arbitrary processes (root or CAP_KILL)"]
fn kills_a_process_tree() {
    // Spawn a bash that backgrounds three sleeps and then waits, so
    // we have a parent with three known children.
    let mut bash = std::process::Command::new("/bin/bash")
        .arg("-c")
        .arg("/bin/sleep 60 & /bin/sleep 60 & /bin/sleep 60 & wait")
        .spawn()
        .expect("spawn bash");
    let bash_pid = bash.id();
    // Give bash time to fork the three sleeps.
    std::thread::sleep(Duration::from_millis(150));

    let exec = Executor::new();
    let report = exec.execute(ResponseAction::KillProcessTree, bash_pid);
    assert!(
        matches!(report.primary, ExecutionOutcome::Killed { pid: p } if p == bash_pid),
        "primary = {:?}",
        report.primary
    );
    // We expect 3 child sleeps; allow a bit of slack (bash may have
    // forked a transient helper).
    let killed_kids = report
        .additional
        .iter()
        .filter(|o| {
            matches!(
                o,
                ExecutionOutcome::Killed { .. } | ExecutionOutcome::AlreadyGone { .. }
            )
        })
        .count();
    assert!(
        killed_kids >= 3,
        "expected at least 3 child kills, got {killed_kids}: {:?}",
        report.additional
    );

    let _ = bash.wait();
}
