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
fn detect_only_suppresses_every_action_with_would_execute() {
    // BUG-033: with the detect-only gate set (`dry_run = true`), the
    // dispatcher suppresses EVERY action — including KillProcess, which
    // previously had no suppression branch and would SIGKILL for real —
    // and returns the honest `WouldExecute` outcome without touching
    // nft / cgroup / fs / process table. This is the single coherent
    // gate: one flag, every action.
    let config = super::ExecutorConfig {
        dry_run: true,
        ..super::ExecutorConfig::default()
    };
    let exec = Executor::with_config(config);

    let pid = 12345;
    for action in [
        ResponseAction::KillProcess,
        ResponseAction::KillProcessTree,
        ResponseAction::BlockOutbound,
        ResponseAction::Quarantine,
        ResponseAction::ThrottleProcess,
    ] {
        let report = exec.execute(action.clone(), pid);
        assert_eq!(
            report.primary,
            ExecutionOutcome::WouldExecute { pid },
            "{action:?} must be suppressed to WouldExecute in detect-only"
        );
        assert!(
            report.additional.is_empty(),
            "{action:?} must produce no child outcomes in detect-only"
        );
    }
}

/// External audit CMB-006: host-wide isolation is the COMBAT ladder's; the
/// executor refuses it from any other source, enforcing or not, and
/// touches nothing.
#[test]
fn host_wide_isolation_is_refused_outside_the_ladder() {
    for dry_run in [true, false] {
        let exec = Executor::with_config(super::ExecutorConfig {
            dry_run,
            ..super::ExecutorConfig::default()
        });
        let report = exec.execute(ResponseAction::FullNetworkIsolation, 4321);
        assert_eq!(
            report.primary,
            ExecutionOutcome::Refused {
                pid: 4321,
                reason: super::executor::ISOLATION_IS_THE_LADDERS,
            }
        );
        assert!(report.additional.is_empty());
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

/// External audit CMB-005: the host-critical guard applies to every
/// action that acts on a process — it used to be consulted by the tree
/// walk only, so a rule's KillProcess could take down sshd or the
/// watchdog. For the actions by PID the pid is fictitious: with the guard
/// broken they would report it gone, never `Refused`. A kill target that
/// does not run is gone before any guard (external audit CMB-004): the
/// kills are tried on a `sleep` of the test's own.
#[test]
fn host_critical_guard_applies_to_every_pid_scoped_action() {
    const GUARDED: u32 = 999_123;
    let mut sleeper = std::process::Command::new("sleep")
        .arg("30")
        .stdout(std::process::Stdio::null())
        .spawn()
        .unwrap();
    let live = sleeper.id();
    let tmp = tempfile::TempDir::new().unwrap();
    let mut cfg = super::ExecutorConfig::for_test(tmp.path());
    cfg.dry_run = false;
    let exec = Executor::with_config(cfg);
    exec.set_tree_guard(std::sync::Arc::new(move |pid: u32| {
        (pid == GUARDED || pid == live).then_some("ssh-service(sshd)")
    }));
    for (action, pid) in [
        (ResponseAction::KillProcess, live),
        (ResponseAction::KillProcessTree, live),
        (ResponseAction::Quarantine, GUARDED),
        (ResponseAction::BlockOutbound, GUARDED),
        (ResponseAction::ThrottleProcess, GUARDED),
    ] {
        let report = exec.execute(action.clone(), pid);
        assert_eq!(
            report.primary,
            ExecutionOutcome::Refused {
                pid,
                reason: "ssh-service(sshd)"
            },
            "{action:?}"
        );
        assert!(report.additional.is_empty(), "{action:?}");
    }
    // the guarded process still runs; a kill target that has exited is
    // gone, whatever the guard says about its PID
    assert!(super::proc_ref::ProcRef::open(live).is_live());
    let _ = sleeper.kill();
    let _ = sleeper.wait();
    let report = exec.execute(ResponseAction::KillProcess, GUARDED);
    assert_eq!(
        report.primary,
        ExecutionOutcome::AlreadyGone { pid: GUARDED }
    );
    // Not a process action: the guard has nothing to say.
    let report = exec.execute(ResponseAction::Log, GUARDED);
    assert!(matches!(
        report.primary,
        ExecutionOutcome::Refused { reason, .. } if reason.contains("Log action")
    ));
}
