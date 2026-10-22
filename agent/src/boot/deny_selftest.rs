//! The deny self-test (lab PR 218; external review AR-09 / G-12).
//!
//! An LSM program can attach and never run: on a kernel without `bpf` in
//! its active LSM list (Ubuntu's default) every deny hook attaches, the
//! health line says "all LSM hooks attached", and root kills the agent.
//! Right after the attach the agent now exercises one deny hook against
//! itself and expects the refusal:
//!
//! - a child of the agent's own binary (`--deny-self-test`), not in
//!   `PROTECTED_PIDS`, sends [`SELFTEST_SIGNAL`] to its parent, the agent;
//! - `task_kill` refuses every signal but 0 to a protected process from an
//!   unprotected one, so the child must get `EPERM` ([`EXIT_DENIED`]); a
//!   root caller gets no `EPERM` from the permission checks, only from an
//!   LSM;
//! - a delivered signal ([`EXIT_DELIVERED`]) means the hooks are attached
//!   but not executed: no enforcement ([`SelfTestOutcome::NotDenied`]),
//!   and the start is refused unless the degraded-mode opt-in is set;
//! - anything else (no child, no exit status within [`CHILD_TIMEOUT`], an
//!   unexpected errno) is [`SelfTestOutcome::Inconclusive`]: the start goes
//!   on, signed, at trust level L1.
//!
//! `SIGURG` is chosen because its default action is to ignore it and the
//! agent installs no handler: when the hook does not run, the signal it
//! lets through changes nothing.
//!
//! The refusal leaves a denial on the evidence ring like any other attempt
//! on the agent (an `FsProtectDenial` from the child, `Signal`, the
//! signal, the agent's pid). [`take_expected_denial`] recognises that one
//! record — the child's pid, the signal, the target, a kernel timestamp
//! between the spawn and the reap — before the posture sees it, so the
//! self-test never raises COMBAT; any other denial is untouched.

use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use nn_model::{Event, FsProtectOperation};
use parking_lot::Mutex;
use tracing::{error, info, warn};

/// The child's flag (hidden from `--help`).
pub const SELFTEST_FLAG: &str = "--deny-self-test";
/// The signal the child sends its parent.
pub const SELFTEST_SIGNAL: i32 = libc::SIGURG;

/// The child's exit statuses.
pub const EXIT_DENIED: i32 = 10;
pub const EXIT_DELIVERED: i32 = 11;
pub const EXIT_NO_TARGET: i32 = 12;
pub const EXIT_OTHER: i32 = 13;

/// How long the agent waits for the child's exit.
pub const CHILD_TIMEOUT: Duration = Duration::from_secs(5);

/// What the self-test measured.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SelfTestOutcome {
    /// The signal was refused: the deny hooks run.
    Denied,
    /// The signal was delivered: the deny hooks are attached and not run.
    NotDenied,
    /// Not measured, and why.
    Inconclusive(String),
}

impl SelfTestOutcome {
    pub fn label(&self) -> &'static str {
        match self {
            SelfTestOutcome::Denied => "denied",
            SelfTestOutcome::NotDenied => "not_denied",
            SelfTestOutcome::Inconclusive(_) => "inconclusive",
        }
    }

    /// For the manifest and the journal: the label, and why when not
    /// measured.
    pub fn describe(&self) -> String {
        match self {
            SelfTestOutcome::Inconclusive(why) => format!("inconclusive: {why}"),
            other => other.label().to_string(),
        }
    }
}

/// The child's exit status, as the parent reads it.
pub fn classify(status: Option<i32>) -> SelfTestOutcome {
    match status {
        Some(EXIT_DENIED) => SelfTestOutcome::Denied,
        Some(EXIT_DELIVERED) => SelfTestOutcome::NotDenied,
        Some(EXIT_NO_TARGET) => {
            SelfTestOutcome::Inconclusive("the child found no parent to signal".to_string())
        }
        Some(EXIT_OTHER) => SelfTestOutcome::Inconclusive(
            "kill(2) failed with an errno other than EPERM".to_string(),
        ),
        Some(code) => SelfTestOutcome::Inconclusive(format!("the child exited {code}")),
        None => SelfTestOutcome::Inconclusive("the child ended on a signal".to_string()),
    }
}

/// The child's side: signal the parent, exit with what `kill(2)` said.
pub fn run_child() -> i32 {
    use nix::errno::Errno;
    use nix::sys::signal::{kill, Signal};
    let parent = nix::unistd::getppid();
    if parent.as_raw() <= 1 {
        return EXIT_NO_TARGET;
    }
    let Ok(sig) = Signal::try_from(SELFTEST_SIGNAL) else {
        return EXIT_OTHER;
    };
    match kill(parent, sig) {
        Ok(()) => EXIT_DELIVERED,
        Err(Errno::EPERM) => EXIT_DENIED,
        Err(Errno::ESRCH) => EXIT_NO_TARGET,
        Err(_) => EXIT_OTHER,
    }
}

/// The denial the child's attempt leaves on the evidence ring.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Expected {
    child: u32,
    target: u32,
    from_ns: u64,
    until_ns: u64,
}

static EXPECTED: Mutex<Option<Expected>> = Mutex::new(None);

/// `CLOCK_MONOTONIC` in nanoseconds, the clock of `bpf_ktime_get_ns`.
fn monotonic_ns() -> u64 {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: a valid clock id and a timespec to fill.
    unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) };
    ts.tv_sec as u64 * 1_000_000_000 + ts.tv_nsec as u64
}

fn arm(child: u32, target: u32, from_ns: u64, until_ns: u64) {
    *EXPECTED.lock() = Some(Expected {
        child,
        target,
        from_ns,
        until_ns,
    });
}

/// `true` when `event` is the self-test's own denial (consumed: once). The
/// event loop calls it first, before the posture and the rules.
pub fn take_expected_denial(event: &Event) -> bool {
    let Event::FsProtectDenial {
        pid,
        operation: FsProtectOperation::Signal,
        target_dev,
        target_ino,
        timestamp_ns,
        ..
    } = event
    else {
        return false;
    };
    let mut slot = EXPECTED.lock();
    let Some(e) = *slot else {
        return false;
    };
    let matches = *pid == e.child
        && *target_dev == SELFTEST_SIGNAL as u64
        && *target_ino == e.target as u64
        && (e.from_ns..=e.until_ns).contains(timestamp_ns);
    if matches {
        *slot = None;
        info!(
            child = pid,
            "deny self-test: its refused signal reached the evidence ring (expected, not an attempt)"
        );
    }
    matches
}

/// Run the self-test with `exe` (the agent's own binary,
/// `/proc/self/exe`) as the child. Blocking, at most [`CHILD_TIMEOUT`].
pub fn run(exe: &Path) -> SelfTestOutcome {
    let mut cmd = Command::new(exe);
    cmd.arg(SELFTEST_FLAG);
    run_command(cmd, &exe.display().to_string())
}

fn run_command(mut cmd: Command, what: &str) -> SelfTestOutcome {
    let target = std::process::id();
    let from_ns = monotonic_ns();
    let spawned = cmd
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn();
    let mut child = match spawned {
        Ok(c) => c,
        Err(e) => {
            return SelfTestOutcome::Inconclusive(format!(
                "cannot spawn {what} {SELFTEST_FLAG}: {e}"
            ))
        }
    };
    let child_pid = child.id();
    let deadline = Instant::now() + CHILD_TIMEOUT;
    let outcome = loop {
        match child.try_wait() {
            Ok(Some(status)) => break classify(status.code()),
            Ok(None) if Instant::now() >= deadline => {
                // The child is not protected: it can be killed and reaped.
                let _ = child.kill();
                let _ = child.wait();
                break SelfTestOutcome::Inconclusive(format!(
                    "the child did not exit within {} s",
                    CHILD_TIMEOUT.as_secs()
                ));
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(10)),
            Err(e) => break SelfTestOutcome::Inconclusive(format!("waiting for the child: {e}")),
        }
    };
    // Reaped: its pid is free from here, and any later denial from it is
    // stamped after `until_ns`. The event loop has not started yet.
    arm(child_pid, target, from_ns, monotonic_ns());
    outcome
}

/// The journal line for `outcome`, and the signed detail when it is not
/// [`SelfTestOutcome::Denied`].
pub fn report(outcome: &SelfTestOutcome) -> Option<String> {
    match outcome {
        SelfTestOutcome::Denied => {
            info!(
                signal = SELFTEST_SIGNAL,
                "deny self-test: a signal from an unprotected child was refused — the deny hooks run"
            );
            None
        }
        SelfTestOutcome::NotDenied => {
            let detail =
                "anti-tamper: deny self-test — a signal from an unprotected child reached \
                          the agent: the deny hooks are attached but the kernel does not run them \
                          (no enforcement)"
                    .to_string();
            error!("{detail}");
            Some(detail)
        }
        SelfTestOutcome::Inconclusive(why) => {
            let detail = format!(
                "anti-tamper: deny self-test inconclusive ({why}): enforcement not verified this boot"
            );
            warn!("{detail}");
            Some(detail)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// [`EXPECTED`] is one per process.
    static TEST_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn exit_statuses_map_to_outcomes() {
        assert_eq!(classify(Some(EXIT_DENIED)), SelfTestOutcome::Denied);
        assert_eq!(classify(Some(EXIT_DELIVERED)), SelfTestOutcome::NotDenied);
        for status in [
            Some(EXIT_NO_TARGET),
            Some(EXIT_OTHER),
            Some(0),
            Some(101),
            None,
        ] {
            assert!(
                matches!(classify(status), SelfTestOutcome::Inconclusive(_)),
                "{status:?}"
            );
        }
    }

    fn denial(pid: u32, sig: u64, target: u64, ts: u64) -> Event {
        Event::FsProtectDenial {
            pid,
            uid: 0,
            comm: "northnarrow-age".to_string(),
            target_dev: sig,
            target_ino: target,
            operation: FsProtectOperation::Signal,
            timestamp_ns: ts,
        }
    }

    /// The self-test's denial is taken once, and only that one: another
    /// pid, signal, target, an earlier or later timestamp, another
    /// operation all reach the posture.
    #[test]
    fn only_the_self_tests_own_denial_is_taken() {
        let _g = TEST_LOCK.lock();
        let sig = SELFTEST_SIGNAL as u64;
        arm(4242, 100, 1_000, 2_000);
        for other in [
            denial(4243, sig, 100, 1_500),
            denial(4242, 9, 100, 1_500),
            denial(4242, sig, 101, 1_500),
            denial(4242, sig, 100, 999),
            denial(4242, sig, 100, 2_001),
            Event::FsProtectDenial {
                pid: 4242,
                uid: 0,
                comm: String::new(),
                target_dev: sig,
                target_ino: 100,
                operation: FsProtectOperation::Unlink,
                timestamp_ns: 1_500,
            },
        ] {
            assert!(!take_expected_denial(&other), "{other:?}");
        }
        assert!(take_expected_denial(&denial(4242, sig, 100, 1_500)));
        assert!(
            !take_expected_denial(&denial(4242, sig, 100, 1_500)),
            "consumed: a second one is an attempt"
        );
    }

    #[test]
    fn a_not_denied_signal_is_an_anti_tamper_record() {
        assert_eq!(report(&SelfTestOutcome::Denied), None);
        let d = report(&SelfTestOutcome::NotDenied).unwrap();
        assert!(
            d.starts_with("anti-tamper:") && d.contains("no enforcement"),
            "{d}"
        );
        let d = report(&SelfTestOutcome::Inconclusive("x".into())).unwrap();
        assert!(
            d.starts_with("anti-tamper:") && d.contains("not verified"),
            "{d}"
        );
    }

    /// The parent side without a hook: a child standing in for the agent's
    /// binary exits with a status and the parent reads it.
    #[test]
    fn the_parent_reads_the_childs_status() {
        let _g = TEST_LOCK.lock();
        let sh = |code: i32| {
            let mut c = Command::new("sh");
            c.arg("-c").arg(format!("exit {code}"));
            c
        };
        assert_eq!(
            run_command(sh(EXIT_DELIVERED), "sh"),
            SelfTestOutcome::NotDenied
        );
        assert_eq!(run_command(sh(EXIT_DENIED), "sh"), SelfTestOutcome::Denied);
        assert!(matches!(
            run(Path::new("/nonexistent/northnarrow-agent")),
            SelfTestOutcome::Inconclusive(_)
        ));
    }
}
