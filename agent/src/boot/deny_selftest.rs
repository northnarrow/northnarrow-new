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
//! signal, the agent's pid). [`ExpectedDenial::take`] recognises that one
//! record — the child's pid, the signal, the target, a kernel timestamp
//! between the spawn and the reap — before the posture sees it, so the
//! self-test never raises COMBAT; any other denial is untouched. R11c (lab
//! PR 264): [`run`] returns it to the start, which hands it to the event
//! loop (it was a process-wide `EXPECTED`).
//!
//! Lot 273b (the review of #489): the cgroup move guard is attached where
//! the kernel's BTF has `cgroup_procs_write_start` in its shape — which
//! does not prove the kernel calls it (an `.isra` / `.constprop` clone, an
//! LTO build would leave the guard attached and silent). [`run_move`]
//! exercises it: a child of the agent's binary
//! (`--move-guard-self-test-target`), registered as a worker (protected,
//! not exempt), and a second one, not registered
//! (`--move-guard-self-test`), which writes the first one's pid to the
//! `cgroup.procs` of a throwaway cgroup at the root of the hierarchy. The
//! move must be refused (`EPERM`); a move done is the guard attached and
//! not run, signed as a degradation. Its refusal is taken like the
//! signal's ([`ExpectedDenial`] holds both).

use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::Arc;
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
    operation: FsProtectOperation,
    child: u32,
    /// `target_dev` of the record: the signal ([`SELFTEST_SIGNAL`]), 0 for
    /// a move.
    detail: u64,
    target: u32,
    from_ns: u64,
    until_ns: u64,
}

/// The self-tests' own denials, which the event loop takes once each (R11c,
/// lab PR 264: what [`run`] returns; clones share it; lot 273b: the move
/// guard's too, [`ExpectedDenial::also`]).
#[derive(Clone, Debug, Default)]
pub struct ExpectedDenial(Arc<Mutex<Vec<Expected>>>);

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

impl ExpectedDenial {
    fn arm(child: u32, target: u32, from_ns: u64, until_ns: u64) -> Self {
        Self(Arc::new(Mutex::new(vec![Expected {
            operation: FsProtectOperation::Signal,
            child,
            detail: SELFTEST_SIGNAL as u64,
            target,
            from_ns,
            until_ns,
        }])))
    }

    /// Lot 273b: the move guard's self-test denial too (its mover `child`,
    /// the moved `target`).
    fn arm_move(&self, child: u32, target: u32, from_ns: u64, until_ns: u64) {
        self.0.lock().push(Expected {
            operation: FsProtectOperation::CgroupMove,
            child,
            detail: 0,
            target,
            from_ns,
            until_ns,
        });
    }

    /// Lot 273b: the expectations of `other` (the move guard's) added to
    /// these.
    pub fn also(&self, other: &ExpectedDenial) {
        let more = other.0.lock().clone();
        self.0.lock().extend(more);
    }

    /// `true` when `event` is the self-test's own denial (consumed: once).
    /// The event loop calls it first, before the posture and the rules.
    pub fn take(&self, event: &Event) -> bool {
        take_expected_denial(&self.0, event)
    }
}

fn take_expected_denial(expected: &Mutex<Vec<Expected>>, event: &Event) -> bool {
    let Event::FsProtectDenial {
        pid,
        operation,
        target_dev,
        target_ino,
        timestamp_ns,
        ..
    } = event
    else {
        return false;
    };
    let mut slot = expected.lock();
    let Some(i) = slot.iter().position(|e| {
        *operation == e.operation
            && *pid == e.child
            && *target_dev == e.detail
            && *target_ino == e.target as u64
            && (e.from_ns..=e.until_ns).contains(timestamp_ns)
    }) else {
        return false;
    };
    slot.remove(i);
    info!(
        child = pid,
        operation = %operation,
        "deny self-test: its refused attempt reached the evidence ring (expected, not an attempt)"
    );
    true
}

/// Run the self-test with `exe` (the agent's own binary,
/// `/proc/self/exe`) as the child. Blocking, at most [`CHILD_TIMEOUT`].
/// The outcome, and the denial it leaves for the event loop to take.
pub fn run(exe: &Path) -> (SelfTestOutcome, ExpectedDenial) {
    let mut cmd = Command::new(exe);
    cmd.arg(SELFTEST_FLAG);
    run_command(cmd, &exe.display().to_string())
}

fn run_command(mut cmd: Command, what: &str) -> (SelfTestOutcome, ExpectedDenial) {
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
            return (
                SelfTestOutcome::Inconclusive(format!("cannot spawn {what} {SELFTEST_FLAG}: {e}")),
                ExpectedDenial::default(),
            )
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
    let expected = ExpectedDenial::arm(child_pid, target, from_ns, monotonic_ns());
    (outcome, expected)
}

/// Lot 273b: the move guard's children's flags (hidden from `--help`).
pub const MOVE_TARGET_FLAG: &str = "--move-guard-self-test-target";
pub const MOVE_FLAG: &str = "--move-guard-self-test";
/// The throwaway cgroup the mover writes to, at the hierarchy's root.
pub const MOVE_SELFTEST_CGROUP: &str = "northnarrow-move-selftest";
/// How long the target waits to be killed, at most.
const MOVE_TARGET_LIFETIME_SECS: u32 = 30;

/// The target's side: wait to be killed (an alarm ends it otherwise).
pub fn run_move_target() -> i32 {
    // SAFETY: plain libc calls; the default action of SIGALRM ends the
    // process.
    unsafe {
        libc::alarm(MOVE_TARGET_LIFETIME_SECS);
        loop {
            libc::pause();
        }
    }
}

/// The mover's side: write `pid` to `procs`, exit with what `write(2)`
/// said — [`EXIT_DENIED`] for `EPERM`, [`EXIT_DELIVERED`] for a move done.
pub fn run_move_child(procs: &str, pid: &str) -> i32 {
    use std::io::Write;
    if pid.parse::<u32>().is_err() {
        return EXIT_OTHER;
    }
    let mut f = match std::fs::OpenOptions::new().write(true).open(procs) {
        Ok(f) => f,
        Err(_) => return EXIT_OTHER,
    };
    match f.write_all(pid.as_bytes()) {
        Ok(()) => EXIT_DELIVERED,
        Err(e) if e.raw_os_error() == Some(libc::EPERM) => EXIT_DENIED,
        Err(e) if e.raw_os_error() == Some(libc::ESRCH) => EXIT_NO_TARGET,
        Err(_) => EXIT_OTHER,
    }
}

/// What [`run_move`] needs of the deny side: the worker role for the
/// target, and its removal.
pub trait MoveRoles {
    fn register(&self, pid: u32) -> Result<(), String>;
    fn evict(&self, pid: u32) -> Result<(), String>;
}

/// The pinned `PROTECTED_PIDS` under the bpffs root.
pub struct PinnedMoveRoles<'a>(pub &'a Path);

impl MoveRoles for PinnedMoveRoles<'_> {
    fn register(&self, pid: u32) -> Result<(), String> {
        antitamper_bpf::ProtectedPidsHandle::open(self.0)
            .and_then(|mut h| h.insert_role(pid, antitamper_bpf::pid_role::WORKER))
            .map_err(|e| format!("{e:#}"))
    }
    fn evict(&self, pid: u32) -> Result<(), String> {
        antitamper_bpf::ProtectedPidsHandle::open(self.0)
            .and_then(|mut h| h.evict(pid))
            .map_err(|e| format!("{e:#}"))
    }
}

/// Wait for `child` at most [`CHILD_TIMEOUT`]; its outcome.
fn reap(child: &mut std::process::Child, what: &str) -> SelfTestOutcome {
    let deadline = Instant::now() + CHILD_TIMEOUT;
    loop {
        match child.try_wait() {
            Ok(Some(status)) => break classify(status.code()),
            Ok(None) if Instant::now() >= deadline => {
                let _ = child.kill();
                let _ = child.wait();
                break SelfTestOutcome::Inconclusive(format!(
                    "the {what} did not exit within {} s",
                    CHILD_TIMEOUT.as_secs()
                ));
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(10)),
            Err(e) => break SelfTestOutcome::Inconclusive(format!("waiting for the {what}: {e}")),
        }
    }
}

/// Lot 273b: the move guard's self-test (the module's text). `exe`: the
/// agent's binary; `root`: the cgroup v2 hierarchy's mount point. Blocking,
/// at most [`CHILD_TIMEOUT`] for the mover. The outcome, and the refusal it
/// leaves for the event loop to take.
pub fn run_move(
    exe: &Path,
    root: &Path,
    roles: &dyn MoveRoles,
) -> (SelfTestOutcome, ExpectedDenial) {
    let expected = ExpectedDenial::default();
    let dir = root.join(MOVE_SELFTEST_CGROUP);
    // A leftover of an earlier boot (empty: its processes are gone).
    let _ = std::fs::remove_dir(&dir);
    if let Err(e) = std::fs::create_dir(&dir) {
        return (
            SelfTestOutcome::Inconclusive(format!("cannot make {}: {e}", dir.display())),
            expected,
        );
    }
    let quiet = |c: &mut Command| {
        c.stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
    };
    let mut target_cmd = Command::new(exe);
    target_cmd.arg(MOVE_TARGET_FLAG);
    quiet(&mut target_cmd);
    let mut target = match target_cmd.spawn() {
        Ok(c) => c,
        Err(e) => {
            let _ = std::fs::remove_dir(&dir);
            return (
                SelfTestOutcome::Inconclusive(format!("cannot spawn {MOVE_TARGET_FLAG}: {e}")),
                expected,
            );
        }
    };
    let target_pid = target.id();
    let outcome = match roles.register(target_pid) {
        Err(e) => SelfTestOutcome::Inconclusive(format!("the target is not protected: {e}")),
        Ok(()) => {
            let from_ns = monotonic_ns();
            let mut mover = Command::new(exe);
            mover
                .arg(MOVE_FLAG)
                .arg(dir.join("cgroup.procs"))
                .arg(target_pid.to_string());
            quiet(&mut mover);
            match mover.spawn() {
                Err(e) => SelfTestOutcome::Inconclusive(format!("cannot spawn {MOVE_FLAG}: {e}")),
                Ok(mut child) => {
                    let outcome = reap(&mut child, "mover");
                    expected.arm_move(child.id(), target_pid, from_ns, monotonic_ns());
                    outcome
                }
            }
        }
    };
    // The agent is exempt: it ends its own worker-registered child.
    let _ = target.kill();
    let _ = target.wait();
    if let Err(e) = roles.evict(target_pid) {
        warn!(pid = target_pid, error = %e, "move guard self-test: the target's role not evicted");
    }
    let _ = std::fs::remove_dir(&dir);
    (outcome, expected)
}

/// Lot 273b: the journal line for the move guard's `outcome`, and the
/// signed detail when it is not [`SelfTestOutcome::Denied`].
pub fn report_move(outcome: &SelfTestOutcome) -> Option<String> {
    match outcome {
        SelfTestOutcome::Denied => {
            info!(
                "move guard self-test: moving a protected process to another cgroup was refused — \
                 the move guard runs"
            );
            None
        }
        SelfTestOutcome::NotDenied => {
            let detail =
                "anti-tamper cgroup: move guard self-test — a protected process was moved \
                          to another cgroup: the guard is attached but the kernel does not run it \
                          (a clone of cgroup_procs_write_start?); a protected process can be moved \
                          out of its unit's cgroup and killed or frozen there"
                    .to_string();
            error!("{detail}");
            Some(detail)
        }
        SelfTestOutcome::Inconclusive(why) => {
            let detail = format!(
                "anti-tamper cgroup: move guard self-test inconclusive ({why}): the move guard \
                 is not verified this boot"
            );
            warn!("{detail}");
            Some(detail)
        }
    }
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

    /// Lot 273b: the move guard's refusal is taken once, beside the
    /// signal's; a move of another pid, by another child, or a signal from
    /// the mover, reach the posture.
    #[test]
    fn the_move_guards_refusal_is_taken_beside_the_signals() {
        let sig = SELFTEST_SIGNAL as u64;
        let expected = ExpectedDenial::arm(4242, 100, 1_000, 2_000);
        let moves = ExpectedDenial::default();
        moves.arm_move(5151, 6161, 3_000, 4_000);
        expected.also(&moves);
        let mv = |pid, target, ts| Event::FsProtectDenial {
            pid,
            uid: 0,
            comm: "northnarrow-age".to_string(),
            target_dev: 0,
            target_ino: target,
            operation: FsProtectOperation::CgroupMove,
            timestamp_ns: ts,
        };
        for other in [
            mv(5152, 6161, 3_500),
            mv(5151, 6162, 3_500),
            mv(5151, 6161, 4_001),
            denial(5151, sig, 6161, 3_500),
        ] {
            assert!(!expected.take(&other), "{other:?}");
        }
        assert!(expected.take(&mv(5151, 6161, 3_500)));
        assert!(!expected.take(&mv(5151, 6161, 3_500)), "consumed");
        assert!(expected.take(&denial(4242, sig, 100, 1_500)));
    }

    /// Lot 273b: the mover's exit statuses are the signal child's, and a
    /// run with nothing to spawn is inconclusive and leaves no cgroup.
    #[test]
    fn the_move_self_test_reads_its_children() {
        assert_eq!(run_move_child("/nonexistent/cgroup.procs", "1"), EXIT_OTHER);
        assert_eq!(run_move_child("/dev/null", "x"), EXIT_OTHER);
        assert_eq!(run_move_child("/dev/null", "1"), EXIT_DELIVERED);
        struct NoRoles;
        impl MoveRoles for NoRoles {
            fn register(&self, _pid: u32) -> Result<(), String> {
                Ok(())
            }
            fn evict(&self, _pid: u32) -> Result<(), String> {
                Ok(())
            }
        }
        let t = tempfile::tempdir().unwrap();
        let (o, _) = run_move(
            Path::new("/nonexistent/northnarrow-agent"),
            t.path(),
            &NoRoles,
        );
        assert!(matches!(o, SelfTestOutcome::Inconclusive(_)), "{o:?}");
        assert!(!t.path().join(MOVE_SELFTEST_CGROUP).exists());
        assert!(report_move(&SelfTestOutcome::Denied).is_none());
        let d = report_move(&SelfTestOutcome::NotDenied).unwrap();
        assert!(d.contains("attached but the kernel does not run it"), "{d}");
    }

    /// The self-test's denial is taken once, and only that one: another
    /// pid, signal, target, an earlier or later timestamp, another
    /// operation all reach the posture.
    #[test]
    fn only_the_self_tests_own_denial_is_taken() {
        let sig = SELFTEST_SIGNAL as u64;
        let expected = ExpectedDenial::arm(4242, 100, 1_000, 2_000);
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
            assert!(!expected.take(&other), "{other:?}");
        }
        assert!(
            !ExpectedDenial::default().take(&denial(4242, sig, 100, 1_500)),
            "another run's: nothing armed (R11c: no process-wide slot)"
        );
        assert!(expected.clone().take(&denial(4242, sig, 100, 1_500)));
        assert!(
            !expected.take(&denial(4242, sig, 100, 1_500)),
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
        let sh = |code: i32| {
            let mut c = Command::new("sh");
            c.arg("-c").arg(format!("exit {code}"));
            c
        };
        assert_eq!(
            run_command(sh(EXIT_DELIVERED), "sh").0,
            SelfTestOutcome::NotDenied
        );
        assert_eq!(
            run_command(sh(EXIT_DENIED), "sh").0,
            SelfTestOutcome::Denied
        );
        assert!(matches!(
            run(Path::new("/nonexistent/northnarrow-agent")).0,
            SelfTestOutcome::Inconclusive(_)
        ));
    }
}
