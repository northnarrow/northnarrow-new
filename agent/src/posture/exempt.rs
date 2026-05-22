//! Posture-trigger PID exemptions for the NorthNarrow process stack
//! (Beta Step 3).
//!
//! The defender must never classify *its own* process stack's activity
//! as adversary behaviour. PR #123 already excludes the agent's own
//! PID from the trigger detector (its continuous state-log writes
//! otherwise self-trip the mass-write heuristic into COMBAT — see the
//! [`super::triggers::TriggerDetector`] docs). The sibling
//! **watchdog** is the same class of problem (T7.13 "watchdog start
//! cascade"): the watchdog reads `/proc/<agent>`, the pinned bpffs map
//! and `/run/northnarrow`, and those reads land back in the event
//! stream as activity from a non-agent PID — escalating posture on a
//! benign host.
//!
//! ## Why PID + exe-path, not comm
//!
//! `comm` is attacker-controllable (`prctl(PR_SET_NAME, …)`), so
//! exempting by comm would let any process rename itself
//! `northnarrow-wat` to gain posture-trigger immunity — the exact
//! bypass the watchdog supervisor model exists to prevent. We instead
//! key on the **PID** published in the root-only
//! `/run/northnarrow/watchdog.pid`, and additionally verify that
//! `/proc/<pid>/exe` (a kernel-resolved symlink, not forgeable from
//! userspace) points at the installed watchdog binary. That closes
//! both the spoofed-comm bypass and the PID-reuse race (a recycled PID
//! belonging to some other binary fails the exe check).
//!
//! The watchdog starts *after* the agent and can be restarted, so the
//! verified PID is held in an [`AtomicU32`] and refreshed on a timer
//! by `main.rs`; this struct is the cheap, `Clone`-able shared handle
//! both the timer and the [`super::PostureMachine`] hold.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;

/// Default install path of the watchdog binary, used to verify a
/// candidate PID's `/proc/<pid>/exe`. Overridable (non-standard
/// install layouts) via the agent's `--watchdog-exe` flag.
pub const DEFAULT_WATCHDOG_EXE: &str = "/usr/local/bin/northnarrow-watchdog";

/// Default path of the watchdog's PID file (written by the watchdog
/// into its root-only RuntimeDirectory). Overridable via
/// `--watchdog-pidfile`.
pub const DEFAULT_WATCHDOG_PIDFILE: &str = "/run/northnarrow/watchdog.pid";

/// Cheap, `Clone`-able set of PIDs belonging to the NorthNarrow
/// process stack that posture triggers must ignore.
///
/// `None` inner = no exemptions (preserves the pre-PR-#123 behaviour
/// for `TriggerDetector::new`). The agent PID is fixed at construction;
/// the watchdog PID is mutated in place by the refresh task.
#[derive(Debug, Clone, Default)]
pub struct ExemptPids {
    inner: Option<Arc<ExemptInner>>,
}

#[derive(Debug)]
struct ExemptInner {
    /// The agent's own PID. Never zero; never changes.
    agent_pid: u32,
    /// The verified watchdog PID, or 0 when no watchdog is currently
    /// verified (not started, stopped, or failed verification).
    watchdog_pid: AtomicU32,
}

impl ExemptPids {
    /// Exempt the agent's own PID. The watchdog slot starts empty.
    pub fn with_agent(agent_pid: u32) -> Self {
        Self {
            inner: Some(Arc::new(ExemptInner {
                agent_pid,
                watchdog_pid: AtomicU32::new(0),
            })),
        }
    }

    /// Is `pid` part of the NorthNarrow stack (agent or verified
    /// watchdog)? PID 0 is never exempt (it is the "no watchdog"
    /// sentinel, and never a real event owner).
    pub fn is_exempt(&self, pid: u32) -> bool {
        if pid == 0 {
            return false;
        }
        match &self.inner {
            None => false,
            Some(i) => pid == i.agent_pid || i.watchdog_pid.load(Ordering::Relaxed) == pid,
        }
    }

    /// Store (or clear, with 0) the verified watchdog PID. No-op on a
    /// default (`with_agent` was never called) handle.
    pub fn set_watchdog_pid(&self, pid: u32) {
        if let Some(i) = &self.inner {
            i.watchdog_pid.store(pid, Ordering::Relaxed);
        }
    }

    /// Current verified watchdog PID, or `None` when unset.
    pub fn watchdog_pid(&self) -> Option<u32> {
        match &self.inner {
            Some(i) => match i.watchdog_pid.load(Ordering::Relaxed) {
                0 => None,
                p => Some(p),
            },
            None => None,
        }
    }
}

/// Outcome of resolving the watchdog PID from its pidfile + exe check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WatchdogResolution {
    /// Pidfile present, PID live, and `/proc/<pid>/exe` matched the
    /// expected binary. Safe to exempt.
    Verified(u32),
    /// Pidfile absent — watchdog not started or operator-stopped. Not
    /// an error; just nothing to exempt.
    NotPresent,
    /// Pidfile present but unparseable.
    InvalidPidfile { reason: String },
    /// PID present but `/proc/<pid>/exe` could not be read (PID gone —
    /// e.g. a refresh race) — do not exempt.
    Unverifiable { pid: u32, reason: String },
    /// `/proc/<pid>/exe` resolved to a *different* binary than
    /// expected (PID reuse, or substitution). Must NOT exempt.
    ExeMismatch { pid: u32, resolved: PathBuf },
}

/// Resolve and verify the current watchdog PID.
///
/// Reads `pidfile`, then `readlink(/proc/<pid>/exe)` and compares it to
/// `expected_exe`. Pure w.r.t. its inputs (the `/proc` and pidfile
/// paths are taken as arguments) so the parse/compare logic is unit
/// testable; the `proc_root` indirection lets tests point at a fixture
/// tree instead of the live `/proc`.
pub fn resolve_verified_watchdog_pid(
    pidfile: &Path,
    expected_exe: &Path,
) -> WatchdogResolution {
    resolve_with_proc_root(pidfile, expected_exe, Path::new("/proc"))
}

pub(crate) fn resolve_with_proc_root(
    pidfile: &Path,
    expected_exe: &Path,
    proc_root: &Path,
) -> WatchdogResolution {
    let text = match fs::read_to_string(pidfile) {
        Ok(t) => t,
        Err(_) => return WatchdogResolution::NotPresent,
    };
    let pid: u32 = match text.trim().parse() {
        Ok(p) => p,
        Err(e) => {
            return WatchdogResolution::InvalidPidfile {
                reason: format!("{e}"),
            }
        }
    };
    let exe_link = proc_root.join(pid.to_string()).join("exe");
    let resolved = match fs::read_link(&exe_link) {
        Ok(p) => p,
        Err(e) => {
            return WatchdogResolution::Unverifiable {
                pid,
                reason: format!("readlink {}: {e}", exe_link.display()),
            }
        }
    };
    // `/proc/<pid>/exe` carries a " (deleted)" suffix if the binary was
    // replaced on disk while running; treat that as a mismatch — a
    // deleted/swapped watchdog binary is exactly what we must not trust.
    if resolved == expected_exe {
        WatchdogResolution::Verified(pid)
    } else {
        WatchdogResolution::ExeMismatch { pid, resolved }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn default_handle_exempts_nothing() {
        let e = ExemptPids::default();
        assert!(!e.is_exempt(1));
        assert!(!e.is_exempt(4242));
        e.set_watchdog_pid(99); // no-op on default handle
        assert_eq!(e.watchdog_pid(), None);
    }

    #[test]
    fn agent_pid_always_exempt_watchdog_when_set() {
        let e = ExemptPids::with_agent(1000);
        assert!(e.is_exempt(1000));
        assert!(!e.is_exempt(2000));
        e.set_watchdog_pid(2000);
        assert!(e.is_exempt(2000));
        assert_eq!(e.watchdog_pid(), Some(2000));
        // Clearing the watchdog PID drops the exemption.
        e.set_watchdog_pid(0);
        assert!(!e.is_exempt(2000));
        assert!(e.is_exempt(1000));
    }

    #[test]
    fn pid_zero_never_exempt() {
        let e = ExemptPids::with_agent(1000);
        assert!(!e.is_exempt(0));
    }

    #[test]
    fn clone_shares_watchdog_slot() {
        let a = ExemptPids::with_agent(1000);
        let b = a.clone();
        a.set_watchdog_pid(3333);
        // The clone sees the update — same Arc-backed atomic.
        assert!(b.is_exempt(3333));
    }

    fn write_pidfile(dir: &Path, pid: &str) -> PathBuf {
        let p = dir.join("watchdog.pid");
        let mut f = fs::File::create(&p).unwrap();
        writeln!(f, "{pid}").unwrap();
        p
    }

    #[test]
    fn resolve_not_present_when_pidfile_missing() {
        let tmp = std::env::temp_dir().join(format!("nn-exempt-{}", std::process::id()));
        let _ = fs::create_dir_all(&tmp);
        let missing = tmp.join("nope.pid");
        assert_eq!(
            resolve_verified_watchdog_pid(&missing, Path::new(DEFAULT_WATCHDOG_EXE)),
            WatchdogResolution::NotPresent
        );
    }

    #[test]
    fn resolve_invalid_pidfile() {
        let tmp = std::env::temp_dir().join(format!("nn-exempt-inv-{}", std::process::id()));
        let _ = fs::create_dir_all(&tmp);
        let pf = write_pidfile(&tmp, "not-a-number");
        assert!(matches!(
            resolve_verified_watchdog_pid(&pf, Path::new(DEFAULT_WATCHDOG_EXE)),
            WatchdogResolution::InvalidPidfile { .. }
        ));
        let _ = fs::remove_dir_all(&tmp);
    }

    #[test]
    fn resolve_verified_when_exe_matches() {
        // Use the test process itself: /proc/self/exe resolves to the
        // test binary; point `expected_exe` at that same target and the
        // pidfile at our own PID.
        let tmp = std::env::temp_dir().join(format!("nn-exempt-ok-{}", std::process::id()));
        let _ = fs::create_dir_all(&tmp);
        let my_pid = std::process::id();
        let pf = write_pidfile(&tmp, &my_pid.to_string());
        let my_exe = fs::read_link("/proc/self/exe").expect("read /proc/self/exe");
        match resolve_verified_watchdog_pid(&pf, &my_exe) {
            WatchdogResolution::Verified(p) => assert_eq!(p, my_pid),
            other => panic!("expected Verified, got {other:?}"),
        }
        let _ = fs::remove_dir_all(&tmp);
    }

    #[test]
    fn resolve_mismatch_when_exe_differs() {
        let tmp = std::env::temp_dir().join(format!("nn-exempt-mm-{}", std::process::id()));
        let _ = fs::create_dir_all(&tmp);
        let pf = write_pidfile(&tmp, &std::process::id().to_string());
        // Expect a binary the test process certainly is not.
        let res = resolve_verified_watchdog_pid(&pf, Path::new("/usr/bin/definitely-not-us"));
        assert!(matches!(res, WatchdogResolution::ExeMismatch { .. }));
        let _ = fs::remove_dir_all(&tmp);
    }

    #[test]
    fn resolve_unverifiable_when_pid_dead() {
        let tmp = std::env::temp_dir().join(format!("nn-exempt-dead-{}", std::process::id()));
        let _ = fs::create_dir_all(&tmp);
        // PID 0 has no /proc/0/exe; readlink fails → Unverifiable.
        let pf = write_pidfile(&tmp, "0");
        assert!(matches!(
            resolve_verified_watchdog_pid(&pf, Path::new(DEFAULT_WATCHDOG_EXE)),
            WatchdogResolution::Unverifiable { pid: 0, .. }
        ));
        let _ = fs::remove_dir_all(&tmp);
    }
}
