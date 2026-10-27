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
//!
//! External audit POS-009: the exe check runs only at that refresh, every
//! 30 s, while the exemption was a bare PID compare: a process given the
//! watchdog's PID in between raised no posture trigger at all, the
//! decisive `AntiTamperDenial` included. The refresh now records the
//! watchdog's start time with its PID, and [`ExemptPids::is_exempt`]
//! re-reads it for the watchdog's PID (one `/proc/<pid>/stat` read per
//! event that PID owns): a recycled PID starts later and is not exempt.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;

use nn_core::posture::host::PostureHost;

/// R08a (lab PR 250): the host the exemption reads through, the agent's,
/// until it moves to nn-core and takes it as a type parameter.
use crate::chain_host_linux::LinuxHost as H;

/// Fallback install path of the watchdog binary, used to verify a
/// candidate PID's `/proc/<pid>/exe` when [`sibling_watchdog_exe`]
/// finds no watchdog next to the agent. Overridable via the agent's
/// `--watchdog-exe` flag.
pub const DEFAULT_WATCHDOG_EXE: &str = "/usr/local/bin/northnarrow-watchdog";

/// Review 26: the watchdog is installed next to the agent — in
/// `/usr/local/bin` by `install.sh`, in `/usr/bin` by a distro package.
/// Resolve it from the agent's own (canonical) executable path; fall
/// back to [`DEFAULT_WATCHDOG_EXE`] when that sibling does not exist.
pub fn sibling_watchdog_exe(own_exe: Option<&Path>) -> PathBuf {
    own_exe
        .and_then(Path::parent)
        .map(|dir| dir.join("northnarrow-watchdog"))
        .filter(|p| H::exists(p))
        .unwrap_or_else(|| PathBuf::from(DEFAULT_WATCHDOG_EXE))
}

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
    /// External audit POS-009: the verified watchdog's start time (field
    /// 22 of `/proc/<pid>/stat`, clock ticks since boot). Stored before
    /// the PID (Release on the PID, Acquire on its load), so a reader that
    /// sees a PID sees its start or a later one — a torn pair fails toward
    /// not exempt.
    watchdog_start: AtomicU64,
    /// `/proc` (a fixture tree in tests).
    proc_root: PathBuf,
}

impl ExemptPids {
    /// Exempt the agent's own PID. The watchdog slot starts empty.
    pub fn with_agent(agent_pid: u32) -> Self {
        Self::with_agent_on(agent_pid, Path::new(H::PROC_ROOT))
    }

    /// [`Self::with_agent`], reading the watchdog's start from
    /// `proc_root` (tests).
    pub(crate) fn with_agent_on(agent_pid: u32, proc_root: &Path) -> Self {
        Self {
            inner: Some(Arc::new(ExemptInner {
                agent_pid,
                watchdog_pid: AtomicU32::new(0),
                watchdog_start: AtomicU64::new(0),
                proc_root: proc_root.to_path_buf(),
            })),
        }
    }

    /// Is `pid` part of the NorthNarrow stack (agent or verified
    /// watchdog)? PID 0 is never exempt (it is the "no watchdog"
    /// sentinel, and never a real event owner).
    ///
    /// External audit POS-009: the watchdog's PID only while the process
    /// it names has the start time recorded when it was verified — a PID
    /// recycled between two refreshes is not exempt. A start that cannot
    /// be read (the process is gone) is not exempt either.
    pub fn is_exempt(&self, pid: u32) -> bool {
        if pid == 0 {
            return false;
        }
        let Some(i) = &self.inner else {
            return false;
        };
        if pid == i.agent_pid {
            return true;
        }
        if i.watchdog_pid.load(Ordering::Acquire) != pid {
            return false;
        }
        let start = i.watchdog_start.load(Ordering::Relaxed);
        proc_start_ticks(&i.proc_root, pid) == Some(start)
    }

    /// External audit POS-009: `pid` is the agent's own — exempt from
    /// every trigger, a kernel denial included (a COMBAT against itself
    /// would be worse than the signal is worth).
    pub fn is_agent(&self, pid: u32) -> bool {
        pid != 0 && self.inner.as_ref().is_some_and(|i| i.agent_pid == pid)
    }

    /// Store the verified watchdog: its PID and the start time it was
    /// verified with ([`WatchdogResolution::Verified`]). No-op on a
    /// default (`with_agent` was never called) handle.
    pub fn set_watchdog(&self, pid: u32, start_ticks: u64) {
        if let Some(i) = &self.inner {
            i.watchdog_start.store(start_ticks, Ordering::Relaxed);
            i.watchdog_pid.store(pid, Ordering::Release);
        }
    }

    /// Clear the watchdog slot: no watchdog is verified.
    pub fn clear_watchdog(&self) {
        if let Some(i) = &self.inner {
            i.watchdog_pid.store(0, Ordering::Release);
        }
    }

    /// Current verified watchdog PID, or `None` when unset.
    pub fn watchdog_pid(&self) -> Option<u32> {
        match &self.inner {
            Some(i) => match i.watchdog_pid.load(Ordering::Acquire) {
                0 => None,
                p => Some(p),
            },
            None => None,
        }
    }
}

/// `starttime`, field 22 of `<proc_root>/<pid>/stat`, counted after the
/// `(comm)` field, which may itself hold spaces or parentheses.
fn proc_start_ticks(proc_root: &Path, pid: u32) -> Option<u64> {
    let stat = H::read_to_string(proc_root.join(pid.to_string()).join("stat")).ok()?;
    stat.rsplit_once(')')?
        .1
        .split_whitespace()
        .nth(19)?
        .parse()
        .ok()
}

/// Outcome of resolving the watchdog PID from its pidfile + exe check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WatchdogResolution {
    /// Pidfile present, PID live, and `/proc/<pid>/exe` matched the
    /// expected binary. Safe to exempt — that process, the one started at
    /// `start_ticks` (external audit POS-009).
    Verified { pid: u32, start_ticks: u64 },
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
pub fn resolve_verified_watchdog_pid(pidfile: &Path, expected_exe: &Path) -> WatchdogResolution {
    resolve_with_proc_root(pidfile, expected_exe, Path::new(H::PROC_ROOT))
}

pub(crate) fn resolve_with_proc_root(
    pidfile: &Path,
    expected_exe: &Path,
    proc_root: &Path,
) -> WatchdogResolution {
    let text = match H::read_to_string(pidfile) {
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
    let resolved = match H::read_link(&exe_link) {
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
    if resolved != expected_exe {
        return WatchdogResolution::ExeMismatch { pid, resolved };
    }
    // External audit POS-009: the start of the process just verified. Read
    // after the exe: a PID recycled in between starts later, and the
    // exemption then names a start no process has (fails toward not
    // exempt) until the next refresh.
    match proc_start_ticks(proc_root, pid) {
        Some(start_ticks) => WatchdogResolution::Verified { pid, start_ticks },
        None => WatchdogResolution::Unverifiable {
            pid,
            reason: format!("no start time in {}/{pid}/stat", proc_root.display()),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::io::Write;

    /// `<proc_root>/<pid>/stat` with `starttime` (field 22) at `ticks`.
    fn write_started(proc_root: &Path, pid: u32, ticks: u64) {
        let dir = proc_root.join(pid.to_string());
        fs::create_dir_all(&dir).unwrap();
        fs::write(
            dir.join("stat"),
            format!("{pid} (northnarrow-wa) S 1 1 1 0 -1 4194560 0 0 0 0 0 0 0 0 20 0 1 0 {ticks} 0 0\n"),
        )
        .unwrap();
    }

    #[test]
    fn default_handle_exempts_nothing() {
        let e = ExemptPids::default();
        assert!(!e.is_exempt(1));
        assert!(!e.is_exempt(4242));
        e.set_watchdog(99, 1); // no-op on default handle
        assert_eq!(e.watchdog_pid(), None);
        assert!(!e.is_agent(4242));
    }

    #[test]
    fn agent_pid_always_exempt_watchdog_when_set() {
        let tmp = tempfile::tempdir().unwrap();
        write_started(tmp.path(), 2000, 5_000);
        let e = ExemptPids::with_agent_on(1000, tmp.path());
        assert!(e.is_exempt(1000));
        assert!(e.is_agent(1000));
        assert!(!e.is_exempt(2000));
        e.set_watchdog(2000, 5_000);
        assert!(e.is_exempt(2000));
        assert!(!e.is_agent(2000));
        assert_eq!(e.watchdog_pid(), Some(2000));
        // Clearing the watchdog PID drops the exemption.
        e.clear_watchdog();
        assert!(!e.is_exempt(2000));
        assert!(e.is_exempt(1000));
    }

    #[test]
    fn pid_zero_never_exempt() {
        let e = ExemptPids::with_agent(1000);
        assert!(!e.is_exempt(0));
        assert!(!e.is_agent(0));
    }

    #[test]
    fn clone_shares_watchdog_slot() {
        let tmp = tempfile::tempdir().unwrap();
        write_started(tmp.path(), 3333, 77);
        let a = ExemptPids::with_agent_on(1000, tmp.path());
        let b = a.clone();
        a.set_watchdog(3333, 77);
        // The clone sees the update — same Arc-backed atomic.
        assert!(b.is_exempt(3333));
    }

    /// External audit POS-009: between two 30-s refreshes the slot still
    /// names the watchdog's PID; a process given that PID since starts
    /// later and is not exempt, nor is a PID whose process is gone.
    #[test]
    fn a_recycled_watchdog_pid_is_not_exempt() {
        let tmp = tempfile::tempdir().unwrap();
        write_started(tmp.path(), 2000, 5_000);
        let e = ExemptPids::with_agent_on(1000, tmp.path());
        e.set_watchdog(2000, 5_000);
        assert!(e.is_exempt(2000), "the verified watchdog");
        write_started(tmp.path(), 2000, 9_000);
        assert!(!e.is_exempt(2000), "the same PID, a later process");
        fs::remove_dir_all(tmp.path().join("2000")).unwrap();
        assert!(!e.is_exempt(2000), "nothing at that PID");
        assert!(e.is_exempt(1000), "the agent stays exempt");
    }

    /// External audit POS-009: the refresh records the start of the
    /// process whose exe it verified.
    #[test]
    fn a_verified_watchdog_carries_its_start() {
        let tmp = tempfile::tempdir().unwrap();
        let proc_root = tmp.path().join("proc");
        write_started(&proc_root, 2000, 5_000);
        std::os::unix::fs::symlink(DEFAULT_WATCHDOG_EXE, proc_root.join("2000/exe")).unwrap();
        let pf = write_pidfile(tmp.path(), "2000");
        assert_eq!(
            resolve_with_proc_root(&pf, Path::new(DEFAULT_WATCHDOG_EXE), &proc_root),
            WatchdogResolution::Verified {
                pid: 2000,
                start_ticks: 5_000
            }
        );
        fs::remove_file(proc_root.join("2000/stat")).unwrap();
        assert!(matches!(
            resolve_with_proc_root(&pf, Path::new(DEFAULT_WATCHDOG_EXE), &proc_root),
            WatchdogResolution::Unverifiable { pid: 2000, .. }
        ));
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
            WatchdogResolution::Verified { pid, start_ticks } => {
                assert_eq!(pid, my_pid);
                assert_eq!(
                    Some(start_ticks),
                    proc_start_ticks(Path::new("/proc"), my_pid)
                );
            }
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

    /// Review 26: the watchdog is resolved next to the agent, whatever the
    /// install layout; without a sibling the fixed default applies.
    #[test]
    fn sibling_watchdog_exe_follows_the_agent_layout() {
        let dir = tempfile::tempdir().unwrap();
        let agent = dir.path().join("northnarrow-agent");
        fs::write(&agent, b"").unwrap();
        assert_eq!(
            sibling_watchdog_exe(Some(&agent)),
            PathBuf::from(DEFAULT_WATCHDOG_EXE),
            "no sibling yet: fixed default"
        );
        let wd = dir.path().join("northnarrow-watchdog");
        fs::write(&wd, b"").unwrap();
        assert_eq!(sibling_watchdog_exe(Some(&agent)), wd);
        assert_eq!(
            sibling_watchdog_exe(None),
            PathBuf::from(DEFAULT_WATCHDOG_EXE)
        );
    }
}
