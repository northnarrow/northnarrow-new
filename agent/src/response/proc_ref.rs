//! [`ProcRef`] — a process, not a PID (external audit CMB-004).
//!
//! The response paths held bare PIDs: the COMBAT ladder attributed an
//! offender and killed it up to 30 s later, the tree kill signalled the
//! PIDs of a `/proc` snapshot, and a stand-down released by PID. A process
//! that exits frees its PID, and the kernel hands it to the next process
//! that asks — a harmless one could be blocked, released or killed in the
//! offender's place.
//!
//! A `ProcRef` opens a pidfd on the process when it is attributed and keeps
//! its start time. Signals go through `pidfd_send_signal(2)`: they reach
//! the process the pidfd was opened on, or nothing once it has exited —
//! never a later holder of the PID. Death is confirmed by polling the pidfd
//! (readable once the process has exited, zombie included) instead of
//! `kill(pid, 0)` plus sleeps. `pidfd_open` and `pidfd_send_signal` are in
//! every supported kernel (5.3 and later; the oldest supported is 5.14).
//! The watchdog has its own copy of the same three syscalls
//! (`watchdog/src/lib.rs`); `common` is shared with the no_std eBPF crate.

use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::time::Duration;

/// A process captured by its pidfd and start time.
#[derive(Debug)]
pub struct ProcRef {
    pid: u32,
    /// `starttime` from `/proc/<pid>/stat` (clock ticks since boot).
    start_ticks: Option<u64>,
    /// The start its event reported (`CLOCK_MONOTONIC` ns), when known.
    start_ns: Option<u64>,
    /// A time it was running (`CLOCK_MONOTONIC` ns: the event that
    /// attributed it). With no start known, a process that started after
    /// it is not this one.
    seen_ns: Option<u64>,
    /// `None`: the process had already exited when it was captured, or
    /// the PID then named another process — signals reach nothing.
    fd: Option<OwnedFd>,
    /// The capture failed although the process may run (`pidfd_open`
    /// out of descriptors or memory): a signal fails with this errno
    /// instead of reporting the process gone.
    errno: Option<i32>,
}

impl ProcRef {
    /// The process `pid` names now.
    pub fn open(pid: u32) -> ProcRef {
        Self::open_checked(pid, None)
    }

    /// The process `pid` names now, if it started at `start_ns`
    /// (`CLOCK_MONOTONIC`, as the sensors report it — `Event::ProcessSpawn
    /// ::start_ns`). A process with another start holds a reused PID: the
    /// result signals nothing. `start_ns == 0` (unknown) checks nothing.
    pub fn open_started_at(pid: u32, start_ns: u64) -> ProcRef {
        Self::open_checked(pid, (start_ns != 0).then_some(start_ns))
    }

    /// The process `pid` names now, if it is the one an event reported:
    /// started at `start_ns` (an exec's start) — or, that unknown, started
    /// by `seen_ns` (the event's time: a process that started after the
    /// event holds a reused PID). `CLOCK_MONOTONIC` ns, 0 = unknown. The
    /// reference keeps `seen_ns` (see [`Self::matches_event`]).
    pub fn open_for_event(pid: u32, start_ns: u64, seen_ns: u64) -> ProcRef {
        let r = Self::open_started_at(pid, start_ns).seen_at(seen_ns);
        if start_ns == 0
            && seen_ns != 0
            && r.has_fd()
            && r.start_ticks.is_some_and(|t| !started_by(t, seen_ns))
        {
            tracing::warn!(
                pid,
                "the pid now names a process that started after the event — not acted on"
            );
            return ProcRef::unopened(pid).seen_at(seen_ns);
        }
        r
    }

    /// The same reference, known to have been running at `seen_ns` (the
    /// event that attributed it, `CLOCK_MONOTONIC`; 0 = unknown).
    pub fn seen_at(mut self, seen_ns: u64) -> ProcRef {
        self.seen_ns = (seen_ns != 0).then_some(seen_ns);
        self
    }

    fn open_checked(pid: u32, start_ns: Option<u64>) -> ProcRef {
        let gone = ProcRef {
            start_ns,
            ..ProcRef::unopened(pid)
        };
        if pid == 0 {
            return gone;
        }
        let uncaptured = |errno: i32| {
            tracing::warn!(
                pid,
                error = %std::io::Error::from_raw_os_error(errno),
                "the process could not be captured — not acted on, reported failed"
            );
            ProcRef {
                start_ns,
                errno: Some(errno),
                ..ProcRef::unopened(pid)
            }
        };
        let raw = match pidfd_open(pid) {
            Ok(raw) => raw,
            Err(e) if e.raw_os_error() == Some(libc::ESRCH) => return gone,
            Err(e) => return uncaptured(e.raw_os_error().unwrap_or(libc::EIO)),
        };
        // SAFETY: pidfd_open returned this fd to us; we own it.
        let fd = unsafe { OwnedFd::from_raw_fd(raw) };
        // The pidfd pins the identity; `/proc/<pid>` read now describes
        // the same process as long as it has not exited — checked after
        // the read, since the PID cannot be reused before it is reaped.
        let stat = proc_stat(pid);
        let fits = |ticks: u64| start_ns.is_none_or(|ns| started_at(ticks, ns));
        if pidfd_exited(&fd) {
            // Exited. A zombie still describes itself in `/proc` (its PID
            // is held until it is reaped): its start is kept, the identity
            // the events of the children it left name.
            let start_ticks = stat
                .filter(|s| s.zombie)
                .map(|s| s.start_ticks)
                .filter(|t| fits(*t));
            return ProcRef {
                start_ticks,
                ..gone
            };
        }
        let Some(stat) = stat else {
            // running, but its `/proc` entry unreadable: no identity
            return uncaptured(libc::EIO);
        };
        if !fits(stat.start_ticks) {
            tracing::warn!(
                pid,
                "the pid now names another process (its start differs from the event's) — not acted on"
            );
            return gone;
        }
        ProcRef {
            start_ticks: Some(stat.start_ticks),
            fd: Some(fd),
            ..gone
        }
    }

    /// The PID only, not opened: for the actions that act by PID.
    pub fn unopened(pid: u32) -> ProcRef {
        ProcRef {
            pid,
            start_ticks: None,
            start_ns: None,
            seen_ns: None,
            fd: None,
            errno: None,
        }
    }

    /// A reference without a pidfd (unit tests: nothing is signalled).
    #[cfg(test)]
    pub(crate) fn for_test(pid: u32, start_ticks: Option<u64>) -> ProcRef {
        ProcRef {
            start_ticks,
            ..ProcRef::unopened(pid)
        }
    }

    pub fn pid(&self) -> u32 {
        self.pid
    }

    /// Whether this reference still holds a pidfd.
    pub fn has_fd(&self) -> bool {
        self.fd.is_some()
    }

    /// The same process without the pidfd: for one that has exited, whose
    /// descriptor holds nothing worth an open file (signals reach no one).
    pub fn without_fd(&self) -> ProcRef {
        ProcRef {
            pid: self.pid,
            start_ticks: self.start_ticks,
            start_ns: self.start_ns,
            seen_ns: self.seen_ns,
            fd: None,
            errno: self.errno,
        }
    }

    pub fn start_ticks(&self) -> Option<u64> {
        self.start_ticks
    }

    /// The start its event reported (`CLOCK_MONOTONIC` ns), when known
    /// (lab PR 245: the COMBAT ladder's rows name it).
    pub fn start_ns(&self) -> Option<u64> {
        self.start_ns
    }

    /// A time it was known to be running (`CLOCK_MONOTONIC` ns: the event
    /// that attributed it), when known.
    pub fn seen_ns(&self) -> Option<u64> {
        self.seen_ns
    }

    /// Why the process could not be captured (an errno), when it may
    /// still run.
    pub fn capture_errno(&self) -> Option<i32> {
        self.errno
    }

    /// An event about this PID — with the process start it reported
    /// (`CLOCK_MONOTONIC` ns, 0 when unknown) — is about this process: it
    /// still runs (its PID cannot have changed hands); or it has exited and
    /// the start is its own; or the event's process had started by a time
    /// this one was running (`seen_ns`: the PID was this one's then, and a
    /// later holder starts after this one is gone — a thread of this
    /// process, whose start differs, passes too). A lookup by PID alone
    /// also matches a later holder of the PID.
    pub fn matches_event(&self, start_ns: u64) -> bool {
        if self.is_live() {
            return true;
        }
        start_ns != 0
            && (self.start_ns == Some(start_ns)
                || self.start_ticks.is_some_and(|t| started_at(t, start_ns))
                || self.seen_ns.is_some_and(|seen| start_ns <= seen))
    }

    /// The process is still running (not exited, not a zombie).
    pub fn is_live(&self) -> bool {
        self.fd.as_ref().is_some_and(|fd| !pidfd_exited(fd))
    }

    /// `/proc/<pid>` still describes this process: it runs, and the PID's
    /// start time is the captured one. A PID written to a cgroup file
    /// right after this is this process (the PID cannot change hands
    /// while it runs).
    pub fn still_named_by_pid(&self) -> bool {
        self.is_live() && proc_start_ticks(self.pid) == self.start_ticks
    }

    /// Send `sig` to this process. `ESRCH` when it has exited (or the PID
    /// named no process when it was captured): the signal reached no one.
    /// A capture that failed returns its error.
    pub fn signal(&self, sig: libc::c_int) -> std::io::Result<()> {
        match &self.fd {
            Some(fd) => pidfd_signal(fd.as_raw_fd(), sig),
            None => Err(std::io::Error::from_raw_os_error(
                self.errno.unwrap_or(libc::ESRCH),
            )),
        }
    }

    /// Wait until the process has exited (zombie included), at most
    /// `timeout`. True once it has; false for a failed capture.
    pub fn wait_exit(&self, timeout: Duration) -> bool {
        let Some(fd) = &self.fd else {
            return self.errno.is_none();
        };
        let deadline = std::time::Instant::now() + timeout;
        loop {
            let mut pfd = libc::pollfd {
                fd: fd.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            };
            let left = deadline.saturating_duration_since(std::time::Instant::now());
            let ms = left.as_millis().min(i32::MAX as u128) as i32;
            // SAFETY: one valid pollfd for the duration of the call.
            let n = unsafe { libc::poll(&mut pfd, 1, ms) };
            if n < 0 && std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return n > 0 && pfd.revents & libc::POLLIN != 0;
        }
    }
}

/// What [`proc_stat`] reads from `/proc/<pid>/stat`.
#[derive(Debug, Clone, Copy)]
pub(crate) struct ProcStat {
    pub start_ticks: u64,
    /// State `Z` (or `X`): exited, not yet reaped.
    pub zombie: bool,
}

/// The state and start of process `pid`.
pub(crate) fn proc_stat(pid: u32) -> Option<ProcStat> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let state = stat.rsplit_once(')')?.1.split_whitespace().next()?;
    Some(ProcStat {
        start_ticks: stat_start_ticks(&stat)?,
        zombie: matches!(state, "Z" | "X" | "x"),
    })
}

/// `pidfd_open(2)`.
pub(crate) fn pidfd_open(pid: u32) -> std::io::Result<RawFd> {
    // SAFETY: a plain syscall taking a pid_t and flags; returns an fd.
    let ret = unsafe { libc::syscall(libc::SYS_pidfd_open, pid as libc::pid_t, 0u32) };
    if ret < 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(ret as RawFd)
    }
}

/// `pidfd_send_signal(2)`.
fn pidfd_signal(pidfd: RawFd, sig: libc::c_int) -> std::io::Result<()> {
    // SAFETY: a plain syscall on an fd we hold; a null siginfo is allowed.
    let ret = unsafe {
        libc::syscall(
            libc::SYS_pidfd_send_signal,
            pidfd,
            sig,
            std::ptr::null::<libc::siginfo_t>(),
            0u32,
        )
    };
    if ret < 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    }
}

/// The process behind `pidfd` has exited (a zombie, or reaped).
pub(crate) fn pidfd_exited(pidfd: &OwnedFd) -> bool {
    let mut pfd = libc::pollfd {
        fd: pidfd.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    // SAFETY: one valid pollfd, zero timeout.
    let n = unsafe { libc::poll(&mut pfd, 1, 0) };
    n > 0 && pfd.revents & libc::POLLIN != 0
}

/// `starttime`, field 22 of `/proc/<pid>/stat`, counted after the `(comm)`
/// field, which may itself hold spaces or parentheses.
pub fn proc_start_ticks(pid: u32) -> Option<u64> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    stat_start_ticks(&stat)
}

pub(crate) fn stat_start_ticks(stat: &str) -> Option<u64> {
    stat.rsplit_once(')')?
        .1
        .split_whitespace()
        .nth(19)?
        .parse()
        .ok()
}

/// Does a process with `/proc` start `ticks` (CLOCK_BOOTTIME, in clock
/// ticks) have the sensor start `start_ns` (CLOCK_MONOTONIC)? BOOTTIME runs
/// ahead of MONOTONIC by the time the host spent suspended before the
/// process started: between nothing and all of it so far. Two ticks of
/// slack for the rounding (the same test as the lineage cache's).
fn started_at(ticks: u64, start_ns: u64) -> bool {
    let tick = tick_ns();
    let shown = ticks.saturating_mul(tick);
    let slack = 2 * tick;
    shown + slack >= start_ns && shown <= start_ns + suspended_ns() + slack
}

/// Could a process with `/proc` start `ticks` (BOOTTIME) have started by
/// `seen_ns` (MONOTONIC)? False only when it surely started later, with
/// the host's suspended time and two ticks of slack in its favour.
fn started_by(ticks: u64, seen_ns: u64) -> bool {
    let tick = tick_ns();
    ticks.saturating_mul(tick) <= seen_ns + suspended_ns() + 2 * tick
}

fn tick_ns() -> u64 {
    // SAFETY: sysconf has no preconditions.
    let hz = unsafe { libc::sysconf(libc::_SC_CLK_TCK) };
    1_000_000_000 / if hz > 0 { hz as u64 } else { 100 }
}

/// `CLOCK_BOOTTIME` − `CLOCK_MONOTONIC` now.
fn suspended_ns() -> u64 {
    let now = |clock| {
        let mut ts = libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        // SAFETY: a valid clock id and a timespec to fill.
        unsafe { libc::clock_gettime(clock, &mut ts) };
        ts.tv_sec as u64 * 1_000_000_000 + ts.tv_nsec as u64
    };
    now(libc::CLOCK_BOOTTIME).saturating_sub(now(libc::CLOCK_MONOTONIC))
}

/// The start of process `pid` as the sensors report it (`CLOCK_MONOTONIC`
/// ns), from `/proc` — tests and callers without an event start.
pub fn proc_start_ns(pid: u32) -> Option<u64> {
    proc_start_ticks(pid).map(|t| t.saturating_mul(tick_ns()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::{Command, Stdio};

    fn sleeper() -> std::process::Child {
        Command::new("sleep")
            .arg("30")
            .stdout(Stdio::null())
            .spawn()
            .expect("spawn sleep")
    }

    /// External audit CMB-004: a reference to a process that has exited
    /// signals nothing — not the next holder of its PID.
    #[test]
    fn a_ref_to_an_exited_process_signals_nothing() {
        let mut child = sleeper();
        let r = ProcRef::open(child.id());
        assert!(r.is_live());
        child.kill().unwrap();
        child.wait().unwrap();
        assert!(!r.is_live());
        assert!(r.wait_exit(Duration::from_millis(10)));
        let err = r.signal(libc::SIGKILL).unwrap_err();
        assert_eq!(err.raw_os_error(), Some(libc::ESRCH));
        // a PID that names nothing: nothing captured
        let none = ProcRef::open(999_999_999);
        assert!(!none.is_live());
        assert!(none.signal(0).is_err());
    }

    /// A captured process is signalled through its pidfd, and its death
    /// is seen by polling it.
    #[test]
    fn signal_and_wait_through_the_pidfd() {
        let mut child = sleeper();
        let r = ProcRef::open(child.id());
        assert!(r.still_named_by_pid());
        r.signal(libc::SIGKILL).unwrap();
        assert!(r.wait_exit(Duration::from_secs(2)));
        child.wait().unwrap();
    }

    /// External audit CMB-004: an event's start time that does not match
    /// the process now holding the PID — a reused PID — captures nothing.
    #[test]
    fn a_start_from_another_process_captures_nothing() {
        let mut child = sleeper();
        let pid = child.id();
        let start = proc_start_ns(pid).unwrap();
        assert!(ProcRef::open_started_at(pid, start).is_live());
        // an hour later: another process (not earlier — a host up for
        // less than an hour has no "an hour earlier", and 0 is "unknown")
        let other = ProcRef::open_started_at(pid, start + 3_600_000_000_000);
        assert!(!other.is_live());
        assert!(other.signal(0).is_err());
        // unknown start: no check
        assert!(ProcRef::open_started_at(pid, 0).is_live());
        child.kill().unwrap();
        child.wait().unwrap();
    }

    /// A copy without the pidfd keeps the identity and signals nothing.
    #[test]
    fn a_copy_without_the_fd_keeps_the_identity() {
        let mut child = sleeper();
        let r = ProcRef::open(child.id());
        let closed = r.without_fd();
        assert!(r.has_fd() && !closed.has_fd());
        assert_eq!(closed.pid(), r.pid());
        assert_eq!(closed.start_ticks(), r.start_ticks());
        assert!(!closed.is_live());
        assert!(closed.signal(0).is_err());
        child.kill().unwrap();
        child.wait().unwrap();
    }

    /// External audit CMB-004: an event names this process while it runs,
    /// or, once it has exited, when the event's start is its own — not a
    /// process that took the PID after it.
    #[test]
    fn an_event_matches_the_process_by_its_start_once_it_has_exited() {
        let mut child = sleeper();
        let pid = child.id();
        let start = proc_start_ns(pid).unwrap();
        let other = start + 3_600_000_000_000;
        let r = ProcRef::open(pid);
        assert!(r.matches_event(0) && r.matches_event(start) && r.matches_event(other));
        child.kill().unwrap();
        child.wait().unwrap();
        assert!(r.matches_event(start), "its own start");
        assert!(!r.matches_event(other), "another process's start");
        assert!(!r.matches_event(0), "no start: the PID alone says nothing");
    }

    /// A process captured after it exited, before it was reaped (a zombie):
    /// its start is kept — the events of the children it left name it.
    #[test]
    fn a_zombie_is_captured_with_its_start() {
        let mut child = sleeper();
        let pid = child.id();
        let start = proc_start_ns(pid).unwrap();
        let ticks = proc_start_ticks(pid);
        // SAFETY: plain kill(2) on our own child, not reaped yet.
        unsafe { libc::kill(pid as i32, libc::SIGKILL) };
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while !proc_stat(pid).is_some_and(|s| s.zombie) {
            assert!(std::time::Instant::now() < deadline, "no zombie");
            std::thread::sleep(Duration::from_millis(5));
        }
        let r = ProcRef::open(pid);
        assert!(!r.is_live() && !r.has_fd());
        assert_eq!(r.start_ticks(), ticks);
        assert!(r.matches_event(start));
        assert!(!r.matches_event(start + 3_600_000_000_000));
        assert_eq!(r.signal(0).unwrap_err().raw_os_error(), Some(libc::ESRCH));
        child.wait().unwrap();
    }

    /// External audit CMB-004: what an event says about a process that is
    /// gone when it is captured still identifies it — the start of its
    /// exec, or a time it was running.
    #[test]
    fn a_gone_process_keeps_what_its_event_said() {
        let gone = ProcRef::open_started_at(999_999_999, 12_345);
        assert!(!gone.is_live());
        assert!(gone.matches_event(12_345));
        assert!(!gone.matches_event(12_346));
        let seen = ProcRef::open(999_999_999).seen_at(1_000);
        assert!(
            seen.matches_event(999),
            "started before it was seen running"
        );
        assert!(!seen.matches_event(1_001), "started after: another process");
        assert!(!seen.matches_event(0));
        // its start known, another start before the time it was seen: a
        // thread of it (the PID was its own then)
        let both = ProcRef::open_started_at(999_999_999, 500).seen_at(1_000);
        assert!(both.matches_event(500) && both.matches_event(700));
        assert!(!both.matches_event(1_001));
        assert!(
            !ProcRef::open(999_999_999).matches_event(5),
            "nothing known"
        );
    }

    /// External audit CMB-004: an event without the process's start (not
    /// an exec) still has its time — a process that started after the
    /// event holds a reused PID, and is not captured.
    #[test]
    fn a_process_started_after_the_event_is_not_captured() {
        let mut child = sleeper();
        let pid = child.id();
        let start = proc_start_ns(pid).unwrap();
        // the event an hour after the start: this process
        assert!(ProcRef::open_for_event(pid, 0, start + 3_600_000_000_000).is_live());
        // the event a second before it started: another process
        let before = ProcRef::open_for_event(pid, 0, start.saturating_sub(1_000_000_000).max(1));
        if start > 1_000_000_000 {
            assert!(!before.is_live());
            assert!(before.signal(0).is_err());
        }
        // nothing known: no check
        assert!(ProcRef::open_for_event(pid, 0, 0).is_live());
        child.kill().unwrap();
        child.wait().unwrap();
    }

    /// A capture that failed (the agent out of descriptors) is not a
    /// process that has exited: a kill reports the error.
    #[test]
    fn a_failed_capture_is_not_reported_gone() {
        let r = ProcRef {
            errno: Some(libc::EMFILE),
            ..ProcRef::unopened(4242)
        };
        assert_eq!(
            r.signal(libc::SIGKILL).unwrap_err().raw_os_error(),
            Some(libc::EMFILE)
        );
        assert!(!r.wait_exit(Duration::from_millis(1)));
        assert!(!r.is_live() && !r.matches_event(0));
        assert_eq!(r.capture_errno(), Some(libc::EMFILE));
        assert!(ProcRef::unopened(4242).capture_errno().is_none());
    }

    #[test]
    fn start_ticks_survive_a_comm_with_spaces_and_parens() {
        let stat = "42 (a b) c) S 1 42 42 0 -1 4194560 100 0 0 0 0 0 0 0 20 0 1 0 98765 1000 100";
        assert_eq!(stat_start_ticks(stat), Some(98765));
    }
}
