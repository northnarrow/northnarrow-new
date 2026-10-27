//! What the COMBAT ladder needs from the host it runs on (Wave 4
//! restructure, R08c, lab PR 252): a process captured when it is
//! attributed.
//!
//! The ladder acts on processes, not on PIDs (external audit CMB-004): it
//! captures an offender when it attributes it — the agent opens a pidfd on
//! the process and keeps the start `/proc` gives it
//! (`response::proc_ref::ProcRef`) — and every action reaches that process
//! or nothing, never a later holder of its PID. The ladder holds the
//! captures, asks whether an event names a captured process, drops the
//! descriptor of one that has exited, and hands them to its actuator, which
//! acts on them (`combat::actuator::CombatActuator`, the agent's
//! `SystemActuator`). The capture is the host's: an associated type of a
//! trait the host implements (the agent: `LinuxHost`, in its
//! `combat_host_linux` module, where the pidfd is), with the calls the
//! ladder made on `ProcRef` before R08c, the same arguments.
//!
//! The host is a type parameter of the ladder's types, as the posture's and
//! the engine's ([`crate::posture::host`], [`crate::decision::host`]): no
//! state, no global. The capture is a value the ladder holds and reads, so
//! what it reads of it is a trait of its own ([`Capture`]), with the method
//! names `ProcRef` has; how one is made is the host's static function
//! ([`CombatHost::open_for_event`]).

use std::fmt::Debug;

/// The host's capture of a process, for the ladder.
pub trait CombatHost: Copy + Default + Debug + Send + Sync + 'static {
    /// A process captured when the ladder attributes it (the agent: a pidfd
    /// and the start of the process, `ProcRef`).
    type Proc: Capture;

    /// The process `pid` names now, if it is the one an event reported:
    /// started at `start_ns` (an exec's start) — or, that unknown, started
    /// by `seen_ns` (the event's time: a process that started after the
    /// event holds a reused PID). `CLOCK_MONOTONIC` ns, 0 = unknown. The
    /// capture keeps `seen_ns` ([`Capture::matches_event`]); one of a
    /// process that has exited, or of another holder of the PID, reaches
    /// nothing.
    fn open_for_event(pid: u32, start_ns: u64, seen_ns: u64) -> Self::Proc;
}

/// A captured process: what the ladder reads of it and asks of it.
pub trait Capture: Debug + Send + Sync + 'static {
    /// The PID the process had when it was captured.
    fn pid(&self) -> u32;

    /// Its start, clock ticks since boot (`starttime` of
    /// `/proc/<pid>/stat`), when the capture read it.
    fn start_ticks(&self) -> Option<u64>;

    /// The start its event reported (`CLOCK_MONOTONIC` ns), when known.
    fn start_ns(&self) -> Option<u64>;

    /// A time it was known to be running (`CLOCK_MONOTONIC` ns: the event
    /// that attributed it), when known.
    fn seen_ns(&self) -> Option<u64>;

    /// Why the process could not be captured (the OS's error number), when
    /// it may still run: an action on it fails with this error instead of
    /// reporting the process gone.
    fn capture_errno(&self) -> Option<i32>;

    /// An event about this PID — with the process start it reported
    /// (`CLOCK_MONOTONIC` ns, 0 when unknown) — is about this process: it
    /// still runs; or it has exited and the start is its own; or the
    /// event's process had started by a time this one was running.
    fn matches_event(&self, start_ns: u64) -> bool;

    /// The process is still running (not exited, not a zombie).
    fn is_live(&self) -> bool;

    /// The capture still holds its descriptor of the process (the agent: a
    /// pidfd).
    fn has_fd(&self) -> bool;

    /// The same process without its descriptor: for one that has exited,
    /// whose descriptor holds nothing worth an open file.
    fn without_fd(&self) -> Self;
}

/// The ladder's own tests: the posture's portable test host
/// ([`crate::posture::host::testing::TestHost`]), whose capture is the
/// identity alone — the pid and the starts, no descriptor: nothing is
/// signalled and it never reads as running, as the agent's
/// `ProcRef::for_test`. What is Linux about the agent's capture (the
/// pidfd) is tested with its host, in the agent (`combat_host_linux`).
#[cfg(test)]
pub(crate) mod testing {
    use super::{Capture, CombatHost};
    use crate::posture::host::testing::TestHost;

    /// A capture without a descriptor.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub(crate) struct TestProc {
        pid: u32,
        start_ticks: Option<u64>,
        start_ns: Option<u64>,
        seen_ns: Option<u64>,
    }

    impl TestProc {
        /// The process `pid` with the start `start_ticks` (the tests' mocks
        /// compare an event's start with it).
        pub(crate) fn for_test(pid: u32, start_ticks: Option<u64>) -> Self {
            Self {
                pid,
                start_ticks,
                start_ns: None,
                seen_ns: None,
            }
        }
    }

    impl Capture for TestProc {
        fn pid(&self) -> u32 {
            self.pid
        }

        fn start_ticks(&self) -> Option<u64> {
            self.start_ticks
        }

        fn start_ns(&self) -> Option<u64> {
            self.start_ns
        }

        fn seen_ns(&self) -> Option<u64> {
            self.seen_ns
        }

        fn capture_errno(&self) -> Option<i32> {
            None
        }

        /// Not running: an event names it by its own start, or one that had
        /// started by a time it ran.
        fn matches_event(&self, start_ns: u64) -> bool {
            start_ns != 0
                && (self.start_ns == Some(start_ns)
                    || self.seen_ns.is_some_and(|seen| start_ns <= seen))
        }

        fn is_live(&self) -> bool {
            false
        }

        fn has_fd(&self) -> bool {
            false
        }

        fn without_fd(&self) -> Self {
            self.clone()
        }
    }

    /// A capture is the identity the event gave.
    impl CombatHost for TestHost {
        type Proc = TestProc;

        fn open_for_event(pid: u32, start_ns: u64, seen_ns: u64) -> TestProc {
            TestProc {
                pid,
                start_ticks: None,
                start_ns: (start_ns != 0).then_some(start_ns),
                seen_ns: (seen_ns != 0).then_some(seen_ns),
            }
        }
    }
}
