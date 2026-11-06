//! Lot 288 (#125): the agent's stop ends in bounded time.
//!
//! From the moment the event loop ends (a signal, the admin shutdown, a
//! dead pump) the stop has [`BUDGET`]`.total` (2 s) to end the process: what
//! follows its exit — the kernel's release of the agent's BPF programs and
//! links, 2.4 s measured on ubuntu2404 (lot 288's lab) — must fit in
//! systemd's `TimeoutStopSec` of the unit (5 s) too ([`KERNEL_RELEASE`]).
//! Each stage of the stop that waits is bounded by what is left of it
//! ([`StopDeadline::drain_bound`], [`StopDeadline::left`]); a stage that
//! blocks anyway (a thread that does not come back to be joined, a lock
//! held, a drop that waits) is cut by the deadline's own thread at the
//! note's point:
//!
//! - before the stop's signed rows are written, it signs a note if the
//!   audit chain is still writable ([`audit_note`]), then the process exits
//!   with [`EXIT_STATUS`] — at [`BUDGET`]`.total` at the latest, whatever
//!   the note does;
//! - after them ([`StopDeadline::evidence_done`]) what is left is the
//!   release of the process's resources, which its exit does in the kernel:
//!   the process exits with the stop's own status, no note.
//!
//! The COMBAT isolation is never touched by the stop: the iptables chain
//! stays as the run left it (the stop runs no `iptables`, and an exit cuts
//! no table half-way: `iptables-restore` commits a table at once), and the
//! next start finds it, tears it down and signs `combat_reconcile` (Beta
//! Step 4a, external audit MAIN-013). An agent that dies in COMBAT leaves
//! the host isolated until then.

use std::sync::Arc;
use std::time::{Duration, Instant};

use parking_lot::{Condvar, Mutex};
use tracing::{error, warn};

use crate::anti_tamper::network_isolate::NetworkIsolator;

/// The stop's budget and the parts of it kept for its signed rows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Budget {
    /// From the end of the event loop to the process's exit.
    pub(crate) total: Duration,
    /// The end of `total`, kept for the deadline's note: it starts when
    /// only this much is left and the stop has not ended.
    pub(crate) note: Duration,
    /// Before the note's part, kept for the stop's own signed rows (the
    /// `agent_stop`, the heads anchored at stop): the stages that drain
    /// end before it ([`StopDeadline::drain_bound`]).
    pub(crate) evidence: Duration,
}

/// systemd's `TimeoutStopSec` of `northnarrow-agent.service` (a test reads
/// it from the unit): with `SendSIGKILL=no`, a stop job (the host's
/// shutdown) leaves a process still there after it running; install.sh's
/// and uninstall.sh's stop (`systemctl kill -s SIGTERM` in the window)
/// sends SIGKILL after 10 s.
pub(crate) const UNIT_TIMEOUT_STOP: Duration = Duration::from_secs(5);

/// What the kernel takes, after the process's exit, to release the agent's
/// BPF programs and links (the trampolines of its fentry/fexit and LSM
/// programs, its kprobes, tracepoints and rings) — or what the agent's own
/// drops take to detach them: 2.4 s on ubuntu2404, kernel 6.8, in both
/// cases (lot 288's lab: an `_exit` at 3.25 s seen by systemd at 5.67 s, a
/// clean stop's drops 2.37 s), kept with a margin.
pub(crate) const KERNEL_RELEASE: Duration = Duration::from_secs(3);

/// The agent's: 2 s in all — [`UNIT_TIMEOUT_STOP`] less
/// [`KERNEL_RELEASE`]; the last 0.5 s for the note, the 0.5 s before it for
/// the stop's signed rows, the first second for what drains.
pub(crate) const BUDGET: Budget = Budget {
    total: UNIT_TIMEOUT_STOP.saturating_sub(KERNEL_RELEASE),
    note: Duration::from_millis(500),
    evidence: Duration::from_millis(500),
};

/// What the note waits for the audit log's lock: a stage that holds it
/// past this is the stage that blocks, and the chain is not writable.
pub(crate) const NOTE_LOCK_WAIT: Duration = Duration::from_millis(250);

/// The exit status of a stop cut at its deadline (sysexits' `EX_TEMPFAIL`).
pub(crate) const EXIT_STATUS: i32 = 75;

/// The signed degradation's `source`.
pub(crate) const SOURCE: &str = "stop_deadline";

/// What the note is told: why the stop began, the stage it was in, how
/// long it had run, whether its `agent_stop` was already signed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Expired {
    pub(crate) reason: &'static str,
    pub(crate) stage: &'static str,
    pub(crate) after: Duration,
    pub(crate) stop_signed: bool,
    pub(crate) budget: Budget,
}

/// The note, run once on a thread of its own when the deadline expires.
pub(crate) type Note = Box<dyn FnOnce(&Expired) + Send>;

/// How the process ends at the deadline (the tests' records the call).
pub(crate) type Exit = Arc<dyn Fn(i32) + Send + Sync>;

/// The stop's deadline: made idle at the start (its thread exists before
/// anything could keep one from starting), begun when the event loop ends.
pub(crate) struct StopDeadline {
    shared: Arc<Shared>,
}

struct Shared {
    budget: Budget,
    state: Mutex<State>,
    wake: Condvar,
}

#[derive(Default)]
struct State {
    begun: Option<(Instant, &'static str)>,
    note: Option<Note>,
    stage: &'static str,
    stop_signed: bool,
    /// The stop's signed rows are written: its exit status.
    evidence_done: Option<i32>,
    finished: bool,
    fired: bool,
    noted: bool,
    exited: bool,
}

impl StopDeadline {
    /// The agent's: [`BUDGET`], and the process ends with `_exit`.
    pub(crate) fn start() -> Self {
        Self::start_with(BUDGET, Arc::new(exit_now))
    }

    /// The deadline's thread, idle until [`Self::begin`].
    pub(crate) fn start_with(budget: Budget, exit: Exit) -> Self {
        let shared = Arc::new(Shared {
            budget,
            state: Mutex::new(State {
                stage: "loop",
                ..State::default()
            }),
            wake: Condvar::new(),
        });
        let s = Arc::clone(&shared);
        if let Err(e) = std::thread::Builder::new()
            .name("nn-stop-deadline".to_string())
            .spawn(move || {
                // R14c: the core's set, as every thread the core starts
                nn_linux::caps::restore_core();
                watch(&s, &exit);
            })
        {
            error!(
                error = %e,
                "the stop's deadline thread did not start: a stop that blocks is not cut"
            );
        }
        Self { shared }
    }

    /// The stop begins (the first call; a later one changes nothing):
    /// `reason` is the way out of the loop, `note` what the deadline signs
    /// if it expires.
    pub(crate) fn begin(&self, reason: &'static str, note: Note) {
        let mut st = self.shared.state.lock();
        if st.begun.is_none() {
            st.begun = Some((Instant::now(), reason));
            st.note = Some(note);
            self.shared.wake.notify_all();
        }
    }

    /// The stage the stop is in now (the note names it).
    pub(crate) fn stage(&self, stage: &'static str) {
        self.shared.state.lock().stage = stage;
    }

    /// The stop's `agent_stop` is signed: the note does not sign another.
    pub(crate) fn stop_signed(&self) {
        self.shared.state.lock().stop_signed = true;
    }

    /// The stop's signed rows are written (its `agent_stop`, the heads
    /// anchored, its files removed) and `status` is its exit status: from
    /// here the drop of the start's state and the runtime's shutdown
    /// release what the process holds, which its exit does in the kernel —
    /// at the note's point the deadline exits with `status`, no note.
    pub(crate) fn evidence_done(&self, status: i32) {
        let mut st = self.shared.state.lock();
        st.stage = "teardown";
        st.evidence_done = Some(status);
    }

    /// When the stages that drain must have ended: the note's point less
    /// the part kept for the stop's signed rows (`None` before the stop).
    pub(crate) fn drain_until(&self) -> Option<Instant> {
        let b = self.shared.budget;
        self.shared
            .state
            .lock()
            .begun
            .map(|(at, _)| at + b.total.saturating_sub(b.note).saturating_sub(b.evidence))
    }

    /// `own`, the stage's own bound, or less: what is left before
    /// [`Self::drain_until`].
    pub(crate) fn drain_bound(&self, own: Duration) -> Duration {
        match self.drain_until() {
            Some(until) => own.min(until.saturating_duration_since(Instant::now())),
            None => own,
        }
    }

    /// What is left before the note's point (the whole of it before the
    /// stop: a start that failed is bounded the same).
    pub(crate) fn left(&self) -> Duration {
        let b = self.shared.budget;
        let to_note = b.total.saturating_sub(b.note);
        match self.shared.state.lock().begun {
            Some((at, _)) => (at + to_note).saturating_duration_since(Instant::now()),
            None => to_note,
        }
    }

    /// The stop ended: the deadline stands down — unless it already
    /// expired: then its exit is the process's, and this waits for it (its
    /// note may be writing a row), at most to the end of the budget.
    pub(crate) fn finish(&self) {
        let mut st = self.shared.state.lock();
        st.finished = true;
        self.shared.wake.notify_all();
        if !st.fired {
            return;
        }
        let Some((at, _)) = st.begun else {
            return;
        };
        let until = at + self.shared.budget.total;
        while !st.exited && Instant::now() < until {
            self.shared.wake.wait_until(&mut st, until);
        }
    }
}

/// The deadline's thread: idle until the stop begins; at the note's point
/// (the stop not ended) the note on a thread of its own, then the exit —
/// once the note is done, at the end of the budget at the latest.
fn watch(shared: &Arc<Shared>, exit: &Exit) {
    let b = shared.budget;
    let mut st = shared.state.lock();
    let (at, reason) = loop {
        if st.finished {
            return;
        }
        if let Some(begun) = st.begun {
            break begun;
        }
        shared.wake.wait(&mut st);
    };
    let note_at = at + b.total.saturating_sub(b.note);
    let exit_at = at + b.total;
    while !st.finished && Instant::now() < note_at {
        shared.wake.wait_until(&mut st, note_at);
    }
    if st.finished {
        return;
    }
    st.fired = true;
    if let Some(status) = st.evidence_done {
        drop(st);
        exit(status);
        shared.state.lock().exited = true;
        shared.wake.notify_all();
        return;
    }
    let expired = Expired {
        reason,
        stage: st.stage,
        after: at.elapsed(),
        stop_signed: st.stop_signed,
        budget: b,
    };
    let note = st.note.take();
    drop(st);
    if let Some(note) = note {
        let s = Arc::clone(shared);
        // a note that blocks (a log line, a disk) never holds the exit
        let started = std::thread::Builder::new()
            .name("nn-stop-note".to_string())
            .spawn(move || {
                nn_linux::caps::restore_core();
                note(&expired);
                s.state.lock().noted = true;
                s.wake.notify_all();
            });
        if started.is_ok() {
            let mut st = shared.state.lock();
            while !st.noted && Instant::now() < exit_at {
                shared.wake.wait_until(&mut st, exit_at);
            }
        }
    }
    exit(EXIT_STATUS);
    // the tests' exit returns: what `finish` waits for
    shared.state.lock().exited = true;
    shared.wake.notify_all();
}

/// The agent's exit at the deadline: `_exit`, no destructor or `atexit`
/// handler run — the stage that blocks may hold any lock they would take.
fn exit_now(status: i32) {
    // SAFETY: _exit has no preconditions; it ends the process.
    unsafe { libc::_exit(status) }
}

/// What the run leaves of the COMBAT isolation, as the note says it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Isolation {
    /// The `NORTHNARROW_COMBAT` chain is in the tables (either family).
    Kept,
    /// No family isolated.
    None,
    /// No isolator in this run (no trusted `iptables`, a dev build).
    NoIsolator,
}

impl Isolation {
    /// From the isolator's state: engaged (either family), or not, or no
    /// isolator.
    pub(crate) fn of(engaged: Option<bool>) -> Self {
        match engaged {
            Some(true) => Isolation::Kept,
            Some(false) => Isolation::None,
            None => Isolation::NoIsolator,
        }
    }
}

/// The signed degradation's detail.
pub(crate) fn note_detail(e: &Expired, isolation: Isolation) -> String {
    let isolation = match isolation {
        Isolation::Kept => {
            "COMBAT isolation kept: the NORTHNARROW_COMBAT chain stays as the run left it (the \
             stop runs no iptables); the next start tears it down and signs combat_reconcile \
             (docs/operator/COMBAT_RECOVERY.md)"
        }
        Isolation::None => "no COMBAT isolation in place",
        Isolation::NoIsolator => "no network isolator in this run",
    };
    format!(
        "the stop ({}) did not end within its deadline: stage {} still running after {} ms \
         (budget {} ms, systemd TimeoutStopSec {} s); the agent exits with status {}. {}",
        e.reason,
        e.stage,
        e.after.as_millis(),
        e.budget.total.as_millis(),
        UNIT_TIMEOUT_STOP.as_secs(),
        EXIT_STATUS,
        isolation
    )
}

/// What the note signed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Signed {
    /// The degradation, and the `agent_stop` when the stop had not signed
    /// it (`stop`).
    Rows { degraded: bool, stop: bool },
    /// The audit log's lock was not free within [`NOTE_LOCK_WAIT`].
    NotWritable,
}

/// Sign the note into `log`: the degradation (`subsystem_degraded`,
/// source [`SOURCE`]), then the run's `agent_stop` if the stop had not
/// signed it — the next start reads a run that ended, with its reason.
pub(crate) fn sign_note(
    log: &Mutex<crate::audit::AuditLog>,
    e: &Expired,
    isolation: Isolation,
    uptime_secs: u64,
) -> Signed {
    let Some(mut log) = log.try_lock_for(NOTE_LOCK_WAIT) else {
        return Signed::NotWritable;
    };
    let degraded =
        nn_linux::boot::degradation::sign_into(&mut log, SOURCE, &note_detail(e, isolation), false);
    let stop = !e.stop_signed && log.stop_entry(e.reason, uptime_secs).is_ok();
    Signed::Rows { degraded, stop }
}

/// The agent's note: the journal's ERROR, then the signed rows if the
/// audit chain is writable.
pub(crate) fn audit_note(
    audit: Option<Arc<Mutex<crate::audit::AuditLog>>>,
    isolator: Option<Arc<NetworkIsolator>>,
    loop_started: Instant,
) -> Note {
    Box::new(move |e: &Expired| {
        let isolation = Isolation::of(isolator.as_deref().map(NetworkIsolator::is_engaged));
        error!(
            reason = e.reason,
            stage = e.stage,
            after_ms = e.after.as_millis() as u64,
            isolation = ?isolation,
            "the stop did not end within its deadline — the agent exits now (status {EXIT_STATUS})"
        );
        let Some(log) = &audit else {
            return;
        };
        match sign_note(log, e, isolation, loop_started.elapsed().as_secs()) {
            Signed::Rows { degraded, stop } => warn!(
                degraded,
                agent_stop = stop,
                "stop deadline: the note signed in the audit log"
            ),
            Signed::NotWritable => error!(
                "stop deadline: the audit log is held by the stage that blocks — no signed note \
                 (the next start reports the run as ended without agent_stop)"
            ),
        }
    })
}

#[cfg(test)]
mod tests;
