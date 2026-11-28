//! Lot M4 (#633): the stop releases every process the kernel holds,
//! whatever the controller thread is doing.
//!
//! The kernel stops a candidate exec after naming it in `EXECQ_STOPPED`
//! (pid → start, stop time), and stops nothing without a fresh heartbeat in
//! `EXECQ_ALIVE`. The controller resumed what it held at its own stop
//! ([`super::controller::Controller::stop_all`]), reached only between two
//! of its passes. On an rpm host a pass that handles a ring of reports runs
//! `rpm -qf` for each one (the package trust, [`super::pkgtrust`]): seconds.
//! The agent's stop waited 2 s for it; the stop's deadline ends the process
//! at 1.5 s; the held processes stayed in state T, in the pinned map, until
//! the next start with the guard on.
//!
//! Here the two maps are shared ([`Held`]): the controller writes its
//! heartbeat and removes the entries it resolved through them, and the
//! stop's [`Sweeper`] — on the stopping thread, after a wait bounded by the
//! stop's deadline — clears the heartbeat for good, waits for the programs
//! that read it, and releases what the map still names: each process
//! resumed, its kill carried out when the map says one is owed, and the
//! ones it cannot capture signed as left (the next start releases them).
//! The deadline's own exit runs it too ([`Sweeper::sweep_at_exit`]):
//! whichever stage of the stop blocks, the process does not end holding
//! processes stopped.
//!
//! Lot M7: the sweep signs what it has released by the stop's signing
//! time — [`SIGN_MARGIN`] before the deadline's note — and goes on with
//! the rest, signed at its end. On ubuntu 26.04 (the nightly of 27/11) a
//! stop whose earlier stages took 750 ms left the sweep 0.5 s for more
//! than 1 000 held processes, the burst still running: the deadline cut
//! it, its exit resumed the last 146, and no signed `stopping` entry named
//! any process the stop had resumed.

use std::collections::HashSet;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use common::wire::execq::ExecqStopped;
use parking_lot::Mutex;
use tracing::warn;

use super::AUDIT_OP;
use super::controller::Recorder;
use super::kernel::{KILL_OWED, entry_is_its_own};
use crate::response::journal::{ActionIntent, ActionJournal, ActionResult};
use crate::response::proc_ref::{Liveness, ProcRef};

/// The two maps of the stop, raw (the kernel's in production, a test's).
pub trait HeldMaps: Send {
    /// `EXECQ_ALIVE[0]` (0: no heartbeat, the kernel stops nothing).
    fn set_beat(&mut self, ns: u64);
    /// Every entry of `EXECQ_STOPPED`.
    fn entries(&self) -> Vec<(u32, ExecqStopped)>;
    /// The entry of `pid`.
    fn entry(&self, pid: u32) -> Option<ExecqStopped>;
    /// The entry of `pid` goes.
    fn remove(&mut self, pid: u32);
    /// The entry of `pid` is `v` (insert or update).
    fn put(&mut self, pid: u32, v: ExecqStopped) -> Result<(), String>;
    /// Return once every program run that read the heartbeat before it
    /// was cleared has ended ([`super::kernel::quiesce`]).
    fn quiesce(&mut self);
}

/// The maps, shared by the controller and the stop's sweep. A lock held
/// for one map operation at a time — never across a pass of the
/// controller.
pub struct Held<M> {
    inner: Mutex<HeldState<M>>,
}

struct HeldState<M> {
    maps: M,
    /// The stop cleared the heartbeat: no beat writes it again.
    cleared: bool,
}

/// What [`Sweeper::sweep_at_exit`] waits for the maps' lock at most.
const EXIT_LOCK_WAIT: Duration = Duration::from_millis(100);

impl<M: HeldMaps> Held<M> {
    pub fn new(maps: M) -> Self {
        Self {
            inner: Mutex::new(HeldState {
                maps,
                cleared: false,
            }),
        }
    }

    /// The controller's heartbeat: refused once the stop has cleared it —
    /// a beat of a pass that began before the stop never re-arms the
    /// kernel behind the sweep. 0 is the stop's clear ([`Self::clear`]).
    pub fn beat(&self, ns: u64) {
        let mut st = self.inner.lock();
        if ns == 0 {
            st.cleared = true;
        } else if st.cleared {
            return;
        }
        st.maps.set_beat(ns);
    }

    /// The heartbeat cleared, for good: from here the kernel stops nothing.
    pub fn clear(&self) {
        let mut st = self.inner.lock();
        st.cleared = true;
        st.maps.set_beat(0);
    }

    /// Whether the stop has cleared the heartbeat.
    pub fn cleared(&self) -> bool {
        self.inner.lock().cleared
    }

    pub fn quiesce(&self) {
        self.inner.lock().maps.quiesce();
    }

    /// The entries of `EXECQ_STOPPED`.
    pub fn stopped(&self) -> Vec<(u32, ExecqStopped)> {
        self.inner.lock().maps.entries()
    }

    /// Lot 317 (review F5): the entry of process `pid` started at
    /// `start_ns` goes — not one a later holder of the pid has.
    pub fn unstop(&self, pid: u32, start_ns: u64) {
        let mut st = self.inner.lock();
        let found = st.maps.entry(pid).map(|v| v.start_ns);
        if entry_is_its_own(found, start_ns) {
            st.maps.remove(pid);
        }
    }

    /// Lot 317 (review F2): the entry of process `(pid, start_ns)` marked
    /// [`KILL_OWED`]; an entry a later holder of the pid has is left as it
    /// is (the re-check of #541, N2).
    pub fn owe_kill(&self, pid: u32, start_ns: u64) {
        let mut st = self.inner.lock();
        let found = st.maps.entry(pid).map(|v| v.start_ns);
        if !entry_is_its_own(found, start_ns) {
            return;
        }
        let v = ExecqStopped {
            start_ns,
            stop_ns: KILL_OWED,
        };
        if let Err(e) = st.maps.put(pid, v) {
            warn!(pid, error = %e, "exec quarantine: the owed kill could not be marked in the map");
        }
    }

    /// [`Self::clear`], [`Self::quiesce`] and [`Self::stopped`] with the
    /// lock waited for at most `wait` (the deadline's exit: a stage that
    /// blocks may be anywhere). `None`: not taken.
    fn clear_and_read_within(&self, wait: Duration) -> Option<Vec<(u32, ExecqStopped)>> {
        let mut st = self.inner.try_lock_for(wait)?;
        st.cleared = true;
        st.maps.set_beat(0);
        st.maps.quiesce();
        Some(st.maps.entries())
    }
}

/// How the sweep captures a held process (production:
/// [`ProcRef::open_started_at`]).
pub type SweepCapture = Box<dyn Fn(u32, u64) -> ProcRef + Send + Sync>;

/// What a sweep did, by pid.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Swept {
    /// `SIGCONT` delivered.
    pub resumed: Vec<u32>,
    /// The kill the map owed, carried out.
    pub killed: Vec<u32>,
    /// Ended before the sweep reached it (its entry removed).
    pub gone: u64,
    /// Not released: not captured, or the signal refused — left in the map
    /// (the next start releases it), signed.
    pub left: Vec<u32>,
    /// A kill owed that this sweep did not carry out (the deadline's exit,
    /// which kills nothing): left in the map for the next start.
    pub kills_left: Vec<u32>,
}

impl Swept {
    fn is_empty(&self) -> bool {
        self.resumed.is_empty()
            && self.killed.is_empty()
            && self.left.is_empty()
            && self.kills_left.is_empty()
    }

    /// What was done after `mark` (a copy of `self` taken earlier: each
    /// list only grows).
    fn since(&self, mark: &Swept) -> Swept {
        Swept {
            resumed: self.resumed[mark.resumed.len()..].to_vec(),
            killed: self.killed[mark.killed.len()..].to_vec(),
            gone: self.gone - mark.gone,
            left: self.left[mark.left.len()..].to_vec(),
            kills_left: self.kills_left[mark.kills_left.len()..].to_vec(),
        }
    }
}

/// Lot M7: which part of a sweep a signed `stopping` entry is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Part {
    /// The sweep ended before its signing time: everything, signed once.
    Whole,
    /// Signed at the sweep's signing time, the sweep not ended: what was
    /// done so far, and the processes still to release (`unfinished`).
    First,
    /// What the sweep did after its first part, signed at its end.
    Rest,
}

impl Part {
    fn as_str(self) -> &'static str {
        match self {
            Part::Whole => "whole",
            Part::First => "first",
            Part::Rest => "rest",
        }
    }
}

/// Lot M7: what the stop keeps, before its deadline's note, for the
/// sweep's signed `stopping` entry — the sweep signs what it has done at
/// the latest this long before the note's point ([`signing_time`]).
pub const SIGN_MARGIN: Duration = Duration::from_millis(200);

/// Lot M7: the sweep's signing time, from `now` and what the stop's
/// deadline leaves before its note (`to_note`): [`SIGN_MARGIN`] before it,
/// or `now` when less is left.
pub fn signing_time(now: Instant, to_note: Duration) -> Instant {
    now + to_note.saturating_sub(SIGN_MARGIN)
}

/// How many times a sweep reads the map: a read after the last that finds
/// no entry it has not tried ends it (the heartbeat is cleared, the
/// programs waited for: nothing adds to the map after the first).
const PASSES: usize = 4;

/// The stop's release of what the kernel holds.
pub struct Sweeper<M> {
    held: Arc<Held<M>>,
    capture: SweepCapture,
    /// Lot 341: an observing run kills nothing — a kill the map owes is
    /// resumed.
    enforce: bool,
    /// The review of #635 (P3-1): a kill is never without its signed
    /// intent — the journal is not optional.
    journal: ActionJournal,
    recorder: Option<SharedRecorder>,
    /// Lot M7: a `debug-trigger` build's `NN_DEBUG_EXECQ_SLOW_SWEEP_US=<µs>`
    /// (the lab's privileged e2e, never a release): the stop's sweep waits
    /// that long before each release — a slow host's sweep, which the
    /// stop's deadline cuts (the deadline's own exit sweep is not slowed).
    #[cfg(feature = "debug-trigger")]
    slow: Option<Duration>,
}

/// The controller's recorder, shared with the stop's sweep (each call
/// takes the lock for its own write only).
#[derive(Clone)]
pub struct SharedRecorder(Arc<Mutex<Box<dyn Recorder>>>);

impl SharedRecorder {
    pub fn new(r: Box<dyn Recorder>) -> Self {
        Self(Arc::new(Mutex::new(r)))
    }
}

impl Recorder for SharedRecorder {
    fn detection(&self, rec: super::record::ExecqRecord) {
        self.0.lock().detection(rec)
    }
    fn audit(&self, extra: serde_json::Value, result: &str) {
        self.0.lock().audit(extra, result)
    }
    fn degraded(&self, detail: &str) {
        self.0.lock().degraded(detail)
    }
}

impl<M: HeldMaps> Sweeper<M> {
    pub fn new(
        held: Arc<Held<M>>,
        capture: SweepCapture,
        enforce: bool,
        journal: ActionJournal,
        recorder: Option<SharedRecorder>,
    ) -> Self {
        Self {
            held,
            capture,
            enforce,
            journal,
            recorder,
            #[cfg(feature = "debug-trigger")]
            slow: std::env::var("NN_DEBUG_EXECQ_SLOW_SWEEP_US")
                .ok()
                .and_then(|v| v.parse::<u64>().ok())
                .map(|us| Duration::from_micros(us.min(10_000))),
        }
    }

    /// Clear the heartbeat, wait for the programs that read it, release
    /// every process the map names, and sign what was done (`by`: who
    /// asked) when there was anything to do.
    ///
    /// Lot M7: `sign_by`, the stop's signing time. A sweep still releasing
    /// then signs what it has done so far (the `first` part, the processes
    /// it has still to release named `unfinished`) and goes on; what it
    /// does after is signed at its end (the `rest`). On ubuntu 26.04 a
    /// sweep of more than 1 000 held processes outlasted what the stop's
    /// deadline left it: the deadline's exit resumed the last ones, and the
    /// audit chain named none of the processes the stop had resumed.
    pub fn sweep(&self, by: &str, sign_by: Option<Instant>) -> Swept {
        self.held.clear();
        self.held.quiesce();
        let mut tried: HashSet<(u32, u64)> = HashSet::new();
        let mut out = Swept::default();
        // what the first part signed, once signed
        let mut first: Option<Swept> = None;
        for _ in 0..PASSES {
            let fresh: Vec<_> = self
                .held
                .stopped()
                .into_iter()
                .filter(|(pid, st)| tried.insert((*pid, st.start_ns)))
                .collect();
            if fresh.is_empty() {
                break;
            }
            for (i, &(pid, st)) in fresh.iter().enumerate() {
                #[cfg(feature = "debug-trigger")]
                if let Some(d) = self.slow {
                    std::thread::sleep(d);
                }
                self.release(pid, st, true, &mut out);
                let more = i + 1 < fresh.len();
                if first.is_none() && more && sign_by.is_some_and(|t| Instant::now() >= t) {
                    let unfinished: Vec<u32> = fresh[i + 1..].iter().map(|(p, _)| *p).collect();
                    warn!(
                        done = out.resumed.len() + out.killed.len(),
                        unfinished = unfinished.len(),
                        "exec quarantine: the stop's sweep signs what it has released at the \
                         stop's signing time, and goes on with the rest"
                    );
                    self.sign(by, &out, Part::First, &unfinished);
                    first = Some(out.clone());
                }
            }
        }
        match &first {
            // what became of each process the first part left unfinished
            Some(mark) => self.sign(by, &out.since(mark), Part::Rest, &[]),
            None if !out.is_empty() => self.sign(by, &out, Part::Whole, &[]),
            None => {}
        }
        out
    }

    /// The deadline's exit: the same release, with the maps' lock waited
    /// for a bounded time, no kill (a kill owed stays in the map: the next
    /// start carries it out, signed) and nothing signed (the audit log may
    /// be held by the stage that blocks). `None`: the maps' lock was not
    /// free.
    pub fn sweep_at_exit(&self) -> Option<Swept> {
        let entries = self.held.clear_and_read_within(EXIT_LOCK_WAIT)?;
        let mut out = Swept::default();
        for (pid, st) in entries {
            self.release(pid, st, false, &mut out);
        }
        Some(out)
    }

    fn release(&self, pid: u32, st: ExecqStopped, may_kill: bool, out: &mut Swept) {
        let owed = st.stop_ns == KILL_OWED && self.enforce;
        let pr = (self.capture)(pid, st.start_ns);
        match pr.liveness() {
            Liveness::Uncaptured(_) => {
                out.left.push(pid);
                return;
            }
            Liveness::Live if owed && !may_kill => {
                out.kills_left.push(pid);
                return;
            }
            Liveness::Live if owed => {
                if kill_with_intent(&self.journal, &pr, pid, OWED_KILL_PATH, true).0 {
                    out.killed.push(pid);
                } else {
                    out.left.push(pid);
                    return;
                }
            }
            Liveness::Live => match pr.signal(libc::SIGCONT) {
                Ok(()) => out.resumed.push(pid),
                Err(_) => {
                    out.left.push(pid);
                    return;
                }
            },
            Liveness::Gone => out.gone += 1,
        }
        self.held.unstop(pid, st.start_ns);
    }

    fn sign(&self, by: &str, s: &Swept, part: Part, unfinished: &[u32]) {
        if !s.left.is_empty() || !s.kills_left.is_empty() {
            warn!(
                left = ?s.left,
                kills_left = ?s.kills_left,
                "exec quarantine: held processes the stop could not release stay stopped — \
                 the next start resumes them, or kills them when their kill is owed"
            );
        }
        let Some(r) = &self.recorder else {
            return;
        };
        r.audit(
            serde_json::json!({
                "kind": "stopping",
                "by": by,
                "detail": "the stop's sweep of the kernel's map of held processes: each one \
                           resumed undecided, a kill owed carried out, those not released left \
                           stopped for the next start",
                "resumed": s.resumed,
                "killed": s.killed,
                "left": s.left,
                // the kills owed that the deadline's exit leaves to the next start
                "kills_left": s.kills_left,
                "gone": s.gone,
                // held without an entry the controller resolved: all of them
                "unreported": s.resumed,
                // lot M7: the part of the sweep this entry is, and for its
                // first part the processes it had still to release — the
                // rest of the sweep (its `rest` entry) or, when the stop's
                // deadline cuts it, the deadline's exit (unsigned) releases
                // them
                "part": part.as_str(),
                "unfinished": unfinished,
                "op": AUDIT_OP,
            }),
            "success",
        );
    }
}

/// The stop of the controller's thread: its flag set and the thread woken,
/// its own stop waited for `wait` at most, then the sweep — whatever the
/// thread is doing (a pass that does not end: an rpm host's package
/// lookups, a lookup that hangs). The controller's stop that ends in time
/// leaves the sweep what it could not capture, if anything. Lot M7: the
/// sweep signs what it has done by `sign_by` at the latest
/// ([`Sweeper::sweep`]).
/// The thread's handle comes back when it was still running (production
/// lets it go: the process's exit ends it).
pub fn stop_then_sweep<M: HeldMaps>(
    stop: &AtomicBool,
    wake: impl FnOnce(),
    thread: std::thread::JoinHandle<()>,
    sweeper: &Sweeper<M>,
    wait: Duration,
    sign_by: Option<Instant>,
) -> Option<std::thread::JoinHandle<()>> {
    stop.store(true, Ordering::Relaxed);
    wake();
    let deadline = Instant::now() + wait;
    while !thread.is_finished() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(5));
    }
    let running = if thread.is_finished() {
        let _ = thread.join();
        None
    } else {
        warn!(
            wait_ms = wait.as_millis() as u64,
            "exec quarantine controller did not stop in time — the stop's sweep releases what \
             the kernel holds"
        );
        Some(thread)
    };
    sweeper.sweep(
        if running.is_none() {
            "sweep after the controller's stop"
        } else {
            "sweep: the controller did not stop in time"
        },
        sign_by,
    );
    running
}

/// The path a kill's signed intent names for a process the agent holds
/// without an entry (its report unread, or its kill owed by a previous
/// agent).
pub const OWED_KILL_PATH: &str = "(a process held without a report of this run)";

/// The kill of a captured process (`held`: the kernel holds it), with its
/// signed intent (R12c, lab PR 270) and its outcome: whether the signal was
/// delivered, and the response. One path for the controller and the stop's
/// sweep. The review of #635 (P3-1): the journal is not optional — no kill
/// without its intent (`xtask/tests/action_records.rs` holds it).
pub fn kill_with_intent(
    journal: &ActionJournal,
    pr: &ProcRef,
    pid: u32,
    path: &str,
    held: bool,
) -> (bool, String) {
    let intent = journal.intent(intent_named("KillProcess", pid, path));
    match pr.signal(libc::SIGKILL) {
        Ok(()) => {
            super::COUNTERS
                .killed
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let text = if held {
                "killed while held".to_string()
            } else {
                "killed".to_string()
            };
            intent.finish(ActionResult::Success, text.clone(), None);
            (true, text)
        }
        Err(e) => {
            intent.finish(
                ActionResult::Failure,
                "kill failed".to_string(),
                Some(e.to_string()),
            );
            (false, format!("kill failed: {e}"))
        }
    }
}

/// R12c (lab PR 270): the signed intent of one of the exec quarantine's
/// actions (`response`) on `pid`, whose exec of `path` it held.
pub fn intent_named(response: &str, pid: u32, path: &str) -> ActionIntent {
    let mut i = ActionIntent::named("exec_quarantine", response, pid);
    i.severity = "high".into();
    i.why = vec![super::RULE_ID.to_string()];
    let mut d = format!("exec of {path}");
    if d.len() > 200 {
        let mut cut = 200;
        while !d.is_char_boundary(cut) {
            cut -= 1;
        }
        d.truncate(cut);
    }
    i.detail = Some(d);
    i
}

#[cfg(test)]
mod tests;
