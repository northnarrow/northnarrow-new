//! Wave 4 restructure, R12c (lab PR 270; plan §3.4): the response
//! dispatcher — the responses a decision runs, off the decision thread.
//!
//! Until R12c the decision thread ran each decision's responses itself, in
//! order, before the next event (the kill syscalls, the cgroup freeze and
//! its verify retries up to 50 ms, the quarantine's copy and its synced
//! ledger): one slow response held every later decision back. Now the
//! decision thread hands the responses to the dispatcher
//! ([`Dispatcher::submit`]: a queue push, never a wait) and judges the next
//! event; a thread of its own, `nn-response`, takes them by severity, each
//! process's in the order they were decided (stage 6:
//! `nn_core::response::dispatch`), and carries them out.
//!
//! **No action without a signed record.** For each batch it takes (up to
//! [`BATCH`] responses queued at once) the dispatcher writes every
//! response's signed intent row into the `actions` chain and syncs it
//! (`ActionJournal::intents`), then runs each response with its ticket —
//! the executor's acting entry points take nothing else — and writes its
//! outcome row; the batch's outcomes are synced before the next batch. The
//! decision's detection record follows its responses' outcomes, as before,
//! and an acting decision's record is never held by the record budget
//! (`detection_budget::admit_acted`): only its journal lines are.
//!
//! **A full queue** displaces a less severe response or refuses the new one
//! (`ResponseQueue::submit`); either is answered at once — its decision's
//! record says "not run: the response queue was full" —, counted (stage
//! 6), named in the next signed `overflow` row of the `actions` chain (at
//! most one a second, and at the stop) and raises the posture's
//! `TelemetryLoss`. At the stop the dispatcher runs what is queued for at
//! most [`STOP_WAIT`]; what is left is answered "not run: the agent
//! stopped" and counted in a last `overflow` row.

use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use nn_core::response::dispatch::{
    lane_of, severity_name, DispatchJob, DispatchStats, ResponseQueue, Submitted, TakenJob, LANES,
    RESPONSE_QUEUE_CAP,
};
use nn_model::posture_types::PostureKind;
use nn_model::{Event, ResponseAction, Severity};
use northnarrow_agent::decision::combine::Decision;
use northnarrow_agent::response::journal::{
    ActionIntent, ActionJournal, ActionOverflow, Intent, JournalCounts, OVERFLOW_SAMPLES,
};
use northnarrow_agent::response::{ExecutionOutcome, ExecutionReport, Executor};
use parking_lot::{Condvar, Mutex};
use tracing::{error, info, warn};

/// Responses taken at once: their intents written with one sync.
pub(crate) const BATCH: usize = 16;
/// How long the stop runs what is still queued.
pub(crate) const STOP_WAIT: Duration = Duration::from_secs(2);
/// Overflow rows at most this often (and at the stop).
const OVERFLOW_ROW_EVERY: Duration = Duration::from_secs(1);

/// Why a response was not run, in its decision's record.
pub(crate) const NOT_RUN_DISPLACED: &str =
    "not run: the response queue was full and a more severe response took its place";
pub(crate) const NOT_RUN_REFUSED: &str =
    "not run: the response queue was full of responses at least as severe";
pub(crate) const NOT_RUN_STOPPED: &str = "not run: the agent stopped before it";
pub(crate) const NOT_RUN_NO_DISPATCHER: &str = "not run: the response dispatcher is not running";

/// One decision whose responses the dispatcher runs: what its detection
/// record needs once every response has its outcome.
pub(crate) struct Decided {
    pub(crate) event: Event,
    pub(crate) decision: Decision,
    pub(crate) posture: PostureKind,
    /// The record budget's count held before this record.
    pub(crate) suppressed_before: u64,
    /// Its journal lines (the budget's): `EXECUTED`.
    pub(crate) lines: bool,
    reports: Mutex<Vec<Option<ExecutionReport>>>,
    left: AtomicUsize,
}

impl Decided {
    pub(crate) fn new(
        event: Event,
        decision: Decision,
        posture: PostureKind,
        suppressed_before: u64,
        lines: bool,
    ) -> Arc<Self> {
        let n = decision.responses.len();
        Arc::new(Self {
            event,
            decision,
            posture,
            suppressed_before,
            lines,
            reports: Mutex::new(vec![None; n]),
            left: AtomicUsize::new(n),
        })
    }
}

/// One response of one decision (or of several: a repeat merged into it).
pub(crate) struct ResponseJob {
    /// The decisions it answers, with the index of the response in each.
    answers: Vec<(Arc<Decided>, usize)>,
    action: ResponseAction,
    pid: u32,
    start_ns: u64,
    seen_ns: u64,
    file: String,
    why: Vec<String>,
}

impl DispatchJob for ResponseJob {
    fn same_action(&self, other: &Self) -> bool {
        self.action == other.action && self.pid == other.pid && self.file == other.file
    }

    fn absorb(&mut self, other: Self) {
        for w in other.why {
            if !self.why.contains(&w) {
                self.why.push(w);
            }
        }
        self.answers.extend(other.answers);
    }
}

impl ResponseJob {
    /// The jobs of `decided`'s responses, each with its severity: the
    /// severity of the rule whose verdict it is (the decision's, without
    /// one). `owner`: the process the event names, its start and the
    /// event's time (external audit CMB-004).
    pub(crate) fn of(
        decided: &Arc<Decided>,
        owner: Option<u32>,
        owner_start_ns: u64,
        owner_seen_ns: u64,
    ) -> Vec<(Severity, ResponseJob)> {
        let d = &decided.decision;
        d.responses
            .iter()
            .enumerate()
            .map(|(i, r)| {
                let severity = d
                    .matches
                    .iter()
                    .find(|m| m.rule_id == r.rule_id)
                    .map_or(d.verdict.severity, |m| m.verdict.severity);
                let (start_ns, seen_ns) = if owner == Some(r.pid) {
                    (owner_start_ns, owner_seen_ns)
                } else {
                    (0, 0)
                };
                let mut why = vec![r.rule_id.to_string()];
                why.extend(r.also.iter().map(|a| a.to_string()));
                (
                    severity,
                    ResponseJob {
                        answers: vec![(Arc::clone(decided), i)],
                        action: r.action.clone(),
                        pid: r.pid,
                        start_ns,
                        seen_ns,
                        file: r.filename.clone(),
                        why,
                    },
                )
            })
            .collect()
    }

    /// Its intent row.
    fn intent(&self, severity: Severity, waited_ns: u64) -> ActionIntent {
        let mut i = ActionIntent::named("rule", &format!("{:?}", self.action), self.pid);
        i.start_ns = self.start_ns;
        i.file = (self.action == ResponseAction::StripFileCapability).then(|| self.file.clone());
        i.severity = severity_name(severity).to_string();
        i.why = self.why.clone();
        i.detail = self.answers.first().map(|(d, _)| detail_of(&d.event));
        i.queued_us = waited_ns / 1_000;
        i
    }

    /// One line naming it (an overflow row's sample).
    fn sample(&self) -> String {
        format!(
            "{:?} pid {} ({})",
            self.action,
            self.pid,
            self.why.first().map(String::as_str).unwrap_or("-")
        )
    }

    /// The report of a response that was not run, `why`.
    fn not_run(&self, why: &'static str) -> ExecutionReport {
        ExecutionReport {
            action: self.action.clone(),
            primary: ExecutionOutcome::Refused {
                pid: self.pid,
                reason: why,
            },
            additional: Vec::new(),
            elapsed: Duration::from_micros(1),
        }
    }
}

/// The detection an intent names, bounded: the sensor, the actor.
fn detail_of(event: &Event) -> String {
    let p = northnarrow_agent::detection_store::Principal::from_event(event);
    let sensor = northnarrow_agent::detection_payload::Sensor::from_event(event);
    let mut s = format!(
        "{sensor:?} event of {} (pid {}, uid {})",
        p.comm, p.pid, p.uid
    );
    if s.len() > 200 {
        let mut cut = 200;
        while !s.is_char_boundary(cut) {
            cut -= 1;
        }
        s.truncate(cut);
    }
    s
}

/// What the decisions' records need once their responses ran: the detection
/// sink, the copy-on-first-write guard.
#[derive(Clone)]
pub(crate) struct Followups {
    pub(crate) sink: Option<northnarrow_agent::detection_store::DetectionSink>,
    pub(crate) cow: northnarrow_agent::cow::CowGuard,
}

/// Answer response `slot` of `d` with `report`; the last answer completes
/// the decision: the copy-on-first-write guard told of a ransomware rule's
/// kill, the `EXECUTED` lines (the budget's), the detection record.
fn answer(d: &Arc<Decided>, slot: usize, report: ExecutionReport, f: &Followups) {
    {
        let mut r = d.reports.lock();
        if r[slot].is_some() {
            return;
        }
        r[slot] = Some(report);
    }
    if d.left.fetch_sub(1, Ordering::AcqRel) != 1 {
        return;
    }
    let reports: Vec<ExecutionReport> = d.reports.lock().iter().flatten().cloned().collect();
    let responses = &d.decision.responses;
    // Lab PR 222: a ransomware rule's match flags its writer (done at the
    // submission), and a kill of that process (whichever matched rule's
    // response it was) neutralized it.
    for m in &d.decision.matches {
        let pid = m.verdict.event_pid;
        let neutralized = responses.iter().zip(&reports).any(|(r, report)| {
            r.pid == pid
                && matches!(
                    report.primary,
                    ExecutionOutcome::Killed { .. } | ExecutionOutcome::AlreadyGone { .. }
                )
        });
        if neutralized {
            f.cow.after_rule_response(m.rule_id, pid, true);
        }
    }
    if d.lines {
        for report in &reports {
            info!(
                action = ?report.action,
                primary = ?report.primary,
                additional_count = report.additional.len(),
                elapsed_us = report.elapsed.as_micros() as u64,
                "EXECUTED"
            );
        }
    }
    // Tappa 9.0.a: persist the rule detection (off the hot path).
    if let Some(sink) = &f.sink {
        let response = match reports.as_slice() {
            [only] => northnarrow_agent::detection_store::describe_response(only),
            many => responses
                .iter()
                .zip(many)
                .map(|(r, report)| {
                    format!(
                        "{} (pid {}, {})",
                        northnarrow_agent::detection_store::describe_response(report),
                        r.pid,
                        r.rule_id
                    )
                })
                .collect::<Vec<_>>()
                .join("; "),
        };
        sink.record_decision(
            &d.event,
            &d.decision,
            d.posture,
            response,
            d.suppressed_before,
        );
    }
}

/// The responses not run since the last overflow row.
#[derive(Default)]
struct OverflowWindow {
    displaced: [u64; LANES],
    refused: [u64; LANES],
    queued_at_stop: u64,
    samples: Vec<String>,
    last_row: Option<Instant>,
}

impl OverflowWindow {
    fn pending(&self) -> bool {
        self.displaced.iter().chain(&self.refused).any(|n| *n > 0) || self.queued_at_stop > 0
    }

    fn note(&mut self, sample: String) {
        if self.samples.len() < OVERFLOW_SAMPLES {
            self.samples.push(sample);
        }
    }
}

/// The dispatcher's counts (`nn-admin status`, the heartbeat).
#[derive(Debug, Clone, Default)]
pub(crate) struct DispatchStatus {
    pub(crate) queue: DispatchStats,
    /// Responses run, and the longest run (µs).
    pub(crate) executed: u64,
    pub(crate) execution_max_us: u64,
    /// Not run at the stop, and while the thread did not run (stage 6).
    pub(crate) not_run_at_stop: u64,
    pub(crate) not_run_down: u64,
    pub(crate) journal: JournalCounts,
    /// The dispatcher's thread runs.
    pub(crate) running: bool,
}

struct Shared {
    queue: Mutex<ResponseQueue<u32, ResponseJob>>,
    ready: Condvar,
    stop: AtomicBool,
    executor: Executor,
    journal: ActionJournal,
    followups: Followups,
    posture: Option<northnarrow_agent::posture::PostureMachine>,
    overflow: Mutex<OverflowWindow>,
    executed: AtomicU64,
    execution_max_us: AtomicU64,
    not_run_at_stop: AtomicU64,
    /// Submitted while the thread was not running.
    not_run_down: AtomicU64,
    /// A batch is being run.
    busy: AtomicBool,
    running: AtomicBool,
    epoch: Instant,
    /// `debug-trigger` builds: abort the process after the next action and
    /// before its outcome (the lab's crash between intent and outcome).
    #[cfg(feature = "debug-trigger")]
    crash_mid_action: AtomicBool,
    /// Tests: held, it stalls the thread before its next batch's intents.
    #[cfg(test)]
    hold: Mutex<()>,
}

impl Shared {
    fn now_ns(&self) -> u64 {
        self.epoch.elapsed().as_nanos() as u64
    }
}

/// The response dispatcher (see the module's doc). Cheap to clone: every
/// clone submits to the same queue.
#[derive(Clone)]
pub(crate) struct Dispatcher {
    shared: Arc<Shared>,
    thread: Arc<Mutex<Option<std::thread::JoinHandle<()>>>>,
}

impl Dispatcher {
    /// Start the dispatcher's thread (`nn-response`). Without it (the thread
    /// could not start) a submitted response is answered "not run", counted
    /// and signed — never run on the decision thread.
    pub(crate) fn start(
        executor: Executor,
        journal: ActionJournal,
        followups: Followups,
        posture: Option<northnarrow_agent::posture::PostureMachine>,
    ) -> Self {
        Self::start_with(executor, journal, followups, posture, RESPONSE_QUEUE_CAP)
    }

    pub(crate) fn start_with(
        executor: Executor,
        journal: ActionJournal,
        followups: Followups,
        posture: Option<northnarrow_agent::posture::PostureMachine>,
        capacity: usize,
    ) -> Self {
        let shared = Arc::new(Shared {
            queue: Mutex::new(ResponseQueue::new(capacity)),
            ready: Condvar::new(),
            stop: AtomicBool::new(false),
            executor,
            journal,
            followups,
            posture,
            overflow: Mutex::new(OverflowWindow::default()),
            executed: AtomicU64::new(0),
            execution_max_us: AtomicU64::new(0),
            not_run_at_stop: AtomicU64::new(0),
            not_run_down: AtomicU64::new(0),
            busy: AtomicBool::new(false),
            running: AtomicBool::new(false),
            epoch: Instant::now(),
            #[cfg(feature = "debug-trigger")]
            crash_mid_action: AtomicBool::new(false),
            #[cfg(test)]
            hold: Mutex::new(()),
        });
        let thread = {
            let shared = Arc::clone(&shared);
            std::thread::Builder::new()
                .name("nn-response".into())
                .spawn(move || run(&shared))
        };
        let thread = match thread {
            Ok(t) => {
                shared.running.store(true, Ordering::Release);
                Some(t)
            }
            Err(e) => {
                error!(
                    error = %e,
                    "the response dispatcher's thread did not start — responses will NOT run \
                     (each counted and signed as not run)"
                );
                None
            }
        };
        Self {
            shared,
            thread: Arc::new(Mutex::new(thread)),
        }
    }

    /// Hand `jobs` to the queue: never waits. A response the full queue
    /// displaces or refuses — or every response, when the thread is not
    /// running — is answered at once as not run, and counted for the next
    /// overflow row.
    pub(crate) fn submit(&self, jobs: Vec<(Severity, ResponseJob)>) {
        let s = &self.shared;
        // (the job, why, its lane, displaced)
        let mut not_run: Vec<(ResponseJob, &'static str, usize, bool)> = Vec::new();
        if !s.running.load(Ordering::Acquire) {
            s.not_run_down
                .fetch_add(jobs.len() as u64, Ordering::Relaxed);
            for (sev, j) in jobs {
                not_run.push((j, NOT_RUN_NO_DISPATCHER, lane_of(sev), false));
            }
        } else {
            let now = s.now_ns();
            let mut q = s.queue.lock();
            for (sev, job) in jobs {
                match q.submit(job.pid, sev, now, job) {
                    Submitted::Queued(_) | Submitted::Merged(_) => {}
                    Submitted::Displacing(_, d) => {
                        let lane = lane_of_job(&d);
                        not_run.push((d, NOT_RUN_DISPLACED, lane, true))
                    }
                    Submitted::Refused(j) => {
                        not_run.push((j, NOT_RUN_REFUSED, lane_of(sev), false))
                    }
                }
            }
            drop(q);
            s.ready.notify_one();
        }
        if not_run.is_empty() {
            return;
        }
        {
            let mut w = s.overflow.lock();
            for (job, _, lane, displaced) in &not_run {
                if *displaced {
                    w.displaced[*lane] += 1;
                } else {
                    w.refused[*lane] += 1;
                }
                w.note(job.sample());
            }
        }
        warn!(
            not_run = not_run.len(),
            "response dispatcher: responses NOT run (the queue full, or the dispatcher down) — \
             counted, signed in the actions chain's next overflow row"
        );
        for (job, why, _, _) in not_run {
            for (d, slot) in &job.answers {
                answer(d, *slot, job.not_run(why), &s.followups);
            }
        }
        s.ready.notify_one();
    }

    /// Its thread runs (false once it ended: the stop's, or a panic).
    pub(crate) fn is_running(&self) -> bool {
        self.shared.running.load(Ordering::Acquire)
    }

    /// The counts.
    pub(crate) fn status(&self) -> DispatchStatus {
        let s = &self.shared;
        DispatchStatus {
            queue: s.queue.lock().stats(),
            executed: s.executed.load(Ordering::Relaxed),
            execution_max_us: s.execution_max_us.load(Ordering::Relaxed),
            not_run_at_stop: s.not_run_at_stop.load(Ordering::Relaxed),
            not_run_down: s.not_run_down.load(Ordering::Relaxed),
            journal: s.journal.counts(),
            running: s.running.load(Ordering::Acquire),
        }
    }

    /// Where the admin socket's status reads stages 6 and 7 (with the
    /// canary writer's unwritten rows, `canary`).
    pub(crate) fn status_source(
        &self,
        canary: Option<Arc<northnarrow_agent::canary::detector::Detector>>,
        ransom: Option<Arc<northnarrow_agent::impact::RansomTracker>>,
    ) -> northnarrow_agent::admin::ResponseDispatchSource {
        let me = self.clone();
        Arc::new(move || {
            let mut w = me.wire_status(canary.as_deref());
            if let Some(r) = &ransom {
                let c = r.counts();
                w.ransomware_prepared = c.prepared;
                w.ransomware_inline = c.inline;
            }
            w
        })
    }

    /// Stages 6 and 7 on the wire.
    pub(crate) fn wire_status(
        &self,
        canary: Option<&northnarrow_agent::canary::detector::Detector>,
    ) -> nn_proto::admin_protocol::ResponseDispatchStatus {
        let st = self.status();
        let q = &st.queue;
        let j = &st.journal;
        let e = self
            .shared
            .followups
            .sink
            .as_ref()
            .map(|s| s.stats())
            .unwrap_or_default();
        nn_proto::admin_protocol::ResponseDispatchStatus {
            running: st.running,
            capacity: q.capacity,
            depth: q.depth.to_vec(),
            max_depth: q.max_depth,
            submitted: q.submitted,
            queued: q.queued,
            merged: q.merged,
            displaced: q.displaced.to_vec(),
            refused: q.refused.to_vec(),
            not_run_other: st.not_run_at_stop + st.not_run_down,
            taken: q.taken,
            inherited: q.inherited,
            aged: q.aged,
            wait_p50_us: q.wait.quantile_us(0.5),
            wait_p99_us: q.wait.quantile_us(0.99),
            wait_max_us: (q.wait.count() > 0).then(|| q.wait.max_us()),
            executed: st.executed,
            execution_max_us: st.execution_max_us,
            intents: j.intents,
            outcomes: j.outcomes,
            unwritten: j.unwritten,
            interrupted_at_boot: j.interrupted_at_boot,
            abandoned: j.abandoned,
            overflow_rows: j.overflow_rows,
            in_flight: j.in_flight,
            evidence_capacity: e.capacity,
            evidence_depth: e.depth,
            evidence_max_depth: e.max_depth,
            evidence_over_cap: e.over_cap,
            evidence_dropped: e.dropped,
            evidence_dropped_acted: e.dropped_acted,
            evidence_wait_max_us: e.wait_max_us,
            evidence_written: e.written,
            evidence_append_failed: e.append_failed,
            canary_unwritten: canary.map_or(0, |c| c.unwritten().1),
            ransomware_prepared: 0,
            ransomware_inline: 0,
        }
    }

    /// `debug-trigger` builds: abort after the next action, before its
    /// outcome (lab: the crash between intent and outcome).
    #[cfg(feature = "debug-trigger")]
    pub(crate) fn crash_after_next_action(&self) {
        self.shared.crash_mid_action.store(true, Ordering::Release);
    }

    /// The stop: run what is queued for at most `wait`, answer the rest
    /// "not run: the agent stopped" (counted, signed), end the thread.
    pub(crate) fn stop(&self, wait: Duration) {
        let s = &self.shared;
        let deadline = Instant::now() + wait;
        while Instant::now() < deadline {
            if s.queue.lock().is_empty() && !s.busy.load(Ordering::Acquire) {
                break;
            }
            s.ready.notify_one();
            std::thread::park_timeout(Duration::from_millis(10));
        }
        s.stop.store(true, Ordering::Release);
        let left = s.queue.lock().drain();
        if !left.is_empty() {
            warn!(
                left = left.len(),
                "response dispatcher: responses still queued at the stop — NOT run (signed)"
            );
            s.not_run_at_stop
                .fetch_add(left.len() as u64, Ordering::Relaxed);
            let mut w = s.overflow.lock();
            w.queued_at_stop += left.len() as u64;
            for (_, _, job) in &left {
                w.note(job.sample());
            }
        }
        for (_, _, job) in left {
            for (d, slot) in &job.answers {
                answer(d, *slot, job.not_run(NOT_RUN_STOPPED), &s.followups);
            }
        }
        s.ready.notify_all();
        if let Some(t) = self.thread.lock().take() {
            if t.join().is_err() {
                error!("the response dispatcher's thread panicked");
            }
        }
        s.running.store(false, Ordering::Release);
        write_overflow(s, true);
        s.journal.sync();
    }
}

/// The lane of a displaced job (the queue gives it back without its
/// severity): its decisions' highest.
fn lane_of_job(job: &ResponseJob) -> usize {
    job.answers
        .iter()
        .map(|(d, slot)| {
            let r = &d.decision.responses[*slot];
            d.decision
                .matches
                .iter()
                .find(|m| m.rule_id == r.rule_id)
                .map_or(lane_of(d.decision.verdict.severity), |m| {
                    lane_of(m.verdict.severity)
                })
        })
        .max()
        .unwrap_or(0)
}

/// Marks the thread not running however it ends (a panic outside the
/// executor's — which is caught —, the stop): from then on a response is
/// answered "not run" and counted, and the event loop stops the agent
/// (`Dispatcher::is_running`, as for a dead sensor pump).
struct Exit<'a>(&'a Shared);

impl Drop for Exit<'_> {
    fn drop(&mut self) {
        self.0.running.store(false, Ordering::Release);
        if std::thread::panicking() {
            error!("the response dispatcher's thread panicked — responses no longer run");
        }
    }
}

/// The dispatcher's thread: a batch at a time, intents first.
fn run(s: &Shared) {
    let _exit = Exit(s);
    loop {
        let batch: Vec<TakenJob<ResponseJob>> = {
            let mut q = s.queue.lock();
            while q.is_empty() {
                if s.stop.load(Ordering::Acquire) {
                    return;
                }
                let _ = s.ready.wait_for(&mut q, Duration::from_millis(500));
                if q.is_empty() && overflow_due(s) {
                    drop(q);
                    write_overflow(s, false);
                    q = s.queue.lock();
                }
            }
            s.busy.store(true, Ordering::Release);
            let now = s.now_ns();
            std::iter::from_fn(|| q.take(now)).take(BATCH).collect()
        };
        #[cfg(test)]
        drop(s.hold.lock());
        let intents = s.journal.intents(
            batch
                .iter()
                .map(|t| t.job.intent(t.severity, t.waited_ns))
                .collect(),
        );
        for (t, intent) in batch.into_iter().zip(intents) {
            let report = run_one(s, &t.job, intent);
            for (d, slot) in &t.job.answers {
                answer(d, *slot, report.clone(), &s.followups);
            }
        }
        s.journal.sync();
        s.busy.store(false, Ordering::Release);
        if overflow_due(s) {
            write_overflow(s, false);
        }
    }
}

/// Run one response with its ticket; its outcome row (synced with the
/// batch). A panic in the executor drops the ticket unanswered — it signs
/// itself abandoned — and the response reads failed.
fn run_one(s: &Shared, job: &ResponseJob, intent: Intent) -> ExecutionReport {
    let started = Instant::now();
    let ran = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        s.executor.execute_for_started(
            job.action.clone(),
            job.pid,
            job.start_ns,
            job.seen_ns,
            &job.file,
            &intent,
        )
    }));
    let us = started.elapsed().as_micros() as u64;
    s.executed.fetch_add(1, Ordering::Relaxed);
    s.execution_max_us.fetch_max(us, Ordering::Relaxed);
    match ran {
        Ok(report) => {
            #[cfg(feature = "debug-trigger")]
            if s.crash_mid_action.swap(false, Ordering::AcqRel) {
                error!(
                    action = intent.number(),
                    "debug-trigger: aborting between the action and its outcome (lab test of \
                     R12c: the next start reports the intent without its outcome)"
                );
                std::process::abort();
            }
            let (result, text, reason) = northnarrow_agent::response::journal_outcome(&report);
            intent.finish_deferred(result, text, reason);
            report
        }
        Err(_) => {
            warn!(
                action = ?job.action,
                pid = job.pid,
                "executor panicked — the response is recorded as failed (its intent abandoned)"
            );
            drop(intent);
            ExecutionReport {
                action: job.action.clone(),
                primary: ExecutionOutcome::Failed {
                    pid: job.pid,
                    errno: 0,
                },
                additional: Vec::new(),
                elapsed: started.elapsed(),
            }
        }
    }
}

fn overflow_due(s: &Shared) -> bool {
    let w = s.overflow.lock();
    w.pending() && w.last_row.is_none_or(|t| t.elapsed() >= OVERFLOW_ROW_EVERY)
}

/// The signed overflow row of what was not run since the last one, and the
/// posture's `TelemetryLoss` (`force`: the stop's, whatever the time).
fn write_overflow(s: &Shared, force: bool) {
    let row = {
        let mut w = s.overflow.lock();
        if !w.pending() || (!force && w.last_row.is_some_and(|t| t.elapsed() < OVERFLOW_ROW_EVERY))
        {
            return;
        }
        w.last_row = Some(Instant::now());
        let row = ActionOverflow {
            displaced: w.displaced.to_vec(),
            refused: w.refused.to_vec(),
            queued_at_stop: w.queued_at_stop,
            samples: std::mem::take(&mut w.samples),
            total: 0,
        };
        w.displaced = [0; LANES];
        w.refused = [0; LANES];
        w.queued_at_stop = 0;
        row
    };
    let total = s.queue.lock().stats().lost()
        + s.not_run_at_stop.load(Ordering::Relaxed)
        + s.not_run_down.load(Ordering::Relaxed);
    let not_run: u64 = row.displaced.iter().chain(&row.refused).sum::<u64>() + row.queued_at_stop;
    let row = ActionOverflow { total, ..row };
    warn!(
        not_run,
        total, "response dispatcher: responses decided and NOT run — signed overflow row"
    );
    s.journal.overflow(row);
    if let Some(p) = &s.posture {
        let reason =
            format!("{not_run} response(s) decided and not run (stage 6, the response queue)");
        if let Some(state) =
            p.raise_signal(nn_model::posture_types::TriggerType::TelemetryLoss, &reason)
        {
            warn!(
                state = %state.kind(),
                trigger = "TelemetryLoss",
                "POSTURE TRANSITION"
            );
        }
    }
}

#[cfg(test)]
mod tests;
