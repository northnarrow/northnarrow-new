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
    lane_of, severity_name, DispatchJob, DispatchStats, ResponseQueue, Submitted, LANES,
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

/// R12c-3: a worker syncs the rows it wrote unsynced (the outcomes, the
/// intents of actions that end with the host) when it finds no work, and
/// at least every this many actions.
pub(crate) const SYNC_EVERY: usize = 16;
/// R12c-3: the response workers (`NN_RESPONSE_WORKERS`, 1 to
/// [`MAX_WORKERS`]): different processes' responses run at once, one
/// process's one at a time and in order (the queue's).
pub(crate) const DEFAULT_WORKERS: usize = 8;
pub(crate) const MAX_WORKERS: usize = 32;
pub(crate) const WORKERS_ENV: &str = "NN_RESPONSE_WORKERS";
/// R12c-3: an action still running after this long is stalled — a signed
/// `stalled` row, `TelemetryLoss`, and a spare worker so that the other
/// processes' responses do not wait behind it.
pub(crate) const STALL_AFTER: Duration = Duration::from_secs(10);
/// How often the stall watch looks.
const STALL_WATCH_EVERY: Duration = Duration::from_millis(500);

/// The workers `NN_RESPONSE_WORKERS` asks for (1 to [`MAX_WORKERS`];
/// unset, empty or not a number: [`DEFAULT_WORKERS`]).
pub(crate) fn workers_from_env() -> usize {
    std::env::var(WORKERS_ENV)
        .ok()
        .and_then(|v| v.trim().parse::<usize>().ok())
        .map_or(DEFAULT_WORKERS, |n| n.clamp(1, MAX_WORKERS))
}
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
pub(crate) const NOT_RUN_SUPERSEDED: &str =
    "not run: superseded by a kill of the same process decided after it";

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
    /// The same action on the same process — its pid *and* its start,
    /// known (a process that reused the pid is another one: review of
    /// #476, X1; the start is 0, not known, for every response but an
    /// exec's — review of #477: then never merged, a second kill costs an
    /// `AlreadyGone`) — and, but for a kill, the same file (two strips of
    /// two files are two actions).
    fn same_action(&self, other: &Self) -> bool {
        self.action == other.action
            && self.same_process(other)
            && (self.is_kill() || self.file == other.file)
    }

    /// The same process, its start known and equal (review of #477): a
    /// kill supersedes only that process's throttles and blocks.
    fn same_process(&self, other: &Self) -> bool {
        self.pid == other.pid && self.start_ns != 0 && self.start_ns == other.start_ns
    }

    fn is_kill(&self) -> bool {
        matches!(
            self.action,
            ResponseAction::KillProcess | ResponseAction::KillProcessTree
        )
    }

    fn superseded_by_kill(&self) -> bool {
        matches!(
            self.action,
            ResponseAction::ThrottleProcess | ResponseAction::BlockOutbound
        )
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
    /// R12c-3: the workers (and spares running now), actions running now,
    /// actions stalled now and since the start.
    pub(crate) workers: u64,
    pub(crate) spares: u64,
    pub(crate) active: u64,
    pub(crate) stalled_now: u64,
    pub(crate) stalled: u64,
    /// The dispatcher's thread runs.
    pub(crate) running: bool,
}

struct Shared {
    /// Keyed by pid (review of #477): one pid's responses never run at
    /// once nor out of order, whichever event — knowing the start or not —
    /// decided them; a reused pid waits behind the old one's, harmlessly.
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
    /// Submitted while the workers were not running.
    not_run_down: AtomicU64,
    /// R12c-3: the pool — its size, the spares started for stalled
    /// actions, the actions running now, each worker's slot (what it runs,
    /// since when), the stalls, the threads (joined at the stop).
    workers: usize,
    spares: AtomicUsize,
    active: AtomicUsize,
    slots: Mutex<Vec<Arc<Slot>>>,
    stalled_now: AtomicUsize,
    stalled: AtomicU64,
    stall_after: Duration,
    threads: Mutex<Vec<std::thread::JoinHandle<()>>>,
    running: AtomicBool,
    epoch: Instant,
    /// `debug-trigger` builds: abort the process after the next action and
    /// before its outcome (the lab's crash between intent and outcome).
    #[cfg(feature = "debug-trigger")]
    crash_mid_action: AtomicBool,
    /// `debug-trigger` builds: the next action hangs past the stall bound
    /// before it acts (the lab's stalled action, R12c-3).
    #[cfg(feature = "debug-trigger")]
    hang_next_action: AtomicBool,
    /// Tests: held, it stalls a worker before its next intent.
    #[cfg(test)]
    hold: Mutex<()>,
    /// Tests: a worker panics before its next job (its end seen).
    #[cfg(test)]
    panic_next: AtomicBool,
    /// Tests: the action on this pid hangs (after its intent) until this
    /// goes back to 0 — a stalled action.
    #[cfg(test)]
    hang_pids: Mutex<std::collections::HashSet<u32>>,
}

/// R12c-3: what one worker runs now (the stall watch reads it).
#[derive(Default)]
struct Slot {
    /// When its action began (ns since the epoch; 0: idle).
    since_ns: AtomicU64,
    /// Its intent's number, and what it is.
    action: AtomicU64,
    what: Mutex<String>,
    /// Its stall signed.
    stalled: AtomicBool,
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
}

impl Dispatcher {
    /// Start the dispatcher's workers (`nn-response-<n>`, [`workers_from_env`]
    /// of them) and its stall watch. Without them (no thread could start) a
    /// submitted response is answered "not run", counted and signed — never
    /// run on the decision thread.
    pub(crate) fn start(
        executor: Executor,
        journal: ActionJournal,
        followups: Followups,
        posture: Option<northnarrow_agent::posture::PostureMachine>,
    ) -> Self {
        Self::start_with(
            executor,
            journal,
            followups,
            posture,
            RESPONSE_QUEUE_CAP,
            workers_from_env(),
        )
    }

    pub(crate) fn start_with(
        executor: Executor,
        journal: ActionJournal,
        followups: Followups,
        posture: Option<northnarrow_agent::posture::PostureMachine>,
        capacity: usize,
        workers: usize,
    ) -> Self {
        Self::start_inner(
            executor,
            journal,
            followups,
            posture,
            capacity,
            workers,
            STALL_AFTER,
        )
    }

    fn start_inner(
        executor: Executor,
        journal: ActionJournal,
        followups: Followups,
        posture: Option<northnarrow_agent::posture::PostureMachine>,
        capacity: usize,
        workers: usize,
        stall_after: Duration,
    ) -> Self {
        let workers = workers.clamp(1, MAX_WORKERS);
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
            workers,
            spares: AtomicUsize::new(0),
            active: AtomicUsize::new(0),
            slots: Mutex::new(Vec::new()),
            stalled_now: AtomicUsize::new(0),
            stalled: AtomicU64::new(0),
            stall_after,
            threads: Mutex::new(Vec::new()),
            running: AtomicBool::new(false),
            epoch: Instant::now(),
            #[cfg(feature = "debug-trigger")]
            crash_mid_action: AtomicBool::new(false),
            #[cfg(feature = "debug-trigger")]
            hang_next_action: AtomicBool::new(false),
            #[cfg(test)]
            hold: Mutex::new(()),
            #[cfg(test)]
            panic_next: AtomicBool::new(false),
            #[cfg(test)]
            hang_pids: Mutex::new(std::collections::HashSet::new()),
        });
        let mut started = 0;
        for n in 0..workers {
            if spawn_worker(&shared, format!("nn-response-{n}"), false) {
                started += 1;
            }
        }
        if started == workers {
            shared.running.store(true, Ordering::Release);
            let watch = Arc::clone(&shared);
            match std::thread::Builder::new()
                .name("nn-response-watch".into())
                .spawn(move || watch_stalls(&watch))
            {
                Ok(t) => shared.threads.lock().push(t),
                Err(e) => warn!(
                    error = %e,
                    "the response dispatcher's stall watch did not start — a hanging action \
                     is not reported"
                ),
            }
        } else {
            error!(
                started,
                workers,
                "the response dispatcher's workers did not all start — responses will NOT run \
                 (each counted and signed as not run)"
            );
            shared.stop.store(true, Ordering::Release);
            shared.ready.notify_all();
        }
        Self { shared }
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
                // keyed by pid (review of #477); merged only for a known
                // and equal start (`same_action`: #476's X1)
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
            s.ready.notify_all();
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
            workers: s.workers as u64,
            spares: s.spares.load(Ordering::Relaxed) as u64,
            active: s.active.load(Ordering::Relaxed) as u64,
            stalled_now: s.stalled_now.load(Ordering::Relaxed) as u64,
            stalled: s.stalled.load(Ordering::Relaxed),
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
            over_cap: q.over_cap,
            superseded: q.superseded,
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
            sync_failed: j.sync_failed,
            workers: st.workers,
            spares: st.spares,
            active: st.active,
            stalled_now: st.stalled_now,
            stalled: st.stalled,
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

    /// `debug-trigger` builds: the next action hangs past the stall bound
    /// (5 s more) before it acts (lab: the stalled action, R12c-3).
    #[cfg(feature = "debug-trigger")]
    pub(crate) fn hang_next_action(&self) {
        self.shared.hang_next_action.store(true, Ordering::Release);
    }

    /// The stop: run what is queued for at most `wait`, answer the rest
    /// "not run: the agent stopped" (counted, signed), end the workers —
    /// a worker whose action hangs is left (named), not waited for — and
    /// sign the run's end. (The agent's stop is [`Self::stop_by`], lot 288.)
    #[cfg(test)]
    pub(crate) fn stop(&self, wait: Duration) {
        self.stop_by(wait, None);
    }

    /// [`Self::stop`], every wait of it ended by `until` too (lot 288: the
    /// stop's deadline, `StopDeadline::drain_until`).
    pub(crate) fn stop_by(&self, wait: Duration, until: Option<Instant>) {
        let s = &self.shared;
        let by = |at: Instant| until.map_or(at, |u| at.min(u));
        let deadline = by(Instant::now() + wait);
        while Instant::now() < deadline {
            if s.queue.lock().is_empty() && s.active.load(Ordering::Acquire) == 0 {
                break;
            }
            s.ready.notify_all();
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
        let threads: Vec<_> = std::mem::take(&mut *s.threads.lock());
        let joined_by = by(Instant::now() + Duration::from_secs(2));
        for t in threads {
            while !t.is_finished() && Instant::now() < joined_by {
                std::thread::park_timeout(Duration::from_millis(10));
            }
            if t.is_finished() {
                if t.join().is_err() {
                    error!("a response dispatcher thread panicked");
                }
            } else {
                warn!(
                    thread = t.thread().name().unwrap_or("?"),
                    "a response worker is still in its action at the stop — left running"
                );
            }
        }
        s.running.store(false, Ordering::Release);
        write_overflow(s, true);
        s.journal.end_run();
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

/// Marks the dispatcher not running when a worker ends (a panic outside
/// the executor's — which is caught —, the stop): from then on a response
/// is answered "not run" and counted, and the event loop stops the agent
/// (`Dispatcher::is_running`, as for a dead sensor pump). A spare that
/// ends because it is no longer needed changes nothing.
struct Exit<'a>(&'a Shared, bool);

impl Drop for Exit<'_> {
    fn drop(&mut self) {
        let panicking = std::thread::panicking();
        if self.1 || panicking {
            self.0.running.store(false, Ordering::Release);
        }
        if panicking {
            error!("a response dispatcher worker panicked — responses no longer run");
        }
    }
}

/// Start one worker (`spare`: one the stall watch added); false when its
/// thread did not start.
fn spawn_worker(s: &Arc<Shared>, name: String, spare: bool) -> bool {
    let slot = Arc::new(Slot::default());
    s.slots.lock().push(Arc::clone(&slot));
    let me = Arc::clone(s);
    match std::thread::Builder::new()
        .name(name)
        .spawn(move || work(&me, &slot, spare))
    {
        Ok(t) => {
            s.threads.lock().push(t);
            true
        }
        Err(e) => {
            error!(error = %e, "a response worker did not start");
            false
        }
    }
}

/// A worker: the next job of a process with none running (the queue's
/// order: by severity, aging, each process's oldest first), its signed
/// intent, the action, its outcome; the process freed for its next job.
fn work(s: &Shared, slot: &Slot, spare: bool) {
    // R14c (plan §3.1): the actuator's capabilities
    nn_linux::caps::enter_or_report(nn_linux::caps::Role::Actuator);
    let _exit = Exit(s, !spare);
    let mut unsynced = 0usize;
    loop {
        let t = {
            let mut q = s.queue.lock();
            loop {
                if s.stop.load(Ordering::Acquire) {
                    drop(q);
                    if unsynced > 0 {
                        s.journal.sync();
                    }
                    return;
                }
                #[cfg(test)]
                if !q.is_empty() && s.panic_next.swap(false, Ordering::AcqRel) {
                    panic!("test: a response worker panics");
                }
                if let Some(t) = q.take(s.now_ns()) {
                    break t;
                }
                // nothing free: this worker's rows to the disk, then wait
                if unsynced > 0 {
                    drop(q);
                    s.journal.sync();
                    unsynced = 0;
                    q = s.queue.lock();
                    continue;
                }
                if spare && s.spares.load(Ordering::Acquire) > s.stalled_now.load(Ordering::Acquire)
                {
                    // the stall it stood in for is over
                    s.spares.fetch_sub(1, Ordering::AcqRel);
                    return;
                }
                let _ = s.ready.wait_for(&mut q, Duration::from_millis(500));
                if overflow_due(s) {
                    drop(q);
                    write_overflow(s, false);
                    q = s.queue.lock();
                }
            }
        };
        s.active.fetch_add(1, Ordering::AcqRel);
        #[cfg(test)]
        drop(s.hold.lock());
        let key = t.job.pid;
        let intent = s.journal.intent(t.job.intent(t.severity, t.waited_ns));
        slot.action.store(intent.number(), Ordering::Relaxed);
        *slot.what.lock() = t.job.sample();
        slot.since_ns.store(s.now_ns().max(1), Ordering::Release);
        let report = run_one(s, &t.job, intent);
        slot.since_ns.store(0, Ordering::Release);
        if slot.stalled.swap(false, Ordering::AcqRel) {
            s.stalled_now.fetch_sub(1, Ordering::AcqRel);
            info!(what = %slot.what.lock(), "a stalled response action ended");
        }
        unsynced += 1;
        let gone = {
            let mut q = s.queue.lock();
            q.done(&key);
            if t.job.is_kill() && killed_it(&report) {
                // the re-check of #476: only a kill that killed supersedes
                // its process's throttles and blocks still queued
                q.supersede(&key, &t.job)
            } else {
                Vec::new()
            }
        };
        s.ready.notify_all();
        for job in gone {
            for (d, slot) in &job.answers {
                answer(d, *slot, job.not_run(NOT_RUN_SUPERSEDED), &s.followups);
            }
        }
        for (d, n) in &t.job.answers {
            answer(d, *n, report.clone(), &s.followups);
        }
        s.active.fetch_sub(1, Ordering::AcqRel);
        if unsynced >= SYNC_EVERY {
            s.journal.sync();
            unsynced = 0;
        }
        if overflow_due(s) {
            write_overflow(s, false);
        }
    }
}

/// R12c-3: the stall watch — an action running past the stall bound is
/// signed (`stalled` row: its intent's number, what, how long),
/// WARNed, counted, raises `TelemetryLoss`, and gets a spare worker, so
/// the other processes' responses do not wait behind it (at most one spare
/// per stalled action, at most the pool's size of them).
fn watch_stalls(s: &Arc<Shared>) {
    // R14c (plan §3.1): the actuator's capabilities (it starts the spares)
    nn_linux::caps::enter_or_report(nn_linux::caps::Role::Actuator);
    while !s.stop.load(Ordering::Acquire) {
        std::thread::park_timeout(STALL_WATCH_EVERY);
        let now = s.now_ns();
        let slots: Vec<Arc<Slot>> = s.slots.lock().clone();
        for slot in slots {
            let since = slot.since_ns.load(Ordering::Acquire);
            if since == 0 || now.saturating_sub(since) < s.stall_after.as_nanos() as u64 {
                continue;
            }
            if slot.stalled.swap(true, Ordering::AcqRel) {
                continue;
            }
            let busy = Duration::from_nanos(now.saturating_sub(since));
            let what = slot.what.lock().clone();
            let action = slot.action.load(Ordering::Relaxed);
            s.stalled_now.fetch_add(1, Ordering::AcqRel);
            s.stalled.fetch_add(1, Ordering::Relaxed);
            warn!(
                action,
                what = %what,
                secs = busy.as_secs(),
                "a response action is still running past the stall bound — signed, a spare \
                 worker takes the other responses"
            );
            s.journal.stalled(action, &what, busy);
            if let Some(p) = &s.posture {
                let reason = format!("a response action stalled ({what}, {} s)", busy.as_secs());
                if let Some(state) =
                    p.raise_signal(nn_model::posture_types::TriggerType::TelemetryLoss, &reason)
                {
                    warn!(state = %state.kind(), trigger = "TelemetryLoss", "POSTURE TRANSITION");
                }
            }
            if s.spares.load(Ordering::Acquire) < s.workers
                && s.spares.load(Ordering::Acquire) < s.stalled_now.load(Ordering::Acquire)
            {
                let n = s.spares.fetch_add(1, Ordering::AcqRel);
                if !spawn_worker(s, format!("nn-response-s{n}"), true) {
                    s.spares.fetch_sub(1, Ordering::AcqRel);
                }
            }
            s.ready.notify_all();
        }
    }
}

/// The process is dead: killed now, or gone before.
fn killed_it(report: &ExecutionReport) -> bool {
    matches!(
        report.primary,
        ExecutionOutcome::Killed { .. } | ExecutionOutcome::AlreadyGone { .. }
    )
}

/// Run one response with its ticket; its outcome row (synced with the
/// batch). A panic in the executor drops the ticket unanswered — it signs
/// itself abandoned — and the response reads failed.
fn run_one(s: &Shared, job: &ResponseJob, intent: Intent) -> ExecutionReport {
    let started = Instant::now();
    #[cfg(test)]
    while s.hang_pids.lock().contains(&job.pid) {
        std::thread::sleep(Duration::from_millis(5));
    }
    #[cfg(feature = "debug-trigger")]
    if s.hang_next_action.swap(false, Ordering::AcqRel) {
        warn!(
            pid = job.pid,
            "debug-trigger: this action hangs past the stall bound before it acts (lab test of \
             R12c-3: a stalled action, signed, the other responses not held)"
        );
        std::thread::sleep(s.stall_after + Duration::from_secs(5));
    }
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
