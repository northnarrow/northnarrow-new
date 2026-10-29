//! The priority event bus's runtime (Wave 4 restructure, R12a, lab PR 267;
//! plan §3.4): what the pumps send into and the event loop reads from, in
//! place of the one `mpsc` channel of 4,096 events every source shared.
//!
//! Each class of events has a queue of its own ([`nn_core::bus`]: the
//! classes, the queues, the take order). A sender — every ring pump, the
//! FIM and network drains, the file-open sensor, the exploit guard — sends
//! an event into its class's queue; a full queue does what the class says
//! ([`nn_core::bus::when_full`]): P0 (tamper) waits at most 50 ms for room
//! while its kernel ring absorbs, P1 (process) 10 ms, then the event is
//! dropped and counted; P2 (file) and P3 (network) drop the new event at
//! once, except the file events other than `FileOpen`, which wait for room
//! as every source waited before (review 75). The wait is fair: a waiting
//! sender takes the next free slot of its queue before a sender that comes
//! later. The receiver — the event loop, the one consumer — takes by strict
//! priority with aging, FIFO inside a class; a flood of one class no longer
//! holds the others back, and the kernel no longer drops a tamper record
//! because a flood of opens filled the shared queue (plan §1.5, EXP-13).
//!
//! What the receiver hands over with an event (lab PR 267, the property test
//! of `agent/src/decision/golden.rs`): a tamper event taken ahead of execs
//! still queued in P1 brings them along ([`Received::overtaken`]), and the
//! process lineage learns them first ([`BusReceiver::recv_with`]), so the
//! tamper event is judged on the process tree of every exec that reached
//! the bus before it — as on a single queue — and the rules' own tree learns
//! them at the event loop (`RuleEngine::observe_arrival`).
//!
//! What it counts, per queue ([`BusStats`]): events queued, dropped, the
//! depth and the most it held, the longest wait in it, the sends that had
//! to wait for room, the takes by aging, and the latency from queue to
//! decision (p50/p99), for `nn-admin status --key`. A drop is never silent
//! ([`spawn_loss_recorder`]): a WARN each sample it happens in, a signed
//! `event_bus_drop` row — for P0 at the first sample after it (at most one
//! a sample), for the other queues at most once per [`AUDIT_WINDOW_SECS`],
//! each row carrying every drop since the queue's previous row — and, past
//! the security rings' threshold, the posture's `TelemetryLoss`, as a
//! security ring's kernel drops raised it (P0, P1 and P2: the events of the
//! exec, file-open, FIM and tamper rings that would have been lost in the
//! kernel before R12a; P3's network rings were never security rings).

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use nn_core::bus::{
    self as core_bus, ClassQueues, LatencyHistogram, Priority, QueueSpec, QueueStats, WhenFull,
    QUEUES, SPECS,
};
use nn_model::Event;
use parking_lot::Mutex;
use tokio::sync::{Notify, Semaphore, TryAcquireError};
use tokio::task::JoinHandle;
use tracing::{debug, warn};

use crate::late_audit::{AuditHandle, LateAudit};
use crate::posture::lineage::AuthSessionTracker;
use crate::sensors::ring_drops::{self, PostureSink};

/// Audit op of a drop on the bus.
pub const AUDIT_OP: &str = "event_bus_drop";
/// The loss recorder's sample (the ring-drop sampler's).
pub const SAMPLE_SECS: u64 = ring_drops::SAMPLE_SECS;
/// At most one signed row per queue per window, P0 aside (P0: one per
/// sample).
pub const AUDIT_WINDOW_SECS: u64 = ring_drops::AUDIT_WINDOW_SECS;

/// The receiver is gone (the agent is stopping).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SendError;

struct State {
    queues: ClassQueues<Event>,
    /// Queue → decision, per queue.
    latency: [LatencyHistogram; QUEUES],
    /// Sends that waited for room, per queue.
    waited: [u64; QUEUES],
}

struct Inner {
    state: Mutex<State>,
    /// Free slots, per queue (fair: a waiting sender is served first).
    room: [Semaphore; QUEUES],
    /// An event was queued, or the last sender left.
    ready: Notify,
    senders: AtomicUsize,
    closed: AtomicBool,
    specs: [QueueSpec; QUEUES],
    epoch: Instant,
}

impl Inner {
    fn now_ns(&self) -> u64 {
        u64::try_from(self.epoch.elapsed().as_nanos()).unwrap_or(u64::MAX)
    }

    /// What a full queue does with `event`: [`core_bus::when_full`], with
    /// this bus's waits.
    fn when_full(&self, event: &Event, p: Priority) -> WhenFull {
        match core_bus::when_full(event) {
            WhenFull::Backpressure => WhenFull::Backpressure,
            WhenFull::DropNew => WhenFull::DropNew,
            WhenFull::Wait { .. } => self.specs[p.index()].when_full,
        }
    }

    fn note_dropped(&self, p: Priority) {
        self.state.lock().queues.note_dropped(p);
    }
}

/// A bus of the plan's queues ([`SPECS`]): its sender and its receiver.
pub fn channel() -> (BusSender, BusReceiver) {
    channel_with(SPECS)
}

/// A bus of the given queues (tests: small queues, short waits).
pub fn channel_with(specs: [QueueSpec; QUEUES]) -> (BusSender, BusReceiver) {
    let inner = Arc::new(Inner {
        state: Mutex::new(State {
            queues: ClassQueues::new(specs.map(|s| s.capacity)),
            latency: Default::default(),
            waited: [0; QUEUES],
        }),
        room: specs.map(|s| Semaphore::new(s.capacity.max(1))),
        ready: Notify::new(),
        senders: AtomicUsize::new(1),
        closed: AtomicBool::new(false),
        specs,
        epoch: Instant::now(),
    });
    (
        BusSender {
            inner: Arc::clone(&inner),
        },
        BusReceiver {
            inner,
            in_flight: None,
        },
    )
}

/// What the pumps and the drains send into; clones share the bus.
pub struct BusSender {
    inner: Arc<Inner>,
}

impl Clone for BusSender {
    fn clone(&self) -> Self {
        self.inner.senders.fetch_add(1, Ordering::AcqRel);
        Self {
            inner: Arc::clone(&self.inner),
        }
    }
}

impl Drop for BusSender {
    fn drop(&mut self) {
        if self.inner.senders.fetch_sub(1, Ordering::AcqRel) == 1 {
            self.inner.ready.notify_one();
        }
    }
}

impl BusSender {
    /// Queue `event` in its class's queue; a full queue does what the class
    /// says ([`nn_core::bus::when_full`]): the send waits for room, at most
    /// the class's wait, or the event is dropped and counted. `Ok` either
    /// way; `Err` only when the receiver is gone (the agent stops), as a
    /// closed channel's send was.
    pub async fn send(&self, event: Event) -> Result<(), SendError> {
        let inner = &self.inner;
        if inner.closed.load(Ordering::Acquire) {
            return Err(SendError);
        }
        let p = Priority::of_event(&event);
        let room = &inner.room[p.index()];
        let permit = match room.try_acquire() {
            Ok(permit) => permit,
            Err(TryAcquireError::Closed) => return Err(SendError),
            Err(TryAcquireError::NoPermits) => {
                let waited = match inner.when_full(&event, p) {
                    WhenFull::DropNew => {
                        inner.note_dropped(p);
                        return Ok(());
                    }
                    WhenFull::Backpressure => room.acquire().await.ok(),
                    WhenFull::Wait { max_ns } => {
                        match tokio::time::timeout(Duration::from_nanos(max_ns), room.acquire())
                            .await
                        {
                            Ok(permit) => permit.ok(),
                            Err(_) => {
                                inner.note_dropped(p);
                                return Ok(());
                            }
                        }
                    }
                };
                let Some(permit) = waited else {
                    return Err(SendError);
                };
                inner.state.lock().waited[p.index()] += 1;
                permit
            }
        };
        // The slot is the queue's now: the receiver gives it back at the take.
        permit.forget();
        {
            let mut st = inner.state.lock();
            let now = inner.now_ns();
            if st.queues.push(p, now, event).is_err() {
                // A permit is a slot: never here. Counted, never silent.
                st.queues.note_dropped(p);
                drop(st);
                inner.room[p.index()].add_permits(1);
                debug_assert!(false, "a send held a slot of a full queue");
                return Ok(());
            }
        }
        inner.ready.notify_one();
        Ok(())
    }

    /// The bus's counts.
    pub fn stats(&self) -> BusStats {
        BusStats(Arc::clone(&self.inner))
    }
}

/// An event taken from the bus, with the execs it overtook.
#[derive(Debug)]
pub struct Received {
    pub event: Event,
    /// Lab PR 267: the execs (`Event::ProcessSpawn`) still queued in P1
    /// that reached the bus before this tamper event, each handed over
    /// once; they are taken in their turn all the same. Empty for every
    /// other event (no other class is taken ahead of an older P1 event).
    pub overtaken: Vec<Event>,
}

/// What the event loop reads from: the one consumer.
pub struct BusReceiver {
    inner: Arc<Inner>,
    /// The event being decided: its queue and when it was queued.
    in_flight: Option<(usize, u64)>,
}

impl Drop for BusReceiver {
    fn drop(&mut self) {
        self.inner.closed.store(true, Ordering::Release);
        for room in &self.inner.room {
            room.close();
        }
    }
}

impl BusReceiver {
    /// The next event, by strict priority with aging; `None` once every
    /// sender is gone and the queues are empty. Cancel-safe: an event is
    /// taken and returned in one step.
    pub async fn recv(&mut self) -> Option<Received> {
        loop {
            if let Some(r) = self.try_recv() {
                return Some(r);
            }
            if self.inner.senders.load(Ordering::Acquire) == 0 {
                return self.try_recv();
            }
            self.inner.ready.notified().await;
        }
    }

    /// [`Self::recv`], the lineage first taught the execs the event
    /// overtook (made absolute as the event loop makes them,
    /// `exe_identity::resolve`) — the bus's barrier for the process lineage
    /// (lab PR 267).
    pub async fn recv_with(&mut self, lineage: Option<&AuthSessionTracker>) -> Option<Received> {
        let mut r = self.recv().await?;
        for e in &mut r.overtaken {
            crate::sensors::exe_identity::resolve(e);
            if let Some(l) = lineage {
                l.ingest_spawn_event(e);
            }
        }
        Some(r)
    }

    /// The next event if one is queued.
    pub fn try_recv(&mut self) -> Option<Received> {
        self.decided();
        let inner = &self.inner;
        let mut st = inner.state.lock();
        let now = inner.now_ns();
        let taken = st.queues.take(now)?;
        let mut overtaken = Vec::new();
        if taken.priority < Priority::P1 {
            st.queues
                .hand_over_older(Priority::P1, taken.enqueued_ns, |e| {
                    if matches!(e, Event::ProcessSpawn { .. }) {
                        overtaken.push(e.clone());
                    }
                });
        }
        drop(st);
        inner.room[taken.priority.index()].add_permits(1);
        self.in_flight = Some((taken.priority.index(), taken.enqueued_ns));
        Some(Received {
            event: taken.item,
            overtaken,
        })
    }

    /// The event last taken is decided: its latency, queue to decision, is
    /// counted. Taking the next event counts it too.
    pub fn decided(&mut self) {
        if let Some((i, enqueued)) = self.in_flight.take() {
            let mut st = self.inner.state.lock();
            let now = self.inner.now_ns();
            st.latency[i].record_ns(now.saturating_sub(enqueued));
        }
    }

    /// The bus's counts.
    pub fn stats(&self) -> BusStats {
        BusStats(Arc::clone(&self.inner))
    }
}

/// The bus's counts, for the status and the loss recorder; clones share
/// the bus.
#[derive(Clone)]
pub struct BusStats(Arc<Inner>);

impl std::fmt::Debug for BusStats {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("BusStats").field(&self.snapshot()).finish()
    }
}

/// One queue's counts since the agent started.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QueueSnapshot {
    pub priority: Priority,
    pub capacity: u64,
    /// What a full queue does, as `nn-admin status` shows it.
    pub when_full: String,
    pub stats: QueueStats,
    /// Sends that waited for room.
    pub waited: u64,
    /// Queue → decision, microseconds: p50, p99, the largest; `None` before
    /// the first decision.
    pub latency_p50_us: Option<u64>,
    pub latency_p99_us: Option<u64>,
    pub latency_max_us: Option<u64>,
    /// Decisions counted.
    pub decided: u64,
}

impl BusStats {
    /// Every queue's counts, P0 first.
    pub fn snapshot(&self) -> Vec<QueueSnapshot> {
        let st = self.0.state.lock();
        Priority::ALL
            .iter()
            .map(|&p| {
                let i = p.index();
                let h = &st.latency[i];
                QueueSnapshot {
                    priority: p,
                    capacity: st.queues.capacity(p) as u64,
                    when_full: when_full_text(p, self.0.specs[i].when_full),
                    stats: st.queues.stats(p),
                    waited: st.waited[i],
                    latency_p50_us: h.quantile_us(0.50),
                    latency_p99_us: h.quantile_us(0.99),
                    latency_max_us: (h.count() > 0).then(|| h.max_us()),
                    decided: h.count(),
                }
            })
            .collect()
    }
}

/// A queue's full behaviour for the status: its class's, and on P2 the
/// opens' drop with the other file events' wait.
fn when_full_text(p: Priority, w: WhenFull) -> String {
    match (p, w) {
        (Priority::P2, WhenFull::DropNew) => {
            "drop the new FileOpen; other file events wait".to_string()
        }
        _ => w.describe(),
    }
}

// ── the loss counters by stage ───────────────────────────────────────

/// One stage of an event's path where it can be lost (plan §3.4), as the
/// status shows it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StageCount {
    pub stage: u8,
    pub name: &'static str,
    /// Lost there since boot; `None`: not counted yet.
    pub total: Option<u64>,
    /// Where it is counted, or the lot that will count it.
    pub source: &'static str,
}

/// The `RING_DROPS` slots that count records a kernel budget held back
/// before the ring (stage 2), not a full ring (stage 1).
const BUDGET_SLOTS: [u32; 4] = [
    common::ring_drops::ring_slot::DNS_RATE,
    common::ring_drops::ring_slot::LISTEN_RATE,
    common::ring_drops::ring_slot::IOURING_RATE,
    common::ring_drops::ring_slot::TASK_DENIAL_RATE,
];

/// The eight stages with their counts: 1 to 3 as the kernel's and the
/// pumps' counters have them (`ring_drops`, `reject`), 4 the bus's queues
/// (`queues`), 5 to 8 not counted yet — R12b counts the decision's delay
/// per class, R12c the response and the evidence writer's queues and the
/// signed `telemetry_loss` rows, R15 the export.
pub fn loss_stages(
    ring: &[(&'static str, u64)],
    rejected: u64,
    queues: &[QueueSnapshot],
) -> Vec<StageCount> {
    let budget: Vec<&str> = BUDGET_SLOTS
        .iter()
        .map(|&s| common::ring_drops::RING_DROP_NAMES[s as usize])
        .collect();
    let (mut kernel_ring, mut kernel_budget) = (0u64, 0u64);
    for (name, n) in ring {
        if budget.contains(name) {
            kernel_budget += n;
        } else {
            kernel_ring += n;
        }
    }
    let bus: u64 = queues.iter().map(|q| q.stats.dropped).sum();
    vec![
        StageCount {
            stage: 1,
            name: "kernel ring",
            total: Some(kernel_ring),
            source: "RING_DROPS: a ring or map full",
        },
        StageCount {
            stage: 2,
            name: "kernel budget",
            total: Some(kernel_budget),
            source: "RING_DROPS dns_rate, listen_rate, io_uring_rate, task_denial_rate",
        },
        StageCount {
            stage: 3,
            name: "decode",
            total: Some(rejected),
            source: "RejectThrottle: malformed records",
        },
        StageCount {
            stage: 4,
            name: "bus queue",
            total: Some(bus),
            source: "the event bus, per queue",
        },
        StageCount {
            stage: 5,
            name: "decision delay",
            total: None,
            source: "not counted yet: R12b",
        },
        StageCount {
            stage: 6,
            name: "response queue",
            total: None,
            source: "not counted yet: R12c",
        },
        StageCount {
            stage: 7,
            name: "evidence writer queue",
            total: None,
            source: "not counted yet: R12c",
        },
        StageCount {
            stage: 8,
            name: "export",
            total: None,
            source: "not counted yet: R12c, the telemetry_loss rows; R15, the export",
        },
    ]
}

// ── the loss recorder ────────────────────────────────────────────────

/// The loss recorder's bindings, late (the bus starts with the eBPF load,
/// before the audit log and the posture exist; the start binds them where
/// it binds the ring-drop sampler's). Clones share them.
#[derive(Clone, Default)]
pub struct BusLosses {
    audit: LateAudit,
    posture: Arc<OnceLock<PostureSink>>,
    recorder: Arc<Mutex<LossRecorder>>,
}

impl BusLosses {
    /// Hand the signed audit log to the recorder.
    pub fn bind_audit_log(&self, log: Option<AuditHandle>) {
        self.audit.bind(log);
    }

    /// Hand the posture (and the trusted-installer window) to the recorder,
    /// so a queue of security events that drops raises ALERTED.
    pub fn bind_posture(
        &self,
        posture: crate::posture::PostureMachine,
        installer: Option<Arc<crate::anti_tamper::trusted_installer::TrustedInstallerOverride>>,
    ) {
        let _ = self.posture.set(PostureSink { posture, installer });
    }

    /// At the stop: every drop not yet in a signed row is signed now,
    /// whatever its queue's window.
    pub fn flush(&self, stats: &BusStats) {
        record(stats, self, true);
    }
}

/// The queues whose drops are security events lost (the posture's
/// `TelemetryLoss` past [`ring_drops::TELEMETRY_LOSS_THRESHOLD`] in a
/// sample): tamper, process, file — what the exec, file-open, FIM and
/// tamper rings carried, security rings whose kernel drops raised it.
const SECURITY_QUEUES: [Priority; 3] = [Priority::P0, Priority::P1, Priority::P2];

/// What one sample decided (pure: [`LossRecorder::sample`]).
#[derive(Debug, Default, PartialEq, Eq)]
pub struct SampleOutcome {
    /// `(queue, dropped this sample, total)` to WARN about.
    pub warn: Vec<(Priority, u64, u64)>,
    /// `(queue, dropped since its last row, total)` to sign.
    pub rows: Vec<(Priority, u64, u64)>,
    /// `(queue, dropped this sample)` past the threshold, for the posture.
    pub telemetry_loss: Vec<(Priority, u64)>,
}

/// The recorder's memory between samples.
#[derive(Debug, Default)]
pub struct LossRecorder {
    seen: [u64; QUEUES],
    signed: [u64; QUEUES],
    last_row: [Option<Instant>; QUEUES],
}

impl LossRecorder {
    /// One sample of the queues' drop totals (`dropped[i]`, P0 first) at
    /// `now`: what to WARN, sign and raise (`flush`: every queue's row is
    /// due). Each row written is told back ([`Self::row_written`]); one
    /// that could not be (no audit log yet) is tried again at the next
    /// sample, with what accrued since.
    pub fn sample(&mut self, dropped: [u64; QUEUES], now: Instant, flush: bool) -> SampleOutcome {
        let mut out = SampleOutcome::default();
        for p in Priority::ALL {
            let i = p.index();
            let (total, delta) = (dropped[i], dropped[i].saturating_sub(self.seen[i]));
            self.seen[i] = self.seen[i].max(total);
            if delta > 0 {
                out.warn.push((p, delta, total));
                if SECURITY_QUEUES.contains(&p) && delta > ring_drops::TELEMETRY_LOSS_THRESHOLD {
                    out.telemetry_loss.push((p, delta));
                }
            }
            let unsigned = total.saturating_sub(self.signed[i]);
            let due = p == Priority::P0
                || flush
                || self.last_row[i].is_none_or(|t| {
                    now.duration_since(t) >= Duration::from_secs(AUDIT_WINDOW_SECS)
                });
            if unsigned > 0 && due {
                out.rows.push((p, unsigned, total));
            }
        }
        out
    }

    /// The row of `p` up to `total` was signed at `now`.
    pub fn row_written(&mut self, p: Priority, total: u64, now: Instant) {
        let i = p.index();
        self.signed[i] = self.signed[i].max(total);
        self.last_row[i] = Some(now);
    }
}

/// Run one sample: WARN, sign, raise.
fn record(stats: &BusStats, losses: &BusLosses, flush: bool) {
    let mut rec = losses.recorder.lock();
    let snap = stats.snapshot();
    let mut dropped = [0u64; QUEUES];
    for q in &snap {
        dropped[q.priority.index()] = q.stats.dropped;
    }
    let now = Instant::now();
    let out = rec.sample(dropped, now, flush);
    for (p, d, total) in &out.warn {
        let q = &snap[p.index()];
        warn!(
            queue = p.label(),
            class = p.name(),
            dropped_since_last_sample = d,
            total,
            capacity = q.capacity,
            when_full = %q.when_full,
            "event bus: events DROPPED — the queue was full; events of this class were lost"
        );
    }
    for (p, d, total) in out.rows {
        let q = &snap[p.index()];
        if sign_drop(&losses.audit, q, d, total) {
            rec.row_written(p, total, now);
        }
    }
    if !out.telemetry_loss.is_empty() {
        let lost: Vec<(String, u64)> = out
            .telemetry_loss
            .iter()
            .map(|(p, d)| (format!("{} {}", p.label(), p.name()), *d))
            .collect();
        let lost: Vec<(&str, u64)> = lost.iter().map(|(n, d)| (n.as_str(), *d)).collect();
        ring_drops::raise_loss(&losses.posture, &lost, "event bus");
    }
}

/// The signed row of a queue's drops; `false` when it could not be written
/// (no audit log bound yet, or the append failed).
fn sign_drop(audit: &LateAudit, q: &QueueSnapshot, dropped: u64, total: u64) -> bool {
    let Some(log) = audit.get() else {
        return false;
    };
    let draft = crate::audit::AuditEntryDraft {
        op: AUDIT_OP.to_string(),
        extra: serde_json::json!({
            "queue": q.priority.label(),
            "class": q.priority.name(),
            "dropped_since_last_row": dropped,
            "total": total,
            "capacity": q.capacity,
            "max_depth": q.stats.max_depth,
            "when_full": q.when_full,
        }),
        key_fp: "agent-self".to_string(),
        cosigner_fps: Vec::new(),
        result: "detected".to_string(),
        client_pid: std::process::id(),
        client_uid: 0,
        client_comm: "northnarrow-agent".to_string(),
        client_exe: None,
    };
    match log.lock().append(draft) {
        Ok(_) => true,
        Err(e) => {
            warn!(
                error = format!("{e:#}"),
                "event-bus drop audit entry failed"
            );
            false
        }
    }
}

/// The loss recorder: every [`SAMPLE_SECS`], the queues' drops WARNed,
/// signed and, for the security queues past the threshold, raised.
pub fn spawn_loss_recorder(stats: BusStats, losses: BusLosses) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_secs(SAMPLE_SECS));
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        tick.tick().await;
        loop {
            tick.tick().await;
            record(&stats, &losses, false);
            debug!("event-bus loss sample");
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn open(pid: u32) -> Event {
        Event::FileOpen {
            pid,
            uid: 1000,
            gid: 1000,
            comm: "flood".into(),
            filename: "/etc/passwd".into(),
            flags: 0,
            timestamp_ns: 0,
            path_from_user: false,
            kernel_class: 0,
        }
    }

    fn denial(pid: u32) -> Event {
        Event::FsProtectDenial {
            pid,
            uid: 0,
            comm: "rm".into(),
            target_dev: 1,
            target_ino: 2,
            operation: nn_model::FsProtectOperation::Unlink,
            timestamp_ns: 0,
        }
    }

    fn spawn(pid: u32) -> Event {
        Event::ProcessSpawn {
            pid,
            ppid: 1,
            uid: 0,
            gid: 0,
            comm: "sh".into(),
            filename: "/bin/sh".into(),
            timestamp_ns: u64::from(pid),
            argv: Vec::new(),
            parent_comm: String::new(),
            parent_start_ns: 0,
            start_ns: u64::from(pid),
            parent_is_kthread: false,
            exe: Default::default(),
            argv_truncated: false,
            filename_truncated: false,
            stdio: Default::default(),
        }
    }

    fn pid_of(e: &Event) -> u32 {
        match e {
            Event::FileOpen { pid, .. }
            | Event::FsProtectDenial { pid, .. }
            | Event::ProcessSpawn { pid, .. } => *pid,
            _ => 0,
        }
    }

    fn small(wait_ms: u64) -> [QueueSpec; QUEUES] {
        let mut s = SPECS;
        for q in &mut s {
            q.capacity = 2;
        }
        s[0].when_full = WhenFull::Wait {
            max_ns: wait_ms * 1_000_000,
        };
        s[1].when_full = WhenFull::Wait {
            max_ns: wait_ms * 1_000_000,
        };
        s
    }

    /// EXP-13 in miniature: a full file queue drops new opens at once and
    /// never delays a tamper event, which is taken first.
    #[tokio::test]
    async fn a_flood_of_opens_neither_blocks_nor_hides_a_denial() {
        let (tx, mut rx) = channel_with(small(50));
        for i in 0..100 {
            tx.send(open(i)).await.unwrap();
        }
        let started = Instant::now();
        tx.send(denial(7)).await.unwrap();
        assert!(
            started.elapsed() < Duration::from_millis(20),
            "never waited"
        );
        let first = rx.try_recv().unwrap();
        assert_eq!(pid_of(&first.event), 7, "the denial first");
        let snap = rx.stats().snapshot();
        assert_eq!(snap[0].stats.enqueued, 1);
        assert_eq!(snap[0].stats.dropped, 0);
        assert_eq!(snap[2].stats.enqueued, 2);
        assert_eq!(snap[2].stats.dropped, 98, "the new opens dropped, counted");
        let rest: Vec<u32> =
            std::iter::from_fn(|| rx.try_recv().map(|r| pid_of(&r.event))).collect();
        assert_eq!(rest, [0, 1], "FIFO: the first two opens");
    }

    /// A full P0 waits for room at most its wait, then drops and counts; a
    /// slot freed meanwhile takes the waiting event.
    #[tokio::test]
    async fn a_full_tamper_queue_waits_then_drops() {
        let (tx, mut rx) = channel_with(small(30));
        tx.send(denial(1)).await.unwrap();
        tx.send(denial(2)).await.unwrap();
        let started = Instant::now();
        tx.send(denial(3)).await.unwrap();
        let waited = started.elapsed();
        assert!(waited >= Duration::from_millis(25), "{waited:?}");
        let snap = rx.stats().snapshot();
        assert_eq!((snap[0].stats.enqueued, snap[0].stats.dropped), (2, 1));
        // now one waits and a take frees its slot
        let tx2 = tx.clone();
        let waiter = tokio::spawn(async move { tx2.send(denial(4)).await });
        tokio::time::sleep(Duration::from_millis(5)).await;
        assert_eq!(pid_of(&rx.try_recv().unwrap().event), 1);
        waiter.await.unwrap().unwrap();
        let snap = rx.stats().snapshot();
        assert_eq!((snap[0].stats.enqueued, snap[0].stats.dropped), (3, 1));
        assert_eq!(snap[0].waited, 1);
        let rest: Vec<u32> =
            std::iter::from_fn(|| rx.try_recv().map(|r| pid_of(&r.event))).collect();
        assert_eq!(rest, [2, 4]);
    }

    /// A file event other than an open waits for room (review 75), ahead of
    /// the opens that come after it.
    #[tokio::test]
    async fn a_drift_waits_for_room_ahead_of_new_opens() {
        let (tx, mut rx) = channel_with(small(30));
        tx.send(open(1)).await.unwrap();
        tx.send(open(2)).await.unwrap();
        let drift = Event::MassWrite {
            pid: 9,
            uid: 0,
            comm: "w".into(),
            count: 64,
            filename: "/srv/x".into(),
            timestamp_ns: 0,
            overwrites: true,
            cgroup_window: false,
        };
        let tx2 = tx.clone();
        let waiter = tokio::spawn(async move { tx2.send(drift).await });
        tokio::time::sleep(Duration::from_millis(5)).await;
        assert!(!waiter.is_finished(), "it waits");
        assert_eq!(pid_of(&rx.try_recv().unwrap().event), 1);
        tx.send(open(3)).await.unwrap(); // the freed slot is the drift's
        waiter.await.unwrap().unwrap();
        let order: Vec<Event> = std::iter::from_fn(|| rx.try_recv().map(|r| r.event)).collect();
        assert!(matches!(order[0], Event::FileOpen { pid: 2, .. }));
        assert!(matches!(order[1], Event::MassWrite { .. }));
        assert_eq!(order.len(), 2, "the open after it was dropped");
        assert_eq!(rx.stats().snapshot()[2].stats.dropped, 1);
    }

    /// A tamper event taken ahead of queued execs brings the older ones
    /// along, each once.
    #[tokio::test]
    async fn a_tamper_event_hands_over_the_execs_it_overtakes() {
        let (tx, mut rx) = channel();
        tx.send(spawn(10)).await.unwrap();
        tx.send(spawn(11)).await.unwrap();
        tx.send(denial(10)).await.unwrap();
        tx.send(spawn(12)).await.unwrap();
        let r = rx.recv().await.unwrap();
        assert_eq!(pid_of(&r.event), 10);
        assert!(matches!(r.event, Event::FsProtectDenial { .. }));
        let handed: Vec<u32> = r.overtaken.iter().map(pid_of).collect();
        assert_eq!(handed, [10, 11], "the execs before it, not the one after");
        let rest: Vec<(u32, usize)> =
            std::iter::from_fn(|| rx.try_recv().map(|r| (pid_of(&r.event), r.overtaken.len())))
                .collect();
        assert_eq!(rest, [(10, 0), (11, 0), (12, 0)]);
    }

    /// The receiver ends once every sender is gone; senders fail once the
    /// receiver is.
    #[tokio::test]
    async fn the_ends_close_each_other() {
        let (tx, mut rx) = channel();
        tx.send(open(1)).await.unwrap();
        drop(tx);
        assert!(rx.recv().await.is_some());
        assert!(rx.recv().await.is_none());
        let (tx, rx) = channel();
        drop(rx);
        assert!(tx.send(open(1)).await.is_err());
    }

    /// A decision's latency is counted at the next take, or when said.
    #[tokio::test]
    async fn decisions_are_timed_per_queue() {
        let (tx, mut rx) = channel();
        tx.send(denial(1)).await.unwrap();
        tx.send(open(2)).await.unwrap();
        rx.try_recv().unwrap();
        rx.try_recv().unwrap(); // the denial's decision ends here
        rx.decided();
        let snap = rx.stats().snapshot();
        assert_eq!((snap[0].decided, snap[2].decided), (1, 1));
        assert!(snap[0].latency_p50_us.is_some());
        assert_eq!(snap[1].latency_p50_us, None);
    }

    /// The stages: the ring drops split into full rings and budgets, the
    /// decoder's, the bus's, and 5 to 8 not counted.
    #[test]
    fn the_stages_split_the_kernel_s_drops_and_name_the_rest() {
        let (tx, rx) = channel_with(small(1));
        drop(tx);
        let mut queues = rx.stats().snapshot();
        queues[2].stats.dropped = 7;
        queues[0].stats.dropped = 1;
        let ring = [
            ("fs_protect", 2u64),
            ("dns_rate", 5),
            ("task_denial_rate", 1),
            ("open_sensor", 3),
        ];
        let st = loss_stages(&ring, 4, &queues);
        let totals: Vec<(u8, Option<u64>)> = st.iter().map(|s| (s.stage, s.total)).collect();
        assert_eq!(
            totals,
            [
                (1, Some(5)),
                (2, Some(6)),
                (3, Some(4)),
                (4, Some(8)),
                (5, None),
                (6, None),
                (7, None),
                (8, None)
            ]
        );
        assert!(st[4].source.contains("R12b") && st[5].source.contains("R12c"));
    }

    /// The recorder: a WARN for each sample with drops; P0 signed at once,
    /// every drop in a row; the other queues at most once per window, the
    /// row then carrying everything since the previous one; the security
    /// queues raise past the threshold.
    #[test]
    fn the_recorder_signs_every_drop() {
        let mut rec = LossRecorder::default();
        let t0 = Instant::now();
        let out = rec.sample([3, 0, 100, 5], t0, false);
        assert_eq!(out.warn.len(), 3);
        assert_eq!(
            out.rows,
            [
                (Priority::P0, 3, 3),
                (Priority::P2, 100, 100),
                (Priority::P3, 5, 5)
            ]
        );
        assert_eq!(out.telemetry_loss, [(Priority::P2, 100)]);
        for (p, _, total) in &out.rows {
            rec.row_written(*p, *total, t0);
        }
        let t1 = t0 + Duration::from_secs(10);
        let out = rec.sample([4, 0, 130, 5], t1, false);
        assert_eq!(out.rows, [(Priority::P0, 1, 4)], "P2 waits for its window");
        rec.row_written(Priority::P0, 4, t1);
        // an unwritten row (no audit log) is tried again with what accrued
        let t2 = t1 + Duration::from_secs(AUDIT_WINDOW_SECS);
        let out = rec.sample([6, 0, 130, 9], t2, false);
        assert_eq!(
            out.rows,
            [
                (Priority::P0, 2, 6),
                (Priority::P2, 30, 130),
                (Priority::P3, 4, 9)
            ]
        );
        let out = rec.sample([6, 0, 130, 9], t2 + Duration::from_secs(10), false);
        assert_eq!(
            out.rows,
            [
                (Priority::P0, 2, 6),
                (Priority::P2, 30, 130),
                (Priority::P3, 4, 9)
            ],
            "again: none was written"
        );
        // a flush signs every queue whatever the window
        rec.row_written(Priority::P0, 6, t2);
        let out = rec.sample([6, 0, 130, 9], t2 + Duration::from_secs(20), true);
        assert_eq!(out.rows, [(Priority::P2, 30, 130), (Priority::P3, 4, 9)]);
        assert!(out.warn.is_empty());
    }
}
