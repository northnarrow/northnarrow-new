//! Tappa 9.0.a — detection persistence.
//!
//! Until now the agent was fire-and-forget on detections: the rule path
//! in `main::process_event` (and, until Wave 4, the path of the on-host
//! LLM advisor) computed a verdict, `warn!`-logged it, ran the executor,
//! and DROPPED the record. The
//! local dashboard (Tappa 9) needs detections to PERSIST so a later
//! sub-step (9.0.b) can expose "the last N detections" over the admin
//! socket and aggregate them for the pipeline/Sankey view.
//!
//! This module is the data layer only. It provides:
//!
//! - [`DetectionRecord`] — one serializable detection, joining the
//!   firing sensor, rule, severity, MITRE tags, principal,
//!   posture-at-detection, the response taken, and an
//!   `Open`/`Acknowledged`/`Closed` lifecycle status. It REUSES the
//!   existing [`Severity`](nn_model::Severity),
//!   [`ResponseAction`](nn_model::ResponseAction) and
//!   [`PostureKind`](nn_model::posture_types::PostureKind) types rather
//!   than redefining them. Records written before Wave 4 (lab PR 214) can
//!   also carry a verdict of the removed LLM advisor
//!   ([`DetectionPath::Ade`], [`AdvisorAction`]); they still decode and
//!   chain-verify, and nothing writes them any more.
//! - [`DetectionSink`] — a cheap, cloneable handle the hot event path
//!   pushes records into. It NEVER blocks on fsync: a record is stamped
//!   with a monotonic id, pushed onto a bounded in-memory queue, and a
//!   dedicated writer task is woken. On a full queue the OLDEST record
//!   that was only logged is dropped, a record of a response that ran
//!   only when nothing else is queued (review 75), and a counter is
//!   bumped (a live dashboard cares about the freshest detections; the
//!   drop is observable via the counter + a log line). This is the
//!   bounded-MPSC-with-drop-oldest the design calls for; a raw `mpsc`
//!   can't drop from the *oldest* end at the producer, so the queue is a
//!   `Mutex<VecDeque>` woken by a `Notify`. Floods of one detection are
//!   kept off the queue upstream ([`crate::detection_budget`]).
//! - [`open`] — wires a [`RotatingChainLog<DetectionRecord>`] (the same
//!   signed, rotation-aware primitive behind audit / FIM / netflow /
//!   canary, [`crate::chainlog`]) to the sink + writer task, seeding the
//!   id counter from the persisted tail so ids stay monotonic across a
//!   restart.
//!
//! OUT OF SCOPE for 9.0.a (later sub-steps): a `Detections` socket read
//! verb (9.0.b) and status-change events (9.0.c). The XAI `explanation`
//! field (9.0.e) was schema-only, never written, and left with the LLM
//! advisor in Wave 4 (lab PR 214).

use std::collections::{HashMap, HashSet, VecDeque};
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use anyhow::{Context, Result};
use chrono::Utc;
use nn_model::posture_types::PostureKind;
use nn_model::{Event, ResponseAction, Severity, Verdict};
use parking_lot::Mutex;
use tokio::sync::Notify;
use tokio::task::JoinHandle;
use tracing::{info, warn};

use crate::audit::AgentSigningKey;
use crate::chainlog::{ProtectionManager, RotatingChainLog, RotationConfig};
use crate::decision::attack::{mitre_of, AttackRef, ATTACK_VERSION};
use crate::response::{ExecutionOutcome, ExecutionReport};

/// Default on-disk location of the detection chainlog. Lives under the
/// anti-tamper-protected state dir (`/var/lib/northnarrow`, mode 0700)
/// in its own `detections/` sub-directory — higher-volume runtime data
/// belongs in `/var/lib`, NOT `/etc` (config). Sealed archives and the
/// manifest are siblings of this active file inside `detections/`.
pub const DEFAULT_DETECTIONS_LOG_PATH: &str = "/var/lib/northnarrow/detections/detections.jsonl";

/// Default on-disk location of the Tappa 9.0.c status-event chainlog —
/// a SECOND signed chain, sibling of [`DEFAULT_DETECTIONS_LOG_PATH`]
/// inside the same anti-tamper-protected `detections/` dir. Triage
/// status changes are event-sourced here ([`StatusEvent`] rows);
/// `detections.jsonl` is never mutated, so its hash chain stays
/// byte-intact. "Current status" of a detection is derived at read
/// time as the latest `StatusEvent` for its id (else the record's own
/// initial `Open`).
pub const DEFAULT_STATUS_EVENTS_LOG_PATH: &str =
    "/var/lib/northnarrow/detections/status_events.jsonl";

/// Default active-file rotation cap for the status-event chain.
/// Status changes are far lower-volume than detections (only operator
/// triage actions, not every fired detection), so a smaller 4 MiB ×
/// [`DEFAULT_MAX_ARCHIVES`] budget is ample. Overridable for test/ops
/// rotation validation via `NN_STATUS_EVENTS_CAP_BYTES` (see `main.rs`).
pub const DEFAULT_STATUS_EVENTS_CAP_BYTES: u64 = 4 * 1024 * 1024;

/// Default active-file rotation cap. Detections are lower-volume than
/// netflow (only *fired* detections, not every flow), so 16 MiB ×
/// [`DEFAULT_MAX_ARCHIVES`] keeps the worst-case on-disk budget at
/// ≈ 9 × 16 MiB = 144 MiB — in line with fim_drift (32 MiB × 8 = 288
/// MiB) and netflow (16 MiB × 16 = 272 MiB). Overridable for test/ops
/// rotation validation via `NN_DETECTIONS_CAP_BYTES` (see `main.rs`).
pub const DEFAULT_DETECTIONS_CAP_BYTES: u64 = 16 * 1024 * 1024;

/// Default sealed-archive retention. Same as fim_drift.
pub const DEFAULT_MAX_ARCHIVES: usize = 8;

/// Default bounded-queue depth between the hot path and the writer task.
/// At a few KiB per record this is ≈ a couple MiB of worst-case buffered
/// memory. A burst beyond this drops the oldest queued record that was
/// only logged (see [`DetectionSink`]).
pub const DEFAULT_QUEUE_CAP: usize = 1024;

// ── record shape ────────────────────────────────────────────────────

/// The records of the detection and status-event logs, and what they are
/// built of: `crate::detection_payload`'s since R04a (lab PR 241, plan:
/// "i tipi dei payload vanno in file propri"), named here as they were.
/// Their constructors from the engine's decisions stay below.
pub use crate::detection_payload::*;

/// Lab PR 224: the network side of a detection ([`DetectionRecord::network`]):
/// for a flow `"<tcp|udp> <dst>:<port> <phase>"` (`connect`, `snapshot
/// open=<N>s`, `closed`, `denied`), for a connect attempt `"tcp <dst>:<port>
/// attempt"`, for an exec whose standard streams are an inet socket
/// `"stdio <tcp|udp> <peer>:<port> <outbound|inbound>"` or, when only its
/// parent's are one connected out, `"parent-stdio … outbound"`. `None`
/// otherwise.
pub fn network_from_event(event: &Event) -> Option<String> {
    use nn_model::telemetry::FlowPhase;
    let proto = |p: u8| match p {
        6 => "tcp",
        17 => "udp",
        _ => "ip",
    };
    match event {
        Event::NetFlow(nf) => {
            let phase = match nf.phase {
                FlowPhase::Snapshot => format!(
                    "snapshot open={}s",
                    nf.observed_ns.saturating_sub(nf.start_ns) / 1_000_000_000
                ),
                p => p.as_str().to_string(),
            };
            Some(format!(
                "{} {} {phase}",
                proto(nf.proto),
                std::net::SocketAddr::new(nf.dst_addr, nf.dst_port)
            ))
        }
        Event::TcpConnect { .. } => crate::decision::rules::net_fanout::attempt_text(event),
        Event::ProcessSpawn { stdio, .. } => {
            let (label, s) = if stdio.own.stdin_or_stdout_inet() {
                ("stdio", &stdio.own)
            } else if stdio.parent.stdin_or_stdout_inet() && stdio.parent.outbound {
                ("parent-stdio", &stdio.parent)
            } else {
                return None;
            };
            let peer = s.peer.map_or_else(|| "?".to_string(), |p| p.to_string());
            let dir = if s.outbound { "outbound" } else { "inbound" };
            Some(format!("{label} {} {peer} {dir}", s.proto_name()))
        }
        _ => None,
    }
}

impl RuleMatchRecord {
    /// The record entries of `d`'s matches, when the record lists them.
    pub fn of(d: &crate::decision::combine::Decision) -> Option<Vec<Self>> {
        use crate::decision::combine::Applied;
        if d.matches.len() < 2
            && d.primary().applied == Applied::Builtin
            && d.primary().held != Some(crate::decision::combine::LEGACY_CEILING)
        {
            return None;
        }
        Some(
            d.matches
                .iter()
                .map(|m| RuleMatchRecord {
                    rule_id: m.rule_id.to_string(),
                    action: m.verdict.action.clone(),
                    severity: m.verdict.severity,
                    mode: m.applied.name().to_string(),
                    pid: m.verdict.event_pid,
                    mitre: mitre_of(m.attack),
                    held: m.held.map(str::to_string),
                    held_action: m.held_action.clone(),
                    exempt: match &m.applied {
                        Applied::Exempt(e) => Some(e.clone()),
                        _ => None,
                    },
                })
                .collect(),
        )
    }
}

impl DetectionRecord {
    /// Build a detection from a rule-path verdict. Pure (no clock / no
    /// id assignment) so it is deterministic in tests; the [`DetectionSink`]
    /// supplies `id` + `ts`.
    pub fn from_rule(
        id: u64,
        ts: String,
        event: &Event,
        verdict: &Verdict,
        posture: PostureKind,
        response: String,
    ) -> Self {
        DetectionRecord {
            id,
            ts,
            sensor: Sensor::from_event(event),
            path: DetectionPath::Rule,
            rule_id: Some(verdict.rule_id.clone()),
            rule_name: Some(verdict.rule_name.clone()),
            severity: verdict.severity,
            verdict: DetectionVerdict::Rule(verdict.action.clone()),
            confidence: 1.0,
            // The verdict names no ATT&CK reference: the rule that issued
            // it does ([`Self::with_attack`], lab PR 221). Empty until then.
            mitre: MitreAttack::default(),
            principal: Principal::from_event(event),
            exe: exe_from_event(event),
            posture_at: posture,
            response,
            detection_type: verdict.category.clone(),
            status: DetectionStatus::Open,
            suppressed_before: None,
            file: file_from_event(event),
            operation: operation_from_event(event),
            mitre_version: None,
            execq: None,
            network: network_from_event(event),
            sanction: None,
            execpol: None,
            matches: None,
        }
    }

    /// Lab PR 221 (capability C16): this rule-path record with the ATT&CK
    /// references of the rule that fired — their tactic and technique ids
    /// in [`Self::mitre`] ([`mitre_of`]), their version in
    /// [`Self::mitre_version`]. No reference (a demo rule) leaves both as
    /// they were: empty, absent.
    pub fn with_attack(mut self, refs: &[AttackRef]) -> Self {
        if !refs.is_empty() {
            self.mitre = mitre_of(refs);
            self.mitre_version = Some(ATTACK_VERSION.to_string());
        }
        self
    }
}

impl DetectionRecord {
    /// The record of a response that ran, or would have in detect-only
    /// mode (a kill, an isolation, a kernel denial), as opposed to a
    /// verdict that was only logged. A full queue evicts these last
    /// (review 75).
    fn acted(&self) -> bool {
        match &self.verdict {
            DetectionVerdict::Rule(ResponseAction::Log) => self.sensor == Sensor::AntiTamper,
            DetectionVerdict::Rule(_) => true,
            DetectionVerdict::Ade(_) => self.response != "none",
        }
    }
}

/// Render the executor's outcome into the record's `response` string.
/// Detect-only suppression ([`ExecutionOutcome::WouldExecute`]) is
/// surfaced distinctly from a real action; a `Log` action (observe-only)
/// is `"none"`.
///
/// External audit NN-AUD-234: the bare action name (`"KillProcess"`) means
/// the action was carried out. It was also what a kill that found the
/// process gone, was refused (a protected PID), was denied by the kernel or
/// failed recorded, so the record claimed a containment that did not
/// happen. Those now name the outcome after the action, in parentheses:
/// `"KillProcess (already gone)"`, `"KillProcessTree (refused: <reason>)"`,
/// `"KillProcess (permission denied)"`, `"Quarantine (failed: <error>)"`,
/// and a tree kill that left part of the tree running
/// `"KillProcessTree (partial: 1 not killed, 1 spared)"`. The action name
/// stays the first word, so a reader keyed on it (a prefix match) still
/// finds the action; records written before keep their text (the chain
/// covers each line as written).
pub fn describe_response(report: &ExecutionReport) -> String {
    let outcome = match &report.primary {
        ExecutionOutcome::WouldExecute { .. } => return "suppressed (detect-only)".to_string(),
        _ if report.action == ResponseAction::Log => return "none".to_string(),
        ExecutionOutcome::Killed { .. }
        | ExecutionOutcome::Blocked { .. }
        | ExecutionOutcome::Quarantined { .. }
        | ExecutionOutcome::Throttled { .. }
        | ExecutionOutcome::CapabilityStripped { .. } => partial_outcome(&report.additional),
        ExecutionOutcome::AlreadyGone { .. } => Some("already gone".to_string()),
        ExecutionOutcome::Refused { reason, .. } => Some(format!("refused: {reason}")),
        ExecutionOutcome::PermissionDenied { .. } => Some("permission denied".to_string()),
        ExecutionOutcome::Failed { errno: 0, .. } => Some("failed".to_string()),
        ExecutionOutcome::Failed { errno, .. } => Some(format!("failed: {}", errno_text(*errno))),
        // Never a primary outcome today; reported, not hidden, if it becomes one.
        ExecutionOutcome::TreeTruncated { .. } => Some("partial: walk truncated".to_string()),
    };
    let action = format!("{:?}", report.action);
    match outcome {
        Some(outcome) => format!("{action} ({outcome})"),
        None => action,
    }
}

/// What a successful action left undone, from the outcomes beyond the
/// primary one (the descendants of a `KillProcessTree`): those not killed,
/// those the guard spared, a walk cut short. `None` when nothing was left.
fn partial_outcome(additional: &[ExecutionOutcome]) -> Option<String> {
    let not_killed = additional
        .iter()
        .filter(|o| {
            matches!(
                o,
                ExecutionOutcome::Failed { .. } | ExecutionOutcome::PermissionDenied { .. }
            )
        })
        .count();
    let spared = additional
        .iter()
        .filter(|o| matches!(o, ExecutionOutcome::Refused { .. }))
        .count();
    let truncated = additional
        .iter()
        .any(|o| matches!(o, ExecutionOutcome::TreeTruncated { .. }));
    let mut parts = Vec::new();
    if not_killed > 0 {
        parts.push(format!("{not_killed} not killed"));
    }
    if spared > 0 {
        parts.push(format!("{spared} spared"));
    }
    if truncated {
        parts.push("walk truncated".to_string());
    }
    (!parts.is_empty()).then(|| format!("partial: {}", parts.join(", ")))
}

/// `errno` as the system describes it, with its number: "Connection timed
/// out, errno 110".
fn errno_text(errno: i32) -> String {
    let text = std::io::Error::from_raw_os_error(errno).to_string();
    let detail = text
        .strip_suffix(&format!(" (os error {errno})"))
        .unwrap_or(&text);
    format!("{detail}, errno {errno}")
}

// ── sink + writer ───────────────────────────────────────────────────

/// Shared state between the [`DetectionSink`] handles and the writer
/// task.
struct SinkInner {
    queue: Mutex<VecDeque<DetectionRecord>>,
    notify: Notify,
    /// Last assigned id (seeded from the persisted tail). The next id is
    /// `fetch_add(1) + 1`, so a fresh store hands out `1, 2, 3, …`.
    last_id: AtomicU64,
    /// Cumulative records dropped under backpressure.
    dropped: AtomicU64,
    /// External audit NN-AUD-111: what was dropped since the last report
    /// ([`DetectionSink::report_drops`]). Locked after `queue`, never
    /// before.
    drops: Mutex<DropWindow>,
    cap: usize,
}

/// Audit op of the signed record of queue drops (external audit NN-AUD-111).
pub const DROPPED_AUDIT_OP: &str = "detections_dropped";

/// Records dropped from the queue in one report window.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DropWindow {
    pub count: u64,
    /// Id of the first and the last record dropped in the window (ids of
    /// dropped records need not be contiguous).
    pub first_id: u64,
    pub last_id: u64,
    pub lowest_id: u64,
    pub highest_id: u64,
    /// Dropped per severity: low, medium, high, critical.
    pub by_severity: [u64; 4],
    /// Dropped records of a response that ran.
    pub acted: u64,
}

impl DropWindow {
    fn note(&mut self, r: &DetectionRecord) {
        if self.count == 0 {
            self.first_id = r.id;
            self.lowest_id = r.id;
            self.highest_id = r.id;
        }
        self.count += 1;
        self.last_id = r.id;
        self.lowest_id = self.lowest_id.min(r.id);
        self.highest_id = self.highest_id.max(r.id);
        self.by_severity[usize::from(severity_rank(r.severity))] += 1;
        if r.acted() {
            self.acted += 1;
        }
    }
}

/// Cheap, cloneable handle the hot event path uses to record detections.
/// Recording never blocks on I/O: it stamps an id, pushes onto the
/// bounded queue (dropping the oldest entry if full), and wakes the
/// writer task.
#[derive(Clone)]
pub struct DetectionSink {
    inner: Arc<SinkInner>,
}

impl DetectionSink {
    fn next_id(&self) -> u64 {
        self.inner.last_id.fetch_add(1, Ordering::SeqCst) + 1
    }

    /// Push `record` onto the bounded queue. If full, one record goes and
    /// the dropped counter moves. The record of a response that ran goes
    /// only when every queued record is one: a flood of logged verdicts
    /// can no longer evict the record of a kill (review 75); then a logged
    /// record that finds no room is the one dropped. Among logged-only
    /// records the lowest severity goes first, oldest first within a
    /// severity (external audit NN-AUD-111: a flood of Low verdicts used to
    /// evict a High canary read queued before it); an incoming logged
    /// record of a lower severity than every queued one is dropped itself.
    /// Each drop is noted for the signed report. Wakes the writer. Holds
    /// the queue lock only for the push — the fsync happens on the writer
    /// task, never here.
    fn enqueue(&self, record: DetectionRecord) {
        {
            let mut q = self.inner.queue.lock();
            if q.len() >= self.inner.cap {
                self.inner.dropped.fetch_add(1, Ordering::Relaxed);
                let victim = q
                    .iter()
                    .enumerate()
                    .filter(|(_, r)| !r.acted())
                    .min_by_key(|(i, r)| (severity_rank(r.severity), *i))
                    .map(|(i, r)| (i, severity_rank(r.severity)));
                let gone = match victim {
                    Some((i, rank)) if record.acted() || severity_rank(record.severity) >= rank => {
                        q.remove(i)
                    }
                    Some(_) => None,
                    None if !record.acted() => None,
                    None => q.pop_front(),
                };
                let mut drops = self.inner.drops.lock();
                match gone {
                    Some(r) => drops.note(&r),
                    None => {
                        drops.note(&record);
                        return;
                    }
                }
            }
            q.push_back(record);
        }
        self.inner.notify.notify_one();
    }

    /// External audit NN-AUD-111: take what was dropped since the last
    /// call, `None` when nothing was.
    pub fn take_drops(&self) -> Option<DropWindow> {
        let mut d = self.inner.drops.lock();
        (d.count > 0).then(|| std::mem::take(&mut *d))
    }

    /// External audit NN-AUD-111: record in the signed audit chain what the
    /// queue dropped since the last call (one entry per window, none when
    /// nothing was dropped), so the missing ids are evidence, not only a
    /// counter and a WARN. Called by the budget reporter every
    /// [`crate::detection_budget::REPORT_SECS`].
    pub fn report_drops(&self, audit_log: Option<&Mutex<crate::audit::AuditLog>>) {
        let Some(d) = self.take_drops() else {
            return;
        };
        let [low, medium, high, critical] = d.by_severity;
        warn!(
            target: "detection_store",
            dropped = d.count,
            first_id = d.first_id,
            last_id = d.last_id,
            low, medium, high, critical,
            acted = d.acted,
            "detection records dropped from a full queue (not in the detection chain)",
        );
        let Some(log) = audit_log else { return };
        let draft = crate::audit::AuditEntryDraft {
            op: DROPPED_AUDIT_OP.to_string(),
            extra: serde_json::json!({
                "window_secs": crate::detection_budget::REPORT_SECS,
                "count": d.count,
                "first_id": d.first_id,
                "last_id": d.last_id,
                "lowest_id": d.lowest_id,
                "highest_id": d.highest_id,
                "severities": {
                    "low": low,
                    "medium": medium,
                    "high": high,
                    "critical": critical,
                },
                "acted": d.acted,
                "dropped_total": self.dropped(),
            }),
            key_fp: "agent-self".to_string(),
            cosigner_fps: Vec::new(),
            result: "detected".to_string(),
            client_pid: std::process::id(),
            client_uid: 0,
            client_comm: "northnarrow-agent".to_string(),
            client_exe: None,
        };
        if let Err(e) = log.lock().append(draft) {
            warn!(
                target: "detection_store",
                error = format!("{e:#}"),
                "detections-dropped audit entry failed"
            );
        }
    }

    /// Record a rule-path detection (off the hot path).
    /// `attack`: the ATT&CK references of the rule that issued `verdict`
    /// ([`DetectionRecord::with_attack`]).
    /// `suppressed_before`: see [`DetectionRecord::suppressed_before`].
    pub fn record_rule(
        &self,
        event: &Event,
        verdict: &Verdict,
        attack: &[AttackRef],
        posture: PostureKind,
        response: String,
        suppressed_before: u64,
    ) {
        let mut record =
            DetectionRecord::from_rule(self.next_id(), now_ts(), event, verdict, posture, response)
                .with_attack(attack);
        record.suppressed_before = (suppressed_before > 0).then_some(suppressed_before);
        // Lab PR 225: a sanctioned security-tool finding names why.
        if verdict.rule_id.starts_with("NN-L-EVA-") {
            record.sanction = crate::impair::published_sanction(event);
        }
        self.enqueue(record);
    }

    /// Lab PR 236: record an engine decision — its verdict (the primary
    /// rule's, with the decision's action and severity), the ATT&CK union
    /// of its matches, and the matches ([`DetectionRecord::matches`]).
    pub fn record_decision(
        &self,
        event: &Event,
        decision: &crate::decision::combine::Decision,
        posture: PostureKind,
        response: String,
        suppressed_before: u64,
    ) {
        let verdict = &decision.verdict;
        let mut record =
            DetectionRecord::from_rule(self.next_id(), now_ts(), event, verdict, posture, response)
                .with_attack(&decision.attack());
        record.suppressed_before = (suppressed_before > 0).then_some(suppressed_before);
        // Lab PR 225: a sanctioned security-tool finding names why.
        if decision
            .matches
            .iter()
            .any(|m| m.rule_id.starts_with("NN-L-EVA-"))
        {
            record.sanction = crate::impair::published_sanction(event);
        }
        record.matches = RuleMatchRecord::of(decision);
        self.enqueue(record);
    }

    /// Lab PR 223: record an exec quarantine decision — a rule-path record
    /// of `verdict`, with its ATT&CK references (lab PR 221: typed, their
    /// ids in `mitre` and the version in `mitre_version`) and the guard's
    /// `evidence`.
    #[allow(clippy::too_many_arguments)]
    pub fn record_execq(
        &self,
        event: &Event,
        verdict: &Verdict,
        posture: PostureKind,
        response: String,
        attack: &[AttackRef],
        evidence: ExecqEvidence,
        suppressed_before: u64,
    ) {
        let mut record =
            DetectionRecord::from_rule(self.next_id(), now_ts(), event, verdict, posture, response)
                .with_attack(attack);
        record.execq = Some(evidence);
        record.suppressed_before = (suppressed_before > 0).then_some(suppressed_before);
        self.enqueue(record);
    }

    /// Lab PR 226: record an exec policy finding — a rule-path record of
    /// `verdict`, with its ATT&CK references (lab PR 221: typed, their ids
    /// in `mitre`, the version in `mitre_version`) and the policy's
    /// `evidence`.
    #[allow(clippy::too_many_arguments)]
    pub fn record_execpol(
        &self,
        event: &Event,
        verdict: &Verdict,
        posture: PostureKind,
        response: String,
        attack: &[AttackRef],
        evidence: ExecPolEvidence,
        suppressed_before: u64,
    ) {
        let mut record =
            DetectionRecord::from_rule(self.next_id(), now_ts(), event, verdict, posture, response)
                .with_attack(attack);
        record.execpol = Some(evidence);
        record.suppressed_before = (suppressed_before > 0).then_some(suppressed_before);
        self.enqueue(record);
    }

    /// Cumulative records dropped under backpressure (for metrics).
    pub fn dropped(&self) -> u64 {
        self.inner.dropped.load(Ordering::Relaxed)
    }

    #[cfg(test)]
    fn queue_snapshot(&self) -> Vec<u64> {
        self.inner.queue.lock().iter().map(|r| r.id).collect()
    }

    #[cfg(test)]
    fn for_test(cap: usize, seed_last_id: u64) -> Self {
        DetectionSink {
            inner: Arc::new(SinkInner {
                queue: Mutex::new(VecDeque::new()),
                notify: Notify::new(),
                last_id: AtomicU64::new(seed_last_id),
                dropped: AtomicU64::new(0),
                drops: Mutex::new(DropWindow::default()),
                cap,
            }),
        }
    }
}

/// Wall-clock timestamp string, matching the audit log's format. Used
/// to stamp [`DetectionRecord`]s (the sink) and [`StatusEvent`]s (the
/// 9.0.c set-status dispatch).
pub fn now_ts() -> String {
    Utc::now().format("%Y-%m-%dT%H:%M:%S%.6fZ").to_string()
}

/// Open the detection chainlog at `active_path`, seed the id counter
/// from its persisted tail, and spawn the dedicated writer task. Returns
/// the [`DetectionSink`] to thread into the event loop plus the writer's
/// [`JoinHandle`]. The active file should already exist (bootstrapped
/// pre-attach, mirroring the FIM/netflow logs) so the inode is
/// registered with the anti-tamper LSM map before lockdown.
pub fn open(
    active_path: &Path,
    key: AgentSigningKey,
    cfg: RotationConfig,
    protection: Arc<dyn ProtectionManager>,
    queue_cap: usize,
) -> Result<(DetectionSink, JoinHandle<()>)> {
    let log = RotatingChainLog::<DetectionRecord>::open(active_path, key, cfg, protection)
        .with_context(|| format!("opening detection chainlog {}", active_path.display()))?;
    // Seed AFTER open so any torn-tail repair has already run.
    let seed = seed_last_id(active_path);
    let inner = Arc::new(SinkInner {
        queue: Mutex::new(VecDeque::new()),
        notify: Notify::new(),
        last_id: AtomicU64::new(seed),
        dropped: AtomicU64::new(0),
        drops: Mutex::new(DropWindow::default()),
        cap: queue_cap,
    });
    let handle = spawn_writer(log, Arc::clone(&inner));
    info!(
        target: "detection_store",
        path = %active_path.display(),
        seed_last_id = seed,
        queue_cap,
        "detection store opened",
    );
    Ok((DetectionSink { inner }, handle))
}

/// The dedicated writer task: sleeps on the [`Notify`], drains the whole
/// queue under a brief lock, then appends each record to the chainlog
/// (the only place fsync happens). Append failures are logged, not
/// fatal — losing one detection must not take down the agent. Runs for
/// the life of the process.
fn spawn_writer(
    mut log: RotatingChainLog<DetectionRecord>,
    inner: Arc<SinkInner>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut reported_dropped = 0u64;
        loop {
            inner.notify.notified().await;
            // Drain everything queued so far under a brief lock; append
            // (and fsync) outside the lock so producers never wait on I/O.
            let batch: Vec<DetectionRecord> = {
                let mut q = inner.queue.lock();
                q.drain(..).collect()
            };
            for record in batch {
                let id = record.id;
                if let Err(e) = log.append(record) {
                    warn!(
                        target: "detection_store",
                        error = %e,
                        id,
                        "detection chainlog append failed (record lost)",
                    );
                }
            }
            // Surface backpressure drops once per change, off the hot path.
            let dropped = inner.dropped.load(Ordering::Relaxed);
            if dropped != reported_dropped {
                warn!(
                    target: "detection_store",
                    dropped_total = dropped,
                    "detection records dropped under backpressure (queue full: logged-only records first)",
                );
                reported_dropped = dropped;
            }
        }
    })
}

// ── id seeding ──────────────────────────────────────────────────────

/// Seed the id counter so ids stay monotonic across a restart. Reads the
/// last data line of the active file; if the active file is empty (fresh
/// install, or it was just rotated and no new record has landed yet),
/// falls back to the highest id across the sealed archives so ids never
/// reuse across a rotation boundary. Returns `0` ⇒ the first id is `1`.
fn seed_last_id(active_path: &Path) -> u64 {
    if let Some(id) = last_id_in_file(active_path) {
        return id;
    }
    crate::chainlog::archives_newest_first(active_path)
        .iter()
        .filter_map(|p| last_id_in_file(p))
        .max()
        .unwrap_or(0)
}

/// Highest `id` among the data lines of `path`, or `None`. Scans from the
/// end and returns the first line that parses to a JSON object carrying a
/// numeric `id` — this skips a trailing terminator / manifest line (which
/// have no `id`). The file is size-capped (≤ rotation cap), so this
/// one-time, bounded boot read is not the unbounded whole-file walk that
/// BUG-026 removed from the chainlog hot path.
fn last_id_in_file(path: &Path) -> Option<u64> {
    let body = std::fs::read_to_string(path).ok()?;
    body.lines().rev().find_map(|line| {
        let value: serde_json::Value = serde_json::from_str(line).ok()?;
        value.get("id")?.as_u64()
    })
}

// ── bounded last-N read (9.0.b) ─────────────────────────────────────

/// CLI default for `nn-admin detections --limit` when the operator
/// gives none (the wire carries `limit = 0` ⇒ this default). A live
/// dashboard wants the freshest handful, not the whole store.
pub const DEFAULT_DETECTIONS_LIMIT: usize = 50;

/// Hard server-side ceiling on a single `Detections` read. Clamps a
/// fat-fingered or hostile `--limit`: combined with the wire frame's
/// own [`crate::admin_socket`] soft cap, the response can never force
/// an unbounded read of the retained set.
pub const MAX_DETECTIONS_LIMIT: usize = 1000;

/// Parsed, typed filter for a [`read_last_n`] query. All fields are
/// optional; `None` means "no constraint on that dimension". Built by
/// the admin-socket dispatch from the wire `DetectionsExtra` (which
/// carries the enum filters as lowercase strings).
#[derive(Debug, Clone, Default)]
pub struct DetectionFilter {
    /// Inclusive lower bound on the detection's wall-clock `ts`, in
    /// UNIX seconds.
    pub since_unix: Option<i64>,
    /// Inclusive upper bound on the detection's wall-clock `ts`, in
    /// UNIX seconds.
    pub until_unix: Option<i64>,
    /// Keep detections at or above this severity rung.
    pub min_severity: Option<Severity>,
    /// Exact-match the triage status.
    pub status: Option<DetectionStatus>,
    /// Exact-match the originating sensor.
    pub sensor: Option<Sensor>,
    /// The `--path` operator filter: a substring of what the record says
    /// the detection is about — its executable
    /// ([`DetectionRecord::exe`], exec sensors), its file
    /// ([`DetectionRecord::file`], file sensors) or the acting
    /// principal's `comm` (every sensor). A record is kept when any of
    /// the three contains it. External audit ASK-018: it was matched
    /// against `comm` only, so `--path /usr/bin/curl` found nothing while
    /// the records named the path; the matches are a superset of before.
    pub subject_substr: Option<String>,
}

/// Severity as a comparable rung (`Low` < `Medium` < `High` <
/// `Critical`). [`nn_model::Severity`] is not `Ord`, so the
/// `min_severity` filter ranks explicitly rather than relying on a
/// derived ordering that could silently drift if a rung is inserted.
fn severity_rank(s: Severity) -> u8 {
    match s {
        Severity::Low => 0,
        Severity::Medium => 1,
        Severity::High => 2,
        Severity::Critical => 3,
    }
}

/// Parse a `--min-severity` token (case-insensitive). `None` on an
/// unrecognised token.
pub fn parse_severity_filter(s: &str) -> Option<Severity> {
    match s.trim().to_ascii_lowercase().as_str() {
        "low" => Some(Severity::Low),
        "medium" => Some(Severity::Medium),
        "high" => Some(Severity::High),
        "critical" => Some(Severity::Critical),
        _ => None,
    }
}

impl DetectionStatus {
    /// Parse a `--status` filter token (case-insensitive). Accepts
    /// every rung, INCLUDING `open` (an operator can filter for
    /// still-open detections). `None` on an unrecognised token.
    pub fn parse_filter(s: &str) -> Option<DetectionStatus> {
        match s.trim().to_ascii_lowercase().as_str() {
            "open" => Some(DetectionStatus::Open),
            "acknowledged" | "ack" => Some(DetectionStatus::Acknowledged),
            "investigating" => Some(DetectionStatus::Investigating),
            "resolved" => Some(DetectionStatus::Resolved),
            "false-positive" | "false_positive" | "falsepositive" | "fp" => {
                Some(DetectionStatus::FalsePositive)
            }
            _ => None,
        }
    }

    /// Parse a `detection-set-status` TARGET token (case-insensitive).
    /// Like [`Self::parse_filter`] but REJECTS `open`: `Open` is the
    /// initial state a detection is recorded in, not a triage target an
    /// operator transitions TO (the lifecycle only moves forward). An
    /// unrecognised token (or `open`) yields `None`.
    pub fn parse_settable(s: &str) -> Option<DetectionStatus> {
        match Self::parse_filter(s) {
            Some(DetectionStatus::Open) | None => None,
            other => other,
        }
    }

    /// Canonical lowercase wire string for this status (the inverse of
    /// [`Self::parse_filter`]). Used for the `DetectionSetStatus` ack
    /// echo and for rendering. `false-positive` is hyphenated, matching
    /// the CLI value-enum + the `Sensor` wire spelling convention.
    pub fn as_str(&self) -> &'static str {
        match self {
            DetectionStatus::Open => "open",
            DetectionStatus::Acknowledged => "acknowledged",
            DetectionStatus::Investigating => "investigating",
            DetectionStatus::Resolved => "resolved",
            DetectionStatus::FalsePositive => "false-positive",
        }
    }
}

/// Parse a record's wall-clock `ts` (RFC-3339, e.g.
/// `2026-06-09T12:00:00.123456Z`) to UNIX seconds, or `None` if it
/// does not parse. The agent writes this field itself, so a parse
/// failure is not expected; the time filter treats it leniently (an
/// unparseable `ts` is not excluded) rather than silently dropping a
/// detection an operator might need to see.
fn ts_to_unix(ts: &str) -> Option<i64> {
    chrono::DateTime::parse_from_rfc3339(ts)
        .ok()
        .map(|dt| dt.timestamp())
}

impl DetectionRecord {
    /// Does this record satisfy every set constraint in `filter`?
    fn matches(&self, filter: &DetectionFilter) -> bool {
        if let Some(since) = filter.since_unix {
            if let Some(t) = ts_to_unix(&self.ts) {
                if t < since {
                    return false;
                }
            }
        }
        if let Some(until) = filter.until_unix {
            if let Some(t) = ts_to_unix(&self.ts) {
                if t > until {
                    return false;
                }
            }
        }
        if let Some(min) = filter.min_severity {
            if severity_rank(self.severity) < severity_rank(min) {
                return false;
            }
        }
        if let Some(status) = filter.status {
            if self.status != status {
                return false;
            }
        }
        if let Some(sensor) = filter.sensor {
            if self.sensor != sensor {
                return false;
            }
        }
        if let Some(ref sub) = filter.subject_substr {
            let sub = sub.as_str();
            let names = |field: &Option<String>| field.as_deref().is_some_and(|v| v.contains(sub));
            if !(self.principal.comm.contains(sub) || names(&self.exe) || names(&self.file)) {
                return false;
            }
        }
        true
    }
}

/// Read the last `limit` detections from the chainlog at
/// `active_path`, **newest-first**, applying `filter`.
///
/// Bounded read (BUG-026 discipline): the size-capped active file is
/// read in full (it is the newest data and ≤ the rotation cap), then
/// sealed archives are descended **newest-sealed-first** ONLY while
/// fewer than `limit` matching records have been collected. So the
/// common case — the active file alone satisfies `limit` — opens
/// exactly one file, and even a highly selective filter is bounded by
/// the retention window ([`DEFAULT_MAX_ARCHIVES`] files), never an
/// unbounded walk. Records are then sorted by `id` descending (the id
/// is monotonic, so id-desc == newest-first across files) and bounded
/// to `limit`.
///
/// Each line is parsed directly as a [`DetectionRecord`]; the chain
/// envelope fields (`prev_hash` / `entry_hash` / `agent_sig` /
/// `fmt_ver`) are flattened siblings and are simply ignored, while a
/// terminator / manifest / torn line (which carries no `id`) fails to
/// parse and is skipped. This entry point does not verify the rows; the
/// admin read path uses [`read_last_n_verified`].
pub fn read_last_n(
    active_path: &Path,
    limit: usize,
    filter: &DetectionFilter,
) -> Vec<DetectionRecord> {
    read_last_n_verified(active_path, limit, filter, None).0
}

/// [`read_last_n`], and with `pubkey` every row returned is checked
/// first: its `entry_hash` recomputes and its signature verifies (external
/// audit NN-AUD-112: any well-formed JSON line in `detections.jsonl` was
/// served as a detection). A row that fails is left out and counted (the
/// second value). Only the rows returned are checked (at most `limit`, a
/// few milliseconds); the chain's links are `nn-admin chain verify`'s.
pub fn read_last_n_verified(
    active_path: &Path,
    limit: usize,
    filter: &DetectionFilter,
    pubkey: Option<&ed25519_dalek::VerifyingKey>,
) -> (Vec<DetectionRecord>, usize) {
    // (record, raw line, already verified)
    let mut collected: Vec<(DetectionRecord, String, bool)> = Vec::new();
    let mut unverified = 0usize;
    // External audit EVD-010 (NN-AUD-275): what one file can contribute.
    // Without a key, the newest `limit` matches; with one, the newest
    // `limit` that verify within MAX_UNVERIFIED_PER_READ failures — so the
    // newest `limit + MAX_UNVERIFIED_PER_READ` matches by id suffice. The
    // collector keeps only those, never the whole file.
    let cap = match pubkey {
        Some(_) => limit.saturating_add(MAX_UNVERIFIED_PER_READ),
        None => limit,
    };
    let mut fill = |collected: &mut Vec<(DetectionRecord, String, bool)>, path: &Path| {
        let found = collect_matching_from_file(path, filter, cap, pubkey.is_some());
        collected.extend(found.into_iter().map(|(r, l)| (r, l, false)));
        // Newest first; with a key, keep the newest `limit` rows that
        // verify (a forged row does not count towards `limit`). At most
        // MAX_UNVERIFIED_PER_READ failures are tried, so a flood of forged
        // lines cannot make one read verify the whole file.
        collected.sort_by_key(|(r, _, _)| std::cmp::Reverse(r.id));
        let Some(pk) = pubkey else {
            collected.truncate(limit);
            return;
        };
        let mut kept = Vec::with_capacity(limit.min(collected.len()));
        for (r, line, checked) in collected.drain(..) {
            if kept.len() >= limit || unverified >= MAX_UNVERIFIED_PER_READ {
                break;
            }
            if checked || crate::chainlog::line_is_genuine::<DetectionRecord>(line.as_bytes(), pk) {
                kept.push((r, line, true));
            } else {
                unverified += 1;
            }
        }
        *collected = kept;
    };
    fill(&mut collected, active_path);
    if collected.len() < limit {
        for archive in crate::chainlog::archives_newest_first(active_path) {
            fill(&mut collected, &archive);
            if collected.len() >= limit {
                break;
            }
        }
    }
    // Monotonic id ⇒ id-desc is newest-first across every file we
    // touched; bound to the requested N.
    (
        collected.into_iter().map(|(r, _, _)| r).collect(),
        unverified,
    )
}

/// Rows that fail verification tried by one [`read_last_n_verified`].
const MAX_UNVERIFIED_PER_READ: usize = 1000;

/// One match held by [`collect_matching_from_file`], ordered as the
/// read's sort orders it: higher id first, and for equal ids (a forged
/// copy) the earlier line first.
struct Held {
    id: u64,
    line_no: usize,
    record: DetectionRecord,
    line: String,
}

impl Held {
    /// Larger = served first.
    fn rank(&self) -> (u64, std::cmp::Reverse<usize>) {
        (self.id, std::cmp::Reverse(self.line_no))
    }
}

impl PartialEq for Held {
    fn eq(&self, other: &Self) -> bool {
        self.rank() == other.rank()
    }
}
impl Eq for Held {}
impl PartialOrd for Held {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}
impl Ord for Held {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.rank().cmp(&other.rank())
    }
}

#[cfg(test)]
thread_local! {
    /// The most matches [`collect_matching_from_file`] held at once on
    /// this thread (external audit EVD-010's test).
    static HELD_HIGH_WATER: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

/// The matching [`DetectionRecord`]s of one chainlog file (active or
/// sealed archive), at most `cap` of them: the ones the read serves first
/// (highest id, then earliest line), in that order, each with its raw
/// line when `keep_lines` (the signature check needs it). Best-effort: a
/// missing / unreadable file contributes nothing; lines that don't parse
/// as a `DetectionRecord` (terminators, blanks) are skipped.
///
/// External audit EVD-010 (NN-AUD-275): a bounded min-heap of `cap`
/// entries — the file is still read line by line (≤ the rotation cap),
/// but no longer held in memory whole with every raw line.
fn collect_matching_from_file(
    path: &Path,
    filter: &DetectionFilter,
    cap: usize,
    keep_lines: bool,
) -> Vec<(DetectionRecord, String)> {
    use std::collections::BinaryHeap;
    use std::io::{BufRead, BufReader};
    if cap == 0 {
        return Vec::new();
    }
    let f = match std::fs::OpenOptions::new().read(true).open(path) {
        Ok(f) => f,
        Err(_) => return Vec::new(),
    };
    // Min-heap on the rank: the root is the first to give way.
    let mut held: BinaryHeap<std::cmp::Reverse<Held>> = BinaryHeap::new();
    for (line_no, line) in BufReader::new(f).lines().enumerate() {
        let Ok(line) = line else { continue };
        if line.trim().is_empty() {
            continue;
        }
        let Ok(record) = serde_json::from_str::<DetectionRecord>(&line) else {
            continue;
        };
        if !record.matches(filter) {
            continue;
        }
        let entry = Held {
            id: record.id,
            line_no,
            record,
            line: if keep_lines { line } else { String::new() },
        };
        if held.len() < cap {
            held.push(std::cmp::Reverse(entry));
        } else if held.peek().is_some_and(|least| entry > least.0) {
            held.pop();
            held.push(std::cmp::Reverse(entry));
        }
        #[cfg(test)]
        HELD_HIGH_WATER.with(|h| h.set(h.get().max(held.len())));
    }
    // Ascending in `Reverse` = descending in rank: served first, first.
    held.into_sorted_vec()
        .into_iter()
        .map(|std::cmp::Reverse(h)| (h.record, h.line))
        .collect()
}

// ── Tappa 9.0.c — status-event chain: open + max-id guard + overlay ──

/// Open (or initialise) the [`StatusEvent`] chainlog at `active_path`.
/// Thin wrapper over [`RotatingChainLog::open`] specialised to
/// `StatusEvent` so callers (main.rs boot, the admin set-status
/// dispatch) don't repeat the turbofish. Unlike [`open`] there is no id
/// counter to seed — a status event references an existing detection id
/// rather than minting its own. The active file should already exist
/// (bootstrapped pre-attach, like `detections.jsonl`) so its inode is
/// registered with the anti-tamper LSM map before lockdown.
pub fn open_status_log(
    active_path: &Path,
    key: AgentSigningKey,
    cfg: RotationConfig,
    protection: Arc<dyn ProtectionManager>,
) -> Result<RotatingChainLog<StatusEvent>> {
    let log = RotatingChainLog::<StatusEvent>::open(active_path, key, cfg, protection)
        .with_context(|| format!("opening status-event chainlog {}", active_path.display()))?;
    info!(
        target: "detection_store",
        path = %active_path.display(),
        "status-event store opened",
    );
    Ok(log)
}

/// Highest detection `id` currently persisted in the detection chain at
/// `detections_path` (`0` when the store is empty). The cheap validity
/// guard for `DetectionSetStatus`: an id in `1..=max_detection_id` is
/// accepted, anything outside is a clean "detection not found". Reuses
/// the same bounded boot-read [`open`] uses to seed its id counter — no
/// unbounded whole-store scan (BUG-026 discipline). NOTE: a gap id
/// (a record dropped under backpressure) below the max still passes;
/// the full existence scan is deliberately deferred (id ≤ max suffices).
pub fn max_detection_id(detections_path: &Path) -> u64 {
    seed_last_id(detections_path)
}

/// Read the last `limit` detections (newest-first) from the detection
/// chain at `detections_path`, with each record's triage status
/// OVERLAID from the status-event chain at `status_events_path` — i.e.
/// the CURRENT (event-sourced) status rather than the record's frozen
/// initial `Open`. This is the read path the Tappa 9.0.c admin
/// `Detections` verb serves; `detections.jsonl` is never mutated, so a
/// record's own line still reads `Open` after triage (the chain is
/// history, the status is derived).
///
/// Filter semantics: every filter EXCEPT `status` constrains immutable
/// record fields and is applied during the bounded base read. The
/// `status` filter, when present, is applied against the OVERLAID
/// (current) status — that is what an operator means by
/// `--status resolved` (the on-disk record still says `Open`; status
/// lives in the event chain). So the status filter is split off, the
/// candidates are overlaid, then retained on current status. To let
/// that post-overlay retain still fill up to `limit` rows, the
/// candidate scan widens to the hard ceiling [`MAX_DETECTIONS_LIMIT`]
/// when a status filter is set; the read stays bounded by the retention
/// window either way.
pub fn read_last_n_overlaid(
    detections_path: &Path,
    status_events_path: &Path,
    limit: usize,
    filter: &DetectionFilter,
) -> Vec<DetectionRecord> {
    read_last_n_overlaid_verified(detections_path, status_events_path, limit, filter, None).0
}

/// [`read_last_n_overlaid`] over [`read_last_n_verified`]: with `pubkey`,
/// detection rows that do not verify are left out and counted.
pub fn read_last_n_overlaid_verified(
    detections_path: &Path,
    status_events_path: &Path,
    limit: usize,
    filter: &DetectionFilter,
    pubkey: Option<&ed25519_dalek::VerifyingKey>,
) -> (Vec<DetectionRecord>, usize) {
    let mut base_filter = filter.clone();
    let status_target = base_filter.status.take();

    // Common case (no status filter): read exactly `limit` candidates.
    // With a status filter we can't know up front how many survive the
    // post-overlay retain, so widen the candidate scan to the ceiling.
    let scan_limit = if status_target.is_some() {
        limit.max(MAX_DETECTIONS_LIMIT)
    } else {
        limit
    };
    let (mut records, unverified) =
        read_last_n_verified(detections_path, scan_limit, &base_filter, pubkey);

    // Overlay current status for just the window's ids (bounded).
    let ids: HashSet<u64> = records.iter().map(|r| r.id).collect();
    let status_map = latest_status_for_ids(status_events_path, &ids);
    for record in &mut records {
        if let Some(&status) = status_map.get(&record.id) {
            record.status = status;
        }
    }

    // Post-overlay status filter: match the CURRENT status.
    if let Some(target) = status_target {
        records.retain(|r| r.status == target);
    }
    records.truncate(limit);
    (records, unverified)
}

/// Build a `{detection_id -> current status}` map for exactly the ids
/// in `wanted`, reading the status-event chain at `status_events_path`.
/// Bounded (BUG-026 discipline): the size-capped active file is read
/// first; sealed archives are descended newest-first ONLY while some
/// requested id is still unresolved. The active file holds the newest
/// events, so its latest event for an id wins over any archive's; an id
/// with no event anywhere is simply absent from the map (the caller
/// keeps the record's own status). Empty map for an empty `wanted`.
pub fn latest_status_for_ids(
    status_events_path: &Path,
    wanted: &HashSet<u64>,
) -> HashMap<u64, DetectionStatus> {
    let mut out: HashMap<u64, DetectionStatus> = HashMap::new();
    if wanted.is_empty() {
        return out;
    }
    let mut unresolved: HashSet<u64> = wanted.clone();
    collect_latest_status_from_file(status_events_path, &mut out, &mut unresolved);
    if !unresolved.is_empty() {
        for archive in crate::chainlog::archives_newest_first(status_events_path) {
            collect_latest_status_from_file(&archive, &mut out, &mut unresolved);
            if unresolved.is_empty() {
                break;
            }
        }
    }
    out
}

/// Scan one status-event file (active or archive) for the still-
/// unresolved ids, recording each id's LATEST event (last matching line
/// wins within the file, since events are appended oldest-first). Ids
/// recorded here are removed from `unresolved` AFTER the whole file is
/// read, so a newer file always shadows an older one for the same id.
/// Best-effort: a missing/unreadable file contributes nothing; lines
/// that don't parse as a [`StatusEvent`] (terminators, blanks, the
/// detection records in a different file) are skipped. Bounded read
/// (the file is ≤ the rotation cap).
fn collect_latest_status_from_file(
    path: &Path,
    out: &mut HashMap<u64, DetectionStatus>,
    unresolved: &mut HashSet<u64>,
) {
    use std::io::{BufRead, BufReader};
    let f = match std::fs::OpenOptions::new().read(true).open(path) {
        Ok(f) => f,
        Err(_) => return,
    };
    let mut touched: Vec<u64> = Vec::new();
    for line in BufReader::new(f).lines() {
        let Ok(line) = line else { continue };
        if line.trim().is_empty() {
            continue;
        }
        if let Ok(ev) = serde_json::from_str::<StatusEvent>(&line) {
            if unresolved.contains(&ev.detection_id) {
                out.insert(ev.detection_id, ev.new_status);
                touched.push(ev.detection_id);
            }
        }
    }
    for id in touched {
        unresolved.remove(&id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chainlog::{verify_log_set, NoProtection};

    fn test_key() -> AgentSigningKey {
        let dir = tempfile::tempdir().unwrap();
        AgentSigningKey::load_or_bootstrap(&dir.path().join("agent.sig.key")).unwrap()
    }

    fn sample_event() -> Event {
        Event::ProcessSpawn {
            pid: 4242,
            ppid: 1,
            uid: 0,
            gid: 0,
            comm: "evil".to_string(),
            filename: "/tmp/payload".to_string(),
            timestamp_ns: 123,
            argv: Vec::new(),
            parent_comm: String::new(),
            parent_start_ns: 0,
            start_ns: 0,
            parent_is_kthread: false,
            exe: Default::default(),
            argv_truncated: false,
            filename_truncated: false,
            stdio: Default::default(),
        }
    }

    fn sample_verdict() -> Verdict {
        Verdict {
            rule_id: "R001_ExecFromTmp".to_string(),
            rule_name: "Exec from /tmp/".to_string(),
            category: "execution".to_string(),
            action: ResponseAction::KillProcess,
            severity: Severity::Medium,
            reasoning: "binary executed from world-writable /tmp".to_string(),
            event_pid: 4242,
            event_filename: "/tmp/payload".to_string(),
            timestamp_ns: 123,
        }
    }

    /// A round-trip is "stable" iff re-serialising the decoded value
    /// yields byte-identical JSON. (We compare JSON rather than deriving
    /// `PartialEq`: the chain verifiers compare bytes too.)
    fn assert_roundtrip(record: &DetectionRecord) {
        let json = serde_json::to_string(record).expect("serialize");
        let decoded: DetectionRecord = serde_json::from_str(&json).expect("deserialize");
        let reencoded = serde_json::to_string(&decoded).expect("re-serialize");
        assert_eq!(json, reencoded, "detection record did not round-trip");
    }

    #[test]
    fn rule_record_roundtrips() {
        let record = DetectionRecord::from_rule(
            7,
            "2026-06-08T12:00:00.000000Z".to_string(),
            &sample_event(),
            &sample_verdict(),
            PostureKind::Engaged,
            "KillProcess".to_string(),
        );
        assert_roundtrip(&record);
    }

    /// Wave 4 (lab PR 214): a record of the removed LLM advisor, written
    /// by an older agent, still decodes and re-serialises byte for byte
    /// (the chain verifiers hash the re-serialised record).
    #[test]
    fn pre_wave4_advisor_record_roundtrips() {
        let record = DetectionRecord {
            id: 9,
            ts: "2026-06-08T12:00:01.000000Z".to_string(),
            sensor: Sensor::Exec,
            path: DetectionPath::Ade,
            rule_id: None,
            rule_name: None,
            severity: Severity::High,
            verdict: DetectionVerdict::Ade(AdvisorAction::Kill),
            confidence: 0.91,
            mitre: MitreAttack {
                tactic: vec!["TA0002".to_string()],
                technique: vec!["T1059".to_string()],
            },
            principal: Principal::from_event(&sample_event()),
            exe: Some("/tmp/payload".to_string()),
            posture_at: PostureKind::Alerted,
            response: "suppressed (detect-only)".to_string(),
            detection_type: "reverse_shell".to_string(),
            status: DetectionStatus::Open,
            suppressed_before: None,
            file: None,
            operation: None,
            mitre_version: None,
            execq: None,
            network: None,
            sanction: None,
            execpol: None,
            matches: None,
        };
        assert_roundtrip(&record);
    }

    /// Wave 4 (lab PR 214): the line an agent with the advisor wrote for
    /// an advisory verdict (`common::ade_types::{AdeAction, MitreAttack}`
    /// then) decodes into the kept shapes and re-encodes to the same bytes.
    #[test]
    fn pre_wave4_advisor_line_decodes_to_the_same_bytes() {
        let line = r#"{"id":12,"ts":"2026-10-01T08:00:00.000001Z","sensor":"Exec","path":"Ade","severity":"Medium","verdict":{"Ade":"Escalate"},"confidence":0.35,"mitre":{"tactic":["TA0002"],"technique":[]},"principal":{"pid":4242,"comm":"evil","uid":1000,"ppid":1},"exe":"/tmp/payload","posture_at":"Observing","response":"none","detection_type":"process","status":"Open"}"#;
        let decoded: DetectionRecord = serde_json::from_str(line).expect("an advisor record");
        assert_eq!(decoded.path, DetectionPath::Ade);
        assert!(matches!(
            decoded.verdict,
            DetectionVerdict::Ade(AdvisorAction::Escalate)
        ));
        assert!(!decoded.acted(), "an advisory record ran nothing");
        assert_eq!(serde_json::to_string(&decoded).unwrap(), line);
        // Every recommendation the advisor could write still decodes.
        for a in [
            "Allow",
            "Monitor",
            "Alert",
            "Throttle",
            "Kill",
            "KillTree",
            "Quarantine",
            "BlockNetwork",
            "Isolate",
            "Escalate",
        ] {
            let v: AdvisorAction = serde_json::from_str(&format!("\"{a}\"")).unwrap();
            assert_eq!(serde_json::to_string(&v).unwrap(), format!("\"{a}\""));
        }
    }

    /// Lab PR 223: an exec quarantine record carries its evidence and its
    /// ATT&CK mapping and round-trips; every other record serialises
    /// without the field (old lines stay byte-identical).
    #[test]
    fn execq_record_roundtrips_and_others_omit_the_field() {
        let sink = DetectionSink::for_test(8, 0);
        let event = sample_event();
        let verdict = Verdict {
            rule_id: crate::execq::RULE_ID.to_string(),
            rule_name: crate::execq::RULE_NAME.to_string(),
            category: crate::execq::CATEGORY.to_string(),
            action: ResponseAction::Quarantine,
            severity: Severity::Critical,
            reasoning: "first sight".to_string(),
            event_pid: 1,
            event_filename: "/tmp/payload".to_string(),
            timestamp_ns: 0,
        };
        let evidence = ExecqEvidence {
            verdict: "malicious".into(),
            sha256: Some("ab".repeat(32)),
            format: Some("elf64-x86_64-exec".into()),
            reasons: vec!["blocklist: nn-lab-test-elf".into()],
            decision: "kill".into(),
            basis: "block-listed content".into(),
            classes: vec!["tmp".into()],
            held: true,
            held_ms: 3,
        };
        sink.record_execq(
            &event,
            &verdict,
            PostureKind::Observing,
            "killed while held; quarantined (vault x)".into(),
            &crate::execq::attack_refs("elf64-x86_64-exec"),
            evidence.clone(),
            0,
        );
        let record = sink.inner.queue.lock().pop_front().unwrap();
        assert_eq!(record.execq.as_ref(), Some(&evidence));
        assert_eq!(record.mitre.technique, ["T1204.002"]);
        assert_eq!(record.mitre.tactic, ["TA0002"]);
        assert_eq!(record.mitre_version.as_deref(), Some("20.0"));
        assert_roundtrip(&record);
        let plain = DetectionRecord::from_rule(
            2,
            "t".into(),
            &event,
            &verdict,
            PostureKind::Observing,
            "none".into(),
        );
        assert!(!serde_json::to_string(&plain).unwrap().contains("execq"));
    }

    #[test]
    fn status_initializes_open() {
        let record = DetectionRecord::from_rule(
            1,
            now_ts(),
            &sample_event(),
            &sample_verdict(),
            PostureKind::Observing,
            "none".to_string(),
        );
        assert_eq!(record.status, DetectionStatus::Open);
    }

    #[test]
    fn principal_carries_ppid_for_process_events_only() {
        let p = Principal::from_event(&sample_event());
        assert_eq!(p.pid, 4242);
        assert_eq!(p.comm, "evil");
        assert_eq!(p.ppid, Some(1));
    }

    // ── Tappa 9.0.a.1 — exec path on the record ──────────────────────

    /// An `ExecCheck` (pre-exec `bprm_check_security`) event — the second
    /// exec sensor; its `filename` must reach `exe` just like `ProcessSpawn`.
    fn sample_exec_check() -> Event {
        Event::ExecCheck {
            pid: 5151,
            ppid: 1,
            uid: 0,
            comm: "nn-test-mock-re".to_string(),
            filename: "/tmp/staging/dropper".to_string(),
            timestamp_ns: 456,
            exe: Default::default(),
        }
    }

    /// A `FileOpen` event — a NON-exec (file) sensor that DOES carry a
    /// `filename` (the OPENED file, not an executable). The adversarial
    /// case for `exe`: a `filename` that must NOT leak into `exe`.
    fn sample_file_open() -> Event {
        Event::FileOpen {
            pid: 77,
            uid: 0,
            gid: 0,
            comm: "cat".to_string(),
            filename: "/etc/shadow".to_string(),
            flags: 0,
            timestamp_ns: 789,
            path_from_user: false,
            kernel_class: 0,
        }
    }

    /// Review 77: a file detection names its file; an exec detection
    /// does not carry the field at all (pre-field byte shape).
    #[test]
    fn file_detection_records_its_file() {
        let r = DetectionRecord::from_rule(
            1,
            now_ts(),
            &sample_file_open(),
            &sample_verdict(),
            PostureKind::Observing,
            "none".to_string(),
        );
        assert_eq!(r.file.as_deref(), Some("/etc/shadow"));
        let drift = Event::Fim(nn_model::telemetry::FimEvent {
            timestamp_ns: 1,
            path: "/etc/cron.d/backdoor".to_string(),
            op: nn_model::telemetry::FimOp::Created,
            new_sha256: None,
            baseline_sha256: None,
            new_size: None,
            baseline_size: None,
            modifier_exe: None,
            modifier_pid: 4242,
            modifier_uid: 0,
            modifier_comm: "sh".to_string(),
            dest_path: None,
            child_truncated: false,
            wide_coverage: false,
            owner_uid: None,
            reader_dac_capable: false,
            capability: None,
            attrs: None,
            file_key: None,
            is_dir: false,
            moved_in: false,
        });
        let r = DetectionRecord::from_rule(
            2,
            now_ts(),
            &drift,
            &sample_verdict(),
            PostureKind::Observing,
            "KillProcess".to_string(),
        );
        assert_eq!(r.file.as_deref(), Some("/etc/cron.d/backdoor"));
        let r = DetectionRecord::from_rule(
            3,
            now_ts(),
            &sample_event(),
            &sample_verdict(),
            PostureKind::Observing,
            "KillProcess".to_string(),
        );
        assert_eq!(r.file, None);
        assert!(!serde_json::to_string(&r).unwrap().contains("\"file\""));
    }

    #[test]
    fn exec_detection_records_exe_path() {
        // R001 "Exec from /tmp": the rule fires on comm="evil", but the
        // path that actually triggered it is /tmp/payload — `exe` must
        // carry it (the 9.0.a.1 fix), on BOTH exec sensors.
        let spawn = DetectionRecord::from_rule(
            1,
            now_ts(),
            &sample_event(),
            &sample_verdict(),
            PostureKind::Engaged,
            "KillProcess".to_string(),
        );
        assert_eq!(spawn.exe.as_deref(), Some("/tmp/payload"));
        // ExecCheck (pre-exec) carries its filename into exe too.
        assert_eq!(
            exe_from_event(&sample_exec_check()).as_deref(),
            Some("/tmp/staging/dropper"),
        );
    }

    #[test]
    fn non_exec_detection_records_no_exe() {
        // A FileOpen has a `filename` (the OPENED file) but names no
        // executable — exe must be None, not the opened path. Proves exe
        // is exec-only, not "any filename".
        let file = DetectionRecord::from_rule(
            2,
            now_ts(),
            &sample_file_open(),
            &sample_verdict(),
            PostureKind::Observing,
            "none".to_string(),
        );
        assert_eq!(file.sensor, Sensor::File);
        assert_eq!(
            file.exe, None,
            "FileOpen.filename is the opened file, not an exe"
        );
        assert_eq!(file.principal.comm, "cat");
    }

    fn flow_event(phase: nn_model::telemetry::FlowPhase, proto: u8) -> Event {
        Event::NetFlow(nn_model::telemetry::NetFlowEvent {
            start_ns: 10_000_000_000,
            end_ns: 0,
            family: 2,
            src_addr: "0.0.0.0".parse().unwrap(),
            src_port: 0,
            dst_addr: "127.0.0.1".parse().unwrap(),
            dst_port: 4444,
            proto,
            pid: 4100,
            uid: 1000,
            comm: "python3".into(),
            exe: Some("/usr/bin/python3.12".into()),
            proc_start_ns: 0,
            bytes_sent: 0,
            bytes_recv: 0,
            resolved_hostname: None,
            tls_fingerprint: None,
            flow_id: String::new(),
            close_reason: 0,
            phase,
            observed_ns: 75_000_000_000,
        })
    }

    /// Lab PR 224: a network detection says in the signed record where the
    /// flow went and in which phase it was judged — the lab reads a
    /// connect-time verdict from it — and a connect the kernel refused is
    /// the refused operation `connect`. The starting tree's records named
    /// neither.
    #[test]
    fn network_detections_record_the_flow_and_its_phase() {
        use nn_model::telemetry::FlowPhase;
        let rec = |e: &Event| {
            DetectionRecord::from_rule(
                1,
                now_ts(),
                e,
                &sample_verdict(),
                PostureKind::Observing,
                "none".to_string(),
            )
        };
        let r = rec(&flow_event(FlowPhase::Connect, 6));
        assert_eq!(r.network.as_deref(), Some("tcp 127.0.0.1:4444 connect"));
        assert_eq!(r.operation, None);
        assert_eq!(
            rec(&flow_event(FlowPhase::Snapshot, 6)).network.as_deref(),
            Some("tcp 127.0.0.1:4444 snapshot open=65s")
        );
        assert_eq!(
            rec(&flow_event(FlowPhase::Closed, 17)).network.as_deref(),
            Some("udp 127.0.0.1:4444 closed")
        );
        let denied = rec(&flow_event(FlowPhase::Denied, 6));
        assert_eq!(denied.network.as_deref(), Some("tcp 127.0.0.1:4444 denied"));
        assert_eq!(denied.operation.as_deref(), Some("connect"));
        // An exec whose stdio is a connected socket (R020's evidence).
        let mut spawn = sample_event();
        if let Event::ProcessSpawn { stdio, .. } = &mut spawn {
            stdio.own = nn_model::StdioSocket {
                read: true,
                inet_fds: 0b111,
                outbound: true,
                proto: 6,
                peer: Some("127.0.0.1:44401".parse().unwrap()),
            };
        }
        assert_eq!(
            rec(&spawn).network.as_deref(),
            Some("stdio tcp 127.0.0.1:44401 outbound")
        );
        // Nothing for an exec on a terminal; the field is absent on disk.
        let plain = rec(&sample_event());
        assert_eq!(plain.network, None);
        assert!(!serde_json::to_string(&plain).unwrap().contains("network"));
        assert_roundtrip(&denied);
    }

    #[test]
    fn record_without_exe_field_deserializes_to_none() {
        // Simulate a 9.0.a/b/c-era on-disk line: serialise a record, then
        // STRIP the `exe` key (those binaries had no such field). It must
        // deserialise back with exe = None (serde default).
        let rec = DetectionRecord::from_rule(
            1,
            "2026-06-08T12:00:00.000000Z".to_string(),
            &sample_event(),
            &sample_verdict(),
            PostureKind::Engaged,
            "KillProcess".to_string(),
        );
        let mut v = serde_json::to_value(&rec).unwrap();
        v.as_object_mut().unwrap().remove("exe");
        let line = serde_json::to_string(&v).unwrap();
        assert!(
            !line.contains("\"exe\""),
            "pre-9.0.a.1 line carries no exe key"
        );
        let decoded: DetectionRecord = serde_json::from_str(&line).unwrap();
        assert_eq!(decoded.exe, None, "absent exe deserialises to None");
    }

    /// Lab PR 221: a rule-path line written before the ATT&CK mapping
    /// (empty `mitre`, no `mitre_version`), byte for byte as such an agent
    /// wrote it, decodes and re-serialises to the same bytes — the
    /// pre-image the chain verifier recomputes.
    #[test]
    fn a_rule_line_written_before_the_attack_mapping_keeps_its_bytes() {
        const LEGACY: &str = concat!(
            r#"{"id":7,"ts":"2026-06-08T12:00:00.000000Z","sensor":"Exec","path":"Rule","#,
            r#""rule_id":"R001_ExecFromTmp","rule_name":"Exec from /tmp/","severity":"Medium","#,
            r#""verdict":{"Rule":"KillProcess"},"confidence":1.0,"mitre":{"tactic":[],"technique":[]},"#,
            r#""principal":{"pid":4242,"comm":"evil","uid":0,"ppid":1},"exe":"/tmp/payload","#,
            r#""posture_at":"Engaged","response":"KillProcess","detection_type":"execution","#,
            r#""status":"Open"}"#,
        );
        let decoded: DetectionRecord = serde_json::from_str(LEGACY).expect("legacy line decodes");
        assert_eq!(decoded.mitre_version, None);
        assert!(decoded.mitre.tactic.is_empty() && decoded.mitre.technique.is_empty());
        assert_eq!(serde_json::to_string(&decoded).unwrap(), LEGACY);
        // A record built today without references has that shape too.
        let today = DetectionRecord::from_rule(
            7,
            "2026-06-08T12:00:00.000000Z".to_string(),
            &sample_event(),
            &sample_verdict(),
            PostureKind::Engaged,
            "KillProcess".to_string(),
        )
        .with_attack(&[]);
        assert_eq!(serde_json::to_string(&today).unwrap(), LEGACY);
    }

    /// Lab PR 221: the rule's references fill `mitre` (tactic ids, then
    /// technique ids, each once) and `mitre_version`, and the record
    /// round-trips.
    #[test]
    fn a_rule_record_carries_its_rules_attack_ids_and_version() {
        use crate::decision::attack::Tactic;
        const REFS: &[AttackRef] = &[
            AttackRef::new(Tactic::Persistence, "T1053.003"),
            AttackRef::new(Tactic::PrivilegeEscalation, "T1053.003"),
            AttackRef::new(Tactic::Execution, "T1059.004"),
        ];
        let record = DetectionRecord::from_rule(
            7,
            "2026-06-08T12:00:00.000000Z".to_string(),
            &sample_event(),
            &sample_verdict(),
            PostureKind::Engaged,
            "KillProcess".to_string(),
        )
        .with_attack(REFS);
        assert_eq!(record.mitre.tactic, ["TA0003", "TA0004", "TA0002"]);
        assert_eq!(record.mitre.technique, ["T1053.003", "T1059.004"]);
        assert_eq!(record.mitre_version.as_deref(), Some(ATTACK_VERSION));
        let json = serde_json::to_string(&record).unwrap();
        assert!(json.contains(
            r#""mitre":{"tactic":["TA0003","TA0004","TA0002"],"technique":["T1053.003","T1059.004"]}"#
        ));
        assert!(json.ends_with(r#","mitre_version":"20.0"}"#), "{json}");
        assert_roundtrip(&record);
    }

    /// Lab PR 221: through the real signed chain, a record with the
    /// rule's ATT&CK ids and one without (the pre-221 shape) verify
    /// together.
    #[tokio::test]
    async fn chain_verifies_with_attack_ids_and_without() {
        use crate::decision::attack::Tactic;
        const REFS: &[AttackRef] = &[AttackRef::new(Tactic::Execution, "T1059")];
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("detections.jsonl");
        let key = test_key();
        let pubkey = key.verifying_key();
        let (sink, _writer) = open(
            &path,
            key,
            RotationConfig::default(),
            Arc::new(NoProtection),
            DEFAULT_QUEUE_CAP,
        )
        .expect("open detection store");
        for refs in [REFS, &[]] {
            sink.record_rule(
                &sample_event(),
                &sample_verdict(),
                refs,
                PostureKind::Observing,
                "KillProcess".to_string(),
                0,
            );
        }
        let mut flushed = 0usize;
        for _ in 0..200 {
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            flushed = count_data_lines(&path);
            if flushed >= 2 {
                break;
            }
        }
        assert_eq!(flushed, 2, "writer appended both records");
        let report =
            verify_log_set::<DetectionRecord>(&path, &pubkey).expect("detection chain verifies");
        assert_eq!(report.total_records, 2);
        let body = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = body.lines().filter(|l| !l.trim().is_empty()).collect();
        assert!(lines[0].contains(r#""mitre":{"tactic":["TA0002"],"technique":["T1059"]}"#));
        assert!(lines[0].contains(r#""mitre_version":"20.0""#));
        assert!(lines[1].contains(r#""mitre":{"tactic":[],"technique":[]}"#));
        assert!(!lines[1].contains("mitre_version"));
    }

    #[tokio::test]
    async fn chain_verifies_across_exe_present_and_absent() {
        // The load-bearing safety test for 9.0.a.1 (recon Q2). Write two
        // detections through the REAL signed chain: one exec (exe = Some)
        // and one FileOpen (exe = None). Then:
        //  * verify_log_set must pass (hashes + sigs + linkage) — adding
        //    the field did not break chaining;
        //  * the exe=None line carries NO `exe` key, making it byte-
        //    identical to a record written by 9.0.a/b/c (no exe field). So
        //    that line IS a faithful pre-field record, and its passing
        //    verification proves OLD lines still verify under the new
        //    schema: the verifier re-serialises the decoded struct, but a
        //    skipped `None` reproduces the original pre-image byte-for-byte,
        //    so the recomputed entry_hash matches the stored one;
        //  * the envelope quartet (fmt_ver/prev_hash/entry_hash/agent_sig)
        //    is unchanged on every line.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("detections.jsonl");
        let key = test_key();
        let pubkey = key.verifying_key();
        let (sink, _writer) = open(
            &path,
            key,
            RotationConfig::default(),
            Arc::new(NoProtection),
            DEFAULT_QUEUE_CAP,
        )
        .expect("open detection store");

        sink.record_rule(
            &sample_event(),
            &sample_verdict(),
            &[],
            PostureKind::Observing,
            "KillProcess".to_string(),
            0,
        );
        sink.record_rule(
            &sample_file_open(),
            &sample_verdict(),
            &[],
            PostureKind::Observing,
            "none".to_string(),
            0,
        );

        // Poll until the writer task has flushed both (bounded wait).
        let mut flushed = 0usize;
        for _ in 0..200 {
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            flushed = count_data_lines(&path);
            if flushed >= 2 {
                break;
            }
        }
        assert_eq!(flushed, 2, "writer appended both records");

        // Chain verifies end-to-end (the decisive recon-Q2 check).
        let report = verify_log_set::<DetectionRecord>(&path, &pubkey)
            .expect("detection chain verifies with mixed exe-present/absent records");
        assert_eq!(report.total_records, 2);

        // Inspect the on-disk lines: envelope shape + exe presence/absence.
        let body = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = body.lines().filter(|l| !l.trim().is_empty()).collect();
        assert_eq!(lines.len(), 2);
        for l in &lines {
            let v: serde_json::Value = serde_json::from_str(l).unwrap();
            assert!(v.get("fmt_ver").is_some(), "envelope fmt_ver present");
            assert!(v.get("prev_hash").is_some(), "envelope prev_hash present");
            assert!(v.get("entry_hash").is_some(), "envelope entry_hash present");
            assert!(v.get("agent_sig").is_some(), "envelope agent_sig present");
        }
        let with_exe = lines
            .iter()
            .filter(|l| l.contains("\"exe\":\"/tmp/payload\""))
            .count();
        let without_exe = lines.iter().filter(|l| !l.contains("\"exe\"")).count();
        assert_eq!(with_exe, 1, "exec detection carries its exe path");
        assert_eq!(
            without_exe, 1,
            "non-exec detection omits exe — the pre-9.0.a.1 byte shape",
        );
    }

    #[test]
    fn enqueue_drops_oldest_when_full() {
        // cap = 2, no writer draining: pushing 3 records must drop the
        // OLDEST (id 1) and keep the two freshest (ids 2, 3).
        let sink = DetectionSink::for_test(2, 0);
        for _ in 0..3 {
            sink.record_rule(
                &sample_event(),
                &sample_verdict(),
                &[],
                PostureKind::Observing,
                "none".to_string(),
                0,
            );
        }
        assert_eq!(sink.queue_snapshot(), vec![2, 3], "freshest two retained");
        assert_eq!(sink.dropped(), 1, "exactly one (oldest) dropped");
    }

    /// Review 75: a flood of logged verdicts must not evict the record of
    /// a kill. A full queue drops the oldest logged record first, and a
    /// logged record that finds only kills queued is the one dropped.
    #[test]
    fn full_queue_evicts_logged_records_before_kills() {
        let sink = DetectionSink::for_test(3, 0);
        let mut logged = sample_verdict();
        logged.action = ResponseAction::Log;
        let kill = sample_verdict();
        let push = |v: &Verdict, response: &str| {
            sink.record_rule(
                &sample_event(),
                v,
                &[],
                PostureKind::Observing,
                response.to_string(),
                0,
            )
        };
        push(&kill, "KillProcess"); // 1
        push(&logged, "none"); // 2
        push(&kill, "KillProcess"); // 3
        push(&logged, "none"); // 4: evicts 2, the oldest logged one
        assert_eq!(sink.queue_snapshot(), vec![1, 3, 4]);
        push(&kill, "KillProcess"); // 5: evicts 4, the only logged one
        assert_eq!(sink.queue_snapshot(), vec![1, 3, 5]);
        push(&logged, "none"); // 6: only kills queued → 6 is dropped
        assert_eq!(sink.queue_snapshot(), vec![1, 3, 5]);
        push(&kill, "KillProcess"); // 7: only kills → the oldest goes
        assert_eq!(sink.queue_snapshot(), vec![3, 5, 7]);
        assert_eq!(sink.dropped(), 4);
    }

    /// External audit NN-AUD-111: among logged-only records a full queue
    /// evicts the lowest severity first (oldest first within it), and a
    /// logged record below everything queued is dropped itself. Before the
    /// fix the oldest logged record went whatever its severity (here the
    /// High one, id 1).
    #[test]
    fn full_queue_evicts_lowest_severity_logged_record_first() {
        let sink = DetectionSink::for_test(3, 0);
        let logged = |sev: Severity| {
            let mut v = sample_verdict();
            v.action = ResponseAction::Log;
            v.severity = sev;
            v
        };
        let push = |v: &Verdict| {
            sink.record_rule(
                &sample_event(),
                v,
                &[],
                PostureKind::Observing,
                "none".to_string(),
                0,
            )
        };
        push(&logged(Severity::High)); // 1
        push(&logged(Severity::Low)); // 2
        push(&logged(Severity::Low)); // 3
        push(&logged(Severity::Medium)); // 4: evicts 2 (Low, oldest)
        assert_eq!(sink.queue_snapshot(), vec![1, 3, 4]);
        push(&logged(Severity::Low)); // 5: evicts 3 (Low, same rank: freshest wins)
        assert_eq!(sink.queue_snapshot(), vec![1, 4, 5]);
        push(&logged(Severity::Critical)); // 6: evicts 5 (Low)
        assert_eq!(sink.queue_snapshot(), vec![1, 4, 6]);
        push(&logged(Severity::Low)); // 7: below everything queued: dropped
        assert_eq!(sink.queue_snapshot(), vec![1, 4, 6]);
        push(&sample_verdict()); // 8: a kill evicts the lowest logged (4, Medium)
        assert_eq!(sink.queue_snapshot(), vec![1, 6, 8]);
        assert_eq!(sink.dropped(), 5);
        let d = sink.take_drops().expect("drops noted");
        assert_eq!(d.count, 5);
        assert_eq!((d.first_id, d.last_id), (2, 4));
        assert_eq!((d.lowest_id, d.highest_id), (2, 7));
        assert_eq!(d.by_severity, [4, 1, 0, 0]);
        assert_eq!(d.acted, 0);
    }

    /// External audit NN-AUD-111: queue drops reach the signed audit chain,
    /// one entry per report window that saw drops and none otherwise.
    /// Before the fix a drop was only a WARN and a counter.
    #[test]
    fn queue_drops_are_attested_once_per_window() {
        let dir = tempfile::tempdir().unwrap();
        let key = AgentSigningKey::load_or_bootstrap(&dir.path().join("agent.key")).unwrap();
        let path = dir.path().join("audit.log");
        let log = Mutex::new(crate::audit::AuditLog::open(&path, key, [0u8; 16]).unwrap());
        let entries = || -> Vec<serde_json::Value> {
            std::fs::read_to_string(&path)
                .unwrap_or_default()
                .lines()
                .map(|l| serde_json::from_str(l).unwrap())
                .collect()
        };
        let sink = DetectionSink::for_test(2, 0);
        let push = || {
            sink.record_rule(
                &sample_event(),
                &sample_verdict(),
                &[],
                PostureKind::Observing,
                "KillProcess".to_string(),
                0,
            )
        };
        sink.report_drops(Some(&log));
        assert!(entries().is_empty(), "no drops, no entry");
        for _ in 0..5 {
            push();
        }
        sink.report_drops(Some(&log));
        sink.report_drops(Some(&log));
        let e = entries();
        assert_eq!(e.len(), 1, "one entry for the window");
        assert_eq!(e[0]["op"], DROPPED_AUDIT_OP);
        assert_eq!(e[0]["extra"]["count"], 3);
        assert_eq!(e[0]["extra"]["first_id"], 1);
        assert_eq!(e[0]["extra"]["last_id"], 3);
        assert_eq!(e[0]["extra"]["severities"]["medium"], 3);
        assert_eq!(e[0]["extra"]["acted"], 3);
        push();
        sink.report_drops(Some(&log));
        let e = entries();
        assert_eq!(e.len(), 2, "a new window with drops, a new entry");
        assert_eq!(e[1]["extra"]["count"], 1);
        assert_eq!(e[1]["extra"]["first_id"], 4);
        assert_eq!(e[1]["extra"]["dropped_total"], 4);
    }

    /// An anti-tamper denial is a Log verdict, but the kernel acted: it
    /// is kept like a kill.
    #[test]
    fn anti_tamper_denial_counts_as_acted() {
        let mut logged = sample_verdict();
        logged.action = ResponseAction::Log;
        let denial = Event::FsProtectDenial {
            timestamp_ns: 1,
            pid: 4242,
            uid: 0,
            comm: "rm".to_string(),
            target_dev: 1,
            target_ino: 2,
            operation: nn_model::FsProtectOperation::Unlink,
        };
        let r = DetectionRecord::from_rule(
            1,
            now_ts(),
            &denial,
            &logged,
            PostureKind::Observing,
            "denied in kernel (anti-tamper LSM hook)".to_string(),
        );
        assert!(r.acted());
        // NN-AUD-413: the signed record names what was refused.
        assert_eq!(r.operation.as_deref(), Some("unlink"));
        let json = serde_json::to_string(&r).unwrap();
        assert!(json.contains(r#""operation":"unlink""#), "{json}");
        // the chain verifier re-serialises the decoded record
        assert_roundtrip(&r);
        let r = DetectionRecord::from_rule(
            2,
            now_ts(),
            &sample_event(),
            &logged,
            PostureKind::Observing,
            "none".to_string(),
        );
        assert!(!r.acted());
        assert_eq!(r.operation, None);
        assert!(!serde_json::to_string(&r)
            .unwrap()
            .contains(r#""operation":"#));
    }

    /// `suppressed_before` is absent unless something was held back, so
    /// records without it keep the pre-field byte shape.
    #[test]
    fn suppressed_before_absent_unless_held() {
        let sink = DetectionSink::for_test(4, 0);
        for held in [0, 7] {
            sink.record_rule(
                &sample_event(),
                &sample_verdict(),
                &[],
                PostureKind::Observing,
                "KillProcess".to_string(),
                held,
            );
        }
        let q = sink.inner.queue.lock();
        let lines: Vec<String> = q
            .iter()
            .map(|r| serde_json::to_string(r).unwrap())
            .collect();
        assert!(!lines[0].contains("suppressed_before"));
        assert!(lines[1].ends_with(",\"suppressed_before\":7}"));
        let back: DetectionRecord = serde_json::from_str(&lines[1]).unwrap();
        assert_eq!(back.suppressed_before, Some(7));
    }

    fn report(
        action: ResponseAction,
        primary: ExecutionOutcome,
        additional: Vec<ExecutionOutcome>,
    ) -> ExecutionReport {
        ExecutionReport {
            action,
            primary,
            additional,
            elapsed: std::time::Duration::from_micros(1),
        }
    }

    /// External audit NN-AUD-234: a kill that did not happen was recorded
    /// as the bare action name, the same as one that did.
    #[test]
    fn response_names_the_outcome_when_the_action_did_not_happen() {
        use ResponseAction::*;
        let cases = [
            (
                report(
                    KillProcess,
                    ExecutionOutcome::AlreadyGone { pid: 7 },
                    vec![],
                ),
                "KillProcess (already gone)",
            ),
            (
                report(
                    KillProcessTree,
                    ExecutionOutcome::Refused {
                        pid: 7,
                        reason: "ssh-service(sshd)",
                    },
                    vec![],
                ),
                "KillProcessTree (refused: ssh-service(sshd))",
            ),
            (
                report(
                    KillProcess,
                    ExecutionOutcome::PermissionDenied {
                        pid: 7,
                        errno: libc::EPERM,
                    },
                    vec![],
                ),
                "KillProcess (permission denied)",
            ),
            (
                report(
                    KillProcess,
                    ExecutionOutcome::Failed {
                        pid: 7,
                        errno: libc::ETIMEDOUT,
                    },
                    vec![],
                ),
                "KillProcess (failed: Connection timed out, errno 110)",
            ),
            (
                report(
                    Quarantine,
                    ExecutionOutcome::Failed { pid: 7, errno: 0 },
                    vec![],
                ),
                "Quarantine (failed)",
            ),
            (
                report(
                    FullNetworkIsolation,
                    ExecutionOutcome::Refused {
                        pid: 7,
                        reason: "host-wide isolation is the COMBAT ladder's",
                    },
                    vec![],
                ),
                "FullNetworkIsolation (refused: host-wide isolation is the COMBAT ladder's)",
            ),
        ];
        for (r, want) in cases {
            assert_eq!(describe_response(&r), want, "{r:?}");
        }
    }

    /// The tree's root killed and part of the tree still running is not a
    /// tree killed.
    #[test]
    fn response_reports_a_tree_kill_that_left_processes_running() {
        let killed = ExecutionOutcome::Killed { pid: 7 };
        let r = report(
            ResponseAction::KillProcessTree,
            killed.clone(),
            vec![
                ExecutionOutcome::Killed { pid: 8 },
                ExecutionOutcome::Refused {
                    pid: 9,
                    reason: "northnarrow-watchdog",
                },
                ExecutionOutcome::Failed {
                    pid: 10,
                    errno: libc::ETIMEDOUT,
                },
                ExecutionOutcome::PermissionDenied {
                    pid: 11,
                    errno: libc::EPERM,
                },
                ExecutionOutcome::TreeTruncated {
                    pid: 7,
                    limit: 4096,
                },
            ],
        );
        assert_eq!(
            describe_response(&r),
            "KillProcessTree (partial: 2 not killed, 1 spared, walk truncated)"
        );
        // descendants killed, or gone by themselves: the whole tree
        let r = report(
            ResponseAction::KillProcessTree,
            killed,
            vec![
                ExecutionOutcome::Killed { pid: 8 },
                ExecutionOutcome::AlreadyGone { pid: 9 },
            ],
        );
        assert_eq!(describe_response(&r), "KillProcessTree");
    }

    /// The values readers already know keep their text: an action carried
    /// out is its bare name, detect-only and `Log` are unchanged.
    #[test]
    fn response_of_an_action_carried_out_is_unchanged() {
        use ResponseAction::*;
        let cases = [
            (
                report(KillProcess, ExecutionOutcome::Killed { pid: 7 }, vec![]),
                "KillProcess",
            ),
            (
                report(KillProcessTree, ExecutionOutcome::Killed { pid: 7 }, vec![]),
                "KillProcessTree",
            ),
            (
                report(BlockOutbound, ExecutionOutcome::Blocked { pid: 7 }, vec![]),
                "BlockOutbound",
            ),
            (
                report(
                    Quarantine,
                    ExecutionOutcome::Quarantined {
                        original_path: "/tmp/x".to_string(),
                        vault_id: "00".repeat(16),
                    },
                    vec![],
                ),
                "Quarantine",
            ),
            (
                report(
                    ThrottleProcess,
                    ExecutionOutcome::Throttled {
                        pid: 7,
                        cpu_max_pct: Some(10),
                        io_weight: None,
                        memory_high_bytes: None,
                    },
                    vec![],
                ),
                "ThrottleProcess",
            ),
            (
                report(
                    StripFileCapability,
                    ExecutionOutcome::CapabilityStripped {
                        path: "/usr/bin/x".to_string(),
                    },
                    vec![],
                ),
                "StripFileCapability",
            ),
            (
                report(
                    KillProcess,
                    ExecutionOutcome::WouldExecute { pid: 7 },
                    vec![],
                ),
                "suppressed (detect-only)",
            ),
            (
                report(Log, ExecutionOutcome::WouldExecute { pid: 7 }, vec![]),
                "suppressed (detect-only)",
            ),
            (
                report(
                    Log,
                    ExecutionOutcome::Refused {
                        pid: 7,
                        reason: "Log action — no execution required",
                    },
                    vec![],
                ),
                "none",
            ),
        ];
        for (r, want) in cases {
            assert_eq!(describe_response(&r), want, "{r:?}");
        }
    }

    /// The record says what the executor did to a real process: spared by
    /// the host-critical guard (it still runs), killed, gone before the
    /// kill. Only signals a child of the test: no privilege needed.
    #[test]
    fn recorded_response_matches_what_the_executor_did() {
        use crate::response::{Executor, ExecutorConfig};
        use std::os::unix::process::ExitStatusExt;
        let mut sleeper = std::process::Command::new("sleep")
            .arg("30")
            .stdout(std::process::Stdio::null())
            .spawn()
            .unwrap();
        let pid = sleeper.id();
        let tmp = tempfile::tempdir().unwrap();
        let mut cfg = ExecutorConfig::for_test(tmp.path());
        cfg.dry_run = false;

        let guarded = Executor::with_config(cfg.clone());
        guarded.set_tree_guard(std::sync::Arc::new(move |p: u32| {
            (p == pid).then_some("ssh-service(sshd)")
        }));
        let r = guarded.execute(ResponseAction::KillProcess, pid);
        assert_eq!(
            describe_response(&r),
            "KillProcess (refused: ssh-service(sshd))"
        );
        assert!(
            sleeper.try_wait().unwrap().is_none(),
            "a spared process runs"
        );

        let exec = Executor::with_config(cfg);
        let r = exec.execute(ResponseAction::KillProcess, pid);
        assert_eq!(describe_response(&r), "KillProcess");
        assert_eq!(sleeper.wait().unwrap().signal(), Some(libc::SIGKILL));

        // A PID above any pid_max: nothing to kill.
        let r = exec.execute(ResponseAction::KillProcess, 999_999_999);
        assert_eq!(describe_response(&r), "KillProcess (already gone)");
    }

    #[tokio::test]
    async fn writer_appends_records_with_intact_chain() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("detections.jsonl");
        let key = test_key();
        let pubkey = key.verifying_key();
        let (sink, _writer) = open(
            &path,
            key,
            RotationConfig::default(),
            Arc::new(NoProtection),
            DEFAULT_QUEUE_CAP,
        )
        .expect("open detection store");

        for _ in 0..5 {
            sink.record_rule(
                &sample_event(),
                &sample_verdict(),
                &[],
                PostureKind::Observing,
                "KillProcess".to_string(),
                0,
            );
        }

        // Poll until the writer task has flushed all 5 (bounded wait).
        let mut flushed = 0usize;
        for _ in 0..200 {
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            flushed = count_data_lines(&path);
            if flushed >= 5 {
                break;
            }
        }
        assert_eq!(flushed, 5, "writer task appended every record");

        // The persisted chain must verify end-to-end (Ok ⇒ hashes +
        // signatures + linkage all check out).
        let report =
            verify_log_set::<DetectionRecord>(&path, &pubkey).expect("detection chain verifies");
        assert_eq!(
            report.total_records, 5,
            "all five records in the verified chain"
        );
    }

    fn count_data_lines(path: &Path) -> usize {
        std::fs::read_to_string(path)
            .map(|body| {
                body.lines()
                    .filter(|l| {
                        serde_json::from_str::<serde_json::Value>(l)
                            .ok()
                            .and_then(|v| v.get("id").map(|_| ()))
                            .is_some()
                    })
                    .count()
            })
            .unwrap_or(0)
    }

    // ── 9.0.b bounded read + filter tests ───────────────────────────

    /// Build a detection record with the fields the read/filter tests
    /// vary; everything else is a fixed, valid placeholder.
    fn mk(
        id: u64,
        ts: &str,
        severity: Severity,
        status: DetectionStatus,
        sensor: Sensor,
        comm: &str,
    ) -> DetectionRecord {
        DetectionRecord {
            id,
            ts: ts.to_string(),
            sensor,
            path: DetectionPath::Rule,
            rule_id: Some("R001".to_string()),
            rule_name: Some("rule".to_string()),
            severity,
            verdict: DetectionVerdict::Rule(ResponseAction::Log),
            confidence: 1.0,
            mitre: MitreAttack {
                tactic: Vec::new(),
                technique: Vec::new(),
            },
            principal: Principal {
                pid: 1,
                comm: comm.to_string(),
                uid: 0,
                ppid: None,
            },
            exe: None,
            posture_at: PostureKind::Observing,
            response: "none".to_string(),
            detection_type: "test".to_string(),
            status,
            suppressed_before: None,
            file: None,
            operation: None,
            mitre_version: None,
            execq: None,
            network: None,
            sanction: None,
            execpol: None,
            matches: None,
        }
    }

    /// Default-ish record varying only the id (ts derived from id so
    /// the on-disk append order is chronological, like production).
    fn mk_id(id: u64) -> DetectionRecord {
        mk(
            id,
            &format!("2026-06-09T12:00:{:02}.000000Z", id % 60),
            Severity::Medium,
            DetectionStatus::Open,
            Sensor::Exec,
            "proc",
        )
    }

    /// Write detection records as plain JSONL (one record per line) to
    /// `path` — the on-disk data-line shape the reader parses (the
    /// chain envelope fields are optional siblings the reader ignores).
    fn write_records(path: &Path, records: &[DetectionRecord]) {
        let body: String = records
            .iter()
            .map(|r| serde_json::to_string(r).unwrap() + "\n")
            .collect();
        std::fs::write(path, body).unwrap();
    }

    fn ids(records: &[DetectionRecord]) -> Vec<u64> {
        records.iter().map(|r| r.id).collect()
    }

    #[test]
    fn read_last_n_orders_newest_first() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("detections.jsonl");
        // Appended oldest-first (1..=5); the reader must return them
        // newest-first.
        write_records(&path, &[mk_id(1), mk_id(2), mk_id(3), mk_id(4), mk_id(5)]);
        let got = read_last_n(&path, 10, &DetectionFilter::default());
        assert_eq!(ids(&got), vec![5, 4, 3, 2, 1]);
    }

    #[test]
    fn read_last_n_respects_limit() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("detections.jsonl");
        let records: Vec<_> = (1..=10).map(mk_id).collect();
        write_records(&path, &records);
        let got = read_last_n(&path, 3, &DetectionFilter::default());
        assert_eq!(ids(&got), vec![10, 9, 8], "the 3 newest only");
    }

    #[test]
    fn read_last_n_missing_file_is_empty() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("does-not-exist.jsonl");
        let got = read_last_n(&path, 10, &DetectionFilter::default());
        assert!(got.is_empty());
    }

    #[test]
    fn read_last_n_filters_min_severity() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("detections.jsonl");
        write_records(
            &path,
            &[
                mk(
                    1,
                    "2026-06-09T12:00:01.000000Z",
                    Severity::Low,
                    DetectionStatus::Open,
                    Sensor::Exec,
                    "a",
                ),
                mk(
                    2,
                    "2026-06-09T12:00:02.000000Z",
                    Severity::Medium,
                    DetectionStatus::Open,
                    Sensor::Exec,
                    "b",
                ),
                mk(
                    3,
                    "2026-06-09T12:00:03.000000Z",
                    Severity::High,
                    DetectionStatus::Open,
                    Sensor::Exec,
                    "c",
                ),
                mk(
                    4,
                    "2026-06-09T12:00:04.000000Z",
                    Severity::Critical,
                    DetectionStatus::Open,
                    Sensor::Exec,
                    "d",
                ),
            ],
        );
        let filter = DetectionFilter {
            min_severity: Some(Severity::High),
            ..Default::default()
        };
        let got = read_last_n(&path, 10, &filter);
        assert_eq!(
            ids(&got),
            vec![4, 3],
            "only High and Critical, newest-first"
        );
    }

    #[test]
    fn read_last_n_filters_status() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("detections.jsonl");
        write_records(
            &path,
            &[
                mk(
                    1,
                    "2026-06-09T12:00:01.000000Z",
                    Severity::Medium,
                    DetectionStatus::Open,
                    Sensor::Exec,
                    "a",
                ),
                mk(
                    2,
                    "2026-06-09T12:00:02.000000Z",
                    Severity::Medium,
                    DetectionStatus::Resolved,
                    Sensor::Exec,
                    "b",
                ),
                mk(
                    3,
                    "2026-06-09T12:00:03.000000Z",
                    Severity::Medium,
                    DetectionStatus::Open,
                    Sensor::Exec,
                    "c",
                ),
            ],
        );
        let filter = DetectionFilter {
            status: Some(DetectionStatus::Open),
            ..Default::default()
        };
        let got = read_last_n(&path, 10, &filter);
        assert_eq!(ids(&got), vec![3, 1]);
    }

    #[test]
    fn read_last_n_filters_sensor() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("detections.jsonl");
        write_records(
            &path,
            &[
                mk(
                    1,
                    "2026-06-09T12:00:01.000000Z",
                    Severity::Medium,
                    DetectionStatus::Open,
                    Sensor::Exec,
                    "a",
                ),
                mk(
                    2,
                    "2026-06-09T12:00:02.000000Z",
                    Severity::Medium,
                    DetectionStatus::Open,
                    Sensor::Network,
                    "b",
                ),
                mk(
                    3,
                    "2026-06-09T12:00:03.000000Z",
                    Severity::Medium,
                    DetectionStatus::Open,
                    Sensor::Network,
                    "c",
                ),
            ],
        );
        let filter = DetectionFilter {
            sensor: Some(Sensor::Network),
            ..Default::default()
        };
        let got = read_last_n(&path, 10, &filter);
        assert_eq!(ids(&got), vec![3, 2]);
    }

    #[test]
    fn read_last_n_filters_path_against_comm() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("detections.jsonl");
        write_records(
            &path,
            &[
                mk(
                    1,
                    "2026-06-09T12:00:01.000000Z",
                    Severity::Medium,
                    DetectionStatus::Open,
                    Sensor::Exec,
                    "sshd",
                ),
                mk(
                    2,
                    "2026-06-09T12:00:02.000000Z",
                    Severity::Medium,
                    DetectionStatus::Open,
                    Sensor::Exec,
                    "curl",
                ),
                mk(
                    3,
                    "2026-06-09T12:00:03.000000Z",
                    Severity::Medium,
                    DetectionStatus::Open,
                    Sensor::Exec,
                    "curl-helper",
                ),
            ],
        );
        let filter = DetectionFilter {
            subject_substr: Some("curl".to_string()),
            ..Default::default()
        };
        let got = read_last_n(&path, 10, &filter);
        assert_eq!(ids(&got), vec![3, 2], "substring matches both curl* comms");
    }

    /// External audit ASK-018: `--path` finds a record by the executable
    /// or the file it names, not only by `comm`.
    #[test]
    fn read_last_n_filters_path_against_exe_and_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("detections.jsonl");
        let mut curl = mk(
            1,
            "2026-06-09T12:00:01.000000Z",
            Severity::Medium,
            DetectionStatus::Open,
            Sensor::Exec,
            "curl",
        );
        curl.exe = Some("/usr/bin/curl".to_string());
        let mut cron = mk(
            2,
            "2026-06-09T12:00:02.000000Z",
            Severity::Medium,
            DetectionStatus::Open,
            Sensor::File,
            "bash",
        );
        cron.file = Some("/etc/cron.d/backdoor".to_string());
        // A short name the kernel truncated: comm differs from the image.
        let mut helper = mk(
            3,
            "2026-06-09T12:00:03.000000Z",
            Severity::Medium,
            DetectionStatus::Open,
            Sensor::Exec,
            "systemd-network",
        );
        helper.exe = Some("/usr/lib/systemd/systemd-networkd-wait-online".to_string());
        write_records(&path, &[curl, cron, helper]);
        let by = |sub: &str| {
            let filter = DetectionFilter {
                subject_substr: Some(sub.to_string()),
                ..Default::default()
            };
            ids(&read_last_n(&path, 10, &filter))
        };
        assert_eq!(by("/usr/bin/curl"), vec![1], "the executable's path");
        assert_eq!(by("curl"), vec![1], "the comm still matches");
        assert_eq!(by("/etc/cron.d/"), vec![2], "the file's path");
        assert_eq!(by("bash"), vec![2]);
        assert_eq!(by("wait-online"), vec![3], "beyond the 15-byte comm");
        assert_eq!(by("/usr/"), vec![3, 1]);
        assert!(by("/opt/").is_empty());
    }

    #[test]
    fn read_last_n_filters_time_bounds() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("detections.jsonl");
        let t1 = "2026-06-09T12:00:01.000000Z";
        let t2 = "2026-06-09T12:00:02.000000Z";
        let t3 = "2026-06-09T12:00:03.000000Z";
        write_records(
            &path,
            &[
                mk(
                    1,
                    t1,
                    Severity::Medium,
                    DetectionStatus::Open,
                    Sensor::Exec,
                    "a",
                ),
                mk(
                    2,
                    t2,
                    Severity::Medium,
                    DetectionStatus::Open,
                    Sensor::Exec,
                    "b",
                ),
                mk(
                    3,
                    t3,
                    Severity::Medium,
                    DetectionStatus::Open,
                    Sensor::Exec,
                    "c",
                ),
            ],
        );
        // since = t2 ⇒ keep t2, t3 (inclusive lower bound).
        let filter = DetectionFilter {
            since_unix: ts_to_unix(t2),
            ..Default::default()
        };
        assert_eq!(ids(&read_last_n(&path, 10, &filter)), vec![3, 2]);
        // until = t2 ⇒ keep t1, t2 (inclusive upper bound).
        let filter = DetectionFilter {
            until_unix: ts_to_unix(t2),
            ..Default::default()
        };
        assert_eq!(ids(&read_last_n(&path, 10, &filter)), vec![2, 1]);
        // since = t2 AND until = t2 ⇒ only t2.
        let filter = DetectionFilter {
            since_unix: ts_to_unix(t2),
            until_unix: ts_to_unix(t2),
            ..Default::default()
        };
        assert_eq!(ids(&read_last_n(&path, 10, &filter)), vec![2]);
    }

    #[test]
    fn read_last_n_descends_into_archive_when_active_insufficient() {
        let dir = tempfile::tempdir().unwrap();
        let active = dir.path().join("detections.jsonl");
        // Active holds the two newest (ids 6, 7); the sealed archive
        // .000001 holds the older five (ids 1..=5).
        write_records(&active, &[mk_id(6), mk_id(7)]);
        write_records(
            &dir.path().join("detections.jsonl.000001"),
            &[mk_id(1), mk_id(2), mk_id(3), mk_id(4), mk_id(5)],
        );
        // limit 4 isn't satisfied by the active file alone, so the
        // reader descends into the archive and returns the 4 newest
        // across both files.
        let got = read_last_n(&active, 4, &DetectionFilter::default());
        assert_eq!(ids(&got), vec![7, 6, 5, 4]);
    }

    #[test]
    fn read_last_n_stops_at_active_when_limit_satisfied() {
        let dir = tempfile::tempdir().unwrap();
        let active = dir.path().join("detections.jsonl");
        write_records(
            &active,
            &[mk_id(6), mk_id(7), mk_id(8), mk_id(9), mk_id(10)],
        );
        // White-box probe: the archive carries a SENTINEL id (999)
        // that would sort to the top IF the reader opened it. Because
        // the active file already satisfies limit=3, the archive must
        // NOT be read — so 999 must be absent from the result. (In a
        // real store an archive only holds OLDER ids than the active
        // file; the inflated id here exists purely to detect an
        // unnecessary descent.)
        write_records(&dir.path().join("detections.jsonl.000001"), &[mk_id(999)]);
        let got = read_last_n(&active, 3, &DetectionFilter::default());
        assert_eq!(ids(&got), vec![10, 9, 8]);
        assert!(
            !ids(&got).contains(&999),
            "archive must not be read once N is satisfied"
        );
    }

    #[test]
    fn read_last_n_descends_archives_newest_seq_first() {
        let dir = tempfile::tempdir().unwrap();
        let active = dir.path().join("detections.jsonl");
        // Active empty-ish (1 record); two archives — the higher seq
        // (.000002) is the more-recently-sealed, hence newer records.
        write_records(&active, &[mk_id(9)]);
        write_records(
            &dir.path().join("detections.jsonl.000002"),
            &[mk_id(7), mk_id(8)],
        );
        write_records(
            &dir.path().join("detections.jsonl.000001"),
            &[mk_id(1), mk_id(2)],
        );
        // limit 3 ⇒ active (9) + newest archive .000002 (8,7); the
        // older .000001 must not be needed.
        let got = read_last_n(&active, 3, &DetectionFilter::default());
        assert_eq!(ids(&got), vec![9, 8, 7]);
    }

    #[test]
    fn read_last_n_parses_real_chain_envelope_and_skips_terminators() {
        // Exercise the REAL on-disk shape: RotatingChainLog writes
        // each DetectionRecord wrapped in a flattened ChainLine
        // envelope (prev_hash/entry_hash/agent_sig/fmt_ver). The
        // reader must parse the payload regardless, and must SKIP a
        // terminator/torn line (which carries no `id`).
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("detections.jsonl");
        {
            let mut log = RotatingChainLog::<DetectionRecord>::open(
                &path,
                test_key(),
                RotationConfig::default(),
                std::sync::Arc::new(NoProtection),
            )
            .expect("open chainlog");
            log.append(mk_id(1)).unwrap();
            log.append(mk_id(2)).unwrap();
            log.append(mk_id(3)).unwrap();
        }
        // The active file now has 3 envelope-wrapped data lines. Append
        // a terminator-shaped line (no `id`) — it must be skipped.
        let mut body = std::fs::read_to_string(&path).unwrap();
        body.push_str(
            "{\"rotate\":{\"seq\":1},\"prev_hash\":\"a\",\"entry_hash\":\"b\",\"agent_sig\":\"c\"}\n",
        );
        std::fs::write(&path, body).unwrap();

        let got = read_last_n(&path, 10, &DetectionFilter::default());
        assert_eq!(
            ids(&got),
            vec![3, 2, 1],
            "payloads parsed, terminator skipped"
        );
    }

    // ── External audit EVD-010 (NN-AUD-275, lab PR 179) ─────────────

    /// The read as it was before lab PR 179: every match of a file held
    /// with its raw line, sorted, then cut — the reference the bounded
    /// collector must agree with.
    fn reference_read(
        active_path: &Path,
        limit: usize,
        filter: &DetectionFilter,
        pubkey: Option<&ed25519_dalek::VerifyingKey>,
    ) -> (Vec<u64>, usize) {
        let all_of = |path: &Path| -> Vec<(DetectionRecord, String)> {
            std::fs::read_to_string(path)
                .unwrap_or_default()
                .lines()
                .filter(|l| !l.trim().is_empty())
                .filter_map(|l| {
                    serde_json::from_str::<DetectionRecord>(l)
                        .ok()
                        .map(|r| (r, l.to_string()))
                })
                .filter(|(r, _)| r.matches(filter))
                .collect()
        };
        let mut collected: Vec<(DetectionRecord, String, bool)> = Vec::new();
        let mut unverified = 0usize;
        let mut fill = |collected: &mut Vec<(DetectionRecord, String, bool)>, path: &Path| {
            collected.extend(all_of(path).into_iter().map(|(r, l)| (r, l, false)));
            collected.sort_by_key(|(r, _, _)| std::cmp::Reverse(r.id));
            let Some(pk) = pubkey else {
                collected.truncate(limit);
                return;
            };
            let mut kept = Vec::new();
            for (r, line, checked) in collected.drain(..) {
                if kept.len() >= limit || unverified >= MAX_UNVERIFIED_PER_READ {
                    break;
                }
                if checked
                    || crate::chainlog::line_is_genuine::<DetectionRecord>(line.as_bytes(), pk)
                {
                    kept.push((r, line, true));
                } else {
                    unverified += 1;
                }
            }
            *collected = kept;
        };
        fill(&mut collected, active_path);
        if collected.len() < limit {
            for archive in crate::chainlog::archives_newest_first(active_path) {
                fill(&mut collected, &archive);
                if collected.len() >= limit {
                    break;
                }
            }
        }
        (collected.iter().map(|(r, _, _)| r.id).collect(), unverified)
    }

    fn high_water_reset() {
        HELD_HIGH_WATER.with(|h| h.set(0));
    }

    fn high_water() -> usize {
        HELD_HIGH_WATER.with(|h| h.get())
    }

    /// A forged detection line: chain-shaped, signed by no one.
    fn forged_line(r: DetectionRecord) -> String {
        let mut fake = serde_json::to_value(r).unwrap();
        fake["fmt_ver"] = serde_json::json!(2);
        fake["prev_hash"] = serde_json::json!("00".repeat(32));
        fake["entry_hash"] = serde_json::json!("11".repeat(32));
        fake["agent_sig"] = serde_json::json!("AAAA");
        serde_json::to_string(&fake).unwrap()
    }

    /// External audit EVD-010 (NN-AUD-275): `detections` held every
    /// matching record of a file, with its raw line, before cutting to
    /// `limit`. Without a key the collector now holds at most `limit`
    /// rows of a 20,000-row file, and serves what the full scan served.
    #[test]
    fn detections_collector_is_bounded_without_a_key() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("detections.jsonl");
        let records: Vec<DetectionRecord> = (1..=20_000u64)
            .map(|id| {
                let sensor = if id % 3 == 0 {
                    Sensor::File
                } else {
                    Sensor::Exec
                };
                mk(
                    id,
                    "2026-06-09T12:00:00.000000Z",
                    Severity::Medium,
                    DetectionStatus::Open,
                    sensor,
                    "proc",
                )
            })
            .collect();
        write_records(&path, &records);
        let selective = DetectionFilter {
            sensor: Some(Sensor::File),
            ..Default::default()
        };
        for filter in [DetectionFilter::default(), selective] {
            for limit in [1usize, 10, 1000] {
                high_water_reset();
                let (got, unverified) = read_last_n_verified(&path, limit, &filter, None);
                assert!(
                    high_water() <= limit,
                    "held {} rows for limit {limit}",
                    high_water()
                );
                assert_eq!(unverified, 0);
                assert_eq!(
                    (ids(&got), 0),
                    reference_read(&path, limit, &filter, None),
                    "limit {limit}"
                );
            }
        }
    }

    /// External audit EVD-010 (NN-AUD-275): with the agent key, the
    /// collector holds at most `limit + MAX_UNVERIFIED_PER_READ` rows of a
    /// file and returns what the full scan returned — the same rows and
    /// the same count of rows that do not verify — with forged rows mixed
    /// in: newer ids at the end, many copies of genuine ids after them
    /// (1,300 matches in all, more than the bound). Then a flood of newer
    /// forgeries: both reads give up after the same 1,000 failures.
    #[test]
    fn detections_collector_is_bounded_with_a_key_and_forged_rows() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("detections.jsonl");
        let key = test_key();
        let pk = key.verifying_key();
        {
            let mut log = RotatingChainLog::<DetectionRecord>::open(
                &path,
                key,
                RotationConfig::default(),
                std::sync::Arc::new(NoProtection),
            )
            .unwrap();
            for id in 1..=60u64 {
                log.append_deferred(mk_id(id)).unwrap();
            }
            log.sync().unwrap();
        }
        let genuine = std::fs::read_to_string(&path).unwrap();
        let mut body = genuine.clone();
        // 20 forged copies of every genuine id, after the genuine rows
        for round in 0..20 {
            for id in 1..=60u64 {
                let mut r = mk_id(id);
                r.detection_type = format!("forged-{round}");
                body.push_str(&forged_line(r));
                body.push('\n');
            }
        }
        // forged rows newer than any genuine one, at the end
        for id in 61..=100u64 {
            body.push_str(&forged_line(mk_id(id)));
            body.push('\n');
        }
        std::fs::write(&path, &body).unwrap();

        let filter = DetectionFilter::default();
        for limit in [1usize, 10, 40] {
            high_water_reset();
            let (got, unverified) = read_last_n_verified(&path, limit, &filter, Some(&pk));
            assert!(
                high_water() <= limit + MAX_UNVERIFIED_PER_READ,
                "held {} rows for limit {limit}",
                high_water()
            );
            assert_eq!(
                (ids(&got), unverified),
                reference_read(&path, limit, &filter, Some(&pk)),
                "limit {limit}"
            );
            assert_eq!(got.len(), limit, "genuine rows fill the limit");
            assert!(
                got.iter().all(|r| r.detection_type == "test"),
                "no forged row served"
            );
        }
        let (got, unverified) = read_last_n_verified(&path, 10, &filter, Some(&pk));
        assert_eq!(ids(&got), (51..=60u64).rev().collect::<Vec<_>>());
        assert_eq!(
            unverified,
            40 + 20 * 9,
            "the 40 newer forgeries, the copies of 60 to 52"
        );

        // A flood: 1,500 forged rows newer than every genuine one.
        let mut flood = genuine;
        for id in 61..=1_560u64 {
            flood.push_str(&forged_line(mk_id(id)));
            flood.push('\n');
        }
        std::fs::write(&path, &flood).unwrap();
        high_water_reset();
        let (got, unverified) = read_last_n_verified(&path, 10, &filter, Some(&pk));
        assert!(high_water() <= 10 + MAX_UNVERIFIED_PER_READ);
        assert_eq!(
            (ids(&got), unverified),
            reference_read(&path, 10, &filter, Some(&pk))
        );
        assert_eq!(unverified, MAX_UNVERIFIED_PER_READ);
    }

    /// External audit NN-AUD-112: before lab PR 160 any well-formed JSON
    /// line in `detections.jsonl` was served as a detection. With the agent
    /// key the read leaves out a line that does not verify, and counts it.
    #[test]
    fn read_last_n_skips_unsigned_lines() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("detections.jsonl");
        let key = test_key();
        let pk = key.verifying_key();
        {
            let mut log = RotatingChainLog::<DetectionRecord>::open(
                &path,
                key,
                RotationConfig::default(),
                std::sync::Arc::new(NoProtection),
            )
            .unwrap();
            log.append(mk_id(1)).unwrap();
            log.append(mk_id(2)).unwrap();
        }
        // A fabricated detection, chain-shaped but signed by no one.
        let mut fake = serde_json::to_value(mk_id(3)).unwrap();
        fake["fmt_ver"] = serde_json::json!(2);
        fake["prev_hash"] = serde_json::json!("00".repeat(32));
        fake["entry_hash"] = serde_json::json!("11".repeat(32));
        fake["agent_sig"] = serde_json::json!("AAAA");
        let mut body = std::fs::read_to_string(&path).unwrap();
        body.push_str(&serde_json::to_string(&fake).unwrap());
        body.push('\n');
        std::fs::write(&path, body).unwrap();

        let filter = DetectionFilter::default();
        assert_eq!(ids(&read_last_n(&path, 10, &filter)), vec![3, 2, 1]);
        let (got, unverified) = read_last_n_verified(&path, 10, &filter, Some(&pk));
        assert_eq!(ids(&got), vec![2, 1], "the fabricated row is not served");
        assert_eq!(unverified, 1);
        // the bound still holds: limit 1 serves the newest genuine row
        let (got, _) = read_last_n_verified(&path, 1, &filter, Some(&pk));
        assert_eq!(ids(&got), vec![2]);
    }

    #[test]
    fn severity_and_sensor_and_status_filters_parse_case_insensitively() {
        assert_eq!(parse_severity_filter("HIGH"), Some(Severity::High));
        assert_eq!(parse_severity_filter("critical"), Some(Severity::Critical));
        assert_eq!(parse_severity_filter("nope"), None);
        assert_eq!(
            Sensor::parse_filter("module-load"),
            Some(Sensor::ModuleLoad)
        );
        assert_eq!(
            Sensor::parse_filter("Anti-Tamper"),
            Some(Sensor::AntiTamper)
        );
        assert_eq!(Sensor::parse_filter("nope"), None);
        assert_eq!(
            DetectionStatus::parse_filter("Open"),
            Some(DetectionStatus::Open)
        );
        assert_eq!(
            DetectionStatus::parse_filter("Investigating"),
            Some(DetectionStatus::Investigating)
        );
        assert_eq!(
            DetectionStatus::parse_filter("RESOLVED"),
            Some(DetectionStatus::Resolved)
        );
        assert_eq!(
            DetectionStatus::parse_filter("false-positive"),
            Some(DetectionStatus::FalsePositive)
        );
        assert_eq!(
            DetectionStatus::parse_filter("fp"),
            Some(DetectionStatus::FalsePositive)
        );
        assert_eq!(DetectionStatus::parse_filter("nope"), None);
    }

    // ── Tappa 9.0.c — status parsing + event-sourced overlay ─────────

    #[test]
    fn parse_settable_rejects_open_and_unknown_accepts_transitions() {
        // `open` is the initial state, not a settable triage target.
        assert_eq!(DetectionStatus::parse_settable("open"), None);
        assert_eq!(DetectionStatus::parse_settable("nope"), None);
        assert_eq!(
            DetectionStatus::parse_settable("acknowledged"),
            Some(DetectionStatus::Acknowledged)
        );
        assert_eq!(
            DetectionStatus::parse_settable("Investigating"),
            Some(DetectionStatus::Investigating)
        );
        assert_eq!(
            DetectionStatus::parse_settable("resolved"),
            Some(DetectionStatus::Resolved)
        );
        assert_eq!(
            DetectionStatus::parse_settable("false-positive"),
            Some(DetectionStatus::FalsePositive)
        );
    }

    #[test]
    fn status_as_str_round_trips_through_parse_filter() {
        for s in [
            DetectionStatus::Open,
            DetectionStatus::Acknowledged,
            DetectionStatus::Investigating,
            DetectionStatus::Resolved,
            DetectionStatus::FalsePositive,
        ] {
            assert_eq!(DetectionStatus::parse_filter(s.as_str()), Some(s));
        }
    }

    /// Build a [`StatusEvent`] for the overlay tests.
    fn mk_event(id: u64, ts: &str, status: DetectionStatus) -> StatusEvent {
        StatusEvent {
            detection_id: id,
            new_status: status,
            ts: ts.to_string(),
            principal: Principal {
                pid: 1000,
                comm: "nn-admin".to_string(),
                uid: 0,
                ppid: None,
            },
            note: None,
            principal_exe: None,
        }
    }

    fn write_events(path: &Path, events: &[StatusEvent]) {
        let body: String = events
            .iter()
            .map(|e| serde_json::to_string(e).unwrap() + "\n")
            .collect();
        std::fs::write(path, body).unwrap();
    }

    #[test]
    fn overlay_reflects_latest_status_event() {
        let dir = tempfile::tempdir().unwrap();
        let det = dir.path().join("detections.jsonl");
        let evt = dir.path().join("status_events.jsonl");
        write_records(&det, &[mk_id(1), mk_id(2), mk_id(3)]);
        // id 1: two changes — latest (Investigating) wins. id 3: one
        // change. id 2: no change — keeps its on-disk Open.
        write_events(
            &evt,
            &[
                mk_event(
                    1,
                    "2026-06-09T12:01:00.000000Z",
                    DetectionStatus::Acknowledged,
                ),
                mk_event(3, "2026-06-09T12:01:01.000000Z", DetectionStatus::Resolved),
                mk_event(
                    1,
                    "2026-06-09T12:01:02.000000Z",
                    DetectionStatus::Investigating,
                ),
            ],
        );
        let got = read_last_n_overlaid(&det, &evt, 10, &DetectionFilter::default());
        let by_id: std::collections::HashMap<u64, DetectionStatus> =
            got.iter().map(|r| (r.id, r.status)).collect();
        assert_eq!(
            by_id[&1],
            DetectionStatus::Investigating,
            "latest event wins"
        );
        assert_eq!(by_id[&2], DetectionStatus::Open, "no event → initial Open");
        assert_eq!(by_id[&3], DetectionStatus::Resolved);
    }

    #[test]
    fn overlay_leaves_detection_lines_byte_intact() {
        let dir = tempfile::tempdir().unwrap();
        let det = dir.path().join("detections.jsonl");
        let evt = dir.path().join("status_events.jsonl");
        write_records(&det, &[mk_id(1)]);
        let before = std::fs::read(&det).unwrap();
        write_events(
            &evt,
            &[mk_event(
                1,
                "2026-06-09T12:02:00.000000Z",
                DetectionStatus::Resolved,
            )],
        );
        // Reading with overlay must not touch detections.jsonl.
        let got = read_last_n_overlaid(&det, &evt, 10, &DetectionFilter::default());
        assert_eq!(
            got[0].status,
            DetectionStatus::Resolved,
            "overlay applied to result"
        );
        let after = std::fs::read(&det).unwrap();
        assert_eq!(before, after, "detections.jsonl is byte-for-byte unchanged");
    }

    #[test]
    fn overlay_status_filter_matches_current_not_recorded_status() {
        let dir = tempfile::tempdir().unwrap();
        let det = dir.path().join("detections.jsonl");
        let evt = dir.path().join("status_events.jsonl");
        // All three recorded Open; id 2 resolved via an event.
        write_records(&det, &[mk_id(1), mk_id(2), mk_id(3)]);
        write_events(
            &evt,
            &[mk_event(
                2,
                "2026-06-09T12:03:00.000000Z",
                DetectionStatus::Resolved,
            )],
        );
        // Filter on CURRENT status = resolved → only id 2.
        let resolved = read_last_n_overlaid(
            &det,
            &evt,
            10,
            &DetectionFilter {
                status: Some(DetectionStatus::Resolved),
                ..Default::default()
            },
        );
        assert_eq!(
            ids(&resolved),
            vec![2],
            "only the currently-resolved detection"
        );
        // Filter on current status = open → ids 1 and 3 (NOT 2, which
        // was resolved even though its on-disk line still says Open).
        let open = read_last_n_overlaid(
            &det,
            &evt,
            10,
            &DetectionFilter {
                status: Some(DetectionStatus::Open),
                ..Default::default()
            },
        );
        assert_eq!(ids(&open), vec![3, 1], "currently-open only, newest-first");
    }

    #[test]
    fn latest_status_for_ids_descends_archive_only_when_unresolved() {
        let dir = tempfile::tempdir().unwrap();
        let active = dir.path().join("status_events.jsonl");
        // Active resolves id 1 (newest). Archive .000001 holds an OLDER
        // id-1 event (must be shadowed) + the only id-2 event.
        write_events(
            &active,
            &[mk_event(
                1,
                "2026-06-09T12:05:00.000000Z",
                DetectionStatus::Resolved,
            )],
        );
        write_events(
            &dir.path().join("status_events.jsonl.000001"),
            &[
                mk_event(
                    1,
                    "2026-06-09T12:04:00.000000Z",
                    DetectionStatus::Acknowledged,
                ),
                mk_event(
                    2,
                    "2026-06-09T12:04:01.000000Z",
                    DetectionStatus::Investigating,
                ),
            ],
        );
        let wanted: std::collections::HashSet<u64> = [1u64, 2].into_iter().collect();
        let map = latest_status_for_ids(&active, &wanted);
        assert_eq!(
            map[&1],
            DetectionStatus::Resolved,
            "active shadows archive for id 1"
        );
        assert_eq!(
            map[&2],
            DetectionStatus::Investigating,
            "archive resolves id 2"
        );
    }

    #[tokio::test]
    async fn status_event_chain_has_signed_envelope() {
        // A StatusEvent appended via the RotatingChainLog carries the
        // same prev_hash/entry_hash/agent_sig envelope as a detection
        // line, and the chain verifies end-to-end.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("status_events.jsonl");
        let key = test_key();
        let pubkey = key.verifying_key();
        {
            let mut log = open_status_log(
                &path,
                key,
                RotationConfig::default(),
                Arc::new(NoProtection),
            )
            .expect("open status log");
            log.append(mk_event(
                1,
                "2026-06-09T12:06:00.000000Z",
                DetectionStatus::Acknowledged,
            ))
            .unwrap();
            log.append(mk_event(
                1,
                "2026-06-09T12:06:01.000000Z",
                DetectionStatus::Resolved,
            ))
            .unwrap();
        }
        // Each persisted line carries the envelope siblings.
        let body = std::fs::read_to_string(&path).unwrap();
        for line in body.lines().filter(|l| !l.trim().is_empty()) {
            let v: serde_json::Value = serde_json::from_str(line).unwrap();
            assert!(v.get("prev_hash").is_some(), "envelope prev_hash present");
            assert!(v.get("entry_hash").is_some(), "envelope entry_hash present");
            assert!(v.get("agent_sig").is_some(), "envelope agent_sig present");
            assert!(
                v.get("detection_id").is_some(),
                "payload detection_id present"
            );
        }
        let report = verify_log_set::<StatusEvent>(&path, &pubkey).expect("status chain verifies");
        assert_eq!(
            report.total_records, 2,
            "both status events in the verified chain"
        );
    }

    #[test]
    fn overlay_reads_through_real_signed_chain_envelope() {
        // End-to-end: status events written THROUGH the RotatingChainLog
        // (so each line is wrapped in the prev_hash/entry_hash/agent_sig
        // envelope) must still be parsed by the overlay read — the
        // overlay must see past the envelope siblings to the payload.
        let dir = tempfile::tempdir().unwrap();
        let det = dir.path().join("detections.jsonl");
        let evt = dir.path().join("status_events.jsonl");
        write_records(&det, &[mk_id(1)]);
        {
            let mut log = open_status_log(
                &evt,
                test_key(),
                RotationConfig::default(),
                Arc::new(NoProtection),
            )
            .expect("open status log");
            log.append(mk_event(
                1,
                "2026-06-09T12:07:00.000000Z",
                DetectionStatus::Acknowledged,
            ))
            .unwrap();
            log.append(mk_event(
                1,
                "2026-06-09T12:07:01.000000Z",
                DetectionStatus::Resolved,
            ))
            .unwrap();
        }
        let got = read_last_n_overlaid(&det, &evt, 10, &DetectionFilter::default());
        assert_eq!(got.len(), 1);
        assert_eq!(
            got[0].status,
            DetectionStatus::Resolved,
            "overlay reads the latest status through the real signed chain envelope"
        );
    }
}
