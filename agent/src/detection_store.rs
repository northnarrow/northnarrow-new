//! Tappa 9.0.a — detection persistence.
//!
//! Until now the agent was fire-and-forget on detections: both the rule
//! path and the ADE path in `main::process_event` computed a verdict,
//! `warn!`-logged it, ran the executor, and DROPPED the record. The
//! local dashboard (Tappa 9) needs detections to PERSIST so a later
//! sub-step (9.0.b) can expose "the last N detections" over the admin
//! socket and aggregate them for the pipeline/Sankey view.
//!
//! This module is the data layer only. It provides:
//!
//! - [`DetectionRecord`] — one serializable detection, joining the
//!   firing sensor, rule (rule path) / ADE verdict (ADE path), severity,
//!   MITRE tags, principal, posture-at-detection, the response taken,
//!   and an `Open`/`Acknowledged`/`Closed` lifecycle status. It REUSES
//!   the existing [`Severity`](common::model::Severity),
//!   [`ResponseAction`](common::model::ResponseAction),
//!   [`AdeAction`](common::ade_types::AdeAction),
//!   [`MitreAttack`](common::ade_types::MitreAttack) and
//!   [`PostureKind`](common::posture_types::PostureKind) types rather
//!   than redefining them.
//! - [`DetectionSink`] — a cheap, cloneable handle the hot event path
//!   pushes records into. It NEVER blocks on fsync: a record is stamped
//!   with a monotonic id, pushed onto a bounded in-memory queue, and a
//!   dedicated writer task is woken. On a full queue the OLDEST record
//!   is dropped and a counter is bumped (a live dashboard cares about
//!   the freshest detections; the drop is observable via the counter +
//!   a log line). This is the bounded-MPSC-with-drop-oldest the design
//!   calls for; a raw `mpsc` can't drop from the *oldest* end at the
//!   producer, so the queue is a `Mutex<VecDeque>` woken by a `Notify`.
//! - [`open`] — wires a [`RotatingChainLog<DetectionRecord>`] (the same
//!   signed, rotation-aware primitive behind audit / FIM / netflow /
//!   canary, [`crate::chainlog`]) to the sink + writer task, seeding the
//!   id counter from the persisted tail so ids stay monotonic across a
//!   restart.
//!
//! OUT OF SCOPE for 9.0.a (later sub-steps): a `Detections` socket read
//! verb (9.0.b), status-change events (9.0.c), and XAI explanation
//! wiring — [`DetectionRecord::explanation`] is schema-only (`None`)
//! here (9.0.e).

use std::collections::VecDeque;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use anyhow::{Context, Result};
use chrono::Utc;
use common::ade_types::{AdeAction, AdeSeverity, AdeVerdict, MitreAttack};
use common::{Event, ResponseAction, Severity, Verdict};
use common::posture_types::PostureKind;
use common::xai_types::XaiEvidenceChain;
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use tokio::sync::Notify;
use tokio::task::JoinHandle;
use tracing::{info, warn};

use crate::audit::AgentSigningKey;
use crate::chainlog::{ProtectionManager, RotatingChainLog, RotationConfig};
use crate::response::{ExecutionOutcome, ExecutionReport};

/// Default on-disk location of the detection chainlog. Lives under the
/// anti-tamper-protected state dir (`/var/lib/northnarrow`, mode 0700)
/// in its own `detections/` sub-directory — higher-volume runtime data
/// belongs in `/var/lib`, NOT `/etc` (config). Sealed archives and the
/// manifest are siblings of this active file inside `detections/`.
pub const DEFAULT_DETECTIONS_LOG_PATH: &str = "/var/lib/northnarrow/detections/detections.jsonl";

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
/// memory. A burst beyond this drops the OLDEST queued record (see
/// [`DetectionSink`]).
pub const DEFAULT_QUEUE_CAP: usize = 1024;

// ── record shape ────────────────────────────────────────────────────

/// Which sensor surfaced the triggering event. Derived from the
/// [`Event`] variant via [`Sensor::from_event`]; the Sankey's left-most
/// "Sensor (eBPF)" column. (There is no pre-existing sensor enum in the
/// codebase — events are tagged only by `Event` variant — so this is a
/// thin projection of that, not a redefinition of an existing type.)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Sensor {
    /// Process exec — `sched_process_exec` / `bprm_check_security`.
    Exec,
    /// File access / integrity — `file_open` LSM + FIM drift.
    File,
    /// Kernel module load — `kernel_read_file` / `kernel_load_data`.
    ModuleLoad,
    /// Network — TCP connect, DNS query, finalized flow, listener.
    Network,
    /// Anti-tamper LSM denial on a protected inode.
    AntiTamper,
    /// Canary token trip.
    Canary,
}

impl Sensor {
    /// Map a triggering [`Event`] to its originating sensor. Exhaustive
    /// (no wildcard) on purpose: a new `Event` variant should force an
    /// explicit decision here rather than be silently bucketed.
    pub fn from_event(event: &Event) -> Self {
        match event {
            Event::ProcessSpawn { .. } | Event::ExecCheck { .. } => Sensor::Exec,
            Event::FileOpen { .. } | Event::Fim(_) => Sensor::File,
            Event::ModuleLoad { .. } => Sensor::ModuleLoad,
            Event::TcpConnect { .. }
            | Event::DnsQuery { .. }
            | Event::NetFlow(_)
            | Event::NetListener(_) => Sensor::Network,
            Event::FsProtectDenial { .. } => Sensor::AntiTamper,
            Event::CanaryTripped { .. } => Sensor::Canary,
        }
    }
}

/// Which decision path produced the detection. `path: Rule` ⇒
/// `rule_id`/`rule_name` are `Some`; `path: Ade` ⇒ they are `None` and
/// the verdict carries an [`AdeAction`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DetectionPath {
    /// A compiled `NN-L-*` / `R0*` rule fired.
    Rule,
    /// No rule matched; the ADE (LLM) fallback returned a verdict.
    Ade,
}

/// The decision itself, reusing the existing per-path enums verbatim.
/// Kept as one field (rather than two `Option`s) so a record always has
/// exactly one verdict; the variant matches [`DetectionRecord::path`].
/// This is a thin sum over the two existing decision enums, not a new
/// decision taxonomy.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DetectionVerdict {
    /// Rule-engine action ([`ResponseAction`]).
    Rule(ResponseAction),
    /// ADE recommendation ([`AdeAction`]).
    Ade(AdeAction),
}

/// Triage lifecycle of a detection. Initialised [`Open`](Self::Open).
/// The transition verbs (`Acknowledged`/`Closed`) are wired by 9.0.c —
/// 9.0.a only persists the initial `Open` state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DetectionStatus {
    Open,
    Acknowledged,
    Closed,
}

/// Process attribution for a detection. Best-effort: `comm` is always
/// present, `ppid` only when the source event carried it (process exec
/// events do; file / net / canary events do not). `exe` is deliberately
/// omitted — it is not uniformly available across sensors, and `comm`
/// is the one field every variant exposes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Principal {
    pub pid: u32,
    pub comm: String,
    pub uid: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ppid: Option<u32>,
}

impl Principal {
    /// Extract the acting principal from a triggering [`Event`].
    /// Exhaustive on purpose (see [`Sensor::from_event`]).
    pub fn from_event(event: &Event) -> Self {
        match event {
            Event::ProcessSpawn {
                pid, ppid, uid, comm, ..
            }
            | Event::ExecCheck {
                pid, ppid, uid, comm, ..
            } => Principal {
                pid: *pid,
                comm: comm.clone(),
                uid: *uid,
                ppid: Some(*ppid),
            },
            Event::FileOpen { pid, uid, comm, .. }
            | Event::TcpConnect { pid, uid, comm, .. }
            | Event::DnsQuery { pid, uid, comm, .. }
            | Event::FsProtectDenial { pid, uid, comm, .. } => Principal {
                pid: *pid,
                comm: comm.clone(),
                uid: *uid,
                ppid: None,
            },
            Event::ModuleLoad {
                loader_pid,
                loader_uid,
                loader_comm,
                ..
            } => Principal {
                pid: *loader_pid,
                comm: loader_comm.clone(),
                uid: *loader_uid,
                ppid: None,
            },
            Event::CanaryTripped {
                accessor_pid,
                accessor_uid,
                accessor_comm,
                ..
            } => Principal {
                pid: *accessor_pid,
                comm: accessor_comm.clone(),
                uid: *accessor_uid,
                ppid: None,
            },
            Event::Fim(fe) => Principal {
                pid: fe.modifier_pid,
                comm: fe.modifier_comm.clone(),
                uid: fe.modifier_uid,
                ppid: None,
            },
            Event::NetFlow(nf) => Principal {
                pid: nf.pid,
                comm: nf.comm.clone(),
                uid: nf.uid,
                ppid: None,
            },
            Event::NetListener(nl) => Principal {
                pid: nl.pid,
                comm: nl.comm.clone(),
                uid: nl.uid,
                ppid: None,
            },
        }
    }
}

/// One persisted detection. Serialised as a flattened JSONL line inside
/// the [`RotatingChainLog`] (the chain envelope adds `fmt_ver` /
/// `prev_hash` / `entry_hash` / `agent_sig`). No field collides with the
/// chainlog's reserved keys.
///
/// NOTE: this record does not duplicate `Verdict.timestamp_ns` (a
/// monotonic-clock value) — [`ts`](Self::ts) is the wall-clock instant
/// the detection was recorded, which is what a dashboard needs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectionRecord {
    /// Monotonic, restart-stable id (seeded from the persisted tail).
    /// Gaps are possible and meaningful — a gap means a record was
    /// dropped under backpressure (see [`DetectionSink`]).
    pub id: u64,
    /// Wall-clock UTC, microsecond resolution (matches the audit log).
    pub ts: String,
    pub sensor: Sensor,
    pub path: DetectionPath,
    /// `Some` on the rule path; `None` on the ADE path.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rule_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rule_name: Option<String>,
    pub severity: Severity,
    pub verdict: DetectionVerdict,
    /// `1.0` on the (deterministic) rule path; the model's confidence on
    /// the ADE path.
    pub confidence: f64,
    pub mitre: MitreAttack,
    pub principal: Principal,
    /// Agent posture at the moment of detection.
    pub posture_at: PostureKind,
    /// What the response layer actually did: a [`ResponseAction`] name,
    /// `"suppressed (detect-only)"`, or `"none"`.
    pub response: String,
    /// Detection sub-type: the rule `category` (rule path) or the ADE
    /// threat-classification `kind` (ADE path).
    pub detection_type: String,
    pub status: DetectionStatus,
    /// XAI / Article-13 explanation. Schema-only in 9.0.a (always
    /// `None`); wired by a later sub-step.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub explanation: Option<XaiEvidenceChain>,
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
            // Rule path carries no structured MITRE today (technique ids
            // live only in prose `reasoning`), so this is empty.
            mitre: MitreAttack {
                tactic: Vec::new(),
                technique: Vec::new(),
            },
            principal: Principal::from_event(event),
            posture_at: posture,
            response,
            detection_type: verdict.category.clone(),
            status: DetectionStatus::Open,
            explanation: None,
        }
    }

    /// Build a detection from an ADE-path verdict. Pure (see
    /// [`Self::from_rule`]).
    pub fn from_ade(
        id: u64,
        ts: String,
        event: &Event,
        verdict: &AdeVerdict,
        posture: PostureKind,
        response: String,
    ) -> Self {
        let detection_type = if verdict.threat_classification.kind.is_empty() {
            "ade".to_string()
        } else {
            verdict.threat_classification.kind.clone()
        };
        DetectionRecord {
            id,
            ts,
            sensor: Sensor::from_event(event),
            path: DetectionPath::Ade,
            rule_id: None,
            rule_name: None,
            severity: severity_from_ade(verdict.severity),
            verdict: DetectionVerdict::Ade(verdict.verdict),
            confidence: verdict.confidence,
            mitre: verdict.mitre_attack.clone(),
            principal: Principal::from_event(event),
            posture_at: posture,
            response,
            detection_type,
            status: DetectionStatus::Open,
            explanation: None,
        }
    }
}

/// Map the ADE severity (which has a `None` rung reserved for `Allow`)
/// onto the rule [`Severity`] so the record carries one severity enum.
/// `None` collapses to `Low` (the lowest concrete rung) — by the time a
/// detection is recorded the verdict is never `Allow`, so `None` is only
/// a defensive fallback.
fn severity_from_ade(s: AdeSeverity) -> Severity {
    match s {
        AdeSeverity::None | AdeSeverity::Low => Severity::Low,
        AdeSeverity::Medium => Severity::Medium,
        AdeSeverity::High => Severity::High,
        AdeSeverity::Critical => Severity::Critical,
    }
}

/// Render the executor's outcome into the record's `response` string.
/// Detect-only suppression ([`ExecutionOutcome::WouldExecute`]) is
/// surfaced distinctly from a real action; a `Log` action (observe-only)
/// is `"none"`.
pub fn describe_response(report: &ExecutionReport) -> String {
    match report.primary {
        ExecutionOutcome::WouldExecute { .. } => "suppressed (detect-only)".to_string(),
        _ => match report.action {
            ResponseAction::Log => "none".to_string(),
            ref action => format!("{action:?}"),
        },
    }
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
    /// Cumulative records dropped under backpressure (drop-oldest).
    dropped: AtomicU64,
    cap: usize,
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

    /// Push `record` onto the bounded queue. If full, drop the OLDEST
    /// queued record and bump the dropped counter, then enqueue the new
    /// one (freshest-wins). Wakes the writer. Holds the queue lock only
    /// for the push — the fsync happens on the writer task, never here.
    fn enqueue(&self, record: DetectionRecord) {
        {
            let mut q = self.inner.queue.lock();
            if q.len() >= self.inner.cap {
                q.pop_front();
                self.inner.dropped.fetch_add(1, Ordering::Relaxed);
            }
            q.push_back(record);
        }
        self.inner.notify.notify_one();
    }

    /// Record a rule-path detection (off the hot path).
    pub fn record_rule(
        &self,
        event: &Event,
        verdict: &Verdict,
        posture: PostureKind,
        response: String,
    ) {
        let record =
            DetectionRecord::from_rule(self.next_id(), now_ts(), event, verdict, posture, response);
        self.enqueue(record);
    }

    /// Record an ADE-path detection (off the hot path).
    pub fn record_ade(
        &self,
        event: &Event,
        verdict: &AdeVerdict,
        posture: PostureKind,
        response: String,
    ) {
        let record =
            DetectionRecord::from_ade(self.next_id(), now_ts(), event, verdict, posture, response);
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
                cap,
            }),
        }
    }
}

/// Wall-clock timestamp string, matching the audit log's format.
fn now_ts() -> String {
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
fn spawn_writer(mut log: RotatingChainLog<DetectionRecord>, inner: Arc<SinkInner>) -> JoinHandle<()> {
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
                    "detection records dropped under backpressure (queue full, drop-oldest)",
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
    archive_paths(active_path)
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

/// Sealed-archive siblings of `active_path`: `<active_file_name>.NNNNNN`
/// (6-digit zero-padded seq), excluding the manifest.
fn archive_paths(active_path: &Path) -> Vec<PathBuf> {
    let Some(dir) = active_path.parent() else {
        return Vec::new();
    };
    let Some(name) = active_path.file_name().and_then(|s| s.to_str()) else {
        return Vec::new();
    };
    let prefix = format!("{name}.");
    let mut out = Vec::new();
    if let Ok(read_dir) = std::fs::read_dir(dir) {
        for entry in read_dir.flatten() {
            if let Some(entry_name) = entry.file_name().to_str() {
                if let Some(suffix) = entry_name.strip_prefix(&prefix) {
                    if suffix.len() == 6 && suffix.bytes().all(|b| b.is_ascii_digit()) {
                        out.push(entry.path());
                    }
                }
            }
        }
    }
    out
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
    /// Substring match on the acting principal's `comm`. 9.0.a's
    /// record carries no filesystem path (the `exe`/filename was
    /// deliberately dropped), so the `--path` operator filter is
    /// applied against `comm` — the one subject identifier every
    /// sensor populates.
    pub comm_substr: Option<String>,
}

/// Severity as a comparable rung (`Low` < `Medium` < `High` <
/// `Critical`). [`common::model::Severity`] is not `Ord`, so the
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

impl Sensor {
    /// Parse a `--sensor` token (case-insensitive). Accepts both the
    /// hyphenated and squashed forms of the two-word sensors.
    pub fn parse_filter(s: &str) -> Option<Sensor> {
        match s.trim().to_ascii_lowercase().as_str() {
            "exec" => Some(Sensor::Exec),
            "file" => Some(Sensor::File),
            "module-load" | "moduleload" => Some(Sensor::ModuleLoad),
            "network" => Some(Sensor::Network),
            "anti-tamper" | "antitamper" => Some(Sensor::AntiTamper),
            "canary" => Some(Sensor::Canary),
            _ => None,
        }
    }
}

impl DetectionStatus {
    /// Parse a `--status` token (case-insensitive). `None` on an
    /// unrecognised token.
    pub fn parse_filter(s: &str) -> Option<DetectionStatus> {
        match s.trim().to_ascii_lowercase().as_str() {
            "open" => Some(DetectionStatus::Open),
            "acknowledged" | "ack" => Some(DetectionStatus::Acknowledged),
            "closed" => Some(DetectionStatus::Closed),
            _ => None,
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
        if let Some(ref sub) = filter.comm_substr {
            if !self.principal.comm.contains(sub.as_str()) {
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
/// parse and is skipped. The chain is NOT signature-verified here:
/// this is an on-host read of an LSM-protected file; integrity
/// verification is the dedicated `verify_log_set` / `nn-admin audit
/// verify` path, not every dashboard query.
pub fn read_last_n(
    active_path: &Path,
    limit: usize,
    filter: &DetectionFilter,
) -> Vec<DetectionRecord> {
    let mut collected: Vec<DetectionRecord> = Vec::new();
    collect_matching_from_file(active_path, filter, &mut collected);
    if collected.len() < limit {
        for archive in archives_newest_first(active_path) {
            collect_matching_from_file(&archive, filter, &mut collected);
            if collected.len() >= limit {
                break;
            }
        }
    }
    // Monotonic id ⇒ id-desc is newest-first across every file we
    // touched; bound to the requested N.
    collected.sort_by(|a, b| b.id.cmp(&a.id));
    collected.truncate(limit);
    collected
}

/// Append the matching [`DetectionRecord`]s from one chainlog file
/// (active or sealed archive) to `out`. Best-effort: a missing /
/// unreadable file contributes nothing; lines that don't parse as a
/// `DetectionRecord` (terminators, blanks) are skipped. The file is
/// size-capped (≤ rotation cap), so this is a bounded read.
fn collect_matching_from_file(
    path: &Path,
    filter: &DetectionFilter,
    out: &mut Vec<DetectionRecord>,
) {
    use std::io::{BufRead, BufReader};
    let f = match std::fs::OpenOptions::new().read(true).open(path) {
        Ok(f) => f,
        Err(_) => return,
    };
    for line in BufReader::new(f).lines() {
        let Ok(line) = line else { continue };
        if line.trim().is_empty() {
            continue;
        }
        if let Ok(record) = serde_json::from_str::<DetectionRecord>(&line) {
            if record.matches(filter) {
                out.push(record);
            }
        }
    }
}

/// Sealed-archive siblings of `active_path`, ordered newest-sealed-
/// first (highest 6-digit rotation seq first): the highest seq is the
/// most recently rotated file, hence the newest archived records.
fn archives_newest_first(active_path: &Path) -> Vec<PathBuf> {
    let mut archives = archive_paths(active_path);
    archives.sort_by(|a, b| archive_seq(b).cmp(&archive_seq(a)));
    archives
}

/// Extract the trailing 6-digit rotation seq from an archive path
/// (`<base>.NNNNNN`). [`archive_paths`] only yields well-formed
/// archive names, so the parse always succeeds in practice; a
/// malformed name sorts as `0`.
fn archive_seq(path: &Path) -> u64 {
    path.file_name()
        .and_then(|s| s.to_str())
        .and_then(|name| name.rsplit('.').next())
        .and_then(|suffix| suffix.parse::<u64>().ok())
        .unwrap_or(0)
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
            parent_is_kthread: false,
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
    /// `PartialEq`, because the reused `MitreAttack` is not `PartialEq`.)
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

    #[test]
    fn ade_shaped_record_roundtrips() {
        // Build the ADE-shaped record directly (constructing a full
        // AdeVerdict is unnecessary to exercise the record's serde): this
        // covers DetectionVerdict::Ade + a populated MitreAttack.
        let record = DetectionRecord {
            id: 9,
            ts: "2026-06-08T12:00:01.000000Z".to_string(),
            sensor: Sensor::Exec,
            path: DetectionPath::Ade,
            rule_id: None,
            rule_name: None,
            severity: Severity::High,
            verdict: DetectionVerdict::Ade(AdeAction::Kill),
            confidence: 0.91,
            mitre: MitreAttack {
                tactic: vec!["TA0002".to_string()],
                technique: vec!["T1059".to_string()],
            },
            principal: Principal::from_event(&sample_event()),
            posture_at: PostureKind::Alerted,
            response: "suppressed (detect-only)".to_string(),
            detection_type: "reverse_shell".to_string(),
            status: DetectionStatus::Open,
            explanation: None,
        };
        assert_roundtrip(&record);
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

    #[test]
    fn enqueue_drops_oldest_when_full() {
        // cap = 2, no writer draining: pushing 3 records must drop the
        // OLDEST (id 1) and keep the two freshest (ids 2, 3).
        let sink = DetectionSink::for_test(2, 0);
        for _ in 0..3 {
            sink.record_rule(
                &sample_event(),
                &sample_verdict(),
                PostureKind::Observing,
                "none".to_string(),
            );
        }
        assert_eq!(sink.queue_snapshot(), vec![2, 3], "freshest two retained");
        assert_eq!(sink.dropped(), 1, "exactly one (oldest) dropped");
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
                PostureKind::Observing,
                "KillProcess".to_string(),
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
        assert_eq!(report.total_records, 5, "all five records in the verified chain");
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
            posture_at: PostureKind::Observing,
            response: "none".to_string(),
            detection_type: "test".to_string(),
            status,
            explanation: None,
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
                mk(1, "2026-06-09T12:00:01.000000Z", Severity::Low, DetectionStatus::Open, Sensor::Exec, "a"),
                mk(2, "2026-06-09T12:00:02.000000Z", Severity::Medium, DetectionStatus::Open, Sensor::Exec, "b"),
                mk(3, "2026-06-09T12:00:03.000000Z", Severity::High, DetectionStatus::Open, Sensor::Exec, "c"),
                mk(4, "2026-06-09T12:00:04.000000Z", Severity::Critical, DetectionStatus::Open, Sensor::Exec, "d"),
            ],
        );
        let filter = DetectionFilter {
            min_severity: Some(Severity::High),
            ..Default::default()
        };
        let got = read_last_n(&path, 10, &filter);
        assert_eq!(ids(&got), vec![4, 3], "only High and Critical, newest-first");
    }

    #[test]
    fn read_last_n_filters_status() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("detections.jsonl");
        write_records(
            &path,
            &[
                mk(1, "2026-06-09T12:00:01.000000Z", Severity::Medium, DetectionStatus::Open, Sensor::Exec, "a"),
                mk(2, "2026-06-09T12:00:02.000000Z", Severity::Medium, DetectionStatus::Closed, Sensor::Exec, "b"),
                mk(3, "2026-06-09T12:00:03.000000Z", Severity::Medium, DetectionStatus::Open, Sensor::Exec, "c"),
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
                mk(1, "2026-06-09T12:00:01.000000Z", Severity::Medium, DetectionStatus::Open, Sensor::Exec, "a"),
                mk(2, "2026-06-09T12:00:02.000000Z", Severity::Medium, DetectionStatus::Open, Sensor::Network, "b"),
                mk(3, "2026-06-09T12:00:03.000000Z", Severity::Medium, DetectionStatus::Open, Sensor::Network, "c"),
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
                mk(1, "2026-06-09T12:00:01.000000Z", Severity::Medium, DetectionStatus::Open, Sensor::Exec, "sshd"),
                mk(2, "2026-06-09T12:00:02.000000Z", Severity::Medium, DetectionStatus::Open, Sensor::Exec, "curl"),
                mk(3, "2026-06-09T12:00:03.000000Z", Severity::Medium, DetectionStatus::Open, Sensor::Exec, "curl-helper"),
            ],
        );
        let filter = DetectionFilter {
            comm_substr: Some("curl".to_string()),
            ..Default::default()
        };
        let got = read_last_n(&path, 10, &filter);
        assert_eq!(ids(&got), vec![3, 2], "substring matches both curl* comms");
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
                mk(1, t1, Severity::Medium, DetectionStatus::Open, Sensor::Exec, "a"),
                mk(2, t2, Severity::Medium, DetectionStatus::Open, Sensor::Exec, "b"),
                mk(3, t3, Severity::Medium, DetectionStatus::Open, Sensor::Exec, "c"),
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
        write_records(&active, &[mk_id(6), mk_id(7), mk_id(8), mk_id(9), mk_id(10)]);
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
        assert!(!ids(&got).contains(&999), "archive must not be read once N is satisfied");
    }

    #[test]
    fn read_last_n_descends_archives_newest_seq_first() {
        let dir = tempfile::tempdir().unwrap();
        let active = dir.path().join("detections.jsonl");
        // Active empty-ish (1 record); two archives — the higher seq
        // (.000002) is the more-recently-sealed, hence newer records.
        write_records(&active, &[mk_id(9)]);
        write_records(&dir.path().join("detections.jsonl.000002"), &[mk_id(7), mk_id(8)]);
        write_records(&dir.path().join("detections.jsonl.000001"), &[mk_id(1), mk_id(2)]);
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
        assert_eq!(ids(&got), vec![3, 2, 1], "payloads parsed, terminator skipped");
    }

    #[test]
    fn severity_and_sensor_and_status_filters_parse_case_insensitively() {
        assert_eq!(parse_severity_filter("HIGH"), Some(Severity::High));
        assert_eq!(parse_severity_filter("critical"), Some(Severity::Critical));
        assert_eq!(parse_severity_filter("nope"), None);
        assert_eq!(Sensor::parse_filter("module-load"), Some(Sensor::ModuleLoad));
        assert_eq!(Sensor::parse_filter("Anti-Tamper"), Some(Sensor::AntiTamper));
        assert_eq!(Sensor::parse_filter("nope"), None);
        assert_eq!(DetectionStatus::parse_filter("Open"), Some(DetectionStatus::Open));
        assert_eq!(DetectionStatus::parse_filter("closed"), Some(DetectionStatus::Closed));
        assert_eq!(DetectionStatus::parse_filter("nope"), None);
    }
}
