//! [`LadderEvidence`] — the evidence/audit side effect of a ladder stage
//! transition, behind a trait so [`super::CombatLadder`] is testable
//! without a real signing key.
//!
//! ## Phase 2 (this commit): signed audit trail
//!
//! Every stage transition (INVESTIGATE / NEUTRALIZE / ISOLATE) is written
//! as a signed, hash-chained entry in the agent's tamper-evident audit
//! log ([`crate::audit::AuditLog`]) under op `"combat_stage"`, carrying
//! the from/to stages, the firing posture trigger, the attributed
//! offender PIDs, and a reason string. This is the per-stage-transition
//! audit trail the redesign requires, and it is captured/emitted BEFORE
//! the corresponding enforcement action runs — so the dossier is never
//! lost to a later isolation.
//!
//! External audit CMB-027: the entry can fail (a full filesystem, an I/O
//! error). [`LadderEvidence::record_stage`] says so, and the ladder logs the
//! whole transition at ERROR — the journal line is then its only record —
//! and carries on: holding ISOLATE until the audit log can be written
//! would let whoever breaks the log (fills its filesystem) prevent the
//! containment. [`AuditEvidence`] keeps the transition in a bounded queue
//! ([`RETRY_QUEUE_DEPTH`]) and writes it, in order and before any newer
//! one, at the next append or at the stand-down, marked `deferred` with the
//! time it happened (`occurred_at`); a transition dropped from a full queue
//! is counted in the next entry written (`transitions_lost`). The counts
//! are in `nn-admin status` ([`EvidenceCounts`]).
//!
//! ## Lab PR 217: the outcome of each action, signed after it ran
//!
//! A stage transition is recorded BEFORE its enforcement; what the
//! enforcement did was only logged — a kill that left an offender running,
//! an isolation whose iptables did not take, read as a stage reached.
//! [`LadderEvidence::record_outcome`] writes an [`ActionOutcome`] after the
//! action, under op `"combat_outcome"`: per offender for NEUTRALIZE (killed,
//! not contained and why, its binary quarantined or why not), per IP family
//! for ISOLATE (read back from the tables), with `result` `success` only
//! when the action achieved its purpose. It shares the stage transitions'
//! retry queue and order.
//!
//! ## Phase 3 (next): multi-sink dossier
//!
//! [`LadderEvidence`] is the seam the Panopticon work plugs into: a
//! richer implementation will, in addition to this audit entry, assemble
//! a `DossierPayload` (focal event + correlation snapshot + tail-hashes
//! of the FIM / netflow / audit chains) and stream it to multiple sinks
//! (a local signed `RotatingChainLog`, the journal, and an optional
//! remote uplink) so it survives even STAGE-3 isolation. The audit entry
//! emitted here is the spine that the dossier cross-references.

use std::collections::VecDeque;
use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use parking_lot::Mutex;
use tracing::{info, warn};

use common::posture_types::TriggerType;

use crate::audit::{AuditEntryDraft, AuditLog};

use super::CombatStage;

/// One ladder stage transition — the payload of a signed audit entry.
#[derive(Debug, Clone)]
pub struct StageTransition {
    /// `None` for the COMBAT-entry transition into INVESTIGATE.
    pub from: Option<CombatStage>,
    pub to: CombatStage,
    /// The posture trigger that drove COMBAT (telemetry/audit context).
    pub trigger: Option<TriggerType>,
    /// PIDs attributed to the threat at the time of the transition.
    pub offenders: Vec<u32>,
    /// Human-readable reason (deadline, jump-ahead, neutralization
    /// failure, …).
    pub reason: String,
}

/// Lab PR 217 (capability C17): what a COMBAT enforcement action did — the
/// payload of a signed `combat_outcome` entry, written after the action.
#[derive(Debug, Clone)]
pub struct ActionOutcome {
    /// The stage whose action this is.
    pub stage: CombatStage,
    /// `kill+quarantine`, `isolate`.
    pub action: &'static str,
    /// The posture trigger that drove COMBAT (context).
    pub trigger: Option<TriggerType>,
    /// The action achieved its purpose: every offender contained, every
    /// family isolated.
    pub success: bool,
    /// One line: what happened.
    pub summary: String,
    /// Per offender / per family detail, for the entry's `extra`.
    pub detail: serde_json::Value,
}

/// External audit CMB-027: why a stage transition is not in the signed
/// audit log (yet).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Unrecorded {
    /// This run has no audit log (`NN_AUDIT_ALLOW_UNWRITABLE=1`): the
    /// journal line is the only record.
    NoAuditLog,
    /// The append failed, or an older transition still waits: this one is
    /// queued and written after it, at the next append or the stand-down.
    /// `waiting` counts the queue with it.
    Queued { error: String, waiting: usize },
}

impl fmt::Display for Unrecorded {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoAuditLog => f.write_str("no audit log in this run"),
            Self::Queued { error, waiting } => write!(
                f,
                "audit append failed ({error}); queued for retry ({waiting} waiting)"
            ),
        }
    }
}

/// External audit CMB-027: the stage transitions the signed audit log did
/// not get when they happened, since the agent started.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct EvidenceCounts {
    /// Transitions whose entry was not written when they happened.
    pub unrecorded: u64,
    /// Of those, the ones still waiting in the retry queue.
    pub pending: u64,
    /// Of those, the ones dropped from the full queue: never written.
    pub dropped: u64,
}

/// Records a ladder stage transition. Implementations MUST NOT block the
/// ladder on failure: `Err` reports it, and the ladder logs the whole
/// transition at ERROR and proceeds (external audit CMB-027).
pub trait LadderEvidence: Send + Sync {
    fn record_stage(&self, transition: &StageTransition) -> Result<(), Unrecorded>;

    /// Lab PR 217: the outcome of an action, after it ran. Same contract as
    /// [`Self::record_stage`]: never blocks the ladder.
    fn record_outcome(&self, outcome: &ActionOutcome) -> Result<(), Unrecorded>;

    /// Write the transitions that wait for the audit log, if any (the
    /// stand-down: an episode's last ones would otherwise wait for the
    /// next episode).
    fn retry_pending(&self) {}

    /// What did not reach the audit log when it happened.
    fn counts(&self) -> EvidenceCounts {
        EvidenceCounts::default()
    }
}

/// External audit CMB-027: transitions kept for the audit log at most. An
/// episode records a handful (INVESTIGATE, NEUTRALIZE, ISOLATE, a failed
/// soft block, a refused isolation); past this the oldest is dropped (its
/// ERROR line stays in the journal) and counted.
pub const RETRY_QUEUE_DEPTH: usize = 64;

/// What waits for the audit log: a stage transition, or (lab PR 217) an
/// action's outcome.
#[derive(Clone)]
enum Record {
    Stage(StageTransition),
    Outcome(ActionOutcome),
}

impl Record {
    fn label(&self) -> String {
        match self {
            Record::Stage(t) => format!("stage {}", t.to.as_str()),
            Record::Outcome(o) => format!("outcome of {} ({})", o.stage.as_str(), o.action),
        }
    }
}

/// A record the audit log refused, with the time it happened.
struct Waiting {
    record: Record,
    occurred_at: String,
}

#[derive(Default)]
struct Backlog {
    waiting: VecDeque<Waiting>,
    /// Dropped from the full queue since the last entry written: the next
    /// entry says how many (`transitions_lost`).
    lost_unsaid: u64,
}

/// Production evidence sink: writes each stage transition as a signed,
/// hash-chained entry in the agent audit log. `None` audit log (a run
/// with `NN_AUDIT_ALLOW_UNWRITABLE=1`) records nothing: every transition
/// is `Unrecorded::NoAuditLog`, the ladder's ERROR line its only trace.
pub struct AuditEvidence {
    audit_log: Option<Arc<Mutex<AuditLog>>>,
    backlog: Mutex<Backlog>,
    unrecorded: AtomicU64,
    pending: AtomicU64,
    dropped: AtomicU64,
}

impl AuditEvidence {
    pub fn new(audit_log: Option<Arc<Mutex<AuditLog>>>) -> Self {
        Self {
            audit_log,
            backlog: Mutex::new(Backlog::default()),
            unrecorded: AtomicU64::new(0),
            pending: AtomicU64::new(0),
            dropped: AtomicU64::new(0),
        }
    }

    /// Write the waiting transitions, oldest first, stopping at the first
    /// failure (the rest keep their place). Called with both locks held.
    fn drain(&self, backlog: &mut Backlog, log: &mut AuditLog) -> Result<(), String> {
        let mut written = 0usize;
        while let Some(w) = backlog.waiting.front() {
            let draft = draft(&w.record, Some(&w.occurred_at), backlog.lost_unsaid);
            if let Err(e) = log.append(draft) {
                if written > 0 {
                    self.after_drain(written, backlog);
                }
                return Err(format!("{e:#}"));
            }
            backlog.waiting.pop_front();
            backlog.lost_unsaid = 0;
            written += 1;
        }
        if written > 0 {
            self.after_drain(written, backlog);
        }
        Ok(())
    }

    fn after_drain(&self, written: usize, backlog: &Backlog) {
        self.pending
            .store(backlog.waiting.len() as u64, Ordering::Relaxed);
        info!(
            target: "combat.audit",
            written,
            still_waiting = backlog.waiting.len(),
            "COMBAT stage transitions written to the audit log late (deferred, with their own time)"
        );
    }

    /// Queue `t` behind the waiting ones; a full queue drops its oldest.
    fn enqueue(&self, backlog: &mut Backlog, t: &Record, occurred_at: String) -> usize {
        if backlog.waiting.len() >= RETRY_QUEUE_DEPTH {
            if let Some(old) = backlog.waiting.pop_front() {
                self.dropped.fetch_add(1, Ordering::Relaxed);
                backlog.lost_unsaid += 1;
                warn!(
                    target: "combat.audit",
                    what = %old.record.label(),
                    occurred_at = %old.occurred_at,
                    depth = RETRY_QUEUE_DEPTH,
                    "COMBAT evidence retry queue full — the oldest waiting transition is dropped \
                     (its ERROR line is its only record)"
                );
            }
        }
        backlog.waiting.push_back(Waiting {
            record: t.clone(),
            occurred_at,
        });
        self.pending
            .store(backlog.waiting.len() as u64, Ordering::Relaxed);
        backlog.waiting.len()
    }
}

/// The audit entry of `r`; `deferred` is the time it happened when it is
/// written late.
fn draft(r: &Record, deferred: Option<&str>, lost: u64) -> AuditEntryDraft {
    let (op, mut extra, result) = match r {
        Record::Stage(t) => (
            "combat_stage",
            serde_json::json!({
                "from": t.from.map(|s| s.as_str()),
                "to": t.to.as_str(),
                "trigger": t.trigger.map(|x| x.as_str()),
                "offenders": t.offenders,
                "reason": t.reason,
            }),
            "success".to_string(),
        ),
        // Lab PR 217: `result` says whether the action achieved its
        // purpose — a failed kill or isolation is a `failure` row.
        Record::Outcome(o) => (
            "combat_outcome",
            serde_json::json!({
                "stage": o.stage.as_str(),
                "action": o.action,
                "trigger": o.trigger.map(|x| x.as_str()),
                "summary": o.summary,
                "detail": o.detail,
            }),
            if o.success {
                "success".to_string()
            } else {
                format!("failure: {}", o.summary)
            },
        ),
    };
    if let Some(at) = deferred {
        extra["deferred"] = serde_json::Value::Bool(true);
        extra["occurred_at"] = serde_json::Value::String(at.to_string());
    }
    if lost > 0 {
        extra["transitions_lost"] = serde_json::Value::from(lost);
    }
    AuditEntryDraft {
        op: op.to_string(),
        extra,
        // Agent-internal transition: not an admin-signed op, but
        // signed by the agent's audit key like every other entry.
        // A sentinel key_fp marks it as agent-originated, not a
        // human admin key fingerprint.
        key_fp: "agent-self".to_string(),
        cosigner_fps: Vec::new(),
        result,
        client_pid: std::process::id(),
        client_uid: 0,
        client_comm: "northnarrow-agent".to_string(),
        client_exe: None,
    }
}

impl AuditEvidence {
    /// Append `r`, after what waits; queued when the log refuses it.
    fn append(&self, r: Record) -> Result<(), Unrecorded> {
        let Some(log) = &self.audit_log else {
            self.unrecorded.fetch_add(1, Ordering::Relaxed);
            return Err(Unrecorded::NoAuditLog);
        };
        let occurred_at = crate::audit::format_ts(chrono::Utc::now());
        let mut backlog = self.backlog.lock();
        let mut guard = log.lock();
        // In order: what waits goes first; while it cannot, this one waits
        // behind it.
        let res = match self.drain(&mut backlog, &mut guard) {
            Err(e) => Err(e),
            Ok(()) => guard
                .append(draft(&r, None, backlog.lost_unsaid))
                .map(|_| backlog.lost_unsaid = 0)
                .map_err(|e| format!("{e:#}")),
        };
        drop(guard);
        res.map_err(|error| {
            self.unrecorded.fetch_add(1, Ordering::Relaxed);
            let waiting = self.enqueue(&mut backlog, &r, occurred_at);
            Unrecorded::Queued { error, waiting }
        })
    }
}

impl LadderEvidence for AuditEvidence {
    fn record_stage(&self, t: &StageTransition) -> Result<(), Unrecorded> {
        info!(
            target: "combat.audit",
            from = t.from.map(|s| s.as_str()).unwrap_or("-"),
            to = %t.to,
            trigger = ?t.trigger,
            offenders = ?t.offenders,
            reason = %t.reason,
            "COMBAT stage transition (signed audit entry)"
        );
        self.append(Record::Stage(t.clone()))
    }

    fn record_outcome(&self, o: &ActionOutcome) -> Result<(), Unrecorded> {
        info!(
            target: "combat.audit",
            stage = %o.stage,
            action = o.action,
            success = o.success,
            summary = %common::log_escape::Escaped(&o.summary),
            "COMBAT action outcome (signed audit entry)"
        );
        self.append(Record::Outcome(o.clone()))
    }

    fn retry_pending(&self) {
        let Some(log) = &self.audit_log else {
            return;
        };
        let mut backlog = self.backlog.lock();
        if backlog.waiting.is_empty() {
            return;
        }
        let mut guard = log.lock();
        if let Err(e) = self.drain(&mut backlog, &mut guard) {
            warn!(
                target: "combat.audit",
                error = %e,
                waiting = backlog.waiting.len(),
                "COMBAT stage transitions still not in the audit log — retried at the next append"
            );
        }
    }

    fn counts(&self) -> EvidenceCounts {
        EvidenceCounts {
            unrecorded: self.unrecorded.load(Ordering::Relaxed),
            pending: self.pending.load(Ordering::Relaxed),
            dropped: self.dropped.load(Ordering::Relaxed),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::{Path, PathBuf};

    fn transition(to: CombatStage, reason: &str) -> StageTransition {
        StageTransition {
            from: None,
            to,
            trigger: None,
            offenders: vec![4242],
            reason: reason.to_string(),
        }
    }

    struct Lab {
        _dir: tempfile::TempDir,
        path: PathBuf,
        away: PathBuf,
        pubkey: ed25519_dalek::VerifyingKey,
        log: Arc<Mutex<AuditLog>>,
    }

    impl Lab {
        fn new() -> Self {
            let dir = tempfile::TempDir::new().unwrap();
            let path = dir.path().join("audit.log");
            let key =
                crate::audit::AgentSigningKey::load_or_bootstrap(&dir.path().join("k")).unwrap();
            let pubkey = key.verifying_key();
            let log = Arc::new(Mutex::new(AuditLog::open(&path, key, [0u8; 16]).unwrap()));
            Self {
                away: dir.path().join("audit.log.away"),
                _dir: dir,
                path,
                pubkey,
                log,
            }
        }

        /// Appends fail (the file is a directory: EISDIR, root included).
        fn fail(&self) {
            if self.path.exists() {
                std::fs::rename(&self.path, &self.away).unwrap();
            }
            std::fs::create_dir(&self.path).unwrap();
        }

        fn recover(&self) {
            std::fs::remove_dir(&self.path).unwrap();
            if self.away.exists() {
                std::fs::rename(&self.away, &self.path).unwrap();
            }
        }

        /// The `combat_stage` rows, after the whole chain verified.
        fn stages(&self) -> Vec<crate::audit::AuditEntry> {
            let all = rows(&self.path);
            crate::audit::verify_chain(&all, &self.pubkey).expect("the chain verifies");
            all.into_iter().filter(|e| e.op == "combat_stage").collect()
        }
    }

    fn rows(path: &Path) -> Vec<crate::audit::AuditEntry> {
        std::fs::read_to_string(path)
            .unwrap_or_default()
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect()
    }

    fn reasons(rows: &[crate::audit::AuditEntry]) -> Vec<String> {
        rows.iter()
            .map(|e| e.extra["reason"].as_str().unwrap().to_string())
            .collect()
    }

    /// External audit CMB-027: a refused transition is reported, queued,
    /// and written before the next one, once, with the time it happened.
    #[test]
    fn a_refused_transition_is_written_late_in_order_with_its_time() {
        let lab = Lab::new();
        let ev = AuditEvidence::new(Some(Arc::clone(&lab.log)));
        ev.record_stage(&transition(CombatStage::Investigate, "t1"))
            .unwrap();
        lab.fail();
        let e2 = ev.record_stage(&transition(CombatStage::Neutralize, "t2"));
        assert!(
            matches!(&e2, Err(Unrecorded::Queued { waiting: 1, .. })),
            "{e2:?}"
        );
        let e3 = ev.record_stage(&transition(CombatStage::Isolate, "t3"));
        assert!(
            matches!(&e3, Err(Unrecorded::Queued { waiting: 2, .. })),
            "{e3:?}"
        );
        assert_eq!(
            ev.counts(),
            EvidenceCounts {
                unrecorded: 2,
                pending: 2,
                dropped: 0
            }
        );
        lab.recover();
        ev.record_stage(&transition(CombatStage::Isolate, "t4"))
            .unwrap();
        let rows = lab.stages();
        assert_eq!(reasons(&rows), ["t1", "t2", "t3", "t4"]);
        for (i, e) in rows.iter().enumerate() {
            let deferred = i == 1 || i == 2;
            assert_eq!(e.extra.get("deferred").is_some(), deferred, "{e:?}");
            assert_eq!(e.extra.get("occurred_at").is_some(), deferred, "{e:?}");
        }
        assert!(rows[1].extra["occurred_at"].as_str().unwrap() <= rows[1].ts.as_str());
        assert_eq!(
            ev.counts(),
            EvidenceCounts {
                unrecorded: 2,
                pending: 0,
                dropped: 0
            }
        );
        // Nothing waits: a retry writes nothing more.
        ev.retry_pending();
        assert_eq!(lab.stages().len(), 4);
    }

    /// The stand-down's retry writes what waits without a new transition;
    /// while the log still fails, the queue keeps it.
    #[test]
    fn retry_pending_writes_what_waits() {
        let lab = Lab::new();
        let ev = AuditEvidence::new(Some(Arc::clone(&lab.log)));
        lab.fail();
        assert!(ev
            .record_stage(&transition(CombatStage::Investigate, "t1"))
            .is_err());
        ev.retry_pending();
        assert_eq!(ev.counts().pending, 1);
        lab.recover();
        ev.retry_pending();
        assert_eq!(ev.counts().pending, 0);
        let rows = lab.stages();
        assert_eq!(reasons(&rows), ["t1"]);
        assert_eq!(rows[0].extra["deferred"], true);
    }

    /// A full queue drops its oldest, counts it, and the next entry
    /// written says how many were lost.
    #[test]
    fn a_full_queue_drops_the_oldest_and_says_so() {
        let lab = Lab::new();
        let ev = AuditEvidence::new(Some(Arc::clone(&lab.log)));
        lab.fail();
        let n = RETRY_QUEUE_DEPTH + 2;
        for i in 0..n {
            let r = ev.record_stage(&transition(CombatStage::Investigate, &format!("t{i}")));
            assert!(r.is_err());
        }
        assert_eq!(
            ev.counts(),
            EvidenceCounts {
                unrecorded: n as u64,
                pending: RETRY_QUEUE_DEPTH as u64,
                dropped: 2
            }
        );
        lab.recover();
        ev.retry_pending();
        let rows = lab.stages();
        assert_eq!(rows.len(), RETRY_QUEUE_DEPTH);
        assert_eq!(rows[0].extra["reason"], "t2", "t0 and t1 dropped");
        assert_eq!(rows[0].extra["transitions_lost"], 2);
        assert!(rows[1].extra.get("transitions_lost").is_none());
    }

    /// Lab PR 217 (capability C17): an action's outcome is a signed row of
    /// its own, `failure` when the action did not achieve its purpose, and
    /// it waits behind the transitions the log refused, in order.
    #[test]
    fn an_action_outcome_is_signed_with_its_result() {
        let lab = Lab::new();
        let ev = AuditEvidence::new(Some(Arc::clone(&lab.log)));
        let outcome = |success: bool| ActionOutcome {
            stage: CombatStage::Isolate,
            action: "isolate",
            trigger: None,
            success,
            summary: if success {
                "attempt 1 of 3: IPv4: isolated; IPv6: isolated".to_string()
            } else {
                "attempt 1 of 3: IPv4: FAILED (iptables-restore exited 4)".to_string()
            },
            detail: serde_json::json!({ "attempt": 1 }),
        };
        ev.record_stage(&transition(CombatStage::Isolate, "t1"))
            .unwrap();
        lab.fail();
        assert!(ev.record_outcome(&outcome(false)).is_err());
        lab.recover();
        ev.record_outcome(&outcome(true)).unwrap();
        let all = rows(&lab.path);
        crate::audit::verify_chain(&all, &lab.pubkey).expect("the chain verifies");
        let outcomes: Vec<_> = all.iter().filter(|e| e.op == "combat_outcome").collect();
        assert_eq!(outcomes.len(), 2);
        assert!(
            outcomes[0]
                .result
                .starts_with("failure: attempt 1 of 3: IPv4: FAILED"),
            "{}",
            outcomes[0].result
        );
        assert_eq!(outcomes[0].extra["deferred"], true);
        assert_eq!(outcomes[0].extra["stage"], "ISOLATE");
        assert_eq!(outcomes[0].extra["detail"]["attempt"], 1);
        assert_eq!(outcomes[1].result, "success");
        assert_eq!(outcomes[1].key_fp, "agent-self");
    }

    /// Without an audit log every transition is unrecorded — and said so.
    #[test]
    fn no_audit_log_is_unrecorded() {
        let ev = AuditEvidence::new(None);
        assert_eq!(
            ev.record_stage(&transition(CombatStage::Isolate, "t")),
            Err(Unrecorded::NoAuditLog)
        );
        ev.retry_pending();
        assert_eq!(
            ev.counts(),
            EvidenceCounts {
                unrecorded: 1,
                pending: 0,
                dropped: 0
            }
        );
    }
}
