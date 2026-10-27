//! The tests of the ladder's signed evidence (`AuditEvidence`), which
//! sign with the agent's key into the agent's audit log (R08c, lab PR 252):
//! cut verbatim from `combat/evidence.rs` when it moved to nn-core.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use parking_lot::Mutex;

use super::evidence::RETRY_QUEUE_DEPTH;
use super::{
    ActionOutcome, AuditEvidence, CombatStage, EvidenceCounts, LadderEvidence, StageTransition,
    Unrecorded,
};
use crate::audit::AuditLog;

fn transition(to: CombatStage, reason: &str) -> StageTransition {
    StageTransition {
        from: None,
        to,
        cause: None,
        offenders: vec![4242],
        details: Vec::new(),
        added: None,
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
        Self::stamped(crate::audit::AuditStamps::host())
    }

    /// Lab PR 249: the log stamping its rows with `stamps`.
    fn stamped(stamps: crate::audit::AuditStamps) -> Self {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("audit.log");
        let key = crate::audit::AgentSigningKey::load_or_bootstrap(&dir.path().join("k")).unwrap();
        let pubkey = key.verifying_key();
        let log = Arc::new(Mutex::new(
            AuditLog::open_with(&path, key, [0u8; 16], stamps).unwrap(),
        ));
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

/// Lab PR 249: a clock that stays where it is put.
struct Held(Mutex<chrono::DateTime<chrono::Utc>>);

impl nn_evidence::clock::Clock for Held {
    fn now(&self) -> chrono::DateTime<chrono::Utc> {
        *self.0.lock()
    }
}

/// Lab PR 249: the rows name the log's pid (`AuditLog::self_pid`) and a
/// refused transition the time of the evidence's clock: with the
/// replay's clock and pid given to both, a row written late says when
/// the transition happened (`occurred_at`) and when it was written
/// (`ts`), each the clock's, and every row names the replayed agent.
#[test]
fn a_late_row_names_the_clocks_times_and_the_logs_pid() {
    let at = |s: &str| {
        chrono::DateTime::parse_from_rfc3339(s)
            .unwrap()
            .with_timezone(&chrono::Utc)
    };
    let clock = Arc::new(Held(Mutex::new(at("2026-01-01T00:05:02Z"))));
    let lab = Lab::stamped(crate::audit::AuditStamps {
        clock: clock.clone(),
        self_pid: 4_200_000,
    });
    let ev = AuditEvidence::new(Some(Arc::clone(&lab.log))).with_clock(clock.clone());
    lab.fail();
    assert!(ev
        .record_stage(&transition(CombatStage::Investigate, "t1"))
        .is_err());
    *clock.0.lock() = at("2026-01-01T00:05:40Z");
    lab.recover();
    ev.record_stage(&transition(CombatStage::Neutralize, "t2"))
        .unwrap();
    let rows = lab.stages();
    assert_eq!(reasons(&rows), ["t1", "t2"]);
    assert_eq!(rows[0].extra["occurred_at"], "2026-01-01T00:05:02.000000Z");
    assert_eq!(rows[0].ts, "2026-01-01T00:05:40.000000Z");
    assert_eq!(rows[1].ts, "2026-01-01T00:05:40.000000Z");
    assert!(rows.iter().all(|e| e.client_pid == 4_200_000), "{rows:?}");
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
