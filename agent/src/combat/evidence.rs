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
//! ## Phase 3 (next): multi-sink dossier
//!
//! [`LadderEvidence`] is the seam the Panopticon work plugs into: a
//! richer implementation will, in addition to this audit entry, assemble
//! a `DossierPayload` (focal event + correlation snapshot + tail-hashes
//! of the FIM / netflow / audit chains) and stream it to multiple sinks
//! (a local signed `RotatingChainLog`, the journal, and an optional
//! remote uplink) so it survives even STAGE-3 isolation. The audit entry
//! emitted here is the spine that the dossier cross-references.

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

/// Records a ladder stage transition. Implementations MUST NOT block the
/// ladder on failure — a sink error is logged, never propagated.
pub trait LadderEvidence: Send + Sync {
    fn record_stage(&self, transition: &StageTransition);
}

/// Production evidence sink: writes each stage transition as a signed,
/// hash-chained entry in the agent audit log. `None` audit log (open
/// failed at boot, or a dev build without one) degrades to a structured
/// log line only — the ladder still functions, just unaudited, mirroring
/// how `main.rs` already handles an absent audit log for admin ops.
pub struct AuditEvidence {
    audit_log: Option<Arc<Mutex<AuditLog>>>,
}

impl AuditEvidence {
    pub fn new(audit_log: Option<Arc<Mutex<AuditLog>>>) -> Self {
        Self { audit_log }
    }
}

impl LadderEvidence for AuditEvidence {
    fn record_stage(&self, t: &StageTransition) {
        info!(
            target: "combat.audit",
            from = t.from.map(|s| s.as_str()).unwrap_or("-"),
            to = %t.to,
            trigger = ?t.trigger,
            offenders = ?t.offenders,
            reason = %t.reason,
            "COMBAT stage transition (signed audit entry)"
        );

        let Some(log) = &self.audit_log else {
            return;
        };
        let draft = AuditEntryDraft {
            op: "combat_stage".to_string(),
            extra: serde_json::json!({
                "from": t.from.map(|s| s.as_str()),
                "to": t.to.as_str(),
                "trigger": t.trigger.map(|x| x.as_str()),
                "offenders": t.offenders,
                "reason": t.reason,
            }),
            // Agent-internal transition: not an admin-signed op, but
            // signed by the agent's audit key like every other entry.
            // A sentinel key_fp marks it as agent-originated, not a
            // human admin key fingerprint.
            key_fp: "agent-self".to_string(),
            cosigner_fps: Vec::new(),
            result: "success".to_string(),
            client_pid: std::process::id(),
            client_uid: 0,
            client_comm: "northnarrow-agent".to_string(),
        };
        let mut guard = log.lock();
        if let Err(e) = guard.append(draft) {
            warn!(
                target: "combat.audit",
                error = %e,
                stage = %t.to,
                "failed to append COMBAT stage transition to audit log"
            );
        }
    }
}
