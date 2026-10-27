//! The record of a stale COMBAT chain found at start (Beta Step 4a).
//!
//! The agent always boots into OBSERVING: a `NORTHNARROW_COMBAT` chain
//! present at start was left by a run that died mid-COMBAT, and it is torn
//! down before the audit log opens. External audit MAIN-013 (NN-AUD-255,
//! lab PR 180): that teardown used to be recorded only in
//! `combat-audit.jsonl`, the one unsigned evidence log (BUG-028), opened by
//! its literal path with the default mode. Now the outcome is kept until
//! the signed audit log is open and recorded there ([`attest`]: a signed
//! `integrity_drift`, kind `combat_reconcile`, also when the teardown
//! failed).
//!
//! R08c (lab PR 252): cut verbatim from the agent's `combat::reconcile`,
//! which re-exports it and keeps the compatibility line's Linux file I/O
//! (`append_line`, `record_line`: the anchored, `O_NOFOLLOW` open, the
//! mode, the state directory's dance) for nn-linux (R09). The audit log
//! is the agent's, signed by the key it was opened with.

use std::sync::Arc;

use nn_evidence::chain_host::ChainSigner;
use parking_lot::Mutex;
use tracing::warn;

use crate::audit::{AuditEntryDraft, AuditLog};

/// What the start-time reconcile did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StaleChain {
    /// The chain(s) were present and torn down.
    TornDown { rules_removed: usize },
    /// The chain is (or may still be) present: the probe or the teardown
    /// failed.
    Failed { error: String },
}

/// The signed entry for `outcome` (`integrity_drift`, kind
/// `combat_reconcile`, `at_boot`).
pub fn draft(outcome: &StaleChain) -> AuditEntryDraft {
    let (extra, result) = match outcome {
        StaleChain::TornDown { rules_removed } => (
            serde_json::json!({
                "kind": "combat_reconcile",
                "detail": format!(
                    "a NORTHNARROW_COMBAT chain left by an earlier run (killed or crashed in \
                     COMBAT) was found at start and torn down: {rules_removed} rules removed; \
                     the host is no longer isolated by it"
                ),
                "rules_torn_down": rules_removed,
                "at_boot": true,
            }),
            "repaired",
        ),
        StaleChain::Failed { error } => (
            serde_json::json!({
                "kind": "combat_reconcile",
                "detail": format!(
                    "a NORTHNARROW_COMBAT chain left by an earlier run could not be checked or \
                     torn down at start ({error}): the host may still be isolated by it — \
                     see docs/operator/COMBAT_RECOVERY.md"
                ),
                "at_boot": true,
            }),
            "failed",
        ),
    };
    AuditEntryDraft {
        op: crate::audit::INTEGRITY_DRIFT_OP.to_string(),
        extra,
        key_fp: "agent-self".to_string(),
        cosigner_fps: Vec::new(),
        result: result.to_string(),
        client_pid: std::process::id(),
        client_uid: 0,
        client_comm: "northnarrow-agent".to_string(),
        client_exe: None,
    }
}

/// Record `outcome` in the signed audit log (once it is open). Without a
/// log the journal keeps the WARN the reconcile logged.
pub fn attest<K: ChainSigner>(audit_log: Option<&Arc<Mutex<AuditLog<K>>>>, outcome: &StaleChain) {
    let Some(log) = audit_log else {
        return;
    };
    if let Err(e) = log.lock().append(draft(outcome)) {
        warn!(
            error = format!("{e:#}"),
            "recording the COMBAT reconcile in the audit log failed"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_signed_entry_names_the_outcome() {
        let d = draft(&StaleChain::TornDown { rules_removed: 7 });
        assert_eq!(d.op, "integrity_drift");
        assert_eq!(d.result, "repaired");
        assert_eq!(d.extra["kind"], "combat_reconcile");
        assert_eq!(d.extra["rules_torn_down"], 7);
        assert_eq!(d.extra["at_boot"], true);
        let d = draft(&StaleChain::Failed {
            error: "iptables: exit 4".to_string(),
        });
        assert_eq!(d.result, "failed");
        assert!(d.extra["detail"]
            .as_str()
            .unwrap()
            .contains("iptables: exit 4"));
    }
}
