//! Lot 379 (pre-alpha Phase 7, F7-1): `nn-admin integrity acknowledge` —
//! the operator's signed acknowledgement of the integrity findings
//! `nn-admin status` holds ([`nn_evidence::held`]).
//!
//! The handler checks the request against what the audit log holds; the
//! acknowledgement itself is the request's signed audit row
//! (`integrity_acknowledged`, `through_row`, the operator's note, the key's
//! fingerprint), which the audit log reads as the end of the holds it
//! covers — at once, and at every later open. A refused request's row says
//! `failure` and ends nothing.

use std::sync::Arc;

use parking_lot::Mutex;
use tracing::{info, warn};

use nn_proto::admin_protocol::{
    AdminResult, IntegrityAcknowledgeRequest, IntegrityAcknowledgeResponse,
};
use nn_proto::admin_signed_payload::INTEGRITY_ACK_NOTE_MAX;

use crate::admin::verify::{signed, Verified};
use crate::anti_tamper::admin_auth::ConnAuth;
use crate::audit::AuditLog;

/// `nn-admin integrity acknowledge --through <row>`: `triage` or
/// `config-manage`, 1-of-N.
pub(in crate::admin) fn dispatch_integrity_acknowledge(
    req: IntegrityAcknowledgeRequest,
    auth: &ConnAuth<'_>,
    audit_log: Option<&Arc<Mutex<AuditLog>>>,
    fps_out: &mut Vec<String>,
) -> IntegrityAcknowledgeResponse {
    let refuse = |result: AdminResult, message: String| IntegrityAcknowledgeResponse {
        result,
        acknowledged: 0,
        still_held: 0,
        message,
    };
    signed(
        &req,
        auth,
        fps_out,
        |r| refuse(r, String::new()),
        |v| acknowledge(v, audit_log, refuse),
    )
}

/// What an acknowledgement through `through` would end in `held`, when
/// the log holds `rows` rows: `Ok((covered, still held))`, or why it is
/// refused — a row the log does not hold yet (an acknowledgement of the
/// future would end findings nobody saw), or one that covers nothing.
pub(crate) fn judge(
    held: &nn_evidence::held::Held,
    rows: u64,
    through: u64,
) -> Result<(u64, u64), String> {
    if through >= rows {
        return Err(format!(
            "audit row {through} is not in the audit log (its newest row is {}): an \
             acknowledgement covers only rows already signed",
            rows.saturating_sub(1)
        ));
    }
    let total = held.findings().len() as u64 + held.more();
    let covered = held.covered_by(through);
    if covered == 0 {
        return Err(match held.newest_row() {
            None => "nothing is held: no integrity finding to acknowledge".to_string(),
            Some(newest) => format!(
                "no held finding has its newest row at or before audit row {through} (the \
                 newest held row is {newest})"
            ),
        });
    }
    Ok((covered, total - covered))
}

fn acknowledge(
    v: Verified<'_, IntegrityAcknowledgeRequest>,
    audit_log: Option<&Arc<Mutex<AuditLog>>>,
    refuse: impl Fn(AdminResult, String) -> IntegrityAcknowledgeResponse,
) -> IntegrityAcknowledgeResponse {
    let extra = v.extra();
    if extra.note.len() > INTEGRITY_ACK_NOTE_MAX {
        return refuse(
            AdminResult::Success,
            format!("the note is longer than {INTEGRITY_ACK_NOTE_MAX} bytes"),
        );
    }
    let Some(log) = audit_log else {
        warn!("integrity acknowledge: the agent runs without its audit log");
        return refuse(
            AdminResult::UnknownOperation,
            "the agent runs without its signed audit log: nothing is held".to_string(),
        );
    };
    let (rows, judged) = {
        let log = log.lock();
        (log.rows(), judge(log.held(), log.rows(), extra.through_row))
    };
    match judged {
        Err(why) => refuse(AdminResult::Success, why),
        Ok((covered, still)) => {
            info!(
                through_row = extra.through_row,
                acknowledged = covered,
                still_held = still,
                rows,
                "integrity acknowledge: held findings acknowledged (signed in the audit log)"
            );
            IntegrityAcknowledgeResponse {
                result: AdminResult::Success,
                acknowledged: covered,
                still_held: still,
                message: format!(
                    "{covered} held integrity finding(s) acknowledged through audit row {}; \
                     {still} still held; their rows stay in the chain",
                    extra.through_row
                ),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::AuditEntryDraft;

    fn drift(log: &mut AuditLog, kind: &str, detail: &str) -> u64 {
        log.append(AuditEntryDraft {
            op: crate::audit::INTEGRITY_DRIFT_OP.to_string(),
            extra: serde_json::json!({ "kind": kind, "detail": detail }),
            key_fp: "agent-self".to_string(),
            cosigner_fps: Vec::new(),
            result: "detected".to_string(),
            client_pid: 1,
            client_uid: 0,
            client_comm: "northnarrow-agent".to_string(),
            client_exe: None,
        })
        .unwrap();
        log.rows() - 1
    }

    /// Lot 379: an acknowledgement is refused for a row not signed yet
    /// (it would end what nobody saw) and when it covers nothing; else it
    /// says what it covers and what stays held.
    #[test]
    fn an_acknowledgement_covers_only_signed_rows_that_hold() {
        let dir = tempfile::tempdir().unwrap();
        let key = crate::audit::AgentSigningKey::load_or_bootstrap(&dir.path().join("k")).unwrap();
        let mut log = AuditLog::open(&dir.path().join("audit.log"), key, [1; 16]).unwrap();
        let none = judge(log.held(), log.rows(), 0).unwrap_err();
        assert!(none.contains("is not in the audit log"), "{none}");
        log.append(AuditEntryDraft {
            op: "unlock".to_string(),
            extra: serde_json::json!({}),
            key_fp: "x".to_string(),
            cosigner_fps: Vec::new(),
            result: "success".to_string(),
            client_pid: 1,
            client_uid: 0,
            client_comm: "nn-admin".to_string(),
            client_exe: None,
        })
        .unwrap();
        let nothing = judge(log.held(), log.rows(), 0).unwrap_err();
        assert!(nothing.contains("nothing is held"), "{nothing}");
        let first = drift(&mut log, "unauthorized_overlay", "a.local");
        let second = drift(&mut log, "default_list_modified", "fim-paths");
        let early = judge(log.held(), log.rows(), first - 1).unwrap_err();
        assert!(
            early.contains(&format!("the newest held row is {second}")),
            "{early}"
        );
        assert_eq!(judge(log.held(), log.rows(), first), Ok((1, 1)));
        assert_eq!(judge(log.held(), log.rows(), second), Ok((2, 0)));
        let future = judge(log.held(), log.rows(), second + 1).unwrap_err();
        assert!(future.contains("is not in the audit log"), "{future}");
    }
}
