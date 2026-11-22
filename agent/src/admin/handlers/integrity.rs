//! Lot 379 (pre-alpha Phase 7, F7-1): `nn-admin integrity acknowledge` —
//! the operator's signed acknowledgement of the integrity findings
//! `nn-admin status` holds ([`nn_evidence::held`]).
//!
//! The handler checks the request against what the audit log holds; the
//! acknowledgement itself is the request's signed audit row
//! (`integrity_acknowledged`, `through_row`, the operator's note, the key's
//! fingerprint), which the audit log reads as the end of the holds it
//! covers — at once, and at every later open. A refused request's row says
//! `failure` and ends nothing. The review of #586 (P3-1): the handler
//! appends that row itself, under the lock its judgement was made under,
//! and answers from the append — a row not written acknowledges nothing,
//! and the counts are the log's, not a guess made before it.

use std::sync::Arc;

use parking_lot::Mutex;
use tracing::{info, warn};

use nn_proto::admin_protocol::{
    AdminResult, IntegrityAcknowledgeRequest, IntegrityAcknowledgeResponse,
};
use nn_proto::admin_signed_payload::INTEGRITY_ACK_NOTE_MAX;

use crate::admin::verify::{signed, Verified};
use crate::admin::AuditClient;
use crate::anti_tamper::admin_auth::ConnAuth;
use crate::audit::AuditLog;

/// `nn-admin integrity acknowledge --through <row>`: `triage` or
/// `config-manage`, 1-of-N.
pub(in crate::admin) fn dispatch_integrity_acknowledge(
    req: IntegrityAcknowledgeRequest,
    auth: &ConnAuth<'_>,
    audit_log: Option<&Arc<Mutex<AuditLog>>>,
    client: &AuditClient,
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
        |v| acknowledge(v, audit_log, client, refuse),
    )
}

/// What an acknowledgement through `through` with a note of `note_len`
/// bytes would end in `held`, when the log holds `rows` rows: `Ok((covered,
/// still held))`, or why it is refused — a note past its bound (a client
/// other than `nn-admin`, which refuses it first), a row the log does not
/// hold yet (an acknowledgement of the future would end findings nobody
/// saw), or one that covers nothing.
pub(crate) fn judge(
    held: &nn_evidence::held::Held,
    rows: u64,
    through: u64,
    note_len: usize,
) -> Result<(u64, u64), String> {
    if note_len > INTEGRITY_ACK_NOTE_MAX {
        return Err(format!(
            "the note is longer than {INTEGRITY_ACK_NOTE_MAX} bytes"
        ));
    }
    if through >= rows {
        return Err(format!(
            "audit row {through} is not in the audit log (its newest row is {}): an \
             acknowledgement covers only rows already signed",
            rows.saturating_sub(1)
        ));
    }
    let total = held.count();
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
    client: &AuditClient,
    refuse: impl Fn(AdminResult, String) -> IntegrityAcknowledgeResponse,
) -> IntegrityAcknowledgeResponse {
    let extra = v.extra();
    let Some(log) = audit_log else {
        warn!("integrity acknowledge: the agent runs without its audit log");
        return refuse(
            AdminResult::UnknownOperation,
            "the agent runs without its signed audit log: nothing is held".to_string(),
        );
    };
    let mut log = log.lock();
    let rows = log.rows();
    let (covered, still) = match judge(log.held(), rows, extra.through_row, extra.note.len()) {
        Err(why) => return refuse(AdminResult::Success, why),
        Ok(judged) => judged,
    };
    let held_before = log.held().count();
    let message = format!(
        "{covered} held integrity finding(s) acknowledged through audit row {}; {still} still \
         held; their rows stay in the chain",
        extra.through_row
    );
    let row = crate::admin::audit::admin_row(
        nn_evidence::held::ACK_OP,
        serde_json::json!({
            "through_row": extra.through_row,
            "note": extra.note,
            "acknowledged": covered,
            "still_held": still,
            "detail": message,
        }),
        "success".to_string(),
        client,
        v.fingerprints(),
        v.request().signatures.len().saturating_sub(1),
    );
    // the acknowledgement is this row: not written, nothing acknowledged
    if let Err(e) = log.append(row) {
        warn!(
            through_row = extra.through_row,
            error = %format!("{e:#}"),
            "integrity acknowledge: its signed row was not written — nothing acknowledged"
        );
        return refuse(
            AdminResult::Success,
            format!(
                "the acknowledgement's signed audit row was not written ({e:#}): nothing is \
                 acknowledged, {held_before} finding(s) still held"
            ),
        );
    }
    // what the row ended, as the log now holds it
    let still = log.held().count();
    let acknowledged = held_before.saturating_sub(still);
    info!(
        through_row = extra.through_row,
        acknowledged,
        still_held = still,
        rows,
        "integrity acknowledge: held findings acknowledged (signed in the audit log)"
    );
    IntegrityAcknowledgeResponse {
        result: AdminResult::Success,
        acknowledged,
        still_held: still,
        message: format!(
            "{acknowledged} held integrity finding(s) acknowledged through audit row {}; {still} \
             still held; their rows stay in the chain",
            extra.through_row
        ),
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
        let none = judge(log.held(), log.rows(), 0, 0).unwrap_err();
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
        let nothing = judge(log.held(), log.rows(), 0, 0).unwrap_err();
        assert!(nothing.contains("nothing is held"), "{nothing}");
        let first = drift(&mut log, "unauthorized_overlay", "a.local");
        let second = drift(&mut log, "default_list_modified", "fim-paths");
        let early = judge(log.held(), log.rows(), first - 1, 0).unwrap_err();
        assert!(
            early.contains(&format!("the newest held row is {second}")),
            "{early}"
        );
        assert_eq!(judge(log.held(), log.rows(), first, 0), Ok((1, 1)));
        assert_eq!(judge(log.held(), log.rows(), second, 0), Ok((2, 0)));
        let future = judge(log.held(), log.rows(), second + 1, 0).unwrap_err();
        assert!(future.contains("is not in the audit log"), "{future}");
        // the note's bound: at it accepted, past it refused
        assert_eq!(
            judge(log.held(), log.rows(), second, INTEGRITY_ACK_NOTE_MAX),
            Ok((2, 0))
        );
        let long = judge(log.held(), log.rows(), second, INTEGRITY_ACK_NOTE_MAX + 1).unwrap_err();
        assert!(long.contains("note is longer"), "{long}");
    }

    /// Lot 384 (pre-alpha Phase 3c, F3c-1): past the 16 findings listed, an
    /// acknowledgement covers every row counted at or before its own, and
    /// says so — on main one through the second of three counted rows
    /// covered none of them ("16 acknowledged, 3 still held").
    #[test]
    fn an_acknowledgement_past_the_cap_covers_the_counted_rows_before_it() {
        use nn_evidence::held::MAX_HELD;
        let dir = tempfile::tempdir().unwrap();
        let key = crate::audit::AgentSigningKey::load_or_bootstrap(&dir.path().join("k")).unwrap();
        let mut log = AuditLog::open(&dir.path().join("audit.log"), key, [1; 16]).unwrap();
        let rows: Vec<u64> = (0..MAX_HELD + 3)
            .map(|i| drift(&mut log, "witness_row", &format!("role_vacated {i}")))
            .collect();
        let counted = &rows[MAX_HELD..];
        let total = MAX_HELD as u64 + 3;
        assert_eq!(
            judge(log.held(), log.rows(), rows[MAX_HELD - 1], 0),
            Ok((MAX_HELD as u64, 3))
        );
        assert_eq!(
            judge(log.held(), log.rows(), counted[1], 0),
            Ok((total - 1, 1))
        );
        assert_eq!(judge(log.held(), log.rows(), counted[2], 0), Ok((total, 0)));
        assert_eq!(log.held().newest_row(), Some(counted[2]));
    }
}
