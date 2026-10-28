//! The signed audit row of each admin request (R11d, lab PR 263: from
//! `admin_socket.rs`): who connected, what was asked and what was
//! answered, as design §9.1 records them.

use std::sync::Arc;

use parking_lot::Mutex;
use sha2::{Digest, Sha256};
use tracing::warn;

use nn_proto::admin_protocol::{AdminMessage, AdminResult, UnlockResult};
use nn_proto::admin_signed_payload::OperationExtra;

use crate::audit::{AuditEntryDraft, AuditLog};

/// A row the agent writes from one admin frame fits the line caps of the
/// chain readers: the operator's strings come from one signed frame of at
/// most `MAX_FRAME_BODY`, a JSON escape is at most six bytes for one, and
/// the rest of a row is bounded (hashes, signature, ids, a `PATH_MAX`
/// executable). The caps are the readers' (`verify_lines`, the canary
/// chains' `chain_lines`), the frame bound the admin protocol's; the agent,
/// which writes the rows and sees both, holds the two to each other.
/// R04a (lab PR 241): these assertions were in `verify_lines` and
/// `canary::chain_lines`, the only names of the admin protocol in the
/// evidence code (nn-evidence and nn-proto are siblings, plan §2.1).
const _: () = assert!(
    crate::verify_lines::MAX_VERIFY_LINE_BYTES
        >= 6 * (nn_proto::admin_protocol::MAX_FRAME_BODY + 4096) + 64 * 1024,
    "a row the agent can write must fit the verifiers' line cap"
);
const _: () = assert!(
    crate::canary::chain_lines::MAX_CHAIN_LINE_BYTES
        >= 6 * (nn_proto::admin_protocol::MAX_FRAME_BODY + 4096) + 64 * 1024,
    "a row the agent can write must fit the chain line cap"
);

// ── Tappa 8 B5 — SO_PEERCRED + audit-log emission ─────────────────

/// Who connected, as the audit log records it: `(pid, uid)` from
/// `SO_PEERCRED`, `comm` and `exe` from `/proc/<pid>`. The audit log's
/// per-entry `client_*` fields (design §9.1) come from here so every
/// admin operation records WHO connected, not just which key signed.
#[derive(Debug, Clone)]
pub(crate) struct AuditClient {
    pub pid: u32,
    pub uid: u32,
    /// `/proc/<pid>/comm`. Self-reported (external audit ASK-013,
    /// NN-AUD-239): the name the peer gave itself, which any process
    /// chooses (`prctl(PR_SET_NAME)`). `<exited>` when the peer was gone
    /// before it could be read, `<unknown>` when it could not be read.
    pub comm: String,
    /// `/proc/<pid>/exe`: the program the kernel says the peer runs
    /// (external audit ASK-013). `None` when it could not be read.
    pub exe: Option<String>,
}

/// What a dispatcher learned that neither the request nor the reply
/// carries, for the audit row. Filled by `dispatch`, read by
/// [`emit_audit_for`]; next to the signers' fingerprints (`matched_fps`).
#[derive(Debug, Default)]
pub(super) struct DispatchNotes {
    /// External audit ASK-015: the posture a force-posture left, when the
    /// transition was applied (also a no-op to the same state). `None`
    /// when it was refused: the state did not change.
    pub(super) force_from: Option<nn_model::posture_types::PostureKind>,
    /// Lab PR 217: a force-posture out of COMBAT — what its release
    /// released, or why it did not (the posture then stayed COMBAT).
    pub(super) force_release: Option<std::result::Result<String, String>>,
}

/// Inspect the (request, reply) pair after `dispatch` returns
/// and append a single audit-log entry if the message was an
/// auditable admin operation (challenge/status are not
/// auditable — they're plumbing). On any audit failure, log
/// plus continue: the operator's authorised action MUST succeed
/// even if the audit log is temporarily unwritable (design §9
/// states "the entry is the receipt; the action is the action").
// PHASE_D_004: `matched_fps` is what the verification pipeline wrote
// (`verify::signed`, R11d) — empty for the legacy `Unlock` (refused since
// lab PR 217, verified by no one) and for failure paths, but the
// telemetry status refused for its roles (lab PR 213: the row names the
// key that tried); populated for every request the pipeline accepted,
// the signed unlock included (lab PR 217: its row names the signer).
pub(super) fn emit_audit_for(
    msg: &AdminMessage,
    reply: &AdminMessage,
    client: &AuditClient,
    audit_log: Option<&Arc<Mutex<AuditLog>>>,
    matched_fps: &[String],
    notes: &DispatchNotes,
) {
    let Some(audit_log) = audit_log else {
        return;
    };
    let (op, extra, result, cosigner_count) = match (msg, reply) {
        // Lab PR 217: refused (`failure: legacy_protocol_refused`) — the
        // row says which protocol was used.
        (AdminMessage::Unlock(_), AdminMessage::UnlockResult(r)) => (
            "unlock",
            serde_json::json!({ "protocol": "legacy" }),
            unlock_result_str(r),
            0,
        ),
        // Lab PR 217 (NN-AUD-243 residue, capability C17): `success` only
        // when the release was carried out and the tables read back clear;
        // a verified request whose teardown failed is a failure with why,
        // and the row names the signer (`key_fp`).
        (AdminMessage::SignedUnlockRequest(req), AdminMessage::SignedUnlockResponse(r)) => (
            "unlock",
            serde_json::json!({
                "protocol": "signed",
                "released": r.released,
                "isolation_v4": r.isolation_v4,
                "isolation_v6": r.isolation_v6,
                "detail": r.message,
            }),
            match r.result {
                AdminResult::Success if r.released => "success".to_string(),
                AdminResult::Success | AdminResult::ActionFailed => {
                    format!("failure: release_failed ({})", r.message)
                }
                other => audit_result_str(other),
            },
            req.signatures.len().saturating_sub(1),
        ),
        (AdminMessage::ShutdownRequest(req), AdminMessage::ShutdownResult(r)) => {
            let grace = match &req.payload.extra {
                OperationExtra::Shutdown(s) => s.grace_secs,
                _ => 0,
            };
            (
                "shutdown",
                serde_json::json!({ "grace_secs": grace }),
                audit_result_str(*r),
                req.signatures.len().saturating_sub(1),
            )
        }
        (AdminMessage::ForcePostureRequest(req), AdminMessage::ForcePostureResult(r)) => {
            let target = match &req.payload.extra {
                OperationExtra::ForcePosture(f) => format!("{:?}", f.target),
                _ => "?".to_string(),
            };
            // External audit ASK-015: the state left, when the force was
            // applied; a refused one changed nothing and has no `from`.
            let mut extra = serde_json::json!({ "target": target });
            if let Some(from) = notes.force_from {
                extra["from"] = serde_json::Value::String(format!("{from:?}"));
            }
            // Lab PR 217: leaving COMBAT released the containment — or did
            // not, and the posture stayed COMBAT.
            let result = match &notes.force_release {
                Some(Ok(released)) => {
                    extra["release"] = serde_json::Value::String(released.clone());
                    audit_result_str(*r)
                }
                Some(Err(why)) => {
                    extra["release"] = serde_json::Value::String(why.clone());
                    format!("failure: release_failed ({why})")
                }
                None => audit_result_str(*r),
            };
            (
                "force_posture",
                extra,
                result,
                req.signatures.len().saturating_sub(1),
            )
        }
        (AdminMessage::RotateKeysAddRequest(req), AdminMessage::RotateKeysAddResult(r)) => {
            let new_fp = match &req.payload.extra {
                OperationExtra::RotateKeysAdd(extra) => {
                    hex::encode(&Sha256::digest(extra.new_pubkey)[..4])
                }
                _ => String::new(),
            };
            (
                "rotate_keys_add",
                serde_json::json!({ "new_key_fp": new_fp }),
                audit_result_str(*r),
                req.signatures.len().saturating_sub(1),
            )
        }
        (AdminMessage::RotateKeysRevokeRequest(req), AdminMessage::RotateKeysRevokeResult(r)) => {
            let target_fp = match &req.payload.extra {
                OperationExtra::RotateKeysRevoke(extra) => hex::encode(extra.fingerprint),
                _ => String::new(),
            };
            (
                "rotate_keys_revoke",
                serde_json::json!({ "target_fp": target_fp }),
                audit_result_str(*r),
                req.signatures.len().saturating_sub(1),
            )
        }
        // C6: FIM admin ops. Both are 1-of-N so cosigner_count
        // is 0 (saturating_sub on a 1-element signatures vec).
        (AdminMessage::FimBaselineRequest(req), AdminMessage::FimBaselineResult(r)) => (
            "fim_baseline",
            serde_json::json!({}),
            audit_result_str(*r),
            req.signatures.len().saturating_sub(1),
        ),
        (AdminMessage::FimReportRequest(req), AdminMessage::FimReportResponse(resp)) => {
            let since = match &req.payload.extra {
                OperationExtra::FimReport(extra) => extra.since_unix_ts,
                _ => None,
            };
            (
                "fim_report",
                serde_json::json!({
                    "since_unix_ts": since,
                    "entries_count": resp.entries_count,
                    "truncated": resp.entries_truncated,
                }),
                audit_result_str(resp.result),
                req.signatures.len().saturating_sub(1),
            )
        }
        // C7: fim_status. Extra captures the snapshot counts so an
        // off-host audit reader can answer "at the moment the
        // operator ran status, what did the agent report?" without
        // needing a parallel time-series collector.
        (AdminMessage::FimStatusRequest(req), AdminMessage::FimStatusResponse(resp)) => (
            "fim_status",
            serde_json::json!({
                "watched_paths_count": resp.watched_paths_count,
                "disabled_default_count": resp.disabled_default_count,
                "added_path_count": resp.added_path_count,
                "baseline_entries_total": resp.baseline_entries_total,
                "drift_entries_total": resp.drift_entries_total,
            }),
            audit_result_str(resp.result),
            req.signatures.len().saturating_sub(1),
        ),
        // K6: 4 canary admin ops. Each row carries the canary_id
        // for the chain (deploy populates it from the response;
        // burn/refresh from the request's extra). Operator
        // `nn-admin audit read` greps by canary_id for the
        // lifecycle trail across the audit chain + the K2
        // registry chain.
        (AdminMessage::CanaryDeployRequest(req), AdminMessage::CanaryDeployResponse(resp)) => {
            let (name, family) = match &req.payload.extra {
                OperationExtra::CanaryDeploy(e) => {
                    let family = match &e.deployment {
                        nn_proto::admin_signed_payload::CanaryDeploymentWire::Credential {
                            cred_family,
                            ..
                        } => cred_family.clone(),
                        _ => String::new(),
                    };
                    (e.name.clone(), family)
                }
                _ => (String::new(), String::new()),
            };
            (
                "canary_deploy",
                serde_json::json!({
                    "name": name,
                    "canary_id": resp.canary_id,
                    "cred_family": family,
                }),
                audit_result_str(resp.result),
                req.signatures.len().saturating_sub(1),
            )
        }
        (AdminMessage::CanaryListRequest(req), AdminMessage::CanaryListResponse(resp)) => (
            "canary_list",
            serde_json::json!({
                "entries_count": resp.entries_count,
                "truncated": resp.entries_truncated,
            }),
            audit_result_str(resp.result),
            req.signatures.len().saturating_sub(1),
        ),
        (AdminMessage::CanaryBurnRequest(req), AdminMessage::CanaryBurnResult(r)) => {
            let canary_id = match &req.payload.extra {
                OperationExtra::CanaryBurn(e) => e.canary_id.clone(),
                _ => String::new(),
            };
            (
                "canary_burn",
                serde_json::json!({ "canary_id": canary_id }),
                audit_result_str(*r),
                req.signatures.len().saturating_sub(1),
            )
        }
        (AdminMessage::CanaryRefreshRequest(req), AdminMessage::CanaryRefreshResult(r)) => {
            let canary_id = match &req.payload.extra {
                OperationExtra::CanaryRefresh(e) => e.canary_id.clone(),
                _ => String::new(),
            };
            (
                "canary_refresh",
                serde_json::json!({ "canary_id": canary_id }),
                audit_result_str(*r),
                req.signatures.len().saturating_sub(1),
            )
        }
        // N7: 4 net admin ops. Each row carries the response
        // counters / qname slot so an off-host audit reader sees
        // the same "what did the operator just learn?" detail
        // that fim_report + fim_status capture for their domain.
        (AdminMessage::NetFlowsRequest(req), AdminMessage::NetFlowsResponse(resp)) => {
            use nn_proto::admin_signed_payload::NetFlowsExtra;
            let since = match &req.payload.extra {
                OperationExtra::NetFlows(NetFlowsExtra { since_unix_ts }) => *since_unix_ts,
                _ => None,
            };
            (
                "net_flows",
                serde_json::json!({
                    "since_unix_ts": since,
                    "entries_count": resp.entries_count,
                    "truncated": resp.entries_truncated,
                }),
                audit_result_str(resp.result),
                req.signatures.len().saturating_sub(1),
            )
        }
        (AdminMessage::NetListenersRequest(req), AdminMessage::NetListenersResponse(resp)) => (
            "net_listeners",
            serde_json::json!({
                "entries_count": resp.entries_count,
                "truncated": resp.entries_truncated,
            }),
            audit_result_str(resp.result),
            req.signatures.len().saturating_sub(1),
        ),
        (AdminMessage::NetResolveRequest(req), AdminMessage::NetResolveResponse(resp)) => {
            use nn_proto::admin_signed_payload::NetResolveExtra;
            let ip = match &req.payload.extra {
                OperationExtra::NetResolve(NetResolveExtra { ip }) => ip.clone(),
                _ => String::new(),
            };
            (
                "net_resolve",
                serde_json::json!({
                    "ip": ip,
                    "resolved": resp.qname.is_some(),
                }),
                audit_result_str(resp.result),
                req.signatures.len().saturating_sub(1),
            )
        }
        (AdminMessage::NetFingerprintRequest(req), AdminMessage::NetFingerprintResponse(resp)) => {
            use nn_proto::admin_signed_payload::NetFingerprintExtra;
            let flow_id = match &req.payload.extra {
                OperationExtra::NetFingerprint(NetFingerprintExtra { flow_id }) => flow_id.clone(),
                _ => String::new(),
            };
            (
                "net_fingerprint",
                serde_json::json!({
                    "flow_id": flow_id,
                    "entries_count": resp.entries_count,
                    "truncated": resp.entries_truncated,
                }),
                audit_result_str(resp.result),
                req.signatures.len().saturating_sub(1),
            )
        }
        // FIM-009 self-upgrade (§15.1) — the trusted-installer grant
        // ARM record (the close/expiry record is written by the
        // override itself, not on an admin op).
        (
            AdminMessage::TrustedInstallerGrantRequest(req),
            AdminMessage::TrustedInstallerGrantResult(r),
        ) => {
            let window = match &req.payload.extra {
                OperationExtra::TrustedInstallerGrant(e) => e.window_secs,
                _ => 0,
            };
            (
                "trusted_installer_grant",
                serde_json::json!({ "window_secs": window }),
                audit_result_str(*r),
                req.signatures.len().saturating_sub(1),
            )
        }
        // Tappa 10.8 — signed overlay store. `result` is `success` only when
        // the overlay and its signature were written: the boot check reads
        // these rows as the newest accepted signature per kind (rollback
        // guard), so a verified-but-refused request must not count.
        (AdminMessage::ConfigOverlaySetRequest(req), AdminMessage::ConfigOverlaySetResponse(r)) => {
            let (kind, sha, len) = match &req.payload.extra {
                OperationExtra::ConfigOverlaySet(e) => (
                    e.kind.keyword(),
                    e.sha256
                        .iter()
                        .map(|b| format!("{b:02x}"))
                        .collect::<String>(),
                    e.len,
                ),
                _ => ("unknown", String::new(), 0),
            };
            let result = if r.stored {
                "success".to_string()
            } else if r.result == AdminResult::Success {
                format!("failure: rejected ({})", r.message)
            } else {
                audit_result_str(r.result)
            };
            (
                crate::config::overlay_auth::AUDIT_OP_SET,
                serde_json::json!({
                    "kind": kind,
                    "sha256": sha,
                    "signed_ts": req.payload.ts,
                    "bytes": len,
                    "detail": r.message,
                }),
                result,
                req.signatures.len().saturating_sub(1),
            )
        }
        // Tappa 9.0.b — detections read. The extra captures the
        // operator's filters + the response counters so an off-host
        // audit reader sees exactly what was asked for and how much
        // was returned (mirrors the fim_report / net_flows rows).
        (AdminMessage::DetectionsRequest(req), AdminMessage::DetectionsResponse(resp)) => {
            let extra = match &req.payload.extra {
                OperationExtra::Detections(e) => serde_json::json!({
                    "limit": e.limit,
                    "since_unix_ts": e.since_unix_ts,
                    "until_unix_ts": e.until_unix_ts,
                    "min_severity": e.min_severity,
                    "status": e.status,
                    "sensor": e.sensor,
                    "path": e.path,
                    "entries_count": resp.entries_count,
                    "truncated": resp.entries_truncated,
                }),
                _ => serde_json::json!({}),
            };
            (
                "detections",
                extra,
                audit_result_str(resp.result),
                req.signatures.len().saturating_sub(1),
            )
        }
        // Tappa 9.0.c — detection triage status change. Records the
        // target id + new status + note + the auth result so an
        // off-host audit reader sees the full triage history (the
        // status-event chain is the data-of-record; this is the
        // who/when receipt alongside it).
        (
            AdminMessage::DetectionSetStatusRequest(req),
            AdminMessage::DetectionSetStatusResponse(resp),
        ) => {
            let extra = match &req.payload.extra {
                OperationExtra::DetectionSetStatus(e) => serde_json::json!({
                    "id": e.id,
                    "new_status": e.new_status,
                    "note": e.note,
                }),
                _ => serde_json::json!({}),
            };
            (
                "detection_set_status",
                extra,
                audit_result_str(resp.result),
                req.signatures.len().saturating_sub(1),
            )
        }
        // External audit CMB-016 — undoing a response. A verified request
        // that did nothing (no record of the pid, a refused destination)
        // is recorded with why, not as a success.
        (AdminMessage::ResponseStatusRequest(req), AdminMessage::ResponseStatusResponse(r)) => (
            "response_status",
            serde_json::json!({
                "contained_total": r.contained_total,
                "quarantined_total": r.quarantined_total,
                "combat_stage": r.combat_stage,
            }),
            audit_result_str(r.result),
            req.signatures.len().saturating_sub(1),
        ),
        (AdminMessage::ResponseReleaseRequest(req), AdminMessage::ResponseReleaseResponse(r)) => {
            let pid = match &req.payload.extra {
                OperationExtra::ResponseRelease(e) => Some(e.pid),
                _ => None,
            };
            (
                "response_release",
                serde_json::json!({ "pid": pid, "by": "admin", "detail": r.message }),
                verified_result_str(r.result, r.released, &r.message),
                req.signatures.len().saturating_sub(1),
            )
        }
        (AdminMessage::ResponseRestoreRequest(req), AdminMessage::ResponseRestoreResponse(r)) => {
            let (vault_id, to) = match &req.payload.extra {
                OperationExtra::ResponseRestore(e) => (e.vault_id.clone(), e.to.clone()),
                _ => (String::new(), None),
            };
            (
                "response_restore",
                serde_json::json!({
                    "vault_id": vault_id,
                    "to": to,
                    "path": r.path,
                    "detail": r.message,
                }),
                verified_result_str(r.result, r.restored, &r.message),
                req.signatures.len().saturating_sub(1),
            )
        }
        // External audit ASK-009 (lab PR 213): who read the telemetry the
        // unsigned status withholds. The counters themselves are not copied
        // into the row.
        (AdminMessage::TelemetryStatusRequest(req), AdminMessage::TelemetryStatusResponse(r)) => (
            "telemetry_status",
            serde_json::json!({}),
            audit_result_str(r.result),
            req.signatures.len().saturating_sub(1),
        ),
        // Lab PR 222: the verb's own row; every file it touched has a
        // `cow_restore` row of its own, signed before this one.
        (
            AdminMessage::RemediateRansomwareRequest(req),
            AdminMessage::RemediateRansomwareResponse(r),
        ) => {
            let (pid, since, dry_run) = match &req.payload.extra {
                OperationExtra::RemediateRansomware(e) => (e.pid, e.since_unix, e.dry_run),
                _ => (None, None, false),
            };
            (
                "remediate_ransomware",
                serde_json::json!({
                    "pid": pid,
                    "since_unix": since,
                    "dry_run": dry_run,
                    "files": r.rows_total,
                    "restored": r.restored,
                    "recreated": r.recreated,
                    "kept_both": r.kept_both,
                    "unchanged": r.unchanged,
                    "refused": r.refused,
                    "skipped": r.skipped,
                    "detail": r.message,
                }),
                verified_result_str(r.result, r.done, &r.message),
                req.signatures.len().saturating_sub(1),
            )
        }
        // Non-auditable here: ChallengeRequest, the debug path. The unsigned
        // Status is summarised per peer by `StatusPolls` (external audit
        // ASK-009). Server-only reply variants reaching dispatch are
        // out-of-spec and already logged; no audit row.
        _ => return,
    };
    // PHASE_D_004: split matched_fps into primary + cosigners.
    // matched_fps is in admin.pub index-order — the first slot
    // is the canonical "key_fp" (primary signer), the rest are
    // cosigners. Empty matched_fps (legacy Unlock path / failure
    // paths) falls back to empty strings — the same shape B5
    // shipped, so audit-verify of an existing chain still parses.
    let (key_fp, cosigner_fps): (String, Vec<String>) = if matched_fps.is_empty() {
        (String::new(), vec![String::new(); cosigner_count])
    } else {
        let mut iter = matched_fps.iter().cloned();
        let primary = iter.next().unwrap_or_default();
        (primary, iter.collect())
    };
    let draft = AuditEntryDraft {
        op: op.to_string(),
        extra,
        key_fp,
        cosigner_fps,
        result,
        client_pid: client.pid,
        client_uid: client.uid,
        client_comm: client.comm.clone(),
        client_exe: client.exe.clone(),
    };
    let mut log = audit_log.lock();
    if let Err(e) = log.append(draft) {
        warn!(
            error = %e,
            op,
            "audit log append failed — admin op succeeded, audit row missing"
        );
    }
}

/// Map a legacy [`UnlockResult`] (predates the Tappa 8 A7
/// `AdminResult` superset) to the same `"success"` /
/// `"failure: <reason>"` shape audit entries use.
fn unlock_result_str(r: &UnlockResult) -> String {
    match r {
        UnlockResult::Success => "success".to_string(),
        UnlockResult::InvalidSignature => "failure: invalid_signature".to_string(),
        UnlockResult::NoPendingChallenge => "failure: no_pending_challenge".to_string(),
        UnlockResult::RateLimited { retry_after_secs } => {
            format!("failure: rate_limited (retry_after_secs={retry_after_secs})")
        }
        UnlockResult::LegacyProtocolRefused => "failure: legacy_protocol_refused".to_string(),
    }
}

/// The audit `result` of a verb that can be verified and still do nothing:
/// `success` only when it was done.
fn verified_result_str(r: AdminResult, done: bool, message: &str) -> String {
    if done {
        "success".to_string()
    } else if r == AdminResult::Success {
        format!("failure: rejected ({message})")
    } else {
        audit_result_str(r)
    }
}

/// Map an [`AdminResult`] to the audit-log `result` field shape
/// from design §9.1: `"success"` or `"failure: <reason>"`.
fn audit_result_str(r: AdminResult) -> String {
    match r {
        AdminResult::Success => "success".to_string(),
        AdminResult::InvalidSignature => "failure: invalid_signature".to_string(),
        AdminResult::NoPendingChallenge => "failure: no_pending_challenge".to_string(),
        AdminResult::RateLimited { retry_after_secs } => {
            format!("failure: rate_limited (retry_after_secs={retry_after_secs})")
        }
        AdminResult::QuorumNotMet { required, provided } => {
            format!("failure: quorum_not_met (required={required}, provided={provided})")
        }
        AdminResult::RoleDenied => "failure: role_denied".to_string(),
        AdminResult::TimestampSkew {
            server_ts,
            max_skew_secs,
        } => format!(
            "failure: timestamp_skew (server_ts={server_ts}, max_skew_secs={max_skew_secs})"
        ),
        AdminResult::AgentIdMismatch => "failure: agent_id_mismatch".to_string(),
        AdminResult::UnknownOperation => "failure: unknown_operation".to_string(),
        AdminResult::ProtocolVersionUnsupported { server_version } => {
            format!("failure: protocol_version_unsupported (server_version={server_version})")
        }
        AdminResult::ActionFailed => "failure: action_failed".to_string(),
    }
}
