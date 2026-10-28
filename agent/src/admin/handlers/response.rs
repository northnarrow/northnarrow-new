//! The response verbs (R11d, lab PR 263: from `admin_socket.rs`): `response
//! status`, `release` and `restore`, and `remediate ransomware`.

use tracing::{info, warn};

use nn_proto::admin_protocol::{
    AdminResult, RemediateRansomwareRequest, RemediateRansomwareResponse, ResponseReleaseRequest,
    ResponseReleaseResponse, ResponseRestoreRequest, ResponseRestoreResponse,
    ResponseStatusRequest, ResponseStatusResponse,
};
use nn_proto::admin_signed_payload::{OperationCode, OperationExtra, Role};

use crate::admin::verify::{map_admin_auth_error, now_unix_secs};
use crate::admin::ResponseAdminState;
use crate::anti_tamper::admin_auth::ConnAuth;
use crate::posture::PostureMachine;

// ── External audit CMB-016 — undoing a response ───────────────────

fn empty_response_status(result: AdminResult) -> ResponseStatusResponse {
    ResponseStatusResponse {
        result,
        contained: Vec::new(),
        contained_total: 0,
        quarantined: Vec::new(),
        quarantined_total: 0,
        combat_stage: None,
        combat_locked: None,
    }
}

/// `nn-admin response status`: the processes the agent holds in its
/// `blocked` / `throttled` scopes (the containment record, with whether
/// the pid still names the process moved), the quarantine vault, and the
/// COMBAT stage. Read-only; `audit-read`, the role every key carries by
/// default, so the operator who undoes a response sees what there is to
/// undo.
pub(in crate::admin) fn dispatch_response_status(
    req: ResponseStatusRequest,
    auth: &ConnAuth<'_>,
    posture: &PostureMachine,
    state: Option<&ResponseAdminState>,
    fps_out: &mut Vec<String>,
) -> ResponseStatusResponse {
    use nn_proto::admin_protocol::{
        ContainedProcessWire, QuarantinedFileWire, MAX_RESPONSE_STATUS_ROWS,
    };
    let sigs: Vec<[u8; 64]> = req.signatures.iter().map(|s| s.signature).collect();
    let (_token, matched_fps) = match auth.verify_signed_payload_quorum(
        &req.payload,
        &sigs,
        1,
        &[Role::AuditRead],
        OperationCode::ResponseStatus,
        now_unix_secs(),
    ) {
        Ok(t) => t,
        Err(e) => return empty_response_status(map_admin_auth_error(e, "response-status")),
    };
    *fps_out = matched_fps;
    if !matches!(&req.payload.extra, OperationExtra::ResponseStatus(_)) {
        warn!("response-status payload extra is not ResponseStatus variant");
        return empty_response_status(AdminResult::UnknownOperation);
    }
    let Some(state) = state else {
        warn!("response-status: agent boot did not wire ResponseAdminState");
        return empty_response_status(AdminResult::UnknownOperation);
    };
    let records = crate::response::containment::load(&state.config);
    let contained_total = records.len() as u32;
    let contained = records
        .iter()
        .rev()
        .take(MAX_RESPONSE_STATUS_ROWS)
        .map(|c| {
            let now = crate::response::proc_ref::proc_start_ticks(c.pid);
            ContainedProcessWire {
                pid: c.pid,
                scope: c.scope.clone(),
                origin: c.origin.clone(),
                since: c.since,
                running: now.is_some() && (c.start_ticks.is_none() || now == c.start_ticks),
            }
        })
        .collect();
    let vault = crate::response::quarantine::list_vault(&state.config);
    let quarantined_total = vault.len() as u32;
    let quarantined = vault
        .into_iter()
        .rev()
        .take(MAX_RESPONSE_STATUS_ROWS)
        .map(|e| QuarantinedFileWire {
            vault_id: e.vault_id,
            // a path is at most PATH_MAX; keep the reply inside a frame
            original_path: e.original_path.chars().take(512).collect(),
            size_bytes: e.size_bytes,
            captured_at: e.captured_at,
        })
        .collect();
    ResponseStatusResponse {
        result: AdminResult::Success,
        contained,
        contained_total,
        quarantined,
        quarantined_total,
        combat_stage: (state.combat_stage)(),
        combat_locked: Some(posture.is_combat_locked()),
    }
}

/// `nn-admin response release --pid N`: write a process the agent
/// contained back to the cgroup it came from, by its containment record
/// (external audit CMB-010: never the root cgroup, and only while the pid
/// still names the process moved). `response-manage`.
pub(in crate::admin) fn dispatch_response_release(
    req: ResponseReleaseRequest,
    auth: &ConnAuth<'_>,
    state: Option<&ResponseAdminState>,
    fps_out: &mut Vec<String>,
) -> ResponseReleaseResponse {
    let refuse = |result: AdminResult, message: String| ResponseReleaseResponse {
        result,
        released: false,
        message,
    };
    let sigs: Vec<[u8; 64]> = req.signatures.iter().map(|s| s.signature).collect();
    let (_token, matched_fps) = match auth.verify_signed_payload_quorum(
        &req.payload,
        &sigs,
        1,
        &[Role::ResponseManage],
        OperationCode::ResponseRelease,
        now_unix_secs(),
    ) {
        Ok(t) => t,
        Err(e) => return refuse(map_admin_auth_error(e, "response-release"), String::new()),
    };
    *fps_out = matched_fps;
    let OperationExtra::ResponseRelease(extra) = &req.payload.extra else {
        warn!("response-release payload extra is not ResponseRelease variant");
        return refuse(AdminResult::UnknownOperation, String::new());
    };
    let pid = extra.pid;
    let Some(state) = state else {
        warn!("response-release: agent boot did not wire ResponseAdminState");
        return refuse(AdminResult::UnknownOperation, String::new());
    };
    let records: Vec<_> = crate::response::containment::load(&state.config)
        .into_iter()
        .filter(|c| c.pid == pid)
        .collect();
    if records.is_empty() {
        return refuse(
            AdminResult::Success,
            format!("pid {pid} is not contained by this agent (no containment record)"),
        );
    }
    let mut released = false;
    let mut parts = Vec::new();
    for rec in records {
        let outcome = match rec.scope.as_str() {
            "blocked" => crate::response::block_outbound::release_blocked_pid(
                pid,
                rec.start_ticks,
                &state.config,
            ),
            "throttled" => {
                crate::response::throttle::release_pid(pid, rec.start_ticks, &state.config)
            }
            other => {
                parts.push(format!("{other}: unknown scope, left as it is"));
                continue;
            }
        };
        match outcome {
            Ok(crate::response::containment::Release::Released) => {
                released = true;
                parts.push(format!(
                    "{}: released to {}",
                    rec.scope,
                    if rec.origin.is_empty() {
                        "?"
                    } else {
                        &rec.origin
                    }
                ));
            }
            Ok(crate::response::containment::Release::Skipped(why)) => {
                parts.push(format!("{}: skipped ({why})", rec.scope));
            }
            Err(e) => parts.push(format!("{}: failed ({e})", rec.scope)),
        }
    }
    let message = parts.join("; ");
    info!(
        target: "admin.response_release",
        signer_fp = %fps_out.first().map(String::as_str).unwrap_or(""),
        pid,
        released,
        detail = %nn_model::log_escape::Escaped(&message),
        "response release"
    );
    ResponseReleaseResponse {
        result: AdminResult::Success,
        released,
        message,
    }
}

/// `nn-admin response restore --vault-id ID [--to PATH]`: write a
/// quarantined file back out of the vault — to the path it was taken from
/// unless `--to` says otherwise; never over an existing file, through a
/// link, or under a protected prefix (external audit CMB-026). The entry
/// stays in the vault. `response-manage`: a restore can put malware back.
pub(in crate::admin) fn dispatch_response_restore(
    req: ResponseRestoreRequest,
    auth: &ConnAuth<'_>,
    state: Option<&ResponseAdminState>,
    fps_out: &mut Vec<String>,
) -> ResponseRestoreResponse {
    let refuse = |result: AdminResult, message: String| ResponseRestoreResponse {
        result,
        restored: false,
        path: String::new(),
        message,
    };
    let sigs: Vec<[u8; 64]> = req.signatures.iter().map(|s| s.signature).collect();
    let (_token, matched_fps) = match auth.verify_signed_payload_quorum(
        &req.payload,
        &sigs,
        1,
        &[Role::ResponseManage],
        OperationCode::ResponseRestore,
        now_unix_secs(),
    ) {
        Ok(t) => t,
        Err(e) => return refuse(map_admin_auth_error(e, "response-restore"), String::new()),
    };
    *fps_out = matched_fps;
    let OperationExtra::ResponseRestore(extra) = &req.payload.extra else {
        warn!("response-restore payload extra is not ResponseRestore variant");
        return refuse(AdminResult::UnknownOperation, String::new());
    };
    let Some(state) = state else {
        warn!("response-restore: agent boot did not wire ResponseAdminState");
        return refuse(AdminResult::UnknownOperation, String::new());
    };
    match crate::response::quarantine::restore_entry(
        &extra.vault_id,
        extra.to.as_deref(),
        &state.config,
    ) {
        Ok(path) => {
            let path = path.to_string_lossy().into_owned();
            warn!(
                target: "admin.response_restore",
                signer_fp = %fps_out.first().map(String::as_str).unwrap_or(""),
                vault_id = %extra.vault_id,
                path = %nn_model::log_escape::Escaped(&path),
                "quarantined file restored by an administrator (mode 0600)"
            );
            ResponseRestoreResponse {
                result: AdminResult::Success,
                restored: true,
                message: format!("restored to {path} (mode 0600); the vault keeps the entry"),
                path,
            }
        }
        Err(e) => {
            warn!(vault_id = %extra.vault_id, error = %e, "response-restore refused");
            refuse(AdminResult::Success, e.to_string())
        }
    }
}

/// Lab PR 222: `nn-admin remediate ransomware --pid N | --since TS
/// [--dry-run]` (`response-manage`): restore, from the copy-on-first-write
/// journal, the files the process tree rewrote (or every file copied since
/// the time). The agent does the work under the rules of
/// [`crate::cow::restore`] and signs one `cow_restore` row per file.
pub(in crate::admin) fn dispatch_remediate_ransomware(
    req: RemediateRansomwareRequest,
    auth: &ConnAuth<'_>,
    fps_out: &mut Vec<String>,
) -> RemediateRansomwareResponse {
    let refuse = |result: AdminResult, message: String| RemediateRansomwareResponse {
        result,
        done: false,
        message,
        rows: Vec::new(),
        rows_total: 0,
        restored: 0,
        recreated: 0,
        kept_both: 0,
        unchanged: 0,
        refused: 0,
        skipped: 0,
    };
    let sigs: Vec<[u8; 64]> = req.signatures.iter().map(|s| s.signature).collect();
    let (_token, matched_fps) = match auth.verify_signed_payload_quorum(
        &req.payload,
        &sigs,
        1,
        &[Role::ResponseManage],
        OperationCode::RemediateRansomware,
        now_unix_secs(),
    ) {
        Ok(t) => t,
        Err(e) => {
            return refuse(
                map_admin_auth_error(e, "remediate-ransomware"),
                String::new(),
            )
        }
    };
    *fps_out = matched_fps;
    let OperationExtra::RemediateRansomware(extra) = &req.payload.extra else {
        warn!("remediate-ransomware payload extra is not RemediateRansomware variant");
        return refuse(AdminResult::UnknownOperation, String::new());
    };
    let key_fp = fps_out.first().cloned().unwrap_or_default();
    let report = match crate::cow::admin_restore(extra.pid, extra.since_unix, extra.dry_run, key_fp)
    {
        Ok(r) => r,
        Err(why) => return refuse(AdminResult::Success, why),
    };
    if let Some(why) = report.refusal.clone() {
        return refuse(AdminResult::Success, why);
    }
    let total = report.rows.len();
    // Keep the reply inside a frame: at most REMEDIATE_ROWS_MAX rows and
    // about 48 KiB of them (a path is up to PATH_MAX).
    let mut budget = 48 * 1024usize;
    let mut rows = Vec::new();
    for r in &report.rows {
        let clip = |s: &str| s.chars().take(512).collect::<String>();
        let row = nn_proto::admin_protocol::CowRestoreRow {
            path: clip(&r.path),
            action: r.action.clone(),
            entry: r.entry,
            detail: clip(&r.detail),
            beside: r.beside.as_deref().map(clip),
            evidence: r.evidence.as_deref().map(clip),
            sha256_original: r.sha256_original.clone(),
            sha256_after: r.sha256_after.clone(),
        };
        let cost = row.path.len()
            + row.detail.len()
            + row.beside.as_ref().map_or(0, |s| s.len())
            + row.evidence.as_ref().map_or(0, |s| s.len())
            + 200;
        if rows.len() >= nn_proto::admin_protocol::REMEDIATE_ROWS_MAX || cost > budget {
            break;
        }
        budget -= cost;
        rows.push(row);
    }
    let done = if extra.dry_run {
        report.restored + report.recreated + report.kept_both > 0
    } else {
        report.restored + report.recreated > 0
    };
    let message = format!(
        "{}{} file(s): {} restored in place, {} recreated, {} kept both, {} unchanged, {} refused, {} skipped{}",
        if extra.dry_run { "dry run — " } else { "" },
        total,
        report.restored,
        report.recreated,
        report.kept_both,
        report.unchanged,
        report.refused,
        report.skipped,
        if rows.len() < total {
            format!(" ({} listed; every file is in the signed audit log)", rows.len())
        } else {
            String::new()
        }
    );
    warn!(
        target: "admin.remediate_ransomware",
        signer_fp = %fps_out.first().map(String::as_str).unwrap_or(""),
        pid = ?extra.pid,
        since = ?extra.since_unix,
        dry_run = extra.dry_run,
        detail = %message,
        "remediate ransomware"
    );
    RemediateRansomwareResponse {
        result: AdminResult::Success,
        done,
        message,
        rows,
        rows_total: total as u32,
        restored: report.restored,
        recreated: report.recreated,
        kept_both: report.kept_both,
        unchanged: report.unchanged,
        refused: report.refused,
        skipped: report.skipped,
    }
}
