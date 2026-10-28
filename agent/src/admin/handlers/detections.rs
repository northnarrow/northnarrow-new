//! The detection verbs (R11d, lab PR 263: from `admin_socket.rs`): the
//! signed read and the triage status change.

use tracing::{info, warn};

use nn_proto::admin_protocol::{
    AdminResult, DetectionSetStatusRequest, DetectionSetStatusResponse, DetectionsRequest,
    DetectionsResponse, MAX_FRAME_BODY,
};
use nn_proto::admin_signed_payload::OperationExtra;

use crate::admin::audit::AuditClient;
use crate::admin::verify::{signed, Verified};
use crate::admin::DetectionAdminState;
use crate::anti_tamper::admin_auth::ConnAuth;
use crate::detection_store::{Principal, StatusEvent};

/// An auth-failure / empty [`DetectionsResponse`] carrying `result`.
/// Also used for the "filter recognised nothing" success path.
fn empty_detections(result: AdminResult) -> DetectionsResponse {
    DetectionsResponse {
        result,
        entries_jsonl: String::new(),
        entries_count: 0,
        entries_truncated: false,
    }
}

/// Tappa 9.0.b — handle one [`DetectionsRequest`]. Verifies the
/// 1-of-N signed-payload quorum carrying [`Role::TelemetryRead`]
/// (read != control: this NEVER accepts a control-only key, and the
/// read-only key it does accept can never `unlock`), then reads the
/// last N persisted detections from the chainlog — newest-first, with
/// the operator's optional filters applied — and returns them as a
/// JSONL body. The read is bounded (see
/// [`crate::detection_store::read_last_n`]); the body is capped at the
/// wire soft cap and `entries_truncated` is set if the matching set
/// would overflow the frame. Like the FIM/net read verbs, the store
/// path is the build-default constant, so no extra serve-time state is
/// threaded.
pub(in crate::admin) fn dispatch_detections(
    req: DetectionsRequest,
    auth: &ConnAuth<'_>,
    det_state: Option<&DetectionAdminState>,
    fps_out: &mut Vec<String>,
) -> DetectionsResponse {
    // 1-of-N: a read verb, like fim-report / net-flows. Role::TelemetryRead
    // — a Triage key also satisfies this via the 9.0.c subsumption (triage
    // subsumes read), so a triage-only key can read the detections it
    // triages. The pipeline's (`verify::signed`).
    signed(&req, auth, fps_out, empty_detections, |v| {
        detections(v, det_state)
    })
}

/// The verified `detections`: the newest records, verified and filtered,
/// with their current triage status.
fn detections(
    v: Verified<'_, DetectionsRequest>,
    det_state: Option<&DetectionAdminState>,
) -> DetectionsResponse {
    use crate::detection_store::{self, DetectionFilter};
    const SOFT_CAP: usize = MAX_FRAME_BODY / 2;

    // Lab PR 263 (R11d): the detection store's state — the files the
    // command line names (`--detections-file`, `--status-events-file`) and
    // the agent key every row is verified with. Without it the read is
    // refused, as set-status is: it read the built-in paths and served
    // their rows unverified (external audit NN-AUD-112's check skipped).
    let Some(state) = det_state else {
        warn!("detections: the detection store is not wired this boot (no agent key) — refused");
        return empty_detections(AdminResult::UnknownOperation);
    };
    let extra = v.extra();

    // Build the typed filter. A provided-but-unrecognised enum filter
    // can match nothing, so we short-circuit to an empty success
    // rather than silently dropping the constraint and widening the
    // result (the CLI restricts these to valid values; this is the
    // defensive server-side path).
    let mut filter = DetectionFilter {
        since_unix: extra.since_unix_ts.map(|s| s as i64),
        until_unix: extra.until_unix_ts.map(|s| s as i64),
        subject_substr: extra.path.clone().filter(|s| !s.is_empty()),
        ..Default::default()
    };
    if let Some(s) = &extra.min_severity {
        match detection_store::parse_severity_filter(s) {
            Some(v) => filter.min_severity = Some(v),
            None => {
                warn!(value = %s, "detections: unrecognised min_severity filter — empty result");
                return empty_detections(AdminResult::Success);
            }
        }
    }
    if let Some(s) = &extra.status {
        match crate::detection_store::DetectionStatus::parse_filter(s) {
            Some(v) => filter.status = Some(v),
            None => {
                warn!(value = %s, "detections: unrecognised status filter — empty result");
                return empty_detections(AdminResult::Success);
            }
        }
    }
    if let Some(s) = &extra.sensor {
        match crate::detection_store::Sensor::parse_filter(s) {
            Some(v) => filter.sensor = Some(v),
            None => {
                warn!(value = %s, "detections: unrecognised sensor filter — empty result");
                return empty_detections(AdminResult::Success);
            }
        }
    }

    let limit = if extra.limit == 0 {
        detection_store::DEFAULT_DETECTIONS_LIMIT
    } else {
        (extra.limit as usize).min(detection_store::MAX_DETECTIONS_LIMIT)
    };

    // The store's paths from the wired state (a custom --detections-file
    // honoured); an absent file simply yields no records / no overlay. The
    // read OVERLAYS the event-sourced current status from the
    // status-event chain onto each record (9.0.c).
    let (detections_path, status_events_path) = (&state.detections_path, &state.status_events_path);
    // External audit NN-AUD-112: the rows served are verified with the
    // agent key; a row that does not verify is left out, logged and
    // recorded in the signed chain.
    let (records, unverified) = detection_store::read_last_n_overlaid_verified(
        detections_path,
        status_events_path,
        limit,
        &filter,
        Some(&state.agent_key),
    );
    if unverified > 0 {
        crate::chains::report_unverified_rows("detections", detections_path, unverified);
    }

    // Serialise newest-first, bounding the body at the wire soft cap.
    // The records are already newest-first, so truncation drops the
    // oldest of the matching set — a dashboard wants the freshest.
    let mut entries_jsonl = String::new();
    let mut entries_count = 0u32;
    let mut entries_truncated = false;
    for record in &records {
        let Ok(line) = serde_json::to_string(record) else {
            continue;
        };
        if entries_jsonl.len() + line.len() + 1 > SOFT_CAP {
            entries_truncated = true;
            break;
        }
        entries_jsonl.push_str(&line);
        entries_jsonl.push('\n');
        entries_count += 1;
    }
    info!(
        target: "admin.detections",
        signer_fp = %v.signer_fp(),
        entries = entries_count,
        truncated = entries_truncated,
        "detections served"
    );
    DetectionsResponse {
        result: AdminResult::Success,
        entries_jsonl,
        entries_count,
        entries_truncated,
    }
}

/// An auth-failure / not-found / unavailable
/// [`DetectionSetStatusResponse`] carrying `result`, echoing the
/// requested `id`, with an empty status string.
fn fail_set_status(result: AdminResult, id: u64) -> DetectionSetStatusResponse {
    DetectionSetStatusResponse {
        result,
        id,
        new_status: String::new(),
        persist_failed: false,
    }
}

/// Tappa 9.0.c — handle one [`DetectionSetStatusRequest`]. Verifies the
/// 1-of-N signed-payload quorum carrying [`Role::Triage`] (control
/// roles do NOT implicitly authorise set-status, and a
/// telemetry-read-only key is RoleDenied — read != triage), validates
/// the target id against the detection store's max id (cheap
/// `1 <= id <= max` guard; an out-of-range id is a clean "not found",
/// folded into `UnknownOperation` like the K6 canary-burn contract),
/// parses the target status string, then appends a signed
/// [`StatusEvent`] to the status-event chain SYNCHRONOUSLY (triage is
/// human-initiated + low-frequency, not the hot path — no off-thread
/// writer). The detection chain (`detections.jsonl`) is never mutated;
/// status is event-sourced and derived at read time.
pub(in crate::admin) fn dispatch_detection_set_status(
    req: DetectionSetStatusRequest,
    auth: &ConnAuth<'_>,
    det_state: Option<&DetectionAdminState>,
    client: &AuditClient,
    fps_out: &mut Vec<String>,
) -> DetectionSetStatusResponse {
    // Recover the requested id up front so every reply (including auth
    // failures) echoes it. Only meaningful for the matching extra
    // variant; 0 otherwise (an op/extra mismatch is rejected anyway).
    let req_id = match &req.payload.extra {
        OperationExtra::DetectionSetStatus(e) => e.id,
        _ => 0,
    };

    // 1-of-N: a single triage operator suffices; the pipeline's
    // (`verify::signed`).
    signed(
        &req,
        auth,
        fps_out,
        |r| fail_set_status(r, req_id),
        |v| detection_set_status(v, det_state, client),
    )
}

/// The verified `detection set-status`: one signed StatusEvent appended.
fn detection_set_status(
    v: Verified<'_, DetectionSetStatusRequest>,
    det_state: Option<&DetectionAdminState>,
    client: &AuditClient,
) -> DetectionSetStatusResponse {
    use crate::detection_store::{self, DetectionStatus};

    let extra = v.extra();

    // The status-event store must be wired (it isn't on a degraded boot
    // where the detection store failed to open). Without it set-status
    // cannot persist — surface UnknownOperation (mirrors the canary
    // "registry None → UnknownOperation" degraded contract).
    let Some(state) = det_state else {
        warn!("detection-set-status: detection store not wired this boot");
        return fail_set_status(AdminResult::UnknownOperation, extra.id);
    };
    let Some(status_log) = state.status_log.as_ref() else {
        warn!("detection-set-status: the status-event store did not open this boot");
        return fail_set_status(AdminResult::UnknownOperation, extra.id);
    };

    // Parse the target status. `open` and unknown strings are rejected
    // (`open` is the initial state, not a settable triage target).
    let Some(new_status) = DetectionStatus::parse_settable(&extra.new_status) else {
        warn!(value = %extra.new_status, "detection-set-status: invalid target status");
        return fail_set_status(AdminResult::UnknownOperation, extra.id);
    };

    // Validity guard: the id must reference an existing detection.
    // Cheap `1 <= id <= max` check (full existence scan deferred). An
    // out-of-range id folds into UnknownOperation → the CLI renders it
    // as a clean "detection not found".
    let max_id = detection_store::max_detection_id(&state.detections_path);
    if extra.id == 0 || extra.id > max_id {
        warn!(
            id = extra.id,
            max_id, "detection-set-status: id out of range (not found)"
        );
        return fail_set_status(AdminResult::UnknownOperation, extra.id);
    }

    // Append the StatusEvent synchronously (append + fsync happen inside
    // the chainlog). The principal is the SO_PEERCRED admin caller —
    // the local operator process that initiated the change.
    let event = StatusEvent {
        detection_id: extra.id,
        new_status,
        ts: detection_store::now_ts(),
        principal: Principal {
            pid: client.pid,
            comm: client.comm.clone(),
            uid: client.uid,
            ppid: None,
        },
        note: extra.note.clone().filter(|s| !s.is_empty()),
        principal_exe: client.exe.clone(),
    };
    {
        let mut log = status_log.lock();
        if let Err(e) = log.append(event) {
            warn!(
                error = %e,
                id = extra.id,
                "detection-set-status: status-event append failed (change not persisted)"
            );
            // chain-persist-1: flag the persistence failure so the CLI
            // can tell it apart from "not found" (same AdminResult).
            let mut resp = fail_set_status(AdminResult::UnknownOperation, extra.id);
            resp.persist_failed = true;
            return resp;
        }
    }
    info!(
        target: "admin.detection_set_status",
        signer_fp = %v.signer_fp(),
        id = extra.id,
        new_status = new_status.as_str(),
        "detection triage status updated",
    );
    DetectionSetStatusResponse {
        result: AdminResult::Success,
        id: extra.id,
        new_status: new_status.as_str().to_string(),
        persist_failed: false,
    }
}
