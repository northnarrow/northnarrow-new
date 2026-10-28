//! The FIM verbs (R11d, lab PR 263: from `admin_socket.rs`): `fim
//! baseline`, `fim status` and `fim report`.

use std::path::Path;

use tracing::{info, warn};

use nn_proto::admin_protocol::{
    AdminResult, FimBaselineRequest, FimReportRequest, FimReportResponse, FimStatusRequest,
    FimStatusResponse,
};

use super::read::{extract_ts_field, read_tail_jsonl};
use crate::admin::verify::{signed, Verified};
use crate::admin::{AdminReadPaths, FimAdminState};
use crate::anti_tamper::admin_auth::ConnAuth;
use crate::fim::recompute::RecomputeReason;

// PHASE_D_004: `fps_out` populated on success with the matched
// signer fingerprint (1-of-N quorum → one fingerprint).
//
/// Tappa 9 C6 → C7 — handle one [`FimBaselineRequest`] (design §6.1 +
/// §13 Q6). Verifies 1-of-N quorum carrying `Role::FimManage`,
/// then fires the in-process recompute channel so the running
/// agent re-walks every watched path without an operator-driven
/// restart (C7 closes C6's lazy deferral). When the agent boots
/// WITHOUT a recompute channel — every legacy `serve_with_*`
/// callsite that hasn't migrated to `serve_with_fim_state` —
/// the dispatcher falls back to the C6 info-log shape ("scheduled
/// for next restart") so legacy unit-test fixtures stay green.
pub(in crate::admin) fn dispatch_fim_baseline(
    req: FimBaselineRequest,
    auth: &ConnAuth<'_>,
    fim_state: Option<&FimAdminState>,
    fps_out: &mut Vec<String>,
) -> AdminResult {
    // 1-of-N per §13 Q6 (workflow gate, not security gate), the
    // pipeline's (`verify::signed`).
    signed(&req, auth, fps_out, |r| r, |v| fim_baseline(v, fim_state))
}

/// The verified `fim baseline`: the recompute channel fired.
fn fim_baseline(
    v: Verified<'_, FimBaselineRequest>,
    fim_state: Option<&FimAdminState>,
) -> AdminResult {
    match fim_state {
        Some(state) => {
            let queued = state
                .recompute_sender
                .trigger(RecomputeReason::AdminRequest);
            info!(
                target: "admin.fim_baseline",
                signer_fp = %v.signer_fp(),
                queued,
                "fim baseline requested — recompute channel fired"
            );
        }
        None => {
            info!(
                target: "admin.fim_baseline",
                signer_fp = %v.signer_fp(),
                "fim baseline requested — recompute scheduled for next agent restart \
                 (legacy serve_with_marker_path path; production main.rs uses \
                 serve_with_fim_state)"
            );
        }
    }
    AdminResult::Success
}

/// Tappa 9 C7 — handle one [`FimStatusRequest`] (closes the C6
/// deferral). Verifies 1-of-N quorum carrying `Role::FimRead` and
/// returns the in-process snapshot. Read-only — no disk-side
/// effects. When `fim_state` is `None` (legacy serve path) the
/// snapshot is zeroed and the result is `UnknownOperation` so a
/// stale test fixture doesn't accidentally serve stale data; the
/// production code path always supplies state via
/// `serve_with_fim_state`.
pub(in crate::admin) fn dispatch_fim_status(
    req: FimStatusRequest,
    auth: &ConnAuth<'_>,
    fim_state: Option<&FimAdminState>,
    fps_out: &mut Vec<String>,
) -> FimStatusResponse {
    // 1-of-N per §13 Q6, the pipeline's (`verify::signed`).
    signed(&req, auth, fps_out, empty_fim_status, |v| {
        fim_status(v, fim_state)
    })
}

/// The verified `fim status`: the in-process snapshot.
fn fim_status(
    v: Verified<'_, FimStatusRequest>,
    fim_state: Option<&FimAdminState>,
) -> FimStatusResponse {
    let state = match fim_state {
        Some(s) => s,
        None => {
            warn!("fim-status: agent boot did not wire FimAdminState — returning empty snapshot");
            return empty_fim_status(AdminResult::UnknownOperation);
        }
    };

    let (high_remaining, medium_remaining, bucket_window_resets_in_secs) =
        state.rate_limiter.snapshot();
    let (baseline_entries_total, last_baseline_ts) =
        count_and_last_ts_jsonl(&state.baseline_log_path);
    let (drift_entries_total, _) = count_and_last_ts_jsonl(&state.drift_log_path);

    info!(
        target: "admin.fim_status",
        signer_fp = %v.signer_fp(),
        watched = state.paths_summary.watched_paths_count,
        baseline_total = baseline_entries_total,
        drift_total = drift_entries_total,
        "fim status served"
    );

    FimStatusResponse {
        result: AdminResult::Success,
        watched_paths_count: state.paths_summary.watched_paths_count,
        disabled_default_count: state.paths_summary.disabled_default_count,
        added_path_count: state.paths_summary.added_path_count,
        last_baseline_ts,
        baseline_entries_total,
        drift_entries_total,
        high_remaining,
        high_cap_per_min: state.rate_limiter.high_cap_per_min(),
        medium_remaining,
        medium_cap_per_min: state.rate_limiter.medium_cap_per_min(),
        bucket_window_resets_in_secs,
    }
}

/// Build a zero/empty [`FimStatusResponse`] carrying the supplied
/// auth `result`. Used by both the auth-failure path and the
/// "agent boot didn't wire FIM state" fallback.
fn empty_fim_status(result: AdminResult) -> FimStatusResponse {
    FimStatusResponse {
        result,
        watched_paths_count: 0,
        disabled_default_count: 0,
        added_path_count: 0,
        last_baseline_ts: String::new(),
        baseline_entries_total: 0,
        drift_entries_total: 0,
        high_remaining: 0,
        high_cap_per_min: 0,
        medium_remaining: 0,
        medium_cap_per_min: 0,
        bucket_window_resets_in_secs: 0,
    }
}

/// Count JSONL rows + return the `ts` of the last row in a
/// chained log file at `path`. Missing file → `(0, "")`. Used by
/// `dispatch_fim_status` for the baseline + drift counts; the
/// chain integrity is already enforced at append time, so a
/// best-effort line-count is appropriate here (verify happens at
/// the dedicated `verify_chain` paths, not at every status query).
fn count_and_last_ts_jsonl(path: &Path) -> (u32, String) {
    use std::io::BufRead;
    let f = match std::fs::OpenOptions::new().read(true).open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return (0, String::new()),
        Err(e) => {
            warn!(
                error = %e,
                path = %path.display(),
                "fim-status: jsonl read failed — reporting (0, empty)"
            );
            return (0, String::new());
        }
    };
    let reader = std::io::BufReader::new(f);
    let mut count = 0u32;
    let mut last_ts = String::new();
    for line in reader.lines() {
        let Ok(line) = line else {
            continue;
        };
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        count = count.saturating_add(1);
        if let Some(ts) = extract_ts_field(trimmed) {
            last_ts = ts;
        }
    }
    (count, last_ts)
}

/// Tappa 9 C6 — handle one [`FimReportRequest`] (design §6.3 +
/// §13 Q6). Verifies 1-of-N quorum carrying `Role::FimRead`,
/// reads the drift log from disk, returns the chained JSONL
/// body (or a truncation flag if the chain exceeds the wire
/// frame budget). Filtering by `since_unix_ts` from the
/// payload's extra keeps entries whose `ts` field is `>=`
/// the threshold (lexicographic ISO-8601 compare, valid
/// because the format is fixed-width).
///
/// External audit NN-AUD-080/082: the drift log configured by
/// `--fim-drift-file` (not the built-in path), newest rows first,
/// rotated archives included ([`read_tail_jsonl`]).
pub(in crate::admin) fn dispatch_fim_report(
    req: FimReportRequest,
    auth: &ConnAuth<'_>,
    read_paths: &AdminReadPaths,
    fps_out: &mut Vec<String>,
) -> FimReportResponse {
    // 1-of-N per §13 Q6, the pipeline's (`verify::signed`).
    let refuse = |result| FimReportResponse {
        result,
        entries_jsonl: String::new(),
        entries_count: 0,
        entries_truncated: false,
    };
    signed(&req, auth, fps_out, refuse, |v| fim_report(v, read_paths))
}

/// The verified `fim report`: the drift log's newest rows.
fn fim_report(v: Verified<'_, FimReportRequest>, read_paths: &AdminReadPaths) -> FimReportResponse {
    let since = v.extra().since_unix_ts;
    let (entries_jsonl, entries_count, entries_truncated) =
        read_tail_jsonl(&read_paths.fim_drift, since, None, usize::MAX);
    info!(
        target: "admin.fim_report",
        signer_fp = %v.signer_fp(),
        entries = entries_count,
        truncated = entries_truncated,
        "fim report served"
    );
    FimReportResponse {
        result: AdminResult::Success,
        entries_jsonl,
        entries_count,
        entries_truncated,
    }
}
