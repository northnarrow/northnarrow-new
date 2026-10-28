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
fn dispatch_fim_baseline(
    req: FimBaselineRequest,
    auth: &ConnAuth<'_>,
    fim_state: Option<&FimAdminState>,
    fps_out: &mut Vec<String>,
) -> AdminResult {
    let server_now = now_unix_secs();
    let sigs: Vec<[u8; 64]> = req.signatures.iter().map(|s| s.signature).collect();

    let (_token, matched_fps) = match auth.verify_signed_payload_quorum(
        &req.payload,
        &sigs,
        1, // 1-of-N per §13 Q6 (workflow gate, not security gate)
        &[Role::FimManage],
        OperationCode::FimBaseline,
        server_now,
    ) {
        Ok(t) => t,
        Err(e) => return map_admin_auth_error(e, "fim-baseline"),
    };
    *fps_out = matched_fps;

    // The payload's extra MUST be FimBaseline (op/extra invariant
    // already enforced inside verify_signed_payload_quorum).
    if !matches!(&req.payload.extra, OperationExtra::FimBaseline(_)) {
        warn!(
            extra = ?req.payload.extra,
            "fim-baseline payload extra is not FimBaseline variant"
        );
        return AdminResult::UnknownOperation;
    }

    match fim_state {
        Some(state) => {
            let queued = state
                .recompute_sender
                .trigger(RecomputeReason::AdminRequest);
            info!(
                target: "admin.fim_baseline",
                signer_fp = %fps_out.first().map(String::as_str).unwrap_or(""),
                queued,
                "fim baseline requested — recompute channel fired"
            );
        }
        None => {
            info!(
                target: "admin.fim_baseline",
                signer_fp = %fps_out.first().map(String::as_str).unwrap_or(""),
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
fn dispatch_fim_status(
    req: FimStatusRequest,
    auth: &ConnAuth<'_>,
    fim_state: Option<&FimAdminState>,
    fps_out: &mut Vec<String>,
) -> FimStatusResponse {
    let server_now = now_unix_secs();
    let sigs: Vec<[u8; 64]> = req.signatures.iter().map(|s| s.signature).collect();

    let (_token, matched_fps) = match auth.verify_signed_payload_quorum(
        &req.payload,
        &sigs,
        1, // 1-of-N per §13 Q6
        &[Role::FimRead],
        OperationCode::FimStatus,
        server_now,
    ) {
        Ok(t) => t,
        Err(e) => return empty_fim_status(map_admin_auth_error(e, "fim-status")),
    };
    *fps_out = matched_fps;

    if !matches!(&req.payload.extra, OperationExtra::FimStatus(_)) {
        warn!(
            extra = ?req.payload.extra,
            "fim-status payload extra is not FimStatus variant"
        );
        return empty_fim_status(AdminResult::UnknownOperation);
    }

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
        signer_fp = %fps_out.first().map(String::as_str).unwrap_or(""),
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
fn dispatch_fim_report(
    req: FimReportRequest,
    auth: &ConnAuth<'_>,
    read_paths: &AdminReadPaths,
    fps_out: &mut Vec<String>,
) -> FimReportResponse {
    use nn_proto::admin_signed_payload::FimReportExtra;

    let server_now = now_unix_secs();
    let sigs: Vec<[u8; 64]> = req.signatures.iter().map(|s| s.signature).collect();

    let (_token, matched_fps) = match auth.verify_signed_payload_quorum(
        &req.payload,
        &sigs,
        1, // 1-of-N per §13 Q6
        &[Role::FimRead],
        OperationCode::FimReport,
        server_now,
    ) {
        Ok(t) => t,
        Err(e) => {
            return FimReportResponse {
                result: map_admin_auth_error(e, "fim-report"),
                entries_jsonl: String::new(),
                entries_count: 0,
                entries_truncated: false,
            };
        }
    };
    *fps_out = matched_fps;

    let since = match &req.payload.extra {
        OperationExtra::FimReport(FimReportExtra { since_unix_ts }) => *since_unix_ts,
        _ => {
            warn!("fim-report payload extra is not FimReport variant");
            return FimReportResponse {
                result: AdminResult::UnknownOperation,
                entries_jsonl: String::new(),
                entries_count: 0,
                entries_truncated: false,
            };
        }
    };

    let (entries_jsonl, entries_count, entries_truncated) =
        read_tail_jsonl(&read_paths.fim_drift, since, None, usize::MAX);
    info!(
        target: "admin.fim_report",
        signer_fp = %fps_out.first().map(String::as_str).unwrap_or(""),
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
