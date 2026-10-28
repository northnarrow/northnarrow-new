//! The status verbs (R11d, lab PR 263: from `admin_socket.rs`): the
//! unsigned public status and the signed telemetry status.

use nn_proto::admin_protocol::{
    AdminResult, StatusResponse, TelemetryStatusRequest, TelemetryStatusResponse,
};

use crate::admin::verify::{signed, Verified};
use crate::admin::ResponseAdminState;
use crate::anti_tamper::admin_auth::ConnAuth;
use crate::anti_tamper::network_isolate::{Family, NetworkIsolator};
use crate::posture::PostureMachine;

/// The whole status, telemetry included: the reply to the signed
/// [`TelemetryStatusRequest`] (external audit ASK-009, lab PR 213).
fn telemetry_status(
    posture: &PostureMachine,
    isolator: &NetworkIsolator,
    response_state: Option<&ResponseAdminState>,
) -> StatusResponse {
    let evidence = response_state.map(|s| (s.combat_evidence)());
    let encrypted = crate::net::blind_spots::encrypted_flows();
    let trust = crate::boot::trust::current();
    let execq = crate::execq::snapshot();
    let ransom = crate::impact::published_counts();
    let defense = crate::impair::published_counts();
    let execpol = crate::execpol::snapshot();
    StatusResponse {
        posture: posture.current_kind(),
        network_isolation_engaged: isolator.is_engaged(),
        // Lab PR 217 (capability C18): per IP family, as read back.
        network_isolation_v4: Some(isolator.is_isolated(Family::V4)),
        network_isolation_v6: Some(isolator.is_isolated(Family::V6)),
        last_admin_action_secs_ago: posture.last_admin_action_secs_ago(),
        ringbuf_drops_total: Some(crate::sensors::ring_drops::total()),
        ringbuf_drops: Some(crate::sensors::ring_drops::snapshot_nonzero()),
        // External audit CMB-016: where the COMBAT ladder stands.
        combat_stage: response_state.and_then(|s| (s.combat_stage)()),
        combat_locked: Some(posture.is_combat_locked()),
        // External audit SNS-008: malformed records the pumps rejected.
        ringbuf_rejected_total: Some(crate::sensors::reject::total()),
        ringbuf_rejected: Some(crate::sensors::reject::snapshot()),
        // External audit NET-019 / NET-012 / NET-009: `nn-admin net status`.
        netflow_rows_skipped_total: Some(crate::net::limiter::rows_skipped_total()),
        netflow_pending_evicted_total: Some(crate::net::flow_tracker::pending_evictions_total()),
        net_inactive_rules: Some(crate::net::blind_spots::inactive_net_rules()),
        // Lab PR 164: the kernel's connect→close socket map.
        flow_sock_pending: crate::sensors::flow_sock::snapshot().map(|o| o.pending),
        flow_sock_capacity: crate::sensors::flow_sock::snapshot().map(|o| o.capacity),
        flow_sock_forgotten_min: crate::sensors::flow_sock::snapshot().map(|o| o.forgotten_min),
        // External audit CMB-018: an enforcing agent and a detect-only
        // one no longer look the same.
        detect_only: response_state.map(|s| s.config.dry_run),
        detect_only_source: response_state.and_then(|s| s.detect_only_source.clone()),
        // External audit CMB-027: what the signed audit log lacks.
        combat_evidence_unrecorded: evidence.map(|c| c.unrecorded),
        combat_evidence_pending: evidence.map(|c| c.pending),
        combat_evidence_dropped: evidence.map(|c| c.dropped),
        // External audit NET-017 (lab PR 207): the rows no DNS or TLS
        // reader sees into.
        net_dot_rows_total: Some(encrypted.dot),
        net_dot_rows_resolver: Some(encrypted.dot_resolver),
        net_quic_rows_total: Some(encrypted.quic),
        // Lab PR 215: operations a deny hook let through undecided.
        deny_fail_open_total: crate::anti_tamper::fail_open::total(),
        deny_fail_open: crate::anti_tamper::fail_open::total()
            .map(|_| crate::anti_tamper::fail_open::snapshot_nonzero()),
        // Lab PR 218: the trust level now, the degradations of this run and
        // the boot's signed capability manifest.
        trust_level: trust.as_ref().map(|t| t.level.as_u8()),
        trust_reasons: trust.map(|t| t.reasons),
        degradations: Some(crate::boot::degradation::snapshot()),
        capability_manifest: crate::boot::manifest::current_json(),
        // Lab PR 219: the exploit post-condition guard.
        exploit_guard: Some(crate::sensors::epg::status()),
        // Lab PR 222: the copy-on-first-write guard.
        cow_guard: crate::cow::status(),
        // Lab PR 223 (EXPERIMENTAL): the exec quarantine.
        execq_state: Some(execq.state),
        execq_held_total: Some(execq.held),
        execq_resumed_total: Some(execq.resumed),
        execq_killed_total: Some(execq.killed),
        execq_quarantined_total: Some(execq.quarantined),
        execq_defaulted_total: Some(execq.defaulted),
        execq_known_identity_total: Some(execq.known_identity),
        execq_known_hash_total: Some(execq.known_hash),
        execq_not_held_total: Some(execq.not_held),
        execq_scanner_deaths_total: Some(execq.scanner_deaths),
        // Lab PR 224 (CM-02): connect-time verdicts, open-flow snapshots,
        // the optional kernel connect deny.
        net_connect_verdicts_total: Some(crate::decision::engine::connect_verdicts_total()),
        net_flow_snapshots_total: Some(crate::net::flow_tracker::snapshots_total()),
        net_flow_snapshots_deferred_total: Some(
            crate::net::flow_tracker::snapshots_deferred_total(),
        ),
        net_connect_denied_total: crate::sensors::connect_deny::denied_total(),
        // Lab PR 225: the ransomware signal and the security tools.
        ransomware_decisive_total: ransom.map(|c| c.decisive),
        ransomware_signals_total: ransom.map(|c| c.signals),
        ransomware_trusted_total: ransom.map(|c| c.trusted),
        ransomware_samplings_total: ransom.map(|c| c.samplings),
        defense_tamper_total: defense.map(|c| c.findings),
        defense_tamper_sanctioned_total: defense.map(|c| c.sanctioned),
        defense_tools_watched: defense.map(|c| c.defenders),
        // Lab PR 226 (EXPERIMENTAL): the exec policy.
        execpol_state: Some(execpol.state),
        execpol_denied_total: Some(execpol.denied),
        execpol_would_deny_total: Some(execpol.would_deny),
        execpol_quarantine_total: Some(execpol.quarantine),
        execpol_quarantine_inactive_total: Some(execpol.quarantine_inactive),
        execpol_env_denied_total: Some(execpol.env_denied),
        execpol_env_recorded_total: Some(execpol.env_recorded),
        execpol_map_denied_total: Some(execpol.map_denied),
        execpol_map_recorded_total: Some(execpol.map_recorded),
        execq_script_refused_total: Some(execq.script_refused),
    }
}

/// External audit ASK-009 (lab PR 213): the reply to the unsigned `status`
/// — the posture, the isolation, the last admin action and where the COMBAT
/// ladder stands, what the watchdog and COMBAT recovery read. The
/// telemetry (ring drops and rejected records, netflow pacing and
/// evictions, `FLOW_SOCK_MAP`, the inactive network rules, detect-only, the
/// COMBAT evidence gaps, the encrypted-flow counts) is not even computed:
/// it told a local root without an admin key how much the agent was losing
/// — the feedback of a ring flood — and is the signed verb's.
pub(in crate::admin) fn public_status(
    posture: &PostureMachine,
    isolator: &NetworkIsolator,
    response_state: Option<&ResponseAdminState>,
) -> StatusResponse {
    StatusResponse::public(
        posture.current_kind(),
        isolator.is_engaged(),
        posture.last_admin_action_secs_ago(),
        response_state.and_then(|s| (s.combat_stage)()),
        Some(posture.is_combat_locked()),
    )
    // Lab PR 217 (capability C18): the isolation per IP family, public.
    .with_isolation_families(
        isolator.is_isolated(Family::V4),
        isolator.is_isolated(Family::V6),
    )
}

/// `nn-admin status --key` / `nn-admin net status --key` (external audit
/// ASK-009, lab PR 213): the whole status, 1-of-N, `audit-read` or
/// `telemetry-read` (the pipeline's `verify::Roles::AnyOf`); one audit row
/// per request.
pub(in crate::admin) fn dispatch_telemetry_status(
    req: TelemetryStatusRequest,
    auth: &ConnAuth<'_>,
    posture: &PostureMachine,
    isolator: &NetworkIsolator,
    response_state: Option<&ResponseAdminState>,
    fps_out: &mut Vec<String>,
) -> TelemetryStatusResponse {
    let refuse = |result| TelemetryStatusResponse {
        result,
        status: None,
    };
    // No role in the quorum check (it would want each listed role): the
    // signer's roles are checked after it, any one of the two — the
    // pipeline's `Roles::AnyOf`, whose refusal names the signer.
    signed(&req, auth, fps_out, refuse, |v| {
        signed_telemetry_status(v, posture, isolator, response_state)
    })
}

/// The verified telemetry status: the whole status.
fn signed_telemetry_status(
    _v: Verified<'_, TelemetryStatusRequest>,
    posture: &PostureMachine,
    isolator: &NetworkIsolator,
    response_state: Option<&ResponseAdminState>,
) -> TelemetryStatusResponse {
    TelemetryStatusResponse {
        result: AdminResult::Success,
        status: Some(telemetry_status(posture, isolator, response_state)),
    }
}
