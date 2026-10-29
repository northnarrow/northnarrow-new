//! The admin verbs (R11d, lab PR 263: from `admin_socket.rs`): `dispatch`
//! routes each request to its handler, one file per family of verbs.

pub(in crate::admin) mod canary;
pub(in crate::admin) mod config;
pub(in crate::admin) mod detections;
pub(in crate::admin) mod fim;
pub(in crate::admin) mod installer;
pub(in crate::admin) mod keys;
pub(in crate::admin) mod net;
pub(in crate::admin) mod posture;
pub(in crate::admin) mod read;
pub(in crate::admin) mod response;
pub(in crate::admin) mod shutdown;
pub(in crate::admin) mod status;
pub(in crate::admin) mod unlock;

use std::path::Path;

use tracing::{error, warn};

use nn_proto::admin_protocol::{AdminMessage, Challenge, UnlockResult};

use super::audit::{AuditClient, DispatchNotes};
use super::{
    AdminHandles, AdminReadPaths, CanaryAdminState, DetectionAdminState, FimAdminState,
    ResponseAdminState, ShutdownSignal,
};
use crate::anti_tamper::admin_auth::{AdminAuthError, ConnAuth};
use crate::anti_tamper::network_isolate::NetworkIsolator;
use crate::anti_tamper::trusted_installer::TrustedInstallerOverride;
use crate::posture::PostureMachine;

use canary::{
    dispatch_canary_burn, dispatch_canary_deploy, dispatch_canary_list, dispatch_canary_refresh,
};
use config::dispatch_config_overlay_set;
use detections::{dispatch_detection_set_status, dispatch_detections};
use fim::{dispatch_fim_baseline, dispatch_fim_report, dispatch_fim_status};
use installer::dispatch_trusted_installer_grant;
use keys::{dispatch_rotate_keys_add, dispatch_rotate_keys_revoke};
use net::{
    dispatch_net_fingerprint, dispatch_net_flows, dispatch_net_listeners, dispatch_net_resolve,
};
use posture::dispatch_force_posture;
use response::{
    dispatch_remediate_ransomware, dispatch_response_release, dispatch_response_restore,
    dispatch_response_status,
};
use shutdown::dispatch_shutdown;
use status::{dispatch_telemetry_status, public_status};
use unlock::dispatch_signed_unlock;

/// What a request may act on: the agent's subsystems as its boot wired
/// them for the admin socket, borrowed for one request (`None`: not wired
/// this boot, or by a legacy serve entry point).
#[derive(Clone, Copy)]
pub(in crate::admin) struct Wired<'a> {
    pub(in crate::admin) posture: &'a PostureMachine,
    pub(in crate::admin) isolator: &'a NetworkIsolator,
    pub(in crate::admin) marker_path: &'a Path,
    pub(in crate::admin) shutdown_signal: Option<&'a ShutdownSignal>,
    pub(in crate::admin) fim_state: Option<&'a FimAdminState>,
    pub(in crate::admin) canary_state: Option<&'a CanaryAdminState>,
    pub(in crate::admin) installer_override: Option<&'a TrustedInstallerOverride>,
    pub(in crate::admin) detection_state: Option<&'a DetectionAdminState>,
    pub(in crate::admin) response_state: Option<&'a ResponseAdminState>,
    pub(in crate::admin) read_paths: &'a AdminReadPaths,
    /// R11c (lab PR 264): the start's handles (the per-rule policy, …).
    pub(in crate::admin) handles: &'a AdminHandles,
}

/// Synchronous request→reply mapping. All AdminAuth + PostureMachine
/// methods are sync; we don't `await` between read and write inside
/// `handle_connection`, so the dispatch itself can stay sync. Every
/// signed verb goes through `verify::signed` in its handler's entry; the
/// arms without a signature are this function's own.
pub(super) fn dispatch(
    msg: AdminMessage,
    auth: &ConnAuth<'_>,
    ctx: Wired<'_>,
    client: &AuditClient,
    fps_out: &mut Vec<String>,
    notes: &mut DispatchNotes,
) -> AdminMessage {
    let Wired {
        posture,
        isolator,
        marker_path,
        shutdown_signal,
        fim_state,
        canary_state,
        installer_override,
        detection_state,
        response_state,
        read_paths,
        handles,
    } = ctx;
    match msg {
        AdminMessage::ChallengeRequest(_) => match auth.issue_challenge() {
            Ok(nonce) => AdminMessage::Challenge(Challenge { nonce }),
            // Rate-limited at the challenge-issuance gate. The
            // protocol reuses `UnlockResult::RateLimited` here
            // because the wire surface has no dedicated
            // ChallengeResponse error variant; clients treat any
            // `RateLimited` reply as "back off and retry later"
            // regardless of which request prompted it.
            Err(AdminAuthError::RateLimited { retry_after_secs }) => {
                AdminMessage::UnlockResult(UnlockResult::RateLimited { retry_after_secs })
            }
            // No-pending / invalid-sig don't apply to challenge
            // issuance, but the typed error enum requires all arms.
            Err(other) => {
                warn!(error = ?other, "unexpected error path during issue_challenge");
                AdminMessage::UnlockResult(UnlockResult::InvalidSignature)
            }
        },

        // Lab PR 217 (NN-AUD-243 residue, capability C17): the legacy unlock
        // — a signature over the bare nonce, no operation, install or time
        // bound to it, its audit row unable to name the signer — no longer
        // releases COMBAT. Refused outright, whatever it carries: a
        // compatibility switch would be a downgrade of the one operation
        // that lifts the host's isolation, and the `nn-admin` that signs the
        // payload ships in the same release as this agent. The connection's
        // challenge is spent; the refusal is audited.
        AdminMessage::Unlock(_) => {
            auth.discard_challenge();
            error!(
                target: "admin.unlock",
                "legacy unlock (signature over the bare nonce) REFUSED — sign an \
                 `OperationCode::Unlock` payload: use the nn-admin of this agent's release \
                 (`nn-admin unlock --key … --agent-id-file …`)"
            );
            AdminMessage::UnlockResult(UnlockResult::LegacyProtocolRefused)
        }

        AdminMessage::SignedUnlockRequest(req) => AdminMessage::SignedUnlockResponse(
            dispatch_signed_unlock(req, auth, posture, isolator, fps_out),
        ),

        // External audit ASK-009 (lab PR 213): unsigned, what the watchdog
        // and COMBAT recovery need; the telemetry is the signed verb's.
        AdminMessage::Status(_) => {
            AdminMessage::StatusResponse(public_status(posture, isolator, response_state))
        }

        AdminMessage::TelemetryStatusRequest(req) => {
            AdminMessage::TelemetryStatusResponse(dispatch_telemetry_status(
                req,
                auth,
                posture,
                isolator,
                response_state,
                handles,
                fps_out,
            ))
        }

        // Lab PR 216: unsigned, the event loop's round count — the
        // watchdog's check that the loop moves, not only this socket.
        AdminMessage::LoopProgress(_) => {
            AdminMessage::LoopProgressResponse(crate::loop_progress::snapshot())
        }

        AdminMessage::ShutdownRequest(req) => AdminMessage::ShutdownResult(dispatch_shutdown(
            req,
            auth,
            marker_path,
            shutdown_signal,
            fps_out,
        )),

        AdminMessage::ForcePostureRequest(req) => AdminMessage::ForcePostureResult(
            dispatch_force_posture(req, auth, posture, fps_out, notes),
        ),

        AdminMessage::RotateKeysAddRequest(req) => {
            AdminMessage::RotateKeysAddResult(dispatch_rotate_keys_add(req, auth, fps_out))
        }

        AdminMessage::RotateKeysRevokeRequest(req) => {
            AdminMessage::RotateKeysRevokeResult(dispatch_rotate_keys_revoke(req, auth, fps_out))
        }

        AdminMessage::FimBaselineRequest(req) => {
            AdminMessage::FimBaselineResult(dispatch_fim_baseline(req, auth, fim_state, fps_out))
        }

        AdminMessage::FimReportRequest(req) => {
            AdminMessage::FimReportResponse(dispatch_fim_report(req, auth, read_paths, fps_out))
        }

        AdminMessage::FimStatusRequest(req) => {
            AdminMessage::FimStatusResponse(dispatch_fim_status(req, auth, fim_state, fps_out))
        }

        AdminMessage::CanaryDeployRequest(req) => AdminMessage::CanaryDeployResponse(
            dispatch_canary_deploy(req, auth, canary_state, fps_out),
        ),

        AdminMessage::CanaryListRequest(req) => {
            AdminMessage::CanaryListResponse(dispatch_canary_list(req, auth, canary_state, fps_out))
        }

        AdminMessage::CanaryBurnRequest(req) => {
            AdminMessage::CanaryBurnResult(dispatch_canary_burn(req, auth, canary_state, fps_out))
        }

        AdminMessage::CanaryRefreshRequest(req) => AdminMessage::CanaryRefreshResult(
            dispatch_canary_refresh(req, auth, canary_state, fps_out),
        ),

        // Tappa 10 N7 — net admin ops.
        AdminMessage::NetFlowsRequest(req) => {
            AdminMessage::NetFlowsResponse(dispatch_net_flows(req, auth, read_paths, fps_out))
        }
        AdminMessage::NetListenersRequest(req) => AdminMessage::NetListenersResponse(
            dispatch_net_listeners(req, auth, read_paths, fps_out),
        ),
        AdminMessage::NetResolveRequest(req) => {
            AdminMessage::NetResolveResponse(dispatch_net_resolve(req, auth, read_paths, fps_out))
        }
        AdminMessage::NetFingerprintRequest(req) => AdminMessage::NetFingerprintResponse(
            dispatch_net_fingerprint(req, auth, read_paths, fps_out),
        ),

        // FIM-009 self-upgrade (§15.1) — signed trusted-installer grant.
        AdminMessage::TrustedInstallerGrantRequest(req) => {
            AdminMessage::TrustedInstallerGrantResult(dispatch_trusted_installer_grant(
                req,
                auth,
                installer_override,
                fps_out,
            ))
        }
        AdminMessage::ConfigOverlaySetRequest(req) => {
            AdminMessage::ConfigOverlaySetResponse(dispatch_config_overlay_set(
                req,
                auth,
                &handles.rule_policy,
                handles.overlay_gate.as_deref(),
                fps_out,
            ))
        }

        // Tappa 9.0.b — signed detections read (read-only,
        // Role::TelemetryRead, or Triage via subsumption). Overlays the
        // event-sourced current status from the status-event chain
        // (9.0.c) onto the returned records.
        AdminMessage::DetectionsRequest(req) => AdminMessage::DetectionsResponse(
            dispatch_detections(req, auth, detection_state, fps_out),
        ),

        // Tappa 9.0.c — signed detection triage status-change
        // (Role::Triage). Appends a StatusEvent to the status-event
        // chain; detections.jsonl is never mutated.
        AdminMessage::DetectionSetStatusRequest(req) => AdminMessage::DetectionSetStatusResponse(
            dispatch_detection_set_status(req, auth, detection_state, client, fps_out),
        ),

        // External audit CMB-016 — undoing a response.
        AdminMessage::ResponseStatusRequest(req) => AdminMessage::ResponseStatusResponse(
            dispatch_response_status(req, auth, posture, response_state, fps_out),
        ),
        AdminMessage::ResponseReleaseRequest(req) => AdminMessage::ResponseReleaseResponse(
            dispatch_response_release(req, auth, response_state, fps_out),
        ),
        AdminMessage::ResponseRestoreRequest(req) => AdminMessage::ResponseRestoreResponse(
            dispatch_response_restore(req, auth, response_state, fps_out),
        ),
        // Lab PR 222 — restore from the copy-on-first-write journal.
        AdminMessage::RemediateRansomwareRequest(req) => AdminMessage::RemediateRansomwareResponse(
            dispatch_remediate_ransomware(req, auth, handles.cow_guard.as_ref(), fps_out),
        ),

        // Server-only variants — clients sending these are speaking
        // out-of-spec. Reply with a benign sentinel; the connection
        // closes naturally on the next read EOF.
        AdminMessage::Challenge(_)
        | AdminMessage::UnlockResult(_)
        | AdminMessage::StatusResponse(_)
        | AdminMessage::ShutdownResult(_)
        | AdminMessage::ForcePostureResult(_)
        | AdminMessage::RotateKeysAddResult(_)
        | AdminMessage::RotateKeysRevokeResult(_)
        | AdminMessage::FimBaselineResult(_)
        | AdminMessage::FimReportResponse(_)
        | AdminMessage::FimStatusResponse(_)
        | AdminMessage::CanaryDeployResponse(_)
        | AdminMessage::CanaryListResponse(_)
        | AdminMessage::CanaryBurnResult(_)
        | AdminMessage::CanaryRefreshResult(_)
        | AdminMessage::NetFlowsResponse(_)
        | AdminMessage::NetListenersResponse(_)
        | AdminMessage::NetResolveResponse(_)
        | AdminMessage::NetFingerprintResponse(_)
        | AdminMessage::TrustedInstallerGrantResult(_)
        | AdminMessage::DetectionsResponse(_)
        | AdminMessage::DetectionSetStatusResponse(_)
        | AdminMessage::ConfigOverlaySetResponse(_)
        | AdminMessage::ResponseStatusResponse(_)
        | AdminMessage::ResponseReleaseResponse(_)
        | AdminMessage::ResponseRestoreResponse(_)
        | AdminMessage::TelemetryStatusResponse(_)
        | AdminMessage::LoopProgressResponse(_)
        | AdminMessage::SignedUnlockResponse(_)
        | AdminMessage::RemediateRansomwareResponse(_) => {
            warn!("client sent server-only message variant; ignoring");
            AdminMessage::UnlockResult(UnlockResult::NoPendingChallenge)
        }

        #[cfg(feature = "debug-trigger")]
        AdminMessage::DebugForcePosture(state) => {
            let target = match state {
                nn_proto::admin_protocol::DebugForcePosture::Observing => {
                    nn_model::posture_types::PostureKind::Observing
                }
                nn_proto::admin_protocol::DebugForcePosture::Alerted => {
                    nn_model::posture_types::PostureKind::Alerted
                }
                nn_proto::admin_protocol::DebugForcePosture::Engaged => {
                    nn_model::posture_types::PostureKind::Engaged
                }
                nn_proto::admin_protocol::DebugForcePosture::Combat => {
                    nn_model::posture_types::PostureKind::Combat
                }
            };
            posture.force_state_for_test(target);
            AdminMessage::DebugForcePostureAck
        }

        #[cfg(feature = "debug-trigger")]
        AdminMessage::DebugForcePostureAck => {
            warn!("client sent DebugForcePostureAck; ignoring");
            AdminMessage::UnlockResult(UnlockResult::NoPendingChallenge)
        }
    }
}
