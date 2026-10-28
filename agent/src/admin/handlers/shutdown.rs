//! The signed `shutdown` (R11d, lab PR 263: from `admin_socket.rs`): a
//! verified 2-of-N request writes the marker the watchdog verifies, then
//! signals the agent's exit.

use std::path::Path;

use tracing::{error, info, warn};

use nn_proto::admin_protocol::{AdminResult, ShutdownRequest};
use nn_proto::admin_signed_payload::{OperationCode, OperationExtra, Role};

use crate::admin::verify::now_unix_secs;
use crate::admin::ShutdownSignal;
use crate::anti_tamper::admin_auth::{AdminAuthError, ConnAuth};
use crate::shutdown_marker::{self, ShutdownMarker};

/// Handle one [`ShutdownRequest`] (Tappa 8 A7, design §10.3).
/// On verify success, atomically write the shutdown-authorisation
/// marker (so the watchdog will stand down when it observes the
/// agent's pidfd POLLIN — design §10.4) and return
/// [`AdminResult::Success`]. On verify failure, surface the
/// corresponding [`AdminResult`] variant; the marker is NOT
/// written, so the watchdog will respawn the agent normally if
/// the dispatcher later exits for any reason.
///
/// Note: this commit (A7) intentionally does NOT trigger the
/// agent's graceful exit. The dispatcher writes the marker and
/// replies; the actual `std::process::exit(0)` is part of A8's
/// integration story (which wires a shutdown channel from the
/// dispatcher → main.rs → the agent's tokio runtime). For now,
/// the cross-component contract is "marker on disk = the agent
/// authorised this exit"; production E2E will be exercised once
/// A8 lands the main-loop integration.
// PHASE_D_004: `fps_out` is an out-parameter populated on the
// success path with the 8-hex-char fingerprints of every
// matched signer. dispatch() reads this for emit_audit_for
// so the audit chain records WHICH operators authorised each
// signed action.
pub(in crate::admin) fn dispatch_shutdown(
    req: ShutdownRequest,
    auth: &ConnAuth<'_>,
    marker_path: &Path,
    shutdown_signal: Option<&ShutdownSignal>,
    fps_out: &mut Vec<String>,
) -> AdminResult {
    // Per §10.3 step 1: quorum verify (2-of-N including ≥1
    // Role::Shutdown). The integrated verify path
    // (verify_signed_payload_quorum) chains nonce-binding +
    // op-tag check + agent_id check + ±60s skew check + per-sig
    // verify_strict + distinct-key tally + role check, returning
    // the precise error so we can map to the wire variant.
    let server_now = now_unix_secs();
    let sigs: Vec<[u8; 64]> = req.signatures.iter().map(|s| s.signature).collect();

    let verify_outcome = auth.verify_signed_payload_quorum(
        &req.payload,
        &sigs,
        2,
        &[Role::Shutdown],
        OperationCode::Shutdown,
        server_now,
    );

    let (_token, matched_fps) = match verify_outcome {
        Ok(t) => t,
        Err(AdminAuthError::NoPendingChallenge) => return AdminResult::NoPendingChallenge,
        Err(AdminAuthError::NonceMismatch) => return AdminResult::InvalidSignature,
        Err(AdminAuthError::UnknownOperation { .. }) => return AdminResult::UnknownOperation,
        Err(AdminAuthError::AgentIdMismatch) => return AdminResult::AgentIdMismatch,
        Err(AdminAuthError::TimestampSkew {
            server_ts,
            max_skew_secs,
        }) => {
            return AdminResult::TimestampSkew {
                server_ts,
                max_skew_secs,
            };
        }
        Err(AdminAuthError::InvalidSignature) => return AdminResult::InvalidSignature,
        Err(AdminAuthError::QuorumNotMet { required, provided }) => {
            return AdminResult::QuorumNotMet { required, provided };
        }
        Err(AdminAuthError::RoleDenied { .. }) => return AdminResult::RoleDenied,
        Err(AdminAuthError::RateLimited { retry_after_secs }) => {
            return AdminResult::RateLimited { retry_after_secs };
        }
        Err(AdminAuthError::TooManySignatures { .. }) => return AdminResult::InvalidSignature,
        Err(AdminAuthError::PayloadVerify(e)) => {
            warn!(error = ?e, "shutdown payload verify failed at common layer");
            return AdminResult::InvalidSignature;
        }
    };

    // Per §10.3 step 2: the marker carries what the admins signed and
    // this agent's pid, so the watchdog can verify it against admin.pub
    // as we just did (external audit WDG-001) — a marker it cannot
    // verify makes it respawn us.
    //
    // External audit AUT-001: the verify above refuses a payload whose
    // extra is not a shutdown's (`admin_signed_payload::check_op`); it
    // only checked the op tag, and this fallback stood down with a grace
    // nobody signed. A payload that reaches here otherwise is refused.
    let grace_secs = match &req.payload.extra {
        OperationExtra::Shutdown(s) => s.grace_secs,
        other => {
            error!(
                extra = ?other.op_code(),
                "shutdown payload extra is not a shutdown's after verify — refused"
            );
            return AdminResult::UnknownOperation;
        }
    };
    *fps_out = matched_fps;
    let grace_deadline_unix_ts = server_now.saturating_add(u64::from(grace_secs));
    let marker = match ShutdownMarker::new(&req.payload, &sigs, std::process::id()) {
        Ok(m) => m,
        Err(e) => {
            warn!(error = ?e, "encoding the shutdown marker failed");
            return AdminResult::InvalidSignature;
        }
    };

    // Per §10.3 step 2 (atomic write): tmpfile + fsync + rename.
    if let Err(e) = shutdown_marker::write_marker(marker_path, &marker) {
        warn!(
            error = ?e,
            marker_path = %marker_path.display(),
            "failed to write shutdown-authorisation marker — refusing to ack"
        );
        // Refuse to ack the operator — without the marker, the
        // watchdog won't stand down and we'd just respawn after
        // exit. Surface as InvalidSignature so the client retries.
        return AdminResult::InvalidSignature;
    }

    info!(
        target: "admin.shutdown",
        grace_secs,
        grace_deadline_unix_ts,
        marker_path = %marker_path.display(),
        "shutdown authorised — marker written, watchdog will stand down on next pidfd POLLIN"
    );

    // Tappa 8 A8: signal the agent's main loop that an
    // admin-authorised shutdown has begun. The marker is already on
    // disk (the watchdog's cross-component contract) BEFORE we fire
    // here, so the ordering is: disk → in-process signal → wire
    // reply. If the signal is `None` (legacy `serve()` callers or
    // tests that aren't exercising the exit path), we still wrote
    // the marker — the contract with the watchdog is intact, only
    // the in-process exit is uninstrumented.
    if let Some(sig) = shutdown_signal {
        sig.fire();
    }

    AdminResult::Success
}
