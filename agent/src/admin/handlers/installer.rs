//! The signed trusted-installer grant (R11d, lab PR 263: from
//! `admin_socket.rs`): the window an upgrade needs, armed for the signed
//! span.

use std::time::Instant;

use tracing::{info, warn};

use nn_proto::admin_protocol::{AdminResult, TrustedInstallerGrantRequest};

use crate::admin::verify::{signed, Verified};
use crate::anti_tamper::admin_auth::ConnAuth;
use crate::anti_tamper::trusted_installer::TrustedInstallerOverride;

/// FIM-009 self-upgrade (§15.1) — handle one
/// [`TrustedInstallerGrantRequest`]. Verifies the signed grant (M=1
/// quorum carrying `Role::TrustedInstaller`, with the full nonce +
/// agent_id + skew binding the standard `verify_signed_payload_quorum`
/// enforces), then arms the TTL'd FS-pin override + the NN-L-FIM-009
/// own-unit detection downgrade for the (clamped) signed window. The
/// ARM is recorded in the audit chain by `emit_audit_for`; the
/// close/expiry record is written by the override itself.
///
/// M=1 today — like COMBAT reactivation — but expressed through the
/// pipeline's quorum (`verify::Quorum`) so a future hardening can require
/// co-signers without touching this dispatcher.
pub(in crate::admin) fn dispatch_trusted_installer_grant(
    req: TrustedInstallerGrantRequest,
    auth: &ConnAuth<'_>,
    installer_override: Option<&TrustedInstallerOverride>,
    fps_out: &mut Vec<String>,
) -> AdminResult {
    // Required distinct signatures (M of N): 1 today, the pipeline's
    // (`verify::signed`); raise it there to harden.
    signed(
        &req,
        auth,
        fps_out,
        |r| r,
        |v| trusted_installer_grant(v, installer_override),
    )
}

/// The verified grant: the window armed for the (clamped) signed span.
fn trusted_installer_grant(
    v: Verified<'_, TrustedInstallerGrantRequest>,
    installer_override: Option<&TrustedInstallerOverride>,
) -> AdminResult {
    // The op/extra invariant is enforced inside the verify; this pulls
    // the signed window out.
    let window_secs = v.extra().window_secs;

    match installer_override {
        Some(ov) => {
            let window = ov.arm_by(
                window_secs,
                Instant::now(),
                v.fingerprints()
                    .first()
                    .map(String::as_str)
                    .unwrap_or("(unknown)"),
            );
            info!(
                target: "admin.trusted_installer_grant",
                signer_fp = %v.signer_fp(),
                window_secs = window.as_secs(),
                "trusted-installer override ARMED via signed grant (FIM-009 §15.1)"
            );
            AdminResult::Success
        }
        None => {
            // Legacy serve path with no override wired — verified but
            // nothing to arm. Surface as UnknownOperation so a stale
            // test fixture doesn't read as a successful arm.
            warn!(
                target: "admin.trusted_installer_grant",
                "trusted-installer grant verified but no override wired (legacy serve path)"
            );
            AdminResult::UnknownOperation
        }
    }
}
