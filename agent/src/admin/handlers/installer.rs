/// FIM-009 self-upgrade (§15.1) — handle one
/// [`TrustedInstallerGrantRequest`]. Verifies the signed grant (M=1
/// quorum carrying [`Role::TrustedInstaller`], with the full nonce +
/// agent_id + skew binding the standard `verify_signed_payload_quorum`
/// enforces), then arms the TTL'd FS-pin override + the NN-L-FIM-009
/// own-unit detection downgrade for the (clamped) signed window. The
/// ARM is recorded in the audit chain by `emit_audit_for`; the
/// close/expiry record is written by the override itself.
///
/// M=1 today — like COMBAT reactivation — but expressed through
/// `min_distinct` so a future hardening can require co-signers without
/// touching this dispatcher.
fn dispatch_trusted_installer_grant(
    req: TrustedInstallerGrantRequest,
    auth: &ConnAuth<'_>,
    installer_override: Option<&TrustedInstallerOverride>,
    fps_out: &mut Vec<String>,
) -> AdminResult {
    // Required distinct signatures (M of N). 1 today; raise to harden.
    const TRUSTED_INSTALLER_QUORUM: u8 = 1;

    let server_now = now_unix_secs();
    let sigs: Vec<[u8; 64]> = req.signatures.iter().map(|s| s.signature).collect();

    let (_token, matched_fps) = match auth.verify_signed_payload_quorum(
        &req.payload,
        &sigs,
        TRUSTED_INSTALLER_QUORUM,
        &[Role::TrustedInstaller],
        OperationCode::TrustedInstallerGrant,
        server_now,
    ) {
        Ok(t) => t,
        Err(e) => return map_admin_auth_error(e, "trusted-installer-grant"),
    };
    *fps_out = matched_fps;

    // The op/extra invariant is already enforced inside
    // verify_signed_payload_quorum; this pulls the signed window out.
    let window_secs = match &req.payload.extra {
        OperationExtra::TrustedInstallerGrant(extra) => extra.window_secs,
        other => {
            warn!(
                extra = ?other,
                "trusted-installer-grant payload extra is not TrustedInstallerGrant variant"
            );
            return AdminResult::UnknownOperation;
        }
    };

    match installer_override {
        Some(ov) => {
            let window = ov.arm_by(
                window_secs,
                Instant::now(),
                fps_out.first().map(String::as_str).unwrap_or("(unknown)"),
            );
            info!(
                target: "admin.trusted_installer_grant",
                signer_fp = %fps_out.first().map(String::as_str).unwrap_or(""),
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
