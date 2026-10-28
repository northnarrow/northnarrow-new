/// Tappa 8 A10 — handle one [`ForcePostureRequest`] (design §4 +
/// §12.2). Distinct from the existing `cfg(debug-trigger)`
/// `DebugForcePosture` arm: that one bypasses every authentication
/// layer for integration testing; this one runs the full Tappa-8
/// verify path AND honours the role allowlist.
///
/// Quorum semantics: 1-of-N per §3.3 (unlike shutdown's 2-of-N).
/// Required role: [`Role::ForcePosture`]. Expected op tag:
/// [`OperationCode::ForcePosture`]. The signed payload's `extra`
/// MUST be [`OperationExtra::ForcePosture { target }`]; any other
/// extra variant trips the op/extra invariant check inside
/// [`crate::anti_tamper::admin_auth::ConnAuth::verify_signed_payload_quorum`]
/// (Tappa 8 A7) and surfaces as `UnknownOperation` on the wire.
///
/// On verify success, mutates the posture machine to the requested
/// target via [`PostureMachine::admin_force_state_with_token`]
/// (Tappa 8 A10), which fires the COMBAT entry/release hooks per
/// §12.2 if the direction crosses the COMBAT boundary.
///
/// External audit NN-AUD-083: leaving COMBAT this way releases the
/// containment exactly like `unlock`, so it also needs a signer that
/// holds [`Role::Unlock`]. The posture machine checks it under its own
/// state lock (an autonomous COMBAT entry may land between this
/// dispatcher and the transition); a refusal answers `RoleDenied`.
/// Entering COMBAT stays 1-of-N `force-posture` (POS-001: the
/// administrator forces it).
///
/// External audit ASK-015: the journal line and the audit row (through
/// `notes.force_from`) name the state the force left, as the posture
/// machine read it under its lock; they named the state it entered.
fn dispatch_force_posture(
    req: ForcePostureRequest,
    auth: &ConnAuth<'_>,
    posture: &PostureMachine,
    fps_out: &mut Vec<String>,
    notes: &mut DispatchNotes,
) -> AdminResult {
    let server_now = now_unix_secs();
    let sigs: Vec<[u8; 64]> = req.signatures.iter().map(|s| s.signature).collect();

    let verify_outcome = auth.verify_signed_payload_quorum_keys(
        &req.payload,
        &sigs,
        1, // 1-of-N per §3.3
        &[Role::ForcePosture],
        OperationCode::ForcePosture,
        server_now,
    );

    let signers = match verify_outcome {
        Ok(v) => v,
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
            warn!(error = ?e, "force-posture payload verify failed at common layer");
            return AdminResult::InvalidSignature;
        }
    };
    *fps_out = signers.fingerprints;
    // External audit NN-AUD-083: may this request release COMBAT?
    let may_release = signers.keys.iter().any(|k| k.authorizes(Role::Unlock));

    // Extract the target from the verified payload. The verify checks
    // the op/extra invariant (`admin_signed_payload::check_op`, external
    // audit AUT-001 — before it, only the op tag was checked and this
    // match was the only guard), so this is the ForcePosture variant; the
    // match keeps the compiler exhaustive and refuses with
    // UnknownOperation if a future refactor ever breaks the invariant.
    let target = match &req.payload.extra {
        OperationExtra::ForcePosture(extra) => extra.target,
        other => {
            warn!(
                extra = ?other,
                "force-posture payload extra is not ForcePosture variant — \
                 op/extra invariant breach"
            );
            return AdminResult::UnknownOperation;
        }
    };

    // Drive the posture mutation through the capability-gated path.
    // `admin_force_state_signed_by` consumes the token, fires
    // hooks per §12.2, and returns the state it left and the
    // post-transition state. It refuses COMBAT → non-COMBAT without
    // `may_release`; any other error shape maps to InvalidSignature
    // defensively. Lab PR 245: a COMBAT it enters names the keys that
    // signed the order as its cause, in the ladder's signed rows.
    match posture.admin_force_state_signed_by(signers.token, target, may_release, fps_out.clone()) {
        Ok(outcome) => {
            notes.force_from = Some(outcome.from);
            notes.force_release = outcome.release.map(Ok);
            info!(
                target: "admin.force_posture",
                from = ?outcome.from,
                to = ?outcome.state.kind(),
                "production force-posture applied"
            );
            AdminResult::Success
        }
        Err(AdminReleaseError::NeedsUnlock) => {
            warn!(
                target: "admin.force_posture",
                to = ?target,
                signer_fp = %fps_out.first().map(String::as_str).unwrap_or(""),
                "force-posture out of COMBAT refused: no signer holds the `unlock` role"
            );
            AdminResult::RoleDenied
        }
        // Lab PR 217 (NN-AUD-243 residue): leaving COMBAT released nothing
        // the tables confirm — the posture stays COMBAT, and the reply says
        // the request was not carried out (it was `Success`).
        Err(AdminReleaseError::ReleaseFailed(why)) => {
            error!(
                target: "admin.force_posture",
                to = ?target,
                why = %why,
                "force-posture out of COMBAT verified, but the isolation was NOT released — \
                 the posture stays COMBAT"
            );
            notes.force_release = Some(Err(why));
            AdminResult::ActionFailed
        }
        Err(e) => {
            warn!(
                error = ?e,
                target = ?target,
                "admin_force_state_with_token errored unexpectedly"
            );
            AdminResult::InvalidSignature
        }
    }
}
