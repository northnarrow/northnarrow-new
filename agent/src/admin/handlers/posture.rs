//! The signed `force-posture` (R11d, lab PR 263: from `admin_socket.rs`):
//! the posture the administrator orders, out of COMBAT only with a signer
//! holding `unlock`.

use tracing::{error, info, warn};

use nn_proto::admin_protocol::{AdminResult, ForcePostureRequest};
use nn_proto::admin_signed_payload::Role;

use crate::admin::audit::DispatchNotes;
use crate::admin::verify::{signed, Verified};
use crate::anti_tamper::admin_auth::ConnAuth;
use crate::posture::{AdminReleaseError, PostureMachine};

/// Tappa 8 A10 — handle one [`ForcePostureRequest`] (design §4 +
/// §12.2). Distinct from the existing `cfg(debug-trigger)`
/// `DebugForcePosture` arm: that one bypasses every authentication
/// layer for integration testing; this one runs the full Tappa-8
/// verify path AND honours the role allowlist.
///
/// Quorum semantics: 1-of-N per §3.3 (unlike shutdown's 2-of-N).
/// Required role: [`Role::ForcePosture`]. Expected op tag:
/// `OperationCode::ForcePosture`. The signed payload's `extra`
/// MUST be `OperationExtra::ForcePosture { target }`; any other
/// extra variant trips the op/extra invariant check inside
/// [`crate::anti_tamper::admin_auth::ConnAuth::verify_signed_payload_quorum`]
/// (Tappa 8 A7) and surfaces as `UnknownOperation` on the wire.
///
/// On verify success, mutates the posture machine to the requested
/// target via [`PostureMachine::admin_force_state_signed_by`]
/// (Tappa 8 A10, lab PR 245: the token, whether a signer holds `unlock`,
/// and the signers a COMBAT it enters cites), which fires the COMBAT
/// entry/release hooks per §12.2 if the direction crosses the COMBAT
/// boundary.
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
pub(in crate::admin) fn dispatch_force_posture(
    req: ForcePostureRequest,
    auth: &ConnAuth<'_>,
    posture: &PostureMachine,
    fps_out: &mut Vec<String>,
    notes: &mut DispatchNotes,
) -> AdminResult {
    signed(
        &req,
        auth,
        fps_out,
        |r| r,
        |v| force_posture(v, posture, notes),
    )
}

/// The verified `force-posture`: the transition, through the posture's
/// capability-gated path.
fn force_posture(
    v: Verified<'_, ForcePostureRequest>,
    posture: &PostureMachine,
    notes: &mut DispatchNotes,
) -> AdminResult {
    // External audit NN-AUD-083: may this request release COMBAT?
    let may_release = v.keys().iter().any(|k| k.authorizes(Role::Unlock));

    // The target of the verified payload. The verify checks the op/extra
    // invariant (`admin_signed_payload::check_op`, external audit AUT-001
    // — before it, only the op tag was checked and a match here was the
    // only guard), so the extra is the ForcePosture variant.
    let target = v.extra().target;

    // Drive the posture mutation through the capability-gated path.
    // `admin_force_state_signed_by` consumes the token, fires
    // hooks per §12.2, and returns the state it left and the
    // post-transition state. It refuses COMBAT → non-COMBAT without
    // `may_release`; any other error shape maps to InvalidSignature
    // defensively. Lab PR 245: a COMBAT it enters names the keys that
    // signed the order as its cause, in the ladder's signed rows.
    let fps = v.fingerprints().to_vec();
    let signer_fp = v.signer_fp().to_string();
    match posture.admin_force_state_signed_by(v.into_token(), target, may_release, fps) {
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
                signer_fp = %signer_fp,
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
