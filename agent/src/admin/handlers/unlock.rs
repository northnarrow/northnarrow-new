//! The signed `unlock` (R11d, lab PR 263: from `admin_socket.rs`): a
//! verified request releases COMBAT through the posture, and the reply says
//! what the release did.

use tracing::{error, info};

use nn_proto::admin_protocol::{AdminResult, SignedUnlockRequest, SignedUnlockResponse};

use crate::admin::verify::{signed, Verified};
use crate::anti_tamper::admin_auth::ConnAuth;
use crate::anti_tamper::network_isolate::{Family, NetworkIsolator};
use crate::posture::{AdminReleaseError, PostureMachine};

/// Lab PR 217 (NN-AUD-243 residue, capability C17) — handle one signed
/// `unlock` (`OperationCode::Unlock`, 1-of-N, `Role::Unlock`): verify, run
/// the release through the posture — the ladder stood down, the iptables
/// teardown read back per family — and answer what it did.
///
/// `Success` only when the release was carried out and the tables read
/// back clear (or there was nothing to release); a verified request whose
/// teardown did not leave them clear is [`AdminResult::ActionFailed`] with
/// why, and the posture stays COMBAT (external audit ASK-017 / NN-AUD-243:
/// this was `Success`, recorded "success", whatever the teardown did). The
/// signer's fingerprint goes to the audit row.
pub(in crate::admin) fn dispatch_signed_unlock(
    req: SignedUnlockRequest,
    auth: &ConnAuth<'_>,
    posture: &PostureMachine,
    isolator: &NetworkIsolator,
    fps_out: &mut Vec<String>,
) -> SignedUnlockResponse {
    let reply = |result: AdminResult, released: bool, message: String| SignedUnlockResponse {
        result,
        released,
        isolation_v4: isolator.is_isolated(Family::V4),
        isolation_v6: isolator.is_isolated(Family::V6),
        message,
    };
    signed(
        &req,
        auth,
        fps_out,
        |r| reply(r, false, "signature verification failed".to_string()),
        |v| signed_unlock(v, posture, reply),
    )
}

/// The verified `unlock`: the release, and what it did.
fn signed_unlock(
    v: Verified<'_, SignedUnlockRequest>,
    posture: &PostureMachine,
    reply: impl Fn(AdminResult, bool, String) -> SignedUnlockResponse,
) -> SignedUnlockResponse {
    let signer = v.signer_fp().to_string();
    match posture.admin_release_combat_with_token(v.into_token()) {
        Ok(out) => {
            let message = if out.left_combat {
                format!(
                    "COMBAT released, posture {}: {}",
                    out.state.kind(),
                    out.detail
                )
            } else {
                format!(
                    "not in COMBAT (posture {}): {}",
                    out.state.kind(),
                    out.detail
                )
            };
            info!(
                target: "admin.unlock",
                signer_fp = %signer,
                outcome = %message,
                "signed unlock carried out"
            );
            reply(AdminResult::Success, true, message)
        }
        Err(e) => {
            error!(
                target: "admin.unlock",
                signer_fp = %signer,
                error = %e,
                "signed unlock verified, but the isolation was NOT released — answering a \
                 failure; the posture stays {}",
                posture.current_kind()
            );
            let why = match e {
                AdminReleaseError::ReleaseFailed(why) => why,
                other => other.to_string(),
            };
            reply(
                AdminResult::ActionFailed,
                false,
                format!(
                    "the isolation was NOT released, the posture stays {}: {why}",
                    posture.current_kind()
                ),
            )
        }
    }
}
