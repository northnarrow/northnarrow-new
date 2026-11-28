//! Lot 2.3b (D1, the design's "Trusted-installer window per process tree",
//! section 2): what a member of the open window asks of the agent itself,
//! since PID 1 gets nothing from a window — the controlled stop or restart
//! of the agent, and the single-use leases for PID 1's removal of our
//! units' enablement links. Not signed: the agent authenticates the asker
//! by its pidfd (the socket's peer, pinned before it is read), its member
//! entry and the window's generation
//! ([`TrustedInstallerOverride::window_member`]). An outsider's request is
//! refused, signed with its reason.

use std::path::Path;

use tracing::{info, warn};

use nn_proto::admin_protocol::{
    AdminResult, LeaseAction, WindowAction, WindowControlRequest, WindowLeaseRequest, WindowReply,
};

use crate::admin::ShutdownSignal;
use crate::anti_tamper::trusted_installer::TrustedInstallerOverride;
use crate::shutdown_marker::{self, ShutdownMarker};

/// Lot 2.3b: a member's request refused — signed with its reason, answered
/// `ActionFailed` with it.
fn refused(ov: &TrustedInstallerOverride, what: &str, why: String) -> WindowReply {
    warn!(
        target: "admin.trusted_installer_grant",
        what,
        reason = %why,
        "a window member's request REFUSED"
    );
    ov.note_member_refusal(what, &why);
    WindowReply::new(AdminResult::ActionFailed, 0, &why)
}

/// Lot 2.3b (D1): the controlled stop or restart asked by `requester` (the
/// socket's peer). A member of the window `req.generation` gets it: the
/// record naming it is signed, then — for a stop — the watchdog's
/// stand-down (the window's signed grant, at `marker_path`, which the
/// watchdog verifies against `admin.pub`) is written, and the run loop is
/// woken to exit with the controlled reason; a restart leaves the watchdog
/// to start the agent again at once. PID 1's stop signals stay refused.
pub(in crate::admin) fn dispatch_window_control(
    req: WindowControlRequest,
    installer_override: Option<&TrustedInstallerOverride>,
    requester: u32,
    marker_path: &Path,
    shutdown_signal: Option<&ShutdownSignal>,
) -> WindowReply {
    let Some(ov) = installer_override else {
        return WindowReply::new(AdminResult::UnknownOperation, 0, "");
    };
    let what = match req.action {
        WindowAction::Stop => "controlled_stop",
        WindowAction::Restart => "controlled_restart",
    };
    let member = match ov.window_member(requester, req.generation) {
        Ok(m) => m,
        Err(why) => return refused(ov, what, why),
    };
    let restart = matches!(req.action, WindowAction::Restart);
    // the stand-down's proof is checked before anything is recorded as asked
    let proof = if restart {
        None
    } else {
        match ov.tree_proof(req.generation) {
            Some(p) => Some(p),
            None => {
                return refused(
                    ov,
                    what,
                    "the window's signed grant is not held: no stand-down can be written".to_string(),
                );
            }
        }
    };
    let reason = match ov.controlled_stop(member, req.generation, restart) {
        Ok(r) => r,
        Err(why) => return refused(ov, what, why),
    };
    if let Some((payload, sigs)) = proof {
        let written = ShutdownMarker::new(&payload, &sigs, std::process::id())
            .map_err(|e| format!("encoding the stand-down: {e:?}"))
            .and_then(|m| {
                shutdown_marker::write_marker(marker_path, &m)
                    .map_err(|e| format!("writing the stand-down: {e:#}"))
            });
        if let Err(why) = written {
            ov.withdraw_controlled_stop();
            return refused(ov, what, why);
        }
    }
    info!(
        target: "admin.trusted_installer_grant",
        reason,
        member = member.0,
        generation = req.generation,
        "controlled stop asked by a member of the window — the agent stops"
    );
    match shutdown_signal {
        Some(s) => s.fire(),
        None => warn!("controlled stop recorded but no shutdown signal wired (legacy serve path)"),
    }
    let detail = if restart {
        "the agent restarts (the watchdog starts it again)"
    } else {
        "the agent and the watchdog stand down"
    };
    WindowReply::new(AdminResult::Success, req.generation, detail)
}

/// Lot 2.3b (the single-use leases): a lease for PID 1's removal of our
/// units' enablement link `req.link`, asked by `requester`, a member of the
/// window `req.generation`. A creation (an enable) is never refused, so no
/// lease is armed for it: the reply says so. Each lease armed, and each
/// refusal, is signed.
pub(in crate::admin) fn dispatch_window_lease(
    req: WindowLeaseRequest,
    installer_override: Option<&TrustedInstallerOverride>,
    requester: u32,
) -> WindowReply {
    let Some(ov) = installer_override else {
        return WindowReply::new(AdminResult::UnknownOperation, 0, "");
    };
    let member = match ov.window_member(requester, req.generation) {
        Ok(m) => m,
        Err(why) => return refused(ov, "lease", why),
    };
    if req.action == LeaseAction::Create {
        return WindowReply::new(
            AdminResult::Success,
            req.generation,
            "a link's creation (an enable) is never refused: no lease is armed",
        );
    }
    match ov.arm_lease(member, req.generation, &req.link) {
        Ok(slot) => WindowReply::new(
            AdminResult::Success,
            req.generation,
            &format!(
                "lease armed (slot {slot}) for PID 1's removal of {}, for {} s at most, once",
                req.link,
                common::wire::WINDOW_LEASE_TTL_NS / 1_000_000_000
            ),
        ),
        Err(why) => refused(ov, "lease", why),
    }
}
