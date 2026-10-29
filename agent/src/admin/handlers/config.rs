//! The signed `config overlay set` (R11d, lab PR 263: from
//! `admin_socket.rs`): an operator overlay and its signature, stored where
//! the agent reads them at boot.

use std::path::{Path, PathBuf};

use tracing::{info, warn};

use nn_proto::admin_protocol::{AdminResult, ConfigOverlaySetRequest, ConfigOverlaySetResponse};

use crate::admin::verify::{signed, Verified};
use crate::anti_tamper::admin_auth::ConnAuth;
use crate::decision::rule_policy::PolicyHandle;

/// Tappa 10.8 — handle one [`ConfigOverlaySetRequest`]: verify the
/// 1-of-N quorum carrying `Role::ConfigManage` (single-use challenge, skew,
/// agent_id), check that `content` is exactly what was signed and parses as
/// that overlay kind, then write the overlay and its `.sig` where the agent
/// reads it at boot. Takes effect at the next agent start.
pub(in crate::admin) fn dispatch_config_overlay_set(
    req: ConfigOverlaySetRequest,
    auth: &ConnAuth<'_>,
    rule_policy: &PolicyHandle,
    overlay_gate: Option<&crate::config::overlay_auth::OverlayGate>,
    fps_out: &mut Vec<String>,
) -> ConfigOverlaySetResponse {
    let refuse = |result: AdminResult, message: String| ConfigOverlaySetResponse {
        result,
        stored: false,
        message,
    };
    signed(
        &req,
        auth,
        fps_out,
        |r| refuse(r, "signature verification failed".to_string()),
        |v| config_overlay_set(v, auth, rule_policy, overlay_gate, refuse),
    )
}

/// The verified `config overlay set`: the content checked against what
/// was signed, then stored with its signature.
fn config_overlay_set(
    v: Verified<'_, ConfigOverlaySetRequest>,
    auth: &ConnAuth<'_>,
    rule_policy: &PolicyHandle,
    overlay_gate: Option<&crate::config::overlay_auth::OverlayGate>,
    refuse: impl Fn(AdminResult, String) -> ConfigOverlaySetResponse,
) -> ConfigOverlaySetResponse {
    use crate::config::overlay_auth;
    let req = v.request();
    let extra = v.extra();
    if req.content.len() > nn_proto::admin_protocol::MAX_OVERLAY_BYTES {
        return refuse(
            AdminResult::Success,
            format!(
                "content larger than {} bytes",
                nn_proto::admin_protocol::MAX_OVERLAY_BYTES
            ),
        );
    }
    if overlay_auth::content_sha256(req.content.as_bytes()) != extra.sha256
        || req.content.len() != extra.len as usize
    {
        return refuse(
            AdminResult::Success,
            "content does not match the signed hash".to_string(),
        );
    }
    if let Err(e) = overlay_auth::validate_content(extra.kind, &req.content) {
        return refuse(
            AdminResult::Success,
            format!("content does not parse: {e:#}"),
        );
    }
    let config_dir = auth
        .config_path()
        .and_then(|p| p.parent())
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("/etc/northnarrow"));
    let target = overlay_auth::configured_path(overlay_gate, extra.kind, &config_dir);
    let sigs: Vec<[u8; 64]> = req.signatures.iter().map(|s| s.signature).collect();
    let sig = match overlay_auth::OverlaySignature::new(req.payload.clone(), &sigs) {
        Ok(s) => s,
        Err(e) => return refuse(AdminResult::Success, format!("{e:#}")),
    };
    match crate::config::overlay_install::store(&target, &req.content, &sig) {
        // Lab PR 236: the per-rule policy is put in force at once, between
        // two events; the signed `config_overlay_set` row records it
        // (`applied` in its detail). R11c (lab PR 264): through the start's
        // handle, the one the engine and the posture read (it was the
        // process-wide `rule_policy::install_global`).
        Ok(sig_file) if extra.kind == nn_proto::admin_signed_payload::OverlayKind::RulePolicy => {
            use crate::decision::rule_policy as rp;
            let boot = rp::boot_policy(Some((&target, &req.content)));
            let summary = boot.policy.summary();
            let source = boot.policy.source.clone();
            let previous = rule_policy.install(boot.policy);
            warn!(
                target: "admin.config_overlay",
                path = %target.display(),
                source = %source,
                summary = %summary,
                previous = %previous.source,
                signer_fp = %v.signer_fp(),
                "signed per-rule response policy stored and applied"
            );
            ConfigOverlaySetResponse {
                result: AdminResult::Success,
                stored: true,
                message: format!(
                    "{} and {} written; applied now ({summary}; replaces {})",
                    target.display(),
                    sig_file.display(),
                    previous.source
                ),
            }
        }
        Ok(sig_file) => {
            info!(
                target: "admin.config_overlay",
                kind = extra.kind.keyword(),
                path = %target.display(),
                signer_fp = %v.signer_fp(),
                "signed overlay stored — takes effect at the next agent start"
            );
            ConfigOverlaySetResponse {
                result: AdminResult::Success,
                stored: true,
                message: format!(
                    "{} and {} written; restart the agent to apply (systemctl restart northnarrow-agent)",
                    target.display(),
                    sig_file.display()
                ),
            }
        }
        Err(e) => refuse(
            AdminResult::Success,
            format!("writing the overlay failed: {e:#}"),
        ),
    }
}
