//! The signed `config overlay set` (R11d, lab PR 263: from
//! `admin_socket.rs`): an operator overlay and its signature, stored where
//! the agent reads them at boot.

use std::path::{Path, PathBuf};

use tracing::{info, warn};

use nn_proto::admin_protocol::{AdminResult, ConfigOverlaySetRequest, ConfigOverlaySetResponse};
use nn_proto::admin_signed_payload::{OperationCode, OperationExtra, Role};

use crate::admin::verify::{map_admin_auth_error, now_unix_secs};
use crate::anti_tamper::admin_auth::ConnAuth;

/// Tappa 10.8 — handle one [`ConfigOverlaySetRequest`]: verify the
/// 1-of-N quorum carrying `Role::ConfigManage` (single-use challenge, skew,
/// agent_id), check that `content` is exactly what was signed and parses as
/// that overlay kind, then write the overlay and its `.sig` where the agent
/// reads it at boot. Takes effect at the next agent start.
pub(in crate::admin) fn dispatch_config_overlay_set(
    req: ConfigOverlaySetRequest,
    auth: &ConnAuth<'_>,
    fps_out: &mut Vec<String>,
) -> ConfigOverlaySetResponse {
    use crate::config::overlay_auth;
    const CONFIG_OVERLAY_QUORUM: u8 = 1;
    let refuse = |result: AdminResult, message: String| ConfigOverlaySetResponse {
        result,
        stored: false,
        message,
    };
    let sigs: Vec<[u8; 64]> = req.signatures.iter().map(|s| s.signature).collect();
    let (_token, matched_fps) = match auth.verify_signed_payload_quorum(
        &req.payload,
        &sigs,
        CONFIG_OVERLAY_QUORUM,
        &[Role::ConfigManage],
        OperationCode::ConfigOverlaySet,
        now_unix_secs(),
    ) {
        Ok(t) => t,
        Err(e) => {
            let r = map_admin_auth_error(e, "config-overlay-set");
            return refuse(r, "signature verification failed".to_string());
        }
    };
    *fps_out = matched_fps;
    let OperationExtra::ConfigOverlaySet(extra) = &req.payload.extra else {
        return refuse(
            AdminResult::UnknownOperation,
            "not a config-overlay payload".to_string(),
        );
    };
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
    let target = overlay_auth::configured_path(extra.kind, &config_dir);
    let sig = match overlay_auth::OverlaySignature::new(req.payload.clone(), &sigs) {
        Ok(s) => s,
        Err(e) => return refuse(AdminResult::Success, format!("{e:#}")),
    };
    match crate::config::overlay_install::store(&target, &req.content, &sig) {
        // Lab PR 236: the per-rule policy is put in force at once, between
        // two events; the signed `config_overlay_set` row records it
        // (`applied` in its detail).
        Ok(sig_file) if extra.kind == nn_proto::admin_signed_payload::OverlayKind::RulePolicy => {
            use crate::decision::rule_policy as rp;
            let boot = rp::boot_policy(Some((&target, &req.content)));
            let summary = boot.policy.summary();
            let source = boot.policy.source.clone();
            let previous = rp::install_global(boot.policy);
            warn!(
                target: "admin.config_overlay",
                path = %target.display(),
                source = %source,
                summary = %summary,
                previous = %previous.source,
                signer_fp = %fps_out.first().map(String::as_str).unwrap_or(""),
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
                signer_fp = %fps_out.first().map(String::as_str).unwrap_or(""),
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
