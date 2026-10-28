//! The canary verbs (R11d, lab PR 263: from `admin_socket.rs`): deploy,
//! list, burn and refresh.

use anyhow::Result;
use tracing::{info, warn};

use nn_proto::admin_protocol::{
    AdminResult, CanaryBurnRequest, CanaryDeployRequest, CanaryDeployResponse, CanaryListRequest,
    CanaryListResponse, CanaryRefreshRequest,
};
use nn_proto::admin_signed_payload::{OperationCode, Role};
use sha2::{Digest, Sha256};

use super::read::read_tail_jsonl;
use crate::admin::verify::{map_admin_auth_error, now_unix_secs};
use crate::admin::CanaryAdminState;
use crate::anti_tamper::admin_auth::ConnAuth;
use crate::canary::registry::{CanaryToken, CanaryTokenDraft, DecoyContent, RegistryError};

// ── Tappa 9.5 K6 — canary admin dispatch handlers ───────────────────

/// Rebuild the K3 detector's hot-path indexes from the K2
/// registry snapshot. Called by every successful canary
/// deploy / burn / refresh dispatch so the detector sees the
/// new state on the next inbound `Event::Fim` /
/// `Event::ProcessSpawn`. The `inode_resolver` closure
/// stats() each File/Credential canary path to populate the
/// inode_index — files that don't yet exist (deploy race)
/// fall back to the path-based exe_index pathway K3 already
/// uses (V1.0 pragmatism documented in K3 module doc).
/// The decoy path of a File or Credential canary.
pub fn canary_path(
    deployment: &nn_proto::admin_signed_payload::CanaryDeploymentWire,
) -> Option<&str> {
    use nn_proto::admin_signed_payload::CanaryDeploymentWire;
    match deployment {
        CanaryDeploymentWire::File { path, .. } | CanaryDeploymentWire::Credential { path, .. } => {
            Some(path)
        }
        _ => None,
    }
}

/// External audit DEC-001: watch a decoy's inode through the FIM. External
/// audit NN-AUD-120 (FIMP-008): `false` when it cannot be — the kernel
/// watch map refused it (full of entries that are never evicted, or
/// absent), or the FIM is not running — and the deploy is refused: a decoy
/// whose opens are not seen never trips, and the deploy used to answer
/// Success with only a WARN in the journal.
pub(in crate::admin) fn watch_decoy(
    state: &CanaryAdminState,
    key: common::wire::InodeKey,
    path: &str,
) -> bool {
    match &state.fim_watch {
        Some(watch) => {
            if watch.watch(key, path, crate::fim::drain::WatchClass::Decoy) {
                return true;
            }
            tracing::error!(
                path,
                "canary: the kernel watch map refused the decoy (full, or absent) — its opens \
                 would not be seen; deploy refused"
            );
            false
        }
        None => {
            tracing::error!(
                path,
                "canary: FIM is not running — the decoy's opens would not be seen; deploy refused"
            );
            false
        }
    }
}

/// What a decoy's inode was watched as before the deploy watched it: a
/// decoy written over a watched file (a credential canary at a watched
/// credential path) keeps that file's inode.
type PriorWatch = Option<(String, crate::fim::drain::WatchClass)>;

fn prior_watch(state: &CanaryAdminState, key: common::wire::InodeKey) -> PriorWatch {
    let watch = state.fim_watch.as_ref()?;
    Some((watch.path_map.lookup(&key)?, watch.path_map.class_of(&key)?))
}

/// Undo the watch of a decoy the deploy did not keep: the inode goes back
/// to what it was watched as, or stops being watched (the drain must not
/// name an inode the kernel does not report).
fn undo_decoy_watch(state: &CanaryAdminState, key: common::wire::InodeKey, prior: PriorWatch) {
    let Some(watch) = &state.fim_watch else {
        return;
    };
    match prior {
        Some((path, class)) => {
            let _ = watch.path_map.insert_as(key, path, class);
        }
        None => watch.unwatch(key),
    }
}

fn rebuild_canary_indexes(state: &CanaryAdminState) {
    // External audit DEC-003: the same rebuild the boot runs.
    let mut idx = state.indexes.lock();
    let reg = state.registry.lock();
    idx.rebuild_live(&reg);
}

/// dispatch_canary_deploy — verify 1-of-N quorum with
/// Role::CanaryManage, render template (for Credential
/// canaries) + write the canary file to disk (for
/// File/Credential), call Registry::deploy, rebuild indexes,
/// return the freshly-allocated canary_id. Per §12 Q1
/// EXPLICIT-PER-HOST lock-in: this is the ONLY way canaries
/// get on-host (no default deployments).
pub(in crate::admin) fn dispatch_canary_deploy(
    req: CanaryDeployRequest,
    auth: &ConnAuth<'_>,
    state: Option<&CanaryAdminState>,
    fps_out: &mut Vec<String>,
) -> CanaryDeployResponse {
    use nn_proto::admin_signed_payload::OperationExtra;

    let server_now = now_unix_secs();
    let sigs: Vec<[u8; 64]> = req.signatures.iter().map(|s| s.signature).collect();
    let (_token, matched_fps) = match auth.verify_signed_payload_quorum(
        &req.payload,
        &sigs,
        1,
        &[Role::CanaryManage],
        OperationCode::CanaryDeploy,
        server_now,
    ) {
        Ok(t) => t,
        Err(e) => {
            return CanaryDeployResponse {
                result: map_admin_auth_error(e, "canary-deploy"),
                canary_id: String::new(),
            };
        }
    };
    *fps_out = matched_fps;

    let extra = match &req.payload.extra {
        OperationExtra::CanaryDeploy(e) => e.clone(),
        _ => {
            warn!("canary-deploy payload extra is not CanaryDeploy variant");
            return CanaryDeployResponse {
                result: AdminResult::UnknownOperation,
                canary_id: String::new(),
            };
        }
    };

    let state = match state {
        Some(s) => s,
        None => {
            warn!("canary-deploy: agent boot did not wire CanaryAdminState — rejecting");
            return CanaryDeployResponse {
                result: AdminResult::UnknownOperation,
                canary_id: String::new(),
            };
        }
    };

    let primary_fp = fps_out.first().cloned().unwrap_or_default();

    // External audit DEC-015 (lab PR 178): a File / Credential path is
    // judged, written, recorded and watched in its normal form (`//`
    // folded) — the deny prefixes used to be matched on the raw string.
    let mut extra = extra;
    extra.deployment = match crate::canary::path_policy::normalised_deployment(&extra.deployment) {
        Ok(d) => d,
        Err(e) => {
            warn!(
                error = %format!("{e:#}"),
                signer_fp = %primary_fp,
                "canary-deploy: REFUSED — canary path"
            );
            return CanaryDeployResponse {
                result: AdminResult::UnknownOperation,
                canary_id: String::new(),
            };
        }
    };

    // Lab PR 163: a network canary trips on a connect to its address and
    // port (`canary::network`). One whose address is not an IP address
    // could never trip, and one where a listener on this host takes the
    // connections would trip on every client of that service.
    if let nn_proto::admin_signed_payload::CanaryDeploymentWire::Network {
        bind_addr,
        bind_port,
    } = &extra.deployment
    {
        if let Err(why) = crate::canary::network::check_deployable(bind_addr, *bind_port) {
            warn!(
                signer_fp = %primary_fp,
                bind_addr = %bind_addr,
                bind_port = *bind_port,
                reason = %why,
                "canary-deploy: REFUSED — network canary"
            );
            return CanaryDeployResponse {
                result: AdminResult::UnknownOperation,
                canary_id: String::new(),
            };
        }
    }

    // For File + Credential types: render the file content +
    // write to the deployment path. The K3 detector matches
    // on the resulting inode (after rebuild_canary_indexes
    // stats it).
    let (decoy, content) = match materialise_canary_file(&extra.deployment, state) {
        Ok(m) => m,
        Err(e) => {
            warn!(
                error = %format!("{e:#}"),
                signer_fp = %primary_fp,
                "canary-deploy: REFUSED — file materialisation failed (path policy or I/O)"
            );
            return CanaryDeployResponse {
                result: AdminResult::UnknownOperation,
                canary_id: String::new(),
            };
        }
    };

    // External audit DEC-001: have the kernel report the decoy's opens,
    // and the drain name them — a decoy outside the FIM path list was
    // never watched, so it never tripped. NN-AUD-120: watched before it is
    // registered; one that cannot be watched is refused, not registered.
    let prior = decoy.and_then(|key| prior_watch(state, key));
    if let (Some(key), Some(path)) = (decoy, canary_path(&extra.deployment)) {
        if !watch_decoy(state, key, path) {
            undo_decoy_watch(state, key, prior.clone());
            warn!(
                signer_fp = %primary_fp,
                path,
                "canary-deploy: REFUSED — the decoy cannot be watched; the file written at the \
                 path is left in place (remove it, or deploy again once the FIM watches)"
            );
            return CanaryDeployResponse {
                result: AdminResult::UnknownOperation,
                canary_id: String::new(),
            };
        }
    }

    // Deploy via the K2 registry. Allocates the canary_id +
    // appends the Deploy row to the chain.
    let draft = CanaryTokenDraft {
        name: extra.name.clone(),
        canary_type: extra.canary_type,
        deployment: extra.deployment.clone(),
        deployed_by_fp: primary_fp.clone(),
        content,
    };
    let entry = {
        let mut reg = state.registry.lock();
        match reg.deploy(draft) {
            Ok(e) => e,
            Err(e) => {
                warn!(error = %e, "canary registry deploy failed");
                // not a canary: its decoy is not watched as one either
                if let Some(key) = decoy {
                    undo_decoy_watch(state, key, prior);
                }
                return CanaryDeployResponse {
                    result: AdminResult::UnknownOperation,
                    canary_id: String::new(),
                };
            }
        }
    };

    // Refresh the K3 detector's hot-path indexes so the new
    // canary is visible to the next inbound event.
    rebuild_canary_indexes(state);

    info!(
        target: "admin.canary_deploy",
        signer_fp = %primary_fp,
        canary_id = %entry.canary_id,
        canary_name = %nn_model::log_escape::Escaped(&entry.name),
        "canary deployed"
    );
    CanaryDeployResponse {
        result: AdminResult::Success,
        canary_id: entry.canary_id,
    }
}

/// Write the canary file to its deployment path: for a `Credential`
/// canary the K4 template of its `cred_family`, for a `File` canary
/// [`crate::canary::templates::render_file_body`]. Both from a fresh
/// random seed (external audit DEC-008: it used to be `<operator key
/// fingerprint>:<path>`, which printed the fingerprint into the decoy
/// and gave every host the same credential), with no marker in the bytes
/// (DEC-007: the File body used to name the product, the operator key
/// and the rule). Returns the decoy's inode and what it was written with
/// — its SHA-256 and seed, for the registry row (DEC-010). Process +
/// Network canaries write nothing: `(None, None)`.
pub(in crate::admin) fn materialise_canary_file(
    deployment: &nn_proto::admin_signed_payload::CanaryDeploymentWire,
    state: &CanaryAdminState,
) -> Result<(Option<common::wire::InodeKey>, Option<DecoyContent>)> {
    use crate::canary::templates::{new_content_seed, render, render_file_body, CredFamily};
    use nn_proto::admin_signed_payload::CanaryDeploymentWire;
    let seed = new_content_seed();
    let (path, body) = match deployment {
        CanaryDeploymentWire::File { path, .. } => (path, render_file_body(&seed)),
        CanaryDeploymentWire::Credential { path, cred_family } => {
            let family = CredFamily::from_wire(cred_family)
                .map_err(|e| anyhow::anyhow!("unknown cred_family `{cred_family}`: {e}"))?;
            let body = render(family, &seed, state.template_dir.as_deref())
                .map_err(|e| anyhow::anyhow!("rendering cred canary: {e}"))?;
            (path, body.into_bytes())
        }
        // Process + Network canaries: no file materialisation
        // at deploy time. The operator places a Process canary's
        // binary; a Network canary opens no listener (lab PR 163,
        // `canary::network`).
        CanaryDeploymentWire::Process { .. } | CanaryDeploymentWire::Network { .. } => {
            return Ok((None, None))
        }
    };
    // canary-path-1 / external audit DEC-002: policy check, then a walk
    // that follows no symlink (write_canary_checked).
    let decoy = crate::canary::path_policy::write_canary_checked(path, &body)?;
    let content = DecoyContent {
        contents_sha256: hex::encode(Sha256::digest(&body)),
        content_seed: Some(seed),
    };
    Ok((Some(decoy_key(&decoy)?), Some(content)))
}

/// `nn-admin canary refresh`: re-arm the canary, and write its File /
/// Credential decoy again from a new seed (external audit DEC-008: a
/// refresh used to leave a burned credential in place). The write goes
/// to the same inode when the decoy is there (`O_TRUNC`), else creates
/// it, and the decoy is watched before the Refresh row records it — as
/// a deploy (NN-AUD-120). A decoy that cannot be written or watched
/// refuses the refresh: the canary stays as recorded.
pub(in crate::admin) fn refresh_canary(
    state: &CanaryAdminState,
    canary_id: &str,
    refreshed_by_fp: &str,
) -> Result<CanaryToken> {
    let deployment = state
        .registry
        .lock()
        .get(canary_id)
        .ok_or(RegistryError::CanaryIdNotFound)?
        .deployment;
    let (decoy, content) = materialise_canary_file(&deployment, state)?;
    if let (Some(key), Some(path)) = (decoy, canary_path(&deployment)) {
        if !watch_decoy(state, key, path) {
            anyhow::bail!("the decoy written again at {path} cannot be watched");
        }
    }
    state
        .registry
        .lock()
        .refresh(canary_id, refreshed_by_fp, content)
}

/// External audit DEC-001: the kernel's `(dev, ino)` of the decoy just
/// written, read from its open file — no second path resolution.
fn decoy_key(decoy: &std::fs::File) -> Result<common::wire::InodeKey> {
    use std::os::unix::fs::MetadataExt;
    let m = decoy.metadata()?;
    Ok(common::wire::InodeKey {
        dev: crate::fim::attach::stat_dev_to_kernel_dev(m.dev()),
        ino: m.ino(),
    })
}

/// dispatch_canary_list — verify 1-of-N quorum with
/// `Role::CanaryRead`, read the chained registry log from
/// disk, return the JSONL body with the standard truncation
/// flag (same shape as `dispatch_fim_report`). External audit
/// NN-AUD-080: newest rows first, so a long history no longer
/// hides the latest deploy, trip or burn.
pub(in crate::admin) fn dispatch_canary_list(
    req: CanaryListRequest,
    auth: &ConnAuth<'_>,
    state: Option<&CanaryAdminState>,
    fps_out: &mut Vec<String>,
) -> CanaryListResponse {
    use nn_proto::admin_signed_payload::OperationExtra;

    let server_now = now_unix_secs();
    let sigs: Vec<[u8; 64]> = req.signatures.iter().map(|s| s.signature).collect();
    let (_token, matched_fps) = match auth.verify_signed_payload_quorum(
        &req.payload,
        &sigs,
        1,
        &[Role::CanaryRead],
        OperationCode::CanaryList,
        server_now,
    ) {
        Ok(t) => t,
        Err(e) => {
            return CanaryListResponse {
                result: map_admin_auth_error(e, "canary-list"),
                entries_jsonl: String::new(),
                entries_count: 0,
                entries_truncated: false,
            };
        }
    };
    *fps_out = matched_fps;
    if !matches!(&req.payload.extra, OperationExtra::CanaryList(_)) {
        warn!("canary-list payload extra is not CanaryList variant");
        return CanaryListResponse {
            result: AdminResult::UnknownOperation,
            entries_jsonl: String::new(),
            entries_count: 0,
            entries_truncated: false,
        };
    }

    let log_path = match state {
        Some(s) => s.registry_log_path.clone(),
        None => {
            warn!("canary-list: agent boot did not wire CanaryAdminState");
            return CanaryListResponse {
                result: AdminResult::UnknownOperation,
                entries_jsonl: String::new(),
                entries_count: 0,
                entries_truncated: false,
            };
        }
    };
    let (entries_jsonl, entries_count, entries_truncated) =
        read_tail_jsonl(&log_path, None, None, usize::MAX);
    info!(
        target: "admin.canary_list",
        signer_fp = %fps_out.first().map(String::as_str).unwrap_or(""),
        entries = entries_count,
        truncated = entries_truncated,
        "canary list served"
    );
    CanaryListResponse {
        result: AdminResult::Success,
        entries_jsonl,
        entries_count,
        entries_truncated,
    }
}

/// dispatch_canary_burn — verify 1-of-N quorum with
/// `Role::CanaryManage`, call Registry::burn, rebuild indexes
/// so the K3 detector stops matching on the burned canary.
pub(in crate::admin) fn dispatch_canary_burn(
    req: CanaryBurnRequest,
    auth: &ConnAuth<'_>,
    state: Option<&CanaryAdminState>,
    fps_out: &mut Vec<String>,
) -> AdminResult {
    use nn_proto::admin_signed_payload::OperationExtra;

    let server_now = now_unix_secs();
    let sigs: Vec<[u8; 64]> = req.signatures.iter().map(|s| s.signature).collect();
    let (_token, matched_fps) = match auth.verify_signed_payload_quorum(
        &req.payload,
        &sigs,
        1,
        &[Role::CanaryManage],
        OperationCode::CanaryBurn,
        server_now,
    ) {
        Ok(t) => t,
        Err(e) => return map_admin_auth_error(e, "canary-burn"),
    };
    *fps_out = matched_fps;

    let canary_id = match &req.payload.extra {
        OperationExtra::CanaryBurn(e) => e.canary_id.clone(),
        _ => {
            warn!("canary-burn payload extra is not CanaryBurn variant");
            return AdminResult::UnknownOperation;
        }
    };
    let state = match state {
        Some(s) => s,
        None => {
            warn!("canary-burn: agent boot did not wire CanaryAdminState");
            return AdminResult::UnknownOperation;
        }
    };
    let primary_fp = fps_out.first().cloned().unwrap_or_default();
    let (result, decoy) = {
        let mut reg = state.registry.lock();
        let decoy = reg
            .list()
            .iter()
            .find(|c| c.canary_id == canary_id)
            .and_then(|c| canary_path(&c.deployment).map(str::to_string));
        (reg.burn(&canary_id, &primary_fp), decoy)
    };
    match result {
        Ok(_) => {
            // External audit DEC-001: a burned decoy is no longer watched.
            if let (Some(path), Some(watch)) = (decoy, &state.fim_watch) {
                if let Ok(key) = crate::fim::attach::key_for_path(std::path::Path::new(&path)) {
                    watch.unwatch(key);
                }
            }
            rebuild_canary_indexes(state);
            info!(
                target: "admin.canary_burn",
                signer_fp = %primary_fp,
                canary_id = %canary_id,
                "canary burned"
            );
            AdminResult::Success
        }
        Err(e) => {
            // Distinguish "canary not found" from systemic
            // errors. K2 surfaces CanaryIdNotFound as a typed
            // variant; map to a recognisable AdminResult so
            // the operator gets actionable feedback.
            if let Some(RegistryError::CanaryIdNotFound) = e.downcast_ref::<RegistryError>() {
                warn!(canary_id = %canary_id, "canary-burn: canary_id not found");
                AdminResult::UnknownOperation
            } else {
                warn!(error = %e, "canary registry burn failed");
                AdminResult::UnknownOperation
            }
        }
    }
}

/// dispatch_canary_refresh — verify 1-of-N quorum with
/// `Role::CanaryManage`, write the decoy again and call
/// Registry::refresh ([`refresh_canary`]), rebuild indexes (the
/// decoy may be a new inode).
pub(in crate::admin) fn dispatch_canary_refresh(
    req: CanaryRefreshRequest,
    auth: &ConnAuth<'_>,
    state: Option<&CanaryAdminState>,
    fps_out: &mut Vec<String>,
) -> AdminResult {
    use nn_proto::admin_signed_payload::OperationExtra;

    let server_now = now_unix_secs();
    let sigs: Vec<[u8; 64]> = req.signatures.iter().map(|s| s.signature).collect();
    let (_token, matched_fps) = match auth.verify_signed_payload_quorum(
        &req.payload,
        &sigs,
        1,
        &[Role::CanaryManage],
        OperationCode::CanaryRefresh,
        server_now,
    ) {
        Ok(t) => t,
        Err(e) => return map_admin_auth_error(e, "canary-refresh"),
    };
    *fps_out = matched_fps;

    let canary_id = match &req.payload.extra {
        OperationExtra::CanaryRefresh(e) => e.canary_id.clone(),
        _ => {
            warn!("canary-refresh payload extra is not CanaryRefresh variant");
            return AdminResult::UnknownOperation;
        }
    };
    let state = match state {
        Some(s) => s,
        None => {
            warn!("canary-refresh: agent boot did not wire CanaryAdminState");
            return AdminResult::UnknownOperation;
        }
    };
    let primary_fp = fps_out.first().cloned().unwrap_or_default();
    let result = refresh_canary(state, &canary_id, &primary_fp);
    match result {
        Ok(_) => {
            rebuild_canary_indexes(state);
            info!(
                target: "admin.canary_refresh",
                signer_fp = %primary_fp,
                canary_id = %canary_id,
                "canary refreshed (tripped flag cleared; a file decoy written again)"
            );
            AdminResult::Success
        }
        Err(e) => {
            if let Some(RegistryError::CanaryIdNotFound) = e.downcast_ref::<RegistryError>() {
                AdminResult::UnknownOperation
            } else {
                warn!(error = %format!("{e:#}"), "canary refresh failed");
                AdminResult::UnknownOperation
            }
        }
    }
}
