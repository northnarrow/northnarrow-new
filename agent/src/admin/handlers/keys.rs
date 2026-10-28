//! The signed `rotate-keys add` and `revoke` (R11d, lab PR 263: from
//! `admin_socket.rs`): admin.pub rewritten atomically, protected again and
//! reloaded.

use std::path::Path;

use tracing::{info, warn};

use common::wire::{FS_PROTECT_MUTATE, FS_PROTECT_WRITE};
use ed25519_dalek::VerifyingKey;
use nn_proto::admin_protocol::{AdminResult, RotateKeysAddRequest, RotateKeysRevokeRequest};
use nn_proto::admin_signed_payload::{OperationCode, OperationExtra, Role};

use crate::admin::verify::{map_admin_auth_error, now_unix_secs};
use crate::anti_tamper::admin_auth::ConnAuth;

/// at-authz-1 verify-item 1: re-register the rotated admin.pub inode in
/// `PROTECTED_INODES` after a rotate-keys rewrite. The atomic rewrite does
/// tmp-write + `rename(2)`, installing a NEW inode the boot-time
/// `register_etc_files` never saw — so without this every deny hook (the
/// five existing + the at-authz-1 write-open deny) lapses on the rotated
/// admin.pub until the next agent restart, silently reopening the gap.
/// Best-effort + loud on failure: a failure means the file is unprotected
/// until restart, NOT that the (already-committed-on-disk) rotation should
/// be reported as failed. Called right after the rename(2), before the
/// in-memory reload, so a reload failure cannot skip it.
fn reregister_admin_pub_after_rotate(
    config_path: &Path,
    old_inode_key: Option<common::wire::InodeKey>,
) {
    if let Err(e) = crate::anti_tamper::filesystem::reregister_protected_file(
        crate::anti_tamper::prepare_pin_root(),
        config_path,
        old_inode_key,
        FS_PROTECT_MUTATE | FS_PROTECT_WRITE,
    ) {
        warn!(
            error = ?e,
            "rotate-keys: re-registering rotated admin.pub inode in PROTECTED_INODES \
             FAILED — admin.pub is UNPROTECTED against tamper until the next agent restart"
        );
    }
}

/// Tappa 8 A13 — handle one [`RotateKeysAddRequest`] (design
/// §7.2). Verifies 2-of-N quorum carrying `Role::RotateKeys`,
/// atomically appends a new line to `admin.pub`, and reloads
/// the in-memory key set so the next challenge already sees
/// the addition.
///
/// `AdminAuth::config_path()` MUST be `Some` — production
/// `AdminAuth::load_with_agent_id` always sets it; test builders
/// that go through `build_*` don't, and trying to rotate keys
/// against an in-memory-only auth surfaces as a clear log line
/// + `AdminResult::UnknownOperation`.
///
/// External audit NN-AUD-084: the new key's roles must be a subset of
/// what the matched signers hold, else `AdminResult::RoleDenied` and
/// admin.pub is untouched.
pub(in crate::admin) fn dispatch_rotate_keys_add(
    req: RotateKeysAddRequest,
    auth: &ConnAuth<'_>,
    fps_out: &mut Vec<String>,
) -> AdminResult {
    // BUG-013 (PHASE 15.1): bootstrap-mode 1-of-N gate. Consulted
    // BEFORE verify_signed_payload_quorum so the relaxed min_distinct
    // (1) goes into the verify call. The gate is evaluated against the
    // key set in memory (one key), the signed chain (no second key ever
    // added) and the sentinel + nonce on disk; ALL must hold, and any
    // other outcome falls through to the permanent 2-of-N path. See
    // `crate::anti_tamper::bootstrap` for the full security argument.
    let bootstrap_armed = match auth.config_path() {
        Some(admin_pub_path) => {
            let paths = crate::anti_tamper::bootstrap::BootstrapPaths::default_paths(
                admin_pub_path.to_path_buf(),
            );
            // External audit ATP-004: the keys in memory, and the
            // consumption recorded in the signed chain.
            matches!(
                crate::anti_tamper::bootstrap::evaluate_loaded(
                    &paths,
                    &auth.loaded_admin_pub(),
                    auth.bootstrap_consumed(),
                ),
                crate::anti_tamper::bootstrap::BootstrapGate::Armed
            )
        }
        // In-memory test builders have no config_path; bootstrap
        // gate is structurally inapplicable. Fall through to the
        // existing 2-of-N path.
        None => false,
    };
    let min_distinct: u8 = if bootstrap_armed { 1 } else { 2 };

    let server_now = now_unix_secs();
    let sigs: Vec<[u8; 64]> = req.signatures.iter().map(|s| s.signature).collect();

    let signers = match auth.verify_signed_payload_quorum_keys(
        &req.payload,
        &sigs,
        min_distinct, // 2-of-N normally; 1-of-N when bootstrap-armed (BUG-013)
        &[Role::RotateKeys],
        OperationCode::RotateKeysAdd,
        server_now,
    ) {
        Ok(v) => v,
        Err(e) => return map_admin_auth_error(e, "rotate-keys-add"),
    };
    *fps_out = signers.fingerprints;

    let (new_pubkey_bytes, roles) = match &req.payload.extra {
        OperationExtra::RotateKeysAdd(extra) => (extra.new_pubkey, extra.roles.clone()),
        other => {
            warn!(
                extra = ?other,
                "rotate-keys-add payload extra is not RotateKeysAdd variant"
            );
            return AdminResult::UnknownOperation;
        }
    };

    // External audit NN-AUD-084: the new key may hold only roles its
    // signers hold, the bootstrap 1-of-N path included — a key with only
    // `rotate-keys` used to mint an `all` key.
    if let Some(beyond) = role_beyond_signers(&roles, &signers.keys) {
        warn!(
            target: "admin.rotate_keys",
            role = ?beyond,
            requested = ?roles,
            bootstrap_armed,
            "rotate-keys add refused: the new key would hold a role none of its signers holds"
        );
        return AdminResult::RoleDenied;
    }

    let Some(config_path) = auth.config_path() else {
        warn!(
            "rotate-keys-add: AdminAuth has no config_path — agent was loaded \
             via in-memory builder, rotation requires a real admin.pub file"
        );
        return AdminResult::UnknownOperation;
    };
    let config_path = config_path.to_path_buf();
    // at-authz-1 verify-item 1: capture the CURRENT admin.pub inode before
    // the rename-based rewrite installs a new one, so we can drop the stale
    // key from PROTECTED_INODES afterwards.
    let old_inode_key = crate::fim::attach::key_for_path(&config_path).ok();

    let new_pubkey = match VerifyingKey::from_bytes(&new_pubkey_bytes) {
        Ok(vk) => vk,
        Err(e) => {
            warn!(error = ?e, "rotate-keys-add: new_pubkey not a valid Ed25519 key");
            return AdminResult::InvalidSignature;
        }
    };

    match crate::anti_tamper::admin_auth::atomic_rewrite_admin_pub_add(
        &config_path,
        &new_pubkey,
        &roles,
    ) {
        Ok(()) => {}
        Err(crate::anti_tamper::admin_auth::RotateKeysError::KeyAlreadyPresent { fingerprint }) => {
            warn!(
                target: "admin.rotate_keys",
                fingerprint,
                "rotate-keys-add rejected: pubkey already present"
            );
            return AdminResult::InvalidSignature;
        }
        // External audit AUT-006: a different key already has this
        // fingerprint; the wire keeps `InvalidSignature`.
        Err(crate::anti_tamper::admin_auth::RotateKeysError::FingerprintCollision {
            fingerprint,
        }) => {
            warn!(
                target: "admin.rotate_keys",
                fingerprint,
                "rotate-keys-add rejected: a different admin.pub key has the same fingerprint \
                 (revocation by fingerprint would be ambiguous)"
            );
            return AdminResult::InvalidSignature;
        }
        Err(e) => {
            warn!(error = ?e, "rotate-keys-add: atomic rewrite failed");
            return AdminResult::InvalidSignature;
        }
    }

    // at-authz-1 verify-item 1: re-register the rotated inode NOW, after the
    // rename(2) committed the new on-disk inode but BEFORE the reload — the
    // protection property depends only on the on-disk inode, not the
    // in-memory key reload (which has its own reachable failure path below).
    // Re-registering after the reload would skip it on a reload failure and
    // silently leave the rotated admin.pub unprotected until restart.
    reregister_admin_pub_after_rotate(&config_path, old_inode_key);

    if let Err(e) = auth.reload(&config_path) {
        warn!(error = ?e, "rotate-keys-add: admin.pub rewrite succeeded but reload failed");
        return AdminResult::InvalidSignature;
    }

    // BUG-013 (PHASE 15.1): if we entered this dispatch via the
    // bootstrap-armed 1-of-N relaxation, scrub the sentinel now that
    // the add is complete. Best-effort: any failure leaves a stale
    // sentinel that the NEXT dispatch will scrub via the
    // BootstrapAlreadyComplete arm (admin.pub now has ≥2 keys, so
    // `evaluate` will remove it). If the gate was NOT armed (i.e.
    // we took the normal 2-of-N path), there's nothing to clean up.
    if bootstrap_armed {
        let paths =
            crate::anti_tamper::bootstrap::BootstrapPaths::default_paths(config_path.clone());
        if let Err(e) = crate::anti_tamper::bootstrap::complete(&paths) {
            warn!(
                error = ?e,
                "BUG-013: post-bootstrap sentinel scrub failed (next dispatch will retry)"
            );
        }
    }

    // External audit ATP-004: a second key exists now — no later admin.pub
    // with one key re-arms the bootstrap in this run (the next boots read
    // the signed chain).
    auth.mark_bootstrap_consumed();
    info!(
        target: "admin.rotate_keys",
        new_key_fp = %hex::encode(crate::anti_tamper::admin_auth::fingerprint_bytes(&new_pubkey)),
        role_count = roles.len(),
        bootstrap_armed,
        "rotate-keys add: admin.pub updated + in-memory keys reloaded"
    );
    AdminResult::Success
}

/// External audit NN-AUD-084: the first role a key added with `roles`
/// would hold that none of `signers` holds ([`AdminKey::authorizes`], so
/// `all` needs a signer holding `all`). An empty list is written as a
/// pubkey-only line, which loads with the default roles — those are
/// checked.
///
/// [`AdminKey::authorizes`]: nn_proto::admin_quorum::AdminKey::authorizes
pub(in crate::admin) fn role_beyond_signers(
    roles: &[Role],
    signers: &[nn_proto::admin_quorum::AdminKey],
) -> Option<Role> {
    let defaults;
    let granted = if roles.is_empty() {
        defaults = nn_proto::admin_quorum::default_roles();
        &defaults[..]
    } else {
        roles
    };
    granted
        .iter()
        .copied()
        .find(|role| !signers.iter().any(|k| k.authorizes(*role)))
}

/// Tappa 8 A13 — handle one [`RotateKeysRevokeRequest`] (design
/// §7.2 + §7.3). Symmetric to [`dispatch_rotate_keys_add`]: 2-of-N
/// quorum with `Role::RotateKeys`, atomic file rewrite removing
/// the matched line, in-memory reload. Refuses to revoke the
/// LAST remaining key — that would soft-brick the agent
/// (`AdminResult::InvalidSignature` rather than a dedicated
/// variant; the operator-facing detail is in the agent's own log).
pub(in crate::admin) fn dispatch_rotate_keys_revoke(
    req: RotateKeysRevokeRequest,
    auth: &ConnAuth<'_>,
    fps_out: &mut Vec<String>,
) -> AdminResult {
    let server_now = now_unix_secs();
    let sigs: Vec<[u8; 64]> = req.signatures.iter().map(|s| s.signature).collect();

    let (_token, matched_fps) = match auth.verify_signed_payload_quorum(
        &req.payload,
        &sigs,
        2, // 2-of-N per §3.3
        &[Role::RotateKeys],
        OperationCode::RotateKeysRevoke,
        server_now,
    ) {
        Ok(t) => t,
        Err(e) => return map_admin_auth_error(e, "rotate-keys-revoke"),
    };
    *fps_out = matched_fps;

    let target_fp = match &req.payload.extra {
        OperationExtra::RotateKeysRevoke(extra) => extra.fingerprint,
        other => {
            warn!(
                extra = ?other,
                "rotate-keys-revoke payload extra is not RotateKeysRevoke variant"
            );
            return AdminResult::UnknownOperation;
        }
    };

    let Some(config_path) = auth.config_path() else {
        warn!(
            "rotate-keys-revoke: AdminAuth has no config_path — agent was loaded \
             via in-memory builder, rotation requires a real admin.pub file"
        );
        return AdminResult::UnknownOperation;
    };
    let config_path = config_path.to_path_buf();
    // at-authz-1 verify-item 1: capture the CURRENT admin.pub inode before
    // the rename-based rewrite installs a new one.
    let old_inode_key = crate::fim::attach::key_for_path(&config_path).ok();

    match crate::anti_tamper::admin_auth::atomic_rewrite_admin_pub_revoke(&config_path, target_fp) {
        Ok(()) => {}
        Err(crate::anti_tamper::admin_auth::RotateKeysError::KeyNotFound { fingerprint }) => {
            warn!(
                target: "admin.rotate_keys",
                fingerprint,
                "rotate-keys-revoke rejected: no matching pubkey"
            );
            return AdminResult::InvalidSignature;
        }
        Err(crate::anti_tamper::admin_auth::RotateKeysError::LastKey) => {
            warn!(
                target: "admin.rotate_keys",
                "rotate-keys-revoke rejected: would remove the last admin key \
                 (soft-brick guard — add a replacement key first)"
            );
            return AdminResult::InvalidSignature;
        }
        // External audit AUT-006: the fingerprint names several keys;
        // nothing was removed.
        Err(crate::anti_tamper::admin_auth::RotateKeysError::AmbiguousFingerprint {
            fingerprint,
            matches,
        }) => {
            warn!(
                target: "admin.rotate_keys",
                fingerprint,
                matches,
                "rotate-keys-revoke rejected: the fingerprint matches several different \
                 admin.pub keys; admin.pub left untouched"
            );
            return AdminResult::InvalidSignature;
        }
        Err(e) => {
            warn!(error = ?e, "rotate-keys-revoke: atomic rewrite failed");
            return AdminResult::InvalidSignature;
        }
    }

    // at-authz-1 verify-item 1: re-register BEFORE the reload (see the add
    // path) — protection of the new on-disk inode must not be gated on the
    // in-memory reload's reachable failure path.
    reregister_admin_pub_after_rotate(&config_path, old_inode_key);

    if let Err(e) = auth.reload(&config_path) {
        warn!(
            error = ?e,
            "rotate-keys-revoke: admin.pub rewrite succeeded but reload failed"
        );
        return AdminResult::InvalidSignature;
    }

    info!(
        target: "admin.rotate_keys",
        revoked_fp = %hex::encode(target_fp),
        "rotate-keys revoke: admin.pub updated + in-memory keys reloaded"
    );
    AdminResult::Success
}
