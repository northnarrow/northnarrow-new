//! Installing a signed operator overlay (Tappa 10.8): the Linux half of
//! `config overlay set` — the overlay and its `.sig` replaced atomically,
//! then both new inodes protected (`PROTECTED_INODES`). The verification
//! is `overlay_auth`'s; this is the write. Wave 4 restructure, R04c (lab
//! PR 247, with R07): from `overlay_auth`, verbatim; the map sends it to
//! nn-linux, the verifying half to nn-core.

use std::path::{Path, PathBuf};

use anyhow::{anyhow, Context, Result};
use tracing::warn;

use super::overlay_auth::{sig_path, OverlaySignature};

/// Store an overlay and its signature (`nn-admin config overlay set`,
/// after the request was verified): both written to a temporary file in
/// the same directory, fsynced and renamed into place — the agent is a
/// protected pid, so the inode guard lets it; then both new inodes are
/// registered in PROTECTED_INODES (unlink/rename/setattr denied).
pub fn store(path: &Path, content: &str, sig: &OverlaySignature) -> Result<PathBuf> {
    let sig_file = sig_path(path);
    let sig_json = sig.to_json()?;
    for (target, body) in [
        (path.to_path_buf(), content.to_string()),
        (sig_file.clone(), sig_json),
    ] {
        let old_key = inode_key(&target);
        let dir = target
            .parent()
            .ok_or_else(|| anyhow!("{} has no parent", target.display()))?;
        let name = target
            .file_name()
            .and_then(|n| n.to_str())
            .ok_or_else(|| anyhow!("bad file name {}", target.display()))?;
        // External audit AUT-003: never through a link planted at the
        // temporary name (the agent writes where nobody else may).
        crate::atomic_file::replace(&target, body.as_bytes(), 0o644)
            .with_context(|| format!("replacing {} in {}", name, dir.display()))?;
        if let Err(e) = crate::anti_tamper::filesystem::reregister_protected_file(
            crate::anti_tamper::prepare_pin_root(),
            &target,
            old_key,
            common::wire::FS_PROTECT_MUTATE,
        ) {
            warn!(error = ?e, path = %target.display(), "overlay store: protecting the new inode FAILED — unprotected until the next agent start");
        }
    }
    Ok(sig_file)
}

fn inode_key(path: &Path) -> Option<common::wire::InodeKey> {
    use std::os::unix::fs::MetadataExt;
    let m = std::fs::metadata(path).ok()?;
    Some(common::wire::InodeKey {
        dev: crate::anti_tamper::filesystem::stat_dev_to_kernel_dev(m.dev()),
        ino: m.ino(),
    })
}
