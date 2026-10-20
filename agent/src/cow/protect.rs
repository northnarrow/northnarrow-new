//! The journals under the anti-tamper inode protections.
//!
//! Each journal's three directories take the flags of the agent's own
//! directories ([`crate::anti_tamper::filesystem::PROTECTED_DIR_FLAGS`]:
//! MUTATE | NOCREATE — no unlink, rename, chmod, chattr or xattr of them,
//! and no new entry in them, from outside the agent's family outside a
//! trusted-installer window) and `index.jsonl` takes MUTATE | WRITE (no
//! write-open either), in the kernel's pinned `PROTECTED_INODES` map that
//! the `inode_*` and `file_open` LSM deny hooks read. A root process can
//! therefore neither delete the copies nor rewrite the index; without the
//! anti-tamper hooks (no BPF LSM, or `NN_ANTI_TAMPER_ALLOW_DEGRADED`) it
//! can, and the guard says so (`journal_unprotected`).

use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use anyhow::{anyhow, Result};
use common::wire::{InodeKey, FS_PROTECT_MUTATE, FS_PROTECT_WRITE};

use super::journal::Journal;
use crate::anti_tamper::filesystem::{ProtectedInodesHandle, PROTECTED_DIR_FLAGS};

static PIN_ROOT: OnceLock<Option<PathBuf>> = OnceLock::new();

/// The bpffs pin root the agent's anti-tamper maps live under (`None`: the
/// anti-tamper layer did not come up). Set once at the guard's start.
pub fn set_pin_root(root: Option<PathBuf>) {
    let _ = PIN_ROOT.set(root);
}

fn pin_root() -> Option<&'static Path> {
    PIN_ROOT.get().and_then(|r| r.as_deref())
}

/// Register the journal's directories and index. `Ok(n)` with the inodes
/// registered; `Err` when the map cannot be reached.
pub fn protect_journal(j: &Journal) -> Result<usize> {
    let root = pin_root().ok_or_else(|| anyhow!("no anti-tamper pin root this boot"))?;
    let mut handle = ProtectedInodesHandle::open(root)?;
    let (dirs, index) = j.protected_paths();
    let mut n = 0;
    for d in &dirs {
        handle.register(crate::fim::attach::key_for_path(d)?, PROTECTED_DIR_FLAGS)?;
        n += 1;
    }
    handle.register(
        crate::fim::attach::key_for_path(&index)?,
        FS_PROTECT_MUTATE | FS_PROTECT_WRITE,
    )?;
    Ok(n + 1)
}

/// The index file's key, before a compaction replaces its inode.
pub fn index_key(j: &Journal) -> Option<InodeKey> {
    crate::fim::attach::key_for_path(&j.protected_paths().1).ok()
}

/// After a compaction: the new index inode registered, the old one
/// dropped (its inode number could be reused by another file).
pub fn reprotect_index(j: &Journal, old: Option<InodeKey>) {
    let Some(root) = pin_root() else {
        return;
    };
    let path = j.protected_paths().1;
    if let Err(e) = crate::anti_tamper::filesystem::reregister_protected_file(
        Some(root),
        &path,
        old,
        FS_PROTECT_MUTATE | FS_PROTECT_WRITE,
    ) {
        tracing::error!(
            error = %e,
            path = %path.display(),
            "copy on first write: the compacted index could not be registered — unprotected until restart"
        );
    }
}
