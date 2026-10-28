//! The FIM's helpers the self-defence and the canary registry name, which
//! move here (Wave 4 restructure, R09a, lab PR 253): the kernel's form of a
//! `stat(2)` device number and a path's `InodeKey`, cut verbatim from the
//! agent's `fim::attach`, which re-exports them. The attach itself is
//! R09b's.

use std::os::unix::fs::MetadataExt;
use std::path::Path;

use anyhow::{Context, Result};
use common::wire::InodeKey;

/// Convert the userland-encoded `dev_t` returned by `stat(2)` /
/// `MetadataExt::dev()` back into the kernel-internal `MKDEV`
/// form. Mirrors
/// [`crate::anti_tamper::filesystem::stat_dev_to_kernel_dev`]
/// (private there — duplicated here so the FIM module doesn't
/// reach into anti-tamper internals).
pub fn stat_dev_to_kernel_dev(st_dev: u64) -> u64 {
    let major = libc::major(st_dev) as u64;
    let minor = libc::minor(st_dev) as u64;
    (major << 20) | minor
}

/// Tappa 9 C8 — diagnostic helper. Stat a candidate path and
/// return its kernel-form `InodeKey` for cross-checking against
/// `WATCHED_PATHS` map dumps. Used in privileged e2e tests.
pub fn key_for_path(path: &Path) -> Result<InodeKey> {
    let meta = std::fs::symlink_metadata(path)
        .with_context(|| format!("symlink_metadata({})", path.display()))?;
    Ok(InodeKey {
        dev: stat_dev_to_kernel_dev(meta.dev()),
        ino: meta.ino(),
    })
}
