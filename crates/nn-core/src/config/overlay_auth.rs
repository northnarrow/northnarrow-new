//! Signed operator overlays (Tappa 10.8): what the list loaders take from
//! the boot gate.
//!
//! An overlay (`/etc/northnarrow/*.local`) is loaded only if the gate
//! verified its signature (the agent's `config::overlay_auth::OverlayGate`:
//! an admin-signed statement binding the overlay kind to the SHA-256 and
//! length of its exact content, not older than the rollback floor). The
//! gate reads the file once, through the host ([`read_overlay`]), and hands
//! each loader the text it decided on ([`Verified`]); the loaders never
//! read the path again (external audit LLMR-013). A shipped default list
//! (`.v1`) is read the same way, and compared by [`content_sha256`]
//! (LLMR-015). [`ALLOW_UNSIGNED_ENV`] is the escape hatch that loads an
//! unsigned overlay anyway, still reported.
//!
//! Wave 4 restructure, R07 (lab PR 247): cut verbatim from the agent's
//! `config::overlay_auth`, whose gate (it verifies through the agent's
//! admin key set, `anti_tamper::admin_auth`, and writes the agent's audit
//! log), signature file, content checks and install stay in the agent; the
//! agent re-exports these under their old paths.

use std::path::{Path, PathBuf};

use nn_proto::admin_signed_payload::OverlayKind;
use sha2::{Digest, Sha256};

use crate::content_host::ContentHost;

/// Escape hatch: load unsigned overlays (still reported).
pub const ALLOW_UNSIGNED_ENV: &str = "NN_OVERLAY_ALLOW_UNSIGNED";
/// Largest overlay the gate reads: an overlay is a list of lines; a larger
/// file is refused rather than read whole into memory.
pub const MAX_OVERLAY_BYTES: u64 = 4 << 20;

/// SHA-256 of an overlay's bytes.
pub fn content_sha256(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

/// What the loader of an overlay gets from the gate (`OverlayGate::verified`)
/// (external audit LLMR-013). The gate used to hand over a path, and every
/// loader read the file again after the gate had verified its own read: a
/// root process able to pause the agent's `open()` could serve the gate
/// the signed bytes and the loader others. The loaders now take this, and
/// only the gate makes one: the text is the one the decision was made on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verified {
    /// No overlay at the path: the shipped defaults only.
    Missing,
    /// The file is the content the agent was built with (the COMBAT files).
    ShippedDefault,
    /// Present but refused (logged and recorded by the gate): the shipped
    /// defaults only.
    Refused,
    /// The text to apply: signed, or loaded through the escape hatch.
    Content { path: PathBuf, text: String },
}

impl Verified {
    /// The overlay's text, when there is one to apply.
    pub fn text(&self) -> Option<&str> {
        match self {
            Verified::Content { text, .. } => Some(text),
            _ => None,
        }
    }

    /// Where the applied text was read (for the loaders' logs).
    pub fn source(&self) -> Option<&Path> {
        match self {
            Verified::Content { path, .. } => Some(path),
            _ => None,
        }
    }
}

/// What vouches for a file before it is applied: the signed-overlay gate
/// (the agent's `config::overlay_auth::OverlayGate`), as the network
/// isolator holds it. Wave 4 restructure, R09a (lab PR 253): the isolator
/// moves to nn-linux, and the gate stays in the agent until it can move
/// here with the rest of this module (its admin key set's verification
/// first goes to nn-proto, R04b): the isolator names the gate through this
/// trait, and the agent's gate implements it with its own read and check.
/// R09c (lab PR 257): the integrity check, which moves to nn-linux too,
/// holds the gate the same way ([`Vouch::is_signed`]).
pub trait Vouch: Send + Sync + std::fmt::Debug {
    /// What the gate decided on the file at `path` for `kind`, with the text
    /// it read and verified (`OverlayGate::verified`).
    fn verified(&self, kind: OverlayKind, path: &Path) -> Verified;

    /// Whether the file at `path` (an overlay of `kind`) carries a valid
    /// signature for its current content (`OverlayGate::is_signed`): the
    /// integrity check's question, to tell a `nn-admin config overlay set`
    /// from an edit.
    fn is_signed(&self, kind: OverlayKind, path: &Path) -> bool;
}

/// External audit LLMR-013: an overlay is read once, without following a
/// link (the last component), without blocking on a FIFO planted at its
/// name, and at most [`MAX_OVERLAY_BYTES`]. So is a shipped default list
/// (`.v1`, LLMR-015). The open is the host's ([`ContentHost`], R07: the
/// agent's is `LinuxHost`, `O_NOFOLLOW | O_NONBLOCK`).
pub fn read_overlay<H: ContentHost>(path: &Path) -> std::io::Result<Vec<u8>> {
    use std::io::Read as _;
    let f = H::open_read_nofollow(path).map_err(|e| {
        if H::is_symlink_refusal(&e) {
            std::io::Error::other("a symbolic link (not read through one)")
        } else {
            e
        }
    })?;
    if !f.metadata()?.file_type().is_file() {
        return Err(std::io::Error::other("not a regular file"));
    }
    let mut bytes = Vec::new();
    f.take(MAX_OVERLAY_BYTES + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_OVERLAY_BYTES {
        return Err(std::io::Error::other(format!(
            "larger than {MAX_OVERLAY_BYTES} bytes"
        )));
    }
    Ok(bytes)
}
