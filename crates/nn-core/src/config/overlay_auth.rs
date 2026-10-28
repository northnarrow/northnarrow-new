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
//! agent re-exports these under their old paths. R10 (lab PR 259): the
//! signature file ([`OverlaySignature`] at [`sig_path`]) and the gate's
//! decision on an overlay ([`Decision`]) were cut here the same way: the
//! gate reads the file and nn-admin writes it (`config overlay sign`), and
//! nn-admin reads the gate's decisions (`config overlay status`, `policy
//! show`) through its host.

use std::path::{Path, PathBuf};

use anyhow::{anyhow, Context, Result};
use nn_proto::admin_signed_payload::{OperationExtra, OverlayKind, SignedPayload};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::content_host::ContentHost;

/// Escape hatch: load unsigned overlays (still reported).
pub const ALLOW_UNSIGNED_ENV: &str = "NN_OVERLAY_ALLOW_UNSIGNED";
/// Largest overlay the gate reads: an overlay is a list of lines; a larger
/// file is refused rather than read whole into memory.
pub const MAX_OVERLAY_BYTES: u64 = 4 << 20;

/// Suffix of the signature file next to an overlay.
pub const SIG_SUFFIX: &str = ".sig";

/// SHA-256 of an overlay's bytes.
pub fn content_sha256(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

/// `<overlay>.sig` on disk.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OverlaySignature {
    pub v: u8,
    pub kind: String,
    pub payload: SignedPayload,
    /// Ed25519 signatures, hex.
    pub signatures: Vec<String>,
}

impl OverlaySignature {
    pub fn new(payload: SignedPayload, signatures: &[[u8; 64]]) -> Result<Self> {
        let kind = match &payload.extra {
            OperationExtra::ConfigOverlaySet(e) => e.kind.keyword().to_string(),
            _ => return Err(anyhow!("payload is not a config-overlay payload")),
        };
        Ok(Self {
            v: 1,
            kind,
            payload,
            signatures: signatures.iter().map(|s| hex(s)).collect(),
        })
    }

    pub fn signatures(&self) -> Result<Vec<[u8; 64]>> {
        self.signatures
            .iter()
            .map(|h| {
                let bytes = unhex(h).ok_or_else(|| anyhow!("signature is not hex"))?;
                <[u8; 64]>::try_from(bytes.as_slice())
                    .map_err(|_| anyhow!("signature is not 64 bytes"))
            })
            .collect()
    }

    pub fn to_json(&self) -> Result<String> {
        let mut s = serde_json::to_string_pretty(self).context("serialising overlay signature")?;
        s.push('\n');
        Ok(s)
    }
}

/// Lowercase hex of `b`: the signature file's signatures, and the digests
/// the gate reports (R10, lab PR 259: public for the agent's gate).
pub fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn unhex(s: &str) -> Option<Vec<u8>> {
    let s = s.trim();
    if !s.len().is_multiple_of(2) {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(s.get(i..i + 2)?, 16).ok())
        .collect()
}

/// `<overlay>.sig`.
pub fn sig_path(overlay: &Path) -> PathBuf {
    let mut s = overlay.as_os_str().to_os_string();
    s.push(SIG_SUFFIX);
    PathBuf::from(s)
}

/// Outcome of the boot check for one overlay.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    /// No overlay file: nothing to load, nothing to check.
    Absent,
    /// Signed, matching, not a rollback. `new` = content not yet recorded
    /// in the audit chain for this kind.
    Accepted {
        sha256: String,
        signed_ts: u64,
        key_fps: Vec<String>,
        new: bool,
    },
    /// Present but not loadable: why.
    Refused {
        reason: String,
        sha256: Option<String>,
    },
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
