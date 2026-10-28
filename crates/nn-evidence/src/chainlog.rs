//! BUG-026 — shared rotating, signed, hash-chained append-only log.
//!
//! Every NorthNarrow on-disk audit artifact (FIM drift/baseline,
//! NetFlow, canary access/registry, the admin audit log) is the same
//! shape: a JSONL file where each line carries `prev_hash` →
//! `entry_hash` = `SHA-256(prev_hash_bytes ‖ canonical_json(line minus
//! entry_hash+agent_sig))` → `agent_sig` = `Ed25519(entry_hash)`, the
//! first line rooted at [`crate::audit::GENESIS_PREV_HASH`]. That gives
//! tamper-evidence *within* a file but **roots every file at GENESIS**,
//! so a file deleted wholesale still "verifies" — and nothing caps the
//! file, so it grows without bound (BUG-026: `fim_drift.jsonl` hit
//! 1.7 GB). This module is the shared primitive that fixes both: it
//! **rotates with a seal + meta-chain** so the *file sequence* is one
//! continuous chain, and bounds total disk with a size cap + retention.
//!
//! ## On-disk format contract (PERSISTENT — versioned)
//!
//! A chainlog directory holds, for an active path `<base>` (e.g.
//! `/var/lib/northnarrow/netflow.jsonl`):
//! - the **active file** `<base>` — open, no terminator yet;
//! - **sealed archives** `<base>.NNNNNN` (zero-padded monotonic seq),
//!   each ending in exactly one **terminator** line;
//! - a **manifest** `<base>.manifest.jsonl` — itself a chain — with one
//!   row per rotation ([`ManifestEvent::Rotated`]) and per retention
//!   drop ([`ManifestEvent::Evicted`]), and the active file's checkpoints
//!   ([`ManifestEvent::ActiveCheckpoint`], external audit NN-AUD-109).
//!
//! Three line kinds, all chained + signed:
//! - **data line** — [`ChainLine<P>`]: the payload `P` flattened inline
//!   plus `fmt_ver?`,`prev_hash`,`entry_hash`,`agent_sig`. `fmt_ver` is
//!   ABSENT on legacy pre-BUG-026 lines (so they still verify
//!   byte-for-byte), [`CHAINLOG_FMT_V2`] on the lines written up to lab
//!   PR 204 and [`CHAINLOG_FMT_V3`] on new lines.
//! - **terminator line** — [`TerminatorLine`]: identified by its
//!   `rotate` key (a data line never has one). Its `prev_hash` is the
//!   sealed file's last data line's `entry_hash`; its `entry_hash`
//!   becomes the **meta-chain link**.
//! - **manifest line** — `ChainLine<`[`ManifestEntry`]`>`.
//!
//! **Meta-chain:** only seq-0's first line roots at GENESIS. Every later
//! file's first data line uses `prev_hash` = the *previous* file's
//! terminator `entry_hash`. So [`verify_log_set`] verifies the whole
//! sequence end-to-end and a missing/forged file breaks the link.
//!
//! **Versioning:** the terminator, the manifest entry, and the data
//! envelope each carry an `fmt_ver`, so the on-disk shape can evolve
//! without breaking already-rotated files (a verifier dispatches on it).
//! External audit EVD-007/EVD-008 (lab PR 204): v1/v2 lines are signed over
//! `SHA-256(prev_hash ‖ json)`, the same for every log and line type; v3
//! lines over `SHA-256(domain ‖ prev_hash ‖ json)` with a domain per log
//! ([`ChainPayload::KIND`]) and line type ([`LineRole`]), and must be
//! byte-canonical ([`CHAINLOG_FMT_V3`]). The writer writes v3 only; the old
//! lines keep verifying with their own pre-image, and none may follow a v3
//! line.
//!
//! ## Anti-tamper interaction (the reason rotation is not a plain rename)
//!
//! The state logs are in `PROTECTED_INODES` and `/var/lib/northnarrow`
//! is `chattr +i`. The agent is *caller-exempt* from its own
//! `inode_protect` LSM deny (it is in `PROTECTED_PIDS`), so it may
//! rename/unlink/create these inodes — but `chattr +i` on the directory
//! blocks dir-entry mutation for everyone. Rotation therefore lifts the
//! directory immutability for the rename/create/unlink, via the
//! [`ProtectionManager`] hook, which MUST restore `+i` on every exit
//! path (fail-safe) and which boot re-asserts idempotently. Logs that
//! are NOT under the protected dir (e.g. `combat-audit.jsonl`) use the
//! [`NoProtection`] manager — no dance.

use std::fs::{self, OpenOptions};
use std::io::{BufRead, BufReader, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use anyhow::{anyhow, Context, Result};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use ed25519_dalek::{Signature, VerifyingKey};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tracing::{error, warn};

use crate::audit::GENESIS_PREV_HASH;
use crate::chain_host::{ChainHost, ChainSigner};
use crate::clock::{stamp, Clock, SystemClock};

/// On-disk format of the lines written before lab PR 204 (BUG-026). A v1
/// line (the legacy flat line, NO `fmt_ver`) and a v2 line are read and
/// verified with the untagged pre-image they were signed with; never
/// written again.
pub const CHAINLOG_FMT_V2: u32 = 2;

/// External audit EVD-007, EVD-008, EVD-023 (NN-AUD-273, NN-AUD-274,
/// NN-AUD-427, lab PR 204): the format this module writes, for data lines,
/// terminators and manifest lines alike. Its pre-image is
/// `SHA-256(domain ‖ prev_hash ‖ json)` with `domain` =
/// `northnarrow/chainlog/<kind>/<role>/v3\0` ([`chain_domain`]): `<kind>` the
/// log ([`ChainPayload::KIND`]), `<role>` the line type ([`LineRole`]). The
/// same agent key signs every log, and a line signed for one log or one line
/// type no longer verifies in another. A v3 line must also be byte-canonical:
/// the verifier re-serialises the decoded line, hash and signature included,
/// and the result must be the bytes on disk ([`LogSetError::NonCanonicalLine`];
/// a key added, a key order or a spelling of a value the writer does not
/// produce is refused, where the hash alone covered only the modelled fields).
/// Once a set holds a v3 line, a later line in the old format is refused
/// ([`LogSetError::LegacyAfterV3`]).
pub const CHAINLOG_FMT_V3: u32 = 3;

/// The payload of one rotating log. External audit EVD-008 (NN-AUD-274, lab
/// PR 204).
pub trait ChainPayload {
    /// The log's name in every v3 pre-image ([`chain_domain`]). PERSISTENT:
    /// part of the signed bytes of every line written, `[a-z0-9_]`, 3 to 32
    /// characters, never given to another payload type.
    const KIND: &'static str;
}

/// The line types of a rotating log, each signed under its own domain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LineRole {
    /// [`ChainLine`].
    Data,
    /// [`TerminatorLine`].
    Terminator,
    /// [`ManifestLine`].
    Manifest,
}

impl LineRole {
    pub fn as_str(self) -> &'static str {
        match self {
            LineRole::Data => "data",
            LineRole::Terminator => "terminator",
            LineRole::Manifest => "manifest",
        }
    }
}

/// The v3 pre-image prefix of a `role` line of the log `kind`:
/// `northnarrow/chainlog/<kind>/<role>/v3\0`. At least 33 bytes, so it never
/// lines up with an untagged pre-image (32 bytes of `prev_hash`, then the
/// row's `{`), and distinct from the flat chains'
/// (`northnarrow/audit/v2\0`, `northnarrow/canary-…`).
pub fn chain_domain(kind: &str, role: LineRole) -> Result<Vec<u8>> {
    let ok = (3..=32).contains(&kind.len())
        && kind
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_');
    if !ok {
        return Err(anyhow!(
            "chain log kind {kind:?} is not 3 to 32 characters of [a-z0-9_]"
        ));
    }
    Ok(format!("northnarrow/chainlog/{kind}/{}/v3\0", role.as_str()).into_bytes())
}

/// Which pre-image a line was signed with, from its version field.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PreImage {
    /// v1/v2: `SHA-256(prev_hash ‖ json)`, untagged.
    Legacy,
    /// [`CHAINLOG_FMT_V3`].
    V3,
}

fn pre_image(fmt_ver: Option<u32>) -> std::result::Result<PreImage, String> {
    match fmt_ver {
        None | Some(0..=CHAINLOG_FMT_V2) => Ok(PreImage::Legacy),
        Some(CHAINLOG_FMT_V3) => Ok(PreImage::V3),
        Some(v) => Err(format!(
            "fmt_ver {v}: a format this reader does not know (it reads up to {CHAINLOG_FMT_V3})"
        )),
    }
}

/// Width of the zero-padded archive sequence suffix (`.NNNNNN`).
const SEQ_WIDTH: usize = 6;

// ── on-disk line types (the persistent contract) ────────────────────

/// A data line: payload `P` flattened inline + the chain fields.
///
/// `entry_hash`/`agent_sig` are empty strings during hashing (matching
/// the legacy `audit::compute_entry_hash` pre-image), then filled.
/// `fmt_ver` is skipped when `None` so a legacy line round-trips to the
/// exact bytes it was written with.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainLine<P> {
    #[serde(flatten)]
    pub payload: P,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fmt_ver: Option<u32>,
    pub prev_hash: String,
    pub entry_hash: String,
    pub agent_sig: String,
}

/// The seal written as the final line of a rotated file. Identified on
/// read by its `rotate` key (no data/manifest line has one).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TerminatorLine {
    /// Seal payload. Boxed in its own object so the `rotate` key is the
    /// unambiguous "this is a terminator" marker.
    pub rotate: RotateTerminator,
    pub ts: String,
    pub prev_hash: String,
    pub entry_hash: String,
    pub agent_sig: String,
}

/// Versioned seal body. `this_seq` is the archive number this file
/// becomes; `next_seq` is the file that continues the chain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RotateTerminator {
    pub fmt_ver: u32,
    pub this_seq: u64,
    pub next_seq: u64,
    pub record_count: u64,
    pub bytes: u64,
}

/// One manifest row (carried as a `ChainLine<ManifestEntry>` payload).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManifestEntry {
    pub fmt_ver: u32,
    pub ts: String,
    pub event: ManifestEvent,
}

/// A rotation or a retention eviction. `terminator_hash` lets the
/// verifier corroborate a sealed file (Rotated) or prove a now-absent
/// file was authentically dropped, not tampered (Evicted).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ManifestEvent {
    Rotated {
        seq: u64,
        terminator_hash: String,
        bytes: u64,
        records: u64,
    },
    Evicted {
        seq: u64,
        terminator_hash: String,
    },
    /// A torn trailing fragment was truncated from a chain file at boot
    /// (crash recovery). Recorded so the truncation of a signed log is
    /// ATTESTED, not silent — a tamper-evident log must distinguish a
    /// legitimate repair from an attacker shrinking the file. Advisory to
    /// the verifier (not an eviction); the manifest line is itself
    /// signed + chained like any other.
    TornTailRepaired {
        /// Which file under this log: `"active"` or `"manifest"`.
        role: String,
        /// Offset the intact chain ended at (file truncated to here).
        recovered_len: u64,
        /// Bytes discarded (`file_size - recovered_len`).
        dropped_bytes: u64,
        /// SHA-256 (hex) of the discarded bytes.
        dropped_sha256: String,
    },
    /// External audit NN-AUD-110: the tail line adopted at open is
    /// well-formed and its hash recomputes, but it could not be fully
    /// verified (`reason`: its signature does not match this agent's key,
    /// or too many trailing lines failed verification to cut them all).
    /// It was kept, not truncated; the verifier will flag it if forged.
    TailUnverified {
        /// `"active"` or `"manifest"`.
        role: String,
        entry_hash: String,
        reason: String,
    },
    /// External audit NN-AUD-115: a rotation found a name it did not create
    /// at the archive slot `seq` and archived into the next free slot
    /// instead. The foreign entry is left in place, untouched
    /// (`entry_type`: `file`, `symlink`, `dir` or `other`; `bytes`: its
    /// lstat size).
    ForeignArchive {
        seq: u64,
        entry_type: String,
        bytes: u64,
    },
    /// External audit NN-AUD-109: the active file of generation `seq` (the
    /// archive seq it becomes when sealed) held a line with `tail_hash`
    /// ending at offset `bytes`. Written every [`CHECKPOINT_EVERY_RECORDS`]
    /// records, every [`CHECKPOINT_EVERY_SECS`] while records arrive, and
    /// when the log opens a non-empty active file. [`verify_log_set`] and
    /// the boot check require each checkpoint to be reachable: an active
    /// file deleted, emptied or cut below it is found.
    ActiveCheckpoint {
        seq: u64,
        bytes: u64,
        tail_hash: String,
    },
}

/// A manifest line: the entry nested under `manifest` (keyed, like the
/// terminator's `rotate`) so the manifest's own `fmt_ver` never
/// collides with a flattened data payload's fields.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManifestLine {
    pub manifest: ManifestEntry,
    pub prev_hash: String,
    pub entry_hash: String,
    pub agent_sig: String,
}

// ── hashing / signing (shared pre-image rule) ───────────────────────

/// One line type of a rotating log: its chain fields and the version field
/// that selects its pre-image.
trait Frame: Serialize {
    const ROLE: LineRole;
    fn fmt_ver(&self) -> Option<u32>;
    fn prev(&self) -> &str;
    /// `(entry_hash, agent_sig)`.
    fn seal(&self) -> (&str, &str);
    fn seal_mut(&mut self) -> (&mut String, &mut String);
}

impl<P: Serialize> Frame for ChainLine<P> {
    const ROLE: LineRole = LineRole::Data;
    fn fmt_ver(&self) -> Option<u32> {
        self.fmt_ver
    }
    fn prev(&self) -> &str {
        &self.prev_hash
    }
    fn seal(&self) -> (&str, &str) {
        (&self.entry_hash, &self.agent_sig)
    }
    fn seal_mut(&mut self) -> (&mut String, &mut String) {
        (&mut self.entry_hash, &mut self.agent_sig)
    }
}

impl Frame for TerminatorLine {
    const ROLE: LineRole = LineRole::Terminator;
    fn fmt_ver(&self) -> Option<u32> {
        Some(self.rotate.fmt_ver)
    }
    fn prev(&self) -> &str {
        &self.prev_hash
    }
    fn seal(&self) -> (&str, &str) {
        (&self.entry_hash, &self.agent_sig)
    }
    fn seal_mut(&mut self) -> (&mut String, &mut String) {
        (&mut self.entry_hash, &mut self.agent_sig)
    }
}

impl Frame for ManifestLine {
    const ROLE: LineRole = LineRole::Manifest;
    fn fmt_ver(&self) -> Option<u32> {
        Some(self.manifest.fmt_ver)
    }
    fn prev(&self) -> &str {
        &self.prev_hash
    }
    fn seal(&self) -> (&str, &str) {
        (&self.entry_hash, &self.agent_sig)
    }
    fn seal_mut(&mut self) -> (&mut String, &mut String) {
        (&mut self.entry_hash, &mut self.agent_sig)
    }
}

/// The digest a line of the log `kind` is signed over: `SHA-256(prev_hash
/// ‖ json)` for a v1/v2 line, `SHA-256(domain ‖ prev_hash ‖ json)` for a v3
/// one ([`CHAINLOG_FMT_V3`]), `json` the line with `entry_hash` and
/// `agent_sig` empty, `prev_hash` its own.
///
/// External audit EVD-023 (NN-AUD-427, lab PR 204): a line that still
/// carries its `entry_hash` or `agent_sig` is an error, in every build — the
/// rule was a comment, and a caller that forgot to clear them hashed a
/// pre-image no verifier reproduces.
fn chain_digest<T: Frame>(line: &T, kind: &str) -> Result<[u8; 32]> {
    let (hash, sig) = line.seal();
    if !hash.is_empty() || !sig.is_empty() {
        return Err(anyhow!(
            "chain pre-image carries its own entry_hash or agent_sig: refused"
        ));
    }
    let domain = match pre_image(line.fmt_ver()).map_err(|e| anyhow!(e))? {
        PreImage::Legacy => None,
        PreImage::V3 => Some(chain_domain(kind, T::ROLE)?),
    };
    let prev = hex::decode(line.prev()).map_err(|e| anyhow!("prev_hash not hex: {e}"))?;
    let json = serde_json::to_vec(line).map_err(|e| anyhow!("serialising chain pre-image: {e}"))?;
    let mut h = Sha256::new();
    if let Some(d) = &domain {
        h.update(d);
    }
    h.update(&prev);
    h.update(&json);
    Ok(h.finalize().into())
}

/// Hash and sign `line` (its seal empty) for the log `kind`, in the format
/// its version field names.
fn seal_line<T: Frame, K: ChainSigner>(mut line: T, key: &K, kind: &str) -> Result<T> {
    let digest = chain_digest(&line, kind)?;
    let (hash, sig) = line.seal_mut();
    *hash = hex::encode(digest);
    *sig = B64.encode(key.sign(&digest).to_bytes());
    Ok(line)
}

/// Why one line of a rotating log does not verify on its own.
#[derive(Debug, Clone, PartialEq, Eq)]
enum LineFault {
    /// It does not decode as its line type, names a format this reader does
    /// not know, or its `prev_hash` is not hex.
    Malformed(String),
    EntryHash {
        recomputed: String,
        stored: String,
    },
    /// `agent_sig` is not 64 bytes of base64.
    SigMalformed(String),
    /// The signature does not verify with the key. The hash is checked
    /// first and recomputed: the line is as it was written, signed by
    /// another key or forged. Its seal and link, for the boot check's class
    /// and extent (lab PR 256, [`verify_recent`]).
    SigInvalid(LineOk),
    /// External audit EVD-007: a v3 line whose hash and signature verify but
    /// whose bytes are not its canonical serialisation.
    NonCanonical,
}

/// A line that verified on its own (its link is the caller's).
#[derive(Debug, Clone, PartialEq, Eq)]
struct LineOk {
    prev_hash: String,
    entry_hash: String,
    pre_image: PreImage,
    /// A v1/v2 line whose bytes differ from its canonical serialisation:
    /// counted, not refused (it verifies as it always did).
    non_canonical_legacy: bool,
}

/// Verify one decoded line against `raw`, its bytes on disk (without the
/// newline): the pre-image its version names, its hash, its signature
/// (strict, NN-AUD-292), and for v3 that `raw` is its canonical
/// serialisation (external audit EVD-007).
fn verify_frame<T: Frame>(
    mut line: T,
    raw: &[u8],
    kind: &str,
    pk: &VerifyingKey,
) -> std::result::Result<(LineOk, T), LineFault> {
    let pre = pre_image(line.fmt_ver()).map_err(LineFault::Malformed)?;
    let (stored, sig) = {
        let (h, s) = line.seal_mut();
        (std::mem::take(h), std::mem::take(s))
    };
    let digest = chain_digest(&line, kind).map_err(|e| LineFault::Malformed(format!("{e:#}")))?;
    let recomputed = hex::encode(digest);
    if recomputed != stored {
        return Err(LineFault::EntryHash { recomputed, stored });
    }
    let sig_bytes = B64
        .decode(&sig)
        .map_err(|e| LineFault::SigMalformed(format!("agent_sig b64: {e}")))?;
    let sig_arr = <[u8; 64]>::try_from(sig_bytes.as_slice())
        .map_err(|_| LineFault::SigMalformed(format!("agent_sig len {} != 64", sig_bytes.len())))?;
    // External audit NN-AUD-292 (FIMP-013): strict.
    if pk
        .verify_strict(&digest, &Signature::from_bytes(&sig_arr))
        .is_err()
    {
        return Err(LineFault::SigInvalid(LineOk {
            prev_hash: line.prev().to_string(),
            entry_hash: stored,
            pre_image: pre,
            non_canonical_legacy: false,
        }));
    }
    {
        let (h, s) = line.seal_mut();
        *h = stored;
        *s = sig;
    }
    let canonical = serde_json::to_vec(&line).is_ok_and(|b| b == raw);
    if pre == PreImage::V3 && !canonical {
        return Err(LineFault::NonCanonical);
    }
    let ok = LineOk {
        prev_hash: line.prev().to_string(),
        entry_hash: line.seal().0.to_string(),
        pre_image: pre,
        non_canonical_legacy: pre == PreImage::Legacy && !canonical,
    };
    Ok((ok, line))
}

/// A data line or a terminator of an active file or archive.
enum ActiveLine {
    Data,
    Terminator(RotateTerminator),
}

/// Whether a raw line is a terminator: it has a top-level `rotate` key,
/// which no data line may carry ([`RESERVED_LINE_KEYS`]).
fn has_rotate_key(raw: &[u8]) -> bool {
    serde_json::from_slice::<serde_json::Value>(raw)
        .ok()
        .is_some_and(|v| v.get("rotate").is_some())
}

/// Decode and verify one raw line of an active file or archive of the log
/// of `P` ([`verify_frame`]).
fn verify_active_line<P: Serialize + DeserializeOwned + ChainPayload>(
    raw: &[u8],
    pk: &VerifyingKey,
) -> std::result::Result<(LineOk, ActiveLine), LineFault> {
    if has_rotate_key(raw) {
        let t: TerminatorLine = serde_json::from_slice(raw)
            .map_err(|e| LineFault::Malformed(format!("terminator decode: {e}")))?;
        let (ok, t) = verify_frame(t, raw, P::KIND, pk)?;
        Ok((ok, ActiveLine::Terminator(t.rotate)))
    } else {
        let d: ChainLine<P> = serde_json::from_slice(raw)
            .map_err(|e| LineFault::Malformed(format!("data decode: {e}")))?;
        let (ok, _) = verify_frame(d, raw, P::KIND, pk)?;
        Ok((ok, ActiveLine::Data))
    }
}

/// Decode and verify one raw manifest line of the log `kind`.
fn verify_manifest_line(
    raw: &[u8],
    kind: &str,
    pk: &VerifyingKey,
) -> std::result::Result<(LineOk, ManifestLine), LineFault> {
    let m: ManifestLine = serde_json::from_slice(raw)
        .map_err(|e| LineFault::Malformed(format!("manifest decode: {e}")))?;
    verify_frame(m, raw, kind, pk)
}

impl LineFault {
    /// The verifier's error for this fault at line `idx` of `file`.
    fn at(self, file: &str, idx: usize) -> LogSetError {
        let file = file.to_string();
        match self {
            LineFault::Malformed(reason) | LineFault::SigMalformed(reason) => {
                LogSetError::Malformed { file, idx, reason }
            }
            LineFault::EntryHash { recomputed, stored } => LogSetError::EntryHashMismatch {
                file,
                idx,
                recomputed,
                stored,
            },
            LineFault::SigInvalid(_) => LogSetError::SignatureInvalid { file, idx },
            LineFault::NonCanonical => LogSetError::NonCanonicalLine { file, idx },
        }
    }

    /// The tail recovery's view of it ([`LineCheck`]).
    fn check(&self) -> LineCheck {
        match self {
            LineFault::SigMalformed(_) | LineFault::SigInvalid(_) => LineCheck::BadSignature,
            LineFault::Malformed(_) | LineFault::EntryHash { .. } | LineFault::NonCanonical => {
                LineCheck::Invalid
            }
        }
    }
}

/// External audit EVD-008 (lab PR 204): once a v3 line has been seen in a
/// set (or a manifest), a later line in the old format is refused — the
/// untagged pre-image is accepted only for what was written before the
/// upgrade.
fn track_format(
    ok: &LineOk,
    seen_v3: &mut bool,
    file: &str,
    idx: usize,
) -> std::result::Result<(), LogSetError> {
    match ok.pre_image {
        PreImage::V3 => {
            *seen_v3 = true;
            Ok(())
        }
        PreImage::Legacy if *seen_v3 => Err(LogSetError::LegacyAfterV3 {
            file: file.to_string(),
            idx,
        }),
        PreImage::Legacy => Ok(()),
    }
}

/// Top-level JSON keys reserved by the line framing. A flattened data
/// payload `P` MUST NOT use any of these: the envelope keys
/// (`fmt_ver`/`prev_hash`/`entry_hash`/`agent_sig`) would corrupt the
/// chain fields, and the control discriminators (`rotate`/`manifest`)
/// would make a data line indistinguishable from a terminator/manifest
/// line. Enforced on every data append by [`check_reserved_keys`] so the
/// discriminator is GUARANTEED at write time, not assumed.
const RESERVED_LINE_KEYS: &[&str] = &[
    "fmt_ver",
    "prev_hash",
    "entry_hash",
    "agent_sig",
    "rotate",
    "manifest",
];

/// Reject a data payload that serialises to a non-object or carries any
/// [`RESERVED_LINE_KEYS`] at the top level. Run on EVERY append (cheap
/// vs the per-append fsync) so an `Option` field that is `None` on the
/// first record but `Some` later cannot slip a reserved key onto disk
/// undetected — the discriminator stays sound for the whole file.
fn check_reserved_keys<P: Serialize>(payload: &P) -> Result<()> {
    let v = serde_json::to_value(payload)
        .map_err(|e| anyhow!("serialising payload for reserved-key check: {e}"))?;
    let obj = v
        .as_object()
        .ok_or_else(|| anyhow!("chainlog data payload must serialise to a JSON object"))?;
    for k in RESERVED_LINE_KEYS {
        if obj.contains_key(*k) {
            return Err(anyhow!(
                "chainlog payload uses reserved top-level key `{k}` — it would collide \
                 with the line framing / data-vs-control discriminator"
            ));
        }
    }
    Ok(())
}

impl<P: Serialize + ChainPayload> ChainLine<P> {
    /// Build a fully-signed v3 data line chained off `prev_hash`.
    fn sealed<K: ChainSigner>(payload: P, key: &K, prev_hash: &str) -> Result<Self> {
        Self::sealed_as(payload, Some(CHAINLOG_FMT_V3), key, prev_hash)
    }

    /// A data line in the format `fmt_ver` names (the writer: v3; the
    /// tests' legacy fixtures: `None` or v2).
    fn sealed_as<K: ChainSigner>(
        payload: P,
        fmt_ver: Option<u32>,
        key: &K,
        prev_hash: &str,
    ) -> Result<Self> {
        let line = ChainLine {
            payload,
            fmt_ver,
            prev_hash: prev_hash.to_string(),
            entry_hash: String::new(),
            agent_sig: String::new(),
        };
        seal_line(line, key, P::KIND)
    }
}

impl TerminatorLine {
    /// The seal of the log `kind`, in the format `rotate.fmt_ver` names,
    /// stamped by `clock` (lab PR 249).
    fn sealed<K: ChainSigner>(
        rotate: RotateTerminator,
        key: &K,
        prev_hash: &str,
        kind: &str,
        clock: &dyn Clock,
    ) -> Result<Self> {
        let line = TerminatorLine {
            rotate,
            ts: stamp(clock),
            prev_hash: prev_hash.to_string(),
            entry_hash: String::new(),
            agent_sig: String::new(),
        };
        seal_line(line, key, kind)
    }
}

impl ManifestLine {
    /// A manifest row of the log `kind`, in the format `manifest.fmt_ver`
    /// names.
    fn sealed<K: ChainSigner>(
        manifest: ManifestEntry,
        key: &K,
        prev_hash: &str,
        kind: &str,
    ) -> Result<Self> {
        let line = ManifestLine {
            manifest,
            prev_hash: prev_hash.to_string(),
            entry_hash: String::new(),
            agent_sig: String::new(),
        };
        seal_line(line, key, kind)
    }
}

/// Serialise a line struct to a `\n`-terminated JSONL string.
fn to_jsonl<T: Serialize>(line: &T) -> Result<String> {
    let mut s =
        serde_json::to_string(line).map_err(|e| anyhow!("serialising chainlog line: {e}"))?;
    s.push('\n');
    Ok(s)
}

/// Append a pre-serialised line to `path` (create if missing) + fsync.
fn append_and_fsync<H: ChainHost>(path: &Path, line: &str, mode: u32) -> Result<()> {
    let f = append_line::<H>(path, line, mode)?;
    f.sync_all()
        .with_context(|| format!("fsync {}", path.display()))?;
    Ok(())
}

/// Append a pre-serialised line to `path` (create if missing), without
/// waiting for the disk. Returns the open file.
fn append_line<H: ChainHost>(path: &Path, line: &str, mode: u32) -> Result<std::fs::File> {
    let mut f = H::open_with_mode(OpenOptions::new().create(true).append(true), mode, path)
        .with_context(|| format!("opening chainlog {} for append", path.display()))?;
    f.write_all(line.as_bytes())
        .with_context(|| format!("appending to {}", path.display()))?;
    Ok(f)
}

// ── protection manager (the +i dance hook) ──────────────────────────

/// Hook the rotator calls for the dir-entry mutations (`rename`,
/// `create`, `unlink`) that `chattr +i` on the state dir would block.
///
/// The production impl (in `anti_tamper`) lifts the directory's
/// immutability for the duration of `f`, restoring `+i` on EVERY exit
/// path — success, error, or panic — so a failed rotation can never
/// leave the dir mutable, and registers the new active inode in
/// `PROTECTED_INODES`. Logs outside the protected dir use
/// [`NoProtection`].
///
/// **Object-safe** (no generic methods, `Send + Sync` supertrait) so a
/// single manager can be shared as `Arc<dyn ProtectionManager>` across
/// the several writers under one state dir — `netflow.jsonl` +
/// `fim_drift.jsonl` both live in `/var/lib/northnarrow` and MUST share
/// the same dance mutex (else two concurrent rotations race the dir's
/// `+i`). The writers therefore stay non-generic and unit-testable
/// (tests pass `Arc::new(NoProtection)`).
pub trait ProtectionManager: Send + Sync {
    /// Run `f` with the state dir mutable, then restore immutability
    /// before returning (fail-safe). `f` returns `()`; rotation captures
    /// its outputs (the evicted list) via its own closure environment so
    /// this method stays object-safe.
    fn with_mutable_dir(&self, f: &mut dyn FnMut() -> Result<()>) -> Result<()>;

    /// Register a freshly-created active file's inode in
    /// `PROTECTED_INODES` so the LSM defends it like its predecessor.
    fn register_active(&self, path: &Path) -> Result<()>;

    /// Drop an archive's inode from `PROTECTED_INODES` just before it is
    /// evicted (review 80). Left there, the key outlived the file until the
    /// next agent start, and the filesystem gives a freed inode number to
    /// the next file it creates: an unrelated file, anyone's, that could no
    /// longer be written, renamed or removed, each try an anti-tamper
    /// denial (NN-L-AT-001, the strongest posture signal). Default: no
    /// protection, nothing to drop.
    fn release(&self, _path: &Path) -> Result<()> {
        Ok(())
    }
}

/// No-op manager for unprotected logs and tests: the dir is plain-
/// writable, so the dance is a direct call.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoProtection;

impl ProtectionManager for NoProtection {
    fn with_mutable_dir(&self, f: &mut dyn FnMut() -> Result<()>) -> Result<()> {
        f()
    }
    fn register_active(&self, _path: &Path) -> Result<()> {
        Ok(())
    }
}

// ── rotating writer ─────────────────────────────────────────────────

/// Environment overrides of the evidence logs' active-file caps
/// (test/ops knobs for rotation checks).
pub const FIM_DRIFT_CAP_ENV: &str = "NN_FIM_DRIFT_CAP_BYTES";
pub const DETECTIONS_CAP_ENV: &str = "NN_DETECTIONS_CAP_BYTES";
pub const STATUS_EVENTS_CAP_ENV: &str = "NN_STATUS_EVENTS_CAP_BYTES";

/// Lowest cap an environment override may set. External audit MAIN-004:
/// any `u64` used to be taken, so a one-line drop-in could rotate the
/// signed evidence away after every row.
pub const MIN_ENV_CAP_BYTES: u64 = 1024 * 1024;

/// The active-file cap for `env`: `default` unless the variable is set,
/// never below [`MIN_ENV_CAP_BYTES`]. Every override is logged; the
/// self-integrity check also records it in the signed chain.
pub fn cap_from_env(env: &str, default: u64) -> u64 {
    cap_from_value(env, std::env::var(env).ok().as_deref(), default)
}

fn cap_from_value(env: &str, raw: Option<&str>, default: u64) -> u64 {
    let Some(raw) = raw else {
        return default;
    };
    match raw.trim().parse::<u64>() {
        Err(_) => {
            warn!(
                env,
                value = raw,
                default_bytes = default,
                "rotation cap override does not parse — the default applies"
            );
            default
        }
        Ok(bytes) if bytes < MIN_ENV_CAP_BYTES => {
            warn!(
                env,
                requested_bytes = bytes,
                cap_bytes = MIN_ENV_CAP_BYTES,
                "rotation cap override below the floor — raised to the floor"
            );
            MIN_ENV_CAP_BYTES
        }
        Ok(bytes) => {
            if bytes != default {
                warn!(
                    env,
                    cap_bytes = bytes,
                    default_bytes = default,
                    "rotation cap OVERRIDDEN (test/ops knob)"
                );
            }
            bytes
        }
    }
}

/// Mode of the evidence logs the agent creates in its state directory
/// (`/var/lib/northnarrow`: detections, status events, netflow and its
/// listeners, the FIM baseline and drift, the canary chains), their
/// archives and manifests. External audit EVD-019 (NN-AUD-281): they were
/// `0644` and closed only by the directory's `0700`; a copy that keeps
/// the mode (`cp -a`, a backup) or a log moved out of the directory was
/// readable by every local user. Root reads them (`nn-admin`, the agent).
pub const STATE_LOG_FILE_MODE: u32 = 0o600;

/// Size + retention policy for one log.
#[derive(Debug, Clone, Copy)]
pub struct RotationConfig {
    /// Rotate when the active file would exceed this many bytes.
    pub size_cap_bytes: u64,
    /// Keep at most this many sealed archives; evict the oldest beyond.
    /// Total on-disk budget for the log ≈ `(max_archives + 1) *
    /// size_cap_bytes` (+ the small manifest).
    pub max_archives: usize,
    /// Mode for created files.
    pub file_mode: u32,
}

impl Default for RotationConfig {
    fn default() -> Self {
        Self {
            size_cap_bytes: 64 * 1024 * 1024,
            max_archives: 8,
            file_mode: STATE_LOG_FILE_MODE,
        }
    }
}

/// A sealed active file waiting for its rename (see `pending_seal`).
#[derive(Debug, Clone)]
struct PendingSeal {
    seq: u64,
    terminator_hash: String,
    bytes: u64,
    records: u64,
}

/// Append-only, rotation-aware, signed chain writer for one log.
pub struct RotatingChainLog<P, K> {
    active_path: PathBuf,
    manifest_path: PathBuf,
    key: K,
    cfg: RotationConfig,
    protection: std::sync::Arc<dyn ProtectionManager>,
    /// Tail `entry_hash` the next data line chains off (the previous
    /// file's terminator hash right after a rotation; GENESIS on a
    /// fresh seq-0 file).
    last_hash: String,
    /// Separate tail for the manifest chain.
    manifest_last_hash: String,
    /// Byte length of the active file. Recovered O(1) from the file length
    /// at open (was an unbounded whole-file walk); the rotation trigger.
    active_bytes: u64,
    /// Records appended *this session* (0 after open — the O(1) open no
    /// longer counts the file). Feeds only the advisory `record_count` in
    /// the terminator/manifest, which the verifier recomputes and does not
    /// trust; NOT used for the rotation decision (that is `active_bytes`).
    active_records: u64,
    /// Seq the NEXT rotation assigns to the sealed file.
    next_seq: u64,
    /// External audit NN-AUD-115: the active file is already sealed (its
    /// terminator is on disk) but the rename did not happen. The next append
    /// retries only the finish step; sealing again would put a second
    /// terminator in one file, which fails `verify_one_file`.
    pending_seal: Option<PendingSeal>,
    /// External audit NET-019: lines written by [`Self::append_deferred`]
    /// that no fsync has covered yet.
    unsynced: bool,
    /// fsyncs of the active file by this writer (introspection, tests).
    fsyncs: u64,
    /// External audit NN-AUD-109: records appended since the last
    /// [`ManifestEvent::ActiveCheckpoint`], and when it was written.
    since_checkpoint: u64,
    checkpoint_at: std::time::Instant,
    /// Lab PR 249: the time the terminators and manifest rows are stamped
    /// with (the host's unless [`Self::open_with_clock`] was given another).
    clock: std::sync::Arc<dyn Clock>,
    _marker: std::marker::PhantomData<P>,
}

/// External audit NN-AUD-109: a checkpoint after this many records...
pub const CHECKPOINT_EVERY_RECORDS: u64 = 1000;
/// ...or after this long with records appended since the last one.
pub const CHECKPOINT_EVERY_SECS: u64 = 600;

impl<P: Serialize + DeserializeOwned + ChainPayload, K: ChainSigner> RotatingChainLog<P, K> {
    /// Open (or initialise) the log at `active_path`. Scans existing
    /// archives to recover `next_seq`, walks the (bounded) active file
    /// for its tail/size/count, and completes a half-finished rotation
    /// if a crash left the active file sealed-but-unrenamed.
    pub fn open(
        active_path: &Path,
        key: K,
        cfg: RotationConfig,
        protection: std::sync::Arc<dyn ProtectionManager>,
    ) -> Result<Self> {
        Self::open_with_clock(
            active_path,
            key,
            cfg,
            protection,
            std::sync::Arc::new(SystemClock),
        )
    }

    /// Lab PR 249: [`Self::open`] stamping the rows it writes — the
    /// terminators and the manifest rows, those written at open included —
    /// with `clock` instead of the host's. Its data lines carry no time of
    /// their own.
    pub fn open_with_clock(
        active_path: &Path,
        key: K,
        cfg: RotationConfig,
        protection: std::sync::Arc<dyn ProtectionManager>,
        clock: std::sync::Arc<dyn Clock>,
    ) -> Result<Self> {
        // Review entry 44: every later open/rename goes through a directory
        // fd taken now, so a mount over the directory cannot divert the log.
        let anchored = K::Host::anchor(active_path);
        let active_path = anchored.as_path();
        let manifest_path = manifest_path_for(active_path);
        let next_seq = scan_max_archive_seq(active_path)?.map_or(1, |m| m + 1);
        // External audit NN-AUD-110: the adopted tail line must recompute
        // to its own `entry_hash` (and is signature-checked) before the
        // chain continues from it or a rotation is completed on its word.
        let pubkey = key.verifying_key();
        let check_active = |l: &[u8]| check_active_line::<P>(l, &pubkey);
        let check_manifest = |l: &[u8]| check_manifest_line(l, P::KIND, &pubkey);
        // Recover the manifest tail O(1). If a prior crash tore its last
        // line, truncate the fragment so the next manifest line can't fuse
        // with it; the repair is attested below (once the log can sign one).
        let manifest_rec = recover_tail(&manifest_path, &check_manifest)?;
        if manifest_rec.torn {
            truncate_file(&manifest_path, manifest_rec.clean_len)?;
        }

        let mut log = Self {
            active_path: active_path.to_path_buf(),
            manifest_path,
            key,
            cfg,
            protection,
            last_hash: GENESIS_PREV_HASH.to_string(),
            manifest_last_hash: manifest_rec.tail_hash.clone(),
            active_bytes: 0,
            active_records: 0,
            next_seq,
            pending_seal: None,
            unsynced: false,
            fsyncs: 0,
            since_checkpoint: 0,
            checkpoint_at: std::time::Instant::now(),
            clock,
            _marker: std::marker::PhantomData,
        };

        // Attest a manifest self-repair into its own meta-chain (chained off
        // the recovered tail) — truncating a signed log MUST be recorded.
        if manifest_rec.torn {
            log.attest_torn_repair(
                "manifest",
                manifest_rec.clean_len,
                manifest_rec.dropped_bytes,
                manifest_rec.dropped_sha256.clone(),
            )?;
        }
        if let Some(reason) = &manifest_rec.unverified {
            log.attest_tail_unverified("manifest", &manifest_rec.tail_hash, reason);
        }

        // Recover the active file's tail O(1) — replaces the unbounded
        // whole-file walk that was the BUG-026 boot hang. Repair + attest a
        // torn tail the same way (the agent is exempt from its own LSM
        // setattr deny, so the in-place truncate is allowed).
        let active_rec = recover_tail(active_path, &check_active)?;
        if active_rec.torn {
            truncate_file(active_path, active_rec.clean_len)?;
            log.attest_torn_repair(
                "active",
                active_rec.clean_len,
                active_rec.dropped_bytes,
                active_rec.dropped_sha256.clone(),
            )?;
        }
        if let Some(reason) = &active_rec.unverified {
            log.attest_tail_unverified("active", &active_rec.tail_hash, reason);
        }
        if let Some(this_seq) = active_rec.sealed_seq {
            // Crash recovery: the active file was sealed (terminator
            // written) but the rename never completed. Finish it so the
            // invariant "the active file has no terminator" is restored.
            // External audit NN-AUD-110: only a fully decoded, verified
            // terminator gets here, and its own `this_seq` names the slot.
            log.last_hash = active_rec.tail_hash; // terminator hash → meta-chain link
            log.active_bytes = active_rec.clean_len;
            if let Err(e) = log.complete_interrupted_rotation(this_seq) {
                // External audit NN-AUD-115: keep the log usable; the next
                // append retries the finish step (never a second seal).
                error!(
                    error = %format!("{e:#}"),
                    log = %log.active_path.display(),
                    "chainlog: could not finish an interrupted rotation at open; will retry"
                );
            }
        } else {
            log.last_hash = if active_rec.clean_len == 0 {
                // Fresh seq-0 file roots at GENESIS; a fresh post-rotation
                // file would already have its first line written, so an
                // empty active here is genuinely seq-0.
                if next_seq == 1 {
                    GENESIS_PREV_HASH.to_string()
                } else {
                    // Empty active after rotation: its first line must
                    // chain off the prior archive's terminator.
                    log.prior_link_or_genesis(next_seq - 1)
                }
            } else {
                active_rec.tail_hash
            };
            log.active_bytes = active_rec.clean_len;
        }
        // `active_records` is intentionally left 0 here: the O(1) open no
        // longer counts the file (that was the unbounded walk). It now
        // tracks records appended *this session* and feeds only the
        // terminator/manifest `record_count`, which the verifier treats as
        // advisory (it recounts independently — see `verify_one_file`). The
        // rotation trigger keys on `active_bytes` (recovered from the file
        // length), not on this count.
        //
        // External audit NN-AUD-109: anchor what this open found, unless the
        // manifest already says exactly that. Non-fatal.
        if log.pending_seal.is_none() && log.active_bytes > 0 {
            let current = (log.next_seq, log.active_bytes, log.last_hash.clone());
            let anchored = manifest_tail_events::<K::Host>(&log.active_path, P::KIND, &pubkey)
                .into_iter()
                .find_map(|e| match e {
                    ManifestEvent::ActiveCheckpoint {
                        seq,
                        bytes,
                        tail_hash,
                    } => Some((seq, bytes, tail_hash)),
                    _ => None,
                });
            if anchored.as_ref() != Some(&current) {
                if let Err(e) = log.checkpoint() {
                    warn!(
                        error = %format!("{e:#}"),
                        log = %log.active_path.display(),
                        "chainlog: active checkpoint not written at open"
                    );
                }
            }
        }
        Ok(log)
    }

    /// Tail hash the next data line will chain off (test/introspection).
    pub fn last_hash(&self) -> &str {
        &self.last_hash
    }

    /// The verifying key of this log's signing key (the read path checks
    /// rows with it, external audit NN-AUD-112).
    pub fn verifying_key(&self) -> VerifyingKey {
        self.key.verifying_key()
    }

    /// External audit NN-AUD-109: record the active file's head in the
    /// manifest ([`ManifestEvent::ActiveCheckpoint`]). Nothing to record
    /// for an empty active file.
    pub fn checkpoint(&mut self) -> Result<()> {
        if self.active_bytes == 0 || self.pending_seal.is_some() {
            return Ok(());
        }
        // NET-019 group commit: the head recorded must be on disk first, or
        // a power loss would leave a checkpoint naming a line that is gone
        // (read at the next boot as a truncation).
        self.sync()?;
        self.ensure_manifest()?;
        self.manifest_append(ManifestEvent::ActiveCheckpoint {
            seq: self.next_seq,
            bytes: self.active_bytes,
            tail_hash: self.last_hash.clone(),
        })?;
        self.since_checkpoint = 0;
        self.checkpoint_at = std::time::Instant::now();
        Ok(())
    }

    /// Create the manifest if it does not exist yet, inside the `+i`
    /// dance (a new name in the immutable state directory), and register
    /// it. Must not be called from inside the dance (it takes it).
    fn ensure_manifest(&mut self) -> Result<()> {
        if fs::symlink_metadata(&self.manifest_path).is_ok() {
            return Ok(());
        }
        let manifest = self.manifest_path.clone();
        let mode = self.cfg.file_mode;
        self.protection
            .with_mutable_dir(&mut || match K::Host::open_with_mode(
                OpenOptions::new().create_new(true).write(true),
                mode,
                &manifest,
            ) {
                Ok(_) => Ok(()),
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => Ok(()),
                Err(e) => Err(anyhow!(e).context(format!("creating {}", manifest.display()))),
            })?;
        if let Err(e) = self.protection.register_active(&self.manifest_path) {
            warn!(
                error = %format!("{e:#}"),
                path = %self.manifest_path.display(),
                "chainlog: could not register the manifest in PROTECTED_INODES"
            );
        }
        Ok(())
    }

    /// A checkpoint is due after an append.
    fn checkpoint_due(&self) -> bool {
        self.since_checkpoint >= CHECKPOINT_EVERY_RECORDS
            || (self.since_checkpoint > 0
                && self.checkpoint_at.elapsed().as_secs() >= CHECKPOINT_EVERY_SECS)
    }

    /// Count one appended record and write a checkpoint when due
    /// (non-fatal: the record is already on disk).
    fn after_append(&mut self) {
        self.since_checkpoint += 1;
        if self.checkpoint_due() {
            if let Err(e) = self.checkpoint() {
                warn!(
                    error = %format!("{e:#}"),
                    log = %self.active_path.display(),
                    "chainlog: active checkpoint not written"
                );
                self.checkpoint_at = std::time::Instant::now();
            }
        }
    }

    /// Append one payload as a signed data line, rotating first if it
    /// would push the active file past the size cap. Returns the new
    /// line's `entry_hash`. The line is on disk (fsync) when this returns.
    pub fn append(&mut self, payload: P) -> Result<String> {
        self.append_with(payload, true)
    }

    /// External audit NET-019: [`Self::append`] without the fsync, for a
    /// group commit. The line is written (other readers see it); it is on
    /// disk at the next [`Self::sync`] or rotation. Until then a crash of
    /// the host can lose it, or tear it — the next open cuts a torn tail
    /// and attests the repair (`repair_torn_tail`), so the chain stays
    /// verifiable. The caller bounds how long lines wait.
    pub fn append_deferred(&mut self, payload: P) -> Result<String> {
        self.append_with(payload, false)
    }

    /// External audit NET-019: fsync the lines [`Self::append_deferred`]
    /// wrote. A no-op when there are none.
    pub fn sync(&mut self) -> Result<()> {
        if !self.unsynced {
            return Ok(());
        }
        let f = OpenOptions::new()
            .append(true)
            .open(&self.active_path)
            .with_context(|| {
                format!("opening chainlog {} for fsync", self.active_path.display())
            })?;
        f.sync_all()
            .with_context(|| format!("fsync {}", self.active_path.display()))?;
        self.unsynced = false;
        self.fsyncs += 1;
        Ok(())
    }

    /// Whether lines written by [`Self::append_deferred`] wait for an fsync.
    pub fn has_unsynced(&self) -> bool {
        self.unsynced
    }

    /// fsyncs of the active file by this writer since it was opened.
    pub fn fsyncs(&self) -> u64 {
        self.fsyncs
    }

    /// Write `bytes` to the active file, with or without an fsync.
    fn write_active(&mut self, bytes: &str, durable: bool) -> Result<()> {
        if durable {
            append_and_fsync::<K::Host>(&self.active_path, bytes, self.cfg.file_mode)?;
            // The fsync covers the earlier deferred lines of this file.
            self.unsynced = false;
            self.fsyncs += 1;
        } else {
            append_line::<K::Host>(&self.active_path, bytes, self.cfg.file_mode)?;
            self.unsynced = true;
        }
        Ok(())
    }

    fn append_with(&mut self, payload: P, durable: bool) -> Result<String> {
        check_reserved_keys(&payload)?;
        // External audit NN-AUD-115: a previous rotation sealed the active
        // file but could not rename it. Retry only the finish step.
        if let Some(p) = self.pending_seal.clone() {
            self.finish_rotation(p.seq, p.terminator_hash, p.bytes, p.records)?;
        }
        let line = ChainLine::sealed(payload, &self.key, &self.last_hash)?;
        let bytes = to_jsonl(&line)?;
        // Guard on `active_bytes` (recovered from the file length at open),
        // NOT `active_records` (which is now 0 after a mid-life open): a
        // pre-existing over-cap active file — e.g. a legacy log inherited at
        // the BUG-026 migration — must rotate on its FIRST append, and an
        // empty fresh file (0 bytes) must NOT rotate its first line.
        if self.active_bytes > 0 && self.active_bytes + bytes.len() as u64 > self.cfg.size_cap_bytes
        {
            self.rotate()?;
            // After rotation the line was hashed off the OLD tail; rebuild
            // it off the new tail (the terminator hash / meta-chain link).
            let line = ChainLine::sealed(line.payload, &self.key, &self.last_hash)?;
            let bytes = to_jsonl(&line)?;
            self.write_active(&bytes, durable)?;
            self.last_hash = line.entry_hash.clone();
            self.active_bytes += bytes.len() as u64;
            self.active_records += 1;
            self.after_append();
            return Ok(line.entry_hash);
        }
        self.write_active(&bytes, durable)?;
        self.last_hash = line.entry_hash.clone();
        self.active_bytes += bytes.len() as u64;
        self.active_records += 1;
        self.after_append();
        Ok(line.entry_hash)
    }

    /// Seal the active file, archive it, open a fresh active, and evict
    /// the oldest archive(s) beyond the retention budget.
    fn rotate(&mut self) -> Result<()> {
        // External audit NN-AUD-115: the archive slot is free in every state
        // this writer produces, so an occupied slot is a foreign entry. Pick
        // the next free slot before sealing, so the terminator names the
        // archive it will really become (lstat: a symlink counts as taken).
        let mut seq = self.next_seq;
        for _ in 0..MAX_SLOT_PROBES {
            if slot_kind(&archive_path(&self.active_path, seq)).is_none() {
                break;
            }
            seq = next_free_candidate(&self.active_path, seq);
        }
        self.next_seq = seq;
        let term = TerminatorLine::sealed(
            RotateTerminator {
                fmt_ver: CHAINLOG_FMT_V3,
                this_seq: seq,
                next_seq: seq + 1,
                record_count: self.active_records,
                bytes: self.active_bytes,
            },
            &self.key,
            &self.last_hash,
            P::KIND,
            self.clock.as_ref(),
        )?;
        let terminator_hash = term.entry_hash.clone();
        let sealed_bytes = self.active_bytes;
        let sealed_records = self.active_records;
        // SEAL: append the terminator to the active file. Done OUTSIDE the
        // `+i` dance — appending to an *existing* file is allowed under an
        // immutable dir; only NEW/renamed dir entries need the lift.
        append_and_fsync::<K::Host>(&self.active_path, &to_jsonl(&term)?, self.cfg.file_mode)?;
        // The terminator's fsync covers the deferred lines before it.
        self.unsynced = false;
        self.fsyncs += 1;
        self.pending_seal = Some(PendingSeal {
            seq,
            terminator_hash: terminator_hash.clone(),
            bytes: sealed_bytes,
            records: sealed_records,
        });
        self.finish_rotation(seq, terminator_hash, sealed_bytes, sealed_records)
    }

    /// Commit a sealed active file to its `seq` archive and open a fresh
    /// active. Shared by [`rotate`] (which writes the terminator first) and
    /// [`complete_interrupted_rotation`] (whose active was sealed before a
    /// crash). BUG-030 — failure-atomic, and EVERY dir-entry mutation runs
    /// INSIDE the `+i` dance:
    ///
    /// 1. **rename** active → `.NNNNNN`, never over an existing name (an
    ///    occupied slot is foreign: skipped and attested, NN-AUD-115).
    /// 2. **advance** `next_seq` + reset counters IMMEDIATELY — the archive
    ///    is now committed on disk, so NO later failure in this function can
    ///    re-rotate into `seq` and overwrite the sealed archive (the bug-2
    ///    data-loss path).
    /// 3. **create** the fresh empty active + register its inode.
    /// 4. **manifest** Rotated/Evicted rows — created INSIDE the dance (a new
    ///    `.manifest.jsonl` dir entry the `+i` dir would otherwise reject with
    ///    EPERM: the bug-1 path). NON-FATAL: a missing manifest row is
    ///    recoverable (the verifier doesn't need it for a non-evicted set); a
    ///    destroyed signed archive is not. Priority: never lose signed data >
    ///    attest the rotation.
    fn finish_rotation(
        &mut self,
        seq: u64,
        terminator_hash: String,
        sealed_bytes: u64,
        sealed_records: u64,
    ) -> Result<()> {
        let active = self.active_path.clone();
        let file_mode = self.cfg.file_mode;
        let max_archives = self.cfg.max_archives;
        // Receiver clone + a second clone for register_active, so the dance
        // closure can borrow `self` mutably (advance + manifest) without
        // aliasing the protection manager it runs under.
        let protection = std::sync::Arc::clone(&self.protection);
        let protection_inner = std::sync::Arc::clone(&self.protection);
        protection.with_mutable_dir(&mut || -> Result<()> {
            // 1. RENAME without replacing anything. External audit NN-AUD-115:
            //    this used to skip the rename when the archive name existed
            //    and then truncate the active anyway, destroying the sealed
            //    file. The slot is free in every state this writer produces,
            //    so an occupied one is foreign: leave it untouched, attest it
            //    below and archive into the next free slot.
            let mut seq = seq;
            let mut foreign: Vec<(u64, &'static str, u64)> = Vec::new();
            let mut attempts = 0;
            loop {
                let archive = archive_path(&active, seq);
                match K::Host::rename_noreplace(&active, &archive) {
                    Ok(()) => break,
                    Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                        let (kind, bytes) = slot_kind(&archive).unwrap_or(("other", 0));
                        foreign.push((seq, kind, bytes));
                        attempts += 1;
                        if attempts >= MAX_SLOT_PROBES {
                            return Err(anyhow!(
                                "sealing {}: {attempts} archive slots taken by foreign entries",
                                active.display()
                            ));
                        }
                        seq = next_free_candidate(&active, seq);
                    }
                    Err(e) => {
                        return Err(anyhow!(e).context(format!(
                            "sealing {} → {}",
                            active.display(),
                            archive.display()
                        )))
                    }
                }
            }
            // 2. COMMIT POINT — advance seq + reset counters immediately. The
            //    archive is now on disk; from here no failure may re-rotate
            //    into `seq`. last_hash = terminator (fresh active's chain link).
            self.last_hash = terminator_hash.clone();
            self.active_bytes = 0;
            self.active_records = 0;
            self.next_seq = seq + 1;
            self.pending_seal = None;
            // The `Rotated` row anchors the sealed file.
            self.since_checkpoint = 0;
            self.checkpoint_at = std::time::Instant::now();
            // 3. Fresh empty active (O_EXCL: never truncate or follow a name
            //    that appeared after the rename) + register its inode.
            create_fresh_active::<K::Host>(&active, file_mode)?;
            protection_inner.register_active(&active)?;
            // 4. Manifest + eviction — NON-FATAL (archive already committed).
            let evicted = evict_excess_archives(&active, max_archives, protection_inner.as_ref())
                .unwrap_or_else(|e| {
                error!(error = %e, "chainlog: archive eviction failed post-rotate (committed; continuing)");
                Vec::new()
            });
            let rotated = self.manifest_append(ManifestEvent::Rotated {
                seq,
                terminator_hash: terminator_hash.clone(),
                bytes: sealed_bytes,
                records: sealed_records,
            });
            // Review 81: the manifest is born at the first rotation; protect
            // it like the logs it attests (idempotent on later rotations).
            if self.manifest_path.exists() {
                if let Err(e) = protection_inner.register_active(&self.manifest_path) {
                    warn!(
                        error = %format!("{e:#}"),
                        path = %self.manifest_path.display(),
                        "chainlog: could not register the manifest in PROTECTED_INODES"
                    );
                }
            }
            if let Err(e) = rotated {
                error!(
                    error = %e, seq,
                    "chainlog: manifest Rotated append failed — archive committed + chain \
                     intact; manifest row missing but recoverable (BUG-030 degrade)"
                );
            }
            for (fseq, kind, bytes) in foreign.drain(..) {
                error!(
                    seq = fseq, kind, bytes,
                    log = %active.display(),
                    "chainlog: a foreign entry holds an archive slot; archived to the next free slot"
                );
                if let Err(e) = self.manifest_append(ManifestEvent::ForeignArchive {
                    seq: fseq,
                    entry_type: kind.to_string(),
                    bytes,
                }) {
                    error!(error = %e, fseq, "chainlog: manifest ForeignArchive append failed (continuing)");
                }
            }
            for (eseq, ehash) in evicted {
                if let Err(e) = self.manifest_append(ManifestEvent::Evicted {
                    seq: eseq,
                    terminator_hash: ehash,
                }) {
                    error!(error = %e, eseq, "chainlog: manifest Evicted append failed (continuing)");
                }
            }
            Ok(())
        })
    }

    /// Finish a rotation that crashed after the seal but before/at the
    /// rename. The active file currently ends in a verified terminator for
    /// `seq` (its `this_seq`); [`finish_rotation`] renames it to its archive
    /// (never over an existing name) and opens a fresh active. `self.last_hash` is already the terminator
    /// hash (set by `open` from the recovered tail), so it is the meta-chain
    /// link for the fresh active's first line.
    fn complete_interrupted_rotation(&mut self, seq: u64) -> Result<()> {
        let terminator_hash = self.last_hash.clone();
        let sealed_bytes = self.active_bytes;
        let sealed_records = self.active_records;
        self.pending_seal = Some(PendingSeal {
            seq,
            terminator_hash: terminator_hash.clone(),
            bytes: sealed_bytes,
            records: sealed_records,
        });
        self.finish_rotation(seq, terminator_hash, sealed_bytes, sealed_records)
    }

    /// Attest a torn-tail repair (a boot-time truncation of this signed log)
    /// into the manifest meta-chain, so the truncation is recorded and an
    /// auditor can tell a legitimate crash-repair from tampering. `role` is
    /// `"active"` or `"manifest"`. The attestation line is itself signed and
    /// chained off the current manifest tail.
    fn attest_torn_repair(
        &mut self,
        role: &str,
        recovered_len: u64,
        dropped_bytes: u64,
        dropped_sha256: String,
    ) -> Result<()> {
        warn!(
            log = %self.active_path.display(),
            role,
            recovered_len,
            dropped_bytes,
            dropped_sha256 = %dropped_sha256,
            "chainlog: torn-tail repair — truncated to the last complete entry; \
             attesting the discard in the manifest"
        );
        self.manifest_append(ManifestEvent::TornTailRepaired {
            role: role.to_string(),
            recovered_len,
            dropped_bytes,
            dropped_sha256,
        })
    }

    /// The terminator hash of archive `seq`, which a fresh empty active
    /// chains off. External audit NN-AUD-110: a newest archive without a
    /// well-formed terminator (a foreign file, or a forged non-hex hash)
    /// made `open` fail, or every append fail on `hex::decode`, at every
    /// boot. It is attested as foreign instead and the active roots at
    /// GENESIS; the verifier still flags the archive.
    fn prior_link_or_genesis(&mut self, seq: u64) -> String {
        let reason = match prior_terminator_hash(&self.active_path, seq) {
            Ok(h) if is_chain_hash(&h) => return h,
            Ok(h) => format!("terminator entry_hash {h:?} is not a chain hash"),
            Err(e) => format!("{e:#}"),
        };
        let (kind, bytes) =
            slot_kind(&archive_path(&self.active_path, seq)).unwrap_or(("other", 0));
        error!(
            log = %self.active_path.display(),
            seq,
            reason = %reason,
            "chainlog: newest archive has no usable terminator; rooting the active at GENESIS"
        );
        if let Err(e) = self.manifest_append(ManifestEvent::ForeignArchive {
            seq,
            entry_type: kind.to_string(),
            bytes,
        }) {
            error!(error = %format!("{e:#}"), seq, "chainlog: manifest ForeignArchive append failed");
        }
        GENESIS_PREV_HASH.to_string()
    }

    /// External audit NN-AUD-110: record that the tail adopted at open was
    /// kept without full verification (see [`ManifestEvent::TailUnverified`]).
    /// Non-fatal: a failed attestation must not keep the log closed.
    fn attest_tail_unverified(&mut self, role: &str, entry_hash: &str, reason: &str) {
        warn!(
            log = %self.active_path.display(),
            role,
            entry_hash,
            reason,
            "chainlog: tail line kept without full verification; attesting it in the manifest"
        );
        if let Err(e) = self.manifest_append(ManifestEvent::TailUnverified {
            role: role.to_string(),
            entry_hash: entry_hash.to_string(),
            reason: reason.to_string(),
        }) {
            error!(error = %format!("{e:#}"), role, "chainlog: manifest TailUnverified append failed");
        }
    }

    fn manifest_append(&mut self, event: ManifestEvent) -> Result<()> {
        let entry = ManifestEntry {
            fmt_ver: CHAINLOG_FMT_V3,
            ts: stamp(self.clock.as_ref()),
            event,
        };
        let line = ManifestLine::sealed(entry, &self.key, &self.manifest_last_hash, P::KIND)?;
        append_and_fsync::<K::Host>(&self.manifest_path, &to_jsonl(&line)?, self.cfg.file_mode)?;
        self.manifest_last_hash = line.entry_hash;
        Ok(())
    }
}

// ── path helpers ────────────────────────────────────────────────────

/// The sealed files of the chain log whose active file is `active`: its
/// archives and its manifest, those that exist (review 81). The agent
/// registers them in `PROTECTED_INODES` at start: until then a sealed
/// archive kept its key only for the boot that rotated it, and a manifest
/// never had one.
pub fn sealed_files(active: &Path) -> Vec<PathBuf> {
    let mut out: Vec<PathBuf> = list_archive_seqs(active)
        .unwrap_or_default()
        .into_iter()
        .map(|seq| archive_path(active, seq))
        .collect();
    let manifest = manifest_path_for(active);
    if manifest.exists() {
        out.push(manifest);
    }
    out
}

/// The manifest of the log whose active file is `active`.
pub fn manifest_path(active: &Path) -> PathBuf {
    manifest_path_for(active)
}

/// The archive `seq` of the log whose active file is `active`.
pub fn archive_path_for(active: &Path, seq: u64) -> PathBuf {
    archive_path(active, seq)
}

/// External audit NN-AUD-109: the generation of the active file now — the
/// archive seq it becomes when sealed (1 before any rotation).
pub fn current_generation(active: &Path) -> u64 {
    scan_max_archive_seq(active)
        .ok()
        .flatten()
        .map_or(1, |m| m + 1)
}

/// Lowest archive seq on disk.
pub fn earliest_archive(active: &Path) -> Option<u64> {
    list_archive_seqs(active).ok()?.into_iter().min()
}

fn manifest_path_for(active: &Path) -> PathBuf {
    let mut s = active.as_os_str().to_os_string();
    s.push(".manifest.jsonl");
    PathBuf::from(s)
}

fn archive_path(active: &Path, seq: u64) -> PathBuf {
    let mut s = active.as_os_str().to_os_string();
    s.push(format!(".{:0w$}", seq, w = SEQ_WIDTH));
    PathBuf::from(s)
}

/// Parse the `.NNNNNN` seq suffix of an archive path whose stem equals
/// `active`'s file name. `None` if `name` is not an archive of `active`.
///
/// External audit EVD-022 (NN-AUD-283, lab PR 190): the suffix is the one
/// [`archive_path`] writes for its value — six digits with leading zeros,
/// or more digits without one (`.1000000` from seq 1,000,000 on). Exactly
/// six digits were accepted, so an archive past seq 999,999 was invisible
/// to listing, eviction, verification and the read verbs. Any other
/// spelling of a number (`.00099`, `.0123456`) is not an archive, nor is a
/// seq of more than [`MAX_SEQ_DIGITS`] digits: every seq listed leaves room
/// for the `+ 1` of the next one.
fn parse_archive_seq(active: &Path, name: &std::ffi::OsStr) -> Option<u64> {
    let base = active.file_name()?.to_str()?;
    let name = name.to_str()?;
    let suffix = name.strip_prefix(base)?.strip_prefix('.')?;
    if !(SEQ_WIDTH..=MAX_SEQ_DIGITS).contains(&suffix.len())
        || !suffix.bytes().all(|b| b.is_ascii_digit())
    {
        return None;
    }
    let seq = suffix.parse::<u64>().ok()?;
    (format!("{:0w$}", seq, w = SEQ_WIDTH) == suffix).then_some(seq)
}

/// Longest archive seq suffix: 19 digits, below `u64::MAX` (20 digits) by
/// more than any number of rotations (one a second for 10^11 years).
const MAX_SEQ_DIGITS: usize = 19;

/// All present archive seqs for `active`, ascending.
fn list_archive_seqs(active: &Path) -> Result<Vec<u64>> {
    let dir = active.parent().unwrap_or_else(|| Path::new("."));
    let mut seqs = Vec::new();
    let rd = match fs::read_dir(dir) {
        Ok(rd) => rd,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(seqs),
        Err(e) => return Err(anyhow!(e).context(format!("read_dir {}", dir.display()))),
    };
    for ent in rd {
        let ent = ent.with_context(|| format!("dir entry in {}", dir.display()))?;
        if let Some(seq) = parse_archive_seq(active, &ent.file_name()) {
            seqs.push(seq);
        }
    }
    seqs.sort_unstable();
    Ok(seqs)
}

fn scan_max_archive_seq(active: &Path) -> Result<Option<u64>> {
    Ok(list_archive_seqs(active)?.into_iter().max())
}

/// The sealed archives of `active`, newest first (highest seq first: the
/// last rotated file holds the newest archived rows). An unreadable
/// directory yields none. External audit NN-AUD-080: the one lister for
/// the readers (the detection store and the admin read verbs).
pub fn archives_newest_first(active: &Path) -> Vec<PathBuf> {
    let mut seqs = list_archive_seqs(active).unwrap_or_default();
    seqs.reverse();
    seqs.into_iter()
        .map(|seq| archive_path(active, seq))
        .collect()
}

/// Whether a raw line is a [`TerminatorLine`]: its first key is `rotate`
/// (field order of the struct), which no data line may carry
/// ([`RESERVED_LINE_KEYS`]).
pub fn is_terminator_line(line: &str) -> bool {
    line.starts_with("{\"rotate\":")
}

/// Bound on the archive slots one rotation probes past foreign entries.
const MAX_SLOT_PROBES: u32 = 16;

/// What occupies `path`, by `lstat` (a symlink is reported, never
/// followed): `None` if the name is free.
fn slot_kind(path: &Path) -> Option<(&'static str, u64)> {
    let m = fs::symlink_metadata(path).ok()?;
    let ft = m.file_type();
    let kind = if ft.is_symlink() {
        "symlink"
    } else if ft.is_file() {
        "file"
    } else if ft.is_dir() {
        "dir"
    } else {
        "other"
    };
    Some((kind, m.len()))
}

/// The next archive slot to try after `taken`: past every archive name on
/// disk, so a foreign entry is never reused or overwritten.
fn next_free_candidate(active: &Path, taken: u64) -> u64 {
    let max = scan_max_archive_seq(active).ok().flatten().unwrap_or(0);
    max.max(taken) + 1
}

/// Create the fresh, empty active file after a rotation. External audit
/// NN-AUD-115: `O_CREAT|O_EXCL` (which also refuses a dangling symlink), so
/// a name that appeared after the rename is an error, never truncated or
/// followed.
fn create_fresh_active<H: ChainHost>(active: &Path, mode: u32) -> Result<()> {
    H::open_with_mode(
        OpenOptions::new().create_new(true).write(true),
        mode,
        active,
    )
    .with_context(|| format!("creating fresh active {}", active.display()))?;
    Ok(())
}

/// Drop oldest archives beyond `max_archives`, returning the
/// `(seq, terminator_hash)` of each evicted file (hash read from the
/// archive's terminator line before unlink, for the manifest record).
/// Each archive's inode is released from the protection first (review 80).
fn evict_excess_archives(
    active: &Path,
    max_archives: usize,
    protection: &dyn ProtectionManager,
) -> Result<Vec<(u64, String)>> {
    let seqs = list_archive_seqs(active)?;
    if seqs.len() <= max_archives {
        return Ok(Vec::new());
    }
    let drop_n = seqs.len() - max_archives;
    let mut evicted = Vec::new();
    for &seq in seqs.iter().take(drop_n) {
        let path = archive_path(active, seq);
        let hash = read_terminator_hash(&path).unwrap_or_default();
        if let Err(e) = protection.release(&path) {
            warn!(
                error = %format!("{e:#}"),
                path = %path.display(),
                "chainlog: could not release an evicted archive's inode from PROTECTED_INODES"
            );
        }
        fs::remove_file(&path).with_context(|| format!("evicting archive {}", path.display()))?;
        evicted.push((seq, hash));
    }
    Ok(evicted)
}

// ── torn tail of an append-only chain file ─────────────────────────

/// What [`repair_torn_tail`] did to a chain file's end.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TailRepair {
    /// The last line was complete but its `\n` never reached the disk: the
    /// newline was added, nothing dropped.
    Terminated,
    /// A fragment after the last newline did not parse — a write cut short.
    /// It was cut off; `dropped_sha256` fingerprints it for the
    /// attestation.
    Truncated {
        kept_len: u64,
        dropped_len: u64,
        dropped_sha256: String,
    },
}

/// External audit EVD-005, NET-003, DEC-006: a crash, a power loss or
/// ENOSPC between `write` and `fsync` leaves a chain file ending in a
/// fragment with no newline, and the strict readers then refused the file
/// at every later start — the agent would not boot (audit log), the
/// network drain never ran (listener log), deception was off (canary
/// logs).
///
/// Only that final fragment is repaired, never anything before it: a
/// complete line that does not parse is corruption, which stays the
/// reader's error. A fragment that `is_line` accepts gets its missing
/// newline back; any other fragment is cut off, unless nothing would
/// remain — a file with no complete line is left untouched and refused,
/// so no repair ever empties a chain. `None` when the file is missing,
/// empty or already ends in a newline.
pub fn repair_torn_tail(
    path: &Path,
    is_line: impl Fn(&[u8]) -> bool,
) -> Result<Option<TailRepair>> {
    let mut f = match OpenOptions::new().read(true).write(true).open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(anyhow!(e).context(format!("opening {}", path.display()))),
    };
    let size = f.metadata()?.len();
    if size == 0 {
        return Ok(None);
    }
    let mut last = [0u8; 1];
    f.seek(SeekFrom::Start(size - 1))?;
    f.read_exact(&mut last)?;
    if last[0] == b'\n' {
        return Ok(None);
    }
    // Walk back to the last newline, a window at a time.
    let mut window = 64 * 1024u64;
    let (fragment_start, fragment) = loop {
        let start = size.saturating_sub(window);
        f.seek(SeekFrom::Start(start))?;
        let mut buf = vec![0u8; (size - start) as usize];
        f.read_exact(&mut buf)?;
        if let Some(nl) = buf.iter().rposition(|&c| c == b'\n') {
            break (start + nl as u64 + 1, buf[nl + 1..].to_vec());
        }
        if start == 0 {
            break (0, buf);
        }
        if window >= TAIL_WINDOW_MAX {
            return Err(anyhow!(
                "{}: no newline in the last {TAIL_WINDOW_MAX} bytes — corrupt, not torn",
                path.display()
            ));
        }
        window = window.saturating_mul(4);
    };
    if is_line(&fragment) {
        f.seek(SeekFrom::End(0))?;
        f.write_all(b"\n")?;
        f.sync_all()?;
        return Ok(Some(TailRepair::Terminated));
    }
    if fragment_start == 0 {
        return Err(anyhow!(
            "{}: not one complete line ({size} bytes, no newline) — left untouched",
            path.display()
        ));
    }
    f.set_len(fragment_start)
        .with_context(|| format!("truncating the torn tail of {}", path.display()))?;
    f.sync_all()?;
    Ok(Some(TailRepair::Truncated {
        kept_len: fragment_start,
        dropped_len: fragment.len() as u64,
        dropped_sha256: sha256_hex(&fragment),
    }))
}

impl TailRepair {
    /// One line for the journal and the attestation.
    pub fn describe(&self) -> String {
        match self {
            TailRepair::Terminated => "a complete last line lacked its newline: added".to_string(),
            TailRepair::Truncated {
                kept_len,
                dropped_len,
                dropped_sha256,
            } => format!(
                "a torn last write ({dropped_len} bytes, sha256 {dropped_sha256}) was cut off; \
                 {kept_len} bytes of complete lines kept"
            ),
        }
    }
}

// ── readers (tail recovery, recovery probe) ─────────────────────────

/// Outcome of an O(1) tail recovery (see [`recover_tail`]).
struct TailRecovery {
    /// `entry_hash` of the last complete, parseable line; GENESIS if the
    /// file is missing / empty / has no parseable line.
    tail_hash: String,
    /// Logical length up to and including the last complete line's `\n`.
    /// Equals the file size when the tail is clean; smaller when a torn
    /// trailing fragment (or unparseable trailing line) was discarded.
    /// This is the byte count the rotation trigger keys on.
    clean_len: u64,
    /// The last complete line is a verified rotation terminator (crash
    /// recovery: a rotation that sealed but didn't finish the rename);
    /// carries its `this_seq`.
    sealed_seq: Option<u64>,
    /// External audit NN-AUD-110: the adopted tail was kept without full
    /// verification (why); the caller attests it.
    unverified: Option<String>,
    /// A trailing byte run past `clean_len` was discarded; the caller MUST
    /// truncate the file to `clean_len` before appending (so the torn bytes
    /// never land mid-chain → would fail `verify_log_set`) AND attest it.
    torn: bool,
    /// Bytes that would be discarded (`file_size - clean_len`); 0 if clean.
    dropped_bytes: u64,
    /// SHA-256 (hex) of the discarded bytes; empty if clean. Recorded in the
    /// repair attestation so an auditor can confirm WHAT was dropped and
    /// tell a legitimate boot repair from tampering.
    dropped_sha256: String,
}

impl TailRecovery {
    /// A clean, empty chain rooted at GENESIS (missing / zero-byte file).
    fn empty() -> Self {
        Self {
            tail_hash: GENESIS_PREV_HASH.to_string(),
            clean_len: 0,
            sealed_seq: None,
            unverified: None,
            torn: false,
            dropped_bytes: 0,
            dropped_sha256: String::new(),
        }
    }
}

/// Largest tail window we read looking for the last complete line. Chain
/// lines are a few hundred bytes, so 256 KiB holds thousands; we grow up
/// to [`TAIL_WINDOW_MAX`] only if a window somehow contains no complete
/// line, then declare the file corrupt rather than torn.
const TAIL_WINDOW: u64 = 256 * 1024;
const TAIL_WINDOW_MAX: u64 = 8 * 1024 * 1024;

/// SHA-256 (hex) of `bytes`. Fingerprints a discarded torn fragment for the
/// repair attestation.
fn sha256_hex(bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(bytes);
    hex::encode(h.finalize())
}

/// Recover a chain file's tail in **O(tail window), not O(file)** — the
/// fix for the BUG-026 boot hang. The old `walk_active` read + JSON-parsed
/// *every* line to recover the tail/size, which re-introduced an unbounded
/// multi-GB boot scan the moment the active file outgrew its rotation cap
/// (a legacy pre-rotation `fim_drift.jsonl` was 1.7 GB / 2.6M lines → ~129 s
/// of boot CPU). Here we seek to EOF and read backward a bounded window,
/// returning the last newline-terminated line that parses.
///
/// Robust to a torn final write (the agent has been SIGKILLed mid-append):
/// a trailing fragment with no terminating newline, or a final line that
/// fails to parse, is discarded and the tail is taken from the last line
/// that *does* parse (`torn` is set so the caller can truncate it away).
///
/// External audit NN-AUD-110: a candidate line must carry a 64-character
/// lowercase hex `entry_hash` (else it is skipped like a torn one) and pass
/// `check`, the typed hash/signature check of the caller. See
/// [`scan_back_for_tail`] for how a failed check is handled.
fn recover_tail(path: &Path, check: &dyn Fn(&[u8]) -> LineCheck) -> Result<TailRecovery> {
    let mut f = match OpenOptions::new().read(true).open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(TailRecovery::empty()),
        Err(e) => {
            return Err(anyhow!(e).context(format!("opening {} for tail recovery", path.display())))
        }
    };
    let size = f.metadata()?.len();
    if size == 0 {
        return Ok(TailRecovery::empty());
    }
    let mut window = TAIL_WINDOW.min(size);
    loop {
        let start = size - window;
        f.seek(SeekFrom::Start(start))
            .with_context(|| format!("seeking in {}", path.display()))?;
        let mut buf = vec![0u8; window as usize];
        f.read_exact(&mut buf)
            .with_context(|| format!("reading tail window of {}", path.display()))?;
        if let Some(rec) = scan_back_for_tail(&buf, start, start == 0, size, check) {
            return Ok(rec);
        }
        if start == 0 {
            // Whole file in the window, no parseable complete line at all →
            // it is all junk: root at GENESIS and drop everything (torn, so
            // the caller truncates to 0 and attests the discard).
            return Ok(TailRecovery {
                tail_hash: GENESIS_PREV_HASH.to_string(),
                clean_len: 0,
                sealed_seq: None,
                unverified: None,
                torn: true,
                dropped_bytes: size,
                dropped_sha256: sha256_hex(&buf),
            });
        }
        if window >= TAIL_WINDOW_MAX {
            return Err(anyhow!(
                "no complete parseable line in the last {TAIL_WINDOW_MAX} bytes of {} — \
                 file appears corrupt, not merely torn",
                path.display()
            ));
        }
        window = window.saturating_mul(4).min(size);
    }
}

/// Outcome of the typed check of one candidate tail line.
#[derive(Debug, Clone, PartialEq, Eq)]
enum LineCheck {
    /// Decodes, its `entry_hash` recomputes, its signature verifies.
    /// `Some(this_seq)` for a rotation terminator.
    Verified { terminator_seq: Option<u64> },
    /// Decodes and its hash recomputes, but the signature does not verify
    /// with this agent's key (for example a regenerated key).
    BadSignature,
    /// Does not decode as its line type, or its hash does not recompute.
    Invalid,
}

/// Most trailing lines a recovery cuts for failing [`LineCheck`]. Past it
/// the failure is systematic (a schema or key problem), not a forged tail.
const MAX_TAIL_REJECTS: usize = 16;

/// `entry_hash` shape this writer produces: 64 lowercase hex characters.
fn is_chain_hash(h: &str) -> bool {
    h.len() == 64
        && h.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// Typed check of an active-file line (data line or terminator), with the
/// same rule as [`verify_one_file`] (external audit EVD-007/EVD-008: the
/// pre-image its version names, and for v3 its canonical bytes).
fn check_active_line<P: Serialize + DeserializeOwned + ChainPayload>(
    line: &[u8],
    pk: &VerifyingKey,
) -> LineCheck {
    match verify_active_line::<P>(line, pk) {
        Ok((_, ActiveLine::Terminator(rotate))) => LineCheck::Verified {
            terminator_seq: Some(rotate.this_seq),
        },
        Ok((_, ActiveLine::Data)) => LineCheck::Verified {
            terminator_seq: None,
        },
        Err(fault) => fault.check(),
    }
}

/// External audit NN-AUD-112: whether one raw line of an active file or
/// archive is a genuine line of this log (data line or terminator: it
/// decodes, its hash recomputes, its signature verifies, and a v3 line is
/// one of this log, in its canonical bytes). Its link to the line before is
/// the verifier's.
pub fn line_is_genuine<P: Serialize + DeserializeOwned + ChainPayload>(
    line: &[u8],
    pk: &VerifyingKey,
) -> bool {
    matches!(check_active_line::<P>(line, pk), LineCheck::Verified { .. })
}

/// Whether one raw manifest line is a genuine row of the manifest of the
/// log `kind` ([`ChainPayload::KIND`]).
pub fn manifest_line_is_genuine(line: &[u8], kind: &str, pk: &VerifyingKey) -> bool {
    matches!(
        check_manifest_line(line, kind, pk),
        LineCheck::Verified { .. }
    )
}

/// Bytes read from the end of a manifest by [`manifest_tail_events`].
const MANIFEST_TAIL_WINDOW: u64 = 256 * 1024;

/// External audit NN-AUD-109: the genuine events in the last
/// [`MANIFEST_TAIL_WINDOW`] bytes of the manifest of `active`, the log
/// `kind` ([`ChainPayload::KIND`]), newest first. Lines that do not verify
/// are left out.
pub fn manifest_tail_events<H: ChainHost>(
    active: &Path,
    kind: &str,
    pk: &VerifyingKey,
) -> Vec<ManifestEvent> {
    let path = manifest_path_for(active);
    let mut f = match H::open_read_nofollow(&path) {
        Ok(f) => f,
        Err(_) => return Vec::new(),
    };
    let Ok(size) = f.metadata().map(|m| m.len()) else {
        return Vec::new();
    };
    let start = size.saturating_sub(MANIFEST_TAIL_WINDOW);
    let mut buf = Vec::new();
    if f.seek(SeekFrom::Start(start)).is_err() || f.read_to_end(&mut buf).is_err() {
        return Vec::new();
    }
    let mut lines: Vec<&[u8]> = buf.split(|&c| c == b'\n').collect();
    // The piece after the last newline is a fragment (or empty); the first
    // piece is cut by the window unless it starts the file.
    lines.pop();
    if start > 0 && !lines.is_empty() {
        lines.remove(0);
    }
    lines
        .into_iter()
        .rev()
        .filter(|l| !l.is_empty())
        .filter_map(|l| {
            verify_manifest_line(l, kind, pk)
                .ok()
                .map(|(_, m)| m.manifest.event)
        })
        .collect()
}

/// External audit NN-AUD-109: why the active file of `active` counts as
/// deleted — it is absent while the newest archive's `Rotated` row is in
/// the manifest (`tail`, from [`manifest_tail_events`]). The rotation
/// creates the fresh active file before it writes that row, so only a
/// crash between the rename and the create leaves no active file and no
/// row; that state is not reported.
pub fn active_missing(active: &Path, tail: &[ManifestEvent]) -> Option<String> {
    if fs::symlink_metadata(active).is_ok() {
        return None;
    }
    let newest = scan_max_archive_seq(active).ok().flatten()?;
    tail.iter()
        .any(|e| matches!(e, ManifestEvent::Rotated { seq, .. } if *seq == newest))
        .then(|| {
            format!(
                "the active file is gone while archive {newest} was sealed and recorded: it was \
                 deleted after the rotation"
            )
        })
}

/// Typed check of a manifest line of the log `kind`.
fn check_manifest_line(line: &[u8], kind: &str, pk: &VerifyingKey) -> LineCheck {
    match verify_manifest_line(line, kind, pk) {
        Ok(_) => LineCheck::Verified {
            terminator_seq: None,
        },
        Err(fault) => fault.check(),
    }
}

/// Find the last complete, chain-shaped line in `buf` (= file bytes
/// `[buf_start, file_size)`), scanning newest→oldest. `at_bof` means
/// `buf_start == 0`, so the buffer's first segment is a genuine line start
/// rather than a window-split fragment. Returns `None` if no acceptable
/// line is fully contained in `buf` (caller widens the window).
///
/// External audit NN-AUD-110 — what is adopted:
/// - a line without a 64-hex `entry_hash` is skipped like a torn one;
/// - a line that fails `check` ([`LineCheck::Invalid`]) is skipped too, so
///   it is truncated and attested — but at most [`MAX_TAIL_REJECTS`] of
///   them, and never all the chain-shaped lines of a file: past either
///   bound the newest chain-shaped line is kept, marked `unverified`;
/// - a line whose only fault is its signature is kept, marked
///   `unverified` (a regenerated key must not cut a line at every boot);
/// - `sealed_seq` is set only for a terminator that fully verifies.
fn scan_back_for_tail(
    buf: &[u8],
    buf_start: u64,
    at_bof: bool,
    file_size: u64,
    check: &dyn Fn(&[u8]) -> LineCheck,
) -> Option<TailRecovery> {
    let nls: Vec<usize> = buf
        .iter()
        .enumerate()
        .filter_map(|(i, &c)| (c == b'\n').then_some(i))
        .collect();
    let adopt = |nl: usize, h: &str, sealed_seq: Option<u64>, unverified: Option<String>| {
        let clean_len = buf_start + nl as u64 + 1; // include the '\n'
        let torn = clean_len < file_size;
        let dropped = &buf[(nl + 1)..]; // bytes past the adopted line
        TailRecovery {
            tail_hash: h.to_string(),
            clean_len,
            sealed_seq,
            unverified,
            torn,
            dropped_bytes: dropped.len() as u64,
            dropped_sha256: if torn {
                sha256_hex(dropped)
            } else {
                String::new()
            },
        }
    };
    // Newest chain-shaped line that failed `check`: kept as an unverified
    // tail if the walk hits one of the bounds above.
    let mut newest_rejected: Option<(usize, String)> = None;
    let mut rejects = 0usize;
    // Bytes after the final '\n' are an un-terminated trailing fragment;
    // they are never a candidate (no terminating newline). Walk the
    // newline-terminated lines from the end.
    for k in (0..nls.len()).rev() {
        let nl = nls[k];
        let line_start = if k == 0 {
            // The first newline's line begins at BOF only when the window
            // starts at BOF; otherwise its head is outside the window and
            // this (and every older) line is not fully contained → widen.
            if at_bof {
                0
            } else {
                return None;
            }
        } else {
            nls[k - 1] + 1
        };
        let line = &buf[line_start..nl];
        if line.is_empty() {
            continue;
        }
        // Every line type (data / terminator / manifest) carries a
        // top-level `entry_hash`; anything else is torn/corrupt/foreign.
        let Ok(v) = serde_json::from_slice::<serde_json::Value>(line) else {
            continue;
        };
        let Some(h) = v.get("entry_hash").and_then(|h| h.as_str()) else {
            continue;
        };
        if !is_chain_hash(h) {
            continue;
        }
        match check(line) {
            LineCheck::Verified { terminator_seq } => {
                return Some(adopt(nl, h, terminator_seq, None));
            }
            LineCheck::BadSignature => {
                return Some(adopt(
                    nl,
                    h,
                    None,
                    Some("signature does not verify with this agent's key".to_string()),
                ));
            }
            LineCheck::Invalid => {
                if newest_rejected.is_none() {
                    newest_rejected = Some((nl, h.to_string()));
                }
                rejects += 1;
                if rejects > MAX_TAIL_REJECTS {
                    break;
                }
            }
        }
    }
    // Reached BOF (or the reject bound) without a verified line: keep the
    // newest chain-shaped line rather than cut a whole run of them.
    let (nl, h) = newest_rejected?;
    Some(adopt(
        nl,
        &h,
        None,
        Some(format!(
            "{rejects} trailing line(s) fail hash verification; none cut"
        )),
    ))
}

/// Truncate `path` to `len` bytes (+ fsync) to drop a torn trailing fragment
/// recovered by [`recover_tail`]. Truncating the agent's own (LSM-protected)
/// log is safe: the agent is caller-exempt from its own `inode_setattr` deny
/// hook (PHASE_D_002 — `agent-ebpf/src/inode_protect.rs`), and `set_len`
/// touches no directory entry, so no `+i` dance is required.
fn truncate_file(path: &Path, len: u64) -> Result<()> {
    let f = OpenOptions::new()
        .write(true)
        .open(path)
        .with_context(|| format!("opening {} to truncate torn tail", path.display()))?;
    f.set_len(len)
        .with_context(|| format!("truncating {} to {len} bytes", path.display()))?;
    f.sync_all()
        .with_context(|| format!("fsync after truncating {}", path.display()))?;
    Ok(())
}

/// If `line` is a terminator, return its `entry_hash`.
/// Fuzzing entry (see `crate::fuzz_api`).
#[doc(hidden)]
pub fn fuzz_terminator_entry_hash(line: &str) -> Option<String> {
    terminator_entry_hash(line)
}

fn terminator_entry_hash(line: &str) -> Option<String> {
    let v: serde_json::Value = serde_json::from_str(line).ok()?;
    if v.get("rotate").is_some() {
        v.get("entry_hash")
            .and_then(|h| h.as_str())
            .map(str::to_string)
    } else {
        None
    }
}

/// Read the terminator `entry_hash` from the last line of a sealed
/// archive file.
fn read_terminator_hash(path: &Path) -> Result<String> {
    let f = OpenOptions::new()
        .read(true)
        .open(path)
        .with_context(|| format!("opening archive {}", path.display()))?;
    let mut last_term: Option<String> = None;
    for line in BufReader::new(f).lines() {
        let line = line.with_context(|| format!("reading {}", path.display()))?;
        if let Some(h) = terminator_entry_hash(&line) {
            last_term = Some(h);
        }
    }
    last_term.ok_or_else(|| anyhow!("archive {} has no terminator", path.display()))
}

/// The terminator hash of archive `seq` (used to root a fresh
/// post-rotation active file's first line in the meta-chain).
fn prior_terminator_hash(active: &Path, seq: u64) -> Result<String> {
    read_terminator_hash(&archive_path(active, seq))
}

// ── multi-file verifier ─────────────────────────────────────────────

/// Outcome of [`verify_log_set`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogSetReport {
    /// Lowest archive seq still on disk. `> 0` means seqs `0..earliest`
    /// were retention-evicted (corroborated by the manifest), NOT lost.
    pub earliest_retained_seq: u64,
    /// Number of sealed archives verified.
    pub archives_verified: usize,
    /// Records across all verified files (data lines, excl. terminators).
    pub total_records: u64,
    /// External audit NN-AUD-109: manifest checkpoints found reachable.
    pub checkpoints_verified: usize,
    /// External audit EVD-008 (lab PR 204): lines in the format from before
    /// v3 (data lines, terminators and manifest rows), verified with the
    /// untagged pre-image they were signed with. Every line after them is v3.
    pub legacy_lines: u64,
    /// External audit EVD-007 (lab PR 204): of those, the lines whose bytes
    /// are not their canonical serialisation (a key the type does not have,
    /// another key order or spelling): they verify as they always did, but
    /// the signature does not cover those bytes.
    pub non_canonical_legacy: u64,
}

/// Why a chainlog set failed verification.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum LogSetError {
    #[error("file {file}: entry {idx}: prev_hash {got} != expected {expected}")]
    PrevHashMismatch {
        file: String,
        idx: usize,
        got: String,
        expected: String,
    },
    #[error(
        "file {file}: entry {idx}: entry_hash mismatch (recomputed {recomputed}, stored {stored})"
    )]
    EntryHashMismatch {
        file: String,
        idx: usize,
        recomputed: String,
        stored: String,
    },
    /// The hash is checked first: a line that fails here is as it was
    /// written, and another key than this agent's signed it — or it was
    /// forged (lab PR 256: the class named).
    #[error(
        "file {file}: entry {idx}: signature invalid (its entry_hash recomputes: the line is as \
         it was written, but this agent's key did not sign it — another key did, or it was \
         forged)"
    )]
    SignatureInvalid { file: String, idx: usize },
    /// External audit EVD-007 (NN-AUD-273, lab PR 204): a v3 line whose hash
    /// and signature verify, but whose bytes are not the serialisation of
    /// what they decode to — a key added, keys reordered, a value spelled
    /// another way. The signature covers the decoded line, not those bytes.
    #[error(
        "file {file}: entry {idx}: a v3 line not in its canonical form (the bytes on disk are \
         not what the agent wrote: a key added, reordered or re-spelled)"
    )]
    NonCanonicalLine { file: String, idx: usize },
    /// External audit EVD-008 (NN-AUD-274, lab PR 204): a line in the format
    /// from before v3 after a v3 line of the same set or manifest. The
    /// agent writes only v3; the untagged pre-image is accepted only for
    /// the lines written before the upgrade.
    #[error(
        "file {file}: entry {idx}: a line in the old format (v1/v2, untagged pre-image) after \
         v3 lines"
    )]
    LegacyAfterV3 { file: String, idx: usize },
    #[error("archive sequence gap: expected seq {expected}, found {found}")]
    SequenceGap { expected: u64, found: u64 },
    #[error("archive {seq}: terminator this_seq {got} != {seq}")]
    TerminatorSeqMismatch { seq: u64, got: u64 },
    #[error("evicted prefix seq {seq} not corroborated by the manifest")]
    UncorroboratedEviction { seq: u64 },
    #[error("file {file}: malformed line {idx}: {reason}")]
    Malformed {
        file: String,
        idx: usize,
        reason: String,
    },
    /// External audit NN-AUD-109: the active file is gone after a completed
    /// rotation (see [`active_missing`]).
    #[error("active file {file} is missing: {reason}")]
    ActiveMissing { file: String, reason: String },
    /// External audit EVD-017 (NN-AUD-280, lab PR 190): a sealed archive
    /// without its terminator line — empty, or cut before its last line.
    /// The verifier hit an `expect` here and `nn-admin chain verify`
    /// aborted before it reported any chain.
    #[error(
        "archive {seq} ({file}) has no terminator: it is empty or was cut before its last line"
    )]
    ArchiveWithoutTerminator { file: String, seq: u64 },
    /// External audit NN-AUD-109: a manifest checkpoint names a line that
    /// is no longer there — the file was deleted, emptied, cut or
    /// rewritten below it.
    #[error(
        "file {file}: the manifest checkpoint of generation {seq} (line ending at byte {bytes}, \
         entry_hash {tail_hash}) is unreachable: {reason}"
    )]
    CheckpointUnreachable {
        file: String,
        seq: u64,
        bytes: u64,
        tail_hash: String,
        reason: String,
    },
}

/// What a full read of the manifest yields for [`verify_log_set`].
#[derive(Default)]
struct ManifestFacts {
    /// `Evicted` seq → attested terminator hash.
    evicted: std::collections::BTreeMap<u64, String>,
    /// Seqs with a `Rotated` row.
    rotated: std::collections::BTreeSet<u64>,
    /// `ActiveCheckpoint` rows: (generation, bytes, tail_hash).
    checkpoints: Vec<(u64, u64, String)>,
    /// Manifest rows in the format from before v3, and those of them not in
    /// canonical form (see [`LogSetReport`]).
    legacy_lines: u64,
    non_canonical_legacy: u64,
}

/// Verify the entire rotation set for `active_path` end-to-end against
/// `pubkey`: every sealed archive in seq order, then the active file,
/// carrying `expected_prev` across terminator boundaries (GENESIS only
/// for seq 0). A retention-evicted prefix is accepted **only** if the
/// signed manifest carries an `Evicted` row for each missing seq.
///
/// External audit NN-AUD-109: the suffix is bounded too. The manifest is
/// verified whole; every [`ManifestEvent::ActiveCheckpoint`] must name a
/// line still there (by end offset and hash) in the archive or active file
/// of its generation, and the active file may be absent only when the
/// newest archive has no `Rotated` row yet (the crash window between the
/// rename and the create).
///
/// External audit EVD-007/EVD-008 (lab PR 204): every line is checked with
/// the pre-image its version names ([`CHAINLOG_FMT_V3`] for new lines, the
/// untagged one for v1/v2 lines) and, for v3, its canonical bytes; no line in
/// the old format may follow a v3 line of the set (data lines and
/// terminators) or of the manifest.
pub fn verify_log_set<P: Serialize + DeserializeOwned + ChainPayload>(
    active_path: &Path,
    pubkey: &VerifyingKey,
) -> Result<LogSetReport, LogSetError> {
    let seqs = list_archive_seqs(active_path).map_err(|e| LogSetError::Malformed {
        file: active_path.display().to_string(),
        idx: 0,
        reason: e.to_string(),
    })?;
    let earliest_retained_seq = seqs.first().copied().unwrap_or(0);

    // Archive seqs start at 1 (the first sealed file, ex-active, which is
    // the ONLY genesis-rooted file). `earliest <= 1` ⇒ nothing was evicted
    // ⇒ the set roots at GENESIS. `earliest > 1` ⇒ seqs `1..earliest` were
    // retention-evicted; the SIGNED manifest (whose own chain + signatures
    // are verified inside `verify_manifest`) must attest each
    // dropped seq, and the earliest retained archive is rooted on the
    // manifest's attested terminator hash of its now-absent predecessor —
    // NOT on the file's own claimed prev_hash (which would make the
    // first-line boundary check a tautology and let a forged predecessor
    // link slide through).
    let mut expected_prev = GENESIS_PREV_HASH.to_string();
    // External audit NN-AUD-109: the manifest is read whole every time —
    // its checkpoints and `Rotated` rows bound the suffix of the set.
    let facts = verify_manifest(active_path, P::KIND, pubkey)?;
    let evicted = &facts.evicted;
    if earliest_retained_seq > 1 {
        // External audit EVD-022 (lab PR 190): the first seq below the
        // earliest archive without an `Evicted` row, found over the
        // manifest's rows — not by counting up to a seq an archive name may
        // put at 10^18.
        let mut next = 1u64;
        for &seq in evicted.range(1..earliest_retained_seq).map(|(s, _)| s) {
            if seq != next {
                break;
            }
            next += 1;
        }
        if next < earliest_retained_seq {
            return Err(LogSetError::UncorroboratedEviction { seq: next });
        }
        expected_prev = evicted.get(&(earliest_retained_seq - 1)).cloned().ok_or(
            LogSetError::UncorroboratedEviction {
                seq: earliest_retained_seq - 1,
            },
        )?;
    }

    let mut total_records = 0u64;
    let mut legacy_lines = facts.legacy_lines;
    let mut non_canonical_legacy = facts.non_canonical_legacy;
    // External audit EVD-008: one format history for the whole set.
    let mut seen_v3 = false;
    let active_gen = seqs.last().map_or(1, |m| m + 1);
    let mut checkpoints_verified = 0usize;
    // Checkpoints of generations past the active one: newer archives gone.
    if let Some((seq, bytes, tail_hash)) =
        facts.checkpoints.iter().find(|(g, _, _)| *g > active_gen)
    {
        return Err(LogSetError::CheckpointUnreachable {
            file: active_path.display().to_string(),
            seq: *seq,
            bytes: *bytes,
            tail_hash: tail_hash.clone(),
            reason: format!(
                "generation {seq} is past the active file's ({active_gen}): the newest archives \
                 were removed"
            ),
        });
    }
    let checkpoints_of = |g: u64| -> Vec<(u64, String)> {
        facts
            .checkpoints
            .iter()
            .filter(|(cg, _, _)| *cg == g)
            .map(|(_, b, h)| (*b, h.clone()))
            .collect()
    };

    // Sealed archives, ascending, contiguous.
    let mut prev_seq: Option<u64> = None;
    for &seq in &seqs {
        if let Some(p) = prev_seq {
            if seq != p + 1 {
                return Err(LogSetError::SequenceGap {
                    expected: p + 1,
                    found: seq,
                });
            }
        }
        let path = archive_path(active_path, seq);
        let wanted = checkpoints_of(seq);
        let walk = verify_one_file::<P>(
            &path,
            &expected_prev,
            pubkey,
            Some(seq),
            &wanted,
            &mut seen_v3,
        )?;
        total_records += walk.records;
        legacy_lines += walk.legacy_lines;
        non_canonical_legacy += walk.non_canonical_legacy;
        checkpoints_verified += reach_checkpoints(&path, seq, &wanted, &walk)?;
        expected_prev = walk
            .terminator
            .ok_or_else(|| LogSetError::ArchiveWithoutTerminator {
                file: path.display().to_string(),
                seq,
            })?;
        prev_seq = Some(seq);
    }

    // Active file (no terminator). External audit NN-AUD-109: missing is an
    // empty chain only when nothing says it existed.
    if fs::symlink_metadata(active_path).is_err() {
        let rotated_newest = seqs.last().is_some_and(|m| facts.rotated.contains(m));
        if rotated_newest {
            return Err(LogSetError::ActiveMissing {
                file: active_path.display().to_string(),
                reason: format!(
                    "archive {} was sealed and recorded, so its successor was created",
                    seqs.last().copied().unwrap_or_default()
                ),
            });
        }
    }
    let wanted = checkpoints_of(active_gen);
    let walk = verify_one_file::<P>(
        active_path,
        &expected_prev,
        pubkey,
        None,
        &wanted,
        &mut seen_v3,
    )?;
    total_records += walk.records;
    legacy_lines += walk.legacy_lines;
    non_canonical_legacy += walk.non_canonical_legacy;
    checkpoints_verified += reach_checkpoints(active_path, active_gen, &wanted, &walk)?;

    Ok(LogSetReport {
        earliest_retained_seq,
        archives_verified: seqs.len(),
        total_records,
        checkpoints_verified,
        legacy_lines,
        non_canonical_legacy,
    })
}

/// What [`verify_recent`] checked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecentReport {
    /// Lines verified (data lines and a terminator).
    pub lines: u64,
    /// Bytes of the active file covered.
    pub bytes: u64,
    /// The window covered the whole active file (its first line's link to
    /// the previous file was checked too, when that file is still there).
    pub whole_file: bool,
}

/// Where a line of an active file is (lab PR 256): the offset of its first
/// byte in the file, its line number (from 1) when the check read the file
/// from its start, and its `ts` when that is a plain timestamp. The window
/// of [`verify_recent`] starts inside a file longer than it, where the
/// index of a line in the window (`entry 0`) was not its place in the file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinePos {
    pub offset: u64,
    pub line: Option<u64>,
    pub ts: Option<String>,
}

impl std::fmt::Display for LinePos {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match (self.line, &self.ts) {
            (Some(n), Some(ts)) => write!(f, "line {n} (byte {}, ts {ts})", self.offset),
            (Some(n), None) => write!(f, "line {n} (byte {})", self.offset),
            (None, Some(ts)) => write!(f, "the line at byte {} (ts {ts})", self.offset),
            (None, None) => write!(f, "the line at byte {}", self.offset),
        }
    }
}

/// The `ts` of a line that failed verification, when it is a plain
/// timestamp (`2026-10-20T08:35:00.123456Z`: digits, `-:.+TZ`, at most 40
/// bytes). Nothing else of such a line goes into the journal or the signed
/// finding.
fn plain_ts(line: &serde_json::Value) -> Option<String> {
    let ts = line.get("ts")?.as_str()?;
    let plain = !ts.is_empty()
        && ts.len() <= 40
        && ts
            .bytes()
            .all(|b| b.is_ascii_digit() || b"-:.+TZ".contains(&b));
    plain.then(|| ts.to_string())
}

/// How a line breaks the chain ([`RecentError::Broken`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LineBreak {
    /// Its `entry_hash` does not recompute: its content changed after it
    /// was written.
    ContentAltered { recomputed: String, stored: String },
    /// Its `prev_hash` is not the `entry_hash` of the line before it: a line
    /// was removed, inserted or moved.
    LinkBroken { got: String, expected: String },
    /// Not a line of this log: not JSON, not its line type, a format this
    /// reader does not know, a signature that is not 64 bytes of base64.
    Malformed { reason: String },
    /// External audit EVD-007: a v3 line whose bytes are not its canonical
    /// serialisation.
    NotCanonical,
    /// External audit EVD-008: a line in the old format after a v3 line.
    LegacyAfterV3,
}

impl std::fmt::Display for LineBreak {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LineBreak::ContentAltered { recomputed, stored } => write!(
                f,
                "its entry_hash does not recompute (recomputed {recomputed}, stored {stored}): \
                 the line was altered after it was written"
            ),
            LineBreak::LinkBroken { got, expected } => write!(
                f,
                "its prev_hash {got} is not the entry_hash {expected} of the line before it: a \
                 line was removed, inserted or moved"
            ),
            LineBreak::Malformed { reason } => write!(f, "a malformed line ({reason})"),
            LineBreak::NotCanonical => write!(
                f,
                "a v3 line not in its canonical form (the bytes on disk are not what the agent \
                 wrote: a key added, reordered or re-spelled)"
            ),
            LineBreak::LegacyAfterV3 => write!(
                f,
                "a line in the old format (v1/v2, untagged pre-image) after v3 lines"
            ),
        }
    }
}

/// Lines of a window another key signed ([`RecentError::SignedByAnotherKey`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForeignLines {
    pub file: String,
    /// Those lines.
    pub count: u64,
    /// The lines of the window, those included.
    pub checked: u64,
    pub first: LinePos,
    pub last: LinePos,
    /// The first 8 hex digits of the agent's public key (`agent.sig.pub`).
    pub key: String,
}

/// The first line that breaks the chain otherwise ([`RecentError::Broken`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BrokenLine {
    pub file: String,
    pub pos: LinePos,
    pub line_break: LineBreak,
    /// Lines before it another key signed ([`RecentError::SignedByAnotherKey`]).
    pub signed_by_another_key_before: u64,
}

/// Why the bounded boot check of a rotating log failed ([`verify_recent`],
/// lab PR 256): the class, and where. Every one is a `chain_verify_failed`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecentError {
    /// Lines of the window whose `entry_hash` recomputes and whose link to
    /// the line before them is intact, but whose signature does not verify
    /// with the agent's key: written under another key (a regenerated
    /// agent key, another agent or a test run writing the file) or forged.
    /// Counted over the whole window, the first and the last named.
    SignedByAnotherKey(Box<ForeignLines>),
    /// The first line that breaks the chain otherwise; the check stops
    /// there, as before.
    Broken(Box<BrokenLine>),
    /// The file could not be read.
    Unreadable { file: String, reason: String },
}

impl RecentError {
    /// The class, for the signed `chain_verify` entry.
    pub fn class(&self) -> &'static str {
        match self {
            RecentError::SignedByAnotherKey(_) => "signed_by_another_key",
            RecentError::Broken(b) => match b.line_break {
                LineBreak::ContentAltered { .. } => "content_altered",
                LineBreak::LinkBroken { .. } => "link_broken",
                LineBreak::Malformed { .. } => "malformed",
                LineBreak::NotCanonical => "not_canonical",
                LineBreak::LegacyAfterV3 => "legacy_after_v3",
            },
            RecentError::Unreadable { .. } => "unreadable",
        }
    }
}

impl std::fmt::Display for RecentError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RecentError::SignedByAnotherKey(l) => {
                let ForeignLines {
                    file,
                    count,
                    checked,
                    first,
                    last,
                    key,
                } = l.as_ref();
                if *count == 1 {
                    write!(
                        f,
                        "file {file}: 1 of the {checked} lines checked is signed by another \
                         key, {first}: its entry_hash recomputes and its link to the line before \
                         it is intact, but its signature does not verify with this agent's key \
                         (agent.sig.pub {key}…)"
                    )?;
                } else {
                    write!(
                        f,
                        "file {file}: {count} of the {checked} lines checked are signed by \
                         another key, from {first} to {last}: each one's entry_hash recomputes \
                         and its link to the line before it is intact, but its signature does \
                         not verify with this agent's key (agent.sig.pub {key}…)"
                    )?;
                }
                write!(
                    f,
                    " — written under another key (a regenerated agent key, another agent or a \
                     test run writing this file), or forged"
                )
            }
            RecentError::Broken(b) => {
                let BrokenLine {
                    file,
                    pos,
                    line_break,
                    signed_by_another_key_before,
                } = b.as_ref();
                write!(f, "file {file}: {pos}: {line_break}")?;
                match signed_by_another_key_before {
                    0 => Ok(()),
                    1 => write!(
                        f,
                        "; before it, 1 line of the window signed by another key (its hash \
                         and link intact)"
                    ),
                    n => write!(
                        f,
                        "; before it, {n} lines of the window signed by another key (their \
                         hash and link intact)"
                    ),
                }
            }
            RecentError::Unreadable { file, reason } => {
                write!(f, "file {file}: cannot be read: {reason}")
            }
        }
    }
}

impl std::error::Error for RecentError {}

/// External audit NN-AUD-112: the bounded check the agent runs on each
/// rotating log after it starts — every line in the last `max_bytes` of
/// the active file must verify (hash and signature) and link to the line
/// before it. The full check of the set is [`verify_log_set`]
/// (`nn-admin chain verify`).
///
/// Lab PR 256: a failure says its class and where it is
/// ([`RecentError`]). A line whose hash recomputes and whose link holds
/// but whose signature does not verify with this key is counted, and the
/// check goes on to the end of the window: the report names how many of
/// the lines checked another key signed, the first and the last (lot 255:
/// an e2e fixture's agent had appended its rows, under its own key, to the
/// installed agent's log). Any other break stops the check at the first, as
/// before. Lines are placed by byte offset in the file, and by line number
/// when the window starts at the top of the file.
pub fn verify_recent<P: Serialize + DeserializeOwned + ChainPayload, H: ChainHost>(
    active: &Path,
    pubkey: &VerifyingKey,
    max_bytes: u64,
) -> Result<RecentReport, RecentError> {
    let file = active.display().to_string();
    let unreadable = |reason: String| RecentError::Unreadable {
        file: file.clone(),
        reason,
    };
    let generation = current_generation(active);
    let mut f = match H::open_read_nofollow(active) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Ok(RecentReport {
                lines: 0,
                bytes: 0,
                whole_file: true,
            })
        }
        Err(e) => return Err(unreadable(e.to_string())),
    };
    let len = f.metadata().map_err(|e| unreadable(e.to_string()))?.len();
    let start = len.saturating_sub(max_bytes);
    let mut buf = Vec::new();
    f.seek(SeekFrom::Start(start))
        .and_then(|_| f.read_to_end(&mut buf))
        .map_err(|e| unreadable(e.to_string()))?;
    let mut body: &[u8] = &buf;
    let mut at = start;
    if start > 0 {
        // The first piece is cut by the window.
        let Some(nl) = body.iter().position(|&c| c == b'\n') else {
            return Ok(RecentReport {
                lines: 0,
                bytes: 0,
                whole_file: false,
            });
        };
        at += nl as u64 + 1;
        body = &body[nl + 1..];
    }
    let covered = len - at;
    // The link of the first line, known only when the window starts the file
    // and no rotation ran while it was read.
    let mut expected: Option<String> = if start == 0 && current_generation(active) == generation {
        if generation == 1 {
            Some(GENESIS_PREV_HASH.to_string())
        } else {
            read_terminator_hash(&archive_path(active, generation - 1)).ok()
        }
    } else {
        None
    };
    // Complete lines only: a last write cut short is the open's to repair.
    let complete = body
        .iter()
        .rposition(|&c| c == b'\n')
        .map_or(&body[..0], |i| &body[..i]);
    let mut lines = 0u64;
    // External audit EVD-008: no old-format line after a v3 one.
    let mut seen_v3 = false;
    // Lab PR 256: the lines another key signed (count, first, last).
    let mut foreign: Option<(u64, LinePos, LinePos)> = None;
    let mut offset = at;
    let broken = |pos: LinePos, line_break: LineBreak, before: u64| {
        RecentError::Broken(Box::new(BrokenLine {
            file: file.clone(),
            pos,
            line_break,
            signed_by_another_key_before: before,
        }))
    };
    for (idx, line) in complete.split(|&c| c == b'\n').enumerate() {
        let line_at = offset;
        offset += line.len() as u64 + 1;
        if line.is_empty() {
            continue;
        }
        let before = foreign.as_ref().map_or(0, |(n, _, _)| *n);
        let pos = |value: Option<&serde_json::Value>| LinePos {
            offset: line_at,
            line: (start == 0).then_some(idx as u64 + 1),
            ts: value.and_then(plain_ts),
        };
        let value: serde_json::Value = match serde_json::from_slice(line) {
            Ok(v) => v,
            Err(e) => {
                return Err(broken(
                    pos(None),
                    LineBreak::Malformed {
                        reason: format!("not JSON: {e}"),
                    },
                    before,
                ))
            }
        };
        let ok = match verify_active_line::<P>(line, pubkey) {
            Ok((ok, _)) => ok,
            Err(LineFault::SigInvalid(ok)) => {
                let here = pos(Some(&value));
                foreign = Some(match foreign.take() {
                    None => (1, here.clone(), here),
                    Some((n, first, _)) => (n + 1, first, here),
                });
                ok
            }
            Err(LineFault::EntryHash { recomputed, stored }) => {
                return Err(broken(
                    pos(Some(&value)),
                    LineBreak::ContentAltered { recomputed, stored },
                    before,
                ))
            }
            Err(LineFault::NonCanonical) => {
                return Err(broken(pos(Some(&value)), LineBreak::NotCanonical, before))
            }
            Err(LineFault::Malformed(reason) | LineFault::SigMalformed(reason)) => {
                return Err(broken(
                    pos(Some(&value)),
                    LineBreak::Malformed { reason },
                    before,
                ))
            }
        };
        match ok.pre_image {
            PreImage::V3 => seen_v3 = true,
            PreImage::Legacy if seen_v3 => {
                return Err(broken(pos(Some(&value)), LineBreak::LegacyAfterV3, before))
            }
            PreImage::Legacy => {}
        }
        if let Some(want) = &expected {
            if &ok.prev_hash != want {
                return Err(broken(
                    pos(Some(&value)),
                    LineBreak::LinkBroken {
                        got: ok.prev_hash,
                        expected: want.clone(),
                    },
                    before,
                ));
            }
        }
        expected = Some(ok.entry_hash);
        lines += 1;
    }
    if let Some((count, first, last)) = foreign {
        return Err(RecentError::SignedByAnotherKey(Box::new(ForeignLines {
            file,
            count,
            checked: lines,
            first,
            last,
            key: hex::encode(&pubkey.to_bytes()[..4]),
        })));
    }
    Ok(RecentReport {
        lines,
        bytes: covered,
        whole_file: start == 0,
    })
}

/// External audit NN-AUD-109: every checkpoint of `generation` must name a
/// line of `file` (by its end offset and hash). Returns how many did.
fn reach_checkpoints(
    file: &Path,
    generation: u64,
    checkpoints: &[(u64, String)],
    walk: &FileWalk,
) -> Result<usize, LogSetError> {
    for (bytes, tail_hash) in checkpoints {
        let reason = match walk.line_ends.get(bytes) {
            Some(h) if h == tail_hash => continue,
            Some(h) => format!("the line ending there is {h}"),
            None if walk.len < *bytes => {
                format!(
                    "the file is {} bytes: it was emptied, deleted or cut",
                    walk.len
                )
            }
            None => "no line ends there: the file was rewritten".to_string(),
        };
        return Err(LogSetError::CheckpointUnreachable {
            file: file.display().to_string(),
            seq: generation,
            bytes: *bytes,
            tail_hash: tail_hash.clone(),
            reason,
        });
    }
    Ok(checkpoints.len())
}

/// What [`verify_one_file`] read.
struct FileWalk {
    /// Terminator `entry_hash` of a sealed archive.
    terminator: Option<String>,
    /// Data lines.
    records: u64,
    /// The `entry_hash` of the line ending (newline included) at each
    /// offset a checkpoint names, when one does. External audit EVD-017
    /// (lab PR 190): only those offsets are kept — every line's was, so the
    /// memory of a verification grew with the file.
    line_ends: std::collections::HashMap<u64, String>,
    /// Bytes read (0 for a missing file).
    len: u64,
    /// External audit EVD-007/EVD-008: lines in the old format, and those of
    /// them not in canonical form.
    legacy_lines: u64,
    non_canonical_legacy: u64,
}

/// Verify one file's chain from `expected_prev`: its terminator hash if
/// sealed, its data record count, and the lines ending where the manifest
/// checkpoints `checkpoints` (end offset, hash) say a line ends.
/// `archive_seq` is `Some` for sealed archives (asserts the terminator's
/// `this_seq`).
///
/// External audit EVD-017 (lab PR 190): one line in memory at a time
/// ([`crate::verify_lines`]): a line over the cap or not UTF-8 is
/// [`LogSetError::Malformed`], never read whole.
fn verify_one_file<P: Serialize + DeserializeOwned + ChainPayload>(
    path: &Path,
    expected_prev: &str,
    pubkey: &VerifyingKey,
    archive_seq: Option<u64>,
    checkpoints: &[(u64, String)],
    seen_v3: &mut bool,
) -> Result<FileWalk, LogSetError> {
    let file = path.display().to_string();
    let f = match OpenOptions::new().read(true).open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound && archive_seq.is_none() => {
            // A never-created active file (fresh seq-0 deploy, or the crash
            // window between rename and create) is an empty chain; the
            // caller has already ruled out a deleted one.
            return Ok(FileWalk {
                terminator: None,
                records: 0,
                line_ends: std::collections::HashMap::new(),
                len: 0,
                legacy_lines: 0,
                non_canonical_legacy: 0,
            });
        }
        Err(e) => {
            return Err(LogSetError::Malformed {
                file,
                idx: 0,
                reason: e.to_string(),
            })
        }
    };

    let wanted: std::collections::HashSet<u64> = checkpoints.iter().map(|(b, _)| *b).collect();
    let mut expected = expected_prev.to_string();
    let mut records = 0u64;
    let mut term_hash = None;
    let mut line_ends = std::collections::HashMap::new();
    let mut legacy_lines = 0u64;
    let mut non_canonical_legacy = 0u64;
    let mut reader = crate::verify_lines::VerifyLines::new(BufReader::new(f));
    let mut lines_read = 0usize;
    loop {
        let read = reader.next_line().map_err(|e| LogSetError::Malformed {
            file: file.clone(),
            idx: lines_read,
            reason: e.to_string(),
        })?;
        let Some(raw) = read else {
            break;
        };
        // 0-based line index, empty lines counted (as before).
        let idx = lines_read;
        lines_read += 1;
        let (end, newline) = (raw.end, raw.newline);
        let line = match raw.text() {
            Ok(l) => l.to_string(),
            Err(reason) => return Err(LogSetError::Malformed { file, idx, reason }),
        };
        if line.is_empty() {
            continue;
        }
        let (ok, kind) =
            verify_active_line::<P>(line.as_bytes(), pubkey).map_err(|f| f.at(&file, idx))?;
        // An archive's terminator must name the archive.
        if let (Some(seq), ActiveLine::Terminator(rotate)) = (archive_seq, &kind) {
            if rotate.this_seq != seq {
                return Err(LogSetError::TerminatorSeqMismatch {
                    seq,
                    got: rotate.this_seq,
                });
            }
        }
        track_format(&ok, seen_v3, &file, idx)?;
        if ok.pre_image == PreImage::Legacy {
            legacy_lines += 1;
            non_canonical_legacy += u64::from(ok.non_canonical_legacy);
        }
        match kind {
            ActiveLine::Terminator(_) => term_hash = Some(ok.entry_hash.clone()),
            ActiveLine::Data => records += 1,
        }
        if ok.prev_hash != expected {
            return Err(LogSetError::PrevHashMismatch {
                file,
                idx,
                got: ok.prev_hash,
                expected,
            });
        }
        if newline && wanted.contains(&end) {
            line_ends.insert(end, ok.entry_hash.clone());
        }
        expected = ok.entry_hash;
    }
    Ok(FileWalk {
        terminator: term_hash,
        records,
        line_ends,
        len: reader.offset(),
        legacy_lines,
        non_canonical_legacy,
    })
}

/// First line's `prev_hash` of a file. Test-only: the verifier roots the
/// earliest retained archive on the manifest's attested terminator hash
/// (not the file's own claim), so this helper is used only to assert the
/// meta-chain boundary link in tests.
#[cfg(test)]
fn first_line_prev_hash(path: &Path) -> Result<String> {
    let f = OpenOptions::new().read(true).open(path)?;
    for line in BufReader::new(f).lines() {
        let line = line?;
        if line.is_empty() {
            continue;
        }
        let v: serde_json::Value = serde_json::from_str(&line)?;
        return v
            .get("prev_hash")
            .and_then(|h| h.as_str())
            .map(str::to_string)
            .ok_or_else(|| anyhow!("first line missing prev_hash"));
    }
    Err(anyhow!("{} is empty", path.display()))
}

/// Verify the manifest's OWN chain + signatures (so a tampered or forged
/// manifest can't fabricate eviction records), and return a map of each
/// `Evicted` seq → its attested terminator hash. The evicted-prefix
/// branch of [`verify_log_set`] roots the earliest retained archive on
/// these attested hashes, so this verification is load-bearing, not
/// informational.
fn verify_manifest(
    active_path: &Path,
    kind: &str,
    pubkey: &VerifyingKey,
) -> Result<ManifestFacts, LogSetError> {
    let path = manifest_path_for(active_path);
    let file = path.display().to_string();
    let mut facts = ManifestFacts::default();
    let f = match OpenOptions::new().read(true).open(&path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(facts),
        Err(e) => {
            return Err(LogSetError::Malformed {
                file,
                idx: 0,
                reason: e.to_string(),
            })
        }
    };
    let mut expected = GENESIS_PREV_HASH.to_string();
    // External audit EVD-008: the manifest's own format history.
    let mut seen_v3 = false;
    // External audit EVD-017 (lab PR 190): one bounded line at a time.
    let mut reader = crate::verify_lines::VerifyLines::new(BufReader::new(f));
    let mut lines_read = 0usize;
    loop {
        let raw = reader.next_line().map_err(|e| LogSetError::Malformed {
            file: file.clone(),
            idx: lines_read,
            reason: e.to_string(),
        })?;
        let Some(raw) = raw else {
            break;
        };
        let idx = lines_read;
        lines_read += 1;
        let line = raw.text().map_err(|reason| LogSetError::Malformed {
            file: file.clone(),
            idx,
            reason,
        })?;
        if line.is_empty() {
            continue;
        }
        let (ok, entry) =
            verify_manifest_line(line.as_bytes(), kind, pubkey).map_err(|f| f.at(&file, idx))?;
        track_format(&ok, &mut seen_v3, &file, idx)?;
        if ok.pre_image == PreImage::Legacy {
            facts.legacy_lines += 1;
            facts.non_canonical_legacy += u64::from(ok.non_canonical_legacy);
        }
        if ok.prev_hash != expected {
            return Err(LogSetError::PrevHashMismatch {
                file,
                idx,
                got: ok.prev_hash,
                expected,
            });
        }
        expected = ok.entry_hash;
        match entry.manifest.event {
            ManifestEvent::Evicted {
                seq,
                terminator_hash,
            } => {
                facts.evicted.insert(seq, terminator_hash);
            }
            ManifestEvent::Rotated { seq, .. } => {
                facts.rotated.insert(seq);
            }
            ManifestEvent::ActiveCheckpoint {
                seq,
                bytes,
                tail_hash,
            } => facts.checkpoints.push((seq, bytes, tail_hash)),
            _ => {}
        }
    }
    Ok(facts)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain_host::testing::{PortableHost, TestKey};
    use tempfile::TempDir;

    #[test]
    fn cap_from_env_clamps_below_floor_and_keeps_bad_values_at_default() {
        let d = 16 * 1024 * 1024;
        assert_eq!(cap_from_value("X", None, d), d);
        assert_eq!(cap_from_value("X", Some("1"), d), MIN_ENV_CAP_BYTES);
        assert_eq!(cap_from_value("X", Some("16384"), d), MIN_ENV_CAP_BYTES);
        assert_eq!(cap_from_value("X", Some("1MiB"), d), d);
        assert_eq!(cap_from_value("X", Some(""), d), d);
        assert_eq!(cap_from_value("X", Some(" 2097152 "), d), 2 * 1024 * 1024);
        assert_eq!(cap_from_value("X", Some("67108864"), d), 64 * 1024 * 1024);
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    struct TestPayload {
        ts: String,
        seq: u64,
        data: String,
    }

    impl ChainPayload for TestPayload {
        const KIND: &'static str = "test_payload";
    }

    fn key() -> TestKey {
        // Deterministic-enough for tests: bootstrap a fresh key in a tmp.
        let dir = TempDir::new().unwrap();
        TestKey::load_or_bootstrap(&dir.path().join("k")).unwrap()
    }

    fn cfg(cap: u64, archives: usize) -> RotationConfig {
        RotationConfig {
            size_cap_bytes: cap,
            max_archives: archives,
            file_mode: 0o600,
        }
    }

    fn payload(i: u64) -> TestPayload {
        TestPayload {
            ts: format!("2026-05-30T00:00:{i:02}.000000Z"),
            seq: i,
            data: format!("record-number-{i}-with-some-bulk-to-grow-the-file"),
        }
    }

    /// External audit NET-019: deferred lines are written but not fsynced
    /// until `sync` (or a durable append, or a rotation's terminator);
    /// the chain verifies across a rotation of deferred lines.
    #[test]
    fn deferred_lines_wait_for_one_sync_and_verify() {
        let dir = tempfile::tempdir().unwrap();
        let active = dir.path().join("log.jsonl");
        let k = key();
        let pk = k.verifying_key();
        let mut log = RotatingChainLog::<TestPayload, _>::open(
            &active,
            k,
            cfg(4096, 64),
            std::sync::Arc::new(NoProtection),
        )
        .unwrap();
        for i in 0..10 {
            log.append_deferred(payload(i)).unwrap();
        }
        assert_eq!(log.fsyncs(), 0);
        assert!(log.has_unsynced());
        assert_eq!(data_lines(&active), 10, "written before the fsync");
        log.sync().unwrap();
        assert_eq!(log.fsyncs(), 1);
        assert!(!log.has_unsynced());
        log.sync().unwrap();
        assert_eq!(log.fsyncs(), 1, "nothing to sync");
        // Past the cap: the terminator's fsync covers the sealed file.
        for i in 10..200 {
            log.append_deferred(payload(i)).unwrap();
        }
        let rotations = list_archive_seqs(&active).unwrap().len() as u64;
        assert!(rotations > 1, "rotated");
        // One fsync per terminator, none per line.
        assert_eq!(log.fsyncs(), 1 + rotations);
        log.sync().unwrap();
        let report = verify_log_set::<TestPayload>(&active, &pk).unwrap();
        assert_eq!(report.total_records, 200);
    }

    /// External audit NN-AUD-292 (FIMP-013): the rotating logs' data lines,
    /// terminators and manifest lines verify strictly with the agent's key
    /// (the full verifier and the line check of a recovery). The same set
    /// with every signature replaced by a small-order one, under a
    /// small-order key, verified with the lax `verify`; it is refused now.
    #[test]
    fn rotating_logs_are_verified_strictly() {
        use crate::chain_anchor::small_order;
        let dir = TempDir::new().unwrap();
        let active = dir.path().join("test.jsonl");
        let k = key();
        let pk = k.verifying_key();
        let mut log = RotatingChainLog::<TestPayload, _>::open(
            &active,
            k,
            cfg(2000, 50),
            std::sync::Arc::new(NoProtection),
        )
        .unwrap();
        for i in 0..40 {
            log.append(payload(i)).unwrap();
        }
        drop(log);
        assert!(!list_archive_seqs(&active).unwrap().is_empty(), "rotated");
        let report = verify_log_set::<TestPayload>(&active, &pk).unwrap();
        assert_eq!(report.total_records, 40);
        let text = std::fs::read_to_string(&active).unwrap();
        let line = text.lines().next().unwrap();
        assert!(line_is_genuine::<TestPayload>(line.as_bytes(), &pk));

        let first: ChainLine<TestPayload> = serde_json::from_str(line).unwrap();
        small_order::assert_premise(&hex::decode(&first.entry_hash).unwrap());
        let forged = small_order::forge(line);
        assert!(!line_is_genuine::<TestPayload>(
            forged.as_bytes(),
            &small_order::key()
        ));
        for entry in std::fs::read_dir(dir.path()).unwrap() {
            let path = entry.unwrap().path();
            let body = std::fs::read_to_string(&path).unwrap();
            std::fs::write(&path, small_order::forge(&body)).unwrap();
        }
        assert!(matches!(
            verify_log_set::<TestPayload>(&active, &small_order::key()),
            Err(LogSetError::SignatureInvalid { .. })
        ));
    }

    /// REAL rotation: a small byte cap makes a handful of appends spill
    /// into archives; the sealed-old file + the new file verify
    /// end-to-end ACROSS the boundary (terminator hash == new file's
    /// first prev_hash, carried by the verifier).
    #[test]
    fn real_rotation_seals_and_meta_chains_across_the_boundary() {
        let dir = TempDir::new().unwrap();
        let active = dir.path().join("test.jsonl");
        let k = key();
        let pk = k.verifying_key();
        let mut log = RotatingChainLog::<TestPayload, _>::open(
            &active,
            k,
            cfg(2000, 50),
            std::sync::Arc::new(NoProtection),
        )
        .unwrap();

        for i in 0..40 {
            log.append(payload(i)).unwrap();
        }

        // Rotation actually happened (real byte threshold, not a mock).
        let seqs = list_archive_seqs(&active).unwrap();
        assert!(
            !seqs.is_empty(),
            "300-byte cap over 40 records must have rotated"
        );
        assert_eq!(seqs, (1..=seqs.len() as u64).collect::<Vec<_>>());

        // The whole set verifies end-to-end across every terminator
        // boundary — this is the meta-chain guarantee.
        let report = verify_log_set::<TestPayload>(&active, &pk).unwrap();
        assert_eq!(report.earliest_retained_seq, 1);
        assert_eq!(report.archives_verified, seqs.len());
        assert_eq!(report.total_records, 40);

        // Concretely assert the boundary link: archive seq-1's terminator
        // hash == the first line prev_hash of seq-2 (or the active file).
        let term1 = read_terminator_hash(&archive_path(&active, 1)).unwrap();
        let next = if seqs.contains(&2) {
            first_line_prev_hash(&archive_path(&active, 2)).unwrap()
        } else {
            first_line_prev_hash(&active).unwrap()
        };
        assert_eq!(term1, next, "meta-chain boundary must link seq1 → seq2");
    }

    /// Retention evicts the oldest archive and the multi-file verifier
    /// accepts the gap as EVICTION (manifest-corroborated), not tamper.
    #[test]
    fn retention_evicts_oldest_and_verifier_reports_eviction_not_tamper() {
        let dir = TempDir::new().unwrap();
        let active = dir.path().join("test.jsonl");
        let k = key();
        let pk = k.verifying_key();
        let mut log = RotatingChainLog::<TestPayload, _>::open(
            &active,
            k,
            cfg(300, 2),
            std::sync::Arc::new(NoProtection),
        )
        .unwrap();

        for i in 0..80 {
            log.append(payload(i)).unwrap();
        }

        let seqs = list_archive_seqs(&active).unwrap();
        assert!(seqs.len() <= 2, "max_archives=2 must cap retained archives");
        let earliest = *seqs.first().unwrap();
        assert!(earliest > 1, "oldest archives must have been evicted");

        // Verifier accepts the evicted prefix (manifest attests it) and
        // reports the earliest retained seq.
        let report = verify_log_set::<TestPayload>(&active, &pk).unwrap();
        assert_eq!(report.earliest_retained_seq, earliest);
        assert_eq!(report.archives_verified, seqs.len());
    }

    /// Tampering an archived data line still breaks verification.
    #[test]
    fn tampered_archive_fails_verification() {
        let dir = TempDir::new().unwrap();
        let active = dir.path().join("test.jsonl");
        let k = key();
        let pk = k.verifying_key();
        let mut log = RotatingChainLog::<TestPayload, _>::open(
            &active,
            k,
            cfg(2000, 50),
            std::sync::Arc::new(NoProtection),
        )
        .unwrap();
        for i in 0..40 {
            log.append(payload(i)).unwrap();
        }
        assert!(verify_log_set::<TestPayload>(&active, &pk).is_ok());

        // Flip one byte of a record's payload in archive seq-1.
        let arch = archive_path(&active, 1);
        let contents = fs::read_to_string(&arch).unwrap();
        let tampered = contents.replacen("record-number-0", "record-number-X", 1);
        assert_ne!(contents, tampered, "test must actually mutate a line");
        fs::write(&arch, tampered).unwrap();

        let err = verify_log_set::<TestPayload>(&active, &pk).unwrap_err();
        assert!(
            matches!(
                err,
                LogSetError::EntryHashMismatch { .. } | LogSetError::PrevHashMismatch { .. }
            ),
            "a tampered archive line must fail verification, got {err:?}"
        );
    }

    /// Deleting a retained archive WITHOUT a manifest eviction record is
    /// caught (sequence gap or uncorroborated eviction) — wholesale file
    /// removal is no longer a clean escape.
    #[test]
    fn deleting_a_retained_archive_is_detected() {
        let dir = TempDir::new().unwrap();
        let active = dir.path().join("test.jsonl");
        let k = key();
        let pk = k.verifying_key();
        let mut log = RotatingChainLog::<TestPayload, _>::open(
            &active,
            k,
            cfg(2000, 50),
            std::sync::Arc::new(NoProtection),
        )
        .unwrap();
        for i in 0..40 {
            log.append(payload(i)).unwrap();
        }
        let seqs = list_archive_seqs(&active).unwrap();
        assert!(seqs.len() >= 3, "need a middle archive to delete");
        // Delete a MIDDLE archive (not the oldest) → a real sequence gap.
        let victim = seqs[1];
        fs::remove_file(archive_path(&active, victim)).unwrap();

        assert!(
            verify_log_set::<TestPayload>(&active, &pk).is_err(),
            "a deleted middle archive must break verification"
        );
    }

    /// Reopening continues the chain across a process restart: the tail
    /// survives close/open and the next append meta-chains correctly, so
    /// the full set (across the seam) verifies under the one key.
    #[test]
    fn reopen_continues_the_chain() {
        let dir = TempDir::new().unwrap();
        let active = dir.path().join("test.jsonl");
        let kpath = dir.path().join("agent.sig.key");
        // Bootstrap + persist the key once; pk is its pubkey. Every
        // session reloads the SAME key from kpath.
        let pk = TestKey::load_or_bootstrap(&kpath).unwrap().verifying_key();

        for round in [0u64, 25] {
            let k = TestKey::load_or_bootstrap(&kpath).unwrap();
            let mut log = RotatingChainLog::<TestPayload, _>::open(
                &active,
                k,
                cfg(2000, 50),
                std::sync::Arc::new(NoProtection),
            )
            .unwrap();
            for i in round..round + 25 {
                log.append(payload(i)).unwrap();
            }
        }

        let report = verify_log_set::<TestPayload>(&active, &pk).unwrap();
        assert_eq!(report.total_records, 50);
    }

    /// Eviction PAST the genesis file: a tight cap+retention drops seq 1
    /// (the ONLY genesis-rooted archive), so the earliest retained file is
    /// rooted on the SIGNED manifest's attested terminator hash of its
    /// evicted predecessor — the path the plain retention test doesn't
    /// isolate. A valid such set verifies.
    #[test]
    fn evict_past_genesis_verifies_via_manifest_attested_prev() {
        let dir = TempDir::new().unwrap();
        let active = dir.path().join("test.jsonl");
        let k = key();
        let pk = k.verifying_key();
        let mut log = RotatingChainLog::<TestPayload, _>::open(
            &active,
            k,
            cfg(2000, 2),
            std::sync::Arc::new(NoProtection),
        )
        .unwrap();
        for i in 0..60 {
            log.append(payload(i)).unwrap();
        }
        let earliest = *list_archive_seqs(&active).unwrap().first().unwrap();
        assert!(
            earliest > 1,
            "seq 1 (the genesis-rooted file) must be evicted"
        );
        let report = verify_log_set::<TestPayload>(&active, &pk).unwrap();
        assert_eq!(report.earliest_retained_seq, earliest);
    }

    /// Review 81: the sealed files of a log are its retained archives and
    /// its manifest — what the agent registers at start.
    #[test]
    fn sealed_files_are_the_archives_and_the_manifest() {
        let dir = TempDir::new().unwrap();
        let active = dir.path().join("test.jsonl");
        assert!(sealed_files(&active).is_empty());
        let mut log = RotatingChainLog::<TestPayload, _>::open(
            &active,
            key(),
            cfg(2000, 2),
            std::sync::Arc::new(NoProtection),
        )
        .unwrap();
        for i in 0..60 {
            log.append(payload(i)).unwrap();
        }
        let sealed = sealed_files(&active);
        let archives: Vec<PathBuf> = list_archive_seqs(&active)
            .unwrap()
            .into_iter()
            .map(|seq| archive_path(&active, seq))
            .collect();
        assert_eq!(archives.len(), 2);
        assert_eq!(sealed.len(), 3);
        assert!(archives.iter().all(|a| sealed.contains(a)));
        assert!(sealed.contains(&manifest_path_for(&active)));
        assert!(!sealed.contains(&active));
    }

    /// Review 80: every archive the retention evicts is released from the
    /// protection before it is removed (while it still exists), and only
    /// those: the retained archives and the active file keep theirs.
    #[test]
    fn eviction_releases_each_archive_before_removing_it() {
        #[derive(Default)]
        struct Recorder {
            released: std::sync::Mutex<Vec<(PathBuf, bool)>>,
        }
        impl ProtectionManager for Recorder {
            fn with_mutable_dir(&self, f: &mut dyn FnMut() -> Result<()>) -> Result<()> {
                f()
            }
            fn register_active(&self, _path: &Path) -> Result<()> {
                Ok(())
            }
            fn release(&self, path: &Path) -> Result<()> {
                self.released
                    .lock()
                    .unwrap()
                    .push((path.to_path_buf(), path.exists()));
                Ok(())
            }
        }
        let dir = TempDir::new().unwrap();
        let active = dir.path().join("test.jsonl");
        let rec = std::sync::Arc::new(Recorder::default());
        let mut log =
            RotatingChainLog::<TestPayload, _>::open(&active, key(), cfg(2000, 2), rec.clone())
                .unwrap();
        for i in 0..60 {
            log.append(payload(i)).unwrap();
        }
        let retained = list_archive_seqs(&active).unwrap();
        let released = rec.released.lock().unwrap().clone();
        assert!(!released.is_empty(), "the retention evicted archives");
        for (path, existed) in &released {
            assert!(existed, "{} released after its removal", path.display());
            assert!(!path.exists(), "{} released but kept", path.display());
            assert!(retained
                .iter()
                .all(|&seq| archive_path(&active, seq) != *path));
        }
        assert_eq!(
            released.len() + retained.len(),
            retained.last().copied().unwrap() as usize
        );
    }

    /// The evicted-prefix trust rests entirely on the manifest, so a
    /// tampered manifest MUST break verification — proving the manifest's
    /// own chain is VERIFIED before its attestations are trusted (not just
    /// read). Without eviction-past-genesis the manifest isn't consulted,
    /// so use the same tight cap+retention as above.
    #[test]
    fn tampered_manifest_breaks_verification() {
        let dir = TempDir::new().unwrap();
        let active = dir.path().join("test.jsonl");
        let k = key();
        let pk = k.verifying_key();
        let mut log = RotatingChainLog::<TestPayload, _>::open(
            &active,
            k,
            cfg(2000, 2),
            std::sync::Arc::new(NoProtection),
        )
        .unwrap();
        for i in 0..60 {
            log.append(payload(i)).unwrap();
        }
        assert!(verify_log_set::<TestPayload>(&active, &pk).is_ok());

        // Corrupt the first attested terminator_hash in the manifest.
        let mpath = manifest_path_for(&active);
        let contents = fs::read_to_string(&mpath).unwrap();
        let tampered = contents.replacen("\"terminator_hash\":\"", "\"terminator_hash\":\"0", 1);
        assert_ne!(contents, tampered, "test must actually mutate the manifest");
        fs::write(&mpath, tampered).unwrap();

        assert!(
            verify_log_set::<TestPayload>(&active, &pk).is_err(),
            "a tampered manifest must fail the evicted-prefix verification"
        );
    }

    /// A payload that carries a reserved top-level key (`rotate`) is
    /// rejected at write time — the data-vs-control discriminator is
    /// GUARANTEED, not assumed. Runs on every append, so an `Option`
    /// reserved field that is `None`-then-`Some` can't slip through.
    #[test]
    fn reserved_payload_key_is_rejected() {
        #[derive(Debug, Serialize, Deserialize)]
        struct Evil {
            rotate: u32,
            ts: String,
        }
        impl ChainPayload for Evil {
            const KIND: &'static str = "test_evil";
        }
        let dir = TempDir::new().unwrap();
        let active = dir.path().join("evil.jsonl");
        let k = key();
        let mut log = RotatingChainLog::<Evil, _>::open(
            &active,
            k,
            cfg(2000, 50),
            std::sync::Arc::new(NoProtection),
        )
        .unwrap();
        let err = log
            .append(Evil {
                rotate: 1,
                ts: "x".into(),
            })
            .unwrap_err();
        assert!(
            err.to_string().contains("reserved top-level key"),
            "a payload with a `rotate` field must be rejected, got: {err}"
        );
        // And nothing was written.
        assert!(!active.exists(), "rejected append must not create the file");
    }

    // ── BUG-026 boot-hang fix: O(1) open + torn-tail recovery ───────────

    /// Same key across "restarts" so a continued chain verifies under one
    /// pubkey (a fixed path → `load_or_bootstrap` reloads the same key).
    fn key_at(path: &Path) -> TestKey {
        TestKey::load_or_bootstrap(path).unwrap()
    }

    /// Append a REAL legacy-v1 data line (no `fmt_ver` on the wire), signed
    /// exactly as the pre-BUG-026 writer did; returns its `entry_hash` so
    /// the caller can chain the next line. Same byte-compat invariant as
    /// `drain::bug026_legacy_v1_drift_line_still_verifies`.
    fn append_v1(path: &Path, p: TestPayload, k: &TestKey, prev_hash: &str) -> String {
        // v1: `fmt_ver` omitted on the wire (skip_serializing_if), untagged
        // pre-image.
        let line = ChainLine::sealed_as(p, None, k, prev_hash).unwrap();
        append_and_fsync::<PortableHost>(path, &to_jsonl(&line).unwrap(), 0o600).unwrap();
        line.entry_hash
    }

    /// Reopen after a clean shutdown recovers the tail (O(1), no full-file
    /// walk) and the chain continues across the restart boundary.
    #[test]
    fn reopen_recovers_tail_and_continues_chain() {
        let dir = TempDir::new().unwrap();
        let active = dir.path().join("test.jsonl");
        let kp = dir.path().join("key");
        let pk = key_at(&kp).verifying_key();
        {
            let mut log = RotatingChainLog::<TestPayload, _>::open(
                &active,
                key_at(&kp),
                cfg(1 << 30, 50),
                std::sync::Arc::new(NoProtection),
            )
            .unwrap();
            for i in 0..5 {
                log.append(payload(i)).unwrap();
            }
        } // drop ⇒ simulate a restart
        {
            let mut log = RotatingChainLog::<TestPayload, _>::open(
                &active,
                key_at(&kp),
                cfg(1 << 30, 50),
                std::sync::Arc::new(NoProtection),
            )
            .unwrap();
            log.append(payload(5)).unwrap();
            log.append(payload(6)).unwrap();
        }
        let report = verify_log_set::<TestPayload>(&active, &pk).unwrap();
        assert_eq!(
            report.total_records, 7,
            "chain must span the reopen boundary"
        );
    }

    /// A torn final write (SIGKILL mid-append: trailing bytes with no
    /// newline) is discarded + the file truncated on reopen, so the next
    /// append lands cleanly and the whole log still verifies. Without the
    /// repair, the fragment would fuse with the next line into an
    /// unparseable record and fail `verify_log_set`.
    #[test]
    fn torn_trailing_fragment_discarded_and_repaired() {
        let dir = TempDir::new().unwrap();
        let active = dir.path().join("test.jsonl");
        let kp = dir.path().join("key");
        let pk = key_at(&kp).verifying_key();
        {
            let mut log = RotatingChainLog::<TestPayload, _>::open(
                &active,
                key_at(&kp),
                cfg(1 << 30, 50),
                std::sync::Arc::new(NoProtection),
            )
            .unwrap();
            for i in 0..4 {
                log.append(payload(i)).unwrap();
            }
        }
        let clean_len = fs::metadata(&active).unwrap().len();
        // Simulate a torn append: a partial line with NO terminating '\n'.
        {
            let mut f = OpenOptions::new().append(true).open(&active).unwrap();
            f.write_all(b"{\"ts\":\"2026-05-30T00:00:99.000000Z\",\"seq\":99,\"dat")
                .unwrap();
            f.sync_all().unwrap();
        }
        assert!(fs::metadata(&active).unwrap().len() > clean_len);
        {
            let mut log = RotatingChainLog::<TestPayload, _>::open(
                &active,
                key_at(&kp),
                cfg(1 << 30, 50),
                std::sync::Arc::new(NoProtection),
            )
            .unwrap();
            log.append(payload(4)).unwrap();
        }
        // Repair must have truncated the fragment before the new append.
        let report = verify_log_set::<TestPayload>(&active, &pk).unwrap();
        assert_eq!(
            report.total_records, 5,
            "4 clean + 1 post-repair, fragment dropped"
        );
    }

    /// A newline-terminated-but-unparseable final line is also discarded on
    /// reopen (recover the tail from the last line that *parses*).
    #[test]
    fn corrupt_newline_terminated_tail_discarded_on_reopen() {
        let dir = TempDir::new().unwrap();
        let active = dir.path().join("test.jsonl");
        let kp = dir.path().join("key");
        let pk = key_at(&kp).verifying_key();
        {
            let mut log = RotatingChainLog::<TestPayload, _>::open(
                &active,
                key_at(&kp),
                cfg(1 << 30, 50),
                std::sync::Arc::new(NoProtection),
            )
            .unwrap();
            for i in 0..4 {
                log.append(payload(i)).unwrap();
            }
        }
        {
            let mut f = OpenOptions::new().append(true).open(&active).unwrap();
            f.write_all(b"this is not valid json at all\n").unwrap();
            f.sync_all().unwrap();
        }
        {
            let mut log = RotatingChainLog::<TestPayload, _>::open(
                &active,
                key_at(&kp),
                cfg(1 << 30, 50),
                std::sync::Arc::new(NoProtection),
            )
            .unwrap();
            log.append(payload(4)).unwrap();
        }
        let report = verify_log_set::<TestPayload>(&active, &pk).unwrap();
        assert_eq!(
            report.total_records, 5,
            "corrupt trailing line must be dropped"
        );
    }

    /// THE legacy-migration case (BUG-026): a pre-existing **v1** active
    /// file already larger than the rotation cap must rotate on its FIRST
    /// append — proving (a) the guard keys on `active_bytes`, not the
    /// now-dropped record count, and (b) the v1→v2 terminator/meta-chain
    /// contract: the sealed v1 archive + v2 terminator + fresh active all
    /// verify end-to-end. (O(1) open is what clears the boot hang; this
    /// confirms "let the first append rotate the legacy file" is sound, so
    /// no separate seal-in-open migration is needed.)
    #[test]
    fn legacy_v1_over_cap_rotates_on_first_append_and_verifies() {
        let dir = TempDir::new().unwrap();
        let active = dir.path().join("test.jsonl");
        let kp = dir.path().join("key");
        let pk = key_at(&kp).verifying_key();
        // Hand-write 5 chained v1 lines from GENESIS (the legacy on-disk log).
        {
            let kv = key_at(&kp);
            let mut prev = GENESIS_PREV_HASH.to_string();
            for i in 0..5 {
                prev = append_v1(&active, payload(i), &kv, &prev);
            }
        }
        let v1_len = fs::metadata(&active).unwrap().len();
        assert!(
            v1_len > 64,
            "the legacy file must exceed the tiny cap below"
        );
        // Reopen with a cap SMALLER than the existing file ⇒ over-cap at open.
        {
            let mut log = RotatingChainLog::<TestPayload, _>::open(
                &active,
                key_at(&kp),
                cfg(64, 50),
                std::sync::Arc::new(NoProtection),
            )
            .unwrap();
            log.append(payload(99)).unwrap(); // first append → must rotate
        }
        assert_eq!(
            list_archive_seqs(&active).unwrap(),
            vec![1],
            "over-cap legacy-v1 file must seal to archive seq-1 on first append"
        );
        let report = verify_log_set::<TestPayload>(&active, &pk).unwrap();
        assert_eq!(
            report.total_records, 6,
            "5 legacy-v1 + 1 new-v2 verify across the v1→v2 rotation boundary"
        );
    }

    /// A torn-tail repair is ATTESTED in the signed manifest meta-chain (not
    /// a silent truncation of a tamper-evident log): the manifest gains a
    /// `torn_tail_repaired` event carrying the discarded fragment's hash, and
    /// the surviving data still verifies.
    #[test]
    fn torn_tail_repair_is_attested_in_manifest() {
        let dir = TempDir::new().unwrap();
        let active = dir.path().join("test.jsonl");
        let kp = dir.path().join("key");
        let pk = key_at(&kp).verifying_key();
        {
            let mut log = RotatingChainLog::<TestPayload, _>::open(
                &active,
                key_at(&kp),
                cfg(1 << 30, 50),
                std::sync::Arc::new(NoProtection),
            )
            .unwrap();
            for i in 0..3 {
                log.append(payload(i)).unwrap();
            }
        }
        // Tear the tail: a partial line with no terminating newline.
        let fragment: &[u8] = b"{\"ts\":\"2026-05-30T00:00:09.000000Z\",\"seq\":9,\"dat";
        {
            let mut f = OpenOptions::new().append(true).open(&active).unwrap();
            f.write_all(fragment).unwrap();
            f.sync_all().unwrap();
        }
        // Reopen → repair + attest.
        {
            let _ = RotatingChainLog::<TestPayload, _>::open(
                &active,
                key_at(&kp),
                cfg(1 << 30, 50),
                std::sync::Arc::new(NoProtection),
            )
            .unwrap();
        }
        let manifest = fs::read_to_string(manifest_path_for(&active)).unwrap();
        assert!(
            manifest.contains("torn_tail_repaired"),
            "the truncation must be attested in the manifest, got: {manifest}"
        );
        assert!(
            manifest.contains(&sha256_hex(fragment)),
            "the attestation must record the discarded fragment's hash"
        );
        // The 3 intact records still verify; the fragment was dropped.
        let report = verify_log_set::<TestPayload>(&active, &pk).unwrap();
        assert_eq!(report.total_records, 3);
    }

    // ── BUG-030: rotation failure-atomicity under the +i state dir ──────

    /// THE failure-injection test that proves bug 2 dead. A rotation whose
    /// MANIFEST write fails (injected by making the manifest path a directory,
    /// so the create/open fails AFTER rename + fresh-active succeed — the same
    /// shape as the `+i`-dir EPERM on the manifest create) must NOT lose sealed
    /// data and must NOT re-rotate into the same seq. On the buggy code the
    /// first such append errored and the next re-rotation renamed the empty
    /// active over the sealed archive → total data loss; the happy path never
    /// exercises this.
    #[test]
    fn rotation_survives_manifest_failure_without_data_loss() {
        let dir = TempDir::new().unwrap();
        let active = dir.path().join("test.jsonl");
        let kp = dir.path().join("key");
        let pk = key_at(&kp).verifying_key();
        let mut log = RotatingChainLog::<TestPayload, _>::open(
            &active,
            key_at(&kp),
            cfg(2000, 50),
            std::sync::Arc::new(NoProtection),
        )
        .unwrap();
        // One append first, so `open` saw a normal (absent) manifest; THEN
        // make the manifest path a DIRECTORY so every subsequent
        // manifest_append (a create) fails — the same shape as the +i EPERM.
        log.append(payload(0)).unwrap();
        std::fs::create_dir_all(manifest_path_for(&active)).unwrap();
        // Many rotations, each with a failing manifest_append — none may error.
        for i in 1..40 {
            log.append(payload(i)).unwrap_or_else(|e| {
                panic!("append {i} must succeed despite manifest failure: {e:#}")
            });
        }
        // Archives are distinct + contiguous — no seq reuse, no overwrite.
        let seqs = list_archive_seqs(&active).unwrap();
        assert!(
            seqs.len() >= 2,
            "~300 B payloads over a 2 KiB cap must rotate ≥2×"
        );
        assert_eq!(
            seqs,
            (1..=seqs.len() as u64).collect::<Vec<_>>(),
            "seqs must be contiguous — a re-rotation overwriting an archive would skip/reuse"
        );
        // Every signed record survives across the archives + active. The
        // verifier reads the manifest (NN-AUD-109) and refuses one that is
        // not a file, so the set is checked as the operator would after
        // clearing the obstruction.
        assert!(verify_log_set::<TestPayload>(&active, &pk).is_err());
        std::fs::remove_dir(manifest_path_for(&active)).unwrap();
        let report = verify_log_set::<TestPayload>(&active, &pk).unwrap();
        assert_eq!(
            report.total_records, 40,
            "no signed records lost despite manifest failures"
        );
    }

    /// Partial-rotation recovery (point #5): a crash AFTER the seal but BEFORE
    /// the rename leaves an active ending in a terminator with no archive.
    /// `open` must detect it and complete the rotation (archive seq-1 + fresh
    /// active), and the set must verify across the recovered boundary.
    #[test]
    fn interrupted_rotation_recovers_cleanly_on_open() {
        let dir = TempDir::new().unwrap();
        let active = dir.path().join("test.jsonl");
        let kp = dir.path().join("key");
        let pk = key_at(&kp).verifying_key();
        let tail = {
            let mut log = RotatingChainLog::<TestPayload, _>::open(
                &active,
                key_at(&kp),
                cfg(1 << 30, 50),
                std::sync::Arc::new(NoProtection),
            )
            .unwrap();
            for i in 0..3 {
                log.append(payload(i)).unwrap();
            }
            log.last_hash().to_string()
        };
        // Crash after seal, before rename: append a terminator chained off the
        // data tail; leave NO archive.
        let k = key_at(&kp);
        let term = TerminatorLine::sealed(
            RotateTerminator {
                fmt_ver: CHAINLOG_FMT_V3,
                this_seq: 1,
                next_seq: 2,
                record_count: 3,
                bytes: 0,
            },
            &k,
            &tail,
            TestPayload::KIND,
            &SystemClock,
        )
        .unwrap();
        append_and_fsync::<PortableHost>(&active, &to_jsonl(&term).unwrap(), 0o600).unwrap();
        assert!(
            list_archive_seqs(&active).unwrap().is_empty(),
            "pre-recovery: sealed active, no archive yet"
        );
        // Reopen → open() sees the sealed active → complete_interrupted_rotation.
        {
            let mut log = RotatingChainLog::<TestPayload, _>::open(
                &active,
                key_at(&kp),
                cfg(1 << 30, 50),
                std::sync::Arc::new(NoProtection),
            )
            .unwrap();
            log.append(payload(99)).unwrap();
        }
        assert_eq!(
            list_archive_seqs(&active).unwrap(),
            vec![1],
            "interrupted rotation completed on open → seq-1 archived"
        );
        let report = verify_log_set::<TestPayload>(&active, &pk).unwrap();
        assert_eq!(
            report.total_records, 4,
            "3 sealed + 1 post-recovery verify across the boundary"
        );
    }

    /// Partial-rotation recovery, CASE 2 (point #5): a crash AFTER the rename
    /// but BEFORE the fresh active is created — archive present, active ABSENT,
    /// with NO data loss (the rename already put everything in the archive).
    /// `open` must chain the lazily-recreated active off the prior archive's
    /// terminator, NOT re-root at genesis or re-rotate. (Reaches the empty-
    /// active state via the interrupted-rotation path, then removes it.)
    #[test]
    fn post_rename_crash_recovers_with_active_absent() {
        let dir = TempDir::new().unwrap();
        let active = dir.path().join("test.jsonl");
        let kp = dir.path().join("key");
        let pk = key_at(&kp).verifying_key();
        let tail = {
            let mut log = RotatingChainLog::<TestPayload, _>::open(
                &active,
                key_at(&kp),
                cfg(1 << 30, 50),
                std::sync::Arc::new(NoProtection),
            )
            .unwrap();
            for i in 0..3 {
                log.append(payload(i)).unwrap();
            }
            log.last_hash().to_string()
        };
        let k = key_at(&kp);
        let term = TerminatorLine::sealed(
            RotateTerminator {
                fmt_ver: CHAINLOG_FMT_V3,
                this_seq: 1,
                next_seq: 2,
                record_count: 3,
                bytes: 0,
            },
            &k,
            &tail,
            TestPayload::KIND,
            &SystemClock,
        )
        .unwrap();
        append_and_fsync::<PortableHost>(&active, &to_jsonl(&term).unwrap(), 0o600).unwrap();
        // open #1 completes the interrupted rotation → archive seq-1 + EMPTY active.
        drop(
            RotatingChainLog::<TestPayload, _>::open(
                &active,
                key_at(&kp),
                cfg(1 << 30, 50),
                std::sync::Arc::new(NoProtection),
            )
            .unwrap(),
        );
        assert_eq!(list_archive_seqs(&active).unwrap(), vec![1]);
        // Model case 2: the fresh active was never (re)created — remove the
        // empty active (loses no data; everything is in seq-1).
        std::fs::remove_file(&active).unwrap();
        // open #2 must recover: active absent → chain off seq-1's terminator.
        {
            let mut log = RotatingChainLog::<TestPayload, _>::open(
                &active,
                key_at(&kp),
                cfg(1 << 30, 50),
                std::sync::Arc::new(NoProtection),
            )
            .unwrap();
            log.append(payload(99)).unwrap();
        }
        let report = verify_log_set::<TestPayload>(&active, &pk).unwrap();
        assert_eq!(
            report.total_records, 4,
            "3 archived + 1 recovered off the prior terminator"
        );
    }

    // ── repair_torn_tail (external audit EVD-005, NET-003, DEC-006) ──

    fn parses(l: &[u8]) -> bool {
        serde_json::from_slice::<serde_json::Value>(l).is_ok()
    }

    #[test]
    fn a_torn_last_write_is_cut_off_and_fingerprinted() {
        let dir = tempfile::TempDir::new().unwrap();
        let p = dir.path().join("x.jsonl");
        fs::write(&p, "{\"a\":1}\n{\"a\":2}\n{\"a\":3, \"tr").unwrap();
        let r = repair_torn_tail(&p, parses).unwrap().unwrap();
        assert!(
            matches!(
                r,
                TailRepair::Truncated {
                    dropped_len: 11,
                    ..
                }
            ),
            "{r:?}"
        );
        assert_eq!(fs::read_to_string(&p).unwrap(), "{\"a\":1}\n{\"a\":2}\n");
        // clean now
        assert_eq!(repair_torn_tail(&p, parses).unwrap(), None);
    }

    #[test]
    fn a_complete_last_line_only_gets_its_newline() {
        let dir = tempfile::TempDir::new().unwrap();
        let p = dir.path().join("x.jsonl");
        fs::write(&p, "{\"a\":1}\n{\"a\":2}").unwrap();
        assert_eq!(
            repair_torn_tail(&p, parses).unwrap(),
            Some(TailRepair::Terminated)
        );
        assert_eq!(fs::read_to_string(&p).unwrap(), "{\"a\":1}\n{\"a\":2}\n");
    }

    #[test]
    fn corruption_before_the_end_and_a_lone_fragment_are_left_alone() {
        let dir = tempfile::TempDir::new().unwrap();
        // a complete bad line mid-file is not a torn write: untouched
        let p = dir.path().join("mid.jsonl");
        fs::write(&p, "{\"a\":1}\ngarbage\n{\"a\":3}\n").unwrap();
        assert_eq!(repair_torn_tail(&p, parses).unwrap(), None);
        assert_eq!(
            fs::read_to_string(&p).unwrap(),
            "{\"a\":1}\ngarbage\n{\"a\":3}\n"
        );
        // nothing complete would remain: refused, untouched
        let q = dir.path().join("lone.jsonl");
        fs::write(&q, "{\"a\":1, \"tor").unwrap();
        assert!(repair_torn_tail(&q, parses).is_err());
        assert_eq!(fs::read_to_string(&q).unwrap(), "{\"a\":1, \"tor");
        // missing and empty files: nothing to do
        assert_eq!(
            repair_torn_tail(&dir.path().join("none"), parses).unwrap(),
            None
        );
        let e = dir.path().join("empty");
        fs::write(&e, "").unwrap();
        assert_eq!(repair_torn_tail(&e, parses).unwrap(), None);
    }

    // ── External audit NN-AUD-110 / NN-AUD-115 ──

    fn open_log(active: &Path, kp: &Path, cap: u64) -> RotatingChainLog<TestPayload, TestKey> {
        open_log_with(active, kp, cap, std::sync::Arc::new(NoProtection))
    }

    fn open_log_with(
        active: &Path,
        kp: &Path,
        cap: u64,
        prot: std::sync::Arc<dyn ProtectionManager>,
    ) -> RotatingChainLog<TestPayload, TestKey> {
        RotatingChainLog::<TestPayload, _>::open(active, key_at(kp), cfg(cap, 50), prot).unwrap()
    }

    fn append_raw(path: &Path, bytes: &[u8]) {
        let mut f = OpenOptions::new().append(true).open(path).unwrap();
        f.write_all(bytes).unwrap();
        f.sync_all().unwrap();
    }

    fn manifest_events(active: &Path) -> Vec<ManifestEvent> {
        fs::read_to_string(manifest_path_for(active))
            .unwrap_or_default()
            .lines()
            .map(|l| {
                serde_json::from_str::<ManifestLine>(l)
                    .unwrap()
                    .manifest
                    .event
            })
            .collect()
    }

    fn data_lines(path: &Path) -> usize {
        fs::read_to_string(path)
            .unwrap()
            .lines()
            .filter(|l| !l.contains("\"rotate\""))
            .count()
    }

    /// External audit NN-AUD-110: a one-line forged tail with a non-hex
    /// `entry_hash` and a bare `rotate` key used to trigger a spurious
    /// rotation and then fail every append (`prev_hash not hex`).
    #[test]
    fn a_non_hex_forged_tail_is_cut_and_attested() {
        let dir = TempDir::new().unwrap();
        let active = dir.path().join("test.jsonl");
        let kp = dir.path().join("key");
        let pk = key_at(&kp).verifying_key();
        {
            let mut log = open_log(&active, &kp, 1 << 30);
            for i in 0..3 {
                log.append(payload(i)).unwrap();
            }
        }
        let forged = b"{\"rotate\":{},\"entry_hash\":\"b\"}\n";
        append_raw(&active, forged);
        let mut log = open_log(&active, &kp, 1 << 30);
        log.append(payload(3)).expect("appends must keep working");
        drop(log);
        assert!(
            list_archive_seqs(&active).unwrap().is_empty(),
            "no spurious rotation"
        );
        assert!(manifest_events(&active).iter().any(|e| matches!(e,
            ManifestEvent::TornTailRepaired { role, dropped_sha256, .. }
                if role == "active" && *dropped_sha256 == sha256_hex(forged))));
        let report = verify_log_set::<TestPayload>(&active, &pk).unwrap();
        assert_eq!(report.total_records, 4);
    }

    /// External audit NN-AUD-110: `sealed` needs a terminator that decodes
    /// and verifies, not the mere presence of a `rotate` key.
    #[test]
    fn a_rotate_key_on_a_non_terminator_does_not_rotate() {
        let dir = TempDir::new().unwrap();
        let active = dir.path().join("test.jsonl");
        let kp = dir.path().join("key");
        let pk = key_at(&kp).verifying_key();
        {
            let mut log = open_log(&active, &kp, 1 << 30);
            for i in 0..3 {
                log.append(payload(i)).unwrap();
            }
        }
        let forged = format!(
            "{{\"rotate\":{{\"seq\":1}},\"prev_hash\":\"a\",\"entry_hash\":\"{}\",\"agent_sig\":\"c\"}}\n",
            "b".repeat(64)
        );
        append_raw(&active, forged.as_bytes());
        let mut log = open_log(&active, &kp, 1 << 30);
        log.append(payload(3)).unwrap();
        drop(log);
        assert!(
            list_archive_seqs(&active).unwrap().is_empty(),
            "archive count unchanged"
        );
        assert_eq!(
            verify_log_set::<TestPayload>(&active, &pk)
                .unwrap()
                .total_records,
            4
        );
    }

    /// External audit NN-AUD-110: a hash-valid terminator signed by another
    /// key is kept (attested, never cut) but never completes a rotation.
    #[test]
    fn a_terminator_signed_by_another_key_does_not_rotate() {
        let dir = TempDir::new().unwrap();
        let active = dir.path().join("test.jsonl");
        let kp = dir.path().join("key");
        let tail = {
            let mut log = open_log(&active, &kp, 1 << 30);
            for i in 0..3 {
                log.append(payload(i)).unwrap();
            }
            log.last_hash().to_string()
        };
        let other = key_at(&dir.path().join("other"));
        let term = TerminatorLine::sealed(
            RotateTerminator {
                fmt_ver: CHAINLOG_FMT_V3,
                this_seq: 7,
                next_seq: 8,
                record_count: 3,
                bytes: 0,
            },
            &other,
            &tail,
            TestPayload::KIND,
            &SystemClock,
        )
        .unwrap();
        append_raw(&active, to_jsonl(&term).unwrap().as_bytes());
        let mut log = open_log(&active, &kp, 1 << 30);
        log.append(payload(3)).unwrap();
        drop(log);
        assert!(list_archive_seqs(&active).unwrap().is_empty());
        assert!(manifest_events(&active).iter().any(|e| matches!(e,
            ManifestEvent::TailUnverified { role, entry_hash, .. }
                if role == "active" && *entry_hash == term.entry_hash)));
        assert_eq!(data_lines(&active), 4, "nothing cut");
    }

    /// External audit NN-AUD-110: a forged manifest tail made the torn-tail
    /// attestation fail on `hex::decode`, so `open` failed every boot.
    #[test]
    fn a_forged_manifest_tail_does_not_fail_open() {
        let dir = TempDir::new().unwrap();
        let active = dir.path().join("test.jsonl");
        let kp = dir.path().join("key");
        let pk = key_at(&kp).verifying_key();
        {
            let mut log = open_log(&active, &kp, 2000);
            for i in 0..12 {
                log.append(payload(i)).unwrap();
            }
        }
        assert!(!list_archive_seqs(&active).unwrap().is_empty());
        let forged = b"{\"manifest\":{},\"entry_hash\":\"zz\"}\n";
        append_raw(&manifest_path_for(&active), forged);
        let mut log = open_log(&active, &kp, 2000);
        log.append(payload(12)).unwrap();
        drop(log);
        assert!(manifest_events(&active).iter().any(|e| matches!(e,
            ManifestEvent::TornTailRepaired { role, .. } if role == "manifest")));
        verify_manifest(&active, TestPayload::KIND, &pk).expect("manifest chain intact");
        assert_eq!(
            verify_log_set::<TestPayload>(&active, &pk)
                .unwrap()
                .total_records,
            13
        );
    }

    /// External audit NN-AUD-110: chain-shaped lines whose hash does not
    /// recompute are cut and attested, within a bound; a longer run (a
    /// schema or key problem, not a forged tail) is kept and attested, and
    /// no recovery empties a file.
    #[test]
    fn hash_invalid_tail_lines_are_cut_within_a_bound() {
        let forged = |i: u64| {
            format!(
                "{{\"ts\":\"x\",\"seq\":{i},\"data\":\"forged\",\"prev_hash\":\"{z}\",\"entry_hash\":\"{h:064x}\",\"agent_sig\":\"\"}}\n",
                z = "0".repeat(64),
                h = i + 1
            )
        };
        let dir = TempDir::new().unwrap();
        let kp = dir.path().join("key");
        let pk = key_at(&kp).verifying_key();
        // A short run is cut.
        let a = dir.path().join("a.jsonl");
        {
            let mut log = open_log(&a, &kp, 1 << 30);
            for i in 0..3 {
                log.append(payload(i)).unwrap();
            }
        }
        for i in 0..2 {
            append_raw(&a, forged(i).as_bytes());
        }
        open_log(&a, &kp, 1 << 30).append(payload(3)).unwrap();
        assert_eq!(
            verify_log_set::<TestPayload>(&a, &pk)
                .unwrap()
                .total_records,
            4
        );
        // A run past the bound is kept, not cut.
        let b = dir.path().join("b.jsonl");
        {
            let mut log = open_log(&b, &kp, 1 << 30);
            log.append(payload(0)).unwrap();
        }
        for i in 0..=(MAX_TAIL_REJECTS as u64) {
            append_raw(&b, forged(i).as_bytes());
        }
        drop(open_log(&b, &kp, 1 << 30));
        assert_eq!(data_lines(&b), MAX_TAIL_REJECTS + 2);
        assert!(manifest_events(&b)
            .iter()
            .any(|e| matches!(e, ManifestEvent::TailUnverified { .. })));
        // A file of nothing but such lines is never emptied.
        let c = dir.path().join("c.jsonl");
        fs::write(&c, forged(0) + &forged(1)).unwrap();
        drop(open_log(&c, &kp, 1 << 30));
        assert_eq!(data_lines(&c), 2);
    }

    /// External audit NN-AUD-110: an interrupted rotation completes into the
    /// slot its verified terminator names (`this_seq`), not `next_seq`.
    #[test]
    fn an_interrupted_rotation_uses_the_terminator_this_seq() {
        let dir = TempDir::new().unwrap();
        let active = dir.path().join("test.jsonl");
        let kp = dir.path().join("key");
        let tail = {
            let mut log = open_log(&active, &kp, 1 << 30);
            log.append(payload(0)).unwrap();
            log.last_hash().to_string()
        };
        let term = TerminatorLine::sealed(
            RotateTerminator {
                fmt_ver: CHAINLOG_FMT_V3,
                this_seq: 3,
                next_seq: 4,
                record_count: 1,
                bytes: 0,
            },
            &key_at(&kp),
            &tail,
            TestPayload::KIND,
            &SystemClock,
        )
        .unwrap();
        append_raw(&active, to_jsonl(&term).unwrap().as_bytes());
        drop(open_log(&active, &kp, 1 << 30));
        assert_eq!(list_archive_seqs(&active).unwrap(), vec![3]);
    }

    /// External audit NN-AUD-115: a foreign file at the archive slot used to
    /// skip the rename and then truncate the sealed active file.
    #[test]
    fn a_foreign_file_at_the_archive_slot_never_truncates_the_active() {
        let dir = TempDir::new().unwrap();
        let active = dir.path().join("test.jsonl");
        let kp = dir.path().join("key");
        let slot = archive_path(&active, 1);
        let mut log = open_log(&active, &kp, 2000);
        fs::write(&slot, b"foreign\n").unwrap();
        let n = 8;
        for i in 0..n {
            log.append(payload(i)).unwrap();
        }
        drop(log);
        assert_eq!(
            fs::read(&slot).unwrap(),
            b"foreign\n",
            "foreign entry untouched"
        );
        let seqs = list_archive_seqs(&active).unwrap();
        assert!(
            seqs.len() >= 2 && seqs[0] == 1,
            "rotated past the slot: {seqs:?}"
        );
        let kept: usize = seqs[1..]
            .iter()
            .map(|&s| data_lines(&archive_path(&active, s)))
            .sum::<usize>()
            + data_lines(&active);
        assert_eq!(kept as u64, n, "every signed record survives");
        // The terminator names the slot the file really became.
        let t: TerminatorLine = serde_json::from_str(
            fs::read_to_string(archive_path(&active, seqs[1]))
                .unwrap()
                .lines()
                .last()
                .unwrap(),
        )
        .unwrap();
        assert_eq!(t.rotate.this_seq, seqs[1]);
        // The foreign archive is still flagged by the verifier.
        let pk = key_at(&kp).verifying_key();
        assert!(verify_log_set::<TestPayload>(&active, &pk).is_err());
    }

    /// External audit NN-AUD-110: a newest archive with no usable
    /// terminator (foreign file, or a forged non-hex hash) used to fail
    /// `open`, or every append, at every boot.
    #[test]
    fn a_newest_archive_without_a_usable_terminator_does_not_block_the_log() {
        let dir = TempDir::new().unwrap();
        let kp = dir.path().join("key");
        for (name, body) in [
            ("a.jsonl", "foreign\n".to_string()),
            (
                "b.jsonl",
                "{\"rotate\":{},\"entry_hash\":\"b\"}\n".to_string(),
            ),
        ] {
            let active = dir.path().join(name);
            fs::write(archive_path(&active, 1), body).unwrap();
            let mut log = open_log(&active, &kp, 1 << 30);
            log.append(payload(0)).expect("appends must keep working");
            drop(log);
            assert!(manifest_events(&active)
                .iter()
                .any(|e| matches!(e, ManifestEvent::ForeignArchive { seq: 1, .. })));
        }
    }

    /// External audit NN-AUD-115: the slot check is an lstat, and the rename
    /// never replaces: a foreign entry at the slot is not overwritten, even
    /// when it appears after the seal (interrupted rotation completed at
    /// open). R04a (lab PR 241): a regular file here, on the portable host;
    /// the symlink case, on the agent's host, is
    /// `chain_host_linux::tests::a_symlink_at_the_slot_of_an_interrupted_rotation_is_left_alone`.
    #[test]
    fn a_foreign_file_at_the_slot_of_an_interrupted_rotation_is_left_alone() {
        let dir = TempDir::new().unwrap();
        let active = dir.path().join("test.jsonl");
        let kp = dir.path().join("key");
        let tail = {
            let mut log = open_log(&active, &kp, 1 << 30);
            for i in 0..3 {
                log.append(payload(i)).unwrap();
            }
            log.last_hash().to_string()
        };
        let term = TerminatorLine::sealed(
            RotateTerminator {
                fmt_ver: CHAINLOG_FMT_V3,
                this_seq: 1,
                next_seq: 2,
                record_count: 3,
                bytes: 0,
            },
            &key_at(&kp),
            &tail,
            TestPayload::KIND,
            &SystemClock,
        )
        .unwrap();
        append_raw(&active, to_jsonl(&term).unwrap().as_bytes());
        let slot = archive_path(&active, 1);
        fs::write(&slot, b"foreign").unwrap();
        let mut log = open_log(&active, &kp, 1 << 30);
        log.append(payload(3)).unwrap();
        drop(log);
        assert_eq!(fs::read(&slot).unwrap(), b"foreign");
        let archived = archive_path(&active, 2);
        assert_eq!(data_lines(&archived), 3, "sealed file archived intact");
        assert_eq!(data_lines(&active), 1);
        assert!(manifest_events(&active).iter().any(|e| matches!(e,
            ManifestEvent::ForeignArchive { seq: 1, entry_type, .. } if entry_type == "file")));
    }

    /// External audit NN-AUD-115: the fresh active is created with O_EXCL —
    /// an existing file is not truncated. R04a (lab PR 241): that a symlink
    /// is not followed is the host's open, tested on the agent's
    /// (`chain_host_linux::tests::an_exclusive_create_follows_no_symlink`).
    #[test]
    fn fresh_active_is_created_exclusively() {
        let dir = TempDir::new().unwrap();
        let existing = dir.path().join("existing");
        fs::write(&existing, b"keep").unwrap();
        assert!(create_fresh_active::<PortableHost>(&existing, 0o600).is_err());
        assert_eq!(fs::read(&existing).unwrap(), b"keep");
        let fresh = dir.path().join("fresh");
        create_fresh_active::<PortableHost>(&fresh, 0o600).unwrap();
        assert_eq!(fs::metadata(&fresh).unwrap().len(), 0);
    }

    /// External audit NN-AUD-115: when the finish step fails after the seal,
    /// the next append retries only the finish step; it used to seal again,
    /// leaving two terminators in one file.
    #[test]
    fn a_failed_rename_does_not_seal_twice() {
        struct FailOnce(std::sync::atomic::AtomicBool);
        impl ProtectionManager for FailOnce {
            fn with_mutable_dir(&self, f: &mut dyn FnMut() -> Result<()>) -> Result<()> {
                if self.0.swap(false, std::sync::atomic::Ordering::SeqCst) {
                    return Err(anyhow!("simulated dance failure"));
                }
                f()
            }
            fn register_active(&self, _path: &Path) -> Result<()> {
                Ok(())
            }
        }
        let dir = TempDir::new().unwrap();
        let active = dir.path().join("test.jsonl");
        let kp = dir.path().join("key");
        let pk = key_at(&kp).verifying_key();
        let prot = std::sync::Arc::new(FailOnce(std::sync::atomic::AtomicBool::new(false)));
        let mut log = open_log_with(&active, &kp, 2000, prot.clone());
        let mut i = 0;
        while log.active_bytes + 400 < 2000 {
            log.append(payload(i)).unwrap();
            i += 1;
        }
        prot.0.store(true, std::sync::atomic::Ordering::SeqCst);
        assert!(
            log.append(payload(i)).is_err(),
            "the first finish step fails"
        );
        log.append(payload(i + 1)).unwrap();
        drop(log);
        let seqs = list_archive_seqs(&active).unwrap();
        assert_eq!(seqs, vec![1]);
        let terminators = fs::read_to_string(archive_path(&active, 1))
            .unwrap()
            .lines()
            .filter(|l| l.contains("\"rotate\""))
            .count();
        assert_eq!(terminators, 1, "sealed exactly once");
        let report = verify_log_set::<TestPayload>(&active, &pk).unwrap();
        assert_eq!(report.total_records, i + 1);
    }

    // ── External audit NN-AUD-109 / NN-AUD-112 (lab PR 160) ──────────

    fn checkpoints(active: &Path) -> Vec<(u64, u64, String)> {
        manifest_events(active)
            .into_iter()
            .filter_map(|e| match e {
                ManifestEvent::ActiveCheckpoint {
                    seq,
                    bytes,
                    tail_hash,
                } => Some((seq, bytes, tail_hash)),
                _ => None,
            })
            .collect()
    }

    /// The open anchors a non-empty active file once, not again while
    /// nothing changed; an empty one is not anchored.
    #[test]
    fn open_checkpoints_a_non_empty_active_file_once() {
        let dir = TempDir::new().unwrap();
        let active = dir.path().join("test.jsonl");
        let kp = dir.path().join("key");
        drop(open_log(&active, &kp, 1 << 30));
        assert!(checkpoints(&active).is_empty(), "nothing to anchor yet");
        let mut log = open_log(&active, &kp, 1 << 30);
        for i in 0..3 {
            log.append(payload(i)).unwrap();
        }
        let tail = log.last_hash().to_string();
        drop(log);
        drop(open_log(&active, &kp, 1 << 30));
        let len = fs::metadata(&active).unwrap().len();
        assert_eq!(checkpoints(&active), vec![(1, len, tail.clone())]);
        drop(open_log(&active, &kp, 1 << 30));
        assert_eq!(checkpoints(&active).len(), 1, "unchanged: no new row");
        let pk = key_at(&kp).verifying_key();
        assert_eq!(
            verify_log_set::<TestPayload>(&active, &pk)
                .unwrap()
                .checkpoints_verified,
            1
        );
    }

    /// External audit NN-AUD-109: before lab PR 160 an emptied active file
    /// verified as an empty chain. The checkpoint names what was there.
    #[test]
    fn emptying_the_active_file_after_a_checkpoint_is_detected() {
        let dir = TempDir::new().unwrap();
        let active = dir.path().join("test.jsonl");
        let kp = dir.path().join("key");
        let pk = key_at(&kp).verifying_key();
        let mut log = open_log(&active, &kp, 1 << 30);
        for i in 0..5 {
            log.append(payload(i)).unwrap();
        }
        log.checkpoint().unwrap();
        drop(log);
        verify_log_set::<TestPayload>(&active, &pk).unwrap();
        fs::write(&active, b"").unwrap();
        let err = verify_log_set::<TestPayload>(&active, &pk).unwrap_err();
        assert!(
            matches!(err, LogSetError::CheckpointUnreachable { seq: 1, .. }),
            "{err:?}"
        );
        // cut, not emptied: same
        let mut log = open_log(&active, &kp, 1 << 30);
        log.append(payload(9)).unwrap();
        drop(log);
        assert!(matches!(
            verify_log_set::<TestPayload>(&active, &pk).unwrap_err(),
            LogSetError::CheckpointUnreachable { .. }
        ));
    }

    /// External audit NN-AUD-109: before lab PR 160 a deleted active file
    /// verified as "a never-created active file".
    #[test]
    fn deleting_the_active_file_with_archives_is_detected() {
        let dir = TempDir::new().unwrap();
        let active = dir.path().join("test.jsonl");
        let kp = dir.path().join("key");
        let pk = key_at(&kp).verifying_key();
        let mut log = open_log(&active, &kp, 2000);
        for i in 0..12 {
            log.append(payload(i)).unwrap();
        }
        drop(log);
        assert!(!list_archive_seqs(&active).unwrap().is_empty());
        verify_log_set::<TestPayload>(&active, &pk).unwrap();
        fs::remove_file(&active).unwrap();
        let err = verify_log_set::<TestPayload>(&active, &pk).unwrap_err();
        assert!(matches!(err, LogSetError::ActiveMissing { .. }), "{err:?}");
        let tail = manifest_tail_events::<PortableHost>(&active, TestPayload::KIND, &pk);
        assert!(active_missing(&active, &tail).is_some());
    }

    /// The newest archive and the active file both removed: the manifest
    /// still names what followed.
    #[test]
    fn deleting_the_newest_archive_and_the_active_is_detected() {
        let dir = TempDir::new().unwrap();
        let active = dir.path().join("test.jsonl");
        let kp = dir.path().join("key");
        let pk = key_at(&kp).verifying_key();
        let mut log = open_log(&active, &kp, 2000);
        for i in 0..30 {
            log.append(payload(i)).unwrap();
        }
        log.checkpoint().unwrap();
        drop(log);
        let seqs = list_archive_seqs(&active).unwrap();
        assert!(seqs.len() >= 2);
        fs::remove_file(archive_path(&active, *seqs.last().unwrap())).unwrap();
        fs::remove_file(&active).unwrap();
        let err = verify_log_set::<TestPayload>(&active, &pk).unwrap_err();
        assert!(
            matches!(
                err,
                LogSetError::CheckpointUnreachable { .. } | LogSetError::ActiveMissing { .. }
            ),
            "{err:?}"
        );
    }

    /// External audit NN-AUD-112: the bounded boot check verifies the tail
    /// of the active file and finds a line that does not verify.
    #[test]
    fn verify_recent_checks_the_tail_and_finds_a_forged_line() {
        let dir = TempDir::new().unwrap();
        let active = dir.path().join("test.jsonl");
        let kp = dir.path().join("key");
        let pk = key_at(&kp).verifying_key();
        let mut log = open_log(&active, &kp, 1 << 30);
        for i in 0..20 {
            log.append(payload(i)).unwrap();
        }
        drop(log);
        let whole = verify_recent::<TestPayload, PortableHost>(&active, &pk, 1 << 20).unwrap();
        assert_eq!((whole.lines, whole.whole_file), (20, true));
        let part = verify_recent::<TestPayload, PortableHost>(&active, &pk, 600).unwrap();
        assert!(!part.whole_file && part.lines < 20 && part.lines > 0);
        // a fabricated detection-shaped line at the end
        let forged = format!(
            "{{\"ts\":\"x\",\"seq\":99,\"data\":\"forged\",\"fmt_ver\":2,\"prev_hash\":\"{}\",\
             \"entry_hash\":\"{}\",\"agent_sig\":\"AAAA\"}}\n",
            "00".repeat(32),
            "11".repeat(32)
        );
        append_raw(&active, forged.as_bytes());
        assert!(verify_recent::<TestPayload, PortableHost>(&active, &pk, 1 << 20).is_err());
        assert!(verify_log_set::<TestPayload>(&active, &pk).is_err());
    }

    // ── Lab PR 256: the boot check says the class and where ──────────────

    /// The offset each line of `path` starts at.
    fn line_offsets(path: &Path) -> Vec<u64> {
        let body = fs::read(path).unwrap();
        let mut out = vec![0u64];
        for (i, c) in body.iter().enumerate() {
            if *c == b'\n' && i + 1 < body.len() {
                out.push(i as u64 + 1);
            }
        }
        out
    }

    /// `payload(i)`'s timestamp.
    fn ts(i: u64) -> Option<String> {
        Some(format!("2026-05-30T00:00:{i:02}.000000Z"))
    }

    /// `n` lines of the agent's key (`kp`), then `m` of another key, then
    /// `k` of the agent's again: an agent of another key — an e2e
    /// fixture's, started on the host with a key of its own (lot 255) —
    /// appended to the log, and the agent's next lines link to its tail.
    fn interleaved(dir: &Path, kp: &Path, n: u64, m: u64, k: u64) -> PathBuf {
        let active = dir.join("test.jsonl");
        let mut log = open_log(&active, kp, 1 << 30);
        for i in 0..n {
            log.append(payload(i)).unwrap();
        }
        drop(log);
        let mut other = open_log(&active, &dir.join("other-key"), 1 << 30);
        for i in n..n + m {
            other.append(payload(i)).unwrap();
        }
        drop(other);
        let mut log = open_log(&active, kp, 1 << 30);
        for i in n + m..n + m + k {
            log.append(payload(i)).unwrap();
        }
        drop(log);
        active
    }

    /// Lines another key signed recompute and link: the boot check names
    /// that class, counts them over the window, places the first and the
    /// last (line number and byte offset), and fails — a
    /// `chain_verify_failed` as before. `chain verify` fails at the first
    /// and says its hash recomputes.
    #[test]
    fn the_boot_check_counts_and_places_lines_another_key_signed() {
        let dir = TempDir::new().unwrap();
        let kp = dir.path().join("key");
        let pk = key_at(&kp).verifying_key();
        let active = interleaved(dir.path(), &kp, 5, 3, 2);
        let at = line_offsets(&active);
        assert_eq!(at.len(), 10);
        let err = verify_recent::<TestPayload, PortableHost>(&active, &pk, 1 << 20).unwrap_err();
        assert_eq!(err.class(), "signed_by_another_key");
        let key = hex::encode(&pk.to_bytes()[..4]);
        assert_eq!(
            err,
            RecentError::SignedByAnotherKey(Box::new(ForeignLines {
                file: active.display().to_string(),
                count: 3,
                checked: 10,
                first: LinePos {
                    offset: at[5],
                    line: Some(6),
                    ts: ts(5)
                },
                last: LinePos {
                    offset: at[7],
                    line: Some(8),
                    ts: ts(7)
                },
                key: key.clone(),
            }))
        );
        let text = err.to_string();
        let want = format!(
            "3 of the 10 lines checked are signed by another key, from line 6 (byte {}, ts \
             2026-05-30T00:00:05.000000Z) to line 8 (byte {}, ts 2026-05-30T00:00:07.000000Z): \
             each one's entry_hash recomputes and its link to the line before it is intact, but \
             its signature does not verify with this agent's key (agent.sig.pub {key}…)",
            at[5], at[7]
        );
        assert!(text.contains(&want), "{text}");
        let full = verify_log_set::<TestPayload>(&active, &pk).unwrap_err();
        assert!(
            matches!(full, LogSetError::SignatureInvalid { .. }),
            "{full:?}"
        );
        assert!(
            full.to_string().contains("its entry_hash recomputes"),
            "{full}"
        );
        // One line: said in the singular.
        let dir = TempDir::new().unwrap();
        let kp = dir.path().join("key");
        let pk = key_at(&kp).verifying_key();
        let active = interleaved(dir.path(), &kp, 2, 1, 1);
        let text = verify_recent::<TestPayload, PortableHost>(&active, &pk, 1 << 20)
            .unwrap_err()
            .to_string();
        assert!(
            text.contains("1 of the 4 lines checked is signed by another key, line 3 (byte"),
            "{text}"
        );
        // Under the other key, the agent's own lines are the other key's.
        let other = key_at(&dir.path().join("other-key")).verifying_key();
        assert!(matches!(
            verify_recent::<TestPayload, PortableHost>(&active, &other, 1 << 20),
            Err(RecentError::SignedByAnotherKey(l)) if l.count == 3 && l.checked == 4
        ));
    }

    /// In a window that starts inside the file, lines are placed by their
    /// byte offset in the file: the index in the window (`entry 0`) was not
    /// their place.
    #[test]
    fn a_window_inside_the_file_places_lines_by_byte_offset() {
        let dir = TempDir::new().unwrap();
        let kp = dir.path().join("key");
        let pk = key_at(&kp).verifying_key();
        let active = interleaved(dir.path(), &kp, 20, 2, 3);
        let at = line_offsets(&active);
        let len = fs::metadata(&active).unwrap().len();
        // The window starts in the middle of line 15: lines 16 to 25.
        let window = len - (at[14] + 10);
        let err = verify_recent::<TestPayload, PortableHost>(&active, &pk, window).unwrap_err();
        assert!(
            matches!(
                &err,
                RecentError::SignedByAnotherKey(l) if l.count == 2
                    && l.checked == 10
                    && l.first == LinePos { offset: at[20], line: None, ts: ts(20) }
                    && l.last == LinePos { offset: at[21], line: None, ts: ts(21) }
            ),
            "{err:?}"
        );
        let text = err.to_string();
        assert!(
            text.contains(&format!(
                "2 of the 10 lines checked are signed by another key, from the line at byte {} \
                 (ts 2026-05-30T00:00:20.000000Z) to the line at byte {} (ts \
                 2026-05-30T00:00:21.000000Z)",
                at[20], at[21]
            )),
            "{text}"
        );
        // The window without them verifies.
        let tail = len - at[22];
        assert!(verify_recent::<TestPayload, PortableHost>(&active, &pk, tail).is_ok());
    }

    /// The other classes keep their name and stop the check at the first
    /// line, placed: a line altered after it was written
    /// (`content_altered`), a line removed (`link_broken`). Lines another
    /// key signed before such a line are counted in its report.
    #[test]
    fn altered_and_removed_lines_keep_their_class_and_place() {
        let dir = TempDir::new().unwrap();
        let kp = dir.path().join("key");
        let pk = key_at(&kp).verifying_key();
        let active = dir.path().join("test.jsonl");
        let mut log = open_log(&active, &kp, 1 << 30);
        for i in 0..6 {
            log.append(payload(i)).unwrap();
        }
        drop(log);
        let pristine = fs::read(&active).unwrap();
        let at = line_offsets(&active);
        // altered: line 3's data, its hash and signature as they were
        rewrite_line(&active, 2, |l| {
            l.replace("record-number-2-", "record-number-X-")
        });
        let err = verify_recent::<TestPayload, PortableHost>(&active, &pk, 1 << 20).unwrap_err();
        assert_eq!(err.class(), "content_altered");
        assert!(
            matches!(
                &err,
                RecentError::Broken(b) if b.pos.line == Some(3)
                    && b.pos.offset == at[2]
                    && matches!(b.line_break, LineBreak::ContentAltered { .. })
                    && b.signed_by_another_key_before == 0
            ),
            "{err:?}"
        );
        assert!(
            err.to_string().contains(&format!(
                "line 3 (byte {}, ts 2026-05-30T00:00:02.000000Z): its entry_hash does not \
                 recompute",
                at[2]
            )),
            "{err}"
        );
        // removed: line 3 gone, the next one no longer links
        fs::write(&active, &pristine).unwrap();
        let mut lines = raw_lines(&active);
        lines.remove(2);
        fs::write(&active, lines.join("\n") + "\n").unwrap();
        let err = verify_recent::<TestPayload, PortableHost>(&active, &pk, 1 << 20).unwrap_err();
        assert_eq!(err.class(), "link_broken");
        assert!(
            matches!(
                &err,
                RecentError::Broken(b) if b.pos == LinePos { offset: at[2], line: Some(3), ts: ts(3) }
                    && matches!(b.line_break, LineBreak::LinkBroken { .. })
            ),
            "{err:?}"
        );
        assert!(
            err.to_string()
                .contains("a line was removed, inserted or moved"),
            "{err}"
        );
        // another key's lines, then an altered line of the agent's
        fs::write(&active, &pristine).unwrap();
        let mut other = open_log(&active, &dir.path().join("other-key"), 1 << 30);
        for i in 6..8 {
            other.append(payload(i)).unwrap();
        }
        drop(other);
        let mut log = open_log(&active, &kp, 1 << 30);
        log.append(payload(8)).unwrap();
        drop(log);
        rewrite_line(&active, 8, |l| {
            l.replace("record-number-8-", "record-number-Y-")
        });
        let err = verify_recent::<TestPayload, PortableHost>(&active, &pk, 1 << 20).unwrap_err();
        assert!(
            matches!(
                &err,
                RecentError::Broken(b) if b.pos.line == Some(9)
                    && matches!(b.line_break, LineBreak::ContentAltered { .. })
                    && b.signed_by_another_key_before == 2
            ),
            "{err:?}"
        );
        assert!(
            err.to_string().ends_with(
                "; before it, 2 lines of the window signed by another key (their hash and link \
                 intact)"
            ),
            "{err}"
        );
    }

    /// Only a plain timestamp of a line that failed is quoted.
    #[test]
    fn only_a_plain_timestamp_is_quoted() {
        let v = |ts: &str| serde_json::json!({ "ts": ts });
        assert_eq!(
            plain_ts(&v("2026-10-20T08:35:00.123456Z")).as_deref(),
            Some("2026-10-20T08:35:00.123456Z")
        );
        assert_eq!(
            plain_ts(&v("2026-10-20T08:35:00+02:00")).as_deref(),
            Some("2026-10-20T08:35:00+02:00")
        );
        for bad in ["x\nERROR forged", "", "2026-10-20 08:35", &"1".repeat(41)] {
            assert_eq!(plain_ts(&v(bad)), None, "{bad:?}");
        }
        assert_eq!(plain_ts(&serde_json::json!({ "ts": 5 })), None);
        assert_eq!(plain_ts(&serde_json::json!({})), None);
    }

    // ── External audit, Wave 3, lab PR 190 ─────────────────────────────

    /// EVD-017 (NN-AUD-280): an empty `<base>.000001` next to a valid
    /// active file, or an archive cut before its terminator, made
    /// `verify_log_set` hit `.expect("sealed archive ends in a terminator")`
    /// (an abort in a release build, so `nn-admin chain verify` reported no
    /// chain at all). It is a typed error naming the archive.
    #[test]
    fn an_archive_without_terminator_is_a_typed_error_not_a_panic() {
        let dir = TempDir::new().unwrap();
        let active = dir.path().join("test.jsonl");
        let k = key();
        let pk = k.verifying_key();
        let mut log = RotatingChainLog::<TestPayload, _>::open(
            &active,
            k,
            cfg(1 << 30, 50),
            std::sync::Arc::new(NoProtection),
        )
        .unwrap();
        for i in 0..3 {
            log.append(payload(i)).unwrap();
        }
        drop(log);
        verify_log_set::<TestPayload>(&active, &pk).expect("the active file alone verifies");
        let empty = archive_path(&active, 1);
        fs::File::create(&empty).unwrap();
        let err = verify_log_set::<TestPayload>(&active, &pk).unwrap_err();
        assert_eq!(
            err,
            LogSetError::ArchiveWithoutTerminator {
                file: empty.display().to_string(),
                seq: 1,
            }
        );
        assert!(err.to_string().contains("no terminator"), "{err}");

        // A real archive cut before its terminator: the data lines left
        // verify, the terminator is gone.
        let dir = TempDir::new().unwrap();
        let active = dir.path().join("test.jsonl");
        let k = key();
        let pk = k.verifying_key();
        let mut log = RotatingChainLog::<TestPayload, _>::open(
            &active,
            k,
            cfg(2000, 50),
            std::sync::Arc::new(NoProtection),
        )
        .unwrap();
        for i in 0..40 {
            log.append(payload(i)).unwrap();
        }
        drop(log);
        verify_log_set::<TestPayload>(&active, &pk).expect("the set verifies");
        let arch = archive_path(&active, 1);
        let body = fs::read_to_string(&arch).unwrap();
        let cut: String = body
            .lines()
            .filter(|l| !is_terminator_line(l))
            .map(|l| format!("{l}\n"))
            .collect();
        assert!(!cut.is_empty() && cut.len() < body.len());
        fs::write(&arch, cut).unwrap();
        assert!(matches!(
            verify_log_set::<TestPayload>(&active, &pk),
            Err(LogSetError::ArchiveWithoutTerminator { seq: 1, .. })
        ));
    }

    /// EVD-022 (NN-AUD-283): an archive name is the canonical spelling of
    /// its seq — six digits with leading zeros, or more digits without one.
    /// Exactly six digits were accepted, so from seq 1,000,000 on the
    /// archives were invisible to listing, eviction, verification and the
    /// read verbs.
    #[test]
    fn archive_names_past_seq_999999_are_listed_and_other_spellings_are_not() {
        let dir = TempDir::new().unwrap();
        let active = dir.path().join("log.jsonl");
        for name in [
            "log.jsonl.000999",
            "log.jsonl.1000000",
            "log.jsonl.00099",
            "log.jsonl.0123456",
            "log.jsonl.+00001",
            "log.jsonl.000998x",
            "log.jsonl.99999999999999999999999",
            "log.jsonl.18446744073709551615",
            "log.jsonl.manifest.jsonl",
            "other.jsonl.000997",
        ] {
            fs::write(dir.path().join(name), b"").unwrap();
        }
        assert_eq!(list_archive_seqs(&active).unwrap(), vec![999, 1_000_000]);
        assert_eq!(scan_max_archive_seq(&active).unwrap(), Some(1_000_000));
        assert_eq!(current_generation(&active), 1_000_001);
        assert_eq!(earliest_archive(&active), Some(999));
        assert_eq!(
            archive_path(&active, 1_000_000),
            dir.path().join("log.jsonl.1000000")
        );
        assert_eq!(
            archive_path(&active, 1_000_001),
            dir.path().join("log.jsonl.1000001")
        );
        assert_eq!(
            archives_newest_first(&active),
            vec![
                dir.path().join("log.jsonl.1000000"),
                dir.path().join("log.jsonl.000999")
            ]
        );
        // What the writer names, the lister reads back, up to 19 digits.
        for seq in [
            1,
            999_999,
            1_000_000,
            123_456_789,
            9_999_999_999_999_999_999,
        ] {
            let p = archive_path(&active, seq);
            assert_eq!(
                parse_archive_seq(&active, p.file_name().unwrap()),
                Some(seq)
            );
        }
    }

    /// EVD-022 (lab PR 190): with names past six digits listed, an archive
    /// named with a 19-digit seq must not make the verifier count up to it
    /// (the evicted-prefix check walked every seq below the earliest one):
    /// it answers at once, naming seq 1 as uncorroborated.
    #[test]
    fn a_huge_archive_seq_is_reported_at_once() {
        let dir = TempDir::new().unwrap();
        let active = dir.path().join("test.jsonl");
        let pk = key().verifying_key();
        fs::write(dir.path().join("test.jsonl.9000000000000000000"), b"").unwrap();
        let t = std::time::Instant::now();
        assert_eq!(
            verify_log_set::<TestPayload>(&active, &pk),
            Err(LogSetError::UncorroboratedEviction { seq: 1 })
        );
        assert!(t.elapsed() < std::time::Duration::from_secs(5));
        assert_eq!(current_generation(&active), 9_000_000_000_000_000_001);
    }

    /// EVD-017 (lab PR 190): the manifest checkpoints are reached by the
    /// offsets they name, without a list of every line's end (which grew
    /// with the file): checkpoints in archives and in the active file are
    /// all reached, and a cut below the last one is still found.
    #[test]
    fn checkpoints_are_reached_without_keeping_every_line_end() {
        let dir = TempDir::new().unwrap();
        let active = dir.path().join("test.jsonl");
        let kp = dir.path().join("key");
        let pk = key_at(&kp).verifying_key();
        let mut log = open_log(&active, &kp, 2000);
        for i in 0..40 {
            log.append(payload(i)).unwrap();
            if i % 7 == 3 {
                log.checkpoint().unwrap();
            }
        }
        let mut i = 40;
        while fs::read_to_string(&active).unwrap().lines().count() < 2 {
            log.append(payload(i)).unwrap();
            i += 1;
        }
        log.checkpoint().unwrap();
        drop(log);
        assert!(list_archive_seqs(&active).unwrap().len() >= 2);
        let r = verify_log_set::<TestPayload>(&active, &pk).unwrap();
        assert_eq!(r.checkpoints_verified, checkpoints(&active).len());
        assert!(r.checkpoints_verified >= 2, "{r:?}");
        // Cut the active file at a line boundary below its checkpoint.
        let body = fs::read_to_string(&active).unwrap();
        let first = body.lines().next().unwrap();
        fs::write(&active, format!("{first}\n")).unwrap();
        let err = verify_log_set::<TestPayload>(&active, &pk).unwrap_err();
        assert!(
            matches!(&err, LogSetError::CheckpointUnreachable { reason, .. } if reason.contains("cut")),
            "{err:?}"
        );
    }

    // ── External audit, Wave 3, lab PR 204: pre-image v3 ────────────────

    /// A payload of the same shape as [`TestPayload`] written to another
    /// log: the transplant target of the EVD-008 tests.
    #[derive(Debug, Clone, Serialize, Deserialize)]
    struct TwinPayload {
        ts: String,
        seq: u64,
        data: String,
    }

    impl ChainPayload for TwinPayload {
        const KIND: &'static str = "test_twin";
    }

    fn twin(i: u64) -> TwinPayload {
        let p = payload(i);
        TwinPayload {
            ts: p.ts,
            seq: p.seq,
            data: p.data,
        }
    }

    /// Every line of `path` (archives, active file or manifest), as on disk.
    fn raw_lines(path: &Path) -> Vec<String> {
        fs::read_to_string(path)
            .unwrap_or_default()
            .lines()
            .filter(|l| !l.is_empty())
            .map(str::to_string)
            .collect()
    }

    /// Every file of the set of `active`: archives ascending, the active
    /// file, the manifest.
    fn set_files(active: &Path) -> Vec<PathBuf> {
        let mut v: Vec<PathBuf> = list_archive_seqs(active)
            .unwrap()
            .into_iter()
            .map(|s| archive_path(active, s))
            .collect();
        v.push(active.to_path_buf());
        v.push(manifest_path_for(active));
        v
    }

    /// The version field of one raw line of any type.
    fn line_fmt_ver(raw: &str) -> Option<u64> {
        let v: serde_json::Value = serde_json::from_str(raw).unwrap();
        if let Some(r) = v.get("rotate") {
            r.get("fmt_ver").and_then(|f| f.as_u64())
        } else if let Some(m) = v.get("manifest") {
            m.get("fmt_ver").and_then(|f| f.as_u64())
        } else {
            v.get("fmt_ver").and_then(|f| f.as_u64())
        }
    }

    /// Replace line `n` (0-based, empty lines excluded) of `path`.
    fn rewrite_line(path: &Path, n: usize, f: impl Fn(&str) -> String) {
        let mut lines = raw_lines(path);
        lines[n] = f(&lines[n]);
        fs::write(path, lines.join("\n") + "\n").unwrap();
    }

    /// `"injected":"x"` before the closing brace of a JSON object line.
    fn inject_key(line: &str) -> String {
        format!("{},\"injected\":\"x\"}}", line.strip_suffix('}').unwrap())
    }

    /// EVD-007/EVD-008 (NN-AUD-273/274): every line type the writer
    /// produces — data lines, terminators, manifest rows (Rotated,
    /// Evicted, ActiveCheckpoint, TornTailRepaired) — is v3, and is its own
    /// canonical serialisation, byte for byte. On the starting code the
    /// lines were v2.
    #[test]
    fn every_line_the_writer_produces_is_v3_and_byte_canonical() {
        let dir = TempDir::new().unwrap();
        let active = dir.path().join("test.jsonl");
        let kp = dir.path().join("key");
        let pk = key_at(&kp).verifying_key();
        {
            let mut log =
                RotatingChainLog::<TestPayload, _>::open(&active, key_at(&kp), cfg(900, 3), {
                    std::sync::Arc::new(NoProtection)
                })
                .unwrap();
            for i in 0..60 {
                log.append(payload(i)).unwrap();
                if i % 9 == 0 {
                    log.checkpoint().unwrap();
                }
            }
        }
        // A torn last write: repaired and attested at the next open.
        append_raw(&active, b"{\"ts\":\"torn");
        drop(open_log(&active, &kp, 900));
        let events = manifest_events(&active);
        for want in [
            "rotated",
            "evicted",
            "active_checkpoint",
            "torn_tail_repaired",
        ] {
            assert!(
                events
                    .iter()
                    .any(|e| serde_json::to_value(e).unwrap()["kind"] == want),
                "{want} row written"
            );
        }
        let mut terminators = 0;
        for file in set_files(&active) {
            for raw in raw_lines(&file) {
                assert_eq!(line_fmt_ver(&raw), Some(3), "{}: {raw}", file.display());
                let canonical = if is_terminator_line(&raw) {
                    terminators += 1;
                    serde_json::to_string(&serde_json::from_str::<TerminatorLine>(&raw).unwrap())
                } else if raw.starts_with("{\"manifest\":") {
                    serde_json::to_string(&serde_json::from_str::<ManifestLine>(&raw).unwrap())
                } else {
                    serde_json::to_string(
                        &serde_json::from_str::<ChainLine<TestPayload>>(&raw).unwrap(),
                    )
                }
                .unwrap();
                assert_eq!(canonical, raw, "round trip of {}", file.display());
            }
        }
        assert!(terminators >= 3, "rotated: {terminators}");
        let r = verify_log_set::<TestPayload>(&active, &pk).unwrap();
        assert_eq!((r.legacy_lines, r.non_canonical_legacy), (0, 0));
        assert!(r.earliest_retained_seq > 1, "evicted: {r:?}");
    }

    /// EVD-007 (NN-AUD-273): a v3 line rewritten with a key the type does
    /// not have, its keys reordered, whitespace, or a value spelled with an
    /// escape decodes to the same line, so its hash and signature still
    /// verify; the bytes on disk are not what the agent wrote and the line
    /// is refused — by the full verifier, the boot check of the tail and the
    /// one-line check of the read verbs. On the starting code every one of
    /// these verified.
    #[test]
    fn a_v3_line_not_in_canonical_form_is_refused_everywhere() {
        let dir = TempDir::new().unwrap();
        let active = dir.path().join("test.jsonl");
        let kp = dir.path().join("key");
        let pk = key_at(&kp).verifying_key();
        {
            let mut log = open_log(&active, &kp, 1 << 30);
            for i in 0..4 {
                log.append(payload(i)).unwrap();
            }
        }
        let pristine = fs::read(&active).unwrap();
        let line1 = raw_lines(&active)[1].clone();
        assert!(line_is_genuine::<TestPayload>(line1.as_bytes(), &pk));
        let rewrites: Vec<(&str, String)> = vec![
            ("an injected key", inject_key(&line1)),
            (
                "keys reordered",
                line1
                    .replacen("{\"ts\":", "{\"seq\":1,\"ts\":", 1)
                    .replacen(",\"seq\":1,", ",", 1),
            ),
            ("whitespace", line1.replacen("\"seq\":", "\"seq\": ", 1)),
            (
                "an escaped spelling",
                line1.replacen("record-", "\\u0072ecord-", 1),
            ),
        ];
        for (what, forged) in rewrites {
            assert_ne!(forged, line1, "{what}");
            let decoded: ChainLine<TestPayload> = serde_json::from_str(&forged).unwrap();
            assert_eq!(decoded.payload.data, payload(1).data, "{what}: same row");
            assert!(
                !line_is_genuine::<TestPayload>(forged.as_bytes(), &pk),
                "{what}: one-line check"
            );
            fs::write(&active, &pristine).unwrap();
            rewrite_line(&active, 1, |_| forged.clone());
            let err = verify_log_set::<TestPayload>(&active, &pk).unwrap_err();
            assert_eq!(
                err,
                LogSetError::NonCanonicalLine {
                    file: active.display().to_string(),
                    idx: 1
                },
                "{what}"
            );
            assert!(
                matches!(
                    verify_recent::<TestPayload, PortableHost>(&active, &pk, 1 << 20),
                    Err(RecentError::Broken(b)) if b.line_break == LineBreak::NotCanonical
                        && b.pos.line == Some(2)
                        && b.signed_by_another_key_before == 0
                ),
                "{what}: boot check"
            );
        }
        // A terminator and a manifest row are held to the same rule.
        fs::write(&active, &pristine).unwrap();
        {
            let mut log = open_log(&active, &kp, 900);
            for i in 4..30 {
                log.append(payload(i)).unwrap();
            }
        }
        verify_log_set::<TestPayload>(&active, &pk).unwrap();
        let archive = archive_path(&active, 1);
        let n = raw_lines(&archive).len();
        rewrite_line(&archive, n - 1, inject_key);
        assert!(matches!(
            verify_log_set::<TestPayload>(&active, &pk),
            Err(LogSetError::NonCanonicalLine { idx, .. }) if idx == n - 1
        ));
        rewrite_line(&archive, n - 1, |l| l.replace(",\"injected\":\"x\"", ""));
        verify_log_set::<TestPayload>(&active, &pk).unwrap();
        let manifest = manifest_path_for(&active);
        let m0 = raw_lines(&manifest)[0].clone();
        assert!(manifest_line_is_genuine(
            m0.as_bytes(),
            TestPayload::KIND,
            &pk
        ));
        rewrite_line(&manifest, 0, inject_key);
        assert!(!manifest_line_is_genuine(
            inject_key(&m0).as_bytes(),
            TestPayload::KIND,
            &pk
        ));
        assert!(matches!(
            verify_log_set::<TestPayload>(&active, &pk),
            Err(LogSetError::NonCanonicalLine { idx: 0, .. })
        ));
    }

    /// EVD-007: a v1/v2 line keeps the check it was written under — a key
    /// added to it still verifies (its signature never covered the bytes),
    /// and is counted, not refused.
    #[test]
    fn a_legacy_line_not_in_canonical_form_verifies_and_is_counted() {
        let dir = TempDir::new().unwrap();
        let active = dir.path().join("test.jsonl");
        let kp = dir.path().join("key");
        let k = key_at(&kp);
        let pk = k.verifying_key();
        let mut prev = GENESIS_PREV_HASH.to_string();
        for i in 0..3 {
            prev = append_v1(&active, payload(i), &k, &prev);
        }
        let r = verify_log_set::<TestPayload>(&active, &pk).unwrap();
        assert_eq!((r.legacy_lines, r.non_canonical_legacy), (3, 0));
        rewrite_line(&active, 1, inject_key);
        let r = verify_log_set::<TestPayload>(&active, &pk).unwrap();
        assert_eq!(
            (r.total_records, r.legacy_lines, r.non_canonical_legacy),
            (3, 3, 1)
        );
        assert!(line_is_genuine::<TestPayload>(
            raw_lines(&active)[1].as_bytes(),
            &pk
        ));
    }

    /// EVD-008 (NN-AUD-274): the same agent key signs every rotating log.
    /// A line of one log moved into another whose payload has the same
    /// shape, at a position where `prev_hash` matches (the first line of
    /// both roots at GENESIS), no longer verifies; nor does one log's
    /// manifest put in place of another's. Two identical payloads hash
    /// differently in two logs. On the starting code the transplant
    /// verified.
    #[test]
    fn a_line_transplanted_between_logs_is_refused() {
        let dir = TempDir::new().unwrap();
        let kp = dir.path().join("key");
        let pk = key_at(&kp).verifying_key();
        let a = dir.path().join("a.jsonl");
        let b = dir.path().join("b.jsonl");
        {
            let mut la = open_log(&a, &kp, 1 << 30);
            let mut lb = RotatingChainLog::<TwinPayload, _>::open(
                &b,
                key_at(&kp),
                cfg(1 << 30, 50),
                std::sync::Arc::new(NoProtection),
            )
            .unwrap();
            for i in 0..3 {
                la.append(payload(i)).unwrap();
                lb.append(twin(i)).unwrap();
            }
            la.checkpoint().unwrap();
            lb.checkpoint().unwrap();
        }
        verify_log_set::<TestPayload>(&a, &pk).unwrap();
        verify_log_set::<TwinPayload>(&b, &pk).unwrap();
        let a0 = raw_lines(&a)[0].clone();
        let b0 = raw_lines(&b)[0].clone();
        // Same payload, same prev_hash, same key: two digests.
        assert_eq!(
            serde_json::from_str::<ChainLine<TestPayload>>(&a0)
                .unwrap()
                .prev_hash,
            serde_json::from_str::<ChainLine<TwinPayload>>(&b0)
                .unwrap()
                .prev_hash
        );
        assert_ne!(a0, b0, "the entry_hash differs");
        assert!(line_is_genuine::<TestPayload>(a0.as_bytes(), &pk));
        assert!(!line_is_genuine::<TwinPayload>(a0.as_bytes(), &pk));
        // a's first line put in place of b's first line (b's file only).
        let b_body = fs::read(&b).unwrap();
        fs::write(&b, format!("{a0}\n")).unwrap();
        fs::remove_file(manifest_path_for(&b)).unwrap();
        assert!(matches!(
            verify_log_set::<TwinPayload>(&b, &pk),
            Err(LogSetError::EntryHashMismatch { idx: 0, .. })
        ));
        // a's manifest in place of b's.
        fs::write(&b, &b_body).unwrap();
        fs::copy(manifest_path_for(&a), manifest_path_for(&b)).unwrap();
        let err = verify_log_set::<TwinPayload>(&b, &pk).unwrap_err();
        assert!(
            matches!(&err, LogSetError::EntryHashMismatch { file, idx: 0, .. }
                if file.ends_with(".manifest.jsonl")),
            "{err:?}"
        );
        assert!(manifest_tail_events::<PortableHost>(&b, TwinPayload::KIND, &pk).is_empty());
        assert!(!manifest_tail_events::<PortableHost>(&b, TestPayload::KIND, &pk).is_empty());
    }

    /// EVD-008: the three line types are signed under three domains, per
    /// log; a kind outside `[a-z0-9_]{3,32}` has none.
    #[test]
    fn each_log_and_line_type_has_its_own_domain() {
        let mut seen = std::collections::HashSet::new();
        for kind in ["detections", "status_events", "netflow", "fim_drift"] {
            for role in [LineRole::Data, LineRole::Terminator, LineRole::Manifest] {
                let d = chain_domain(kind, role).unwrap();
                assert!(d.len() > 32 && d.ends_with(b"/v3\0"), "{d:?}");
                assert!(seen.insert(d), "{kind}/{role:?} unique");
            }
        }
        assert_eq!(
            chain_domain("detections", LineRole::Data).unwrap(),
            b"northnarrow/chainlog/detections/data/v3\0"
        );
        for bad in [
            "",
            "ab",
            "Detections",
            "a/b",
            "x".repeat(33).as_str(),
            "fim-drift",
        ] {
            assert!(chain_domain(bad, LineRole::Data).is_err(), "{bad:?}");
        }
    }

    /// EVD-008: once a set holds a v3 line, a later v2 line — even one the
    /// agent's key signed and that links — is refused, by the full verifier
    /// and the boot check. On the starting code it verified.
    #[test]
    fn an_old_format_line_after_v3_lines_is_refused() {
        let dir = TempDir::new().unwrap();
        let active = dir.path().join("test.jsonl");
        let kp = dir.path().join("key");
        let pk = key_at(&kp).verifying_key();
        let tail = {
            let mut log = open_log(&active, &kp, 1 << 30);
            for i in 0..3 {
                log.append(payload(i)).unwrap();
            }
            log.last_hash().to_string()
        };
        let v2 =
            ChainLine::sealed_as(payload(3), Some(CHAINLOG_FMT_V2), &key_at(&kp), &tail).unwrap();
        append_raw(&active, to_jsonl(&v2).unwrap().as_bytes());
        assert!(line_is_genuine::<TestPayload>(
            to_jsonl(&v2).unwrap().trim_end().as_bytes(),
            &pk
        ));
        let err = verify_log_set::<TestPayload>(&active, &pk).unwrap_err();
        assert!(
            matches!(err, LogSetError::LegacyAfterV3 { idx: 3, .. }),
            "{err:?}"
        );
        assert!(matches!(
            verify_recent::<TestPayload, PortableHost>(&active, &pk, 1 << 20),
            Err(RecentError::Broken(b))
                if b.line_break == LineBreak::LegacyAfterV3 && b.pos.line == Some(4)
        ));
    }

    /// A version this reader does not know is refused as such, not hashed
    /// as an old line.
    #[test]
    fn an_unknown_format_version_is_named() {
        let dir = TempDir::new().unwrap();
        let active = dir.path().join("test.jsonl");
        let kp = dir.path().join("key");
        let pk = key_at(&kp).verifying_key();
        drop(open_log(&active, &kp, 1 << 30));
        let line = ChainLine {
            payload: payload(0),
            fmt_ver: Some(4),
            prev_hash: GENESIS_PREV_HASH.to_string(),
            entry_hash: "00".repeat(32),
            agent_sig: B64.encode([0u8; 64]),
        };
        fs::write(&active, to_jsonl(&line).unwrap()).unwrap();
        let err = verify_log_set::<TestPayload>(&active, &pk).unwrap_err();
        assert!(
            matches!(&err, LogSetError::Malformed { reason, .. } if reason.contains("fmt_ver 4")),
            "{err:?}"
        );
        assert!(seal_line(line.clone(), &key_at(&kp), TestPayload::KIND).is_err());
    }

    /// EVD-023 (NN-AUD-427): a pre-image that still carries its
    /// `entry_hash` or `agent_sig` is refused in every build (the invariant
    /// was a `debug_assert!`: a release build hashed it).
    #[test]
    fn a_pre_image_that_carries_its_seal_is_refused() {
        let k = key();
        let line = ChainLine::sealed(payload(0), &k, GENESIS_PREV_HASH).unwrap();
        let err = chain_digest(&line, TestPayload::KIND).unwrap_err();
        assert!(err.to_string().contains("carries its own"), "{err}");
        let mut half = line.clone();
        half.entry_hash.clear();
        assert!(chain_digest(&half, TestPayload::KIND).is_err());
        assert!(seal_line(line, &k, TestPayload::KIND).is_err());
    }

    /// Fixed key for the frozen vectors.
    fn frozen_key(dir: &Path) -> TestKey {
        let p = dir.join("frozen.key");
        fs::write(&p, format!("{}\n", "42".repeat(32))).unwrap();
        TestKey::load_or_bootstrap(&p).unwrap()
    }

    const FROZEN_ROW: &str =
        "{\"ts\":\"2026-10-09T00:00:00.000000Z\",\"seq\":7,\"data\":\"caf\u{e9} \\\"q\\\" \\\\ \\n\"";

    /// Frozen vectors. A v2 line built by hand, as the 0.0.1 writer did
    /// (`SHA-256(prev ‖ json)`, untagged), verifies byte for byte; a v3
    /// line's `entry_hash` is pinned (domain, layout and canonical bytes of
    /// the format). Both hashes were computed independently (Python
    /// `hashlib`) from the bytes below.
    #[test]
    fn frozen_v2_and_v3_vectors() {
        let dir = TempDir::new().unwrap();
        let k = frozen_key(dir.path());
        let pk = k.verifying_key();
        let prev = GENESIS_PREV_HASH;
        let sign = |pre: &[u8]| -> (String, String) {
            let d: [u8; 32] = Sha256::digest(pre).into();
            (hex::encode(d), B64.encode(k.sign(&d).to_bytes()))
        };
        let prev_bytes = hex::decode(prev).unwrap();
        // v2, by hand.
        let body = format!(
            "{FROZEN_ROW},\"fmt_ver\":2,\"prev_hash\":\"{prev}\",\"entry_hash\":\"\",\"agent_sig\":\"\"}}"
        );
        let (h2, s2) = sign(&[prev_bytes.as_slice(), body.as_bytes()].concat());
        assert_eq!(h2, FROZEN_V2_HASH);
        let v2 = format!(
            "{FROZEN_ROW},\"fmt_ver\":2,\"prev_hash\":\"{prev}\",\"entry_hash\":\"{h2}\",\"agent_sig\":\"{s2}\"}}"
        );
        let active = dir.path().join("frozen.jsonl");
        fs::write(&active, format!("{v2}\n")).unwrap();
        let r = verify_log_set::<TestPayload>(&active, &pk).unwrap();
        assert_eq!((r.total_records, r.legacy_lines), (1, 1));
        // v3, by hand: the domain of `test_payload` data lines.
        let body3 = format!(
            "{FROZEN_ROW},\"fmt_ver\":3,\"prev_hash\":\"{prev}\",\"entry_hash\":\"\",\"agent_sig\":\"\"}}"
        );
        let (h3, s3) = sign(
            &[
                b"northnarrow/chainlog/test_payload/data/v3\0".as_slice(),
                prev_bytes.as_slice(),
                body3.as_bytes(),
            ]
            .concat(),
        );
        assert_eq!(h3, FROZEN_V3_HASH);
        let v3 = format!(
            "{FROZEN_ROW},\"fmt_ver\":3,\"prev_hash\":\"{prev}\",\"entry_hash\":\"{h3}\",\"agent_sig\":\"{s3}\"}}"
        );
        let decoded: ChainLine<TestPayload> = serde_json::from_str(&v3).unwrap();
        let written = ChainLine::sealed(decoded.payload, &k, prev).unwrap();
        assert_eq!(
            to_jsonl(&written).unwrap(),
            format!("{v3}\n"),
            "the writer's bytes"
        );
        fs::write(&active, format!("{v3}\n")).unwrap();
        let r = verify_log_set::<TestPayload>(&active, &pk).unwrap();
        assert_eq!((r.total_records, r.legacy_lines), (1, 0));
        // The v2 line's signature does not make a v3 line (nor the reverse).
        let swapped = v2.replace("\"fmt_ver\":2", "\"fmt_ver\":3");
        assert!(!line_is_genuine::<TestPayload>(swapped.as_bytes(), &pk));
        let swapped = v3.replace("\"fmt_ver\":3", "\"fmt_ver\":2");
        assert!(!line_is_genuine::<TestPayload>(swapped.as_bytes(), &pk));
    }

    const FROZEN_V2_HASH: &str = "0435d58b4dd033a649fe3776d97df54399435a6a235b072b787e5d6ca8772dc0";
    const FROZEN_V3_HASH: &str = "84a1b49dca9cd4ef0622ccb78a9f5e62ac694524b20973471b89ceb9f0342bed";

    /// EVD-007/EVD-008, the upgrade: a set written by 0.0.1 (v2 data lines,
    /// a v2 terminator, a v2 manifest row — built here as that writer built
    /// them) is opened by this version and written on. The old lines keep
    /// their bytes and verify with their pre-image; every line written
    /// after them is v3; the set verifies end to end across the boundary.
    #[test]
    fn a_0_0_1_set_upgraded_keeps_its_lines_and_continues_in_v3() {
        let dir = TempDir::new().unwrap();
        let active = dir.path().join("test.jsonl");
        let kp = dir.path().join("key");
        let k = key_at(&kp);
        let pk = k.verifying_key();
        let kind = TestPayload::KIND;
        // 0.0.1: archive 1 (3 data lines + terminator), its Rotated row,
        // an active file of 2 lines chained off the terminator.
        let archive1 = archive_path(&active, 1);
        let mut prev = GENESIS_PREV_HASH.to_string();
        let mut bytes = 0u64;
        for i in 0..3 {
            let l = ChainLine::sealed_as(payload(i), Some(CHAINLOG_FMT_V2), &k, &prev).unwrap();
            let s = to_jsonl(&l).unwrap();
            bytes += s.len() as u64;
            append_and_fsync::<PortableHost>(&archive1, &s, 0o600).unwrap();
            prev = l.entry_hash;
        }
        let rotate = RotateTerminator {
            fmt_ver: CHAINLOG_FMT_V2,
            this_seq: 1,
            next_seq: 2,
            record_count: 3,
            bytes,
        };
        let term = TerminatorLine::sealed(rotate, &k, &prev, kind, &SystemClock).unwrap();
        append_and_fsync::<PortableHost>(&archive1, &to_jsonl(&term).unwrap(), 0o600).unwrap();
        let rotated = ManifestEntry {
            fmt_ver: CHAINLOG_FMT_V2,
            ts: stamp(&SystemClock),
            event: ManifestEvent::Rotated {
                seq: 1,
                terminator_hash: term.entry_hash.clone(),
                bytes,
                records: 3,
            },
        };
        let m = ManifestLine::sealed(rotated, &k, GENESIS_PREV_HASH, kind).unwrap();
        append_and_fsync::<PortableHost>(
            &manifest_path_for(&active),
            &to_jsonl(&m).unwrap(),
            0o600,
        )
        .unwrap();
        let mut prev = term.entry_hash.clone();
        for i in 3..5 {
            let l = ChainLine::sealed_as(payload(i), Some(CHAINLOG_FMT_V2), &k, &prev).unwrap();
            append_and_fsync::<PortableHost>(&active, &to_jsonl(&l).unwrap(), 0o600).unwrap();
            prev = l.entry_hash;
        }
        let r = verify_log_set::<TestPayload>(&active, &pk).unwrap();
        assert_eq!((r.total_records, r.legacy_lines), (5, 7));
        let old: Vec<(PathBuf, Vec<u8>)> = set_files(&active)
            .into_iter()
            .map(|f| {
                let b = fs::read(&f).unwrap();
                (f, b)
            })
            .collect();
        // This version opens it and writes on, rotating twice.
        {
            let mut log = open_log(&active, &kp, 1500);
            for i in 5..30 {
                log.append(payload(i)).unwrap();
            }
            log.checkpoint().unwrap();
        }
        assert!(list_archive_seqs(&active).unwrap().len() >= 3, "rotated");
        // The old bytes are where they were: archive 1 and the manifest
        // unchanged up to their old end, the old active file the head of
        // archive 2.
        for (f, b) in &old {
            let now = if *f == active {
                fs::read(archive_path(&active, 2)).unwrap()
            } else {
                fs::read(f).unwrap()
            };
            assert!(now.starts_with(b), "{} keeps its old lines", f.display());
            let tail = String::from_utf8(now[b.len()..].to_vec()).unwrap();
            for raw in tail.lines().filter(|l| !l.is_empty()) {
                assert_eq!(
                    line_fmt_ver(raw),
                    Some(3),
                    "new line in {}: {raw}",
                    f.display()
                );
            }
        }
        for raw in raw_lines(&active) {
            assert_eq!(line_fmt_ver(&raw), Some(3));
        }
        let r = verify_log_set::<TestPayload>(&active, &pk).unwrap();
        assert_eq!(
            (r.total_records, r.legacy_lines, r.non_canonical_legacy),
            (30, 7, 0)
        );
    }

    /// Lab PR 249: one writing of a rotating set with a fixed key and a
    /// clock that moves 250 ms before each append: three rotations (each a
    /// terminator and a manifest `Rotated` row), then a checkpoint. Every
    /// file of the set, by name, with its bytes.
    fn write_rotating_set(dir: &Path) -> Vec<(String, Vec<u8>)> {
        let kp = dir.join("fixed.key");
        fs::write(
            &kp,
            "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60\n",
        )
        .unwrap();
        let clock = std::sync::Arc::new(crate::clock::testing::FixedClock::at(
            "2026-01-01T00:00:05.000001Z",
        ));
        let active = dir.join("set.jsonl");
        let mut log = RotatingChainLog::<TestPayload, _>::open_with_clock(
            &active,
            TestKey::load_or_bootstrap(&kp).unwrap(),
            cfg(1600, 8),
            std::sync::Arc::new(NoProtection),
            clock.clone(),
        )
        .unwrap();
        for i in 0..12 {
            clock.advance(chrono::TimeDelta::milliseconds(250));
            log.append(payload(i)).unwrap();
        }
        clock.advance(chrono::TimeDelta::seconds(1));
        log.checkpoint().unwrap();
        drop(log);
        let mut files: Vec<(String, Vec<u8>)> = fs::read_dir(dir)
            .unwrap()
            .map(|e| e.unwrap().path())
            .filter(|p| {
                p.file_name()
                    .unwrap()
                    .to_str()
                    .unwrap()
                    .starts_with("set.jsonl")
            })
            .map(|p| {
                (
                    p.file_name().unwrap().to_str().unwrap().to_string(),
                    fs::read(&p).unwrap(),
                )
            })
            .collect();
        files.sort();
        files
    }

    /// Lab PR 249: the rows a rotating log stamps — its terminators and its
    /// manifest rows — carry its clock's time: with a fixed key and a clock
    /// of the caller's, the set written twice is the same bytes, every file,
    /// and verifies.
    #[test]
    fn a_fixed_clock_and_key_write_the_same_rotating_set_twice() {
        let (a, b) = (TempDir::new().unwrap(), TempDir::new().unwrap());
        let first = write_rotating_set(a.path());
        let second = write_rotating_set(b.path());
        let names: Vec<&str> = first.iter().map(|(n, _)| n.as_str()).collect();
        let archives = names.len() - 2;
        assert!(archives >= 2, "{names:?}");
        let mut want = vec!["set.jsonl".to_string()];
        want.extend((1..=archives).map(|n| format!("set.jsonl.{n:06}")));
        want.push("set.jsonl.manifest.jsonl".to_string());
        assert_eq!(names, want);
        assert_eq!(first, second);
        let pk = TestKey::load_or_bootstrap(&a.path().join("fixed.key"))
            .unwrap()
            .verifying_key();
        let r = verify_log_set::<TestPayload>(&a.path().join("set.jsonl"), &pk).unwrap();
        assert_eq!((r.archives_verified, r.total_records), (archives, 12));
        // The stamps are the clock's: terminators and manifest rows in the
        // order they were written, the checkpoint a second after the last.
        let ts_of = |line: &str| -> String {
            let v: serde_json::Value = serde_json::from_str(line).unwrap();
            v.get("ts")
                .or_else(|| v["manifest"].get("ts"))
                .and_then(|t| t.as_str())
                .unwrap()
                .to_string()
        };
        let text = |name: &str| {
            String::from_utf8(first.iter().find(|(n, _)| n == name).unwrap().1.clone()).unwrap()
        };
        let mut stamps = Vec::new();
        for seq in 1..=archives {
            let archive = text(&format!("set.jsonl.{seq:06}"));
            stamps.push(ts_of(archive.lines().last().unwrap()));
        }
        let manifest: Vec<String> = text("set.jsonl.manifest.jsonl")
            .lines()
            .map(ts_of)
            .collect();
        assert_eq!(
            manifest.len(),
            archives + 1,
            "the rotations and a checkpoint"
        );
        for (t, m) in stamps.iter().zip(&manifest) {
            assert_eq!(t, m, "a rotation's terminator and its manifest row");
            assert!(t.starts_with("2026-01-01T00:00:0"), "{t}");
            assert!(t.ends_with("0001Z"), "{t}");
        }
        assert!(stamps.windows(2).all(|w| w[0] < w[1]), "{stamps:?}");
        assert_eq!(manifest[archives], "2026-01-01T00:00:09.000001Z");
    }

    /// Lab PR 249: `open` stamps with the host's clock, as before.
    #[test]
    fn open_stamps_with_the_host_clock() {
        let dir = TempDir::new().unwrap();
        let active = dir.path().join("host.jsonl");
        let before = crate::audit::format_ts(chrono::Utc::now());
        let mut log = RotatingChainLog::<TestPayload, _>::open(
            &active,
            key(),
            cfg(1600, 8),
            std::sync::Arc::new(NoProtection),
        )
        .unwrap();
        for i in 0..6 {
            log.append(payload(i)).unwrap();
        }
        log.checkpoint().unwrap();
        drop(log);
        let after = crate::audit::format_ts(chrono::Utc::now());
        let manifest = fs::read_to_string(manifest_path_for(&active)).unwrap();
        let mut n = 0;
        for line in manifest.lines() {
            let v: serde_json::Value = serde_json::from_str(line).unwrap();
            let ts = v["manifest"]["ts"].as_str().unwrap();
            assert!(
                before.as_str() <= ts && ts <= after.as_str(),
                "{before} {ts} {after}"
            );
            n += 1;
        }
        assert!(n >= 2, "a rotation and a checkpoint: {manifest}");
    }
}
