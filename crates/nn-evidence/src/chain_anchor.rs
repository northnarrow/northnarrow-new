//! Completeness of the signed chains: row numbers, file heads and the head
//! anchor (external audit NN-AUD-108, NN-AUD-109, NN-AUD-112, NN-AUD-174;
//! lab PR 160).
//!
//! A hash chain proves that the rows it holds were not changed. It cannot
//! prove that none were cut from its end, that a file was not emptied or
//! deleted, or that rows were not removed from a chain nobody re-reads.
//! This module holds the one design shared by every chain for that:
//!
//! - **Row numbers** on the flat chains (`audit.log`, `canaries.jsonl`,
//!   `canary_access.jsonl`): a row written by this version carries `seq`,
//!   its 0-based position in the file ([`RowSeq`]). Rows written before
//!   carry none and verify exactly as before; numbering starts at the
//!   number of rows already there, so the first numbered row also proves
//!   that no older row was removed. Once a numbered row exists, every later
//!   row must be numbered.
//! - **Domain separation**: a numbered row's `entry_hash` is
//!   `SHA-256(domain ‖ prev_hash ‖ row)`, with one domain per chain
//!   ([`AUDIT_DOMAIN_V2`], [`CANARY_REGISTRY_DOMAIN_V2`],
//!   [`CANARY_ACCESS_DOMAIN_V2`]); the same agent key signs them all, and a
//!   signature made for one chain no longer verifies in another. Rows
//!   without `seq` keep the untagged pre-image.
//! - **File heads** ([`FileHead`]): the byte length up to the end of the
//!   last complete, genuine line of an append-only chain file and that
//!   line's `entry_hash`. A head is checked in O(1) ([`check_head`]): the
//!   file must still be at least that long and the line ending there must
//!   carry that hash. The rotating logs also anchor their active file in
//!   their own manifest ([`crate::chainlog::ManifestEvent::ActiveCheckpoint`]).
//! - **The head anchor** (`chain_heads.json` next to `audit.log`,
//!   [`HeadsStore`]): a signed
//!   snapshot of every chain's head, written when the agent starts, every
//!   [`ANCHOR_SECS`] when a head moved, and when it stops. It is two
//!   fixed-size slots written in turn, so a write cut short leaves the
//!   previous snapshot readable and the file never grows. The anchor also
//!   carries the sticky facts read from the audit chain that a cut would
//!   otherwise erase (a second admin key added, external audit ATP-004).
//! - **The boot check** ([`boot_check`]): before any writer opens, every
//!   head of the last snapshot and the newest checkpoint of every rotating
//!   log are checked against the files. A chain shorter than its anchored
//!   head, rewritten under it, deleted, or a rotating log missing its
//!   active file or archives is a signed `integrity_drift` at this boot
//!   ([`ChainFinding`]).
//!
//! Every head is also written to the journal (`chain.head` target) when it
//! is anchored, for an operator who forwards the journal off the host and
//! checks it later with `nn-admin audit verify --expect-head`.
//!
//! Residual (documented in the runbook): an attacker who can write these
//! files can also put back an older, genuine snapshot together with
//! chains cut back to it, or roll every file back to before this version
//! numbered anything. On the host that cannot be told from the real past;
//! the journal heads forwarded off the host can.

use std::fs::OpenOptions;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{anyhow, Context, Result};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tracing::{error, info, warn};

use crate::audit::{AuditEntryDraft, AuditLog};
use crate::chain_host::{ChainHost, ChainSigner};

/// Pre-image prefix of a numbered `audit.log` row.
pub const AUDIT_DOMAIN_V2: &[u8] = b"northnarrow/audit/v2\0";
/// Pre-image prefix of a numbered `canaries.jsonl` row.
pub const CANARY_REGISTRY_DOMAIN_V2: &[u8] = b"northnarrow/canary-registry/v2\0";
/// Pre-image prefix of a numbered `canary_access.jsonl` row.
pub const CANARY_ACCESS_DOMAIN_V2: &[u8] = b"northnarrow/canary-access/v2\0";
/// Prefix of the digest a heads snapshot is signed over.
const HEADS_DOMAIN: &[u8] = b"northnarrow/chain-heads/v1\0";

/// Default location of the head anchor: next to the audit log it anchors
/// (a test agent with its own audit log gets its own anchor).
pub const DEFAULT_HEADS_PATH: &str = "/etc/northnarrow/chain_heads.json";
/// File name of the head anchor (next to the audit log).
pub const HEADS_FILE_NAME: &str = "chain_heads.json";
/// Mode of the head anchor when it is created: the audit log's
/// ([`crate::audit::AUDIT_LOG_FILE_MODE`], external audit EVD-019): it
/// tells when and how far every chain moved, and the same readers check
/// it.
pub const HEADS_FILE_MODE: u32 = crate::audit::AUDIT_LOG_FILE_MODE;

/// How often the running agent re-reads the heads and anchors the ones
/// that moved.
pub const ANCHOR_SECS: u64 = 300;

/// Audit op of the one-time record of where numbering starts.
pub const NUMBERING_STARTED_OP: &str = "chain_numbering_started";

/// Largest window read backwards from a head looking for its line.
const HEAD_WINDOW: u64 = 64 * 1024;
const HEAD_WINDOW_MAX: u64 = 8 * 1024 * 1024;

/// One slot of the heads file. Two slots, written in turn.
const SLOT_BYTES: u64 = 8192;

/// Chain-shaped lines checked from the end before a file is said to have
/// no genuine head (bounds the signature work on a tail of forged lines).
const MAX_HEAD_PROBES: usize = 64;

// ── row numbers ─────────────────────────────────────────────────────

/// What is wrong with a row's `seq`.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SeqBreak {
    #[error("row {row} carries seq {seq}: rows before it were removed or inserted")]
    Mismatch { row: u64, seq: u64 },
    #[error("row {row} carries no seq after numbered rows: a row in the old format was inserted")]
    Missing { row: u64 },
}

/// Row-number bookkeeping for a flat chain, fed one row at a time in file
/// order (empty lines excluded).
#[derive(Debug, Clone, Default)]
pub struct RowSeq {
    rows: u64,
    numbered: bool,
}

impl RowSeq {
    /// The next row (at position [`Self::rows`]) carries `seq`.
    pub fn push(&mut self, seq: Option<u64>) -> Result<(), SeqBreak> {
        let row = self.rows;
        self.rows += 1;
        match seq {
            Some(seq) => {
                self.numbered = true;
                if seq == row {
                    Ok(())
                } else {
                    Err(SeqBreak::Mismatch { row, seq })
                }
            }
            None if self.numbered => Err(SeqBreak::Missing { row }),
            None => Ok(()),
        }
    }

    /// A line that cannot be read still takes a position.
    pub fn skip(&mut self) {
        self.rows += 1;
    }

    /// Rows seen: the `seq` the next row is written with.
    pub fn rows(&self) -> u64 {
        self.rows
    }

    /// A numbered row was seen.
    pub fn numbered(&self) -> bool {
        self.numbered
    }
}

/// `SHA-256(domain? ‖ prev_hash ‖ body)`: the pre-image of a flat-chain
/// row; `domain` is set for numbered rows only.
pub fn flat_digest(domain: Option<&[u8]>, prev_hash: &str, body: &[u8]) -> Result<[u8; 32]> {
    let prev = hex::decode(prev_hash).map_err(|e| anyhow!("prev_hash is not valid hex: {e}"))?;
    let mut h = Sha256::new();
    if let Some(d) = domain {
        h.update(d);
    }
    h.update(&prev);
    h.update(body);
    Ok(h.finalize().into())
}

/// External audit EVD-023 (NN-AUD-427, lab PR 204): a pre-image is the row
/// with its `entry_hash` and `agent_sig` empty. A row that still carries
/// either is refused in every build (it was a `debug_assert!`): its digest
/// is one no verifier reproduces.
pub fn check_unsealed(entry_hash: &str, agent_sig: &str) -> Result<()> {
    if entry_hash.is_empty() && agent_sig.is_empty() {
        Ok(())
    } else {
        Err(anyhow!(
            "chain pre-image carries its own entry_hash or agent_sig: refused"
        ))
    }
}

/// External audit EVD-007 (NN-AUD-273, lab PR 204): whether `raw`, one line
/// as it is on disk (without its newline), is the serialisation of `row`,
/// the value decoded from it. The hash covers the decoded row only: a key
/// the type does not have, another key order, whitespace or another
/// spelling of a value decode to the same row and verify. Numbered rows
/// (`seq`) and v3 rotating-log lines must be canonical; older rows are
/// counted when they are not.
pub fn is_canonical<T: Serialize>(row: &T, raw: &[u8]) -> bool {
    serde_json::to_vec(row).is_ok_and(|b| b == raw)
}

/// `entry_hash` shape every chain writes: 64 lowercase hex characters.
pub fn is_chain_hash(h: &str) -> bool {
    h.len() == 64
        && h.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// Check `sig_b64` over `digest` with `pk`, strictly (external audit
/// NN-AUD-292, FIMP-013: a small-order key or `R` is refused).
pub fn signature_ok(digest: &[u8; 32], sig_b64: &str, pk: &VerifyingKey) -> bool {
    B64.decode(sig_b64)
        .ok()
        .and_then(|b| <[u8; 64]>::try_from(b.as_slice()).ok())
        .is_some_and(|b| pk.verify_strict(digest, &Signature::from_bytes(&b)).is_ok())
}

// ── file heads ──────────────────────────────────────────────────────

/// The head of an append-only chain file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileHead {
    /// Offset just past the head line's newline.
    pub bytes: u64,
    /// The head line's `entry_hash`.
    pub tail_hash: String,
    /// The head line's `seq`, when it carries one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub seq: Option<u64>,
}

/// Whether one raw line is a genuine row of its chain (decodes, its hash
/// recomputes, its signature verifies).
pub type LineCheck = fn(&[u8], &VerifyingKey) -> bool;

/// The head of `path`: its newest complete line that `genuine` accepts,
/// looked for in a bounded window from the end. `None` when the file is
/// missing, empty, or holds no such line in the window.
pub fn read_file_head<H: ChainHost>(
    path: &Path,
    genuine: &dyn Fn(&[u8]) -> bool,
) -> std::io::Result<Option<FileHead>> {
    let mut f = match H::open_read_nofollow(path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e),
    };
    let size = f.metadata()?.len();
    if size == 0 {
        return Ok(None);
    }
    let mut window = HEAD_WINDOW.min(size);
    loop {
        let start = size - window;
        let mut buf = vec![0u8; window as usize];
        f.seek(SeekFrom::Start(start))?;
        f.read_exact(&mut buf)?;
        let mut probes = 0usize;
        // Complete lines only: a trailing fragment without '\n' is skipped.
        let nls: Vec<usize> = buf
            .iter()
            .enumerate()
            .filter_map(|(i, &c)| (c == b'\n').then_some(i))
            .collect();
        for k in (0..nls.len()).rev() {
            let line_start = if k == 0 {
                if start != 0 {
                    break; // head of this line is outside the window
                }
                0
            } else {
                nls[k - 1] + 1
            };
            let line = &buf[line_start..nls[k]];
            if line.is_empty() {
                continue;
            }
            let Some((hash, seq)) = hash_and_seq(line) else {
                continue;
            };
            probes += 1;
            if probes > MAX_HEAD_PROBES {
                return Ok(None);
            }
            if genuine(line) {
                return Ok(Some(FileHead {
                    bytes: start + nls[k] as u64 + 1,
                    tail_hash: hash,
                    seq,
                }));
            }
        }
        if start == 0 || window >= HEAD_WINDOW_MAX {
            return Ok(None);
        }
        window = window.saturating_mul(4).min(size);
    }
}

/// `entry_hash` (chain-shaped) and `seq` of a raw line.
fn hash_and_seq(line: &[u8]) -> Option<(String, Option<u64>)> {
    let v: serde_json::Value = serde_json::from_slice(line).ok()?;
    let h = v.get("entry_hash")?.as_str()?;
    if !is_chain_hash(h) {
        return None;
    }
    Some((h.to_string(), v.get("seq").and_then(|s| s.as_u64())))
}

/// How a file compares with a head anchored earlier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HeadCheck {
    /// The anchored line is still there, at the same offset.
    Intact,
    /// The file is gone.
    Missing,
    /// The file ends before the anchored line does.
    Shorter { len: u64 },
    /// The file is long enough, but no line with the anchored hash ends
    /// at the anchored offset.
    Changed,
}

/// Compare `path` with `head` in O(window).
pub fn check_head<H: ChainHost>(path: &Path, head: &FileHead) -> std::io::Result<HeadCheck> {
    let mut f = match H::open_read_nofollow(path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(HeadCheck::Missing),
        // A symlink put where the chain file was is not the chain.
        Err(e) if H::is_symlink_refusal(&e) => return Ok(HeadCheck::Changed),
        Err(e) => return Err(e),
    };
    let meta = f.metadata()?;
    if !meta.is_file() {
        return Ok(HeadCheck::Changed);
    }
    let len = meta.len();
    if head.bytes == 0 {
        return Ok(HeadCheck::Intact);
    }
    if len < head.bytes {
        return Ok(HeadCheck::Shorter { len });
    }
    let end = head.bytes;
    let mut window = HEAD_WINDOW.min(end);
    loop {
        let start = end - window;
        let mut buf = vec![0u8; window as usize];
        f.seek(SeekFrom::Start(start))?;
        f.read_exact(&mut buf)?;
        if buf.last() != Some(&b'\n') {
            return Ok(HeadCheck::Changed);
        }
        let body = &buf[..buf.len() - 1];
        if let Some(nl) = body.iter().rposition(|&c| c == b'\n') {
            return Ok(line_has_hash(&body[nl + 1..], &head.tail_hash));
        }
        if start == 0 {
            return Ok(line_has_hash(body, &head.tail_hash));
        }
        if window >= HEAD_WINDOW_MAX {
            return Ok(HeadCheck::Changed);
        }
        window = window.saturating_mul(4).min(end);
    }
}

fn line_has_hash(line: &[u8], want: &str) -> HeadCheck {
    match hash_and_seq(line) {
        Some((h, _)) if h == want => HeadCheck::Intact,
        _ => HeadCheck::Changed,
    }
}

// ── chains the agent anchors ────────────────────────────────────────

/// How a chain is laid out on disk.
#[derive(Clone, Copy)]
pub enum ChainKind {
    /// One append-only file.
    Flat,
    /// A [`crate::chainlog::RotatingChainLog`]: active file, archives,
    /// manifest.
    Rotating,
}

/// One chain the agent anchors.
#[derive(Clone)]
pub struct ChainTarget {
    /// Stable name (`audit`, `canary_registry`, `detections`, …).
    pub chain: &'static str,
    /// The file (the active file of a rotating log).
    pub path: PathBuf,
    pub kind: ChainKind,
    /// Genuineness of one data line.
    pub genuine: LineCheck,
    /// Rotating logs: the bounded boot verification
    /// ([`crate::chainlog::verify_recent`] for the log's payload type).
    pub recent: Option<RecentCheck>,
    /// The full verification (`nn-admin chain verify`): a one-line
    /// summary, or why the chain is broken.
    pub full: FullCheck,
    /// Rotating logs: the log's [`crate::chainlog::ChainPayload::KIND`],
    /// the domain its manifest rows are checked under (external audit
    /// EVD-008, lab PR 204).
    pub payload_kind: Option<&'static str>,
}

impl ChainTarget {
    /// The target of the rotating log of `P` at `path`, on the host `H`.
    pub fn rotating<P, H>(chain: &'static str, path: &Path) -> Self
    where
        P: Serialize + serde::de::DeserializeOwned + crate::chainlog::ChainPayload,
        H: ChainHost,
    {
        ChainTarget {
            chain,
            path: path.to_path_buf(),
            kind: ChainKind::Rotating,
            genuine: crate::chainlog::line_is_genuine::<P>,
            recent: Some(crate::chainlog::verify_recent::<P, H>),
            full: full_rotating::<P>,
            payload_kind: Some(P::KIND),
        }
    }
}

/// Full verification of one chain.
pub type FullCheck = fn(&Path, &VerifyingKey) -> Result<String, String>;

/// [`crate::chainlog::verify_log_set`] for one payload type.
fn full_rotating<P: Serialize + serde::de::DeserializeOwned + crate::chainlog::ChainPayload>(
    active: &Path,
    pk: &VerifyingKey,
) -> Result<String, String> {
    crate::chainlog::verify_log_set::<P>(active, pk)
        .map(|r| {
            let mut s = format!(
                "{} records, {} archive(s) from seq {}, {} checkpoint(s) reachable",
                r.total_records,
                r.archives_verified,
                r.earliest_retained_seq,
                r.checkpoints_verified
            );
            // External audit EVD-007/EVD-008 (lab PR 204).
            s.push_str(&legacy_summary(r.legacy_lines, r.non_canonical_legacy));
            s
        })
        .map_err(|e| e.to_string())
}

/// External audit EVD-007/EVD-008 (lab PR 204): what a chain still holds in
/// the format from before v3, for the one-line summaries: nothing when it
/// holds none.
fn legacy_summary(legacy: u64, non_canonical: u64) -> String {
    match (legacy, non_canonical) {
        (0, _) => String::new(),
        (n, 0) => {
            format!(", {n} line(s) in the old format (untagged pre-image) before the v3 ones")
        }
        (n, c) => format!(
            ", {n} line(s) in the old format (untagged pre-image) before the v3 ones, {c} of them \
             not in canonical form (bytes the signature does not cover)"
        ),
    }
}

/// The rows of a flat chain file, and each row's line as on disk (external
/// audit EVD-007, lab PR 204); a line that does not parse is an error.
pub fn flat_rows<T: serde::de::DeserializeOwned>(
    path: &Path,
) -> Result<(Vec<T>, Vec<String>), String> {
    let body = match std::fs::read_to_string(path) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok((Vec::new(), Vec::new())),
        Err(e) => return Err(format!("unreadable: {e}")),
    };
    let mut rows = Vec::new();
    let mut raws = Vec::new();
    for (i, l) in body.lines().enumerate().filter(|(_, l)| !l.is_empty()) {
        rows.push(serde_json::from_str(l).map_err(|e| format!("line {}: {e}", i + 1))?);
        raws.push(l.to_string());
    }
    Ok((rows, raws))
}

/// External audit EVD-007 (NN-AUD-273, lab PR 204): every numbered row of a
/// flat chain is in its canonical bytes; returns how many rows without
/// `seq` are not (they verify as before).
pub fn canonical_rows<T: Serialize>(
    rows: &[T],
    raws: &[String],
    numbered: impl Fn(&T) -> bool,
) -> Result<usize, String> {
    let mut legacy = 0;
    for (idx, (row, raw)) in rows.iter().zip(raws).enumerate() {
        if is_canonical(row, raw.as_bytes()) {
            continue;
        }
        if numbered(row) {
            return Err(format!(
                "entry {idx}: a numbered row not in its canonical form (the bytes on disk are not \
                 what the agent wrote: a key added, reordered or re-spelled)"
            ));
        }
        legacy += 1;
    }
    Ok(legacy)
}

/// The summary's note on rows without `seq` not in canonical bytes.
pub fn non_canonical_note(n: usize) -> String {
    if n == 0 {
        String::new()
    } else {
        format!(
            ", {n} old-format row(s) not in canonical form (bytes the signature does not cover)"
        )
    }
}

/// External audit MAIN-014 (NN-AUD-256, lab PR 190): the audit chain in one
/// streaming pass ([`crate::audit::verify_chain_file`]); it was read whole
/// and kept row by row, and a line that is not a row was named only by its
/// parse error.
pub fn full_audit(path: &Path, pk: &VerifyingKey) -> Result<String, String> {
    let r =
        crate::audit::verify_chain_file(path, pk, None).map_err(|e| format!("unreadable: {e}"))?;
    if let Some(e) = r.broken {
        return Err(e.to_string());
    }
    Ok(numbered_summary(r.rows, r.first_numbered) + &non_canonical_note(r.non_canonical_legacy))
}

pub fn numbered_summary(rows: usize, first_numbered: Option<usize>) -> String {
    match first_numbered {
        Some(0) => format!("{rows} rows, all numbered"),
        Some(n) => format!("{rows} rows, {n} in the old format then numbered"),
        None => format!("{rows} rows in the old format"),
    }
}

/// [`crate::chainlog::verify_recent`] for one payload type.
pub type RecentCheck = fn(
    &Path,
    &VerifyingKey,
    u64,
) -> Result<crate::chainlog::RecentReport, crate::chainlog::LogSetError>;

// ── the head anchor ─────────────────────────────────────────────────

/// One anchored head.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AnchoredHead {
    /// [`ChainTarget::chain`], with `.manifest` for a rotating log's
    /// manifest.
    pub chain: String,
    pub path: String,
    /// Rotating active file: the archive seq it becomes when sealed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub generation: Option<u64>,
    #[serde(flatten)]
    pub head: FileHead,
}

/// What the head anchor holds.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HeadsSnapshot {
    /// Incremented at every write; picks the slot.
    pub counter: u64,
    pub ts: String,
    pub agent_id: String,
    /// The audit chain showed a successful `rotate_keys_add` (ATP-004).
    pub second_key_added: bool,
    pub heads: Vec<AnchoredHead>,
}

#[derive(Serialize, Deserialize)]
struct SignedSlot {
    snapshot: HeadsSnapshot,
    sig: String,
}

/// What a read of the head anchor found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HeadsRead {
    /// No file.
    Missing,
    /// A file with no snapshot written yet.
    Empty,
    /// The newest genuine snapshot.
    Valid(HeadsSnapshot),
    /// A file that holds no genuine snapshot.
    Invalid(String),
}

fn snapshot_digest(s: &HeadsSnapshot) -> Result<[u8; 32]> {
    let json = serde_json::to_vec(s).map_err(|e| anyhow!("serialising heads snapshot: {e}"))?;
    let mut h = Sha256::new();
    h.update(HEADS_DOMAIN);
    h.update(&json);
    Ok(h.finalize().into())
}

/// The two-slot signed head anchor.
pub struct HeadsStore;

impl HeadsStore {
    /// The newest genuine snapshot in `path`.
    pub fn read<H: ChainHost>(path: &Path, pk: &VerifyingKey) -> HeadsRead {
        let bytes = match read_bounded::<H>(path, 2 * SLOT_BYTES) {
            Ok(Some(b)) => b,
            Ok(None) => return HeadsRead::Missing,
            Err(e) => return HeadsRead::Invalid(format!("unreadable: {e}")),
        };
        if bytes.iter().all(|&c| c == 0 || c == b' ' || c == b'\n') {
            return HeadsRead::Empty;
        }
        let mut best: Option<HeadsSnapshot> = None;
        let mut why = Vec::new();
        for (i, slot) in bytes.chunks(SLOT_BYTES as usize).enumerate() {
            let text = slot
                .iter()
                .copied()
                .take_while(|&c| c != 0)
                .collect::<Vec<u8>>();
            let text = String::from_utf8_lossy(&text);
            let text = text.trim();
            if text.is_empty() {
                continue;
            }
            match serde_json::from_str::<SignedSlot>(text) {
                Ok(s) => match snapshot_digest(&s.snapshot) {
                    Ok(d) if signature_ok(&d, &s.sig, pk) => {
                        if best.as_ref().is_none_or(|b| s.snapshot.counter > b.counter) {
                            best = Some(s.snapshot);
                        }
                    }
                    _ => why.push(format!("slot {i}: signature does not verify")),
                },
                Err(e) => why.push(format!("slot {i}: {e}")),
            }
        }
        match best {
            Some(s) => HeadsRead::Valid(s),
            None => HeadsRead::Invalid(why.join("; ")),
        }
    }

    /// Write `snapshot` (its `counter` picks the slot) and fsync. The file
    /// is created if missing (`O_NOFOLLOW`, never truncated).
    pub fn write<K: ChainSigner>(path: &Path, key: &K, snapshot: &HeadsSnapshot) -> Result<()> {
        let digest = snapshot_digest(snapshot)?;
        let slot = SignedSlot {
            snapshot: snapshot.clone(),
            sig: B64.encode(key.sign(&digest).to_bytes()),
        };
        let mut text = serde_json::to_vec(&slot)?;
        if text.len() as u64 >= SLOT_BYTES {
            return Err(anyhow!(
                "heads snapshot is {} bytes, over the {SLOT_BYTES}-byte slot",
                text.len()
            ));
        }
        text.resize(SLOT_BYTES as usize - 1, b' ');
        text.push(b'\n');
        let f = K::Host::open_with_mode_nofollow(
            OpenOptions::new().write(true).create(true).truncate(false),
            HEADS_FILE_MODE,
            path,
        )
        .with_context(|| format!("opening {}", path.display()))?;
        let offset = (snapshot.counter % 2) * SLOT_BYTES;
        K::Host::write_all_at(&f, &text, offset)
            .with_context(|| format!("writing {}", path.display()))?;
        f.sync_all()
            .with_context(|| format!("fsync {}", path.display()))?;
        Ok(())
    }
}

fn read_bounded<H: ChainHost>(path: &Path, max: u64) -> std::io::Result<Option<Vec<u8>>> {
    let f = match H::open_read_nofollow(path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e),
    };
    let mut buf = Vec::new();
    f.take(max).read_to_end(&mut buf)?;
    Ok(Some(buf))
}

/// The heads of every target, read from disk now.
pub fn collect_heads<H: ChainHost>(
    targets: &[ChainTarget],
    pk: &VerifyingKey,
) -> Vec<AnchoredHead> {
    let mut out = Vec::new();
    for t in targets {
        let genuine = |l: &[u8]| (t.genuine)(l, pk);
        let head =
            |path: &Path, check: &dyn Fn(&[u8]) -> bool| match read_file_head::<H>(path, check) {
                Ok(h) => h,
                Err(e) => {
                    warn!(error = %e, path = %path.display(), "chain head: file not read");
                    None
                }
            };
        match t.kind {
            ChainKind::Flat => {
                if let Some(h) = head(&t.path, &genuine) {
                    out.push(AnchoredHead {
                        chain: t.chain.to_string(),
                        path: t.path.display().to_string(),
                        generation: None,
                        head: h,
                    });
                }
            }
            ChainKind::Rotating => {
                // A rotation between reading the generation and the head
                // would anchor the head under the wrong file: the
                // generation must be the same before and after.
                let stable = (0..3).find_map(|_| {
                    let before = crate::chainlog::current_generation(&t.path);
                    let h = head(&t.path, &genuine);
                    (crate::chainlog::current_generation(&t.path) == before).then_some((before, h))
                });
                if let Some((generation, Some(h))) = stable {
                    out.push(AnchoredHead {
                        chain: t.chain.to_string(),
                        path: t.path.display().to_string(),
                        generation: Some(generation),
                        head: h,
                    });
                }
                let manifest = crate::chainlog::manifest_path(&t.path);
                let kind = t.payload_kind.unwrap_or_default();
                let mcheck = |l: &[u8]| crate::chainlog::manifest_line_is_genuine(l, kind, pk);
                if let Some(h) = head(&manifest, &mcheck) {
                    out.push(AnchoredHead {
                        chain: format!("{}.manifest", t.chain),
                        path: manifest.display().to_string(),
                        generation: None,
                        head: h,
                    });
                }
            }
        }
    }
    out
}

// ── findings ────────────────────────────────────────────────────────

/// A completeness problem found in a chain, reported as a signed
/// `integrity_drift` with this `kind`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChainFinding {
    /// The chain (`audit`, `canary_access`, `detections`, …).
    pub chain: String,
    pub file: PathBuf,
    /// `chain_truncated`, `chain_rewritten`, `chain_missing`,
    /// `chain_archives_missing`, `active_file_missing`,
    /// `chain_sequence_broken`, `chain_lines_unverified`,
    /// `chain_verify_failed`, `chain_heads_missing`,
    /// `chain_heads_unverified`.
    pub kind: &'static str,
    pub detail: String,
}

impl ChainFinding {
    pub fn new(
        chain: impl Into<String>,
        file: &Path,
        kind: &'static str,
        detail: impl Into<String>,
    ) -> Self {
        Self {
            chain: chain.into(),
            file: file.to_path_buf(),
            kind,
            detail: detail.into(),
        }
    }

    /// The signed `integrity_drift` entry.
    pub fn draft(&self) -> AuditEntryDraft {
        AuditEntryDraft {
            op: crate::audit::INTEGRITY_DRIFT_OP.to_string(),
            extra: serde_json::json!({
                "kind": self.kind,
                "chain": self.chain,
                "file": self.file.display().to_string(),
                "detail": self.detail,
                "at_boot": true,
            }),
            key_fp: "agent-self".to_string(),
            cosigner_fps: Vec::new(),
            result: "detected".to_string(),
            client_pid: std::process::id(),
            client_uid: 0,
            client_comm: "northnarrow-agent".to_string(),
            client_exe: None,
        }
    }

    /// ERROR in the journal, then the signed entry.
    pub fn attest<K: ChainSigner>(&self, log: Option<&mut AuditLog<K>>) {
        error!(
            kind = self.kind,
            chain = %self.chain,
            file = %self.file.display(),
            detail = %self.detail,
            "chain integrity: evidence missing or altered — see the runbook (chain verification failed)"
        );
        if let Some(log) = log {
            if let Err(e) = log.append(self.draft()) {
                warn!(error = %format!("{e:#}"), "attesting a chain finding failed");
            }
        }
    }

    /// Whether this finding means the audit chain lost history.
    fn audit_history(&self) -> bool {
        (self.chain == "audit" && self.kind != "chain_lines_unverified")
            || self.kind == "chain_heads_missing"
            || self.kind == "chain_heads_unverified"
    }
}

/// What [`boot_check`] found.
#[derive(Debug, Clone, Default)]
pub struct BootCheck {
    pub findings: Vec<ChainFinding>,
    /// The newest genuine snapshot, if any.
    pub previous: Option<HeadsSnapshot>,
    /// No head anchor file, or one never written.
    heads_absent: bool,
}

impl BootCheck {
    /// The head anchor is absent although the audit chain records that
    /// anchoring started ([`NUMBERING_STARTED_OP`], written only after the
    /// first snapshot was on disk): it was removed. Fails ATP-004 closed.
    pub fn heads_missing(
        &mut self,
        heads_file: &Path,
        anchoring_started: bool,
    ) -> Option<ChainFinding> {
        if !(self.heads_absent && anchoring_started) {
            return None;
        }
        let f = ChainFinding::new(
            "chain_heads",
            heads_file,
            "chain_heads_missing",
            "the audit chain records that head anchoring started, but the head anchor is missing \
             or empty: it was removed",
        );
        self.findings.push(f.clone());
        Some(f)
    }

    /// Why the audit chain's history cannot be trusted to be complete:
    /// it is shorter than its anchored head, or the anchor itself was
    /// removed or replaced. `None` when nothing says so.
    pub fn audit_history_lost(&self) -> Option<String> {
        let lost: Vec<String> = self
            .findings
            .iter()
            .filter(|f| f.audit_history())
            .map(|f| format!("{}: {}", f.kind, f.detail))
            .collect();
        (!lost.is_empty()).then(|| lost.join("; "))
    }

    /// The anchored sticky flag (ATP-004), or `true` when the audit
    /// history was lost and the flag cannot be known (fail closed).
    pub fn second_key_added(&self) -> bool {
        self.previous.as_ref().is_some_and(|p| p.second_key_added)
            || self.audit_history_lost().is_some()
    }
}

/// Compare the chains with what was anchored: every head of the last
/// snapshot in `heads_file`, and the newest manifest checkpoint of every
/// rotating log. O(1) reads per file; run before any writer opens.
pub fn boot_check<H: ChainHost>(
    targets: &[ChainTarget],
    heads_file: &Path,
    pk: &VerifyingKey,
) -> BootCheck {
    let mut out = BootCheck::default();
    match HeadsStore::read::<H>(heads_file, pk) {
        HeadsRead::Valid(s) => out.previous = Some(s),
        HeadsRead::Invalid(why) => out.findings.push(ChainFinding::new(
            "chain_heads",
            heads_file,
            "chain_heads_unverified",
            format!("the head anchor holds no genuine snapshot ({why})"),
        )),
        // Whether one should exist is known once the audit log is open
        // ([`BootCheck::heads_missing`]).
        HeadsRead::Missing | HeadsRead::Empty => out.heads_absent = true,
    }
    if let Some(prev) = &out.previous {
        for h in &prev.heads {
            check_anchored::<H>(h, &prev.ts, targets, &mut out.findings);
        }
    }
    for t in targets
        .iter()
        .filter(|t| matches!(t.kind, ChainKind::Rotating))
    {
        check_rotating::<H>(t, pk, &mut out.findings);
    }
    // One finding per file and kind is enough.
    let mut seen = std::collections::HashSet::new();
    out.findings
        .retain(|f| seen.insert((f.file.clone(), f.kind)));
    out
}

/// Which file holds a head anchored at `generation` of the rotating log
/// `active`, now: the active file, an archive, or nothing.
enum Holder {
    File(PathBuf),
    /// Archived then dropped by retention (the verifier checks the
    /// manifest's `Evicted` rows).
    Evicted,
    /// Generations past what is on disk.
    RolledBack {
        now: u64,
    },
}

fn holder(active: &Path, generation: u64) -> Holder {
    let now = crate::chainlog::current_generation(active);
    if generation == now {
        return Holder::File(active.to_path_buf());
    }
    if generation > now {
        return Holder::RolledBack { now };
    }
    let archive = crate::chainlog::archive_path_for(active, generation);
    if archive.exists() {
        return Holder::File(archive);
    }
    let earliest = crate::chainlog::earliest_archive(active);
    if earliest.is_some_and(|e| generation < e) {
        Holder::Evicted
    } else {
        Holder::File(archive)
    }
}

fn check_anchored<H: ChainHost>(
    h: &AnchoredHead,
    anchored_at: &str,
    targets: &[ChainTarget],
    findings: &mut Vec<ChainFinding>,
) {
    let base = h.chain.trim_end_matches(".manifest");
    let Some(t) = targets.iter().find(|t| t.chain == base) else {
        return; // a chain this build no longer anchors
    };
    let path = if h.chain.ends_with(".manifest") {
        crate::chainlog::manifest_path(&t.path)
    } else {
        match (t.kind, h.generation) {
            (ChainKind::Rotating, Some(g)) => match holder(&t.path, g) {
                Holder::File(p) => p,
                Holder::Evicted => return,
                Holder::RolledBack { now } => {
                    findings.push(ChainFinding::new(
                        h.chain.clone(),
                        &t.path,
                        "chain_archives_missing",
                        format!(
                            "the head anchored at {anchored_at} is in generation {g}, but only \
                             {} archive(s) are on disk: the newest archives were removed",
                            now.saturating_sub(1)
                        ),
                    ));
                    return;
                }
            },
            _ => t.path.clone(),
        }
    };
    report_head::<H>(
        &h.chain,
        &path,
        &h.head,
        &format!("anchored at {anchored_at}"),
        findings,
    );
}

fn report_head<H: ChainHost>(
    chain: &str,
    path: &Path,
    head: &FileHead,
    source: &str,
    findings: &mut Vec<ChainFinding>,
) {
    let row = head.seq.map(|s| format!("row {s}, ")).unwrap_or_default();
    let what = format!(
        "the head {source} ends at byte {} ({row}entry_hash {})",
        head.bytes, head.tail_hash
    );
    let finding = match check_head::<H>(path, head) {
        Ok(HeadCheck::Intact) => return,
        Ok(HeadCheck::Missing) => ("chain_missing", format!("the file is gone; {what}")),
        Ok(HeadCheck::Shorter { len }) => (
            "chain_truncated",
            format!("the file is {len} bytes; {what}: rows were cut from its end"),
        ),
        Ok(HeadCheck::Changed) => (
            "chain_rewritten",
            format!("no line with that hash ends there; {what}: the file was rewritten"),
        ),
        Err(e) => {
            warn!(error = %e, path = %path.display(), "chain head: file not checked");
            return;
        }
    };
    findings.push(ChainFinding::new(chain, path, finding.0, finding.1));
}

/// The newest manifest checkpoint, and a missing active file, of one
/// rotating log.
fn check_rotating<H: ChainHost>(
    t: &ChainTarget,
    pk: &VerifyingKey,
    findings: &mut Vec<ChainFinding>,
) {
    let tail =
        crate::chainlog::manifest_tail_events::<H>(&t.path, t.payload_kind.unwrap_or_default(), pk);
    if let Some((seq, head)) = tail.iter().find_map(|e| match e {
        crate::chainlog::ManifestEvent::ActiveCheckpoint {
            seq,
            bytes,
            tail_hash,
        } => Some((
            *seq,
            FileHead {
                bytes: *bytes,
                tail_hash: tail_hash.clone(),
                seq: None,
            },
        )),
        _ => None,
    }) {
        match holder(&t.path, seq) {
            Holder::File(p) => report_head::<H>(
                t.chain,
                &p,
                &head,
                &format!("checkpointed in the manifest (generation {seq})"),
                findings,
            ),
            Holder::Evicted => {}
            Holder::RolledBack { now } => findings.push(ChainFinding::new(
                t.chain,
                &t.path,
                "chain_archives_missing",
                format!(
                    "the manifest checkpoints generation {seq}, but only {} archive(s) are on \
                     disk: the newest archives were removed",
                    now.saturating_sub(1)
                ),
            )),
        }
    }
    if let Some(why) = crate::chainlog::active_missing(&t.path, &tail) {
        findings.push(ChainFinding::new(
            t.chain,
            &t.path,
            "active_file_missing",
            why,
        ));
    }
}

// ── the anchor writer ───────────────────────────────────────────────

/// Writes the head anchor for the running agent.
pub struct Anchor<K> {
    file: PathBuf,
    key: K,
    agent_id: [u8; 16],
    targets: Vec<ChainTarget>,
    last: Option<HeadsSnapshot>,
    second_key_added: bool,
    /// Registers the file when it is created at run time (and creates it
    /// inside the `+i` dance if a direct create is refused).
    protection: Option<Arc<dyn crate::chainlog::ProtectionManager>>,
    /// The audit chain does not record yet that anchoring started.
    marker_pending: bool,
}

impl<K: ChainSigner> Anchor<K> {
    /// `previous`: the snapshot the boot check read (its counter and
    /// sticky flag carry over). `anchoring_started`: the audit chain
    /// already holds the [`NUMBERING_STARTED_OP`] row.
    pub fn new(
        file: PathBuf,
        key: K,
        agent_id: [u8; 16],
        targets: Vec<ChainTarget>,
        previous: Option<HeadsSnapshot>,
        anchoring_started: bool,
    ) -> Self {
        let second_key_added = previous.as_ref().is_some_and(|p| p.second_key_added);
        Self {
            file,
            key,
            agent_id,
            targets,
            last: previous,
            second_key_added,
            protection: None,
            marker_pending: !anchoring_started,
        }
    }

    /// Use `protection` to create the file when it is missing.
    pub fn set_protection(&mut self, protection: Arc<dyn crate::chainlog::ProtectionManager>) {
        self.protection = Some(protection);
    }

    /// The sticky ATP-004 flag as anchored.
    pub fn second_key_added(&self) -> bool {
        self.second_key_added
    }

    /// Once a snapshot is on disk: the one-time audit row that records
    /// where numbering and anchoring start (the legacy head of every flat
    /// chain). `None` once taken, or before the first write.
    pub fn take_marker(&mut self) -> Option<AuditEntryDraft> {
        if !self.marker_pending {
            return None;
        }
        let snapshot = self.last.as_ref()?;
        self.marker_pending = false;
        Some(numbering_started_draft(snapshot, &self.file))
    }

    /// Create the file if missing: directly, or inside the `+i` dance.
    fn ensure_file(&self) -> Result<()> {
        if std::fs::symlink_metadata(&self.file).is_ok() {
            return Ok(());
        }
        let create = |path: &Path| -> Result<()> {
            match K::Host::open_with_mode(
                OpenOptions::new().write(true).create_new(true),
                HEADS_FILE_MODE,
                path,
            ) {
                Ok(_) => Ok(()),
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => Ok(()),
                Err(e) => Err(anyhow!(e).context(format!("creating {}", path.display()))),
            }
        };
        let Some(p) = &self.protection else {
            return create(&self.file);
        };
        if create(&self.file).is_err() {
            let file = self.file.clone();
            p.with_mutable_dir(&mut || create(&file))?;
        }
        if let Err(e) = p.register_active(&self.file) {
            warn!(error = %format!("{e:#}"), path = %self.file.display(),
                "chain heads: anchor file not registered in PROTECTED_INODES");
        }
        Ok(())
    }

    /// Re-read every head; write a snapshot when `force` or one moved
    /// (or the sticky flag turned on). Returns the heads that moved.
    pub fn refresh(&mut self, force: bool, second_key_added: bool) -> Result<Vec<AnchoredHead>> {
        let heads = collect_heads::<K::Host>(&self.targets, &self.key.verifying_key());
        let flag = self.second_key_added || second_key_added;
        // Sticky in memory even if the write below fails.
        self.second_key_added = flag;
        let moved: Vec<AnchoredHead> = match &self.last {
            Some(last) => heads
                .iter()
                .filter(|h| !last.heads.contains(h))
                .cloned()
                .collect(),
            None => heads.clone(),
        };
        let unchanged = self
            .last
            .as_ref()
            .is_some_and(|l| l.heads == heads && l.second_key_added == flag);
        if unchanged && !force {
            return Ok(Vec::new());
        }
        let snapshot = HeadsSnapshot {
            counter: self.last.as_ref().map_or(1, |l| l.counter + 1),
            ts: chrono::Utc::now()
                .format("%Y-%m-%dT%H:%M:%S%.6fZ")
                .to_string(),
            agent_id: hex::encode(self.agent_id),
            second_key_added: flag,
            heads,
        };
        self.ensure_file()?;
        HeadsStore::write(&self.file, &self.key, &snapshot)?;
        for h in &moved {
            info!(
                target: "chain.head",
                chain = %h.chain,
                file = %h.path,
                generation = ?h.generation,
                seq = ?h.head.seq,
                bytes = h.head.bytes,
                entry_hash = %h.head.tail_hash,
                "chain head anchored"
            );
        }
        self.second_key_added = flag;
        self.last = Some(snapshot);
        Ok(moved)
    }
}

/// Bytes of each rotating log's active file the boot verification covers.
pub const BOOT_VERIFY_BYTES: u64 = 4 * 1024 * 1024;

/// Audit op of the boot verification's result.
pub const CHAIN_VERIFY_OP: &str = "chain_verify";

/// The one-time record, in the audit chain, of where numbering and head
/// anchoring start: the head of every flat chain in the first snapshot.
/// Rows after these heads carry `seq` and a domain-tagged hash; the rows up
/// to them verify in the old format.
pub fn numbering_started_draft(first: &HeadsSnapshot, heads_file: &Path) -> AuditEntryDraft {
    let chains: Vec<serde_json::Value> = first
        .heads
        .iter()
        .filter(|h| h.generation.is_none() && !h.chain.ends_with(".manifest"))
        .map(|h| {
            serde_json::json!({
                "chain": h.chain,
                "file": h.path,
                "bytes": h.head.bytes,
                "entry_hash": h.head.tail_hash,
                "seq": h.head.seq,
            })
        })
        .collect();
    AuditEntryDraft {
        op: NUMBERING_STARTED_OP.to_string(),
        extra: serde_json::json!({
            "detail": "rows written after these heads carry seq and a domain-tagged hash; rows \
                       up to them verify in the old format; the heads are anchored in heads_file",
            "heads_file": heads_file.display().to_string(),
            "chains": chains,
        }),
        key_fp: "agent-self".to_string(),
        cosigner_fps: Vec::new(),
        result: "success".to_string(),
        client_pid: std::process::id(),
        client_uid: 0,
        client_comm: "northnarrow-agent".to_string(),
        client_exe: None,
    }
}

/// External audit NN-AUD-292 (FIMP-013), for the tests of every chain
/// verifier: a public key of small order (the identity point, which
/// `VerifyingKey::from_bytes` takes) and a signature (`R` the identity,
/// `s = 0`) that the lax `verify` accepts under that key for every
/// message. `verify_strict` refuses both; a signature the agent made
/// passes either.
///
/// R04a (lab PR 241): compiled in every build, hidden from the docs, for
/// the verifiers' tests on both sides of the crate boundary (the canary
/// chains and the FIM baseline keep theirs in the agent).
#[doc(hidden)]
pub mod small_order {
    use base64::engine::general_purpose::STANDARD as B64;
    use base64::Engine as _;
    use ed25519_dalek::{Signature, VerifyingKey};

    pub fn key() -> VerifyingKey {
        let mut b = [0u8; 32];
        b[0] = 1;
        VerifyingKey::from_bytes(&b).expect("the identity point decompresses")
    }

    pub fn signature() -> Signature {
        let mut b = [0u8; 64];
        b[0] = 1;
        Signature::from_bytes(&b)
    }

    /// The premise of each test: the lax check accepts the pair over
    /// `msg`, the strict one does not.
    pub fn assert_premise(msg: &[u8]) {
        use ed25519_dalek::Verifier as _;
        assert!(key().verify(msg, &signature()).is_ok(), "lax verify");
        assert!(key().verify_strict(msg, &signature()).is_err());
    }

    /// `text` with every `agent_sig` value replaced by the small-order
    /// signature; nothing else changed (the hashes still recompute).
    pub fn forge(text: &str) -> String {
        const MARK: &str = "\"agent_sig\":\"";
        let sig = B64.encode(signature().to_bytes());
        let mut out = String::with_capacity(text.len());
        let mut rest = text;
        while let Some(i) = rest.find(MARK) {
            let start = i + MARK.len();
            out.push_str(&rest[..start]);
            out.push_str(&sig);
            let end = start + rest[start..].find('"').expect("a closed string");
            rest = &rest[end..];
        }
        out.push_str(rest);
        out
    }
}

/// Append raw bytes to `path` (tests only).
#[cfg(test)]
pub(crate) fn append_raw(path: &Path, bytes: &[u8]) {
    use std::io::Write;
    let mut f = OpenOptions::new().append(true).open(path).unwrap();
    f.write_all(bytes).unwrap();
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::{AuditEntryDraft, AuditLog};
    use crate::chain_host::testing::{PortableHost, TestKey};
    use tempfile::TempDir;

    fn draft(n: u32) -> AuditEntryDraft {
        AuditEntryDraft {
            op: format!("op_{n}"),
            extra: serde_json::json!({ "n": n }),
            key_fp: "00000000".to_string(),
            cosigner_fps: vec![],
            result: "success".to_string(),
            client_pid: 1,
            client_uid: 0,
            client_comm: "t".to_string(),
            client_exe: None,
        }
    }

    fn key(dir: &TempDir) -> TestKey {
        TestKey::load_or_bootstrap(&dir.path().join("agent.sig.key")).unwrap()
    }

    /// External audit NN-AUD-292 (FIMP-013): the heads snapshot's signature
    /// is checked strictly — the agent's passes, a small-order pair the lax
    /// check took does not.
    #[test]
    fn signature_ok_refuses_a_small_order_pair_and_takes_the_agents() {
        let dir = TempDir::new().unwrap();
        let k = key(&dir);
        let digest = [7u8; 32];
        small_order::assert_premise(&digest);
        let weak = B64.encode(small_order::signature().to_bytes());
        assert!(!signature_ok(&digest, &weak, &small_order::key()));
        let genuine = B64.encode(k.sign(&digest).to_bytes());
        assert!(signature_ok(&digest, &genuine, &k.verifying_key()));
    }

    #[test]
    fn row_seq_starts_after_legacy_rows_and_rejects_gaps_and_old_rows() {
        let mut s = RowSeq::default();
        s.push(None).unwrap();
        s.push(None).unwrap();
        s.push(Some(2)).unwrap();
        s.skip();
        s.push(Some(4)).unwrap();
        assert_eq!(s.rows(), 5);
        assert!(s.numbered());
        assert_eq!(
            s.clone().push(Some(9)),
            Err(SeqBreak::Mismatch { row: 5, seq: 9 })
        );
        assert_eq!(s.push(None), Err(SeqBreak::Missing { row: 5 }));
        let mut legacy = RowSeq::default();
        legacy.push(None).unwrap();
        assert_eq!(
            legacy.push(Some(0)),
            Err(SeqBreak::Mismatch { row: 1, seq: 0 })
        );
    }

    #[test]
    fn a_head_is_found_and_checked_in_place() {
        let dir = TempDir::new().unwrap();
        let k = key(&dir);
        let pk = k.verifying_key();
        let path = dir.path().join("audit.log");
        let mut log = AuditLog::open(&path, k, [1; 16]).unwrap();
        for n in 0..5 {
            log.append(draft(n)).unwrap();
        }
        let ok = |l: &[u8]| crate::audit::row_is_genuine(l, &pk);
        let head = read_file_head::<PortableHost>(&path, &ok).unwrap().unwrap();
        assert_eq!(head.seq, Some(4));
        assert_eq!(head.bytes, std::fs::metadata(&path).unwrap().len());
        assert_eq!(
            check_head::<PortableHost>(&path, &head).unwrap(),
            HeadCheck::Intact
        );
        // growth keeps it intact
        log.append(draft(9)).unwrap();
        assert_eq!(
            check_head::<PortableHost>(&path, &head).unwrap(),
            HeadCheck::Intact
        );
        // a forged trailing line is not a head
        append_raw(&path, b"{\"entry_hash\":\"");
        append_raw(&path, "ab".repeat(32).as_bytes());
        append_raw(&path, b"\"}\n");
        let again = read_file_head::<PortableHost>(&path, &ok).unwrap().unwrap();
        assert_eq!(again.seq, Some(5));
        // cut below the head
        let body = std::fs::read(&path).unwrap();
        std::fs::write(&path, &body[..head.bytes as usize - 10]).unwrap();
        assert!(matches!(
            check_head::<PortableHost>(&path, &head).unwrap(),
            HeadCheck::Shorter { .. }
        ));
        std::fs::remove_file(&path).unwrap();
        assert_eq!(
            check_head::<PortableHost>(&path, &head).unwrap(),
            HeadCheck::Missing
        );
    }

    #[test]
    fn the_heads_store_keeps_the_previous_snapshot_when_a_write_is_torn() {
        let dir = TempDir::new().unwrap();
        let k = key(&dir);
        let pk = k.verifying_key();
        let file = dir.path().join(HEADS_FILE_NAME);
        assert_eq!(
            HeadsStore::read::<PortableHost>(&file, &pk),
            HeadsRead::Missing
        );
        std::fs::write(&file, b"").unwrap();
        assert_eq!(
            HeadsStore::read::<PortableHost>(&file, &pk),
            HeadsRead::Empty
        );
        let mut s = HeadsSnapshot {
            counter: 1,
            ts: "t1".into(),
            agent_id: "00".into(),
            second_key_added: false,
            heads: vec![],
        };
        HeadsStore::write(&file, &k, &s).unwrap();
        s.counter = 2;
        s.ts = "t2".into();
        HeadsStore::write(&file, &k, &s).unwrap();
        assert!(
            matches!(HeadsStore::read::<PortableHost>(&file, &pk), HeadsRead::Valid(v) if v.counter == 2)
        );
        // slot of counter 2 torn: counter 1 is still there
        let f = OpenOptions::new().write(true).open(&file).unwrap();
        PortableHost::write_all_at(&f, b"{\"torn", 0).unwrap();
        assert!(
            matches!(HeadsStore::read::<PortableHost>(&file, &pk), HeadsRead::Valid(v) if v.counter == 1)
        );
        // another key's snapshot is not genuine
        let other = TestKey::load_or_bootstrap(&dir.path().join("other")).unwrap();
        HeadsStore::write(&file, &other, &s).unwrap();
        s.counter = 3;
        HeadsStore::write(&file, &other, &s).unwrap();
        assert!(matches!(
            HeadsStore::read::<PortableHost>(&file, &pk),
            HeadsRead::Invalid(_)
        ));
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    struct P {
        ts: String,
        n: u64,
    }

    impl crate::chainlog::ChainPayload for P {
        const KIND: &'static str = "test_log";
    }

    fn rotating_target(path: &Path) -> ChainTarget {
        ChainTarget::rotating::<P, PortableHost>("test_log", path)
    }

    fn rotating_log(
        path: &Path,
        key: TestKey,
        cap: u64,
    ) -> crate::chainlog::RotatingChainLog<P, TestKey> {
        crate::chainlog::RotatingChainLog::<P, _>::open(
            path,
            key,
            crate::chainlog::RotationConfig {
                size_cap_bytes: cap,
                max_archives: 50,
                file_mode: 0o600,
            },
            Arc::new(crate::chainlog::NoProtection),
        )
        .unwrap()
    }

    fn p(n: u64) -> P {
        P {
            ts: format!("2026-10-15T00:00:{n:02}.000000Z"),
            n,
        }
    }

    /// External audit NN-AUD-109: an active file emptied while the agent is
    /// down is found at the next start — from the manifest checkpoint, and
    /// from the anchor written at stop when no checkpoint covers it.
    #[test]
    fn an_emptied_active_file_is_found_at_the_next_boot() {
        let dir = TempDir::new().unwrap();
        let k = key(&dir);
        let pk = k.verifying_key();
        let heads = dir.path().join(HEADS_FILE_NAME);
        // (a) the checkpoint the open wrote
        let active = dir.path().join("a.jsonl");
        let mut log = rotating_log(&active, key(&dir), 1 << 30);
        for n in 0..4 {
            log.append(p(n)).unwrap();
        }
        drop(log);
        drop(rotating_log(&active, key(&dir), 1 << 30));
        std::fs::write(&active, b"").unwrap();
        let found = boot_check::<PortableHost>(&[rotating_target(&active)], &heads, &pk);
        assert_eq!(found.findings.len(), 1, "{:?}", found.findings);
        assert_eq!(found.findings[0].kind, "chain_truncated");
        // (b) no checkpoint yet: the snapshot taken at stop
        let active = dir.path().join("b.jsonl");
        let mut log = rotating_log(&active, key(&dir), 1 << 30);
        for n in 0..3 {
            log.append(p(n)).unwrap();
        }
        drop(log);
        assert!(
            crate::chainlog::manifest_tail_events::<PortableHost>(&active, "test_log", &pk)
                .is_empty()
        );
        Anchor::new(
            heads.clone(),
            k,
            [1; 16],
            vec![rotating_target(&active)],
            None,
            false,
        )
        .refresh(true, false)
        .unwrap();
        assert!(
            boot_check::<PortableHost>(&[rotating_target(&active)], &heads, &pk)
                .findings
                .is_empty()
        );
        std::fs::write(&active, b"").unwrap();
        let found = boot_check::<PortableHost>(&[rotating_target(&active)], &heads, &pk);
        assert_eq!(found.findings.len(), 1, "{:?}", found.findings);
        assert_eq!(found.findings[0].kind, "chain_truncated");
        assert_eq!(found.findings[0].chain, "test_log");
    }

    /// External audit NN-AUD-109: the active file deleted after a
    /// completed rotation; the crash window (no `Rotated` row yet) is not
    /// reported.
    #[test]
    fn a_deleted_active_file_is_found_at_the_next_boot() {
        let dir = TempDir::new().unwrap();
        let pk = key(&dir).verifying_key();
        let heads = dir.path().join(HEADS_FILE_NAME);
        let active = dir.path().join("c.jsonl");
        let mut log = rotating_log(&active, key(&dir), 400);
        for n in 0..10 {
            log.append(p(n)).unwrap();
        }
        drop(log);
        assert!(crate::chainlog::current_generation(&active) > 1);
        std::fs::remove_file(&active).unwrap();
        let found = boot_check::<PortableHost>(&[rotating_target(&active)], &heads, &pk);
        assert!(
            found
                .findings
                .iter()
                .any(|f| f.kind == "active_file_missing"),
            "{:?}",
            found.findings
        );
        // full verification agrees
        assert!((rotating_target(&active).full)(&active, &pk).is_err());
    }
}
