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
/// missing, empty, or holds no such line at all.
///
/// Lot 295 (BUG26): when the search stops at its bounds — more than
/// [`MAX_HEAD_PROBES`] chain-shaped lines at the end that do not verify, or
/// a window past [`HEAD_WINDOW_MAX`] (it grows by 4: 16 MiB) read without
/// one that does, before the file's start — the head is not known: an
/// error ([`std::io::ErrorKind::InvalidData`]), never `None`. Lines
/// appended after the head must not make a file read as one without a
/// head: the anchor would drop the chain, and a cut made later would not
/// be found.
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
                return Err(head_not_found(
                    path,
                    &format!(
                        "the last {MAX_HEAD_PROBES} chain-shaped lines do not verify (lines \
                         appended after the head)"
                    ),
                ));
            }
            if genuine(line) {
                return Ok(Some(FileHead {
                    bytes: start + nls[k] as u64 + 1,
                    tail_hash: hash,
                    seq,
                }));
            }
        }
        if start == 0 {
            return Ok(None);
        }
        if window >= HEAD_WINDOW_MAX {
            return Err(head_not_found(
                path,
                &format!("no genuine line in its last {window} bytes"),
            ));
        }
        window = window.saturating_mul(4).min(size);
    }
}

fn head_not_found(path: &Path, why: &str) -> std::io::Error {
    std::io::Error::new(
        std::io::ErrorKind::InvalidData,
        format!("{}: the head is not known: {why}", path.display()),
    )
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
) -> Result<crate::chainlog::RecentReport, crate::chainlog::RecentError>;

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

/// The heads of every target, read from disk now (it was `collect_heads`,
/// which left out a chain whose head it could not read). Lot 295 (BUG26):
/// the heads, and apart the chains whose head is not known — not the same
/// as a file with no head: the anchor keeps such a chain's anchored head.
struct HeadsNow {
    heads: Vec<AnchoredHead>,
    /// `chain` (`x`, `x.manifest`) and why its head is not known.
    unread: Vec<(String, String)>,
}

impl HeadsNow {
    fn unread(&self, chain: &str) -> bool {
        self.unread.iter().any(|(c, _)| c == chain)
    }
}

fn read_heads<H: ChainHost>(targets: &[ChainTarget], pk: &VerifyingKey) -> HeadsNow {
    let mut now = HeadsNow {
        heads: Vec::new(),
        unread: Vec::new(),
    };
    for t in targets {
        let genuine = |l: &[u8]| (t.genuine)(l, pk);
        let mut put = |chain: String,
                       path: &Path,
                       generation: Option<u64>,
                       head: std::io::Result<Option<FileHead>>| match head {
            Ok(Some(h)) => now.heads.push(AnchoredHead {
                chain,
                path: path.display().to_string(),
                generation,
                head: h,
            }),
            Ok(None) => {}
            Err(e) => now.unread.push((chain, e.to_string())),
        };
        match t.kind {
            ChainKind::Flat => put(
                t.chain.to_string(),
                &t.path,
                None,
                read_file_head::<H>(&t.path, &genuine),
            ),
            ChainKind::Rotating => {
                // A rotation between reading the generation and the head
                // would anchor the head under the wrong file: the
                // generation must be the same before and after.
                let stable = (0..3).find_map(|_| {
                    let before = crate::chainlog::current_generation(&t.path);
                    let h = read_file_head::<H>(&t.path, &genuine);
                    (crate::chainlog::current_generation(&t.path) == before).then_some((before, h))
                });
                match stable {
                    Some((generation, h)) => put(t.chain.to_string(), &t.path, Some(generation), h),
                    None => put(
                        t.chain.to_string(),
                        &t.path,
                        None,
                        Err(std::io::Error::other(
                            "the log rotated at every read: its generation not known",
                        )),
                    ),
                }
                let manifest = crate::chainlog::manifest_path(&t.path);
                let kind = t.payload_kind.unwrap_or_default();
                let mcheck = |l: &[u8]| crate::chainlog::manifest_line_is_genuine(l, kind, pk);
                let h = read_file_head::<H>(&manifest, &mcheck);
                put(format!("{}.manifest", t.chain), &manifest, None, h);
            }
        }
    }
    now
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
    /// Found by the start's check (`true`), or by the running agent's
    /// anchor (lot 295: a head that went back while it ran).
    pub at_boot: bool,
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
            at_boot: true,
        }
    }

    /// The same finding, made by the running agent (lot 295).
    pub fn at_run_time(mut self) -> Self {
        self.at_boot = false;
        self
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
                "at_boot": self.at_boot,
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

    /// ERROR in the journal, then the signed entry. `true` when the entry
    /// is in the audit chain.
    pub fn attest<K: ChainSigner>(&self, log: Option<&mut AuditLog<K>>) -> bool {
        error!(
            kind = self.kind,
            chain = %self.chain,
            file = %self.file.display(),
            detail = %self.detail,
            "chain integrity: evidence missing or altered — see the runbook (chain verification failed)"
        );
        match log.map(|log| log.append(self.draft())) {
            Some(Ok(_)) => true,
            Some(Err(e)) => {
                warn!(error = %format!("{e:#}"), "attesting a chain finding failed");
                false
            }
            None => false,
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
            if let Anchored::Lost(f) = check_anchored::<H>(h, &prev.ts, targets, pk, false) {
                out.findings.push(f);
            }
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
    /// Archived then dropped by retention: the manifest's signed `Evicted`
    /// row for it says so (the verifier checks every one).
    Evicted,
    /// Lot 295 (BUG08): the archive is gone and no signed `Evicted` row
    /// says retention dropped it.
    Gone(PathBuf),
    /// Generations past what is on disk.
    RolledBack {
        now: u64,
    },
}

/// `evicted(g)`: the manifest holds a genuine `Evicted` row for archive `g`.
fn holder(active: &Path, generation: u64, evicted: &dyn Fn(u64) -> bool) -> Holder {
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
    // Lot 295 (BUG08): an archive below the earliest on disk was taken for
    // evicted — so a foreign `<active>.000009` made a generation deleted
    // with every archive look dropped by retention. Only the manifest's
    // signed row says that; past its tail window (256 KiB) the archive is
    // reported gone, the safe side.
    if evicted(generation) {
        Holder::Evicted
    } else {
        Holder::Gone(archive)
    }
}

/// Whether `tail` (from [`crate::chainlog::manifest_tail_events`]) holds a
/// genuine `Evicted` row for archive `seq`.
fn evicted_in(tail: &[crate::chainlog::ManifestEvent], seq: u64) -> bool {
    tail.iter()
        .any(|e| matches!(e, crate::chainlog::ManifestEvent::Evicted { seq: s, .. } if *s == seq))
}

/// What a head anchored earlier is now.
enum Anchored {
    /// Still where it was: in its file, or in an archive retention dropped
    /// (attested), or of a chain this build no longer anchors.
    Held,
    /// Cut, rewritten, deleted, or its archives removed.
    Lost(ChainFinding),
    /// Not checked (an I/O error, warned).
    Unknown,
}

/// `running`: the check of the running agent's anchor, while the writers
/// run — an archive gone without its `Evicted` row may be a retention in
/// progress (the row follows the unlink): not known yet, the start's check
/// decides.
fn check_anchored<H: ChainHost>(
    h: &AnchoredHead,
    anchored_at: &str,
    targets: &[ChainTarget],
    pk: &VerifyingKey,
    running: bool,
) -> Anchored {
    let base = h.chain.trim_end_matches(".manifest");
    let Some(t) = targets.iter().find(|t| t.chain == base) else {
        return Anchored::Held; // a chain this build no longer anchors
    };
    let path = if h.chain.ends_with(".manifest") {
        crate::chainlog::manifest_path(&t.path)
    } else {
        match (t.kind, h.generation) {
            (ChainKind::Rotating, Some(g)) => {
                let evicted = |seq: u64| {
                    let kind = t.payload_kind.unwrap_or_default();
                    evicted_in(
                        &crate::chainlog::manifest_tail_events::<H>(&t.path, kind, pk),
                        seq,
                    )
                };
                match holder(&t.path, g, &evicted) {
                    Holder::File(p) => p,
                    Holder::Evicted => return Anchored::Held,
                    Holder::Gone(_) if running => return Anchored::Unknown,
                    Holder::Gone(archive) => {
                        return Anchored::Lost(archive_gone(
                            &h.chain,
                            &archive,
                            g,
                            &format!("the head anchored at {anchored_at}"),
                        ))
                    }
                    Holder::RolledBack { now } => {
                        return Anchored::Lost(ChainFinding::new(
                            h.chain.clone(),
                            &t.path,
                            "chain_archives_missing",
                            format!(
                                "the head anchored at {anchored_at} is in generation {g}, but \
                                 only {} archive(s) are on disk: the newest archives were removed",
                                now.saturating_sub(1)
                            ),
                        ))
                    }
                }
            }
            _ => t.path.clone(),
        }
    };
    report_head::<H>(
        &h.chain,
        &path,
        &h.head,
        &format!("anchored at {anchored_at}"),
    )
}

/// Lot 295 (BUG08): archive `g`, which holds a head, is gone, and no signed
/// `Evicted` row says retention dropped it.
fn archive_gone(chain: &str, archive: &Path, g: u64, source: &str) -> ChainFinding {
    ChainFinding::new(
        chain,
        archive,
        "chain_missing",
        format!(
            "archive {g} is gone and the manifest holds no signed Evicted row for it; {source} \
             is in that archive: it was deleted"
        ),
    )
}

fn report_head<H: ChainHost>(chain: &str, path: &Path, head: &FileHead, source: &str) -> Anchored {
    let row = head.seq.map(|s| format!("row {s}, ")).unwrap_or_default();
    let what = format!(
        "the head {source} ends at byte {} ({row}entry_hash {})",
        head.bytes, head.tail_hash
    );
    let finding = match check_head::<H>(path, head) {
        Ok(HeadCheck::Intact) => return Anchored::Held,
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
            return Anchored::Unknown;
        }
    };
    Anchored::Lost(ChainFinding::new(chain, path, finding.0, finding.1))
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
        let source = format!("checkpointed in the manifest (generation {seq})");
        match holder(&t.path, seq, &|g| evicted_in(&tail, g)) {
            Holder::File(p) => {
                if let Anchored::Lost(f) = report_head::<H>(t.chain, &p, &head, &source) {
                    findings.push(f);
                }
            }
            Holder::Evicted => {}
            Holder::Gone(archive) => findings.push(archive_gone(
                t.chain,
                &archive,
                seq,
                &format!("the head {source}"),
            )),
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
    /// Lab PR 249: the time each snapshot is stamped with (the host's
    /// unless [`Self::with_clock`] gave another).
    clock: Arc<dyn crate::clock::Clock>,
    /// Lot 295 (BUG25): `last` is a snapshot this anchor wrote, its heads
    /// compared at every refresh. Not the `previous` one the start read:
    /// the boot check compared that one (and attests what it found).
    own: bool,
    /// Lot 295: the findings of the last refresh not in the audit chain
    /// yet (their heads stay anchored until they are).
    unattested: Vec<ChainFinding>,
    /// Lot 295 (BUG26): the chains whose head was not known at the last
    /// refresh (warned when one becomes so).
    unread: Vec<String>,
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
            clock: Arc::new(crate::clock::SystemClock),
            own: false,
            unattested: Vec::new(),
            unread: Vec::new(),
        }
    }

    /// Lab PR 249: stamp the snapshots with `clock` instead of the host's
    /// (a test's or a replay's: the same head anchor every run).
    pub fn with_clock(mut self, clock: Arc<dyn crate::clock::Clock>) -> Self {
        self.clock = clock;
        self
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

    /// [`Self::refresh_attesting`] with nothing to attest in: a head that
    /// went back stays anchored ([`Self::unattested`]).
    pub fn refresh(&mut self, force: bool, second_key_added: bool) -> Result<Vec<AnchoredHead>> {
        self.refresh_attesting(force, second_key_added, &mut |_| false)
    }

    /// The findings of the last refresh that `attest` did not put in the
    /// audit chain: their heads are still the anchored ones.
    pub fn unattested(&self) -> &[ChainFinding] {
        &self.unattested
    }

    /// Re-read every head; write a snapshot when `force` or one moved
    /// (or the sticky flag turned on). Returns the heads that moved.
    ///
    /// Lot 295 (BUG25, BUG26): a head never leaves the anchor, nor goes
    /// back, without a signed finding. Each head of the last snapshot this
    /// anchor wrote that is not read again as it was is checked first. One
    /// no longer in its file — cut, emptied, rewritten, its file or its
    /// archives removed while the agent ran — is a finding
    /// (`at_boot: false`) handed to `attest`, which signs it and says
    /// whether it is in the audit chain; until it is, the snapshot keeps
    /// that head, so the next start finds the loss too. A head that cannot
    /// be read now (lines that do not verify appended after it,
    /// [`read_file_head`]) stays anchored while it is still in its file.
    pub fn refresh_attesting(
        &mut self,
        force: bool,
        second_key_added: bool,
        attest: &mut dyn FnMut(&ChainFinding) -> bool,
    ) -> Result<Vec<AnchoredHead>> {
        let pk = self.key.verifying_key();
        let mut now = read_heads::<K::Host>(&self.targets, &pk);
        let mut kept: Vec<AnchoredHead> = Vec::new();
        let mut signed = false;
        self.unattested.clear();
        if let Some(last) = &self.last {
            for o in last.heads.iter().filter(|o| !now.heads.contains(o)) {
                match self.check_moved(o, &last.ts, &pk) {
                    Anchored::Held if now.unread(&o.chain) => kept.push(o.clone()),
                    Anchored::Held => {}
                    Anchored::Unknown => kept.push(o.clone()),
                    // the start's check compared the snapshot it read
                    Anchored::Lost(_) if !self.own => {}
                    Anchored::Lost(f) => {
                        let f = f.at_run_time();
                        if attest(&f) {
                            signed = true;
                        } else {
                            kept.push(o.clone());
                            self.unattested.push(f);
                        }
                    }
                }
            }
        }
        if signed {
            // the findings moved the audit chain's head: this snapshot
            // anchors it past them
            now = read_heads::<K::Host>(&self.targets, &pk);
        }
        self.note_unread(&now);
        let mut heads = now.heads;
        for o in kept {
            match heads.iter_mut().find(|h| h.chain == o.chain) {
                Some(h) => *h = o,
                None => heads.push(o),
            }
        }
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
            ts: crate::clock::stamp(self.clock.as_ref()),
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
        self.own = true;
        Ok(moved)
    }

    /// Lot 295 (BUG25): where a head of the last snapshot is now. A
    /// rotating log's head is checked under one generation: a rotation
    /// while it is checked moves it into an archive, and is checked again.
    fn check_moved(&self, o: &AnchoredHead, anchored_at: &str, pk: &VerifyingKey) -> Anchored {
        let generation = || {
            let base = o.chain.trim_end_matches(".manifest");
            self.targets
                .iter()
                .find(|t| t.chain == base && matches!(t.kind, ChainKind::Rotating))
                .map(|t| crate::chainlog::current_generation(&t.path))
        };
        for _ in 0..3 {
            let before = generation();
            // (the writers run once this anchor has written: before, the
            // start's own check, as the boot check did)
            let found = check_anchored::<K::Host>(o, anchored_at, &self.targets, pk, self.own);
            if generation() == before {
                return found;
            }
        }
        Anchored::Unknown
    }

    /// Lot 295 (BUG26): a chain whose head is not known now, warned once
    /// (its anchored head is kept while it is still in its file).
    fn note_unread(&mut self, now: &HeadsNow) {
        for (chain, why) in &now.unread {
            if !self.unread.contains(chain) {
                warn!(chain = %chain, error = %why,
                    "chain head: not known — the anchored head is kept while it is still in its file");
            }
        }
        self.unread = now.unread.iter().map(|(c, _)| c.clone()).collect();
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

    /// Lab PR 256: lines another key appended are their own class in the
    /// background check — `signed_by_another_key`, counted, the first and
    /// the last placed — and a file cut below its anchored head is still
    /// `chain_truncated` at the next start: neither hides or renames the
    /// other, and both stay findings.
    #[test]
    fn lines_of_another_key_and_a_cut_file_are_reported_apart() {
        let dir = TempDir::new().unwrap();
        let k = key(&dir);
        let pk = k.verifying_key();
        let heads = dir.path().join(HEADS_FILE_NAME);
        let active = dir.path().join("t.jsonl");
        let mut log = rotating_log(&active, key(&dir), 1 << 30);
        for n in 0..4 {
            log.append(p(n)).unwrap();
        }
        drop(log);
        let other = TestKey::load_or_bootstrap(&dir.path().join("other.sig.key")).unwrap();
        let mut log = rotating_log(&active, other, 1 << 30);
        for n in 4..7 {
            log.append(p(n)).unwrap();
        }
        drop(log);
        let mut log = rotating_log(&active, key(&dir), 1 << 30);
        for n in 7..9 {
            log.append(p(n)).unwrap();
        }
        drop(log);
        let recent = rotating_target(&active)
            .recent
            .expect("a rotating log's check");
        let err = recent(&active, &pk, BOOT_VERIFY_BYTES).unwrap_err();
        assert!(
            matches!(
                &err,
                crate::chainlog::RecentError::SignedByAnotherKey(l) if l.count == 3
                    && l.checked == 9
                    && l.first.line == Some(5)
                    && l.last.line == Some(7)
            ),
            "{err:?}"
        );
        // Anchored as it is, then its last line cut while the agent is down.
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
        let body = std::fs::read(&active).unwrap();
        let cut = body[..body.len() - 1]
            .iter()
            .rposition(|&c| c == b'\n')
            .unwrap()
            + 1;
        std::fs::write(&active, &body[..cut]).unwrap();
        let found = boot_check::<PortableHost>(&[rotating_target(&active)], &heads, &pk);
        assert!(
            found.findings.iter().any(|f| f.kind == "chain_truncated"),
            "{:?}",
            found.findings
        );
        let err = recent(&active, &pk, BOOT_VERIFY_BYTES).unwrap_err();
        assert_eq!(err.class(), "signed_by_another_key", "{err}");
        assert!(
            matches!(
                &err,
                crate::chainlog::RecentError::SignedByAnotherKey(l) if l.count == 3 && l.checked == 8
            ),
            "{err:?}"
        );
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

    /// Lab PR 249: the head anchor's snapshot carries its clock's time —
    /// the host's by default (between two readings of `Utc::now`), a clock
    /// of the caller's with `with_clock` — and the snapshot verifies.
    #[test]
    fn the_head_snapshot_is_stamped_by_the_anchor_s_clock() {
        let dir = TempDir::new().unwrap();
        let pk = key(&dir).verifying_key();
        let active = dir.path().join("d.jsonl");
        let mut log = rotating_log(&active, key(&dir), 1 << 30);
        log.append(p(0)).unwrap();
        drop(log);
        let read = |heads: &Path| match HeadsStore::read::<PortableHost>(heads, &pk) {
            HeadsRead::Valid(s) => s,
            other => panic!("{other:?}"),
        };
        let fixed = dir.path().join("fixed_heads.json");
        Anchor::new(
            fixed.clone(),
            key(&dir),
            [1; 16],
            vec![rotating_target(&active)],
            None,
            false,
        )
        .with_clock(Arc::new(crate::clock::testing::FixedClock::at(
            "2026-01-01T00:00:42.000007Z",
        )))
        .refresh(true, false)
        .unwrap();
        assert_eq!(read(&fixed).ts, "2026-01-01T00:00:42.000007Z");
        let host = dir.path().join("host_heads.json");
        let before = crate::audit::format_ts(chrono::Utc::now());
        Anchor::new(
            host.clone(),
            key(&dir),
            [1; 16],
            vec![rotating_target(&active)],
            None,
            false,
        )
        .refresh(true, false)
        .unwrap();
        let after = crate::audit::format_ts(chrono::Utc::now());
        let ts = read(&host).ts;
        assert!(before <= ts && ts <= after, "{before} <= {ts} <= {after}");
    }

    // ── lot 295: the anchor's head never leaves it nor goes back without a
    // signed finding (external bug hunt, editions 1.2/1.3: BUG08, BUG25, BUG26) ──

    fn flat_target(path: &Path) -> ChainTarget {
        ChainTarget {
            chain: "canary_access",
            path: path.to_path_buf(),
            kind: ChainKind::Flat,
            genuine: crate::audit::row_is_genuine,
            recent: None,
            full: full_audit,
            payload_kind: None,
        }
    }

    fn cut_last_rows(path: &Path, rows: usize) {
        let body = std::fs::read(path).unwrap();
        let mut end = body.len();
        for _ in 0..rows {
            end = body[..end - 1].iter().rposition(|&c| c == b'\n').unwrap() + 1;
        }
        std::fs::write(path, &body[..end]).unwrap();
    }

    /// BUG08: with the anchored generation (the active file) and every
    /// archive deleted while the agent is down, an empty foreign
    /// `<active>.000009` made `holder` call the anchored generation
    /// "evicted" (below the earliest archive on disk) and the boot check
    /// said nothing. Only a signed `Evicted` row says that now.
    #[test]
    fn fake_higher_archive_hides_the_deleted_anchored_generation() {
        let dir = TempDir::new().unwrap();
        let k = key(&dir);
        let pk = k.verifying_key();
        let heads = dir.path().join(HEADS_FILE_NAME);
        let active = dir.path().join("e.jsonl");
        let mut log = rotating_log(&active, key(&dir), 300);
        let mut n = 0;
        while crate::chainlog::current_generation(&active) < 5 {
            log.append(p(n)).unwrap();
            n += 1;
            assert!(n < 500);
        }
        drop(log);
        assert!(std::fs::metadata(&active).unwrap().len() > 0);
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
        let t = || vec![rotating_target(&active)];
        assert!(boot_check::<PortableHost>(&t(), &heads, &pk)
            .findings
            .is_empty());
        // agent down: the active file and every archive deleted
        for s in 1..=4u64 {
            std::fs::remove_file(crate::chainlog::archive_path_for(&active, s)).unwrap();
        }
        std::fs::remove_file(&active).unwrap();
        // control: without the foreign name the deletion is found
        let control = boot_check::<PortableHost>(&t(), &heads, &pk);
        assert!(
            control
                .findings
                .iter()
                .any(|f| f.kind == "chain_archives_missing"),
            "{:?}",
            control.findings
        );
        // an empty foreign `<active>.000009`: generation 5 is below the
        // earliest archive on disk, and no signed `Evicted` row says
        // retention dropped it (it was taken for evicted)
        std::fs::write(crate::chainlog::archive_path_for(&active, 9), b"").unwrap();
        let tail = crate::chainlog::manifest_tail_events::<PortableHost>(&active, "test_log", &pk);
        assert!(matches!(
            holder(&active, 5, &|g| evicted_in(&tail, g)),
            Holder::Gone(_)
        ));
        // the full verifier (nn-admin chain verify) still refuses the set
        assert!((rotating_target(&active).full)(&active, &pk).is_err());
        let found = boot_check::<PortableHost>(&t(), &heads, &pk);
        assert!(
            !found.findings.is_empty(),
            "the anchored generation 5 was deleted, no Evicted row attests it, yet the boot check \
             is silent"
        );
    }

    /// BUG25 (rotating log, the report's case): the active file emptied
    /// while the agent runs; the periodic refresh signed a snapshot without
    /// its head and the next boot found nothing. With nothing to sign the
    /// finding in, the anchored head stays: the next boot finds the loss.
    #[test]
    fn active_emptied_while_running_is_reanchored_silently() {
        let dir = TempDir::new().unwrap();
        let k = key(&dir);
        let pk = k.verifying_key();
        let heads = dir.path().join(HEADS_FILE_NAME);
        let active = dir.path().join("b.jsonl");
        let mut log = rotating_log(&active, key(&dir), 1 << 30);
        for n in 0..3 {
            log.append(p(n)).unwrap();
        }
        drop(log);
        let mut anchor = Anchor::new(
            heads.clone(),
            k,
            [1; 16],
            vec![rotating_target(&active)],
            None,
            false,
        );
        anchor.refresh(true, false).unwrap();
        assert!(
            boot_check::<PortableHost>(&[rotating_target(&active)], &heads, &pk)
                .findings
                .is_empty()
        );
        std::fs::write(&active, b"").unwrap(); // emptied while the agent runs
        anchor.refresh(false, false).unwrap(); // the ANCHOR_SECS tick
        assert_eq!(
            anchor
                .unattested()
                .iter()
                .map(|f| (f.kind, f.at_boot))
                .collect::<Vec<_>>(),
            [("chain_truncated", false)]
        );
        let found = boot_check::<PortableHost>(&[rotating_target(&active)], &heads, &pk);
        assert!(
            found.findings.iter().any(|f| f.kind == "chain_truncated"),
            "the anchored head was replaced without a finding: {:?}",
            found.findings
        );
    }

    /// BUG25 (flat chain): rows cut from a flat chain while the agent runs
    /// were re-anchored at the next tick, the boot check silent. The cut is
    /// a finding of the running anchor now: until it is signed the anchored
    /// head stays (the next boot finds the cut too); once it is, the
    /// shorter head is anchored, the next boot is quiet, and it is not
    /// signed again.
    #[test]
    fn flat_chain_cut_while_running_is_reanchored_silently() {
        let dir = TempDir::new().unwrap();
        let k = key(&dir);
        let pk = k.verifying_key();
        let heads = dir.path().join(HEADS_FILE_NAME);
        let path = dir.path().join("flat.log");
        let mut log = AuditLog::open(&path, key(&dir), [1; 16]).unwrap();
        for n in 0..5 {
            log.append(draft(n)).unwrap();
        }
        drop(log);
        let mut anchor = Anchor::new(
            heads.clone(),
            k,
            [1; 16],
            vec![flat_target(&path)],
            None,
            false,
        );
        anchor.refresh(true, false).unwrap();
        cut_last_rows(&path, 2); // rows 3 and 4 removed while running
        let mut offered = Vec::new();
        let moved = anchor
            .refresh_attesting(false, false, &mut |f| {
                offered.push(f.clone());
                false // the audit chain did not take it
            })
            .unwrap();
        assert!(moved.is_empty(), "not signed: the anchored head stays");
        assert_eq!(
            offered
                .iter()
                .map(|f| (f.chain.as_str(), f.kind, f.at_boot))
                .collect::<Vec<_>>(),
            [("canary_access", "chain_truncated", false)]
        );
        assert!(offered[0].detail.contains("row 4"), "{:?}", offered[0]);
        assert_eq!(anchor.unattested(), &offered[..]);
        let found = boot_check::<PortableHost>(&[flat_target(&path)], &heads, &pk);
        assert!(
            found.findings.iter().any(|f| f.kind == "chain_truncated"),
            "rows cut below the anchored head, re-anchored without a finding: {:?}",
            found.findings
        );
        // signed: the shorter head is anchored
        let mut signed = Vec::new();
        let moved = anchor
            .refresh_attesting(false, false, &mut |f| {
                signed.push(f.kind);
                true
            })
            .unwrap();
        assert_eq!(signed, ["chain_truncated"]);
        assert_eq!(moved.len(), 1, "the shorter head is anchored as a move");
        assert_eq!(moved[0].head.seq, Some(2));
        assert!(anchor.unattested().is_empty());
        assert!(
            boot_check::<PortableHost>(&[flat_target(&path)], &heads, &pk)
                .findings
                .is_empty()
        );
        let again = anchor
            .refresh_attesting(true, false, &mut |f| panic!("signed twice: {f:?}"))
            .unwrap();
        assert!(again.is_empty());
    }

    /// BUG26 (the report's case): 64 chain-shaped lines that do not verify
    /// after the genuine head: `read_file_head` returned `Ok(None)`, as for
    /// an empty file. The head is not known: an error, never "no head".
    #[test]
    fn forged_tail_lines_hide_the_head() {
        let dir = TempDir::new().unwrap();
        let k = key(&dir);
        let pk = k.verifying_key();
        let path = dir.path().join("audit.log");
        let mut log = AuditLog::open(&path, k, [1; 16]).unwrap();
        for n in 0..5 {
            log.append(draft(n)).unwrap();
        }
        let ok = |l: &[u8]| crate::audit::row_is_genuine(l, &pk);
        let before = read_file_head::<PortableHost>(&path, &ok).unwrap().unwrap();
        for _ in 0..MAX_HEAD_PROBES {
            append_raw(&path, b"{\"entry_hash\":\"");
            append_raw(&path, "ab".repeat(32).as_bytes());
            append_raw(&path, b"\"}\n");
        }
        let after = read_file_head::<PortableHost>(&path, &ok);
        // a fix may return the head or an error the caller warns about;
        // `Ok(None)` ("no head", as for an empty file) is the defect
        assert!(
            !matches!(after, Ok(None)),
            "the genuine head ({before:?}) is in the window, yet the file reads as one without a \
             head: {after:?}"
        );
    }

    /// BUG26 (effect): the forged tail is in place when the stop snapshot
    /// is taken; the chain left the anchor, and a cut made while the agent
    /// was down was not found at the next boot. The anchored head is kept
    /// while it is still in its file.
    #[test]
    fn forged_tail_then_cut_while_down_is_not_found_at_boot() {
        let dir = TempDir::new().unwrap();
        let k = key(&dir);
        let pk = k.verifying_key();
        let heads = dir.path().join(HEADS_FILE_NAME);
        let path = dir.path().join("flat.log");
        let mut log = AuditLog::open(&path, key(&dir), [1; 16]).unwrap();
        for n in 0..5 {
            log.append(draft(n)).unwrap();
        }
        drop(log);
        let mut anchor = Anchor::new(
            heads.clone(),
            k,
            [1; 16],
            vec![flat_target(&path)],
            None,
            false,
        );
        anchor.refresh(true, false).unwrap();
        let genuine_len = std::fs::metadata(&path).unwrap().len();
        for _ in 0..=MAX_HEAD_PROBES {
            append_raw(&path, b"{\"entry_hash\":\"");
            append_raw(&path, "ab".repeat(32).as_bytes());
            append_raw(&path, b"\"}\n");
        }
        anchor.refresh(true, false).unwrap(); // the snapshot at stop
                                              // agent down: forged lines and the last two genuine rows removed
        let body = std::fs::read(&path).unwrap();
        std::fs::write(&path, &body[..genuine_len as usize]).unwrap();
        cut_last_rows(&path, 2);
        let found = boot_check::<PortableHost>(&[flat_target(&path)], &heads, &pk);
        assert!(
            found.findings.iter().any(|f| f.kind == "chain_truncated"),
            "the chain left the anchor and its cut is not found: {:?}",
            found.findings
        );
    }

    fn flat_named(chain: &'static str, path: &Path) -> ChainTarget {
        ChainTarget {
            chain,
            ..flat_target(path)
        }
    }

    fn rotating_log_kept(
        path: &Path,
        key: TestKey,
        cap: u64,
        max_archives: usize,
    ) -> crate::chainlog::RotatingChainLog<P, TestKey> {
        crate::chainlog::RotatingChainLog::<P, _>::open(
            path,
            key,
            crate::chainlog::RotationConfig {
                size_cap_bytes: cap,
                max_archives,
                file_mode: 0o600,
            },
            Arc::new(crate::chainlog::NoProtection),
        )
        .unwrap()
    }

    /// BUG08, the positive control: retention dropping the anchored
    /// generation (its signed `Evicted` row in the manifest) stays silent at
    /// the next boot, and the full verification agrees.
    #[test]
    fn a_genuine_eviction_of_the_anchored_generation_stays_silent() {
        let dir = TempDir::new().unwrap();
        let k = key(&dir);
        let pk = k.verifying_key();
        let heads = dir.path().join(HEADS_FILE_NAME);
        let active = dir.path().join("g.jsonl");
        let mut log = rotating_log_kept(&active, key(&dir), 300, 2);
        let mut n = 0;
        while crate::chainlog::current_generation(&active) < 3 {
            log.append(p(n)).unwrap();
            n += 1;
        }
        log.append(p(n)).unwrap();
        n += 1;
        let g = crate::chainlog::current_generation(&active);
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
        // the agent runs on: generation g sealed, then dropped by retention
        while crate::chainlog::current_generation(&active) <= g
            || crate::chainlog::archive_path_for(&active, g).exists()
        {
            log.append(p(n)).unwrap();
            n += 1;
            assert!(n < 1000);
        }
        drop(log);
        let tail = crate::chainlog::manifest_tail_events::<PortableHost>(&active, "test_log", &pk);
        assert!(evicted_in(&tail, g), "{tail:?}");
        let now = crate::chainlog::current_generation(&active);
        assert!(
            !evicted_in(&tail, now),
            "the active file's generation: {tail:?}"
        );
        assert!(matches!(
            holder(&active, g, &|s| evicted_in(&tail, s)),
            Holder::Evicted
        ));
        let found = boot_check::<PortableHost>(&[rotating_target(&active)], &heads, &pk);
        assert!(found.findings.is_empty(), "{:?}", found.findings);
        assert!((rotating_target(&active).full)(&active, &pk).is_ok());
    }

    /// BUG25, the quiet the fix must keep: chains that only grow, rotate
    /// and drop archives by retention while the agent runs give no finding
    /// at any tick, and every tick anchors their new heads.
    #[test]
    fn chains_that_only_grow_and_rotate_give_no_finding() {
        let dir = TempDir::new().unwrap();
        let k = key(&dir);
        let pk = k.verifying_key();
        let heads = dir.path().join(HEADS_FILE_NAME);
        let active = dir.path().join("q.jsonl");
        let flat = dir.path().join("audit.log");
        let mut log = rotating_log_kept(&active, key(&dir), 400, 2);
        let mut audit = AuditLog::open(&flat, key(&dir), [1; 16]).unwrap();
        let targets = || vec![flat_named("audit", &flat), rotating_target(&active)];
        let mut anchor = Anchor::new(heads.clone(), k, [1; 16], targets(), None, false);
        log.append(p(0)).unwrap();
        audit.append(draft(0)).unwrap();
        anchor.refresh(true, false).unwrap();
        let mut n = 1;
        for round in 0..6 {
            // a few rows (round 3: enough for the anchored generation to be
            // sealed and dropped by retention between two ticks)
            let rows = if round == 3 { 40 } else { 3 };
            for _ in 0..rows {
                log.append(p(n)).unwrap();
                audit.append(draft(n as u32)).unwrap();
                n += 1;
            }
            let moved = anchor
                .refresh_attesting(false, false, &mut |f| panic!("round {round}: {f:?}"))
                .unwrap();
            assert!(!moved.is_empty(), "round {round}: the heads moved");
            assert!(anchor.unattested().is_empty());
            let anchored = match HeadsStore::read::<PortableHost>(&heads, &pk) {
                HeadsRead::Valid(s) => s,
                other => panic!("{other:?}"),
            };
            let data = anchored
                .heads
                .iter()
                .find(|h| h.chain == "test_log")
                .expect("the log's head");
            assert_eq!(
                data.generation,
                Some(crate::chainlog::current_generation(&active)),
                "round {round}: the new generation's head, not the old one kept"
            );
        }
        assert!(crate::chainlog::current_generation(&active) > 4);
        assert!(boot_check::<PortableHost>(&targets(), &heads, &pk)
            .findings
            .is_empty());
    }

    /// BUG25: the running anchor's finding is signed before the head is
    /// replaced, and the snapshot written then anchors the audit chain past
    /// the finding's own row (cut while the agent is down, it is found).
    #[test]
    fn a_cut_found_while_running_is_signed_and_its_row_anchored() {
        let dir = TempDir::new().unwrap();
        let k = key(&dir);
        let pk = k.verifying_key();
        let heads = dir.path().join(HEADS_FILE_NAME);
        let audit_path = dir.path().join("audit.log");
        let canary = dir.path().join("canary_access.jsonl");
        let mut audit = AuditLog::open(&audit_path, key(&dir), [1; 16]).unwrap();
        let mut other = AuditLog::open(&canary, key(&dir), [2; 16]).unwrap();
        for n in 0..4 {
            audit.append(draft(n)).unwrap();
            other.append(draft(n)).unwrap();
        }
        drop(other);
        let targets = || vec![flat_named("audit", &audit_path), flat_target(&canary)];
        let mut anchor = Anchor::new(heads.clone(), k, [1; 16], targets(), None, false);
        anchor.refresh(true, false).unwrap();
        cut_last_rows(&canary, 1);
        anchor
            .refresh_attesting(false, false, &mut |f| f.attest(Some(&mut audit)))
            .unwrap();
        let body = std::fs::read_to_string(&audit_path).unwrap();
        let last: serde_json::Value = serde_json::from_str(body.lines().last().unwrap()).unwrap();
        assert_eq!(last["op"], crate::audit::INTEGRITY_DRIFT_OP);
        assert_eq!(last["extra"]["kind"], "chain_truncated");
        assert_eq!(last["extra"]["chain"], "canary_access");
        assert_eq!(last["extra"]["at_boot"], false);
        let anchored = match HeadsStore::read::<PortableHost>(&heads, &pk) {
            HeadsRead::Valid(s) => s,
            other => panic!("{other:?}"),
        };
        let audit_head = anchored.heads.iter().find(|h| h.chain == "audit").unwrap();
        assert_eq!(
            audit_head.head.tail_hash,
            last["entry_hash"].as_str().unwrap(),
            "the snapshot anchors the finding's row"
        );
        assert!(boot_check::<PortableHost>(&targets(), &heads, &pk)
            .findings
            .is_empty());
        // the finding's row cut while the agent is down: found
        cut_last_rows(&audit_path, 1);
        let found = boot_check::<PortableHost>(&targets(), &heads, &pk);
        assert!(
            found
                .findings
                .iter()
                .any(|f| f.chain == "audit" && f.kind == "chain_truncated"),
            "{:?}",
            found.findings
        );
    }

    /// BUG25: the snapshot the start read was compared by the boot check
    /// (which signs what it found): the start's anchor does not sign it
    /// again, and anchors the files as they are.
    #[test]
    fn the_start_s_own_findings_are_not_signed_again_by_its_anchor() {
        let dir = TempDir::new().unwrap();
        let k = key(&dir);
        let pk = k.verifying_key();
        let heads = dir.path().join(HEADS_FILE_NAME);
        let path = dir.path().join("flat.log");
        let mut log = AuditLog::open(&path, key(&dir), [1; 16]).unwrap();
        for n in 0..5 {
            log.append(draft(n)).unwrap();
        }
        drop(log);
        Anchor::new(
            heads.clone(),
            key(&dir),
            [1; 16],
            vec![flat_target(&path)],
            None,
            false,
        )
        .refresh(true, false)
        .unwrap();
        cut_last_rows(&path, 2); // while the agent is down
        let boot = boot_check::<PortableHost>(&[flat_target(&path)], &heads, &pk);
        assert_eq!(boot.findings.len(), 1, "{:?}", boot.findings);
        let mut start = Anchor::new(
            heads.clone(),
            k,
            [1; 16],
            vec![flat_target(&path)],
            boot.previous.clone(),
            true,
        );
        let moved = start
            .refresh_attesting(true, false, &mut |f| panic!("signed again: {f:?}"))
            .unwrap();
        assert_eq!(moved.len(), 1, "the files as they are");
        assert!(
            boot_check::<PortableHost>(&[flat_target(&path)], &heads, &pk)
                .findings
                .is_empty()
        );
    }

    /// BUG25: an archive that holds the anchored head, older than the
    /// newest, deleted while the agent runs without a signed `Evicted` row,
    /// may be a retention in progress (the row follows the unlink): no
    /// finding of the running anchor, the head stays anchored, and the next
    /// start reports it. The newest archive deleted is a finding at once
    /// (retention never drops it: the generation goes back).
    #[test]
    fn an_archive_deleted_while_running_is_left_to_the_next_start() {
        let dir = TempDir::new().unwrap();
        let k = key(&dir);
        let pk = k.verifying_key();
        let heads = dir.path().join(HEADS_FILE_NAME);
        let active = dir.path().join("r.jsonl");
        let mut log = rotating_log(&active, key(&dir), 400);
        log.append(p(0)).unwrap();
        let mut anchor = Anchor::new(
            heads.clone(),
            k,
            [1; 16],
            vec![rotating_target(&active)],
            None,
            false,
        );
        anchor.refresh(true, false).unwrap();
        let g = crate::chainlog::current_generation(&active);
        let mut n = 1;
        while crate::chainlog::current_generation(&active) < g + 3 {
            log.append(p(n)).unwrap();
            n += 1;
        }
        drop(log);
        std::fs::remove_file(crate::chainlog::archive_path_for(&active, g)).unwrap();
        anchor
            .refresh_attesting(false, false, &mut |f| panic!("{f:?}"))
            .unwrap();
        // (the next tick still waits for the row, and the head stays)
        anchor
            .refresh_attesting(true, false, &mut |f| panic!("{f:?}"))
            .unwrap();
        let anchored = match HeadsStore::read::<PortableHost>(&heads, &pk) {
            HeadsRead::Valid(s) => s,
            other => panic!("{other:?}"),
        };
        assert!(
            anchored
                .heads
                .iter()
                .any(|h| h.chain == "test_log" && h.generation == Some(g)),
            "{anchored:?}"
        );
        let found = boot_check::<PortableHost>(&[rotating_target(&active)], &heads, &pk);
        assert!(
            found
                .findings
                .iter()
                .any(|f| f.kind == "chain_missing" && f.detail.contains("no signed Evicted row")),
            "{:?}",
            found.findings
        );
        // that start's anchor takes the files as they are: the start after
        // it is quiet (the start's check signed the loss once)
        Anchor::new(
            heads.clone(),
            key(&dir),
            [1; 16],
            vec![rotating_target(&active)],
            found.previous.clone(),
            true,
        )
        .refresh_attesting(true, false, &mut |f| panic!("signed again: {f:?}"))
        .unwrap();
        let again = boot_check::<PortableHost>(&[rotating_target(&active)], &heads, &pk);
        assert!(
            !again
                .findings
                .iter()
                .any(|f| f.detail.contains("the head anchored at")),
            "{:?}",
            again.findings
        );
        // the newest archive deleted while the agent runs, the anchored
        // head in it: a finding of the running anchor
        let active = dir.path().join("s.jsonl");
        let mut log = rotating_log(&active, key(&dir), 400);
        log.append(p(0)).unwrap();
        let mut anchor = Anchor::new(
            dir.path().join("s_heads.json"),
            key(&dir),
            [1; 16],
            vec![rotating_target(&active)],
            None,
            false,
        );
        anchor.refresh(true, false).unwrap();
        let g = crate::chainlog::current_generation(&active);
        let mut n = 1;
        while crate::chainlog::current_generation(&active) == g {
            log.append(p(n)).unwrap();
            n += 1;
        }
        drop(log);
        std::fs::remove_file(crate::chainlog::archive_path_for(&active, g)).unwrap();
        let mut offered = Vec::new();
        anchor
            .refresh_attesting(false, false, &mut |f| {
                offered.push(f.kind);
                true
            })
            .unwrap();
        assert_eq!(offered.len(), 1, "{offered:?}");
    }

    /// BUG26: the head past the search's window — more than
    /// `HEAD_WINDOW_MAX` bytes of lines that are not the chain's after it —
    /// is not known (an error, not "no head"), and the anchor keeps it while
    /// it is in its file. A small file with no genuine line has no head.
    #[test]
    fn junk_past_the_window_after_the_head_is_not_a_file_without_a_head() {
        let dir = TempDir::new().unwrap();
        let k = key(&dir);
        let pk = k.verifying_key();
        let heads = dir.path().join(HEADS_FILE_NAME);
        let path = dir.path().join("flat.log");
        let mut log = AuditLog::open(&path, key(&dir), [1; 16]).unwrap();
        for n in 0..3 {
            log.append(draft(n)).unwrap();
        }
        drop(log);
        let mut anchor = Anchor::new(
            heads.clone(),
            k,
            [1; 16],
            vec![flat_target(&path)],
            None,
            false,
        );
        anchor.refresh(true, false).unwrap();
        // (the window grows by 4 up to the first size past HEAD_WINDOW_MAX:
        // 16 MiB)
        let line = format!("{}\n", "x".repeat(1023));
        let junk = line.repeat((2 * HEAD_WINDOW_MAX / 1024) as usize + 2);
        append_raw(&path, junk.as_bytes());
        let ok = |l: &[u8]| crate::audit::row_is_genuine(l, &pk);
        let read = read_file_head::<PortableHost>(&path, &ok);
        assert!(
            matches!(&read, Err(e) if e.kind() == std::io::ErrorKind::InvalidData),
            "{read:?}"
        );
        assert!(anchor
            .refresh_attesting(true, false, &mut |f| panic!("{f:?}"))
            .unwrap()
            .is_empty());
        let body = std::fs::read(&path).unwrap();
        let genuine = body.len() - junk.len();
        std::fs::write(&path, &body[..genuine]).unwrap();
        cut_last_rows(&path, 1);
        let found = boot_check::<PortableHost>(&[flat_target(&path)], &heads, &pk);
        assert!(
            found.findings.iter().any(|f| f.kind == "chain_truncated"),
            "{:?}",
            found.findings
        );
        // a whole file read, no genuine line in it: no head
        let forged = dir.path().join("forged.log");
        for _ in 0..3 {
            append_raw_create(&forged, b"{\"entry_hash\":\"");
            append_raw_create(&forged, "ab".repeat(32).as_bytes());
            append_raw_create(&forged, b"\"}\n");
        }
        assert_eq!(read_file_head::<PortableHost>(&forged, &ok).unwrap(), None);
    }

    /// BUG08 (the manifest's checkpoint, no snapshot to compare): the
    /// checkpointed generation deleted with every archive while the agent
    /// is down, and a foreign `<active>.000009` planted, is still found.
    #[test]
    fn a_fake_higher_archive_does_not_hide_the_checkpointed_generation() {
        let dir = TempDir::new().unwrap();
        let pk = key(&dir).verifying_key();
        let heads = dir.path().join(HEADS_FILE_NAME);
        let active = dir.path().join("h.jsonl");
        let mut log = rotating_log(&active, key(&dir), 300);
        let mut n = 0;
        while crate::chainlog::current_generation(&active) < 5 {
            log.append(p(n)).unwrap();
            n += 1;
        }
        log.append(p(n)).unwrap();
        drop(log);
        drop(rotating_log(&active, key(&dir), 300)); // the open's checkpoint
        let tail = crate::chainlog::manifest_tail_events::<PortableHost>(&active, "test_log", &pk);
        let checkpointed = tail
            .iter()
            .find_map(|e| match e {
                crate::chainlog::ManifestEvent::ActiveCheckpoint { seq, .. } => Some(*seq),
                _ => None,
            })
            .expect("a checkpoint");
        assert_eq!(checkpointed, crate::chainlog::current_generation(&active));
        for s in 1..checkpointed {
            std::fs::remove_file(crate::chainlog::archive_path_for(&active, s)).unwrap();
        }
        std::fs::remove_file(&active).unwrap();
        std::fs::write(
            crate::chainlog::archive_path_for(&active, checkpointed + 4),
            b"",
        )
        .unwrap();
        let found = boot_check::<PortableHost>(&[rotating_target(&active)], &heads, &pk);
        let want = format!("checkpointed in the manifest (generation {checkpointed})");
        assert!(
            found
                .findings
                .iter()
                .any(|f| f.kind == "chain_missing" && f.detail.contains(&want)),
            "{:?}",
            found.findings
        );
    }

    fn append_raw_create(path: &Path, bytes: &[u8]) {
        use std::io::Write;
        let mut f = OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .unwrap();
        f.write_all(bytes).unwrap();
    }
}
