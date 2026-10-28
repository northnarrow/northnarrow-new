//! Tappa 9.5 (K3) — canary access log: chained signed JSONL
//! of every canary trip.
//!
//! Persists to `/var/lib/northnarrow/canary_access.jsonl`
//! (Tappa 7 LSM-protected via the K7 `STATE_PROTECTED_FILES`
//! extension). DISTINCT chain from the K2
//! `canaries.jsonl` registry — the registry captures
//! deployment lifecycle (deploy / burn / refresh), the access
//! log captures TRIP events. The split keeps each chain
//! single-purpose + makes operator forensic queries cleaner
//! (`jq` on trips alone).
//!
//! Same hash-chain + signature shape as the Tappa 8 audit log
//! plus Tappa 9 baseline/drift plus K2 registry chains:
//! verification reuses the same `prev_hash` / `entry_hash` /
//! `agent_sig` triple primitives.
//!
//! ## Single-trip semantics interaction (§12 Q2 lock-in)
//!
//! The K3 detector calls
//! [`CanaryAccessDb::append`] on EVERY observed canary
//! access — including repeat accesses to an already-tripped
//! canary. The chain captures ALL accesses for forensic
//! completeness; the rule-engine re-fire suppression lives
//! in `Registry::mark_tripped`'s idempotent return value
//! (only the FIRST access fires NN-L-CANARY-* + posture
//! transition; subsequent accesses log to this chain but
//! don't re-fire). This split — "chain always, rule sometimes"
//! — mirrors Tappa 9 §6.5 Q4 lock-in: evidence preservation
//! is non-negotiable; downstream throttling is the rule-
//! engine's concern.

use std::fs::OpenOptions;
use std::io::{BufReader, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use anyhow::{anyhow, Context, Result};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use chrono::{DateTime, Utc};
use ed25519_dalek::{Signature, VerifyingKey};
use nn_model::{CanaryAccessKind, CanaryTypeTag};
use serde::{Deserialize, Serialize};

use crate::audit::{AgentSigningKey, GENESIS_PREV_HASH};

/// Default deploy location of the chained access log. Sibling
/// to the K2 registry under `/var/lib/northnarrow/`.
pub const DEFAULT_ACCESS_LOG_PATH: &str = "/var/lib/northnarrow/canary_access.jsonl";

/// File mode for the persisted access log: root only (external audit
/// EVD-019, [`crate::chainlog::STATE_LOG_FILE_MODE`]). Operators read it
/// with `sudo` or `nn-admin`.
const ACCESS_LOG_FILE_MODE: u32 = crate::chainlog::STATE_LOG_FILE_MODE;

// ── on-disk schema ──────────────────────────────────────────────────

/// One on-disk JSONL row per design §4.3. Field order MATTERS
/// for the `entry_hash` computation: `serde_json` preserves
/// struct field declaration order on serialisation, so any
/// reorder is a chain-format break.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CanaryAccessEntry {
    /// ISO-8601 UTC timestamp of the access. Same fixed-width
    /// format as Tappa 8 audit + Tappa 9 baseline/drift +
    /// K2 registry chains.
    pub ts: String,
    /// References [`crate::canary::registry::CanaryToken::canary_id`].
    pub canary_id: String,
    /// Operator-supplied canary name (cached on this row so an
    /// off-host audit reader doesn't need to cross-reference
    /// `canaries.jsonl` for the friendly label).
    pub canary_name: String,
    /// Canary kind that tripped — drives K5 rule selection.
    pub canary_type: CanaryTypeTag,
    /// What the agent observed.
    pub access_kind: CanaryAccessKind,
    /// Process triple at access time.
    pub accessor_pid: u32,
    pub accessor_uid: u32,
    pub accessor_comm: String,
    /// `/proc/<pid>/exe` of the accessor if userland resolved
    /// it at detect time. Best-effort.
    pub accessor_exe: Option<String>,
    /// Whether THIS access is the first trip for this canary
    /// (per `Registry::mark_tripped` returning `true`). The
    /// rule engine only fires on `first_trip = true`; subsequent
    /// accesses (`false`) log here for forensics but stay quiet
    /// per §12 Q2 single-trip lock-in.
    pub first_trip: bool,
    /// Chain integrity (Tappa 8 B1 shape).
    pub agent_id: String,
    /// External audit NN-AUD-174: the row's 0-based position in the file,
    /// on rows written from lab PR 160 on (pre-image domain-tagged with
    /// [`crate::chain_anchor::CANARY_ACCESS_DOMAIN_V2`]); absent on older
    /// rows, which keep their bytes and pre-image.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub seq: Option<u64>,
    pub prev_hash: String,
    pub entry_hash: String,
    pub agent_sig: String,
}

/// Operator-supplied fields for [`CanaryAccessDb::append`]: nn-core's
/// since the canary detector, which fills them, moved there (R08b, lab PR
/// 251).
pub use nn_core::canary::host::CanaryAccessDraft;

// ── access log ──────────────────────────────────────────────────────

/// Append-only writer for the canary access log. Holds the
/// [`AgentSigningKey`] in memory + tracks the chain tail-hash
/// so each `append` produces a well-chained next row. Same
/// shape as [`AuditLog`](nn_evidence::audit::AuditLog) + Tappa 9 C3 +
/// K2 `Registry`.
pub struct CanaryAccessDb {
    path: PathBuf,
    key: AgentSigningKey,
    agent_id: [u8; 16],
    last_hash: String,
    tail_repair: Option<crate::chainlog::TailRepair>,
    skipped_lines: usize,
    /// External audit NN-AUD-174: rows in the file (the next `seq`) and
    /// what the open's verification of the tail found.
    rows: u64,
    chain_findings: Vec<crate::chain_anchor::ChainFinding>,
}

/// External audit NN-AUD-174: rows verified at open, from the end. The log
/// is never rotated, so a full check at every boot would grow with it;
/// `nn-admin chain verify --log canary-access` checks it whole.
pub const OPEN_VERIFY_ROWS: usize = 256;

impl CanaryAccessDb {
    /// Open `path` for append, walk any existing rows to
    /// recover `last_hash`. Missing file → empty chain
    /// (`last_hash = GENESIS_PREV_HASH`). K7 deploy bootstrap
    /// is responsible for ensuring the parent dir exists
    /// with the right mode.
    pub fn open(path: &Path, key: AgentSigningKey, agent_id: [u8; 16]) -> Result<Self> {
        // External audit DEC-006: a torn last write is repaired; an
        // unreadable line elsewhere is skipped and reported instead of
        // disabling the canary subsystem.
        let tail_repair = crate::chainlog::repair_torn_tail(path, |l| {
            serde_json::from_slice::<CanaryAccessEntry>(l).is_ok()
        })?;
        let read = read_tail_hash(path, &key.verifying_key())?;
        Ok(Self {
            // review 44: appends go through a directory fd taken now
            path: crate::anchored::anchor(path),
            key,
            agent_id,
            last_hash: read.last_hash,
            tail_repair,
            skipped_lines: read.skipped,
            rows: read.rows,
            chain_findings: read.findings,
        })
    }

    /// External audit NN-AUD-174: what the open's verification found, for
    /// the caller to attest once.
    pub fn take_chain_findings(&mut self) -> Vec<crate::chain_anchor::ChainFinding> {
        std::mem::take(&mut self.chain_findings)
    }

    /// What the open found wrong, for the caller to attest once.
    pub fn take_open_findings(&mut self) -> (Option<crate::chainlog::TailRepair>, usize) {
        (
            self.tail_repair.take(),
            std::mem::take(&mut self.skipped_lines),
        )
    }

    /// Append one access entry. Computes timestamp + chain
    /// hash + signature, writes one `\n`-terminated JSON line
    /// via `O_APPEND` + fsync, advances the in-memory tail.
    /// On success returns the entry as persisted (so the K3
    /// detector can read `entry.entry_hash` to populate
    /// `Registry::mark_tripped(canary_id, access_hash)` for
    /// cross-chain reference).
    pub fn append(&mut self, draft: CanaryAccessDraft) -> Result<CanaryAccessEntry> {
        let entry = build_signed_entry(
            &draft,
            &self.key,
            &self.agent_id,
            &self.last_hash,
            self.rows,
        )?;
        let mut line = serde_json::to_string(&entry)
            .map_err(|e| anyhow!("serialising canary access entry: {e}"))?;
        line.push('\n');
        crate::canary::chain_lines::check_row_len(&line)?;
        let mut f = OpenOptions::new()
            .create(true)
            .append(true)
            .mode(ACCESS_LOG_FILE_MODE)
            .open(&self.path)
            .with_context(|| {
                format!(
                    "opening canary access log {} for append",
                    self.path.display()
                )
            })?;
        f.write_all(line.as_bytes())
            .with_context(|| format!("appending canary access entry to {}", self.path.display()))?;
        f.sync_all()
            .with_context(|| format!("fsync {}", self.path.display()))?;
        self.last_hash = entry.entry_hash.clone();
        self.rows += 1;
        Ok(entry)
    }

    /// Tail hash an auditor would chain the NEXT row off.
    pub fn last_hash(&self) -> &str {
        &self.last_hash
    }
}

// ── chain helpers ───────────────────────────────────────────────────

/// What [`read_tail_hash`] recovers.
struct TailRead {
    last_hash: String,
    skipped: usize,
    rows: u64,
    findings: Vec<crate::chain_anchor::ChainFinding>,
}

/// Walk the log for its tail, its row count and its row numbers (no
/// signature work), then verify the last [`OPEN_VERIFY_ROWS`] rows: hash,
/// signature, link (external audit NN-AUD-174). The chain continues from
/// the newest row that verifies; what does not is reported.
fn read_tail_hash(path: &Path, pubkey: &VerifyingKey) -> Result<TailRead> {
    let mut seq = crate::chain_anchor::RowSeq::default();
    let f = match OpenOptions::new().read(true).open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Ok(TailRead {
                last_hash: GENESIS_PREV_HASH.to_string(),
                skipped: 0,
                rows: 0,
                findings: Vec::new(),
            });
        }
        Err(e) => return Err(anyhow!(e).context(format!("reading {}", path.display()))),
    };
    // External audit DEC-012 (lab PR 178): a line over the cap or not
    // UTF-8 is skipped and counted like one that does not parse — it used
    // to fail the open, and trips were not persisted that boot.
    let mut reader = crate::canary::chain_lines::ChainLines::new(BufReader::new(f));
    let mut skipped = 0usize;
    let mut first_break: Option<String> = None;
    // (row, entry, canonical bytes) of the last rows, oldest first.
    let mut window: std::collections::VecDeque<(u64, CanaryAccessEntry, bool)> =
        std::collections::VecDeque::with_capacity(OPEN_VERIFY_ROWS);
    while let Some(line) = reader
        .next_line()
        .with_context(|| format!("reading line from {}", path.display()))?
    {
        let parsed = match line {
            crate::canary::chain_lines::ChainLine::Text(l) => {
                serde_json::from_str::<CanaryAccessEntry>(l).ok().map(|e| {
                    let canonical = crate::chain_anchor::is_canonical(&e, l.as_bytes());
                    (e, canonical)
                })
            }
            crate::canary::chain_lines::ChainLine::Unreadable => None,
        };
        match parsed {
            Some((entry, canonical)) => {
                let row = seq.rows();
                if let Err(b) = seq.push(entry.seq) {
                    first_break.get_or_insert_with(|| b.to_string());
                }
                if window.len() == OPEN_VERIFY_ROWS {
                    window.pop_front();
                }
                window.push_back((row, entry, canonical));
            }
            None => {
                skipped += 1;
                seq.skip();
            }
        }
    }
    let mut last: Option<String> = None;
    let mut unverified = 0usize;
    let mut prev: Option<&str> = None;
    for (row, entry, canonical) in &window {
        // External audit EVD-007 (lab PR 204): a numbered row not in its
        // canonical bytes is not continued from, like one that does not
        // verify.
        if verify_row(entry, pubkey).is_err() || (entry.seq.is_some() && !canonical) {
            unverified += 1;
            continue;
        }
        if prev.is_some_and(|p| p != entry.prev_hash) {
            first_break.get_or_insert_with(|| {
                format!(
                    "row {row} does not chain from the genuine row before it: rows were removed"
                )
            });
        }
        prev = Some(&entry.entry_hash);
        last = Some(entry.entry_hash.clone());
    }
    let mut findings = Vec::new();
    if unverified > 0 {
        findings.push(crate::chain_anchor::ChainFinding::new(
            "canary_access",
            path,
            "chain_lines_unverified",
            format!(
                "{unverified} of the last {} row(s) fail hash or signature verification",
                window.len()
            ),
        ));
    }
    if let Some(why) = first_break {
        findings.push(crate::chain_anchor::ChainFinding::new(
            "canary_access",
            path,
            "chain_sequence_broken",
            why,
        ));
    }
    // Nothing in the window verifies: continue from the newest parsed row,
    // as before (its failure is reported above).
    let last = last.or_else(|| window.back().map(|(_, e, _)| e.entry_hash.clone()));
    Ok(TailRead {
        last_hash: last.unwrap_or_else(|| GENESIS_PREV_HASH.to_string()),
        skipped,
        rows: seq.rows(),
        findings,
    })
}

fn build_signed_entry(
    draft: &CanaryAccessDraft,
    key: &AgentSigningKey,
    agent_id: &[u8; 16],
    prev_hash: &str,
    seq: u64,
) -> Result<CanaryAccessEntry> {
    let ts = format_ts(Utc::now());
    let mut entry = CanaryAccessEntry {
        ts,
        canary_id: draft.canary_id.clone(),
        canary_name: draft.canary_name.clone(),
        canary_type: draft.canary_type,
        access_kind: draft.access_kind,
        accessor_pid: draft.accessor_pid,
        accessor_uid: draft.accessor_uid,
        accessor_comm: draft.accessor_comm.clone(),
        accessor_exe: draft.accessor_exe.clone(),
        first_trip: draft.first_trip,
        agent_id: hex::encode(agent_id),
        seq: Some(seq),
        prev_hash: prev_hash.to_string(),
        // Filled below — empty here so the pre-image
        // serialisation excludes them.
        entry_hash: String::new(),
        agent_sig: String::new(),
    };
    let entry_hash = compute_entry_hash(&entry)?;
    entry.entry_hash = hex::encode(entry_hash);
    let sig = key.sign(&entry_hash);
    entry.agent_sig = B64.encode(sig.to_bytes());
    Ok(entry)
}

/// External audit NN-AUD-174: a numbered row (`seq` set) prefixes the
/// pre-image with [`crate::chain_anchor::CANARY_ACCESS_DOMAIN_V2`]; a row
/// without `seq` keeps the pre-image it was signed with.
///
/// External audit EVD-023 (NN-AUD-427, lab PR 204): a row that still
/// carries `entry_hash` or `agent_sig` is an error in every build.
fn compute_entry_hash(entry: &CanaryAccessEntry) -> Result<[u8; 32]> {
    crate::chain_anchor::check_unsealed(&entry.entry_hash, &entry.agent_sig)?;
    let body = serde_json::to_vec(entry)
        .map_err(|e| anyhow!("serialising canary access pre-image: {e}"))?;
    let domain = entry
        .seq
        .map(|_| crate::chain_anchor::CANARY_ACCESS_DOMAIN_V2);
    crate::chain_anchor::flat_digest(domain, &entry.prev_hash, &body)
}

/// External audit NN-AUD-174: one row's own hash and signature.
fn verify_row(
    entry: &CanaryAccessEntry,
    pubkey: &VerifyingKey,
) -> Result<(), AccessLogVerifyError> {
    let idx = 0;
    let mut stripped = entry.clone();
    stripped.entry_hash.clear();
    stripped.agent_sig.clear();
    let recomputed =
        compute_entry_hash(&stripped).map_err(|e| AccessLogVerifyError::MalformedField {
            idx,
            reason: e.to_string(),
        })?;
    if hex::encode(recomputed) != entry.entry_hash {
        return Err(AccessLogVerifyError::EntryHashMismatch {
            idx,
            recomputed: hex::encode(recomputed),
            stored: entry.entry_hash.clone(),
        });
    }
    let sig = B64
        .decode(&entry.agent_sig)
        .ok()
        .and_then(|b| <[u8; 64]>::try_from(b.as_slice()).ok())
        .ok_or(AccessLogVerifyError::SignatureInvalid { idx })?;
    // External audit NN-AUD-292 (FIMP-013): strict.
    pubkey
        .verify_strict(&recomputed, &Signature::from_bytes(&sig))
        .map_err(|_| AccessLogVerifyError::SignatureInvalid { idx })
}

/// External audit NN-AUD-174: whether one raw line is a genuine access row.
/// External audit EVD-007 (lab PR 204): a numbered row must also be in its
/// canonical bytes.
pub fn row_is_genuine(line: &[u8], pubkey: &VerifyingKey) -> bool {
    serde_json::from_slice::<CanaryAccessEntry>(line).is_ok_and(|e| {
        verify_row(&e, pubkey).is_ok()
            && (e.seq.is_none() || crate::chain_anchor::is_canonical(&e, line))
    })
}

fn format_ts(t: DateTime<Utc>) -> String {
    t.format("%Y-%m-%dT%H:%M:%S%.6fZ").to_string()
}

// ── off-host verifier ───────────────────────────────────────────────

/// Outcome of one [`verify_chain`] run. Symmetric to
/// `crate::canary::registry::RegistryVerifyError` +
/// `crate::fim::baseline::BaselineVerifyError` +
/// `crate::audit::AuditVerifyError`.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AccessLogVerifyError {
    #[error("entry {idx}: prev_hash {got} does not match expected {expected}")]
    PrevHashMismatch {
        idx: usize,
        got: String,
        expected: String,
    },
    #[error("entry {idx}: entry_hash mismatch (recomputed {recomputed}, stored {stored})")]
    EntryHashMismatch {
        idx: usize,
        recomputed: String,
        stored: String,
    },
    #[error("entry {idx}: agent_sig invalid")]
    SignatureInvalid { idx: usize },
    #[error("entry {idx}: malformed field — {reason}")]
    MalformedField { idx: usize, reason: String },
    /// External audit NN-AUD-174: a numbered row out of place.
    #[error("entry {idx}: {reason}")]
    Sequence {
        idx: usize,
        reason: crate::chain_anchor::SeqBreak,
    },
}

/// Replay `entries` in order, recomputing each `entry_hash`
/// and checking each `agent_sig` against `pubkey`. Returns
/// `Ok(())` on a fully-intact chain. External audit NN-AUD-174: the full
/// check (`nn-admin chain verify --log canary-access`);
/// [`CanaryAccessDb::open`] verifies the last [`OPEN_VERIFY_ROWS`] rows.
/// Rows without `seq` verify as before; from the first numbered row on,
/// each must carry its position.
pub fn verify_chain(
    entries: &[CanaryAccessEntry],
    pubkey: &VerifyingKey,
) -> Result<(), AccessLogVerifyError> {
    let mut expected_prev = GENESIS_PREV_HASH.to_string();
    let mut seq = crate::chain_anchor::RowSeq::default();
    for (idx, entry) in entries.iter().enumerate() {
        seq.push(entry.seq)
            .map_err(|reason| AccessLogVerifyError::Sequence { idx, reason })?;
        if entry.prev_hash != expected_prev {
            return Err(AccessLogVerifyError::PrevHashMismatch {
                idx,
                got: entry.prev_hash.clone(),
                expected: expected_prev,
            });
        }
        let mut stripped = entry.clone();
        stripped.entry_hash.clear();
        stripped.agent_sig.clear();
        let recomputed =
            compute_entry_hash(&stripped).map_err(|e| AccessLogVerifyError::MalformedField {
                idx,
                reason: e.to_string(),
            })?;
        let recomputed_hex = hex::encode(recomputed);
        if recomputed_hex != entry.entry_hash {
            return Err(AccessLogVerifyError::EntryHashMismatch {
                idx,
                recomputed: recomputed_hex,
                stored: entry.entry_hash.clone(),
            });
        }
        let sig_bytes =
            B64.decode(&entry.agent_sig)
                .map_err(|e| AccessLogVerifyError::MalformedField {
                    idx,
                    reason: format!("agent_sig base64 decode: {e}"),
                })?;
        if sig_bytes.len() != 64 {
            return Err(AccessLogVerifyError::MalformedField {
                idx,
                reason: format!("agent_sig length {} (expected 64)", sig_bytes.len()),
            });
        }
        let mut sig_arr = [0u8; 64];
        sig_arr.copy_from_slice(&sig_bytes);
        let sig = Signature::from_bytes(&sig_arr);
        if pubkey.verify_strict(&recomputed, &sig).is_err() {
            return Err(AccessLogVerifyError::SignatureInvalid { idx });
        }
        expected_prev = entry.entry_hash.clone();
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn fresh_signing_key(dir: &TempDir) -> (AgentSigningKey, VerifyingKey) {
        let key_path = dir.path().join("agent.sig.key");
        let k = AgentSigningKey::load_or_bootstrap(&key_path).unwrap();
        let vk = k.verifying_key();
        (k, vk)
    }

    fn sample_draft(seq: u32, first: bool) -> CanaryAccessDraft {
        CanaryAccessDraft {
            canary_id: format!("canary_id_{seq}"),
            canary_name: format!("decoy_{seq}"),
            canary_type: CanaryTypeTag::File,
            access_kind: CanaryAccessKind::FileOpen,
            accessor_pid: 1000 + seq,
            accessor_uid: 0,
            accessor_comm: format!("attacker_{seq}"),
            accessor_exe: Some(format!("/usr/bin/attacker_{seq}")),
            first_trip: first,
        }
    }

    /// External audit DEC-012 (lab PR 178): a line that is not UTF-8 failed
    /// the open, and trips were not persisted that boot; one over the cap
    /// was read whole. Both are skipped and counted, the rows after them
    /// kept: the chain continues from the last one.
    #[test]
    fn non_utf8_and_oversized_lines_are_skipped_not_fatal() {
        let dir = TempDir::new().unwrap();
        let log_path = dir.path().join("canary_access.jsonl");
        {
            let (key, _) = fresh_signing_key(&dir);
            let mut db = CanaryAccessDb::open(&log_path, key, [0u8; 16]).unwrap();
            db.append(sample_draft(1, true)).unwrap();
        }
        let mut body = std::fs::read(&log_path).unwrap();
        body.extend_from_slice(b"\xff\xfe{\"seq\":1}\n");
        body.extend(std::iter::repeat_n(
            b'y',
            crate::canary::chain_lines::MAX_CHAIN_LINE_BYTES + 1,
        ));
        body.push(b'\n');
        std::fs::write(&log_path, &body).unwrap();
        let last = {
            let (key, _) = fresh_signing_key(&dir);
            let mut db = CanaryAccessDb::open(&log_path, key, [0u8; 16]).expect("opens");
            assert_eq!(db.take_open_findings().1, 2);
            db.append(sample_draft(2, false)).expect("appends continue")
        };
        assert_eq!(last.seq, Some(3), "the skipped lines keep their positions");
        let (key, _) = fresh_signing_key(&dir);
        let db = CanaryAccessDb::open(&log_path, key, [0u8; 16]).unwrap();
        assert_eq!(db.last_hash(), last.entry_hash);
    }

    /// External audit NN-AUD-292 (FIMP-013): the access log's rows pass the
    /// strict check with the agent's key (whole chain and one row at a
    /// time); rows carrying a small-order signature, under a small-order
    /// key, passed the lax one and are refused now.
    #[test]
    fn access_chain_is_verified_strictly() {
        use crate::chain_anchor::small_order;
        let dir = TempDir::new().unwrap();
        let (key, pubkey) = fresh_signing_key(&dir);
        let log_path = dir.path().join("canary_access.jsonl");
        let mut db = CanaryAccessDb::open(&log_path, key, [0u8; 16]).unwrap();
        for i in 1..=8 {
            db.append(sample_draft(i, i == 1)).unwrap();
        }
        let parse = |text: &str| -> Vec<CanaryAccessEntry> {
            text.lines()
                .map(|l| serde_json::from_str(l).unwrap())
                .collect()
        };
        let text = std::fs::read_to_string(&log_path).unwrap();
        verify_chain(&parse(&text), &pubkey).expect("strict accepts the agent's rows");
        assert!(text.lines().all(|l| row_is_genuine(l.as_bytes(), &pubkey)));
        let forged_text = small_order::forge(&text);
        let forged = parse(&forged_text);
        small_order::assert_premise(&hex::decode(&forged[0].entry_hash).unwrap());
        assert!(matches!(
            verify_chain(&forged, &small_order::key()),
            Err(AccessLogVerifyError::SignatureInvalid { idx: 0 })
        ));
        let first = forged_text.lines().next().unwrap();
        assert!(!row_is_genuine(first.as_bytes(), &small_order::key()));
    }

    /// K3 access-log test #1: first append writes one signed
    /// row + chain verifies against the agent's pubkey.
    #[test]
    fn access_log_first_append_writes_signed_row() {
        let dir = TempDir::new().unwrap();
        let (key, pubkey) = fresh_signing_key(&dir);
        let log_path = dir.path().join("canary_access.jsonl");
        let mut db = CanaryAccessDb::open(&log_path, key, [0u8; 16]).unwrap();
        let entry = db.append(sample_draft(1, true)).expect("first append");
        assert_eq!(entry.prev_hash, GENESIS_PREV_HASH);
        assert!(entry.first_trip);
        assert_eq!(db.last_hash(), entry.entry_hash);
        let raw = std::fs::read_to_string(&log_path).unwrap();
        assert_eq!(raw.lines().count(), 1);
        verify_chain(&[entry], &pubkey).expect("single-entry chain verifies");
    }

    /// K3 access-log test #2: chain integrity — payload tamper
    /// detected at the right index. Anchors the off-host
    /// verifier's bit-level sensitivity for the access log
    /// (same property the K2 registry has).
    #[test]
    fn access_log_verify_chain_detects_payload_tamper() {
        let dir = TempDir::new().unwrap();
        let (key, pubkey) = fresh_signing_key(&dir);
        let log_path = dir.path().join("canary_access.jsonl");
        let mut db = CanaryAccessDb::open(&log_path, key, [0u8; 16]).unwrap();
        let _ = db.append(sample_draft(1, true)).unwrap();
        // Second access on the same canary — first_trip=false
        // (matches the K3 detector's §12 Q2 single-trip
        // contract).
        let _ = db.append(sample_draft(1, false)).unwrap();
        let raw = std::fs::read_to_string(&log_path).unwrap();
        let mut entries: Vec<CanaryAccessEntry> = raw
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect();
        // Attacker rewrites the first row's accessor_comm field.
        entries[0].accessor_comm = "tampered_comm".to_string();
        let err = verify_chain(&entries, &pubkey).expect_err("tampered chain must fail");
        assert!(
            matches!(err, AccessLogVerifyError::EntryHashMismatch { idx: 0, .. }),
            "expected EntryHashMismatch on entry 0; got: {err:?}"
        );
    }

    // ── External audit NN-AUD-174 (lab PR 160) ──────────────────────

    /// Before lab PR 160 the open only parsed rows. A row at the end that
    /// does not verify is now reported, and the chain continues from the
    /// last genuine row.
    #[test]
    fn access_log_open_flags_a_bad_tail_row() {
        let dir = TempDir::new().unwrap();
        let log_path = dir.path().join("canary_access.jsonl");
        let first = {
            let (key, _) = fresh_signing_key(&dir);
            let mut db = CanaryAccessDb::open(&log_path, key, [0u8; 16]).unwrap();
            db.append(sample_draft(1, true)).unwrap()
        };
        let mut forged = first.clone();
        forged.seq = Some(1);
        forged.accessor_comm = "not-the-attacker".to_string();
        forged.prev_hash = first.entry_hash.clone();
        forged.entry_hash = "cd".repeat(32);
        let mut body = std::fs::read_to_string(&log_path).unwrap();
        body.push_str(&serde_json::to_string(&forged).unwrap());
        body.push('\n');
        std::fs::write(&log_path, body).unwrap();
        let (key, _) = fresh_signing_key(&dir);
        let mut db = CanaryAccessDb::open(&log_path, key, [0u8; 16]).unwrap();
        let found = db.take_chain_findings();
        assert!(
            found.iter().any(|f| f.kind == "chain_lines_unverified"),
            "{found:?}"
        );
        assert_eq!(db.last_hash(), first.entry_hash);
    }

    /// Rows written before lab PR 160 open and verify as before;
    /// numbering starts at their count.
    #[test]
    fn legacy_access_rows_verify_and_numbering_starts_after_them() {
        let dir = TempDir::new().unwrap();
        let (key, pk) = fresh_signing_key(&dir);
        let log_path = dir.path().join("canary_access.jsonl");
        let mut prev = GENESIS_PREV_HASH.to_string();
        let mut body = String::new();
        for i in 0..3 {
            let mut e =
                build_signed_entry(&sample_draft(i, i == 0), &key, &[0u8; 16], &prev, 0).unwrap();
            e.seq = None;
            e.entry_hash.clear();
            e.agent_sig.clear();
            let h = compute_entry_hash(&e).unwrap();
            e.entry_hash = hex::encode(h);
            e.agent_sig = B64.encode(key.sign(&h).to_bytes());
            body.push_str(&serde_json::to_string(&e).unwrap());
            body.push('\n');
            prev = e.entry_hash;
        }
        std::fs::write(&log_path, &body).unwrap();
        let mut db = CanaryAccessDb::open(&log_path, key, [0u8; 16]).unwrap();
        assert!(db.take_chain_findings().is_empty());
        let row = db.append(sample_draft(9, false)).unwrap();
        assert_eq!(row.seq, Some(3));
        let rows: Vec<CanaryAccessEntry> = std::fs::read_to_string(&log_path)
            .unwrap()
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect();
        verify_chain(&rows, &pk).expect("old rows then numbered rows verify");
        // a numbered row cut from the middle is a sequence break
        let mut cut = rows.clone();
        cut.remove(2);
        assert!(matches!(
            verify_chain(&cut, &pk),
            Err(AccessLogVerifyError::Sequence { .. })
        ));
    }

    /// External audit NN-AUD-174: an access row hashed for the registry
    /// domain is refused.
    #[test]
    fn an_access_row_signed_for_another_domain_is_rejected() {
        let dir = TempDir::new().unwrap();
        let (key, pk) = fresh_signing_key(&dir);
        let log_path = dir.path().join("canary_access.jsonl");
        let mut db = CanaryAccessDb::open(&log_path, key, [0u8; 16]).unwrap();
        let good = db.append(sample_draft(1, true)).unwrap();
        let (key, _) = fresh_signing_key(&dir);
        let mut e = good.clone();
        e.entry_hash.clear();
        e.agent_sig.clear();
        let body = serde_json::to_vec(&e).unwrap();
        let h = crate::chain_anchor::flat_digest(
            Some(crate::chain_anchor::CANARY_REGISTRY_DOMAIN_V2),
            &e.prev_hash,
            &body,
        )
        .unwrap();
        e.entry_hash = hex::encode(h);
        e.agent_sig = B64.encode(key.sign(&h).to_bytes());
        assert!(matches!(
            verify_chain(&[e], &pk),
            Err(AccessLogVerifyError::EntryHashMismatch { idx: 0, .. })
        ));
    }

    // ── External audit, Wave 3, lab PR 204 ─────────────────────────────

    /// EVD-007 (NN-AUD-273): a numbered access row with a key added still
    /// decodes to the genuine row and verifies; its bytes are not what the
    /// agent wrote. The open does not continue from it, it is not a head,
    /// and the full check refuses it. On the starting code it verified.
    #[test]
    fn a_numbered_access_row_not_in_canonical_form_is_refused() {
        let dir = TempDir::new().unwrap();
        let log_path = dir.path().join("canary_access.jsonl");
        let (key, pk) = fresh_signing_key(&dir);
        let mut db = CanaryAccessDb::open(&log_path, key, [0u8; 16]).unwrap();
        let first = db.append(sample_draft(1, true)).unwrap();
        db.append(sample_draft(2, false)).unwrap();
        drop(db);
        let body = std::fs::read_to_string(&log_path).unwrap();
        let lines: Vec<&str> = body.lines().collect();
        let forged = format!(
            "{},\"injected\":\"x\"}}",
            lines[1].strip_suffix('}').unwrap()
        );
        let decoded: CanaryAccessEntry = serde_json::from_str(&forged).unwrap();
        assert!(
            verify_row(&decoded, &pk).is_ok(),
            "the decoded row verifies"
        );
        assert!(row_is_genuine(lines[1].as_bytes(), &pk));
        assert!(!row_is_genuine(forged.as_bytes(), &pk));
        std::fs::write(&log_path, format!("{}\n{forged}\n", lines[0])).unwrap();
        let (key, _) = fresh_signing_key(&dir);
        let mut db = CanaryAccessDb::open(&log_path, key, [0u8; 16]).unwrap();
        assert!(db
            .take_chain_findings()
            .iter()
            .any(|f| f.kind == "chain_lines_unverified"));
        assert_eq!(db.last_hash(), first.entry_hash);
    }

    /// EVD-023 (NN-AUD-427): a pre-image that carries its seal is refused
    /// in every build.
    #[test]
    fn access_compute_entry_hash_refuses_a_sealed_row() {
        let dir = TempDir::new().unwrap();
        let log_path = dir.path().join("canary_access.jsonl");
        let (key, _) = fresh_signing_key(&dir);
        let mut db = CanaryAccessDb::open(&log_path, key, [0u8; 16]).unwrap();
        let row = db.append(sample_draft(1, true)).unwrap();
        assert!(compute_entry_hash(&row).is_err());
        let mut stripped = row.clone();
        stripped.entry_hash.clear();
        stripped.agent_sig.clear();
        assert_eq!(
            hex::encode(compute_entry_hash(&stripped).unwrap()),
            row.entry_hash
        );
    }
}
