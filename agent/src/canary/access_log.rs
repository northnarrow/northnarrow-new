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
use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use anyhow::{anyhow, Context, Result};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use chrono::{DateTime, Utc};
use common::{CanaryAccessKind, CanaryTypeTag};
use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::audit::{AgentSigningKey, GENESIS_PREV_HASH};

/// Default deploy location of the chained access log. Sibling
/// to the K2 registry under `/var/lib/northnarrow/`.
pub const DEFAULT_ACCESS_LOG_PATH: &str = "/var/lib/northnarrow/canary_access.jsonl";

/// File mode for the persisted access log. World-readable
/// (operators inspect with `cat`); only root + the agent's
/// own user can write.
const ACCESS_LOG_FILE_MODE: u32 = 0o644;

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
    pub prev_hash: String,
    pub entry_hash: String,
    pub agent_sig: String,
}

/// Operator-supplied fields for [`CanaryAccessDb::append`].
/// Chain integrity fields (`ts`, `prev_hash`, `entry_hash`,
/// `agent_sig`, `agent_id`) are computed by `append`, never
/// supplied by the caller.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CanaryAccessDraft {
    pub canary_id: String,
    pub canary_name: String,
    pub canary_type: CanaryTypeTag,
    pub access_kind: CanaryAccessKind,
    pub accessor_pid: u32,
    pub accessor_uid: u32,
    pub accessor_comm: String,
    pub accessor_exe: Option<String>,
    pub first_trip: bool,
}

// ── access log ──────────────────────────────────────────────────────

/// Append-only writer for the canary access log. Holds the
/// [`AgentSigningKey`] in memory + tracks the chain tail-hash
/// so each `append` produces a well-chained next row. Same
/// shape as [`crate::audit::AuditLog`] + Tappa 9 C3 +
/// K2 `Registry`.
pub struct CanaryAccessDb {
    path: PathBuf,
    key: AgentSigningKey,
    agent_id: [u8; 16],
    last_hash: String,
}

impl CanaryAccessDb {
    /// Open `path` for append, walk any existing rows to
    /// recover `last_hash`. Missing file → empty chain
    /// (`last_hash = GENESIS_PREV_HASH`). K7 deploy bootstrap
    /// is responsible for ensuring the parent dir exists
    /// with the right mode.
    pub fn open(path: &Path, key: AgentSigningKey, agent_id: [u8; 16]) -> Result<Self> {
        let last_hash = read_tail_hash(path)?;
        Ok(Self {
            path: path.to_path_buf(),
            key,
            agent_id,
            last_hash,
        })
    }

    /// Append one access entry. Computes timestamp + chain
    /// hash + signature, writes one `\n`-terminated JSON line
    /// via `O_APPEND` + fsync, advances the in-memory tail.
    /// On success returns the entry as persisted (so the K3
    /// detector can read `entry.entry_hash` to populate
    /// `Registry::mark_tripped(canary_id, access_hash)` for
    /// cross-chain reference).
    pub fn append(&mut self, draft: CanaryAccessDraft) -> Result<CanaryAccessEntry> {
        let entry = build_signed_entry(&draft, &self.key, &self.agent_id, &self.last_hash)?;
        let mut line = serde_json::to_string(&entry)
            .map_err(|e| anyhow!("serialising canary access entry: {e}"))?;
        line.push('\n');
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
        Ok(entry)
    }

    /// Tail hash an auditor would chain the NEXT row off.
    pub fn last_hash(&self) -> &str {
        &self.last_hash
    }
}

// ── chain helpers ───────────────────────────────────────────────────

fn read_tail_hash(path: &Path) -> Result<String> {
    let f = match OpenOptions::new().read(true).open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Ok(GENESIS_PREV_HASH.to_string());
        }
        Err(e) => return Err(anyhow!(e).context(format!("reading {}", path.display()))),
    };
    let reader = BufReader::new(f);
    let mut last: Option<String> = None;
    for line in reader.lines() {
        let line = line.with_context(|| format!("reading line from {}", path.display()))?;
        if line.is_empty() {
            continue;
        }
        let entry: CanaryAccessEntry = serde_json::from_str(&line)
            .with_context(|| format!("parsing canary access line: {line}"))?;
        last = Some(entry.entry_hash);
    }
    Ok(last.unwrap_or_else(|| GENESIS_PREV_HASH.to_string()))
}

fn build_signed_entry(
    draft: &CanaryAccessDraft,
    key: &AgentSigningKey,
    agent_id: &[u8; 16],
    prev_hash: &str,
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

fn compute_entry_hash(entry: &CanaryAccessEntry) -> Result<[u8; 32]> {
    debug_assert!(entry.entry_hash.is_empty());
    debug_assert!(entry.agent_sig.is_empty());
    let prev_bytes =
        hex::decode(&entry.prev_hash).map_err(|e| anyhow!("prev_hash is not valid hex: {e}"))?;
    let body = serde_json::to_vec(entry)
        .map_err(|e| anyhow!("serialising canary access pre-image: {e}"))?;
    let mut hasher = Sha256::new();
    hasher.update(&prev_bytes);
    hasher.update(&body);
    let digest: [u8; 32] = hasher.finalize().into();
    Ok(digest)
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
}

/// Replay `entries` in order, recomputing each `entry_hash`
/// and checking each `agent_sig` against `pubkey`. Returns
/// `Ok(())` on a fully-intact chain. Used by the agent's
/// own [`CanaryAccessDb::open`] path (via test fixtures) and
/// the future K6 `nn-admin canary verify-access` reader.
pub fn verify_chain(
    entries: &[CanaryAccessEntry],
    pubkey: &VerifyingKey,
) -> Result<(), AccessLogVerifyError> {
    use ed25519_dalek::Verifier;
    let mut expected_prev = GENESIS_PREV_HASH.to_string();
    for (idx, entry) in entries.iter().enumerate() {
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
        if pubkey.verify(&recomputed, &sig).is_err() {
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
}
