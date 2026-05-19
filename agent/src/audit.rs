//! Tamper-evident audit log (Tappa 8 design §9, sub-sprint B
//! commit B1 / table row A11).
//!
//! Every admin operation the agent processes — success or failure —
//! appends a single JSONL line to `/etc/northnarrow/audit.log`. Each
//! record is bound to the previous record by a SHA-256 hash chain
//! (`entry_hash = SHA-256(prev_hash || serialised record minus
//! entry_hash + agent_sig)`) and signed by an agent-owned Ed25519
//! key, so off-host auditors can verify the chain end-to-end with
//! nothing more than the agent binary's embedded public key
//! (forthcoming sub-sprint B commits ship the `nn-admin audit
//! verify` reader).
//!
//! ## What this commit (B1) ships
//!
//! - [`AgentSigningKey::load_or_bootstrap`] — mirrors the
//!   [`crate::agent_id::load_or_bootstrap`] policy: existing file →
//!   parse, missing file → mint via `OsRng` + atomic persist,
//!   corrupted file → hard error (no silent regen). On-disk mode is
//!   `0400` — the agent's own boot user (root) is the only reader,
//!   and the file is the LSM-protected `agent.sig.key` whose
//!   protection ships in commit A14 / sub-sprint B's LSM widening.
//! - [`AuditEntry`] — the on-disk JSON record per §9.1.
//! - [`AuditLog::open`] — opens the log in `O_APPEND` mode and
//!   walks the existing chain to recover `prev_hash`. An empty or
//!   absent file starts the chain at the canonical genesis
//!   ([`GENESIS_PREV_HASH`]).
//! - [`AuditLog::append`] — atomically computes `entry_hash`,
//!   signs it, and appends one `\n`-terminated JSON line. The
//!   in-memory `prev_hash` advances on success.
//! - [`verify_chain`] — replays a sequence of [`AuditEntry`]s,
//!   recomputing `entry_hash` and checking `agent_sig` against a
//!   supplied verifying key. Used by `AuditLog::open` to populate
//!   the tail-hash and exposed for the off-host verifier the next
//!   sub-sprint B commit will wire into `nn-admin audit verify`.
//!
//! ## What this commit (B1) deliberately does NOT ship
//!
//! - **No CLI surface.** `nn-admin audit read / audit verify` is
//!   commit A12 (sub-sprint B's next commit). B1 is a foundation
//!   primitive: tested in isolation, no wire-protocol changes, no
//!   admin-socket dispatch changes.
//! - **No `admin_socket::dispatch` integration.** The agent does
//!   not yet log operations to the audit log; the dispatch
//!   integration lands in a later sub-sprint B commit so this
//!   commit stays a small additive module with no behaviour
//!   change for existing admin ops.
//! - **No LSM widening of `/etc/northnarrow/`.** The
//!   `agent.sig.key` and `audit.log` files live under
//!   `/etc/northnarrow/` and become tamper-evident only when the
//!   Tappa 7 FS-LSM hooks extend to that directory in commit A14.
//!   B1 ships the files with the right modes; A14 enforces them
//!   against root.
//! - **No rotation.** Append-only file grows forever in B1. The
//!   rotation policy is RFC item §14 Q9 and tracked for sub-sprint
//!   B's `audit-rotate` commit (or deferred to V1.1 per the design).
//!
//! ## Test surface
//!
//! Eight tests per the design table A11:
//!
//! 1. Signing-key fresh-gen creates the file with mode `0400`.
//! 2. Signing-key reuse-existing returns the same key bytes.
//! 3. Signing-key load on corrupted file errors (no silent regen).
//! 4. `AuditLog::open` on a missing file initialises with the
//!    genesis prev_hash.
//! 5. `AuditLog::append` writes a JSONL line with the correct
//!    chain link + a signature that verifies against the key's
//!    pubkey.
//! 6. Two sequential `append` calls chain correctly
//!    (`second.prev_hash == first.entry_hash`).
//! 7. `verify_chain` rejects an entry whose payload field was
//!    tampered with after writing.
//! 8. `verify_chain` rejects an entry whose signature was
//!    flipped.

use std::fs::{self, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use anyhow::{anyhow, Context, Result};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use chrono::{DateTime, Utc};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey, SECRET_KEY_LENGTH};
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tracing::info;

/// Default location of the tamper-evident audit log. Mirrors the
/// `/etc/northnarrow/` install layout (`admin.pub`, `agent_id`).
/// The directory is LSM-protected by commit A14; until then the
/// path enjoys ordinary `0644` POSIX protection only.
pub const DEFAULT_AUDIT_LOG_PATH: &str = "/etc/northnarrow/audit.log";

/// Default location of the agent's audit-log signing key. Stored
/// as exactly 32 lowercase-hex bytes + `\n` so an operator can
/// inspect it with `cat` (cf. the agent_id encoding) without the
/// risk of a base64 padding mismatch.
pub const DEFAULT_SIGNING_KEY_PATH: &str = "/etc/northnarrow/agent.sig.key";

/// Genesis chain anchor: 32 zero bytes hex-encoded. The first
/// entry's `prev_hash` is exactly this value, so a verifier
/// replaying the chain from scratch starts with a known
/// well-formed seed regardless of when the log was first written.
pub const GENESIS_PREV_HASH: &str =
    "0000000000000000000000000000000000000000000000000000000000000000";

/// Owner-read-only — only the boot user (root) loads or rotates
/// it. The file is the LSM-protected signing-key root-of-trust;
/// `0400` keeps a curious non-root admin tool from accidentally
/// reading it before the LSM widening lands.
const SIGNING_KEY_FILE_MODE: u32 = 0o400;

/// `0644` matches `agent_id` — the log is world-readable for
/// `nn-admin audit read`'s default operator workflow (later
/// commit). Append-only is enforced by `O_APPEND` in this module
/// and by the FS-LSM hooks in commit A14.
const AUDIT_LOG_FILE_MODE: u32 = 0o644;

/// Parent directory mode. Conventional `/etc/<vendor>/` layout —
/// root writes, world reads. Matches `agent_id`.
const PARENT_DIR_MODE: u32 = 0o755;

/// Strict pre-decode length check: an Ed25519 secret key is
/// exactly 32 bytes ⇒ exactly 64 hex chars on disk.
const SIGNING_KEY_HEX_LEN: usize = SECRET_KEY_LENGTH * 2;

// ── agent signing key ───────────────────────────────────────────────

/// Agent-owned Ed25519 keypair that signs audit-log entries. The
/// key is **internal** to the agent install — not an admin key,
/// not user-facing — and is rotated only by re-installing the
/// agent. Off-host verifiers consume the pubkey via
/// [`AgentSigningKey::verifying_key`] which the future
/// `nn-admin audit verify` command will accept on the CLI.
///
/// Wrapping `SigningKey` (not transparent newtype) so the
/// secret bytes never accidentally leak through `Debug` or
/// `Display` derives. `Drop` zeroisation is owned by
/// `ed25519-dalek`'s `zeroize` feature in its standard build.
pub struct AgentSigningKey {
    inner: SigningKey,
}

// Manual Debug: never print the secret bytes. We expose the
// public verifying key's fingerprint instead so logs + test
// failure output stay informative without leaking secrets.
impl std::fmt::Debug for AgentSigningKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let pk = self.inner.verifying_key().to_bytes();
        write!(f, "AgentSigningKey(pubkey_fp={})", hex::encode(&pk[..4]))
    }
}

impl AgentSigningKey {
    /// Open `path` if it exists, else mint a fresh keypair via
    /// `OsRng` and persist it atomically. Returns the loaded /
    /// minted key.
    ///
    /// Errors are the same shape as
    /// [`crate::agent_id::load_or_bootstrap`]:
    /// - corrupted file (wrong length, non-hex) → hard error,
    ///   operator must investigate. Silent regeneration is
    ///   forbidden because a new key would silently invalidate
    ///   every signature in the existing audit log.
    /// - I/O refused (`EROFS`, `ENOSPC`, missing parent we
    ///   can't create) → propagated with context.
    pub fn load_or_bootstrap(path: &Path) -> Result<Self> {
        match fs::read_to_string(path) {
            Ok(content) => {
                let key = parse_signing_key(&content).with_context(|| {
                    format!(
                        "agent signing key {} present but corrupted — refuse to \
                         silently regenerate; remove the file deliberately if you \
                         intend to mint a new key (note: every existing audit-log \
                         signature stops verifying)",
                        path.display()
                    )
                })?;
                info!(
                    target: "audit.signing_key",
                    path = %path.display(),
                    "reusing existing agent signing key"
                );
                Ok(Self { inner: key })
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                let key = mint_signing_key()?;
                persist_signing_key_atomically(path, &key)?;
                info!(
                    target: "audit.signing_key",
                    path = %path.display(),
                    "bootstrapped fresh agent signing key"
                );
                Ok(Self { inner: key })
            }
            Err(e) => Err(anyhow!(e).context(format!("reading {}", path.display()))),
        }
    }

    /// Public verifying key for off-host auditors. Embeds in the
    /// agent binary at build time so `nn-admin audit verify`
    /// doesn't need a separate key distribution step.
    pub fn verifying_key(&self) -> VerifyingKey {
        self.inner.verifying_key()
    }

    /// Sign `msg` with the agent signing key. Used by
    /// [`AuditLog::append`] to sign `entry_hash`; exposed for
    /// tests + the future `audit verify` reader.
    pub fn sign(&self, msg: &[u8]) -> Signature {
        self.inner.sign(msg)
    }
}

fn mint_signing_key() -> Result<SigningKey> {
    let mut secret = [0u8; SECRET_KEY_LENGTH];
    OsRng
        .try_fill_bytes(&mut secret)
        .map_err(|e| anyhow!("OsRng failed to provide entropy for signing key: {e}"))?;
    Ok(SigningKey::from_bytes(&secret))
}

fn parse_signing_key(raw: &str) -> Result<SigningKey> {
    let trimmed = raw.strip_suffix('\n').unwrap_or(raw);
    if trimmed.contains('\n') || trimmed.contains('\r') {
        return Err(anyhow!(
            "signing key file has embedded newline — expected single-line hex"
        ));
    }
    if trimmed.len() != SIGNING_KEY_HEX_LEN {
        return Err(anyhow!(
            "signing key has {} hex chars (expected {SIGNING_KEY_HEX_LEN})",
            trimmed.len()
        ));
    }
    let bytes = hex::decode(trimmed).map_err(|e| anyhow!("signing key is not valid hex: {e}"))?;
    let mut secret = [0u8; SECRET_KEY_LENGTH];
    secret.copy_from_slice(&bytes);
    Ok(SigningKey::from_bytes(&secret))
}

fn persist_signing_key_atomically(path: &Path, key: &SigningKey) -> Result<()> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::DirBuilder::new()
                .mode(PARENT_DIR_MODE)
                .recursive(true)
                .create(parent)
                .with_context(|| {
                    format!("creating signing-key parent dir {}", parent.display())
                })?;
        }
    }
    let tmp_path = tmp_path_for(path);
    {
        let mut f = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(SIGNING_KEY_FILE_MODE)
            .open(&tmp_path)
            .with_context(|| format!("creating signing-key tmpfile {}", tmp_path.display()))?;
        let mut line = hex::encode(key.to_bytes());
        line.push('\n');
        f.write_all(line.as_bytes()).with_context(|| {
            format!("writing signing-key bytes to {}", tmp_path.display())
        })?;
        f.sync_all()
            .with_context(|| format!("fsync {}", tmp_path.display()))?;
    }
    fs::rename(&tmp_path, path)
        .with_context(|| format!("renaming {} → {}", tmp_path.display(), path.display()))?;
    Ok(())
}

fn tmp_path_for(path: &Path) -> PathBuf {
    let mut s = path.as_os_str().to_owned();
    s.push(".tmp");
    PathBuf::from(s)
}

// ── audit entry on-disk shape ───────────────────────────────────────

/// One on-disk JSONL record per §9.1. Field order MATTERS for the
/// `entry_hash` computation: we serialise via `serde_json` with
/// the struct's declared field order (`preserve_order` is not
/// needed because `serde_json` already preserves struct order).
/// Re-ordering fields here is a chain-format break — bump
/// [`AUDIT_LOG_FORMAT_VERSION`] if you must.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditEntry {
    /// ISO-8601 UTC timestamp, microsecond resolution.
    pub ts: String,
    /// Hex of the 16-byte agent install UUID (see
    /// [`crate::agent_id`]).
    pub agent_id: String,
    /// Operation code, e.g. `"unlock"`, `"shutdown"`,
    /// `"force_posture"`. Matches the §4 operation list.
    pub op: String,
    /// Free-form op-specific extra context. JSON value preserves
    /// the wire `*Extra` shape without forcing a strongly-typed
    /// dispatch here.
    pub extra: serde_json::Value,
    /// Hex fingerprint of the primary signer's pubkey (first 8
    /// hex chars of the ed25519 pubkey, same shape `AdminAuth`
    /// uses in log lines).
    pub key_fp: String,
    /// Hex fingerprints of any cosigners (empty for single-sig
    /// ops; non-empty for the §3.3 quorum path).
    pub cosigner_fps: Vec<String>,
    /// `"success"` or `"failure: <reason>"` — the latter is
    /// what the agent logs when it rejected the op (bad sig,
    /// role denied, skew, etc.).
    pub result: String,
    /// PID of the connecting client (`SO_PEERCRED`).
    pub client_pid: u32,
    /// UID of the connecting client (`SO_PEERCRED`).
    pub client_uid: u32,
    /// Comm of the connecting client (best-effort read from
    /// `/proc/<pid>/comm`).
    pub client_comm: String,
    /// Hex of the prior entry's `entry_hash`. First record uses
    /// [`GENESIS_PREV_HASH`].
    pub prev_hash: String,
    /// Hex of `SHA-256(prev_hash_bytes || canonical_json_of_entry_minus(entry_hash,agent_sig))`.
    pub entry_hash: String,
    /// Base64-`STANDARD` encoded Ed25519 signature over the raw
    /// 32 bytes of `entry_hash` (hex-decoded). Base64 over the
    /// signature, hex over the hash — both choices match what
    /// the rest of the agent uses for the same primitive types.
    pub agent_sig: String,
}

/// Bumped when the on-disk schema or hash-input bytes change.
/// Verifiers consult this to refuse a chain they were not built
/// to read.
pub const AUDIT_LOG_FORMAT_VERSION: u32 = 1;

/// Fields the user provides to [`AuditLog::append`]. The chain
/// fields (`prev_hash`, `entry_hash`, `agent_sig`) are computed
/// by `append`, never supplied by the caller — that's exactly
/// the property the chain enforces.
#[derive(Debug, Clone)]
pub struct AuditEntryDraft {
    pub op: String,
    pub extra: serde_json::Value,
    pub key_fp: String,
    pub cosigner_fps: Vec<String>,
    pub result: String,
    pub client_pid: u32,
    pub client_uid: u32,
    pub client_comm: String,
}

// ── audit log writer ────────────────────────────────────────────────

/// Append-only writer for the audit log. Holds the
/// [`AgentSigningKey`] in memory and tracks the tail-hash so each
/// `append` produces a well-chained next entry. Cheap to keep
/// open for the lifetime of the agent — the underlying file is
/// `O_APPEND`, so a concurrent reader (auditor) sees consistent
/// records without taking a lock.
pub struct AuditLog {
    path: PathBuf,
    key: AgentSigningKey,
    agent_id: [u8; 16],
    last_hash: String,
}

impl AuditLog {
    /// Open `path` for append + walk any existing entries to
    /// recover `last_hash`. A missing file is treated as empty
    /// (starts the chain at [`GENESIS_PREV_HASH`] — A14's LSM
    /// widening will assert presence at install time).
    ///
    /// Walks but does NOT verify signatures on open — the agent's
    /// hot path must boot quickly even with a long log;
    /// `nn-admin audit verify` (later commit) is the
    /// signature-checking reader.
    pub fn open(path: &Path, key: AgentSigningKey, agent_id: [u8; 16]) -> Result<Self> {
        let last_hash = read_tail_hash(path)?;
        // Ensure the parent directory exists with the canonical
        // mode so the first append never fails on a missing
        // `/etc/northnarrow/` install.
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() && !parent.exists() {
                fs::DirBuilder::new()
                    .mode(PARENT_DIR_MODE)
                    .recursive(true)
                    .create(parent)
                    .with_context(|| {
                        format!("creating audit-log parent dir {}", parent.display())
                    })?;
            }
        }
        Ok(Self {
            path: path.to_path_buf(),
            key,
            agent_id,
            last_hash,
        })
    }

    /// Append one record. Computes timestamp + chain hash +
    /// signature, writes one `\n`-terminated JSON line via
    /// `O_APPEND` (atomic for writes under PIPE_BUF on Linux,
    /// and JSONL lines on the agent's hot path are well under
    /// 4 KiB — typical entry is <500 bytes). On success advances
    /// the in-memory tail hash and returns the entry as
    /// persisted.
    pub fn append(&mut self, draft: AuditEntryDraft) -> Result<AuditEntry> {
        let entry = build_signed_entry(&draft, &self.key, &self.agent_id, &self.last_hash)?;
        let mut line = serde_json::to_string(&entry)
            .map_err(|e| anyhow!("serialising audit entry: {e}"))?;
        line.push('\n');
        let mut f = OpenOptions::new()
            .create(true)
            .append(true)
            .mode(AUDIT_LOG_FILE_MODE)
            .open(&self.path)
            .with_context(|| format!("opening audit log {} for append", self.path.display()))?;
        f.write_all(line.as_bytes())
            .with_context(|| format!("appending audit entry to {}", self.path.display()))?;
        f.sync_all()
            .with_context(|| format!("fsync {}", self.path.display()))?;
        self.last_hash = entry.entry_hash.clone();
        Ok(entry)
    }

    /// Tail hash an auditor would chain the NEXT entry off. Test
    /// helper + future-proofing for the off-host reader.
    pub fn last_hash(&self) -> &str {
        &self.last_hash
    }
}

/// Read the final `entry_hash` from `path`, or
/// [`GENESIS_PREV_HASH`] if the file is missing / empty. Errors
/// on a malformed final line — that is exactly the corruption
/// signal A12's verify-on-read flow surfaces, but for the
/// agent's write path the early failure is preferable to
/// chaining off garbage.
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
        let entry: AuditEntry = serde_json::from_str(&line)
            .with_context(|| format!("parsing audit-log line: {line}"))?;
        last = Some(entry.entry_hash);
    }
    Ok(last.unwrap_or_else(|| GENESIS_PREV_HASH.to_string()))
}

/// Pure helper: compute `entry_hash` + signature for a draft
/// against a given `prev_hash` and signing key. Extracted from
/// [`AuditLog::append`] so [`verify_chain`] can recompute the
/// same bytes for cross-check.
fn build_signed_entry(
    draft: &AuditEntryDraft,
    key: &AgentSigningKey,
    agent_id: &[u8; 16],
    prev_hash: &str,
) -> Result<AuditEntry> {
    let ts = format_ts(Utc::now());
    let mut entry = AuditEntry {
        ts,
        agent_id: hex::encode(agent_id),
        op: draft.op.clone(),
        extra: draft.extra.clone(),
        key_fp: draft.key_fp.clone(),
        cosigner_fps: draft.cosigner_fps.clone(),
        result: draft.result.clone(),
        client_pid: draft.client_pid,
        client_uid: draft.client_uid,
        client_comm: draft.client_comm.clone(),
        prev_hash: prev_hash.to_string(),
        // Filled below — empty here so they are excluded from the
        // hashed pre-image.
        entry_hash: String::new(),
        agent_sig: String::new(),
    };
    let entry_hash = compute_entry_hash(&entry)?;
    entry.entry_hash = hex::encode(entry_hash);
    let sig = key.sign(&entry_hash);
    entry.agent_sig = B64.encode(sig.to_bytes());
    Ok(entry)
}

/// Compute `entry_hash` over the canonical pre-image:
/// `SHA-256(prev_hash_bytes || canonical_json(entry minus
/// entry_hash + agent_sig))`. Both `entry_hash` and `agent_sig`
/// MUST be empty strings at call time so the JSON pre-image
/// stays free of those fields' eventual contents — verifiers
/// reproduce the same bytes by clearing those fields before
/// recomputing.
fn compute_entry_hash(entry: &AuditEntry) -> Result<[u8; 32]> {
    debug_assert!(entry.entry_hash.is_empty());
    debug_assert!(entry.agent_sig.is_empty());
    let prev_bytes =
        hex::decode(&entry.prev_hash).map_err(|e| anyhow!("prev_hash is not valid hex: {e}"))?;
    let body =
        serde_json::to_vec(entry).map_err(|e| anyhow!("serialising audit pre-image: {e}"))?;
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

/// Outcome of one [`verify_chain`] run on a tampered chain.
/// Carrying the 0-based index lets the operator pinpoint the
/// first broken entry without re-running the verifier.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AuditVerifyError {
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

/// Replay `entries` in order, recomputing each `entry_hash` and
/// checking each `agent_sig` against `pubkey`. Returns `Ok(())` on
/// a fully-intact chain. Used by the agent's own `AuditLog::open`
/// path (which discards the result, since open is best-effort
/// fast) and by the future `nn-admin audit verify` reader.
pub fn verify_chain(entries: &[AuditEntry], pubkey: &VerifyingKey) -> Result<(), AuditVerifyError> {
    let mut expected_prev = GENESIS_PREV_HASH.to_string();
    for (idx, entry) in entries.iter().enumerate() {
        if entry.prev_hash != expected_prev {
            return Err(AuditVerifyError::PrevHashMismatch {
                idx,
                got: entry.prev_hash.clone(),
                expected: expected_prev,
            });
        }
        // Recompute against a "stripped" copy with both
        // chain-output fields cleared, matching the pre-image
        // build_signed_entry hashed.
        let mut stripped = entry.clone();
        stripped.entry_hash.clear();
        stripped.agent_sig.clear();
        let recomputed = compute_entry_hash(&stripped).map_err(|e| {
            AuditVerifyError::MalformedField {
                idx,
                reason: e.to_string(),
            }
        })?;
        let recomputed_hex = hex::encode(recomputed);
        if recomputed_hex != entry.entry_hash {
            return Err(AuditVerifyError::EntryHashMismatch {
                idx,
                recomputed: recomputed_hex,
                stored: entry.entry_hash.clone(),
            });
        }
        let sig_bytes = B64
            .decode(&entry.agent_sig)
            .map_err(|e| AuditVerifyError::MalformedField {
                idx,
                reason: format!("agent_sig base64 decode: {e}"),
            })?;
        if sig_bytes.len() != 64 {
            return Err(AuditVerifyError::MalformedField {
                idx,
                reason: format!("agent_sig length {} (expected 64)", sig_bytes.len()),
            });
        }
        let mut sig_arr = [0u8; 64];
        sig_arr.copy_from_slice(&sig_bytes);
        let sig = Signature::from_bytes(&sig_arr);
        if pubkey.verify(&recomputed, &sig).is_err() {
            return Err(AuditVerifyError::SignatureInvalid { idx });
        }
        expected_prev = entry.entry_hash.clone();
    }
    Ok(())
}

// ── tests ───────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use tempfile::TempDir;

    fn fresh_paths() -> (TempDir, PathBuf, PathBuf) {
        let dir = tempfile::tempdir().expect("create tempdir");
        let key_path = dir.path().join("agent.sig.key");
        let log_path = dir.path().join("audit.log");
        (dir, key_path, log_path)
    }

    fn sample_draft(seq: u32) -> AuditEntryDraft {
        AuditEntryDraft {
            op: format!("test_op_{seq}"),
            extra: serde_json::json!({ "seq": seq }),
            key_fp: format!("{seq:08x}"),
            cosigner_fps: vec![],
            result: "success".to_string(),
            client_pid: 12345,
            client_uid: 0,
            client_comm: "nn-admin".to_string(),
        }
    }

    // ── Test 1 (design A11 #1): fresh-gen signing key on disk has
    //                            mode 0400.
    #[test]
    fn signing_key_fresh_gen_writes_mode_0400() {
        let (_dir, key_path, _) = fresh_paths();
        let _key = AgentSigningKey::load_or_bootstrap(&key_path)
            .expect("bootstrap should succeed on missing path");
        let meta = fs::metadata(&key_path).expect("file should exist");
        assert_eq!(
            meta.permissions().mode() & 0o777,
            0o400,
            "signing key file should be mode 0400"
        );
        let raw = fs::read_to_string(&key_path).unwrap();
        let trimmed = raw.strip_suffix('\n').unwrap_or(&raw);
        assert_eq!(trimmed.len(), SIGNING_KEY_HEX_LEN);
        assert!(trimmed.chars().all(|c| c.is_ascii_hexdigit()));
    }

    // ── Test 2 (design A11 #2): reuse-existing returns same key
    //                            (round-trips via the disk file).
    #[test]
    fn signing_key_reuses_existing_file() {
        let (_dir, key_path, _) = fresh_paths();
        let first = AgentSigningKey::load_or_bootstrap(&key_path).expect("first bootstrap");
        let second = AgentSigningKey::load_or_bootstrap(&key_path).expect("second load");
        assert_eq!(
            first.inner.to_bytes(),
            second.inner.to_bytes(),
            "second load must return the persisted key bytes"
        );
    }

    // ── Test 3 (design A11 #3): corrupted file is a hard error
    //                            (NO silent regeneration).
    #[test]
    fn signing_key_corrupted_file_errors_without_regen() {
        let (_dir, key_path, _) = fresh_paths();
        fs::write(&key_path, "definitely not hex\n").unwrap();
        let err = AgentSigningKey::load_or_bootstrap(&key_path)
            .expect_err("corrupted file must hard-error");
        let msg = format!("{err:#}");
        assert!(
            msg.contains("corrupted") || msg.contains("not valid hex") || msg.contains("hex chars"),
            "error must mention corruption / hex problem; got: {msg}"
        );
        // The corrupted file must remain untouched — no silent
        // regeneration that would invalidate the audit log.
        let after = fs::read_to_string(&key_path).unwrap();
        assert_eq!(after, "definitely not hex\n");
    }

    // ── Test 4 (design A11 #4): open on missing file initialises
    //                            with the genesis prev_hash.
    #[test]
    fn open_missing_log_starts_at_genesis() {
        let (_dir, key_path, log_path) = fresh_paths();
        let key = AgentSigningKey::load_or_bootstrap(&key_path).unwrap();
        let log = AuditLog::open(&log_path, key, [0u8; 16]).expect("open missing file");
        assert_eq!(log.last_hash(), GENESIS_PREV_HASH);
        // open() must NOT create the file itself — first append
        // does. That keeps "open then never write" cheap.
        assert!(!log_path.exists());
    }

    // ── Test 5 (design A11 #5): append produces a JSONL line whose
    //                            entry_hash + signature both verify.
    #[test]
    fn append_writes_signed_jsonl_line() {
        let (_dir, key_path, log_path) = fresh_paths();
        let key = AgentSigningKey::load_or_bootstrap(&key_path).unwrap();
        let pubkey = key.verifying_key();
        let mut log = AuditLog::open(&log_path, key, [0u8; 16]).unwrap();
        let entry = log.append(sample_draft(1)).expect("first append");
        // File contents are exactly one JSONL line.
        let raw = fs::read_to_string(&log_path).unwrap();
        assert!(raw.ends_with('\n'));
        assert_eq!(raw.lines().count(), 1);
        // Round-trip parses cleanly.
        let parsed: AuditEntry = serde_json::from_str(raw.trim_end()).unwrap();
        assert_eq!(parsed, entry);
        // Chain link starts at genesis.
        assert_eq!(parsed.prev_hash, GENESIS_PREV_HASH);
        // verify_chain accepts this single-entry log.
        verify_chain(&[parsed], &pubkey).expect("single-entry chain must verify");
    }

    // ── Test 6 (design A11 #6): two appends chain (second.prev_hash
    //                            == first.entry_hash).
    #[test]
    fn second_append_chains_off_first_entry() {
        let (_dir, key_path, log_path) = fresh_paths();
        let key = AgentSigningKey::load_or_bootstrap(&key_path).unwrap();
        let pubkey = key.verifying_key();
        let mut log = AuditLog::open(&log_path, key, [0u8; 16]).unwrap();
        let first = log.append(sample_draft(1)).unwrap();
        let second = log.append(sample_draft(2)).unwrap();
        assert_eq!(
            second.prev_hash, first.entry_hash,
            "second.prev_hash must chain off first.entry_hash"
        );
        // Read both lines back and verify the full chain.
        let raw = fs::read_to_string(&log_path).unwrap();
        let entries: Vec<AuditEntry> = raw
            .lines()
            .map(|l| serde_json::from_str(l).expect("parse"))
            .collect();
        assert_eq!(entries.len(), 2);
        verify_chain(&entries, &pubkey).expect("two-entry chain must verify");
    }

    // ── Test 7 (design A11 #7): verify_chain rejects a payload
    //                            field tampered post-write.
    #[test]
    fn verify_chain_detects_payload_tamper() {
        let (_dir, key_path, log_path) = fresh_paths();
        let key = AgentSigningKey::load_or_bootstrap(&key_path).unwrap();
        let pubkey = key.verifying_key();
        let mut log = AuditLog::open(&log_path, key, [0u8; 16]).unwrap();
        let _ = log.append(sample_draft(1)).unwrap();
        let _ = log.append(sample_draft(2)).unwrap();
        let raw = fs::read_to_string(&log_path).unwrap();
        let mut entries: Vec<AuditEntry> = raw
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect();
        // Attacker rewrites the first record's `result` field but
        // leaves the chain hashes alone — entry_hash recomputation
        // catches the divergence on entry 0.
        entries[0].result = "failure: attacker covered tracks".to_string();
        let err = verify_chain(&entries, &pubkey).expect_err("tampered chain must fail");
        assert!(
            matches!(err, AuditVerifyError::EntryHashMismatch { idx: 0, .. }),
            "expected EntryHashMismatch on entry 0; got: {err:?}"
        );
    }

    // ── Test 8 (design A11 #8): verify_chain rejects a flipped
    //                            signature.
    #[test]
    fn verify_chain_detects_signature_tamper() {
        let (_dir, key_path, log_path) = fresh_paths();
        let key = AgentSigningKey::load_or_bootstrap(&key_path).unwrap();
        let pubkey = key.verifying_key();
        let mut log = AuditLog::open(&log_path, key, [0u8; 16]).unwrap();
        let _ = log.append(sample_draft(1)).unwrap();
        let raw = fs::read_to_string(&log_path).unwrap();
        let mut entries: Vec<AuditEntry> = raw
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect();
        // Flip one byte in the signature. Decode-encode round-trip
        // keeps the base64 length intact and exercises the
        // verify path, not the parser.
        let mut sig_bytes = B64.decode(&entries[0].agent_sig).unwrap();
        sig_bytes[0] ^= 0x01;
        entries[0].agent_sig = B64.encode(sig_bytes);
        let err = verify_chain(&entries, &pubkey).expect_err("flipped sig must fail");
        assert!(
            matches!(err, AuditVerifyError::SignatureInvalid { idx: 0 }),
            "expected SignatureInvalid on entry 0; got: {err:?}"
        );
    }
}
