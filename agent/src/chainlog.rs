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
//!   drop ([`ManifestEvent::Evicted`]).
//!
//! Three line kinds, all chained + signed:
//! - **data line** — [`ChainLine<P>`]: the payload `P` flattened inline
//!   plus `fmt_ver?`,`prev_hash`,`entry_hash`,`agent_sig`. `fmt_ver` is
//!   ABSENT on legacy pre-BUG-026 lines (so they still verify
//!   byte-for-byte) and `Some(`[`CHAINLOG_FMT_V2`]`)` on new lines.
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
use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use anyhow::{anyhow, Context, Result};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use chrono::Utc;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::audit::{AgentSigningKey, GENESIS_PREV_HASH};

/// On-disk format version this module writes. v1 (the legacy flat line
/// with NO `fmt_ver`) is still read + verified; we never write it.
pub const CHAINLOG_FMT_V2: u32 = 2;

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

/// `SHA-256(prev_hash_bytes ‖ canonical_json(body))` where `body` is the
/// line struct with `entry_hash`/`agent_sig` already empty. Mirrors
/// `audit::compute_entry_hash` so the rule is identical across every
/// chain in the system.
fn chain_digest<T: Serialize>(body: &T, prev_hash: &str) -> Result<[u8; 32]> {
    let prev = hex::decode(prev_hash).map_err(|e| anyhow!("prev_hash not hex: {e}"))?;
    let json = serde_json::to_vec(body).map_err(|e| anyhow!("serialising chain pre-image: {e}"))?;
    let mut h = Sha256::new();
    h.update(&prev);
    h.update(&json);
    Ok(h.finalize().into())
}

fn now_ts() -> String {
    Utc::now().format("%Y-%m-%dT%H:%M:%S%.6fZ").to_string()
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

impl<P: Serialize> ChainLine<P> {
    /// Build a fully-signed v2 data line chained off `prev_hash`.
    fn sealed(payload: P, key: &AgentSigningKey, prev_hash: &str) -> Result<Self> {
        let mut line = ChainLine {
            payload,
            fmt_ver: Some(CHAINLOG_FMT_V2),
            prev_hash: prev_hash.to_string(),
            entry_hash: String::new(),
            agent_sig: String::new(),
        };
        let digest = chain_digest(&line, prev_hash)?;
        line.entry_hash = hex::encode(digest);
        line.agent_sig = B64.encode(key.sign(&digest).to_bytes());
        Ok(line)
    }
}

impl TerminatorLine {
    fn sealed(
        rotate: RotateTerminator,
        key: &AgentSigningKey,
        prev_hash: &str,
    ) -> Result<Self> {
        let mut line = TerminatorLine {
            rotate,
            ts: now_ts(),
            prev_hash: prev_hash.to_string(),
            entry_hash: String::new(),
            agent_sig: String::new(),
        };
        let digest = chain_digest(&line, prev_hash)?;
        line.entry_hash = hex::encode(digest);
        line.agent_sig = B64.encode(key.sign(&digest).to_bytes());
        Ok(line)
    }
}

impl ManifestLine {
    fn sealed(manifest: ManifestEntry, key: &AgentSigningKey, prev_hash: &str) -> Result<Self> {
        let mut line = ManifestLine {
            manifest,
            prev_hash: prev_hash.to_string(),
            entry_hash: String::new(),
            agent_sig: String::new(),
        };
        let digest = chain_digest(&line, prev_hash)?;
        line.entry_hash = hex::encode(digest);
        line.agent_sig = B64.encode(key.sign(&digest).to_bytes());
        Ok(line)
    }
}

/// Serialise a line struct to a `\n`-terminated JSONL string.
fn to_jsonl<T: Serialize>(line: &T) -> Result<String> {
    let mut s = serde_json::to_string(line).map_err(|e| anyhow!("serialising chainlog line: {e}"))?;
    s.push('\n');
    Ok(s)
}

/// Append a pre-serialised line to `path` (create if missing) + fsync.
fn append_and_fsync(path: &Path, line: &str, mode: u32) -> Result<()> {
    let mut f = OpenOptions::new()
        .create(true)
        .append(true)
        .mode(mode)
        .open(path)
        .with_context(|| format!("opening chainlog {} for append", path.display()))?;
    f.write_all(line.as_bytes())
        .with_context(|| format!("appending to {}", path.display()))?;
    f.sync_all()
        .with_context(|| format!("fsync {}", path.display()))?;
    Ok(())
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
            file_mode: 0o600,
        }
    }
}

/// Append-only, rotation-aware, signed chain writer for one log.
pub struct RotatingChainLog<P> {
    active_path: PathBuf,
    manifest_path: PathBuf,
    key: AgentSigningKey,
    cfg: RotationConfig,
    protection: std::sync::Arc<dyn ProtectionManager>,
    /// Tail `entry_hash` the next data line chains off (the previous
    /// file's terminator hash right after a rotation; GENESIS on a
    /// fresh seq-0 file).
    last_hash: String,
    /// Separate tail for the manifest chain.
    manifest_last_hash: String,
    active_bytes: u64,
    active_records: u64,
    /// Seq the NEXT rotation assigns to the sealed file.
    next_seq: u64,
    _marker: std::marker::PhantomData<P>,
}

impl<P: Serialize + DeserializeOwned> RotatingChainLog<P> {
    /// Open (or initialise) the log at `active_path`. Scans existing
    /// archives to recover `next_seq`, walks the (bounded) active file
    /// for its tail/size/count, and completes a half-finished rotation
    /// if a crash left the active file sealed-but-unrenamed.
    pub fn open(
        active_path: &Path,
        key: AgentSigningKey,
        cfg: RotationConfig,
        protection: std::sync::Arc<dyn ProtectionManager>,
    ) -> Result<Self> {
        let manifest_path = manifest_path_for(active_path);
        let next_seq = scan_max_archive_seq(active_path)?.map_or(1, |m| m + 1);
        let manifest_last_hash = read_tail_hash(&manifest_path)?;

        let mut log = Self {
            active_path: active_path.to_path_buf(),
            manifest_path,
            key,
            cfg,
            protection,
            last_hash: GENESIS_PREV_HASH.to_string(),
            manifest_last_hash,
            active_bytes: 0,
            active_records: 0,
            next_seq,
            _marker: std::marker::PhantomData,
        };

        let (tail, records, bytes, sealed) = walk_active(active_path)?;
        if sealed {
            // Crash recovery: the active file was sealed (terminator
            // written) but the rename never completed. Finish it so the
            // invariant "the active file has no terminator" is restored.
            log.last_hash = tail; // terminator hash → meta-chain link
            log.active_bytes = bytes;
            log.active_records = records;
            log.complete_interrupted_rotation()?;
        } else {
            log.last_hash = if records == 0 {
                // Fresh seq-0 file roots at GENESIS; a fresh post-rotation
                // file would already have its first line written, so an
                // empty active here is genuinely seq-0.
                if next_seq == 1 {
                    GENESIS_PREV_HASH.to_string()
                } else {
                    // Empty active after rotation: its first line must
                    // chain off the prior archive's terminator.
                    prior_terminator_hash(active_path, next_seq - 1)?
                }
            } else {
                tail
            };
            log.active_bytes = bytes;
            log.active_records = records;
        }
        Ok(log)
    }

    /// Tail hash the next data line will chain off (test/introspection).
    pub fn last_hash(&self) -> &str {
        &self.last_hash
    }

    /// Append one payload as a signed data line, rotating first if it
    /// would push the active file past the size cap. Returns the new
    /// line's `entry_hash`.
    pub fn append(&mut self, payload: P) -> Result<String> {
        check_reserved_keys(&payload)?;
        let line = ChainLine::sealed(payload, &self.key, &self.last_hash)?;
        let bytes = to_jsonl(&line)?;
        if self.active_records > 0
            && self.active_bytes + bytes.len() as u64 > self.cfg.size_cap_bytes
        {
            self.rotate()?;
            // After rotation the line was hashed off the OLD tail; rebuild
            // it off the new tail (the terminator hash / meta-chain link).
            let line = ChainLine::sealed(line.payload, &self.key, &self.last_hash)?;
            let bytes = to_jsonl(&line)?;
            append_and_fsync(&self.active_path, &bytes, self.cfg.file_mode)?;
            self.last_hash = line.entry_hash.clone();
            self.active_bytes += bytes.len() as u64;
            self.active_records += 1;
            return Ok(line.entry_hash);
        }
        append_and_fsync(&self.active_path, &bytes, self.cfg.file_mode)?;
        self.last_hash = line.entry_hash.clone();
        self.active_bytes += bytes.len() as u64;
        self.active_records += 1;
        Ok(line.entry_hash)
    }

    /// Seal the active file, archive it, open a fresh active, and evict
    /// the oldest archive(s) beyond the retention budget.
    fn rotate(&mut self) -> Result<()> {
        let seq = self.next_seq;
        let term = TerminatorLine::sealed(
            RotateTerminator {
                fmt_ver: CHAINLOG_FMT_V2,
                this_seq: seq,
                next_seq: seq + 1,
                record_count: self.active_records,
                bytes: self.active_bytes,
            },
            &self.key,
            &self.last_hash,
        )?;
        let terminator_hash = term.entry_hash.clone();
        append_and_fsync(&self.active_path, &to_jsonl(&term)?, self.cfg.file_mode)?;

        // Dir-entry mutations under lifted immutability, restored on every
        // exit path by the manager's RAII guard.
        let active = self.active_path.clone();
        let archive = archive_path(&active, seq);
        let max_archives = self.cfg.max_archives;
        let file_mode = self.cfg.file_mode;
        let protection_inner = std::sync::Arc::clone(&self.protection);
        let mut evicted: Vec<(u64, String)> = Vec::new();
        {
            let evicted_ref = &mut evicted;
            self.protection.with_mutable_dir(&mut || -> Result<()> {
                fs::rename(&active, &archive).with_context(|| {
                    format!("sealing {} → {}", active.display(), archive.display())
                })?;
                OpenOptions::new()
                    .create(true)
                    .write(true)
                    .truncate(true)
                    .mode(file_mode)
                    .open(&active)
                    .with_context(|| format!("creating fresh active {}", active.display()))?;
                protection_inner.register_active(&active)?;
                *evicted_ref = evict_excess_archives(&active, max_archives)?;
                Ok(())
            })?;
        }

        let sealed_bytes = self.active_bytes;
        let sealed_records = self.active_records;
        self.manifest_append(ManifestEvent::Rotated {
            seq,
            terminator_hash: terminator_hash.clone(),
            bytes: sealed_bytes,
            records: sealed_records,
        })?;
        for (eseq, ehash) in evicted {
            self.manifest_append(ManifestEvent::Evicted {
                seq: eseq,
                terminator_hash: ehash,
            })?;
        }

        // Meta-chain: the fresh active's first data line chains off the
        // terminator we just wrote.
        self.last_hash = terminator_hash;
        self.active_bytes = 0;
        self.active_records = 0;
        self.next_seq = seq + 1;
        Ok(())
    }

    /// Finish a rotation that crashed after the seal but before/at the
    /// rename. The active file currently ends in a terminator for
    /// `next_seq`; rename it to its archive and open a fresh active.
    fn complete_interrupted_rotation(&mut self) -> Result<()> {
        let seq = self.next_seq;
        let active = self.active_path.clone();
        let archive = archive_path(&active, seq);
        let file_mode = self.cfg.file_mode;
        let max_archives = self.cfg.max_archives;
        let terminator_hash = self.last_hash.clone();
        let protection_inner = std::sync::Arc::clone(&self.protection);
        let mut evicted: Vec<(u64, String)> = Vec::new();
        {
            let evicted_ref = &mut evicted;
            self.protection.with_mutable_dir(&mut || -> Result<()> {
                if !archive.exists() {
                    fs::rename(&active, &archive).with_context(|| {
                        format!("recovering {} → {}", active.display(), archive.display())
                    })?;
                }
                OpenOptions::new()
                    .create(true)
                    .write(true)
                    .truncate(true)
                    .mode(file_mode)
                    .open(&active)
                    .with_context(|| format!("creating fresh active {}", active.display()))?;
                protection_inner.register_active(&active)?;
                *evicted_ref = evict_excess_archives(&active, max_archives)?;
                Ok(())
            })?;
        }
        // Manifest may or may not already carry the Rotated row (crash
        // timing). A duplicate is harmless to the verifier (it matches
        // the terminator); record it to be safe.
        self.manifest_append(ManifestEvent::Rotated {
            seq,
            terminator_hash,
            bytes: self.active_bytes,
            records: self.active_records,
        })?;
        for (eseq, ehash) in evicted {
            self.manifest_append(ManifestEvent::Evicted {
                seq: eseq,
                terminator_hash: ehash,
            })?;
        }
        // last_hash already == terminator hash (meta-chain link).
        self.active_bytes = 0;
        self.active_records = 0;
        self.next_seq = seq + 1;
        Ok(())
    }

    fn manifest_append(&mut self, event: ManifestEvent) -> Result<()> {
        let entry = ManifestEntry {
            fmt_ver: CHAINLOG_FMT_V2,
            ts: now_ts(),
            event,
        };
        let line = ManifestLine::sealed(entry, &self.key, &self.manifest_last_hash)?;
        append_and_fsync(&self.manifest_path, &to_jsonl(&line)?, self.cfg.file_mode)?;
        self.manifest_last_hash = line.entry_hash;
        Ok(())
    }
}

// ── path helpers ────────────────────────────────────────────────────

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
fn parse_archive_seq(active: &Path, name: &std::ffi::OsStr) -> Option<u64> {
    let base = active.file_name()?.to_str()?;
    let name = name.to_str()?;
    let suffix = name.strip_prefix(base)?.strip_prefix('.')?;
    if suffix.len() == SEQ_WIDTH && suffix.bytes().all(|b| b.is_ascii_digit()) {
        suffix.parse::<u64>().ok()
    } else {
        None
    }
}

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

/// Drop oldest archives beyond `max_archives`, returning the
/// `(seq, terminator_hash)` of each evicted file (hash read from the
/// archive's terminator line before unlink, for the manifest record).
fn evict_excess_archives(active: &Path, max_archives: usize) -> Result<Vec<(u64, String)>> {
    let seqs = list_archive_seqs(active)?;
    if seqs.len() <= max_archives {
        return Ok(Vec::new());
    }
    let drop_n = seqs.len() - max_archives;
    let mut evicted = Vec::new();
    for &seq in seqs.iter().take(drop_n) {
        let path = archive_path(active, seq);
        let hash = read_terminator_hash(&path).unwrap_or_default();
        fs::remove_file(&path)
            .with_context(|| format!("evicting archive {}", path.display()))?;
        evicted.push((seq, hash));
    }
    Ok(evicted)
}

// ── readers (tail recovery, recovery probe) ─────────────────────────

/// Walk `path`, returning `(tail_entry_hash, record_count, byte_len,
/// ends_with_terminator)`. Used at open to recover the active file's
/// state; the active file is size-capped so this is bounded (it also
/// replaces the old unbounded boot walk over a multi-GB file).
fn walk_active(path: &Path) -> Result<(String, u64, u64, bool)> {
    let f = match OpenOptions::new().read(true).open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Ok((GENESIS_PREV_HASH.to_string(), 0, 0, false));
        }
        Err(e) => return Err(anyhow!(e).context(format!("reading {}", path.display()))),
    };
    let mut tail = GENESIS_PREV_HASH.to_string();
    let mut records = 0u64;
    let mut bytes = 0u64;
    let mut sealed = false;
    for line in BufReader::new(f).lines() {
        let line = line.with_context(|| format!("reading line from {}", path.display()))?;
        if line.is_empty() {
            continue;
        }
        bytes += line.len() as u64 + 1; // + '\n'
        if let Some(hash) = terminator_entry_hash(&line) {
            tail = hash;
            sealed = true;
        } else {
            let v: serde_json::Value = serde_json::from_str(&line)
                .with_context(|| format!("parsing chainlog line: {line}"))?;
            tail = v
                .get("entry_hash")
                .and_then(|h| h.as_str())
                .ok_or_else(|| anyhow!("line missing entry_hash"))?
                .to_string();
            records += 1;
            sealed = false;
        }
    }
    Ok((tail, records, bytes, sealed))
}

/// Tail `entry_hash` of a chain file (manifest / generic), GENESIS if
/// missing/empty. Does not distinguish data vs terminator (manifests
/// have neither terminators); used for the manifest chain's tail.
fn read_tail_hash(path: &Path) -> Result<String> {
    let (tail, _, _, _) = walk_active(path)?;
    Ok(tail)
}

/// If `line` is a terminator, return its `entry_hash`.
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
    #[error("file {file}: entry {idx}: entry_hash mismatch (recomputed {recomputed}, stored {stored})")]
    EntryHashMismatch {
        file: String,
        idx: usize,
        recomputed: String,
        stored: String,
    },
    #[error("file {file}: entry {idx}: signature invalid")]
    SignatureInvalid { file: String, idx: usize },
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
}

/// Verify the entire rotation set for `active_path` end-to-end against
/// `pubkey`: every sealed archive in seq order, then the active file,
/// carrying `expected_prev` across terminator boundaries (GENESIS only
/// for seq 0). A retention-evicted prefix is accepted **only** if the
/// signed manifest carries an `Evicted` row for each missing seq.
pub fn verify_log_set<P: Serialize + DeserializeOwned>(
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
    // are verified inside `verify_manifest_evictions`) must attest each
    // dropped seq, and the earliest retained archive is rooted on the
    // manifest's attested terminator hash of its now-absent predecessor —
    // NOT on the file's own claimed prev_hash (which would make the
    // first-line boundary check a tautology and let a forged predecessor
    // link slide through).
    let mut expected_prev = GENESIS_PREV_HASH.to_string();
    if earliest_retained_seq > 1 {
        let evicted = verify_manifest_evictions(active_path, pubkey)?;
        for seq in 1..earliest_retained_seq {
            if !evicted.contains_key(&seq) {
                return Err(LogSetError::UncorroboratedEviction { seq });
            }
        }
        expected_prev = evicted
            .get(&(earliest_retained_seq - 1))
            .cloned()
            .ok_or(LogSetError::UncorroboratedEviction {
                seq: earliest_retained_seq - 1,
            })?;
    }

    let mut total_records = 0u64;

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
        let (term_hash, records) =
            verify_one_file::<P>(&path, &expected_prev, pubkey, Some(seq))?;
        total_records += records;
        expected_prev = term_hash.expect("sealed archive ends in a terminator");
        prev_seq = Some(seq);
    }

    // Active file (no terminator).
    let (_tail, records) = verify_one_file::<P>(active_path, &expected_prev, pubkey, None)?;
    total_records += records;

    Ok(LogSetReport {
        earliest_retained_seq,
        archives_verified: seqs.len(),
        total_records,
    })
}

/// Verify one file's chain from `expected_prev`. Returns
/// `(terminator_hash_if_sealed, data_record_count)`. `archive_seq` is
/// `Some` for sealed archives (asserts the terminator's `this_seq`).
fn verify_one_file<P: Serialize + DeserializeOwned>(
    path: &Path,
    expected_prev: &str,
    pubkey: &VerifyingKey,
    archive_seq: Option<u64>,
) -> Result<(Option<String>, u64), LogSetError> {
    let file = path.display().to_string();
    let f = match OpenOptions::new().read(true).open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound && archive_seq.is_none() => {
            // A never-created active file (fresh seq-0 deploy) is a
            // valid empty chain.
            return Ok((None, 0));
        }
        Err(e) => {
            return Err(LogSetError::Malformed {
                file,
                idx: 0,
                reason: e.to_string(),
            })
        }
    };

    let mut expected = expected_prev.to_string();
    let mut records = 0u64;
    let mut term_hash = None;
    for (idx, line) in BufReader::new(f).lines().enumerate() {
        let line = line.map_err(|e| LogSetError::Malformed {
            file: file.clone(),
            idx,
            reason: e.to_string(),
        })?;
        if line.is_empty() {
            continue;
        }
        let is_terminator = serde_json::from_str::<serde_json::Value>(&line)
            .ok()
            .and_then(|v| v.get("rotate").cloned())
            .is_some();

        let (prev, stored_hash) = if is_terminator {
            let t: TerminatorLine =
                serde_json::from_str(&line).map_err(|e| LogSetError::Malformed {
                    file: file.clone(),
                    idx,
                    reason: format!("terminator decode: {e}"),
                })?;
            if let Some(seq) = archive_seq {
                if t.rotate.this_seq != seq {
                    return Err(LogSetError::TerminatorSeqMismatch {
                        seq,
                        got: t.rotate.this_seq,
                    });
                }
            }
            let mut stripped = t.clone();
            stripped.entry_hash.clear();
            stripped.agent_sig.clear();
            let recomputed = recompute_hex(&stripped, &t.prev_hash, &file, idx)?;
            check_entry(&file, idx, &recomputed, &t.entry_hash, &t.agent_sig, pubkey)?;
            term_hash = Some(t.entry_hash.clone());
            (t.prev_hash, t.entry_hash)
        } else {
            let mut d: ChainLine<P> =
                serde_json::from_str(&line).map_err(|e| LogSetError::Malformed {
                    file: file.clone(),
                    idx,
                    reason: format!("data decode: {e}"),
                })?;
            let prev = d.prev_hash.clone();
            let stored_hash = d.entry_hash.clone();
            let sig = d.agent_sig.clone();
            d.entry_hash.clear();
            d.agent_sig.clear();
            let recomputed = recompute_hex(&d, &prev, &file, idx)?;
            check_entry(&file, idx, &recomputed, &stored_hash, &sig, pubkey)?;
            records += 1;
            (prev, stored_hash)
        };
        if prev != expected {
            return Err(LogSetError::PrevHashMismatch {
                file,
                idx,
                got: prev,
                expected,
            });
        }
        expected = stored_hash;
    }
    Ok((term_hash, records))
}

fn recompute_hex<T: Serialize>(
    body: &T,
    prev_hash: &str,
    file: &str,
    idx: usize,
) -> Result<String, LogSetError> {
    chain_digest(body, prev_hash)
        .map(hex::encode)
        .map_err(|e| LogSetError::Malformed {
            file: file.to_string(),
            idx,
            reason: e.to_string(),
        })
}

fn check_entry(
    file: &str,
    idx: usize,
    recomputed_hex: &str,
    stored_hex: &str,
    sig_b64: &str,
    pubkey: &VerifyingKey,
) -> Result<(), LogSetError> {
    if recomputed_hex != stored_hex {
        return Err(LogSetError::EntryHashMismatch {
            file: file.to_string(),
            idx,
            recomputed: recomputed_hex.to_string(),
            stored: stored_hex.to_string(),
        });
    }
    let digest = hex::decode(stored_hex).map_err(|e| LogSetError::Malformed {
        file: file.to_string(),
        idx,
        reason: format!("entry_hash hex: {e}"),
    })?;
    let sig_bytes = B64.decode(sig_b64).map_err(|e| LogSetError::Malformed {
        file: file.to_string(),
        idx,
        reason: format!("agent_sig b64: {e}"),
    })?;
    if sig_bytes.len() != 64 {
        return Err(LogSetError::Malformed {
            file: file.to_string(),
            idx,
            reason: format!("agent_sig len {} != 64", sig_bytes.len()),
        });
    }
    let mut arr = [0u8; 64];
    arr.copy_from_slice(&sig_bytes);
    if pubkey.verify(&digest, &Signature::from_bytes(&arr)).is_err() {
        return Err(LogSetError::SignatureInvalid {
            file: file.to_string(),
            idx,
        });
    }
    Ok(())
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
fn verify_manifest_evictions(
    active_path: &Path,
    pubkey: &VerifyingKey,
) -> Result<std::collections::BTreeMap<u64, String>, LogSetError> {
    let path = manifest_path_for(active_path);
    let file = path.display().to_string();
    let mut evicted = std::collections::BTreeMap::new();
    let f = match OpenOptions::new().read(true).open(&path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(evicted),
        Err(e) => {
            return Err(LogSetError::Malformed {
                file,
                idx: 0,
                reason: e.to_string(),
            })
        }
    };
    let mut expected = GENESIS_PREV_HASH.to_string();
    for (idx, line) in BufReader::new(f).lines().enumerate() {
        let line = line.map_err(|e| LogSetError::Malformed {
            file: file.clone(),
            idx,
            reason: e.to_string(),
        })?;
        if line.is_empty() {
            continue;
        }
        let mut entry: ManifestLine =
            serde_json::from_str(&line).map_err(|e| LogSetError::Malformed {
                file: file.clone(),
                idx,
                reason: format!("manifest decode: {e}"),
            })?;
        let prev = entry.prev_hash.clone();
        let stored = entry.entry_hash.clone();
        let sig = entry.agent_sig.clone();
        entry.entry_hash.clear();
        entry.agent_sig.clear();
        let recomputed = recompute_hex(&entry, &prev, &file, idx)?;
        check_entry(&file, idx, &recomputed, &stored, &sig, pubkey)?;
        if prev != expected {
            return Err(LogSetError::PrevHashMismatch {
                file,
                idx,
                got: prev,
                expected,
            });
        }
        expected = stored;
        if let ManifestEvent::Evicted {
            seq,
            terminator_hash,
        } = entry.manifest.event
        {
            evicted.insert(seq, terminator_hash);
        }
    }
    Ok(evicted)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[derive(Debug, Clone, Serialize, Deserialize)]
    struct TestPayload {
        ts: String,
        seq: u64,
        data: String,
    }

    fn key() -> AgentSigningKey {
        // Deterministic-enough for tests: bootstrap a fresh key in a tmp.
        let dir = TempDir::new().unwrap();
        AgentSigningKey::load_or_bootstrap(&dir.path().join("k")).unwrap()
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
        let mut log =
            RotatingChainLog::<TestPayload>::open(&active, k, cfg(2000, 50), std::sync::Arc::new(NoProtection))
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
        let mut log =
            RotatingChainLog::<TestPayload>::open(&active, k, cfg(300, 2), std::sync::Arc::new(NoProtection))
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
        let mut log =
            RotatingChainLog::<TestPayload>::open(&active, k, cfg(2000, 50), std::sync::Arc::new(NoProtection))
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
        let mut log =
            RotatingChainLog::<TestPayload>::open(&active, k, cfg(2000, 50), std::sync::Arc::new(NoProtection))
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
        let pk = AgentSigningKey::load_or_bootstrap(&kpath)
            .unwrap()
            .verifying_key();

        for round in [0u64, 25] {
            let k = AgentSigningKey::load_or_bootstrap(&kpath).unwrap();
            let mut log =
                RotatingChainLog::<TestPayload>::open(&active, k, cfg(2000, 50), std::sync::Arc::new(NoProtection))
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
        let mut log =
            RotatingChainLog::<TestPayload>::open(&active, k, cfg(2000, 2), std::sync::Arc::new(NoProtection))
                .unwrap();
        for i in 0..60 {
            log.append(payload(i)).unwrap();
        }
        let earliest = *list_archive_seqs(&active).unwrap().first().unwrap();
        assert!(earliest > 1, "seq 1 (the genesis-rooted file) must be evicted");
        let report = verify_log_set::<TestPayload>(&active, &pk).unwrap();
        assert_eq!(report.earliest_retained_seq, earliest);
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
        let mut log =
            RotatingChainLog::<TestPayload>::open(&active, k, cfg(2000, 2), std::sync::Arc::new(NoProtection))
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
        let dir = TempDir::new().unwrap();
        let active = dir.path().join("evil.jsonl");
        let k = key();
        let mut log =
            RotatingChainLog::<Evil>::open(&active, k, cfg(2000, 50), std::sync::Arc::new(NoProtection))
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
}
