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
use std::io::{BufRead, BufReader, Read, Seek, SeekFrom, Write};
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
use tracing::{error, warn};

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
        // Recover the manifest tail O(1). If a prior crash tore its last
        // line, truncate the fragment so the next manifest line can't fuse
        // with it; the repair is attested below (once the log can sign one).
        let manifest_rec = recover_tail(&manifest_path)?;
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
            manifest_last_hash: manifest_rec.tail_hash,
            active_bytes: 0,
            active_records: 0,
            next_seq,
            _marker: std::marker::PhantomData,
        };

        // Attest a manifest self-repair into its own meta-chain (chained off
        // the recovered tail) — truncating a signed log MUST be recorded.
        if manifest_rec.torn {
            log.attest_torn_repair(
                "manifest",
                manifest_rec.clean_len,
                manifest_rec.dropped_bytes,
                manifest_rec.dropped_sha256,
            )?;
        }

        // Recover the active file's tail O(1) — replaces the unbounded
        // whole-file walk that was the BUG-026 boot hang. Repair + attest a
        // torn tail the same way (the agent is exempt from its own LSM
        // setattr deny, so the in-place truncate is allowed).
        let active_rec = recover_tail(active_path)?;
        if active_rec.torn {
            truncate_file(active_path, active_rec.clean_len)?;
            log.attest_torn_repair(
                "active",
                active_rec.clean_len,
                active_rec.dropped_bytes,
                active_rec.dropped_sha256.clone(),
            )?;
        }
        if active_rec.sealed {
            // Crash recovery: the active file was sealed (terminator
            // written) but the rename never completed. Finish it so the
            // invariant "the active file has no terminator" is restored.
            log.last_hash = active_rec.tail_hash; // terminator hash → meta-chain link
            log.active_bytes = active_rec.clean_len;
            log.complete_interrupted_rotation()?;
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
                    prior_terminator_hash(active_path, next_seq - 1)?
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
        // Guard on `active_bytes` (recovered from the file length at open),
        // NOT `active_records` (which is now 0 after a mid-life open): a
        // pre-existing over-cap active file — e.g. a legacy log inherited at
        // the BUG-026 migration — must rotate on its FIRST append, and an
        // empty fresh file (0 bytes) must NOT rotate its first line.
        if self.active_bytes > 0
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
        let sealed_bytes = self.active_bytes;
        let sealed_records = self.active_records;
        // SEAL: append the terminator to the active file. Done OUTSIDE the
        // `+i` dance — appending to an *existing* file is allowed under an
        // immutable dir; only NEW/renamed dir entries need the lift.
        append_and_fsync(&self.active_path, &to_jsonl(&term)?, self.cfg.file_mode)?;
        self.finish_rotation(seq, terminator_hash, sealed_bytes, sealed_records)
    }

    /// Commit a sealed active file to its `seq` archive and open a fresh
    /// active. Shared by [`rotate`] (which writes the terminator first) and
    /// [`complete_interrupted_rotation`] (whose active was sealed before a
    /// crash). BUG-030 — failure-atomic, and EVERY dir-entry mutation runs
    /// INSIDE the `+i` dance:
    ///
    /// 1. **rename** active → `.NNNNNN` (idempotent: skipped if already done).
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
        let archive = archive_path(&active, seq);
        let file_mode = self.cfg.file_mode;
        let max_archives = self.cfg.max_archives;
        // Receiver clone + a second clone for register_active, so the dance
        // closure can borrow `self` mutably (advance + manifest) without
        // aliasing the protection manager it runs under.
        let protection = std::sync::Arc::clone(&self.protection);
        let protection_inner = std::sync::Arc::clone(&self.protection);
        protection.with_mutable_dir(&mut || -> Result<()> {
            // 1. RENAME (idempotent: a crash may have renamed but not finished).
            if !archive.exists() {
                fs::rename(&active, &archive).with_context(|| {
                    format!("sealing {} → {}", active.display(), archive.display())
                })?;
            }
            // 2. COMMIT POINT — advance seq + reset counters immediately. The
            //    archive is now on disk; from here no failure may re-rotate
            //    into `seq`. last_hash = terminator (fresh active's chain link).
            self.last_hash = terminator_hash.clone();
            self.active_bytes = 0;
            self.active_records = 0;
            self.next_seq = seq + 1;
            // 3. Fresh empty active + register its inode.
            OpenOptions::new()
                .create(true)
                .write(true)
                .truncate(true)
                .mode(file_mode)
                .open(&active)
                .with_context(|| format!("creating fresh active {}", active.display()))?;
            protection_inner.register_active(&active)?;
            // 4. Manifest + eviction — NON-FATAL (archive already committed).
            let evicted = evict_excess_archives(&active, max_archives).unwrap_or_else(|e| {
                error!(error = %e, "chainlog: archive eviction failed post-rotate (committed; continuing)");
                Vec::new()
            });
            if let Err(e) = self.manifest_append(ManifestEvent::Rotated {
                seq,
                terminator_hash: terminator_hash.clone(),
                bytes: sealed_bytes,
                records: sealed_records,
            }) {
                error!(
                    error = %e, seq,
                    "chainlog: manifest Rotated append failed — archive committed + chain \
                     intact; manifest row missing but recoverable (BUG-030 degrade)"
                );
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
    /// rename. The active file currently ends in a terminator for
    /// `next_seq`; [`finish_rotation`] renames it to its archive (idempotent)
    /// and opens a fresh active. `self.last_hash` is already the terminator
    /// hash (set by `open` from the recovered tail), so it is the meta-chain
    /// link for the fresh active's first line.
    fn complete_interrupted_rotation(&mut self) -> Result<()> {
        let seq = self.next_seq;
        let terminator_hash = self.last_hash.clone();
        let sealed_bytes = self.active_bytes;
        let sealed_records = self.active_records;
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
    /// The last complete line is a rotation terminator (crash-recovery:
    /// a rotation that sealed but didn't finish the rename).
    sealed: bool,
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
            sealed: false,
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
fn recover_tail(path: &Path) -> Result<TailRecovery> {
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
        if let Some(rec) = scan_back_for_tail(&buf, start, start == 0, size) {
            return Ok(rec);
        }
        if start == 0 {
            // Whole file in the window, no parseable complete line at all →
            // it is all junk: root at GENESIS and drop everything (torn, so
            // the caller truncates to 0 and attests the discard).
            return Ok(TailRecovery {
                tail_hash: GENESIS_PREV_HASH.to_string(),
                clean_len: 0,
                sealed: false,
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

/// Find the last complete, parseable line in `buf` (= file bytes
/// `[buf_start, file_size)`), scanning newest→oldest. `at_bof` means
/// `buf_start == 0`, so the buffer's first segment is a genuine line start
/// rather than a window-split fragment. Returns `None` if no complete
/// parseable line is fully contained in `buf` (caller widens the window).
fn scan_back_for_tail(
    buf: &[u8],
    buf_start: u64,
    at_bof: bool,
    file_size: u64,
) -> Option<TailRecovery> {
    let nls: Vec<usize> = buf
        .iter()
        .enumerate()
        .filter_map(|(i, &c)| (c == b'\n').then_some(i))
        .collect();
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
        // Parse generically: every line type (data / terminator / manifest)
        // carries a top-level `entry_hash`; a terminator also has `rotate`.
        if let Ok(v) = serde_json::from_slice::<serde_json::Value>(line) {
            if let Some(h) = v.get("entry_hash").and_then(|h| h.as_str()) {
                let clean_len = buf_start + nl as u64 + 1; // include the '\n'
                let torn = clean_len < file_size;
                let dropped = &buf[(nl + 1)..]; // bytes past the last good line
                return Some(TailRecovery {
                    tail_hash: h.to_string(),
                    clean_len,
                    sealed: v.get("rotate").is_some(),
                    torn,
                    dropped_bytes: dropped.len() as u64,
                    dropped_sha256: if torn { sha256_hex(dropped) } else { String::new() },
                });
            }
            // Parsed but not a chain line (no entry_hash) → keep walking back.
        }
        // Parse failed (torn/corrupt) → discard, keep walking back.
    }
    None
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

    // ── BUG-026 boot-hang fix: O(1) open + torn-tail recovery ───────────

    /// Same key across "restarts" so a continued chain verifies under one
    /// pubkey (a fixed path → `load_or_bootstrap` reloads the same key).
    fn key_at(path: &Path) -> AgentSigningKey {
        AgentSigningKey::load_or_bootstrap(path).unwrap()
    }

    /// Append a REAL legacy-v1 data line (no `fmt_ver` on the wire), signed
    /// exactly as the pre-BUG-026 writer did; returns its `entry_hash` so
    /// the caller can chain the next line. Same byte-compat invariant as
    /// `drain::bug026_legacy_v1_drift_line_still_verifies`.
    fn append_v1(path: &Path, p: TestPayload, k: &AgentSigningKey, prev_hash: &str) -> String {
        let mut line = ChainLine {
            payload: p,
            fmt_ver: None, // v1: omitted on the wire (skip_serializing_if)
            prev_hash: prev_hash.to_string(),
            entry_hash: String::new(),
            agent_sig: String::new(),
        };
        let digest = chain_digest(&line, prev_hash).unwrap();
        line.entry_hash = hex::encode(digest);
        line.agent_sig = B64.encode(k.sign(&digest).to_bytes());
        append_and_fsync(path, &to_jsonl(&line).unwrap(), 0o600).unwrap();
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
            let mut log = RotatingChainLog::<TestPayload>::open(
                &active, key_at(&kp), cfg(1 << 30, 50), std::sync::Arc::new(NoProtection),
            ).unwrap();
            for i in 0..5 {
                log.append(payload(i)).unwrap();
            }
        } // drop ⇒ simulate a restart
        {
            let mut log = RotatingChainLog::<TestPayload>::open(
                &active, key_at(&kp), cfg(1 << 30, 50), std::sync::Arc::new(NoProtection),
            ).unwrap();
            log.append(payload(5)).unwrap();
            log.append(payload(6)).unwrap();
        }
        let report = verify_log_set::<TestPayload>(&active, &pk).unwrap();
        assert_eq!(report.total_records, 7, "chain must span the reopen boundary");
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
            let mut log = RotatingChainLog::<TestPayload>::open(
                &active, key_at(&kp), cfg(1 << 30, 50), std::sync::Arc::new(NoProtection),
            ).unwrap();
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
            let mut log = RotatingChainLog::<TestPayload>::open(
                &active, key_at(&kp), cfg(1 << 30, 50), std::sync::Arc::new(NoProtection),
            ).unwrap();
            log.append(payload(4)).unwrap();
        }
        // Repair must have truncated the fragment before the new append.
        let report = verify_log_set::<TestPayload>(&active, &pk).unwrap();
        assert_eq!(report.total_records, 5, "4 clean + 1 post-repair, fragment dropped");
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
            let mut log = RotatingChainLog::<TestPayload>::open(
                &active, key_at(&kp), cfg(1 << 30, 50), std::sync::Arc::new(NoProtection),
            ).unwrap();
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
            let mut log = RotatingChainLog::<TestPayload>::open(
                &active, key_at(&kp), cfg(1 << 30, 50), std::sync::Arc::new(NoProtection),
            ).unwrap();
            log.append(payload(4)).unwrap();
        }
        let report = verify_log_set::<TestPayload>(&active, &pk).unwrap();
        assert_eq!(report.total_records, 5, "corrupt trailing line must be dropped");
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
        assert!(v1_len > 64, "the legacy file must exceed the tiny cap below");
        // Reopen with a cap SMALLER than the existing file ⇒ over-cap at open.
        {
            let mut log = RotatingChainLog::<TestPayload>::open(
                &active, key_at(&kp), cfg(64, 50), std::sync::Arc::new(NoProtection),
            ).unwrap();
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
            let mut log = RotatingChainLog::<TestPayload>::open(
                &active, key_at(&kp), cfg(1 << 30, 50), std::sync::Arc::new(NoProtection),
            ).unwrap();
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
            let _ = RotatingChainLog::<TestPayload>::open(
                &active, key_at(&kp), cfg(1 << 30, 50), std::sync::Arc::new(NoProtection),
            ).unwrap();
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
        let mut log = RotatingChainLog::<TestPayload>::open(
            &active, key_at(&kp), cfg(2000, 50), std::sync::Arc::new(NoProtection),
        ).unwrap();
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
        assert!(seqs.len() >= 2, "~300 B payloads over a 2 KiB cap must rotate ≥2×");
        assert_eq!(
            seqs,
            (1..=seqs.len() as u64).collect::<Vec<_>>(),
            "seqs must be contiguous — a re-rotation overwriting an archive would skip/reuse"
        );
        // Every signed record survives across the archives + active.
        let report = verify_log_set::<TestPayload>(&active, &pk).unwrap();
        assert_eq!(report.total_records, 40, "no signed records lost despite manifest failures");
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
            let mut log = RotatingChainLog::<TestPayload>::open(
                &active, key_at(&kp), cfg(1 << 30, 50), std::sync::Arc::new(NoProtection),
            ).unwrap();
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
                fmt_ver: CHAINLOG_FMT_V2,
                this_seq: 1,
                next_seq: 2,
                record_count: 3,
                bytes: 0,
            },
            &k,
            &tail,
        )
        .unwrap();
        append_and_fsync(&active, &to_jsonl(&term).unwrap(), 0o600).unwrap();
        assert!(
            list_archive_seqs(&active).unwrap().is_empty(),
            "pre-recovery: sealed active, no archive yet"
        );
        // Reopen → open() sees the sealed active → complete_interrupted_rotation.
        {
            let mut log = RotatingChainLog::<TestPayload>::open(
                &active, key_at(&kp), cfg(1 << 30, 50), std::sync::Arc::new(NoProtection),
            ).unwrap();
            log.append(payload(99)).unwrap();
        }
        assert_eq!(
            list_archive_seqs(&active).unwrap(),
            vec![1],
            "interrupted rotation completed on open → seq-1 archived"
        );
        let report = verify_log_set::<TestPayload>(&active, &pk).unwrap();
        assert_eq!(report.total_records, 4, "3 sealed + 1 post-recovery verify across the boundary");
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
            let mut log = RotatingChainLog::<TestPayload>::open(
                &active, key_at(&kp), cfg(1 << 30, 50), std::sync::Arc::new(NoProtection),
            ).unwrap();
            for i in 0..3 {
                log.append(payload(i)).unwrap();
            }
            log.last_hash().to_string()
        };
        let k = key_at(&kp);
        let term = TerminatorLine::sealed(
            RotateTerminator {
                fmt_ver: CHAINLOG_FMT_V2,
                this_seq: 1,
                next_seq: 2,
                record_count: 3,
                bytes: 0,
            },
            &k,
            &tail,
        )
        .unwrap();
        append_and_fsync(&active, &to_jsonl(&term).unwrap(), 0o600).unwrap();
        // open #1 completes the interrupted rotation → archive seq-1 + EMPTY active.
        drop(
            RotatingChainLog::<TestPayload>::open(
                &active, key_at(&kp), cfg(1 << 30, 50), std::sync::Arc::new(NoProtection),
            )
            .unwrap(),
        );
        assert_eq!(list_archive_seqs(&active).unwrap(), vec![1]);
        // Model case 2: the fresh active was never (re)created — remove the
        // empty active (loses no data; everything is in seq-1).
        std::fs::remove_file(&active).unwrap();
        // open #2 must recover: active absent → chain off seq-1's terminator.
        {
            let mut log = RotatingChainLog::<TestPayload>::open(
                &active, key_at(&kp), cfg(1 << 30, 50), std::sync::Arc::new(NoProtection),
            )
            .unwrap();
            log.append(payload(99)).unwrap();
        }
        let report = verify_log_set::<TestPayload>(&active, &pk).unwrap();
        assert_eq!(report.total_records, 4, "3 archived + 1 recovered off the prior terminator");
    }
}
