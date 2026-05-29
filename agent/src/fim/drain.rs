//! Tappa 9 (C4) — FIM drift drain loop + path resolve + diff +
//! `Event::Fim` emit.
//!
//! Bridges C2's kernel-side `FS_FIM_EVENTS` ringbuf to the
//! agent's existing `Event` channel that the decision engine +
//! ADE consume. Per design §6.3 + §6.5:
//!
//! 1. Drain `FS_FIM_EVENTS` via aya's `RingBuf::poll` (the
//!    pattern matches `agent/src/sensors/multiplexer.rs::pump`).
//! 2. Decode each `FimDriftRaw` (C1 wire type).
//! 3. Resolve `(target_dev, target_ino)` → absolute path via
//!    the userland [`InodePathMap`] populated by C7 deploy
//!    bootstrap (this commit ships the map type + lookup; C7
//!    wires the populator).
//! 4. Re-hash the file (C3 [`crate::fim::baseline::compute_baseline`])
//!    and diff against the BaselineDb's last entry for the
//!    path.
//! 5. If the SHA actually differs, the drift is REAL. Apply
//!    the §6.5 hierarchical token-bucket rate-limiter, then:
//!    - **Always** append a [`FimDriftEntry`] to
//!      `/var/lib/northnarrow/fim_drift.jsonl` (evidence
//!      preservation is non-negotiable — Q4 lock-in).
//!    - **Only** emit `Event::Fim(FimEvent)` to the decision
//!      engine when the bucket has tokens.
//!    - Suppressed events get
//!      `decision_engine_skipped: true` + `skip_reason:
//!      "rate_limit:tier_<X>"` on the persisted entry.
//!
//! ## What this commit (C4) ships
//!
//! - [`Event::Fim(FimEvent)`] wire variant (in
//!   `common/src/model.rs` — pure additive, the bus accepts
//!   the new variant alongside ProcessSpawn / FsProtectDenial
//!   / etc).
//! - [`InodePathMap`] — userland (dev, ino) → path resolver.
//! - [`FimDriftEntry`] — on-disk JSONL row for
//!   `fim_drift.jsonl`, with the §6.5 `decision_engine_skipped`
//!   and `skip_reason` fields (#[serde(default)] for
//!   forward-compat).
//! - [`FimDriftDb`] — chained writer mirroring
//!   [`crate::fim::baseline::BaselineDb`] + the B1 audit-log
//!   shape.
//! - [`DriftClassifier`] — provisional severity from
//!   `FimOp` + path heuristic. C5's rule engine may upgrade
//!   the severity later; the drain only needs the tier to
//!   pick a token bucket.
//! - [`DriftRateLimiter`] — hierarchical token-bucket per
//!   severity tier (Q4 resolution: 100/min Medium, 50/min
//!   High, **NO LIMIT Critical**). C5 may refine to per-rule
//!   if needed; per-tier is a strict subset that doesn't lose
//!   correctness.
//! - [`process_drift`] — pure (non-async) function that
//!   handles ONE `FimDriftRaw` end-to-end. Testable without a
//!   real ringbuf. The async drain loop is a thin shell
//!   around it.
//! - [`drain_loop`] — async tokio task draining the ringbuf,
//!   mirroring `sensors/multiplexer.rs::pump`. Not unit-
//!   tested in this commit (deferred to C8 privileged e2e);
//!   the pure logic in `process_drift` is the test surface.
//!
//! ## What this commit (C4) does NOT ship
//!
//! - **No agent-boot wiring.** C7 deploy bootstrap spawns the
//!   `drain_loop` tokio task alongside the existing sensor
//!   pumps + populates the InodePathMap from the BaselineDb.
//! - **No per-rule severity** in `DriftRateLimiter`. Per-tier
//!   ships in C4; per-rule (if C5 needs it) is a small
//!   refinement on the existing bucket layer.

use std::collections::HashMap;
use std::fs::OpenOptions;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use anyhow::{anyhow, Context, Result};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use chrono::{DateTime, Utc};
use common::wire::{FimDriftRaw, FimEvent, FimOp, InodeKey};
use common::Event;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

use crate::audit::{AgentSigningKey, GENESIS_PREV_HASH};
use crate::fim::baseline::{compute_baseline, BaselineCache, BaselineEntry};

/// Default location of the chained drift log. Lives alongside
/// the baseline DB so the Tappa 7 task 5 FS-LSM protection +
/// §6.5 PROTECTED_PIDS caller exemption naturally cover it
/// once C7 adds it to the state directory's protected-files
/// list.
pub const DEFAULT_DRIFT_LOG_PATH: &str = "/var/lib/northnarrow/fim_drift.jsonl";

// BUG-012 (v2): the v1 `FIM_OPENED_SUPPRESS_PATHS` 4-path allowlist
// was removed here. A read (`FimOp::Opened`) is never an integrity
// drift regardless of path, so suppression is now op-level in
// `process_drift` (drop every non-credential `Opened`; forward
// credential-path `Opened` silently to the rule engine). The
// credential predicate lives in `fim::rules::is_credential_path`,
// derived from the NN-L-FIM-011..017 rule fragment lists.

/// File mode for the drift log. World-readable so operators
/// inspect it with `cat`; root + agent are the only writers.
const DRIFT_FILE_MODE: u32 = 0o644;

// ── userland inode → path map ──────────────────────────────────────

/// Userland `(dev, ino)` → absolute path resolver. Populated by
/// C7 deploy bootstrap from the BaselineDb when the agent
/// starts; consulted by [`process_drift`] to turn a kernel-side
/// `FimDriftRaw` into a userland [`FimEvent`] with an absolute
/// path.
///
/// Lookup-only struct — operators don't mutate this at runtime
/// (re-baselining via `nn-admin fim rebaseline` rebuilds it
/// atomically). Thread-safety: the type is `Send + Sync` via
/// `RwLock` so the async drain loop + future operator-driven
/// rebaseline can share it.
#[derive(Debug, Default)]
pub struct InodePathMap {
    inner: parking_lot::RwLock<HashMap<InodeKey, String>>,
}

impl InodePathMap {
    /// Empty map. C7 populates from BaselineDb at boot.
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert/replace a `(dev, ino) → path` mapping. Idempotent
    /// over the value (last write wins) — re-baseline of a path
    /// that already maps just refreshes the lookup.
    pub fn insert(&self, key: InodeKey, path: String) {
        self.inner.write().insert(key, path);
    }

    /// Look up a path by inode key. Returns owned `String` so
    /// the read lock is dropped immediately — avoids holding a
    /// read lock across the (slow) baseline rehash that follows.
    pub fn lookup(&self, key: &InodeKey) -> Option<String> {
        self.inner.read().get(key).cloned()
    }

    /// Number of mapped inodes. Useful for `nn-admin fim
    /// status` (C6) summary output.
    pub fn len(&self) -> usize {
        self.inner.read().len()
    }

    /// True if no inodes are mapped (fresh boot, baseline
    /// hasn't run yet).
    pub fn is_empty(&self) -> bool {
        self.inner.read().is_empty()
    }
}

// ── severity tier (Q4) ─────────────────────────────────────────────

/// Provisional severity assigned by the drain to feed the §6.5
/// token bucket. C5's rule engine may upgrade or refine, but
/// the drain has to commit to a tier *before* the rule fires
/// because the bucket gate is upstream of the decision engine.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DriftSeverity {
    /// Never throttled — Q4 lock-in. Reserved for ops that the
    /// classifier can already prove are evasion techniques
    /// (e.g., a hardlink-create into a user-writable dir on a
    /// SUID-root inode). The drain stays conservative: most
    /// events go to High or Medium, Critical only when the
    /// classifier has high-confidence signal.
    Critical,
    /// 50 events/minute per process under default Q4
    /// configuration.
    High,
    /// 100 events/minute per process under default Q4
    /// configuration.
    Medium,
}

/// Default per-tier emission caps from §13 Q4 resolution.
/// Owner-tunable via `/etc/northnarrow/config.toml` in future
/// commits; the defaults here are the design's recommendation.
pub const DEFAULT_HIGH_PER_MIN: u32 = 50;
pub const DEFAULT_MEDIUM_PER_MIN: u32 = 100;

// ── classifier ─────────────────────────────────────────────────────

/// Pure FimOp + path → DriftSeverity assignment. Conservative:
/// the drain only escalates to Critical when the signal is
/// unambiguous (hardlink-into-user-writable-dir per §13 Q2);
/// everything else is High (op-driven) or Medium (default).
/// C5 rules may upgrade by re-classifying the FimEvent based
/// on per-path policy.
#[derive(Debug, Default)]
pub struct DriftClassifier;

impl DriftClassifier {
    pub fn new() -> Self {
        Self
    }

    /// Classify `(op, path)`. The path is informational (used
    /// only for the Linked-into-user-writable-dir heuristic);
    /// classification is otherwise op-only so C5's rule engine
    /// retains full path-policy authority.
    pub fn classify(&self, op: FimOp, path: &str) -> DriftSeverity {
        match op {
            // Hardlink into a user-writable dir on a SUID-root
            // inode is the §13 Q2 evasion path — never throttle.
            // The drain doesn't know the inode's SUID bit here
            // (the BPF program only sent (dev,ino) + op); the
            // classifier escalates based on the LINK DESTINATION
            // path (which the path map resolves before this call).
            FimOp::Linked if is_user_writable_prefix(path) => DriftSeverity::Critical,
            // Deletion + creation are high-signal — a file that
            // appears or disappears in a watched dir is rarely a
            // benign event.
            FimOp::Deleted | FimOp::Created | FimOp::Linked => DriftSeverity::High,
            // Modified + Renamed are noisier (package upgrades
            // generate dozens) — default to Medium so the
            // bucket can throttle them without losing High
            // tokens.
            FimOp::Modified | FimOp::Renamed => DriftSeverity::Medium,
            // C5.2: FimOp::Opened fires on every open of a
            // watched inode. Default to Medium so legitimate
            // periodic reads (cloud-CLI tools, monitoring
            // agents) can be rate-limited. C5.3 rules
            // (NN-L-FIM-011..014) classify cred-path reads
            // separately + the rule fires regardless of the
            // bucket — Critical-tier path-rule severity comes
            // from the rule, not this classifier.
            FimOp::Opened => DriftSeverity::Medium,
        }
    }
}

fn is_user_writable_prefix(path: &str) -> bool {
    path.starts_with("/tmp/")
        || path.starts_with("/var/tmp/")
        || path.starts_with("/dev/shm/")
        || path.starts_with("/home/")
}

// ── rate limiter (Q4 hierarchical token bucket) ────────────────────

/// Hierarchical token-bucket per `DriftSeverity` tier. Critical
/// is never throttled (per Q4 lock-in). High + Medium have
/// independent buckets that refill linearly over a 60s window.
///
/// Thread-safety: a single `Mutex` wraps the bucket state. The
/// async drain loop holds the lock for microseconds per drift
/// — sub-millisecond contention even under burst load. parking
/// _lot::Mutex chosen over std for fairness + no poisoning
/// (a panicked drain task shouldn't lock out a future restart).
pub struct DriftRateLimiter {
    state: Mutex<BucketState>,
    high_per_min: u32,
    medium_per_min: u32,
}

struct BucketState {
    high_remaining: u32,
    medium_remaining: u32,
    window_started: Instant,
}

impl DriftRateLimiter {
    /// Build with default Q4 caps (`DEFAULT_HIGH_PER_MIN` +
    /// `DEFAULT_MEDIUM_PER_MIN`).
    pub fn new() -> Self {
        Self::with_caps(DEFAULT_HIGH_PER_MIN, DEFAULT_MEDIUM_PER_MIN)
    }

    /// Build with explicit caps. Test-friendly + operator-
    /// override-friendly.
    pub fn with_caps(high_per_min: u32, medium_per_min: u32) -> Self {
        Self {
            state: Mutex::new(BucketState {
                high_remaining: high_per_min,
                medium_remaining: medium_per_min,
                window_started: Instant::now(),
            }),
            high_per_min,
            medium_per_min,
        }
    }

    /// Try to consume one token for `severity`. Returns
    /// `Ok(())` if the event may pass through to the decision
    /// engine, or `Err(reason)` if the bucket is empty and the
    /// event should be suppressed (audit chain still records).
    ///
    /// `now` is injected so tests can advance time deterministically
    /// without sleeping. Production callers pass `Instant::now()`.
    pub fn try_consume_with_now(
        &self,
        severity: DriftSeverity,
        now: Instant,
    ) -> Result<(), String> {
        let mut s = self.state.lock().expect("DriftRateLimiter mutex poisoned");
        // Window roll-over — when 60s elapsed since the window
        // started, refill both buckets to full and reset the
        // anchor. Single mutex lock window keeps this race-free.
        if now.duration_since(s.window_started) >= Duration::from_secs(60) {
            s.high_remaining = self.high_per_min;
            s.medium_remaining = self.medium_per_min;
            s.window_started = now;
        }
        match severity {
            DriftSeverity::Critical => Ok(()), // Q4: never throttled
            DriftSeverity::High => {
                if s.high_remaining > 0 {
                    s.high_remaining -= 1;
                    Ok(())
                } else {
                    Err("rate_limit:tier_high".to_string())
                }
            }
            DriftSeverity::Medium => {
                if s.medium_remaining > 0 {
                    s.medium_remaining -= 1;
                    Ok(())
                } else {
                    Err("rate_limit:tier_medium".to_string())
                }
            }
        }
    }

    /// Production wrapper around `try_consume_with_now` that
    /// pins `now = Instant::now()`. Most callers use this.
    pub fn try_consume(&self, severity: DriftSeverity) -> Result<(), String> {
        self.try_consume_with_now(severity, Instant::now())
    }

    /// C7 — read-only snapshot of bucket state for the
    /// `nn-admin fim status` reply. Returns
    /// `(high_remaining, medium_remaining, secs_until_window_resets)`.
    /// Holds the mutex for microseconds (three field reads + an
    /// arithmetic on `Instant`); same lock-contention budget as
    /// `try_consume`.
    pub fn snapshot(&self) -> (u32, u32, u32) {
        let s = self.state.lock().expect("DriftRateLimiter mutex poisoned");
        let elapsed = Instant::now().duration_since(s.window_started);
        let remaining_secs = Duration::from_secs(60)
            .checked_sub(elapsed)
            .map(|d| d.as_secs() as u32)
            .unwrap_or(0);
        (s.high_remaining, s.medium_remaining, remaining_secs)
    }

    /// C7 — configured High-tier cap. Surfaced in
    /// `FimStatusResponse` so the CLI can render
    /// `<remaining>/<cap>` ratios.
    pub fn high_cap_per_min(&self) -> u32 {
        self.high_per_min
    }

    /// C7 — configured Medium-tier cap. Same rationale as
    /// [`Self::high_cap_per_min`].
    pub fn medium_cap_per_min(&self) -> u32 {
        self.medium_per_min
    }
}

impl Default for DriftRateLimiter {
    fn default() -> Self {
        Self::new()
    }
}

// ── on-disk drift entry (chained, signed) ──────────────────────────

/// One on-disk JSONL row in `fim_drift.jsonl`. Same chain shape
/// as Tappa 8 B1 audit log + C3 BaselineEntry. Q4 resolution
/// adds the two `decision_engine_skipped` + `skip_reason`
/// fields (#[serde(default)] for forward-compat).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FimDriftEntry {
    pub ts: String,
    pub path: String,
    pub op: FimOp,
    pub baseline_sha256: Option<String>,
    pub new_sha256: Option<String>,
    pub modifier_pid: u32,
    pub modifier_uid: u32,
    pub modifier_comm: String,
    pub severity: DriftSeverity,
    /// Q4 NEW. `false` when the event flows to the decision
    /// engine; `true` when the bucket suppressed it.
    /// `#[serde(default)]` → older drift logs deserialise to
    /// `false`.
    #[serde(default)]
    pub decision_engine_skipped: bool,
    /// Q4 NEW. Populated to e.g. `"rate_limit:tier_medium"`
    /// when `decision_engine_skipped == true`; empty otherwise.
    #[serde(default)]
    pub skip_reason: String,
    pub agent_id: String,
    pub prev_hash: String,
    pub entry_hash: String,
    pub agent_sig: String,
}

/// Caller-supplied fields for [`FimDriftDb::append`].
#[derive(Debug, Clone)]
pub struct FimDriftDraft {
    pub path: String,
    pub op: FimOp,
    pub baseline_sha256: Option<String>,
    pub new_sha256: Option<String>,
    pub modifier_pid: u32,
    pub modifier_uid: u32,
    pub modifier_comm: String,
    pub severity: DriftSeverity,
    pub decision_engine_skipped: bool,
    pub skip_reason: String,
}

// ── drift DB (mirror BaselineDb) ───────────────────────────────────

/// Append-only writer for the drift log. Same shape as
/// [`crate::fim::baseline::BaselineDb`] — chain primitives are
/// COPIED rather than extracted into a shared trait (same
/// rationale as C3: extraction is a clean future refactor).
pub struct FimDriftDb {
    path: PathBuf,
    key: AgentSigningKey,
    agent_id: [u8; 16],
    last_hash: String,
}

impl FimDriftDb {
    pub fn open(path: &Path, key: AgentSigningKey, agent_id: [u8; 16]) -> Result<Self> {
        let last_hash = read_tail_hash(path)?;
        Ok(Self {
            path: path.to_path_buf(),
            key,
            agent_id,
            last_hash,
        })
    }

    pub fn append(&mut self, draft: FimDriftDraft) -> Result<FimDriftEntry> {
        let entry = build_signed_drift_entry(&draft, &self.key, &self.agent_id, &self.last_hash)?;
        let mut line =
            serde_json::to_string(&entry).map_err(|e| anyhow!("serialising drift entry: {e}"))?;
        line.push('\n');
        let mut f = OpenOptions::new()
            .create(true)
            .append(true)
            .mode(DRIFT_FILE_MODE)
            .open(&self.path)
            .with_context(|| format!("opening drift log {} for append", self.path.display()))?;
        f.write_all(line.as_bytes())
            .with_context(|| format!("appending drift entry to {}", self.path.display()))?;
        f.sync_all()
            .with_context(|| format!("fsync {}", self.path.display()))?;
        self.last_hash = entry.entry_hash.clone();
        Ok(entry)
    }

    pub fn last_hash(&self) -> &str {
        &self.last_hash
    }
}

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
        let entry: FimDriftEntry =
            serde_json::from_str(&line).with_context(|| format!("parsing drift line: {line}"))?;
        last = Some(entry.entry_hash);
    }
    Ok(last.unwrap_or_else(|| GENESIS_PREV_HASH.to_string()))
}

fn build_signed_drift_entry(
    draft: &FimDriftDraft,
    key: &AgentSigningKey,
    agent_id: &[u8; 16],
    prev_hash: &str,
) -> Result<FimDriftEntry> {
    let ts = format_ts(Utc::now());
    let mut entry = FimDriftEntry {
        ts,
        path: draft.path.clone(),
        op: draft.op,
        baseline_sha256: draft.baseline_sha256.clone(),
        new_sha256: draft.new_sha256.clone(),
        modifier_pid: draft.modifier_pid,
        modifier_uid: draft.modifier_uid,
        modifier_comm: draft.modifier_comm.clone(),
        severity: draft.severity,
        decision_engine_skipped: draft.decision_engine_skipped,
        skip_reason: draft.skip_reason.clone(),
        agent_id: hex::encode(agent_id),
        prev_hash: prev_hash.to_string(),
        entry_hash: String::new(),
        agent_sig: String::new(),
    };
    let entry_hash = compute_entry_hash(&entry)?;
    entry.entry_hash = hex::encode(entry_hash);
    let sig = key.sign(&entry_hash);
    entry.agent_sig = B64.encode(sig.to_bytes());
    Ok(entry)
}

fn compute_entry_hash(entry: &FimDriftEntry) -> Result<[u8; 32]> {
    debug_assert!(entry.entry_hash.is_empty());
    debug_assert!(entry.agent_sig.is_empty());
    let prev_bytes =
        hex::decode(&entry.prev_hash).map_err(|e| anyhow!("prev_hash is not valid hex: {e}"))?;
    let body =
        serde_json::to_vec(entry).map_err(|e| anyhow!("serialising drift pre-image: {e}"))?;
    let mut hasher = Sha256::new();
    hasher.update(&prev_bytes);
    hasher.update(&body);
    let digest: [u8; 32] = hasher.finalize().into();
    Ok(digest)
}

fn format_ts(t: DateTime<Utc>) -> String {
    t.format("%Y-%m-%dT%H:%M:%S%.6fZ").to_string()
}

// ── process_drift (pure, testable) ─────────────────────────────────

/// Reusable single-event processor. The async drain loop calls
/// this per `FimDriftRaw`; tests call it directly with seeded
/// state to exercise every branch.
///
/// Steps:
/// 1. Resolve `(dev, ino)` → path. Missing → warn-and-skip (a
///    drift event whose path the agent doesn't track is
///    operator config drift, not data drift).
/// 2. Re-hash the file via C3's `compute_baseline`. Two-row
///    symlink semantics handled naturally — the drain takes
///    the `is_symlink: false` row for content comparison.
/// 3. Compare new sha256 against `last_baseline` for that path.
///    Equal → no real drift; skip silently (kernel hook fires
///    on every setattr including no-op touches).
/// 4. Apply rate limiter → record `decision_engine_skipped` +
///    `skip_reason` on the persisted entry.
/// 5. Append to drift DB (always, evidence preservation).
/// 6. Emit `Event::Fim` to `event_tx` ONLY if rate limiter
///    allowed.
///
/// Returns `Ok(true)` if an event was emitted to the bus,
/// `Ok(false)` if processing completed without emission (path
/// unknown, no drift, or rate-limited). Errors are propagated
/// for the drain loop to log + continue.
pub fn process_drift(
    raw: &FimDriftRaw,
    path_map: &InodePathMap,
    last_baseline: Option<&BaselineEntry>,
    drift_db: &mut FimDriftDb,
    classifier: &DriftClassifier,
    rate_limiter: &DriftRateLimiter,
    event_tx: Option<&mpsc::Sender<Event>>,
) -> Result<bool> {
    let key = InodeKey {
        dev: raw.target_dev,
        ino: raw.target_ino,
    };
    let path = match path_map.lookup(&key) {
        Some(p) => p,
        None => {
            warn!(
                target: "fim.drain",
                target_dev = key.dev,
                target_ino = key.ino,
                "drift event for (dev,ino) not in inode→path map — operator config drift, skipping"
            );
            return Ok(false);
        }
    };
    let op = FimOp::try_from(raw.op).map_err(|e| anyhow!("decoding raw.op: {e}"))?;
    // BUG-012 (v2): a read (`FimOp::Opened`) is NEVER an integrity
    // drift. It must produce zero FIM-DRIFT rows — no drift_db
    // append, no `fim_drift.jsonl` line, no "FIM DRIFT" WARN
    // (`main.rs` silences the WARN for Opened too). The v1 fix masked
    // only a 4-path allowlist; every OTHER watched path's reads
    // (`/etc/nsswitch.conf`, `/etc/pam.d/*`, `/etc/group`,
    // `/usr/bin/dash`, …) still drifted — the boot-time noise this
    // refit kills. The op-level rule replaces the path allowlist.
    //
    // The one carve-out is coverage, not noise: `Opened` on a
    // CREDENTIAL path is the ONLY event source for the cloud-cred /
    // browser / password-manager / GPG-keyring read rules
    // (NN-L-FIM-011..017). Those paths must still emit `Event::Fim`
    // so the engine can evaluate them — but SILENTLY: no drift_db
    // append, no rate-limit accounting, no "FIM DRIFT" line. If a
    // rule fires it raises the alert with proper credential-read
    // framing; the drain stays out of it. `is_credential_path` is
    // derived from the rules' own fragment lists, so the drain
    // forwards exactly — and only — what a rule consumes.
    //
    // Integrity-changing ops (Modified / Created / Deleted / Renamed
    // / Linked) skip this block entirely and flow through unchanged.
    if matches!(op, FimOp::Opened) {
        if !crate::fim::rules::is_credential_path(&path) {
            debug!(
                target: "fim.drain",
                path = %path,
                "BUG-012 v2: dropping FimOp::Opened on non-credential watched path \
                 (a read is not integrity drift; no rule consumes it)"
            );
            return Ok(false);
        }
        // Credential-path read: forward to the rule engine without
        // recording any drift. No drift_db append (keeps it out of
        // fim_drift.jsonl) and no rate limiting (a cred-theft read is
        // high-signal and must not be throttled away). The
        // NN-L-FIM-011..017 rules need only op / path / modifier_comm,
        // so we emit a content-less event and skip the baseline probe.
        debug!(
            target: "fim.drain",
            path = %path,
            modifier_comm = %comm_to_string(&raw.modifier_comm),
            "BUG-012 v2: forwarding FimOp::Opened on credential path to rule engine \
             (silent — not recorded as drift)"
        );
        if let Some(tx) = event_tx {
            let event = Event::Fim(FimEvent {
                timestamp_ns: raw.timestamp_ns,
                path: path.clone(),
                op,
                new_sha256: None,
                baseline_sha256: None,
                modifier_exe: None,
                modifier_pid: raw.modifier_pid,
                modifier_uid: raw.modifier_uid,
                modifier_comm: comm_to_string(&raw.modifier_comm),
                dest_path: None,
            });
            if tx.try_send(event).is_err() {
                warn!(
                    target: "fim.drain",
                    path = %path,
                    "Event::Fim (cred-read) send to decision engine failed (channel full / closed)"
                );
            }
            return Ok(true);
        }
        return Ok(false);
    }

    // Resolve any 1-hop symlink + capture content. For Deleted
    // and Renamed ops the target may be gone; treat the SHA
    // probe as None in that case and let the diff fall to the
    // baseline-side comparison.
    let new_sha256 = match op {
        FimOp::Deleted | FimOp::Renamed => None,
        _ => match compute_baseline(Path::new(&path)) {
            Ok(drafts) => drafts
                .iter()
                .find(|d| !d.is_symlink)
                .map(|d| d.sha256.clone()),
            Err(e) => {
                debug!(
                    target: "fim.drain",
                    path = %path,
                    error = %e,
                    "compute_baseline failed during drift re-hash; emitting with new_sha256=None"
                );
                None
            }
        },
    };
    let baseline_sha256 = last_baseline.map(|b| b.sha256.clone());

    // Skip if SHA matches baseline (kernel hook fired but
    // content didn't actually change — e.g., `touch -t` on an
    // unchanged file). Deleted/Renamed always counts as drift
    // even if hashes are None on both sides (the file
    // disappeared — operator wants to know).
    let real_drift = !matches!(
        (&baseline_sha256, &new_sha256),
        (Some(old), Some(new)) if old == new
    );
    // Polish #2 semantics: ONLY suppress no-op events for
    // content-class ops (Modified / Created / Linked). Deleted
    // + Renamed always emit (the file disappeared; operator
    // wants to know). `FimOp::Opened` never reaches here — BUG-012
    // (v2) handles every read above this point — so it needs no
    // entry in this set.
    let suppress_on_match = matches!(op, FimOp::Modified | FimOp::Created | FimOp::Linked);
    if !real_drift && suppress_on_match {
        debug!(
            target: "fim.drain",
            path = %path,
            ?op,
            "no-op drift: sha256 unchanged for content-class op, skipping"
        );
        return Ok(false);
    }

    let severity = classifier.classify(op, &path);
    let (skipped, skip_reason) = match rate_limiter.try_consume(severity) {
        Ok(()) => (false, String::new()),
        Err(reason) => (true, reason),
    };

    let draft = FimDriftDraft {
        path: path.clone(),
        op,
        baseline_sha256: baseline_sha256.clone(),
        new_sha256: new_sha256.clone(),
        modifier_pid: raw.modifier_pid,
        modifier_uid: raw.modifier_uid,
        modifier_comm: comm_to_string(&raw.modifier_comm),
        severity,
        decision_engine_skipped: skipped,
        skip_reason: skip_reason.clone(),
    };
    let _ = drift_db.append(draft).context("append to drift DB")?;

    if skipped {
        info!(
            target: "fim.drain",
            path = %path,
            severity = ?severity,
            skip_reason,
            "drift suppressed by rate limit — audit chain still recorded"
        );
        return Ok(false);
    }

    if let Some(tx) = event_tx {
        // Polish #3: resolve the rename dest path via InodePathMap.
        // Populated only when raw.dest_dev + raw.dest_ino are non-
        // zero (the kernel-side fim_rename_observe sets them when
        // it can extract a dest inode from the rename's dentry
        // args) AND the dest inode is in the userland map. Misses
        // fall back to None and the NN-L-FIM-010 rule's dest-side
        // matcher skips silently — the rule still fires on src-side
        // matches.
        let dest_path = if matches!(op, FimOp::Renamed) && raw.dest_ino != 0 {
            path_map.lookup(&InodeKey {
                dev: raw.dest_dev,
                ino: raw.dest_ino,
            })
        } else {
            None
        };
        let event = Event::Fim(FimEvent {
            timestamp_ns: raw.timestamp_ns,
            path: path.clone(),
            op,
            new_sha256: new_sha256.and_then(|h| decode_sha_hex(&h)),
            baseline_sha256: baseline_sha256.and_then(|h| decode_sha_hex(&h)),
            modifier_exe: None,
            modifier_pid: raw.modifier_pid,
            modifier_uid: raw.modifier_uid,
            modifier_comm: comm_to_string(&raw.modifier_comm),
            dest_path,
        });
        if tx.try_send(event).is_err() {
            warn!(
                target: "fim.drain",
                path = %path,
                "Event::Fim send to decision engine failed (channel full / closed)"
            );
        }
    }
    Ok(true)
}

fn comm_to_string(comm: &[u8]) -> String {
    let end = comm.iter().position(|&b| b == 0).unwrap_or(comm.len());
    String::from_utf8_lossy(&comm[..end]).into_owned()
}

// ── async drain loop (Tappa 9 C8) ──────────────────────────────────

/// Tappa 9 C8 — async tokio task that drains the `FS_FIM_EVENTS`
/// ringbuf and feeds each event through [`process_drift`]. Mirrors
/// the [`crate::sensors::multiplexer::pump`] pattern (AsyncFd<RingBuf>
/// → poll readable → drain iterator). One task is spawned at agent
/// boot from [`crate::main`] post-attach; the task lifetime equals
/// the agent's.
///
/// The drain takes ownership of the [`FimDriftDb`] writer because
/// per-event appends are serialised through it — single-writer DB
/// invariant matches the recompute-task contract from C7. The
/// [`BaselineCache`] (Tappa 9 polish #2) lets process_drift
/// compare the kernel-observed event against the previously-
/// baselined SHA, suppressing no-op events (`touch -t`,
/// permission-set-to-same-value) before they hit the drift log.
/// The recompute task updates the cache after each successful
/// `BaselineDb::append` so on-disk and in-memory views stay
/// consistent.
///
/// The `event_tx` is the same channel
/// [`crate::sensors::SensorMultiplexer`] funnels its events into;
/// `Event::Fim(FimEvent)` lands alongside `ProcessSpawn` /
/// `FsProtectDenial` so the existing main-loop `process_event`
/// path picks them up without changes.
#[allow(clippy::too_many_arguments)]
pub async fn drain_loop(
    rb: aya::maps::ring_buf::RingBuf<aya::maps::MapData>,
    inode_map: std::sync::Arc<InodePathMap>,
    baseline_cache: std::sync::Arc<BaselineCache>,
    drift_db: std::sync::Arc<parking_lot::Mutex<FimDriftDb>>,
    classifier: std::sync::Arc<DriftClassifier>,
    rate_limiter: std::sync::Arc<DriftRateLimiter>,
    event_tx: mpsc::Sender<Event>,
) -> std::io::Result<()> {
    use tokio::io::unix::AsyncFd;
    let mut async_fd = AsyncFd::new(rb)?;
    info!(
        target: "fim.drain",
        baseline_cache_entries = baseline_cache.len(),
        "fim drain loop: ready"
    );
    loop {
        let mut guard = async_fd.readable_mut().await?;
        let inner = guard.get_inner_mut();
        let mut drained = 0u32;
        while let Some(item) = inner.next() {
            drained += 1;
            let bytes: &[u8] = item.as_ref();
            let raw = match bytemuck::try_from_bytes::<FimDriftRaw>(bytes) {
                Ok(r) => *r,
                Err(e) => {
                    warn!(
                        target: "fim.drain",
                        expected = std::mem::size_of::<FimDriftRaw>(),
                        got = bytes.len(),
                        error = %e,
                        "ringbuf entry rejected"
                    );
                    continue;
                }
            };
            // Drop the iterator item so the slot is released before
            // we call into the rest-of-the-world (process_drift may
            // hash the file, which can take milliseconds). Owning
            // `raw` by value already disconnected from the borrow.
            let _ = item; // keep clippy happy + readable
                          // Resolve the watched path BEFORE locking the drift DB
                          // so the BaselineCache lookup doesn't hold the DB mutex.
            let path_for_lookup = inode_map.lookup(&InodeKey {
                dev: raw.target_dev,
                ino: raw.target_ino,
            });
            let last_baseline = path_for_lookup.and_then(|p| baseline_cache.get_content(&p));
            let mut db = drift_db.lock();
            if let Err(e) = process_drift(
                &raw,
                inode_map.as_ref(),
                last_baseline.as_ref(),
                &mut db,
                classifier.as_ref(),
                rate_limiter.as_ref(),
                Some(&event_tx),
            ) {
                warn!(
                    target: "fim.drain",
                    error = %e,
                    "process_drift error — event dropped, drain continues"
                );
            }
        }
        guard.clear_ready();
        if drained == 0 {
            tokio::time::sleep(std::time::Duration::from_millis(1)).await;
        }
    }
}

fn decode_sha_hex(hex_str: &str) -> Option<[u8; 32]> {
    let bytes = hex::decode(hex_str).ok()?;
    if bytes.len() != 32 {
        return None;
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Some(out)
}

// ── tests ───────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn fresh_signing_key(dir: &TempDir) -> AgentSigningKey {
        let key_path = dir.path().join("agent.sig.key");
        AgentSigningKey::load_or_bootstrap(&key_path).unwrap()
    }

    fn fake_raw(dev: u64, ino: u64, op: u8) -> FimDriftRaw {
        FimDriftRaw {
            timestamp_ns: 1_700_000_000_000_000_000,
            target_dev: dev,
            target_ino: ino,
            modifier_pid: 12345,
            modifier_uid: 0,
            modifier_comm: *b"dpkg\0\0\0\0\0\0\0\0\0\0\0\0",
            op,
            _pad: [0u8; 7],
            // Polish #3 defaults — non-Rename events leave the
            // dest pair zeroed; rename-specific tests construct
            // FimDriftRaw directly with non-zero dest values.
            dest_dev: 0,
            dest_ino: 0,
        }
    }

    fn dummy_baseline(path: &str, sha256: &str) -> BaselineEntry {
        BaselineEntry {
            ts: "2026-05-19T00:00:00.000000Z".to_string(),
            path: path.to_string(),
            sha256: sha256.to_string(),
            mode: "0o644".to_string(),
            uid: 0,
            gid: 0,
            size_bytes: 11,
            is_symlink: false,
            agent_id: "00".repeat(16),
            prev_hash: GENESIS_PREV_HASH.to_string(),
            entry_hash: "deadbeef".repeat(8),
            agent_sig: "A".repeat(88),
        }
    }

    // ── C4 test 1: InodePathMap insert + lookup ─────────────────────

    #[test]
    fn inode_path_map_insert_and_lookup_round_trip() {
        let map = InodePathMap::new();
        assert!(map.is_empty());
        let key = InodeKey {
            dev: 0x800002,
            ino: 42,
        };
        map.insert(key, "/usr/bin/sshd".to_string());
        assert_eq!(map.len(), 1);
        assert_eq!(map.lookup(&key), Some("/usr/bin/sshd".to_string()));
        // Re-insert same key: idempotent, value replaced.
        map.insert(key, "/usr/sbin/sshd".to_string());
        assert_eq!(map.len(), 1);
        assert_eq!(map.lookup(&key), Some("/usr/sbin/sshd".to_string()));
        // Unknown key: None.
        let other = InodeKey {
            dev: 0x800002,
            ino: 99,
        };
        assert_eq!(map.lookup(&other), None);
    }

    // ── C4 test 2: Classifier provisional severity ──────────────────

    #[test]
    fn classifier_assigns_provisional_severity() {
        let c = DriftClassifier::new();
        // Modified + Renamed → Medium (noisy under upgrades).
        assert_eq!(
            c.classify(FimOp::Modified, "/usr/bin/sshd"),
            DriftSeverity::Medium
        );
        assert_eq!(
            c.classify(FimOp::Renamed, "/etc/passwd"),
            DriftSeverity::Medium
        );
        // Created + Deleted → High (high-signal).
        assert_eq!(
            c.classify(FimOp::Created, "/etc/cron.d/x"),
            DriftSeverity::High
        );
        assert_eq!(
            c.classify(FimOp::Deleted, "/etc/shadow"),
            DriftSeverity::High
        );
        // Linked to non-user-writable → High.
        assert_eq!(
            c.classify(FimOp::Linked, "/usr/local/bin/x"),
            DriftSeverity::High
        );
        // Linked INTO user-writable → Critical (§13 Q2 evasion path).
        assert_eq!(
            c.classify(FimOp::Linked, "/tmp/.x"),
            DriftSeverity::Critical
        );
        assert_eq!(
            c.classify(FimOp::Linked, "/var/tmp/x"),
            DriftSeverity::Critical
        );
        assert_eq!(
            c.classify(FimOp::Linked, "/dev/shm/y"),
            DriftSeverity::Critical
        );
        assert_eq!(
            c.classify(FimOp::Linked, "/home/alice/.x"),
            DriftSeverity::Critical
        );
        // C5.2: Opened defaults to Medium so legitimate
        // periodic cred-CLI reads can be rate-limited; the
        // C5.3 NN-L-FIM-011..014 rules upgrade to High at the
        // rule layer when the path actually matches a cred
        // file.
        assert_eq!(
            c.classify(FimOp::Opened, "/root/.aws/credentials"),
            DriftSeverity::Medium
        );
        assert_eq!(
            c.classify(FimOp::Opened, "/etc/passwd"),
            DriftSeverity::Medium
        );
    }

    // ── C4 test 3: RateLimiter never throttles Critical ─────────────

    #[test]
    fn rate_limiter_never_throttles_critical() {
        let rl = DriftRateLimiter::with_caps(1, 1);
        // Even after exhausting Medium + High, Critical flows.
        let _ = rl.try_consume(DriftSeverity::High);
        let _ = rl.try_consume(DriftSeverity::Medium);
        let _ = rl.try_consume(DriftSeverity::High); // exhausted
        let _ = rl.try_consume(DriftSeverity::Medium); // exhausted
        for _ in 0..100 {
            rl.try_consume(DriftSeverity::Critical)
                .expect("Critical must NEVER throttle (Q4 lock-in)");
        }
    }

    // ── C4 test 4: RateLimiter throttles Medium after N/min ─────────

    #[test]
    fn rate_limiter_throttles_medium_then_refills_after_window() {
        let rl = DriftRateLimiter::with_caps(50, 100);
        let t0 = Instant::now();
        // First 100 Medium pass.
        for i in 0..100 {
            rl.try_consume_with_now(DriftSeverity::Medium, t0)
                .unwrap_or_else(|e| panic!("Medium #{i} unexpectedly throttled: {e}"));
        }
        // 101st throttles.
        let err = rl
            .try_consume_with_now(DriftSeverity::Medium, t0)
            .expect_err("Medium #101 must throttle");
        assert_eq!(err, "rate_limit:tier_medium");
        // Advance past window — bucket refills.
        let later = t0 + Duration::from_secs(61);
        rl.try_consume_with_now(DriftSeverity::Medium, later)
            .expect("Medium after window roll-over must pass");
    }

    // ── C4 test 5: RateLimiter throttles High independently ─────────

    #[test]
    fn rate_limiter_high_and_medium_have_independent_buckets() {
        let rl = DriftRateLimiter::with_caps(2, 100);
        let t0 = Instant::now();
        // Exhaust High.
        rl.try_consume_with_now(DriftSeverity::High, t0).unwrap();
        rl.try_consume_with_now(DriftSeverity::High, t0).unwrap();
        assert!(rl.try_consume_with_now(DriftSeverity::High, t0).is_err());
        // Medium is independent — still full.
        for _ in 0..50 {
            rl.try_consume_with_now(DriftSeverity::Medium, t0).unwrap();
        }
    }

    // ── C4 test 6: FimDriftEntry serde round-trip with Q4 fields ───

    #[test]
    fn fim_drift_entry_round_trips_with_q4_skipped_field() {
        let entry = FimDriftEntry {
            ts: "2026-05-19T00:00:00.000000Z".to_string(),
            path: "/etc/passwd".to_string(),
            op: FimOp::Modified,
            baseline_sha256: Some("aa".repeat(32)),
            new_sha256: Some("bb".repeat(32)),
            modifier_pid: 12345,
            modifier_uid: 0,
            modifier_comm: "dpkg".to_string(),
            severity: DriftSeverity::Medium,
            decision_engine_skipped: true,
            skip_reason: "rate_limit:tier_medium".to_string(),
            agent_id: "00".repeat(16),
            prev_hash: GENESIS_PREV_HASH.to_string(),
            entry_hash: "deadbeef".repeat(8),
            agent_sig: "A".repeat(88),
        };
        let json = serde_json::to_string(&entry).unwrap();
        assert!(
            json.contains(r#""decision_engine_skipped":true"#),
            "field must surface in JSON: {json}"
        );
        let restored: FimDriftEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(restored, entry);
    }

    // ── C4 test 7: process_drift skips path-unknown events ──────────

    #[test]
    fn process_drift_skips_when_inode_path_unknown() {
        let dir = TempDir::new().unwrap();
        let key = fresh_signing_key(&dir);
        let drift_path = dir.path().join("drift.jsonl");
        let mut drift_db = FimDriftDb::open(&drift_path, key, [0u8; 16]).unwrap();
        let path_map = InodePathMap::new(); // empty
        let classifier = DriftClassifier::new();
        let rate_limiter = DriftRateLimiter::new();
        let (tx, _rx) = mpsc::channel::<Event>(8);
        let raw = fake_raw(0x800002, 99, FimOp::Modified as u8);
        let emitted = process_drift(
            &raw,
            &path_map,
            None,
            &mut drift_db,
            &classifier,
            &rate_limiter,
            Some(&tx),
        )
        .unwrap();
        assert!(!emitted, "unknown path → no event");
        // Drift log not appended either (no path → can't even
        // make a meaningful row).
        assert!(
            !drift_path.exists() || std::fs::read_to_string(&drift_path).unwrap().is_empty(),
            "unknown-path skip must NOT append to drift log"
        );
    }

    // ── C4 test 8: process_drift on real-drift emits + appends ──────

    #[test]
    fn process_drift_on_real_drift_emits_event_and_appends_to_log() {
        let dir = TempDir::new().unwrap();
        let key = fresh_signing_key(&dir);
        let drift_path = dir.path().join("drift.jsonl");
        let mut drift_db = FimDriftDb::open(&drift_path, key, [0u8; 16]).unwrap();
        let path_map = InodePathMap::new();

        // Create a real on-disk file with known content so
        // compute_baseline succeeds.
        let watched = dir.path().join("watched.bin");
        std::fs::write(&watched, b"the new content").unwrap();
        let watched_meta = std::fs::metadata(&watched).unwrap();
        use std::os::unix::fs::MetadataExt;
        let key_ino = InodeKey {
            dev: watched_meta.dev(),
            ino: watched_meta.ino(),
        };
        path_map.insert(key_ino, watched.to_string_lossy().to_string());

        let stale_baseline = dummy_baseline(
            &watched.to_string_lossy(),
            // Old hash that intentionally doesn't match
            // "the new content"'s SHA-256.
            &"99".repeat(32),
        );
        let classifier = DriftClassifier::new();
        let rate_limiter = DriftRateLimiter::new();
        let (tx, mut rx) = mpsc::channel::<Event>(8);
        let raw = fake_raw(
            watched_meta.dev(),
            watched_meta.ino(),
            FimOp::Modified as u8,
        );
        let emitted = process_drift(
            &raw,
            &path_map,
            Some(&stale_baseline),
            &mut drift_db,
            &classifier,
            &rate_limiter,
            Some(&tx),
        )
        .unwrap();
        assert!(emitted, "real drift must emit Event::Fim");
        match rx.try_recv().unwrap() {
            Event::Fim(fe) => {
                assert_eq!(fe.path, watched.to_string_lossy());
                assert_eq!(fe.op, FimOp::Modified);
                assert!(fe.new_sha256.is_some());
            }
            other => panic!("expected Event::Fim, got {other:?}"),
        }
        let body = std::fs::read_to_string(&drift_path).unwrap();
        assert_eq!(body.lines().count(), 1);
        let row: FimDriftEntry = serde_json::from_str(body.trim_end()).unwrap();
        assert!(!row.decision_engine_skipped);
    }

    // ── C4 test 9: process_drift on no-real-drift skips silently ────

    #[test]
    fn process_drift_silently_skips_when_sha_matches_baseline() {
        let dir = TempDir::new().unwrap();
        let key = fresh_signing_key(&dir);
        let drift_path = dir.path().join("drift.jsonl");
        let mut drift_db = FimDriftDb::open(&drift_path, key, [0u8; 16]).unwrap();
        let path_map = InodePathMap::new();

        let watched = dir.path().join("watched.bin");
        std::fs::write(&watched, b"same content").unwrap();
        let watched_meta = std::fs::metadata(&watched).unwrap();
        use std::os::unix::fs::MetadataExt;
        let key_ino = InodeKey {
            dev: watched_meta.dev(),
            ino: watched_meta.ino(),
        };
        path_map.insert(key_ino, watched.to_string_lossy().to_string());

        // Baseline whose SHA matches the file content exactly.
        let mut h = Sha256::new();
        h.update(b"same content");
        let matching_sha = hex::encode(h.finalize());
        let matching_baseline = dummy_baseline(&watched.to_string_lossy(), &matching_sha);

        let classifier = DriftClassifier::new();
        let rate_limiter = DriftRateLimiter::new();
        let (tx, mut rx) = mpsc::channel::<Event>(8);
        let raw = fake_raw(
            watched_meta.dev(),
            watched_meta.ino(),
            FimOp::Modified as u8,
        );
        let emitted = process_drift(
            &raw,
            &path_map,
            Some(&matching_baseline),
            &mut drift_db,
            &classifier,
            &rate_limiter,
            Some(&tx),
        )
        .unwrap();
        assert!(!emitted, "no-op drift (hash matches) must not emit");
        assert!(rx.try_recv().is_err(), "no event must be sent");
        // Drift log also empty — no point recording a no-op.
        assert!(!drift_path.exists() || std::fs::read_to_string(&drift_path).unwrap().is_empty());
    }

    // ── C4 test 10: rate-limited drift still records to audit chain ─

    #[test]
    fn process_drift_rate_limited_records_audit_chain_with_skipped_flag() {
        let dir = TempDir::new().unwrap();
        let key = fresh_signing_key(&dir);
        let drift_path = dir.path().join("drift.jsonl");
        let mut drift_db = FimDriftDb::open(&drift_path, key, [0u8; 16]).unwrap();
        let path_map = InodePathMap::new();

        let watched = dir.path().join("watched.bin");
        std::fs::write(&watched, b"new content").unwrap();
        let watched_meta = std::fs::metadata(&watched).unwrap();
        use std::os::unix::fs::MetadataExt;
        let key_ino = InodeKey {
            dev: watched_meta.dev(),
            ino: watched_meta.ino(),
        };
        path_map.insert(key_ino, watched.to_string_lossy().to_string());
        let stale_baseline = dummy_baseline(&watched.to_string_lossy(), &"99".repeat(32));

        let classifier = DriftClassifier::new();
        // Zero Medium tokens → first Modified drift suppressed.
        let rate_limiter = DriftRateLimiter::with_caps(50, 0);
        let (tx, mut rx) = mpsc::channel::<Event>(8);
        let raw = fake_raw(
            watched_meta.dev(),
            watched_meta.ino(),
            FimOp::Modified as u8,
        );
        let emitted = process_drift(
            &raw,
            &path_map,
            Some(&stale_baseline),
            &mut drift_db,
            &classifier,
            &rate_limiter,
            Some(&tx),
        )
        .unwrap();
        assert!(!emitted, "throttled drift must NOT emit Event::Fim");
        assert!(rx.try_recv().is_err(), "no event must be sent");
        // BUT drift log MUST contain the row with skipped flag.
        let body = std::fs::read_to_string(&drift_path).unwrap();
        assert_eq!(body.lines().count(), 1);
        let row: FimDriftEntry = serde_json::from_str(body.trim_end()).unwrap();
        assert!(row.decision_engine_skipped, "audit chain MUST record");
        assert_eq!(row.skip_reason, "rate_limit:tier_medium");
    }

    // ─── BUG-012 (v2) — op-level FimOp::Opened handling ─────────────
    //
    // A read is NEVER an integrity drift. The drain drops every
    // `Opened` on a non-credential watched path (zero drift row, zero
    // event, hence zero "FIM DRIFT" WARN in main.rs), and forwards
    // `Opened` on a credential path SILENTLY to the rule engine (event
    // emitted, but NO drift row) so NN-L-FIM-011..017 keep their only
    // event source. The v1 4-path allowlist (FIM_OPENED_SUPPRESS_PATHS)
    // was replaced by this op-level rule.

    /// Build a (real on-disk file, InodeKey, registered path map)
    /// triple so process_drift can compute baseline without panicking.
    /// The on-disk path lives under tempdir; the `path_map` ALIAS
    /// registers it under the desired absolute path (e.g.
    /// "/etc/nsswitch.conf") so the op-level Opened logic sees the
    /// real watched path.
    fn make_watched_alias(
        dir: &TempDir,
        path_alias: &str,
    ) -> (std::path::PathBuf, InodeKey, InodePathMap) {
        let on_disk = dir.path().join("watched.bin");
        std::fs::write(&on_disk, b"unimportant content").unwrap();
        let meta = std::fs::metadata(&on_disk).unwrap();
        use std::os::unix::fs::MetadataExt;
        let key = InodeKey {
            dev: meta.dev(),
            ino: meta.ino(),
        };
        let map = InodePathMap::new();
        map.insert(key, path_alias.to_string());
        (on_disk, key, map)
    }

    /// BUG-012 (v2) #1 — the headline fix. `FimOp::Opened` on a
    /// non-credential watched path yields ZERO FIM drift: no
    /// `Event::Fim` (so main.rs never logs "FIM DRIFT"), and no row
    /// appended to `fim_drift.jsonl`. Parameterised over the exact VM
    /// boot-noise samples from the report plus the paths the v1
    /// 4-path allowlist used to cover (now subsumed by the op rule).
    #[test]
    fn bug012_v2_opened_on_noncred_watched_path_yields_zero_drift() {
        for path in &[
            // VM boot-noise samples (BUG-012 v2 report) — the 101 in
            // a 2-minute boot these were the shape of.
            "/etc/nsswitch.conf",
            "/etc/pam.d/common-auth",
            "/etc/group",
            "/usr/bin/dash",
            // Formerly the v1 FIM_OPENED_SUPPRESS_PATHS allowlist —
            // still dropped, now by the general op rule.
            "/etc/passwd",
            "/etc/shadow",
            "/etc/sudoers",
            "/etc/login.defs",
        ] {
            let dir = TempDir::new().unwrap();
            let key = fresh_signing_key(&dir);
            let drift_path = dir.path().join("drift.jsonl");
            let mut drift_db = FimDriftDb::open(&drift_path, key, [0u8; 16]).unwrap();
            let (_on_disk, key_ino, path_map) = make_watched_alias(&dir, path);
            let classifier = DriftClassifier::new();
            let rate_limiter = DriftRateLimiter::new();
            let (tx, mut rx) = mpsc::channel::<Event>(8);
            let raw = fake_raw(key_ino.dev, key_ino.ino, FimOp::Opened as u8);

            let emitted = process_drift(
                &raw,
                &path_map,
                None,
                &mut drift_db,
                &classifier,
                &rate_limiter,
                Some(&tx),
            )
            .unwrap();

            assert!(!emitted, "{path}: Opened must yield zero drift");
            assert!(
                rx.try_recv().is_err(),
                "{path}: no Event::Fim → main.rs logs no 'FIM DRIFT' WARN"
            );
            assert!(
                !drift_path.exists()
                    || std::fs::read_to_string(&drift_path).unwrap().is_empty(),
                "{path}: read must NOT append to fim_drift.jsonl"
            );
        }
    }

    /// BUG-012 (v2) #2 — `FimOp::Opened` on a CREDENTIAL path
    /// (`~/.aws/credentials`, NN-L-FIM-011 surface) is forwarded
    /// SILENTLY: an `Event::Fim` is emitted (so the rule engine can
    /// evaluate it) but NO drift row is written (no "FIM DRIFT"
    /// noise). The end-to-end assertion: the very event the drain
    /// emits, fed to NN-L-FIM-011, STILL fires. This is the
    /// credential-theft-read coverage the literal "drop all Opened"
    /// reading would have silently destroyed.
    #[test]
    fn bug012_v2_opened_on_cred_path_forwards_to_rules_silently() {
        use crate::decision::Rule;
        use crate::fim::rules::NnLFim011AwsCredsRead;
        use common::ResponseAction;

        let dir = TempDir::new().unwrap();
        let key = fresh_signing_key(&dir);
        let drift_path = dir.path().join("drift.jsonl");
        let mut drift_db = FimDriftDb::open(&drift_path, key, [0u8; 16]).unwrap();
        let (_on_disk, key_ino, path_map) =
            make_watched_alias(&dir, "/root/.aws/credentials");
        let classifier = DriftClassifier::new();
        let rate_limiter = DriftRateLimiter::new();
        let (tx, mut rx) = mpsc::channel::<Event>(8);
        // fake_raw uses modifier_comm "dpkg" — NOT an AWS CLI, so the
        // NN-L-FIM-011 FP guard does not exempt it.
        let raw = fake_raw(key_ino.dev, key_ino.ino, FimOp::Opened as u8);

        let emitted = process_drift(
            &raw,
            &path_map,
            None,
            &mut drift_db,
            &classifier,
            &rate_limiter,
            Some(&tx),
        )
        .unwrap();

        assert!(emitted, "cred-path Opened MUST forward to the rule engine");
        // SILENT: forwarded but NOT recorded as drift.
        assert!(
            !drift_path.exists()
                || std::fs::read_to_string(&drift_path).unwrap().is_empty(),
            "cred-path read MUST NOT append to fim_drift.jsonl (no 'FIM DRIFT' noise)"
        );

        let ev = rx.try_recv().expect("Event::Fim must be sent for cred-path read");
        let fe = match &ev {
            Event::Fim(fe) => {
                assert_eq!(fe.path, "/root/.aws/credentials");
                assert_eq!(fe.op, FimOp::Opened);
                fe.clone()
            }
            other => panic!("expected Event::Fim, got {other:?}"),
        };
        // The forwarded event STILL reaches + fires NN-L-FIM-011.
        assert_eq!(fe.op, common::wire::FimOp::Opened);
        let verdict = NnLFim011AwsCredsRead
            .evaluate(&ev)
            .expect("BUG-012 v2 coverage: NN-L-FIM-011 MUST still fire on the forwarded event");
        assert_eq!(verdict.rule_id, "NN-L-FIM-011_AwsCredsRead");
        assert_eq!(verdict.action, ResponseAction::KillProcess);
    }

    /// BUG-012 (v2) #3 — regression guard: a `Modified` on a critical
    /// path STILL drifts exactly as before. The read carve-out must
    /// not touch the integrity-changing ops FIM-001..009 depend on.
    #[test]
    fn bug012_v2_modify_on_critical_path_still_fires() {
        let dir = TempDir::new().unwrap();
        let key = fresh_signing_key(&dir);
        let drift_path = dir.path().join("drift.jsonl");
        let mut drift_db = FimDriftDb::open(&drift_path, key, [0u8; 16]).unwrap();
        let (on_disk, key_ino, path_map) = make_watched_alias(&dir, "/etc/passwd");
        // Mutate the file so a real-drift hash-diff is observed.
        std::fs::write(&on_disk, b"MUTATED content").unwrap();

        let classifier = DriftClassifier::new();
        let rate_limiter = DriftRateLimiter::new();
        let (tx, mut rx) = mpsc::channel::<Event>(8);
        let stale_baseline = dummy_baseline("/etc/passwd", &"42".repeat(32));
        let raw = fake_raw(key_ino.dev, key_ino.ino, FimOp::Modified as u8);

        let emitted = process_drift(
            &raw,
            &path_map,
            Some(&stale_baseline),
            &mut drift_db,
            &classifier,
            &rate_limiter,
            Some(&tx),
        )
        .unwrap();
        assert!(emitted, "Modified on /etc/passwd MUST still fire");
        match rx.try_recv().unwrap() {
            Event::Fim(fe) => {
                assert_eq!(fe.path, "/etc/passwd");
                assert_eq!(fe.op, FimOp::Modified);
            }
            other => panic!("expected Event::Fim, got {other:?}"),
        }
    }
}
