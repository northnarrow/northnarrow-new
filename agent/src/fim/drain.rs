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
//!    the §6.5 hierarchical token-bucket rate-limiter to drift
//!    written by a package manager (review 76: only there; any
//!    other writer always reaches the rules), then:
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
use std::path::Path;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use anyhow::{anyhow, Context, Result};
use chrono::{DateTime, Utc};
use common::wire::{
    FimDriftRaw, FimEvent, FimOp, InodeKey, FIM_CHILD_NAME_LEN, FIM_CHILD_TRUNCATED,
    FIM_RENAME_REPLACED,
};
use common::Event;
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;

use crate::posture::lineage::AuthSessionTracker;
use tracing::{debug, info, warn};

use crate::audit::AgentSigningKey;
use crate::fim::attach::{key_for_path, WatchedPathsHandle};
use crate::fim::baseline::{compute_baseline, BaselineCache, BaselineEntry};

// BUG-026: production now uses the chainlog core; the legacy-v1
// `build_signed_drift_entry` / `compute_entry_hash` (kept only so the
// byte-compat gate can mint a real legacy line) are `#[cfg(test)]`, so
// their imports are gated to test builds.
#[cfg(test)]
use crate::audit::GENESIS_PREV_HASH;
#[cfg(test)]
use base64::{engine::general_purpose::STANDARD as B64, Engine};
#[cfg(test)]
use sha2::{Digest, Sha256};

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

    /// Forget an inode whose file is gone (review 57).
    pub fn remove(&self, key: &InodeKey) {
        self.inner.write().remove(key);
    }

    /// Every inode mapped to `path` (external audit FIMP-004: a path whose
    /// file was replaced may still hold its old inode's entry).
    pub fn keys_for_path(&self, path: &str) -> Vec<InodeKey> {
        self.inner
            .read()
            .iter()
            .filter(|(_, p)| p.as_str() == path)
            .map(|(k, _)| *k)
            .collect()
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
        // External audit FIMR-005: a path a Critical rule guards is never
        // throttled (§6.5, Q4), whatever the op — a modification of
        // /usr/sbin/sshd was "Medium" here. Since review 76 only a package
        // transaction's drift is paced at all.
        if op != FimOp::Opened && crate::fim::rules::is_critical_rule_path(path) {
            return DriftSeverity::Critical;
        }
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
            // Review 86: a capability grant comes from the file-open
            // sensor, never from the drift ring; never throttled.
            FimOp::CapabilitySet => DriftSeverity::Critical,
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
/// [`process_drift`] spends them only on drift written by a package
/// manager (review 76).
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

/// BUG-026 migration — the `fim_drift.jsonl` DATA payload: every
/// [`FimDriftEntry`] field EXCEPT the chain framing (`prev_hash` /
/// `entry_hash` / `agent_sig`), in the SAME declaration order. A
/// [`crate::chainlog::ChainLine<FimDriftPayload>`] with `fmt_ver = None`
/// therefore serialises BYTE-FOR-BYTE identically to a legacy v1
/// `FimDriftEntry`, so an existing on-disk `fim_drift.jsonl` still
/// verifies under the rotation-aware reader (proven by
/// `bug026_legacy_v1_drift_line_still_verifies`). The two Q4 fields keep
/// `#[serde(default)]` with NO `skip_serializing_if`, exactly matching
/// the legacy struct (they are always serialised).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FimDriftPayload {
    pub ts: String,
    pub path: String,
    pub op: FimOp,
    pub baseline_sha256: Option<String>,
    pub new_sha256: Option<String>,
    pub modifier_pid: u32,
    pub modifier_uid: u32,
    pub modifier_comm: String,
    pub severity: DriftSeverity,
    #[serde(default)]
    pub decision_engine_skipped: bool,
    #[serde(default)]
    pub skip_reason: String,
    pub agent_id: String,
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

/// Append-only writer for the drift log. BUG-026: now a thin wrapper
/// over the shared [`crate::chainlog::RotatingChainLog`] — it builds the
/// [`FimDriftPayload`] and the core handles chaining, signing, rotation
/// (size cap + retention), and the chattr dance via the shared
/// `StateDirProtection`. New lines are v2 (`fmt_ver`); existing v1 lines
/// stay valid (see `bug026_legacy_v1_drift_line_still_verifies`).
pub struct FimDriftDb {
    inner: crate::chainlog::RotatingChainLog<FimDriftPayload>,
    agent_id: [u8; 16],
}

/// Where a drift row goes: the drift log itself, or the drain's shared one
/// behind its lock. External audit FIMP-003: the drain held that lock
/// while it hashed the file, so a large file stalled every other writer of
/// the chain; the lock is now taken for the append alone.
pub trait DriftSink {
    fn append_drift(&mut self, draft: FimDriftDraft) -> Result<String>;
}

impl DriftSink for FimDriftDb {
    fn append_drift(&mut self, draft: FimDriftDraft) -> Result<String> {
        self.append(draft)
    }
}

impl DriftSink for &parking_lot::Mutex<FimDriftDb> {
    fn append_drift(&mut self, draft: FimDriftDraft) -> Result<String> {
        self.lock().append(draft)
    }
}

impl FimDriftDb {
    pub fn open(
        path: &Path,
        key: AgentSigningKey,
        agent_id: [u8; 16],
        protection: std::sync::Arc<dyn crate::chainlog::ProtectionManager>,
        cfg: crate::chainlog::RotationConfig,
    ) -> Result<Self> {
        let inner =
            crate::chainlog::RotatingChainLog::<FimDriftPayload>::open(path, key, cfg, protection)?;
        Ok(Self { inner, agent_id })
    }

    /// Append one drift row as a signed chainlog data line (rotating the
    /// log at the size cap). Returns the new line's `entry_hash` hex.
    pub fn append(&mut self, draft: FimDriftDraft) -> Result<String> {
        let payload = FimDriftPayload {
            ts: format_ts(Utc::now()),
            path: draft.path,
            op: draft.op,
            baseline_sha256: draft.baseline_sha256,
            new_sha256: draft.new_sha256,
            modifier_pid: draft.modifier_pid,
            modifier_uid: draft.modifier_uid,
            modifier_comm: draft.modifier_comm,
            severity: draft.severity,
            decision_engine_skipped: draft.decision_engine_skipped,
            skip_reason: draft.skip_reason,
            agent_id: hex::encode(self.agent_id),
        };
        self.inner.append(payload)
    }

    pub fn last_hash(&self) -> &str {
        self.inner.last_hash()
    }
}

/// Build a signed legacy-v1 `FimDriftEntry`. Production now uses the
/// chainlog core; retained ONLY so the BUG-026 byte-compat gate
/// (`bug026_legacy_v1_drift_line_still_verifies`) can produce a real
/// legacy line to verify against the rotation-aware reader.
#[cfg(test)]
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

#[cfg(test)]
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

/// BUG-022 — rebuild a watched directory's child path from the bare
/// dir path + the kernel-carried leaf in [`FimDriftRaw::child_name`]
/// (NUL-terminated, UTF-8 lossy). Returns `None` when the leaf is
/// empty or (defensively) contains a `/` — the kernel hands a single
/// dentry component, so a slash means a crafted / garbled record.
fn reconstruct_child_path(dir: &str, raw: &FimDriftRaw) -> Option<String> {
    let end = raw
        .child_name
        .iter()
        .position(|&b| b == 0)
        .unwrap_or(raw.child_name.len());
    if end == 0 {
        return None;
    }
    let leaf = String::from_utf8_lossy(&raw.child_name[..end]);
    if leaf.contains('/') {
        return None;
    }
    Some(format!("{}/{}", dir.trim_end_matches('/'), leaf))
}

/// Review 58: children whose create or rename event was handled before
/// the file existed at its final path. The LSM hooks fire before the
/// operation, and a fast drain used to `stat` too early and skip the
/// enrollment for good, so the dropped file's later in-place edits went
/// unseen. The drain loop retries them for [`ENROLL_RETRY_FOR`].
static PENDING_ENROLL: std::sync::Mutex<Vec<(String, std::time::Instant)>> =
    std::sync::Mutex::new(Vec::new());
const ENROLL_RETRY_FOR: std::time::Duration = std::time::Duration::from_secs(2);

/// External audit FIMP-005: watched inodes renamed away from their path,
/// waiting for the rename to land (the LSM hook fires before it). See
/// [`settle_rename`].
static PENDING_RENAME: std::sync::Mutex<Vec<PendingRename>> = std::sync::Mutex::new(Vec::new());

/// A watched inode renamed away, and — external audit FIMR-004 — the
/// renamer's event when the rename put another file over it.
type PendingRename = (InodeKey, String, std::time::Instant, Option<FimDriftRaw>);

/// External audit FIMR-004: watched paths whose file another one replaced
/// by a rename over it (`mv` of a prepared file onto a binary, a PAM
/// module, a unit: how installers and rootkits alike swap a file), with
/// the renamer's event, once the rename landed. The rename alone reached
/// only the rename rules; every rule guarding the path's content watches
/// modifications. Each is checked as one: the new file against the
/// baseline, attributed to the renamer.
static REPLACEMENTS: std::sync::Mutex<Vec<(String, FimDriftRaw)>> =
    std::sync::Mutex::new(Vec::new());
const REPLACEMENTS_MAX: usize = 1024;

fn queue_replacement(path: &str, renamed: &FimDriftRaw) {
    let Ok(mut q) = REPLACEMENTS.lock() else {
        return;
    };
    if q.len() < REPLACEMENTS_MAX {
        q.push((path.to_string(), *renamed));
    } else {
        warn!(target: "fim.drain", path, "replacement checks queue full — this replacement is not checked");
    }
}

/// The queued replacements as modification events of the file now at each
/// path, by the renamer. A path holding nothing any more is dropped.
fn replacement_raws() -> Vec<FimDriftRaw> {
    let queued = match REPLACEMENTS.lock() {
        Ok(mut q) => std::mem::take(&mut *q),
        Err(_) => return Vec::new(),
    };
    queued
        .into_iter()
        .filter_map(|(path, mut raw)| {
            let key = key_for_path(Path::new(&path)).ok()?;
            // the rename has landed: read what is there now
            raw.timestamp_ns = monotonic_ns();
            raw.target_dev = key.dev;
            raw.target_ino = key.ino;
            raw.op = FimOp::Modified as u8;
            raw.op_flags = 0;
            raw.dest_dev = 0;
            raw.dest_ino = 0;
            raw.child_name = [0u8; FIM_CHILD_NAME_LEN];
            raw.child_name_flags = 0;
            Some(raw)
        })
        .collect()
}

/// Retry the pending enrollments and renames; `true` while some are still
/// waiting.
fn retry_pending_enrollments(
    path_map: &InodePathMap,
    watched_paths: Option<&parking_lot::Mutex<WatchedPathsHandle>>,
) -> bool {
    let renames_waiting = match PENDING_RENAME.lock() {
        Ok(mut pending) => {
            pending.retain(|(key, path, since, replaced)| {
                if settle_rename(key, path, path_map, watched_paths) {
                    if let Some(raw) = replaced {
                        queue_replacement(path, raw);
                    }
                    return false;
                }
                since.elapsed() < ENROLL_RETRY_FOR
            });
            !pending.is_empty()
        }
        Err(_) => false,
    };
    let Ok(mut pending) = PENDING_ENROLL.lock() else {
        return renames_waiting;
    };
    pending.retain(|(path, since)| {
        !enroll_child(path, path_map, watched_paths) && since.elapsed() < ENROLL_RETRY_FOR
    });
    renames_waiting || !pending.is_empty()
}

/// External audit FIMP-005: a watched file renamed away keeps its inode,
/// which went on resolving to the watched path — every later event on the
/// moved file was reported under the watched name (`mv authorized_keys
/// authorized_keys.bak`, then an edit of the copy, drew the
/// authorized_keys rule's kill). Once the path no longer resolves to
/// `key`, forget `key` and watch whatever now lives at the path. `false`
/// while the path still resolves to `key`: the rename has not landed yet,
/// or was refused.
fn settle_rename(
    key: &InodeKey,
    path: &str,
    path_map: &InodePathMap,
    watched_paths: Option<&parking_lot::Mutex<WatchedPathsHandle>>,
) -> bool {
    if matches!(key_for_path(Path::new(path)), Ok(k) if k == *key) {
        return false;
    }
    forget_if_gone(key, path, path_map, watched_paths);
    // A replacement may already sit at the path (rename-over). If nothing
    // does, wait for one: see AWAITING_RETURN.
    if !enroll_child(path, path_map, watched_paths) {
        if let Ok(mut awaiting) = AWAITING_RETURN.lock() {
            if !awaiting.iter().any(|p| p == path) && awaiting.len() < AWAITING_RETURN_MAX {
                awaiting.push(path.to_string());
            }
        }
    }
    true
}

/// External audit FIMP-005: watched paths whose file was renamed away and
/// not replaced. The kernel watches inodes, and nothing tells the drain
/// when a file comes back to a path no watched inode holds — `mv` back,
/// or a new file put there. The drain looks once a second
/// ([`AWAITING_RETURN_EVERY`]); a file back at its path is watched again
/// and checked against the baseline as a creation: a replacement is a
/// change of the watched file.
static AWAITING_RETURN: std::sync::Mutex<Vec<String>> = std::sync::Mutex::new(Vec::new());
const AWAITING_RETURN_MAX: usize = 256;
const AWAITING_RETURN_EVERY: std::time::Duration = std::time::Duration::from_secs(1);

/// Paths back at their place since the last look: enrolled again, and
/// returned with their new inode for a drift check.
fn returned_paths(
    path_map: &InodePathMap,
    watched_paths: Option<&parking_lot::Mutex<WatchedPathsHandle>>,
) -> Vec<InodeKey> {
    let mut back = Vec::new();
    if let Ok(mut awaiting) = AWAITING_RETURN.lock() {
        awaiting.retain(|path| match key_for_path(Path::new(path)) {
            Ok(key) if enroll_child(path, path_map, watched_paths) => {
                back.push(key);
                false
            }
            _ => true,
        });
    }
    back
}

/// `true` while a renamed-away path waits for its file.
fn awaiting_returns() -> bool {
    AWAITING_RETURN
        .lock()
        .map(|a| !a.is_empty())
        .unwrap_or(false)
}

/// External audit FIMP-005: the drift record for a file back at a watched
/// path — a creation, whose writer the drain cannot know.
fn returned_raw(key: InodeKey) -> FimDriftRaw {
    let mut raw: FimDriftRaw = bytemuck::Zeroable::zeroed();
    raw.timestamp_ns = monotonic_ns();
    raw.target_dev = key.dev;
    raw.target_ino = key.ino;
    raw.op = FimOp::Created as u8;
    raw
}

/// External audit FIMP-004: watch `path` by the inode it holds now — the
/// recompute task's re-baseline (an operator's `nn-admin fim baseline`, a
/// path added to the overlay) wrote the chain but left the kernel watching
/// the inode of boot time, or nothing. Inodes the path held before are
/// forgotten (map and `WATCHED_PATHS`), so an old file elsewhere does not
/// answer for it. `false` when nothing is at the path.
pub fn reenroll_path(
    path: &str,
    path_map: &InodePathMap,
    watched_paths: Option<&parking_lot::Mutex<WatchedPathsHandle>>,
) -> bool {
    let Ok(key) = key_for_path(Path::new(path)) else {
        return false;
    };
    for stale in path_map.keys_for_path(path) {
        if stale != key {
            path_map.remove(&stale);
            if let Some(w) = watched_paths {
                w.lock().unenroll(stale);
            }
        }
    }
    enroll_child(path, path_map, watched_paths)
}

/// BUG-022 — enroll a freshly-dropped child of a watched directory
/// into the userland [`InodePathMap`] AND (when a handle is wired) the
/// kernel `WATCHED_PATHS` map, so a later in-place edit of the dropped
/// file is observed directly by the BUG-023 write-then-close hook. The
/// child is stat'd for its kernel-form `(dev,ino)`; `false` when it is
/// not there (yet: the caller queues it for a retry, review 58). A full
/// `WATCHED_PATHS` (8192 cap) is logged LOUD — a silently-dropped
/// enroll must not masquerade as coverage.
fn enroll_child(
    child_path: &str,
    path_map: &InodePathMap,
    watched_paths: Option<&parking_lot::Mutex<WatchedPathsHandle>>,
) -> bool {
    let key = match key_for_path(Path::new(child_path)) {
        Ok(k) => k,
        Err(_) => return false,
    };
    path_map.insert(key, child_path.to_string());
    if let Some(wp) = watched_paths {
        if !wp.lock().enroll(key) {
            warn!(
                target: "fim.drain",
                path = %child_path,
                "BUG-022: WATCHED_PATHS full (8192 cap) — dropped child NOT enrolled; \
                 its later in-place edits stay unobserved until a re-baseline"
            );
        }
    }
    true
}

/// Review 57: once a watched file is deleted its inode number is free, and
/// the filesystem reuses it for unrelated files (ext4 does so at once). If
/// the path no longer resolves to `key` (gone, or replaced by another
/// inode), stop watching `key`; if it still does (the unlink was refused,
/// or another hard link remains), keep it.
fn forget_if_gone(
    key: &InodeKey,
    path: &str,
    path_map: &InodePathMap,
    watched_paths: Option<&parking_lot::Mutex<WatchedPathsHandle>>,
) {
    if matches!(key_for_path(Path::new(path)), Ok(k) if k == *key) {
        return;
    }
    path_map.remove(key);
    if let Some(wp) = watched_paths {
        wp.lock().unenroll(*key);
    }
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
///    `skip_reason` on the persisted entry. Only drift whose writer
///    descends from a package manager (`lineage`) is throttled: the
///    buckets are host-wide, so a writer that could spend them could
///    also skip the rules for its own next write (review 76). With no
///    `lineage`, nothing is throttled.
/// 5. Append to drift DB (always, evidence preservation).
/// 6. Push `Event::Fim` onto `outbox` ONLY if rate limiter
///    allowed. The drain loop forwards the outbox to the engine
///    with backpressure (review 75): a full event channel delays
///    an event, it never drops it.
///
/// Returns `Ok(true)` if an event was emitted to the outbox,
/// `Ok(false)` if processing completed without emission (path
/// unknown, no drift, or rate-limited). Errors are propagated
/// for the drain loop to log + continue.
#[allow(clippy::too_many_arguments)] // drain pipeline context; grouping into a struct is a Tappa-9 refactor
pub fn process_drift(
    raw: &FimDriftRaw,
    path_map: &InodePathMap,
    last_baseline: Option<&BaselineEntry>,
    drift_db: &mut impl DriftSink,
    classifier: &DriftClassifier,
    rate_limiter: &DriftRateLimiter,
    watched_paths: Option<&parking_lot::Mutex<WatchedPathsHandle>>,
    lineage: Option<&AuthSessionTracker>,
    outbox: Option<&mut Vec<Event>>,
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

    // BUG-022 — child-leaf reconstruction. When the kernel carried a
    // child leaf (a Create in, or a rename INTO, a watched DIRECTORY),
    // the `path` resolved above is only the bare watched dir — which no
    // child-prefix rule matches (the dead-rule root). Rebuild
    // `dir + "/" + leaf`, normalize a drop-via-rename to Created, mirror
    // the truncated flag for the rules, and enroll the new child inode
    // so its later in-place edits are caught by the write-then-close
    // hook. Events without a child leaf (every non-Create/Rename op, and
    // renames whose dest dir isn't watched) fall through unchanged.
    let (path, op, child_truncated) =
        if matches!(op, FimOp::Created | FimOp::Renamed) && raw.child_name[0] != 0 {
            match reconstruct_child_path(&path, raw) {
                Some(child) => {
                    let truncated = raw.child_name_flags & FIM_CHILD_TRUNCATED != 0;
                    if !enroll_child(&child, path_map, watched_paths) {
                        if let Ok(mut pending) = PENDING_ENROLL.lock() {
                            pending.push((child.clone(), std::time::Instant::now()));
                        }
                    }
                    // A rename INTO a watched dir is a drop → present as Created
                    // (single userland normalization point; the dir-class rules
                    // keep their Created|Modified op-sets unchanged).
                    (child, FimOp::Created, truncated)
                }
                None => (path, op, false),
            }
        } else {
            (path, op, false)
        };
    if op == FimOp::Deleted {
        forget_if_gone(&key, &path, path_map, watched_paths);
    }
    // External audit FIMP-005: the watched inode itself renamed (no child
    // leaf: the source was watched). FIMR-004: or replaced by another file
    // renamed over it — checked as a modification once the rename lands.
    if op == FimOp::Renamed && raw.child_name[0] == 0 {
        let replaced = (raw.op_flags & FIM_RENAME_REPLACED != 0).then_some(*raw);
        if settle_rename(&key, &path, path_map, watched_paths) {
            if let Some(r) = &replaced {
                queue_replacement(&path, r);
            }
        } else if let Ok(mut pending) = PENDING_RENAME.lock() {
            pending.push((key, path.clone(), std::time::Instant::now(), replaced));
        }
    }

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
        // Two consumers of a read-open exist: the credential-read rules
        // (NN-L-FIM-011..017, matched by path) and the K3 file-canary
        // detector (matched by inode, published by the canary index
        // rebuilds). Everything else is dropped as non-drift noise.
        let is_canary = crate::canary::read_forward::contains(&key);
        if !is_canary && !crate::fim::rules::is_credential_path(&path) {
            debug!(
                target: "fim.drain",
                path = %path,
                "BUG-012 v2: dropping FimOp::Opened on non-credential, non-canary watched path \
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
            canary = is_canary,
            "BUG-012 v2: forwarding FimOp::Opened on credential/canary path to rule engine \
             (silent — not recorded as drift)"
        );
        if let Some(out) = outbox {
            out.push(Event::Fim(FimEvent {
                timestamp_ns: raw.timestamp_ns,
                path: path.clone(),
                op,
                new_sha256: None,
                baseline_sha256: None,
                // Content-less cred-read event: no size delta, and the
                // NN-L-FIM-011..017 rules don't consume exe — leave all None.
                new_size: None,
                baseline_size: None,
                modifier_exe: None,
                modifier_pid: raw.modifier_pid,
                modifier_uid: raw.modifier_uid,
                modifier_comm: comm_to_string(&raw.modifier_comm),
                dest_path: None,
                child_truncated,
                wide_coverage: false,
                owner_uid: None,
                reader_dac_capable: false,
                capability: None,
            }));
            return Ok(true);
        }
        return Ok(false);
    }

    // Resolve any 1-hop symlink + capture content. For Deleted
    // and Renamed ops the target may be gone; treat the SHA
    // probe as None in that case and let the diff fall to the
    // baseline-side comparison. We keep the chosen non-symlink
    // draft so the post-mod SIZE (`size_bytes`) rides alongside
    // the hash — NN-L-FIM-005's rsyslogd-append exemption needs
    // the size delta to tell an append (grew) from a truncation.
    let content = match op {
        FimOp::Deleted | FimOp::Renamed => None,
        _ => content_after(&path, raw.timestamp_ns),
    };
    let new_sha256 = content.as_ref().map(|c| c.0.clone());
    let new_size = content.as_ref().map(|c| c.1);
    let baseline_sha256 = last_baseline.map(|b| b.sha256.clone());
    let baseline_size = last_baseline.map(|b| b.size_bytes);

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
    // Review 76: the §6.5 buckets are host-wide. Spent by anyone, they
    // made the next writer's drift skip the rules: 60 throwaway files in
    // /etc/cron.d, then a real drop-in, and NN-L-FIM-007 never ran. They
    // now pace only the burst source they were sized for, a package
    // transaction (whose writes the rules log, not kill, anyway); every
    // other write reaches the rules. The journal and the detection store
    // have their own per-rule budget (`detection_budget`).
    let package_managed = lineage.is_some_and(|l| l.is_system_daemon_mediated(raw.modifier_pid));
    let (skipped, skip_reason) = if package_managed {
        match rate_limiter.try_consume(severity) {
            Ok(()) => (false, String::new()),
            Err(reason) => (true, reason),
        }
    } else {
        (false, String::new())
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
    // External audit FIMP-006: evidence and detection are separate. A drift
    // log that cannot be written (disk full, a rotation or protection
    // fault) used to return here, before the event reached the rules —
    // silencing every FIM rule on every watched path at once.
    if let Err(e) = drift_db.append_drift(draft).context("append to drift DB") {
        report_evidence_loss(&path, &e);
    }

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

    if let Some(out) = outbox {
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
        out.push(Event::Fim(FimEvent {
            timestamp_ns: raw.timestamp_ns,
            path: path.clone(),
            op,
            new_sha256: new_sha256.and_then(|h| decode_sha_hex(&h)),
            baseline_sha256: baseline_sha256.and_then(|h| decode_sha_hex(&h)),
            new_size,
            baseline_size,
            // Best-effort `/proc/<pid>/exe` of the writer. Feeds the
            // NN-L-FIM-005 rsyslogd-append exemption; a miss (writer
            // already exited, PID reused, unreadable link) leaves it
            // None → the rule falls through and still fires.
            modifier_exe: resolve_pid_exe(raw.modifier_pid),
            modifier_pid: raw.modifier_pid,
            modifier_uid: raw.modifier_uid,
            modifier_comm: comm_to_string(&raw.modifier_comm),
            dest_path,
            child_truncated,
            wide_coverage: false,
            owner_uid: None,
            reader_dac_capable: false,
            capability: None,
        }));
    }
    Ok(true)
}

/// External audit FIMP-006: drift the agent detected but could not
/// record. Logged at ERROR once a minute with the count since, never
/// silently.
fn report_evidence_loss(path: &str, error: &anyhow::Error) {
    static LOST: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    static LAST_REPORT: parking_lot::Mutex<Option<std::time::Instant>> =
        parking_lot::Mutex::new(None);
    let lost = LOST.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1;
    let mut last = LAST_REPORT.lock();
    if last.is_some_and(|at| at.elapsed() < std::time::Duration::from_secs(60)) {
        return;
    }
    *last = Some(std::time::Instant::now());
    tracing::error!(
        target: "fim.drain",
        path,
        error = %format!("{error:#}"),
        lost_since_boot = lost,
        "FIM EVIDENCE LOSS: fim_drift.jsonl cannot be written — drift still reaches the \
         rules, but is not recorded"
    );
}

fn comm_to_string(comm: &[u8]) -> String {
    let end = comm.iter().position(|&b| b == 0).unwrap_or(comm.len());
    String::from_utf8_lossy(&comm[..end]).into_owned()
}

/// Best-effort resolve of a writer PID's `/proc/<pid>/exe` for
/// [`FimEvent::modifier_exe`]. Kernel-resolved symlink (never `comm`,
/// which is `prctl(PR_SET_NAME)`-spoofable). Returns `None` when the
/// process has already exited, the link is unreadable, or the path is
/// non-UTF-8 — every miss is fail-open for detection (the consuming
/// NN-L-FIM-005 exemption only ever SUPPRESSES on a positive match, so
/// a miss means the rule still fires). Racy by nature (PID may be reused
/// between the kernel event and this read); the exemption layers a uid
/// and size-delta check on top so a stale resolution alone can't
/// silence a real truncation.
fn resolve_pid_exe(pid: u32) -> Option<String> {
    std::fs::read_link(format!("/proc/{pid}/exe"))
        .ok()
        .map(|p| p.to_string_lossy().into_owned())
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
    watched_paths: Option<std::sync::Arc<parking_lot::Mutex<WatchedPathsHandle>>>,
    lineage: AuthSessionTracker,
    event_tx: mpsc::Sender<Event>,
) -> std::io::Result<()> {
    use tokio::io::unix::AsyncFd;
    let mut async_fd = AsyncFd::new(rb)?;
    info!(
        target: "fim.drain",
        baseline_cache_entries = baseline_cache.len(),
        "fim drain loop: ready"
    );
    // Events for the engine, forwarded as soon as they are made, with
    // backpressure. `try_send` dropped them when the channel was full, and a
    // flood of events (an unprivileged loop of reads was enough) filled it:
    // the FIM kill rules never saw a persistence write (review 75).
    let mut outbox: Vec<Event> = Vec::new();
    let mut returns_checked = std::time::Instant::now();
    // One event through the pipeline: the baseline looked up by the watched
    // path, the hash and the rules' input built off the runtime's threads,
    // the drift log locked for its append only (external audit FIMP-003).
    let check = |raw: &FimDriftRaw, outbox: &mut Vec<Event>| -> Result<bool> {
        let last_baseline = inode_map
            .lookup(&InodeKey {
                dev: raw.target_dev,
                ino: raw.target_ino,
            })
            .and_then(|p| baseline_cache.get_content(&p));
        off_the_runtime(|| {
            process_drift(
                raw,
                inode_map.as_ref(),
                last_baseline.as_ref(),
                &mut drift_db.as_ref(),
                classifier.as_ref(),
                rate_limiter.as_ref(),
                watched_paths.as_deref(),
                Some(&lineage),
                Some(outbox),
            )
        })
    };
    loop {
        // Review 58: while children wait for their file to appear, wake up
        // every few milliseconds to retry them.
        let waiting = retry_pending_enrollments(inode_map.as_ref(), watched_paths.as_deref());
        // External audit FIMP-005: a file back at a watched path it was
        // renamed away from is watched again and checked as a creation.
        if returns_checked.elapsed() >= AWAITING_RETURN_EVERY && awaiting_returns() {
            returns_checked = std::time::Instant::now();
            for key in returned_paths(inode_map.as_ref(), watched_paths.as_deref()) {
                if let Err(e) = check(&returned_raw(key), &mut outbox) {
                    warn!(target: "fim.drain", error = %format!("{e:#}"), "drift check of a returned file failed");
                }
            }
        }
        // External audit FIMR-004: files renamed over watched ones, landed.
        for raw in replacement_raws() {
            if let Err(e) = check(&raw, &mut outbox) {
                warn!(target: "fim.drain", error = %format!("{e:#}"), "drift check of a replaced file failed");
            }
        }
        for event in outbox.drain(..) {
            if event_tx.send(event).await.is_err() {
                warn!(target: "fim.drain", "event channel closed — Event::Fim not delivered");
            }
        }
        let wake_after = if waiting {
            Some(std::time::Duration::from_millis(5))
        } else if awaiting_returns() {
            Some(AWAITING_RETURN_EVERY)
        } else {
            None
        };
        let mut guard = match wake_after {
            Some(after) => match tokio::time::timeout(after, async_fd.readable_mut()).await {
                Ok(g) => g?,
                Err(_) => continue,
            },
            None => async_fd.readable_mut().await?,
        };
        let inner = guard.get_inner_mut();
        let mut drained = 0u32;
        let mut more = false;
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
            if let Err(e) = check(&raw, &mut outbox) {
                warn!(
                    target: "fim.drain",
                    error = %format!("{e:#}"),
                    "process_drift error — event dropped, drain continues"
                );
            }
            // Forward at once: under a flood of reads the ring never runs
            // empty, and an event held for the end of the batch would wait
            // for the flood to stop.
            if !outbox.is_empty() || drained >= DRAIN_TURN {
                more = true;
                break;
            }
        }
        // Records still queued: stay ready so the next turn reads them at once.
        if !more {
            guard.clear_ready();
        }
        drop(guard);
        for event in outbox.drain(..) {
            if event_tx.send(event).await.is_err() {
                warn!(target: "fim.drain", "event channel closed — Event::Fim not delivered");
            }
        }
        if drained == 0 {
            tokio::time::sleep(std::time::Duration::from_millis(1)).await;
        }
    }
}

/// Records read per drain turn at most before the loop yields.
const DRAIN_TURN: u32 = 4096;

/// External audit FIMP-003: the content hash of each path, with when it
/// began (CLOCK_MONOTONIC, the kernel events' clock). An event that
/// happened before a hash of its path began is answered by that hash: the
/// file it saw was already the one read. Each event is still checked and
/// attributed on its own; a burst of events on one large file (up to 512
/// MiB is hashed) no longer costs one hash each, which kept the drain —
/// the only reader of the kernel's ring — behind while the ring filled.
static HASHED: std::sync::Mutex<Option<HashMap<String, Hashed>>> = std::sync::Mutex::new(None);
const HASHED_MAX: usize = 4096;
/// The LSM hooks fire just before the change they report: a hash that
/// began within this margin after an event may have read the file before
/// the change landed, and does not answer for it.
const HASH_REUSE_MARGIN_NS: u64 = 50_000_000;

#[derive(Clone)]
struct Hashed {
    began_ns: u64,
    /// SHA-256 (hex) and size of the file, `None` when it could not be read.
    content: Option<(String, u64)>,
}

/// The content of `path` as of an event at `event_ns`: the last hash when
/// it began after the event, else a new one.
fn content_after(path: &str, event_ns: u64) -> Option<(String, u64)> {
    if let Ok(cache) = HASHED.lock() {
        if let Some(h) = cache.as_ref().and_then(|c| c.get(path)) {
            if event_ns != 0 && event_ns + HASH_REUSE_MARGIN_NS <= h.began_ns {
                return h.content.clone();
            }
        }
    }
    let began_ns = monotonic_ns();
    let content = match compute_baseline(Path::new(path)) {
        Ok(drafts) => drafts
            .into_iter()
            .find(|d| !d.is_symlink)
            .map(|d| (d.sha256, d.size_bytes)),
        Err(e) => {
            debug!(
                target: "fim.drain",
                path = %path,
                error = %e,
                "compute_baseline failed during drift re-hash; emitting with new_sha256=None"
            );
            None
        }
    };
    if let Ok(mut cache) = HASHED.lock() {
        let cache = cache.get_or_insert_with(HashMap::new);
        if cache.len() >= HASHED_MAX {
            cache.clear();
        }
        cache.insert(
            path.to_string(),
            Hashed {
                began_ns,
                content: content.clone(),
            },
        );
    }
    content
}

/// CLOCK_MONOTONIC in ns: `bpf_ktime_get_ns`'s clock.
fn monotonic_ns() -> u64 {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: a valid clock id and a timespec to fill.
    unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) };
    ts.tv_sec as u64 * 1_000_000_000 + ts.tv_nsec as u64
}

/// Run the drain's synchronous work (hashing, the drift log, `/proc`
/// reads) where it does not hold up the runtime's other tasks.
fn off_the_runtime<T>(f: impl FnOnce() -> T) -> T {
    match tokio::runtime::Handle::try_current() {
        Ok(h) if h.runtime_flavor() == tokio::runtime::RuntimeFlavor::MultiThread => {
            tokio::task::block_in_place(f)
        }
        _ => f(),
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
            op_flags: 0,
            _pad: [0u8; 6],
            // Polish #3 defaults — non-Rename events leave the
            // dest pair zeroed; rename-specific tests construct
            // FimDriftRaw directly with non-zero dest values.
            dest_dev: 0,
            dest_ino: 0,
            // BUG-022 defaults — no child leaf unless a dir-drop
            // test seeds child_name explicitly.
            child_name: [0u8; common::wire::FIM_CHILD_NAME_LEN],
            child_name_flags: 0,
            _pad2: [0u8; 7],
        }
    }

    /// BUG-022 #1 — reconstruction MUST be driven by the REAL wire
    /// shape: a `FimDriftRaw` keyed on a watched DIRECTORY inode with
    /// the dropped leaf in `child_name`. Feeding a pre-baked full child
    /// path — the exact thing that hid BUG-022 (green tests on a path
    /// the live pipeline never produces) — is forbidden. Asserts the
    /// emitted event carries `dir/leaf` (so the child-prefix rules
    /// match), op is normalized to Created, and the dropped child is
    /// enrolled into the InodePathMap on the fly.
    #[test]
    fn bug022_reconstructs_child_path_from_dir_key_plus_leaf() {
        let dir = TempDir::new().unwrap();
        let signing = fresh_signing_key(&dir);
        let drift_path = dir.path().join("drift.jsonl");
        let mut drift_db = FimDriftDb::open(
            &drift_path,
            signing,
            [0u8; 16],
            std::sync::Arc::new(crate::chainlog::NoProtection),
            crate::chainlog::RotationConfig::default(),
        )
        .unwrap();

        // A real watched DIRECTORY + a child dropped into it, so enroll
        // + re-hash operate on real inodes.
        let watched_dir = dir.path().join("systemd-system");
        std::fs::create_dir(&watched_dir).unwrap();
        let child = watched_dir.join("evil.service");
        std::fs::write(&child, b"[Service]\nExecStart=/tmp/x\n").unwrap();
        let dir_str = watched_dir.to_string_lossy().into_owned();

        // The pipeline shape: target is the DIR inode (arbitrary key
        // here), child leaf carried inline. NOT a pre-baked full path.
        let dir_key = InodeKey {
            dev: 0x1234,
            ino: 99,
        };
        let path_map = InodePathMap::new();
        path_map.insert(dir_key, dir_str.clone());

        let mut raw = fake_raw(dir_key.dev, dir_key.ino, FimOp::Created as u8);
        let leaf = b"evil.service";
        raw.child_name[..leaf.len()].copy_from_slice(leaf);

        let classifier = DriftClassifier::new();
        let rate_limiter = DriftRateLimiter::new();
        let mut out: Vec<Event> = Vec::new();
        let emitted = process_drift(
            &raw,
            &path_map,
            None,
            &mut drift_db,
            &classifier,
            &rate_limiter,
            None,
            None,
            Some(&mut out),
        )
        .unwrap();

        assert!(emitted, "a drop into a watched dir must emit");
        let ev = match out.remove(0) {
            Event::Fim(fe) => fe,
            other => panic!("expected Event::Fim, got {other:?}"),
        };
        assert_eq!(ev.path, format!("{dir_str}/evil.service"));
        assert_eq!(ev.op, FimOp::Created, "create/rename into dir → Created");
        assert!(!ev.child_truncated);
        // On-the-fly enroll: the dropped child is now resolvable by its
        // own inode, so a later in-place edit (write-then-close) lands.
        let child_key = key_for_path(&child).unwrap();
        assert!(
            path_map.lookup(&child_key).is_some(),
            "dropped child must be enrolled into the InodePathMap"
        );
    }

    /// Review 58: the create event of a dropped child can be handled before
    /// the file exists at its final path; the child waits and is enrolled
    /// once it appears.
    #[test]
    fn child_handled_before_it_exists_is_enrolled_when_it_appears() {
        let dir = TempDir::new().unwrap();
        let signing = fresh_signing_key(&dir);
        let mut drift_db = FimDriftDb::open(
            &dir.path().join("drift.jsonl"),
            signing,
            [0u8; 16],
            std::sync::Arc::new(crate::chainlog::NoProtection),
            crate::chainlog::RotationConfig::default(),
        )
        .unwrap();
        let watched_dir = dir.path().join("cron.d");
        std::fs::create_dir(&watched_dir).unwrap();
        let dir_key = InodeKey { dev: 0x77, ino: 7 };
        let path_map = InodePathMap::new();
        path_map.insert(dir_key, watched_dir.to_string_lossy().into_owned());
        let mut raw = fake_raw(dir_key.dev, dir_key.ino, FimOp::Created as u8);
        let leaf = b"late-drop";
        raw.child_name[..leaf.len()].copy_from_slice(leaf);
        process_drift(
            &raw,
            &path_map,
            None,
            &mut drift_db,
            &DriftClassifier::new(),
            &DriftRateLimiter::new(),
            None,
            None,
            None,
        )
        .unwrap();
        // The file appears only now: the retry enrolls it.
        let child = watched_dir.join("late-drop");
        std::fs::write(&child, b"* * * * * root true\n").unwrap();
        let key = key_for_path(&child).unwrap();
        assert!(path_map.lookup(&key).is_none());
        retry_pending_enrollments(&path_map, None);
        assert_eq!(
            path_map.lookup(&key).as_deref(),
            Some(child.to_string_lossy().as_ref()),
            "the late child must be enrolled by the retry"
        );
    }

    /// Review 57: a Deleted event for a file that is gone forgets its inode
    /// (the filesystem reuses the number for unrelated files); one for a
    /// file still in place (refused unlink, another hard link) keeps it.
    #[test]
    fn deleted_watched_file_forgets_its_inode_only_when_gone() {
        let dir = TempDir::new().unwrap();
        let signing = fresh_signing_key(&dir);
        let mut drift_db = FimDriftDb::open(
            &dir.path().join("drift.jsonl"),
            signing,
            [0u8; 16],
            std::sync::Arc::new(crate::chainlog::NoProtection),
            crate::chainlog::RotationConfig::default(),
        )
        .unwrap();
        let classifier = DriftClassifier::new();
        let rate_limiter = DriftRateLimiter::new();
        let path_map = InodePathMap::new();

        let kept = dir.path().join("still-here.conf");
        std::fs::write(&kept, b"x").unwrap();
        let kept_key = key_for_path(&kept).unwrap();
        path_map.insert(kept_key, kept.to_string_lossy().into_owned());
        let gone = dir.path().join("dropped.conf");
        std::fs::write(&gone, b"y").unwrap();
        let gone_key = key_for_path(&gone).unwrap();
        path_map.insert(gone_key, gone.to_string_lossy().into_owned());
        std::fs::remove_file(&gone).unwrap();

        for key in [kept_key, gone_key] {
            let raw = fake_raw(key.dev, key.ino, FimOp::Deleted as u8);
            process_drift(
                &raw,
                &path_map,
                None,
                &mut drift_db,
                &classifier,
                &rate_limiter,
                None,
                None,
                None,
            )
            .unwrap();
        }
        assert!(
            path_map.lookup(&kept_key).is_some(),
            "a file still in place stays watched"
        );
        assert!(
            path_map.lookup(&gone_key).is_none(),
            "a deleted file's inode is forgotten"
        );
    }

    /// BUG-022 #2 — a truncated child leaf (kernel filled the buffer +
    /// set the flag for a >63-byte name) sets `FimEvent::child_truncated`
    /// so the suffix-rules (FIM-021/023) still fire when the extension
    /// was lost to truncation. Again: driven by the wire record, not a
    /// synthetic path.
    #[test]
    fn bug022_truncated_child_leaf_sets_event_flag() {
        let dir = TempDir::new().unwrap();
        let signing = fresh_signing_key(&dir);
        let drift_path = dir.path().join("drift.jsonl");
        let mut drift_db = FimDriftDb::open(
            &drift_path,
            signing,
            [0u8; 16],
            std::sync::Arc::new(crate::chainlog::NoProtection),
            crate::chainlog::RotationConfig::default(),
        )
        .unwrap();

        let dir_str = dir.path().to_string_lossy().into_owned();
        let dir_key = InodeKey {
            dev: 0x1234,
            ino: 7,
        };
        let path_map = InodePathMap::new();
        path_map.insert(dir_key, dir_str.clone());

        let mut raw = fake_raw(dir_key.dev, dir_key.ino, FimOp::Created as u8);
        // Whole buffer filled, no NUL, truncated flag set — the kernel's
        // shape for a leaf longer than the inline buffer.
        raw.child_name = [b'a'; common::wire::FIM_CHILD_NAME_LEN];
        raw.child_name_flags = FIM_CHILD_TRUNCATED;

        let classifier = DriftClassifier::new();
        let rate_limiter = DriftRateLimiter::new();
        let mut out: Vec<Event> = Vec::new();
        let emitted = process_drift(
            &raw,
            &path_map,
            None,
            &mut drift_db,
            &classifier,
            &rate_limiter,
            None,
            None,
            Some(&mut out),
        )
        .unwrap();

        assert!(emitted);
        let ev = match out.remove(0) {
            Event::Fim(fe) => fe,
            other => panic!("expected Event::Fim, got {other:?}"),
        };
        assert!(ev.child_truncated, "truncated leaf must flag the event");
        assert!(ev.path.starts_with(&format!("{dir_str}/")));
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

    /// External audit FIMR-005: a path a Critical rule guards is never
    /// throttled, whatever the op (a read is not drift).
    #[test]
    fn critical_rule_paths_are_never_throttled() {
        let c = DriftClassifier::new();
        let rl = DriftRateLimiter::new();
        for path in [
            "/usr/sbin/sshd",
            "/usr/bin/sudo",
            "/bin/login",
            "/usr/lib/x86_64-linux-gnu/libc.so.6",
            "/lib/modules/6.8.0/kernel/x.ko",
            "/usr/lib/x86_64-linux-gnu/security/pam_unix.so",
            "/etc/ld.so.preload",
            crate::fim::rules::HONEYPOT_PATHS[0],
        ] {
            for op in [
                FimOp::Modified,
                FimOp::Renamed,
                FimOp::Created,
                FimOp::Deleted,
            ] {
                assert_eq!(
                    c.classify(op, path),
                    DriftSeverity::Critical,
                    "{op:?} {path}"
                );
            }
        }
        // the buckets spent, a Critical drift still goes through
        while rl.try_consume(DriftSeverity::Medium).is_ok() {}
        while rl.try_consume(DriftSeverity::High).is_ok() {}
        assert!(rl
            .try_consume(c.classify(FimOp::Modified, "/usr/sbin/sshd"))
            .is_ok());
        assert_eq!(
            c.classify(FimOp::Opened, "/usr/sbin/sshd"),
            DriftSeverity::Medium
        );
    }

    #[test]
    fn classifier_assigns_provisional_severity() {
        let c = DriftClassifier::new();
        // Modified + Renamed → Medium (noisy under upgrades).
        assert_eq!(
            c.classify(FimOp::Modified, "/etc/ssh/sshd_config"),
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

    /// BUG-026 migration GATE: an existing on-disk **v1** `fim_drift.jsonl`
    /// line (legacy flat `FimDriftEntry`, NO `fmt_ver`) MUST still verify
    /// under the rotation-aware reader after the payload/envelope split —
    /// breaking files already on disk is the migration's main risk. Proven
    /// two ways: (1) byte-equality of the serialisations; (2) end-to-end
    /// verification of a REALLY-signed v1 line via
    /// `chainlog::verify_log_set::<FimDriftPayload>`.
    #[test]
    fn bug026_legacy_v1_drift_line_still_verifies() {
        use crate::chainlog::{verify_log_set, ChainLine};
        let dir = TempDir::new().unwrap();
        let key = fresh_signing_key(&dir);
        let pk = key.verifying_key();
        let agent_id = [7u8; 16];

        let draft = FimDriftDraft {
            path: "/etc/passwd".to_string(),
            op: FimOp::Modified,
            baseline_sha256: Some("aa".repeat(32)),
            new_sha256: Some("bb".repeat(32)),
            modifier_pid: 4242,
            modifier_uid: 0,
            modifier_comm: "evil".to_string(),
            severity: DriftSeverity::High,
            decision_engine_skipped: false,
            skip_reason: String::new(),
        };
        // A real legacy v1 line — built + signed EXACTLY as the old writer did.
        let legacy = build_signed_drift_entry(&draft, &key, &agent_id, GENESIS_PREV_HASH).unwrap();

        // (1) byte-equality: ChainLine<FimDriftPayload>{fmt_ver:None} with the
        // same field values serialises identically to the legacy entry.
        let envelope = ChainLine {
            payload: FimDriftPayload {
                ts: legacy.ts.clone(),
                path: legacy.path.clone(),
                op: legacy.op,
                baseline_sha256: legacy.baseline_sha256.clone(),
                new_sha256: legacy.new_sha256.clone(),
                modifier_pid: legacy.modifier_pid,
                modifier_uid: legacy.modifier_uid,
                modifier_comm: legacy.modifier_comm.clone(),
                severity: legacy.severity,
                decision_engine_skipped: legacy.decision_engine_skipped,
                skip_reason: legacy.skip_reason.clone(),
                agent_id: legacy.agent_id.clone(),
            },
            fmt_ver: None,
            prev_hash: legacy.prev_hash.clone(),
            entry_hash: legacy.entry_hash.clone(),
            agent_sig: legacy.agent_sig.clone(),
        };
        assert_eq!(
            serde_json::to_string(&envelope).unwrap(),
            serde_json::to_string(&legacy).unwrap(),
            "ChainLine<FimDriftPayload>{{fmt_ver:None}} must serialise byte-identically \
             to the legacy FimDriftEntry — else on-disk v1 lines stop verifying"
        );

        // (2) end-to-end: the really-signed legacy line verifies via the
        // rotation-aware reader (same hash pre-image ⇒ same digest ⇒ sig OK).
        let log = dir.path().join("fim_drift.jsonl");
        std::fs::write(
            &log,
            format!("{}\n", serde_json::to_string(&legacy).unwrap()),
        )
        .unwrap();
        let report = verify_log_set::<FimDriftPayload>(&log, &pk).unwrap();
        assert_eq!(report.total_records, 1);
    }

    // ── C4 test 7: process_drift skips path-unknown events ──────────

    #[test]
    fn process_drift_skips_when_inode_path_unknown() {
        let dir = TempDir::new().unwrap();
        let key = fresh_signing_key(&dir);
        let drift_path = dir.path().join("drift.jsonl");
        let mut drift_db = FimDriftDb::open(
            &drift_path,
            key,
            [0u8; 16],
            std::sync::Arc::new(crate::chainlog::NoProtection),
            crate::chainlog::RotationConfig::default(),
        )
        .unwrap();
        let path_map = InodePathMap::new(); // empty
        let classifier = DriftClassifier::new();
        let rate_limiter = DriftRateLimiter::new();
        let mut out: Vec<Event> = Vec::new();
        let raw = fake_raw(0x800002, 99, FimOp::Modified as u8);
        let emitted = process_drift(
            &raw,
            &path_map,
            None,
            &mut drift_db,
            &classifier,
            &rate_limiter,
            None,
            None,
            Some(&mut out),
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
        let mut drift_db = FimDriftDb::open(
            &drift_path,
            key,
            [0u8; 16],
            std::sync::Arc::new(crate::chainlog::NoProtection),
            crate::chainlog::RotationConfig::default(),
        )
        .unwrap();
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
        let mut out: Vec<Event> = Vec::new();
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
            None,
            None,
            Some(&mut out),
        )
        .unwrap();
        assert!(emitted, "real drift must emit Event::Fim");
        match out.remove(0) {
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

    /// External audit FIMR-004: a file renamed over a watched one (the
    /// kernel flags the replaced inode) is checked, once the rename lands,
    /// as a modification of the path: the new content against the
    /// baseline, attributed to the renamer — the event the rules guarding
    /// the path's content consume. The drift row is written through the
    /// drain's lock (FIMP-003).
    #[test]
    fn a_file_renamed_over_a_watched_one_is_checked_as_a_modification() {
        use std::os::unix::fs::MetadataExt;
        let dir = TempDir::new().unwrap();
        let drift_path = dir.path().join("drift.jsonl");
        let drift_db = parking_lot::Mutex::new(
            FimDriftDb::open(
                &drift_path,
                fresh_signing_key(&dir),
                [0u8; 16],
                std::sync::Arc::new(crate::chainlog::NoProtection),
                crate::chainlog::RotationConfig::default(),
            )
            .unwrap(),
        );
        let path_map = InodePathMap::new();
        let watched = dir.path().join("sshd");
        std::fs::write(&watched, b"the real binary").unwrap();
        let old = std::fs::metadata(&watched).unwrap();
        let watched_s = watched.to_string_lossy().to_string();
        path_map.insert(
            InodeKey {
                dev: old.dev(),
                ino: old.ino(),
            },
            watched_s.clone(),
        );
        let baseline = dummy_baseline(&watched_s, &hex::encode(Sha256::digest(b"the real binary")));
        // the trojan, prepared next to it and renamed over it
        let prepared = dir.path().join(".sshd.new");
        std::fs::write(&prepared, b"a trojan").unwrap();
        std::fs::rename(&prepared, &watched).unwrap();

        let mut raw = fake_raw(old.dev(), old.ino(), FimOp::Renamed as u8);
        raw.op_flags = FIM_RENAME_REPLACED;
        raw.modifier_pid = 4242;
        raw.modifier_comm = *b"mv\0\0\0\0\0\0\0\0\0\0\0\0\0\0";
        let (c, rl) = (DriftClassifier::new(), DriftRateLimiter::new());
        let mut out = Vec::new();
        process_drift(
            &raw,
            &path_map,
            None,
            &mut &drift_db,
            &c,
            &rl,
            None,
            None,
            Some(&mut out),
        )
        .unwrap();
        assert!(matches!(&out[..], [Event::Fim(fe)] if fe.op == FimOp::Renamed));

        let replaced: Vec<_> = replacement_raws()
            .into_iter()
            .filter(|r| r.modifier_pid == 4242)
            .collect();
        assert_eq!(replaced.len(), 1, "one check of the new file");
        let new = key_for_path(&watched).unwrap();
        assert_eq!(
            (replaced[0].target_dev, replaced[0].target_ino),
            (new.dev, new.ino)
        );
        let mut out = Vec::new();
        let emitted = process_drift(
            &replaced[0],
            &path_map,
            Some(&baseline),
            &mut &drift_db,
            &c,
            &rl,
            None,
            None,
            Some(&mut out),
        )
        .unwrap();
        assert!(emitted);
        match &out[..] {
            [Event::Fim(fe)] => {
                assert_eq!(fe.op, FimOp::Modified);
                assert_eq!(fe.path, watched_s);
                assert_eq!(fe.modifier_pid, 4242);
                assert_eq!(fe.modifier_comm, "mv");
                assert_eq!(fe.new_sha256, Some(Sha256::digest(b"a trojan").into()));
            }
            other => panic!("{other:?}"),
        }
        let rows = std::fs::read_to_string(&drift_path).unwrap();
        assert_eq!(rows.lines().count(), 2, "the rename and the modification");
    }

    /// External audit FIMP-003: an event that happened before a hash of
    /// its path began is answered by that hash; a later one hashes again.
    #[test]
    fn an_event_before_the_last_hash_of_its_path_reuses_it() {
        let dir = TempDir::new().unwrap();
        let f = dir.path().join("big.log");
        let p = f.to_string_lossy().to_string();
        std::fs::write(&f, b"first").unwrap();
        let before = monotonic_ns();
        let first = content_after(&p, before).unwrap();
        std::fs::write(&f, b"second").unwrap();
        // an event older than the hash (by more than the margin) is the
        // same file the hash read
        let old_event = before.saturating_sub(10 * HASH_REUSE_MARGIN_NS);
        assert_eq!(content_after(&p, old_event).unwrap(), first);
        // an event since: read again
        let now = content_after(&p, monotonic_ns()).unwrap();
        assert_eq!(now.0, hex::encode(Sha256::digest(b"second")));
        // within the margin: read again too (the hook fires before the change)
        std::fs::write(&f, b"third").unwrap();
        let recent = content_after(&p, monotonic_ns()).unwrap();
        assert_eq!(recent.0, hex::encode(Sha256::digest(b"third")));
    }

    /// External audit FIMP-004: re-enrolling a path watches the inode it
    /// holds now and forgets the ones it held — a replaced file, a path
    /// that appeared since boot.
    #[test]
    fn reenrolling_a_path_watches_its_current_inode_only() {
        let dir = TempDir::new().unwrap();
        let map = InodePathMap::new();
        let f = dir.path().join("sshd_config");
        let fs_ = f.to_string_lossy().to_string();
        assert!(!reenroll_path(&fs_, &map, None), "nothing there yet");
        std::fs::write(&f, b"a").unwrap();
        assert!(reenroll_path(&fs_, &map, None), "appeared since boot");
        let old_key = key_for_path(&f).unwrap();
        assert_eq!(map.lookup(&old_key), Some(fs_.clone()));
        let tmp = dir.path().join("sshd_config.new");
        std::fs::write(&tmp, b"b").unwrap();
        std::fs::rename(&tmp, &f).unwrap();
        assert!(reenroll_path(&fs_, &map, None));
        let new_key = key_for_path(&f).unwrap();
        assert_eq!(map.lookup(&new_key), Some(fs_.clone()));
        assert_eq!(map.lookup(&old_key), None, "the old inode forgotten");
        assert_eq!(map.keys_for_path(&fs_), vec![new_key]);
    }

    /// External audit FIMP-005: a watched file renamed away stops
    /// resolving to the watched path; a file renamed over the watched
    /// path is watched in its place.
    #[test]
    fn renamed_watched_file_stops_resolving_to_old_path() {
        let dir = TempDir::new().unwrap();
        let mut drift_db = FimDriftDb::open(
            &dir.path().join("drift.jsonl"),
            fresh_signing_key(&dir),
            [0u8; 16],
            std::sync::Arc::new(crate::chainlog::NoProtection),
            crate::chainlog::RotationConfig::default(),
        )
        .unwrap();
        let path_map = InodePathMap::new();
        let watched = dir.path().join("authorized_keys");
        std::fs::write(&watched, b"ssh-ed25519 AAAA admin\n").unwrap();
        let old = key_for_path(&watched).unwrap();
        let watched_str = watched.to_string_lossy().to_string();
        path_map.insert(old, watched_str.clone());

        // mv authorized_keys authorized_keys.bak
        std::fs::rename(&watched, dir.path().join("authorized_keys.bak")).unwrap();
        let raw = fake_raw(old.dev, old.ino, FimOp::Renamed as u8);
        let _ = process_drift(
            &raw,
            &path_map,
            None,
            &mut drift_db,
            &DriftClassifier::new(),
            &DriftRateLimiter::new(),
            None,
            None,
            None,
        );
        assert_eq!(
            path_map.lookup(&old),
            None,
            "the moved inode is no longer the watched path"
        );

        // Moved back: the file is watched again (and drift-checked as a
        // creation) once the drain looks for returns.
        assert!(AWAITING_RETURN.lock().unwrap().contains(&watched_str));
        std::fs::rename(dir.path().join("authorized_keys.bak"), &watched).unwrap();
        let back = key_for_path(&watched).unwrap();
        assert!(returned_paths(&path_map, None).contains(&back));
        assert_eq!(
            path_map.lookup(&back).as_deref(),
            Some(watched_str.as_str())
        );
        assert!(!AWAITING_RETURN.lock().unwrap().contains(&watched_str));
        let raw = returned_raw(back);
        assert_eq!(raw.op, FimOp::Created as u8);
        assert_eq!((raw.target_dev, raw.target_ino), (back.dev, back.ino));
        // Away again, for the rename-over case below.
        std::fs::rename(&watched, dir.path().join("authorized_keys.bak")).unwrap();
        let raw = fake_raw(back.dev, back.ino, FimOp::Renamed as u8);
        let _ = process_drift(
            &raw,
            &path_map,
            None,
            &mut drift_db,
            &DriftClassifier::new(),
            &DriftRateLimiter::new(),
            None,
            None,
            None,
        );

        // A new file renamed over the watched path is watched in its place.
        let fresh = dir.path().join("authorized_keys.new");
        std::fs::write(&fresh, b"ssh-ed25519 BBBB admin\n").unwrap();
        std::fs::write(&watched, b"placeholder\n").unwrap();
        let placeholder = key_for_path(&watched).unwrap();
        path_map.insert(placeholder, watched_str.clone());
        std::fs::rename(&fresh, &watched).unwrap();
        let new = key_for_path(&watched).unwrap();
        let raw = fake_raw(placeholder.dev, placeholder.ino, FimOp::Renamed as u8);
        let _ = process_drift(
            &raw,
            &path_map,
            None,
            &mut drift_db,
            &DriftClassifier::new(),
            &DriftRateLimiter::new(),
            None,
            None,
            None,
        );
        assert_eq!(path_map.lookup(&placeholder), None);
        assert_eq!(path_map.lookup(&new).as_deref(), Some(watched_str.as_str()));
    }

    /// External audit FIMP-005: the hook fires before the rename lands; a
    /// drain that runs first keeps the inode, and the retry settles it.
    #[test]
    fn rename_seen_before_it_lands_is_settled_by_the_retry() {
        let dir = TempDir::new().unwrap();
        let mut drift_db = FimDriftDb::open(
            &dir.path().join("drift.jsonl"),
            fresh_signing_key(&dir),
            [0u8; 16],
            std::sync::Arc::new(crate::chainlog::NoProtection),
            crate::chainlog::RotationConfig::default(),
        )
        .unwrap();
        let path_map = InodePathMap::new();
        let watched = dir.path().join("sshd_config");
        std::fs::write(&watched, b"PermitRootLogin no\n").unwrap();
        let key = key_for_path(&watched).unwrap();
        path_map.insert(key, watched.to_string_lossy().to_string());
        let raw = fake_raw(key.dev, key.ino, FimOp::Renamed as u8);
        let _ = process_drift(
            &raw,
            &path_map,
            None,
            &mut drift_db,
            &DriftClassifier::new(),
            &DriftRateLimiter::new(),
            None,
            None,
            None,
        );
        assert!(
            path_map.lookup(&key).is_some(),
            "not moved yet: still watched"
        );
        std::fs::rename(&watched, dir.path().join("sshd_config.orig")).unwrap();
        retry_pending_enrollments(&path_map, None);
        assert_eq!(path_map.lookup(&key), None);
    }

    /// External audit FIMP-006: a drift log that cannot be written must not
    /// keep the event from the rules.
    #[test]
    fn drift_append_failure_still_emits_event() {
        let dir = TempDir::new().unwrap();
        let drift_path = dir.path().join("drift.jsonl");
        let mut drift_db = FimDriftDb::open(
            &drift_path,
            fresh_signing_key(&dir),
            [0u8; 16],
            std::sync::Arc::new(crate::chainlog::NoProtection),
            crate::chainlog::RotationConfig::default(),
        )
        .unwrap();
        // Every append now fails (EISDIR), whoever runs the test.
        let _ = std::fs::remove_file(&drift_path);
        std::fs::create_dir(&drift_path).unwrap();

        let path_map = InodePathMap::new();
        let watched = dir.path().join("watched.bin");
        std::fs::write(&watched, b"the new content").unwrap();
        let key = key_for_path(&watched).unwrap();
        path_map.insert(key, watched.to_string_lossy().to_string());
        let stale = dummy_baseline(&watched.to_string_lossy(), &"99".repeat(32));
        let mut out: Vec<Event> = Vec::new();
        let emitted = process_drift(
            &fake_raw(key.dev, key.ino, FimOp::Modified as u8),
            &path_map,
            Some(&stale),
            &mut drift_db,
            &DriftClassifier::new(),
            &DriftRateLimiter::new(),
            None,
            None,
            Some(&mut out),
        )
        .expect("an unwritable drift log is not a processing error");
        assert!(emitted);
        assert!(matches!(out.first(), Some(Event::Fim(_))), "{out:?}");
    }

    // ── C4 test 9: process_drift on no-real-drift skips silently ────

    #[test]
    fn process_drift_silently_skips_when_sha_matches_baseline() {
        let dir = TempDir::new().unwrap();
        let key = fresh_signing_key(&dir);
        let drift_path = dir.path().join("drift.jsonl");
        let mut drift_db = FimDriftDb::open(
            &drift_path,
            key,
            [0u8; 16],
            std::sync::Arc::new(crate::chainlog::NoProtection),
            crate::chainlog::RotationConfig::default(),
        )
        .unwrap();
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
        let mut out: Vec<Event> = Vec::new();
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
            None,
            None,
            Some(&mut out),
        )
        .unwrap();
        assert!(!emitted, "no-op drift (hash matches) must not emit");
        assert!(out.is_empty(), "no event must be sent");
        // Drift log also empty — no point recording a no-op.
        assert!(!drift_path.exists() || std::fs::read_to_string(&drift_path).unwrap().is_empty());
    }

    // ── C4 test 10: rate-limited drift still records to audit chain ─

    #[test]
    fn process_drift_rate_limited_records_audit_chain_with_skipped_flag() {
        let dir = TempDir::new().unwrap();
        let key = fresh_signing_key(&dir);
        let drift_path = dir.path().join("drift.jsonl");
        let mut drift_db = FimDriftDb::open(
            &drift_path,
            key,
            [0u8; 16],
            std::sync::Arc::new(crate::chainlog::NoProtection),
            crate::chainlog::RotationConfig::default(),
        )
        .unwrap();
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
        let mut out: Vec<Event> = Vec::new();
        let raw = fake_raw(
            watched_meta.dev(),
            watched_meta.ino(),
            FimOp::Modified as u8,
        );
        // The writer descends from dpkg: the only drift the buckets pace
        // (review 76).
        let lineage = AuthSessionTracker::new(dir.path().join("no-proc"));
        lineage.ingest_spawn(raw.modifier_pid, 1, "/usr/bin/dpkg", 0);
        let emitted = process_drift(
            &raw,
            &path_map,
            Some(&stale_baseline),
            &mut drift_db,
            &classifier,
            &rate_limiter,
            None,
            Some(&lineage),
            Some(&mut out),
        )
        .unwrap();
        assert!(!emitted, "throttled drift must NOT emit Event::Fim");
        assert!(out.is_empty(), "no event must be sent");
        // BUT drift log MUST contain the row with skipped flag.
        let body = std::fs::read_to_string(&drift_path).unwrap();
        assert_eq!(body.lines().count(), 1);
        let row: FimDriftEntry = serde_json::from_str(body.trim_end()).unwrap();
        assert!(row.decision_engine_skipped, "audit chain MUST record");
        assert_eq!(row.skip_reason, "rate_limit:tier_medium");
    }

    /// Review 76: spent buckets no longer let any other writer skip the
    /// rules. Root wrote 60 throwaway files in /etc/cron.d, and the real
    /// drop-in after them never reached NN-L-FIM-007.
    #[test]
    fn process_drift_never_throttles_a_writer_outside_the_package_manager() {
        let dir = TempDir::new().unwrap();
        let key = fresh_signing_key(&dir);
        let drift_path = dir.path().join("drift.jsonl");
        let mut drift_db = FimDriftDb::open(
            &drift_path,
            key,
            [0u8; 16],
            std::sync::Arc::new(crate::chainlog::NoProtection),
            crate::chainlog::RotationConfig::default(),
        )
        .unwrap();
        let path_map = InodePathMap::new();
        let watched = dir.path().join("watched.bin");
        std::fs::write(&watched, b"new content").unwrap();
        let watched_meta = std::fs::metadata(&watched).unwrap();
        use std::os::unix::fs::MetadataExt;
        path_map.insert(
            InodeKey {
                dev: watched_meta.dev(),
                ino: watched_meta.ino(),
            },
            watched.to_string_lossy().to_string(),
        );
        let stale_baseline = dummy_baseline(&watched.to_string_lossy(), &"99".repeat(32));
        // Both buckets empty, as after a burst of throwaway writes.
        let rate_limiter = DriftRateLimiter::with_caps(0, 0);
        // The writer is a shell under sshd, not a package manager.
        let lineage = AuthSessionTracker::new(dir.path().join("no-proc"));
        let mut raw = fake_raw(
            watched_meta.dev(),
            watched_meta.ino(),
            FimOp::Modified as u8,
        );
        raw.modifier_comm = *b"sh\0\0\0\0\0\0\0\0\0\0\0\0\0\0";
        lineage.ingest_spawn(raw.modifier_pid, 4000, "/usr/bin/dash", 0);
        lineage.ingest_spawn(4000, 1, "/usr/sbin/sshd", 0);
        let mut out: Vec<Event> = Vec::new();
        let emitted = process_drift(
            &raw,
            &path_map,
            Some(&stale_baseline),
            &mut drift_db,
            &DriftClassifier::new(),
            &rate_limiter,
            None,
            Some(&lineage),
            Some(&mut out),
        )
        .unwrap();
        assert!(emitted, "the drift must reach the rules");
        assert_eq!(out.len(), 1);
        let body = std::fs::read_to_string(&drift_path).unwrap();
        let row: FimDriftEntry = serde_json::from_str(body.trim_end()).unwrap();
        assert!(!row.decision_engine_skipped);
        assert!(row.skip_reason.is_empty());
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
            let mut drift_db = FimDriftDb::open(
                &drift_path,
                key,
                [0u8; 16],
                std::sync::Arc::new(crate::chainlog::NoProtection),
                crate::chainlog::RotationConfig::default(),
            )
            .unwrap();
            let (_on_disk, key_ino, path_map) = make_watched_alias(&dir, path);
            let classifier = DriftClassifier::new();
            let rate_limiter = DriftRateLimiter::new();
            let mut out: Vec<Event> = Vec::new();
            let raw = fake_raw(key_ino.dev, key_ino.ino, FimOp::Opened as u8);

            let emitted = process_drift(
                &raw,
                &path_map,
                None,
                &mut drift_db,
                &classifier,
                &rate_limiter,
                None,
                None,
                Some(&mut out),
            )
            .unwrap();

            assert!(!emitted, "{path}: Opened must yield zero drift");
            assert!(
                out.is_empty(),
                "{path}: no Event::Fim → main.rs logs no 'FIM DRIFT' WARN"
            );
            assert!(
                !drift_path.exists() || std::fs::read_to_string(&drift_path).unwrap().is_empty(),
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
        let mut drift_db = FimDriftDb::open(
            &drift_path,
            key,
            [0u8; 16],
            std::sync::Arc::new(crate::chainlog::NoProtection),
            crate::chainlog::RotationConfig::default(),
        )
        .unwrap();
        let (_on_disk, key_ino, path_map) = make_watched_alias(&dir, "/root/.aws/credentials");
        let classifier = DriftClassifier::new();
        let rate_limiter = DriftRateLimiter::new();
        let mut out: Vec<Event> = Vec::new();
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
            None,
            None,
            Some(&mut out),
        )
        .unwrap();

        assert!(emitted, "cred-path Opened MUST forward to the rule engine");
        // SILENT: forwarded but NOT recorded as drift.
        assert!(
            !drift_path.exists() || std::fs::read_to_string(&drift_path).unwrap().is_empty(),
            "cred-path read MUST NOT append to fim_drift.jsonl (no 'FIM DRIFT' noise)"
        );

        assert_eq!(out.len(), 1, "Event::Fim must be sent for cred-path read");
        let ev = out.remove(0);
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
        let mut drift_db = FimDriftDb::open(
            &drift_path,
            key,
            [0u8; 16],
            std::sync::Arc::new(crate::chainlog::NoProtection),
            crate::chainlog::RotationConfig::default(),
        )
        .unwrap();
        let (on_disk, key_ino, path_map) = make_watched_alias(&dir, "/etc/passwd");
        // Mutate the file so a real-drift hash-diff is observed.
        std::fs::write(&on_disk, b"MUTATED content").unwrap();

        let classifier = DriftClassifier::new();
        let rate_limiter = DriftRateLimiter::new();
        let mut out: Vec<Event> = Vec::new();
        let stale_baseline = dummy_baseline("/etc/passwd", &"42".repeat(32));
        let raw = fake_raw(key_ino.dev, key_ino.ino, FimOp::Modified as u8);

        let emitted = process_drift(
            &raw,
            &path_map,
            Some(&stale_baseline),
            &mut drift_db,
            &classifier,
            &rate_limiter,
            None,
            None,
            Some(&mut out),
        )
        .unwrap();
        assert!(emitted, "Modified on /etc/passwd MUST still fire");
        match out.remove(0) {
            Event::Fim(fe) => {
                assert_eq!(fe.path, "/etc/passwd");
                assert_eq!(fe.op, FimOp::Modified);
            }
            other => panic!("expected Event::Fim, got {other:?}"),
        }
    }
}
