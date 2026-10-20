//! Tappa 9 (C4) — FIM drift drain loop + path resolve + diff +
//! `Event::Fim` emit.
//!
//! Bridges C2's kernel-side `FS_FIM_EVENTS` ringbuf to the
//! agent's existing `Event` channel that the decision engine
//! consumes. Per design §6.3 + §6.5:
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
//!    written in a package transaction (review 76: only there; any
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
use std::sync::{Arc, LazyLock, OnceLock};
use std::time::{Duration, Instant};

use anyhow::{anyhow, Context, Result};
use chrono::{DateTime, Utc};
use common::wire::{
    FileAttrChange, FimDriftRaw, FimEvent, FimOp, InodeKey, FIM_CHILD_NAME_LEN,
    FIM_CHILD_TRUNCATED, FIM_RENAME_DEST_LEAF, FIM_RENAME_REPLACED,
};
use common::Event;
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;

use crate::posture::lineage::AuthSessionTracker;
// The drain's synchronous work (hashing, the drift log, `/proc` reads)
// runs where it does not hold up the runtime's other tasks.
use crate::runtime::off_the_runtime;
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

/// External audit NN-AUD-120 (FIMP-008): why an inode is watched. Only a
/// runtime child is ever evicted; the others are what the operator
/// configured or deployed, and a full map must not cost them their watch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WatchClass {
    /// A file dropped into a watched directory, enrolled at runtime
    /// (BUG-022). At most [`RUNTIME_CHILD_CAP`]; the oldest makes room.
    RuntimeChild,
    /// A link or the final target behind a symlinked watched path,
    /// named by that path (NN-AUD-122).
    ChainHop,
    /// A canary decoy (DEC-001).
    Decoy,
    /// A path of the watch list — at boot, re-baselined, or back after a
    /// rename — or one of the agent's control-surface baits.
    Configured,
}

impl WatchClass {
    /// Which class keeps an inode claimed twice: a runtime child never
    /// takes over a hop, a hop never takes over a configured path or a
    /// decoy.
    fn rank(self) -> u8 {
        match self {
            Self::RuntimeChild => 0,
            Self::ChainHop => 1,
            Self::Decoy | Self::Configured => 2,
        }
    }
}

/// External audit NN-AUD-120 (FIMP-008): the most runtime children watched
/// at once — half of `WATCHED_PATHS`, the rest kept for the configured
/// paths, the symlink hops, the decoys and the re-baselines. Every new
/// child of a watched directory used to take a slot for good (a lost
/// Deleted event, a directory removed with its files), and a full map
/// refused even a canary decoy with only a WARN.
pub const RUNTIME_CHILD_CAP: usize = crate::fim::attach::WATCHED_PATHS_CAPACITY / 2;

/// Userland `(dev, ino)` → absolute path resolver. Populated at boot from
/// the watch list ([`crate::fim::attach::populate_watched_paths`]) and at
/// runtime by the drain (children of watched directories, renames,
/// re-baselines) and the canaries; consulted by [`process_drift`] to turn
/// a kernel-side `FimDriftRaw` into a userland [`FimEvent`] with an
/// absolute path. Each inode carries its [`WatchClass`]; runtime children
/// are kept within a cap, oldest out first.
#[derive(Debug)]
pub struct InodePathMap {
    inner: parking_lot::RwLock<PathMapInner>,
    child_cap: usize,
}

#[derive(Debug, Default)]
struct PathMapInner {
    entries: HashMap<InodeKey, Watched>,
    /// Runtime children, oldest first. A key removed or re-classed since
    /// stays until it reaches the front (skipped there) or a compaction.
    children: std::collections::VecDeque<InodeKey>,
    child_count: usize,
    /// External audit NN-AUD-122: the hop inodes watched behind each
    /// symlinked path.
    chains: HashMap<String, Vec<InodeKey>>,
}

#[derive(Debug, Clone)]
struct Watched {
    path: String,
    class: WatchClass,
}

impl PathMapInner {
    /// Take the oldest runtime child other than `except` out of the map.
    fn take_oldest_child(&mut self, except: Option<InodeKey>) -> Option<(InodeKey, String)> {
        let mut i = 0;
        while i < self.children.len() {
            let k = self.children[i];
            let live =
                matches!(self.entries.get(&k), Some(w) if w.class == WatchClass::RuntimeChild);
            if !live {
                self.children.remove(i);
                continue;
            }
            if Some(k) == except {
                i += 1;
                continue;
            }
            self.children.remove(i);
            let w = self.entries.remove(&k)?;
            self.child_count -= 1;
            return Some((k, w.path));
        }
        None
    }

    /// Drop the queue's dead and repeated keys once it is twice the cap.
    fn compact_children(&mut self, cap: usize) {
        if self.children.len() <= 2 * cap.max(16) {
            return;
        }
        let entries = &self.entries;
        let mut seen = std::collections::HashSet::new();
        self.children.retain(|k| {
            matches!(entries.get(k), Some(w) if w.class == WatchClass::RuntimeChild)
                && seen.insert(*k)
        });
    }
}

impl Default for InodePathMap {
    fn default() -> Self {
        Self::with_child_cap(RUNTIME_CHILD_CAP)
    }
}

impl InodePathMap {
    /// Empty map, with the [`RUNTIME_CHILD_CAP`].
    pub fn new() -> Self {
        Self::default()
    }

    /// Empty map holding at most `child_cap` runtime children.
    pub fn with_child_cap(child_cap: usize) -> Self {
        Self {
            inner: parking_lot::RwLock::new(PathMapInner::default()),
            child_cap,
        }
    }

    /// Map a configured path: [`Self::insert_as`] with
    /// [`WatchClass::Configured`].
    pub fn insert(&self, key: InodeKey, path: String) {
        let _ = self.insert_as(key, path, WatchClass::Configured);
    }

    /// Map `key` to `path` as `class`. An inode already held by a class
    /// that outranks `class` keeps its path and class. Returns the runtime
    /// child evicted to keep within the cap (the caller stops the kernel
    /// watching it), if any.
    pub fn insert_as(
        &self,
        key: InodeKey,
        path: String,
        class: WatchClass,
    ) -> Option<(InodeKey, String)> {
        let mut g = self.inner.write();
        let inner = &mut *g;
        if let Some(cur) = inner.entries.get(&key).map(|w| w.class) {
            if cur.rank() > class.rank() {
                return None;
            }
            if cur == WatchClass::RuntimeChild && class != WatchClass::RuntimeChild {
                inner.child_count -= 1;
            }
            inner.entries.insert(key, Watched { path, class });
            return None;
        }
        inner.entries.insert(key, Watched { path, class });
        if class != WatchClass::RuntimeChild {
            return None;
        }
        inner.child_count += 1;
        inner.children.push_back(key);
        let evicted = if inner.child_count > self.child_cap {
            inner.take_oldest_child(Some(key))
        } else {
            None
        };
        inner.compact_children(self.child_cap);
        evicted
    }

    /// Look up a path by inode key. Returns owned `String` so
    /// the read lock is dropped immediately — avoids holding a
    /// read lock across the (slow) baseline rehash that follows.
    pub fn lookup(&self, key: &InodeKey) -> Option<String> {
        self.inner.read().entries.get(key).map(|w| w.path.clone())
    }

    /// Why `key` is watched.
    pub fn class_of(&self, key: &InodeKey) -> Option<WatchClass> {
        self.inner.read().entries.get(key).map(|w| w.class)
    }

    /// Forget an inode whose file is gone (review 57).
    pub fn remove(&self, key: &InodeKey) {
        let mut g = self.inner.write();
        if let Some(w) = g.entries.remove(key) {
            if w.class == WatchClass::RuntimeChild {
                g.child_count -= 1;
            }
        }
    }

    /// Every inode mapped to `path` as its own file (external audit
    /// FIMP-004: a path whose file was replaced may still hold its old
    /// inode's entry). The links and target behind a symlinked path,
    /// named by it too, are not its own (see [`Self::chain`]).
    pub fn keys_for_path(&self, path: &str) -> Vec<InodeKey> {
        self.inner
            .read()
            .entries
            .iter()
            .filter(|(_, w)| w.path == path && w.class != WatchClass::ChainHop)
            .map(|(k, _)| *k)
            .collect()
    }

    /// Take the oldest runtime child other than `except` out of the map
    /// (to make room in a full kernel map).
    pub fn evict_oldest_child(&self, except: Option<InodeKey>) -> Option<(InodeKey, String)> {
        self.inner.write().take_oldest_child(except)
    }

    /// The runtime children, for the periodic sweep of those gone.
    pub fn runtime_children(&self) -> Vec<(InodeKey, String)> {
        self.inner
            .read()
            .entries
            .iter()
            .filter(|(_, w)| w.class == WatchClass::RuntimeChild)
            .map(|(k, w)| (*k, w.path.clone()))
            .collect()
    }

    /// How many runtime children are mapped.
    pub fn child_count(&self) -> usize {
        self.inner.read().child_count
    }

    /// The most runtime children this map keeps.
    pub fn child_cap(&self) -> usize {
        self.child_cap
    }

    /// External audit NN-AUD-122: record the hop inodes watched behind
    /// `owner`.
    pub fn set_chain(&self, owner: &str, keys: Vec<InodeKey>) {
        self.inner.write().chains.insert(owner.to_string(), keys);
    }

    /// The hop inodes watched behind `owner`.
    pub fn chain(&self, owner: &str) -> Vec<InodeKey> {
        self.inner
            .read()
            .chains
            .get(owner)
            .cloned()
            .unwrap_or_default()
    }

    /// `key` is no longer behind `owner`. Another watched link still
    /// passing through it keeps it (named by that link); otherwise the
    /// entry goes and `true` tells the caller to stop the kernel watching
    /// it. Never touches an entry of another class.
    pub fn release_hop(&self, owner: &str, key: InodeKey) -> bool {
        let mut g = self.inner.write();
        if !matches!(g.entries.get(&key), Some(w) if w.class == WatchClass::ChainHop) {
            return false;
        }
        let other = g
            .chains
            .iter()
            .find(|(o, keys)| o.as_str() != owner && keys.contains(&key))
            .map(|(o, _)| o.clone());
        match other {
            Some(o) => {
                g.entries.insert(
                    key,
                    Watched {
                        path: o,
                        class: WatchClass::ChainHop,
                    },
                );
                false
            }
            None => {
                g.entries.remove(&key);
                true
            }
        }
    }

    /// Number of mapped inodes. Useful for `nn-admin fim
    /// status` (C6) summary output.
    pub fn len(&self) -> usize {
        self.inner.read().entries.len()
    }

    /// True if no inodes are mapped (fresh boot, baseline
    /// hasn't run yet).
    pub fn is_empty(&self) -> bool {
        self.inner.read().entries.is_empty()
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
            // Wave 2 (TST-004): a permission or ownership change is
            // rarer than a content change and as telling.
            FimOp::AttrChanged => DriftSeverity::High,
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
/// — sub-millisecond contention even under burst load. A
/// `parking_lot::Mutex`, for fairness and no poisoning: a panic
/// while it was held cannot turn every later drift into a second
/// one (external audit NN-AUD-293 FIMP-014: it was a
/// `std::sync::Mutex` with `.expect("… poisoned")` on each lock,
/// against this note).
pub struct DriftRateLimiter {
    state: parking_lot::Mutex<BucketState>,
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
            state: parking_lot::Mutex::new(BucketState {
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
        let mut s = self.state.lock();
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
        let s = self.state.lock();
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
    /// Wave 2 (TST-004): mode, owner and group before and after, on an
    /// [`FimOp::AttrChanged`] row. Absent on every other row, so a line
    /// written before it existed serialises (and verifies) as it did.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attrs: Option<FileAttrChange>,
}

/// External audit EVD-008 (lab PR 204): the FIM drift log's name in its v3
/// pre-images.
impl crate::chainlog::ChainPayload for FimDriftPayload {
    const KIND: &'static str = "fim_drift";
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
    /// Wave 2 (TST-004): see [`FimDriftPayload::attrs`].
    pub attrs: Option<FileAttrChange>,
}

// ── drift DB (mirror BaselineDb) ───────────────────────────────────

/// Append-only writer for the drift log. BUG-026: now a thin wrapper
/// over the shared [`crate::chainlog::RotatingChainLog`] — it builds the
/// [`FimDriftPayload`] and the core handles chaining, signing, rotation
/// (size cap + retention), and the chattr dance via the shared
/// `StateDirProtection`. New lines are v3 (`fmt_ver`, lab PR 204); existing
/// v1 and v2 lines stay valid (see
/// `bug026_legacy_v1_drift_line_still_verifies`).
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
            attrs: draft.attrs,
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
/// (NUL-terminated), named by [`leaf_display`]. Returns `None` when the
/// leaf is empty, `.` or `..`, or contains a `/` — the kernel hands a
/// single dentry component, so a slash means a crafted / garbled record
/// (external audit NN-AUD-291: the VFS never hands `.` or `..` either;
/// refused all the same).
fn reconstruct_child_path(dir: &str, raw: &FimDriftRaw) -> Option<String> {
    let end = raw
        .child_name
        .iter()
        .position(|&b| b == 0)
        .unwrap_or(raw.child_name.len());
    let leaf = &raw.child_name[..end];
    if leaf.is_empty() || leaf == b"." || leaf == b".." || leaf.contains(&b'/') {
        return None;
    }
    Some(format!(
        "{}/{}",
        dir.trim_end_matches('/'),
        leaf_display(leaf)
    ))
}

/// External audit NN-AUD-291 (FIMP-012): a file name as the drain names it.
/// A UTF-8 name is itself. Any other is spelled with `\xNN` for each byte
/// that is not UTF-8 and `\\` for each backslash, so that two names stay
/// two and [`fs_path`] finds the file again. It was decoded lossily
/// (U+FFFD for each such byte): a name no file has, so the new file was
/// never watched — its later in-place edits went unseen — and its drift
/// row named a file that does not exist.
fn leaf_display(leaf: &[u8]) -> String {
    use std::fmt::Write as _;
    if let Ok(name) = std::str::from_utf8(leaf) {
        return name.to_string();
    }
    let mut out = String::with_capacity(leaf.len() * 2);
    for chunk in leaf.utf8_chunks() {
        for c in chunk.valid().chars() {
            if c == '\\' {
                out.push_str("\\\\");
            } else {
                out.push(c);
            }
        }
        for b in chunk.invalid() {
            let _ = write!(out, "\\x{b:02x}");
        }
    }
    out
}

/// External audit NN-AUD-291: the bytes of a name [`leaf_display`]
/// escaped; `None` for any other text. Only its exact spelling counts: a
/// name that decodes to UTF-8 is not one it escaped (a UTF-8 name is
/// itself, backslashes included — `mnt-data\x2dvol.mount`).
fn leaf_bytes(name: &str) -> Option<Vec<u8>> {
    if !name.contains('\\') {
        return None;
    }
    let text = name.as_bytes();
    let mut out = Vec::with_capacity(text.len());
    let mut i = 0;
    while i < text.len() {
        if text[i] != b'\\' {
            out.push(text[i]);
            i += 1;
            continue;
        }
        match text.get(i + 1) {
            Some(b'\\') => {
                out.push(b'\\');
                i += 2;
            }
            Some(b'x') => {
                let hex = name.get(i + 2..i + 4)?;
                out.push(u8::from_str_radix(hex, 16).ok()?);
                i += 4;
            }
            _ => return None,
        }
    }
    (std::str::from_utf8(&out).is_err() && leaf_display(&out) == name).then_some(out)
}

/// External audit NN-AUD-291: the file a path the drain names stands for.
/// Each component [`leaf_display`] escaped is turned back into its bytes —
/// unless a file is there under the name as written: a UTF-8 name may hold
/// the same characters, and that file is the one.
fn fs_path(path: &str) -> std::borrow::Cow<'_, Path> {
    use std::os::unix::ffi::OsStringExt;
    if !path.contains('\\') || std::fs::symlink_metadata(path).is_ok() {
        return std::borrow::Cow::Borrowed(Path::new(path));
    }
    let mut decoded = false;
    let mut out = Vec::with_capacity(path.len());
    for (i, component) in path.split('/').enumerate() {
        if i > 0 {
            out.push(b'/');
        }
        match leaf_bytes(component) {
            Some(bytes) => {
                decoded = true;
                out.extend_from_slice(&bytes);
            }
            None => out.extend_from_slice(component.as_bytes()),
        }
    }
    if decoded {
        std::borrow::Cow::Owned(std::ffi::OsString::from_vec(out).into())
    } else {
        std::borrow::Cow::Borrowed(Path::new(path))
    }
}

/// The drain's pending work, between events. External audit NN-AUD-119
/// (FIMP-007): every retry queue is keyed — one entry per path or inode —
/// and capped where it grows.
struct DrainQueues {
    /// Review 58: children whose create or rename event was handled
    /// before the file existed at its final path. The LSM hooks fire
    /// before the operation, and a fast drain used to `stat` too early and
    /// skip the enrollment for good, so the dropped file's later in-place
    /// edits went unseen. Retried for [`ENROLL_RETRY_FOR`]. NN-AUD-119: a
    /// burst of short-lived files grew this queue without bound, a path
    /// once per creation.
    enroll: RetryQueue<String, Instant>,
    /// External audit FIMP-005: watched inodes renamed away from their
    /// path, waiting for the rename to land (the LSM hook fires before
    /// it). See [`settle_rename`].
    rename: RetryQueue<InodeKey, PendingRename>,
    /// External audit NN-AUD-122 (FIMP-010): symlinked watched paths whose
    /// chain an event may have changed — a link or the target behind them
    /// unlinked, renamed or replaced — waiting for the change to land, with
    /// the event (its writer is the change's).
    chain: RetryQueue<String, (Instant, FimDriftRaw)>,
    /// See [`queue_replacement`].
    replacements: Vec<(String, FimDriftRaw)>,
    /// See [`settle_rename`] and [`returned_paths`].
    awaiting_return: Vec<(String, WatchClass)>,
    /// See [`await_chain_repair`].
    chain_awaiting: Vec<String>,
}

impl DrainQueues {
    fn new() -> Self {
        Self {
            enroll: RetryQueue::new("child enrollment", PENDING_MAX),
            rename: RetryQueue::new("rename", PENDING_MAX),
            chain: RetryQueue::new("symlink chain", PENDING_MAX),
            replacements: Vec::new(),
            awaiting_return: Vec::new(),
            chain_awaiting: Vec::new(),
        }
    }
}

#[cfg(not(test))]
static QUEUES: LazyLock<parking_lot::Mutex<DrainQueues>> =
    LazyLock::new(|| parking_lot::Mutex::new(DrainQueues::new()));

// Tests drive the drain functions in parallel, each with its own map: one
// set of queues per test thread, so one test's retry pass does not settle
// another's entries against the wrong map.
#[cfg(test)]
thread_local! {
    static QUEUES: std::cell::RefCell<DrainQueues> = std::cell::RefCell::new(DrainQueues::new());
}

/// Work on the drain's queues. External audit NN-AUD-119: never across a
/// `stat` — entries are taken out, worked on, and put back.
fn queues<R>(f: impl FnOnce(&mut DrainQueues) -> R) -> R {
    #[cfg(not(test))]
    {
        f(&mut QUEUES.lock())
    }
    #[cfg(test)]
    {
        QUEUES.with(|q| f(&mut q.borrow_mut()))
    }
}

const ENROLL_RETRY_FOR: Duration = Duration::from_secs(2);

/// External audit NN-AUD-119 (FIMP-007): the cap of each retry queue.
const PENDING_MAX: usize = 1024;

/// External audit NN-AUD-119 (FIMP-007): the retry pass runs at most this
/// often. It ran at the top of every loop turn — since review 75 after
/// every event that emits — so a burst of creations cost one `stat` per
/// queued entry per event, on the only reader of the FIM ring.
const RETRY_EVERY: Duration = Duration::from_millis(5);

/// A watched inode renamed away: its path, why it was watched, since when,
/// and — external audit FIMR-004 — the renamer's event when the rename put
/// another file over it.
#[derive(Debug, Clone)]
struct PendingRename {
    path: String,
    class: WatchClass,
    since: Instant,
    replaced: Option<FimDriftRaw>,
}

/// External audit NN-AUD-119 (FIMP-007): a retry queue keyed by what it
/// retries — one entry per key — with a hard cap applied where it grows.
/// An entry over the cap is dropped, counted, and reported (WARN, at most
/// once a minute): the pre-review-58 behaviour for that file, now visible.
struct RetryQueue<K, V> {
    name: &'static str,
    entries: HashMap<K, V>,
    cap: usize,
    dropped: u64,
    warned: Option<Instant>,
}

impl<K: Eq + std::hash::Hash, V> RetryQueue<K, V> {
    fn new(name: &'static str, cap: usize) -> Self {
        Self {
            name,
            entries: HashMap::new(),
            cap,
            dropped: 0,
            warned: None,
        }
    }

    /// Queue `value` under `key`; an entry already queued is merged with
    /// it (`merge(queued, new)`). `false` when the queue is full: the entry
    /// is dropped and counted.
    fn push_with(&mut self, key: K, value: V, merge: impl FnOnce(&mut V, V)) -> bool {
        if let Some(queued) = self.entries.get_mut(&key) {
            merge(queued, value);
            return true;
        }
        if self.entries.len() >= self.cap {
            self.overflow();
            return false;
        }
        self.entries.insert(key, value);
        true
    }

    /// Queue `value` under `key`; an entry already queued is kept as it is.
    fn push(&mut self, key: K, value: V) -> bool {
        self.push_with(key, value, |_, _| {})
    }

    /// Every entry, taken out of the queue to be worked on without its lock.
    fn take(&mut self) -> HashMap<K, V> {
        std::mem::take(&mut self.entries)
    }

    /// Put back the entries still pending after a pass. One queued since
    /// is kept as it is; the cap holds.
    fn put_back(&mut self, pending: impl IntoIterator<Item = (K, V)>) {
        for (k, v) in pending {
            if !self.entries.contains_key(&k) && self.entries.len() >= self.cap {
                self.overflow();
                continue;
            }
            self.entries.entry(k).or_insert(v);
        }
    }

    fn overflow(&mut self) {
        self.dropped += 1;
        if self
            .warned
            .is_none_or(|t| t.elapsed() >= Duration::from_secs(60))
        {
            self.warned = Some(Instant::now());
            warn!(
                target: "fim.drain",
                queue = self.name,
                cap = self.cap,
                dropped_total = self.dropped,
                "FIM retry queue full — entries over the cap are dropped: a file dropped into a \
                 watched directory may stay unwatched, a rename or a symlink change unchecked"
            );
        }
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.entries.len()
    }

    fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// External audit NN-AUD-119 (FIMP-007): a periodic step of the drain loop,
/// run at most once per `every` however often the loop turns.
#[derive(Debug)]
struct Pacer {
    every: Duration,
    last: Option<Instant>,
}

impl Pacer {
    fn new(every: Duration) -> Self {
        Self { every, last: None }
    }

    /// Whether the step is due at `now` (and, if so, that it ran then).
    fn due(&mut self, now: Instant) -> bool {
        if self
            .last
            .is_some_and(|t| now.saturating_duration_since(t) < self.every)
        {
            return false;
        }
        self.last = Some(now);
        true
    }
}

/// External audit FIMR-004: watched paths whose file another one replaced
/// by a rename over it (`mv` of a prepared file onto a binary, a PAM
/// module, a unit: how installers and rootkits alike swap a file), with
/// the renamer's event, once the rename landed. The rename alone reached
/// only the rename rules; every rule guarding the path's content watches
/// modifications. Each is checked as one: the new file against the
/// baseline, attributed to the renamer.
const REPLACEMENTS_MAX: usize = 1024;

fn queue_replacement(path: &str, renamed: &FimDriftRaw) {
    queues(|q| {
        if q.replacements.len() < REPLACEMENTS_MAX {
            q.replacements.push((path.to_string(), *renamed));
        } else {
            warn!(target: "fim.drain", path, "replacement checks queue full — this replacement is not checked");
        }
    });
}

/// The queued replacements as modification events of the file now at each
/// path, by the renamer. A path holding nothing any more is dropped.
fn replacement_raws() -> Vec<FimDriftRaw> {
    let queued = queues(|q| std::mem::take(&mut q.replacements));
    queued
        .into_iter()
        .filter_map(|(path, raw)| replacement_raw(&path, raw))
        .collect()
}

/// A replacement as a modification event of the file now at `path`.
fn replacement_raw(path: &str, mut raw: FimDriftRaw) -> Option<FimDriftRaw> {
    let key = key_for_path(&fs_path(path)).ok()?;
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
}

/// What a retry pass did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct RetryPass {
    /// Entries are still waiting.
    waiting: bool,
    /// Entries looked at (each costs a `stat` or more).
    examined: usize,
}

/// Retry the pending renames, enrollments and symlink-chain checks.
/// External audit NN-AUD-119 (FIMP-007): each queue is taken out under its
/// lock and worked on without it — the `stat`s ran under the lock, entry
/// by entry — and what is still pending is put back.
fn retry_pending_enrollments(
    path_map: &InodePathMap,
    watched_paths: Option<&parking_lot::Mutex<WatchedPathsHandle>>,
) -> RetryPass {
    let mut examined = 0;
    let renames = queues(|q| q.rename.take());
    examined += renames.len();
    let mut left = Vec::new();
    for (key, p) in renames {
        if settle_rename(&key, &p.path, p.class, path_map, watched_paths) {
            if let Some(raw) = &p.replaced {
                queue_replacement(&p.path, raw);
            }
        } else if p.since.elapsed() < ENROLL_RETRY_FOR {
            left.push((key, p));
        }
    }
    let renames_waiting = queues(|q| {
        q.rename.put_back(left);
        !q.rename.is_empty()
    });
    let enrolls_waiting = retry_enrollments(path_map, watched_paths, &mut examined);
    let chains_waiting = retry_chain_checks(path_map, watched_paths, &mut examined);
    RetryPass {
        waiting: renames_waiting || enrolls_waiting || chains_waiting,
        examined,
    }
}

/// The waiting child enrollments; `true` while some still wait.
fn retry_enrollments(
    path_map: &InodePathMap,
    watched_paths: Option<&parking_lot::Mutex<WatchedPathsHandle>>,
    examined: &mut usize,
) -> bool {
    let todo = queues(|q| q.enroll.take());
    *examined += todo.len();
    let left: Vec<(String, Instant)> = todo
        .into_iter()
        .filter(|(path, since)| {
            !enroll_path(path, WatchClass::RuntimeChild, path_map, watched_paths)
                && since.elapsed() < ENROLL_RETRY_FOR
        })
        .collect();
    queues(|q| {
        q.enroll.put_back(left);
        !q.enroll.is_empty()
    })
}

/// External audit NN-AUD-122 (FIMP-010): the symlink chains an event may
/// have changed, re-resolved. One that changed is watched anew and its path
/// checked against the baseline, attributed to the event's writer — as a
/// file renamed over a watched one is (FIMR-004). One unchanged after
/// [`ENROLL_RETRY_FOR`] was not changed (the operation was refused).
fn retry_chain_checks(
    path_map: &InodePathMap,
    watched_paths: Option<&parking_lot::Mutex<WatchedPathsHandle>>,
    examined: &mut usize,
) -> bool {
    let todo = queues(|q| q.chain.take());
    *examined += todo.len();
    let mut left = Vec::new();
    for (owner, (since, raw)) in todo {
        if chain_keys_now(&owner) != path_map.chain(&owner) {
            enroll_chain(&owner, path_map, watched_paths);
            queue_replacement(&owner, &raw);
        } else if since.elapsed() < ENROLL_RETRY_FOR {
            left.push((owner, (since, raw)));
        }
    }
    queues(|q| {
        q.chain.put_back(left);
        !q.chain.is_empty()
    })
}

/// `true` while a retry queue holds entries.
fn retries_waiting() -> bool {
    queues(|q| !q.rename.is_empty() || !q.enroll.is_empty() || !q.chain.is_empty())
}

/// External audit FIMP-005: a watched file renamed away keeps its inode,
/// which went on resolving to the watched path — every later event on the
/// moved file was reported under the watched name (`mv authorized_keys
/// authorized_keys.bak`, then an edit of the copy, drew the
/// authorized_keys rule's kill). Once the path no longer resolves to
/// `key`, forget `key` and watch whatever now lives at the path, as
/// `class`. `false` while the path still resolves to `key`: the rename has
/// not landed yet, or was refused.
fn settle_rename(
    key: &InodeKey,
    path: &str,
    class: WatchClass,
    path_map: &InodePathMap,
    watched_paths: Option<&parking_lot::Mutex<WatchedPathsHandle>>,
) -> bool {
    if matches!(key_for_path(&fs_path(path)), Ok(k) if k == *key) {
        return false;
    }
    forget_if_gone(key, path, path_map, watched_paths);
    // A replacement may already sit at the path (rename-over). If nothing
    // does, wait for one: see [`returned_paths`]. External audit NN-AUD-119:
    // not for a runtime child — a file put back in a watched directory is
    // enrolled by the directory's own event, and children renamed away
    // (`crontab`'s temporary file) filled the list for good.
    if !enroll_path(path, class, path_map, watched_paths) && class != WatchClass::RuntimeChild {
        await_return(path, class);
    }
    true
}

/// Wait for a file to come back at `path`, watched as `class`.
fn await_return(path: &str, class: WatchClass) {
    queues(|q| {
        let awaiting = &mut q.awaiting_return;
        if !awaiting.iter().any(|(p, _)| p == path) && awaiting.len() < AWAITING_RETURN_MAX {
            awaiting.push((path.to_string(), class));
        }
    });
}

/// External audit FIMP-005: watched paths whose file was renamed away and
/// not replaced, with why they were watched. The kernel watches inodes, and
/// nothing tells the drain when a file comes back to a path no watched
/// inode holds — `mv` back, or a new file put there. The drain looks once a
/// second ([`AWAITING_RETURN_EVERY`]); a file back at its path is watched
/// again and checked against the baseline as a creation: a replacement is
/// a change of the watched file.
const AWAITING_RETURN_MAX: usize = 256;
const AWAITING_RETURN_EVERY: Duration = Duration::from_secs(1);

/// Paths back at their place since the last look: enrolled again, and
/// returned with their new inode for a drift check.
fn returned_paths(
    path_map: &InodePathMap,
    watched_paths: Option<&parking_lot::Mutex<WatchedPathsHandle>>,
) -> Vec<InodeKey> {
    let todo = queues(|q| std::mem::take(&mut q.awaiting_return));
    let mut back = Vec::new();
    for (path, class) in todo {
        match key_for_path(&fs_path(&path)) {
            Ok(key) if enroll_path(&path, class, path_map, watched_paths) => back.push(key),
            _ => await_return(&path, class),
        }
    }
    back
}

/// External audit NN-AUD-122 (FIMP-010): symlinked watched paths whose
/// final target is missing. Nothing the kernel watches tells the drain when
/// it is back — a re-created `/etc/alternatives/nc` touches no watched
/// inode — so the drain looks with the renamed-away paths, once a second,
/// and checks the path as a creation once its chain is whole.
const CHAIN_AWAITING_MAX: usize = 256;

/// Wait for the final target behind `owner` to exist again.
pub(crate) fn await_chain_repair(owner: &str) {
    queues(|q| {
        let awaiting = &mut q.chain_awaiting;
        if !awaiting.iter().any(|p| p == owner) && awaiting.len() < CHAIN_AWAITING_MAX {
            awaiting.push(owner.to_string());
        }
    });
}

/// Symlinked paths whose chain is whole again: watched anew, and returned
/// with their own inode for a drift check. A path gone itself is dropped
/// (its own rename or deletion handling covers it).
fn repaired_chains(
    path_map: &InodePathMap,
    watched_paths: Option<&parking_lot::Mutex<WatchedPathsHandle>>,
) -> Vec<InodeKey> {
    let todo = queues(|q| std::mem::take(&mut q.chain_awaiting));
    let mut back = Vec::new();
    for owner in todo {
        match crate::fim::attach::plan_path_watches(Path::new(&owner)) {
            Ok(plan) if !plan.broken => {
                enroll_chain(&owner, path_map, watched_paths);
                back.push(plan.own);
            }
            Ok(_) => await_chain_repair(&owner),
            Err(_) => {}
        }
    }
    back
}

/// `true` while a renamed-away path waits for its file, or a symlinked one
/// for its target.
fn awaiting_returns() -> bool {
    queues(|q| !q.awaiting_return.is_empty() || !q.chain_awaiting.is_empty())
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
/// answer for it. External audit NN-AUD-122: behind a symlink, the links
/// and the target are watched as they are now. `false` when nothing is at
/// the path.
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
    enroll_path(path, WatchClass::Configured, path_map, watched_paths)
}

/// Watch whatever is at `path` now, as `class` — BUG-022: a file dropped
/// into a watched directory, so a later in-place edit is observed directly
/// by the BUG-023 write-then-close hook. For a configured path, the links
/// and the target behind it too (NN-AUD-122). `false` when nothing is at
/// the path (yet: a child is queued for a retry, review 58).
fn enroll_path(
    path: &str,
    class: WatchClass,
    path_map: &InodePathMap,
    watched_paths: Option<&parking_lot::Mutex<WatchedPathsHandle>>,
) -> bool {
    // External audit NN-AUD-291: by the file's own name.
    let file = fs_path(path);
    let Ok(key) = key_for_path(&file) else {
        return false;
    };
    watch_inode(key, path, class, path_map, watched_paths);
    // External audit EBPF-016: a new watch on overlayfs, FUSE or NFS.
    crate::fs_type::note_identity(&file);
    if class == WatchClass::Configured {
        enroll_chain(path, path_map, watched_paths);
    }
    true
}

/// External audit NN-AUD-122 (FIMP-010): watch the links and the target
/// behind `owner` as they are now, named by `owner`. Those no longer behind
/// it stop being watched, unless another watched link passes through them.
/// A chain whose final target is missing waits for it
/// ([`await_chain_repair`]).
fn enroll_chain(
    owner: &str,
    path_map: &InodePathMap,
    watched_paths: Option<&parking_lot::Mutex<WatchedPathsHandle>>,
) {
    let plan = crate::fim::attach::plan_path_watches(Path::new(owner)).ok();
    let hops: Vec<InodeKey> = plan
        .as_ref()
        .map(|p| p.hops.iter().map(|(_, k)| *k).collect())
        .unwrap_or_default();
    let broken = plan.as_ref().is_some_and(|p| p.broken);
    let before = path_map.chain(owner);
    if hops.is_empty() && before.is_empty() && !broken {
        // not a symlink, and never was one here
        return;
    }
    path_map.set_chain(owner, hops.clone());
    for old in before {
        if !hops.contains(&old) && path_map.release_hop(owner, old) {
            if let Some(w) = watched_paths {
                w.lock().unenroll(old);
            }
        }
    }
    for key in hops {
        watch_inode(key, owner, WatchClass::ChainHop, path_map, watched_paths);
    }
    if broken {
        await_chain_repair(owner);
    }
}

/// The hop inodes behind `owner` now: empty when it is not a symlink, or
/// its chain cannot be followed.
fn chain_keys_now(owner: &str) -> Vec<InodeKey> {
    crate::fim::attach::plan_path_watches(Path::new(owner))
        .map(|p| p.hops.into_iter().map(|(_, k)| k).collect())
        .unwrap_or_default()
}

/// External audit NN-AUD-120 (FIMP-008): how many runtime children
/// [`watch_inode`] evicts, at most, to make room in a full kernel map.
const MAKE_ROOM_TRIES: usize = 8;

/// External audit NN-AUD-120 (FIMP-008): watch inode `key` as `path` of
/// `class`, in the drain's map and in the kernel's `WATCHED_PATHS`. A
/// runtime child over [`RUNTIME_CHILD_CAP`] evicts the oldest one; a full
/// kernel map evicts the oldest runtime children to make room — never an
/// entry of another class, whatever is enrolled. An eviction or a refusal
/// is an ERROR and a signed `subsystem_degraded` (`fim_watch_map_full`,
/// rate-limited: [`WatchPressure`]); a full map used to refuse everything,
/// a canary decoy included, with a WARN. `true` when the kernel watches
/// `key` (always without a kernel map: nothing there refuses).
pub fn watch_inode(
    key: InodeKey,
    path: &str,
    class: WatchClass,
    path_map: &InodePathMap,
    watched_paths: Option<&parking_lot::Mutex<WatchedPathsHandle>>,
) -> bool {
    let mut evicted = 0u64;
    if let Some((old, _)) = path_map.insert_as(key, path.to_string(), class) {
        if let Some(wp) = watched_paths {
            wp.lock().unenroll(old);
        }
        evicted += 1;
    }
    let mut watched = true;
    if let Some(wp) = watched_paths {
        let mut wp = wp.lock();
        watched = wp.enroll(key);
        for _ in 0..MAKE_ROOM_TRIES {
            if watched {
                break;
            }
            let Some((old, _)) = path_map.evict_oldest_child(Some(key)) else {
                break;
            };
            wp.unenroll(old);
            evicted += 1;
            watched = wp.enroll(key);
        }
    }
    if !watched && class == WatchClass::RuntimeChild {
        // not watched: not counted as watched either
        path_map.remove(&key);
    }
    if evicted > 0 || !watched {
        note_watch_pressure(evicted, u64::from(!watched), path, path_map);
    }
    watched
}

/// External audit NN-AUD-120 (FIMP-008): runtime children evicted and
/// watches refused since boot. Reported as an ERROR at most once per
/// [`PRESSURE_LOG_EVERY`], and as a signed `subsystem_degraded`
/// (`fim_watch_map_full`) at most once per [`PRESSURE_ATTEST_EVERY`], each
/// with the totals.
#[derive(Debug)]
struct WatchPressure {
    evicted: u64,
    refused: u64,
    logged: Option<Instant>,
    attested: Option<Instant>,
}

const PRESSURE_LOG_EVERY: Duration = Duration::from_secs(60);
const PRESSURE_ATTEST_EVERY: Duration = Duration::from_secs(3600);

impl WatchPressure {
    const fn new() -> Self {
        Self {
            evicted: 0,
            refused: 0,
            logged: None,
            attested: None,
        }
    }

    /// Count `evicted` and `refused` at `now`: whether the ERROR and the
    /// signed record are due.
    fn note(&mut self, evicted: u64, refused: u64, now: Instant) -> (bool, bool) {
        self.evicted += evicted;
        self.refused += refused;
        let due = |last: Option<Instant>, every: Duration| {
            last.is_none_or(|t| now.saturating_duration_since(t) >= every)
        };
        let log = due(self.logged, PRESSURE_LOG_EVERY);
        if log {
            self.logged = Some(now);
        }
        let attest = due(self.attested, PRESSURE_ATTEST_EVERY);
        if attest {
            self.attested = Some(now);
        }
        (log, attest)
    }
}

static WATCH_PRESSURE: parking_lot::Mutex<WatchPressure> =
    parking_lot::Mutex::new(WatchPressure::new());

/// The signed audit log, for [`note_watch_pressure`].
static FIM_AUDIT_LOG: OnceLock<Arc<parking_lot::Mutex<crate::audit::AuditLog>>> = OnceLock::new();

/// Hand the signed audit log to the FIM (from `main`, once it exists): a
/// full watch set is recorded there (external audit NN-AUD-120).
pub fn set_audit_log(log: Option<Arc<parking_lot::Mutex<crate::audit::AuditLog>>>) {
    if let Some(l) = log {
        let _ = FIM_AUDIT_LOG.set(l);
    }
}

fn note_watch_pressure(evicted: u64, refused: u64, path: &str, path_map: &InodePathMap) {
    let (log, attest, evicted_total, refused_total) = {
        let mut p = WATCH_PRESSURE.lock();
        let (log, attest) = p.note(evicted, refused, Instant::now());
        (log, attest, p.evicted, p.refused)
    };
    let children = path_map.child_count();
    let cap = path_map.child_cap();
    if log {
        tracing::error!(
            target: "fim.drain",
            path,
            evicted_total,
            refused_total,
            runtime_children = children,
            runtime_child_cap = cap,
            capacity = crate::fim::attach::WATCHED_PATHS_CAPACITY,
            "FIM WATCH SET FULL: runtime children evicted or watches refused — the oldest files \
             dropped into watched directories are no longer watched for in-place edits; a \
             refused path is not watched at all"
        );
    }
    if attest {
        if let Some(log) = FIM_AUDIT_LOG.get() {
            let draft = watch_map_full_draft(evicted_total, refused_total, children, cap);
            if let Err(e) = log.lock().append(draft) {
                warn!(
                    error = format!("{e:#}"),
                    "attesting the full FIM watch set failed"
                );
            }
        }
    }
}

/// The signed `subsystem_degraded` record of a full FIM watch set.
fn watch_map_full_draft(
    evicted: u64,
    refused: u64,
    children: usize,
    cap: usize,
) -> crate::audit::AuditEntryDraft {
    let detail = format!(
        "fim_watch_map_full: {evicted} runtime child watch(es) evicted and {refused} watch(es) \
         refused since boot ({children}/{cap} runtime children watched) — not every file \
         dropped into a watched directory is watched"
    );
    crate::audit::AuditEntryDraft {
        op: crate::self_integrity::AUDIT_OP.to_string(),
        extra: serde_json::json!({
            "kind": "subsystem_degraded",
            "detail": detail,
            "at_boot": false,
            "reason": "fim_watch_map_full",
            "evicted": evicted,
            "refused": refused,
            "runtime_children": children,
            "runtime_child_cap": cap,
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

/// External audit NN-AUD-120 (FIMP-008): runtime children whose file is
/// gone stop being watched — a Deleted event the ring dropped, a directory
/// removed with its files: removal was only ever on a processed event.
/// Every [`CHILD_GC_EVERY`]; returns how many went.
const CHILD_GC_EVERY: Duration = Duration::from_secs(60);

fn gc_runtime_children(
    path_map: &InodePathMap,
    watched_paths: Option<&parking_lot::Mutex<WatchedPathsHandle>>,
) -> usize {
    let mut gone = 0;
    for (key, path) in path_map.runtime_children() {
        if !matches!(key_for_path(&fs_path(&path)), Ok(k) if k == key) {
            path_map.remove(&key);
            if let Some(wp) = watched_paths {
                wp.lock().unenroll(key);
            }
            gone += 1;
        }
    }
    gone
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
    let now = key_for_path(&fs_path(path));
    if matches!(now, Ok(k) if k == *key) {
        return;
    }
    // External audit NN-AUD-120: the inode is named by another path since
    // — a file renamed within watched directories (`tmp.X` to its final
    // name), enrolled under the new name by the directory's event before
    // the rename of the old name was settled. It is live there.
    if path_map.lookup(key).is_some_and(|p| p != path) {
        return;
    }
    path_map.remove(key);
    if let Some(wp) = watched_paths {
        wp.lock().unenroll(*key);
    }
    // External audit NN-AUD-122: a symlinked path gone takes the links and
    // the target behind it out of the watch (they were named by it); they
    // are watched again with it, when it is back.
    if now.is_err() && !path_map.chain(path).is_empty() {
        enroll_chain(path, path_map, watched_paths);
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
///    `skip_reason` on the persisted entry. Only drift written in a
///    package transaction (`lineage`,
///    [`AuthSessionTracker::is_package_transaction_write`]) is throttled:
///    the buckets are host-wide, so a writer that could spend them could
///    also skip the rules for its own next write (review 76; external
///    audit NN-AUD-284: not under `mandb`, not after the transaction).
///    With no `lineage`, nothing is throttled.
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
    let class = path_map.class_of(&key).unwrap_or(WatchClass::RuntimeChild);

    // BUG-022 — child-leaf reconstruction. When the kernel carried a
    // child leaf (a Create in, or a rename INTO, a watched DIRECTORY),
    // the `path` resolved above is only the bare watched dir — which no
    // child-prefix rule matches (the dead-rule root). Rebuild
    // `dir + "/" + leaf`, normalize a drop-via-rename to Created, mirror
    // the truncated flag for the rules, and enroll the new child inode
    // so its later in-place edits are caught by the write-then-close
    // hook. Events without a child leaf (every non-Create/Rename op, and
    // renames whose dest dir isn't watched) fall through unchanged.
    // External audit NN-AUD-285 (FIMR-011): which file the event is about.
    // The watched inode itself, unless a child is reconstructed below.
    let mut ident = FileIdent {
        key: Some(key),
        is_dir: false,
        moved_in: false,
    };
    let mut child_read = false;
    // Lab PR 225: a leaf in a `Renamed` record names a file renamed INTO a
    // watched directory, unless the kernel marked it as the new name of the
    // watched inode itself (`FIM_RENAME_DEST_LEAF`).
    let moved_in_leaf = raw.child_name[0] != 0
        && (op != FimOp::Renamed || raw.op_flags & FIM_RENAME_DEST_LEAF == 0);
    let (path, op, child_truncated) =
        if matches!(op, FimOp::Created | FimOp::Renamed) && moved_in_leaf {
            match reconstruct_child_path(&path, raw) {
                Some(child) => {
                    let truncated = raw.child_name_flags & FIM_CHILD_TRUNCATED != 0;
                    // Read before the enrollment below names the inode by
                    // this path.
                    ident = child_ident(&child, op == FimOp::Renamed, path_map);
                    child_read = true;
                    if !enroll_path(&child, WatchClass::RuntimeChild, path_map, watched_paths) {
                        queues(|q| q.enroll.push(child.clone(), Instant::now()));
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
    // External audit NN-AUD-122 (FIMP-010): a link or the target behind a
    // watched symlink unlinked, renamed away or replaced — what the watched
    // path reaches may have changed. Its chain is resolved again once the
    // change has landed (the hooks fire before it), watched anew, and the
    // path checked against its baseline, attributed to this writer.
    if class == WatchClass::ChainHop
        && (op == FimOp::Deleted || (op == FimOp::Renamed && !moved_in_leaf))
    {
        queues(|q| q.chain.push(path.clone(), (Instant::now(), *raw)));
        return Ok(false);
    }
    if op == FimOp::Deleted {
        forget_if_gone(&key, &path, path_map, watched_paths);
    }
    // External audit FIMP-005: the watched inode itself renamed (no child
    // leaf: the source was watched). FIMR-004: or replaced by another file
    // renamed over it — checked as a modification once the rename lands.
    if op == FimOp::Renamed && !moved_in_leaf {
        let replaced = (raw.op_flags & FIM_RENAME_REPLACED != 0).then_some(*raw);
        if settle_rename(&key, &path, class, path_map, watched_paths) {
            if let Some(r) = &replaced {
                queue_replacement(&path, r);
            }
        } else {
            let pending = PendingRename {
                path: path.clone(),
                class,
                since: Instant::now(),
                replaced,
            };
            queues(|q| {
                q.rename.push_with(key, pending, |queued, new| {
                    if queued.replaced.is_none() {
                        queued.replaced = new.replaced;
                    }
                })
            });
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
                path = %common::log_escape::Escaped(&path),
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
            path = %common::log_escape::Escaped(&path),
            modifier_comm = %common::log_escape::Escaped(comm_to_string(&raw.modifier_comm)),
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
                attrs: None,
                file_key: ident.key,
                is_dir: false,
                moved_in: ident.moved_in,
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
    // NN-AUD-285: a watched directory's own event (its setattr) is told from
    // a file's. A directory is never hashed, so only an event without
    // content needs the look.
    if content.is_none() && !child_read {
        ident.is_dir = std::fs::symlink_metadata(fs_path(&path)).is_ok_and(|m| m.is_dir());
    }
    let new_sha256 = content.as_ref().map(|c| c.sha256.clone());
    let new_size = content.as_ref().map(|c| c.size);
    let baseline_sha256 = last_baseline.map(|b| b.sha256.clone());
    let baseline_size = last_baseline.map(|b| b.size_bytes);

    // Wave 2 (TST-004): the kernel reports a chmod or chown as Modified,
    // and an unchanged hash used to drop it as a no-op below — `chmod u+s`
    // on a watched binary, `chmod o+r /etc/shadow`, left no trace. The
    // baseline holds the mode and ownership too: a change there is drift
    // of its own.
    let attrs = match (op, last_baseline, &content) {
        (FimOp::Modified, Some(base), Some(now)) if base.sha256 == now.sha256 => {
            attr_change(base, now)
        }
        _ => None,
    };
    let op = if attrs.is_some() {
        FimOp::AttrChanged
    } else {
        op
    };

    // Skip if SHA matches baseline (kernel hook fired but
    // content didn't actually change — e.g., `touch -t` on an
    // unchanged file). Deleted/Renamed always counts as drift
    // even if hashes are None on both sides (the file
    // disappeared — operator wants to know).
    let real_drift = attrs.is_some()
        || !matches!(
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
        // External audit NN-AUD-121 (FIMP-009): the kernel saw a write, and
        // the re-hash — which runs after it — found the baseline content: a
        // touch, or a write undone before the drain looked (write, use,
        // restore). On a path a Critical rule guards that is not dropped
        // silently: a drift row flagged `content_restored`, kept from the
        // rules (no verdict on content that matches), counted per path.
        // Everywhere else the no-op suppression against touch noise stays.
        if crate::fim::rules::is_critical_rule_path(&path) {
            let restored = note_content_restored(&path);
            if restored.is_power_of_two() {
                warn!(
                    target: "fim.drain",
                    path = %common::log_escape::Escaped(&path),
                    ?op,
                    modifier_pid = raw.modifier_pid,
                    modifier_comm = %common::log_escape::Escaped(comm_to_string(&raw.modifier_comm)),
                    restored_writes = restored,
                    "FIM: a write on a critical path left its content as baselined — recorded \
                     as content_restored (a touch, or a change undone before the re-hash)"
                );
            }
            let draft = FimDriftDraft {
                path: path.clone(),
                op,
                baseline_sha256: baseline_sha256.clone(),
                new_sha256: new_sha256.clone(),
                modifier_pid: raw.modifier_pid,
                modifier_uid: raw.modifier_uid,
                modifier_comm: comm_to_string(&raw.modifier_comm),
                severity: classifier.classify(op, &path),
                decision_engine_skipped: true,
                skip_reason: CONTENT_RESTORED.to_string(),
                attrs: None,
            };
            if let Err(e) = drift_db.append_drift(draft).context("append to drift DB") {
                report_evidence_loss(&path, &e);
            }
            return Ok(false);
        }
        debug!(
            target: "fim.drain",
            path = %common::log_escape::Escaped(&path),
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
    // External audit NN-AUD-284: the package carve-out's own test — the
    // package managers proper, during their transaction.
    let package_managed =
        lineage.is_some_and(|l| l.is_package_transaction_write(raw.modifier_pid, raw.timestamp_ns));
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
        attrs,
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
            path = %common::log_escape::Escaped(&path),
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
        // Lab PR 225: the file's new path, not the directory it went to.
        let dest_path = if matches!(op, FimOp::Renamed) && raw.dest_ino != 0 {
            rename_destination(raw, &path, path_map)
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
            attrs,
            file_key: ident.key,
            is_dir: ident.is_dir,
            moved_in: ident.moved_in,
        }));
    }
    Ok(true)
}

/// Lab PR 225: where a watched file was renamed to — `dir/leaf`. The kernel
/// names the destination directory (`dest_dev`/`dest_ino`); NN-L-FIM-010
/// used to match that directory's path, so `x → x.locked` never fired. The
/// directory is the watched one the map names, or the source's own (a
/// rename in place, the encrypt-and-rename loop: the directory itself is
/// rarely watched). The leaf is the one the kernel carried
/// (`FIM_RENAME_DEST_LEAF`), else the entry of that directory that now holds
/// the renamed inode (an older eBPF object, or a leaf cut at
/// `FIM_CHILD_NAME_LEN`). `None` when neither can be found: a rename to an
/// unwatched directory elsewhere.
fn rename_destination(raw: &FimDriftRaw, src: &str, path_map: &InodePathMap) -> Option<String> {
    let dir_key = InodeKey {
        dev: raw.dest_dev,
        ino: raw.dest_ino,
    };
    let dir = path_map.lookup(&dir_key).or_else(|| {
        let parent = Path::new(src).parent()?.to_str()?;
        let parent = if parent.is_empty() { "/" } else { parent };
        matches!(key_for_path(&fs_path(parent)), Ok(k) if k == dir_key).then(|| parent.to_string())
    })?;
    let carried = raw.op_flags & FIM_RENAME_DEST_LEAF != 0
        && raw.child_name[0] != 0
        && raw.child_name_flags & FIM_CHILD_TRUNCATED == 0;
    if carried {
        if let Some(p) = reconstruct_child_path(&dir, raw) {
            return Some(p);
        }
    }
    let leaf = entry_holding(&dir, raw.target_ino)?;
    Some(format!("{}/{}", dir.trim_end_matches('/'), leaf))
}

/// Lab PR 225: entries of a directory read when looking for a renamed inode.
const RENAME_SCAN_MAX: usize = 65_536;

/// Lab PR 225: the name, as the drain spells it ([`leaf_display`]), of the
/// entry of `dir` whose inode number is `ino`.
fn entry_holding(dir: &str, ino: u64) -> Option<String> {
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::DirEntryExt;
    let entries = std::fs::read_dir(fs_path(dir)).ok()?;
    entries
        .take(RENAME_SCAN_MAX)
        .flatten()
        .find(|e| e.ino() == ino)
        .map(|e| leaf_display(e.file_name().as_bytes()))
}

/// External audit NN-AUD-285 (FIMR-011): the file a FIM event is about
/// ([`FimEvent::file_key`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FileIdent {
    key: Option<InodeKey>,
    is_dir: bool,
    moved_in: bool,
}

/// NN-AUD-285: the file a child created in (or moved into, `moved_in`) a
/// watched directory is, read at its path. The hooks fire before the
/// operation: the name may not hold the file yet, or hold it no more (a
/// temporary file renamed on), and then the file is not told. An inode
/// the map already names by this very path is the file the operation
/// replaces, still there (a rename over it not landed yet): not told
/// either.
fn child_ident(child: &str, moved_in: bool, path_map: &InodePathMap) -> FileIdent {
    use std::os::unix::fs::MetadataExt;
    let Ok(meta) = std::fs::symlink_metadata(fs_path(child)) else {
        return FileIdent {
            key: None,
            is_dir: false,
            moved_in,
        };
    };
    let key = InodeKey {
        dev: crate::fim::attach::stat_dev_to_kernel_dev(meta.dev()),
        ino: meta.ino(),
    };
    let replaced = path_map.lookup(&key).as_deref() == Some(child);
    FileIdent {
        key: (!replaced).then_some(key),
        is_dir: meta.is_dir(),
        moved_in,
    }
}

/// External audit NN-AUD-121 (FIMP-009): the `skip_reason` of a drift row
/// whose re-hash found the baseline content on a critical path.
pub const CONTENT_RESTORED: &str = "content_restored";

/// External audit NN-AUD-121 (FIMP-009): writes seen on each critical path
/// whose re-hash found the baseline content, since boot (at most
/// [`RESTORED_PATHS_MAX`] paths; the count starts over beyond). Returns the
/// count for `path`, this one included.
fn note_content_restored(path: &str) -> u64 {
    static RESTORED: LazyLock<parking_lot::Mutex<HashMap<String, u64>>> =
        LazyLock::new(|| parking_lot::Mutex::new(HashMap::new()));
    let mut counts = RESTORED.lock();
    if counts.len() >= RESTORED_PATHS_MAX && !counts.contains_key(path) {
        counts.clear();
    }
    let n = counts.entry(path.to_string()).or_insert(0);
    *n += 1;
    *n
}
const RESTORED_PATHS_MAX: usize = 1024;

/// The mode, owner or group of `now` where they differ from `base`.
fn attr_change(base: &BaselineEntry, now: &Content) -> Option<FileAttrChange> {
    // A baseline row whose mode does not parse cannot be compared: no
    // attribute drift is claimed from it.
    let mode_before = parse_mode(&base.mode)?;
    let change = FileAttrChange {
        mode_before,
        mode_after: now.mode,
        uid_before: base.uid,
        uid_after: now.uid,
        gid_before: base.gid,
        gid_after: now.gid,
    };
    (change.mode_before != change.mode_after || change.owner_changed()).then_some(change)
}

/// A baseline mode, `"0o4755"`.
fn parse_mode(mode: &str) -> Option<u32> {
    u32::from_str_radix(mode.strip_prefix("0o")?, 8).ok()
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
    let mut async_fd = crate::async_fd::register(rb)?;
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
    // External audit NN-AUD-119 / NN-AUD-120: the periodic steps, each at
    // most once per period however often the loop turns.
    let mut retry_pacer = Pacer::new(RETRY_EVERY);
    let mut returns_pacer = Pacer::new(AWAITING_RETURN_EVERY);
    let mut gc_pacer = Pacer::new(CHILD_GC_EVERY);
    // the first sweep a period after boot
    let _ = returns_pacer.due(Instant::now());
    let _ = gc_pacer.due(Instant::now());
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
        let now = Instant::now();
        // Review 58: while children wait for their file to appear, wake up
        // every few milliseconds to retry them. External audit NN-AUD-119:
        // at most once per RETRY_EVERY (it ran after every emitted event),
        // and its `stat`s off the runtime's threads.
        let waiting = if retry_pacer.due(now) {
            off_the_runtime(|| {
                retry_pending_enrollments(inode_map.as_ref(), watched_paths.as_deref())
            })
            .waiting
        } else {
            retries_waiting()
        };
        // External audit FIMP-005: a file back at a watched path it was
        // renamed away from is watched again and checked as a creation.
        // NN-AUD-122: so is a symlinked path whose target is back.
        if awaiting_returns() && returns_pacer.due(now) {
            let back = off_the_runtime(|| {
                let mut back = returned_paths(inode_map.as_ref(), watched_paths.as_deref());
                back.extend(repaired_chains(
                    inode_map.as_ref(),
                    watched_paths.as_deref(),
                ));
                back
            });
            for key in back {
                if let Err(e) = check(&returned_raw(key), &mut outbox) {
                    warn!(target: "fim.drain", error = %format!("{e:#}"), "drift check of a returned file failed");
                }
            }
        }
        // External audit NN-AUD-120: runtime children whose file is gone.
        if gc_pacer.due(now) {
            let gone = off_the_runtime(|| {
                gc_runtime_children(inode_map.as_ref(), watched_paths.as_deref())
            });
            if gone > 0 {
                debug!(target: "fim.drain", gone, "runtime children gone from disk no longer watched");
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
            RETRY_EVERY
        } else if awaiting_returns() {
            AWAITING_RETURN_EVERY
        } else {
            CHILD_GC_EVERY
        };
        let mut guard = match tokio::time::timeout(wake_after, async_fd.readable_mut()).await {
            Ok(g) => g?,
            Err(_) => continue,
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
    /// The file's content and attributes, `None` when it could not be read.
    content: Option<Content>,
}

/// A watched file as the drain re-read it after an event.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Content {
    /// SHA-256, lowercase hex.
    sha256: String,
    size: u64,
    /// `st_mode & 0o7777`, owner and group (Wave 2, TST-004).
    mode: u32,
    uid: u32,
    gid: u32,
}

/// The content of `path` as of an event at `event_ns`: the last hash when
/// it began after the event, else a new one.
fn content_after(path: &str, event_ns: u64) -> Option<Content> {
    if let Ok(cache) = HASHED.lock() {
        if let Some(h) = cache.as_ref().and_then(|c| c.get(path)) {
            if event_ns != 0 && event_ns + HASH_REUSE_MARGIN_NS <= h.began_ns {
                return h.content.clone();
            }
        }
    }
    let began_ns = monotonic_ns();
    let content = match compute_baseline(&fs_path(path)) {
        Ok(drafts) => drafts.into_iter().find(|d| !d.is_symlink).map(|d| Content {
            mode: parse_mode(&d.mode).unwrap_or(0),
            sha256: d.sha256,
            size: d.size_bytes,
            uid: d.uid,
            gid: d.gid,
        }),
        Err(e) => {
            debug!(
                target: "fim.drain",
                path = %common::log_escape::Escaped(&path),
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

    fn raw_with_leaf(leaf: &[u8]) -> FimDriftRaw {
        let mut raw = fake_raw(0x77, 7, FimOp::Created as u8);
        raw.child_name[..leaf.len()].copy_from_slice(leaf);
        raw
    }

    /// External audit NN-AUD-291 (FIMP-012): the leaf was decoded lossily
    /// (U+FFFD), a name no file has. It is kept as bytes: a UTF-8 name is
    /// itself (backslashes included), any other is spelled with `\xNN` and
    /// `\\`, distinct names stay distinct, and the spelling leads back to
    /// the bytes. An empty leaf, `.`, `..` and a slash are refused.
    #[test]
    fn reconstruct_child_path_rejects_dot_dot_and_keeps_raw_bytes() {
        let child = |leaf: &[u8]| reconstruct_child_path("/etc/cron.d/", &raw_with_leaf(leaf));
        for refused in [&b""[..], b".", b"..", b"a/b"] {
            assert_eq!(child(refused), None, "{refused:?}");
        }
        assert_eq!(child(b"job").as_deref(), Some("/etc/cron.d/job"));
        assert_eq!(
            child(b"mnt-data\\x2dvol.mount").as_deref(),
            Some("/etc/cron.d/mnt-data\\x2dvol.mount"),
            "a UTF-8 name is itself"
        );
        assert_eq!(child(b"ev\xffil").as_deref(), Some("/etc/cron.d/ev\\xffil"));
        assert_ne!(child(b"ev\xffil"), child(b"ev\xfeil"));
        assert_eq!(
            child(b"a\\\xc3").as_deref(),
            Some("/etc/cron.d/a\\\\\\xc3"),
            "a backslash in a name that is not UTF-8 is doubled"
        );
        for name in [&b"ev\xffil"[..], b"a\\\xc3", b"\xe2\x82", b"x\\xff\xff"] {
            assert_eq!(
                leaf_bytes(&leaf_display(name)).as_deref(),
                Some(name),
                "{name:?}"
            );
        }
        // Text the escape did not produce is not decoded.
        for text in [
            "job",
            "mnt-data\\x2dvol.mount",
            "\\xc3\\xa9",
            "a\\q",
            "a\\x+f\\xff",
        ] {
            assert_eq!(leaf_bytes(text), None, "{text:?}");
        }
    }

    /// External audit NN-AUD-291 (FIMP-012): a file dropped into a watched
    /// directory under a name that is not UTF-8 is enrolled by its own
    /// bytes, hashed, kept by the sweep of children gone, and its later
    /// in-place edit is reported under the escaped name. On the code before,
    /// the lossy path did not exist: no enrollment, no hash, no edit.
    #[test]
    fn a_child_with_a_non_utf8_name_is_watched_and_its_edit_reported() {
        use sha2::Digest as _;
        use std::os::unix::ffi::OsStrExt;
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
        let dir_str = watched_dir.to_string_lossy().into_owned();
        let leaf = b"ev\xffil";
        let file = watched_dir.join(std::ffi::OsStr::from_bytes(leaf));
        std::fs::write(&file, b"* * * * * root true\n").unwrap();
        let shown = format!("{dir_str}/ev\\xffil");

        let dir_key = InodeKey { dev: 0x77, ino: 7 };
        let path_map = InodePathMap::new();
        path_map.insert(dir_key, dir_str.clone());
        let classifier = DriftClassifier::new();
        let rate_limiter = DriftRateLimiter::new();
        let mut run = |raw: &FimDriftRaw| {
            let mut out = Vec::new();
            assert!(process_drift(
                raw,
                &path_map,
                None,
                &mut drift_db,
                &classifier,
                &rate_limiter,
                None,
                None,
                Some(&mut out),
            )
            .unwrap());
            match out.remove(0) {
                Event::Fim(fe) => fe,
                other => panic!("expected Event::Fim, got {other:?}"),
            }
        };
        let sha = |bytes: &[u8]| -> [u8; 32] { sha2::Sha256::digest(bytes).into() };

        let mut created = fake_raw(dir_key.dev, dir_key.ino, FimOp::Created as u8);
        created.child_name[..leaf.len()].copy_from_slice(leaf);
        let ev = run(&created);
        assert_eq!(ev.path, shown);
        assert_eq!(ev.op, FimOp::Created);
        assert_eq!(
            ev.new_sha256,
            Some(sha(b"* * * * * root true\n")),
            "hashed by its bytes"
        );
        let key = key_for_path(&file).unwrap();
        assert_eq!(
            path_map.lookup(&key).as_deref(),
            Some(shown.as_str()),
            "enrolled at once, not queued for a path that does not exist"
        );

        std::fs::write(&file, b"* * * * * root true\n* * * * * root id\n").unwrap();
        let ev = run(&fake_raw(key.dev, key.ino, FimOp::Modified as u8));
        assert_eq!(ev.path, shown);
        assert_eq!(ev.op, FimOp::Modified);
        assert_eq!(
            ev.new_sha256,
            Some(sha(b"* * * * * root true\n* * * * * root id\n"))
        );
        assert_eq!(
            gc_runtime_children(&path_map, None),
            0,
            "a child still there is not swept"
        );

        // A UTF-8 file spelled like the escape is the one under that name.
        let literal = watched_dir.join("ev\\xffil");
        std::fs::write(&literal, b"x").unwrap();
        assert_eq!(fs_path(&shown).as_ref(), literal.as_path());
        std::fs::remove_file(&literal).unwrap();
        assert_eq!(fs_path(&shown).as_ref(), file.as_path());
    }

    /// Wave 2 (TST-004): `chmod u+s` on a watched file leaves its content
    /// as it was; the drain used to drop the event as a no-op touch. A
    /// mode or owner that differs from the baseline is drift of its own;
    /// the same mode and owner is still the no-op it was.
    #[test]
    fn a_mode_change_with_unchanged_content_is_attribute_drift() {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
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
        let file = dir.path().join("sshd");
        std::fs::write(&file, b"ELF binary").unwrap();
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o755)).unwrap();
        let path = file.to_string_lossy().into_owned();
        let drafts = compute_baseline(&file).unwrap();
        let meta = std::fs::metadata(&file).unwrap();
        let mut baseline = dummy_baseline(&path, &drafts[0].sha256);
        baseline.mode = "0o755".to_string();
        baseline.uid = meta.uid();
        baseline.gid = meta.gid();

        let key = InodeKey {
            dev: 0x1234,
            ino: 77,
        };
        let path_map = InodePathMap::new();
        path_map.insert(key, path.clone());
        let raw = fake_raw(key.dev, key.ino, FimOp::Modified as u8);
        let classifier = DriftClassifier::new();
        let rate_limiter = DriftRateLimiter::new();
        let run = |db: &mut FimDriftDb| {
            let mut out: Vec<Event> = Vec::new();
            let emitted = process_drift(
                &raw,
                &path_map,
                Some(&baseline),
                db,
                &classifier,
                &rate_limiter,
                None,
                None,
                Some(&mut out),
            )
            .unwrap();
            (emitted, out)
        };

        // touch: same content, same mode — the no-op it always was
        let (emitted, out) = run(&mut drift_db);
        assert!(!emitted && out.is_empty(), "an unchanged file is no drift");

        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o4755)).unwrap();
        let (emitted, mut out) = run(&mut drift_db);
        assert!(emitted, "a set-uid bit is drift");
        let Event::Fim(ev) = out.remove(0) else {
            panic!("expected Event::Fim")
        };
        assert_eq!(ev.op, FimOp::AttrChanged);
        let attrs = ev.attrs.expect("what changed rides on the event");
        assert_eq!((attrs.mode_before, attrs.mode_after), (0o755, 0o4755));
        assert!(attrs.grants_privilege());
        assert_eq!(ev.new_sha256, ev.baseline_sha256, "content unchanged");
        // and on the signed row
        let text = std::fs::read_to_string(dir.path().join("drift.jsonl")).unwrap();
        let row: serde_json::Value = serde_json::from_str(text.lines().last().unwrap()).unwrap();
        assert_eq!(row["op"], FimOp::AttrChanged as u8);
        assert_eq!(row["attrs"]["mode_after"], 0o4755);
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
            target: None,
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

    /// External audit NN-AUD-293 (FIMP-014): a panic while the limiter's
    /// lock was held poisoned the `std::sync::Mutex`, and every later drift
    /// panicked at `.expect("… poisoned")` (with `panic = "abort"`, the
    /// agent). The lock is a `parking_lot::Mutex`: released on the unwind,
    /// never poisoned.
    #[test]
    fn rate_limiter_keeps_working_after_a_panic_under_its_lock() {
        let rl = Arc::new(DriftRateLimiter::with_caps(2, 2));
        let held = Arc::clone(&rl);
        let died = std::thread::spawn(move || {
            let _guard = held.state.lock();
            panic!("a drain task dies holding the limiter (expected by this test)");
        })
        .join();
        assert!(died.is_err());
        rl.try_consume(DriftSeverity::High)
            .expect("the limiter still answers");
        let (high, medium, _) = rl.snapshot();
        assert_eq!((high, medium), (1, 2));
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
            attrs: None,
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
                attrs: None,
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
        assert_eq!(now.sha256, hex::encode(Sha256::digest(b"second")));
        // within the margin: read again too (the hook fires before the change)
        std::fs::write(&f, b"third").unwrap();
        let recent = content_after(&p, monotonic_ns()).unwrap();
        assert_eq!(recent.sha256, hex::encode(Sha256::digest(b"third")));
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
        assert!(queues(|q| {
            q.awaiting_return
                .iter()
                .any(|(p, c)| *p == watched_str && *c == WatchClass::Configured)
        }));
        std::fs::rename(dir.path().join("authorized_keys.bak"), &watched).unwrap();
        let back = key_for_path(&watched).unwrap();
        assert!(returned_paths(&path_map, None).contains(&back));
        assert_eq!(
            path_map.lookup(&back).as_deref(),
            Some(watched_str.as_str())
        );
        assert!(!queues(|q| q
            .awaiting_return
            .iter()
            .any(|(p, _)| *p == watched_str)));
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
        let mut matching_baseline = dummy_baseline(&watched.to_string_lossy(), &matching_sha);
        // ... and the same mode and owner (Wave 2: those are compared too).
        matching_baseline.mode = format!("0o{:o}", watched_meta.mode() & 0o7777);
        matching_baseline.uid = watched_meta.uid();
        matching_baseline.gid = watched_meta.gid();

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
        // The writer is dpkg, running: the only drift the buckets pace
        // (review 76; NN-AUD-284: during the transaction).
        let proc_root = dir.path().join("proc");
        running_proc(&proc_root, raw.modifier_pid);
        let lineage = AuthSessionTracker::new(&proc_root);
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

    /// `<proc_root>/<pid>` of a running process.
    fn running_proc(proc_root: &Path, pid: u32) {
        let d = proc_root.join(pid.to_string());
        std::fs::create_dir_all(&d).unwrap();
        std::fs::write(
            d.join("stat"),
            format!("{pid} (p) S 1 {pid} {pid} 0 -1 0\n"),
        )
        .unwrap();
    }

    /// External audit NN-AUD-284 (FIMR-010): the buckets pace only a
    /// package transaction's burst. A writer under `mandb` (any user runs
    /// it) and one a finished dpkg left behind are not paced, so neither
    /// can spend the buckets to keep its next write from the rules.
    #[test]
    fn process_drift_paces_only_a_running_package_transaction() {
        let dir = TempDir::new().unwrap();
        let mut drift_db = drift_db_in(&dir);
        let path_map = InodePathMap::new();
        let watched = dir.path().join("watched.bin");
        std::fs::write(&watched, b"new content").unwrap();
        let key = key_for_path(&watched).unwrap();
        path_map.insert(key, watched.to_string_lossy().to_string());
        let stale_baseline = dummy_baseline(&watched.to_string_lossy(), &"99".repeat(32));
        let proc_root = dir.path().join("proc");
        let lineage = AuthSessionTracker::new(&proc_root);
        let raw = fake_raw(key.dev, key.ino, FimOp::Modified as u8);
        // mandb (running) → the writer; dpkg exited ten minutes before the
        // write → another writer.
        lineage.ingest_spawn(7001, 1, "/usr/bin/mandb", 1);
        running_proc(&proc_root, 7001);
        lineage.ingest_spawn(7002, 7001, "/usr/bin/crontab", 2);
        lineage.ingest_spawn(7101, 1, "/usr/bin/dpkg", raw.timestamp_ns - 600_000_000_000);
        lineage.ingest_spawn(7102, 7101, "/bin/sh", raw.timestamp_ns - 599_000_000_000);
        for writer in [7002, 7102] {
            let mut raw = raw;
            raw.modifier_pid = writer;
            let mut out = Vec::new();
            let emitted = process_drift(
                &raw,
                &path_map,
                Some(&stale_baseline),
                &mut drift_db,
                &DriftClassifier::new(),
                &DriftRateLimiter::with_caps(0, 0),
                None,
                Some(&lineage),
                Some(&mut out),
            )
            .unwrap();
            assert!(emitted, "writer {writer}: the drift must reach the rules");
        }
        assert!(drift_rows(&dir)
            .iter()
            .all(|r| r["decision_engine_skipped"] == false));
    }

    /// External audit NN-AUD-285 (FIMR-011): each event names the file it
    /// is about — a child as found at its path (not yet there, there, moved
    /// in, or the name still holding the file a rename replaces), a
    /// watched file by its own inode, a watched directory as one.
    #[test]
    fn events_name_the_file_they_are_about() {
        let dir = TempDir::new().unwrap();
        let mut db = drift_db_in(&dir);
        let spool = dir.path().join("crontabs");
        std::fs::create_dir(&spool).unwrap();
        let dir_key = InodeKey { dev: 0x99, ino: 9 };
        let path_map = InodePathMap::new();
        path_map.insert(dir_key, spool.to_string_lossy().into_owned());
        // the user's crontab before the install, watched
        std::fs::write(spool.join("nn"), b"# old\n").unwrap();
        let old = key_for_path(&spool.join("nn")).unwrap();
        path_map.insert(old, spool.join("nn").to_string_lossy().into_owned());
        let child = |leaf: &[u8], op: FimOp| {
            let mut raw = fake_raw(dir_key.dev, dir_key.ino, op as u8);
            raw.child_name[..leaf.len()].copy_from_slice(leaf);
            raw
        };
        let mut run = |raw: FimDriftRaw| {
            let mut out = Vec::new();
            process_drift(
                &raw,
                &path_map,
                None,
                &mut db,
                &DriftClassifier::new(),
                &DriftRateLimiter::new(),
                None,
                None,
                Some(&mut out),
            )
            .unwrap();
            match out.pop() {
                Some(Event::Fim(fe)) => (fe.file_key, fe.moved_in, fe.is_dir),
                other => panic!("expected one FIM event, got {other:?}"),
            }
        };
        // created, read before it exists
        assert_eq!(run(child(b"tmp.A", FimOp::Created)), (None, false, false));
        std::fs::write(spool.join("tmp.A"), b"* * * * * true\n").unwrap();
        let tmp = key_for_path(&spool.join("tmp.A")).unwrap();
        // created, read once there
        assert_eq!(
            run(child(b"tmp.A", FimOp::Created)),
            (Some(tmp), false, false)
        );
        // a write of the enrolled file: its own inode
        assert_eq!(
            run(fake_raw(tmp.dev, tmp.ino, FimOp::Modified as u8)).0,
            Some(tmp)
        );
        // moved over the old crontab, read before the rename landed
        assert_eq!(run(child(b"nn", FimOp::Renamed)), (None, true, false));
        std::fs::rename(spool.join("tmp.A"), spool.join("nn")).unwrap();
        // … and after: the temporary file's inode
        assert_eq!(run(child(b"nn", FimOp::Renamed)), (Some(tmp), true, false));
        // the spool directory's own setattr
        assert_eq!(
            run(fake_raw(dir_key.dev, dir_key.ino, FimOp::Modified as u8)),
            (Some(dir_key), false, true)
        );
    }

    /// NN-AUD-285, end to end: the events the drain emits for a `crontab`
    /// install (each read at its worst moment) give NN-L-FIM-007 one
    /// verdict, and those of two drop-ins written by one process (`cp a b
    /// /etc/cron.d/`) two — whether or not the drain read them in time.
    /// The temp directory stands for the cron directory.
    #[test]
    fn a_crontab_install_is_one_verdict_and_two_dropins_are_two() {
        use crate::decision::Rule;
        let dir = TempDir::new().unwrap();
        let mut db = drift_db_in(&dir);
        let path_map = InodePathMap::new();
        let watched = |name: &str, ino: u64| {
            let d = dir.path().join(name);
            std::fs::create_dir(&d).unwrap();
            let key = InodeKey { dev: 0x42, ino };
            path_map.insert(key, d.to_string_lossy().into_owned());
            (d, key)
        };
        let (spool, spool_key) = watched("crontabs", 1);
        let (crond, crond_key) = watched("cron.d", 2);
        std::fs::write(spool.join("nn"), b"# old\n").unwrap();
        let old = key_for_path(&spool.join("nn")).unwrap();
        path_map.insert(old, spool.join("nn").to_string_lossy().into_owned());
        let child = |key: InodeKey, leaf: &[u8], op: FimOp| {
            let mut raw = fake_raw(key.dev, key.ino, op as u8);
            raw.child_name[..leaf.len()].copy_from_slice(leaf);
            raw
        };
        let as_cron = |mut fe: FimEvent| {
            fe.path = fe
                .path
                .replace(&*spool.to_string_lossy(), "/var/spool/cron/crontabs")
                .replace(&*crond.to_string_lossy(), "/etc/cron.d");
            Event::Fim(fe)
        };
        let run = |raw: FimDriftRaw, db: &mut FimDriftDb| -> Event {
            let mut out = Vec::new();
            process_drift(
                &raw,
                &path_map,
                None,
                db,
                &DriftClassifier::new(),
                &DriftRateLimiter::new(),
                None,
                None,
                Some(&mut out),
            )
            .unwrap();
            match out.pop() {
                Some(Event::Fim(fe)) => as_cron(fe),
                other => panic!("expected one FIM event, got {other:?}"),
            }
        };
        let mut install = Vec::new();
        install.push(run(child(spool_key, b"tmp.B", FimOp::Created), &mut db));
        std::fs::write(spool.join("tmp.B"), b"* * * * * true\n").unwrap();
        retry_pending_enrollments(&path_map, None);
        let tmp = key_for_path(&spool.join("tmp.B")).unwrap();
        install.push(run(
            fake_raw(tmp.dev, tmp.ino, FimOp::Modified as u8),
            &mut db,
        ));
        install.push(run(child(spool_key, b"nn", FimOp::Renamed), &mut db));
        std::fs::rename(spool.join("tmp.B"), spool.join("nn")).unwrap();
        install.push(run(
            fake_raw(tmp.dev, tmp.ino, FimOp::Modified as u8),
            &mut db,
        ));
        install.push(run(
            fake_raw(spool_key.dev, spool_key.ino, FimOp::Modified as u8),
            &mut db,
        ));
        let rule = crate::fim::rules::NnLFim007CronDropInCreated::with_fresh_window();
        let fired = install
            .iter()
            .filter(|e| rule.evaluate(e).is_some())
            .count();
        assert_eq!(fired, 1, "one crontab install: {install:#?}");

        for early in [false, true] {
            let rule = crate::fim::rules::NnLFim007CronDropInCreated::with_fresh_window();
            let mut fired = Vec::new();
            for leaf in ["job-a", "job-b"] {
                let leaf = if early {
                    format!("{leaf}-early")
                } else {
                    leaf.to_string()
                };
                if !early {
                    std::fs::write(crond.join(&leaf), b"* * * * * root true\n").unwrap();
                }
                let e = run(child(crond_key, leaf.as_bytes(), FimOp::Created), &mut db);
                if let Some(v) = rule.evaluate(&e) {
                    fired.push(v.event_filename);
                }
            }
            assert_eq!(
                fired.len(),
                2,
                "two drop-ins (read early: {early}): {fired:?}"
            );
        }
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

    fn drift_db_in(dir: &TempDir) -> FimDriftDb {
        FimDriftDb::open(
            &dir.path().join("drift.jsonl"),
            fresh_signing_key(dir),
            [0u8; 16],
            std::sync::Arc::new(crate::chainlog::NoProtection),
            crate::chainlog::RotationConfig::default(),
        )
        .unwrap()
    }

    fn drift_rows(dir: &TempDir) -> Vec<serde_json::Value> {
        std::fs::read_to_string(dir.path().join("drift.jsonl"))
            .unwrap_or_default()
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect()
    }

    fn content_baseline(path: &str) -> BaselineEntry {
        let row = compute_baseline(Path::new(path))
            .unwrap()
            .into_iter()
            .find(|d| !d.is_symlink)
            .unwrap();
        let mut b = dummy_baseline(path, &row.sha256);
        b.mode = row.mode;
        b.uid = row.uid;
        b.gid = row.gid;
        b.size_bytes = row.size_bytes;
        b
    }

    /// External audit NN-AUD-119 (FIMP-007): a path queued again is one
    /// entry, the queue stops at its cap (the rest counted), and putting
    /// entries back after a pass keeps the cap.
    #[test]
    fn pending_queues_are_deduplicated_and_capped() {
        let mut q: RetryQueue<String, Instant> = RetryQueue::new("test", PENDING_MAX);
        let t0 = Instant::now();
        for _ in 0..10_000 {
            assert!(q.push("/etc/cron.d/tmp.same".to_string(), t0));
        }
        assert_eq!(q.len(), 1, "one entry per path");
        for i in 0..10_000 {
            q.push(format!("/etc/cron.d/tmp.{i}"), t0);
        }
        assert_eq!(q.len(), PENDING_MAX, "capped where it grows");
        assert_eq!(q.dropped, 10_001 - PENDING_MAX as u64);
        let taken = q.take();
        assert!(q.is_empty());
        q.push("/etc/cron.d/new".to_string(), t0);
        q.put_back(taken);
        assert_eq!(q.len(), PENDING_MAX, "put back within the cap");

        // the drain's own queues: a child whose file is not there yet,
        // reported twice, waits once; a rename seen twice merges the
        // replacement the second one carries
        let dir = TempDir::new().unwrap();
        let mut db = drift_db_in(&dir);
        let watched_dir = dir.path().join("cron.d");
        std::fs::create_dir(&watched_dir).unwrap();
        let dir_key = InodeKey { dev: 0x77, ino: 70 };
        let path_map = InodePathMap::new();
        path_map.insert(dir_key, watched_dir.to_string_lossy().into_owned());
        let mut raw = fake_raw(dir_key.dev, dir_key.ino, FimOp::Created as u8);
        raw.child_name[..6].copy_from_slice(b"tmp.ab");
        for _ in 0..3 {
            process_drift(
                &raw,
                &path_map,
                None,
                &mut db,
                &DriftClassifier::new(),
                &DriftRateLimiter::new(),
                None,
                None,
                None,
            )
            .unwrap();
        }
        assert_eq!(queues(|q| q.enroll.len()), 1);
        let watched = dir.path().join("sshd_config");
        std::fs::write(&watched, b"x").unwrap();
        let key = key_for_path(&watched).unwrap();
        path_map.insert(key, watched.to_string_lossy().into_owned());
        let plain = fake_raw(key.dev, key.ino, FimOp::Renamed as u8);
        let mut over = plain;
        over.op_flags = FIM_RENAME_REPLACED;
        for r in [&plain, &over, &plain] {
            process_drift(
                r,
                &path_map,
                None,
                &mut db,
                &DriftClassifier::new(),
                &DriftRateLimiter::new(),
                None,
                None,
                None,
            )
            .unwrap();
        }
        let renames = queues(|q| q.rename.take());
        assert_eq!(renames.len(), 1, "one entry per inode");
        assert!(renames[&key].replaced.is_some(), "the replacement is kept");
        let _ = queues(|q| q.enroll.take());
    }

    /// External audit NN-AUD-119 (FIMP-007): however many events a burst
    /// brings, the retry pass — one `stat` per waiting entry — runs at
    /// most once per RETRY_EVERY. It ran once per loop turn, and the loop
    /// turns after every event that emits.
    #[test]
    fn retry_pass_runs_at_most_every_5ms() {
        let dir = TempDir::new().unwrap();
        let path_map = InodePathMap::new();
        let t0 = Instant::now();
        queues(|q| {
            for i in 0..100 {
                let gone = dir.path().join(format!("short-lived.{i}"));
                q.enroll.push(gone.to_string_lossy().into_owned(), t0);
            }
        });
        let mut pacer = Pacer::new(RETRY_EVERY);
        let mut examined = 0;
        let mut turn = |now: Instant, examined: &mut usize| {
            if pacer.due(now) {
                *examined += retry_pending_enrollments(&path_map, None).examined;
            }
        };
        // 10 000 events within one millisecond: one pass
        for i in 0..10_000u32 {
            turn(t0 + Duration::from_nanos(u64::from(i) * 100), &mut examined);
        }
        assert_eq!(
            examined, 100,
            "one pass over the 100 entries, not one per event"
        );
        // the next one is due RETRY_EVERY after the first
        turn(t0 + RETRY_EVERY - Duration::from_micros(1), &mut examined);
        assert_eq!(examined, 100);
        turn(t0 + RETRY_EVERY, &mut examined);
        assert_eq!(examined, 200);
        let _ = queues(|q| q.enroll.take());
    }

    /// External audit NN-AUD-120 (FIMP-008): with the kernel map full,
    /// room is made by evicting the oldest runtime children — never a
    /// configured path, a symlink hop or a decoy — and a watch that cannot
    /// be placed is refused (reported), not silently dropped.
    #[test]
    fn configured_and_decoy_entries_are_never_evicted() {
        let key = |i: u64| InodeKey { dev: 9, ino: i };
        let path_map = InodePathMap::with_child_cap(4);
        let wp = parking_lot::Mutex::new(WatchedPathsHandle::fake(8));
        let protected = [
            (1, WatchClass::Configured),
            (2, WatchClass::Configured),
            (3, WatchClass::Configured),
            (4, WatchClass::ChainHop),
            (5, WatchClass::Decoy),
        ];
        for (i, class) in protected {
            assert!(watch_inode(
                key(i),
                &format!("/p/{i}"),
                class,
                &path_map,
                Some(&wp)
            ));
        }
        for i in 100..120 {
            assert!(
                watch_inode(
                    key(i),
                    &format!("/d/{i}"),
                    WatchClass::RuntimeChild,
                    &path_map,
                    Some(&wp)
                ),
                "a new child makes room for itself"
            );
        }
        for (i, _) in protected {
            assert!(path_map.lookup(&key(i)).is_some() && wp.lock().holds(&key(i)));
        }
        // the 3 newest children hold the 3 free slots
        assert_eq!(path_map.child_count(), 3);
        assert!((117..120).all(|i| wp.lock().holds(&key(i))));
        assert!(!wp.lock().holds(&key(116)) && path_map.lookup(&key(116)).is_none());
        // a decoy deployed now evicts a child, not a configured path
        assert!(watch_inode(
            key(6),
            "/p/decoy2",
            WatchClass::Decoy,
            &path_map,
            Some(&wp)
        ));
        assert!(!wp.lock().holds(&key(117)), "the oldest child made room");
        // only protected entries left once the children are gone: refused
        assert!(watch_inode(
            key(7),
            "/p/7",
            WatchClass::Configured,
            &path_map,
            Some(&wp)
        ));
        assert!(watch_inode(
            key(8),
            "/p/8",
            WatchClass::Configured,
            &path_map,
            Some(&wp)
        ));
        assert_eq!(path_map.child_count(), 0);
        let refused_before = WATCH_PRESSURE.lock().refused;
        assert!(!watch_inode(
            key(9),
            "/p/decoy3",
            WatchClass::Decoy,
            &path_map,
            Some(&wp)
        ));
        assert!(WATCH_PRESSURE.lock().refused > refused_before, "counted");
        for (i, _) in protected {
            assert!(wp.lock().holds(&key(i)), "never evicted");
        }
        // a refused child is not kept as if it were watched
        assert!(!watch_inode(
            key(200),
            "/d/200",
            WatchClass::RuntimeChild,
            &path_map,
            Some(&wp)
        ));
        assert!(path_map.lookup(&key(200)).is_none());
        // a child never takes over an inode a configured path holds
        let _ = path_map.insert_as(key(1), "/d/x".into(), WatchClass::RuntimeChild);
        assert_eq!(path_map.lookup(&key(1)).as_deref(), Some("/p/1"));
        assert_eq!(path_map.class_of(&key(1)), Some(WatchClass::Configured));
    }

    /// External audit NN-AUD-120 (FIMP-008): runtime children are held
    /// within their cap, oldest out first (out of the kernel map too), and
    /// the periodic sweep drops those whose file is gone — a Deleted event
    /// lost in the ring left them watched for good.
    #[test]
    fn runtime_children_are_capped_and_gcd() {
        let dir = TempDir::new().unwrap();
        let path_map = InodePathMap::with_child_cap(4);
        let wp = parking_lot::Mutex::new(WatchedPathsHandle::fake(64));
        let conf = dir.path().join("sshd_config");
        std::fs::write(&conf, b"x").unwrap();
        assert!(enroll_path(
            &conf.to_string_lossy(),
            WatchClass::Configured,
            &path_map,
            Some(&wp)
        ));
        let mut kids = Vec::new();
        for i in 0..6 {
            let f = dir.path().join(format!("drop.{i}"));
            std::fs::write(&f, b"payload").unwrap();
            assert!(enroll_path(
                &f.to_string_lossy(),
                WatchClass::RuntimeChild,
                &path_map,
                Some(&wp)
            ));
            kids.push(key_for_path(&f).unwrap());
        }
        assert_eq!(path_map.child_count(), 4);
        for k in &kids[..2] {
            assert!(
                path_map.lookup(k).is_none() && !wp.lock().holds(k),
                "oldest out"
            );
        }
        for k in &kids[2..] {
            assert!(path_map.lookup(k).is_some() && wp.lock().holds(k));
        }
        std::fs::remove_file(dir.path().join("drop.2")).unwrap();
        std::fs::remove_file(dir.path().join("drop.3")).unwrap();
        std::fs::remove_file(&conf).unwrap();
        assert_eq!(gc_runtime_children(&path_map, Some(&wp)), 2);
        assert_eq!(path_map.child_count(), 2);
        assert!(!wp.lock().holds(&kids[2]) && !wp.lock().holds(&kids[3]));
        assert!(wp.lock().holds(&kids[4]) && wp.lock().holds(&kids[5]));
        // the sweep is for runtime children only
        assert!(path_map
            .lookup(&key_for_path(dir.path()).unwrap())
            .is_none());
        assert_eq!(path_map.len(), 3, "the configured path stays");
    }

    /// External audit NN-AUD-120 (FIMP-008): a full watch set is an ERROR
    /// at most once a minute and a signed record at most once an hour, each
    /// with the totals since boot.
    #[test]
    fn full_map_is_attested_once_per_hour() {
        let mut p = WatchPressure::new();
        let t0 = Instant::now();
        assert_eq!(p.note(1, 0, t0), (true, true), "the first one says so");
        assert_eq!(p.note(1, 0, t0 + Duration::from_secs(30)), (false, false));
        assert_eq!(p.note(0, 1, t0 + Duration::from_secs(61)), (true, false));
        for m in 2..60 {
            let (_, attest) = p.note(1, 0, t0 + Duration::from_secs(m * 60));
            assert!(!attest, "minute {m}");
        }
        assert_eq!(p.note(0, 1, t0 + Duration::from_secs(3600)), (true, true));
        assert_eq!((p.evicted, p.refused), (60, 2), "totals since boot");
        // the signed record names the condition and carries the counts
        let draft = watch_map_full_draft(60, 2, 4096, 4096);
        assert_eq!(draft.op, crate::self_integrity::AUDIT_OP);
        assert_eq!(draft.extra["kind"], "subsystem_degraded");
        assert_eq!(draft.extra["reason"], "fim_watch_map_full");
        assert_eq!(draft.extra["evicted"], 60);
        assert_eq!(draft.extra["refused"], 2);
        assert!(draft.extra["detail"]
            .as_str()
            .unwrap()
            .starts_with("fim_watch_map_full"));
    }

    /// A regular, readable file a Critical rule guards (a system binary).
    /// Ubuntu 26.04's coreutils (uutils, one multicall binary) make `env`
    /// and `true` symlinks; `bash` is a regular file on every distro.
    fn critical_system_file() -> String {
        [
            "/usr/bin/env",
            "/usr/bin/true",
            "/bin/true",
            "/usr/bin/bash",
            "/bin/bash",
        ]
        .iter()
        .find(|p| {
            crate::fim::rules::is_critical_rule_path(p)
                && std::fs::symlink_metadata(p).is_ok_and(|m| m.is_file())
        })
        .expect("a system binary to read")
        .to_string()
    }

    /// External audit NN-AUD-121 (FIMP-009): a write on a critical path
    /// whose re-hash finds the baseline content — the shape of a change
    /// undone before the drain looked — leaves a flagged row, not nothing;
    /// still no verdict.
    #[test]
    fn unchanged_hash_on_a_critical_path_is_still_recorded() {
        let dir = TempDir::new().unwrap();
        let mut db = drift_db_in(&dir);
        let path = critical_system_file();
        let baseline = content_baseline(&path);
        let key = InodeKey { dev: 0x51, ino: 5 };
        let path_map = InodePathMap::new();
        path_map.insert(key, path.clone());
        let mut out = Vec::new();
        for op in [FimOp::Modified, FimOp::Modified, FimOp::Created] {
            let emitted = process_drift(
                &fake_raw(key.dev, key.ino, op as u8),
                &path_map,
                Some(&baseline),
                &mut db,
                &DriftClassifier::new(),
                &DriftRateLimiter::new(),
                None,
                None,
                Some(&mut out),
            )
            .unwrap();
            assert!(!emitted, "no verdict on content that matches");
        }
        assert!(out.is_empty());
        let rows = drift_rows(&dir);
        assert_eq!(rows.len(), 3, "one row per write");
        for row in &rows {
            assert_eq!(row["path"], path.as_str());
            assert_eq!(row["skip_reason"], CONTENT_RESTORED);
            assert_eq!(row["decision_engine_skipped"], true);
            assert_eq!(row["new_sha256"], row["baseline_sha256"]);
        }
    }

    /// External audit NN-AUD-121 (FIMP-009): elsewhere a write that leaves
    /// the content as baselined (a `touch`) stays the no-op it was.
    #[test]
    fn touch_on_a_non_critical_path_is_still_suppressed() {
        let dir = TempDir::new().unwrap();
        let mut db = drift_db_in(&dir);
        let f = dir.path().join("hosts.allow");
        std::fs::write(&f, b"sshd: 10.0.0.0/8\n").unwrap();
        let path = f.to_string_lossy().into_owned();
        assert!(!crate::fim::rules::is_critical_rule_path(&path));
        let key = key_for_path(&f).unwrap();
        let path_map = InodePathMap::new();
        path_map.insert(key, path.clone());
        let emitted = process_drift(
            &fake_raw(key.dev, key.ino, FimOp::Modified as u8),
            &path_map,
            Some(&content_baseline(&path)),
            &mut db,
            &DriftClassifier::new(),
            &DriftRateLimiter::new(),
            None,
            None,
            None,
        )
        .unwrap();
        assert!(!emitted);
        assert!(drift_rows(&dir).is_empty(), "no row for a touch");
    }

    /// External audit NN-AUD-122 (FIMP-010): an in-place edit of the file
    /// behind a watched symlink (`python3` -> `python3.12`) is drift of the
    /// watched path, compared with its content row. Only the link's inode
    /// was watched, so the edit produced no event at all.
    #[test]
    fn an_edit_of_the_target_behind_a_watched_link_is_drift_of_the_link() {
        let dir = TempDir::new().unwrap();
        let mut db = drift_db_in(&dir);
        let target = dir.path().join("python3.12");
        std::fs::write(&target, b"ELF 3.12").unwrap();
        let link = dir.path().join("python3");
        std::os::unix::fs::symlink("python3.12", &link).unwrap();
        let link_s = link.to_string_lossy().into_owned();
        let path_map = InodePathMap::new();
        let wp = parking_lot::Mutex::new(WatchedPathsHandle::fake(64));
        assert!(enroll_path(
            &link_s,
            WatchClass::Configured,
            &path_map,
            Some(&wp)
        ));
        let tkey = key_for_path(&target).unwrap();
        assert!(wp.lock().holds(&tkey), "the target is watched");
        assert_eq!(path_map.lookup(&tkey).as_deref(), Some(link_s.as_str()));
        assert_eq!(path_map.class_of(&tkey), Some(WatchClass::ChainHop));
        let baseline = content_baseline(&link_s);
        // append a byte in place
        use std::io::Write;
        std::fs::OpenOptions::new()
            .append(true)
            .open(&target)
            .unwrap()
            .write_all(b"X")
            .unwrap();
        let mut out = Vec::new();
        let emitted = process_drift(
            &fake_raw(tkey.dev, tkey.ino, FimOp::Modified as u8),
            &path_map,
            Some(&baseline),
            &mut db,
            &DriftClassifier::new(),
            &DriftRateLimiter::new(),
            Some(&wp),
            None,
            Some(&mut out),
        )
        .unwrap();
        assert!(emitted);
        let Event::Fim(fe) = &out[0] else {
            panic!("{out:?}")
        };
        assert_eq!(fe.path, link_s);
        assert_eq!(fe.op, FimOp::Modified);
        assert_eq!(fe.new_sha256, Some(Sha256::digest(b"ELF 3.12X").into()));
    }

    /// External audit NN-AUD-122 (FIMP-010): a link in the middle of the
    /// chain re-pointed (`ln -sfn` over `/etc/alternatives/nc`) is drift of
    /// the watched path once it has landed, attributed to the writer; the
    /// new chain is watched and the old link no longer is. A target removed
    /// and put back is watched again when it is back.
    #[test]
    fn a_repointed_link_in_the_chain_is_drift_of_the_watched_path() {
        let dir = TempDir::new().unwrap();
        let mut db = drift_db_in(&dir);
        let d = dir.path();
        std::fs::create_dir(d.join("alternatives")).unwrap();
        std::fs::write(d.join("nc.openbsd"), b"netcat").unwrap();
        std::fs::write(d.join("evil"), b"a backdoor").unwrap();
        std::os::unix::fs::symlink(d.join("nc.openbsd"), d.join("alternatives/nc")).unwrap();
        std::os::unix::fs::symlink(d.join("alternatives/nc"), d.join("nc")).unwrap();
        let nc = d.join("nc").to_string_lossy().into_owned();
        let path_map = InodePathMap::new();
        let wp = parking_lot::Mutex::new(WatchedPathsHandle::fake(64));
        assert!(enroll_path(
            &nc,
            WatchClass::Configured,
            &path_map,
            Some(&wp)
        ));
        let baseline = content_baseline(&nc);
        let old_alt = key_for_path(&d.join("alternatives/nc")).unwrap();
        let old_target = key_for_path(&d.join("nc.openbsd")).unwrap();
        assert_eq!(path_map.chain(&nc), vec![old_alt, old_target]);

        // ln -sfn: a new link renamed over the old one; the hook fires
        // before the rename lands
        let mut raw = fake_raw(old_alt.dev, old_alt.ino, FimOp::Renamed as u8);
        raw.op_flags = FIM_RENAME_REPLACED;
        raw.modifier_pid = 4343;
        raw.modifier_comm = *b"ln\0\0\0\0\0\0\0\0\0\0\0\0\0\0";
        let run = |raw: &FimDriftRaw, db: &mut FimDriftDb, out: &mut Vec<Event>| {
            process_drift(
                raw,
                &path_map,
                Some(&baseline),
                db,
                &DriftClassifier::new(),
                &DriftRateLimiter::new(),
                Some(&wp),
                None,
                Some(out),
            )
            .unwrap()
        };
        let mut out = Vec::new();
        assert!(!run(&raw, &mut db, &mut out), "checked once it has landed");
        assert!(
            retry_pending_enrollments(&path_map, Some(&wp)).waiting,
            "not landed yet"
        );
        assert!(replacement_raws().is_empty());
        std::os::unix::fs::symlink(d.join("evil"), d.join("alternatives/nc.tmp")).unwrap();
        std::fs::rename(d.join("alternatives/nc.tmp"), d.join("alternatives/nc")).unwrap();
        retry_pending_enrollments(&path_map, Some(&wp));
        let new_alt = key_for_path(&d.join("alternatives/nc")).unwrap();
        let evil = key_for_path(&d.join("evil")).unwrap();
        assert_eq!(path_map.chain(&nc), vec![new_alt, evil], "the new chain");
        assert!(wp.lock().holds(&new_alt) && wp.lock().holds(&evil));
        assert!(!wp.lock().holds(&old_alt) && path_map.lookup(&old_alt).is_none());
        assert!(
            !wp.lock().holds(&old_target),
            "nc.openbsd is no longer behind it"
        );
        let checks = replacement_raws();
        assert_eq!(checks.len(), 1);
        assert!(run(&checks[0], &mut db, &mut out));
        let Event::Fim(fe) = &out[0] else {
            panic!("{out:?}")
        };
        assert_eq!((fe.path.as_str(), fe.op), (nc.as_str(), FimOp::Modified));
        assert_eq!((fe.modifier_pid, fe.modifier_comm.as_str()), (4343, "ln"));
        assert_eq!(fe.new_sha256, Some(Sha256::digest(b"a backdoor").into()));

        // the target removed: drift (nothing is reachable), and watched
        // again once it is back
        std::fs::remove_file(d.join("evil")).unwrap();
        assert!(!run(
            &fake_raw(evil.dev, evil.ino, FimOp::Deleted as u8),
            &mut db,
            &mut out
        ));
        retry_pending_enrollments(&path_map, Some(&wp));
        assert_eq!(path_map.chain(&nc), vec![new_alt]);
        assert!(awaiting_returns(), "waits for the target");
        std::fs::write(d.join("evil"), b"back").unwrap();
        let back = repaired_chains(&path_map, Some(&wp));
        assert_eq!(back, vec![key_for_path(&d.join("nc")).unwrap()]);
        let evil = key_for_path(&d.join("evil")).unwrap();
        assert!(wp.lock().holds(&evil));
        assert!(!awaiting_returns());
        let _ = replacement_raws();

        // the watched link itself removed: the chain behind it goes too,
        // and comes back with it
        let own = key_for_path(&d.join("nc")).unwrap();
        std::fs::remove_file(d.join("nc")).unwrap();
        run(
            &fake_raw(own.dev, own.ino, FimOp::Deleted as u8),
            &mut db,
            &mut out,
        );
        assert!(path_map.chain(&nc).is_empty());
        assert!(!wp.lock().holds(&evil) && !wp.lock().holds(&new_alt));
        std::os::unix::fs::symlink(d.join("alternatives/nc"), d.join("nc")).unwrap();
        assert!(enroll_path(
            &nc,
            WatchClass::Configured,
            &path_map,
            Some(&wp)
        ));
        assert_eq!(path_map.chain(&nc), vec![new_alt, evil]);
    }

    /// External audit NN-AUD-122 (FIMP-010): two watched links through one
    /// target (`iptables`, `ip6tables` -> `xtables-nft-multi`): one
    /// re-pointed away leaves the target watched for the other.
    #[test]
    fn a_target_shared_by_two_watched_links_stays_watched() {
        let dir = TempDir::new().unwrap();
        let d = dir.path();
        std::fs::write(d.join("xtables-nft-multi"), b"ELF").unwrap();
        std::fs::write(d.join("other"), b"ELF2").unwrap();
        std::os::unix::fs::symlink(d.join("xtables-nft-multi"), d.join("iptables")).unwrap();
        std::os::unix::fs::symlink(d.join("xtables-nft-multi"), d.join("ip6tables")).unwrap();
        let path_map = InodePathMap::new();
        let wp = parking_lot::Mutex::new(WatchedPathsHandle::fake(64));
        for l in ["iptables", "ip6tables"] {
            assert!(enroll_path(
                &d.join(l).to_string_lossy(),
                WatchClass::Configured,
                &path_map,
                Some(&wp)
            ));
        }
        let shared = key_for_path(&d.join("xtables-nft-multi")).unwrap();
        std::fs::remove_file(d.join("ip6tables")).unwrap();
        std::os::unix::fs::symlink(d.join("other"), d.join("ip6tables")).unwrap();
        enroll_chain(&d.join("ip6tables").to_string_lossy(), &path_map, Some(&wp));
        assert!(wp.lock().holds(&shared), "still behind iptables");
        assert_eq!(
            path_map.lookup(&shared).as_deref(),
            Some(d.join("iptables").to_string_lossy().as_ref())
        );
    }

    /// External audit NN-AUD-120 (FIMP-008): a file renamed within a
    /// watched directory (`tmp.X` to its final name) is enrolled under the
    /// new name by the directory's event; settling the rename of the old
    /// name afterwards used to drop the inode, so the file's later in-place
    /// edits went unseen.
    #[test]
    fn a_child_renamed_within_a_watched_directory_stays_watched() {
        let dir = TempDir::new().unwrap();
        let mut db = drift_db_in(&dir);
        let watched_dir = dir.path().join("system");
        std::fs::create_dir(&watched_dir).unwrap();
        let dir_key = InodeKey { dev: 0x88, ino: 8 };
        let path_map = InodePathMap::new();
        path_map.insert(dir_key, watched_dir.to_string_lossy().into_owned());
        let created = |leaf: &[u8], op: FimOp| {
            let mut raw = fake_raw(dir_key.dev, dir_key.ino, op as u8);
            raw.child_name[..leaf.len()].copy_from_slice(leaf);
            raw
        };
        let run = |raw: &FimDriftRaw, db: &mut FimDriftDb| {
            process_drift(
                raw,
                &path_map,
                None,
                db,
                &DriftClassifier::new(),
                &DriftRateLimiter::new(),
                None,
                None,
                None,
            )
            .unwrap()
        };
        std::fs::write(watched_dir.join("tmp.X"), b"[Service]\n").unwrap();
        run(&created(b"tmp.X", FimOp::Created), &mut db);
        let key = key_for_path(&watched_dir.join("tmp.X")).unwrap();
        assert_eq!(path_map.class_of(&key), Some(WatchClass::RuntimeChild));
        // the rename of the watched child, seen before it lands
        run(&fake_raw(key.dev, key.ino, FimOp::Renamed as u8), &mut db);
        std::fs::rename(watched_dir.join("tmp.X"), watched_dir.join("evil.service")).unwrap();
        // the directory's event for the new name, then the retry
        run(&created(b"evil.service", FimOp::Renamed), &mut db);
        retry_pending_enrollments(&path_map, None);
        assert_eq!(
            path_map.lookup(&key).as_deref(),
            Some(watched_dir.join("evil.service").to_string_lossy().as_ref()),
            "still watched under its new name"
        );
    }

    /// Lab PR 225: the rename of a watched file, as `process_drift` turns
    /// it into the event NN-L-FIM-010 reads. `leaf`: the new name the
    /// kernel carried (`FIM_RENAME_DEST_LEAF`), or `None` for the wire shape
    /// of the starting tree (the destination directory's key only).
    fn renamed_watched_file(leaf: Option<&[u8]>) -> (TempDir, Vec<Event>) {
        let dir = TempDir::new().unwrap();
        let drift_db = parking_lot::Mutex::new(
            FimDriftDb::open(
                &dir.path().join("drift.jsonl"),
                fresh_signing_key(&dir),
                [0u8; 16],
                std::sync::Arc::new(crate::chainlog::NoProtection),
                crate::chainlog::RotationConfig::default(),
            )
            .unwrap(),
        );
        let data = dir.path().join("data");
        std::fs::create_dir(&data).unwrap();
        let x = data.join("x");
        std::fs::write(&x, b"quarterly report").unwrap();
        let file_key = key_for_path(&x).unwrap();
        let dir_key = key_for_path(&data).unwrap();
        // The file is watched (fim-paths.local), its directory is not.
        let path_map = InodePathMap::new();
        path_map.insert(file_key, x.to_string_lossy().into_owned());
        // The rename has landed when the drain reads the record.
        std::fs::rename(&x, data.join("x.locked")).unwrap();
        let mut raw = fake_raw(file_key.dev, file_key.ino, FimOp::Renamed as u8);
        raw.dest_dev = dir_key.dev;
        raw.dest_ino = dir_key.ino;
        raw.modifier_pid = 4343;
        if let Some(leaf) = leaf {
            raw.op_flags = FIM_RENAME_DEST_LEAF;
            raw.child_name[..leaf.len()].copy_from_slice(leaf);
        }
        let mut out = Vec::new();
        process_drift(
            &raw,
            &path_map,
            None,
            &mut &drift_db,
            &DriftClassifier::new(),
            &DriftRateLimiter::new(),
            None,
            None,
            Some(&mut out),
        )
        .unwrap();
        (dir, out)
    }

    fn fim010_fires(out: &[Event]) -> bool {
        fim010_verdict(out).is_some_and(|a| a == common::ResponseAction::KillProcessTree)
    }

    /// NN-L-FIM-010's action on the first event it fires on.
    fn fim010_verdict(out: &[Event]) -> Option<common::ResponseAction> {
        use crate::decision::Rule as _;
        out.iter().find_map(|e| {
            crate::fim::rules::NnLFim010RansomwareExtensionRename
                .evaluate(e)
                .map(|v| v.action)
        })
    }

    /// Lab PR 225: `x → x.locked` of a watched file. The event named the
    /// destination DIRECTORY as `dest_path`, so NN-L-FIM-010 never matched
    /// `.locked`. Fails on the starting tree.
    #[test]
    fn fim010_rename_destination_is_the_new_file_not_its_directory() {
        let (dir, out) = renamed_watched_file(None);
        let want = dir.path().join("data/x.locked");
        let fe = match &out[..] {
            [Event::Fim(fe)] => fe,
            other => panic!("{other:?}"),
        };
        assert_eq!(fe.op, FimOp::Renamed);
        assert_eq!(fe.dest_path.as_deref(), Some(want.to_str().unwrap()));
        assert!(fim010_fires(&out), "x → x.locked must fire NN-L-FIM-010");
        use crate::decision::Rule as _;
        let v = crate::fim::rules::NnLFim010RansomwareExtensionRename
            .evaluate(&Event::Fim(FimEvent {
                timestamp_ns: fe.timestamp_ns + 10_000_000_000,
                ..fe.clone()
            }))
            .unwrap();
        assert!(v.reasoning.contains("x.locked"), "{}", v.reasoning);
    }

    /// Lab PR 225: the new leaf as the kernel carries it. It is the
    /// renamed file's own new name, not a file moved into a watched
    /// directory: no child reconstruction against the file's path.
    #[test]
    fn fim010_kernel_carried_leaf_names_the_destination() {
        let (dir, out) = renamed_watched_file(Some(b"x.locked"));
        let want = dir.path().join("data/x.locked");
        let fe = match &out[..] {
            [Event::Fim(fe)] => fe,
            other => panic!("{other:?}"),
        };
        assert_eq!(fe.op, FimOp::Renamed, "not normalised to a Created");
        assert_eq!(fe.path, dir.path().join("data/x").to_string_lossy());
        assert_eq!(fe.dest_path.as_deref(), Some(want.to_str().unwrap()));
        assert!(fim010_fires(&out));
    }

    /// Lab PR 225: the rename inside a watched data directory reaches the
    /// rules as the directory's `Created` of the new name (`moved_in`).
    /// NN-L-FIM-010 looked at `Renamed` only. Fails on the starting tree.
    /// The match is new: its kill is held behind the per-rule policy (off
    /// by default), the Critical record kept.
    #[test]
    fn fim010_rename_into_a_watched_directory_fires() {
        let dir = TempDir::new().unwrap();
        let drift_db = parking_lot::Mutex::new(
            FimDriftDb::open(
                &dir.path().join("drift.jsonl"),
                fresh_signing_key(&dir),
                [0u8; 16],
                std::sync::Arc::new(crate::chainlog::NoProtection),
                crate::chainlog::RotationConfig::default(),
            )
            .unwrap(),
        );
        let data = dir.path().join("vm-images");
        std::fs::create_dir(&data).unwrap();
        std::fs::write(data.join("disk.qcow2.locked"), b"ciphertext").unwrap();
        let dir_key = key_for_path(&data).unwrap();
        let path_map = InodePathMap::new();
        path_map.insert(dir_key, data.to_string_lossy().into_owned());
        let mut raw = fake_raw(dir_key.dev, dir_key.ino, FimOp::Renamed as u8);
        raw.modifier_pid = 4444;
        let leaf = b"disk.qcow2.locked";
        raw.child_name[..leaf.len()].copy_from_slice(leaf);
        let mut out = Vec::new();
        process_drift(
            &raw,
            &path_map,
            None,
            &mut &drift_db,
            &DriftClassifier::new(),
            &DriftRateLimiter::new(),
            None,
            None,
            Some(&mut out),
        )
        .unwrap();
        assert!(
            matches!(&out[..], [Event::Fim(fe)] if fe.op == FimOp::Created && fe.moved_in),
            "{out:?}"
        );
        assert_eq!(fim010_verdict(&out), Some(common::ResponseAction::Log));
    }
}
