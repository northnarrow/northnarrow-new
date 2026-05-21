//! Tappa 10.6 (D3) — `CorrelationStore`.
//!
//! Generalises the T10.5 D5 `ChainCorrelationBuffer` (same-PID,
//! single-precursor, timestamp-only) into the engine's shared
//! correlation state, per design §4.2 / §13 Q3 (single-pass, deferred
//! store — the `Rule::evaluate` contract is unchanged; chain rules hold
//! an `Arc<Mutex<CorrelationStore>>` and record/query through it).
//!
//! What D3 adds over the old buffer:
//!
//! - **Typed precursors.** One shared store records *kinds*
//!   ([`PrecursorKind`]) instead of one buffer per rule, so different
//!   chain rules stay isolated by kind while sharing memory + eviction.
//! - **N-event sequences.** [`CorrelationStore::has_sequence`] matches
//!   an ordered list of precursor kinds within a window — the
//!   foundation for the D6 multi-step kill chains (CHAIN-004..008).
//! - **(pid, start_ns) keying.** Entries key on [`ProcKey`] so a
//!   recycled PID (same number, new `start_time`) is a *distinct*
//!   process (§13 Q2). D3 records the **structure** and exercises it in
//!   tests; the pid-based convenience API resolves to `start_ns = 0`
//!   ("incarnation unknown") until **D4** wires the ancestry tree's
//!   pid→start_ns resolution. Same-PID behaviour is therefore
//!   bit-for-bit preserved this commit.
//! - **Per-rule window.** Each query passes its own `window_ns`
//!   (§13 Q4 — 300 s default, configurable per rule).
//!
//! Memory is bounded exactly as the old buffer was: a per-process ring
//! capped at [`MAX_EVENTS_PER_PROC`], a tracked-process cap of
//! [`MAX_TRACKED_PROCS`] with stale-first eviction, and TTL pruning on
//! every access.

use std::collections::{HashMap, VecDeque};

use super::ancestry::AncestryTree;

/// Default correlation lookback (§13 Q4). Rules may pass a different
/// `window_ns`; this is the value the migrated CHAIN-001..003 use,
/// matching the T10.5 5-minute precedent.
pub const CORRELATION_WINDOW_NS: u64 = 300 * 1_000_000_000;

/// Per-process precursor ring cap. A process that re-triggers the same
/// precursor many times only needs the most recent few to answer
/// "any/which precursor in window?".
const MAX_EVENTS_PER_PROC: usize = 16;

/// Distinct-process cap. On overflow, stale (fully out-of-window)
/// processes are pruned first.
const MAX_TRACKED_PROCS: usize = 4096;

/// PID-reuse-safe process identity (§13 Q2). `start_ns` is the task's
/// `start_time` (CLOCK_MONOTONIC ns, captured by the D2 BPF refit);
/// `start_ns == 0` means "incarnation unknown" (the D3 pid-based API,
/// until D4 resolves it from the ancestry tree).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct ProcKey {
    pub pid: u32,
    pub start_ns: u64,
}

impl ProcKey {
    /// Key for a bare PID whose incarnation is not yet resolved.
    pub fn unresolved(pid: u32) -> Self {
        Self { pid, start_ns: 0 }
    }
}

/// The kind of precursor a chain rule records. Isolated by kind so a
/// credential read never satisfies a `/tmp`-exec query. Extensible:
/// D6 multi-step chains add their own kinds.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum PrecursorKind {
    /// NN-L-CHAIN-001 — credential-store FIM access (T1555).
    CredRead,
    /// NN-L-CHAIN-002 — process image executed from `/tmp/` (T1059).
    TmpExec,
    /// NN-L-CHAIN-003 — deception canary trip.
    CanaryTrip,
}

#[derive(Clone, Copy)]
struct Precursor {
    kind: PrecursorKind,
    ts_ns: u64,
}

/// Shared correlation state. `Arc<Mutex<_>>`-wrapped by the engine and
/// queried from `Rule::evaluate`.
#[derive(Default)]
pub struct CorrelationStore {
    per_proc: HashMap<ProcKey, VecDeque<Precursor>>,
    /// FIFO insertion order of keys, for stale-first overflow eviction.
    eviction: VecDeque<ProcKey>,
    /// D4 — parent→child lineage for cross-PID correlation.
    tree: AncestryTree,
}

impl CorrelationStore {
    pub fn new() -> Self {
        Self::default()
    }

    // ── recording ───────────────────────────────────────────────────

    /// Record a `kind` precursor for an explicit [`ProcKey`].
    pub fn record(&mut self, key: ProcKey, kind: PrecursorKind, ts_ns: u64) {
        if self.per_proc.len() >= MAX_TRACKED_PROCS && !self.per_proc.contains_key(&key) {
            self.prune_stale(ts_ns);
        }
        let is_new = !self.per_proc.contains_key(&key);
        let q = self.per_proc.entry(key).or_default();
        q.push_back(Precursor { kind, ts_ns });
        while q.len() > MAX_EVENTS_PER_PROC {
            q.pop_front();
        }
        if is_new {
            self.eviction.push_back(key);
        }
    }

    /// Record for a bare PID (incarnation unknown — D3 same-PID path).
    /// D4 overrides the resolution to consult the ancestry tree.
    pub fn record_for_pid(&mut self, pid: u32, kind: PrecursorKind, ts_ns: u64) {
        self.record(ProcKey::unresolved(pid), kind, ts_ns);
    }

    // ── querying ─────────────────────────────────────────────────────

    /// `true` if `key` has a `kind` precursor within `window_ns` at or
    /// before `now_ns`. Prunes out-of-window entries; drops the key
    /// when its ring empties.
    pub fn has_recent(
        &mut self,
        key: ProcKey,
        kind: PrecursorKind,
        now_ns: u64,
        window_ns: u64,
    ) -> bool {
        let hit = self.with_in_window(key, now_ns, window_ns, |events, match_cutoff| {
            events
                .iter()
                .any(|e| e.kind == kind && e.ts_ns >= match_cutoff)
        });
        self.drop_if_empty(&key);
        hit
    }

    /// Bare-PID variant (D3 same-PID path).
    pub fn has_recent_for_pid(
        &mut self,
        pid: u32,
        kind: PrecursorKind,
        now_ns: u64,
        window_ns: u64,
    ) -> bool {
        self.has_recent(ProcKey::unresolved(pid), kind, now_ns, window_ns)
    }

    /// `true` if every kind in `kinds` appears, **in order**, among
    /// `key`'s in-window precursors (an ordered subsequence by
    /// timestamp). The N-event foundation for the D6 kill chains. An
    /// empty `kinds` is vacuously `true`.
    pub fn has_sequence(
        &mut self,
        key: ProcKey,
        kinds: &[PrecursorKind],
        now_ns: u64,
        window_ns: u64,
    ) -> bool {
        let matched = self.with_in_window(key, now_ns, window_ns, |events, match_cutoff| {
            // Consider only in-(query)-window precursors, in ts order
            // (insertion order ≈ ts order; sort defensively).
            let mut ordered: Vec<&Precursor> =
                events.iter().filter(|e| e.ts_ns >= match_cutoff).collect();
            ordered.sort_by_key(|e| e.ts_ns);
            let mut idx = 0usize;
            for e in ordered {
                if idx < kinds.len() && e.kind == kinds[idx] {
                    idx += 1;
                }
            }
            idx == kinds.len()
        });
        self.drop_if_empty(&key);
        matched
    }

    /// Bare-PID variant.
    pub fn has_sequence_for_pid(
        &mut self,
        pid: u32,
        kinds: &[PrecursorKind],
        now_ns: u64,
        window_ns: u64,
    ) -> bool {
        self.has_sequence(ProcKey::unresolved(pid), kinds, now_ns, window_ns)
    }

    // ── D4: cross-PID lineage ────────────────────────────────────────

    /// Observe a process spawn: link `child_pid` to its `parent`
    /// [`ProcKey`] in the ancestry tree. If `child_pid` was already
    /// known, the PID has been **recycled** — wipe the prior
    /// incarnation's same-PID precursors so they can't false-correlate
    /// with the new process (the PID-reuse guard, given the D2 wire
    /// carries the parent's `start_ns` but not the child's own).
    pub fn observe_spawn(&mut self, child_pid: u32, parent: ProcKey) {
        let reused = self.tree.observe(child_pid, parent);
        if reused {
            self.forget_pid(child_pid);
        }
    }

    /// Same-PID **or** any-ancestor: `true` if `pid` itself, or any
    /// process in its lineage, has a `kind` precursor in window. The
    /// cross-PID kill-chain query (design §4 G4) the D6 chains build on.
    pub fn has_recent_in_lineage(
        &mut self,
        pid: u32,
        kind: PrecursorKind,
        now_ns: u64,
        window_ns: u64,
    ) -> bool {
        if self.has_recent_for_pid(pid, kind, now_ns, window_ns) {
            return true;
        }
        for ancestor in self.tree.get_ancestors(pid) {
            if self.has_recent_for_pid(ancestor.pid, kind, now_ns, window_ns) {
                return true;
            }
        }
        false
    }

    /// Read-only view of the ancestry tree (lineage queries / tests).
    pub fn ancestry(&self) -> &AncestryTree {
        &self.tree
    }

    /// Drop every precursor recorded for `pid` (any incarnation key).
    fn forget_pid(&mut self, pid: u32) {
        self.per_proc.retain(|k, _| k.pid != pid);
        self.eviction.retain(|k| k.pid != pid);
    }

    // ── internals ────────────────────────────────────────────────────

    /// TTL-prune `key`'s entries, then run `f` over the survivors with
    /// the query's match-cutoff. Pruning uses the **larger** of the
    /// query window and [`CORRELATION_WINDOW_NS`] so a short-window
    /// query never evicts precursors a longer-window rule sharing this
    /// store still needs; `f` then filters to the query's own window
    /// via the `match_cutoff` it receives. Returns `f`'s result (or its
    /// default when `key` is absent).
    fn with_in_window<R: Default>(
        &mut self,
        key: ProcKey,
        now_ns: u64,
        window_ns: u64,
        f: impl FnOnce(&VecDeque<Precursor>, u64) -> R,
    ) -> R {
        let prune_cutoff = now_ns.saturating_sub(window_ns.max(CORRELATION_WINDOW_NS));
        let match_cutoff = now_ns.saturating_sub(window_ns);
        if let Some(q) = self.per_proc.get_mut(&key) {
            while q.front().is_some_and(|e| e.ts_ns < prune_cutoff) {
                q.pop_front();
            }
            f(q, match_cutoff)
        } else {
            R::default()
        }
    }

    fn drop_if_empty(&mut self, key: &ProcKey) {
        if self.per_proc.get(key).is_some_and(|q| q.is_empty()) {
            self.per_proc.remove(key);
        }
    }

    /// Drop processes whose every precursor is out of the *default*
    /// window relative to `now_ns`. Called on tracked-process overflow.
    fn prune_stale(&mut self, now_ns: u64) {
        let cutoff = now_ns.saturating_sub(CORRELATION_WINDOW_NS);
        let per_proc = &mut self.per_proc;
        per_proc.retain(|_, q| {
            while q.front().is_some_and(|e| e.ts_ns < cutoff) {
                q.pop_front();
            }
            !q.is_empty()
        });
        self.eviction.retain(|k| per_proc.contains_key(k));
    }

    #[cfg(test)]
    fn tracked_procs(&self) -> usize {
        self.per_proc.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SEC: u64 = 1_000_000_000;
    const W: u64 = CORRELATION_WINDOW_NS;

    fn key(pid: u32, start: u64) -> ProcKey {
        ProcKey {
            pid,
            start_ns: start,
        }
    }

    #[test]
    fn records_and_finds_within_window() {
        let mut s = CorrelationStore::new();
        s.record_for_pid(42, PrecursorKind::CredRead, 10 * SEC);
        assert!(s.has_recent_for_pid(42, PrecursorKind::CredRead, 10 * SEC + 30 * SEC, W));
    }

    #[test]
    fn evicts_after_ttl() {
        let mut s = CorrelationStore::new();
        s.record_for_pid(42, PrecursorKind::CredRead, 10 * SEC);
        // 6 minutes later — past the 5-minute window.
        assert!(!s.has_recent_for_pid(42, PrecursorKind::CredRead, 10 * SEC + 360 * SEC, W));
        // And the now-empty key was dropped.
        assert_eq!(s.tracked_procs(), 0);
    }

    #[test]
    fn per_pid_isolated() {
        let mut s = CorrelationStore::new();
        s.record_for_pid(42, PrecursorKind::CredRead, 10 * SEC);
        assert!(!s.has_recent_for_pid(99, PrecursorKind::CredRead, 11 * SEC, W));
        assert!(s.has_recent_for_pid(42, PrecursorKind::CredRead, 11 * SEC, W));
    }

    #[test]
    fn kinds_are_isolated() {
        // Cross-rule isolation: a CredRead precursor must not satisfy a
        // TmpExec query for the same pid.
        let mut s = CorrelationStore::new();
        s.record_for_pid(42, PrecursorKind::CredRead, 10 * SEC);
        assert!(!s.has_recent_for_pid(42, PrecursorKind::TmpExec, 11 * SEC, W));
        assert!(s.has_recent_for_pid(42, PrecursorKind::CredRead, 11 * SEC, W));
    }

    #[test]
    fn pid_reuse_keys_are_distinct() {
        // (pid=42, start=A) and (pid=42, start=B) are different processes.
        let mut s = CorrelationStore::new();
        s.record(key(42, 1_000), PrecursorKind::CredRead, 10 * SEC);
        assert!(
            !s.has_recent(key(42, 2_000), PrecursorKind::CredRead, 11 * SEC, W),
            "recycled PID with a new start_ns must not inherit the old precursor"
        );
        assert!(s.has_recent(key(42, 1_000), PrecursorKind::CredRead, 11 * SEC, W));
    }

    #[test]
    fn bounded_events_per_proc() {
        let mut s = CorrelationStore::new();
        for i in 0..(MAX_EVENTS_PER_PROC as u64 + 10) {
            s.record_for_pid(7, PrecursorKind::CanaryTrip, (i + 1) * SEC);
        }
        let k = ProcKey::unresolved(7);
        assert_eq!(
            s.per_proc.get(&k).map(|q| q.len()),
            Some(MAX_EVENTS_PER_PROC)
        );
    }

    #[test]
    fn bounded_tracked_procs_prunes_stale_on_overflow() {
        let mut s = CorrelationStore::new();
        // Fill with stale (t=1) entries, then insert a fresh one far in
        // the future at capacity → stale ones get pruned.
        for pid in 0..MAX_TRACKED_PROCS as u32 {
            s.record_for_pid(pid, PrecursorKind::TmpExec, SEC);
        }
        assert_eq!(s.tracked_procs(), MAX_TRACKED_PROCS);
        // A new pid at t = 10 min forces prune_stale (all old are stale).
        s.record_for_pid(u32::MAX, PrecursorKind::TmpExec, 600 * SEC);
        assert!(s.tracked_procs() <= MAX_TRACKED_PROCS);
    }

    #[test]
    fn sequence_three_events_in_order() {
        let mut s = CorrelationStore::new();
        let k = key(42, 1_000);
        s.record(k, PrecursorKind::TmpExec, SEC);
        s.record(k, PrecursorKind::CredRead, 2 * SEC);
        s.record(k, PrecursorKind::CanaryTrip, 3 * SEC);
        assert!(s.has_sequence(
            k,
            &[
                PrecursorKind::TmpExec,
                PrecursorKind::CredRead,
                PrecursorKind::CanaryTrip
            ],
            4 * SEC,
            W
        ));
    }

    #[test]
    fn sequence_breaks_if_event_missing() {
        let mut s = CorrelationStore::new();
        let k = key(42, 1_000);
        s.record(k, PrecursorKind::TmpExec, SEC);
        s.record(k, PrecursorKind::CanaryTrip, 3 * SEC);
        // CredRead never recorded → the 3-step sequence does not match.
        assert!(!s.has_sequence(
            k,
            &[
                PrecursorKind::TmpExec,
                PrecursorKind::CredRead,
                PrecursorKind::CanaryTrip
            ],
            4 * SEC,
            W
        ));
        // But the 2-step subsequence still present does.
        assert!(s.has_sequence(
            k,
            &[PrecursorKind::TmpExec, PrecursorKind::CanaryTrip],
            4 * SEC,
            W
        ));
    }

    #[test]
    fn sequence_respects_window() {
        let mut s = CorrelationStore::new();
        let k = key(42, 1_000);
        s.record(k, PrecursorKind::TmpExec, SEC);
        s.record(k, PrecursorKind::CredRead, 2 * SEC);
        // Query 6 minutes after the first event — TmpExec is now out of
        // window, so the [TmpExec, CredRead] sequence can't complete.
        assert!(!s.has_sequence(
            k,
            &[PrecursorKind::TmpExec, PrecursorKind::CredRead],
            SEC + 360 * SEC,
            W
        ));
    }

    #[test]
    fn sequence_out_of_order_does_not_match() {
        let mut s = CorrelationStore::new();
        let k = key(42, 1_000);
        // Recorded CredRead before TmpExec.
        s.record(k, PrecursorKind::CredRead, SEC);
        s.record(k, PrecursorKind::TmpExec, 2 * SEC);
        // Asking for [TmpExec, CredRead] order → no match (CredRead is
        // earlier than TmpExec).
        assert!(!s.has_sequence(
            k,
            &[PrecursorKind::TmpExec, PrecursorKind::CredRead],
            3 * SEC,
            W
        ));
    }

    #[test]
    fn empty_sequence_is_vacuously_true_when_proc_known() {
        let mut s = CorrelationStore::new();
        let k = key(1, 1);
        s.record(k, PrecursorKind::CredRead, SEC);
        assert!(s.has_sequence(k, &[], 2 * SEC, W));
    }

    #[test]
    fn per_rule_window_is_honoured() {
        let mut s = CorrelationStore::new();
        s.record_for_pid(42, PrecursorKind::CredRead, 100 * SEC);
        // A short 10s window misses a 30s-old precursor...
        assert!(!s.has_recent_for_pid(42, PrecursorKind::CredRead, 130 * SEC, 10 * SEC));
        // ...but the default window still finds it.
        assert!(s.has_recent_for_pid(42, PrecursorKind::CredRead, 130 * SEC, W));
    }

    // ── D4 cross-PID lineage ────────────────────────────────────────

    #[test]
    fn cross_pid_chain_detection_via_ancestry() {
        // Parent (pid 100) reads creds; it spawns child 200; the child
        // does the egress. has_recent_in_lineage(child) finds the
        // parent's precursor via the ancestry walk.
        let mut s = CorrelationStore::new();
        s.record_for_pid(100, PrecursorKind::CredRead, 10 * SEC);
        s.observe_spawn(200, key(100, 1_000));
        assert!(s.has_recent_in_lineage(200, PrecursorKind::CredRead, 12 * SEC, W));
        // Same-PID still matches via lineage (self is checked first).
        s.record_for_pid(300, PrecursorKind::CanaryTrip, 10 * SEC);
        assert!(s.has_recent_in_lineage(300, PrecursorKind::CanaryTrip, 11 * SEC, W));
    }

    #[test]
    fn multi_level_lineage_lookup() {
        // 100 → 200 → 300; precursor on the grandparent reaches the
        // grandchild.
        let mut s = CorrelationStore::new();
        s.record_for_pid(100, PrecursorKind::TmpExec, 10 * SEC);
        s.observe_spawn(200, key(100, 1_000));
        s.observe_spawn(300, key(200, 2_000));
        assert!(s.has_recent_in_lineage(300, PrecursorKind::TmpExec, 12 * SEC, W));
    }

    #[test]
    fn ancestor_chain_breaks_on_unrelated_process() {
        let mut s = CorrelationStore::new();
        s.record_for_pid(100, PrecursorKind::CredRead, 10 * SEC);
        s.observe_spawn(200, key(100, 1_000));
        // 999 is not in 200's lineage and has no precursor of its own.
        assert!(!s.has_recent_in_lineage(999, PrecursorKind::CredRead, 12 * SEC, W));
        // And a different kind along the real lineage still misses.
        assert!(!s.has_recent_in_lineage(200, PrecursorKind::TmpExec, 12 * SEC, W));
    }

    #[test]
    fn pid_reuse_via_observe_spawn_wipes_stale_precursor() {
        // pid 200 reads creds, then the PID is recycled (a fresh spawn
        // of 200) — the new incarnation must not inherit the precursor.
        let mut s = CorrelationStore::new();
        s.record_for_pid(200, PrecursorKind::CredRead, 10 * SEC);
        s.observe_spawn(200, key(100, 1_000)); // first sighting (not reuse)
        assert!(
            s.has_recent_for_pid(200, PrecursorKind::CredRead, 11 * SEC, W),
            "first spawn does not wipe"
        );
        s.observe_spawn(200, key(150, 9_000)); // second sighting = reuse
        assert!(
            !s.has_recent_for_pid(200, PrecursorKind::CredRead, 12 * SEC, W),
            "recycled PID's stale precursor must be wiped"
        );
    }

    #[test]
    fn lineage_exposes_ancestry_tree() {
        let mut s = CorrelationStore::new();
        s.observe_spawn(200, key(100, 1_000));
        assert!(s.ancestry().is_ancestor(200, 100));
    }
}
