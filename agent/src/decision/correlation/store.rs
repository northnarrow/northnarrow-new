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
//!   process (§13 Q2). External audit NETR-009: an exec precursor is
//!   recorded with the start its `ProcessSpawn` carries (POS-003); any
//!   other precursor, and every query, takes the PID's current
//!   incarnation from the ancestry tree. An unknown incarnation is
//!   `start_ns = 0` and matches only 0, so processes started before the
//!   agent keep the PID-only behaviour.
//! - **Per-rule window.** Each query passes its own `window_ns`
//!   (§13 Q4 — 300 s default, configurable per rule).
//!
//! External audit NETR-004: memory is bounded by a per-process ring
//! capped at [`MAX_EVENTS_PER_PROC`] and a hard cap of
//! [`MAX_TRACKED_PROCS`] keys, enforced in O(1) per insert with
//! [`LazyLru`] queues. Keys that hold only `PrivEsc` (whose chain only
//! logs) go first; evicting a key that still holds a `CredRead`,
//! `TmpExec` or `CanaryTrip` is counted, with a rate-limited WARN. Stale
//! keys are swept every [`SWEEP_EVERY`] new keys and dropped on query.

use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};

use super::ancestry::AncestryTree;
use crate::decision::bounded::{LazyLru, LossCounter};

/// Default correlation lookback (§13 Q4). Rules may pass a different
/// `window_ns`; this is the value the migrated CHAIN-001..003 use,
/// matching the T10.5 5-minute precedent.
pub const CORRELATION_WINDOW_NS: u64 = 300 * 1_000_000_000;

/// Per-process precursor ring cap. A process that re-triggers the same
/// precursor many times only needs the most recent few to answer
/// "any/which precursor in window?".
const MAX_EVENTS_PER_PROC: usize = 16;

/// Distinct-process cap (hard, external audit NETR-004).
const MAX_TRACKED_PROCS: usize = 4096;

/// New keys between two sweeps of fully stale keys.
const SWEEP_EVERY: u64 = 256;

/// Review 70: egresses kept per process for a late precursor.
const MAX_EGRESS_PER_PROC: usize = 4;

/// Keys evicted while holding an in-window `CredRead`, `TmpExec` or
/// `CanaryTrip`, by any store since the agent started.
static LOST_PRECURSOR_KEYS: AtomicU64 = AtomicU64::new(0);

/// External audit NETR-004: processes whose blocking-chain precursors were
/// evicted for room, process-wide.
pub fn lost_precursor_keys_total() -> u64 {
    LOST_PRECURSOR_KEYS.load(Ordering::Relaxed)
}

/// Review 70 — an egress a chain rule evaluated before a precursor that
/// happened earlier in kernel time. The precursor travels through another
/// ring and pump (a credential read through the open sensor or FIM, the
/// egress through the network drain), so it can be processed after the
/// egress it precedes; the chain then completes on the precursor. Only
/// what the verdict needs is kept.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EgressNote {
    pub pid: u32,
    pub comm: String,
    pub start_ns: u64,
}

/// PID-reuse-safe process identity (§13 Q2). `start_ns` is the task's
/// `start_time` (CLOCK_MONOTONIC ns, `Event::ProcessSpawn::start_ns`);
/// `start_ns == 0` means "incarnation unknown".
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct ProcKey {
    pub pid: u32,
    pub start_ns: u64,
}

impl ProcKey {
    /// Key for a bare PID whose incarnation is not known.
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
    /// NN-L-CHAIN-008 (D6) — `sudo`/`su` privilege-escalation exec
    /// (T1548). Recorded on the privesc process so a descendant's
    /// egress can be back-correlated to it.
    PrivEsc,
}

#[derive(Clone, Copy)]
struct Precursor {
    kind: PrecursorKind,
    ts_ns: u64,
}

/// Shared correlation state. `Arc<Mutex<_>>`-wrapped by the engine and
/// queried from `Rule::evaluate`.
pub struct CorrelationStore {
    per_proc: HashMap<ProcKey, VecDeque<Precursor>>,
    /// External audit NETR-004: keys holding only `PrivEsc`, evicted
    /// first, least recently recorded first.
    privesc_only: LazyLru<ProcKey>,
    /// Keys holding a `CredRead`, `TmpExec` or `CanaryTrip`.
    protected: LazyLru<ProcKey>,
    /// New keys recorded, for the periodic sweep.
    new_keys: u64,
    lost: LossCounter,
    /// D4 — parent→child lineage for cross-PID correlation, and the
    /// `pid → start_ns` map (NETR-009).
    tree: AncestryTree,
    /// Review 70 — egresses no chain has claimed yet, per process.
    egress: HashMap<ProcKey, VecDeque<EgressNote>>,
    egress_order: LazyLru<ProcKey>,
}

impl Default for CorrelationStore {
    fn default() -> Self {
        Self::with_tree(AncestryTree::new())
    }
}

impl CorrelationStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// A store over `tree` (a fixture proc root in tests).
    pub fn with_tree(tree: AncestryTree) -> Self {
        Self {
            per_proc: HashMap::new(),
            privesc_only: LazyLru::new(),
            protected: LazyLru::new(),
            new_keys: 0,
            lost: LossCounter::new(&LOST_PRECURSOR_KEYS),
            tree,
            egress: HashMap::new(),
            egress_order: LazyLru::new(),
        }
    }

    // ── recording ───────────────────────────────────────────────────

    /// Record a `kind` precursor for an explicit [`ProcKey`] (an exec
    /// precursor, keyed with the start its event carries).
    pub fn record(&mut self, key: ProcKey, kind: PrecursorKind, ts_ns: u64) {
        if !self.per_proc.contains_key(&key) {
            self.new_keys = self.new_keys.wrapping_add(1);
            if self.new_keys % SWEEP_EVERY == 0 {
                self.prune_stale(ts_ns);
            }
            while self.per_proc.len() >= MAX_TRACKED_PROCS {
                if !self.evict_one(ts_ns) {
                    break;
                }
            }
        }
        let q = self.per_proc.entry(key).or_default();
        q.push_back(Precursor { kind, ts_ns });
        while q.len() > MAX_EVENTS_PER_PROC {
            q.pop_front();
        }
        if kind == PrecursorKind::PrivEsc && !self.protected.contains(&key) {
            self.privesc_only.touch(key);
        } else {
            self.privesc_only.remove(&key);
            self.protected.touch(key);
        }
    }

    /// Record for `pid`'s current incarnation (a precursor from a non-exec
    /// event: a FIM read, a canary trip).
    pub fn record_for_pid(&mut self, pid: u32, kind: PrecursorKind, ts_ns: u64) {
        self.record(self.current_key(pid), kind, ts_ns);
    }

    /// `pid`'s current incarnation as the ancestry tree knows it
    /// (`start_ns = 0` when its exec was never seen).
    pub fn current_key(&self, pid: u32) -> ProcKey {
        self.tree.current(pid)
    }

    /// Review 70: keep an egress that completed no same-process chain, for
    /// a precursor that arrives after it but happened before it.
    /// External audit NETR-004: the least recently noted key makes room,
    /// in O(1).
    pub fn note_egress(&mut self, key: ProcKey, note: EgressNote) {
        if !self.egress.contains_key(&key) {
            while self.egress.len() >= MAX_TRACKED_PROCS {
                match self.egress_order.pop_oldest() {
                    Some(old) => {
                        self.egress.remove(&old);
                    }
                    None => break,
                }
            }
        }
        let q = self.egress.entry(key).or_default();
        q.push_back(note);
        while q.len() > MAX_EGRESS_PER_PROC {
            q.pop_front();
        }
        self.egress_order.touch(key);
    }

    /// Review 70: take the earliest noted egress of `key` that happened
    /// after `after_ns`, within `window_ns` of it — the one a precursor
    /// stamped `after_ns` completes. It is taken: an egress completes one
    /// late chain only.
    pub fn take_egress_after(
        &mut self,
        key: ProcKey,
        after_ns: u64,
        window_ns: u64,
    ) -> Option<EgressNote> {
        let q = self.egress.get_mut(&key)?;
        let idx = q
            .iter()
            .enumerate()
            .filter(|(_, n)| n.start_ns > after_ns && n.start_ns - after_ns <= window_ns)
            .min_by_key(|(_, n)| n.start_ns)
            .map(|(i, _)| i);
        let note = idx.and_then(|i| q.remove(i));
        if q.is_empty() {
            self.remove_egress(&key);
        }
        note
    }

    /// Review 70: a chain fired on this egress in order, so no late
    /// precursor may complete a chain with it again.
    pub fn claim_egress(&mut self, key: ProcKey, start_ns: u64) {
        if let Some(q) = self.egress.get_mut(&key) {
            q.retain(|n| n.start_ns != start_ns);
            if q.is_empty() {
                self.remove_egress(&key);
            }
        }
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

    /// [`Self::has_recent`] for `pid`'s current incarnation.
    pub fn has_recent_for_pid(
        &mut self,
        pid: u32,
        kind: PrecursorKind,
        now_ns: u64,
        window_ns: u64,
    ) -> bool {
        self.has_recent(self.current_key(pid), kind, now_ns, window_ns)
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

    /// [`Self::has_sequence`] for `pid`'s current incarnation.
    pub fn has_sequence_for_pid(
        &mut self,
        pid: u32,
        kinds: &[PrecursorKind],
        now_ns: u64,
        window_ns: u64,
    ) -> bool {
        self.has_sequence(self.current_key(pid), kinds, now_ns, window_ns)
    }

    // ── D4: cross-PID lineage ────────────────────────────────────────

    /// Observe the exec of `child_pid` (own start `start_ns`, 0 when the
    /// record predates POS-003) under parent `ppid`.
    ///
    /// External audit NETR-009: a start other than the one recorded for
    /// the PID is a new incarnation. It takes over the precursors and
    /// egresses recorded under the PID's previous or unknown incarnation
    /// that happened at or after its own start — an event processed
    /// before the exec that started it (another ring) — and the rest is
    /// dropped. A re-exec of the same process (same start) keeps its
    /// state. Without a start, a second sighting of the PID is a reuse
    /// and its state is dropped, as before.
    pub fn observe_spawn(&mut self, child_pid: u32, ppid: u32, start_ns: u64) {
        let previous = self.tree.observe(child_pid, ppid, start_ns);
        if previous == Some(start_ns) && start_ns != 0 {
            return;
        }
        let new_key = ProcKey {
            pid: child_pid,
            start_ns,
        };
        let mut old_keys = vec![ProcKey::unresolved(child_pid)];
        if let Some(prev) = previous.filter(|&p| p != 0 && p != start_ns) {
            old_keys.push(ProcKey {
                pid: child_pid,
                start_ns: prev,
            });
        }
        if start_ns == 0 {
            // No incarnation to hand anything to.
            if previous.is_some() {
                for k in old_keys {
                    self.remove_key(&k);
                    self.remove_egress(&k);
                }
            }
            return;
        }
        for old in old_keys {
            if let Some(q) = self.per_proc.get(&old).cloned() {
                self.remove_key(&old);
                for p in q.iter().filter(|p| p.ts_ns >= start_ns) {
                    self.record(new_key, p.kind, p.ts_ns);
                }
            }
            if let Some(q) = self.egress.get(&old).cloned() {
                self.remove_egress(&old);
                for n in q.into_iter().filter(|n| n.start_ns >= start_ns) {
                    self.note_egress(new_key, n);
                }
            }
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
        self.has_recent_for_pid(pid, kind, now_ns, window_ns)
            || self.has_recent_in_ancestors(pid, kind, now_ns, window_ns)
    }

    /// Strictly an **ancestor** (not self) has a `kind` precursor in
    /// window — the pure cross-PID query the D6 CHAIN-004..008 rules use,
    /// so they never shadow the same-PID CHAIN-001..003. External audit
    /// NETR-009: each ancestor is queried with its own incarnation.
    pub fn has_recent_in_ancestors(
        &mut self,
        pid: u32,
        kind: PrecursorKind,
        now_ns: u64,
        window_ns: u64,
    ) -> bool {
        for ancestor in self.tree.get_ancestors(pid) {
            if self.has_recent(ancestor, kind, now_ns, window_ns) {
                return true;
            }
        }
        false
    }

    /// Read-only view of the ancestry tree (lineage queries / tests).
    pub fn ancestry(&self) -> &AncestryTree {
        &self.tree
    }

    /// Keys evicted from this store while holding an in-window
    /// `CredRead`, `TmpExec` or `CanaryTrip`.
    pub fn lost_precursor_keys(&self) -> u64 {
        self.lost.count()
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
            self.remove_key(key);
        }
    }

    /// O(1): the queues drop their entries lazily.
    fn remove_key(&mut self, key: &ProcKey) {
        if self.per_proc.remove(key).is_some() {
            self.privesc_only.remove(key);
            self.protected.remove(key);
        }
    }

    fn remove_egress(&mut self, key: &ProcKey) {
        if self.egress.remove(key).is_some() {
            self.egress_order.remove(key);
        }
    }

    /// External audit NETR-004: evict one key, `PrivEsc`-only keys first.
    /// `false` when there is nothing to evict.
    fn evict_one(&mut self, now_ns: u64) -> bool {
        let (victim, protected) = match self.privesc_only.pop_oldest() {
            Some(k) => (k, false),
            None => match self.protected.pop_oldest() {
                Some(k) => (k, true),
                None => return false,
            },
        };
        let cutoff = now_ns.saturating_sub(CORRELATION_WINDOW_NS);
        let lost = self.per_proc.remove(&victim).is_some_and(|q| {
            protected
                && q.iter()
                    .any(|p| p.kind != PrecursorKind::PrivEsc && p.ts_ns >= cutoff)
        });
        if lost && self.lost.bump() {
            tracing::warn!(
                pid = victim.pid,
                evicted = self.lost.count(),
                cap = MAX_TRACKED_PROCS,
                "correlation store full: evicted a process holding a chain \
                 precursor, its chain can no longer complete"
            );
        }
        true
    }

    /// Drop processes whose every precursor is out of the *default*
    /// window relative to `now_ns`. Run every [`SWEEP_EVERY`] new keys.
    fn prune_stale(&mut self, now_ns: u64) {
        let cutoff = now_ns.saturating_sub(CORRELATION_WINDOW_NS);
        let (low, high) = (&mut self.privesc_only, &mut self.protected);
        self.per_proc.retain(|k, q| {
            while q.front().is_some_and(|e| e.ts_ns < cutoff) {
                q.pop_front();
            }
            if q.is_empty() {
                low.remove(k);
                high.remove(k);
                false
            } else {
                true
            }
        });
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
        s.observe_spawn(200, 100, 0);
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
        s.observe_spawn(200, 100, 0);
        s.observe_spawn(300, 200, 0);
        assert!(s.has_recent_in_lineage(300, PrecursorKind::TmpExec, 12 * SEC, W));
    }

    #[test]
    fn ancestor_chain_breaks_on_unrelated_process() {
        let mut s = CorrelationStore::new();
        s.record_for_pid(100, PrecursorKind::CredRead, 10 * SEC);
        s.observe_spawn(200, 100, 0);
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
        s.observe_spawn(200, 100, 0); // first sighting (not reuse)
        assert!(
            s.has_recent_for_pid(200, PrecursorKind::CredRead, 11 * SEC, W),
            "first spawn does not wipe"
        );
        s.observe_spawn(200, 150, 0); // second sighting = reuse
        assert!(
            !s.has_recent_for_pid(200, PrecursorKind::CredRead, 12 * SEC, W),
            "recycled PID's stale precursor must be wiped"
        );
    }

    #[test]
    fn lineage_exposes_ancestry_tree() {
        let mut s = CorrelationStore::new();
        s.observe_spawn(200, 100, 0);
        assert!(s.ancestry().is_ancestor(200, ProcKey::unresolved(100)));
    }

    // ── External audit NETR-004: a hard cap, O(1) per insert ─────────

    #[test]
    fn record_keeps_the_cap_with_live_keys() {
        let mut s = CorrelationStore::new();
        // The oldest key holds only PrivEsc; the others a TmpExec.
        s.record(key(1, 1), PrecursorKind::PrivEsc, SEC);
        for pid in 2..=5000u32 {
            s.record(key(pid, 1), PrecursorKind::TmpExec, SEC + u64::from(pid));
        }
        assert_eq!(s.tracked_procs(), MAX_TRACKED_PROCS);
        assert!(!s.has_recent(key(1, 1), PrecursorKind::PrivEsc, 2 * SEC, W));
        assert!(s.has_recent(key(5000, 1), PrecursorKind::TmpExec, 2 * SEC, W));
        // 5000 keys for a cap of 4096: the PrivEsc-only key went first,
        // then 903 protected ones, each counted.
        assert_eq!(s.lost_precursor_keys(), 5000 - 1 - MAX_TRACKED_PROCS as u64);
        assert!(lost_precursor_keys_total() >= s.lost_precursor_keys());
    }

    #[test]
    fn a_hundred_thousand_live_keys_stay_cheap() {
        let mut s = CorrelationStore::new();
        let t0 = std::time::Instant::now();
        for pid in 0..100_000u32 {
            s.record(key(pid, 7), PrecursorKind::PrivEsc, SEC + u64::from(pid));
            s.note_egress(
                key(pid, 7),
                EgressNote {
                    pid,
                    comm: String::new(),
                    start_ns: SEC + u64::from(pid),
                },
            );
        }
        assert_eq!(s.tracked_procs(), MAX_TRACKED_PROCS);
        assert_eq!(s.egress.len(), MAX_TRACKED_PROCS);
        assert!(s.privesc_only.queue_len() <= 2 * MAX_TRACKED_PROCS + 1);
        assert!(s.egress_order.queue_len() <= 2 * MAX_TRACKED_PROCS + 1);
        // O(n) per insert above the cap took minutes in a debug build.
        let took = t0.elapsed();
        assert!(took < std::time::Duration::from_secs(10), "{took:?}");
    }

    #[test]
    fn eviction_queue_stays_bounded_under_query_churn() {
        let mut s = CorrelationStore::new();
        for pid in 0..10_000u32 {
            s.record(key(pid, 1), PrecursorKind::CredRead, SEC);
            // Out of window by now: the query drops the key.
            assert!(!s.has_recent(key(pid, 1), PrecursorKind::CredRead, 400 * SEC, W));
        }
        assert_eq!(s.tracked_procs(), 0);
        assert!(
            s.protected.queue_len() <= 2 * 64 + 1,
            "{}",
            s.protected.queue_len()
        );
    }

    #[test]
    fn a_privesc_flood_does_not_evict_a_cred_read() {
        let mut s = CorrelationStore::new();
        s.record(key(42, 1), PrecursorKind::CredRead, SEC);
        for pid in 1_000..21_000u32 {
            s.record(key(pid, 1), PrecursorKind::PrivEsc, 2 * SEC);
        }
        assert!(s.has_recent(key(42, 1), PrecursorKind::CredRead, 3 * SEC, W));
        assert_eq!(s.lost_precursor_keys(), 0);
        assert!(s.tracked_procs() <= MAX_TRACKED_PROCS);
    }

    #[test]
    fn a_privesc_key_that_gains_a_cred_read_is_protected() {
        let mut s = CorrelationStore::new();
        s.record(key(42, 1), PrecursorKind::PrivEsc, SEC);
        s.record(key(42, 1), PrecursorKind::CredRead, SEC);
        s.record(key(42, 1), PrecursorKind::PrivEsc, SEC);
        for pid in 1_000..9_000u32 {
            s.record(key(pid, 1), PrecursorKind::PrivEsc, 2 * SEC);
        }
        assert!(s.has_recent(key(42, 1), PrecursorKind::CredRead, 3 * SEC, W));
    }

    // ── External audit NETR-009: the incarnation is kept ─────────────

    #[test]
    fn precursors_follow_the_incarnation() {
        let mut s = CorrelationStore::new();
        // (200, start 10 s) runs from /tmp.
        s.observe_spawn(200, 1, 10 * SEC);
        s.record(key(200, 10 * SEC), PrecursorKind::TmpExec, 10 * SEC);
        assert!(s.has_recent_for_pid(200, PrecursorKind::TmpExec, 11 * SEC, W));
        // A FIM read is recorded for the current incarnation.
        s.record_for_pid(200, PrecursorKind::CredRead, 11 * SEC);
        assert!(s.has_recent(key(200, 10 * SEC), PrecursorKind::CredRead, 12 * SEC, W));
        // A re-exec of the same process keeps them.
        s.observe_spawn(200, 1, 10 * SEC);
        assert!(s.has_recent_for_pid(200, PrecursorKind::TmpExec, 12 * SEC, W));
        // The PID goes to a new process: nothing carries over.
        s.observe_spawn(200, 1, 20 * SEC);
        assert!(!s.has_recent_for_pid(200, PrecursorKind::TmpExec, 21 * SEC, W));
        assert!(!s.has_recent_for_pid(200, PrecursorKind::CredRead, 21 * SEC, W));
    }

    /// The tree lost the PID's edge (evicted): the new incarnation still
    /// does not inherit what the old one recorded.
    #[test]
    fn a_reused_pid_inherits_nothing_once_its_edge_is_gone() {
        let mut s = CorrelationStore::new();
        s.observe_spawn(200, 1, 10 * SEC);
        s.record(key(200, 10 * SEC), PrecursorKind::TmpExec, 10 * SEC);
        s.tree.forget(200);
        s.observe_spawn(200, 1, 20 * SEC);
        assert!(!s.has_recent_for_pid(200, PrecursorKind::TmpExec, 21 * SEC, W));
    }

    /// A precursor processed before the exec that started its process
    /// (another ring) is handed to that process; an older one is not.
    #[test]
    fn a_precursor_processed_before_the_exec_goes_to_the_new_incarnation() {
        let mut s = CorrelationStore::new();
        s.record_for_pid(300, PrecursorKind::CredRead, 5 * SEC); // older holder
        s.record_for_pid(300, PrecursorKind::CanaryTrip, 12 * SEC);
        s.observe_spawn(300, 1, 10 * SEC);
        assert!(s.has_recent_for_pid(300, PrecursorKind::CanaryTrip, 13 * SEC, W));
        assert!(!s.has_recent_for_pid(300, PrecursorKind::CredRead, 13 * SEC, W));
    }

    #[test]
    fn a_recycled_ancestor_pid_carries_nothing() {
        let mut s = CorrelationStore::new();
        // (100, 1 s) read credentials, then exited; its PID went to a new
        // process (100, 9 s), whose child 300 egresses.
        s.observe_spawn(100, 1, SEC);
        s.record_for_pid(100, PrecursorKind::CredRead, 2 * SEC);
        s.observe_spawn(100, 1, 9 * SEC);
        s.observe_spawn(300, 100, 10 * SEC);
        assert!(!s.has_recent_in_ancestors(300, PrecursorKind::CredRead, 11 * SEC, W));
        // The real parent's precursor still reaches its child.
        s.record_for_pid(100, PrecursorKind::CredRead, 10 * SEC);
        assert!(s.has_recent_in_ancestors(300, PrecursorKind::CredRead, 11 * SEC, W));
    }

    #[test]
    fn an_ancestor_started_after_the_child_ends_the_walk() {
        let mut s = CorrelationStore::new();
        // 300 was forked by the first holder of 100; 100 now names a
        // process that started later and reads credentials.
        s.observe_spawn(300, 100, 3 * SEC);
        s.observe_spawn(100, 1, 5 * SEC);
        s.record_for_pid(100, PrecursorKind::CredRead, 6 * SEC);
        assert!(!s.has_recent_in_ancestors(300, PrecursorKind::CredRead, 7 * SEC, W));
    }

    /// A parent started before the agent (no exec seen) keeps the PID-only
    /// behaviour.
    #[test]
    fn a_parent_older_than_the_agent_keeps_pid_only_matching() {
        let mut s = CorrelationStore::new();
        s.record_for_pid(100, PrecursorKind::CredRead, 10 * SEC);
        s.observe_spawn(300, 100, 11 * SEC);
        assert!(s.has_recent_in_ancestors(300, PrecursorKind::CredRead, 12 * SEC, W));
    }
}
