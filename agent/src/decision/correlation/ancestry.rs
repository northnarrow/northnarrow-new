//! Tappa 10.6 (D4) — process-lineage ancestry tree.
//!
//! Tracks per-host parent→child edges so the [`CorrelationStore`] can
//! correlate a precursor on an *ancestor* with a trigger on a
//! *descendant* (the cross-PID kill chains of design §4.2 / §4 G4 —
//! `sshd → bash → curl`).
//!
//! ## Keying note (D2 data shape)
//!
//! The D2 BPF refit captures, per spawn, the child's `pid` and the
//! **parent's** full identity `(parent_pid, parent_start_ns)` — but not
//! the child's *own* `start_time`. So an edge keys the parent with a
//! PID-reuse-safe [`ProcKey`] (the value a grandchild's lineage walk
//! relies on), while the child is keyed by `pid` alone. PID reuse of a
//! child is handled where it actually matters — the store invalidates a
//! recycled PID's stale precursors when it observes the fresh spawn
//! (see `CorrelationStore::observe_spawn`) — rather than by a child
//! `start_ns` we don't have.
//!
//! Bounded: at most [`MAX_TRACKED_EDGES`] edges with FIFO eviction;
//! walks are capped at [`MAX_ANCESTRY_DEPTH`] with a cycle guard. There
//! is no `sched_process_exit` sensor today, so dead processes are reaped
//! by the cap + eviction rather than on exit.

use std::collections::{HashMap, HashSet, VecDeque};

use super::store::ProcKey;

/// Max parent→child edges retained. A busy host churns processes; this
/// bounds memory while comfortably covering live lineages.
const MAX_TRACKED_EDGES: usize = 10_000;

/// Max ancestry-walk depth — deep enough for real process trees, capped
/// so a pathological/looping chain can't run unbounded.
const MAX_ANCESTRY_DEPTH: usize = 16;

/// Per-host parent→child lineage. `edges[child_pid] = parent ProcKey`.
#[derive(Default)]
pub struct AncestryTree {
    edges: HashMap<u32, ProcKey>,
    /// FIFO of child pids for stale-first overflow eviction.
    eviction: VecDeque<u32>,
}

impl AncestryTree {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record that `child_pid`'s parent is `parent`. Returns `true` if
    /// `child_pid` was **already** an edge (i.e. the PID was recycled),
    /// which the store uses to invalidate the prior incarnation's state.
    pub fn observe(&mut self, child_pid: u32, parent: ProcKey) -> bool {
        let reused = self.edges.contains_key(&child_pid);
        if !reused {
            if self.edges.len() >= MAX_TRACKED_EDGES {
                if let Some(old) = self.eviction.pop_front() {
                    self.edges.remove(&old);
                }
            }
            self.eviction.push_back(child_pid);
        }
        self.edges.insert(child_pid, parent);
        reused
    }

    /// The immediate parent of `pid`, if known.
    pub fn parent_of(&self, pid: u32) -> Option<ProcKey> {
        self.edges.get(&pid).copied()
    }

    /// Ancestor [`ProcKey`]s of `pid`, nearest first, walking
    /// parent→parent up to [`MAX_ANCESTRY_DEPTH`]. Cycle-guarded.
    pub fn get_ancestors(&self, pid: u32) -> Vec<ProcKey> {
        let mut out = Vec::new();
        let mut visited = HashSet::new();
        visited.insert(pid);
        let mut cur = pid;
        for _ in 0..MAX_ANCESTRY_DEPTH {
            match self.edges.get(&cur) {
                Some(pkey) => {
                    if !visited.insert(pkey.pid) {
                        break; // cycle / reused-pid loop guard
                    }
                    out.push(*pkey);
                    cur = pkey.pid;
                }
                None => break,
            }
        }
        out
    }

    /// `true` if `ancestor_pid` appears anywhere in `descendant_pid`'s
    /// lineage.
    pub fn is_ancestor(&self, descendant_pid: u32, ancestor_pid: u32) -> bool {
        self.get_ancestors(descendant_pid)
            .iter()
            .any(|k| k.pid == ancestor_pid)
    }

    /// Drop a process's edge — e.g. on observed PID reuse, or a future
    /// `sched_process_exit` reap.
    pub fn forget(&mut self, pid: u32) {
        if self.edges.remove(&pid).is_some() {
            self.eviction.retain(|&p| p != pid);
        }
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.edges.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn k(pid: u32, start: u64) -> ProcKey {
        ProcKey {
            pid,
            start_ns: start,
        }
    }

    #[test]
    fn direct_parent_child_detected() {
        let mut t = AncestryTree::new();
        // child 200's parent is (100, start=A).
        t.observe(200, k(100, 1_000));
        assert!(t.is_ancestor(200, 100));
        assert_eq!(t.parent_of(200), Some(k(100, 1_000)));
    }

    #[test]
    fn multi_level_ancestry() {
        let mut t = AncestryTree::new();
        // 100 → 200 → 300 (grandparent → parent → child).
        t.observe(200, k(100, 1_000));
        t.observe(300, k(200, 2_000));
        let anc = t.get_ancestors(300);
        assert_eq!(anc, vec![k(200, 2_000), k(100, 1_000)]);
        assert!(t.is_ancestor(300, 100));
        assert!(t.is_ancestor(300, 200));
        assert!(!t.is_ancestor(300, 999));
    }

    #[test]
    fn pid_reuse_is_reported() {
        let mut t = AncestryTree::new();
        assert!(!t.observe(200, k(100, 1_000)), "first sighting");
        assert!(
            t.observe(200, k(150, 5_000)),
            "second sighting of pid 200 = reuse"
        );
        // The edge now points at the new parent.
        assert_eq!(t.parent_of(200), Some(k(150, 5_000)));
    }

    #[test]
    fn cycle_guard_terminates_walk() {
        let mut t = AncestryTree::new();
        // Construct a degenerate loop 1→2→1 (only possible via PID
        // reuse); the walk must terminate, not spin.
        t.observe(1, k(2, 10));
        t.observe(2, k(1, 20));
        let anc = t.get_ancestors(1);
        assert!(anc.len() <= 2);
    }

    #[test]
    fn forget_drops_edge() {
        let mut t = AncestryTree::new();
        t.observe(200, k(100, 1));
        t.forget(200);
        assert!(t.parent_of(200).is_none());
        assert!(!t.is_ancestor(200, 100));
    }

    #[test]
    fn bounded_edges_evict_oldest() {
        let mut t = AncestryTree::new();
        for child in 0..(MAX_TRACKED_EDGES as u32 + 100) {
            t.observe(child, k(child.wrapping_add(1), 1));
        }
        assert!(t.len() <= MAX_TRACKED_EDGES);
    }
}
