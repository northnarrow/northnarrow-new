//! Bounded-state helpers shared by the decision layer.
//!
//! External audit NETR-004 / NETR-010: the correlation store and the
//! ancestry tree enforced their caps with an O(n) scan per insert (or not
//! at all) and lost state without a trace. [`LazyLru`] gives O(1)
//! amortised recency order with lazy deletion; [`LossCounter`] counts
//! evictions of state that still mattered and rate-limits the WARN about
//! them. NETR-005 (the network rule windows) reuses both; NET-012 is meant
//! to.
//!
//! Lot 314 (the third bug hunt, F3): [`BoundedMap`], a map with a cap, and
//! the two memories built on it — [`RepeatWindow`] (a key once per window)
//! and [`OncePerProcess`] (a rule that fires once per process, keyed by pid
//! and start). A rule's "once" or "repeat" memory is one of these (the
//! ratchet `xtask/tests/state_machines.rs`): a table without a cap grew
//! with every distinct key a user made (BUG-125), and a "once" without a
//! memory fired on every later record (BUG-83).

use std::collections::{HashMap, VecDeque};
use std::hash::Hash;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

/// Below this many live keys the queue is never compacted: a handful of
/// stale entries costs nothing.
const COMPACT_FLOOR: usize = 64;

/// At most one WARN per counter in this interval.
const WARN_INTERVAL: Duration = Duration::from_secs(60);

/// Recency queue with lazy deletion.
///
/// The queue holds `(key, stamp)` pairs; a pair is current only while
/// `live[key] == stamp`. Removing a key or moving it to the back leaves its
/// old pair behind, which [`LazyLru::pop_oldest`] skips and a compaction
/// drops once the queue holds more than twice the live keys. Every
/// operation is O(1) amortised.
pub struct LazyLru<K> {
    queue: VecDeque<(K, u64)>,
    live: HashMap<K, u64>,
    next_stamp: u64,
    compact_floor: usize,
}

impl<K> Default for LazyLru<K> {
    fn default() -> Self {
        Self {
            queue: VecDeque::new(),
            live: HashMap::new(),
            next_stamp: 0,
            compact_floor: COMPACT_FLOOR,
        }
    }
}

impl<K: Clone + Eq + Hash> LazyLru<K> {
    pub fn new() -> Self {
        Self::default()
    }

    /// A queue compacted from `floor` live keys up. For many small
    /// instances (one per process), where the default floor's stale
    /// entries would add up (external audit NETR-005).
    pub fn with_compact_floor(floor: usize) -> Self {
        Self {
            compact_floor: floor.max(1),
            ..Self::default()
        }
    }

    /// Live keys.
    pub fn len(&self) -> usize {
        self.live.len()
    }

    pub fn is_empty(&self) -> bool {
        self.live.is_empty()
    }

    pub fn contains(&self, key: &K) -> bool {
        self.live.contains_key(key)
    }

    /// Insert `key` as the most recent, or move it there.
    pub fn touch(&mut self, key: K) {
        let stamp = self.next_stamp;
        self.next_stamp = self.next_stamp.wrapping_add(1);
        self.live.insert(key.clone(), stamp);
        self.queue.push_back((key, stamp));
        self.maybe_compact();
    }

    /// Forget `key`. Its queue entry is dropped lazily.
    pub fn remove(&mut self, key: &K) -> bool {
        self.live.remove(key).is_some()
    }

    /// Remove and return the least recently touched live key.
    pub fn pop_oldest(&mut self) -> Option<K> {
        while let Some((key, stamp)) = self.queue.pop_front() {
            if self.live.get(&key) == Some(&stamp) {
                self.live.remove(&key);
                return Some(key);
            }
        }
        None
    }

    /// Queue entries, stale ones included.
    pub fn queue_len(&self) -> usize {
        self.queue.len()
    }

    fn maybe_compact(&mut self) {
        if self.queue.len() > 2 * self.live.len().max(self.compact_floor) {
            let live = &self.live;
            self.queue.retain(|(k, s)| live.get(k) == Some(s));
        }
    }
}

/// Counts evictions of state that still mattered: a per-instance count for
/// tests and callers, a process-wide total for the status surface, and a
/// WARN at most once a minute.
pub struct LossCounter {
    count: u64,
    last_warn: Option<Instant>,
    total: &'static AtomicU64,
}

impl LossCounter {
    pub const fn new(total: &'static AtomicU64) -> Self {
        Self {
            count: 0,
            last_warn: None,
            total,
        }
    }

    /// Count one loss. `true` when the caller should WARN now.
    pub fn bump(&mut self) -> bool {
        self.count = self.count.saturating_add(1);
        self.total.fetch_add(1, Ordering::Relaxed);
        let now = Instant::now();
        if self
            .last_warn
            .is_none_or(|t| now.duration_since(t) >= WARN_INTERVAL)
        {
            self.last_warn = Some(now);
            true
        } else {
            false
        }
    }

    pub fn count(&self) -> u64 {
        self.count
    }
}

/// Lot 314 (the third bug hunt, family F3 "state, windows and counts"): a
/// map with a cap. Inserting past the cap evicts the entry written or
/// touched least recently ([`LazyLru`] order). The decision layer's "once"
/// and "once per window" memories are built on it ([`OncePerProcess`],
/// [`RepeatWindow`]): a table a user can grow with distinct keys never
/// outgrows its cap (BUG-125: the exec policy's repeat table had none).
pub struct BoundedMap<K, V> {
    map: HashMap<K, V>,
    order: LazyLru<K>,
    cap: usize,
    evicted: u64,
}

impl<K: Clone + Eq + Hash, V> BoundedMap<K, V> {
    /// An empty map holding at most `cap` entries (at least one).
    pub fn new(cap: usize) -> Self {
        Self {
            map: HashMap::new(),
            order: LazyLru::new(),
            cap: cap.max(1),
            evicted: 0,
        }
    }

    pub fn get(&self, key: &K) -> Option<&V> {
        self.map.get(key)
    }

    /// `key` becomes the most recent entry, its value `value`; past the cap
    /// the least recent entry goes.
    pub fn insert(&mut self, key: K, value: V) {
        self.map.insert(key.clone(), value);
        self.order.touch(key);
        while self.map.len() > self.cap {
            let Some(oldest) = self.order.pop_oldest() else {
                break;
            };
            self.map.remove(&oldest);
            self.evicted = self.evicted.saturating_add(1);
        }
    }

    /// `key`, when held, becomes the most recent entry.
    pub fn touch(&mut self, key: &K) {
        if self.map.contains_key(key) {
            self.order.touch(key.clone());
        }
    }

    /// Entries held.
    pub fn len(&self) -> usize {
        self.map.len()
    }

    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    /// The most entries it holds.
    pub fn cap(&self) -> usize {
        self.cap
    }

    /// Entries evicted by the cap so far.
    pub fn evicted(&self) -> u64 {
        self.evicted
    }
}

/// Lot 314 (BUG-92, BUG-125): admit a key at most once per `window`; the
/// table capped ([`BoundedMap`]). A key evicted by the cap is admitted again
/// (one more record, which the per-rule budget still bounds): a flood of
/// distinct keys costs a bounded table, never an unbounded one. The window
/// is anchored on the admission (a repeat held back does not extend it).
pub struct RepeatWindow<K> {
    seen: BoundedMap<K, Instant>,
    window: Duration,
}

impl<K: Clone + Eq + Hash> RepeatWindow<K> {
    pub fn new(window: Duration, cap: usize) -> Self {
        Self {
            seen: BoundedMap::new(cap),
            window,
        }
    }

    /// Whether `key` is admitted at `now`: never seen, evicted, or its last
    /// admission at least a window old.
    pub fn admit(&mut self, key: K, now: Instant) -> bool {
        if let Some(t) = self.seen.get(&key) {
            if now.saturating_duration_since(*t) < self.window {
                return false;
            }
        }
        self.seen.insert(key, now);
        true
    }

    /// Keys held.
    pub fn len(&self) -> usize {
        self.seen.len()
    }

    pub fn is_empty(&self) -> bool {
        self.seen.is_empty()
    }

    /// The most keys it holds.
    pub fn cap(&self) -> usize {
        self.seen.cap()
    }
}

/// Lot 314 (BUG-83): a rule that fires once per process — keyed by the
/// process's pid and start, so a pid the kernel gives to a new process is a
/// new key, and capped ([`BoundedMap`], the pid fired for least recently
/// evicted). It holds, per pid, the start of the process it last fired for
/// (`None`: the start could not be read — the process had exited when its
/// record was read).
///
/// [`Self::first`] answers, for a record of process (`pid`, `start`):
/// - a pid never seen (or evicted): the first — fire;
/// - the same start: the same process — not again;
/// - another start: a new process holds the pid — fire;
/// - no start (the process has exited since its record was written): the
///   record is the last process's that held the pid — not again. A start
///   that could not be read before and can now is a new process (the
///   earlier one had exited) — fire.
pub struct OncePerProcess {
    fired: BoundedMap<u32, Option<u64>>,
}

impl OncePerProcess {
    pub fn new(cap: usize) -> Self {
        Self {
            fired: BoundedMap::new(cap),
        }
    }

    /// Whether this is the first time for process (`pid`, `start`); see the
    /// type's doc.
    pub fn first(&mut self, pid: u32, start: Option<u64>) -> bool {
        let first = match (self.fired.get(&pid), start) {
            (None, _) => true,
            (Some(_), None) => false,
            (Some(held), Some(s)) => *held != Some(s),
        };
        if first {
            self.fired.insert(pid, start);
        } else {
            self.fired.touch(&pid);
        }
        first
    }

    /// Processes held.
    pub fn len(&self) -> usize {
        self.fired.len()
    }

    pub fn is_empty(&self) -> bool {
        self.fired.is_empty()
    }

    /// The most processes it holds.
    pub fn cap(&self) -> usize {
        self.fired.cap()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pops_in_recency_order_and_skips_removed_keys() {
        let mut l = LazyLru::new();
        for k in 1..=4u32 {
            l.touch(k);
        }
        l.touch(1); // 1 moves to the back
        l.remove(&2);
        assert_eq!(l.len(), 3);
        assert_eq!(l.pop_oldest(), Some(3));
        assert_eq!(l.pop_oldest(), Some(4));
        assert_eq!(l.pop_oldest(), Some(1));
        assert_eq!(l.pop_oldest(), None);
        assert!(l.is_empty());
    }

    #[test]
    fn the_queue_stays_bounded_under_churn() {
        let mut l = LazyLru::new();
        for k in 0..100_000u32 {
            l.touch(k);
            l.remove(&k);
            l.touch(7);
        }
        assert_eq!(l.len(), 1);
        assert!(l.queue_len() <= 2 * COMPACT_FLOOR + 1, "{}", l.queue_len());
    }

    #[test]
    fn a_small_floor_keeps_a_small_queue() {
        let mut l = LazyLru::with_compact_floor(4);
        for _ in 0..1000 {
            l.touch(1u32);
        }
        assert_eq!(l.len(), 1);
        assert!(l.queue_len() <= 9, "{}", l.queue_len());
    }

    #[test]
    fn loss_counter_warns_once_a_minute() {
        static TOTAL: AtomicU64 = AtomicU64::new(0);
        let mut c = LossCounter::new(&TOTAL);
        assert!(c.bump());
        assert!(!c.bump());
        assert!(!c.bump());
        assert_eq!(c.count(), 3);
        assert_eq!(TOTAL.load(Ordering::Relaxed), 3);
    }

    #[test]
    fn a_bounded_map_evicts_the_least_recent_past_its_cap() {
        let mut m = BoundedMap::new(3);
        for k in 1..=3u32 {
            m.insert(k, k * 10);
        }
        m.touch(&1); // 1 is now the most recent
        m.insert(4, 40);
        assert_eq!(m.len(), 3);
        assert_eq!(m.get(&2), None, "the least recent went");
        assert_eq!((m.get(&1), m.get(&3), m.get(&4)), (Some(&10), Some(&30), Some(&40)));
        assert_eq!(m.evicted(), 1);
        m.insert(3, 31); // a rewrite is no new entry
        assert_eq!((m.len(), m.get(&3), m.evicted()), (3, Some(&31), 1));
        assert_eq!(BoundedMap::<u32, ()>::new(0).cap(), 1, "a cap is at least one");
    }

    #[test]
    fn a_repeat_window_admits_once_per_window_within_its_cap() {
        let t0 = Instant::now();
        let s = Duration::from_secs(1);
        let mut w = RepeatWindow::new(10 * s, 2);
        assert!(w.admit("a".to_string(), t0));
        assert!(!w.admit("a".to_string(), t0 + 9 * s), "within the window");
        assert!(w.admit("a".to_string(), t0 + 10 * s), "a window later");
        assert!(!w.admit("a".to_string(), t0 + 15 * s), "anchored on the admission");
        assert!(w.admit("b".to_string(), t0 + 15 * s));
        assert!(w.admit("c".to_string(), t0 + 15 * s));
        assert_eq!(w.len(), 2, "capped");
        assert!(w.admit("a".to_string(), t0 + 16 * s), "evicted: admitted again");
        // a clock that went back is within the window (never a second admission)
        assert!(!w.admit("a".to_string(), t0));
    }

    #[test]
    fn once_per_process_is_one_answer_per_pid_and_start() {
        let mut o = OncePerProcess::new(2);
        assert!(o.first(10, Some(500)));
        assert!(!o.first(10, Some(500)), "the same process");
        assert!(!o.first(10, None), "its record read after it exited");
        assert!(o.first(10, Some(900)), "a new process holds the pid");
        assert!(!o.first(10, Some(900)));
        assert!(o.first(11, None), "a process that had exited when read");
        assert!(!o.first(11, None));
        assert!(o.first(11, Some(70)), "a live process after one that had exited");
        assert!(o.first(12, Some(1)));
        assert_eq!(o.len(), 2, "capped");
        assert!(o.first(10, Some(900)), "evicted: a first time again");
    }
}
