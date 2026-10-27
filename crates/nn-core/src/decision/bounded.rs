//! Bounded-state helpers shared by the decision layer.
//!
//! External audit NETR-004 / NETR-010: the correlation store and the
//! ancestry tree enforced their caps with an O(n) scan per insert (or not
//! at all) and lost state without a trace. [`LazyLru`] gives O(1)
//! amortised recency order with lazy deletion; [`LossCounter`] counts
//! evictions of state that still mattered and rate-limits the WARN about
//! them. NETR-005 (the network rule windows) reuses both; NET-012 is meant
//! to.

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

impl<K: Copy + Eq + Hash> LazyLru<K> {
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
        self.live.insert(key, stamp);
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
}
