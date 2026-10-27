//! Bounded ring buffer of recent events.
//!
//! The agent main loop pushes every event into the buffer, and the posture
//! trigger detector reads the buffered events, borrowed under the read
//! lock ([`CorrelationBuffer::with_recent`]), for the patterns it counts
//! over time (reconnaissance, bursts). The buffer is bounded (default 1000
//! events, oldest evicted first) so memory stays predictable on a busy
//! host.
//!
//! It also used to select the events related to a focal one for the
//! prompt of the on-host LLM advisor (external audit XAI-004, XAI-013,
//! LLMR-010); that selection left with the advisor in Wave 4 (lab PR 214).
//! The rules' own correlation is the agent's `decision::correlation`.

use std::collections::VecDeque;

use nn_model::Event;
use parking_lot::RwLock;

const DEFAULT_CAPACITY: usize = 1000;

/// Lock-free-ish ring of recent events. Cloning is cheap (`Arc`).
#[derive(Debug, Clone)]
pub struct CorrelationBuffer {
    inner: std::sync::Arc<Inner>,
}

#[derive(Debug)]
struct Inner {
    capacity: usize,
    queue: RwLock<VecDeque<Event>>,
}

impl CorrelationBuffer {
    /// A buffer of `capacity` events, at least one. External audit XAI-017
    /// (NN-AUD-351): a capacity of 0 never evicted, and the buffer grew
    /// with every event (only tests build one with `new`; the agent's is
    /// [`Self::with_default_capacity`]).
    pub fn new(capacity: usize) -> Self {
        let capacity = capacity.max(1);
        Self {
            inner: std::sync::Arc::new(Inner {
                capacity,
                queue: RwLock::new(VecDeque::with_capacity(capacity)),
            }),
        }
    }

    pub fn with_default_capacity() -> Self {
        Self::new(DEFAULT_CAPACITY)
    }

    pub fn push(&self, event: Event) {
        let mut q = self.inner.queue.write();
        while q.len() >= self.inner.capacity {
            q.pop_front();
        }
        q.push_back(event);
    }

    pub fn len(&self) -> usize {
        self.inner.queue.read().len()
    }

    pub fn is_empty(&self) -> bool {
        self.inner.queue.read().is_empty()
    }

    pub fn capacity(&self) -> usize {
        self.inner.capacity
    }

    /// Run `f` over the buffered events, borrowed under the read lock
    /// (review 72: `snapshot` cloned up to 1,000 events per event).
    pub fn with_recent<R>(&self, f: impl FnOnce(&VecDeque<Event>) -> R) -> R {
        f(&self.inner.queue.read())
    }

    /// Snapshot of all currently buffered events (cloned).
    pub fn snapshot(&self) -> Vec<Event> {
        self.inner.queue.read().iter().cloned().collect()
    }
}

impl Default for CorrelationBuffer {
    fn default() -> Self {
        Self::with_default_capacity()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spawn(pid: u32, ppid: u32, filename: &str, ts: u64) -> Event {
        Event::ProcessSpawn {
            pid,
            ppid,
            uid: 1000,
            gid: 1000,
            comm: "x".into(),
            filename: filename.into(),
            timestamp_ns: ts,
            argv: Vec::new(),
            parent_comm: String::new(),
            parent_start_ns: 0,
            start_ns: 0,
            parent_is_kthread: false,
            exe: Default::default(),
            argv_truncated: false,
            filename_truncated: false,
            stdio: Default::default(),
        }
    }

    #[test]
    fn ring_evicts_oldest_on_overflow() {
        let buf = CorrelationBuffer::new(3);
        buf.push(spawn(1, 0, "/a", 1));
        buf.push(spawn(2, 0, "/b", 2));
        buf.push(spawn(3, 0, "/c", 3));
        assert_eq!(buf.len(), 3);
        buf.push(spawn(4, 0, "/d", 4));
        assert_eq!(buf.len(), 3);
        let snap = buf.snapshot();
        // pid=1 evicted
        assert!(!snap
            .iter()
            .any(|e| matches!(e, Event::ProcessSpawn { pid: 1, .. })));
        assert!(snap
            .iter()
            .any(|e| matches!(e, Event::ProcessSpawn { pid: 4, .. })));
    }

    /// External audit XAI-017: a capacity of 0 never evicted.
    #[test]
    fn zero_capacity_is_normalised_and_bounded() {
        let buf = CorrelationBuffer::new(0);
        assert_eq!(buf.capacity(), 1);
        for i in 0..5 {
            buf.push(spawn(i, 0, "/a", u64::from(i)));
        }
        assert_eq!(buf.len(), 1);
        assert!(matches!(
            buf.snapshot().as_slice(),
            [Event::ProcessSpawn { pid: 4, .. }]
        ));
    }
}
