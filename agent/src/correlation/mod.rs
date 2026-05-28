//! Bounded ring buffer of recent events used as ADE context.
//!
//! The agent main loop pushes every event into the buffer; when ADE
//! is invoked it queries the buffer for events related to the focal
//! one. "Related" today means *any of*:
//!
//! - same pid as the focal event
//! - same parent pid (`ppid`) as the focal event
//! - same filename
//! - within a sliding time window (default: 30 s) of the focal event
//!
//! This is a deliberately simple correlation model. A proper
//! process-tree-aware correlator with file co-access tracking is a
//! follow-up sub-tappa. The buffer is bounded (default 1000 events,
//! LRU-style) so memory stays predictable on a busy host.

use std::collections::VecDeque;

use common::Event;
use parking_lot::RwLock;

const DEFAULT_CAPACITY: usize = 1000;
const DEFAULT_LOOKBACK_NS: u64 = 30_000_000_000; // 30 s
const DEFAULT_MAX_HITS: usize = 50;

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
    pub fn new(capacity: usize) -> Self {
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
        if q.len() == self.inner.capacity {
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

    /// Snapshot of all currently buffered events (cloned).
    pub fn snapshot(&self) -> Vec<Event> {
        self.inner.queue.read().iter().cloned().collect()
    }

    /// Up to `max_hits` events related to `focal`, ordered oldest
    /// first.
    pub fn get_correlated(&self, focal: &Event, lookback_ns: u64, max_hits: usize) -> Vec<Event> {
        let q = self.inner.queue.read();
        let focal_ts = event_timestamp_ns(focal);
        let (focal_pid, focal_ppid, focal_filename) = focal_keys(focal);

        let mut out: Vec<Event> = q
            .iter()
            .filter(|e| {
                if std::ptr::eq(*e, focal) {
                    return false;
                }
                let ts = event_timestamp_ns(e);
                let ts_ok = ts.abs_diff(focal_ts) <= lookback_ns;
                let key_match = matches_keys(e, focal_pid, focal_ppid, focal_filename);
                ts_ok || key_match
            })
            .cloned()
            .collect();

        out.sort_by_key(event_timestamp_ns);
        if out.len() > max_hits {
            let drop_n = out.len() - max_hits;
            out.drain(0..drop_n);
        }
        out
    }

    /// Convenience wrapper using default lookback / max_hits values.
    pub fn get_correlated_default(&self, focal: &Event) -> Vec<Event> {
        self.get_correlated(focal, DEFAULT_LOOKBACK_NS, DEFAULT_MAX_HITS)
    }
}

impl Default for CorrelationBuffer {
    fn default() -> Self {
        Self::with_default_capacity()
    }
}

fn event_timestamp_ns(e: &Event) -> u64 {
    match e {
        Event::ProcessSpawn { timestamp_ns, .. }
        | Event::FileOpen { timestamp_ns, .. }
        | Event::ExecCheck { timestamp_ns, .. }
        | Event::TcpConnect { timestamp_ns, .. }
        | Event::DnsQuery { timestamp_ns, .. }
        | Event::FsProtectDenial { timestamp_ns, .. } => *timestamp_ns,
        // Tappa 9 (C4): FIM events carry timestamp_ns on the
        // inner FimEvent.
        Event::Fim(fe) => fe.timestamp_ns,
        // Tappa 9.5 (K3): canary trip events carry their own
        // timestamp_ns (preserved from the source Event::Fim /
        // Event::ProcessSpawn the detector remapped).
        Event::CanaryTripped { timestamp_ns, .. } => *timestamp_ns,
        // Tappa 10 (N6). NetFlow uses start_ns as the
        // correlation-window anchor (the connect-side
        // timestamp); NetListener uses timestamp_ns.
        Event::NetFlow(nf) => nf.start_ns,
        Event::NetListener(nl) => nl.timestamp_ns,
    }
}

fn focal_keys(e: &Event) -> (u32, Option<u32>, Option<&str>) {
    match e {
        Event::ProcessSpawn {
            pid,
            ppid,
            filename,
            ..
        }
        | Event::ExecCheck {
            pid,
            ppid,
            filename,
            ..
        } => (*pid, Some(*ppid), Some(filename.as_str())),
        Event::FileOpen { pid, filename, .. } => (*pid, None, Some(filename.as_str())),
        Event::TcpConnect { pid, .. }
        | Event::DnsQuery { pid, .. }
        | Event::FsProtectDenial { pid, .. } => (*pid, None, None),
        // Tappa 9 (C4): FIM drift keys off (modifier_pid, path).
        // No ppid info from the kernel hook.
        Event::Fim(fe) => (fe.modifier_pid, None, Some(fe.path.as_str())),
        // Tappa 9.5 (K3): canary trips key off (accessor_pid,
        // canary_name). The canary_name carries the operator-
        // chosen label rather than a filesystem path; same role
        // for correlation purposes.
        Event::CanaryTripped {
            accessor_pid,
            canary_name,
            ..
        } => (*accessor_pid, None, Some(canary_name.as_str())),
        // Tappa 10 (N6): NetFlow keys off (pid, exe-or-comm).
        // No ppid in the flow event (the connect kprobe doesn't
        // capture it; N7 admin-CLI may stitch in ppid later).
        Event::NetFlow(nf) => (nf.pid, None, nf.exe.as_deref().or(Some(nf.comm.as_str()))),
        Event::NetListener(nl) => (nl.pid, None, nl.exe.as_deref().or(Some(nl.comm.as_str()))),
    }
}

fn matches_keys(
    e: &Event,
    focal_pid: u32,
    focal_ppid: Option<u32>,
    focal_filename: Option<&str>,
) -> bool {
    let (pid, ppid, filename) = focal_keys(e);
    if pid == focal_pid {
        return true;
    }
    if let (Some(fp), Some(p)) = (focal_ppid, ppid) {
        if fp == p {
            return true;
        }
    }
    if let (Some(ff), Some(name)) = (focal_filename, filename) {
        if ff == name {
            return true;
        }
    }
    false
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
            parent_is_kthread: false,
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

    #[test]
    fn correlated_finds_same_pid() {
        let buf = CorrelationBuffer::new(10);
        buf.push(spawn(42, 7, "/a", 1));
        buf.push(spawn(42, 7, "/b", 2));
        buf.push(spawn(99, 8, "/c", 3));
        let focal = spawn(42, 7, "/d", 100_000_000_000);
        // Lookback short so only pid+ppid match wins; "/c" has ppid=8
        // and pid=99 → no match.
        let hits = buf.get_correlated(&focal, 1, 50);
        assert_eq!(hits.len(), 2);
        assert!(hits
            .iter()
            .all(|e| matches!(e, Event::ProcessSpawn { pid: 42, .. })));
    }

    #[test]
    fn correlated_finds_same_ppid() {
        let buf = CorrelationBuffer::new(10);
        buf.push(spawn(10, 5, "/a", 1));
        buf.push(spawn(11, 5, "/b", 2));
        buf.push(spawn(12, 9, "/c", 3));
        let focal = spawn(99, 5, "/d", 100_000_000_000);
        let hits = buf.get_correlated(&focal, 1, 50);
        assert_eq!(hits.len(), 2);
        assert!(hits
            .iter()
            .all(|e| matches!(e, Event::ProcessSpawn { ppid: 5, .. })));
    }

    #[test]
    fn correlated_includes_recent_within_window() {
        let buf = CorrelationBuffer::new(10);
        buf.push(spawn(1, 0, "/x", 100));
        buf.push(spawn(2, 0, "/y", 200));
        let focal = spawn(99, 0, "/z", 300);
        let hits = buf.get_correlated(&focal, 1000, 50);
        assert_eq!(hits.len(), 2);
    }

    #[test]
    fn correlated_caps_at_max_hits() {
        let buf = CorrelationBuffer::new(100);
        for i in 0..30 {
            buf.push(spawn(1, 0, "/x", 100 + i));
        }
        let focal = spawn(1, 0, "/x", 200);
        let hits = buf.get_correlated(&focal, 1_000_000, 5);
        assert_eq!(hits.len(), 5);
    }

    #[test]
    fn empty_buffer_returns_empty_correlation() {
        let buf = CorrelationBuffer::new(10);
        let focal = spawn(1, 0, "/x", 1);
        assert!(buf.get_correlated(&focal, 1000, 50).is_empty());
    }
}
