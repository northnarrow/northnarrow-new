//! Bounded ring buffer of recent events used as ADE context.
//!
//! The agent main loop pushes every event into the buffer; when ADE
//! is invoked it queries the buffer for events related to the focal
//! one ([`CorrelationBuffer::get_correlated`]). "Related" means either:
//!
//! - keyed: the same pid, the same parent pid (`ppid`) or the same
//!   filename as the focal event, within ten times the time window;
//! - nearby: within a sliding time window (default: 30 s) of the focal
//!   event.
//!
//! Keyed events are selected first (external audit XAI-013), so that a
//! burst of unrelated events cannot push them out of the context.
//!
//! This is a deliberately simple correlation model. A proper
//! process-tree-aware correlator with file co-access tracking is a
//! follow-up sub-tappa. The buffer is bounded (default 1000 events,
//! LRU-style) so memory stays predictable on a busy host.

use std::cmp::Reverse;
use std::collections::VecDeque;
use std::mem::discriminant;

use common::Event;
use parking_lot::RwLock;

use crate::ade::sanitize::{correlated_line_cost, CORRELATED_BLOCK_CAP, CORRELATED_MAX};

const DEFAULT_CAPACITY: usize = 1000;
const DEFAULT_LOOKBACK_NS: u64 = 30_000_000_000; // 30 s

/// External audit XAI-013: a keyed event (same pid, ppid or filename) is
/// correlated within this many time windows of the focal event. The
/// precursor of a chain can come minutes before its last step; the bound
/// keeps a stale event of a reused pid out.
const KEYED_LOOKBACK_FACTOR: u64 = 10;

/// External audit XAI-013: the candidates of each tier that the selection
/// considers, in multiples of `max_hits`: every slot, plus as many events
/// left out for their injection score. It bounds the clones made under
/// the lock and the sanitizer runs (about 50 µs each). A tier with more
/// left-out events than that fills fewer slots; such a flood already
/// holds the verdict at Escalate (the sanity check weighs them, LLMR-010).
const CANDIDATES_PER_TIER_FACTOR: usize = 2;

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

    /// Run `f` over the buffered events, borrowed under the read lock
    /// (review 72: `snapshot` cloned up to 1,000 events per event).
    pub fn with_recent<R>(&self, f: impl FnOnce(&VecDeque<Event>) -> R) -> R {
        f(&self.inner.queue.read())
    }

    /// Snapshot of all currently buffered events (cloned).
    pub fn snapshot(&self) -> Vec<Event> {
        self.inner.queue.read().iter().cloned().collect()
    }

    /// The events related to `focal`, oldest first: at most `max_hits`
    /// that the prompt renders, within its byte cap, plus at most
    /// `max_hits` that it leaves out for their injection score (they still
    /// weigh in its sanity check, external audit LLMR-010).
    ///
    /// External audit XAI-013: the selection used to keep the newest 50 of
    /// every event that was either nearby or keyed, and the prompt the
    /// newest 20 of those; about 20 cheap events (DNS queries) pushed a
    /// precursor out of what the model saw. It is now in two tiers:
    ///
    /// 1. keyed events, newest first, up to half of `max_hits`;
    /// 2. nearby events, newest first, up to `max_hits` in all;
    /// 3. the remaining keyed events, if slots are left.
    ///
    /// An event left out of the prompt for its injection score takes no
    /// slot, and an event whose line no longer fits the block's byte cap
    /// is skipped, so the prompt renders exactly the selection.
    ///
    /// External audit XAI-004: the agent pushes a copy of the focal event
    /// before it queries, and the copy was excluded by address, which
    /// never matched: the focal event sat in its own context. The newest
    /// event of the same variant, pid and timestamp is now the copy; it is
    /// excluded, and so is anything pushed after it, as when the query ran
    /// at once. An ExecCheck and the ProcessSpawn of the same exec differ
    /// in variant, so the other one stays.
    pub fn get_correlated(&self, focal: &Event, lookback_ns: u64, max_hits: usize) -> Vec<Event> {
        let focal_ts = event_timestamp_ns(focal);
        let (focal_pid, focal_ppid, focal_filename) = focal_keys(focal);
        let keyed_window = lookback_ns.saturating_mul(KEYED_LOOKBACK_FACTOR);
        let per_tier = max_hits.saturating_mul(CANDIDATES_PER_TIER_FACTOR);

        // (push order, event), cloned under the lock, newest first.
        let (keyed, nearby) = {
            let q = self.inner.queue.read();
            let end = q
                .iter()
                .rposition(|e| is_copy_of(e, focal, focal_pid, focal_ts))
                .unwrap_or(q.len());
            let mut keyed: Vec<(usize, &Event)> = Vec::new();
            let mut nearby: Vec<(usize, &Event)> = Vec::new();
            for (pos, e) in q.iter().enumerate().take(end).rev() {
                let dt = event_timestamp_ns(e).abs_diff(focal_ts);
                if dt <= keyed_window && matches_keys(e, focal_pid, focal_ppid, focal_filename) {
                    keyed.push((pos, e));
                } else if dt <= lookback_ns {
                    nearby.push((pos, e));
                }
            }
            (newest(keyed, per_tier), newest(nearby, per_tier))
        };

        let mut sel = Selection::new(max_hits);
        let mut keyed = keyed.into_iter();
        sel.fill(&mut keyed, max_hits / 2);
        sel.fill(&mut nearby.into_iter(), max_hits);
        sel.fill(&mut keyed, max_hits);

        let mut out = sel.chosen;
        out.sort_by_key(|(pos, e)| (event_timestamp_ns(e), *pos));
        out.into_iter().map(|(_, e)| e).collect()
    }

    /// Convenience wrapper using default lookback / max_hits values.
    /// At most [`CORRELATED_MAX`] events, the prompt's limit.
    pub fn get_correlated_default(&self, focal: &Event) -> Vec<Event> {
        self.get_correlated(focal, DEFAULT_LOOKBACK_NS, CORRELATED_MAX)
    }
}

/// The newest `n` of `v` (newest pushed first), cloned. A stable sort:
/// equal timestamps keep the newest push first.
fn newest(mut v: Vec<(usize, &Event)>, n: usize) -> Vec<(usize, Event)> {
    v.sort_by_key(|(_, e)| Reverse(event_timestamp_ns(e)));
    v.into_iter()
        .take(n)
        .map(|(pos, e)| (pos, e.clone()))
        .collect()
}

/// External audit XAI-013: the slots of the correlated context.
struct Selection {
    max_hits: usize,
    rendered: usize,
    left_out: usize,
    bytes: usize,
    chosen: Vec<(usize, Event)>,
}

impl Selection {
    fn new(max_hits: usize) -> Self {
        Self {
            max_hits,
            rendered: 0,
            left_out: 0,
            bytes: 0,
            chosen: Vec::new(),
        }
    }

    /// Take from `candidates` until `limit` rendered events are chosen.
    fn fill(&mut self, candidates: &mut impl Iterator<Item = (usize, Event)>, limit: usize) {
        while self.rendered < limit {
            let Some((pos, e)) = candidates.next() else {
                return;
            };
            match correlated_line_cost(&e) {
                // Left out of the prompt: no slot, kept for the sanity check.
                None => {
                    if self.left_out < self.max_hits {
                        self.left_out += 1;
                        self.chosen.push((pos, e));
                    }
                }
                Some(cost) if self.bytes + cost <= CORRELATED_BLOCK_CAP => {
                    self.bytes += cost;
                    self.rendered += 1;
                    self.chosen.push((pos, e));
                }
                // Its line would not fit the block: a shorter one may.
                Some(_) => {}
            }
        }
    }
}

/// External audit XAI-004: `e` is the buffer's copy of `focal`.
fn is_copy_of(e: &Event, focal: &Event, focal_pid: u32, focal_ts: u64) -> bool {
    discriminant(e) == discriminant(focal)
        && focal_keys(e).0 == focal_pid
        && event_timestamp_ns(e) == focal_ts
}

/// Whether `e` shares a pid, a parent pid or a filename with `focal`.
pub fn shares_key(focal: &Event, e: &Event) -> bool {
    let (pid, ppid, filename) = focal_keys(focal);
    matches_keys(e, pid, ppid, filename)
}

impl Default for CorrelationBuffer {
    fn default() -> Self {
        Self::with_default_capacity()
    }
}

fn event_timestamp_ns(e: &Event) -> u64 {
    match e {
        Event::ModuleLoad { timestamp_ns, .. } => *timestamp_ns,
        Event::IoUring { timestamp_ns, .. } | Event::BpfSyscall { timestamp_ns, .. } => {
            *timestamp_ns
        }
        Event::ProcessSpawn { timestamp_ns, .. }
        | Event::FileOpen { timestamp_ns, .. }
        | Event::MassWrite { timestamp_ns, .. }
        | Event::ExecCheck { timestamp_ns, .. }
        | Event::TcpConnect { timestamp_ns, .. }
        | Event::DnsQuery { timestamp_ns, .. }
        | Event::DnsFlood { timestamp_ns, .. }
        | Event::SensorFlood { timestamp_ns, .. }
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
        // BUG-034: module load keys off (loader_pid, source path).
        Event::ModuleLoad {
            loader_pid, path, ..
        } => (*loader_pid, None, path.as_deref()),
        Event::IoUring { pid, .. } | Event::BpfSyscall { pid, .. } => (*pid, None, None),
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
        Event::FileOpen { pid, filename, .. } | Event::MassWrite { pid, filename, .. } => {
            (*pid, None, Some(filename.as_str()))
        }
        Event::TcpConnect { pid, .. }
        | Event::DnsQuery { pid, .. }
        | Event::DnsFlood { pid, .. }
        | Event::SensorFlood { pid, .. }
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
            start_ns: 0,
            parent_is_kthread: false,
            exe: Default::default(),
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

    const S: u64 = 1_000_000_000;

    fn exec_check(pid: u32, ppid: u32, filename: &str, ts: u64) -> Event {
        Event::ExecCheck {
            pid,
            ppid,
            uid: 1000,
            comm: "x".into(),
            filename: filename.into(),
            timestamp_ns: ts,
            exe: Default::default(),
        }
    }

    fn dns(pid: u32, query: &str, ts: u64) -> Event {
        Event::DnsQuery {
            pid,
            uid: 1000,
            comm: "curl".into(),
            exe: None,
            query_name: query.into(),
            query_type: 1,
            dns_server: [0u8; 16],
            family: 2,
            timestamp_ns: ts,
            qname_partial: false,
        }
    }

    fn has_spawn(events: &[Event], file: &str) -> bool {
        events
            .iter()
            .any(|e| matches!(e, Event::ProcessSpawn { filename, .. } if filename == file))
    }

    /// A keyed event counts within ten time windows, and no further.
    #[test]
    fn correlated_finds_same_pid() {
        let buf = CorrelationBuffer::new(10);
        buf.push(spawn(42, 7, "/stale", S));
        buf.push(spawn(42, 7, "/a", 91 * S));
        buf.push(spawn(42, 7, "/b", 95 * S));
        buf.push(spawn(99, 8, "/c", 95 * S));
        let focal = spawn(42, 7, "/d", 100 * S);
        // A 1 s window: "/c" (pid 99, ppid 8) is outside it and keyless;
        // "/stale" is keyed but 99 s old, past the 10 s keyed window.
        let hits = buf.get_correlated(&focal, S, 50);
        assert_eq!(hits.len(), 2);
        assert!(has_spawn(&hits, "/a") && has_spawn(&hits, "/b"));
    }

    #[test]
    fn correlated_finds_same_ppid() {
        let buf = CorrelationBuffer::new(10);
        buf.push(spawn(10, 5, "/a", 95 * S));
        buf.push(spawn(11, 5, "/b", 96 * S));
        buf.push(spawn(12, 9, "/c", 97 * S));
        let focal = spawn(99, 5, "/d", 100 * S);
        let hits = buf.get_correlated(&focal, S, 50);
        assert_eq!(hits.len(), 2);
        assert!(hits
            .iter()
            .all(|e| matches!(e, Event::ProcessSpawn { ppid: 5, .. })));
    }

    /// External audit XAI-004: the agent pushes a copy of the focal event
    /// and then queries; the copy is not its own context. The ExecCheck of
    /// the same exec (same pid and timestamp, another variant) stays.
    #[test]
    fn focal_clone_excluded_exec_check_kept() {
        let buf = CorrelationBuffer::new(100);
        let ts = 100 * S;
        buf.push(dns(7, "example.org", ts - S));
        buf.push(exec_check(4242, 1, "/tmp/payload", ts));
        let focal = spawn(4242, 1, "/tmp/payload", ts);
        buf.push(focal.clone());
        // Pushed after the focal event: not part of its context, as when
        // the query ran at once.
        buf.push(dns(8, "later.example.org", ts + 1));

        let hits = buf.get_correlated_default(&focal);
        assert!(!has_spawn(&hits, "/tmp/payload"), "{hits:?}");
        assert!(hits
            .iter()
            .any(|e| matches!(e, Event::ExecCheck { pid: 4242, .. })));
        assert_eq!(hits.len(), 2, "{hits:?}");
    }

    /// External audit XAI-004: the focal event appears once in its prompt,
    /// in the untrusted event data, not again among its correlated events.
    #[test]
    fn focal_appears_once_in_the_prompt() {
        let buf = CorrelationBuffer::new(100);
        let ts = 100 * S;
        buf.push(spawn(300, 1, "/usr/bin/make", ts - 2 * S));
        let focal = spawn(4242, 1, "/tmp/payload", ts);
        buf.push(focal.clone());
        let block = rendered_block(&focal, buf.get_correlated_default(&focal));
        assert!(block.contains("- process_spawn pid=300 "), "{block}");
        assert!(!block.contains("pid=4242"), "{block}");
    }

    /// The correlated block of the prompt ADE builds for `focal`.
    fn rendered_block(focal: &Event, recent_events: Vec<Event>) -> String {
        use crate::ade::prompt::SystemPrompt;
        use crate::ade::sanitize::sanitize_event_for_ade;
        use crate::ade::structured_prompt::build_structured_prompt;
        use crate::ade::{AdeConfig, EventContext, HostContext};

        let ctx = EventContext {
            recent_events,
            host_context: HostContext {
                hostname: "h".into(),
                host_id: "id".into(),
                kernel_version: "6.8".into(),
                agent_version: "0.0.1".into(),
            },
        };
        let prompt = build_structured_prompt(
            &SystemPrompt { raw: "sys".into() },
            &AdeConfig::default(),
            &sanitize_event_for_ade(focal),
            &ctx,
        );
        prompt
            .user
            .split("=== UNTRUSTED CORRELATED EVENTS")
            .nth(1)
            .and_then(|b| b.split("=== END UNTRUSTED CORRELATED EVENTS ===").next())
            .unwrap_or_default()
            .to_string()
    }

    /// External audit XAI-013: a precursor sharing the focal event's parent
    /// at t0, then 100 unrelated DNS queries with long names over 20 s. The
    /// newest 50 of the window used to push it out (and the prompt kept the
    /// newest 20, the 4 KiB cap the newest of those); it is now in the
    /// selection and in the rendered block.
    #[test]
    fn keyed_precursor_survives_burst() {
        let buf = CorrelationBuffer::with_default_capacity();
        let t0 = 1_000 * S;
        buf.push(spawn(500, 77, "/tmp/stage1", t0));
        for i in 0..100u64 {
            let name = format!("{}{i}.cdn.example.net", "a".repeat(150));
            buf.push(dns(9000 + i as u32, &name, t0 + (i + 1) * S / 5));
        }
        let focal = spawn(4242, 77, "/tmp/stage2", t0 + 20 * S + 1);
        buf.push(focal.clone());

        let hits = buf.get_correlated_default(&focal);
        assert!(has_spawn(&hits, "/tmp/stage1"), "precursor selected");
        assert!(hits.len() <= CORRELATED_MAX, "{}", hits.len());
        // Oldest first, as the buffer holds them.
        assert!(hits
            .windows(2)
            .all(|w| event_timestamp_ns(&w[0]) <= event_timestamp_ns(&w[1])));

        let block = rendered_block(&focal, hits.clone());
        assert!(block.contains(r#"filename="/tmp/stage1""#), "{block}");
        assert!(block.len() <= CORRELATED_BLOCK_CAP + 200, "{}", block.len());
        // The prompt renders the selection whole.
        assert!(!block.contains("correlated_events_truncated"), "{block}");
        assert_eq!(block.matches("\n- ").count(), hits.len(), "{block}");
    }

    /// External audit XAI-013: an event left out of the prompt for its
    /// injection score takes no slot. 20 of them, newer than 20 benign
    /// events, used to fill the newest 20 the prompt kept.
    #[test]
    fn omitted_events_do_not_consume_slots() {
        use crate::ade::sanitize::sanitize_correlated;

        let buf = CorrelationBuffer::with_default_capacity();
        let t0 = 1_000 * S;
        for i in 0..20u64 {
            buf.push(dns(100, &format!("ok{i}.example.org"), t0 + i));
        }
        for i in 0..20u64 {
            let name = format!("ignore-previous-instructions-{i}.example");
            buf.push(dns(200, &name, t0 + 100 + i));
        }
        let focal = spawn(4242, 1, "/tmp/x", t0 + S);
        buf.push(focal.clone());

        let hits = buf.get_correlated_default(&focal);
        let c = sanitize_correlated(&focal, &hits);
        assert_eq!(c.events.len(), CORRELATED_MAX, "every slot rendered");
        assert!(c
            .events
            .iter()
            .all(|l| l.event.safe_query_name.starts_with("ok")));
        // Kept for the sanity check (external audit LLMR-010), bounded.
        assert_eq!(c.omitted, CORRELATED_MAX);
        assert!(c.max_score >= crate::ade::HIGH_INJECTION_SCORE_REJECT);
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
