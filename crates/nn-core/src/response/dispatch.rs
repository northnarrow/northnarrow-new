//! Wave 4 restructure, R12c (lab PR 270; plan §3.4): the response
//! dispatcher's queue — stage 6 of an event's path.
//!
//! The decision thread decides; a thread of its own carries the responses
//! out (`nn-response`, the agent's `pipeline::dispatch`). Between them, this
//! queue: bounded, taken by severity, each process's responses in the order
//! they were decided, and a full queue that never drops an action silently.
//!
//! - **By severity.** Four lanes, Critical first. Aging: once the oldest
//!   job waited [`STARVATION_NS`], one take in [`AGED_TAKE_EVERY`] is it,
//!   whatever its lane — a flood of Critical kills cannot hold a Low
//!   throttle back for ever, and a backlog of old jobs cannot hold a new
//!   Critical kill back behind all of them (the more severe lanes keep the
//!   other takes; lab PR 270's EXP-13r: with every old job taken first, a
//!   backlog of 350 made the queue first in, first out).
//! - **In order per process** (the brief: "a later response for the same
//!   process never overtakes an earlier one"). The queue keeps each
//!   process's jobs (its [`ResponseQueue`] key: the process's pid *and*
//!   start, so a process that reused a pid is another process) in the order
//!   they were submitted, and a take runs the *oldest* job of the process
//!   the lane names: a Critical quarantine decided after a Low strip of the
//!   same process raises that process's turn (priority inheritance), and
//!   the strip runs first, then the quarantine. One thread takes: two jobs
//!   of one process never run at once.
//! - **A kill goes first** (review of #476). A kill of a process is placed
//!   before that process's queued jobs: it never waits behind its own
//!   process's throttle (the priority inversion), and a quarantine or a
//!   strip of the process runs after it. Once the kill *succeeded* (the
//!   process killed, or already gone) the caller takes out the process's
//!   queued throttles and blocks ([`DispatchJob::superseded_by_kill`],
//!   [`ResponseQueue::supersede`]) and answers them "superseded"; a kill
//!   that did not kill (a protected process, EPERM, a cgroup that would not
//!   die) leaves them to run — the re-check of #476: a compromised daemon
//!   the guard will not kill must still lose its network.
//! - **A repeat merges.** A job of the same process and the same action as
//!   the process's last queued job (a process that tripped two rules, or
//!   one rule twice, before its kill ran) is merged into it
//!   ([`DispatchJob::absorb`]): one action, both decisions answered by its
//!   outcome — not a second kill of a process already dead. Only into the
//!   last queued job of the process (its first, for a kill: a kill goes
//!   first), so the order is the submissions'.
//! - **A full queue** ([`RESPONSE_QUEUE_CAP`] jobs) never blocks the
//!   decision and never drops silently: the newest job of the least severe
//!   lane below the new job's severity is displaced (returned to the
//!   caller, which answers its decisions "not run" and counts it); when
//!   every queued job is at least as severe, a Critical kill is queued past
//!   the capacity (counted `over_cap`, up to [`OVER_CAP_FACTOR`] times it —
//!   review of #476: a full queue must not lose the kill of the payload to
//!   a flood of decoys), and any other new job is refused (returned,
//!   answered and counted the same way). The dispatcher signs
//!   the displaced and refused jobs in its next `overflow` row and the
//!   posture's `TelemetryLoss` is raised: a response not run is a loss the
//!   operator sees, never one nobody hears of.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet, VecDeque};
use std::hash::Hash;

use nn_model::Severity;

use crate::bus::LatencyHistogram;

/// Jobs the queue holds at most (stage 6). A job is one response of one
/// decision (its event and decision are shared by the decision's other
/// responses): with each event's paths and arguments bounded, a full queue
/// holds a few MiB.
pub const RESPONSE_QUEUE_CAP: usize = 1_024;

/// A full queue takes Critical kills past its capacity up to this many
/// times it (a hard bound: memory), counted `over_cap`.
pub const OVER_CAP_FACTOR: usize = 4;

/// The oldest job, once it waited this long, has a take by age (aging).
pub const STARVATION_NS: u64 = 500_000_000;

/// At most one take in this many is by age; the others go by severity.
pub const AGED_TAKE_EVERY: u32 = 4;

/// The lanes, by severity: index 0 is Low, 3 Critical.
pub const LANES: usize = 4;

/// The lane of a severity (0 Low … 3 Critical).
pub const fn lane_of(s: Severity) -> usize {
    match s {
        Severity::Low => 0,
        Severity::Medium => 1,
        Severity::High => 2,
        Severity::Critical => 3,
    }
}

/// The severity of a lane.
pub const fn severity_of_lane(lane: usize) -> Severity {
    match lane {
        0 => Severity::Low,
        1 => Severity::Medium,
        2 => Severity::High,
        _ => Severity::Critical,
    }
}

/// A severity's name in a row or the status (`low` … `critical`).
pub const fn severity_name(s: Severity) -> &'static str {
    match s {
        Severity::Low => "low",
        Severity::Medium => "medium",
        Severity::High => "high",
        Severity::Critical => "critical",
    }
}

/// What the queue needs of a job.
pub trait DispatchJob {
    /// The same action on the same target as `other` (merged when it is the
    /// process's last queued job).
    fn same_action(&self, other: &Self) -> bool;
    /// Take `other`'s decisions: one action answers both.
    fn absorb(&mut self, other: Self);
    /// A kill: placed before its process's queued jobs, never refused by a
    /// full queue when Critical.
    fn is_kill(&self) -> bool {
        false
    }
    /// Pointless once its process is killed (a throttle, a block): taken
    /// out after a kill of the process succeeded ([`ResponseQueue::
    /// supersede`]).
    fn superseded_by_kill(&self) -> bool {
        false
    }
}

/// What became of a submitted job.
#[derive(Debug, PartialEq, Eq)]
pub enum Submitted<J> {
    /// Queued; its sequence number.
    Queued(u64),
    /// Merged into the queued job with this sequence number.
    Merged(u64),
    /// Queued (its sequence number); the queue was full, and this less
    /// severe job was taken out to make room — not run.
    Displacing(u64, J),
    /// The queue was full of jobs at least as severe: not queued, not run.
    Refused(J),
}

/// A job the dispatcher takes.
#[derive(Debug, PartialEq, Eq)]
pub struct TakenJob<J> {
    pub seq: u64,
    pub job: J,
    pub severity: Severity,
    /// How long it waited in the queue (ns).
    pub waited_ns: u64,
    /// Taken before a more severe job of the same process that the lane
    /// named (priority inheritance), or by age (aging).
    pub inherited: bool,
    pub aged: bool,
}

/// The queue's counts since boot (stage 6).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DispatchStats {
    pub capacity: u64,
    /// Jobs submitted, queued, merged into a queued one.
    pub submitted: u64,
    pub queued: u64,
    pub merged: u64,
    /// Critical kills a full queue took past its capacity; jobs a kill of
    /// their process that succeeded took out (answered "superseded", not a
    /// loss).
    pub over_cap: u64,
    pub superseded: u64,
    /// Jobs not run: displaced by a more severe one, refused when full —
    /// per lane (Low … Critical). Stage 6's loss.
    pub displaced: [u64; LANES],
    pub refused: [u64; LANES],
    /// Jobs taken; by inheritance, by age.
    pub taken: u64,
    pub inherited: u64,
    pub aged: u64,
    /// Jobs in it now, per lane, and the most it held.
    pub depth: [u64; LANES],
    pub max_depth: u64,
    /// Queue to start of execution.
    pub wait: LatencyHistogram,
}

impl DispatchStats {
    /// Stage 6's total: jobs not run (displaced or refused).
    pub fn lost(&self) -> u64 {
        self.displaced.iter().sum::<u64>() + self.refused.iter().sum::<u64>()
    }
}

struct Entry<K, J> {
    key: K,
    lane: usize,
    enqueued_ns: u64,
    job: J,
}

/// The response queue (see the module's doc).
pub struct ResponseQueue<K, J> {
    cap: usize,
    next_seq: u64,
    /// Every queued job by its sequence number (the oldest first).
    jobs: BTreeMap<u64, Entry<K, J>>,
    /// Each lane's jobs, oldest first.
    lanes: [BTreeSet<u64>; LANES],
    /// Each process's jobs, in submission order.
    by_key: HashMap<K, VecDeque<u64>>,
    /// R12c-3: the processes whose job is running now (a take marks one,
    /// [`Self::done`] clears it). A take skips them: one process's jobs
    /// never run at once, in order, whatever the number of workers.
    running: HashSet<K>,
    /// Takes since the last one by age (aging's share).
    since_aged: u32,
    stats: DispatchStats,
}

impl<K: Eq + Hash + Clone, J: DispatchJob> ResponseQueue<K, J> {
    pub fn new(cap: usize) -> Self {
        Self {
            cap: cap.max(1),
            next_seq: 1,
            jobs: BTreeMap::new(),
            lanes: Default::default(),
            by_key: HashMap::new(),
            running: HashSet::new(),
            since_aged: AGED_TAKE_EVERY - 1,
            stats: DispatchStats {
                capacity: cap.max(1) as u64,
                ..DispatchStats::default()
            },
        }
    }

    pub fn len(&self) -> usize {
        self.jobs.len()
    }

    pub fn is_empty(&self) -> bool {
        self.jobs.is_empty()
    }

    /// R12c-3: the process `key`'s job taken last has run (its outcome
    /// written): its next job may be taken.
    pub fn done(&mut self, key: &K) {
        self.running.remove(key);
    }

    /// Processes with a job running now.
    pub fn running(&self) -> usize {
        self.running.len()
    }

    /// After a kill of the process `key` succeeded: its queued throttles
    /// and blocks, taken out (counted `superseded`) for the caller to
    /// answer. Never before the kill ran: a kill that did not kill leaves
    /// them to run.
    pub fn supersede(&mut self, key: &K) -> Vec<J> {
        let gone: Vec<u64> = self
            .by_key
            .get(key)
            .map(|q| {
                q.iter()
                    .copied()
                    .filter(|s| self.jobs[s].job.superseded_by_kill())
                    .collect()
            })
            .unwrap_or_default();
        gone.into_iter()
            .map(|s| {
                self.stats.superseded += 1;
                self.remove(s).job
            })
            .collect()
    }

    /// Submit `job` for the process `key`, of `severity`, at `now_ns`.
    /// Never blocks; see [`Submitted`].
    pub fn submit(&mut self, key: K, severity: Severity, now_ns: u64, job: J) -> Submitted<J> {
        self.stats.submitted += 1;
        let lane = lane_of(severity);
        let kill = job.is_kill();
        // A repeat of the process's last queued job (its first, for a kill)
        // is merged into it.
        let candidate = self
            .by_key
            .get(&key)
            .and_then(|q| if kill { q.front() } else { q.back() })
            .copied();
        if let Some(last) = candidate {
            if let Some(e) = self.jobs.get_mut(&last) {
                if e.job.same_action(&job) {
                    e.job.absorb(job);
                    if lane > e.lane {
                        // the more severe decision raises the job's lane
                        self.lanes[e.lane].remove(&last);
                        self.lanes[lane].insert(last);
                        e.lane = lane;
                    }
                    self.stats.merged += 1;
                    self.refresh_depth();
                    return Submitted::Merged(last);
                }
            }
        }
        let mut displaced = None;
        if self.jobs.len() >= self.cap {
            // the newest job of the least severe lane below this one's
            let victim = (0..lane).find_map(|l| self.lanes[l].last().copied());
            match victim {
                Some(v) => {
                    let e = self.remove(v);
                    self.stats.displaced[e.lane] += 1;
                    displaced = Some(e.job);
                }
                None if kill
                    && lane == LANES - 1
                    && self.jobs.len() < self.cap.saturating_mul(OVER_CAP_FACTOR) =>
                {
                    // a Critical kill is never refused: past the capacity
                    self.stats.over_cap += 1;
                }
                None => {
                    self.stats.refused[lane] += 1;
                    return Submitted::Refused(job);
                }
            }
        }
        let seq = self.next_seq;
        self.next_seq += 1;
        self.lanes[lane].insert(seq);
        let q = self.by_key.entry(key.clone()).or_default();
        if kill {
            q.push_front(seq);
        } else {
            q.push_back(seq);
        }
        self.jobs.insert(
            seq,
            Entry {
                key,
                lane,
                enqueued_ns: now_ns,
                job,
            },
        );
        self.stats.queued += 1;
        self.stats.max_depth = self.stats.max_depth.max(self.jobs.len() as u64);
        self.refresh_depth();
        match displaced {
            Some(d) => Submitted::Displacing(seq, d),
            None => Submitted::Queued(seq),
        }
    }

    /// The next job to run at `now_ns`: the oldest job of the process the
    /// most severe lane's oldest job is of — or, when the oldest job of all
    /// waited [`STARVATION_NS`] and none of the last [`AGED_TAKE_EVERY`]` -
    /// 1` takes was by age, that job's process's oldest (itself).
    ///
    /// R12c-3 (the pool): only the jobs of processes with no job running
    /// ([`Self::done`] not yet called for their last take) are candidates;
    /// `None` when every queued job's process has one running. The process
    /// taken is marked running until [`Self::done`].
    pub fn take(&mut self, now_ns: u64) -> Option<TakenJob<J>> {
        let (oldest, oldest_ns) = self
            .jobs
            .iter()
            .find(|(_, e)| !self.running.contains(&e.key))
            .map(|(s, e)| (*s, e.enqueued_ns))?;
        let aged = self.since_aged + 1 >= AGED_TAKE_EVERY
            && now_ns.saturating_sub(oldest_ns) >= STARVATION_NS;
        self.since_aged = if aged {
            0
        } else {
            self.since_aged.saturating_add(1)
        };
        let named = if aged {
            oldest
        } else {
            (0..LANES)
                .rev()
                .find_map(|l| {
                    self.lanes[l]
                        .iter()
                        .copied()
                        .find(|s| !self.running.contains(&self.jobs[s].key))
                })
                .expect("a free job is in a lane")
        };
        let key = self.jobs[&named].key.clone();
        self.running.insert(key.clone());
        let first = *self
            .by_key
            .get(&key)
            .and_then(|q| q.front())
            .expect("a queued job's process holds it");
        let e = self.remove(first);
        let waited_ns = now_ns.saturating_sub(e.enqueued_ns);
        self.stats.taken += 1;
        let inherited = first != named;
        if inherited {
            self.stats.inherited += 1;
        }
        let aged = aged && !inherited && self.lanes.iter().skip(e.lane + 1).any(|l| !l.is_empty());
        if aged {
            self.stats.aged += 1;
        }
        self.stats.wait.record_ns(waited_ns);
        Some(TakenJob {
            seq: first,
            job: e.job,
            severity: severity_of_lane(e.lane),
            waited_ns,
            inherited,
            aged,
        })
    }

    /// Every queued job, oldest first, taken out (the stop's).
    pub fn drain(&mut self) -> Vec<(u64, Severity, J)> {
        let seqs: Vec<u64> = self.jobs.keys().copied().collect();
        seqs.into_iter()
            .map(|s| {
                let e = self.remove(s);
                (s, severity_of_lane(e.lane), e.job)
            })
            .collect()
    }

    pub fn stats(&self) -> DispatchStats {
        self.stats.clone()
    }

    fn remove(&mut self, seq: u64) -> Entry<K, J> {
        let e = self.jobs.remove(&seq).expect("the job is queued");
        self.lanes[e.lane].remove(&seq);
        if let Some(q) = self.by_key.get_mut(&e.key) {
            q.retain(|s| *s != seq);
            if q.is_empty() {
                self.by_key.remove(&e.key);
            }
        }
        self.refresh_depth();
        e
    }

    fn refresh_depth(&mut self) {
        for (l, lane) in self.lanes.iter().enumerate() {
            self.stats.depth[l] = lane.len() as u64;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A job: its process, its action, the decisions it answers.
    #[derive(Debug, Clone, PartialEq, Eq)]
    struct J {
        pid: u32,
        action: &'static str,
        decisions: Vec<u32>,
    }

    impl DispatchJob for J {
        fn same_action(&self, other: &Self) -> bool {
            self.pid == other.pid && self.action == other.action
        }
        fn absorb(&mut self, other: Self) {
            self.decisions.extend(other.decisions);
        }
        fn is_kill(&self) -> bool {
            self.action == "kill"
        }
        fn superseded_by_kill(&self) -> bool {
            matches!(self.action, "throttle" | "block")
        }
    }

    fn j(pid: u32, action: &'static str, d: u32) -> J {
        J {
            pid,
            action,
            decisions: vec![d],
        }
    }

    const C: Severity = Severity::Critical;
    const H: Severity = Severity::High;
    const M: Severity = Severity::Medium;
    const L: Severity = Severity::Low;

    /// A take by a single worker: the job, its process done at once.
    fn take1(q: &mut ResponseQueue<u32, J>, now: u64) -> Option<TakenJob<J>> {
        let t = q.take(now)?;
        q.done(&t.job.pid);
        Some(t)
    }

    fn order(q: &mut ResponseQueue<u32, J>, now: u64) -> Vec<(u32, &'static str)> {
        std::iter::from_fn(|| take1(q, now).map(|t| (t.job.pid, t.job.action))).collect()
    }

    /// The most severe first; FIFO in a lane.
    #[test]
    fn the_most_severe_job_runs_first() {
        let mut q = ResponseQueue::new(16);
        q.submit(1, L, 0, j(1, "throttle", 1));
        q.submit(2, H, 0, j(2, "kill", 2));
        q.submit(3, C, 0, j(3, "kill", 3));
        q.submit(4, H, 0, j(4, "block", 4));
        q.submit(5, M, 0, j(5, "quarantine", 5));
        assert_eq!(
            order(&mut q, 1),
            [
                (3, "kill"),
                (2, "kill"),
                (4, "block"),
                (5, "quarantine"),
                (1, "throttle")
            ]
        );
        assert!(q.is_empty());
    }

    /// The brief: a later response for the same process never overtakes an
    /// earlier one — the Critical quarantine decided after the Low strip of
    /// pid 7 raises 7's turn, and the strip runs first, then the
    /// quarantine, both before pid 8's High.
    #[test]
    fn a_later_response_for_a_process_never_overtakes_an_earlier_one() {
        let mut q = ResponseQueue::new(16);
        q.submit(7, L, 0, j(7, "strip", 1));
        q.submit(8, H, 0, j(8, "block", 2));
        q.submit(7, C, 0, j(7, "quarantine", 3));
        let t = take1(&mut q, 1).unwrap();
        assert_eq!((t.job.pid, t.job.action, t.inherited), (7, "strip", true));
        assert_eq!(t.severity, L, "it keeps its own severity in the record");
        let t = take1(&mut q, 1).unwrap();
        assert_eq!(
            (t.job.pid, t.job.action, t.inherited),
            (7, "quarantine", false)
        );
        assert_eq!(order(&mut q, 1), [(8, "block")]);
        assert_eq!(q.stats().inherited, 1);
    }

    /// Review of #476: a kill goes before its process's queued jobs (its
    /// quarantine runs after it; another process's jobs are untouched);
    /// once it killed, the caller takes out its throttles and blocks
    /// (handed back once, answered "superseded") — the re-check of #476:
    /// never before, so a kill that did not kill leaves them to run.
    #[test]
    fn a_kill_goes_first_and_supersedes_its_process_s_throttle_and_block() {
        let submit_all = |q: &mut ResponseQueue<u32, J>| {
            q.submit(7, L, 0, j(7, "throttle", 1));
            q.submit(7, M, 0, j(7, "quarantine", 2));
            q.submit(7, L, 0, j(7, "block", 3));
            q.submit(8, L, 0, j(8, "throttle", 4));
            assert!(matches!(
                q.submit(7, H, 0, j(7, "kill", 5)),
                Submitted::Queued(_)
            ));
            // a second kill of 7 merges into the first (its process's first job)
            assert!(matches!(
                q.submit(7, C, 0, j(7, "kill", 6)),
                Submitted::Merged(_)
            ));
        };
        // the kill killed
        let mut q = ResponseQueue::new(16);
        submit_all(&mut q);
        let t = take1(&mut q, 1).unwrap();
        assert_eq!((t.job.pid, t.job.action), (7, "kill"));
        assert_eq!(t.job.decisions, [5, 6]);
        let gone: Vec<u32> = q
            .supersede(&7)
            .iter()
            .flat_map(|j| j.decisions.clone())
            .collect();
        assert_eq!(gone, [1, 3]);
        assert!(q.supersede(&7).is_empty(), "handed back once");
        assert_eq!(order(&mut q, 1), [(7, "quarantine"), (8, "throttle")]);
        let s = q.stats();
        assert_eq!((s.superseded, s.merged, s.lost()), (2, 1, 0));
        // the kill did not kill: nothing taken out, everything runs after it
        let mut q = ResponseQueue::new(16);
        submit_all(&mut q);
        assert_eq!(take1(&mut q, 1).unwrap().job.action, "kill");
        assert_eq!(
            order(&mut q, 1),
            [
                (7, "throttle"),
                (7, "quarantine"),
                (7, "block"),
                (8, "throttle")
            ]
        );
        assert_eq!(q.stats().superseded, 0);
    }

    /// R12c-3 (the pool): a process with a job running is skipped — the
    /// next free process's job is taken instead, whatever its lane — and
    /// its next job is taken only once the first is done; with every
    /// queued process running, nothing is taken.
    #[test]
    fn a_process_with_a_job_running_waits_for_it() {
        let mut q = ResponseQueue::new(16);
        q.submit(7, C, 0, j(7, "kill", 1));
        q.submit(7, C, 0, j(7, "quarantine", 2));
        q.submit(8, L, 0, j(8, "throttle", 3));
        let a = q.take(1).unwrap();
        assert_eq!((a.job.pid, a.job.action), (7, "kill"));
        let b = q.take(1).unwrap();
        assert_eq!((b.job.pid, b.job.action), (8, "throttle"), "7 is running");
        assert!(q.take(1).is_none(), "7 and 8 running");
        assert_eq!(q.running(), 2);
        q.done(&7);
        let c = q.take(1).unwrap();
        assert_eq!((c.job.pid, c.job.action), (7, "quarantine"));
        q.done(&8);
        q.done(&7);
        assert!(q.is_empty() && q.running() == 0);
    }

    /// Review of #476 (X2): a full queue of Critical jobs refuses no
    /// Critical kill — it goes past the capacity (counted), up to
    /// OVER_CAP_FACTOR times it; a Critical job that is not a kill, and a
    /// High kill, are refused as before.
    #[test]
    fn a_full_queue_never_refuses_a_critical_kill() {
        let mut q = ResponseQueue::new(2);
        q.submit(1, C, 0, j(1, "quarantine", 1));
        q.submit(2, C, 0, j(2, "kill", 2));
        assert!(matches!(
            q.submit(3, C, 0, j(3, "kill", 3)),
            Submitted::Queued(_)
        ));
        assert!(matches!(
            q.submit(4, C, 0, j(4, "quarantine", 4)),
            Submitted::Refused(_)
        ));
        assert!(matches!(
            q.submit(5, H, 0, j(5, "kill", 5)),
            Submitted::Refused(_)
        ));
        for pid in 6..=11 {
            q.submit(pid, C, 0, j(pid, "kill", pid));
        }
        assert_eq!(q.len(), 2 * OVER_CAP_FACTOR, "the hard bound");
        let s = q.stats();
        assert_eq!(s.over_cap, 6);
        assert_eq!(s.refused, [0, 0, 1, 2], "past the hard bound, refused");
        assert_eq!(s.max_depth, 8);
    }

    /// Every interleaving of submissions keeps each process's order (a
    /// pseudo-random sweep over processes, severities and actions).
    #[test]
    fn each_process_keeps_its_order_under_any_mix() {
        let mut seed = 0x9e37_79b9_7f4a_7c15u64;
        let mut next = || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };
        let sevs = [L, M, H, C];
        let actions = ["kill", "block", "throttle", "quarantine", "strip"];
        for round in 0..200 {
            let mut q: ResponseQueue<u32, J> = ResponseQueue::new(64);
            let mut submitted: HashMap<u32, Vec<u32>> = HashMap::new();
            let mut taken: HashMap<u32, Vec<u32>> = HashMap::new();
            let mut gone: Vec<u32> = Vec::new();
            let mut action_of: HashMap<u32, &'static str> = HashMap::new();
            let mut d = 0;
            let mut now = 0;
            for _ in 0..(20 + round % 40) {
                let r = next();
                now += r % 50_000_000;
                if r % 3 == 0 {
                    if let Some(t) = take1(&mut q, now) {
                        // a kill that killed (one in two) supersedes
                        if t.job.action == "kill" && (r >> 40) % 2 == 0 {
                            gone.extend(
                                q.supersede(&t.job.pid)
                                    .into_iter()
                                    .flat_map(|j| j.decisions),
                            );
                        }
                        taken.entry(t.job.pid).or_default().extend(&t.job.decisions);
                    }
                    continue;
                }
                d += 1;
                let pid = (r >> 8) as u32 % 5;
                let action = actions[(r >> 16) as usize % actions.len()];
                action_of.insert(d, action);
                match q.submit(pid, sevs[(r >> 24) as usize % 4], now, j(pid, action, d)) {
                    Submitted::Queued(_) | Submitted::Merged(_) => {
                        submitted.entry(pid).or_default().push(d)
                    }
                    other => panic!("room for all: {other:?}"),
                }
            }
            while let Some(t) = take1(&mut q, now) {
                taken.entry(t.job.pid).or_default().extend(&t.job.decisions);
            }
            // only throttles and blocks are superseded, each once
            assert!(gone
                .iter()
                .all(|d| matches!(action_of[d], "throttle" | "block")));
            for (pid, ds) in &submitted {
                let got = taken.get(pid).cloned().unwrap_or_default();
                // every decision taken or superseded, once
                let mut all: Vec<u32> = got
                    .iter()
                    .chain(gone.iter().filter(|d| ds.contains(d)))
                    .copied()
                    .collect();
                all.sort_unstable();
                let mut want = ds.clone();
                want.sort_unstable();
                assert_eq!(all, want, "round {round}, pid {pid}");
                // the jobs that are not kills keep the submissions' order (a
                // merged decision runs with the job it joined, the process's
                // last queued); kills go first
                let others = |v: &[u32]| -> Vec<u32> {
                    v.iter()
                        .copied()
                        .filter(|d| action_of[d] != "kill" && !gone.contains(d))
                        .collect()
                };
                assert_eq!(others(&got), others(ds), "round {round}, pid {pid}");
            }
        }
    }

    /// A repeat of the process's last queued job is merged: one action
    /// answers both decisions; a more severe repeat raises the lane.
    #[test]
    fn a_repeat_of_the_last_queued_job_is_merged() {
        let mut q = ResponseQueue::new(16);
        assert_eq!(q.submit(9, M, 0, j(9, "kill", 1)), Submitted::Queued(1));
        q.submit(10, H, 0, j(10, "kill", 2));
        assert_eq!(q.submit(9, C, 0, j(9, "kill", 3)), Submitted::Merged(1));
        assert_eq!(q.len(), 2);
        let t = take1(&mut q, 1).unwrap();
        assert_eq!(t.job.decisions, vec![1, 3]);
        assert_eq!(t.severity, C, "raised to the more severe decision's lane");
        // not into an earlier job of the process: that would reorder
        let mut q = ResponseQueue::new(16);
        q.submit(9, M, 0, j(9, "quarantine", 1));
        q.submit(9, M, 0, j(9, "strip", 2));
        assert!(matches!(
            q.submit(9, M, 0, j(9, "quarantine", 3)),
            Submitted::Queued(_)
        ));
        assert_eq!(
            order(&mut q, 1),
            [(9, "quarantine"), (9, "strip"), (9, "quarantine")]
        );
        assert_eq!(q.stats().merged, 0);
    }

    /// A full queue: a more severe job displaces the newest of the least
    /// severe lane; a job no more severe than everything queued is refused.
    /// Both come back to the caller (answered "not run", counted).
    #[test]
    fn a_full_queue_displaces_the_least_severe_or_refuses_never_silently() {
        let mut q = ResponseQueue::new(3);
        q.submit(1, L, 0, j(1, "throttle", 1));
        q.submit(2, L, 0, j(2, "throttle", 2));
        q.submit(3, H, 0, j(3, "kill", 3));
        match q.submit(4, C, 0, j(4, "kill", 4)) {
            Submitted::Displacing(_, d) => assert_eq!(d.decisions, vec![2], "the newest Low"),
            other => panic!("{other:?}"),
        }
        match q.submit(5, L, 0, j(5, "throttle", 5)) {
            Submitted::Refused(r) => assert_eq!(r.decisions, vec![5]),
            other => panic!("{other:?}"),
        }
        match q.submit(6, H, 0, j(6, "kill", 6)) {
            Submitted::Displacing(_, d) => assert_eq!(d.decisions, vec![1]),
            other => panic!("{other:?}"),
        }
        match q.submit(7, H, 0, j(7, "kill", 7)) {
            Submitted::Refused(r) => assert_eq!(r.decisions, vec![7], "High finds only High+"),
            other => panic!("{other:?}"),
        }
        let s = q.stats();
        assert_eq!(s.displaced, [2, 0, 0, 0]);
        assert_eq!(s.refused, [1, 0, 1, 0]);
        assert_eq!(s.lost(), 4);
        assert_eq!(s.submitted, 7);
        assert_eq!(s.max_depth, 3);
        assert_eq!(order(&mut q, 1), [(4, "kill"), (3, "kill"), (6, "kill")]);
        // a merge needs no room
        let mut q = ResponseQueue::new(1);
        q.submit(1, C, 0, j(1, "kill", 1));
        assert_eq!(q.submit(1, C, 0, j(1, "kill", 2)), Submitted::Merged(1));
    }

    /// Aging: a Low job that waited STARVATION_NS goes before a flood of
    /// Critical ones.
    #[test]
    fn a_job_that_waited_long_enough_goes_next() {
        let mut q = ResponseQueue::new(64);
        q.submit(1, L, 0, j(1, "throttle", 1));
        for i in 0..10 {
            q.submit(100 + i, C, 1, j(100 + i, "kill", 10 + i));
        }
        assert_eq!(take1(&mut q, STARVATION_NS - 1).unwrap().job.pid, 100);
        let t = take1(&mut q, STARVATION_NS).unwrap();
        assert_eq!((t.job.pid, t.aged), (1, true));
        assert_eq!(take1(&mut q, STARVATION_NS).unwrap().job.pid, 101);
        assert_eq!(q.stats().aged, 1);
    }

    /// Aging's share: a backlog of old Low jobs gets one take in
    /// AGED_TAKE_EVERY, a new Critical job the others — it does not wait
    /// behind the whole backlog (lab PR 270, EXP-13r).
    #[test]
    fn a_backlog_of_old_jobs_leaves_the_severe_ones_their_turns() {
        let mut q = ResponseQueue::new(64);
        for i in 0..20 {
            q.submit(i, L, 0, j(i, "throttle", 1 + i));
        }
        for i in 0..5 {
            q.submit(100 + i, C, 2 * STARVATION_NS, j(100 + i, "kill", 100 + i));
        }
        let order: Vec<u32> = std::iter::from_fn(|| take1(&mut q, 2 * STARVATION_NS))
            .take(10)
            .map(|t| t.job.pid)
            .collect();
        assert_eq!(order, [0, 100, 101, 102, 1, 103, 104, 2, 3, 4]);
        assert_eq!(q.stats().aged, 2, "the Low jobs taken past a Critical one");
    }

    /// The counts: depth per lane, the wait from queue to take, the drain.
    #[test]
    fn the_counts_follow_the_queue() {
        let mut q = ResponseQueue::new(8);
        q.submit(1, C, 1_000_000, j(1, "kill", 1));
        q.submit(2, L, 1_000_000, j(2, "throttle", 2));
        assert_eq!(q.stats().depth, [1, 0, 0, 1]);
        let t = take1(&mut q, 4_000_000).unwrap();
        assert_eq!(t.waited_ns, 3_000_000);
        let s = q.stats();
        assert_eq!(s.depth, [1, 0, 0, 0]);
        assert_eq!((s.taken, s.wait.count(), s.wait.max_us()), (1, 1, 3_000));
        let left = q.drain();
        assert_eq!(left.len(), 1);
        assert_eq!(left[0].1, L);
        assert!(q.is_empty());
        assert_eq!(q.stats().depth, [0; LANES]);
    }
}
