//! The event bus (Wave 4 restructure; R08c, lab PR 252, laid down its
//! types; R12a, lab PR 267, gives them behaviour — plan §2.3, §3.4).
//!
//! Until R12a every source — a pump per eBPF ring, the FIM and network
//! drains — wrote into one queue that one consumer read: a flood of one
//! class held every other class back, and while the queue was full the
//! kernel dropped the next records of every ring (plan §1.5: a `file_open`
//! flood made the `fs_protect` denials lost). R12a gives each class of
//! events ([`nn_model::EventClass`]) a queue of its own, drained by strict
//! priority with aging, FIFO inside a class, with a loss counter per class.
//! This module is the bus's portable half: which class an event is
//! ([`class_of`], an exhaustive match: a new variant does not compile until
//! it is placed), each class's priority and queue ([`Priority`],
//! [`QueueSpec`], [`SPECS`]), what a full queue does with a new event
//! ([`when_full`]), the queues and their take order ([`ClassQueues`]), and
//! the latency they report ([`LatencyHistogram`]). The runtime — the
//! senders the pumps hold, the waits, the receiver the event loop reads,
//! the signed record of a dropped tamper event — is nn-linux's
//! (`nn_linux::sensors::bus`): it needs tokio and the audit log.
//!
//! What R12a does not change: the decision. The consumer is still the one
//! event loop, every event still goes through `process_event` the way it
//! did; only the order between classes can differ (a property test checks
//! that every interleaving consistent with per-class FIFO gives the same
//! verdicts on the golden corpus: `agent/src/decision/golden.rs`). The
//! decision thread without `await` is R12b; the response dispatcher, the
//! signed `telemetry_loss` rows and the loss counters of stages 5 to 8 are
//! R12b and R12c ([`LossStage`]).

use std::collections::VecDeque;

use nn_model::{CanaryAccessKind, Event, EventClass, ProcessKey};

/// A priority of the bus; [`Priority::P0`] is drained first. Plan §3.4:
/// tamper (with the sensors' health) at P0, a process's life at P1, files at
/// P2, the network at P3 — strict, with aging (every [`AGING_EVERY`] draws
/// from the higher classes, one from the class whose head is oldest).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Priority {
    P0,
    P1,
    P2,
    P3,
}

/// The number of the bus's queues, one per [`Priority`].
pub const QUEUES: usize = 4;

impl Priority {
    /// Every priority, the highest first.
    pub const ALL: [Priority; QUEUES] = [Priority::P0, Priority::P1, Priority::P2, Priority::P3];

    /// The queue of a class: tamper and the sensors' health at P0, a
    /// process's life at P1, files at P2, the network at P3 (plan §3.4).
    pub const fn of(class: EventClass) -> Self {
        match class {
            EventClass::Tamper | EventClass::Health => Priority::P0,
            EventClass::Process => Priority::P1,
            EventClass::File => Priority::P2,
            EventClass::Network => Priority::P3,
        }
    }

    /// The queue of an event ([`class_of`]).
    pub fn of_event(event: &Event) -> Self {
        Self::of(class_of(event))
    }

    /// Its place in [`Self::ALL`] (0 for P0).
    pub const fn index(self) -> usize {
        self as usize
    }

    /// `P0` … `P3`.
    pub const fn label(self) -> &'static str {
        match self {
            Priority::P0 => "P0",
            Priority::P1 => "P1",
            Priority::P2 => "P2",
            Priority::P3 => "P3",
        }
    }

    /// The classes it queues, as `nn-admin status` names them.
    pub const fn name(self) -> &'static str {
        match self {
            Priority::P0 => "tamper",
            Priority::P1 => "process",
            Priority::P2 => "file",
            Priority::P3 => "network",
        }
    }

    /// Its queue ([`SPECS`]).
    pub const fn spec(self) -> QueueSpec {
        SPECS[self.index()]
    }
}

/// The class of an event: the queue it waits in (plan §3.4; R12a, lab PR
/// 267). Every variant is named — no wildcard — so a new one does not
/// compile until it is placed here.
///
/// The plan's table, and the variants added since it was written:
/// - [`EventClass::Tamper`]: `FsProtectDenial`, `BpfSyscall`, `ModuleLoad`,
///   `SensorFlood` (the plan's), and `DefenderSignal` (lab PR 225: a stop
///   signal to another security tool of the host), `ExploitPostcondition`
///   (lab PR 219: privilege gained with no mechanism for it) — attempts on
///   the agent or the host's defences, rare by nature and bounded in the
///   kernel (budgets, dedup).
/// - `CanaryTripped` never travels the bus: the canary detector makes it
///   inside the consumer from the source event it replaces (a FIM record,
///   an exec, a connect); it is that event's class — File, Process or
///   Network by its `access_kind`.
/// - [`EventClass::Process`]: `ProcessSpawn`, `ExecCheck`, `IoUring`.
/// - [`EventClass::File`]: `Fim`, `MassWrite`, `FileOpen`, and `FileBurst`
///   (lab PR 225: a rename or unlink burst, the ransomware signal's).
/// - [`EventClass::Network`]: `TcpConnect`, `DnsQuery`, `DnsFlood`,
///   `NetFlow`, `NetListener`.
/// - [`EventClass::Health`]: no event yet (the sensors' liveness is checked
///   by the event loop, not carried on the bus); its queue is P0's.
pub fn class_of(event: &Event) -> EventClass {
    match event {
        Event::FsProtectDenial { .. }
        | Event::BpfSyscall { .. }
        | Event::ModuleLoad { .. }
        | Event::SensorFlood { .. }
        | Event::DefenderSignal { .. }
        | Event::ExploitPostcondition { .. } => EventClass::Tamper,
        // Made by the canary detector inside the consumer from the source
        // event it replaces: the class of that event.
        Event::CanaryTripped { access_kind, .. } => match access_kind {
            CanaryAccessKind::FileOpen => EventClass::File,
            CanaryAccessKind::ProcessExec => EventClass::Process,
            CanaryAccessKind::NetworkConnect => EventClass::Network,
        },
        Event::ProcessSpawn { .. } | Event::ExecCheck { .. } | Event::IoUring { .. } => {
            EventClass::Process
        }
        Event::Fim(_)
        | Event::MassWrite { .. }
        | Event::FileOpen { .. }
        | Event::FileBurst { .. } => EventClass::File,
        Event::TcpConnect { .. }
        | Event::DnsQuery { .. }
        | Event::DnsFlood { .. }
        | Event::NetFlow(_)
        | Event::NetListener(_) => EventClass::Network,
    }
}

/// What a full queue does with a new event (plan §3.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WhenFull {
    /// The source waits for room at most `max_ns` — its kernel ring absorbs
    /// meanwhile — then the event is dropped and counted.
    Wait { max_ns: u64 },
    /// The source waits for room as long as it takes, as every source did
    /// before R12 (its kernel ring absorbs, and counts what it drops).
    Backpressure,
    /// The new event is dropped and counted; the source reads on.
    DropNew,
}

impl WhenFull {
    /// As `nn-admin status` shows it.
    pub fn describe(self) -> String {
        match self {
            WhenFull::Wait { max_ns } => format!("wait {} ms, then drop", max_ns / 1_000_000),
            WhenFull::Backpressure => "wait".to_string(),
            WhenFull::DropNew => "drop the new event".to_string(),
        }
    }
}

/// A queue of the bus: how many events it holds, and what it does when
/// they are there.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QueueSpec {
    pub capacity: usize,
    pub when_full: WhenFull,
}

/// P0's wait for room: the kernel ring absorbs 50 ms of a tamper burst
/// (plan §3.4).
pub const P0_WAIT_NS: u64 = 50_000_000;
/// P1's "short wait" (plan §3.4): 10 ms.
pub const P1_WAIT_NS: u64 = 10_000_000;

/// The queues, by priority (plan §3.4).
pub const SPECS: [QueueSpec; QUEUES] = [
    QueueSpec {
        capacity: 1024,
        when_full: WhenFull::Wait { max_ns: P0_WAIT_NS },
    },
    QueueSpec {
        capacity: 4096,
        when_full: WhenFull::Wait { max_ns: P1_WAIT_NS },
    },
    QueueSpec {
        capacity: 8192,
        when_full: WhenFull::DropNew,
    },
    QueueSpec {
        capacity: 8192,
        when_full: WhenFull::DropNew,
    },
];

/// What a full queue does with `event`: its queue's
/// [`QueueSpec::when_full`], except for the file events other than
/// `FileOpen`. Review 75 made the FIM drain wait for room (it dropped its
/// events on a full queue, and an unprivileged loop of reads was enough to
/// keep the FIM kill rules from seeing a persistence write); on P2 the
/// flood is `FileOpen`, so the opens are what a full P2 drops, and a drift,
/// a credential read, a mass write or a rename burst waits for room — ahead
/// of the next opens (the runtime's wait is fair), as it waited before.
pub fn when_full(event: &Event) -> WhenFull {
    let p = Priority::of_event(event);
    if p == Priority::P2 && !matches!(event, Event::FileOpen { .. }) {
        return WhenFull::Backpressure;
    }
    p.spec().when_full
}

/// Takes from the higher classes before one is taken by age: after this
/// many takes in a row that passed over a waiting lower class, the next
/// take is from the class whose head waited longest (plan §3.4).
pub const AGING_EVERY: u32 = 64;

/// One event taken from the bus, with where and how long it waited.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Taken<T> {
    pub priority: Priority,
    pub item: T,
    /// When it was queued (the caller's clock, ns).
    pub enqueued_ns: u64,
    /// How long it waited in its queue.
    pub waited_ns: u64,
    /// Taken by aging, ahead of a higher class.
    pub aged: bool,
}

/// One queue's counts since the bus started.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct QueueStats {
    /// Events queued.
    pub enqueued: u64,
    /// Events dropped because the queue was full (after the wait its
    /// [`WhenFull`] allows).
    pub dropped: u64,
    /// Events in the queue now.
    pub depth: u64,
    /// The most it held.
    pub max_depth: u64,
    /// The longest an event waited in it before its take.
    pub max_wait_ns: u64,
    /// Events taken by aging ahead of a higher class.
    pub aged: u64,
}

/// The bus's queues, one per [`Priority`], and their take order: strict
/// priority with aging, FIFO inside a queue. Bounded: a push to a full
/// queue gives the event back (the runtime then waits or drops it, as its
/// [`WhenFull`] says, and counts the drop with [`Self::note_dropped`]).
/// Pure: the caller passes the time.
#[derive(Debug)]
pub struct ClassQueues<T> {
    queues: [VecDeque<(u64, T)>; QUEUES],
    capacity: [usize; QUEUES],
    /// Takes in a row that passed over a waiting lower class.
    streak: u32,
    stats: [QueueStats; QUEUES],
    /// Per queue, how many of its front events [`Self::hand_over_older`]
    /// has handed over (each once).
    handed: [usize; QUEUES],
}

/// A queue's memory is given back once it runs empty above this capacity:
/// a burst does not keep its peak allocated.
const SHRINK_ABOVE: usize = 1024;

impl<T> ClassQueues<T> {
    /// Queues of the given capacities (each at least 1).
    pub fn new(capacity: [usize; QUEUES]) -> Self {
        Self {
            queues: Default::default(),
            capacity: capacity.map(|c| c.max(1)),
            streak: 0,
            stats: [QueueStats::default(); QUEUES],
            handed: [0; QUEUES],
        }
    }

    /// The queues of [`SPECS`].
    pub fn with_specs() -> Self {
        Self::new(SPECS.map(|s| s.capacity))
    }

    /// Queue `item` at `p` at `now_ns`; `Err(item)` when the queue is full.
    pub fn push(&mut self, p: Priority, now_ns: u64, item: T) -> Result<(), T> {
        let i = p.index();
        if self.queues[i].len() >= self.capacity[i] {
            return Err(item);
        }
        self.queues[i].push_back((now_ns, item));
        let st = &mut self.stats[i];
        st.enqueued += 1;
        st.depth = self.queues[i].len() as u64;
        st.max_depth = st.max_depth.max(st.depth);
        Ok(())
    }

    /// Count an event of `p` dropped (its queue was full).
    pub fn note_dropped(&mut self, p: Priority) {
        self.stats[p.index()].dropped += 1;
    }

    /// The next event: from the highest queue that holds one, except that
    /// after [`AGING_EVERY`] such takes in a row that passed over a waiting
    /// lower queue, from the queue whose head was queued first (the higher
    /// on a tie). FIFO inside a queue.
    pub fn take(&mut self, now_ns: u64) -> Option<Taken<T>> {
        let top = (0..QUEUES).find(|&i| !self.queues[i].is_empty())?;
        let lower_waiting = (top + 1..QUEUES).any(|i| !self.queues[i].is_empty());
        let mut pick = top;
        if !lower_waiting {
            self.streak = 0;
        } else if self.streak >= AGING_EVERY {
            self.streak = 0;
            // the oldest head; `min_by_key` keeps the first (higher) on a tie
            pick = (0..QUEUES)
                .filter(|&i| !self.queues[i].is_empty())
                .min_by_key(|&i| self.queues[i].front().map_or(u64::MAX, |(t, _)| *t))
                .unwrap_or(top);
        } else {
            self.streak += 1;
        }
        let (enqueued_ns, item) = self.queues[pick].pop_front()?;
        self.handed[pick] = self.handed[pick].saturating_sub(1);
        if self.queues[pick].is_empty() && self.queues[pick].capacity() > SHRINK_ABOVE {
            self.queues[pick].shrink_to(SHRINK_ABOVE);
        }
        let waited_ns = now_ns.saturating_sub(enqueued_ns);
        let aged = pick != top;
        let st = &mut self.stats[pick];
        st.depth = self.queues[pick].len() as u64;
        st.max_wait_ns = st.max_wait_ns.max(waited_ns);
        if aged {
            st.aged += 1;
        }
        Some(Taken {
            priority: Priority::ALL[pick],
            item,
            enqueued_ns,
            waited_ns,
            aged,
        })
    }

    /// Hand `f` every event of `p` queued before `before_ns` that no earlier
    /// call handed over, front first, each once — the events of `p` an event
    /// taken from a higher queue overtakes (lab PR 267: the execs the
    /// lineage learns before the tamper event that overtakes them is
    /// judged). Amortised O(1) per event. The queue's times are its push
    /// order's (the caller takes the time under the same lock as the push).
    pub fn hand_over_older(&mut self, p: Priority, before_ns: u64, mut f: impl FnMut(&T)) {
        let i = p.index();
        while let Some((t, item)) = self.queues[i].get(self.handed[i]) {
            if *t >= before_ns {
                break;
            }
            f(item);
            self.handed[i] += 1;
        }
    }

    /// Events queued at `p` now.
    pub fn len(&self, p: Priority) -> usize {
        self.queues[p.index()].len()
    }

    /// No event in any queue.
    pub fn is_empty(&self) -> bool {
        self.queues.iter().all(VecDeque::is_empty)
    }

    /// The capacity of `p`'s queue.
    pub fn capacity(&self, p: Priority) -> usize {
        self.capacity[p.index()]
    }

    /// `p`'s counts.
    pub fn stats(&self, p: Priority) -> QueueStats {
        self.stats[p.index()]
    }
}

/// Sub-buckets per power of two of [`LatencyHistogram`]: a value is placed
/// within 1/8 of its octave (12.5 %).
const SUB_BITS: u32 = 3;
const SUB: usize = 1 << SUB_BITS;
/// Octaves of microseconds kept (2^26 µs ≈ 67 s; longer is the last bucket).
const OCTAVES: usize = 27;

/// Latencies in microseconds, by bucket (8 per power of two), for the
/// percentiles `nn-admin status` shows per class (lab PR 267: the
/// overhead lab's p50/p99 decision latency).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LatencyHistogram {
    buckets: Vec<u64>,
    count: u64,
    max_us: u64,
}

impl Default for LatencyHistogram {
    fn default() -> Self {
        Self {
            buckets: vec![0; OCTAVES * SUB],
            count: 0,
            max_us: 0,
        }
    }
}

impl LatencyHistogram {
    fn bucket(us: u64) -> usize {
        if us < SUB as u64 {
            return us as usize;
        }
        let octave = 63 - us.leading_zeros(); // ≥ SUB_BITS
        let sub = ((us >> (octave - SUB_BITS)) as usize) & (SUB - 1);
        (((octave - SUB_BITS + 1) as usize) * SUB + sub).min(OCTAVES * SUB - 1)
    }

    /// The largest value of a bucket.
    fn upper(b: usize) -> u64 {
        if b < SUB {
            return b as u64;
        }
        let octave = (b / SUB) as u32 + SUB_BITS - 1;
        let sub = (b % SUB) as u64;
        ((SUB as u64 + sub + 1) << (octave - SUB_BITS)) - 1
    }

    /// Count one latency.
    pub fn record_ns(&mut self, ns: u64) {
        let us = ns / 1_000;
        self.buckets[Self::bucket(us)] += 1;
        self.count += 1;
        self.max_us = self.max_us.max(us);
    }

    /// Latencies counted.
    pub fn count(&self) -> u64 {
        self.count
    }

    /// The `q` quantile (0.0–1.0) in microseconds: the upper end of the
    /// bucket that holds it (at most 12.5 % above the value), never above
    /// the largest seen. `None` before the first latency.
    pub fn quantile_us(&self, q: f64) -> Option<u64> {
        if self.count == 0 {
            return None;
        }
        let rank = ((q.clamp(0.0, 1.0) * self.count as f64).ceil() as u64).max(1);
        let mut seen = 0;
        for (b, n) in self.buckets.iter().enumerate() {
            seen += n;
            if seen >= rank {
                return Some(Self::upper(b).min(self.max_us));
            }
        }
        Some(self.max_us)
    }

    /// The largest latency counted, in microseconds.
    pub fn max_us(&self) -> u64 {
        self.max_us
    }
}

/// A source of events — an adapter's sensor, a drain — by its place in the
/// boot's sources, which the sensor contract names
/// ([`crate::contract::ClassContract::source`], R13).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SourceId(pub u16);

/// An event on the bus, with what orders it: in its class, the order its
/// source read it in (FIFO); between classes, its time and its process
/// (plan §3.4). R12a's queues hold the event itself (the runtime adds the
/// time it was queued); this envelope is for the decision thread of R12b,
/// which orders the classes by `ts_ns` and `key`.
#[derive(Debug, Clone)]
pub struct Envelope {
    /// The source that read it.
    pub source: SourceId,
    /// Its place in its source's reads.
    pub seq: u64,
    /// Its class: the queue it waits in.
    pub class: EventClass,
    /// The kernel's time of the event (`CLOCK_MONOTONIC` ns).
    pub ts_ns: u64,
    /// The process it is about.
    pub key: ProcessKey,
    /// The event.
    pub event: Event,
}

/// Where on its path an event can be lost (plan §3.4), in the order it
/// meets them. R12a counts 1 to 4 (`nn-admin status`); 5 is R12b's (the
/// decision thread's budget per class), 6 to 8 R12c's and later lots'.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LossStage {
    /// 1. The kernel's ring was full (`RING_DROPS`).
    KernelRing,
    /// 2. The kernel's budget dropped a flood.
    KernelBudget,
    /// 3. The decoder refused a record (`RejectThrottle`).
    Decode,
    /// 4. The bus's queue of a class was full.
    BusQueue(EventClass),
    /// 5. The decision came later than its class allows.
    DecisionDelay(EventClass),
    /// 6. The response queue was full.
    ResponseQueue,
    /// 7. The evidence writer's queue was full.
    EvidenceQueue,
    /// 8. The export: a record late, or missing.
    Export,
}

impl LossStage {
    /// Its number in the plan's list (§3.4).
    pub const fn number(self) -> u8 {
        match self {
            LossStage::KernelRing => 1,
            LossStage::KernelBudget => 2,
            LossStage::Decode => 3,
            LossStage::BusQueue(_) => 4,
            LossStage::DecisionDelay(_) => 5,
            LossStage::ResponseQueue => 6,
            LossStage::EvidenceQueue => 7,
            LossStage::Export => 8,
        }
    }
}

/// The events lost at each stage (plan §3.4) since the agent started: what
/// `nn-admin status`, the signed `telemetry_loss` rows and the heartbeat
/// report (R12; INI-14).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LossCounters {
    /// [`LossStage::KernelRing`].
    pub kernel_ring: u64,
    /// [`LossStage::KernelBudget`].
    pub kernel_budget: u64,
    /// [`LossStage::Decode`].
    pub decode: u64,
    /// [`LossStage::BusQueue`], per class.
    pub bus_queue: PerClass,
    /// [`LossStage::DecisionDelay`], per class.
    pub decision_delay: PerClass,
    /// [`LossStage::ResponseQueue`].
    pub response_queue: u64,
    /// [`LossStage::EvidenceQueue`].
    pub evidence_queue: u64,
    /// [`LossStage::Export`].
    pub export: u64,
}

/// A count for each class of events.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PerClass {
    pub tamper: u64,
    pub process: u64,
    pub file: u64,
    pub network: u64,
    pub health: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(i: usize) -> Priority {
        Priority::ALL[i]
    }

    /// Every class has its queue; tamper and health share P0.
    #[test]
    fn each_class_has_the_plan_s_queue() {
        assert_eq!(Priority::of(EventClass::Tamper), Priority::P0);
        assert_eq!(Priority::of(EventClass::Health), Priority::P0);
        assert_eq!(Priority::of(EventClass::Process), Priority::P1);
        assert_eq!(Priority::of(EventClass::File), Priority::P2);
        assert_eq!(Priority::of(EventClass::Network), Priority::P3);
        let caps: Vec<usize> = SPECS.iter().map(|s| s.capacity).collect();
        assert_eq!(caps, [1024, 4096, 8192, 8192]);
        assert_eq!(SPECS[0].when_full, WhenFull::Wait { max_ns: 50_000_000 });
        assert!(matches!(SPECS[1].when_full, WhenFull::Wait { max_ns } if max_ns < P0_WAIT_NS));
        assert_eq!(SPECS[2].when_full, WhenFull::DropNew);
        assert_eq!(SPECS[3].when_full, WhenFull::DropNew);
        for (i, pr) in Priority::ALL.iter().enumerate() {
            assert_eq!(pr.index(), i);
        }
    }

    /// FIFO inside a queue, strict priority between them.
    #[test]
    fn takes_are_fifo_in_a_queue_and_by_priority_between() {
        let mut q = ClassQueues::new([8; QUEUES]);
        q.push(p(3), 1, "n1").unwrap();
        q.push(p(2), 2, "f1").unwrap();
        q.push(p(2), 3, "f2").unwrap();
        q.push(p(0), 4, "t1").unwrap();
        q.push(p(1), 5, "p1").unwrap();
        let order: Vec<&str> = std::iter::from_fn(|| q.take(10).map(|t| t.item)).collect();
        assert_eq!(order, ["t1", "p1", "f1", "f2", "n1"]);
        assert!(q.is_empty());
        assert!(q.take(11).is_none());
    }

    /// After 64 takes that passed over a waiting lower queue, one take by
    /// age: a lower class is never starved by a flood of a higher one.
    #[test]
    fn aging_takes_the_oldest_head_once_every_64() {
        let mut q = ClassQueues::new([1000; QUEUES]);
        q.push(p(3), 0, 9999u32).unwrap();
        for i in 0..200u32 {
            q.push(p(2), 1 + u64::from(i), i).unwrap();
        }
        let mut taken = Vec::new();
        while let Some(t) = q.take(1_000) {
            taken.push((t.priority, t.item, t.aged));
        }
        let net_at = taken
            .iter()
            .position(|(pr, _, _)| *pr == Priority::P3)
            .unwrap();
        assert_eq!(
            net_at, AGING_EVERY as usize,
            "the 65th take is the aged one"
        );
        assert!(taken[net_at].2, "marked aged");
        // FIFO of the file queue is kept around it
        let files: Vec<u32> = taken
            .iter()
            .filter(|(pr, _, _)| *pr == Priority::P2)
            .map(|(_, i, _)| *i)
            .collect();
        assert_eq!(files, (0..200).collect::<Vec<_>>());
        assert_eq!(q.stats(p(3)).aged, 1);
        assert_eq!(q.stats(p(2)).aged, 0);
    }

    /// An aging take picks the oldest head, which can be a higher class:
    /// then nothing is taken out of order, and nothing counts as aged.
    #[test]
    fn aging_picks_the_oldest_head_even_a_higher_one() {
        let mut q = ClassQueues::new([1000; QUEUES]);
        for i in 0..100u64 {
            q.push(p(0), i, ("t", i)).unwrap();
        }
        q.push(p(1), 1_000, ("p", 0)).unwrap();
        let mut aged = 0;
        let mut first_p = None;
        let mut n = 0;
        while let Some(t) = q.take(2_000) {
            aged += u32::from(t.aged);
            if t.item.0 == "p" && first_p.is_none() {
                first_p = Some(n);
            }
            n += 1;
        }
        assert_eq!(aged, 0, "the P0 heads were older than the P1 one");
        assert_eq!(first_p, Some(100), "P1 after every older P0");
    }

    /// No lower queue waiting: no streak builds (a lone flood takes no
    /// aging turn that would later jump an event that just arrived).
    #[test]
    fn the_streak_counts_only_takes_that_passed_over_a_waiting_queue() {
        let mut q = ClassQueues::new([1000; QUEUES]);
        for i in 0..300u64 {
            q.push(p(0), i, i).unwrap();
        }
        for _ in 0..200 {
            q.take(400).unwrap();
        }
        q.push(p(3), 500, 7).unwrap();
        let mut before = 0;
        while let Some(t) = q.take(600) {
            if t.priority == Priority::P3 {
                break;
            }
            before += 1;
        }
        assert_eq!(before, 100, "the P0 queue ran empty first (all older)");
    }

    /// A full queue gives the event back; the counts follow the queue.
    #[test]
    fn a_full_queue_refuses_and_counts() {
        let mut q = ClassQueues::new([2, 1, 1, 1]);
        q.push(p(0), 1, 1).unwrap();
        q.push(p(0), 2, 2).unwrap();
        assert_eq!(q.push(p(0), 3, 3), Err(3));
        q.note_dropped(p(0));
        let st = q.stats(p(0));
        assert_eq!(
            (st.enqueued, st.dropped, st.depth, st.max_depth),
            (2, 1, 2, 2)
        );
        let t = q.take(10).unwrap();
        assert_eq!((t.item, t.waited_ns, t.enqueued_ns), (1, 9, 1));
        let st = q.stats(p(0));
        assert_eq!((st.depth, st.max_depth, st.max_wait_ns), (1, 2, 9));
        q.push(p(0), 11, 4).unwrap();
        assert_eq!(q.len(p(0)), 2);
        assert_eq!(q.capacity(p(0)), 2);
    }

    /// The events of a lower queue an event taken ahead of them overtakes
    /// are handed over once each, front first, and only those queued before
    /// it.
    #[test]
    fn overtaken_events_are_handed_over_once() {
        let mut q = ClassQueues::new([16; QUEUES]);
        q.push(p(1), 1, "e1").unwrap();
        q.push(p(1), 2, "e2").unwrap();
        q.push(p(0), 3, "t1").unwrap();
        q.push(p(1), 4, "e3").unwrap();
        q.push(p(0), 5, "t2").unwrap();
        let t1 = q.take(10).unwrap();
        assert_eq!(t1.item, "t1");
        let mut got = Vec::new();
        q.hand_over_older(p(1), t1.enqueued_ns, |e| got.push(*e));
        assert_eq!(got, ["e1", "e2"]);
        let t2 = q.take(10).unwrap();
        got.clear();
        q.hand_over_older(p(1), t2.enqueued_ns, |e| got.push(*e));
        assert_eq!(got, ["e3"], "e1 and e2 were handed already");
        // the handed ones are taken in their order; nothing again
        assert_eq!(q.take(10).unwrap().item, "e1");
        got.clear();
        q.hand_over_older(p(1), u64::MAX, |e| got.push(*e));
        assert!(got.is_empty(), "{got:?}");
        q.push(p(1), 11, "e4").unwrap();
        q.hand_over_older(p(1), u64::MAX, |e| got.push(*e));
        assert_eq!(got, ["e4"]);
        let rest: Vec<&str> = std::iter::from_fn(|| q.take(20).map(|t| t.item)).collect();
        assert_eq!(rest, ["e2", "e3", "e4"]);
    }

    /// The opens are what a full P2 drops; every other file event waits
    /// for room (review 75); the other classes follow their queue.
    #[test]
    fn a_full_file_queue_drops_only_the_opens() {
        let open = Event::FileOpen {
            pid: 1,
            uid: 0,
            gid: 0,
            comm: String::new(),
            filename: String::new(),
            flags: 0,
            timestamp_ns: 0,
            path_from_user: false,
            kernel_class: 0,
        };
        assert_eq!(when_full(&open), WhenFull::DropNew);
        let mass = Event::MassWrite {
            pid: 1,
            uid: 0,
            comm: String::new(),
            count: 1,
            filename: String::new(),
            timestamp_ns: 0,
            overwrites: false,
            cgroup_window: false,
        };
        assert_eq!(when_full(&mass), WhenFull::Backpressure);
        let denial = Event::FsProtectDenial {
            pid: 1,
            uid: 0,
            comm: String::new(),
            target_dev: 0,
            target_ino: 0,
            operation: nn_model::FsProtectOperation::Unlink,
            timestamp_ns: 0,
        };
        assert_eq!(class_of(&denial), EventClass::Tamper);
        assert_eq!(when_full(&denial), WhenFull::Wait { max_ns: P0_WAIT_NS });
        let listener = Event::NetListener(nn_model::telemetry::NetListenerEvent {
            timestamp_ns: 0,
            family: 2,
            bind_addr: std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
            bind_port: 22,
            proto: 6,
            pid: 1,
            uid: 0,
            comm: String::new(),
            exe: None,
        });
        assert_eq!(when_full(&listener), WhenFull::DropNew);
    }

    /// The histogram's quantiles stay within a bucket (12.5 %) of the value
    /// and never above the largest seen.
    #[test]
    fn latency_quantiles_are_within_a_bucket() {
        let mut h = LatencyHistogram::default();
        assert_eq!(h.quantile_us(0.5), None);
        for us in 1..=1000u64 {
            h.record_ns(us * 1_000);
        }
        assert_eq!(h.count(), 1000);
        let p50 = h.quantile_us(0.5).unwrap();
        let p99 = h.quantile_us(0.99).unwrap();
        assert!((500..=563).contains(&p50), "{p50}");
        assert!((990..=1000).contains(&p99), "{p99}");
        assert_eq!(h.quantile_us(1.0), Some(1000));
        assert_eq!(h.max_us(), 1000);
        for us in [0u64, 1, 7, 8, 9, 15, 16, 1_000_000, u64::MAX / 1_000] {
            let b = LatencyHistogram::bucket(us);
            assert!(
                LatencyHistogram::upper(b) >= us.min(LatencyHistogram::upper(OCTAVES * SUB - 1))
            );
            if b > 0 && b < OCTAVES * SUB - 1 {
                assert!(LatencyHistogram::upper(b - 1) < us, "{us} in bucket {b}");
            }
        }
    }
}
