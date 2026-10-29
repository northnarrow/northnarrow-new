//! The event bus (Wave 4 restructure; R08c, lab PR 252, laid down its
//! types; R12a, lab PR 267, gives them behaviour — plan §2.3, §3.4).
//!
//! Until R12a every source — a pump per eBPF ring, the FIM and network
//! drains — wrote into one queue that one consumer read: a flood of one
//! class held every other class back, and while the queue was full the
//! kernel dropped the next records of every ring (plan §1.5: a `file_open`
//! flood made the `fs_protect` denials lost). R12a gives each class of
//! events ([`nn_model::EventClass`]) a queue of its own, drained by weighted
//! shares (tamper far ahead, never alone), FIFO inside a class, with a loss
//! counter per class.
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
/// P2, the network at P3. Every queue is taken by its weight
/// ([`SHARE_WEIGHTS`]): P0 far ahead, never alone (review #471 A2: the
/// plan's aging gave a lower class one take in 65 under a higher class's
/// flood; R-A of its second review: a strict P0 gave them none while a
/// flood kept P0 full).
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
/// [`QueueSpec::when_full`], except two kinds of event that wait for room
/// as every source waited before R12a, their kernel ring absorbing:
/// - the file events other than `FileOpen`. Review 75 made the FIM drain
///   wait for room (it dropped its events on a full queue, and an
///   unprivileged loop of reads was enough to keep the FIM kill rules from
///   seeing a persistence write); on P2 the flood is `FileOpen`, so the
///   opens are what a full P2 drops, and a drift, a credential read, a mass
///   write or a rename burst waits — ahead of the next opens (the runtime's
///   wait is fair);
/// - the tamper events other than `FsProtectDenial` (review #471 M1): a
///   module load, a `bpf()` call, an exploit post-condition, a security
///   tool signalled, a sensor flood — rare, each from a ring of its own or
///   carried by another record. Root can fill P0 with refused operations
///   (inode denials have no kernel budget); while the loop stands still
///   those wait 50 ms and are dropped, and the rare one queues behind them
///   instead of being dropped with them.
///
/// And (second review of #471, R-E) a `FileOpen` that writes a file the
/// kernel classes CRITICAL or PERSIST ([`guarded_write_open`]): rare (only
/// who may write the file opens it so), and what a flood of reads must not
/// hide — it waits for room like the FIM records, outside the opens' cap.
pub fn when_full(event: &Event) -> WhenFull {
    match Priority::of_event(event) {
        Priority::P0 if !matches!(event, Event::FsProtectDenial { .. }) => WhenFull::Backpressure,
        Priority::P2 if !matches!(event, Event::FileOpen { .. }) || guarded_write_open(event) => {
            WhenFull::Backpressure
        }
        p => p.spec().when_full,
    }
}

/// Second review of #471, R-E: a `FileOpen` for writing (`O_WRONLY` or
/// `O_RDWR`) of a file the kernel's open sensor classes CRITICAL or PERSIST
/// (its `kernel_class`: a system binary, a unit, a cron or profile file) —
/// a write-open that waits for room and is not counted in the opens' cap.
pub fn guarded_write_open(event: &Event) -> bool {
    use common::wire::open_sensor::open_reason;
    match event {
        Event::FileOpen {
            flags,
            kernel_class,
            ..
        } => {
            matches!(flags & 0b11, 1 | 2)
                && kernel_class & (open_reason::CRITICAL | open_reason::PERSIST) != 0
        }
        _ => false,
    }
}

/// Second review of #471, R-A/R-D: the tamper events a process can repeat
/// at will — a refused operation on a protected inode (root; no kernel
/// budget) and a `bpf()` call (on 6.x the LSM hook runs before the
/// permission checks: any user, one record per new process and command a
/// second). They share P0 but for [`P0_RESERVE`] slots, so the rare ones
/// (a module load, an exploit post-condition, a signal to a security tool,
/// a sensor flood — the last two carried by pumps of other classes) never
/// wait behind them.
pub fn floods_p0(event: &Event) -> bool {
    matches!(
        event,
        Event::FsProtectDenial { .. } | Event::BpfSyscall { .. }
    )
}

/// The P0 slots only the rare tamper events take ([`floods_p0`]).
pub const P0_RESERVE: usize = 64;

/// Review #471 B3: the most `FileOpen`s the file queue holds (a quarter
/// of it). Past it a new open is dropped as on a full queue; the rest of
/// the queue is the other file events' — a FIM record, a mass write, a
/// rename burst — so a flood of opens holds them at most this many events
/// behind it (≈ 0.3–1.2 s at EXP-13's rates, where the whole queue held
/// them four times longer) and never makes the FIM drain wait for room.
pub const FILE_OPEN_SHARE: usize = 2048;

/// What each queue gets of the takes while every queue holds events:
/// 8 : 2 : 1 : 1 (a smooth weighted round robin, work-conserving: a queue
/// with nothing queued gives its turns to the others and banks none).
///
/// - P0 two thirds when every queue is busy, more when fewer are (8/9
///   against one other): a tamper burst is still taken first — its first
///   event within a take or two — and drained at ≥ 2/3 of the consumer,
///   ~4,700 a second at EXP-13's ~7,000 decisions a second. Second review
///   of #471, R-A: a strict P0 gave the other classes nothing while a flood
///   kept it full — a root loop of refused `chmod`s, or any user's
///   `fork` + `bpf()` loop (the rare P0 sources wait for room since M1, so
///   their pumps refill P0 at each freed slot). Now P1 keeps 1/6 and P2, P3
///   1/12 each in the worst case (all four flooded: ~1,170 execs and ~580
///   file and network events a second); against a P0 flood alone, P3 keeps
///   1/9 (~780 a second).
/// - Among P1–P3 the review #471 A2 shares stand: 2 : 1 : 1, a quarter each
///   to P2 and P3 under a flood of the other lower classes (≥ 1,750 network
///   events a second against a file flood, ≥ 3,500 with no exec load, where
///   the plan's aging gave one take in 65, ~110 a second). P1 has the
///   larger share: an exec is the lineage every later event of its process
///   is judged on, and the exec quarantine holds a process until its exec
///   is judged.
pub const SHARE_WEIGHTS: [i64; QUEUES] = [8, 2, 1, 1];

/// One event taken from the bus, with where and how long it waited.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Taken<T> {
    pub priority: Priority,
    pub item: T,
    /// When it was queued (the caller's clock, ns).
    pub enqueued_ns: u64,
    /// How long it waited in its queue.
    pub waited_ns: u64,
    /// Taken by its share ahead of a higher class that held events.
    pub ahead: bool,
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
    /// The longest since [`ClassQueues::take_window_max_wait`] was last
    /// called (review #471 B2: the all-time maximum is the boot's backlog).
    pub window_max_wait_ns: u64,
    /// Events taken by their share ahead of a higher class.
    pub ahead: u64,
}

/// The bus's queues, one per [`Priority`], and their take order: by
/// weighted shares ([`SHARE_WEIGHTS`]), P0 far ahead, FIFO inside a queue. Bounded: a push to a full
/// queue gives the event back (the runtime then waits or drops it, as its
/// [`WhenFull`] says, and counts the drop with [`Self::note_dropped`]).
/// Pure: the caller passes the time.
#[derive(Debug)]
pub struct ClassQueues<T> {
    queues: [VecDeque<(u64, T)>; QUEUES],
    capacity: [usize; QUEUES],
    /// The smooth weighted round robin's current weights.
    credit: [i64; QUEUES],
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
            credit: [0; QUEUES],
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

    /// The next event: the turn of the queues that hold events, by the
    /// smooth weighted round robin of [`SHARE_WEIGHTS`] (each adds its
    /// weight, the largest total is taken and pays the sum back; the higher
    /// queue on a tie). FIFO inside a queue.
    pub fn take(&mut self, now_ns: u64) -> Option<Taken<T>> {
        let top = (0..QUEUES).find(|&i| !self.queues[i].is_empty())?;
        let pick = {
            let mut total = 0;
            let mut best = top;
            let all = self.queues.iter().zip(&mut self.credit).zip(SHARE_WEIGHTS);
            for ((queue, credit), weight) in all {
                if queue.is_empty() {
                    *credit = 0;
                } else {
                    *credit += weight;
                    total += weight;
                }
            }
            for i in top..QUEUES {
                if !self.queues[i].is_empty() && self.credit[i] > self.credit[best] {
                    best = i;
                }
            }
            self.credit[best] -= total;
            best
        };
        let (enqueued_ns, item) = self.queues[pick].pop_front()?;
        self.handed[pick] = self.handed[pick].saturating_sub(1);
        if self.queues[pick].is_empty() && self.queues[pick].capacity() > SHRINK_ABOVE {
            self.queues[pick].shrink_to(SHRINK_ABOVE);
        }
        let waited_ns = now_ns.saturating_sub(enqueued_ns);
        let ahead = pick != top;
        let st = &mut self.stats[pick];
        st.depth = self.queues[pick].len() as u64;
        st.max_wait_ns = st.max_wait_ns.max(waited_ns);
        st.window_max_wait_ns = st.window_max_wait_ns.max(waited_ns);
        if ahead {
            st.ahead += 1;
        }
        Some(Taken {
            priority: Priority::ALL[pick],
            item,
            enqueued_ns,
            waited_ns,
            ahead,
        })
    }

    /// The longest wait of `p` since the last call (review #471 B2: the
    /// loss recorder's sample window), and start a new window.
    pub fn take_window_max_wait(&mut self, p: Priority) -> u64 {
        std::mem::take(&mut self.stats[p.index()].window_max_wait_ns)
    }

    /// Hand `f` every event of `p` queued before `before_ns` that no earlier
    /// call handed over, front first, each once — the events of `p` an event
    /// taken from another queue overtakes (lab PR 267: the execs the lineage
    /// learns before the event that overtakes them is judged). Amortised O(1) per event. The queue's times are its push
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

    /// FIFO inside a queue; P0 first (its weight); then P1–P3 by their
    /// shares — P1's two turns in four, P2's and P3's one each, an empty
    /// queue's turns to the others (the higher on a tie).
    #[test]
    fn takes_are_fifo_in_a_queue_p0_first_then_by_share() {
        let mut q = ClassQueues::new([8; QUEUES]);
        q.push(p(3), 1, "n1").unwrap();
        q.push(p(2), 2, "f1").unwrap();
        q.push(p(2), 3, "f2").unwrap();
        q.push(p(0), 4, "t1").unwrap();
        q.push(p(1), 5, "p1").unwrap();
        let order: Vec<&str> = std::iter::from_fn(|| q.take(10).map(|t| t.item)).collect();
        assert_eq!(order, ["t1", "p1", "f1", "n1", "f2"]);
        assert!(q.is_empty());
        assert!(q.take(11).is_none());
        assert_eq!(q.stats(p(3)).ahead, 1, "n1 went ahead of f2");
        assert_eq!(q.stats(p(2)).ahead, 0);
    }

    /// Second review of #471, R-A: P0 is far ahead but never alone — a
    /// flood of it leaves a waiting exec and a waiting network event their
    /// turns within the first takes (8 : 2 : 1 of 11 here), P0 in its order.
    #[test]
    fn p0_is_first_but_never_alone() {
        let mut q = ClassQueues::new([1000; QUEUES]);
        q.push(p(3), 0, ("n", 0)).unwrap();
        q.push(p(1), 0, ("p", 0)).unwrap();
        for i in 0..300u64 {
            q.push(p(0), 1 + i, ("t", i)).unwrap();
        }
        let order: Vec<(&str, u64)> =
            std::iter::from_fn(|| q.take(1_000).map(|t| t.item)).collect();
        assert_eq!(order[0], ("t", 0), "a tamper event first");
        let at = |c: &str| order.iter().position(|(k, _)| *k == c).unwrap();
        assert!(at("p") < 6, "the exec within the first takes: {}", at("p"));
        assert!(at("n") < 11, "the network event too: {}", at("n"));
        let tampers: Vec<u64> = order
            .iter()
            .filter(|(k, _)| *k == "t")
            .map(|(_, i)| *i)
            .collect();
        assert_eq!(tampers, (0..300).collect::<Vec<_>>(), "FIFO");
        assert_eq!(
            q.stats(p(1)).ahead + q.stats(p(3)).ahead,
            2,
            "both taken ahead of P0"
        );
    }

    /// Every queue flooded: every window of twelve takes is 8 of P0, 2 of
    /// P1, 1 of P2, 1 of P3 (the floor holds at every point, R-A).
    #[test]
    fn under_a_p0_flood_every_class_keeps_its_share() {
        let mut q = ClassQueues::new([10_000; QUEUES]);
        for i in 0..2_400u32 {
            for c in 0..QUEUES {
                q.push(p(c), u64::from(i), i).unwrap();
            }
        }
        let taken: Vec<usize> = (0..2_400)
            .map(|_| q.take(10_000).unwrap().priority.index())
            .collect();
        for w in taken.chunks(12) {
            let n = |c| w.iter().filter(|pr| **pr == c).count();
            assert_eq!((n(0), n(1), n(2), n(3)), (8, 2, 1, 1), "{w:?}");
        }
    }

    /// With P1, P2 and P3 all holding events (P0 empty), every window of
    /// four takes is two of P1, one of P2, one of P3, each queue FIFO
    /// (review #471 A2: the share is a floor at every point, not on
    /// average).
    #[test]
    fn the_shares_hold_in_every_window_of_four_takes() {
        let mut q = ClassQueues::new([1000; QUEUES]);
        for i in 0..400u32 {
            for c in 1..QUEUES {
                q.push(p(c), u64::from(i), i).unwrap();
            }
        }
        let mut taken: Vec<(usize, u32)> = Vec::new();
        for _ in 0..400 {
            let t = q.take(1_000).unwrap();
            taken.push((t.priority.index(), t.item));
        }
        for w in taken.chunks(4) {
            let n = |c| w.iter().filter(|(pr, _)| *pr == c).count();
            assert_eq!((n(1), n(2), n(3)), (2, 1, 1), "{w:?}");
        }
        for c in 1..QUEUES {
            let items: Vec<u32> = taken
                .iter()
                .filter(|(pr, _)| *pr == c)
                .map(|(_, i)| *i)
                .collect();
            assert_eq!(
                items,
                (0..items.len() as u32).collect::<Vec<_>>(),
                "P{c} FIFO"
            );
        }
    }

    /// A queue that ran empty banks no turns: an event arriving after a
    /// long flood of another class waits at most one take, not a burst of
    /// saved-up turns that would hold the flood back.
    #[test]
    fn an_empty_queue_banks_no_turns() {
        let mut q = ClassQueues::new([1000; QUEUES]);
        for i in 0..300u64 {
            q.push(p(2), i, i).unwrap();
        }
        for _ in 0..200 {
            assert_eq!(q.take(400).unwrap().priority, Priority::P2);
        }
        for i in 0..4u64 {
            q.push(p(3), 500 + i, 1_000 + i).unwrap();
        }
        let order: Vec<usize> = (0..8)
            .map(|_| q.take(600).unwrap().priority.index())
            .collect();
        assert_eq!(order, [2, 3, 2, 3, 2, 3, 2, 3]);
    }

    /// Review #471 A2, the reviewer's simulation as a test: P2 kept full
    /// (a file-open flood), the network arriving at a fraction of the
    /// takes, P3 dropping when full. With the plan's aging the network got
    /// one take in ~66: at 1/20 of the takes 5,781 of 20,000 were dropped,
    /// at 1/10 25,781 of 40,000. With the shares nothing is dropped up to
    /// half the takes, the wait stays a take or two; and with P1 flooded
    /// too, the network keeps its quarter.
    #[test]
    fn a_flood_of_a_higher_class_leaves_the_network_its_share() {
        const TAKES: u64 = 400_000;
        // (P1 flooded too, network every n takes) -> (taken, dropped, max wait in takes)
        let run = |p1_flood: bool, every: u64| {
            let mut q = ClassQueues::with_specs();
            let (mut arrived, mut taken, mut dropped, mut max_wait) = (0u64, 0u64, 0u64, 0u64);
            for now in 0..TAKES {
                while q.len(Priority::P2) < q.capacity(Priority::P2) {
                    q.push(Priority::P2, now, false).unwrap();
                }
                while p1_flood && q.len(Priority::P1) < q.capacity(Priority::P1) {
                    q.push(Priority::P1, now, false).unwrap();
                }
                if now % every == 0 {
                    arrived += 1;
                    if q.push(Priority::P3, now, true).is_err() {
                        q.note_dropped(Priority::P3);
                        dropped += 1;
                    }
                }
                let t = q.take(now).unwrap();
                if t.item {
                    taken += 1;
                    max_wait = max_wait.max(t.waited_ns);
                }
            }
            assert_eq!(q.stats(Priority::P3).dropped, dropped);
            (arrived, taken, dropped, max_wait)
        };
        for every in [100, 50, 20, 10, 4, 2] {
            let (arrived, taken, dropped, max_wait) = run(false, every);
            assert_eq!(dropped, 0, "1/{every}: {dropped} dropped");
            assert!(
                arrived - taken <= 1,
                "1/{every}: {taken} of {arrived} taken"
            );
            assert!(max_wait <= 1, "1/{every}: waited {max_wait} takes");
        }
        for every in [100, 20, 10, 4] {
            let (arrived, taken, dropped, max_wait) = run(true, every);
            assert_eq!(dropped, 0, "P1 flooded, 1/{every}: {dropped} dropped");
            assert!(
                arrived - taken <= 1,
                "P1 flooded, 1/{every}: {taken} of {arrived}"
            );
            assert!(
                max_wait <= 3,
                "P1 flooded, 1/{every}: waited {max_wait} takes"
            );
        }
        // past its share the queue fills and drops, and says so
        let (arrived, taken, dropped, _) = run(true, 2);
        assert!(
            dropped > 0 && taken >= TAKES / 4 - 1,
            "{taken} of {arrived}, {dropped} dropped"
        );
    }

    /// Second review of #471, R-A, as a simulation: P0 kept full (a root
    /// `chmod` loop, a `fork` + `bpf()` loop), the opens flooding P2, execs
    /// flooding P1 or not, the network at a fraction of the takes. With a
    /// strict P0 the network got no take at all; now it keeps 1/10 of the
    /// consumer (1/12 with P1 flooded too) and drops nothing below it.
    #[test]
    fn a_tamper_flood_leaves_the_other_classes_their_share() {
        const TAKES: u64 = 120_000;
        let run = |p1_flood: bool, every: u64| {
            let mut q = ClassQueues::with_specs();
            let (mut arrived, mut net, mut dropped, mut max_wait) = (0u64, 0u64, 0u64, 0u64);
            let mut execs = 0u64;
            for now in 0..TAKES {
                for c in [0, 2] {
                    while q.len(p(c)) < q.capacity(p(c)) {
                        q.push(p(c), now, 0u8).unwrap();
                    }
                }
                while p1_flood && q.len(p(1)) < q.capacity(p(1)) {
                    q.push(p(1), now, 1).unwrap();
                }
                if now % every == 0 {
                    arrived += 1;
                    if q.push(p(3), now, 3).is_err() {
                        dropped += 1;
                    }
                }
                let t = q.take(now).unwrap();
                match t.item {
                    3 => {
                        net += 1;
                        max_wait = max_wait.max(t.waited_ns);
                    }
                    1 => execs += 1,
                    _ => {}
                }
            }
            (arrived, net, dropped, max_wait, execs)
        };
        for every in [100, 20, 10] {
            let (arrived, net, dropped, max_wait, _) = run(false, every);
            assert_eq!(dropped, 0, "1/{every}: {dropped} dropped");
            assert!(arrived - net <= 1, "1/{every}: {net} of {arrived}");
            // a network event waits at most about one round of the shares
            assert!(max_wait <= 12, "1/{every}: waited {max_wait} takes");
        }
        for every in [100, 20, 12] {
            let (arrived, net, dropped, max_wait, execs) = run(true, every);
            assert_eq!(dropped, 0, "P1 flooded, 1/{every}: {dropped} dropped");
            assert!(
                arrived - net <= 1,
                "P1 flooded, 1/{every}: {net} of {arrived}"
            );
            assert!(
                max_wait <= 14,
                "P1 flooded, 1/{every}: waited {max_wait} takes"
            );
            assert!(
                execs >= TAKES / 6 - 1,
                "the execs keep their sixth: {execs}"
            );
        }
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
        // review #471 M1: the rare tamper sources wait for room — a flood of
        // denials does not drop them
        let module = Event::ModuleLoad {
            method: nn_model::ModuleLoadMethod::Finit,
            loader_pid: 1,
            loader_uid: 0,
            loader_comm: String::new(),
            parent_comm: String::new(),
            parent_is_kthread: false,
            path: None,
            timestamp_ns: 0,
        };
        assert_eq!(class_of(&module), EventClass::Tamper);
        assert_eq!(when_full(&module), WhenFull::Backpressure);
        assert!(floods_p0(&denial) && !floods_p0(&module));
        let bpf = Event::BpfSyscall {
            pid: 1,
            uid: 1000,
            comm: String::new(),
            cmd: 0,
            arg: 0,
            timestamp_ns: 0,
        };
        assert!(floods_p0(&bpf));
        assert_eq!(when_full(&bpf), WhenFull::Backpressure);
        // second review, R-E: a write-open of a CRITICAL or PERSIST file
        // waits for room; a read of it, or a write of another file, is an
        // open a full P2 drops
        use common::wire::open_sensor::open_reason;
        let open_of = |flags: u32, kernel_class: u32| Event::FileOpen {
            pid: 1,
            uid: 0,
            gid: 0,
            comm: String::new(),
            filename: "/etc/cron.d/x".into(),
            flags,
            timestamp_ns: 0,
            path_from_user: false,
            kernel_class,
        };
        for (flags, class, waits) in [
            (1, open_reason::PERSIST, true),
            (2 | 0o100, open_reason::CRITICAL, true),
            (0, open_reason::PERSIST, false),
            (1, open_reason::SENSITIVE, false),
            (1, open_reason::PROBE, false),
        ] {
            let e = open_of(flags, class);
            assert_eq!(guarded_write_open(&e), waits, "{flags:o} {class}");
            let want = if waits {
                WhenFull::Backpressure
            } else {
                WhenFull::DropNew
            };
            assert_eq!(when_full(&e), want, "{flags:o} {class}");
        }
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

    /// A canary trip is its source event's class (review #471 M10: a file
    /// canary read is a file event, judged in P2's order, not a tamper
    /// event jumping the opens of the same reader).
    #[test]
    fn a_canary_trip_is_its_source_event_s_class() {
        let trip = |access_kind, canary_type| Event::CanaryTripped {
            canary_id: String::new(),
            canary_name: String::new(),
            canary_type,
            access_kind,
            accessor_pid: 1,
            accessor_uid: 0,
            accessor_comm: String::new(),
            accessor_exe: None,
            timestamp_ns: 0,
            first_trip: true,
        };
        use nn_model::CanaryTypeTag as T;
        for (kind, ty, class) in [
            (CanaryAccessKind::FileOpen, T::File, EventClass::File),
            (CanaryAccessKind::FileOpen, T::Credential, EventClass::File),
            (
                CanaryAccessKind::ProcessExec,
                T::Process,
                EventClass::Process,
            ),
            (
                CanaryAccessKind::NetworkConnect,
                T::Network,
                EventClass::Network,
            ),
        ] {
            assert_eq!(class_of(&trip(kind, ty)), class, "{kind:?}");
        }
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
