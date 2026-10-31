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
//! verdicts on the golden corpus: `agent/src/decision/golden.rs`).
//!
//! R12b (lab PR 269): the queues hold [`Envelope`]s (source, sequence,
//! the record's kernel time, the process); the decision's delay is timed
//! from that kernel time against its class's budget ([`DECISION_BUDGET_NS`],
//! stage 5 of [`LossStage`]); the events that can flood P0 are capped per
//! uid and second ([`FloodCap`], the third review of #471's C3). The
//! response dispatcher, the signed `telemetry_loss` rows and the loss
//! counters of stages 6 to 8 are R12c's.

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
/// ([`crate::contract::ClassContract::source`], R13). R12b (lab PR 269):
/// the bus numbers its senders in the order they are named; 0 is a sender
/// no source named (the tests', a clone of the bus's first sender).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Default)]
pub struct SourceId(pub u16);

/// An event on the bus, with what orders it: in its class, the order its
/// source read it in (FIFO: `seq`); between classes, its time and its
/// process (plan §3.4). R12b (lab PR 269): the queues hold envelopes — the
/// sender stamps each event with its source, its place in the source's
/// sends, its class, the kernel's time of its record ([`record_time_ns`],
/// stage 5's clock) and the process it is about ([`actor_of`]).
#[derive(Debug, Clone)]
pub struct Envelope {
    /// The source that read it.
    pub source: SourceId,
    /// Its place in its source's sends (from 1; gaps where the source's
    /// events were coalesced, capped or dropped).
    pub seq: u64,
    /// Its class: the queue it waits in.
    pub class: EventClass,
    /// The kernel's time of its record (`CLOCK_MONOTONIC` ns,
    /// [`record_time_ns`]); 0 when the event has none the decision's delay
    /// can be measured from.
    pub ts_ns: u64,
    /// The process it is about: the boot, its pid, its start when the
    /// record names it (0 otherwise).
    pub key: ProcessKey,
    /// The event.
    pub event: Event,
}

impl Envelope {
    /// `event` from `source`, its `seq`-th send, on the boot `boot_id`.
    pub fn new(source: SourceId, seq: u64, boot_id: [u8; 16], event: Event) -> Self {
        let (tgid, start_ns) = actor_of(&event);
        Self {
            source,
            seq,
            class: class_of(&event),
            ts_ns: record_time_ns(&event),
            key: ProcessKey {
                boot_id,
                tgid,
                start_ns,
            },
            event,
        }
    }

    /// Its queue.
    pub fn priority(&self) -> Priority {
        Priority::of(self.class)
    }
}

/// R12b (lab PR 269): the kernel's time of the record an event was made
/// from (`CLOCK_MONOTONIC` ns, `bpf_ktime_get_ns`), the time stage 5
/// measures the decision's delay from (review #471 B2: the bus timed from
/// its push). Every variant named. A flow's row by its phase: a TCP flow's
/// closed row from its close, an open-phase row from when it was observed
/// (`observed_ns`: the connect, a refused connect, the snapshot's time);
/// 0 — not timed — for a UDP flow's row, which closes a window of sends
/// the drain holds by design.
pub fn record_time_ns(event: &Event) -> u64 {
    use nn_model::telemetry::FlowPhase;
    match event {
        Event::ProcessSpawn { timestamp_ns, .. }
        | Event::FileOpen { timestamp_ns, .. }
        | Event::MassWrite { timestamp_ns, .. }
        | Event::FileBurst { timestamp_ns, .. }
        | Event::DefenderSignal { timestamp_ns, .. }
        | Event::ExecCheck { timestamp_ns, .. }
        | Event::ModuleLoad { timestamp_ns, .. }
        | Event::BpfSyscall { timestamp_ns, .. }
        | Event::IoUring { timestamp_ns, .. }
        | Event::TcpConnect { timestamp_ns, .. }
        | Event::DnsQuery { timestamp_ns, .. }
        | Event::FsProtectDenial { timestamp_ns, .. }
        | Event::CanaryTripped { timestamp_ns, .. }
        | Event::DnsFlood { timestamp_ns, .. }
        | Event::SensorFlood { timestamp_ns, .. }
        | Event::ExploitPostcondition { timestamp_ns, .. } => *timestamp_ns,
        Event::Fim(fe) => fe.timestamp_ns,
        Event::NetListener(nl) => nl.timestamp_ns,
        Event::NetFlow(nf) => match nf.phase {
            FlowPhase::Connect | FlowPhase::Denied | FlowPhase::Snapshot => nf.observed_ns,
            FlowPhase::Closed if nf.proto == 6 => nf.end_ns,
            FlowPhase::Closed => 0,
        },
    }
}

/// R12b (lab PR 269): the process an event is about — its pid, and its
/// start (`CLOCK_MONOTONIC` ns) when the record names it, else 0: the
/// envelope's [`ProcessKey`]. Every variant named.
pub fn actor_of(event: &Event) -> (u32, u64) {
    match event {
        Event::ProcessSpawn { pid, start_ns, .. } => (*pid, *start_ns),
        Event::NetFlow(nf) => (nf.pid, nf.proc_start_ns),
        Event::FileOpen { pid, .. }
        | Event::MassWrite { pid, .. }
        | Event::FileBurst { pid, .. }
        | Event::DefenderSignal { pid, .. }
        | Event::ExecCheck { pid, .. }
        | Event::BpfSyscall { pid, .. }
        | Event::IoUring { pid, .. }
        | Event::TcpConnect { pid, .. }
        | Event::DnsQuery { pid, .. }
        | Event::FsProtectDenial { pid, .. }
        | Event::DnsFlood { pid, .. }
        | Event::SensorFlood { pid, .. }
        | Event::ExploitPostcondition { pid, .. } => (*pid, 0),
        Event::ModuleLoad { loader_pid, .. } => (*loader_pid, 0),
        Event::CanaryTripped { accessor_pid, .. } => (*accessor_pid, 0),
        Event::Fim(fe) => (fe.modifier_pid, 0),
        Event::NetListener(nl) => (nl.pid, 0),
    }
}

// ── stage 5: the decision's delay ────────────────────────────────────

/// R12b (lab PR 269), stage 5: how late a class's decision may come,
/// counted from the kernel's time of its record ([`record_time_ns`]) to the
/// end of its judgement; a later one is counted as over its budget (plan
/// §3.4: the decision's delay, per class).
/// - P0 tamper, 100 ms: drained first (two thirds of the consumer or more);
///   on R12a the bursts' first records were judged 0.2–5 ms after the
///   burst began under EXP-13's flood, where the one channel took 0.5 s.
/// - P1 process, 250 ms: the exec quarantine holds a process until its exec
///   is judged, and every later event of the process is judged on it.
/// - P2 file, 1 s: the opens' share leaves a file event at most 2,048 opens
///   behind (≈ 0.3–1.2 s under a flood, `FILE_OPEN_SHARE`).
/// - P3 network, 500 ms: a refused or blocklisted connect is judged while
///   the connection is young (NET-001's kills came 13–27 ms after the
///   connect under EXP-13c).
pub const DECISION_BUDGET_NS: [u64; QUEUES] =
    [100_000_000, 250_000_000, 1_000_000_000, 500_000_000];

/// One queue's decisions, timed from their record (stage 5).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DecisionDelay {
    /// The delays of the timed decisions.
    pub delay: LatencyHistogram,
    /// Decided later than the queue's budget.
    pub over_budget: u64,
    /// Decided with no record time to measure from ([`record_time_ns`] 0).
    pub untimed: u64,
}

impl DecisionDelay {
    /// A decision of a record timed `ts_ns`, ended at `now_ns` (the same
    /// clock), against `budget_ns`; `true` when it was over the budget. A
    /// record without a time is counted as untimed; one timed after `now_ns`
    /// (no such record: a clock read before the record's) as no delay.
    pub fn record(&mut self, ts_ns: u64, now_ns: u64, budget_ns: u64) -> bool {
        if ts_ns == 0 {
            self.untimed += 1;
            return false;
        }
        let delay = now_ns.saturating_sub(ts_ns);
        self.delay.record_ns(delay);
        let over = delay > budget_ns;
        if over {
            self.over_budget += 1;
        }
        over
    }
}

// ── C3: the floods of P0, capped per uid ─────────────────────────────

/// Third review of #471, C3 (R12b, lab PR 269): of the events that can
/// flood P0 ([`floods_p0`]), each uid gets this many queued a second per
/// kind (refused operations, `bpf()` calls); the rest of its second is
/// counted, not queued — in a signed row (uid, count, the first processes
/// named) and the status. Under the shares a flood that keeps P0 full takes
/// two thirds of the consumer; capped, a uid's flood takes at most this
/// many decisions a second (EXP-13's consumer judged ~7,000 to ~17,000):
/// any user's `fork` + `bpf()` loop on 6.x (one record per new process and
/// command a second, refused with EPERM), root's loop of new processes'
/// refused `chmod`s. Legitimate traffic is far below it: the kernel keeps
/// one `bpf()` record per process and command a second, and a refused
/// operation outside an attack is rare. Another uid's events have their
/// own allowance — a flood by one never caps another's — and a repeat of a
/// queued denial is coalesced before it is counted here.
pub const FLOOD_CAP_PER_UID: u32 = 256;
/// The cap's window: [`FLOOD_CAP_PER_UID`] per uid and kind each second.
pub const FLOOD_CAP_WINDOW_NS: u64 = 1_000_000_000;
/// The keys ([`CapKey`]: kind, uid and target) the cap keeps. Full, the
/// keys whose window has ended and that hold nothing to sign go first. A
/// new key that still finds no room is queued uncapped — judged like any
/// P0 event, or, when P0 itself is full, dropped by the bus with its signed
/// `event_bus_drop` row and `TelemetryLoss`: never set aside uncounted and
/// unjudged. It is counted ([`FloodCap::take_overflow`]) and signed in the
/// next capped row, and raises the posture's `TelemetryLoss` (review of
/// #474: the policy for a full table).
pub const FLOOD_CAP_KEYS: usize = 4096;
/// The kinds of process (`comm` and action) a capped key names between
/// two rows (its count covers them all).
pub const FLOOD_CAP_SAMPLES: usize = 8;

/// Review of #474: the `bpf()` commands the cap never holds back —
/// NN-L-BPF-001's (a program loaded, attached, a link made). Each is judged
/// whatever else the same uid sends; a burst of them is bounded by P0's
/// shares and its wait for room, as on R12a.
pub const NEVER_CAPPED_BPF: [u32; 3] = [
    common::bpf_cmd::BPF_PROG_LOAD,
    common::bpf_cmd::BPF_PROG_ATTACH,
    common::bpf_cmd::BPF_LINK_CREATE,
];

/// R12b: the allowance of a uid's `bpf()` records about the agent's own
/// objects ([`FloodKind::BpfOwn`]: a handle to one of its maps, programs or
/// links taken by id, a write handle on one of its maps — NN-L-BPF-002's
/// tampering), a second: four times [`FLOOD_CAP_PER_UID`]. The lab's soak
/// found the sampler's `bpftool map dump`s of the agent's maps making
/// ~450 such records in a second as root; capped at 256 with the other
/// `bpf()` calls, BPF-002 lost them. Still a cap: a fork loop of
/// `bpf(BPF_MAP_GET_FD_BY_ID, <an agent map>)` by any user takes at most
/// this many decisions a second.
pub const FLOOD_CAP_OWN_PER_UID: u32 = 4 * FLOOD_CAP_PER_UID;

/// Which flood of P0 an event is ([`floods_p0`]); each kind has its own
/// allowance per uid.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum FloodKind {
    /// `FsProtectDenial`: a refused operation on a protected inode, or a
    /// refused signal or ptrace of a protected process.
    Denial,
    /// `BpfSyscall`: a `bpf()` call the LSM hook saw, but those of
    /// [`FloodKind::BpfOwn`].
    Bpf,
    /// `BpfSyscall` about the agent's own objects (the kernel's
    /// `foreign_get_fd`, `foreign_map_write`): NN-L-BPF-002's, with a larger
    /// allowance ([`FLOOD_CAP_OWN_PER_UID`]).
    BpfOwn,
}

impl FloodKind {
    /// The kind of `event`, `None` when it does not flood P0.
    pub fn of(event: &Event) -> Option<(FloodKind, u32)> {
        use common::wire::{BPF_CMD_FOREIGN_GET_FD, BPF_CMD_FOREIGN_MAP_WRITE};
        match event {
            Event::FsProtectDenial { uid, .. } => Some((FloodKind::Denial, *uid)),
            Event::BpfSyscall { uid, cmd, .. }
                if matches!(*cmd, BPF_CMD_FOREIGN_GET_FD | BPF_CMD_FOREIGN_MAP_WRITE) =>
            {
                Some((FloodKind::BpfOwn, *uid))
            }
            Event::BpfSyscall { uid, .. } => Some((FloodKind::Bpf, *uid)),
            _ => None,
        }
    }

    /// As the signed row and the status name it.
    pub const fn name(self) -> &'static str {
        match self {
            FloodKind::Denial => "FsProtectDenial",
            FloodKind::Bpf => "BpfSyscall",
            FloodKind::BpfOwn => "BpfSyscall (the agent's own objects)",
        }
    }
}

/// What, inside a kind and a uid, the cap counts apart (review of #474):
/// each refused operation on each target, each `bpf()` command — one
/// target's or command's burst never holds back another's event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum CapTarget {
    /// A refused operation on one target (`target_dev`, `target_ino`: an
    /// inode, or the process of a refused signal or ptrace).
    Denial {
        operation: nn_model::FsProtectOperation,
        dev: u64,
        ino: u64,
    },
    /// A `bpf()` command (uapi, or a synthetic `BPF_CMD_*`).
    Bpf { cmd: u32 },
    /// Third review of #475: `keys` keys a full table released past
    /// [`FloodCap`]'s bound on them, their counts summed per kind and uid
    /// (the uid [`u32::MAX`]: the uids past the bound on those sums).
    Rest { keys: u32 },
}

/// The cap's key: the kind of flood, the actor's uid, and its target.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct CapKey {
    pub kind: FloodKind,
    pub uid: u32,
    pub target: CapTarget,
}

impl CapKey {
    /// The key `event` is counted under, `None` when the cap never holds it
    /// back: not a flood of P0, or one of [`NEVER_CAPPED_BPF`].
    pub fn of(event: &Event) -> Option<CapKey> {
        let (kind, uid) = FloodKind::of(event)?;
        let target = match event {
            Event::FsProtectDenial {
                operation,
                target_dev,
                target_ino,
                ..
            } => CapTarget::Denial {
                operation: *operation,
                dev: *target_dev,
                ino: *target_ino,
            },
            Event::BpfSyscall { cmd, .. } => {
                if NEVER_CAPPED_BPF.contains(cmd) {
                    return None;
                }
                CapTarget::Bpf { cmd: *cmd }
            }
            _ => return None,
        };
        Some(CapKey { kind, uid, target })
    }

    /// As the signed row names the target.
    pub fn target_json(&self) -> serde_json::Value {
        match self.target {
            CapTarget::Denial {
                operation,
                dev,
                ino,
            } => serde_json::json!({
                "operation": operation.to_string(),
                "target_dev": dev,
                "target_ino": ino,
            }),
            CapTarget::Bpf { cmd } => serde_json::json!({
                "cmd": common::wire::bpf_cmd_name(cmd),
            }),
            CapTarget::Rest { keys } => serde_json::json!({
                "released_keys": keys,
            }),
        }
    }
}

/// One process a capped key names: its pid, its `comm`, and what it did
/// (a refused operation and its target, a `bpf()` command).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapSample {
    pub pid: u32,
    pub comm: String,
    pub what: String,
}

/// What one key ([`CapKey`]) had capped since the last row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Capped {
    pub kind: FloodKind,
    pub uid: u32,
    pub target: CapTarget,
    /// Events counted, not queued.
    pub count: u64,
    /// Bus time (ns) of the first and the last.
    pub first_ns: u64,
    pub last_ns: u64,
    /// What the flood is made of: the first process of each distinct
    /// `comm` and action among them (at most [`FLOOD_CAP_SAMPLES`]) — a
    /// fork loop of one program is one, another program's attempt inside
    /// the flood is named apart.
    pub samples: Vec<CapSample>,
}

#[derive(Debug)]
struct CapWindow {
    started_ns: u64,
    queued: u32,
    pending: Option<Capped>,
}

/// C3's cap ([`FLOOD_CAP_PER_UID`]): per key ([`CapKey`]: kind, uid,
/// target), a window of a second that lets the first events through and
/// counts the rest. Pure: the caller passes the time.
#[derive(Debug)]
pub struct FloodCap {
    per_uid: u32,
    window_ns: u64,
    keys: usize,
    windows: std::collections::HashMap<CapKey, CapWindow>,
    total: u64,
    /// Queued uncapped because the table was full, since the last
    /// [`Self::take_overflow`], and the uids among them that were root's.
    overflow: u64,
    overflow_root: bool,
    overflow_total: u64,
    /// Pending counts of keys a full table released before their row, at
    /// most `keys` of them; past it summed per kind and uid, at most `keys`
    /// sums and then one per kind for the rest of the uids (third review of
    /// #475: a row names a bounded number of keys).
    released: Vec<Capped>,
    released_rest: std::collections::HashMap<(FloodKind, u32), Capped>,
}

impl Default for FloodCap {
    fn default() -> Self {
        Self::new(FLOOD_CAP_PER_UID, FLOOD_CAP_WINDOW_NS, FLOOD_CAP_KEYS)
    }
}

impl FloodCap {
    /// A cap of `per_uid` per `window_ns`, keeping at most `keys` pairs.
    pub fn new(per_uid: u32, window_ns: u64, keys: usize) -> Self {
        Self {
            per_uid,
            window_ns: window_ns.max(1),
            keys: keys.max(1),
            windows: std::collections::HashMap::new(),
            total: 0,
            overflow: 0,
            overflow_root: false,
            overflow_total: 0,
            released: Vec::new(),
            released_rest: std::collections::HashMap::new(),
        }
    }

    /// The event of `key` at `now_ns`: `true` it may be queued (counted in
    /// its key's allowance), `false` it is over it — counted, `sample`
    /// naming its process while the key names fewer than
    /// [`FLOOD_CAP_SAMPLES`] kinds (`comm` and action). A full table queues
    /// a new key uncapped and counts it ([`FLOOD_CAP_KEYS`]).
    pub fn admit(&mut self, key: CapKey, now_ns: u64, sample: impl FnOnce() -> CapSample) -> bool {
        let kind = key.kind;
        if !self.windows.contains_key(&key) && self.windows.len() >= self.keys {
            self.prune(now_ns);
            if self.windows.len() >= self.keys {
                self.release_oldest_pending(now_ns);
            }
            if self.windows.len() >= self.keys {
                self.overflow += 1;
                self.overflow_total += 1;
                self.overflow_root |= key.uid == 0;
                return true;
            }
        }
        let window_ns = self.window_ns;
        let w = self.windows.entry(key).or_insert(CapWindow {
            started_ns: now_ns,
            queued: 0,
            pending: None,
        });
        if now_ns.saturating_sub(w.started_ns) >= window_ns {
            w.started_ns = now_ns;
            w.queued = 0;
        }
        let allowance = match kind {
            FloodKind::BpfOwn => self.per_uid.saturating_mul(4),
            FloodKind::Denial | FloodKind::Bpf => self.per_uid,
        };
        if w.queued < allowance {
            w.queued += 1;
            return true;
        }
        let p = w.pending.get_or_insert_with(|| Capped {
            kind,
            uid: key.uid,
            target: key.target,
            count: 0,
            first_ns: now_ns,
            last_ns: now_ns,
            samples: Vec::new(),
        });
        p.count += 1;
        p.last_ns = now_ns;
        if p.samples.len() < FLOOD_CAP_SAMPLES {
            let s = sample();
            if !p
                .samples
                .iter()
                .any(|x| x.comm == s.comm && x.what == s.what)
            {
                p.samples.push(s);
            }
        }
        self.total += 1;
        false
    }

    /// An event [`Self::admit`] let through that was not queued after all
    /// (the bus dropped it, or the batch's fast path handed it to the slow
    /// one, which admits it again): its place in the allowance is given back.
    pub fn refund(&mut self, key: CapKey) {
        if let Some(w) = self.windows.get_mut(&key) {
            w.queued = w.queued.saturating_sub(1);
        }
    }

    /// The events queued uncapped because the table was full, since the
    /// last call, and whether root's were among them; and since boot.
    pub fn take_overflow(&mut self) -> (u64, bool, u64) {
        let out = (self.overflow, self.overflow_root, self.overflow_total);
        self.overflow = 0;
        self.overflow_root = false;
        out
    }

    /// Every event capped since boot.
    pub fn total(&self) -> u64 {
        self.total
    }

    /// What was capped since the last call, per key — every key that
    /// capped something —, the most first; the keys start counting again.
    pub fn take_pending(&mut self) -> Vec<Capped> {
        let mut out: Vec<Capped> = std::mem::take(&mut self.released);
        out.extend(self.released_rest.drain().map(|(_, c)| c));
        out.extend(self.windows.values_mut().filter_map(|w| w.pending.take()));
        out.sort_by(|a, b| {
            b.count
                .cmp(&a.count)
                .then((a.kind, a.uid, a.target).cmp(&(b.kind, b.uid, b.target)))
        });
        out
    }

    /// The re-review of #475: a full table releases a key sooner — the one
    /// whose window ended longest ago, its pending count kept for the next
    /// row ([`Self::take_pending`]) — instead of holding it until the row.
    fn release_oldest_pending(&mut self, now_ns: u64) {
        let window_ns = self.window_ns;
        let oldest = self
            .windows
            .iter()
            .filter(|(_, w)| now_ns.saturating_sub(w.started_ns) >= window_ns)
            .min_by_key(|(_, w)| w.started_ns)
            .map(|(k, _)| *k);
        if let Some(k) = oldest {
            if let Some(Some(p)) = self.windows.remove(&k).map(|w| w.pending) {
                self.push_released(p);
            }
        }
    }

    /// A released key's pending count, kept for the next row: as it is
    /// while fewer than `keys` are, else added to its kind's and uid's sum
    /// (past `keys` sums, to its kind's for the uid [`u32::MAX`]).
    fn push_released(&mut self, p: Capped) {
        if self.released.len() < self.keys {
            self.released.push(p);
            return;
        }
        let uid = if self.released_rest.len() < self.keys
            || self.released_rest.contains_key(&(p.kind, p.uid))
        {
            p.uid
        } else {
            u32::MAX
        };
        let r = self
            .released_rest
            .entry((p.kind, uid))
            .or_insert_with(|| Capped {
                kind: p.kind,
                uid,
                target: CapTarget::Rest { keys: 0 },
                count: 0,
                first_ns: p.first_ns,
                last_ns: p.last_ns,
                samples: Vec::new(),
            });
        r.count += p.count;
        r.first_ns = r.first_ns.min(p.first_ns);
        r.last_ns = r.last_ns.max(p.last_ns);
        if let CapTarget::Rest { keys } = &mut r.target {
            *keys = keys.saturating_add(1);
        }
        for s in p.samples {
            if r.samples.len() >= FLOOD_CAP_SAMPLES {
                break;
            }
            if !r
                .samples
                .iter()
                .any(|x| x.comm == s.comm && x.what == s.what)
            {
                r.samples.push(s);
            }
        }
    }

    /// Forget the pairs whose window ended and that hold nothing to sign.
    fn prune(&mut self, now_ns: u64) {
        let window_ns = self.window_ns;
        self.windows
            .retain(|_, w| w.pending.is_some() || now_ns.saturating_sub(w.started_ns) < window_ns);
    }
}

/// Where on its path an event can be lost (plan §3.4), in the order it
/// meets them. R12a counts 1 to 4 (`nn-admin status`), R12b (lab PR 269)
/// 5 (the decision's delay from the record's kernel time against its
/// class's budget, [`DECISION_BUDGET_NS`]); 6 to 8 are R12c's and later
/// lots'.
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

    fn bpf(pid: u32, uid: u32) -> Event {
        Event::BpfSyscall {
            pid,
            uid,
            comm: "loop".into(),
            cmd: 0,
            arg: 0,
            timestamp_ns: 7,
        }
    }

    fn denial_of(pid: u32, uid: u32) -> Event {
        Event::FsProtectDenial {
            pid,
            uid,
            comm: "chmod".into(),
            target_dev: 1,
            target_ino: 2,
            operation: nn_model::FsProtectOperation::Setattr,
            timestamp_ns: 9,
        }
    }

    /// A key of `kind` by `uid` on one fixed target (a `bpf(BPF_MAP_CREATE)`,
    /// a handle on an agent object, a `chmod` of inode 1:2).
    fn key(kind: FloodKind, uid: u32) -> CapKey {
        let target = match kind {
            FloodKind::Denial => CapTarget::Denial {
                operation: nn_model::FsProtectOperation::Setattr,
                dev: 1,
                ino: 2,
            },
            FloodKind::Bpf => CapTarget::Bpf { cmd: 0 },
            FloodKind::BpfOwn => CapTarget::Bpf {
                cmd: common::wire::BPF_CMD_FOREIGN_GET_FD,
            },
        };
        CapKey { kind, uid, target }
    }

    fn sample(pid: u32) -> CapSample {
        CapSample {
            pid,
            comm: format!("c{pid}"),
            what: String::new(),
        }
    }

    /// C3 (R12b): each uid gets its allowance a second per kind; the rest
    /// of the second is counted with its processes named; the next second
    /// starts again; another uid and the other kind are not capped by it.
    #[test]
    fn the_floods_of_p0_are_capped_per_uid_and_second() {
        let mut cap = FloodCap::new(3, 1_000, 16);
        let admitted: Vec<bool> = (0..5u32)
            .map(|i| cap.admit(key(FloodKind::Bpf, 1000), 10 + u64::from(i), || sample(i)))
            .collect();
        assert_eq!(admitted, [true, true, true, false, false]);
        // another uid, the other kind: their own allowance
        assert!(cap.admit(key(FloodKind::Bpf, 1001), 20, || sample(9)));
        assert!(cap.admit(key(FloodKind::Denial, 1000), 20, || sample(9)));
        // the window's end (exclusive): still capped at 1_009, not at 1_010
        assert!(!cap.admit(key(FloodKind::Bpf, 1000), 1_009, || sample(5)));
        assert!(cap.admit(key(FloodKind::Bpf, 1000), 1_010, || sample(6)));
        assert_eq!(cap.total(), 3);
        let rows = cap.take_pending();
        assert_eq!(rows.len(), 1, "{rows:?}");
        let r = &rows[0];
        assert_eq!((r.kind, r.uid, r.count), (FloodKind::Bpf, 1000, 3));
        assert_eq!((r.first_ns, r.last_ns), (13, 1_009));
        let pids: Vec<u32> = r.samples.iter().map(|s| s.pid).collect();
        assert_eq!(pids, [3, 4, 5]);
        assert!(cap.take_pending().is_empty(), "taken once");
        // a refund gives one place back
        assert!(cap.admit(key(FloodKind::Bpf, 1000), 1_011, || sample(7)));
        assert!(cap.admit(key(FloodKind::Bpf, 1000), 1_012, || sample(7)));
        assert!(!cap.admit(key(FloodKind::Bpf, 1000), 1_013, || sample(7)));
        cap.refund(key(FloodKind::Bpf, 1000));
        assert!(cap.admit(key(FloodKind::Bpf, 1000), 1_014, || sample(7)));
    }

    /// The cap's samples name what the flood is made of: one process per
    /// distinct `comm` and action — a fork loop of one program is one
    /// sample, another program's attempt inside it its own — at most
    /// [`FLOOD_CAP_SAMPLES`]; the production allowance is
    /// [`FLOOD_CAP_PER_UID`] a second.
    #[test]
    fn a_capped_pair_names_distinct_processes() {
        let mut one = FloodCap::new(1, 1_000, 16);
        let loop_of = |pid: u32, comm: &str| CapSample {
            pid,
            comm: comm.into(),
            what: "setattr 1:2".into(),
        };
        assert!(one.admit(key(FloodKind::Denial, 0), 0, || loop_of(1, "forkloop")));
        for pid in 2..50 {
            assert!(!one.admit(key(FloodKind::Denial, 0), 1, || loop_of(pid, "forkloop")));
        }
        assert!(!one.admit(key(FloodKind::Denial, 0), 2, || loop_of(77, "rm")));
        let rows = one.take_pending();
        let named: Vec<(u32, &str)> = rows[0]
            .samples
            .iter()
            .map(|s| (s.pid, s.comm.as_str()))
            .collect();
        assert_eq!(
            named,
            [(2, "forkloop"), (77, "rm")],
            "the loop once, the other program apart"
        );
        let mut cap = FloodCap::default();
        let per = FLOOD_CAP_PER_UID;
        for i in 0..per {
            assert!(cap.admit(key(FloodKind::Denial, 0), u64::from(i), || sample(i)));
        }
        for i in 0..40u32 {
            assert!(!cap.admit(key(FloodKind::Denial, 0), 500_000_000, || sample(i % 20)));
        }
        let rows = cap.take_pending();
        assert_eq!(rows[0].count, 40);
        assert_eq!(rows[0].samples.len(), FLOOD_CAP_SAMPLES);
        let mut pids: Vec<u32> = rows[0].samples.iter().map(|s| s.pid).collect();
        pids.dedup();
        assert_eq!(pids.len(), FLOOD_CAP_SAMPLES);
        assert!(
            cap.admit(key(FloodKind::Denial, 0), FLOOD_CAP_WINDOW_NS + 1, || {
                sample(0)
            }),
            "a second later"
        );
    }

    /// A full table forgets the pairs with nothing to sign whose window
    /// ended; a new pair that finds no room is queued, never capped.
    #[test]
    fn a_full_cap_table_never_caps_a_new_uid() {
        let mut cap = FloodCap::new(1, 100, 2);
        assert!(cap.admit(key(FloodKind::Bpf, 1), 0, || sample(1)));
        assert!(
            !cap.admit(key(FloodKind::Bpf, 1), 1, || sample(1)),
            "uid 1 capped"
        );
        assert!(cap.admit(key(FloodKind::Bpf, 2), 1, || sample(2)));
        // full: uid 3 finds no room yet (uid 1 has a row to sign, uid 2's
        // window runs) — queued uncapped, again and again
        assert!(cap.admit(key(FloodKind::Bpf, 3), 2, || sample(3)));
        assert!(cap.admit(key(FloodKind::Bpf, 3), 3, || sample(3)));
        // uid 2's window ends: it goes, uid 3 takes its place
        assert!(cap.admit(key(FloodKind::Bpf, 3), 200, || sample(3)));
        assert!(
            !cap.admit(key(FloodKind::Bpf, 3), 201, || sample(3)),
            "uid 3 counted now"
        );
        assert_eq!(cap.take_pending().len(), 2);
        // the two queued for want of a slot are counted, uid 3's (not root)
        assert_eq!(cap.take_overflow(), (2, false, 2));
        assert_eq!(cap.take_overflow(), (0, false, 2), "taken once");
        // root's overflow is said apart (the posture's signal)
        let mut full = FloodCap::new(1, 100, 1);
        assert!(full.admit(key(FloodKind::Bpf, 5), 0, || sample(5)));
        assert!(full.admit(key(FloodKind::Bpf, 0), 1, || sample(0)));
        assert_eq!(full.take_overflow(), (1, true, 1));
    }

    /// The re-review of #475: a full table releases the key whose window
    /// ended longest ago (its pending count kept for the row) before it
    /// queues a new key uncapped.
    #[test]
    fn a_full_table_releases_an_ended_key_before_it_overflows() {
        let mut cap = FloodCap::new(1, 100, 2);
        assert!(cap.admit(key(FloodKind::Bpf, 1), 0, || sample(1)));
        assert!(
            !cap.admit(key(FloodKind::Bpf, 1), 1, || sample(1)),
            "uid 1 capped"
        );
        assert!(cap.admit(key(FloodKind::Bpf, 2), 120, || sample(2)));
        // uid 1's window ended (it holds a count), uid 2's runs: uid 3
        // takes uid 1's place instead of overflowing
        assert!(cap.admit(key(FloodKind::Bpf, 3), 150, || sample(3)));
        assert!(
            !cap.admit(key(FloodKind::Bpf, 3), 151, || sample(3)),
            "and is capped"
        );
        assert_eq!(cap.take_overflow().0, 0);
        let rows = cap.take_pending();
        assert_eq!(
            rows.len(),
            2,
            "uid 1's released count and uid 3's: {rows:?}"
        );
        assert!(rows.iter().any(|r| r.uid == 1 && r.count == 1));
    }

    /// Third review of #475: the keys a full table releases are kept apart
    /// up to the table's size, then summed per kind and uid (as many sums,
    /// then one per kind for the rest of the uids) — a row names a bounded
    /// number of keys, and every count is in it.
    #[test]
    fn released_keys_past_the_bound_are_summed_per_kind_and_uid() {
        let mut cap = FloodCap::new(1, 100, 2);
        let mut t = 0;
        let mut capped = 0;
        // 8 keys, each capped once, each window ended before the next key:
        // every new key past the second releases an older one
        for uid in 1..=8u32 {
            assert!(cap.admit(key(FloodKind::Bpf, uid), t, || sample(uid)));
            assert!(!cap.admit(key(FloodKind::Bpf, uid), t + 1, || sample(uid)));
            capped += 1;
            t += 200;
        }
        assert_eq!(cap.take_overflow().0, 0);
        let rows = cap.take_pending();
        assert_eq!(rows.iter().map(|r| r.count).sum::<u64>(), capped);
        // released 2, sums 2 and one per kind for the rest, the table's 2
        assert!(rows.len() <= 2 + (2 + 3) + 2, "{rows:?}");
        let rest: Vec<_> = rows
            .iter()
            .filter(|r| matches!(r.target, CapTarget::Rest { .. }))
            .collect();
        assert!(!rest.is_empty(), "past the bound: summed ({rows:?})");
        assert!(
            rest.iter().any(|r| r.uid == u32::MAX),
            "past the sums' bound: the rest of the uids ({rows:?})"
        );
    }

    /// Review of #474: inside a uid the cap counts each command and each
    /// (operation, target) apart, and never holds back NN-L-BPF-001's
    /// commands — one command's or target's burst never keeps another's
    /// event from its judgement; every key that capped something is
    /// reported with its count.
    #[test]
    fn each_command_and_target_has_its_own_allowance() {
        use common::bpf_cmd::{BPF_LINK_CREATE, BPF_MAP_CREATE, BPF_PROG_ATTACH, BPF_PROG_LOAD};
        let call = |cmd: u32| Event::BpfSyscall {
            pid: 7,
            uid: 0,
            comm: "c".into(),
            cmd,
            arg: 0,
            timestamp_ns: 1,
        };
        for cmd in [BPF_PROG_LOAD, BPF_PROG_ATTACH, BPF_LINK_CREATE] {
            assert_eq!(CapKey::of(&call(cmd)), None, "cmd {cmd} is never capped");
        }
        let map = CapKey::of(&call(BPF_MAP_CREATE)).expect("a map create is counted");
        assert_eq!(
            map.target,
            CapTarget::Bpf {
                cmd: BPF_MAP_CREATE
            }
        );
        let mut cap = FloodCap::new(3, 1_000, 16);
        let n = |cap: &mut FloodCap, k: CapKey| {
            (0..10u32)
                .filter(|i| cap.admit(k, 10, || sample(*i)))
                .count()
        };
        assert_eq!(n(&mut cap, map), 3);
        // another command of the same uid (`BPF_MAP_LOOKUP_ELEM`, 1), keyed
        // apart by `CapKey::of` itself (the final mutation AN2)
        let other = CapKey::of(&call(1)).expect("a lookup is counted");
        assert_eq!(other.target, CapTarget::Bpf { cmd: 1 });
        assert_ne!(other, map);
        assert_eq!(n(&mut cap, other), 3, "another command: its own allowance");
        let on = |ino: u64| {
            CapKey::of(&Event::FsProtectDenial {
                pid: 1,
                uid: 0,
                comm: "chmod".into(),
                target_dev: 1,
                target_ino: ino,
                operation: nn_model::FsProtectOperation::Setattr,
                timestamp_ns: 1,
            })
            .unwrap()
        };
        assert_eq!(n(&mut cap, on(2)), 3);
        assert_eq!(n(&mut cap, on(3)), 3, "another target: its own allowance");
        let rows = cap.take_pending();
        assert_eq!(rows.len(), 4, "every key that capped: {rows:?}");
        assert!(rows.iter().all(|r| r.count == 7 && r.uid == 0));
        assert_eq!(cap.total(), 28);
        assert_eq!(
            map.target_json(),
            serde_json::json!({"cmd": common::wire::bpf_cmd_name(BPF_MAP_CREATE)})
        );
        assert_eq!(on(3).target_json()["target_ino"], 3);
    }

    /// R12b (the lab's soak): a uid's `bpf()` records about the agent's own
    /// objects (NN-L-BPF-002's) have an allowance of their own, four times
    /// the others' — a burst of `bpftool map dump`s of the agent's maps is
    /// not capped with the uid's other calls, and a flood of them still is.
    #[test]
    fn the_agent_s_own_objects_have_an_allowance_of_their_own() {
        use common::wire::{BPF_CMD_FOREIGN_GET_FD, BPF_CMD_FOREIGN_MAP_WRITE};
        let own = |cmd| Event::BpfSyscall {
            pid: 1,
            uid: 0,
            comm: "bpftool".into(),
            cmd,
            arg: 7,
            timestamp_ns: 1,
        };
        assert_eq!(
            FloodKind::of(&own(BPF_CMD_FOREIGN_GET_FD)),
            Some((FloodKind::BpfOwn, 0))
        );
        assert_eq!(
            FloodKind::of(&own(BPF_CMD_FOREIGN_MAP_WRITE)),
            Some((FloodKind::BpfOwn, 0))
        );
        assert_eq!(FloodKind::of(&own(0)), Some((FloodKind::Bpf, 0)));
        assert_eq!(FLOOD_CAP_OWN_PER_UID, 4 * FLOOD_CAP_PER_UID);
        let mut cap = FloodCap::new(3, 1_000, 16);
        let n = |cap: &mut FloodCap, kind| {
            (0..20u32)
                .filter(|i| cap.admit(key(kind, 0), u64::from(*i), || sample(*i)))
                .count()
        };
        assert_eq!(n(&mut cap, FloodKind::Bpf), 3, "the other calls' allowance");
        assert_eq!(n(&mut cap, FloodKind::BpfOwn), 12, "four times it, apart");
        assert_eq!(n(&mut cap, FloodKind::Denial), 3);
    }

    /// Only the events that flood P0 have a kind; their uid is the actor's.
    #[test]
    fn the_flood_kinds_are_the_floods_of_p0() {
        assert_eq!(FloodKind::of(&bpf(1, 1000)), Some((FloodKind::Bpf, 1000)));
        assert_eq!(
            FloodKind::of(&denial_of(1, 0)),
            Some((FloodKind::Denial, 0))
        );
        assert!(floods_p0(&bpf(1, 1)) && floods_p0(&denial_of(1, 1)));
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
        assert_eq!(FloodKind::of(&open), None);
    }

    /// Stage 5 (R12b): the decision's delay from the record's kernel time,
    /// against the budget; a record without a time is counted apart.
    #[test]
    fn the_decision_delay_is_timed_from_the_record() {
        let mut d = DecisionDelay::default();
        assert!(
            !d.record(1_000, 1_000 + 100, 100),
            "at the budget: not over"
        );
        assert!(d.record(1_000, 1_000 + 101, 100), "past it");
        assert!(!d.record(0, 5_000, 100), "untimed");
        assert!(
            !d.record(9_000, 5_000, 100),
            "a record after the clock read"
        );
        assert_eq!((d.over_budget, d.untimed, d.delay.count()), (1, 1, 3));
        assert_eq!(d.delay.max_us(), 0);
        let mut d = DecisionDelay::default();
        d.record(1, 1 + 250_000_000, DECISION_BUDGET_NS[1]);
        assert_eq!(d.delay.max_us(), 250_000);
        assert_eq!(d.over_budget, 0, "P1's budget is 250 ms");
        // the budgets: P0 the tightest
        assert!(DECISION_BUDGET_NS[0] < DECISION_BUDGET_NS[1]);
        assert!(DECISION_BUDGET_NS[1] < DECISION_BUDGET_NS[3]);
        assert!(DECISION_BUDGET_NS[3] < DECISION_BUDGET_NS[2]);
    }

    /// The envelope: the class, the record's time, the actor and its start
    /// when the record names it; a flow's row by its phase.
    #[test]
    fn an_envelope_carries_the_class_the_record_s_time_and_the_process() {
        let e = Envelope::new(SourceId(3), 42, [7; 16], denial_of(55, 0));
        assert_eq!(
            (e.source, e.seq, e.class),
            (SourceId(3), 42, EventClass::Tamper)
        );
        assert_eq!(e.ts_ns, 9);
        assert_eq!(
            (e.key.boot_id, e.key.tgid, e.key.start_ns),
            ([7; 16], 55, 0)
        );
        assert_eq!(e.priority(), Priority::P0);
        let spawn = Event::ProcessSpawn {
            pid: 9,
            ppid: 1,
            uid: 0,
            gid: 0,
            comm: String::new(),
            filename: String::new(),
            timestamp_ns: 500,
            argv: Vec::new(),
            parent_comm: String::new(),
            parent_start_ns: 0,
            start_ns: 499,
            parent_is_kthread: false,
            exe: Default::default(),
            argv_truncated: false,
            filename_truncated: false,
            stdio: Default::default(),
        };
        let e = Envelope::new(SourceId(1), 1, [0; 16], spawn);
        assert_eq!((e.ts_ns, e.key.tgid, e.key.start_ns), (500, 9, 499));
        use nn_model::telemetry::{FlowPhase, NetFlowEvent};
        let flow = |phase, proto, observed_ns| {
            let any = std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED);
            Event::NetFlow(NetFlowEvent {
                start_ns: 10,
                end_ns: 20,
                family: 2,
                src_addr: any,
                src_port: 0,
                dst_addr: any,
                dst_port: 0,
                proto,
                pid: 4,
                uid: 0,
                comm: String::new(),
                exe: None,
                proc_start_ns: 3,
                bytes_sent: 0,
                bytes_recv: 0,
                resolved_hostname: None,
                tls_fingerprint: None,
                flow_id: String::new(),
                close_reason: 0,
                phase,
                observed_ns,
            })
        };
        assert_eq!(
            record_time_ns(&flow(FlowPhase::Closed, 6, 0)),
            20,
            "a TCP close"
        );
        assert_eq!(record_time_ns(&flow(FlowPhase::Connect, 6, 10)), 10);
        assert_eq!(record_time_ns(&flow(FlowPhase::Denied, 6, 11)), 11);
        assert_eq!(
            record_time_ns(&flow(FlowPhase::Snapshot, 6, 15)),
            15,
            "its time"
        );
        assert_eq!(
            record_time_ns(&flow(FlowPhase::Closed, 17, 0)),
            0,
            "a UDP window"
        );
        assert_eq!(actor_of(&flow(FlowPhase::Closed, 6, 0)), (4, 3));
        assert_eq!(actor_of(&bpf(8, 1000)), (8, 0));
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
