//! The priority event bus's runtime (Wave 4 restructure, R12a, lab PR 267;
//! plan §3.4): what the pumps send into and the event loop reads from, in
//! place of the one `mpsc` channel of 4,096 events every source shared.
//!
//! Each class of events has a queue of its own ([`nn_core::bus`]: the
//! classes, the queues, the take order). A sender — every ring pump, the
//! FIM and network drains, the file-open sensor, the exploit guard — sends
//! an event into its class's queue; a full queue does what the event's
//! class says ([`nn_core::bus::when_full`]): an `FsProtectDenial` waits at
//! most 50 ms for room while its kernel ring absorbs, a P1 (process) event
//! 10 ms, then the event is dropped and counted; P2 (file) and P3
//! (network) drop the new event at once. The other tamper events (review
//! #471 M1), the file events other than `FileOpen` (review 75) and the
//! write-opens of CRITICAL/PERSIST files (second review, R-E) wait for room
//! as every source waited before; the opens fill at most
//! [`core_bus::FILE_OPEN_SHARE`] of P2 (review #471 B3; the opens counted,
//! R-E), so a flood of them neither holds a FIM record seconds behind it
//! nor makes the FIM drain wait. The wait is fair: a waiting sender takes
//! the next free slot of its queue before a sender that comes later. The
//! events that can flood P0 (`FsProtectDenial`, `BpfSyscall`) take all of
//! it but [`core_bus::P0_RESERVE`] slots, the rare tamper events' (R-D);
//! and a denial repeated by one process on one inode within a second is
//! counted into the one queued and signed (R-A). The receiver — the event
//! loop, the one consumer — takes by weighted shares 8 : 2 : 1 : 1
//! ([`core_bus::SHARE_WEIGHTS`]: review #471 A2, R-A of the second review),
//! FIFO inside a class; a flood of one class no longer holds the others
//! back, and the kernel no longer drops a tamper record because a flood of
//! opens filled the shared queue (plan §1.5, EXP-13).
//!
//! What the receiver hands over with an event (lab PR 267, the property test
//! of `agent/src/decision/golden.rs`): an event taken ahead of execs still
//! queued in P1 brings them along ([`Received::overtaken`]), and the process
//! lineage learns them first ([`BusReceiver::recv_with`]), so the event is
//! judged on the process tree of every exec that reached the bus before it
//! — as on a single queue — and the rules' own tree learns them at the
//! event loop (`RuleEngine::observe_arrival`).
//!
//! What it counts, per queue ([`BusStats`]): events queued, dropped, the
//! depth and the most it held, the longest wait in it (since boot and in
//! the last sample), the sends that had to wait for room and the longest
//! such wait, the takes by share ahead of a higher class, and the latency
//! from queue to decision (p50/p99), for `nn-admin status --key`. A drop is
//! never silent ([`spawn_loss_recorder`]): a WARN each sample it happens in,
//! a signed `event_bus_drop` row — for P0 within a second of the first drop
//! (at most one a second: an agent that crashes leaves at most a second of
//! P0 drops unsigned), for the other queues at most once per
//! [`AUDIT_WINDOW_SECS`], each row carrying every drop since the queue's
//! previous row — and the posture's `TelemetryLoss`: any P0 drop, and past
//! the security rings' threshold in a sample a drop of any other queue
//! (review #471 A2: P3's too — NET-001's connects, the chains' egress, the
//! DNS rules). At the stop ([`BusLosses::stop`]) what is still queued is
//! counted and signed (`event_bus_stop`), and every drop not yet signed is.

use std::sync::atomic::{AtomicBool, AtomicU16, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use nn_core::bus::{
    self as core_bus, CapSample, ClassQueues, DecisionDelay, Envelope, FloodCap, FloodKind,
    LatencyHistogram, Priority, QueueSpec, QueueStats, SourceId, WhenFull, DECISION_BUDGET_NS,
    QUEUES, SPECS,
};
use nn_model::Event;
use parking_lot::Mutex;
use tokio::sync::{Notify, Semaphore, TryAcquireError};
use tokio::task::JoinHandle;
use tracing::{debug, warn};

use crate::late_audit::{AuditHandle, LateAudit};
use crate::net::dns_ingest::monotonic_ns;
use crate::posture::lineage::AuthSessionTracker;
use crate::sensors::ring_drops::{self, PostureSink};

/// Audit op of a drop on the bus.
pub const AUDIT_OP: &str = "event_bus_drop";
/// Audit op of the events still queued at the stop (review #471 M3).
pub const STOP_AUDIT_OP: &str = "event_bus_stop";
/// The least time between two P0 rows written ahead of the sample.
pub const P0_ROW_EVERY: Duration = Duration::from_secs(1);
/// The loss recorder's sample (the ring-drop sampler's).
pub const SAMPLE_SECS: u64 = ring_drops::SAMPLE_SECS;
/// At most one signed row per queue per window, P0 aside (P0: one per
/// sample).
pub const AUDIT_WINDOW_SECS: u64 = ring_drops::AUDIT_WINDOW_SECS;

/// Audit op of the denials coalesced on the bus (second review of #471).
pub const COALESCED_AUDIT_OP: &str = "event_bus_coalesced";
/// Audit op of the floods of P0 counted past their uid's cap (third review
/// of #471, C3; R12b, lab PR 269).
pub const CAPPED_AUDIT_OP: &str = "event_bus_capped";
/// Second review of #471, R-A: a refused operation repeated by the same
/// process on the same inode within this window of the one sent is
/// counted into it, not queued.
pub const COALESCE_WINDOW_NS: u64 = 1_000_000_000;
/// The coalescing windows kept (a repeat of an evicted one is sent again).
const COALESCE_KEYS: usize = 512;
/// The keys a coalesced row names, the rest summed.
const COALESCED_ROW_KEYS: usize = 32;
/// R12b (lab PR 269): the most events a batch sends with one round of the
/// queue's lock ([`BusSender::send_batch`]); a pump's longer read goes in
/// several.
pub const BATCH_MAX: usize = 256;

/// The receiver is gone (the agent is stopping).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SendError;

/// One process's refused operation on one inode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct DenialKey {
    pid: u32,
    op: std::mem::Discriminant<nn_model::FsProtectOperation>,
    dev: u64,
    ino: u64,
}

/// A coalescing window: the denial sent at `sent_ns` and the repeats
/// counted into it since the last signed row.
#[derive(Debug, Clone)]
struct Window {
    operation: nn_model::FsProtectOperation,
    sent_ns: u64,
    repeats: u64,
    first_ns: u64,
    last_ns: u64,
    /// R12b, the third review's C5: whose denial — the repeats are counted
    /// into NN-L-AT-001's record budget of the uid ([`BusLosses::bind_held`]),
    /// named as its records name them.
    uid: u32,
    comm: String,
}

/// Second review of #471, R-A: identical denials (same pid, operation and
/// inode) within [`COALESCE_WINDOW_NS`] of the one queued are counted, not
/// queued — P0 no longer fills with copies of one refused `chmod` loop, and
/// every repeat is in a signed `event_bus_coalesced` row (count, first and
/// last time per key). A window opens only when its denial was queued
/// (third review, C1: a denial the bus dropped coalesces nothing — the
/// next one is sent and judged); the oldest window goes first when the
/// keys are full, in O(1) (C2: a fork loop is a new key per event).
#[derive(Debug, Default)]
struct Coalescer {
    windows: std::collections::HashMap<DenialKey, Window>,
    /// The windows in the order they were opened or restarted, with that
    /// time: the front is the oldest (an entry whose window restarted
    /// since, or went, is stale and skipped).
    order: std::collections::VecDeque<(u64, DenialKey)>,
    /// Repeats of windows evicted before their row.
    evicted: u64,
    /// The same, per uid with one of its windows' names (C5: counted into
    /// the uid's record budget at the next row).
    evicted_held: std::collections::BTreeMap<u32, (u64, String)>,
    /// Every repeat since boot.
    total: u64,
}

/// A denial's coalescing key, its operation, its time and its uid.
type DenialOf = (DenialKey, nn_model::FsProtectOperation, u64, u32);

fn denial_key(event: &Event) -> Option<DenialOf> {
    let Event::FsProtectDenial {
        pid,
        uid,
        target_dev,
        target_ino,
        operation,
        timestamp_ns,
        ..
    } = event
    else {
        return None;
    };
    let key = DenialKey {
        pid: *pid,
        op: std::mem::discriminant(operation),
        dev: *target_dev,
        ino: *target_ino,
    };
    Some((key, *operation, *timestamp_ns, *uid))
}

/// The `comm` of a denial (the window's name for its records).
fn denial_comm(event: &Event) -> &str {
    match event {
        Event::FsProtectDenial { comm, .. } => comm,
        _ => "",
    }
}

impl Coalescer {
    /// `true`: the denial repeats one queued within the window — counted.
    /// Changes nothing otherwise: the window opens only once the denial is
    /// queued ([`Self::queued`]).
    fn repeat(&mut self, denial: &DenialOf) -> bool {
        let (key, _, ts, _) = *denial;
        let Some(w) = self.windows.get_mut(&key) else {
            return false;
        };
        if ts < w.sent_ns || ts - w.sent_ns >= COALESCE_WINDOW_NS {
            return false;
        }
        if w.repeats == 0 {
            w.first_ns = ts;
        }
        w.repeats += 1;
        w.last_ns = w.last_ns.max(ts);
        self.total += 1;
        true
    }

    /// The denial was queued: its window opens (or restarts, the repeats
    /// not yet in a row kept).
    fn queued(&mut self, denial: &DenialOf, comm: &str) {
        let (key, operation, ts, uid) = *denial;
        if let Some(w) = self.windows.get_mut(&key) {
            w.sent_ns = ts;
        } else {
            while self.windows.len() >= COALESCE_KEYS {
                self.evict_oldest();
            }
            self.windows.insert(
                key,
                Window {
                    operation,
                    sent_ns: ts,
                    repeats: 0,
                    first_ns: 0,
                    last_ns: 0,
                    uid,
                    comm: comm.to_string(),
                },
            );
        }
        self.order.push_back((ts, key));
        if self.order.len() > 4 * COALESCE_KEYS {
            // restarted windows leave stale entries: drop them, keeping the
            // order (amortised O(1) per event)
            let windows = &self.windows;
            self.order
                .retain(|(t, k)| windows.get(k).is_some_and(|w| w.sent_ns == *t));
        }
    }

    /// The oldest window goes, its repeats not yet in a row kept in the
    /// evicted count.
    fn evict_oldest(&mut self) {
        while let Some((t, k)) = self.order.pop_front() {
            if self.windows.get(&k).is_some_and(|w| w.sent_ns == t) {
                if let Some(w) = self.windows.remove(&k) {
                    self.note_evicted(&k, w);
                }
                return;
            }
        }
        // no order left (cannot be): any one
        if let Some(k) = self.windows.keys().next().copied() {
            if let Some(w) = self.windows.remove(&k) {
                self.note_evicted(&k, w);
            }
        }
    }

    fn note_evicted(&mut self, k: &DenialKey, w: Window) {
        if w.repeats == 0 {
            return;
        }
        self.evicted += w.repeats;
        let e = self
            .evicted_held
            .entry(w.uid)
            .or_insert_with(|| (0, held_text(&w.comm, k.pid)));
        e.0 += w.repeats;
    }

    /// The repeats not yet in a row, per key (the most first), and those
    /// of evicted windows (in all, and per uid); their counters start
    /// again.
    fn take_pending(&mut self) -> Pending {
        let mut keys: Vec<(DenialKey, Window)> = self
            .windows
            .iter()
            .filter(|(_, w)| w.repeats > 0)
            .map(|(k, w)| (*k, w.clone()))
            .collect();
        keys.sort_by_key(|(_, w)| std::cmp::Reverse(w.repeats));
        for (k, _) in &keys {
            if let Some(w) = self.windows.get_mut(k) {
                w.repeats = 0;
            }
        }
        Pending {
            keys,
            evicted: std::mem::take(&mut self.evicted),
            evicted_held: std::mem::take(&mut self.evicted_held),
        }
    }
}

/// What [`Coalescer::take_pending`] took.
struct Pending {
    keys: Vec<(DenialKey, Window)>,
    evicted: u64,
    evicted_held: std::collections::BTreeMap<u32, (u64, String)>,
}

/// A held detection's subject, as the agent's records name a denial's
/// (`detection_payload::held_sample`: no file, no executable — its
/// `comm` and pid).
fn held_text(comm: &str, pid: u32) -> String {
    format!("{comm} (pid {pid})")
}

struct State {
    queues: ClassQueues<Envelope>,
    /// Queue → decision, per queue.
    latency: [LatencyHistogram; QUEUES],
    /// R12b, stage 5: the record's kernel time → decision, per queue,
    /// against [`DECISION_BUDGET_NS`].
    delay: [DecisionDelay; QUEUES],
    /// Sends that waited for room, per queue, and the longest such wait.
    waited: [u64; QUEUES],
    send_wait_max_ns: [u64; QUEUES],
    /// The longest wait in each queue in the last complete sample window
    /// (review #471 B2).
    recent_max_wait_ns: [u64; QUEUES],
    /// The `FileOpen`s queued in P2 that count against the opens' cap
    /// (second review of #471, R-E: not the whole of P2).
    opens: usize,
    /// R12b: per source, the last sequence taken (FIFO per source inside a
    /// class: a debug check at the take).
    #[cfg(debug_assertions)]
    last_taken: std::collections::HashMap<(SourceId, usize), u64>,
}

struct Inner {
    state: Mutex<State>,
    /// Free slots, per queue (fair: a waiting sender is served first).
    room: [Semaphore; QUEUES],
    /// An event was queued, or the last sender left.
    ready: Notify,
    /// A P0 event was dropped: the loss recorder signs it ahead of its
    /// sample.
    p0_dropped: Notify,
    /// The most `FileOpen`s P2 holds ([`core_bus::FILE_OPEN_SHARE`]).
    open_cap: usize,
    /// The opens queued, for the open-sensor pump's check before it builds
    /// an open (second review of #471: the event a full cap drops is not
    /// decoded, resolved and allocated first) — kept with `State::opens`.
    opens_hint: AtomicUsize,
    /// Opens the pump dropped on that check, without the queue's lock.
    opens_dropped_early: AtomicU64,
    /// Second review of #471, R-D: P0's slots for the events that can flood
    /// it ([`core_bus::floods_p0`]) — its capacity less
    /// [`core_bus::P0_RESERVE`]; the rare tamper events take the rest.
    p0_flood_room: Semaphore,
    coalescer: Mutex<Coalescer>,
    /// R12b, the third review's C3: the floods of P0 capped per uid.
    cap: Mutex<FloodCap>,
    senders: AtomicUsize,
    closed: AtomicBool,
    specs: [QueueSpec; QUEUES],
    epoch: Instant,
    /// R12b: the boot the envelopes' process keys name.
    boot_id: [u8; 16],
    /// R12b: the next source a sender is named ([`BusSender::for_source`]),
    /// and the sources' names by id.
    next_source: AtomicU16,
    sources: Mutex<Vec<&'static str>>,
}

impl Inner {
    fn now_ns(&self) -> u64 {
        u64::try_from(self.epoch.elapsed().as_nanos()).unwrap_or(u64::MAX)
    }

    /// What a full queue does with `event`: [`core_bus::when_full`], with
    /// this bus's waits.
    fn when_full(&self, event: &Event, p: Priority) -> WhenFull {
        match core_bus::when_full(event) {
            WhenFull::Backpressure => WhenFull::Backpressure,
            WhenFull::DropNew => WhenFull::DropNew,
            WhenFull::Wait { .. } => self.specs[p.index()].when_full,
        }
    }

    fn note_dropped(&self, p: Priority) {
        self.state.lock().queues.note_dropped(p);
        if p == Priority::P0 {
            self.p0_dropped.notify_one();
        }
    }

    /// C3: whether a flood of P0 by its uid may be queued now (counted in
    /// the uid's allowance), else counted as capped.
    fn admit_flood(&self, cap: &mut FloodCap, event: &Event) -> bool {
        let Some((kind, uid)) = FloodKind::of(event) else {
            return true;
        };
        cap.admit(kind, uid, self.now_ns(), || cap_sample(event))
    }

    /// A flood admitted by the cap that the bus dropped after all.
    fn refund_flood(&self, event: &Event) {
        if let Some((kind, uid)) = FloodKind::of(event) {
            self.cap.lock().refund(kind, uid);
        }
    }
}

/// The process a capped event names in the signed row.
fn cap_sample(event: &Event) -> CapSample {
    match event {
        Event::FsProtectDenial {
            pid,
            comm,
            operation,
            target_dev,
            target_ino,
            ..
        } => CapSample {
            pid: *pid,
            comm: comm.clone(),
            what: format!("{operation} {target_dev}:{target_ino}"),
        },
        Event::BpfSyscall { pid, comm, cmd, .. } => CapSample {
            pid: *pid,
            comm: comm.clone(),
            what: common::wire::bpf_cmd_name(*cmd).to_string(),
        },
        _ => CapSample {
            pid: 0,
            comm: String::new(),
            what: String::new(),
        },
    }
}

/// P0's slots the events that can flood it may take: its capacity less the
/// reserve (a quarter of a small test queue at most).
fn p0_flood_slots(capacity: usize) -> usize {
    let capacity = capacity.max(1);
    (capacity - core_bus::P0_RESERVE.min(capacity / 4)).max(1)
}

/// A plain `FileOpen`: one the opens' cap counts (not a guarded write-open,
/// which waits for room — second review of #471, R-E).
fn counted_open(event: &Event) -> bool {
    matches!(event, Event::FileOpen { .. }) && !core_bus::guarded_write_open(event)
}

/// Take one slot of `room` as `policy` says: `Ok(Some)` a slot, `Ok(None)`
/// the event is to be dropped, `Err` the bus is closed. Counts the wait.
async fn slot<'a>(
    inner: &Inner,
    room: &'a Semaphore,
    policy: WhenFull,
    p: Priority,
) -> Result<Option<tokio::sync::SemaphorePermit<'a>>, SendError> {
    match room.try_acquire() {
        Ok(permit) => return Ok(Some(permit)),
        Err(TryAcquireError::Closed) => return Err(SendError),
        Err(TryAcquireError::NoPermits) => {}
    }
    let started = Instant::now();
    let permit = match policy {
        WhenFull::DropNew => return Ok(None),
        WhenFull::Backpressure => room.acquire().await.map_err(|_| SendError)?,
        WhenFull::Wait { max_ns } => {
            match tokio::time::timeout(Duration::from_nanos(max_ns), room.acquire()).await {
                Ok(permit) => permit.map_err(|_| SendError)?,
                Err(_) => return Ok(None),
            }
        }
    };
    let waited_ns = u64::try_from(started.elapsed().as_nanos()).unwrap_or(u64::MAX);
    let mut st = inner.state.lock();
    st.waited[p.index()] += 1;
    st.send_wait_max_ns[p.index()] = st.send_wait_max_ns[p.index()].max(waited_ns);
    Ok(Some(permit))
}

/// The boot's id (`/proc/sys/kernel/random/boot_id`), the envelopes'
/// process keys' first part; zeros when it cannot be read.
fn read_boot_id() -> [u8; 16] {
    let text = std::fs::read_to_string("/proc/sys/kernel/random/boot_id").unwrap_or_default();
    parse_boot_id(&text).unwrap_or([0; 16])
}

/// A boot id's 32 hex digits (dashes skipped) as its 16 bytes.
fn parse_boot_id(text: &str) -> Option<[u8; 16]> {
    let hex: Vec<u8> = text
        .trim()
        .bytes()
        .filter(|b| *b != b'-')
        .map(|b| (b as char).to_digit(16).map(|d| d as u8))
        .collect::<Option<_>>()?;
    if hex.len() != 32 {
        return None;
    }
    let mut out = [0u8; 16];
    for (i, pair) in hex.chunks(2).enumerate() {
        out[i] = pair[0] << 4 | pair[1];
    }
    Some(out)
}

/// A bus of the plan's queues ([`SPECS`]) and P0's per-uid cap
/// ([`core_bus::FLOOD_CAP_PER_UID`]): its sender and its receiver; the
/// envelopes name this boot.
pub fn channel() -> (BusSender, BusReceiver) {
    build(SPECS, read_boot_id(), FloodCap::default())
}

/// A bus of the given queues and no per-uid cap (tests of the queues:
/// small queues, short waits, floods of one uid).
pub fn channel_with(specs: [QueueSpec; QUEUES]) -> (BusSender, BusReceiver) {
    build(specs, [0; 16], FloodCap::new(u32::MAX, 1, 1))
}

/// A bus of the given queues, P0's floods capped at `per_uid` a second
/// (tests of the cap).
pub fn channel_capped(specs: [QueueSpec; QUEUES], per_uid: u32) -> (BusSender, BusReceiver) {
    build(
        specs,
        [0; 16],
        FloodCap::new(
            per_uid,
            core_bus::FLOOD_CAP_WINDOW_NS,
            core_bus::FLOOD_CAP_KEYS,
        ),
    )
}

fn build(specs: [QueueSpec; QUEUES], boot_id: [u8; 16], cap: FloodCap) -> (BusSender, BusReceiver) {
    let inner = Arc::new(Inner {
        state: Mutex::new(State {
            queues: ClassQueues::new(specs.map(|s| s.capacity)),
            latency: Default::default(),
            delay: Default::default(),
            waited: [0; QUEUES],
            send_wait_max_ns: [0; QUEUES],
            recent_max_wait_ns: [0; QUEUES],
            opens: 0,
            #[cfg(debug_assertions)]
            last_taken: Default::default(),
        }),
        room: specs.map(|s| Semaphore::new(s.capacity.max(1))),
        ready: Notify::new(),
        p0_dropped: Notify::new(),
        open_cap: core_bus::FILE_OPEN_SHARE.min(specs[Priority::P2.index()].capacity.max(1)),
        opens_hint: AtomicUsize::new(0),
        opens_dropped_early: AtomicU64::new(0),
        p0_flood_room: Semaphore::new(p0_flood_slots(specs[Priority::P0.index()].capacity)),
        coalescer: Mutex::new(Coalescer::default()),
        cap: Mutex::new(cap),
        senders: AtomicUsize::new(1),
        closed: AtomicBool::new(false),
        specs,
        epoch: Instant::now(),
        boot_id,
        next_source: AtomicU16::new(1),
        sources: Mutex::new(vec!["(unnamed)"]),
    });
    (
        BusSender {
            inner: Arc::clone(&inner),
            source: SourceId(0),
            seq: Arc::new(AtomicU64::new(0)),
        },
        BusReceiver {
            inner,
            in_flight: None,
        },
    )
}

/// What the pumps and the drains send into; clones share the bus, and the
/// source and its sequence ([`Self::for_source`] names another).
pub struct BusSender {
    inner: Arc<Inner>,
    /// R12b: the source its envelopes name, and its sends' sequence.
    source: SourceId,
    seq: Arc<AtomicU64>,
}

impl Clone for BusSender {
    fn clone(&self) -> Self {
        self.inner.senders.fetch_add(1, Ordering::AcqRel);
        Self {
            inner: Arc::clone(&self.inner),
            source: self.source,
            seq: Arc::clone(&self.seq),
        }
    }
}

impl Drop for BusSender {
    fn drop(&mut self) {
        if self.inner.senders.fetch_sub(1, Ordering::AcqRel) == 1 {
            self.inner.ready.notify_one();
        }
    }
}

/// One envelope a batch could queue at once, with the slots it holds.
struct Ready {
    env: Envelope,
    counted: bool,
    floods: bool,
}

impl BusSender {
    /// R12b (lab PR 269): a sender of the same bus for the source `name` —
    /// a source id of its own (the next free one) and a sequence of its
    /// own, which its envelopes carry.
    pub fn for_source(&self, name: &'static str) -> BusSender {
        let id = self.inner.next_source.fetch_add(1, Ordering::AcqRel);
        self.inner.sources.lock().push(name);
        self.inner.senders.fetch_add(1, Ordering::AcqRel);
        BusSender {
            inner: Arc::clone(&self.inner),
            source: SourceId(id),
            seq: Arc::new(AtomicU64::new(0)),
        }
    }

    /// The source its envelopes name.
    pub fn source(&self) -> SourceId {
        self.source
    }

    /// `event`'s envelope: this sender's source and next sequence.
    fn envelope(&self, event: Event) -> Envelope {
        let seq = self.seq.fetch_add(1, Ordering::Relaxed) + 1;
        Envelope::new(self.source, seq, self.inner.boot_id, event)
    }

    /// Queue `event` in its class's queue; a full queue does what the class
    /// says ([`nn_core::bus::when_full`]): the send waits for room, at most
    /// the class's wait, or the event is dropped and counted. `Ok` either
    /// way; `Err` only when the receiver is gone (the agent stops), as a
    /// closed channel's send was.
    pub async fn send(&self, event: Event) -> Result<(), SendError> {
        if self.inner.closed.load(Ordering::Acquire) {
            return Err(SendError);
        }
        let env = self.envelope(event);
        self.send_envelope(env).await
    }

    /// R12b (lab PR 269): queue `events` in their order, as [`Self::send`]
    /// would one by one — each class's FIFO kept, the repeats coalesced,
    /// the floods capped, a full queue's wait or drop as its class says —
    /// with one round of the queue's lock for the events that find room at
    /// once (the pumps' batches: a send cost more than one `mpsc` send, and
    /// the `fs_protect` ring fell behind in EXP-13e). From the first event
    /// that finds no slot on, each is sent as [`Self::send`] sends it.
    pub async fn send_batch(&self, events: Vec<Event>) -> Result<(), SendError> {
        let rest = self.send_ready(events)?;
        for env in rest {
            self.send_envelope(env).await?;
        }
        Ok(())
    }

    /// [`Self::send_batch`] from a thread of its own (a pump's): the events
    /// that find room are queued without the runtime; a wait for room, the
    /// rare case, runs on `rt` (its timers), this thread blocked meanwhile.
    pub fn send_batch_blocking(
        &self,
        rt: &tokio::runtime::Handle,
        events: Vec<Event>,
    ) -> Result<(), SendError> {
        let rest = self.send_ready(events)?;
        if rest.is_empty() {
            return Ok(());
        }
        rt.block_on(async {
            for env in rest {
                self.send_envelope(env).await?;
            }
            Ok(())
        })
    }

    /// The batch's fast path: in order, each event coalesced, capped or
    /// given its slots without waiting, up to the first that finds none;
    /// those queued under one lock. The rest, to send one by one.
    fn send_ready(&self, events: Vec<Event>) -> Result<Vec<Envelope>, SendError> {
        let inner = &self.inner;
        if inner.closed.load(Ordering::Acquire) {
            return Err(SendError);
        }
        let mut envs = events.into_iter().map(|e| self.envelope(e));
        let mut ready: Vec<Ready> = Vec::new();
        let mut rest: Vec<Envelope> = Vec::new();
        // P2 and P3 drop a new event on a full queue: counted at the push
        let mut dropped = [0u64; QUEUES];
        {
            let mut coalescer = None;
            let mut cap = None;
            while let Some(env) = envs.next() {
                let denial = denial_key(&env.event);
                if let Some(d) = &denial {
                    if coalescer
                        .get_or_insert_with(|| inner.coalescer.lock())
                        .repeat(d)
                    {
                        continue;
                    }
                }
                let p = env.priority();
                let counted = counted_open(&env.event);
                if counted && !self.open_room() {
                    self.note_open_dropped();
                    continue;
                }
                let floods = p == Priority::P0 && core_bus::floods_p0(&env.event);
                if floods
                    && !inner.admit_flood(cap.get_or_insert_with(|| inner.cap.lock()), &env.event)
                {
                    continue;
                }
                let flood_slot = if floods {
                    match inner.p0_flood_room.try_acquire() {
                        Ok(permit) => Some(permit),
                        Err(TryAcquireError::Closed) => return Err(SendError),
                        Err(TryAcquireError::NoPermits) => None,
                    }
                } else {
                    None
                };
                let queue_slot = if floods && flood_slot.is_none() {
                    None
                } else {
                    match inner.room[p.index()].try_acquire() {
                        Ok(permit) => Some(permit),
                        Err(TryAcquireError::Closed) => return Err(SendError),
                        Err(TryAcquireError::NoPermits) => None,
                    }
                };
                let Some(queue_slot) = queue_slot else {
                    drop(flood_slot);
                    if inner.when_full(&env.event, p) == WhenFull::DropNew {
                        // a full queue that drops the new event: counted
                        dropped[p.index()] += 1;
                        continue;
                    }
                    // no room at once: this one and the rest one by one
                    // (the allowance it took is the slow path's to take)
                    if let (Some(c), Some((kind, uid))) = (cap.as_mut(), FloodKind::of(&env.event))
                    {
                        if floods {
                            FloodCap::refund(c, kind, uid);
                        }
                    }
                    rest.push(env);
                    rest.extend(envs.by_ref());
                    break;
                };
                // the slots are the queue's now: the receiver gives them
                // back at the take
                queue_slot.forget();
                if let Some(fp) = flood_slot {
                    fp.forget();
                }
                if let Some(d) = &denial {
                    // C1: the window opens once the denial is queued — it
                    // is, below, before this batch returns: it holds its
                    // slot, and a denial is never dropped at the push
                    coalescer
                        .get_or_insert_with(|| inner.coalescer.lock())
                        .queued(d, denial_comm(&env.event));
                }
                ready.push(Ready {
                    env,
                    counted,
                    floods,
                });
            }
        }
        if !ready.is_empty() || dropped.iter().any(|&n| n > 0) {
            self.push_ready(ready, dropped);
        }
        Ok(rest)
    }

    /// Queue envelopes that hold their slots, under one lock, and count the
    /// batch's drops.
    fn push_ready(&self, ready: Vec<Ready>, dropped: [u64; QUEUES]) {
        let inner = &self.inner;
        let mut freed = [0usize; QUEUES];
        let mut flood_freed = 0usize;
        let any = !ready.is_empty();
        {
            let mut st = inner.state.lock();
            for (p, n) in Priority::ALL.iter().zip(dropped) {
                for _ in 0..n {
                    st.queues.note_dropped(*p);
                }
            }
            let now = inner.now_ns();
            for r in ready {
                let p = r.env.priority();
                if r.counted && st.opens >= inner.open_cap {
                    // Review #471 B3 (R-E: the opens only): the opens' part
                    // of P2 is full — dropped as on a full queue
                    st.queues.note_dropped(p);
                    freed[p.index()] += 1;
                    continue;
                }
                if st.queues.push(p, now, r.env).is_err() {
                    // A permit is a slot: never here. Counted, never silent.
                    st.queues.note_dropped(p);
                    freed[p.index()] += 1;
                    flood_freed += usize::from(r.floods);
                    debug_assert!(false, "a send held a slot of a full queue");
                    continue;
                }
                if r.counted {
                    st.opens += 1;
                    inner.opens_hint.store(st.opens, Ordering::Relaxed);
                }
            }
        }
        for (p, n) in Priority::ALL.iter().zip(freed) {
            if n > 0 {
                inner.room[p.index()].add_permits(n);
            }
        }
        if flood_freed > 0 {
            inner.p0_flood_room.add_permits(flood_freed);
        }
        if any {
            inner.ready.notify_one();
        }
    }

    /// One envelope, waiting for room as its class says.
    async fn send_envelope(&self, env: Envelope) -> Result<(), SendError> {
        let inner = &self.inner;
        if inner.closed.load(Ordering::Acquire) {
            return Err(SendError);
        }
        // Second review of #471, R-A: a repeat of a denial just sent is
        // counted into it (a signed row), not queued.
        let denial = denial_key(&env.event);
        if let Some(d) = &denial {
            if inner.coalescer.lock().repeat(d) {
                return Ok(());
            }
        }
        let p = env.priority();
        let counted = counted_open(&env.event);
        if counted && !self.open_room() {
            self.note_open_dropped();
            return Ok(());
        }
        let floods = p == Priority::P0 && core_bus::floods_p0(&env.event);
        // C3 (R12b): a uid's flood past its allowance is counted, not
        // queued.
        if floods && !inner.admit_flood(&mut inner.cap.lock(), &env.event) {
            return Ok(());
        }
        let policy = inner.when_full(&env.event, p);
        let started = Instant::now();
        // R-D: the events that can flood P0 take its slots but the reserve
        // first (their own policy), then the queue's slot, which is then
        // free unless the rare events hold more than the reserve.
        let flood_permit = if floods {
            match slot(inner, &inner.p0_flood_room, policy, p).await? {
                Some(permit) => Some(permit),
                None => {
                    inner.refund_flood(&env.event);
                    inner.note_dropped(p);
                    return Ok(());
                }
            }
        } else {
            None
        };
        // The queue's slot: a denial keeps its bound for both slots (third
        // review, C6: with the rare events past the reserve the second slot
        // can be full too); a bpf() call waits as it waited for the first.
        let policy = match (flood_permit.is_some(), policy) {
            (true, WhenFull::Wait { max_ns }) => {
                let spent = u64::try_from(started.elapsed().as_nanos()).unwrap_or(u64::MAX);
                WhenFull::Wait {
                    max_ns: max_ns.saturating_sub(spent).max(1),
                }
            }
            (true, _) => WhenFull::Backpressure,
            (false, policy) => policy,
        };
        let Some(permit) = slot(inner, &inner.room[p.index()], policy, p).await? else {
            drop(flood_permit); // back to the semaphore
            if floods {
                inner.refund_flood(&env.event);
            }
            inner.note_dropped(p);
            return Ok(());
        };
        // The slots are the queue's now: the receiver gives them back at
        // the take.
        permit.forget();
        if let Some(fp) = flood_permit {
            fp.forget();
        }
        let comm = denial.as_ref().map(|_| denial_comm(&env.event).to_string());
        {
            let mut st = inner.state.lock();
            if counted && st.opens >= inner.open_cap {
                // Review #471 B3 (second review, R-E: the opens only): the
                // opens' part of P2 is full — the open is dropped as on a
                // full queue; the slot stays the other file events'.
                st.queues.note_dropped(p);
                drop(st);
                inner.room[p.index()].add_permits(1);
                return Ok(());
            }
            let now = inner.now_ns();
            if st.queues.push(p, now, env).is_err() {
                // A permit is a slot: never here. Counted, never silent.
                st.queues.note_dropped(p);
                drop(st);
                inner.room[p.index()].add_permits(1);
                if floods {
                    inner.p0_flood_room.add_permits(1);
                }
                debug_assert!(false, "a send held a slot of a full queue");
                return Ok(());
            }
            if counted {
                st.opens += 1;
                inner.opens_hint.store(st.opens, Ordering::Relaxed);
            }
        }
        if let (Some(d), Some(comm)) = (&denial, comm) {
            // C1: the window opens now the denial is queued
            inner.coalescer.lock().queued(d, &comm);
        }
        inner.ready.notify_one();
        Ok(())
    }

    /// Second review of #471: whether the opens' cap leaves room for one
    /// more open — the open-sensor pump asks before it builds one (a hint:
    /// `send` checks again under the queue's lock).
    pub fn open_room(&self) -> bool {
        self.inner.opens_hint.load(Ordering::Relaxed) < self.inner.open_cap
    }

    /// An open the pump dropped on [`Self::open_room`]: counted as P2's.
    pub fn note_open_dropped(&self) {
        self.inner
            .opens_dropped_early
            .fetch_add(1, Ordering::Relaxed);
    }

    /// The bus's counts.
    pub fn stats(&self) -> BusStats {
        BusStats(Arc::clone(&self.inner))
    }
}

/// An event taken from the bus, with the execs it overtook.
#[derive(Debug)]
pub struct Received {
    /// R12b (lab PR 269): the event in its envelope — its source and
    /// sequence, its class, its record's kernel time, its process.
    pub envelope: Envelope,
    /// Lab PR 267: the execs (`Event::ProcessSpawn`) still queued in P1
    /// that reached the bus before this event, each handed over once; they
    /// are taken in their turn all the same. Any class but P1 can be taken
    /// ahead of an older exec: P0 always, P2 and P3 by their share (review
    /// #471 A2). Empty for a P1 event (FIFO in its queue).
    pub overtaken: Vec<Event>,
}

/// What the event loop reads from: the one consumer.
pub struct BusReceiver {
    inner: Arc<Inner>,
    /// The event being decided: its queue, when it was queued, and its
    /// record's kernel time (stage 5).
    in_flight: Option<(usize, u64, u64)>,
}

impl Drop for BusReceiver {
    fn drop(&mut self) {
        self.inner.closed.store(true, Ordering::Release);
        for room in &self.inner.room {
            room.close();
        }
        self.inner.p0_flood_room.close();
    }
}

impl BusReceiver {
    /// The next event, by share (P0 far ahead); `None` once every
    /// sender is gone and the queues are empty. Cancel-safe: an event is
    /// taken and returned in one step.
    pub async fn recv(&mut self) -> Option<Received> {
        loop {
            if let Some(r) = self.try_recv() {
                return Some(r);
            }
            if self.inner.senders.load(Ordering::Acquire) == 0 {
                return self.try_recv();
            }
            self.inner.ready.notified().await;
        }
    }

    /// [`Self::recv`], the lineage first taught the execs the event
    /// overtook (made absolute as the event loop makes them,
    /// `exe_identity::resolve`) — the bus's barrier for the process lineage
    /// (lab PR 267).
    pub async fn recv_with(&mut self, lineage: Option<&AuthSessionTracker>) -> Option<Received> {
        let mut r = self.recv().await?;
        for e in &mut r.overtaken {
            crate::sensors::exe_identity::resolve(e);
            if let Some(l) = lineage {
                l.ingest_spawn_event(e);
            }
        }
        Some(r)
    }

    /// The next event if one is queued.
    pub fn try_recv(&mut self) -> Option<Received> {
        self.decided();
        let inner = &self.inner;
        let mut st = inner.state.lock();
        let now = inner.now_ns();
        let taken = st.queues.take(now)?;
        if counted_open(&taken.item.event) {
            st.opens = st.opens.saturating_sub(1);
            inner.opens_hint.store(st.opens, Ordering::Relaxed);
        }
        let floods = taken.priority == Priority::P0 && core_bus::floods_p0(&taken.item.event);
        #[cfg(debug_assertions)]
        if taken.item.source != SourceId(0) {
            // FIFO per named source inside a class: its sequence grows (a
            // named source sends from one task or thread; the unnamed one's
            // clones may send concurrently)
            let key = (taken.item.source, taken.priority.index());
            let prev = st.last_taken.insert(key, taken.item.seq);
            debug_assert!(
                prev.is_none_or(|s| s < taken.item.seq),
                "source {:?} out of its order in {:?}: {prev:?} then {}",
                taken.item.source,
                taken.priority,
                taken.item.seq
            );
        }
        let mut overtaken = Vec::new();
        if taken.priority != Priority::P1 {
            st.queues
                .hand_over_older(Priority::P1, taken.enqueued_ns, |env| {
                    if matches!(env.event, Event::ProcessSpawn { .. }) {
                        overtaken.push(env.event.clone());
                    }
                });
        }
        drop(st);
        inner.room[taken.priority.index()].add_permits(1);
        if floods {
            inner.p0_flood_room.add_permits(1);
        }
        self.in_flight = Some((taken.priority.index(), taken.enqueued_ns, taken.item.ts_ns));
        Some(Received {
            envelope: taken.item,
            overtaken,
        })
    }

    /// The stop (review #471 M3): no event is taken any more, a send is
    /// refused from now on (a pump waiting for room is woken and ends, as
    /// at a closed channel), and the events still queued are counted —
    /// `[P0, P1, P2, P3]`, for [`BusLosses::stop`] to sign.
    pub fn close(&mut self) -> [u64; QUEUES] {
        self.decided();
        self.inner.closed.store(true, Ordering::Release);
        for room in &self.inner.room {
            room.close();
        }
        self.inner.p0_flood_room.close();
        let st = self.inner.state.lock();
        Priority::ALL.map(|p| st.queues.len(p) as u64)
    }

    /// The event last taken is decided: its latency, queue to decision, is
    /// counted, and (R12b, stage 5) its delay from its record's kernel
    /// time against its class's budget. Taking the next event counts it
    /// too.
    pub fn decided(&mut self) {
        if let Some((i, enqueued, ts_ns)) = self.in_flight.take() {
            let mono = monotonic_ns();
            let mut st = self.inner.state.lock();
            let now = self.inner.now_ns();
            st.latency[i].record_ns(now.saturating_sub(enqueued));
            st.delay[i].record(ts_ns, mono, DECISION_BUDGET_NS[i]);
        }
    }

    /// The bus's counts.
    pub fn stats(&self) -> BusStats {
        BusStats(Arc::clone(&self.inner))
    }
}

/// The bus's counts, for the status and the loss recorder; clones share
/// the bus.
#[derive(Clone)]
pub struct BusStats(Arc<Inner>);

impl std::fmt::Debug for BusStats {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("BusStats").field(&self.snapshot()).finish()
    }
}

/// One queue's counts since the agent started.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QueueSnapshot {
    pub priority: Priority,
    pub capacity: u64,
    /// What a full queue does, as `nn-admin status` shows it.
    pub when_full: String,
    pub stats: QueueStats,
    /// Sends that waited for room, and the longest such wait (µs).
    pub waited: u64,
    pub send_wait_max_us: u64,
    /// The longest wait in the queue in the last sample window and the one
    /// running (µs; review #471 B2 — `stats.max_wait_ns` is since boot).
    pub recent_max_wait_us: u64,
    /// Queue → decision, microseconds: p50, p99, the largest; `None` before
    /// the first decision.
    pub latency_p50_us: Option<u64>,
    pub latency_p99_us: Option<u64>,
    pub latency_max_us: Option<u64>,
    /// Decisions counted.
    pub decided: u64,
    /// Repeated denials counted into the one sent (P0; 0 elsewhere —
    /// second review of #471, R-A).
    pub coalesced: u64,
    /// R12b, stage 5: the decision's delay from its record's kernel time —
    /// the class's budget (µs), the decisions timed, those with no record
    /// time, p50, p99, the largest (µs), and those over the budget.
    pub delay_budget_us: u64,
    pub delay_timed: u64,
    pub delay_untimed: u64,
    pub delay_p50_us: Option<u64>,
    pub delay_p99_us: Option<u64>,
    pub delay_max_us: Option<u64>,
    pub over_budget: u64,
    /// R12b, C3: the floods of P0 counted past their uid's cap, not queued
    /// (P0; 0 elsewhere).
    pub capped: u64,
}

impl BusStats {
    /// Every queue's counts, P0 first.
    pub fn snapshot(&self) -> Vec<QueueSnapshot> {
        let coalesced = self.0.coalescer.lock().total;
        let capped = self.0.cap.lock().total();
        let early = self.0.opens_dropped_early.load(Ordering::Relaxed);
        let st = self.0.state.lock();
        Priority::ALL
            .iter()
            .map(|&p| {
                let i = p.index();
                let h = &st.latency[i];
                let d = &st.delay[i];
                let mut stats = st.queues.stats(p);
                if p == Priority::P2 {
                    stats.dropped += early;
                }
                QueueSnapshot {
                    priority: p,
                    capacity: st.queues.capacity(p) as u64,
                    when_full: when_full_text(p, self.0.specs[i].when_full, self.0.open_cap),
                    stats,
                    waited: st.waited[i],
                    send_wait_max_us: st.send_wait_max_ns[i] / 1_000,
                    recent_max_wait_us: st.recent_max_wait_ns[i]
                        .max(st.queues.stats(p).window_max_wait_ns)
                        / 1_000,
                    latency_p50_us: h.quantile_us(0.50),
                    latency_p99_us: h.quantile_us(0.99),
                    latency_max_us: (h.count() > 0).then(|| h.max_us()),
                    decided: h.count(),
                    coalesced: if p == Priority::P0 { coalesced } else { 0 },
                    delay_budget_us: DECISION_BUDGET_NS[i] / 1_000,
                    delay_timed: d.delay.count(),
                    delay_untimed: d.untimed,
                    delay_p50_us: d.delay.quantile_us(0.50),
                    delay_p99_us: d.delay.quantile_us(0.99),
                    delay_max_us: (d.delay.count() > 0).then(|| d.delay.max_us()),
                    over_budget: d.over_budget,
                    capped: if p == Priority::P0 { capped } else { 0 },
                }
            })
            .collect()
    }

    /// The loss recorder's sample: each queue's longest wait since the
    /// last one becomes the "recent" one the status shows.
    fn roll_window(&self) {
        let mut st = self.0.state.lock();
        for p in Priority::ALL {
            let w = st.queues.take_window_max_wait(p);
            st.recent_max_wait_ns[p.index()] = w;
        }
    }

    /// R12b: the names of the bus's sources, by id.
    pub fn sources(&self) -> Vec<&'static str> {
        self.0.sources.lock().clone()
    }
}

/// A queue's full behaviour for the status: its class's, with the events
/// that wait for room instead (P0's rare sources, P2's other file events)
/// and the opens' part of P2.
fn when_full_text(p: Priority, w: WhenFull, open_cap: usize) -> String {
    match (p, w) {
        (Priority::P0, WhenFull::Wait { .. }) => format!(
            "{} for FsProtectDenial (repeats within 1 s coalesced); other tamper events wait, \
             {} slots kept from denials and bpf() calls; denials and bpf() calls past {} per uid \
             a second counted, not queued",
            w.describe(),
            core_bus::P0_RESERVE,
            core_bus::FLOOD_CAP_PER_UID
        ),
        (Priority::P2, WhenFull::DropNew) => format!(
            "drop the new FileOpen (past {open_cap} opens queued); write-opens of CRITICAL/PERSIST \
             files and other file events wait"
        ),
        _ => w.describe(),
    }
}

// ── the loss counters by stage ───────────────────────────────────────

/// One stage of an event's path where it can be lost (plan §3.4), as the
/// status shows it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StageCount {
    pub stage: u8,
    pub name: &'static str,
    /// Lost there since boot; `None`: not counted yet.
    pub total: Option<u64>,
    /// Where it is counted, or the lot that will count it.
    pub source: &'static str,
}

/// The `RING_DROPS` slots that count records a kernel budget held back
/// before the ring (stage 2), not a full ring (stage 1).
const BUDGET_SLOTS: [u32; 4] = [
    common::ring_drops::ring_slot::DNS_RATE,
    common::ring_drops::ring_slot::LISTEN_RATE,
    common::ring_drops::ring_slot::IOURING_RATE,
    common::ring_drops::ring_slot::TASK_DENIAL_RATE,
];

/// The eight stages with their counts: 1 to 3 as the kernel's and the
/// pumps' counters have them (`ring_drops`, `reject`), 4 the bus's queues
/// (`queues`: the drops), 5 the decisions later than their class's budget
/// from their record's kernel time (R12b, lab PR 269: `queues`' over
/// budget); 6 to 8 not counted yet — R12c the response and the evidence
/// writer's queues and the signed `telemetry_loss` rows, R15 the export.
pub fn loss_stages(
    ring: &[(&'static str, u64)],
    rejected: u64,
    queues: &[QueueSnapshot],
) -> Vec<StageCount> {
    let budget: Vec<&str> = BUDGET_SLOTS
        .iter()
        .map(|&s| common::ring_drops::RING_DROP_NAMES[s as usize])
        .collect();
    let (mut kernel_ring, mut kernel_budget) = (0u64, 0u64);
    for (name, n) in ring {
        if budget.contains(name) {
            kernel_budget += n;
        } else {
            kernel_ring += n;
        }
    }
    let bus: u64 = queues.iter().map(|q| q.stats.dropped).sum();
    let late: u64 = queues.iter().map(|q| q.over_budget).sum();
    vec![
        StageCount {
            stage: 1,
            name: "kernel ring",
            total: Some(kernel_ring),
            source: "RING_DROPS: a ring or map full",
        },
        StageCount {
            stage: 2,
            name: "kernel budget",
            total: Some(kernel_budget),
            source: "RING_DROPS dns_rate, listen_rate, io_uring_rate, task_denial_rate",
        },
        StageCount {
            stage: 3,
            name: "decode",
            total: Some(rejected),
            source: "RejectThrottle: malformed records",
        },
        StageCount {
            stage: 4,
            name: "bus queue",
            total: Some(bus),
            source: "the event bus, per queue",
        },
        StageCount {
            stage: 5,
            name: "decision delay",
            total: Some(late),
            source: "decisions later than their class's budget, from the record's kernel time",
        },
        StageCount {
            stage: 6,
            name: "response queue",
            total: None,
            source: "not counted yet: R12c",
        },
        StageCount {
            stage: 7,
            name: "evidence writer queue",
            total: None,
            source: "not counted yet: R12c",
        },
        StageCount {
            stage: 8,
            name: "export",
            total: None,
            source: "not counted yet: R12c, the telemetry_loss rows; R15, the export",
        },
    ]
}

// ── the loss recorder ────────────────────────────────────────────────

/// The loss recorder's bindings, late (the bus starts with the eBPF load,
/// before the audit log and the posture exist; the start binds them where
/// it binds the ring-drop sampler's). Clones share them.
#[derive(Clone, Default)]
pub struct BusLosses {
    audit: LateAudit,
    posture: Arc<OnceLock<PostureSink>>,
    recorder: Arc<Mutex<LossRecorder>>,
    held: Arc<OnceLock<HeldSink>>,
}

/// Where the denials the bus coalesced or capped are counted as the
/// records NN-L-AT-001 held back (the third review's C5): `(uid, count,
/// (subject key, subject text))`.
pub type HeldSink = Arc<dyn Fn(u32, u64, (String, String)) + Send + Sync>;

impl BusLosses {
    /// R12b, the third review's C5: count the denials the bus did not queue
    /// — coalesced into one queued, or capped (C3) — as held records of the
    /// rule that records every denial, at each sample: the rule's next
    /// record of the uid carries them (`suppressed_before`), and its signed
    /// `detections_held` rows count them, so a reader of the rule's records
    /// alone sees every attempt.
    pub fn bind_held(&self, sink: HeldSink) {
        let _ = self.held.set(sink);
    }

    /// [`Self::bind_held`] on the process-wide record budget
    /// ([`nn_core::detection_budget`]) for `rule` (NN-L-AT-001's id).
    pub fn bind_held_budget(&self, rule: &'static str) {
        self.bind_held(Arc::new(move |uid, n, sample| {
            nn_core::detection_budget::count_coalesced_many(rule, uid, n, || sample)
        }));
    }

    /// Hand the signed audit log to the recorder.
    pub fn bind_audit_log(&self, log: Option<AuditHandle>) {
        self.audit.bind(log);
    }

    /// Hand the posture (and the trusted-installer window) to the recorder,
    /// so a queue of security events that drops raises ALERTED.
    pub fn bind_posture(
        &self,
        posture: crate::posture::PostureMachine,
        installer: Option<Arc<crate::anti_tamper::trusted_installer::TrustedInstallerOverride>>,
    ) {
        let _ = self.posture.set(PostureSink { posture, installer });
    }

    /// Every drop not yet in a signed row is signed now, whatever its
    /// queue's window.
    pub fn flush(&self, stats: &BusStats) {
        record(stats, self, Sample::Flush);
    }

    /// At the stop (review #471 M3), the receiver closed
    /// ([`BusReceiver::close`]): the events it left queued (`queued`, P0
    /// first) are counted in a signed `event_bus_stop` row and WARNed —
    /// never judged, never silent — and every drop is signed
    /// ([`Self::flush`]). `false` when a row was due and could not be
    /// written (no audit log).
    pub fn stop(&self, stats: &BusStats, queued: [u64; QUEUES]) -> bool {
        self.flush(stats);
        if queued.iter().all(|&n| n == 0) {
            return true;
        }
        warn!(
            p0 = queued[0],
            p1 = queued[1],
            p2 = queued[2],
            p3 = queued[3],
            "event bus: the agent stops with events queued — they are not judged"
        );
        sign_stop(&self.audit, queued)
    }
}

/// The queues whose drops are security events lost (the posture's
/// `TelemetryLoss`): every queue — the exec, file-open, FIM and tamper
/// rings' events, security rings whose kernel drops raised it, and (review
/// #471 A2) the network's, NET-001's connects and the chains' egress.
const SECURITY_QUEUES: [Priority; QUEUES] = Priority::ALL;

/// What a queue must drop in a sample to raise `TelemetryLoss`: any tamper
/// event; past [`ring_drops::TELEMETRY_LOSS_THRESHOLD`] for the others.
const fn loss_threshold(p: Priority) -> u64 {
    match p {
        Priority::P0 => 0,
        _ => ring_drops::TELEMETRY_LOSS_THRESHOLD,
    }
}

/// Why the recorder samples.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Sample {
    /// Its tick, every [`SAMPLE_SECS`].
    Tick,
    /// A P0 drop, ahead of the tick: P0 alone.
    P0Drop,
    /// The stop: every queue's row is due.
    Flush,
}

/// What one sample decided (pure: [`LossRecorder::sample`]).
#[derive(Debug, Default, PartialEq, Eq)]
pub struct SampleOutcome {
    /// `(queue, dropped this sample, total)` to WARN about.
    pub warn: Vec<(Priority, u64, u64)>,
    /// `(queue, dropped since its last row, total)` to sign.
    pub rows: Vec<(Priority, u64, u64)>,
    /// `(queue, dropped this sample)` past the threshold, for the posture.
    pub telemetry_loss: Vec<(Priority, u64)>,
}

/// The recorder's memory between samples.
#[derive(Debug, Default)]
pub struct LossRecorder {
    seen: [u64; QUEUES],
    signed: [u64; QUEUES],
    last_row: [Option<Instant>; QUEUES],
    /// R12b, stage 5: the decisions over budget seen at the last sample.
    over_seen: [u64; QUEUES],
}

impl LossRecorder {
    /// One sample of the queues' drop totals (`dropped[i]`, P0 first) at
    /// `now`: what to WARN, sign and raise ([`Sample::Flush`]: every
    /// queue's row is due; [`Sample::P0Drop`]: P0 alone). Each row written
    /// is told back ([`Self::row_written`]); one that could not be (no
    /// audit log yet) is tried again at the next sample, with what accrued
    /// since.
    pub fn sample(&mut self, dropped: [u64; QUEUES], now: Instant, why: Sample) -> SampleOutcome {
        let mut out = SampleOutcome::default();
        let flush = why == Sample::Flush;
        for p in Priority::ALL {
            if why == Sample::P0Drop && p != Priority::P0 {
                continue;
            }
            let i = p.index();
            let (total, delta) = (dropped[i], dropped[i].saturating_sub(self.seen[i]));
            self.seen[i] = self.seen[i].max(total);
            if delta > 0 {
                out.warn.push((p, delta, total));
                if SECURITY_QUEUES.contains(&p) && delta > loss_threshold(p) {
                    out.telemetry_loss.push((p, delta));
                }
            }
            let unsigned = total.saturating_sub(self.signed[i]);
            let due = p == Priority::P0
                || flush
                || self.last_row[i].is_none_or(|t| {
                    now.duration_since(t) >= Duration::from_secs(AUDIT_WINDOW_SECS)
                });
            if unsigned > 0 && due {
                out.rows.push((p, unsigned, total));
            }
        }
        out
    }

    /// The row of `p` up to `total` was signed at `now`.
    pub fn row_written(&mut self, p: Priority, total: u64, now: Instant) {
        let i = p.index();
        self.signed[i] = self.signed[i].max(total);
        self.last_row[i] = Some(now);
    }

    /// R12b, stage 5: the queues whose decisions over budget grew since the
    /// last call (`over[i]`, P0 first) — `(queue, new, total)` to WARN
    /// about.
    pub fn late(&mut self, over: [u64; QUEUES]) -> Vec<(Priority, u64, u64)> {
        let mut out = Vec::new();
        for p in Priority::ALL {
            let i = p.index();
            let new = over[i].saturating_sub(self.over_seen[i]);
            self.over_seen[i] = self.over_seen[i].max(over[i]);
            if new > 0 {
                out.push((p, new, over[i]));
            }
        }
        out
    }
}

/// Run one sample: WARN, sign, raise.
fn record(stats: &BusStats, losses: &BusLosses, why: Sample) {
    let mut rec = losses.recorder.lock();
    if why == Sample::Tick {
        stats.roll_window();
    }
    let snap = stats.snapshot();
    let mut dropped = [0u64; QUEUES];
    for q in &snap {
        dropped[q.priority.index()] = q.stats.dropped;
    }
    let now = Instant::now();
    let out = rec.sample(dropped, now, why);
    for (p, d, total) in &out.warn {
        let q = &snap[p.index()];
        warn!(
            queue = p.label(),
            class = p.name(),
            dropped_since_last_sample = d,
            total,
            capacity = q.capacity,
            when_full = %q.when_full,
            "event bus: events DROPPED — the queue was full; events of this class were lost"
        );
    }
    for (p, d, total) in out.rows {
        let q = &snap[p.index()];
        if sign_drop(&losses.audit, q, d, total) {
            rec.row_written(p, total, now);
        }
    }
    if !out.telemetry_loss.is_empty() {
        let lost: Vec<(String, u64)> = out
            .telemetry_loss
            .iter()
            .map(|(p, d)| (format!("{} {}", p.label(), p.name()), *d))
            .collect();
        let lost: Vec<(&str, u64)> = lost.iter().map(|(n, d)| (n.as_str(), *d)).collect();
        ring_drops::raise_loss(&losses.posture, &lost, "event bus");
    }
    if why != Sample::P0Drop {
        // R12b, stage 5: the decisions later than their class allows, said
        // once a sample (counted in the status and the stages)
        let mut over = [0u64; QUEUES];
        for q in &snap {
            over[q.priority.index()] = q.over_budget;
        }
        for (p, new, total) in rec.late(over) {
            let q = &snap[p.index()];
            warn!(
                queue = p.label(),
                class = p.name(),
                late_since_last_sample = new,
                total,
                budget_ms = q.delay_budget_us / 1_000,
                max_ms = q.delay_max_us.unwrap_or(0) / 1_000,
                "event bus: decisions LATE — judged later than their class's budget after the \
                 kernel recorded them"
            );
        }
        sign_coalesced(stats, losses);
        sign_capped(stats, losses);
    }
}

/// Second review of #471, R-A: the denials coalesced since the last row,
/// signed — per key (pid, operation, inode) the repeats and their first
/// and last time, the most repeated first, the rest summed. Nothing while
/// no audit log is bound (they wait for the next sample).
fn sign_coalesced(stats: &BusStats, losses: &BusLosses) {
    let Some(log) = losses.audit.get() else {
        return;
    };
    let Pending {
        keys,
        evicted,
        evicted_held,
    } = stats.0.coalescer.lock().take_pending();
    let since: u64 = keys.iter().map(|(_, w)| w.repeats).sum::<u64>() + evicted;
    if since == 0 {
        return;
    }
    // C5 (R12b): the repeats are NN-L-AT-001's records held back, per uid
    if let Some(held) = losses.held.get() {
        for (k, w) in &keys {
            held(
                w.uid,
                w.repeats,
                (w.comm.clone(), held_text(&w.comm, k.pid)),
            );
        }
        for (uid, (n, text)) in &evicted_held {
            held(*uid, *n, (text.clone(), text.clone()));
        }
    }
    let named: Vec<serde_json::Value> = keys
        .iter()
        .take(COALESCED_ROW_KEYS)
        .map(|(k, w)| {
            serde_json::json!({
                "pid": k.pid,
                "operation": w.operation.to_string(),
                "target_dev": k.dev,
                "target_ino": k.ino,
                "repeats": w.repeats,
                "first_ns": w.first_ns,
                "last_ns": w.last_ns,
            })
        })
        .collect();
    let other: u64 = keys
        .iter()
        .skip(COALESCED_ROW_KEYS)
        .map(|(_, w)| w.repeats)
        .sum::<u64>()
        + evicted;
    let total = stats.0.coalescer.lock().total;
    let draft = crate::audit::AuditEntryDraft {
        op: COALESCED_AUDIT_OP.to_string(),
        extra: serde_json::json!({
            "queue": Priority::P0.label(),
            "event": "FsProtectDenial",
            "window_ms": COALESCE_WINDOW_NS / 1_000_000,
            "repeats_since_last_row": since,
            "total": total,
            "keys": named,
            "other_keys_repeats": other,
        }),
        key_fp: "agent-self".to_string(),
        cosigner_fps: Vec::new(),
        result: "detected".to_string(),
        client_pid: std::process::id(),
        client_uid: 0,
        client_comm: "northnarrow-agent".to_string(),
        client_exe: None,
    };
    if let Err(e) = log.lock().append(draft) {
        warn!(
            error = format!("{e:#}"),
            "event-bus coalesced audit entry failed"
        );
        // counted again at the next row, without their keys
        stats.0.coalescer.lock().evicted += since;
    }
}

/// R12b, the third review's C3: the floods of P0 counted past their uid's
/// cap since the last row, signed — per (kind, uid) the count, its first
/// and last time on the bus's clock, and the processes it names — and the
/// capped denials counted as NN-L-AT-001's held records (C5). Nothing
/// while no audit log is bound (they wait for the next sample).
fn sign_capped(stats: &BusStats, losses: &BusLosses) {
    let Some(log) = losses.audit.get() else {
        return;
    };
    let pending = stats.0.cap.lock().take_pending();
    if pending.is_empty() {
        return;
    }
    if let Some(held) = losses.held.get() {
        for c in pending.iter().filter(|c| c.kind == FloodKind::Denial) {
            let name = c
                .samples
                .first()
                .map_or_else(String::new, |s| held_text(&s.comm, s.pid));
            held(c.uid, c.count, (name.clone(), name));
        }
    }
    let since: u64 = pending.iter().map(|c| c.count).sum();
    let total = stats.0.cap.lock().total();
    for c in &pending {
        warn!(
            event = c.kind.name(),
            uid = c.uid,
            capped = c.count,
            cap_per_second = core_bus::FLOOD_CAP_PER_UID,
            "event bus: a flood of tamper events CAPPED for this uid — counted and signed, not \
             judged one by one"
        );
    }
    let floods: Vec<serde_json::Value> = pending
        .iter()
        .map(|c| {
            serde_json::json!({
                "event": c.kind.name(),
                "uid": c.uid,
                "capped": c.count,
                "first_ns": c.first_ns,
                "last_ns": c.last_ns,
                "processes": c.samples.iter().map(|s| serde_json::json!({
                    "pid": s.pid,
                    "comm": s.comm,
                    "what": s.what,
                })).collect::<Vec<_>>(),
            })
        })
        .collect();
    let draft = crate::audit::AuditEntryDraft {
        op: CAPPED_AUDIT_OP.to_string(),
        extra: serde_json::json!({
            "queue": Priority::P0.label(),
            "cap_per_uid_per_second": core_bus::FLOOD_CAP_PER_UID,
            "capped_since_last_row": since,
            "total": total,
            "floods": floods,
        }),
        key_fp: "agent-self".to_string(),
        cosigner_fps: Vec::new(),
        result: "detected".to_string(),
        client_pid: std::process::id(),
        client_uid: 0,
        client_comm: "northnarrow-agent".to_string(),
        client_exe: None,
    };
    if let Err(e) = log.lock().append(draft) {
        warn!(
            error = format!("{e:#}"),
            "event-bus capped audit entry failed — the counts stay in the status total"
        );
    }
}

/// The signed row of a queue's drops; `false` when it could not be written
/// (no audit log bound yet, or the append failed).
fn sign_drop(audit: &LateAudit, q: &QueueSnapshot, dropped: u64, total: u64) -> bool {
    let Some(log) = audit.get() else {
        return false;
    };
    let draft = crate::audit::AuditEntryDraft {
        op: AUDIT_OP.to_string(),
        extra: serde_json::json!({
            "queue": q.priority.label(),
            "class": q.priority.name(),
            "dropped_since_last_row": dropped,
            "total": total,
            "capacity": q.capacity,
            "max_depth": q.stats.max_depth,
            "when_full": q.when_full,
        }),
        key_fp: "agent-self".to_string(),
        cosigner_fps: Vec::new(),
        result: "detected".to_string(),
        client_pid: std::process::id(),
        client_uid: 0,
        client_comm: "northnarrow-agent".to_string(),
        client_exe: None,
    };
    match log.lock().append(draft) {
        Ok(_) => true,
        Err(e) => {
            warn!(
                error = format!("{e:#}"),
                "event-bus drop audit entry failed"
            );
            false
        }
    }
}

/// The signed row of the events left queued at the stop.
fn sign_stop(audit: &LateAudit, queued: [u64; QUEUES]) -> bool {
    let Some(log) = audit.get() else {
        return false;
    };
    let per_queue: serde_json::Map<String, serde_json::Value> = Priority::ALL
        .iter()
        .map(|p| (p.label().to_string(), serde_json::json!(queued[p.index()])))
        .collect();
    let draft = crate::audit::AuditEntryDraft {
        op: STOP_AUDIT_OP.to_string(),
        extra: serde_json::json!({
            "queued_at_stop": per_queue,
            "total": queued.iter().sum::<u64>(),
            "judged": false,
        }),
        key_fp: "agent-self".to_string(),
        cosigner_fps: Vec::new(),
        result: "detected".to_string(),
        client_pid: std::process::id(),
        client_uid: 0,
        client_comm: "northnarrow-agent".to_string(),
        client_exe: None,
    };
    match log.lock().append(draft) {
        Ok(_) => true,
        Err(e) => {
            warn!(
                error = format!("{e:#}"),
                "event-bus stop audit entry failed"
            );
            false
        }
    }
}

/// The loss recorder: every [`SAMPLE_SECS`], the queues' drops WARNed,
/// signed and raised; a P0 drop ahead of that, at most once per
/// [`P0_ROW_EVERY`] (review #471 M3: an agent that crashes leaves at most
/// that much of P0's drops unsigned, not a sample's).
pub fn spawn_loss_recorder(stats: BusStats, losses: BusLosses) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_secs(SAMPLE_SECS));
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        tick.tick().await;
        let inner = Arc::clone(&stats.0);
        loop {
            let why = tokio::select! {
                _ = tick.tick() => Sample::Tick,
                () = inner.p0_dropped.notified() => Sample::P0Drop,
            };
            // Review #471 B4: the sample can scan /proc (the posture's
            // package-transaction exemption) and append to the audit log —
            // off the runtime's workers.
            // A panic still ends the recorder (the multiplexer's task check
            // stops the agent, as for a dead pump); a cancel is the stop.
            let (s, l) = (stats.clone(), losses.clone());
            if let Err(e) = tokio::task::spawn_blocking(move || record(&s, &l, why)).await {
                if e.is_panic() {
                    std::panic::resume_unwind(e.into_panic());
                }
                return;
            }
            debug!(?why, "event-bus loss sample");
            if why == Sample::P0Drop {
                tokio::time::sleep(P0_ROW_EVERY).await;
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::AuditLog;

    fn open(pid: u32) -> Event {
        Event::FileOpen {
            pid,
            uid: 1000,
            gid: 1000,
            comm: "flood".into(),
            filename: "/etc/passwd".into(),
            flags: 0,
            timestamp_ns: 0,
            path_from_user: false,
            kernel_class: 0,
        }
    }

    fn denial(pid: u32) -> Event {
        Event::FsProtectDenial {
            pid,
            uid: 0,
            comm: "rm".into(),
            target_dev: 1,
            target_ino: 2,
            operation: nn_model::FsProtectOperation::Unlink,
            timestamp_ns: 0,
        }
    }

    fn spawn(pid: u32) -> Event {
        Event::ProcessSpawn {
            pid,
            ppid: 1,
            uid: 0,
            gid: 0,
            comm: "sh".into(),
            filename: "/bin/sh".into(),
            timestamp_ns: u64::from(pid),
            argv: Vec::new(),
            parent_comm: String::new(),
            parent_start_ns: 0,
            start_ns: u64::from(pid),
            parent_is_kthread: false,
            exe: Default::default(),
            argv_truncated: false,
            filename_truncated: false,
            stdio: Default::default(),
        }
    }

    fn pid_of(e: &Event) -> u32 {
        match e {
            Event::FileOpen { pid, .. }
            | Event::FsProtectDenial { pid, .. }
            | Event::ProcessSpawn { pid, .. } => *pid,
            _ => 0,
        }
    }

    /// Review #471: a bus test that hangs fails instead (the M3 mutation
    /// hung one forever).
    async fn within<F: std::future::Future>(f: F) -> F::Output {
        tokio::time::timeout(Duration::from_secs(30), f)
            .await
            .expect("a bus test hung")
    }

    fn module_load(pid: u32) -> Event {
        Event::ModuleLoad {
            method: nn_model::ModuleLoadMethod::Finit,
            loader_pid: pid,
            loader_uid: 0,
            loader_comm: "insmod".into(),
            parent_comm: "sh".into(),
            parent_is_kthread: false,
            path: Some("/tmp/rk.ko".into()),
            timestamp_ns: 0,
        }
    }

    fn audit_log(dir: &std::path::Path) -> (AuditHandle, std::path::PathBuf) {
        let key = crate::audit::AgentSigningKey::load_or_bootstrap(&dir.join("agent.key")).unwrap();
        let path = dir.join("audit.log");
        let log = AuditLog::open(&path, key, [0u8; 16]).unwrap();
        (Arc::new(Mutex::new(log)), path)
    }

    /// The rows of `op` in the log at `path`, the chain verified.
    fn rows(dir: &std::path::Path, path: &std::path::Path, op: &str) -> Vec<serde_json::Value> {
        let key = crate::audit::AgentSigningKey::load_or_bootstrap(&dir.join("agent.key")).unwrap();
        let text = std::fs::read_to_string(path).unwrap_or_default();
        let entries: Vec<crate::audit::AuditEntry> = text
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect();
        crate::audit::verify_chain(&entries, &key.verifying_key()).expect("the rows verify");
        entries
            .into_iter()
            .filter(|e| e.op == op)
            .map(|e| e.extra)
            .collect()
    }

    fn small(wait_ms: u64) -> [QueueSpec; QUEUES] {
        let mut s = SPECS;
        for q in &mut s {
            q.capacity = 2;
        }
        s[0].when_full = WhenFull::Wait {
            max_ns: wait_ms * 1_000_000,
        };
        s[1].when_full = WhenFull::Wait {
            max_ns: wait_ms * 1_000_000,
        };
        s
    }

    /// EXP-13 in miniature: a full file queue drops new opens at once and
    /// never delays a tamper event, which is taken first.
    #[tokio::test]
    async fn a_flood_of_opens_neither_blocks_nor_hides_a_denial() {
        within(async {
            let (tx, mut rx) = channel_with(small(50));
            for i in 0..100 {
                tx.send(open(i)).await.unwrap();
            }
            let started = Instant::now();
            tx.send(denial(7)).await.unwrap();
            assert!(
                started.elapsed() < Duration::from_millis(20),
                "never waited"
            );
            let first = rx.try_recv().unwrap();
            assert_eq!(pid_of(&first.envelope.event), 7, "the denial first");
            let snap = rx.stats().snapshot();
            assert_eq!(snap[0].stats.enqueued, 1);
            assert_eq!(snap[0].stats.dropped, 0);
            assert_eq!(snap[2].stats.enqueued, 2);
            assert_eq!(snap[2].stats.dropped, 98, "the new opens dropped, counted");
            let rest: Vec<u32> =
                std::iter::from_fn(|| rx.try_recv().map(|r| pid_of(&r.envelope.event))).collect();
            assert_eq!(rest, [0, 1], "FIFO: the first two opens");
        })
        .await
    }

    /// A full P0 waits for room at most its wait, then drops and counts; a
    /// slot freed meanwhile takes the waiting event.
    #[tokio::test]
    async fn a_full_tamper_queue_waits_then_drops() {
        within(async {
            let (tx, mut rx) = channel_with(small(30));
            tx.send(denial(1)).await.unwrap();
            tx.send(denial(2)).await.unwrap();
            let started = Instant::now();
            tx.send(denial(3)).await.unwrap();
            let waited = started.elapsed();
            assert!(waited >= Duration::from_millis(25), "{waited:?}");
            let snap = rx.stats().snapshot();
            assert_eq!((snap[0].stats.enqueued, snap[0].stats.dropped), (2, 1));
            // now one waits and a take frees its slot
            let tx2 = tx.clone();
            let waiter = tokio::spawn(async move { tx2.send(denial(4)).await });
            tokio::time::sleep(Duration::from_millis(5)).await;
            assert_eq!(pid_of(&rx.try_recv().unwrap().envelope.event), 1);
            waiter.await.unwrap().unwrap();
            let snap = rx.stats().snapshot();
            assert_eq!((snap[0].stats.enqueued, snap[0].stats.dropped), (3, 1));
            assert_eq!(snap[0].waited, 1);
            assert!(
                snap[0].send_wait_max_us >= 4_000,
                "{}",
                snap[0].send_wait_max_us
            );
            let rest: Vec<u32> =
                std::iter::from_fn(|| rx.try_recv().map(|r| pid_of(&r.envelope.event))).collect();
            assert_eq!(rest, [2, 4]);
        })
        .await
    }

    /// A file event other than an open waits for room (review 75), ahead of
    /// the opens that come after it.
    #[tokio::test]
    async fn a_drift_waits_for_room_ahead_of_new_opens() {
        within(async {
            let (tx, mut rx) = channel_with(small(30));
            tx.send(open(1)).await.unwrap();
            tx.send(open(2)).await.unwrap();
            let drift = Event::MassWrite {
                pid: 9,
                uid: 0,
                comm: "w".into(),
                count: 64,
                filename: "/srv/x".into(),
                timestamp_ns: 0,
                overwrites: true,
                cgroup_window: false,
            };
            let tx2 = tx.clone();
            let waiter = tokio::spawn(async move { tx2.send(drift).await });
            tokio::time::sleep(Duration::from_millis(5)).await;
            assert!(!waiter.is_finished(), "it waits");
            assert_eq!(pid_of(&rx.try_recv().unwrap().envelope.event), 1);
            tx.send(open(3)).await.unwrap(); // the freed slot is the drift's
            waiter.await.unwrap().unwrap();
            let order: Vec<Event> =
                std::iter::from_fn(|| rx.try_recv().map(|r| r.envelope.event)).collect();
            assert!(matches!(order[0], Event::FileOpen { pid: 2, .. }));
            assert!(matches!(order[1], Event::MassWrite { .. }));
            assert_eq!(order.len(), 2, "the open after it was dropped");
            assert_eq!(rx.stats().snapshot()[2].stats.dropped, 1);
        })
        .await
    }

    /// A tamper event taken ahead of queued execs brings the older ones
    /// along, each once.
    #[tokio::test]
    async fn a_tamper_event_hands_over_the_execs_it_overtakes() {
        within(async {
            let (tx, mut rx) = channel();
            tx.send(spawn(10)).await.unwrap();
            tx.send(spawn(11)).await.unwrap();
            tx.send(denial(10)).await.unwrap();
            tx.send(spawn(12)).await.unwrap();
            let r = rx.recv().await.unwrap();
            assert_eq!(pid_of(&r.envelope.event), 10);
            assert!(matches!(r.envelope.event, Event::FsProtectDenial { .. }));
            let handed: Vec<u32> = r.overtaken.iter().map(pid_of).collect();
            assert_eq!(handed, [10, 11], "the execs before it, not the one after");
            let rest: Vec<(u32, usize)> = std::iter::from_fn(|| {
                rx.try_recv()
                    .map(|r| (pid_of(&r.envelope.event), r.overtaken.len()))
            })
            .collect();
            assert_eq!(rest, [(10, 0), (11, 0), (12, 0)]);
        })
        .await
    }

    /// Under concurrent senders of every class and a slow receiver: every
    /// event sent is taken or counted as dropped, never both and never lost;
    /// inside a class each sender's events keep their order; a tamper event
    /// is never dropped while its wait allows the receiver to free a slot.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_senders_keep_each_class_fifo_and_account_for_every_event() {
        within(async {
            let mut specs = SPECS;
            for (q, c) in specs.iter_mut().zip([64, 64, 128, 128]) {
                q.capacity = c;
            }
            let (tx, mut rx) = channel_with(specs);
            const PER: u32 = 3_000;
            let mut senders = Vec::new();
            for s in 0..4u32 {
                let tx = tx.clone();
                senders.push(tokio::spawn(async move {
                    for i in 0..PER {
                        let seq = s * 1_000_000 + i;
                        let e = match i % 4 {
                            0 => denial(seq),
                            1 => spawn(seq),
                            2 => open(seq),
                            _ => Event::NetListener(nn_model::telemetry::NetListenerEvent {
                                timestamp_ns: 0,
                                family: 2,
                                bind_addr: std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
                                bind_port: 1,
                                proto: 6,
                                pid: seq,
                                uid: 0,
                                comm: String::new(),
                                exe: None,
                            }),
                        };
                        tx.send(e).await.unwrap();
                    }
                }));
            }
            drop(tx);
            let mut last: std::collections::HashMap<(usize, u32), u32> = Default::default();
            let mut taken = [0u64; QUEUES];
            while let Some(r) = rx.recv().await {
                let (p, pid) = match &r.envelope.event {
                    Event::NetListener(l) => (Priority::P3, l.pid),
                    e => (Priority::of_event(e), pid_of(e)),
                };
                let (sender, i) = (pid / 1_000_000, pid % 1_000_000);
                if let Some(prev) = last.insert((p.index(), sender), i) {
                    assert!(prev < i, "{p:?} sender {sender}: {prev} then {i}");
                }
                taken[p.index()] += 1;
                if taken.iter().sum::<u64>() % 97 == 0 {
                    tokio::time::sleep(Duration::from_micros(200)).await;
                }
            }
            for h in senders {
                h.await.unwrap();
            }
            let snap = rx.stats().snapshot();
            for q in &snap {
                let i = q.priority.index();
                assert_eq!(q.stats.enqueued, taken[i], "{:?}", q.priority);
                assert_eq!(
                    q.stats.enqueued + q.stats.dropped,
                    u64::from(4 * PER / 4),
                    "{:?}: every event queued or dropped",
                    q.priority
                );
                assert_eq!(q.stats.depth, 0);
            }
            assert_eq!(
                snap[0].stats.dropped, 0,
                "P0 waits 50 ms; the receiver frees slots well within it"
            );
        })
        .await
    }

    /// The receiver ends once every sender is gone; senders fail once the
    /// receiver is.
    #[tokio::test]
    async fn the_ends_close_each_other() {
        within(async {
            let (tx, mut rx) = channel();
            tx.send(open(1)).await.unwrap();
            drop(tx);
            assert!(rx.recv().await.is_some());
            assert!(rx.recv().await.is_none());
            let (tx, rx) = channel();
            drop(rx);
            assert!(tx.send(open(1)).await.is_err());
        })
        .await
    }

    /// A decision's latency is counted at the next take, or when said.
    #[tokio::test]
    async fn decisions_are_timed_per_queue() {
        within(async {
            let (tx, mut rx) = channel();
            tx.send(denial(1)).await.unwrap();
            tx.send(open(2)).await.unwrap();
            rx.try_recv().unwrap();
            rx.try_recv().unwrap(); // the denial's decision ends here
            rx.decided();
            let snap = rx.stats().snapshot();
            assert_eq!((snap[0].decided, snap[2].decided), (1, 1));
            assert!(snap[0].latency_p50_us.is_some());
            assert_eq!(snap[1].latency_p50_us, None);
        })
        .await
    }

    /// The stages: the ring drops split into full rings and budgets, the
    /// decoder's, the bus's, the late decisions (R12b), and 6 to 8 not
    /// counted.
    #[test]
    fn the_stages_split_the_kernel_s_drops_and_name_the_rest() {
        let (tx, rx) = channel_with(small(1));
        drop(tx);
        let mut queues = rx.stats().snapshot();
        queues[2].stats.dropped = 7;
        queues[0].stats.dropped = 1;
        let ring = [
            ("fs_protect", 2u64),
            ("dns_rate", 5),
            ("task_denial_rate", 1),
            ("open_sensor", 3),
        ];
        let st = loss_stages(&ring, 4, &queues);
        let totals: Vec<(u8, Option<u64>)> = st.iter().map(|s| (s.stage, s.total)).collect();
        assert_eq!(
            totals,
            [
                (1, Some(5)),
                (2, Some(6)),
                (3, Some(4)),
                (4, Some(8)),
                (5, Some(0)),
                (6, None),
                (7, None),
                (8, None)
            ]
        );
        assert!(st[4].source.contains("budget") && st[5].source.contains("R12c"));
        queues[1].over_budget = 3;
        queues[3].over_budget = 2;
        assert_eq!(
            loss_stages(&ring, 4, &queues)[4].total,
            Some(5),
            "the late decisions"
        );
    }

    /// The recorder: a WARN for each sample with drops; P0 signed at once,
    /// every drop in a row; the other queues at most once per window, the
    /// row then carrying everything since the previous one; any P0 drop
    /// raises, the other queues past the threshold — the network's too
    /// (review #471 A2).
    #[test]
    fn the_recorder_signs_every_drop() {
        let mut rec = LossRecorder::default();
        let t0 = Instant::now();
        let out = rec.sample([3, 0, 100, 5], t0, Sample::Tick);
        assert_eq!(out.warn.len(), 3);
        assert_eq!(
            out.rows,
            [
                (Priority::P0, 3, 3),
                (Priority::P2, 100, 100),
                (Priority::P3, 5, 5)
            ]
        );
        assert_eq!(out.telemetry_loss, [(Priority::P0, 3), (Priority::P2, 100)]);
        for (p, _, total) in &out.rows {
            rec.row_written(*p, *total, t0);
        }
        let t1 = t0 + Duration::from_secs(10);
        let out = rec.sample([4, 0, 130, 5], t1, Sample::Tick);
        assert_eq!(out.rows, [(Priority::P0, 1, 4)], "P2 waits for its window");
        rec.row_written(Priority::P0, 4, t1);
        // an unwritten row (no audit log) is tried again with what accrued
        let t2 = t1 + Duration::from_secs(AUDIT_WINDOW_SECS);
        let out = rec.sample([6, 0, 130, 9], t2, Sample::Tick);
        assert_eq!(
            out.rows,
            [
                (Priority::P0, 2, 6),
                (Priority::P2, 30, 130),
                (Priority::P3, 4, 9)
            ]
        );
        let out = rec.sample([6, 0, 130, 9], t2 + Duration::from_secs(10), Sample::Tick);
        assert_eq!(
            out.rows,
            [
                (Priority::P0, 2, 6),
                (Priority::P2, 30, 130),
                (Priority::P3, 4, 9)
            ],
            "again: none was written"
        );
        // a flush signs every queue whatever the window
        rec.row_written(Priority::P0, 6, t2);
        let out = rec.sample([6, 0, 130, 9], t2 + Duration::from_secs(20), Sample::Flush);
        assert_eq!(out.rows, [(Priority::P2, 30, 130), (Priority::P3, 4, 9)]);
        assert!(out.warn.is_empty());
        // a P0 drop ahead of the sample: P0 alone, the others left to theirs
        let t3 = t2 + Duration::from_secs(21);
        let out = rec.sample([7, 0, 200, 300], t3, Sample::P0Drop);
        assert_eq!(out.rows, [(Priority::P0, 1, 7)]);
        assert_eq!(out.warn, [(Priority::P0, 1, 7)]);
        assert_eq!(out.telemetry_loss, [(Priority::P0, 1)]);
        rec.row_written(Priority::P0, 7, t3);
        let out = rec.sample([7, 0, 200, 300], t3 + Duration::from_secs(1), Sample::Tick);
        assert_eq!(
            out.warn,
            [(Priority::P2, 70, 200), (Priority::P3, 291, 300)]
        );
        assert_eq!(
            out.telemetry_loss,
            [(Priority::P2, 70), (Priority::P3, 291)]
        );
    }

    /// Review #471 A2: an event of P2 or P3 taken by its share ahead of
    /// older execs brings them along too (the lineage learns an exec before
    /// any later event of its process is judged, whatever its class).
    #[tokio::test]
    async fn an_event_of_any_class_but_p1_hands_over_the_execs_it_overtakes() {
        within(async {
            let (tx, mut rx) = channel();
            for pid in [10, 11, 12] {
                tx.send(spawn(pid)).await.unwrap();
            }
            tx.send(open(5)).await.unwrap();
            let first = rx.try_recv().unwrap();
            assert_eq!(
                (pid_of(&first.envelope.event), first.overtaken.len()),
                (10, 0)
            );
            let second = rx.try_recv().unwrap();
            assert!(
                matches!(second.envelope.event, Event::FileOpen { pid: 5, .. }),
                "P2's turn"
            );
            let handed: Vec<u32> = second.overtaken.iter().map(pid_of).collect();
            assert_eq!(handed, [11, 12]);
            let rest: Vec<(u32, usize)> = std::iter::from_fn(|| {
                rx.try_recv()
                    .map(|r| (pid_of(&r.envelope.event), r.overtaken.len()))
            })
            .collect();
            assert_eq!(rest, [(11, 0), (12, 0)]);
        })
        .await
    }

    /// Review #471 M4c: the receiver itself teaches the process lineage the
    /// execs an event overtook — before the event is handed to the loop.
    #[tokio::test]
    async fn the_receiver_teaches_the_lineage_the_execs_an_event_overtook() {
        within(async {
            let tmp = tempfile::tempdir().unwrap();
            let lineage = AuthSessionTracker::new(tmp.path());
            let (tx, mut rx) = channel();
            tx.send(spawn(4242)).await.unwrap();
            tx.send(denial(4242)).await.unwrap();
            assert_eq!(lineage.image_path(4242), None);
            let r = rx.recv_with(Some(&lineage)).await.unwrap();
            assert!(matches!(r.envelope.event, Event::FsProtectDenial { .. }));
            assert_eq!(r.overtaken.len(), 1);
            assert_eq!(
                lineage.image_path(4242).as_deref(),
                Some("/bin/sh"),
                "the lineage knows the exec before the denial is judged"
            );
        })
        .await
    }

    fn sensor_flood(pid: u32) -> Event {
        Event::SensorFlood {
            source: nn_model::FloodSource::Listen,
            pid,
            uid: 1000,
            comm: "l".into(),
            exe: None,
            held: 10,
            uid_level: false,
            timestamp_ns: 0,
        }
    }

    /// Review #471 M1, second review R-D: P0 full of denials (a flooder
    /// refilling it) while the loop stands still — the rare tamper events
    /// find the reserve at once (a module load; a sensor flood, which the
    /// network drain carries between its flows: the drain does not stall);
    /// one past the reserve waits for room and arrives; the denials wait
    /// their 20 ms and are dropped.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_rare_tamper_event_outlasts_a_flood_of_denials() {
        within(async {
            let mut specs = small(20);
            specs[0].capacity = 8; // a reserve of 2
            let (tx, mut rx) = channel_with(specs);
            for i in 0..6 {
                tx.send(denial(i)).await.unwrap();
            }
            let stop = Arc::new(AtomicBool::new(false));
            let flood = {
                let (tx, stop) = (tx.clone(), Arc::clone(&stop));
                tokio::spawn(async move {
                    let mut i = 100;
                    while !stop.load(Ordering::Acquire) {
                        if tx.send(denial(i)).await.is_err() {
                            return;
                        }
                        i += 1;
                    }
                })
            };
            tokio::time::sleep(Duration::from_millis(30)).await;
            let started = Instant::now();
            tx.send(module_load(77)).await.unwrap();
            tx.send(sensor_flood(5)).await.unwrap();
            assert!(
                started.elapsed() < Duration::from_millis(15),
                "the reserve: no wait ({:?})",
                started.elapsed()
            );
            let late = {
                let tx = tx.clone();
                tokio::spawn(async move { tx.send(module_load(78)).await })
            };
            // the loop stands still for 200 ms
            tokio::time::sleep(Duration::from_millis(200)).await;
            assert!(!late.is_finished(), "past the reserve it waits for room");
            assert!(
                rx.stats().snapshot()[0].stats.dropped >= 3,
                "denials dropped meanwhile"
            );
            let mut seen = Vec::new();
            while seen.len() < 3 {
                match rx.recv().await.unwrap().envelope.event {
                    Event::ModuleLoad { loader_pid, .. } => seen.push(loader_pid),
                    Event::SensorFlood { pid, .. } => seen.push(pid),
                    _ => {}
                }
            }
            seen.sort_unstable();
            assert_eq!(seen, [5, 77, 78], "none dropped");
            late.await.unwrap().unwrap();
            stop.store(true, Ordering::Release);
            drop(rx);
            flood.await.unwrap();
        })
        .await
    }

    /// Second review of #471, R-A: a refused operation repeated by one
    /// process on one inode is queued once a second and counted into it;
    /// another process, operation or inode is its own; the repeats are in a
    /// signed row (count, first and last time) and in the status.
    #[tokio::test]
    async fn repeated_denials_are_coalesced_and_signed() {
        within(async {
            let dir = tempfile::tempdir().unwrap();
            let (log, path) = audit_log(dir.path());
            let (tx, mut rx) = channel();
            let at = |pid: u32, ino: u64, ts: u64| Event::FsProtectDenial {
                pid,
                uid: 0,
                comm: "chmod".into(),
                target_dev: 1,
                target_ino: ino,
                operation: nn_model::FsProtectOperation::Setattr,
                timestamp_ns: ts,
            };
            for i in 0..1_500u64 {
                tx.send(at(9, 2, 1_000 + i * 1_000)).await.unwrap(); // 1.5 ms
            }
            tx.send(at(10, 2, 2_000)).await.unwrap(); // another process
            tx.send(at(9, 3, 2_000)).await.unwrap(); // another inode
                                                     // third review, C4: the window is one second — 0.9 s after the
                                                     // queued one a repeat is counted, 1.1 s after it is queued
            tx.send(at(9, 2, 1_000 + 900_000_000)).await.unwrap();
            tx.send(at(9, 2, 1_000 + 1_100_000_000)).await.unwrap();
            let queued: Vec<(u32, u64, u64)> = std::iter::from_fn(|| rx.try_recv())
                .map(|r| match r.envelope.event {
                    Event::FsProtectDenial {
                        pid,
                        target_ino,
                        timestamp_ns,
                        ..
                    } => (pid, target_ino, timestamp_ns),
                    e => panic!("{e:?}"),
                })
                .collect();
            assert_eq!(
                queued,
                [
                    (9, 2, 1_000),
                    (10, 2, 2_000),
                    (9, 3, 2_000),
                    (9, 2, 1_000 + 1_100_000_000)
                ]
            );
            let snap = rx.stats().snapshot();
            assert_eq!((snap[0].stats.enqueued, snap[0].coalesced), (4, 1_500));
            let losses = BusLosses::default();
            losses.bind_audit_log(Some(log));
            record(&rx.stats(), &losses, Sample::Tick);
            let got = rows(dir.path(), &path, COALESCED_AUDIT_OP);
            assert_eq!(got.len(), 1, "{got:?}");
            assert_eq!(got[0]["repeats_since_last_row"], 1_500);
            assert_eq!(got[0]["keys"][0]["pid"], 9);
            assert_eq!(got[0]["keys"][0]["repeats"], 1_500);
            assert_eq!(got[0]["keys"][0]["first_ns"], 2_000);
            assert_eq!(got[0]["keys"][0]["last_ns"], 1_000 + 900_000_000);
            record(&rx.stats(), &losses, Sample::Tick);
            assert_eq!(
                rows(dir.path(), &path, COALESCED_AUDIT_OP).len(),
                1,
                "nothing new"
            );
        })
        .await
    }

    /// Third review of #471, C1: a denial the bus dropped (P0 full while
    /// the loop stands still) opens no coalescing window — its process's
    /// next denial is queued and judged, not counted into one that never
    /// was.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_dropped_denial_coalesces_nothing() {
        within(async {
            let mut specs = small(20);
            specs[0].capacity = 4; // a reserve of 1: denials take 3
            let (tx, mut rx) = channel_with(specs);
            let at = |pid: u32, ts: u64| Event::FsProtectDenial {
                pid,
                uid: 0,
                comm: "chmod".into(),
                target_dev: 1,
                target_ino: 2,
                operation: nn_model::FsProtectOperation::Setattr,
                timestamp_ns: ts,
            };
            for pid in [100, 101, 102] {
                tx.send(at(pid, 1)).await.unwrap();
            }
            tx.send(at(7, 1_000)).await.unwrap(); // waits 20 ms, dropped
            for i in 1..=5 {
                tx.send(at(7, 1_000 + i)).await.unwrap(); // dropped too
            }
            let snap = rx.stats().snapshot();
            assert_eq!(
                (snap[0].stats.dropped, snap[0].coalesced),
                (6, 0),
                "none counted into a drop"
            );
            let pid_of_denial = |r: Received| match r.envelope.event {
                Event::FsProtectDenial { pid, .. } => Some(pid),
                _ => None,
            };
            let mut pids: Vec<u32> = std::iter::from_fn(|| rx.try_recv())
                .filter_map(pid_of_denial)
                .collect();
            tx.send(at(7, 1_000 + 10)).await.unwrap(); // after the stall, within the second
            pids.extend(std::iter::from_fn(|| rx.try_recv()).filter_map(pid_of_denial));
            assert_eq!(pids, [100, 101, 102, 7], "the process is judged");
        })
        .await
    }

    /// Third review of #471, C6: a denial keeps its 50 ms bound (20 here)
    /// on the queue's slot too — with the rare events holding every slot
    /// of P0, past the reserve, it is dropped, not held without end.
    #[tokio::test]
    async fn a_denial_s_bound_holds_on_the_second_slot() {
        within(async {
            let mut specs = small(20);
            specs[0].capacity = 8; // a reserve of 2
            let (tx, rx) = channel_with(specs);
            for i in 0..8 {
                tx.send(module_load(i)).await.unwrap(); // the rare events hold all 8
            }
            let started = Instant::now();
            tx.send(denial(9)).await.unwrap();
            let took = started.elapsed();
            assert!(
                took >= Duration::from_millis(15) && took < Duration::from_millis(500),
                "{took:?}"
            );
            assert_eq!(rx.stats().snapshot()[0].stats.dropped, 1);
        })
        .await
    }

    /// Third review of #471, C2: with every key of the coalescer in use, a
    /// new one evicts the oldest window — in the order they opened, a
    /// restarted window counting from its restart — its repeats not yet in
    /// a row kept in the count; the evicted key's next denial is queued.
    #[test]
    fn the_oldest_coalescing_window_goes_first() {
        let mut c = Coalescer::default();
        let d = |pid: u32, ts: u64| {
            denial_key(&Event::FsProtectDenial {
                pid,
                uid: 0,
                comm: String::new(),
                target_dev: 1,
                target_ino: 2,
                operation: nn_model::FsProtectOperation::Setattr,
                timestamp_ns: ts,
            })
            .unwrap()
        };
        for pid in 0..COALESCE_KEYS as u32 {
            c.queued(&d(pid, 10), "");
        }
        assert!(c.repeat(&d(0, 20)) && c.repeat(&d(1, 20)));
        c.queued(&d(1, 30), ""); // pid 1's window restarts: now the newest
        c.queued(&d(9_000, 40), ""); // a new key: pid 0's window goes
        assert_eq!(c.windows.len(), COALESCE_KEYS);
        assert!(!c.windows.contains_key(&d(0, 0).0) && c.windows.contains_key(&d(1, 0).0));
        assert_eq!(
            (c.evicted, c.total),
            (1, 2),
            "pid 0's repeat kept in the count"
        );
        assert!(!c.repeat(&d(0, 50)), "an evicted key is queued again");
        c.queued(&d(9_001, 60), ""); // pid 2's goes next, not pid 1's
        assert!(!c.windows.contains_key(&d(2, 0).0) && c.windows.contains_key(&d(1, 0).0));
        // stale order entries stay bounded
        for i in 0..(8 * COALESCE_KEYS as u64) {
            c.queued(&d(1, 100 + i), "");
        }
        assert!(c.order.len() <= 4 * COALESCE_KEYS + 1, "{}", c.order.len());
        let Pending {
            keys: pending,
            evicted,
            evicted_held,
        } = c.take_pending();
        assert_eq!(evicted, 1);
        assert_eq!(
            evicted_held.get(&0).map(|(n, _)| *n),
            Some(1),
            "uid 0's, for C5"
        );
        assert_eq!(
            pending.iter().map(|(_, w)| w.repeats).sum::<u64>(),
            1,
            "pid 1's repeat"
        );
    }

    /// Second review of #471, R-E: the opens' cap counts the opens — a
    /// P2 full of other file events up to the cap still takes an open; a
    /// write-open of a PERSIST file waits for room and is not capped; the
    /// pump's early check sees the cap and its drops are P2's.
    #[tokio::test]
    async fn the_opens_cap_counts_the_opens_only() {
        within(async {
            let (tx, rx) = channel();
            let mass = |pid: u32| Event::MassWrite {
                pid,
                uid: 0,
                comm: "w".into(),
                count: 64,
                filename: "/srv/x".into(),
                timestamp_ns: 0,
                overwrites: true,
                cgroup_window: false,
            };
            for i in 0..core_bus::FILE_OPEN_SHARE as u32 {
                tx.send(mass(i)).await.unwrap();
            }
            let write_open = |kernel_class: u32| Event::FileOpen {
                pid: 7,
                uid: 0,
                gid: 0,
                comm: "sh".into(),
                filename: "/etc/cron.d/x".into(),
                flags: 1,
                timestamp_ns: 0,
                path_from_user: false,
                kernel_class,
            };
            use common::wire::open_sensor::open_reason;
            tx.send(write_open(open_reason::PERSIST)).await.unwrap();
            tx.send(open(1)).await.unwrap();
            let snap = rx.stats().snapshot();
            assert_eq!(snap[2].stats.enqueued, core_bus::FILE_OPEN_SHARE as u64 + 2);
            assert_eq!(snap[2].stats.dropped, 0);
            for i in 2..core_bus::FILE_OPEN_SHARE as u32 + 10 {
                tx.send(open(i)).await.unwrap();
            }
            let snap = rx.stats().snapshot();
            assert_eq!(
                (snap[2].stats.enqueued, snap[2].stats.dropped),
                (2 * core_bus::FILE_OPEN_SHARE as u64 + 1, 9),
                "the cap is the opens'"
            );
            assert!(!tx.open_room());
            tx.send(write_open(open_reason::CRITICAL)).await.unwrap();
            tx.note_open_dropped();
            let snap = rx.stats().snapshot();
            assert_eq!(
                snap[2].stats.enqueued,
                2 * core_bus::FILE_OPEN_SHARE as u64 + 2,
                "past the cap"
            );
            assert_eq!(snap[2].stats.dropped, 10, "the pump's early drop is P2's");
        })
        .await
    }

    /// Review #471 B3: the opens fill a quarter of P2; the other file
    /// events find room at once behind them.
    #[tokio::test]
    async fn the_opens_fill_a_quarter_of_the_file_queue() {
        within(async {
            let (tx, rx) = channel();
            for i in 0..3_000 {
                tx.send(open(i)).await.unwrap();
            }
            let snap = rx.stats().snapshot();
            assert_eq!(
                (snap[2].stats.enqueued, snap[2].stats.dropped),
                (
                    core_bus::FILE_OPEN_SHARE as u64,
                    3_000 - core_bus::FILE_OPEN_SHARE as u64
                )
            );
            let drift = Event::MassWrite {
                pid: 9,
                uid: 0,
                comm: "w".into(),
                count: 64,
                filename: "/srv/x".into(),
                timestamp_ns: 0,
                overwrites: true,
                cgroup_window: false,
            };
            tx.send(drift).await.unwrap();
            let snap = rx.stats().snapshot();
            assert_eq!(snap[2].stats.depth, core_bus::FILE_OPEN_SHARE as u64 + 1);
            assert_eq!(snap[2].waited, 0, "no wait for room");
            assert!(
                snap[2].when_full.contains("past 2048"),
                "{}",
                snap[2].when_full
            );
        })
        .await
    }

    /// Review #471 M5a: a drop is signed into the audit log — a row that
    /// verifies, with the queue and its counts.
    #[tokio::test]
    async fn a_drop_is_signed_into_the_audit_log() {
        within(async {
            let dir = tempfile::tempdir().unwrap();
            let (log, path) = audit_log(dir.path());
            let (tx, rx) = channel_with(small(1));
            for i in 0..3 {
                tx.send(denial(i)).await.unwrap();
            }
            for i in 0..5 {
                tx.send(open(i)).await.unwrap();
            }
            let losses = BusLosses::default();
            losses.bind_audit_log(Some(log));
            record(&rx.stats(), &losses, Sample::Tick);
            let got = rows(dir.path(), &path, AUDIT_OP);
            assert_eq!(got.len(), 2, "{got:?}");
            assert_eq!(got[0]["queue"], "P0");
            assert_eq!(got[0]["dropped_since_last_row"], 1);
            assert_eq!(got[1]["queue"], "P2");
            assert_eq!(got[1]["total"], 3);
            // nothing new: no row
            record(&rx.stats(), &losses, Sample::Tick);
            assert_eq!(rows(dir.path(), &path, AUDIT_OP).len(), 2);
        })
        .await
    }

    /// Review #471 M3: a P0 drop is signed within about a second, not at
    /// the next ten-second sample (a crash leaves at most that unsigned).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_p0_drop_is_signed_ahead_of_the_sample() {
        within(async {
            let dir = tempfile::tempdir().unwrap();
            let (log, path) = audit_log(dir.path());
            let (tx, rx) = channel_with(small(1));
            let losses = BusLosses::default();
            losses.bind_audit_log(Some(log));
            let recorder = spawn_loss_recorder(rx.stats(), losses.clone());
            tokio::time::sleep(Duration::from_millis(50)).await;
            let started = Instant::now();
            for i in 0..3 {
                tx.send(denial(i)).await.unwrap();
            }
            while rows(dir.path(), &path, AUDIT_OP).is_empty() {
                assert!(
                    started.elapsed() < Duration::from_secs(SAMPLE_SECS / 2),
                    "no row ahead of the sample"
                );
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
            let got = rows(dir.path(), &path, AUDIT_OP);
            assert_eq!((got.len(), &got[0]["queue"]), (1, &serde_json::json!("P0")));
            recorder.abort();
        })
        .await
    }

    /// Review #471 M3: at the stop the bus refuses sends, and the events it
    /// still held are counted in a signed row with the drops not yet
    /// signed; a stop with nothing queued writes no stop row.
    #[tokio::test]
    async fn the_stop_counts_and_signs_what_is_still_queued() {
        within(async {
            let dir = tempfile::tempdir().unwrap();
            let (log, path) = audit_log(dir.path());
            let (tx, mut rx) = channel_with(small(1));
            tx.send(denial(1)).await.unwrap();
            tx.send(spawn(2)).await.unwrap();
            for i in 0..4 {
                tx.send(open(i)).await.unwrap();
            }
            let losses = BusLosses::default();
            losses.bind_audit_log(Some(log));
            assert!(rx.try_recv().is_some());
            let queued = rx.close();
            assert_eq!(queued, [0, 1, 2, 0]);
            assert!(tx.send(denial(3)).await.is_err(), "refused after the stop");
            assert!(rx.try_recv().is_some(), "close takes nothing itself");
            assert!(losses.stop(&rx.stats(), queued));
            let stop = rows(dir.path(), &path, STOP_AUDIT_OP);
            assert_eq!(stop.len(), 1);
            assert_eq!(stop[0]["queued_at_stop"]["P1"], 1);
            assert_eq!(stop[0]["queued_at_stop"]["P2"], 2);
            assert_eq!(stop[0]["total"], 3);
            let drops = rows(dir.path(), &path, AUDIT_OP);
            assert_eq!(
                drops.len(),
                1,
                "the P2 drops signed at the stop, whatever the window"
            );
            assert_eq!(drops[0]["queue"], "P2");
            assert!(losses.stop(&rx.stats(), [0; QUEUES]));
            assert_eq!(rows(dir.path(), &path, STOP_AUDIT_OP).len(), 1);
        })
        .await
    }

    /// Review #471 B2: the status's recent wait is the last sample's — a
    /// boot backlog leaves it; the all-time maximum stays.
    #[tokio::test]
    async fn the_recent_wait_is_the_last_sample_s() {
        within(async {
            let (tx, mut rx) = channel();
            tx.send(open(1)).await.unwrap();
            tokio::time::sleep(Duration::from_millis(5)).await;
            rx.try_recv().unwrap();
            let st = rx.stats();
            let q = |s: &BusStats| s.snapshot()[2].clone();
            assert!(q(&st).recent_max_wait_us >= 4_000, "{:?}", q(&st));
            // the recorder's sample rolls the window
            let losses = BusLosses::default();
            record(&st, &losses, Sample::Tick);
            assert!(q(&st).recent_max_wait_us >= 4_000, "the last window's");
            record(&st, &losses, Sample::Tick);
            assert_eq!(q(&st).recent_max_wait_us, 0, "a window with no take");
            assert!(q(&st).stats.max_wait_ns >= 4_000_000, "since boot");
        })
        .await
    }

    fn bpf(pid: u32, uid: u32) -> Event {
        Event::BpfSyscall {
            pid,
            uid,
            comm: "bpfloop".into(),
            cmd: 0,
            arg: 0,
            timestamp_ns: 0,
        }
    }

    fn net(pid: u32) -> Event {
        Event::NetListener(nn_model::telemetry::NetListenerEvent {
            timestamp_ns: 0,
            family: 2,
            bind_addr: std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
            bind_port: 1,
            proto: 6,
            pid,
            uid: 0,
            comm: String::new(),
            exe: None,
        })
    }

    fn pid_any(e: &Event) -> u32 {
        match e {
            Event::NetListener(l) => l.pid,
            Event::BpfSyscall { pid, .. } => *pid,
            e => pid_of(e),
        }
    }

    /// R12b: a batch queues its events as the sends one by one would —
    /// each class's FIFO, a repeat of a denial queued earlier in the same
    /// batch counted into it, a full queue that drops the new event
    /// dropping it — in one round; the envelopes carry the source and the
    /// sequence of its sends, in order.
    #[tokio::test]
    async fn a_batch_queues_as_the_sends_one_by_one_would() {
        within(async {
            let mut specs = SPECS;
            specs[3].capacity = 2;
            let run = |batched: bool| {
                let specs = specs;
                async move {
                    let (tx, mut rx) = channel_with(specs);
                    let tx = tx.for_source("batch");
                    let at = |pid: u32, ts: u64| Event::FsProtectDenial {
                        pid,
                        uid: 0,
                        comm: "chmod".into(),
                        target_dev: 1,
                        target_ino: 2,
                        operation: nn_model::FsProtectOperation::Setattr,
                        timestamp_ns: ts,
                    };
                    let events = vec![
                        spawn(1),
                        at(7, 10),
                        open(2),
                        at(7, 20), // a repeat of the one above: coalesced
                        net(3),
                        spawn(4),
                        net(5),
                        net(6), // P3 full (2): dropped
                        at(8, 30),
                        open(9),
                    ];
                    if batched {
                        tx.send_batch(events).await.unwrap();
                    } else {
                        for e in events {
                            tx.send(e).await.unwrap();
                        }
                    }
                    let snap = rx.stats().snapshot();
                    let got: Vec<(Priority, u32, u64)> = std::iter::from_fn(|| rx.try_recv())
                        .map(|r| {
                            assert_eq!(r.envelope.source, tx.source());
                            (
                                r.envelope.priority(),
                                pid_any(&r.envelope.event),
                                r.envelope.seq,
                            )
                        })
                        .collect();
                    let counts: Vec<(u64, u64, u64)> = snap
                        .iter()
                        .map(|q| (q.stats.enqueued, q.stats.dropped, q.coalesced))
                        .collect();
                    (got, counts)
                }
            };
            let (one_by_one, counts1) = run(false).await;
            let (batched, counts2) = run(true).await;
            assert_eq!(batched, one_by_one);
            assert_eq!(counts2, counts1);
            let per_class = |p: Priority| -> Vec<u32> {
                batched
                    .iter()
                    .filter(|(q, _, _)| *q == p)
                    .map(|(_, pid, _)| *pid)
                    .collect()
            };
            assert_eq!(per_class(Priority::P0), [7, 8]);
            assert_eq!(per_class(Priority::P1), [1, 4]);
            assert_eq!(per_class(Priority::P2), [2, 9]);
            assert_eq!(per_class(Priority::P3), [3, 5]);
            assert_eq!(counts2[3], (2, 1, 0), "P3 dropped its third");
            assert_eq!(counts2[0], (2, 0, 1), "the repeat coalesced");
            // the sequence numbers are the batch's order
            let seq_of = |pid: u32| batched.iter().find(|(_, p, _)| *p == pid).unwrap().2;
            assert_eq!((seq_of(1), seq_of(7), seq_of(9)), (1, 2, 10));
        })
        .await
    }

    /// R12b: a batch that meets a full queue sends the rest one by one —
    /// the denial waits its 20 ms and is dropped, the event after it of
    /// another class is still queued, in order.
    #[tokio::test]
    async fn a_batch_that_meets_a_full_queue_sends_the_rest_one_by_one() {
        within(async {
            let (tx, mut rx) = channel_with(small(20));
            tx.send(denial(1)).await.unwrap();
            let started = Instant::now();
            tx.send_batch(vec![spawn(2), denial(3), denial(4), spawn(5)])
                .await
                .unwrap();
            assert!(
                started.elapsed() >= Duration::from_millis(15),
                "the denial waited"
            );
            let snap = rx.stats().snapshot();
            assert_eq!((snap[0].stats.enqueued, snap[0].stats.dropped), (2, 1));
            assert_eq!(snap[1].stats.enqueued, 2);
            let got: Vec<(Priority, u32)> = std::iter::from_fn(|| rx.try_recv())
                .map(|r| (r.envelope.priority(), pid_of(&r.envelope.event)))
                .collect();
            let of = |p: Priority| -> Vec<u32> {
                got.iter()
                    .filter(|(q, _)| *q == p)
                    .map(|(_, x)| *x)
                    .collect()
            };
            assert_eq!(
                (of(Priority::P0), of(Priority::P1)),
                (vec![1, 3], vec![2, 5])
            );
        })
        .await
    }

    /// R12b, the third review's C3: a uid's `bpf()` flood is queued up to
    /// its allowance a second, the rest counted (status, signed row with
    /// the uid and its processes); another uid's calls are queued; a repeat
    /// of a denial is coalesced before the cap counts it.
    #[tokio::test]
    async fn a_flood_of_p0_is_capped_per_uid_and_signed() {
        within(async {
            let dir = tempfile::tempdir().unwrap();
            let (log, path) = audit_log(dir.path());
            let (tx, mut rx) = channel_capped(SPECS, 5);
            for pid in 0..12u32 {
                tx.send(bpf(100 + pid, 1000)).await.unwrap();
            }
            tx.send_batch((0..6).map(|pid| bpf(200 + pid, 1000)).collect())
                .await
                .unwrap();
            tx.send(bpf(300, 1001)).await.unwrap();
            let snap = rx.stats().snapshot();
            assert_eq!(snap[0].stats.enqueued, 6, "uid 1000's five, uid 1001's one");
            assert_eq!(snap[0].capped, 13);
            assert_eq!(snap[1].capped, 0);
            assert!(
                snap[0].when_full.contains("per uid"),
                "{}",
                snap[0].when_full
            );
            let held: Arc<Mutex<Vec<(u32, u64)>>> = Arc::default();
            let losses = BusLosses::default();
            losses.bind_audit_log(Some(log));
            let h = Arc::clone(&held);
            losses.bind_held(Arc::new(move |uid, n, _| h.lock().push((uid, n))));
            record(&rx.stats(), &losses, Sample::Tick);
            let got = rows(dir.path(), &path, CAPPED_AUDIT_OP);
            assert_eq!(got.len(), 1, "{got:?}");
            assert_eq!(got[0]["capped_since_last_row"], 13);
            assert_eq!(got[0]["floods"][0]["uid"], 1000);
            assert_eq!(got[0]["floods"][0]["event"], "BpfSyscall");
            assert_eq!(got[0]["floods"][0]["processes"][0]["pid"], 105);
            assert_eq!(
                got[0]["cap_per_uid_per_second"],
                core_bus::FLOOD_CAP_PER_UID
            );
            assert!(held.lock().is_empty(), "bpf() calls are no AT-001 records");
            record(&rx.stats(), &losses, Sample::Tick);
            assert_eq!(
                rows(dir.path(), &path, CAPPED_AUDIT_OP).len(),
                1,
                "nothing new"
            );
            let uids: Vec<u32> = std::iter::from_fn(|| rx.try_recv())
                .map(|r| match r.envelope.event {
                    Event::BpfSyscall { uid, .. } => uid,
                    e => panic!("{e:?}"),
                })
                .collect();
            assert_eq!(uids, [1000, 1000, 1000, 1000, 1000, 1001]);
        })
        .await
    }

    /// R12b, the third review's C5: the denials the bus did not queue —
    /// coalesced repeats, and a uid's capped denials — are counted as
    /// NN-L-AT-001's held records of their uid at the sample, once.
    #[tokio::test]
    async fn the_denials_not_queued_are_counted_as_the_rule_s_held_records() {
        within(async {
            let dir = tempfile::tempdir().unwrap();
            let (log, _) = audit_log(dir.path());
            let (tx, rx) = channel_capped(SPECS, 3);
            let at = |pid: u32, uid: u32, ino: u64, ts: u64| Event::FsProtectDenial {
                pid,
                uid,
                comm: "chmod".into(),
                target_dev: 1,
                target_ino: ino,
                operation: nn_model::FsProtectOperation::Setattr,
                timestamp_ns: ts,
            };
            // uid 0: one process repeating (1 queued + 9 coalesced)
            for i in 0..10u64 {
                tx.send(at(9, 0, 2, 1_000 + i)).await.unwrap();
            }
            // uid 7: five new processes, the cap 3 (3 queued, 2 capped)
            tx.send_batch((0..5).map(|p| at(70 + p, 7, 5, 1_000)).collect())
                .await
                .unwrap();
            let held: Arc<Mutex<Vec<(u32, u64, String)>>> = Arc::default();
            let losses = BusLosses::default();
            losses.bind_audit_log(Some(log));
            let h = Arc::clone(&held);
            losses.bind_held(Arc::new(move |uid, n, (_, text)| {
                h.lock().push((uid, n, text))
            }));
            record(&rx.stats(), &losses, Sample::Tick);
            let mut got = held.lock().clone();
            got.sort();
            assert_eq!(
                got,
                [
                    (0, 9, "chmod (pid 9)".to_string()),
                    (7, 2, "chmod (pid 73)".to_string())
                ]
            );
            record(&rx.stats(), &losses, Sample::Tick);
            assert_eq!(held.lock().len(), 2, "counted once");
        })
        .await
    }

    /// R12b, stage 5: each decision is timed from its record's kernel time
    /// (`CLOCK_MONOTONIC`) to the end of its judgement, against its class's
    /// budget; late ones are counted (the status, stage 5, a WARN a
    /// sample), a record without a time apart.
    #[tokio::test]
    async fn the_decision_delay_is_timed_from_the_kernel_s_record() {
        within(async {
            let (tx, mut rx) = channel();
            let now = monotonic_ns();
            let denial_at = |pid: u32, ts: u64| Event::FsProtectDenial {
                pid,
                uid: 0,
                comm: "chmod".into(),
                target_dev: 1,
                target_ino: u64::from(pid),
                operation: nn_model::FsProtectOperation::Setattr,
                timestamp_ns: ts,
            };
            tx.send(denial_at(1, now - 500_000_000)).await.unwrap(); // 0.5 s ago: late for P0
            tx.send(denial_at(2, now)).await.unwrap();
            tx.send(denial_at(3, 0)).await.unwrap(); // no time
            for _ in 0..3 {
                rx.try_recv().unwrap();
            }
            rx.decided();
            let q = rx.stats().snapshot()[0].clone();
            assert_eq!((q.delay_timed, q.delay_untimed, q.over_budget), (2, 1, 1));
            assert!(q.delay_max_us.unwrap() >= 500_000, "{q:?}");
            assert_eq!(q.delay_budget_us, DECISION_BUDGET_NS[0] / 1_000);
            let stages = loss_stages(&[], 0, &rx.stats().snapshot());
            assert_eq!((stages[4].stage, stages[4].total), (5, Some(1)));
            let mut rec = LossRecorder::default();
            assert_eq!(rec.late([1, 0, 0, 0]), [(Priority::P0, 1, 1)]);
            assert!(rec.late([1, 0, 0, 0]).is_empty(), "said once");
            assert_eq!(
                rec.late([3, 0, 2, 0]),
                [(Priority::P0, 2, 3), (Priority::P2, 2, 2)]
            );
        })
        .await
    }

    /// R12b: a named source's envelopes carry its id and its own sequence;
    /// clones share them; the bus lists the sources by name.
    #[tokio::test]
    async fn a_named_source_stamps_its_envelopes() {
        within(async {
            let (tx, mut rx) = channel();
            let a = tx.for_source("a");
            let b = tx.for_source("b");
            a.send(spawn(1)).await.unwrap();
            b.send(spawn(2)).await.unwrap();
            a.clone().send(spawn(3)).await.unwrap();
            tx.send(spawn(4)).await.unwrap();
            let got: Vec<(SourceId, u64)> = std::iter::from_fn(|| rx.try_recv())
                .map(|r| (r.envelope.source, r.envelope.seq))
                .collect();
            assert_eq!(
                got,
                [
                    (SourceId(1), 1),
                    (SourceId(2), 1),
                    (SourceId(1), 2),
                    (SourceId(0), 1)
                ]
            );
            assert_eq!(rx.stats().sources(), ["(unnamed)", "a", "b"]);
            // a source's sender counts as one: the receiver ends when all go
            drop((tx, a, b));
            assert!(rx.recv().await.is_none());
        })
        .await
    }

    /// The boot id: 32 hex digits, dashes skipped; anything else is none.
    #[test]
    fn the_boot_id_is_parsed_from_its_hex() {
        let id = parse_boot_id("0f1e2d3c-4b5a-6978-8796-a5b4c3d2e1f0\n").unwrap();
        assert_eq!(id[0], 0x0f);
        assert_eq!(id[15], 0xf0);
        assert_eq!(parse_boot_id("0f1e"), None);
        assert_eq!(parse_boot_id("zz1e2d3c-4b5a-6978-8796-a5b4c3d2e1f0"), None);
        assert_eq!(read_boot_id().len(), 16);
    }
}
