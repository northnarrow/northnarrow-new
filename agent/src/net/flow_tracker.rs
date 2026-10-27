//! Tappa 10 (N3) — userland flow tracker.
//!
//! Stitches the kernel-side connect kprobe + `tcp_close` fexit
//! (N2) into the user-visible [`NetFlowEvent`] (N1) per design
//! §6.1. The tracker is a pure-userland data structure with no
//! I/O or BPF coupling — callers feed it three typed inputs
//! ([`TcpConnectInfo`], [`TcpCloseInfo`], [`UdpSendInfo`]), it
//! returns the finalised [`NetFlowEvent`] ready for the event
//! bus.
//!
//! ## Correlation contract (kernel ↔ userland)
//!
//! Per the N2 BPF design:
//!
//! 1. `tcp_v[46]_connect` (kprobe) populates
//!    `FLOW_SOCK_MAP[sk_ptr] = corr_id` where
//!    `corr_id = [start_ns_le; 8] || [sk_ptr_le; 8]` (16 bytes).
//!    The userland `TcpConnectRaw` ringbuf entry carries
//!    `sk_ptr` + `timestamp_ns` so the same `corr_id` is
//!    derivable userland-side via [`Self::corr_id`].
//! 2. `tcp_close` (fexit) reads `FLOW_SOCK_MAP[sk_ptr]` and
//!    emits the same 16-byte `corr_id` in
//!    `NetFlowCloseRaw.flow_id`. (The field name is a
//!    misleading carry-over from the §4.1 spec — the kernel-
//!    emitted value is the corr_id, not the canonical
//!    SHA-256-derived `flow_id`.)
//!
//! The tracker keys its `pending` map by `corr_id`. On close,
//! it looks up the pending entry, computes the canonical
//! `flow_id = SHA-256(start_ns || five_tuple_bytes || pid)[..16]`
//! per design §4.1, and emits the [`NetFlowEvent`].
//!
//! ## State machine (implicit)
//!
//! - **Established**: a [`PendingFlow`] exists in the map
//!   (connect seen, close not yet).
//! - **Closed**: the close call drains the pending entry +
//!   produces a finalised [`NetFlowEvent`] with the
//!   close-time byte counters + `close_reason` byte the
//!   N2 `tcp_close` fexit carries (`0` graceful, `104`
//!   ECONNRESET, `110` ETIMEDOUT, other = errored close).
//! - **UDP**: no state machine; per design §6.1 the udp_sendmsg
//!   outbound path emits a `NetFlowEvent` immediately (the
//!   §6.1 burst-window stitcher is N3.1 / V1.1 territory, NOT
//!   N3 scope — V1.0 emits per-send).
//!
//! ## Open flows (lab PR 224, CM-02)
//!
//! A TCP row used to exist only once its socket closed, so a reverse
//! shell or a C2 session that stays open had no verdict while it lived.
//! The tracker now hands out two kinds of rows for an open flow, both
//! marked by [`FlowPhase`] and never written to `netflow.jsonl`:
//!
//! - at the connect ([`FlowTracker::on_tcp_connect`]): the row the rules
//!   that need no byte count judge at once ([`FlowPhase::Connect`]);
//! - periodically ([`FlowTracker::due_snapshots`]): a flow still pending
//!   past [`SnapshotPolicy::min_age_ns`] is handed out again every
//!   [`SnapshotPolicy::interval_ns`], at most
//!   [`SnapshotPolicy::max_per_tick`] per tick (the least recently
//!   snapshotted first, the rest counted as deferred), so a precursor
//!   recorded after the connect, or an image the process executed since,
//!   is judged while the session is open ([`FlowPhase::Snapshot`]). The
//!   snapshot carries no byte counters: the kernel's are read at close.
//!
//! ## The connect before its close (lab PR 246)
//!
//! The connect and the close come on two rings, read by two tasks (the
//! connect pump, the net drain), so a close can reach the tracker, and the
//! bus, before its connect: a refused loopback connect closes within
//! microseconds. The close was then judged before the connect it ends —
//! the close of a network canary trip's own connection as an egress after
//! the trip (NN-L-CHAIN-003). The connect pump now announces each connect
//! once its events are on the bus ([`FlowTracker::announce`]), and the
//! drain holds a close until its connect is announced, a bounded time
//! ([`FlowTracker::close_may_proceed`], `net::drain::CONNECT_WAIT`). A
//! close whose connect is lost or later than that is synthesised as
//! before, under its connect's time ([`FlowTracker::corr_start_ns`]).
//!
//! ## Bounded memory
//!
//! Per §6.1: a `PendingFlow` open > 24 h gets emitted as a
//! long-lived snapshot (lab PR 224: every snapshot interval instead,
//! above). V1.0 bounds the pending
//! map at a capacity instead. Default capacity = 65,536 pending
//! flows — generous enough that ordinary hosts never evict, small
//! enough that pathological kernel-leak / sk_ptr-reuse scenarios
//! stay bounded.
//!
//! External audit NET-012: past the capacity the eviction takes the
//! oldest pending connect of the process holding the most (ties: the
//! process that connected last), so a flood of unclosed connects
//! evicts its own entries, not another process's long session. It
//! used to take the oldest entry of the whole map: exactly the
//! long-lived flow (a C2 channel, an interactive session), whose row
//! then lost its start time. Each process's connects are held in a
//! [`LazyLru`]: a close removes its entry in O(1) (a linear scan of
//! up to 65,536 entries under the tracker's lock before) and the
//! eviction skips the closed ones.

use std::collections::{BTreeSet, HashMap, VecDeque};
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use nn_model::telemetry::{FlowPhase, NetFlowEvent, TlsFingerprint};
use sha2::{Digest, Sha256};
use tokio::sync::Notify;
use tracing::warn;

use crate::decision::bounded::{LazyLru, LossCounter};

/// Default ceiling on simultaneous in-flight (connect-seen,
/// close-not-yet) flows. Past it a connect evicts one (module docs).
pub const DEFAULT_PENDING_CAPACITY: usize = 65_536;

/// Pending connects evicted at capacity since boot, all trackers.
static PENDING_EVICTIONS: AtomicU64 = AtomicU64::new(0);

/// Pending connects evicted at capacity since boot (status surface).
pub fn pending_evictions_total() -> u64 {
    PENDING_EVICTIONS.load(Ordering::Relaxed)
}

/// Lab PR 224: open-flow snapshots handed to the rules since boot.
static SNAPSHOTS_SENT: AtomicU64 = AtomicU64::new(0);
/// Lab PR 224: snapshots due but left for a later tick (the per-tick bound).
static SNAPSHOTS_DEFERRED: AtomicU64 = AtomicU64::new(0);

/// Lab PR 224: open-flow snapshots the rules re-judged since boot.
pub fn snapshots_total() -> u64 {
    SNAPSHOTS_SENT.load(Ordering::Relaxed)
}

/// Lab PR 224: snapshots deferred by the per-tick bound since boot.
pub fn snapshots_deferred_total() -> u64 {
    SNAPSHOTS_DEFERRED.load(Ordering::Relaxed)
}

/// Lab PR 224: count one snapshot handed to the rules (the drain, after
/// its liveness check).
pub fn note_snapshot_sent() {
    SNAPSHOTS_SENT.fetch_add(1, Ordering::Relaxed);
}

/// Lab PR 224 (CM-02 b): which open flows [`FlowTracker::due_snapshots`]
/// hands out again, and how many at once.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SnapshotPolicy {
    /// A flow is re-judged every this long while open.
    pub interval_ns: u64,
    /// It is not snapshotted before it has been open this long (the
    /// connect-time verdict covers the start).
    pub min_age_ns: u64,
    /// At most this many snapshots per tick; the others are deferred,
    /// least recently snapshotted first.
    pub max_per_tick: usize,
}

/// Default snapshot interval and minimum age: 60 s.
pub const DEFAULT_SNAPSHOT_SECS: u64 = 60;
/// Default bound on snapshots per tick.
pub const DEFAULT_SNAPSHOT_MAX: usize = 512;

/// Lab PR 224: an interval or minimum age (seconds, `NN_NET_SNAPSHOT_*`)
/// above the default, or unreadable, re-judges open flows less often.
pub fn snapshot_value_weakens(v: &str) -> bool {
    v.trim()
        .parse::<u64>()
        .map_or(true, |n| n > DEFAULT_SNAPSHOT_SECS)
}

impl Default for SnapshotPolicy {
    fn default() -> Self {
        Self {
            interval_ns: DEFAULT_SNAPSHOT_SECS * 1_000_000_000,
            min_age_ns: DEFAULT_SNAPSHOT_SECS * 1_000_000_000,
            max_per_tick: DEFAULT_SNAPSHOT_MAX,
        }
    }
}

/// What one [`FlowTracker::due_snapshots`] tick hands out.
#[derive(Debug, Default)]
pub struct SnapshotBatch {
    /// The snapshots, oldest-snapshotted first.
    pub flows: Vec<NetFlowEvent>,
    /// Flows that were due and are left for a later tick.
    pub deferred: usize,
}

/// Canonical correlation key — exactly the 16 bytes the N2
/// `tcp_close` fexit emits. Same shape on the connect side
/// (built locally via [`FlowTracker::corr_id`]).
pub type CorrId = [u8; 16];

/// Input describing a TCP connect observation (one
/// `Event::TcpConnect`-equivalent, but with the `sk_ptr` the N2
/// extension carries).
#[derive(Debug, Clone)]
pub struct TcpConnectInfo {
    pub start_ns: u64,
    pub sk_ptr: u64,
    pub family: u8,
    pub src_addr: IpAddr,
    pub src_port: u16,
    pub dst_addr: IpAddr,
    pub dst_port: u16,
    /// `IPPROTO_TCP` (always 6 for this input shape but kept
    /// explicit so the emitted NetFlowEvent.proto matches the
    /// kernel-observed value).
    pub proto: u8,
    pub pid: u32,
    pub uid: u32,
    pub comm: String,
    pub exe: Option<String>,
    /// External audit NET-016: the connecting process's start, or a time
    /// before it (`CLOCK_MONOTONIC` ns; 0 unknown), read at connect time.
    pub proc_start_ns: u64,
}

/// Input describing a TCP close observation (N2
/// `NetFlowCloseRaw` with `proto == IPPROTO_TCP`). `corr_id`
/// is the 16-byte FLOW_SOCK_MAP lookup the fexit emits.
/// How many close-synthesised corr_ids to remember for late connects.
const RECENT_SYNTH_CAP: usize = 256;

#[derive(Debug, Clone)]
pub struct TcpCloseInfo {
    pub end_ns: u64,
    pub corr_id: CorrId,
    /// Close-time local end (`skc_rcv_saddr` / `skc_num`). At
    /// `tcp_v4_connect` entry the socket is still unbound, so the
    /// pending flow carries `0.0.0.0:0`; the close hook is the first
    /// (and only) point where the kernel-assigned source is known
    /// (audit `abi-tcpconnect-srcport-1`).
    pub src_addr: IpAddr,
    pub src_port: u16,
    pub bytes_sent: u64,
    pub bytes_recv: u64,
    /// Low 8 bits of `sock->sk_err` at fexit. 0 = graceful
    /// FIN; 104 = ECONNRESET; 110 = ETIMEDOUT.
    pub close_reason: u8,
    /// Remote end + owner as seen by the close hook. Used to synthesise
    /// the row when the close overtakes its own connect (short-lived
    /// flows: the connect event rides the main event pipeline, the close
    /// rides the netflow drain, and a loopback connect+close can finish
    /// before the connect is registered). `dst_port == 0` and an
    /// unspecified `dst_addr` mean "unknown" (test fixtures).
    pub family: u8,
    pub dst_addr: IpAddr,
    pub dst_port: u16,
    pub pid: u32,
    pub uid: u32,
    pub comm: String,
}

/// Input describing one UDP outbound send (N2 `NetFlowCloseRaw`
/// with `proto == IPPROTO_UDP`). UDP records carry the full
/// 5-tuple + per-send byte count; V1.0 emits one
/// [`NetFlowEvent`] per send (no burst-window stitch).
#[derive(Debug, Clone)]
pub struct UdpSendInfo {
    pub timestamp_ns: u64,
    pub family: u8,
    pub src_addr: IpAddr,
    pub src_port: u16,
    pub dst_addr: IpAddr,
    pub dst_port: u16,
    pub bytes_sent: u64,
    pub pid: u32,
    pub uid: u32,
    pub comm: String,
    pub exe: Option<String>,
    /// External audit NET-016: as [`TcpConnectInfo::proc_start_ns`].
    pub proc_start_ns: u64,
}

#[derive(Debug, Clone)]
struct PendingFlow {
    /// Lab PR 246: the connect pump has put this connect's events on the
    /// bus ([`FlowTracker::announce`]); its close may follow them.
    announced: bool,
    /// Lab PR 224: when [`FlowTracker::due_snapshots`] last handed this
    /// flow out (0 never).
    last_snapshot_ns: u64,
    start_ns: u64,
    family: u8,
    src_addr: IpAddr,
    src_port: u16,
    dst_addr: IpAddr,
    dst_port: u16,
    proto: u8,
    pid: u32,
    uid: u32,
    comm: String,
    exe: Option<String>,
    proc_start_ns: u64,
}

/// One process's pending connects, oldest first (lazy deletion).
struct PidPending {
    order: LazyLru<CorrId>,
    /// Sequence number of this process's latest connect.
    last_seq: u64,
}

/// In-process tracker for TCP flow correlation + UDP per-send
/// emission. Holds a bounded map of `corr_id → PendingFlow`
/// plus, per process, the order of its pending connects.
/// Single-threaded today; callers that need cross-thread access
/// wrap it in `Arc<parking_lot::Mutex<FlowTracker>>`.
pub struct FlowTracker {
    pending: HashMap<CorrId, PendingFlow>,
    /// Every pending entry, under the pid of its connect.
    by_pid: HashMap<u32, PidPending>,
    /// `(pending connects, latest connect seq, pid)` for each process
    /// in `by_pid`: the last element is the process an eviction takes
    /// from.
    weight: BTreeSet<(usize, u64, u32)>,
    next_seq: u64,
    capacity: usize,
    /// corr_ids whose row was synthesised at close time because no
    /// pending connect existed yet; a connect arriving afterwards for
    /// one of these must not open a pending entry that never closes.
    recent_synth: VecDeque<CorrId>,
    evicted: LossCounter,
    /// Lab PR 246: woken when the connect pump announces connects
    /// ([`Self::announce`]); the drain's [`crate::net::drain`] close
    /// waits on it.
    announced: Arc<Notify>,
    /// Lab PR 246: the connect pump runs, so connects get announced.
    connect_pump: bool,
}

impl std::fmt::Debug for FlowTracker {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FlowTracker")
            .field("pending", &self.pending.len())
            .field("pids", &self.by_pid.len())
            .field("capacity", &self.capacity)
            .finish()
    }
}

impl Default for FlowTracker {
    fn default() -> Self {
        Self::with_capacity(DEFAULT_PENDING_CAPACITY)
    }
}

impl FlowTracker {
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            pending: HashMap::new(),
            by_pid: HashMap::new(),
            weight: BTreeSet::new(),
            next_seq: 0,
            recent_synth: VecDeque::new(),
            capacity,
            evicted: LossCounter::new(&PENDING_EVICTIONS),
            announced: Arc::new(Notify::new()),
            connect_pump: false,
        }
    }

    /// Lab PR 246: what wakes a close waiting for its connect
    /// ([`Self::close_may_proceed`]).
    pub fn announcements(&self) -> Arc<Notify> {
        Arc::clone(&self.announced)
    }

    /// Lab PR 246: the connect pump starts (`true`) or stops. While it
    /// does not run, nothing announces a connect and no close waits.
    pub fn set_connect_pump(&mut self, running: bool) {
        self.connect_pump = running;
        if !running {
            self.announced.notify_waiters();
        }
    }

    /// Lab PR 246: the connect pump has sent the events of the connect
    /// `corr` on the bus (its `Event::TcpConnect`, then its connect-time
    /// row). The waiters are woken.
    pub fn announce(&mut self, corr: &CorrId) {
        if let Some(p) = self.pending.get_mut(corr) {
            p.announced = true;
        }
        self.announced.notify_waiters();
    }

    /// Lab PR 246: whether the close of the flow `corr` may be resolved
    /// and sent now — its connect is on the bus already (announced), or
    /// no connect will come: a kernel lookup miss (zero), a row already
    /// synthesised, or no connect pump. Otherwise the close waits, a
    /// bounded time ([`crate::net::drain::CONNECT_WAIT`]): the connect and
    /// the close come on two rings, read by two tasks, and a close sent
    /// first was judged before the connect it ends — a network canary
    /// trip's own connection before the trip that owns it.
    pub fn close_may_proceed(&self, corr: &CorrId) -> bool {
        !self.connect_pump
            || *corr == [0u8; 16]
            || self.pending.get(corr).is_some_and(|p| p.announced)
            || self.recent_synth.contains(corr)
    }

    /// Pending connects this tracker evicted at capacity.
    pub fn evictions(&self) -> u64 {
        self.evicted.count()
    }

    /// How many flows are currently waiting for a close event.
    /// Exposed for tests + future admin-CLI status surface.
    pub fn pending_len(&self) -> usize {
        self.pending.len()
    }

    /// Build the 16-byte correlation ID from connect-side state.
    /// Mirrors the N2 BPF `build_corr_id` byte layout exactly —
    /// the kernel writes the same bytes into `FLOW_SOCK_MAP` and
    /// later the `tcp_close` fexit emits them; userland recomputes
    /// here as a defensive cross-check (and so the unit tests can
    /// drive the tracker without an actual BPF round-trip).
    pub fn corr_id(start_ns: u64, sk_ptr: u64) -> CorrId {
        let mut out = [0u8; 16];
        out[..8].copy_from_slice(&start_ns.to_le_bytes());
        out[8..].copy_from_slice(&sk_ptr.to_le_bytes());
        out
    }

    /// The connect's kernel time a correlator carries (bytes 0..8,
    /// little-endian, [`Self::corr_id`]): the start of the flow it names.
    /// External audit EBPF-019: the half that may be logged (bytes 8..16
    /// are the socket's kernel address).
    pub fn corr_start_ns(corr: &CorrId) -> u64 {
        let mut ts = [0u8; 8];
        ts.copy_from_slice(&corr[..8]);
        u64::from_le_bytes(ts)
    }

    /// Register a TCP connect observation. The pending entry
    /// stays in the map until a matching [`Self::on_tcp_close`]
    /// arrives (or an eviction takes it past `capacity`).
    ///
    /// Lab PR 224 (CM-02 a): returns the flow's [`FlowPhase::Connect`]
    /// row for the rules to judge now, while it is open; `None` when the
    /// close was already seen (its row is out).
    pub fn on_tcp_connect(&mut self, info: &TcpConnectInfo) -> Option<NetFlowEvent> {
        let key = Self::corr_id(info.start_ns, info.sk_ptr);
        if self.recent_synth.contains(&key) {
            // The close already produced this flow's row (see
            // `on_tcp_close`): a pending entry now would never close.
            return None;
        }
        // If the same corr_id is re-inserted (kernel sk_ptr
        // re-use + same start_ns — extremely unlikely but
        // possible), replace it: its old position goes, under the
        // pid it was filed under.
        if let Some(old) = self.pending.get(&key) {
            let old_pid = old.pid;
            self.unlink(old_pid, &key);
        }
        self.pending.insert(
            key,
            PendingFlow {
                announced: false,
                last_snapshot_ns: 0,
                start_ns: info.start_ns,
                family: info.family,
                src_addr: info.src_addr,
                src_port: info.src_port,
                dst_addr: info.dst_addr,
                dst_port: info.dst_port,
                proto: info.proto,
                pid: info.pid,
                uid: info.uid,
                comm: info.comm.clone(),
                exe: info.exe.clone(),
                proc_start_ns: info.proc_start_ns,
            },
        );
        self.link(info.pid, key);
        self.evict_to_capacity();
        Some(Self::open_row(info, FlowPhase::Connect, info.start_ns))
    }

    /// Lab PR 224 (CM-02 c): the row of a connect the `socket_connect`
    /// deny refused — no flow, nothing pending.
    pub fn denied_row(info: &TcpConnectInfo) -> NetFlowEvent {
        let mut row = Self::open_row(info, FlowPhase::Denied, info.start_ns);
        row.end_ns = info.start_ns;
        row
    }

    /// An open-phase row of a connect (the fields the close adds unset).
    fn open_row(info: &TcpConnectInfo, phase: FlowPhase, observed_ns: u64) -> NetFlowEvent {
        NetFlowEvent {
            start_ns: info.start_ns,
            end_ns: 0,
            family: info.family,
            src_addr: info.src_addr,
            src_port: info.src_port,
            dst_addr: info.dst_addr,
            dst_port: info.dst_port,
            proto: info.proto,
            pid: info.pid,
            uid: info.uid,
            comm: info.comm.clone(),
            exe: info.exe.clone(),
            proc_start_ns: info.proc_start_ns,
            bytes_sent: 0,
            bytes_recv: 0,
            resolved_hostname: None,
            tls_fingerprint: None,
            flow_id: String::new(),
            close_reason: 0,
            phase,
            observed_ns,
        }
    }

    /// Lab PR 224 (CM-02 b): the pending flows open at least
    /// `policy.min_age_ns` at `now_ns` and not handed out within
    /// `policy.interval_ns`, as [`FlowPhase::Snapshot`] rows, at most
    /// `policy.max_per_tick` (the least recently snapshotted first; the
    /// others are counted as deferred and come first next time). Each
    /// one handed out is stamped `now_ns`. The image and the DNS name are
    /// the connect's: the caller refreshes them.
    pub fn due_snapshots(&mut self, now_ns: u64, policy: &SnapshotPolicy) -> SnapshotBatch {
        let mut due: Vec<(u64, u64, CorrId)> = self
            .pending
            .iter()
            .filter(|(_, p)| {
                now_ns.saturating_sub(p.start_ns) >= policy.min_age_ns
                    && (p.last_snapshot_ns == 0
                        || now_ns.saturating_sub(p.last_snapshot_ns) >= policy.interval_ns)
            })
            .map(|(k, p)| (p.last_snapshot_ns, p.start_ns, *k))
            .collect();
        let deferred = due.len().saturating_sub(policy.max_per_tick);
        if deferred > 0 {
            due.select_nth_unstable(policy.max_per_tick);
            due.truncate(policy.max_per_tick);
            SNAPSHOTS_DEFERRED.fetch_add(deferred as u64, Ordering::Relaxed);
        }
        due.sort_unstable();
        let mut flows = Vec::with_capacity(due.len());
        for (_, _, key) in due {
            let Some(p) = self.pending.get_mut(&key) else {
                continue;
            };
            p.last_snapshot_ns = now_ns;
            flows.push(NetFlowEvent {
                start_ns: p.start_ns,
                end_ns: 0,
                family: p.family,
                src_addr: p.src_addr,
                src_port: p.src_port,
                dst_addr: p.dst_addr,
                dst_port: p.dst_port,
                proto: p.proto,
                pid: p.pid,
                uid: p.uid,
                comm: p.comm.clone(),
                exe: p.exe.clone(),
                proc_start_ns: p.proc_start_ns,
                bytes_sent: 0,
                bytes_recv: 0,
                resolved_hostname: None,
                tls_fingerprint: None,
                flow_id: String::new(),
                close_reason: 0,
                phase: FlowPhase::Snapshot,
                observed_ns: now_ns,
            });
        }
        SnapshotBatch { flows, deferred }
    }

    /// Resolve a TCP close observation against the pending map.
    /// `Some(NetFlowEvent)` on a successful correlation; `None`
    /// when the close has no matching pending entry (orphan
    /// close — happens at agent boot when the connect predated
    /// the agent, or after an eviction). Defensive callers
    /// log + drop the orphan.
    pub fn on_tcp_close(&mut self, info: &TcpCloseInfo) -> Option<NetFlowEvent> {
        // Zero corr_id = kernel-side FLOW_SOCK_MAP lookup miss
        // (LRU evicted the entry between connect + close). Same
        // outcome as an orphan close — drop on the floor.
        if info.corr_id == [0u8; 16] {
            return None;
        }
        let Some(pending) = self.pending.remove(&info.corr_id) else {
            return self.synthesise_from_close(info);
        };
        // TCP: the connect hook cannot know the local end; take it from
        // the close observation so the emitted row AND the canonical
        // flow_id carry the real 5-tuple (cross-host correlatable) instead
        // of a zeroed source half.
        let (src_addr, src_port) = if pending.src_port == 0 && pending.src_addr.is_unspecified() {
            (info.src_addr, info.src_port)
        } else {
            (pending.src_addr, pending.src_port)
        };
        // External audit NET-012: O(1); the queue entry goes lazily.
        self.unlink(pending.pid, &info.corr_id);
        let flow_id = canonical_flow_id(
            pending.start_ns,
            pending.family,
            src_addr,
            src_port,
            pending.dst_addr,
            pending.dst_port,
            pending.proto,
            pending.pid,
        );
        Some(NetFlowEvent {
            start_ns: pending.start_ns,
            end_ns: info.end_ns,
            family: pending.family,
            src_addr,
            src_port,
            dst_addr: pending.dst_addr,
            dst_port: pending.dst_port,
            proto: pending.proto,
            pid: pending.pid,
            uid: pending.uid,
            comm: pending.comm,
            exe: pending.exe,
            proc_start_ns: pending.proc_start_ns,
            bytes_sent: info.bytes_sent,
            bytes_recv: info.bytes_recv,
            resolved_hostname: None,
            tls_fingerprint: None,
            flow_id,
            close_reason: info.close_reason,
            phase: FlowPhase::Closed,
            observed_ns: 0,
        })
    }

    /// Close arrived with a kernel-side flow id but no pending connect:
    /// the connect event has not reached the tracker yet (short-lived
    /// flow, loopback connect+close in well under the pipeline latency;
    /// since lab PR 246 the drain waits for it first, so this is the
    /// connect lost or late past [`crate::net::drain::CONNECT_WAIT`]).
    /// Build the row from what the close hook carries — the full
    /// 5-tuple, owner and byte counters — with no exe/hostname
    /// enrichment (the drain names the image, external audit NET-012),
    /// and remember the corr_id so the late connect is ignored. Without
    /// this every connect-and-close-at-once flow (reverse-shell probes,
    /// scanners, the CHAIN-007 egress leg) vanished from netflow.jsonl.
    ///
    /// Lab PR 246: the row starts at its connect, whose kernel time the
    /// correlator carries ([`Self::corr_start_ns`]), not at its close
    /// (`start_ns = end_ns` before): every row of a flow names it by
    /// (pid, connect time) — the flow ledger, the egress notes and a
    /// network canary trip that owns the connection do — whichever ring
    /// the tracker heard first. The close of a canary trip's own
    /// connection, synthesised, was judged as an egress after the trip
    /// (NN-L-CHAIN-003 on the trip's own connection, the KVM failure of
    /// 27/10/2026). The destination stays the close's: a refused connect
    /// shows port 0 there (the kernel cleared it).
    fn synthesise_from_close(&mut self, info: &TcpCloseInfo) -> Option<NetFlowEvent> {
        if info.dst_port == 0 && info.dst_addr.is_unspecified() {
            return None;
        }
        if self.recent_synth.len() >= RECENT_SYNTH_CAP {
            self.recent_synth.pop_front();
        }
        self.recent_synth.push_back(info.corr_id);
        let start_ns = match Self::corr_start_ns(&info.corr_id) {
            0 => info.end_ns,
            connect => connect.min(info.end_ns),
        };
        let flow_id = canonical_flow_id(
            start_ns,
            info.family,
            info.src_addr,
            info.src_port,
            info.dst_addr,
            info.dst_port,
            6,
            info.pid,
        );
        Some(NetFlowEvent {
            start_ns,
            end_ns: info.end_ns,
            family: info.family,
            src_addr: info.src_addr,
            src_port: info.src_port,
            dst_addr: info.dst_addr,
            dst_port: info.dst_port,
            proto: 6,
            pid: info.pid,
            uid: info.uid,
            comm: info.comm.clone(),
            exe: None,
            proc_start_ns: 0,
            bytes_sent: info.bytes_sent,
            bytes_recv: info.bytes_recv,
            resolved_hostname: None,
            tls_fingerprint: None,
            flow_id,
            close_reason: info.close_reason,
            phase: FlowPhase::Closed,
            observed_ns: 0,
        })
    }

    /// Emit a single [`NetFlowEvent`] for a UDP send. V1.0
    /// emits per-send; the burst-window stitcher is N3.1.
    pub fn on_udp_send(&mut self, info: &UdpSendInfo) -> NetFlowEvent {
        let flow_id = canonical_flow_id(
            info.timestamp_ns,
            info.family,
            info.src_addr,
            info.src_port,
            info.dst_addr,
            info.dst_port,
            17, // IPPROTO_UDP
            info.pid,
        );
        NetFlowEvent {
            start_ns: info.timestamp_ns,
            // UDP has no "end" in the connect/close sense —
            // emit the same ts as start so the row carries a
            // duration of zero (the burst-window stitch in
            // N3.1 will replace this).
            end_ns: info.timestamp_ns,
            family: info.family,
            src_addr: info.src_addr,
            src_port: info.src_port,
            dst_addr: info.dst_addr,
            dst_port: info.dst_port,
            proto: 17,
            pid: info.pid,
            uid: info.uid,
            comm: info.comm.clone(),
            exe: info.exe.clone(),
            proc_start_ns: info.proc_start_ns,
            bytes_sent: info.bytes_sent,
            bytes_recv: 0,
            resolved_hostname: None,
            tls_fingerprint: None,
            flow_id,
            // UDP has no close-reason semantics.
            close_reason: 0,
            phase: FlowPhase::Closed,
            observed_ns: 0,
        }
    }

    /// Future N4 hook — attach a resolved hostname to an
    /// emitted event after the DNS cache lookup. Plumbed now so
    /// the N4 commit doesn't need to reshape `on_tcp_close` /
    /// `on_udp_send` signatures.
    #[allow(dead_code)]
    pub fn attach_hostname(event: &mut NetFlowEvent, hostname: String) {
        event.resolved_hostname = Some(hostname);
    }

    /// Future N5 hook — attach a TLS fingerprint after the
    /// userland parser extracts it from the captured ClientHello.
    #[allow(dead_code)]
    pub fn attach_tls(event: &mut NetFlowEvent, fp: TlsFingerprint) {
        event.tls_fingerprint = Some(fp);
    }

    /// File `key` under `pid` as its latest connect.
    fn link(&mut self, pid: u32, key: CorrId) {
        let seq = self.next_seq;
        self.next_seq = self.next_seq.wrapping_add(1);
        let entry = self.by_pid.entry(pid).or_insert_with(|| PidPending {
            // Small queues, one per process (as NETR-005's windows).
            order: LazyLru::with_compact_floor(4),
            last_seq: 0,
        });
        if !entry.order.is_empty() {
            self.weight
                .remove(&(entry.order.len(), entry.last_seq, pid));
        }
        entry.order.touch(key);
        entry.last_seq = seq;
        self.weight.insert((entry.order.len(), seq, pid));
    }

    /// Take `key` out of `pid`'s pending connects.
    fn unlink(&mut self, pid: u32, key: &CorrId) {
        let Some(entry) = self.by_pid.get_mut(&pid) else {
            return;
        };
        if !entry.order.contains(key) {
            return;
        }
        self.weight
            .remove(&(entry.order.len(), entry.last_seq, pid));
        entry.order.remove(key);
        if entry.order.is_empty() {
            self.by_pid.remove(&pid);
        } else {
            self.weight.insert((entry.order.len(), entry.last_seq, pid));
        }
    }

    /// External audit NET-012: past the capacity, evict the oldest
    /// pending connect of the process holding the most (ties: the
    /// process that connected last).
    fn evict_to_capacity(&mut self) {
        while self.pending.len() > self.capacity {
            let Some(&(count, last_seq, pid)) = self.weight.iter().next_back() else {
                break;
            };
            self.weight.remove(&(count, last_seq, pid));
            let Some(entry) = self.by_pid.get_mut(&pid) else {
                continue;
            };
            let victim = entry.order.pop_oldest();
            if entry.order.is_empty() {
                self.by_pid.remove(&pid);
            } else {
                self.weight.insert((entry.order.len(), last_seq, pid));
            }
            let Some(victim) = victim else {
                continue;
            };
            if self.pending.remove(&victim).is_some() && self.evicted.bump() {
                warn!(
                    pid,
                    pending = count,
                    evicted = self.evicted.count(),
                    capacity = self.capacity,
                    "flow tracker full: evicted the oldest pending connect of the process \
                     holding the most; its close is recorded without its start time"
                );
            }
        }
    }
}

/// Compute the per-flow stable ID per design §4.1:
/// `SHA-256(start_ns || five_tuple_bytes || pid)[..16]` rendered
/// as 32-char lowercase hex. Deterministic + reproducible across
/// hosts (no sk_ptr in the input) — operators can quote the
/// `flow_id` in incident reports + a peer host can recompute it
/// from the same 5-tuple + connect timestamp + pid for cross-
/// host correlation.
///
/// The 8 inputs come from disjoint origins (kernel BPF event,
/// userland process attribution) so packing into a struct
/// would just push the same parameter list one layer down +
/// add a one-shot type. `#[allow(too_many_arguments)]` is the
/// pragmatic call here.
#[allow(clippy::too_many_arguments)]
fn canonical_flow_id(
    start_ns: u64,
    family: u8,
    src_addr: IpAddr,
    src_port: u16,
    dst_addr: IpAddr,
    dst_port: u16,
    proto: u8,
    pid: u32,
) -> String {
    let mut h = Sha256::new();
    h.update(start_ns.to_le_bytes());
    h.update([family]);
    // Address bytes (v4 padded to 16, v6 raw 16).
    h.update(addr_bytes(src_addr));
    h.update(src_port.to_le_bytes());
    h.update(addr_bytes(dst_addr));
    h.update(dst_port.to_le_bytes());
    h.update([proto]);
    h.update(pid.to_le_bytes());
    let digest = h.finalize();
    hex::encode(&digest[..16])
}

fn addr_bytes(a: IpAddr) -> [u8; 16] {
    match a {
        IpAddr::V4(v4) => {
            let mut out = [0u8; 16];
            out[..4].copy_from_slice(&v4.octets());
            out
        }
        IpAddr::V6(v6) => v6.octets(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn v4(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(a, b, c, d))
    }

    fn connect_fixture(
        start_ns: u64,
        sk_ptr: u64,
        pid: u32,
        dst: IpAddr,
        dport: u16,
    ) -> TcpConnectInfo {
        TcpConnectInfo {
            start_ns,
            sk_ptr,
            family: if matches!(dst, IpAddr::V4(_)) { 2 } else { 10 },
            src_addr: v4(192, 0, 2, 10),
            src_port: 54321,
            dst_addr: dst,
            dst_port: dport,
            proto: 6,
            pid,
            uid: 1000,
            comm: "curl".to_string(),
            exe: Some("/usr/bin/curl".to_string()),
            proc_start_ns: start_ns / 2,
        }
    }

    fn close_fixture(end_ns: u64, corr: CorrId, sent: u64, recv: u64, reason: u8) -> TcpCloseInfo {
        TcpCloseInfo {
            family: 2,
            dst_addr: IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
            dst_port: 0,
            pid: 0,
            uid: 0,
            comm: String::new(),
            src_addr: "10.0.0.7".parse().unwrap(),
            src_port: 51234,
            end_ns,
            corr_id: corr,
            bytes_sent: sent,
            bytes_recv: recv,
            close_reason: reason,
        }
    }

    /// N3 test #1 — same connect inputs MUST hash to the same
    /// `flow_id`. This is the load-bearing reproducibility
    /// promise (design §4.1) that lets operators quote a
    /// flow_id in an incident report + a peer host derive the
    /// same value from raw kernel events.
    #[test]
    fn flow_id_is_deterministic_per_5_tuple() {
        let id_a = canonical_flow_id(1, 2, v4(1, 1, 1, 1), 80, v4(2, 2, 2, 2), 443, 6, 9999);
        let id_b = canonical_flow_id(1, 2, v4(1, 1, 1, 1), 80, v4(2, 2, 2, 2), 443, 6, 9999);
        assert_eq!(id_a, id_b);
        assert_eq!(
            id_a.len(),
            32,
            "flow_id must be 32 hex chars (SHA-256[..16])"
        );
    }

    /// N3 test #2 — differing in ANY component of the 5-tuple
    /// produces a different `flow_id`. Anchors the spec's
    /// "five_tuple feeds the hash" promise.
    #[test]
    fn flow_id_differs_across_different_5_tuples() {
        let base = canonical_flow_id(1, 2, v4(1, 1, 1, 1), 80, v4(2, 2, 2, 2), 443, 6, 9999);
        // Different src_port.
        assert_ne!(
            base,
            canonical_flow_id(1, 2, v4(1, 1, 1, 1), 81, v4(2, 2, 2, 2), 443, 6, 9999)
        );
        // Different dst_addr.
        assert_ne!(
            base,
            canonical_flow_id(1, 2, v4(1, 1, 1, 1), 80, v4(3, 3, 3, 3), 443, 6, 9999)
        );
        // Different proto.
        assert_ne!(
            base,
            canonical_flow_id(1, 2, v4(1, 1, 1, 1), 80, v4(2, 2, 2, 2), 443, 17, 9999)
        );
    }

    /// N3 test #3 — `pid` is part of the hash input. Two
    /// different processes connecting to the SAME 5-tuple at
    /// the same `start_ns` produce different `flow_id`s; the
    /// design's per-PID attribution wouldn't work otherwise.
    #[test]
    fn flow_id_includes_pid_in_hash() {
        let id_pid_a = canonical_flow_id(1, 2, v4(1, 1, 1, 1), 80, v4(2, 2, 2, 2), 443, 6, 100);
        let id_pid_b = canonical_flow_id(1, 2, v4(1, 1, 1, 1), 80, v4(2, 2, 2, 2), 443, 6, 200);
        assert_ne!(id_pid_a, id_pid_b);
    }

    /// N3 test #4 — `start_ns` is part of the hash input.
    /// Same (5-tuple, pid) at different times = different
    /// `flow_id`. This is what distinguishes a reconnecting
    /// process's old + new flow.
    #[test]
    fn flow_id_includes_start_ns_in_hash() {
        let a = canonical_flow_id(100, 2, v4(1, 1, 1, 1), 80, v4(2, 2, 2, 2), 443, 6, 9999);
        let b = canonical_flow_id(200, 2, v4(1, 1, 1, 1), 80, v4(2, 2, 2, 2), 443, 6, 9999);
        assert_ne!(a, b);
    }

    /// N3 test #5 — happy path: connect then close → one
    /// `NetFlowEvent` with the correct byte counters + 5-tuple
    /// + flow_id.
    #[test]
    fn connect_then_close_emits_net_flow_event_with_byte_counters() {
        let mut t = FlowTracker::default();
        let conn = connect_fixture(1_000_000, 0xDEAD_BEEF, 8888, v4(1, 2, 3, 4), 443);
        t.on_tcp_connect(&conn);
        assert_eq!(t.pending_len(), 1);

        let corr = FlowTracker::corr_id(conn.start_ns, conn.sk_ptr);
        let evt = t
            .on_tcp_close(&close_fixture(2_000_000, corr, 1234, 5678, 0))
            .expect("close must correlate to pending");
        assert_eq!(evt.start_ns, 1_000_000);
        assert_eq!(evt.end_ns, 2_000_000);
        assert_eq!(evt.bytes_sent, 1234);
        assert_eq!(evt.bytes_recv, 5678);
        assert_eq!(evt.dst_addr, v4(1, 2, 3, 4));
        assert_eq!(evt.dst_port, 443);
        assert_eq!(evt.flow_id.len(), 32);
        // external audit NET-016: the connecting process's start, read at
        // connect time, reaches the row the DNS attribution reads
        assert_eq!(evt.proc_start_ns, 500_000);
        assert_eq!(t.pending_len(), 0, "pending entry must be drained on close");
    }

    /// Audit `abi-tcpconnect-srcport-1`: the connect hook never knows the
    /// local end (unbound at tcp_v4_connect entry), so the emitted row and
    /// the canonical flow_id must take it from the close observation.
    #[test]
    fn tcp_close_supplies_the_real_source_half() {
        let mut t = FlowTracker::default();
        let mut conn = connect_fixture(1_000_000, 0xC0FFEE, 4242, v4(203, 0, 113, 9), 8443);
        // What the kernel really reports at tcp_v4_connect entry: unbound.
        conn.src_addr = v4(0, 0, 0, 0);
        conn.src_port = 0;
        t.on_tcp_connect(&conn);
        let corr = FlowTracker::corr_id(conn.start_ns, conn.sk_ptr);
        let mut close = close_fixture(2_000_000, corr, 10, 20, 0);
        close.src_addr = v4(10, 0, 0, 7);
        close.src_port = 51234;
        let evt = t.on_tcp_close(&close).expect("correlates");
        assert_eq!(evt.src_addr, v4(10, 0, 0, 7));
        assert_eq!(evt.src_port, 51234);
        assert_ne!(evt.src_port, 0, "netflow rows must not carry 0.0.0.0:0");

        // Same connect, different close-time source → different flow_id
        // (the hash really covers the 5-tuple now).
        let mut t2 = FlowTracker::default();
        t2.on_tcp_connect(&conn);
        let mut close2 = close_fixture(2_000_000, corr, 10, 20, 0);
        close2.src_addr = v4(10, 0, 0, 8);
        close2.src_port = 51234;
        let evt2 = t2.on_tcp_close(&close2).expect("correlates");
        assert_ne!(evt.flow_id, evt2.flow_id);
    }

    /// N3 test #6 — close with no matching pending entry
    /// returns `None` (orphan defensive). The agent could see
    /// a close for a connect that fired before agent boot, or
    /// for one whose FLOW_SOCK_MAP entry got LRU-evicted.
    #[test]
    fn close_without_connect_returns_none() {
        let mut t = FlowTracker::default();
        let corr = [0x11u8; 16];
        assert!(t.on_tcp_close(&close_fixture(1, corr, 0, 0, 0)).is_none());
        assert_eq!(t.pending_len(), 0);
    }

    /// N3 test #7 — close with all-zero corr_id is treated as
    /// a kernel-side FLOW_SOCK_MAP miss + drops on the floor.
    /// The N2 `tcp_close` fexit emits zero when the LRU map
    /// missed the sk_ptr lookup; userland mustn't synthesise
    /// a phantom flow for it.
    #[test]
    fn close_with_zero_corr_id_returns_none_even_with_pending() {
        let mut t = FlowTracker::default();
        let conn = connect_fixture(1, 1, 1, v4(1, 2, 3, 4), 443);
        t.on_tcp_connect(&conn);
        let zero: CorrId = [0u8; 16];
        assert!(t.on_tcp_close(&close_fixture(2, zero, 0, 0, 0)).is_none());
        assert_eq!(
            t.pending_len(),
            1,
            "zero-corr close must NOT consume an unrelated pending entry"
        );
    }

    /// N3 test #8 — UDP path emits one `NetFlowEvent` per
    /// send, with no state machine + `proto = IPPROTO_UDP`.
    #[test]
    fn udp_flow_emits_immediately_no_state_machine() {
        let mut t = FlowTracker::default();
        let udp = UdpSendInfo {
            timestamp_ns: 5_000,
            family: 2,
            src_addr: v4(10, 0, 0, 1),
            src_port: 1234,
            dst_addr: v4(8, 8, 8, 8),
            dst_port: 53,
            bytes_sent: 56,
            pid: 999,
            uid: 0,
            comm: "dig".to_string(),
            exe: None,
            proc_start_ns: 4_000,
        };
        let evt = t.on_udp_send(&udp);
        assert_eq!(evt.proto, 17);
        assert_eq!(evt.bytes_sent, 56);
        assert_eq!(evt.bytes_recv, 0);
        assert_eq!(evt.dst_addr, v4(8, 8, 8, 8));
        assert_eq!(evt.start_ns, 5_000);
        assert_eq!(evt.end_ns, 5_000, "UDP record has zero duration in V1.0");
        assert_eq!(evt.proc_start_ns, 4_000);
        assert_eq!(evt.close_reason, 0);
        assert_eq!(t.pending_len(), 0, "UDP must NOT register a pending entry");
    }

    /// N3 test #9 — close_reason=104 (ECONNRESET) propagates
    /// through to the emitted event.
    #[test]
    fn tcp_reset_close_reason_propagates_to_event() {
        let mut t = FlowTracker::default();
        let conn = connect_fixture(1, 0xCAFE, 1, v4(1, 2, 3, 4), 80);
        t.on_tcp_connect(&conn);
        let corr = FlowTracker::corr_id(conn.start_ns, conn.sk_ptr);
        let evt = t
            .on_tcp_close(&close_fixture(2, corr, 0, 0, 104))
            .expect("close correlates");
        assert_eq!(evt.close_reason, 104);
    }

    /// N3 test #10 — close_reason=110 (ETIMEDOUT) propagates.
    #[test]
    fn tcp_timeout_close_reason_propagates_to_event() {
        let mut t = FlowTracker::default();
        let conn = connect_fixture(1, 0xBEEF, 1, v4(1, 2, 3, 4), 80);
        t.on_tcp_connect(&conn);
        let corr = FlowTracker::corr_id(conn.start_ns, conn.sk_ptr);
        let evt = t
            .on_tcp_close(&close_fixture(2, corr, 0, 0, 110))
            .expect("close correlates");
        assert_eq!(evt.close_reason, 110);
    }

    /// N3 test #11 — graceful close (close_reason=0)
    /// propagates as `0` too (vs `Option::None` or some
    /// sentinel). The wire field is a flat `u8` per N3
    /// `NetFlowEvent.close_reason` extension; 0 IS the
    /// graceful value, distinct from "unset" because the
    /// flow reached `on_tcp_close`.
    #[test]
    fn tcp_graceful_close_reason_propagates_to_event() {
        let mut t = FlowTracker::default();
        let conn = connect_fixture(1, 0xFEED, 1, v4(1, 2, 3, 4), 80);
        t.on_tcp_connect(&conn);
        let corr = FlowTracker::corr_id(conn.start_ns, conn.sk_ptr);
        let evt = t
            .on_tcp_close(&close_fixture(2, corr, 0, 0, 0))
            .expect("close correlates");
        assert_eq!(evt.close_reason, 0);
    }

    /// N3 test #12 — past capacity, the oldest pending entry of
    /// the process holding the most is evicted first (one process
    /// here). A subsequent close on the evicted flow returns `None`
    /// (correctly reported as an orphan); the NEWER flow still
    /// correlates.
    #[test]
    fn flow_tracker_bounded_memory_evicts_oldest_when_full() {
        let mut t = FlowTracker::with_capacity(2);
        let c1 = connect_fixture(1, 1, 7, v4(1, 1, 1, 1), 80);
        let c2 = connect_fixture(2, 2, 7, v4(2, 2, 2, 2), 80);
        let c3 = connect_fixture(3, 3, 7, v4(3, 3, 3, 3), 80);
        t.on_tcp_connect(&c1);
        t.on_tcp_connect(&c2);
        t.on_tcp_connect(&c3); // evicts c1
        assert_eq!(t.pending_len(), 2);

        // c1's close — now an orphan.
        let corr1 = FlowTracker::corr_id(c1.start_ns, c1.sk_ptr);
        assert!(t.on_tcp_close(&close_fixture(10, corr1, 0, 0, 0)).is_none());

        // c3's close still works.
        let corr3 = FlowTracker::corr_id(c3.start_ns, c3.sk_ptr);
        assert!(t.on_tcp_close(&close_fixture(10, corr3, 0, 0, 0)).is_some());
    }

    /// N3 test #13 — within one process, eviction preserves the
    /// more recent entries (oldest first).
    #[test]
    fn flow_tracker_eviction_preserves_recent_pending() {
        let mut t = FlowTracker::with_capacity(3);
        for i in 1..=5 {
            let c = connect_fixture(i, i, 9, v4(i as u8, 0, 0, 1), 80);
            t.on_tcp_connect(&c);
        }
        assert_eq!(t.pending_len(), 3);
        // The 3 most-recent corr_ids (3, 4, 5) should still
        // resolve; (1, 2) evicted.
        for i in 3..=5 {
            let corr = FlowTracker::corr_id(i, i);
            assert!(
                t.on_tcp_close(&close_fixture(99, corr, 0, 0, 0)).is_some(),
                "recent flow {i} should still correlate"
            );
        }
    }

    /// External audit NET-012: a flood of unclosed connects from one
    /// process evicts its own entries, never another process's long
    /// session (the oldest entry of the map, which FIFO took first).
    #[test]
    fn a_connect_flood_evicts_the_flooders_entries_first() {
        let mut t = FlowTracker::with_capacity(8);
        let long = connect_fixture(1, 1, 100, v4(1, 2, 3, 4), 443);
        t.on_tcp_connect(&long);
        let other = connect_fixture(2, 2, 200, v4(5, 6, 7, 8), 22);
        t.on_tcp_connect(&other);
        for i in 10..1_000u64 {
            t.on_tcp_connect(&connect_fixture(i, i, 666, v4(10, 255, 0, 1), 80));
        }
        assert_eq!(t.pending_len(), 8);
        assert_eq!(t.evictions(), 1_000 - 10 + 2 - 8);
        for (c, end) in [(&long, 5_000), (&other, 5_001)] {
            let corr = FlowTracker::corr_id(c.start_ns, c.sk_ptr);
            let evt = t
                .on_tcp_close(&close_fixture(end, corr, 1, 1, 0))
                .expect("the long session is still pending");
            assert_eq!(evt.start_ns, c.start_ns, "its start time is kept");
            assert_eq!(evt.exe.as_deref(), Some("/usr/bin/curl"));
        }
        // The flooder kept its most recent connects.
        let newest = FlowTracker::corr_id(999, 999);
        assert!(t
            .on_tcp_close(&close_fixture(6_000, newest, 0, 0, 0))
            .is_some());
    }

    /// The same with one connect per process (a fork per connect): at
    /// equal counts the process that connected last gives way, so the
    /// long session of an earlier process survives (the shape of the
    /// audit's `long_lived_flow_survives_a_connect_flood`).
    #[test]
    fn a_fork_flood_does_not_evict_an_earlier_long_session() {
        let mut t = FlowTracker::with_capacity(8);
        let long = connect_fixture(1, 1, 1, v4(1, 2, 3, 4), 443);
        t.on_tcp_connect(&long);
        for i in 2..100u64 {
            t.on_tcp_connect(&connect_fixture(i, i, i as u32, v4(9, 9, 9, 9), 80));
        }
        let corr = FlowTracker::corr_id(1, 1);
        let evt = t
            .on_tcp_close(&close_fixture(10_000, corr, 1, 1, 0))
            .expect("the long session is still pending");
        assert!(evt.exe.is_some());
        assert!(evt.end_ns > evt.start_ns);
    }

    /// External audit NET-012: a close leaves its queue entry behind
    /// (no scan); the eviction skips it and takes the oldest connect
    /// still pending, and the queues stay bounded under churn.
    #[test]
    fn evict_to_capacity_skips_closed_entries() {
        let mut t = FlowTracker::with_capacity(2);
        let a = connect_fixture(1, 1, 7, v4(1, 1, 1, 1), 80);
        let b = connect_fixture(2, 2, 7, v4(2, 2, 2, 2), 80);
        let c = connect_fixture(3, 3, 7, v4(3, 3, 3, 3), 80);
        let d = connect_fixture(4, 4, 7, v4(4, 4, 4, 4), 80);
        t.on_tcp_connect(&a);
        t.on_tcp_connect(&b);
        let corr = |c: &TcpConnectInfo| FlowTracker::corr_id(c.start_ns, c.sk_ptr);
        assert!(t
            .on_tcp_close(&close_fixture(9, corr(&a), 0, 0, 0))
            .is_some());
        t.on_tcp_connect(&c);
        assert_eq!(t.evictions(), 0);
        t.on_tcp_connect(&d); // over capacity: `a` is closed, `b` goes
        assert_eq!(t.evictions(), 1);
        assert!(t
            .on_tcp_close(&close_fixture(9, corr(&b), 0, 0, 0))
            .is_none());
        assert!(t
            .on_tcp_close(&close_fixture(9, corr(&c), 0, 0, 0))
            .is_some());
        assert!(t
            .on_tcp_close(&close_fixture(9, corr(&d), 0, 0, 0))
            .is_some());
        assert!(t.by_pid.is_empty() && t.weight.is_empty());

        // Churn beside one long session: the queue holds the live entry
        // and a bounded number of closed ones.
        let mut t = FlowTracker::with_capacity(16);
        t.on_tcp_connect(&connect_fixture(1, 1, 7, v4(1, 1, 1, 1), 443));
        for i in 2..50_000u64 {
            let c = connect_fixture(i, i, 7, v4(2, 2, 2, 2), 80);
            t.on_tcp_connect(&c);
            assert!(t
                .on_tcp_close(&close_fixture(i, corr(&c), 0, 0, 0))
                .is_some());
        }
        assert_eq!(t.pending_len(), 1);
        assert!(t.by_pid[&7].order.queue_len() <= 9);
        assert_eq!(t.weight.len(), 1);
    }

    /// N3 test #14 — a second close for the same corr_id
    /// (e.g. a duplicate ringbuf delivery) is a no-op rather
    /// than a panic. The pending entry has already been
    /// drained by the first close; the second returns `None`.
    #[test]
    fn flow_tracker_dual_close_for_same_corr_id_handles_gracefully() {
        let mut t = FlowTracker::default();
        let conn = connect_fixture(1, 1, 1, v4(1, 2, 3, 4), 443);
        t.on_tcp_connect(&conn);
        let corr = FlowTracker::corr_id(conn.start_ns, conn.sk_ptr);
        assert!(t.on_tcp_close(&close_fixture(2, corr, 1, 1, 0)).is_some());
        // Duplicate — must NOT emit a second event.
        assert!(t.on_tcp_close(&close_fixture(3, corr, 1, 1, 0)).is_none());
    }

    /// N3 test #15 — IPv6 connect → close round-trip. The
    /// address-bytes hashing path differs between IPv4 +
    /// IPv6 (v4 is padded to 16 in the hash input); regression
    /// test that the emitted event still carries the proper
    /// IpAddr variant and the flow_id is shaped correctly.
    #[test]
    fn ipv6_flow_close_round_trip() {
        let mut t = FlowTracker::default();
        let v6 = IpAddr::V6("2001:db8::1".parse().unwrap());
        let conn = connect_fixture(7777, 0xAABB, 42, v6, 443);
        t.on_tcp_connect(&conn);
        let corr = FlowTracker::corr_id(conn.start_ns, conn.sk_ptr);
        let evt = t
            .on_tcp_close(&close_fixture(9999, corr, 100, 200, 0))
            .expect("ipv6 close correlates");
        assert_eq!(evt.dst_addr, v6);
        assert_eq!(evt.family, 10);
        assert_eq!(evt.flow_id.len(), 32);
    }

    /// Short-lived flow: the close reaches the tracker before its connect.
    /// With a real destination on the close, the row is synthesised (no
    /// exe) and the late connect is ignored. Lab PR 246: the row starts at
    /// the connect, whose time the correlator carries — the same flow key
    /// (pid, connect time) as a row resolved against its connect.
    #[test]
    fn close_before_connect_synthesises_row_and_ignores_late_connect() {
        let mut t = FlowTracker::default();
        let conn = connect_fixture(1_000_000, 0x00C0_FFEE, 42, v4(10, 0, 0, 9), 4444);
        let corr = FlowTracker::corr_id(conn.start_ns, conn.sk_ptr);
        let mut close = close_fixture(1_000_500, corr, 64, 0, 0);
        close.dst_addr = v4(10, 0, 0, 9);
        close.dst_port = 4444;
        close.pid = 42;
        close.comm = "nnseq".into();
        let evt = t.on_tcp_close(&close).expect("synthesised row");
        assert_eq!(evt.dst_port, 4444);
        assert_eq!(
            (evt.start_ns, evt.end_ns),
            (conn.start_ns, 1_000_500),
            "the connect's time, from the correlator"
        );
        assert_eq!(
            evt.flow_id,
            canonical_flow_id(
                conn.start_ns,
                2,
                close.src_addr,
                close.src_port,
                close.dst_addr,
                4444,
                6,
                42
            )
        );
        assert_eq!(evt.pid, 42);
        assert!(evt.exe.is_none());
        assert_eq!(evt.proc_start_ns, 0, "start unknown");
        assert_eq!(evt.bytes_sent, 64);
        // The connect that arrives afterwards must not open a pending flow.
        t.on_tcp_connect(&conn);
        assert_eq!(
            t.pending_len(),
            0,
            "late connect after a synthesised close must be ignored"
        );
        // Fixture closes without a destination still drop (no 5-tuple).
        assert!(t
            .on_tcp_close(&close_fixture(2, [0x55u8; 16], 0, 0, 0))
            .is_none());
    }

    /// Lab PR 246, the KVM failure of 27/10/2026: a shell's connect to a
    /// loopback port nothing listens on is refused, and the shell closes
    /// the socket at once; the kernel cleared the destination port before
    /// the close (`tcp_disconnect`), and the close reached the tracker
    /// first. Its row — `tcp 127.0.0.1:0 closed` in the record — names
    /// the flow as its connect does, (pid, connect time): the key the
    /// canary trip of that connect owns. It used to start at the close.
    #[test]
    fn a_refused_connect_closed_first_keeps_its_connects_flow_key() {
        let mut t = FlowTracker::default();
        let t0 = 3_000_000_000_000;
        let conn = connect_fixture(t0, 0xFFFF_8880_1234_5678, 9825, v4(127, 0, 0, 1), 41147);
        let corr = FlowTracker::corr_id(conn.start_ns, conn.sk_ptr);
        let mut close = close_fixture(t0 + 40_000, corr, 0, 0, 0);
        close.dst_addr = v4(127, 0, 0, 1);
        close.dst_port = 0;
        close.pid = 9825;
        close.comm = "bash".into();
        let row = t.on_tcp_close(&close).expect("synthesised row");
        assert_eq!((row.pid, row.start_ns), (conn.pid, conn.start_ns));
        assert_eq!((row.dst_addr, row.dst_port), (v4(127, 0, 0, 1), 0));
        assert_eq!(row.phase, FlowPhase::Closed);
        assert!(
            t.on_tcp_connect(&conn).is_none(),
            "no connect-time row after the close"
        );
        // A correlator of time 0 (never written so) keeps the close's time.
        let mut odd = close.clone();
        odd.corr_id = FlowTracker::corr_id(0, 0xAB);
        assert_eq!(t.on_tcp_close(&odd).expect("row").start_ns, t0 + 40_000);
    }

    /// Lab PR 246: a close may be resolved once its connect is on the bus
    /// (announced by the connect pump), or when no connect will come; it
    /// waits otherwise — and never while no connect pump runs.
    #[test]
    fn a_close_waits_until_its_connect_is_announced() {
        let mut t = FlowTracker::default();
        let conn = connect_fixture(7 * S, 0xC1, 501, v4(127, 0, 0, 1), 4444);
        let corr = FlowTracker::corr_id(conn.start_ns, conn.sk_ptr);
        assert!(t.close_may_proceed(&corr), "no connect pump: no wait");
        t.set_connect_pump(true);
        assert!(!t.close_may_proceed(&corr), "the connect is not read yet");
        assert!(t.close_may_proceed(&[0u8; 16]), "a kernel lookup miss");
        t.on_tcp_connect(&conn).expect("connect-time row");
        assert!(
            !t.close_may_proceed(&corr),
            "fed to the tracker, not on the bus yet"
        );
        t.announce(&corr);
        assert!(t.close_may_proceed(&corr));
        // A row already synthesised: its connect is ignored, nothing waits.
        let other = FlowTracker::corr_id(8 * S, 0xC2);
        let mut close = close_fixture(8 * S + 1, other, 0, 0, 0);
        close.dst_addr = v4(127, 0, 0, 1);
        assert!(t.on_tcp_close(&close).is_some());
        assert!(t.close_may_proceed(&other));
        // The pump stops: nothing waits any more.
        let third = FlowTracker::corr_id(9 * S, 0xC3);
        assert!(!t.close_may_proceed(&third));
        t.set_connect_pump(false);
        assert!(t.close_may_proceed(&third));
    }

    const S: u64 = 1_000_000_000;

    /// Lab PR 224 (CM-02 a): the connect hands out the flow's connect-time
    /// row — open, no bytes, the image named at the connect — and the close
    /// still produces the closed row with the same start (the key the
    /// engine's per-flow ledger uses). On the starting tree the connect
    /// returned nothing: an open flow had no row at all.
    #[test]
    fn the_connect_hands_out_an_open_row_and_the_close_a_closed_one() {
        let mut t = FlowTracker::default();
        let conn = connect_fixture(10 * S, 0xA1, 77, v4(127, 0, 0, 1), 4444);
        let row = t.on_tcp_connect(&conn).expect("connect-time row");
        assert_eq!(row.phase, FlowPhase::Connect);
        assert_eq!(row.observed_ns, 10 * S);
        assert_eq!((row.end_ns, row.bytes_sent, row.bytes_recv), (0, 0, 0));
        assert_eq!(row.exe.as_deref(), Some("/usr/bin/curl"));
        assert_eq!((row.dst_port, row.pid), (4444, 77));
        assert!(row.flow_id.is_empty(), "no canonical id before the close");
        let corr = FlowTracker::corr_id(conn.start_ns, conn.sk_ptr);
        let closed = t
            .on_tcp_close(&close_fixture(20 * S, corr, 5, 6, 0))
            .unwrap();
        assert_eq!(closed.phase, FlowPhase::Closed);
        assert_eq!(closed.start_ns, row.start_ns);
        assert_eq!(closed.bytes_sent, 5);
    }

    /// Lab PR 224 (CM-02 b): a flow is snapshotted once open `min_age`,
    /// then every `interval`, never before; closed flows never.
    #[test]
    fn snapshots_follow_the_age_and_the_interval() {
        let mut t = FlowTracker::default();
        let p = SnapshotPolicy::default();
        let conn = connect_fixture(100 * S, 0xB1, 88, v4(127, 0, 0, 2), 8443);
        t.on_tcp_connect(&conn);
        assert!(t.due_snapshots(130 * S, &p).flows.is_empty(), "30 s old");
        let b = t.due_snapshots(160 * S, &p);
        assert_eq!(b.flows.len(), 1);
        let row = &b.flows[0];
        assert_eq!(row.phase, FlowPhase::Snapshot);
        assert_eq!((row.start_ns, row.observed_ns), (100 * S, 160 * S));
        assert_eq!(row.bytes_sent, 0, "no byte counters in a snapshot");
        assert!(
            t.due_snapshots(200 * S, &p).flows.is_empty(),
            "within the interval"
        );
        assert_eq!(t.due_snapshots(220 * S, &p).flows.len(), 1);
        let corr = FlowTracker::corr_id(conn.start_ns, conn.sk_ptr);
        t.on_tcp_close(&close_fixture(230 * S, corr, 0, 0, 0));
        assert!(t.due_snapshots(400 * S, &p).flows.is_empty(), "closed");
    }

    /// Lab PR 224: at most `max_per_tick` per tick, the least recently
    /// snapshotted first; the others are counted and come next.
    #[test]
    fn snapshots_are_bounded_per_tick_oldest_first() {
        let mut t = FlowTracker::default();
        let p = SnapshotPolicy {
            max_per_tick: 2,
            ..SnapshotPolicy::default()
        };
        for i in 0..5u64 {
            t.on_tcp_connect(&connect_fixture(
                i * S,
                0xC0 + i,
                90,
                v4(10, 0, 0, i as u8),
                443,
            ));
        }
        let before = snapshots_deferred_total();
        let first = t.due_snapshots(100 * S, &p);
        assert_eq!((first.flows.len(), first.deferred), (2, 3));
        assert!(snapshots_deferred_total() >= before + 3);
        let second = t.due_snapshots(101 * S, &p);
        assert_eq!(second.flows.len(), 2);
        let third = t.due_snapshots(102 * S, &p);
        assert_eq!((third.flows.len(), third.deferred), (1, 0));
        let mut seen: Vec<u64> = first
            .flows
            .iter()
            .chain(&second.flows)
            .chain(&third.flows)
            .map(|f| f.start_ns)
            .collect();
        seen.sort_unstable();
        assert_eq!(seen, vec![0, S, 2 * S, 3 * S, 4 * S], "every flow, once");
    }

    /// Lab PR 224 (CM-02 c): a refused connect's row; nothing pending.
    #[test]
    fn a_denied_connect_is_a_row_and_nothing_pending() {
        let t = FlowTracker::default();
        let conn = connect_fixture(5 * S, 0, 99, v4(192, 0, 2, 7), 443);
        let row = FlowTracker::denied_row(&conn);
        assert_eq!(row.phase, FlowPhase::Denied);
        assert_eq!(
            (row.start_ns, row.end_ns, row.observed_ns),
            (5 * S, 5 * S, 5 * S)
        );
        assert_eq!(t.pending_len(), 0);
    }

    #[test]
    fn a_longer_snapshot_interval_weakens() {
        assert!(snapshot_value_weakens("120"));
        assert!(snapshot_value_weakens("never"));
        assert!(!snapshot_value_weakens("30"));
        assert!(!snapshot_value_weakens("60"));
    }
}
