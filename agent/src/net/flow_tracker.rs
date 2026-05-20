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
//! ## Bounded memory
//!
//! Per §6.1: a `PendingFlow` open > 24 h gets emitted as a
//! long-lived snapshot. V1.0 ships a simpler "FIFO eviction
//! when over capacity" bound — the 24-hour snapshot is N3.1.
//! Eviction order is insertion-time (oldest evicted first).
//! Default capacity = 65,536 pending flows — generous enough
//! that ordinary hosts never evict, small enough that pathological
//! kernel-leak / sk_ptr-reuse scenarios stay bounded.

use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;

use common::wire::{NetFlowEvent, TlsFingerprint};
use sha2::{Digest, Sha256};

/// Default ceiling on simultaneous in-flight (connect-seen,
/// close-not-yet) flows. Eviction is FIFO past this point.
pub const DEFAULT_PENDING_CAPACITY: usize = 65_536;

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
}

/// Input describing a TCP close observation (N2
/// `NetFlowCloseRaw` with `proto == IPPROTO_TCP`). `corr_id`
/// is the 16-byte FLOW_SOCK_MAP lookup the fexit emits.
#[derive(Debug, Clone)]
pub struct TcpCloseInfo {
    pub end_ns: u64,
    pub corr_id: CorrId,
    pub bytes_sent: u64,
    pub bytes_recv: u64,
    /// Low 8 bits of `sock->sk_err` at fexit. 0 = graceful
    /// FIN; 104 = ECONNRESET; 110 = ETIMEDOUT.
    pub close_reason: u8,
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
}

#[derive(Debug, Clone)]
struct PendingFlow {
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
}

/// In-process tracker for TCP flow correlation + UDP per-send
/// emission. Holds a bounded map of `corr_id → PendingFlow`
/// plus a FIFO eviction queue. Single-threaded today; callers
/// that need cross-thread access wrap it in
/// `Arc<parking_lot::Mutex<FlowTracker>>` (the future N7
/// admin-CLI `net flows` path will).
#[derive(Debug)]
pub struct FlowTracker {
    pending: HashMap<CorrId, PendingFlow>,
    /// Insertion-order queue for FIFO eviction past `capacity`.
    /// Held alongside `pending`; both invariants checked in
    /// [`Self::evict_to_capacity`].
    eviction: VecDeque<CorrId>,
    capacity: usize,
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
            eviction: VecDeque::new(),
            capacity,
        }
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

    /// Register a TCP connect observation. The pending entry
    /// stays in the map until a matching [`Self::on_tcp_close`]
    /// arrives (or FIFO eviction kicks in past `capacity`).
    pub fn on_tcp_connect(&mut self, info: &TcpConnectInfo) {
        let key = Self::corr_id(info.start_ns, info.sk_ptr);
        // If the same corr_id is re-inserted (kernel sk_ptr
        // re-use + same start_ns — extremely unlikely but
        // possible), replace + don't double-enqueue: pull the
        // prior position out so the queue stays in correct
        // FIFO order.
        if self.pending.contains_key(&key) {
            self.eviction.retain(|k| k != &key);
        }
        self.pending.insert(
            key,
            PendingFlow {
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
            },
        );
        self.eviction.push_back(key);
        self.evict_to_capacity();
    }

    /// Resolve a TCP close observation against the pending map.
    /// `Some(NetFlowEvent)` on a successful correlation; `None`
    /// when the close has no matching pending entry (orphan
    /// close — happens at agent boot when the connect predated
    /// the agent, or after FIFO eviction). Defensive callers
    /// log + drop the orphan.
    pub fn on_tcp_close(&mut self, info: &TcpCloseInfo) -> Option<NetFlowEvent> {
        // Zero corr_id = kernel-side FLOW_SOCK_MAP lookup miss
        // (LRU evicted the entry between connect + close). Same
        // outcome as an orphan close — drop on the floor.
        if info.corr_id == [0u8; 16] {
            return None;
        }
        let pending = self.pending.remove(&info.corr_id)?;
        // Pull the corr_id out of the eviction queue so it
        // doesn't carry a phantom slot. Linear scan but only
        // runs at close time + the queue is bounded by
        // `capacity`.
        self.eviction.retain(|k| k != &info.corr_id);
        let flow_id = canonical_flow_id(
            pending.start_ns,
            pending.family,
            pending.src_addr,
            pending.src_port,
            pending.dst_addr,
            pending.dst_port,
            pending.proto,
            pending.pid,
        );
        Some(NetFlowEvent {
            start_ns: pending.start_ns,
            end_ns: info.end_ns,
            family: pending.family,
            src_addr: pending.src_addr,
            src_port: pending.src_port,
            dst_addr: pending.dst_addr,
            dst_port: pending.dst_port,
            proto: pending.proto,
            pid: pending.pid,
            uid: pending.uid,
            comm: pending.comm,
            exe: pending.exe,
            bytes_sent: info.bytes_sent,
            bytes_recv: info.bytes_recv,
            resolved_hostname: None,
            tls_fingerprint: None,
            flow_id,
            close_reason: info.close_reason,
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
            bytes_sent: info.bytes_sent,
            bytes_recv: 0,
            resolved_hostname: None,
            tls_fingerprint: None,
            flow_id,
            // UDP has no close-reason semantics.
            close_reason: 0,
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

    fn evict_to_capacity(&mut self) {
        while self.pending.len() > self.capacity {
            // Drop the oldest entry. `pop_front` matches the
            // FIFO contract callers + tests rely on.
            if let Some(oldest) = self.eviction.pop_front() {
                self.pending.remove(&oldest);
            } else {
                break;
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
        }
    }

    fn close_fixture(end_ns: u64, corr: CorrId, sent: u64, recv: u64, reason: u8) -> TcpCloseInfo {
        TcpCloseInfo {
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
        assert_eq!(t.pending_len(), 0, "pending entry must be drained on close");
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
        };
        let evt = t.on_udp_send(&udp);
        assert_eq!(evt.proto, 17);
        assert_eq!(evt.bytes_sent, 56);
        assert_eq!(evt.bytes_recv, 0);
        assert_eq!(evt.dst_addr, v4(8, 8, 8, 8));
        assert_eq!(evt.start_ns, 5_000);
        assert_eq!(evt.end_ns, 5_000, "UDP record has zero duration in V1.0");
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

    /// N3 test #12 — past capacity, the oldest pending entry
    /// is evicted first. A subsequent close on the evicted
    /// flow returns `None` (correctly reported as an orphan);
    /// the NEWER flow still correlates.
    #[test]
    fn flow_tracker_bounded_memory_evicts_oldest_when_full() {
        let mut t = FlowTracker::with_capacity(2);
        let c1 = connect_fixture(1, 1, 1, v4(1, 1, 1, 1), 80);
        let c2 = connect_fixture(2, 2, 2, v4(2, 2, 2, 2), 80);
        let c3 = connect_fixture(3, 3, 3, v4(3, 3, 3, 3), 80);
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

    /// N3 test #13 — eviction preserves the more recent
    /// entries; it must not knock out a brand-new pending
    /// flow added concurrently with an at-capacity buffer.
    /// Anchors the FIFO contract.
    #[test]
    fn flow_tracker_eviction_preserves_recent_pending() {
        let mut t = FlowTracker::with_capacity(3);
        for i in 1..=5 {
            let c = connect_fixture(i, i, i as u32, v4(i as u8, 0, 0, 1), 80);
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
}
