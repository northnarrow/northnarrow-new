//! Tappa 10 (N2) — outbound UDP flow observation kprobe.
//!
//! Hooked at the entry of `udp_sendmsg(struct sock *sk, struct
//! msghdr *msg, size_t len)`. Fires on every UDP send. Emits a
//! [`NetFlowCloseRaw`] (proto=IPPROTO_UDP) into the shared
//! [`crate::tcp_close::NET_FLOW_CLOSE_EVENTS`] ringbuf — design
//! §13 Q3 LOCK-IN: UDP "flow close" is conceptually equivalent
//! to TCP flow close, so one ringbuf + one drain task. Single
//! source of truth + simpler architecture.
//!
//! DNS (`dport == 53`) is filtered OUT here — the existing
//! Tappa 4 [`crate::dns_query`] kprobe already captures DNS via
//! its own ringbuf with QNAME decoding. Re-emitting DNS as a
//! UDP outbound flow would double-count.
//!
//! ## Destination resolution (review `net-udp-blind-1`)
//!
//! * **Connected** sockets (`connect()` + `send()`): destination from
//!   `sk->__sk_common` (`skc_daddr` / `skc_dport`). Every send emits.
//! * **Unconnected** `sendto()` (`skc_dport == 0`): the destination
//!   lives in `msghdr->msg_name` (already copied to kernel memory by
//!   `__sys_sendto` / `copy_msghdr_from_user`); resolved with the same
//!   [`crate::dns_query::dest_from_msg_name`] walk the DNS sensor
//!   uses. Before this fix such sends were skipped, so QUIC-like
//!   beacons and raw-UDP exfil through an unconnected socket emitted
//!   no network event at all. Unconnected sends are **rate-limited
//!   kernel-side** to one emission per `(pid, dst addr, dst port)`
//!   per [`UDP_UNCONNECTED_MIN_INTERVAL_NS`] (LRU map): a chatty
//!   sendto loop (VoIP, games, syslog) yields one row per second per
//!   destination, not one per datagram. The local source may still be
//!   the wildcard (`0.0.0.0:0`) when the socket is autobound later in
//!   `udp_sendmsg` — the row still carries pid/comm/uid + destination.
//!
//! UDP has no socket-lifetime "close" event, so the emission
//! carries:
//!   * `flow_id` = zeros (N3 userland synthesises per (pid,
//!     5-tuple) burst window).
//!   * `bytes_sent` = `len` arg of this send.
//!   * `bytes_recv` = 0.
//!   * `close_reason` = 0 (UDP has no graceful/RST distinction).
//!
//! Reads `__sk_common` fields via the same validated BTF offsets
//! in [`crate::btf_offsets`] the TCP fexit uses.

use aya_ebpf::{
    helpers::{
        bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_get_current_uid_gid, bpf_ktime_get_ns,
        bpf_probe_read_kernel,
    },
    macros::{kprobe, map},
    maps::LruHashMap,
    programs::ProbeContext,
};
use northnarrow_common::wire::{NetFlowCloseRaw, ADDR_LEN, TASK_COMM_LEN};

use crate::btf_offsets::{
    SOCK_SKC_DADDR_OFFSET, SOCK_SKC_DPORT_OFFSET, SOCK_SKC_FAMILY_OFFSET, SOCK_SKC_NUM_OFFSET,
    SOCK_SKC_RCV_SADDR_OFFSET, SOCK_SKC_V6_DADDR_OFFSET, SOCK_SKC_V6_RCV_SADDR_OFFSET,
};
use crate::dns_query::dest_from_msg_name;
use crate::tcp_close::NET_FLOW_CLOSE_EVENTS;

const AF_INET: u16 = 2;
const AF_INET6: u16 = 10;
const IPPROTO_UDP: u8 = 17;
const DNS_DST_PORT: u16 = 53;

/// Minimum spacing between two emissions for the same unconnected
/// `(pid, dst)` key. One second: enough to see a beacon cadence and
/// its byte volume per row, cheap enough under a sendto storm.
const UDP_UNCONNECTED_MIN_INTERVAL_NS: u64 = 1_000_000_000;
const UDP_UNCONNECTED_SEEN_MAX_ENTRIES: u32 = 4096;

/// Rate-limit key for unconnected sends: who, to where.
#[repr(C)]
#[derive(Copy, Clone)]
pub struct UdpDstKey {
    pid: u32,
    port_be: u16,
    family: u8,
    _pad: u8,
    addr: [u8; ADDR_LEN],
}

/// Last emission time (`bpf_ktime_get_ns`) per unconnected
/// `(pid, dst)`. LRU-evicted, never pinned: a restart starts fresh.
#[map]
static UDP_UNCONNECTED_SEEN: LruHashMap<UdpDstKey, u64> =
    LruHashMap::with_max_entries(UDP_UNCONNECTED_SEEN_MAX_ENTRIES, 0);

/// Resolved destination for this send.
struct Dst {
    family: u16,
    port_host: u16,
    addr: [u8; ADDR_LEN],
    /// `true` when the destination came from `msg_name` (unconnected
    /// send) and is therefore subject to the kernel-side rate limit.
    unconnected: bool,
}

#[kprobe]
pub fn udp_sendmsg_outbound(ctx: ProbeContext) -> u32 {
    let _ = try_udp_sendmsg_outbound(&ctx);
    0
}

#[inline(always)]
fn try_udp_sendmsg_outbound(ctx: &ProbeContext) -> Result<(), i64> {
    let sk_ptr: *const u8 = match ctx.arg(0) {
        Some(p) => p,
        None => return Ok(()),
    };
    if sk_ptr.is_null() {
        return Ok(());
    }
    let msg_ptr: *const u8 = match ctx.arg(1) {
        Some(p) => p,
        None => core::ptr::null(),
    };
    // arg(2) is `size_t len` — the payload bytes the caller is
    // about to send. We use this as a per-emission bytes_sent;
    // N3 accumulates across the (pid, 5-tuple) burst window.
    let len: u64 = match ctx.arg::<usize>(2) {
        Some(v) => v as u64,
        None => 0,
    };

    let sk_family: u16 =
        match unsafe { bpf_probe_read_kernel(sk_ptr.add(off!(SOCK_SKC_FAMILY_OFFSET)) as *const u16) } {
            Ok(v) => v,
            Err(_) => return Ok(()),
        };
    if sk_family != AF_INET && sk_family != AF_INET6 {
        return Ok(());
    }

    let dport_be: u16 =
        match unsafe { bpf_probe_read_kernel(sk_ptr.add(off!(SOCK_SKC_DPORT_OFFSET)) as *const u16) } {
            Ok(v) => v,
            Err(_) => 0,
        };
    let dport_host = u16::from_be(dport_be);

    let dst = if dport_host != 0 {
        // Connected socket: destination lives in the sock.
        let mut addr = [0u8; ADDR_LEN];
        if sk_family == AF_INET {
            let daddr: u32 = match unsafe {
                bpf_probe_read_kernel(sk_ptr.add(off!(SOCK_SKC_DADDR_OFFSET)) as *const u32)
            } {
                Ok(v) => v,
                Err(_) => 0,
            };
            let db = daddr.to_ne_bytes();
            let mut i = 0usize;
            while i < 4 {
                addr[i] = db[i];
                i += 1;
            }
        } else {
            addr = match unsafe {
                bpf_probe_read_kernel(sk_ptr.add(off!(SOCK_SKC_V6_DADDR_OFFSET)) as *const [u8; ADDR_LEN])
            } {
                Ok(v) => v,
                Err(_) => [0u8; ADDR_LEN],
            };
        }
        Dst {
            family: sk_family,
            port_host: dport_host,
            addr,
            unconnected: false,
        }
    } else {
        // Unconnected sendto(): destination lives in msg_name
        // (net-udp-blind-1). No msg_name either → nothing to attribute.
        if msg_ptr.is_null() {
            return Ok(());
        }
        let Some(d) = dest_from_msg_name(msg_ptr)? else {
            return Ok(());
        };
        Dst {
            family: d.family as u16,
            port_host: u16::from_be(d.port_be),
            addr: d.addr,
            unconnected: true,
        }
    };

    // Filter DNS to dst port 53 — the existing dns_query kprobe
    // owns those events (connected AND unconnected shapes).
    if dst.port_host == DNS_DST_PORT {
        return Ok(());
    }

    let sport_host: u16 =
        match unsafe { bpf_probe_read_kernel(sk_ptr.add(off!(SOCK_SKC_NUM_OFFSET)) as *const u16) } {
            Ok(v) => v,
            Err(_) => 0,
        };

    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = (pid_tgid >> 32) as u32;
    let now = unsafe { bpf_ktime_get_ns() };

    if dst.unconnected {
        // A DNS *server* answering its clients (systemd-resolved's
        // stub on 127.0.0.53, bind, unbound) is an unconnected sendto
        // FROM port 53 to a fresh client port per query: the (pid,
        // dst) limiter cannot collapse it and every local lookup would
        // cost a netflow row. Port 53 belongs to the DNS sensor in
        // both directions; the listener side is the resolver's own
        // business, not an outbound flow.
        if sport_host == DNS_DST_PORT {
            return Ok(());
        }
        let key = UdpDstKey {
            pid,
            port_be: dst.port_host.to_be(),
            family: dst.family as u8,
            _pad: 0,
            addr: dst.addr,
        };
        if let Some(last) = unsafe { UDP_UNCONNECTED_SEEN.get(&key) } {
            if now.wrapping_sub(*last) < UDP_UNCONNECTED_MIN_INTERVAL_NS {
                return Ok(());
            }
        }
        // Best-effort: a failed insert only means a possible extra
        // emission on the next send, never a lost one.
        let _ = UDP_UNCONNECTED_SEEN.insert(&key, &now, 0);
    }

    let mut entry = match NET_FLOW_CLOSE_EVENTS.reserve::<NetFlowCloseRaw>(0) {
        Some(e) => e,
        None => return Ok(()),
    };
    let raw_ptr: *mut NetFlowCloseRaw = entry.as_mut_ptr();
    unsafe {
        crate::zero::zero(raw_ptr);
    }

    let uid_gid = bpf_get_current_uid_gid();
    let comm = bpf_get_current_comm().unwrap_or([0u8; 16]);

    unsafe {
        (*raw_ptr).timestamp_ns = now;
        (*raw_ptr).bytes_sent = len;
        (*raw_ptr).bytes_recv = 0;
        // flow_id = zeros by write_bytes above.
        (*raw_ptr).pid = pid;
        (*raw_ptr).uid = (uid_gid & 0xFFFF_FFFF) as u32;
        (*raw_ptr).family = dst.family as u8;
        (*raw_ptr).proto = IPPROTO_UDP;
        (*raw_ptr).close_reason = 0;
        (*raw_ptr).src_port = sport_host;
        (*raw_ptr).dst_port = dst.port_host;

        let src_dst = (*raw_ptr).src_addr.as_mut_ptr();
        let dst_dst = (*raw_ptr).dst_addr.as_mut_ptr();
        let mut i = 0usize;
        while i < ADDR_LEN {
            *dst_dst.add(i) = dst.addr[i];
            i += 1;
        }
        // Local end: from the sock, in the sock's own family. A
        // destination family that differs from the socket's (v6
        // socket, v4 msg_name) leaves the source as the wildcard.
        if dst.family == sk_family {
            if sk_family == AF_INET {
                let saddr: u32 = match bpf_probe_read_kernel(
                    sk_ptr.add(off!(SOCK_SKC_RCV_SADDR_OFFSET)) as *const u32,
                ) {
                    Ok(v) => v,
                    Err(_) => 0,
                };
                let sb = saddr.to_ne_bytes();
                let mut i = 0usize;
                while i < 4 {
                    *src_dst.add(i) = sb[i];
                    i += 1;
                }
            } else {
                let s6: [u8; ADDR_LEN] = match bpf_probe_read_kernel(
                    sk_ptr.add(off!(SOCK_SKC_V6_RCV_SADDR_OFFSET)) as *const [u8; ADDR_LEN],
                ) {
                    Ok(v) => v,
                    Err(_) => [0u8; ADDR_LEN],
                };
                let mut i = 0usize;
                while i < ADDR_LEN {
                    *src_dst.add(i) = s6[i];
                    i += 1;
                }
            }
        }

        let src = comm.as_ptr();
        let cdst = (*raw_ptr).comm.as_mut_ptr();
        let mut i = 0usize;
        while i < TASK_COMM_LEN {
            *cdst.add(i) = *src.add(i);
            i += 1;
        }
    }
    entry.submit(0);
    Ok(())
}
