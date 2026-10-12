//! Tappa 10 (N2) — outbound UDP flow observation kprobe.
//!
//! Hooked at the entry of `udp_sendmsg(struct sock *sk, struct
//! msghdr *msg, size_t len)`, and of `udpv6_sendmsg` (same signature;
//! review 68: IPv6 destinations left no flow row before). Fires on every
//! UDP send. Emits a [`NetFlowCloseRaw`] (proto=IPPROTO_UDP) into
//! [`NET_UDP_EVENTS`], drained with the TCP closes by the same task (design
//! §13 Q3: a UDP "flow close" is handled like a TCP one). Review 73: the
//! UDP records have their own ring since a UDP flood erased the TCP closes
//! that shared one.
//!
//! DNS (`dport == 53`) is filtered OUT here — the existing
//! Tappa 4 [`crate::dns_query`] kprobe already captures DNS via
//! its own ringbuf with QNAME decoding. Re-emitting DNS as a
//! UDP outbound flow would double-count.
//!
//! ## Destination resolution (review `net-udp-blind-1`)
//!
//! * **Connected** sockets (`connect()` + `send()`): destination from
//!   `sk->__sk_common` (`skc_daddr` / `skc_dport`).
//! * **Unconnected** `sendto()` (`skc_dport == 0`): the destination
//!   lives in `msghdr->msg_name` (already copied to kernel memory by
//!   `__sys_sendto` / `copy_msghdr_from_user`); resolved with the same
//!   [`crate::dns_query::dest_from_msg_name`] walk the DNS sensor
//!   uses. Before this fix such sends were skipped, so QUIC-like
//!   beacons and raw-UDP exfil through an unconnected socket emitted
//!   no network event at all. The local source may still be the
//!   wildcard (`0.0.0.0:0`) when the socket is autobound later in
//!   `udp_sendmsg` — the row still carries pid/comm/uid + destination.
//!
//! ## Aggregation (review 73)
//!
//! Every send, connected or not, is aggregated in the kernel per
//! `(pid, dst addr, dst port)` and per CPU ([`UDP_FLOWS`]). The first send
//! to a destination is emitted at once. Later ones add their bytes, and
//! are emitted with everything pending at most once per
//! [`UDP_EMIT_MIN_INTERVAL_NS`] or as soon as [`UDP_EMIT_MAX_PENDING`]
//! bytes are pending. A chatty socket (QUIC, VoIP, syslog) therefore yields
//! about one row per second per destination, and the rows add up to the
//! bytes sent. The bytes of a flow's last interval wait for its next
//! datagram (at most 1 MiB per key and CPU).
//!
//! UDP has no socket-lifetime "close" event, so the emission
//! carries:
//!   * `flow_id` = zeros (N3 userland synthesises per (pid,
//!     5-tuple) burst window).
//!   * `bytes_sent` = the bytes sent to this destination since the last
//!     emission on this CPU (this send included).
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
    maps::{LruPerCpuHashMap, RingBuf},
    programs::ProbeContext,
};
use northnarrow_common::wire::{NetFlowCloseRaw, ADDR_LEN, TASK_COMM_LEN};

use crate::btf_offsets::{
    SOCK_SKC_DADDR_OFFSET, SOCK_SKC_DPORT_OFFSET, SOCK_SKC_FAMILY_OFFSET, SOCK_SKC_NUM_OFFSET,
    SOCK_SKC_RCV_SADDR_OFFSET, SOCK_SKC_V6_DADDR_OFFSET, SOCK_SKC_V6_RCV_SADDR_OFFSET,
};
use crate::dns_query::dest_from_msg_name;

/// Review 73: UDP flow records have their own ring. They shared
/// `NET_FLOW_CLOSE_EVENTS` with the TCP closes, so a UDP flood that filled
/// it also erased the TCP flows of the same moment.
#[map]
pub static NET_UDP_EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

const AF_INET: u16 = 2;
const AF_INET6: u16 = 10;
const IPPROTO_UDP: u8 = 17;
const DNS_DST_PORT: u16 = 53;

/// Minimum spacing between two emissions for the same `(pid, dst)` key
/// on one CPU. One second: enough to see a beacon cadence and its byte
/// volume per row, cheap enough under a send storm.
const UDP_EMIT_MIN_INTERVAL_NS: u64 = 1_000_000_000;
/// Bytes pending for a key that force an emission before the interval
/// ends, so a large burst is reported while it happens.
const UDP_EMIT_MAX_PENDING: u64 = 1 << 20;
const UDP_FLOWS_MAX_ENTRIES: u32 = 4096;

/// Aggregation key: who, to where.
#[repr(C)]
#[derive(Copy, Clone)]
pub struct UdpDstKey {
    pid: u32,
    port_be: u16,
    family: u8,
    _pad: u8,
    addr: [u8; ADDR_LEN],
}

/// Per `(pid, dst)` and per CPU: the last emission and the bytes sent
/// since. Per CPU, so concurrent senders need no atomics; a key emits at
/// most once per interval on each CPU. LRU-evicted, never pinned.
#[repr(C)]
#[derive(Copy, Clone)]
pub struct UdpAgg {
    last_emit_ns: u64,
    pending_bytes: u64,
}

/// Review 73: every UDP send is aggregated, connected or not. Connected
/// sends used to emit one record each: an unprivileged process sending
/// 146k datagrams/s lost 1.45 M records in 10 s, TCP closes included.
#[map]
static UDP_FLOWS: LruPerCpuHashMap<UdpDstKey, UdpAgg> =
    LruPerCpuHashMap::with_max_entries(UDP_FLOWS_MAX_ENTRIES, 0);

/// Resolved destination for this send.
struct Dst {
    family: u16,
    port_host: u16,
    addr: [u8; ADDR_LEN],
    /// `true` when the destination came from `msg_name` (unconnected
    /// send).
    unconnected: bool,
}

#[kprobe]
pub fn udp_sendmsg_outbound(ctx: ProbeContext) -> u32 {
    let _ = try_udp_sendmsg_outbound(&ctx, false);
    0
}

/// Review 68: the same program on `udpv6_sendmsg` (same signature), so a
/// datagram to an IPv6 destination gives a flow row too. An IPv4-mapped
/// destination (`::ffff:a.b.c.d`) is skipped here: `udpv6_sendmsg` hands
/// it to `udp_sendmsg`, where [`udp_sendmsg_outbound`] records it once.
#[kprobe]
pub fn udpv6_sendmsg_outbound(ctx: ProbeContext) -> u32 {
    let _ = try_udp_sendmsg_outbound(&ctx, true);
    0
}

/// `::ffff:0:0/96`, an IPv4 address carried in an IPv6 one.
#[inline(always)]
fn v4_mapped(addr: &[u8; ADDR_LEN]) -> bool {
    let mut i = 0usize;
    while i < 10 {
        if addr[i] != 0 {
            return false;
        }
        i += 1;
    }
    addr[10] == 0xff && addr[11] == 0xff
}

#[inline(always)]
fn try_udp_sendmsg_outbound(ctx: &ProbeContext, v6: bool) -> Result<(), i64> {
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
    // Review 68: `udp_sendmsg` records the IPv4-mapped destinations.
    if v6 && dst.family == AF_INET6 && v4_mapped(&dst.addr) {
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

    // A DNS *server* answering its clients (systemd-resolved's stub on
    // 127.0.0.53, bind, unbound) is an unconnected sendto FROM port 53 to
    // a fresh client port per query: the (pid, dst) aggregate cannot
    // collapse it and every local lookup would cost a netflow row. Port 53
    // belongs to the DNS sensor in both directions; the listener side is
    // the resolver's own business, not an outbound flow.
    if dst.unconnected && sport_host == DNS_DST_PORT {
        return Ok(());
    }
    // Review 73: aggregate per (pid, dst), connected or not. The first
    // send to a destination is emitted at once; later ones add their bytes
    // and are emitted, with everything pending, at most once per interval
    // or as soon as UDP_EMIT_MAX_PENDING bytes are pending.
    let key = UdpDstKey {
        pid,
        port_be: dst.port_host.to_be(),
        family: dst.family as u8,
        _pad: 0,
        addr: dst.addr,
    };
    let bytes = match UDP_FLOWS.get_ptr_mut(&key) {
        Some(agg) => unsafe {
            let pending = (*agg).pending_bytes.wrapping_add(len);
            if now.wrapping_sub((*agg).last_emit_ns) < UDP_EMIT_MIN_INTERVAL_NS
                && pending < UDP_EMIT_MAX_PENDING
            {
                (*agg).pending_bytes = pending;
                return Ok(());
            }
            (*agg).last_emit_ns = now;
            (*agg).pending_bytes = 0;
            pending
        },
        None => {
            // Best-effort: a failed insert only means another immediate
            // emission on the next send, never a lost one.
            let _ = UDP_FLOWS.insert(
                &key,
                &UdpAgg {
                    last_emit_ns: now,
                    pending_bytes: 0,
                },
                0,
            );
            len
        }
    };

    let mut entry = match NET_UDP_EVENTS.reserve::<NetFlowCloseRaw>(0) {
        Some(e) => e,
        None => {
            crate::drops::bump(northnarrow_common::ring_drops::ring_slot::UDP);
            return Ok(());
        }
    };
    let raw_ptr: *mut NetFlowCloseRaw = entry.as_mut_ptr();
    unsafe {
        crate::zero::zero(raw_ptr);
    }

    let uid_gid = bpf_get_current_uid_gid();
    let comm = bpf_get_current_comm().unwrap_or([0u8; 16]);

    unsafe {
        (*raw_ptr).timestamp_ns = now;
        (*raw_ptr).bytes_sent = bytes;
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
