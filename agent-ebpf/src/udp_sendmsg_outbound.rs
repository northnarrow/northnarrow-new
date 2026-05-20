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
    macros::kprobe,
    programs::ProbeContext,
};
use northnarrow_common::wire::{NetFlowCloseRaw, ADDR_LEN, TASK_COMM_LEN};

use crate::btf_offsets::{
    SOCK_SKC_DADDR_OFFSET, SOCK_SKC_DPORT_OFFSET, SOCK_SKC_FAMILY_OFFSET, SOCK_SKC_NUM_OFFSET,
    SOCK_SKC_RCV_SADDR_OFFSET, SOCK_SKC_V6_DADDR_OFFSET, SOCK_SKC_V6_RCV_SADDR_OFFSET,
};
use crate::tcp_close::NET_FLOW_CLOSE_EVENTS;

const AF_INET: u16 = 2;
const AF_INET6: u16 = 10;
const IPPROTO_UDP: u8 = 17;
const DNS_DST_PORT: u16 = 53;

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
    // arg(2) is `size_t len` — the payload bytes the caller is
    // about to send. We use this as a per-emission bytes_sent;
    // N3 accumulates across the (pid, 5-tuple) burst window.
    let len: u64 = match ctx.arg::<usize>(2) {
        Some(v) => v as u64,
        None => 0,
    };

    let family: u16 =
        match unsafe { bpf_probe_read_kernel(sk_ptr.add(SOCK_SKC_FAMILY_OFFSET) as *const u16) } {
            Ok(v) => v,
            Err(_) => return Ok(()),
        };
    if family != AF_INET && family != AF_INET6 {
        return Ok(());
    }

    // Filter DNS to dst port 53 — the existing dns_query kprobe
    // owns those events.
    let dport_be: u16 =
        match unsafe { bpf_probe_read_kernel(sk_ptr.add(SOCK_SKC_DPORT_OFFSET) as *const u16) } {
            Ok(v) => v,
            Err(_) => 0,
        };
    let dport_host = u16::from_be(dport_be);
    if dport_host == DNS_DST_PORT {
        return Ok(());
    }
    // Skip unconnected sends (dport == 0) — the kernel passes the
    // dest via msghdr in that case, which requires another read
    // and another offset; out of N2 scope (V1.1 enrichment).
    if dport_host == 0 {
        return Ok(());
    }

    let mut entry = match NET_FLOW_CLOSE_EVENTS.reserve::<NetFlowCloseRaw>(0) {
        Some(e) => e,
        None => return Ok(()),
    };
    let raw_ptr: *mut NetFlowCloseRaw = entry.as_mut_ptr();
    unsafe {
        core::ptr::write_bytes(raw_ptr, 0u8, 1);
    }

    let sport_host: u16 =
        match unsafe { bpf_probe_read_kernel(sk_ptr.add(SOCK_SKC_NUM_OFFSET) as *const u16) } {
            Ok(v) => v,
            Err(_) => 0,
        };

    let pid_tgid = bpf_get_current_pid_tgid();
    let uid_gid = bpf_get_current_uid_gid();
    let comm = bpf_get_current_comm().unwrap_or([0u8; 16]);

    unsafe {
        (*raw_ptr).timestamp_ns = bpf_ktime_get_ns();
        (*raw_ptr).bytes_sent = len;
        (*raw_ptr).bytes_recv = 0;
        // flow_id = zeros by write_bytes above.
        (*raw_ptr).pid = (pid_tgid >> 32) as u32;
        (*raw_ptr).uid = (uid_gid & 0xFFFF_FFFF) as u32;
        (*raw_ptr).family = family as u8;
        (*raw_ptr).proto = IPPROTO_UDP;
        (*raw_ptr).close_reason = 0;
        (*raw_ptr).src_port = sport_host;
        (*raw_ptr).dst_port = dport_host;

        let src_dst = (*raw_ptr).src_addr.as_mut_ptr();
        let dst_dst = (*raw_ptr).dst_addr.as_mut_ptr();
        if family == AF_INET {
            let saddr: u32 =
                match bpf_probe_read_kernel(sk_ptr.add(SOCK_SKC_RCV_SADDR_OFFSET) as *const u32) {
                    Ok(v) => v,
                    Err(_) => 0,
                };
            let daddr: u32 =
                match bpf_probe_read_kernel(sk_ptr.add(SOCK_SKC_DADDR_OFFSET) as *const u32) {
                    Ok(v) => v,
                    Err(_) => 0,
                };
            let sb = saddr.to_ne_bytes();
            let db = daddr.to_ne_bytes();
            let mut i = 0usize;
            while i < 4 {
                *src_dst.add(i) = sb[i];
                *dst_dst.add(i) = db[i];
                i += 1;
            }
            while i < ADDR_LEN {
                *src_dst.add(i) = 0;
                *dst_dst.add(i) = 0;
                i += 1;
            }
        } else {
            let s6: [u8; ADDR_LEN] = match bpf_probe_read_kernel(
                sk_ptr.add(SOCK_SKC_V6_RCV_SADDR_OFFSET) as *const [u8; ADDR_LEN],
            ) {
                Ok(v) => v,
                Err(_) => [0u8; ADDR_LEN],
            };
            let d6: [u8; ADDR_LEN] = match bpf_probe_read_kernel(
                sk_ptr.add(SOCK_SKC_V6_DADDR_OFFSET) as *const [u8; ADDR_LEN],
            ) {
                Ok(v) => v,
                Err(_) => [0u8; ADDR_LEN],
            };
            let mut i = 0usize;
            while i < ADDR_LEN {
                *src_dst.add(i) = s6[i];
                *dst_dst.add(i) = d6[i];
                i += 1;
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
