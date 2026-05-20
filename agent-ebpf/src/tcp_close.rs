//! Tappa 10 (N2) — TCP close fexit. Emits accurate byte counters
//! at the moment the kernel finishes draining a TCP socket.
//!
//! Hook: `fexit` on `tcp_close(struct sock *sk, long timeout)`.
//!
//! Owner decision §13 Q5: **fexit chosen over kprobe** for byte
//! counter accuracy. `tcp_close()` flushes pending tx/rx during
//! its execution; reading `tp->bytes_sent` / `tp->bytes_received`
//! at fexit captures those flushes. A kprobe at entry would miss
//! them. The trade-off is that fexit only attaches on kernel 5.5+
//! (BTF-aware fexit programs); the production target (6.8.x)
//! satisfies that, recorded in the deploy runbook.
//!
//! Emission shape: [`NetFlowCloseRaw`] (unified TCP + UDP), with:
//!   * `flow_id` looked up from
//!     [`crate::tcp_connect::FLOW_SOCK_MAP`] keyed by `sk_ptr`.
//!     Zero-filled when the lookup misses (sub-ms connect→close
//!     races, or LRU-evicted flows on a busy host).
//!   * `bytes_sent` / `bytes_recv` from `tcp_sock` fields via the
//!     validated BTF offsets in [`crate::btf_offsets`].
//!   * `close_reason` = low 8 bits of `sk->sk_err`. 0 = graceful
//!     FIN; 104 (ECONNRESET) = RST received; 110 (ETIMEDOUT) =
//!     keepalive timeout. Operator-readable via `nn-admin net
//!     flows`.

use aya_ebpf::{
    helpers::{
        bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_get_current_uid_gid, bpf_ktime_get_ns,
        bpf_probe_read_kernel,
    },
    macros::{fexit, map},
    maps::RingBuf,
    programs::FExitContext,
};
use northnarrow_common::wire::{
    NetFlowCloseRaw, ADDR_LEN, NET_FLOW_CLOSE_EVENTS_BYTES, TASK_COMM_LEN,
};

use crate::btf_offsets::{
    SOCK_SKC_DADDR_OFFSET, SOCK_SKC_DPORT_OFFSET, SOCK_SKC_FAMILY_OFFSET, SOCK_SKC_NUM_OFFSET,
    SOCK_SKC_RCV_SADDR_OFFSET, SOCK_SKC_V6_DADDR_OFFSET, SOCK_SKC_V6_RCV_SADDR_OFFSET,
    SOCK_SK_ERR_OFFSET, TCP_SOCK_BYTES_RECEIVED_OFFSET, TCP_SOCK_BYTES_SENT_OFFSET,
};
use crate::tcp_connect::FLOW_SOCK_MAP;

/// Tappa 10 (N2) — shared ringbuf for TCP fexit + UDP outbound
/// kprobe close events (design §13 Q3 lock-in: one ringbuf,
/// one drain task).
#[map]
pub static NET_FLOW_CLOSE_EVENTS: RingBuf = RingBuf::with_byte_size(NET_FLOW_CLOSE_EVENTS_BYTES, 0);

const AF_INET: u16 = 2;
const AF_INET6: u16 = 10;
const IPPROTO_TCP: u8 = 6;

#[fexit(function = "tcp_close")]
pub fn tcp_close(ctx: FExitContext) -> u32 {
    let _ = unsafe { try_tcp_close(&ctx) };
    0
}

#[inline(always)]
unsafe fn try_tcp_close(ctx: &FExitContext) -> Result<(), i64> {
    // arg(0) of tcp_close(struct sock *sk, long timeout) is the
    // sock pointer. The fexit context's arg() is unsafe — caller
    // promises the kernel function signature matches.
    let sk_ptr: *const u8 = ctx.arg::<*const u8>(0);
    if sk_ptr.is_null() {
        return Ok(());
    }
    let sk_key: u64 = sk_ptr as u64;

    // Family — skip non-IPv4/v6 early.
    let family: u16 = match bpf_probe_read_kernel(sk_ptr.add(SOCK_SKC_FAMILY_OFFSET) as *const u16)
    {
        Ok(v) => v,
        Err(_) => return Ok(()),
    };
    if family != AF_INET && family != AF_INET6 {
        return Ok(());
    }

    // Reserve a slot before the field-read avalanche; if the
    // ringbuf is full we drop the event cheaply.
    let mut entry = match NET_FLOW_CLOSE_EVENTS.reserve::<NetFlowCloseRaw>(0) {
        Some(e) => e,
        None => return Ok(()),
    };
    let raw_ptr: *mut NetFlowCloseRaw = entry.as_mut_ptr();
    core::ptr::write_bytes(raw_ptr, 0u8, 1);

    // Byte counters from tcp_sock (sock is the prefix; sk_ptr
    // doubles as tcp_sock pointer).
    let bytes_sent: u64 =
        match bpf_probe_read_kernel(sk_ptr.add(TCP_SOCK_BYTES_SENT_OFFSET) as *const u64) {
            Ok(v) => v,
            Err(_) => 0,
        };
    let bytes_recv: u64 =
        match bpf_probe_read_kernel(sk_ptr.add(TCP_SOCK_BYTES_RECEIVED_OFFSET) as *const u64) {
            Ok(v) => v,
            Err(_) => 0,
        };

    // Ports + addrs from sock_common.
    let dport_be: u16 = match bpf_probe_read_kernel(sk_ptr.add(SOCK_SKC_DPORT_OFFSET) as *const u16)
    {
        Ok(v) => v,
        Err(_) => 0,
    };
    let sport_host: u16 = match bpf_probe_read_kernel(sk_ptr.add(SOCK_SKC_NUM_OFFSET) as *const u16)
    {
        Ok(v) => v,
        Err(_) => 0,
    };
    // sk_err — sign-extended i32 stored in network code as positive
    // errno values; treat as u32 for bit math.
    let sk_err_raw: u32 = match bpf_probe_read_kernel(sk_ptr.add(SOCK_SK_ERR_OFFSET) as *const u32)
    {
        Ok(v) => v,
        Err(_) => 0,
    };
    let close_reason: u8 = (sk_err_raw & 0xFF) as u8;

    let pid_tgid = bpf_get_current_pid_tgid();
    let uid_gid = bpf_get_current_uid_gid();
    let comm = bpf_get_current_comm().unwrap_or([0u8; 16]);

    // flow_id from FLOW_SOCK_MAP[sk_ptr]. LRU miss leaves zeros.
    let corr_opt = FLOW_SOCK_MAP.get(&sk_key);
    let corr: [u8; 16] = match corr_opt {
        Some(c) => *c,
        None => [0u8; 16],
    };

    (*raw_ptr).timestamp_ns = bpf_ktime_get_ns();
    (*raw_ptr).bytes_sent = bytes_sent;
    (*raw_ptr).bytes_recv = bytes_recv;
    (*raw_ptr).flow_id = corr;
    (*raw_ptr).pid = (pid_tgid >> 32) as u32;
    (*raw_ptr).uid = (uid_gid & 0xFFFF_FFFF) as u32;
    (*raw_ptr).family = family as u8;
    (*raw_ptr).proto = IPPROTO_TCP;
    (*raw_ptr).close_reason = close_reason;
    (*raw_ptr).src_port = sport_host;
    (*raw_ptr).dst_port = u16::from_be(dport_be);

    // Addresses — v4 OR v6 per family.
    let src_dst = (*raw_ptr).src_addr.as_mut_ptr();
    let dst_dst = (*raw_ptr).dst_addr.as_mut_ptr();
    if family == AF_INET {
        let saddr: u32 =
            match bpf_probe_read_kernel(sk_ptr.add(SOCK_SKC_RCV_SADDR_OFFSET) as *const u32) {
                Ok(v) => v,
                Err(_) => 0,
            };
        let daddr: u32 = match bpf_probe_read_kernel(sk_ptr.add(SOCK_SKC_DADDR_OFFSET) as *const u32)
        {
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
            sk_ptr.add(SOCK_SKC_V6_DADDR_OFFSET) as *const [u8; ADDR_LEN]
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

    // comm
    let src = comm.as_ptr();
    let cdst = (*raw_ptr).comm.as_mut_ptr();
    let mut i = 0usize;
    while i < TASK_COMM_LEN {
        *cdst.add(i) = *src.add(i);
        i += 1;
    }

    // Drop the FLOW_SOCK_MAP entry on close so the LRU has room
    // for the next flow on this sk slot. Best-effort; ignore err.
    let _ = FLOW_SOCK_MAP.remove(&sk_key);

    entry.submit(0);
    Ok(())
}
