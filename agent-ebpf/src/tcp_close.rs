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
    cty::c_void,
    helpers::{bpf_get_current_pid_tgid, bpf_get_current_uid_gid, bpf_ktime_get_ns, bpf_probe_read_kernel, generated},
    macros::{fexit, map},
    maps::RingBuf,
    programs::FExitContext,
};
use northnarrow_common::wire::{NetFlowCloseRaw, ADDR_LEN, NET_FLOW_CLOSE_EVENTS_BYTES};

use crate::btf_offsets::{
    INET_SOCK_INET_SPORT_OFFSET, SOCK_SKC_DADDR_OFFSET, SOCK_SKC_DPORT_OFFSET, SOCK_SKC_FAMILY_OFFSET, SOCK_SKC_NUM_OFFSET,
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
    // SAFETY: the socket is the hook's argument, read only through the probe
    // helper (a fault is 0, as each field's default); the flow id is two
    // aligned words of the map's value, copied before the entry is removed;
    // the record is this run's reserved ring entry, zeroed before any field is
    // written, the addresses and the `comm` written into it by the helpers
    // (which zero what they fail to read).
    unsafe {
        // arg(0) of tcp_close(struct sock *sk, long timeout) is the
        // sock pointer. The fexit context's arg() is unsafe — caller
        // promises the kernel function signature matches.
        let sk_ptr: *const u8 = ctx.arg::<*const u8>(0);
        if sk_ptr.is_null() {
            return Ok(());
        }
        let sk_key: u64 = sk_ptr as u64;

        // Family — skip non-IPv4/v6 early.
        let family: u16 = match bpf_probe_read_kernel(sk_ptr.add(off!(SOCK_SKC_FAMILY_OFFSET)) as *const u16)
        {
            Ok(v) => v,
            Err(_) => return Ok(()),
        };
        if family != AF_INET && family != AF_INET6 {
            return Ok(());
        }

        // Lot 275: an outbound socket whose first send never came is no longer
        // a ClientHello candidate (the next socket at this address is not it).
        crate::tls_hello::forget(sk_key);
        // Review 79: only a socket the connect kprobe recorded has a flow to
        // close on this ring. Every passive socket (listeners, accepted peers)
        // and every connect that predates the agent missed FLOW_SOCK_MAP, and
        // userland dropped those records ("not recorded"): sending them only let
        // an inbound connection flood fill this ring and push out the closes of
        // outbound flows, the ones the flow rules judge. Lot 275: an accepted
        // socket the inbound sensor recorded has its close on its own ring
        // (`crate::inbound`), never this one.
        // Lot 1.4b (stack): the flow id copied as two words — a byte-wise copy
        // of the `[u8; 16]` kept each byte in a stack slot of its own (the
        // program's frame was 448 of the verifier's 512 bytes). A map value is
        // 8-byte aligned (the kernel rounds the key up to 8 before it).
        let (corr_lo, corr_hi) = match FLOW_SOCK_MAP.get_ptr(&sk_key) {
            Some(c) => {
                let w = c as *const u64;
                (core::ptr::read_volatile(w), core::ptr::read_volatile(w.add(1)))
            }
            None => {
                crate::inbound::close(sk_ptr, family);
                return Ok(());
            }
        };
        // Forget the socket before anything can fail: an entry left behind by
        // a full ring would be found again by the next socket the slab puts at
        // this address (an accepted peer, typically), and its close would pass
        // for an outbound flow's.
        if FLOW_SOCK_MAP.remove(&sk_key).is_ok() {
            crate::tcp_connect::count_flow_sock(northnarrow_common::wire::flow_sock_slot::REMOVED);
        }

        // Reserve a slot before the field-read avalanche; if the
        // ringbuf is full we drop the event cheaply.
        let mut entry = match NET_FLOW_CLOSE_EVENTS.reserve::<NetFlowCloseRaw>(0) {
            Some(e) => e,
            None => {
                crate::drops::bump(northnarrow_common::ring_drops::ring_slot::TCP_CLOSE);
                return Ok(());
            }
        };
        let raw_ptr: *mut NetFlowCloseRaw = entry.as_mut_ptr();
        crate::zero::zero(raw_ptr);

        // Byte counters from tcp_sock (sock is the prefix; sk_ptr
        // doubles as tcp_sock pointer).
        let bytes_sent: u64 =
            match bpf_probe_read_kernel(sk_ptr.add(off!(TCP_SOCK_BYTES_SENT_OFFSET)) as *const u64) {
                Ok(v) => v,
                Err(_) => 0,
            };
        let bytes_recv: u64 =
            match bpf_probe_read_kernel(sk_ptr.add(off!(TCP_SOCK_BYTES_RECEIVED_OFFSET)) as *const u64) {
                Ok(v) => v,
                Err(_) => 0,
            };

        // Ports + addrs from sock_common.
        let dport_be: u16 = match bpf_probe_read_kernel(sk_ptr.add(off!(SOCK_SKC_DPORT_OFFSET)) as *const u16)
        {
            Ok(v) => v,
            Err(_) => 0,
        };
        let mut sport_host: u16 =
            match bpf_probe_read_kernel(sk_ptr.add(off!(SOCK_SKC_NUM_OFFSET)) as *const u16) {
                Ok(v) => v,
                Err(_) => 0,
            };
        // An abortive close (RST, SO_LINGER 0) has released the port by the
        // fexit — `inet_put_port` zeroes `skc_num` — but `inet_sport` keeps
        // it (network byte order).
        if sport_host == 0 {
            if let Ok(v) = bpf_probe_read_kernel(
                sk_ptr.add(off!(INET_SOCK_INET_SPORT_OFFSET)) as *const u16,
            ) {
                sport_host = u16::from_be(v);
            }
        }
        // sk_err — sign-extended i32 stored in network code as positive
        // errno values; treat as u32 for bit math.
        let sk_err_raw: u32 = match bpf_probe_read_kernel(sk_ptr.add(off!(SOCK_SK_ERR_OFFSET)) as *const u32)
        {
            Ok(v) => v,
            Err(_) => 0,
        };
        let close_reason: u8 = (sk_err_raw & 0xFF) as u8;

        let pid_tgid = bpf_get_current_pid_tgid();
        let uid_gid = bpf_get_current_uid_gid();

        (*raw_ptr).timestamp_ns = bpf_ktime_get_ns();
        (*raw_ptr).bytes_sent = bytes_sent;
        (*raw_ptr).bytes_recv = bytes_recv;
        let flow = (*raw_ptr).flow_id.as_mut_ptr() as *mut u64;
        core::ptr::write_volatile(flow, corr_lo);
        core::ptr::write_volatile(flow.add(1), corr_hi);
        (*raw_ptr).pid = (pid_tgid >> 32) as u32;
        (*raw_ptr).uid = (uid_gid & 0xFFFF_FFFF) as u32;
        (*raw_ptr).family = family as u8;
        (*raw_ptr).proto = IPPROTO_TCP;
        (*raw_ptr).close_reason = close_reason;
        (*raw_ptr).src_port = sport_host;
        (*raw_ptr).dst_port = u16::from_be(dport_be);

        // Addresses — v4 OR v6 per family, read by the helper straight into
        // the record (lot 1.4b: no stack copy, no byte loop). The record was
        // zeroed above, and the helper zeroes what it fails to read: a v4
        // address fills the first 4 bytes, the other 12 stay 0, as before.
        let src_dst = (*raw_ptr).src_addr.as_mut_ptr() as *mut c_void;
        let dst_dst = (*raw_ptr).dst_addr.as_mut_ptr() as *mut c_void;
        if family == AF_INET {
            let _ = generated::bpf_probe_read_kernel(
                src_dst,
                4,
                sk_ptr.add(off!(SOCK_SKC_RCV_SADDR_OFFSET)) as *const c_void,
            );
            let _ = generated::bpf_probe_read_kernel(dst_dst, 4, sk_ptr.add(off!(SOCK_SKC_DADDR_OFFSET)) as *const c_void);
        } else {
            let _ = generated::bpf_probe_read_kernel(
                src_dst,
                ADDR_LEN as u32,
                sk_ptr.add(off!(SOCK_SKC_V6_RCV_SADDR_OFFSET)) as *const c_void,
            );
            let _ = generated::bpf_probe_read_kernel(
                dst_dst,
                ADDR_LEN as u32,
                sk_ptr.add(off!(SOCK_SKC_V6_DADDR_OFFSET)) as *const c_void,
            );
        }

        // comm, straight into the zeroed record (`crate::comm`: no `memset`)
        crate::comm::comm_into(&mut (*raw_ptr).comm);

        entry.submit(0);
        Ok(())
    }
}
