//! Outbound TCP connect sensor (kprobe).
//!
//! Hooked at the entry of `tcp_v4_connect(struct sock *sk, struct
//! sockaddr *uaddr, int addr_len)` and the v6 equivalent. The
//! `sockaddr` argument carries the destination — the kernel has
//! already copied it in from userspace by the time this function
//! is called, so a kernel-space probe read is safe.
//!
//! Source address/port are intentionally left zero: at this entry
//! point the local end has not been bound yet, so reading
//! `sk->sk_rcv_saddr` would just yield the unconnected wildcard
//! and require a (BTF-dependent) struct field offset.
//!
//! Tappa 10 (N2) — extended to:
//!   * Emit the kernel `struct sock *` pointer in
//!     [`TcpConnectRaw::sk_ptr`] so userland can correlate this
//!     connect event with the later `NetFlowCloseRaw` emitted by
//!     the `tcp_close` fexit (which carries the `flow_id` looked
//!     up from `FLOW_SOCK_MAP[sk_ptr]`).
//!   * Write `FLOW_SOCK_MAP[sk_ptr] = corr_id` so the `tcp_close`
//!     fexit can read the correlation ID back out. The corr_id
//!     is `[timestamp_ns_le_bytes; 8] || [sk_ptr_le_bytes; 8]`
//!     — kernel-side derivable, unique per (sk, connect-time).
//!     Userland is NOT expected to interpret these bytes; it
//!     just matches them against the same 16-byte payload the
//!     tcp_close emission carries.
//!
//! This Q2-explicit scope deviation (modifying a T4 program from
//! an N2 commit) is required to complete the flow tracking chain
//! — `tcp_close` cannot function without a write-side counterpart
//! in the connect kprobes. Documented in the N2 commit message.

use aya_ebpf::{
    helpers::{
        bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_get_current_uid_gid, bpf_ktime_get_ns,
        bpf_probe_read_kernel,
    },
    macros::{kprobe, map},
    maps::{LruHashMap, PerCpuArray, RingBuf},
    programs::ProbeContext,
};
use northnarrow_common::wire::{
    flow_sock_slot, TcpConnectRaw, ADDR_LEN, FLOW_SOCK_COUNT_SLOTS, FLOW_SOCK_MAP_MAX_ENTRIES,
    TASK_COMM_LEN,
};

/// Also written by the `socket_connect` deny (`socket_connect.rs`): a
/// refused connect is a record of this ring with `tcp_connect_flags::DENIED`.
#[map]
pub(crate) static TCP_CONNECT_EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

/// Tappa 10 (N2) — `FLOW_SOCK_MAP`. Key = kernel `struct sock *`
/// (cast to u64), value = 16-byte correlation ID. Populated by
/// this connect kprobe at flow start, read by the `tcp_close`
/// fexit at flow end. LRU eviction bounds the per-flow kernel
/// state under DDoS (65,536 entries since lab PR 164, see
/// `FLOW_SOCK_MAP_MAX_ENTRIES`).
#[map]
pub static FLOW_SOCK_MAP: LruHashMap<u64, [u8; 16]> =
    LruHashMap::with_max_entries(FLOW_SOCK_MAP_MAX_ENTRIES, 0);

/// Lab PR 164 — sockets entered into and taken out of [`FLOW_SOCK_MAP`]
/// (`northnarrow_common::wire::flow_sock_slot`), read by the agent for
/// `nn-admin net status`: an LRU does not report its evictions.
#[map]
pub static FLOW_SOCK_COUNTS: PerCpuArray<u64> =
    PerCpuArray::with_max_entries(FLOW_SOCK_COUNT_SLOTS, 0);

/// `BPF_NOEXIST` (uapi): insert only a key that is not there yet.
const BPF_NOEXIST: u64 = 1;

/// Count one event in [`FLOW_SOCK_COUNTS`] (per-CPU, no atomics).
#[inline(always)]
pub(crate) fn count_flow_sock(slot: u32) {
    if let Some(c) = FLOW_SOCK_COUNTS.get_ptr_mut(slot) {
        // SAFETY: per-CPU slot owned by this CPU while the program runs;
        // the verifier bounds `slot` against the map size.
        unsafe { *c = (*c).wrapping_add(1) };
    }
}

/// Remember `sk_ptr`'s flow for its close. A new socket is counted; a
/// socket connecting again (after a failed connect) has its entry
/// overwritten, as before. Best-effort: a full LRU drops its oldest entry.
#[inline(always)]
fn remember_flow_sock(sk_ptr: u64, corr: &[u8; 16]) {
    if FLOW_SOCK_MAP.insert(&sk_ptr, corr, BPF_NOEXIST).is_ok() {
        count_flow_sock(flow_sock_slot::INSERTED);
    } else {
        let _ = FLOW_SOCK_MAP.insert(&sk_ptr, corr, 0);
    }
}

/// Build the 16-byte correlation ID for `FLOW_SOCK_MAP`. Layout:
///   bytes 0..8  = `timestamp_ns` (little-endian)
///   bytes 8..16 = `sk_ptr`       (little-endian)
/// Both halves are recoverable kernel-side AND embed enough
/// uniqueness that no two concurrent flows produce the same
/// corr_id (sk_ptr alone is unique while the sock is allocated;
/// the ts prefix de-confuses across allocator reuse).
#[inline(always)]
fn build_corr_id(timestamp_ns: u64, sk_ptr: u64) -> [u8; 16] {
    let mut out = [0u8; 16];
    let ts = timestamp_ns.to_le_bytes();
    let sp = sk_ptr.to_le_bytes();
    let mut i = 0usize;
    while i < 8 {
        out[i] = ts[i];
        out[i + 8] = sp[i];
        i += 1;
    }
    out
}

/// `struct sockaddr_in` (UAPI, stable).
#[repr(C)]
#[derive(Copy, Clone)]
struct SockaddrIn {
    sin_family: u16,
    sin_port: u16, // network byte order
    sin_addr: u32, // network byte order
    sin_zero: [u8; 8],
}

/// `struct sockaddr_in6` (UAPI, stable).
#[repr(C)]
#[derive(Copy, Clone)]
struct SockaddrIn6 {
    sin6_family: u16,
    sin6_port: u16,
    sin6_flowinfo: u32,
    sin6_addr: [u8; 16],
    sin6_scope_id: u32,
}

const AF_INET: u8 = 2;
const AF_INET6: u8 = 10;

#[kprobe]
pub fn tcp_v4_connect(ctx: ProbeContext) -> u32 {
    let _ = try_tcp_connect_v4(&ctx);
    0
}

#[kprobe]
pub fn tcp_v6_connect(ctx: ProbeContext) -> u32 {
    let _ = try_tcp_connect_v6(&ctx);
    0
}

#[inline(always)]
fn try_tcp_connect_v4(ctx: &ProbeContext) -> Result<(), i64> {
    // arg(0) is `struct sock *sk` — opaque kernel pointer used as
    // the FLOW_SOCK_MAP key.
    let sk_ptr: u64 = match ctx.arg::<*const u8>(0) {
        Some(p) => p as u64,
        None => 0,
    };
    let uaddr_ptr: *const SockaddrIn = match ctx.arg(1) {
        Some(p) => p,
        None => return Ok(()),
    };
    if uaddr_ptr.is_null() {
        return Ok(());
    }
    let sa: SockaddrIn = match unsafe { bpf_probe_read_kernel(uaddr_ptr) } {
        Ok(v) => v,
        Err(_) => return Ok(()),
    };
    // Tappa 10 N9.1 hotfix: loopback (127.0.0.0/8) is NO LONGER
    // skipped here. The pre-existing T4-era filter
    // (`if addr_bytes[0] == 127 { return Ok(()); }`, commit 210c596)
    // was a defensible call for Tappa 4's outbound-C2-monitoring
    // scope, but it's incompatible with Tappa 10's flow-correlation
    // contract: tcp_close fexit fires on loopback sockets the same
    // as any other TCP socket, and the userland N3 flow_tracker
    // can only correlate close-side events against connect-side
    // events that wrote to FLOW_SOCK_MAP. Skipping the connect kprobe
    // means no map write → tcp_close lookup misses → drain drops
    // the close on the floor as an orphan → zero netflow.jsonl rows
    // for the loopback flow. That's the bug the §11.2 priv-e2e #1
    // hit on northnarrowdev (kernel 6.8.0-117, 2026-05-21). It's
    // also a real operator-visibility gap: container-to-container
    // C2 in shared-netns Kubernetes pods goes over loopback. N6
    // rules don't false-positive on loopback (NN-L-NET-007 RFC1918
    // excludes 127/8; -001/-003 gate on empty default blocklists;
    // -008/-009 gate on specific TTPs); volume is bounded and the
    // §6.5 rate limiter handles bursts. Tappa 10's contract
    // supersedes T4's filter.
    let addr_bytes = sa.sin_addr.to_ne_bytes();

    let mut entry = match TCP_CONNECT_EVENTS.reserve::<TcpConnectRaw>(0) {
        Some(e) => e,
        None => {
            crate::drops::bump(northnarrow_common::ring_drops::ring_slot::TCP_CONNECT);
            return Ok(());
        }
    };
    let raw_ptr: *mut TcpConnectRaw = entry.as_mut_ptr();
    unsafe {
        crate::zero::zero(raw_ptr);
    }
    populate_common(raw_ptr);
    let ts = unsafe { (*raw_ptr).timestamp_ns };
    unsafe {
        (*raw_ptr).family = AF_INET;
        (*raw_ptr).dst_port = u16::from_be(sa.sin_port);
        (*raw_ptr).sk_ptr = sk_ptr;
        let dst = (*raw_ptr).dst_addr.as_mut_ptr();
        // Copy 4 bytes of v4 address into first 4 bytes of the 16-byte slot.
        let mut i = 0usize;
        while i < 4 {
            *dst.add(i) = addr_bytes[i];
            i += 1;
        }
        let mut i = 4usize;
        while i < ADDR_LEN {
            *dst.add(i) = 0;
            i += 1;
        }
    }
    // N2: populate FLOW_SOCK_MAP so the tcp_close fexit can read
    // a stable corr_id back out.
    if sk_ptr != 0 {
        let corr = build_corr_id(ts, sk_ptr);
        remember_flow_sock(sk_ptr, &corr);
    }
    entry.submit(0);
    Ok(())
}

#[inline(always)]
fn try_tcp_connect_v6(ctx: &ProbeContext) -> Result<(), i64> {
    let sk_ptr: u64 = match ctx.arg::<*const u8>(0) {
        Some(p) => p as u64,
        None => 0,
    };
    let uaddr_ptr: *const SockaddrIn6 = match ctx.arg(1) {
        Some(p) => p,
        None => return Ok(()),
    };
    if uaddr_ptr.is_null() {
        return Ok(());
    }
    let sa: SockaddrIn6 = match unsafe { bpf_probe_read_kernel(uaddr_ptr) } {
        Ok(v) => v,
        Err(_) => return Ok(()),
    };
    // Tappa 10 N9.1 hotfix: ::1 (IPv6 loopback) is NO LONGER skipped
    // here — see the matching rationale in `try_tcp_connect_v4`
    // above. Same flow-correlation contract applies to v6.

    let mut entry = match TCP_CONNECT_EVENTS.reserve::<TcpConnectRaw>(0) {
        Some(e) => e,
        None => {
            crate::drops::bump(northnarrow_common::ring_drops::ring_slot::TCP_CONNECT);
            return Ok(());
        }
    };
    let raw_ptr: *mut TcpConnectRaw = entry.as_mut_ptr();
    unsafe {
        crate::zero::zero(raw_ptr);
    }
    populate_common(raw_ptr);
    let ts = unsafe { (*raw_ptr).timestamp_ns };
    unsafe {
        (*raw_ptr).family = AF_INET6;
        (*raw_ptr).dst_port = u16::from_be(sa.sin6_port);
        (*raw_ptr).sk_ptr = sk_ptr;
        let dst = (*raw_ptr).dst_addr.as_mut_ptr();
        let mut i = 0usize;
        while i < ADDR_LEN {
            *dst.add(i) = sa.sin6_addr[i];
            i += 1;
        }
    }
    if sk_ptr != 0 {
        let corr = build_corr_id(ts, sk_ptr);
        remember_flow_sock(sk_ptr, &corr);
    }
    entry.submit(0);
    Ok(())
}

#[inline(always)]
fn populate_common(raw_ptr: *mut TcpConnectRaw) {
    let pid_tgid = bpf_get_current_pid_tgid();
    let uid_gid = bpf_get_current_uid_gid();
    unsafe {
        (*raw_ptr).pid = (pid_tgid >> 32) as u32;
        (*raw_ptr).uid = (uid_gid & 0xFFFF_FFFF) as u32;
        (*raw_ptr).timestamp_ns = bpf_ktime_get_ns();
    }
    let comm = bpf_get_current_comm().unwrap_or([0u8; 16]);
    unsafe {
        let dst = (*raw_ptr).comm.as_mut_ptr();
        let src = comm.as_ptr();
        let mut i = 0usize;
        while i < TASK_COMM_LEN {
            *dst.add(i) = *src.add(i);
            i += 1;
        }
    }
}
