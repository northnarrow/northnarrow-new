//! Lot 275 (C07 1→2) — inbound TCP connections: the accept and the close.
//!
//! [`inbound_accept_ret4`] and [`inbound_accept_ret2`] are fexit programs on
//! `inet_csk_accept`, which hands a listener's established child socket to
//! the process that called `accept()`: the program runs in that process's
//! context, so the record names the server that took the connection, as the
//! connect kprobe names the client of an outbound one. The function's
//! return value follows its parameters in the fexit context: four up to
//! 6.9 (`sk, flags, err, kern`), two from 6.10 (`sk, arg`). The agent loads
//! the four-parameter program first; the verifier refuses it where the
//! function has two (the fifth slot does not exist), and the agent loads the
//! other one. A fexit has no instance limit — a kretprobe's would run out
//! with threads blocked in `accept()`.
//!
//! An accept within its budgets ([`crate::budget`]: per process
//! [`TASK_BURST`], then 512 a second; per user [`UID_BURST`], then 1,024 a
//! second) writes its correlator in [`INBOUND_SOCK_MAP`] and a record in
//! [`INBOUND_EVENTS`]; `tcp_close` finds the socket there and records its
//! close in the same ring ([`close`]), with the byte counters. Outbound
//! flows keep their own map and ring (review 79): an inbound flood fills
//! this ring and this map only, and an accept over its budget is counted
//! (`inbound_rate`, and the process's next record carries the count).
//!
//! Verifier rules of `docs/operator/KERNEL_COMPATIBILITY.md` ("Older
//! verifiers"): the entry is zeroed by [`crate::zero::zero`], every helper
//! taking a pointer into it is `#[inline(always)]`.

use aya_ebpf::{
    helpers::{
        bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_get_current_uid_gid, bpf_ktime_get_ns,
        bpf_probe_read_kernel,
    },
    macros::{fexit, map},
    maps::{LruHashMap, RingBuf},
    programs::FExitContext,
};
use northnarrow_common::wire::{
    held_flags, inbound_kind, NetInboundRaw, ADDR_LEN, INBOUND_EVENTS_BYTES,
    INBOUND_SOCK_MAP_MAX_ENTRIES,
};

use crate::budget::{admit, Budget, Limits};
use crate::btf_offsets::{
    SOCK_SKC_DADDR_OFFSET, SOCK_SKC_DPORT_OFFSET, SOCK_SKC_FAMILY_OFFSET, SOCK_SKC_NUM_OFFSET,
    SOCK_SKC_RCV_SADDR_OFFSET, SOCK_SKC_V6_DADDR_OFFSET, SOCK_SKC_V6_RCV_SADDR_OFFSET,
    SOCK_SK_ERR_OFFSET, TCP_SOCK_BYTES_RECEIVED_OFFSET, TCP_SOCK_BYTES_SENT_OFFSET,
};

#[map]
pub static INBOUND_EVENTS: RingBuf = RingBuf::with_byte_size(INBOUND_EVENTS_BYTES, 0);

/// The accepted sockets recorded, by `struct sock *`, with their correlator
/// (the accept's time, then the socket's address, as `FLOW_SOCK_MAP`'s).
#[map]
pub static INBOUND_SOCK_MAP: LruHashMap<u64, [u8; 16]> =
    LruHashMap::with_max_entries(INBOUND_SOCK_MAP_MAX_ENTRIES, 0);

#[map]
static INBOUND_TASK_BUDGET: LruHashMap<u32, Budget> = LruHashMap::with_max_entries(4096, 0);
#[map]
static INBOUND_UID_BUDGET: LruHashMap<u32, Budget> = LruHashMap::with_max_entries(1024, 0);

/// Accepts a process may record in a burst (also its first ones).
const TASK_BURST: u64 = 256;
/// Accepts a user may record in a burst, across its processes.
const UID_BURST: u64 = 2048;

const INBOUND_LIMITS: Limits = Limits {
    task_burst: TASK_BURST,
    // After a burst, 512 records per second.
    task_refill_ns: 1_000_000_000 / 512,
    uid_burst: UID_BURST,
    // After a burst, 1,024 records per second.
    uid_refill_ns: 1_000_000_000 / 1024,
};

const AF_INET: u16 = 2;
const AF_INET6: u16 = 10;
/// `MAX_ERRNO` (include/linux/err.h): a pointer in the last page is an
/// `ERR_PTR`.
const MAX_ERRNO: u64 = 4095;

/// `inet_csk_accept(sk, flags, err, kern)` (≤ 6.9): the return value is the
/// fifth slot.
#[fexit(function = "inet_csk_accept")]
pub fn inbound_accept_ret4(ctx: FExitContext) -> i32 {
    let newsk: u64 = ctx.arg(4);
    unsafe { try_accept(newsk) };
    0
}

/// `inet_csk_accept(sk, arg)` (6.10+): the return value is the third slot.
#[fexit(function = "inet_csk_accept")]
pub fn inbound_accept_ret2(ctx: FExitContext) -> i32 {
    let newsk: u64 = ctx.arg(2);
    unsafe { try_accept(newsk) };
    0
}

#[inline(always)]
fn sat16(n: u64) -> u16 {
    if n > 0xFFFF {
        0xFFFF
    } else {
        n as u16
    }
}

#[inline(always)]
unsafe fn try_accept(newsk: u64) {
    // NULL or an ERR_PTR: no connection was taken.
    if newsk == 0 || newsk >= 0u64.wrapping_sub(MAX_ERRNO) {
        return;
    }
    // The fexit's return slot is a `PTR_TO_BTF_ID` (`struct sock *`), and
    // the verifier refuses arithmetic on it: the correlator splits the
    // address into bytes (shifts), the 6.8 lab's refusal of lot 275's first
    // build ("pointer arithmetic with >>= operator prohibited"). A copy
    // through the probe helper is a plain scalar, the value `tcp_connect`'s
    // correlator gets from its own probe.
    let newsk: u64 = match bpf_probe_read_kernel(&newsk as *const u64) {
        Ok(v) => v,
        Err(_) => return,
    };
    let sk_ptr = newsk as *const u8;
    let family: u16 = match bpf_probe_read_kernel(sk_ptr.add(off!(SOCK_SKC_FAMILY_OFFSET)) as *const u16) {
        Ok(v) => v,
        Err(_) => return,
    };
    if family != AF_INET && family != AF_INET6 {
        return;
    }
    let pid_tgid = bpf_get_current_pid_tgid();
    let uid_gid = bpf_get_current_uid_gid();
    let now = bpf_ktime_get_ns();
    let held = match admit(
        &INBOUND_TASK_BUDGET,
        &INBOUND_UID_BUDGET,
        (pid_tgid >> 32) as u32,
        (uid_gid & 0xFFFF_FFFF) as u32,
        now,
        INBOUND_LIMITS,
        northnarrow_common::ring_drops::ring_slot::INBOUND_RATE,
    ) {
        Some(h) => h,
        None => return,
    };
    let corr = crate::tcp_connect::build_corr_id(now, newsk);
    let mut entry = match INBOUND_EVENTS.reserve::<NetInboundRaw>(0) {
        Some(e) => e,
        None => {
            crate::drops::bump(northnarrow_common::ring_drops::ring_slot::INBOUND);
            return;
        }
    };
    // Only a recorded accept has its close recorded.
    let _ = INBOUND_SOCK_MAP.insert(&newsk, &corr, 0);
    let raw: *mut NetInboundRaw = entry.as_mut_ptr();
    crate::zero::zero(raw);
    (*raw).timestamp_ns = now;
    (*raw).flow_id = corr;
    (*raw).kind = inbound_kind::ACCEPT;
    (*raw).pid = (pid_tgid >> 32) as u32;
    (*raw).uid = (uid_gid & 0xFFFF_FFFF) as u32;
    (*raw).held = sat16(held.task);
    (*raw).held_uid = sat16(held.user);
    let mut flags = 0u8;
    if held.task != 0 {
        flags |= held_flags::TASK;
    }
    if held.user != 0 {
        flags |= held_flags::UID;
    }
    (*raw).flags = flags;
    if let Ok(comm) = bpf_get_current_comm() {
        (*raw).comm = comm;
    }
    endpoints(raw, sk_ptr, family);
    entry.submit(0);
}

/// Lot 275: `tcp_close` of a socket the outbound map did not know. A socket
/// [`INBOUND_SOCK_MAP`] holds is an accepted connection recorded at its
/// accept: its close goes to [`INBOUND_EVENTS`], forgotten first (as the
/// outbound close does, so the slab's next socket at this address is not
/// taken for it). `true` when the socket was one.
#[inline(always)]
pub(crate) unsafe fn close(sk_ptr: *const u8, family: u16) -> bool {
    let key = sk_ptr as u64;
    let corr: [u8; 16] = match INBOUND_SOCK_MAP.get(&key) {
        Some(c) => *c,
        None => return false,
    };
    let _ = INBOUND_SOCK_MAP.remove(&key);
    let mut entry = match INBOUND_EVENTS.reserve::<NetInboundRaw>(0) {
        Some(e) => e,
        None => {
            crate::drops::bump(northnarrow_common::ring_drops::ring_slot::INBOUND);
            return true;
        }
    };
    let raw: *mut NetInboundRaw = entry.as_mut_ptr();
    crate::zero::zero(raw);
    let pid_tgid = bpf_get_current_pid_tgid();
    let uid_gid = bpf_get_current_uid_gid();
    (*raw).timestamp_ns = bpf_ktime_get_ns();
    (*raw).flow_id = corr;
    (*raw).kind = inbound_kind::CLOSE;
    (*raw).pid = (pid_tgid >> 32) as u32;
    (*raw).uid = (uid_gid & 0xFFFF_FFFF) as u32;
    (*raw).bytes_sent =
        bpf_probe_read_kernel(sk_ptr.add(off!(TCP_SOCK_BYTES_SENT_OFFSET)) as *const u64).unwrap_or(0);
    (*raw).bytes_recv =
        bpf_probe_read_kernel(sk_ptr.add(off!(TCP_SOCK_BYTES_RECEIVED_OFFSET)) as *const u64)
            .unwrap_or(0);
    let sk_err: u32 =
        bpf_probe_read_kernel(sk_ptr.add(off!(SOCK_SK_ERR_OFFSET)) as *const u32).unwrap_or(0);
    (*raw).close_reason = (sk_err & 0xFF) as u8;
    if let Ok(comm) = bpf_get_current_comm() {
        (*raw).comm = comm;
    }
    endpoints(raw, sk_ptr, family);
    entry.submit(0);
    true
}

/// The socket's two ends into `raw`: the peer (`skc_daddr`, `skc_dport`) as
/// the remote end, the listener's address and port (`skc_rcv_saddr`,
/// `skc_num`) as the local one.
#[inline(always)]
unsafe fn endpoints(raw: *mut NetInboundRaw, sk_ptr: *const u8, family: u16) {
    (*raw).family = family as u8;
    let dport_be: u16 =
        bpf_probe_read_kernel(sk_ptr.add(off!(SOCK_SKC_DPORT_OFFSET)) as *const u16).unwrap_or(0);
    (*raw).remote_port = u16::from_be(dport_be);
    (*raw).local_port =
        bpf_probe_read_kernel(sk_ptr.add(off!(SOCK_SKC_NUM_OFFSET)) as *const u16).unwrap_or(0);
    let remote = (*raw).remote_addr.as_mut_ptr();
    let local = (*raw).local_addr.as_mut_ptr();
    if family == AF_INET {
        let daddr: u32 =
            bpf_probe_read_kernel(sk_ptr.add(off!(SOCK_SKC_DADDR_OFFSET)) as *const u32).unwrap_or(0);
        let saddr: u32 =
            bpf_probe_read_kernel(sk_ptr.add(off!(SOCK_SKC_RCV_SADDR_OFFSET)) as *const u32)
                .unwrap_or(0);
        let db = daddr.to_ne_bytes();
        let sb = saddr.to_ne_bytes();
        let mut i = 0usize;
        while i < 4 {
            *remote.add(i) = db[i];
            *local.add(i) = sb[i];
            i += 1;
        }
    } else {
        let d6: [u8; ADDR_LEN] =
            bpf_probe_read_kernel(sk_ptr.add(off!(SOCK_SKC_V6_DADDR_OFFSET)) as *const [u8; ADDR_LEN])
                .unwrap_or([0u8; ADDR_LEN]);
        let s6: [u8; ADDR_LEN] = bpf_probe_read_kernel(
            sk_ptr.add(off!(SOCK_SKC_V6_RCV_SADDR_OFFSET)) as *const [u8; ADDR_LEN],
        )
        .unwrap_or([0u8; ADDR_LEN]);
        let mut i = 0usize;
        while i < ADDR_LEN {
            *remote.add(i) = d6[i];
            *local.add(i) = s6[i];
            i += 1;
        }
    }
}
