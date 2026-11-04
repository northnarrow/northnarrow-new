//! Lot 275 (C07 1→2) — the TLS ClientHello of an outbound TCP flow.
//!
//! The connect kprobes (`crate::tcp_connect`) mark each outbound socket in
//! [`TLS_PENDING`]; [`tls_client_hello`], an fentry program on
//! `tcp_sendmsg(sk, msg, size)` (one shape from 5.15 to 7.x), takes the mark
//! off at the socket's first send and looks at its first bytes: a TLS
//! handshake record (content type 22, version 3.x) carrying a ClientHello
//! (handshake type 1). Such a send is copied, up to [`TLS_HELLO_CAP`] bytes,
//! from the sender's buffer into [`TLS_HELLO_EVENTS`] with the flow's
//! correlator (`FLOW_SOCK_MAP`), for the parse worker's JA3 and JA4. Every
//! other send costs one lookup that misses: an accepted socket, a flow past
//! its first send, a connect that predates the agent are never marked;
//! `tcp_close` takes the mark off a socket that closed before sending.
//!
//! The bytes are the sender's (user memory read at the call, before the
//! kernel copies them): a sender can rewrite them meanwhile, as it can
//! shape its hello to look like another client's. A ClientHello sent with
//! the connect (TCP Fast Open: `sendto(MSG_FASTOPEN)` connects inside
//! `tcp_sendmsg`) is not seen: the mark is set after the fentry ran.
//!
//! Budgets ([`crate::budget`]): per process [`TASK_BURST`], then 32 a
//! second; per user [`UID_BURST`], then 256 a second. A hello over them is
//! counted (`tls_rate`) and the process's next record carries the count.

use aya_ebpf::{
    cty::c_void,
    helpers::{
        bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_get_current_uid_gid, bpf_ktime_get_ns,
        bpf_probe_read_user, generated,
    },
    macros::{fentry, map},
    maps::{LruHashMap, RingBuf},
    programs::FEntryContext,
};
use northnarrow_common::wire::{
    held_flags, tls_flags, TlsHelloRaw, TLS_HELLO_CAP, TLS_HELLO_EVENTS_BYTES,
    TLS_PENDING_MAX_ENTRIES,
};

use crate::budget::{admit, Budget, Limits};

#[map]
pub static TLS_HELLO_EVENTS: RingBuf = RingBuf::with_byte_size(TLS_HELLO_EVENTS_BYTES, 0);

/// The outbound sockets whose first send has not been seen, by
/// `struct sock *` (the value is unused).
#[map]
pub static TLS_PENDING: LruHashMap<u64, u8> = LruHashMap::with_max_entries(TLS_PENDING_MAX_ENTRIES, 0);

#[map]
static TLS_TASK_BUDGET: LruHashMap<u32, Budget> = LruHashMap::with_max_entries(4096, 0);
#[map]
static TLS_UID_BUDGET: LruHashMap<u32, Budget> = LruHashMap::with_max_entries(1024, 0);

/// ClientHellos a process may record in a burst (also its first ones).
const TASK_BURST: u64 = 64;
/// ClientHellos a user may record in a burst, across its processes.
const UID_BURST: u64 = 512;

const TLS_LIMITS: Limits = Limits {
    task_burst: TASK_BURST,
    // After a burst, 32 records per second.
    task_refill_ns: 1_000_000_000 / 32,
    uid_burst: UID_BURST,
    // After a burst, 256 records per second.
    uid_refill_ns: 1_000_000_000 / 256,
};

/// A TLS record header (5 bytes) and a handshake message's type (1).
const HELLO_PEEK: usize = 6;
const CONTENT_HANDSHAKE: u8 = 22;
const HANDSHAKE_CLIENT_HELLO: u8 = 1;

/// Lot 275: mark `sk` as an outbound socket whose first send is a
/// ClientHello candidate (the connect kprobes).
#[inline(always)]
pub(crate) fn remember(sk: u64) {
    let _ = TLS_PENDING.insert(&sk, &1u8, 0);
}

/// Lot 275: `tcp_close` of `sk` — not a candidate any more.
#[inline(always)]
pub(crate) fn forget(sk: u64) {
    let _ = TLS_PENDING.remove(&sk);
}

#[fentry(function = "tcp_sendmsg")]
pub fn tls_client_hello(ctx: FEntryContext) -> i32 {
    unsafe { try_hello(&ctx) };
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
unsafe fn try_hello(ctx: &FEntryContext) {
    let sk: u64 = ctx.arg(0);
    if TLS_PENDING.get(&sk).is_none() {
        return;
    }
    // the first send: whatever it is, the socket is no candidate after it
    let _ = TLS_PENDING.remove(&sk);
    let msg_ptr: *const u8 = ctx.arg(1);
    let size: u64 = ctx.arg(2);
    if size < HELLO_PEEK as u64 {
        return;
    }
    let base = match crate::uiter::user_base(msg_ptr) {
        Some(b) => b,
        None => return,
    };
    let head: [u8; HELLO_PEEK] = match bpf_probe_read_user::<[u8; HELLO_PEEK]>(base as *const [u8; HELLO_PEEK]) {
        Ok(h) => h,
        Err(_) => return,
    };
    if head[0] != CONTENT_HANDSHAKE || head[1] != 3 || head[5] != HANDSHAKE_CLIENT_HELLO {
        return;
    }
    let pid_tgid = bpf_get_current_pid_tgid();
    let uid_gid = bpf_get_current_uid_gid();
    let now = bpf_ktime_get_ns();
    let held = match admit(
        &TLS_TASK_BUDGET,
        &TLS_UID_BUDGET,
        (pid_tgid >> 32) as u32,
        (uid_gid & 0xFFFF_FFFF) as u32,
        now,
        TLS_LIMITS,
        northnarrow_common::ring_drops::ring_slot::TLS_RATE,
    ) {
        Some(h) => h,
        None => return,
    };
    let mut entry = match TLS_HELLO_EVENTS.reserve::<TlsHelloRaw>(0) {
        Some(e) => e,
        None => {
            crate::drops::bump(northnarrow_common::ring_drops::ring_slot::TLS);
            return;
        }
    };
    let raw: *mut TlsHelloRaw = entry.as_mut_ptr();
    crate::zero::zero(raw);
    (*raw).timestamp_ns = now;
    (*raw).pid = (pid_tgid >> 32) as u32;
    (*raw).uid = (uid_gid & 0xFFFF_FFFF) as u32;
    if let Ok(comm) = bpf_get_current_comm() {
        (*raw).comm = comm;
    }
    if let Some(corr) = crate::tcp_connect::FLOW_SOCK_MAP.get(&sk) {
        (*raw).flow_id = *corr;
    }
    if let Ok(Some(d)) = crate::dns_query::dest_from_sock(sk as *const u8) {
        (*raw).family = d.family;
        (*raw).dst_port = u16::from_be(d.port_be);
        (*raw).dst_addr = d.addr;
    }
    (*raw).send_len = if size > 0xFFFF_FFFF { 0xFFFF_FFFF } else { size as u32 };
    (*raw).held = sat16(held.task);
    (*raw).held_uid = sat16(held.user);
    let mut flags = 0u8;
    if held.task != 0 {
        flags |= held_flags::TASK;
    }
    if held.user != 0 {
        flags |= held_flags::UID;
    }
    let dst = (*raw).data.as_mut_ptr() as *mut c_void;
    if size >= TLS_HELLO_CAP as u64 {
        if size > TLS_HELLO_CAP as u64 {
            flags |= tls_flags::TRUNCATED;
        }
        if generated::bpf_probe_read_user(dst, TLS_HELLO_CAP as u32, base as *const c_void) == 0 {
            (*raw).captured = TLS_HELLO_CAP as u16;
        }
    } else {
        // A variable size the verifier bounds: below the cap.
        let n = (size as u32) & (TLS_HELLO_CAP as u32 - 1);
        if generated::bpf_probe_read_user(dst, n, base as *const c_void) == 0 {
            (*raw).captured = n as u16;
        }
    }
    (*raw).flags = flags;
    entry.submit(0);
}
