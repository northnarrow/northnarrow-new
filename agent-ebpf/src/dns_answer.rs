//! Lot 275 (C07 1→2) — the DNS responses a process receives.
//!
//! fexit programs on `udp_recvmsg` and `udpv6_recvmsg`: they run in the
//! receiving process's context once the kernel has copied the datagram into
//! its buffer, so a response is attributed to the process that asked — the
//! application itself on a stub-resolver host (glibc to `127.0.0.53`), or
//! the local resolver for its upstream leg. The return value follows the
//! parameters in the fexit context: six up to 5.18 (`sk, msg, len,
//! noblock, flags, addr_len`), five from 5.19 (`noblock` went). The agent
//! loads the six-parameter programs first; the verifier refuses them where
//! the function has five, and the agent loads the others.
//!
//! The datagram is a response when it came from port 53: its source is the
//! `msg_name` the kernel filled for the caller (`recvfrom`, `recvmsg`), or
//! the connected socket's peer when the caller asked for no address
//! (`recv` on a connected socket: a connected UDP socket only receives from
//! its peer). `msg_namelen` is not set yet when the function returns (its
//! caller sets it), so the address's family says whether it was filled.
//! The bytes are read from the receiver's own buffer — the kernel's copy of
//! a response in page fragments (a virtio NIC's) would have needed the
//! fragments walked — up to [`DNS_ANSWER_CAP`]; the parse worker decodes
//! them. A record within the process's and the user's budgets (64, then
//! 128 a second, per process; 2,048, then 1,024 a second, per user; the
//! local resolvers' users exempt, as for the queries) is recorded; the rest
//! are counted (`dns_answer_rate`) and carried by the next record.
//!
//! Every other datagram costs the return value's test and, for one of more
//! than 12 bytes, two reads of the source port.

use aya_ebpf::{
    cty::c_void,
    helpers::{
        bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_get_current_uid_gid, bpf_ktime_get_ns,
        bpf_probe_read_kernel, generated,
    },
    macros::{fexit, map},
    maps::{LruHashMap, RingBuf},
    programs::FExitContext,
};
use northnarrow_common::wire::{
    answer_flags, held_flags, DnsAnswerRaw, ADDR_LEN, DNS_ANSWER_CAP, DNS_ANSWER_EVENTS_BYTES,
};

use crate::budget::{admit, Budget, Limits};
use crate::btf_offsets::MSGHDR_NAME_OFFSET;

#[map]
pub static DNS_ANSWER_EVENTS: RingBuf = RingBuf::with_byte_size(DNS_ANSWER_EVENTS_BYTES, 0);

#[map]
static ANSWER_TASK_BUDGET: LruHashMap<u32, Budget> = LruHashMap::with_max_entries(8192, 0);
#[map]
static ANSWER_UID_BUDGET: LruHashMap<u32, Budget> = LruHashMap::with_max_entries(1024, 0);

/// Responses a process may record in a burst (also its first ones).
const TASK_BURST: u64 = 64;
/// Responses a user may record in a burst, across its processes.
const UID_BURST: u64 = 2048;

const ANSWER_LIMITS: Limits = Limits {
    task_burst: TASK_BURST,
    // After a burst, 128 records per second.
    task_refill_ns: 1_000_000_000 / 128,
    uid_burst: UID_BURST,
    // After a burst, 1,024 records per second.
    uid_refill_ns: 1_000_000_000 / 1024,
};

/// 53 in network byte order, as a little-endian `u16` read.
const DNS_PORT_BE: u16 = 0x3500;
/// A DNS message's header.
const DNS_HDR_LEN: i32 = 12;
const AF_INET: u16 = 2;
const AF_INET6: u16 = 10;

/// `udp_recvmsg` with six parameters (≤ 5.18): the return value is slot 6.
#[fexit(function = "udp_recvmsg")]
pub fn dns_answer_v4_ret6(ctx: FExitContext) -> i32 {
    let ret: i32 = ctx.arg(6);
    unsafe { try_answer(&ctx, ret) };
    0
}

/// `udp_recvmsg` with five parameters (5.19+): the return value is slot 5.
#[fexit(function = "udp_recvmsg")]
pub fn dns_answer_v4_ret5(ctx: FExitContext) -> i32 {
    let ret: i32 = ctx.arg(5);
    unsafe { try_answer(&ctx, ret) };
    0
}

/// `udpv6_recvmsg`, six parameters.
#[fexit(function = "udpv6_recvmsg")]
pub fn dns_answer_v6_ret6(ctx: FExitContext) -> i32 {
    let ret: i32 = ctx.arg(6);
    unsafe { try_answer(&ctx, ret) };
    0
}

/// `udpv6_recvmsg`, five parameters.
#[fexit(function = "udpv6_recvmsg")]
pub fn dns_answer_v6_ret5(ctx: FExitContext) -> i32 {
    let ret: i32 = ctx.arg(5);
    unsafe { try_answer(&ctx, ret) };
    0
}

/// Where a received datagram came from.
struct Source {
    family: u16,
    port_be: u16,
    addr: [u8; ADDR_LEN],
}

/// The source the kernel wrote into `msg->msg_name` (a kernel
/// `sockaddr_storage`), when the caller asked for one.
#[inline(always)]
unsafe fn source_from_name(msg_ptr: *const u8) -> Option<Source> {
    let name: *const u8 =
        bpf_probe_read_kernel::<*const u8>(msg_ptr.add(off!(MSGHDR_NAME_OFFSET)) as *const *const u8).ok()?;
    if name.is_null() {
        return None;
    }
    let family: u16 = bpf_probe_read_kernel::<u16>(name as *const u16).ok()?;
    let port_be: u16 = bpf_probe_read_kernel::<u16>(name.add(2) as *const u16).ok()?;
    let mut addr = [0u8; ADDR_LEN];
    match family {
        AF_INET => {
            let a: [u8; 4] = bpf_probe_read_kernel::<[u8; 4]>(name.add(4) as *const [u8; 4]).ok()?;
            let mut i = 0usize;
            while i < 4 {
                addr[i] = a[i];
                i += 1;
            }
        }
        AF_INET6 => {
            addr = bpf_probe_read_kernel::<[u8; ADDR_LEN]>(name.add(8) as *const [u8; ADDR_LEN]).ok()?;
        }
        _ => return None,
    }
    Some(Source {
        family,
        port_be,
        addr,
    })
}

/// The connected socket's peer (`recv()` on a connected socket: no
/// `msg_name`).
#[inline(always)]
unsafe fn source_from_sock(sk_ptr: *const u8) -> Option<Source> {
    let d = crate::dns_query::dest_from_sock(sk_ptr).ok()??;
    Some(Source {
        family: u16::from(d.family),
        port_be: d.port_be,
        addr: d.addr,
    })
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
unsafe fn try_answer(ctx: &FExitContext, ret: i32) {
    // A DNS message is at least its header; an error is negative. The
    // function returns an `int`: only the slot's low 32 bits are its value.
    if ret <= DNS_HDR_LEN {
        return;
    }
    let sk_ptr: *const u8 = ctx.arg(0);
    let msg_ptr: *const u8 = ctx.arg(1);
    if msg_ptr.is_null() {
        return;
    }
    let src = match source_from_name(msg_ptr) {
        Some(s) => s,
        None => match source_from_sock(sk_ptr) {
            Some(s) => s,
            None => return,
        },
    };
    if src.port_be != DNS_PORT_BE {
        return;
    }
    let uid = (bpf_get_current_uid_gid() & 0xFFFF_FFFF) as u32;
    let tgid = (bpf_get_current_pid_tgid() >> 32) as u32;
    let now = bpf_ktime_get_ns();
    // The local resolvers' users (`DNS_EXEMPT_UIDS`, written by the agent)
    // have no budget: their upstream answers are what the others' names
    // resolve to.
    let held = if crate::dns_query::DNS_EXEMPT_UIDS.get(&uid).is_some() {
        crate::budget::Held::NONE
    } else {
        match admit(
            &ANSWER_TASK_BUDGET,
            &ANSWER_UID_BUDGET,
            tgid,
            uid,
            now,
            ANSWER_LIMITS,
            northnarrow_common::ring_drops::ring_slot::DNS_ANSWER_RATE,
        ) {
            Some(h) => h,
            None => return,
        }
    };
    let mut entry = match DNS_ANSWER_EVENTS.reserve::<DnsAnswerRaw>(0) {
        Some(e) => e,
        None => {
            crate::drops::bump(northnarrow_common::ring_drops::ring_slot::DNS_ANSWER);
            return;
        }
    };
    let raw: *mut DnsAnswerRaw = entry.as_mut_ptr();
    crate::zero::zero(raw);
    (*raw).timestamp_ns = now;
    (*raw).pid = tgid;
    (*raw).uid = uid;
    if let Ok(comm) = bpf_get_current_comm() {
        (*raw).comm = comm;
    }
    (*raw).family = src.family as u8;
    (*raw).server = src.addr;
    (*raw).server_port = u16::from_be(src.port_be);
    let len: u64 = ret as u64;
    (*raw).datagram_len = if len > 0xFFFF_FFFF { 0xFFFF_FFFF } else { len as u32 };
    (*raw).held = sat16(held.task);
    (*raw).held_uid = sat16(held.user);
    let mut flags = 0u8;
    if held.task != 0 {
        flags |= held_flags::TASK;
    }
    if held.user != 0 {
        flags |= held_flags::UID;
    }
    // The receiver's buffer, the datagram at its start.
    let dst = (*raw).payload.as_mut_ptr() as *mut c_void;
    let read = match crate::uiter::user_base(msg_ptr) {
        None => -1,
        Some(base) => {
            if len >= DNS_ANSWER_CAP as u64 {
                flags |= if len > DNS_ANSWER_CAP as u64 {
                    answer_flags::TRUNCATED
                } else {
                    0
                };
                let r = generated::bpf_probe_read_user(dst, DNS_ANSWER_CAP as u32, base as *const c_void);
                if r == 0 {
                    (*raw).captured = DNS_ANSWER_CAP as u16;
                }
                r
            } else {
                // A variable size the verifier bounds: below the cap.
                let n = (len as u32) & (DNS_ANSWER_CAP as u32 - 1);
                let r = generated::bpf_probe_read_user(dst, n, base as *const c_void);
                if r == 0 {
                    (*raw).captured = n as u16;
                }
                r
            }
        }
    };
    if read != 0 {
        flags |= answer_flags::UNREAD;
    }
    (*raw).flags = flags;
    entry.submit(0);
}
