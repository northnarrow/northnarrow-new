//! Tappa 10.9 step 3 — the DNS sensor on the socket buffer the kernel sends.
//!
//! Design: `docs/design/TAPPA10_9_SENSOR_ATTACH_POINTS_DESIGN.md` §12.
//! [`dns_udp_send_skb`] and [`dns_udp_v6_send_skb`] are kprobes on
//! `udp_send_skb(skb, fl4, cork)` and `udp_v6_send_skb(skb, fl6, cork)`,
//! where the uncorked and the corked send paths meet. The flow argument
//! holds the destination the datagram will use; the buffer holds the
//! kernel's copy of the payload. Reviews 66 and 67: the `udp_sendmsg`
//! kprobe ([`crate::dns_query`]) read the name from user memory before the
//! copy, and saw no IPv6 query at all.
//!
//! The record carries up to [`QNAME_WIRE_LEN`] wire bytes from the start of
//! the name, read in 32-byte pieces up to the end of the linear data.
//! Userland walks the labels and takes the type after the root label
//! (`common::model`), so a zero byte inside a label does not cut the name.
//! A name that goes on past the linear data (a corked send, UDP GSO, zero
//! copy) arrives partial, with [`dns_flags::NONLINEAR`].
use aya_ebpf::{
    cty::c_void,
    helpers::{
        bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_get_current_uid_gid,
        bpf_ktime_get_ns, generated,
    },
    macros::kprobe,
    programs::ProbeContext,
};
use northnarrow_common::wire::{dns_flags, DnsQueryRaw, QNAME_WIRE_LEN};

use crate::btf_offsets::{
    FLOWI4_DADDR_OFFSET, FLOWI4_ULI_OFFSET, FLOWI6_DADDR_OFFSET, FLOWI6_ULI_OFFSET,
    SK_BUFF_DATA_LEN_OFFSET, SK_BUFF_HEAD_OFFSET, SK_BUFF_TAIL_OFFSET,
    SK_BUFF_TRANSPORT_HEADER_OFFSET,
};
use crate::dns_query::DNS_QUERY_EVENTS;

/// 53 in network byte order: `uli.ports.dport` as a little-endian `u16`.
const DNS_PORT_BE: u16 = 0x3500;
const AF_INET: u8 = 2;
const AF_INET6: u8 = 10;
/// The payload starts after the UDP header; the name after the DNS header.
const UDP_HDR_LEN: usize = 8;
const DNS_HDR_LEN: usize = 12;
/// Bytes per read: a constant size, so the verifier bounds every copy.
const CHUNK: usize = 32;
const CHUNKS: usize = QNAME_WIRE_LEN / CHUNK;
/// `skb->transport_header` when unset (`(u16)~0U`).
const HEADER_UNSET: usize = 0xffff;

/// `u64` at `src`, 0 when unreadable, without a branch on the result
/// (the helper always writes its destination).
#[inline(always)]
unsafe fn peek_u64(src: *const u8) -> u64 {
    let mut v = core::mem::MaybeUninit::<u64>::uninit();
    let _ = generated::bpf_probe_read_kernel(v.as_mut_ptr() as *mut c_void, 8, src as *const c_void);
    v.assume_init()
}

#[inline(always)]
unsafe fn peek_u32(src: *const u8) -> u32 {
    let mut v = core::mem::MaybeUninit::<u32>::uninit();
    let _ = generated::bpf_probe_read_kernel(v.as_mut_ptr() as *mut c_void, 4, src as *const c_void);
    v.assume_init()
}

#[inline(always)]
unsafe fn peek_u16(src: *const u8) -> u16 {
    let mut v = core::mem::MaybeUninit::<u16>::uninit();
    let _ = generated::bpf_probe_read_kernel(v.as_mut_ptr() as *mut c_void, 2, src as *const c_void);
    v.assume_init()
}

#[kprobe]
pub fn dns_udp_send_skb(ctx: ProbeContext) -> u32 {
    unsafe { try_dns_send_skb(&ctx, false) };
    0
}

#[kprobe]
pub fn dns_udp_v6_send_skb(ctx: ProbeContext) -> u32 {
    unsafe { try_dns_send_skb(&ctx, true) };
    0
}

#[inline(always)]
unsafe fn try_dns_send_skb(ctx: &ProbeContext, v6: bool) {
    // Kernel signatures: (skb, fl4, cork) and (skb, fl6, cork).
    let skb: *const u8 = match ctx.arg(0) {
        Some(p) => p,
        None => return,
    };
    let fl: *const u8 = match ctx.arg(1) {
        Some(p) => p,
        None => return,
    };
    // One read per datagram: the destination port, the first field of
    // `uli`. Optional offsets one at a time (5.15 rule 3); userland
    // attaches these programs only when all of them resolved.
    let o_uli = match if v6 {
        off_opt!(FLOWI6_ULI_OFFSET)
    } else {
        off_opt!(FLOWI4_ULI_OFFSET)
    } {
        Some(o) => o & 0xffff,
        None => return,
    };
    if peek_u16(fl.add(o_uli)) != DNS_PORT_BE {
        return;
    }
    let o_daddr = match if v6 {
        off_opt!(FLOWI6_DADDR_OFFSET)
    } else {
        off_opt!(FLOWI4_DADDR_OFFSET)
    } {
        Some(o) => o & 0xffff,
        None => return,
    };
    let o_head = match off_opt!(SK_BUFF_HEAD_OFFSET) {
        Some(o) => o & 0xffff,
        None => return,
    };
    let o_tail = match off_opt!(SK_BUFF_TAIL_OFFSET) {
        Some(o) => o & 0xffff,
        None => return,
    };
    let o_th = match off_opt!(SK_BUFF_TRANSPORT_HEADER_OFFSET) {
        Some(o) => o & 0xffff,
        None => return,
    };
    let o_dlen = match off_opt!(SK_BUFF_DATA_LEN_OFFSET) {
        Some(o) => o & 0xffff,
        None => return,
    };
    // Review 78: the DNS record budgets.
    let admitted = match crate::dns_query::dns_admit() {
        Some(a) => a,
        None => return,
    };

    let mut entry = match DNS_QUERY_EVENTS.reserve::<DnsQueryRaw>(0) {
        Some(e) => e,
        None => {
            crate::drops::bump(northnarrow_common::ring_drops::ring_slot::DNS);
            return;
        }
    };
    let raw: *mut DnsQueryRaw = entry.as_mut_ptr();
    crate::zero::zero(raw);
    (*raw).pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    (*raw).uid = (bpf_get_current_uid_gid() & 0xFFFF_FFFF) as u32;
    (*raw).timestamp_ns = bpf_ktime_get_ns();
    if let Ok(comm) = bpf_get_current_comm() {
        (*raw).comm = comm;
    }
    // The destination the datagram will use (after any cgroup/sendmsg
    // rewrite): 4 or 16 bytes, network order, as the old sensor stored it.
    let dst = (*raw).dns_server.as_mut_ptr() as *mut c_void;
    if v6 {
        (*raw).family = AF_INET6;
        let _ = generated::bpf_probe_read_kernel(dst, 16, fl.add(o_daddr) as *const c_void);
    } else {
        (*raw).family = AF_INET;
        let _ = generated::bpf_probe_read_kernel(dst, 4, fl.add(o_daddr) as *const c_void);
    }

    // The payload the kernel copied: `head + transport_header` is the UDP
    // header (blank until this function fills it), the linear data ends at
    // `head + tail`; both are offsets from `head` on 64-bit kernels.
    let head = peek_u64(skb.add(o_head)) as *const u8;
    let tail = peek_u32(skb.add(o_tail)) as usize;
    let th = peek_u16(skb.add(o_th)) as usize;
    let mut flags = dns_flags::SKB | admitted.flags;
    if peek_u32(skb.add(o_dlen)) != 0 {
        flags |= dns_flags::NONLINEAR;
    }
    (*raw).flags = flags;
    (*raw).held = admitted.held;
    if !head.is_null() && th != HEADER_UNSET {
        let start = (th & 0xffff) + UDP_HDR_LEN + DNS_HDR_LEN;
        let avail = if tail > start { tail - start } else { 0 };
        let src = head.add(start);
        // Constant-size pieces up to the end of the linear data. The last
        // one may read up to 31 bytes past `tail`, still inside the
        // buffer's allocation (tailroom, then `skb_shared_info`); userland
        // reads only `qname_len` bytes.
        let mut copied = 0usize;
        let mut i = 0usize;
        while i < CHUNKS {
            let off = i * CHUNK;
            if off >= avail {
                break;
            }
            let dst = (*raw).query_name.as_mut_ptr().add(off) as *mut c_void;
            if generated::bpf_probe_read_kernel(dst, CHUNK as u32, src.add(off) as *const c_void) != 0 {
                break;
            }
            copied = off + CHUNK;
            i += 1;
        }
        let n = if copied < avail { copied } else { avail };
        (*raw).qname_len = n as u16;
    }
    entry.submit(0);
}
