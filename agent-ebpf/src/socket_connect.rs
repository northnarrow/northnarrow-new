//! Lab PR 224 (CM-02 c) — optional synchronous deny of a connect to a
//! policy-blocked destination.
//!
//! NN-L-NET-001 kills a process that reaches an address of the operator
//! blocklist, after the fact: the connection was made. With
//! `--net-connect-deny` the agent loads the blocklist into the two LPM
//! tries below, sets [`NET_CONNECT_DENY_MODE`] and attaches
//! [`socket_connect_deny`] on LSM `socket_connect`: a `connect()` of an
//! `AF_INET` / `AF_INET6` socket (TCP or a connected UDP socket) to a
//! listed address is refused with `-EPERM` before the stack sees it, and
//! one `TcpConnectRaw` record with `tcp_connect_flags::DENIED` goes to the
//! connect ring, which the agent turns into the signed NN-L-NET-001 record
//! of the refused connect. Off by default; never attached otherwise.
//!
//! Not covered: `sendto()` on an unconnected UDP socket (no connect),
//! raw sockets, an address the blocklist does not list. An IPv4-mapped
//! IPv6 destination (`::ffff:a.b.c.d`) is looked up in the IPv4 trie, as
//! NN-L-NET-001 canonicalises it (external audit NET-001).
//!
//! Hook prototype `(struct socket *, struct sockaddr *, int addrlen)`,
//! fixed and checked at boot (`HOOK_ARG_CHECKS`). The previous LSM's
//! verdict (the context's fourth word) is kept when it already refused.
//! Offsets added to the BTF-typed `sock` are masked (rule 8).

use aya_ebpf::{
    cty::c_void,
    helpers::{bpf_get_current_pid_tgid, bpf_get_current_uid_gid, bpf_ktime_get_ns, generated},
    macros::{lsm, map},
    maps::{lpm_trie::Key, Array, LpmTrie},
    programs::LsmContext,
};
use northnarrow_common::wire::{tcp_connect_flags, TcpConnectRaw, NET_BLOCK_MAX_ENTRIES};

use crate::btf_offsets::{SOCKET_SK_OFFSET, SOCK_SK_PROTOCOL_OFFSET};

/// IPv4 destinations to refuse (`prefix_len` + address, network order).
#[map]
pub static NET_BLOCK_V4: LpmTrie<[u8; 4], u8> = LpmTrie::with_max_entries(NET_BLOCK_MAX_ENTRIES, 0);
/// IPv6 destinations to refuse.
#[map]
pub static NET_BLOCK_V6: LpmTrie<[u8; 16], u8> =
    LpmTrie::with_max_entries(NET_BLOCK_MAX_ENTRIES, 0);
/// Slot 0: 1 = refuse listed destinations; anything else = allow all.
/// Written once by the agent before it attaches the program.
#[map]
pub static NET_CONNECT_DENY_MODE: Array<u32> = Array::with_max_entries(1, 0);

const AF_INET: u16 = 2;
const AF_INET6: u16 = 10;
/// `-EPERM`.
const EPERM: i32 = -1;

#[inline(always)]
unsafe fn peek_u64(src: u64) -> u64 {
    let mut v = core::mem::MaybeUninit::<u64>::uninit();
    let _ = generated::bpf_probe_read_kernel(v.as_mut_ptr() as *mut c_void, 8, src as *const c_void);
    v.assume_init()
}

#[inline(always)]
unsafe fn peek_u32(src: u64) -> u32 {
    let mut v = core::mem::MaybeUninit::<u32>::uninit();
    let _ = generated::bpf_probe_read_kernel(v.as_mut_ptr() as *mut c_void, 4, src as *const c_void);
    v.assume_init()
}

#[inline(always)]
unsafe fn peek_u16(src: u64) -> u16 {
    let mut v = core::mem::MaybeUninit::<u16>::uninit();
    let _ = generated::bpf_probe_read_kernel(v.as_mut_ptr() as *mut c_void, 2, src as *const c_void);
    v.assume_init()
}

#[lsm(hook = "socket_connect")]
pub fn socket_connect_deny(ctx: LsmContext) -> i32 {
    unsafe { try_socket_connect(&ctx) }
}

#[inline(always)]
unsafe fn try_socket_connect(ctx: &LsmContext) -> i32 {
    let previous: i32 = ctx.arg(3);
    if previous != 0 {
        return previous;
    }
    match NET_CONNECT_DENY_MODE.get(0) {
        Some(m) if *m == 1 => {}
        _ => return 0,
    }
    let sock: *const u8 = ctx.arg(0);
    let addr: *const u8 = ctx.arg(1);
    let addrlen: i32 = ctx.arg(2);
    if addr.is_null() {
        return 0;
    }
    let a = addr as u64;
    let family = peek_u16(a);
    let (port_be, v4, v6_hi, v6_lo, is_v6) = if family == AF_INET {
        if addrlen < 8 {
            return 0;
        }
        (peek_u16(a + 2), peek_u32(a + 4), 0u64, 0u64, false)
    } else if family == AF_INET6 {
        if addrlen < 24 {
            return 0;
        }
        let hi = peek_u64(a + 8);
        let lo = peek_u64(a + 16);
        // ::ffff:a.b.c.d — bytes 0..10 zero, 10..12 0xff (little-endian
        // words: the low six bytes of `lo`'s predecessor are in `hi`).
        let mapped = hi == 0 && (lo & 0xffff_ffff) == 0xffff_0000;
        if mapped {
            (peek_u16(a + 2), (lo >> 32) as u32, 0, 0, false)
        } else {
            (peek_u16(a + 2), 0, hi, lo, true)
        }
    } else {
        return 0;
    };
    let listed = if is_v6 {
        // The address as read, two words (no zeroed stack array, rule 4).
        let bytes: [u8; 16] = core::mem::transmute::<[u64; 2], [u8; 16]>([v6_hi, v6_lo]);
        NET_BLOCK_V6.get(&Key::new(128, bytes)).is_some()
    } else {
        NET_BLOCK_V4.get(&Key::new(32, v4.to_ne_bytes())).is_some()
    };
    if !listed {
        return 0;
    }
    record_denial(sock, port_be, v4, v6_hi, v6_lo, is_v6);
    EPERM
}

/// One `TcpConnectRaw` with `DENIED` for the agent's record. Best-effort:
/// a full ring drops the record (counted), never the denial.
#[inline(always)]
unsafe fn record_denial(sock: *const u8, port_be: u16, v4: u32, hi: u64, lo: u64, is_v6: bool) {
    let mut entry = match crate::tcp_connect::TCP_CONNECT_EVENTS.reserve::<TcpConnectRaw>(0) {
        Some(e) => e,
        None => {
            crate::drops::bump(northnarrow_common::ring_drops::ring_slot::TCP_CONNECT);
            return;
        }
    };
    let raw: *mut TcpConnectRaw = entry.as_mut_ptr();
    crate::zero::zero(raw);
    let pid_tgid = bpf_get_current_pid_tgid();
    let uid_gid = bpf_get_current_uid_gid();
    (*raw).pid = (pid_tgid >> 32) as u32;
    (*raw).uid = (uid_gid & 0xFFFF_FFFF) as u32;
    (*raw).timestamp_ns = bpf_ktime_get_ns();
    (*raw).flags = tcp_connect_flags::DENIED;
    (*raw).dst_port = u16::from_be(port_be);
    if is_v6 {
        (*raw).family = AF_INET6 as u8;
        let d = (*raw).dst_addr.as_mut_ptr();
        *(d as *mut u64) = hi;
        *(d.add(8) as *mut u64) = lo;
    } else {
        (*raw).family = AF_INET as u8;
        *((*raw).dst_addr.as_mut_ptr() as *mut u32) = v4;
    }
    // The socket's protocol, through `sock->sk` (optional offset).
    if !sock.is_null() {
        if let Some(o) = off_opt!(SOCKET_SK_OFFSET) {
            let sk = peek_u64((sock as u64) + ((o as u64) & 0xffff));
            if sk != 0 {
                (*raw).proto = peek_u16(sk + off!(SOCK_SK_PROTOCOL_OFFSET) as u64) as u8;
            }
        }
    }
    // Straight into the record: no zeroed stack copy, no `memset`
    // subprogram (KERNEL_COMPATIBILITY "Older verifiers", rule 9).
    crate::comm::comm_into(&mut (*raw).comm);
    entry.submit(0);
}
