//! DNS query sensor (kprobe on `udp_sendmsg`).
//!
//! Emits one `DnsQueryRaw` per outbound UDP datagram to port 53,
//! carrying pid/comm/uid, the destination DNS server, and the
//! label-encoded QNAME so userland can attribute a later connect to
//! the resolved host (`DnsCache::on_dns_query` → `lookup_for_connect`).
//!
//! ## Tappa 4.1 refit — closes two pre-existing T4 bugs
//!
//! 1. **Connected-UDP destination (Bug 2).** glibc's resolver uses
//!    `connect()` + `send()` on its UDP socket, so `udp_sendmsg`
//!    receives `msg_name == NULL` / `msg_namelen == 0` — the old code
//!    early-returned and never fired for real resolution. We now fall
//!    back to the socket's `__sk_common` destination
//!    (`skc_daddr`/`skc_dport`/`skc_family`, validated N2 offsets) when
//!    `msg_name` is absent. The explicit-address `sendto` path is kept.
//!
//! 2. **QNAME extraction (Bug 3).** The old code hard-set
//!    `qname_len = 0` and never copied the query name. We now walk
//!    `msg->msg_iter` and copy the label-encoded QNAME out of the UDP
//!    payload. The DNS root label is a `0x00` byte == a C-string NUL,
//!    so `bpf_probe_read_user_str_bytes` reads the QNAME cleanly and
//!    bounded, stopping at the terminator (the same helper the
//!    exec/file sensors use for user strings).
//!
//! ## iov_iter coverage (verifier-scoped)
//!
//! `msg_iter` on 6.x is a tagged union (see `btf_offsets.rs`). This
//! refit handles **`ITER_UBUF`** — the single inline buffer the
//! connected-UDP `send()` path produces — which is what the resolver
//! emits. `ITER_IOVEC` (scatter-gather `sendmsg`) is a documented
//! follow-up: we leave the QNAME empty for it rather than risk a
//! mis-read, and the destination/attribution still work.
//!
//! The payload buffer is **user** memory at `udp_sendmsg` entry (not
//! yet copied into the kernel), so the QNAME read uses
//! `bpf_probe_read_user*`, while the `msghdr`/`iov_iter`/`sock` fields
//! themselves are kernel memory read with `bpf_probe_read_kernel`.

use aya_ebpf::{
    helpers::{
        bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_get_current_uid_gid, bpf_ktime_get_ns,
        bpf_probe_read_kernel, bpf_probe_read_user, bpf_probe_read_user_str_bytes,
    },
    macros::{kprobe, map},
    maps::RingBuf,
    programs::ProbeContext,
};
use northnarrow_common::wire::{DnsQueryRaw, ADDR_LEN, QNAME_LEN, TASK_COMM_LEN};

use crate::btf_offsets::{
    IOV_ITER_ITER_TYPE_OFFSET, IOV_ITER_UBUF_BASE_OFFSET, MSGHDR_MSG_ITER_OFFSET,
    SOCK_SKC_DADDR_OFFSET, SOCK_SKC_DPORT_OFFSET, SOCK_SKC_FAMILY_OFFSET, SOCK_SKC_V6_DADDR_OFFSET,
};

#[map]
static DNS_QUERY_EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

const DNS_PORT_BE: u16 = 0x3500; // 53 in network byte order
const AF_INET: u16 = 2;
const AF_INET6: u16 = 10;

// `struct msghdr` UAPI-relevant prefix (kernel internal struct, but
// the first two fields have been stable for >15 years):
//   void *msg_name;     offset 0
//   int   msg_namelen;  offset 8
const MSGHDR_NAME_OFFSET: usize = 0;
const MSGHDR_NAMELEN_OFFSET: usize = 8;

// `iov_iter.iter_type` discriminant value for a single inline user
// buffer (the connected-UDP `send()` shape). See `btf_offsets.rs`.
const ITER_UBUF: u8 = 0;

// DNS message header is a fixed 12 bytes; the QNAME starts right after.
const DNS_HEADER_LEN: usize = 12;

#[repr(C)]
#[derive(Copy, Clone)]
struct SockaddrIn {
    sin_family: u16,
    sin_port: u16, // network byte order
    sin_addr: u32,
    sin_zero: [u8; 8],
}

#[repr(C)]
#[derive(Copy, Clone)]
struct SockaddrIn6 {
    sin6_family: u16,
    sin6_port: u16,
    sin6_flowinfo: u32,
    sin6_addr: [u8; 16],
    sin6_scope_id: u32,
}

/// Resolved destination of the datagram, address-family-tagged.
struct Dest {
    family: u8,             // 2 (AF_INET) or 10 (AF_INET6)
    port_be: u16,           // network byte order
    addr: [u8; ADDR_LEN],   // v4 in [0..4], v6 in [0..16]
}

#[kprobe]
pub fn udp_sendmsg(ctx: ProbeContext) -> u32 {
    let _ = try_udp_sendmsg(&ctx);
    0
}

#[inline(always)]
fn try_udp_sendmsg(ctx: &ProbeContext) -> Result<(), i64> {
    // udp_sendmsg(struct sock *sk, struct msghdr *msg, size_t len)
    let sk_ptr: *const u8 = match ctx.arg(0) {
        Some(p) => p,
        None => return Ok(()),
    };
    let msg_ptr: *const u8 = match ctx.arg(1) {
        Some(p) => p,
        None => return Ok(()),
    };
    if msg_ptr.is_null() {
        return Ok(());
    }

    // Resolve the destination: prefer an explicit `msg_name`
    // (connectionless `sendto`); fall back to the socket destination
    // for connected UDP (`connect()` + `send()`, what glibc uses).
    let dest = match dest_from_msg_name(msg_ptr)? {
        Some(d) => d,
        None => match dest_from_sock(sk_ptr)? {
            Some(d) => d,
            None => return Ok(()),
        },
    };

    // Cheap filter: only DNS (UDP/53).
    if dest.port_be != DNS_PORT_BE {
        return Ok(());
    }

    let mut entry = match DNS_QUERY_EVENTS.reserve::<DnsQueryRaw>(0) {
        Some(e) => e,
        None => return Ok(()),
    };
    let raw_ptr: *mut DnsQueryRaw = entry.as_mut_ptr();
    unsafe {
        core::ptr::write_bytes(raw_ptr, 0u8, 1);
    }

    let pid_tgid = bpf_get_current_pid_tgid();
    let uid_gid = bpf_get_current_uid_gid();
    unsafe {
        (*raw_ptr).pid = (pid_tgid >> 32) as u32;
        (*raw_ptr).uid = (uid_gid & 0xFFFF_FFFF) as u32;
        (*raw_ptr).family = dest.family;
        (*raw_ptr).timestamp_ns = bpf_ktime_get_ns();
        let dst = (*raw_ptr).dns_server.as_mut_ptr();
        let mut i = 0usize;
        while i < ADDR_LEN {
            *dst.add(i) = dest.addr[i];
            i += 1;
        }
    }

    // Bug 3 — copy the label-encoded QNAME + qtype out of the UDP
    // payload. Best-effort: a miss (ITER_IOVEC, short/odd packet,
    // user-read fault) leaves qname_len = 0 / qtype = 0, and the event
    // still carries pid/comm/dst for destination-level attribution.
    let (qname_len, qtype) = extract_qname(msg_ptr, raw_ptr);
    unsafe {
        (*raw_ptr).qname_len = qname_len;
        (*raw_ptr).qtype = qtype;
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

    entry.submit(0);
    Ok(())
}

/// Read the destination from an explicit `msg_name` sockaddr (the
/// connectionless `sendto(addr)` path). Returns `None` when there is
/// no usable address (NULL pointer or `namelen < 4`), signalling the
/// caller to fall back to the socket.
#[inline(always)]
fn dest_from_msg_name(msg_ptr: *const u8) -> Result<Option<Dest>, i64> {
    let name_ptr: *const u8 = match unsafe {
        bpf_probe_read_kernel::<*const u8>(msg_ptr.add(MSGHDR_NAME_OFFSET) as *const _)
    } {
        Ok(p) => p,
        Err(_) => return Ok(None),
    };
    if name_ptr.is_null() {
        return Ok(None);
    }
    let namelen: i32 = match unsafe {
        bpf_probe_read_kernel::<i32>(msg_ptr.add(MSGHDR_NAMELEN_OFFSET) as *const _)
    } {
        Ok(v) => v,
        Err(_) => return Ok(None),
    };
    // Need at least sa_family + sa_port (4 bytes). 0/negative means
    // "no msg_name" — connected socket; the caller falls back to `sk`.
    if namelen < 4 {
        return Ok(None);
    }

    let family: u16 = match unsafe { bpf_probe_read_kernel::<u16>(name_ptr as *const u16) } {
        Ok(v) => v,
        Err(_) => return Ok(None),
    };
    let mut addr = [0u8; ADDR_LEN];
    match family {
        AF_INET => {
            let sa: SockaddrIn =
                match unsafe { bpf_probe_read_kernel::<SockaddrIn>(name_ptr as *const SockaddrIn) }
                {
                    Ok(v) => v,
                    Err(_) => return Ok(None),
                };
            let bytes = sa.sin_addr.to_ne_bytes();
            let mut i = 0usize;
            while i < 4 {
                addr[i] = bytes[i];
                i += 1;
            }
            Ok(Some(Dest {
                family: 2,
                port_be: sa.sin_port,
                addr,
            }))
        }
        AF_INET6 => {
            let sa: SockaddrIn6 = match unsafe {
                bpf_probe_read_kernel::<SockaddrIn6>(name_ptr as *const SockaddrIn6)
            } {
                Ok(v) => v,
                Err(_) => return Ok(None),
            };
            let mut i = 0usize;
            while i < ADDR_LEN {
                addr[i] = sa.sin6_addr[i];
                i += 1;
            }
            Ok(Some(Dest {
                family: 10,
                port_be: sa.sin6_port,
                addr,
            }))
        }
        _ => Ok(None),
    }
}

/// Bug 2 — read the destination from the socket's `__sk_common` for
/// connected UDP (no `msg_name`). Uses the N2-validated `sock` offsets.
#[inline(always)]
fn dest_from_sock(sk_ptr: *const u8) -> Result<Option<Dest>, i64> {
    if sk_ptr.is_null() {
        return Ok(None);
    }
    let family: u16 =
        match unsafe { bpf_probe_read_kernel::<u16>(sk_ptr.add(SOCK_SKC_FAMILY_OFFSET) as *const _) }
        {
            Ok(v) => v,
            Err(_) => return Ok(None),
        };
    let port_be: u16 =
        match unsafe { bpf_probe_read_kernel::<u16>(sk_ptr.add(SOCK_SKC_DPORT_OFFSET) as *const _) }
        {
            Ok(v) => v,
            Err(_) => return Ok(None),
        };
    let mut addr = [0u8; ADDR_LEN];
    match family {
        AF_INET => {
            let daddr: u32 = match unsafe {
                bpf_probe_read_kernel::<u32>(sk_ptr.add(SOCK_SKC_DADDR_OFFSET) as *const _)
            } {
                Ok(v) => v,
                Err(_) => return Ok(None),
            };
            let bytes = daddr.to_ne_bytes();
            let mut i = 0usize;
            while i < 4 {
                addr[i] = bytes[i];
                i += 1;
            }
            Ok(Some(Dest {
                family: 2,
                port_be,
                addr,
            }))
        }
        AF_INET6 => {
            let v6: [u8; ADDR_LEN] = match unsafe {
                bpf_probe_read_kernel::<[u8; ADDR_LEN]>(
                    sk_ptr.add(SOCK_SKC_V6_DADDR_OFFSET) as *const _
                )
            } {
                Ok(v) => v,
                Err(_) => return Ok(None),
            };
            let mut i = 0usize;
            while i < ADDR_LEN {
                addr[i] = v6[i];
                i += 1;
            }
            Ok(Some(Dest {
                family: 10,
                port_be,
                addr,
            }))
        }
        _ => Ok(None),
    }
}

/// Bug 3 — copy the label-encoded QNAME into `(*raw_ptr).query_name`
/// and return `(qname_len, qtype_host_order)`. Handles the `ITER_UBUF`
/// single-buffer path only; any other iter type / read failure returns
/// `(0, 0)` (empty name) without faulting.
#[inline(always)]
fn extract_qname(msg_ptr: *const u8, raw_ptr: *mut DnsQueryRaw) -> (u16, u16) {
    // iter_type discriminant.
    let iter_type: u8 = match unsafe {
        bpf_probe_read_kernel::<u8>(
            msg_ptr.add(MSGHDR_MSG_ITER_OFFSET + IOV_ITER_ITER_TYPE_OFFSET) as *const _,
        )
    } {
        Ok(v) => v,
        Err(_) => return (0, 0),
    };
    if iter_type != ITER_UBUF {
        // ITER_IOVEC / ITER_KVEC / ITER_BVEC — documented follow-up.
        return (0, 0);
    }

    // For ITER_UBUF the inline iovec's iov_base sits at the union start
    // and is a *user* pointer to the datagram the caller is sending.
    let buf_ptr: *const u8 = match unsafe {
        bpf_probe_read_kernel::<*const u8>(
            msg_ptr.add(MSGHDR_MSG_ITER_OFFSET + IOV_ITER_UBUF_BASE_OFFSET) as *const _,
        )
    } {
        Ok(p) => p,
        Err(_) => return (0, 0),
    };
    if buf_ptr.is_null() {
        return (0, 0);
    }

    // QNAME begins right after the fixed 12-byte DNS header. The root
    // label is 0x00 == NUL, so the str helper stops at the QNAME end,
    // bounded by the destination length.
    let qname_src = unsafe { buf_ptr.add(DNS_HEADER_LEN) };
    let read = unsafe {
        let dst = core::slice::from_raw_parts_mut((*raw_ptr).query_name.as_mut_ptr(), QNAME_LEN);
        bpf_probe_read_user_str_bytes(qname_src, dst)
    };
    let qname_len = match read {
        Ok(bytes) => bytes.len(),
        Err(_) => return (0, 0),
    };
    if qname_len == 0 || qname_len >= QNAME_LEN {
        // Empty (root query) or no terminator within bounds — emit the
        // name length we have, but skip qtype (offset unreliable).
        return (qname_len as u16, 0);
    }

    // QTYPE is the 2 big-endian bytes immediately after the QNAME's
    // 0x00 root label (which str_bytes consumed but did not count).
    let qtype_be: [u8; 2] = match unsafe {
        bpf_probe_read_user::<[u8; 2]>(qname_src.add(qname_len + 1) as *const _)
    } {
        Ok(v) => v,
        Err(_) => return (qname_len as u16, 0),
    };
    let qtype = ((qtype_be[0] as u16) << 8) | (qtype_be[1] as u16);
    (qname_len as u16, qtype)
}
