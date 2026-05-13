//! DNS query sensor (kprobe on `udp_sendmsg`).
//!
//! **Deviations from spec**, for verifier and BTF reasons:
//!
//! 1. We do not parse the DNS payload in eBPF. The verifier rejects
//!    iov_iter walking without CO-RE field access against the kernel
//!    `struct msghdr`, which we lack since bpf-linker 0.10 doesn't
//!    emit BTF. Instead we emit `qname_len = 0`, `qtype = 0`, and let
//!    userland enrich later (Tappa 6, with the LLM, or Tappa 7 once
//!    full CO-RE is wired). The event still carries pid, comm, uid,
//!    and the destination address from `msg_name` — enough to assert
//!    "process X just talked DNS to Y".
//!
//! 2. We read `msg_name` and `msg_namelen` directly from
//!    `struct msghdr` using their UAPI-stable offsets (0 and 8).
//!    These have not moved across the 5.x → 6.x window and are
//!    documented kernel ABI for `recvmsg(2)` users.

use aya_ebpf::{
    helpers::{
        bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_get_current_uid_gid, bpf_ktime_get_ns,
        bpf_probe_read_kernel,
    },
    macros::{kprobe, map},
    maps::RingBuf,
    programs::ProbeContext,
};
use northnarrow_common::wire::{DnsQueryRaw, ADDR_LEN, TASK_COMM_LEN};

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

#[kprobe]
pub fn udp_sendmsg(ctx: ProbeContext) -> u32 {
    let _ = try_udp_sendmsg(&ctx);
    0
}

#[inline(always)]
fn try_udp_sendmsg(ctx: &ProbeContext) -> Result<(), i64> {
    // arg(1) is `struct msghdr *msg`.
    let msg_ptr: *const u8 = match ctx.arg(1) {
        Some(p) => p,
        None => return Ok(()),
    };
    if msg_ptr.is_null() {
        return Ok(());
    }

    // Read msg_name pointer + msg_namelen.
    let name_ptr: *const u8 = match unsafe {
        bpf_probe_read_kernel::<*const u8>(msg_ptr.add(MSGHDR_NAME_OFFSET) as *const _)
    } {
        Ok(p) => p,
        Err(_) => return Ok(()),
    };
    if name_ptr.is_null() {
        return Ok(());
    }
    let namelen: i32 = match unsafe {
        bpf_probe_read_kernel::<i32>(msg_ptr.add(MSGHDR_NAMELEN_OFFSET) as *const _)
    } {
        Ok(v) => v,
        Err(_) => return Ok(()),
    };

    // Need at least sa_family + sa_port (4 bytes). 0/negative means
    // "no msg_name" — the caller used connect() instead, in which
    // case we can't tell the dst port without poking sk fields.
    if namelen < 4 {
        return Ok(());
    }

    // Read the sockaddr family + port first to filter cheaply.
    let family: u16 = match unsafe { bpf_probe_read_kernel::<u16>(name_ptr as *const u16) } {
        Ok(v) => v,
        Err(_) => return Ok(()),
    };
    let port_be: u16 = match unsafe { bpf_probe_read_kernel::<u16>(name_ptr.add(2) as *const u16) }
    {
        Ok(v) => v,
        Err(_) => return Ok(()),
    };
    if port_be != DNS_PORT_BE {
        return Ok(());
    }

    // Pull address bytes per family.
    let mut dns_server = [0u8; ADDR_LEN];
    let raw_family;
    match family {
        AF_INET => {
            raw_family = 2u8;
            let sa: SockaddrIn =
                match unsafe { bpf_probe_read_kernel::<SockaddrIn>(name_ptr as *const SockaddrIn) }
                {
                    Ok(v) => v,
                    Err(_) => return Ok(()),
                };
            let bytes = sa.sin_addr.to_ne_bytes();
            let mut i = 0usize;
            while i < 4 {
                dns_server[i] = bytes[i];
                i += 1;
            }
        }
        AF_INET6 => {
            raw_family = 10u8;
            let sa: SockaddrIn6 = match unsafe {
                bpf_probe_read_kernel::<SockaddrIn6>(name_ptr as *const SockaddrIn6)
            } {
                Ok(v) => v,
                Err(_) => return Ok(()),
            };
            let mut i = 0usize;
            while i < ADDR_LEN {
                dns_server[i] = sa.sin6_addr[i];
                i += 1;
            }
        }
        _ => return Ok(()),
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
        (*raw_ptr).qtype = 0;
        (*raw_ptr).family = raw_family;
        (*raw_ptr).qname_len = 0;
        (*raw_ptr).timestamp_ns = bpf_ktime_get_ns();
        let dst = (*raw_ptr).dns_server.as_mut_ptr();
        let mut i = 0usize;
        while i < ADDR_LEN {
            *dst.add(i) = dns_server[i];
            i += 1;
        }
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
