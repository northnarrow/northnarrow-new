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

use aya_ebpf::{
    helpers::{
        bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_get_current_uid_gid, bpf_ktime_get_ns,
        bpf_probe_read_kernel,
    },
    macros::{kprobe, map},
    maps::RingBuf,
    programs::ProbeContext,
};
use northnarrow_common::wire::{TcpConnectRaw, ADDR_LEN, TASK_COMM_LEN};

#[map]
static TCP_CONNECT_EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

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
    // Skip loopback (127.0.0.0/8 → first byte 127 in network order
    // since the address is stored big-endian).
    let addr_bytes = sa.sin_addr.to_ne_bytes();
    if addr_bytes[0] == 127 {
        return Ok(());
    }

    let mut entry = match TCP_CONNECT_EVENTS.reserve::<TcpConnectRaw>(0) {
        Some(e) => e,
        None => return Ok(()),
    };
    let raw_ptr: *mut TcpConnectRaw = entry.as_mut_ptr();
    unsafe {
        core::ptr::write_bytes(raw_ptr, 0u8, 1);
    }
    populate_common(raw_ptr);
    unsafe {
        (*raw_ptr).family = AF_INET;
        (*raw_ptr).dst_port = u16::from_be(sa.sin_port);
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
    entry.submit(0);
    Ok(())
}

#[inline(always)]
fn try_tcp_connect_v6(ctx: &ProbeContext) -> Result<(), i64> {
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
    // Skip ::1 (loopback) — bytes 0..15 == 0, byte 15 == 1.
    let mut all_zero = true;
    let mut i = 0usize;
    while i < 15 {
        if sa.sin6_addr[i] != 0 {
            all_zero = false;
            break;
        }
        i += 1;
    }
    if all_zero && sa.sin6_addr[15] == 1 {
        return Ok(());
    }

    let mut entry = match TCP_CONNECT_EVENTS.reserve::<TcpConnectRaw>(0) {
        Some(e) => e,
        None => return Ok(()),
    };
    let raw_ptr: *mut TcpConnectRaw = entry.as_mut_ptr();
    unsafe {
        core::ptr::write_bytes(raw_ptr, 0u8, 1);
    }
    populate_common(raw_ptr);
    unsafe {
        (*raw_ptr).family = AF_INET6;
        (*raw_ptr).dst_port = u16::from_be(sa.sin6_port);
        let dst = (*raw_ptr).dst_addr.as_mut_ptr();
        let mut i = 0usize;
        while i < ADDR_LEN {
            *dst.add(i) = sa.sin6_addr[i];
            i += 1;
        }
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
