//! Tappa 10 (N2) — TCP listener observation kprobe.
//!
//! Hooked at the entry of `inet_csk_listen_start(struct sock *sk,
//! int backlog)` (per design §13 Q1 owner decision — canonical
//! kernel function, matches T4's `tcp_v4_connect` naming
//! precedent). Fires on every listen() syscall on a TCP socket.
//! Emits one [`NetListenRaw`] per call into [`NET_LISTEN_EVENTS`],
//! unconditionally — design §13 Q6 LOCK-IN: TRACK EVERY listener
//! (forensic-visibility goal; rule-side N6 NN-L-NET-006 does the
//! operator-tunable comm + port allowlist filtering).
//!
//! Reads `__sk_common` + `sk_protocol` via the empirically-validated
//! BTF offsets in [`crate::btf_offsets`] (kernel 6.8.0-117,
//! validated 2026-05-20). The runbook bumps these offsets on a
//! kernel upgrade.
//!
//! External audit EBPF-013: an unprivileged loop of `listen()` on fresh
//! sockets filled the 64 KiB ring and pushed other processes' listener
//! records out, leaving only an anonymous drop counter. Every listener is
//! still tracked within a record budget ([`crate::budget`]: per process
//! [`TASK_BURST`], then 128 per second; per user [`UID_BURST`], then 256
//! per second), which no real server reaches. Calls over it are held
//! back, counted in the `listen_rate` slot, and the process's next record
//! carries the count (`held`, `held_uid`), so the agent names the looping
//! process (NN-L-NET-021).

use aya_ebpf::{
    helpers::{
        bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_get_current_uid_gid, bpf_ktime_get_ns,
        bpf_probe_read_kernel,
    },
    macros::{kprobe, map},
    maps::{LruHashMap, RingBuf},
    programs::ProbeContext,
};
use northnarrow_common::wire::{NetListenRaw, ADDR_LEN, NET_LISTEN_EVENTS_BYTES, TASK_COMM_LEN};

use crate::budget::{admit, saturate_u32, Budget, Limits};
use crate::btf_offsets::{
    SOCK_SKC_FAMILY_OFFSET, SOCK_SKC_NUM_OFFSET, SOCK_SKC_RCV_SADDR_OFFSET,
    SOCK_SKC_V6_RCV_SADDR_OFFSET, SOCK_SK_PROTOCOL_OFFSET,
};

#[map]
pub static NET_LISTEN_EVENTS: RingBuf = RingBuf::with_byte_size(NET_LISTEN_EVENTS_BYTES, 0);

/// External audit EBPF-013: listener record budgets, per process (tgid)
/// and per user.
#[map]
static LISTEN_TASK_BUDGET: LruHashMap<u32, Budget> = LruHashMap::with_max_entries(4096, 0);
#[map]
static LISTEN_UID_BUDGET: LruHashMap<u32, Budget> = LruHashMap::with_max_entries(1024, 0);

/// Listener records a process may send in a burst (also its first ones).
const TASK_BURST: u64 = 64;
/// Records a user may send in a burst, across its processes.
const UID_BURST: u64 = 512;

const LISTEN_LIMITS: Limits = Limits {
    task_burst: TASK_BURST,
    // After a burst, 128 records per second.
    task_refill_ns: 1_000_000_000 / 128,
    uid_burst: UID_BURST,
    // After a burst, 256 records per second.
    uid_refill_ns: 1_000_000_000 / 256,
};

const AF_INET: u16 = 2;
const AF_INET6: u16 = 10;

#[kprobe]
pub fn inet_csk_listen_start(ctx: ProbeContext) -> u32 {
    let _ = try_inet_csk_listen_start(&ctx);
    0
}

#[inline(always)]
fn try_inet_csk_listen_start(ctx: &ProbeContext) -> Result<(), i64> {
    // arg(0) is `struct sock *sk`.
    let sk_ptr: *const u8 = match ctx.arg(0) {
        Some(p) => p,
        None => return Ok(()),
    };
    if sk_ptr.is_null() {
        return Ok(());
    }

    // Read scalar fields from `__sk_common` + `struct sock` via
    // bpf_probe_read_kernel + the validated offsets. Each read
    // is unsafe but bounded to a single primitive read.
    let family: u16 =
        match unsafe { bpf_probe_read_kernel(sk_ptr.add(off!(SOCK_SKC_FAMILY_OFFSET)) as *const u16) } {
            Ok(v) => v,
            Err(_) => return Ok(()),
        };
    // Only TCP listeners reach `inet_csk_listen_start`; UDP "bind"
    // doesn't go through this path. Still defensively gate on
    // family for cleanliness.
    if family != AF_INET && family != AF_INET6 {
        return Ok(());
    }
    let proto: u16 =
        match unsafe { bpf_probe_read_kernel(sk_ptr.add(off!(SOCK_SK_PROTOCOL_OFFSET)) as *const u16) } {
            Ok(v) => v,
            Err(_) => return Ok(()),
        };
    let bind_port_host: u16 =
        match unsafe { bpf_probe_read_kernel(sk_ptr.add(off!(SOCK_SKC_NUM_OFFSET)) as *const u16) } {
            Ok(v) => v,
            Err(_) => return Ok(()),
        };

    // External audit EBPF-013: the record budget, before the ring.
    let pid_tgid = bpf_get_current_pid_tgid();
    let uid_gid = bpf_get_current_uid_gid();
    let held = match unsafe {
        admit(
            &LISTEN_TASK_BUDGET,
            &LISTEN_UID_BUDGET,
            (pid_tgid >> 32) as u32,
            (uid_gid & 0xFFFF_FFFF) as u32,
            bpf_ktime_get_ns(),
            LISTEN_LIMITS,
            northnarrow_common::ring_drops::ring_slot::LISTEN_RATE,
        )
    } {
        Some(h) => h,
        None => return Ok(()),
    };

    // Reserve + populate.
    let mut entry = match NET_LISTEN_EVENTS.reserve::<NetListenRaw>(0) {
        Some(e) => e,
        None => {
            crate::drops::bump(northnarrow_common::ring_drops::ring_slot::LISTEN);
            return Ok(());
        }
    };
    let raw_ptr: *mut NetListenRaw = entry.as_mut_ptr();
    unsafe {
        crate::zero::zero(raw_ptr);
    }

    let comm = bpf_get_current_comm().unwrap_or([0u8; 16]);
    unsafe {
        (*raw_ptr).held = saturate_u32(held.task);
        (*raw_ptr).held_uid = saturate_u32(held.user);
        (*raw_ptr).timestamp_ns = bpf_ktime_get_ns();
        (*raw_ptr).pid = (pid_tgid >> 32) as u32;
        (*raw_ptr).uid = (uid_gid & 0xFFFF_FFFF) as u32;
        (*raw_ptr).family = family as u8;
        (*raw_ptr).proto = proto as u8;
        (*raw_ptr).bind_port = bind_port_host;
        // bind_addr: read v4 OR v6 source per family.
        let dst = (*raw_ptr).bind_addr.as_mut_ptr();
        if family == AF_INET {
            // skc_rcv_saddr is u32; copy into first 4 bytes of slot.
            let saddr: u32 =
                match bpf_probe_read_kernel(sk_ptr.add(off!(SOCK_SKC_RCV_SADDR_OFFSET)) as *const u32) {
                    Ok(v) => v,
                    Err(_) => 0,
                };
            let bytes = saddr.to_ne_bytes();
            let mut i = 0usize;
            while i < 4 {
                *dst.add(i) = bytes[i];
                i += 1;
            }
            while i < ADDR_LEN {
                *dst.add(i) = 0;
                i += 1;
            }
        } else {
            // AF_INET6 — 16 bytes from skc_v6_rcv_saddr.
            let v6: [u8; ADDR_LEN] = match bpf_probe_read_kernel(
                sk_ptr.add(off!(SOCK_SKC_V6_RCV_SADDR_OFFSET)) as *const [u8; ADDR_LEN],
            ) {
                Ok(v) => v,
                Err(_) => [0u8; ADDR_LEN],
            };
            let mut i = 0usize;
            while i < ADDR_LEN {
                *dst.add(i) = v6[i];
                i += 1;
            }
        }
        let src = comm.as_ptr();
        let cdst = (*raw_ptr).comm.as_mut_ptr();
        let mut i = 0usize;
        while i < TASK_COMM_LEN {
            *cdst.add(i) = *src.add(i);
            i += 1;
        }
    }
    entry.submit(0);
    Ok(())
}
