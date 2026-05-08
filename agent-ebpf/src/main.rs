//! NorthNarrow eBPF program: process exec sensor.
//!
//! Tappa 1: a tracepoint on `sched/sched_process_exec` builds a
//! [`ProcessSpawnRaw`] event for every exec on the system and pushes
//! it into a 256 KiB ringbuffer for the userland agent to consume.
//!
//! Constraints (verifier-friendly):
//! - `no_std`, no allocations, no panics in the hot path.
//! - All loops are bounded by compile-time constants.
//! - The event lives in ringbuffer-reserved memory; no extra copy.
//!
//! Layout MUST stay in sync with `northnarrow_common::wire`. The
//! struct is consumed by userland via `bytemuck::Pod`.

#![no_std]
#![no_main]
#![allow(static_mut_refs)]

use aya_ebpf::{
    helpers::{
        bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_get_current_uid_gid,
        bpf_ktime_get_ns, bpf_probe_read_kernel_buf,
    },
    macros::{map, tracepoint},
    maps::{PerCpuArray, RingBuf},
    programs::TracePointContext,
    EbpfContext,
};
use core::mem::MaybeUninit;
use northnarrow_common::wire::{ProcessSpawnRaw, FILENAME_LEN, TASK_COMM_LEN};

/// Ringbuffer carrying [`ProcessSpawnRaw`] events to userland.
/// 256 KiB is room for ~880 events; sized to absorb short bursts.
#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

/// Per-CPU drop counter, incremented when the ringbuf is full.
/// Userland may inspect it for telemetry; not consumed yet.
#[map]
static DROPPED: PerCpuArray<u64> = PerCpuArray::with_max_entries(1, 0);

// `sched_process_exec` event format (see
// /sys/kernel/debug/tracing/events/sched/sched_process_exec/format):
//
//   field:unsigned short common_type;        offset:0;  size:2;
//   field:unsigned char  common_flags;       offset:2;  size:1;
//   field:unsigned char  common_preempt_count;offset:3; size:1;
//   field:int            common_pid;         offset:4;  size:4;
//   field:__data_loc char[] filename;        offset:8;  size:4;
//   field:pid_t          pid;                offset:12; size:4;
//   field:pid_t          old_pid;            offset:16; size:4;
//
// The `__data_loc` is a u32: low 16 bits = byte offset to the string
// from the start of the event, high 16 bits = string length (incl NUL).
const FILENAME_DATA_LOC_OFFSET: usize = 8;

#[tracepoint]
pub fn sched_process_exec(ctx: TracePointContext) -> u32 {
    match try_sched_process_exec(&ctx) {
        Ok(()) => 0,
        Err(_) => 1,
    }
}

#[inline(always)]
fn try_sched_process_exec(ctx: &TracePointContext) -> Result<(), i64> {
    let mut entry = match EVENTS.reserve::<ProcessSpawnRaw>(0) {
        Some(e) => e,
        None => {
            // Ringbuf full — bump the per-CPU drop counter and return
            // success so the verifier doesn't see this as an error path.
            if let Some(c) = DROPPED.get_ptr_mut(0) {
                unsafe { *c = (*c).wrapping_add(1) };
            }
            return Ok(());
        }
    };

    // Initialise the reserved slot. `reserve` returns
    // `MaybeUninit<ProcessSpawnRaw>`; we must fully populate it before
    // calling `submit`. We zero first so any padding/short reads stay
    // deterministic.
    let raw_ptr: *mut ProcessSpawnRaw = entry.as_mut_ptr();
    unsafe {
        // SAFETY: ringbuf reservation gives us exclusive write access
        // to a properly aligned region of size_of::<ProcessSpawnRaw>.
        core::ptr::write_bytes(raw_ptr, 0u8, 1);
    }

    let pid_tgid = bpf_get_current_pid_tgid();
    let uid_gid = bpf_get_current_uid_gid();

    // Fields are filled via direct pointer writes to keep the BPF
    // verifier happy (no large stack copies of MaybeUninit).
    unsafe {
        (*raw_ptr).pid = (pid_tgid >> 32) as u32;
        (*raw_ptr).ppid = 0; // populated below if cheap; left 0 otherwise
        (*raw_ptr).uid = (uid_gid & 0xFFFF_FFFF) as u32;
        (*raw_ptr).gid = (uid_gid >> 32) as u32;
        (*raw_ptr).timestamp_ns = bpf_ktime_get_ns();
    }

    // comm
    let comm = bpf_get_current_comm().unwrap_or([0u8; 16]);
    unsafe {
        // Copy up to TASK_COMM_LEN bytes; the source is exactly 16.
        let src = comm.as_ptr();
        let dst = (*raw_ptr).comm.as_mut_ptr();
        // Bounded compile-time loop, verifier-friendly.
        let mut i = 0usize;
        while i < TASK_COMM_LEN {
            *dst.add(i) = *src.add(i);
            i += 1;
        }
    }

    // filename (variable length via __data_loc)
    let data_loc: u32 = match unsafe { ctx.read_at::<u32>(FILENAME_DATA_LOC_OFFSET) } {
        Ok(v) => v,
        Err(_) => 0,
    };
    let f_off = (data_loc & 0xFFFF) as usize;
    let mut f_len = ((data_loc >> 16) & 0xFFFF) as usize;
    if f_len > FILENAME_LEN {
        f_len = FILENAME_LEN;
    }
    if f_off != 0 && f_len != 0 {
        // SAFETY: the tracepoint context pointer is valid kernel memory
        // for the lifetime of this callback; bpf_probe_read_kernel_buf
        // is the verified way to read from it.
        let base = ctx.as_ptr() as *const u8;
        let src = unsafe { base.add(f_off) };
        let mut tmp: MaybeUninit<[u8; FILENAME_LEN]> = MaybeUninit::uninit();
        let dst_slice = unsafe {
            core::slice::from_raw_parts_mut(tmp.as_mut_ptr() as *mut u8, FILENAME_LEN)
        };
        // Read the actual length we computed; fall back to nothing on err.
        let _ = unsafe { bpf_probe_read_kernel_buf(src, &mut dst_slice[..f_len]) };
        unsafe {
            let dst = (*raw_ptr).filename.as_mut_ptr();
            let mut i = 0usize;
            while i < FILENAME_LEN {
                if i < f_len {
                    *dst.add(i) = *(tmp.as_ptr() as *const u8).add(i);
                } else {
                    *dst.add(i) = 0;
                }
                i += 1;
            }
        }
    }

    entry.submit(0);
    Ok(())
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    // Reachable only if the verifier accepts a panic path — which it
    // won't. This satisfies the `no_std` requirement for a panic_handler.
    loop {}
}

#[link_section = "license"]
#[no_mangle]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
