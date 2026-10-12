//! File-open sensor on the `syscalls/sys_enter_openat` tracepoint: one
//! record per `openat` of the host, read from user memory.
//!
//! Since Tappa 10.9 step 1 the default sensor is the LSM `file_open`
//! observer (`open_sensor.rs`), which filters in the kernel. This program
//! stays for `--file-open-sensor tracepoint` and as the fallback when the
//! LSM sensor cannot be armed. Review 69: it is attached at start either
//! way, but emits only once userland turns [`FILE_OPEN_TP_ON`] on. In LSM
//! mode it stays inert until the LSM sensor takes over and it is detached;
//! before, its records filled the ring and the agent's event channel while
//! the agent booted, and the events of every sensor waited behind them.

use aya_ebpf::{
    helpers::{
        bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_get_current_uid_gid, bpf_ktime_get_ns,
        bpf_probe_read_user_str_bytes,
    },
    macros::{map, tracepoint},
    maps::{Array, RingBuf},
    programs::TracePointContext,
};
use northnarrow_common::wire::{FileOpenRaw, FILENAME_LEN, TASK_COMM_LEN};

/// Ringbuffer dedicated to FileOpen events.
#[map]
static FILE_OPEN_EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

/// Slot 0: non-zero = emit (tracepoint mode, or the LSM sensor could not be
/// armed). Zero, the map's initial value, keeps the program inert.
#[map]
static FILE_OPEN_TP_ON: Array<u32> = Array::with_max_entries(1, 0);

// `sys_enter_openat` event format (offsets confirmed against
// /sys/kernel/debug/tracing/events/syscalls/sys_enter_openat/format
// on Linux 6.x; stable across the 5.x→6.x window):
//
//   field:int            __syscall_nr;  offset:8;  size:4;
//   field:int            dfd;           offset:16; size:8;  (long)
//   field:const char *   filename;      offset:24; size:8;
//   field:int            flags;         offset:32; size:8;  (long)
//   field:umode_t        mode;          offset:40; size:8;
// `sys_enter_openat.filename` / `.flags` — resolved from tracefs at boot
// (`off!(…)`, upstream 24 / 32).
use crate::btf_offsets::{TP_SYS_ENTER_OPENAT_FILENAME_OFFSET, TP_SYS_ENTER_OPENAT_FLAGS_OFFSET};

#[tracepoint]
pub fn sys_enter_openat(ctx: TracePointContext) -> u32 {
    let _ = try_sys_enter_openat(&ctx);
    0
}

#[inline(always)]
fn try_sys_enter_openat(ctx: &TracePointContext) -> Result<(), i64> {
    match FILE_OPEN_TP_ON.get(0) {
        Some(on) if *on != 0 => {}
        _ => return Ok(()),
    }
    let mut entry = match FILE_OPEN_EVENTS.reserve::<FileOpenRaw>(0) {
        Some(e) => e,
        None => {
            crate::drops::bump(northnarrow_common::ring_drops::ring_slot::FILE_OPEN);
            return Ok(());
        }
    };
    let raw_ptr: *mut FileOpenRaw = entry.as_mut_ptr();
    unsafe {
        crate::zero::zero(raw_ptr);
    }

    let pid_tgid = bpf_get_current_pid_tgid();
    let uid_gid = bpf_get_current_uid_gid();
    let flags = unsafe { ctx.read_at::<u64>(off!(TP_SYS_ENTER_OPENAT_FLAGS_OFFSET)) }.unwrap_or(0) as u32;
    let filename_ptr = unsafe { ctx.read_at::<u64>(off!(TP_SYS_ENTER_OPENAT_FILENAME_OFFSET)) }.unwrap_or(0);

    unsafe {
        (*raw_ptr).pid = (pid_tgid >> 32) as u32;
        (*raw_ptr).uid = (uid_gid & 0xFFFF_FFFF) as u32;
        (*raw_ptr).gid = (uid_gid >> 32) as u32;
        (*raw_ptr).flags = flags;
        (*raw_ptr).timestamp_ns = bpf_ktime_get_ns();
    }

    // comm
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

    // filename — read from user memory.
    if filename_ptr != 0 {
        unsafe {
            let dst =
                core::slice::from_raw_parts_mut((*raw_ptr).filename.as_mut_ptr(), FILENAME_LEN);
            let _ = bpf_probe_read_user_str_bytes(filename_ptr as *const u8, dst);
        }
    }

    entry.submit(0);
    Ok(())
}
