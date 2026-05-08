//! File-open sensor.
//!
//! **Deviation from spec:** this hooks the `syscalls/sys_enter_openat`
//! tracepoint instead of the LSM `file_open` hook. Rationale:
//! `bpf-linker` 0.10 does not emit a `.BTF` section for Rust eBPF
//! programs, and Aya's LSM loader needs CO-RE relocations against
//! kernel structs (`struct file`, `f_path.dentry`) that fail without
//! it. The tracepoint gives the same userland telemetry (pid, uid,
//! gid, filename, flags) and is portable across kernels. When eBPF
//! BTF lands properly, we'll switch the hook for Tappa 7
//! enforcement.

use aya_ebpf::{
    helpers::{
        bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_get_current_uid_gid,
        bpf_ktime_get_ns, bpf_probe_read_user_str_bytes,
    },
    macros::{map, tracepoint},
    maps::RingBuf,
    programs::TracePointContext,
};
use northnarrow_common::wire::{FileOpenRaw, FILENAME_LEN, TASK_COMM_LEN};

/// Ringbuffer dedicated to FileOpen events.
#[map]
static FILE_OPEN_EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

// `sys_enter_openat` event format (offsets confirmed against
// /sys/kernel/debug/tracing/events/syscalls/sys_enter_openat/format
// on Linux 6.x; stable across the 5.x→6.x window):
//
//   field:int            __syscall_nr;  offset:8;  size:4;
//   field:int            dfd;           offset:16; size:8;  (long)
//   field:const char *   filename;      offset:24; size:8;
//   field:int            flags;         offset:32; size:8;  (long)
//   field:umode_t        mode;          offset:40; size:8;
const FILENAME_PTR_OFFSET: usize = 24;
const FLAGS_OFFSET: usize = 32;

#[tracepoint]
pub fn sys_enter_openat(ctx: TracePointContext) -> u32 {
    let _ = try_sys_enter_openat(&ctx);
    0
}

#[inline(always)]
fn try_sys_enter_openat(ctx: &TracePointContext) -> Result<(), i64> {
    let mut entry = match FILE_OPEN_EVENTS.reserve::<FileOpenRaw>(0) {
        Some(e) => e,
        None => return Ok(()),
    };
    let raw_ptr: *mut FileOpenRaw = entry.as_mut_ptr();
    unsafe {
        core::ptr::write_bytes(raw_ptr, 0u8, 1);
    }

    let pid_tgid = bpf_get_current_pid_tgid();
    let uid_gid = bpf_get_current_uid_gid();
    let flags = unsafe { ctx.read_at::<u64>(FLAGS_OFFSET) }.unwrap_or(0) as u32;
    let filename_ptr = unsafe { ctx.read_at::<u64>(FILENAME_PTR_OFFSET) }.unwrap_or(0);

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
            let dst = core::slice::from_raw_parts_mut(
                (*raw_ptr).filename.as_mut_ptr(),
                FILENAME_LEN,
            );
            let _ = bpf_probe_read_user_str_bytes(filename_ptr as *const u8, dst);
        }
    }

    entry.submit(0);
    Ok(())
}
