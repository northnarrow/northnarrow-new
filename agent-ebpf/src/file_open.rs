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
//!
//! Lot 324: on a kernel where the syscall tracepoint runs only on CPU 0
//! (Ubuntu 26.04's 7.0), the boot's self-test takes [`file_open_raw`], on
//! the raw `sys_enter` tracepoint, instead (`exec_check.rs`, "Lot 324:
//! every CPU").

use aya_ebpf::{
    helpers::{
        bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_get_current_uid_gid, bpf_ktime_get_ns,
        bpf_probe_read_kernel, bpf_probe_read_user_str_bytes,
    },
    macros::{map, raw_tracepoint, tracepoint},
    maps::{Array, RingBuf},
    programs::{RawTracePointContext, TracePointContext},
    EbpfContext,
};
use northnarrow_common::wire::{FileOpenRaw, FILENAME_LEN, TASK_COMM_LEN};

/// Ringbuffer dedicated to FileOpen events.
#[map]
static FILE_OPEN_EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

/// Slot 0: non-zero = emit (tracepoint mode, or the LSM sensor could not be
/// armed). Zero, the map's initial value, keeps the program inert — both
/// attach points ([`sys_enter_openat`], [`file_open_raw`]) read it.
#[map]
static FILE_OPEN_TP_ON: Array<u32> = Array::with_max_entries(1, 0);

/// x86-64's `openat` (`arch/x86/entry/syscalls/syscall_64.tbl`). The
/// fallback is armed only where the `pt_regs` offsets resolve, x86-64.
const NR_OPENAT: u64 = 257;

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
use crate::btf_offsets::{
    PT_REGS_DX_OFFSET, PT_REGS_SI_OFFSET, TP_SYS_ENTER_OPENAT_FILENAME_OFFSET, TP_SYS_ENTER_OPENAT_FLAGS_OFFSET,
};

#[tracepoint]
pub fn sys_enter_openat(ctx: TracePointContext) -> u32 {
    if !emitting() {
        return 0;
    }
    // SAFETY: `read_at` copies the record's fields with
    // `bpf_probe_read_kernel` at offsets tracefs gave for this kernel's
    // record (a failed read is 0).
    let (filename_ptr, flags) = unsafe {
        (
            ctx.read_at::<u64>(off!(TP_SYS_ENTER_OPENAT_FILENAME_OFFSET)).unwrap_or(0),
            ctx.read_at::<u64>(off!(TP_SYS_ENTER_OPENAT_FLAGS_OFFSET)).unwrap_or(0) as u32,
        )
    };
    record(crate::exec_check::SEEN_OPEN_TP, crate::exec_check::BY_TRACEPOINT, filename_ptr, flags);
    0
}

/// Lot 324: the file-open sensor's every-CPU fallback, on the raw
/// `sys_enter` tracepoint (`exec_check.rs`, "Lot 324: every CPU"): native
/// `openat` only, as [`sys_enter_openat`] sees it — the path from the
/// call's second register (`si`), the flags from its third (`dx`).
#[raw_tracepoint(tracepoint = "sys_enter")]
pub fn file_open_raw(ctx: RawTracePointContext) -> i32 {
    // SAFETY: `sys_enter(struct pt_regs *regs, long id)`: the context holds
    // two 8-byte arguments, which the verifier checks the two loads against;
    // `regs` is read through `bpf_probe_read_kernel` only (`native_arg`).
    unsafe {
        let args = ctx.as_ptr() as *const u64;
        if *args.add(1) != NR_OPENAT || !emitting() {
            return 0;
        }
        let regs = *args;
        if let Some(filename_ptr) = crate::exec_check::native_arg(regs, off_opt!(PT_REGS_SI_OFFSET)) {
            let flags = match off_opt!(PT_REGS_DX_OFFSET) {
                Some(o) => bpf_probe_read_kernel::<u64>((regs as *const u8).add(o & 0xfff) as *const u64)
                    .unwrap_or(0) as u32,
                None => 0,
            };
            record(crate::exec_check::SEEN_OPEN_RAW, crate::exec_check::BY_RAW, filename_ptr, flags);
        }
    }
    0
}

/// [`FILE_OPEN_TP_ON`] is on.
#[inline(always)]
fn emitting() -> bool {
    matches!(FILE_OPEN_TP_ON.get(0), Some(on) if *on != 0)
}

/// One record for the open of the path at `filename_ptr` in the caller's
/// memory (0: none) with `flags`, or nothing: for the boot's self-test's
/// call (`exec_check::probe_seen`, marked in the attach point's `row`), and
/// while the other attach point (`by`) records (`exec_check::emits`).
#[inline(always)]
fn record(row: u32, by: u32, filename_ptr: u64, flags: u32) {
    let pid_tgid = bpf_get_current_pid_tgid();
    if crate::exec_check::probe_seen(row, pid_tgid) {
        return;
    }
    if !crate::exec_check::emits(crate::exec_check::EMIT_OPEN, by) {
        return;
    }
    let mut entry = match FILE_OPEN_EVENTS.reserve::<FileOpenRaw>(0) {
        Some(e) => e,
        None => {
            crate::drops::bump(northnarrow_common::ring_drops::ring_slot::FILE_OPEN);
            return;
        }
    };
    let raw_ptr: *mut FileOpenRaw = entry.as_mut_ptr();
    let uid_gid = bpf_get_current_uid_gid();
    let comm = bpf_get_current_comm().unwrap_or([0u8; 16]);
    // SAFETY: `raw_ptr` is the ring entry reserved above, ours alone until
    // the submit below, and `FileOpenRaw`-sized: the zeroing and the field
    // writes stay inside it; `comm` is 16 bytes and `TASK_COMM_LEN` is 16.
    // The path is copied from user memory by `bpf_probe_read_user_str_bytes`,
    // bounded by the field's `FILENAME_LEN` (a failed read leaves it zeroed).
    unsafe {
        crate::zero::zero(raw_ptr);
        (*raw_ptr).pid = (pid_tgid >> 32) as u32;
        (*raw_ptr).uid = (uid_gid & 0xFFFF_FFFF) as u32;
        (*raw_ptr).gid = (uid_gid >> 32) as u32;
        (*raw_ptr).flags = flags;
        (*raw_ptr).timestamp_ns = bpf_ktime_get_ns();
        let dst = (*raw_ptr).comm.as_mut_ptr();
        let src = comm.as_ptr();
        let mut i = 0usize;
        while i < TASK_COMM_LEN {
            *dst.add(i) = *src.add(i);
            i += 1;
        }
        // filename — read from user memory.
        if filename_ptr != 0 {
            let dst = core::slice::from_raw_parts_mut((*raw_ptr).filename.as_mut_ptr(), FILENAME_LEN);
            let _ = bpf_probe_read_user_str_bytes(filename_ptr as *const u8, dst);
        }
    }
    entry.submit(0);
}
