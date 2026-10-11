//! io_uring sensor (Tappa 10.8 — the blind channel).
//!
//! A process that drives file and network I/O through `io_uring` never
//! issues the `openat` / `connect` / `sendto` syscalls the other sensors
//! hook: it fills a shared ring and the kernel performs the operations
//! (RingReaper and the 2025 EDR-evasion write-ups). Two tracepoints close
//! the gap:
//!
//! * `io_uring/io_uring_create` — a ring was set up: emitted once per
//!   call (ring creation is rare and high-signal);
//! * `io_uring/io_uring_submit_req` (`io_uring_submit_sqe` on ≤ 6.1) —
//!   one firing per submission. Submissions can run at hundreds of
//!   thousands per second on an io_uring-native server, so they are
//!   aggregated per pid in [`IOURING_STATE`]: a record is emitted when
//!   the pid uses a NEW opcode class (file open, file read/write, network
//!   connect, network send/recv, filesystem mutation, other) or at most
//!   once per second with the submission count since the last record.
//!
//! Field offsets come from the `BTF_OFFSETS` map (`off!`), placed by the
//! tracefs resolver: the layouts differ on every kernel the lab runs
//! (opcode at 24 on 5.15, 32 on 6.1 and 6.8, 40 on RHEL 9).

use aya_ebpf::{
    helpers::{bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_get_current_uid_gid, bpf_ktime_get_ns},
    macros::{map, tracepoint},
    maps::{LruHashMap, RingBuf},
    programs::TracePointContext,
};
use northnarrow_common::ring_drops::ring_slot;
use northnarrow_common::wire::{
    io_uring_opcode_class, IoUringRaw, IOURING_KIND_ACTIVITY, IOURING_KIND_CREATE,
};

use crate::btf_offsets::{
    TP_IOURING_CREATE_FD_OFFSET, TP_IOURING_CREATE_FLAGS_OFFSET,
    TP_IOURING_CREATE_SQ_ENTRIES_OFFSET, TP_IOURING_SUBMIT_OPCODE_OFFSET,
    TP_IOURING_SUBMIT_SQ_THREAD_OFFSET,
};

/// Per-pid aggregation state.
#[repr(C)]
#[derive(Copy, Clone)]
pub struct IoUringState {
    /// Classes already reported for this pid.
    pub classes: u32,
    /// Submissions since the last emitted record.
    pub pending: u32,
    /// Monotonic ns of the last emitted record.
    pub last_emit_ns: u64,
}

/// Records to userland (ring creations + aggregated activity).
#[map]
pub static IOURING_EVENTS: RingBuf = RingBuf::with_byte_size(128 * 1024, 0);

/// pid → aggregation state. LRU: a pid that stops submitting ages out.
#[map]
pub static IOURING_STATE: LruHashMap<u32, IoUringState> = LruHashMap::with_max_entries(4096, 0);

/// Minimum interval between two ACTIVITY records of the same pid when no
/// new class appears (1 s).
const ACTIVITY_INTERVAL_NS: u64 = 1_000_000_000;

#[tracepoint]
pub fn io_uring_create(ctx: TracePointContext) -> u32 {
    let _ = try_create(&ctx);
    0
}

#[inline(always)]
fn try_create(ctx: &TracePointContext) -> Result<(), i64> {
    let fd: i32 = unsafe { ctx.read_at::<i32>(off!(TP_IOURING_CREATE_FD_OFFSET)) }.unwrap_or(-1);
    let sq_entries: u32 =
        unsafe { ctx.read_at::<u32>(off!(TP_IOURING_CREATE_SQ_ENTRIES_OFFSET)) }.unwrap_or(0);
    let flags: u32 = unsafe { ctx.read_at::<u32>(off!(TP_IOURING_CREATE_FLAGS_OFFSET)) }.unwrap_or(0);
    let _ = fd;
    emit(IOURING_KIND_CREATE, flags, sq_entries, 0, 0)
}

/// Same program body for both tracepoint names; userland attaches
/// whichever exists (`io_uring_submit_req`, else `io_uring_submit_sqe`).
#[tracepoint]
pub fn io_uring_submit(ctx: TracePointContext) -> u32 {
    let _ = try_submit(&ctx);
    0
}

#[inline(always)]
fn try_submit(ctx: &TracePointContext) -> Result<(), i64> {
    let opcode: u8 = unsafe { ctx.read_at::<u8>(off!(TP_IOURING_SUBMIT_OPCODE_OFFSET)) }.unwrap_or(0);
    let sq_thread: u8 =
        unsafe { ctx.read_at::<u8>(off!(TP_IOURING_SUBMIT_SQ_THREAD_OFFSET)) }.unwrap_or(0);
    let class = io_uring_opcode_class(opcode);
    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    let now = unsafe { bpf_ktime_get_ns() };

    let mut emit_now = false;
    let mut classes = class;
    let mut pending = 1u32;
    match IOURING_STATE.get_ptr_mut(&pid) {
        Some(st) => unsafe {
            let new_class = (*st).classes & class == 0;
            (*st).classes |= class;
            (*st).pending = (*st).pending.wrapping_add(1);
            if new_class || now.wrapping_sub((*st).last_emit_ns) >= ACTIVITY_INTERVAL_NS {
                emit_now = true;
                classes = (*st).classes;
                pending = (*st).pending;
                (*st).pending = 0;
                (*st).last_emit_ns = now;
            }
        },
        None => {
            // first submission of this pid: record it and emit
            let st = IoUringState {
                classes: class,
                pending: 0,
                last_emit_ns: now,
            };
            let _ = IOURING_STATE.insert(&pid, &st, 0);
            emit_now = true;
        }
    }
    if emit_now {
        return emit(IOURING_KIND_ACTIVITY, classes, pending, opcode, sq_thread);
    }
    Ok(())
}

#[inline(always)]
fn emit(kind: u8, classes: u32, count: u32, last_opcode: u8, sq_thread: u8) -> Result<(), i64> {
    let mut entry = match IOURING_EVENTS.reserve::<IoUringRaw>(0) {
        Some(e) => e,
        None => {
            crate::drops::bump(ring_slot::IOURING);
            return Ok(());
        }
    };
    let raw_ptr: *mut IoUringRaw = entry.as_mut_ptr();
    unsafe {
        crate::zero::zero(raw_ptr);
        (*raw_ptr).timestamp_ns = bpf_ktime_get_ns();
        let pid_tgid = bpf_get_current_pid_tgid();
        (*raw_ptr).pid = (pid_tgid >> 32) as u32;
        (*raw_ptr).uid = (bpf_get_current_uid_gid() & 0xFFFF_FFFF) as u32;
        if let Ok(comm) = bpf_get_current_comm() {
            (*raw_ptr).comm = comm;
        }
        (*raw_ptr).kind = kind;
        (*raw_ptr).last_opcode = last_opcode;
        (*raw_ptr).sq_thread = sq_thread;
        (*raw_ptr).classes = classes;
        (*raw_ptr).count = count;
    }
    entry.submit(0);
    Ok(())
}
