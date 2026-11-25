//! Pre-exec validation sensor: one [`ExecCheckRaw`] per native `execve(2)`
//! of the host, with the path read from the caller's memory.
//!
//! **Deviation from spec:** uses `syscalls/sys_enter_execve` instead
//! of the LSM `bprm_check_security` hook, for the same reason as
//! `file_open` — bpf-linker 0.10 doesn't emit BTF, so LSM CO-RE
//! reloc would fail at load time. The tracepoint gives userland
//! every field listed in the spec (pid, uid, comm, filename) and
//! fires at the same moment in the exec path (after copy_strings,
//! before the new image starts). Real `-EPERM` enforcement is a
//! Tappa 7 task anyway. (Since Tappa 10.9 step 2 the default exec sensor
//! is the LSM program, `exec_lsm.rs`; this one is its fallback.)
//!
//! ## Lot 324: every CPU
//!
//! On Ubuntu 26.04's 7.0 a program on a *syscall* tracepoint, attached as
//! aya attaches it (one perf event, CPU 0), ran only for the calls made on
//! CPU 0. The record has two attach points:
//!
//! - [`sys_enter_execve`], the syscall tracepoint (the path from the
//!   tracepoint's record, at the offset tracefs gives);
//! - [`exec_check_raw`], the raw `sys_enter` tracepoint, which runs on
//!   every CPU for every call of the host and keeps native `execve` only
//!   (the path from the call's first register, `pt_regs.di`).
//!
//! The agent's boot attaches the first, runs the self-test (a thread of the
//! agent pinned to each online CPU in turn makes one `execve("")`, which
//! fails at once), and takes the second when the first did not run on
//! every CPU (`nn_linux::sensors::exec::every_cpu`, signed). The
//! self-test's calls mark [`SYSCALL_TP_SEEN`] and leave no record.

use aya_ebpf::{
    helpers::{
        bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_get_current_task, bpf_get_current_uid_gid,
        bpf_get_smp_processor_id, bpf_ktime_get_ns, bpf_probe_read_kernel, bpf_probe_read_user_str_bytes,
    },
    macros::{map, raw_tracepoint, tracepoint},
    maps::{Array, RingBuf},
    programs::{RawTracePointContext, TracePointContext},
    EbpfContext,
};
use northnarrow_common::epg::TS_COMPAT;
use northnarrow_common::wire::{ExecCheckRaw, FILENAME_LEN, TASK_COMM_LEN};

#[map]
pub(crate) static EXEC_CHECK_EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

/// Lot 324: the CPUs the self-test can tell apart. A CPU at or above it is
/// never marked seen, so the boot's self-test counts it as missed and takes
/// the fallback.
pub(crate) const SEEN_CPUS: u32 = 1024;
/// Lot 324: the self-test's rows of [`SYSCALL_TP_SEEN`], one per attach
/// point: the exec sensor's and the file-open sensor's (`file_open.rs`), on
/// the syscall tracepoint and on the raw fallback. The review of #625
/// (P2-1): the fallback's test runs with the tracepoint still attached, and
/// with one row per sensor the tracepoint's mark of CPU 0 read as the
/// fallback's — a fallback that never ran was taken and the tracepoint
/// retired.
pub(crate) const SEEN_EXEC_TP: u32 = 0;
pub(crate) const SEEN_OPEN_TP: u32 = 1;
pub(crate) const SEEN_EXEC_RAW: u32 = 2;
pub(crate) const SEEN_OPEN_RAW: u32 = 3;
/// The rows of [`SYSCALL_TP_SEEN`].
pub(crate) const SEEN_ROWS: u32 = 4;

/// Lot 324: the boot's self-test. Slot 0: the probing thread's
/// `pid_tgid` as `bpf_get_current_pid_tgid` reads it (thread group in the
/// high half, thread in the low), 0 while no test runs; slot 1: the
/// test's round. The agent writes the round, then the thread, before the
/// test, and clears the thread after it.
#[map]
pub(crate) static SYSCALL_TP_PROBE: Array<u64> = Array::with_max_entries(2, 0);

/// Lot 324: per attach point's row and CPU (`row * SEEN_CPUS + cpu`), the
/// round of the self-test (`SYSCALL_TP_PROBE` slot 1) last seen there.
#[map]
pub(crate) static SYSCALL_TP_SEEN: Array<u32> = Array::with_max_entries(SEEN_ROWS * SEEN_CPUS, 0);

/// Lot 1.3 (the review of #625, P3-5): which of a sensor's two attach
/// points records its calls — slot [`EMIT_EXEC`] or [`EMIT_OPEN`]:
/// [`BY_TRACEPOINT`] (0, the map's initial value) or [`BY_RAW`]. The other
/// one marks the self-test's calls and records nothing, so the fallback is
/// tested with the tracepoint still attached and no call of the host is
/// recorded twice; the boot turns the slot to [`BY_RAW`] in one write once
/// the fallback is chosen, then retires the tracepoint.
#[map]
pub(crate) static SYSCALL_TP_EMIT: Array<u32> = Array::with_max_entries(2, 0);
pub(crate) const EMIT_EXEC: u32 = 0;
pub(crate) const EMIT_OPEN: u32 = 1;
pub(crate) const BY_TRACEPOINT: u32 = 0;
pub(crate) const BY_RAW: u32 = 1;

/// x86-64's `execve` (`arch/x86/entry/syscalls/syscall_64.tbl`). The
/// fallback is armed only where `pt_regs.di` resolves, x86-64.
const NR_EXECVE: u64 = 59;

// sys_enter_execve event format:
//   field:int            __syscall_nr;  offset:8;
//   field:const char *   filename;      offset:16;
//   field:const char *const * argv;     offset:24;
//   field:const char *const * envp;     offset:32;
// `sys_enter_execve.filename` — resolved from tracefs at boot
// (`off!(TP_SYS_ENTER_EXECVE_FILENAME_OFFSET)`, upstream 16).
use crate::btf_offsets::{
    PT_REGS_DI_OFFSET, TASK_STRUCT_REAL_PARENT_OFFSET, TASK_STRUCT_TGID_OFFSET, TASK_STRUCT_TI_STATUS_OFFSET,
    TP_SYS_ENTER_EXECVE_FILENAME_OFFSET,
};

#[tracepoint]
pub fn sys_enter_execve(ctx: TracePointContext) -> u32 {
    // SAFETY: `read_at` copies the record's field with
    // `bpf_probe_read_kernel` at an offset tracefs gave for this kernel's
    // record (a failed read is 0: no path).
    let filename_ptr = unsafe { ctx.read_at::<u64>(off!(TP_SYS_ENTER_EXECVE_FILENAME_OFFSET)) }.unwrap_or(0);
    record(SEEN_EXEC_TP, BY_TRACEPOINT, filename_ptr);
    0
}

/// Lot 324: the exec sensor's every-CPU fallback, on the raw `sys_enter`
/// tracepoint: native `execve` only, as [`sys_enter_execve`] sees it.
#[raw_tracepoint(tracepoint = "sys_enter")]
pub fn exec_check_raw(ctx: RawTracePointContext) -> i32 {
    // SAFETY: `sys_enter(struct pt_regs *regs, long id)`: the context holds
    // two 8-byte arguments, which the verifier checks the two loads against;
    // `regs` is read through `bpf_probe_read_kernel` only.
    unsafe {
        let args = ctx.as_ptr() as *const u64;
        if *args.add(1) != NR_EXECVE {
            return 0;
        }
        if let Some(filename_ptr) = native_arg(*args, off_opt!(PT_REGS_DI_OFFSET)) {
            record(SEEN_EXEC_RAW, BY_RAW, filename_ptr);
        }
    }
    0
}

/// Lot 324: the call's argument at `reg` (an offset in `regs`, resolved
/// from this kernel's BTF), when the call is a native 64-bit one: a 32-bit
/// call (`int 0x80`, `TS_COMPAT`) numbers its calls in another table
/// (its 59 is `olduname`), and the syscall tracepoints do not fire for it
/// either. `None`: not native, or an offset not resolved (another
/// architecture: the boot does not arm the fallback there).
#[inline(always)]
pub(crate) unsafe fn native_arg(regs: u64, reg: Option<usize>) -> Option<u64> {
    // SAFETY: both reads are `bpf_probe_read_kernel` (a failed read is 0),
    // at offsets below 4 KiB (masked) from the current task and from
    // `regs` (main.rs, "Unsafe code").
    unsafe {
        let ti = off_opt!(TASK_STRUCT_TI_STATUS_OFFSET)? & 0xfff;
        let reg = reg? & 0xfff;
        let task = bpf_get_current_task() as *const u8;
        let status = bpf_probe_read_kernel::<u32>(task.add(ti) as *const u32).unwrap_or(TS_COMPAT);
        if status & TS_COMPAT != 0 {
            return None;
        }
        bpf_probe_read_kernel::<u64>((regs as *const u8).add(reg) as *const u64).ok()
    }
}

/// Lot 324: the call is the self-test's (the thread the agent named in
/// [`SYSCALL_TP_PROBE`]): this CPU is marked seen in the attach point's
/// `row`, and the caller emits nothing.
#[inline(always)]
pub(crate) fn probe_seen(row: u32, pid_tgid: u64) -> bool {
    match SYSCALL_TP_PROBE.get(0) {
        Some(p) if *p != 0 && *p == pid_tgid => {}
        _ => return false,
    }
    let round = SYSCALL_TP_PROBE.get(1).map_or(0, |r| *r as u32);
    // SAFETY: a helper call with no argument.
    let cpu = unsafe { bpf_get_smp_processor_id() };
    if cpu < SEEN_CPUS {
        if let Some(seen) = SYSCALL_TP_SEEN.get_ptr_mut(row * SEEN_CPUS + cpu) {
            // SAFETY: a map value's pointer, checked for null by `get_ptr_mut`;
            // only this CPU's slot is written.
            unsafe { *seen = round };
        }
    }
    true
}

/// Lot 1.3: `by` ([`BY_TRACEPOINT`], [`BY_RAW`]) is the attach point that
/// records `sensor`'s calls now ([`SYSCALL_TP_EMIT`]; a failed lookup is the
/// tracepoint, as before the fallback existed).
#[inline(always)]
pub(crate) fn emits(sensor: u32, by: u32) -> bool {
    SYSCALL_TP_EMIT.get(sensor).map_or(BY_TRACEPOINT, |v| *v) == by
}

/// One record for the exec whose path is at `filename_ptr` in the caller's
/// memory (0: none), or nothing: for the self-test's call (marked in the
/// attach point's `row`), and while the other attach point (`by`) records.
#[inline(always)]
fn record(row: u32, by: u32, filename_ptr: u64) {
    let pid_tgid = bpf_get_current_pid_tgid();
    if probe_seen(row, pid_tgid) {
        return;
    }
    if !emits(EMIT_EXEC, by) {
        return;
    }
    let mut entry = match EXEC_CHECK_EVENTS.reserve::<ExecCheckRaw>(0) {
        Some(e) => e,
        None => {
            crate::drops::bump(northnarrow_common::ring_drops::ring_slot::EXEC_CHECK);
            return;
        }
    };
    let raw_ptr: *mut ExecCheckRaw = entry.as_mut_ptr();
    let uid_gid = bpf_get_current_uid_gid();
    let comm = bpf_get_current_comm().unwrap_or([0u8; 16]);
    // SAFETY: `raw_ptr` is the ring entry reserved above, ours alone until
    // the submit below, and `ExecCheckRaw`-sized: the zeroing and the field
    // writes stay inside it; `comm` is 16 bytes and `TASK_COMM_LEN` is 16.
    // The parent is read with `bpf_probe_read_kernel` (a failed read is 0).
    // The path is copied from user memory by `bpf_probe_read_user_str_bytes`,
    // bounded by the field's `FILENAME_LEN` (a failed read leaves it zeroed).
    unsafe {
        crate::zero::zero(raw_ptr);
        (*raw_ptr).pid = (pid_tgid >> 32) as u32;
        // Lot 1.3: the parent's thread group, as `exec_lsm.rs` reads it (it
        // was left 0, and the sensor self-test's exec step, which knows the
        // probe child by its parent, the agent, never matched on this
        // sensor).
        let task = bpf_get_current_task() as *const u8;
        let parent = bpf_probe_read_kernel::<u64>(task.add(off!(TASK_STRUCT_REAL_PARENT_OFFSET)) as *const u64)
            .unwrap_or(0);
        if parent != 0 {
            (*raw_ptr).ppid =
                bpf_probe_read_kernel::<u32>((parent as *const u8).add(off!(TASK_STRUCT_TGID_OFFSET)) as *const u32)
                    .unwrap_or(0);
        }
        (*raw_ptr).uid = (uid_gid & 0xFFFF_FFFF) as u32;
        (*raw_ptr).timestamp_ns = bpf_ktime_get_ns();
        let dst = (*raw_ptr).comm.as_mut_ptr();
        let src = comm.as_ptr();
        let mut i = 0usize;
        while i < TASK_COMM_LEN {
            *dst.add(i) = *src.add(i);
            i += 1;
        }
        if filename_ptr != 0 {
            let dst = core::slice::from_raw_parts_mut((*raw_ptr).filename.as_mut_ptr(), FILENAME_LEN);
            let _ = bpf_probe_read_user_str_bytes(filename_ptr as *const u8, dst);
        }
    }
    entry.submit(0);
}
