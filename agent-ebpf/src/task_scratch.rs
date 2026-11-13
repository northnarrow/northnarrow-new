//! Lot 322: a task's own scratch entry, for programs that keep a buffer
//! across their run.
//!
//! LSM, fentry/fexit and iterator programs run with migration disabled but
//! preemption enabled (the trampoline's `migrate_disable`): on a kernel
//! with `full` or `lazy` preemption — Ubuntu 26.04's default — the task can
//! be preempted in the middle of the program, and another task's run of
//! the same program on the same CPU rewrites a per-CPU buffer before the
//! first one reads it back (a path walk, then the classes judged from it).
//! A buffer that must outlive a helper call is therefore an entry of a
//! hash keyed by the running task ([`TaskKey`]: thread id and start time),
//! made from [`TASK_SCRATCH_ZERO`] at the start of the run, read through
//! the key by the global functions, and removed before the program
//! returns. The ratchet in `xtask/tests/percpu_maps.rs` keeps per-CPU maps
//! to what is safe across preemption (counters, rate state) or to programs
//! that run with preemption off.
//!
//! The review of #546 (F4): a plain hash, never an LRU. An LRU insert that
//! finds its CPU's free list empty evicts — an entry in flight included,
//! whose node then goes to the new key, and the first task's pointer reads
//! the other task's buffer. A plain hash never evicts: past
//! [`TASK_SCRATCH_CAP`] entries in flight (each one a run preempted in the
//! middle) an insert fails, and each caller takes its fail-closed path and
//! counts it.

use aya_ebpf::{
    cty::c_void,
    helpers::{bpf_get_current_pid_tgid, bpf_get_current_task, generated},
    macros::{lsm, map},
    maps::{Array, HashMap},
    programs::LsmContext,
};
use northnarrow_common::wire::exe::TaskKey;

use northnarrow_common::wire::execq::OVERFLOW_SHARE;

use crate::btf_offsets::{TASK_STRUCT_LOGINUID_OFFSET, TASK_STRUCT_START_TIME_OFFSET};

/// Entries of each per-task map: the runs in flight at once, which is the
/// tasks preempted in the middle of one of these programs. Far above any
/// legitimate load; past it, a fail-closed path, counted.
pub(crate) const TASK_SCRATCH_CAP: u32 = 2048;

/// Bytes of [`TASK_SCRATCH_ZERO`]: at least the largest scratch value.
pub(crate) const ZERO_BYTES: usize = 1024;

/// Zeroes every per-task entry starts from. Never written.
#[map]
pub(crate) static TASK_SCRATCH_ZERO: Array<[u64; ZERO_BYTES / 8]> = Array::with_max_entries(1, 0);

/// The running task's key. `task` is the running task's `task_struct`.
#[inline(always)]
pub(crate) unsafe fn key_of(task: *const u8) -> TaskKey {
    let mut start = core::mem::MaybeUninit::<u64>::uninit();
    let _ = generated::bpf_probe_read_kernel(
        start.as_mut_ptr() as *mut c_void,
        8,
        task.add(off!(TASK_STRUCT_START_TIME_OFFSET)) as *const c_void,
    );
    TaskKey {
        start_ns: start.assume_init(),
        tid: bpf_get_current_pid_tgid() as u32,
        _pad: 0,
    }
}

/// The running task's key, from inside a global function (whose integer
/// arguments cannot carry it).
#[inline(always)]
pub(crate) unsafe fn current_key() -> TaskKey {
    key_of(bpf_get_current_task() as *const u8)
}

/// The key from a global function's integer arguments.
#[inline(always)]
pub(crate) fn key(tid: u64, start: u64) -> TaskKey {
    TaskKey {
        start_ns: start,
        tid: tid as u32,
        _pad: 0,
    }
}

/// Make the task's zeroed entry in `map` and return it (`None`: the map is
/// full — [`TASK_SCRATCH_CAP`] runs in flight — the caller fails closed).
/// `T` must fit in [`ZERO_BYTES`] (checked at build). `K` is a [`TaskKey`],
/// or (the FIM sensor's buffers, on the file-open path) the running
/// `task_struct`'s address: a run-scoped entry, made and removed while the
/// task runs the program, cannot be found by another task that gets the
/// address later, and the address costs no read.
#[inline(always)]
pub(crate) unsafe fn make<K, T>(map: &HashMap<K, T>, key: &K) -> Option<*mut T> {
    const { assert!(core::mem::size_of::<T>() <= ZERO_BYTES) };
    let zero = TASK_SCRATCH_ZERO.get_ptr(0)?;
    map.insert(key, &*(zero as *const T), 0).ok()?;
    map.get_ptr_mut(key)
}

/// `BPF_F_NO_PREALLOC`: a hash whose entries are allocated as they are
/// made (the entries that live as long as their task).
pub(crate) const BPF_F_NO_PREALLOC: u32 = 1;

/// Lot 325: slot 0 is 1 once the agent attached [`nn_task_free`]: the
/// entries keyed by a `task_struct` that live as long as their task
/// (`open_sensor::OPEN_TASK`) are kept between runs then, and removed by it.
#[map]
pub(crate) static TASK_FREE_ARMED: Array<u32> = Array::with_max_entries(1, 0);

/// Whether [`nn_task_free`] runs (the agent attached it).
#[inline(always)]
pub(crate) fn task_free_armed() -> bool {
    matches!(TASK_FREE_ARMED.get(0), Some(v) if *v == 1)
}

/// Lot 325 (cost, and the re-check of #546, R6): LSM `task_free`, when the
/// kernel frees a `task_struct` — after every hook of that task has run,
/// before its address can be another task's. It removes the entries keyed
/// by that address that outlive one run: the FIM sensor's buffers
/// (`open_sensor::OPEN_TASK`, kept between opens), the exec quarantine's
/// candidate (`execq::EXECQ_CAND`, a plain hash since lot 325: a failed
/// exec's candidate stayed until the LRU evicted it), the exec policy's
/// note for the post-commit check (`execpol::EXECPOL_ENV_SEEN`). A void
/// hook: its return is ignored.
#[lsm(hook = "task_free")]
pub fn nn_task_free(ctx: LsmContext) -> i32 {
    // Kernel signature: (task).
    let task: u64 = ctx.arg(0);
    if task != 0 {
        crate::open_sensor::forget_freed(task);
        crate::execq::forget_freed(task);
        crate::execpol::forget_freed(task);
    }
    0
}

/// The review of #547 (F4, F6; the re-check, G5): one share of a map whose
/// entries outlive a run (the exec quarantine's candidates, the FIM sensor's
/// task buffers), counted in `rows` (share → entries): the running task's
/// login's ([`share_key`]: its subuids, a rootless container's, are the
/// login's), so that one login cannot take the room every other one needs.
/// Takes one more entry of `key`'s share, below `cap`, and returns the row
/// it was counted in — `key`'s, or, when `rows` has no room for a new row,
/// the overflow row ([`OVERFLOW_SHARE`], `overflow[0]`, the same cap: the
/// keys the map cannot track share one, they are not let through
/// uncounted). `None`: the share is taken. The counts are plain
/// read-modify-writes (no atomics in this crate: the re-review of #494, R1)
/// — two runs updating one row at the same instant can lose an update; the
/// agent recounts both maps from their entries (the candidates' every 30 s,
/// the task buffers' when opens lost their buffer), so a drift lasts no
/// longer.
#[inline(always)]
pub(crate) fn share_take(
    rows: &HashMap<u32, u64>,
    overflow: &Array<u64>,
    key: u32,
    cap: u64,
) -> Option<u32> {
    if let Some(n) = rows.get_ptr_mut(&key) {
        // SAFETY: a map value's address.
        unsafe {
            if *n >= cap {
                return None;
            }
            *n += 1;
        }
        return Some(key);
    }
    if rows.insert(&key, &1u64, BPF_NOEXIST).is_ok() {
        return Some(key);
    }
    let n = overflow.get_ptr_mut(0)?;
    // SAFETY: as above.
    unsafe {
        if *n >= cap {
            return None;
        }
        *n += 1;
    }
    Some(OVERFLOW_SHARE)
}

/// The row `row` ([`share_take`]'s) gave one entry back; never below zero.
#[inline(always)]
pub(crate) fn share_give(rows: &HashMap<u32, u64>, overflow: &Array<u64>, row: u32) {
    let n = if row == OVERFLOW_SHARE {
        overflow.get_ptr_mut(0)
    } else {
        rows.get_ptr_mut(&row)
    };
    if let Some(n) = n {
        // SAFETY: a map value's address.
        unsafe {
            if *n > 0 {
                *n -= 1;
            }
        }
    }
}

/// `BPF_NOEXIST`: an insert that makes a new entry only.
const BPF_NOEXIST: u64 = 1;

/// The running task's share key: its login uid, or its uid without one
/// (`northnarrow_common::wire::execq::share_key`).
#[inline(always)]
pub(crate) fn share_key() -> u32 {
    northnarrow_common::wire::execq::share_key(current_loginuid(), current_uid())
}

/// The running task's login uid (`task->loginuid`), or `u32::MAX` when it
/// has none or the kernel keeps none (no audit).
#[inline(always)]
pub(crate) fn current_loginuid() -> u32 {
    // SAFETY: a helper call, then a read of the running task.
    unsafe {
        let task = aya_ebpf::helpers::bpf_get_current_task() as *const u8;
        match off_opt!(TASK_STRUCT_LOGINUID_OFFSET) {
            Some(o) if !task.is_null() => {
                match aya_ebpf::helpers::bpf_probe_read_kernel::<u32>(task.add(o) as *const u32) {
                    Ok(u) => u,
                    Err(_) => u32::MAX,
                }
            }
            _ => u32::MAX,
        }
    }
}

/// The real uid of the running task.
#[inline(always)]
pub(crate) fn current_uid() -> u32 {
    aya_ebpf::helpers::bpf_get_current_uid_gid() as u32
}
