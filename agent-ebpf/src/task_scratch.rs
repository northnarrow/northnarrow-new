//! Lot 322: a task's own scratch entry, for programs that keep a buffer
//! across their run.
//!
//! LSM, fentry/fexit and iterator programs run with migration disabled but
//! preemption enabled (the trampoline's `migrate_disable`): on a kernel
//! with `full` or `lazy` preemption — Ubuntu 26.04's default — the task can
//! be preempted in the middle of the program, and another task's run of
//! the same program on the same CPU rewrites a per-CPU buffer before the
//! first one reads it back (a path walk, then the classes judged from it).
//! A buffer that must outlive a helper call is therefore an entry of an
//! LRU hash keyed by the running task ([`TaskKey`]: thread id and start
//! time), made from [`TASK_SCRATCH_ZERO`] at the start of the run, read
//! through the key by the global functions, and removed before the program
//! returns. The ratchet in `xtask/tests/percpu_maps.rs` keeps per-CPU maps
//! to what is safe across preemption (counters, rate state) or to programs
//! that run with preemption off.

use aya_ebpf::{
    cty::c_void,
    helpers::{bpf_get_current_pid_tgid, generated},
    macros::map,
    maps::{Array, LruHashMap},
};
use northnarrow_common::wire::exe::TaskKey;

use crate::btf_offsets::TASK_STRUCT_START_TIME_OFFSET;

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

/// The key from a global function's integer arguments.
#[inline(always)]
pub(crate) fn key(tid: u64, start: u64) -> TaskKey {
    TaskKey {
        start_ns: start,
        tid: tid as u32,
        _pad: 0,
    }
}

/// Make the task's zeroed entry in `map` and return it (`None`: the entry
/// could not be made). `T` must fit in [`ZERO_BYTES`] (checked at build).
/// `K` is a [`TaskKey`], or (the exec quarantine's candidate, read later
/// by the same task's `sched_process_exec`) its `task_struct` address.
#[inline(always)]
pub(crate) unsafe fn make<K, T>(map: &LruHashMap<K, T>, key: &K) -> Option<*mut T> {
    const { assert!(core::mem::size_of::<T>() <= ZERO_BYTES) };
    let zero = TASK_SCRATCH_ZERO.get_ptr(0)?;
    map.insert(key, &*(zero as *const T), 0).ok()?;
    map.get_ptr_mut(key)
}
