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

use northnarrow_common::wire::execq::{share_admits, OVERFLOW_ROW, OVERFLOW_SHARE, TOTAL_ROW, USERNS_MAX_LEVEL};

use crate::btf_offsets::{
    CRED_USER_NS_OFFSET, TASK_STRUCT_CRED_OFFSET, TASK_STRUCT_START_TIME_OFFSET, USER_NAMESPACE_INUM_OFFSET,
    USER_NAMESPACE_LEVEL_OFFSET, USER_NAMESPACE_OWNER_OFFSET, USER_NAMESPACE_PARENT_OFFSET,
};

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
/// account's ([`nn_share_key`]), so that one account cannot take the room
/// every other one needs. Takes one more entry of `key`'s share and returns
/// the row it was counted in — `key`'s, or, when `rows` has no room for a
/// new row, the overflow row ([`OVERFLOW_SHARE`], `overflow[OVERFLOW_ROW]`,
/// the same cap: the keys the map cannot track share one, they are not let
/// through uncounted). `None`: the share is taken.
///
/// Lot 332 (the re-check 2 of #547, G5): and a global cap.
/// `overflow[TOTAL_ROW]` counts every share's entries; past `global` (the
/// map's room less one share's), only a share holding fewer than `floor`
/// takes one more (`wire::execq::share_admits`): four shares at their cap
/// filled the map, and every later candidate was dropped. A row made here
/// for a new key is made empty and counted only when the take is admitted;
/// one another run made at the same instant is found again, not counted in
/// the overflow row.
///
/// The counts are plain read-modify-writes (no atomics in this crate: the
/// re-review of #494, R1) — two runs updating one row at the same instant
/// can lose an update; the agent recounts both maps from their entries
/// (the candidates' every 30 s, the task buffers' when opens lost their
/// buffer), the total with them, so a drift lasts no longer.
#[inline(always)]
pub(crate) fn share_take(
    rows: &HashMap<u32, u64>,
    overflow: &Array<u64>,
    key: u32,
    cap: u64,
    global: u64,
    floor: u64,
) -> Option<u32> {
    let total = overflow.get_ptr_mut(TOTAL_ROW)?;
    let (n, row) = match rows.get_ptr_mut(&key) {
        Some(n) => (n, key),
        None => {
            let _ = rows.insert(&key, &0u64, BPF_NOEXIST);
            match rows.get_ptr_mut(&key) {
                Some(n) => (n, key),
                None => (overflow.get_ptr_mut(OVERFLOW_ROW)?, OVERFLOW_SHARE),
            }
        }
    };
    // SAFETY: map values' addresses.
    unsafe {
        if !share_admits(*n, *total, cap, global, floor) {
            return None;
        }
        *n += 1;
        *total += 1;
    }
    Some(row)
}

/// The row `row` ([`share_take`]'s) gave one entry back, and the total;
/// never below zero.
#[inline(always)]
pub(crate) fn share_give(rows: &HashMap<u32, u64>, overflow: &Array<u64>, row: u32) {
    let n = if row == OVERFLOW_SHARE {
        overflow.get_ptr_mut(OVERFLOW_ROW)
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
    if let Some(t) = overflow.get_ptr_mut(TOTAL_ROW) {
        // SAFETY: as above.
        unsafe {
            if *t > 0 {
                *t -= 1;
            }
        }
    }
}

/// `BPF_NOEXIST`: an insert that makes a new entry only.
const BPF_NOEXIST: u64 = 1;

/// The running task's share key (`northnarrow_common::wire::execq::share_key`):
/// its real uid in the initial user namespace; in a user namespace, the
/// creator of the outermost one below the initial namespace, or that
/// namespace's inode number when root made it (a system container). Lot 332
/// (the re-check 2 of #547, G5): it was the login uid, which a task whose
/// login uid is unset (a service, a container under a root daemon) sets to
/// any value without a privilege.
///
/// A global function (no argument): the walk up the namespaces is checked
/// once, not on every way into its callers.
#[no_mangle]
#[inline(never)]
pub extern "C" fn nn_share_key() -> u64 {
    let uid = current_uid();
    // SAFETY: reads of the running task's credentials and namespaces, each
    // through `bpf_probe_read_kernel` (0 when unreadable).
    let (level, owner, inum) = unsafe { outer_user_ns() };
    u64::from(northnarrow_common::wire::execq::share_key(uid, level, owner, inum))
}

/// The running task's share key ([`nn_share_key`]).
#[inline(always)]
pub(crate) fn share_key() -> u32 {
    nn_share_key() as u32
}

/// The running task's user namespace depth, and the creator (`owner`) and
/// inode number of its outermost ancestor below the initial namespace; all
/// 0 (the initial namespace: keyed by the uid) when a field is not known on
/// this kernel or cannot be read. Each offset is read where it is used, and
/// every read goes through one scratch word: this runs at the end of the
/// FIM sensor's deepest call chain (the sensor, the directory walk, the
/// buffer's share), whose stack the verifier holds to 512 bytes.
#[inline(always)]
unsafe fn outer_user_ns() -> (u32, u32, u32) {
    let Some(o_cred) = off_opt!(TASK_STRUCT_CRED_OFFSET) else {
        return (0, 0, 0);
    };
    let Some(o_ns) = off_opt!(CRED_USER_NS_OFFSET) else {
        return (0, 0, 0);
    };
    let Some(o_level) = off_opt!(USER_NAMESPACE_LEVEL_OFFSET) else {
        return (0, 0, 0);
    };
    let task = bpf_get_current_task() as *const u8;
    let cred = peek_u64(task.add(o_cred)) as *const u8;
    let mut ns = peek_u64(cred.add(o_ns)) as *const u8;
    let level = peek_u32(ns.add(o_level));
    if level == 0 {
        return (0, 0, 0);
    }
    let Some(o_parent) = off_opt!(USER_NAMESPACE_PARENT_OFFSET) else {
        return (0, 0, 0);
    };
    let mut l = level;
    let mut i = 0u32;
    while i < USERNS_MAX_LEVEL && l > 1 {
        ns = peek_u64(ns.add(o_parent)) as *const u8;
        l = peek_u32(ns.add(o_level));
        i += 1;
    }
    if l != 1 {
        return (0, 0, 0);
    }
    let Some(o_owner) = off_opt!(USER_NAMESPACE_OWNER_OFFSET) else {
        return (0, 0, 0);
    };
    let Some(o_inum) = off_opt!(USER_NAMESPACE_INUM_OFFSET) else {
        return (0, 0, 0);
    };
    (level, peek_u32(ns.add(o_owner)), peek_u32(ns.add(o_inum)))
}

/// A kernel `u64`, 0 when unreadable, without a branch on the result: the
/// helper always writes its destination (zeros on a fault). A branch per
/// read in the namespaces' walk multiplied the states the 5.15 verifier
/// explores past its million instructions (lot 332's lab).
#[inline(always)]
unsafe fn peek_u64(src: *const u8) -> u64 {
    let mut v = core::mem::MaybeUninit::<u64>::uninit();
    let _ = generated::bpf_probe_read_kernel(v.as_mut_ptr() as *mut c_void, 8, src as *const c_void);
    v.assume_init()
}

/// A kernel `u32`, as [`peek_u64`].
#[inline(always)]
unsafe fn peek_u32(src: *const u8) -> u32 {
    let mut v = core::mem::MaybeUninit::<u32>::uninit();
    let _ = generated::bpf_probe_read_kernel(v.as_mut_ptr() as *mut c_void, 4, src as *const c_void);
    v.assume_init()
}

/// The real uid of the running task.
#[inline(always)]
pub(crate) fn current_uid() -> u32 {
    aya_ebpf::helpers::bpf_get_current_uid_gid() as u32
}
