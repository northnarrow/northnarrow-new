//! Per-process and per-user record budgets (token buckets) for producers
//! an unprivileged loop can drive (review 78 for DNS; external audit
//! EBPF-013 for `listen()` and `io_uring_setup()`).
//!
//! Each producer owns two LRU maps: one bucket per process (keyed by tgid,
//! so threads share it) and one per user (which bounds a loop of
//! `fork()`s). A bucket starts full; a record takes one token from both;
//! tokens come back at a fixed rate up to the burst. A call over either
//! budget is not recorded, but it is never silent: it is counted in the
//! producer's `RING_DROPS` slot and in the bucket's `held`, and the
//! process's next admitted record carries the counts ([`Held`]), so the
//! agent can name the process that floods.
//!
//! The constructs are the ones review 78 had verified on 5.15
//! (`dns_admit`): map lookups by pointer, a division by a constant, no
//! loop. Every function is `#[inline(always)]`, so the budget constants of
//! each producer are folded in.

use aya_ebpf::maps::LruHashMap;

#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct Budget {
    last_ns: u64,
    tokens: u64,
    held: u64,
}

/// A producer's budgets: per process `task_burst` records, then one per
/// `task_refill_ns`; per user `uid_burst`, then one per `uid_refill_ns`.
#[derive(Clone, Copy)]
pub(crate) struct Limits {
    pub task_burst: u64,
    pub task_refill_ns: u64,
    pub uid_burst: u64,
    pub uid_refill_ns: u64,
}

/// What an admitted record carries: the calls held back since the
/// process's previous record by its own budget (`task`) and by its user's
/// (`user`).
pub(crate) struct Held {
    pub task: u64,
    pub user: u64,
}

impl Held {
    pub const NONE: Held = Held { task: 0, user: 0 };
}

#[inline(always)]
unsafe fn refill(b: *mut Budget, now: u64, burst: u64, refill_ns: u64) {
    let steps = now.wrapping_sub((*b).last_ns) / refill_ns;
    if steps == 0 {
        return;
    }
    if (*b).tokens + steps >= burst {
        (*b).tokens = burst;
        (*b).last_ns = now;
    } else {
        (*b).tokens += steps;
        (*b).last_ns += steps * refill_ns;
    }
}

/// The budget entry of `key` in `map`, created full on first use; `None`
/// when the map refuses it (the record is then admitted, unpaced).
#[inline(always)]
unsafe fn budget(
    map: &LruHashMap<u32, Budget>,
    key: u32,
    now: u64,
    burst: u64,
) -> Option<*mut Budget> {
    if let Some(b) = map.get_ptr_mut(&key) {
        return Some(b);
    }
    let fresh = Budget {
        last_ns: now,
        tokens: burst,
        held: 0,
    };
    let _ = map.insert(&key, &fresh, 0);
    map.get_ptr_mut(&key)
}

/// `Some` when process `tgid` of user `uid` may record one more call (with
/// the counts held back since its previous record); `None` when the call
/// is held back, counted in `slot` and in the process's or the user's
/// budget.
#[inline(always)]
pub(crate) unsafe fn admit(
    task_map: &LruHashMap<u32, Budget>,
    uid_map: &LruHashMap<u32, Budget>,
    tgid: u32,
    uid: u32,
    now: u64,
    limits: Limits,
    slot: u32,
) -> Option<Held> {
    let task = match budget(task_map, tgid, now, limits.task_burst) {
        Some(b) => b,
        None => return Some(Held::NONE),
    };
    let user = match budget(uid_map, uid, now, limits.uid_burst) {
        Some(b) => b,
        None => return Some(Held::NONE),
    };
    refill(task, now, limits.task_burst, limits.task_refill_ns);
    refill(user, now, limits.uid_burst, limits.uid_refill_ns);
    if (*task).tokens == 0 {
        (*task).held += 1;
        crate::drops::bump(slot);
        return None;
    }
    if (*user).tokens == 0 {
        (*user).held += 1;
        crate::drops::bump(slot);
        return None;
    }
    (*task).tokens -= 1;
    (*user).tokens -= 1;
    let held = Held {
        task: (*task).held,
        user: (*user).held,
    };
    (*task).held = 0;
    (*user).held = 0;
    Some(held)
}

/// A held count for a `u32` wire field.
#[inline(always)]
pub(crate) fn saturate_u32(n: u64) -> u32 {
    if n > 0xFFFF_FFFF {
        0xFFFF_FFFF
    } else {
        n as u32
    }
}
