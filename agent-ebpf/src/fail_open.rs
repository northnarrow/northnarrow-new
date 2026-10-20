//! Per-hook fail-open counters (see `northnarrow_common::fail_open`).
//!
//! `bump(hook)` is called by a deny hook that lets an operation through
//! because a kernel read it needed failed (or a position it needed is not
//! known): the operation is allowed undecided, and the agent sees it.
//! Per-CPU array like `RING_DROPS`: no atomics, no contention; a failure
//! path only, so the hot path pays nothing.

use aya_ebpf::{macros::map, maps::PerCpuArray};
use northnarrow_common::fail_open::FAIL_OPEN_SLOTS;

#[map]
pub static DENY_FAIL_OPEN: PerCpuArray<u64> = PerCpuArray::with_max_entries(FAIL_OPEN_SLOTS, 0);

#[inline(always)]
pub fn bump(hook: u32) {
    if let Some(c) = DENY_FAIL_OPEN.get_ptr_mut(hook) {
        // SAFETY: per-CPU slot owned by this CPU for the duration of the
        // program; the helper bounds `hook` against the map size.
        unsafe { *c = (*c).wrapping_add(1) };
    }
}
