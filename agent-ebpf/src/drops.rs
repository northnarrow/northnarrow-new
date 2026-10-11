//! Per-ring drop counters (see `northnarrow_common::ring_drops`).
//!
//! `bump(slot)` is called by every producer whose `reserve()` returned
//! `None`. Per-CPU array: no atomics, no contention, and the verifier is
//! happy with it on every program type the agent uses (tracepoint,
//! kprobe, fexit, LSM) down to 5.15.

use aya_ebpf::{macros::map, maps::PerCpuArray};
use northnarrow_common::ring_drops::RING_DROP_SLOTS;

#[map]
pub static RING_DROPS: PerCpuArray<u64> = PerCpuArray::with_max_entries(RING_DROP_SLOTS, 0);

#[inline(always)]
pub fn bump(slot: u32) {
    if let Some(c) = RING_DROPS.get_ptr_mut(slot) {
        // SAFETY: per-CPU slot owned by this CPU for the duration of the
        // program; the verifier bounds `slot` against the map size.
        unsafe { *c = (*c).wrapping_add(1) };
    }
}
