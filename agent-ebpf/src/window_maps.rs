//! Lot 2.2 (stage S2): the per-tree trusted-installer window's kernel
//! layout, declared before any hook reads it (the design:
//! `docs/design/ANTITAMPER_TRUST_MODEL.md`, "Trusted-installer window per
//! process tree", sections 2, 5 and 7).
//!
//! * [`FS_GRANT_V2`]: the grant slot (`northnarrow_common::wire::FsGrantV2`:
//!   the 64-bit generation, the `CLOCK_BOOTTIME` deadline, the agent's
//!   heartbeat).
//! * [`TREE_MEMBERS`]: the members, by tgid.
//! * [`WINDOW_LEASES`]: the single-use leases of PID 1's link actions.
//! * [`WINDOW_EVENTS`]: the window's own ring, with its pinned per-CPU
//!   sequence ([`WINDOW_EVENT_SEQ`]) and drop counters
//!   ([`WINDOW_EVENT_DROPS`]); [`emit_window_event`] is the one writer.
//!
//! All pinned by name but the ring (process-local, as every event ring):
//! a restarted agent zeroes them at its start (boot-zero), and the drops
//! and the sequence counted while no agent ran are read by the next start. The per-tree decisions that read them are
//! lot 2.3's; nothing here lifts or refuses anything.

use aya_ebpf::{
    helpers::{bpf_get_smp_processor_id, bpf_ktime_get_boot_ns},
    macros::map,
    maps::{Array, HashMap, PerCpuArray, RingBuf},
};
use northnarrow_common::wire::{
    FsGrantV2, TreeMember, WindowEventRaw, WindowLease, TREE_MEMBERS_MAX, WINDOW_EVENTS_RING_BYTES,
    WINDOW_LEASES_MAX,
};

/// The grant slot (one).
#[map]
pub static FS_GRANT_V2: Array<FsGrantV2> = Array::pinned(1, 0);

/// The window's members.
#[map]
pub static TREE_MEMBERS: HashMap<u32, TreeMember> = HashMap::pinned(TREE_MEMBERS_MAX, 0);

/// The single-use leases.
#[map]
pub static WINDOW_LEASES: Array<WindowLease> = Array::pinned(WINDOW_LEASES_MAX, 0);

/// The window's records. Process-local, as every event ring of the object
/// (external audit SNS-015): whether lot 2.3 pins it, so that the next
/// start drains what the hooks wrote while no agent ran, is its decision
/// against that audit's fix. Its sequence and drop counters ARE pinned: a
/// gap across a restart stays visible to the next start.
#[map]
pub static WINDOW_EVENTS: RingBuf = RingBuf::with_byte_size(WINDOW_EVENTS_RING_BYTES, 0);

/// Per CPU: the last sequence number written.
#[map]
pub static WINDOW_EVENT_SEQ: PerCpuArray<u64> = PerCpuArray::pinned(1, 0);

/// Per CPU: the records the ring could not take.
#[map]
pub static WINDOW_EVENT_DROPS: PerCpuArray<u64> = PerCpuArray::pinned(1, 0);

/// Write one window record: its fields, with the CPU's next sequence
/// number, the CPU and the time filled here, straight into the ring's
/// reservation (lot 2.3a: no copy of the record on the stack — every byte of
/// the global functions that call it counts in the hooks' 512-byte chains),
/// or, when the ring is full, a drop counted on this CPU (the number is
/// spent all the same, so the gap is visible). The caller's decision never
/// depends on the record (a refusal whose record is lost is still a
/// refusal). Lot 2.3's hooks call it (`crate::window_tree`).
#[inline(always)]
pub fn emit_window_event(kind: u8, class: u8, operation: u8, generation: u64, tgid: u32, start_ticks: u64, detail: u64) {
    let seq = match WINDOW_EVENT_SEQ.get_ptr_mut(0) {
        // SAFETY: this CPU's slot of a per-CPU array, written by this
        // program alone while it runs (no preemption inside a BPF program).
        Some(p) => unsafe {
            *p += 1;
            *p
        },
        None => 0,
    };
    match WINDOW_EVENTS.reserve::<WindowEventRaw>(0) {
        Some(mut entry) => {
            let ev = entry.as_mut_ptr();
            // SAFETY: the reservation is this program's, aligned and the
            // record's size; every field is written before the submit.
            unsafe {
                (*ev).seq = seq;
                (*ev).boot_ns = bpf_ktime_get_boot_ns();
                (*ev).generation = generation;
                (*ev).start_ticks = start_ticks;
                (*ev).detail = detail;
                (*ev).tgid = tgid;
                (*ev).cpu = bpf_get_smp_processor_id();
                (*ev).kind = kind;
                (*ev).class = class;
                (*ev).operation = operation;
                (*ev)._pad = [0; 5];
            }
            entry.submit(0);
        }
        None => {
            if let Some(p) = WINDOW_EVENT_DROPS.get_ptr_mut(0) {
                // SAFETY: as above.
                unsafe { *p += 1 };
            }
        }
    }
}
