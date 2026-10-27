//! A process's key (Wave 4 restructure, R08c, lab PR 252; plan §2.3): the
//! identity of a process that no reuse of its PID gives to another — the
//! OCSF `process.uid`. The priority bus orders events of different classes
//! by their time and this key (R12, plan §3.4). A type only: how a source
//! fills it is R12's.

/// A process, as no later holder of its PID can be named: the boot it ran
/// in, its thread group and its start.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ProcessKey {
    /// The boot (`/proc/sys/kernel/random/boot_id`).
    pub boot_id: [u8; 16],
    /// The thread group: the process's PID.
    pub tgid: u32,
    /// Its start, `CLOCK_MONOTONIC` ns, as its exec reported it.
    pub start_ns: u64,
}
