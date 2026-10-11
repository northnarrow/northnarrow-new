//! Ring-buffer drop accounting shared by the eBPF programs and the agent.
//!
//! Every producer reserves an entry in its ring buffer and, when the
//! reservation fails (consumer too slow, burst too large), bumps the
//! per-CPU counter of its slot in the `RING_DROPS` map instead of
//! dropping silently. The agent sums the per-CPU values every few
//! seconds, logs an increase at WARN, exposes the totals through
//! `nn-admin status`, and the lab soak reads the same map. Before this,
//! only the exec ring counted its drops and nothing read the counter
//! (ROADMAP Tappa 10.8, external review of 2026-10-10: "drop detection
//! must be explicit").
//!
//! Slot order is wire-stable: append only.

/// Number of counted ring buffers (map size).
pub const RING_DROP_SLOTS: u32 = 11;

/// Slot of each ring buffer in `RING_DROPS`.
pub mod ring_slot {
    pub const EXEC: u32 = 0;
    pub const EXEC_CHECK: u32 = 1;
    pub const FILE_OPEN: u32 = 2;
    pub const FIM: u32 = 3;
    pub const LISTEN: u32 = 4;
    pub const FS_PROTECT: u32 = 5;
    pub const MODULE_LOAD: u32 = 6;
    pub const TCP_CLOSE: u32 = 7;
    pub const TCP_CONNECT: u32 = 8;
    pub const UDP: u32 = 9;
    pub const DNS: u32 = 10;
}

/// Human names, indexed by slot.
pub const RING_DROP_NAMES: [&str; RING_DROP_SLOTS as usize] = [
    "exec",
    "exec_check",
    "file_open",
    "fim",
    "listen",
    "fs_protect",
    "module_load",
    "tcp_close",
    "tcp_connect",
    "udp",
    "dns",
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_cover_every_slot_in_order() {
        assert_eq!(RING_DROP_NAMES.len() as u32, RING_DROP_SLOTS);
        assert_eq!(RING_DROP_NAMES[ring_slot::EXEC as usize], "exec");
        assert_eq!(RING_DROP_NAMES[ring_slot::DNS as usize], "dns");
        assert_eq!(ring_slot::DNS + 1, RING_DROP_SLOTS);
    }
}
