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
pub const RING_DROP_SLOTS: u32 = 20;

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
    pub const IOURING: u32 = 11;
    pub const BPF: u32 = 12;
    /// Tappa 10.9 step 1: the file-open sensor on LSM `file_open`.
    pub const OPEN_SENSOR: u32 = 13;
    /// Review 78: DNS queries over a process's budget, not recorded (not
    /// a ring overflow: the kernel holds them back before the ring).
    pub const DNS_RATE: u32 = 14;
    /// External audit EBPF-009: a write-then-close marker the kernel could
    /// not store (`FIM_DIRTY_INODES` full), so the close emits no
    /// `Modified` for that inode.
    pub const FIM_DIRTY_FULL: u32 = 15;
    /// External audit EBPF-013: `listen()` calls over a process's or a
    /// user's record budget, not recorded (held back before the ring).
    pub const LISTEN_RATE: u32 = 16;
    /// External audit EBPF-013: io_uring ring creations over a process's or
    /// a user's record budget, not recorded (held back before the ring).
    pub const IOURING_RATE: u32 = 17;
    /// External audit EBPF-017: anti-tamper task denials (a refused
    /// signal or ptrace attach on a protected pid) over the per-CPU record
    /// budget, not recorded (held back before the `fs_protect` ring; the
    /// deny itself still applies).
    pub const TASK_DENIAL_RATE: u32 = 18;
    /// Lab PR 219: the exploit post-condition guard's ring (an anomaly
    /// record lost; the guard's kill in enforce mode does not depend on it).
    pub const EXPLOIT_GUARD: u32 = 19;
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
    "io_uring",
    "bpf",
    "open_sensor",
    "dns_rate",
    "fim_dirty_full",
    "listen_rate",
    "io_uring_rate",
    "task_denial_rate",
    "exploit_guard",
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_cover_every_slot_in_order() {
        assert_eq!(RING_DROP_NAMES.len() as u32, RING_DROP_SLOTS);
        assert_eq!(RING_DROP_NAMES[ring_slot::EXEC as usize], "exec");
        assert_eq!(RING_DROP_NAMES[ring_slot::DNS as usize], "dns");
        assert_eq!(RING_DROP_NAMES[ring_slot::IOURING as usize], "io_uring");
        assert_eq!(RING_DROP_NAMES[ring_slot::BPF as usize], "bpf");
        assert_eq!(
            RING_DROP_NAMES[ring_slot::OPEN_SENSOR as usize],
            "open_sensor"
        );
        assert_eq!(RING_DROP_NAMES[ring_slot::DNS_RATE as usize], "dns_rate");
        assert_eq!(
            RING_DROP_NAMES[ring_slot::FIM_DIRTY_FULL as usize],
            "fim_dirty_full"
        );
        assert_eq!(
            RING_DROP_NAMES[ring_slot::LISTEN_RATE as usize],
            "listen_rate"
        );
        assert_eq!(
            RING_DROP_NAMES[ring_slot::IOURING_RATE as usize],
            "io_uring_rate"
        );
        assert_eq!(
            RING_DROP_NAMES[ring_slot::TASK_DENIAL_RATE as usize],
            "task_denial_rate"
        );
        assert_eq!(
            RING_DROP_NAMES[ring_slot::EXPLOIT_GUARD as usize],
            "exploit_guard"
        );
        assert_eq!(ring_slot::EXPLOIT_GUARD + 1, RING_DROP_SLOTS);
    }

    /// Slot order is wire-stable: the lab soak and older status readers
    /// index the map by slot. A new ring goes at the end; this pins every
    /// existing slot to its number and name.
    #[test]
    fn ring_drop_slots_append_only() {
        let pinned: [(u32, &str); RING_DROP_SLOTS as usize] = [
            (ring_slot::EXEC, "exec"),
            (ring_slot::EXEC_CHECK, "exec_check"),
            (ring_slot::FILE_OPEN, "file_open"),
            (ring_slot::FIM, "fim"),
            (ring_slot::LISTEN, "listen"),
            (ring_slot::FS_PROTECT, "fs_protect"),
            (ring_slot::MODULE_LOAD, "module_load"),
            (ring_slot::TCP_CLOSE, "tcp_close"),
            (ring_slot::TCP_CONNECT, "tcp_connect"),
            (ring_slot::UDP, "udp"),
            (ring_slot::DNS, "dns"),
            (ring_slot::IOURING, "io_uring"),
            (ring_slot::BPF, "bpf"),
            (ring_slot::OPEN_SENSOR, "open_sensor"),
            (ring_slot::DNS_RATE, "dns_rate"),
            (ring_slot::FIM_DIRTY_FULL, "fim_dirty_full"),
            (ring_slot::LISTEN_RATE, "listen_rate"),
            (ring_slot::IOURING_RATE, "io_uring_rate"),
            (ring_slot::TASK_DENIAL_RATE, "task_denial_rate"),
            (ring_slot::EXPLOIT_GUARD, "exploit_guard"),
        ];
        for (i, (slot, name)) in pinned.iter().enumerate() {
            assert_eq!(*slot as usize, i, "slot {name} moved");
            assert_eq!(RING_DROP_NAMES[i], *name);
        }
    }
}
