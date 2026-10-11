//! Tappa 10.9, step 0 — records of the sensor-feasibility probes
//! (`agent-ebpf/src/sensor_probe.rs`, runner `agent/src/sensor_feasibility.rs`).
//!
//! The probes check, on each lab kernel, that the attach points proposed by
//! `docs/design/TAPPA10_9_SENSOR_ATTACH_POINTS_DESIGN.md` load under the
//! verifier and report what the design needs. Nothing in the production
//! sensors reads these records.

use super::TASK_COMM_LEN;

/// LSM `file_open`: the opened inode's parent directory is in `PROBE_DIRS`.
pub const PROBE_KIND_DIR: u8 = 1;
/// LSM `file_open`: the leaf name (with its parent's name) is in `PROBE_NAMES`.
pub const PROBE_KIND_NAME: u8 = 2;
/// LSM `file_open`: an ancestor directory name is in `PROBE_ANCESTORS`.
pub const PROBE_KIND_ANCESTOR: u8 = 3;
/// LSM `file_open`: a process crossed the write-open threshold.
pub const PROBE_KIND_MASS_WRITE: u8 = 4;
/// LSM `bprm_check_security`.
pub const PROBE_KIND_EXEC: u8 = 5;
/// kretprobe `ip_make_skb` (IPv4 UDP payload after the copy).
pub const PROBE_KIND_DNS4: u8 = 6;
/// kretprobe `ip6_make_skb`.
pub const PROBE_KIND_DNS6: u8 = 7;
/// kprobe `udp_send_skb` (IPv4) / `udp_v6_send_skb` (IPv6).
pub const PROBE_KIND_UDP_SEND_SKB: u8 = 8;

/// Path components captured leaf → root, each in a fixed 32-byte slot.
pub const PROBE_PATH_SLOTS: usize = 16;
pub const PROBE_PATH_SLOT_LEN: usize = 32;
/// Bytes of kernel data copied for the exec filename or the UDP payload.
pub const PROBE_DETAIL_LEN: usize = 128;

/// Slots of the probes' own offset map (`PROBE_OFFSETS`), written by the
/// runner from the live BTF. Slot 0 holds [`PROBE_OFFSETS_MAGIC`] once armed.
pub mod probe_slot {
    pub const MAGIC: u32 = 0;
    pub const SUPER_BLOCK_S_MAGIC: u32 = 1;
    pub const INODE_I_NLINK: u32 = 2;
    pub const INODE_I_MODE: u32 = 3;
    pub const LINUX_BINPRM_FILE: u32 = 4;
    pub const LINUX_BINPRM_FILENAME: u32 = 5;
    pub const SK_BUFF_HEAD: u32 = 6;
    pub const SK_BUFF_TRANSPORT_HEADER: u32 = 7;
    pub const SK_BUFF_LEN: u32 = 8;
    pub const COUNT: u32 = 16;
}
pub const PROBE_OFFSETS_MAGIC: u32 = 0x5E15_0B0E;

/// Write-open threshold and window of the in-kernel counter (the posture
/// mass-write arm's values: 20 write-opens in 60 s).
pub const PROBE_MASS_WRITE_MIN: u32 = 20;
pub const PROBE_MASS_WRITE_WINDOW_NS: u64 = 60 * 1_000_000_000;

/// Per-tgid write-open window of the in-kernel counter.
#[repr(C)]
#[derive(Copy, Clone, Debug)]
#[cfg_attr(feature = "std", derive(bytemuck::Pod, bytemuck::Zeroable))]
pub struct ProbeWriteWindow {
    pub start_ns: u64,
    pub count: u32,
    pub fired: u32,
}

/// One probe observation. 8-aligned, no implicit padding:
/// 8·5 + 4·4 + 16 + 1 + 1 + 2 + 2 + 2 + 512 + 128 = 720.
#[repr(C)]
#[derive(Copy, Clone, Debug)]
#[cfg_attr(feature = "std", derive(bytemuck::Pod, bytemuck::Zeroable))]
pub struct SensorProbeRaw {
    pub timestamp_ns: u64,
    pub dev: u64,
    pub ino: u64,
    pub s_magic: u64,
    /// Kernel pointer bits of the skb (DNS kinds) — non-zero proves the
    /// return value was read.
    pub aux: u64,
    pub pid: u32,
    pub uid: u32,
    pub nlink: u32,
    /// `f_mode` for opens, `i_mode` for execs, `skb->len` for DNS.
    pub mode: u32,
    pub comm: [u8; TASK_COMM_LEN],
    pub kind: u8,
    pub path_truncated: u8,
    pub path_n: u16,
    pub detail_len: u16,
    pub _pad: [u8; 2],
    pub path: [u8; PROBE_PATH_SLOTS * PROBE_PATH_SLOT_LEN],
    pub detail: [u8; PROBE_DETAIL_LEN],
}

#[cfg(all(test, feature = "std"))]
mod tests {
    use super::*;

    #[test]
    fn sensor_probe_record_layout() {
        assert_eq!(core::mem::size_of::<SensorProbeRaw>(), 720);
        assert_eq!(core::mem::align_of::<SensorProbeRaw>(), 8);
        assert_eq!(core::mem::size_of::<ProbeWriteWindow>(), 16);
    }
}
