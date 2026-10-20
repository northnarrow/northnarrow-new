//! Kernel→userland record of the exploit post-condition guard (lab PR 219,
//! `agent-ebpf/src/epg.rs`). One record per anomaly; the guard puts nothing
//! on the ring on its fast path.

use crate::wire::TASK_COMM_LEN;

/// Record flags.
pub mod flags {
    /// `task->cred` is another `struct cred` than at the snapshot (a
    /// replaced pointer); clear for a write into the same one.
    pub const CRED_REPLACED: u8 = 1 << 0;
    /// `fs->root` changed.
    pub const ROOT_CHANGED: u8 = 1 << 1;
    /// `task->fs` replaced.
    pub const FS_CHANGED: u8 = 1 << 2;
    /// `task->nsproxy` replaced.
    pub const NS_CHANGED: u8 = 1 << 3;
    /// Found at `sys_enter`, the previous call of the task having never
    /// reached `sys_exit`.
    pub const EXIT_BYPASSED: u8 = 1 << 4;
    /// Lab fault injection (`GuardConfig::inject_comm_*`): nothing changed.
    pub const INJECTED: u8 = 1 << 5;
    /// Lite, degraded evidence: the task's record was lost (the LRU task
    /// map evicted it, or the fork-time insert failed) and its snapshot was
    /// re-taken here; the credential it holds (`before` = `after`) holds
    /// privilege that nothing attributes to a mechanism. Recorded only:
    /// never refused or killed for it.
    pub const BASELINE_LOST: u8 = 1 << 6;
    /// Lite: the task's snapshot was re-taken after a lost record, here
    /// ([`BASELINE_LOST`]) or earlier: `before` comes from that re-take.
    pub const REBASELINED: u8 = 1 << 7;
}

/// One anomaly (176 bytes). Ids in the kernel's `cred` order (`uid, gid,
/// suid, sgid, euid, egid, fsuid, fsgid`); namespaces by `ns.inum` (0 when
/// not read).
#[repr(C)]
#[derive(Copy, Clone, Debug)]
#[cfg_attr(feature = "std", derive(bytemuck::Pod, bytemuck::Zeroable))]
pub struct EpgEventRaw {
    pub timestamp_ns: u64,
    pub before_cap_permitted: u64,
    pub before_cap_effective: u64,
    pub after_cap_permitted: u64,
    pub after_cap_effective: u64,
    pub before_ids: [u32; 8],
    pub after_ids: [u32; 8],
    /// Thread group (the process) and thread.
    pub pid: u32,
    pub tid: u32,
    /// The call's number in its ABI (`abi`), or `NO_SYSCALL`.
    pub nr: u32,
    /// `crate::epg::mech` bits seen during the call.
    pub mechanisms: u32,
    pub before_user_ns: u32,
    pub after_user_ns: u32,
    pub before_mnt_ns: u32,
    pub after_mnt_ns: u32,
    pub before_pid_ns: u32,
    pub after_pid_ns: u32,
    pub before_net_ns: u32,
    pub after_net_ns: u32,
    pub comm: [u8; TASK_COMM_LEN],
    /// `crate::epg::kind`.
    pub kind: u8,
    /// `crate::epg::action`.
    pub action: u8,
    /// `crate::epg::abi`.
    pub abi: u8,
    /// [`flags`].
    pub flags: u8,
    /// `crate::epg::point`: where it was caught.
    pub point: u8,
    /// `crate::epg::variant`: lite or strict.
    pub variant: u8,
    pub _pad: u16,
}

#[cfg(all(test, feature = "std"))]
mod tests {
    use super::*;
    use core::mem::{offset_of, size_of};

    #[test]
    fn layout_is_pinned() {
        assert_eq!(size_of::<EpgEventRaw>(), 176);
        assert_eq!(core::mem::align_of::<EpgEventRaw>(), 8);
        assert_eq!(offset_of!(EpgEventRaw, before_ids), 40);
        assert_eq!(offset_of!(EpgEventRaw, after_ids), 72);
        assert_eq!(offset_of!(EpgEventRaw, pid), 104);
        assert_eq!(offset_of!(EpgEventRaw, before_user_ns), 120);
        assert_eq!(offset_of!(EpgEventRaw, comm), 152);
        assert_eq!(offset_of!(EpgEventRaw, kind), 168);
        assert_eq!(offset_of!(EpgEventRaw, flags), 171);
        assert_eq!(offset_of!(EpgEventRaw, point), 172);
        assert_eq!(offset_of!(EpgEventRaw, variant), 173);
    }

    #[test]
    fn bytemuck_round_trip() {
        let mut r: EpgEventRaw = bytemuck::Zeroable::zeroed();
        r.kind = crate::epg::kind::CRED_FROM_SYSCALL;
        r.after_ids = [0; 8];
        r.before_ids = [1000; 8];
        r.nr = crate::epg::nr::IOCTL;
        let bytes = bytemuck::bytes_of(&r);
        let back: &EpgEventRaw = bytemuck::try_from_bytes(bytes).expect("pod");
        assert_eq!(back.kind, r.kind);
        assert_eq!(back.before_ids, [1000; 8]);
        assert_eq!(back.nr, 16);
    }
}
