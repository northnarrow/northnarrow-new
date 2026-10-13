//! Tappa 10.9 step 1 — the file-open sensor on LSM `file_open`
//! (`agent-ebpf/src/open_sensor.rs`, design
//! `docs/design/TAPPA10_9_SENSOR_ATTACH_POINTS_DESIGN.md` §10).
//!
//! The kernel classifies every open and ships only the interesting ones:
//! rules keyed by inode (`OPEN_RULES`), by `(parent inode, name)` for paths
//! that do not exist yet (`CHILD_RULES`), and by name for credential stores
//! (`OPEN_NAME_RULES`); directory classes are cached per parent directory
//! (`DIR_CLASS`). Write-opens are counted per tgid in the kernel.

use super::{InodeKey, TASK_COMM_LEN};

/// Rule and directory-class bits. Rule values and cached directory
/// classes share one space.
pub mod open_class {
    /// The file itself: every open reports (`SENSITIVE_FILES`).
    pub const FILE_SENSITIVE: u32 = 1 << 0;
    /// The file itself: write-opens report (critical files).
    pub const FILE_CRITICAL: u32 = 1 << 1;
    /// The file itself: write-opens report (persistence files).
    pub const FILE_PERSIST: u32 = 1 << 2;
    /// Directory: write-opens anywhere below report (critical trees).
    pub const TREE_CRITICAL: u32 = 1 << 3;
    /// Directory: write-opens anywhere below report (persistence trees).
    pub const TREE_PERSIST: u32 = 1 << 4;
    /// Directory: every open of a direct child reports (telemetry probe).
    pub const CHILDREN_PROBE: u32 = 1 << 5;
    /// Directory: every file below is a credential store (`.gnupg`, …).
    pub const TREE_CRED: u32 = 1 << 6;
    /// Directory: some children are credential stores (`.aws`, …), so
    /// the leaf name is read.
    pub const LEAVES_CRED: u32 = 1 << 7;
    /// Directory: inside a home tree; the browser and KeePass names are
    /// checked on the leaf.
    pub const TREE_HOME: u32 = 1 << 8;
    /// Directory: writes below do not count toward mass write.
    pub const TREE_CARVEOUT: u32 = 1 << 9;
    /// Directory: a user's runtime directory; writes by that login uid
    /// (`DirClass::uid`) do not count toward mass write.
    pub const TREE_RUNTIME: u32 = 1 << 10;
    /// Name rule: a leaf with this name (and parent name) is a
    /// credential store.
    pub const LEAF_CRED: u32 = 1 << 11;
    /// Directory: `CHILD_RULES` hold file rules for some of its children
    /// (files missing at registration), so the leaf name is read.
    pub const CHILD_FILES: u32 = 1 << 12;
    /// Directory: some of its children have their own `OPEN_RULES` entry
    /// (a sensitive, critical or persistence file), so an open there
    /// looks the file up; elsewhere the lookup is skipped.
    pub const DIR_HAS_FILES: u32 = 1 << 13;
    /// A computed `DIR_CLASS` entry (an empty class is still cached).
    pub const CLASSIFIED: u32 = 1 << 31;
    /// What a directory passes to every descendant.
    pub const SUBTREE: u32 =
        TREE_CRITICAL | TREE_PERSIST | TREE_CRED | TREE_HOME | TREE_CARVEOUT | TREE_RUNTIME;
    /// What a directory's own rule says about its direct children.
    pub const DIRECT: u32 = SUBTREE | CHILDREN_PROBE | LEAVES_CRED | CHILD_FILES | DIR_HAS_FILES;
}

/// Why a record was emitted (`OpenRecordRaw::reason`, any combination).
pub mod open_reason {
    pub const SENSITIVE: u32 = 1 << 0;
    pub const CRITICAL: u32 = 1 << 1;
    pub const PERSIST: u32 = 1 << 2;
    pub const PROBE: u32 = 1 << 3;
    pub const CRED: u32 = 1 << 4;
    pub const MASS_WRITE: u32 = 1 << 5;
    /// Review 86: a file capability was set (`security.capability`). The
    /// record's `count` carries the permitted set's low 32 bits, `flags`
    /// the high 32, and `mode` the xattr's `magic_etc` (revision in the
    /// top byte, the effective flag in bit 0).
    pub const FILE_CAP: u32 = 1 << 6;
    /// External audit POS-002: the tgid's write-opens of files that
    /// existed before the open (no `FMODE_CREATED`: rewritten, not
    /// created) crossed the mass-write threshold in the window. `count`
    /// still carries all its write-opens.
    pub const MASS_OVERWRITE: u32 = 1 << 7;
}

/// Names in the rule maps: NUL-padded, at most 31 bytes kept.
pub const OPEN_NAME_LEN: usize = 32;
/// Path components carried leaf → root, each in a fixed 32-byte slot.
pub const OPEN_PATH_SLOTS: usize = 16;
pub const OPEN_PATH_SLOT_LEN: usize = 32;
/// Ancestors walked when a directory is classified.
pub const OPEN_CLASSIFY_DEPTH: usize = 8;
/// Mass write: write-opens per tgid within the window (the posture arm's
/// values).
pub const OPEN_MASS_WRITE_MIN: u32 = 20;
pub const OPEN_MASS_WRITE_WINDOW_NS: u64 = 60 * 1_000_000_000;
/// `OPEN_SENSOR[0]` once userland armed the sensor (LSM mode).
pub const OPEN_SENSOR_ARMED: u32 = 1;

/// `CHILD_RULES` key: a registered directory and a child name.
#[repr(C)]
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "std", derive(bytemuck::Pod, bytemuck::Zeroable))]
pub struct ChildRuleKey {
    pub parent: InodeKey,
    pub name: [u8; OPEN_NAME_LEN],
}

/// Cached class of a directory (`DIR_CLASS` value).
#[repr(C)]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
#[cfg_attr(feature = "std", derive(bytemuck::Pod, bytemuck::Zeroable))]
pub struct DirClass {
    pub bits: u32,
    /// Owner of a runtime directory (`TREE_RUNTIME`).
    pub uid: u32,
    /// `DIR_CLASS_GEN[0]` when computed; any other value is stale.
    pub gen: u32,
    pub _pad: u32,
}

/// Per-tgid write-open window of the mass-write counter.
#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
#[cfg_attr(feature = "std", derive(bytemuck::Pod, bytemuck::Zeroable))]
pub struct OpenWriteWindow {
    pub start_ns: u64,
    pub count: u32,
    /// [`open_reason::MASS_WRITE`] / [`open_reason::MASS_OVERWRITE`] once
    /// each was reported in this window.
    pub fired: u32,
    /// External audit POS-002: the write-opens of files that existed.
    pub overwrites: u32,
    pub _pad: u32,
}

/// One interesting open. 8-aligned, no implicit padding:
/// 8·5 + 4·7 + 16 + 2 + 1 + 1 + 512 = 600.
#[repr(C)]
#[derive(Copy, Clone, Debug)]
#[cfg_attr(feature = "std", derive(bytemuck::Pod, bytemuck::Zeroable))]
pub struct OpenRecordRaw {
    pub timestamp_ns: u64,
    /// The opened file, `(dev, ino)` as `stat()` reports it.
    pub dev: u64,
    pub ino: u64,
    /// The top of the path walk (a filesystem root): userland maps it to
    /// a mount point to make the path absolute.
    pub root_dev: u64,
    pub root_ino: u64,
    pub pid: u32,
    pub uid: u32,
    pub gid: u32,
    /// `file->f_flags` (`O_*`; the kernel clears `O_CREAT`/`O_TRUNC`).
    pub flags: u32,
    /// `file->f_mode` (`FMODE_READ` = 1, `FMODE_WRITE` = 2).
    pub mode: u32,
    /// [`open_reason`] bits.
    pub reason: u32,
    /// Write-opens in the window when `reason` has `MASS_WRITE` or
    /// `MASS_OVERWRITE`.
    pub count: u32,
    pub comm: [u8; TASK_COMM_LEN],
    pub path_n: u16,
    pub path_truncated: u8,
    pub _pad: u8,
    pub path: [u8; OPEN_PATH_SLOTS * OPEN_PATH_SLOT_LEN],
}

#[cfg(all(test, feature = "std"))]
mod tests {
    use super::*;

    #[test]
    fn open_sensor_layouts() {
        assert_eq!(core::mem::size_of::<OpenRecordRaw>(), 600);
        assert_eq!(core::mem::align_of::<OpenRecordRaw>(), 8);
        assert_eq!(core::mem::size_of::<ChildRuleKey>(), 48);
        assert_eq!(core::mem::size_of::<DirClass>(), 16);
        assert_eq!(core::mem::size_of::<OpenWriteWindow>(), 24);
    }

    #[test]
    fn class_groups_are_consistent() {
        use open_class::*;
        assert_eq!(SUBTREE & CLASSIFIED, 0);
        assert_eq!(DIRECT & SUBTREE, SUBTREE);
        assert_eq!(
            DIRECT & (FILE_SENSITIVE | FILE_CRITICAL | FILE_PERSIST | LEAF_CRED),
            0
        );
    }
}
