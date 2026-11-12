//! Review 55: the device number of an inode as `stat()` reports it.
//!
//! Userland fills every inode-keyed map (`WATCHED_PATHS`,
//! `PROTECTED_INODES`, `OWN_EXE_INODES`) from `stat()`, and the eBPF side
//! looks them up from the kernel's inode. For every filesystem except
//! btrfs, `stat()` reports the superblock's `s_dev`. btrfs reports the
//! device of the inode's subvolume instead (`btrfs_getattr`:
//! `stat->dev = BTRFS_I(inode)->root->anon_dev`), and inode numbers
//! restart in every subvolume. The superblock's device would therefore
//! neither match userland's keys nor tell two subvolumes apart: on btrfs
//! no key ever matched.

use aya_ebpf::helpers::bpf_probe_read_kernel;

use crate::btf_offsets::{
    BTRFS_INODE_ROOT_OFFSET, BTRFS_INODE_VFS_INODE_OFFSET, BTRFS_ROOT_ANON_DEV_OFFSET,
    SUPER_BLOCK_S_MAGIC_OFFSET,
};

/// `BTRFS_SUPER_MAGIC`, include/uapi/linux/magic.h.
const BTRFS_SUPER_MAGIC: u64 = 0x9123_683E;

/// `s_dev` (already read from `sb`), or, for a btrfs inode, the anonymous
/// device of its subvolume. Without the btrfs offsets (no btrfs on this
/// host) or on a failed read it stays `s_dev`: the extra cost elsewhere is
/// three array lookups.
#[inline(always)]
pub unsafe fn stat_dev(inode: *const u8, sb: *const u8, s_dev: u32) -> u32 {
    // Bounded to 16 bits (the real values are below 1 KiB): `inode` is a
    // BTF-typed pointer in the hooks that receive one, and the verifier
    // refuses arithmetic on it with an unbounded offset ("value -4294967295
    // makes trusted_ptr_ pointer be out of bounds"). One offset at a time,
    // each consumed at once: a tuple of three `Option`s was spilled and
    // read back on a path that never wrote it, which the 5.15 verifier
    // refuses ("invalid read from stack", 5.15 rule 3) once the caller is
    // large enough (the file-open sensor of Tappa 10.9).
    let root_off = match off_opt!(BTRFS_INODE_ROOT_OFFSET) {
        Some(o) => o & 0xffff,
        None => return s_dev,
    };
    let vfs_off = match off_opt!(BTRFS_INODE_VFS_INODE_OFFSET) {
        Some(o) => o & 0xffff,
        None => return s_dev,
    };
    let anon_off = match off_opt!(BTRFS_ROOT_ANON_DEV_OFFSET) {
        Some(o) => o & 0xffff,
        None => return s_dev,
    };
    let magic = match bpf_probe_read_kernel::<u64>(
        sb.add(off!(SUPER_BLOCK_S_MAGIC_OFFSET)) as *const u64,
    ) {
        Ok(m) => m,
        Err(_) => return s_dev,
    };
    if magic != BTRFS_SUPER_MAGIC {
        return s_dev;
    }
    // container_of(inode, struct btrfs_inode, vfs_inode)
    let bi = (inode as usize).wrapping_sub(vfs_off) as *const u8;
    let root = match bpf_probe_read_kernel::<*const u8>(bi.add(root_off) as *const *const u8) {
        Ok(p) if !p.is_null() => p,
        _ => return s_dev,
    };
    match bpf_probe_read_kernel::<u32>(root.add(anon_off) as *const u32) {
        Ok(d) if d != 0 => d,
        _ => s_dev,
    }
}

/// Lot 318 (external bug hunt BUG108): [`stat_dev`] for many inodes of one
/// superblock — a dentry walk, where `d_parent` never leaves it. The
/// superblock's facts are read once: `s_dev`, and for a btrfs superblock
/// with the three offsets resolved, those offsets (`btrfs` says so;
/// `btrfs_inode.root` is at byte 0, so no offset can stand for "absent").
/// Otherwise `s_dev` stands, as in [`stat_dev`]. Plain integers, every one
/// written on every path: the 5.15 verifier refuses a stack slot one path
/// left unwritten.
#[derive(Clone, Copy)]
pub struct SbDev {
    s_dev: u32,
    btrfs: u32,
    vfs_off: usize,
    root_off: usize,
    anon_off: usize,
}

impl SbDev {
    /// The facts of superblock `sb` (whose `s_dev` the caller read).
    #[inline(always)]
    pub unsafe fn of(sb: *const u8, s_dev: u32) -> Self {
        let mut d = SbDev {
            s_dev,
            btrfs: 0,
            vfs_off: 0,
            root_off: 0,
            anon_off: 0,
        };
        let magic = bpf_probe_read_kernel::<u64>(
            sb.add(off!(SUPER_BLOCK_S_MAGIC_OFFSET)) as *const u64,
        )
        .unwrap_or(0);
        if magic != BTRFS_SUPER_MAGIC {
            return d;
        }
        let mut have = 0u32;
        if let Some(o) = off_opt!(BTRFS_INODE_ROOT_OFFSET) {
            d.root_off = o & 0xffff;
            have += 1;
        }
        if let Some(o) = off_opt!(BTRFS_INODE_VFS_INODE_OFFSET) {
            d.vfs_off = o & 0xffff;
            have += 1;
        }
        if let Some(o) = off_opt!(BTRFS_ROOT_ANON_DEV_OFFSET) {
            d.anon_off = o & 0xffff;
            have += 1;
        }
        if have == 3 {
            d.btrfs = 1;
        }
        d
    }

    /// `stat()`'s device of `inode`, an inode of this superblock.
    #[inline(always)]
    pub unsafe fn dev(&self, inode: *const u8) -> u32 {
        if self.btrfs == 0 {
            return self.s_dev;
        }
        // container_of(inode, struct btrfs_inode, vfs_inode)
        let bi = (inode as usize).wrapping_sub(self.vfs_off) as *const u8;
        let root = match bpf_probe_read_kernel::<*const u8>(bi.add(self.root_off) as *const *const u8) {
            Ok(p) if !p.is_null() => p,
            _ => return self.s_dev,
        };
        match bpf_probe_read_kernel::<u32>(root.add(self.anon_off) as *const u32) {
            Ok(d) if d != 0 => d,
            _ => self.s_dev,
        }
    }
}
