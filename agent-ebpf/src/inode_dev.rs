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
    // makes trusted_ptr_ pointer be out of bounds").
    let (root_off, vfs_off, anon_off) = match (
        off_opt!(BTRFS_INODE_ROOT_OFFSET),
        off_opt!(BTRFS_INODE_VFS_INODE_OFFSET),
        off_opt!(BTRFS_ROOT_ANON_DEV_OFFSET),
    ) {
        (Some(a), Some(b), Some(c)) => (a & 0xffff, b & 0xffff, c & 0xffff),
        _ => return s_dev,
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
