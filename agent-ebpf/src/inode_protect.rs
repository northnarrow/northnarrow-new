//! `inode_*` and `file_ioctl` LSM hooks — Tappa 7 filesystem
//! protection.
//!
//! Five BPF-LSM programs guard the inodes registered by userland
//! (the `/var/lib/northnarrow/` directory, plus future Tappa 8 state
//! files). Each hook returns `-EPERM` to deny the operation and
//! emits one [`FsProtectDenialRaw`] record into the
//! [`FS_PROTECT_EVENTS`] ringbuffer for userland's audit log /
//! posture trigger.
//!
//! | Hook | Defends against |
//! |---|---|
//! | `inode_unlink` | `rm` of any file inside a protected dir, or of a protected file |
//! | `inode_rmdir`  | `rmdir` of a protected directory |
//! | `inode_rename` | `mv` involving a protected inode on either side |
//! | `inode_setattr`| `chmod` / `chown` / `truncate` on a protected inode |
//! | `file_ioctl`   | `chattr -i` / `chattr +i` via `FS_IOC_SETFLAGS` |
//!
//! Note: `chattr` does NOT go through `inode_setattr` — flag changes
//! travel down the `ioctl(FS_IOC_SETFLAGS)` path, bypassing
//! `notify_change()`. The `file_ioctl` hook is the only correct
//! place to defeat `chattr -i` from BPF-LSM.
//!
//! Identity policy: each LSM-chain prev-retval is honoured at
//! `arg(N)` where N = number of kernel args (2 / 2 / 4 / 3 / 3);
//! a non-zero prior verdict is propagated unchanged. The
//! [`FS_PROTECT_OVERRIDE`] map is the Tappa 8 escape hatch
//! (Ed25519-signed admin grant), shipped empty in the Tappa 7 ELF.

use aya_ebpf::{
    cty::{c_int, c_uint, c_void},
    helpers::{
        bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_get_current_uid_gid,
        bpf_ktime_get_ns, bpf_probe_read_kernel,
    },
    macros::{lsm, map},
    maps::{Array, HashMap, RingBuf},
    programs::LsmContext,
};
use northnarrow_common::wire::{
    FsProtectDenialRaw, InodeKey, FS_OP_IOCTL, FS_OP_RENAME, FS_OP_RMDIR, FS_OP_SETATTR,
    FS_OP_UNLINK,
};

use crate::btf_offsets::{
    DENTRY_D_INODE_OFFSET, FILE_F_INODE_OFFSET, INODE_I_INO_OFFSET, INODE_I_SB_OFFSET,
    SUPER_BLOCK_S_DEV_OFFSET,
};

/// Linux `EPERM` — LSM hooks return `-errno` to deny.
const EPERM: c_int = 1;

/// `FS_IOC_SETFLAGS = _IOW('f', 2, long)` on a 64-bit kernel.
/// `chattr +i` / `-i` sends this ioctl with the inode flag bitmap.
const FS_IOC_SETFLAGS: c_uint = 0x4008_6602;

/// `FS_IOC32_SETFLAGS = _IOW('f', 2, int)` — the 32-bit compat
/// variant. A 32-bit `chattr` binary on a 64-bit kernel ends up
/// here.
const FS_IOC32_SETFLAGS: c_uint = 0x4004_6602;

// ---------------------------------------------------------------------------
// Maps
// ---------------------------------------------------------------------------

/// Inodes the userland loader has registered for protection. Up to
/// 1024 entries; the Tappa 7 build only registers
/// `/var/lib/northnarrow/` (one entry). Value is unused (presence is
/// the signal); kept as `u8` to keep the map node tiny.
#[map]
pub static PROTECTED_INODES: HashMap<InodeKey, u8> = HashMap::with_max_entries(1024, 0);

/// Tappa 8 stub: Ed25519-signed override capability for FS
/// modification. Non-zero slot 0 = active admin grant, hooks
/// pass-through. Empty in Tappa 7.
#[map]
pub static FS_PROTECT_OVERRIDE: Array<u32> = Array::with_max_entries(1, 0);

/// Audit ringbuffer for denials. 64 KiB ≈ ~1100
/// [`FsProtectDenialRaw`] (56 B each). Denials are by definition
/// rare; if userland is asleep when a burst hits, losing the record
/// is acceptable — the kernel-side deny still fires.
#[map]
pub static FS_PROTECT_EVENTS: RingBuf = RingBuf::with_byte_size(64 * 1024, 0);

// ---------------------------------------------------------------------------
// Helpers — common pointer-chase logic for every hook.
// ---------------------------------------------------------------------------

/// Dereference a `*dentry` and return its `d_inode` pointer.
#[inline(always)]
unsafe fn inode_from_dentry(dentry: *const c_void) -> Option<*const c_void> {
    if dentry.is_null() {
        return None;
    }
    let slot = (dentry as *const u8).add(DENTRY_D_INODE_OFFSET) as *const *const c_void;
    match bpf_probe_read_kernel::<*const c_void>(slot) {
        Ok(p) if !p.is_null() => Some(p),
        _ => None,
    }
}

/// Read `(super_block->s_dev, inode->i_ino)` for the given inode.
#[inline(always)]
unsafe fn inode_key(inode: *const c_void) -> Option<InodeKey> {
    if inode.is_null() {
        return None;
    }
    let sb_slot = (inode as *const u8).add(INODE_I_SB_OFFSET) as *const *const c_void;
    let sb_ptr = bpf_probe_read_kernel::<*const c_void>(sb_slot).ok()?;
    if sb_ptr.is_null() {
        return None;
    }
    let dev_slot = (sb_ptr as *const u8).add(SUPER_BLOCK_S_DEV_OFFSET) as *const u32;
    let dev = bpf_probe_read_kernel::<u32>(dev_slot).ok()?;

    let ino_slot = (inode as *const u8).add(INODE_I_INO_OFFSET) as *const u64;
    let ino = bpf_probe_read_kernel::<u64>(ino_slot).ok()?;

    Some(InodeKey {
        dev: dev as u64,
        ino,
    })
}

/// `true` if the key is present in [`PROTECTED_INODES`].
#[inline(always)]
unsafe fn is_protected(key: &InodeKey) -> bool {
    PROTECTED_INODES.get(key).is_some()
}

/// Read [`FS_PROTECT_OVERRIDE`] slot 0; non-zero = bypass.
#[inline(always)]
fn override_active() -> bool {
    match FS_PROTECT_OVERRIDE.get(0) {
        Some(v) => *v != 0,
        None => false,
    }
}

/// Best-effort audit record. Silently drops if the ringbuffer is
/// full — the deny verdict still fires.
#[inline(always)]
fn emit_denial(operation: u8, key: InodeKey) {
    let mut entry = match FS_PROTECT_EVENTS.reserve::<FsProtectDenialRaw>(0) {
        Some(e) => e,
        None => return,
    };

    let raw_ptr: *mut FsProtectDenialRaw = entry.as_mut_ptr();
    unsafe {
        // SAFETY: the ringbuf reservation gives us exclusive
        // access to a properly aligned region the size of
        // FsProtectDenialRaw; zero the slot before writing so any
        // padding stays deterministic.
        core::ptr::write_bytes(raw_ptr, 0u8, 1);

        (*raw_ptr).timestamp_ns = bpf_ktime_get_ns();
        let pid_tgid = bpf_get_current_pid_tgid();
        (*raw_ptr).attacker_pid = (pid_tgid >> 32) as u32;
        let uid_gid = bpf_get_current_uid_gid();
        (*raw_ptr).attacker_uid = (uid_gid & 0xFFFF_FFFF) as u32;
        (*raw_ptr).target_dev = key.dev;
        (*raw_ptr).target_ino = key.ino;
        (*raw_ptr).operation = operation;

        if let Ok(comm) = bpf_get_current_comm() {
            (*raw_ptr).attacker_comm = comm;
        }
    }

    entry.submit(0);
}

/// Standard "should we deny?" decision used by every hook once it
/// has the target inode key. Returns `true` if the operation must
/// be blocked; emits the audit record as a side effect.
#[inline(always)]
unsafe fn deny_if_protected(operation: u8, target: *const c_void) -> bool {
    let key = match inode_key(target) {
        Some(k) => k,
        None => return false,
    };
    if !is_protected(&key) {
        return false;
    }
    if override_active() {
        return false;
    }
    emit_denial(operation, key);
    true
}

// ---------------------------------------------------------------------------
// LSM programs
// ---------------------------------------------------------------------------

#[lsm(hook = "inode_unlink")]
pub fn inode_unlink(ctx: LsmContext) -> i32 {
    unsafe { try_inode_unlink(&ctx) }
}

#[inline(always)]
unsafe fn try_inode_unlink(ctx: &LsmContext) -> i32 {
    let prev: c_int = ctx.arg(2);
    if prev != 0 {
        return prev;
    }
    // arg(0) = parent dir inode, arg(1) = target dentry. Block if
    // either the parent dir or the target inode itself is in the
    // protected set — that covers both "rm somefile inside dir" and
    // "rm /the/protected/file".
    let parent: *const c_void = ctx.arg(0);
    if deny_if_protected(FS_OP_UNLINK, parent) {
        return -EPERM;
    }
    let dentry: *const c_void = ctx.arg(1);
    if let Some(target_inode) = inode_from_dentry(dentry) {
        if deny_if_protected(FS_OP_UNLINK, target_inode) {
            return -EPERM;
        }
    }
    0
}

#[lsm(hook = "inode_rmdir")]
pub fn inode_rmdir(ctx: LsmContext) -> i32 {
    unsafe { try_inode_rmdir(&ctx) }
}

#[inline(always)]
unsafe fn try_inode_rmdir(ctx: &LsmContext) -> i32 {
    let prev: c_int = ctx.arg(2);
    if prev != 0 {
        return prev;
    }
    let parent: *const c_void = ctx.arg(0);
    if deny_if_protected(FS_OP_RMDIR, parent) {
        return -EPERM;
    }
    let dentry: *const c_void = ctx.arg(1);
    if let Some(target_inode) = inode_from_dentry(dentry) {
        if deny_if_protected(FS_OP_RMDIR, target_inode) {
            return -EPERM;
        }
    }
    0
}

#[lsm(hook = "inode_rename")]
pub fn inode_rename(ctx: LsmContext) -> i32 {
    unsafe { try_inode_rename(&ctx) }
}

#[inline(always)]
unsafe fn try_inode_rename(ctx: &LsmContext) -> i32 {
    // Kernel signature: (old_dir, old_dentry, new_dir, new_dentry).
    // Aya appends prev-retval at arg(4).
    let prev: c_int = ctx.arg(4);
    if prev != 0 {
        return prev;
    }

    let old_dir: *const c_void = ctx.arg(0);
    if deny_if_protected(FS_OP_RENAME, old_dir) {
        return -EPERM;
    }
    let new_dir: *const c_void = ctx.arg(2);
    if deny_if_protected(FS_OP_RENAME, new_dir) {
        return -EPERM;
    }

    let old_dentry: *const c_void = ctx.arg(1);
    if let Some(old_inode) = inode_from_dentry(old_dentry) {
        if deny_if_protected(FS_OP_RENAME, old_inode) {
            return -EPERM;
        }
    }
    let new_dentry: *const c_void = ctx.arg(3);
    if let Some(new_inode) = inode_from_dentry(new_dentry) {
        if deny_if_protected(FS_OP_RENAME, new_inode) {
            return -EPERM;
        }
    }
    0
}

#[lsm(hook = "inode_setattr")]
pub fn inode_setattr(ctx: LsmContext) -> i32 {
    unsafe { try_inode_setattr(&ctx) }
}

#[inline(always)]
unsafe fn try_inode_setattr(ctx: &LsmContext) -> i32 {
    // Kernel signature on Ubuntu 6.8 (verified against
    // /sys/kernel/btf/vmlinux): vlen=2, (dentry, iattr). Mainline
    // 6.3+ prepended a `struct mnt_idmap *` for idmapped mounts and
    // the hook became (mnt_idmap, dentry, iattr); Ubuntu's 6.8
    // backport kept the older 2-arg form. Aya appends prev-retval
    // as the final arg, so it lives at arg(2) here, not arg(3).
    // Using arg(3) made the verifier reject the program at load.
    let prev: c_int = ctx.arg(2);
    if prev != 0 {
        return prev;
    }
    let dentry: *const c_void = ctx.arg(0);
    if let Some(target_inode) = inode_from_dentry(dentry) {
        if deny_if_protected(FS_OP_SETATTR, target_inode) {
            return -EPERM;
        }
    }
    0
}

#[lsm(hook = "file_ioctl")]
pub fn file_ioctl(ctx: LsmContext) -> i32 {
    unsafe { try_file_ioctl(&ctx) }
}

#[inline(always)]
unsafe fn try_file_ioctl(ctx: &LsmContext) -> i32 {
    // Kernel signature: (file, cmd, arg). Prev-retval at arg(3).
    let prev: c_int = ctx.arg(3);
    if prev != 0 {
        return prev;
    }

    // Fast path: this hook fires for EVERY ioctl on EVERY fd.
    // Filter on cmd before touching any kernel struct.
    let cmd: c_uint = ctx.arg(1);
    if cmd != FS_IOC_SETFLAGS && cmd != FS_IOC32_SETFLAGS {
        return 0;
    }

    let file: *const c_void = ctx.arg(0);
    if file.is_null() {
        return 0;
    }
    let inode_slot = (file as *const u8).add(FILE_F_INODE_OFFSET) as *const *const c_void;
    let inode = match bpf_probe_read_kernel::<*const c_void>(inode_slot) {
        Ok(p) => p,
        Err(_) => return 0,
    };
    if deny_if_protected(FS_OP_IOCTL, inode) {
        return -EPERM;
    }
    0
}
