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
        bpf_ktime_get_ns, bpf_probe_read_kernel, bpf_printk, bpf_trace_vprintk,
    },
    macros::{lsm, map},
    maps::{Array, HashMap, RingBuf},
    programs::LsmContext,
};

/// Trustworthy single-u64 printk that uses `bpf_trace_vprintk`
/// (helper #177) instead of aya 0.13's `bpf_printk!` macro.
///
/// The macro's 1-3-args path transmutes helper #6 to a Rust variadic
/// fn and passes `PrintkArg` aggregates by value. The BPF backend
/// lowers that as pass-by-pointer, so the kernel sees a STACK
/// POINTER instead of our value (verified in disassembly: r3 = &slot,
/// not r3 = value). The vprintk path takes an explicit
/// `data_ptr + data_len` so there's no variadic ambiguity.
///
/// Diagnostic-only; remove or gate behind a feature once Tappa 7
/// task 5 is verified working.
#[inline(always)]
unsafe fn nn_printk_u64(fmt: &[u8], value: u64) {
    let data: [u64; 1] = [value];
    bpf_trace_vprintk(
        fmt.as_ptr() as *const _,
        fmt.len() as u32,
        data.as_ptr() as *const _,
        core::mem::size_of_val(&data) as u32,
    );
}
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
    // 2026-05-12 diagnostic: zero-arg bpf_printk! markers in place of
    // nn_printk_u64. Suspected aya 0.13 bpf_trace_vprintk binding
    // silently drops output on Ubuntu 6.8's BPF-LSM trampoline (see
    // docs/TAPPA7_TASK5_DEEP_DEBUG.md §2 hypothesis B). If these
    // markers fire but the nn_printk_u64 ones in try_inode_rename /
    // try_file_ioctl do not, B is confirmed and we rip the helper out.
    bpf_printk!(b"nn-diag-REACHED-deny-if");
    let _ = operation;
    let key = match inode_key(target) {
        Some(k) => k,
        None => {
            bpf_printk!(b"nn-diag-REACHED-key-none");
            return false;
        }
    };
    bpf_printk!(b"nn-diag-REACHED-key-ok");
    if !is_protected(&key) {
        bpf_printk!(b"nn-diag-REACHED-MISS");
        return false;
    }
    if override_active() {
        bpf_printk!(b"nn-diag-REACHED-OVERRIDE");
        return false;
    }
    bpf_printk!(b"nn-diag-REACHED-MATCH");
    emit_denial(operation, key);
    true
}

// ---------------------------------------------------------------------------
// LSM programs
// ---------------------------------------------------------------------------

#[lsm(hook = "inode_unlink")]
pub fn inode_unlink(ctx: LsmContext) -> i32 {
    // Unconditional body marker — same role as inode_rename / file_ioctl
    // (see docs/TAPPA7_TASK5_DEEP_DEBUG.md). If `rm` runs and this
    // line never lands in trace_pipe, the kernel is not dispatching
    // security_inode_unlink to our BPF program at all.
    unsafe { bpf_printk!(b"nn-diag-unlink-body fired") };
    unsafe { try_inode_unlink(&ctx) }
}

#[inline(always)]
unsafe fn try_inode_unlink(ctx: &LsmContext) -> i32 {
    // No prev-retval read — see task_kill.rs for rationale (kernel
    // call_int_hook short-circuits, aya 0.13's phony-retval slot is
    // unreliable on Ubuntu 6.8 trampoline).
    //
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
    unsafe { bpf_printk!(b"nn-diag-rmdir-body fired") };
    unsafe { try_inode_rmdir(&ctx) }
}

#[inline(always)]
unsafe fn try_inode_rmdir(ctx: &LsmContext) -> i32 {
    // No prev-retval read — see task_kill.rs.
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
    // Unconditional entry marker — fires the instant the kernel
    // dispatches this BPF program, BEFORE any ctx.arg() access or
    // verifier-visible logic. Used to disambiguate "kernel called
    // security_inode_rename but our BPF prog didn't run" vs
    // "our prog ran but its logic didn't match" during 2026-05-12
    // Tappa 7 task 5 diagnosis.
    unsafe { bpf_printk!(b"nn-diag-rename-body fired") };
    unsafe { try_inode_rename(&ctx) }
}

#[inline(always)]
unsafe fn try_inode_rename(ctx: &LsmContext) -> i32 {
    // Kernel signature: (old_dir, old_dentry, new_dir, new_dentry).
    // No prev-retval read — see task_kill.rs for rationale.
    nn_printk_u64(b"nn-diag: ENTER inode_rename", 0);

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
    // Body marker covers chmod / chown / truncate paths. `touch` on
    // an existing file routes through notify_change → security_inode_setattr
    // so we expect this marker for `touch existingfile` too.
    unsafe { bpf_printk!(b"nn-diag-setattr-body fired") };
    unsafe { try_inode_setattr(&ctx) }
}

#[inline(always)]
unsafe fn try_inode_setattr(ctx: &LsmContext) -> i32 {
    // Kernel signature on Ubuntu 6.8: vlen=2, (dentry, iattr) —
    // verified against /sys/kernel/btf/vmlinux. Mainline 6.3+
    // prepended a `struct mnt_idmap *`. We previously read
    // ctx.arg(2) as the aya "phony retval" but per task_kill.rs
    // rationale we no longer trust that slot, so the read is gone.
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
    // Same diagnostic marker as inode_rename — unconditional, top
    // of body, no arg access yet. If the kernel calls
    // security_file_ioctl but this line never appears in
    // trace_pipe, our BPF program is registered to the wrong
    // attach point.
    unsafe { bpf_printk!(b"nn-diag-ioctl-body fired") };
    unsafe { try_file_ioctl(&ctx) }
}

#[inline(always)]
unsafe fn try_file_ioctl(ctx: &LsmContext) -> i32 {
    // Kernel signature: (file, cmd, arg). No prev-retval read —
    // this is exactly where aya's phony-retval convention bit us
    // in the 2026-05-12 diagnosis: ctx.arg(3) consistently returned
    // non-zero garbage on Ubuntu 6.8's trampoline, so every chattr
    // ioctl early-returned before reaching the cmd filter. See
    // task_kill.rs for the broader rationale.

    // Fast path: this hook fires for EVERY ioctl on EVERY fd.
    // Filter on cmd before touching any kernel struct.
    let cmd: c_uint = ctx.arg(1);
    nn_printk_u64(b"nn-diag: ENTER file_ioctl cmd=0x%lx", cmd as u64);
    if cmd != FS_IOC_SETFLAGS && cmd != FS_IOC32_SETFLAGS {
        return 0;
    }
    nn_printk_u64(b"nn-diag: file_ioctl matched chattr cmd=0x%lx", cmd as u64);

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
