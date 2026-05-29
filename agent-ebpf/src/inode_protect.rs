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
        bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_get_current_uid_gid, bpf_ktime_get_ns,
        bpf_printk, bpf_probe_read_kernel,
    },
    macros::{lsm, map},
    maps::{Array, HashMap, RingBuf},
    programs::LsmContext,
};

// 2026-05-12 iter 2: removed the `nn_printk_u64` helper (and its
// `bpf_trace_vprintk` import). The helper was a workaround for aya
// 0.13's `bpf_printk!` macro losing values on the 1-3 args path, but
// iteration 1 proved the helper itself silently drops *every* call
// on Ubuntu 6.8's BPF-LSM trampoline. Diagnostics now use the
// zero-arg form of `bpf_printk!`, which is the only printk path
// observationally known to work on this build (see
// docs/TAPPA7_TASK5_DEEP_DEBUG.md §2 bug #1).

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

/// `FS_IOC_FSSETXATTR = _IOW('X', 32, struct fsxattr)` — the
/// project-quota / fsxattr path. Diagnostic-only: some recent
/// `chattr` binaries try this before falling back to FS_IOC_SETFLAGS.
/// We only print a marker if we see it; we do not yet treat it as a
/// chattr signal because it carries a 28-byte struct rather than a
/// raw flag bitmap.
const FS_IOC_FSSETXATTR: c_uint = 0x4028_5821;

/// `FS_IOC_FSGETXATTR = _IOR('X', 31, struct fsxattr)` — usually
/// paired with FSSETXATTR. Diagnostic marker only.
const FS_IOC_FSGETXATTR: c_uint = 0x801c_581f;

// ---------------------------------------------------------------------------
// Maps
// ---------------------------------------------------------------------------

/// Inodes the userland loader has registered for protection. Up to
/// 1024 entries; the Tappa 7 build only registers
/// `/var/lib/northnarrow/` (one entry). Value is unused (presence is
/// the signal); kept as `u8` to keep the map node tiny.
///
/// By-name pinned (Tappa 7 task 6 #2): the pinned `inode_*` hooks
/// must read the same kernel map a restarted agent re-registers
/// into. See `task_kill::PROTECTED_PIDS` for the full rationale.
#[map]
pub static PROTECTED_INODES: HashMap<InodeKey, u8> = HashMap::pinned(1024, 0);

/// Tappa 8 stub: Ed25519-signed override capability for FS
/// modification. Non-zero slot 0 = active admin grant, hooks
/// pass-through. Empty in Tappa 7. Pinned by-name; Tappa-8 caveat:
/// slot 0 persists across restart and must be zeroed on boot.
#[map]
pub static FS_PROTECT_OVERRIDE: Array<u32> = Array::pinned(1, 0);

/// Audit ringbuffer for denials. 64 KiB ≈ ~1100
/// [`FsProtectDenialRaw`] (56 B each). Denials are by definition
/// rare; if userland is asleep when a burst hits, losing the record
/// is acceptable — the kernel-side deny still fires.
///
/// Pinned by-name: the pinned `inode_*` hooks write here, so a
/// restarted agent must drain the SAME kernel ringbuf rather than a
/// fresh one (same split-brain class as `PROTECTED_INODES`).
///
/// TODO(fs-protect-ringbuf-reuse): a pinned-and-reused BPF ringbuf
/// desyncs the new process's fresh consumer across `systemctl
/// restart` (consumer/producer position lives in the kernel map
/// object) — the exact bug fixed for `FS_FIM_EVENTS` by making it
/// process-local. Do NOT apply the same one-line `pinned ->
/// with_byte_size` here in isolation: this ring's producer is the
/// `inode_*` LSM program attached via a REUSED pinned link
/// (non-transient — anti_tamper/mod.rs `filesystem::attach`), so
/// unpinning only the ring splits producer (old reused prog -> old
/// ring) from consumer (new ring) = a SILENT fs-protect blackout
/// instead of a loud `expected got=0` flood. The fix must drop the
/// ring-pin AND the program-link-pin together so both reattach fresh;
/// that is a separate change with anti-tamper-persistence
/// implications and is deliberately deferred.
#[map]
pub static FS_PROTECT_EVENTS: RingBuf = RingBuf::pinned(64 * 1024, 0);

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
    // 2026-05-12 iter 2: zero-arg bpf_printk! markers throughout —
    // bpf_trace_vprintk was confirmed broken in iteration 1 and
    // ripped out. These REACHED markers, plus the granular
    // pre-deny markers in each try_* wrapper, let us localise the
    // current cutoff (body marker fires, REACHED-deny-if does not).
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
    // Tappa 8 A14 (B4): caller-side mutual whitelist. If the
    // CALLER's tgid is in `task_kill::PROTECTED_PIDS`, allow the
    // operation — same symmetric exemption PHASE_D_002 added to
    // ptrace_access_check. The agent and watchdog are both
    // inserted into PROTECTED_PIDS by W6, so this naturally
    // exempts the agent's own A13 rotate-keys atomic rewrite +
    // every other in-family FS-mutation path (audit log
    // append, agent.sig.key rotation on re-install, etc.)
    // while denying every unrelated root caller.
    let caller_tgid = (bpf_get_current_pid_tgid() >> 32) as u32;
    if crate::task_kill::PROTECTED_PIDS.get(&caller_tgid).is_some() {
        bpf_printk!(b"nn-diag-REACHED-CALLER-EXEMPT");
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
    bpf_printk!(b"nn-diag-unlink-tryentry");
    let parent: *const c_void = ctx.arg(0);
    bpf_printk!(b"nn-diag-unlink-pre-deny-parent");
    if deny_if_protected(FS_OP_UNLINK, parent) {
        return -EPERM;
    }
    let dentry: *const c_void = ctx.arg(1);
    if let Some(target_inode) = inode_from_dentry(dentry) {
        bpf_printk!(b"nn-diag-unlink-pre-deny-target");
        if deny_if_protected(FS_OP_UNLINK, target_inode) {
            return -EPERM;
        }
    } else {
        bpf_printk!(b"nn-diag-unlink-target-dentry-none");
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
    bpf_printk!(b"nn-diag-rmdir-tryentry");
    let parent: *const c_void = ctx.arg(0);
    bpf_printk!(b"nn-diag-rmdir-pre-deny-parent");
    if deny_if_protected(FS_OP_RMDIR, parent) {
        return -EPERM;
    }
    let dentry: *const c_void = ctx.arg(1);
    if let Some(target_inode) = inode_from_dentry(dentry) {
        bpf_printk!(b"nn-diag-rmdir-pre-deny-target");
        if deny_if_protected(FS_OP_RMDIR, target_inode) {
            return -EPERM;
        }
    } else {
        bpf_printk!(b"nn-diag-rmdir-target-dentry-none");
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
    bpf_printk!(b"nn-diag-rename-tryentry");

    let old_dir: *const c_void = ctx.arg(0);
    bpf_printk!(b"nn-diag-rename-pre-deny-old-dir");
    if deny_if_protected(FS_OP_RENAME, old_dir) {
        return -EPERM;
    }
    let new_dir: *const c_void = ctx.arg(2);
    bpf_printk!(b"nn-diag-rename-pre-deny-new-dir");
    if deny_if_protected(FS_OP_RENAME, new_dir) {
        return -EPERM;
    }

    let old_dentry: *const c_void = ctx.arg(1);
    if let Some(old_inode) = inode_from_dentry(old_dentry) {
        bpf_printk!(b"nn-diag-rename-pre-deny-old-inode");
        if deny_if_protected(FS_OP_RENAME, old_inode) {
            return -EPERM;
        }
    } else {
        bpf_printk!(b"nn-diag-rename-old-dentry-none");
    }
    let new_dentry: *const c_void = ctx.arg(3);
    if let Some(new_inode) = inode_from_dentry(new_dentry) {
        bpf_printk!(b"nn-diag-rename-pre-deny-new-inode");
        if deny_if_protected(FS_OP_RENAME, new_inode) {
            return -EPERM;
        }
    } else {
        bpf_printk!(b"nn-diag-rename-new-dentry-none");
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
    bpf_printk!(b"nn-diag-setattr-tryentry");
    let dentry: *const c_void = ctx.arg(0);
    if let Some(target_inode) = inode_from_dentry(dentry) {
        bpf_printk!(b"nn-diag-setattr-pre-deny");
        if deny_if_protected(FS_OP_SETATTR, target_inode) {
            return -EPERM;
        }
    } else {
        bpf_printk!(b"nn-diag-setattr-dentry-none");
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
    // see task_kill.rs.
    //
    // Fast path: this hook fires for EVERY ioctl on EVERY fd. To
    // keep trace_pipe readable we deliberately do NOT emit a marker
    // on the no-match branch — only on the cmd values that *could*
    // be chattr-family, and on every step after the cmd match.

    let cmd: c_uint = ctx.arg(1);

    // Forensic markers for the four chattr-family ioctls. Some
    // recent `chattr` binaries try FSSETXATTR before falling back
    // to SETFLAGS; if we see the FSSETXATTR marker but no
    // SETFLAGS, the cmd-filter list is incomplete and we need to
    // widen it.
    if cmd == FS_IOC_SETFLAGS {
        bpf_printk!(b"nn-diag-ioctl-cmd-SETFLAGS");
    } else if cmd == FS_IOC32_SETFLAGS {
        bpf_printk!(b"nn-diag-ioctl-cmd-SETFLAGS32");
    } else if cmd == FS_IOC_FSSETXATTR {
        bpf_printk!(b"nn-diag-ioctl-cmd-FSSETXATTR");
    } else if cmd == FS_IOC_FSGETXATTR {
        bpf_printk!(b"nn-diag-ioctl-cmd-FSGETXATTR");
    }

    if cmd != FS_IOC_SETFLAGS && cmd != FS_IOC32_SETFLAGS {
        return 0;
    }
    bpf_printk!(b"nn-diag-ioctl-cmd-matched");

    let file: *const c_void = ctx.arg(0);
    if file.is_null() {
        bpf_printk!(b"nn-diag-ioctl-file-null");
        return 0;
    }
    bpf_printk!(b"nn-diag-ioctl-file-ok");

    let inode_slot = (file as *const u8).add(FILE_F_INODE_OFFSET) as *const *const c_void;
    let inode = match bpf_probe_read_kernel::<*const c_void>(inode_slot) {
        Ok(p) => p,
        Err(_) => {
            bpf_printk!(b"nn-diag-ioctl-probe-err");
            return 0;
        }
    };
    bpf_printk!(b"nn-diag-ioctl-pre-deny");
    if deny_if_protected(FS_OP_IOCTL, inode) {
        return -EPERM;
    }
    0
}
