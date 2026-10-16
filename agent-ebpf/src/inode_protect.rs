//! `inode_*` and `file_ioctl` LSM hooks — Tappa 7 filesystem
//! protection.
//!
//! BPF-LSM deny programs guard the inodes registered by userland (the
//! agent's directories, its identity and state files, its binaries and
//! units, its bpffs pins). Each hook returns `-EPERM` to deny the
//! operation and emits one [`FsProtectDenialRaw`] record into the
//! [`FS_PROTECT_EVENTS`] ringbuffer for userland's audit log / posture
//! trigger.
//!
//! | Hook | Defends against |
//! |---|---|
//! | `inode_unlink` | `rm` of any file inside a protected dir, or of a protected file |
//! | `inode_rmdir`  | `rmdir` of a protected directory |
//! | `inode_rename` | `mv` involving a protected inode on either side |
//! | `inode_setattr`| `chmod` / `chown` / `truncate` on a protected inode |
//! | `file_ioctl`   | `chattr -i` / `chattr +i` via `FS_IOC_SETFLAGS` / `FS_IOC_FSSETXATTR` |
//! | `file_open`    | a write-open of a WRITE-protected inode, any open of a READ-protected one |
//! | `inode_create`, `inode_mkdir`, `inode_mknod`, `inode_symlink`, `inode_link` | a new entry in a NOCREATE directory |
//! | `inode_setxattr`, `inode_removexattr` (`inode_set_acl`, `inode_remove_acl` on 6.2+) | an extended attribute or ACL changed on a protected inode |
//!
//! Note: `chattr` does NOT go through `inode_setattr` — flag changes
//! travel down the `ioctl(FS_IOC_SETFLAGS)` path, bypassing
//! `notify_change()`. The `file_ioctl` hook is the only correct
//! place to defeat `chattr -i` from BPF-LSM.
//!
//! No hook reads the LSM chain's previous verdict (see `task_kill.rs`).
//! The [`FS_GRANT`] map is the trusted-installer window: while it is
//! open, nothing is denied.

use aya_ebpf::{
    cty::{c_int, c_uint, c_void},
    helpers::{
        bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_get_current_uid_gid, bpf_ktime_get_ns,
        bpf_probe_read_kernel, bpf_probe_read_kernel_str_bytes,
    },
    macros::{lsm, map},
    maps::{Array, HashMap, LruHashMap, RingBuf},
    programs::LsmContext,
    EbpfContext,
};

// Review 56: the zero-arg `bpf_printk!` diagnostic markers of the
// 2026-05 investigation (docs/TAPPA7_TASK5_DEEP_DEBUG.md) are gone.
// `bpf_trace_printk` takes a global lock and writes the trace buffer on
// every call: one per `file_open` and up to five per write-open of the
// whole host, and the kernel's "trace_printk() being used" banner on every
// agent host. Do not put printk back in a hot hook; count in a map instead.

use northnarrow_common::wire::{
    fs_protect_required, FsGrant, FsProtectDenialRaw, InodeKey, FS_OP_CREATE, FS_OP_IOCTL,
    FS_OP_LINK, FS_OP_MKDIR, FS_OP_MKNOD, FS_OP_READ, FS_OP_RENAME, FS_OP_RMDIR, FS_OP_SETATTR,
    FS_OP_SYMLINK, FS_OP_UNLINK, FS_OP_WRITE, FS_OP_XATTR, READ_PROTECTED_SLOTS,
};

use crate::btf_offsets::{
    DENTRY_D_INODE_OFFSET, FILE_F_INODE_OFFSET, FILE_F_MODE_OFFSET, INODE_I_INO_OFFSET,
    INODE_I_SB_OFFSET, SUPER_BLOCK_S_DEV_OFFSET,
};

/// Linux `EPERM` — LSM hooks return `-errno` to deny.
const EPERM: c_int = 1;

/// `FMODE_WRITE` from `include/linux/fs.h` — the `file->f_mode` bit set
/// when a file is opened for writing (`O_WRONLY` / `O_RDWR`). The
/// at-authz-1 `protected_open_deny` hook denies only opens carrying this
/// bit; a read-open (the agent's own O_RDONLY admin.pub load, `cat`, the
/// init system reading a unit) has `FMODE_READ` only and passes through.
const FMODE_WRITE: u32 = 0x2;

/// The chattr-family ioctls the deny filters: `FS_IOC_SETFLAGS` and its
/// 32-bit variant carry the inode flag bitmap (`chattr +i/-i/+a`);
/// `FS_IOC_FSSETXATTR` sets the same flags through `struct fsxattr`
/// (`xfs_io -c 'chattr -i'`). External audit EBPF-008: the last one was
/// neither filtered nor right (`0x40285821`); the numbers now come from
/// `common`, where a test pins them to the uapi.
const FS_IOC_SETFLAGS: c_uint = northnarrow_common::wire::FS_IOC_SETFLAGS;
const FS_IOC32_SETFLAGS: c_uint = northnarrow_common::wire::FS_IOC32_SETFLAGS;
const FS_IOC_FSSETXATTR: c_uint = northnarrow_common::wire::FS_IOC_FSSETXATTR;

// ---------------------------------------------------------------------------
// Maps
// ---------------------------------------------------------------------------

/// Inodes the userland loader has registered for protection. Up to
/// 1024 entries. The value is an at-authz-1 flag-mask
/// (`FS_PROTECT_MUTATE` bit0 = the legacy unlink/rmdir/rename/setattr/
/// ioctl/xattr denies, set on every member; `FS_PROTECT_WRITE` bit1 = the
/// `file_open` write-open deny, set only on the secret/integrity subset;
/// `FS_PROTECT_READ` bit2 = the signing key; `FS_PROTECT_NOCREATE` bit3 =
/// no new entry, set only on the agent's own directories).
/// `deny_if_protected` reads it op-aware. Kept as `u8` (map node tiny).
///
/// By-name pinned (Tappa 7 task 6 #2): the pinned `inode_*` hooks
/// must read the same kernel map a restarted agent re-registers
/// into. See `task_kill::PROTECTED_PIDS` for the full rationale.
#[map]
pub static PROTECTED_INODES: HashMap<InodeKey, u8> = HashMap::pinned(1024, 0);

/// External audit EVD-001: inode numbers of the READ-protected inodes (the
/// agent's private signing key), 0 = empty slot. A read-only open is
/// matched on the inode number against these few slots first, so the
/// common read path pays no hash lookup; a match goes through
/// `deny_if_protected` (`FS_OP_READ`, `FS_PROTECT_READ`, the device, the
/// family and the trusted-installer window). Pinned with `PROTECTED_INODES`.
#[map]
pub static READ_PROTECTED_INOS: Array<u64> = Array::pinned(READ_PROTECTED_SLOTS, 0);

/// The trusted-installer window's kernel half (external audit ATP-003):
/// slot 0 carries this boot's session nonce and the window's deadline,
/// written by the agent for a signed grant and zeroed when it closes and
/// at every boot. Pinned by name. A new map, not `FS_PROTECT_OVERRIDE`
/// grown to 16 bytes: aya reuses a by-name pin at load, and a 4-byte pin
/// left by an older agent would fail every deny hook's verification.
#[map]
pub static FS_GRANT: Array<FsGrant> = Array::pinned(1, 0);

/// Audit ringbuffer for denials. 64 KiB ≈ ~1100
/// [`FsProtectDenialRaw`] (56 B each). Denials are by definition
/// rare; if userland is asleep when a burst hits, losing the record
/// is acceptable — the kernel-side deny still fires.
///
/// Pinned by-name: the pinned `inode_*` hooks write here, so a
/// restarted agent must drain the SAME kernel ringbuf rather than a
/// fresh one (same split-brain class as `PROTECTED_INODES`).
///
/// BUG-024 fix (fs-protect-ringbuf-reuse): this ring is process-local
/// (`with_byte_size`, fresh per boot) — NOT pinned. A pinned-and-reused
/// BPF ringbuf desyncs the new process's consumer across `systemctl
/// restart` (consumer/producer position lives in the kernel map object);
/// on a real host that replayed stale denials at ~1.6k/sec and DoS'd the
/// agent's own LogNamespace. The one-line `pinned -> with_byte_size` used
/// for `FS_FIM_EVENTS` is NOT safe alone here, because this ring's
/// producers (the `inode_*` LSM deny programs) must not stay
/// pinned-and-reused against a fresh ring (that would split old-producer/
/// old-ring from new-consumer = a SILENT blackout). So the ring AND its
/// producer links are reattached fresh TOGETHER every boot:
/// `antitamper_bpf::reattach_fresh` (driven by `filesystem::attach`)
/// attaches this boot's program BEFORE purging the prior boot's pin —
/// zero-window split-brain — while binding to this fresh ring. task_kill /
/// ptrace emit here too (`emit_task_denial`) and are reattached fresh the
/// same way (review 62).
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
    let slot = (dentry as *const u8).add(off!(DENTRY_D_INODE_OFFSET)) as *const *const c_void;
    match bpf_probe_read_kernel::<*const c_void>(slot) {
        Ok(p) if !p.is_null() => Some(p),
        _ => None,
    }
}

/// Read `(device, inode->i_ino)` for the given inode, the device as
/// `stat(2)` reports it ([`crate::inode_dev::stat_dev`], review 55).
#[inline(always)]
unsafe fn inode_key(inode: *const c_void) -> Option<InodeKey> {
    if inode.is_null() {
        return None;
    }
    let sb_slot = (inode as *const u8).add(off!(INODE_I_SB_OFFSET)) as *const *const c_void;
    let sb_ptr = bpf_probe_read_kernel::<*const c_void>(sb_slot).ok()?;
    if sb_ptr.is_null() {
        return None;
    }
    let dev_slot = (sb_ptr as *const u8).add(off!(SUPER_BLOCK_S_DEV_OFFSET)) as *const u32;
    let dev = bpf_probe_read_kernel::<u32>(dev_slot).ok()?;
    let dev = crate::inode_dev::stat_dev(inode as *const u8, sb_ptr as *const u8, dev);

    let ino_slot = (inode as *const u8).add(off!(INODE_I_INO_OFFSET)) as *const u64;
    let ino = bpf_probe_read_kernel::<u64>(ino_slot).ok()?;

    Some(InodeKey {
        dev: dev as u64,
        ino,
    })
}

/// FIM-009 self-upgrade (§15.1): the trusted-installer FS-pin override
/// is active while [`FS_GRANT`]`[0]` carries this boot's session nonce
/// ([`crate::task_kill::AGENT_SESSION`]`[0]`) and its deadline has not
/// passed ([`FsGrant::active`]).
///
/// The session compare keeps a grant pinned by an earlier boot from
/// reopening the pin; the deadline (external audit ATP-003) closes the
/// window on time even when the agent cannot — before, the slot stayed
/// armed until an event reached the agent's sweep, and a host whose
/// event path had stalled kept every protected file, the pin root and
/// the kexec refusal open past the deadline.
#[inline(always)]
pub(crate) fn override_active() -> bool {
    let session = match crate::task_kill::AGENT_SESSION.get(0) {
        Some(v) => *v,
        None => return false,
    };
    match FS_GRANT.get(0) {
        Some(g) => g.active(unsafe { bpf_ktime_get_ns() }, session),
        None => false,
    }
}

/// `(caller tgid << 8) | op` → monotonic ns of the last task-denial record
/// for that caller and operation (1 s dedup: a `while true; kill` loop
/// from one shell is one record per second).
#[map]
static TASK_DENIAL_SEEN: LruHashMap<u64, u64> = LruHashMap::with_max_entries(1024, 0);

/// Global budget for task-denial records: slot 0 = window start (ns),
/// slot 1 = records in the window. A loop of fresh `/bin/kill` processes
/// defeats the per-caller dedup; this caps it at [`TASK_DENIAL_PER_SEC`]
/// so the denial ring cannot be used to bury other evidence.
#[map]
static TASK_DENIAL_RATE: Array<u64> = Array::with_max_entries(2, 0);

const TASK_DENIAL_PER_SEC: u64 = 50;
const TASK_DENIAL_DEDUP_NS: u64 = 1_000_000_000;

/// Evidence for a refused signal or ptrace attach on a protected pid
/// (`FS_OP_SIGNAL` / `FS_OP_PTRACE`): same ring and record as the inode
/// denials, `target_ino` = target tgid, `target_dev` = signal or ptrace
/// mode. The deny itself never depends on this record.
#[inline(always)]
pub fn emit_task_denial(operation: u8, detail: u64, target_tgid: u32) {
    let now = unsafe { bpf_ktime_get_ns() };
    let caller = (bpf_get_current_pid_tgid() >> 32) as u64;
    let key = (caller << 8) | operation as u64;
    match TASK_DENIAL_SEEN.get_ptr_mut(&key) {
        Some(last) => unsafe {
            if now.wrapping_sub(*last) < TASK_DENIAL_DEDUP_NS {
                return;
            }
            *last = now;
        },
        None => {
            let _ = TASK_DENIAL_SEEN.insert(&key, &now, 0);
        }
    }
    let (Some(start), Some(count)) = (TASK_DENIAL_RATE.get_ptr_mut(0), TASK_DENIAL_RATE.get_ptr_mut(1)) else {
        return;
    };
    unsafe {
        if now.wrapping_sub(*start) >= TASK_DENIAL_DEDUP_NS {
            *start = now;
            *count = 0;
        }
        if *count >= TASK_DENIAL_PER_SEC {
            return;
        }
        *count += 1;
    }
    emit_denial(
        operation,
        InodeKey {
            dev: detail,
            ino: target_tgid as u64,
        },
    );
}

/// Best-effort audit record. Silently drops if the ringbuffer is
/// full — the deny verdict still fires.
#[inline(always)]
fn emit_denial(operation: u8, key: InodeKey) {
    let mut entry = match FS_PROTECT_EVENTS.reserve::<FsProtectDenialRaw>(0) {
        Some(e) => e,
        None => {
            crate::drops::bump(northnarrow_common::ring_drops::ring_slot::FS_PROTECT);
            return;
        }
    };

    let raw_ptr: *mut FsProtectDenialRaw = entry.as_mut_ptr();
    unsafe {
        // SAFETY: the ringbuf reservation gives us exclusive
        // access to a properly aligned region the size of
        // FsProtectDenialRaw; zero the slot before writing so any
        // padding stays deterministic.
        crate::zero::zero(raw_ptr);

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
        None => {
            return false;
        }
    };
    // at-authz-1: the map value is a flag-mask. An absent key is not
    // protected; a present key is denied for THIS op only if the op's
    // bit is set (`fs_protect_required`): `FS_PROTECT_WRITE` for a
    // write-open, `FS_PROTECT_READ` for a read-open, `FS_PROTECT_NOCREATE`
    // (the agent's own directories only) for a new entry, and
    // `FS_PROTECT_MUTATE`, which the loader sets on every member, for
    // every other op. `operation` is a constant at each call site, so the
    // match folds away.
    let flags = match PROTECTED_INODES.get(&key) {
        Some(f) => *f,
        None => {
            return false;
        }
    };
    let required = fs_protect_required(operation);
    if flags & required == 0 {
        return false;
    }
    if override_active() {
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
    } else {
    }
    0
}

#[lsm(hook = "inode_rmdir")]
pub fn inode_rmdir(ctx: LsmContext) -> i32 {
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
    } else {
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
    unsafe { try_inode_rename(&ctx) }
}

#[inline(always)]
unsafe fn try_inode_rename(ctx: &LsmContext) -> i32 {
    // Kernel signature: (old_dir, old_dentry, new_dir, new_dentry).
    // No prev-retval read — see task_kill.rs for rationale.

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
    } else {
    }
    let new_dentry: *const c_void = ctx.arg(3);
    if let Some(new_inode) = inode_from_dentry(new_dentry) {
        if deny_if_protected(FS_OP_RENAME, new_inode) {
            return -EPERM;
        }
    } else {
    }
    0
}

#[lsm(hook = "inode_setattr")]
pub fn inode_setattr(ctx: LsmContext) -> i32 {
    // Body marker covers chmod / chown / truncate paths. `touch` on
    // an existing file routes through notify_change → security_inode_setattr
    // so we expect this marker for `touch existingfile` too.
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
    } else {
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

    if cmd != FS_IOC_SETFLAGS && cmd != FS_IOC32_SETFLAGS && cmd != FS_IOC_FSSETXATTR {
        return 0;
    }

    let file: *const c_void = ctx.arg(0);
    if file.is_null() {
        return 0;
    }

    let inode_slot = (file as *const u8).add(off!(FILE_F_INODE_OFFSET)) as *const *const c_void;
    let inode = match bpf_probe_read_kernel::<*const c_void>(inode_slot) {
        Ok(p) => p,
        Err(_) => {
            return 0;
        }
    };
    if deny_if_protected(FS_OP_IOCTL, inode) {
        return -EPERM;
    }
    0
}

/// at-authz-1 — write-open deny. The sixth deny hook in the
/// inode_protect family. The first five cover dir-entry mutation
/// (unlink/rmdir/rename) and metadata (setattr/ioctl), but a root caller
/// could still `open(O_WRONLY|O_APPEND)` + `write(2)` a protected file —
/// an append/in-place pwrite touches no metadata, so `inode_setattr`
/// never fires. `tee -a admin.pub` thereby injects a `Role::All` key.
///
/// `file_open` fires once per open and carries the resolved write
/// capability in `file->f_mode`, so denying `FMODE_WRITE` opens of a
/// `FS_PROTECT_WRITE` inode blocks the write at the chokepoint. It also
/// forecloses the shared-writable-mmap vector for free: a
/// `MAP_SHARED|PROT_WRITE` mapping requires `FMODE_WRITE` (`do_mmap`
/// returns `-EACCES` otherwise), which this deny refuses. Reads
/// (`FMODE_READ` only — the agent's own O_RDONLY admin.pub load, `cat`,
/// the init system reading a unit) pass through. Routes through the
/// shared `deny_if_protected`, so the FS_GRANT +
/// PROTECTED_PIDS exemptions (the agent's own rename-based rotation /
/// chain-log appends / signed self-upgrade) are inherited, not
/// re-implemented.
#[lsm(hook = "file_open")]
pub fn protected_open_deny(ctx: LsmContext) -> i32 {
    unsafe { try_protected_open_deny(&ctx) }
}

#[inline(always)]
unsafe fn try_protected_open_deny(ctx: &LsmContext) -> i32 {
    // Kernel signature: `int file_open(struct file *file)` (vlen=1,
    // verified on 6.8 — the observe-only `fim_file_open_observe` already
    // attaches here). No prev-retval read.
    let file: *const c_void = ctx.arg(0);
    if file.is_null() {
        return 0;
    }

    // Only write-intent opens can mutate the file; a read-only open
    // matters only for the few READ-protected inodes (external audit
    // EVD-001), matched on the inode number before any map lookup.
    let mode_slot = (file as *const u8).add(off!(FILE_F_MODE_OFFSET)) as *const u32;
    let f_mode = match bpf_probe_read_kernel::<u32>(mode_slot) {
        Ok(m) => m,
        Err(_) => return 0,
    };

    let inode_slot = (file as *const u8).add(off!(FILE_F_INODE_OFFSET)) as *const *const c_void;
    let inode = match bpf_probe_read_kernel::<*const c_void>(inode_slot) {
        Ok(p) => p,
        Err(_) => return 0,
    };
    if f_mode & FMODE_WRITE == 0 {
        if read_protected_ino(inode) && deny_if_protected(FS_OP_READ, inode) {
            return -EPERM;
        }
        return 0;
    }
    if deny_if_protected(FS_OP_WRITE, inode) {
        return -EPERM;
    }
    0
}

/// External audit EVD-001: `inode`'s number is one of
/// [`READ_PROTECTED_INOS`] (the device is checked by the map lookup after).
#[inline(always)]
unsafe fn read_protected_ino(inode: *const c_void) -> bool {
    if inode.is_null() {
        return false;
    }
    let ino = match bpf_probe_read_kernel::<u64>((inode as *const u8).add(off!(INODE_I_INO_OFFSET)) as *const u64) {
        Ok(i) => i,
        Err(_) => return false,
    };
    let mut slot = 0u32;
    while slot < READ_PROTECTED_SLOTS {
        if let Some(v) = READ_PROTECTED_INOS.get(slot) {
            if *v != 0 && *v == ino {
                return true;
            }
        }
        slot += 1;
    }
    false
}

// ---------------------------------------------------------------------------
// External audit EBPF-015: new entries and extended attributes
// ---------------------------------------------------------------------------
//
// The hooks above refuse removing or changing an entry of a protected
// directory, not adding one: root could drop a file, a link, a symlink, a
// device node or a subdirectory into `/etc/northnarrow`, the state
// directory, the unit drop-in directory or the pin root, and change the
// extended attributes of any protected inode. One program per hook, each
// one map lookup like `inode_unlink`: nothing here loops.
//
// Argument positions, the same on 5.15, 6.1 and 6.8 (and 6.18):
// `inode_create`, `inode_mkdir`, `inode_mknod`, `inode_symlink` take the
// parent directory first; `inode_link` is `(old_dentry, dir, new_dentry)`;
// `inode_setxattr` / `inode_removexattr` (5.12+) and `inode_set_acl` /
// `inode_remove_acl` (6.2+) take a `user_namespace` / `mnt_idmap` first,
// then the dentry, then the attribute name.

/// A new entry in `dir`: refused when `dir` carries `FS_PROTECT_NOCREATE`
/// (the agent's own directories only), outside the trusted-installer
/// window, for a caller outside the agent's family.
#[inline(always)]
unsafe fn deny_new_entry(operation: u8, dir: *const c_void) -> i32 {
    if deny_if_protected(operation, dir) {
        -EPERM
    } else {
        0
    }
}

/// `open(O_CREAT)`, `creat(2)`, `mknod(S_IFREG)`, a bpffs pin
/// (`vfs_mkobj`). Kernel signature: `(dir, dentry, mode)`.
#[lsm(hook = "inode_create")]
pub fn protected_create_deny(ctx: LsmContext) -> i32 {
    unsafe { deny_new_entry(FS_OP_CREATE, ctx.arg(0)) }
}

/// Kernel signature: `(dir, dentry, mode)`.
#[lsm(hook = "inode_mkdir")]
pub fn protected_mkdir_deny(ctx: LsmContext) -> i32 {
    unsafe { deny_new_entry(FS_OP_MKDIR, ctx.arg(0)) }
}

/// A device node, FIFO or socket. Kernel signature: `(dir, dentry, mode,
/// dev)`.
#[lsm(hook = "inode_mknod")]
pub fn protected_mknod_deny(ctx: LsmContext) -> i32 {
    unsafe { deny_new_entry(FS_OP_MKNOD, ctx.arg(0)) }
}

/// Kernel signature: `(dir, dentry, old_name)`.
#[lsm(hook = "inode_symlink")]
pub fn protected_symlink_deny(ctx: LsmContext) -> i32 {
    unsafe { deny_new_entry(FS_OP_SYMLINK, ctx.arg(0)) }
}

/// A hard link made in a NOCREATE directory — also the way an `O_TMPFILE`
/// file (which no create hook sees) would get a name there. Kernel
/// signature: `(old_dentry, dir, new_dentry)`. The source is not checked:
/// the denies are keyed by inode, so a protected file linked elsewhere is
/// as protected under its new name, and refusing it would only turn a
/// backup's or a deduplicator's link into a COMBAT trigger.
#[lsm(hook = "inode_link")]
pub fn protected_link_deny(ctx: LsmContext) -> i32 {
    unsafe { deny_new_entry(FS_OP_LINK, ctx.arg(1)) }
}

/// `security.selinux` with its terminator, as the three words a
/// zero-filled 24-byte buffer holds once the name is read into it.
const XATTR_SELINUX: [u64; 3] = [
    u64::from_le_bytes(*b"security"),
    u64::from_le_bytes(*b".selinux"),
    0,
];

/// Argument `i` of the hook, read from the context's argument array
/// without the verifier's BTF typing (the `const char *name` argument; see
/// `open_sensor::raw_arg`).
#[inline(always)]
unsafe fn raw_arg(ctx: &LsmContext, i: usize) -> u64 {
    let args = ctx.as_ptr() as *const u64;
    bpf_probe_read_kernel(args.add(i)).unwrap_or(0)
}

/// Whether the attribute `name` is exactly `security.selinux` — the one
/// attribute left writable, so `restorecon` / `setfiles` (and rpm's
/// labelling) relabel the agent's files on an SELinux host. A longer name
/// leaves a non-zero byte in the third word; an unreadable one is not
/// SELinux's.
#[inline(always)]
unsafe fn xattr_is_selinux(name: u64) -> bool {
    if name == 0 {
        return false;
    }
    let mut buf = [0u64; 3];
    let bytes = core::slice::from_raw_parts_mut(buf.as_mut_ptr() as *mut u8, 24);
    if bpf_probe_read_kernel_str_bytes(name as *const u8, bytes).is_err() {
        return false;
    }
    buf[0] == XATTR_SELINUX[0] && buf[1] == XATTR_SELINUX[1] && buf[2] == XATTR_SELINUX[2]
}

/// An extended attribute set, removed or (6.2+) an ACL changed on a
/// protected inode: arg 1 is the dentry, arg 2 the attribute name.
#[inline(always)]
unsafe fn deny_xattr(ctx: &LsmContext) -> i32 {
    let dentry: *const c_void = ctx.arg(1);
    let inode = match inode_from_dentry(dentry) {
        Some(i) => i,
        None => return 0,
    };
    if xattr_is_selinux(raw_arg(ctx, 2)) {
        return 0;
    }
    if deny_if_protected(FS_OP_XATTR, inode) {
        return -EPERM;
    }
    0
}

/// Kernel signature: `(mnt_userns | idmap, dentry, name, value, size,
/// flags)`. On 5.15 and 6.1 a POSIX ACL (`setfacl`) comes this way too, as
/// `system.posix_acl_*`.
#[lsm(hook = "inode_setxattr")]
pub fn protected_setxattr_deny(ctx: LsmContext) -> i32 {
    unsafe { deny_xattr(&ctx) }
}

/// Kernel signature: `(mnt_userns | idmap, dentry, name)`.
#[lsm(hook = "inode_removexattr")]
pub fn protected_removexattr_deny(ctx: LsmContext) -> i32 {
    unsafe { deny_xattr(&ctx) }
}

/// 6.2+: a POSIX ACL no longer passes `inode_setxattr`. Kernel signature:
/// `(idmap, dentry, acl_name, kacl)`. Attached only where the kernel has
/// the hook.
#[lsm(hook = "inode_set_acl")]
pub fn protected_set_acl_deny(ctx: LsmContext) -> i32 {
    unsafe { deny_xattr(&ctx) }
}

/// 6.2+. Kernel signature: `(idmap, dentry, acl_name)`.
#[lsm(hook = "inode_remove_acl")]
pub fn protected_remove_acl_deny(ctx: LsmContext) -> i32 {
    unsafe { deny_xattr(&ctx) }
}
