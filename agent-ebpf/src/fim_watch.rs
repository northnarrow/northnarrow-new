//! Tappa 9 (C2) — File Integrity Monitoring (FIM) observation
//! BPF-LSM hooks.
//!
//! Six observation-only BPF-LSM programs (design §5.1) that watch
//! file-mutation paths against the userland-populated
//! [`WATCHED_PATHS`] map. On hit, each program emits one
//! [`FimDriftRaw`] record into the [`FS_FIM_EVENTS`] ringbuf for
//! the userland drain loop (C4) to decode + diff against the
//! baseline DB (C3) + classify via the C5 rule engine.
//!
//! **Observation only — NEVER returns `-EPERM`.** The Tappa 7
//! task 5 deny path (`inode_protect.rs`) is the existing
//! prevention layer for the few inodes in `PROTECTED_INODES`;
//! Tappa 9 is the much-broader DETECTION layer (~100 V1.0
//! curated paths + future operator additions). The two map
//! sets are distinct; a path can be in either, both, or
//! neither, and the two programs that share a hook never
//! disagree (deny returns `-EPERM`, observe always returns 0).
//!
//! ## Hooks
//!
//! | Program | LSM hook | Trigger | `FimOp` |
//! |---|---|---|---|
//! | [`fim_setattr_observe`] | `inode_setattr` | chmod/chown/truncate | `Modified` |
//! | [`fim_create_observe`] | `inode_create` | new file in watched dir | `Created` |
//! | [`fim_unlink_observe`] | `inode_unlink` | `rm` | `Deleted` |
//! | [`fim_rename_observe`] | `inode_rename` | `mv` | `Renamed` |
//! | [`fim_link_observe`] | `inode_link` | hardlink creation (Q2 evasion-detection) | `Linked` |
//! | [`fim_file_open_observe`] | `file_open` | open of a watched inode (any access mode) | `Opened` |
//!
//! **C5.2 closes the C2-deferred sixth program** — the
//! `FILE_F_FLAGS_OFFSET = 72` BTF offset is now validated on
//! the target kernel (Ubuntu 24.04.x / 6.8.x) via
//! `bpftool btf dump file /sys/kernel/btf/vmlinux format raw`.
//! V1.0 emits on EVERY open of a watched inode rather than
//! filtering by access mode in BPF — the WATCHED_PATHS set is
//! operator-curated (~100 paths) so the volume is bounded, and
//! userland C5.3 cred-read rules (NN-L-FIM-011..014)
//! classify by path-vs-access semantics that the BPF layer
//! couldn't express anyway. The `FILE_F_FLAGS_OFFSET` constant
//! remains validated + checked in for future read/write-tier
//! split rules.
//!
//! ## Caller-side exemption (PHASE_D_002 symmetric)
//!
//! Every program checks the calling task's tgid against the
//! shared [`crate::task_kill::PROTECTED_PIDS`] map before
//! emitting. In-family processes (agent + watchdog per W6) are
//! exempted — the agent's own audit-log writes, B3 rotate-keys
//! rewrites, and C3 baseline rehash file-opens all originate
//! from a protected PID and would otherwise generate spurious
//! drift events. Every other root caller (including a malicious
//! one) is observed normally.
//!
//! ## Resource budget (per design §5.2 + §13 Q3 resolution)
//!
//! - `WATCHED_PATHS` capacity: **8192** entries (bumped from the
//!   initial 4096 estimate per Q1 + Q3 + Q7 cross-cutting —
//!   ~100 curated base + ~10 Q1 symlink-target rows + headroom
//!   for Q7 per-deployment `add:` lists + Q3 V1.1 recursive
//!   opt-in).
//! - `FS_FIM_EVENTS` ringbuf: 256 KiB
//!   (~4680 [`FimDriftRaw`] records at 56 bytes each — drift is
//!   bursty under package upgrades, ringbuf is deliberately
//!   larger than the Tappa 7 deny ringbuf).
//! - Per-program verifier complexity: ~50 instructions (lookup
//!   + caller-check + reserve + memcpy + submit). Well under
//!   aya 0.13's 1M instruction ceiling.

use aya_ebpf::{
    cty::c_void,
    helpers::{
        bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_get_current_uid_gid, bpf_ktime_get_ns,
        bpf_probe_read_kernel,
    },
    macros::{lsm, map},
    maps::{HashMap, RingBuf},
    programs::LsmContext,
};
use northnarrow_common::wire::{
    FimDriftRaw, InodeKey, FIM_OP_CREATED, FIM_OP_DELETED, FIM_OP_LINKED, FIM_OP_MODIFIED,
    FIM_OP_OPENED, FIM_OP_RENAMED,
};

use crate::btf_offsets::{
    DENTRY_D_INODE_OFFSET, FILE_F_INODE_OFFSET, INODE_I_INO_OFFSET, INODE_I_SB_OFFSET,
    SUPER_BLOCK_S_DEV_OFFSET,
};

// ── Maps ────────────────────────────────────────────────────────────

/// Inodes the userland C7 deploy step (and operator
/// `fim-paths.local` overrides per §13 Q7) registers for
/// observation. Value byte is unused — presence is the signal;
/// kept as `u8` to keep each map node tiny.
///
/// Capacity is **8192** (design §5.2 + §13 Q1/Q3/Q7 resolution).
///
/// By-name pinned (Tappa 7 task 6 #2 idiom): the LSM observe
/// programs must read the same kernel map the userland populates
/// across agent restarts. PHASE_D_001 fix applies — the agent
/// must explicitly `ebpf.map_mut("WATCHED_PATHS").pin(<path>)`
/// in its post-load path (C7 wires this).
#[map]
pub static WATCHED_PATHS: HashMap<InodeKey, u8> = HashMap::pinned(8192, 0);

/// Drift-event ringbuffer. 256 KiB ≈ ~4680 [`FimDriftRaw`]
/// records at 56 bytes each. Userland's C4 drain loop polls
/// this via aya's `RingBuf::poll`. If userland is asleep when
/// a burst lands the kernel ringbuf drops events at the tail
/// (best-effort by design per §6.5 rate-limit notes — the
/// audit chain captures events the userland actually saw, not
/// kernel-dropped overflow).
///
/// Pinned by-name so a restarted agent drains the SAME ringbuf
/// instead of a fresh one (same split-brain class as
/// `PROTECTED_INODES`).
#[map]
pub static FS_FIM_EVENTS: RingBuf = RingBuf::pinned(256 * 1024, 0);

// ── Helpers (mirror inode_protect.rs idioms) ────────────────────────

/// Dereference a `*dentry` and return its `d_inode` pointer.
/// Returns `None` if the dentry is null or the inode probe
/// fails; the verifier requires defensive null-check on every
/// kernel pointer read.
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

/// Read `(super_block->s_dev, inode->i_ino)` for the given
/// inode. Same shape userland builds via `stat(2)` + the
/// kernel-form conversion in
/// `agent/src/anti_tamper/filesystem.rs::stat_dev_to_kernel_dev`
/// — both sides agree on the `(dev, ino)` key bytes.
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

/// `true` if `key` is in [`WATCHED_PATHS`].
#[inline(always)]
unsafe fn is_watched(key: &InodeKey) -> bool {
    WATCHED_PATHS.get(key).is_some()
}

/// PHASE_D_002-symmetric caller exemption: `true` if the
/// calling task's tgid is in [`crate::task_kill::PROTECTED_PIDS`].
/// The agent + watchdog are inserted into PROTECTED_PIDS by W6,
/// so their own file modifications (audit log appends,
/// rotate-keys rewrites, baseline rehash file-opens) don't
/// generate spurious drift events. Every other root caller
/// (including a malicious one) is observed normally.
#[inline(always)]
fn caller_is_in_family() -> bool {
    let caller_tgid = (bpf_get_current_pid_tgid() >> 32) as u32;
    unsafe { crate::task_kill::PROTECTED_PIDS.get(&caller_tgid).is_some() }
}

/// Reserve a slot in [`FS_FIM_EVENTS`], populate the
/// [`FimDriftRaw`] fields, submit. Best-effort: silent drop on
/// reservation failure (ringbuf full). Caller has already
/// established `is_watched(key)` and `!caller_is_in_family()`,
/// so we're emitting an event we definitely want.
#[inline(always)]
fn emit_drift(op: u8, key: InodeKey) {
    let mut entry = match FS_FIM_EVENTS.reserve::<FimDriftRaw>(0) {
        Some(e) => e,
        None => return,
    };
    let raw_ptr: *mut FimDriftRaw = entry.as_mut_ptr();
    unsafe {
        // SAFETY: ringbuf reservation gives us exclusive write
        // access to a properly aligned region the size of
        // FimDriftRaw. Zero first so the trailing _pad bytes
        // stay deterministic.
        core::ptr::write_bytes(raw_ptr, 0u8, 1);
        (*raw_ptr).timestamp_ns = bpf_ktime_get_ns();
        let pid_tgid = bpf_get_current_pid_tgid();
        (*raw_ptr).modifier_pid = (pid_tgid >> 32) as u32;
        let uid_gid = bpf_get_current_uid_gid();
        (*raw_ptr).modifier_uid = (uid_gid & 0xFFFF_FFFF) as u32;
        (*raw_ptr).target_dev = key.dev;
        (*raw_ptr).target_ino = key.ino;
        (*raw_ptr).op = op;
        if let Ok(comm) = bpf_get_current_comm() {
            (*raw_ptr).modifier_comm = comm;
        }
    }
    entry.submit(0);
}

/// Standard "should we emit a drift event?" decision used by
/// every program once it has the target inode key. The order
/// is: watched-check (fast-skip the common no-match path)
/// → caller-check (skip in-family). Mirrors
/// `inode_protect.rs::deny_if_protected` but inverted —
/// `true` means "emit"; `false` means "skip silently".
#[inline(always)]
unsafe fn should_emit(target: *const c_void) -> Option<InodeKey> {
    let key = inode_key(target)?;
    if !is_watched(&key) {
        return None;
    }
    if caller_is_in_family() {
        return None;
    }
    Some(key)
}

// ── LSM programs ────────────────────────────────────────────────────

/// `inode_setattr` observation — fires on chmod/chown/truncate
/// of a watched inode. Mapped to `FimOp::Modified` so the C5
/// rules can classify by content-vs-metadata after the C4
/// drain loop re-hashes the file. Note: the userland drain
/// suppresses no-op events (e.g., `touch -t` on an unchanged
/// file generates a hook fire but the SHA-256 matches the
/// baseline) so this hook can fire freely without flooding
/// the decision engine.
#[lsm(hook = "inode_setattr")]
pub fn fim_setattr_observe(ctx: LsmContext) -> i32 {
    unsafe { try_fim_setattr_observe(&ctx) }
}

#[inline(always)]
unsafe fn try_fim_setattr_observe(ctx: &LsmContext) -> i32 {
    // Kernel signature on Ubuntu 6.8: (dentry, iattr). Same
    // shape inode_protect.rs::try_inode_setattr handles.
    let dentry: *const c_void = ctx.arg(0);
    if let Some(inode) = inode_from_dentry(dentry) {
        if let Some(key) = should_emit(inode) {
            emit_drift(FIM_OP_MODIFIED, key);
        }
    }
    0 // observe-only — NEVER return -EPERM
}

/// `inode_create` observation — fires on creation of a new
/// file in a watched directory inode (the PARENT is what gets
/// matched against WATCHED_PATHS, not the not-yet-created
/// child). Maps to `FimOp::Created`. Catches the
/// drop-a-backdoor attack: `cp /tmp/.x /usr/local/bin/` fires
/// when `/usr/local/bin/` is in WATCHED_PATHS.
#[lsm(hook = "inode_create")]
pub fn fim_create_observe(ctx: LsmContext) -> i32 {
    unsafe { try_fim_create_observe(&ctx) }
}

#[inline(always)]
unsafe fn try_fim_create_observe(ctx: &LsmContext) -> i32 {
    // Kernel signature: (dir, dentry, mode). The DIR (arg 0)
    // is the parent inode we watch; the dentry is the
    // not-yet-created child.
    let dir: *const c_void = ctx.arg(0);
    if let Some(key) = should_emit(dir) {
        emit_drift(FIM_OP_CREATED, key);
    }
    0
}

/// `inode_unlink` observation — fires on `rm` of a watched
/// inode. Mapped to `FimOp::Deleted`. NN-L-FIM-005 (log
/// truncation) and NN-L-FIM-003 (sensitive config) both
/// consume this op to detect attacker cover-tracks behaviour.
#[lsm(hook = "inode_unlink")]
pub fn fim_unlink_observe(ctx: LsmContext) -> i32 {
    unsafe { try_fim_unlink_observe(&ctx) }
}

#[inline(always)]
unsafe fn try_fim_unlink_observe(ctx: &LsmContext) -> i32 {
    // Kernel signature: (parent dir, target dentry).
    // Either the parent dir OR the target inode being in
    // WATCHED_PATHS is a hit — `rm` of a watched file fires
    // both if both are registered; the C4 drain dedups by
    // (target_dev, target_ino, timestamp_ns) before chaining
    // into fim_drift.jsonl.
    let parent: *const c_void = ctx.arg(0);
    if let Some(key) = should_emit(parent) {
        emit_drift(FIM_OP_DELETED, key);
    }
    let dentry: *const c_void = ctx.arg(1);
    if let Some(target_inode) = inode_from_dentry(dentry) {
        if let Some(key) = should_emit(target_inode) {
            emit_drift(FIM_OP_DELETED, key);
        }
    }
    0
}

/// `inode_rename` observation — fires on `mv` involving a
/// watched inode (either side). Mapped to `FimOp::Renamed`.
/// The C5 NN-L-FIM-002 (new SUID binary) rule also consumes
/// rename events on the destination side.
#[lsm(hook = "inode_rename")]
pub fn fim_rename_observe(ctx: LsmContext) -> i32 {
    unsafe { try_fim_rename_observe(&ctx) }
}

#[inline(always)]
unsafe fn try_fim_rename_observe(ctx: &LsmContext) -> i32 {
    // Kernel signature: (old_dir, old_dentry, new_dir,
    // new_dentry). Four inodes to check — userland C4 dedups
    // by (target_dev, target_ino, timestamp_ns) so duplicate
    // emissions for the same rename don't flood the drift
    // chain.
    let old_dir: *const c_void = ctx.arg(0);
    if let Some(key) = should_emit(old_dir) {
        emit_drift(FIM_OP_RENAMED, key);
    }
    let new_dir: *const c_void = ctx.arg(2);
    if let Some(key) = should_emit(new_dir) {
        emit_drift(FIM_OP_RENAMED, key);
    }
    let old_dentry: *const c_void = ctx.arg(1);
    if let Some(old_inode) = inode_from_dentry(old_dentry) {
        if let Some(key) = should_emit(old_inode) {
            emit_drift(FIM_OP_RENAMED, key);
        }
    }
    let new_dentry: *const c_void = ctx.arg(3);
    if let Some(new_inode) = inode_from_dentry(new_dentry) {
        if let Some(key) = should_emit(new_inode) {
            emit_drift(FIM_OP_RENAMED, key);
        }
    }
    0
}

/// `inode_link` observation — fires on hardlink creation
/// involving a watched inode (the SOURCE inode being watched
/// — a new link to a watched file is the signal). Mapped to
/// `FimOp::Linked`. This is the §13 Q2 evasion-detection
/// path: an attacker creating `/tmp/.x` as a hardlink to
/// `/usr/bin/sudo` fires here when `/usr/bin/sudo` is in
/// WATCHED_PATHS. NN-L-FIM-002 then classifies based on the
/// new-link path (user-writable directories trip Critical).
#[lsm(hook = "inode_link")]
pub fn fim_link_observe(ctx: LsmContext) -> i32 {
    unsafe { try_fim_link_observe(&ctx) }
}

#[inline(always)]
unsafe fn try_fim_link_observe(ctx: &LsmContext) -> i32 {
    // Kernel signature: (old_dentry, new_dir, new_dentry).
    // The OLD dentry points at the source inode (the watched
    // file). The NEW dir is the parent of where the link is
    // being created — userland C4 resolves the new link's
    // absolute path from /proc/<modifier_pid>/cwd + the call's
    // path arg (best-effort; if path resolution fails, the
    // event still fires with the source key — operators see
    // "hardlink to /usr/bin/sudo created by uid=… pid=…").
    let old_dentry: *const c_void = ctx.arg(0);
    if let Some(src_inode) = inode_from_dentry(old_dentry) {
        if let Some(key) = should_emit(src_inode) {
            emit_drift(FIM_OP_LINKED, key);
        }
    }
    // Also check the NEW DIR — a hardlink created INTO a
    // watched directory (e.g., `ln /etc/passwd /watched-dir/x`)
    // is the symmetric case worth observing.
    let new_dir: *const c_void = ctx.arg(1);
    if let Some(key) = should_emit(new_dir) {
        emit_drift(FIM_OP_LINKED, key);
    }
    0
}

/// `file_open` observation — fires on EVERY open of a watched
/// inode (any access mode). Mapped to `FimOp::Opened`.
/// `struct file::f_inode` is the resolved target inode pointer
/// (offset 168, validated via the existing `FILE_F_INODE_OFFSET`
/// constant), so no dentry-chase is needed.
///
/// **Access-mode filter deliberately omitted at the BPF layer**:
/// C5.2 chose to emit on every open of a watched inode rather
/// than fast-skip read-only at the kernel side. The WATCHED_PATHS
/// set is operator-curated (~100 paths in the V1.0 default
/// `fim-paths.v1`) so the volume is bounded; userland C5.3 rules
/// (NN-L-FIM-011..014 cloud-credentials-read family) classify
/// by path-vs-access semantics that the BPF layer can't express
/// anyway. The validated `crate::btf_offsets::FILE_F_FLAGS_OFFSET`
/// constant remains checked in for future read/write-tier rules.
#[lsm(hook = "file_open")]
pub fn fim_file_open_observe(ctx: LsmContext) -> i32 {
    unsafe { try_fim_file_open_observe(&ctx) }
}

#[inline(always)]
unsafe fn try_fim_file_open_observe(ctx: &LsmContext) -> i32 {
    // Kernel signature: (file).
    let file: *const c_void = ctx.arg(0);
    if file.is_null() {
        return 0;
    }
    let inode_slot = (file as *const u8).add(FILE_F_INODE_OFFSET) as *const *const c_void;
    let inode = match bpf_probe_read_kernel::<*const c_void>(inode_slot) {
        Ok(p) => p,
        Err(_) => return 0,
    };
    if let Some(key) = should_emit(inode) {
        emit_drift(FIM_OP_OPENED, key);
    }
    0
}
