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
//! | [`fim_create_observe`] | `inode_create` | new file in watched dir (carries child leaf, BUG-022) | `Created` |
//! | [`fim_unlink_observe`] | `inode_unlink` | `rm` | `Deleted` |
//! | [`fim_rename_observe`] | `inode_rename` | `mv` (carries dest leaf on into-dir drops, BUG-022) | `Renamed` |
//! | [`fim_link_observe`] | `inode_link` | hardlink creation (Q2 evasion-detection) | `Linked` |
//! | [`fim_file_open_observe`] | `file_open` | open of a watched inode (any access mode) | `Opened` |
//! | [`fim_write_intent_observe`] | `file_permission` | write (`MAY_WRITE`) to a watched inode — sets a dirty mark, no event (BUG-023) | — |
//! | [`fim_close_emit_observe`] | `file_free_security` | close of a written watched inode — emits the deferred event (BUG-023) | `Modified` |
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
        bpf_probe_read_kernel, bpf_probe_read_kernel_str_bytes,
    },
    macros::{lsm, map},
    maps::{HashMap, RingBuf},
    programs::LsmContext,
};
use northnarrow_common::wire::{
    FimDriftRaw, InodeKey, FIM_CHILD_NAME_LEN, FIM_CHILD_TRUNCATED, FIM_OP_CREATED, FIM_OP_DELETED,
    FIM_OP_LINKED, FIM_OP_MODIFIED, FIM_OP_OPENED, FIM_OP_RENAMED, TASK_COMM_LEN,
};

use crate::btf_offsets::{
    DENTRY_D_INODE_OFFSET, DENTRY_D_NAME_OFFSET, FILE_F_INODE_OFFSET, INODE_I_INO_OFFSET,
    INODE_I_SB_OFFSET, QSTR_LEN_OFFSET, QSTR_NAME_OFFSET, SUPER_BLOCK_S_DEV_OFFSET,
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

/// Drift-event ringbuffer. 256 KiB ≈ ~3640 [`FimDriftRaw`]
/// records at 72 bytes each. Userland's C4 drain loop polls
/// this via aya's `RingBuf::poll`. If userland is asleep when
/// a burst lands the kernel ringbuf drops events at the tail
/// (best-effort by design per §6.5 rate-limit notes — the
/// audit chain captures events the userland actually saw, not
/// kernel-dropped overflow).
///
/// PROCESS-LOCAL (NOT pinned). A BPF ringbuf carries its
/// consumer/producer position counters + data pages inside the
/// kernel map object itself. Pinning + reusing it across an
/// agent restart hands the new process a ring whose position
/// state was left by the dead process; the new process's fresh
/// `RingBuf` consumer desyncs from that state and decodes every
/// record header as 0-length → a `FimDriftRaw` `expected=72
/// got=0` SizeMismatch flood, i.e. total FIM blindness on
/// `systemctl restart` (a reboot is fine — bpffs is wiped).
/// Unlike the anti-tamper STATE maps (`PROTECTED_INODES` etc.)
/// a ringbuf holds NO cross-restart state worth persisting, and
/// the FIM observe programs that write it are transient
/// (re-attached fresh each boot — `agent/src/fim/attach.rs`), so
/// a fresh ring + fresh program + fresh consumer always align.
/// Keep it unpinned.
#[map]
pub static FS_FIM_EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

/// `MAY_WRITE` from `include/linux/fs.h` — the `mask` bit the
/// `file_permission` LSM hook carries for a write access
/// (`MAY_EXEC=1`, `MAY_WRITE=2`, `MAY_READ=4`). The BUG-023
/// write-intent hook gates on it so reads are skipped before any
/// kernel-pointer work.
const MAY_WRITE: i32 = 0x2;

/// Tappa 9 (BUG-023) — per-inode "written since last close" marker
/// plus the WRITER's identity, captured at write-intent time by
/// [`fim_write_intent_observe`] and consumed by
/// [`fim_close_emit_observe`]. Carrying the writer (not the closer)
/// is essential: NN-L-FIM-003/004 are KillProcess rules, so the
/// emitted `FimOp::Modified` must name the process that changed the
/// bytes, not whoever happened to close the fd last.
///
/// **Multi-writer attribution is LAST-WRITE-WINS.** If several distinct
/// non-family writers modify the same watched inode before it is
/// closed, each write-intent `insert` overwrites the mark, so the
/// single `Modified` emitted at close names the LAST writer to touch
/// it. This is a deliberate fidelity limit: every candidate is a
/// non-family writer, so detection still fires; only the KillProcess
/// target could be one of several concurrent attackers (and the audit
/// chain still records the event regardless). Family writers NEVER set
/// or overwrite the mark — `should_emit` excludes them at write-intent
/// — so a legitimate agent/watchdog write cannot clobber an attacker's
/// already-recorded attribution, nor manufacture a spurious one.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct DirtyMeta {
    pub pid: u32,
    pub uid: u32,
    pub comm: [u8; TASK_COMM_LEN],
}

/// Inodes written-but-not-yet-closed (BUG-023 write-then-close).
/// PROCESS-LOCAL (NOT pinned): purely per-boot transient state, same
/// rationale as [`FS_FIM_EVENTS`] — a restart starts clean (any
/// in-flight write re-marks on its next `write()`). Sized for the
/// count of watched files concurrently open for write, which is
/// tiny; 4096 is generous headroom.
#[map]
pub static FIM_DIRTY_INODES: HashMap<InodeKey, DirtyMeta> = HashMap::with_max_entries(4096, 0);

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
    emit_drift_with_dest(op, key, None);
}

/// Polish #3 — variant of [`emit_drift`] that also writes the
/// rename DEST `(dev, ino)` pair. Userland's drain resolves
/// `(dest_dev, dest_ino)` against the `InodePathMap` and
/// populates `FimEvent::dest_path` on success; the NN-L-FIM-010
/// rule then matches the ransomware extension on EITHER side.
/// `dest_key: None` writes zeroes (matches the C8 behaviour
/// for non-Rename ops).
#[inline(always)]
fn emit_drift_with_dest(op: u8, key: InodeKey, dest_key: Option<InodeKey>) {
    let mut entry = match FS_FIM_EVENTS.reserve::<FimDriftRaw>(0) {
        Some(e) => e,
        None => return,
    };
    let raw_ptr: *mut FimDriftRaw = entry.as_mut_ptr();
    unsafe {
        // SAFETY: ringbuf reservation gives us exclusive write
        // access to a properly aligned region the size of
        // FimDriftRaw. Zero first so the trailing _pad bytes
        // (and dest pair, when dest_key is None) stay
        // deterministic.
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
        if let Some(dest) = dest_key {
            (*raw_ptr).dest_dev = dest.dev;
            (*raw_ptr).dest_ino = dest.ino;
        }
    }
    entry.submit(0);
}

/// Tappa 9 (BUG-022) — emit variant that also captures the leaf name
/// of the child created in / renamed into a watched directory. The
/// standard fields (ts, modifier triple, target key, op) are the
/// creating/renaming caller's — correct attribution, since the
/// dropper IS the current task. Userland reconstructs
/// `dir + "/" + child_name` so the child-prefix rules can match.
#[inline(always)]
fn emit_drift_with_child(op: u8, key: InodeKey, child_dentry: *const c_void) {
    let mut entry = match FS_FIM_EVENTS.reserve::<FimDriftRaw>(0) {
        Some(e) => e,
        None => return,
    };
    let raw_ptr: *mut FimDriftRaw = entry.as_mut_ptr();
    unsafe {
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
        let flags = read_child_leaf(child_dentry, &mut (*raw_ptr).child_name);
        (*raw_ptr).child_name_flags = flags;
    }
    entry.submit(0);
}

/// Tappa 9 (BUG-023) — emit a `FimOp::Modified` for a watched inode
/// that was written and is now closing, using the WRITER's stored
/// identity (`meta`) rather than the closer's. No child name.
#[inline(always)]
fn emit_drift_close(key: InodeKey, meta: DirtyMeta) {
    let mut entry = match FS_FIM_EVENTS.reserve::<FimDriftRaw>(0) {
        Some(e) => e,
        None => return,
    };
    let raw_ptr: *mut FimDriftRaw = entry.as_mut_ptr();
    unsafe {
        core::ptr::write_bytes(raw_ptr, 0u8, 1);
        (*raw_ptr).timestamp_ns = bpf_ktime_get_ns();
        (*raw_ptr).modifier_pid = meta.pid;
        (*raw_ptr).modifier_uid = meta.uid;
        (*raw_ptr).modifier_comm = meta.comm;
        (*raw_ptr).target_dev = key.dev;
        (*raw_ptr).target_ino = key.ino;
        (*raw_ptr).op = FIM_OP_MODIFIED;
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

/// Dereference a `*file` and return its `f_inode` pointer (the
/// resolved target inode). Mirrors the read in
/// [`try_fim_file_open_observe`]; factored out for the BUG-023
/// write-intent + close hooks. `None` on null / probe failure.
#[inline(always)]
unsafe fn inode_from_file(file: *const c_void) -> Option<*const c_void> {
    if file.is_null() {
        return None;
    }
    let inode_slot = (file as *const u8).add(FILE_F_INODE_OFFSET) as *const *const c_void;
    match bpf_probe_read_kernel::<*const c_void>(inode_slot) {
        Ok(p) if !p.is_null() => Some(p),
        _ => None,
    }
}

/// Tappa 9 (BUG-022) — read the leaf name out of a child `*dentry`
/// (`dentry->d_name`, a `struct qstr`) into `dst`, NUL-terminated,
/// and return the child-name flag byte ([`FIM_CHILD_TRUNCATED`] when
/// the true leaf length overflows `dst`). Fails SAFE: on any
/// null/probe error it leaves `dst` as the caller zeroed it and
/// returns 0, so a wrong BTF offset degrades to "no child leaf"
/// (userland keeps the bare-dir path) rather than emitting garbage.
#[inline(always)]
unsafe fn read_child_leaf(child_dentry: *const c_void, dst: &mut [u8; FIM_CHILD_NAME_LEN]) -> u8 {
    if child_dentry.is_null() {
        return 0;
    }
    let name_ptr_slot = (child_dentry as *const u8)
        .add(DENTRY_D_NAME_OFFSET + QSTR_NAME_OFFSET)
        as *const *const u8;
    let name_ptr = match bpf_probe_read_kernel::<*const u8>(name_ptr_slot) {
        Ok(p) if !p.is_null() => p,
        _ => return 0,
    };
    // Best-effort NUL-terminated leaf copy, truncated to the buffer.
    if bpf_probe_read_kernel_str_bytes(name_ptr, &mut dst[..]).is_err() {
        return 0;
    }
    // Truncation: a leaf whose true length (excl. NUL) doesn't fit the
    // buffer sets the flag so userland rules don't lose a suffix.
    let len_slot =
        (child_dentry as *const u8).add(DENTRY_D_NAME_OFFSET + QSTR_LEN_OFFSET) as *const u32;
    let true_len = bpf_probe_read_kernel::<u32>(len_slot).unwrap_or(0) as usize;
    if true_len >= FIM_CHILD_NAME_LEN {
        FIM_CHILD_TRUNCATED
    } else {
        0
    }
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
    // is the parent inode we watch; the dentry (arg 1) is the
    // not-yet-created child whose leaf name BUG-022 carries to
    // userland so the child-prefix rules (FIM-007/008/009/021/023)
    // can match instead of seeing only the bare watched-dir path.
    let dir: *const c_void = ctx.arg(0);
    if let Some(key) = should_emit(dir) {
        let child_dentry: *const c_void = ctx.arg(1);
        emit_drift_with_child(FIM_OP_CREATED, key, child_dentry);
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
    //
    // Polish #3 — when the OLD dentry's inode is watched, emit
    // a single combined event with `dest_dev` + `dest_ino` set
    // to the NEW dir's inode key. Userland's drain resolves the
    // dest key via InodePathMap so NN-L-FIM-010 can match the
    // ransomware extension on the destination side. The OTHER
    // three inode-checks (old_dir / new_dir / new_dentry) keep
    // the C8 single-event emit path — dedup by
    // (target_dev, target_ino, timestamp_ns) in userland.
    let old_dentry: *const c_void = ctx.arg(1);
    let new_dir: *const c_void = ctx.arg(2);
    let new_dir_key = inode_key(new_dir);
    let old_inode_opt = inode_from_dentry(old_dentry);
    let mut combined_emitted_for_old_inode = false;
    if let Some(old_inode) = old_inode_opt {
        if let Some(key) = should_emit(old_inode) {
            emit_drift_with_dest(FIM_OP_RENAMED, key, new_dir_key);
            combined_emitted_for_old_inode = true;
        }
    }

    let old_dir: *const c_void = ctx.arg(0);
    if let Some(key) = should_emit(old_dir) {
        emit_drift(FIM_OP_RENAMED, key);
    }
    if let Some(key) = should_emit(new_dir) {
        // BUG-022 — a rename INTO a watched dir is a drop; carry the
        // dest leaf (new_dentry, arg 3) so userland reconstructs the
        // child path and normalizes this to a Created against it.
        let new_dentry_for_child: *const c_void = ctx.arg(3);
        emit_drift_with_child(FIM_OP_RENAMED, key, new_dentry_for_child);
    }
    let _ = combined_emitted_for_old_inode; // verifier-friendly no-op
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

/// `file_permission` (BUG-023 write-intent) — fires on every file
/// read/write permission check. Gates on `MAY_WRITE` and, for a
/// watched non-family writer, sets the per-inode dirty marker with
/// the WRITER's identity. NO event is emitted here: one content edit
/// is many `write()` calls, so emitting per-write would flood; the
/// single event is emitted at close ([`fim_close_emit_observe`]).
/// This is what makes an `O_APPEND` or same-size in-place rewrite
/// observable at all — neither touches metadata, so `inode_setattr`
/// never fires (the BUG-023 root cause).
#[lsm(hook = "file_permission")]
pub fn fim_write_intent_observe(ctx: LsmContext) -> i32 {
    unsafe { try_fim_write_intent_observe(&ctx) }
}

#[inline(always)]
unsafe fn try_fim_write_intent_observe(ctx: &LsmContext) -> i32 {
    // Kernel signature: (file, mask). Skip reads BEFORE any
    // kernel-pointer work — file_permission is a hot path.
    let mask = ctx.arg::<u64>(1) as i32;
    if mask & MAY_WRITE == 0 {
        return 0;
    }
    let file: *const c_void = ctx.arg(0);
    if let Some(inode) = inode_from_file(file) {
        if let Some(key) = should_emit(inode) {
            let pid_tgid = bpf_get_current_pid_tgid();
            let uid_gid = bpf_get_current_uid_gid();
            let mut meta = DirtyMeta {
                pid: (pid_tgid >> 32) as u32,
                uid: (uid_gid & 0xFFFF_FFFF) as u32,
                comm: [0u8; TASK_COMM_LEN],
            };
            if let Ok(comm) = bpf_get_current_comm() {
                meta.comm = comm;
            }
            // Best-effort; last writer wins. Map-full is silently fine.
            let _ = FIM_DIRTY_INODES.insert(&key, &meta, 0);
        }
    }
    0
}

/// `file_free_security` (BUG-023 close-emit) — fires when a file
/// object is released (last fput). If the inode was marked dirty by
/// [`fim_write_intent_observe`], emit ONE `FimOp::Modified` with the
/// stored writer identity and clear the mark. Userland re-hashes and
/// suppresses no-ops, so a write that didn't actually change the
/// bytes (rewriting identical content) yields no drift. No
/// caller-in-family check — the mark was only ever set for a
/// non-family writer; the closer is irrelevant.
///
/// **Close-hook choice is VM-validation-gated** (catalog §21 / the
/// agreed plan): `file_free_security` (this), `__fput`-fexit, and
/// `filp_close`-fexit are the candidates. If this one proves not to
/// fire with a readable `f_inode` on the target kernel, swap the
/// attach point — the emit body ([`emit_drift_close`]) is reused.
#[lsm(hook = "file_free_security")]
pub fn fim_close_emit_observe(ctx: LsmContext) -> i32 {
    unsafe { try_fim_close_emit_observe(&ctx) }
}

#[inline(always)]
unsafe fn try_fim_close_emit_observe(ctx: &LsmContext) -> i32 {
    // Kernel signature: (file).
    let file: *const c_void = ctx.arg(0);
    if let Some(inode) = inode_from_file(file) {
        if let Some(key) = inode_key(inode) {
            if let Some(meta) = FIM_DIRTY_INODES.get(&key) {
                // Copy out so the map borrow ends before remove().
                let meta = *meta;
                emit_drift_close(key, meta);
                let _ = FIM_DIRTY_INODES.remove(&key);
            }
        }
    }
    0
}
