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
//! | `file_ioctl_compat` (6.8+, 6.7.3, 6.6.15, 6.1.76, 5.15.149, 5.10.210) | the same ioctls from a 32-bit process |
//! | `file_open`    | a write-open of a WRITE-protected inode, any open of a READ-protected one |
//! | `inode_create`, `inode_mkdir`, `inode_mknod`, `inode_symlink`, `inode_link` | a new entry in a NOCREATE directory |
//! | `inode_setxattr`, `inode_removexattr` (`inode_set_acl`, `inode_remove_acl` on 6.2+) | an extended attribute or ACL changed on a protected inode |
//!
//! Lot 273: the protected units' cgroups are registered here too — the
//! unit directory (no `rmdir` but PID 1's, no new child, no `chown`), its
//! `cgroup.kill` / `cgroup.freeze` (and the ancestor slices') against a
//! write-open, signed as `cgroup_kill` / `cgroup_freeze`. A protected
//! process moved to another cgroup is `cgroup_guard.rs`'s.
//!
//! Note: `chattr` does NOT go through `inode_setattr` — flag changes
//! travel down the `ioctl(FS_IOC_SETFLAGS)` path, bypassing
//! `notify_change()`. The `file_ioctl` hook is the only correct
//! place to defeat `chattr -i` from BPF-LSM — and, on a kernel that has
//! it, `file_ioctl_compat` for a 32-bit caller (lab PR 174).
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
    maps::{Array, HashMap, LruHashMap, PerCpuArray, RingBuf},
    programs::LsmContext,
    EbpfContext,
};

// Review 56: the zero-arg `bpf_printk!` diagnostic markers of the
// 2026-05 investigation (docs/TAPPA7_TASK5_DEEP_DEBUG.md) are gone.
// `bpf_trace_printk` takes a global lock and writes the trace buffer on
// every call: one per `file_open` and up to five per write-open of the
// whole host, and the kernel's "trace_printk() being used" banner on every
// agent host. Do not put printk back in a hot hook; count in a map instead.

use northnarrow_common::cgroup_limits::same_value;
use northnarrow_common::fail_open::hook;
use northnarrow_common::wire::{
    fs_protect_denied_op, fs_protect_init_may, fs_protect_init_may_open, fs_protect_required,
    fs_protect_thaw_value, FsGrant, FsProtectDenialRaw,
    InodeKey, FS_OP_CREATE, FS_OP_IOCTL,
    FS_OP_LINK, FS_OP_MKDIR, FS_OP_MKNOD, FS_OP_READ, FS_OP_RENAME, FS_OP_RMDIR, FS_OP_SETATTR,
    FS_OP_SYMLINK, FS_OP_UNLINK, FS_OP_WRITE, FS_OP_XATTR, READ_PROTECTED_SLOTS, TASK_COMM_LEN,
};

use crate::btf_offsets::{
    DENTRY_D_INODE_OFFSET, FILE_F_INODE_OFFSET, FILE_F_MODE_OFFSET, INODE_I_INO_OFFSET,
    INODE_I_MODE_OFFSET, INODE_I_SB_OFFSET, INODE_REMOVEXATTR_DENTRY_ARG_SLOT, INODE_SETATTR_DENTRY_ARG_SLOT,
    INODE_SETXATTR_DENTRY_ARG_SLOT, SUPER_BLOCK_S_DEV_OFFSET,
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

/// Lot 302: the tgid of the deny self-test's child while its round runs
/// (0 otherwise), written by the agent around each round
/// (`nn_linux::telemetry_probe::deny::SelfTestMark`). The child is the
/// agent's own binary, spawned and reaped by the agent, so its pid is not
/// another process's before the agent writes 0 again. Its refusals are
/// decided like any caller's — the mark changes no verdict — and recorded
/// outside the denials' budgets ([`ATTEMPT_DENIAL_RATE`], lot 293;
/// [`TASK_DENIAL_RATE`]) and the per-caller dedup: the self-test never
/// takes the room a real attempt's record needs, and a flood that spends
/// the budgets never hides the self-test's own refusals. Per boot, not
/// pinned: an earlier boot's programs never read this boot's mark.
#[map]
pub static SELFTEST_TGID: Array<u32> = Array::with_max_entries(1, 0);

/// Lot 302: the calling process is the deny self-test's child of this
/// round ([`SELFTEST_TGID`]).
#[inline(always)]
pub(crate) fn caller_is_self_test() -> bool {
    let tgid = (bpf_get_current_pid_tgid() >> 32) as u32;
    if tgid == 0 {
        return false;
    }
    matches!(SELFTEST_TGID.get(0), Some(t) if *t == tgid)
}

// ---------------------------------------------------------------------------
// Helpers — common pointer-chase logic for every hook.
// ---------------------------------------------------------------------------

/// Dereference a `*dentry` and return its `d_inode` pointer. `None` for a
/// negative dentry (no inode: the new name of a rename, say), and for a
/// read that failed, which is a fail-open of `hook` (lab PR 215: counted
/// in `DENY_FAIL_OPEN`).
#[inline(always)]
unsafe fn inode_from_dentry(dentry: *const c_void, hook: u32) -> Option<*const c_void> {
    if dentry.is_null() {
        return None;
    }
    let slot = (dentry as *const u8).add(off!(DENTRY_D_INODE_OFFSET)) as *const *const c_void;
    match bpf_probe_read_kernel::<*const c_void>(slot) {
        Ok(p) if !p.is_null() => Some(p),
        Ok(_) => None,
        Err(_) => {
            crate::fail_open::bump(hook);
            None
        }
    }
}

/// Read `(device, inode->i_ino)` for the given inode, the device as
/// `stat(2)` reports it ([`crate::inode_dev::stat_dev`], review 55). A
/// read that fails is a fail-open of `hook` (lab PR 215): the caller lets
/// the operation through without knowing whether the inode is protected.
#[inline(always)]
unsafe fn inode_key(inode: *const c_void, hook: u32) -> Option<InodeKey> {
    if inode.is_null() {
        return None;
    }
    let key = read_inode_key(inode);
    if key.is_none() {
        crate::fail_open::bump(hook);
    }
    key
}

/// [`inode_key`]'s reads: `None` when one fails (or the inode has no
/// superblock, which no live inode lacks).
#[inline(always)]
pub(crate) unsafe fn read_inode_key(inode: *const c_void) -> Option<InodeKey> {
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

/// Budget for task-denial records, per CPU: `[window start (ns), records
/// in the window]`. A loop of fresh `/bin/kill` processes defeats the
/// per-caller dedup; this caps it at [`TASK_DENIAL_PER_SEC`] per CPU so
/// the denial ring cannot be used to bury other evidence.
///
/// External audit EBPF-017: it was one global `Array<u64>` read, changed
/// and written from every CPU (updates lost under a burst), and a record
/// over budget left no trace. Per CPU, each program owns its slot while it
/// runs; a record held back is counted in `RING_DROPS`
/// (`ring_slot::TASK_DENIAL_RATE`), which the agent reports in the journal,
/// in a signed `ringbuf_drop` entry and, past the threshold, as telemetry
/// loss. The deny never depends on the record. On N CPUs at most
/// 50 × N records a second reach the 64 KiB ring.
#[map]
static TASK_DENIAL_RATE: PerCpuArray<[u64; 2]> = PerCpuArray::with_max_entries(1, 0);

const TASK_DENIAL_PER_SEC: u64 = 50;
const TASK_DENIAL_DEDUP_NS: u64 = 1_000_000_000;
/// The budget's window.
const TASK_DENIAL_WINDOW_NS: u64 = 1_000_000_000;

/// Lot 293 (external bug hunt BUG37): the budget of the refusals signed at
/// every attempt — [`deny_if_protected`]'s, the write-open deny's, a
/// protected cgroup file's open — per CPU: `[window start
/// (ns), records in the window]`. They had none: a root loop of `rm` on a
/// protected file filled the 64 KiB ring and every other denial record
/// (a refused `kill`, a refused ptrace) was lost with it. A budget of its
/// own, apart from [`TASK_DENIAL_RATE`]: such a loop never takes the task
/// denials' room. No dedup by caller: each refused attempt of a process is
/// recorded until its CPU's budget is spent; one held back is counted in
/// `RING_DROPS` (`ring_slot::DENIAL_RATE`), signed and, past the
/// threshold, telemetry loss. The deny never depends on the record.
#[map]
static ATTEMPT_DENIAL_RATE: PerCpuArray<[u64; 2]> = PerCpuArray::with_max_entries(1, 0);

const ATTEMPT_DENIAL_PER_SEC: u64 = 50;

/// Lot 293: whether this CPU's attempt budget ([`ATTEMPT_DENIAL_RATE`])
/// has room for one more record, taking it; a record over it is counted
/// (`ring_slot::DENIAL_RATE`) and must not be written.
#[inline(always)]
pub(crate) fn attempt_budget() -> bool {
    let Some(rate) = ATTEMPT_DENIAL_RATE.get_ptr_mut(0) else {
        return false;
    };
    let now = unsafe { bpf_ktime_get_ns() };
    unsafe {
        // SAFETY: this CPU's slot, owned by the program while it runs.
        if now.wrapping_sub((*rate)[0]) >= TASK_DENIAL_WINDOW_NS {
            (*rate)[0] = now;
            (*rate)[1] = 0;
        }
        if (*rate)[1] >= ATTEMPT_DENIAL_PER_SEC {
            crate::drops::bump(northnarrow_common::ring_drops::ring_slot::DENIAL_RATE);
            return false;
        }
        (*rate)[1] += 1;
    }
    true
}

/// Lot 293: [`emit_denial`] behind the attempt budget ([`attempt_budget`]).
#[inline(always)]
pub(crate) fn emit_attempt(operation: u8, key: InodeKey) {
    // Lot 302: the deny self-test's refusal, outside the budget
    if caller_is_self_test() {
        emit_denial(operation, key);
        return;
    }
    if attempt_budget() {
        emit_denial(operation, key);
    }
}

/// Evidence for a refused signal or ptrace attach on a protected pid
/// (`FS_OP_SIGNAL` / `FS_OP_PTRACE`): same ring and record as the inode
/// denials, `target_ino` = target tgid, `target_dev` = signal or ptrace
/// mode. The deny itself never depends on this record.
#[inline(always)]
pub fn emit_task_denial(operation: u8, detail: u64, target_tgid: u32) {
    emit_limited(
        operation,
        InodeKey {
            dev: detail,
            ino: target_tgid as u64,
        },
    );
}

/// [`emit_denial`] behind the per-caller dedup and the per-CPU budget of
/// the task denials: a signal loop, a move loop, and (lot 273b) a loop of
/// writes on a descriptor of a protected file are one record per caller
/// and operation a second.
#[inline(always)]
pub(crate) fn emit_limited(operation: u8, key: InodeKey) {
    // Lot 302: the deny self-test's refusal, outside the dedup and the
    // budget (it takes no slot of either)
    if caller_is_self_test() {
        emit_denial(operation, key);
        return;
    }
    let now = unsafe { bpf_ktime_get_ns() };
    let caller = (bpf_get_current_pid_tgid() >> 32) as u64;
    let seen = (caller << 8) | operation as u64;
    match TASK_DENIAL_SEEN.get_ptr_mut(&seen) {
        Some(last) => unsafe {
            if now.wrapping_sub(*last) < TASK_DENIAL_DEDUP_NS {
                return;
            }
            *last = now;
        },
        None => {
            let _ = TASK_DENIAL_SEEN.insert(&seen, &now, 0);
        }
    }
    let Some(rate) = TASK_DENIAL_RATE.get_ptr_mut(0) else {
        return;
    };
    unsafe {
        // SAFETY: this CPU's slot, owned by the program while it runs.
        if now.wrapping_sub((*rate)[0]) >= TASK_DENIAL_WINDOW_NS {
            (*rate)[0] = now;
            (*rate)[1] = 0;
        }
        if (*rate)[1] >= TASK_DENIAL_PER_SEC {
            crate::drops::bump(northnarrow_common::ring_drops::ring_slot::TASK_DENIAL_RATE);
            return;
        }
        (*rate)[1] += 1;
    }
    emit_denial(operation, key);
}

/// Lot 280a: a record of the `cgroup/sysctl` program (`crate::
/// sysctl_guard`), on the denials' ring — whose 5.15 helpers include
/// neither `bpf_get_current_pid_tgid` nor `bpf_get_current_comm`: the
/// writer's `tgid` and `comm` are read from its task by the caller. A
/// refusal (`limited`) goes behind the per-caller dedup of
/// [`emit_limited`]; an opt-out's write behind the per-CPU budget only —
/// each one is recorded, a flood is counted as a ring drop.
#[inline(always)]
pub(crate) fn emit_sysctl_record(
    operation: u8,
    key: InodeKey,
    tgid: u32,
    comm: [u8; TASK_COMM_LEN],
    limited: bool,
) {
    let now = unsafe { bpf_ktime_get_ns() };
    if limited {
        let seen = ((tgid as u64) << 8) | operation as u64;
        match TASK_DENIAL_SEEN.get_ptr_mut(&seen) {
            Some(last) => unsafe {
                if now.wrapping_sub(*last) < TASK_DENIAL_DEDUP_NS {
                    return;
                }
                *last = now;
            },
            None => {
                let _ = TASK_DENIAL_SEEN.insert(&seen, &now, 0);
            }
        }
    }
    let Some(rate) = TASK_DENIAL_RATE.get_ptr_mut(0) else {
        return;
    };
    unsafe {
        // SAFETY: this CPU's slot, owned by the program while it runs.
        if now.wrapping_sub((*rate)[0]) >= TASK_DENIAL_WINDOW_NS {
            (*rate)[0] = now;
            (*rate)[1] = 0;
        }
        if (*rate)[1] >= TASK_DENIAL_PER_SEC {
            crate::drops::bump(northnarrow_common::ring_drops::ring_slot::TASK_DENIAL_RATE);
            return;
        }
        (*rate)[1] += 1;
    }
    let mut entry = match FS_PROTECT_EVENTS.reserve::<FsProtectDenialRaw>(0) {
        Some(e) => e,
        None => {
            crate::drops::bump(northnarrow_common::ring_drops::ring_slot::FS_PROTECT);
            return;
        }
    };
    let raw_ptr: *mut FsProtectDenialRaw = entry.as_mut_ptr();
    unsafe {
        // SAFETY: the reservation is exclusive and sized for the record.
        crate::zero::zero(raw_ptr);
        (*raw_ptr).timestamp_ns = now;
        (*raw_ptr).attacker_pid = tgid;
        (*raw_ptr).attacker_uid = (bpf_get_current_uid_gid() & 0xFFFF_FFFF) as u32;
        (*raw_ptr).target_dev = key.dev;
        (*raw_ptr).target_ino = key.ino;
        (*raw_ptr).operation = operation;
        (*raw_ptr).attacker_comm = comm;
    }
    entry.submit(0);
}

/// Best-effort audit record. Silently drops if the ringbuffer is
/// full — the deny verdict still fires.
///
/// Lot 318 (external bug hunt BUG37): private to this module — every
/// other refusal reaches the ring through a budget ([`emit_attempt`],
/// [`emit_limited`], [`emit_task_denial`]; the BPF guard's through
/// `emit_attempt`). `xtask/tests/self_defense.rs` keeps the ring's writers
/// to this function and [`emit_sysctl_record`].
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
/// be blocked; emits the audit record as a side effect. `hook` is the
/// caller's `DENY_FAIL_OPEN` slot (lab PR 215).
#[inline(always)]
unsafe fn deny_if_protected(operation: u8, target: *const c_void, hook: u32) -> bool {
    match protected_verdict(operation, target, hook) {
        Some((op, key)) => {
            emit_attempt(op, key);
            true
        }
        None => false,
    }
}

/// [`deny_if_protected`]'s decision without the record: the operation to
/// sign and the inode when `operation` on `target` must be refused.
#[inline(always)]
unsafe fn protected_verdict(operation: u8, target: *const c_void, hook: u32) -> Option<(u8, InodeKey)> {
    let key = match inode_key(target, hook) {
        Some(k) => k,
        None => {
            return None;
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
            return None;
        }
    };
    let required = fs_protect_required(operation);
    if flags & required == 0 {
        return None;
    }
    if override_active() {
        return None;
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
    // R14a: exempt callers only (the agent and the watchdog); a worker is
    // protected but not exempt, so it is denied the keys and the protected
    // paths as any other process is (plan §3.3).
    let caller_tgid = (bpf_get_current_pid_tgid() >> 32) as u32;
    if crate::task_kill::is_exempt_pid(caller_tgid) {
        return None;
    }
    // Lot 273: PID 1 removes a protected unit's cgroup directory once its
    // processes are gone (the kernel refuses a populated one), and
    // systemd-shutdown trims the tree; nothing else is let through here.
    if fs_protect_init_may(operation, flags, caller_tgid) {
        return None;
    }
    // Lot 273: a refused write-open of a protected `cgroup.kill` or
    // `cgroup.freeze` is signed by what it would have done.
    Some((fs_protect_denied_op(operation, flags), key))
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
    if deny_if_protected(FS_OP_UNLINK, parent, hook::INODE_UNLINK) {
        return -EPERM;
    }
    let dentry: *const c_void = ctx.arg(1);
    if let Some(target_inode) = inode_from_dentry(dentry, hook::INODE_UNLINK) {
        if deny_if_protected(FS_OP_UNLINK, target_inode, hook::INODE_UNLINK) {
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
    // No prev-retval read — see task_kill.rs.
    let parent: *const c_void = ctx.arg(0);
    if deny_if_protected(FS_OP_RMDIR, parent, hook::INODE_RMDIR) {
        return -EPERM;
    }
    let dentry: *const c_void = ctx.arg(1);
    if let Some(target_inode) = inode_from_dentry(dentry, hook::INODE_RMDIR) {
        if deny_if_protected(FS_OP_RMDIR, target_inode, hook::INODE_RMDIR) {
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
    // No prev-retval read — see task_kill.rs for rationale.

    let old_dir: *const c_void = ctx.arg(0);
    if deny_if_protected(FS_OP_RENAME, old_dir, hook::INODE_RENAME) {
        return -EPERM;
    }
    let new_dir: *const c_void = ctx.arg(2);
    if deny_if_protected(FS_OP_RENAME, new_dir, hook::INODE_RENAME) {
        return -EPERM;
    }

    let old_dentry: *const c_void = ctx.arg(1);
    if let Some(old_inode) = inode_from_dentry(old_dentry, hook::INODE_RENAME) {
        if deny_if_protected(FS_OP_RENAME, old_inode, hook::INODE_RENAME) {
            return -EPERM;
        }
    }
    let new_dentry: *const c_void = ctx.arg(3);
    if let Some(new_inode) = inode_from_dentry(new_dentry, hook::INODE_RENAME) {
        if deny_if_protected(FS_OP_RENAME, new_inode, hook::INODE_RENAME) {
            return -EPERM;
        }
    }
    0
}

#[lsm(hook = "inode_setattr")]
pub fn inode_setattr(ctx: LsmContext) -> i32 {
    // chmod / chown / truncate, and `touch` of an existing file
    // (notify_change → security_inode_setattr).
    unsafe { try_inode_setattr(&ctx) }
}

#[inline(always)]
unsafe fn try_inode_setattr(ctx: &LsmContext) -> i32 {
    // The dentry is argument 0 up to 6.8, `(dentry, iattr)`, and argument
    // 1 from 6.9, `(idmap, dentry, iattr)` (lab PR 164): its position
    // comes from the running kernel's prototype. No prev-retval read, see
    // task_kill.rs.
    let dentry = match setattr_dentry(ctx) {
        Some(d) => d,
        None => {
            // Lab PR 215: the dentry's position is not known here (the
            // agent attaches the hook only once it is) or its read failed.
            crate::fail_open::bump(hook::INODE_SETATTR);
            return 0;
        }
    };
    if let Some(target_inode) = inode_from_dentry(dentry, hook::INODE_SETATTR) {
        if deny_if_protected(FS_OP_SETATTR, target_inode, hook::INODE_SETATTR) {
            return -EPERM;
        }
    }
    0
}

/// `inode_setattr`'s `struct dentry *`, read at the position the agent
/// resolved from the running kernel's prototype of `bpf_lsm_inode_setattr`
/// (`INODE_SETATTR_DENTRY_ARG`). `None` when that position is not known:
/// the hook then reads nothing, rather than the `mnt_idmap` a fixed
/// position 0 is on 6.9 and later. Shared with the FIM setattr observer.
/// The read goes through `bpf_probe_read_kernel` because the position is
/// a runtime value (a context load needs a constant offset); the value is
/// bounded below `HOOK_ARG_MAX`.
#[inline(always)]
pub(crate) unsafe fn setattr_dentry(ctx: &LsmContext) -> Option<*const c_void> {
    let i = crate::btf_offsets::hook_arg(INODE_SETATTR_DENTRY_ARG_SLOT)?;
    let dentry = raw_arg(ctx, i) as *const c_void;
    if dentry.is_null() {
        None
    } else {
        Some(dentry)
    }
}

/// Lot 282 (the re-review of #500): `inode_setattr`'s `struct iattr *`,
/// the argument after the dentry ([`setattr_dentry`]'s position, resolved
/// from the running kernel's prototype; below `HOOK_ARG_MAX`, so the
/// next one is a read of the context at most one slot further, through
/// `bpf_probe_read_kernel`). `None` when the position is not known.
#[inline(always)]
pub(crate) unsafe fn setattr_iattr(ctx: &LsmContext) -> Option<*const u8> {
    let i = crate::btf_offsets::hook_arg(INODE_SETATTR_DENTRY_ARG_SLOT)?;
    let iattr = raw_arg(ctx, i + 1) as *const u8;
    if iattr.is_null() {
        None
    } else {
        Some(iattr)
    }
}

#[lsm(hook = "file_ioctl")]
pub fn file_ioctl(ctx: LsmContext) -> i32 {
    unsafe { try_file_ioctl(&ctx, hook::FILE_IOCTL) }
}

/// Lab PR 174: the `ioctl(2)` of a 32-bit process. Since upstream commit
/// f1bb47a31dff ("lsm: new security_file_ioctl_compat() hook", 6.8, and
/// the stable releases 6.7.3, 6.6.15, 6.1.76, 5.15.149 and 5.10.210) the
/// compat `ioctl` syscall calls `security_file_ioctl_compat` instead of
/// `security_file_ioctl`, so the `file_ioctl` deny no longer sees it: a
/// 32-bit `chattr -i` of a protected file went through. Same prototype
/// `(file, cmd, arg)` and the `cmd` as the caller passed it (the
/// `FS_IOC32_*` translation comes after the hook), so the same deny.
/// Attached only where the kernel's BTF has `bpf_lsm_file_ioctl_compat`
/// (an optional deny hook); older kernels route the compat syscall
/// through `file_ioctl`.
#[lsm(hook = "file_ioctl_compat")]
pub fn protected_ioctl_compat_deny(ctx: LsmContext) -> i32 {
    unsafe { try_file_ioctl(&ctx, hook::FILE_IOCTL_COMPAT) }
}

/// The chattr-family deny of `file_ioctl` and `file_ioctl_compat` (`hook`:
/// the caller's `DENY_FAIL_OPEN` slot).
#[inline(always)]
unsafe fn try_file_ioctl(ctx: &LsmContext, hook: u32) -> i32 {
    // Kernel signature of both hooks: (file, cmd, arg). No prev-retval
    // read — see task_kill.rs.
    //
    // Fast path: this hook fires for EVERY ioctl on EVERY fd; anything
    // but the chattr-family commands returns before any read.

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
            crate::fail_open::bump(hook);
            return 0;
        }
    };
    if deny_if_protected(FS_OP_IOCTL, inode, hook) {
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
        Err(_) => {
            crate::fail_open::bump(hook::FILE_OPEN);
            return 0;
        }
    };

    let inode_slot = (file as *const u8).add(off!(FILE_F_INODE_OFFSET)) as *const *const c_void;
    let inode = match bpf_probe_read_kernel::<*const c_void>(inode_slot) {
        Ok(p) => p,
        Err(_) => {
            crate::fail_open::bump(hook::FILE_OPEN);
            return 0;
        }
    };
    if f_mode & FMODE_WRITE == 0 {
        if read_protected_ino(inode) && deny_if_protected(FS_OP_READ, inode, hook::FILE_OPEN) {
            return -EPERM;
        }
        return 0;
    }
    if let Some((op, key)) = protected_verdict(FS_OP_WRITE, inode, hook::FILE_OPEN) {
        // Lot 273b: PID 1's thaw (systemd 254/255 at every start and stop)
        // is judged at its write, by its value.
        if !fs_protect_init_may_open(op, (bpf_get_current_pid_tgid() >> 32) as u32) {
            emit_attempt(op, key);
            return -EPERM;
        }
    }
    // Lot 273b: a protected cgroup's resource file, a cgroup v1 hierarchy,
    // a protected process's `oom_score_adj`.
    if crate::cgroup_files::refuse_write(file, inode, hook::FILE_OPEN, crate::cgroup_files::Phase::Open) {
        return -EPERM;
    }
    0
}

/// Lot 273b — the write deny. `file_open` refuses a write-open of a
/// protected inode; a descriptor opened before the inode was registered
/// (one of `system.slice/cgroup.kill` opened before the agent's first
/// start, one of a unit's opened inside a window or in a fresh cgroup's
/// first milliseconds) kept writing. `file_permission` runs for every
/// `write(2)`-family call (`rw_verify_area`, io_uring's writes included)
/// before anything is written: a write to a `FS_PROTECT_WRITE` inode is
/// refused like its open, and so is a write to a protected cgroup's
/// resource file, a cgroup v1 file or a protected process's
/// `oom_score_adj` (`cgroup_files`), where PID 1's value is judged. One
/// map lookup per write; reads return at the mask test. Signed
/// rate-limited per caller (a loop of writes is one record a second).
#[lsm(hook = "file_permission")]
pub fn protected_write_deny(ctx: LsmContext) -> i32 {
    unsafe { try_protected_write_deny(&ctx) }
}

/// `MAY_WRITE` (include/linux/fs.h).
const MAY_WRITE: c_int = 0x2;
/// `S_IFMT` / `S_IFREG` (include/uapi/linux/stat.h).
const S_IFMT: u16 = 0o170000;
const S_IFREG: u16 = 0o100000;

#[inline(always)]
unsafe fn try_protected_write_deny(ctx: &LsmContext) -> i32 {
    // Kernel signature: `int file_permission(struct file *file, int mask)`.
    let mask: c_int = ctx.arg(1);
    if mask & MAY_WRITE == 0 {
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
            crate::fail_open::bump(hook::FILE_PERMISSION);
            return 0;
        }
    };
    // Lot 273c (the review of #490): a socket, a pipe, a tty — most writes
    // of a busy host — is never protected (every protected file, cgroup
    // file and proc file is a regular one): out before the map lookup. A
    // mode that cannot be read goes on to the lookup.
    if !inode.is_null() {
        if let Ok(mode) = bpf_probe_read_kernel::<u16>((inode as *const u8).add(off!(INODE_I_MODE_OFFSET)) as *const u16) {
            if mode & S_IFMT != S_IFREG {
                return 0;
            }
        }
    }
    if let Some((op, key)) = protected_verdict(FS_OP_WRITE, inode, hook::FILE_PERMISSION) {
        // Lot 273b: PID 1's write of `0` to a protected cgroup.freeze — a
        // thaw — goes through; a freeze is refused here.
        let thaw = fs_protect_init_may_open(op, (bpf_get_current_pid_tgid() >> 32) as u32)
            && matches!(crate::cgroup_files::written_value(), Some(v) if same_value(&v, &fs_protect_thaw_value()));
        if !thaw {
            emit_limited(op, key);
            return -EPERM;
        }
    }
    if crate::cgroup_files::refuse_write(file, inode, hook::FILE_PERMISSION, crate::cgroup_files::Phase::Write) {
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
        Err(_) => {
            // Lab PR 215: a read-only open the key's deny could not judge.
            crate::fail_open::bump(hook::FILE_OPEN);
            return false;
        }
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
// then the dentry, then the attribute name. On 5.7 to 5.11 the two xattr
// hooks start with the dentry, so their dentry's position comes from the
// running kernel's prototype (lab PR 164); the agent checks the fixed
// positions of the others at boot.

/// A new entry in `dir`: refused when `dir` carries `FS_PROTECT_NOCREATE`
/// (the agent's own directories only), outside the trusted-installer
/// window, for a caller outside the agent's family.
#[inline(always)]
unsafe fn deny_new_entry(operation: u8, dir: *const c_void, hook: u32) -> i32 {
    if deny_if_protected(operation, dir, hook) {
        -EPERM
    } else {
        0
    }
}

/// `open(O_CREAT)`, `creat(2)`, `mknod(S_IFREG)`, a bpffs pin
/// (`vfs_mkobj`). Kernel signature: `(dir, dentry, mode)`.
#[lsm(hook = "inode_create")]
pub fn protected_create_deny(ctx: LsmContext) -> i32 {
    unsafe { deny_new_entry(FS_OP_CREATE, ctx.arg(0), hook::INODE_CREATE) }
}

/// Kernel signature: `(dir, dentry, mode)`.
#[lsm(hook = "inode_mkdir")]
pub fn protected_mkdir_deny(ctx: LsmContext) -> i32 {
    unsafe { deny_new_entry(FS_OP_MKDIR, ctx.arg(0), hook::INODE_MKDIR) }
}

/// A device node, FIFO or socket. Kernel signature: `(dir, dentry, mode,
/// dev)`.
#[lsm(hook = "inode_mknod")]
pub fn protected_mknod_deny(ctx: LsmContext) -> i32 {
    unsafe { deny_new_entry(FS_OP_MKNOD, ctx.arg(0), hook::INODE_MKNOD) }
}

/// Kernel signature: `(dir, dentry, old_name)`.
#[lsm(hook = "inode_symlink")]
pub fn protected_symlink_deny(ctx: LsmContext) -> i32 {
    unsafe { deny_new_entry(FS_OP_SYMLINK, ctx.arg(0), hook::INODE_SYMLINK) }
}

/// A hard link made in a NOCREATE directory — also the way an `O_TMPFILE`
/// file (which no create hook sees) would get a name there. Kernel
/// signature: `(old_dentry, dir, new_dentry)`. The source is not checked:
/// the denies are keyed by inode, so a protected file linked elsewhere is
/// as protected under its new name, and refusing it would only turn a
/// backup's or a deduplicator's link into a COMBAT trigger.
#[lsm(hook = "inode_link")]
pub fn protected_link_deny(ctx: LsmContext) -> i32 {
    unsafe { deny_new_entry(FS_OP_LINK, ctx.arg(1), hook::INODE_LINK) }
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
/// protected inode: the dentry is argument `dentry_arg`, the attribute
/// name the next one. `None` (the position was not resolved): nothing is
/// read. Lab PR 215: that, and a dentry that could not be read, are
/// fail-opens of `hook` (the agent attaches the hook only once the
/// position is known, and these hooks always get a dentry).
#[inline(always)]
unsafe fn deny_xattr(ctx: &LsmContext, dentry_arg: Option<usize>, hook: u32) -> i32 {
    let i = match dentry_arg {
        Some(i) => i,
        None => {
            crate::fail_open::bump(hook);
            return 0;
        }
    };
    let dentry = raw_arg(ctx, i) as *const c_void;
    if dentry.is_null() {
        crate::fail_open::bump(hook);
        return 0;
    }
    let inode = match inode_from_dentry(dentry, hook) {
        Some(i) => i,
        None => return 0,
    };
    if xattr_is_selinux(raw_arg(ctx, i + 1)) {
        return 0;
    }
    if deny_if_protected(FS_OP_XATTR, inode, hook) {
        return -EPERM;
    }
    0
}

/// Kernel signature: `(mnt_userns | idmap, dentry, name, value, size,
/// flags)`, `(dentry, name, value, size, flags)` on 5.7 to 5.11: the
/// dentry's position is resolved at boot. On 5.15 and 6.1 a POSIX ACL
/// (`setfacl`) comes this way too, as `system.posix_acl_*`.
#[lsm(hook = "inode_setxattr")]
pub fn protected_setxattr_deny(ctx: LsmContext) -> i32 {
    unsafe {
        deny_xattr(
            &ctx,
            crate::btf_offsets::hook_arg(INODE_SETXATTR_DENTRY_ARG_SLOT),
            hook::INODE_SETXATTR,
        )
    }
}

/// Kernel signature: `(mnt_userns | idmap, dentry, name)`, `(dentry,
/// name)` on 5.7 to 5.11 (resolved at boot).
#[lsm(hook = "inode_removexattr")]
pub fn protected_removexattr_deny(ctx: LsmContext) -> i32 {
    unsafe {
        deny_xattr(
            &ctx,
            crate::btf_offsets::hook_arg(INODE_REMOVEXATTR_DENTRY_ARG_SLOT),
            hook::INODE_REMOVEXATTR,
        )
    }
}

/// 6.2+: a POSIX ACL no longer passes `inode_setxattr`. Kernel signature:
/// `(idmap, dentry, acl_name, kacl)` on every kernel that has the hook
/// (checked at boot). Attached only where the kernel has the hook.
#[lsm(hook = "inode_set_acl")]
pub fn protected_set_acl_deny(ctx: LsmContext) -> i32 {
    unsafe { deny_xattr(&ctx, Some(1), hook::INODE_SET_ACL) }
}

/// 6.2+. Kernel signature: `(idmap, dentry, acl_name)`.
#[lsm(hook = "inode_remove_acl")]
pub fn protected_remove_acl_deny(ctx: LsmContext) -> i32 {
    unsafe { deny_xattr(&ctx, Some(1), hook::INODE_REMOVE_ACL) }
}
