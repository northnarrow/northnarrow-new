//! Lot 273 — the protected processes stay in their units' cgroups.
//!
//! The kernel can end or stop every process of a cgroup without a signal
//! from userland: a write to `cgroup.kill` (5.14+) is a SIGKILL of the
//! whole cgroup that no `task_kill` hook sees, and `cgroup.freeze` stops
//! it. systemd 257 and later answer `systemctl kill -s SIGKILL` with that
//! write once the main process refused the signal. The agent registers its
//! own and the watchdog's unit cgroups in `PROTECTED_INODES` (their
//! `cgroup.kill` and `cgroup.freeze` write-protected, and the ancestor
//! slices' as well): the existing `file_open` deny refuses the write.
//!
//! What a file deny cannot see is a protected process moved to another
//! cgroup — a fresh one whose `cgroup.kill` nobody protects, or a frozen
//! one, which freezes it on arrival. A move is a write of the pid to the
//! destination's `cgroup.procs` (or of a tid to `cgroup.threads`), any
//! cgroup's. No LSM hook names the moved task; the migration's permission
//! check does run one, though: `cgroup_procs_write_start()` finds the task
//! the pid names, then `cgroup_attach_permissions()` checks write access to
//! the `cgroup.procs` of the source's and the destination's common
//! ancestor through `inode_permission()` — in the writer's thread, before
//! anything moves. So:
//!
//! * [`cgroup_move_stash`] (fexit `cgroup_procs_write_start`) records, for
//!   the writing thread, the protected tgid it is about to move — only for
//!   a caller outside the agent's family and outside a trusted-installer
//!   window;
//! * [`cgroup_move_deny`] (LSM `inode_permission`) refuses the next write
//!   check of that thread, the migration's, and signs it
//!   (`FS_OP_CGROUP_MOVE`, rate-limited as a signal is).
//!
//! * [`cgroup_move_clear`] (fexit `cgroup_file_write`; lot 273b, lot 303)
//!   drops the thread's record when the write ends, whatever it did.
//!   `cgroup_file_write` is the kernfs `write` operation of every cgroup
//!   file, called through a pointer: never inlined. Lot 273b's fentry on
//!   `cgroup_procs_write_finish` missed every cgroup v2 write on 7.0, whose
//!   compiler inlines the two-line function into `__cgroup_procs_write`
//!   (lot 303: a write the DAC refused left its record, and the thread's
//!   next own move was refused).
//!
//! The write check runs in the same thread right after the lookup, and the
//! stash is consumed by it. Lot 273b: a record lives only from the lookup
//! to the end of the write, so a write that never reached the check — a
//! cgroup v1 write (no inode checked; refused at its open where the host
//! runs the unified hierarchy only: `cgroup_files`), a write whose
//! permission check the DAC refused first (an unprivileged writer in a
//! delegated subtree) — leaves nothing behind; and the check consumes a
//! record only on a cgroup v2 `cgroup.procs` / `cgroup.threads`, the file
//! a migration's permission check is made on. Every migration runs under
//! `cgroup_mutex` (`cgroup_kn_lock_live` before the lookup): at most one
//! record is live at a time, and the map, which never evicts, has room for
//! [`MOVE_STASH_ENTRIES`]; an insert it refuses is counted as a fail-open
//! of the lookup half.

use aya_ebpf::{
    cty::{c_int, c_void},
    helpers::{bpf_get_current_pid_tgid, bpf_ktime_get_ns, bpf_probe_read_kernel, generated},
    macros::{fexit, lsm, map},
    maps::HashMap,
    programs::{FExitContext, LsmContext},
    EbpfContext,
};
use northnarrow_common::btf_offsets::CGROUP_MOVE_RET_ARG;
use northnarrow_common::cgroup_limits::name_words;
use northnarrow_common::fail_open::hook;
use northnarrow_common::wire::{CGROUP2_SUPER_MAGIC, FS_OP_CGROUP_MOVE};

use crate::btf_offsets::{
    INODE_I_MODE_OFFSET, INODE_I_PRIVATE_OFFSET, INODE_I_SB_OFFSET, KERNFS_NODE_NAME_OFFSET,
    SUPER_BLOCK_S_MAGIC_OFFSET, TASK_STRUCT_TGID_OFFSET,
};

/// Linux `EPERM`; LSM hooks return `-errno` to deny.
const EPERM: c_int = 1;
/// `MAY_WRITE` (include/linux/fs.h): the bit of `inode_permission`'s mask
/// a migration's permission check carries.
const MAY_WRITE: c_int = 0x2;
/// The largest `-errno` an `ERR_PTR` carries (include/linux/err.h).
const MAX_ERRNO: u64 = 4095;
/// How long a stashed move waits for its permission check. The check
/// follows the lookup by microseconds, and the end of the write drops the
/// record ([`cgroup_move_clear`]); a record older than this one is refused
/// nothing (defence in depth: a record whose end was not seen).
const STASH_TTL_NS: u64 = 1_000_000_000;

/// Capacity of [`CGROUP_MOVES`]. One record is live at a time (migrations
/// are serialised by `cgroup_mutex`); the bound is explicit, and an insert
/// past it is counted (`DENY_FAIL_OPEN`, the lookup half's slot) and the
/// move goes through undecided — never an eviction of a live record.
const MOVE_STASH_ENTRIES: u32 = 64;

/// The writing thread (`pid_tgid`) → `[protected tgid it moves, ktime of
/// the lookup]`. A plain hash map (lot 273b: an LRU map's per-CPU free
/// lists may evict a live record before the map is full). Not pinned: the
/// three programs are attached fresh together every boot, and they share
/// their own object's map.
#[map]
static CGROUP_MOVES: HashMap<u64, [u64; 2]> = HashMap::with_max_entries(MOVE_STASH_ENTRIES, 0);

/// `S_IFMT` / `S_IFREG` (include/uapi/linux/stat.h).
const S_IFMT: u16 = 0o170000;
const S_IFREG: u16 = 0o100000;

/// `struct task_struct *cgroup_procs_write_start(char *buf, bool
/// threadgroup, <lock state> *)` returned: the task a `cgroup.procs` /
/// `cgroup.threads` write is about to move (the thread group leader for
/// `cgroup.procs`), or an `ERR_PTR`. The agent attaches this program only
/// where the kernel's BTF gives the function that shape (three parameters,
/// a `struct task_struct *` back), so the return value is the fourth slot
/// of the context.
#[fexit(function = "cgroup_procs_write_start")]
pub fn cgroup_move_stash(ctx: FExitContext) -> i32 {
    unsafe { try_cgroup_move_stash(&ctx) };
    0
}

#[inline(always)]
unsafe fn try_cgroup_move_stash(ctx: &FExitContext) {
    let args = ctx.as_ptr() as *const u64;
    let task = match bpf_probe_read_kernel::<u64>(args.add(CGROUP_MOVE_RET_ARG)) {
        Ok(t) => t,
        Err(_) => {
            crate::fail_open::bump(hook::CGROUP_PROCS_WRITE_START);
            return;
        }
    };
    // NULL or an ERR_PTR (a pid that names no task, a kernel thread): the
    // write fails by itself.
    if task == 0 || task >= 0u64.wrapping_sub(MAX_ERRNO) {
        return;
    }
    let tgid_ptr = (task as *const u8).add(off!(TASK_STRUCT_TGID_OFFSET)) as *const u32;
    let tgid = match bpf_probe_read_kernel::<u32>(tgid_ptr) {
        Ok(v) => v,
        Err(_) => {
            // The task cannot be told: the move goes through undecided,
            // and is counted (lab PR 215).
            crate::fail_open::bump(hook::CGROUP_PROCS_WRITE_START);
            return;
        }
    };
    let pid_tgid = bpf_get_current_pid_tgid();
    // Only a protected process moved by a caller outside the agent's
    // family (a worker is protected, not exempt: R14a), outside a signed
    // trusted-installer window, is recorded.
    if !crate::task_kill::is_protected_pid(tgid)
        || crate::task_kill::is_exempt_pid((pid_tgid >> 32) as u32)
        || crate::inode_protect::override_active()
    {
        return;
    }
    let rec = [u64::from(tgid), bpf_ktime_get_ns()];
    if CGROUP_MOVES.insert(&pid_tgid, &rec, 0).is_err() {
        // Lot 273b: the map is full (it never evicts): counted, and the
        // move goes through undecided.
        crate::fail_open::bump(hook::CGROUP_PROCS_WRITE_START);
    }
}

/// Lot 273b, lot 303: `ssize_t cgroup_file_write(struct kernfs_open_file *,
/// char *, size_t, loff_t)` returns at the end of every write of a cgroup
/// file, the `cgroup.procs` / `cgroup.threads` writes
/// `cgroup_procs_write_start` returned a task for among them — the move
/// done, refused by the permission check (ours or the DAC's), or failed —
/// on cgroup v2 and on v1 alike. The thread's record goes with it: a write
/// that never reached the permission check leaves nothing for a later
/// check of the thread to consume. Kernfs calls the function through its
/// `write` pointer, so it is never inlined (lot 303: 7.0 inlines lot
/// 273b's `cgroup_procs_write_finish` into its cgroup v2 caller).
#[fexit(function = "cgroup_file_write")]
pub fn cgroup_move_clear(_ctx: FExitContext) -> i32 {
    let pid_tgid = bpf_get_current_pid_tgid();
    let _ = CGROUP_MOVES.remove(&pid_tgid);
    0
}

/// Lot 273b: whether `inode` is the file a migration's permission check is
/// made on — a `cgroup.procs` (or `cgroup.threads`) of a cgroup v2
/// hierarchy. Without the kernfs offsets, any regular file of a cgroup v2
/// hierarchy. A read that fails is no such file.
#[inline(always)]
unsafe fn is_cgroup2_members_file(inode: *const c_void) -> bool {
    if inode.is_null() {
        return false;
    }
    let Ok(sb) = bpf_probe_read_kernel::<*const u8>(
        (inode as *const u8).add(off!(INODE_I_SB_OFFSET)) as *const *const u8,
    ) else {
        return false;
    };
    if sb.is_null() {
        return false;
    }
    let Ok(magic) = bpf_probe_read_kernel::<u64>(sb.add(off!(SUPER_BLOCK_S_MAGIC_OFFSET)) as *const u64)
    else {
        return false;
    };
    if magic & 0xffff_ffff != CGROUP2_SUPER_MAGIC {
        return false;
    }
    let Ok(mode) = bpf_probe_read_kernel::<u16>((inode as *const u8).add(off!(INODE_I_MODE_OFFSET)) as *const u16)
    else {
        return false;
    };
    if mode & S_IFMT != S_IFREG {
        return false;
    }
    let (Some(private), Some(name_off)) = (
        off_opt!(INODE_I_PRIVATE_OFFSET),
        off_opt!(KERNFS_NODE_NAME_OFFSET),
    ) else {
        return true;
    };
    let Ok(kn) = bpf_probe_read_kernel::<*const u8>((inode as *const u8).add(private) as *const *const u8)
    else {
        return false;
    };
    if kn.is_null() {
        return false;
    }
    let Ok(name) = bpf_probe_read_kernel::<*const u8>(kn.add(name_off) as *const *const u8) else {
        return false;
    };
    if name.is_null() {
        return false;
    }
    // "cgroup.procs" (12 bytes) or "cgroup.threads" (14): read up to its
    // NUL into two zeroed words (never past the string), compared whole.
    let mut w = [0u64; 2];
    let n = generated::bpf_probe_read_kernel_str(
        w.as_mut_ptr() as *mut c_void,
        16,
        name as *const c_void,
    );
    if n <= 0 {
        return false;
    }
    const PROCS: [u64; 3] = name_words(b"cgroup.procs");
    const THREADS: [u64; 3] = name_words(b"cgroup.threads");
    (w[0] == PROCS[0] && w[1] == PROCS[1]) || (w[0] == THREADS[0] && w[1] == THREADS[1])
}

/// `int inode_permission(struct inode *inode, int mask)`: the next write
/// check of a thread that is moving a protected process is the migration's
/// — refused. Every other call returns at the mask test, or at one lookup
/// in a map that holds only refused-to-be moves.
#[lsm(hook = "inode_permission")]
pub fn cgroup_move_deny(ctx: LsmContext) -> i32 {
    unsafe { try_cgroup_move_deny(&ctx) }
}

#[inline(always)]
unsafe fn try_cgroup_move_deny(ctx: &LsmContext) -> i32 {
    // No prev-retval read, see task_kill.rs.
    let mask: c_int = ctx.arg(1);
    if mask & MAY_WRITE == 0 {
        return 0;
    }
    let pid_tgid = bpf_get_current_pid_tgid();
    let rec = match CGROUP_MOVES.get(&pid_tgid) {
        Some(r) => *r,
        None => return 0,
    };
    // Lot 273b: consumed only by the check a migration makes.
    if !is_cgroup2_members_file(ctx.arg(0)) {
        return 0;
    }
    let _ = CGROUP_MOVES.remove(&pid_tgid);
    if bpf_ktime_get_ns().wrapping_sub(rec[1]) >= STASH_TTL_NS {
        return 0;
    }
    // Checked again at the refusal: a window opened in between, or a
    // process that joined the family, is let through.
    if crate::inode_protect::override_active()
        || crate::task_kill::is_exempt_pid((pid_tgid >> 32) as u32)
    {
        return 0;
    }
    crate::inode_protect::emit_task_denial(FS_OP_CGROUP_MOVE, 0, rec[0] as u32);
    -EPERM
}
