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
//! The write check runs in the same thread right after the lookup, and the
//! stash is consumed by it. On a cgroup v1 hierarchy the write path checks
//! no inode and the move is not refused (the record ages out after
//! [`STASH_TTL_NS`]); the agent protects cgroup v2 only.

use aya_ebpf::{
    cty::c_int,
    helpers::{bpf_get_current_pid_tgid, bpf_ktime_get_ns, bpf_probe_read_kernel},
    macros::{fexit, lsm, map},
    maps::LruHashMap,
    programs::{FExitContext, LsmContext},
    EbpfContext,
};
use northnarrow_common::btf_offsets::CGROUP_MOVE_RET_ARG;
use northnarrow_common::fail_open::hook;
use northnarrow_common::wire::FS_OP_CGROUP_MOVE;

use crate::btf_offsets::TASK_STRUCT_TGID_OFFSET;

/// Linux `EPERM`; LSM hooks return `-errno` to deny.
const EPERM: c_int = 1;
/// `MAY_WRITE` (include/linux/fs.h): the bit of `inode_permission`'s mask
/// a migration's permission check carries.
const MAY_WRITE: c_int = 0x2;
/// The largest `-errno` an `ERR_PTR` carries (include/linux/err.h).
const MAX_ERRNO: u64 = 4095;
/// How long a stashed move waits for its permission check. The check
/// follows the lookup by microseconds; a record older than this one is the
/// leftover of a write path that checks nothing (cgroup v1) and is dropped.
const STASH_TTL_NS: u64 = 1_000_000_000;

/// The writing thread (`pid_tgid`) → `[protected tgid it moves, ktime of
/// the lookup]`. LRU: a v1 write leaves its record behind, and records
/// must never fill the map. Not pinned: the two programs are attached fresh
/// together every boot, and each pair shares its own object's map.
#[map]
static CGROUP_MOVES: LruHashMap<u64, [u64; 2]> = LruHashMap::with_max_entries(1024, 0);

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
    if !crate::task_kill::is_protected_pid(tgid) {
        return;
    }
    let pid_tgid = bpf_get_current_pid_tgid();
    // The agent and the watchdog manage their own family; a worker is
    // protected, not exempt (R14a).
    if crate::task_kill::is_exempt_pid((pid_tgid >> 32) as u32) {
        return;
    }
    // Inside a signed trusted-installer window nothing is refused.
    if crate::inode_protect::override_active() {
        return;
    }
    let rec = [u64::from(tgid), bpf_ktime_get_ns()];
    let _ = CGROUP_MOVES.insert(&pid_tgid, &rec, 0);
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
