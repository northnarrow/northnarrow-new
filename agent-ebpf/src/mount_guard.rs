//! Lot 357 — the mount guard: `sb_mount`, `move_mount`, `sb_umount`,
//! `sb_pivotroot` and (the review of #567, F3) `sb_remount`. A mount on,
//! over or below the paths the agent depends on is refused in PID 1's
//! mount namespace, the agent's own and the watchdog's
//! ([`MOUNT_GUARD_NS`]); a reconfigure of a super block they hold, in any.
//!
//! The decision is `northnarrow_common::mount_guard::decide` (the host's
//! tests judge it); this file reads what it weighs from the kernel's own
//! objects — the target's dentry and mount as path resolution left them,
//! the mounts stacked there, the dentries' names up to their file system's
//! root, the caller's namespaces and capabilities — never the caller's
//! path string. `mount(2)`'s source is a string the kernel resolves only
//! after this hook: a bind's source is not judged (where it lands is), and
//! a move through `MS_MOVE` is refused in the host's namespace whatever it
//! moves (`move_mount(2)`, which util-linux 2.39 and later uses, names the
//! mount it moves).
//!
//! The protected points are the agent's (`MOUNT_PROTECTED`, by device and
//! inode as `stat(2)` gives them in PID 1's root: the views, the agent's
//! directories, binaries and units, the directories above them; and the
//! super blocks they are on, `(s_dev, 0)` with `MG_SB`), written before the
//! hooks attach. The mounts held (no unmount, no move away) are mounts, by
//! their id (`MOUNT_HELD`, the review of #567 F1): a copy of one (a
//! backup's bind of `/`, a chroot's sysfs) is another mount.
//! `MOUNT_GUARD_CONF` carries PID 1's mount and user namespaces (0 = not
//! armed: every hook lets through), and the agent's and the watchdog's
//! mount namespaces, which [`vacate`] drops at their exit. A read that
//! fails lets the operation through, counted (`DENY_FAIL_OPEN`).
//!
//! A refusal is signed at each attempt (`FS_OP_MOUNT`, the attempt budget);
//! the signed trusted-installer window lets everything through and records
//! what it let through that is refused outside one (`FS_OP_MOUNT_WINDOW`).

use aya_ebpf::{
    cty::{c_int, c_void},
    helpers::{bpf_get_current_pid_tgid, bpf_get_current_task, bpf_ktime_get_ns, generated},
    macros::{fentry, lsm, map},
    maps::{Array, HashMap, LruHashMap, ProgramArray},
    programs::{FEntryContext, LsmContext},
};
use northnarrow_common::fail_open::hook;
use northnarrow_common::mount_guard::{
    decide, fnv16, held_by_id, held_by_place, inode_key, is_view_magic, mount_op,
    reach_in, record_dev, target_reach, view_of, Mounts, NameKey, Point, Query, Verdict,
    BTRFS_SUPER_MAGIC, DEPTH_DEEPER, GUARD_HOST, HELD_REFUSE, MAX_STACK, MAX_WALK, MG_HOLD,
    MG_NOTE, MG_OP_MOUNT, MG_OP_MOVE_MOUNT, MG_OP_MOVE_OLD, MG_OP_PASS, MG_OP_PIVOT, MG_OP_REMOUNT,
    MG_OP_REMOUNT_BIND, MG_OP_UMOUNT, MG_OWN, MG_SB, MG_VIEW, MS_NOEXEC, MS_RDONLY,
    umount_spread, umount_takes_held, Spread, HELD_UNDER, PLACE_ANY_GROUP, REACH_OTHER_NS,
    below_of, below_takes_held, umount_below, Tree,
    lock_bind, lock_maker, lock_shutdown_step, lock_step_at, lock_touched, lock_verdict,
    BindShape, MG_LOCK, MG_LOCK_ABOVE, MG_OP_PROPAGATE,
    copy_move_verdict, held_root, moves_held_copy, propagation_counts, sb_mount_route, vacates,
    SbRoute, CONF_PROPAGATED, CONF_SLOTS,
    STAGE_POINT, STAGE_PROPAGATE, STAGE_SLOTS,
};
use northnarrow_common::wire::{InodeKey, FS_OP_MOUNT, FS_OP_MOUNT_NOTED, FS_OP_MOUNT_WINDOW};

use crate::btf_offsets::{
    BTRFS_INODE_ROOT_OFFSET, BTRFS_INODE_VFS_INODE_OFFSET, BTRFS_ROOT_ANON_DEV_OFFSET,
    CRED_CAP_EFFECTIVE_OFFSET, CRED_USER_NS_OFFSET, DENTRY_D_INODE_OFFSET, DENTRY_D_NAME_OFFSET,
    FS_CONTEXT_SB_FLAGS_MASK_OFFSET, FS_CONTEXT_SB_FLAGS_OFFSET,
    DENTRY_D_PARENT_OFFSET, FILE_SYSTEM_TYPE_NAME_OFFSET, INODE_I_INO_OFFSET, INODE_I_SB_OFFSET,
    MNT_NAMESPACE_INUM_OFFSET, MOUNT_MNT_CHILD_OFFSET, MOUNT_MNT_GROUP_ID_OFFSET,
    MOUNT_MNT_ID_OFFSET, MOUNT_MNT_MOUNTPOINT_OFFSET, MOUNT_MNT_MOUNTS_OFFSET,
    MOUNT_MNT_NS_OFFSET, MOUNT_MNT_OFFSET, MOUNT_MNT_PARENT_OFFSET, MOUNT_MNT_SHARE_OFFSET,
    MOUNT_MNT_SLAVE_LIST_OFFSET, MOUNT_MNT_SLAVE_OFFSET, NSPROXY_MNT_NS_OFFSET,
    PATH_DENTRY_OFFSET, PATH_MNT_OFFSET, PF_KTHREAD, QSTR_LEN_OFFSET, QSTR_NAME_OFFSET,
    SUPER_BLOCK_S_DEV_OFFSET, SUPER_BLOCK_S_MAGIC_OFFSET, SUPER_BLOCK_S_TYPE_OFFSET,
    TASK_STRUCT_COMM_OFFSET, TASK_STRUCT_CRED_OFFSET, TASK_STRUCT_FLAGS_OFFSET,
    TASK_STRUCT_NSPROXY_OFFSET, TASK_STRUCT_REAL_PARENT_OFFSET, TASK_STRUCT_START_TIME_OFFSET,
    TASK_STRUCT_TGID_OFFSET,
    USER_NAMESPACE_INUM_OFFSET, VFSMOUNT_MNT_ROOT_OFFSET,
};

/// Linux `EPERM`; LSM hooks return `-errno` to deny.
const EPERM: c_int = 1;

/// `CAP_SYS_ADMIN`'s bit in `cred.cap_effective`.
const CAP_SYS_ADMIN: u64 = 1 << 21;

/// Entries of [`MOUNT_PROTECTED`]: the views, the agent's directories,
/// binaries, units and drop-in directories, and the directories above them
/// (some sixty on a host), and the super blocks they are on.
pub const MOUNT_PROTECTED_MAX: u32 = 512;

/// The protected points, by device and inode → `MG_ON` / `MG_OWN` /
/// `MG_VIEW` / `MG_HOLD`; the super blocks, `(s_dev, 0)` → `MG_SB` (and
/// the views' own `MG_VIEW`). Pinned by name with the hooks: a restarted
/// agent registers into the map the pinned programs read (as
/// `PROTECTED_INODES`).
#[map]
pub static MOUNT_PROTECTED: HashMap<InodeKey, u8> = HashMap::pinned(MOUNT_PROTECTED_MAX, 0);

/// Entries of [`MOUNT_HELD`]: in each of three namespaces, the mounts the
/// protected points resolve through, by id and by place.
pub const MOUNT_HELD_MAX: u32 = 512;

/// The review of #567 (F1): the mounts held — no unmount, no move away —
/// by their id (`common::mount_guard::held_by_id`), and by their place
/// under their parent's peer groups, for an unmount that propagates there
/// (`held_by_place`) → `HELD_REFUSE` or `MG_NOTE`, the namespace in the
/// high nibble. Pinned.
#[map]
pub static MOUNT_HELD: HashMap<InodeKey, u8> = HashMap::pinned(MOUNT_HELD_MAX, 0);

/// The review of #567 (F2): the mount namespaces judged as PID 1's, by
/// their `ns.inum` → `GUARD_HOST` / `GUARD_AGENT` / `GUARD_WATCHDOG`. The
/// agent's and the watchdog's go at their exit ([`vacate`]): before the
/// kernel frees the number, which the next namespace (a unit's sandbox
/// being set up) would otherwise take judged. Pinned.
#[map]
pub static MOUNT_GUARD_NS: HashMap<u64, u8> = HashMap::pinned(8, 0);

/// The review of #567 (the cross-model check): the peer groups through
/// which a change made in another namespace reaches a guarded one — the
/// own group (`shared:N`) and the master's (`master:N`) of each mount of
/// PID 1's, the agent's and the watchdog's namespaces that holds a
/// protected point or is a view → a bit per namespace. One look-up for a
/// group the agent's refresh has seen; one it has not (re-check N1: a
/// guarded mount regrouped since) is walked (`common::mount_guard::
/// spread`), and a propagation change in a guarded namespace wakes the
/// refresh ([`CONF_REGROUP`]). Pinned.
#[map]
pub static MOUNT_GROUPS: HashMap<u32, u8> = HashMap::pinned(MOUNT_HELD_MAX, 0);

/// The review of #567 (F3): the new flags of a super block's reconfigure in
/// flight, by `pid_tgid` → `sb_flags | sb_flags_mask << 32` — written by
/// [`mount_guard_reconfigure`] at `reconfigure_super()`'s entry, read and
/// dropped by `sb_remount`, which that function calls next and which does
/// not see them. Pinned with it.
#[map]
pub static MOUNT_RECONF: LruHashMap<u64, u64> = LruHashMap::pinned(1024, 0);

/// Slot 0: PID 1's mount namespace (its `ns.inum`), slot 1: PID 1's user
/// namespace, slot 2: the agent's mount namespace, slot 3: the
/// watchdog's (the keys [`vacate`] drops from [`MOUNT_GUARD_NS`]), slot 4
/// ([`CONF_REGROUP`]): the propagation changes counted, slot 5 (lot 1.1,
/// `common::mount_guard::CONF_PROPAGATED`): the propagation changes the
/// kernel made on a guarded mount (`crate::mount_setattr`). 0 in slot 0:
/// not armed, every hook lets through. Pinned.
#[map]
pub static MOUNT_GUARD_CONF: Array<u64> = Array::pinned(CONF_SLOTS, 0);

/// Lot 1.1 (F8b-1): `sb_mount`'s stages, tail-called by its entry
/// ([`mount_guard_sb_mount`]): [`STAGE_POINT`] judges where a mount lands
/// ([`mount_guard_sb_mount_point`]), [`STAGE_PROPAGATE`] a change of
/// propagation that reaches the pin directory's lock
/// ([`mount_guard_sb_mount_propagate`]). Loaded for the hook, never
/// attached; filled by the agent before the entry is attached, and pinned
/// with it (a program array is emptied when its last user reference goes:
/// the pin carries the stages across the agent's restart). An empty slot
/// lets the operation through, counted (`DENY_FAIL_OPEN`).
#[map]
pub static MOUNT_SB_STAGES: ProgramArray = ProgramArray::with_max_entries(STAGE_SLOTS, 0);

/// Lot 1.1 (F8b-1): `move_mount`'s stage ([`STAGE_POINT`]:
/// [`mount_guard_move_mount_point`]) — an array of its own: from 6.11 a
/// tracing program tail-calls only a program attached to the same kernel
/// function (the array's first program's).
#[map]
pub static MOUNT_MOVE_STAGES: ProgramArray = ProgramArray::with_max_entries(STAGE_SLOTS, 0);

/// The re-check of #567 (N1): [`MOUNT_GUARD_CONF`]'s slot counting the
/// propagation changes that may give a guarded namespace's mount a peer
/// group [`MOUNT_GROUPS`] does not hold — `mount(2)`'s `MS_SHARED`,
/// `MS_PRIVATE`, `MS_SLAVE`, `MS_UNBINDABLE` on a mount of a guarded
/// namespace or of a group it holds, a `move_mount(2)` into a guarded
/// namespace of a mount in a peer group (`MOVE_MOUNT_SET_GROUP` among
/// them). The hook runs before the change (the new group has no number
/// yet): the agent reads the count each second and refreshes the map when
/// it moved. `mount_setattr(2)` has no hook: lot 1.1's fentry on the
/// kernel's `change_mnt_propagation()` counts its changes (`crate::
/// mount_setattr`).
pub(crate) const CONF_REGROUP: u32 = 4;

/// A propagation change counted ([`CONF_REGROUP`]; two at once may count
/// one: any change of the count wakes the refresh).
#[inline(always)]
pub(crate) fn note_regroup() {
    if let Some(v) = MOUNT_GUARD_CONF.get_ptr_mut(CONF_REGROUP) {
        unsafe { *v = (*v).wrapping_add(1) };
    }
}

/// The review of #567 (F2): the agent (role slot 1 of
/// `bpf_defense::ROLE_TGIDS`) or the watchdog (slot 0) exits — its mount
/// namespace is no longer judged as PID 1's. Called by `role_exit`, at
/// `sched_process_exit`, before the kernel drops the exiting task's
/// namespaces (`exit_task_namespaces`): the number cannot have been freed
/// for another namespace yet. Lot 1.1 (the re-check 2 of #569, N3): never
/// PID 1's (`common::mount_guard::vacates`) — a role run by hand there.
#[inline(always)]
pub(crate) fn vacate(role_slot: u32) {
    let conf_slot = if role_slot == 1 { 2 } else { 3 };
    let host = match MOUNT_GUARD_CONF.get(0) {
        Some(h) => *h,
        None => 0,
    };
    if let Some(v) = MOUNT_GUARD_CONF.get_ptr_mut(conf_slot) {
        // SAFETY: `v` is the map's own slot, valid for the program's run;
        // a concurrent write by the agent is a whole `u64`
        let inum = unsafe { *v };
        if vacates(inum, host) {
            let _ = MOUNT_GUARD_NS.remove(&inum);
        }
        if inum != 0 {
            // SAFETY: as above
            unsafe { *v = 0 };
        }
    }
}

/// A kernel `u64`, 0 when unreadable, without a branch on the result (the
/// helper writes zeros on a fault; see `task_scratch::peek_u64`).
#[inline(always)]
unsafe fn peek_u64(src: *const u8) -> u64 {
    // SAFETY: the body's 2021 unsafe context, made explicit (main.rs, "Unsafe code").
    unsafe {
        let mut v = core::mem::MaybeUninit::<u64>::uninit();
        let _ =
            generated::bpf_probe_read_kernel(v.as_mut_ptr() as *mut c_void, 8, src as *const c_void);
        v.assume_init()
    }
}

#[inline(always)]
unsafe fn peek_u32(src: *const u8) -> u32 {
    // SAFETY: the body's 2021 unsafe context, made explicit (main.rs, "Unsafe code").
    unsafe {
        let mut v = core::mem::MaybeUninit::<u32>::uninit();
        let _ =
            generated::bpf_probe_read_kernel(v.as_mut_ptr() as *mut c_void, 4, src as *const c_void);
        v.assume_init()
    }
}

#[inline(always)]
unsafe fn peek_ptr(src: *const u8) -> *const u8 {
    // SAFETY: the body's 2021 unsafe context, made explicit (main.rs, "Unsafe code").
    unsafe {
        peek_u64(src) as *const u8
    }
}

/// Every offset the hooks read, resolved once per run before any loop: an
/// `off!` inside the walks is two map lookups and three branches an
/// iteration, which multiplied the states 5.15's verifier explores past its
/// million instructions (the lot's first lab round). Each is masked to the
/// range its structure has.
#[derive(Clone, Copy)]
pub struct Offs {
    d_inode: u16,
    d_parent: u16,
    d_name: u16,
    qstr_len: u16,
    qstr_name: u16,
    i_sb: u16,
    i_ino: u16,
    s_dev: u16,
    s_magic: u16,
    path_mnt: u16,
    path_dentry: u16,
    mnt_root: u16,
    mount_mnt: u16,
    mnt_parent: u16,
    mnt_mountpoint: u16,
    mnt_ns: u16,
    mnt_ns_inum: u16,
    mnt_share: u16,
    mnt_slave_list: u16,
    mnt_slave: u16,
    mnt_id: u16,
    mnt_group_id: u16,
    /// The re-check 2 of #567 (N3): the children (`mnt_mounts`) and the
    /// place in the parent's list (`mnt_child`).
    mnt_mounts: u16,
    mnt_child: u16,
    /// btrfs: `(vfs_inode, root, anon_dev)`, `vfs_inode` 0 when unknown.
    btrfs_vfs: u16,
    btrfs_root: u16,
    btrfs_anon: u16,
}

/// The offsets the hooks read, in a map slot rather than on the stack (5.15
/// gives the hooks 512 bytes across their calls). Every run writes the same
/// values, so two runs on one CPU never see each other's half: there is no
/// other half.
#[map]
static MOUNT_GUARD_OFFS: Array<Offs> = Array::with_max_entries(1, 0);

impl Offs {
    /// This kernel's offsets, written into [`MOUNT_GUARD_OFFS`]; `None` when
    /// an optional one is unknown (the agent attaches the hooks only with
    /// every one resolved).
    #[inline(always)]
    fn load() -> Option<&'static Offs> {
        let o = unsafe { &mut *MOUNT_GUARD_OFFS.get_ptr_mut(0)? };
        match (
            off_opt!(BTRFS_INODE_VFS_INODE_OFFSET),
            off_opt!(BTRFS_INODE_ROOT_OFFSET),
            off_opt!(BTRFS_ROOT_ANON_DEV_OFFSET),
        ) {
            (Some(v), Some(r), Some(a)) => {
                o.btrfs_vfs = (v & 0xffff) as u16;
                o.btrfs_root = (r & 0xffff) as u16;
                o.btrfs_anon = (a & 0xffff) as u16;
            }
            _ => {
                o.btrfs_vfs = 0;
                o.btrfs_root = 0;
                o.btrfs_anon = 0;
            }
        }
        o.d_inode = (off!(DENTRY_D_INODE_OFFSET) & 0xfff) as u16;
        o.d_parent = (off!(DENTRY_D_PARENT_OFFSET) & 0xfff) as u16;
        o.d_name = (off!(DENTRY_D_NAME_OFFSET) & 0xfff) as u16;
        o.qstr_len = (off!(QSTR_LEN_OFFSET) & 0xff) as u16;
        o.qstr_name = (off!(QSTR_NAME_OFFSET) & 0xff) as u16;
        o.i_sb = (off!(INODE_I_SB_OFFSET) & 0xfff) as u16;
        o.i_ino = (off!(INODE_I_INO_OFFSET) & 0xfff) as u16;
        o.s_dev = (off!(SUPER_BLOCK_S_DEV_OFFSET) & 0xfff) as u16;
        o.s_magic = (off!(SUPER_BLOCK_S_MAGIC_OFFSET) & 0xfff) as u16;
        o.path_mnt = (off_opt!(PATH_MNT_OFFSET)? & 0xff) as u16;
        o.path_dentry = (off!(PATH_DENTRY_OFFSET) & 0xff) as u16;
        o.mnt_root = (off_opt!(VFSMOUNT_MNT_ROOT_OFFSET)? & 0xff) as u16;
        o.mount_mnt = (off_opt!(MOUNT_MNT_OFFSET)? & 0xfff) as u16;
        o.mnt_parent = (off_opt!(MOUNT_MNT_PARENT_OFFSET)? & 0xfff) as u16;
        o.mnt_mountpoint = (off_opt!(MOUNT_MNT_MOUNTPOINT_OFFSET)? & 0xfff) as u16;
        o.mnt_ns = (off_opt!(MOUNT_MNT_NS_OFFSET)? & 0xfff) as u16;
        o.mnt_ns_inum = (off_opt!(MNT_NAMESPACE_INUM_OFFSET)? & 0xfff) as u16;
        o.mnt_share = (off_opt!(MOUNT_MNT_SHARE_OFFSET)? & 0xfff) as u16;
        o.mnt_slave_list = (off_opt!(MOUNT_MNT_SLAVE_LIST_OFFSET)? & 0xfff) as u16;
        o.mnt_slave = (off_opt!(MOUNT_MNT_SLAVE_OFFSET)? & 0xfff) as u16;
        o.mnt_id = (off_opt!(MOUNT_MNT_ID_OFFSET)? & 0xfff) as u16;
        o.mnt_group_id = (off_opt!(MOUNT_MNT_GROUP_ID_OFFSET)? & 0xfff) as u16;
        o.mnt_mounts = (off_opt!(MOUNT_MNT_MOUNTS_OFFSET)? & 0xfff) as u16;
        o.mnt_child = (off_opt!(MOUNT_MNT_CHILD_OFFSET)? & 0xfff) as u16;
        Some(o)
    }
}

/// The caller, as the hooks weigh it.
#[derive(Clone, Copy)]
struct Caller {
    /// The guarded namespace it runs in (`GUARD_HOST`, `GUARD_AGENT`,
    /// `GUARD_WATCHDOG`), 0 for another one.
    guard: u8,
    /// `CAP_SYS_ADMIN` in PID 1's user namespace.
    privileged: bool,
}

/// The caller. `None`: the guard is not armed, or an offset is unknown
/// (the agent attaches the hooks only with every one resolved).
#[inline(always)]
unsafe fn caller(hook: u32) -> Option<Caller> {
    // SAFETY: the body's 2021 unsafe context, made explicit (main.rs, "Unsafe code").
    unsafe {
        let host_mnt = *MOUNT_GUARD_CONF.get(0)?;
        if host_mnt == 0 {
            return None;
        }
        let host_user = *MOUNT_GUARD_CONF.get(1)?;
        let (Some(o_nsproxy), Some(o_mnt_ns), Some(o_mnt_inum)) = (
            off_opt!(TASK_STRUCT_NSPROXY_OFFSET),
            off_opt!(NSPROXY_MNT_NS_OFFSET),
            off_opt!(MNT_NAMESPACE_INUM_OFFSET),
        ) else {
            crate::fail_open::bump(hook);
            return None;
        };
        let task = bpf_get_current_task() as *const u8;
        let nsproxy = peek_ptr(task.add(o_nsproxy & 0xffff));
        if nsproxy.is_null() {
            crate::fail_open::bump(hook);
            return None;
        }
        let mnt_ns = peek_ptr(nsproxy.add(o_mnt_ns & 0xfff));
        let inum = peek_u32(mnt_ns.add(o_mnt_inum & 0xfff)) as u64;
        let guard = match MOUNT_GUARD_NS.get(&inum) {
            Some(g) => *g,
            None => 0,
        };
        let (Some(o_cred), Some(o_cap), Some(o_user_ns), Some(o_user_inum)) = (
            off_opt!(TASK_STRUCT_CRED_OFFSET),
            off_opt!(CRED_CAP_EFFECTIVE_OFFSET),
            off_opt!(CRED_USER_NS_OFFSET),
            off_opt!(USER_NAMESPACE_INUM_OFFSET),
        ) else {
            crate::fail_open::bump(hook);
            return None;
        };
        let cred = peek_ptr(task.add(o_cred & 0xffff));
        let cap = peek_u64(cred.add(o_cap & 0xfff));
        let user_ns = peek_ptr(cred.add(o_user_ns & 0xfff));
        let user_inum = peek_u32(user_ns.add(o_user_inum & 0xfff)) as u64;
        Some(Caller {
            guard,
            privileged: cap & CAP_SYS_ADMIN != 0 && user_inum == host_user,
        })
    }
}

/// `systemd-shutdown` at the end of a shutdown (the review of #567, F4):
/// PID 1 itself, or a helper it forked (`(sd-umount)`, `(sd-remount)` —
/// PID 1's child), PID 1's comm being `systemd-shutdown`'s (only PID 1 sets
/// its own) and the caller running the file the agent recorded
/// (`task_kill::SHUTDOWN_EXE`: a comm set by `ptrace` of PID 1 is not
/// enough, nor a copy of the program run elsewhere with a preload — its
/// parent is not PID 1 running it).
#[inline(always)]
unsafe fn shutdown_stage() -> bool {
    // SAFETY: the body's 2021 unsafe context, made explicit (main.rs, "Unsafe code").
    unsafe {
        let task = bpf_get_current_task() as *const u8;
        let leader = if (bpf_get_current_pid_tgid() >> 32) == 1 {
            task
        } else {
            let parent = peek_ptr(task.add(off!(TASK_STRUCT_REAL_PARENT_OFFSET)));
            if parent.is_null() || peek_u32(parent.add(off!(TASK_STRUCT_TGID_OFFSET))) != 1 {
                return false;
            }
            parent
        };
        let comm = leader.add(off!(TASK_STRUCT_COMM_OFFSET));
        if peek_u64(comm) != crate::task_kill::SHUTDOWN_COMM_LO
            || peek_u64(comm.add(8)) != crate::task_kill::SHUTDOWN_COMM_HI
        {
            return false;
        }
        let want = match crate::task_kill::SHUTDOWN_EXE.get(0) {
            Some(k) if k.ino != 0 => *k,
            _ => return false,
        };
        match crate::bpf_defense::caller_exe_key() {
            Some(k) => k.dev == want.dev && k.ino == want.ino,
            None => false,
        }
    }
}

/// Lot 359 (the re-check 3 of #567, N4): the caller is the pin directory's
/// lock's maker (`common::mount_guard::lock_maker`) — the agent's binary
/// (`bpf_defense::OWN_EXE_INODES`, by `mm->exe_file`), the main thread, a
/// child of PID 1 (a unit's `ExecStartPre=+` step, or the transient unit
/// the integrity round starts), in its first seconds, its lot 277/281
/// marks clean. Asked only of an operation that is one of the lock's own
/// steps.
#[inline(always)]
unsafe fn lock_maker_now() -> bool {
    // SAFETY: the body's 2021 unsafe context, made explicit (main.rs, "Unsafe code").
    unsafe {
        let pid_tgid = bpf_get_current_pid_tgid();
        let tgid = (pid_tgid >> 32) as u32;
        let task = bpf_get_current_task() as *const u8;
        let parent = peek_ptr(task.add(off!(TASK_STRUCT_REAL_PARENT_OFFSET)));
        let ptgid = if parent.is_null() {
            0
        } else {
            peek_u32(parent.add(off!(TASK_STRUCT_TGID_OFFSET)))
        };
        let start = peek_u64(task.add(off!(TASK_STRUCT_START_TIME_OFFSET)));
        lock_maker(
            tgid == pid_tgid as u32,
            ptgid,
            crate::bpf_defense::caller_role() == crate::bpf_defense::ROLE_AGENT,
            bpf_ktime_get_ns().wrapping_sub(start),
            crate::cgroup_join::marks_clean(tgid),
        )
    }
}

/// A kernel thread (`PF_KTHREAD`): the emergency remount of `SysRq-u`.
#[inline(always)]
unsafe fn kernel_thread() -> bool {
    // SAFETY: the body's 2021 unsafe context, made explicit (main.rs, "Unsafe code").
    unsafe {
        let task = bpf_get_current_task() as *const u8;
        peek_u32(task.add(off!(TASK_STRUCT_FLAGS_OFFSET))) & PF_KTHREAD != 0
    }
}

/// The guarded namespace a mount (a `struct mount`) belongs to — the
/// namespace that owns the target, never the caller's (the review of #567,
/// the cross-model check: an `O_PATH` descriptor of
/// `/proc/<pid>/root/…`, or a path through it, names a mount of another
/// namespace) — `GUARD_HOST`, `GUARD_AGENT`, `GUARD_WATCHDOG`, or 0.
#[inline(always)]
unsafe fn guard_of(o: &Offs, real: *const u8) -> u8 {
    // SAFETY: the body's 2021 unsafe context, made explicit (main.rs, "Unsafe code").
    unsafe {
        let inum = peek_u32(peek_ptr(real.add(o.mnt_ns as usize)).add(o.mnt_ns_inum as usize)) as u64;
        match MOUNT_GUARD_NS.get(&inum) {
            Some(g) => *g,
            None => 0,
        }
    }
}

/// The kernel's propagation objects (`struct mount`), as
/// `common::mount_guard::spread` walks them: the peer ring (`mnt_share`, a
/// `list_head`), the slaves (`mnt_slave_list` and `mnt_slave`: a
/// `list_head` to 6.x, an `hlist` from 6.18 — the head's first link, or a
/// link's next, is the head itself or NULL at the end, either way).
struct Kernel<'a>(&'a Offs);

impl Mounts for Kernel<'_> {
    type M = *const u8;
    #[inline(always)]
    fn group(&self, m: *const u8) -> u32 {
        unsafe { peek_u32(m.add(self.0.mnt_group_id as usize)) }
    }
    #[inline(always)]
    fn guard(&self, m: *const u8) -> u8 {
        unsafe { guard_of(self.0, m) }
    }
    #[inline(always)]
    fn known(&self, group: u32) -> bool {
        unsafe { MOUNT_GROUPS.get(&group).is_some() }
    }
    #[inline(always)]
    fn next_peer(&self, m: *const u8) -> Option<*const u8> {
        let o = self.0.mnt_share as usize;
        let n = unsafe { peek_ptr(m.add(o)) };
        if n.is_null() {
            None
        } else {
            Some((n as usize).wrapping_sub(o) as *const u8)
        }
    }
    #[inline(always)]
    fn first_slave(&self, m: *const u8) -> Option<*const u8> {
        let head = unsafe { m.add(self.0.mnt_slave_list as usize) };
        self.slave_at(head, unsafe { peek_ptr(head) })
    }
    #[inline(always)]
    fn next_slave(&self, master: *const u8, s: *const u8) -> Option<*const u8> {
        let head = unsafe { master.add(self.0.mnt_slave_list as usize) };
        self.slave_at(head, unsafe { peek_ptr(s.add(self.0.mnt_slave as usize)) })
    }
}

impl Kernel<'_> {
    /// The slave whose `mnt_slave` link is `n`, `None` at the end of the
    /// list whose head is `head`.
    #[inline(always)]
    fn slave_at(&self, head: *const u8, n: *const u8) -> Option<*const u8> {
        if n.is_null() || n == head {
            None
        } else {
            Some((n as usize).wrapping_sub(self.0.mnt_slave as usize) as *const u8)
        }
    }
}

/// The re-check of #567 (N1), an unmount's propagation: the mounts of the
/// parent's peers and slaves, each asked whether a held mount sits at the
/// unmounted mount's place under it (`MOUNT_HELD`'s [`HELD_UNDER`] key, the
/// place's hash `h`) — as [`Mounts::guard`], for `common::mount_guard::
/// umount_reaches_held`.
struct HeldUnder<'a> {
    k: Kernel<'a>,
    h: u64,
}

impl Mounts for HeldUnder<'_> {
    type M = *const u8;
    #[inline(always)]
    fn group(&self, m: *const u8) -> u32 {
        self.k.group(m)
    }
    #[inline(always)]
    fn guard(&self, m: *const u8) -> u8 {
        let id = unsafe { peek_u32(m.add(self.k.0.mnt_id as usize)) } as u64;
        let key = InodeKey {
            dev: HELD_UNDER | id,
            ino: self.h,
        };
        unsafe { MOUNT_HELD.get(&key).is_some() as u8 }
    }
    #[inline(always)]
    fn known(&self, group: u32) -> bool {
        self.k.known(group)
    }
    #[inline(always)]
    fn next_peer(&self, m: *const u8) -> Option<*const u8> {
        self.k.next_peer(m)
    }
    #[inline(always)]
    fn first_slave(&self, m: *const u8) -> Option<*const u8> {
        self.k.first_slave(m)
    }
    #[inline(always)]
    fn next_slave(&self, master: *const u8, s: *const u8) -> Option<*const u8> {
        self.k.next_slave(master, s)
    }
}

/// Where a change to the mount `real` lands (`common::mount_guard::
/// target_reach`): in a guarded namespace (its guard, judged there),
/// propagated into one (`REACH_OTHER_NS`: its peer group one
/// [`MOUNT_GROUPS`] holds, or — re-check N1, a group not refreshed yet —
/// one whose peers and slaves reach one or are not read whole), or nowhere
/// guarded (`None`: let through unread).
#[inline(always)]
unsafe fn target_of(o: &Offs, real: *const u8) -> Option<(u8, u8)> {
    target_reach(&Kernel(o), real)
}

/// The re-check 2 of #567 (N3): the mounts below an unmounted one
/// (`common::mount_guard::Tree`) — its children (`mnt_mounts`, a
/// `list_head` whose entries are the children's `mnt_child`), each asked
/// what its unmount takes (`common::mount_guard::below_of`): its place
/// under its parent's group, its id in a guarded namespace (`by_id`: 1
/// there, 0 elsewhere — the key is multiplied by it, no branch), a group
/// not followed under a copy of a held mount. A link that cannot be read
/// (NULL) ends its list.
struct Subtree<'a> {
    o: &'a Offs,
    by_id: u64,
}

impl Subtree<'_> {
    /// The mount whose `mnt_child` link is `n`, `None` at the end of the
    /// list whose head is `head`.
    #[inline(always)]
    fn child_at(&self, head: *const u8, n: *const u8) -> Option<*const u8> {
        if n.is_null() || n == head {
            None
        } else {
            Some((n as usize).wrapping_sub(self.o.mnt_child as usize) as *const u8)
        }
    }
}

impl Tree for Subtree<'_> {
    type M = *const u8;
    #[inline(always)]
    fn first_child(&self, m: *const u8) -> Option<*const u8> {
        let head = unsafe { m.add(self.o.mnt_mounts as usize) };
        self.child_at(head, unsafe { peek_ptr(head) })
    }
    #[inline(always)]
    fn next_sibling(&self, m: *const u8) -> Option<*const u8> {
        let parent = self.parent(m);
        let head = unsafe { parent.add(self.o.mnt_mounts as usize) };
        self.child_at(head, unsafe { peek_ptr(m.add(self.o.mnt_child as usize)) })
    }
    #[inline(always)]
    fn parent(&self, m: *const u8) -> *const u8 {
        unsafe { peek_ptr(m.add(self.o.mnt_parent as usize)) }
    }
    #[inline(always)]
    fn below(&self, m: *const u8) -> u64 {
        let o = self.o;
        let parent = self.parent(m);
        let group = unsafe { peek_u32(parent.add(o.mnt_group_id as usize)) };
        below_of(
            group,
            || unsafe { held_at(o, m, group) != 0 },
            || unsafe {
                let mnt = (m as usize).wrapping_add(o.mount_mnt as usize) as *const u8;
                mount_root_flags(o, mnt).0 & MG_HOLD != 0
            },
            || unsafe {
                let (dev, ino) = held_by_id(peek_u32(m.add(o.mnt_id as usize)));
                // outside a guarded namespace the key is (0, 0): never held
                let key = InodeKey {
                    dev: dev.wrapping_mul(self.by_id),
                    ino,
                };
                match MOUNT_HELD.get(&key) {
                    Some(f) => *f & HELD_REFUSE != 0,
                    None => false,
                }
            },
            || unsafe { MOUNT_GROUPS.get(&group).is_some() },
            || unsafe { parent_held_like(o, parent) },
        )
    }
}

/// The re-check 2 of #567 (N3): whether an unmount of the mount `real`
/// takes a held mount below it (`common::mount_guard::umount_below`,
/// `below_takes_held`): 1, else 0. Out of line, a BPF-to-BPF call: the
/// walk's states end with its frame (inlined, each of its exits carried
/// its own state into the rest of the hook, whose propagation walk 5.15's
/// verifier then explored once per exit, past its million instructions —
/// the round's first lab run on ubuntu2204). Whether `real`'s namespace is
/// guarded is read here, without a branch the walk would carry: a guarded
/// namespace's number is 1 to 3, made 1 or 0 by arithmetic.
#[inline(never)]
fn subtree_takes(o: &Offs, real: *const u8) -> u64 {
    let g = unsafe { guard_of(o, real) } as u64;
    let by_id = (g | g.wrapping_neg()) >> 63;
    below_takes_held(umount_below(&Subtree { o, by_id }, real), by_id != 0) as u64
}

/// The re-check 2 of #567 (N3): a held mount sits at the mount `m`'s place
/// under the peer group `group` (`MOUNT_HELD`'s [`held_by_place`] key): 1,
/// else 0. Out of line: the place's name buffer and keys live in its own
/// frame, not in [`subtree_takes`]'s (5.15 gives a chain of calls 512
/// bytes of stack).
#[inline(never)]
unsafe fn held_at(o: &Offs, m: *const u8, group: u32) -> u64 {
    // SAFETY: the body's 2021 unsafe context, made explicit (main.rs, "Unsafe code").
    unsafe {
        let (dev, ino) = place_key(o, m, group);
        MOUNT_HELD.get(&InodeKey { dev, ino }).is_some() as u64
    }
}

/// [`held_by_place`]'s key of the mount `m`'s place (its mountpoint's
/// parent directory and name) under the peer group `group`.
#[inline(always)]
unsafe fn place_key(o: &Offs, m: *const u8, group: u32) -> (u64, u64) {
    // SAFETY: the body's 2021 unsafe context, made explicit (main.rs, "Unsafe code").
    unsafe {
        let place = peek_ptr(m.add(o.mnt_mountpoint as usize));
        let dir = key_of(o, peek_ptr(place.add(o.d_parent as usize)));
        let mut name = NameKey::NONE;
        name_of(o, place, &mut name);
        held_by_place(group, dir.dev, dir.ino, &name)
    }
}

/// The re-check of #567 (N1): a mount is a copy of a held one — its
/// namespace's root, or sitting where a held mount sits (its place under
/// any group, `PLACE_ANY_GROUP`): a raw namespace's `/sys`, not a chroot's
/// own sysfs at `$T/sys`.
#[inline(always)]
unsafe fn parent_held_like(o: &Offs, m: *const u8) -> bool {
    // SAFETY: the body's 2021 unsafe context, made explicit (main.rs, "Unsafe code").
    unsafe {
        let up = peek_ptr(m.add(o.mnt_parent as usize));
        if up.is_null() || up == m {
            return true;
        }
        held_at(o, m, PLACE_ANY_GROUP) != 0
    }
}

/// The `MOUNT_HELD` flags of a mount (a `struct mount`) by its id.
#[inline(always)]
unsafe fn held_flags(o: &Offs, real: *const u8) -> u8 {
    // SAFETY: the body's 2021 unsafe context, made explicit (main.rs, "Unsafe code").
    unsafe {
        let (dev, ino) = held_by_id(peek_u32(real.add(o.mnt_id as usize)));
        match MOUNT_HELD.get(&InodeKey { dev, ino }) {
            Some(f) => *f,
            None => 0,
        }
    }
}

/// A dentry's inode key, as `stat(2)` gives it (a btrfs subvolume's
/// device), without a branch on a read: an unreadable dentry is the key
/// (0, 0), which no point has.
#[inline(always)]
unsafe fn key_of(o: &Offs, dentry: *const u8) -> InodeKey {
    // SAFETY: the body's 2021 unsafe context, made explicit (main.rs, "Unsafe code").
    unsafe {
        let inode = peek_ptr(dentry.add(o.d_inode as usize));
        let sb = peek_ptr(inode.add(o.i_sb as usize));
        let s_dev = peek_u32(sb.add(o.s_dev as usize));
        let ino = peek_u64(inode.add(o.i_ino as usize));
        // the review of #567 (d): `common::mount_guard::inode_key` — a btrfs
        // subvolume's own device (the magic read only with the offsets known)
        let mut magic = 0;
        let mut anon = 0;
        if o.btrfs_vfs != 0 {
            magic = peek_u64(sb.add(o.s_magic as usize));
            if magic == BTRFS_SUPER_MAGIC {
                let bi = (inode as usize).wrapping_sub(o.btrfs_vfs as usize) as *const u8;
                let root = peek_ptr(bi.add(o.btrfs_root as usize));
                anon = peek_u32(root.add(o.btrfs_anon as usize));
            }
        }
        let (dev, ino) = inode_key(s_dev, magic, ino, anon);
        InodeKey { dev, ino }
    }
}

/// The protected flags of a dentry (0 for none or unreadable).
#[inline(always)]
unsafe fn flags_at(key: &InodeKey) -> u8 {
    // SAFETY: the body's 2021 unsafe context, made explicit (main.rs, "Unsafe code").
    unsafe {
        match MOUNT_PROTECTED.get(key) {
            Some(f) => *f,
            None => 0,
        }
    }
}

/// The magic of a dentry's file system (0 when unreadable).
#[inline(always)]
unsafe fn magic_of(o: &Offs, dentry: *const u8) -> u64 {
    // SAFETY: the body's 2021 unsafe context, made explicit (main.rs, "Unsafe code").
    unsafe {
        let inode = peek_ptr(dentry.add(o.d_inode as usize));
        let sb = peek_ptr(inode.add(o.i_sb as usize));
        peek_u64(sb.add(o.s_magic as usize))
    }
}

/// A dentry's name as the allow list compares it, into `out`: its length
/// and the hash of its first 15 bytes, read by the kernel's string copy
/// into a zeroed 16-byte buffer (it stops at the name's NUL).
#[inline(always)]
unsafe fn name_of(o: &Offs, dentry: *const u8, out: &mut NameKey) {
    // SAFETY: the body's 2021 unsafe context, made explicit (main.rs, "Unsafe code").
    unsafe {
        let qstr = dentry.add(o.d_name as usize);
        out.len = peek_u32(qstr.add(o.qstr_len as usize));
        let name = peek_ptr(qstr.add(o.qstr_name as usize));
        // two words, not sixteen bytes: zeroed by two stores, never a call to
        // the `memset` subprogram (its frame counts against 5.15's 512 bytes of
        // a call chain: the re-check 2 of #567, `held_at` below `subtree_takes`)
        let mut words = core::mem::MaybeUninit::<[u64; 2]>::uninit();
        crate::zero::zero(words.as_mut_ptr());
        let _ = generated::bpf_probe_read_kernel_str(
            words.as_mut_ptr() as *mut c_void,
            16,
            name as *const c_void,
        );
        out.h = fnv16(&*(words.as_ptr() as *const [u8; 16]));
    }
}

/// A kernel string as the allow list compares it (a file-system type),
/// into `out`, as [`name_of`] reads a name; its length the copy's.
#[inline(always)]
unsafe fn string_key(s: *const u8, out: &mut NameKey) {
    // SAFETY: the body's 2021 unsafe context, made explicit (main.rs, "Unsafe code").
    unsafe {
        *out = NameKey::NONE;
        if s.is_null() {
            return;
        }
        let mut buf = [0u8; 16];
        let n = generated::bpf_probe_read_kernel_str(
            buf.as_mut_ptr() as *mut c_void,
            16,
            s as *const c_void,
        );
        if n > 0 {
            out.len = (n - 1) as u32;
            out.h = fnv16(&buf);
        }
    }
}

/// The type of a dentry's file system (`super_block.s_type->name`), into
/// `out`.
#[inline(always)]
unsafe fn fstype_of(o: &Offs, dentry: *const u8, out: &mut NameKey) {
    // SAFETY: the body's 2021 unsafe context, made explicit (main.rs, "Unsafe code").
    unsafe {
        let (Some(o_type), Some(o_name)) = (
            off_opt!(SUPER_BLOCK_S_TYPE_OFFSET),
            off_opt!(FILE_SYSTEM_TYPE_NAME_OFFSET),
        ) else {
            *out = NameKey::NONE;
            return;
        };
        let inode = peek_ptr(dentry.add(o.d_inode as usize));
        let sb = peek_ptr(inode.add(o.i_sb as usize));
        let fs_type = peek_ptr(sb.add(o_type & 0xfff));
        string_key(peek_ptr(fs_type.add(o_name & 0xff)), out)
    }
}

/// The `struct mount` of a `vfsmount` (`real_mount()`).
#[inline(always)]
fn real_mount(o: &Offs, mnt: *const u8) -> *const u8 {
    (mnt as usize).wrapping_sub(o.mount_mnt as usize) as *const u8
}

/// What the hook reads at a `struct path` the kernel resolved, into `p`;
/// the target dentry's key. `None` when the path cannot be read (counted).
#[inline(always)]
unsafe fn point_of(
    o: &Offs,
    path: *const u8,
    hook: u32,
    q: &mut Query,
    out: &mut InodeKey,
) -> bool {
    // SAFETY: the body's 2021 unsafe context, made explicit (main.rs, "Unsafe code").
    unsafe {
        let host = q.host;
        let p = &mut q.point;
        if path.is_null() {
            crate::fail_open::bump(hook);
            return false;
        }
        let mut mnt = peek_ptr(path.add(o.path_mnt as usize));
        let target = peek_ptr(path.add(o.path_dentry as usize));
        if mnt.is_null() || target.is_null() {
            crate::fail_open::bump(hook);
            return false;
        }
        let key = key_of(o, target);
        p.flags = flags_at(&key);
        // Down the mounts stacked at the target to the directory below them.
        let mut d = target;
        let mut stack = 0u8;
        let mut i = 0u32;
        while i < MAX_STACK {
            let root = peek_ptr(mnt.add(o.mnt_root as usize));
            let real = real_mount(o, mnt);
            let parent = peek_ptr(real.add(o.mnt_parent as usize));
            let below = peek_ptr(real.add(o.mnt_mountpoint as usize));
            // not a mount's root, the namespace's root mount, or unreadable
            if root != d || parent.is_null() || parent == real || below.is_null() {
                break;
            }
            if stack == 0 {
                p.covered = magic_of(o, d) as u32;
            }
            d = below;
            mnt = (parent as usize).wrapping_add(o.mount_mnt as usize) as *const u8;
            stack += 1;
            i += 1;
        }
        p.stack = stack;
        p.magic = magic_of(o, d) as u32;
        let pk = key_of(o, d);
        let mut below = if stack > 0 {
            flags_at(&pk) & (MG_OWN | MG_VIEW)
        } else {
            0
        };
        // The point's first names and how far its file system's root is.
        let d1 = peek_ptr(d.add(o.d_parent as usize));
        let d2 = peek_ptr(d1.add(o.d_parent as usize));
        let d3 = peek_ptr(d2.add(o.d_parent as usize));
        name_of(o, d, &mut p.names[0]);
        name_of(o, d1, &mut p.names[1]);
        name_of(o, d2, &mut p.names[2]);
        p.depth = if d1 == d {
            0
        } else if d2 == d1 {
            1
        } else if d3 == d2 {
            2
        } else if peek_ptr(d3.add(o.d_parent as usize)) == d3 {
            3
        } else {
            DEPTH_DEEPER
        };
        // Up the point's ancestors: the agent's directories and the views
        // among them (the root's parent is itself: a repeat changes nothing).
        let mut cur = d;
        let mut j = 0u32;
        while j < MAX_WALK {
            cur = peek_ptr(cur.add(o.d_parent as usize));
            below |= flags_at(&key_of(o, cur)) & (MG_OWN | MG_VIEW);
            j += 1;
        }
        p.below = below;
        // From another namespace: the point's file system one of PID 1's views'
        // own (the agent's `(device, 0)` entries) — read last, after the walks
        if !host && is_view_magic(p.magic) {
            p.host_view_sb = flags_at(&InodeKey {
                dev: pk.dev,
                ino: 0,
            }) & MG_VIEW
                != 0;
        }
        *out = key;
        true
    }
}

/// The protected flags at the root of a mount (`vfsmount.mnt_root`), and
/// that root's key.
#[inline(always)]
unsafe fn mount_root_flags(o: &Offs, mnt: *const u8) -> (u8, InodeKey) {
    // SAFETY: the body's 2021 unsafe context, made explicit (main.rs, "Unsafe code").
    unsafe {
        let root = peek_ptr(mnt.add(o.mnt_root as usize));
        let key = key_of(o, root);
        (flags_at(&key), key)
    }
}

/// Sign the verdict and return the hook's answer.
#[inline(always)]
fn answer(verdict: Verdict, op: u8, key: InodeKey, p: &Point, reach: u8) -> i32 {
    answer_parts(
        verdict,
        op,
        key,
        view_of(p.magic),
        (p.stack & 0xf) | reach << 4,
    )
}

/// [`answer`] by its parts: the view and the record's `stack` byte (the
/// mounts covered, the reach in its high nibble).
#[inline(always)]
fn answer_parts(verdict: Verdict, op: u8, key: InodeKey, view: u8, stack: u8) -> i32 {
    let (operation, why, ret) = match verdict {
        Verdict::Allow => return 0,
        Verdict::Refuse(w) => (FS_OP_MOUNT, w, -EPERM),
        Verdict::Window(w) => (FS_OP_MOUNT_WINDOW, w, 0),
        Verdict::Noted(w) => (FS_OP_MOUNT_NOTED, w, 0),
    };
    crate::inode_protect::emit_attempt(
        operation,
        InodeKey {
            dev: record_dev(key.dev, op, why, view, stack),
            ino: key.ino,
        },
    );
    ret
}

/// A query with nothing read but the caller and where its target is
/// (`guard`: the target's guarded namespace, 0 for a change that
/// propagates into one).
#[inline(always)]
fn query(op: u8, c: &Caller, guard: u8) -> Query {
    Query {
        op,
        host: guard != 0,
        reaches: guard == 0,
        privileged: c.privileged,
        init: (bpf_get_current_pid_tgid() >> 32) == 1,
        window: crate::inode_protect::override_active(),
        point: Point::EMPTY,
        fstype: NameKey::NONE,
        held: false,
        noted: false,
        shutdown: false,
        kernel: false,
        src_root: true,
        restrict: false,
        lock_maker: false,
        lock_step: false,
    }
}

/// The reach a record carries: the guarded namespace's own, or
/// `REACH_OTHER_NS` for a change that propagates into one.
#[inline(always)]
fn reach_of_caller(c: &Caller) -> u8 {
    if c.guard != 0 {
        reach_in(c.guard)
    } else {
        REACH_OTHER_NS
    }
}

/// Lot 1.1 (F8b-1): the target lands in a guarded namespace, or its change
/// propagates into one (`common::mount_guard::target_reach`): 1, else 0.
/// Out of line, a BPF-to-BPF call: the walk's states end with its frame,
/// and the entry tail-calls its stage right after it.
#[inline(never)]
fn lands_guarded(o: &Offs, real: *const u8) -> u64 {
    // SAFETY: `target_of` reads the kernel's objects through
    // `bpf_probe_read_kernel` only (a fault reads zeros, never a trap)
    unsafe { target_of(o, real) }.is_some() as u64
}

/// The guard and the reach of a target the entry found landing in a
/// guarded namespace or propagating into one ([`lands_guarded`]), as its
/// stage reads them again without the walk: the namespace that owns the
/// target, or — none guarded — a propagation into one.
#[inline(always)]
unsafe fn landed(o: &Offs, real: *const u8) -> (u8, u8) {
    // SAFETY: `guard_of` reads through `bpf_probe_read_kernel` only
    let guard = unsafe { guard_of(o, real) };
    if guard != 0 {
        (guard, reach_in(guard))
    } else {
        (0, REACH_OTHER_NS)
    }
}

/// `int sb_mount(const char *dev_name, const struct path *path, const char
/// *type, unsigned long flags, void *data)`: `mount(2)` (a new mount, a
/// bind, a move, a remount, a propagation change). `path` is the target as
/// the kernel resolved it, `type` the kernel's copy of the type string.
///
/// Lot 1.1 (F8b-1): the entry — what is cheap, then where the target lands
/// (the walk); the judge is a stage it tail-calls ([`MOUNT_SB_STAGES`]),
/// each program verified on its own.
#[lsm(hook = "sb_mount")]
pub fn mount_guard_sb_mount(ctx: LsmContext) -> i32 {
    // SAFETY: the context is the hook's; every kernel read goes through
    // `bpf_probe_read_kernel`, and a tail call never returns on success
    unsafe { try_sb_mount(&ctx) }
}

#[inline(always)]
unsafe fn try_sb_mount(ctx: &LsmContext) -> i32 {
    // SAFETY: `ctx.arg` reads the trampoline's argument slots, which the
    // verifier bounds by the hook's prototype; the pointers read are only
    // passed to `bpf_probe_read_kernel`
    unsafe {
        let flags: u64 = ctx.arg(3);
        match sb_mount_route(flags) {
            SbRoute::Pass => return 0,
            SbRoute::Propagate => {
                MOUNT_SB_STAGES.tail_call(ctx, STAGE_PROPAGATE);
                // the stage is not in its slot: let through, counted
                crate::fail_open::bump(hook::SB_MOUNT);
                return 0;
            }
            SbRoute::Point => {}
        }
        let Some(c) = caller(hook::SB_MOUNT) else {
            return 0;
        };
        if !c.privileged {
            return 0;
        }
        let Some(o) = Offs::load() else {
            crate::fail_open::bump(hook::SB_MOUNT);
            return 0;
        };
        let path: *const u8 = ctx.arg(1);
        if path.is_null() {
            crate::fail_open::bump(hook::SB_MOUNT);
            return 0;
        }
        let mnt = peek_ptr(path.add(o.path_mnt as usize));
        if mnt.is_null() {
            crate::fail_open::bump(hook::SB_MOUNT);
            return 0;
        }
        // the namespace that owns the target, not the caller's
        if lands_guarded(o, real_mount(o, mnt)) == 0 {
            return 0;
        }
        MOUNT_SB_STAGES.tail_call(ctx, STAGE_POINT);
        crate::fail_open::bump(hook::SB_MOUNT);
        0
    }
}

/// Lot 1.1 (F8b-1): `sb_mount`'s stage judging where a mount lands —
/// tail-called by [`mount_guard_sb_mount`] once the target lands in a
/// guarded namespace or propagates into one; never attached.
#[lsm(hook = "sb_mount")]
pub fn mount_guard_sb_mount_point(ctx: LsmContext) -> i32 {
    // SAFETY: as the entry's
    unsafe { try_sb_mount_point(&ctx) }
}

#[inline(always)]
unsafe fn try_sb_mount_point(ctx: &LsmContext) -> i32 {
    // SAFETY: `ctx.arg` reads the hook's bounded argument slots; every
    // kernel pointer is read through `bpf_probe_read_kernel` (a fault reads
    // zeros); the map pointers are valid for the program's run
    unsafe {
        let flags: u64 = ctx.arg(3);
        let op = mount_op(flags);
        if op == MG_OP_PASS {
            return 0;
        }
        let Some(c) = caller(hook::SB_MOUNT) else {
            return 0;
        };
        if !c.privileged {
            return 0;
        }
        let Some(o) = Offs::load() else {
            crate::fail_open::bump(hook::SB_MOUNT);
            return 0;
        };
        let path: *const u8 = ctx.arg(1);
        if path.is_null() {
            crate::fail_open::bump(hook::SB_MOUNT);
            return 0;
        }
        let mnt = peek_ptr(path.add(o.path_mnt as usize));
        if mnt.is_null() {
            crate::fail_open::bump(hook::SB_MOUNT);
            return 0;
        }
        let real = real_mount(o, mnt);
        let (guard, reach) = landed(o, real);
        if op == MG_OP_REMOUNT_BIND {
            // the review of #567 (F3): one mount's flags, in its own namespace
            // only (they never propagate)
            if guard == 0 || flags & (MS_RDONLY | MS_NOEXEC) == 0 {
                return 0;
            }
            let (rflags, key) = mount_root_flags(o, mnt);
            if held_flags(o, real) & HELD_REFUSE == 0 || rflags & MG_HOLD == 0 {
                return 0;
            }
            let mut q = query(MG_OP_REMOUNT_BIND, &c, guard);
            q.held = true;
            q.restrict = true;
            q.shutdown = shutdown_stage();
            return answer(decide(&q), MG_OP_REMOUNT_BIND, key, &q.point, reach);
        }
        // One decision shape for the verifier: a bind, and an old-API move
        // made elsewhere (judged where it lands), are a mount whose type is not
        // known (`decide`'s own arms for them); the record keeps the operation.
        let mut q = query(MG_OP_MOUNT, &c, guard);
        if op == MG_OP_MOVE_OLD && guard != 0 {
            // refused whatever it moves (but systemd-shutdown's switch to
            // /run/initramfs): the target's key for the record only
            q.op = MG_OP_MOVE_OLD;
            q.shutdown = shutdown_stage();
            let key = key_of(o, peek_ptr(path.add(o.path_dentry as usize)));
            return answer(decide(&q), op, key, &q.point, reach);
        }
        let mut key = InodeKey { dev: 0, ino: 0 };
        if !point_of(o, path, hook::SB_MOUNT, &mut q, &mut key) {
            return 0;
        }
        if op == MG_OP_MOUNT {
            let ty: *const u8 = ctx.arg(2);
            string_key(ty, &mut q.fstype);
        }
        answer(decide(&q), op, key, &q.point, reach)
    }
}

/// Lot 1.1 (F8b-1): `sb_mount`'s stage for a change of propagation
/// (`MS_SHARED`, `MS_PRIVATE`, `MS_SLAVE`, `MS_UNBINDABLE`) — counted for
/// the refresh, and judged where it reaches the pin directory's lock;
/// tail-called by [`mount_guard_sb_mount`], never attached.
#[lsm(hook = "sb_mount")]
pub fn mount_guard_sb_mount_propagate(ctx: LsmContext) -> i32 {
    // SAFETY: as the entry's
    unsafe { try_sb_mount_propagate(&ctx) }
}

#[inline(always)]
unsafe fn try_sb_mount_propagate(ctx: &LsmContext) -> i32 {
    // SAFETY: `ctx.arg` reads the hook's bounded argument slots; the path
    // is only read through `bpf_probe_read_kernel`
    unsafe {
        let flags: u64 = ctx.arg(3);
        if sb_mount_route(flags) != SbRoute::Propagate {
            return 0;
        }
        note_propagation_change(ctx);
        // lot 359 (the re-check 3 of #567, N4): one that reaches the pin
        // directory's lock is judged
        let path: *const u8 = ctx.arg(1);
        let r = lock_propagation(path, flags);
        if r == 0 {
            return 0;
        }
        lock_answer(path, r)
    }
}

/// Lot 1.1: a propagation change the kernel makes on the mount `m` (a
/// `struct mount`), from `crate::mount_setattr`'s fentry — counted
/// (`common::mount_guard::propagation_counts`) when the guard is armed and
/// the mount is in a guarded namespace, in a peer group [`MOUNT_GROUPS`]
/// holds, or is the pin directory's lock or a copy of it ([`MG_LOCK`] at
/// its root): the refresh woken ([`note_regroup`]) and the change counted
/// for the agent (`CONF_PROPAGATED`).
#[inline(always)]
pub(crate) fn propagation_change(m: *const u8) {
    match MOUNT_GUARD_CONF.get(0) {
        Some(h) if *h != 0 => {}
        _ => return,
    }
    let Some(o) = Offs::load() else {
        return;
    };
    // SAFETY: `m` is the kernel's `struct mount` the traced function was
    // given; every read goes through `bpf_probe_read_kernel` (a fault reads
    // zeros: no namespace, no group, no flags)
    let (in_ns, guard, known, lock) = unsafe {
        let ns = peek_ptr(m.add(o.mnt_ns as usize));
        let k = Kernel(o);
        let group = k.group(m);
        let mnt = (m as usize).wrapping_add(o.mount_mnt as usize) as *const u8;
        (
            !ns.is_null(),
            guard_of(o, m),
            group != 0 && k.known(group),
            mount_root_flags(o, mnt).0 & MG_LOCK != 0,
        )
    };
    if propagation_counts(in_ns, guard, known, lock) {
        note_regroup();
        if let Some(v) = MOUNT_GUARD_CONF.get_ptr_mut(CONF_PROPAGATED) {
            // SAFETY: the map's own slot, valid for the program's run (two
            // changes at once may count one: any move of the count wakes)
            unsafe { *v = (*v).wrapping_add(1) };
        }
    }
}

/// The re-check of #567 (N1): a propagation change let through — counted
/// ([`note_regroup`]) when its mount is in a guarded namespace, or in a
/// peer group [`MOUNT_GROUPS`] holds (a master made private hands its
/// slaves, a guarded one among them, to another master).
#[inline(always)]
unsafe fn note_propagation_change(ctx: &LsmContext) {
    // SAFETY: the body's 2021 unsafe context, made explicit (main.rs, "Unsafe code").
    unsafe {
        let Some(o) = Offs::load() else {
            return;
        };
        let path: *const u8 = ctx.arg(1);
        if path.is_null() {
            return;
        }
        let mnt = peek_ptr(path.add(o.path_mnt as usize));
        if mnt.is_null() {
            return;
        }
        let real = real_mount(o, mnt);
        let k = Kernel(o);
        let group = k.group(real);
        if k.guard(real) != 0 || (group != 0 && k.known(group)) {
            note_regroup();
        }
    }
}

/// Lot 359 (the re-check 3 of #567, N4): a change of propagation (`mount(2)`
/// with `MS_SHARED`, `MS_PRIVATE`, `MS_SLAVE`, `MS_UNBINDABLE`) that
/// reaches the pin directory's lock (`common::mount_guard::lock_touched`):
/// made on the lock or a copy of it (a mount whose root and mount point are
/// the pin directory's one dentry, [`MG_LOCK`]), judged where its parent's
/// group lands (the place an unmount propagates through); or a recursive
/// `MS_SHARED` or `MS_PRIVATE` on a mount rooted above it
/// ([`MG_LOCK_ABOVE`]) in PID 1's namespace (the review of #569, F1a, and
/// its re-check, N1: in a raw namespace — runc's `rootfsPropagation:
/// rshared` — it changes that namespace's own copies). Refused but the
/// maker's own step on the host's lock (`MS_UNBINDABLE`, `lock_step_at`)
/// and `systemd-shutdown`'s `switch_root()` (`lock_shutdown_step`). A target that is not a mount's
/// root is the kernel's `EINVAL`: let through. Out of line, a BPF-to-BPF
/// call: its walk's states end with its frame.
#[inline(never)]
fn lock_propagation(path: *const u8, flags: u64) -> u64 {
    unsafe { try_lock_propagation(path, flags) }
}

#[inline(always)]
unsafe fn try_lock_propagation(path: *const u8, flags: u64) -> u64 {
    // SAFETY: the body's 2021 unsafe context, made explicit (main.rs, "Unsafe code").
    unsafe {
        let Some(c) = caller(hook::SB_MOUNT) else {
            return 0;
        };
        if !c.privileged {
            return 0;
        }
        let Some(o) = Offs::load() else {
            crate::fail_open::bump(hook::SB_MOUNT);
            return 0;
        };
        if path.is_null() {
            crate::fail_open::bump(hook::SB_MOUNT);
            return 0;
        }
        let mnt = peek_ptr(path.add(o.path_mnt as usize));
        let target = peek_ptr(path.add(o.path_dentry as usize));
        if mnt.is_null() || target.is_null() {
            crate::fail_open::bump(hook::SB_MOUNT);
            return 0;
        }
        let root = peek_ptr(mnt.add(o.mnt_root as usize));
        if root != target {
            return 0;
        }
        let real = real_mount(o, mnt);
        let key = key_of(o, root);
        let rflags = flags_at(&key);
        let on_lock = rflags & MG_LOCK != 0 && peek_ptr(real.add(o.mnt_mountpoint as usize)) == root;
        let above = rflags & MG_LOCK_ABOVE != 0;
        // the widest first (as in PID 1's namespace), the namespace read after
        if !lock_touched(flags, on_lock, above, GUARD_HOST) {
            return 0;
        }
        let at = if on_lock {
            peek_ptr(real.add(o.mnt_parent as usize))
        } else {
            real
        };
        if at.is_null() {
            crate::fail_open::bump(hook::SB_MOUNT);
            return 0;
        }
        let Some((guard, reach)) = target_of(o, at) else {
            return 0;
        };
        // the review of #569 (F1a) and its re-check (N1): a recursive
        // MS_SHARED or MS_PRIVATE above it, in PID 1's namespace only
        if !lock_touched(flags, on_lock, above, guard) {
            return 0;
        }
        // the maker's own step on the host's lock (F1c), or systemd-shutdown's
        // switch_root(); the verdict without a `Query` or `decide` (whose
        // allow-list call put this chain past 5.15's and 6.8's 512 bytes of
        // stack: the lab's first verifier check of this lot, 576)
        let exempt = (lock_step_at(flags, on_lock, guard) && lock_maker_now())
            || (lock_shutdown_step(flags, on_lock) && shutdown_stage());
        let kind = match lock_verdict(
            c.privileged,
            guard != 0,
            guard == 0,
            exempt,
            crate::inode_protect::override_active(),
        ) {
            Verdict::Refuse(_) => LOCK_REFUSE,
            Verdict::Window(_) => LOCK_WINDOW,
            _ => return 0,
        };
        kind | (view_of(magic_of(o, root) as u32) as u64) << 8 | ((reach << 4) as u64) << 16
    }
}

/// [`lock_propagation`]'s answer: refused, let through in the window (and
/// 0: let through unrecorded).
const LOCK_REFUSE: u64 = 1;
const LOCK_WINDOW: u64 = 2;

/// The record and the answer of [`lock_propagation`]'s verdict `r` (its
/// kind, the view, the reach) — signed here, in the hook's own frame: the
/// record's ring entry, zeroed by a call of its own, would have put the
/// out-of-line judge's chain at 5.15's and 6.8's 512 bytes of stack.
#[inline(always)]
unsafe fn lock_answer(path: *const u8, r: u64) -> i32 {
    // SAFETY: the body's 2021 unsafe context, made explicit (main.rs, "Unsafe code").
    unsafe {
        let Some(o) = Offs::load() else {
            return 0;
        };
        let mnt = peek_ptr(path.add(o.path_mnt as usize));
        let key = key_of(o, peek_ptr(mnt.add(o.mnt_root as usize)));
        let why = northnarrow_common::mount_guard::MG_WHY_LOCK;
        let v = if r & 3 == LOCK_WINDOW {
            Verdict::Window(why)
        } else {
            Verdict::Refuse(why)
        };
        answer_parts(v, MG_OP_PROPAGATE, key, (r >> 8) as u8, (r >> 16) as u8)
    }
}

/// `int move_mount(const struct path *from_path, const struct path
/// *to_path)`: `move_mount(2)` — a detached mount (`fsmount`, `open_tree`)
/// attached at `to_path`, or an attached one moved there.
///
/// Lot 1.1 (F8b-1): the entry — the source (a held mount, or a peer copy of
/// one, moved away), then where the target lands (the walk); the judge of
/// the landing point is a stage it tail-calls ([`MOUNT_MOVE_STAGES`]).
#[lsm(hook = "move_mount")]
pub fn mount_guard_move_mount(ctx: LsmContext) -> i32 {
    // SAFETY: the context is the hook's; every kernel read goes through
    // `bpf_probe_read_kernel`, and a tail call never returns on success
    unsafe { try_move_mount(&ctx) }
}

#[inline(always)]
unsafe fn try_move_mount(ctx: &LsmContext) -> i32 {
    // SAFETY: `ctx.arg` reads the hook's bounded argument slots; every
    // kernel pointer is read through `bpf_probe_read_kernel` (a fault reads
    // zeros); the map pointers are valid for the program's run
    unsafe {
        let Some(c) = caller(hook::MOVE_MOUNT) else {
            return 0;
        };
        if !c.privileged {
            return 0;
        }
        let Some(o) = Offs::load() else {
            crate::fail_open::bump(hook::MOVE_MOUNT);
            return 0;
        };
        let from: *const u8 = ctx.arg(0);
        let to: *const u8 = ctx.arg(1);
        if from.is_null() || to.is_null() {
            crate::fail_open::bump(hook::MOVE_MOUNT);
            return 0;
        }
        let from_mnt = peek_ptr(from.add(o.path_mnt as usize));
        let from_dentry = peek_ptr(from.add(o.path_dentry as usize));
        let to_mnt = peek_ptr(to.add(o.path_mnt as usize));
        if from_mnt.is_null() || from_dentry.is_null() || to_mnt.is_null() {
            crate::fail_open::bump(hook::MOVE_MOUNT);
            return 0;
        }
        // An attached mount moved away: a held one, by its id (the review of
        // #567, F1: a copy of it is another mount), in the namespace it is in
        // (a move out of a shared parent is the kernel's EINVAL: only a
        // guarded namespace's own moves take a held mount away)
        let real = real_mount(o, from_mnt);
        let parent = peek_ptr(real.add(o.mnt_parent as usize));
        let attached = !parent.is_null() && parent != real;
        let from_guard = guard_of(o, real);
        if from_guard != 0 && attached {
            let key = key_of(o, from_dentry);
            if held_flags(o, real) & HELD_REFUSE != 0 && flags_at(&key) & MG_HOLD != 0 {
                let mut q = query(MG_OP_MOVE_MOUNT, &c, from_guard);
                q.held = true;
                q.shutdown = shutdown_stage();
                return answer(
                    decide(&q),
                    MG_OP_MOVE_MOUNT,
                    key,
                    &q.point,
                    reach_in(from_guard),
                );
            }
        }
        // Lot 1.1 (the review of #569, F2): or a peer copy of a held mount —
        // its own group and its root a held mount's (`HELD_ROOT`), in any
        // namespace: a raw namespace's copy of `/sys` moved under a private
        // mount, then unmounted there, takes the host's bpffs and its lock
        let group = Kernel(o).group(real);
        if attached && group != 0 {
            let root = peek_ptr(from_mnt.add(o.mnt_root as usize));
            let rk = key_of(o, root);
            let (dev, ino) = held_root(group, rk.dev, rk.ino);
            let hit = MOUNT_HELD.get(&InodeKey { dev, ino }).is_some();
            if moves_held_copy(attached, group, hit) {
                let reach = if from_guard != 0 {
                    reach_in(from_guard)
                } else {
                    REACH_OTHER_NS
                };
                return answer_parts(
                    copy_move_verdict(
                        true,
                        shutdown_stage(),
                        crate::inode_protect::override_active(),
                    ),
                    MG_OP_MOVE_MOUNT,
                    rk,
                    view_of(magic_of(o, root) as u32),
                    reach << 4,
                );
            }
        }
        // where it lands: the namespace that owns the target
        let to_real = real_mount(o, to_mnt);
        if lands_guarded(o, to_real) == 0 {
            return 0;
        }
        // re-check N1: a mount in a peer group moved into a guarded namespace,
        // or its group given to one there (`MOVE_MOUNT_SET_GROUP`, the same
        // hook): the refresh woken
        if guard_of(o, to_real) != 0 && group != 0 {
            note_regroup();
        }
        MOUNT_MOVE_STAGES.tail_call(ctx, STAGE_POINT);
        crate::fail_open::bump(hook::MOVE_MOUNT);
        0
    }
}

/// Lot 1.1 (F8b-1): `move_mount`'s stage judging where the mount lands —
/// tail-called by [`mount_guard_move_mount`] once the target lands in a
/// guarded namespace or propagates into one; never attached.
#[lsm(hook = "move_mount")]
pub fn mount_guard_move_mount_point(ctx: LsmContext) -> i32 {
    // SAFETY: as the entry's
    unsafe { try_move_mount_point(&ctx) }
}

#[inline(always)]
unsafe fn try_move_mount_point(ctx: &LsmContext) -> i32 {
    // SAFETY: `ctx.arg` reads the hook's bounded argument slots; every
    // kernel pointer is read through `bpf_probe_read_kernel` (a fault reads
    // zeros); the map pointers are valid for the program's run
    unsafe {
        let Some(c) = caller(hook::MOVE_MOUNT) else {
            return 0;
        };
        if !c.privileged {
            return 0;
        }
        let Some(o) = Offs::load() else {
            crate::fail_open::bump(hook::MOVE_MOUNT);
            return 0;
        };
        let from: *const u8 = ctx.arg(0);
        let to: *const u8 = ctx.arg(1);
        if from.is_null() || to.is_null() {
            crate::fail_open::bump(hook::MOVE_MOUNT);
            return 0;
        }
        let from_mnt = peek_ptr(from.add(o.path_mnt as usize));
        let from_dentry = peek_ptr(from.add(o.path_dentry as usize));
        let to_mnt = peek_ptr(to.add(o.path_mnt as usize));
        if from_mnt.is_null() || from_dentry.is_null() || to_mnt.is_null() {
            crate::fail_open::bump(hook::MOVE_MOUNT);
            return 0;
        }
        let real = real_mount(o, from_mnt);
        let parent = peek_ptr(real.add(o.mnt_parent as usize));
        let (guard, reach) = landed(o, real_mount(o, to_mnt));
        let mut q = query(MG_OP_MOVE_MOUNT, &c, guard);
        let mut key = InodeKey { dev: 0, ino: 0 };
        if !point_of(o, to, hook::MOVE_MOUNT, &mut q, &mut key) {
            return 0;
        }
        // the detached mount's own file system: the kernel's, not a string;
        // and its root its file system's (not a clone of a subdirectory)
        fstype_of(o, from_dentry, &mut q.fstype);
        let root = peek_ptr(from_mnt.add(o.mnt_root as usize));
        q.src_root = !root.is_null() && peek_ptr(root.add(o.d_parent as usize)) == root;
        // Lot 359 (the re-check 3 of #567, N4): onto the pin directory — its
        // lock's self-bind by its maker (`common::mount_guard::lock_bind`: the
        // kernel's objects compared, never a path), or the mount on the agent's
        // directory it always was
        if q.point.flags & MG_LOCK != 0 {
            let to_dentry = peek_ptr(to.add(o.path_dentry as usize));
            let head = real.add(o.mnt_mounts as usize);
            let first = peek_ptr(head);
            q.lock_step = lock_bind(&BindShape {
                detached: parent.is_null() || parent == real,
                at_root: root == from_dentry,
                onto_itself: !to_dentry.is_null() && root == to_dentry,
                childless: first.is_null() || first == head,
                target_lock: true,
                stack: q.point.stack,
                magic: q.point.magic,
                guard,
            });
            q.lock_maker = q.lock_step && lock_maker_now();
        }
        answer(decide(&q), MG_OP_MOVE_MOUNT, key, &q.point, reach)
    }
}

/// `int sb_umount(struct vfsmount *mnt, int flags)`: `umount(2)`, lazy or
/// not.
#[lsm(hook = "sb_umount")]
pub fn mount_guard_sb_umount(ctx: LsmContext) -> i32 {
    unsafe { try_sb_umount(&ctx) }
}

#[inline(always)]
unsafe fn try_sb_umount(ctx: &LsmContext) -> i32 {
    // SAFETY: the body's 2021 unsafe context, made explicit (main.rs, "Unsafe code").
    unsafe {
        let Some(c) = caller(hook::SB_UMOUNT) else {
            return 0;
        };
        if !c.privileged {
            return 0;
        }
        let Some(o) = Offs::load() else {
            crate::fail_open::bump(hook::SB_UMOUNT);
            return 0;
        };
        let mnt: *const u8 = ctx.arg(0);
        if mnt.is_null() {
            crate::fail_open::bump(hook::SB_UMOUNT);
            return 0;
        }
        let real = real_mount(o, mnt);
        // The re-check 2 of #567 (N3): what the kernel takes below the mount —
        // a lazy unmount (`MNT_DETACH`) calls this hook once, for the top, and
        // `umount_tree()` then takes the whole subtree, propagating the unmount
        // of each mount to the peers and slaves of its parent (`mount --rbind
        // /sys /mnt/s; umount -l /mnt/s` took the host's childless
        // `/sys/fs/bpf`, in every slave namespace too: the bpffs's last mount).
        // Read first, while one state enters the walk, in a function of its own
        // ([`subtree_takes`]: what the walk leaves behind is not carried on).
        let below = subtree_takes(o, real) != 0;
        let (flags, key) = mount_root_flags(o, mnt);
        // the namespace the unmounted mount is in
        let guard = guard_of(o, real);
        let mut q = query(MG_OP_UMOUNT, &c, guard);
        q.reaches = false;
        let mut reach = reach_in(guard);
        if below {
            q.held = true;
            if guard == 0 {
                q.reaches = true;
                reach = REACH_OTHER_NS;
            }
        }
        if guard != 0 && !q.held {
            // The review of #567 (F1): the mount itself, by its id — a copy of
            // `/`, `/run` or `/sys` (a backup's bind, a chroot's sysfs or its
            // `--bind /run`) is another mount, unmounted unjudged.
            let held = held_flags(o, real);
            let root_magic = magic_of(o, peek_ptr(mnt.add(o.mnt_root as usize))) as u32;
            if held & HELD_REFUSE != 0 && flags & MG_HOLD != 0 {
                q.held = true;
            } else if held & MG_NOTE != 0 && is_view_magic(root_magic) {
                // (its root still a kernel file system's: an id another mount
                // took since is not the one noted)
                q.noted = true;
            }
        }
        if !q.held {
            // An unmount propagates: the kernel takes the mount at the same
            // place of every peer of the parent's group, and of their slaves,
            // with no other LSM call — held when one there is (its place under
            // that group, `held_by_place`): an rbind copy of `/sys` unmounted
            // takes the host's childless `/sys/fs/cgroup`, a raw namespace's
            // copy its peer's. A parent in no peer group propagates nothing.
            let parent = peek_ptr(real.add(o.mnt_parent as usize));
            let group = if parent.is_null() || parent == real {
                0
            } else {
                peek_u32(parent.add(o.mnt_group_id as usize))
            };
            if group != 0 {
                let (dev, ino) = place_key(o, real, group);
                let mut hit = MOUNT_HELD.get(&InodeKey { dev, ino }).is_some();
                // Re-check N1: a parent in a group the map does not hold (one
                // regrouped since the refresh, its places keyed under its old
                // group) — its propagation walked for a mount a held one sits
                // under at this place (`HELD_UNDER`, the same hash `ino`)
                if !hit {
                    let s = umount_spread(&HeldUnder { k: Kernel(o), h: ino }, parent);
                    // undecided: the parent read only then — a copy of a held
                    // mount (its namespace's root, or at a held mount's place)
                    let held_root = flags & MG_HOLD != 0;
                    let like = matches!(s, Some(Spread::Unread))
                        && held_root
                        && parent_held_like(o, parent);
                    hit = umount_takes_held(s, held_root, like);
                }
                if hit {
                    q.held = true;
                    if guard == 0 {
                        q.reaches = true;
                        reach = REACH_OTHER_NS;
                    }
                }
            }
        }
        if !q.held && !q.noted {
            return 0;
        }
        // The cross-model check (C): PID 1's own exemption holds for its own
        // namespace's mounts, never for one of the agent's directories nor for
        // a mount of the agent's or the watchdog's namespace (`systemctl bind`'s
        // worker and PID 1 there are judged); the end of a shutdown is
        // `shutdown`.
        q.init = q.init && guard == GUARD_HOST && flags & MG_OWN == 0;
        q.shutdown = shutdown_stage();
        answer(decide(&q), MG_OP_UMOUNT, key, &q.point, reach)
    }
}

/// `int sb_pivotroot(const struct path *old_path, const struct path
/// *new_path)`: `pivot_root(2)`.
#[lsm(hook = "sb_pivotroot")]
pub fn mount_guard_sb_pivotroot(ctx: LsmContext) -> i32 {
    unsafe { try_sb_pivotroot(&ctx) }
}

#[inline(always)]
unsafe fn try_sb_pivotroot(ctx: &LsmContext) -> i32 {
    // SAFETY: the body's 2021 unsafe context, made explicit (main.rs, "Unsafe code").
    unsafe {
        let Some(c) = caller(hook::SB_PIVOTROOT) else {
            return 0;
        };
        if c.guard == 0 || !c.privileged {
            // a pivot changes its own namespace's root only
            return 0;
        }
        let Some(o) = Offs::load() else {
            crate::fail_open::bump(hook::SB_PIVOTROOT);
            return 0;
        };
        let new_root: *const u8 = ctx.arg(1);
        let key = if new_root.is_null() {
            InodeKey { dev: 0, ino: 0 }
        } else {
            key_of(o, peek_ptr(new_root.add(o.path_dentry as usize)))
        };
        let mut q = query(MG_OP_PIVOT, &c, c.guard);
        q.shutdown = shutdown_stage();
        answer(decide(&q), MG_OP_PIVOT, key, &q.point, reach_in(c.guard))
    }
}

/// `SB_RDONLY` (`include/linux/fs.h`): the super block's read-only flag.
const SB_RDONLY: u64 = 1;

/// `int reconfigure_super(struct fs_context *fc)` (fentry): the new flags
/// of the reconfigure (`fc->sb_flags`, `fc->sb_flags_mask`), for the
/// `sb_remount` that follows on this task. Observe only.
#[fentry(function = "reconfigure_super")]
pub fn mount_guard_reconfigure(ctx: FEntryContext) -> i32 {
    let fc: *const u8 = ctx.arg(0);
    if fc.is_null() {
        return 0;
    }
    let (Some(o_flags), Some(o_mask)) = (
        off_opt!(FS_CONTEXT_SB_FLAGS_OFFSET),
        off_opt!(FS_CONTEXT_SB_FLAGS_MASK_OFFSET),
    ) else {
        return 0;
    };
    let flags = unsafe { peek_u32(fc.add(o_flags & 0xfff)) } as u64;
    let mask = unsafe { peek_u32(fc.add(o_mask & 0xfff)) } as u64;
    let _ = MOUNT_RECONF.insert(&bpf_get_current_pid_tgid(), &(flags | mask << 32), 0);
    0
}

/// `int sb_remount(struct super_block *sb, void *mnt_opts)`: the review of
/// #567 (F3) — a super block reconfigured, through `reconfigure_super()`:
/// `mount(2)`'s `MS_REMOUNT` (after `sb_mount`) and `fsconfig(2)`'s
/// `FSCONFIG_CMD_RECONFIGURE` on an `fspick(2)` descriptor alike (the
/// emergency remount too, a kernel thread's). proc's `subset=pid` and
/// `hidepid`, a read-only state file system: refused for a held super
/// block, whatever namespace asks (it is the same super block).
#[lsm(hook = "sb_remount")]
pub fn mount_guard_sb_remount(ctx: LsmContext) -> i32 {
    unsafe { try_sb_remount(&ctx) }
}

#[inline(always)]
unsafe fn try_sb_remount(ctx: &LsmContext) -> i32 {
    // SAFETY: the body's 2021 unsafe context, made explicit (main.rs, "Unsafe code").
    unsafe {
        let Some(c) = caller(hook::SB_REMOUNT) else {
            return 0;
        };
        if !c.privileged {
            return 0;
        }
        let Some(o) = Offs::load() else {
            crate::fail_open::bump(hook::SB_REMOUNT);
            return 0;
        };
        let sb: *const u8 = ctx.arg(0);
        if sb.is_null() {
            crate::fail_open::bump(hook::SB_REMOUNT);
            return 0;
        }
        let dev = peek_u32(sb.add(o.s_dev as usize)) as u64;
        let key = InodeKey { dev, ino: 0 };
        if flags_at(&key) & MG_SB == 0 {
            return 0;
        }
        let mut q = query(MG_OP_REMOUNT, &c, c.guard);
        q.held = true;
        q.shutdown = shutdown_stage();
        q.kernel = kernel_thread();
        // made read-only — or its new flags unread (the fentry not attached):
        // taken as such
        let me = bpf_get_current_pid_tgid();
        q.restrict = match MOUNT_RECONF.get(&me) {
            Some(v) => {
                let v = *v;
                let _ = MOUNT_RECONF.remove(&me);
                (v >> 32) & SB_RDONLY != 0 && v & SB_RDONLY != 0
            }
            None => true,
        };
        // the view the super block is, for the record
        q.point.magic = peek_u64(sb.add(o.s_magic as usize)) as u32;
        answer(decide(&q), MG_OP_REMOUNT, key, &q.point, reach_of_caller(&c))
    }
}
