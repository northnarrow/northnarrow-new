//! Lot 357 — the mount guard: `sb_mount`, `move_mount`, `sb_umount` and
//! `sb_pivotroot`. A mount on, over or below the paths the agent depends on
//! is refused in PID 1's mount namespace.
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
//! directories, binaries and units, the directories above them), written
//! before the hooks attach; `MOUNT_GUARD_CONF` carries PID 1's mount and
//! user namespaces (0 = not armed: every hook lets through). A read that
//! fails lets the operation through, counted (`DENY_FAIL_OPEN`).
//!
//! A refusal is signed at each attempt (`FS_OP_MOUNT`, the attempt budget);
//! the signed trusted-installer window lets everything through and records
//! what it let through that is refused outside one (`FS_OP_MOUNT_WINDOW`).

use aya_ebpf::{
    cty::{c_int, c_void},
    helpers::{bpf_get_current_pid_tgid, bpf_get_current_task, generated},
    macros::{lsm, map},
    maps::{Array, HashMap},
    programs::LsmContext,
};
use northnarrow_common::fail_open::hook;
use northnarrow_common::mount_guard::{
    decide, fnv16, is_view_magic, mount_op, record_dev, view_of, NameKey, Point, Query, Verdict,
    DEPTH_DEEPER, MAX_STACK, MAX_WALK, MG_HOLD, MG_OP_MOUNT, MG_OP_MOVE_MOUNT, MG_OP_MOVE_OLD,
    MG_OP_PASS, MG_OP_PIVOT, MG_OP_UMOUNT, MG_OWN, MG_VIEW, REACH_OTHER_NS,
};
use northnarrow_common::wire::{InodeKey, FS_OP_MOUNT, FS_OP_MOUNT_WINDOW};

use crate::btf_offsets::{
    BTRFS_INODE_ROOT_OFFSET, BTRFS_INODE_VFS_INODE_OFFSET, BTRFS_ROOT_ANON_DEV_OFFSET,
    CRED_CAP_EFFECTIVE_OFFSET, CRED_USER_NS_OFFSET, DENTRY_D_INODE_OFFSET, DENTRY_D_NAME_OFFSET,
    DENTRY_D_PARENT_OFFSET, FILE_SYSTEM_TYPE_NAME_OFFSET, INODE_I_INO_OFFSET, INODE_I_SB_OFFSET,
    MNT_NAMESPACE_INUM_OFFSET, MOUNT_MNT_MOUNTPOINT_OFFSET, MOUNT_MNT_NS_OFFSET, MOUNT_MNT_OFFSET,
    MOUNT_MNT_PARENT_OFFSET, MOUNT_MNT_SHARE_OFFSET, MOUNT_MNT_SLAVE_LIST_OFFSET,
    MOUNT_MNT_SLAVE_OFFSET, NSPROXY_MNT_NS_OFFSET, PATH_DENTRY_OFFSET, PATH_MNT_OFFSET,
    QSTR_LEN_OFFSET, QSTR_NAME_OFFSET, SUPER_BLOCK_S_DEV_OFFSET, SUPER_BLOCK_S_MAGIC_OFFSET,
    SUPER_BLOCK_S_TYPE_OFFSET, TASK_STRUCT_CRED_OFFSET, TASK_STRUCT_NSPROXY_OFFSET,
    USER_NAMESPACE_INUM_OFFSET, VFSMOUNT_MNT_ROOT_OFFSET,
};

/// Linux `EPERM`; LSM hooks return `-errno` to deny.
const EPERM: c_int = 1;

/// `CAP_SYS_ADMIN`'s bit in `cred.cap_effective`.
const CAP_SYS_ADMIN: u64 = 1 << 21;

/// Entries of [`MOUNT_PROTECTED`]: the views, the agent's directories,
/// binaries, units and drop-in directories, and the directories above them
/// (some sixty on a host).
pub const MOUNT_PROTECTED_MAX: u32 = 256;

/// The protected points, by device and inode → `MG_ON` / `MG_OWN` /
/// `MG_VIEW` / `MG_HOLD`. Pinned by name with the hooks: a restarted agent
/// registers into the map the pinned programs read (as `PROTECTED_INODES`).
#[map]
pub static MOUNT_PROTECTED: HashMap<InodeKey, u8> = HashMap::pinned(MOUNT_PROTECTED_MAX, 0);

/// Slot 0: PID 1's mount namespace (its `ns.inum`), slot 1: PID 1's user
/// namespace. 0 in slot 0: not armed, every hook lets through. Pinned.
#[map]
pub static MOUNT_GUARD_CONF: Array<u64> = Array::pinned(2, 0);

/// A kernel `u64`, 0 when unreadable, without a branch on the result (the
/// helper writes zeros on a fault; see `task_scratch::peek_u64`).
#[inline(always)]
unsafe fn peek_u64(src: *const u8) -> u64 {
    let mut v = core::mem::MaybeUninit::<u64>::uninit();
    let _ =
        generated::bpf_probe_read_kernel(v.as_mut_ptr() as *mut c_void, 8, src as *const c_void);
    v.assume_init()
}

#[inline(always)]
unsafe fn peek_u32(src: *const u8) -> u32 {
    let mut v = core::mem::MaybeUninit::<u32>::uninit();
    let _ =
        generated::bpf_probe_read_kernel(v.as_mut_ptr() as *mut c_void, 4, src as *const c_void);
    v.assume_init()
}

#[inline(always)]
unsafe fn peek_ptr(src: *const u8) -> *const u8 {
    peek_u64(src) as *const u8
}

/// `BTRFS_SUPER_MAGIC`: a btrfs inode's device is its subvolume's (as
/// `stat(2)` gives it, `inode_dev::stat_dev`).
const BTRFS_SUPER_MAGIC: u64 = 0x9123_683E;

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
        Some(o)
    }
}

/// The caller: (in PID 1's mount namespace, `CAP_SYS_ADMIN` in PID 1's
/// user namespace, PID 1's mount namespace's `inum`). `None`: the guard is
/// not armed, or an offset is unknown (the agent attaches the hooks only
/// with every one resolved).
#[inline(always)]
unsafe fn caller(hook: u32) -> Option<(bool, bool, u64)> {
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
    let host = peek_u32(mnt_ns.add(o_mnt_inum & 0xfff)) as u64 == host_mnt;
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
    Some((
        host,
        cap & CAP_SYS_ADMIN != 0 && user_inum == host_user,
        host_mnt,
    ))
}

/// How many peers of a mount, and slaves of each, [`reaches_host`] reads.
const PEERS: u32 = 4;
const SLAVES: u32 = 2;

/// The coordinator's propagation point: whether what is done to the mount
/// `real` (a `struct mount`) is copied into PID 1's mount namespace — a
/// peer of it there (its `mnt_share` ring), or a slave there of it or of a
/// peer (`mnt_slave_list`). A ring or a list longer than the hook reads is
/// taken as reaching it (fail closed: the namespace is root's, and it chose
/// the size).
#[inline(always)]
unsafe fn reaches_host(o: &Offs, real: *const u8, host_mnt: u64) -> bool {
    let ns_of = |m: *const u8| -> u64 {
        peek_u32(peek_ptr(m.add(o.mnt_ns as usize)).add(o.mnt_ns_inum as usize)) as u64
    };
    let mut p = real;
    let mut i = 0u32;
    while i < PEERS {
        if ns_of(p) == host_mnt {
            return true;
        }
        // its slaves
        let head = p.add(o.mnt_slave_list as usize);
        let mut n = peek_ptr(head);
        let mut j = 0u32;
        while j < SLAVES {
            if n.is_null() || n == head {
                break;
            }
            let slave = (n as usize).wrapping_sub(o.mnt_slave as usize) as *const u8;
            if ns_of(slave) == host_mnt {
                return true;
            }
            n = peek_ptr(n);
            j += 1;
        }
        if !(n.is_null() || n == head) {
            // more slaves than read
            return true;
        }
        // the next peer
        let next = peek_ptr(p.add(o.mnt_share as usize));
        let peer = (next as usize).wrapping_sub(o.mnt_share as usize) as *const u8;
        if next.is_null() || peer == real {
            return false;
        }
        p = peer;
        i += 1;
    }
    // more peers than read
    true
}

/// A dentry's inode key, as `stat(2)` gives it (a btrfs subvolume's
/// device), without a branch on a read: an unreadable dentry is the key
/// (0, 0), which no point has.
#[inline(always)]
unsafe fn key_of(o: &Offs, dentry: *const u8) -> InodeKey {
    let inode = peek_ptr(dentry.add(o.d_inode as usize));
    let sb = peek_ptr(inode.add(o.i_sb as usize));
    let mut dev = peek_u32(sb.add(o.s_dev as usize));
    let ino = peek_u64(inode.add(o.i_ino as usize));
    if o.btrfs_vfs != 0 && peek_u64(sb.add(o.s_magic as usize)) == BTRFS_SUPER_MAGIC {
        let bi = (inode as usize).wrapping_sub(o.btrfs_vfs as usize) as *const u8;
        let root = peek_ptr(bi.add(o.btrfs_root as usize));
        let anon = peek_u32(root.add(o.btrfs_anon as usize));
        if anon != 0 {
            dev = anon;
        }
    }
    InodeKey {
        dev: dev as u64,
        ino,
    }
}

/// The protected flags of a dentry (0 for none or unreadable).
#[inline(always)]
unsafe fn flags_at(key: &InodeKey) -> u8 {
    match MOUNT_PROTECTED.get(key) {
        Some(f) => *f,
        None => 0,
    }
}

/// The magic of a dentry's file system (0 when unreadable).
#[inline(always)]
unsafe fn magic_of(o: &Offs, dentry: *const u8) -> u64 {
    let inode = peek_ptr(dentry.add(o.d_inode as usize));
    let sb = peek_ptr(inode.add(o.i_sb as usize));
    peek_u64(sb.add(o.s_magic as usize))
}

/// A dentry's name as the allow list compares it, into `out`: its length
/// and the hash of its first 15 bytes, read by the kernel's string copy
/// into a zeroed 16-byte buffer (it stops at the name's NUL).
#[inline(always)]
unsafe fn name_of(o: &Offs, dentry: *const u8, out: &mut NameKey) {
    let qstr = dentry.add(o.d_name as usize);
    out.len = peek_u32(qstr.add(o.qstr_len as usize));
    let name = peek_ptr(qstr.add(o.qstr_name as usize));
    let mut buf = [0u8; 16];
    let _ = generated::bpf_probe_read_kernel_str(
        buf.as_mut_ptr() as *mut c_void,
        16,
        name as *const c_void,
    );
    out.h = fnv16(&buf);
}

/// A kernel string as the allow list compares it (a file-system type),
/// into `out`, as [`name_of`] reads a name; its length the copy's.
#[inline(always)]
unsafe fn string_key(s: *const u8, out: &mut NameKey) {
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

/// The type of a dentry's file system (`super_block.s_type->name`), into
/// `out`.
#[inline(always)]
unsafe fn fstype_of(o: &Offs, dentry: *const u8, out: &mut NameKey) {
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

/// The protected flags at the root of a mount (`vfsmount.mnt_root`), and
/// that root's key.
#[inline(always)]
unsafe fn mount_root_flags(o: &Offs, mnt: *const u8) -> (u8, InodeKey) {
    let root = peek_ptr(mnt.add(o.mnt_root as usize));
    let key = key_of(o, root);
    (flags_at(&key), key)
}

/// Sign the verdict and return the hook's answer.
#[inline(always)]
fn answer(verdict: Verdict, op: u8, key: InodeKey, p: &Point, reach: u8) -> i32 {
    let (operation, why, ret) = match verdict {
        Verdict::Allow => return 0,
        Verdict::Refuse(w) => (FS_OP_MOUNT, w, -EPERM),
        Verdict::Window(w) => (FS_OP_MOUNT_WINDOW, w, 0),
    };
    crate::inode_protect::emit_attempt(
        operation,
        InodeKey {
            dev: record_dev(
                key.dev,
                op,
                why,
                view_of(p.magic),
                (p.stack & 0xf) | reach << 4,
            ),
            ino: key.ino,
        },
    );
    ret
}

/// A query with nothing read but the caller.
#[inline(always)]
fn query(op: u8, host: bool, privileged: bool) -> Query {
    Query {
        op,
        host,
        reaches: false,
        privileged,
        init: (bpf_get_current_pid_tgid() >> 32) == 1,
        window: crate::inode_protect::override_active(),
        point: Point::EMPTY,
        fstype: NameKey::NONE,
        held: false,
    }
}

/// `int sb_mount(const char *dev_name, const struct path *path, const char
/// *type, unsigned long flags, void *data)`: `mount(2)` (a new mount, a
/// bind, a move, a remount, a propagation change). `path` is the target as
/// the kernel resolved it, `type` the kernel's copy of the type string.
#[lsm(hook = "sb_mount")]
pub fn mount_guard_sb_mount(ctx: LsmContext) -> i32 {
    unsafe { try_sb_mount(&ctx) }
}

#[inline(always)]
unsafe fn try_sb_mount(ctx: &LsmContext) -> i32 {
    let flags: u64 = ctx.arg(3);
    let op = mount_op(flags);
    if op == MG_OP_PASS {
        return 0;
    }
    let Some((host, privileged, host_mnt)) = caller(hook::SB_MOUNT) else {
        return 0;
    };
    if !privileged {
        return 0;
    }
    let Some(o) = Offs::load() else {
        crate::fail_open::bump(hook::SB_MOUNT);
        return 0;
    };
    let path: *const u8 = ctx.arg(1);
    if !host && !path_reaches(o, path, host_mnt) {
        return 0;
    }
    let reach = if host { 0 } else { REACH_OTHER_NS };
    // One decision shape for the verifier: a bind, and an old-API move
    // made elsewhere (judged where it lands), are a mount whose type is not
    // known (`decide`'s own arms for them); the record keeps the operation.
    let mut q = query(MG_OP_MOUNT, host, privileged);
    q.reaches = !host;
    if op == MG_OP_MOVE_OLD && host {
        // refused whatever it moves: the target's key for the record only
        q.op = MG_OP_MOVE_OLD;
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

/// In another namespace: whether the mount `path` names (where a new mount
/// attaches) reaches PID 1's — judged first, so that a container's own
/// mounts (private, or slaves) cost one look at their mount.
#[inline(always)]
unsafe fn path_reaches(o: &Offs, path: *const u8, host_mnt: u64) -> bool {
    if path.is_null() {
        return false;
    }
    let mnt = peek_ptr(path.add(o.path_mnt as usize));
    !mnt.is_null() && reaches_host(o, real_mount(o, mnt), host_mnt)
}

/// `int move_mount(const struct path *from_path, const struct path
/// *to_path)`: `move_mount(2)` — a detached mount (`fsmount`, `open_tree`)
/// attached at `to_path`, or an attached one moved there.
#[lsm(hook = "move_mount")]
pub fn mount_guard_move_mount(ctx: LsmContext) -> i32 {
    unsafe { try_move_mount(&ctx) }
}

#[inline(always)]
unsafe fn try_move_mount(ctx: &LsmContext) -> i32 {
    let Some((host, privileged, host_mnt)) = caller(hook::MOVE_MOUNT) else {
        return 0;
    };
    if !privileged {
        return 0;
    }
    let Some(o) = Offs::load() else {
        crate::fail_open::bump(hook::MOVE_MOUNT);
        return 0;
    };
    let from: *const u8 = ctx.arg(0);
    let to: *const u8 = ctx.arg(1);
    if from.is_null() {
        crate::fail_open::bump(hook::MOVE_MOUNT);
        return 0;
    }
    let from_mnt = peek_ptr(from.add(o.path_mnt as usize));
    let from_dentry = peek_ptr(from.add(o.path_dentry as usize));
    if from_mnt.is_null() || from_dentry.is_null() {
        crate::fail_open::bump(hook::MOVE_MOUNT);
        return 0;
    }
    if !host && !path_reaches(o, to, host_mnt) {
        return 0;
    }
    let reach = if host { 0 } else { REACH_OTHER_NS };
    let mut q = query(MG_OP_MOVE_MOUNT, host, privileged);
    q.reaches = !host;
    // An attached mount moved away: its root's protection.
    let real = real_mount(o, from_mnt);
    let parent = peek_ptr(real.add(o.mnt_parent as usize));
    // (a move out of a shared parent is the kernel's EINVAL: only the
    // host's own moves take a protected mount away)
    if host && !parent.is_null() && parent != real {
        let key = key_of(o, from_dentry);
        if flags_at(&key) & MG_HOLD != 0 {
            q.held = true;
            return answer(decide(&q), MG_OP_MOVE_MOUNT, key, &q.point, reach);
        }
    }
    let mut key = InodeKey { dev: 0, ino: 0 };
    if !point_of(o, to, hook::MOVE_MOUNT, &mut q, &mut key) {
        return 0;
    }
    // the detached mount's own file system: the kernel's, not a string
    fstype_of(o, from_dentry, &mut q.fstype);
    answer(decide(&q), MG_OP_MOVE_MOUNT, key, &q.point, reach)
}

/// `int sb_umount(struct vfsmount *mnt, int flags)`: `umount(2)`, lazy or
/// not.
#[lsm(hook = "sb_umount")]
pub fn mount_guard_sb_umount(ctx: LsmContext) -> i32 {
    unsafe { try_sb_umount(&ctx) }
}

#[inline(always)]
unsafe fn try_sb_umount(ctx: &LsmContext) -> i32 {
    let Some((host, privileged, host_mnt)) = caller(hook::SB_UMOUNT) else {
        return 0;
    };
    if !privileged {
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
    let (flags, key) = mount_root_flags(o, mnt);
    if flags & MG_HOLD == 0 {
        return 0;
    }
    let mut q = query(MG_OP_UMOUNT, host, privileged);
    q.held = true;
    if !host {
        // an unmount propagates to the peers of the mount's parent
        let parent = peek_ptr(real_mount(o, mnt).add(o.mnt_parent as usize));
        if parent.is_null() || !reaches_host(o, parent, host_mnt) {
            return 0;
        }
        q.reaches = true;
    }
    let reach = if host { 0 } else { REACH_OTHER_NS };
    answer(decide(&q), MG_OP_UMOUNT, key, &q.point, reach)
}

/// `int sb_pivotroot(const struct path *old_path, const struct path
/// *new_path)`: `pivot_root(2)`.
#[lsm(hook = "sb_pivotroot")]
pub fn mount_guard_sb_pivotroot(ctx: LsmContext) -> i32 {
    unsafe { try_sb_pivotroot(&ctx) }
}

#[inline(always)]
unsafe fn try_sb_pivotroot(ctx: &LsmContext) -> i32 {
    let Some((host, privileged, _)) = caller(hook::SB_PIVOTROOT) else {
        return 0;
    };
    if !host || !privileged {
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
    let q = query(MG_OP_PIVOT, host, privileged);
    answer(decide(&q), MG_OP_PIVOT, key, &q.point, 0)
}
