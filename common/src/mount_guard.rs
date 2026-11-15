//! Lot 357: the mount guard — a mount on, over or below the paths the agent
//! depends on is refused in the host's mount namespace.
//!
//! Four review rounds of the by-path defences (lot 353) kept finding one
//! more read of `/proc`, `/sys`, the cgroup root, `/etc/northnarrow` or
//! `/run/northnarrow` that a FUSE or a tmpfs mounted over it by root could
//! stall or blind. This closes the class where it starts: the BPF-LSM hooks
//! on `sb_mount`, `move_mount`, `sb_umount` and `sb_pivotroot`
//! (`agent-ebpf/src/mount_guard.rs`) refuse such a mount. The decision is
//! this module's, one function the eBPF programs call with what they read
//! from the kernel (the target's dentry and mount, never the caller's path
//! string), so the host's tests judge exactly what the kernel decides.
//!
//! Scope: PID 1's mount namespace, for a caller with `CAP_SYS_ADMIN` in
//! PID 1's user namespace (an unprivileged call is the kernel's own
//! `EPERM`, and no record) — and any other namespace whose target mount
//! propagates into PID 1's (a peer of a host mount, or a master of one: a
//! raw `unshare(CLONE_NEWNS)` keeps the shared peer groups, and the kernel
//! copies a mount to the peers with no other LSM call). A container,
//! `unshare -m` (private propagation), a unit's sandbox (slave) are
//! untouched.
//!
//! What is refused (each a signed High, `FS_OP_MOUNT`):
//! - a mount on or over a protected point ([`MG_ON`] and the kinds below):
//!   `/proc`, `/sys`, the cgroup root, `/sys/fs/bpf` and the agent's pin
//!   directory, `/etc/northnarrow`, `/run/northnarrow`,
//!   `/var/lib/northnarrow`, the agent's binaries and units and their
//!   directories, and every directory above them (a tmpfs over `/var/lib`
//!   or an overlay over `/etc` hides them as surely);
//! - a mount anywhere below the agent's own directories ([`MG_OWN`]);
//! - a mount below `/proc`, `/sys`, the cgroup root or the bpffs ([`MG_VIEW`]
//!   and the views' file systems by magic) that is not one of the kernel
//!   pseudo-filesystems systemd and the kernel mount there
//!   ([`ALLOWED_KERNEL_MOUNTS`]: by type, by the canonical point the
//!   kernel's dentries name, and by the mount it covers, never by a path);
//! - an unmount, or a move, of a protected mount ([`MG_HOLD`]); a pivot of
//!   the root; and an old-API move (`mount(2)` with `MS_MOVE`), whose source
//!   the hook sees only as the caller's string — `move_mount(2)`, which
//!   util-linux 2.39 and later uses, is judged by the mount itself.
//!
//! - the review of #567 (F3): a reconfigure of the super block of a view or
//!   of a file system the agent's paths are on ([`MG_SB`]: `mount -o
//!   remount`, `fsconfig(FSCONFIG_CMD_RECONFIGURE)`, both through the
//!   kernel's `reconfigure_super()` and its `sb_remount` hook) — proc's
//!   `subset=pid` and `hidepid`, a read-only state file system — whatever
//!   namespace makes it (a super block is the host's in every one of them);
//!   and a bind remount (`MS_REMOUNT | MS_BIND`) that makes a held mount
//!   read-only or `noexec`.
//!
//! The namespaces judged as PID 1's (the review of #567, F2): PID 1's, the
//! agent's own and the watchdog's (`ProtectSystem=strict` gives each unit
//! a namespace of its own, the one it reads its paths through), each while
//! its process lives — the exit of the agent or the watchdog drops its
//! namespace before the kernel can free its number for another one.
//!
//! The mounts held (no unmount, no move away) are the mounts themselves —
//! by their id, in each of those namespaces — that the protected paths
//! resolve through (the review of #567, F1): a copy of `/`, `/run` or `/sys`
//! (a backup's bind, a chroot's sysfs) is another mount, and its unmount is
//! the caller's own business.
//!
//! Let through: a change of propagation (it covers nothing; the integrity
//! round signs it), an unmount by PID 1, and by `systemd-shutdown` and the
//! helpers it forks at the end of a shutdown (their unmounts and read-only
//! remounts, its pivot to `/run/initramfs`), a remount by a kernel thread
//! (the emergency remount), and everything inside the signed
//! trusted-installer window, recorded (`FS_OP_MOUNT_WINDOW`, Low) when the
//! window let through what it refuses outside one. An unmount of the
//! tracefs, debugfs or securityfs the agent reads is let through and
//! recorded ([`MG_NOTE`], `FS_OP_MOUNT_NOTED`).

/// `MS_REMOUNT` (`include/uapi/linux/mount.h`).
pub const MS_REMOUNT: u64 = 32;
/// `MS_BIND`.
pub const MS_BIND: u64 = 4096;
/// `MS_MOVE`.
pub const MS_MOVE: u64 = 8192;
/// `MS_UNBINDABLE`, `MS_PRIVATE`, `MS_SLAVE`, `MS_SHARED`: a change of
/// propagation.
pub const MS_PROPAGATION: u64 = (1 << 17) | (1 << 18) | (1 << 19) | (1 << 20);

/// Superblock magics (`include/uapi/linux/magic.h`).
pub const PROC_SUPER_MAGIC: u32 = 0x9fa0;
pub const SYSFS_MAGIC: u32 = 0x6265_6572;
pub const CGROUP2_SUPER_MAGIC: u32 = 0x6367_7270;
pub const BPF_FS_MAGIC: u32 = 0xcafe_4a11;
pub const TMPFS_MAGIC: u32 = 0x0102_1994;
pub const AUTOFS_SUPER_MAGIC: u32 = 0x0187;
/// The kernel's own file systems the agent reads below `/sys`: the
/// tracepoint formats (tracefs, also at `/sys/kernel/debug/tracing`), the
/// kprobes switch (debugfs), the lockdown state (securityfs).
pub const TRACEFS_MAGIC: u32 = 0x7472_6163;
pub const DEBUGFS_MAGIC: u32 = 0x6462_6720;
pub const SECURITYFS_MAGIC: u32 = 0x7363_6673;

// ── The protected points (the `MOUNT_PROTECTED` map's values) ──────────

/// A mount on or over this exact point is refused (the agent's binaries
/// and units, their directories, and every directory above a protected
/// one).
pub const MG_ON: u8 = 1;
/// The agent's own directory: a mount on it or anywhere below it is
/// refused.
pub const MG_OWN: u8 = 2;
/// A kernel view root (`/proc`, `/sys`, the cgroup root, `/sys/fs/bpf`): a
/// mount on it is refused, one below it unless it is the kernel's own
/// ([`ALLOWED_KERNEL_MOUNTS`]).
pub const MG_VIEW: u8 = 4;
/// The mount whose root is this point is neither unmounted nor moved away
/// — when it is also one of the mounts held by their id ([`HELD_REFUSE`]).
pub const MG_HOLD: u8 = 8;
/// On a `(device, 0)` key: the super block of a view or of a file system
/// the agent's paths are on — not reconfigured (the review of #567, F3).
/// The device is the super block's own (`super_block.s_dev`, field 3 of
/// `mountinfo`), never a btrfs subvolume's.
pub const MG_SB: u8 = 16;

// ── The mounts held, by their id (the `MOUNT_HELD` map, F1) ──────────────

/// `MOUNT_HELD`'s key of a mount by its id (`struct mount.mnt_id`, field 1
/// of `mountinfo`, `statx`'s `stx_mnt_id`): `(HELD_BY_ID | id, 0)`.
pub const HELD_BY_ID: u64 = 1 << 62;
/// `MOUNT_HELD`'s key of a mount by the place it sits at and its parent's
/// peer group: an unmount propagates — the kernel takes, without another
/// LSM call, the mount at the same place (the same mountpoint dentry) of
/// every peer of the unmounted mount's parent, and of their slaves (a
/// copy's unmount in an rbind of `/sys` takes the host's childless
/// `/sys/fs/cgroup`). Registered for each held mount under its parent's
/// own peer group (`shared:N`) and its master's (`master:N`):
/// `(HELD_BY_PLACE | group, mix(the place's parent directory, its name))`.
pub const HELD_BY_PLACE: u64 = 1 << 63;
/// A held mount: no unmount, no move away.
pub const HELD_REFUSE: u8 = 1;
/// The tracefs, debugfs or securityfs the agent reads: an unmount is let
/// through and recorded (the review of #567, F6).
pub const MG_NOTE: u8 = 2;
/// `MOUNT_HELD`'s value: the namespace an entry belongs to, in the high
/// nibble (each namespace's entries are replaced on their own).
pub const HELD_NS_SHIFT: u8 = 4;

/// [`HELD_BY_ID`]'s key of a mount id.
pub const fn held_by_id(mnt_id: u32) -> (u64, u64) {
    (HELD_BY_ID | mnt_id as u64, 0)
}

/// [`HELD_BY_PLACE`]'s key of a peer group and a place: the key of the
/// mountpoint's parent directory (as `stat(2)` gives it), and the
/// mountpoint's name ([`NameKey`]: its length and hash).
pub const fn held_by_place(group: u32, dir_dev: u64, dir_ino: u64, name: &NameKey) -> (u64, u64) {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    let parts = [dir_dev, dir_ino, name.len as u64, name.h];
    let mut i = 0;
    while i < 4 {
        h ^= parts[i];
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
        h ^= h >> 29;
        i += 1;
    }
    (HELD_BY_PLACE | group as u64, h)
}

// ── The namespaces judged as PID 1's (`MOUNT_GUARD_NS`, F2) ──────────────

/// `MOUNT_GUARD_NS`'s value of PID 1's mount namespace.
pub const GUARD_HOST: u8 = 1;
/// Of the agent's own (its unit's `ProtectSystem=strict`).
pub const GUARD_AGENT: u8 = 2;
/// Of the watchdog's.
pub const GUARD_WATCHDOG: u8 = 3;

/// How many ancestors of a mount's point the hook reads for an
/// [`MG_OWN`] or [`MG_VIEW`] one. The agent's directories refuse a new
/// entry to anyone else (`FS_PROTECT_NOCREATE`), so nothing of theirs lies
/// deeper than their own few levels; a point further down than this hides
/// nothing of the agent's. The views' own file systems are told by their
/// magic, at any depth.
pub const MAX_WALK: u32 = 6;

/// How many mounts stacked at one point the hook steps down to find the
/// directory below them.
pub const MAX_STACK: u32 = 3;

/// A view's file system: anything mounted on a dentry of one is below a
/// view, at any depth — proc, sysfs, cgroup2, the bpffs, and the kernel's
/// own file systems the agent reads below `/sys` (tracefs, debugfs,
/// securityfs: nothing is ever mounted inside them).
pub const fn is_view_magic(magic: u32) -> bool {
    matches!(
        magic,
        PROC_SUPER_MAGIC
            | SYSFS_MAGIC
            | CGROUP2_SUPER_MAGIC
            | BPF_FS_MAGIC
            | TRACEFS_MAGIC
            | DEBUGFS_MAGIC
            | SECURITYFS_MAGIC
    )
}

// ── Operations ─────────────────────────────────────────────────────────

/// Not judged by `sb_mount`: a change of propagation, and a remount of a
/// super block (`MS_REMOUNT` without `MS_BIND`: `sb_remount` judges it,
/// as it judges `fsconfig(FSCONFIG_CMD_RECONFIGURE)`).
pub const MG_OP_PASS: u8 = 0;
/// `mount(2)` of a new file system.
pub const MG_OP_MOUNT: u8 = 1;
/// `mount(2)` with `MS_BIND`: the source is a string, its type unknown.
pub const MG_OP_BIND: u8 = 2;
/// `mount(2)` with `MS_MOVE`.
pub const MG_OP_MOVE_OLD: u8 = 3;
/// `move_mount(2)`: a detached mount (`fsmount`, `open_tree`) attached, or
/// an attached one moved.
pub const MG_OP_MOVE_MOUNT: u8 = 4;
/// `umount(2)`.
pub const MG_OP_UMOUNT: u8 = 5;
/// `pivot_root(2)`.
pub const MG_OP_PIVOT: u8 = 6;
/// A super block reconfigured (`sb_remount`: `mount(2)`'s `MS_REMOUNT`,
/// `fsconfig(2)`'s `FSCONFIG_CMD_RECONFIGURE`).
pub const MG_OP_REMOUNT: u8 = 7;
/// `mount(2)` with `MS_REMOUNT | MS_BIND`: one mount's flags changed.
pub const MG_OP_REMOUNT_BIND: u8 = 8;

/// `MS_RDONLY`, `MS_NOEXEC`: the flags of a bind remount that make a held
/// mount refuse the agent's writes, or its binaries' exec at a restart.
pub const MS_RDONLY: u64 = 1;
pub const MS_NOEXEC: u64 = 8;

/// The operation of a `mount(2)` call, in the kernel's own order
/// (`path_mount`: a remount first, then a bind, then a propagation change,
/// then a move, else a new mount). `flags` as the hook receives them (the
/// kernel has dropped `MS_MGC_VAL`).
pub const fn mount_op(flags: u64) -> u8 {
    if flags & MS_REMOUNT != 0 {
        if flags & MS_BIND != 0 {
            MG_OP_REMOUNT_BIND
        } else {
            MG_OP_PASS
        }
    } else if flags & MS_BIND != 0 {
        MG_OP_BIND
    } else if flags & MS_PROPAGATION != 0 {
        MG_OP_PASS
    } else if flags & MS_MOVE != 0 {
        MG_OP_MOVE_OLD
    } else {
        MG_OP_MOUNT
    }
}

// ── Reasons ────────────────────────────────────────────────────────────

/// On or over a protected point.
pub const MG_WHY_ON: u8 = 1;
/// Below one of the agent's own directories.
pub const MG_WHY_BELOW_OWN: u8 = 2;
/// Below a kernel view, and not the kernel's own mount there.
pub const MG_WHY_BELOW_VIEW: u8 = 3;
/// `mount(2)`'s `MS_MOVE` in the host's namespace.
pub const MG_WHY_MOVE_OLD: u8 = 4;
/// A protected mount moved away (`move_mount(2)`).
pub const MG_WHY_MOVE_AWAY: u8 = 5;
/// A protected mount unmounted.
pub const MG_WHY_UMOUNT: u8 = 6;
/// The root pivoted.
pub const MG_WHY_PIVOT: u8 = 7;
/// The super block of a view, or of a file system the agent's paths are
/// on, reconfigured.
pub const MG_WHY_REMOUNT_SB: u8 = 8;
/// A held mount made read-only or `noexec` by a bind remount.
pub const MG_WHY_REMOUNT_RESTRICT: u8 = 9;
/// An unmount of the tracefs, debugfs or securityfs the agent reads (let
/// through, recorded).
pub const MG_WHY_UMOUNT_NOTED: u8 = 10;

/// A dentry name or a file-system type as the hook compares it: its length
/// and a 64-bit FNV-1a hash of its first 15 bytes, zero-padded to 16 (the
/// kernel's string copy into a zeroed 16-byte buffer). Every name the allow
/// list holds is 15 bytes or shorter; a longer one never matches (its
/// length says so). A hash, not the bytes: the eBPF programs' stack holds
/// four of these (the lot's first lab: 576 bytes of 512). The names that
/// must match are the kernel's own dentries of proc and sysfs (and their
/// parents too), where no caller chooses a name.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NameKey {
    pub len: u32,
    pub h: u64,
}

/// [`NameKey::len`] of a name the hook could not read.
pub const NAME_UNREAD: u32 = u32::MAX;
/// [`NameKey::len`] of an allow-list name that matches any name.
pub const NAME_ANY: u32 = u32::MAX - 1;
/// The longest name a [`NameKey`] tells apart.
pub const NAME_MAX: u32 = 15;

/// FNV-1a (64-bit) of 16 bytes.
pub const fn fnv16(bytes: &[u8; 16]) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    let mut i = 0;
    while i < 16 {
        h ^= bytes[i] as u64;
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
        i += 1;
    }
    h
}

impl NameKey {
    /// No name (unread, or not given: an old-API bind's type).
    pub const NONE: NameKey = NameKey {
        len: NAME_UNREAD,
        h: 0,
    };
    /// Any name (an allow-list wildcard).
    pub const ANY: NameKey = NameKey {
        len: NAME_ANY,
        h: 0,
    };

    /// The key of `len` bytes whose first 15 are `bytes` (the rest zero,
    /// as the kernel's string copy leaves it).
    pub const fn from_parts(len: u32, bytes: &[u8; 16]) -> NameKey {
        NameKey {
            len,
            h: fnv16(bytes),
        }
    }

    /// The key of a name (the allow list, the tests).
    pub const fn of(name: &str) -> NameKey {
        NameKey::of_bytes(name.as_bytes())
    }

    /// The key of a name's bytes (a path component, as the kernel's
    /// dentry holds it).
    pub const fn of_bytes(b: &[u8]) -> NameKey {
        let mut buf = [0u8; 16];
        let mut i = 0;
        while i < b.len() && i < NAME_MAX as usize {
            buf[i] = b[i];
            i += 1;
        }
        NameKey::from_parts(b.len() as u32, &buf)
    }

    /// The same name, `ANY` matching any readable one.
    pub const fn matches(&self, other: &NameKey) -> bool {
        if self.len == NAME_ANY {
            return other.len != NAME_UNREAD;
        }
        self.len == other.len && self.len <= NAME_MAX && self.h == other.h
    }
}

/// What the hook read at a mount's point. The point is the directory the
/// new mount lands on: the target dentry itself, or, when the target is
/// the root of a mount (a mount stacked over another), the directory below
/// the mounts stacked there ([`MAX_STACK`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Point {
    /// The `MOUNT_PROTECTED` flags of the target dentry (the top: for a
    /// stacked target, the root of the mount it covers), 0 when none.
    pub flags: u8,
    /// [`MG_OWN`] and [`MG_VIEW`] of the point's ancestors (within
    /// [`MAX_WALK`]), and of the point itself when the target is stacked.
    pub below: u8,
    /// The magic of the point's file system (its low 32 bits: every magic
    /// fits).
    pub magic: u32,
    /// Mounts covered at the point (0: the target is a plain dentry).
    pub stack: u8,
    /// The magic of the top mount covered (when `stack > 0`), low 32 bits.
    pub covered: u32,
    /// The point's name, its parent's and its grandparent's.
    pub names: [NameKey; 3],
    /// How many names lie between the point and its file system's root:
    /// 0 for the root itself, 1 to 3, or [`DEPTH_DEEPER`].
    pub depth: u8,
    /// The point's file system is one of PID 1's views' own (a container's
    /// own proc is another super block: a mount on it never lands in the
    /// host's `/proc`). Only weighed for a change made in another
    /// namespace.
    pub host_view_sb: bool,
}

/// [`Point::depth`] past three names.
pub const DEPTH_DEEPER: u8 = 4;

impl Point {
    /// A point the hook knows nothing of (tests).
    pub const EMPTY: Point = Point {
        flags: 0,
        below: 0,
        magic: 0,
        stack: 0,
        covered: 0,
        names: [NameKey::NONE; 3],
        depth: DEPTH_DEEPER,
        host_view_sb: false,
    };
}

/// One kernel pseudo-filesystem mount systemd or the kernel makes below a
/// view, by its type, the point (its file system's magic and its names up
/// to that file system's root) and what it covers.
#[derive(Clone, Copy, Debug)]
pub struct AllowedMount {
    pub fstype: NameKey,
    /// The point's file system.
    pub magic: u32,
    /// 0: on a plain directory; otherwise the magic of the one mount it
    /// stacks on (binfmt_misc on systemd's autofs).
    pub covers: u32,
    pub depth: u8,
    pub names: [NameKey; 3],
}

const fn allowed(
    fstype: &str,
    magic: u32,
    covers: u32,
    names: [NameKey; 3],
    depth: u8,
) -> AllowedMount {
    AllowedMount {
        fstype: NameKey::of(fstype),
        magic,
        covers,
        depth,
        names,
    }
}

const N: NameKey = NameKey::NONE;
const fn k(s: &str) -> NameKey {
    NameKey::of(s)
}

/// The kernel's and systemd's own mounts below `/proc`, `/sys` and the
/// cgroup root, let through in the host's namespace. A type alone is never
/// enough (a FUSE is never one), nor a path: the point is the kernel's
/// dentry, named up to its file system's root, on the file system of that
/// view. `hugetlbfs` (`/dev/hugepages`), `mqueue` (`/dev/mqueue`) and
/// WSL's tmpfs over `binfmt_misc/status` (a file of binfmt_misc, which no
/// view is) are below no protected point and never refused.
pub const ALLOWED_KERNEL_MOUNTS: [AllowedMount; 19] = [
    // systemd's automount point, then the real mount on it on access
    allowed(
        "autofs",
        PROC_SUPER_MAGIC,
        0,
        [k("binfmt_misc"), k("fs"), k("sys")],
        3,
    ),
    allowed(
        "binfmt_misc",
        PROC_SUPER_MAGIC,
        AUTOFS_SUPER_MAGIC,
        [k("binfmt_misc"), k("fs"), k("sys")],
        3,
    ),
    allowed(
        "binfmt_misc",
        PROC_SUPER_MAGIC,
        0,
        [k("binfmt_misc"), k("fs"), k("sys")],
        3,
    ),
    allowed("nfsd", PROC_SUPER_MAGIC, 0, [k("nfsd"), k("fs"), N], 2),
    allowed("xenfs", PROC_SUPER_MAGIC, 0, [k("xen"), N, N], 1),
    allowed("debugfs", SYSFS_MAGIC, 0, [k("debug"), k("kernel"), N], 2),
    allowed("tracefs", SYSFS_MAGIC, 0, [k("tracing"), k("kernel"), N], 2),
    allowed(
        "securityfs",
        SYSFS_MAGIC,
        0,
        [k("security"), k("kernel"), N],
        2,
    ),
    allowed("configfs", SYSFS_MAGIC, 0, [k("config"), k("kernel"), N], 2),
    allowed(
        "fusectl",
        SYSFS_MAGIC,
        0,
        [k("connections"), k("fuse"), k("fs")],
        3,
    ),
    allowed("pstore", SYSFS_MAGIC, 0, [k("pstore"), k("fs"), N], 2),
    allowed(
        "efivarfs",
        SYSFS_MAGIC,
        0,
        [k("efivars"), k("efi"), k("firmware")],
        3,
    ),
    allowed("bpf", SYSFS_MAGIC, 0, [k("bpf"), k("fs"), N], 2),
    allowed("selinuxfs", SYSFS_MAGIC, 0, [k("selinux"), k("fs"), N], 2),
    allowed("smackfs", SYSFS_MAGIC, 0, [k("smackfs"), k("fs"), N], 2),
    allowed("resctrl", SYSFS_MAGIC, 0, [k("resctrl"), k("fs"), N], 2),
    // the review of #567 (F1): the unified hierarchy at its canonical point
    // of a sysfs — a chroot's `mount -t sysfs` (the host's super block) then
    // `mount -t cgroup2` below it (the host's own /sys/fs/cgroup is a view:
    // a mount over it stays refused)
    allowed("cgroup2", SYSFS_MAGIC, 0, [k("cgroup"), k("fs"), N], 2),
    // A hybrid or legacy host: the tmpfs at /sys/fs/cgroup holds the
    // unified hierarchy and the v1 controllers (by any name: `cpu,cpuacct`,
    // `name=systemd`'s `systemd`).
    allowed("cgroup2", TMPFS_MAGIC, 0, [k("unified"), N, N], 1),
    allowed("cgroup", TMPFS_MAGIC, 0, [NameKey::ANY, N, N], 1),
];

/// The type of each of [`ALLOWED_KERNEL_MOUNTS`] (the documentation's and
/// the tests'; the hook compares the hashed key).
pub const ALLOWED_KERNEL_MOUNT_TYPES: [&str; 19] = [
    "autofs",
    "binfmt_misc",
    "binfmt_misc",
    "nfsd",
    "xenfs",
    "debugfs",
    "tracefs",
    "securityfs",
    "configfs",
    "fusectl",
    "pstore",
    "efivarfs",
    "bpf",
    "selinuxfs",
    "smackfs",
    "resctrl",
    "cgroup2",
    "cgroup2",
    "cgroup",
];

/// Where each of [`ALLOWED_KERNEL_MOUNTS`] is (the documentation's and the
/// tests' name; never read by the hook).
pub const ALLOWED_KERNEL_MOUNT_PATHS: [&str; 19] = [
    "/proc/sys/fs/binfmt_misc",
    "/proc/sys/fs/binfmt_misc",
    "/proc/sys/fs/binfmt_misc",
    "/proc/fs/nfsd",
    "/proc/xen",
    "/sys/kernel/debug",
    "/sys/kernel/tracing",
    "/sys/kernel/security",
    "/sys/kernel/config",
    "/sys/fs/fuse/connections",
    "/sys/fs/pstore",
    "/sys/firmware/efi/efivars",
    "/sys/fs/bpf",
    "/sys/fs/selinux",
    "/sys/fs/smackfs",
    "/sys/fs/resctrl",
    "/sys/fs/cgroup",
    "/sys/fs/cgroup/unified",
    "/sys/fs/cgroup/<controller>",
];

/// Whether a new mount of `fstype` at `point` is one of the kernel's own
/// ([`ALLOWED_KERNEL_MOUNTS`]). An unknown type (an old-API bind's) never
/// is, nor a mount whose root is not its file system's (`src_root` false:
/// an `open_tree(OPEN_TREE_CLONE)` of a subdirectory of the kernel's own
/// type — securityfs' `apparmor/` moved onto `/sys/kernel/security`, the
/// review of #567, F6).
///
/// Out of line on purpose: inlined into [`decide`], the BPF back end
/// specialised its loop by the point's depth and the hooks' allow-list
/// stopped matching on the lab's 5.15 guest (every kernel's own mount
/// refused); as its own function, as lot 357 shipped it, it matches.
#[inline(never)]
pub fn allowed_kernel_mount(fstype: &NameKey, point: &Point, src_root: bool) -> bool {
    if !src_root || fstype.len == NAME_UNREAD || fstype.len == NAME_ANY {
        return false;
    }
    let mut i = 0;
    while i < ALLOWED_KERNEL_MOUNTS.len() {
        let a = &ALLOWED_KERNEL_MOUNTS[i];
        let stacked_ok = if a.covers == 0 {
            point.stack == 0
        } else {
            point.stack == 1 && point.covered == a.covers
        };
        if stacked_ok
            && a.fstype.matches(fstype)
            && a.magic == point.magic
            && a.depth == point.depth
            && names_match(&a.names, &point.names, a.depth)
        {
            return true;
        }
        i += 1;
    }
    false
}

fn names_match(want: &[NameKey; 3], got: &[NameKey; 3], depth: u8) -> bool {
    let mut i = 0;
    while i < 3 {
        if (i as u8) < depth && !want[i].matches(&got[i]) {
            return false;
        }
        i += 1;
    }
    true
}

/// Why a mount at `point` of `fstype` ([`NameKey::NONE`] for an old-API
/// bind) is refused, or `None`. `host`: made in PID 1's namespace — from
/// another one, a view's file system is below a view only when it is one of
/// PID 1's views' own ([`Point::host_view_sb`]).
pub fn point_refusal(point: &Point, fstype: &NameKey, host: bool, src_root: bool) -> Option<u8> {
    if point.flags & (MG_ON | MG_OWN | MG_VIEW) != 0 {
        return Some(MG_WHY_ON);
    }
    if point.below & MG_OWN != 0 {
        return Some(MG_WHY_BELOW_OWN);
    }
    let in_view =
        (is_view_magic(point.magic) && (host || point.host_view_sb)) || point.below & MG_VIEW != 0;
    if in_view && !allowed_kernel_mount(fstype, point, src_root) {
        return Some(MG_WHY_BELOW_VIEW);
    }
    None
}

/// Everything [`decide`] weighs, read by the hook.
#[derive(Clone, Copy, Debug)]
pub struct Query {
    /// [`MG_OP_MOUNT`] … [`MG_OP_PIVOT`], or [`MG_OP_PASS`].
    pub op: u8,
    /// The target is in a guarded mount namespace — PID 1's, the agent's
    /// or the watchdog's: the namespace that owns the target mount (the
    /// cross-model check: a path through `/proc/<pid>/root`, an `O_PATH`
    /// descriptor of one, names another namespace's mount than the
    /// caller's), the caller's own for a pivot and a remount.
    pub host: bool,
    /// The coordinator's propagation point: the mount the operation
    /// changes (the target's mount; for an unmount, the parent of the mount
    /// unmounted) has a peer in PID 1's mount namespace, or a slave of one
    /// there, or more peers than the hook reads — what is done to it is
    /// copied into the host's view without another LSM call.
    pub reaches: bool,
    /// The caller holds `CAP_SYS_ADMIN` in PID 1's user namespace.
    pub privileged: bool,
    /// The caller is PID 1 — for an unmount, and only of a mount of
    /// PID 1's own namespace that is not one of the agent's directories
    /// (the cross-model check: `systemctl bind`'s worker and PID 1 itself
    /// are judged in the agent's and the watchdog's namespaces).
    pub init: bool,
    /// The signed trusted-installer window is open.
    pub window: bool,
    /// Where the mount lands ([`MG_OP_MOUNT`], [`MG_OP_BIND`],
    /// [`MG_OP_MOVE_MOUNT`]).
    pub point: Point,
    /// The new mount's type: `mount(2)`'s type for a new mount, the
    /// detached mount's own file system for `move_mount(2)`, none for a
    /// bind.
    pub fstype: NameKey,
    /// The mount unmounted, or moved by `move_mount(2)` while attached, or
    /// remounted by a bind remount, is a held one (by its id,
    /// [`HELD_REFUSE`], and [`MG_HOLD`] at its root); for a remount
    /// ([`MG_OP_REMOUNT`]), the super block is a held one ([`MG_SB`]).
    pub held: bool,
    /// The mount unmounted is the tracefs, debugfs or securityfs the agent
    /// reads ([`MG_NOTE`]).
    pub noted: bool,
    /// `systemd-shutdown` at the end of a shutdown: PID 1 running it (the
    /// kill guard's identity: its comm and the file the agent recorded),
    /// or a helper it forked (`(sd-umount)`, `(sd-remount)`: PID 1's child
    /// running that file).
    pub shutdown: bool,
    /// A kernel thread (`PF_KTHREAD`: the emergency remount of `SysRq-u`).
    pub kernel: bool,
    /// The new mount's root is its file system's root: a new file system,
    /// or a detached mount that is not a clone of a subdirectory.
    pub src_root: bool,
    /// A bind remount asks for read-only or `noexec`; a super block's
    /// reconfigure makes it read-only, or its new flags could not be read.
    pub restrict: bool,
}

/// What the hook does.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict {
    Allow,
    /// Refused (`-EPERM`), a signed High (`FS_OP_MOUNT`).
    Refuse(u8),
    /// Let through by the trusted-installer window, recorded
    /// (`FS_OP_MOUNT_WINDOW`).
    Window(u8),
    /// Let through and recorded, Low (`FS_OP_MOUNT_NOTED`): an unmount of
    /// a kernel file system the agent reads.
    Noted(u8),
}

/// The mount guard's decision.
///
/// In a guarded namespace ([`Query::host`]: PID 1's, the agent's, the
/// watchdog's) everything below is judged; in another one (a container,
/// `unshare -m`, a unit's sandbox) only what propagates into a guarded one
/// (`reaches`), as it would be there: a mount on, over or below a
/// protected point, an unmount of a held mount (an unmount propagates to
/// the peers of its parent), a bind or move that lands on one. A pivot
/// changes that namespace's root only, and an old-API move there is judged
/// by where it lands. A super block's reconfigure is judged in every
/// namespace: the super block is the same one.
pub fn decide(q: &Query) -> Verdict {
    if !q.privileged {
        return Verdict::Allow;
    }
    let why = if q.op == MG_OP_REMOUNT {
        // a view's super block: any option (proc's subset=pid, hidepid);
        // the file system of the agent's paths: made read-only, or options
        // not read (`restrict`: the hook could not tell) — finalrd's
        // `remount,exec /run` at shutdown, a `remount,commit=` pass
        if q.held && !(q.shutdown || q.kernel) && (is_view_magic(q.point.magic) || q.restrict) {
            Some(MG_WHY_REMOUNT_SB)
        } else {
            None
        }
    } else if !(q.host || q.reaches) {
        None
    } else {
        match q.op {
            MG_OP_PIVOT if !q.host => None,
            MG_OP_MOVE_OLD if !q.host => point_refusal(&q.point, &NameKey::NONE, false, false),
            // systemd-shutdown's switch to /run/initramfs (dracut)
            MG_OP_PIVOT | MG_OP_MOVE_OLD if q.shutdown => None,
            MG_OP_PIVOT => Some(MG_WHY_PIVOT),
            MG_OP_MOVE_OLD => Some(MG_WHY_MOVE_OLD),
            MG_OP_UMOUNT => {
                if q.init || q.shutdown {
                    None
                } else if q.held {
                    Some(MG_WHY_UMOUNT)
                } else if q.noted && q.host {
                    return Verdict::Noted(MG_WHY_UMOUNT_NOTED);
                } else {
                    None
                }
            }
            MG_OP_MOVE_MOUNT if q.held => {
                if q.shutdown {
                    None
                } else {
                    Some(MG_WHY_MOVE_AWAY)
                }
            }
            MG_OP_MOVE_MOUNT | MG_OP_MOUNT => {
                point_refusal(&q.point, &q.fstype, q.host, q.src_root)
            }
            MG_OP_BIND => point_refusal(&q.point, &NameKey::NONE, q.host, false),
            // one mount's flags: only in its own namespace (they never
            // propagate)
            MG_OP_REMOUNT_BIND if q.host && q.held && q.restrict && !q.shutdown => {
                Some(MG_WHY_REMOUNT_RESTRICT)
            }
            _ => None,
        }
    };
    match why {
        None => Verdict::Allow,
        Some(w) if q.window => Verdict::Window(w),
        Some(w) => Verdict::Refuse(w),
    }
}

// ── The record ─────────────────────────────────────────────────────────

/// The view a point lies in, for the record: 0 none, then `/proc`, `/sys`,
/// the cgroup root, the bpffs, the tracefs, the debugfs, the securityfs.
pub const fn view_of(magic: u32) -> u8 {
    match magic {
        PROC_SUPER_MAGIC => 1,
        SYSFS_MAGIC => 2,
        CGROUP2_SUPER_MAGIC => 3,
        BPF_FS_MAGIC => 4,
        TRACEFS_MAGIC => 5,
        DEBUGFS_MAGIC => 6,
        SECURITYFS_MAGIC => 7,
        _ => 0,
    }
}

/// A record's `target_dev`: the target's device (as `stat(2)` gives it),
/// the operation, the reason, the view and the mounts covered.
///
/// `stack`'s high nibble carries [`REACH_OTHER_NS`] for a change made in
/// another namespace (0: made in PID 1's).
pub const fn record_dev(dev: u64, op: u8, why: u8, view: u8, stack: u8) -> u64 {
    (dev & 0xffff_ffff)
        | (op as u64) << 32
        | (why as u64) << 40
        | (view as u64) << 48
        | (stack as u64) << 56
}

/// A record's high nibble of `stack`: the change was made in another mount
/// namespace and reaches PID 1's (its mount a peer or a master of one
/// there, or more peers or slaves than the hook reads). 0: made in PID 1's.
pub const REACH_OTHER_NS: u8 = 1;

/// A record's high nibble of `stack`: made in the agent's own mount
/// namespace ([`GUARD_AGENT`], the review of #567, F2).
pub const REACH_AGENT_NS: u8 = GUARD_AGENT;
/// Made in the watchdog's ([`GUARD_WATCHDOG`]).
pub const REACH_WATCHDOG_NS: u8 = GUARD_WATCHDOG;

/// The reach of a change made in a guarded namespace ([`GUARD_HOST`] …):
/// 0 for PID 1's, else the namespace's own.
pub const fn reach_in(guard: u8) -> u8 {
    match guard {
        GUARD_AGENT => REACH_AGENT_NS,
        GUARD_WATCHDOG => REACH_WATCHDOG_NS,
        _ => 0,
    }
}

/// A record's reach (0, [`REACH_OTHER_NS`], [`REACH_AGENT_NS`],
/// [`REACH_WATCHDOG_NS`]).
pub const fn reach_of(target_dev: u64) -> u8 {
    (target_dev >> 60) as u8
}

/// The reach's words in a record.
pub const fn reach_name(reach: u8) -> &'static str {
    match reach {
        REACH_OTHER_NS => "made in another mount namespace whose change reaches PID 1's, the agent's or the watchdog's (a peer or a master of one of its mounts, or more peers or slaves than the hook reads)",
        REACH_AGENT_NS => "made in the agent's own mount namespace",
        REACH_WATCHDOG_NS => "made in the watchdog's own mount namespace",
        _ => "made in PID 1's mount namespace",
    }
}

/// [`record_dev`] read back: (device, operation, reason, view, stack).
pub const fn record_of(target_dev: u64) -> (u64, u8, u8, u8, u8) {
    (
        target_dev & 0xffff_ffff,
        (target_dev >> 32) as u8,
        (target_dev >> 40) as u8,
        (target_dev >> 48) as u8,
        ((target_dev >> 56) & 0xf) as u8,
    )
}

/// The operation's words in a record.
pub const fn op_name(op: u8) -> &'static str {
    match op {
        MG_OP_MOUNT => "mount(2) of a new file system",
        MG_OP_BIND => "mount(2) --bind",
        MG_OP_MOVE_OLD => "mount(2) --move",
        MG_OP_MOVE_MOUNT => "move_mount(2)",
        MG_OP_UMOUNT => "umount(2)",
        MG_OP_PIVOT => "pivot_root(2)",
        MG_OP_REMOUNT => "remount of a super block (mount(2) MS_REMOUNT, or fsconfig(2) FSCONFIG_CMD_RECONFIGURE)",
        MG_OP_REMOUNT_BIND => "mount(2) -o remount,bind",
        _ => "mount operation",
    }
}

/// The reason's words in a record.
pub const fn why_name(why: u8) -> &'static str {
    match why {
        MG_WHY_ON => "on or over a protected point (a kernel view, the agent's directories, binaries or units, or a directory above them)",
        MG_WHY_BELOW_OWN => "below one of the agent's own directories",
        MG_WHY_BELOW_VIEW => "below a kernel view (/proc, /sys, the cgroup root, the bpffs), and not the kernel's own pseudo-filesystem at its canonical point",
        MG_WHY_MOVE_OLD => "a move through mount(2)'s MS_MOVE in the host's namespace, whose source the kernel hook sees only as the caller's string (move_mount(2) is judged by the mount itself)",
        MG_WHY_MOVE_AWAY => "a protected mount moved away",
        MG_WHY_UMOUNT => "a protected mount unmounted",
        MG_WHY_PIVOT => "the root pivoted in the host's namespace",
        MG_WHY_REMOUNT_SB => "the super block of a kernel view or of a file system the agent's paths are on, reconfigured (proc's subset=pid or hidepid hide what the agent reads; a read-only state file system refuses its writes)",
        MG_WHY_REMOUNT_RESTRICT => "a mount that holds the agent's paths made read-only or noexec",
        MG_WHY_UMOUNT_NOTED => "an unmount of a kernel file system the agent reads (the tracefs, debugfs or securityfs), let through and recorded",
        _ => "a mount refused",
    }
}

/// The view's name in a record.
pub const fn view_name(view: u8) -> &'static str {
    match view {
        1 => "/proc",
        2 => "/sys",
        3 => "the cgroup root",
        4 => "the bpffs",
        5 => "the tracefs",
        6 => "the debugfs",
        7 => "the securityfs",
        _ => "",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn host(op: u8, point: Point, fstype: &str) -> Query {
        Query {
            op,
            host: true,
            reaches: false,
            privileged: true,
            init: false,
            window: false,
            point,
            fstype: if fstype.is_empty() {
                NameKey::NONE
            } else {
                NameKey::of(fstype)
            },
            held: false,
            noted: false,
            shutdown: false,
            kernel: false,
            src_root: true,
            restrict: false,
        }
    }

    fn plain(magic: u32, names: &[&str]) -> Point {
        let mut p = Point {
            magic,
            depth: names.len() as u8,
            ..Point::EMPTY
        };
        for (i, n) in names.iter().take(3).enumerate() {
            p.names[i] = NameKey::of(n);
        }
        if names.len() > 3 {
            p.depth = DEPTH_DEEPER;
        }
        p
    }

    fn view_root(flags: u8, magic: u32) -> Point {
        Point {
            flags,
            magic,
            depth: 0,
            ..Point::EMPTY
        }
    }

    // ── mount(2)'s operations ──

    #[test]
    fn a_mount_call_is_classified_in_the_kernels_order() {
        assert_eq!(mount_op(0), MG_OP_MOUNT);
        assert_eq!(mount_op(MS_BIND), MG_OP_BIND);
        assert_eq!(mount_op(MS_BIND | (1 << 14)), MG_OP_BIND);
        assert_eq!(mount_op(MS_MOVE), MG_OP_MOVE_OLD);
        // a remount first: a bind remount is one mount's flags (judged
        // here, the review of #567 F3); a super block's remount goes to
        // `sb_remount` (judged there, with fsconfig's reconfigure)
        assert_eq!(mount_op(MS_REMOUNT | MS_BIND), MG_OP_REMOUNT_BIND);
        assert_eq!(
            mount_op(MS_REMOUNT | MS_BIND | MS_RDONLY),
            MG_OP_REMOUNT_BIND
        );
        assert_eq!(mount_op(MS_REMOUNT), MG_OP_PASS);
        assert_eq!(mount_op(MS_REMOUNT | MS_RDONLY), MG_OP_PASS);
        // then a bind, before a propagation change
        assert_eq!(mount_op(MS_BIND | (1 << 18)), MG_OP_BIND);
        for p in [1 << 17, 1 << 18, 1 << 19, 1 << 20] {
            assert_eq!(mount_op(p), MG_OP_PASS);
            // a propagation change wins over a move
            assert_eq!(mount_op(p | MS_MOVE), MG_OP_PASS);
        }
        // read-only, nosuid and the like are a new mount's options
        assert_eq!(mount_op(1 | 2 | 4 | 8), MG_OP_MOUNT);
    }

    // ── refused in the host's namespace ──

    #[test]
    fn a_mount_over_each_protected_root_is_refused_in_the_host_namespace() {
        for (flags, magic) in [
            (MG_VIEW | MG_HOLD, PROC_SUPER_MAGIC),
            (MG_VIEW | MG_HOLD, SYSFS_MAGIC),
            (MG_VIEW | MG_HOLD, CGROUP2_SUPER_MAGIC),
            (MG_VIEW | MG_HOLD, TMPFS_MAGIC),
            (MG_VIEW | MG_HOLD, BPF_FS_MAGIC),
            (MG_OWN | MG_HOLD, 0xef53),
            (MG_OWN | MG_HOLD, TMPFS_MAGIC),
            (MG_OWN | MG_HOLD, BPF_FS_MAGIC),
            (MG_ON | MG_HOLD, 0xef53),
        ] {
            // a tmpfs, a FUSE, a bind, the kernel's own type: all refused
            for fstype in [
                "tmpfs",
                "fuse",
                "fuse.sshfs",
                "proc",
                "sysfs",
                "binfmt_misc",
            ] {
                let q = host(MG_OP_MOUNT, view_root(flags, magic), fstype);
                assert_eq!(
                    decide(&q),
                    Verdict::Refuse(MG_WHY_ON),
                    "{flags} {magic:x} {fstype}"
                );
            }
            let q = host(MG_OP_BIND, view_root(flags, magic), "");
            assert_eq!(decide(&q), Verdict::Refuse(MG_WHY_ON));
            let q = host(MG_OP_MOVE_MOUNT, view_root(flags, magic), "tmpfs");
            assert_eq!(decide(&q), Verdict::Refuse(MG_WHY_ON));
        }
    }

    #[test]
    fn a_mount_stacked_over_a_protected_root_is_refused() {
        // a FUSE over the tracefs at /sys/kernel/tracing: the top is
        // tracefs's root, unregistered, the point below it the view's
        let mut p = plain(SYSFS_MAGIC, &["tracing", "kernel"]);
        p.stack = 1;
        p.covered = 0x7472_6163; // tracefs
        assert_eq!(
            decide(&host(MG_OP_MOUNT, p, "fuse")),
            Verdict::Refuse(MG_WHY_BELOW_VIEW)
        );
        // the kernel's own type stacked where it never stacks
        let mut d = plain(SYSFS_MAGIC, &["debug", "kernel"]);
        d.stack = 1;
        d.covered = 0x6462_6720; // debugfs
        assert_eq!(
            decide(&host(MG_OP_MOUNT, d, "debugfs")),
            Verdict::Refuse(MG_WHY_BELOW_VIEW)
        );
    }

    #[test]
    fn a_mount_anywhere_below_the_agents_own_directories_is_refused() {
        for names in [&["agent.toml"][..], &["a", "b", "c", "d", "e", "f"][..]] {
            let mut p = plain(0xef53, names);
            p.below = MG_OWN;
            for op in [MG_OP_MOUNT, MG_OP_BIND, MG_OP_MOVE_MOUNT] {
                assert_eq!(
                    decide(&host(op, p, "tmpfs")),
                    Verdict::Refuse(MG_WHY_BELOW_OWN)
                );
            }
        }
        // even a kernel type at a name the allow list knows: the agent's
        // directory is no view
        let mut p = plain(TMPFS_MAGIC, &["unified"]);
        p.below = MG_OWN | MG_VIEW;
        assert_eq!(
            decide(&host(MG_OP_MOUNT, p, "cgroup2")),
            Verdict::Refuse(MG_WHY_BELOW_OWN)
        );
    }

    #[test]
    fn a_mount_below_a_view_that_is_not_the_kernels_own_is_refused() {
        for (magic, names, fstype) in [
            // F5: a bind of /proc/1 over another pid's directory
            (PROC_SUPER_MAGIC, &["4242"][..], ""),
            // #563's re-check 4: a tmpfs over the agent's /proc/<pid>/fd
            // (false facts, or a stalled decision), over /proc/self's
            // target, a FUSE over a cgroup directory; /proc/<pid>/... is
            // never a mount point the kernel's own list names
            (PROC_SUPER_MAGIC, &["fd", "4242"][..], "tmpfs"),
            (PROC_SUPER_MAGIC, &["fdinfo", "4242"][..], "fuse"),
            (PROC_SUPER_MAGIC, &["exe", "4242"][..], ""),
            (PROC_SUPER_MAGIC, &["self"][..], "tmpfs"),
            (PROC_SUPER_MAGIC, &["4242"][..], "binfmt_misc"),
            (CGROUP2_SUPER_MAGIC, &["x"][..], "fuse"),
            (
                CGROUP2_SUPER_MAGIC,
                &["northnarrow-agent.service", "northnarrow.slice"][..],
                "fuse",
            ),
            (
                PROC_SUPER_MAGIC,
                &["modules_disabled", "kernel", "sys"][..],
                "",
            ),
            (PROC_SUPER_MAGIC, &["kernel", "sys"][..], "tmpfs"),
            // a FUSE over the kernel's BTF
            (SYSFS_MAGIC, &["btf", "kernel"][..], "fuse"),
            (SYSFS_MAGIC, &["kernel"][..], "tmpfs"),
            // a cgroup2 subtree bound over a cgroup directory
            (CGROUP2_SUPER_MAGIC, &["system.slice"][..], ""),
            (CGROUP2_SUPER_MAGIC, &["northnarrow.slice"][..], "tmpfs"),
            // into the bpffs
            (BPF_FS_MAGIC, &["northnarrow"][..], "bpf"),
            // the right type at the wrong point
            (SYSFS_MAGIC, &["debug", "kernel", "x"][..], "debugfs"),
            (SYSFS_MAGIC, &["debug"][..], "debugfs"),
            (SYSFS_MAGIC, &["tracing", "kernel"][..], "debugfs"),
            (PROC_SUPER_MAGIC, &["binfmt_misc", "fs"][..], "binfmt_misc"),
            // inside the kernel's own file systems below /sys: the
            // tracepoint formats, the kprobes switch, the lockdown state
            (
                TRACEFS_MAGIC,
                &["format", "sys_enter_openat", "syscalls", "events"][..],
                "",
            ),
            (TRACEFS_MAGIC, &["events"][..], "tmpfs"),
            (DEBUGFS_MAGIC, &["enabled", "kprobes"][..], ""),
            (DEBUGFS_MAGIC, &["tracing"][..], "tracefs"),
            (SECURITYFS_MAGIC, &["lockdown"][..], ""),
            // the right name under another parent, or in another view
            (SYSFS_MAGIC, &["debug", "class"][..], "debugfs"),
            (
                SYSFS_MAGIC,
                &["connections", "fuse", "kernel"][..],
                "fusectl",
            ),
            (
                PROC_SUPER_MAGIC,
                &["binfmt_misc", "fs", "net"][..],
                "binfmt_misc",
            ),
            (
                SYSFS_MAGIC,
                &["binfmt_misc", "fs", "sys"][..],
                "binfmt_misc",
            ),
            (PROC_SUPER_MAGIC, &["debug", "kernel"][..], "debugfs"),
            // a type that differs past its eighth byte
            (
                PROC_SUPER_MAGIC,
                &["binfmt_misc", "fs", "sys"][..],
                "binfmt_mxxx",
            ),
            (SYSFS_MAGIC, &["security", "kernel"][..], "securityxx"),
            // a FUSE named after a kernel type
            (SYSFS_MAGIC, &["debug", "kernel"][..], "fuse.debugfs"),
            (SYSFS_MAGIC, &["debug", "kernel"][..], "debugfs2"),
            (SYSFS_MAGIC, &["debug", "kernel"][..], "debugf"),
        ] {
            let p = plain(magic, names);
            let op = if fstype.is_empty() {
                MG_OP_BIND
            } else {
                MG_OP_MOUNT
            };
            assert_eq!(
                decide(&host(op, p, fstype)),
                Verdict::Refuse(MG_WHY_BELOW_VIEW),
                "{magic:x} {names:?} {fstype}"
            );
        }
        // a deep directory of a view: refused by the file system's magic,
        // whatever the depth
        let p = plain(SYSFS_MAGIC, &["a", "b", "c", "d", "e"]);
        assert_eq!(
            decide(&host(MG_OP_MOUNT, p, "tmpfs")),
            Verdict::Refuse(MG_WHY_BELOW_VIEW)
        );
        // a tmpfs directory below the hybrid cgroup root (by the walk)
        let mut p = plain(TMPFS_MAGIC, &["unified"]);
        p.below = MG_VIEW;
        assert_eq!(
            decide(&host(MG_OP_MOUNT, p, "fuse")),
            Verdict::Refuse(MG_WHY_BELOW_VIEW)
        );
        // the hybrid cgroup root's tmpfs deeper than a controller
        let mut p = plain(TMPFS_MAGIC, &["x", "cpu"]);
        p.below = MG_VIEW;
        assert_eq!(
            decide(&host(MG_OP_MOUNT, p, "cgroup")),
            Verdict::Refuse(MG_WHY_BELOW_VIEW)
        );
    }

    #[test]
    fn the_kernels_own_type_passes_only_on_what_it_covers() {
        // binfmt_misc lands on systemd's autofs, never on another mount
        let mut p = plain(PROC_SUPER_MAGIC, &["binfmt_misc", "fs", "sys"]);
        p.stack = 1;
        p.covered = AUTOFS_SUPER_MAGIC;
        assert_eq!(decide(&host(MG_OP_MOUNT, p, "binfmt_misc")), Verdict::Allow);
        for covered in [TMPFS_MAGIC, 0x6573_5546, 0x4249_4e4d] {
            p.covered = covered;
            assert_eq!(
                decide(&host(MG_OP_MOUNT, p, "binfmt_misc")),
                Verdict::Refuse(MG_WHY_BELOW_VIEW),
                "{covered:x}"
            );
        }
        // two mounts down, even the autofs first
        p.covered = AUTOFS_SUPER_MAGIC;
        p.stack = 2;
        assert_eq!(
            decide(&host(MG_OP_MOUNT, p, "binfmt_misc")),
            Verdict::Refuse(MG_WHY_BELOW_VIEW)
        );
        // a type the hook could not read is never the kernel's
        let p = plain(SYSFS_MAGIC, &["debug", "kernel"]);
        for op in [MG_OP_MOUNT, MG_OP_MOVE_MOUNT] {
            let q = Query {
                fstype: NameKey::NONE,
                ..host(op, p, "")
            };
            assert_eq!(decide(&q), Verdict::Refuse(MG_WHY_BELOW_VIEW));
        }
    }

    #[test]
    fn an_old_api_bind_never_passes_as_a_kernel_type() {
        // `mount --bind -t debugfs /tmp/evil /sys/kernel/debug`: mount(2)
        // ignores a bind's type, and so does the guard
        let p = plain(SYSFS_MAGIC, &["debug", "kernel"]);
        assert_eq!(
            decide(&host(MG_OP_BIND, p, "debugfs")),
            Verdict::Refuse(MG_WHY_BELOW_VIEW)
        );
    }

    #[test]
    fn a_move_unmount_or_pivot_of_a_protected_mount_is_refused() {
        let held = |op| Query {
            held: true,
            ..host(op, Point::EMPTY, "")
        };
        assert_eq!(decide(&held(MG_OP_UMOUNT)), Verdict::Refuse(MG_WHY_UMOUNT));
        assert_eq!(
            decide(&held(MG_OP_MOVE_MOUNT)),
            Verdict::Refuse(MG_WHY_MOVE_AWAY)
        );
        // mount(2)'s MS_MOVE names its source by a string only: refused in
        // the host's namespace whatever it moves
        assert_eq!(
            decide(&host(MG_OP_MOVE_OLD, Point::EMPTY, "")),
            Verdict::Refuse(MG_WHY_MOVE_OLD)
        );
        assert_eq!(
            decide(&host(MG_OP_PIVOT, Point::EMPTY, "")),
            Verdict::Refuse(MG_WHY_PIVOT)
        );
        // an unprotected mount unmounted or moved by move_mount(2)
        assert_eq!(
            decide(&host(MG_OP_UMOUNT, Point::EMPTY, "")),
            Verdict::Allow
        );
        assert_eq!(
            decide(&host(MG_OP_MOVE_MOUNT, Point::EMPTY, "")),
            Verdict::Allow
        );
    }

    // ── allowed ──

    #[test]
    fn the_kernels_own_mounts_below_the_views_are_allowed() {
        for (i, (a, path)) in ALLOWED_KERNEL_MOUNTS
            .iter()
            .zip(ALLOWED_KERNEL_MOUNT_PATHS)
            .enumerate()
        {
            let names: Vec<&str> = path
                .trim_start_matches('/')
                .split('/')
                .skip(1)
                .collect::<Vec<_>>()
                .into_iter()
                .rev()
                .collect();
            let mut p = match a.magic {
                // the hybrid cgroup root's tmpfs: below the registered view
                TMPFS_MAGIC => {
                    let mut p = plain(TMPFS_MAGIC, &[names[0]]);
                    p.below = MG_VIEW;
                    if a.names[0].len == NAME_ANY {
                        p.names[0] = NameKey::of("cpu,cpuacct");
                    }
                    p
                }
                _ => plain(a.magic, &names),
            };
            if a.covers != 0 {
                p.stack = 1;
                p.covered = a.covers;
            }
            let fstype = ALLOWED_KERNEL_MOUNT_TYPES[i].to_string();
            assert_eq!(NameKey::of(&fstype), a.fstype);
            assert_eq!(
                decide(&host(MG_OP_MOUNT, p, &fstype)),
                Verdict::Allow,
                "{} at {}",
                fstype,
                path
            );
            // the same through the new mount API (libmount 2.39+)
            assert_eq!(decide(&host(MG_OP_MOVE_MOUNT, p, &fstype)), Verdict::Allow);
            // a bind there is not the kernel's mount
            assert_eq!(
                decide(&host(MG_OP_BIND, p, &fstype)),
                Verdict::Refuse(MG_WHY_BELOW_VIEW)
            );
        }
        // systemd's v1 named hierarchy
        let mut p = plain(TMPFS_MAGIC, &["systemd"]);
        p.below = MG_VIEW;
        assert_eq!(decide(&host(MG_OP_MOUNT, p, "cgroup")), Verdict::Allow);
    }

    #[test]
    fn mounts_below_no_protected_point_are_allowed() {
        for (magic, names, fstype) in [
            // hugetlbfs, mqueue
            (0x0102_1994, &["hugepages"][..], "hugetlbfs"),
            (0x0102_1994, &["mqueue"][..], "mqueue"),
            // WSL's tmpfs over binfmt_misc's status file (a bind)
            (0x4249_4e4d, &["status"][..], ""),
            // docker's overlay, snapd's squashfs, a netns bind, logind's tmpfs
            (
                0xef53,
                &["merged", "x", "overlay2", "docker", "lib", "var"][..],
                "overlay",
            ),
            (0xef53, &["1234", "core22", "snap"][..], "squashfs"),
            (TMPFS_MAGIC, &["x", "netns"][..], ""),
            (TMPFS_MAGIC, &["1000", "user"][..], "tmpfs"),
            // an AppImage's FUSE in /tmp
            (TMPFS_MAGIC, &[".mount_app"][..], "fuse.app"),
        ] {
            let p = plain(magic, names);
            let op = if fstype.is_empty() {
                MG_OP_BIND
            } else {
                MG_OP_MOUNT
            };
            assert_eq!(decide(&host(op, p, fstype)), Verdict::Allow, "{names:?}");
        }
    }

    /// The coordinator's propagation point: a mount made in another
    /// namespace whose target mount reaches PID 1's (a shared peer, a
    /// master of a host slave) is judged as it would be in the host's.
    #[test]
    fn a_mount_that_propagates_into_the_host_namespace_is_judged_there_too() {
        let elsewhere = |q: Query| Query {
            host: false,
            reaches: true,
            ..q
        };
        for (flags, magic) in [
            (MG_OWN | MG_HOLD, TMPFS_MAGIC),
            (MG_OWN | MG_HOLD, 0xef53),
            (MG_VIEW | MG_HOLD, PROC_SUPER_MAGIC),
            (MG_ON | MG_HOLD, 0xef53),
        ] {
            for op in [MG_OP_MOUNT, MG_OP_BIND, MG_OP_MOVE_MOUNT, MG_OP_MOVE_OLD] {
                let q = elsewhere(host(op, view_root(flags, magic), "tmpfs"));
                assert_eq!(decide(&q), Verdict::Refuse(MG_WHY_ON), "{op} {flags}");
            }
        }
        let mut below = plain(0xef53, &["x"]);
        below.below = MG_OWN;
        assert_eq!(
            decide(&elsewhere(host(MG_OP_BIND, below, ""))),
            Verdict::Refuse(MG_WHY_BELOW_OWN)
        );
        let mut hsys = plain(SYSFS_MAGIC, &["kernel"]);
        hsys.host_view_sb = true;
        assert_eq!(
            decide(&elsewhere(host(MG_OP_MOUNT, hsys, "fuse"))),
            Verdict::Refuse(MG_WHY_BELOW_VIEW)
        );
        // #563's re-check 4, by propagation: the host's /proc/<pid>/fd
        let mut fd = plain(PROC_SUPER_MAGIC, &["fd", "4242"]);
        fd.host_view_sb = true;
        assert_eq!(
            decide(&elsewhere(host(MG_OP_MOUNT, fd, "tmpfs"))),
            Verdict::Refuse(MG_WHY_BELOW_VIEW)
        );
        // a container's own proc (another super block): its binds below it
        // never land in the host's /proc (systemd-nspawn's /proc/sys,
        // /proc/kmsg, boot_id), whatever its peers
        for names in [
            &["sys"][..],
            &["kmsg"][..],
            &["boot_id", "random", "kernel"][..],
        ] {
            let own = plain(PROC_SUPER_MAGIC, names);
            assert_eq!(
                decide(&elsewhere(host(MG_OP_BIND, own, ""))),
                Verdict::Allow,
                "{names:?}"
            );
        }
        // an unmount propagates to the peers of its parent
        let q = elsewhere(Query {
            held: true,
            ..host(MG_OP_UMOUNT, Point::EMPTY, "")
        });
        assert_eq!(decide(&q), Verdict::Refuse(MG_WHY_UMOUNT));
        // a pivot is that namespace's own; an old-API move there is judged
        // by where it lands, not refused whatever it moves
        assert_eq!(
            decide(&elsewhere(host(MG_OP_PIVOT, Point::EMPTY, ""))),
            Verdict::Allow
        );
        assert_eq!(
            decide(&elsewhere(host(MG_OP_MOVE_OLD, plain(0xef53, &["x"]), ""))),
            Verdict::Allow
        );
        // the kernel's own mounts below a view stay allowed
        let p = plain(SYSFS_MAGIC, &["debug", "kernel"]);
        assert_eq!(
            decide(&elsewhere(host(MG_OP_MOUNT, p, "debugfs"))),
            Verdict::Allow
        );
        // and the window lets it through, recorded
        let q = Query {
            window: true,
            ..elsewhere(host(
                MG_OP_MOUNT,
                view_root(MG_OWN | MG_HOLD, 0xef53),
                "tmpfs",
            ))
        };
        assert_eq!(decide(&q), Verdict::Window(MG_WHY_ON));
    }

    /// The coordinator's ancestors point: a mount ON a directory above a
    /// protected one (its own key, by kernel identity) is refused; one on
    /// another subdirectory of that ancestor (`/var/lib/docker`,
    /// `/run/user/1000`: no key, the ancestor's own key only on its
    /// parent, which `below` does not take) is not.
    #[test]
    fn a_mount_over_an_ancestor_is_refused_and_one_beside_ours_is_not() {
        let ancestor = view_root(MG_ON | MG_HOLD, TMPFS_MAGIC); // /run, /etc, /var/lib
        for fstype in ["tmpfs", "overlay", "fuse"] {
            assert_eq!(
                decide(&host(MG_OP_MOUNT, ancestor, fstype)),
                Verdict::Refuse(MG_WHY_ON)
            );
        }
        assert_eq!(
            decide(&host(MG_OP_BIND, ancestor, "")),
            Verdict::Refuse(MG_WHY_ON)
        );
        // by propagation too
        let q = Query {
            host: false,
            reaches: true,
            ..host(MG_OP_MOUNT, ancestor, "tmpfs")
        };
        assert_eq!(decide(&q), Verdict::Refuse(MG_WHY_ON));
        // a sibling: its parent is the ancestor (an ON key, not OWN/VIEW)
        for (magic, names) in [
            (0xef53, &["docker", "lib", "var"][..]),
            (TMPFS_MAGIC, &["1000", "user"][..]),
        ] {
            let p = plain(magic, names);
            assert_eq!(decide(&host(MG_OP_MOUNT, p, "tmpfs")), Verdict::Allow);
        }
    }

    #[test]
    fn another_mount_namespace_is_untouched() {
        let refused = [
            host(
                MG_OP_MOUNT,
                view_root(MG_VIEW | MG_HOLD, PROC_SUPER_MAGIC),
                "fuse",
            ),
            host(MG_OP_MOVE_OLD, Point::EMPTY, ""),
            host(MG_OP_PIVOT, Point::EMPTY, ""),
            Query {
                held: true,
                ..host(MG_OP_UMOUNT, Point::EMPTY, "")
            },
        ];
        for q in refused {
            assert!(matches!(decide(&q), Verdict::Refuse(_)));
            // a container, `unshare -m`, a unit's sandbox
            assert_eq!(decide(&Query { host: false, ..q }), Verdict::Allow);
            // an unprivileged caller: the kernel's own EPERM, no record
            assert_eq!(
                decide(&Query {
                    privileged: false,
                    ..q
                }),
                Verdict::Allow
            );
        }
    }

    #[test]
    fn a_remount_or_propagation_change_is_never_judged() {
        let q = host(
            MG_OP_PASS,
            view_root(MG_VIEW | MG_HOLD, PROC_SUPER_MAGIC),
            "proc",
        );
        assert_eq!(decide(&q), Verdict::Allow);
    }

    #[test]
    fn pid_one_unmounts_but_never_mounts_unjudged() {
        let q = Query {
            held: true,
            init: true,
            ..host(MG_OP_UMOUNT, Point::EMPTY, "")
        };
        assert_eq!(decide(&q), Verdict::Allow);
        // `systemd-mount` makes PID 1 mount for its caller: judged
        let q = Query {
            init: true,
            ..host(MG_OP_MOUNT, view_root(MG_OWN | MG_HOLD, 0xef53), "tmpfs")
        };
        assert_eq!(decide(&q), Verdict::Refuse(MG_WHY_ON));
        let q = Query {
            init: true,
            ..host(MG_OP_PIVOT, Point::EMPTY, "")
        };
        assert_eq!(decide(&q), Verdict::Refuse(MG_WHY_PIVOT));
    }

    #[test]
    fn the_trusted_installer_window_lets_through_and_records() {
        let q = Query {
            window: true,
            ..host(MG_OP_MOUNT, view_root(MG_OWN | MG_HOLD, 0xef53), "tmpfs")
        };
        assert_eq!(decide(&q), Verdict::Window(MG_WHY_ON));
        let q = Query {
            window: true,
            held: true,
            ..host(MG_OP_UMOUNT, Point::EMPTY, "")
        };
        assert_eq!(decide(&q), Verdict::Window(MG_WHY_UMOUNT));
        // nothing to record for what is allowed outside one
        let q = Query {
            window: true,
            ..host(MG_OP_MOUNT, plain(0xef53, &["x"]), "tmpfs")
        };
        assert_eq!(decide(&q), Verdict::Allow);
    }

    // ── names and the record ──

    #[test]
    fn names_compare_exactly() {
        assert!(NameKey::of("debugfs").matches(&NameKey::of("debugfs")));
        assert!(!NameKey::of("debugfs").matches(&NameKey::of("debugf")));
        assert!(!NameKey::of("debugfs").matches(&NameKey::of("debugfs2")));
        // past the eighth byte
        assert!(!NameKey::of("binfmt_misc").matches(&NameKey::of("binfmt_mxxx")));
        assert!(!NameKey::of("connections").matches(&NameKey::of("connectionz")));
        // 15 bytes, the longest told apart, and their 16-byte extension
        let a = NameKey::of("0123456789abcde");
        assert!(a.matches(&NameKey::of("0123456789abcde")));
        assert!(!a.matches(&NameKey::of("0123456789abcdef")));
        // a name longer than 15 bytes never matches, not even itself
        let long = NameKey::of("0123456789abcdef");
        assert!(!long.matches(&long));
        assert!(!NameKey::NONE.matches(&NameKey::NONE));
        assert!(NameKey::ANY.matches(&NameKey::of("cpu")));
        assert!(!NameKey::ANY.matches(&NameKey::NONE));
        // the hook's buffer: the kernel's copy stops at the NUL, the rest
        // of the zeroed buffer stays zero
        let mut buf = [0u8; 16];
        buf[..5].copy_from_slice(b"proc\0");
        assert_eq!(NameKey::from_parts(4, &buf), NameKey::of("proc"));
        // a 16-byte name cut to 15 by the copy: its length keeps it apart
        let mut cut = [0u8; 16];
        cut[..15].copy_from_slice(b"0123456789abcde");
        assert!(!a.matches(&NameKey::from_parts(16, &cut)));
        assert!(ALLOWED_KERNEL_MOUNTS
            .iter()
            .all(|a| a.fstype.len <= NAME_MAX
                && a.names
                    .iter()
                    .all(|n| n.len <= NAME_MAX || n.len >= NAME_ANY)));
        // the list's own names never collide with each other
        let mut keys: Vec<u64> = ALLOWED_KERNEL_MOUNT_TYPES
            .iter()
            .map(|t| NameKey::of(t).h)
            .collect();
        keys.sort_unstable();
        keys.dedup();
        let mut types: Vec<&str> = ALLOWED_KERNEL_MOUNT_TYPES.to_vec();
        types.sort_unstable();
        types.dedup();
        assert_eq!(keys.len(), types.len());
    }

    #[test]
    fn a_record_carries_its_operation_reason_and_view() {
        let d = record_dev(0x0000_0803, MG_OP_MOUNT, MG_WHY_BELOW_VIEW, 1, 2);
        assert_eq!(record_of(d), (0x803, MG_OP_MOUNT, MG_WHY_BELOW_VIEW, 1, 2));
        // the reach, beside the mounts covered
        let d = record_dev(0x803, MG_OP_BIND, MG_WHY_ON, 2, 3 | REACH_OTHER_NS << 4);
        assert_eq!(reach_of(d), REACH_OTHER_NS);
        assert_eq!(record_of(d).4, 3);
        assert_eq!(reach_of(record_dev(0x803, MG_OP_BIND, MG_WHY_ON, 2, 3)), 0);
        assert_ne!(reach_name(REACH_OTHER_NS), reach_name(0));
        // the device never spills into the operation
        let d = record_dev(u64::MAX, MG_OP_PIVOT, MG_WHY_PIVOT, 0, 0xff);
        assert_eq!(
            record_of(d),
            (0xffff_ffff, MG_OP_PIVOT, MG_WHY_PIVOT, 0, 0xf)
        );
        for op in 1..=8 {
            assert_ne!(op_name(op), "mount operation");
        }
        for why in 1..=10 {
            assert_ne!(why_name(why), "a mount refused");
        }
        // the review of #567 (F2): the agent's and the watchdog's own
        // namespaces are named in the record
        for (guard, reach) in [
            (GUARD_HOST, 0),
            (GUARD_AGENT, REACH_AGENT_NS),
            (GUARD_WATCHDOG, REACH_WATCHDOG_NS),
        ] {
            assert_eq!(reach_in(guard), reach);
            let d = record_dev(0x803, MG_OP_MOUNT, MG_WHY_ON, 0, reach << 4);
            assert_eq!(reach_of(d), reach);
        }
        assert!(reach_name(REACH_AGENT_NS).contains("the agent's own"));
        assert!(reach_name(REACH_WATCHDOG_NS).contains("the watchdog's own"));
        assert_ne!(reach_name(REACH_AGENT_NS), reach_name(0));
        assert_eq!(view_of(PROC_SUPER_MAGIC), 1);
        assert_eq!(view_name(view_of(BPF_FS_MAGIC)), "the bpffs");
    }

    #[test]
    fn the_view_magics_are_the_uapi_ones() {
        // include/uapi/linux/magic.h
        assert_eq!(PROC_SUPER_MAGIC, 0x9fa0);
        assert_eq!(SYSFS_MAGIC, 0x62656572);
        assert_eq!(CGROUP2_SUPER_MAGIC, 0x63677270);
        assert_eq!(BPF_FS_MAGIC, 0xcafe4a11);
        assert_eq!(TMPFS_MAGIC, 0x01021994);
        assert_eq!(AUTOFS_SUPER_MAGIC, 0x0187);
        assert!(!is_view_magic(TMPFS_MAGIC));
        assert!(!is_view_magic(AUTOFS_SUPER_MAGIC));
        assert_eq!(TRACEFS_MAGIC, 0x74726163);
        assert_eq!(DEBUGFS_MAGIC, 0x64626720);
        assert_eq!(SECURITYFS_MAGIC, 0x73636673);
        for (m, v) in [
            (TRACEFS_MAGIC, "the tracefs"),
            (DEBUGFS_MAGIC, "the debugfs"),
            (SECURITYFS_MAGIC, "the securityfs"),
        ] {
            assert!(is_view_magic(m));
            assert_eq!(view_name(view_of(m)), v);
        }
    }

    // ── the review of #567 ──

    /// F3: a super block's reconfigure (proc's `subset=pid`, `hidepid`, a
    /// read-only state file system; `mount -o remount` and fsconfig's
    /// reconfigure alike) is refused for a held super block, in whatever
    /// namespace (the super block is the host's); not for another one.
    #[test]
    fn a_held_super_blocks_remount_is_refused_in_every_namespace() {
        // a read-only remount (or one whose flags were not read)
        let sb = |held| Query {
            held,
            restrict: true,
            ..host(MG_OP_REMOUNT, Point::EMPTY, "")
        };
        assert_eq!(decide(&sb(true)), Verdict::Refuse(MG_WHY_REMOUNT_SB));
        // from a container that holds the host's root file system by a bind
        assert_eq!(
            decide(&Query {
                host: false,
                ..sb(true)
            }),
            Verdict::Refuse(MG_WHY_REMOUNT_SB)
        );
        // another super block (a container's own proc, /boot, /home)
        assert_eq!(decide(&sb(false)), Verdict::Allow);
        assert_eq!(
            decide(&Query {
                host: false,
                ..sb(false)
            }),
            Verdict::Allow
        );
        // an unprivileged caller: the kernel's own EPERM
        assert_eq!(
            decide(&Query {
                privileged: false,
                ..sb(true)
            }),
            Verdict::Allow
        );
        // the window lets it through, recorded
        assert_eq!(
            decide(&Query {
                window: true,
                ..sb(true)
            }),
            Verdict::Window(MG_WHY_REMOUNT_SB)
        );
    }

    /// F4 and F3: `systemd-shutdown` (and the helpers it forks) unmounts,
    /// remounts read-only, moves the API mounts and pivots to
    /// `/run/initramfs` at the end of a shutdown; the emergency remount is
    /// a kernel thread's. PID 1 at any other time pivots and moves judged,
    /// and nobody mounts over a protected point unjudged.
    #[test]
    fn systemd_shutdown_and_the_kernel_finish_a_shutdown_unjudged() {
        let at_end = |q: Query| Query {
            shutdown: true,
            ..q
        };
        // (a read-only remount: the one that is refused outside a shutdown)
        let held = |op| Query {
            held: true,
            restrict: true,
            ..host(op, Point::EMPTY, "")
        };
        for q in [
            held(MG_OP_UMOUNT),
            held(MG_OP_REMOUNT),
            held(MG_OP_MOVE_MOUNT),
            host(MG_OP_MOVE_OLD, Point::EMPTY, ""),
            host(MG_OP_PIVOT, Point::EMPTY, ""),
        ] {
            assert!(matches!(decide(&q), Verdict::Refuse(_)), "{q:?}");
            assert_eq!(decide(&at_end(q)), Verdict::Allow, "{q:?}");
        }
        assert_eq!(
            decide(&Query {
                kernel: true,
                ..held(MG_OP_REMOUNT)
            }),
            Verdict::Allow
        );
        // a kernel thread is no exemption elsewhere
        assert!(matches!(
            decide(&Query {
                kernel: true,
                ..host(MG_OP_PIVOT, Point::EMPTY, "")
            }),
            Verdict::Refuse(_)
        ));
        // never a mount over a protected point
        let over = host(MG_OP_MOUNT, view_root(MG_OWN | MG_HOLD, 0xef53), "tmpfs");
        assert_eq!(decide(&at_end(over)), Verdict::Refuse(MG_WHY_ON));
        // PID 1 outside the final stage (`systemctl soft-reboot`'s pivot)
        assert_eq!(
            decide(&Query {
                init: true,
                ..host(MG_OP_MOVE_OLD, Point::EMPTY, "")
            }),
            Verdict::Refuse(MG_WHY_MOVE_OLD)
        );
    }

    /// F3: a bind remount (`MS_REMOUNT | MS_BIND`) that makes a held mount
    /// read-only or `noexec` is refused in its own namespace; one that
    /// asks neither, one of another mount, one elsewhere is not.
    #[test]
    fn a_bind_remount_restricting_a_held_mount_is_refused() {
        let q = Query {
            held: true,
            restrict: true,
            ..host(MG_OP_REMOUNT_BIND, Point::EMPTY, "")
        };
        assert_eq!(decide(&q), Verdict::Refuse(MG_WHY_REMOUNT_RESTRICT));
        for allowed in [
            Query {
                restrict: false,
                ..q
            },
            Query { held: false, ..q },
            // per-mount flags never propagate: only the caller's own
            // namespace's mounts change
            Query {
                host: false,
                reaches: true,
                ..q
            },
            Query {
                shutdown: true,
                ..q
            },
        ] {
            assert_eq!(decide(&allowed), Verdict::Allow, "{allowed:?}");
        }
    }

    /// F6: an unmount of the tracefs, debugfs or securityfs the agent
    /// reads is let through and recorded; a held one is refused; PID 1's
    /// and another namespace's are not recorded.
    #[test]
    fn an_unmount_of_a_kernel_file_system_the_agent_reads_is_recorded() {
        let q = Query {
            noted: true,
            ..host(MG_OP_UMOUNT, Point::EMPTY, "")
        };
        assert_eq!(decide(&q), Verdict::Noted(MG_WHY_UMOUNT_NOTED));
        assert_eq!(decide(&Query { init: true, ..q }), Verdict::Allow);
        assert_eq!(
            decide(&Query {
                host: false,
                reaches: true,
                ..q
            }),
            Verdict::Allow
        );
        assert_eq!(
            decide(&Query { held: true, ..q }),
            Verdict::Refuse(MG_WHY_UMOUNT)
        );
    }

    /// F6: the kernel's own type at its canonical point passes only as a
    /// whole file system — a clone of one of its subdirectories (securityfs'
    /// `apparmor/` moved onto `/sys/kernel/security`) is refused.
    #[test]
    fn a_clone_of_a_subdirectory_never_passes_as_the_kernels_mount() {
        let p = plain(SYSFS_MAGIC, &["security", "kernel"]);
        let whole = host(MG_OP_MOVE_MOUNT, p, "securityfs");
        assert_eq!(decide(&whole), Verdict::Allow);
        assert_eq!(
            decide(&Query {
                src_root: false,
                ..whole
            }),
            Verdict::Refuse(MG_WHY_BELOW_VIEW)
        );
        assert!(!allowed_kernel_mount(&NameKey::of("securityfs"), &p, false));
    }

    /// F1: the keys of the mounts held are their ids (and, for an unmount
    /// that propagates, their place and their parent's peer group), never
    /// a real inode's key.
    #[test]
    fn the_held_mounts_keys_never_meet_an_inodes() {
        let (d, i) = held_by_id(4242);
        assert_eq!((d & !HELD_BY_ID, i), (4242, 0));
        assert_ne!(d & HELD_BY_ID, 0);
        let cg = NameKey::of("cgroup");
        let (d2, _) = held_by_place(7, 0x16, 33, &cg);
        assert_ne!(d2 & HELD_BY_PLACE, 0);
        assert_eq!(d2 & 0xffff_ffff, 7);
        // a real device is 32 bits (MKDEV): never a tag
        assert_eq!(u32::MAX as u64 & (HELD_BY_ID | HELD_BY_PLACE), 0);
        assert_ne!(held_by_id(7).0, held_by_place(7, 0, 0, &cg).0);
        // another group, directory or name is another place
        let k = held_by_place(7, 0x16, 33, &cg);
        assert_ne!(k, held_by_place(8, 0x16, 33, &cg));
        assert_ne!(k, held_by_place(7, 0x17, 33, &cg));
        assert_ne!(k, held_by_place(7, 0x16, 34, &cg));
        assert_ne!(k, held_by_place(7, 0x16, 33, &NameKey::of("bpf")));
        assert_eq!(k, held_by_place(7, 0x16, 33, &NameKey::of("cgroup")));
    }

    /// F1: a chroot's setup on the host's super blocks (`mount -t sysfs`
    /// at `$T/sys`, then `mount -t cgroup2` at `$T/sys/fs/cgroup`) mounts
    /// the kernel's own type at its canonical point: allowed; another type
    /// there, or anything over the host's own cgroup root, is not.
    #[test]
    fn a_chroots_cgroup2_on_the_hosts_sysfs_is_the_kernels_own() {
        let p = plain(SYSFS_MAGIC, &["cgroup", "fs"]);
        assert_eq!(decide(&host(MG_OP_MOUNT, p, "cgroup2")), Verdict::Allow);
        assert_eq!(
            decide(&host(MG_OP_MOUNT, p, "tmpfs")),
            Verdict::Refuse(MG_WHY_BELOW_VIEW)
        );
        let own = view_root(MG_VIEW | MG_HOLD, CGROUP2_SUPER_MAGIC);
        assert_eq!(
            decide(&host(MG_OP_MOUNT, own, "cgroup2")),
            Verdict::Refuse(MG_WHY_ON)
        );
    }

    /// F3 and finalrd (Ubuntu's shutdown pivot root: `mount -o
    /// remount,exec /run`): a held file system's reconfigure that keeps it
    /// writable passes; made read-only, or its flags unread, it is refused;
    /// a view's is refused whatever its options.
    #[test]
    fn only_a_read_only_remount_of_the_agents_file_systems_is_refused() {
        let q = |magic, restrict| Query {
            held: true,
            restrict,
            point: Point {
                magic,
                ..Point::EMPTY
            },
            ..host(MG_OP_REMOUNT, Point::EMPTY, "")
        };
        assert_eq!(
            decide(&q(TMPFS_MAGIC, false)),
            Verdict::Allow,
            "remount,exec /run"
        );
        assert_eq!(
            decide(&q(0xef53, false)),
            Verdict::Allow,
            "remount,commit=60 /"
        );
        assert_eq!(decide(&q(0xef53, true)), Verdict::Refuse(MG_WHY_REMOUNT_SB));
        for view in [
            PROC_SUPER_MAGIC,
            SYSFS_MAGIC,
            CGROUP2_SUPER_MAGIC,
            BPF_FS_MAGIC,
        ] {
            assert_eq!(
                decide(&q(view, false)),
                Verdict::Refuse(MG_WHY_REMOUNT_SB),
                "{view:x}"
            );
        }
    }
}
