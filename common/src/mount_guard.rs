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
/// `MS_REC`: the change made to the whole subtree of the mount.
pub const MS_REC: u64 = 1 << 14;
/// `MS_UNBINDABLE`.
pub const MS_UNBINDABLE: u64 = 1 << 17;
/// `MS_PRIVATE`.
pub const MS_PRIVATE: u64 = 1 << 18;
/// `MS_SLAVE`.
pub const MS_SLAVE: u64 = 1 << 19;
/// `MS_SHARED`.
pub const MS_SHARED: u64 = 1 << 20;

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
/// Lot 359 (the re-check 3 of #567, N4): the agent's pin directory — the
/// root and the place of its lock ([`lock_bind`]): a self-bind of the
/// directory, private and unbindable, as the bpffs's child in PID 1's
/// namespace.
pub const MG_LOCK: u8 = 32;
/// Lot 359: a directory above the pin directory (`/`, `/sys`, `/sys/fs`,
/// `/sys/fs/bpf`): a recursive `MS_SHARED` made on a mount rooted there,
/// or a recursive `MS_PRIVATE` in PID 1's namespace (the review of #569),
/// reaches the lock ([`lock_touched`]).
pub const MG_LOCK_ABOVE: u8 = 64;
/// Lot 2.3a (the review of #647, K4): the key files (`admin.pub`, the
/// agent's signing key) and their directory: a mount on, over or below
/// one is refused inside a window too — no window lifts it (the window
/// lifts what it lifts of [`MG_OWN`] and [`MG_ON`] elsewhere). Propagated
/// to the points below like [`MG_OWN`] (`Point::below`).
pub const MG_KEPT: u8 = 128;

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

/// The re-check of #567 (N1): `MOUNT_HELD`'s key of a held mount by its
/// place under its parent mount itself (the parent's id, not its group):
/// `(HELD_UNDER | parent id, the place's hash)`. Registered for every held
/// mount beside the keys under its parent's groups; looked up, mount by
/// mount, along the propagation of an unmount whose parent is in a group
/// the map does not hold ([`umount_reaches_held`]) — a parent regrouped
/// since the agent's last refresh (`mount --make-private`, a decoy taking
/// the freed number, `--make-shared`) is in a group the places were not
/// keyed under. By the parent itself: a chroot's own sysfs has the host's
/// dentries (one super block), so a place alone would take its
/// `sys/fs/cgroup` for the host's.
pub const HELD_UNDER: u64 = HELD_BY_PLACE | 1 << 61;

/// [`HELD_UNDER`]'s key of a place under the parent mount `parent_mnt_id`
/// (the hash is [`held_by_place`]'s, whatever the group).
pub const fn held_under(
    parent_mnt_id: u32,
    dir_dev: u64,
    dir_ino: u64,
    name: &NameKey,
) -> (u64, u64) {
    let (_, h) = held_by_place(0, dir_dev, dir_ino, name);
    (HELD_UNDER | parent_mnt_id as u64, h)
}

/// Lot 1.1 (the review of #569, F2): `MOUNT_HELD`'s key of a held mount by
/// its own peer group (`shared:N`) and its root (the root dentry's key, as
/// `stat(2)` gives it): `(HELD_ROOT | group, mix(root))`. Peers share
/// their group and their root dentry, so a mount with that group and that
/// root is a peer copy of the held mount, in whatever namespace it is. A
/// slave (`master:N` only) is not one.
///
/// Its tag is bit 61 alone: a key of every other kind has bit 62
/// ([`HELD_BY_ID`]) or bit 63 ([`HELD_BY_PLACE`], [`HELD_UNDER`]).
pub const HELD_ROOT: u64 = 1 << 61;

/// [`HELD_ROOT`]'s key of a peer group and a root.
pub const fn held_root(group: u32, root_dev: u64, root_ino: u64) -> (u64, u64) {
    let (_, h) = held_by_place(group, root_dev, root_ino, &NameKey::NONE);
    (HELD_ROOT | group as u64, h)
}

/// Lot 1.1 (the review of #569, F2): a `move_mount(2)` takes away a peer
/// copy of a held mount — an attached mount (`attached`: not a detached
/// tree being attached, which is judged where it lands) in a peer group
/// (`group`), whose group and root are a held mount's ([`HELD_ROOT`]'s key
/// found: `root_held`). Its source is judged, not only where it lands:
/// refused in any namespace ([`copy_move_verdict`]), signed as
/// [`MG_WHY_MOVE_COPY`].
pub const fn moves_held_copy(attached: bool, group: u32, root_held: bool) -> bool {
    attached && group != 0 && root_held
}

/// [`moves_held_copy`]'s verdict, [`MG_WHY_MOVE_COPY`]'s: refused
/// (outside the trusted-installer window, which lets it through
/// recorded), never at the end of a shutdown (`systemd-shutdown` moves
/// what it unmounts last). A tag without a payload: a [`Verdict::Allow`]
/// through the stack is a byte 5.15's verifier refuses to read
/// uninitialized.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CopyMove {
    Allow,
    Refuse,
    Window,
}

/// [`CopyMove`] of a move ([`moves_held_copy`]'s answer `held_copy`).
pub const fn copy_move_verdict(held_copy: bool, shutdown: bool, window: bool) -> CopyMove {
    if !held_copy || shutdown {
        CopyMove::Allow
    } else if window {
        CopyMove::Window
    } else {
        CopyMove::Refuse
    }
}

impl CopyMove {
    /// The hook's verdict of it.
    pub const fn verdict(self) -> Verdict {
        match self {
            CopyMove::Allow => Verdict::Allow,
            CopyMove::Refuse => Verdict::Refuse(MG_WHY_MOVE_COPY),
            CopyMove::Window => Verdict::Window(MG_WHY_MOVE_COPY),
        }
    }

    /// The hook's [`verdict_code`] of it.
    pub const fn code(self) -> u16 {
        match self {
            CopyMove::Allow => 0,
            CopyMove::Refuse => CODE_REFUSE | MG_WHY_MOVE_COPY as u16,
            CopyMove::Window => CODE_WINDOW | MG_WHY_MOVE_COPY as u16,
        }
    }
}

// ── The verdict as a number (lot 1.1, F8b-1) ──────────────────────────────

/// [`verdict_code`]'s kinds, in its high byte (the reason in the low one).
pub const CODE_REFUSE: u16 = 1 << 8;
pub const CODE_WINDOW: u16 = 2 << 8;
pub const CODE_NOTED: u16 = 3 << 8;

/// Lot 1.1 (F8b-1): a [`Verdict`] as the hooks carry it — a number whose
/// every bit is defined: `kind << 8 | reason`, 0 to let through. A
/// `Verdict` through a hook's stack, or merged from several of
/// [`decide_as`]'s returns, is a tag and a payload byte, and `Allow`'s
/// payload is undefined: 5.15's verifier refused the read of that byte
/// (`invalid read from stack`, `R3 !read_ok`) where the compiler moved it
/// above the tag's test.
pub const fn verdict_code(v: Verdict) -> u16 {
    match v {
        Verdict::Allow => 0,
        Verdict::Refuse(w) => CODE_REFUSE | w as u16,
        Verdict::Window(w) => CODE_WINDOW | w as u16,
        Verdict::Noted(w) => CODE_NOTED | w as u16,
    }
}

/// [`verdict_code`] read back.
pub const fn verdict_of_code(code: u16) -> Verdict {
    let w = (code & 0xff) as u8;
    match code & 0xff00 {
        CODE_REFUSE => Verdict::Refuse(w),
        CODE_WINDOW => Verdict::Window(w),
        CODE_NOTED => Verdict::Noted(w),
        _ => Verdict::Allow,
    }
}

/// Lot 1.1 (F8b-1): [`decide_as`]'s [`verdict_code`] — the decision the
/// hooks take (inlined: its operation a constant of the hook's).
#[inline(always)]
pub fn decide_code(op: u8, q: &Query) -> u16 {
    verdict_code(decide_as(op, q))
}

// ── The split hooks (lot 1.1, F8b-1) ──────────────────────────────────────

/// Lot 1.1 (F8b-1): `sb_mount` and `move_mount` are each an entry program
/// (the hook) and stages it tail-calls through a program array of its own
/// — the entry reads what is cheap and where the target lands (the
/// propagation walk), the stage what lands there (the point's names and
/// ancestors) and decides. Each program is verified on its own: the
/// states the walk leaves never multiply the point's (5.15 processed
/// 830,908 instructions of `sb_mount`, 92.3 % of the 900k gate). The
/// stage judging where a mount lands: slot 0 of each array.
pub const STAGE_POINT: u32 = 0;
/// `sb_mount`'s stage judging a change of propagation that reaches the pin
/// directory's lock (`MS_SHARED`, `MS_PRIVATE`, `MS_SLAVE`,
/// `MS_UNBINDABLE`): slot 1 of its array.
pub const STAGE_PROPAGATE: u32 = 1;
/// The slots of each hook's program array.
pub const STAGE_SLOTS: u32 = 2;

/// Where `sb_mount`'s entry sends a `mount(2)` by its flags alone, before
/// it reads anything.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SbRoute {
    /// Nothing the guard judges (a plain remount, which `sb_remount`
    /// judges): let through unread.
    Pass,
    /// A change of propagation: counted for the refresh, and judged by
    /// [`STAGE_PROPAGATE`] where it reaches the lock.
    Propagate,
    /// A new mount, a bind, a move, a bind remount: judged by
    /// [`STAGE_POINT`] once the entry found the target reaching a guarded
    /// namespace.
    Point,
}

/// [`SbRoute`] of `mount(2)`'s `flags` — [`mount_op`]'s and [`regroups`]'
/// order, the kernel's (`path_mount()`).
pub const fn sb_mount_route(flags: u64) -> SbRoute {
    if mount_op(flags) != MG_OP_PASS {
        SbRoute::Point
    } else if regroups(flags) {
        SbRoute::Propagate
    } else {
        SbRoute::Pass
    }
}

// ── `MOUNT_GUARD_CONF`'s slots shared with the agent (lot 1.1) ───────────

/// `MOUNT_GUARD_CONF`'s slot counting the propagation changes the kernel
/// makes on a mount of a guarded namespace, of a peer group `MOUNT_GROUPS`
/// holds, or on the pin directory's lock (or a copy of it): counted by the
/// `change_mnt_propagation()` fentry — `mount_setattr(2)`'s changes, which
/// no LSM hook sees, among them — as the change is made. Reserved: no
/// reader yet (the agent's `RegroupWatch::propagated` has no caller until
/// the follow-up that wakes the integrity round on it); until then the
/// round signs such a change at its next pass, and the refresh is woken
/// through the regroup slot (`MOUNT_GUARD_CONF`'s slot 4).
pub const CONF_PROPAGATED: u32 = 5;
/// `MOUNT_GUARD_CONF`'s entries.
pub const CONF_SLOTS: u32 = 6;

/// Lot 1.1 (the change_mnt_propagation fentry): a propagation change the
/// kernel makes on a mount counts — the mount is still in a namespace
/// (`in_ns`: `umount_tree()` makes every mount it takes private after
/// clearing its namespace, an unmount the hooks judged), and it is in a
/// guarded one (`guard`), in a peer group `MOUNT_GROUPS` holds
/// (`group_known`), or it is the pin directory's lock or a copy of it
/// (`lock`: [`MG_LOCK`] at its root).
pub const fn propagation_counts(in_ns: bool, guard: u8, group_known: bool, lock: bool) -> bool {
    in_ns && (guard != 0 || group_known || lock)
}

/// Lot 1.1 (the re-check 2 of #569, N3): the agent's or the watchdog's own
/// mount namespace (`inum`) is judged as theirs — never when it is PID 1's
/// (`host`: an agent or a watchdog run by hand there), whose entry stays
/// [`GUARD_HOST`] and which the role's exit never drops ([`vacates`]).
pub const fn guards_own_namespace(inum: u64, host: u64) -> bool {
    inum != 0 && inum != host
}

/// Lot 1.1 (N3): the role's exit drops its namespace's entry — never PID
/// 1's (`host`), whatever the role's slot holds.
pub const fn vacates(inum: u64, host: u64) -> bool {
    inum != 0 && inum != host
}

// ── Propagation: where a change made elsewhere lands (re-check N1) ───────

/// How many mounts of a peer group's propagation [`spread`] reads: the
/// target mount's peers, each followed by its slaves, one at a time.
pub const SPREAD_MAX: u32 = 16;

/// What [`spread`] found.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Spread {
    /// Every peer and each one's every slave read: none in a guarded
    /// namespace, none propagating further.
    Nowhere,
    /// A mount of a guarded namespace among them.
    Guarded,
    /// Not decided — more mounts than [`SPREAD_MAX`], a slave that has
    /// peers or slaves of its own, a peer ring unreadable: counted as
    /// reaching (fail closed; [`decide`] refuses there only what lands on,
    /// over or below a protected point).
    Unread,
}

/// The kernel's propagation objects as a hook reads them: a `struct mount`
/// (a pointer in the eBPF hooks, an index in the host's tests).
pub trait Mounts {
    type M: Copy + PartialEq;
    /// Its own peer group (`mnt_group_id`), 0 for none.
    fn group(&self, m: Self::M) -> u32;
    /// The guarded namespace it is in (`MOUNT_GUARD_NS` of its `mnt_ns`):
    /// [`GUARD_HOST`] …, 0 for another one.
    fn guard(&self, m: Self::M) -> u8;
    /// `MOUNT_GROUPS` holds the group: the own or master group of a mount
    /// of a guarded namespace that holds a protected point or is a view.
    fn known(&self, group: u32) -> bool;
    /// The next mount of its peer ring (`mnt_share`); `None`: unreadable.
    fn next_peer(&self, m: Self::M) -> Option<Self::M>;
    /// Its first slave (`mnt_slave_list`); `None`: it has none.
    fn first_slave(&self, m: Self::M) -> Option<Self::M>;
    /// The slave after `s` in `master`'s list (`mnt_slave`); `None`: `s`
    /// is the last.
    fn next_slave(&self, master: Self::M, s: Self::M) -> Option<Self::M>;
}

/// The re-check of #567 (N1): whether a change at the mount `m` (in a peer
/// group) is copied into a guarded namespace, read in the kernel's order
/// (`propagation_next()`): `m`, then each of its slaves, then the next peer
/// and its slaves, around the ring. A slave that is itself shared, or a
/// master, carries the change on to mounts not read here: undecided.
#[inline(always)]
pub fn spread<G: Mounts>(g: &G, m: G::M) -> Spread {
    let mut peer = m;
    // the slave walked, valid while `in_slaves` — never an `Option` carried
    // across the loop: its `None` leaves the payload unwritten, and the BPF
    // back end may load it before it tests the tag (the review of #569's
    // fix round: 5.15's verifier refused `sb_mount`, "invalid read from
    // stack", the uninitialized payload of `None`)
    let mut slave = m;
    let mut in_slaves = false;
    let mut i = 0;
    while i < SPREAD_MAX {
        let at = if in_slaves { slave } else { peer };
        if g.guard(at) != 0 {
            return Spread::Guarded;
        }
        if in_slaves && (g.group(at) != 0 || g.first_slave(at).is_some()) {
            return Spread::Unread;
        }
        let next = if in_slaves {
            g.next_slave(peer, slave)
        } else {
            g.first_slave(peer)
        };
        match next {
            Some(s) => {
                slave = s;
                in_slaves = true;
            }
            None => {
                in_slaves = false;
                match g.next_peer(peer) {
                    None => return Spread::Unread,
                    Some(n) if n == m => return Spread::Nowhere,
                    Some(n) => peer = n,
                }
            }
        }
        i += 1;
    }
    Spread::Unread
}

/// A change at the mount `m` propagates into a guarded namespace, or may:
/// its peer group is one `MOUNT_GROUPS` follows, or — a group the agent's
/// refresh has not seen yet (re-check N1: a guarded mount regrouped since,
/// by `mount(2)` or `mount_setattr(2)`) — its propagation reaches one or is
/// not read whole ([`spread`]). A mount in no peer group propagates
/// nothing.
#[inline(always)]
pub fn group_reaches<G: Mounts>(g: &G, m: G::M) -> bool {
    let group = g.group(m);
    group != 0 && (g.known(group) || spread(g, m) != Spread::Nowhere)
}

/// The re-check of #567 (N1): [`held_by_place`]'s group of a held mount's
/// place under any group — registered for every held mount, and asked of
/// the PARENT of an unmount whose propagation could not be read whole
/// ([`umount_takes_held`]): a parent that sits where a held mount sits (a
/// raw namespace's copy of `/sys`) is a copy of a held mount; a chroot's
/// own sysfs at `$T/sys` is not.
pub const PLACE_ANY_GROUP: u32 = 0;

/// The re-check of #567 (N1), its unmount variant: the propagation of an
/// unmount at a place under `parent`, when `parent` is in a peer group the
/// map does not hold — `None` when not walked (no group: it propagates
/// nothing; a group the map holds: the places keyed under it decide,
/// [`held_by_place`]). The kernel takes the mount at the same place under
/// every mount of the parent's propagation; `g`'s [`Mounts::guard`] is,
/// here, "a held mount sits at that place under this mount"
/// ([`held_under`]).
#[inline(always)]
pub fn umount_spread<G: Mounts>(g: &G, parent: G::M) -> Option<Spread> {
    let group = g.group(parent);
    if group == 0 || g.known(group) {
        None
    } else {
        Some(spread(g, parent))
    }
}

/// [`umount_spread`]'s verdict: a held mount under one of the parent's
/// propagation at that place — taken; a walk that could not be finished —
/// taken when the mount unmounted has a held mount's root (`held_root`:
/// [`MG_HOLD`] at its root) and the parent is a copy of a held mount
/// (`parent_held_like`: its namespace's root, or sitting at a held mount's
/// place under any group, [`PLACE_ANY_GROUP`]), fail closed for what
/// resolves to a protected point; let through otherwise (a chroot's own
/// sysfs, whose copies in every sandboxed unit's namespace make its
/// propagation wider than the walk, unmounting its `sys/fs/cgroup`).
pub const fn umount_takes_held(s: Option<Spread>, held_root: bool, parent_held_like: bool) -> bool {
    match s {
        Some(Spread::Guarded) => true,
        Some(Spread::Unread) => held_root && parent_held_like,
        _ => false,
    }
}

// ── An unmount's subtree (the re-check 2 of #567, N3) ────────────────────

/// How many mounts below an unmounted one [`umount_below`] reads, in the
/// kernel's order (`next_mnt()`, the order `umount_tree()` collects them
/// in).
pub const SUBTREE_MAX: u32 = 32;

/// How many levels one step of [`umount_below`] climbs back up, to the
/// next sibling of a mount or of one of its parents.
pub const SUBTREE_DEPTH: u32 = 8;

/// [`below_of`]: the unmount of this mount takes a held mount with it
/// (beyond any peer group's number).
pub const BELOW_TAKES: u64 = 1 << 32;

/// The re-check 2 of #567 (N3): the mounts below an unmounted mount, as
/// `sb_umount` reads them (`struct mount`'s `mnt_mounts`, `mnt_child` and
/// `mnt_parent`; a pointer in the eBPF hook, an index in the host's
/// tests). A lazy unmount (`MNT_DETACH`) calls the hook once, for the top:
/// the kernel then takes the whole subtree (`umount_tree()`) and propagates
/// the unmount of each of its mounts to the peers and slaves of that
/// mount's parent, with no other LSM call.
pub trait Tree {
    type M: Copy + PartialEq;
    /// Its first child (`mnt_mounts`); `None`: it has none.
    fn first_child(&self, m: Self::M) -> Option<Self::M>;
    /// The child of its parent after it (`mnt_child`); `None`: the last.
    fn next_sibling(&self, m: Self::M) -> Option<Self::M>;
    /// Its parent (`mnt_parent`).
    fn parent(&self, m: Self::M) -> Self::M;
    /// [`below_of`] this mount: [`BELOW_TAKES`], or its parent's peer
    /// group (0: none).
    fn below(&self, m: Self::M) -> u64;
}

/// What [`umount_below`] found.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Below {
    /// Every mount below the unmounted one read: none takes a held mount.
    Clear,
    /// One of them takes a held mount with it.
    Takes,
    /// More than [`SUBTREE_MAX`] mounts, or deeper than a climb reads:
    /// not read whole. `reaches`: a mount read sits under a parent in a
    /// peer group.
    Unread { reaches: bool },
}

/// One step of [`umount_below`]: the mount after `at` in the kernel's
/// order below `top` — its first child, else the next sibling of it or of
/// the nearest of its parents that has one ([`SUBTREE_DEPTH`] levels).
#[derive(Clone, Copy)]
enum Step<M> {
    Next(M),
    Done,
    Deep,
}

#[inline(always)]
fn next_below<T: Tree>(t: &T, at: T::M, top: T::M) -> Step<T::M> {
    if let Some(c) = t.first_child(at) {
        return Step::Next(c);
    }
    let mut m = at;
    let mut j = 0;
    while j < SUBTREE_DEPTH {
        if m == top {
            return Step::Done;
        }
        if let Some(s) = t.next_sibling(m) {
            return Step::Next(s);
        }
        m = t.parent(m);
        j += 1;
    }
    Step::Deep
}

/// The re-check 2 of #567 (N3): the subtree of the mount `top` an unmount
/// takes, read in the kernel's order up to [`SUBTREE_MAX`] mounts, each
/// mount below `top` asked [`Tree::below`]. `mount --rbind /sys /mnt/s;
/// umount -l /mnt/s` judged only the top (a copy, at a place nothing is
/// held at); the kernel took the host's childless `/sys/fs/bpf` and
/// `/sys/fs/cgroup` through the copies below it — in every slave namespace
/// too, the agent's own included: the bpffs lost its last mount. Each step
/// carries nothing but the mount reached and the groups read (one value:
/// 5.15's verifier explores every state a step leaves).
#[inline(always)]
pub fn umount_below<T: Tree>(t: &T, top: T::M) -> Below {
    let mut at = top;
    // the peer groups of the parents read, OR-ed
    let mut groups: u64 = 0;
    // Lot 400: the bound's test closes the loop, the step after the last
    // mount read is taken after it. With the test inside (`if i ==
    // SUBTREE_MAX { break }` after the step), every exit of the loop was in
    // its body: rustc 1.99's LLVM 22 laid the latch — the groups OR-ed and
    // the count — above the header it fell through into, a back-edge 5.15's
    // and 6.1's verifiers refuse (`no_function_has_a_back_edge_the_5_15_
    // verifier_rejects`). The mounts read and the verdicts are the same.
    let mut left = SUBTREE_MAX;
    loop {
        match next_below(t, at, top) {
            Step::Done => return Below::Clear,
            Step::Deep => {
                return Below::Unread {
                    reaches: groups != 0,
                };
            }
            Step::Next(n) => {
                at = n;
                let v = t.below(n);
                if v & BELOW_TAKES != 0 {
                    return Below::Takes;
                }
                groups |= v;
            }
        }
        left -= 1;
        if left == 0 {
            break;
        }
    }
    // SUBTREE_MAX mounts read: whether there is another
    match next_below(t, at, top) {
        Step::Done => Below::Clear,
        Step::Deep | Step::Next(_) => Below::Unread {
            reaches: groups != 0,
        },
    }
}

/// [`umount_below`]'s verdict: taken — or not read whole, when the subtree
/// can reach a held mount: it is in a guarded namespace (`guarded`: a
/// copy may lie below the mounts read, behind private ones), or a mount
/// read sits under a parent in a peer group. A container runtime's old
/// root (`pivot_root`, then `umount2(MNT_DETACH)`: every mount a slave or
/// private, in a namespace of its own) is let through, however many
/// mounts it has.
pub const fn below_takes_held(b: Below, guarded: bool) -> bool {
    match b {
        Below::Takes => true,
        Below::Unread { reaches } => guarded || reaches,
        Below::Clear => false,
    }
}

/// The re-check 2 of #567 (N3): what the unmount of one mount below the
/// unmounted one takes, as the unmount of the top is judged — each read
/// only as far as needed, a finding returned at once:
/// - `group`: its parent's peer group (0: none, its unmount propagates
///   nowhere) — returned when it takes nothing;
/// - `held_at_place`: a held mount sits at its place under that group
///   ([`held_by_place`]): the kernel takes it, whatever this mount is;
/// - `held_root`: its root is a held mount's ([`MG_HOLD`]: the mount itself
///   or a copy), and then `held_by_id`: it is a held mount ([`HELD_BY_ID`],
///   in a guarded namespace only), or — its parent's group one
///   `MOUNT_GROUPS` does not hold (`known`: a regroup since the refresh) —
///   the parent is a copy of a held mount (`parent_held_like`, as
///   [`umount_takes_held`] decides an undecided walk).
#[inline(always)]
pub fn below_of(
    group: u32,
    held_at_place: impl FnOnce() -> bool,
    held_root: impl FnOnce() -> bool,
    held_by_id: impl FnOnce() -> bool,
    known: impl FnOnce() -> bool,
    parent_held_like: impl FnOnce() -> bool,
) -> u64 {
    if group != 0 && held_at_place() {
        return BELOW_TAKES;
    }
    if held_root() && (held_by_id() || (group != 0 && !known() && parent_held_like())) {
        return BELOW_TAKES;
    }
    group as u64
}

/// Where a change to the mount `m` lands: in a guarded namespace (its
/// guard and reach: judged there), propagated into one (`(0,
/// REACH_OTHER_NS)`, [`group_reaches`]), or nowhere guarded (`None`: let
/// through unread).
#[inline(always)]
pub fn target_reach<G: Mounts>(g: &G, m: G::M) -> Option<(u8, u8)> {
    let guard = g.guard(m);
    if guard != 0 {
        Some((guard, reach_in(guard)))
    } else if group_reaches(g, m) {
        Some((0, REACH_OTHER_NS))
    } else {
        None
    }
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
/// Lot 359: a change of propagation that reaches the pin directory's lock
/// ([`lock_touched`]) — every other change of propagation is
/// [`MG_OP_PASS`].
pub const MG_OP_PROPAGATE: u8 = 9;

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

/// The re-check of #567 (N1): a `mount(2)` call that changes a mount's
/// propagation (`MS_SHARED`, `MS_PRIVATE`, `MS_SLAVE`, `MS_UNBINDABLE`:
/// neither a remount nor a bind, in `path_mount`'s order). Let through
/// ([`MG_OP_PASS`]); made on a mount of a guarded namespace, or of a group
/// `MOUNT_GROUPS` follows, it wakes the agent's refresh of that map.
pub const fn regroups(flags: u64) -> bool {
    flags & (MS_REMOUNT | MS_BIND) == 0 && flags & MS_PROPAGATION != 0
}

/// `BTRFS_SUPER_MAGIC`.
pub const BTRFS_SUPER_MAGIC: u64 = 0x9123_683E;

/// The review of #567 (d): the guard's key of an inode — `(device,
/// inode)` as the hooks read a dentry's and as `stat(2)` gives it to the
/// agent that registers the points: the super block's device (`s_dev`),
/// and on btrfs the device of the inode's subvolume
/// (`BTRFS_I(inode)->root->anon_dev`, what `btrfs_getattr()` reports), so
/// two subvolumes of one file system, whose roots are both inode 256, are
/// two keys. `anon` 0 (the btrfs offsets unknown, or unreadable): the super
/// block's device — which matches no point registered on a subvolume.
pub const fn inode_key(s_dev: u32, magic: u64, ino: u64, anon: u32) -> (u64, u64) {
    let dev = if magic == BTRFS_SUPER_MAGIC && anon != 0 {
        anon
    } else {
        s_dev
    };
    (dev as u64, ino)
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
/// Lot 359: the pin directory's lock changed — its propagation, or a mount
/// of it that is not its maker's own step.
pub const MG_WHY_LOCK: u8 = 11;
/// Lot 1.1 (the review of #569, F2): a peer copy of a held mount moved
/// ([`moves_held_copy`]).
pub const MG_WHY_MOVE_COPY: u8 = 12;

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
    /// [`MG_OWN`], [`MG_VIEW`] and [`MG_KEPT`] of the point's ancestors (within
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
    // Lot 400: the list is walked from its end, the count taken down at
    // the top of each step and tested at its bottom, so the loop's latch is
    // that test — a jump. `while i < len` (and a `loop` whose test closes
    // it, the same code) became, with rustc 1.99's LLVM 22, a latch whose
    // last instruction was the index's increment, laid out above the
    // header it fell through into: a back-edge 5.15's and 6.1's verifiers
    // refuse (`no_function_has_a_back_edge_the_5_15_verifier_rejects`).
    // The verdict is the same in any order: any entry matching.
    let mut i = ALLOWED_KERNEL_MOUNTS.len();
    loop {
        i -= 1;
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
        if i == 0 {
            return false;
        }
    }
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

// ── The pin directory's lock (lot 359, the re-check 3 of #567, N4) ──────

/// The re-check 3 of #567 (N4): `sb_umount` runs before the kernel takes
/// the namespace lock, so the subtree [`umount_below`] reads can grow
/// before `umount_tree()` collects it (an rbind grafted meanwhile) — and
/// [`umount_below`] reads only its bound. The kernel's own rule closes the
/// rbind variants of both for the pins: `propagate_umount()` never takes a
/// mount that keeps a child that is not itself unmounted. The agent's pin
/// directory is bound onto itself, private and unbindable, as the child of
/// the host's bpffs (an rbind never copies an unbindable mount): the
/// host's bpffs keeps that child, whatever an rbind copy's unmount takes.
/// Not closed (the review of #569, signed at the next integrity round):
/// its flags cleared by `mount_setattr(2)` (no LSM hook), a raw
/// namespace's own copy of it moved (judged by its target only), the
/// units' namespaces (never a copy of it).
///
/// The lock passes the guard only as its maker's own two steps
/// ([`lock_maker`]: the agent's binary as a unit's process), both in PID
/// 1's namespace: the self-bind ([`lock_bind`], `open_tree(OPEN_TREE_CLONE)`
/// then `move_mount(2)`, the kernel's objects compared, never a path), then
/// `MS_UNBINDABLE` on it ([`lock_step_at`]), which alone makes the fresh,
/// shared self-bind private and unbindable. Whatever else is done to it — an
/// unmount or a move (it is a held mount), a mount on or below it (the pin
/// directory is the agent's own), any other change of its propagation, or a
/// recursive change above it that would make it bindable — is refused
/// ([`MG_WHY_LOCK`]). A caller who forged the identity gains nothing: each
/// of the two steps only makes the lock (the review of #569, F1c: a third,
/// `MS_PRIVATE`, made a lock in place bindable again, and a raw namespace's
/// copy of it too — gone).
///
/// A change of propagation touches the lock: one made on the lock itself,
/// or on a copy of it in another namespace (`on_lock`: a mount whose root
/// and mount point are both the pin directory — any change, `MS_SLAVE` and
/// `MS_UNBINDABLE` included, is judged), or a recursive one on a mount
/// rooted above it (`above_lock`, [`MG_LOCK_ABOVE`]) that clears its
/// `MNT_UNBINDABLE` (the kernel's `change_mnt_propagation()`), made in PID
/// 1's namespace (`guard`, [`GUARD_HOST`]): a recursive `MS_SHARED` (it
/// would make the lock shared, and an rbind copies a shared mount) or a
/// recursive `MS_PRIVATE` (the review of #569, F1a — private but bindable,
/// the host's lock is copied by the next rbind). In another namespace
/// either changes that namespace's own copies only (the re-check of #569,
/// N1: runc's `rootfsPropagation: rshared`, which containerd and CRI-O set
/// for any Kubernetes `Bidirectional` mount, and `unshare -m
/// --propagation shared` make `/` recursively shared in a fresh namespace
/// whose `/` is still a peer of PID 1's; container runtimes, `unshare -m`
/// and systemd's unit namespaces make it recursively private): its copy of
/// the lock is the raw namespace's residual, behind the walk and signed at
/// the integrity round. A recursive `MS_SLAVE` or `MS_UNBINDABLE` keeps the
/// flag; a change that is not recursive leaves the lock as it is: not
/// judged.
pub const fn lock_touched(flags: u64, on_lock: bool, above_lock: bool, guard: u8) -> bool {
    (on_lock && flags & MS_PROPAGATION != 0)
        || (above_lock
            && flags & MS_REC != 0
            && guard == GUARD_HOST
            && flags & (MS_SHARED | MS_PRIVATE) != 0)
}

/// The lock's own change of propagation: exactly `MS_UNBINDABLE` — no
/// `MS_REC`, no other flag. `MS_PRIVATE` is not one (the review of #569,
/// F1c: it clears `MNT_UNBINDABLE`).
pub const fn lock_step(flags: u64) -> bool {
    flags == MS_UNBINDABLE
}

/// The maker's step as the hook reads it: [`lock_step`] on the lock itself
/// in PID 1's namespace (`guard` of the lock's parent: [`GUARD_HOST`]) —
/// never on a raw namespace's copy of it (the review of #569, F1c). Asked
/// of [`lock_maker`] only then.
pub const fn lock_step_at(flags: u64, on_lock: bool, guard: u8) -> bool {
    on_lock && guard == GUARD_HOST && lock_step(flags)
}

/// `systemd-shutdown`'s switch to `/run/initramfs` (dracut's shutdown
/// image): `switch_root()` makes `/` recursively private before its move —
/// the one recursive `MS_PRIVATE` above the lock let through in PID 1's
/// namespace, asked of the shutdown's identity only then (the same
/// exemption as its pivot and move, the review of #567, F4).
pub const fn lock_shutdown_step(flags: u64, on_lock: bool) -> bool {
    !on_lock && flags & MS_REC != 0 && flags & MS_PRIVATE != 0 && flags & MS_SHARED == 0
}

/// How long after its start a process may still be the lock's maker: the
/// step runs in well under a second.
pub const LOCK_MAKER_NS: u64 = 10_000_000_000;

/// The lock's maker: the agent's binary (`OWN_EXE_INODES`' agent role, by
/// the kernel's `mm->exe_file`) run as a unit's process — the main thread,
/// a child of PID 1, in its first seconds ([`LOCK_MAKER_NS`]: `age_ns`
/// since its start) — whose lot 277/281 marks are clean (not moved into
/// its cgroup, no code-injection access given to another:
/// [`crate::cgroup_join::clean`]). The agent's unit makes it from an
/// `ExecStartPre=+` step; its integrity round, through a transient unit.
pub const fn lock_maker(
    main_thread: bool,
    parent_tgid: u32,
    agent_image: bool,
    age_ns: u64,
    marks_clean: bool,
) -> bool {
    main_thread && parent_tgid == 1 && agent_image && age_ns < LOCK_MAKER_NS && marks_clean
}

/// The verdict of a change of propagation that reaches the lock
/// ([`MG_OP_PROPAGATE`], [`lock_touched`]): let through for an
/// unprivileged caller (the kernel's own `EPERM`), in a namespace that
/// reaches no guarded one, and for an exempt step (`exempt`: its maker's
/// own step on it, [`lock_maker`] and [`lock_step_at`]; or
/// `systemd-shutdown`'s, [`lock_shutdown_step`]); else refused
/// ([`MG_WHY_LOCK`]), or let through and recorded inside the window. One
/// small function the hook calls without a [`Query`] (5.15's 512 bytes of
/// a call chain), and [`decide`]'s own.
pub const fn lock_verdict(
    privileged: bool,
    host: bool,
    reaches: bool,
    exempt: bool,
    window: bool,
) -> Verdict {
    if !privileged || !(host || reaches) || exempt {
        Verdict::Allow
    } else if window {
        Verdict::Window(MG_WHY_LOCK)
    } else {
        Verdict::Refuse(MG_WHY_LOCK)
    }
}

/// What the hook reads of a `move_mount(2)` that may be the lock's
/// self-bind.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct BindShape {
    /// The source is a detached mount: the root of its own anonymous
    /// namespace (`open_tree(OPEN_TREE_CLONE)`), its parent itself.
    pub detached: bool,
    /// The source path is its mount's root.
    pub at_root: bool,
    /// The source's root is the target's dentry (one dentry, one super
    /// block: the pin directory bound onto itself).
    pub onto_itself: bool,
    /// The source has no mount below it (no `AT_RECURSIVE`).
    pub childless: bool,
    /// The target is the pin directory ([`MG_LOCK`]).
    pub target_lock: bool,
    /// Mounts covered at the target ([`Point::stack`]): 0 — the lock is
    /// made once, never stacked.
    pub stack: u8,
    /// The target's file system ([`Point::magic`]): the bpffs.
    pub magic: u32,
    /// The target's guarded namespace: PID 1's.
    pub guard: u8,
}

/// The lock's self-bind: the pin directory, detached and childless, bound
/// onto itself on the bpffs in PID 1's namespace, nothing below.
pub const fn lock_bind(s: &BindShape) -> bool {
    s.detached
        && s.at_root
        && s.onto_itself
        && s.childless
        && s.target_lock
        && s.stack == 0
        && s.magic == BPF_FS_MAGIC
        && s.guard == GUARD_HOST
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
    /// Lot 359: the caller is the pin directory's lock's maker
    /// ([`lock_maker`]).
    pub lock_maker: bool,
    /// Lot 359: the operation is one of the lock's own steps — a
    /// `move_mount(2)` of its self-bind ([`lock_bind`]), or, on the lock in
    /// PID 1's namespace, a change of propagation [`lock_step_at`] names.
    pub lock_step: bool,
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
    decide_as(q.op, q)
}

/// Lot 1.1 (F8b-1): [`decide`] with the operation given apart, in a
/// register — the hooks pass the operation they judge as a constant
/// (`q.op`'s). A field of the query is read from the stack, where 5.15's
/// verifier keeps no value of a byte: through `q.op` every arm was
/// verified in each state (the allow-list check three times), and
/// `move_mount`'s stage processed more than the million instructions.
/// `decide(q)` is `decide_as(q.op, q)`: one decision.
#[inline(always)]
pub fn decide_as(op: u8, q: &Query) -> Verdict {
    // lot 359: a change of propagation that reaches the lock
    if op == MG_OP_PROPAGATE {
        return lock_verdict(
            q.privileged,
            q.host,
            q.reaches,
            q.lock_maker && q.lock_step,
            q.window,
        );
    }
    if !q.privileged {
        return Verdict::Allow;
    }
    let why = if op == MG_OP_REMOUNT {
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
        match op {
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
            // lot 359: the lock's self-bind, by its maker, in PID 1's
            // namespace (a mount on the pin directory otherwise)
            MG_OP_MOVE_MOUNT if q.host && q.lock_maker && q.lock_step => None,
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
        Some(w) if q.window && !point_kept(&q.point) => Verdict::Window(w),
        Some(w) => Verdict::Refuse(w),
    }
}

/// Lot 2.3a (K4): the point is a key file, their directory or below it
/// ([`MG_KEPT`]): no window lifts a mount there.
#[inline(always)]
pub const fn point_kept(p: &Point) -> bool {
    (p.flags | p.below) & MG_KEPT != 0
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
        REACH_OTHER_NS => {
            "made in another mount namespace whose change reaches PID 1's, the agent's or the watchdog's (a peer or a master of one of its mounts, or more peers or slaves than the hook reads)"
        }
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
        MG_OP_REMOUNT => {
            "remount of a super block (mount(2) MS_REMOUNT, or fsconfig(2) FSCONFIG_CMD_RECONFIGURE)"
        }
        MG_OP_REMOUNT_BIND => "mount(2) -o remount,bind",
        MG_OP_PROPAGATE => {
            "a change of propagation (mount(2) MS_SHARED, MS_PRIVATE, MS_SLAVE or MS_UNBINDABLE)"
        }
        _ => "mount operation",
    }
}

/// The reason's words in a record.
pub const fn why_name(why: u8) -> &'static str {
    match why {
        MG_WHY_ON => {
            "on or over a protected point (a kernel view, the agent's directories, binaries or units, or a directory above them)"
        }
        MG_WHY_BELOW_OWN => "below one of the agent's own directories",
        MG_WHY_BELOW_VIEW => {
            "below a kernel view (/proc, /sys, the cgroup root, the bpffs), and not the kernel's own pseudo-filesystem at its canonical point"
        }
        MG_WHY_MOVE_OLD => {
            "a move through mount(2)'s MS_MOVE in the host's namespace, whose source the kernel hook sees only as the caller's string (move_mount(2) is judged by the mount itself)"
        }
        MG_WHY_MOVE_AWAY => "a protected mount moved away",
        MG_WHY_UMOUNT => "a protected mount unmounted",
        MG_WHY_PIVOT => "the root pivoted in the host's namespace",
        MG_WHY_REMOUNT_SB => {
            "the super block of a kernel view or of a file system the agent's paths are on, reconfigured (proc's subset=pid or hidepid hide what the agent reads; a read-only state file system refuses its writes)"
        }
        MG_WHY_REMOUNT_RESTRICT => "a mount that holds the agent's paths made read-only or noexec",
        MG_WHY_UMOUNT_NOTED => {
            "an unmount of a kernel file system the agent reads (the tracefs, debugfs or securityfs), let through and recorded"
        }
        MG_WHY_LOCK => {
            "the lock of the agent's pin directory (its self-bind, private and unbindable, under the host's bpffs) changed: only its maker's own steps pass"
        }
        MG_WHY_MOVE_COPY => {
            "a peer copy of a protected mount moved away (its unmount propagates to the protected mount it is a peer of)"
        }
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
            lock_maker: false,
            lock_step: false,
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
        assert!(ALLOWED_KERNEL_MOUNTS.iter().all(|a| {
            a.fstype.len <= NAME_MAX
                && a.names
                    .iter()
                    .all(|n| n.len <= NAME_MAX || n.len >= NAME_ANY)
        }));
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

    /// The re-check of #567 (N1): a test graph of mounts — each one's peer
    /// group, guarded namespace, the next mount of its peer ring and its
    /// slaves — and the groups `MOUNT_GROUPS` holds.
    struct Graph {
        m: Vec<(u32, u8, usize, Vec<usize>)>,
        known: Vec<u32>,
    }

    impl Graph {
        /// `n` private mounts in no guarded namespace.
        fn new(n: usize) -> Graph {
            Graph {
                m: (0..n).map(|i| (0, 0, i, Vec::new())).collect(),
                known: Vec::new(),
            }
        }
        /// These mounts are one peer group, `group`.
        fn peers(mut self, group: u32, ring: &[usize]) -> Graph {
            for (i, &x) in ring.iter().enumerate() {
                self.m[x].0 = group;
                self.m[x].2 = ring[(i + 1) % ring.len()];
            }
            self
        }
        fn guard(mut self, x: usize, g: u8) -> Graph {
            self.m[x].1 = g;
            self
        }
        /// Its peer link cannot be read.
        fn unreadable(mut self, x: usize) -> Graph {
            self.m[x].2 = usize::MAX;
            self
        }
        fn slave(mut self, master: usize, s: usize) -> Graph {
            self.m[master].3.push(s);
            self
        }
        fn following(mut self, groups: &[u32]) -> Graph {
            self.known = groups.to_vec();
            self
        }
    }

    impl Mounts for Graph {
        type M = usize;
        fn group(&self, m: usize) -> u32 {
            self.m[m].0
        }
        fn guard(&self, m: usize) -> u8 {
            self.m[m].1
        }
        fn known(&self, group: u32) -> bool {
            self.known.contains(&group)
        }
        fn next_peer(&self, m: usize) -> Option<usize> {
            Some(self.m[m].2).filter(|n| *n != usize::MAX)
        }
        fn first_slave(&self, m: usize) -> Option<usize> {
            self.m[m].3.first().copied()
        }
        fn next_slave(&self, master: usize, s: usize) -> Option<usize> {
            let l = &self.m[master].3;
            l.get(l.iter().position(|x| *x == s)? + 1).copied()
        }
    }

    /// The re-check of #567 (N1), its probe (`unshare -Urm`, 6.18): the
    /// guarded `/` armed in group 198 (`MOUNT_GROUPS`); `mount
    /// --make-private /`, a decoy `mount -t tmpfs d /x; mount --make-shared
    /// /x` takes 198, `mount --make-shared /` gives `/` group 228; a raw
    /// `unshare(CLONE_NEWNS)` copies it — a peer in 228 — and its tmpfs over
    /// `/etc/northnarrow` propagated into the guarded view, the hook having
    /// let a group it did not know through. Now the ring is read.
    #[test]
    fn a_regrouped_guarded_mount_is_still_reached_from_a_raw_namespace() {
        // 0: the guarded `/` (regrouped), 1: the decoy, 2: the raw copy
        let g = Graph::new(3)
            .guard(0, GUARD_HOST)
            .guard(1, GUARD_HOST)
            .peers(228, &[0, 2])
            .peers(198, &[1])
            .following(&[198]);
        assert!(
            !Mounts::known(&g, g.group(2)),
            "the map is stale: 228 unknown"
        );
        assert_eq!(spread(&g, 2), Spread::Guarded);
        assert_eq!(target_reach(&g, 2), Some((0, REACH_OTHER_NS)));
        // and the tmpfs over /etc/northnarrow from there is refused
        let q = Query {
            host: false,
            reaches: true,
            ..host(MG_OP_MOUNT, view_root(MG_ON, 0xef53), "tmpfs")
        };
        assert_eq!(decide(&q), Verdict::Refuse(MG_WHY_ON));
        // the guarded mount itself, and the decoy, are judged where they are
        assert_eq!(target_reach(&g, 0), Some((GUARD_HOST, 0)));
        assert_eq!(target_reach(&g, 1), Some((GUARD_HOST, 0)));
    }

    /// N1's variants: the guarded mount made a slave of the raw copy's new
    /// group (`--make-slave` after the regroup), the agent's namespace a
    /// slave of a regrouped host mount, a group the map still follows.
    #[test]
    fn a_guarded_slave_of_an_unknown_group_is_reached() {
        // 0: the raw copy (group 228), 1: the guarded `/`, now its slave
        let g = Graph::new(2)
            .guard(1, GUARD_HOST)
            .peers(228, &[0])
            .slave(0, 1);
        assert_eq!(target_reach(&g, 0), Some((0, REACH_OTHER_NS)));
        // a raw copy among other peers, the agent's mount a slave of the
        // third (0 → 1 → 2 → 0)
        let g = Graph::new(4)
            .peers(229, &[0, 1, 2])
            .guard(3, GUARD_AGENT)
            .slave(2, 3);
        assert_eq!(spread(&g, 0), Spread::Guarded);
        // the second slave of a peer (each slave of each peer is read)
        let g = Graph::new(3)
            .peers(230, &[0])
            .slave(0, 1)
            .slave(0, 2)
            .guard(2, GUARD_WATCHDOG);
        assert_eq!(spread(&g, 0), Spread::Guarded);
        // a mount in no peer group propagates nothing, even to a slave of
        // its own (the kernel propagates from a shared mount only)
        let g = Graph::new(2).slave(0, 1).guard(1, GUARD_HOST);
        assert!(!group_reaches(&g, 0));
        assert_eq!(target_reach(&g, 0), None);
        // a known group is reached without a walk
        let g = Graph::new(1).peers(7, &[0]).following(&[7]);
        assert_eq!(target_reach(&g, 0), Some((0, REACH_OTHER_NS)));
    }

    /// N1, fail closed but not wide: a container's own group (a ring that
    /// closes, private or slave-only units below it) reaches nothing; a
    /// group wider than the hook reads, or a slave that carries the change
    /// on (shared itself, or a master), counts as reaching — `decide`
    /// refuses there only on, over or below a protected point.
    #[test]
    fn an_unknown_group_is_walked_and_an_unread_one_fails_closed() {
        // a container's `/` (300) and its copy, two unit sandboxes (slaves)
        let g = Graph::new(4).peers(300, &[0, 1]).slave(0, 2).slave(1, 3);
        assert_eq!(spread(&g, 0), Spread::Nowhere);
        assert_eq!(target_reach(&g, 0), None);
        // a private mount, in no group, propagates nothing
        assert_eq!(target_reach(&Graph::new(1), 0), None);
        // wider than the 16 mounts read
        let ring: Vec<usize> = (0..17).collect();
        let g = Graph::new(17).peers(301, &ring);
        assert_eq!(spread(&g, 0), Spread::Unread);
        assert_eq!(target_reach(&g, 0), Some((0, REACH_OTHER_NS)));
        let g = Graph::new(16).peers(301, &ring[..16]);
        assert_eq!(spread(&g, 0), Spread::Nowhere, "a ring of 16 closes");
        // a peer ring that cannot be read
        let g = Graph::new(2).peers(305, &[0, 1]).unreadable(1);
        assert_eq!(spread(&g, 0), Spread::Unread);
        // a slave that is itself shared (its peers are not read)
        let g = Graph::new(3)
            .peers(302, &[0])
            .peers(303, &[1, 2])
            .slave(0, 1);
        assert_eq!(spread(&g, 0), Spread::Unread);
        // a slave that is a master
        let g = Graph::new(3).peers(304, &[0]).slave(0, 1).slave(1, 2);
        assert_eq!(spread(&g, 0), Spread::Unread);
        // and what the undecided reach refuses: a protected point only
        let q = |point: Point| Query {
            host: false,
            reaches: true,
            ..host(MG_OP_MOUNT, point, "tmpfs")
        };
        assert_eq!(decide(&q(plain(0xef53, &["mnt", "x"]))), Verdict::Allow);
        assert_eq!(
            decide(&q(view_root(MG_OWN, 0xef53))),
            Verdict::Refuse(MG_WHY_ON)
        );
    }

    /// N1's unmount variant: a place is keyed under the parent's group at
    /// the refresh, and under the parent mount itself ([`held_under`]), a
    /// key of its own — never a group's, an id's or another place's.
    #[test]
    fn a_place_under_its_parent_mount_is_its_own_key() {
        let cg = NameKey::of("cgroup");
        let under = held_under(7, 0x16, 33, &cg);
        assert_ne!(under, held_by_place(7, 0x16, 33, &cg));
        assert_eq!(under.1, held_by_place(7, 0x16, 33, &cg).1, "one hash");
        assert_ne!(under, held_under(8, 0x16, 33, &cg));
        assert_ne!(under, held_under(7, 0x16, 33, &NameKey::of("bpf")));
        assert_ne!(under.0, held_by_id(7).0);
        assert_ne!(under.0, held_by_place(u32::MAX, 0x16, 33, &cg).0);
        assert_eq!(under.0 & HELD_BY_ID, 0, "never an id's key");
        let any = held_by_place(PLACE_ANY_GROUP, 0x16, 33, &cg);
        assert_ne!(any, under);
        assert_ne!(any, held_by_place(7, 0x16, 33, &cg));
    }

    /// N1's unmount variant (`unshare` after `/sys` was regrouped, then
    /// `umount /sys/fs/bpf` in the raw copy: the kernel takes the host's
    /// childless bpffs): the raw copy of `/sys` is a peer of the host's
    /// `/sys`, under which the bpffs is held — taken. A chroot's own sysfs
    /// (a new mount, its group new, its copies in the guarded namespaces'
    /// slaves of `/`) holds no held mount: its `sys/fs/cgroup` unmounted is
    /// let through (the lab's chroot case on 5.15, refused by a first
    /// version keyed by the place alone). Undecided: fail closed on a held
    /// root only; a known group: the keys under it decide.
    #[test]
    fn an_unmount_under_a_regrouped_parent_takes_a_held_mount_and_a_chroots_does_not() {
        let takes = |g: &Graph, held_root: bool, like: bool| {
            umount_takes_held(umount_spread(g, 0), held_root, like)
        };
        // 0: the raw copy of /sys, 1: the host's /sys (the bpffs held under it)
        let g = Graph::new(2).peers(228, &[0, 1]).guard(1, 1);
        assert_eq!(umount_spread(&g, 0), Some(Spread::Guarded));
        assert!(takes(&g, true, true));
        assert!(
            takes(&g, false, false),
            "found, whatever the root and the parent"
        );
        // 0: a chroot's sysfs, 1 and 2: its copies in the agent's and the
        // watchdog's namespaces (slaves) — none holds a held mount
        let g = Graph::new(3).peers(229, &[0]).slave(0, 1).slave(0, 2);
        assert_eq!(umount_spread(&g, 0), Some(Spread::Nowhere));
        assert!(!takes(&g, true, true));
        // more than the walk reads (the lab's guests: a copy in each
        // sandboxed unit's namespace): a held root under a copy of a held
        // mount is kept; under a chroot's own sysfs, or another root, let go
        let ring: Vec<usize> = (0..17).collect();
        let g = Graph::new(17).peers(230, &ring);
        assert_eq!(umount_spread(&g, 0), Some(Spread::Unread));
        assert!(takes(&g, true, true));
        assert!(!takes(&g, true, false), "the chroot's sysfs at $T/sys");
        assert!(!takes(&g, false, true));
        // a known group, or none: not walked (its keys decide)
        let g = Graph::new(2).peers(7, &[0, 1]).guard(1, 1).following(&[7]);
        assert_eq!(umount_spread(&g, 0), None);
        assert!(!takes(&g, true, true));
        assert!(!takes(&Graph::new(1), true, true));
        // a parent in no peer group propagates nothing (the kernel never
        // gives one slaves: a master is shared)
        let g = Graph::new(2).slave(0, 1).guard(1, 1);
        assert!(!takes(&g, true, true));
    }

    /// The re-check 2 of #567 (N3): a test tree of mounts — each one's
    /// parent, its children in the kernel's order, its own peer group,
    /// whether its root is a held mount's and whether it is held by its
    /// id — the `(group, place)` keys a held mount is registered under
    /// (its place a name here), the groups `MOUNT_GROUPS` holds, and the
    /// mounts that are copies of a held one (`parent_held_like`).
    struct Mnt {
        parent: usize,
        kids: Vec<usize>,
        group: u32,
        place: &'static str,
        held_root: bool,
        held_id: bool,
    }

    struct Forest {
        m: Vec<Mnt>,
        places: Vec<(u32, &'static str)>,
        known: Vec<u32>,
        like: Vec<usize>,
        guarded: bool,
    }

    impl Forest {
        fn new() -> Forest {
            Forest {
                m: Vec::new(),
                places: Vec::new(),
                known: Vec::new(),
                like: Vec::new(),
                guarded: false,
            }
        }
        /// A mount under `parent` (itself for the first, a namespace's
        /// root) at `place`, in `group`; its index.
        fn mount(&mut self, parent: usize, place: &'static str, group: u32) -> usize {
            let i = self.m.len();
            let parent = if self.m.is_empty() { i } else { parent };
            self.m.push(Mnt {
                parent,
                kids: Vec::new(),
                group,
                place,
                held_root: false,
                held_id: false,
            });
            if parent != i {
                self.m[parent].kids.push(i);
            }
            i
        }
        fn held_root(&mut self, x: usize) -> &mut Self {
            self.m[x].held_root = true;
            self
        }
    }

    impl Tree for Forest {
        type M = usize;
        fn first_child(&self, m: usize) -> Option<usize> {
            self.m[m].kids.first().copied()
        }
        fn next_sibling(&self, m: usize) -> Option<usize> {
            let p = self.m[m].parent;
            let k = &self.m[p].kids;
            k.get(k.iter().position(|x| *x == m)? + 1).copied()
        }
        fn parent(&self, m: usize) -> usize {
            self.m[m].parent
        }
        fn below(&self, m: usize) -> u64 {
            let me = &self.m[m];
            let group = self.m[me.parent].group;
            below_of(
                group,
                || self.places.contains(&(group, me.place)),
                || me.held_root,
                || self.guarded && me.held_id,
                || self.known.contains(&group),
                || self.like.contains(&me.parent),
            )
        }
    }

    /// The re-check 2 of #567 (N3), its probes (`unshare -Urm`, 6.18):
    /// `mount --rbind /sys /mnt/s; umount -l /mnt/s` — the copy's top is at
    /// a place nothing is held at, which is all the hook judged; the kernel
    /// took the host's childless `/sys/fs/bpf` and `/sys/fs/cgroup` through
    /// the copies below it, the copy of `/sys` being a peer of the host's
    /// (group 10, under which both are held): the bpffs lost its last
    /// mount. In a slave namespace (the agent's) the copies went too: the
    /// same keys (a held mount is registered under its parent's master
    /// group as well). A raw namespace's `umount -l /` the same, from its
    /// root. Now the subtree is read: refused.
    #[test]
    fn a_lazy_unmount_of_an_rbind_copy_takes_the_held_mounts_beneath_it() {
        let mut f = Forest::new();
        let root = f.mount(0, "/", 1);
        let sys = f.mount(root, "sys", 10);
        let bpf = f.mount(sys, "bpf", 11);
        let cg = f.mount(sys, "cgroup", 12);
        let mnt_s = f.mount(root, "s", 10);
        let security = f.mount(mnt_s, "security", 13);
        let c_cg = f.mount(mnt_s, "cgroup", 12);
        let c_bpf = f.mount(mnt_s, "bpf", 11);
        f.held_root(sys).held_root(bpf).held_root(cg);
        f.held_root(mnt_s).held_root(c_cg).held_root(c_bpf);
        f.places = vec![(1, "sys"), (10, "bpf"), (10, "cgroup")];
        f.known = vec![1, 10, 11, 12];
        f.like = vec![root, sys];
        // what the hook judged on its own: the top, at /mnt/s under `/`'s
        // group — no held mount there
        assert!(
            !f.places
                .contains(&(f.m[f.m[mnt_s].parent].group, f.m[mnt_s].place))
        );
        assert_eq!(umount_below(&f, mnt_s), Below::Takes);
        assert!(below_takes_held(umount_below(&f, mnt_s), false));
        // the copy of /sys's own children read in the kernel's order: the
        // first held one decides (securityfs first, then the cgroup2)
        assert_eq!(f.below(security), 10, "its parent's group");
        assert_eq!(f.below(c_cg), BELOW_TAKES);
        // a raw namespace's root (a peer of the host's `/`): its `/sys`, at
        // the host's place under group 1, is taken at the first step
        let mut r = Forest::new();
        let raw = r.mount(0, "/", 1);
        let raw_sys = r.mount(raw, "sys", 10);
        let _raw_bpf = r.mount(raw_sys, "bpf", 11);
        r.held_root(raw).held_root(raw_sys).held_root(_raw_bpf);
        r.places = vec![(1, "sys"), (10, "bpf")];
        r.known = vec![1, 10];
        assert_eq!(umount_below(&r, raw), Below::Takes);
        // with `--make-rslave` (every copy a slave: no group) nothing
        // propagates — the careful chroot's lazy unmount goes through
        let mut s = Forest::new();
        let root = s.mount(0, "/", 1);
        let copy = s.mount(root, "s", 0);
        let c_bpf = s.mount(copy, "bpf", 0);
        let c_cg = s.mount(copy, "cgroup", 0);
        s.held_root(copy).held_root(c_bpf).held_root(c_cg);
        s.places = vec![(10, "bpf"), (10, "cgroup")];
        s.known = vec![1, 10];
        assert_eq!(umount_below(&s, copy), Below::Clear);
        assert!(!below_takes_held(umount_below(&s, copy), true));
        // a mount with no mount below it: one step, nothing read
        assert_eq!(umount_below(&s, c_bpf), Below::Clear);
    }

    /// N3's variants: a held mount below in a guarded namespace (by its
    /// id), a regrouped copy (a group the map does not hold: taken when its
    /// parent is a copy of a held mount, as an undecided unmount is), a
    /// chroot's own sysfs with its cgroup2 (a new mount at `$T/sys`: let
    /// through, the lab's chroot case), a deep subtree read in the kernel's
    /// order (children before siblings, back up through the parents).
    #[test]
    fn a_held_mount_anywhere_below_is_found_and_a_chroots_is_not() {
        // by id, in a guarded namespace only
        let mut f = Forest::new();
        let root = f.mount(0, "/", 0);
        let x = f.mount(root, "x", 0);
        let held = f.mount(x, "h", 0);
        f.held_root(held);
        f.m[held].held_id = true;
        assert_eq!(umount_below(&f, x), Below::Clear, "another namespace");
        f.guarded = true;
        assert_eq!(umount_below(&f, x), Below::Takes);
        // a regrouped raw copy of /sys (group 228, not followed yet): taken
        // under a copy of a held mount, let through under a chroot's sysfs
        let mut g = Forest::new();
        let root = g.mount(0, "/", 1);
        let t = g.mount(root, "T", 300);
        let chroot_sys = g.mount(t, "sys", 301);
        let chroot_cg = g.mount(chroot_sys, "cgroup", 0);
        let raw_sys = g.mount(root, "sys", 228);
        let raw_bpf = g.mount(raw_sys, "bpf", 0);
        g.held_root(chroot_sys).held_root(chroot_cg);
        g.held_root(raw_sys).held_root(raw_bpf);
        g.known = vec![1];
        g.like = vec![raw_sys];
        assert_eq!(umount_below(&g, t), Below::Clear, "the chroot's");
        assert_eq!(umount_below(&g, raw_sys), Below::Takes);
        // deep: the held copy is the last of a walk that goes down, along
        // and back up
        let mut d = Forest::new();
        let root = d.mount(0, "/", 1);
        let top = d.mount(root, "top", 5);
        let a = d.mount(top, "a", 5);
        let a1 = d.mount(a, "a1", 5);
        let _a11 = d.mount(a1, "a11", 5);
        let _a2 = d.mount(a, "a2", 5);
        let b = d.mount(top, "b", 5);
        let held = d.mount(b, "bpf", 0);
        d.held_root(held);
        d.places = vec![(5, "bpf")];
        d.known = vec![5];
        assert_eq!(umount_below(&d, top), Below::Takes);
        d.places.clear();
        assert_eq!(umount_below(&d, top), Below::Clear);
        // the walk never leaves the subtree: the top's siblings are not read
        let sib = d.mount(root, "sibling", 5);
        let sib_held = d.mount(sib, "bpf", 0);
        d.held_root(sib_held);
        d.places = vec![(5, "bpf")];
        d.m[held].place = "other";
        assert_eq!(umount_below(&d, top), Below::Clear);
        assert_eq!(umount_below(&d, root), Below::Takes);
    }

    /// Fix round 3 of #567, the mutation round on the final walk (two
    /// survivors): a held mount read 32nd is found, one 33rd is not read
    /// (the subtree then not read whole); a peer group read early counts
    /// when the walk ends later, past private mounts.
    #[test]
    fn the_walk_reads_exactly_its_bound_and_every_group_read() {
        let flat = |before: u32| {
            let mut f = Forest::new();
            let root = f.mount(0, "/", 1);
            let top = f.mount(root, "old", 0);
            for _ in 0..before {
                f.mount(top, "m", 0);
            }
            let held = f.mount(top, "bpf", 0);
            f.held_root(held);
            f.m[held].held_id = true;
            f.guarded = true;
            (f, top)
        };
        let (f, top) = flat(SUBTREE_MAX - 1);
        assert_eq!(umount_below(&f, top), Below::Takes, "the 32nd mount read");
        let (f, top) = flat(SUBTREE_MAX);
        assert_eq!(
            umount_below(&f, top),
            Below::Unread { reaches: false },
            "a 33rd mount is not read"
        );
        // a parent in a peer group read early, private mounts past the bound
        let mut f = Forest::new();
        let root = f.mount(0, "/", 1);
        let top = f.mount(root, "old", 0);
        let shared = f.mount(top, "s", 9);
        f.mount(shared, "c", 0);
        for _ in 0..SUBTREE_MAX {
            f.mount(top, "m", 0);
        }
        assert_eq!(umount_below(&f, top), Below::Unread { reaches: true });
    }

    /// N3, the bound: a subtree wider than [`SUBTREE_MAX`] mounts. A
    /// container runtime's old root after `pivot_root` (every mount a slave:
    /// no group) is let through in its own namespace; in a guarded one it
    /// is refused — 32 private mounts can hide a copy of `/sys` below them
    /// there; in another namespace a subtree read in a peer group is
    /// refused, one read private is let through (the named residual: a
    /// copy hidden behind more than 32 private mounts of a namespace that
    /// is not guarded).
    #[test]
    fn a_subtree_wider_than_the_walk_fails_closed_where_it_can_reach() {
        let wide = |group: u32, hidden: bool| {
            let mut f = Forest::new();
            let root = f.mount(0, "/", 1);
            let top = f.mount(root, "old", group);
            for _ in 0..=SUBTREE_MAX {
                f.mount(top, "decoy", group);
            }
            if hidden {
                let copy = f.mount(top, "s", 10);
                let bpf = f.mount(copy, "bpf", 11);
                f.held_root(copy).held_root(bpf);
                f.places = vec![(10, "bpf")];
                f.known = vec![10];
            }
            (f, top)
        };
        let (f, top) = wide(0, false);
        assert_eq!(umount_below(&f, top), Below::Unread { reaches: false });
        assert!(!below_takes_held(umount_below(&f, top), false));
        assert!(below_takes_held(umount_below(&f, top), true));
        let (f, top) = wide(0, true);
        assert_eq!(umount_below(&f, top), Below::Unread { reaches: false });
        assert!(below_takes_held(umount_below(&f, top), true), "guarded");
        assert!(
            !below_takes_held(umount_below(&f, top), false),
            "the named residual"
        );
        let (f, top) = wide(7, false);
        assert_eq!(umount_below(&f, top), Below::Unread { reaches: true });
        assert!(below_takes_held(umount_below(&f, top), false));
        // 32 mounts below: read whole; one more, not
        let mut f = Forest::new();
        let root = f.mount(0, "/", 1);
        let top = f.mount(root, "old", 0);
        for _ in 0..SUBTREE_MAX {
            f.mount(top, "m", 0);
        }
        assert_eq!(umount_below(&f, top), Below::Clear);
        f.mount(top, "m", 0);
        assert_eq!(umount_below(&f, top), Below::Unread { reaches: false });
        // a climb reads up to SUBTREE_DEPTH parents: a chain one shorter is
        // read whole, a chain that long is not (its last climb ends short
        // of the top) unless a sibling is met on the way
        let chain = |n: u32, after: bool| {
            let mut f = Forest::new();
            let root = f.mount(0, "/", 1);
            let top = f.mount(root, "top", 0);
            let mut at = top;
            for _ in 0..n {
                at = f.mount(at, "d", 0);
            }
            if after {
                f.mount(top, "after", 0);
            }
            umount_below(&f, top)
        };
        assert_eq!(chain(SUBTREE_DEPTH - 1, false), Below::Clear);
        assert_eq!(
            chain(SUBTREE_DEPTH, false),
            Below::Unread { reaches: false }
        );
        assert_eq!(chain(SUBTREE_DEPTH, true), Below::Clear);
    }

    /// N3: what one mount below takes, read lazily — a held mount at its
    /// place under its parent's group whatever it is; its root a held
    /// mount's, then held by its id, or under a group not followed yet and
    /// a copy of a held parent; else its parent's group.
    #[test]
    fn one_mount_below_is_judged_as_the_top_is() {
        let never = || -> bool { panic!("read") };
        let yes = || true;
        let no = || false;
        assert_eq!(below_of(0, never, no, never, never, never), 0);
        assert_eq!(below_of(9, no, no, never, never, never), 9);
        assert_eq!(below_of(9, yes, never, never, never, never), BELOW_TAKES);
        assert_eq!(below_of(0, never, yes, yes, never, never), BELOW_TAKES);
        assert_eq!(below_of(0, never, yes, no, never, never), 0);
        assert_eq!(
            below_of(9, no, yes, no, yes, never),
            9,
            "a known group: its keys decided"
        );
        assert_eq!(below_of(9, no, yes, no, no, yes), BELOW_TAKES);
        assert_eq!(below_of(9, no, yes, no, no, no), 9);
        assert!(
            u32::MAX as u64 & BELOW_TAKES == 0,
            "no group reads as taken"
        );
    }

    /// N1: the `mount(2)` calls that change a propagation, in the kernel's
    /// order — a remount or a bind with a propagation flag is not one.
    #[test]
    fn a_propagation_change_is_told_from_a_remount_and_a_bind() {
        const MS_REC: u64 = 1 << 14;
        const MS_SHARED: u64 = 1 << 20;
        const MS_PRIVATE: u64 = 1 << 18;
        const MS_SLAVE: u64 = 1 << 19;
        const MS_UNBINDABLE: u64 = 1 << 17;
        for f in [
            MS_SHARED,
            MS_PRIVATE,
            MS_SLAVE,
            MS_UNBINDABLE,
            MS_SHARED | MS_REC,
        ] {
            assert!(regroups(f), "{f:#x}");
            assert_eq!(mount_op(f), MG_OP_PASS);
        }
        for f in [
            MS_BIND | MS_SHARED,
            MS_REMOUNT | MS_SHARED,
            MS_REMOUNT | MS_BIND | MS_RDONLY,
            MS_MOVE,
            0,
        ] {
            assert!(!regroups(f), "{f:#x}");
        }
    }

    /// The review of #567 (d): two subvolumes of one btrfs (one super
    /// block, one `s_dev`), whose roots are both inode 256, are two keys —
    /// each the one `stat(2)` gives (the subvolume's device), so a point on
    /// one never matches the other; without the subvolume's device read
    /// (the btrfs offsets unknown) the key is the super block's, which no
    /// point registered there has.
    #[test]
    fn two_btrfs_subvolumes_with_one_inode_number_are_two_keys() {
        let (s_dev, a, b) = (0x2d, 0x2e, 0x2f);
        let ka = inode_key(s_dev, BTRFS_SUPER_MAGIC, 256, a);
        let kb = inode_key(s_dev, BTRFS_SUPER_MAGIC, 256, b);
        assert_ne!(ka, kb);
        assert_eq!(ka, (a as u64, 256), "stat(2)'s key on subvolume A");
        assert_eq!(kb, (b as u64, 256), "stat(2)'s key on subvolume B");
        let points = [ka];
        assert!(!points.contains(&kb), "no false match across subvolumes");
        // another file system's inode: its super block's device, whatever is read
        assert_eq!(inode_key(0x803, 0xef53, 256, a), (0x803, 256));
        // the subvolume's device unread: the super block's, no point's
        let blind = inode_key(s_dev, BTRFS_SUPER_MAGIC, 256, 0);
        assert_eq!(blind, (s_dev as u64, 256));
        assert!(!points.contains(&blind));
    }

    // ── Lot 359: the pin directory's lock (the re-check 3 of #567, N4) ──

    /// The pin directory as the hook reads it as a `move_mount(2)` target:
    /// the agent's own directory, held, the lock's place, on the bpffs.
    fn pin_dir() -> Point {
        Point {
            flags: MG_OWN | MG_HOLD | MG_LOCK,
            magic: BPF_FS_MAGIC,
            depth: 1,
            ..Point::EMPTY
        }
    }

    fn the_bind() -> BindShape {
        BindShape {
            detached: true,
            at_root: true,
            onto_itself: true,
            childless: true,
            target_lock: true,
            stack: 0,
            magic: BPF_FS_MAGIC,
            guard: GUARD_HOST,
        }
    }

    /// Named test (lot 359): the agent's own self-bind of its pin directory
    /// passes the guard — by its maker, as its own step, in PID 1's
    /// namespace — and the same bind by anyone else, or of another shape,
    /// is the mount on the pin directory it always was (refused).
    #[test]
    fn the_agents_own_self_bind_of_its_pin_directory_passes_and_nothing_else_does() {
        let bind = Query {
            lock_maker: true,
            lock_step: lock_bind(&the_bind()),
            ..host(MG_OP_MOVE_MOUNT, pin_dir(), "bpf")
        };
        assert!(bind.lock_step);
        assert_eq!(decide(&bind), Verdict::Allow);
        // not its maker (a root shell's open_tree + move_mount)
        let other = Query {
            lock_maker: false,
            ..bind
        };
        assert_eq!(decide(&other), Verdict::Refuse(MG_WHY_ON));
        // its maker, but not the lock's shape
        let shape = Query {
            lock_step: false,
            ..bind
        };
        assert_eq!(decide(&shape), Verdict::Refuse(MG_WHY_ON));
        // made in another namespace that reaches PID 1's: refused
        let elsewhere = Query {
            host: false,
            reaches: true,
            ..bind
        };
        assert_eq!(decide(&elsewhere), Verdict::Refuse(MG_WHY_ON));
        // a new mount (fsmount) or an old-API bind there by its maker: refused
        for op in [MG_OP_MOUNT, MG_OP_BIND] {
            let q = Query { op, ..bind };
            assert_eq!(decide(&q), Verdict::Refuse(MG_WHY_ON), "op {op}");
        }
        // inside a window, the bind of another: let through, recorded
        let window = Query {
            window: true,
            ..other
        };
        assert_eq!(decide(&window), Verdict::Window(MG_WHY_ON));
    }

    /// Named test (lot 359): the self-bind's shape, each part needed — a
    /// clone of something else, a recursive clone, a bind stacked over the
    /// lock, a target that is not the pin directory, another file system,
    /// another namespace than PID 1's.
    #[test]
    fn the_lock_bind_needs_every_part_of_its_shape() {
        assert!(lock_bind(&the_bind()));
        let off = [
            BindShape {
                detached: false,
                ..the_bind()
            },
            BindShape {
                at_root: false,
                ..the_bind()
            },
            BindShape {
                onto_itself: false,
                ..the_bind()
            },
            BindShape {
                childless: false,
                ..the_bind()
            },
            BindShape {
                target_lock: false,
                ..the_bind()
            },
            BindShape {
                stack: 1,
                ..the_bind()
            },
            BindShape {
                magic: TMPFS_MAGIC,
                ..the_bind()
            },
            BindShape {
                guard: GUARD_AGENT,
                ..the_bind()
            },
            BindShape {
                guard: 0,
                ..the_bind()
            },
        ];
        for (i, s) in off.iter().enumerate() {
            assert!(!lock_bind(s), "part {i}: {s:?}");
        }
    }

    /// Named test (lot 359): the lock's maker is the agent's binary as a
    /// unit's fresh main process with clean marks — each part needed.
    #[test]
    fn the_locks_maker_needs_each_part_of_its_identity() {
        assert!(lock_maker(true, 1, true, 0, true));
        assert!(lock_maker(true, 1, true, LOCK_MAKER_NS - 1, true));
        assert!(!lock_maker(false, 1, true, 0, true), "a thread");
        assert!(
            !lock_maker(true, 812, true, 0, true),
            "a root shell's child"
        );
        assert!(!lock_maker(true, 0, true, 0, true), "no parent read");
        assert!(!lock_maker(true, 1, false, 0, true), "another binary");
        assert!(!lock_maker(true, 1, true, LOCK_MAKER_NS, true), "not fresh");
        assert!(!lock_maker(true, 1, true, 0, false), "moved or injected");
    }

    /// Named test (lot 359): which changes of propagation reach the lock —
    /// any on it (or on a copy of it), a recursive shared one above it in
    /// PID 1's namespace; a recursive shared, private or slave one above it
    /// in another namespace (a container's, `unshare -m`'s, a unit's) is
    /// not judged (the re-check of #569, N1: the input of this loop's
    /// shared case is now PID 1's namespace, the other namespaces below).
    #[test]
    fn a_change_of_propagation_reaches_the_lock_on_it_or_shared_from_above() {
        for guard in [GUARD_HOST, GUARD_AGENT, GUARD_WATCHDOG, 0] {
            for f in [
                MS_SHARED,
                MS_PRIVATE,
                MS_SLAVE,
                MS_UNBINDABLE,
                MS_PRIVATE | MS_REC,
                MS_SHARED | MS_REC,
            ] {
                assert!(lock_touched(f, true, false, guard), "on the lock: {f:#x}");
            }
            assert!(!lock_touched(MS_SHARED | MS_REC, false, false, guard));
            assert!(!lock_touched(0, true, true, guard), "no propagation flag");
        }
        assert!(lock_touched(MS_SHARED | MS_REC, false, true, GUARD_HOST));
        for guard in [GUARD_AGENT, GUARD_WATCHDOG, 0] {
            for f in [
                MS_SHARED,
                MS_SHARED | MS_REC,
                MS_PRIVATE | MS_REC,
                MS_SLAVE | MS_REC,
                MS_UNBINDABLE | MS_REC,
                MS_PRIVATE,
            ] {
                assert!(!lock_touched(f, false, true, guard), "above: {f:#x}");
            }
        }
        // the lock's own step: exactly MS_UNBINDABLE (the review of #569, F1c)
        assert!(lock_step(MS_UNBINDABLE));
        for f in [
            MS_SHARED,
            MS_SLAVE,
            MS_PRIVATE,
            MS_PRIVATE | MS_REC,
            MS_UNBINDABLE | MS_REC,
            MS_PRIVATE | MS_UNBINDABLE,
            0,
        ] {
            assert!(!lock_step(f), "{f:#x}");
        }
    }

    /// Named test (the review of #569, F1a): in PID 1's namespace a
    /// recursive `MS_PRIVATE` above the lock (`mount --make-rprivate` of
    /// `/sys/fs/bpf`, `/sys` or `/`) reaches it — it clears the lock's
    /// `MNT_UNBINDABLE`, and the next rbind copies it — and is refused and
    /// signed; a recursive `MS_SLAVE` or `MS_UNBINDABLE` there keeps the
    /// flag, and a change that is not recursive leaves the lock as it is.
    #[test]
    fn a_recursive_private_change_above_the_lock_in_pid_1s_namespace_is_refused() {
        // `MS_SILENT` (`include/uapi/linux/mount.h`): `mount(8)`'s own
        const MS_SILENT: u64 = 1 << 15;
        assert!(lock_touched(MS_PRIVATE | MS_REC, false, true, GUARD_HOST));
        assert!(lock_touched(
            MS_PRIVATE | MS_REC | MS_SILENT,
            false,
            true,
            GUARD_HOST
        ));
        for f in [
            MS_SLAVE | MS_REC,
            MS_UNBINDABLE | MS_REC,
            MS_PRIVATE,
            MS_SHARED,
            MS_SLAVE,
            0,
        ] {
            assert!(!lock_touched(f, false, true, GUARD_HOST), "above: {f:#x}");
        }
        // not above it (another mount's root): never
        assert!(!lock_touched(MS_PRIVATE | MS_REC, false, false, GUARD_HOST));
        // judged as any change that reaches the lock: refused, signed
        let rprivate = Query {
            lock_maker: false,
            lock_step: false,
            ..host(MG_OP_PROPAGATE, Point::EMPTY, "")
        };
        assert_eq!(decide(&rprivate), Verdict::Refuse(MG_WHY_LOCK));
        // the maker's identity is no exemption above it: its step is on the
        // lock only
        assert!(!lock_step_at(MS_PRIVATE | MS_REC, false, GUARD_HOST));
        assert!(!lock_step_at(MS_UNBINDABLE, false, GUARD_HOST));
        // systemd-shutdown's switch_root (`MS_REC | MS_PRIVATE` on `/`): the
        // one exempt shape, asked of the shutdown's identity
        assert!(lock_shutdown_step(MS_PRIVATE | MS_REC, false));
        for (f, on) in [
            (MS_PRIVATE | MS_REC, true),
            (MS_SHARED | MS_REC, false),
            (MS_PRIVATE | MS_SHARED | MS_REC, false),
            (MS_PRIVATE, false),
            (MS_UNBINDABLE | MS_REC, false),
        ] {
            assert!(!lock_shutdown_step(f, on), "{f:#x} on the lock {on}");
        }
        assert_eq!(
            lock_verdict(
                true,
                true,
                false,
                lock_shutdown_step(MS_PRIVATE | MS_REC, false),
                false
            ),
            Verdict::Allow
        );
        assert_eq!(
            lock_verdict(true, true, false, false, false),
            Verdict::Refuse(MG_WHY_LOCK)
        );
    }

    /// Named test (the re-check of #569, N1): runc's `prepareRoot()` with
    /// `rootfsPropagation: rshared` — what containerd and CRI-O set for any
    /// Kubernetes `mountPropagation: Bidirectional` mount (Cilium's bpffs,
    /// the CSI node plugins), and `unshare -m --propagation shared` —
    /// makes `/` recursively shared in the container's fresh namespace,
    /// whose `/` is still a peer of PID 1's: it changes that namespace's
    /// own copies (its copy of the lock among them, a residual behind the
    /// walk, signed at the round) and is let through; the same change
    /// made where the mount is PID 1's own stays refused and signed.
    #[test]
    fn a_recursive_shared_change_above_the_lock_is_judged_in_pid_1s_namespace_only() {
        let flags = MS_SHARED | MS_REC;
        // 0: PID 1's `/` (guarded), 1: the container's copy, a peer of it
        for known in [false, true] {
            let mut g = Graph::new(2).guard(0, GUARD_HOST).peers(1, &[0, 1]);
            if known {
                g = g.following(&[1]);
            }
            let (guard, reach) = target_reach(&g, 1).expect("reaches PID 1's");
            assert_eq!((guard, reach), (0, REACH_OTHER_NS));
            // the hook's widest rule first (`/` is keyed MG_LOCK_ABOVE),
            // then the rule by the target's namespace: not judged there
            assert!(lock_touched(flags, false, true, GUARD_HOST));
            assert!(!lock_touched(flags, false, true, guard), "known {known}");
        }
        for guard in [GUARD_AGENT, GUARD_WATCHDOG, 0] {
            assert!(!lock_touched(flags, false, true, guard), "guard {guard}");
            assert!(
                !lock_touched(flags | MS_PRIVATE, false, true, guard),
                "guard {guard}"
            );
        }
        // in PID 1's namespace: still judged, refused and signed
        assert!(lock_touched(flags, false, true, GUARD_HOST));
        let rshared = Query {
            lock_maker: false,
            lock_step: false,
            ..host(MG_OP_PROPAGATE, Point::EMPTY, "")
        };
        assert_eq!(decide(&rshared), Verdict::Refuse(MG_WHY_LOCK));
        assert!(
            !lock_shutdown_step(flags, false),
            "not the shutdown's shape"
        );
        // on the lock itself, or a raw namespace's copy of it that reaches
        // the host's: judged in every namespace, as before
        for guard in [GUARD_HOST, GUARD_AGENT, GUARD_WATCHDOG, 0] {
            assert!(lock_touched(MS_SHARED, true, false, guard), "guard {guard}");
            assert!(lock_touched(flags, true, false, guard), "guard {guard}");
        }
        let copy = Query {
            host: false,
            reaches: true,
            lock_maker: false,
            lock_step: lock_step_at(MS_SHARED, true, 0),
            ..host(MG_OP_PROPAGATE, pin_dir(), "")
        };
        assert_eq!(decide(&copy), Verdict::Refuse(MG_WHY_LOCK));
    }

    /// Named test (the review of #569, F1a): a plain `MS_SHARED` of the
    /// lock itself — what would follow a recursive `MS_PRIVATE` above it to
    /// make it reachable again — is refused in PID 1's namespace, its
    /// maker's included.
    #[test]
    fn a_plain_shared_change_of_the_lock_is_refused() {
        assert!(lock_touched(MS_SHARED, true, false, GUARD_HOST));
        assert!(!lock_step_at(MS_SHARED, true, GUARD_HOST));
        for maker in [false, true] {
            let q = Query {
                lock_maker: maker,
                lock_step: lock_step_at(MS_SHARED, true, GUARD_HOST),
                ..host(MG_OP_PROPAGATE, pin_dir(), "")
            };
            assert_eq!(decide(&q), Verdict::Refuse(MG_WHY_LOCK), "maker {maker}");
        }
    }

    /// Named test (the review of #569, F1c): the maker's step is
    /// `MS_UNBINDABLE` on the lock in PID 1's namespace only — not
    /// `MS_PRIVATE` (it clears `MNT_UNBINDABLE` of a lock in place), and
    /// not on a raw namespace's copy of the lock (its parent's guard is
    /// not PID 1's), nor in the agent's or the watchdog's.
    #[test]
    fn the_makers_step_is_unbindable_on_the_hosts_lock_only() {
        assert!(lock_step_at(MS_UNBINDABLE, true, GUARD_HOST));
        assert!(!lock_step_at(MS_PRIVATE, true, GUARD_HOST), "MS_PRIVATE");
        for guard in [GUARD_AGENT, GUARD_WATCHDOG, 0] {
            assert!(!lock_step_at(MS_UNBINDABLE, true, guard), "guard {guard}");
        }
        assert!(!lock_step_at(MS_UNBINDABLE, false, GUARD_HOST), "not on it");
        // the maker's MS_PRIVATE on the host's lock: refused, signed
        let private = Query {
            lock_maker: true,
            lock_step: lock_step_at(MS_PRIVATE, true, GUARD_HOST),
            ..host(MG_OP_PROPAGATE, pin_dir(), "")
        };
        assert_eq!(decide(&private), Verdict::Refuse(MG_WHY_LOCK));
        // the maker's MS_UNBINDABLE on a raw namespace's copy that reaches
        // the host's: refused, signed
        let copy = Query {
            host: false,
            reaches: true,
            lock_maker: true,
            lock_step: lock_step_at(MS_UNBINDABLE, true, 0),
            ..host(MG_OP_PROPAGATE, pin_dir(), "")
        };
        assert_eq!(decide(&copy), Verdict::Refuse(MG_WHY_LOCK));
        // its own step on the host's lock: let through
        let own = Query {
            lock_maker: true,
            lock_step: lock_step_at(MS_UNBINDABLE, true, GUARD_HOST),
            ..host(MG_OP_PROPAGATE, pin_dir(), "")
        };
        assert_eq!(decide(&own), Verdict::Allow);
    }

    /// Named test (lot 359): a change of propagation that reaches the lock
    /// is refused and signed (`MG_WHY_LOCK`) — but its maker's own step on
    /// it; let through and recorded inside the window; another
    /// namespace that reaches no guarded one is untouched.
    #[test]
    fn a_change_of_propagation_of_the_lock_is_refused_but_its_makers_steps() {
        let step = Query {
            lock_maker: true,
            lock_step: true,
            ..host(MG_OP_PROPAGATE, pin_dir(), "")
        };
        assert_eq!(decide(&step), Verdict::Allow);
        for q in [
            Query {
                lock_maker: false,
                ..step
            },
            Query {
                lock_step: false,
                ..step
            },
            Query {
                lock_maker: false,
                lock_step: false,
                ..step
            },
            // a raw namespace's copy, whose parent's group reaches PID 1's
            Query {
                host: false,
                reaches: true,
                lock_maker: false,
                ..step
            },
        ] {
            assert_eq!(decide(&q), Verdict::Refuse(MG_WHY_LOCK), "{q:?}");
        }
        let window = Query {
            lock_maker: false,
            window: true,
            ..step
        };
        assert_eq!(decide(&window), Verdict::Window(MG_WHY_LOCK));
        let away = Query {
            host: false,
            reaches: false,
            lock_maker: false,
            ..step
        };
        assert_eq!(
            decide(&away),
            Verdict::Allow,
            "a namespace that reaches none"
        );
        let unprivileged = Query {
            privileged: false,
            lock_maker: false,
            ..step
        };
        assert_eq!(decide(&unprivileged), Verdict::Allow, "the kernel's EPERM");
    }

    /// Named test (lot 359): the lock is a held mount — its maker can
    /// neither unmount nor move it (the uninstaller and the window can).
    #[test]
    fn the_lock_is_never_unmounted_or_moved_outside_a_window_by_its_maker_either() {
        for (op, why) in [
            (MG_OP_UMOUNT, MG_WHY_UMOUNT),
            (MG_OP_MOVE_MOUNT, MG_WHY_MOVE_AWAY),
        ] {
            let q = Query {
                held: true,
                lock_maker: true,
                lock_step: true,
                ..host(op, pin_dir(), "")
            };
            assert_eq!(decide(&q), Verdict::Refuse(why), "op {op}");
            let w = Query { window: true, ..q };
            assert_eq!(decide(&w), Verdict::Window(why), "op {op}");
        }
        // and a record names what it was
        assert!(why_name(MG_WHY_LOCK).contains("lock"));
        assert!(op_name(MG_OP_PROPAGATE).contains("propagation"));
        // its flags are new bits of the protected points'
        const {
            assert!(MG_LOCK & (MG_ON | MG_OWN | MG_VIEW | MG_HOLD | MG_SB) == 0);
            assert!(MG_LOCK_ABOVE & (MG_ON | MG_OWN | MG_VIEW | MG_HOLD | MG_SB | MG_LOCK) == 0);
            assert!(MS_PROPAGATION == MS_SHARED | MS_PRIVATE | MS_SLAVE | MS_UNBINDABLE);
        }
    }

    /// Named test (lot 1.1, the review of #569, F2): a `move_mount(2)` of
    /// an attached peer copy of a held mount — its group and its root a
    /// held mount's — is refused in any namespace (a raw `unshare -m`'s
    /// copy of `/sys` included), let through recorded in the window, and at
    /// the end of a shutdown. Failed on main: only the target was judged
    /// outside a guarded namespace.
    #[test]
    fn a_move_of_a_peer_copy_of_a_held_mount_is_refused_in_any_namespace() {
        // the held /sys of PID 1's namespace, in shared:7, root (0x15, 1)
        let held = held_root(7, 0x15, 1);
        // its raw namespace's copy: the same group, the same root dentry
        assert_eq!(held_root(7, 0x15, 1), held);
        let hit = |group: u32, dev: u64, ino: u64| held_root(group, dev, ino) == held;
        assert!(moves_held_copy(true, 7, hit(7, 0x15, 1)));
        assert_eq!(
            copy_move_verdict(moves_held_copy(true, 7, hit(7, 0x15, 1)), false, false).verdict(),
            Verdict::Refuse(MG_WHY_MOVE_COPY)
        );
        assert_eq!(
            copy_move_verdict(true, false, true).verdict(),
            Verdict::Window(MG_WHY_MOVE_COPY)
        );
        assert_eq!(copy_move_verdict(true, true, false), CopyMove::Allow);
        assert_eq!(CopyMove::Allow.verdict(), Verdict::Allow);
        // a bind of /usr in the same group (another root), or a mount of
        // another group with the same root, is not a copy of it
        assert!(!moves_held_copy(true, 7, hit(7, 0x15, 2)));
        assert!(!moves_held_copy(true, 7, hit(8, 0x15, 1)));
        assert!(!moves_held_copy(true, 7, hit(7, 0x16, 1)));
        assert_eq!(copy_move_verdict(false, false, false), CopyMove::Allow);
        // the key never meets another `MOUNT_HELD` key's
        let (dev, _) = held;
        assert_eq!(dev >> 61, HELD_ROOT >> 61);
        for other in [
            held_by_id(7).0,
            held_by_id(u32::MAX).0,
            held_by_place(7, 0x15, 1, &NameKey::NONE).0,
            held_under(7, 0x15, 1, &NameKey::NONE).0,
        ] {
            assert_ne!(other >> 61, dev >> 61, "{other:#x}");
        }
        assert!(why_name(MG_WHY_MOVE_COPY).contains("peer copy"));
    }

    /// Named test (lot 1.1, F2): a detached tree being attached (judged
    /// where it lands) and a mount in no peer group — a slave, a private
    /// copy, whose changes never reach the held mount — are not a held
    /// copy moved away.
    #[test]
    fn a_detached_tree_or_a_mount_in_no_group_is_judged_where_it_lands() {
        assert!(!moves_held_copy(false, 7, true));
        assert!(!moves_held_copy(true, 0, true));
        assert!(!moves_held_copy(true, 7, false));
    }

    /// Named test (lot 1.1, F8b-1): `sb_mount`'s entry sends to a stage
    /// every `mount(2)` the guard can refuse — every operation `decide`
    /// weighs to the point stage, every change of propagation that can
    /// reach the lock to the propagation stage — over every combination of
    /// the flags the guard reads.
    #[test]
    fn sb_mount_routes_every_judged_operation_to_its_stage() {
        let bits = [
            MS_RDONLY,
            MS_NOEXEC,
            MS_REMOUNT,
            MS_BIND,
            MS_MOVE,
            MS_REC,
            MS_UNBINDABLE,
            MS_PRIVATE,
            MS_SLAVE,
            MS_SHARED,
            1 << 15, // MS_SILENT
        ];
        for mask in 0u32..(1 << bits.len()) {
            let mut flags = 0u64;
            for (i, b) in bits.iter().enumerate() {
                if mask & (1 << i) != 0 {
                    flags |= b;
                }
            }
            let route = sb_mount_route(flags);
            let op = mount_op(flags);
            assert_eq!(route == SbRoute::Point, op != MG_OP_PASS, "{flags:#x}");
            // a change of propagation in the kernel's sense (not a remount
            // that carries a propagation bit): the lock's judge sees it
            assert_eq!(
                route == SbRoute::Propagate,
                op == MG_OP_PASS && regroups(flags),
                "{flags:#x}"
            );
            if route == SbRoute::Pass {
                for guard in [0, GUARD_HOST, GUARD_AGENT, GUARD_WATCHDOG] {
                    // nothing let through unread is one the lock's judge
                    // would weigh as a change of propagation
                    assert!(
                        !(regroups(flags) && lock_touched(flags, true, true, guard)),
                        "{flags:#x} guard {guard}"
                    );
                }
            }
        }
        // the slots are distinct, within the arrays
        const {
            assert!(STAGE_POINT != STAGE_PROPAGATE);
            assert!(STAGE_POINT < STAGE_SLOTS && STAGE_PROPAGATE < STAGE_SLOTS);
        }
    }

    /// Named test (lot 1.1, F8b-1): the hooks' decision as a number is the
    /// decision — [`decide_code`] read back is [`decide`] for every
    /// operation over every combination of the query's flags and points
    /// (on, below the agent's, below a view, elsewhere), and the copy's
    /// move's code is its verdict's.
    #[test]
    fn the_decision_as_a_number_is_the_decision() {
        let points = [
            Point {
                flags: MG_OWN,
                ..Point::EMPTY
            },
            Point {
                below: MG_OWN,
                ..Point::EMPTY
            },
            Point {
                below: MG_VIEW,
                magic: SYSFS_MAGIC,
                ..Point::EMPTY
            },
            Point::EMPTY,
        ];
        let ops = [
            MG_OP_PASS,
            MG_OP_MOUNT,
            MG_OP_BIND,
            MG_OP_MOVE_OLD,
            MG_OP_MOVE_MOUNT,
            MG_OP_UMOUNT,
            MG_OP_PIVOT,
            MG_OP_REMOUNT,
            MG_OP_REMOUNT_BIND,
            MG_OP_PROPAGATE,
        ];
        let mut n = 0;
        for op in ops {
            for point in points {
                for bits in 0u32..(1 << 12) {
                    let b = |i: u32| bits & (1 << i) != 0;
                    let q = Query {
                        op,
                        host: b(0),
                        reaches: b(1),
                        privileged: b(2),
                        init: b(3),
                        window: b(4),
                        held: b(5),
                        noted: b(6),
                        shutdown: b(7),
                        kernel: b(8),
                        restrict: b(9),
                        lock_maker: b(10),
                        lock_step: b(11),
                        ..host(op, point, "")
                    };
                    let v = decide(&q);
                    assert_eq!(verdict_of_code(decide_code(op, &q)), v, "{q:?}");
                    assert_eq!(verdict_of_code(verdict_code(v)), v);
                    assert_eq!(verdict_code(v) == 0, v == Verdict::Allow);
                    n += 1;
                }
            }
        }
        assert!(n > 100_000);
        for c in [CopyMove::Allow, CopyMove::Refuse, CopyMove::Window] {
            assert_eq!(c.code(), verdict_code(c.verdict()));
        }
        // every reason byte reads back whole, not only the reasons defined
        // today (all below 0x80): the code carries the reason's eight bits
        for w in 0..=u8::MAX {
            for v in [Verdict::Refuse(w), Verdict::Window(w), Verdict::Noted(w)] {
                assert_eq!(verdict_of_code(verdict_code(v)), v, "{v:?}");
                assert_eq!(verdict_code(v) & 0xff, u16::from(w), "{v:?}");
            }
        }
    }

    /// Named test (lot 1.1, the change_mnt_propagation fentry): a change
    /// counts on a mount of a guarded namespace, of a held group, or on the
    /// lock or a copy of it — never on a mount `umount_tree()` takes (its
    /// namespace already cleared), nor on a container's own mount.
    #[test]
    fn a_propagation_change_counts_on_a_guarded_or_held_mount_or_the_lock() {
        assert!(propagation_counts(true, GUARD_HOST, false, false));
        assert!(propagation_counts(true, GUARD_AGENT, false, false));
        assert!(propagation_counts(true, 0, true, false));
        assert!(propagation_counts(true, 0, false, true));
        assert!(!propagation_counts(true, 0, false, false));
        for (g, k, l) in [(GUARD_HOST, true, true), (0, true, false), (0, false, true)] {
            assert!(!propagation_counts(false, g, k, l));
        }
        const {
            assert!(CONF_PROPAGATED < CONF_SLOTS);
        }
    }

    /// Named test (lot 1.1, the re-check 2 of #569, N3): an agent or a
    /// watchdog run by hand in PID 1's mount namespace never takes PID 1's
    /// entry as its own, and its exit never drops it. Failed on main: the
    /// entry became `GUARD_AGENT` and was removed at the agent's exit.
    #[test]
    fn pid_1s_namespace_is_never_taken_or_dropped_as_a_roles_own() {
        let host = 4_026_531_841;
        assert!(!guards_own_namespace(host, host));
        assert!(!vacates(host, host));
        assert!(guards_own_namespace(4_026_532_300, host));
        assert!(vacates(4_026_532_300, host));
        assert!(!guards_own_namespace(0, host));
        assert!(!vacates(0, host));
    }

    /// Lot 2.3a (K4): a mount on the key files' directory or below it is
    /// refused inside a window too; the window lifts it elsewhere.
    #[test]
    fn a_mount_on_or_below_the_key_directory_is_refused_inside_a_window() {
        let on = |flags: u8, below: u8| Point {
            flags,
            below,
            ..plain(0xEF53, &["northnarrow", "etc"])
        };
        for (p, why) in [
            (on(MG_OWN | MG_HOLD | MG_KEPT, 0), MG_WHY_ON),
            (on(0, MG_OWN | MG_KEPT), MG_WHY_BELOW_OWN),
        ] {
            for op in [MG_OP_MOUNT, MG_OP_BIND, MG_OP_MOVE_MOUNT] {
                let mut q = host(op, p, "");
                q.window = true;
                assert!(point_kept(&q.point));
                assert_eq!(decide(&q), Verdict::Refuse(why), "op {op}");
                q.window = false;
                assert_eq!(decide(&q), Verdict::Refuse(why), "op {op}");
            }
        }
        // the agent's other directories: the window lifts it, as before
        let mut q = host(MG_OP_MOUNT, on(MG_OWN | MG_HOLD, 0), "");
        q.window = true;
        assert!(!point_kept(&q.point));
        assert_eq!(decide(&q), Verdict::Window(MG_WHY_ON));
    }
}
