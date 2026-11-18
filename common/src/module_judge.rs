//! Lot 285: a kernel module load judged in the kernel, by the FILE.
//!
//! A root user loads a module without any tool (`finit_module(2)` on a
//! file of their choice, `init_module(2)` on a buffer), so the prevention
//! belongs to the kernel's two load hooks (`agent-ebpf/src/module_load.rs`):
//! `kernel_read_file` with `READING_MODULE` (the file `finit_module` reads)
//! and `kernel_load_data` with `LOADING_MODULE` (the buffer `init_module`
//! copied). Who loads is not asked — a `comm` is the caller's to choose —
//! only what is loaded:
//!
//! - a file is trusted when its inode (`dev`, `ino`, as `stat()` reports
//!   them) is in the agent's trust map with the change time and size the
//!   agent verified it at, and it is a regular file owned by root that
//!   neither its group nor others may write. The agent puts in the map only
//!   the files of `/lib/modules/$(uname -r)/` (walked from that directory,
//!   so the inode is the kernel's, not a path's text) that a verified
//!   package installed or DKMS built, unchanged since boot or written since
//!   inside a package transaction (the write history below), and the files
//!   a signed opt-out names. One more kind is let through but recorded
//!   ([`trust_flag::UNATTESTED`]): a DKMS or akmods build in its output
//!   directory, the same content DKMS's registry or the package database
//!   holds, written since boot outside a recognised package transaction —
//!   in the map unless the policy enforces R018;
//! - a buffer (`init_module`) has no file to trust: refused outside a
//!   signed trusted-installer window.
//!
//! The write history ([`write_step`]): the agent cannot see who wrote a
//! file it finds in the tree, so the kernel keeps it — every write-open of
//! a module file in the running kernel's tree, and of any inode in the
//! trust map (whatever name it is opened by), marks the inode as written
//! by a package transaction (the writer, or an ancestor within the
//! lineage's hops, runs a package manager's image as root — or its `#!`
//! script, executed by its own file: dnf, yum) or not. A file
//! created inside a transaction and opened for writing only by it since is
//! [`write_flag::PKG`]; anything else, or no history at all, is not.
//!
//! The verdicts are this module's, so the host's tests judge what the
//! programs decide.

/// The kernel's mode (`MODULE_CONF[conf_slot::MODE]`).
pub mod mode {
    /// The agent has not filled the trust map yet (or never armed the
    /// judge): every load goes through, recorded as not judged.
    pub const NOT_READY: u64 = 0;
    /// Judged; an untrusted file or a buffer goes through, recorded.
    pub const RECORD: u64 = 1;
    /// Judged; an untrusted file or a buffer is refused (`-EPERM`) outside
    /// a signed trusted-installer window.
    pub const DENY: u64 = 2;
}

/// `MODULE_CONF`'s slots.
pub mod conf_slot {
    /// [`super::mode`].
    pub const MODE: u32 = 0;
    /// The running kernel's module tree (`/lib/modules/$(uname -r)`), as
    /// `stat()` reports it: the root the write history walks up to.
    pub const TREE_DEV: u32 = 1;
    pub const TREE_INO: u32 = 2;
    /// Lot 370 (the lab): non-zero when the package locks' observer
    /// (`module_lock_observe`) is not attached — the write history then
    /// names a lineage's package manager without its lock, which the agent
    /// samples. 0 (the default, before the agent writes it): a write is a
    /// transaction's only when its package manager holds its lock
    /// ([`super::holds_lock`]).
    pub const LOCKS_UNOBSERVED: u32 = 3;
    pub const SLOTS: u32 = 4;
}

/// What the kernel made of a load (`ModuleLoadRaw::verdict`).
pub mod verdict {
    /// The judge was not armed ([`super::mode::NOT_READY`]), or an older
    /// eBPF object: the rule judges by the path.
    pub const NOT_JUDGED: u8 = 0;
    /// A trusted file.
    pub const TRUSTED: u8 = 1;
    /// Untrusted (or a buffer), let through by a signed trusted-installer
    /// window.
    pub const WINDOW: u8 = 2;
    /// A file a signed per-module opt-out names.
    pub const OPT_OUT: u8 = 3;
    /// Untrusted (or a buffer), let through: the record mode.
    pub const RECORDED: u8 = 4;
    /// Untrusted (or a buffer), refused.
    pub const DENIED: u8 = 5;
    /// A DKMS or akmods build the registry vouches for, written since boot
    /// outside a recognised package transaction
    /// ([`super::trust_flag::UNATTESTED`]): let through, recorded High.
    pub const UNATTESTED: u8 = 6;
}

/// Why a file is in the trust map (`ModuleTrust::flags`).
pub mod trust_flag {
    /// A verified package's file: listed by the package database, its
    /// content the digest the database recorded.
    pub const PACKAGE: u32 = 1;
    /// DKMS's build, in DKMS's install directory, of a module DKMS has
    /// registered.
    pub const DKMS: u32 = 2;
    /// Changed since boot, written inside a package transaction
    /// ([`super::write_flag::PKG`]).
    pub const PKG_WRITTEN: u32 = 4;
    /// Named by a signed per-module opt-out (nothing else trusts it).
    pub const OPT_OUT: u32 = 8;
    /// In a DKMS or akmods output directory (`updates/dkms/`, `extra/`),
    /// its content the registry's build (DKMS's own copy, or the digest
    /// the package database recorded for an akmods-built kmod package),
    /// written since boot outside a recognised package transaction — a
    /// build by hand, or one the agent's start did not see (`akmods` at
    /// boot). Let through and recorded High, not trusted; the agent leaves
    /// it out of the map when the policy enforces R018 (refused then).
    /// Nothing else trusts it.
    pub const UNATTESTED: u32 = 16;
    /// The flags that let a load through without a record.
    pub const TRUSTING: u32 = PACKAGE | DKMS | PKG_WRITTEN;
}

/// The write history of an inode (`MODULE_WRITES`).
pub mod write_flag {
    /// Created inside a package transaction.
    pub const PKG: u32 = 1;
    /// Opened for writing outside one, or opened for writing with no
    /// history (its creation not seen): its content is not a transaction's.
    pub const TAINT: u32 = 2;
}

/// Lot 303: the ids the two load hooks are called with
/// (include/linux/kernel_read_file.h: `enum kernel_read_file_id`, and
/// `enum kernel_load_data_id`, generated from the same list). The list is
/// appended to, never reordered, from 5.10 (which dropped
/// `READING_FIRMWARE_PREALLOC_BUFFER`) to 7.3 — the agent's kernels (5.14
/// el9 and later); the boot checks every value against the running
/// kernel's BTF ([`READ_IDS`]) and leaves the hooks out where one differs
/// (a judge built for other ids would refuse what it must not, or judge
/// nothing).
pub mod read_id {
    /// `READING_MODULE`: the file `finit_module(2)` reads.
    pub const MODULE: u32 = 2;
    /// `READING_KEXEC_IMAGE` (and `LOADING_KEXEC_IMAGE`): refused outside a
    /// window (review 82).
    pub const KEXEC_IMAGE: u32 = 3;
    /// `READING_MODULE_COMPRESSED` (7.0, appended): the file a
    /// `finit_module(2)` with `MODULE_INIT_COMPRESSED_FILE` reads — kmod's
    /// load of a `.ko.zst` / `.ko.xz` the kernel decompresses itself, every
    /// module of Ubuntu 26.04. The nightly's 7.0 guest recorded no module
    /// load and judged none (lot 303). Before 7.0 the value is
    /// `READING_MAX_ID`, which no caller passes.
    pub const MODULE_COMPRESSED: u32 = 7;
    /// `LOADING_MODULE`: the buffer `init_module(2)` copied.
    pub const LOADING_MODULE: u32 = 2;
}

/// Lot 303: `(enum, enumerator, the value the programs compare against,
/// required)`: the boot's BTF check of [`read_id`]. An optional one may be
/// absent from the kernel (`READING_MODULE_COMPRESSED` before 7.0), never
/// of another value.
pub const READ_IDS: &[(&str, &str, u32, bool)] = &[
    (
        "kernel_read_file_id",
        "READING_MODULE",
        read_id::MODULE,
        true,
    ),
    (
        "kernel_read_file_id",
        "READING_KEXEC_IMAGE",
        read_id::KEXEC_IMAGE,
        true,
    ),
    (
        "kernel_read_file_id",
        "READING_MODULE_COMPRESSED",
        read_id::MODULE_COMPRESSED,
        false,
    ),
    (
        "kernel_load_data_id",
        "LOADING_MODULE",
        read_id::LOADING_MODULE,
        true,
    ),
    (
        "kernel_load_data_id",
        "LOADING_KEXEC_IMAGE",
        read_id::KEXEC_IMAGE,
        true,
    ),
];

/// Lot 303: whether a `kernel_read_file` call reads a module file — plain
/// (`READING_MODULE`) or one the kernel decompresses
/// (`READING_MODULE_COMPRESSED`, 7.0+): both are judged by the file.
pub const fn reads_module_file(id: u32) -> bool {
    id == read_id::MODULE || id == read_id::MODULE_COMPRESSED
}

/// Lot 303: what differs between [`READ_IDS`] and a kernel whose values
/// `lookup(enum, enumerator)` gives (`None`: absent) — one line per
/// enumerator, empty when the hooks may be attached.
#[cfg(feature = "std")]
pub fn read_id_drift(
    lookup: impl Fn(&str, &str) -> Option<i64>,
) -> alloc::vec::Vec<alloc::string::String> {
    READ_IDS
        .iter()
        .filter_map(|(e, name, ours, required)| match lookup(e, name) {
            Some(v) if v == i64::from(*ours) => None,
            None if !*required => None,
            Some(v) => Some(alloc::format!(
                "{e}.{name} is {v} on this kernel, {ours} in the programs"
            )),
            None => Some(alloc::format!("{e}.{name} is not in this kernel's BTF")),
        })
        .collect()
}

/// The hops the write history's lineage and tree walks take at most.
pub const WALK_HOPS: usize = 12;

/// The trust map's entries: a stock tree holds 2,000 to 7,000 module files.
pub const MODULE_TRUST_MAX: u32 = 32_768;
/// The package managers' images the lineage check knows.
pub const MODULE_PKG_IMAGES_MAX: u32 = 64;
/// The write histories kept (least recently used evicted: no history, no
/// trust).
pub const MODULE_WRITES_MAX: u32 = 8_192;
/// The processes running a package manager's `#!` script kept (least
/// recently used evicted: a write of one evicted is no transaction's).
pub const MODULE_PKG_SCRIPTS_MAX: u32 = 1_024;

/// Lot 370 (the lab): the package managers' lock files the kernel watches
/// (`MODULE_PKG_LOCKS`, the agent's list: dpkg's, apt's front end, rpm's).
pub const MODULE_PKG_LOCKS_MAX: u32 = 8;

/// Lot 370 (the lab): the thread groups holding a package manager's lock
/// (`MODULE_PKG_LOCKERS`, an LRU map: a transaction long gone is evicted).
pub const MODULE_PKG_LOCKERS_MAX: u32 = 1_024;

/// `inode.i_ctime`'s nanoseconds as the kernel reads them back: from 6.13
/// the field's high bit tells whether the time was queried
/// (`I_CTIME_QUERIED`, multigrain timestamps); a nanosecond count is below
/// 2^30.
pub const CTIME_NSEC_MASK: u32 = 0x3fff_ffff;

/// One entry of the trust map, keyed by the file's `InodeKey`: what the
/// agent verified the file at.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[cfg_attr(feature = "std", derive(bytemuck::Pod, bytemuck::Zeroable))]
pub struct ModuleTrust {
    pub ctime_sec: i64,
    pub size: i64,
    pub ctime_nsec: u32,
    /// [`trust_flag`] bits.
    pub flags: u32,
}

/// What the kernel reads of the file a load names.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FileFacts {
    pub uid: u32,
    /// `i_mode` (type and permission bits).
    pub mode: u32,
    pub ctime_sec: i64,
    pub ctime_nsec: u32,
    pub size: i64,
}

const S_IFMT: u32 = 0o170_000;
const S_IFREG: u32 = 0o100_000;
/// Writable by the group or by others.
const S_IWGRP_IWOTH: u32 = 0o022;

/// A regular file owned by root that neither its group nor others may
/// write.
#[inline(always)]
pub const fn safe_owner(f: &FileFacts) -> bool {
    f.uid == 0 && f.mode & S_IFMT == S_IFREG && f.mode & S_IWGRP_IWOTH == 0
}

/// The trust flags of the file `f` when `entry` (its trust map entry)
/// still describes it: owner and mode safe, change time and size those the
/// agent verified it at. `None`: untrusted.
#[inline(always)]
pub fn trusted_flags(entry: Option<&ModuleTrust>, f: &FileFacts) -> Option<u32> {
    let e = entry?;
    if !safe_owner(f)
        || e.ctime_sec != f.ctime_sec
        || e.ctime_nsec != f.ctime_nsec & CTIME_NSEC_MASK
        || e.size != f.size
    {
        return None;
    }
    Some(e.flags)
}

/// The verdict on a `finit_module` of the file `f`: `entry` its trust map
/// entry, `window` a signed trusted-installer window open, `mode` the
/// kernel's [`mode`].
#[inline(always)]
pub fn finit_verdict(entry: Option<&ModuleTrust>, f: &FileFacts, window: bool, mode: u64) -> u8 {
    if mode == mode::NOT_READY {
        return verdict::NOT_JUDGED;
    }
    match trusted_flags(entry, f) {
        Some(flags) if flags & trust_flag::TRUSTING != 0 => verdict::TRUSTED,
        Some(flags) if flags & trust_flag::OPT_OUT != 0 => verdict::OPT_OUT,
        Some(flags) if flags & trust_flag::UNATTESTED != 0 => verdict::UNATTESTED,
        _ => untrusted(window, mode),
    }
}

/// The verdict on an `init_module` (a buffer: no file to trust).
#[inline(always)]
pub fn init_verdict(window: bool, mode: u64) -> u8 {
    if mode == mode::NOT_READY {
        return verdict::NOT_JUDGED;
    }
    untrusted(window, mode)
}

#[inline(always)]
fn untrusted(window: bool, mode: u64) -> u8 {
    if window {
        verdict::WINDOW
    } else if mode == mode::DENY {
        verdict::DENIED
    } else {
        verdict::RECORDED
    }
}

/// The load is refused.
#[inline(always)]
pub const fn refuses(v: u8) -> bool {
    v == verdict::DENIED
}

/// The verdict's name (records, logs).
pub const fn verdict_name(v: u8) -> &'static str {
    match v {
        verdict::TRUSTED => "trusted",
        verdict::WINDOW => "window",
        verdict::OPT_OUT => "opt-out",
        verdict::RECORDED => "recorded",
        verdict::DENIED => "denied",
        verdict::UNATTESTED => "dkms-unattested",
        _ => "not-judged",
    }
}

/// The write history after a write-open: `prev` the inode's history,
/// `created` the open created the file (`FMODE_CREATED`), `pkg` the writer
/// is inside a package transaction. A creation starts the history afresh;
/// an open with no history (its creation not seen) or outside a
/// transaction taints it, for the inode's life.
#[inline(always)]
pub const fn write_step(prev: Option<u32>, created: bool, pkg: bool) -> u32 {
    match prev {
        Some(p) => step_flags(p, true, created, pkg),
        None => step_flags(0, false, created, pkg),
    }
}

/// [`write_step`] in plain values: `had` the inode has a history, `prev`
/// its flags then.
#[inline(always)]
const fn step_flags(prev: u32, had: bool, created: bool, pkg: bool) -> u32 {
    if created {
        if pkg {
            write_flag::PKG
        } else {
            write_flag::TAINT
        }
    } else if !had {
        write_flag::TAINT
    } else if pkg {
        prev
    } else {
        prev | write_flag::TAINT
    }
}

/// The history says a package transaction wrote the file, and nothing else
/// did.
#[inline(always)]
pub const fn written_by_package(history: Option<u32>) -> bool {
    matches!(history, Some(write_flag::PKG))
}

/// Lot 370 (F10-2): one inode's write history, `MODULE_WRITES`' value —
/// its [`write_flag`] bits and the package transaction that wrote it.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[cfg_attr(feature = "std", derive(bytemuck::Pod, bytemuck::Zeroable))]
pub struct ModuleWrite {
    /// [`write_flag`] bits.
    pub flags: u32,
    /// The transaction's package manager (its thread group, the lineage's
    /// nearest package manager at the write): 0 none, [`TXN_MIXED`] more
    /// than one wrote the file.
    pub txn_tgid: u32,
    /// Its start, `task_struct.start_boottime` (nanoseconds: what
    /// `/proc/<pid>/stat` shows in ticks).
    pub txn_start: u64,
}

/// [`ModuleWrite::txn_tgid`] of a file two transactions wrote: none vouches.
pub const TXN_MIXED: u32 = u32::MAX;

/// Lot 370 (F10-2): a package transaction as the kernel saw it at a write —
/// its package manager's thread group and start.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Txn {
    pub tgid: u32,
    pub start: u64,
}

impl Txn {
    /// No transaction (no package manager's thread group is 0).
    pub const NONE: Txn = Txn { tgid: 0, start: 0 };
}

/// Lot 370 (F10-2): [`write_step`] with the transaction that wrote: a
/// creation inside one names it; a write by another (or by one where none
/// was named) leaves [`TXN_MIXED`]; a write outside one taints the flags.
/// [`history_step_raw`] is the form the eBPF program calls.
#[inline(always)]
pub fn history_step(prev: Option<ModuleWrite>, created: bool, txn: Option<Txn>) -> ModuleWrite {
    history_step_raw(
        prev.unwrap_or_default(),
        prev.is_some(),
        created,
        txn.unwrap_or(Txn::NONE),
    )
}

/// Lot 370 (the lab on 5.15): [`history_step`] in plain values, the form
/// the eBPF program calls — `had` the inode has a history (`prev` it),
/// `txn` [`Txn::NONE`] outside a transaction. An `Option` built in the
/// program leaves its payload's stack slots unwritten on the `None` path,
/// and the compiler may read them before the test: 5.15's verifier refuses
/// that read ("invalid read from stack"; 7.0's accepts it), and the write
/// history's observer did not load on 5.15.
// the arms kept apart, one per case of `history_step`'s reference match
#[allow(clippy::if_same_then_else)]
#[inline(always)]
pub fn history_step_raw(prev: ModuleWrite, had: bool, created: bool, txn: Txn) -> ModuleWrite {
    let pkg = txn.tgid != 0;
    let flags = step_flags(prev.flags, had, created, pkg);
    let (txn_tgid, txn_start) = if pkg && created {
        (txn.tgid, txn.start)
    } else if had && pkg && prev.txn_tgid == txn.tgid && prev.txn_start == txn.start {
        (txn.tgid, txn.start)
    } else if had && pkg {
        (TXN_MIXED, 0)
    } else if had {
        (prev.txn_tgid, prev.txn_start)
    } else {
        (0, 0)
    };
    ModuleWrite {
        flags,
        txn_tgid,
        txn_start,
    }
}

/// Lot 370 (F10-2): the one transaction that wrote the file, when the
/// history says a package transaction wrote it and nothing else did
/// ([`written_by_package`]).
#[inline(always)]
pub fn package_transaction(history: Option<ModuleWrite>) -> Option<Txn> {
    match history {
        Some(h)
            if written_by_package(Some(h.flags)) && h.txn_tgid != 0 && h.txn_tgid != TXN_MIXED =>
        {
            Some(Txn {
                tgid: h.txn_tgid,
                start: h.txn_start,
            })
        }
        _ => None,
    }
}

/// Lot 370 (the lab): a thread group that asked for a package manager's
/// lock, `MODULE_PKG_LOCKERS`' value — its leader's start
/// (`task_struct.start_boottime`) and the lock files it holds a write lock
/// on (their bits, `MODULE_PKG_LOCKS`' values).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[cfg_attr(feature = "std", derive(bytemuck::Pod, bytemuck::Zeroable))]
pub struct PkgLocker {
    pub start: u64,
    pub locks: u32,
    pub _pad: u32,
}

/// The lock types the `file_lock` hook is called with (`F_RDLCK`,
/// `F_WRLCK`, `F_UNLCK`: fcntl's and flock's, the same on every arch the
/// agent runs on).
pub mod lock_kind {
    pub const RDLCK: u32 = 0;
    pub const WRLCK: u32 = 1;
    pub const UNLCK: u32 = 2;
}

/// Lot 370 (the lab): the locker entry after a lock request `kind` on the
/// lock file `bit` by the thread group started at `start` (`had` it has an
/// entry, `prev`): a write lock holds the file; a release, or a shared lock
/// (rpm's queries take one), holds it no more. An entry of another start
/// (a reused pid) holds nothing. The kernel steps it at the request, before
/// the lock is granted — a package manager refused its lock exits, or waits
/// without starting anything.
#[inline(always)]
pub fn locker_step(prev: PkgLocker, had: bool, start: u64, kind: u32, bit: u32) -> PkgLocker {
    let held = if had && prev.start == start {
        prev.locks
    } else {
        0
    };
    let locks = if kind == lock_kind::WRLCK {
        held | bit
    } else if kind == lock_kind::UNLCK || kind == lock_kind::RDLCK {
        held & !bit
    } else {
        held
    };
    PkgLocker {
        start,
        locks,
        _pad: 0,
    }
}

/// Lot 370 (the lab): at a write, the package manager started at `start`
/// holds a package manager's lock — its entry (`had`, `entry`) is of that
/// start and holds a lock file. Read in the kernel at the write: a
/// transaction shorter than any poll is still one.
#[inline(always)]
pub fn holds_lock(entry: PkgLocker, had: bool, start: u64) -> bool {
    had && start != 0 && entry.start == start && entry.locks != 0
}

/// Lot 370 (F10-2): `task_struct.__state` bits (include/linux/sched.h).
pub mod task_state {
    /// `__TASK_STOPPED` (`SIGSTOP`, a job-control stop).
    pub const STOPPED: u32 = 0x0004;
    /// `__TASK_TRACED` (stopped under a tracer).
    pub const TRACED: u32 = 0x0008;
    /// `TASK_FROZEN` (6.1+: the system's freezer — suspend, the cgroup-v1
    /// freezer; the bit is unused before). The review of #578 (N4): the
    /// cgroup-v2 freezer leaves a task in an ordinary interruptible wait
    /// (`TASK_INTERRUPTIBLE | TASK_FREEZABLE`): not told, it vouches.
    pub const FROZEN: u32 = 0x8000;
}

/// Lot 370 (F10-2): a package manager in this state may vouch for a write
/// of its lineage — not stopped, traced or frozen by the system's freezer
/// (a held transaction is no transaction; one a cgroup-v2 freezer holds
/// waits as any other and still vouches).
#[inline(always)]
pub const fn state_may_vouch(state: u32) -> bool {
    state & (task_state::STOPPED | task_state::TRACED | task_state::FROZEN) == 0
}

/// The length of the name window [`module_file_name`] reads: the last
/// bytes of a dentry's name.
pub const NAME_TAIL: usize = 32;

/// A kernel module's file name, from the last [`NAME_TAIL`] bytes of the
/// name (NUL-padded; the window starts at the name's start when it is
/// shorter): `.ko` at the end or followed by a dot — `x.ko`, `x.ko.zst`,
/// `x.ko.xz`, and the temporary names package managers write before the
/// rename (dpkg's `x.ko.zst.dpkg-new`, rpm's `x.ko;<hex>`).
#[inline(always)]
pub fn module_file_name(tail: &[u8; NAME_TAIL]) -> bool {
    let mut i = 0;
    while i + 3 <= NAME_TAIL {
        if tail[i] == b'.' && tail[i + 1] == b'k' && tail[i + 2] == b'o' {
            let next = if i + 3 < NAME_TAIL { tail[i + 3] } else { 0 };
            if next == 0 || next == b'.' || next == b';' {
                return true;
            }
        }
        i += 1;
    }
    false
}

/// The endings of a module file's name that [`module_stem`] takes off: the
/// module itself, and the compressed forms kmod loads.
pub const MODULE_SUFFIXES: [&str; 4] = [".ko", ".ko.xz", ".ko.zst", ".ko.gz"];

/// Lot 313 (external bug hunt, edition 1.4: BUG-87, BUG-111): the stem of a
/// module file's name — what precedes the `.ko`, `.ko.xz`, `.ko.zst` or
/// `.ko.gz` that ENDS the name (`acme.kontrol.ko` is `acme.kontrol`); `None`
/// for any other name (`x.ko;65a1b2c3`, `zfs.ko.zst.dpkg-new`, `x.kobj`) and
/// for a stem that names no file of its own (empty, `.`, `..`). The one
/// reader of a module's name from its file's: the kernel judge's trust map
/// (`agent/src/module_trust`) and R018's provenance read it here. It cut at
/// the FIRST `.ko` before: `nvidia.kox-rootkit.ko` was DKMS's `nvidia`,
/// `..ko` the registry's own directory.
#[cfg(feature = "std")]
pub fn module_stem(file_name: &str) -> Option<&str> {
    let stem = MODULE_SUFFIXES
        .iter()
        .find_map(|s| file_name.strip_suffix(s))?;
    (!matches!(stem, "" | "." | "..")).then_some(stem)
}

/// The module name a file name carries: its [`module_stem`], with `-` read
/// as `_` (the kernel's and kmod's spelling of the same module).
#[cfg(feature = "std")]
pub fn module_name_of(file_name: &str) -> Option<alloc::string::String> {
    module_stem(file_name).map(|s| s.replace('-', "_"))
}

#[cfg(all(test, feature = "std"))]
mod tests {
    use super::*;

    /// Lot 303 (named): a compressed module's read (7.0's
    /// `READING_MODULE_COMPRESSED`, every `.ko.zst` kmod loads on Ubuntu
    /// 26.04) is a module read like the plain one — the nightly's 7.0 guest
    /// judged and recorded none; no other id is (firmware, the kexec image
    /// and initramfs, a policy, a certificate, `READING_MAX_ID` before 7.0
    /// is 7 too, and no caller passes it).
    #[test]
    fn a_compressed_module_s_read_is_judged_like_a_plain_one() {
        assert!(reads_module_file(read_id::MODULE));
        assert!(reads_module_file(read_id::MODULE_COMPRESSED));
        assert_eq!((read_id::MODULE, read_id::MODULE_COMPRESSED), (2, 7));
        for other in [0, 1, 3, 4, 5, 6, 8, u32::MAX] {
            assert!(!reads_module_file(other), "{other}");
        }
        assert_eq!(read_id::KEXEC_IMAGE, 3);
        assert_eq!(read_id::LOADING_MODULE, 2);
    }

    /// Lot 303 (named): the boot's check of the ids — the enum of 6.x
    /// (no compressed id) and of 7.0 pass; a value that moved, or a
    /// required one gone, is named and keeps the hooks out.
    #[test]
    fn read_ids_that_drift_from_the_kernel_are_named() {
        let v6 = |e: &str, n: &str| -> Option<i64> {
            match (e, n) {
                ("kernel_read_file_id", "READING_MODULE") => Some(2),
                ("kernel_read_file_id", "READING_KEXEC_IMAGE") => Some(3),
                ("kernel_load_data_id", "LOADING_MODULE") => Some(2),
                ("kernel_load_data_id", "LOADING_KEXEC_IMAGE") => Some(3),
                _ => None,
            }
        };
        assert!(read_id_drift(v6).is_empty());
        let v7 = |e: &str, n: &str| {
            if n == "READING_MODULE_COMPRESSED" {
                Some(7)
            } else {
                v6(e, n)
            }
        };
        assert!(read_id_drift(v7).is_empty());
        let inserted = |e: &str, n: &str| match n {
            "READING_MODULE_COMPRESSED" => Some(3),
            "READING_KEXEC_IMAGE" => Some(4),
            _ => v6(e, n),
        };
        assert_eq!(
            read_id_drift(inserted),
            vec![
                "kernel_read_file_id.READING_KEXEC_IMAGE is 4 on this kernel, 3 in the programs"
                    .to_string(),
                "kernel_read_file_id.READING_MODULE_COMPRESSED is 3 on this kernel, 7 in the \
                 programs"
                    .to_string()
            ]
        );
        let gone = |e: &str, n: &str| {
            if n == "LOADING_MODULE" {
                None
            } else {
                v6(e, n)
            }
        };
        assert_eq!(
            read_id_drift(gone),
            vec!["kernel_load_data_id.LOADING_MODULE is not in this kernel's BTF".to_string()]
        );
        assert_eq!(
            READ_IDS.iter().filter(|r| !r.3).count(),
            1,
            "one optional id"
        );
    }

    fn tail(s: &str) -> [u8; NAME_TAIL] {
        let mut t = [0u8; NAME_TAIL];
        let b = s.as_bytes();
        let b = &b[b.len().saturating_sub(NAME_TAIL)..];
        t[..b.len()].copy_from_slice(b);
        t
    }

    fn file() -> FileFacts {
        FileFacts {
            uid: 0,
            mode: 0o100_644,
            ctime_sec: 1_700_000_000,
            ctime_nsec: 123,
            size: 4096,
        }
    }

    fn entry(flags: u32) -> ModuleTrust {
        ModuleTrust {
            ctime_sec: 1_700_000_000,
            size: 4096,
            ctime_nsec: 123,
            flags,
        }
    }

    /// Named test (lot 285): a file outside the running kernel's tree has
    /// no entry (the agent fills the map from the tree's walk) and is
    /// refused in the deny mode, recorded in the record mode, let through
    /// in a window.
    #[test]
    fn an_untrusted_module_file_outside_the_tree_is_denied() {
        let f = file();
        assert_eq!(finit_verdict(None, &f, false, mode::DENY), verdict::DENIED);
        assert!(refuses(finit_verdict(None, &f, false, mode::DENY)));
        assert_eq!(
            finit_verdict(None, &f, false, mode::RECORD),
            verdict::RECORDED
        );
        assert!(!refuses(verdict::RECORDED));
        assert_eq!(finit_verdict(None, &f, true, mode::DENY), verdict::WINDOW);
        assert_eq!(
            finit_verdict(None, &f, false, mode::NOT_READY),
            verdict::NOT_JUDGED
        );
        // a mode the agent never writes is no deny
        assert_eq!(finit_verdict(None, &f, false, 7), verdict::RECORDED);
    }

    /// Named test (lot 285): a trusted file still described by its entry
    /// loads; changed since (its change time, its size), owned by another
    /// account, writable by its group or others, or not a regular file, it
    /// is refused outside a window.
    #[test]
    fn a_trusted_module_modified_after_boot_is_denied_outside_a_window() {
        let e = entry(trust_flag::PACKAGE);
        let f = file();
        assert_eq!(
            finit_verdict(Some(&e), &f, false, mode::DENY),
            verdict::TRUSTED
        );
        // the multigrain "queried" bit is not a change
        let queried = FileFacts {
            ctime_nsec: 123 | 0x4000_0000,
            ..f
        };
        assert_eq!(
            finit_verdict(Some(&e), &queried, false, mode::DENY),
            verdict::TRUSTED
        );
        for changed in [
            FileFacts {
                ctime_sec: f.ctime_sec + 1,
                ..f
            },
            FileFacts {
                ctime_nsec: 124,
                ..f
            },
            FileFacts { size: 4097, ..f },
            FileFacts { uid: 1000, ..f },
            FileFacts {
                mode: 0o100_664,
                ..f
            },
            FileFacts {
                mode: 0o100_646,
                ..f
            },
            FileFacts {
                mode: 0o020_644,
                ..f
            },
        ] {
            assert_eq!(
                finit_verdict(Some(&e), &changed, false, mode::DENY),
                verdict::DENIED,
                "{changed:?}"
            );
            assert_eq!(
                finit_verdict(Some(&e), &changed, true, mode::DENY),
                verdict::WINDOW,
                "{changed:?}"
            );
        }
        assert!(safe_owner(&FileFacts {
            mode: 0o100_444,
            ..f
        }));
        assert!(safe_owner(&FileFacts {
            mode: 0o100_600,
            ..f
        }));
    }

    /// Named test (lot 285): a buffer (`init_module`) is refused outside a
    /// window in the deny mode.
    #[test]
    fn init_module_from_memory_is_denied() {
        assert_eq!(init_verdict(false, mode::DENY), verdict::DENIED);
        assert_eq!(init_verdict(true, mode::DENY), verdict::WINDOW);
        assert_eq!(init_verdict(false, mode::RECORD), verdict::RECORDED);
        assert_eq!(init_verdict(true, mode::RECORD), verdict::WINDOW);
        assert_eq!(init_verdict(false, mode::NOT_READY), verdict::NOT_JUDGED);
    }

    /// Named test (lot 285): an entry the opt-out alone put in the map is
    /// let through as such (the rule records it); one something else
    /// trusts too is trusted.
    #[test]
    fn a_signed_per_module_opt_out_is_allowed_and_recorded() {
        let f = file();
        let opt = entry(trust_flag::OPT_OUT);
        assert_eq!(
            finit_verdict(Some(&opt), &f, false, mode::DENY),
            verdict::OPT_OUT
        );
        assert!(!refuses(verdict::OPT_OUT));
        let both = entry(trust_flag::OPT_OUT | trust_flag::DKMS);
        assert_eq!(
            finit_verdict(Some(&both), &f, false, mode::DENY),
            verdict::TRUSTED
        );
        // an opt-out over an unattested build: the operator's signed choice
        let over = entry(trust_flag::OPT_OUT | trust_flag::UNATTESTED);
        assert_eq!(
            finit_verdict(Some(&over), &f, false, mode::DENY),
            verdict::OPT_OUT
        );
        // an entry with no flag trusts nothing
        assert_eq!(
            finit_verdict(Some(&entry(0)), &f, false, mode::DENY),
            verdict::DENIED
        );
        // the opt-out's file changed since the agent put it in: refused
        let changed = FileFacts { size: 1, ..f };
        assert_eq!(
            finit_verdict(Some(&opt), &changed, false, mode::DENY),
            verdict::DENIED
        );
    }

    /// Named test (lot 285): the write history — created inside a package
    /// transaction and written only by it since; anything else taints, for
    /// the inode's life (a creation starts it afresh).
    #[test]
    fn a_dkms_module_under_a_package_transaction_has_a_package_history() {
        use write_flag::{PKG, TAINT};
        let h = write_step(None, true, true);
        assert_eq!(h, PKG);
        assert!(written_by_package(Some(h)));
        let h = write_step(Some(h), false, true);
        assert!(written_by_package(Some(h)));
        let h = write_step(Some(h), false, false);
        assert_eq!(h, PKG | TAINT);
        assert!(!written_by_package(Some(h)));
        assert_eq!(write_step(Some(h), false, true), PKG | TAINT);
        // created again (a new file on the inode): afresh
        assert_eq!(write_step(Some(h), true, true), PKG);
        assert_eq!(write_step(Some(PKG), true, false), TAINT);
        // no history: the creation was not seen
        assert_eq!(write_step(None, false, true), TAINT);
        assert!(!written_by_package(None));
        assert!(!written_by_package(Some(TAINT)));
    }

    /// Lot 370 (F10-2): the history names the transaction that wrote the
    /// file — one transaction's creation and writes keep it; another's
    /// write, or one by none named, leave none to vouch; a write outside a
    /// transaction taints, as before. A stopped, traced or frozen package
    /// manager vouches for nothing.
    #[test]
    fn the_write_history_names_its_one_live_transaction() {
        use write_flag::{PKG, TAINT};
        let a = Txn {
            tgid: 700,
            start: 5_000,
        };
        let b = Txn {
            tgid: 701,
            start: 6_000,
        };
        let h = history_step(None, true, Some(a));
        assert_eq!((h.flags, h.txn_tgid, h.txn_start), (PKG, 700, 5_000));
        assert_eq!(package_transaction(Some(h)), Some(a));
        let h = history_step(Some(h), false, Some(a));
        assert_eq!(package_transaction(Some(h)), Some(a));
        // another transaction's write: none vouches
        let mixed = history_step(Some(h), false, Some(b));
        assert_eq!((mixed.flags, mixed.txn_tgid), (PKG, TXN_MIXED));
        assert_eq!(package_transaction(Some(mixed)), None);
        // the same pid, another start: another transaction
        let reused = history_step(
            Some(h),
            false,
            Some(Txn {
                tgid: 700,
                start: 9,
            }),
        );
        assert_eq!(package_transaction(Some(reused)), None);
        // outside one: tainted
        let t = history_step(Some(h), false, None);
        assert_eq!(t.flags, PKG | TAINT);
        assert_eq!(package_transaction(Some(t)), None);
        // created outside, written inside: no transaction
        let t = history_step(None, true, None);
        assert_eq!(
            package_transaction(Some(history_step(Some(t), false, Some(a)))),
            None
        );
        assert_eq!(package_transaction(None), None);
        // created again: afresh
        let again = history_step(Some(mixed), true, Some(b));
        assert_eq!(package_transaction(Some(again)), Some(b));
        // the state
        assert!(state_may_vouch(0)); // running
        assert!(state_may_vouch(0x0001)); // interruptible sleep (waits for its child)
        assert!(state_may_vouch(0x0002)); // uninterruptible sleep
        for held in [0x0104, 0x0004, 0x0108, 0x0008, 0x8000, 0x8001] {
            assert!(!state_may_vouch(held), "{held:#x}");
        }
    }

    /// Lot 370 (the lab on 5.15): the eBPF program's plain-value step is
    /// the history's step — every history (none, a transaction's, another's,
    /// mixed, tainted) by every write (created or not, by none, the same
    /// transaction, another, the same pid restarted). The program called the
    /// `Option` form, whose `None` payload 5.15's verifier refused to read:
    /// no write history there.
    #[test]
    fn the_ebpf_history_step_is_the_option_step_in_plain_values() {
        use write_flag::{PKG, TAINT};
        let a = Txn {
            tgid: 700,
            start: 5_000,
        };
        let b = Txn {
            tgid: 701,
            start: 6_000,
        };
        let a_again = Txn {
            tgid: 700,
            start: 9,
        };
        let w = |flags, t: Txn| ModuleWrite {
            flags,
            txn_tgid: t.tgid,
            txn_start: t.start,
        };
        let prevs = [
            None,
            Some(w(PKG, a)),
            Some(w(PKG, b)),
            Some(w(PKG, Txn::NONE)),
            Some(w(PKG | TAINT, a)),
            Some(w(TAINT, Txn::NONE)),
            Some(ModuleWrite {
                flags: PKG,
                txn_tgid: TXN_MIXED,
                txn_start: 0,
            }),
        ];
        // the step as lot 370 first wrote it, on `Option`s: the reference
        let reference = |prev: Option<ModuleWrite>, created: bool, txn: Option<Txn>| {
            let flags = match (created, txn.is_some(), prev) {
                (true, true, _) => PKG,
                (true, false, _) | (false, _, None) => TAINT,
                (false, true, Some(p)) => p.flags,
                (false, false, Some(p)) => p.flags | TAINT,
            };
            let (txn_tgid, txn_start) = match (prev, txn) {
                (_, Some(t)) if created => (t.tgid, t.start),
                (Some(p), Some(t)) if p.txn_tgid == t.tgid && p.txn_start == t.start => {
                    (t.tgid, t.start)
                }
                (Some(_), Some(_)) => (TXN_MIXED, 0),
                (Some(p), None) => (p.txn_tgid, p.txn_start),
                (None, _) => (0, 0),
            };
            ModuleWrite {
                flags,
                txn_tgid,
                txn_start,
            }
        };
        let mut n = 0;
        for prev in prevs {
            for txn in [None, Some(a), Some(b), Some(a_again)] {
                for created in [false, true] {
                    let raw = history_step_raw(
                        prev.unwrap_or_default(),
                        prev.is_some(),
                        created,
                        txn.unwrap_or(Txn::NONE),
                    );
                    let want = reference(prev, created, txn);
                    assert_eq!(raw, want, "{prev:?} {txn:?} {created}");
                    assert_eq!(history_step(prev, created, txn), want);
                    // the flags are write_step's
                    assert_eq!(
                        raw.flags,
                        write_step(prev.map(|p| p.flags), created, txn.is_some())
                    );
                    n += 1;
                }
            }
        }
        assert_eq!(n, 56);
        // and the cases spelled out: a creation inside a names it, outside
        // nothing; no history and a write: tainted, none named
        assert_eq!(
            history_step_raw(ModuleWrite::default(), false, true, a),
            w(PKG, a)
        );
        assert_eq!(
            history_step_raw(ModuleWrite::default(), false, false, a),
            w(TAINT, Txn::NONE)
        );
        assert_eq!(
            history_step_raw(w(PKG, a), true, false, b),
            ModuleWrite {
                flags: PKG,
                txn_tgid: TXN_MIXED,
                txn_start: 0
            }
        );
    }

    /// Lot 370 (the lab): a package manager holds its lock from its write
    /// lock to its release — dpkg's two files, apt's front end released
    /// around each dpkg it runs while it keeps the other; a shared lock
    /// (rpm's queries) holds nothing; a reused pid (another start) inherits
    /// nothing. On the lab a `dpkg -i` shorter than the agent's poll was
    /// never seen holding its lock: its module file, trusted by a longer
    /// one, was refused.
    #[test]
    fn a_package_lock_is_held_from_its_write_lock_to_its_release() {
        use lock_kind::{RDLCK, UNLCK, WRLCK};
        let (front, lock) = (1u32, 2u32);
        let start = 8_812_000_000;
        let none = PkgLocker::default();
        // dpkg -i: the front end's lock, then the database's
        let e = locker_step(none, false, start, WRLCK, front);
        assert!(holds_lock(e, true, start));
        let e = locker_step(e, true, start, WRLCK, lock);
        assert_eq!(e.locks, front | lock);
        // apt releases the database's around a dpkg run, keeps its front end
        let e = locker_step(e, true, start, UNLCK, lock);
        assert!(holds_lock(e, true, start));
        let e = locker_step(e, true, start, UNLCK, front);
        assert!(!holds_lock(e, true, start), "both released");
        // a shared lock holds nothing, a downgrade releases
        let r = locker_step(none, false, start, RDLCK, lock);
        assert!(!holds_lock(r, true, start));
        let w = locker_step(none, false, start, WRLCK, lock);
        assert!(!holds_lock(
            locker_step(w, true, start, RDLCK, lock),
            true,
            start
        ));
        // another start: nothing inherited, and not this start's lock
        let reused = locker_step(w, true, start + 1, UNLCK, front);
        assert_eq!(reused.locks, 0);
        assert!(!holds_lock(w, true, start + 1));
        // no entry, or an unread start: no lock
        assert!(!holds_lock(w, false, start));
        assert!(!holds_lock(PkgLocker { start: 0, ..w }, true, 0));
        // an unknown request changes nothing
        assert_eq!(locker_step(w, true, start, 7, lock), w);
    }

    /// Named test (lot 285, the coordinator's matrix): a DKMS or akmods
    /// build the registry vouches for, written since boot outside a
    /// recognised package transaction, is let through and recorded (its
    /// own verdict, not "trusted"), in the deny mode too; changed since the
    /// agent put it in, it is refused like any untrusted file; with no
    /// entry (the policy enforces R018: the agent leaves it out) refused.
    #[test]
    fn a_registered_dkms_build_written_outside_a_transaction_is_allowed_and_recorded() {
        let f = file();
        let late = entry(trust_flag::UNATTESTED);
        assert_eq!(
            finit_verdict(Some(&late), &f, false, mode::DENY),
            verdict::UNATTESTED
        );
        assert!(!refuses(verdict::UNATTESTED));
        assert_eq!(
            finit_verdict(Some(&late), &f, false, mode::RECORD),
            verdict::UNATTESTED
        );
        assert_eq!(
            finit_verdict(Some(&late), &f, false, mode::NOT_READY),
            verdict::NOT_JUDGED
        );
        let changed = FileFacts { size: 1, ..f };
        assert_eq!(
            finit_verdict(Some(&late), &changed, false, mode::DENY),
            verdict::DENIED
        );
        assert_eq!(finit_verdict(None, &f, false, mode::DENY), verdict::DENIED);
        // a trusting flag beside it: trusted
        for t in [
            trust_flag::PACKAGE,
            trust_flag::DKMS,
            trust_flag::PKG_WRITTEN,
        ] {
            assert_eq!(
                finit_verdict(
                    Some(&entry(t | trust_flag::UNATTESTED)),
                    &f,
                    false,
                    mode::DENY
                ),
                verdict::TRUSTED,
                "{t}"
            );
        }
        assert_eq!(trust_flag::TRUSTING & trust_flag::UNATTESTED, 0);
        assert_eq!(trust_flag::TRUSTING & trust_flag::OPT_OUT, 0);
    }

    #[test]
    fn module_file_names() {
        for n in [
            "e1000.ko",
            "e1000.ko.zst",
            "nvidia-drm.ko.xz",
            "zfs.ko.gz",
            "zfs.ko.zst.dpkg-new",
            "x.ko;65a1b2c3",
            "a_module_name_longer_than_the_thirty_two_byte_window.ko.zst",
        ] {
            assert!(module_file_name(&tail(n)), "{n}");
        }
        for n in [
            "modules.dep",
            "e1000.kobj",
            "x.ko2",
            "README",
            "kotlin.k",
            ".k",
            "",
        ] {
            assert!(!module_file_name(&tail(n)), "{n}");
        }
        // `.ko` in the window's last three bytes
        let mut t = [b'a'; NAME_TAIL];
        t[NAME_TAIL - 3..].copy_from_slice(b".ko");
        assert!(module_file_name(&t));
    }

    #[test]
    fn module_names() {
        assert_eq!(
            module_name_of("nvidia-drm.ko.zst").as_deref(),
            Some("nvidia_drm")
        );
        assert_eq!(module_name_of("zfs.ko").as_deref(), Some("zfs"));
        assert_eq!(module_name_of("modules.dep"), None);
        assert_eq!(module_name_of(".ko"), None);
        assert_eq!(module_name_of("x.kobj"), None);
    }

    #[test]
    fn verdict_names_are_distinct() {
        let all = [
            verdict::NOT_JUDGED,
            verdict::TRUSTED,
            verdict::WINDOW,
            verdict::OPT_OUT,
            verdict::RECORDED,
            verdict::DENIED,
            verdict::UNATTESTED,
        ];
        let names: std::collections::BTreeSet<_> = all.iter().map(|v| verdict_name(*v)).collect();
        assert_eq!(names.len(), all.len());
    }
}

/// Lot 313 (external bug hunt, edition 1.4: BUG-111): `module_name_of`
/// stopped at the FIRST `.ko` whatever followed it, while `module_file_name`
/// recognises the same names as module files by a `.ko` at the end or
/// followed by a dot: a DKMS module named `acme.kontrol.ko` had no name, and
/// its build was never vouched for.
#[cfg(all(test, feature = "std"))]
mod bug111 {
    use super::*;

    fn tail(name: &str) -> [u8; NAME_TAIL] {
        let mut t = [0u8; NAME_TAIL];
        let b = name.as_bytes();
        let from = b.len().saturating_sub(NAME_TAIL);
        t[..b.len() - from].copy_from_slice(&b[from..]);
        t
    }

    #[test]
    fn bug111_a_module_file_with_dot_ko_in_its_name_has_a_module_name() {
        for (file, name) in [
            ("acme.kontrol.ko", "acme.kontrol"),
            ("snd.kobj-bridge.ko.zst", "snd.kobj_bridge"),
        ] {
            assert!(module_file_name(&tail(file)), "{file} is a module file");
            assert_eq!(module_name_of(file).as_deref(), Some(name), "{file}");
        }
    }

    /// Guard: a dot not followed by `ko` already gave the part before the
    /// suffix; a name that is no module file has none.
    #[test]
    fn bug111_guards() {
        assert_eq!(module_name_of("acme.bar.ko").as_deref(), Some("acme.bar"));
        assert_eq!(module_name_of("x.ko;65a1b2c3"), None);
        assert_eq!(module_name_of(".ko.zst"), None);
    }

    /// Lot 313: the stem is what precedes the suffix ending the name, the
    /// last one; a stem naming no file of its own (empty, `.`, `..`) is
    /// none, nor is a name another ending follows (a package manager's
    /// temporary name is no module to name).
    #[test]
    fn module_stem_takes_the_suffix_that_ends_the_name() {
        for (file, stem) in [
            ("e1000.ko", Some("e1000")),
            ("nvidia-drm.ko.zst", Some("nvidia-drm")),
            ("zfs.ko.xz", Some("zfs")),
            ("zfs.ko.gz", Some("zfs")),
            ("nvidia.kox-rootkit.ko", Some("nvidia.kox-rootkit")),
            ("nvidia.komodo.ko.zst", Some("nvidia.komodo")),
            ("a.ko.ko", Some("a.ko")),
            (".x.ko", Some(".x")),
            ("..ko", None),
            ("...ko", None),
            ("..ko.zst", None),
            (".ko", None),
            ("nvidia", None),
            ("x.ko.bz2", None),
            ("zfs.ko.zst.dpkg-new", None),
            ("x.ko;65a1b2c3", None),
            ("", None),
        ] {
            assert_eq!(module_stem(file), stem, "{file}");
        }
    }
}
