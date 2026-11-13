//! Tappa 10.9 step 1 — the file-open sensor on LSM `file_open`
//! (`agent-ebpf/src/open_sensor.rs`, design
//! `docs/design/TAPPA10_9_SENSOR_ATTACH_POINTS_DESIGN.md` §10).
//!
//! The kernel classifies every open and ships only the interesting ones:
//! rules keyed by inode (`OPEN_RULES`), by `(parent inode, name)` for paths
//! that do not exist yet (`CHILD_RULES`), and by name for credential stores
//! (`OPEN_NAME_RULES`); directory classes are cached per parent directory
//! (`DIR_CLASS`). Write-opens are counted per tgid in the kernel, and the
//! rewrites of existing files also per cgroup ([`write_step`],
//! [`cgroup_step`]).
//!
//! Lot 282 (Tappa Prove P0): what the counters measure is what ransomware
//! does to a user's files, not how busy a writer is. An existing file
//! rewritten in place counts once per window however often it is opened
//! (a database, a state file: [`OverwriteSeenKey`]); a file created counts
//! as created, never as a rewrite; an original destroyed — unlinked, or
//! replaced by a rename onto its name — counts once per name and window
//! ([`DestroySeenKey`]): a journal or a lock file deleted at every commit
//! is one name.

use super::{InodeKey, TASK_COMM_LEN};

/// Rule and directory-class bits. Rule values and cached directory
/// classes share one space.
pub mod open_class {
    /// The file itself: every open reports (`SENSITIVE_FILES`).
    pub const FILE_SENSITIVE: u32 = 1 << 0;
    /// The file itself: write-opens report (critical files).
    pub const FILE_CRITICAL: u32 = 1 << 1;
    /// The file itself: write-opens report (persistence files).
    pub const FILE_PERSIST: u32 = 1 << 2;
    /// Directory: write-opens anywhere below report (critical trees).
    pub const TREE_CRITICAL: u32 = 1 << 3;
    /// Directory: write-opens anywhere below report (persistence trees).
    pub const TREE_PERSIST: u32 = 1 << 4;
    /// Directory: every open of a direct child reports (telemetry probe).
    pub const CHILDREN_PROBE: u32 = 1 << 5;
    /// Directory: every file below is a credential store (`.gnupg`, …).
    pub const TREE_CRED: u32 = 1 << 6;
    /// Directory: some children are credential stores (`.aws`, …), so
    /// the leaf name is read.
    pub const LEAVES_CRED: u32 = 1 << 7;
    /// Directory: inside a home tree; the browser and KeePass names are
    /// checked on the leaf.
    pub const TREE_HOME: u32 = 1 << 8;
    /// Directory: writes below do not count toward mass write.
    pub const TREE_CARVEOUT: u32 = 1 << 9;
    /// Directory: a user's runtime directory; writes by that login uid
    /// (`DirClass::uid`) do not count toward mass write.
    pub const TREE_RUNTIME: u32 = 1 << 10;
    /// Name rule: a leaf with this name (and parent name) is a
    /// credential store.
    pub const LEAF_CRED: u32 = 1 << 11;
    /// Directory: `CHILD_RULES` hold file rules for some of its children
    /// (files missing at registration), so the leaf name is read.
    pub const CHILD_FILES: u32 = 1 << 12;
    /// Directory: some of its children have their own `OPEN_RULES` entry
    /// (a sensitive, critical or persistence file), so an open there
    /// looks the file up; elsewhere the lookup is skipped.
    pub const DIR_HAS_FILES: u32 = 1 << 13;
    /// Computed class only (never a rule): the ancestor walk stopped after
    /// `OPEN_CLASSIFY_DEPTH` levels without reaching the filesystem root,
    /// so a rule further up was not seen (external audit EBPF-011). The
    /// walk also counts it in `OPEN_DEPTH_CAPPED`, which userland reads.
    pub const DEPTH_CAPPED: u32 = 1 << 14;
    /// Lot 283c: directory under `/var/lib` or a service account's home
    /// (a system account of the account database): a file there that a
    /// non-root uid owns, in a directory that uid owns, is that account's
    /// own data ([`super::own_code`]). The writes still count; the posture
    /// reads the window's [`super::own_data`] summary.
    pub const TREE_SVC_DATA: u32 = 1 << 15;
    /// Lot 283c: a person's cache directory (`~/.cache`, the
    /// `XDG_CACHE_HOME` default); its owner is `DirClass::uid`, as a
    /// runtime directory's.
    pub const TREE_USER_CACHE: u32 = 1 << 16;
    /// Lot 283c: a data directory of the shipped list `daemon-data.v1` (or
    /// the operator's signed overlay); the directory's tag
    /// ([`UNIT_TAG_SHIFT`]) names the units it belongs to.
    pub const TREE_UNIT_DATA: u32 = 1 << 17;
    /// Lot 283c: the tag of a [`TREE_UNIT_DATA`] directory, bits 18 to 25
    /// (at most [`super::own_data::UNIT_TAGS`] directories). A tag is a
    /// directory's, so no two registered directories nest (the list
    /// refuses it): their tags would mix in the walk.
    pub const UNIT_TAG_SHIFT: u32 = 18;
    pub const UNIT_TAG_MASK: u32 = 0xFF << UNIT_TAG_SHIFT;
    /// Lot 283c: `/dev/shm`, the POSIX shared memory every account shares
    /// (sticky, root's): a file a non-root uid owns there is that
    /// account's own segment ([`super::own_code`]) — PostgreSQL's dynamic
    /// shared memory, which its backends open to write beside their data.
    pub const TREE_SHM: u32 = 1 << 26;
    /// The class bits that carry an owner in `DirClass::uid` (or, for a
    /// daemon's directory, a tag): [`super::own_code`] reads a class with
    /// exactly one of them.
    pub const OWNER_BITS: u32 = TREE_RUNTIME | TREE_USER_CACHE | TREE_UNIT_DATA;
    /// The class bits [`super::own_code`] reads: a write elsewhere is no
    /// one's own data, and its inodes are not read.
    pub const OWN_DATA_BITS: u32 = TREE_SVC_DATA | TREE_USER_CACHE | TREE_UNIT_DATA | TREE_SHM;
    /// Lot 325 (the re-check of #546, R3): computed class only (never a
    /// rule, never cached): the ancestor walk could not run — the running
    /// task's buffer could not be made (`OPEN_TASK` full) — so nothing of
    /// the directory is known; the next open there walks again. It was
    /// cached as the directory's (empty) class: `~/.aws/` lost
    /// `LEAVES_CRED` until the cache entry went.
    pub const WALK_LOST: u32 = 1 << 30;
    /// A computed `DIR_CLASS` entry (an empty class is still cached).
    pub const CLASSIFIED: u32 = 1 << 31;
    /// What a directory passes to every descendant.
    pub const SUBTREE: u32 = TREE_CRITICAL
        | TREE_PERSIST
        | TREE_CRED
        | TREE_HOME
        | TREE_CARVEOUT
        | TREE_RUNTIME
        | TREE_SVC_DATA
        | TREE_USER_CACHE
        | TREE_UNIT_DATA
        | UNIT_TAG_MASK
        | TREE_SHM;
    /// What a directory's own rule says about its direct children.
    pub const DIRECT: u32 = SUBTREE | CHILDREN_PROBE | LEAVES_CRED | CHILD_FILES | DIR_HAS_FILES;
}

/// The review of #547 (F6): the bytes of an `OPEN_TASK` entry before its
/// uid — the task's windows and names (`agent-ebpf/src/open_sensor.rs`,
/// `OpenTask`, which asserts the layout).
pub const OPEN_TASK_BUFFERS: usize = 512;

/// The review of #547 (F6): an `OPEN_TASK` entry as the agent reads it to
/// recount each uid's share of the map (`OPEN_TASK_UIDS`): only `uid` is
/// read.
#[repr(C)]
#[derive(Copy, Clone)]
#[cfg_attr(feature = "std", derive(bytemuck::Pod, bytemuck::Zeroable))]
pub struct OpenTaskRaw {
    pub buffers: [u8; OPEN_TASK_BUFFERS],
    pub uid: u32,
    pub _pad: u32,
}

/// Lot 325 (R3): whether a computed directory class may go into the
/// cache (`DIR_CLASS`): not one whose walk could not run.
#[inline(always)]
pub const fn dir_class_cacheable(bits: u32) -> bool {
    bits & open_class::WALK_LOST == 0
}

/// Why a record was emitted (`OpenRecordRaw::reason`, any combination).
pub mod open_reason {
    pub const SENSITIVE: u32 = 1 << 0;
    pub const CRITICAL: u32 = 1 << 1;
    pub const PERSIST: u32 = 1 << 2;
    pub const PROBE: u32 = 1 << 3;
    pub const CRED: u32 = 1 << 4;
    /// Lot 282: the tgid's distinct files written NEW crossed the
    /// mass-write threshold in the window — an extraction, a clone, a
    /// build, a cache filled, the copies of an encryptor. `count` carries
    /// them. (It was every write-open, the same file's included.) The
    /// review of #500 (B1): a file written new is any file whose first
    /// write-open of the window is no rewrite ([`super::WriteKind::New`]):
    /// created by the open (`FMODE_CREATED`), or empty when opened — made
    /// by `mknod`, an `O_TMPFILE` linked in, an `O_RDONLY | O_CREAT` open
    /// reopened to write. `FMODE_CREATED` alone was evaded by all three.
    pub const MASS_WRITE: u32 = 1 << 5;
    /// Review 86: a file capability was set (`security.capability`). The
    /// record's `count` carries the permitted set's low 32 bits, `flags`
    /// the high 32, and `mode` the xattr's `magic_etc` (revision in the
    /// top byte, the effective flag in bit 0).
    pub const FILE_CAP: u32 = 1 << 6;
    /// External audit POS-002: the tgid's write-opens of files that
    /// existed before the open (no `FMODE_CREATED`: rewritten, not
    /// created), of at least [`super::OVERWRITE_MIN_BYTES`] (lab PR 127),
    /// crossed the mass-write threshold in the window. Lot 282: each file
    /// once per window ([`super::OverwriteSeenKey`]: a database rewritten
    /// 259 times is one file), and `count` carries those distinct files (it
    /// carried every write-open).
    pub const MASS_OVERWRITE: u32 = 1 << 7;
    /// External audit EBPF-011: the overwrites of one cgroup's processes,
    /// each below its own threshold, crossed [`super::OPEN_CG_OVERWRITE_MIN`]
    /// in the window (a writer forking a fresh worker every few files).
    /// `count` carries the cgroup's overwrites.
    pub const MASS_OVERWRITE_CGROUP: u32 = 1 << 8;
    /// Lab PR 225: a tgid's renames of regular files to one new extension
    /// — appended to the whole old name (`a.pdf` → `a.pdf.locked`) or in
    /// place of the old one (`a.pdf` → `a.locked`) — crossed
    /// [`super::OPEN_RENAME_EXT_MIN`] in the window ([`super::rename_step`]).
    /// `count` carries the renames of the streak, `flags` those that
    /// appended, `mode` how often the old extension changed from one
    /// counted rename to the next (originals of different kinds). The path
    /// is the file's new name. Seen on `inode_rename` (regular files, LSM file-open sensor armed).
    pub const MASS_RENAME: u32 = 1 << 9;
    /// Lab PR 225: a tgid's unlinks of regular files crossed
    /// [`super::OPEN_UNLINK_MIN`] in the window ([`super::unlink_step`]).
    /// `count` carries them; the path is the unlinked file's. Seen on
    /// `inode_unlink` (LSM file-open sensor armed). Lot 282: originals
    /// destroyed — an unlink, or a rename onto the name of an existing
    /// regular file (seen on `inode_rename`), which destroys it as surely —
    /// each name once per window ([`super::DestroySeenKey`]), never a file
    /// the process itself created within the window
    /// ([`super::created_in_window`]: its own temporary file); the path is
    /// the destroyed file's. The review of #500 (C1): any file that held
    /// data ([`super::destroys_an_original`]) — it was one of 4 KiB or more
    /// — or one emptied within the window (a `truncate` then an `unlink`).
    pub const MASS_UNLINK: u32 = 1 << 10;
    /// Lab PR 225 (CM-18): a signal that stops or ends a process, sent to
    /// the main process of another security tool (`DEFENDER_PIDS`, filled
    /// by the agent from `security-tools.v1`) by anyone but PID 1, the tool
    /// itself or the agent. Seen on `task_kill`, never refused. `count`
    /// carries the signal, `flags` the target's tgid; no path.
    pub const DEFENDER_SIGNAL: u32 = 1 << 11;
    /// Lot 282, the review of #500 (C1): the tgid's distinct existing
    /// NON-EMPTY files rewritten — those under
    /// [`super::OVERWRITE_MIN_BYTES`] included — crossed the mass-write
    /// threshold in the window before the files of that size alone did
    /// ([`MASS_OVERWRITE`], which a crossing of both reports alone).
    /// `count` carries them. Encryption in place of small documents; the
    /// posture counts it outside an authenticated session only — inside
    /// one, as before, only files of 4 KiB or more count (a build rewrites
    /// its own small outputs: lab PR 127, cargo killed).
    pub const MASS_OVERWRITE_SMALL: u32 = 1 << 12;
    /// Lot 283c: the [`super::own_data`] summary of the crossing's window
    /// rides in the reason's top byte from the counter to the record
    /// (`OpenRecordRaw::own`); no reason bit lies there.
    pub const OWN_SHIFT: u32 = 24;
    /// The reason bits proper, below [`OWN_SHIFT`].
    pub const REASON_BITS: u32 = (1 << OWN_SHIFT) - 1;
}

/// Lot 283c: whose own data every file a window counted was
/// ([`own_code`], [`own_after`]): the summary of a crossing
/// (`OpenRecordRaw::own`, `MassWrite`'s and `FileBurst`'s `own_data`). The
/// counts are the same whatever it says — the ransomware tracker reads
/// every crossing — and the posture's mass-write arm leaves a crossing out
/// only when it says the writer's own data and the writer is who the
/// summary needs (its unit, its account).
pub mod own_data {
    /// Some file of the window was no one's own data (or there was none).
    pub const NONE: u8 = 0;
    /// Every file lay under `/var/lib` or a service account's home, in a
    /// directory the writer's uid owns, or in `/dev/shm` (its POSIX shared
    /// memory), owned by it (not root).
    pub const SERVICE: u8 = 1;
    /// Every file lay in the writer's person's `~/.cache`, owned by it.
    pub const CACHE: u8 = 2;
    /// Every file lay in one listed daemon directory: `UNIT_BASE + tag`.
    pub const UNIT_BASE: u8 = 3;
    /// Tags of daemon directories: `0..UNIT_TAGS` (a byte, less the codes
    /// above).
    pub const UNIT_TAGS: u32 = 256 - UNIT_BASE as u32;
    // every code fits the record's byte
    const _: () = assert!(UNIT_BASE as u32 + UNIT_TAGS == 256);
}

/// Names in the rule maps: NUL-padded, at most 31 bytes kept.
pub const OPEN_NAME_LEN: usize = 32;
/// Path components carried leaf → root, each in a fixed 32-byte slot.
pub const OPEN_PATH_SLOTS: usize = 16;
pub const OPEN_PATH_SLOT_LEN: usize = 32;
/// Ancestors walked when a directory is classified (external audit
/// EBPF-011: 8 left deep credential trees such as `.password-store`
/// unclassified). Inside the global function `nn_open_walk`, verified on
/// its own.
pub const OPEN_CLASSIFY_DEPTH: usize = 16;
/// Mass write: write-opens per tgid within the window (the posture arm's
/// values).
pub const OPEN_MASS_WRITE_MIN: u32 = 20;
pub const OPEN_MASS_WRITE_WINDOW_NS: u64 = 60 * 1_000_000_000;
/// External audit EBPF-011: the cgroup window. Overwrites (the per-tgid
/// discriminant: an existing file of at least 4 KiB) of the processes of
/// one cgroup within the window. Twice the per-process threshold.
pub const OPEN_CG_OVERWRITE_MIN: u32 = 40;
/// A process's overwrites enter its cgroup's window from its third in its
/// own window on (the first two then count too). A build runs one process
/// per output — a compiler's `.d` file, a shell redirect to a `.cmd`
/// file, CMake's `cmake_depends` (two files) — and those never count;
/// a worker that rewrites three files or more does.
pub const OPEN_CG_PROC_MIN: u32 = 3;
const _: () = assert!(OPEN_CG_PROC_MIN >= 2 && OPEN_CG_PROC_MIN < OPEN_CG_OVERWRITE_MIN);
/// Lab PR 225: renames of one streak (one new extension) per tgid within
/// [`OPEN_BURST_WINDOW_NS`] that report [`open_reason::MASS_RENAME`]: the
/// mass-write threshold's value.
pub const OPEN_RENAME_EXT_MIN: u32 = 20;
/// Lab PR 225: unlinks per tgid within [`OPEN_BURST_WINDOW_NS`] that report
/// [`open_reason::MASS_UNLINK`].
pub const OPEN_UNLINK_MIN: u32 = 20;
/// Lab PR 225: the window of the rename and unlink counts, the mass-write
/// window.
pub const OPEN_BURST_WINDOW_NS: u64 = OPEN_MASS_WRITE_WINDOW_NS;
/// An overwrite of [`open_reason::MASS_OVERWRITE`] counts for an existing
/// file of at least this size, read at open (before `O_TRUNC` empties it).
/// A build rewrites its own small outputs — a full workspace rebuild in
/// the lab (lab PR 127): up to 17 overwrites per cargo process in all, at
/// most 4 of 4 KiB or more — and a cargo build, counted as ransomware, was
/// killed and cargo and rustc quarantined. Lot 282 (the review of #500,
/// C1): the smaller non-empty files count apart
/// ([`open_reason::MASS_OVERWRITE_SMALL`]); an unlink counts for any file
/// that held data (it counted from this size: lab PR 225).
pub const OVERWRITE_MIN_BYTES: u64 = 4096;
/// Lab PR 225: bytes of a name's end read for its extension. A longer
/// extension is no extension to the counter.
pub const NAME_TAIL_LEN: usize = 16;
/// Lab PR 225: bytes of a name's start kept (NUL-padded), as in the rule
/// maps.
pub const NAME_HEAD_LEN: usize = 32;
/// Rule map capacities (external audit SNS-007): one inode rule per
/// posture path, home and `/run/user/<uid>` directory; one runtime owner
/// per runtime directory; child rules for posture paths missing at
/// registration.
pub const OPEN_RULES_MAX: u32 = 4096;
pub const CHILD_RULES_MAX: u32 = 1024;
pub const OPEN_NAME_RULES_MAX: u32 = 64;
pub const RUNTIME_UIDS_MAX: u32 = 4096;
/// `OPEN_SENSOR[0]` once userland armed the sensor (LSM mode).
pub const OPEN_SENSOR_ARMED: u32 = 1;

/// `CHILD_RULES` key: a registered directory and a child name.
#[repr(C)]
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "std", derive(bytemuck::Pod, bytemuck::Zeroable))]
pub struct ChildRuleKey {
    pub parent: InodeKey,
    pub name: [u8; OPEN_NAME_LEN],
}

/// Cached class of a directory (`DIR_CLASS` value).
#[repr(C)]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
#[cfg_attr(feature = "std", derive(bytemuck::Pod, bytemuck::Zeroable))]
pub struct DirClass {
    pub bits: u32,
    /// Owner of a runtime directory (`TREE_RUNTIME`) or, lot 283c, of a
    /// person's cache directory (`TREE_USER_CACHE`).
    pub uid: u32,
    /// `DIR_CLASS_GEN[0]` when computed; any other value is stale.
    pub gen: u32,
    pub _pad: u32,
}

/// Per-tgid write-open window of the mass-write counter.
#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
#[cfg_attr(feature = "std", derive(bytemuck::Pod, bytemuck::Zeroable))]
pub struct OpenWriteWindow {
    pub start_ns: u64,
    /// Every counted write-open of the window.
    pub count: u32,
    /// [`open_reason::MASS_WRITE`] / [`open_reason::MASS_OVERWRITE`] once
    /// each was reported in this window.
    pub fired: u32,
    /// External audit POS-002: the write-opens of files that existed, of
    /// at least [`OVERWRITE_MIN_BYTES`]. Lot 282: each file once per window
    /// (the eBPF counter's [`OverwriteSeenKey`] map tells a file's first
    /// write-open of the window from a repeat, which is a plain
    /// write-open).
    pub overwrites: u32,
    /// Lot 282: the files written new ([`WriteKind::New`]), each once per
    /// window.
    pub created: u32,
    /// Lot 282, the review of #500 (C1): the existing non-empty files
    /// under [`OVERWRITE_MIN_BYTES`] rewritten ([`WriteKind::SmallRewrite`]),
    /// each once per window.
    pub small: u32,
    /// Lot 283c: the window's [`own_data`] summary ([`own_after`]), set by
    /// the counter after each [`write_step`].
    pub own: u32,
}

/// Lot 282: what one write-open of a regular file adds to its tgid's
/// window ([`write_kind`]).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum WriteKind {
    /// A file already counted in this window: a plain write-open.
    Repeat,
    /// An existing file of at least [`OVERWRITE_MIN_BYTES`] rewritten.
    Rewrite,
    /// An existing non-empty file under [`OVERWRITE_MIN_BYTES`] rewritten.
    SmallRewrite,
    /// A file written new: created by the open, or empty when opened.
    New,
}

/// Lot 282 (the review of #500, B1 and C1): the kind of one write-open of
/// a regular file — `created` by the open (`FMODE_CREATED`), `data`: it
/// held data when opened (its size, read before `O_TRUNC` empties it, not
/// zero), `big`: at least [`OVERWRITE_MIN_BYTES`] — whose `first`
/// write-open of the window this is ([`first_in_window`] on the seen map).
/// Each file counts once per window: a rewrite when the open found data in
/// it, else a file written new — created by the open, or by `mknod`, an
/// `O_TMPFILE` linked in, an `O_RDONLY | O_CREAT` open reopened to write:
/// whatever made it, it held nothing of the user's. (`FMODE_CREATED` alone
/// decided, and all three evaded it.)
#[inline(always)]
pub fn write_kind(created: bool, data: bool, big: bool, first: bool) -> WriteKind {
    if !first {
        WriteKind::Repeat
    } else if created || !data {
        WriteKind::New
    } else if big {
        WriteKind::Rewrite
    } else {
        WriteKind::SmallRewrite
    }
}

impl OpenWriteWindow {
    /// The window a tgid's first counted write-open, of `kind`, starts.
    #[inline(always)]
    pub fn fresh(now: u64, kind: WriteKind) -> Self {
        OpenWriteWindow {
            start_ns: now,
            count: 1,
            fired: 0,
            overwrites: (kind == WriteKind::Rewrite) as u32,
            created: (kind == WriteKind::New) as u32,
            small: (kind == WriteKind::SmallRewrite) as u32,
            own: 0,
        }
    }

    /// Lot 282: the start of the window a write-open at `now` counts in —
    /// this one's, or `now` when this one has ended (the next
    /// [`write_step`] starts a fresh window at `now`). The key a file's
    /// first rewrite of the window is remembered under
    /// ([`OverwriteSeenKey`]).
    #[inline(always)]
    pub fn start_for(&self, now: u64) -> u64 {
        if now.saturating_sub(self.start_ns) > OPEN_MASS_WRITE_WINDOW_NS {
            now
        } else {
            self.start_ns
        }
    }
}

/// `OpenWriteWindow::fired` bits: the threshold already reported.
pub const FIRED_WRITES: u32 = 1;
pub const FIRED_OVERWRITES: u32 = 2;
/// Lot 282 (the review of #500, C1): [`open_reason::MASS_OVERWRITE_SMALL`].
pub const FIRED_SMALL: u32 = 4;

/// One more write-open, of `kind` ([`write_kind`]), in a tgid's window `w`
/// at `now`. Returns the [`open_reason`] bits it adds — `MASS_OVERWRITE`
/// when the distinct files of at least [`OVERWRITE_MIN_BYTES`] rewritten
/// reach the threshold, `MASS_OVERWRITE_SMALL` when the distinct non-empty
/// files rewritten (the smaller included) reach it first, `MASS_WRITE`
/// when the files written new do, each once per window (lot 282) — the
/// count the record carries when it adds any (the files rewritten for an
/// overwrite crossing, else the files written new), and the overwrites it
/// adds to the cgroup window (external audit EBPF-011): 0 until the
/// process has rewritten [`OPEN_CG_PROC_MIN`] distinct files of at least
/// [`OVERWRITE_MIN_BYTES`] in its window, then all of them at once and one
/// per further file after, and 0 again once its own threshold reported it.
#[inline(always)]
pub fn write_step(w: &mut OpenWriteWindow, kind: WriteKind, now: u64) -> (u32, u32, u32) {
    if now.saturating_sub(w.start_ns) > OPEN_MASS_WRITE_WINDOW_NS {
        *w = OpenWriteWindow::fresh(now, kind);
        return (0, 0, 0);
    }
    let over = (kind == WriteKind::Rewrite) as u32;
    w.count += 1;
    w.overwrites += over;
    w.created += (kind == WriteKind::New) as u32;
    w.small += (kind == WriteKind::SmallRewrite) as u32;
    let mut bits = 0u32;
    if w.created >= OPEN_MASS_WRITE_MIN && w.fired & FIRED_WRITES == 0 {
        w.fired |= FIRED_WRITES;
        bits |= open_reason::MASS_WRITE;
    }
    if w.overwrites >= OPEN_MASS_WRITE_MIN && w.fired & FIRED_OVERWRITES == 0 {
        w.fired |= FIRED_OVERWRITES;
        bits |= open_reason::MASS_OVERWRITE;
    }
    // Reached together with the files of 4 KiB or more, the crossing is
    // theirs alone (it counts inside a session too).
    if w.overwrites + w.small >= OPEN_MASS_WRITE_MIN && w.fired & FIRED_SMALL == 0 {
        w.fired |= FIRED_SMALL;
        if bits & open_reason::MASS_OVERWRITE == 0 {
            bits |= open_reason::MASS_OVERWRITE_SMALL;
        }
    }
    let cg = if over == 0 || w.fired & FIRED_OVERWRITES != 0 || w.overwrites < OPEN_CG_PROC_MIN {
        0
    } else if w.overwrites == OPEN_CG_PROC_MIN {
        OPEN_CG_PROC_MIN
    } else {
        1
    };
    let count = if bits & open_reason::MASS_OVERWRITE != 0 {
        w.overwrites
    } else if bits & open_reason::MASS_OVERWRITE_SMALL != 0 {
        w.overwrites + w.small
    } else if bits != 0 {
        w.created
    } else {
        0
    };
    (bits, count, cg)
}

/// Lot 282: `OPEN_OVERWRITE_SEEN` key — a file a tgid rewrote in its
/// current window. The value is that window's start
/// ([`OpenWriteWindow::start_for`]): equal, the open repeats a file already
/// counted; anything else (absent, an older window's start), it is the
/// file's first rewrite of the window. An entry the LRU map evicted counts
/// the file again — more, never fewer.
#[repr(C)]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "std", derive(bytemuck::Pod, bytemuck::Zeroable))]
pub struct OverwriteSeenKey {
    pub tgid: u32,
    pub _pad: u32,
    pub dev: u64,
    pub ino: u64,
}

/// Lot 282: `OPEN_DESTROY_SEEN` key — an original a tgid destroyed in its
/// current unlink window, by name: the parent dentry (its address: the
/// directory, for as long as it has children) and the name's `hash_len`
/// (the dcache's hash, salted with that parent, and the length). A name
/// unlinked again and again (a journal deleted at every commit, a lock file)
/// is one original; the value is the window's start, as for
/// [`OverwriteSeenKey`].
#[repr(C)]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "std", derive(bytemuck::Pod, bytemuck::Zeroable))]
pub struct DestroySeenKey {
    pub tgid: u32,
    pub _pad: u32,
    pub parent: u64,
    pub hash_len: u64,
}

/// Lot 282: whether a file (or a name) is counted now — `seen` is what the
/// seen map holds for it (`None` when absent), `start` the start of the
/// window the event counts in. A file counts the first time in a window.
#[inline(always)]
pub fn first_in_window(seen: Option<u64>, start: u64) -> bool {
    seen != Some(start)
}

/// Lot 282, the re-review of #500 (cost): whether a write-open is its
/// file's first of the window — always when the open `created` the file
/// (a new inode: the eBPF counter skips the seen map's lookup, and an
/// entry left by a freed inode number cannot make it a repeat), else
/// [`first_in_window`] on what `seen` (the lookup) returned.
#[inline(always)]
pub fn first_write(created: bool, seen: impl FnOnce() -> Option<u64>, start: u64) -> bool {
    created || first_in_window(seen(), start)
}

/// Lot 282, the re-review of #500: whether a directory of class `bits`
/// (its runtime owner `owner`) is one whose writes — and, since then,
/// destructions — the mass-write counts leave out: a carve-out
/// (`TREE_CARVEOUT`: a pseudo-filesystem, `/run/systemd`, the journal, the
/// operator's extras) or the caller's own runtime directory (`TREE_RUNTIME`
/// owned by its login uid, `loginuid`, read only for such a directory).
#[inline(always)]
pub fn carved_class(bits: u32, owner: u32, loginuid: impl FnOnce() -> u32) -> bool {
    bits & open_class::TREE_CARVEOUT != 0
        || (bits & open_class::TREE_RUNTIME != 0 && loginuid() == owner)
}

/// Lot 283c: whose own data one counted write (or destroyed original)
/// is, from its directory's class `bits` and owner `owner`
/// (`DirClass::uid`), the writer's uid `uid`, the owners of the file's
/// directory and of the file (`dir_uid`, `file_uid`) and the file's links
/// `nlink` — an [`own_data`] code:
///
/// - a listed daemon's directory (`TREE_UNIT_DATA`, its tag): the code of
///   the tag, whoever writes (the posture checks the writer's unit);
/// - a person's `~/.cache` (`TREE_USER_CACHE`): `CACHE` when the writer is
///   its owner and owns the file and its directory;
/// - under `/var/lib` or a service account's home (`TREE_SVC_DATA`):
///   `SERVICE` when a uid other than root owns the file and its directory
///   and writes it (the posture checks the account is a service's);
/// - in `/dev/shm` (`TREE_SHM`, a directory every account shares):
///   `SERVICE` when a uid other than root owns the file and writes it — its
///   own shared memory segment, as a service's data (lot 283c's lab:
///   PostgreSQL's backends open their dynamic shared memory to write).
///
/// A file with another link is no one's: a hard link puts any file the
/// writer may link into its own directory. A class with two owner-bearing
/// bits (nested registrations) is no one's either.
#[inline(always)]
pub fn own_code(bits: u32, owner: u32, uid: u32, dir_uid: u32, file_uid: u32, nlink: u32) -> u32 {
    use open_class::*;
    if nlink != 1 {
        return own_data::NONE as u32;
    }
    let owners = bits & OWNER_BITS;
    if owners == TREE_UNIT_DATA {
        let tag = (bits & UNIT_TAG_MASK) >> UNIT_TAG_SHIFT;
        return if tag < own_data::UNIT_TAGS {
            own_data::UNIT_BASE as u32 + tag
        } else {
            own_data::NONE as u32
        };
    }
    let owned = uid != 0 && dir_uid == uid && file_uid == uid;
    if owners == TREE_USER_CACHE {
        return if owned && owner == uid {
            own_data::CACHE as u32
        } else {
            own_data::NONE as u32
        };
    }
    let shm = uid != 0 && file_uid == uid && bits & TREE_SHM != 0;
    if owners == 0 && (bits & TREE_SVC_DATA != 0 && owned || shm) {
        own_data::SERVICE as u32
    } else {
        own_data::NONE as u32
    }
}

/// Lot 283c: a window's [`own_data`] summary after one more event of code
/// `code` — the event's own when the window starts with it (`fresh`), the
/// summary kept when the event counts nothing new (`counted` false: a file
/// already counted in the window), else the summary when the codes agree
/// and `NONE` from the first that does not, for the rest of the window.
#[inline(always)]
pub fn own_after(summary: u32, fresh: bool, counted: bool, code: u32) -> u32 {
    if fresh {
        code
    } else if !counted || summary == code {
        summary
    } else {
        own_data::NONE as u32
    }
}

/// `ATTR_SIZE` (include/linux/fs.h, `1 << 3` in every kernel): an
/// `inode_setattr` that changes the file's size.
pub const ATTR_SIZE: u32 = 1 << 3;

/// Lot 282, the re-review of #500 (cost): whether an `inode_setattr` whose
/// `iattr.ia_valid` is `ia_valid` marks its file in `OPEN_HAD_DATA` — a
/// size change only (`truncate`, `ftruncate`, an `O_TRUNC` open), not a
/// chmod, a chown or a `touch`.
#[inline(always)]
pub fn marks_had_data(ia_valid: u32) -> bool {
    ia_valid & ATTR_SIZE != 0
}

/// Lot 282 (the lab's first run of the lot: `pip install` and `npm install`
/// unpack into temporary files and delete them): a file a process destroys
/// is no original of the user's when that same process created it within a
/// burst window — `created` is when the eBPF counter's `OPEN_CREATED` map
/// (keyed by [`OverwriteSeenKey`]: tgid, device, inode) saw it created,
/// `None` when it did not.
#[inline(always)]
pub fn created_in_window(created: Option<u64>, now: u64) -> bool {
    created.is_some_and(|t| now.saturating_sub(t) <= OPEN_BURST_WINDOW_NS)
}

/// Lot 282, the review of #500 (C1): whether an unlink (or a rename onto
/// its name) of a regular file of `size` bytes destroys an original — the
/// file holds data, or it held data within a burst window before (`had`:
/// when the eBPF counter's `OPEN_HAD_DATA` map last saw it non-empty at an
/// `inode_setattr`, `None` when it did not). A file emptied by a
/// `truncate` — whose own `inode_setattr` runs before it empties the file
/// — and then unlinked is one original destroyed; an empty file never
/// written is none. (A file of 4 KiB or more counted; a smaller one, or one
/// truncated first, did not.)
#[inline(always)]
pub fn destroys_an_original(size: u64, had: Option<u64>, now: u64) -> bool {
    size != 0 || had.is_some_and(|t| now.saturating_sub(t) <= OPEN_BURST_WINDOW_NS)
}

/// `OPEN_CG_WRITES` key: a cgroup (v2 id), or, where the writer sits in
/// the root cgroup (no cgroup v2 hierarchy in use), its uid and login uid.
#[repr(C)]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "std", derive(bytemuck::Pod, bytemuck::Zeroable))]
pub struct OpenCgKey {
    pub cgroup: u64,
    pub uid: u32,
    pub loginuid: u32,
}

/// Per-cgroup overwrite window (external audit EBPF-011).
#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
#[cfg_attr(feature = "std", derive(bytemuck::Pod, bytemuck::Zeroable))]
pub struct OpenCgWindow {
    pub start_ns: u64,
    pub overwrites: u32,
    /// 1 once the crossing was reported in this window.
    pub fired: u32,
    /// Lot 283c: the window's [`own_data`] summary: each process's own
    /// window summary as it adds its overwrites ([`own_after`]).
    pub own: u32,
    pub _pad: u32,
}

/// `add` overwrites ([`write_step`]'s third value) into a cgroup's window
/// `w` at `now`. Returns the window's overwrites when they cross
/// [`OPEN_CG_OVERWRITE_MIN`] (once per window), 0 otherwise.
#[inline(always)]
pub fn cgroup_step(w: &mut OpenCgWindow, add: u32, now: u64) -> u32 {
    if now.saturating_sub(w.start_ns) > OPEN_MASS_WRITE_WINDOW_NS {
        w.start_ns = now;
        w.overwrites = 0;
        w.fired = 0;
    }
    w.overwrites += add;
    if w.overwrites >= OPEN_CG_OVERWRITE_MIN && w.fired == 0 {
        w.fired = 1;
        return w.overwrites;
    }
    0
}

/// One interesting open. 8-aligned, no implicit padding:
/// 8·8 + 4·9 + 16 + 2 + 1 + 1 + 512 = 632 (lot 340: 608 before the fork
/// records).
#[repr(C)]
#[derive(Copy, Clone, Debug)]
#[cfg_attr(feature = "std", derive(bytemuck::Pod, bytemuck::Zeroable))]
pub struct OpenRecordRaw {
    pub timestamp_ns: u64,
    /// The opened file, `(dev, ino)` as `stat()` reports it.
    pub dev: u64,
    pub ino: u64,
    /// The top of the path walk (a filesystem root): userland maps it to
    /// a mount point to make the path absolute.
    pub root_dev: u64,
    pub root_ino: u64,
    /// Lot 282 (the review of #500, C1): the writer's cgroup v2 id
    /// (`bpf_get_current_cgroup_id`; 1, the root, where no hierarchy is in
    /// use). The posture pairs the two halves of a replacement — files
    /// written new, originals destroyed — within one cgroup as well as one
    /// process: an encryptor and a separate deleter.
    pub cgroup: u64,
    /// Lot 340: the writer's start (`task_struct.start_time` of its thread
    /// group's leader, `CLOCK_MONOTONIC` ns) when [`Self::fork_ppid`] is
    /// set; 0 otherwise.
    pub fork_start: u64,
    /// Lot 340: the forker's start when [`Self::fork_pppid`] is set (its
    /// own unexecuted fork record); 0 otherwise.
    pub fork_parent_start: u64,
    pub pid: u32,
    pub uid: u32,
    pub gid: u32,
    /// `file->f_flags` (`O_*`; the kernel clears `O_CREAT`/`O_TRUNC`).
    pub flags: u32,
    /// `file->f_mode` (`FMODE_READ` = 1, `FMODE_WRITE` = 2).
    pub mode: u32,
    /// [`open_reason`] bits.
    pub reason: u32,
    /// Write-opens in the window when `reason` has `MASS_WRITE` or
    /// `MASS_OVERWRITE`.
    pub count: u32,
    /// Lot 340: the thread group that forked the writer, from the kernel's
    /// fork record (`agent-ebpf/src/fork_parent.rs`, lot 310), when the
    /// writer has executed nothing since that fork — a backup's receiver
    /// (`rsync`'s fork), a worker; its exec record names no lineage for it.
    /// 0: not known, or the writer executed since (its exec record names
    /// its fork parent).
    pub fork_ppid: u32,
    /// Lot 340: the thread group that forked the forker, when the forker
    /// too has executed nothing since its fork (rsync's receiver is a fork
    /// of its generator, a fork of rsync); 0: not known, or it executed.
    pub fork_pppid: u32,
    pub comm: [u8; TASK_COMM_LEN],
    pub path_n: u16,
    pub path_truncated: u8,
    /// Lot 283c: the [`own_data`] summary of a mass-write or unlink
    /// crossing's window; `NONE` for any other record.
    pub own: u8,
    pub path: [u8; OPEN_PATH_SLOTS * OPEN_PATH_SLOT_LEN],
}

/// Lab PR 225: a leaf name as the rename counter reads it from a dentry:
/// its first [`NAME_HEAD_LEN`] − 1 bytes (NUL-padded), its last
/// `tail_len` bytes (at most [`NAME_TAIL_LEN`]) and its length.
#[repr(C)]
#[derive(Copy, Clone, Debug)]
#[cfg_attr(feature = "std", derive(bytemuck::Pod, bytemuck::Zeroable))]
pub struct NameParts {
    pub head: [u8; NAME_HEAD_LEN],
    pub tail: [u8; NAME_TAIL_LEN],
    pub len: u32,
    pub tail_len: u32,
}

/// Lab PR 225: both names of a rename, the per-CPU scratch of the counter.
#[repr(C)]
#[derive(Copy, Clone, Debug)]
#[cfg_attr(feature = "std", derive(bytemuck::Pod, bytemuck::Zeroable))]
pub struct RenameNames {
    pub old: NameParts,
    pub new: NameParts,
}

/// Lab PR 225: FNV-1a 64 offset basis and prime.
const FNV_BASIS: u64 = 0xcbf2_9ce4_8422_2325;
const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;

/// Lab PR 225: a name's extension — the bytes after its last dot — as a
/// hash and a length, `(0, 0)` when it has none: no dot in the tail (or an
/// extension longer than [`NAME_TAIL_LEN`] − 1), a dot that ends it, the
/// leading dot of a hidden name with no other (`.bashrc`), or digits only
/// (`syslog.1`, a rotation). Every loop has a constant bound and every
/// index is below it: shared with the eBPF program (5.15 rule 5).
#[inline(always)]
pub fn name_ext(n: &NameParts) -> (u64, u32) {
    let tail_len = if n.tail_len > NAME_TAIL_LEN as u32 {
        NAME_TAIL_LEN as u32
    } else {
        n.tail_len
    };
    let mut dot = NAME_TAIL_LEN as u32;
    let mut i = 0;
    while i < NAME_TAIL_LEN {
        if (i as u32) < tail_len && n.tail[i] == b'.' {
            dot = i as u32;
        }
        i += 1;
    }
    if dot >= tail_len || dot + 1 == tail_len {
        return (0, 0);
    }
    // The tail is the whole name: a dot at its start is a hidden name's.
    if dot == 0 && n.len <= NAME_TAIL_LEN as u32 {
        return (0, 0);
    }
    let mut h = FNV_BASIS;
    let mut digits = true;
    let mut j = 0;
    while j < NAME_TAIL_LEN {
        let jj = j as u32;
        if jj > dot && jj < tail_len {
            let b = n.tail[j];
            if !b.is_ascii_digit() {
                digits = false;
            }
            h ^= b as u64;
            h = h.wrapping_mul(FNV_PRIME);
        }
        j += 1;
    }
    if digits || h == 0 {
        return (0, 0);
    }
    (h, tail_len - dot - 1)
}

/// Lab PR 225: the first `n` bytes (at most [`NAME_HEAD_LEN`] − 1) of two
/// heads agree.
#[inline(always)]
fn heads_agree(a: &[u8; NAME_HEAD_LEN], b: &[u8; NAME_HEAD_LEN], n: u32) -> bool {
    let mut same = true;
    let mut i = 0;
    while i < NAME_HEAD_LEN - 1 {
        if (i as u32) < n && a[i] != b[i] {
            same = false;
        }
        i += 1;
    }
    same
}

/// [`rename_shape`]: the rename is not counted.
pub const RENAME_OTHER: u32 = 0;
/// [`rename_shape`]: the new extension replaces the old one (`a.pdf` →
/// `a.locked`).
pub const RENAME_REPLACED: u32 = 1;
/// [`rename_shape`]: the new extension is appended to the whole old name
/// (`a.pdf` → `a.pdf.locked`, `README` → `README.locked`).
pub const RENAME_APPENDED: u32 = 2;

/// Lab PR 225: what a rename of a regular file is to the burst counter.
/// Counted: the old name with an extension appended, or with its own
/// extension replaced by another; never a rotation's digits. Not counted,
/// by construction: a temporary file renamed to its final name when the
/// temporary appends to it or has a name of its own (`x.py.dpkg-new` →
/// `x.py`, rsync's `.x.c.AbC123` → `x.c`, `sed -i`'s `sedAbc12` → `x.conf`,
/// the interpreter's `x.pyc.140234` → `x.pyc`), a move to another directory
/// under the same name, a random new name. Counted, though (external bug
/// hunt BUG54): an atomic save whose temporary carries its own extension
/// in place of the final one (`data.tmp` → `data.json`, `a.part` → `a.iso`)
/// — the very shape of an encryptor staging its ciphertext (`a.pdf.tmp` →
/// `a.pdf.locked`), which an exception for the old extension would let
/// through; a burst of such saves is not an encryptor's shape to the
/// ransomware tracker (nothing appended, one origin extension, the new one
/// not a marker) and gives no verdict on its own. Names longer than
/// [`NAME_HEAD_LEN`] − 1 are compared on that prefix.
#[inline(always)]
pub fn rename_shape(old: &NameParts, new: &NameParts) -> u32 {
    rename_shape_with(old, new, name_ext(new), name_ext(old))
}

/// [`rename_shape`] with the two names' [`name_ext`] already computed
/// (`new_ext`, `old_ext`). The eBPF counter computes each extension in a
/// global function of its own and passes them here: the two extension
/// scans and the head comparisons inlined in one function took
/// `nn_rename_burst` past the 1M-instruction limit of the 5.15 and 6.1
/// verifiers (lab PR 225; KERNEL_COMPATIBILITY "Older verifiers", rule 11).
#[inline(always)]
pub fn rename_shape_with(
    old: &NameParts,
    new: &NameParts,
    new_ext: (u64, u32),
    old_ext: (u64, u32),
) -> u32 {
    let (new_ext, new_ext_len) = new_ext;
    if new_ext_len == 0 {
        return RENAME_OTHER;
    }
    let max = NAME_HEAD_LEN as u32 - 1;
    if new.len == old.len.saturating_add(1).saturating_add(new_ext_len) {
        let n = if old.len < max { old.len } else { max };
        if heads_agree(&old.head, &new.head, n) {
            return RENAME_APPENDED;
        }
    }
    let (old_ext, old_ext_len) = old_ext;
    if old_ext_len == 0 || old_ext == new_ext || old.len <= old_ext_len + 1 {
        return RENAME_OTHER;
    }
    let stem = old.len - old_ext_len - 1;
    if new.len <= new_ext_len || new.len - new_ext_len - 1 != stem {
        return RENAME_OTHER;
    }
    let n = if stem < max { stem } else { max };
    if heads_agree(&old.head, &new.head, n) {
        RENAME_REPLACED
    } else {
        RENAME_OTHER
    }
}

/// Lab PR 225: per-tgid rename window: the streak of renames to one new
/// extension.
#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
#[cfg_attr(feature = "std", derive(bytemuck::Pod, bytemuck::Zeroable))]
pub struct RenameWindow {
    pub start_ns: u64,
    /// The streak's new extension ([`name_ext`]'s hash).
    pub ext: u64,
    /// The previous counted rename's old extension (0: none).
    pub last_src: u64,
    pub count: u32,
    /// Renames of the streak that appended ([`RENAME_APPENDED`]).
    pub appended: u32,
    /// Changes of the old extension along the streak.
    pub sources: u32,
    /// 1 once the window reported.
    pub fired: u32,
}

impl RenameWindow {
    #[inline(always)]
    pub fn fresh(now: u64, ext: u64, src: u64, appended: bool) -> Self {
        RenameWindow {
            start_ns: now,
            ext,
            last_src: src,
            count: 1,
            appended: appended as u32,
            sources: 0,
            fired: 0,
        }
    }
}

/// Lab PR 225: one more counted rename to extension `ext` (from old
/// extension `src`) in a tgid's window `w` at `now`. `true` once per
/// window, when the streak reaches [`OPEN_RENAME_EXT_MIN`]. Another
/// extension starts a new streak in the same window.
#[inline(always)]
pub fn rename_step(w: &mut RenameWindow, ext: u64, src: u64, appended: bool, now: u64) -> bool {
    if now.saturating_sub(w.start_ns) > OPEN_BURST_WINDOW_NS {
        *w = RenameWindow::fresh(now, ext, src, appended);
        return false;
    }
    if ext != w.ext {
        w.ext = ext;
        w.last_src = src;
        w.count = 1;
        w.appended = appended as u32;
        w.sources = 0;
        return false;
    }
    w.count += 1;
    w.appended += appended as u32;
    if src != w.last_src {
        w.sources += 1;
        w.last_src = src;
    }
    if w.count >= OPEN_RENAME_EXT_MIN && w.fired == 0 {
        w.fired = 1;
        return true;
    }
    false
}

/// Lab PR 225: per-tgid unlink window.
#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
#[cfg_attr(feature = "std", derive(bytemuck::Pod, bytemuck::Zeroable))]
pub struct UnlinkWindow {
    pub start_ns: u64,
    pub count: u32,
    /// 1 once the window reported.
    pub fired: u32,
    /// Lot 283c: the window's [`own_data`] summary of the originals
    /// destroyed ([`own_after`]).
    pub own: u32,
    pub _pad: u32,
}

impl UnlinkWindow {
    /// Lot 282: the start of the window a destruction at `now` counts in
    /// ([`OpenWriteWindow::start_for`], for [`DestroySeenKey`]).
    #[inline(always)]
    pub fn start_for(&self, now: u64) -> u64 {
        if now.saturating_sub(self.start_ns) > OPEN_BURST_WINDOW_NS {
            now
        } else {
            self.start_ns
        }
    }
}

/// Lab PR 225: one more counted unlink in a tgid's window `w` at `now`;
/// the window's unlinks once per window, when they reach
/// [`OPEN_UNLINK_MIN`], else 0. Lot 282: the eBPF counter calls it once per
/// original — a name's first destruction of the window ([`DestroySeenKey`]).
#[inline(always)]
pub fn unlink_step(w: &mut UnlinkWindow, now: u64) -> u32 {
    if now.saturating_sub(w.start_ns) > OPEN_BURST_WINDOW_NS {
        *w = UnlinkWindow {
            start_ns: now,
            count: 1,
            ..UnlinkWindow::default()
        };
        return 0;
    }
    w.count += 1;
    if w.count >= OPEN_UNLINK_MIN && w.fired == 0 {
        w.fired = 1;
        return w.count;
    }
    0
}

/// `name` (a NUL-padded leaf name, as the file-open sensor reads it) ends
/// in `.kdbx`: `.kdbx` followed by the NUL, scanned at constant-bounded
/// positions (no `len - 5`, 5.15 rule 5). A name cut at 31 bytes is judged
/// on the 31 bytes kept. External audit EBPF-022: from position 0, so a
/// file named `.kdbx` matches too (the scan started at 1). Shared with the
/// eBPF program (`fim_file_open_sensor`, on its scratch buffer); the loop
/// bound keeps every index in range, so no bounds check is emitted.
#[inline(always)]
pub fn kdbx_suffix(name: &[u8; OPEN_NAME_LEN]) -> bool {
    let mut i = 0;
    while i + 5 < OPEN_NAME_LEN {
        if name[i + 5] == 0 {
            return name[i] == b'.'
                && name[i + 1] == b'k'
                && name[i + 2] == b'd'
                && name[i + 3] == b'b'
                && name[i + 4] == b'x';
        }
        i += 1;
    }
    false
}

#[cfg(all(test, feature = "std"))]
mod tests {
    /// Lot 325 (the re-check of #546, R3): a walk that could not run is no
    /// class of the directory — never cached, so the next open walks again;
    /// a walk that found nothing (an empty class) still is.
    #[test]
    fn a_lost_walk_is_never_cached() {
        use super::open_class::*;
        assert!(!super::dir_class_cacheable(WALK_LOST));
        assert!(!super::dir_class_cacheable(WALK_LOST | CLASSIFIED));
        assert!(super::dir_class_cacheable(0));
        assert!(super::dir_class_cacheable(
            CLASSIFIED | TREE_CRED | DEPTH_CAPPED
        ));
        // a bit of its own: no rule or other computed class carries it
        for b in [
            SUBTREE,
            DIRECT,
            LEAF_CRED,
            DEPTH_CAPPED,
            CLASSIFIED,
            OWNER_BITS,
        ] {
            assert_eq!(b & WALK_LOST, 0, "{b:#x}");
        }
    }

    use super::*;

    fn name(s: &str) -> [u8; OPEN_NAME_LEN] {
        let mut n = [0u8; OPEN_NAME_LEN];
        let k = s.len().min(OPEN_NAME_LEN - 1);
        n[..k].copy_from_slice(&s.as_bytes()[..k]);
        n
    }

    /// External audit EBPF-022: a file named `.kdbx` is a KeePass
    /// database too; the scan started at position 1 and missed it.
    #[test]
    fn kdbx_suffix_matches_bare_name() {
        let k = |s: &str| kdbx_suffix(&name(s));
        assert!(k(".kdbx"));
        assert!(k("a.kdbx"));
        assert!(k("Passwords.kdbx"));
        assert!(k("twenty-six-bytes-name.kdbx"));
        assert!(!k("kdbx"));
        assert!(!k("a.kdbx.bak"));
        assert!(!k(".kdb"));
        assert!(!k(""));
        // A longer name is judged on the 31 bytes kept.
        assert!(!k("a-name-that-is-cut-at-31-bytes-x.kdbx"));
    }

    #[test]
    fn open_sensor_layouts() {
        // lot 340: + the fork records (fork_start, fork_parent_start,
        // fork_ppid, fork_pppid)
        assert_eq!(core::mem::size_of::<OpenRecordRaw>(), 632);
        assert_eq!(core::mem::align_of::<OpenRecordRaw>(), 8);
        assert_eq!(core::mem::size_of::<ChildRuleKey>(), 48);
        assert_eq!(core::mem::size_of::<DirClass>(), 16);
        assert_eq!(core::mem::size_of::<OpenWriteWindow>(), 32);
        assert_eq!(core::mem::size_of::<OpenCgKey>(), 16);
        assert_eq!(core::mem::size_of::<OpenCgWindow>(), 24);
        assert_eq!(core::mem::size_of::<NameParts>(), 56);
        assert_eq!(core::mem::size_of::<RenameNames>(), 112);
        assert_eq!(core::mem::size_of::<RenameWindow>(), 40);
        assert_eq!(core::mem::size_of::<UnlinkWindow>(), 24);
    }

    #[test]
    fn class_groups_are_consistent() {
        use open_class::*;
        assert_eq!(SUBTREE & CLASSIFIED, 0);
        assert_eq!(DIRECT & SUBTREE, SUBTREE);
        assert_eq!(
            DIRECT & (FILE_SENSITIVE | FILE_CRITICAL | FILE_PERSIST | LEAF_CRED),
            0
        );
        // a computed bit, never inherited nor taken from a rule
        assert_eq!((DIRECT | CLASSIFIED) & DEPTH_CAPPED, 0);
    }

    /// Lot 283c: the own-data bits and the tag fit beside the others, every
    /// directory class of them passes to the subtree, and the summary's
    /// byte lies above every reason bit.
    #[test]
    fn own_data_bits_fit() {
        use open_class::*;
        let others = FILE_SENSITIVE
            | FILE_CRITICAL
            | FILE_PERSIST
            | TREE_CRITICAL
            | TREE_PERSIST
            | CHILDREN_PROBE
            | TREE_CRED
            | LEAVES_CRED
            | TREE_HOME
            | TREE_CARVEOUT
            | TREE_RUNTIME
            | LEAF_CRED
            | CHILD_FILES
            | DIR_HAS_FILES
            | DEPTH_CAPPED
            | CLASSIFIED;
        let own = TREE_SVC_DATA | TREE_USER_CACHE | TREE_UNIT_DATA | UNIT_TAG_MASK | TREE_SHM;
        assert_eq!(own & others, 0);
        assert_eq!(SUBTREE & own, own);
        assert_eq!(OWN_DATA_BITS & UNIT_TAG_MASK, 0);
        assert_eq!(TREE_SHM & UNIT_TAG_MASK, 0);
        assert_eq!((UNIT_TAG_MASK >> UNIT_TAG_SHIFT) + 1, 256);
        let all_reasons = open_reason::SENSITIVE
            | open_reason::CRITICAL
            | open_reason::PERSIST
            | open_reason::PROBE
            | open_reason::CRED
            | open_reason::MASS_WRITE
            | open_reason::FILE_CAP
            | open_reason::MASS_OVERWRITE
            | open_reason::MASS_OVERWRITE_CGROUP
            | open_reason::MASS_RENAME
            | open_reason::MASS_UNLINK
            | open_reason::DEFENDER_SIGNAL
            | open_reason::MASS_OVERWRITE_SMALL;
        assert_eq!(all_reasons & !open_reason::REASON_BITS, 0);
        assert_eq!(0xFFu32 << open_reason::OWN_SHIFT, !open_reason::REASON_BITS);
    }

    /// Lot 283c: whose own data one counted file is, as the kernel judges
    /// it — decisions 1 to 3 at the file.
    #[test]
    fn own_code_tells_whose_own_data_a_file_is() {
        use open_class::*;
        use own_data::*;
        let code = |bits: u32, owner: u32, uid: u32, dir: u32, file: u32, nlink: u32| {
            own_code(bits, owner, uid, dir, file, nlink) as u8
        };
        const PG: u32 = 113;
        const NO: u32 = u32::MAX;
        // decision 1: a service account's file, in its directory, under
        // `/var/lib` or its home — not root's, not another's, not a link
        assert_eq!(code(TREE_SVC_DATA, NO, PG, PG, PG, 1), SERVICE);
        assert_eq!(code(TREE_SVC_DATA | TREE_HOME, NO, PG, PG, PG, 1), SERVICE);
        assert_eq!(code(TREE_SVC_DATA, NO, 0, 0, 0, 1), NONE, "root");
        assert_eq!(
            code(TREE_SVC_DATA, NO, PG, 0, PG, 1),
            NONE,
            "a directory of root's"
        );
        assert_eq!(
            code(TREE_SVC_DATA, NO, PG, PG, 1000, 1),
            NONE,
            "a person's file"
        );
        assert_eq!(code(TREE_SVC_DATA, NO, PG, PG, PG, 2), NONE, "a hard link");
        assert_eq!(code(TREE_SVC_DATA, NO, PG, NO, PG, 1), NONE, "unread");
        assert_eq!(
            code(TREE_HOME, NO, PG, PG, PG, 1),
            NONE,
            "outside the trees"
        );
        assert_eq!(code(0, NO, PG, PG, PG, 1), NONE);
        // its own POSIX shared memory: a file it owns in `/dev/shm`, the
        // directory root's (sticky) — anyone else's segment is not
        assert_eq!(code(TREE_SHM, NO, PG, 0, PG, 1), SERVICE);
        assert_eq!(
            code(TREE_SHM, NO, PG, 0, 1000, 1),
            NONE,
            "a person's segment"
        );
        assert_eq!(code(TREE_SHM, NO, 0, 0, 0, 1), NONE, "root's");
        assert_eq!(code(TREE_SHM, NO, PG, 0, PG, 2), NONE, "a hard link");
        assert_eq!(code(TREE_SHM | TREE_RUNTIME, PG, PG, 0, PG, 1), NONE);
        // decision 3: a person's cache, by its owner only
        assert_eq!(
            code(TREE_USER_CACHE | TREE_HOME, 1000, 1000, 1000, 1000, 1),
            CACHE
        );
        assert_eq!(
            code(TREE_USER_CACHE, 1000, 1001, 1001, 1001, 1),
            NONE,
            "another uid"
        );
        assert_eq!(code(TREE_USER_CACHE, 1000, 0, 0, 0, 1), NONE, "root");
        assert_eq!(
            code(TREE_USER_CACHE, 1000, 1000, 1000, 0, 1),
            NONE,
            "root's file"
        );
        assert_eq!(
            code(TREE_USER_CACHE, 1000, 1000, 1000, 1000, 3),
            NONE,
            "a hard link"
        );
        // decision 2: a listed daemon's directory — its tag, whoever writes
        // (the posture checks the writer's unit)
        let tagged = |tag: u32| TREE_UNIT_DATA | TREE_SVC_DATA | (tag << UNIT_TAG_SHIFT);
        assert_eq!(code(tagged(0), 0, 0, 0, 0, 1), UNIT_BASE);
        assert_eq!(code(tagged(7), 0, 0, 0, 1000, 1), UNIT_BASE + 7);
        assert_eq!(code(tagged(UNIT_TAGS - 1), 0, 0, 0, 0, 1), 255);
        // past the tags no code: the record's byte would wrap to another's
        for tag in UNIT_TAGS..256 {
            assert_eq!(
                own_code(tagged(tag), 0, 0, 0, 0, 1),
                NONE as u32,
                "tag {tag}"
            );
        }
        assert_eq!(code(tagged(7), 0, 0, 0, 0, 2), NONE, "a hard link");
        // two owner-bearing registrations nested: no one's
        assert_eq!(
            code(tagged(7) | TREE_USER_CACHE, 1000, 1000, 1000, 1000, 1),
            NONE
        );
        assert_eq!(
            code(TREE_USER_CACHE | TREE_RUNTIME, 1000, 1000, 1000, 1000, 1),
            NONE
        );
        assert_eq!(code(TREE_SVC_DATA | TREE_RUNTIME, PG, PG, PG, PG, 1), NONE);
    }

    /// Lot 283c: a window is one owner's data only when every file it
    /// counted was — one file elsewhere makes the rest of the window no
    /// one's; a file counted again changes nothing; a new window starts
    /// over.
    #[test]
    fn a_window_is_own_data_only_when_every_file_it_counted_was() {
        let pg = own_data::SERVICE as u32;
        let unit = own_data::UNIT_BASE as u32 + 4;
        let none = own_data::NONE as u32;
        // the counter's sequence: fresh, then each write's code
        let run = |writes: &[(u32, bool)]| {
            let mut w = own_after(0, true, true, writes[0].0);
            for (code, counted) in &writes[1..] {
                w = own_after(w, false, *counted, *code);
            }
            w
        };
        assert_eq!(run(&[(pg, true); 20]), pg);
        assert_eq!(run(&[(unit, true); 20]), unit);
        let mut mixed = vec![(pg, true); 20];
        mixed[7] = (none, true);
        assert_eq!(run(&mixed), none, "one file outside");
        mixed[7] = (unit, true);
        assert_eq!(run(&mixed), none, "another owner's file");
        mixed[7] = (none, false);
        assert_eq!(run(&mixed), pg, "a file counted already");
        let mut late = vec![(none, true)];
        late.extend([(pg, true); 19]);
        assert_eq!(run(&late), none, "no one's from its first file");
        assert_eq!(own_after(none, true, true, pg), pg, "a fresh window");
    }

    const S: u64 = 1_000_000_000;

    /// `n` write-opens by one process, `over` each, from `t0` on (a few ms
    /// apart); the reasons and cgroup shares in order.
    fn process(n: u32, over: bool, t0: u64) -> Vec<(u32, u32, u32)> {
        let kind = if over {
            WriteKind::Rewrite
        } else {
            WriteKind::New
        };
        let mut w = OpenWriteWindow::fresh(t0, kind);
        let mut out = vec![(0, 0, 0)];
        for i in 1..n {
            out.push(write_step(&mut w, kind, t0 + u64::from(i) * 1_000_000));
        }
        out
    }

    /// External audit EBPF-011 (lab probe shape): 40 existing files
    /// rewritten by a fresh child every 10 files. No process crosses its
    /// own threshold; the cgroup window does, on the 40th file.
    #[test]
    fn fork_workers_cross_the_cgroup_window() {
        let mut cg = OpenCgWindow::default();
        let mut fired = Vec::new();
        for child in 0..4u64 {
            for (i, (bits, _, add)) in process(10, true, child * S / 10).into_iter().enumerate() {
                assert_eq!(bits, 0, "no process crosses its own threshold");
                let n = cgroup_step(&mut cg, add, child * S / 10 + i as u64);
                if n != 0 {
                    fired.push((child, i, n));
                }
            }
        }
        assert_eq!(fired, vec![(3, 9, OPEN_CG_OVERWRITE_MIN)]);
    }

    /// The shapes lab PR 127 measured and `make -j`: one process per
    /// output (a compiler's `.d`, a `.cmd` redirect), two per CMake
    /// `cmake_depends`, and cargo's own process with its 4 rewrites of
    /// 4 KiB or more. Hundreds of them in a minute never reach the cgroup
    /// window.
    #[test]
    fn a_build_never_reaches_the_cgroup_window() {
        let mut cg = OpenCgWindow::default();
        let mut total = 0u32;
        let mut feed = |shares: Vec<(u32, u32, u32)>, t: u64| {
            for (_, _, add) in shares {
                total += add;
                assert_eq!(cgroup_step(&mut cg, add, t), 0);
            }
        };
        for job in 0..500u64 {
            feed(process(1, true, job * S / 10), job * S / 10);
        }
        for target in 0..200u64 {
            feed(process(2, true, target * S / 4), target * S / 4);
        }
        feed(process(4, true, 0), S);
        assert_eq!(total, 4, "only cargo's own process counts");
    }

    /// A process that crosses its own threshold is reported by it and
    /// leaves the cgroup window; its overwrites before still count there.
    #[test]
    fn a_process_over_its_own_threshold_is_not_counted_twice() {
        let steps = process(40, true, 0);
        let own: Vec<usize> = steps
            .iter()
            .enumerate()
            .filter(|(_, s)| s.0 & open_reason::MASS_OVERWRITE != 0)
            .map(|(i, _)| i)
            .collect();
        assert_eq!(own, vec![OPEN_MASS_WRITE_MIN as usize - 1]);
        let shares: u32 = steps.iter().map(|s| s.2).sum();
        assert_eq!(shares, OPEN_MASS_WRITE_MIN - 1);
        // new files never count in the cgroup window
        assert!(process(40, false, 0).iter().all(|s| s.2 == 0));
    }

    /// Both windows are tumbling 60-s windows: a slow rewriter never adds
    /// up.
    #[test]
    fn windows_restart_after_sixty_seconds() {
        let mut w = OpenWriteWindow::fresh(0, WriteKind::Rewrite);
        for i in 1..5u64 {
            let (_, _, add) = write_step(&mut w, WriteKind::Rewrite, i * 61 * S);
            assert_eq!(add, 0);
            assert_eq!(w.overwrites, 1);
        }
        let mut cg = OpenCgWindow::default();
        for i in 0..100u64 {
            assert_eq!(cgroup_step(&mut cg, 3, i * 61 * S), 0);
        }
    }

    /// Lot 282: the eBPF counter's glue for one tgid
    /// (`nn_open_count_write`): the seen map decides whether a write-open
    /// is the file's first of the window, [`write_kind`] what it counts as,
    /// `write_step` counts.
    #[derive(Default)]
    struct Tgid {
        w: Option<OpenWriteWindow>,
        seen: std::collections::HashMap<u64, u64>,
    }

    impl Tgid {
        /// One write-open of file `ino`, `size` bytes when opened,
        /// `created` by the open, at `now`.
        fn write(&mut self, ino: u64, created: bool, size: u64, now: u64) -> (u32, u32, u32) {
            let start = self.w.as_ref().map_or(now, |w| w.start_for(now));
            let first = first_in_window(self.seen.get(&ino).copied(), start);
            if first {
                self.seen.insert(ino, start);
            }
            let kind = write_kind(created, size != 0, size >= OVERWRITE_MIN_BYTES, first);
            match self.w.as_mut() {
                Some(w) => write_step(w, kind, now),
                None => {
                    self.w = Some(OpenWriteWindow::fresh(now, kind));
                    (0, 0, 0)
                }
            }
        }

        /// One write-open of file `ino` — `existing` (8 KiB, no
        /// `FMODE_CREATED`) or created — at `now`.
        fn open(&mut self, ino: u64, existing: bool, now: u64) -> (u32, u32, u32) {
            if existing {
                self.write(ino, false, 8192, now)
            } else {
                self.write(ino, true, 0, now)
            }
        }
    }

    fn crossings(steps: &[(u32, u32, u32)]) -> Vec<(usize, u32, u32)> {
        steps
            .iter()
            .enumerate()
            .filter(|(_, s)| s.0 != 0)
            .map(|(i, s)| (i, s.0, s.1))
            .collect()
    }

    /// Lot 282 (lab 04/11, lot 279's podman repro): rootless podman's first
    /// pull opened `bolt_state.db` 259 times in a minute, and the per-open
    /// count made that a mass overwrite. One file rewritten again and again
    /// is one file: no crossing of either kind, however many opens.
    #[test]
    fn a_database_rewritten_hundreds_of_times_is_one_file() {
        let mut t = Tgid::default();
        let steps: Vec<_> = (0..259u64)
            .map(|i| t.open(7, true, i * 200_000_000))
            .collect();
        assert_eq!(crossings(&steps), vec![]);
        let w = t.w.unwrap();
        assert_eq!((w.overwrites, w.created, w.count), (1, 0, 259));
        // and nothing for the cgroup window: one file is below its floor
        assert!(steps.iter().all(|s| s.2 == 0));
    }

    /// Lot 282: twenty DIFFERENT existing files rewritten — encryption in
    /// place — cross the overwrite threshold on the twentieth, with the
    /// distinct files as the count; reopening them does not count again.
    #[test]
    fn distinct_files_rewritten_cross_once_with_their_count() {
        let mut t = Tgid::default();
        let mut steps = Vec::new();
        for round in 0..3u64 {
            for ino in 0..20u64 {
                steps.push(t.open(100 + ino, true, (round * 20 + ino) * 10_000_000));
            }
        }
        assert_eq!(
            crossings(&steps),
            vec![(19, open_reason::MASS_OVERWRITE, OPEN_MASS_WRITE_MIN)]
        );
        assert_eq!(t.w.unwrap().overwrites, 20);
    }

    /// Lot 282: files created — an image's layers extracted, a clone, a
    /// build — cross the creation threshold (`MASS_WRITE`, the files
    /// created as the count), never the overwrite one, and never feed the
    /// cgroup window.
    #[test]
    fn files_created_cross_mass_write_and_never_overwrite() {
        let mut t = Tgid::default();
        let steps: Vec<_> = (0..500u64)
            .map(|i| t.open(1000 + i, false, i * 1_000_000))
            .collect();
        assert_eq!(
            crossings(&steps),
            vec![(19, open_reason::MASS_WRITE, OPEN_MASS_WRITE_MIN)]
        );
        assert!(steps.iter().all(|s| s.2 == 0));
        let w = t.w.unwrap();
        assert_eq!((w.created, w.overwrites), (500, 0));
    }

    /// Lot 282: the creation crossing carries the files created, not the
    /// window's write-opens — a database reopened ten times beside twenty
    /// new files is twenty files created.
    #[test]
    fn the_creation_crossing_carries_the_files_created() {
        let mut t = Tgid::default();
        let mut steps: Vec<_> = (0..10u64).map(|i| t.open(7, true, i)).collect();
        steps.extend((0..20u64).map(|i| t.open(100 + i, false, 10 + i)));
        assert_eq!(
            crossings(&steps),
            vec![(29, open_reason::MASS_WRITE, OPEN_MASS_WRITE_MIN)]
        );
        assert_eq!(t.w.unwrap().count, 30);
    }

    /// Lot 282: one write-open is one kind, so a window crosses each
    /// threshold on its own open, each with its own count — the files
    /// written new for `MASS_WRITE`, the files rewritten for
    /// `MASS_OVERWRITE` (whose crossing reports the small-file one's alone:
    /// none of them was under 4 KiB).
    #[test]
    fn each_crossing_carries_its_own_count() {
        let mut w = OpenWriteWindow::fresh(0, WriteKind::New);
        for i in 1..19u64 {
            assert_eq!(write_step(&mut w, WriteKind::New, i).0, 0);
        }
        for i in 0..19u64 {
            assert_eq!(write_step(&mut w, WriteKind::Rewrite, 100 + i).0, 0);
        }
        assert_eq!(
            write_step(&mut w, WriteKind::New, 200),
            (open_reason::MASS_WRITE, 20, 0)
        );
        let (bits, count, _) = write_step(&mut w, WriteKind::Rewrite, 201);
        assert_eq!(
            (bits, count),
            (open_reason::MASS_OVERWRITE, 20),
            "the overwrite crossing's count: the files rewritten"
        );
        assert_eq!(w.fired, FIRED_WRITES | FIRED_OVERWRITES | FIRED_SMALL);
        assert_eq!(write_step(&mut w, WriteKind::Repeat, 202), (0, 0, 0));
        assert_eq!((w.count, w.created, w.overwrites, w.small), (41, 20, 20, 0));
    }

    /// Lot 282, the review of #500 (C1): an encryptor of small documents
    /// in place — twenty existing non-empty files under 4 KiB rewritten —
    /// crosses `MASS_OVERWRITE_SMALL` (the files rewritten as its count),
    /// never `MASS_OVERWRITE`, and feeds no cgroup window. Mixed with
    /// larger files it crosses on the twentieth distinct file of any size,
    /// and the larger files alone cross `MASS_OVERWRITE` later, on their
    /// twentieth. An empty file is no rewrite: it is written new.
    #[test]
    fn small_files_rewritten_cross_on_their_own_threshold() {
        let mut t = Tgid::default();
        let steps: Vec<_> = (0..40u64)
            .map(|i| t.write(100 + i, false, 1500, i * 1_000_000))
            .collect();
        assert_eq!(
            crossings(&steps),
            vec![(19, open_reason::MASS_OVERWRITE_SMALL, OPEN_MASS_WRITE_MIN)]
        );
        assert!(steps.iter().all(|s| s.2 == 0), "no cgroup share");
        let w = t.w.unwrap();
        assert_eq!((w.small, w.overwrites, w.created), (40, 0, 0));
        // ten of 8 KiB and ten of 1 KiB, then ten more of 8 KiB
        let mut t = Tgid::default();
        let mut steps: Vec<_> = (0..10u64).map(|i| t.write(i, false, 8192, i)).collect();
        steps.extend((10..20u64).map(|i| t.write(i, false, 1024, i)));
        steps.extend((20..30u64).map(|i| t.write(i, false, 8192, i)));
        assert_eq!(
            crossings(&steps),
            vec![
                (19, open_reason::MASS_OVERWRITE_SMALL, 20),
                (29, open_reason::MASS_OVERWRITE, 20)
            ]
        );
        // an empty file, opened to write: a file written new
        let mut t = Tgid::default();
        t.write(1, false, 0, 0);
        assert_eq!(t.w.unwrap().created, 1);
    }

    /// The review of #500 (B1, its probe
    /// `review500_probe_neither_created_nor_overwrite_counts_nothing`):
    /// files the open did not create and that held nothing — made by
    /// `mknod(S_IFREG)`, by an `O_TMPFILE` open linked in with `linkat`, by
    /// an `O_RDONLY | O_CREAT` open then reopened to write — were neither
    /// created (`FMODE_CREATED`) nor rewritten, and 500 of them crossed
    /// nothing. They are files written new: the creation crossing on the
    /// twentieth, with the distinct files as its count; reopened, none
    /// counts again.
    #[test]
    fn files_written_new_whatever_made_them_cross_mass_write() {
        let mut t = Tgid::default();
        let mut steps: Vec<_> = (0..500u64)
            .map(|i| t.write(1000 + i, false, 0, i * 1_000_000))
            .collect();
        steps.extend((0..500u64).map(|i| t.write(1000 + i, false, 2048, S + i)));
        assert_eq!(
            crossings(&steps),
            vec![(19, open_reason::MASS_WRITE, OPEN_MASS_WRITE_MIN)]
        );
        let w = t.w.unwrap();
        assert_eq!(
            (w.created, w.overwrites, w.small, w.count),
            (500, 0, 0, 1000)
        );
    }

    /// The re-review of #500 (cost): an open that created its file is its
    /// file's first write-open of the window without a lookup — even when
    /// the seen map holds the window's start for that inode number (a file
    /// freed and its number reused within the window: a repeat would count
    /// it less) — and the lookup is not made; any other open asks the map.
    #[test]
    fn a_created_file_is_first_without_a_lookup() {
        let asked = core::cell::Cell::new(false);
        let seen = || {
            asked.set(true);
            Some(7)
        };
        assert!(first_write(true, seen, 7));
        assert!(!asked.get(), "no lookup for a created file");
        assert!(!first_write(false, seen, 7));
        assert!(asked.get());
        assert!(first_write(false, || Some(3), 7));
        assert!(first_write(false, || None, 7));
    }

    /// The re-review of #500: what the writes' count leaves out — and the
    /// destructions' since — a carve-out, or the caller's own runtime
    /// directory; a runtime directory of another login uid counts, and the
    /// login uid is read only for a runtime directory.
    #[test]
    fn carved_directories_are_the_carve_outs_and_the_own_runtime_dir() {
        use open_class::*;
        let never = || -> u32 { panic!("login uid read for a directory that is no runtime one") };
        assert!(carved_class(TREE_CARVEOUT, 0, never));
        assert!(carved_class(TREE_CARVEOUT | TREE_HOME, 0, never));
        assert!(!carved_class(TREE_HOME, 0, never));
        assert!(!carved_class(0, 0, never));
        assert!(carved_class(TREE_RUNTIME, 1000, || 1000));
        assert!(!carved_class(TREE_RUNTIME, 1000, || 1001));
        assert!(!carved_class(TREE_RUNTIME, 1000, || u32::MAX));
    }

    /// The re-review of #500 (cost): only a size change marks a file as
    /// having held data — a truncate, an `O_TRUNC` open — never a chmod, a
    /// chown or a `touch` (`ATTR_MODE` 1, `ATTR_UID` 2, `ATTR_GID` 4,
    /// `ATTR_ATIME` 16, `ATTR_MTIME` 32, `ATTR_CTIME` 64; an `O_TRUNC`
    /// open's `ATTR_OPEN` 0x8000 with the size).
    #[test]
    fn only_a_size_change_marks_had_data() {
        assert!(marks_had_data(ATTR_SIZE));
        assert!(marks_had_data(ATTR_SIZE | 32 | 64 | 0x8000));
        for v in [0u32, 1, 2, 4, 1 | 64, 16 | 32 | 64, 2 | 4 | 64] {
            assert!(!marks_had_data(v), "{v:#x}");
        }
        assert_eq!(ATTR_SIZE, 8);
    }

    /// Lot 282: what one write-open counts as.
    #[test]
    fn write_kind_reads_the_open() {
        use WriteKind::*;
        // (created, data, big, first)
        assert_eq!(write_kind(false, true, true, true), Rewrite);
        assert_eq!(write_kind(false, true, false, true), SmallRewrite);
        assert_eq!(write_kind(false, false, false, true), New);
        assert_eq!(write_kind(true, false, false, true), New);
        // created by the open whatever its size (another opener's data
        // cannot be in a file the open made)
        assert_eq!(write_kind(true, true, true, true), New);
        for (c, d, b) in [
            (false, true, true),
            (true, false, false),
            (false, false, false),
        ] {
            assert_eq!(write_kind(c, d, b, false), Repeat);
        }
    }

    /// Lot 282, the review of #500 (C1): an unlink destroys an original
    /// when the file holds data, or held it within a burst window (a
    /// `truncate` then an `unlink`); an empty file never seen with data is
    /// none.
    #[test]
    fn an_original_held_data_now_or_within_the_window() {
        assert!(destroys_an_original(1, None, 10 * S));
        assert!(destroys_an_original(4096, None, 10 * S));
        assert!(!destroys_an_original(0, None, 10 * S));
        assert!(destroys_an_original(0, Some(10 * S), 10 * S));
        assert!(destroys_an_original(0, Some(10 * S), 70 * S));
        assert!(!destroys_an_original(0, Some(10 * S), 70 * S + 1));
        // a clock read before the setattr's (CPUs apart): still within
        assert!(destroys_an_original(0, Some(10 * S), 9 * S));
    }

    /// Lot 282: a file counts once per window — in the next window its
    /// first rewrite counts again; the seen map's value is the window's
    /// start, so a stale entry never hides a file.
    #[test]
    fn a_file_counts_again_in_the_next_window() {
        let w = OpenWriteWindow::fresh(5 * S, WriteKind::Rewrite);
        assert_eq!(w.start_for(5 * S), 5 * S);
        assert_eq!(w.start_for(65 * S), 5 * S, "60 s is still the window");
        assert_eq!(
            w.start_for(65 * S + 1),
            65 * S + 1,
            "past it, a new one at now"
        );
        assert!(first_in_window(None, 5 * S));
        assert!(!first_in_window(Some(5 * S), 5 * S));
        assert!(first_in_window(Some(5 * S), 65 * S + 1));
        let mut t = Tgid::default();
        t.open(9, true, 0);
        t.open(9, true, S);
        assert_eq!(t.w.unwrap().overwrites, 1);
        t.open(9, true, 61 * S);
        assert_eq!(
            t.w.unwrap().overwrites,
            1,
            "a fresh window, its first rewrite"
        );
        assert_eq!(t.w.unwrap().start_ns, 61 * S);
        t.open(9, true, 62 * S);
        assert_eq!(t.w.unwrap().overwrites, 1);
        let u = UnlinkWindow {
            start_ns: 2 * S,
            count: 1,
            fired: 0,
            ..UnlinkWindow::default()
        };
        assert_eq!(u.start_for(62 * S), 2 * S);
        assert_eq!(u.start_for(62 * S + 1), 62 * S + 1);
    }

    /// Lot 282: the unlink counter's glue for one tgid
    /// (`nn_unlink_burst`): originals by name, each once per window — a
    /// journal deleted at every commit of a sqlite workload is one name;
    /// twenty different originals cross.
    #[test]
    fn originals_destroyed_count_by_name_once_per_window() {
        let mut w: Option<UnlinkWindow> = None;
        let mut seen: std::collections::HashMap<u64, u64> = std::collections::HashMap::new();
        let mut destroy = |name: u64, now: u64| -> u32 {
            let start = w.as_ref().map_or(now, |w| w.start_for(now));
            if !first_in_window(seen.get(&name).copied(), start) {
                return 0;
            }
            seen.insert(name, start);
            match w.as_mut() {
                Some(w) => unlink_step(w, now),
                None => {
                    w = Some(UnlinkWindow {
                        start_ns: now,
                        count: 1,
                        fired: 0,
                        ..UnlinkWindow::default()
                    });
                    0
                }
            }
        };
        let journal: Vec<u32> = (0..400u64).map(|i| destroy(1, i * 100_000_000)).collect();
        assert!(journal.iter().all(|c| *c == 0), "one name, 400 commits");
        let many: Vec<u32> = (0..30u64).map(|n| destroy(100 + n, 41 * S + n)).collect();
        assert_eq!(many.iter().filter(|c| **c != 0).count(), 1);
        assert_eq!(
            many[18], OPEN_UNLINK_MIN,
            "19 new names + the journal: the 20th original"
        );
    }

    /// Lot 282: the destruction counter's glue with the files the process
    /// created (`OPEN_CREATED`): `pip` unpacking 300 wheels into temporary
    /// files and deleting them destroys no original; deleting 20 files it
    /// did not create — or created more than a window ago — is 20
    /// originals.
    #[test]
    fn a_process_s_own_temporary_files_are_no_originals() {
        let mut created: std::collections::HashMap<u64, u64> = std::collections::HashMap::new();
        let mut w: Option<UnlinkWindow> = None;
        let mut destroy =
            |ino: u64, now: u64, created: &std::collections::HashMap<u64, u64>| -> u32 {
                if created_in_window(created.get(&ino).copied(), now) {
                    return 0;
                }
                match w.as_mut() {
                    Some(w) => unlink_step(w, now),
                    None => {
                        w = Some(UnlinkWindow {
                            start_ns: now,
                            count: 1,
                            fired: 0,
                            ..UnlinkWindow::default()
                        });
                        0
                    }
                }
            };
        for i in 0..300u64 {
            created.insert(1000 + i, i * 10_000_000);
            assert_eq!(destroy(1000 + i, i * 10_000_000 + 5_000_000, &created), 0);
        }
        // its own files of two minutes ago, and files it never created
        let mut crossed: Vec<u32> = Vec::new();
        for i in 0..10u64 {
            crossed.push(destroy(1000 + i, 125 * S + i, &created));
        }
        for i in 0..10u64 {
            crossed.push(destroy(5000 + i, 125 * S + 10 + i, &created));
        }
        assert_eq!(crossed.iter().filter(|c| **c != 0).count(), 1);
        assert_eq!(crossed[19], OPEN_UNLINK_MIN);
    }

    /// Lot 282: a file the destroying process created within a window is
    /// its own temporary file, not an original; one it created longer ago,
    /// or never, is an original.
    #[test]
    fn a_file_the_process_created_in_the_window_is_no_original() {
        assert!(created_in_window(Some(10 * S), 10 * S));
        assert!(
            created_in_window(Some(10 * S), 70 * S),
            "60 s is still the window"
        );
        assert!(!created_in_window(Some(10 * S), 70 * S + 1));
        assert!(!created_in_window(None, 10 * S));
        // a clock read before the creation's (CPUs apart): still its own
        assert!(created_in_window(Some(10 * S), 9 * S));
    }

    #[test]
    fn seen_key_layouts() {
        assert_eq!(core::mem::size_of::<OverwriteSeenKey>(), 24);
        assert_eq!(core::mem::size_of::<DestroySeenKey>(), 24);
    }

    /// Lab PR 225: a name as the eBPF counter reads it.
    fn parts(s: &str) -> NameParts {
        let b = s.as_bytes();
        let mut p = NameParts {
            head: [0; NAME_HEAD_LEN],
            tail: [0; NAME_TAIL_LEN],
            len: b.len() as u32,
            tail_len: 0,
        };
        let h = b.len().min(NAME_HEAD_LEN - 1);
        p.head[..h].copy_from_slice(&b[..h]);
        let t = b.len().min(NAME_TAIL_LEN);
        p.tail[..t].copy_from_slice(&b[b.len() - t..]);
        p.tail_len = t as u32;
        p
    }

    #[test]
    fn name_ext_reads_the_last_extension() {
        let ext = |s: &str| name_ext(&parts(s)).1;
        assert_eq!(ext("report.pdf"), 3);
        assert_eq!(ext("report.pdf.locked"), 6);
        assert_eq!(ext("a-very-long-document-name-of-a-user.docx.lockbit3"), 8);
        assert_eq!(ext("README"), 0);
        assert_eq!(ext(".bashrc"), 0, "a hidden name has no extension");
        assert_eq!(ext("syslog.1"), 0, "a rotation's digits are not one");
        assert_eq!(ext("trailing."), 0);
        assert_eq!(ext("x.an-extension-too-long"), 0);
        assert_eq!(
            name_ext(&parts("a.locked")).0,
            name_ext(&parts("b.locked")).0
        );
        assert_ne!(
            name_ext(&parts("a.locked")).0,
            name_ext(&parts("a.crypt")).0
        );
    }

    /// Lab PR 225: what the rename counter counts — the shapes of an
    /// encryptor renaming its output — and what it never counts: the
    /// temporary-file renames of package managers, rsync, sed and the
    /// interpreters, rotations, plain moves.
    #[test]
    fn rename_shape_counts_appends_and_replacements_only() {
        let shape = |a: &str, b: &str| rename_shape(&parts(a), &parts(b));
        assert_eq!(shape("report.pdf", "report.pdf.locked"), RENAME_APPENDED);
        assert_eq!(shape("README", "README.locked"), RENAME_APPENDED);
        assert_eq!(
            shape(
                "Quarterly figures for the board 2026.xlsx",
                "Quarterly figures for the board 2026.xlsx.lockbit"
            ),
            RENAME_APPENDED
        );
        assert_eq!(shape("report.pdf", "report.locked"), RENAME_REPLACED);
        for (a, b) in [
            ("x.py.dpkg-new", "x.py"),
            (".x.c.AbC123", "x.c"),
            ("sedAbc123", "x.conf"),
            ("x.cpython-312.pyc.140234", "x.cpython-312.pyc"),
            ("syslog", "syslog.1"),
            ("syslog.1", "syslog.2"),
            ("report.pdf", "report.pdf"),
            ("report.pdf", "Xk3fA9.lockbit"),
            ("report.locked", "report.locked"),
            (".x.locked", "x"),
        ] {
            assert_eq!(shape(a, b), RENAME_OTHER, "{a} -> {b}");
        }
    }

    #[test]
    fn rename_step_reports_one_streak_once_per_window() {
        const S: u64 = 1_000_000_000;
        let locked = name_ext(&parts("a.locked")).0;
        let other = name_ext(&parts("a.bak")).0;
        let (pdf, doc) = (name_ext(&parts("a.pdf")).0, name_ext(&parts("a.doc")).0);
        let mut w = RenameWindow::fresh(0, locked, pdf, true);
        for i in 1..OPEN_RENAME_EXT_MIN - 1 {
            let src = if i % 2 == 0 { pdf } else { doc };
            assert!(!rename_step(&mut w, locked, src, true, i as u64));
        }
        assert!(rename_step(&mut w, locked, pdf, true, 30 * S));
        assert_eq!(w.count, OPEN_RENAME_EXT_MIN);
        assert_eq!(w.appended, OPEN_RENAME_EXT_MIN);
        assert!(w.sources >= OPEN_RENAME_EXT_MIN - 2);
        assert!(
            !rename_step(&mut w, locked, pdf, true, 31 * S),
            "once per window"
        );
        // Another extension starts its own streak.
        assert!(!rename_step(&mut w, other, pdf, false, 32 * S));
        assert_eq!(w.count, 1);
        // A new window.
        let mut w = RenameWindow::fresh(0, locked, pdf, false);
        assert!(!rename_step(&mut w, locked, pdf, false, 61 * S));
        assert_eq!((w.count, w.start_ns), (1, 61 * S));
    }

    #[test]
    fn unlink_step_reports_once_per_window() {
        const S: u64 = 1_000_000_000;
        let mut w = UnlinkWindow {
            start_ns: 0,
            count: 1,
            fired: 0,
            ..UnlinkWindow::default()
        };
        for i in 1..OPEN_UNLINK_MIN - 1 {
            assert_eq!(unlink_step(&mut w, i as u64), 0);
        }
        assert_eq!(unlink_step(&mut w, S), OPEN_UNLINK_MIN);
        assert_eq!(unlink_step(&mut w, 2 * S), 0);
        assert_eq!(unlink_step(&mut w, 62 * S), 0, "a new window");
        assert_eq!(w.count, 1);
    }

    // ── external bug hunt (editions 1.2/1.3) ────────────────────────

    /// BUG54 (documentation): an atomic save whose temporary's extension
    /// stands in place of the final one (`data.tmp` -> `data.json`) IS
    /// counted as a replacement — the promise "never counts the renames of
    /// an atomic write" was wrong, and is corrected, not the code: the
    /// shape is an encryptor's staging's too (the test below). That a
    /// burst of them gives no verdict is the tracker's (nn-core
    /// `impact::tests::an_atomic_save_burst_replacing_the_extension_is_not_shaped`).
    #[test]
    fn an_atomic_save_replacing_the_extension_is_counted_but_not_shaped() {
        for (a, b) in [
            ("data.tmp", "data.json"),
            ("a.part", "a.iso"),
            ("f.crdownload", "f.zip"),
        ] {
            assert_eq!(
                rename_shape(&parts(a), &parts(b)),
                RENAME_REPLACED,
                "{a} -> {b}"
            );
        }
        // the atomic writes the promise names stay uncounted
        for (a, b) in [
            ("x.py.dpkg-new", "x.py"),
            (".x.c.AbC123", "x.c"),
            ("sedAbc12", "x.conf"),
            ("x.pyc.140234", "x.pyc"),
        ] {
            assert_eq!(
                rename_shape(&parts(a), &parts(b)),
                RENAME_OTHER,
                "{a} -> {b}"
            );
        }
    }

    /// BUG54: ransomware staging its ciphertext in a temporary and
    /// renaming it to the marker extension has the very same shape — the
    /// report's fix (old extension `tmp` -> not counted) would drop it, so
    /// it is counted, and the plain append too.
    #[test]
    fn staged_ciphertext_renamed_to_a_marker_is_counted() {
        assert_eq!(
            rename_shape(&parts("a.pdf.tmp"), &parts("a.pdf.locked")),
            RENAME_REPLACED
        );
        assert_eq!(
            rename_shape(&parts("a.pdf"), &parts("a.pdf.locked")),
            RENAME_APPENDED
        );
    }
}
