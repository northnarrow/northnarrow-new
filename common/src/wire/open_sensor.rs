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
    /// A computed `DIR_CLASS` entry (an empty class is still cached).
    pub const CLASSIFIED: u32 = 1 << 31;
    /// What a directory passes to every descendant.
    pub const SUBTREE: u32 =
        TREE_CRITICAL | TREE_PERSIST | TREE_CRED | TREE_HOME | TREE_CARVEOUT | TREE_RUNTIME;
    /// What a directory's own rule says about its direct children.
    pub const DIRECT: u32 = SUBTREE | CHILDREN_PROBE | LEAVES_CRED | CHILD_FILES | DIR_HAS_FILES;
}

/// Why a record was emitted (`OpenRecordRaw::reason`, any combination).
pub mod open_reason {
    pub const SENSITIVE: u32 = 1 << 0;
    pub const CRITICAL: u32 = 1 << 1;
    pub const PERSIST: u32 = 1 << 2;
    pub const PROBE: u32 = 1 << 3;
    pub const CRED: u32 = 1 << 4;
    pub const MASS_WRITE: u32 = 1 << 5;
    /// Review 86: a file capability was set (`security.capability`). The
    /// record's `count` carries the permitted set's low 32 bits, `flags`
    /// the high 32, and `mode` the xattr's `magic_etc` (revision in the
    /// top byte, the effective flag in bit 0).
    pub const FILE_CAP: u32 = 1 << 6;
    /// External audit POS-002: the tgid's write-opens of files that
    /// existed before the open (no `FMODE_CREATED`: rewritten, not
    /// created) crossed the mass-write threshold in the window. `count`
    /// still carries all its write-opens.
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
    /// Lab PR 225: a tgid's unlinks of regular files of at least
    /// [`super::UNLINK_MIN_BYTES`] crossed [`super::OPEN_UNLINK_MIN`] in the
    /// window ([`super::unlink_step`]). `count` carries them; the path is the
    /// unlinked file's. Seen on `inode_unlink` (LSM file-open sensor armed).
    pub const MASS_UNLINK: u32 = 1 << 10;
    /// Lab PR 225 (CM-18): a signal that stops or ends a process, sent to
    /// the main process of another security tool (`DEFENDER_PIDS`, filled
    /// by the agent from `security-tools.v1`) by anyone but PID 1, the tool
    /// itself or the agent. Seen on `task_kill`, never refused. `count`
    /// carries the signal, `flags` the target's tgid; no path.
    pub const DEFENDER_SIGNAL: u32 = 1 << 11;
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
/// Lab PR 225: an unlink counts for a file of at least this size, the
/// overwrite's minimum: originals are documents; a build's and a
/// compiler's temporary files are mostly smaller.
pub const UNLINK_MIN_BYTES: u64 = 4096;
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
    /// Owner of a runtime directory (`TREE_RUNTIME`).
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
    pub count: u32,
    /// [`open_reason::MASS_WRITE`] / [`open_reason::MASS_OVERWRITE`] once
    /// each was reported in this window.
    pub fired: u32,
    /// External audit POS-002: the write-opens of files that existed.
    pub overwrites: u32,
    pub _pad: u32,
}

impl OpenWriteWindow {
    /// The window a tgid's first counted write-open starts.
    #[inline(always)]
    pub fn fresh(now: u64, over: bool) -> Self {
        OpenWriteWindow {
            start_ns: now,
            count: 1,
            fired: 0,
            overwrites: over as u32,
            _pad: 0,
        }
    }
}

/// `OpenWriteWindow::fired` bits: the threshold already reported.
pub const FIRED_WRITES: u32 = 1;
pub const FIRED_OVERWRITES: u32 = 2;

/// One more write-open in a tgid's window `w` at `now`; `over`: it rewrites
/// an existing file (POS-002, at least 4 KiB since lab PR 127). Returns the
/// [`open_reason`] bits it adds (`MASS_WRITE`, `MASS_OVERWRITE`, each once
/// per window), the window's write-opens when it adds any, and the
/// overwrites it adds to the cgroup window (external audit EBPF-011): 0
/// until the process has rewritten [`OPEN_CG_PROC_MIN`] files in its
/// window, then all of them at once and one per overwrite after, and 0
/// again once its own threshold reported it.
#[inline(always)]
pub fn write_step(w: &mut OpenWriteWindow, over: bool, now: u64) -> (u32, u32, u32) {
    let over = over as u32;
    if now.saturating_sub(w.start_ns) > OPEN_MASS_WRITE_WINDOW_NS {
        *w = OpenWriteWindow::fresh(now, over != 0);
        return (0, 0, 0);
    }
    w.count += 1;
    w.overwrites += over;
    let mut bits = 0u32;
    if w.count >= OPEN_MASS_WRITE_MIN && w.fired & FIRED_WRITES == 0 {
        w.fired |= FIRED_WRITES;
        bits |= open_reason::MASS_WRITE;
    }
    if w.overwrites >= OPEN_MASS_WRITE_MIN && w.fired & FIRED_OVERWRITES == 0 {
        w.fired |= FIRED_OVERWRITES;
        bits |= open_reason::MASS_OVERWRITE;
    }
    let cg = if over == 0 || w.fired & FIRED_OVERWRITES != 0 || w.overwrites < OPEN_CG_PROC_MIN {
        0
    } else if w.overwrites == OPEN_CG_PROC_MIN {
        OPEN_CG_PROC_MIN
    } else {
        1
    };
    (bits, if bits == 0 { 0 } else { w.count }, cg)
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
/// 8·5 + 4·7 + 16 + 2 + 1 + 1 + 512 = 600.
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
    pub comm: [u8; TASK_COMM_LEN],
    pub path_n: u16,
    pub path_truncated: u8,
    pub _pad: u8,
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
/// by construction: a temporary file renamed to its final name (`x.py.dpkg-new` → `x.py`,
/// rsync's `.x.c.AbC123` → `x.c`, `sed -i`'s `sedAbc12` → `x.conf`, the
/// interpreter's `x.pyc.140234` → `x.pyc`), a move to another directory
/// under the same name, a random new name. Names longer than
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
}

/// Lab PR 225: one more counted unlink in a tgid's window `w` at `now`;
/// the window's unlinks once per window, when they reach
/// [`OPEN_UNLINK_MIN`], else 0.
#[inline(always)]
pub fn unlink_step(w: &mut UnlinkWindow, now: u64) -> u32 {
    if now.saturating_sub(w.start_ns) > OPEN_BURST_WINDOW_NS {
        *w = UnlinkWindow {
            start_ns: now,
            count: 1,
            fired: 0,
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
        assert_eq!(core::mem::size_of::<OpenRecordRaw>(), 600);
        assert_eq!(core::mem::align_of::<OpenRecordRaw>(), 8);
        assert_eq!(core::mem::size_of::<ChildRuleKey>(), 48);
        assert_eq!(core::mem::size_of::<DirClass>(), 16);
        assert_eq!(core::mem::size_of::<OpenWriteWindow>(), 24);
        assert_eq!(core::mem::size_of::<OpenCgKey>(), 16);
        assert_eq!(core::mem::size_of::<OpenCgWindow>(), 16);
        assert_eq!(core::mem::size_of::<NameParts>(), 56);
        assert_eq!(core::mem::size_of::<RenameNames>(), 112);
        assert_eq!(core::mem::size_of::<RenameWindow>(), 40);
        assert_eq!(core::mem::size_of::<UnlinkWindow>(), 16);
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

    const S: u64 = 1_000_000_000;

    /// `n` write-opens by one process, `over` each, from `t0` on (a few ms
    /// apart); the reasons and cgroup shares in order.
    fn process(n: u32, over: bool, t0: u64) -> Vec<(u32, u32, u32)> {
        let mut w = OpenWriteWindow::fresh(t0, over);
        let mut out = vec![(0, 0, 0)];
        for i in 1..n {
            out.push(write_step(&mut w, over, t0 + u64::from(i) * 1_000_000));
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
        let mut w = OpenWriteWindow::fresh(0, true);
        for i in 1..5u64 {
            let (_, _, add) = write_step(&mut w, true, i * 61 * S);
            assert_eq!(add, 0);
            assert_eq!(w.overwrites, 1);
        }
        let mut cg = OpenCgWindow::default();
        for i in 0..100u64 {
            assert_eq!(cgroup_step(&mut cg, 3, i * 61 * S), 0);
        }
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
        };
        for i in 1..OPEN_UNLINK_MIN - 1 {
            assert_eq!(unlink_step(&mut w, i as u64), 0);
        }
        assert_eq!(unlink_step(&mut w, S), OPEN_UNLINK_MIN);
        assert_eq!(unlink_step(&mut w, 2 * S), 0);
        assert_eq!(unlink_step(&mut w, 62 * S), 0, "a new window");
        assert_eq!(w.count, 1);
    }
}
