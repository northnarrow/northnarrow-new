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
}
