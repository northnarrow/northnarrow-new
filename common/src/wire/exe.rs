//! Tappa 10.9 step 2 — what the kernel executed: the identity of
//! `bprm->file` as the LSM `bprm_check_security` program reads it
//! (`agent-ebpf/src/exec_lsm.rs`, design
//! `docs/design/TAPPA10_9_SENSOR_ATTACH_POINTS_DESIGN.md` §11).
//!
//! The path is rebuilt from the file's dentry, not from the string the
//! caller passed to `execve` (review 61): a relative path, a symlink,
//! `..` or `execveat` with a directory fd all give the file's own path.
//! It is relative to the exec'ing task's root when the walk reaches it
//! (`TASK_ROOT`: a container or a chroot keeps its own view), else to
//! the root of the file's filesystem, whose key userland maps to a mount
//! point.

/// Path slots of the walk, 32 bytes each (a name is cut at 31 bytes).
pub const EXE_PATH_SLOTS: usize = 16;
pub const EXE_PATH_SLOT_LEN: usize = 32;
/// Slots for the levels nearest the file; the remaining ones keep the
/// last levels walked (nearest the root) in rotation, so a deep path
/// still shows its top (`/tmp/a/…/x`).
pub const EXE_PATH_LEAF_SLOTS: usize = 12;
/// Levels walked at most; past them the root is not reached.
pub const EXE_WALK_DEPTH: usize = 64;

/// Slot of path level `level` (0 = the file itself).
pub const fn exe_path_slot(level: usize) -> usize {
    if level < EXE_PATH_LEAF_SLOTS {
        level
    } else {
        EXE_PATH_LEAF_SLOTS + (level & (EXE_PATH_SLOTS - EXE_PATH_LEAF_SLOTS - 1))
    }
}

/// `ExeIdentityRaw::flags`.
pub mod exe_flags {
    /// Filled by the LSM program (zero in tracepoint mode).
    pub const KNOWN: u32 = 1 << 0;
    /// On a tmpfs or hugetlbfs superblock.
    pub const TMPFS: u32 = 1 << 1;
    /// A `memfd_create` file (`memfd:` dentry name).
    pub const MEMFD: u32 = 1 << 2;
    /// `i_nlink == 0`: unlinked, or an `O_TMPFILE`.
    pub const DELETED: u32 = 1 << 3;
    /// The walk stopped at the exec'ing task's root: the path is the
    /// task's own view (container, chroot).
    pub const TASK_ROOT: u32 = 1 << 4;
    /// More levels than slots: the middle of the path is elided.
    pub const DEEP: u32 = 1 << 5;
    /// No root within `EXE_WALK_DEPTH` levels: the path is unknown.
    pub const UNRESOLVED: u32 = 1 << 6;

    // Lot 310 (the review of #539): what the agent's exec pump adds in
    // userland, never the kernel programs (bits 16 and up).

    /// The identity (`dev`, `ino`, [`DELETED`], [`MEMFD`]) was read by the
    /// exec pump from `/proc/<pid>/exe` (tracepoint mode: no LSM identity).
    pub const PROC_EXE: u32 = 1 << 16;
    /// The executed file's directory is root's and writable by no one else:
    /// no user could have unlinked the image.
    pub const ROOT_DIR: u32 = 1 << 17;
    /// An interpreter whose environment loads the caller's code before the
    /// program it names (`PYTHONPATH`, `NODE_OPTIONS`, `PERL5OPT`,
    /// `PERL5LIB`, `RUBYOPT`, `RUBYLIB`, `BASH_ENV`, `ENV`).
    pub const ENV_LOADS: u32 = 1 << 18;
    /// An interpreter naming no program whose standard input is no
    /// terminal (`bash < file`, `curl … | sh`): its program is its input.
    pub const STDIN_PROGRAM: u32 = 1 << 19;
}

/// Lot 310: a device number as `stat(2)` reports it, in the kernel's
/// internal form (`MKDEV`: `major << 20 | minor`) the LSM programs read
/// from `s_dev` — glibc's `major()`/`minor()` decoding.
pub const fn kernel_dev(st_dev: u64) -> u64 {
    let major = ((st_dev >> 8) & 0xfff) | ((st_dev >> 32) & !0xfff);
    let minor = (st_dev & 0xff) | ((st_dev >> 12) & !0xff);
    (major << 20) | minor
}

/// Lot 322: the key of a task's own entry in the exec guards' per-task
/// maps (`EXECPOL_ENV`, the exec sensor's and the mapping check's walks,
/// the BPF guard's path buffer): its thread id and its start time
/// (`task_struct.start_time`, ns since boot), so that a thread id the
/// kernel hands out again never finds an entry it did not make. Each such
/// entry is made, used and removed in one run of one program: a program
/// that runs with migration disabled but preemption enabled (LSM, on a
/// `full` or `lazy` preemption kernel) must not keep a per-CPU buffer
/// across its run, since another task's run on the same CPU may rewrite it.
#[repr(C)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "std", derive(bytemuck::Pod, bytemuck::Zeroable))]
pub struct TaskKey {
    pub start_ns: u64,
    pub tid: u32,
    pub _pad: u32,
}

/// The executed file, as one binfmt pass of `bprm_check_security` saw
/// it. 552 bytes, no implicit padding.
#[repr(C)]
#[derive(Copy, Clone, Debug)]
#[cfg_attr(feature = "std", derive(bytemuck::Pod, bytemuck::Zeroable))]
pub struct ExeIdentityRaw {
    /// `(dev, ino)` as `stat()` reports them (review 55).
    pub dev: u64,
    pub ino: u64,
    /// Key of the filesystem root the walk ended on (0 with `TASK_ROOT`).
    pub root_dev: u64,
    pub root_ino: u64,
    pub flags: u32,
    /// Path levels walked, the file itself included.
    pub levels: u16,
    /// binfmt pass: 0 = the file the caller named, 1+ = interpreters.
    pub pass: u8,
    pub _pad: u8,
    /// Level `l`'s name in slot [`exe_path_slot`]`(l)`, NUL-padded.
    pub path: [u8; EXE_PATH_SLOTS * EXE_PATH_SLOT_LEN],
}

impl ExeIdentityRaw {
    pub const fn zeroed() -> Self {
        Self {
            dev: 0,
            ino: 0,
            root_dev: 0,
            root_ino: 0,
            flags: 0,
            levels: 0,
            pass: 0,
            _pad: 0,
            path: [0u8; EXE_PATH_SLOTS * EXE_PATH_SLOT_LEN],
        }
    }
}

/// Marks a name that may have been cut (external audit EBPF-021).
pub const EXE_NAME_CUT_MARK: char = '…';

/// The path the record describes, relative to the task's root or to the
/// root of the file's filesystem (`/` + names, root first). Empty when
/// unknown. A deep path keeps its top and its file, with `…` between.
///
/// External audit EBPF-021: a name of `EXE_PATH_SLOT_LEN - 1` bytes may
/// have been cut (the kernel's string read keeps 31 bytes and the NUL, and
/// a longer name reads the same), so it ends in [`EXE_NAME_CUT_MARK`]: the
/// path then names no file exactly, as the file-open sensor's paths do
/// since lab PR 137. Before, the 31 bytes read as the whole name.
#[cfg(feature = "std")]
pub fn relative_path(raw: &ExeIdentityRaw) -> String {
    let levels = raw.levels as usize;
    if raw.flags & exe_flags::KNOWN == 0
        || raw.flags & exe_flags::UNRESOLVED != 0
        || levels == 0
        || levels > EXE_WALK_DEPTH
    {
        return String::new();
    }
    let name = |level: usize| -> String {
        let slot = exe_path_slot(level);
        let bytes = &raw.path[slot * EXE_PATH_SLOT_LEN..(slot + 1) * EXE_PATH_SLOT_LEN];
        let end = bytes
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(bytes.len())
            .min(EXE_PATH_SLOT_LEN - 1);
        let name = String::from_utf8_lossy(&bytes[..end]).into_owned();
        if end == EXE_PATH_SLOT_LEN - 1 {
            format!("{name}{EXE_NAME_CUT_MARK}")
        } else {
            name
        }
    };
    let mut parts: Vec<String> = Vec::new();
    if levels <= EXE_PATH_SLOTS {
        parts.extend((0..levels).rev().map(name));
    } else {
        let top = EXE_PATH_SLOTS - EXE_PATH_LEAF_SLOTS;
        parts.extend((levels - top..levels).rev().map(name));
        parts.push("…".to_string());
        parts.extend((0..EXE_PATH_LEAF_SLOTS).rev().map(name));
    }
    let parts: Vec<&str> = parts
        .iter()
        .map(String::as_str)
        .filter(|s| !s.is_empty() && *s != "/")
        .collect();
    format!("/{}", parts.join("/"))
}

#[cfg(all(test, feature = "std"))]
mod tests {

    /// Lot 310: stat's encoding back to the kernel's: `/dev/sda2` (8:2) is
    /// `0x802` in `st_dev`, `0x800002` in `s_dev`; a device-mapper root
    /// (253:1) `64769` and `265289729`; a minor past 255 too.
    #[test]
    fn kernel_dev_is_mkdev_of_stat_s_encoding() {
        assert_eq!(super::kernel_dev(0x802), 0x80_0002);
        assert_eq!(super::kernel_dev(64769), 265_289_729);
        // major 8, minor 257: new_encode_dev = 0x01 | 8 << 8 | 0x100 << 12
        assert_eq!(
            super::kernel_dev(0x1 | (8 << 8) | (0x100 << 12)),
            (8 << 20) | 257
        );
        assert_eq!(super::kernel_dev(0), 0);
        // an anonymous device (overlay, tmpfs: major 0)
        assert_eq!(super::kernel_dev(0x2d), 0x2d);
    }
    use super::*;

    /// Lot 322: the per-task key is 16 bytes with no implicit padding (it
    /// is hashed whole by the kernel).
    #[test]
    fn the_task_key_has_no_hidden_bytes() {
        assert_eq!(core::mem::size_of::<TaskKey>(), 16);
        assert_eq!(core::mem::offset_of!(TaskKey, tid), 8);
        assert_eq!(core::mem::offset_of!(TaskKey, _pad), 12);
    }

    fn raw_with(names: &[&str], flags: u32) -> ExeIdentityRaw {
        // names[0] is the file, the last one the root ("/").
        let mut r = ExeIdentityRaw::zeroed();
        r.flags = flags | exe_flags::KNOWN;
        r.levels = names.len() as u16;
        for (level, n) in names.iter().enumerate() {
            // as the kernel's string read does: the name and its NUL
            let slot = exe_path_slot(level);
            let at = slot * EXE_PATH_SLOT_LEN;
            r.path[at..at + EXE_PATH_SLOT_LEN].fill(0);
            r.path[at..at + n.len()].copy_from_slice(n.as_bytes());
        }
        r
    }

    #[test]
    fn layout_is_fixed() {
        assert_eq!(core::mem::size_of::<ExeIdentityRaw>(), 552);
        assert_eq!(core::mem::align_of::<ExeIdentityRaw>(), 8);
        assert_eq!(core::mem::offset_of!(ExeIdentityRaw, path), 40);
    }

    #[test]
    fn slots_cover_short_paths_one_to_one() {
        for level in 0..EXE_PATH_SLOTS {
            assert_eq!(exe_path_slot(level), level);
        }
        // deeper levels rotate over the last four slots
        assert_eq!(exe_path_slot(16), 12);
        assert_eq!(exe_path_slot(19), 15);
        assert_eq!(exe_path_slot(63), 15);
    }

    #[test]
    fn short_path_is_rebuilt_root_first() {
        let r = raw_with(&["payload", "tmp", "/"], 0);
        assert_eq!(relative_path(&r), "/tmp/payload");
    }

    #[test]
    fn deep_path_keeps_its_top_and_its_file() {
        // 20 levels: x, d18 … d1, tmp, "/"
        let mut names: Vec<String> = vec!["x".to_string()];
        names.extend((1..=17).rev().map(|i| format!("d{i}")));
        names.push("tmp".to_string());
        names.push("/".to_string());
        let refs: Vec<&str> = names.iter().map(String::as_str).collect();
        let r = raw_with(&refs, exe_flags::DEEP);
        let p = relative_path(&r);
        assert!(p.starts_with("/tmp/d1/d2/…/"), "{p}");
        assert!(p.ends_with("/x"), "{p}");
    }

    /// External audit EBPF-021: a 31-byte name may be the first 31 bytes
    /// of a longer one; it is marked, and a shorter one is not.
    #[test]
    fn a_full_length_name_is_marked_as_possibly_cut() {
        let long = "a-build-tool-with-a-long-name-v2"; // 32 bytes, read as 31
        let r = raw_with(&[&long[..31], "bin", "opt", "/"], 0);
        let p = relative_path(&r);
        assert_eq!(p, format!("/opt/bin/{}…", &long[..31]));
        assert!(p.ends_with(EXE_NAME_CUT_MARK));
        let r = raw_with(&["x", &long[..31], "/"], 0);
        assert_eq!(relative_path(&r), format!("/{}…/x", &long[..31]));
        let r = raw_with(&[&long[..30], "tmp", "/"], 0);
        assert_eq!(relative_path(&r), format!("/tmp/{}", &long[..30]));
        // a slot with no NUL at all (not what the kernel writes) reads as
        // 31 bytes and the mark
        let mut r = raw_with(&["x", "tmp", "/"], 0);
        r.path[..EXE_PATH_SLOT_LEN].fill(b'y');
        assert_eq!(relative_path(&r), format!("/tmp/{}…", "y".repeat(31)));
    }

    #[test]
    fn unknown_paths_are_empty() {
        assert_eq!(relative_path(&ExeIdentityRaw::zeroed()), "");
        let r = raw_with(&["x", "a"], exe_flags::UNRESOLVED);
        assert_eq!(relative_path(&r), "");
    }
}
