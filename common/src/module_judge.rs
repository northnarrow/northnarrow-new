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
    if created {
        return if pkg {
            write_flag::PKG
        } else {
            write_flag::TAINT
        };
    }
    match prev {
        None => write_flag::TAINT,
        Some(p) if pkg => p,
        Some(p) => p | write_flag::TAINT,
    }
}

/// The history says a package transaction wrote the file, and nothing else
/// did.
#[inline(always)]
pub const fn written_by_package(history: Option<u32>) -> bool {
    matches!(history, Some(write_flag::PKG))
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
