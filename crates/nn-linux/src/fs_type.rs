//! Filesystem type of a path or an open file, by `statfs(2)` magic.
//!
//! External audit NN-AUD-098: shared by the tracefs provenance check of
//! the tracepoint offsets (`anti_tamper::btf_revalidate`) and the lab
//! feasibility report.
//!
//! External audit EBPF-016 (NN-AUD-267): the ledger of paths the agent
//! keys by `(dev, ino)` — protected inodes, FIM watches — on a filesystem
//! where `stat()` and the eBPF hooks may not see the same pair
//! ([`identity_unverified_fs`]): one signed `subsystem_degraded` per boot
//! names them ([`take_identity_report`]).

use std::collections::BTreeMap;
use std::ffi::CString;
use std::fs::File;
use std::os::fd::AsRawFd;
use std::path::Path;

/// `TRACEFS_MAGIC` (`include/uapi/linux/magic.h`). `/sys/kernel/tracing`
/// and the `/sys/kernel/debug/tracing` automount are both tracefs.
pub const TRACEFS_MAGIC: u64 = 0x7472_6163;

/// `OVERLAYFS_SUPER_MAGIC` (`include/uapi/linux/magic.h`).
pub const OVERLAYFS_SUPER_MAGIC: u64 = 0x794c_7630;
/// `FUSE_SUPER_MAGIC` (`fs/fuse/inode.c`).
pub const FUSE_SUPER_MAGIC: u64 = 0x6573_5546;
/// `NFS_SUPER_MAGIC` (`include/uapi/linux/magic.h`).
pub const NFS_SUPER_MAGIC: u64 = 0x6969;

/// External audit EBPF-016 (NN-AUD-267): the name of a filesystem on which
/// the agent cannot vouch that the key userland computes with `stat()` is
/// the `(dev, ino)` the eBPF hooks read from the kernel's inode
/// (`agent-ebpf/src/inode_dev.rs` handles btrfs and takes `s_dev`
/// elsewhere). overlayfs reports the device and inode of the layer that
/// holds the file (`ovl_getattr`), not those of the overlay inode the
/// hooks see; FUSE and NFS take inode numbers from a server or a daemon,
/// and the file a hook sees can be another inode than the one stat named.
/// A key that does not match fails silently both ways: no deny, no FIM
/// record.
pub fn identity_unverified_fs(magic: u64) -> Option<&'static str> {
    match magic {
        OVERLAYFS_SUPER_MAGIC => Some("overlayfs"),
        FUSE_SUPER_MAGIC => Some("fuse"),
        NFS_SUPER_MAGIC => Some("nfs"),
        _ => None,
    }
}

/// How many paths per filesystem the boot record names.
const REPORT_PATHS: usize = 5;

/// Paths keyed by `(dev, ino)` on a filesystem of
/// [`identity_unverified_fs`], by filesystem: their count and the first
/// [`REPORT_PATHS`].
#[derive(Debug, Default)]
pub struct IdentityLedger {
    by_fs: BTreeMap<&'static str, (usize, Vec<String>)>,
    reported: bool,
}

/// The boot's record of [`IdentityLedger`]: what one signed
/// `subsystem_degraded` (`reason: inode_identity_unverified`) says.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdentityReport {
    /// `(filesystem, paths, first paths)`.
    pub filesystems: Vec<(&'static str, usize, Vec<String>)>,
}

impl IdentityReport {
    /// The sentence of the journal line and the signed record.
    pub fn detail(&self) -> String {
        let parts: Vec<String> = self
            .filesystems
            .iter()
            .map(|(fs, n, first)| format!("{fs}: {n} path(s), first {}", first.join(", ")))
            .collect();
        format!(
            "inode identity unverified — protected or watched paths on a filesystem where the \
             agent cannot vouch that stat() and the eBPF hooks see the same (dev, ino); a key \
             that does not match is neither denied nor recorded ({})",
            parts.join("; ")
        )
    }

    /// The `extra` of the signed `subsystem_degraded`.
    pub fn audit_extra(&self) -> serde_json::Value {
        let fs: serde_json::Map<String, serde_json::Value> = self
            .filesystems
            .iter()
            .map(|(name, n, first)| {
                (
                    name.to_string(),
                    serde_json::json!({ "count": n, "first_paths": first }),
                )
            })
            .collect();
        serde_json::json!({
            "kind": "subsystem_degraded",
            "reason": "inode_identity_unverified",
            "detail": self.detail(),
            "filesystems": fs,
            "at_boot": true,
        })
    }
}

impl IdentityLedger {
    /// Record `path`, whose filesystem has `magic`; `true` when it is on a
    /// filesystem of [`identity_unverified_fs`] that the boot record did
    /// not name (a path enrolled after it: WARN once by the caller).
    pub fn note(&mut self, path: &Path, magic: Option<u64>) -> bool {
        let Some(fs) = magic.and_then(identity_unverified_fs) else {
            return false;
        };
        let reported = self.reported;
        let entry = self.by_fs.entry(fs).or_insert((0, Vec::new()));
        let first_sighting = entry.0 == 0;
        entry.0 += 1;
        if entry.1.len() < REPORT_PATHS {
            entry.1.push(path.display().to_string());
        }
        reported && first_sighting
    }

    /// The boot record: `None` when no path is on such a filesystem. Taken
    /// once; later notes only say whether a filesystem is new.
    pub fn report(&mut self) -> Option<IdentityReport> {
        self.reported = true;
        if self.by_fs.is_empty() {
            return None;
        }
        Some(IdentityReport {
            filesystems: self
                .by_fs
                .iter()
                .map(|(fs, (n, first))| (*fs, *n, first.clone()))
                .collect(),
        })
    }
}

static LEDGER: parking_lot::Mutex<IdentityLedger> = parking_lot::Mutex::new(IdentityLedger {
    by_fs: BTreeMap::new(),
    reported: false,
});

/// External audit EBPF-016: note a path the agent just keyed by
/// `(dev, ino)` (a protected inode, a FIM watch). A path on such a
/// filesystem enrolled after the boot record, on one it did not name, is
/// a WARN.
pub fn note_identity(path: &Path) {
    let magic = magic_of_path(path);
    if LEDGER.lock().note(path, magic) {
        tracing::warn!(
            path = %nn_model::log_escape::Escaped(path.display()),
            fs = magic.and_then(identity_unverified_fs).unwrap_or("?"),
            "inode identity unverified — a path enrolled after boot is on a filesystem where \
             stat() and the eBPF hooks may not see the same (dev, ino): it may be neither \
             denied nor recorded"
        );
    }
}

/// The boot record of the paths noted so far ([`IdentityLedger::report`]).
pub fn take_identity_report() -> Option<IdentityReport> {
    LEDGER.lock().report()
}

/// `statfs` type of the filesystem holding `path` (automounts followed).
pub fn magic_of_path(path: &Path) -> Option<u64> {
    let c = CString::new(path.as_os_str().as_encoded_bytes()).ok()?;
    // SAFETY: `statfs` is plain old data, valid when zeroed.
    let mut st: libc::statfs = unsafe { std::mem::zeroed() };
    // SAFETY: `c` is NUL-terminated and `st` is a valid, writable statfs.
    (unsafe { libc::statfs(c.as_ptr(), &mut st) } == 0).then_some(st.f_type as u64)
}

/// `fstatfs` type of the filesystem an open file lives on: the file that
/// was opened, whatever is mounted at its path afterwards.
pub fn magic_of_file(file: &File) -> Option<u64> {
    // SAFETY: `statfs` is plain old data, valid when zeroed.
    let mut st: libc::statfs = unsafe { std::mem::zeroed() };
    // SAFETY: the fd is borrowed from a live `File`; `st` is writable.
    (unsafe { libc::fstatfs(file.as_raw_fd(), &mut st) } == 0).then_some(st.f_type as u64)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// External audit EBPF-016 (NN-AUD-267): a path registered on
    /// overlayfs, FUSE or NFS is counted and named in the boot record;
    /// one on another filesystem is not; a later path on a filesystem the
    /// record did not name is flagged for its WARN.
    #[test]
    fn registration_on_overlay_is_attested() {
        let mut l = IdentityLedger::default();
        assert!(!l.note(Path::new("/etc/shadow"), Some(0xEF53)), "ext4");
        assert!(!l.note(Path::new("/x"), None), "no statfs");
        assert_eq!(IdentityLedger::default().report(), None);
        for i in 0..7 {
            l.note(
                Path::new(&format!("/etc/northnarrow/f{i}")),
                Some(OVERLAYFS_SUPER_MAGIC),
            );
        }
        l.note(Path::new("/home/u/.ssh/id_ed25519"), Some(NFS_SUPER_MAGIC));
        let r = l.report().expect("overlay paths are reported");
        assert_eq!(r.filesystems.len(), 2);
        let (fs, n, first) = &r.filesystems[1];
        assert_eq!((*fs, *n, first.len()), ("overlayfs", 7, REPORT_PATHS));
        assert_eq!(first[0], "/etc/northnarrow/f0");
        let extra = r.audit_extra();
        assert_eq!(extra["kind"], "subsystem_degraded");
        assert_eq!(extra["reason"], "inode_identity_unverified");
        assert_eq!(extra["filesystems"]["overlayfs"]["count"], 7);
        assert_eq!(extra["filesystems"]["nfs"]["count"], 1);
        assert!(
            r.detail().contains("overlayfs: 7 path(s)"),
            "{}",
            r.detail()
        );
        // after the record: a known filesystem is not new, FUSE is
        assert!(!l.note(Path::new("/etc/northnarrow/g"), Some(OVERLAYFS_SUPER_MAGIC)));
        assert!(l.note(Path::new("/mnt/f/x"), Some(FUSE_SUPER_MAGIC)));
        assert!(!l.note(Path::new("/mnt/f/y"), Some(FUSE_SUPER_MAGIC)));
    }

    #[test]
    fn path_and_file_agree_and_a_missing_path_has_none() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("f");
        std::fs::write(&p, "x").unwrap();
        let by_path = magic_of_path(dir.path()).expect("statfs on a temp dir");
        assert_eq!(magic_of_file(&File::open(&p).unwrap()), Some(by_path));
        assert_eq!(magic_of_path(Path::new("/nonexistent/nn-fs-type")), None);
    }
}
