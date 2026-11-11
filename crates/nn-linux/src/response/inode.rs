//! Lot 312 (external bug hunt, edition 1.4, BUG-90, family F2): whether an
//! executable is gone is the inode's to say — never the name the kernel
//! shows for it.
//!
//! The kernel appends ` (deleted)` to the `/proc` link of a file whose
//! dentry was removed. The quarantine read that suffix as "nothing on disk
//! to quarantine", and it was wrong both ways:
//!
//! - a file ON DISK may carry the suffix in its own name: a payload named
//!   `x (deleted)` was killed by NEUTRALIZE and left on disk, runnable,
//!   while the record said "no binary on disk";
//! - a name removed while another hard link keeps the inode shows the
//!   suffix too: `ln a .b; rm a` after the exec, and the binary lived on as
//!   `.b`.
//!
//! The answer is `st_nlink` of the inode the agent HOLDS open: zero when
//! no name is left anywhere. The suffix stays a hint for one direction
//! only, to distrust a link ([`kernel_marks_deleted`]): the host-critical
//! guard never spares a process whose exe the kernel marks deleted.

use std::os::unix::fs::MetadataExt;
use std::path::Path;

/// Whether the inode `file` holds has no name left anywhere: `fstat`'s
/// `st_nlink == 0` on the held descriptor — an unlinked file, a memfd, an
/// `O_TMPFILE`. A file with a name the agent cannot see (another hard link)
/// is NOT unlinked, whatever `/proc` shows for it.
pub fn exe_unlinked(file: &std::fs::File) -> std::io::Result<bool> {
    Ok(file.metadata()?.nlink() == 0)
}

/// The kernel's mark of a removed dentry at the end of a `/proc` link (`…
/// (deleted)`). A HINT to distrust a link, never a proof that a file is
/// gone: a file on disk may be named so, and a removed name may have a
/// hard link that keeps the inode ([`exe_unlinked`] decides that).
pub fn kernel_marks_deleted(link: &Path) -> bool {
    link.as_os_str()
        .as_encoded_bytes()
        .ends_with(DELETED_MARK.as_bytes())
}

/// What the kernel appends to the path of a removed dentry (`d_path`).
const DELETED_MARK: &str = " (deleted)";

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::PathBuf;

    /// One step of a file's life in a test directory.
    #[derive(Clone, Copy, Debug)]
    enum Step {
        /// A hard link to the inode under a fresh name.
        Link,
        /// A hard link named as the kernel marks a removed dentry.
        LinkNamedDeleted,
        /// Remove one of the inode's names.
        Unlink,
        /// Rename one of its names to `<name> (deleted)`.
        RenameToDeleted,
        /// A file of its own (another inode) under the marked name of one of
        /// the removed names.
        Namesake,
    }

    const STEPS: [Step; 5] = [
        Step::Link,
        Step::LinkNamedDeleted,
        Step::Unlink,
        Step::RenameToDeleted,
        Step::Namesake,
    ];

    /// Property, over every sequence of up to four steps from a file held
    /// open: [`exe_unlinked`] says "gone" exactly when no name of the inode
    /// is left — whatever the names, their suffixes, or the namesakes of
    /// the removed ones. The suffix alone answers wrong on some of them.
    #[test]
    fn unlinked_exactly_when_no_name_is_left() {
        let mut checked = 0;
        let mut suffix_wrong = 0;
        let n = STEPS.len();
        for len in 0..=4u32 {
            for code in 0..n.pow(len) {
                let seq: Vec<Step> = (0..len).map(|i| STEPS[(code / n.pow(i)) % n]).collect();
                let tmp = tempfile::TempDir::new().unwrap();
                let first = tmp.path().join("payload");
                fs::write(&first, b"x").unwrap();
                let held = fs::File::open(&first).unwrap();
                let mut names: Vec<PathBuf> = vec![first];
                let mut removed: Vec<PathBuf> = Vec::new();
                for (i, s) in seq.iter().enumerate() {
                    match s {
                        Step::Link if !names.is_empty() => {
                            let to = tmp.path().join(format!("link{i}"));
                            fs::hard_link(&names[0], &to).unwrap();
                            names.push(to);
                        }
                        Step::LinkNamedDeleted if !names.is_empty() => {
                            let to = tmp.path().join(format!("payload{i} (deleted)"));
                            fs::hard_link(&names[0], &to).unwrap();
                            names.push(to);
                        }
                        Step::Unlink if !names.is_empty() => {
                            let gone = names.remove(0);
                            fs::remove_file(&gone).unwrap();
                            removed.push(gone);
                        }
                        Step::RenameToDeleted if !names.is_empty() => {
                            let from = names.remove(0);
                            let to = PathBuf::from(format!("{} (deleted)", from.display()));
                            if !to.exists() {
                                fs::rename(&from, &to).unwrap();
                                names.push(to);
                            } else {
                                names.insert(0, from);
                            }
                        }
                        Step::Namesake => {
                            if let Some(r) = removed.last() {
                                let p = PathBuf::from(format!("{} (deleted)", r.display()));
                                if !p.exists() {
                                    fs::write(&p, b"other").unwrap();
                                }
                            }
                        }
                        _ => {}
                    }
                }
                let gone = names.is_empty();
                assert_eq!(exe_unlinked(&held).unwrap(), gone, "{seq:?}");
                let link = fs::read_link(format!("/proc/self/fd/{}", held_fd(&held))).unwrap();
                if kernel_marks_deleted(&link) != gone {
                    suffix_wrong += 1;
                }
                checked += 1;
            }
        }
        assert!(checked > 700, "{checked}");
        assert!(
            suffix_wrong > 0,
            "premise: the suffix answers wrong on some sequences"
        );
    }

    fn held_fd(f: &fs::File) -> i32 {
        use std::os::fd::AsRawFd;
        f.as_raw_fd()
    }

    /// A memfd and an `O_TMPFILE` have no name: unlinked from the start.
    #[test]
    fn a_memfd_and_a_tmpfile_are_unlinked() {
        use std::os::fd::FromRawFd;
        // SAFETY: memfd_create with a NUL-terminated name; the fd is owned
        // by the File below.
        let fd = unsafe { libc::memfd_create(c"nn-test".as_ptr(), libc::MFD_CLOEXEC) };
        assert!(fd >= 0);
        // SAFETY: a fresh fd owned by nobody else.
        let memfd = unsafe { fs::File::from_raw_fd(fd) };
        assert!(exe_unlinked(&memfd).unwrap());
        let tmp = tempfile::TempDir::new().unwrap();
        use std::os::unix::fs::OpenOptionsExt;
        if let Ok(t) = fs::OpenOptions::new()
            .write(true)
            .custom_flags(libc::O_TMPFILE)
            .open(tmp.path())
        {
            assert!(exe_unlinked(&t).unwrap());
        }
    }

    #[test]
    fn the_mark_is_only_the_kernels_suffix() {
        assert!(kernel_marks_deleted(Path::new("/tmp/x (deleted)")));
        assert!(!kernel_marks_deleted(Path::new("/tmp/x (deleted) ")));
        assert!(!kernel_marks_deleted(Path::new("/tmp/x(deleted)")));
        assert!(!kernel_marks_deleted(Path::new("/tmp/x")));
    }
}
