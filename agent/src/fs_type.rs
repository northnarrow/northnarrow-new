//! Filesystem type of a path or an open file, by `statfs(2)` magic.
//!
//! External audit NN-AUD-098: shared by the tracefs provenance check of
//! the tracepoint offsets (`anti_tamper::btf_revalidate`) and the lab
//! feasibility report.

use std::ffi::CString;
use std::fs::File;
use std::os::fd::AsRawFd;
use std::path::Path;

/// `TRACEFS_MAGIC` (`include/uapi/linux/magic.h`). `/sys/kernel/tracing`
/// and the `/sys/kernel/debug/tracing` automount are both tracefs.
pub const TRACEFS_MAGIC: u64 = 0x7472_6163;

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
