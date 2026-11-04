//! The JSONL file sink (lot 276): one OCSF record per line in
//! `<dir>/export.jsonl`, rotated to `export.jsonl.1` … `export.jsonl.<N-1>`
//! once it would pass its size, the oldest removed — at most
//! `max_files × max_bytes` on disk. A batch is acknowledged once it is
//! written and `fdatasync`ed. Raw system calls only (`openat`, `write`,
//! `fdatasync`, `lseek`, `renameat2`, `unlinkat`, `close`): the export
//! worker's seccomp allowlist names exactly these.
//!
//! A log shipper reading these files is behind the sink: what rotates out
//! before it reads it, it misses (the files are the bound, the chains the
//! record).

use std::ffi::CString;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::path::{Path, PathBuf};

/// The active file's name.
pub const ACTIVE: &str = nn_proto::ipc::EXPORT_FILE;

/// `openat`'s flags for the active file: append-only, never through a
/// link (the worker's allowlist keeps `openat` with exactly these).
pub const OPEN_FLAGS: libc::c_int =
    libc::O_WRONLY | libc::O_CREAT | libc::O_APPEND | libc::O_CLOEXEC | libc::O_NOFOLLOW;

/// The files' mode: the worker's account alone (and root) reads them —
/// whatever the umask (the review of #499, D8).
pub const FILE_MODE: libc::mode_t = 0o600;

fn errno() -> i32 {
    std::io::Error::last_os_error()
        .raw_os_error()
        .unwrap_or(libc::EIO)
}

fn cpath(p: &Path) -> Result<CString, i32> {
    use std::os::unix::ffi::OsStrExt;
    CString::new(p.as_os_str().as_bytes()).map_err(|_| libc::EINVAL)
}

/// The rotating file sink.
#[derive(Debug)]
pub struct JsonlSink {
    dir: PathBuf,
    max_bytes: u64,
    max_files: u8,
    fd: Option<OwnedFd>,
    size: u64,
    /// Files rotated out (removed) since the sink opened.
    pub dropped_files: u64,
}

impl JsonlSink {
    /// The sink in `dir` (which must exist), its active file opened.
    pub fn open(dir: &Path, max_bytes: u64, max_files: u8) -> Result<Self, i32> {
        let mut s = Self {
            dir: dir.to_path_buf(),
            max_bytes: max_bytes.max(1),
            max_files: max_files.max(1),
            fd: None,
            size: 0,
            dropped_files: 0,
        };
        s.reopen()?;
        Ok(s)
    }

    fn path(&self, n: u8) -> PathBuf {
        if n == 0 {
            self.dir.join(ACTIVE)
        } else {
            self.dir.join(format!("{ACTIVE}.{n}"))
        }
    }

    fn reopen(&mut self) -> Result<(), i32> {
        self.fd = None;
        let p = cpath(&self.path(0))?;
        // SAFETY: openat with a NUL-terminated path and integer flags.
        let fd = unsafe {
            libc::openat(
                libc::AT_FDCWD,
                p.as_ptr(),
                OPEN_FLAGS,
                libc::c_uint::from(FILE_MODE),
            )
        };
        if fd < 0 {
            return Err(errno());
        }
        // SAFETY: a descriptor we just opened and own.
        let fd = unsafe { OwnedFd::from_raw_fd(fd) };
        // SAFETY: lseek on our own descriptor.
        let end = unsafe { libc::lseek(fd.as_raw_fd(), 0, libc::SEEK_END) };
        if end < 0 {
            return Err(errno());
        }
        self.size = end as u64;
        self.fd = Some(fd);
        Ok(())
    }

    /// Rotate: `.N-1` removed, each `.k` to `.k+1`, the active file to
    /// `.1`, a new active file.
    fn rotate(&mut self) -> Result<(), i32> {
        self.fd = None;
        let last = self.max_files - 1;
        let unlink = |p: PathBuf| -> Result<bool, i32> {
            let c = cpath(&p)?;
            // SAFETY: unlinkat with a NUL-terminated path.
            if unsafe { libc::unlinkat(libc::AT_FDCWD, c.as_ptr(), 0) } == 0 {
                return Ok(true);
            }
            match errno() {
                libc::ENOENT => Ok(false),
                e => Err(e),
            }
        };
        if last == 0 {
            if unlink(self.path(0))? {
                self.dropped_files += 1;
            }
            return self.reopen();
        }
        if unlink(self.path(last))? {
            self.dropped_files += 1;
        }
        for k in (0..last).rev() {
            let (from, to) = (cpath(&self.path(k))?, cpath(&self.path(k + 1))?);
            // SAFETY: renameat2 with NUL-terminated paths, flags 0.
            let rc = unsafe {
                libc::syscall(
                    libc::SYS_renameat2,
                    libc::AT_FDCWD,
                    from.as_ptr(),
                    libc::AT_FDCWD,
                    to.as_ptr(),
                    0u32,
                )
            };
            if rc != 0 && errno() != libc::ENOENT {
                return Err(errno());
            }
        }
        self.reopen()
    }

    /// Append `lines` (each without its newline), rotating before a line
    /// that would pass the size, then sync. `Ok`: all of them are on disk.
    pub fn write(&mut self, lines: &[Vec<u8>]) -> Result<(), i32> {
        if self.fd.is_none() {
            self.reopen()?;
        }
        let mut buf: Vec<u8> = Vec::new();
        for l in lines {
            let need = l.len() as u64 + 1;
            if self.size + buf.len() as u64 + need > self.max_bytes
                && self.size + buf.len() as u64 > 0
            {
                self.flush(&buf)?;
                buf.clear();
                self.sync()?;
                self.rotate()?;
            }
            buf.extend_from_slice(l);
            buf.push(b'\n');
        }
        self.flush(&buf)?;
        self.sync()
    }

    fn flush(&mut self, mut buf: &[u8]) -> Result<(), i32> {
        let fd = self.fd.as_ref().ok_or(libc::EBADF)?.as_raw_fd();
        while !buf.is_empty() {
            // SAFETY: write from a live buffer on our own descriptor.
            let n = unsafe { libc::write(fd, buf.as_ptr().cast(), buf.len()) };
            if n < 0 {
                let e = errno();
                if e == libc::EINTR {
                    continue;
                }
                // the file is in an unknown state: reopened at the next write
                self.fd = None;
                return Err(e);
            }
            self.size += n as u64;
            buf = &buf[n as usize..];
        }
        Ok(())
    }

    fn sync(&mut self) -> Result<(), i32> {
        let fd = self.fd.as_ref().ok_or(libc::EBADF)?.as_raw_fd();
        // SAFETY: fdatasync on our own descriptor.
        if unsafe { libc::fdatasync(fd) } != 0 {
            let e = errno();
            self.fd = None;
            return Err(e);
        }
        Ok(())
    }

    /// The active file's size.
    pub fn size(&self) -> u64 {
        self.size
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn files(dir: &Path) -> Vec<(String, Vec<String>)> {
        let mut v: Vec<_> = std::fs::read_dir(dir)
            .unwrap()
            .map(|e| {
                let e = e.unwrap();
                let lines = std::fs::read_to_string(e.path())
                    .unwrap()
                    .lines()
                    .map(str::to_string)
                    .collect();
                (e.file_name().to_string_lossy().into_owned(), lines)
            })
            .collect();
        v.sort();
        v
    }

    #[test]
    fn lines_are_appended_rotated_and_bounded() {
        let d = tempfile::tempdir().unwrap();
        let mut s = JsonlSink::open(d.path(), 15, 3).unwrap();
        let line = |n: u32| format!("{{\"n\":{n:03}}}").into_bytes(); // 9 bytes + \n
        s.write(&[line(1)]).unwrap();
        assert_eq!(s.size(), 10);
        s.write(&[line(2), line(3)]).unwrap();
        // 3 rotated the file: the active holds one line
        assert_eq!(
            files(d.path()),
            vec![
                ("export.jsonl".into(), vec!["{\"n\":003}".into()]),
                ("export.jsonl.1".into(), vec!["{\"n\":002}".into()]),
                ("export.jsonl.2".into(), vec!["{\"n\":001}".into()]),
            ]
        );
        assert_eq!(s.dropped_files, 0);
        s.write(&[line(4), line(5)]).unwrap();
        let f = files(d.path());
        assert_eq!(f.len(), 3, "at most three files: {f:?}");
        assert_eq!(f[0].1, vec!["{\"n\":005}".to_string()]);
        assert_eq!(f[2].1, vec!["{\"n\":003}".to_string()]);
        assert_eq!(s.dropped_files, 2);
        // a reopened sink appends to the active file
        drop(s);
        let mut s = JsonlSink::open(d.path(), 1 << 20, 3).unwrap();
        assert_eq!(s.size(), 10);
        s.write(&[line(6)]).unwrap();
        assert_eq!(files(d.path())[0].1.len(), 2);
        // a line longer than the size is written whole, in a file of its own
        let mut s = JsonlSink::open(d.path(), 20, 1).unwrap();
        s.write(&[vec![b'x'; 40]]).unwrap();
        assert_eq!(files(d.path())[0].1, vec!["x".repeat(40)]);
    }

    /// A line longer than a file goes whole into an empty active file: no
    /// empty file rotated in, no older one dropped for it.
    #[test]
    fn a_long_line_does_not_rotate_an_empty_file() {
        let d = tempfile::tempdir().unwrap();
        let mut s = JsonlSink::open(d.path(), 15, 2).unwrap();
        s.write(&[b"x".repeat(5)]).unwrap();
        s.write(&[b"y".repeat(40)]).unwrap();
        // the 40 bytes rotated the 5 out, then went into the empty file
        let long = || vec!["y".repeat(40)];
        assert_eq!(
            files(d.path()),
            vec![
                ("export.jsonl".into(), long()),
                ("export.jsonl.1".into(), vec!["xxxxx".into()]),
            ]
        );
        assert_eq!(s.dropped_files, 0);
        // a fresh sink's first line, longer than a file: no rotation
        let d = tempfile::tempdir().unwrap();
        let mut s = JsonlSink::open(d.path(), 15, 2).unwrap();
        s.write(&[b"y".repeat(40)]).unwrap();
        assert_eq!(files(d.path()), vec![("export.jsonl".into(), long())]);
        assert_eq!(s.dropped_files, 0);
    }

    /// Every file of the sink, the active one and each rotated, is the
    /// worker's account's alone (0600), whatever the umask.
    #[test]
    fn the_files_are_the_worker_s_alone() {
        use std::os::unix::fs::PermissionsExt;
        let d = tempfile::tempdir().unwrap();
        // SAFETY: umask of this test process, restored below.
        let before = unsafe { libc::umask(0o000) };
        let mut s = JsonlSink::open(d.path(), 15, 3).unwrap();
        for n in 0..5u32 {
            s.write(&[format!("{{\"n\":{n:03}}}").into_bytes()])
                .unwrap();
        }
        // SAFETY: restoring the umask.
        unsafe { libc::umask(before) };
        let mut seen = 0;
        for e in std::fs::read_dir(d.path()).unwrap() {
            let e = e.unwrap();
            let mode = e.metadata().unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "{:?}", e.file_name());
            seen += 1;
        }
        assert_eq!(seen, 3, "the active file and two rotated");
    }

    #[test]
    fn a_missing_directory_or_a_link_is_refused() {
        let d = tempfile::tempdir().unwrap();
        assert_eq!(
            JsonlSink::open(&d.path().join("none"), 100, 2).unwrap_err(),
            libc::ENOENT
        );
        std::os::unix::fs::symlink("/etc/passwd", d.path().join(ACTIVE)).unwrap();
        assert_eq!(
            JsonlSink::open(d.path(), 100, 2).unwrap_err(),
            libc::ELOOP,
            "O_NOFOLLOW"
        );
    }
}
