//! The JSONL file sink (lot 276): one OCSF record per line in
//! `<dir>/export.jsonl`, rotated to `export.jsonl.1` … `export.jsonl.<N-1>`
//! once it would pass its size, the oldest removed — at most
//! `max_files × max_bytes` on disk. A batch is acknowledged once it is
//! written and `fdatasync`ed. Raw system calls only (`openat`, `write`,
//! `fdatasync`, `lseek`, `renameat2`, `unlinkat`, `newfstatat`, `close`):
//! the export worker's seccomp allowlist names exactly these.
//!
//! A configuration's bound holds from the sink's open (the second review of
//! #499, R3): the files an earlier, larger configuration left past it
//! (`export.jsonl.N`, N ≥ `max_files`; regular files only, a link never
//! followed nor removed) are removed, and an active file past `max_bytes`
//! is rotated.
//!
//! A log shipper reading these files is behind the sink: what rotates out
//! before it reads it, it misses (the files are the bound, the chains the
//! record).
//!
//! Lot 296 (external bug hunt BUG31): a write stopped part-way (a full disk:
//! the first `write` takes what fits, the next fails) leaves the start of a
//! line in the active file. The batch is not acknowledged and is written
//! again; its first line used to be glued to that start, one record no
//! longer a line of its own although acknowledged. The sink knows where its
//! last `write` stopped and closes such a line with a newline before the
//! next one; the worker keeps its sink across the error, so that knowledge
//! is not lost.
//!
//! Lot 319 (external bug hunt BUG31's partial): a start left by a process
//! that ended in the middle of a line (a crash, a kill, a power loss) is
//! closed too. The worker cannot read its files (its seccomp list has no
//! `read` of them, and the file is opened write-only), so it does not know
//! how the file it opens ends: a sink opened on a non-empty file closes the
//! line before its first record — a fragment ends there, and a file that
//! ended whole gets one empty line, which `nn-admin export verify` skips (a
//! shipper when configured to: Fluent Bit's `Skip_Empty_Lines`). A record is
//! never glued to a start it does not know of.

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
    /// Lot 296 (BUG31): the active file ends inside a line — the sink's
    /// last `write` stopped before a newline (the start of a line it was not
    /// acknowledged for). The next write closes it first. Lot 319: set at
    /// the open of a non-empty file too (its end is not known).
    torn: bool,
    /// Files rotated out (removed) since the sink opened.
    pub dropped_files: u64,
    /// Files an earlier configuration left past this one's count, removed
    /// at the open.
    pub cleared_files: u64,
}

/// The highest rotated file's number a configuration can have
/// (`file_max_files` is at most 255: `.1` … `.254`).
const MAX_ROTATED: u8 = u8::MAX - 1;

impl JsonlSink {
    /// The sink in `dir` (which must exist), its active file opened.
    pub fn open(dir: &Path, max_bytes: u64, max_files: u8) -> Result<Self, i32> {
        let mut s = Self {
            dir: dir.to_path_buf(),
            max_bytes: max_bytes.max(1),
            max_files: max_files.max(1),
            fd: None,
            size: 0,
            torn: false,
            dropped_files: 0,
            cleared_files: 0,
        };
        s.clear_past_bound()?;
        s.reopen()?;
        // Lot 319 (BUG31's partial): how a non-empty file ends is not known
        // (a dead writer may have left the start of a line): the first
        // write closes the line first.
        s.torn = s.size > 0;
        if s.size > s.max_bytes {
            // written under a larger `max_bytes`: rotated now, not at the
            // next line
            s.rotate()?;
        }
        Ok(s)
    }

    /// Remove each `export.jsonl.N` with N ≥ `max_files` that is a regular
    /// file: what an earlier configuration with more files left (the core
    /// took them for a stranger's files and killed the worker). Its type
    /// is read without following a link (`newfstatat`,
    /// `AT_SYMLINK_NOFOLLOW`); a link, a FIFO or anything else is left as
    /// it is — the core's check of the directory names it.
    fn clear_past_bound(&mut self) -> Result<(), i32> {
        for n in self.max_files..=MAX_ROTATED {
            let p = cpath(&self.path(n))?;
            // SAFETY: an all-zero `stat` is a valid value to be written over.
            let mut st: libc::stat = unsafe { std::mem::zeroed() };
            // SAFETY: newfstatat with a NUL-terminated path into a local
            // `stat`, never following a final link.
            let rc = unsafe {
                libc::syscall(
                    libc::SYS_newfstatat,
                    libc::AT_FDCWD,
                    p.as_ptr(),
                    &mut st as *mut libc::stat,
                    libc::AT_SYMLINK_NOFOLLOW,
                )
            };
            if rc != 0 {
                match errno() {
                    libc::ENOENT => continue,
                    e => return Err(e),
                }
            }
            if st.st_mode & libc::S_IFMT != libc::S_IFREG {
                continue;
            }
            // SAFETY: unlinkat with a NUL-terminated path (a name removed,
            // never a link followed).
            if unsafe { libc::unlinkat(libc::AT_FDCWD, p.as_ptr(), 0) } == 0 {
                self.cleared_files += 1;
            } else if errno() != libc::ENOENT {
                return Err(errno());
            }
        }
        Ok(())
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
        if self.size == 0 {
            // a new active file (a rotation that went through)
            self.torn = false;
        }
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
    /// that would pass the size, then sync. `Ok`: all of them are on disk,
    /// each a line of its own — the start of a line an earlier write left
    /// (it stopped part-way) is closed first.
    pub fn write(&mut self, lines: &[Vec<u8>]) -> Result<(), i32> {
        if self.fd.is_none() {
            self.reopen()?;
        }
        let mut buf: Vec<u8> = Vec::new();
        if self.torn {
            buf.push(b'\n');
        }
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
            if n > 0 {
                self.torn = buf[n as usize - 1] != b'\n';
            }
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
        // a reopened sink appends to the active file — lot 319 (BUG31's
        // partial): after closing the line it cannot know was whole (one
        // empty line, which `nn-admin export verify` skips)
        drop(s);
        let mut s = JsonlSink::open(d.path(), 1 << 20, 3).unwrap();
        assert_eq!(s.size(), 10);
        s.write(&[line(6)]).unwrap();
        assert_eq!(
            files(d.path())[0].1,
            vec![
                "{\"n\":005}".to_string(),
                String::new(),
                "{\"n\":006}".to_string()
            ]
        );
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

    /// The writer of [`the_files_are_the_worker_s_alone`], in a process of
    /// its own (the umask is the process's: the test's threads must not
    /// see it — the second review of #499, N5). A no-op without its
    /// variable.
    #[test]
    #[ignore = "a helper: run by the_files_are_the_worker_s_alone"]
    fn umask_zero_writer() {
        let Some(dir) = std::env::var_os("NN_EXPORT_UMASK_ZERO_DIR") else {
            return;
        };
        // SAFETY: umask of this helper process alone.
        unsafe { libc::umask(0o000) };
        let mut s = JsonlSink::open(Path::new(&dir), 15, 3).unwrap();
        for n in 0..5u32 {
            s.write(&[format!("{{\"n\":{n:03}}}").into_bytes()])
                .unwrap();
        }
    }

    /// Every file of the sink, the active one and each rotated, is the
    /// worker's account's alone (0600), whatever the umask: written by a
    /// process of its own with umask 0.
    #[test]
    fn the_files_are_the_worker_s_alone() {
        use std::os::unix::fs::PermissionsExt;
        let d = tempfile::tempdir().unwrap();
        let st = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--ignored",
                "--exact",
                "jsonl::tests::umask_zero_writer",
                "--test-threads=1",
            ])
            .env("NN_EXPORT_UMASK_ZERO_DIR", d.path())
            .stdout(std::process::Stdio::null())
            .status()
            .unwrap();
        assert!(st.success(), "the writer: {st}");
        let mut seen = 0;
        for e in std::fs::read_dir(d.path()).unwrap() {
            let e = e.unwrap();
            let mode = e.metadata().unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "{:?}", e.file_name());
            seen += 1;
        }
        assert_eq!(seen, 3, "the active file and two rotated");
    }

    /// The second review of #499, R3: a signed configuration with fewer
    /// files — the sink's open removes what the earlier one left past the
    /// new count (regular files), never a link nor what it names.
    #[test]
    fn fewer_files_after_a_new_configuration_are_cleared_at_the_open() {
        let d = tempfile::tempdir().unwrap();
        let mut s = JsonlSink::open(d.path(), 15, 4).unwrap();
        for n in 0..6u32 {
            s.write(&[format!("{{\"n\":{n:03}}}").into_bytes()])
                .unwrap();
        }
        drop(s);
        let names = |d: &Path| files(d).into_iter().map(|f| f.0).collect::<Vec<_>>();
        assert_eq!(
            names(d.path()),
            [
                "export.jsonl",
                "export.jsonl.1",
                "export.jsonl.2",
                "export.jsonl.3"
            ]
        );
        // a link where a rotated file would be, naming a file outside
        let outside = tempfile::tempdir().unwrap();
        let target = outside.path().join("kept");
        std::fs::write(&target, b"kept\n").unwrap();
        std::os::unix::fs::symlink(&target, d.path().join("export.jsonl.9")).unwrap();
        // the next start, signed with file_max_files = 2
        let mut s = JsonlSink::open(d.path(), 15, 2).unwrap();
        assert_eq!(s.cleared_files, 2, "export.jsonl.2 and .3");
        s.write(&[b"{\"n\":999}".to_vec()]).unwrap();
        let mut left: Vec<String> = std::fs::read_dir(d.path())
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        left.sort();
        assert_eq!(left, ["export.jsonl", "export.jsonl.1", "export.jsonl.9"]);
        assert!(std::fs::symlink_metadata(d.path().join("export.jsonl.9"))
            .unwrap()
            .file_type()
            .is_symlink());
        assert_eq!(std::fs::read(&target).unwrap(), b"kept\n");
        // the same count again: nothing to clear
        drop(s);
        let s = JsonlSink::open(d.path(), 15, 2).unwrap();
        assert_eq!(s.cleared_files, 0);
    }

    /// A smaller `max_bytes`: an active file written past it under the
    /// earlier configuration is rotated at the open, not at the next line.
    #[test]
    fn an_active_file_past_a_smaller_size_is_rotated_at_the_open() {
        let d = tempfile::tempdir().unwrap();
        let mut s = JsonlSink::open(d.path(), 1000, 3).unwrap();
        for n in 0..20u32 {
            s.write(&[format!("{{\"n\":{n:03}}}").into_bytes()])
                .unwrap();
        }
        assert_eq!(s.size(), 200);
        drop(s);
        let s = JsonlSink::open(d.path(), 100, 3).unwrap();
        assert_eq!(s.size(), 0, "rotated at the open");
        let f = files(d.path());
        assert_eq!(f[0].0, "export.jsonl");
        assert!(f[0].1.is_empty());
        assert_eq!((f[1].0.as_str(), f[1].1.len()), ("export.jsonl.1", 20));
        // within its size: kept as it is
        drop(s);
        let s = JsonlSink::open(d.path(), 100, 3).unwrap();
        assert_eq!((s.size(), s.dropped_files), (0, 0));
    }

    /// Lot 319 (external bug hunt BUG31, the partial left by lot 296): a
    /// process that died in the middle of a line (a crash, a kill) left its
    /// start in the active file. The next worker's sink did not know — it
    /// cannot read its files (its seccomp list has no `read` of them) — and
    /// its first record was glued to that start: one line, neither record
    /// readable. A sink opened on a non-empty file closes the line first: a
    /// fragment ends there, a file that ended whole gets one empty line
    /// (which `nn-admin export verify` skips), never a glued record.
    #[test]
    fn a_fragment_left_by_a_dead_writer_is_closed_at_open() {
        let d = tempfile::tempdir().unwrap();
        std::fs::write(d.path().join(ACTIVE), b"{\"n\":001}\n{\"n\":0").unwrap();
        let mut s = JsonlSink::open(d.path(), 1 << 20, 3).unwrap();
        s.write(&[b"{\"n\":003}".to_vec()]).unwrap();
        let text = std::fs::read_to_string(d.path().join(ACTIVE)).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(
            lines,
            ["{\"n\":001}", "{\"n\":0", "{\"n\":003}"],
            "the new record a line of its own: {text:?}"
        );
        // a file that ended whole: at most one empty line, every record whole
        drop(s);
        let mut s = JsonlSink::open(d.path(), 1 << 20, 3).unwrap();
        s.write(&[b"{\"n\":004}".to_vec()]).unwrap();
        s.write(&[b"{\"n\":005}".to_vec()]).unwrap();
        let text = std::fs::read_to_string(d.path().join(ACTIVE)).unwrap();
        assert!(
            text.ends_with("{\"n\":003}\n\n{\"n\":004}\n{\"n\":005}\n"),
            "{text:?}"
        );
        // an empty file, or one the open rotates, gets no empty line
        let d = tempfile::tempdir().unwrap();
        let mut s = JsonlSink::open(d.path(), 1 << 20, 3).unwrap();
        s.write(&[b"{\"n\":001}".to_vec()]).unwrap();
        assert_eq!(
            std::fs::read_to_string(d.path().join(ACTIVE)).unwrap(),
            "{\"n\":001}\n"
        );
        drop(s);
        let mut s = JsonlSink::open(d.path(), 5, 3).unwrap();
        s.write(&[b"{\"n\":002}".to_vec()]).unwrap();
        assert_eq!(
            std::fs::read_to_string(d.path().join(ACTIVE)).unwrap(),
            "{\"n\":002}\n"
        );
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
