//! Taking the copy: a reflink when the filesystem shares extents, else a
//! bounded byte copy, inside the event's time budget.
//!
//! `FICLONE` (XFS with `reflink=1`, btrfs, bcachefs) makes the journal
//! object share the file's extents: constant time whatever the size, and
//! the filesystem copies a block only when the writer changes it. It needs
//! the object on the same filesystem *and the same mount* as the file
//! (`EXDEV` otherwise), which is why each scope has its journal on its own
//! filesystem and why both are reached through the host's mount namespace.
//! Elsewhere (ext4, tmpfs) the content is copied with `copy_file_range`
//! (in the kernel, page cache to page cache; it may reflink by itself on a
//! filesystem that can), else `pread`/`write`, in 1 MiB steps with the
//! deadline checked between them, for files up to the copy cap. A copy
//! that misses its deadline, or whose source changed while it ran (a
//! writer that opened the file earlier), is deleted: no object is better
//! than a torn one.

use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::time::Instant;

/// What one attempt produced.
#[derive(Debug)]
pub enum Snapshot {
    /// The object shares the file's extents.
    Reflinked { bytes: u64 },
    /// The object is a byte copy.
    Copied { bytes: u64 },
    /// No reflink, and the file is over the copy cap: not protected.
    OverCap,
    /// The deadline passed during the copy: deleted, not protected.
    Deadline,
    /// The source changed while it was copied: deleted, not protected.
    SourceChanged,
    /// The object could not be created or written.
    Failed(io::Error),
}

const CHUNK: usize = 1 << 20;

fn unlink_at(dir: RawFd, name: &std::ffi::CStr) {
    // SAFETY: valid directory descriptor and NUL-terminated name.
    unsafe { libc::unlinkat(dir, name.as_ptr(), 0) };
}

/// Create `name` (new, 0600, no link followed) in the directory `dir`.
pub fn create_object(dir: RawFd, name: &std::ffi::CStr) -> io::Result<OwnedFd> {
    // SAFETY: valid descriptor, NUL-terminated name.
    let fd = unsafe {
        libc::openat(
            dir,
            name.as_ptr(),
            libc::O_CREAT | libc::O_EXCL | libc::O_WRONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            0o600,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: fresh descriptor we own.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

/// `ioctl(dst, FICLONE, src)`.
pub fn reflink(src: RawFd, dst: RawFd) -> io::Result<()> {
    // SAFETY: two valid descriptors; FICLONE takes the source fd by value.
    let rc = unsafe { libc::ioctl(dst, libc::FICLONE, src) };
    if rc < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

fn copy_file_range(
    src: RawFd,
    off_in: &mut i64,
    dst: RawFd,
    off_out: &mut i64,
    len: usize,
) -> io::Result<usize> {
    // SAFETY: valid descriptors and offset pointers; len bounded.
    let n = unsafe {
        libc::syscall(
            libc::SYS_copy_file_range,
            src,
            off_in as *mut i64,
            dst,
            off_out as *mut i64,
            len,
            0u32,
        )
    };
    if n < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(n as usize)
    }
}

fn pread_write(
    src: RawFd,
    off: &mut i64,
    dst: RawFd,
    len: usize,
    buf: &mut Vec<u8>,
) -> io::Result<usize> {
    buf.resize(len, 0);
    // SAFETY: valid descriptor and a buffer of `len` bytes.
    let n = unsafe { libc::pread(src, buf.as_mut_ptr() as *mut libc::c_void, len, *off) };
    if n < 0 {
        return Err(io::Error::last_os_error());
    }
    let n = n as usize;
    let mut done = 0usize;
    while done < n {
        // SAFETY: the slice is within `buf`.
        let w = unsafe {
            libc::pwrite(
                dst,
                buf[done..n].as_ptr() as *const libc::c_void,
                n - done,
                *off + done as i64,
            )
        };
        if w < 0 {
            return Err(io::Error::last_os_error());
        }
        done += w as usize;
    }
    *off += n as i64;
    Ok(n)
}

/// Same size and modification time as `before` (the source did not
/// change while it was copied).
fn unchanged(src: RawFd, before: &libc::stat) -> bool {
    match super::fanotify::fstat(src) {
        Ok(now) => {
            now.st_size == before.st_size
                && now.st_mtime == before.st_mtime
                && now.st_mtime_nsec == before.st_mtime_nsec
        }
        Err(_) => false,
    }
}

/// Copy `src` (its state `st`) into a new object `name` of `dir`: reflink,
/// else a copy of at most `cap` bytes finished before `deadline`.
pub fn snapshot(
    src: RawFd,
    st: &libc::stat,
    dir: RawFd,
    name: &std::ffi::CStr,
    cap: u64,
    deadline: Instant,
) -> Snapshot {
    let size = st.st_size.max(0) as u64;
    let dst = match create_object(dir, name) {
        Ok(fd) => fd,
        Err(e) => return Snapshot::Failed(e),
    };
    if reflink(src, dst.as_raw_fd()).is_ok() {
        return Snapshot::Reflinked { bytes: size };
    }
    if size > cap {
        drop(dst);
        unlink_at(dir, name);
        return Snapshot::OverCap;
    }
    let mut off_in = 0i64;
    let mut off_out = 0i64;
    let mut plain = false;
    let mut buf = Vec::new();
    while (off_in as u64) < size {
        if Instant::now() >= deadline {
            drop(dst);
            unlink_at(dir, name);
            return Snapshot::Deadline;
        }
        let len = CHUNK.min((size - off_in as u64) as usize);
        let step = if plain {
            let r = pread_write(src, &mut off_in, dst.as_raw_fd(), len, &mut buf);
            off_out = off_in;
            r
        } else {
            match copy_file_range(src, &mut off_in, dst.as_raw_fd(), &mut off_out, len) {
                Err(e)
                    if matches!(
                        e.raw_os_error(),
                        Some(
                            libc::EXDEV
                                | libc::EINVAL
                                | libc::ENOSYS
                                | libc::EOPNOTSUPP
                                | libc::EBADF
                        )
                    ) =>
                {
                    plain = true;
                    continue;
                }
                r => r,
            }
        };
        match step {
            Ok(0) => break, // the file shrank: caught below
            Ok(_) => {}
            Err(e) => {
                drop(dst);
                unlink_at(dir, name);
                return Snapshot::Failed(e);
            }
        }
    }
    if !unchanged(src, st) || off_out as u64 != size {
        drop(dst);
        unlink_at(dir, name);
        return Snapshot::SourceChanged;
    }
    Snapshot::Copied { bytes: size }
}

/// SHA-256 of a file's content, read from `fd` (hex).
pub fn sha256_fd(fd: RawFd) -> io::Result<String> {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    let mut buf = vec![0u8; CHUNK];
    let mut off = 0i64;
    loop {
        // SAFETY: valid descriptor and buffer.
        let n = unsafe { libc::pread(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len(), off) };
        if n < 0 {
            return Err(io::Error::last_os_error());
        }
        if n == 0 {
            break;
        }
        h.update(&buf[..n as usize]);
        off += n as i64;
    }
    Ok(hex::encode(h.finalize()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CString;
    use std::time::Duration;

    fn dir_fd(p: &std::path::Path) -> OwnedFd {
        let c = CString::new(p.as_os_str().as_encoded_bytes()).unwrap();
        // SAFETY: NUL-terminated path.
        let fd = unsafe {
            libc::open(
                c.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
            )
        };
        assert!(fd >= 0);
        // SAFETY: fresh descriptor.
        unsafe { OwnedFd::from_raw_fd(fd) }
    }

    fn source(dir: &std::path::Path, bytes: &[u8]) -> (std::fs::File, libc::stat) {
        let p = dir.join("src");
        std::fs::write(&p, bytes).unwrap();
        let f = std::fs::File::open(&p).unwrap();
        let st = super::super::fanotify::fstat(f.as_raw_fd()).unwrap();
        (f, st)
    }

    #[test]
    fn a_copy_is_byte_identical_and_hashes_the_same() {
        let t = tempfile::TempDir::new().unwrap();
        let data: Vec<u8> = (0..(3 * CHUNK + 17))
            .map(|i| (i * 31 % 251) as u8)
            .collect();
        let (src, st) = source(t.path(), &data);
        let d = dir_fd(t.path());
        let name = CString::new("obj1").unwrap();
        let out = snapshot(
            src.as_raw_fd(),
            &st,
            d.as_raw_fd(),
            &name,
            16 << 20,
            Instant::now() + Duration::from_secs(10),
        );
        match out {
            Snapshot::Reflinked { bytes } | Snapshot::Copied { bytes } => {
                assert_eq!(bytes, data.len() as u64)
            }
            other => panic!("{other:?}"),
        }
        let copy = std::fs::read(t.path().join("obj1")).unwrap();
        assert_eq!(copy, data);
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(t.path().join("obj1"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        let obj = std::fs::File::open(t.path().join("obj1")).unwrap();
        assert_eq!(
            sha256_fd(obj.as_raw_fd()).unwrap(),
            sha256_fd(src.as_raw_fd()).unwrap()
        );
        // never over an existing object
        let again = snapshot(
            src.as_raw_fd(),
            &st,
            d.as_raw_fd(),
            &name,
            16 << 20,
            Instant::now() + Duration::from_secs(10),
        );
        assert!(matches!(again, Snapshot::Failed(_)), "{again:?}");
    }

    #[test]
    fn over_the_cap_or_late_leaves_nothing() {
        let t = tempfile::TempDir::new().unwrap();
        let (src, st) = source(t.path(), &vec![7u8; 4096]);
        let d = dir_fd(t.path());
        let name = CString::new("big").unwrap();
        match snapshot(
            src.as_raw_fd(),
            &st,
            d.as_raw_fd(),
            &name,
            1024,
            Instant::now() + Duration::from_secs(5),
        ) {
            // a filesystem that reflinks protects it whatever the cap
            Snapshot::Reflinked { .. } => return,
            Snapshot::OverCap => {}
            other => panic!("{other:?}"),
        }
        assert!(!t.path().join("big").exists());
        let name = CString::new("late").unwrap();
        match snapshot(
            src.as_raw_fd(),
            &st,
            d.as_raw_fd(),
            &name,
            1 << 20,
            Instant::now() - Duration::from_millis(1),
        ) {
            Snapshot::Deadline => {}
            other => panic!("{other:?}"),
        }
        assert!(!t.path().join("late").exists());
    }

    #[test]
    fn a_source_that_changes_during_the_copy_is_refused() {
        let t = tempfile::TempDir::new().unwrap();
        let (src, mut st) = source(t.path(), b"hello world");
        st.st_mtime_nsec += 1; // as if it changed after the fstat
        let d = dir_fd(t.path());
        let name = CString::new("torn").unwrap();
        match snapshot(
            src.as_raw_fd(),
            &st,
            d.as_raw_fd(),
            &name,
            1 << 20,
            Instant::now() + Duration::from_secs(5),
        ) {
            Snapshot::Reflinked { .. } => {}
            Snapshot::SourceChanged => assert!(!t.path().join("torn").exists()),
            other => panic!("{other:?}"),
        }
    }
}
