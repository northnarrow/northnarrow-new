//! The Linux host of the signed chains: the file operations of
//! [`ChainHost`], as the chain code made them itself before R04a (Wave 4
//! restructure, lab PR 241). Each body is the call that was in `chainlog`,
//! `audit`, `chain_anchor` or `chain_tail`, with the same flags and modes.

use std::fs::{DirBuilder, File, OpenOptions};
use std::io;
use std::os::unix::fs::{DirBuilderExt, FileExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use crate::chain_host::ChainHost;

/// The agent's host: Linux.
#[derive(Debug, Clone, Copy, Default)]
pub struct LinuxHost;

impl ChainHost for LinuxHost {
    /// `O_RDONLY | O_NOFOLLOW | O_NONBLOCK`: a symlink at the name is not
    /// the chain, and a FIFO cannot stall the reader.
    fn open_read_nofollow(path: &Path) -> io::Result<File> {
        OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(path)
    }

    /// `O_NOFOLLOW` on a symlink: `ELOOP`.
    fn is_symlink_refusal(err: &io::Error) -> bool {
        err.raw_os_error() == Some(libc::ELOOP)
    }

    fn open_with_mode(options: &mut OpenOptions, mode: u32, path: &Path) -> io::Result<File> {
        options.mode(mode).open(path)
    }

    fn open_with_mode_nofollow(
        options: &mut OpenOptions,
        mode: u32,
        path: &Path,
    ) -> io::Result<File> {
        options.mode(mode).custom_flags(libc::O_NOFOLLOW).open(path)
    }

    fn create_dir_all_with_mode(dir: &Path, mode: u32) -> io::Result<()> {
        DirBuilder::new().mode(mode).recursive(true).create(dir)
    }

    /// `renameat2(RENAME_NOREPLACE)`. External audit NN-AUD-115. On a
    /// filesystem without the flag, fall back to an `lstat` check then a
    /// plain rename (the window is inside the rotation's `+i` dance).
    fn rename_noreplace(from: &Path, to: &Path) -> io::Result<()> {
        use std::os::unix::ffi::OsStrExt;
        let cstr = |p: &Path| {
            std::ffi::CString::new(p.as_os_str().as_bytes())
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))
        };
        let (f, t) = (cstr(from)?, cstr(to)?);
        // SAFETY: two NUL-terminated paths that outlive the call; renameat2
        // only reads them.
        let rc = unsafe {
            libc::syscall(
                libc::SYS_renameat2,
                libc::AT_FDCWD,
                f.as_ptr(),
                libc::AT_FDCWD,
                t.as_ptr(),
                libc::RENAME_NOREPLACE,
            )
        };
        if rc == 0 {
            return Ok(());
        }
        let err = std::io::Error::last_os_error();
        match err.raw_os_error() {
            Some(libc::EINVAL) | Some(libc::ENOSYS) => {
                if std::fs::symlink_metadata(to).is_ok() {
                    return Err(std::io::Error::from(std::io::ErrorKind::AlreadyExists));
                }
                std::fs::rename(from, to)
            }
            _ => Err(err),
        }
    }

    /// `pwrite` until all of `buf` is written.
    fn write_all_at(file: &File, buf: &[u8], offset: u64) -> io::Result<()> {
        FileExt::write_all_at(file, buf, offset)
    }

    /// Review entry 44: through the directory fd held since the first call
    /// for the path's parent ([`crate::anchored::anchor`]).
    fn anchor(path: &Path) -> PathBuf {
        crate::anchored::anchor(path)
    }
}
