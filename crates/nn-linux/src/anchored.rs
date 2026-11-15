//! Paths anchored to the directory the agent saw when it opened a log.
//!
//! Review entry 44 (`nn-lab.sh tamper-check`, C14): the signed logs were
//! reopened by path on every append, so a bind mount over
//! `/etc/northnarrow` made the agent write its own evidence — including the
//! `integrity_drift` entry reporting that very mount — into the attacker's
//! directory. A directory fd taken before the mount keeps resolving names
//! in the original directory. [`anchor`] opens the parent directory once
//! and keeps the fd for the life of the process; the integrity check still
//! reports the mount itself.
//!
//! Lot 353 (the review of #563, F1): the anchored path was
//! `/proc/self/fd/<dirfd>/<name>`, resolved through the `/proc` mounted
//! NOW at every append: a FUSE over `/proc` held every signed append (and
//! the audit lock with it — the High record of that very mount was never
//! written), a tmpfs over `/proc` made every one fail (`ENOENT`),
//! silently. [`anchor`] now returns the path as it is and the writers'
//! file operations ([`open`], [`symlink_metadata`], [`metadata`],
//! [`read_dir_names`], [`remove_file`], [`rename_noreplace`]) resolve a
//! name of an anchored directory beneath its descriptor: `openat2` with
//! `RESOLVE_BENEATH | RESOLVE_NO_XDEV | RESOLVE_NO_MAGICLINKS`,
//! `renameat2`, `unlinkat` — no `/proc`, no path walked from `/`, no mount
//! crossed (a mount over the file itself is `EXDEV`, never asked
//! anything). Only a name directly in an anchored directory is resolved
//! there (every chain file is: the archives and the manifest beside the
//! active file); any other path is resolved by path, as before.
//!
//! A mount that is already in place when the agent starts is anchored too;
//! the boot integrity check reports it, and the journal keeps the ERROR.
//!
//! [`anchor`] is for the agent's fixed configuration paths (the logs named
//! on its command line: a handful of directories), never for a path a
//! request names: each directory keeps one fd for the life of the process.
//! External audit MAIN-015 (NN-AUD-257, lab PR 180): a parent that cannot
//! be opened (other than one that does not exist) leaves the path
//! unanchored, and that is an ERROR once per directory — it used to be
//! silent, with the mount-diversion protection off for that log.

use std::collections::{HashMap, HashSet};
use std::ffi::{CString, OsStr, OsString};
use std::fs::{File, Metadata};
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};

/// The anchored directories: each descriptor is kept (leaked) for the life
/// of the process, so a lookup copies a `&'static File` out and holds no
/// lock across the operation.
static DIRS: OnceLock<Mutex<HashMap<PathBuf, &'static File>>> = OnceLock::new();

/// Parents already reported as unanchored (one ERROR each).
static UNANCHORED: OnceLock<Mutex<HashSet<PathBuf>>> = OnceLock::new();

/// How a name is resolved beneath an anchored directory: below it only, no
/// mount crossed, no magic link.
const BENEATH: u64 = libc::RESOLVE_BENEATH | libc::RESOLVE_NO_XDEV | libc::RESOLVE_NO_MAGICLINKS;

fn dirs() -> std::sync::MutexGuard<'static, HashMap<PathBuf, &'static File>> {
    match DIRS.get_or_init(|| Mutex::new(HashMap::new())).lock() {
        Ok(m) => m,
        Err(p) => p.into_inner(),
    }
}

/// Anchor the directory of `path` (once per directory) and return `path`
/// unchanged: the operations of this module resolve its name beneath the
/// directory's descriptor. Relative paths and parents that do not exist
/// (yet) are not anchored; a parent that exists but cannot be opened is
/// not either, with an ERROR the first time.
pub fn anchor(path: &Path) -> PathBuf {
    // a log is never under the kernel's views (an old anchored spelling,
    // `/proc/self/fd/<n>/<name>`, is not anchored again)
    if !path.is_absolute() || path.starts_with("/proc") || path.starts_with("/sys") {
        return path.to_path_buf();
    }
    let (Some(parent), Some(_)) = (path.parent(), path.file_name()) else {
        return path.to_path_buf();
    };
    if dirs().contains_key(parent) {
        return path.to_path_buf();
    }
    // opened without the lock: the lookups of the writers never wait on it
    match std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_CLOEXEC)
        .open(parent)
    {
        Ok(f) => {
            let mut map = dirs();
            if !map.contains_key(parent) {
                map.insert(parent.to_path_buf(), Box::leak(Box::new(f)));
            }
        }
        Err(e) => {
            if e.kind() != io::ErrorKind::NotFound {
                report_unanchored(parent, &e);
            }
        }
    }
    path.to_path_buf()
}

/// Whether the directory of `path` is anchored (its name is resolved
/// beneath the directory's descriptor).
pub fn is_anchored(path: &Path) -> bool {
    beneath(path).is_some()
}

/// The anchored directory `path` is directly in, and its name there.
fn beneath(path: &Path) -> Option<(&'static File, &OsStr)> {
    let (parent, name) = (path.parent()?, path.file_name()?);
    let dir = *dirs().get(parent)?;
    Some((dir, name))
}

/// The anchored directory `dir` itself.
fn anchored_dir(dir: &Path) -> Option<&'static File> {
    dirs().get(dir).copied()
}

fn cstr(b: &[u8]) -> io::Result<CString> {
    CString::new(b).map_err(|_| io::Error::from_raw_os_error(libc::EINVAL))
}

/// `name` opened beneath `dir` with `flags` (plus `O_CLOEXEC`), `mode` for
/// a file the open creates. A kernel without `openat2` (before 5.6, or a
/// filter that refuses it): `openat`, and a file on another device than
/// `dir` is a mount crossed (`EXDEV`).
fn openat_beneath(dir: &File, name: &OsStr, flags: i32, mode: u32) -> io::Result<File> {
    let c = cstr(name.as_bytes())?;
    let flags = flags
        | libc::O_CLOEXEC
        | if flags & libc::O_PATH == 0 {
            libc::O_NOCTTY
        } else {
            0
        };
    // SAFETY: `open_how` is plain old data, valid when zeroed.
    let mut how: libc::open_how = unsafe { std::mem::zeroed() };
    how.flags = flags as u64;
    how.mode = if flags & libc::O_CREAT != 0 {
        u64::from(mode)
    } else {
        0
    };
    how.resolve = BENEATH;
    // SAFETY: `c` is NUL-terminated and `how` outlives the call, its size
    // given.
    let fd = unsafe {
        libc::syscall(
            libc::SYS_openat2,
            dir.as_raw_fd(),
            c.as_ptr(),
            &how as *const libc::open_how,
            std::mem::size_of::<libc::open_how>(),
        )
    };
    if fd >= 0 {
        // SAFETY: a new descriptor the kernel gave this call alone.
        return Ok(unsafe { File::from_raw_fd(fd as RawFd) });
    }
    let e = io::Error::last_os_error();
    if e.raw_os_error() != Some(libc::ENOSYS) {
        return Err(e);
    }
    // SAFETY: `c` is NUL-terminated; the mode is read only with O_CREAT.
    let fd = unsafe { libc::openat(dir.as_raw_fd(), c.as_ptr(), flags, mode as libc::c_uint) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: a new descriptor the kernel gave this call alone.
    let f = unsafe { File::from_raw_fd(fd) };
    use std::os::unix::fs::MetadataExt;
    if f.metadata()?.dev() != dir.metadata()?.dev() {
        return Err(io::Error::from_raw_os_error(libc::EXDEV));
    }
    Ok(f)
}

/// `path` opened with `flags` (plus `O_CLOEXEC`), `mode` for a file the
/// open creates: beneath its anchored directory, else by path.
pub fn open(path: &Path, flags: i32, mode: u32) -> io::Result<File> {
    if let Some((dir, name)) = beneath(path) {
        return openat_beneath(dir, name, flags, mode);
    }
    let c = cstr(path.as_os_str().as_bytes())?;
    // SAFETY: `c` is NUL-terminated; the mode is read only with O_CREAT.
    let fd = unsafe {
        libc::open(
            c.as_ptr(),
            flags | libc::O_CLOEXEC | libc::O_NOCTTY,
            mode as libc::c_uint,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: a new descriptor the kernel gave this call alone.
    Ok(unsafe { File::from_raw_fd(fd) })
}

/// `std::fs::symlink_metadata` of `path`, beneath its anchored directory.
pub fn symlink_metadata(path: &Path) -> io::Result<Metadata> {
    match beneath(path) {
        Some((dir, name)) => {
            openat_beneath(dir, name, libc::O_PATH | libc::O_NOFOLLOW, 0)?.metadata()
        }
        None => std::fs::symlink_metadata(path),
    }
}

/// `std::fs::metadata` of `path` (a last symlink followed, beneath the
/// directory), beneath its anchored directory.
pub fn metadata(path: &Path) -> io::Result<Metadata> {
    match beneath(path) {
        Some((dir, name)) => openat_beneath(dir, name, libc::O_PATH, 0)?.metadata(),
        None => std::fs::metadata(path),
    }
}

/// The names in the directory `dir` (not `.` and `..`): beneath its
/// descriptor when it is anchored, else by path.
pub fn read_dir_names(dir: &Path) -> io::Result<Vec<OsString>> {
    match anchored_dir(dir) {
        Some(d) => antitamper_bpf::kernel_roots::dir_names(openat_beneath(
            d,
            OsStr::new("."),
            libc::O_RDONLY | libc::O_DIRECTORY,
            0,
        )?),
        None => std::fs::read_dir(dir)?
            .map(|e| e.map(|e| e.file_name()))
            .collect(),
    }
}

/// `std::fs::remove_file` of `path` (`unlinkat`), beneath its anchored
/// directory.
pub fn remove_file(path: &Path) -> io::Result<()> {
    let Some((dir, name)) = beneath(path) else {
        return std::fs::remove_file(path);
    };
    let c = cstr(name.as_bytes())?;
    // SAFETY: a live directory fd and a NUL-terminated name.
    if unsafe { libc::unlinkat(dir.as_raw_fd(), c.as_ptr(), 0) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// The `(dirfd, name)` a `*at` call takes for `path`: its anchored
/// directory and name, else `AT_FDCWD` and the path.
fn at_args(path: &Path) -> io::Result<(RawFd, CString)> {
    match beneath(path) {
        Some((dir, name)) => Ok((dir.as_raw_fd(), cstr(name.as_bytes())?)),
        None => Ok((libc::AT_FDCWD, cstr(path.as_os_str().as_bytes())?)),
    }
}

/// `rename(from, to)` that fails with `AlreadyExists` instead of replacing
/// `to` (`renameat2(RENAME_NOREPLACE)`), each name beneath its anchored
/// directory. External audit NN-AUD-115: on a filesystem without the flag,
/// an `lstat` check then a plain rename (the window is inside the
/// rotation's `+i` dance).
pub fn rename_noreplace(from: &Path, to: &Path) -> io::Result<()> {
    let (fd_from, c_from) = at_args(from)?;
    let (fd_to, c_to) = at_args(to)?;
    // SAFETY: live fds (or AT_FDCWD) and NUL-terminated names that outlive
    // the call; renameat2 only reads them.
    let rc = unsafe {
        libc::syscall(
            libc::SYS_renameat2,
            fd_from,
            c_from.as_ptr(),
            fd_to,
            c_to.as_ptr(),
            libc::RENAME_NOREPLACE,
        )
    };
    if rc == 0 {
        return Ok(());
    }
    let err = io::Error::last_os_error();
    match err.raw_os_error() {
        Some(libc::EINVAL) | Some(libc::ENOSYS) => {
            if symlink_metadata(to).is_ok() {
                return Err(io::Error::from(io::ErrorKind::AlreadyExists));
            }
            // SAFETY: as above.
            if unsafe { libc::renameat(fd_from, c_from.as_ptr(), fd_to, c_to.as_ptr()) } != 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        }
        _ => Err(err),
    }
}

/// Lot 353 (the review of #563, F1): `name` opened beneath the directory
/// `dir` a caller holds (as [`open`] resolves an anchored name: no mount
/// crossed, no `/proc`) — the boot refusals' fallback directory.
pub fn open_beneath(dir: &File, name: &OsStr, flags: i32, mode: u32) -> io::Result<File> {
    openat_beneath(dir, name, flags, mode)
}

/// The names in the directory `dir` a caller holds (not `.` and `..`).
pub fn names_beneath(dir: &File) -> io::Result<Vec<OsString>> {
    antitamper_bpf::kernel_roots::dir_names(openat_beneath(
        dir,
        OsStr::new("."),
        libc::O_RDONLY | libc::O_DIRECTORY,
        0,
    )?)
}

/// `unlinkat(dir, name, flags)` (`libc::AT_REMOVEDIR`: an empty directory).
pub fn unlink_beneath(dir: &File, name: &OsStr, flags: i32) -> io::Result<()> {
    let c = cstr(name.as_bytes())?;
    // SAFETY: a live directory fd and a NUL-terminated name.
    if unsafe { libc::unlinkat(dir.as_raw_fd(), c.as_ptr(), flags) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// `mkdirat(dir, name, mode)`.
pub fn mkdir_beneath(dir: &File, name: &OsStr, mode: u32) -> io::Result<()> {
    let c = cstr(name.as_bytes())?;
    // SAFETY: a live directory fd and a NUL-terminated name.
    if unsafe { libc::mkdirat(dir.as_raw_fd(), c.as_ptr(), mode as libc::mode_t) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// The metadata of the parent of the directory `dir` a caller holds (its
/// `..`, as the kernel resolves it: up a mount whose root `dir` is).
pub fn parent_metadata(dir: &File) -> io::Result<Metadata> {
    // SAFETY: a live directory fd and a NUL-terminated name.
    let fd = unsafe {
        libc::openat(
            dir.as_raw_fd(),
            c"..".as_ptr(),
            libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: a new descriptor the kernel gave this call alone.
    unsafe { File::from_raw_fd(fd) }.metadata()
}

/// The ERROR for a parent [`anchor`] could not open, once per directory.
fn report_unanchored(parent: &Path, e: &io::Error) {
    let set = UNANCHORED.get_or_init(|| Mutex::new(HashSet::new()));
    let mut set = match set.lock() {
        Ok(s) => s,
        Err(p) => p.into_inner(),
    };
    if !set.insert(parent.to_path_buf()) {
        return;
    }
    tracing::error!(
        dir = %parent.display(),
        error = %e,
        "writes to files in this directory are not anchored: a mount over the directory \
         would divert them (the directory could not be opened)"
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Lot 353 (the review of #563, F1): the anchored path is the path
    /// itself — no `/proc/self/fd` spelling — and every operation on a name
    /// of the anchored directory reaches the real directory: open, create,
    /// rename (never replacing), list, stat, remove.
    #[test]
    fn anchored_names_reach_the_same_directory_without_proc() {
        use std::io::{Read, Write};
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("log.jsonl");
        std::fs::write(&p, "a\n").unwrap();
        let a = anchor(&p);
        assert_eq!(a, p, "the path itself");
        assert!(is_anchored(&p));
        let fd = |p: &Path| dirs().get(p.parent().unwrap()).map(|f| f.as_raw_fd());
        let first = fd(&p);
        anchor(&dir.path().join("other"));
        assert_eq!(fd(&p), first, "one fd per directory");
        let mut text = String::new();
        open(&p, libc::O_RDONLY, 0)
            .unwrap()
            .read_to_string(&mut text)
            .unwrap();
        assert_eq!(text, "a\n");
        let n = dir.path().join("new");
        open(&n, libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL, 0o600)
            .unwrap()
            .write_all(b"b")
            .unwrap();
        let n2 = dir.path().join("new2");
        rename_noreplace(&n, &n2).unwrap();
        assert_eq!(std::fs::read(&n2).unwrap(), b"b");
        std::fs::write(&n, "c").unwrap();
        assert_eq!(
            rename_noreplace(&n, &n2).unwrap_err().kind(),
            io::ErrorKind::AlreadyExists
        );
        let mut names = read_dir_names(dir.path()).unwrap();
        names.sort();
        assert_eq!(names, ["log.jsonl", "new", "new2"]);
        assert!(symlink_metadata(&n2).unwrap().is_file());
        assert!(metadata(&n2).unwrap().is_file());
        remove_file(&n2).unwrap();
        assert!(!n2.exists());
        assert_eq!(
            symlink_metadata(&n2).unwrap_err().kind(),
            io::ErrorKind::NotFound
        );
    }

    /// Lot 353 (the review of #563, F1, its probe): a tmpfs laid over
    /// `/proc` after the open — and one over the log's own directory — do
    /// not reach a name the anchor resolves: the row is appended to the
    /// real file, a rotation's create, rename and listing work (rc2: the
    /// open of `/proc/self/fd/<n>/<name>` failed with `ENOENT`, every
    /// signed record lost). In a user and mount namespace of a child,
    /// skipped where the host refuses one.
    #[test]
    fn a_mount_over_proc_or_the_directory_does_not_reach_an_anchored_name() {
        use std::io::Write;
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("log.jsonl");
        std::fs::write(&p, "a\n").unwrap();
        anchor(&p);
        let target = dir.path().to_path_buf();
        let other = tempfile::tempdir().unwrap();
        let decoy_path = other.path().join("decoy");
        std::fs::write(&decoy_path, "").unwrap();
        // a directory anchored in the child's own namespace
        let second = tempfile::tempdir().unwrap();
        let p2 = second.path().join("log.jsonl");
        std::fs::write(&p2, "").unwrap();
        let rc = testing::in_userns(|| {
            if !testing::tmpfs_over(Path::new("/proc")) {
                return 99;
            }
            // a mount over a log file itself (a decoy bound over it, in the
            // namespace its directory was anchored in) is refused — EXDEV,
            // never asked anything, never written
            anchor(&p2);
            let decoy = std::ffi::CString::new(decoy_path.as_os_str().as_encoded_bytes()).unwrap();
            let at = std::ffi::CString::new(p2.as_os_str().as_encoded_bytes()).unwrap();
            // SAFETY: NUL-terminated paths, no data.
            if unsafe {
                libc::mount(
                    decoy.as_ptr(),
                    at.as_ptr(),
                    std::ptr::null(),
                    libc::MS_BIND,
                    std::ptr::null(),
                )
            } != 0
            {
                return 99;
            }
            match open(&p2, libc::O_WRONLY | libc::O_APPEND, 0) {
                Err(e) if e.raw_os_error() == Some(libc::EXDEV) => {}
                _ => return 15,
            }
            if !testing::tmpfs_over(&target) {
                return 99;
            }
            if std::fs::read(&p).is_ok() {
                return 10; // the cover did not take
            }
            let appended = open(&p, libc::O_WRONLY | libc::O_APPEND, 0)
                .and_then(|mut f| f.write_all(b"row\n"));
            if appended.is_err() {
                return 11;
            }
            let sealed = target.join("log.jsonl.1");
            if rename_noreplace(&p, &sealed).is_err() {
                return 12;
            }
            if open(&p, libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL, 0o600).is_err() {
                return 13;
            }
            match read_dir_names(&target) {
                Ok(n) if n.len() == 2 => 0,
                _ => 14,
            }
        });
        match crate::fuse_testing::ran(rc) {
            None => {}
            Some(rc) => {
                assert_eq!(rc, 0, "the child failed");
                assert_eq!(
                    std::fs::read(dir.path().join("log.jsonl.1")).unwrap(),
                    b"a\nrow\n"
                );
                assert_eq!(std::fs::read(&p).unwrap(), b"");
                assert_eq!(std::fs::read(&decoy_path).unwrap(), b"", "never written");
                assert_eq!(std::fs::read(&p2).unwrap(), b"");
            }
        }
    }

    /// A writer for the ERROR lines of one test.
    #[derive(Clone, Default)]
    struct Captured(std::sync::Arc<Mutex<Vec<u8>>>);

    impl std::io::Write for Captured {
        fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(b);
            Ok(b.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for Captured {
        type Writer = Captured;
        fn make_writer(&'a self) -> Self::Writer {
            self.clone()
        }
    }

    /// External audit MAIN-015: a parent that exists but cannot be opened
    /// leaves the path unanchored, with one ERROR per directory.
    #[test]
    fn an_unopenable_parent_is_reported_once() {
        use std::os::unix::fs::PermissionsExt;
        // SAFETY: geteuid has no preconditions.
        if unsafe { libc::geteuid() } == 0 {
            eprintln!("skipped: root opens a directory at mode 000");
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let shut = dir.path().join("shut");
        std::fs::create_dir(&shut).unwrap();
        std::fs::set_permissions(&shut, std::fs::Permissions::from_mode(0o000)).unwrap();
        let p = shut.join("log.jsonl");
        let out = Captured::default();
        let sub = tracing_subscriber::fmt()
            .with_writer(out.clone())
            .with_ansi(false)
            .finish();
        let (a, b) = tracing::subscriber::with_default(sub, || (anchor(&p), anchor(&p)));
        std::fs::set_permissions(&shut, std::fs::Permissions::from_mode(0o700)).unwrap();
        assert_eq!(a, p, "returned unchanged");
        assert_eq!(b, p);
        let text = String::from_utf8(out.0.lock().unwrap().clone()).unwrap();
        let errors: Vec<&str> = text.lines().filter(|l| l.contains("ERROR")).collect();
        assert_eq!(errors.len(), 1, "{text}");
        assert!(errors[0].contains("not anchored"), "{text}");
        assert!(errors[0].contains(&shut.display().to_string()), "{text}");
    }

    #[test]
    fn a_missing_parent_is_not_an_error() {
        let out = Captured::default();
        let sub = tracing_subscriber::fmt()
            .with_writer(out.clone())
            .with_ansi(false)
            .finish();
        let missing = Path::new("/nonexistent-nn-dir-180/x");
        let a = tracing::subscriber::with_default(sub, || anchor(missing));
        assert_eq!(a, missing.to_path_buf());
        let text = String::from_utf8(out.0.lock().unwrap().clone()).unwrap();
        assert!(!text.contains("ERROR"), "{text}");
    }

    #[test]
    fn relative_missing_and_already_anchored_are_unchanged() {
        assert_eq!(anchor(Path::new("rel/x")), PathBuf::from("rel/x"));
        let missing = Path::new("/nonexistent-nn-dir/x");
        assert_eq!(anchor(missing), missing.to_path_buf());
        let already = Path::new("/proc/self/fd/3/x");
        assert_eq!(anchor(already), already.to_path_buf());
        assert!(!is_anchored(already), "nothing under /proc is anchored");
    }
}

/// The tests' user and mount namespaces (lot 353).
#[cfg(test)]
pub(crate) mod testing {
    use std::path::Path;

    /// `body`'s exit code, run in a forked child in a user and mount
    /// namespace of its own (`/` made private); `None` when the host
    /// refuses the namespaces (the child exits 99 itself for that).
    pub(crate) fn in_userns(body: impl FnOnce() -> i32) -> Option<i32> {
        // SAFETY: fork; the child unshares, runs `body` and `_exit`s.
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0, "fork");
        if pid == 0 {
            // SAFETY: the child's own namespaces; no data.
            let refused = unsafe {
                libc::unshare(libc::CLONE_NEWUSER | libc::CLONE_NEWNS) != 0
                    || libc::mount(
                        std::ptr::null(),
                        c"/".as_ptr(),
                        std::ptr::null(),
                        libc::MS_REC | libc::MS_PRIVATE,
                        std::ptr::null(),
                    ) != 0
            };
            let rc = if refused { 99 } else { body() };
            // SAFETY: _exit in the child.
            unsafe { libc::_exit(rc) };
        }
        let mut status = 0;
        // SAFETY: waiting for our own child.
        unsafe { libc::waitpid(pid, &mut status, 0) };
        assert!(libc::WIFEXITED(status), "child status {status:#x}");
        match libc::WEXITSTATUS(status) {
            99 => None,
            rc => Some(rc),
        }
    }

    /// A tmpfs mounted over `target` (in the caller's mount namespace).
    pub(crate) fn tmpfs_over(target: &Path) -> bool {
        let Ok(t) = std::ffi::CString::new(target.as_os_str().as_encoded_bytes()) else {
            return false;
        };
        // SAFETY: NUL-terminated strings, no data.
        unsafe {
            libc::mount(
                c"none".as_ptr(),
                t.as_ptr(),
                c"tmpfs".as_ptr(),
                0,
                std::ptr::null(),
            ) == 0
        }
    }
}
