//! Where a file/credential canary may be materialised.
//!
//! `CanaryDeploy` is a signed admin verb, but the agent executes it as
//! root with `CAP_DAC_OVERRIDE`, so an operator key that leaks — or a
//! compromised admin host — turned it into "write a root-owned file at
//! any path" (review `canary-path-1`): `/etc/cron.d/x`,
//! `/root/.ssh/authorized_keys`, a systemd unit. A decoy is bait, it
//! never needs to live inside the system trees, so the policy is a
//! denylist of those trees plus the usual path hygiene.
//!
//! Checks, in order:
//! 1. absolute, no `.`/`..` components, not empty;
//! 2. not under a denied prefix (system trees, procfs/sysfs/devfs,
//!    `/run`, NorthNarrow's own state and config);
//! 3. the nearest EXISTING ancestor, canonicalised, is not under a
//!    denied prefix either (a symlink `/home/u/x → /etc` would
//!    otherwise pass check 2);
//! 4. the target itself is not a symlink (writes go through
//!    `O_NOFOLLOW` too, belt and braces).

use std::path::{Component, Path, PathBuf};

use anyhow::{anyhow, Result};

/// Prefixes a canary may never be written under. A trailing `/`
/// matches the subtree; `/var/lib/northnarrow/canary/` is carved back in
/// below so the agent's own canary area stays usable.
pub const CANARY_DENY_PREFIXES: &[&str] = &[
    "/bin/",
    "/sbin/",
    "/lib/",
    "/lib32/",
    "/lib64/",
    "/usr/",
    "/etc/",
    "/boot/",
    "/proc/",
    "/sys/",
    "/dev/",
    "/run/",
    "/var/lib/northnarrow/",
    "/var/log/",
];

/// Subtrees explicitly allowed although a denied prefix covers them.
pub const CANARY_ALLOW_PREFIXES: &[&str] = &["/var/lib/northnarrow/canary/"];

fn denied_prefix(p: &str) -> Option<&'static str> {
    if CANARY_ALLOW_PREFIXES.iter().any(|a| p.starts_with(a)) {
        return None;
    }
    CANARY_DENY_PREFIXES
        .iter()
        .copied()
        .find(|d| p.starts_with(d) || p == &d[..d.len() - 1])
}

/// Validate `path` for materialisation. Returns the path to write.
pub fn check_canary_path(path: &str) -> Result<PathBuf> {
    let p = Path::new(path);
    if path.is_empty() || !p.is_absolute() {
        return Err(anyhow!("canary path must be absolute: {path:?}"));
    }
    // Check the raw segments: `Path::components` normalises a `.`
    // segment away, so a components()-based test would accept "/a/./b".
    if path.split('/').any(|seg| seg == "." || seg == "..")
        || p.components().any(|c| matches!(c, Component::ParentDir))
    {
        return Err(anyhow!(
            "canary path must not contain `.` or `..`: {path:?}"
        ));
    }
    if p.file_name().is_none() {
        return Err(anyhow!("canary path has no file name: {path:?}"));
    }
    if let Some(d) = denied_prefix(path) {
        return Err(anyhow!(
            "canary path {path:?} is under the protected prefix {d:?}"
        ));
    }
    // Symlink escape: resolve the nearest existing ancestor and re-check.
    let mut probe = p.parent();
    while let Some(dir) = probe {
        if dir.exists() {
            let real = std::fs::canonicalize(dir)
                .map_err(|e| anyhow!("canonicalising {}: {e}", dir.display()))?;
            let real_s = format!("{}/", real.to_string_lossy().trim_end_matches('/'));
            if let Some(d) = denied_prefix(&real_s) {
                return Err(anyhow!(
                    "canary path {path:?} resolves into the protected prefix {d:?} via {}",
                    real.display()
                ));
            }
            break;
        }
        probe = dir.parent();
    }
    if let Ok(meta) = std::fs::symlink_metadata(p) {
        if meta.file_type().is_symlink() {
            return Err(anyhow!("canary path {path:?} is a symlink — refusing"));
        }
    }
    Ok(p.to_path_buf())
}

/// External audit DEC-002: write a decoy at a canary path without
/// traversing a symlink anywhere on the way, and return the open file (its
/// inode is what gets watched, DEC-001).
///
/// [`check_canary_path`] judged the path, but the write used to re-resolve
/// it afterwards — `create_dir_all`, then an open that refused a symlink
/// only as the last component. A user owning a directory on the way (the
/// decoys belong in homes) could swap a component for a symlink in
/// between, and have root create directories and write a file wherever it
/// pointed. Now the nearest existing ancestor is canonicalised (no symlink
/// left in it), then walked component by component from the root with
/// `O_NOFOLLOW`; missing directories are created with `mkdirat` inside
/// that walk, and the file is opened relative to its directory, also
/// `O_NOFOLLOW`, and must turn out a regular file. A symlink put in at any
/// point fails the walk.
///
/// The walk starts at the host's root as PID 1 sees it: the unit's
/// `ProtectSystem=strict` and `ProtectHome=read-only` leave every decoy
/// location read-only in the agent's own view, and every deploy of the
/// installed agent failed with EROFS (lab, 2026-10-13).
pub fn write_canary_checked(path: &str, body: &[u8]) -> Result<std::fs::File> {
    let target = check_canary_path(path)?;
    let name = target
        .file_name()
        .ok_or_else(|| anyhow!("canary path has no file name: {path:?}"))?
        .to_os_string();
    let mut existing = target
        .parent()
        .ok_or_else(|| anyhow!("canary path has no parent: {path:?}"))?
        .to_path_buf();
    let mut missing = Vec::new();
    while !existing.exists() {
        missing.push(
            existing
                .file_name()
                .ok_or_else(|| anyhow!("no existing ancestor for {path:?}"))?
                .to_os_string(),
        );
        existing = existing
            .parent()
            .ok_or_else(|| anyhow!("no existing ancestor for {path:?}"))?
            .to_path_buf();
    }
    missing.reverse();
    let canonical = std::fs::canonicalize(&existing)
        .map_err(|e| anyhow!("canonicalising {}: {e}", existing.display()))?;
    write_beneath(&host_root(), &canonical, &missing, &name, body)
        .map_err(|e| anyhow!("writing canary {path:?}: {e}"))
}

/// The host's root as PID 1 sees it, or `/` when that view cannot be
/// reached (no `CAP_SYS_PTRACE`, as in tests).
fn host_root() -> PathBuf {
    if std::fs::metadata("/proc/1/root/").is_ok() {
        PathBuf::from("/proc/1/root")
    } else {
        PathBuf::from("/")
    }
}

/// [`write_canary_checked`]'s walk: from `root`, through the components
/// of `dir` (canonical, so free of symlinks unless one was put in since),
/// then `missing` (created), to `name`.
fn write_beneath(
    root: &Path,
    dir: &Path,
    missing: &[std::ffi::OsString],
    name: &std::ffi::OsStr,
    body: &[u8],
) -> std::io::Result<std::fs::File> {
    use std::ffi::CString;
    use std::io::Write;
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    use std::os::unix::ffi::OsStrExt;

    let cstr = |s: &std::ffi::OsStr| {
        CString::new(s.as_bytes())
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))
    };
    let open_dir =
        |at: libc::c_int, name: &CString, flags: libc::c_int| -> std::io::Result<OwnedFd> {
            // SAFETY: openat on a NUL-terminated name; the fd is ours on success.
            let fd = unsafe {
                libc::openat(
                    at,
                    name.as_ptr(),
                    flags | libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC,
                )
            };
            if fd < 0 {
                return Err(std::io::Error::last_os_error());
            }
            // SAFETY: a fresh fd returned by openat.
            Ok(unsafe { OwnedFd::from_raw_fd(fd) })
        };
    // The root itself is followed: `/proc/1/root` is a link to PID 1's root.
    let mut cur = open_dir(libc::AT_FDCWD, &cstr(root.as_os_str())?, 0)?;
    for comp in dir.components() {
        if let std::path::Component::Normal(c) = comp {
            cur = open_dir(cur.as_raw_fd(), &cstr(c)?, libc::O_NOFOLLOW)?;
        }
    }
    for c in missing {
        let c = cstr(c)?;
        // SAFETY: mkdirat on a NUL-terminated name, relative to our fd.
        if unsafe { libc::mkdirat(cur.as_raw_fd(), c.as_ptr(), 0o755) } != 0 {
            let e = std::io::Error::last_os_error();
            if e.kind() != std::io::ErrorKind::AlreadyExists {
                return Err(e);
            }
        }
        cur = open_dir(cur.as_raw_fd(), &c, libc::O_NOFOLLOW)?;
    }
    let name = cstr(name)?;
    // SAFETY: openat on a NUL-terminated name; the fd is ours on success.
    let fd = unsafe {
        libc::openat(
            cur.as_raw_fd(),
            name.as_ptr(),
            libc::O_WRONLY
                | libc::O_CREAT
                | libc::O_TRUNC
                | libc::O_NOFOLLOW
                | libc::O_NONBLOCK
                | libc::O_CLOEXEC,
            0o644 as libc::c_uint,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: a fresh fd returned by openat.
    let mut f = unsafe { std::fs::File::from_raw_fd(fd) };
    if !f.metadata()?.is_file() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "the canary path is not a regular file",
        ));
    }
    f.write_all(body)?;
    f.sync_all()?;
    Ok(f)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_relative_dotdot_and_empty() {
        assert!(check_canary_path("").is_err());
        assert!(check_canary_path("relative/x").is_err());
        assert!(check_canary_path("/home/u/../etc/passwd").is_err());
        assert!(check_canary_path("/home/u/./x").is_err());
        assert!(check_canary_path("/").is_err());
    }

    #[test]
    fn rejects_system_trees_and_own_state() {
        for p in [
            "/etc/cron.d/nn",
            "/etc/northnarrow/admin.pub",
            "/usr/local/bin/x",
            "/usr/bin/x",
            "/bin/x",
            "/lib/x",
            "/boot/x",
            "/dev/shm/x",
            "/run/northnarrow/x",
            "/proc/self/x",
            "/sys/x",
            "/var/lib/northnarrow/quarantine/key",
            "/var/log/x",
        ] {
            assert!(check_canary_path(p).is_err(), "{p} must be denied");
        }
    }

    #[test]
    fn allows_bait_locations() {
        let tmp = tempfile::tempdir().unwrap();
        let p = tmp.path().join("decoy_aws_keys.txt");
        assert_eq!(check_canary_path(p.to_str().unwrap()).unwrap(), p);
        // Not existing yet, under an allowed tree: fine (parent is created later).
        for p in [
            "/home/user/.aws/credentials",
            "/root/.ssh/id_rsa_backup",
            "/var/lib/northnarrow/canary/x",
            "/opt/app/secrets.env",
            "/srv/www/.env",
        ] {
            assert!(check_canary_path(p).is_ok(), "{p} must be allowed");
        }
    }

    #[test]
    fn rejects_symlink_escape_and_symlink_target() {
        let tmp = tempfile::tempdir().unwrap();
        // parent symlink into /etc
        let link_dir = tmp.path().join("escape");
        std::os::unix::fs::symlink("/etc", &link_dir).unwrap();
        let via = link_dir.join("cron.d").join("x");
        assert!(check_canary_path(via.to_str().unwrap()).is_err());
        // target itself a symlink
        let target = tmp.path().join("real.txt");
        std::fs::write(&target, b"x").unwrap();
        let sl = tmp.path().join("link.txt");
        std::os::unix::fs::symlink(&target, &sl).unwrap();
        assert!(check_canary_path(sl.to_str().unwrap()).is_err());
        // never written through a symlink even if asked
        assert!(write_canary_checked(sl.to_str().unwrap(), b"y").is_err());
        assert_eq!(std::fs::read(&target).unwrap(), b"x");
    }

    #[test]
    fn write_creates_and_truncates_regular_file() {
        let tmp = tempfile::tempdir().unwrap();
        let p = tmp.path().join("c.txt");
        write_canary_checked(p.to_str().unwrap(), b"first-longer").unwrap();
        let f = write_canary_checked(p.to_str().unwrap(), b"second").unwrap();
        assert_eq!(std::fs::read(&p).unwrap(), b"second");
        // the returned file is the decoy (its inode is what gets watched)
        use std::os::unix::fs::MetadataExt;
        assert_eq!(
            f.metadata().unwrap().ino(),
            std::fs::metadata(&p).unwrap().ino()
        );
        // missing directories are created on the way
        let deep = tmp.path().join("a/b/c.txt");
        write_canary_checked(deep.to_str().unwrap(), b"z").unwrap();
        assert_eq!(std::fs::read(&deep).unwrap(), b"z");
    }

    /// External audit DEC-002: a symlink put in after the check — on a
    /// directory the walk creates, or on one it found — fails the walk,
    /// and nothing is written where it points.
    #[test]
    fn write_refuses_a_symlink_swapped_in_on_the_way() {
        let tmp = tempfile::tempdir().unwrap();
        let elsewhere = tmp.path().join("elsewhere");
        std::fs::create_dir(&elsewhere).unwrap();
        let home = tmp.path().join("home");
        std::fs::create_dir(&home).unwrap();
        let canonical = std::fs::canonicalize(&home).unwrap();

        // a directory to create turned out a symlink
        std::os::unix::fs::symlink(&elsewhere, home.join("sub")).unwrap();
        let missing = [std::ffi::OsString::from("sub")];
        let r = write_beneath(
            Path::new("/"),
            &canonical,
            &missing,
            std::ffi::OsStr::new("c.txt"),
            b"x",
        );
        assert!(r.is_err());
        assert!(!elsewhere.join("c.txt").exists());

        // a directory found by the check, swapped for a symlink since
        std::fs::rename(&home, tmp.path().join("home.real")).unwrap();
        std::os::unix::fs::symlink(&elsewhere, &home).unwrap();
        let r = write_beneath(
            Path::new("/"),
            &canonical,
            &[],
            std::ffi::OsStr::new("c.txt"),
            b"x",
        );
        assert!(r.is_err());
        assert!(!elsewhere.join("c.txt").exists());
    }

    /// External audit DEC-002 (with DEC-009): a FIFO at the decoy path is
    /// refused, without blocking.
    #[test]
    fn write_refuses_a_fifo() {
        let tmp = tempfile::tempdir().unwrap();
        let fifo = tmp.path().join("decoy");
        let c = std::ffi::CString::new(fifo.to_str().unwrap()).unwrap();
        // SAFETY: mkfifo on a NUL-terminated path in our temp dir.
        assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);
        assert!(write_canary_checked(fifo.to_str().unwrap(), b"x").is_err());
    }
}
