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
//! 1. absolute, no `.`/`..` components, not empty, no control
//!    character, shorter than `PATH_MAX`; then normalised lexically
//!    (`//` and a trailing `/` folded: external audit DEC-015, lab PR
//!    178 — the prefixes were matched on the raw string, so `//lib32/x`
//!    missed `/lib32/` and, on a host without `/lib32`, the write
//!    created it). Every later step uses the normal form;
//! 2. not under a denied prefix (system trees, procfs/sysfs/devfs,
//!    `/run`, NorthNarrow's own state and config);
//! 3. the nearest EXISTING ancestor, canonicalised, is not under a
//!    denied prefix either (a symlink `/home/u/x → /etc` would
//!    otherwise pass check 2);
//! 4. the target itself is not a symlink (writes go through
//!    `O_NOFOLLOW` too, belt and braces).

use std::path::{Component, Path, PathBuf};

use anyhow::{anyhow, Result};
use common::wire::admin_signed_payload::CanaryDeploymentWire;

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

/// Longest canary path accepted, in bytes: below `PATH_MAX` (4096 with
/// its NUL), so the kernel can resolve it in one go.
const MAX_CANARY_PATH_BYTES: usize = libc::PATH_MAX as usize - 1;

/// External audit DEC-015 (lab PR 178): the lexical checks of a canary
/// path and its normal form — absolute, no `.`/`..` segment, no control
/// character, at most [`MAX_CANARY_PATH_BYTES`], rebuilt from its
/// non-empty segments (`//` and a trailing `/` folded). The deny and
/// allow prefixes end in `/`, so matching them on the normal form is
/// matching by components.
pub fn normalise_canary_path(path: &str) -> Result<String> {
    if path.is_empty() || !path.starts_with('/') {
        return Err(anyhow!("canary path must be absolute: {path:?}"));
    }
    if path.len() > MAX_CANARY_PATH_BYTES {
        return Err(anyhow!(
            "canary path is {} bytes, longer than {MAX_CANARY_PATH_BYTES}",
            path.len()
        ));
    }
    if path.chars().any(char::is_control) {
        return Err(anyhow!(
            "canary path must not contain a control character: {path:?}"
        ));
    }
    // Check the raw segments: `Path::components` normalises a `.`
    // segment away, so a components()-based test would accept "/a/./b".
    if path.split('/').any(|seg| seg == "." || seg == "..")
        || Path::new(path)
            .components()
            .any(|c| matches!(c, Component::ParentDir))
    {
        return Err(anyhow!(
            "canary path must not contain `.` or `..`: {path:?}"
        ));
    }
    let segments: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
    if segments.is_empty() {
        return Err(anyhow!("canary path has no file name: {path:?}"));
    }
    Ok(format!("/{}", segments.join("/")))
}

/// External audit DEC-015 (lab PR 178): `deployment` with the path of a
/// File or Credential canary in its normal form ([`normalise_canary_path`]),
/// so the decoy written, the registry row and the watch name the same
/// path. Process and Network canaries are returned as they are.
pub fn normalised_deployment(deployment: &CanaryDeploymentWire) -> Result<CanaryDeploymentWire> {
    Ok(match deployment {
        CanaryDeploymentWire::File { path, template } => CanaryDeploymentWire::File {
            path: normalise_canary_path(path)?,
            template: template.clone(),
        },
        CanaryDeploymentWire::Credential { path, cred_family } => {
            CanaryDeploymentWire::Credential {
                path: normalise_canary_path(path)?,
                cred_family: cred_family.clone(),
            }
        }
        other => other.clone(),
    })
}

/// Validate `path` for materialisation. Returns the path to write: its
/// normal form ([`normalise_canary_path`]).
pub fn check_canary_path(path: &str) -> Result<PathBuf> {
    let normal = normalise_canary_path(path)?;
    let p = Path::new(&normal);
    if p.file_name().is_none() {
        return Err(anyhow!("canary path has no file name: {path:?}"));
    }
    if let Some(d) = denied_prefix(&normal) {
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
            // External audit DEC-015 (lab PR 178): the raw string missed
            // the prefix. `/var/lib/northnarrow` is absent off the lab, so
            // the canonical ancestor (`/var/lib`) did not catch these either.
            "//lib32/x",
            "//etc/cron.d/nn",
            "/etc//cron.d/nn",
            "///usr/bin/x",
            "//var/lib/northnarrow/quarantine/key",
            "/var//lib//northnarrow/x",
            "/var/lib/northnarrow",
            "//var/lib/northnarrow/",
        ] {
            assert!(check_canary_path(p).is_err(), "{p} must be denied");
        }
    }

    /// External audit DEC-015 (lab PR 178): the prefixes are matched on the
    /// normal form, whatever the host has on disk.
    #[test]
    fn denied_prefixes_match_the_normal_form() {
        for (raw, normal, denied) in [
            ("//lib32/x", "/lib32/x", Some("/lib32/")),
            ("//etc/cron.d/nn", "/etc/cron.d/nn", Some("/etc/")),
            ("/etc//cron.d/nn", "/etc/cron.d/nn", Some("/etc/")),
            ("///usr/bin/x", "/usr/bin/x", Some("/usr/")),
            ("//lib32", "/lib32", Some("/lib32/")),
            (
                "/home//u/.aws/credentials/",
                "/home/u/.aws/credentials",
                None,
            ),
            (
                "/var/lib//northnarrow/canary/x",
                "/var/lib/northnarrow/canary/x",
                None,
            ),
            ("/lib32x/y", "/lib32x/y", None),
        ] {
            let n = normalise_canary_path(raw).unwrap();
            assert_eq!(n, normal, "{raw}");
            assert_eq!(denied_prefix(&n), denied, "{raw}");
        }
        assert!(
            denied_prefix("//lib32/x").is_none(),
            "the raw string misses it"
        );
    }

    #[test]
    fn rejects_control_characters_and_overlong_paths() {
        for p in [
            "/home/u/a\nb",
            "/home/u/\u{1b}[2Jx",
            "/home/u/x\0",
            "/home/u/\u{85}x",
        ] {
            assert!(check_canary_path(p).is_err(), "{p:?} must be refused");
        }
        let long = format!("/home/u/{}", "a".repeat(MAX_CANARY_PATH_BYTES));
        assert!(check_canary_path(&long).is_err());
        let fits = format!("/home/{}", "a".repeat(200));
        assert!(check_canary_path(&fits).is_ok());
    }

    /// External audit DEC-015 (lab PR 178): the deployment recorded and
    /// watched carries the path written.
    #[test]
    fn deployment_paths_are_normalised() {
        let d = CanaryDeploymentWire::Credential {
            path: "/home//u/.aws//credentials".into(),
            cred_family: "aws".into(),
        };
        assert_eq!(
            normalised_deployment(&d).unwrap(),
            CanaryDeploymentWire::Credential {
                path: "/home/u/.aws/credentials".into(),
                cred_family: "aws".into(),
            }
        );
        let f = CanaryDeploymentWire::File {
            path: "relative".into(),
            template: None,
        };
        assert!(normalised_deployment(&f).is_err());
        let n = CanaryDeploymentWire::Network {
            bind_addr: "10.0.0.1".into(),
            bind_port: 22,
        };
        assert_eq!(normalised_deployment(&n).unwrap(), n);
    }

    /// A path written with `//` is written at its normal form.
    #[test]
    fn write_uses_the_normal_form() {
        let tmp = tempfile::tempdir().unwrap();
        let raw = format!("/{}//d//c.txt", tmp.path().display());
        write_canary_checked(&raw, b"n").unwrap();
        assert_eq!(std::fs::read(tmp.path().join("d/c.txt")).unwrap(), b"n");
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
