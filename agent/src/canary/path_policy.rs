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

/// Write `body` to a checked canary path without following a symlink
/// at the final component (`O_NOFOLLOW`), creating or truncating.
pub fn write_canary_file(path: &Path, body: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    f.write_all(body)?;
    f.sync_all()
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
        // O_NOFOLLOW refuses to write through a symlink even if asked
        assert!(write_canary_file(&sl, b"y").is_err());
        assert_eq!(std::fs::read(&target).unwrap(), b"x");
    }

    #[test]
    fn write_creates_and_truncates_regular_file() {
        let tmp = tempfile::tempdir().unwrap();
        let p = tmp.path().join("c.txt");
        write_canary_file(&p, b"first-longer").unwrap();
        write_canary_file(&p, b"second").unwrap();
        assert_eq!(std::fs::read(&p).unwrap(), b"second");
    }
}
