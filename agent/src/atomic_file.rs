//! External audit AUT-003: replacing a file the agent protects.
//!
//! The agent is the one process its own deny hooks let write
//! `/etc/northnarrow` and the state directory, and it rewrote `admin.pub`
//! (rotate-keys) and the signed overlays (`config overlay set`) through a
//! temporary file opened with `create(true).truncate(true)` at a fixed
//! name. Root may create entries in the directory while the agent runs: a
//! link planted at that name (`admin.pub.tmp -> audit.log`) made the next
//! legitimate rotation truncate the audit chain — written through by the
//! one process allowed to — and then rename the link over `admin.pub`.
//!
//! [`replace`] removes whatever sits at the temporary name (`unlink` never
//! follows a link), creates it exclusively and without following one,
//! sets the mode on the descriptor (the umask does not decide it), writes,
//! syncs, renames it into place and syncs the directory, so the rename
//! survives a crash.
//!
//! External audit WDG-015 (NN-AUD-364): the writer lives in
//! [`common::atomic_file`], and the agent's and the watchdog's pidfiles
//! use it too ([`write_pidfile`]); this module keeps the agent's path to
//! it.

pub use common::atomic_file::{replace, write_pidfile};

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    #[test]
    fn a_link_planted_at_the_temporary_name_is_replaced_not_followed() {
        let dir = tempfile::TempDir::new().unwrap();
        let victim = dir.path().join("audit.log");
        fs::write(&victim, "CHAIN").unwrap();
        let target = dir.path().join("admin.pub");
        fs::write(&target, "old").unwrap();
        std::os::unix::fs::symlink(&victim, dir.path().join(".admin.pub.tmp")).unwrap();
        replace(&target, b"new", 0o644).unwrap();
        assert_eq!(
            fs::read_to_string(&victim).unwrap(),
            "CHAIN",
            "the link's target untouched"
        );
        assert_eq!(fs::read_to_string(&target).unwrap(), "new");
        let m = fs::symlink_metadata(&target).unwrap();
        assert!(m.file_type().is_file());
        assert_eq!(m.mode() & 0o7777, 0o644);
        assert!(!dir.path().join(".admin.pub.tmp").exists());
    }

    /// External audit WDG-015 (NN-AUD-364): the agent's pidfile used to be
    /// written to `agent.pid.tmp.<pid>` with `fs::write`, through a link
    /// planted at that predictable name. Links at the old and the new
    /// temporary names: neither target is touched.
    #[test]
    fn the_agent_pidfile_is_not_written_through_a_planted_link() {
        let dir = tempfile::TempDir::new().unwrap();
        let victim = dir.path().join("audit.log");
        fs::write(&victim, "CHAIN").unwrap();
        let pid = std::process::id();
        let pidfile = dir.path().join("agent.pid");
        for name in [format!("agent.pid.tmp.{pid}"), ".agent.pid.tmp".to_string()] {
            std::os::unix::fs::symlink(&victim, dir.path().join(name)).unwrap();
        }
        write_pidfile(&pidfile, pid).unwrap();
        assert_eq!(fs::read_to_string(&victim).unwrap(), "CHAIN");
        assert_eq!(fs::read_to_string(&pidfile).unwrap(), format!("{pid}\n"));
        let m = fs::symlink_metadata(&pidfile).unwrap();
        assert!(m.file_type().is_file());
        assert_eq!(m.mode() & 0o7777, 0o644);
        // A pidfile planted as a link is replaced, not written through.
        fs::remove_file(&pidfile).unwrap();
        std::os::unix::fs::symlink(&victim, &pidfile).unwrap();
        write_pidfile(&pidfile, pid).unwrap();
        assert_eq!(fs::read_to_string(&victim).unwrap(), "CHAIN");
        assert!(fs::symlink_metadata(&pidfile)
            .unwrap()
            .file_type()
            .is_file());
        // A missing directory is still an error (a misconfigured --pid-file).
        assert!(write_pidfile(&dir.path().join("nope/agent.pid"), pid).is_err());
    }

    #[test]
    fn the_mode_is_the_one_asked_whatever_the_leftover_had() {
        let dir = tempfile::TempDir::new().unwrap();
        let target = dir.path().join("x.local");
        let leftover = dir.path().join(".x.local.tmp");
        fs::write(&leftover, "junk").unwrap();
        fs::set_permissions(&leftover, fs::Permissions::from_mode(0o666)).unwrap();
        replace(&target, b"body", 0o600).unwrap();
        assert_eq!(fs::metadata(&target).unwrap().mode() & 0o7777, 0o600);
        assert_eq!(fs::read_to_string(&target).unwrap(), "body");
    }
}
