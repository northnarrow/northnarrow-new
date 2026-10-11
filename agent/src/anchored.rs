//! Paths anchored to the directory the agent saw when it opened a log.
//!
//! Review entry 44 (`nn-lab.sh tamper-check`, C14): the signed logs were
//! reopened by path on every append, so a bind mount over
//! `/etc/northnarrow` made the agent write its own evidence — including the
//! `integrity_drift` entry reporting that very mount — into the attacker's
//! directory. A directory fd taken before the mount keeps resolving names
//! in the original directory (`openat`, and the `/proc/self/fd/<fd>/<name>`
//! magic link, which every path-based call can use unchanged; verified in
//! the lab for open, create, append and rename). [`anchor`] opens the parent
//! directory once, keeps the fd for the life of the process and returns the
//! anchored path; the integrity check still reports the mount itself.
//!
//! A mount that is already in place when the agent starts is anchored too;
//! the boot integrity check reports it, and the journal keeps the ERROR.

use std::collections::HashMap;
use std::fs::File;
use std::os::fd::AsRawFd;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};

static DIRS: OnceLock<Mutex<HashMap<PathBuf, File>>> = OnceLock::new();

const PROC_FD: &str = "/proc/self/fd/";

/// `path` resolved through a directory fd held since the first call for
/// its parent. Relative paths, paths already anchored, and parents that do
/// not exist (yet) are returned unchanged.
pub fn anchor(path: &Path) -> PathBuf {
    if !path.is_absolute() || path.starts_with(PROC_FD) {
        return path.to_path_buf();
    }
    let (Some(parent), Some(name)) = (path.parent(), path.file_name()) else {
        return path.to_path_buf();
    };
    let map = DIRS.get_or_init(|| Mutex::new(HashMap::new()));
    let mut map = match map.lock() {
        Ok(m) => m,
        Err(p) => p.into_inner(),
    };
    if !map.contains_key(parent) {
        match std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY)
            .open(parent)
        {
            Ok(f) => {
                map.insert(parent.to_path_buf(), f);
            }
            Err(_) => return path.to_path_buf(),
        }
    }
    let fd = map[parent].as_raw_fd();
    PathBuf::from(format!("{PROC_FD}{fd}")).join(name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn anchored_path_reaches_the_same_file_and_is_cached() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("log.jsonl");
        std::fs::write(&p, "a\n").unwrap();
        let a = anchor(&p);
        assert!(a.starts_with(PROC_FD), "{a:?}");
        assert_eq!(std::fs::read_to_string(&a).unwrap(), "a\n");
        assert_eq!(anchor(&p), a, "one fd per directory");
        // create + rename through the anchor land in the real directory
        let n = anchor(&dir.path().join("new"));
        std::fs::write(&n, "b").unwrap();
        std::fs::rename(&n, anchor(&dir.path().join("new2"))).unwrap();
        assert!(dir.path().join("new2").exists());
    }

    #[test]
    fn relative_missing_and_already_anchored_are_unchanged() {
        assert_eq!(anchor(Path::new("rel/x")), PathBuf::from("rel/x"));
        let missing = Path::new("/nonexistent-nn-dir/x");
        assert_eq!(anchor(missing), missing.to_path_buf());
        let already = Path::new("/proc/self/fd/3/x");
        assert_eq!(anchor(already), already.to_path_buf());
    }
}
