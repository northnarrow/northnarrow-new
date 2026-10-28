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
//!
//! [`anchor`] is for the agent's fixed configuration paths (the logs named
//! on its command line: a handful of directories), never for a path a
//! request names: each directory keeps one fd for the life of the process.
//! External audit MAIN-015 (NN-AUD-257, lab PR 180): a parent that cannot
//! be opened (other than one that does not exist) leaves the path
//! unanchored, and that is an ERROR once per directory — it used to be
//! silent, with the mount-diversion protection off for that log.

use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::os::fd::AsRawFd;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};

static DIRS: OnceLock<Mutex<HashMap<PathBuf, File>>> = OnceLock::new();

/// Parents already reported as unanchored (one ERROR each).
static UNANCHORED: OnceLock<Mutex<HashSet<PathBuf>>> = OnceLock::new();

const PROC_FD: &str = "/proc/self/fd/";

/// `path` resolved through a directory fd held since the first call for
/// its parent. Relative paths, paths already anchored, and parents that do
/// not exist (yet) are returned unchanged; a parent that exists but cannot
/// be opened is returned unchanged too, with an ERROR the first time.
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
            Err(e) => {
                if e.kind() != std::io::ErrorKind::NotFound {
                    report_unanchored(parent, &e);
                }
                return path.to_path_buf();
            }
        }
    }
    let fd = map[parent].as_raw_fd();
    PathBuf::from(format!("{PROC_FD}{fd}")).join(name)
}

/// The ERROR for a parent [`anchor`] could not open, once per directory.
fn report_unanchored(parent: &Path, e: &std::io::Error) {
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
    }
}
