//! Whether the audit log can be written, checked before anything attaches
//! (lab PR 218, external review G-09 / Q11-03).
//!
//! Wave 4 restructure, R04a (lab PR 241): from `crate::audit`, unchanged.
//! It asks the host (`access(2)`, an open for append): the chain code, for
//! nn-evidence, holds no such call.

use std::fs::OpenOptions;
use std::path::Path;

/// Lab PR 218 (external review G-09 / Q11-03): whether the audit log can be
/// written, checked before anything attaches. The signed `agent_boot` after
/// the attach still proves it with a row; this finds a read-only mount, an
/// immutable file or a missing directory while the host is untouched.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuditPreflight {
    /// Opened for append (no byte written), or its directory is writable.
    Writable,
    /// Refused with a permission error while the previous agent's pinned
    /// hooks may close it to this process (its early registration failed):
    /// the boot probe after the attach decides.
    Deferred(String),
    /// Cannot be written.
    Unwritable(String),
}

/// [`AuditPreflight`] for `path`; `closed_by_previous_hooks`: the early
/// registration in the pinned `PROTECTED_PIDS` failed.
pub fn preflight_writable(path: &Path, closed_by_previous_hooks: bool) -> AuditPreflight {
    let refused = |e: &std::io::Error| {
        if closed_by_previous_hooks && e.kind() == std::io::ErrorKind::PermissionDenied {
            AuditPreflight::Deferred(format!(
                "{}: {e} (the previous agent's hooks close it to an unregistered process)",
                path.display()
            ))
        } else {
            AuditPreflight::Unwritable(format!("{}: {e}", path.display()))
        }
    };
    match OpenOptions::new().append(true).open(path) {
        Ok(_) => AuditPreflight::Writable,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            // Created at the first append: its directory must take it.
            let dir = match path.parent() {
                Some(d) if !d.as_os_str().is_empty() => d,
                _ => Path::new("."),
            };
            match dir_writable(dir) {
                Ok(()) => AuditPreflight::Writable,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    // `AuditLog::open` creates a missing directory: its
                    // nearest existing ancestor must take it.
                    match dir.ancestors().skip(1).find(|a| a.exists()) {
                        Some(a) => match dir_writable(a) {
                            Ok(()) => AuditPreflight::Writable,
                            Err(e) => refused(&e),
                        },
                        None => refused(&e),
                    }
                }
                Err(e) => refused(&e),
            }
        }
        Err(e) => refused(&e),
    }
}

/// `access(dir, W_OK)`: `EROFS` on a read-only mount.
fn dir_writable(dir: &Path) -> std::io::Result<()> {
    use std::os::unix::ffi::OsStrExt;
    let c = std::ffi::CString::new(dir.as_os_str().as_bytes())
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;
    // SAFETY: a NUL-terminated path and a mode constant.
    if unsafe { libc::access(c.as_ptr(), libc::W_OK) } == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Lab PR 218 (external review G-09): the audit log's writability is
    /// read without writing — a missing file in a writable directory, an
    /// existing file, a directory that cannot take it; a permission error
    /// is left to the boot probe only while the previous hooks may cause it.
    #[test]
    fn the_audit_preflight_writes_nothing_and_finds_an_unwritable_log() {
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("audit.log");
        assert_eq!(preflight_writable(&log, false), AuditPreflight::Writable);
        assert!(!log.exists(), "nothing created");
        assert_eq!(
            preflight_writable(&dir.path().join("etc/northnarrow/audit.log"), false),
            AuditPreflight::Writable,
            "the open creates the directory"
        );
        std::fs::write(&log, b"").unwrap();
        assert_eq!(preflight_writable(&log, false), AuditPreflight::Writable);
        assert_eq!(std::fs::read(&log).unwrap(), b"", "no byte written");
        // A directory in place of the file cannot be opened for append.
        let not_a_file = dir.path().join("dir.log");
        std::fs::create_dir(&not_a_file).unwrap();
        assert!(matches!(
            preflight_writable(&not_a_file, false),
            AuditPreflight::Unwritable(_)
        ));
        assert!(
            matches!(
                preflight_writable(&not_a_file, true),
                AuditPreflight::Unwritable(_)
            ),
            "not a permission error: never deferred"
        );
    }
}
