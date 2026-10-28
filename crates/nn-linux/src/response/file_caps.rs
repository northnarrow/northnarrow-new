//! Review 86: `StripFileCapability` — remove the `security.capability`
//! xattr a verdict's file was given, undoing a capability grant.
//!
//! The grant is reported on `inode_post_setxattr`, after the kernel
//! stored it, so the removal cannot run before the grant lands. The
//! file is named by the path the file-open sensor rebuilt; a path it
//! could not rebuild whole (`…/name`) cannot be acted on and reports
//! the error.

use std::ffi::CString;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

use super::ExecutionOutcome;

const XATTR_NAME_CAPS: &str = "security.capability";

/// Remove the capability from `path`, through the host's view of it
/// ([`super::host_path`]: the agent's own mounts are read-only). `pid` is
/// the process that set it, carried into the outcome for the audit trail.
pub fn strip(path: &str, pid: u32) -> ExecutionOutcome {
    let Ok(name) = CString::new(XATTR_NAME_CAPS) else {
        return ExecutionOutcome::Failed {
            pid,
            errno: libc::EINVAL,
        };
    };
    let removed = super::on_host_path(Path::new(path), |p| {
        let c_path = CString::new(p.as_os_str().as_bytes())
            .map_err(|_| std::io::Error::from_raw_os_error(libc::EINVAL))?;
        // SAFETY: both pointers are valid NUL-terminated strings for the call.
        match unsafe { libc::removexattr(c_path.as_ptr(), name.as_ptr()) } {
            0 => Ok(()),
            _ => Err(std::io::Error::last_os_error()),
        }
    });
    match removed.map_err(|e| e.raw_os_error().unwrap_or(0)) {
        // ENODATA: already gone (removed by an operator, or the file replaced).
        Ok(()) | Err(libc::ENODATA) => ExecutionOutcome::CapabilityStripped {
            path: path.to_string(),
        },
        Err(errno) => ExecutionOutcome::Failed { pid, errno },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_missing_file_is_reported_not_claimed() {
        match strip("/nonexistent/nn-review-86", 4242) {
            ExecutionOutcome::Failed { pid, errno } => {
                assert_eq!(pid, 4242);
                assert_eq!(errno, libc::ENOENT);
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn a_file_without_a_capability_is_already_stripped() {
        let f = tempfile::NamedTempFile::new().unwrap();
        let path = f.path().to_str().unwrap();
        match strip(path, 1) {
            // ENODATA, or ENOTSUP on a filesystem without xattrs.
            ExecutionOutcome::CapabilityStripped { .. } | ExecutionOutcome::Failed { .. } => {}
            other => panic!("unexpected {other:?}"),
        }
    }
}
