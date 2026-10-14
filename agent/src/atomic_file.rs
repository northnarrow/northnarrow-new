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

use std::ffi::OsString;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::Path;

/// Replace `path` with `body` at mode `mode`.
pub fn replace(path: &Path, body: &[u8], mode: u32) -> io::Result<()> {
    let name = path
        .file_name()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "no file name"))?;
    let dir = match path.parent() {
        Some(d) if !d.as_os_str().is_empty() => d,
        _ => Path::new("."),
    };
    let mut tmp_name = OsString::from(".");
    tmp_name.push(name);
    tmp_name.push(".tmp");
    let tmp = dir.join(tmp_name);
    match fs::remove_file(&tmp) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }
    let written = (|| {
        let mut f = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(mode)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&tmp)?;
        f.set_permissions(fs::Permissions::from_mode(mode))?;
        f.write_all(body)?;
        f.sync_all()?;
        fs::rename(&tmp, path)?;
        File::open(dir)?.sync_all()
    })();
    if written.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    written
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::MetadataExt;

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
