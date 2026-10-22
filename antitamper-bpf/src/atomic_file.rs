//! Replacing a file in a directory another root process can write
//! (external audit AUT-003; shared with the watchdog since WDG-015,
//! NN-AUD-364).
//!
//! The agent is the one process its own deny hooks let write
//! `/etc/northnarrow` and the state directory, and it rewrote `admin.pub`
//! (rotate-keys) and the signed overlays (`config overlay set`) through a
//! temporary file opened with `create(true).truncate(true)` at a fixed
//! name. Root may create entries in the directory while the agent runs: a
//! link planted at that name (`admin.pub.tmp -> audit.log`) made the next
//! legitimate rotation truncate the audit chain — written through by the
//! one process allowed to — and then rename the link over `admin.pub`.
//! The pidfiles in `/run/northnarrow` (agent and watchdog, the processes
//! the hooks trust) were written the same way.
//!
//! [`replace`] removes whatever sits at the temporary name (`unlink` never
//! follows a link), creates it exclusively — `O_CREAT | O_EXCL`, which
//! fails on any entry at the name, a link included, and never follows one;
//! std opens every file `O_CLOEXEC` — sets the mode on the descriptor (the
//! umask does not decide it), writes, syncs, renames it into place and
//! syncs the directory, so the rename survives a crash.

use std::ffi::OsString;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::Path;

/// Replace `path` with `body` at mode `mode`. The temporary file is
/// `.<name>.tmp` in the same directory; a missing directory is an error.
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

/// A pidfile, `<pid>\n` at mode 0644 (its readers are root processes and
/// the lab tooling), written with [`replace`]: the agent's and the
/// watchdog's in `/run/northnarrow`, which root can write and the inode
/// deny set does not cover (external audit WDG-015, NN-AUD-364).
pub fn write_pidfile(path: &Path, pid: u32) -> io::Result<()> {
    replace(path, format!("{pid}\n").as_bytes(), 0o644)
}
