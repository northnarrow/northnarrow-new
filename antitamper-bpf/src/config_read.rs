//! Lot 311 (bug hunt 1.4, F4; the review of #538, F9): how a configuration
//! file the host's root may name — a drop-in, an `EnvironmentFile=` — is
//! read by the judges (`host_dropins`, `nn_linux::own_dropins`): read
//! only, as bytes, bounded, a regular file only. Its own module so that
//! `host_dropins` keeps no open call at all (`xtask/tests/cgroup_guard.rs`).

use std::path::Path;

/// The most a drop-in or an environment file is read of (systemd's own
/// limit on a unit file is far below it).
pub const MAX_CONFIG_BYTES: u64 = 1 << 20;

/// Lot 311 (F4): a configuration file read as bytes, what is not UTF-8
/// replaced (U+FFFD): a byte in a comment no longer hides the file's
/// directives from the judge. The review of #538 (F9): a regular file
/// only, opened without blocking (a FIFO named by `EnvironmentFile=` no
/// longer stalls the judge) and read up to [`MAX_CONFIG_BYTES`] (nor does
/// `/dev/zero` exhaust it); anything else is an error.
pub fn read_lossy(path: &Path) -> std::io::Result<String> {
    use std::io::Read;
    use std::os::unix::fs::OpenOptionsExt;
    let f = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(path)?;
    if !f.metadata()?.is_file() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "not a regular file",
        ));
    }
    let mut bytes = Vec::new();
    f.take(MAX_CONFIG_BYTES).read_to_end(&mut bytes)?;
    Ok(String::from_utf8_lossy(&bytes).into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Lot 311 (the review of #538, F9): a configuration file is read
    /// bounded and only when it is a regular file — a FIFO does not stall
    /// the judge, a huge file is cut at the bound, a directory is refused.
    #[test]
    fn a_configuration_read_is_bounded_and_never_blocks() {
        let d = tempfile::tempdir().unwrap();
        let fifo = d.path().join("fifo");
        let c = std::ffi::CString::new(fifo.to_str().unwrap()).unwrap();
        // SAFETY: a NUL-terminated path and a mode.
        assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);
        let t0 = std::time::Instant::now();
        assert!(
            read_lossy(&fifo).is_err(),
            "a FIFO is not a configuration file"
        );
        assert!(
            t0.elapsed() < std::time::Duration::from_secs(2),
            "it did not block"
        );
        assert!(read_lossy(d.path()).is_err(), "a directory either");
        let big = d.path().join("big.conf");
        std::fs::write(&big, vec![b'#'; (MAX_CONFIG_BYTES + 10) as usize]).unwrap();
        assert_eq!(read_lossy(&big).unwrap().len() as u64, MAX_CONFIG_BYTES);
    }
}
