//! Lot 311 (bug hunt 1.4, F4; the review of #538, F9 and G1): how a
//! configuration file the host's root may name — a drop-in, an
//! `EnvironmentFile=` — is read by the judges (`host_dropins`,
//! `nn_linux::own_dropins`): read only, as bytes, bounded, a regular file
//! only — and what the judge cannot read is never taken for empty. Its own
//! module so that `host_dropins` keeps no open call at all
//! (`xtask/tests/cgroup_guard.rs`).

use std::path::Path;

/// The most a drop-in or an environment file is read of (systemd's own
/// limit on a unit file is far below it).
pub const MAX_CONFIG_BYTES: u64 = 1 << 20;

/// What a judge reads at a configuration file's path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Config {
    /// Nothing there for systemd either: no such file (`ENOENT`,
    /// `ENOTDIR`, `ELOOP`, `ENAMETOOLONG`: the path resolves the same for
    /// PID 1). A refusal (`EACCES`) is not one: the watchdog runs without
    /// `CAP_DAC_OVERRIDE` and with `ProtectHome=true`, PID 1 reads what it
    /// is refused — that is [`Config::Unjudgeable`].
    Absent,
    /// A regular file's text, bytes that are not UTF-8 replaced (U+FFFD);
    /// or `/dev/null`'s nothing — systemd's way of masking a drop-in.
    Text(String),
    /// The review of #538 (G1): what systemd would read there, the judge
    /// cannot — a FIFO (systemd reads an `EnvironmentFile=` from its
    /// writer), a socket, a device, a directory, or a read that failed for
    /// a reason of the judge's own. Judged harmful, never empty: why, in
    /// words.
    Unjudgeable(String),
}

impl Config {
    /// The text to judge; `None` for nothing there and for what cannot be
    /// judged (a caller that takes `None` as harmless must have judged
    /// [`Config::Unjudgeable`] first).
    pub fn text(self) -> Option<String> {
        match self {
            Config::Text(t) => Some(t),
            Config::Absent | Config::Unjudgeable(_) => None,
        }
    }
}

/// The kind of a file that is not a regular one, in words.
fn kind_of(t: std::fs::FileType) -> &'static str {
    use std::os::unix::fs::FileTypeExt;
    if t.is_fifo() {
        "a FIFO"
    } else if t.is_socket() {
        "a socket"
    } else if t.is_char_device() {
        "a character device"
    } else if t.is_block_device() {
        "a block device"
    } else if t.is_dir() {
        "a directory"
    } else {
        "not a regular file"
    }
}

/// Lot 311 (F4): a configuration file read as bytes, what is not UTF-8
/// replaced: a byte in a comment no longer hides the file's directives from
/// the judge. The review of #538 (F9): read up to [`MAX_CONFIG_BYTES`]
/// (`/dev/zero` does not exhaust the judge). G1: the path is first opened
/// `O_PATH` — no device opened, no FIFO waited on, no terminal taken as a
/// controlling one — and only a regular file is then read, reopened through
/// its descriptor (the same inode, no race with a rename); anything else
/// is [`Config::Unjudgeable`] (`/dev/null` excepted: it reads nothing, for
/// the judge as for systemd).
pub fn read_config(path: &Path) -> Config {
    use std::io::Read;
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt};
    let unjudgeable = |e: std::io::Error| match e.raw_os_error() {
        Some(libc::ENOENT | libc::ENOTDIR | libc::ELOOP | libc::ENAMETOOLONG) => Config::Absent,
        _ => Config::Unjudgeable(format!(
            "it could not be read ({e}): what systemd reads there cannot be judged"
        )),
    };
    let at = match std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_PATH | libc::O_CLOEXEC)
        .open(path)
    {
        Ok(f) => f,
        Err(e) => return unjudgeable(e),
    };
    let meta = match at.metadata() {
        Ok(m) => m,
        Err(e) => return unjudgeable(e),
    };
    let t = meta.file_type();
    if t.is_char_device() && meta.rdev() == libc::makedev(1, 3) {
        return Config::Text(String::new());
    }
    if !t.is_file() {
        return Config::Unjudgeable(format!(
            "{}, not a regular file: what systemd reads from it cannot be judged",
            kind_of(t)
        ));
    }
    let f = match std::fs::File::open(format!("/proc/self/fd/{}", at.as_raw_fd())) {
        Ok(f) => f,
        Err(e) => return unjudgeable(e),
    };
    let mut bytes = Vec::new();
    if let Err(e) = f.take(MAX_CONFIG_BYTES).read_to_end(&mut bytes) {
        return unjudgeable(e);
    }
    Config::Text(String::from_utf8_lossy(&bytes).into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unjudgeable(c: Config, kind: &str) {
        match c {
            Config::Unjudgeable(why) => assert!(why.starts_with(kind), "{why}"),
            other => panic!("{kind}: {other:?}"),
        }
    }

    /// Lot 311 (the review of #538, F9): a configuration file is read
    /// bounded — a huge file is cut at the bound — and read as bytes.
    #[test]
    fn a_configuration_read_is_bounded_and_never_blocks() {
        let d = tempfile::tempdir().unwrap();
        let big = d.path().join("big.conf");
        std::fs::write(&big, vec![b'#'; (MAX_CONFIG_BYTES + 10) as usize]).unwrap();
        let Config::Text(t) = read_config(&big) else {
            panic!("a regular file is text")
        };
        assert_eq!(t.len() as u64, MAX_CONFIG_BYTES);
        let latin1 = d.path().join("l.conf");
        std::fs::write(&latin1, b"# r\xe9glage\nLD_PRELOAD=/tmp/x.so\n").unwrap();
        assert!(read_config(&latin1)
            .text()
            .is_some_and(|t| t.contains("LD_PRELOAD")));
        assert_eq!(read_config(&d.path().join("none")), Config::Absent);
    }

    /// The review of #538 (G1): a FIFO — systemd reads an `EnvironmentFile=`
    /// from its writer — cannot be judged: never empty, and never waited on.
    #[test]
    fn a_fifo_is_unjudgeable_and_never_blocks() {
        let d = tempfile::tempdir().unwrap();
        let fifo = d.path().join("fifo");
        let c = std::ffi::CString::new(fifo.to_str().unwrap()).unwrap();
        // SAFETY: a NUL-terminated path and a mode.
        assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);
        let t0 = std::time::Instant::now();
        unjudgeable(read_config(&fifo), "a FIFO");
        assert!(
            t0.elapsed() < std::time::Duration::from_secs(2),
            "not waited on"
        );
        // through a symlink too (systemd follows it)
        let link = d.path().join("env");
        std::os::unix::fs::symlink(&fifo, &link).unwrap();
        unjudgeable(read_config(&link), "a FIFO");
    }

    /// G1: a socket cannot be judged.
    #[test]
    fn a_socket_is_unjudgeable() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("sock");
        let _l = std::os::unix::net::UnixListener::bind(&p).unwrap();
        unjudgeable(read_config(&p), "a socket");
    }

    /// G1: a character device cannot be judged — and it is not opened
    /// (`O_PATH`: `/dev/zero` is not read, a terminal is not taken) — but
    /// `/dev/null` reads nothing, for the judge as for systemd (a drop-in
    /// masked by a link to it).
    #[test]
    fn a_character_device_is_unjudgeable_but_dev_null_is_empty() {
        unjudgeable(read_config(Path::new("/dev/zero")), "a character device");
        unjudgeable(read_config(Path::new("/dev/tty")), "a character device");
        assert_eq!(
            read_config(Path::new("/dev/null")),
            Config::Text(String::new())
        );
        let d = tempfile::tempdir().unwrap();
        let masked = d.path().join("10-timeout-abort.conf");
        std::os::unix::fs::symlink("/dev/null", &masked).unwrap();
        assert_eq!(read_config(&masked), Config::Text(String::new()));
    }

    /// G1: a block device cannot be judged (`O_PATH` opens none: no
    /// permission on it is needed to see what it is).
    #[test]
    fn a_block_device_is_unjudgeable() {
        use std::os::unix::fs::FileTypeExt;
        let block = std::fs::read_dir("/dev")
            .unwrap()
            .flatten()
            .find(|e| e.file_type().is_ok_and(|t| t.is_block_device()))
            .map(|e| e.path());
        // every Linux host and runner has one (a disk, a loop device)
        let block = block.expect("a block device under /dev");
        unjudgeable(read_config(&block), "a block device");
    }

    /// G1: a file the judge is refused is no absent file — the watchdog
    /// (no `CAP_DAC_OVERRIDE`, `ProtectHome=true`) is refused what PID 1
    /// reads (as root, the file is read through its mode).
    #[test]
    fn a_refused_file_is_unjudgeable_not_absent() {
        let d = tempfile::tempdir().unwrap();
        let shut = d.path().join("shut");
        std::fs::create_dir(&shut).unwrap();
        std::fs::write(shut.join("env"), b"LD_PRELOAD=/tmp/x.so\n").unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&shut, std::fs::Permissions::from_mode(0o000)).unwrap();
        let got = read_config(&shut.join("env"));
        std::fs::set_permissions(&shut, std::fs::Permissions::from_mode(0o700)).unwrap();
        // SAFETY: geteuid has no precondition and cannot fail.
        if unsafe { libc::geteuid() } == 0 {
            // root (CAP_DAC_OVERRIDE) reads through the mode, as PID 1
            assert!(got.text().is_some_and(|t| t.contains("LD_PRELOAD")));
        } else {
            unjudgeable(got, "it could not be read");
        }
    }

    /// G1: a directory where a file is expected cannot be judged.
    #[test]
    fn a_directory_is_unjudgeable() {
        let d = tempfile::tempdir().unwrap();
        let dir = d.path().join("x.conf");
        std::fs::create_dir(&dir).unwrap();
        unjudgeable(read_config(&dir), "a directory");
    }
}
