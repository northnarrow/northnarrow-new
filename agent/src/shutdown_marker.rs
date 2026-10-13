//! Cross-component shutdown-authorisation marker (Tappa 8 A7, design
//! §10.3; external audit WDG-001, EVD-021, TST-003).
//!
//! When an admin quorum authorises a shutdown with a signed
//! [`ShutdownRequest`](common::wire::admin_protocol::ShutdownRequest), the
//! agent writes `/run/northnarrow/agent.shutdown_authorised` BEFORE
//! replying `Success` and beginning its own graceful exit. The watchdog
//! reads it when the agent's pidfd fires, to tell "admin authorised this
//! exit, stand down" from "agent died, restart it" (design §10.4).
//!
//! The marker ([`ShutdownMarker`], defined in `common` with its
//! verification) carries what the admins signed — the payload's canonical
//! CBOR and their signatures — and the exiting agent's pid. The watchdog
//! verifies it against `admin.pub` as the agent did, so a marker written
//! by anyone else, or replayed, is refused and the agent respawned. A
//! refusal is recorded at `/run/northnarrow/agent.shutdown_rejected`; the
//! agent's self-integrity check reports it in the signed audit chain
//! ([`crate::self_integrity`]).
//!
//! ## On-disk atomicity
//!
//! Temporary file + fsync + rename(2), in the marker's directory so the
//! rename is one inode swap. The temporary is created exclusively and
//! never through a symlink: a link planted at `<path>.tmp` is removed,
//! not followed (EVD-021).
//!
//! ## Permissions
//!
//! File mode `0600` (design §10.3): only root reads or writes it. `/run`
//! is tmpfs, so a reboot never inherits an authorisation.

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use anyhow::{anyhow, Context, Result};

pub use common::shutdown_marker::ShutdownMarker;

/// Canonical marker path ([`common::shutdown_marker::MARKER_PATH`]).
pub const DEFAULT_MARKER_PATH: &str = common::shutdown_marker::MARKER_PATH;

/// File mode applied at write time. Design §10.3 mandates 0600.
const MARKER_MODE: u32 = 0o600;

/// Mode for the parent directory if it does not already exist.
/// 0755 matches the `/run/<vendor>/` convention; systemd's
/// `RuntimeDirectory=` will typically already exist with a
/// tighter mode (0700), in which case this never triggers.
const PARENT_DIR_MODE: u32 = 0o755;

/// Atomically write `marker` to `path` (mode 0600, root-owned by virtue
/// of the agent running as root). Creates the parent directory at mode
/// 0755 if it does not exist.
pub fn write_marker(path: &Path, marker: &ShutdownMarker) -> Result<()> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::DirBuilder::new()
                .mode(PARENT_DIR_MODE)
                .recursive(true)
                .create(parent)
                .with_context(|| format!("creating marker parent dir {}", parent.display()))?;
        }
    }

    let tmp_path = tmp_path_for(path);
    // A leftover from a crash, or a link planted to redirect the write:
    // removed (unlink does not follow a symlink), then created exclusively.
    match fs::remove_file(&tmp_path) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => {
            return Err(anyhow!(e)).with_context(|| format!("removing {}", tmp_path.display()))
        }
    }
    {
        let mut f = OpenOptions::new()
            .write(true)
            .create_new(true)
            .custom_flags(libc::O_NOFOLLOW)
            .mode(MARKER_MODE)
            .open(&tmp_path)
            .with_context(|| format!("creating tmpfile {}", tmp_path.display()))?;
        let mut line = marker.to_line();
        line.push('\n');
        f.write_all(line.as_bytes())
            .with_context(|| format!("writing marker to {}", tmp_path.display()))?;
        f.sync_all()
            .with_context(|| format!("fsync {}", tmp_path.display()))?;
    }
    fs::rename(&tmp_path, path)
        .with_context(|| format!("renaming {} → {}", tmp_path.display(), path.display()))?;
    Ok(())
}

/// Read and parse the marker at `path`. `Ok(None)` when absent; `Err` when
/// present but not a marker of this format.
pub fn read_marker(path: &Path) -> Result<Option<ShutdownMarker>> {
    match fs::read_to_string(path) {
        Ok(content) => ShutdownMarker::parse(&content)
            .map(Some)
            .map_err(|e| anyhow!("{}: {e}", path.display())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(anyhow!(e).context(format!("reading {}", path.display()))),
    }
}

/// Best-effort marker removal. Returns Ok even if the file was
/// already absent — the watchdog calls this after successfully
/// honouring a marker; a race where the agent already removed it
/// (or a tmpfs reboot wiped it) is normal.
pub fn remove_marker(path: &Path) -> Result<()> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(anyhow!(e).context(format!("removing {}", path.display()))),
    }
}

/// `<path>.tmp` next to the target. The `.tmp` suffix prevents
/// the watchdog from ever parsing a half-written marker — it
/// reads only the canonical filename.
fn tmp_path_for(path: &Path) -> PathBuf {
    let mut s = path.as_os_str().to_owned();
    s.push(".tmp");
    PathBuf::from(s)
}

#[cfg(test)]
mod tests {
    use super::*;
    use common::wire::admin_signed_payload::SignedPayload;
    use std::os::unix::fs::PermissionsExt;
    use tempfile::TempDir;

    fn fresh_path() -> (TempDir, PathBuf) {
        let dir = TempDir::new().expect("tempdir");
        let path = dir.path().join("agent.shutdown_authorised");
        (dir, path)
    }

    fn sample_marker(pid: u32) -> ShutdownMarker {
        let payload = SignedPayload::new_shutdown([3; 32], 1_710_000_000, [5; 16], 30);
        ShutdownMarker::new(&payload, &[[1; 64], [2; 64]], pid).unwrap()
    }

    #[test]
    fn write_then_read_round_trips_marker() {
        let (_dir, path) = fresh_path();
        let marker = sample_marker(4242);
        write_marker(&path, &marker).expect("write");
        let got = read_marker(&path).expect("read").expect("present");
        assert_eq!(got, marker);
    }

    /// Design §10.3 mandates 0600; the atomic-write tmp file is cleaned
    /// up.
    #[test]
    fn write_marker_sets_mode_0600_and_cleans_up_tmp() {
        let (_dir, path) = fresh_path();
        write_marker(&path, &sample_marker(1)).expect("write");
        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o7777;
        assert_eq!(mode, MARKER_MODE, "marker file mode must be 0600");
        assert!(!tmp_path_for(&path).exists());
    }

    /// External audit EVD-021: a symlink planted at `<path>.tmp` is
    /// removed, not written through.
    #[test]
    fn a_link_planted_at_the_tmp_path_is_not_followed() {
        let (dir, path) = fresh_path();
        let victim = dir.path().join("victim");
        fs::write(&victim, "precious").unwrap();
        std::os::unix::fs::symlink(&victim, tmp_path_for(&path)).unwrap();
        write_marker(&path, &sample_marker(7)).expect("write");
        assert_eq!(fs::read_to_string(&victim).unwrap(), "precious");
        assert_eq!(read_marker(&path).unwrap().unwrap(), sample_marker(7));
    }

    #[test]
    fn read_marker_returns_none_when_path_absent() {
        let (_dir, path) = fresh_path();
        assert!(read_marker(&path)
            .expect("absent is not an error")
            .is_none());
    }

    /// Every corruption shape, and the pre-WDG-001 marker, is an error
    /// (the watchdog refuses it and restarts the agent).
    #[test]
    fn read_marker_rejects_every_corruption_shape() {
        for (label, content) in [
            ("not JSON at all", "this is not json"),
            (
                "the old unsigned marker",
                r#"{"entry_hash":"abababababababababababababababababababababababababababababababab","grace_deadline_unix_ts":1}"#,
            ),
            ("missing fields", r#"{"version":2}"#),
            ("empty file", ""),
        ] {
            let (_dir, path) = fresh_path();
            fs::write(&path, content).unwrap();
            assert!(read_marker(&path).is_err(), "[{label}] should have errored");
        }
    }

    #[test]
    fn remove_marker_is_idempotent_on_absent_file() {
        let (_dir, path) = fresh_path();
        remove_marker(&path).expect("idempotent on absent");
        remove_marker(&path).expect("still idempotent");
    }

    /// An admin re-issuing a shutdown after an earlier failed attempt
    /// left the marker behind overwrites it.
    #[test]
    fn write_marker_overwrites_existing() {
        let (_dir, path) = fresh_path();
        write_marker(&path, &sample_marker(1)).unwrap();
        write_marker(&path, &sample_marker(2)).unwrap();
        assert_eq!(read_marker(&path).unwrap().unwrap(), sample_marker(2));
    }
}
