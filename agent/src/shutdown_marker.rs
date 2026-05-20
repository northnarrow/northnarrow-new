//! Cross-component shutdown-authorisation marker (Tappa 8 A7,
//! design §10.3).
//!
//! When an admin successfully submits a quorum-signed
//! [`ShutdownRequest`](common::wire::admin_protocol::ShutdownRequest),
//! the agent atomically writes a small file at
//! `/run/northnarrow/agent.shutdown_authorised` BEFORE replying
//! `Success` and beginning its own graceful exit. The watchdog
//! (Tappa 7 Task 6) reads this file the next time it observes the
//! agent's `pidfd` POLLIN and uses it to distinguish "admin
//! authorised this exit, stand down" from "agent died
//! unexpectedly, restart it" (design §10.4).
//!
//! ## File format
//!
//! Single-line JSON object:
//! ```text
//! {"entry_hash":"<64 hex chars>","grace_deadline_unix_ts":1234567890}
//! ```
//!
//! Two fields:
//! - **`entry_hash`** — 64 hex chars, intended to be the audit-log
//!   entry hash for this shutdown operation (design §10.4 "validates
//!   the entry_hash against the audit log"). The hash chain itself
//!   ships in A11; until then, A7 uses
//!   `hex(SHA-256(signing_digest(payload)))` as a synthetic
//!   placeholder. The watchdog cross-validates against the audit
//!   log in A8 — for now the field is a stable opaque token.
//! - **`grace_deadline_unix_ts`** — the wall-clock second past
//!   which a marker is considered stale and the watchdog will
//!   restart the agent regardless. Computed by the agent as
//!   `server_now + grace_secs` at write time, where `grace_secs`
//!   came from the operator's [`ShutdownExtra::grace_secs`].
//!
//! ## On-disk atomicity
//!
//! Same tmpfile + fsync + rename(2) pattern as
//! [`crate::agent_id::load_or_bootstrap`]. A crash mid-write
//! never leaves a half-formed marker for the watchdog to
//! misinterpret. The tmp file sits in the same directory as the
//! target so `rename` is one inode swap (EXDEV-free).
//!
//! ## Permissions
//!
//! - File mode `0600` per design §10.3 — only root may read or
//!   write. (Watchdog runs as root, so it can read.)
//! - Directory mode `0755` (created if missing — fresh installs).
//! - `/run/` is tmpfs on systemd hosts, so the marker is
//!   automatically cleared on reboot. That's the desired
//!   behaviour: a fresh boot must NOT inherit a stale shutdown
//!   authorisation from a previous run.

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use anyhow::{anyhow, Context, Result};
use serde::{Deserialize, Serialize};

/// Canonical marker path. systemd `RuntimeDirectory=northnarrow`
/// creates `/run/northnarrow/` at unit start with `RuntimeDirectoryMode=0700`;
/// the dispatcher widens this single file to `0600` regardless
/// (still root-only).
pub const DEFAULT_MARKER_PATH: &str = "/run/northnarrow/agent.shutdown_authorised";

/// File mode applied at write time. Design §10.3 mandates 0600.
const MARKER_MODE: u32 = 0o600;

/// Mode for the parent directory if it does not already exist.
/// 0755 matches the `/run/<vendor>/` convention; systemd's
/// `RuntimeDirectory=` will typically already exist with a
/// tighter mode (0700), in which case this never triggers.
const PARENT_DIR_MODE: u32 = 0o755;

/// On-disk shape of the marker. Wire-stable (the watchdog parses
/// the same struct from the same bytes); fields are append-only.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShutdownMarker {
    /// Hex-encoded opaque hash uniquely identifying the audit-log
    /// record for this shutdown. 64 hex chars (SHA-256 width).
    /// Until the audit chain ships in A11, the agent fills this
    /// with `hex(SHA-256(signing_digest(payload)))` as a stable
    /// placeholder.
    pub entry_hash: String,
    /// Wall-clock second past which the marker is considered
    /// stale. Watchdog rejects markers whose deadline has elapsed.
    pub grace_deadline_unix_ts: u64,
}

/// Atomically write `marker` to `path` (mode 0600, root-owned by
/// virtue of the agent running as root). Creates the parent
/// directory at mode 0755 if it does not exist. The tmp file
/// (`<path>.tmp`) is fsync'd before the rename so a crash between
/// rename(2) and an absent fsync cannot leave a stale marker
/// pointing at zero-byte content.
pub fn write_marker(path: &Path, marker: &ShutdownMarker) -> Result<()> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::DirBuilder::new()
                .mode(PARENT_DIR_MODE)
                .recursive(true)
                .create(parent)
                .with_context(|| {
                    format!("creating marker parent dir {}", parent.display())
                })?;
        }
    }

    let tmp_path = tmp_path_for(path);
    {
        let mut f = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(MARKER_MODE)
            .open(&tmp_path)
            .with_context(|| {
                format!("opening tmpfile {}", tmp_path.display())
            })?;
        let line = serde_json::to_string(marker)
            .context("serialising ShutdownMarker to JSON")?;
        f.write_all(line.as_bytes())
            .with_context(|| {
                format!("writing marker JSON to {}", tmp_path.display())
            })?;
        f.write_all(b"\n").ok();
        f.sync_all()
            .with_context(|| format!("fsync {}", tmp_path.display()))?;
    }
    fs::rename(&tmp_path, path).with_context(|| {
        format!(
            "renaming {} → {}",
            tmp_path.display(),
            path.display()
        )
    })?;
    Ok(())
}

/// Read and parse a marker from `path`. Returns `Ok(None)` if the
/// file is absent (the common case — most boots never have an
/// admin-authorised shutdown pending). Returns `Err` on corruption
/// so the watchdog can distinguish "no marker, restart" (safe
/// default) from "marker present but malformed" (suspicious —
/// design §10.4 step 4 treats this as a tampering attempt).
pub fn read_marker(path: &Path) -> Result<Option<ShutdownMarker>> {
    match fs::read_to_string(path) {
        Ok(content) => {
            let marker: ShutdownMarker = serde_json::from_str(content.trim())
                .with_context(|| {
                    format!("parsing marker JSON from {}", path.display())
                })?;
            if marker.entry_hash.len() != 64
                || !marker.entry_hash.bytes().all(|b| b.is_ascii_hexdigit())
            {
                return Err(anyhow!(
                    "marker entry_hash must be 64 lowercase hex chars (got {} chars)",
                    marker.entry_hash.len()
                ));
            }
            Ok(Some(marker))
        }
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
/// the watchdog from ever parsing a half-written marker — its
/// `read_marker(path)` reads only the canonical filename.
fn tmp_path_for(path: &Path) -> PathBuf {
    let mut s = path.as_os_str().to_owned();
    s.push(".tmp");
    PathBuf::from(s)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use tempfile::TempDir;

    fn fresh_path() -> (TempDir, PathBuf) {
        let dir = TempDir::new().expect("tempdir");
        let path = dir.path().join("agent.shutdown_authorised");
        (dir, path)
    }

    fn sample_marker() -> ShutdownMarker {
        ShutdownMarker {
            entry_hash: "ab".repeat(32),       // 64 hex chars
            grace_deadline_unix_ts: 1_710_000_030,
        }
    }

    /// Required A7 test 1: round-trip write → read returns the
    /// same marker bytes-for-bytes. Anchors the on-disk format
    /// against a future serde-derive regression that might emit
    /// fields in a different order.
    #[test]
    fn write_then_read_round_trips_marker() {
        let (_dir, path) = fresh_path();
        let marker = sample_marker();
        write_marker(&path, &marker).expect("write");
        let got = read_marker(&path).expect("read").expect("present");
        assert_eq!(got, marker);
    }

    /// Required A7 test 2: writer enforces mode 0600 (design
    /// §10.3 mandates this), and the atomic-write tmp file is
    /// cleaned up.
    #[test]
    fn write_marker_sets_mode_0600_and_cleans_up_tmp() {
        let (_dir, path) = fresh_path();
        write_marker(&path, &sample_marker()).expect("write");

        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o7777;
        assert_eq!(mode, MARKER_MODE, "marker file mode must be 0600");

        let tmp = tmp_path_for(&path);
        assert!(
            !tmp.exists(),
            "atomic write must clean up its tmp file: {}",
            tmp.display()
        );
    }

    /// Required A7 test 3: absent file surfaces as Ok(None) (the
    /// common path — most agent boots never have an
    /// admin-authorised shutdown pending). Distinct from
    /// Err(corruption).
    #[test]
    fn read_marker_returns_none_when_path_absent() {
        let (_dir, path) = fresh_path();
        assert!(!path.exists());
        let res = read_marker(&path).expect("absent is not an error");
        assert!(res.is_none(), "absent file should yield Ok(None)");
    }

    /// Required A7 test 4: every corruption shape surfaces Err,
    /// not silently-empty Ok(None). Covers: not-JSON, JSON but
    /// missing fields, entry_hash wrong length, entry_hash
    /// non-hex characters. Watchdog (A8) will treat Err here as
    /// design §10.4 step 4 tampering signal and restart anyway.
    #[test]
    fn read_marker_rejects_every_corruption_shape() {
        for (label, content) in [
            ("not JSON at all", "this is not json"),
            ("JSON missing entry_hash", r#"{"grace_deadline_unix_ts":100}"#),
            ("JSON missing grace_deadline_unix_ts", r#"{"entry_hash":"ab"}"#),
            (
                "entry_hash too short",
                r#"{"entry_hash":"abc","grace_deadline_unix_ts":1}"#,
            ),
            (
                "entry_hash too long",
                &format!(r#"{{"entry_hash":"{}","grace_deadline_unix_ts":1}}"#, "ab".repeat(33)),
            ),
            (
                "entry_hash non-hex",
                &format!(r#"{{"entry_hash":"{}","grace_deadline_unix_ts":1}}"#, "zz".repeat(32)),
            ),
            ("empty file", ""),
        ] {
            let (_dir, path) = fresh_path();
            fs::write(&path, content).unwrap();
            let err = read_marker(&path)
                .unwrap_err_or_else(|| panic!("[{label}] should have errored"));
            let chain = format!("{err:#}");
            assert!(
                !chain.is_empty(),
                "[{label}] error chain should be non-empty"
            );
        }
    }

    /// Supplementary: remove_marker is idempotent — calling it on
    /// an absent path is Ok. Documents the watchdog's safe-to-call
    /// contract.
    #[test]
    fn remove_marker_is_idempotent_on_absent_file() {
        let (_dir, path) = fresh_path();
        assert!(!path.exists());
        remove_marker(&path).expect("idempotent on absent");
        // Run again — still Ok.
        remove_marker(&path).expect("still idempotent");
    }

    /// Supplementary: write+remove cycle leaves the directory
    /// clean. Documents that the watchdog reading + removing the
    /// marker does not leave debris.
    #[test]
    fn write_then_remove_cycle_leaves_no_residue() {
        let (_dir, path) = fresh_path();
        write_marker(&path, &sample_marker()).unwrap();
        assert!(path.exists());
        remove_marker(&path).unwrap();
        assert!(!path.exists(), "remove_marker must unlink the file");
    }

    /// Supplementary: writing twice to the same path overwrites
    /// the first marker. Important for the (uncommon) case of an
    /// admin re-issuing a shutdown after an earlier failed
    /// attempt left the marker behind.
    #[test]
    fn write_marker_overwrites_existing() {
        let (_dir, path) = fresh_path();
        let first = ShutdownMarker {
            entry_hash: "11".repeat(32),
            grace_deadline_unix_ts: 100,
        };
        let second = ShutdownMarker {
            entry_hash: "22".repeat(32),
            grace_deadline_unix_ts: 200,
        };
        write_marker(&path, &first).unwrap();
        write_marker(&path, &second).unwrap();
        let got = read_marker(&path).unwrap().unwrap();
        assert_eq!(got, second);
    }

    // Helper used in `read_marker_rejects_every_corruption_shape`.
    // `Result::unwrap_err_or_else` doesn't exist in std — define
    // an ad-hoc extension trait to keep the test body readable.
    trait UnwrapErrOrElse<T, E> {
        fn unwrap_err_or_else<F: FnOnce() -> E>(self, default: F) -> E;
    }
    impl<T, E> UnwrapErrOrElse<T, E> for std::result::Result<T, E> {
        fn unwrap_err_or_else<F: FnOnce() -> E>(self, default: F) -> E {
            match self {
                Ok(_) => default(),
                Err(e) => e,
            }
        }
    }
}
