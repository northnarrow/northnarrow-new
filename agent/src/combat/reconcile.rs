//! The record of a stale COMBAT chain found at start (Beta Step 4a).
//!
//! The agent always boots into OBSERVING: a `NORTHNARROW_COMBAT` chain
//! present at start was left by a run that died mid-COMBAT, and it is torn
//! down before the audit log opens. External audit MAIN-013 (NN-AUD-255,
//! lab PR 180): that teardown used to be recorded only in
//! `combat-audit.jsonl`, the one unsigned evidence log (BUG-028), opened by
//! its literal path with the default mode. Now the outcome is kept until
//! the signed audit log is open and recorded there ([`attest`]: a signed
//! `integrity_drift`, kind `combat_reconcile`, also when the teardown
//! failed); the jsonl line stays for compatibility, written through the
//! directory fd taken at start ([`crate::anchored::anchor`]), `O_NOFOLLOW`,
//! created `0600` like the other state logs ([`append_line`]).
//!
//! Lab follow-up (lab PR 188): the line is written once the state
//! directory's protection exists, and a missing file is created with the
//! directory's `chattr +i` lifted for that moment ([`record_line`]). Written
//! at the teardown with a plain open, it was refused with EPERM whenever the
//! file did not exist yet.
//!
//! R08c (lab PR 252): the record itself — the outcome ([`StaleChain`]), its
//! signed entry ([`draft`]) and its append to the audit log ([`attest`]) —
//! is nn-core's `combat::reconcile`, here under its names. This file keeps
//! the compatibility log's Linux file I/O: the anchored, `O_NOFOLLOW` open,
//! the mode, the state directory's dance (nn-linux, R09).

use std::io::Write;
use std::os::unix::fs::{FileTypeExt, OpenOptionsExt};
use std::path::Path;

pub use nn_core::combat::reconcile::{attest, draft, StaleChain};

/// The unsigned compatibility log (docs/operator/COMBAT_RECOVERY.md).
pub const LOG_PATH: &str = "/var/lib/northnarrow/combat-audit.jsonl";

/// BUG-026 B-cap: the state directory is `chattr +i`, so a rename-based
/// rotation is a blocked directory-entry operation; past this size the
/// file is truncated in place (a content operation, allowed under `+i`).
pub const CAP_BYTES: u64 = 8 * 1024 * 1024;

/// Append one `combat_reconcile` line to the compatibility log at `path`.
/// The file is opened through the anchored parent, without following a
/// link and without waiting on a FIFO; anything but a regular file is
/// refused. A new file is created `0600` (an existing one keeps its
/// mode); one over `cap` bytes is truncated in place first.
pub fn append_line(path: &Path, rules_removed: usize, cap: u64) -> std::io::Result<()> {
    let line = serde_json::json!({
        "ts": chrono::Utc::now().to_rfc3339(),
        "event": "combat_reconcile",
        "reason": "stale_reconcile",
        "rules_torn_down": rules_removed,
    });
    let anchored = crate::anchored::anchor(path);
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .mode(crate::chainlog::STATE_LOG_FILE_MODE)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(&anchored)?;
    let meta = f.metadata()?;
    if !meta.file_type().is_file() {
        let what = if meta.file_type().is_fifo() {
            "a FIFO"
        } else {
            "not a regular file"
        };
        return Err(std::io::Error::other(format!(
            "{} is {what}: line not written",
            path.display()
        )));
    }
    if meta.len() > cap {
        // O_APPEND: the next write lands at the new end, offset 0.
        f.set_len(0)?;
    }
    writeln!(f, "{line}")
}

/// Lab follow-up (lab PR 188): append the compatibility line, creating the
/// file the way the agent creates its other state files. The state
/// directory is `chattr +i` from one run to the next, and `+i` refuses a new
/// entry to everyone, root and the agent included: an existing file takes
/// the line directly (a content operation, allowed under `+i`), a missing
/// one is created inside `protection`'s dance (`+i` lifted for the moment it
/// takes, restored after — [`crate::anti_tamper::filesystem::StateDirProtection`]).
/// The agent must be registered with the deny hooks a previous run left
/// pinned (the early registration and the anti-tamper attach do it, both
/// before the teardown): the hooks then let it through, and `+i` was what
/// refused the line in lab PR 180's probe (EPERM, the file missing). The
/// file stays out of `PROTECTED_INODES`, as before: the signed
/// `combat_reconcile` row is the evidence.
pub fn record_line(
    path: &Path,
    rules_removed: usize,
    cap: u64,
    protection: &dyn crate::chainlog::ProtectionManager,
) -> anyhow::Result<()> {
    match std::fs::symlink_metadata(path) {
        Ok(_) => Ok(append_line(path, rules_removed, cap)?),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            protection.with_mutable_dir(&mut || Ok(append_line(path, rules_removed, cap)?))
        }
        Err(e) => Err(e.into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use std::sync::Arc;

    use parking_lot::Mutex;

    use crate::audit::AuditLog;

    #[test]
    fn a_new_log_is_created_closed_and_appended() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("combat-audit.jsonl");
        append_line(&p, 3, CAP_BYTES).unwrap();
        append_line(&p, 0, CAP_BYTES).unwrap();
        let mode = std::fs::metadata(&p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "{mode:o}");
        let text = std::fs::read_to_string(&p).unwrap();
        let rows: Vec<serde_json::Value> = text
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0]["event"], "combat_reconcile");
        assert_eq!(rows[0]["reason"], "stale_reconcile");
        assert_eq!(rows[0]["rules_torn_down"], 3);
    }

    #[test]
    fn an_existing_log_keeps_its_mode_and_is_truncated_past_the_cap() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("combat-audit.jsonl");
        std::fs::write(&p, vec![b'x'; 100]).unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o640)).unwrap();
        append_line(&p, 1, 64).unwrap();
        let text = std::fs::read_to_string(&p).unwrap();
        assert_eq!(text.lines().count(), 1, "{text}");
        assert!(text.starts_with('{'), "{text}");
        let mode = std::fs::metadata(&p).unwrap().permissions().mode() & 0o777;
        assert_eq!(
            mode, 0o640,
            "the agent does not chmod a file it did not create"
        );
    }

    #[test]
    fn a_link_at_the_log_path_is_refused_not_followed() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("elsewhere");
        std::fs::write(&target, "").unwrap();
        let p = dir.path().join("combat-audit.jsonl");
        std::os::unix::fs::symlink(&target, &p).unwrap();
        assert!(append_line(&p, 1, CAP_BYTES).is_err());
        assert_eq!(
            std::fs::read_to_string(&target).unwrap(),
            "",
            "nothing written through the link"
        );
    }

    #[test]
    fn a_fifo_at_the_log_path_is_refused_without_waiting() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("combat-audit.jsonl");
        let c = std::ffi::CString::new(p.as_os_str().as_encoded_bytes()).unwrap();
        // SAFETY: a valid NUL-terminated path.
        assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);
        let (tx, rx) = std::sync::mpsc::channel();
        let q = p.clone();
        std::thread::spawn(move || {
            let _ = tx.send(append_line(&q, 1, CAP_BYTES).is_err());
        });
        let refused = rx
            .recv_timeout(std::time::Duration::from_secs(10))
            .expect("the writer must not block on a FIFO");
        assert!(refused);
    }

    /// A state directory that refuses new entries outside the dance: mode
    /// 0500, opened to 0700 for the dance only (the shape of `chattr +i`
    /// for a process without CAP_DAC_OVERRIDE).
    struct ClosedDir {
        dir: std::path::PathBuf,
        dances: std::sync::atomic::AtomicUsize,
    }

    impl ClosedDir {
        fn new(dir: &Path) -> Self {
            std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o500)).unwrap();
            Self {
                dir: dir.to_path_buf(),
                dances: std::sync::atomic::AtomicUsize::new(0),
            }
        }
        fn dances(&self) -> usize {
            self.dances.load(std::sync::atomic::Ordering::SeqCst)
        }
    }

    impl crate::chainlog::ProtectionManager for ClosedDir {
        fn with_mutable_dir(
            &self,
            f: &mut dyn FnMut() -> anyhow::Result<()>,
        ) -> anyhow::Result<()> {
            self.dances
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            std::fs::set_permissions(&self.dir, std::fs::Permissions::from_mode(0o700))?;
            let r = f();
            std::fs::set_permissions(&self.dir, std::fs::Permissions::from_mode(0o500))?;
            r
        }
        fn register_active(&self, _path: &Path) -> anyhow::Result<()> {
            Ok(())
        }
    }

    /// Lab follow-up (lab PR 188): in a directory that takes no new entry
    /// (the state directory under `chattr +i`), the line used to be refused
    /// when the file was missing — the lab's "could not write COMBAT
    /// reconcile audit line … Operation not permitted". It is created inside
    /// the dance, once; an existing file is appended without one.
    #[test]
    fn a_missing_log_is_created_inside_the_state_dir_dance() {
        // SAFETY: geteuid has no preconditions.
        if unsafe { libc::geteuid() } == 0 {
            eprintln!("skipped: root writes into a 0500 directory");
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("combat-audit.jsonl");
        let closed = ClosedDir::new(dir.path());
        let refused = append_line(&p, 1, CAP_BYTES).unwrap_err();
        assert_eq!(refused.kind(), std::io::ErrorKind::PermissionDenied);
        record_line(&p, 2, CAP_BYTES, &closed).expect("created inside the dance");
        assert_eq!(closed.dances(), 1);
        record_line(&p, 3, CAP_BYTES, &closed).expect("appended");
        assert_eq!(closed.dances(), 1, "an existing file needs no dance");
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let mode = std::fs::metadata(&p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "{mode:o}");
        let rows: Vec<serde_json::Value> = std::fs::read_to_string(&p)
            .unwrap()
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0]["rules_torn_down"], 2);
        assert_eq!(rows[1]["rules_torn_down"], 3);
    }

    /// Lab follow-up (lab PR 188): a link at the log path is still refused,
    /// and the dance is not entered for it.
    #[test]
    fn record_line_refuses_a_link_without_a_dance() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("elsewhere");
        std::fs::write(&target, "").unwrap();
        let p = dir.path().join("combat-audit.jsonl");
        std::os::unix::fs::symlink(&target, &p).unwrap();
        let open = ClosedDir {
            dir: dir.path().to_path_buf(),
            dances: std::sync::atomic::AtomicUsize::new(0),
        };
        assert!(record_line(&p, 1, CAP_BYTES, &open).is_err());
        assert_eq!(open.dances(), 0);
        assert_eq!(std::fs::read_to_string(&target).unwrap(), "");
    }

    #[test]
    fn the_outcome_is_signed_into_the_audit_log() {
        let dir = tempfile::tempdir().unwrap();
        let key = crate::audit::AgentSigningKey::load_or_bootstrap(&dir.path().join("agent.key"))
            .unwrap();
        let path = dir.path().join("audit.log");
        let pubkey = key.verifying_key();
        let log = Arc::new(Mutex::new(AuditLog::open(&path, key, [0u8; 16]).unwrap()));
        attest(Some(&log), &StaleChain::TornDown { rules_removed: 2 });
        let text = std::fs::read_to_string(&path).unwrap();
        let entries: Vec<crate::audit::AuditEntry> = text
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect();
        crate::audit::verify_chain(&entries, &pubkey).expect("the row verifies");
        let row = entries.last().unwrap();
        assert_eq!(row.op, "integrity_drift");
        assert_eq!(row.extra["kind"], "combat_reconcile");
        assert_eq!(row.result, "repaired");
    }
}
