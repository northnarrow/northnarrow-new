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

use std::io::Write;
use std::os::unix::fs::{FileTypeExt, OpenOptionsExt};
use std::path::Path;
use std::sync::Arc;

use parking_lot::Mutex;
use tracing::warn;

use crate::audit::{AuditEntryDraft, AuditLog};

/// The unsigned compatibility log (docs/operator/COMBAT_RECOVERY.md).
pub const LOG_PATH: &str = "/var/lib/northnarrow/combat-audit.jsonl";

/// BUG-026 B-cap: the state directory is `chattr +i`, so a rename-based
/// rotation is a blocked directory-entry operation; past this size the
/// file is truncated in place (a content operation, allowed under `+i`).
pub const CAP_BYTES: u64 = 8 * 1024 * 1024;

/// What the start-time reconcile did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StaleChain {
    /// The chain(s) were present and torn down.
    TornDown { rules_removed: usize },
    /// The chain is (or may still be) present: the probe or the teardown
    /// failed.
    Failed { error: String },
}

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

/// The signed entry for `outcome` (`integrity_drift`, kind
/// `combat_reconcile`, `at_boot`).
pub fn draft(outcome: &StaleChain) -> AuditEntryDraft {
    let (extra, result) = match outcome {
        StaleChain::TornDown { rules_removed } => (
            serde_json::json!({
                "kind": "combat_reconcile",
                "detail": format!(
                    "a NORTHNARROW_COMBAT chain left by an earlier run (killed or crashed in \
                     COMBAT) was found at start and torn down: {rules_removed} rules removed; \
                     the host is no longer isolated by it"
                ),
                "rules_torn_down": rules_removed,
                "at_boot": true,
            }),
            "repaired",
        ),
        StaleChain::Failed { error } => (
            serde_json::json!({
                "kind": "combat_reconcile",
                "detail": format!(
                    "a NORTHNARROW_COMBAT chain left by an earlier run could not be checked or \
                     torn down at start ({error}): the host may still be isolated by it — \
                     see docs/operator/COMBAT_RECOVERY.md"
                ),
                "at_boot": true,
            }),
            "failed",
        ),
    };
    AuditEntryDraft {
        op: crate::self_integrity::AUDIT_OP.to_string(),
        extra,
        key_fp: "agent-self".to_string(),
        cosigner_fps: Vec::new(),
        result: result.to_string(),
        client_pid: std::process::id(),
        client_uid: 0,
        client_comm: "northnarrow-agent".to_string(),
        client_exe: None,
    }
}

/// Record `outcome` in the signed audit log (once it is open). Without a
/// log the journal keeps the WARN the reconcile logged.
pub fn attest(audit_log: Option<&Arc<Mutex<AuditLog>>>, outcome: &StaleChain) {
    let Some(log) = audit_log else {
        return;
    };
    if let Err(e) = log.lock().append(draft(outcome)) {
        warn!(
            error = format!("{e:#}"),
            "recording the COMBAT reconcile in the audit log failed"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

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

    #[test]
    fn the_signed_entry_names_the_outcome() {
        let d = draft(&StaleChain::TornDown { rules_removed: 7 });
        assert_eq!(d.op, "integrity_drift");
        assert_eq!(d.result, "repaired");
        assert_eq!(d.extra["kind"], "combat_reconcile");
        assert_eq!(d.extra["rules_torn_down"], 7);
        assert_eq!(d.extra["at_boot"], true);
        let d = draft(&StaleChain::Failed {
            error: "iptables: exit 4".to_string(),
        });
        assert_eq!(d.result, "failed");
        assert!(d.extra["detail"]
            .as_str()
            .unwrap()
            .contains("iptables: exit 4"));
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
