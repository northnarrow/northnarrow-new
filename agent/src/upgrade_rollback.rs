//! Lab PR 220: the record of an upgrade `install.sh` rolled back, signed by
//! the agent it restored (static review of `baf4c25` P0 C-45 / G-07).
//!
//! `install.sh --upgrade` is a transaction: when the new version fails —
//! a step of the switch, its start, or its health check — the script stops
//! what it started, restores the previous binaries, units and configuration
//! byte for byte, and starts the previous units again. Before that start it
//! writes [`DEFAULT_MARKER_PATH`] (its `rollback_marker` block): what failed,
//! at which stage, the two versions, the transaction. The restored agent
//! turns it into one signed `upgrade_rolled_back` row of the audit chain at
//! its boot, before it reports ready, and removes it; `install.sh` then looks
//! for that row and names it in its report.
//!
//! The marker is a claim of root's installer, not something the agent saw,
//! and the row says so (`reported_by: install.sh`); the agent adds its own
//! version. The file is read without following a link, only when it is a
//! regular file of the agent's own user that neither its group nor others can
//! write, of at most [`MAX_MARKER_BYTES`]; each known field must be a string,
//! is cut at [`MAX_FIELD_CHARS`] characters, and its control characters are
//! written `?`. A marker that fails any of that is still recorded — as
//! `failure: marker refused (<why>)`, with none of its fields — and removed
//! all the same, so a bad file cannot repeat at every boot. When the row
//! cannot be written (no audit log this boot) the marker stays for the next
//! boot.

use std::fs::{self, OpenOptions};
use std::io::Read;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;
use std::sync::Arc;

use parking_lot::Mutex;
use serde_json::{Map, Value};
use tracing::{info, warn};

use crate::audit::{AuditEntryDraft, AuditLog};

/// Where `install.sh` leaves the marker (its `ROLLBACK_MARKER` default, in
/// the units' `RuntimeDirectory=`: tmpfs, root's alone, gone at a reboot).
pub const DEFAULT_MARKER_PATH: &str = "/run/northnarrow/upgrade-rolled-back.json";
/// The audit `op` of the row.
pub const AUDIT_OP: &str = "upgrade_rolled_back";
/// A larger file is refused unread.
pub const MAX_MARKER_BYTES: u64 = 4096;
/// Each field is cut at this many characters.
pub const MAX_FIELD_CHARS: usize = 200;
/// The fields `install.sh` writes and the row carries; any other is dropped.
pub const FIELDS: [&str; 6] = [
    "stage",
    "reason",
    "failed_version",
    "restored_version",
    "txn",
    "at",
];

/// What the boot found at the marker path.
#[derive(Debug, Clone, PartialEq)]
pub enum Marker {
    /// No marker: no rollback to record.
    Absent,
    /// The known fields, cleaned.
    Read(Map<String, Value>),
    /// A file that is not a marker `install.sh` wrote, and why.
    Refused(String),
}

/// Read the marker at `path`; `owner_uid` is the only owner accepted (the
/// agent's own user: root).
pub fn read_marker(path: &Path, owner_uid: u32) -> Marker {
    let file = match OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(path)
    {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Marker::Absent,
        Err(e) if e.raw_os_error() == Some(libc::ELOOP) => {
            return Marker::Refused("a symbolic link".to_string())
        }
        Err(e) => return Marker::Refused(format!("unreadable: {e}")),
    };
    let meta = match file.metadata() {
        Ok(m) => m,
        Err(e) => return Marker::Refused(format!("unreadable: {e}")),
    };
    if !meta.file_type().is_file() {
        return Marker::Refused("not a regular file".to_string());
    }
    if meta.uid() != owner_uid {
        return Marker::Refused(format!("owned by uid {}", meta.uid()));
    }
    if meta.mode() & 0o022 != 0 {
        return Marker::Refused(format!(
            "writable by its group or others (mode {:o})",
            meta.mode() & 0o7777
        ));
    }
    if meta.len() > MAX_MARKER_BYTES {
        return Marker::Refused(format!("larger than {MAX_MARKER_BYTES} bytes"));
    }
    let mut bytes = Vec::new();
    if let Err(e) = file.take(MAX_MARKER_BYTES + 1).read_to_end(&mut bytes) {
        return Marker::Refused(format!("unreadable: {e}"));
    }
    if bytes.len() as u64 > MAX_MARKER_BYTES {
        return Marker::Refused(format!("larger than {MAX_MARKER_BYTES} bytes"));
    }
    let text = String::from_utf8_lossy(&bytes);
    let value: Value = match serde_json::from_str(&text) {
        Ok(v) => v,
        Err(_) => return Marker::Refused("not JSON".to_string()),
    };
    let Some(obj) = value.as_object() else {
        return Marker::Refused("not a JSON object".to_string());
    };
    let mut out = Map::new();
    for field in FIELDS {
        match obj.get(field) {
            None => {}
            Some(Value::String(s)) => {
                out.insert(field.to_string(), Value::String(clean(s)));
            }
            Some(_) => return Marker::Refused(format!("`{field}` is not a string")),
        }
    }
    Marker::Read(out)
}

/// At most [`MAX_FIELD_CHARS`] characters, each control character (and
/// the two Unicode line separators) as `?`.
fn clean(s: &str) -> String {
    s.chars()
        .take(MAX_FIELD_CHARS)
        .map(|c| {
            if c.is_control() || c == '\u{2028}' || c == '\u{2029}' {
                '?'
            } else {
                c
            }
        })
        .collect()
}

/// The audit row for `marker`; `None` when there is none.
pub fn audit_draft(marker: &Marker) -> Option<AuditEntryDraft> {
    let (extra, result) = match marker {
        Marker::Absent => return None,
        Marker::Read(fields) => {
            let mut extra = fields.clone();
            extra.insert("reported_by".into(), "install.sh".into());
            extra.insert("agent_version".into(), env!("CARGO_PKG_VERSION").into());
            (Value::Object(extra), "success".to_string())
        }
        Marker::Refused(why) => (
            serde_json::json!({
                "reported_by": "install.sh",
                "agent_version": env!("CARGO_PKG_VERSION"),
            }),
            format!("failure: marker refused ({why})"),
        ),
    };
    Some(AuditEntryDraft {
        op: AUDIT_OP.to_string(),
        extra,
        key_fp: "agent-self".to_string(),
        cosigner_fps: Vec::new(),
        result,
        client_pid: std::process::id(),
        client_uid: 0,
        client_comm: "northnarrow-agent".to_string(),
        client_exe: None,
    })
}

/// Record the marker at `path` in the signed chain, then remove it.
pub fn attest(audit_log: Option<&Arc<Mutex<AuditLog>>>, path: &Path) {
    // SAFETY: geteuid has no preconditions and cannot fail.
    let uid = unsafe { libc::geteuid() };
    attest_as(audit_log, path, uid);
}

fn attest_as(audit_log: Option<&Arc<Mutex<AuditLog>>>, path: &Path, owner_uid: u32) {
    let marker = read_marker(path, owner_uid);
    let Some(draft) = audit_draft(&marker) else {
        return;
    };
    match &marker {
        Marker::Read(f) => {
            let field = |k: &str| f.get(k).and_then(Value::as_str).unwrap_or("unknown");
            warn!(
                stage = field("stage"),
                reason = field("reason"),
                failed_version = field("failed_version"),
                restored_version = field("restored_version"),
                "upgrade rolled back by install.sh: this agent is the restored version"
            );
        }
        Marker::Refused(why) => warn!(
            path = %path.display(),
            why = why.as_str(),
            "upgrade rollback marker refused"
        ),
        Marker::Absent => {}
    }
    let Some(log) = audit_log else {
        warn!(
            path = %path.display(),
            "no audit log this boot: the upgrade rollback marker stays for the next boot"
        );
        return;
    };
    if let Err(e) = log.lock().append(draft) {
        warn!(
            error = %format!("{e:#}"),
            "upgrade_rolled_back not recorded: the marker stays for the next boot"
        );
        return;
    }
    info!("upgrade_rolled_back recorded in the signed audit chain");
    match fs::remove_file(path) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => warn!(
            path = %path.display(),
            error = %e,
            "upgrade rollback marker recorded but not removed"
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::AgentSigningKey;
    use std::os::unix::fs::PermissionsExt;
    use std::process::Command;

    fn me() -> u32 {
        // SAFETY: as in `attest`.
        unsafe { libc::geteuid() }
    }

    fn write(path: &Path, body: &str, mode: u32) {
        fs::write(path, body).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
    }

    const GOOD: &str = r#"{"format":1,"stage":"health_check","reason":"the agent (pid 7) logged no 'anti-tamper: all LSM hooks attached'","failed_version":"northnarrow-agent 0.0.2","restored_version":"northnarrow-agent 0.0.1","txn":"20261020T100000Z-42","at":"2026-10-20T10:00:05Z","extra":"dropped"}"#;

    #[test]
    fn a_marker_install_sh_wrote_is_read_field_by_field() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("m.json");
        assert_eq!(read_marker(&p, me()), Marker::Absent);
        write(&p, GOOD, 0o600);
        let Marker::Read(f) = read_marker(&p, me()) else {
            panic!("{:?}", read_marker(&p, me()));
        };
        assert_eq!(f.len(), FIELDS.len());
        assert_eq!(f["stage"], "health_check");
        assert_eq!(f["restored_version"], "northnarrow-agent 0.0.1");
        assert!(f.get("extra").is_none() && f.get("format").is_none());
        // an absent field is just absent
        write(&p, r#"{"stage":"start"}"#, 0o600);
        let Marker::Read(f) = read_marker(&p, me()) else {
            panic!()
        };
        assert_eq!(f.len(), 1);
    }

    #[test]
    fn values_are_cut_and_their_controls_written_as_question_marks() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("m.json");
        let long = "é".repeat(500);
        write(
            &p,
            &format!(r#"{{"reason":"a\nb\u001b[31mc d","txn":"{long}"}}"#),
            0o644,
        );
        let Marker::Read(f) = read_marker(&p, me()) else {
            panic!()
        };
        assert_eq!(f["reason"], "a?b?[31mc?d");
        assert_eq!(f["txn"].as_str().unwrap().chars().count(), MAX_FIELD_CHARS);
    }

    #[test]
    fn anything_but_a_private_regular_json_file_is_refused() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("m.json");
        let refused = |why: &str| match read_marker(&p, me()) {
            Marker::Refused(w) => assert!(w.contains(why), "{w} / {why}"),
            other => panic!("{why}: {other:?}"),
        };
        write(&p, GOOD, 0o620);
        refused("writable by its group or others");
        write(&p, GOOD, 0o602);
        refused("writable by its group or others");
        write(&p, "not json", 0o600);
        refused("not JSON");
        write(&p, "[1]", 0o600);
        refused("not a JSON object");
        write(&p, r#"{"stage":3}"#, 0o600);
        refused("`stage` is not a string");
        write(&p, &" ".repeat(MAX_MARKER_BYTES as usize + 1), 0o600);
        refused("larger than");
        write(&p, GOOD, 0o600);
        match read_marker(&p, me() + 1) {
            Marker::Refused(w) => assert!(w.starts_with("owned by uid"), "{w}"),
            other => panic!("{other:?}"),
        }
        fs::remove_file(&p).unwrap();
        let target = d.path().join("target.json");
        write(&target, GOOD, 0o600);
        std::os::unix::fs::symlink(&target, &p).unwrap();
        refused("a symbolic link");
        fs::remove_file(&p).unwrap();
        fs::create_dir(&p).unwrap();
        refused("not a regular file");
    }

    fn log_in(d: &Path) -> Arc<Mutex<AuditLog>> {
        let key = AgentSigningKey::load_or_bootstrap(&d.join("agent.sig.key")).unwrap();
        Arc::new(Mutex::new(
            AuditLog::open(&d.join("audit.log"), key, [0u8; 16]).unwrap(),
        ))
    }

    fn rows(d: &Path) -> Vec<Value> {
        fs::read_to_string(d.join("audit.log"))
            .unwrap_or_default()
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect()
    }

    /// The marker becomes one signed row — the fields, who reported them,
    /// this agent's version — and is removed; a refused one is recorded as a
    /// failure without its fields and removed too; without an audit log it
    /// stays for the next boot.
    #[test]
    fn the_restored_agent_signs_the_marker_once() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("upgrade-rolled-back.json");
        let log = log_in(d.path());
        attest_as(Some(&log), &p, me());
        assert!(rows(d.path()).is_empty(), "no marker, no row");

        write(&p, GOOD, 0o600);
        attest_as(None, &p, me());
        assert!(p.exists(), "no audit log: the marker stays");

        attest_as(Some(&log), &p, me());
        assert!(!p.exists(), "recorded: the marker is removed");
        let r = rows(d.path());
        assert_eq!(r.len(), 1);
        assert_eq!(r[0]["op"], AUDIT_OP);
        assert_eq!(r[0]["result"], "success");
        assert_eq!(r[0]["key_fp"], "agent-self");
        assert_eq!(r[0]["extra"]["reported_by"], "install.sh");
        assert_eq!(r[0]["extra"]["stage"], "health_check");
        assert_eq!(r[0]["extra"]["failed_version"], "northnarrow-agent 0.0.2");
        assert_eq!(r[0]["extra"]["agent_version"], env!("CARGO_PKG_VERSION"));
        assert!(!r[0]["agent_sig"].as_str().unwrap().is_empty());

        write(&p, "garbage", 0o666);
        attest_as(Some(&log), &p, me());
        assert!(!p.exists());
        let r = rows(d.path());
        assert_eq!(r.len(), 2);
        assert!(
            r[1]["result"]
                .as_str()
                .unwrap()
                .starts_with("failure: marker refused (writable"),
            "{}",
            r[1]["result"]
        );
        assert!(r[1]["extra"].get("stage").is_none());
    }

    /// install.sh's `rollback_marker` block writes what this module reads:
    /// quotes, backslashes and control characters in a value included.
    #[test]
    fn install_sh_writes_a_marker_this_agent_reads() {
        let script =
            fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("../deploy/install.sh"))
                .unwrap();
        let start = script.find("# >>> rollback_marker").expect("block");
        let end = script.find("# <<< rollback_marker").expect("block end");
        let block = &script[start..end];
        assert!(
            script.contains(&format!(
                "ROLLBACK_MARKER=${{ROLLBACK_MARKER:-$RUN_DIR/{}}}",
                Path::new(DEFAULT_MARKER_PATH)
                    .file_name()
                    .unwrap()
                    .to_str()
                    .unwrap()
            )) && script.contains("RUN_DIR=${RUN_DIR:-/run/northnarrow}"),
            "install.sh's default marker path is DEFAULT_MARKER_PATH"
        );
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("run/upgrade-rolled-back.json");
        let reason = "the agent said \"no\" \\ then\nquit\ttab";
        let out = Command::new("bash")
            .arg("-c")
            .arg(format!(
                "set -euo pipefail\n{block}\nwrite_rollback_marker \"$@\"\n"
            ))
            .arg("bash")
            .args([
                "health_check",
                reason,
                "northnarrow-agent 0.0.2",
                "northnarrow-agent 0.0.1",
                "20261020T100000Z-42",
            ])
            .env("ROLLBACK_MARKER", &p)
            .output()
            .unwrap();
        assert!(out.status.success(), "{out:?}");
        let mode = fs::metadata(&p).unwrap().permissions().mode();
        assert_eq!(mode & 0o077, 0, "{mode:o}");
        let Marker::Read(f) = read_marker(&p, me()) else {
            panic!(
                "{:?}: {}",
                read_marker(&p, me()),
                fs::read_to_string(&p).unwrap()
            );
        };
        assert_eq!(f["stage"], "health_check");
        assert_eq!(f["reason"], "the agent said \"no\" \\ thenquittab");
        assert_eq!(f["failed_version"], "northnarrow-agent 0.0.2");
        assert_eq!(f["txn"], "20261020T100000Z-42");
        assert!(f["at"].as_str().unwrap().ends_with('Z'));
        assert!(!d.path().join("run/upgrade-rolled-back.json.tmp").exists());
    }
}
