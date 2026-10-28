//! What the agent runs without (lab PR 218; external review P0 C-13, G-11,
//! TD-10).
//!
//! A sensor on its fallback attach point, a hook that did not attach, a
//! stream that is not persisted: each one used to be a WARN in the journal,
//! some of them a signed `subsystem_degraded`, none of them visible in
//! `nn-admin status`. Every one now goes through [`report`] (a part of the
//! agent without the audit log at hand) or [`report_signed`] (one that
//! holds it):
//!
//! - it is kept for `nn-admin status --key` ([`snapshot`]) and counts
//!   against the trust level (the agent's `boot::trust`);
//! - it is signed in the audit chain as a `subsystem_degraded` (the
//!   `integrity_drift` op, `source` naming the part): at once when the
//!   caller holds the log, at the log's open for what came before it
//!   ([`attach_audit_log`]), within [`FLUSH_PERIOD`] otherwise
//!   ([`spawn_flusher`]). [`SIGNED_WITHIN`] bounds the wait.

use std::sync::Arc;
use std::time::Duration;

use parking_lot::Mutex;
use tracing::warn;

use crate::audit::{AuditEntryDraft, AuditLog};

/// How often the reports made without the audit log are signed.
pub const FLUSH_PERIOD: Duration = Duration::from_secs(15);

/// The longest a report waits for its signed record once the audit log is
/// open (two flush periods, with room).
pub const SIGNED_WITHIN: Duration = Duration::from_secs(60);

const _: () = assert!(FLUSH_PERIOD.as_secs() * 2 < SIGNED_WITHIN.as_secs());

/// Degradations kept for the status; past it they are counted only (and
/// still signed).
pub const MAX_KEPT: usize = 64;

/// One degradation of this run.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Degradation {
    /// The part of the agent (`exec_sensor`, `net_drain`, …); empty for the
    /// records of the boot sequence that predate the field.
    pub source: String,
    pub detail: String,
    /// Found during the start (before the event loop).
    pub at_boot: bool,
    /// Its signed record is written.
    pub signed: bool,
}

impl Degradation {
    /// The line `nn-admin status` prints.
    pub fn line(&self) -> String {
        if self.source.is_empty() {
            self.detail.clone()
        } else {
            format!("{}: {}", self.source, self.detail)
        }
    }
}

struct Registry {
    entries: Vec<Degradation>,
    /// Reported past [`MAX_KEPT`].
    overflow: u64,
    sink: Option<Arc<Mutex<AuditLog>>>,
    boot_over: bool,
}

static REGISTRY: Mutex<Registry> = Mutex::new(Registry {
    entries: Vec::new(),
    overflow: 0,
    sink: None,
    boot_over: false,
});

/// A degradation found by a part of the agent without the audit log at
/// hand: kept, and signed at the log's open or the next flush. The same
/// `(source, detail)` reported again is one entry. Returns whether it is new.
pub fn report(source: &str, detail: &str) -> bool {
    let overflow = {
        let mut r = REGISTRY.lock();
        if r.entries
            .iter()
            .any(|d| d.source == source && d.detail == detail)
        {
            return false;
        }
        let at_boot = !r.boot_over;
        push(
            &mut r,
            Degradation {
                source: source.to_string(),
                detail: detail.to_string(),
                at_boot,
                signed: false,
            },
        )
    };
    sign_overflow(overflow);
    true
}

/// A degradation whose finder holds the audit log: signed now (every time,
/// as the callers did before the registry), and kept.
pub fn report_signed(
    audit_log: Option<&Arc<Mutex<AuditLog>>>,
    source: &str,
    detail: &str,
    at_boot: bool,
) {
    let signed = match audit_log {
        Some(log) => sign(log, source, detail, at_boot),
        None => false,
    };
    let mut r = REGISTRY.lock();
    if let Some(d) = r
        .entries
        .iter_mut()
        .find(|d| d.source == source && d.detail == detail)
    {
        d.signed |= signed;
        return;
    }
    // Past the cap a signed one is only counted; an unsigned one is signed
    // below, outside the lock.
    let overflow = push(
        &mut r,
        Degradation {
            source: source.to_string(),
            detail: detail.to_string(),
            at_boot,
            signed,
        },
    );
    drop(r);
    if !signed {
        sign_overflow(overflow);
    }
}

/// Keep `d`, or count it past [`MAX_KEPT`]: then it is returned with the
/// sink, to be signed once the registry's lock is released (it is not kept,
/// so no flush would sign it).
fn push(r: &mut Registry, d: Degradation) -> Option<(Arc<Mutex<AuditLog>>, Degradation)> {
    if r.entries.len() < MAX_KEPT {
        r.entries.push(d);
        None
    } else {
        r.overflow += 1;
        r.sink.clone().map(|log| (log, d))
    }
}

fn sign_overflow(overflow: Option<(Arc<Mutex<AuditLog>>, Degradation)>) {
    if let Some((log, d)) = overflow {
        sign(&log, &d.source, &d.detail, d.at_boot);
    }
}

fn sign(log: &Arc<Mutex<AuditLog>>, source: &str, detail: &str, at_boot: bool) -> bool {
    sign_into(&mut log.lock(), source, detail, at_boot)
}

/// The signed `subsystem_degraded` (the shape `main.rs` always wrote, with
/// `source` when there is one), into a log the caller holds — a refused
/// boot's, which exits before the registry has a sink.
pub fn sign_into(log: &mut AuditLog, source: &str, detail: &str, at_boot: bool) -> bool {
    let mut extra = serde_json::json!({
        "kind": "subsystem_degraded",
        "detail": detail,
        "at_boot": at_boot,
    });
    if !source.is_empty() {
        extra["source"] = serde_json::Value::String(source.to_string());
    }
    let draft = AuditEntryDraft {
        op: crate::self_integrity::AUDIT_OP.to_string(),
        extra,
        key_fp: "agent-self".to_string(),
        cosigner_fps: Vec::new(),
        result: "detected".to_string(),
        client_pid: std::process::id(),
        client_uid: 0,
        client_comm: "northnarrow-agent".to_string(),
        client_exe: None,
    };
    match log.append(draft) {
        Ok(_) => true,
        Err(e) => {
            warn!(error = %format!("{e:#}"), source, "attesting a degraded subsystem failed");
            false
        }
    }
}

/// The audit log is open (or `None`: it could not be, under
/// `NN_AUDIT_ALLOW_UNWRITABLE=1`): what was reported before is signed now.
/// Returns how many records were written.
pub fn attach_audit_log(log: Option<Arc<Mutex<AuditLog>>>) -> usize {
    REGISTRY.lock().sink = log;
    flush()
}

/// Sign every report not signed yet; returns how many were written.
pub fn flush() -> usize {
    let (sink, pending) = {
        let mut r = REGISTRY.lock();
        let Some(sink) = r.sink.clone() else {
            return 0;
        };
        let mut pending = Vec::new();
        for d in r.entries.iter_mut().filter(|d| !d.signed) {
            d.signed = true;
            pending.push(d.clone());
        }
        (sink, pending)
    };
    let mut written = 0;
    for d in pending {
        if sign(&sink, &d.source, &d.detail, d.at_boot) {
            written += 1;
        } else if let Some(e) = REGISTRY
            .lock()
            .entries
            .iter_mut()
            .find(|e| e.source == d.source && e.detail == d.detail)
        {
            // Tried again at the next flush.
            e.signed = false;
        }
    }
    written
}

/// Sign the later reports every [`FLUSH_PERIOD`].
pub fn spawn_flusher() {
    tokio::spawn(async {
        let mut tick = tokio::time::interval(FLUSH_PERIOD);
        tick.tick().await;
        loop {
            tick.tick().await;
            flush();
        }
    });
}

/// The event loop starts: later reports are not boot ones.
pub fn mark_boot_over() {
    REGISTRY.lock().boot_over = true;
}

/// Every degradation of this run, as `nn-admin status` prints them; one
/// more line when some were only counted.
pub fn snapshot() -> Vec<String> {
    let r = REGISTRY.lock();
    let mut out: Vec<String> = r.entries.iter().map(Degradation::line).collect();
    if r.overflow > 0 {
        out.push(format!(
            "… and {} more (in the signed audit log only)",
            r.overflow
        ));
    }
    out
}

/// The degradations of this run, counted.
pub fn count() -> usize {
    let r = REGISTRY.lock();
    r.entries.len() + r.overflow as usize
}

/// The kept entries (the capability manifest lists them).
pub fn entries() -> Vec<Degradation> {
    REGISTRY.lock().entries.clone()
}

/// Tests only: an empty registry (the tests that use it hold [`TEST_LOCK`]).
#[cfg(test)]
pub(crate) fn reset_for_tests() {
    let mut r = REGISTRY.lock();
    r.entries.clear();
    r.overflow = 0;
    r.sink = None;
    r.boot_over = false;
}

/// The registry is one per process: the tests that read it run one at a
/// time.
#[cfg(test)]
pub(crate) static TEST_LOCK: Mutex<()> = Mutex::new(());

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::AgentSigningKey;

    fn open_log(dir: &std::path::Path) -> Arc<Mutex<AuditLog>> {
        let key = AgentSigningKey::load_or_bootstrap(&dir.join("agent.sig")).unwrap();
        Arc::new(Mutex::new(
            AuditLog::open(&dir.join("audit.log"), key, [7u8; 16]).unwrap(),
        ))
    }

    fn degraded_rows(dir: &std::path::Path) -> Vec<serde_json::Value> {
        std::fs::read_to_string(dir.join("audit.log"))
            .unwrap_or_default()
            .lines()
            .map(|l| serde_json::from_str::<serde_json::Value>(l).unwrap())
            .filter(|v| v["extra"]["kind"] == "subsystem_degraded")
            .map(|v| v["extra"].clone())
            .collect()
    }

    /// External review P0 C-13: a fallback found before the audit log
    /// opened is signed at the open, one found after within a flush; both
    /// are in the status, once each.
    #[test]
    fn every_report_is_signed_once_and_listed() {
        let _g = TEST_LOCK.lock();
        reset_for_tests();
        let dir = tempfile::tempdir().unwrap();
        assert!(report("exec_sensor", "on sys_enter_execve"));
        assert!(!report("exec_sensor", "on sys_enter_execve"), "one entry");
        assert_eq!(degraded_rows(dir.path()).len(), 0);

        let log = open_log(dir.path());
        assert_eq!(attach_audit_log(Some(Arc::clone(&log))), 1);
        let rows = degraded_rows(dir.path());
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0]["source"], "exec_sensor");
        assert_eq!(rows[0]["at_boot"], true);

        mark_boot_over();
        assert!(report("dns_sensor", "IPv6 resolvers not observed"));
        assert_eq!(flush(), 1);
        assert_eq!(flush(), 0, "signed once");
        let rows = degraded_rows(dir.path());
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[1]["at_boot"], false);

        report_signed(Some(&log), "net_drain", "netflow log not persisted", true);
        assert_eq!(degraded_rows(dir.path()).len(), 3);
        assert_eq!(flush(), 0, "already signed by its finder");
        assert_eq!(
            snapshot(),
            [
                "exec_sensor: on sys_enter_execve",
                "dns_sensor: IPv6 resolvers not observed",
                "net_drain: netflow log not persisted",
            ]
        );
        assert_eq!(count(), 3);
        reset_for_tests();
    }

    /// The records of the boot sequence keep their shape (no `source`).
    #[test]
    fn a_record_without_a_source_keeps_the_old_shape() {
        let _g = TEST_LOCK.lock();
        reset_for_tests();
        let dir = tempfile::tempdir().unwrap();
        let log = open_log(dir.path());
        report_signed(Some(&log), "", "fim watches no path", true);
        let rows = degraded_rows(dir.path());
        assert_eq!(rows.len(), 1);
        assert!(rows[0].get("source").is_none(), "{:?}", rows[0]);
        assert_eq!(snapshot(), ["fim watches no path"]);
        reset_for_tests();
    }

    #[test]
    fn without_an_audit_log_reports_are_kept_unsigned() {
        let _g = TEST_LOCK.lock();
        reset_for_tests();
        report("io_uring", "not observed");
        assert_eq!(attach_audit_log(None), 0);
        assert_eq!(flush(), 0);
        assert_eq!(entries().len(), 1);
        assert!(!entries()[0].signed);
        reset_for_tests();
    }

    #[test]
    fn past_the_cap_reports_are_counted() {
        let _g = TEST_LOCK.lock();
        reset_for_tests();
        for i in 0..MAX_KEPT + 3 {
            report("test", &format!("d{i}"));
        }
        assert_eq!(count(), MAX_KEPT + 3);
        let s = snapshot();
        assert_eq!(s.len(), MAX_KEPT + 1);
        assert!(s.last().unwrap().contains("3 more"), "{s:?}");
        reset_for_tests();
    }
}
