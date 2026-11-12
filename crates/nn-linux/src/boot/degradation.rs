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
//!
//! Lot 319: the torn tails the flat chains' writers cut at run time, after
//! a failed write ([`crate::flat_chain`]), are signed the same way, as
//! `chain_tail_repaired` rows ([`attest_repair`]): at once when the audit
//! log is free, else at the next flush.

use std::sync::Arc;
use std::time::Duration;

use parking_lot::Mutex;
use tracing::warn;

use crate::audit::{AuditEntryDraft, AuditLog};
use crate::chainlog::TailRepair;
use std::path::{Path, PathBuf};

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
    /// Lot 311 (the review of #538, F5): entries withdrawn before they were
    /// signed (no audit log yet, or its append failed) — signed at the next
    /// flush, never lost.
    withdrawn_unsigned: Vec<Degradation>,
    /// Reported past [`MAX_KEPT`].
    overflow: u64,
    sink: Option<Arc<Mutex<AuditLog>>>,
    boot_over: bool,
    /// Lot 319: run-time repairs of the flat chains not signed yet (the
    /// file as the command line names it, the repair).
    repairs: Vec<(PathBuf, TailRepair)>,
    /// Repairs past [`MAX_KEPT`] waiting: not signed (an ERROR each).
    repairs_dropped: u64,
}

static REGISTRY: Mutex<Registry> = Mutex::new(Registry {
    entries: Vec::new(),
    withdrawn_unsigned: Vec::new(),
    overflow: 0,
    sink: None,
    boot_over: false,
    repairs: Vec::new(),
    repairs_dropped: 0,
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

/// Lot 319 (the review of #544, F5): the source of the signed count of the
/// flat chains' repairs dropped past [`MAX_KEPT`].
pub const REPAIRS_DROPPED: &str = "chain_repairs";

/// Lot 319: a torn tail a flat chain's writer cut or closed at run time
/// (after a failed write, [`crate::flat_chain::FlatFile::heal`]), to be
/// signed in the audit chain as the open's repairs are (`chain_tail_repaired`,
/// the cut bytes' length and SHA-256): at once when the audit log is there
/// and free (never waited for: the writer may hold a lock its holder
/// waits on), else at the next flush. At most [`MAX_KEPT`] wait; past it a
/// repair is not signed, and its ERROR says so.
pub fn attest_repair(file: &Path, repair: TailRepair) {
    {
        let mut r = REGISTRY.lock();
        if r.repairs.len() >= MAX_KEPT {
            r.repairs_dropped += 1;
            tracing::error!(
                file = %file.display(),
                detail = %repair.describe(),
                dropped = r.repairs_dropped,
                "a flat chain's repair is not signed: too many wait for the audit log"
            );
            return;
        }
        r.repairs.push((file.to_path_buf(), repair));
    }
    sign_repairs(false);
}

/// Sign the repairs waiting, with the audit log's lock when `wait`, else
/// only if it is free. Returns how many were written.
fn sign_repairs(wait: bool) -> usize {
    let Some(sink) = REGISTRY.lock().sink.clone() else {
        return 0;
    };
    let mut log = if wait {
        sink.lock()
    } else {
        match sink.try_lock() {
            Some(l) => l,
            None => return 0,
        }
    };
    let (pending, dropped) = {
        let mut r = REGISTRY.lock();
        (
            std::mem::take(&mut r.repairs),
            std::mem::take(&mut r.repairs_dropped),
        )
    };
    let mut written = 0;
    let mut failed = Vec::new();
    for (file, repair) in pending {
        match log.attest_tail_repair(&file, &repair) {
            Ok(()) => written += 1,
            Err(e) => {
                warn!(error = %format!("{e:#}"), file = %file.display(), "attesting a chain repair failed");
                failed.push((file, repair));
            }
        }
    }
    // The review of #544 (F5): the repairs dropped past the bound are said in
    // the next signed row — their count, as a degradation of this run.
    let dropped_said = dropped == 0
        || sign_into(
            &mut log,
            REPAIRS_DROPPED,
            &format!(
                "{dropped} run-time repair(s) of the flat chains not signed: more than {MAX_KEPT} \
                 waited for the audit log"
            ),
            false,
        );
    drop(log);
    if dropped > 0 {
        if dropped_said {
            written += 1;
        } else {
            REGISTRY.lock().repairs_dropped += dropped;
        }
    }
    if !failed.is_empty() {
        // Tried again at the next flush, before the ones that came since.
        let mut r = REGISTRY.lock();
        failed.append(&mut r.repairs);
        r.repairs = failed;
    }
    written
}

/// Sign every report not signed yet; returns how many were written.
pub fn flush() -> usize {
    sign_repairs(true) + flush_reports()
}

fn flush_reports() -> usize {
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
        let withdrawn = std::mem::take(&mut r.withdrawn_unsigned);
        (sink, (pending, withdrawn))
    };
    let (pending, withdrawn) = pending;
    let mut written = 0;
    for d in withdrawn {
        if sign(&sink, &d.source, &d.detail, d.at_boot) {
            written += 1;
        } else {
            REGISTRY.lock().withdrawn_unsigned.push(d);
        }
    }
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

/// Lot 273d (the review of #492): the degradations of `source` whose
/// condition ended — every one but `keep` — leave the status, the manifest
/// and the trust level; their signed records stay in the chain, and the
/// condition's own end is signed by its finder (a drift cleared, a reload
/// confirmed). A degradation that holds stays visible as long as it holds.
/// Returns how many left.
/// Lot 311 (the review of #538, F5): one withdrawn before the flush
/// signed it is signed now (with the audit log at hand; else at its
/// open): a condition that ends within the flush period still leaves its
/// record in the chain.
pub fn withdraw(source: &str, keep: &[String]) -> usize {
    let (sink, unsigned, left) = {
        let mut r = REGISTRY.lock();
        let before = r.entries.len();
        let mut unsigned = Vec::new();
        r.entries.retain(|d| {
            let stays = d.source != source || keep.contains(&d.detail);
            if !stays && !d.signed {
                unsigned.push(d.clone());
            }
            stays
        });
        let left = before - r.entries.len();
        if r.sink.is_none() {
            r.withdrawn_unsigned.append(&mut unsigned);
        }
        (r.sink.clone(), unsigned, left)
    };
    if let Some(sink) = sink {
        for d in unsigned {
            if !sign(&sink, &d.source, &d.detail, d.at_boot) {
                REGISTRY.lock().withdrawn_unsigned.push(d);
            }
        }
    }
    left
}

/// Lot 319: [`withdraw`] by a predicate on the detail — the degradations of
/// `source` whose condition `ended` says ended leave the status (one source
/// shared by several parts: the chain logs' stalled retention, one line
/// each). Returns how many left.
pub fn withdraw_where(source: &str, ended: impl Fn(&str) -> bool) -> usize {
    let mut r = REGISTRY.lock();
    let before = r.entries.len();
    r.entries
        .retain(|d| d.source != source || !ended(&d.detail));
    before - r.entries.len()
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
    r.withdrawn_unsigned.clear();
    r.overflow = 0;
    r.sink = None;
    r.boot_over = false;
    r.repairs.clear();
    r.repairs_dropped = 0;
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

    /// Lot 311 (the review of #538, F5): a degradation withdrawn before the
    /// flush signed it is signed all the same — at once with the audit log
    /// at hand, at its open otherwise — and only once.
    #[test]
    fn a_degradation_withdrawn_before_its_flush_is_still_signed() {
        let _g = TEST_LOCK.lock();
        reset_for_tests();
        let dir = tempfile::tempdir().unwrap();
        assert!(report("execq_roots", "the mount table could not be read"));
        assert_eq!(withdraw("execq_roots", &[]), 1);
        assert!(snapshot().is_empty(), "withdrawn from the status");
        let log = open_log(dir.path());
        assert_eq!(attach_audit_log(Some(Arc::clone(&log))), 1);
        let rows = degraded_rows(dir.path());
        assert_eq!(rows.len(), 1, "signed at the log's open");
        assert_eq!(rows[0]["source"], "execq_roots");
        mark_boot_over();
        assert!(report("mount_table", "one line not in the kernel's shape"));
        assert_eq!(withdraw("mount_table", &[]), 1);
        assert_eq!(
            degraded_rows(dir.path()).len(),
            2,
            "signed at its withdrawal"
        );
        assert_eq!(flush(), 0, "once");
        assert_eq!(degraded_rows(dir.path()).len(), 2);
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

    fn repair(n: u64) -> TailRepair {
        TailRepair::Truncated {
            kept_len: 100,
            dropped_len: n,
            dropped_sha256: "ab".repeat(32),
        }
    }

    /// The `chain_tail_repaired` rows of the audit log in `dir` for files
    /// under `under` (the registry is the process's: a test of another
    /// module may report meanwhile).
    fn repaired_rows(dir: &std::path::Path, under: &str) -> Vec<serde_json::Value> {
        std::fs::read_to_string(dir.join("audit.log"))
            .unwrap_or_default()
            .lines()
            .map(|l| serde_json::from_str::<serde_json::Value>(l).unwrap())
            .filter(|v| v["op"] == crate::audit::CHAIN_TAIL_REPAIRED_OP)
            .map(|v| v["extra"].clone())
            .filter(|e| e["file"].as_str().is_some_and(|f| f.starts_with(under)))
            .collect()
    }

    /// Lot 319: a flat chain's run-time repair is signed at once when the
    /// audit log is free; while another thread holds it, the repair waits
    /// — never the writer — and the next flush signs it.
    #[test]
    fn a_flat_chain_repair_is_signed_at_once_or_at_the_flush() {
        let _g = TEST_LOCK.lock();
        reset_for_tests();
        let dir = tempfile::tempdir().unwrap();
        let log = open_log(dir.path());
        attach_audit_log(Some(Arc::clone(&log)));
        attest_repair(Path::new("/k319/canaries.jsonl"), repair(40));
        let rows = repaired_rows(dir.path(), "/k319/");
        assert_eq!(rows.len(), 1, "signed at once");
        assert_eq!(rows[0]["file"], "/k319/canaries.jsonl");
        assert!(rows[0]["detail"].as_str().unwrap().contains("(40 bytes"));
        // the audit log held by another: the writer does not wait
        let held = log.lock();
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            attest_repair(Path::new("/k319/baseline.jsonl"), repair(7));
            let _ = tx.send(());
        });
        rx.recv_timeout(std::time::Duration::from_secs(10))
            .expect("the writer waited for the audit log");
        drop(held);
        assert_eq!(repaired_rows(dir.path(), "/k319/").len(), 1, "waiting");
        flush();
        let rows = repaired_rows(dir.path(), "/k319/");
        assert_eq!(rows.len(), 2, "signed at the flush");
        assert_eq!(rows[1]["file"], "/k319/baseline.jsonl");
        flush();
        assert_eq!(repaired_rows(dir.path(), "/k319/").len(), 2, "once");
        reset_for_tests();
    }

    /// Lot 319: without an audit log the repairs wait, at most
    /// [`MAX_KEPT`]; the one past it is not signed (an ERROR), the others
    /// are once the log is there.
    #[test]
    fn flat_chain_repairs_wait_within_a_bound() {
        let _g = TEST_LOCK.lock();
        reset_for_tests();
        for n in 0..MAX_KEPT as u64 + 1 {
            attest_repair(Path::new("/k319/canary_access.jsonl"), repair(n + 1));
        }
        let dir = tempfile::tempdir().unwrap();
        attach_audit_log(Some(open_log(dir.path())));
        assert_eq!(repaired_rows(dir.path(), "/k319/").len(), MAX_KEPT);
        // the one dropped is said in the next signed row (the review of
        // #544, F5)
        let said: Vec<serde_json::Value> = degraded_rows(dir.path())
            .into_iter()
            .filter(|r| r["source"] == REPAIRS_DROPPED)
            .collect();
        assert_eq!(said.len(), 1, "{said:?}");
        assert!(said[0]["detail"]
            .as_str()
            .unwrap()
            .starts_with("1 run-time repair(s)"));
        reset_for_tests();
    }

    /// Lot 273d: a degradation whose condition ended leaves the status; the
    /// others of its source, and the other sources, stay.
    #[test]
    fn a_degradation_that_ended_is_withdrawn() {
        let _g = TEST_LOCK.lock();
        reset_for_tests();
        report("host_dropins", "a");
        report("host_dropins", "b");
        report("systemd_reload", "c");
        assert_eq!(withdraw("host_dropins", &["b".to_string()]), 1);
        assert_eq!(snapshot(), vec!["host_dropins: b", "systemd_reload: c"]);
        assert_eq!(withdraw("systemd_reload", &[]), 1);
        assert_eq!(count(), 1);
        reset_for_tests();
    }
}
