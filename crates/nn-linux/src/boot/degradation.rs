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
/// still signed). The parts with a budget of their own ([`note_kept`]) are
/// kept outside it.
pub const MAX_KEPT: usize = 64;

/// Lot 366 (the re-check of #573, N2): the source of the signed count of
/// the notes past [`MAX_KEPT`] that could not wait for the flush.
pub const NOTES_DROPPED: &str = "degradation_notes";

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
    /// Lot 366 (the re-check of #573, N2): kept within its source's own
    /// budget ([`note_kept`]), not against [`MAX_KEPT`].
    own_budget: bool,
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
    /// Lot 366 (the re-check of #573, N2): notes not kept — past
    /// [`MAX_KEPT`], or past their source's own budget — waiting for the
    /// next flush, which signs them: a note is never only counted. At most
    /// [`MAX_KEPT`] wait.
    unkept: Vec<Degradation>,
    /// Notes past that bound: their count is signed at the next flush
    /// ([`NOTES_DROPPED`]).
    unkept_dropped: u64,
}

static REGISTRY: Mutex<Registry> = Mutex::new(Registry {
    entries: Vec::new(),
    withdrawn_unsigned: Vec::new(),
    overflow: 0,
    sink: None,
    boot_over: false,
    repairs: Vec::new(),
    repairs_dropped: 0,
    unkept: Vec::new(),
    unkept_dropped: 0,
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
                own_budget: false,
            },
        )
    };
    sign_overflow(overflow);
    true
}

/// Lot 353 (the review of #563, F1): [`report`] for a caller that may hold
/// the audit log's lock (a signed log's writer telling its failure): it
/// never signs here — at the next flush like every report. Lot 366 (the
/// re-check of #573, N2): past [`MAX_KEPT`] it is not kept for the status
/// but waits for that flush all the same (counted, and signed then), never
/// only counted. Returns whether it is new.
pub fn note(source: &str, detail: &str) -> bool {
    let mut r = REGISTRY.lock();
    if noted(&r, source, detail) {
        return false;
    }
    let d = Degradation {
        source: source.to_string(),
        detail: detail.to_string(),
        at_boot: !r.boot_over,
        signed: false,
        own_budget: false,
    };
    if shared_len(&r) >= MAX_KEPT {
        unkept(&mut r, d);
    } else {
        r.entries.push(d);
    }
    true
}

/// Lot 366 (the re-check of #573, N2): [`note`] for a part that keeps its
/// own bounded share of the registry — at most `budget` records of
/// `source` kept at once, outside [`MAX_KEPT`] and never counted against
/// it: no other part's records crowd its records out, and its records
/// crowd out no other part's. Past its budget a record is not kept but is
/// signed at the next flush all the same. The exec pumps' conditions, made
/// on a thread that never waits on the audit log. Returns whether it is
/// new.
pub fn note_kept(source: &str, detail: &str, budget: usize) -> bool {
    if !kept_told() {
        return true;
    }
    let mut r = REGISTRY.lock();
    if noted(&r, source, detail) {
        return false;
    }
    let d = Degradation {
        source: source.to_string(),
        detail: detail.to_string(),
        at_boot: !r.boot_over,
        signed: false,
        own_budget: true,
    };
    let held = r
        .entries
        .iter()
        .filter(|e| e.own_budget && e.source == source)
        .count();
    if held >= budget {
        unkept(&mut r, d);
    } else {
        r.entries.push(d);
    }
    true
}

/// Lot 366 (the re-check of #573, N4): the record `detail` of `source` made
/// with [`note_kept`] leaves the status — that record only, not the
/// source's others — and is signed at the next flush if it was not yet.
/// Returns how many left.
pub fn retire_kept(source: &str, detail: &str) -> usize {
    if !kept_told() {
        return 0;
    }
    retire_where(source, |d| d == detail)
}

/// Lot 366 (the re-check of #573, N2): a record of a condition that held
/// and has ended (a window of the exec pumps' slow reads, with its total),
/// for the signed log only: not kept for the status, signed at the next
/// flush.
pub fn sign_ended(source: &str, detail: &str) {
    if !kept_told() {
        return;
    }
    let mut r = REGISTRY.lock();
    let d = Degradation {
        source: source.to_string(),
        detail: detail.to_string(),
        at_boot: !r.boot_over,
        signed: false,
        own_budget: true,
    };
    if r.unkept.len() < MAX_KEPT {
        r.unkept.push(d);
    } else {
        r.unkept_dropped += 1;
    }
}

/// `(source, detail)` is kept already, or waits for the flush.
fn noted(r: &Registry, source: &str, detail: &str) -> bool {
    r.entries
        .iter()
        .chain(&r.unkept)
        .any(|d| d.source == source && d.detail == detail)
}

/// The entries kept against [`MAX_KEPT`] (not within a budget of their own).
fn shared_len(r: &Registry) -> usize {
    r.entries.iter().filter(|d| !d.own_budget).count()
}

/// A note not kept: counted, and signed at the next flush — at most
/// [`MAX_KEPT`] wait, the count of the others signed then.
fn unkept(r: &mut Registry, d: Degradation) {
    r.overflow += 1;
    if r.unkept.len() < MAX_KEPT {
        r.unkept.push(d);
    } else {
        r.unkept_dropped += 1;
    }
}

/// Lot 366 (the re-check of #573, N1): whether the records of the parts
/// with a budget of their own go into the registry — always in the agent.
/// In the unit tests the exec pumps' records (made by any test that runs a
/// pump step) are told only on a thread whose test asked ([`KeptTold`],
/// with [`TEST_LOCK`] held): the tests that read the registry see their
/// own records alone, whatever runs beside them.
fn kept_told() -> bool {
    #[cfg(test)]
    {
        KEPT_TOLD.with(std::cell::Cell::get)
    }
    #[cfg(not(test))]
    {
        true
    }
}

#[cfg(test)]
thread_local! {
    static KEPT_TOLD: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// Tests (with [`TEST_LOCK`] held): this thread's records of the parts with
/// a budget of their own are told to the registry while this is held.
#[cfg(test)]
pub(crate) struct KeptTold;

#[cfg(test)]
impl KeptTold {
    pub(crate) fn new() -> Self {
        KEPT_TOLD.with(|t| t.set(true));
        KeptTold
    }
}

#[cfg(test)]
impl Drop for KeptTold {
    fn drop(&mut self) {
        KEPT_TOLD.with(|t| t.set(false));
    }
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
            own_budget: false,
        },
    );
    drop(r);
    if !signed {
        sign_overflow(overflow);
    }
}

/// Lot 345 (the re-check of #550, N3b): a degradation its finder already
/// signed in a row of its own kind (`signed`: the start's `integrity_drift`
/// `profile_downgraded`), kept for `nn-admin status` and the trust level;
/// signed here only when that row could not be (`signed` false: at the
/// log's open or the next flush, like [`report`]'s).
pub fn keep(source: &str, detail: &str, signed: bool) {
    if !signed {
        report(source, detail);
        return;
    }
    let mut r = REGISTRY.lock();
    if r.entries
        .iter()
        .any(|d| d.source == source && d.detail == detail)
    {
        return;
    }
    let at_boot = !r.boot_over;
    // past the cap a signed one is only counted (its row exists)
    let _ = push(
        &mut r,
        Degradation {
            source: source.to_string(),
            detail: detail.to_string(),
            at_boot,
            signed: true,
            own_budget: false,
        },
    );
}

/// Keep `d`, or count it past [`MAX_KEPT`]: then it is returned with the
/// sink, to be signed once the registry's lock is released (it is not kept,
/// so no flush would sign it).
fn push(r: &mut Registry, d: Degradation) -> Option<(Arc<Mutex<AuditLog>>, Degradation)> {
    if shared_len(r) < MAX_KEPT {
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
        let mut withdrawn = std::mem::take(&mut r.withdrawn_unsigned);
        // lot 366 (the re-check of #573, N2): the notes not kept, then the
        // count of those that could not wait
        withdrawn.append(&mut r.unkept);
        let dropped = std::mem::take(&mut r.unkept_dropped);
        if dropped > 0 {
            withdrawn.push(Degradation {
                source: NOTES_DROPPED.to_string(),
                detail: format!(
                    "{dropped} degradation note(s) not kept and not signed one by one: more \
                     than {MAX_KEPT} waited for the audit log"
                ),
                at_boot: !r.boot_over,
                signed: false,
                own_budget: false,
            });
        }
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

/// Lot 353 (the review of #563, F1): [`withdraw_where`] for a caller that
/// may hold the audit log's lock: an entry that leaves before its record
/// was signed is kept for the next flush (never signed here, never lost).
/// Returns how many left.
pub fn retire_where(source: &str, ended: impl Fn(&str) -> bool) -> usize {
    let mut r = REGISTRY.lock();
    let before = r.entries.len();
    let mut unsigned = Vec::new();
    r.entries.retain(|d| {
        let stays = d.source != source || !ended(&d.detail);
        if !stays && !d.signed {
            unsigned.push(d.clone());
        }
        stays
    });
    r.withdrawn_unsigned.append(&mut unsigned);
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
    r.unkept.clear();
    r.unkept_dropped = 0;
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

    /// Named (lot 345; the re-check of #550, N3b): an unsigned profile
    /// downgrade the start signed as its own `profile_downgraded` row is
    /// kept for `nn-admin status` (listed, counted against the trust level)
    /// and not signed a second time; one whose row could not be written is
    /// signed at the log's open, as any report.
    #[test]
    fn a_downgrade_signed_by_its_finder_is_listed_not_signed_again() {
        let _g = TEST_LOCK.lock();
        reset_for_tests();
        let dir = tempfile::tempdir().unwrap();
        keep(
            "profile",
            "alpha (install manifest) after a run of the enforcing profile",
            true,
        );
        keep(
            "profile",
            "alpha (install manifest) after a run of the enforcing profile",
            true,
        );
        assert_eq!(
            snapshot(),
            ["profile: alpha (install manifest) after a run of the enforcing profile"]
        );
        assert_eq!(count(), 1);
        assert!(entries().iter().all(|d| d.signed && d.at_boot));
        let log = open_log(dir.path());
        assert_eq!(
            attach_audit_log(Some(Arc::clone(&log))),
            0,
            "its row exists"
        );
        assert_eq!(flush(), 0);
        assert!(degraded_rows(dir.path()).is_empty());
        // its own row could not be written: signed like a report
        keep("profile", "unsigned", false);
        assert_eq!(flush(), 1);
        assert_eq!(degraded_rows(dir.path())[0]["source"], "profile");
        assert_eq!(count(), 2);
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

    /// Lot 353 (the review of #563, F1): the failure of a signed log, told
    /// with the writer's lock held (`note`, `retire_where`): never signed
    /// there, and its record is not lost when the failure ends before a
    /// flush signed it — the next flush signs it, once; past the bound it
    /// is counted, never signed at once.
    #[test]
    fn a_signing_failure_told_under_the_lock_is_signed_at_the_next_flush() {
        let _g = TEST_LOCK.lock();
        reset_for_tests();
        let dir = tempfile::tempdir().unwrap();
        let log = open_log(dir.path());
        assert_eq!(attach_audit_log(Some(Arc::clone(&log))), 0);
        {
            // the writer's lock held: nothing signed here (no deadlock)
            let _held = log.lock();
            assert!(note("signed_log", "audit.jsonl: appends fail: EIO"));
            assert!(
                !note("signed_log", "audit.jsonl: appends fail: EIO"),
                "one entry"
            );
            assert_eq!(
                retire_where("signed_log", |d| d.starts_with("audit.jsonl: ")),
                1
            );
        }
        assert!(snapshot().is_empty(), "left the status");
        assert!(
            degraded_rows(dir.path()).is_empty(),
            "nothing signed under the lock"
        );
        assert_eq!(flush(), 1, "signed at the next flush");
        let rows = degraded_rows(dir.path());
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0]["source"], "signed_log");
        assert_eq!(flush(), 0, "once");
        reset_for_tests();
        for i in 0..MAX_KEPT {
            note("x", &format!("{i}"));
        }
        assert!(note("x", "past the bound"));
        assert!(
            snapshot().iter().any(|l| l.contains("1 more")),
            "{:?}",
            snapshot()
        );
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

    /// Lot 366 (the re-check of #573, N2): a note past [`MAX_KEPT`] is not
    /// kept for the status but is signed at the next flush — counted, never
    /// only counted (the signed log's own "appends fail" note among them).
    /// Fails where a note past the cap was counted and dropped (a79a10b9).
    #[test]
    fn a_note_past_the_cap_is_signed_at_the_next_flush() {
        let _g = TEST_LOCK.lock();
        reset_for_tests();
        for i in 0..MAX_KEPT {
            assert!(note("k366_fill", &format!("{i}")));
        }
        assert!(note("signed_log", "audit.jsonl: appends fail: EIO"));
        assert!(
            !note("signed_log", "audit.jsonl: appends fail: EIO"),
            "one, waiting or kept"
        );
        assert!(
            snapshot().last().unwrap().contains("1 more"),
            "{:?}",
            snapshot()
        );
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(attach_audit_log(Some(open_log(dir.path()))), MAX_KEPT + 1);
        let rows = degraded_rows(dir.path());
        assert!(
            rows.iter().any(|r| r["source"] == "signed_log"),
            "signed though not kept"
        );
        assert_eq!(flush(), 0, "once");
        reset_for_tests();
    }

    /// Lot 366 (the re-check of #573, N2): a part with a budget of its own
    /// keeps its records whatever the other parts keep, and crowds out
    /// none of theirs; past its budget a record is still signed at the next
    /// flush. Fails where every note shared one cap (a79a10b9: the exec
    /// pumps' slow records filled it, a share held was then dropped).
    #[test]
    fn a_part_s_own_budget_is_kept_and_crowds_out_no_other() {
        let _g = TEST_LOCK.lock();
        reset_for_tests();
        let _told = KeptTold::new();
        for i in 0..MAX_KEPT {
            report("k366_fill", &format!("{i}"));
        }
        assert!(note_kept("k366_held", "the users' share", 2));
        assert!(note_kept("k366_held", "root's share", 2));
        assert!(!note_kept("k366_held", "root's share", 2), "one entry");
        let lines = snapshot();
        assert!(
            lines.contains(&"k366_held: the users' share".to_string()),
            "{lines:?}"
        );
        assert!(lines.contains(&"k366_held: root's share".to_string()));
        assert_eq!(lines.len(), MAX_KEPT + 2, "kept beside a full registry");
        // past its budget: not kept, still signed
        assert!(note_kept("k366_held", "the system's share", 2));
        assert!(!snapshot().iter().any(|l| l.contains("the system's share")));
        // the other parts' room is theirs: the budgeted ones take none of it
        reset_for_tests();
        for i in 0..2 {
            note_kept("k366_slow", &format!("{i}"), 2);
        }
        for i in 0..MAX_KEPT {
            report("k366_fill", &format!("{i}"));
        }
        assert_eq!(count(), MAX_KEPT + 2);
        let lines = snapshot();
        assert_eq!(lines.len(), MAX_KEPT + 2, "nothing of theirs only counted");
        assert!(!lines.iter().any(|l| l.contains(" more ")), "{lines:?}");
        assert!(note_kept("k366_slow", "2", 2));
        assert!(
            note_kept("k366_held", "the users' share", 2),
            "another part's budget"
        );
        let dir = tempfile::tempdir().unwrap();
        attach_audit_log(Some(open_log(dir.path())));
        let rows = degraded_rows(dir.path());
        for (source, detail) in [("k366_slow", "2"), ("k366_held", "the users' share")] {
            assert!(
                rows.iter()
                    .any(|r| r["source"] == source && r["detail"] == detail),
                "{source}: {detail} signed"
            );
        }
        // a record retired leaves the status alone: the source's others stay
        assert_eq!(retire_kept("k366_slow", "0"), 1);
        assert!(snapshot().contains(&"k366_slow: 1".to_string()));
        // a window's total: signed, not kept
        sign_ended("k366_slow", "the total");
        assert!(!snapshot().iter().any(|l| l.contains("the total")));
        assert_eq!(flush(), 1);
        drop(_told);
        reset_for_tests();
    }

    /// Lot 366 (the re-check of #573, N1): in the unit tests, the records
    /// of the parts with a budget of their own (the exec pumps', made by
    /// any test that runs a pump step, on any thread) stay out of the
    /// registry the other tests read, unless a test holding [`TEST_LOCK`]
    /// has them told.
    #[test]
    fn the_budgeted_records_are_told_only_while_a_test_asks() {
        let _g = TEST_LOCK.lock();
        reset_for_tests();
        assert!(note_kept("k366_slow", "not told", 1));
        assert!(snapshot().is_empty());
        let told = KeptTold::new();
        assert!(note_kept("k366_slow", "told", 1));
        assert_eq!(snapshot(), vec!["k366_slow: told"]);
        drop(told);
        assert_eq!(
            retire_kept("k366_slow", "told"),
            0,
            "not told: nothing done"
        );
        reset_for_tests();
    }
}
