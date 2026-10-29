//! Copy on first write — ransomware rollback for Linux (lab PR 222,
//! capability C19, EXPERIMENTAL, off unless a signed `cow-guard.local`
//! turns it on).
//!
//! Before a writer whose trust is not established opens an existing file
//! for writing inside a protected scope, the guard takes a copy of the
//! file's content — a reflink where the filesystem shares extents, a
//! bounded byte copy elsewhere — while the open waits in a fanotify
//! permission event (`FAN_OPEN_PERM`, answered `FAN_ALLOW`, never denied:
//! a copy within `event_budget_ms` (50 ms by default) plus 25 ms at the
//! latest, the other opens once the reader has decided). The copies sit in
//! a root-only journal on the scope's filesystem by default, protected by the anti-tamper inode
//! hooks, with a content index, a byte budget, LRU eviction and a 24 h
//! retention. When the ransomware rules fire and the response kills the
//! process tree, the files that tree rewrote can be restored from the
//! journal — by a signed `nn-admin remediate ransomware`, or on their own
//! when `auto_restore = true` (off by default) — each restored file a
//! signed audit row, and not over a file someone else changed after the
//! attack as far as the guard saw it ([`restore`]).
//!
//! - [`config`]: the signed overlay.
//! - [`trust`]: which writers are copied for.
//! - [`fanotify`]: the group, its events, the writers' open flags.
//! - [`copy`]: reflink or bounded copy within the deadline.
//! - [`index`], [`journal`], [`protect`], [`store`]: the journal.
//! - [`restore`]: the restore rules.
//! - [`guard`]: the threads.
//!
//! Design, threat model and limits: `docs/design/COPY_ON_FIRST_WRITE.md`.

pub mod config;
pub mod copy;
pub mod fanotify;
pub mod guard;
pub mod index;
pub mod journal;
pub mod protect;
pub mod restore;
pub mod store;
pub mod trust;

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use parking_lot::Mutex;
use tracing::{error, info, warn};

use nn_model::Event;
use nn_proto::admin_protocol::CowGuardStatus;

use crate::audit::AuditLog;
use crate::config::overlay_auth::Verified;
use crate::posture::lineage::AuthSessionTracker;
use config::CowConfig;
use guard::Runtime;
use restore::Selector;
use store::{now_ms, RestoreBy, RestoreReport, Store};
use trust::{proc_start_ticks, ProcId};

/// The rule whose kill is a ransomware verdict's.
pub const RANSOMWARE_RULE: &str = "NN-L-FIM-010";

/// Every rule whose kill is a ransomware verdict's: NN-L-FIM-010 and lab PR
/// 225's decisive NN-L-IMP-001 (KillProcessTree of the encrypting actor).
pub const RANSOMWARE_RULES: &[&str] = &[RANSOMWARE_RULE, "NN-L-IMP-001"];

/// What the guard is this boot.
#[derive(Clone)]
pub enum GuardState {
    /// No signed overlay, or `enabled = false`.
    Off,
    /// Configured and not running: why.
    Failed(String),
    Running(Arc<Runtime>),
}

/// The guard of this boot (R11c, lab PR 264): what [`boot`] decided, the
/// response mode and the ransomware signals it acts on. The start hands it
/// to the event loop (the signals of the events and of the rules'
/// responses), the COMBAT ladder's NEUTRALIZE, the admin socket (its status
/// and the remediate verb) and the stop. They were process-wide statics
/// (`STATE`, `DETECT_ONLY`, the signals' map) behind free functions.
#[derive(Clone)]
pub struct CowGuard {
    state: GuardState,
    /// The agent runs detect-only: no restore runs on its own.
    detect_only: bool,
    /// Processes a ransomware signal named, by pid.
    signals: Arc<Mutex<HashMap<u32, Signal>>>,
}

impl CowGuard {
    /// What [`boot`] decided.
    pub fn state(&self) -> &GuardState {
        &self.state
    }

    /// The running guard, if any.
    fn running(&self) -> Option<&Arc<Runtime>> {
        match &self.state {
            GuardState::Running(rt) => Some(rt),
            _ => None,
        }
    }

    /// The guard as `status --key` shows it.
    pub fn status(&self) -> CowGuardStatus {
        let off = |state: String| CowGuardStatus {
            state,
            flags_source: String::new(),
            auto_restore: false,
            scopes: Vec::new(),
            counters: Vec::new(),
        };
        match &self.state {
            GuardState::Off => off("off".into()),
            GuardState::Failed(why) => off(format!("failed: {why}")),
            GuardState::Running(rt) => rt.status(),
        }
    }
}

/// Boot: read the signed overlay and start the guard when it says so.
/// Called once, after the anti-tamper hooks are attached (the journals are
/// registered in their map) and the audit log is open.
pub fn boot(
    overlay: &Verified,
    tracker: AuthSessionTracker,
    audit: Option<Arc<parking_lot::Mutex<AuditLog>>>,
    pin_root: Option<PathBuf>,
    detect_only: bool,
) -> CowGuard {
    CowGuard {
        state: boot_inner(overlay, tracker, audit, pin_root),
        detect_only,
        signals: Arc::default(),
    }
}

fn boot_inner(
    overlay: &Verified,
    tracker: AuthSessionTracker,
    audit: Option<Arc<parking_lot::Mutex<AuditLog>>>,
    pin_root: Option<PathBuf>,
) -> GuardState {
    if matches!(overlay, Verified::Refused) {
        // The gate logged and signed why (`unauthorized_overlay`).
        return GuardState::Failed(
            "cow-guard.local refused by the overlay gate (no valid signature)".into(),
        );
    }
    let Some(text) = overlay.text() else {
        return GuardState::Off;
    };
    let cfg = match CowConfig::parse(text) {
        Ok(c) => c,
        Err(e) => {
            error!(error = %e, "cow-guard.local refused — copy on first write off");
            return GuardState::Failed(format!("cow-guard.local: {e:#}"));
        }
    };
    if !cfg.enabled {
        info!("copy on first write: cow-guard.local present, enabled = false — off");
        return GuardState::Off;
    }
    let (store, problems) = Store::open(cfg, pin_root.clone());
    store.set_audit_log(audit);
    for p in &problems {
        warn!(problem = %p, "copy on first write: a journal could not be used");
        store.sign_degraded("journal_open", p, serde_json::json!({}));
    }
    if store.journals.iter().all(|j| j.is_none()) {
        return GuardState::Failed(format!(
            "no journal could be opened: {}",
            problems.join("; ")
        ));
    }
    let mut protected = 0;
    for (i, j) in store.journals.iter().enumerate() {
        let Some(j) = j else { continue };
        match protect::protect_journal(&j.lock(), pin_root.as_deref()) {
            Ok(n) => protected += n,
            Err(e) => {
                let scope = store.cfg.scopes[i].journal.display().to_string();
                warn!(journal = %scope, error = %e, "copy on first write: journal NOT protected by the anti-tamper hooks");
                store.sign_degraded(
                    "journal_unprotected",
                    &format!("{scope}: {e:#} — root can delete the copies"),
                    serde_json::json!({ "journal": scope }),
                );
            }
        }
    }
    match Runtime::start(Arc::clone(&store), tracker) {
        Ok(rt) => {
            let scopes: Vec<serde_json::Value> = store
                .cfg
                .scopes
                .iter()
                .enumerate()
                .map(|(i, s)| {
                    serde_json::json!({
                        "path": s.path.display().to_string(),
                        "mark": s.mark.as_str(),
                        "marks": rt.marks(i),
                        "budget": s.budget,
                        "journal": s.journal.display().to_string(),
                        "copy_method": rt.copy_method(i),
                        "journal_open": store.journals[i].is_some(),
                    })
                })
                .collect();
            info!(
                scopes = ?store.cfg.scopes.iter().map(|s| s.path.display().to_string()).collect::<Vec<_>>(),
                flags = %rt.flags_source,
                protected_inodes = protected,
                auto_restore = store.cfg.auto_restore,
                "copy on first write: guard running (EXPERIMENTAL)"
            );
            store.sign(
                "cow_guard",
                serde_json::json!({
                    "event": "started",
                    "scopes": scopes,
                    "copy_cap": store.cfg.copy_cap,
                    "event_budget_ms": store.cfg.event_budget_ms,
                    "retention_hours": store.cfg.retention_hours,
                    "auto_restore": store.cfg.auto_restore,
                    "trusted_writers": store.cfg.trusted_writers,
                    "flags_source": rt.flags_source,
                    "protected_inodes": protected,
                }),
                "agent-self",
                "started",
            );
            GuardState::Running(rt)
        }
        Err(why) => {
            error!(why = %why, "copy on first write: the guard could not start");
            store.sign_degraded("start_failed", &why, serde_json::json!({}));
            GuardState::Failed(why)
        }
    }
}

// ── ransomware verdicts ───────────────────────────────────────────────

/// A ransomware signal: the process's start, when, which signal.
type Signal = (u64, u64, &'static str);

const SIGNAL_TTL_MS: u64 = 3_600_000;

impl CowGuard {
    /// Agent shutdown: close the group (the kernel allows whatever waits).
    pub fn shutdown(&self) {
        if let Some(rt) = self.running() {
            rt.stop();
        }
    }

    fn flag(&self, pid: u32, why: &'static str) {
        if pid <= 1 {
            return;
        }
        let start = proc_start_ticks(std::path::Path::new("/proc"), pid).unwrap_or(0);
        let now = now_ms();
        let mut s = self.signals.lock();
        if s.len() >= 1024 {
            s.retain(|_, (_, at, _)| now.saturating_sub(*at) < SIGNAL_TTL_MS);
        }
        s.insert(pid, (start, now, why));
    }

    fn flagged(&self, p: ProcId) -> bool {
        let now = now_ms();
        self.signals
            .lock()
            .get(&p.pid)
            .is_some_and(|(start, at, _)| {
                now.saturating_sub(*at) < SIGNAL_TTL_MS
                    && (p.start == 0 || *start == 0 || *start == p.start)
            })
    }

    /// Every event the agent reads: a mass rewrite of existing files is a
    /// ransomware signal for its writer.
    pub fn observe_event(&self, event: &Event) {
        if self.running().is_none() {
            return;
        }
        if let Event::MassWrite {
            pid,
            overwrites: true,
            ..
        } = event
        {
            self.flag(*pid, "mass_write_overwrites");
        }
    }

    /// A rule verdict's response ran: the ransomware rule's kill
    /// neutralized its writer.
    pub fn after_rule_response(&self, rule_id: &str, pid: u32, neutralized: bool) {
        if self.running().is_none() {
            return;
        }
        let Some(rule) = RANSOMWARE_RULES
            .iter()
            .copied()
            .find(|r| rule_id.starts_with(r))
        else {
            return;
        };
        self.flag(pid, rule);
        if neutralized {
            let start = proc_start_ticks(std::path::Path::new("/proc"), pid).unwrap_or(0);
            self.on_neutralized(vec![ProcId { pid, start }], format!("{rule} kill"));
        }
    }

    /// The COMBAT ladder's NEUTRALIZE contained these offenders.
    pub fn on_ladder_neutralized(&self, offenders: Vec<ProcId>) {
        self.on_neutralized(offenders, "COMBAT NEUTRALIZE".into());
    }

    /// A response killed `offenders`. When a ransomware signal named one of
    /// them (or a writer of their trees) and the journal holds copies of
    /// their writes: restore them if `auto_restore`, else say how.
    pub fn on_neutralized(&self, offenders: Vec<ProcId>, source: String) {
        on_neutralized(self, offenders, source)
    }

    /// The signed admin verb's restore.
    pub fn admin_restore(
        &self,
        pid: Option<u32>,
        since_unix: Option<u64>,
        dry_run: bool,
        key_fp: String,
    ) -> Result<RestoreReport, String> {
        admin_restore(Some(self), pid, since_unix, dry_run, key_fp)
    }
}

/// [`CowGuard::on_neutralized`].
fn on_neutralized(guard: &CowGuard, offenders: Vec<ProcId>, source: String) {
    let Some(rt) = guard.running() else {
        return;
    };
    let entries: Vec<ProcId> = {
        let ix = rt.store.index.lock();
        ix.entries()
            .filter(|e| offenders.iter().any(|o| e.in_tree_of(*o)))
            .map(|e| e.writer)
            .collect()
    };
    if entries.is_empty() {
        return;
    }
    let ransomware =
        offenders.iter().any(|o| guard.flagged(*o)) || entries.iter().any(|w| guard.flagged(*w));
    if !ransomware {
        return;
    }
    let pids: Vec<u32> = offenders.iter().map(|o| o.pid).collect();
    let detect_only = guard.detect_only;
    if !rt.store.cfg.auto_restore || detect_only {
        warn!(
            offenders = ?pids,
            copies = entries.len(),
            source = %source,
            detect_only,
            "copy on first write: ransomware neutralized — the journal holds copies of its writes; \
             no restore on its own (auto_restore off, or detect-only): \
             `nn-admin remediate ransomware --pid <pid> --key <key>` restores them"
        );
        rt.store.sign(
            "cow_guard",
            serde_json::json!({
                "event": "restore_available",
                "offenders": pids,
                "copies": entries.len(),
                "source": source,
            }),
            "agent-self",
            "detected",
        );
        return;
    }
    let rt = Arc::clone(rt);
    let spawned = std::thread::Builder::new()
        .name("nn-cow-restore".into())
        .spawn(move || {
            // The kill is verified by the response; give the tree a moment
            // to be gone from /proc (a running writer is skipped).
            for _ in 0..50 {
                if offenders.iter().all(|o| !store::alive(*o)) {
                    break;
                }
                std::thread::sleep(Duration::from_millis(100));
            }
            let report = rt.store.restore(
                &Selector {
                    roots: offenders,
                    since_ms: None,
                },
                false,
                &RestoreBy::Auto {
                    source: source.clone(),
                },
            );
            log_report(&report, &source);
            rt.store.sign(
                "cow_guard",
                serde_json::json!({
                    "event": "auto_restore",
                    "offenders": pids,
                    "source": source,
                    "restored": report.restored,
                    "recreated": report.recreated,
                    "kept_both": report.kept_both,
                    "unchanged": report.unchanged,
                    "refused": report.refused,
                    "skipped": report.skipped,
                    "refusal": report.refusal,
                }),
                "agent-self",
                "success",
            );
        });
    if let Err(e) = spawned {
        error!(error = %e, "copy on first write: the restore thread could not start");
    }
}

fn log_report(r: &RestoreReport, source: &str) {
    warn!(
        source,
        restored = r.restored,
        recreated = r.recreated,
        kept_both = r.kept_both,
        unchanged = r.unchanged,
        refused = r.refused,
        skipped = r.skipped,
        refusal = ?r.refusal,
        "copy on first write: restore done (every file is a signed cow_restore row)"
    );
}

/// [`CowGuard::admin_restore`]; `guard`: `None` when the start gave the
/// admin socket none (tests, the legacy serve entry points): the guard is
/// off, as it said before a boot decided.
pub fn admin_restore(
    guard: Option<&CowGuard>,
    pid: Option<u32>,
    since_unix: Option<u64>,
    dry_run: bool,
    key_fp: String,
) -> Result<RestoreReport, String> {
    let Some(rt) = guard.and_then(CowGuard::running) else {
        return Err(match guard.map(CowGuard::state) {
            Some(GuardState::Failed(why)) => {
                format!("the copy-on-first-write guard is not running: {why}")
            }
            _ => "the copy-on-first-write guard is off on this host (no signed cow-guard.local)"
                .into(),
        });
    };
    if pid.is_none() && since_unix.is_none() {
        return Err("name a process (--pid) or a time (--since)".into());
    }
    let sel = Selector {
        roots: pid
            .map(|pid| vec![ProcId { pid, start: 0 }])
            .unwrap_or_default(),
        since_ms: since_unix.map(|s| s.saturating_mul(1000)),
    };
    let report = rt
        .store
        .restore(&sel, dry_run, &RestoreBy::Admin { key_fp });
    if !dry_run {
        log_report(&report, "admin");
    }
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn guard(state: GuardState) -> CowGuard {
        CowGuard {
            state,
            detect_only: false,
            signals: Arc::default(),
        }
    }

    #[test]
    fn signals_match_by_pid_and_start() {
        let g = guard(GuardState::Off);
        let me = std::process::id();
        g.flag(me, "test");
        let start = proc_start_ticks(std::path::Path::new("/proc"), me).unwrap();
        assert!(g.flagged(ProcId { pid: me, start }));
        assert!(g.flagged(ProcId { pid: me, start: 0 }));
        assert!(!g.flagged(ProcId {
            pid: me,
            start: start + 1
        }));
        assert!(!g.flagged(ProcId {
            pid: 4_000_001,
            start: 0
        }));
        g.flag(1, "init is never flagged");
        assert!(!g.flagged(ProcId { pid: 1, start: 0 }));
        // R11c (lab PR 264): another guard's signals are its own.
        assert!(!guard(GuardState::Off).flagged(ProcId { pid: me, start: 0 }));
    }

    #[test]
    fn without_a_guard_the_verb_says_so() {
        let err = guard(GuardState::Off)
            .admin_restore(Some(1), None, true, "k".into())
            .unwrap_err();
        assert!(err.contains("off"), "{err}");
        let err = guard(GuardState::Failed("no journal".into()))
            .admin_restore(Some(1), None, true, "k".into())
            .unwrap_err();
        assert!(err.contains("not running: no journal"), "{err}");
    }
}
