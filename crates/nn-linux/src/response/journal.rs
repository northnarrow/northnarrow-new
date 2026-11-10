//! Wave 4 restructure, R12c (lab PR 270; plan §3.4): **no action without a
//! signed record** — the writer of the `actions` chain and the ticket an
//! action needs.
//!
//! An [`Intent`] is the only way to an action: the executor's acting entry
//! points ([`super::Executor::execute_on`] and the rest), the isolator's
//! engage, the outbound block's release and the exec quarantine's kill all
//! take one, and only [`ActionJournal::intent`] (or
//! [`ActionJournal::intents`]) makes one — after it has appended the signed
//! [`ActionRow::Intent`] row. The row is written (`write(2)`) before the
//! action, so it survives a crash of the agent; it is on the disk (fsync)
//! before the action only when the action's effect outlives a restart of
//! the host — a quarantine, a capability strip, a restore
//! ([`synced_before_action`]); a kill's, a block's, a throttle's, an
//! isolation's is synced with its outcome (review of #476: the fsync before
//! them slowed the kills on a busy disk and protected only against a crash
//! of the host, which ends their effect too). Every fsync is done outside
//! the writer's lock, so the ladder, the exec quarantine and the restore do
//! not wait behind the dispatcher's. [`Intent::finish`] appends the
//! [`ActionRow::Outcome`] row; an intent dropped without one (a panic in the
//! action) appends an [`ActionResult::Abandoned`] outcome itself. So no code
//! can act without the intent written first, and no intent stays without an
//! answer while the agent runs.
//!
//! So the invariant is: no action without an **attempt** at a signed
//! record. When the journal cannot take a row — not open yet, its log refused at
//! the start (no key), a write that fails — the action still runs (external
//! audit CMB-027's rule: whoever fills the disk must not stop the
//! containment): the row is logged whole at ERROR (the journal's line is its
//! record), counted (`unwritten`, `nn-admin status`, stage 7) and the action
//! proceeds.
//!
//! The start ([`ActionJournal::bind`]) reads the chain's newest archive and
//! active file for intents of earlier runs with no outcome — the agent
//! stopped, crashed or was killed between the two — and answers each with a
//! signed [`ActionRow::Interrupted`] row: whether that action took effect is
//! not known, and the operator is told (a WARN, the status, and the boot's
//! signed `response_interrupted` audit row).
//!
//! Lot 296 (lot 295's finding): the chain's rows are written by the response
//! threads (role actuator), which may not lift the state directory's `+i`
//! (`CAP_LINUX_IMMUTABLE`, the writer role's). Their rotation sealed the
//! active file, failed the rename, and every later row was lost. Now such a
//! thread seals nothing: its rows go on past the cap and the rotation is
//! owed ([`crate::chainlog::RotatingChainLog::rotate_owed`]) to the chain's
//! rotation thread ([`ROTOR_THREAD`], role writer), which the journal starts
//! when it is bound and wakes when a row leaves a rotation owed. The
//! actuator is given no capability for it.

use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;

use parking_lot::{Mutex, MutexGuard};
use rand::Rng;
use tracing::{error, warn};

pub use nn_evidence::action_payload::{
    unanswered_intents, ActionIntent, ActionOutcome, ActionOverflow, ActionRecord, ActionResult,
    ActionRow, OVERFLOW_SAMPLES,
};
use nn_evidence::clock::{Clock, SystemClock};
use nn_model::log_escape::Escaped;

/// The `actions` chain's active file (beside the detection log, under the
/// same protection and rotation).
pub const DEFAULT_ACTIONS_LOG_PATH: &str = "/var/lib/northnarrow/detections/actions.jsonl";

/// Its rotation cap (`NN_ACTIONS_CAP_BYTES` overrides it, as the detection
/// log's), and archives kept: the detection log's budget.
pub const DEFAULT_ACTIONS_CAP_BYTES: u64 = 16 * 1024 * 1024;
pub const DEFAULT_ACTIONS_MAX_ARCHIVES: usize = 8;
/// The variable that overrides [`DEFAULT_ACTIONS_CAP_BYTES`] (never below
/// 1 MiB: `chainlog::cap_from_env`; reported as weakening by the
/// self-integrity check, as the other evidence logs' caps).
pub use crate::chainlog::ACTIONS_CAP_ENV;

/// Audit op of the start's report of intents without an outcome.
pub const INTERRUPTED_AUDIT_OP: &str = "response_interrupted";

/// Whether an action's intent row is synced (on the disk) before the
/// action, not only written: when its effect outlives a restart of the host
/// (a quarantine, a capability strip, a restore — and any action not named
/// here). A kill, a block, a throttle, an isolation and a release end with
/// the host; their intent is written before them (it survives a crash of
/// the agent) and synced with their outcome.
pub fn synced_before_action(response: &str) -> bool {
    !matches!(
        response,
        "KillProcess"
            | "KillProcessTree"
            | "BlockOutbound"
            | "ThrottleProcess"
            | "FullNetworkIsolation"
            | "Isolate"
            | "Release"
    )
}

/// Bytes of a file the start's scan reads at most (its tail).
const SCAN_BYTES: u64 = 32 * 1024 * 1024;

type Log = crate::chainlog::RotatingChainLog<ActionRecord>;

enum Writer {
    /// Not bound yet (the start opens the log after the executor exists).
    Late,
    /// The signed chain.
    Log(Box<Log>),
    /// Rows kept in memory (tests, replays).
    Memory(Vec<ActionRecord>),
    /// The log did not open: why.
    Off(String),
}

/// The journal's counts (`nn-admin status`, the heartbeat).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct JournalCounts {
    /// Intent and outcome rows written.
    pub intents: u64,
    pub outcomes: u64,
    /// Rows the journal could not write (logged whole at ERROR instead).
    pub unwritten: u64,
    /// Intents of earlier runs found without an outcome at the start.
    pub interrupted_at_boot: u64,
    /// Intents dropped without an outcome (a panic in the action).
    pub abandoned: u64,
    /// Overflow rows written.
    pub overflow_rows: u64,
    /// Actions between their intent and their outcome now.
    pub in_flight: u64,
    /// fsyncs of the chain that failed (its rows written, whether on the
    /// disk not known).
    pub sync_failed: u64,
}

#[derive(Default)]
struct Counters {
    intents: AtomicU64,
    outcomes: AtomicU64,
    unwritten: AtomicU64,
    interrupted: AtomicU64,
    abandoned: AtomicU64,
    overflow_rows: AtomicU64,
    in_flight: AtomicU64,
    sync_failed: AtomicU64,
}

struct Inner {
    run: String,
    next: AtomicU64,
    writer: Mutex<Writer>,
    counters: Counters,
    clock: Arc<dyn Clock>,
    /// Lot 296: the rotation thread's wake-up ([`ROTOR_THREAD`]); `None`
    /// before [`ActionJournal::bind`], or when it could not start.
    rotor: Mutex<Option<std::sync::mpsc::Sender<()>>>,
    /// Lot 296: the rotation thread's last rotation failed (said once).
    rotor_failed: std::sync::atomic::AtomicBool,
}

/// Lot 296: the `actions` chain's rotation thread (role writer: it may lift
/// the state directory's `+i`): it rotates the chain when a response
/// thread's row left a rotation owed.
pub const ROTOR_THREAD: &str = "nn-actions-rotate";

/// The writer of the `actions` chain (see the module's doc). Cheap to
/// clone: every clone writes the same chain.
#[derive(Clone)]
pub struct ActionJournal {
    inner: Arc<Inner>,
}

impl std::fmt::Debug for ActionJournal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ActionJournal")
            .field("run", &self.inner.run)
            .finish_non_exhaustive()
    }
}

/// What the start's scan found ([`ActionJournal::bind`]).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Recovery {
    /// Each intent of an earlier run without an outcome: its run, number,
    /// response and target, as answered by an interrupted row.
    pub interrupted: Vec<String>,
    /// The same: (run, action, what), for [`ActionJournal::start_run`].
    pub open: Vec<(String, u64, String)>,
    /// Why the scan could not read the chain (`None`: it read it).
    pub unread: Option<String>,
}

impl ActionJournal {
    fn with(writer: Writer, clock: Arc<dyn Clock>, run: String) -> Self {
        Self {
            inner: Arc::new(Inner {
                run,
                next: AtomicU64::new(1),
                writer: Mutex::new(writer),
                counters: Counters::default(),
                clock,
                rotor: Mutex::new(None),
                rotor_failed: std::sync::atomic::AtomicBool::new(false),
            }),
        }
    }

    /// The agent's journal, bound to its log later ([`Self::bind`]); its
    /// run drawn from the OS CSPRNG.
    pub fn late() -> Self {
        Self::with(
            Writer::Late,
            Arc::new(SystemClock),
            format!("{:016x}", crate::os_rng::OsRng.next_u64()),
        )
    }

    /// A journal that keeps its rows in memory (tests, replays): the same
    /// tickets, the same rows.
    pub fn memory() -> Self {
        Self::memory_with(Arc::new(SystemClock), "0000000000000001")
    }

    /// [`Self::memory`] stamping its rows with `clock`, for `run`.
    pub fn memory_with(clock: Arc<dyn Clock>, run: &str) -> Self {
        Self::with(Writer::Memory(Vec::new()), clock, run.to_string())
    }

    /// This run's id.
    pub fn run(&self) -> &str {
        &self.inner.run
    }

    /// Open the chain at `active` ([`DEFAULT_ACTIONS_LOG_PATH`]).
    pub fn open_log(
        active: &Path,
        key: crate::keys::AgentSigningKey,
        cfg: crate::chainlog::RotationConfig,
        protection: Arc<dyn crate::chainlog::ProtectionManager>,
    ) -> anyhow::Result<Log> {
        use anyhow::Context;
        Log::open(active, key, cfg, protection)
            .with_context(|| format!("opening the actions chain {}", active.display()))
    }

    /// Bind the journal to `log` (whose active file is `active`): from now
    /// on its rows are signed there. First the scan of the chain's newest
    /// archive and active file: every intent of an earlier run without an
    /// outcome is answered by an [`ActionRow::Interrupted`] row and WARNed.
    pub fn bind(&self, log: Log, active: &Path) -> Recovery {
        let mut recovery = Recovery::default();
        let rows = match read_back(active) {
            Ok(rows) => rows,
            Err(e) => {
                recovery.unread = Some(e);
                Vec::new()
            }
        };
        *self.inner.writer.lock() = Writer::Log(Box::new(log));
        self.start_rotor();
        for open in unanswered_intents(&rows, &self.inner.run) {
            let what = open
                .intent
                .as_ref()
                .map(|i| format!("{} pid {} ({})", i.response, i.pid, i.why.join(", ")))
                .unwrap_or_else(|| "an action".to_string());
            recovery
                .interrupted
                .push(format!("run {} action {}: {what}", open.run, open.action));
            recovery.open.push((open.run.clone(), open.action, what));
        }
        recovery
    }

    /// Lot 296: start the chain's rotation thread (once). It must be started
    /// by a thread that holds the core's sets — the start's, which binds the
    /// journal: it inherits its creator's, and takes the writer's role. When
    /// it cannot start, a rotation owed waits for a thread that may rotate
    /// (the run's last row, at the stop), the rows past the cap kept.
    fn start_rotor(&self) {
        let mut rotor = self.inner.rotor.lock();
        if rotor.is_some() {
            return;
        }
        let (tx, rx) = std::sync::mpsc::channel::<()>();
        let inner = Arc::downgrade(&self.inner);
        let started = std::thread::Builder::new()
            .name(ROTOR_THREAD.to_string())
            .spawn(move || {
                crate::caps::enter_or_report(crate::caps::Role::Writer);
                // ends with the journal: its sender dropped with it
                while rx.recv().is_ok() {
                    let Some(inner) = inner.upgrade() else {
                        return;
                    };
                    rotate_owed(&inner);
                }
            });
        match started {
            Ok(_) => *rotor = Some(tx),
            Err(e) => error!(
                target: "response.journal",
                error = %e,
                "the actions chain's rotation thread did not start — a rotation a response \
                 thread cannot do waits for the stop; its rows go on past the cap"
            ),
        }
    }

    /// R12c-3: the run's start, once the boot signed its audit row of
    /// `recovery` (`response_interrupted`): each open intent of an earlier
    /// run answered by an interrupted row (WARNed, counted), then this
    /// run's `run_started` row. A crash before this leaves the intents
    /// open: the next start reports them again — the audit row is never
    /// missing for an interrupted row (the re-check of #476).
    pub fn start_run(&self, recovery: &Recovery) {
        let mut w = self.inner.writer.lock();
        for (run, action, what) in &recovery.open {
            let row = ActionRecord {
                row: ActionRow::Interrupted,
                run: run.clone(),
                action: *action,
                ts: nn_evidence::clock::stamp(self.inner.clock.as_ref()),
                intent: None,
                outcome: Some(ActionOutcome {
                    result: ActionResult::Unknown,
                    outcome: format!("{what}: not known"),
                    reason: Some(
                        "the agent stopped between the action's intent and its outcome".to_string(),
                    ),
                    elapsed_us: 0,
                    intent_written: true,
                }),
                overflow: None,
                noted_by: Some(self.inner.run.clone()),
            };
            warn!(
                run = %run,
                action = *action,
                what = %Escaped(what),
                "an action of an earlier run has its intent and no outcome: the agent stopped \
                 between the two — whether it took effect is not known (signed interrupted row)"
            );
            self.inner
                .counters
                .interrupted
                .fetch_add(1, Ordering::Relaxed);
            write_row(&mut w, &self.inner, row);
        }
        let started = self.run_row(ActionRow::RunStarted);
        write_row(&mut w, &self.inner, started);
        self.commit(w);
    }

    /// R12c-3: the run's last row, at a clean stop (synced).
    pub fn end_run(&self) {
        let mut w = self.inner.writer.lock();
        let ended = self.run_row(ActionRow::RunEnded);
        write_row(&mut w, &self.inner, ended);
        self.commit(w);
    }

    /// R12c-3: action `action` still running after `busy` (the stall
    /// bound): a signed `stalled` row — not its answer; its outcome row
    /// comes when it ends.
    pub fn stalled(&self, action: u64, what: &str, busy: std::time::Duration) {
        let row = ActionRecord {
            row: ActionRow::Stalled,
            run: self.inner.run.clone(),
            action,
            ts: nn_evidence::clock::stamp(self.inner.clock.as_ref()),
            intent: None,
            outcome: Some(ActionOutcome {
                result: ActionResult::Unknown,
                outcome: format!("{what}: still running"),
                reason: Some(format!(
                    "running for {} s, past the stall bound",
                    busy.as_secs()
                )),
                elapsed_us: busy.as_micros() as u64,
                intent_written: true,
            }),
            overflow: None,
            noted_by: None,
        };
        let mut w = self.inner.writer.lock();
        write_row(&mut w, &self.inner, row);
        self.commit(w);
    }

    fn run_row(&self, row: ActionRow) -> ActionRecord {
        ActionRecord {
            row,
            run: self.inner.run.clone(),
            action: 0,
            ts: nn_evidence::clock::stamp(self.inner.clock.as_ref()),
            intent: None,
            outcome: None,
            overflow: None,
            noted_by: None,
        }
    }

    /// The log could not be opened (`why`): every row from now on is logged
    /// at ERROR and counted unwritten; the actions still run.
    pub fn bind_off(&self, why: &str) {
        *self.inner.writer.lock() = Writer::Off(why.to_string());
    }

    /// The intent of one action, written (and synced when
    /// [`synced_before_action`]): the ticket the action needs.
    pub fn intent(&self, intent: ActionIntent) -> Intent {
        self.intents(vec![intent])
            .pop()
            .expect("one intent for one row")
    }

    /// The intents of several actions (the dispatcher's batch), written —
    /// with one sync when one of them is [`synced_before_action`]: the
    /// tickets, in order.
    pub fn intents(&self, intents: Vec<ActionIntent>) -> Vec<Intent> {
        let durable = intents.iter().any(|i| synced_before_action(&i.response));
        let mut w = self.inner.writer.lock();
        let mut out = Vec::with_capacity(intents.len());
        for i in intents {
            let action = self.inner.next.fetch_add(1, Ordering::Relaxed);
            let what = format!("{} pid {}", i.response, i.pid);
            let row = ActionRecord {
                row: ActionRow::Intent,
                run: self.inner.run.clone(),
                action,
                ts: nn_evidence::clock::stamp(self.inner.clock.as_ref()),
                intent: Some(i),
                outcome: None,
                overflow: None,
                noted_by: None,
            };
            let written = write_row(&mut w, &self.inner, row);
            if written {
                self.inner.counters.intents.fetch_add(1, Ordering::Relaxed);
            }
            self.inner
                .counters
                .in_flight
                .fetch_add(1, Ordering::Relaxed);
            out.push(Intent {
                journal: self.clone(),
                action,
                started: Instant::now(),
                written,
                done: false,
                what,
            });
        }
        if durable {
            // on the disk before the action, whoever's fsync is under way
            // (the re-check of #476: another thread's detached fsync may
            // not have finished)
            self.commit_with(w, true);
        }
        out
    }

    /// Responses decided and not run (stage 6), signed.
    pub fn overflow(&self, overflow: ActionOverflow) {
        let row = ActionRecord {
            row: ActionRow::Overflow,
            run: self.inner.run.clone(),
            action: 0,
            ts: nn_evidence::clock::stamp(self.inner.clock.as_ref()),
            intent: None,
            outcome: None,
            overflow: Some(overflow),
            noted_by: None,
        };
        let mut w = self.inner.writer.lock();
        if write_row(&mut w, &self.inner, row) {
            self.inner
                .counters
                .overflow_rows
                .fetch_add(1, Ordering::Relaxed);
        }
        self.commit(w);
    }

    /// Sync the rows written without one (the outcomes
    /// [`Intent::finish_deferred`] wrote, the intents of actions not
    /// [`synced_before_action`]).
    pub fn sync(&self) {
        self.commit(self.inner.writer.lock());
    }

    /// fsyncs of the chain's active file by this journal (introspection,
    /// tests).
    pub fn fsyncs(&self) -> u64 {
        match &*self.inner.writer.lock() {
            Writer::Log(log) => log.fsyncs(),
            _ => 0,
        }
    }

    /// The fsync of the rows written so far, done after `w` is released:
    /// the other writers do not wait for the disk.
    fn commit(&self, w: MutexGuard<'_, Writer>) {
        self.commit_with(w, false)
    }

    /// [`Self::commit`]; `always`: the fsync even when the writer counts
    /// its rows synced — another thread's detached fsync of them may still
    /// be under way, and the caller's action waits for the disk.
    fn commit_with(&self, mut w: MutexGuard<'_, Writer>, always: bool) {
        let path = match &mut *w {
            Writer::Log(log) => log
                .detach_sync()
                .or_else(|| always.then(|| log.active_path().to_path_buf())),
            _ => None,
        };
        drop(w);
        if let Some(path) = path {
            if let Err(e) = crate::chainlog::sync_detached(&path) {
                // the rows are in the chain; whether on the disk is not known
                self.inner
                    .counters
                    .sync_failed
                    .fetch_add(1, Ordering::Relaxed);
                error!(
                    target: "response.journal",
                    error = %format!("{e:#}"),
                    "the actions chain's sync failed — its last rows may not be on the disk"
                );
            }
        }
    }

    /// The chain's head — its position (the number its active file will
    /// have as an archive, the bytes in it) and its last row's entry hash:
    /// the heartbeat's commitment of the head (R12c-2; review of #476: a
    /// tail cut from the chain shows off the host). `None` before the log
    /// is bound.
    pub fn head(&self) -> Option<(u64, u64, String)> {
        match &*self.inner.writer.lock() {
            Writer::Log(log) => {
                let (file, bytes) = log.position();
                Some((file, bytes, log.last_hash().to_string()))
            }
            _ => None,
        }
    }

    /// R12c-2: whether the chain still holds the head (`file`, `bytes`,
    /// `hash`) its [`Self::head`] named earlier — `false`: its tail was cut
    /// or rewritten since (`None`: not bound, or the file not readable).
    pub fn holds(&self, file: u64, bytes: u64, hash: &str) -> Option<bool> {
        // (the file, and whether the chain must still have it: the active
        // file, or an archive within those it keeps — review of #478, X2)
        let (path, kept) = match &*self.inner.writer.lock() {
            Writer::Log(log) => {
                let now = log.position().0;
                if file == now {
                    (log.active_path().to_path_buf(), true)
                } else {
                    let kept = file < now && now - file <= log.max_archives() as u64;
                    (
                        crate::chainlog::archive_path_for(log.active_path(), file),
                        kept,
                    )
                }
            }
            _ => return None,
        };
        match crate::chainlog::holds_line_ending_at(&path, bytes, hash) {
            Ok(held) => Some(held),
            // a file the chain keeps, gone: removed — the head not held
            Err(_) if kept && std::fs::symlink_metadata(&path).is_err() => Some(false),
            Err(_) => None,
        }
    }

    /// The rows a memory journal holds (empty for the signed chain's).
    pub fn rows(&self) -> Vec<ActionRecord> {
        match &*self.inner.writer.lock() {
            Writer::Memory(rows) => rows.clone(),
            _ => Vec::new(),
        }
    }

    pub fn counts(&self) -> JournalCounts {
        let c = &self.inner.counters;
        JournalCounts {
            intents: c.intents.load(Ordering::Relaxed),
            outcomes: c.outcomes.load(Ordering::Relaxed),
            unwritten: c.unwritten.load(Ordering::Relaxed),
            interrupted_at_boot: c.interrupted.load(Ordering::Relaxed),
            abandoned: c.abandoned.load(Ordering::Relaxed),
            overflow_rows: c.overflow_rows.load(Ordering::Relaxed),
            in_flight: c.in_flight.load(Ordering::Relaxed),
            sync_failed: c.sync_failed.load(Ordering::Relaxed),
        }
    }

    fn outcome(&self, action: u64, outcome: ActionOutcome, durable: bool) {
        let row = ActionRecord {
            row: ActionRow::Outcome,
            run: self.inner.run.clone(),
            action,
            ts: nn_evidence::clock::stamp(self.inner.clock.as_ref()),
            intent: None,
            outcome: Some(outcome),
            overflow: None,
            noted_by: None,
        };
        let mut w = self.inner.writer.lock();
        if write_row(&mut w, &self.inner, row) {
            self.inner.counters.outcomes.fetch_add(1, Ordering::Relaxed);
        }
        if durable {
            self.commit(w);
        } else {
            drop(w);
        }
        let in_flight = &self.inner.counters.in_flight;
        let mut n = in_flight.load(Ordering::Relaxed);
        while n > 0 {
            match in_flight.compare_exchange_weak(n, n - 1, Ordering::Relaxed, Ordering::Relaxed) {
                Ok(_) => break,
                Err(now) => n = now,
            }
        }
    }
}

/// The ticket of one action (see the module's doc): made only by
/// [`ActionJournal::intent`], after the intent row; answered by
/// [`Self::finish`] — or, dropped unanswered, by an
/// [`ActionResult::Abandoned`] outcome.
#[must_use = "an intent is answered by its outcome (finish)"]
pub struct Intent {
    journal: ActionJournal,
    action: u64,
    started: Instant,
    written: bool,
    done: bool,
    what: String,
}

impl std::fmt::Debug for Intent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Intent")
            .field("run", &self.journal.inner.run)
            .field("action", &self.action)
            .field("written", &self.written)
            .finish_non_exhaustive()
    }
}

impl Intent {
    /// The action's number in its run.
    pub fn number(&self) -> u64 {
        self.action
    }

    /// The intent row is in the chain (false: logged at ERROR instead).
    pub fn written(&self) -> bool {
        self.written
    }

    /// The action's outcome, written and synced.
    pub fn finish(self, result: ActionResult, outcome: String, reason: Option<String>) {
        self.finish_with(result, outcome, reason, true)
    }

    /// [`Self::finish`] without the sync (the dispatcher syncs its batch:
    /// [`ActionJournal::sync`]).
    pub fn finish_deferred(self, result: ActionResult, outcome: String, reason: Option<String>) {
        self.finish_with(result, outcome, reason, false)
    }

    fn finish_with(
        mut self,
        result: ActionResult,
        outcome: String,
        reason: Option<String>,
        durable: bool,
    ) {
        self.done = true;
        let elapsed_us = self.started.elapsed().as_micros() as u64;
        self.journal.outcome(
            self.action,
            ActionOutcome {
                result,
                outcome,
                reason,
                elapsed_us,
                intent_written: self.written,
            },
            durable,
        );
    }
}

impl Drop for Intent {
    fn drop(&mut self) {
        if self.done {
            return;
        }
        self.journal
            .inner
            .counters
            .abandoned
            .fetch_add(1, Ordering::Relaxed);
        error!(
            action = self.action,
            what = %Escaped(&self.what),
            "an action's intent was dropped without its outcome (a panic in the action?) — \
             signed as abandoned"
        );
        self.journal.outcome(
            self.action,
            ActionOutcome {
                result: ActionResult::Abandoned,
                outcome: format!("{}: not known", self.what),
                reason: Some("the action ended without an outcome".to_string()),
                elapsed_us: self.started.elapsed().as_micros() as u64,
                intent_written: self.written,
            },
            true,
        );
    }
}

/// The tests' ticket: a memory journal's intent (nn-linux's own tests).
#[cfg(test)]
pub(crate) fn test_intent() -> Intent {
    ActionJournal::memory().intent(ActionIntent::named("test", "test", 0))
}

/// Append `row`, written, not synced (the caller's [`ActionJournal::commit`]
/// syncs). A row the writer cannot take is logged whole at ERROR and
/// counted. Returns whether it is in the chain (or the memory journal).
fn write_row(w: &mut Writer, inner: &Inner, row: ActionRecord) -> bool {
    let counters = &inner.counters;
    let why = match w {
        Writer::Memory(rows) => {
            rows.push(row);
            return true;
        }
        Writer::Log(log) => {
            let appended = log.append_deferred(row.clone());
            if log.rotation_owed() {
                // lot 296: to the thread that may rotate
                if let Some(rotor) = &*inner.rotor.lock() {
                    let _ = rotor.send(());
                }
            }
            match appended {
                Ok(_) => return true,
                Err(e) => format!("{e:#}"),
            }
        }
        Writer::Late => "the actions chain is not open yet".to_string(),
        Writer::Off(why) => why.clone(),
    };
    counters.unwritten.fetch_add(1, Ordering::Relaxed);
    let text = serde_json::to_string(&row).unwrap_or_default();
    error!(
        target: "response.journal",
        why = %Escaped(&why),
        row = %Escaped(&text),
        "an action's row is NOT in the signed actions chain — this line is its record; the \
         action proceeds"
    );
    false
}

/// Lot 296: the rotation a response thread's row left owed, on the rotation
/// thread. A failure is said once (ERROR), and again only after a rotation
/// went through: the rows go on past the cap meanwhile, none lost.
fn rotate_owed(inner: &Inner) {
    let mut w = inner.writer.lock();
    let Writer::Log(log) = &mut *w else {
        return;
    };
    match log.rotate_owed() {
        Ok(true) => {
            inner.rotor_failed.store(false, Ordering::Relaxed);
            let (file, bytes) = log.position();
            tracing::info!(
                target: "response.journal",
                file,
                bytes,
                "the actions chain rotated on its rotation thread"
            );
        }
        Ok(false) => {}
        Err(e) => {
            if !inner.rotor_failed.swap(true, Ordering::Relaxed) {
                error!(
                    target: "response.journal",
                    error = %format!("{e:#}"),
                    "the actions chain could not rotate on its rotation thread — its rows go \
                     on past the cap, none lost; tried again at the next row"
                );
            }
        }
    }
}

/// The rows of the chain's newest archive and active file, in chain order
/// (each file's last [`SCAN_BYTES`]). Decoded only: the chain's own checks
/// (the boot check, `nn-admin chain verify`) prove them; the scan only
/// pairs intents with their answers.
/// R12c-3: the rows the start's scan needs — the newest archive and the
/// active file, and, when the last run there has neither its `run_ended`
/// (a clean stop) nor its `run_started` (it crashed: its start is further
/// back), the older archives one by one until its `run_started` (the
/// review of #476: an intent more than one rotation back). Bounded by the
/// archives kept.
fn read_back(active: &Path) -> Result<Vec<ActionRecord>, String> {
    let archives = crate::chainlog::archives_newest_first(active);
    let mut rows = read_file(active)?;
    for (n, a) in archives.iter().enumerate() {
        if n >= 1 {
            let last_run = rows.last().map(|r| r.run.clone());
            let complete = last_run.is_none_or(|run| {
                rows.iter().any(|r| {
                    r.run == run && matches!(r.row, ActionRow::RunStarted | ActionRow::RunEnded)
                })
            });
            if complete {
                break;
            }
        }
        let mut older = read_file(a)?;
        older.append(&mut rows);
        rows = older;
    }
    Ok(rows)
}

/// The rows of one file of the chain (its last [`SCAN_BYTES`]); none when
/// it is not there.
fn read_file(f: &Path) -> Result<Vec<ActionRecord>, String> {
    let bytes = match read_tail(f) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(format!("{}: {e}", f.display())),
    };
    Ok(bytes
        .split(|b| *b == b'\n')
        .filter_map(|line| {
            serde_json::from_slice::<crate::chainlog::ChainLine<ActionRecord>>(line).ok()
        })
        .map(|l| l.payload)
        .collect())
}

#[cfg(test)]
fn read_rows(active: &Path) -> Result<Vec<ActionRecord>, String> {
    let mut files: Vec<std::path::PathBuf> = crate::chainlog::archives_newest_first(active)
        .into_iter()
        .take(1)
        .collect();
    files.push(active.to_path_buf());
    let mut rows = Vec::new();
    for f in files {
        let bytes = match read_tail(&f) {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(e) => return Err(format!("{}: {e}", f.display())),
        };
        for line in bytes.split(|b| *b == b'\n') {
            if let Ok(l) = serde_json::from_slice::<crate::chainlog::ChainLine<ActionRecord>>(line)
            {
                rows.push(l.payload);
            }
        }
    }
    Ok(rows)
}

/// The last [`SCAN_BYTES`] of `path` (from the start of a line), opened
/// without following a final symbolic link.
fn read_tail(path: &Path) -> std::io::Result<Vec<u8>> {
    use std::io::{Read, Seek, SeekFrom};
    use std::os::unix::fs::OpenOptionsExt;
    let mut f = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)?;
    let len = f.metadata()?.len();
    let from = len.saturating_sub(SCAN_BYTES);
    f.seek(SeekFrom::Start(from))?;
    let mut buf = Vec::new();
    f.take(SCAN_BYTES).read_to_end(&mut buf)?;
    if from > 0 {
        // the first line may be cut: start after it
        let cut = buf
            .iter()
            .position(|b| *b == b'\n')
            .map_or(buf.len(), |p| p + 1);
        buf.drain(..cut);
    }
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    pub(crate) fn intent_row(response: &str, pid: u32) -> ActionIntent {
        ActionIntent {
            source: "rule".into(),
            response: response.into(),
            pid,
            start_ns: 0,
            file: None,
            severity: "critical".into(),
            why: vec!["NN-L-TEST-001".into()],
            detail: None,
            queued_us: 0,
        }
    }

    /// Intent, then outcome, paired by run and number; the counts follow.
    #[test]
    fn an_intent_is_answered_by_its_outcome() {
        let j = ActionJournal::memory();
        let i = j.intent(intent_row("KillProcess", 42));
        assert!(i.written());
        assert_eq!(j.counts().in_flight, 1);
        i.finish(ActionResult::Success, "Killed { pid: 42 }".into(), None);
        let rows = j.rows();
        assert_eq!(rows.len(), 2);
        assert_eq!((rows[0].row, rows[0].action), (ActionRow::Intent, 1));
        assert_eq!((rows[1].row, rows[1].action), (ActionRow::Outcome, 1));
        assert_eq!(rows[0].run, rows[1].run);
        assert_eq!(
            rows[1].outcome.as_ref().unwrap().result,
            ActionResult::Success
        );
        let c = j.counts();
        assert_eq!(
            (c.intents, c.outcomes, c.in_flight, c.unwritten),
            (1, 1, 0, 0)
        );
        // a batch: intents first, in order, then each outcome
        let tickets = j.intents(vec![intent_row("A", 1), intent_row("B", 2)]);
        let numbers: Vec<u64> = tickets.iter().map(super::Intent::number).collect();
        assert_eq!(numbers, [2, 3]);
        for t in tickets {
            t.finish_deferred(ActionResult::Failure, "Refused".into(), Some("why".into()));
        }
        let kinds: Vec<ActionRow> = j.rows().iter().map(|r| r.row).collect();
        use ActionRow::*;
        assert_eq!(kinds, [Intent, Outcome, Intent, Intent, Outcome, Outcome]);
    }

    /// An intent dropped unanswered (a panic in the action) answers itself
    /// as abandoned.
    #[test]
    fn an_intent_dropped_unanswered_is_signed_abandoned() {
        let j = ActionJournal::memory();
        let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _i = j.intent(intent_row("KillProcessTree", 7));
            panic!("the action panicked");
        }));
        assert!(r.is_err());
        let rows = j.rows();
        assert_eq!(rows.len(), 2);
        let o = rows[1].outcome.as_ref().unwrap();
        assert_eq!(o.result, ActionResult::Abandoned);
        assert_eq!(j.counts().abandoned, 1);
        assert_eq!(j.counts().in_flight, 0);
    }

    /// Not bound yet, or bound off: the row is logged and counted, the
    /// ticket still made (the action runs: CMB-027).
    #[test]
    fn a_row_the_journal_cannot_take_is_counted_and_the_action_runs() {
        let j = ActionJournal::late();
        let i = j.intent(intent_row("KillProcess", 9));
        assert!(!i.written());
        i.finish(ActionResult::Success, "Killed".into(), None);
        j.bind_off("no signing key");
        j.intent(intent_row("KillProcess", 10)).finish(
            ActionResult::Success,
            "Killed".into(),
            None,
        );
        let c = j.counts();
        assert_eq!((c.intents, c.outcomes, c.unwritten), (0, 0, 4));
        // the re-check of #476: the chain opened between an intent and its
        // outcome — the outcome says its intent is not in the chain
        let dir = tempfile::tempdir().unwrap();
        let active = dir.path().join("actions.jsonl");
        let j = ActionJournal::late();
        let i = j.intent(intent_row("KillProcess", 11));
        j.bind(log_at(&active, &dir.path().join("k"), u64::MAX), &active);
        i.finish(ActionResult::Success, "Killed".into(), None);
        let w = j.intent(intent_row("KillProcess", 12));
        w.finish(ActionResult::Success, "Killed".into(), None);
        let flags: Vec<bool> = read_rows(&active)
            .unwrap()
            .iter()
            .filter_map(|r| r.outcome.as_ref().map(|o| o.intent_written))
            .collect();
        assert_eq!(flags, [false, true]);
    }

    /// A row the chain refuses (its file gone, a directory in its place) is
    /// counted unwritten, logged whole — and the ticket still made: the
    /// action runs (CMB-027).
    #[test]
    fn a_row_the_chain_refuses_is_counted_unwritten() {
        let dir = tempfile::tempdir().unwrap();
        let active = dir.path().join("actions.jsonl");
        let key_path = dir.path().join("agent.sig.key");
        let log = ActionJournal::open_log(
            &active,
            crate::keys::AgentSigningKey::load_or_bootstrap(&key_path).unwrap(),
            crate::chainlog::RotationConfig {
                size_cap_bytes: u64::MAX,
                max_archives: 8,
                file_mode: 0o600,
            },
            Arc::new(crate::chainlog::NoProtection),
        )
        .unwrap();
        let j = ActionJournal::late();
        j.bind(log, &active);
        j.intent(intent_row("KillProcess", 1))
            .finish(ActionResult::Success, "Killed".into(), None);
        assert_eq!(j.counts().unwritten, 0);
        std::fs::remove_file(&active).unwrap();
        std::fs::create_dir(&active).unwrap();
        let i = j.intent(intent_row("KillProcess", 2));
        assert!(!i.written(), "the chain refused it");
        i.finish(ActionResult::Success, "Killed".into(), None);
        let c = j.counts();
        assert_eq!((c.intents, c.outcomes, c.unwritten), (1, 1, 2));
    }

    /// The start finds an earlier run's intent without its outcome in the
    /// signed chain, answers it with an interrupted row, and a third start
    /// finds nothing more to answer.
    #[test]
    fn a_crash_between_intent_and_outcome_is_reported_at_the_next_start() {
        let dir = tempfile::tempdir().unwrap();
        let active = dir.path().join("actions.jsonl");
        let key_path = dir.path().join("agent.sig.key");
        let key = || crate::keys::AgentSigningKey::load_or_bootstrap(&key_path).unwrap();
        let open = |k| {
            ActionJournal::open_log(
                &active,
                k,
                crate::chainlog::RotationConfig {
                    size_cap_bytes: u64::MAX,
                    max_archives: 8,
                    file_mode: 0o600,
                },
                Arc::new(crate::chainlog::NoProtection),
            )
            .unwrap()
        };
        // run 1: one action answered, one cut short (the process "dies":
        // the ticket is leaked, as a SIGKILL leaves it)
        let first = ActionJournal::late();
        let rec = first.bind(open(key()), &active);
        assert_eq!(rec, Recovery::default());
        first.start_run(&rec);
        first.intent(intent_row("KillProcess", 100)).finish(
            ActionResult::Success,
            "Killed".into(),
            None,
        );
        std::mem::forget(first.intent(intent_row("KillProcessTree", 200)));
        // run 2: the start finds it; the boot signs its audit row, then the
        // run's start answers it
        let second = ActionJournal::late();
        let rec = second.bind(open(key()), &active);
        assert_eq!(rec.interrupted.len(), 1, "{rec:?}");
        assert!(
            rec.interrupted[0].contains("KillProcessTree pid 200"),
            "{rec:?}"
        );
        assert_eq!(second.counts().interrupted_at_boot, 0, "not answered yet");
        second.start_run(&rec);
        assert_eq!(second.counts().interrupted_at_boot, 1);
        second.end_run();
        // run 3: nothing left unanswered
        let third = ActionJournal::late();
        assert_eq!(third.bind(open(key()), &active), Recovery::default());
        // the chain: run 1's start, intent, outcome, intent; run 2's
        // interrupted row, its start, its end
        let rows = read_rows(&active).unwrap();
        let kinds: Vec<ActionRow> = rows.iter().map(|r| r.row).collect();
        use ActionRow::*;
        assert_eq!(
            kinds,
            [
                RunStarted,
                Intent,
                Outcome,
                Intent,
                Interrupted,
                RunStarted,
                RunEnded
            ]
        );
        assert_eq!(rows[4].noted_by.as_deref(), Some(second.run()));
        assert_eq!(rows[4].run, rows[3].run);
        assert_eq!(rows[5].run, second.run());
    }

    /// R12c-3: a run that crashed before its start answered the open
    /// intents (after the boot's audit row) leaves them open — the next
    /// start finds them again; never an interrupted row without its audit
    /// row.
    #[test]
    fn a_crash_before_the_run_started_leaves_the_intents_open() {
        let dir = tempfile::tempdir().unwrap();
        let active = dir.path().join("actions.jsonl");
        let key_path = dir.path().join("k");
        let first = ActionJournal::late();
        let rec = first.bind(log_at(&active, &key_path, u64::MAX), &active);
        first.start_run(&rec);
        std::mem::forget(first.intent(intent_row("KillProcessTree", 300)));
        let second = ActionJournal::late();
        let rec = second.bind(log_at(&active, &key_path, u64::MAX), &active);
        assert_eq!(rec.interrupted.len(), 1);
        // (the second run dies here, before `start_run`)
        let third = ActionJournal::late();
        let rec = third.bind(log_at(&active, &key_path, u64::MAX), &active);
        assert_eq!(rec.interrupted.len(), 1, "still open: {rec:?}");
    }

    /// R12c-3 (the review of #476): a run that crashed with its intent
    /// more than one rotation back — the start reads back to that run's
    /// `run_started`, however many archives ago.
    #[test]
    fn an_intent_two_rotations_back_is_found_at_the_next_start() {
        let dir = tempfile::tempdir().unwrap();
        let active = dir.path().join("actions.jsonl");
        let key_path = dir.path().join("k");
        let first = ActionJournal::late();
        let rec = first.bind(log_at(&active, &key_path, 16 * 1024), &active);
        first.start_run(&rec);
        std::mem::forget(first.intent(intent_row("KillProcessTree", 400)));
        let mut pid = 2000;
        while crate::chainlog::archives_newest_first(&active).len() < 3 {
            first.intent(intent_row("KillProcess", pid)).finish(
                ActionResult::Success,
                "Killed".into(),
                None,
            );
            pid += 1;
        }
        let second = ActionJournal::late();
        let rec = second.bind(log_at(&active, &key_path, 16 * 1024), &active);
        assert_eq!(rec.interrupted.len(), 1, "{rec:?}");
        assert!(rec.interrupted[0].contains("KillProcessTree pid 400"));
        // a run that ended cleanly: its start not looked for further back
        second.start_run(&rec);
        second.end_run();
        let third = ActionJournal::late();
        assert_eq!(
            third.bind(log_at(&active, &key_path, 16 * 1024), &active),
            Recovery::default()
        );
    }

    fn log_at(active: &Path, key_path: &Path, cap: u64) -> Log {
        ActionJournal::open_log(
            active,
            crate::keys::AgentSigningKey::load_or_bootstrap(key_path).unwrap(),
            crate::chainlog::RotationConfig {
                size_cap_bytes: cap,
                max_archives: 8,
                file_mode: 0o600,
            },
            Arc::new(crate::chainlog::NoProtection),
        )
        .unwrap()
    }

    /// Review of #478 (X2): a head the chain named, rotated into an
    /// archive, is held there; the archive removed (within those the chain
    /// keeps), it is not — never "not known".
    #[test]
    fn a_head_in_a_removed_archive_is_not_held() {
        let dir = tempfile::tempdir().unwrap();
        let active = dir.path().join("actions.jsonl");
        let j = ActionJournal::late();
        j.bind(log_at(&active, &dir.path().join("k"), 16 * 1024), &active);
        j.intent(intent_row("KillProcess", 1))
            .finish(ActionResult::Success, "Killed".into(), None);
        let (file, bytes, hash) = j.head().unwrap();
        let mut pid = 10;
        while crate::chainlog::archives_newest_first(&active).is_empty() {
            j.intent(intent_row("KillProcess", pid)).finish(
                ActionResult::Success,
                "Killed".into(),
                None,
            );
            pid += 1;
        }
        assert!(j.head().unwrap().0 > file, "rotated");
        assert_eq!(j.holds(file, bytes, &hash), Some(true), "in the archive");
        let archive = crate::chainlog::archive_path_for(&active, file);
        std::fs::remove_file(&archive).unwrap();
        assert_eq!(
            j.holds(file, bytes, &hash),
            Some(false),
            "the archive removed"
        );
        // a file the chain no longer keeps (evicted, one archive kept):
        // not known
        let dir = tempfile::tempdir().unwrap();
        let active = dir.path().join("actions.jsonl");
        let j = ActionJournal::late();
        let log = ActionJournal::open_log(
            &active,
            crate::keys::AgentSigningKey::load_or_bootstrap(&dir.path().join("k")).unwrap(),
            crate::chainlog::RotationConfig {
                size_cap_bytes: 16 * 1024,
                max_archives: 1,
                file_mode: 0o600,
            },
            Arc::new(crate::chainlog::NoProtection),
        )
        .unwrap();
        j.bind(log, &active);
        j.intent(intent_row("KillProcess", 1))
            .finish(ActionResult::Success, "Killed".into(), None);
        let (file, bytes, hash) = j.head().unwrap();
        while j.head().unwrap().0 < file + 2 {
            j.intent(intent_row("KillProcess", 2)).finish(
                ActionResult::Success,
                "Killed".into(),
                None,
            );
        }
        assert_eq!(j.holds(file, bytes, &hash), None, "evicted, not removed");
    }

    /// The crash after a rotation: the intent left without its outcome is
    /// in the newest archive by the next start, which still finds it
    /// (review of #476, its mutation K2).
    #[test]
    fn an_intent_rotated_into_the_archive_is_found_at_the_next_start() {
        let dir = tempfile::tempdir().unwrap();
        let active = dir.path().join("actions.jsonl");
        let key_path = dir.path().join("agent.sig.key");
        let first = ActionJournal::late();
        first.bind(log_at(&active, &key_path, 16 * 1024), &active);
        std::mem::forget(first.intent(intent_row("KillProcessTree", 300)));
        let mut pid = 1000;
        while crate::chainlog::archives_newest_first(&active).is_empty() {
            first.intent(intent_row("KillProcess", pid)).finish(
                ActionResult::Success,
                "Killed".into(),
                None,
            );
            pid += 1;
        }
        assert!(
            !std::fs::read_to_string(&active)
                .unwrap()
                .contains("\"pid\":300"),
            "the intent is in the archive, not the active file"
        );
        let second = ActionJournal::late();
        let rec = second.bind(log_at(&active, &key_path, 16 * 1024), &active);
        assert_eq!(rec.interrupted.len(), 1, "{rec:?}");
        assert!(
            rec.interrupted[0].contains("KillProcessTree pid 300"),
            "{rec:?}"
        );
    }

    /// Review of #476: a kill's intent is written before the kill (another
    /// reader of the file sees it: a crash of the agent keeps it) and
    /// synced with its outcome; a quarantine's is synced before it.
    #[test]
    fn a_kill_s_intent_is_synced_with_its_outcome_a_quarantine_s_before_it() {
        let dir = tempfile::tempdir().unwrap();
        let active = dir.path().join("actions.jsonl");
        let j = ActionJournal::late();
        j.bind(log_at(&active, &dir.path().join("k"), u64::MAX), &active);
        let f0 = j.fsyncs();
        let kill = j.intent(intent_row("KillProcess", 1));
        assert_eq!(j.fsyncs(), f0, "not synced before the kill");
        let rows = read_rows(&active).unwrap();
        assert!(
            rows.iter()
                .any(|r| r.row == ActionRow::Intent && r.action == kill.number()),
            "written before the kill"
        );
        kill.finish(ActionResult::Success, "Killed".into(), None);
        assert_eq!(j.fsyncs(), f0 + 1, "synced with its outcome");
        let q = j.intent(intent_row("Quarantine", 2));
        assert_eq!(j.fsyncs(), f0 + 2, "synced before the quarantine");
        q.finish(ActionResult::Success, "Quarantined".into(), None);
        // a batch with one action that outlives the host: one sync for all
        let batch = j.intents(vec![
            intent_row("KillProcessTree", 3),
            intent_row("StripFileCapability", 4),
        ]);
        assert_eq!(j.fsyncs(), f0 + 4);
        for t in batch {
            t.finish_deferred(ActionResult::Success, "done".into(), None);
        }
        j.sync();
        assert_eq!(j.fsyncs(), f0 + 5);
        for r in [
            "Quarantine",
            "StripFileCapability",
            "Restore",
            "SomethingNew",
        ] {
            assert!(synced_before_action(r), "{r}");
        }
        for r in [
            "KillProcess",
            "KillProcessTree",
            "BlockOutbound",
            "ThrottleProcess",
            "FullNetworkIsolation",
            "Isolate",
            "Release",
        ] {
            assert!(!synced_before_action(r), "{r}");
        }
    }

    /// Lot 296: the state directory's protection as the agent's threads meet
    /// it — only the writer's role may lift it: here, the rotation thread.
    struct OnlyTheRotor;

    impl crate::chainlog::ProtectionManager for OnlyTheRotor {
        fn with_mutable_dir(
            &self,
            f: &mut dyn FnMut() -> anyhow::Result<()>,
        ) -> anyhow::Result<()> {
            if std::thread::current().name() != Some(ROTOR_THREAD) {
                anyhow::bail!(
                    "lifting immutability on the state directory: FS_IOC_SETFLAGS: Operation \
                     not permitted (os error 1)"
                );
            }
            f()
        }
        fn register_active(&self, _path: &Path) -> anyhow::Result<()> {
            Ok(())
        }
    }

    /// Lot 296 (lot 295's finding in the lab): the response threads may not
    /// lift the state directory, so the chain's rotation sealed its file,
    /// failed, and every later action's rows were lost (an ERROR each).
    /// Rows written by such threads past the cap are kept, the rotation
    /// thread rotates the chain, and every row is in it, verifiable.
    #[test]
    fn actions_past_the_cap_rotate_and_the_chain_stays_verifiable() {
        let dir = tempfile::tempdir().unwrap();
        let active = dir.path().join("actions.jsonl");
        let key_path = dir.path().join("k");
        let log = ActionJournal::open_log(
            &active,
            crate::keys::AgentSigningKey::load_or_bootstrap(&key_path).unwrap(),
            crate::chainlog::RotationConfig {
                size_cap_bytes: 16 * 1024,
                max_archives: 500,
                file_mode: 0o600,
            },
            Arc::new(OnlyTheRotor),
        )
        .unwrap();
        let j = ActionJournal::late();
        j.bind(log, &active);
        // a burst from response threads, past the cap several times
        let mut handles = Vec::new();
        for t in 0..4u32 {
            let j = j.clone();
            handles.push(
                std::thread::Builder::new()
                    .name(format!("nn-response-{t}"))
                    .spawn(move || {
                        for n in 0..60 {
                            j.intent(intent_row("KillProcess", 1000 * t + n)).finish(
                                ActionResult::Success,
                                "Killed".into(),
                                None,
                            );
                        }
                    })
                    .unwrap(),
            );
        }
        for h in handles {
            h.join().unwrap();
        }
        // the rotation thread's last rotation, then one more row
        let deadline = Instant::now() + std::time::Duration::from_secs(10);
        while match &*j.inner.writer.lock() {
            Writer::Log(log) => log.rotation_owed(),
            _ => false,
        } {
            assert!(
                Instant::now() < deadline,
                "the rotation thread never rotated"
            );
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        j.intent(intent_row("KillProcess", 9999)).finish(
            ActionResult::Success,
            "Killed".into(),
            None,
        );
        let counts = j.counts();
        assert_eq!(counts.unwritten, 0, "no row lost");
        assert_eq!((counts.intents, counts.outcomes), (241, 241));
        let archives = crate::chainlog::archives_newest_first(&active);
        assert!(archives.len() >= 2, "rotated: {archives:?}");
        let pk = crate::keys::AgentSigningKey::load_or_bootstrap(&key_path)
            .unwrap()
            .verifying_key();
        drop(j);
        let r = crate::chainlog::verify_log_set::<ActionRecord>(&active, &pk);
        assert!(
            r.as_ref().is_ok_and(|r| r.total_records == 2 * 241),
            "{r:?}"
        );
    }

    /// A writer for one test's log lines.
    #[derive(Clone, Default)]
    struct Captured(Arc<std::sync::Mutex<Vec<u8>>>);

    impl std::io::Write for Captured {
        fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(b);
            Ok(b.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for Captured {
        type Writer = Captured;
        fn make_writer(&'a self) -> Self::Writer {
            self.clone()
        }
    }

    /// A protection that refuses while `0` is set.
    struct Refusing(std::sync::atomic::AtomicBool);

    impl crate::chainlog::ProtectionManager for Refusing {
        fn with_mutable_dir(
            &self,
            f: &mut dyn FnMut() -> anyhow::Result<()>,
        ) -> anyhow::Result<()> {
            if self.0.load(Ordering::Relaxed) {
                anyhow::bail!("Operation not permitted (os error 1)");
            }
            f()
        }
        fn register_active(&self, _path: &Path) -> anyhow::Result<()> {
            Ok(())
        }
    }

    /// Lot 296: no line per row — a thread that may not rotate says so once
    /// (WARN), keeping its rows; a rotation the rotation thread cannot do
    /// either is said once (ERROR), and again only after one went through.
    /// Its log lines are read in a process of its own (the helper below): a
    /// test thread's subscriber misses events the other tests' threads
    /// raced it to.
    #[test]
    fn a_rotation_that_cannot_be_done_is_said_once() {
        let dir = tempfile::tempdir().unwrap();
        let st = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--ignored",
                "--exact",
                "response::journal::tests::said_once_helper",
                "--test-threads=1",
            ])
            .env("NN_JOURNAL_SAID_ONCE_DIR", dir.path())
            .stdout(std::process::Stdio::null())
            .status()
            .unwrap();
        assert!(st.success(), "the helper: {st}");
        assert!(
            dir.path().join("done").exists(),
            "the helper ran its checks"
        );
    }

    /// The body of [`a_rotation_that_cannot_be_done_is_said_once`], in a
    /// process of its own. A no-op without its variable.
    #[test]
    #[ignore = "a helper: run by a_rotation_that_cannot_be_done_is_said_once"]
    fn said_once_helper() {
        let Some(dir) = std::env::var_os("NN_JOURNAL_SAID_ONCE_DIR") else {
            return;
        };
        let dir = std::path::PathBuf::from(dir);
        let active = dir.join("actions.jsonl");
        let prot = Arc::new(Refusing(std::sync::atomic::AtomicBool::new(false)));
        let log = ActionJournal::open_log(
            &active,
            crate::keys::AgentSigningKey::load_or_bootstrap(&dir.join("k")).unwrap(),
            crate::chainlog::RotationConfig {
                size_cap_bytes: 16 * 1024,
                max_archives: 50,
                file_mode: 0o600,
            },
            prot.clone(),
        )
        .unwrap();
        // bound without its rotation thread: the test calls it
        let j = ActionJournal::late();
        *j.inner.writer.lock() = Writer::Log(Box::new(log));
        prot.0.store(true, Ordering::Relaxed);
        let lines = |f: &mut dyn FnMut()| {
            let out = Captured::default();
            let sub = tracing_subscriber::fmt()
                .with_writer(out.clone())
                .with_ansi(false)
                .finish();
            tracing::subscriber::with_default(sub, f);
            let text = String::from_utf8(out.0.lock().unwrap().clone()).unwrap();
            text
        };
        let burst = |j: &ActionJournal, from: u32| {
            for n in 0..40 {
                j.intent(intent_row("KillProcess", from + n)).finish(
                    ActionResult::Success,
                    "Killed".into(),
                    None,
                );
            }
        };
        let text = lines(&mut || burst(&j, 0));
        assert_eq!(j.counts().unwritten, 0, "rows kept past the cap");
        assert_eq!(
            text.matches("go on past the cap until").count(),
            1,
            "{text}"
        );
        assert!(!text.contains("ERROR"), "{text}");
        let text = lines(&mut || {
            for _ in 0..3 {
                rotate_owed(&j.inner);
            }
        });
        assert_eq!(
            text.matches("could not rotate on its rotation thread")
                .count(),
            1,
            "{text}"
        );
        // the rotation goes through, then cannot again: said again, once
        prot.0.store(false, Ordering::Relaxed);
        rotate_owed(&j.inner);
        assert_eq!(crate::chainlog::archives_newest_first(&active).len(), 1);
        prot.0.store(true, Ordering::Relaxed);
        let text = lines(&mut || {
            burst(&j, 100);
            rotate_owed(&j.inner);
            rotate_owed(&j.inner);
        });
        assert_eq!(
            text.matches("go on past the cap until").count(),
            1,
            "{text}"
        );
        assert_eq!(
            text.matches("could not rotate on its rotation thread")
                .count(),
            1,
            "{text}"
        );
        assert_eq!(j.counts().unwritten, 0);
        std::fs::write(dir.join("done"), b"").unwrap();
    }
}
