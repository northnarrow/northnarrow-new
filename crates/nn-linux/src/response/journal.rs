//! Wave 4 restructure, R12c (lab PR 270; plan §3.4): **no action without a
//! signed record** — the writer of the `actions` chain and the ticket an
//! action needs.
//!
//! An [`Intent`] is the only way to an action: the executor's acting entry
//! points ([`super::Executor::execute_on`] and the rest), the isolator's
//! engage, the outbound block's release and the exec quarantine's kill all
//! take one, and only [`ActionJournal::intent`] (or
//! [`ActionJournal::intents`]) makes one — after it has appended the signed
//! [`ActionRow::Intent`] row and synced it. [`Intent::finish`] appends the
//! [`ActionRow::Outcome`] row; an intent dropped without one (a panic in the
//! action) appends an [`ActionResult::Abandoned`] outcome itself. So no code
//! can act without the intent written first, and no intent stays without an
//! answer while the agent runs.
//!
//! When the journal cannot take a row — not open yet, its log refused at
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

use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;

use parking_lot::Mutex;
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
}

struct Inner {
    run: String,
    next: AtomicU64,
    writer: Mutex<Writer>,
    counters: Counters,
    clock: Arc<dyn Clock>,
}

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
        let rows = match read_rows(active) {
            Ok(rows) => rows,
            Err(e) => {
                recovery.unread = Some(e);
                Vec::new()
            }
        };
        let mut w = self.inner.writer.lock();
        *w = Writer::Log(Box::new(log));
        for open in unanswered_intents(&rows, &self.inner.run) {
            let what = open
                .intent
                .as_ref()
                .map(|i| format!("{} pid {} ({})", i.response, i.pid, i.why.join(", ")))
                .unwrap_or_else(|| "an action".to_string());
            let row = ActionRecord {
                row: ActionRow::Interrupted,
                run: open.run.clone(),
                action: open.action,
                ts: nn_evidence::clock::stamp(self.inner.clock.as_ref()),
                intent: None,
                outcome: Some(ActionOutcome {
                    result: ActionResult::Unknown,
                    outcome: format!("{what}: not known"),
                    reason: Some(
                        "the agent stopped between the action's intent and its outcome".to_string(),
                    ),
                    elapsed_us: 0,
                }),
                overflow: None,
                noted_by: Some(self.inner.run.clone()),
            };
            warn!(
                run = %open.run,
                action = open.action,
                what = %Escaped(&what),
                "an action of an earlier run has its intent and no outcome: the agent stopped \
                 between the two — whether it took effect is not known (signed interrupted row)"
            );
            self.inner
                .counters
                .interrupted
                .fetch_add(1, Ordering::Relaxed);
            write_row(&mut w, &self.inner.counters, row, true);
            recovery
                .interrupted
                .push(format!("run {} action {}: {what}", open.run, open.action));
        }
        recovery
    }

    /// The log could not be opened (`why`): every row from now on is logged
    /// at ERROR and counted unwritten; the actions still run.
    pub fn bind_off(&self, why: &str) {
        *self.inner.writer.lock() = Writer::Off(why.to_string());
    }

    /// The intent of one action, written and synced: the ticket the action
    /// needs.
    pub fn intent(&self, intent: ActionIntent) -> Intent {
        self.intents(vec![intent])
            .pop()
            .expect("one intent for one row")
    }

    /// The intents of several actions, written with one sync (the
    /// dispatcher's batch): the tickets, in order.
    pub fn intents(&self, intents: Vec<ActionIntent>) -> Vec<Intent> {
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
            let written = write_row(&mut w, &self.inner.counters, row, false);
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
        sync(&mut w, &self.inner.counters);
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
        if write_row(&mut w, &self.inner.counters, row, true) {
            self.inner
                .counters
                .overflow_rows
                .fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Sync the outcomes [`Intent::finish_deferred`] wrote.
    pub fn sync(&self) {
        sync(&mut self.inner.writer.lock(), &self.inner.counters);
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
        if write_row(&mut w, &self.inner.counters, row, durable) {
            self.inner.counters.outcomes.fetch_add(1, Ordering::Relaxed);
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

/// Append `row`; `durable`: synced before this returns. A row the writer
/// cannot take is logged whole at ERROR and counted. Returns whether it is
/// in the chain (or the memory journal).
fn write_row(w: &mut Writer, counters: &Counters, row: ActionRecord, durable: bool) -> bool {
    let why = match w {
        Writer::Memory(rows) => {
            rows.push(row);
            return true;
        }
        Writer::Log(log) => {
            let res = if durable {
                log.append(row.clone())
            } else {
                log.append_deferred(row.clone())
            };
            match res {
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

fn sync(w: &mut Writer, counters: &Counters) {
    if let Writer::Log(log) = w {
        if let Err(e) = log.sync() {
            counters.unwritten.fetch_add(1, Ordering::Relaxed);
            error!(
                target: "response.journal",
                error = %format!("{e:#}"),
                "the actions chain's sync failed — its last rows may not be on the disk"
            );
        }
    }
}

/// The rows of the chain's newest archive and active file, in chain order
/// (each file's last [`SCAN_BYTES`]). Decoded only: the chain's own checks
/// (the boot check, `nn-admin chain verify`) prove them; the scan only
/// pairs intents with their answers.
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
        assert_eq!(first.bind(open(key()), &active), Recovery::default());
        first.intent(intent_row("KillProcess", 100)).finish(
            ActionResult::Success,
            "Killed".into(),
            None,
        );
        std::mem::forget(first.intent(intent_row("KillProcessTree", 200)));
        // run 2: the start answers it
        let second = ActionJournal::late();
        let rec = second.bind(open(key()), &active);
        assert_eq!(rec.interrupted.len(), 1, "{rec:?}");
        assert!(
            rec.interrupted[0].contains("KillProcessTree pid 200"),
            "{rec:?}"
        );
        assert_eq!(second.counts().interrupted_at_boot, 1);
        // run 3: nothing left unanswered
        let third = ActionJournal::late();
        assert_eq!(third.bind(open(key()), &active), Recovery::default());
        // the chain holds intent, outcome, intent, interrupted (+ run 2's
        // own rows: none)
        let rows = read_rows(&active).unwrap();
        let kinds: Vec<ActionRow> = rows.iter().map(|r| r.row).collect();
        use ActionRow::*;
        assert_eq!(kinds, [Intent, Outcome, Intent, Interrupted]);
        assert_eq!(rows[3].noted_by.as_deref(), Some(second.run()));
        assert_eq!(rows[3].run, rows[2].run);
    }
}
