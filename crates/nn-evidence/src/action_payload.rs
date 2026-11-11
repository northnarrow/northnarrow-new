//! Wave 4 restructure, R12c (lab PR 270; plan §3.4): the signed record of
//! the agent's actions — the rows of the `actions` chain
//! (`/var/lib/northnarrow/detections/actions.jsonl`).
//!
//! The invariant (plan §3.4): **no action without a signed record**. Every
//! response the agent carries out on the host on its own decision — a
//! rule's response, a step of the COMBAT ladder, an exec quarantine's kill,
//! a copy-on-write restore — writes an [`ActionRow::Intent`] row before it
//! acts (on the disk: the writer syncs before the action) and an
//! [`ActionRow::Outcome`] row after, with what became of it. The two share
//! the agent run that wrote them ([`ActionRecord::run`]) and the action's
//! number in it ([`ActionRecord::action`]). An intent whose outcome never
//! came — the agent stopped, crashed or was killed in between — is found by
//! the next start and answered by an [`ActionRow::Interrupted`] row: the
//! intent without its outcome is visible, and said to be. The responses the
//! queue could not run (displaced or refused when full, or still queued at
//! the stop) are counted and named in [`ActionRow::Overflow`] rows: never
//! dropped silently.
//!
//! The record budget (review 75: the journal lines and the Log-only
//! detections of a flood) never applies to these rows.
//!
//! SCHEMA FREEZE (as `DetectionRecord`): the chain verifier re-serialises
//! decoded rows, so the field names, their order and their serialised types
//! are frozen from this first version; only additive `Option` fields with
//! `#[serde(default, skip_serializing_if = "Option::is_none")]` may be
//! added. The wire form is pinned (`action_rows_are_pinned`).

use serde::{Deserialize, Serialize};

/// The kind of an [`ActionRecord`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActionRow {
    /// Written, and synced, before the action: what is about to be done,
    /// to whom, and why.
    Intent,
    /// Written after the action: what became of it.
    Outcome,
    /// Written by a later run for an intent of an earlier one that has no
    /// outcome: the agent stopped between the two. Whether the action took
    /// effect is not known.
    Interrupted,
    /// Responses decided and never run: displaced or refused by the full
    /// queue, or still queued when the agent stopped (stage 6).
    Overflow,
    /// R12c-3: an action still running past the stall bound (its intent's
    /// `action`; `outcome.result` `unknown`, how long so far) — not an
    /// answer: its outcome row still comes when it ends.
    Stalled,
    /// R12c-3: a run's first row, once the start answered the earlier
    /// runs' open intents.
    RunStarted,
    /// R12c-3: a run's last row, at a clean stop. A run with a
    /// `run_started` and no `run_ended` crashed: the next start reads back
    /// to its `run_started` for its open intents, however many rotations
    /// ago.
    RunEnded,
}

/// What became of an action ([`ActionOutcome::result`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActionResult {
    /// Done, and verified where the action verifies (a kill: gone).
    Success,
    /// Not done: refused (a protected process), failed (an errno), the
    /// target already gone where that is a failure to contain.
    Failure,
    /// Done in part: a kill tree with a descendant left, an isolation with
    /// a family left open.
    Partial,
    /// Detect-only: approved, not enforced — the host untouched.
    WouldExecute,
    /// Not run (the action's own guard, nothing to do: the target gone
    /// before it).
    NotRun,
    /// Not known: the agent stopped between the intent and the outcome
    /// ([`ActionRow::Interrupted`]).
    Unknown,
    /// The code that held the intent ended without an outcome (a panic in
    /// the action): the action may or may not have taken effect.
    Abandoned,
}

impl ActionResult {
    pub fn as_str(self) -> &'static str {
        match self {
            ActionResult::Success => "success",
            ActionResult::Failure => "failure",
            ActionResult::Partial => "partial",
            ActionResult::WouldExecute => "would_execute",
            ActionResult::NotRun => "not_run",
            ActionResult::Unknown => "unknown",
            ActionResult::Abandoned => "abandoned",
        }
    }
}

/// What an [`ActionRow::Intent`] row says.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActionIntent {
    /// Who decided it: `rule`, `combat`, `exec_quarantine`,
    /// `copy_on_write`.
    pub source: String,
    /// The response: `KillProcessTree`, `Quarantine`, `BlockOutbound`,
    /// `Isolate`, `Release`, `Restore`, …
    pub response: String,
    /// The target process (0: host-wide, an isolation).
    pub pid: u32,
    /// The target's start (`CLOCK_MONOTONIC` ns, from its exec event; 0
    /// unknown): a pid the target no longer holds is not acted on.
    pub start_ns: u64,
    /// The file a file action acts on.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub file: Option<String>,
    /// `low` … `critical`: the decision's severity.
    pub severity: String,
    /// Why: the rules that decided it, or the ladder's stage and trigger.
    pub why: Vec<String>,
    /// The detection, bounded: the event's kind, its actor.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    /// How long the decision waited in the response queue (µs).
    pub queued_us: u64,
}

impl ActionIntent {
    /// An intent of `source` to run `response` on `pid`, the rest unknown
    /// (filled by the caller as it knows them).
    pub fn named(source: &str, response: &str, pid: u32) -> Self {
        Self {
            source: source.to_string(),
            response: response.to_string(),
            pid,
            start_ns: 0,
            file: None,
            severity: "high".to_string(),
            why: Vec::new(),
            detail: None,
            queued_us: 0,
        }
    }
}

/// What an [`ActionRow::Outcome`] (or [`ActionRow::Interrupted`]) row says.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActionOutcome {
    pub result: ActionResult,
    /// The executor's report, as text.
    pub outcome: String,
    /// Why it failed, was refused or is not known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// From the intent to the outcome (µs).
    pub elapsed_us: u64,
    /// The re-check of #476: `false` when the action's intent row is not in
    /// the chain (the journal could not take it: logged whole at ERROR and
    /// counted) — the gap named where the outcome is. Written only then.
    #[serde(default = "intent_in_chain", skip_serializing_if = "is_in_chain")]
    pub intent_written: bool,
}

fn intent_in_chain() -> bool {
    true
}

fn is_in_chain(written: &bool) -> bool {
    *written
}

/// What an [`ActionRow::Overflow`] row says: the responses decided and not
/// run since the previous such row.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActionOverflow {
    /// Displaced by a more severe response from the full queue, per
    /// severity (low, medium, high, critical).
    pub displaced: Vec<u64>,
    /// Refused by the full queue, per severity.
    pub refused: Vec<u64>,
    /// Still queued when the agent stopped.
    pub queued_at_stop: u64,
    /// The first of them, named (`KillProcessTree pid 4242 (NN-L-…)`), at
    /// most [`OVERFLOW_SAMPLES`].
    pub samples: Vec<String>,
    /// Stage 6's total since the run started.
    pub total: u64,
}

/// Responses named in an [`ActionOverflow`] row at most.
pub const OVERFLOW_SAMPLES: usize = 16;

/// One row of the `actions` chain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActionRecord {
    pub row: ActionRow,
    /// The agent run whose action it is (16 hex digits drawn at the start;
    /// for an [`ActionRow::Interrupted`] row, the run of the intent).
    pub run: String,
    /// The action's number in its run, from 1; 0 for an
    /// [`ActionRow::Overflow`] row.
    pub action: u64,
    /// Wall-clock UTC (`DetectionRecord::ts`'s format).
    pub ts: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub intent: Option<ActionIntent>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub outcome: Option<ActionOutcome>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub overflow: Option<ActionOverflow>,
    /// [`ActionRow::Interrupted`]: the run that found the intent without its
    /// outcome.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub noted_by: Option<String>,
}

/// The `actions` chain's name in its v3 pre-images.
impl crate::chainlog::ChainPayload for ActionRecord {
    const KIND: &'static str = "actions";
}

/// An intent without its outcome among `rows` (in chain order): each
/// `(run, action)` of an [`ActionRow::Intent`] row that no
/// [`ActionRow::Outcome`] or [`ActionRow::Interrupted`] row of the same
/// `(run, action)` answers, of a run other than `current` — in the order
/// the intents were written.
pub fn unanswered_intents<'a>(
    rows: impl IntoIterator<Item = &'a ActionRecord>,
    current: &str,
) -> Vec<&'a ActionRecord> {
    let mut open: Vec<&ActionRecord> = Vec::new();
    let mut answered = std::collections::HashSet::new();
    for r in rows {
        match r.row {
            ActionRow::Intent => open.push(r),
            ActionRow::Outcome | ActionRow::Interrupted => {
                answered.insert((r.run.clone(), r.action));
            }
            ActionRow::Overflow
            | ActionRow::Stalled
            | ActionRow::RunStarted
            | ActionRow::RunEnded => {}
        }
    }
    open.retain(|r| r.run != current && !answered.contains(&(r.run.clone(), r.action)));
    open
}

#[cfg(test)]
mod tests {
    use super::*;

    fn intent(run: &str, action: u64) -> ActionRecord {
        ActionRecord {
            row: ActionRow::Intent,
            run: run.into(),
            action,
            ts: "2026-10-31T23:59:00.000000Z".into(),
            intent: Some(ActionIntent {
                source: "rule".into(),
                response: "KillProcessTree".into(),
                pid: 4242,
                start_ns: 1_000_000,
                file: None,
                severity: "critical".into(),
                why: vec!["NN-L-CANARY-001".into()],
                detail: Some("CanaryTripped by cat".into()),
                queued_us: 120,
            }),
            outcome: None,
            overflow: None,
            noted_by: None,
        }
    }

    fn outcome(run: &str, action: u64, row: ActionRow) -> ActionRecord {
        ActionRecord {
            row,
            run: run.into(),
            action,
            ts: "2026-10-31T23:59:00.004000Z".into(),
            intent: None,
            outcome: Some(ActionOutcome {
                result: ActionResult::Success,
                outcome: "Killed { pid: 4242 }".into(),
                reason: None,
                elapsed_us: 4_000,
                intent_written: true,
            }),
            overflow: None,
            noted_by: None,
        }
    }

    /// The wire form of each row kind (SCHEMA FREEZE: a change here is a
    /// change of the signed bytes every reader verifies).
    #[test]
    fn action_rows_are_pinned() {
        assert_eq!(
            serde_json::to_string(&intent("00112233aabbccdd", 7)).unwrap(),
            r#"{"row":"intent","run":"00112233aabbccdd","action":7,"ts":"2026-10-31T23:59:00.000000Z","intent":{"source":"rule","response":"KillProcessTree","pid":4242,"start_ns":1000000,"severity":"critical","why":["NN-L-CANARY-001"],"detail":"CanaryTripped by cat","queued_us":120}}"#
        );
        assert_eq!(
            serde_json::to_string(&outcome("00112233aabbccdd", 7, ActionRow::Outcome)).unwrap(),
            r#"{"row":"outcome","run":"00112233aabbccdd","action":7,"ts":"2026-10-31T23:59:00.004000Z","outcome":{"result":"success","outcome":"Killed { pid: 4242 }","elapsed_us":4000}}"#
        );
        // R12c-3: a stall, a run's start and end
        let mut st = outcome("00112233aabbccdd", 9, ActionRow::Stalled);
        {
            let o = st.outcome.as_mut().unwrap();
            o.result = ActionResult::Unknown;
            o.outcome = "KillProcessTree pid 4242 (R001): still running".into();
            o.reason = Some("running for 10 s, past the stall bound".into());
            o.elapsed_us = 10_000_000;
        }
        assert_eq!(
            serde_json::to_string(&st).unwrap(),
            r#"{"row":"stalled","run":"00112233aabbccdd","action":9,"ts":"2026-10-31T23:59:00.004000Z","outcome":{"result":"unknown","outcome":"KillProcessTree pid 4242 (R001): still running","reason":"running for 10 s, past the stall bound","elapsed_us":10000000}}"#
        );
        for (row, name) in [
            (ActionRow::RunStarted, "run_started"),
            (ActionRow::RunEnded, "run_ended"),
        ] {
            let mut r = outcome("00112233aabbccdd", 0, row);
            r.outcome = None;
            assert_eq!(
                serde_json::to_string(&r).unwrap(),
                format!(
                    r#"{{"row":"{name}","run":"00112233aabbccdd","action":0,"ts":"2026-10-31T23:59:00.004000Z"}}"#
                )
            );
        }
        // a stall answers nothing; nor does a run's start or end
        let open = [
            intent("aa", 1),
            outcome("aa", 1, ActionRow::Stalled),
            outcome("aa", 0, ActionRow::RunStarted),
        ];
        assert_eq!(unanswered_intents(&open, "bb").len(), 1);
        // the re-check of #476: an outcome whose intent is not in the chain
        let mut gap = outcome("00112233aabbccdd", 9, ActionRow::Outcome);
        gap.outcome.as_mut().unwrap().intent_written = false;
        let line = serde_json::to_string(&gap).unwrap();
        assert!(
            line.ends_with(r#""elapsed_us":4000,"intent_written":false}}"#),
            "{line}"
        );
        assert_eq!(serde_json::from_str::<ActionRecord>(&line).unwrap(), gap);
        let mut i = outcome("00112233aabbccdd", 8, ActionRow::Interrupted);
        i.outcome.as_mut().unwrap().result = ActionResult::Unknown;
        i.noted_by = Some("ffeeddccbbaa9988".into());
        assert_eq!(
            serde_json::to_string(&i).unwrap(),
            r#"{"row":"interrupted","run":"00112233aabbccdd","action":8,"ts":"2026-10-31T23:59:00.004000Z","outcome":{"result":"unknown","outcome":"Killed { pid: 4242 }","elapsed_us":4000},"noted_by":"ffeeddccbbaa9988"}"#
        );
        let o = ActionRecord {
            row: ActionRow::Overflow,
            run: "00112233aabbccdd".into(),
            action: 0,
            ts: "2026-10-31T23:59:01.000000Z".into(),
            intent: None,
            outcome: None,
            overflow: Some(ActionOverflow {
                displaced: vec![2, 0, 0, 0],
                refused: vec![0, 0, 1, 0],
                queued_at_stop: 0,
                samples: vec!["BlockOutbound pid 9 (NN-L-NET-001)".into()],
                total: 3,
            }),
            noted_by: None,
        };
        assert_eq!(
            serde_json::to_string(&o).unwrap(),
            r#"{"row":"overflow","run":"00112233aabbccdd","action":0,"ts":"2026-10-31T23:59:01.000000Z","overflow":{"displaced":[2,0,0,0],"refused":[0,0,1,0],"queued_at_stop":0,"samples":["BlockOutbound pid 9 (NN-L-NET-001)"],"total":3}}"#
        );
        for r in [intent("a", 1), o, i] {
            let back: ActionRecord =
                serde_json::from_str(&serde_json::to_string(&r).unwrap()).unwrap();
            assert_eq!(back, r);
        }
        use crate::chainlog::ChainPayload;
        assert_eq!(ActionRecord::KIND, "actions");
    }

    /// Lot 298 (external bug hunt, BUG19): the interrupted row the journal
    /// writes since lot 298 carries the intent it answers — the same
    /// `intent` field as an intent row's, between `ts` and `outcome` (the
    /// form without it, an older agent's, is pinned above and still reads).
    #[test]
    fn an_interrupted_row_with_its_intent_is_pinned() {
        let mut i = outcome("00112233aabbccdd", 7, ActionRow::Interrupted);
        {
            let o = i.outcome.as_mut().unwrap();
            o.result = ActionResult::Unknown;
            o.outcome = "KillProcessTree pid 4242 (NN-L-CANARY-001): not known".into();
            o.reason = Some("the agent stopped between the action's intent and its outcome".into());
            o.elapsed_us = 0;
        }
        i.intent = intent("00112233aabbccdd", 7).intent;
        i.noted_by = Some("ffeeddccbbaa9988".into());
        let line = serde_json::to_string(&i).unwrap();
        assert_eq!(
            line,
            r#"{"row":"interrupted","run":"00112233aabbccdd","action":7,"ts":"2026-10-31T23:59:00.004000Z","intent":{"source":"rule","response":"KillProcessTree","pid":4242,"start_ns":1000000,"severity":"critical","why":["NN-L-CANARY-001"],"detail":"CanaryTripped by cat","queued_us":120},"outcome":{"result":"unknown","outcome":"KillProcessTree pid 4242 (NN-L-CANARY-001): not known","reason":"the agent stopped between the action's intent and its outcome","elapsed_us":0},"noted_by":"ffeeddccbbaa9988"}"#
        );
        assert_eq!(serde_json::from_str::<ActionRecord>(&line).unwrap(), i);
        // it answers its intent as the form without one did
        let rows = [intent("00112233aabbccdd", 7), i];
        assert!(unanswered_intents(&rows, "bb").is_empty());
    }

    /// An intent of an earlier run with neither an outcome nor an
    /// interrupted row is unanswered; this run's own intents are not (they
    /// are in flight), nor answered ones.
    #[test]
    fn an_intent_without_its_outcome_is_found() {
        let rows = [
            intent("r1", 1),
            outcome("r1", 1, ActionRow::Outcome),
            intent("r1", 2),
            intent("r1", 3),
            outcome("r1", 3, ActionRow::Interrupted),
            intent("r2", 1),
            intent("r3", 1),
        ];
        let open: Vec<(String, u64)> = unanswered_intents(&rows, "r3")
            .into_iter()
            .map(|r| (r.run.clone(), r.action))
            .collect();
        assert_eq!(open, [("r1".to_string(), 2), ("r2".to_string(), 1)]);
    }
}
