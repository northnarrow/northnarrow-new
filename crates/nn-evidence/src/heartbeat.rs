//! Wave 4 restructure, R12c-2 (lab PR 270; report 06 INI-14, R2-12): the
//! agent's signed heartbeat, and the minimal external verifier's checks.
//!
//! **The beat.** Every interval the agent appends a [`HeartbeatRecord`] to
//! its `heartbeat` chain (`/var/lib/northnarrow/heartbeat.jsonl`, a rotating
//! signed chain: each line chained to the one before by its hash and signed
//! with the agent's key, KIND `heartbeat`). A beat is numbered (`seq`,
//! continuing across the agent's restarts), stamped (`ts`), and carries what
//! a reader off the host needs to see the agent alive and whole: the loss
//! counters of every stage of an event's path (1 to 7), the actions chain's
//! counts (intents, outcomes, rows not written, intents found interrupted),
//! the telemetry probe's gaps, the decision thread's progress, the posture,
//! the degradations, and the heads of the audit and actions chains (the
//! commitment of the head, INI-14: a chain rolled back on the host shows as a
//! head going back). A `start` beat opens each run, a `stop` beat closes a
//! clean stop with its reason.
//!
//! **The verifier** ([`check`]) is the pure half of `nn-admin heartbeat
//! watch`, run on ANOTHER host — independent of any backend: it reads the
//! newest lines of the chain (fetched by a command of the operator's, an
//! SSH pull through a forced command, or read from an exported file),
//! verifies each line's hash and signature with the agent's public key, the
//! chain's links and the beats' numbers, and compares with what it saw last
//! ([`WatchState`]). It alerts ([`Alert`]) when the host is silent (no
//! newer beat within `max_silence`), a line is not genuine (tampered), the
//! chain breaks or beats are missing, an older beat comes back (replay) or a
//! head goes back (rollback), the counters show loss, the agent stopped, or
//! its health degraded. The signature proves who wrote a beat; only its
//! *absence* in time is the signal against a root attacker on the host (who
//! holds the key), which is why the verifier runs elsewhere.
//!
//! SCHEMA FREEZE (as the other chains' payloads): field names, order and
//! types are frozen from this version; only additive `Option` fields.

use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use ed25519_dalek::VerifyingKey;
use serde::{Deserialize, Serialize};

/// What kind of beat.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BeatKind {
    /// The first beat of a run.
    Start,
    /// A periodic beat.
    Beat,
    /// A clean stop's last beat (`stop_reason`).
    Stop,
}

/// The actions chain's counts in a beat (R12c-1).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct BeatActions {
    pub intents: u64,
    pub outcomes: u64,
    /// Rows the chain could not take (logged at ERROR instead).
    pub unwritten: u64,
    /// Intents of an earlier run found without an outcome at the start.
    pub interrupted_at_boot: u64,
    pub in_flight: u64,
}

/// A chain's head at the beat: its row number (when the chain numbers its
/// rows: the audit log), or its position (a rotating chain: the actions
/// chain — review of #476), and its last entry hash.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct BeatHead {
    pub chain: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub seq: Option<u64>,
    /// A rotating chain's position: the number its active file will have
    /// as an archive, and the bytes in that file (`RotatingChainLog::
    /// position`). Together they only grow: a tail cut from the chain, or
    /// a rotation undone, shows as a position that went back.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub file: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bytes: Option<u64>,
    pub hash: String,
    /// Whether the chain still holds the head the agent's previous beat
    /// named (a rotating chain: the agent reads it back at each beat, and
    /// at the start from the last run's last beat). `false`: its tail was
    /// cut or rewritten since — even if rows appended after it carried the
    /// position past the one a verifier saw.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kept: Option<bool>,
}

impl BeatHead {
    /// Whether this head is behind `seen` (the same chain's, an earlier
    /// beat's): a lower row number or position, or the same with another
    /// hash — the chain rolled back or rewritten on the host.
    pub fn went_back(&self, seen: &BeatHead) -> bool {
        match (seen.seq, self.seq) {
            (Some(a), Some(b)) => return b < a || (b == a && self.hash != seen.hash),
            (Some(_), None) | (None, Some(_)) => return false,
            (None, None) => {}
        }
        match (seen.file.zip(seen.bytes), self.file.zip(self.bytes)) {
            (Some(a), Some(b)) => b < a || (b == a && self.hash != seen.hash),
            _ => false,
        }
    }

    /// Where it is, for a message.
    fn at(&self) -> String {
        match (self.seq, self.file, self.bytes) {
            (Some(s), _, _) => format!("row {s}"),
            (None, Some(f), Some(b)) => format!("file {f} at byte {b}"),
            _ => "-".to_string(),
        }
    }
}

/// One beat of the `heartbeat` chain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HeartbeatRecord {
    pub kind: BeatKind,
    /// The beat's number, from 1, continuing across the agent's runs.
    pub seq: u64,
    /// Wall clock UTC (the chains' format).
    pub ts: String,
    /// The agent's id (hex), its run (the actions chain's), the kernel's
    /// boot id.
    pub agent_id: String,
    pub run: String,
    pub boot_id: String,
    /// Since the agent started (ms).
    pub uptime_ms: u64,
    /// The beats' period (s): the verifier's freshness bound.
    pub interval_secs: u64,
    pub version: String,
    /// `observing` … `combat`; the ladder's stage; the trust level.
    pub posture: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub combat_stage: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trust_level: Option<String>,
    /// The degradations signed this run (at most [`MAX_DEGRADATIONS`]).
    pub degradations: Vec<String>,
    /// The decision thread's rounds, and the age of its last (ms): a count
    /// that stands still is a decision that does.
    pub decision_rounds: u64,
    pub decision_since_last_ms: u64,
    /// The events lost at each stage of their path since the run started,
    /// stages 1 to 7 (`None`: not counted on this agent).
    pub loss: Vec<Option<u64>>,
    pub actions: BeatActions,
    /// The telemetry probe's gaps since the run started (`None`: off).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub probe_gaps: Option<u64>,
    /// The audit and actions chains' heads.
    pub heads: Vec<BeatHead>,
    /// A `stop` beat's reason.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stop_reason: Option<String>,
    /// R13 (lab PR 271): the signed capability manifest's newest revision
    /// (`None`: an agent older than R13, or before its boot signed it).
    /// Not `manifest`: a chain line's top-level key of its rotation
    /// records, reserved by the chain log.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capabilities: Option<BeatManifest>,
    /// Lot 275 (the second review of #495, R2): NN-L-NET-028's judgements
    /// this run, by outcome and, the unknown ones, by reason (`None`: an
    /// agent older than lot 275, or one with no DNS response table).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nodns: Option<BeatNoDns>,
}

/// NN-L-NET-028's judgements since the run started: a rule blinded for
/// every process (`unknown.degraded`, `unknown.barrier`) shows in the beat,
/// as do its `nodns_coverage_lost` rows queued to be signed
/// (`coverage_lost`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct BeatNoDns {
    pub lineage: u64,
    pub other_lineage: u64,
    pub unresolved: u64,
    pub unknown: BeatNoDnsUnknown,
    /// `nodns_coverage_lost` rows queued to be signed (at most one a cause
    /// a window; the final check of #495, N4: queued, not appended — an
    /// `append` that fails is the agent's warning).
    pub coverage_lost: u64,
}

/// The unknown judgements by reason.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct BeatNoDnsUnknown {
    /// The evidence lost for every process (undecoded, a user's held
    /// records, DNS losses).
    pub degraded: u64,
    /// The lineage's own records held back.
    pub held: u64,
    /// A name asked whose response was never seen whole.
    pub unseen: u64,
    /// A binding of a process whose start is not known.
    pub start: u64,
    /// The DNS pumps had not caught up.
    pub barrier: u64,
    /// The DNS response sensor does not run.
    pub sensor: u64,
    /// The process predates the sensor.
    pub older: u64,
}

/// R13 (lab PR 271): what a beat carries of the capability manifest — the
/// hash of what the agent runs with (`CapabilityManifest::content_hash`),
/// the revision it is (0: the boot's), and whether the telemetry probe has
/// had its word on every probed source (`settled`: before its first round
/// the manifest says "pending", a hash a verifier does not compare).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BeatManifest {
    pub hash: String,
    pub revision: u64,
    pub settled: bool,
    /// The hash of the contract's terms, the agent's version and the
    /// kernel's release (the review of #479): a change of it alone is an
    /// upgrade, a NOTICE of the verifier's, not an alert — when nothing
    /// went backwards (the re-check of #479).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub contract: Option<String>,
    /// The contract's version and the kernel's release it was hashed with
    /// (the re-check of #479: the verifier checks that they, and the beat's
    /// agent `version`, do not go backwards).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub contract_version: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kernel: Option<String>,
}

/// The versions a run's contract was hashed with, as the verifier last saw
/// them (the re-check of #479).
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct ContractSeen {
    pub agent: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub contract_version: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kernel: Option<String>,
}

/// The order of two releases (an agent's version, a kernel's release):
/// compared part by part (split at `.`, `-`, `+`, `~`, `_`), numbers as
/// numbers; `None` when they differ in a part that is not a number on both
/// sides (a kernel's flavour, a pre-release tag), or one has more parts
/// and they are not all numbers — not known to be a step forward.
pub fn release_order(a: &str, b: &str) -> Option<std::cmp::Ordering> {
    use std::cmp::Ordering;
    let parts = |s: &str| -> Vec<String> {
        s.split(['.', '-', '+', '~', '_'])
            .map(str::to_string)
            .collect()
    };
    let (pa, pb) = (parts(a), parts(b));
    for (x, y) in pa.iter().zip(pb.iter()) {
        match (x.parse::<u64>(), y.parse::<u64>()) {
            (Ok(m), Ok(n)) if m != n => return Some(m.cmp(&n)),
            (Ok(_), Ok(_)) => {}
            _ if x != y => return None,
            _ => {}
        }
    }
    let rest = |p: &[String]| p.iter().all(|x| x.parse::<u64>().is_ok());
    match pa.len().cmp(&pb.len()) {
        Ordering::Equal => Some(Ordering::Equal),
        Ordering::Greater if rest(&pa[pb.len()..]) => Some(Ordering::Greater),
        Ordering::Less if rest(&pb[pa.len()..]) => Some(Ordering::Less),
        _ => None,
    }
}

/// What went backwards (or is not known to have gone forward) from
/// `before` to `now`: one phrase each, empty when every one advanced or
/// stayed (the re-check of #479).
pub fn contract_backwards(before: &ContractSeen, now: &ContractSeen) -> Vec<String> {
    let mut out = Vec::new();
    let mut release = |what: &str, a: &str, b: &str| match release_order(b, a) {
        Some(std::cmp::Ordering::Less) => out.push(format!("{what} {a} → {b} (older)")),
        None => out.push(format!("{what} {a} → {b} (not known to be newer)")),
        Some(_) => {}
    };
    release("agent", &before.agent, &now.agent);
    if let Some(k) = &before.kernel {
        release("kernel", k, now.kernel.as_deref().unwrap_or("(not said)"));
    }
    if let Some(v) = before.contract_version {
        match now.contract_version {
            Some(w) if w >= v => {}
            Some(w) => out.push(format!("contract version {v} → {w} (older)")),
            None => out.push(format!("contract version {v} → (not said)")),
        }
    }
    out
}

/// A run's manifest not settled this long after its start is DEGRADED: the
/// probe's first round ends 25 s after the start at most
/// (`FIRST_ROUND_SECS` + `DEADLINE_SECS`); two minutes leave room for a
/// round skipped.
pub const MANIFEST_SETTLE_SECS: u64 = 120;

/// Degradations named in a beat at most.
pub const MAX_DEGRADATIONS: usize = 16;

/// The `heartbeat` chain's name in its v3 pre-images.
impl crate::chainlog::ChainPayload for HeartbeatRecord {
    const KIND: &'static str = "heartbeat";
}

/// The names of the stages a beat's `loss` counts (index 0: stage 1).
pub const STAGE_NAMES: [&str; 7] = [
    "kernel ring",
    "kernel budget",
    "decode",
    "bus queue",
    "decision delay",
    "response queue",
    "evidence writer queue",
];

/// What the verifier remembers of the last beat it verified.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WatchState {
    pub seq: u64,
    pub entry_hash: String,
    pub ts: String,
    pub run: String,
    pub boot_id: String,
    pub interval_secs: u64,
    pub loss: Vec<Option<u64>>,
    pub actions: BeatActions,
    pub probe_gaps: Option<u64>,
    pub degradations: Vec<String>,
    /// The chains' heads, by chain.
    pub heads: BTreeMap<String, BeatHead>,
    /// The last beat was a stop.
    pub stopped: bool,
    /// Review of #478 (X1): when the verifier first saw that beat — on the
    /// verifier's clock: the freshness bound is measured from it, never
    /// from the host's clock — and the beat's own `uptime_ms` (lateness
    /// within a run, on the agent's monotonic clock).
    #[serde(default)]
    pub seen_at: String,
    #[serde(default)]
    pub uptime_ms: u64,
    /// R13 (lab PR 271): the hash of the last settled capability manifest
    /// seen (across runs: a change at a restart is a change), its revision
    /// and its run.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub manifest_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub manifest_revision: Option<u64>,
    /// The run whose beat carried it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub manifest_run: Option<String>,
    /// The contract's hash last seen (the review of #479).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub manifest_contract: Option<String>,
    /// The versions it was hashed with (the re-check of #479).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub manifest_versions: Option<ContractSeen>,
}

/// One alert, by kind (the most severe first in [`Alert::rank`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Alert {
    /// A line is not genuine: its hash or signature does not verify, or it
    /// does not decode (a beat altered, or written with another key).
    Tampered(String),
    /// An older beat than one already seen, a fork of one, or a chain's
    /// head that went back (a rollback on the host, a replayed export).
    Replay(String),
    /// The chain does not link, or beats are missing.
    Broken(String),
    /// No newer beat within `max_silence` (the host, the agent or the
    /// channel silent), or the source could not be read past it.
    Silent(String),
    /// The agent stopped (its signed stop beat).
    Stopped(String),
    /// The counters show loss since the last beat seen.
    Loss(String),
    /// The agent's health degraded (a stalled decision, a probe gap, a new
    /// degradation, an action row not written, an interrupted action, R13:
    /// its capability manifest changed or did not settle).
    Degraded(String),
}

impl Alert {
    /// The alert's word in the verifier's output.
    pub fn kind(&self) -> &'static str {
        match self {
            Alert::Tampered(_) => "TAMPERED",
            Alert::Replay(_) => "REPLAY",
            Alert::Broken(_) => "BROKEN",
            Alert::Silent(_) => "SILENT",
            Alert::Stopped(_) => "STOPPED",
            Alert::Loss(_) => "LOSS",
            Alert::Degraded(_) => "DEGRADED",
        }
    }

    pub fn detail(&self) -> &str {
        match self {
            Alert::Tampered(d)
            | Alert::Replay(d)
            | Alert::Broken(d)
            | Alert::Silent(d)
            | Alert::Stopped(d)
            | Alert::Loss(d)
            | Alert::Degraded(d) => d,
        }
    }

    /// The verifier's exit code for it (the most severe alert's wins).
    pub fn exit_code(&self) -> i32 {
        match self {
            Alert::Tampered(_) => 13,
            Alert::Replay(_) => 12,
            Alert::Broken(_) => 11,
            Alert::Silent(_) => 10,
            Alert::Stopped(_) => 15,
            Alert::Loss(_) => 14,
            Alert::Degraded(_) => 16,
        }
    }

    /// Severity order: lower first.
    pub fn rank(&self) -> u8 {
        match self {
            Alert::Tampered(_) => 0,
            Alert::Replay(_) => 1,
            Alert::Broken(_) => 2,
            Alert::Silent(_) => 3,
            Alert::Stopped(_) => 4,
            Alert::Loss(_) => 5,
            Alert::Degraded(_) => 6,
        }
    }
}

/// A beat this much later than its interval after the one before it (in
/// one run) is late: the agent stood still (DEGRADED).
pub const LATE_BEAT_SLACK_SECS: u64 = 15;

/// The verifier's bounds.
#[derive(Debug, Clone, Copy)]
pub struct WatchConfig {
    /// No newer beat for this long is silence. `None`: two of the beats'
    /// intervals plus 15 s (report 06, K-09: within two intervals).
    pub max_silence_secs: Option<u64>,
    /// A beat stamped this far in the future is not believed.
    pub max_skew_secs: u64,
    /// A decision whose last round is this many intervals old is stalled.
    pub stall_intervals: u64,
}

impl Default for WatchConfig {
    fn default() -> Self {
        Self {
            max_silence_secs: None,
            max_skew_secs: 30,
            stall_intervals: 2,
        }
    }
}

/// What one check found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckResult {
    pub alerts: Vec<Alert>,
    /// The newest verified beat (the state to keep), when one verified.
    pub state: Option<WatchState>,
    /// Beats new since the last check, verified.
    pub new_beats: u64,
    /// The newest beat's age (s) at the check, when one verified.
    pub age_secs: Option<i64>,
    /// No state before: the newest beat is the anchor.
    pub anchored: bool,
    /// What is worth saying and is no alert (the review of #479: the sensor
    /// contract changed — an upgrade, a new kernel).
    pub notices: Vec<String>,
}

impl CheckResult {
    /// The exit code of a one-shot check: the most severe alert's, 0 none.
    pub fn exit_code(&self) -> i32 {
        self.alerts
            .iter()
            .min_by_key(|a| a.rank())
            .map_or(0, Alert::exit_code)
    }
}

/// A line of the chain as the verifier reads it.
struct Line {
    prev_hash: String,
    entry_hash: String,
    beat: Option<HeartbeatRecord>,
}

fn parse_ts(ts: &str) -> Option<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(ts)
        .ok()
        .map(|d| d.with_timezone(&Utc))
}

/// The beats' silence bound for `interval_secs`.
pub fn silence_bound(cfg: &WatchConfig, interval_secs: u64) -> u64 {
    cfg.max_silence_secs
        .unwrap_or(2 * interval_secs.max(1) + 15)
}

/// Check the newest lines of the chain (`lines`, in chain order, as fetched;
/// `None`: the source could not be read, `why`) against `last` at `now`.
pub fn check(
    lines: Result<&[Vec<u8>], &str>,
    pk: &VerifyingKey,
    last: Option<&WatchState>,
    now: DateTime<Utc>,
    cfg: &WatchConfig,
) -> CheckResult {
    let mut out = CheckResult {
        alerts: Vec::new(),
        state: last.cloned(),
        new_beats: 0,
        age_secs: None,
        anchored: false,
        notices: Vec::new(),
    };
    let silent_if_old = |out: &mut CheckResult, why: &str| {
        if let Some(l) = last {
            let bound = silence_bound(cfg, l.interval_secs);
            if let Some(t) = parse_ts(&l.seen_at).or_else(|| parse_ts(&l.ts)) {
                let age = (now - t).num_seconds();
                out.age_secs = Some(age);
                if age > bound as i64 {
                    out.alerts.push(Alert::Silent(format!(
                        "no beat newer than seq {} for {age} s (bound {bound} s){why}",
                        l.seq
                    )));
                }
            }
        } else {
            out.alerts
                .push(Alert::Silent(format!("no beat ever verified{why}")));
        }
    };
    let raw = match lines {
        Ok(l) => l,
        Err(why) => {
            silent_if_old(&mut out, &format!("; the source: {why}"));
            return out;
        }
    };
    // every line genuine, decoded
    let mut parsed: Vec<Line> = Vec::new();
    for (i, l) in raw.iter().enumerate() {
        let l = trim(l);
        if l.is_empty() {
            continue;
        }
        if !crate::chainlog::line_is_genuine::<HeartbeatRecord>(l, pk) {
            out.alerts.push(Alert::Tampered(format!(
                "line {} of the fetched tail does not verify with the agent's key (altered, \
                 or not this agent's)",
                i + 1
            )));
            continue;
        }
        let v: serde_json::Value = match serde_json::from_slice(l) {
            Ok(v) => v,
            Err(_) => continue,
        };
        let s = |k: &str| v.get(k).and_then(|x| x.as_str()).unwrap_or("").to_string();
        let beat = if v.get("rotate").is_some() {
            None
        } else {
            serde_json::from_value::<crate::chainlog::ChainLine<HeartbeatRecord>>(v.clone())
                .ok()
                .map(|c| c.payload)
        };
        parsed.push(Line {
            prev_hash: s("prev_hash"),
            entry_hash: s("entry_hash"),
            beat,
        });
    }
    if !out.alerts.is_empty() {
        // a tampered tail is not believed for anything else
        return out;
    }
    // the chain's links in what was fetched
    for w in parsed.windows(2) {
        if w[1].prev_hash != w[0].entry_hash {
            out.alerts.push(Alert::Broken(format!(
                "the chain does not link: a line names {} as the one before, the line before \
                 is {}",
                short(&w[1].prev_hash),
                short(&w[0].entry_hash)
            )));
            return out;
        }
    }
    let beats: Vec<(usize, &HeartbeatRecord)> = parsed
        .iter()
        .enumerate()
        .filter_map(|(i, l)| l.beat.as_ref().map(|b| (i, b)))
        .collect();
    let Some(&(newest_i, newest)) = beats.last() else {
        silent_if_old(&mut out, "; the source holds no beat");
        return out;
    };
    for w in beats.windows(2) {
        if w[1].1.seq != w[0].1.seq + 1 {
            out.alerts.push(Alert::Broken(format!(
                "beats missing: seq {} follows seq {}",
                w[1].1.seq, w[0].1.seq
            )));
            return out;
        }
    }
    // Review of #478 (X1): the host's clock orders nothing and alerts
    // nothing grave — the beats are ordered by their numbers and links; a
    // time that goes back or runs ahead of the verifier's is DEGRADED.
    let mut clock = Vec::new();
    let newest_ts = parse_ts(&newest.ts);
    match newest_ts {
        None => clock.push(format!("beat {} has no readable time", newest.seq)),
        Some(t) if (t - now).num_seconds() > cfg.max_skew_secs as i64 => clock.push(format!(
            "the agent's clock is {} s ahead of the verifier's (beat {}; bound {} s)",
            (t - now).num_seconds(),
            newest.seq,
            cfg.max_skew_secs
        )),
        Some(_) => {}
    }
    // against what was seen last
    if let Some(l) = last {
        if newest.seq < l.seq {
            out.alerts.push(Alert::Replay(format!(
                "the newest beat fetched is seq {}, older than seq {} already seen (a replay or \
                 a rollback of the chain)",
                newest.seq, l.seq
            )));
            return out;
        }
        if let (Some(lt), Some(nt)) = (parse_ts(&l.ts), newest_ts) {
            if nt < lt && newest.seq > l.seq {
                clock.push(format!(
                    "the agent's clock went back: beat {} is stamped {} s before beat {} seen \
                     (its numbers and links in order)",
                    newest.seq,
                    (lt - nt).num_seconds(),
                    l.seq
                ));
            }
        }
        // the beat seen last must be in what was fetched (or just before it)
        match beats.iter().find(|(_, b)| b.seq == l.seq) {
            Some(&(i, b)) => {
                if parsed[i].entry_hash != l.entry_hash {
                    out.alerts.push(Alert::Replay(format!(
                        "beat {} is not the one seen before (a fork of the chain)",
                        b.seq
                    )));
                    return out;
                }
            }
            None => {
                let first = beats[0];
                if first.1.seq == l.seq + 1 {
                    // the first fetched follows it: it must link to it (or
                    // through a terminator line that does)
                    let links = parsed[..=first.0]
                        .iter()
                        .any(|p| p.prev_hash == l.entry_hash);
                    if !links {
                        out.alerts.push(Alert::Broken(format!(
                            "beat {} does not link to beat {} seen before",
                            first.1.seq, l.seq
                        )));
                        return out;
                    }
                } else if first.1.seq > l.seq + 1 {
                    out.alerts.push(Alert::Broken(format!(
                        "beats missing between seq {} seen before and seq {} fetched (fetch \
                         more, or beats were removed)",
                        l.seq, first.1.seq
                    )));
                    return out;
                }
            }
        }
        for (chain, seen) in &l.heads {
            let Some(h) = newest.heads.iter().find(|h| &h.chain == chain) else {
                // a chain whose head was in the beats is gone from them: the
                // agent could not open it (cut, removed, its key refused)
                out.alerts.push(Alert::Replay(format!(
                    "the {chain} chain's head, {} {} seen, is not in the beat any more (the \
                     chain not open on the host: cut, removed, or refused)",
                    seen.at(),
                    short(&seen.hash)
                )));
                continue;
            };
            if h.kept == Some(false) {
                out.alerts.push(Alert::Replay(format!(
                    "the {chain} chain no longer holds the head the agent's previous beat named \
                     (its tail cut or rewritten on the host), now {} {}",
                    h.at(),
                    short(&h.hash)
                )));
            } else if h.went_back(seen) {
                out.alerts.push(Alert::Replay(format!(
                    "the {chain} chain's head went back: {} {} seen, now {} {} (a tail cut \
                     from the chain, or the chain rolled back, on the host)",
                    seen.at(),
                    short(&seen.hash),
                    h.at(),
                    short(&h.hash)
                )));
            }
        }
    } else {
        out.anchored = true;
    }
    out.new_beats = match last {
        Some(l) => newest.seq.saturating_sub(l.seq),
        None => 1,
    };
    // freshness on the verifier's clock: since it first saw the newest beat
    let seen_at = match last {
        Some(l) if newest.seq == l.seq => parse_ts(&l.seen_at).unwrap_or(now),
        _ => now,
    };
    let age = (now - seen_at).num_seconds();
    out.age_secs = Some(age);
    let bound = silence_bound(cfg, newest.interval_secs);
    if newest.kind == BeatKind::Stop {
        if last.is_none_or(|l| !(l.stopped && l.seq == newest.seq)) {
            out.alerts.push(Alert::Stopped(format!(
                "the agent stopped (seq {}, {}): {}",
                newest.seq,
                newest.ts,
                newest.stop_reason.as_deref().unwrap_or("no reason given")
            )));
        } else {
            out.alerts.push(Alert::Stopped(format!(
                "the agent is stopped since seq {} ({})",
                newest.seq, newest.ts
            )));
        }
    } else if age > bound as i64 {
        out.alerts.push(Alert::Silent(format!(
            "the newest beat (seq {}) is {age} s old (bound {bound} s)",
            newest.seq
        )));
    }
    // loss and health against the beat seen last, when it is of the same
    // run (its counters are the run's since it started); a new run's start
    // from zero. The first check only anchors: what the run counted before
    // it is not an alert of this verifier's.
    let (prev_loss, prev_actions, prev_gaps, prev_deg): (
        Vec<Option<u64>>,
        BeatActions,
        Option<u64>,
        Vec<String>,
    ) = match last {
        None => (
            newest.loss.clone(),
            newest.actions.clone(),
            newest.probe_gaps,
            newest.degradations.clone(),
        ),
        Some(l) if l.run == newest.run => (
            l.loss.clone(),
            l.actions.clone(),
            l.probe_gaps,
            l.degradations.clone(),
        ),
        Some(_) => (
            vec![Some(0); 7],
            BeatActions::default(),
            Some(0),
            Vec::new(),
        ),
    };
    let mut lost = Vec::new();
    for (i, n) in newest.loss.iter().enumerate() {
        let before = prev_loss.get(i).copied().flatten().unwrap_or(0);
        if let Some(n) = n {
            if *n > before {
                lost.push(format!(
                    "stage {} ({}) +{}",
                    i + 1,
                    STAGE_NAMES.get(i).copied().unwrap_or("?"),
                    n - before
                ));
            }
        }
    }
    if !lost.is_empty() {
        out.alerts.push(Alert::Loss(format!(
            "events lost since the last beat seen: {}",
            lost.join(", ")
        )));
    }
    let mut degraded = Vec::new();
    // A beat late after the one before it, in one run: the agent stood
    // still for a while — frozen, or starved — though less than the
    // silence bound (the lab's `systemctl freeze`, ended by the watchdog
    // after ~70 s: no SILENT at 75 s, only this).
    // A new run whose start beat follows a beat that was not a stop: the
    // last run ended without its stop beat — the agent was killed, crashed,
    // or was frozen and restarted by the watchdog — however quickly it came
    // back (the lab's freeze: restarted after ~70 s, under the silence
    // bound).
    if let Some(l) = last {
        // (seq, uptime, a stop, its run): lateness on the agent's monotonic
        // clock (review of #478: never its wall clock)
        let mut prev = (l.seq, l.uptime_ms, l.stopped, l.run.as_str());
        for (_, b) in beats.iter().filter(|(_, b)| b.seq > l.seq) {
            let (ps, pu, stopped, prun) = prev;
            if b.seq == ps + 1 && b.kind == BeatKind::Start && !stopped {
                degraded.push(format!(
                    "the agent restarted without a clean stop: run {} began after beat {ps}, \
                     with no stop beat between (killed, crashed, or frozen and restarted)",
                    b.run
                ));
            } else if b.seq == ps + 1
                && b.kind != BeatKind::Start
                && b.run == prun
                && pu != 0
                && b.uptime_ms.saturating_sub(pu) > (b.interval_secs + LATE_BEAT_SLACK_SECS) * 1000
            {
                degraded.push(format!(
                    "beat {} came {} s after beat {ps} (every {} s, the agent's uptime): the \
                     agent stood still — frozen, or starved",
                    b.seq,
                    b.uptime_ms.saturating_sub(pu) / 1000,
                    b.interval_secs
                ));
            }
            prev = (b.seq, b.uptime_ms, b.kind == BeatKind::Stop, b.run.as_str());
        }
    }
    degraded.extend(clock);
    if newest.kind != BeatKind::Stop
        && newest.decision_since_last_ms > cfg.stall_intervals * newest.interval_secs * 1000
    {
        degraded.push(format!(
            "the decision thread's last round is {} ms old",
            newest.decision_since_last_ms
        ));
    }
    if let (Some(n), b) = (newest.probe_gaps, prev_gaps.unwrap_or(0)) {
        if n > b {
            degraded.push(format!("{} new telemetry gap(s) of the probe", n - b));
        }
    }
    if newest.actions.unwritten > prev_actions.unwritten {
        degraded.push(format!(
            "{} action row(s) not in the signed actions chain",
            newest.actions.unwritten - prev_actions.unwritten
        ));
    }
    if newest.actions.interrupted_at_boot > prev_actions.interrupted_at_boot {
        degraded.push(format!(
            "{} action(s) of an earlier run interrupted between intent and outcome",
            newest.actions.interrupted_at_boot - prev_actions.interrupted_at_boot
        ));
    }
    let new_deg: Vec<&String> = newest
        .degradations
        .iter()
        .filter(|d| !prev_deg.contains(d))
        .collect();
    if !new_deg.is_empty() {
        degraded.push(format!(
            "degradations: {}",
            new_deg
                .iter()
                .map(|s| s.as_str())
                .collect::<Vec<_>>()
                .join("; ")
        ));
    }
    // R13 (lab PR 271): the capability manifest — a settled hash other
    // than the last one seen is a change of what the agent runs with
    // (within a run, or across a restart); every new beat is read, so a
    // change undone before this check is still seen. A run whose manifest
    // has not settled long after its start, and a manifest gone from the
    // beats, are DEGRADED too.
    let mut manifest_hash = last.and_then(|l| l.manifest_hash.clone());
    let mut manifest_revision = last.and_then(|l| l.manifest_revision);
    let mut manifest_run = last
        .and_then(|l| l.manifest_run.clone())
        .unwrap_or_default();
    let mut manifest_contract = last.and_then(|l| l.manifest_contract.clone());
    let mut manifest_versions = last.and_then(|l| l.manifest_versions.clone());
    let fresh: Vec<&HeartbeatRecord> = match last {
        Some(l) => beats
            .iter()
            .map(|(_, b)| *b)
            .filter(|b| b.seq > l.seq)
            .collect(),
        None => vec![newest],
    };
    for b in fresh {
        match &b.capabilities {
            Some(m) if m.settled => {
                // the contract first: its change alone is an upgrade, when
                // nothing went backwards (the re-check of #479)
                if let Some(c) = &m.contract {
                    let versions = ContractSeen {
                        agent: b.version.clone(),
                        contract_version: m.contract_version,
                        kernel: m.kernel.clone(),
                    };
                    if let Some(seen) = manifest_contract.as_deref() {
                        if seen != c && last.is_some() {
                            let back = manifest_versions
                                .as_ref()
                                .map(|v| contract_backwards(v, &versions))
                                .unwrap_or_default();
                            if back.is_empty() {
                                out.notices.push(format!(
                                    "the sensor contract changed: {} → {} (run {}, agent {}): \
                                     an upgrade or a new kernel — the capabilities are \
                                     compared on their own",
                                    short(seen),
                                    short(c),
                                    b.run,
                                    b.version
                                ));
                            } else {
                                degraded.push(format!(
                                    "the sensor contract changed backwards: {} → {} (run {}): \
                                     {} — a downgrade or an older kernel, its terms weaker \
                                     than the ones seen",
                                    short(seen),
                                    short(c),
                                    b.run,
                                    back.join(", ")
                                ));
                            }
                        }
                    }
                    manifest_contract = Some(c.clone());
                    manifest_versions = Some(versions);
                }
                if let Some(seen) = manifest_hash.as_deref() {
                    if seen != m.hash && last.is_some() {
                        degraded.push(format!(
                            "the capability manifest changed{}: {} → {} (revision {} of run {}; nn-admin \
                             capabilities --key names the change, signed capability_manifest_change)",
                            if b.run != manifest_run { " across a restart" } else { "" },
                            short(seen),
                            short(&m.hash),
                            m.revision,
                            b.run
                        ));
                    }
                }
                manifest_hash = Some(m.hash.clone());
                manifest_revision = Some(m.revision);
                manifest_run = b.run.clone();
            }
            Some(_)
                if b.kind != BeatKind::Stop
                    && b.uptime_ms > MANIFEST_SETTLE_SECS * 1000
                    && b.seq == newest.seq =>
            {
                degraded.push(format!(
                    "the capability manifest has not settled {} s after the start (the \
                     telemetry probe's first round not ended)",
                    b.uptime_ms / 1000
                ));
            }
            Some(_) => {}
            None if manifest_hash.is_some() && b.seq == newest.seq => {
                degraded.push(
                    "the beat carries no capability manifest any more (an agent older than \
                     R13, or its boot did not sign one)"
                        .to_string(),
                );
            }
            None => {}
        }
    }
    if !degraded.is_empty() {
        out.alerts.push(Alert::Degraded(degraded.join("; ")));
    }
    out.state = Some(WatchState {
        seq: newest.seq,
        entry_hash: parsed[newest_i].entry_hash.clone(),
        ts: newest.ts.clone(),
        run: newest.run.clone(),
        boot_id: newest.boot_id.clone(),
        interval_secs: newest.interval_secs,
        loss: newest.loss.clone(),
        actions: newest.actions.clone(),
        probe_gaps: newest.probe_gaps,
        degradations: newest.degradations.clone(),
        heads: newest
            .heads
            .iter()
            .map(|h| (h.chain.clone(), h.clone()))
            .collect(),
        stopped: newest.kind == BeatKind::Stop,
        seen_at: crate::audit::format_ts(seen_at),
        uptime_ms: newest.uptime_ms,
        manifest_hash,
        manifest_revision,
        manifest_run: Some(manifest_run).filter(|r| !r.is_empty()),
        manifest_contract,
        manifest_versions,
    });
    out
}

/// `nn-admin heartbeat export`'s read: the last `count` lines of the chain
/// whose active file is `path`, in chain order — its newest archive's tail
/// first when the active file holds fewer — exactly as on disk.
pub fn tail_lines(path: &std::path::Path, count: usize) -> std::io::Result<Vec<String>> {
    let mut lines: Vec<String> = std::fs::read_to_string(path)?
        .lines()
        .map(str::to_string)
        .collect();
    if lines.len() < count {
        if let Some(a) = crate::chainlog::archives_newest_first(path).first() {
            if let Ok(text) = std::fs::read_to_string(a) {
                let mut older: Vec<String> = text.lines().map(str::to_string).collect();
                older.append(&mut lines);
                lines = older;
            }
        }
    }
    let n = lines.len();
    Ok(lines.split_off(n.saturating_sub(count)))
}

fn trim(l: &[u8]) -> &[u8] {
    let mut l = l;
    while let [rest @ .., b'\n' | b'\r' | b' '] = l {
        l = rest;
    }
    l
}

fn short(h: &str) -> &str {
    &h[..h.len().min(16)]
}

#[cfg(test)]
mod tests;
