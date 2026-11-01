//! The capability manifest (lab PR 218; R13, lab PR 271 — plan §2.3, §3.6):
//! what this boot runs with, against the sensor contract.
//!
//! The boot signs it before `READY=1` (op `capability_manifest`, the
//! agent's `boot::manifest`); every change while the agent runs — a sensor
//! lost, a fallback taken, the telemetry probe's self-test failing, passing
//! again or going stale, a degradation recorded — is signed as a new
//! revision (op `capability_manifest_change`, at most one a minute, every
//! change counted) with what changed and the hash of the revision before it.
//! The heartbeat carries the newest [`CapabilityManifest::content_hash`] (the
//! capabilities) and [`CapabilityManifest::contract_hash`] (the contract's
//! terms, the build, the kernel), so a verifier off the host tells a
//! capability change from an upgrade.
//!
//! This module is the portable half: the manifest's types, each source's
//! entry built from what the boot noted ([`source_entries`]), each class's
//! ([`class_entries`]), the hashes and what changed between two revisions
//! ([`CapabilityManifest::changes_from`]).
//!
//! What `ok` rests on (the review of #479): a source is `ok` only when its
//! attach code noted that it took the contract's attach point whole (or an
//! equivalent fallback) — exactly that note, never a prefix of it —, its
//! pump runs, its BPF LSM programs run when it has some, and the probe has
//! not found it silent or stopped speaking; each entry says which of those
//! is evidence of its own (`evidence`: the probe's event, the deny self-test,
//! or the attach alone).

use nn_model::EventClass;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::{class_contracts, FailureMode, SourceContract};

/// Bumped when a field changes meaning or goes. 2 (R13): the class and
/// source entries, the revisions and their hashes.
pub const MANIFEST_VERSION: u32 = 2;

/// How the attach code took a sensor's attach point (R13, the review of
/// #479, X1): the manifest reads the state from this, never from the note's
/// words.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "as", rename_all = "snake_case")]
pub enum Took {
    /// The attach point whole.
    Whole,
    /// Part of it; what did not attach.
    Partial { missing: Vec<String> },
    /// A fallback.
    Fallback,
    /// Switched off by the operator.
    Off,
    /// Nothing attached (the note says why).
    Absent,
}

/// One sensor and where it is attached, as the boot notes it (lab PR 218;
/// R13: from nn-linux's `boot::manifest`, which notes them).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SensorEntry {
    pub sensor: String,
    pub attach: String,
    /// R13: how it was taken (`None`: a note that does not say — read as
    /// `unknown`, never as `ok`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub took: Option<Took>,
}

/// The deny hooks of the boot.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DenyHooks {
    pub expected: usize,
    pub attached: usize,
    /// Each missing hook with why, and the failed protection steps.
    pub missing: Vec<String>,
    /// The observe hooks that did not attach.
    pub observe_missing: Vec<String>,
}

/// One row of the host hardening table.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostCheck {
    pub id: String,
    pub status: String,
    pub value: String,
}

/// Where a source runs on this boot.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AttachedOn {
    /// Its contract's attach point.
    Primary,
    /// One of its fallbacks.
    Fallback,
    /// Nowhere: not attached, switched off, or the fallback of a source
    /// that runs on its own.
    None,
}

/// The state of a source (plan §2.3), as the manifest signs it. Its losses
/// (the plan's "lossy" and "over budget") are not a state of the manifest:
/// they are counted by stage, signed in `telemetry_loss` rows and carried by
/// every beat — a manifest that changed at every lost record would say
/// nothing about what is attached.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceState {
    /// Attached whole (or on an equivalent fallback), running, and — when
    /// the telemetry probe exercises it — seen by the probe (or not probed
    /// yet).
    Ok,
    /// Attached and inert by design: the fallback of a source that runs on
    /// its own attach point.
    Standby,
    /// Switched off by an administrator.
    DisabledByAdmin,
    /// Part of it runs: a hook of it not attached, a fallback that covers
    /// less (the events it no longer sends named), part of it an LSM
    /// program that does not run, an opt-in configured and inert.
    Partial,
    /// Not known: an attach note the contract does not know, or the
    /// telemetry probe's word stale (no round has ended for two intervals).
    Unknown,
    /// Attached, and not invoked: its BPF LSM programs do not run (`bpf`
    /// not in the active LSM list, or the deny self-test's signal
    /// delivered), or the telemetry probe's event did not reach the
    /// pipeline.
    AttachedNotInvoked,
    /// Not on this host: nothing attached, or no pump started to read it.
    Unavailable,
    /// Its adapter stopped: the pump or the drain ended (the agent stops
    /// for the watchdog's restart).
    AdapterTerminated,
}

impl SourceState {
    /// As `nn-admin` prints it.
    pub const fn name(self) -> &'static str {
        match self {
            SourceState::Ok => "ok",
            SourceState::Standby => "standby",
            SourceState::DisabledByAdmin => "disabled by admin",
            SourceState::Partial => "partial",
            SourceState::Unknown => "unknown",
            SourceState::AttachedNotInvoked => "attached, not invoked",
            SourceState::Unavailable => "unavailable",
            SourceState::AdapterTerminated => "adapter terminated",
        }
    }

    /// How bad, for a class's state (the worst of its sources) and for a
    /// source's own (a reason only makes it worse).
    pub const fn rank(self) -> u8 {
        match self {
            SourceState::Ok | SourceState::Standby => 0,
            SourceState::DisabledByAdmin => 1,
            SourceState::Partial => 2,
            SourceState::Unknown => 3,
            SourceState::AttachedNotInvoked => 4,
            SourceState::Unavailable => 5,
            SourceState::AdapterTerminated => 6,
        }
    }
}

/// `state` made `to` when that is worse.
fn worsen(state: &mut SourceState, to: SourceState) {
    if to.rank() > state.rank() {
        *state = to;
    }
}

/// The telemetry probe's word on a source.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProbeState {
    /// No round has ended yet.
    Pending,
    /// The last round's event reached the pipeline.
    Seen,
    /// The last round's event did not (a `telemetry_gap`).
    Gap,
    /// No round has ended for two of its intervals (the review of #479,
    /// X2): what it said last is not believed any more.
    Stale,
}

/// What a source's `ok` rests on (the review of #479).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Evidence {
    /// The telemetry probe's event reached the pipeline through it.
    Probe,
    /// The deny self-test's refusal (one hook, at the boot).
    SelfTest,
    /// Its attach and its pump only.
    AttachOnly,
}

/// A source's terms, as the manifest signs them (its contract): in the
/// boot's row; a change's row names them by the contract's hash.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceTerms {
    pub attach: String,
    pub fallbacks: Vec<String>,
    pub sync_verdict: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub opt_in_verdict: Option<String>,
    pub on_failure: FailureMode,
    pub on_failure_detail: String,
    pub kernel_budgets: Vec<String>,
    pub truncations: Vec<String>,
    pub rings: Vec<String>,
    /// The stages (plan §3.4) that count its losses.
    pub loss_counters: Vec<u8>,
}

impl SourceTerms {
    fn of(c: &SourceContract) -> Self {
        SourceTerms {
            attach: c.attach.to_string(),
            fallbacks: c
                .fallbacks
                .iter()
                .map(|f| {
                    let mut t = format!("{} (when {}; costs: {}", f.attach, f.when, f.costs);
                    if f.equivalent {
                        t.push_str("; equivalent");
                    }
                    if !f.lost.is_empty() {
                        t.push_str(&format!("; no {}", kind_names(f.lost)));
                    }
                    t.push(')');
                    t
                })
                .collect(),
            sync_verdict: c.sync_verdict.describe(),
            opt_in_verdict: c
                .opt_in
                .map(|o| format!("{} ({})", o.verdict.describe(), o.when)),
            on_failure: c.on_failure,
            on_failure_detail: c.on_failure_detail.to_string(),
            kernel_budgets: c
                .kernel_budgets
                .iter()
                .map(|b| format!("{} (counted: {})", b.allows, b.counter))
                .collect(),
            truncations: c
                .truncations
                .iter()
                .map(|t| format!("{} {} B ({})", t.field, t.max_bytes, t.marked))
                .collect(),
            rings: c.rings.iter().map(|r| r.to_string()).collect(),
            loss_counters: c.loss_counters().iter().map(|s| s.number()).collect(),
        }
    }
}

fn kind_names(kinds: &[super::EventKind]) -> String {
    kinds
        .iter()
        .map(|k| k.name())
        .collect::<Vec<_>>()
        .join(", ")
}

/// A source of the bus on this boot: where it runs, its state and why,
/// the probe's word, what its state rests on, and its terms.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceEntry {
    pub source: String,
    pub classes: Vec<EventClass>,
    /// Its attach point as the boot noted it ("not attached" without one).
    pub attach: String,
    pub on: AttachedOn,
    pub state: SourceState,
    /// Why it is not on its attach point, or not in the `ok` state: the
    /// boot's reasons and the degradations recorded about it.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub why: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub probe: Option<ProbeState>,
    /// What its `ok` rests on (the review of #479).
    pub evidence: Evidence,
    /// Its contract's terms: in the boot's row (revision 0) and the running
    /// agent's view; a change's row carries the contract's hash instead.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub terms: Option<SourceTerms>,
}

/// A class of events on this boot: its contract and the worst state of
/// its sources.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClassEntry {
    pub class: EventClass,
    pub queue: String,
    pub queue_capacity: usize,
    pub when_full: String,
    pub decision_budget_ms: u64,
    pub sources: Vec<String>,
    pub sync_verdict: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub on_failure: Option<FailureMode>,
    pub loss_counters: Vec<u8>,
    /// The worst state of its sources; `None` without a source.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state: Option<SourceState>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

/// What the boot measured that a source's state is read from.
#[derive(Clone, Debug, Default)]
pub struct SourceFacts {
    /// The attach points the boot noted.
    pub notes: Vec<SensorEntry>,
    /// Whether the BPF LSM programs run (`None`: not known), and why not.
    pub lsm_runs: Option<bool>,
    pub lsm_why: String,
    /// The telemetry probe's word per probed sensor (empty: the probe is
    /// off).
    pub probe: Vec<(String, ProbeState)>,
    /// The degradations recorded, `(source, detail)`.
    pub degradations: Vec<(String, String)>,
    /// The sources whose adapter ended.
    pub terminated: Vec<String>,
    /// The sources whose pump or drain the start registered (`None`: not
    /// known): one on its attach point without it reads nothing.
    pub running: Option<Vec<String>>,
    /// The opt-ins configured (their `OptIn::key`).
    pub opt_ins: Vec<String>,
}

impl SourceFacts {
    fn probe_of(&self, sensor: &str) -> Option<ProbeState> {
        self.probe
            .iter()
            .find(|(s, _)| s == sensor)
            .map(|(_, st)| *st)
    }

    fn note(&self, sensor: &str) -> Option<&SensorEntry> {
        self.notes.iter().find(|n| n.sensor == sensor)
    }
}

/// Each source of `contract` on this boot, in the contract's order.
pub fn source_entries(contract: &[SourceContract], facts: &SourceFacts) -> Vec<SourceEntry> {
    let mut out: Vec<SourceEntry> = contract
        .iter()
        .map(|c| source_entry(c, contract, facts))
        .collect();
    // A standby source runs when the source it stands in for is on its
    // fallback: then it carries the events, and the probe's word is its.
    for (i, c) in contract.iter().enumerate() {
        let Some(other) = c.standby_for else {
            continue;
        };
        let Some(j) = contract.iter().position(|o| o.source == other) else {
            continue;
        };
        if out[j].on != AttachedOn::Fallback {
            continue;
        }
        let e = &mut out[i];
        e.attach = c.attach.to_string();
        e.on = AttachedOn::Primary;
        e.state = SourceState::Ok;
        e.why = vec![format!(
            "{other} is on its fallback: this source carries its events"
        )];
        e.probe = c.probe.and_then(|p| facts.probe_of(p));
        probe_word(e, c, e.probe);
        if facts.terminated.iter().any(|t| t == c.source) {
            e.state = SourceState::AdapterTerminated;
        }
        e.evidence = evidence(c, e.probe, facts);
    }
    out
}

/// The probe's word on `e`: a gap is not invoked, a stale word unknown.
fn probe_word(e: &mut SourceEntry, c: &SourceContract, probe: Option<ProbeState>) {
    let sensor = c.probe.unwrap_or("?");
    match probe {
        Some(ProbeState::Gap) => {
            worsen(&mut e.state, SourceState::AttachedNotInvoked);
            e.why.push(format!(
                "telemetry probe: its {sensor} event did not reach the pipeline within the \
                 round's deadline (signed telemetry_gap)"
            ));
        }
        Some(ProbeState::Stale) => {
            worsen(&mut e.state, SourceState::Unknown);
            e.why.push(format!(
                "telemetry probe: no round has ended for two of its intervals — its word on \
                 {sensor} is stale"
            ));
        }
        _ => {}
    }
}

fn evidence(c: &SourceContract, probe: Option<ProbeState>, facts: &SourceFacts) -> Evidence {
    if probe == Some(ProbeState::Seen) {
        Evidence::Probe
    } else if c.self_tested && facts.lsm_runs == Some(true) {
        Evidence::SelfTest
    } else {
        Evidence::AttachOnly
    }
}

fn source_entry(
    c: &SourceContract,
    contract: &[SourceContract],
    facts: &SourceFacts,
) -> SourceEntry {
    let note = c.sensors.first().and_then(|s| facts.note(s));
    let mut why: Vec<String> = facts
        .degradations
        .iter()
        .filter(|(src, _)| c.degradation_sources.contains(&src.as_str()))
        .map(|(src, d)| format!("{src}: {d}"))
        .collect();
    // the other attach points of the source (dns_nss beside dns)
    for s in c.sensors.iter().skip(1) {
        match facts.note(s) {
            None => why.push(format!("{s}: not attached")),
            Some(n) => match &n.took {
                Some(Took::Whole) => {}
                Some(Took::Partial { missing }) => why.push(format!(
                    "{s}: {} — not attached: {}",
                    n.attach,
                    missing.join("; ")
                )),
                Some(_) => why.push(format!("{s}: {}", n.attach)),
                None => why.push(format!("{s}: {} (how it attached not said)", n.attach)),
            },
        }
    }
    let (attach, on, mut state) = match (c.standby_for, note) {
        (Some(other), _) => (
            format!("{} (inert: {other} runs)", c.attach),
            AttachedOn::None,
            SourceState::Standby,
        ),
        (None, None) => (
            "not attached".to_string(),
            AttachedOn::None,
            SourceState::Unavailable,
        ),
        (None, Some(n)) => {
            let a = n.attach.clone();
            let whole = n.attach == c.attach || c.also.contains(&n.attach.as_str());
            match &n.took {
                Some(Took::Off) => (a, AttachedOn::None, SourceState::DisabledByAdmin),
                Some(Took::Absent) => (a, AttachedOn::None, SourceState::Unavailable),
                Some(Took::Whole) if whole => (a, AttachedOn::Primary, SourceState::Ok),
                Some(Took::Partial { missing }) => {
                    why.push(format!("not attached: {}", missing.join("; ")));
                    (a, AttachedOn::Primary, SourceState::Partial)
                }
                Some(Took::Fallback) => match c.fallbacks.iter().find(|f| f.attach == a) {
                    Some(f) if f.equivalent => (a, AttachedOn::Fallback, SourceState::Ok),
                    Some(f) => {
                        why.push(format!("on its fallback: {}", f.costs));
                        if !f.lost.is_empty() {
                            why.push(format!("events not sent on it: {}", kind_names(f.lost)));
                        }
                        (a, AttachedOn::Fallback, SourceState::Partial)
                    }
                    None => {
                        why.push(format!("a fallback its contract does not know: {a}"));
                        (a, AttachedOn::Fallback, SourceState::Unknown)
                    }
                },
                Some(Took::Whole) => {
                    why.push(format!(
                        "attached as {a}, which is not its contract's attach point ({})",
                        c.attach
                    ));
                    (a, AttachedOn::Primary, SourceState::Unknown)
                }
                None => {
                    why.push(format!("the attach note does not say how it attached: {a}"));
                    (a, AttachedOn::None, SourceState::Unknown)
                }
            }
        }
    };
    // attached, and nothing reads its ring: its pump or drain did not start
    // (a fallback is another source's adapter, a standby one's or none)
    if on == AttachedOn::Primary
        && facts
            .running
            .as_ref()
            .is_some_and(|r| !r.iter().any(|x| x == c.source))
    {
        state = SourceState::Unavailable;
        why.push("its pump or drain did not start: nothing reads its ring".to_string());
    }
    if on == AttachedOn::Primary && c.needs_bpf_lsm && facts.lsm_runs == Some(false) {
        match c.lsm_part {
            Some(part) => {
                worsen(&mut state, SourceState::Partial);
                why.push(format!("{} — {part}", facts.lsm_why));
            }
            None => {
                worsen(&mut state, SourceState::AttachedNotInvoked);
                why.push(facts.lsm_why.clone());
            }
        }
    }
    if let Some(o) = c.opt_in {
        if o.needs_bpf_lsm
            && facts.lsm_runs == Some(false)
            && facts.opt_ins.iter().any(|k| k == o.key)
        {
            worsen(&mut state, SourceState::Partial);
            why.push(format!(
                "the opt-in {} is configured and does not run: {}",
                o.when, facts.lsm_why
            ));
        }
    }
    // the probe's word on what runs; a source on its fallback whose events
    // a standby source carries leaves it to that one (`source_entries`)
    let handed_over =
        on == AttachedOn::Fallback && contract.iter().any(|o| o.standby_for == Some(c.source));
    let probe = match c.probe {
        Some(p) if c.standby_for.is_none() && on != AttachedOn::None && !handed_over => {
            facts.probe_of(p)
        }
        _ => None,
    };
    let mut e = SourceEntry {
        source: c.source.to_string(),
        classes: c.classes(),
        attach,
        on,
        state,
        why,
        probe,
        evidence: Evidence::AttachOnly,
        terms: Some(SourceTerms::of(c)),
    };
    if !matches!(
        e.state,
        SourceState::Unavailable | SourceState::DisabledByAdmin
    ) {
        probe_word(&mut e, c, probe);
    }
    if facts.terminated.iter().any(|t| t == c.source) {
        e.state = SourceState::AdapterTerminated;
        e.why
            .push("its pump or drain ended: the agent stops for the watchdog's restart".into());
    }
    e.evidence = evidence(c, probe, facts);
    e
}

/// Each class on this boot, in [`EventClass::ALL`]'s order.
pub fn class_entries(contract: &[SourceContract], sources: &[SourceEntry]) -> Vec<ClassEntry> {
    class_contracts(contract)
        .into_iter()
        .map(|cc| {
            // a standby source says nothing of its class while another
            // carries the events
            let of: Vec<SourceState> = sources
                .iter()
                .filter(|s| cc.sources.contains(&s.source.as_str()))
                .map(|s| s.state)
                .collect();
            let state = of
                .iter()
                .copied()
                .filter(|s| *s != SourceState::Standby)
                .max_by_key(|s| s.rank())
                .or_else(|| of.first().copied());
            ClassEntry {
                class: cc.class,
                queue: cc.queue.to_string(),
                queue_capacity: cc.queue_capacity,
                when_full: cc.when_full,
                decision_budget_ms: cc.decision_budget_ms,
                sources: cc.sources.iter().map(|s| s.to_string()).collect(),
                sync_verdict: cc.sync_verdict.describe(),
                on_failure: cc.on_failure,
                loss_counters: cc.loss_counters.iter().map(|s| s.number()).collect(),
                state,
                note: cc.note.map(str::to_string),
            }
        })
        .collect()
}

/// R14a (plan §3.1, §3.5): a worker kind's state, as the manifest states it
/// (the supervisor's `Health`, without the transient start).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkerState {
    /// A worker serves.
    Ready,
    /// Between two workers: one died or is starting, within the backoff.
    Restarting,
    /// Failures in a row: its requests are refused (the core does without
    /// what it gives) until a worker stays up.
    Disabled,
    /// It cannot be started (no account, no image).
    Unavailable,
    /// The agent stopped it.
    Stopped,
}

impl WorkerState {
    pub fn name(self) -> &'static str {
        match self {
            WorkerState::Ready => "ready",
            WorkerState::Restarting => "restarting",
            WorkerState::Disabled => "disabled",
            WorkerState::Unavailable => "unavailable",
            WorkerState::Stopped => "stopped",
        }
    }

    /// Worse is higher (a change to a higher rank is signed at once).
    pub fn rank(self) -> u8 {
        match self {
            WorkerState::Ready => 0,
            WorkerState::Restarting => 1,
            WorkerState::Stopped => 2,
            WorkerState::Disabled => 3,
            WorkerState::Unavailable => 4,
        }
    }
}

/// R14a: a worker kind of this boot, its state and the sandbox its workers
/// enter on this kernel — declared as the worker measured it, never
/// assumed (plan §5 risk 8: the Landlock ABI is 1 on 5.15, 2 on 6.1, 4 on
/// 6.8, 6 on 6.12).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkerEntry {
    /// `parse`.
    pub kind: String,
    pub state: WorkerState,
    /// Why it is disabled or unavailable.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub why: String,
    /// The kernel's Landlock ABI as the core read it at boot (0: none).
    pub kernel_landlock_abi: u8,
    /// The level the running (or the last ready) worker declared in its
    /// hello, which the core checked; `None` before the first one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sandbox: Option<nn_proto::ipc::SandboxLevel>,
}

/// What this boot runs with (lab PR 218), and since R13 each source and
/// class against its contract, the revision, its hashes and what changed.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilityManifest {
    pub manifest_version: u32,
    pub agent_version: String,
    /// `/proc/sys/kernel/osrelease`.
    pub kernel: String,
    /// `/sys/kernel/btf/vmlinux` was there, and the offsets resolved from
    /// it (the drifted ones read at their runtime value; the absent ones
    /// disable the path that needs them).
    pub btf: bool,
    pub btf_offsets_resolved: usize,
    pub btf_offsets_drifted: usize,
    pub btf_offsets_absent: Vec<String>,
    /// `/sys/kernel/security/lsm`, and what it says of `bpf`.
    pub active_lsms: Option<String>,
    pub bpf_lsm: String,
    pub deny_hooks: DenyHooks,
    pub deny_self_test: String,
    /// The BPF map guard enforces or only observes (a debug build).
    pub bpf_guard: String,
    pub sensors: Vec<SensorEntry>,
    pub host_hardening: Vec<HostCheck>,
    pub detect_only: bool,
    pub degradations: Vec<String>,
    pub trust_level: u8,
    pub trust_reasons: Vec<String>,
    /// R13: the contract's version, each source and each class.
    #[serde(default)]
    pub contract_version: u32,
    #[serde(default)]
    pub sources: Vec<SourceEntry>,
    #[serde(default)]
    pub classes: Vec<ClassEntry>,
    /// R13: the sources on a fallback, and what is missing, partial, not
    /// known or not invoked (deny hooks, observe hooks, sources), one line
    /// each.
    #[serde(default)]
    pub fallbacks: Vec<String>,
    #[serde(default)]
    pub missing: Vec<String>,
    /// R13: the shipped content lists not in force from their file (the
    /// copy built into the agent, or a file edited by hand).
    #[serde(default)]
    pub content: Vec<String>,
    /// R14a: the workers (plan §3.1), their state and their sandbox level.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub workers: Vec<WorkerEntry>,
    /// R13: the telemetry probe's period (`off` when switched off), and
    /// whether its first round has ended (`settled`: the manifest states
    /// the self-test's word on every probed source).
    #[serde(default)]
    pub telemetry_probe: String,
    #[serde(default)]
    pub settled: bool,
    /// R13: the hash of the contract's terms, the agent's version and the
    /// kernel's release ([`Self::contract_hash_now`]): a change of it
    /// alone is an upgrade, not a capability's.
    #[serde(default)]
    pub contract_hash: String,
    /// R13: 0 at the boot, one more at each change signed while the agent
    /// runs; this revision's capabilities hash ([`Self::content_hash`]),
    /// the one before it, what changed, and how many changes the row folds
    /// (at most one row a minute; the running view counts those not signed
    /// yet in `unsigned_changes`).
    #[serde(default)]
    pub revision: u64,
    #[serde(default)]
    pub hash: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub change: Vec<String>,
    #[serde(default, skip_serializing_if = "is_zero")]
    pub changes: u64,
    #[serde(default, skip_serializing_if = "is_zero")]
    pub unsigned_changes: u64,
}

fn is_zero(n: &u64) -> bool {
    *n == 0
}

fn sha256_hex<T: Serialize>(v: &T) -> String {
    hex::encode(Sha256::digest(serde_json::to_vec(v).unwrap_or_default()))
}

impl CapabilityManifest {
    /// The SHA-256 (hex) of what the agent runs with — the capabilities:
    /// the manifest without its revision fields, without the contract's
    /// terms (`terms`, each class's queue, budget, verdict, failure and loss
    /// stages: [`Self::contract_hash_now`]'s), without what an upgrade or a
    /// new kernel changes by itself (the agent's version, the kernel's
    /// release, the offsets counted, the host checks' values), its lists
    /// that have no order of their own sorted. Two starts that attach the
    /// same way on the same host have the same hash; a change of a
    /// capability changes it, an upgrade alone does not.
    pub fn content_hash(&self) -> String {
        let mut c = self.clone();
        c.revision = 0;
        c.hash = String::new();
        c.previous_hash = None;
        c.change = Vec::new();
        c.changes = 0;
        c.unsigned_changes = 0;
        c.contract_hash = String::new();
        c.contract_version = 0;
        c.agent_version = String::new();
        c.kernel = String::new();
        c.btf_offsets_resolved = 0;
        c.btf_offsets_drifted = 0;
        for h in &mut c.host_hardening {
            h.value = String::new();
        }
        c.host_hardening.sort_by(|a, b| a.id.cmp(&b.id));
        c.sensors.sort_by(|a, b| a.sensor.cmp(&b.sensor));
        c.degradations.sort();
        c.fallbacks.sort();
        c.missing.sort();
        c.content.sort();
        c.workers.sort_by(|a, b| a.kind.cmp(&b.kind));
        for s in &mut c.sources {
            s.terms = None;
            s.why.sort();
        }
        for cl in &mut c.classes {
            cl.queue = String::new();
            cl.queue_capacity = 0;
            cl.when_full = String::new();
            cl.decision_budget_ms = 0;
            cl.sync_verdict = String::new();
            cl.on_failure = None;
            cl.loss_counters = Vec::new();
            cl.note = None;
        }
        sha256_hex(&c)
    }

    /// The SHA-256 (hex) of the contract's terms (each source's, each
    /// class's), its version, the agent's version and the kernel's release:
    /// what an upgrade or a new kernel changes. Read from the boot's row,
    /// which carries the terms.
    pub fn contract_hash_now(&self) -> String {
        let terms: Vec<(&String, &Option<SourceTerms>)> =
            self.sources.iter().map(|s| (&s.source, &s.terms)).collect();
        // each class's terms: its entry without its sources' state
        let classes: Vec<ClassEntry> = self
            .classes
            .iter()
            .map(|c| ClassEntry {
                state: None,
                ..c.clone()
            })
            .collect();
        sha256_hex(&(
            self.contract_version,
            &self.agent_version,
            &self.kernel,
            terms,
            classes,
        ))
    }

    /// The row a change is signed as: the terms by the contract's hash.
    pub fn without_terms(&self) -> Self {
        let mut c = self.clone();
        for s in &mut c.sources {
            s.terms = None;
        }
        c
    }

    /// What changed from `before` to `self`, one line each (the signed
    /// change's `change`).
    pub fn changes_from(&self, before: &CapabilityManifest) -> Vec<String> {
        let mut out = Vec::new();
        for s in &self.sources {
            match before.sources.iter().find(|b| b.source == s.source) {
                Some(b) => {
                    if (b.state, b.on, &b.attach) != (s.state, s.on, &s.attach) {
                        out.push(format!(
                            "source {}: {} on {} ({}) → {} on {} ({})",
                            s.source,
                            b.state.name(),
                            on_name(b.on),
                            b.attach,
                            s.state.name(),
                            on_name(s.on),
                            s.attach
                        ));
                    }
                    if b.probe != s.probe {
                        out.push(format!(
                            "source {}: telemetry probe {} → {}",
                            s.source,
                            probe_name(b.probe),
                            probe_name(s.probe)
                        ));
                    }
                }
                None => out.push(format!("source {}: new ({})", s.source, s.state.name())),
            }
        }
        for b in &before.sources {
            if !self.sources.iter().any(|s| s.source == b.source) {
                out.push(format!("source {}: gone", b.source));
            }
        }
        let added = |now: &[String], then: &[String], what: &str, out: &mut Vec<String>| {
            for x in now.iter().filter(|x| !then.contains(x)) {
                out.push(format!("{what} + {x}"));
            }
            for x in then.iter().filter(|x| !now.contains(x)) {
                out.push(format!("{what} - {x}"));
            }
        };
        added(
            &self.degradations,
            &before.degradations,
            "degradation",
            &mut out,
        );
        added(&self.content, &before.content, "content", &mut out);
        for w in &self.workers {
            match before.workers.iter().find(|b| b.kind == w.kind) {
                Some(b) if b.state != w.state => out.push(format!(
                    "worker {}: {} → {}{}",
                    w.kind,
                    b.state.name(),
                    w.state.name(),
                    if w.why.is_empty() {
                        String::new()
                    } else {
                        format!(" ({})", w.why)
                    }
                )),
                Some(b) if b.sandbox != w.sandbox => out.push(format!(
                    "worker {}: sandbox {} → {}",
                    w.kind,
                    b.sandbox
                        .as_ref()
                        .map_or_else(|| "unknown".to_string(), |l| l.summary()),
                    w.sandbox
                        .as_ref()
                        .map_or_else(|| "unknown".to_string(), |l| l.summary())
                )),
                Some(_) => {}
                None => out.push(format!("worker {}: new ({})", w.kind, w.state.name())),
            }
        }
        for b in &before.workers {
            if !self.workers.iter().any(|w| w.kind == b.kind) {
                out.push(format!("worker {}: gone", b.kind));
            }
        }
        if self.deny_hooks != before.deny_hooks {
            out.push(format!(
                "deny hooks: {} of {} → {} of {}",
                before.deny_hooks.attached,
                before.deny_hooks.expected,
                self.deny_hooks.attached,
                self.deny_hooks.expected
            ));
        }
        if self.trust_level != before.trust_level {
            out.push(format!(
                "trust level L{} → L{}",
                before.trust_level, self.trust_level
            ));
        }
        if self.telemetry_probe != before.telemetry_probe {
            out.push(format!(
                "telemetry probe {} → {}",
                before.telemetry_probe, self.telemetry_probe
            ));
        }
        if out.is_empty() && self.content_hash() != before.content_hash() {
            out.push("the manifest changed (nn-admin capabilities shows it)".to_string());
        }
        out
    }

    /// The re-check of #479: whether `self` is worse than `before` — a
    /// source in a worse state, gone, or new and not `ok`; a probe's word
    /// turned `gap` or `stale`; a line new in `missing`, `fallbacks`, the
    /// degradations, the content or the deny hooks' missing ones; fewer
    /// deny hooks attached; a lower trust level. A worse change's row is
    /// signed at once, a better one's waits for the minute.
    pub fn worsens_from(&self, before: &CapabilityManifest) -> bool {
        let sources = self.sources.iter().any(|s| {
            match before.sources.iter().find(|b| b.source == s.source) {
                Some(b) => {
                    s.state.rank() > b.state.rank()
                        || (matches!(s.probe, Some(ProbeState::Gap | ProbeState::Stale))
                            && s.probe != b.probe)
                }
                None => s.state.rank() > 0,
            }
        }) || before
            .sources
            .iter()
            .any(|b| !self.sources.iter().any(|s| s.source == b.source));
        let new_line = |now: &[String], then: &[String]| now.iter().any(|x| !then.contains(x));
        sources
            || new_line(&self.missing, &before.missing)
            || new_line(&self.fallbacks, &before.fallbacks)
            || new_line(&self.degradations, &before.degradations)
            || new_line(&self.content, &before.content)
            || new_line(&self.deny_hooks.missing, &before.deny_hooks.missing)
            || new_line(
                &self.deny_hooks.observe_missing,
                &before.deny_hooks.observe_missing,
            )
            || self.deny_hooks.attached < before.deny_hooks.attached
            || self.trust_level < before.trust_level
            || self.workers_worsen_from(before)
    }

    /// R14a: a worker kind in a worse state, gone, or sandboxed less than
    /// before (a Landlock level, the seccomp filter).
    fn workers_worsen_from(&self, before: &CapabilityManifest) -> bool {
        let weaker = |a: &nn_proto::ipc::SandboxLevel, b: &nn_proto::ipc::SandboxLevel| {
            a.landlock_abi < b.landlock_abi
                || (b.fs_denied && !a.fs_denied)
                || (b.net_denied && !a.net_denied)
                || (b.scoped && !a.scoped)
                || (b.seccomp && !a.seccomp)
        };
        self.workers
            .iter()
            .any(|w| match before.workers.iter().find(|b| b.kind == w.kind) {
                Some(b) => {
                    w.state.rank() > b.state.rank()
                        || matches!((&w.sandbox, &b.sandbox), (Some(a), Some(b)) if weaker(a, b))
                }
                None => w.state.rank() > 0,
            })
            || before
                .workers
                .iter()
                .any(|b| !self.workers.iter().any(|w| w.kind == b.kind))
    }

    /// Every probed source has the probe's word (or the probe is off).
    pub fn probe_settled(&self) -> bool {
        !self
            .sources
            .iter()
            .any(|s| s.probe == Some(ProbeState::Pending))
    }
}

fn on_name(on: AttachedOn) -> &'static str {
    match on {
        AttachedOn::Primary => "its attach point",
        AttachedOn::Fallback => "a fallback",
        AttachedOn::None => "nothing",
    }
}

fn probe_name(p: Option<ProbeState>) -> &'static str {
    match p {
        None => "not probed",
        Some(ProbeState::Pending) => "pending",
        Some(ProbeState::Seen) => "seen",
        Some(ProbeState::Gap) => "gap",
        Some(ProbeState::Stale) => "stale",
    }
}

/// The lines of [`CapabilityManifest::fallbacks`] and
/// [`CapabilityManifest::missing`] for `sources` and `deny`: each deny and
/// observe hook not attached (the review of #479, K5), each source not `ok`
/// with its first reason.
pub fn fallbacks_and_missing(
    sources: &[SourceEntry],
    deny: &DenyHooks,
) -> (Vec<String>, Vec<String>) {
    let mut fallbacks = Vec::new();
    let mut missing: Vec<String> = deny
        .missing
        .iter()
        .map(|m| format!("deny hook: {m}"))
        .chain(
            deny.observe_missing
                .iter()
                .map(|m| format!("observe hook: {m}")),
        )
        .collect();
    for s in sources {
        if s.on == AttachedOn::Fallback {
            fallbacks.push(format!("{}: {}", s.source, s.attach));
        }
        match s.state {
            SourceState::Ok | SourceState::Standby => {}
            st => missing.push(format!(
                "{}: {} ({}){}",
                s.source,
                st.name(),
                s.attach,
                s.why.first().map(|w| format!(" — {w}")).unwrap_or_default()
            )),
        }
    }
    (fallbacks, missing)
}
