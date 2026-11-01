//! The capability manifest (lab PR 218; R13, lab PR 271 — plan §2.3, §3.6):
//! what this boot runs with, against the sensor contract.
//!
//! The boot signs it before `READY=1` (op `capability_manifest`, the
//! agent's `boot::manifest`); every change while the agent runs — a sensor
//! lost, a fallback taken, the telemetry probe's self-test failing or
//! passing again, a degradation recorded — is signed as a new revision (op
//! `capability_manifest_change`) with what changed and the hash of the
//! revision before it. The heartbeat carries the newest revision's
//! [`CapabilityManifest::content_hash`], so a verifier off the host sees a
//! capability change.
//!
//! This module is the portable half: the manifest's types, each source's
//! entry built from what the boot noted ([`source_entries`]), each class's
//! ([`class_entries`]), the content hash and what changed between two
//! revisions ([`CapabilityManifest::changes_from`]).

use nn_model::EventClass;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::{class_contracts, FailureMode, SourceContract};

/// Bumped when a field changes meaning or goes. 2 (R13): the class and
/// source entries, the revisions and their hash.
pub const MANIFEST_VERSION: u32 = 2;

/// One sensor and where it is attached, as the boot notes it (lab PR 218;
/// R13: from nn-linux's `boot::manifest`, which notes them).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SensorEntry {
    pub sensor: String,
    pub attach: String,
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
    /// Attached, running, and — when the telemetry probe exercises it —
    /// seen by the probe (or not probed yet).
    Ok,
    /// Attached and inert by design: the fallback of a source that runs on
    /// its own attach point.
    Standby,
    /// Switched off by an administrator.
    DisabledByAdmin,
    /// Attached, and not invoked: its BPF LSM programs do not run (`bpf`
    /// not in the active LSM list, or the deny self-test's signal
    /// delivered), or the telemetry probe's event did not reach the
    /// pipeline.
    AttachedNotInvoked,
    /// Not on this host: nothing attached.
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
            SourceState::AttachedNotInvoked => "attached, not invoked",
            SourceState::Unavailable => "unavailable",
            SourceState::AdapterTerminated => "adapter terminated",
        }
    }

    /// How bad, for a class's state: the worst of its sources.
    const fn rank(self) -> u8 {
        match self {
            SourceState::Ok | SourceState::Standby => 0,
            SourceState::DisabledByAdmin => 1,
            SourceState::AttachedNotInvoked => 2,
            SourceState::Unavailable => 3,
            SourceState::AdapterTerminated => 4,
        }
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
}

/// A source's terms, as the manifest signs them (its contract).
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
                .map(|f| format!("{} (when {}; costs: {})", f.attach, f.when, f.costs))
                .collect(),
            sync_verdict: c.sync_verdict.describe(),
            opt_in_verdict: c
                .opt_in_verdict
                .map(|(v, when)| format!("{} ({when})", v.describe())),
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

/// A source of the bus on this boot: where it runs, its state and why,
/// the probe's word, and its terms.
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
    pub terms: SourceTerms,
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
}

impl SourceFacts {
    fn probe_of(&self, sensor: &str) -> Option<ProbeState> {
        self.probe
            .iter()
            .find(|(s, _)| s == sensor)
            .map(|(_, st)| *st)
    }

    fn note(&self, sensor: &str) -> Option<&str> {
        self.notes
            .iter()
            .find(|n| n.sensor == sensor)
            .map(|n| n.attach.as_str())
    }
}

/// A note that says the sensor is not attached.
fn absent(note: &str) -> bool {
    note.starts_with("not attached") || note.starts_with("none")
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
        if e.probe == Some(ProbeState::Gap) {
            e.state = SourceState::AttachedNotInvoked;
            e.why.push(probe_gap_why(c.probe.unwrap_or("?")));
        }
        if facts.terminated.iter().any(|t| t == c.source) {
            e.state = SourceState::AdapterTerminated;
        }
    }
    out
}

fn probe_gap_why(sensor: &str) -> String {
    format!(
        "telemetry probe: its {sensor} event did not reach the pipeline within the round's \
         deadline (signed telemetry_gap)"
    )
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
            Some(n) if absent(n) => why.push(format!("{s}: {n}")),
            None => why.push(format!("{s}: not attached")),
            Some(_) => {}
        }
    }
    let (attach, on, mut state) = match (c.standby_for, note) {
        (Some(_), _) => (
            format!(
                "{} (inert: {} runs)",
                c.attach,
                c.standby_for.unwrap_or("?")
            ),
            AttachedOn::None,
            SourceState::Standby,
        ),
        (None, None) => (
            "not attached".to_string(),
            AttachedOn::None,
            SourceState::Unavailable,
        ),
        (None, Some(n)) if n.starts_with("off") => (
            n.to_string(),
            AttachedOn::None,
            SourceState::DisabledByAdmin,
        ),
        (None, Some(n)) if absent(n) => (n.to_string(), AttachedOn::None, SourceState::Unavailable),
        // a fallback's note may begin as the attach point's does (the
        // process-spawn tracepoint without its probes): read it first
        (None, Some(n)) if c.fallbacks.iter().any(|f| n.starts_with(f.attach)) => {
            (n.to_string(), AttachedOn::Fallback, SourceState::Ok)
        }
        (None, Some(n)) if n.starts_with(c.attach) => {
            (n.to_string(), AttachedOn::Primary, SourceState::Ok)
        }
        // a note the contract does not know: not its attach point
        (None, Some(n)) => (n.to_string(), AttachedOn::Fallback, SourceState::Ok),
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
    let lsm_hook_runs_here = on == AttachedOn::Primary && c.needs_bpf_lsm;
    if lsm_hook_runs_here && facts.lsm_runs == Some(false) {
        state = SourceState::AttachedNotInvoked;
        why.push(facts.lsm_why.clone());
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
    if probe == Some(ProbeState::Gap) && state == SourceState::Ok {
        state = SourceState::AttachedNotInvoked;
        why.push(probe_gap_why(c.probe.unwrap_or("?")));
    }
    if facts.terminated.iter().any(|t| t == c.source) {
        state = SourceState::AdapterTerminated;
        why.push("its pump or drain ended: the agent stops for the watchdog's restart".into());
    }
    SourceEntry {
        source: c.source.to_string(),
        classes: c.classes(),
        attach,
        on,
        state,
        why,
        probe,
        terms: SourceTerms::of(c),
    }
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

/// What this boot runs with (lab PR 218), and since R13 each source and
/// class against its contract, the revision, its hash and what changed.
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
    /// R13: the sources on a fallback, and what is missing or not invoked
    /// (deny hooks, observe hooks, sources), one line each.
    #[serde(default)]
    pub fallbacks: Vec<String>,
    #[serde(default)]
    pub missing: Vec<String>,
    /// R13: the shipped content lists not in force from their file (the
    /// copy built into the agent, or a file edited by hand).
    #[serde(default)]
    pub content: Vec<String>,
    /// R13: the telemetry probe's period (`off` when switched off), and
    /// whether its first round has ended (`settled`: the manifest states
    /// the self-test's word on every probed source).
    #[serde(default)]
    pub telemetry_probe: String,
    #[serde(default)]
    pub settled: bool,
    /// R13: 0 at the boot, one more at each change signed while the agent
    /// runs; this revision's [`Self::content_hash`], the one before it, and
    /// what changed.
    #[serde(default)]
    pub revision: u64,
    #[serde(default)]
    pub hash: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub change: Vec<String>,
}

impl CapabilityManifest {
    /// The SHA-256 (hex) of what the agent runs with: the manifest's JSON
    /// without its revision fields (`revision`, `hash`, `previous_hash`,
    /// `change`), its lists that have no order of their own sorted. Two
    /// boots that attach the same way on the same host have the same hash;
    /// a change of any capability changes it.
    pub fn content_hash(&self) -> String {
        let mut c = self.clone();
        c.revision = 0;
        c.hash = String::new();
        c.previous_hash = None;
        c.change = Vec::new();
        c.sensors.sort_by(|a, b| a.sensor.cmp(&b.sensor));
        c.degradations.sort();
        c.fallbacks.sort();
        c.missing.sort();
        c.content.sort();
        for s in &mut c.sources {
            s.why.sort();
        }
        let bytes = serde_json::to_vec(&c).unwrap_or_default();
        hex::encode(Sha256::digest(&bytes))
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
    }
}

/// The lines of [`CapabilityManifest::fallbacks`] and
/// [`CapabilityManifest::missing`] for `sources` and `deny`.
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
