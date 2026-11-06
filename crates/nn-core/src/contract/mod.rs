//! The sensor contract (Wave 4 restructure: R08c's skeleton, lab PR 252;
//! R13, lab PR 271 — plan §3.6, report 06 INI-09 and R4-01).
//!
//! For each source of the bus — a ring's pump, a drain — the agent declares
//! where its events come from (its attach point, and each fallback), what
//! decides on an event before the operation it reports completes (the
//! synchronous verdict), what a failure of the source means (fail-open,
//! fail-closed, blind), the kernel's budgets that hold its records back
//! before its ring, what its records cut (the truncations, with their real
//! bytes) and where its losses are counted (the stages of plan §3.4). For
//! each class of events the contract is derived from its sources' and from
//! the bus's own parameters: its queue, what a full queue does, the
//! decision's budget ([`class_contracts`]).
//!
//! This half is portable: the types, the kinds of events ([`EventKind`]),
//! the derivation of the class contracts and the check that every class and
//! every kind of event has its entry ([`check`]). The Linux values are
//! nn-linux's (`sensors::contract::SOURCES`), whose tests run [`check`]
//! over them, and a test of the agent's reads its sources: a pump or a drain
//! the code starts without an entry here fails it. The capability manifest
//! the boot signs ([`manifest`]) states each source's attach and state on
//! this boot against its contract.

use nn_model::{Event, EventClass};
use serde::{Deserialize, Serialize};

use crate::bus::{LossStage, Priority, DECISION_BUDGET_NS, SPECS};

pub mod manifest;

#[cfg(test)]
mod tests;

/// Bumped when a term of the contract changes meaning or goes; the manifest
/// signs it (`contract_version`).
pub const CONTRACT_VERSION: u32 = 1;

macro_rules! event_kinds {
    ($($(#[doc = $d:literal])* $kind:ident => $class:expr,)+) => {
        /// The kind of an event: an [`Event`] variant without its fields
        /// (R13). The enum and its list, [`EventKind::ALL`], are made by one
        /// macro, so a kind cannot be left out of the list; [`EventKind::of`]
        /// is an exhaustive match, so a new variant of [`Event`] does not
        /// compile until it has its kind — and [`check`] fails until a source
        /// of the contract sends it.
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
        pub enum EventKind {
            $($(#[doc = $d])* $kind,)+
        }

        impl EventKind {
            /// Every kind, in the declaration's order.
            pub const ALL: &'static [EventKind] = &[$(EventKind::$kind),+];

            /// Its name: the [`Event`] variant's.
            pub const fn name(self) -> &'static str {
                match self {
                    $(EventKind::$kind => stringify!($kind),)+
                }
            }

            /// The class of its events ([`crate::bus::class_of`] reads it);
            /// `None` for [`EventKind::CanaryTripped`], whose class is the
            /// class of the event it replaces.
            pub const fn class(self) -> Option<EventClass> {
                match self {
                    $(EventKind::$kind => $class,)+
                }
            }
        }
    };
}

event_kinds! {
    /// A refused operation on the agent's files, processes or maps.
    FsProtectDenial => Some(EventClass::Tamper),
    /// A `bpf()` call.
    BpfSyscall => Some(EventClass::Tamper),
    /// A kernel module loaded.
    ModuleLoad => Some(EventClass::Tamper),
    /// A sensor's own kernel budget dropped a flood.
    SensorFlood => Some(EventClass::Tamper),
    /// A signal to another security tool.
    DefenderSignal => Some(EventClass::Tamper),
    /// Privilege gained with no mechanism for it.
    ExploitPostcondition => Some(EventClass::Tamper),
    /// A process executed.
    ProcessSpawn => Some(EventClass::Process),
    /// An exec judged before it runs (the exec sensor's record).
    ExecCheck => Some(EventClass::Process),
    /// An io_uring ring made or used.
    IoUring => Some(EventClass::Process),
    /// A file integrity record.
    Fim => Some(EventClass::File),
    /// A process writing many files.
    MassWrite => Some(EventClass::File),
    /// A file opened.
    FileOpen => Some(EventClass::File),
    /// A burst of renames or unlinks.
    FileBurst => Some(EventClass::File),
    /// A TCP connect.
    TcpConnect => Some(EventClass::Network),
    /// A DNS query.
    DnsQuery => Some(EventClass::Network),
    /// A process's DNS queries over its kernel budget.
    DnsFlood => Some(EventClass::Network),
    /// A network flow's row.
    NetFlow => Some(EventClass::Network),
    /// A listening socket.
    NetListener => Some(EventClass::Network),
    /// Lot 275: an inbound TCP connection's row (accepted, closed).
    NetInbound => Some(EventClass::Network),
    /// Lot 275: a DNS response a process received.
    DnsAnswer => Some(EventClass::Network),
    /// Lot 275: an outbound flow's TLS ClientHello.
    TlsClientHello => Some(EventClass::Network),
    /// A canary token tripped (made by the canary detector, not a source).
    CanaryTripped => None,
}

impl EventKind {
    /// The kind of `event`.
    pub fn of(event: &Event) -> Self {
        match event {
            Event::FsProtectDenial { .. } => EventKind::FsProtectDenial,
            Event::BpfSyscall { .. } => EventKind::BpfSyscall,
            Event::ModuleLoad { .. } => EventKind::ModuleLoad,
            Event::SensorFlood { .. } => EventKind::SensorFlood,
            Event::DefenderSignal { .. } => EventKind::DefenderSignal,
            Event::ExploitPostcondition { .. } => EventKind::ExploitPostcondition,
            Event::ProcessSpawn { .. } => EventKind::ProcessSpawn,
            Event::ExecCheck { .. } => EventKind::ExecCheck,
            Event::IoUring { .. } => EventKind::IoUring,
            Event::Fim(_) => EventKind::Fim,
            Event::MassWrite { .. } => EventKind::MassWrite,
            Event::FileOpen { .. } => EventKind::FileOpen,
            Event::FileBurst { .. } => EventKind::FileBurst,
            Event::TcpConnect { .. } => EventKind::TcpConnect,
            Event::DnsQuery { .. } => EventKind::DnsQuery,
            Event::DnsFlood { .. } => EventKind::DnsFlood,
            Event::NetFlow(_) => EventKind::NetFlow,
            Event::NetListener(_) => EventKind::NetListener,
            Event::NetInbound(_) => EventKind::NetInbound,
            Event::DnsAnswer(_) => EventKind::DnsAnswer,
            Event::TlsClientHello(_) => EventKind::TlsClientHello,
            Event::CanaryTripped { .. } => EventKind::CanaryTripped,
        }
    }
}

/// The kinds no source sends: the canary detector makes a
/// [`EventKind::CanaryTripped`] inside the decision from the source event it
/// replaces (that event's source and class are its contract).
pub const DERIVED_KINDS: [EventKind; 1] = [EventKind::CanaryTripped];

/// The classes no source sends yet: no event is of the health class — the
/// sensors' health is the manifest's, the telemetry probe's and the
/// heartbeat's (their contract is [`HEALTH_TERMS`]).
pub const CLASSES_WITHOUT_SOURCE: [EventClass; 1] = [EventClass::Health];

/// What stands for the health class's sources until an event is of it.
pub const HEALTH_TERMS: &str = "no event is of this class yet: the sensors' health is the signed \
     capability manifest's (each source's attach and state, a change signed), the telemetry \
     probe's (an exec, a file open and a DNS datagram a minute, each signed when it does not \
     arrive: telemetry_gap) and the heartbeat's (every 30 s, off the host)";

/// What decides on an event before the operation it reports completes
/// (plan §3.6).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum SyncVerdict {
    /// Nothing: the event reports what happened.
    None,
    /// The kernel refuses the operation, on these hooks.
    KernelDeny { hooks: &'static str },
    /// User space decides within this deadline, the operation held.
    UserDeadline {
        deadline_ms: u64,
        holds: &'static str,
    },
}

impl SyncVerdict {
    /// As the manifest and `nn-admin capabilities` print it.
    pub fn describe(&self) -> String {
        match self {
            SyncVerdict::None => "none (the event reports what happened)".to_string(),
            SyncVerdict::KernelDeny { hooks } => format!("kernel deny on {hooks}"),
            SyncVerdict::UserDeadline { deadline_ms, holds } => {
                format!("user-space deadline {deadline_ms} ms ({holds})")
            }
        }
    }
}

/// What a failure of a source means (plan §3.6).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FailureMode {
    /// The operations go on, unchecked (a deny hook that cannot decide lets
    /// the operation through).
    FailOpen,
    /// The operations are refused, or the agent does not run without it.
    FailClosed,
    /// Nothing of the source is seen until it is back.
    Blind,
}

impl FailureMode {
    /// `fail-open`, `fail-closed`, `blind`.
    pub const fn name(self) -> &'static str {
        match self {
            FailureMode::FailOpen => "fail-open",
            FailureMode::FailClosed => "fail-closed",
            FailureMode::Blind => "blind",
        }
    }
}

/// A field a record cuts at a bound.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct Truncation {
    /// The field (`argv`, `qname`).
    pub field: &'static str,
    /// The bytes kept at most.
    pub max_bytes: u32,
    /// How a reader knows it was cut (a flag, or nothing).
    pub marked: &'static str,
}

/// A budget the kernel holds a source's records to, before its ring
/// (stage 2): past it the records are counted, not sent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct KernelBudget {
    /// What it allows (`64 queries a second per process`).
    pub allows: &'static str,
    /// The `RING_DROPS` slot that counts what it holds back.
    pub counter: &'static str,
}

/// Lot 273b (the review of #489): what an attach point of a source costs
/// the host, measured — an explicit budget the manifest signs with the
/// contract's terms.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct Overhead {
    /// The program and the calls it runs on.
    pub what: &'static str,
    /// What it costs, as the lab measured it.
    pub cost: &'static str,
}

/// An attach point a source falls back to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct Fallback {
    /// As the boot notes it, whole (the review of #479, X1: matched
    /// exactly, never by a prefix).
    pub attach: &'static str,
    /// When it is taken.
    pub when: &'static str,
    /// What it costs.
    pub costs: &'static str,
    /// It covers what the attach point covers: the source is `ok` on it.
    /// Otherwise the source is `partial` on it, with what it costs and the
    /// kinds of events it no longer sends (`lost`).
    pub equivalent: bool,
    pub lost: &'static [EventKind],
}

/// A verdict an operator's opt-in adds to a source.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct OptIn {
    pub verdict: SyncVerdict,
    /// The opt-in, as an operator sets it.
    pub when: &'static str,
    /// Its key in the boot's list of the opt-ins configured
    /// (`SourceFacts::opt_ins`).
    pub key: &'static str,
    /// It runs in a BPF LSM program: without `bpf` in the active LSM list
    /// it is configured and inert (the review of #479).
    pub needs_bpf_lsm: bool,
}

/// What a source of the bus is promised (plan §3.6).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct SourceContract {
    /// The bus's name of the source (the pump's or the drain's label).
    pub source: &'static str,
    /// The attach points the boot notes for it (the manifest's `sensors`);
    /// the first is the one its state is read from.
    pub sensors: &'static [&'static str],
    /// The kinds of the events it sends.
    pub events: &'static [EventKind],
    /// Its attach point, whole, as the boot notes it; and the same attach
    /// point under another kernel's names (`also`). A note is `ok` only
    /// when its attach code says it took it whole and the note is one of
    /// these exactly (the review of #479, X1).
    pub attach: &'static str,
    pub also: &'static [&'static str],
    /// Its programs are BPF LSM programs: without `bpf` in the active LSM
    /// list they attach and never run.
    pub needs_bpf_lsm: bool,
    /// What of it still runs without the BPF LSM, when part of it does
    /// (then `partial`, not `attached_not_invoked`).
    pub lsm_part: Option<&'static str>,
    /// Where it goes when the attach point is not there or not wanted.
    pub fallbacks: &'static [Fallback],
    /// What decides before the operation completes, as shipped; and the
    /// verdict an operator's opt-in adds.
    pub sync_verdict: SyncVerdict,
    pub opt_in: Option<OptIn>,
    /// What a failure of it means, and what the agent does then.
    pub on_failure: FailureMode,
    pub on_failure_detail: &'static str,
    /// The kernel's budgets before its ring (stage 2).
    pub kernel_budgets: &'static [KernelBudget],
    /// Lot 273b: what its programs cost the host, where it is more than
    /// noise (the deny hooks on every path walk and every write).
    pub overhead: &'static [Overhead],
    /// What its records cut.
    pub truncations: &'static [Truncation],
    /// Its rings' `RING_DROPS` slots (stage 1).
    pub rings: &'static [&'static str],
    /// The sensor self-test's word on it (the telemetry probe's sensor that
    /// exercises it), if any — lot 280c: every source has one.
    pub probe: Option<&'static str>,
    /// Lot 280c: that word is a check of its attach (each of its programs
    /// still linked), not a live event: no cheap, harmless operation makes
    /// it report (a module load, an exploit's post-condition, a DNS
    /// response from port 53, which the unit cannot bind).
    pub attach_check: bool,
    /// The deny self-test exercises it (one of its hooks, at the boot).
    pub self_tested: bool,
    /// The degradation registry's sources that are about it (their entries
    /// are the manifest's reasons for its state).
    pub degradation_sources: &'static [&'static str],
    /// The source whose fallback this one is: it is attached and inert
    /// while that source runs on its own attach point (the file-open
    /// tracepoint's pump, the LSM file-open sensor's fallback).
    pub standby_for: Option<&'static str>,
}

impl SourceContract {
    /// The classes of its events, in [`EventClass::ALL`]'s order.
    pub fn classes(&self) -> Vec<EventClass> {
        EventClass::ALL
            .into_iter()
            .filter(|c| self.events.iter().any(|k| k.class() == Some(*c)))
            .collect()
    }

    /// The stages that count what it loses: its rings (1), its kernel
    /// budgets (2), the decoder (3, every ring's records), and for each class
    /// of its events the bus's queue (4) and the decision's delay (5).
    pub fn loss_counters(&self) -> Vec<LossStage> {
        let mut out = Vec::new();
        if !self.rings.is_empty() {
            out.push(LossStage::KernelRing);
        }
        if !self.kernel_budgets.is_empty() {
            out.push(LossStage::KernelBudget);
        }
        if !self.rings.is_empty() {
            out.push(LossStage::Decode);
        }
        for c in self.classes() {
            out.push(LossStage::BusQueue(c));
        }
        for c in self.classes() {
            out.push(LossStage::DecisionDelay(c));
        }
        out
    }
}

/// What a class of events is promised: its sources' terms and the bus's
/// (plan §3.6), derived by [`class_contracts`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ClassContract {
    /// The class.
    pub class: EventClass,
    /// Its queue on the bus, the queue's capacity and what it does when
    /// full.
    pub queue: &'static str,
    pub queue_capacity: usize,
    pub when_full: String,
    /// The decision's budget from the record's kernel time (stage 5).
    pub decision_budget_ms: u64,
    /// Its sources; empty for a class no source sends yet ([`HEALTH_TERMS`]).
    pub sources: Vec<&'static str>,
    /// The strongest synchronous verdict among its sources as shipped (a
    /// kernel deny over a deadline over none).
    pub sync_verdict: SyncVerdict,
    /// The worst failure among its sources (blind over fail-open over
    /// fail-closed: what an operator must expect); `None` without a source.
    pub on_failure: Option<FailureMode>,
    /// The stages that count its losses.
    pub loss_counters: Vec<LossStage>,
    /// Why it has no source, when it has none.
    pub note: Option<&'static str>,
}

/// The contracts of every class (one per [`EventClass::ALL`], in its order),
/// derived from `sources` and the bus's parameters.
pub fn class_contracts(sources: &[SourceContract]) -> Vec<ClassContract> {
    EventClass::ALL
        .into_iter()
        .map(|class| {
            let of: Vec<&SourceContract> = sources
                .iter()
                .filter(|s| s.classes().contains(&class))
                .collect();
            let q = Priority::of(class);
            let spec = SPECS[q.index()];
            let sync_verdict = of
                .iter()
                .map(|s| s.sync_verdict)
                .max_by_key(|v| match v {
                    SyncVerdict::None => 0,
                    SyncVerdict::UserDeadline { .. } => 1,
                    SyncVerdict::KernelDeny { .. } => 2,
                })
                .unwrap_or(SyncVerdict::None);
            let on_failure = of.iter().map(|s| s.on_failure).max_by_key(|f| match f {
                FailureMode::FailClosed => 0,
                FailureMode::FailOpen => 1,
                FailureMode::Blind => 2,
            });
            let mut loss_counters: Vec<LossStage> = Vec::new();
            for s in &of {
                for st in s.loss_counters() {
                    let keep = match st {
                        LossStage::BusQueue(c) | LossStage::DecisionDelay(c) => c == class,
                        _ => true,
                    };
                    if keep && !loss_counters.contains(&st) {
                        loss_counters.push(st);
                    }
                }
            }
            loss_counters.sort_by_key(|st| st.number());
            ClassContract {
                class,
                queue: q.label(),
                queue_capacity: spec.capacity,
                when_full: spec.when_full.describe(),
                decision_budget_ms: DECISION_BUDGET_NS[q.index()] / 1_000_000,
                sources: of.iter().map(|s| s.source).collect(),
                sync_verdict,
                on_failure,
                loss_counters,
                note: CLASSES_WITHOUT_SOURCE
                    .contains(&class)
                    .then_some(HEALTH_TERMS),
            }
        })
        .collect()
}

/// What is wrong with `sources` as a contract: an entry missing for a kind
/// of event or a class, a source or an attach point named twice, a source
/// that sends nothing, an LSM source whose attach is not an LSM hook. Empty
/// when it holds.
pub fn check(sources: &[SourceContract]) -> Vec<String> {
    let mut problems = Vec::new();
    for kind in EventKind::ALL {
        if DERIVED_KINDS.contains(kind) {
            continue;
        }
        if !sources.iter().any(|s| s.events.contains(kind)) {
            problems.push(format!(
                "no source of the contract sends {} events",
                kind.name()
            ));
        }
    }
    for class in EventClass::ALL {
        let sent = sources.iter().any(|s| s.classes().contains(&class));
        match (sent, CLASSES_WITHOUT_SOURCE.contains(&class)) {
            (false, false) => problems.push(format!(
                "no source of the contract sends the {} class",
                class.name()
            )),
            (true, true) => problems.push(format!(
                "the {} class has a source now: take it out of CLASSES_WITHOUT_SOURCE",
                class.name()
            )),
            _ => {}
        }
    }
    for (i, s) in sources.iter().enumerate() {
        if sources[..i].iter().any(|o| o.source == s.source) {
            problems.push(format!("source {} has two entries", s.source));
        }
        for sensor in s.sensors {
            if sources[..i].iter().any(|o| o.sensors.contains(sensor)) {
                problems.push(format!("attach point {sensor} is in two sources"));
            }
        }
        if s.events.is_empty() {
            problems.push(format!("source {} sends no kind of event", s.source));
        }
        if s.events.iter().any(|k| DERIVED_KINDS.contains(k)) {
            problems.push(format!("source {} names a derived kind", s.source));
        }
        if s.needs_bpf_lsm && !s.attach.starts_with("lsm:") {
            problems.push(format!(
                "source {} needs the BPF LSM but its attach is {}",
                s.source, s.attach
            ));
        }
        for f in s.fallbacks {
            if f.equivalent && !f.lost.is_empty() {
                problems.push(format!(
                    "source {}: the fallback {} is equivalent and loses events",
                    s.source, f.attach
                ));
            }
            if f.lost.iter().any(|k| !s.events.contains(k)) {
                problems.push(format!(
                    "source {}: the fallback {} loses a kind the source does not send",
                    s.source, f.attach
                ));
            }
        }
        if s.attach_check && s.probe.is_none() {
            problems.push(format!(
                "source {}: an attach check without the self-test's word",
                s.source
            ));
        }
        if s.lsm_part.is_some() && !s.needs_bpf_lsm {
            problems.push(format!(
                "source {}: part of it without the BPF LSM, and it needs none",
                s.source
            ));
        }
        if let Some(other) = s.standby_for {
            if !sources.iter().any(|o| o.source == other) {
                problems.push(format!(
                    "source {} is the fallback of {other}, which has no entry",
                    s.source
                ));
            }
        }
    }
    problems
}
