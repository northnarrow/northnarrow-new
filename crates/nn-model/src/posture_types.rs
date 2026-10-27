//! Adaptive Defensive Posture types (Sub-tappa 6.5).
//!
//! These structs are the serializable, on-the-wire portion of the
//! posture state machine. The agent crate keeps a richer runtime
//! representation around (with `std::time::Instant` timestamps and
//! `RwLock`s); these types are what cross logging, audit and future
//! C2 boundaries.
//!
//! Design rules:
//!
//! - `PostureKind` is a flat enum, ordered by gravity. Comparison is
//!   meaningful (`PostureKind::Observing < PostureKind::Combat`).
//! - `TriggerType` enumerates every condition that can drive a
//!   transition. New triggers append at the end (stable
//!   serialization).
//! - `PostureTransition` is the audit record: it captures the
//!   from/to states, the firing trigger (or `None` for decay), a
//!   wall-clock unix timestamp, and a short reason string.

use alloc::string::String;
use serde::{Deserialize, Serialize};

/// Defensive posture levels, ordered by gravity (Observing < Combat).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum PostureKind {
    /// Baseline. No suspicious correlation observed.
    Observing,
    /// Reconnaissance / recon-adjacent signals seen.
    Alerted,
    /// Active exploitation or critical file mutation observed.
    Engaged,
    /// Confirmed compromise. No automatic exit.
    Combat,
}

impl PostureKind {
    /// Canonical PascalCase rendering used in logs and on the wire.
    pub fn as_str(&self) -> &'static str {
        match self {
            PostureKind::Observing => "OBSERVING",
            PostureKind::Alerted => "ALERTED",
            PostureKind::Engaged => "ENGAGED",
            PostureKind::Combat => "COMBAT",
        }
    }
}

impl core::fmt::Display for PostureKind {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Triggers that can drive an upward posture transition.
///
/// The variant ordering tracks the level of escalation a trigger
/// produces (recon < exploit < intrusion). New entries append.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TriggerType {
    // OBSERVING -> ALERTED
    Reconnaissance,
    SuspiciousDns,
    SensitiveFileAccess,
    Lolbas,

    // ALERTED -> ENGAGED
    ExploitAttempt,
    AdjacentCompromise,
    HeavyReconnaissance,
    CriticalFileModification,

    // ENGAGED -> COMBAT
    ConfirmedIntrusion,
    PersistenceMechanism,
    LateralMovement,
    ExfiltrationPattern,

    // Decisive (kernel-adjudicated) — straight to COMBAT, no
    // corroboration required. Appended last to keep variant ordering
    // stable (BUG-032). Split out of `ConfirmedIntrusion`'s
    // FsProtectDenial arm: a *denied* anti-tamper attempt is the kernel
    // having already blocked malice, not a heuristic pattern.
    AntiTamperDenial,

    // External audit EBPF-001: a signal to the agent or the watchdog that
    // PID 1 relayed (`systemctl stop`/`kill`/`restart`) outside a signed
    // trusted-installer window, refused by the kernel. The requester is
    // not known — systemd only relays it — so it raises ENGAGED, never a
    // COMBAT with init as the offender (whose only containment would be
    // ISOLATE). Appended last to keep variant ordering stable.
    RelayedTamperAttempt,

    // External audit SNS-009: a security ring buffer lost events (the
    // kernel could not reserve an entry). A blind spot, not behaviour: it
    // raises ALERTED and never corroborates a COMBAT-tier signal (its
    // evidence class is `Telemetry`, and an ALERTED-tier trigger is never
    // recorded in the corroboration ledger). Appended last to keep variant
    // ordering stable.
    TelemetryLoss,

    // External audit POS-015: a binary run from a staging directory
    // (`/tmp`, `/var/tmp`, `/dev/shm`) with no second factor — a build's
    // `conftest`, a self-extracting installer, as well as a dropper. It
    // raises ENGAGED and is never recorded in the corroboration ledger
    // ([`TriggerType::is_corroboration`]); with a second factor the agent
    // observes, the exec raises `ConfirmedIntrusion` instead. Appended last
    // to keep variant ordering stable.
    StagingExec,

    // Lab PR 162: a tamper of an anti-tamper control-surface file (the
    // match of NN-L-FIM-024: `kill_switch.conf`, `pause.flag`, …). No
    // workflow touches those files while the agent runs, so the tamper is
    // as decisive as a denial: straight to COMBAT, locked. The name says
    // what the rule's name says and no more: whoever reads the journal of
    // a compromised host must not learn that the files are bait. Appended
    // last to keep variant ordering stable.
    ControlSurfaceTamper,

    // Lab PR 219: the exploit post-condition guard found a task that gained
    // credentials, or left its namespaces or its root, with no legitimate
    // mechanism for its system call (NN-L-EPG-001/002). Kernel evidence,
    // COMBAT tier, but it needs corroboration while the guard is
    // experimental: a false positive of a new kernel heuristic must not lock
    // COMBAT and isolate the host on its own (design note, "Response").
    // Appended last to keep variant ordering stable.
    ExploitPostcondition,

    // Lab PR 225: one process's file activity has two of the four shapes of
    // ransomware at once — rewrites of existing files, high-entropy content
    // over them, renames to one new extension, deletion of originals after
    // writing new files — from a writer whose trust (a package transaction,
    // or a packaged program with no foreign program in its lineage) is not
    // established (NN-L-IMP-001). The combination is its own corroboration:
    // straight to COMBAT. It does not lock COMBAT (any user can encrypt
    // their own files: external audit POS-001), so the ladder contains at the
    // process level and the posture decays once quiet. Appended last to keep
    // variant ordering stable.
    RansomwareEncryption,

    // Lab PR 225: a security tool of the host — auditd, AppArmor, the
    // firewall, an EDR or cloud agent of the signed list
    // `security-tools.v1` — stopped, disabled, masked, killed, switched off
    // by its own command or its configuration changed, outside a package
    // transaction and an administrator's interactive session
    // (NN-L-EVA-001..004). ENGAGED: it vouches for a later COMBAT-tier
    // heuristic of another kind from the same actor. Appended last to keep
    // variant ordering stable.
    DefenseImpairment,
}

/// Lab PR 225, held by the decision of 21/10/2026 (no new destructive
/// automation on by default until the signed per-rule response policy,
/// Phase 2): whether [`TriggerType::RansomwareEncryption`] — two shapes of
/// one actor's file activity — reaches COMBAT without corroboration
/// ([`Confidence::Decisive`]). Off: it needs corroboration like the other
/// heuristics — ENGAGED alone, COMBAT when a signal of another class in its
/// scope vouches for it. NN-L-IMP-001's kill is held with it
/// (`decision::response_policy::IMP_001_KILL` in the agent).
///
/// The built-in default. Lab PR 236: a signed per-rule policy turns it on
/// (`combat-without-corroboration NN-L-IMP-001`); lab PR 249: the value in
/// force is the posture machine's own — the policy it reads — passed to
/// [`TriggerType::confidence`] (it was a process-wide switch, so two
/// machines could not hold two values, nor a test change it without racing
/// every other one).
pub const RANSOMWARE_COMBAT_WITHOUT_CORROBORATION: bool = false;

/// How much trust a [`TriggerType`] carries when it targets COMBAT.
///
/// BUG-032: only a *Decisive* signal escalates straight to locked
/// COMBAT (auto-isolation). A *NeedsCorroboration* signal is a
/// heuristic pattern that can be legitimate, so on its own it stops at
/// ENGAGED (alert) and reaches COMBAT only with a second distinct
/// escalation signal. Irrelevant for triggers below COMBAT tier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Confidence {
    /// Kernel-adjudicated malice (e.g. an LSM denial). Straight to COMBAT.
    Decisive,
    /// Heuristic pattern — needs corroboration before auto-isolation.
    NeedsCorroboration,
}

/// External audit POS-001 (NN-AUD-002): the kind of evidence a trigger
/// is. Two heuristic signals corroborate each other only across classes:
/// two network patterns (an update's twenty HTTPS connections, then three
/// internal SSH sessions) are one kind of behaviour, not two pieces of
/// evidence, and any unprivileged user produces both.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EvidenceClass {
    Network,
    Execution,
    FileSystem,
    Kernel,
    /// External audit SNS-009: a loss of visibility, not evidence of
    /// behaviour. Never corroborates anything.
    Telemetry,
}

impl TriggerType {
    /// The kind of evidence this trigger is ([`EvidenceClass`]).
    pub fn evidence_class(&self) -> EvidenceClass {
        match self {
            TriggerType::Reconnaissance
            | TriggerType::SuspiciousDns
            | TriggerType::HeavyReconnaissance
            | TriggerType::AdjacentCompromise
            | TriggerType::LateralMovement
            | TriggerType::ExfiltrationPattern => EvidenceClass::Network,
            TriggerType::Lolbas
            | TriggerType::ExploitAttempt
            | TriggerType::ConfirmedIntrusion
            | TriggerType::StagingExec => EvidenceClass::Execution,
            TriggerType::SensitiveFileAccess
            | TriggerType::CriticalFileModification
            | TriggerType::PersistenceMechanism
            | TriggerType::RansomwareEncryption => EvidenceClass::FileSystem,
            TriggerType::DefenseImpairment => EvidenceClass::Execution,
            TriggerType::AntiTamperDenial
            | TriggerType::RelayedTamperAttempt
            | TriggerType::ControlSurfaceTamper
            | TriggerType::ExploitPostcondition => EvidenceClass::Kernel,
            TriggerType::TelemetryLoss => EvidenceClass::Telemetry,
        }
    }

    /// Highest posture level this trigger can promote to.
    pub fn target_level(&self) -> PostureKind {
        match self {
            TriggerType::Reconnaissance
            | TriggerType::SuspiciousDns
            | TriggerType::SensitiveFileAccess
            | TriggerType::Lolbas
            | TriggerType::TelemetryLoss => PostureKind::Alerted,

            TriggerType::ExploitAttempt
            | TriggerType::AdjacentCompromise
            | TriggerType::HeavyReconnaissance
            | TriggerType::CriticalFileModification
            | TriggerType::RelayedTamperAttempt
            | TriggerType::StagingExec
            | TriggerType::DefenseImpairment => PostureKind::Engaged,

            TriggerType::ConfirmedIntrusion
            | TriggerType::PersistenceMechanism
            | TriggerType::LateralMovement
            | TriggerType::ExfiltrationPattern
            | TriggerType::AntiTamperDenial
            | TriggerType::ControlSurfaceTamper
            | TriggerType::ExploitPostcondition
            | TriggerType::RansomwareEncryption => PostureKind::Combat,
        }
    }

    /// Whether a signal of this trigger is recorded in the corroboration
    /// ledger, where it can vouch for a later COMBAT-tier heuristic of
    /// another class: ENGAGED tier and above (ALERTED-tier recon and DNS
    /// are too noisy), except a staging-directory exec without a second
    /// factor (external audit POS-015: any user, and any build, produces
    /// one, and it was the cheapest half of a COMBAT pair).
    pub fn is_corroboration(&self) -> bool {
        self.target_level() >= PostureKind::Engaged && *self != TriggerType::StagingExec
    }

    /// Trust class for COMBAT-targeting triggers (BUG-032). Only
    /// [`Confidence::Decisive`] escalates straight to COMBAT; every
    /// heuristic pattern is [`Confidence::NeedsCorroboration`].
    /// [`TriggerType::RansomwareEncryption`] is decisive only when
    /// `ransomware_combat_without_corroboration` is on — the asking posture
    /// machine's value (lab PR 249; [`RANSOMWARE_COMBAT_WITHOUT_CORROBORATION`],
    /// off, by default; lab PR 236: the signed per-rule policy's directive).
    pub fn confidence(&self, ransomware_combat_without_corroboration: bool) -> Confidence {
        match self {
            TriggerType::AntiTamperDenial | TriggerType::ControlSurfaceTamper => {
                Confidence::Decisive
            }
            TriggerType::RansomwareEncryption if ransomware_combat_without_corroboration => {
                Confidence::Decisive
            }
            _ => Confidence::NeedsCorroboration,
        }
    }

    /// Lab PR 225: whether this trigger alone LOCKS the COMBAT it reaches
    /// (external audit POS-001: no decay, a signed release, the ladder may
    /// isolate the host). Only evidence an unprivileged user cannot produce:
    /// a kernel-adjudicated denial, a tamper of the anti-tamper control
    /// surface. [`TriggerType::RansomwareEncryption`] is decisive — it
    /// reaches COMBAT without corroboration — but it does not lock: any user
    /// can encrypt their own files, and a lock would let them have the host
    /// isolated. Its COMBAT locks only as POS-001 says for every other
    /// signal (corroborated in its scope by root's change outside an
    /// administrator's session).
    pub fn locks_combat(&self) -> bool {
        matches!(
            self,
            TriggerType::AntiTamperDenial | TriggerType::ControlSurfaceTamper
        )
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            TriggerType::Reconnaissance => "Reconnaissance",
            TriggerType::SuspiciousDns => "SuspiciousDns",
            TriggerType::SensitiveFileAccess => "SensitiveFileAccess",
            TriggerType::Lolbas => "Lolbas",
            TriggerType::ExploitAttempt => "ExploitAttempt",
            TriggerType::AdjacentCompromise => "AdjacentCompromise",
            TriggerType::HeavyReconnaissance => "HeavyReconnaissance",
            TriggerType::CriticalFileModification => "CriticalFileModification",
            TriggerType::ConfirmedIntrusion => "ConfirmedIntrusion",
            TriggerType::PersistenceMechanism => "PersistenceMechanism",
            TriggerType::LateralMovement => "LateralMovement",
            TriggerType::ExfiltrationPattern => "ExfiltrationPattern",
            TriggerType::AntiTamperDenial => "AntiTamperDenial",
            TriggerType::RelayedTamperAttempt => "RelayedTamperAttempt",
            TriggerType::TelemetryLoss => "TelemetryLoss",
            TriggerType::StagingExec => "StagingExec",
            TriggerType::ControlSurfaceTamper => "ControlSurfaceTamper",
            TriggerType::ExploitPostcondition => "ExploitPostcondition",
            TriggerType::RansomwareEncryption => "RansomwareEncryption",
            TriggerType::DefenseImpairment => "DefenseImpairment",
        }
    }
}

impl core::fmt::Display for TriggerType {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One audit record per posture state change.
///
/// `trigger` is `None` for decay transitions (timer-driven down-shift).
/// `unix_ts_secs` is a wall-clock timestamp, captured at the moment of
/// the transition (not used by the state machine itself; the runtime
/// uses monotonic `Instant`s, immune to NTP jumps).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PostureTransition {
    pub from: PostureKind,
    pub to: PostureKind,
    pub trigger: Option<TriggerType>,
    pub unix_ts_secs: u64,
    pub reason: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::string::ToString;

    #[test]
    fn posture_kind_orders_by_gravity() {
        assert!(PostureKind::Observing < PostureKind::Alerted);
        assert!(PostureKind::Alerted < PostureKind::Engaged);
        assert!(PostureKind::Engaged < PostureKind::Combat);
    }

    #[test]
    fn trigger_target_levels_are_consistent() {
        assert_eq!(
            TriggerType::Reconnaissance.target_level(),
            PostureKind::Alerted
        );
        assert_eq!(
            TriggerType::ExploitAttempt.target_level(),
            PostureKind::Engaged
        );
        assert_eq!(
            TriggerType::ConfirmedIntrusion.target_level(),
            PostureKind::Combat
        );
    }

    /// External audit SNS-009: a ring that lost events raises ALERTED only,
    /// and is a class of its own (it corroborates nothing).
    #[test]
    fn telemetry_loss_targets_alerted_in_its_own_class() {
        let t = TriggerType::TelemetryLoss;
        assert_eq!(t.target_level(), PostureKind::Alerted);
        assert_eq!(
            t.confidence(RANSOMWARE_COMBAT_WITHOUT_CORROBORATION),
            Confidence::NeedsCorroboration
        );
        assert_eq!(t.evidence_class(), EvidenceClass::Telemetry);
        assert_eq!(t.as_str(), "TelemetryLoss");
    }

    /// External audit POS-015: a staging-directory exec without a second
    /// factor is execution evidence at ENGAGED tier that never enters the
    /// ledger; the other ENGAGED-and-above triggers do.
    #[test]
    fn staging_exec_engages_and_is_not_corroboration() {
        let t = TriggerType::StagingExec;
        assert_eq!(t.target_level(), PostureKind::Engaged);
        assert_eq!(t.evidence_class(), EvidenceClass::Execution);
        assert_eq!(t.as_str(), "StagingExec");
        assert!(!t.is_corroboration());
        assert!(TriggerType::ConfirmedIntrusion.is_corroboration());
        assert!(TriggerType::ExploitAttempt.is_corroboration());
        assert!(!TriggerType::Reconnaissance.is_corroboration());
        assert!(!TriggerType::TelemetryLoss.is_corroboration());
    }

    /// Lab PR 162: a control-surface tamper is anti-tamper evidence that
    /// reaches a locked COMBAT on its own, and its name, which the journal
    /// shows, does not give the bait away.
    #[test]
    fn control_surface_tamper_is_decisive_anti_tamper_evidence() {
        let t = TriggerType::ControlSurfaceTamper;
        assert_eq!(t.target_level(), PostureKind::Combat);
        assert_eq!(
            t.confidence(RANSOMWARE_COMBAT_WITHOUT_CORROBORATION),
            Confidence::Decisive
        );
        assert_eq!(t.evidence_class(), EvidenceClass::Kernel);
        assert!(t.is_corroboration());
        assert_eq!(t.as_str(), "ControlSurfaceTamper");
        assert_eq!(alloc::format!("{t:?}"), "ControlSurfaceTamper");
        let name = t.as_str().to_lowercase();
        for banned in ["honeypot", "decoy", "canary", "bait", "trap"] {
            assert!(!name.contains(banned), "{name} names the {banned}");
        }
    }

    /// Lab PR 219: the guard's finding is kernel evidence of COMBAT tier
    /// that a second signal of another class must corroborate before it
    /// locks COMBAT (experimental guard: no isolation on its word alone).
    #[test]
    fn exploit_postcondition_is_kernel_evidence_needing_corroboration() {
        let t = TriggerType::ExploitPostcondition;
        assert_eq!(t.target_level(), PostureKind::Combat);
        assert_eq!(
            t.confidence(RANSOMWARE_COMBAT_WITHOUT_CORROBORATION),
            Confidence::NeedsCorroboration
        );
        assert_eq!(t.evidence_class(), EvidenceClass::Kernel);
        assert!(t.is_corroboration());
        assert_eq!(t.as_str(), "ExploitPostcondition");
    }

    /// Lab PR 225: the ransomware combination targets COMBAT, file-system
    /// evidence, never locking it (POS-001); it reaches COMBAT on its own
    /// only once the per-rule policy turns that on — until then it needs
    /// corroboration. The security-tool tamper raises ENGAGED as execution
    /// evidence that can corroborate. The kernel-adjudicated triggers keep
    /// their lock.
    #[test]
    fn ransomware_is_decisive_without_locking_and_defense_impairment_engages() {
        let r = TriggerType::RansomwareEncryption;
        assert_eq!(r.target_level(), PostureKind::Combat);
        const { assert!(!RANSOMWARE_COMBAT_WITHOUT_CORROBORATION) };
        assert_eq!(
            r.confidence(RANSOMWARE_COMBAT_WITHOUT_CORROBORATION),
            Confidence::NeedsCorroboration
        );
        // Lab PR 236: the signed policy's directive makes it decisive,
        // still never locking; off, it needs corroboration again. Lab PR
        // 249: the directive is the asking machine's, not the process's.
        assert_eq!(r.confidence(true), Confidence::Decisive);
        assert!(!r.locks_combat());
        assert_eq!(r.confidence(false), Confidence::NeedsCorroboration);
        // Only the ransomware trigger reads it.
        for t in [
            TriggerType::ConfirmedIntrusion,
            TriggerType::ExploitPostcondition,
            TriggerType::PersistenceMechanism,
        ] {
            assert_eq!(t.confidence(true), Confidence::NeedsCorroboration, "{t:?}");
        }
        for t in [
            TriggerType::AntiTamperDenial,
            TriggerType::ControlSurfaceTamper,
        ] {
            assert_eq!(t.confidence(false), Confidence::Decisive, "{t:?}");
        }
        assert_eq!(r.evidence_class(), EvidenceClass::FileSystem);
        assert!(!r.locks_combat());
        assert!(r.is_corroboration());
        assert_eq!(r.as_str(), "RansomwareEncryption");
        let d = TriggerType::DefenseImpairment;
        assert_eq!(d.target_level(), PostureKind::Engaged);
        assert_eq!(d.evidence_class(), EvidenceClass::Execution);
        assert!(d.is_corroboration());
        assert!(!d.locks_combat());
        assert_eq!(d.as_str(), "DefenseImpairment");
        assert!(TriggerType::AntiTamperDenial.locks_combat());
        assert!(TriggerType::ControlSurfaceTamper.locks_combat());
    }

    #[test]
    fn posture_transition_round_trips_through_serde_json() {
        let t = PostureTransition {
            from: PostureKind::Observing,
            to: PostureKind::Alerted,
            trigger: Some(TriggerType::Reconnaissance),
            unix_ts_secs: 1_700_000_000,
            reason: "demo".to_string(),
        };
        let json = serde_json::to_string(&t).expect("serialize");
        let parsed: PostureTransition = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(parsed.from, PostureKind::Observing);
        assert_eq!(parsed.to, PostureKind::Alerted);
        assert_eq!(parsed.trigger, Some(TriggerType::Reconnaissance));
    }

    #[test]
    fn decay_transition_serializes_without_trigger() {
        let t = PostureTransition {
            from: PostureKind::Alerted,
            to: PostureKind::Observing,
            trigger: None,
            unix_ts_secs: 1_700_000_000,
            reason: "decay 1h".to_string(),
        };
        let json = serde_json::to_string(&t).expect("serialize");
        assert!(json.contains("\"trigger\":null"));
    }
}
