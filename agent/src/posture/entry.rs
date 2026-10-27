//! Lab PR 245: what the posture hands the COMBAT ladder when it enters
//! COMBAT — why ([`CombatCause`]) and against whom ([`EntryProcess`]).
//!
//! The entry hook took no argument. `main.rs` opened the ladder's episode
//! from it (`engage(None, None)`) inside [`super::PostureMachine::observe`],
//! and `process_event` named the offender and the firing trigger to the
//! ladder only after `observe` returned: by then the episode was open, the
//! ladder merged the offender and dropped the trigger, and the signed
//! `combat_stage` rows of every COMBAT the posture reached said
//! `"trigger": null`, the INVESTIGATE row naming no offender (found by the
//! golden replay of lab PR 243). The hook now receives a [`CombatEntry`]
//! built where the posture decides: the episode opens with its cause and
//! its offender, and every row names them.

use nn_model::posture_types::{Confidence, EvidenceClass, TriggerType};
use nn_model::Event;
use serde_json::{json, Value};

use super::triggers;

/// What the posture knows when it enters COMBAT, handed to the entry hook.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CombatEntry {
    /// Why the posture entered COMBAT.
    pub cause: CombatCause,
    /// The process the event names ([`triggers::event_owner_pid`]), with
    /// what the event says about it. `None` for a forced COMBAT, and for an
    /// event that names no process. External audit EBPF-001: never init
    /// (nor pid 0) — its only containment would be ISOLATE, and the events
    /// it owns (a relayed `systemctl`, the console writes of a shutdown)
    /// are not its own.
    pub offender: Option<EntryProcess>,
}

/// The process an entry names, as the event names it (external audit
/// CMB-004: what identifies it after it has exited).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EntryProcess {
    pub pid: u32,
    /// Its start (an exec's, `CLOCK_MONOTONIC` ns); 0 when the event does
    /// not say.
    pub start_ns: u64,
    /// The event's time: it was running then. 0 when unknown.
    pub seen_ns: u64,
}

/// Why the posture entered COMBAT.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CombatCause {
    /// A trigger an event raised moved the posture to COMBAT.
    Trigger(TriggerEvidence),
    /// An administrator's signed force-posture; the fingerprints of the
    /// keys that signed it (empty when the caller did not say).
    AdminForce { signers: Vec<String> },
    /// `nn-admin debug force-posture` (`debug-trigger` builds only).
    DebugForce,
}

/// A posture trigger and the evidence it cites.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TriggerEvidence {
    /// The trigger that moved the posture to COMBAT.
    pub trigger: TriggerType,
    /// Every trigger the event raised, in the detector's order (the
    /// posture transition's reason).
    pub raised: Vec<TriggerType>,
    /// The kind of evidence `trigger` is, raised on this event
    /// ([`triggers::evidence_class`]).
    pub class: EvidenceClass,
    /// Decisive, or a heuristic that needed corroboration.
    pub confidence: Confidence,
    /// For a heuristic: the earlier signals of the actor's scope that
    /// vouched for it — trigger and kind of evidence, each once, sorted.
    /// Empty for a decisive trigger.
    pub corroborated_by: Vec<(TriggerType, EvidenceClass)>,
    /// External audit POS-001: COMBAT is locked — evidence an unprivileged
    /// user cannot produce (or an administrator's order); only then may the
    /// ladder isolate the host.
    pub locked: bool,
    /// The actor's scope the signal was judged in (`login uid 1000`,
    /// `workload /system.slice/apache2.service`, `unattributed`).
    pub scope: String,
    /// The event: its kind, the process it names, its time (the sensors'
    /// clock, ns; `None` when it carries none).
    pub event_kind: &'static str,
    pub event_pid: Option<u32>,
    pub event_ns: Option<u64>,
}

impl CombatEntry {
    /// The entry of a COMBAT that `evidence`, raised on `event`, reached:
    /// the offender is the process the event names.
    pub(crate) fn of_event(event: &Event, evidence: TriggerEvidence) -> Self {
        let (start_ns, seen_ns) = triggers::event_owner_seen(event);
        Self {
            cause: CombatCause::Trigger(evidence),
            offender: triggers::event_owner_pid(event)
                .filter(|pid| *pid > 1)
                .map(|pid| EntryProcess {
                    pid,
                    start_ns,
                    seen_ns,
                }),
        }
    }

    /// A forced COMBAT: no event, no offender.
    pub fn forced(cause: CombatCause) -> Self {
        Self {
            cause,
            offender: None,
        }
    }
}

impl CombatCause {
    /// The posture trigger, when an event's trigger is the cause.
    pub fn trigger(&self) -> Option<TriggerType> {
        match self {
            CombatCause::Trigger(t) => Some(t.trigger),
            CombatCause::AdminForce { .. } | CombatCause::DebugForce => None,
        }
    }

    /// The cause as a signed row carries it (`combat_stage`'s `cause`).
    pub fn to_json(&self) -> Value {
        match self {
            CombatCause::Trigger(t) => json!({
                "kind": "posture_trigger",
                "trigger": t.trigger.as_str(),
                "raised": t.raised.iter().map(|x| x.as_str()).collect::<Vec<_>>(),
                "class": format!("{:?}", t.class),
                "confidence": format!("{:?}", t.confidence),
                "corroborated_by": t
                    .corroborated_by
                    .iter()
                    .map(|(x, c)| json!({"trigger": x.as_str(), "class": format!("{c:?}")}))
                    .collect::<Vec<_>>(),
                "locked": t.locked,
                "scope": t.scope,
                "event": {
                    "kind": t.event_kind,
                    "pid": t.event_pid,
                    "timestamp_ns": t.event_ns,
                },
            }),
            CombatCause::AdminForce { signers } => json!({
                "kind": "admin_force_posture",
                "signers": signers,
            }),
            CombatCause::DebugForce => json!({"kind": "debug_force_posture"}),
        }
    }

    /// One line, for a row's reason and the journal.
    pub fn summary(&self) -> String {
        match self {
            CombatCause::Trigger(t) => {
                let mut s = format!(
                    "{} ({:?}, {:?}) on {}",
                    t.trigger.as_str(),
                    t.class,
                    t.confidence,
                    t.event_kind
                );
                if let Some(pid) = t.event_pid {
                    s.push_str(&format!(" of pid {pid}"));
                }
                s
            }
            CombatCause::AdminForce { signers } if signers.is_empty() => {
                "an administrator's signed force-posture".to_string()
            }
            CombatCause::AdminForce { signers } => format!(
                "an administrator's signed force-posture (key {})",
                signers.join(", ")
            ),
            CombatCause::DebugForce => "nn-admin debug force-posture".to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::posture::triggers::testutil::fs_protect_denial;

    fn evidence(trigger: TriggerType) -> TriggerEvidence {
        TriggerEvidence {
            trigger,
            raised: vec![trigger],
            class: trigger.evidence_class(),
            confidence: trigger.confidence(),
            corroborated_by: Vec::new(),
            locked: true,
            scope: "login uid 1000".to_string(),
            event_kind: "FsProtectDenial",
            event_pid: Some(4242),
            event_ns: Some(5),
        }
    }

    /// The entry names the event's process with what the event says of
    /// it; never init or pid 0 (external audit EBPF-001).
    #[test]
    fn an_event_entry_names_the_events_process_but_never_init() {
        let e = CombatEntry::of_event(
            &fs_protect_denial(4242, 77),
            evidence(TriggerType::AntiTamperDenial),
        );
        assert_eq!(
            e.offender,
            Some(EntryProcess {
                pid: 4242,
                start_ns: 0,
                seen_ns: 77
            })
        );
        assert_eq!(e.cause.trigger(), Some(TriggerType::AntiTamperDenial));
        for pid in [0, 1] {
            let e = CombatEntry::of_event(
                &fs_protect_denial(pid, 77),
                evidence(TriggerType::AntiTamperDenial),
            );
            assert_eq!(e.offender, None, "pid {pid}");
        }
        let forced = CombatEntry::forced(CombatCause::DebugForce);
        assert_eq!((forced.offender, forced.cause.trigger()), (None, None));
    }

    /// What a signed row carries for each cause.
    #[test]
    fn a_cause_renders_what_it_cites() {
        let mut t = evidence(TriggerType::ConfirmedIntrusion);
        t.corroborated_by = vec![(TriggerType::ExploitAttempt, EvidenceClass::Execution)];
        t.class = EvidenceClass::FileSystem;
        let v = CombatCause::Trigger(t).to_json();
        assert_eq!(v["kind"], "posture_trigger");
        assert_eq!(v["trigger"], "ConfirmedIntrusion");
        assert_eq!(v["class"], "FileSystem");
        assert_eq!(v["confidence"], "NeedsCorroboration");
        assert_eq!(v["corroborated_by"][0]["trigger"], "ExploitAttempt");
        assert_eq!(v["corroborated_by"][0]["class"], "Execution");
        assert_eq!(v["event"]["pid"], 4242);
        assert_eq!(v["scope"], "login uid 1000");
        let admin = CombatCause::AdminForce {
            signers: vec!["a1b2c3d4".to_string()],
        };
        assert_eq!(admin.to_json()["kind"], "admin_force_posture");
        assert_eq!(admin.to_json()["signers"][0], "a1b2c3d4");
        assert!(admin.summary().contains("a1b2c3d4"), "{}", admin.summary());
        assert_eq!(
            CombatCause::DebugForce.to_json()["kind"],
            "debug_force_posture"
        );
        assert_eq!(
            CombatCause::Trigger(evidence(TriggerType::AntiTamperDenial)).summary(),
            "AntiTamperDenial (Kernel, Decisive) on FsProtectDenial of pid 4242"
        );
    }
}
