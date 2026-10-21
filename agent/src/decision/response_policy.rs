//! Destructive responses held behind the per-rule response policy.
//!
//! Decision of 21/10/2026 (founder-delegated rule, review of lab PRs
//! 219–226): no new destructive automation is on by default until the
//! signed per-rule response policy (Phase 2) can turn it on, rule by rule.
//! Every kill — and every COMBAT entry without corroboration — that those
//! lots added, whether a new rule's or a wider match of a rule that existed
//! before them (12db406), stays in its rule's definition behind a
//! [`PolicySwitch`] that is off by default. With the switch off the verdict
//! keeps its severity, its signed record and its posture escalation; its
//! action is `Log`, and its reasoning says what was held back. A kill that
//! existed before (same rule, same match) is not held.
//!
//! A held verdict never stands in for a response that existed before it:
//! the engine (first match wins) learns from [`take_held`] that a rule's
//! verdict was held, keeps evaluating, and returns a later rule's
//! destructive verdict when one fires — the response that rule gave before
//! the hold existed — or else the held alert (which outranks a later
//! rule's record).
//!
//! Phase 2 wires each switch to the signed per-rule policy. Until then the
//! constants below are the only values production uses; tests turn a switch
//! on ([`PolicySwitch::enabled`]) to keep the held response exercised.

use std::cell::Cell;

use common::{ResponseAction, Verdict};

/// A destructive response a rule holds until the per-rule policy enables
/// it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PolicySwitch {
    /// What the switch holds back, named in a held verdict's reasoning.
    pub held: &'static str,
    /// The held response runs. `false` for every switch until the signed
    /// per-rule policy exists.
    pub on: bool,
}

impl PolicySwitch {
    /// A switch off by default, holding `held`.
    pub const fn off(held: &'static str) -> Self {
        Self { held, on: false }
    }

    /// The same switch, on (tests; the per-rule policy in Phase 2).
    pub const fn enabled(self) -> Self {
        Self { on: true, ..self }
    }

    /// `v` as the rule built it when the switch is on, or when its action
    /// is already `Log`. Otherwise its action becomes `Log`, its reasoning
    /// says what was held back, and the engine is told ([`take_held`]).
    pub fn hold(self, mut v: Verdict) -> Verdict {
        if self.on || v.action == ResponseAction::Log {
            return v;
        }
        v.reasoning = format!(
            "{} [held back: {} — alert only, by default, until the signed per-rule response \
             policy enables it]",
            v.reasoning, self.held
        );
        v.action = ResponseAction::Log;
        HELD.with(|h| h.set(true));
        v
    }
}

thread_local! {
    /// Set by [`PolicySwitch::hold`] when it held a response; read and
    /// cleared by the engine around each rule.
    static HELD: Cell<bool> = const { Cell::new(false) };
}

/// Whether a response was held on this thread since the last call (and
/// clear it). The engine calls it before and after each rule.
pub fn take_held() -> bool {
    HELD.with(|h| h.replace(false))
}

/// R020 (lab PR 224, new rule).
pub const R020_KILL: PolicySwitch =
    PolicySwitch::off("the kill of the shell's process tree (R020, lab PR 224)");

/// NN-L-NET-026 (lab PR 224, new rule): the kill tier.
pub const NET_026_KILL: PolicySwitch = PolicySwitch::off(
    "the kill of one process past the scan kill threshold (NN-L-NET-026, lab PR 224)",
);

/// NN-L-NET-027 (lab PR 224, new rule): the kill tier.
pub const NET_027_KILL: PolicySwitch = PolicySwitch::off(
    "the kill of one process past the brute-force kill threshold (NN-L-NET-027, lab PR 224)",
);

/// NN-L-NET-008, NN-L-CHAIN-002 and NN-L-CHAIN-005: a flow to port 53 was
/// exempt from them before lab PR 224, which exempts only a configured
/// resolver.
pub const PORT_53_KILL: PolicySwitch = PolicySwitch::off(
    "the kill for a flow to port 53 of a server that is no configured resolver \
     (port 53 was exempt before lab PR 224)",
);

/// [`PORT_53_KILL`] for a verdict on a flow to port 53 (the rules skip a
/// configured resolver's); a verdict on another port passes unchanged.
pub fn hold_port_53(nf: &common::wire::NetFlowEvent, v: Verdict) -> Verdict {
    if nf.dst_port == crate::net::resolvers::DNS_PORT {
        PORT_53_KILL.hold(v)
    } else {
        v
    }
}

/// The network allowlist's transfer tools were exempt before lab PR 224,
/// which judges them as any program while their lineage holds a
/// precursor ([`Judgement::Revoked`](crate::config::comm_allowlist::Judgement::Revoked)).
pub const REVOKED_TRANSFER_TOOL_KILL: PolicySwitch = PolicySwitch::off(
    "the kill of an allowlisted transfer tool whose lineage holds a precursor \
     (exempt before lab PR 224)",
);

/// NN-L-IMP-001 (lab PR 225, new rule): the kill of the actor's tree. Its
/// posture trigger's COMBAT without corroboration is held likewise
/// ([`common::posture_types::RANSOMWARE_COMBAT_WITHOUT_CORROBORATION`]).
pub const IMP_001_KILL: PolicySwitch =
    PolicySwitch::off("the kill of the ransomware actor's process tree (NN-L-IMP-001, lab PR 225)");

/// NN-L-EVA-001..004 (lab PR 225, new rules): the kill of a staged,
/// deleted or memory-only program that asked a security tool off.
pub const EVA_KILL: PolicySwitch = PolicySwitch::off(
    "the kill of the staged program that asked a security tool off (NN-L-EVA, lab PR 225)",
);

/// NN-L-FIM-010: a rename seen as the watched directory's creation of the
/// new name (`moved_in`), a match lab PR 225 added. The kill of a watched
/// file's own rename to a ransomware extension is the rule's from before.
pub const FIM_010_MOVED_IN_KILL: PolicySwitch = PolicySwitch::off(
    "the kill for a rename seen only as a watched directory's new entry (NN-L-FIM-010, a \
     match added by lab PR 225)",
);

/// Every switch, for the tests and the documents.
pub const ALL: &[PolicySwitch] = &[
    R020_KILL,
    NET_026_KILL,
    NET_027_KILL,
    PORT_53_KILL,
    REVOKED_TRANSFER_TOOL_KILL,
    IMP_001_KILL,
    EVA_KILL,
    FIM_010_MOVED_IN_KILL,
];

#[cfg(test)]
mod tests {
    use super::*;
    use common::Severity;

    fn kill() -> Verdict {
        Verdict {
            rule_id: "R999_Test".into(),
            rule_name: "test".into(),
            category: "test".into(),
            action: ResponseAction::KillProcessTree,
            severity: Severity::Critical,
            reasoning: "why; kill the process tree".into(),
            event_pid: 4242,
            event_filename: "/tmp/x".into(),
            timestamp_ns: 1,
        }
    }

    /// Every switch is off by default: the decision of 21/10/2026.
    #[test]
    fn every_switch_is_off_by_default() {
        assert!(!ALL.is_empty());
        for s in ALL {
            assert!(!s.on, "{} is on by default", s.held);
            assert!(!s.held.is_empty());
        }
        // The posture half of NN-L-IMP-001's hold.
        const { assert!(!common::posture_types::RANSOMWARE_COMBAT_WITHOUT_CORROBORATION) };
    }

    /// Off: the action is `Log`, severity and the rest kept, the reasoning
    /// says what was held, and the engine is told once.
    #[test]
    fn an_off_switch_holds_the_response_and_keeps_the_alert() {
        take_held();
        let v = R020_KILL.hold(kill());
        assert_eq!(v.action, ResponseAction::Log);
        assert_eq!(v.severity, Severity::Critical);
        assert_eq!(v.event_pid, 4242);
        assert!(v
            .reasoning
            .starts_with("why; kill the process tree [held back: "));
        assert!(v.reasoning.contains("per-rule response policy"));
        assert!(take_held());
        assert!(!take_held(), "read once");
    }

    /// A rule for the engine tests: fires on every event with `action`,
    /// held behind `switch` when there is one.
    struct Fires(&'static str, ResponseAction, Option<PolicySwitch>);

    impl crate::decision::Rule for Fires {
        fn id(&self) -> &'static str {
            self.0
        }
        fn name(&self) -> &'static str {
            self.0
        }
        fn category(&self) -> &'static str {
            "test"
        }
        fn attack(&self) -> &'static [crate::decision::attack::AttackRef] {
            &[]
        }
        fn evaluate(&self, _event: &common::Event) -> Option<Verdict> {
            let mut v = kill();
            v.rule_id = self.0.to_string();
            v.action = self.1.clone();
            Some(match self.2 {
                Some(s) => s.hold(v),
                None => v,
            })
        }
    }

    fn engine(rules: Vec<Fires>) -> crate::decision::RuleEngine {
        let mut e = crate::decision::RuleEngine::new();
        for r in rules {
            e.add_rule(Box::new(r));
        }
        e
    }

    fn event() -> common::Event {
        crate::decision::rules::testutil::spawn_exe("bash", "/bin/bash", "/usr/bin/bash", 0)
    }

    /// A held verdict never stands in for a later rule's response (the one
    /// it gave before the hold existed); it outranks a later record; alone,
    /// it is the verdict.
    #[test]
    fn the_engine_lets_a_held_verdict_through_to_a_later_kill() {
        let held = || Fires("NEW", ResponseAction::KillProcessTree, Some(R020_KILL));
        let v = engine(vec![
            held(),
            Fires("OLD", ResponseAction::KillProcess, None),
        ])
        .evaluate(&event())
        .unwrap();
        assert_eq!(
            (v.rule_id.as_str(), v.action),
            ("OLD", ResponseAction::KillProcess)
        );
        let v = engine(vec![held(), Fires("REC", ResponseAction::Log, None)])
            .evaluate(&event())
            .unwrap();
        assert_eq!((v.rule_id.as_str(), v.action), ("NEW", ResponseAction::Log));
        let v = engine(vec![held()]).evaluate(&event()).unwrap();
        assert_eq!((v.rule_id.as_str(), v.action), ("NEW", ResponseAction::Log));
        // Switch on: first match wins, as for every rule.
        let on = Fires(
            "NEW",
            ResponseAction::KillProcessTree,
            Some(R020_KILL.enabled()),
        );
        let v = engine(vec![on, Fires("OLD", ResponseAction::KillProcess, None)])
            .evaluate(&event())
            .unwrap();
        assert_eq!(
            (v.rule_id.as_str(), v.action),
            ("NEW", ResponseAction::KillProcessTree)
        );
    }

    /// On: the rule's response is untouched; a `Log` verdict is never held.
    #[test]
    fn an_on_switch_and_a_record_pass_unchanged() {
        take_held();
        let v = R020_KILL.enabled().hold(kill());
        assert_eq!(v.action, ResponseAction::KillProcessTree);
        assert_eq!(v.reasoning, "why; kill the process tree");
        let mut log = kill();
        log.action = ResponseAction::Log;
        let l = R020_KILL.hold(log.clone());
        assert_eq!(l.reasoning, log.reasoning);
        assert!(!take_held());
    }
}
