//! Lab PR 236 (C14): the decision of an event, computed from every rule
//! that matched it.
//!
//! The engine evaluates every rule and hands each verdict, with the
//! per-rule policy's mode ([`apply_policy`]), to [`combine`]:
//!
//! - the action is the strongest among the matches whose mode allows one
//!   (`builtin`, `enforce`; [`action_rank`]) — under the **legacy ceiling**:
//!   a `builtin` match never runs more than the first-match engine ran on
//!   the same event ([`legacy_first_match`]: the first rule in registration
//!   order that fired, with the held-kill switches applied), on its target;
//!   only `enforce` for the rule supplying a stronger action lifts it
//!   (decision of 22/10/2026: multi-match never unmasks a destructive
//!   response by default);
//! - the responses are, per target (a process, or a file for
//!   `StripFileCapability`), the strongest action aimed at it;
//! - the severity is the maximum over the counted matches (not `audit`, not
//!   exempt);
//! - the primary rule is the counted match with the highest severity, then
//!   the strongest action, then the earliest registered (the engine order
//!   encodes specificity);
//! - the record lists every match.
//!
//! Every tie ends on the registration index, unique per rule: the same
//! matches give the same decision on any run and thread.
//! `docs/design/MULTI_MATCH_AND_RULE_POLICY.md` §2.

use nn_model::{ResponseAction, Severity, Verdict};

use super::attack::AttackRef;
use super::response_policy::Held;
use super::rule_policy::{Mode, RulePolicy};

/// Strength of an action, weakest first.
pub fn action_rank(a: &ResponseAction) -> u8 {
    match a {
        ResponseAction::Log => 0,
        ResponseAction::ThrottleProcess => 1,
        ResponseAction::StripFileCapability => 2,
        ResponseAction::BlockOutbound => 3,
        ResponseAction::Quarantine => 4,
        ResponseAction::KillProcess => 5,
        ResponseAction::KillProcessTree => 6,
        ResponseAction::FullNetworkIsolation => 7,
    }
}

/// The record's `held` of a match whose action the legacy ceiling held.
pub const LEGACY_CEILING: &str = "legacy_ceiling";

/// What the per-rule policy made of one match.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Applied {
    /// No policy line: the rule's own response, a held kill held.
    Builtin,
    /// `enforce`: the rule's own response, a held kill given back.
    Enforce,
    /// `alert`: recorded and counted, `Log`.
    Alert,
    /// `audit`: recorded only.
    Audit,
    /// An exemption of the policy covers the actor: recorded only.
    Exempt(String),
    /// `off`: dropped from the decision. Kept until [`combine`] has read it
    /// for the legacy first match (an `off` rule never unmasks another's
    /// response), then removed.
    Off,
}

impl Applied {
    /// The record's name for it.
    pub fn name(&self) -> &'static str {
        match self {
            Applied::Builtin => "builtin",
            Applied::Enforce => "enforce",
            Applied::Alert => "alert",
            Applied::Audit => "audit",
            Applied::Exempt(_) => "exempt",
            Applied::Off => "off",
        }
    }
}

/// One rule's verdict on the event, after the policy.
#[derive(Debug, Clone)]
pub struct RuleMatch {
    /// The rule's registration index in the engine (unique).
    pub index: usize,
    pub rule_id: &'static str,
    pub attack: &'static [AttackRef],
    pub verdict: Verdict,
    pub applied: Applied,
    /// What still holds this match's response: a switch (its text, built
    /// in) or the legacy ceiling ([`LEGACY_CEILING`]).
    pub held: Option<&'static str>,
    /// The action held back (the rule's own), when [`Self::held`] is set.
    pub held_action: Option<ResponseAction>,
    /// The action the rule's verdict carried with today's switches, before
    /// the policy: what the first-match engine would have run.
    pub builtin_action: ResponseAction,
    /// A switch held the rule's response (before the policy).
    pub switch_held: bool,
}

impl RuleMatch {
    /// Counted for the severity and the primary rule.
    pub fn counted(&self) -> bool {
        !matches!(
            self.applied,
            Applied::Audit | Applied::Exempt(_) | Applied::Off
        )
    }

    /// Its response runs.
    pub fn acts(&self) -> bool {
        matches!(self.applied, Applied::Builtin | Applied::Enforce)
            && self.verdict.action != ResponseAction::Log
    }
}

/// What the executor runs for one target.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Response {
    pub action: ResponseAction,
    pub pid: u32,
    pub filename: String,
    pub timestamp_ns: u64,
    /// The rule whose verdict it is (the strongest for the target, then
    /// the earliest), and every other acting rule aimed at the target.
    pub rule_id: &'static str,
    pub also: Vec<&'static str>,
}

/// The decision on one event.
#[derive(Debug, Clone)]
pub struct Decision {
    /// The primary rule's verdict, with the decision's action and
    /// severity, and a reasoning naming the other matches.
    pub verdict: Verdict,
    /// Index into [`Self::matches`] of the primary rule.
    pub primary: usize,
    /// Every match, in registration order.
    pub matches: Vec<RuleMatch>,
    /// What runs, strongest first.
    pub responses: Vec<Response>,
}

impl Decision {
    pub fn primary(&self) -> &RuleMatch {
        &self.matches[self.primary]
    }

    /// Every match is `audit` or exempt: a record, no alert.
    pub fn audit_only(&self) -> bool {
        !self.matches.iter().any(RuleMatch::counted)
    }

    /// The ATT&CK references of every match, the primary's first, each once.
    pub fn attack(&self) -> Vec<AttackRef> {
        let mut out: Vec<AttackRef> = Vec::new();
        let order = std::iter::once(self.primary)
            .chain((0..self.matches.len()).filter(|i| *i != self.primary));
        for i in order {
            for r in self.matches[i].attack {
                if !out.contains(r) {
                    out.push(*r);
                }
            }
        }
        out
    }
}

/// The match of rule `rule_id` (index `index`) as the policy makes it
/// (an `off` rule's is [`Applied::Off`]). `held` is what the rule's switch held
/// ([`super::response_policy::take_held`]); `exempt` says which exemption,
/// if any, covers the actor (read only when the rule has exemptions).
pub fn apply_policy(
    index: usize,
    rule_id: &'static str,
    attack: &'static [AttackRef],
    mut v: Verdict,
    held: Option<Held>,
    policy: &RulePolicy,
    exempt: impl FnOnce(&Verdict) -> Option<String>,
) -> RuleMatch {
    let mode = policy.mode(rule_id);
    let builtin_action = v.action.clone();
    let switch_held = held.is_some();
    // Named only while the switch still holds the response (built in).
    let mut held_switch = held.as_ref().map(|h| h.switch);
    let held_action = held.as_ref().map(|h| h.action.clone());
    let applied = if mode == Some(Mode::Off) {
        held_switch = None;
        Applied::Off
    } else if let Some(e) = (!policy.exemptions(rule_id).is_empty())
        .then(|| exempt(&v))
        .flatten()
    {
        v.action = ResponseAction::Log;
        v.reasoning = format!(
            "{} [exempt by the signed per-rule policy ({e}): recorded only]",
            v.reasoning
        );
        held_switch = None;
        Applied::Exempt(e)
    } else {
        match mode {
            None => Applied::Builtin,
            Some(Mode::Enforce) => {
                if let Some(h) = held {
                    v.action = h.action;
                    v.reasoning = format!(
                        "{} [enforced by the signed per-rule policy: {}]",
                        h.reasoning, h.switch
                    );
                    held_switch = None;
                }
                Applied::Enforce
            }
            Some(Mode::Alert) => {
                held_switch = None;
                if v.action != ResponseAction::Log {
                    v.reasoning = format!(
                        "{} [alert only by the signed per-rule policy: {:?} not run]",
                        v.reasoning, v.action
                    );
                    v.action = ResponseAction::Log;
                }
                Applied::Alert
            }
            Some(Mode::Audit) => {
                held_switch = None;
                v.reasoning = format!(
                    "{} [audit by the signed per-rule policy: recorded only]",
                    v.reasoning
                );
                v.action = ResponseAction::Log;
                Applied::Audit
            }
            Some(Mode::Off) => unreachable!("handled above"),
        }
    };
    RuleMatch {
        index,
        rule_id,
        attack,
        verdict: v,
        applied,
        held_action: held_switch.and(held_action),
        held: held_switch,
        builtin_action,
        switch_held,
    }
}

/// The match the first-match engine (before lab PR 236) would have
/// answered the event with, among `matches` sorted by registration index,
/// and the action it ran: the first rule that fired, with the held-kill
/// switches applied — a held verdict let a later rule's response through,
/// and outranked a later record (`response_policy` before lab PR 236).
/// Computed on the rules' own verdicts before the policy, `off` rules
/// included. `None` when there is no match.
pub fn legacy_first_match(matches: &[RuleMatch]) -> Option<(usize, ResponseAction)> {
    let mut first_held = None;
    for (pos, m) in matches.iter().enumerate() {
        if m.switch_held {
            first_held.get_or_insert(pos);
            continue;
        }
        if let Some(h) = first_held {
            if m.builtin_action == ResponseAction::Log {
                return Some((h, ResponseAction::Log));
            }
        }
        return Some((pos, m.builtin_action.clone()));
    }
    first_held.map(|h| (h, ResponseAction::Log))
}

/// The legacy ceiling on `matches` (sorted): a `builtin` match whose
/// response the first-match engine would not have run on this event —
/// stronger than its action, or aimed at another target — is held
/// (`Log`, [`LEGACY_CEILING`], the action in `held_action`, its reasoning
/// saying so). `enforce` matches are not capped.
fn apply_legacy_ceiling(matches: &mut [RuleMatch]) {
    let Some((pos, action)) = legacy_first_match(matches) else {
        return;
    };
    let winner = &matches[pos];
    let (rule, pid, file) = (
        winner.rule_id,
        winner.verdict.event_pid,
        winner.verdict.event_filename.clone(),
    );
    let ceiling_target = target_for(&action, pid, &file);
    for m in matches.iter_mut() {
        if m.applied != Applied::Builtin || m.verdict.action == ResponseAction::Log {
            continue;
        }
        let within = action != ResponseAction::Log
            && target(&m.verdict) == ceiling_target
            && action_rank(&m.verdict.action) <= action_rank(&action);
        if within {
            continue;
        }
        let ran = if action == ResponseAction::Log {
            format!("only a record ({rule})")
        } else {
            format!("{action:?} of pid {pid} ({rule})")
        };
        m.verdict.reasoning = format!(
            "{} [legacy ceiling: {:?} held — the first-match engine ran {ran} on this event; \
             `enforce {}` in the signed per-rule policy lifts it]",
            m.verdict.reasoning,
            m.verdict.action,
            super::rule_policy::short_id(m.rule_id)
        );
        m.held_action = Some(std::mem::replace(
            &mut m.verdict.action,
            ResponseAction::Log,
        ));
        m.held = Some(LEGACY_CEILING);
    }
}

/// The action a match ranks by for the primary rule: its own, also when
/// the legacy ceiling held it (the primary may be the strongest rule, its
/// action executed at the ceiling); a switch's hold ranks as `Log`, as it
/// did before lab PR 236.
fn ranked_action(m: &RuleMatch) -> &ResponseAction {
    match (m.held, &m.held_action) {
        (Some(LEGACY_CEILING), Some(a)) => a,
        _ => &m.verdict.action,
    }
}

/// The primary order: higher severity, then stronger action, then the
/// earlier rule. `a` before `b` = `Less`.
fn primary_order(a: &RuleMatch, b: &RuleMatch) -> std::cmp::Ordering {
    (b.verdict.severity as u8)
        .cmp(&(a.verdict.severity as u8))
        .then(action_rank(ranked_action(b)).cmp(&action_rank(ranked_action(a))))
        .then(a.index.cmp(&b.index))
}

/// A response's target: a process, or a file for the action that acts on
/// the verdict's file.
#[derive(PartialEq, Eq)]
enum Target<'a> {
    Process(u32),
    File(u32, &'a str),
}

fn target(v: &Verdict) -> Target<'_> {
    target_for(&v.action, v.event_pid, &v.event_filename)
}

fn target_for<'a>(action: &ResponseAction, pid: u32, file: &'a str) -> Target<'a> {
    match action {
        ResponseAction::StripFileCapability => Target::File(pid, file),
        _ => Target::Process(pid),
    }
}

/// The decision from `matches` (any order; sorted here by registration
/// index), under the legacy ceiling; `off` matches are read for it, then
/// dropped. `None` when no match is left.
pub fn combine(mut matches: Vec<RuleMatch>) -> Option<Decision> {
    matches.sort_by_key(|m| m.index);
    apply_legacy_ceiling(&mut matches);
    matches.retain(|m| m.applied != Applied::Off);
    if matches.is_empty() {
        return None;
    }
    let any_counted = matches.iter().any(RuleMatch::counted);
    let pool = |m: &&RuleMatch| !any_counted || m.counted();
    let primary = matches
        .iter()
        .enumerate()
        .filter(|(_, m)| pool(m))
        .min_by(|(_, a), (_, b)| primary_order(a, b))
        .map(|(i, _)| i)
        .expect("one match at least");
    let severity: Severity = matches
        .iter()
        .filter(pool)
        .map(|m| m.verdict.severity)
        .max_by_key(|s| *s as u8)
        .expect("one match at least");
    // Per target, the strongest acting match (then the earliest).
    let mut responses: Vec<(usize, Response)> = Vec::new();
    for m in matches.iter().filter(|m| m.acts()) {
        let v = &m.verdict;
        match responses
            .iter_mut()
            .find(|(_, r)| target_of(r) == target(v))
        {
            Some((first, r)) => {
                if action_rank(&v.action) > action_rank(&r.action) {
                    let mut also = std::mem::take(&mut r.also);
                    also.push(r.rule_id);
                    *r = response_of(m, also);
                    *first = (*first).min(m.index);
                } else {
                    r.also.push(m.rule_id);
                }
            }
            None => responses.push((m.index, response_of(m, Vec::new()))),
        }
    }
    responses.sort_by(|(ia, a), (ib, b)| {
        action_rank(&b.action)
            .cmp(&action_rank(&a.action))
            .then(ia.cmp(ib))
    });
    let responses: Vec<Response> = responses.into_iter().map(|(_, r)| r).collect();
    let mut verdict = matches[primary].verdict.clone();
    verdict.severity = severity;
    verdict.action = responses
        .first()
        .map_or(ResponseAction::Log, |r| r.action.clone());
    if matches.len() > 1 {
        let others: Vec<String> = matches
            .iter()
            .enumerate()
            .filter(|(i, _)| *i != primary)
            .map(|(_, m)| {
                format!(
                    "{} ({:?}, {:?}{})",
                    m.rule_id,
                    m.verdict.action,
                    m.verdict.severity,
                    match (&m.applied, m.held) {
                        (Applied::Builtin, Some(LEGACY_CEILING)) => format!(
                            ", legacy ceiling: {:?} held",
                            m.held_action.clone().unwrap_or(ResponseAction::Log)
                        ),
                        (Applied::Builtin, _) => String::new(),
                        (a, _) => format!(", {}", a.name()),
                    }
                )
            })
            .collect();
        verdict.reasoning = format!(
            "{} [also matched: {}]",
            verdict.reasoning,
            others.join(", ")
        );
    }
    Some(Decision {
        verdict,
        primary,
        matches,
        responses,
    })
}

fn target_of(r: &Response) -> Target<'_> {
    match r.action {
        ResponseAction::StripFileCapability => Target::File(r.pid, &r.filename),
        _ => Target::Process(r.pid),
    }
}

fn response_of(m: &RuleMatch, also: Vec<&'static str>) -> Response {
    Response {
        action: m.verdict.action.clone(),
        pid: m.verdict.event_pid,
        filename: m.verdict.event_filename.clone(),
        timestamp_ns: m.verdict.timestamp_ns,
        rule_id: m.rule_id,
        also,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decision::attack::Tactic;
    use crate::decision::response_policy::R020_KILL;
    use crate::decision::rule_policy::parse;

    const A1: &[AttackRef] = &[AttackRef::new(Tactic::Execution, "T1059")];
    const A2: &[AttackRef] = &[
        AttackRef::new(Tactic::Execution, "T1059"),
        AttackRef::new(Tactic::Impact, "T1486"),
    ];

    fn v(rule: &str, action: ResponseAction, sev: Severity, pid: u32) -> Verdict {
        Verdict {
            rule_id: rule.into(),
            rule_name: rule.into(),
            category: "test".into(),
            action,
            severity: sev,
            reasoning: format!("{rule} fired"),
            event_pid: pid,
            event_filename: "/tmp/x".into(),
            timestamp_ns: 7,
        }
    }

    fn m(index: usize, rule: &'static str, action: ResponseAction, sev: Severity) -> RuleMatch {
        RuleMatch {
            index,
            rule_id: rule,
            attack: A1,
            builtin_action: action.clone(),
            verdict: v(rule, action, sev, 100),
            applied: Applied::Builtin,
            held: None,
            held_action: None,
            switch_held: false,
        }
    }

    /// `m` under `enforce` (no legacy ceiling).
    fn e(index: usize, rule: &'static str, action: ResponseAction, sev: Severity) -> RuleMatch {
        RuleMatch {
            applied: Applied::Enforce,
            ..m(index, rule, action, sev)
        }
    }

    use ResponseAction::*;
    use Severity::*;

    #[test]
    fn no_match_no_decision() {
        assert!(combine(Vec::new()).is_none());
    }

    #[test]
    fn a_single_match_is_its_verdict_unchanged() {
        let one = m(3, "A", KillProcess, High);
        let d = combine(vec![one.clone()]).unwrap();
        assert_eq!(d.verdict.reasoning, one.verdict.reasoning);
        assert_eq!(d.verdict.action, KillProcess);
        assert_eq!(d.primary().rule_id, "A");
        assert_eq!(d.responses.len(), 1);
    }

    /// The highest severity is primary, whatever the action.
    #[test]
    fn primary_is_the_highest_severity_first() {
        let d = combine(vec![
            m(0, "LOW-KILL", KillProcessTree, Medium),
            m(1, "CRIT-LOG", Log, Critical),
        ])
        .unwrap();
        assert_eq!(d.primary().rule_id, "CRIT-LOG");
        // The action is still the strongest allowed; the severity the max.
        assert_eq!(d.verdict.action, KillProcessTree);
        assert_eq!(d.verdict.severity, Critical);
        assert_eq!(d.verdict.rule_id, "CRIT-LOG");
        assert!(d
            .verdict
            .reasoning
            .ends_with("[also matched: LOW-KILL (KillProcessTree, Medium)]"));
    }

    /// Equal severity: the stronger action is primary.
    #[test]
    fn then_the_strongest_action() {
        let d = combine(vec![
            m(0, "LOG", Log, High),
            m(1, "KILL", KillProcess, High),
        ])
        .unwrap();
        // Ranked by its own action, though the legacy ceiling holds it.
        assert_eq!(d.primary().rule_id, "KILL");
        assert_eq!(d.primary().held, Some(LEGACY_CEILING));
    }

    /// Equal severity and action: the earliest registered (the most
    /// specific), whatever order the matches came in.
    #[test]
    fn then_the_earliest_rule() {
        let d = combine(vec![
            m(5, "LATE", KillProcess, High),
            m(2, "EARLY", KillProcess, High),
        ])
        .unwrap();
        assert_eq!(d.primary().rule_id, "EARLY");
        assert_eq!(
            d.matches.iter().map(|m| m.rule_id).collect::<Vec<_>>(),
            ["EARLY", "LATE"]
        );
        assert_eq!(d.responses.len(), 1, "one kill of one process");
        assert_eq!(d.responses[0].rule_id, "EARLY");
        assert_eq!(d.responses[0].also, ["LATE"]);
    }

    /// Every action has its own rank, in the documented order.
    #[test]
    fn action_ranks_are_a_total_order() {
        let order = [
            Log,
            ThrottleProcess,
            StripFileCapability,
            BlockOutbound,
            Quarantine,
            KillProcess,
            KillProcessTree,
            FullNetworkIsolation,
        ];
        for w in order.windows(2) {
            assert!(action_rank(&w[0]) < action_rank(&w[1]), "{w:?}");
        }
    }

    /// Per process the strongest action runs once; another process and a
    /// file action keep their own response.
    #[test]
    fn responses_per_target() {
        // Enforced, so the legacy ceiling does not cap them.
        let mut other = e(2, "OTHER-PID", KillProcess, High);
        other.verdict.event_pid = 200;
        let strip = e(3, "STRIP", StripFileCapability, High);
        let d = combine(vec![
            e(0, "KP", KillProcess, High),
            e(1, "KPT", KillProcessTree, High),
            other,
            strip,
        ])
        .unwrap();
        let got: Vec<(&str, ResponseAction, u32, Vec<&str>)> = d
            .responses
            .iter()
            .map(|r| (r.rule_id, r.action.clone(), r.pid, r.also.clone()))
            .collect();
        assert_eq!(
            got,
            vec![
                ("KPT", KillProcessTree, 100, vec!["KP"]),
                ("OTHER-PID", KillProcess, 200, vec![]),
                ("STRIP", StripFileCapability, 100, vec![]),
            ]
        );
        assert_eq!(d.verdict.action, KillProcessTree);
    }

    /// A record only: no response, but listed.
    #[test]
    fn a_log_match_runs_nothing() {
        let d = combine(vec![m(0, "A", Log, High), m(1, "B", Log, Low)]).unwrap();
        assert!(d.responses.is_empty());
        assert_eq!(d.verdict.action, Log);
        assert_eq!(d.matches.len(), 2);
    }

    /// Audit and exempt matches do not count; alone, they make an
    /// audit-only decision.
    #[test]
    fn audit_and_exempt_matches_are_not_counted() {
        let mut audit = m(0, "AUDIT", Log, Critical);
        audit.applied = Applied::Audit;
        let mut ex = m(1, "EXEMPT", Log, Critical);
        ex.applied = Applied::Exempt("uid 998".into());
        let d = combine(vec![audit.clone(), ex.clone(), m(2, "REC", Log, Low)]).unwrap();
        assert_eq!(d.primary().rule_id, "REC");
        assert_eq!(d.verdict.severity, Low);
        assert!(!d.audit_only());
        assert!(d.verdict.reasoning.contains("AUDIT (Log, Critical, audit)"));
        assert!(d
            .verdict
            .reasoning
            .contains("EXEMPT (Log, Critical, exempt)"));
        let d = combine(vec![audit, ex]).unwrap();
        assert!(d.audit_only());
        assert_eq!(d.primary().rule_id, "AUDIT");
        assert_eq!(d.verdict.severity, Critical);
    }

    #[test]
    fn attack_is_the_union_primary_first() {
        let mut a = m(0, "A", Log, Low);
        a.attack = A1;
        let mut b = m(1, "B", KillProcess, Critical);
        b.attack = A2;
        let d = combine(vec![a, b]).unwrap();
        assert_eq!(d.primary().rule_id, "B");
        assert_eq!(d.attack(), A2.to_vec());
    }

    fn held_kill() -> (Verdict, Option<Held>) {
        crate::decision::response_policy::take_held();
        let built = v("R020_ShellWithSocketStdio", KillProcessTree, Critical, 9);
        let out = R020_KILL.hold(built);
        (out, crate::decision::response_policy::take_held())
    }

    const R020: &str = "R020_ShellWithSocketStdio";

    /// No policy line: a held kill stays held.
    #[test]
    fn builtin_keeps_a_held_kill_held() {
        let (out, held) = held_kill();
        let p = RulePolicy::builtin();
        let m = apply_policy(0, R020, A1, out, held, &p, |_| None);
        assert_eq!(m.applied, Applied::Builtin);
        assert_eq!(m.verdict.action, Log);
        assert_eq!(m.held, Some(R020_KILL.held));
        assert_eq!(m.held_action, Some(KillProcessTree));
        assert!(m.switch_held);
        assert_eq!(m.builtin_action, Log);
        assert!(!m.acts());
    }

    /// `enforce` gives the held kill back, with the rule's reasoning.
    #[test]
    fn enforce_gives_a_held_kill_back() {
        let (out, held) = held_kill();
        let p = parse("enforce R020\n").unwrap();
        let m = apply_policy(0, R020, A1, out, held, &p, |_| None);
        assert_eq!(m.applied, Applied::Enforce);
        assert_eq!(m.verdict.action, KillProcessTree);
        assert!(m
            .verdict
            .reasoning
            .starts_with("R020_ShellWithSocketStdio fired [enforced"));
        assert!(!m.verdict.reasoning.contains("[held back: "));
        assert_eq!(m.held, None);
        assert!(m.acts());
    }

    #[test]
    fn alert_audit_and_off() {
        let p = parse("alert R020\n").unwrap();
        let m = apply_policy(0, R020, A1, v(R020, KillProcess, High, 1), None, &p, |_| {
            None
        });
        assert_eq!(
            (m.verdict.action.clone(), m.applied.clone()),
            (Log, Applied::Alert)
        );
        assert!(m.verdict.reasoning.contains("KillProcess not run"));
        assert!(m.counted());
        let p = parse("audit R020\n").unwrap();
        let m = apply_policy(0, R020, A1, v(R020, KillProcess, High, 1), None, &p, |_| {
            None
        });
        assert_eq!(
            (m.verdict.action.clone(), m.applied.clone()),
            (Log, Applied::Audit)
        );
        assert!(!m.counted());
        let p = parse("off R020\n").unwrap();
        let off = apply_policy(0, R020, A1, v(R020, KillProcess, High, 1), None, &p, |_| {
            None
        });
        assert_eq!(off.applied, Applied::Off);
        assert!(combine(vec![off]).is_none(), "an off match is dropped");
    }

    /// An exemption wins over `enforce`; it is consulted only when the rule
    /// has one.
    #[test]
    fn an_exemption_makes_the_match_a_record() {
        let p = parse("enforce R020\nexempt R020 uid 998\n").unwrap();
        let (out, held) = held_kill();
        let m = apply_policy(0, R020, A1, out, held, &p, |_| Some("uid 998".into()));
        assert_eq!(m.applied, Applied::Exempt("uid 998".into()));
        assert_eq!(m.verdict.action, Log);
        assert!(!m.acts() && !m.counted());
        assert!(m.verdict.reasoning.contains("(uid 998): recorded only]"));
        // Not the exempt actor: enforced.
        let (out, held) = held_kill();
        let m = apply_policy(0, R020, A1, out, held, &p, |_| None);
        assert_eq!(m.verdict.action, KillProcessTree);
        // No exemption: the check is never asked.
        let p = parse("enforce R020\n").unwrap();
        let (out, held) = held_kill();
        apply_policy(0, R020, A1, out, held, &p, |_| panic!("asked"));
    }

    /// The same matches in any order give the same decision.
    #[test]
    fn the_decision_does_not_depend_on_the_input_order() {
        let all = vec![
            m(0, "A", Log, High),
            m(1, "B", KillProcess, High),
            m(2, "C", KillProcessTree, Medium),
            m(3, "D", Log, Critical),
        ];
        let base = combine(all.clone()).unwrap();
        let mut rev = all.clone();
        rev.reverse();
        let d = combine(rev).unwrap();
        assert_eq!(d.verdict.reasoning, base.verdict.reasoning);
        assert_eq!(d.responses, base.responses);
        assert_eq!(d.primary().rule_id, "D");
    }

    // ── the legacy ceiling (decision of 22/10/2026) ──

    /// The shadowed kill (FIM-004 behind FIM-002's record): held by the
    /// ceiling by default — recorded, its action named — and run once the
    /// policy enforces its rule.
    #[test]
    fn the_legacy_ceiling_holds_an_unmasked_kill_until_enforced() {
        let d = combine(vec![
            m(0, "REC", Log, Medium),
            m(1, "KILL", KillProcess, High),
        ])
        .unwrap();
        assert!(d.responses.is_empty());
        assert_eq!(d.verdict.action, Log);
        assert_eq!(d.verdict.severity, High);
        assert_eq!(
            d.verdict.rule_id, "KILL",
            "the primary may be the stronger rule"
        );
        let k = &d.matches[1];
        assert_eq!(
            (k.held, k.held_action.clone(), k.verdict.action.clone()),
            (Some(LEGACY_CEILING), Some(KillProcess), Log)
        );
        assert!(k.verdict.reasoning.contains(
            "[legacy ceiling: KillProcess held — the first-match engine ran only a record (REC)"
        ));
        assert!(k.verdict.reasoning.contains("`enforce KILL`"));
        let d = combine(vec![
            m(0, "REC", Log, Medium),
            e(1, "KILL", KillProcess, High),
        ])
        .unwrap();
        assert_eq!(d.verdict.action, KillProcess);
        assert_eq!(d.responses[0].rule_id, "KILL");
        assert_eq!(d.matches[1].held, None);
    }

    /// The legacy winner was already the strongest (R001's tree kill before
    /// R009's): unchanged, and a weaker action on its target runs within it.
    #[test]
    fn the_ceiling_keeps_a_legacy_winner_that_was_the_strongest() {
        let d = combine(vec![
            m(0, "FIRST", KillProcessTree, Medium),
            m(1, "LATER", KillProcess, High),
        ])
        .unwrap();
        assert_eq!(d.verdict.action, KillProcessTree);
        assert_eq!(d.responses.len(), 1);
        assert_eq!(
            (d.responses[0].rule_id, d.responses[0].also.clone()),
            ("FIRST", vec!["LATER"])
        );
        assert!(d.matches.iter().all(|m| m.held.is_none()));
    }

    /// Another target than the legacy winner's, or a stronger action on its
    /// own: held.
    #[test]
    fn the_ceiling_holds_another_target_and_a_stronger_action() {
        let mut other = m(1, "OTHER-PID", KillProcess, High);
        other.verdict.event_pid = 200;
        let d = combine(vec![
            m(0, "FIRST", KillProcess, High),
            other,
            m(2, "TREE", KillProcessTree, High),
            m(3, "STRIP", StripFileCapability, High),
        ])
        .unwrap();
        assert_eq!(d.responses.len(), 1);
        assert_eq!(
            (d.responses[0].rule_id, d.responses[0].action.clone()),
            ("FIRST", KillProcess)
        );
        for m in &d.matches[1..] {
            assert_eq!(m.held, Some(LEGACY_CEILING), "{}", m.rule_id);
        }
    }

    /// The legacy first match with switches: a held alert lets a later
    /// response through, and outranks a later record.
    #[test]
    fn the_legacy_first_match_reads_the_switches() {
        let held = |i| RuleMatch {
            switch_held: true,
            ..m(i, "HELD", Log, Critical)
        };
        let ms = vec![held(0), m(1, "KILL", KillProcess, High)];
        assert_eq!(legacy_first_match(&ms), Some((1, KillProcess)));
        assert_eq!(combine(ms).unwrap().verdict.action, KillProcess);
        let ms = vec![
            held(0),
            m(1, "REC", Log, High),
            m(2, "KILL", KillProcess, High),
        ];
        assert_eq!(legacy_first_match(&ms), Some((0, Log)));
        assert_eq!(combine(ms).unwrap().verdict.action, Log);
        assert_eq!(legacy_first_match(&[held(0)]), Some((0, Log)));
        assert_eq!(legacy_first_match(&[]), None);
    }

    /// An `off` rule still counts for the legacy first match: turning the
    /// first rule off never unmasks a later rule's response.
    #[test]
    fn an_off_legacy_winner_never_unmasks_a_later_response() {
        let off = RuleMatch {
            applied: Applied::Off,
            ..m(0, "REC", Log, Medium)
        };
        let d = combine(vec![off, m(1, "KILL", KillProcess, High)]).unwrap();
        assert_eq!(d.matches.len(), 1, "the off match is dropped");
        assert_eq!(d.verdict.action, Log);
        assert_eq!(d.matches[0].held, Some(LEGACY_CEILING));
    }
}
