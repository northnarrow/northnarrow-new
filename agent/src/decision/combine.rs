//! Lab PR 236 (C14): the decision of an event, computed from every rule
//! that matched it.
//!
//! The engine evaluates every rule and hands each verdict, with the
//! per-rule policy's mode ([`apply_policy`]), to [`combine`]:
//!
//! - the action is the strongest among the matches whose mode allows one
//!   (`builtin`, `enforce`; [`action_rank`]);
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

use common::{ResponseAction, Severity, Verdict};

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
    /// The switch still holding this match's response (built in).
    pub held: Option<&'static str>,
}

impl RuleMatch {
    /// Counted for the severity and the primary rule.
    pub fn counted(&self) -> bool {
        !matches!(self.applied, Applied::Audit | Applied::Exempt(_))
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

/// The match of rule `rule_id` (index `index`) as the policy makes it:
/// `None` when the rule is `off`. `held` is what the rule's switch held
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
) -> Option<RuleMatch> {
    let mode = policy.mode(rule_id);
    if mode == Some(Mode::Off) {
        return None;
    }
    // Named only while the switch still holds the response (built in).
    let mut held_switch = held.as_ref().map(|h| h.switch);
    let applied = if let Some(e) = (!policy.exemptions(rule_id).is_empty())
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
            Some(Mode::Off) => unreachable!("returned above"),
        }
    };
    Some(RuleMatch {
        index,
        rule_id,
        attack,
        verdict: v,
        applied,
        held: held_switch,
    })
}

/// The primary order: higher severity, then stronger action, then the
/// earlier rule. `a` before `b` = `Less`.
fn primary_order(a: &RuleMatch, b: &RuleMatch) -> std::cmp::Ordering {
    (b.verdict.severity as u8)
        .cmp(&(a.verdict.severity as u8))
        .then(action_rank(&b.verdict.action).cmp(&action_rank(&a.verdict.action)))
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
    match v.action {
        ResponseAction::StripFileCapability => Target::File(v.event_pid, &v.event_filename),
        _ => Target::Process(v.event_pid),
    }
}

/// The decision from `matches` (any order; sorted here by registration
/// index). `None` when there is none.
pub fn combine(mut matches: Vec<RuleMatch>) -> Option<Decision> {
    if matches.is_empty() {
        return None;
    }
    matches.sort_by_key(|m| m.index);
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
                    match m.applied {
                        Applied::Builtin => String::new(),
                        ref a => format!(", {}", a.name()),
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
            verdict: v(rule, action, sev, 100),
            applied: Applied::Builtin,
            held: None,
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
        assert_eq!(d.primary().rule_id, "KILL");
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
        let mut other = m(2, "OTHER-PID", KillProcess, High);
        other.verdict.event_pid = 200;
        let strip = m(3, "STRIP", StripFileCapability, High);
        let d = combine(vec![
            m(0, "KP", KillProcess, High),
            m(1, "KPT", KillProcessTree, High),
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
        let m = apply_policy(0, R020, A1, out, held, &p, |_| None).unwrap();
        assert_eq!(m.applied, Applied::Builtin);
        assert_eq!(m.verdict.action, Log);
        assert_eq!(m.held, Some(R020_KILL.held));
        assert!(!m.acts());
    }

    /// `enforce` gives the held kill back, with the rule's reasoning.
    #[test]
    fn enforce_gives_a_held_kill_back() {
        let (out, held) = held_kill();
        let p = parse("enforce R020\n").unwrap();
        let m = apply_policy(0, R020, A1, out, held, &p, |_| None).unwrap();
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
        })
        .unwrap();
        assert_eq!(
            (m.verdict.action.clone(), m.applied.clone()),
            (Log, Applied::Alert)
        );
        assert!(m.verdict.reasoning.contains("KillProcess not run"));
        assert!(m.counted());
        let p = parse("audit R020\n").unwrap();
        let m = apply_policy(0, R020, A1, v(R020, KillProcess, High, 1), None, &p, |_| {
            None
        })
        .unwrap();
        assert_eq!(
            (m.verdict.action.clone(), m.applied.clone()),
            (Log, Applied::Audit)
        );
        assert!(!m.counted());
        let p = parse("off R020\n").unwrap();
        assert!(
            apply_policy(0, R020, A1, v(R020, KillProcess, High, 1), None, &p, |_| {
                None
            })
            .is_none()
        );
    }

    /// An exemption wins over `enforce`; it is consulted only when the rule
    /// has one.
    #[test]
    fn an_exemption_makes_the_match_a_record() {
        let p = parse("enforce R020\nexempt R020 uid 998\n").unwrap();
        let (out, held) = held_kill();
        let m = apply_policy(0, R020, A1, out, held, &p, |_| Some("uid 998".into())).unwrap();
        assert_eq!(m.applied, Applied::Exempt("uid 998".into()));
        assert_eq!(m.verdict.action, Log);
        assert!(!m.acts() && !m.counted());
        assert!(m.verdict.reasoning.contains("(uid 998): recorded only]"));
        // Not the exempt actor: enforced.
        let (out, held) = held_kill();
        let m = apply_policy(0, R020, A1, out, held, &p, |_| None).unwrap();
        assert_eq!(m.verdict.action, KillProcessTree);
        // No exemption: the check is never asked.
        let p = parse("enforce R020\n").unwrap();
        let (out, held) = held_kill();
        apply_policy(0, R020, A1, out, held, &p, |_| panic!("asked")).unwrap();
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
}
