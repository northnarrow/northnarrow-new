//! Lab PR 225 (CM-18): the host's other defences switched off, over the
//! shared [`DefenseDetector`](crate::impair::DefenseDetector) and the
//! shipped list `security-tools.v1` (pinned to the agent's built-in copy,
//! not signed).
//!
//! | Id | Evidence | Action / severity |
//! |---|---|---|
//! | NN-L-EVA-001 | a listed unit stopped, disabled, masked or killed | Log / High |
//! | NN-L-EVA-002 | a listed switch-off command (`auditctl -e 0`, `ufw disable`, …); one record per command and process tree within 10 s, the repeats counted | Log / High |
//! | NN-L-EVA-003 | a stop or end signal to a listed tool's process (`task_kill`, `kill`, `pkill`, `killall`) | Log / High |
//! | NN-L-EVA-004 | a listed tool's configuration changed (FIM) | Log / High |
//!
//! In a package transaction run by root, an administrator's interactive
//! sudo/su session or under a configuration-management actor: Log / Low.
//! Asked by a lineage that holds a program from a staging directory or a
//! deleted or memory-only executable: KillProcessTree of that program /
//! High — a kill new in lab PR 225, held behind the per-rule response
//! policy ([`response_policy::EVA_KILL`], off by default: the record is
//! High, action `Log`, by the decision of 21/10/2026). ATT&CK v20: T1685
//! (Disable or Modify Tools), T1685.004 for the
//! audit system, T1686 for the firewall — tactic Defense Impairment
//! (TA0112), the ids of lab PR 221.

use std::sync::Arc;

use nn_model::{Event, ResponseAction, Severity, Verdict};

use crate::decision::attack::{AttackRef, Tactic};
use crate::decision::host::DecisionHost;
use crate::decision::response_policy::{self, PolicySwitch};
use crate::decision::Rule;
use crate::impair::{DefenseDetector, EvaRule, Finding, SWITCHED_OFF_RULE_ID, SWITCH_OFF_COALESCE};

struct EvaSpec {
    id: &'static str,
    name: &'static str,
    rule: EvaRule,
}

const SPECS: [EvaSpec; 4] = [
    EvaSpec {
        id: "NN-L-EVA-001_SecurityServiceStopped",
        name: "Security tool's service stopped, disabled or masked",
        rule: EvaRule::ServiceStopped,
    },
    EvaSpec {
        id: SWITCHED_OFF_RULE_ID,
        name: "Security tool switched off by its own command",
        rule: EvaRule::SwitchedOff,
    },
    EvaSpec {
        id: "NN-L-EVA-003_SecurityToolKilled",
        name: "Security tool's process killed or stopped",
        rule: EvaRule::Killed,
    },
    EvaSpec {
        id: "NN-L-EVA-004_SecurityToolConfigChanged",
        name: "Security tool's configuration changed",
        rule: EvaRule::ConfigChanged,
    },
];

/// One of NN-L-EVA-001..004.
pub struct NnLEvaSecurityTool<H: DecisionHost> {
    spec: &'static EvaSpec,
    detector: Arc<DefenseDetector<H>>,
    /// The kill of a staged program that asked ([`response_policy::EVA_KILL`]).
    kill: PolicySwitch,
}

impl<H: DecisionHost> Rule for NnLEvaSecurityTool<H> {
    fn id(&self) -> &'static str {
        self.spec.id
    }
    fn name(&self) -> &'static str {
        self.spec.name
    }
    fn category(&self) -> &'static str {
        "defense_impairment"
    }
    fn attack(&self) -> &'static [AttackRef] {
        // Lab PR 221's typed mapping: every class a finding can be of (the
        // record's reasoning names the one it was) — a tool switched off,
        // the audit system, the firewall.
        const ATTACK: &[AttackRef] = &[
            AttackRef::new(Tactic::DefenseImpairment, "T1685"),
            AttackRef::new(Tactic::DefenseImpairment, "T1685.004"),
            AttackRef::new(Tactic::DefenseImpairment, "T1686"),
        ];
        ATTACK
    }
    fn evaluate(&self, event: &Event) -> Option<Verdict> {
        if !matches!(
            event,
            Event::ProcessSpawn { .. } | Event::DefenderSignal { .. } | Event::Fim(_)
        ) {
            return None;
        }
        let f = self.detector.assess(event)?;
        // A repeat coalesced into an earlier record (NN-L-EVA-002): counted
        // there, not recorded again.
        if f.rule != self.spec.rule || f.coalesced_into.is_some() {
            return None;
        }
        Some(self.kill.hold(self.verdict(&f)))
    }
}

impl<H: DecisionHost> NnLEvaSecurityTool<H> {
    fn verdict(&self, f: &Finding) -> Verdict {
        let head = format!(
            "{} ({}, ATT&CK {}): {}",
            self.spec.name,
            f.tool,
            f.class.attack(),
            f.what
        );
        let (action, severity, pid, reasoning) = match (&f.sanctioned, &f.suspicious) {
            (Some(why), _) => (
                ResponseAction::Log,
                Severity::Low,
                f.pid,
                format!("{head} — {why}: recorded"),
            ),
            (None, Some((actor, program))) => (
                ResponseAction::KillProcessTree,
                Severity::High,
                *actor,
                format!(
                    "{head} — asked by a lineage holding {program} (pid {actor}), from a staging \
                     directory or a deleted executable: kill its tree"
                ),
            ),
            (None, None) => (
                ResponseAction::Log,
                Severity::High,
                f.pid,
                format!(
                    "{head} — outside a package transaction and an administrator's \
                     interactive session: recorded"
                ),
            ),
        };
        let reasoning = if f.rule == EvaRule::SwitchedOff && f.suspicious.is_none() {
            format!(
                "{reasoning}; its repeats by the children of the same parent within {} s are \
                 counted, not recorded (detections_held)",
                SWITCH_OFF_COALESCE.as_secs()
            )
        } else {
            reasoning
        };
        Verdict {
            rule_id: self.spec.id.to_string(),
            rule_name: self.spec.name.to_string(),
            category: "defense_impairment".to_string(),
            action,
            severity,
            reasoning,
            event_pid: pid,
            event_filename: f.filename.clone(),
            timestamp_ns: f.timestamp_ns,
        }
    }
}

/// NN-L-EVA-001..004, in id order.
pub fn evasion_rules<H: DecisionHost>(detector: Arc<DefenseDetector<H>>) -> Vec<Box<dyn Rule>> {
    evasion_rules_with_kill(detector, response_policy::EVA_KILL)
}

/// [`evasion_rules`] with their kill switch set to `kill` (tests; the
/// per-rule policy in Phase 2).
pub fn evasion_rules_with_kill<H: DecisionHost>(
    detector: Arc<DefenseDetector<H>>,
    kill: PolicySwitch,
) -> Vec<Box<dyn Rule>> {
    SPECS
        .iter()
        .map(|spec| {
            Box::new(NnLEvaSecurityTool {
                spec,
                detector: Arc::clone(&detector),
                kill,
            }) as Box<dyn Rule>
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    // R08b (lab PR 251): on the portable test host.
    use crate::posture::host::testing::TestHost as H;
    type AuthSessionTracker = crate::posture::lineage::AuthSessionTracker<H>;
    type DefenseDetector = crate::impair::DefenseDetector<H>;
    use crate::impair::SecurityTools;

    const S: u64 = 1_000_000_000;

    fn spawn(pid: u32, ppid: u32, exe: &str, argv: &[&str]) -> Event {
        Event::ProcessSpawn {
            pid,
            ppid,
            uid: 0,
            gid: 0,
            comm: "x".into(),
            filename: exe.to_string(),
            timestamp_ns: 100 * S + pid as u64,
            argv: argv.iter().map(|a| a.to_string()).collect(),
            parent_comm: String::new(),
            parent_start_ns: 0,
            start_ns: 0,
            parent_is_kthread: false,
            exe: nn_model::ExeIdentity::default(),
            argv_truncated: false,
            filename_truncated: false,
            // Lab PR 224: the new image's standard streams (not read here).
            stdio: Default::default(),
        }
    }

    fn rules() -> (tempfile::TempDir, AuthSessionTracker, Vec<Box<dyn Rule>>) {
        let t = tempfile::TempDir::new().unwrap();
        let l = AuthSessionTracker::new(t.path());
        l.ingest_exec(200, 1, "/usr/bin/bash", &["bash".into()], S, S, 0);
        let d = Arc::new(DefenseDetector::new(
            Arc::new(SecurityTools::builtin()),
            l.clone(),
            None,
        ));
        (t, l, evasion_rules(d))
    }

    fn first(rules: &[Box<dyn Rule>], e: &Event) -> Option<Verdict> {
        rules.iter().find_map(|r| r.evaluate(e))
    }

    /// Lab PR 225 (MS-25): `systemctl stop auditd`, `auditctl -e 0`,
    /// `ufw disable` — each its rule, High, recorded.
    #[test]
    fn eva_rules_record_the_ms25_commands() {
        let (_t, l, rules) = rules();
        for (pid, exe, argv, id, attack) in [
            (
                301,
                "/usr/bin/systemctl",
                vec!["systemctl", "stop", "auditd"],
                "NN-L-EVA-001_SecurityServiceStopped",
                "T1685.004",
            ),
            (
                302,
                "/usr/sbin/auditctl",
                vec!["auditctl", "-e", "0"],
                "NN-L-EVA-002_SecurityToolSwitchedOff",
                "T1685.004",
            ),
            (
                303,
                "/usr/sbin/ufw",
                vec!["ufw", "disable"],
                "NN-L-EVA-002_SecurityToolSwitchedOff",
                "T1686",
            ),
            (
                304,
                "/usr/bin/pkill",
                vec!["pkill", "-9", "rsyslogd"],
                "NN-L-EVA-003_SecurityToolKilled",
                "T1685",
            ),
        ] {
            let argv_s: Vec<String> = argv.iter().map(|a| a.to_string()).collect();
            l.ingest_exec(
                pid,
                200,
                exe,
                &argv_s,
                100 * S + pid as u64,
                100 * S + pid as u64,
                0,
            );
            let v =
                first(&rules, &spawn(pid, 200, exe, &argv)).unwrap_or_else(|| panic!("{argv:?}"));
            assert_eq!(v.rule_id, id, "{argv:?}");
            assert_eq!(
                (v.action, v.severity),
                (ResponseAction::Log, Severity::High)
            );
            assert!(v.reasoning.contains(attack), "{}", v.reasoning);
        }
        assert!(first(
            &rules,
            &spawn(
                305,
                200,
                "/usr/bin/systemctl",
                &["systemctl", "restart", "auditd"]
            )
        )
        .is_none());
    }

    /// Lab PR 225: `ufw disable` runs `ufw-init`, which flushes and resets
    /// each chain with one `iptables`/`ip6tables` exec apiece — a High
    /// record each. One record per command and process tree within the
    /// window, the first at once, the repeats counted; another tree, a
    /// later window and a staged lineage still draw their own.
    #[test]
    fn eva_002_coalesces_the_iptables_calls_of_one_ufw_disable() {
        let (_t, l, _) = rules();
        let d = Arc::new(DefenseDetector::new(
            Arc::new(SecurityTools::builtin()),
            l.clone(),
            None,
        ));
        let rules = evasion_rules(Arc::clone(&d));
        let at = |pid: u32, s: u64| 100 * S + s * S + u64::from(pid);
        let run = |pid: u32, ppid: u32, exe: &str, argv: &[&str], ts: u64| {
            let argv_s: Vec<String> = argv.iter().map(|a| a.to_string()).collect();
            l.ingest_exec(pid, ppid, exe, &argv_s, ts, ts, 0);
            let mut e = spawn(pid, ppid, exe, argv);
            if let Event::ProcessSpawn { timestamp_ns, .. } = &mut e {
                *timestamp_ns = ts;
            }
            first(&rules, &e)
        };
        let ipt = "/usr/sbin/xtables-nft-multi";
        let mut verdicts = Vec::new();
        verdicts.extend(run(
            600,
            200,
            "/usr/sbin/ufw",
            &["ufw", "disable"],
            at(600, 0),
        ));
        verdicts.extend(run(
            601,
            600,
            "/usr/lib/ufw/ufw-init",
            &["/bin/sh", "/usr/lib/ufw/ufw-init", "force-stop"],
            at(601, 0),
        ));
        for pid in 602..632 {
            verdicts.extend(run(
                pid,
                601,
                ipt,
                &["iptables", "-F", "ufw-user-input"],
                at(pid, 1),
            ));
        }
        for pid in 632..642 {
            verdicts.extend(run(
                pid,
                601,
                ipt,
                &["ip6tables", "-F", "ufw6-user-input"],
                at(pid, 2),
            ));
        }
        for pid in 642..645 {
            verdicts.extend(run(
                pid,
                601,
                ipt,
                &["iptables", "-P", "INPUT", "ACCEPT"],
                at(pid, 2),
            ));
        }
        let shown: Vec<(&str, u32)> = verdicts
            .iter()
            .map(|v| (v.reasoning.split('`').nth(1).unwrap_or(""), v.event_pid))
            .collect();
        assert_eq!(
            shown,
            vec![
                ("ufw disable", 600),
                ("iptables -F", 602),
                ("ip6tables -F", 632),
                ("iptables -P INPUT ACCEPT", 642),
            ],
        );
        for v in &verdicts {
            assert_eq!(v.rule_id, SWITCHED_OFF_RULE_ID);
            assert_eq!(
                (v.action.clone(), v.severity),
                (ResponseAction::Log, Severity::High)
            );
            assert!(
                v.reasoning.contains("counted, not recorded"),
                "{}",
                v.reasoning
            );
        }
        // Another process tree, in the same window: its own record.
        let v = run(651, 650, ipt, &["iptables", "-F"], at(651, 3)).unwrap();
        assert_eq!(v.event_pid, 651);
        // The first tree after the window: recorded again, at once.
        let v = run(700, 601, ipt, &["iptables", "-F"], at(700, 12)).unwrap();
        assert_eq!(v.event_pid, 700);
        assert!(run(701, 601, ipt, &["iptables", "-F"], at(701, 12)).is_none());
        // A staged script's calls are never coalesced: each is its verdict
        // (the kill path, held by default).
        l.ingest_exec(
            800,
            200,
            "/usr/bin/bash",
            &["bash".into(), "/tmp/.x/off.sh".into()],
            99 * S,
            99 * S,
            0,
        );
        for pid in [801, 802] {
            let v = run(pid, 800, ipt, &["iptables", "-F"], at(pid, 4)).unwrap();
            assert_eq!(v.event_pid, 800);
            assert!(
                v.reasoning.contains("[held back: the kill"),
                "{}",
                v.reasoning
            );
        }
        // The repeats, 29 + 9 + 2 + 1, are counted apart from the findings
        // (the six recorded and the staged script's two).
        let c = d.counts();
        assert_eq!((c.coalesced, c.findings), (41, 8));
    }

    /// A script from /tmp that stops a cloud agent: its tree is killed.
    #[test]
    fn eva_kills_a_staged_script_that_asks() {
        let (_t, l, rules) = rules();
        l.ingest_exec(
            500,
            200,
            "/usr/bin/bash",
            &["bash".into(), "/tmp/.x/a.sh".into()],
            99 * S,
            99 * S,
            0,
        );
        let argv = ["systemctl", "disable", "--now", "aegis"];
        let argv_s: Vec<String> = argv.iter().map(|a| a.to_string()).collect();
        l.ingest_exec(
            501,
            500,
            "/usr/bin/systemctl",
            &argv_s,
            100 * S + 501,
            100 * S + 501,
            0,
        );
        let v = first(&rules, &spawn(501, 500, "/usr/bin/systemctl", &argv)).unwrap();
        assert_eq!(v.rule_id, "NN-L-EVA-001_SecurityServiceStopped");
        // The kill is held behind the per-rule policy, off by default.
        assert_eq!(v.action, ResponseAction::Log);
        assert_eq!(v.severity, Severity::High);
        assert!(
            v.reasoning.contains("[held back: the kill"),
            "{}",
            v.reasoning
        );
        assert_eq!(v.event_pid, 500);
        // With the switch on, the staged program's tree is killed.
        let d = Arc::new(DefenseDetector::new(
            Arc::new(SecurityTools::builtin()),
            l.clone(),
            None,
        ));
        let on = evasion_rules_with_kill(d, response_policy::EVA_KILL.enabled());
        let v = first(&on, &spawn(501, 500, "/usr/bin/systemctl", &argv)).unwrap();
        assert_eq!(v.action, ResponseAction::KillProcessTree);
        assert_eq!(v.event_pid, 500);
    }
}
