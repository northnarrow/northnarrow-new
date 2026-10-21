//! R016 — Debugger / tracer exec by a non-developer uid (Tappa 10.5
//! D2).
//!
//! The tracer of ptrace injection (ATT&CK T1055.008, its `attack()`;
//! lab PR 221 — the T1622 Debugger Evasion this rule used to name is a
//! payload detecting a debugger, not running one) — and the adjacent
//! credential-dump prep use (`gdb`/`strace` attaching to a process to
//! read its memory). A debugger run by a *service account* (not a human dev,
//! not root) is the anomaly: daemons don't normally trace processes.
//! Medium + Log, scoped to the service-account uid class it shares
//! with R015 ([`super::is_service_uid`]: 1..999, `nobody`, systemd's
//! `DynamicUser=` range; external audit PROC-012) to keep
//! developer/sysadmin debugging — root, human users, their containers'
//! sub-uids — out of scope. Gated by `process-comm-allowlist`.
//! Design §7.1.

use std::sync::Arc;

use common::{Event, ResponseAction, Severity, Verdict};

use crate::config::comm_allowlist::CommAllowlist;
use crate::config::comm_allowlist::Judgement;
use crate::decision::attack::{AttackRef, Tactic};
use crate::decision::{rules::build_verdict, Rule};

/// Debugger / tracer tool comms (design §7.1).
const DEBUGGER_TOOLS: &[&str] = &["gdb", "strace", "ltrace"];

pub struct R016DebuggerServiceUid {
    allowlist: Arc<CommAllowlist>,
}

impl R016DebuggerServiceUid {
    pub fn new(allowlist: Arc<CommAllowlist>) -> Self {
        Self { allowlist }
    }
}

impl Rule for R016DebuggerServiceUid {
    fn id(&self) -> &'static str {
        "R016_DebuggerServiceUid"
    }
    fn name(&self) -> &'static str {
        "Debugger/tracer exec by service account"
    }
    fn category(&self) -> &'static str {
        "defense_evasion"
    }
    fn attack(&self) -> &'static [AttackRef] {
        const ATTACK: &[AttackRef] = &[AttackRef::new(Tactic::Stealth, "T1055.008")];
        ATTACK
    }

    fn evaluate(&self, event: &Event) -> Option<Verdict> {
        let Event::ProcessSpawn {
            comm, uid, argv, ..
        } = event
        else {
            return None;
        };
        if !DEBUGGER_TOOLS.contains(&comm.as_str()) {
            return None;
        }
        // Service-class uid only (PROC-012: nobody and DynamicUser too).
        if !super::is_service_uid(*uid) {
            return None;
        }
        // External audit NETR-003 class: the allowlist judged on what the
        // kernel executed, not on the comm the process chose.
        let judgement = super::judge_spawn(&self.allowlist, event);
        if judgement == Judgement::Allowed {
            return None;
        }
        // D5: `-p <pid>` (attach to a live process) is the credential-dump
        // / live-tamper tell vs launching a target. Additive.
        let mut reasoning = String::from(
            "Debugger/tracer (gdb/strace/ltrace) exec by a service \
             account — ptrace-injection / credential-dump prep; \
             posture → ALERTED",
        );
        if argv
            .iter()
            .any(|a| a == "-p" || a == "--pid" || a == "--attach")
        {
            reasoning = format!("{reasoning} — attaching to a live process (argv has -p/--pid)");
        }
        Some(judgement.apply(
            build_verdict(
                self,
                event,
                ResponseAction::Log,
                Severity::Medium,
                &reasoning,
            ),
            comm,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decision::rules::testutil::{spawn_as, spawn_full};

    fn rule() -> R016DebuggerServiceUid {
        R016DebuggerServiceUid::new(Arc::new(CommAllowlist::default()))
    }

    #[test]
    fn argv_attach_pid_enriches_reasoning() {
        let ev = spawn_full("gdb", "/usr/bin/gdb", 33, &["gdb", "-p", "4242"], "sh");
        let v = rule().evaluate(&ev).expect("fires");
        assert!(v.reasoning.contains("attaching to a live process"));
    }

    #[test]
    fn fires_on_debugger_by_service_uid() {
        for tool in DEBUGGER_TOOLS {
            let v = rule()
                .evaluate(&spawn_as(33, tool, &format!("/usr/bin/{tool}")))
                .unwrap_or_else(|| panic!("should fire on {tool}"));
            assert_eq!(v.rule_id, "R016_DebuggerServiceUid");
            assert_eq!(v.action, ResponseAction::Log);
            assert_eq!(v.severity, Severity::Medium);
        }
    }

    /// External audit PROC-012: a `DynamicUser=yes` unit's transient uid.
    #[test]
    fn dynamic_user_uid_is_service_class() {
        let v = rule()
            .evaluate(&spawn_as(61_500, "strace", "/usr/bin/strace"))
            .expect("fires");
        assert_eq!(v.rule_id, "R016_DebuggerServiceUid");
        assert_eq!(v.action, ResponseAction::Log);
        assert_eq!(v.severity, Severity::Medium);
    }

    /// External audit PROC-012: `nobody` (65534).
    #[test]
    fn nobody_is_service_class() {
        let v = rule()
            .evaluate(&spawn_as(65_534, "gdb", "/usr/bin/gdb"))
            .expect("fires");
        assert_eq!(v.rule_id, "R016_DebuggerServiceUid");
        assert_eq!(v.action, ResponseAction::Log);
    }

    #[test]
    fn ignores_root_or_human_uid() {
        assert!(rule()
            .evaluate(&spawn_as(0, "gdb", "/usr/bin/gdb"))
            .is_none());
        // Human users and a rootless container's sub-uids (PROC-012).
        for uid in [1000, 60_000, 100_000, 100_032] {
            assert!(
                rule()
                    .evaluate(&spawn_as(uid, "strace", "/usr/bin/strace"))
                    .is_none(),
                "{uid}"
            );
        }
        assert!(rule()
            .evaluate(&spawn_as(33, "ls", "/usr/bin/ls"))
            .is_none());
    }

    #[test]
    fn allowlisted_comm_is_exempt() {
        let r = R016DebuggerServiceUid::new(Arc::new(CommAllowlist::from_iter_owned([
            "strace".to_string()
        ])));
        assert!(r
            .evaluate(&spawn_as(33, "strace", "/usr/bin/strace"))
            .is_none());
        assert!(r.evaluate(&spawn_as(33, "gdb", "/usr/bin/gdb")).is_some());
    }
}
