//! R014 — `at` / `batch` scheduling-binary exec (Tappa 10.5 D2).
//!
//! MITRE T1053.002 (Scheduled Task/Job: At). One-shot job scheduling
//! is a low-noise persistence / delayed-execution primitive. Medium +
//! Log (the legitimate-admin base rate is high), gated by
//! `process-comm-allowlist`. Design §7.1.

use std::sync::Arc;

use common::{Event, ResponseAction, Severity, Verdict};

use crate::config::comm_allowlist::CommAllowlist;
use crate::decision::{rules::build_verdict, Rule};

/// One-shot scheduling tool comms (design §7.1).
const SCHEDULING_TOOLS: &[&str] = &["at", "batch"];

pub struct R014AtBatchScheduling {
    allowlist: Arc<CommAllowlist>,
}

impl R014AtBatchScheduling {
    pub fn new(allowlist: Arc<CommAllowlist>) -> Self {
        Self { allowlist }
    }
}

impl Rule for R014AtBatchScheduling {
    fn id(&self) -> &'static str {
        "R014_AtBatchScheduling"
    }
    fn name(&self) -> &'static str {
        "at/batch scheduling exec"
    }
    fn category(&self) -> &'static str {
        "persistence"
    }

    fn evaluate(&self, event: &Event) -> Option<Verdict> {
        let Event::ProcessSpawn { comm, argv, .. } = event else {
            return None;
        };
        if !SCHEDULING_TOOLS.contains(&comm.as_str()) {
            return None;
        }
        if self.allowlist.contains(comm) {
            return None;
        }
        // D5: surface the scheduled time-spec from argv (e.g. `at now + 1
        // minute`) for triage. Additive — base fires regardless.
        let mut reasoning = String::from(
            "at/batch one-shot scheduling exec — delayed-execution / \
             persistence primitive (T1053.002); posture → ALERTED",
        );
        if argv.len() > 1 {
            reasoning = format!("{reasoning} — argv: {}", argv.join(" "));
        }
        Some(build_verdict(
            self,
            event,
            ResponseAction::Log,
            Severity::Medium,
            &reasoning,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decision::rules::testutil::{spawn, spawn_full};

    fn rule() -> R014AtBatchScheduling {
        R014AtBatchScheduling::new(Arc::new(CommAllowlist::default()))
    }

    #[test]
    fn fires_on_scheduling_tool() {
        for tool in SCHEDULING_TOOLS {
            let v = rule()
                .evaluate(&spawn(tool, &format!("/usr/bin/{tool}")))
                .unwrap_or_else(|| panic!("should fire on {tool}"));
            assert_eq!(v.rule_id, "R014_AtBatchScheduling");
            assert_eq!(v.action, ResponseAction::Log);
            assert_eq!(v.severity, Severity::Medium);
        }
    }

    #[test]
    fn argv_schedule_spec_enriches_reasoning() {
        let ev = spawn_full(
            "at",
            "/usr/bin/at",
            1000,
            &["at", "now", "+", "1", "minute"],
            "bash",
        );
        let v = rule().evaluate(&ev).expect("fires");
        assert!(v.reasoning.contains("argv: at now + 1 minute"));
    }

    #[test]
    fn ignores_non_scheduling_tool() {
        // `atd` (the daemon) is not `at` (the client) — exact match.
        assert!(rule().evaluate(&spawn("atd", "/usr/sbin/atd")).is_none());
        assert!(rule().evaluate(&spawn("ls", "/usr/bin/ls")).is_none());
    }

    #[test]
    fn allowlisted_comm_is_exempt() {
        let r =
            R014AtBatchScheduling::new(Arc::new(CommAllowlist::from_iter_owned(
                ["at".to_string()],
            )));
        assert!(r.evaluate(&spawn("at", "/usr/bin/at")).is_none());
    }
}
