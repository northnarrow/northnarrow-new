//! R012 — Capability-set tooling exec (Tappa 10.5 D2).
//!
//! MITRE T1548 (Abuse Elevation Control Mechanism). `setcap` grants
//! file capabilities (e.g. `cap_setuid`, `cap_dac_override`) that are
//! a stealthier privilege-escalation primitive than a setuid bit.
//! Design §7.1: comm = `setcap`, gated by `process-comm-allowlist`
//! (a provisioning tool that legitimately sets caps adds its comm to
//! the overlay).

use std::sync::Arc;

use common::{Event, ResponseAction, Severity, Verdict};

use crate::config::comm_allowlist::CommAllowlist;
use crate::decision::{rules::build_verdict, Rule};

pub struct R012SetcapTooling {
    allowlist: Arc<CommAllowlist>,
}

impl R012SetcapTooling {
    pub fn new(allowlist: Arc<CommAllowlist>) -> Self {
        Self { allowlist }
    }
}

impl Rule for R012SetcapTooling {
    fn id(&self) -> &'static str {
        "R012_SetcapTooling"
    }
    fn name(&self) -> &'static str {
        "Capability-set tooling exec"
    }
    fn category(&self) -> &'static str {
        "privilege_escalation"
    }

    fn evaluate(&self, event: &Event) -> Option<Verdict> {
        let Event::ProcessSpawn { comm, .. } = event else {
            return None;
        };
        if comm != "setcap" {
            return None;
        }
        if self.allowlist.contains(comm) {
            return None;
        }
        Some(build_verdict(
            self,
            event,
            ResponseAction::KillProcess,
            Severity::High,
            "setcap exec — file-capability privilege-escalation primitive \
             (T1548); posture → ENGAGED",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decision::rules::testutil::spawn;

    fn rule() -> R012SetcapTooling {
        R012SetcapTooling::new(Arc::new(CommAllowlist::default()))
    }

    #[test]
    fn fires_on_setcap() {
        let v = rule()
            .evaluate(&spawn("setcap", "/usr/sbin/setcap"))
            .expect("should fire");
        assert_eq!(v.rule_id, "R012_SetcapTooling");
        assert_eq!(v.action, ResponseAction::KillProcess);
        assert_eq!(v.severity, Severity::High);
    }

    #[test]
    fn ignores_non_setcap() {
        assert!(rule()
            .evaluate(&spawn("getcap", "/usr/sbin/getcap"))
            .is_none());
        assert!(rule().evaluate(&spawn("ls", "/usr/bin/ls")).is_none());
    }

    #[test]
    fn allowlisted_comm_is_exempt() {
        let r = R012SetcapTooling::new(Arc::new(CommAllowlist::from_iter_owned([
            "setcap".to_string()
        ])));
        assert!(r.evaluate(&spawn("setcap", "/usr/sbin/setcap")).is_none());
    }
}
