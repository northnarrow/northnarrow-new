//! R011 — Kernel-module tooling exec (Tappa 10.5 D2).
//!
//! MITRE T1547.006 (Boot or Logon Autostart Execution: Kernel
//! Modules and Extensions). A process whose `comm` is one of the
//! kernel-module load/manage tools is a kernel-rootkit / persistence
//! indicator. The design §7.1 trigger is "comm ∈ {insmod, modprobe,
//! kmod} & uid ≠ pkg-mgr context"; the package-manager-context guard
//! needs the parent `comm`, which `Event::ProcessSpawn` does not
//! carry (deferred to T10.6 per the accepted architectural limit), so
//! the false-positive guard is the operator `process-comm-allowlist`:
//! a site that loads modules from trusted automation adds the tool's
//! comm to the allowlist `.local` overlay.

use std::sync::Arc;

use common::{Event, ResponseAction, Severity, Verdict};

use crate::config::comm_allowlist::CommAllowlist;
use crate::decision::{rules::build_verdict, Rule};

/// Kernel-module load/manage tool comms (design §7.1).
const KMOD_TOOLS: &[&str] = &["insmod", "modprobe", "kmod"];

pub struct R011KernelModuleTooling {
    allowlist: Arc<CommAllowlist>,
}

impl R011KernelModuleTooling {
    pub fn new(allowlist: Arc<CommAllowlist>) -> Self {
        Self { allowlist }
    }
}

impl Rule for R011KernelModuleTooling {
    fn id(&self) -> &'static str {
        "R011_KernelModuleTooling"
    }
    fn name(&self) -> &'static str {
        "Kernel-module tooling exec"
    }
    fn category(&self) -> &'static str {
        "persistence"
    }

    fn evaluate(&self, event: &Event) -> Option<Verdict> {
        let Event::ProcessSpawn { comm, .. } = event else {
            return None;
        };
        if !KMOD_TOOLS.contains(&comm.as_str()) {
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
            "Kernel-module tooling (insmod/modprobe/kmod) exec — kernel \
             rootkit / persistence indicator (T1547.006); parent-context \
             refinement deferred to T10.6 — posture → ENGAGED",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decision::rules::testutil::spawn;

    fn rule() -> R011KernelModuleTooling {
        R011KernelModuleTooling::new(Arc::new(CommAllowlist::default()))
    }

    #[test]
    fn fires_on_kmod_tooling() {
        for tool in KMOD_TOOLS {
            let v = rule()
                .evaluate(&spawn(tool, &format!("/usr/sbin/{tool}")))
                .unwrap_or_else(|| panic!("should fire on {tool}"));
            assert_eq!(v.rule_id, "R011_KernelModuleTooling");
            assert_eq!(v.action, ResponseAction::KillProcess);
            assert_eq!(v.severity, Severity::High);
        }
    }

    #[test]
    fn ignores_non_kmod_tooling() {
        assert!(rule().evaluate(&spawn("ls", "/usr/bin/ls")).is_none());
        // A non-ProcessSpawn event never matches.
        assert!(rule()
            .evaluate(&spawn("modprobed-but-not-exact", "/usr/sbin/x"))
            .is_none());
    }

    #[test]
    fn allowlisted_comm_is_exempt() {
        let r = R011KernelModuleTooling::new(Arc::new(CommAllowlist::from_iter_owned([
            "modprobe".to_string(),
        ])));
        assert!(r
            .evaluate(&spawn("modprobe", "/usr/sbin/modprobe"))
            .is_none());
        // A different kmod tool not on the allowlist still fires.
        assert!(r.evaluate(&spawn("insmod", "/usr/sbin/insmod")).is_some());
    }
}
