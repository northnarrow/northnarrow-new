//! R016 — Debugger / tracer exec by a non-developer uid (Tappa 10.5
//! D2).
//!
//! MITRE T1622 (Debugger Evasion) — and the adjacent credential-dump
//! prep use (`gdb`/`strace` attaching to a process to read its
//! memory). A debugger run by a *service account* (not a human dev,
//! not root) is the anomaly: daemons don't normally trace processes.
//! Medium + Log, scoped to the same non-root system-account uid class
//! as R015 (`uid != 0 && uid < 1000`) to keep developer/sysadmin
//! debugging out of scope. Gated by `process-comm-allowlist`.
//! Design §7.1.

use std::sync::Arc;

use common::{Event, ResponseAction, Severity, Verdict};

use crate::config::comm_allowlist::CommAllowlist;
use crate::decision::{rules::build_verdict, Rule};

/// Debugger / tracer tool comms (design §7.1).
const DEBUGGER_TOOLS: &[&str] = &["gdb", "strace", "ltrace"];

/// Linux `UID_MIN` boundary (see R015): accounts below this and
/// non-root are system/service accounts, i.e. "non-developer".
const SYSTEM_UID_CEILING: u32 = 1000;

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

    fn evaluate(&self, event: &Event) -> Option<Verdict> {
        let Event::ProcessSpawn { comm, uid, .. } = event else {
            return None;
        };
        if !DEBUGGER_TOOLS.contains(&comm.as_str()) {
            return None;
        }
        if *uid == 0 || *uid >= SYSTEM_UID_CEILING {
            return None;
        }
        if self.allowlist.contains(comm) {
            return None;
        }
        Some(build_verdict(
            self,
            event,
            ResponseAction::Log,
            Severity::Medium,
            "Debugger/tracer (gdb/strace/ltrace) exec by a service \
             account — debugger-evasion / credential-dump prep \
             (T1622); posture → ALERTED",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decision::rules::testutil::spawn_as;

    fn rule() -> R016DebuggerServiceUid {
        R016DebuggerServiceUid::new(Arc::new(CommAllowlist::default()))
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

    #[test]
    fn ignores_root_or_human_uid() {
        assert!(rule()
            .evaluate(&spawn_as(0, "gdb", "/usr/bin/gdb"))
            .is_none());
        assert!(rule()
            .evaluate(&spawn_as(1000, "strace", "/usr/bin/strace"))
            .is_none());
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
