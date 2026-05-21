//! R013 — Namespace / container-escape tooling from a non-standard
//! path (Tappa 10.5 D2).
//!
//! MITRE T1611 (Escape to Host). `nsenter` / `unshare` / `runc` are
//! the canonical container-escape primitives. They legitimately ship
//! under the standard binary dirs (util-linux / the container
//! runtime); a copy running from anywhere ELSE (a dropped binary in
//! `/tmp`, `/dev/shm`, a home dir, …) is the escape-attempt shape.
//! Design §7.1: comm ∈ {nsenter, unshare, runc} & filename ∉ standard
//! path, gated by `process-comm-allowlist`.

use std::sync::Arc;

use common::{Event, ResponseAction, Severity, Verdict};

use crate::config::comm_allowlist::CommAllowlist;
use crate::decision::{rules::build_verdict, Rule};

/// Container/namespace escape tool comms (design §7.1).
const ESCAPE_TOOLS: &[&str] = &["nsenter", "unshare", "runc"];

/// Standard system binary directories these tools legitimately live
/// in. A match from outside all of these is the suspicious case.
const STD_EXEC_PREFIXES: &[&str] = &["/usr/bin/", "/bin/", "/usr/sbin/", "/sbin/"];

pub struct R013NamespaceEscapeTooling {
    allowlist: Arc<CommAllowlist>,
}

impl R013NamespaceEscapeTooling {
    pub fn new(allowlist: Arc<CommAllowlist>) -> Self {
        Self { allowlist }
    }
}

impl Rule for R013NamespaceEscapeTooling {
    fn id(&self) -> &'static str {
        "R013_NamespaceEscapeTooling"
    }
    fn name(&self) -> &'static str {
        "Namespace/escape tooling from non-standard path"
    }
    fn category(&self) -> &'static str {
        "privilege_escalation"
    }

    fn evaluate(&self, event: &Event) -> Option<Verdict> {
        let Event::ProcessSpawn { comm, filename, .. } = event else {
            return None;
        };
        if !ESCAPE_TOOLS.contains(&comm.as_str()) {
            return None;
        }
        if STD_EXEC_PREFIXES.iter().any(|p| filename.starts_with(p)) {
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
            "Namespace/escape tool (nsenter/unshare/runc) exec from a \
             non-standard path — container-escape primitive (T1611); \
             posture → ENGAGED",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decision::rules::testutil::spawn;

    fn rule() -> R013NamespaceEscapeTooling {
        R013NamespaceEscapeTooling::new(Arc::new(CommAllowlist::default()))
    }

    #[test]
    fn fires_on_escape_tool_from_nonstandard_path() {
        for tool in ESCAPE_TOOLS {
            let v = rule()
                .evaluate(&spawn(tool, &format!("/tmp/{tool}")))
                .unwrap_or_else(|| panic!("should fire on /tmp/{tool}"));
            assert_eq!(v.rule_id, "R013_NamespaceEscapeTooling");
            assert_eq!(v.action, ResponseAction::KillProcess);
            assert_eq!(v.severity, Severity::High);
        }
    }

    #[test]
    fn ignores_escape_tool_from_standard_path() {
        // Legit util-linux / runtime location → no fire.
        assert!(rule()
            .evaluate(&spawn("nsenter", "/usr/bin/nsenter"))
            .is_none());
        assert!(rule().evaluate(&spawn("runc", "/usr/sbin/runc")).is_none());
        // Non-escape tool from a weird path is not R013's concern.
        assert!(rule().evaluate(&spawn("ls", "/tmp/ls")).is_none());
    }

    #[test]
    fn allowlisted_comm_is_exempt() {
        let r = R013NamespaceEscapeTooling::new(Arc::new(CommAllowlist::from_iter_owned([
            "runc".to_string()
        ])));
        assert!(r.evaluate(&spawn("runc", "/opt/cri/runc")).is_none());
        // A different escape tool from a non-standard path still fires.
        assert!(r.evaluate(&spawn("nsenter", "/tmp/nsenter")).is_some());
    }
}
