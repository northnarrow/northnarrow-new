//! R006 — Known offensive security tooling.

use common::{Event, ResponseAction, Severity, Verdict};

use crate::decision::{rules::build_verdict, Rule};

const OFFSEC_COMMS: &[&str] = &["socat", "msfvenom", "meterpreter", "sliver", "havoc"];

pub struct R006ReverseShellTooling;

impl Rule for R006ReverseShellTooling {
    fn id(&self) -> &'static str {
        "R006_ReverseShellTooling"
    }
    fn name(&self) -> &'static str {
        "Reverse shell tooling"
    }
    fn category(&self) -> &'static str {
        "lateral_movement"
    }

    fn evaluate(&self, event: &Event) -> Option<Verdict> {
        let Event::ProcessSpawn { comm, .. } = event else {
            return None;
        };
        if !OFFSEC_COMMS.iter().any(|c| comm == c) {
            return None;
        }
        Some(build_verdict(
            self,
            event,
            ResponseAction::KillProcess,
            Severity::Critical,
            "Known offensive security tooling detected",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decision::rules::testutil::spawn;

    #[test]
    fn fires_on_each_offsec_tool() {
        for comm in OFFSEC_COMMS {
            let v = R006ReverseShellTooling
                .evaluate(&spawn(comm, "/usr/local/bin/whatever"))
                .unwrap_or_else(|| panic!("should fire on {comm}"));
            assert_eq!(v.action, ResponseAction::KillProcess);
            assert_eq!(v.severity, Severity::Critical);
        }
    }

    #[test]
    fn ignores_benign_tools() {
        assert!(R006ReverseShellTooling
            .evaluate(&spawn("ssh", "/usr/bin/ssh"))
            .is_none());
    }

    #[test]
    fn match_is_exact_not_prefix() {
        assert!(R006ReverseShellTooling
            .evaluate(&spawn("socat-helper", "/usr/bin/socat-helper"))
            .is_none());
    }
}
