//! R005 — Netcat-family tool launched. Alert only; netcat has legit uses.

use common::{Event, ResponseAction, Severity, Verdict};

use crate::decision::{rules::build_verdict, Rule};

const NETCAT_COMMS: &[&str] = &["nc", "ncat", "netcat", "nc.openbsd", "nc.traditional"];

pub struct R005NetcatExec;

impl Rule for R005NetcatExec {
    fn id(&self) -> &'static str {
        "R005_NetcatExec"
    }
    fn name(&self) -> &'static str {
        "Netcat family launched"
    }
    fn category(&self) -> &'static str {
        "lateral_movement"
    }

    fn evaluate(&self, event: &Event) -> Option<Verdict> {
        let Event::ProcessSpawn { comm, .. } = event else {
            return None;
        };
        if !NETCAT_COMMS.iter().any(|c| comm == c) {
            return None;
        }
        Some(build_verdict(
            self,
            event,
            ResponseAction::Log,
            Severity::High,
            "Netcat-family tool launched — possible reverse shell vector",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decision::rules::testutil::spawn;

    #[test]
    fn fires_on_each_netcat_alias() {
        for comm in NETCAT_COMMS {
            let v = R005NetcatExec
                .evaluate(&spawn(comm, "/usr/bin/nc"))
                .unwrap_or_else(|| panic!("rule should fire on {comm}"));
            assert_eq!(v.action, ResponseAction::Log);
            assert_eq!(v.severity, Severity::High);
        }
    }

    #[test]
    fn ignores_unrelated_comms() {
        assert!(R005NetcatExec
            .evaluate(&spawn("ls", "/usr/bin/ls"))
            .is_none());
    }

    #[test]
    fn does_not_match_substrings() {
        // "ncurses-tool" contains "nc" as a substring but is not nc.
        assert!(R005NetcatExec
            .evaluate(&spawn("ncurses-tool", "/usr/bin/ncurses-tool"))
            .is_none());
    }
}
