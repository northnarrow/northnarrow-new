//! R003 — Process executed from `/var/tmp/`.

use common::{Event, ResponseAction, Severity, Verdict};

use crate::decision::{rules::build_verdict, Rule};

pub struct R003ExecFromVarTmp;

impl Rule for R003ExecFromVarTmp {
    fn id(&self) -> &'static str {
        "R003_ExecFromVarTmp"
    }
    fn name(&self) -> &'static str {
        "Exec from /var/tmp/"
    }
    fn category(&self) -> &'static str {
        "execution"
    }

    fn evaluate(&self, event: &Event) -> Option<Verdict> {
        let Event::ProcessSpawn { filename, .. } = event else {
            return None;
        };
        if !filename.starts_with("/var/tmp/") {
            return None;
        }
        Some(build_verdict(
            self,
            event,
            ResponseAction::KillProcess,
            Severity::Medium,
            "Process executed from /var/tmp/ — persistent staging location",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decision::rules::testutil::spawn;

    #[test]
    fn fires_on_var_tmp() {
        let v = R003ExecFromVarTmp
            .evaluate(&spawn("loader", "/var/tmp/loader"))
            .expect("fires");
        assert_eq!(v.severity, Severity::Medium);
        assert_eq!(v.action, ResponseAction::KillProcess);
    }

    #[test]
    fn ignores_plain_tmp_and_legit_paths() {
        // /tmp/ is R001's job; /usr/bin/ is fine.
        assert!(R003ExecFromVarTmp.evaluate(&spawn("x", "/tmp/x")).is_none());
        assert!(R003ExecFromVarTmp
            .evaluate(&spawn("ls", "/usr/bin/ls"))
            .is_none());
    }

    #[test]
    fn does_not_match_var_root_or_lookalikes() {
        assert!(R003ExecFromVarTmp
            .evaluate(&spawn("x", "/var/tmpfoo/x"))
            .is_none());
        assert!(R003ExecFromVarTmp
            .evaluate(&spawn("x", "/var/log/syslog"))
            .is_none());
    }
}
