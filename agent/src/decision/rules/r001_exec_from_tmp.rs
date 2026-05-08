//! R001 — Process executed from `/tmp/`.

use common::{Event, ResponseAction, Severity, Verdict};

use crate::decision::{rules::build_verdict, Rule};

/// Filenames inside `/tmp/` that are NOT considered suspicious.
/// Empty for now; the slot exists so legit tooling (build systems
/// staging compiled artifacts, etc.) can be carved out without
/// touching the rule body.
const TMP_WHITELIST: &[&str] = &[];

pub struct R001ExecFromTmp;

impl Rule for R001ExecFromTmp {
    fn id(&self) -> &'static str {
        "R001_ExecFromTmp"
    }
    fn name(&self) -> &'static str {
        "Exec from /tmp/"
    }
    fn category(&self) -> &'static str {
        "execution"
    }

    fn evaluate(&self, event: &Event) -> Option<Verdict> {
        let Event::ProcessSpawn { filename, .. } = event else {
            return None;
        };
        if !filename.starts_with("/tmp/") {
            return None;
        }
        if TMP_WHITELIST.iter().any(|w| filename == w) {
            return None;
        }
        Some(build_verdict(
            self,
            event,
            ResponseAction::KillProcess,
            Severity::Medium,
            "Process executed from /tmp/ — common malware staging location",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decision::rules::testutil::spawn;

    #[test]
    fn fires_on_exec_from_tmp() {
        let event = spawn("payload", "/tmp/payload");
        let v = R001ExecFromTmp.evaluate(&event).expect("should fire");
        assert_eq!(v.rule_id, "R001_ExecFromTmp");
        assert_eq!(v.action, ResponseAction::KillProcess);
        assert_eq!(v.severity, Severity::Medium);
        assert_eq!(v.event_filename, "/tmp/payload");
    }

    #[test]
    fn ignores_legitimate_paths() {
        let event = spawn("ls", "/usr/bin/ls");
        assert!(R001ExecFromTmp.evaluate(&event).is_none());
    }

    #[test]
    fn does_not_match_path_named_like_tmp_elsewhere() {
        // `/var/tmp/...` is R003's job, not R001's. `/tmpfoo/...`
        // (no trailing slash) is unrelated.
        assert!(R001ExecFromTmp
            .evaluate(&spawn("x", "/var/tmp/x"))
            .is_none());
        assert!(R001ExecFromTmp
            .evaluate(&spawn("tmpfoo", "/tmpfoo/payload"))
            .is_none());
    }
}
