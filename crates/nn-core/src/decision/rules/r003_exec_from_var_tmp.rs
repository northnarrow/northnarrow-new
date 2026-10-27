//! R003 — Process executed from `/var/tmp/`.
//!
//! Lab PR 166: the executable is the payload itself, so the response is
//! the tree, as for R001.

use nn_model::{Event, ResponseAction, Severity, Verdict};

use crate::decision::attack::{AttackRef, Tactic};
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
    fn attack(&self) -> &'static [AttackRef] {
        const ATTACK: &[AttackRef] = &[AttackRef::new(Tactic::Execution, "T1059")];
        ATTACK
    }

    fn evaluate(&self, event: &Event) -> Option<Verdict> {
        let Event::ProcessSpawn { filename, exe, .. } = event else {
            return None;
        };
        // Review 61: the file the kernel executed, not the caller's string.
        let filename = exe.path_or(filename);
        if !filename.starts_with("/var/tmp/") {
            return None;
        }
        Some(build_verdict(
            self,
            event,
            ResponseAction::KillProcessTree,
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
        assert_eq!(v.action, ResponseAction::KillProcessTree);
    }

    /// Lab PR 166: the payload's forked children die with it.
    #[test]
    fn r003_kills_the_process_tree() {
        let v = R003ExecFromVarTmp
            .evaluate(&spawn("loader", "/var/tmp/loader"))
            .expect("fires");
        assert_eq!(v.action, ResponseAction::KillProcessTree);
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
