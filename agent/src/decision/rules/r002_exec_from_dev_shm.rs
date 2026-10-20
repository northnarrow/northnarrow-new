//! R002 — Process executed from `/dev/shm/`.
//!
//! Lab PR 166: the executable is the payload itself, so the response is
//! the tree, as for R001.

use common::{Event, ResponseAction, Severity, Verdict};

use crate::decision::attack::{AttackRef, Tactic};
use crate::decision::{rules::build_verdict, Rule};

pub struct R002ExecFromDevShm;

impl Rule for R002ExecFromDevShm {
    fn id(&self) -> &'static str {
        "R002_ExecFromDevShm"
    }
    fn name(&self) -> &'static str {
        "Exec from /dev/shm/"
    }
    fn category(&self) -> &'static str {
        "execution"
    }
    fn attack(&self) -> &'static [AttackRef] {
        const ATTACK: &[AttackRef] = &[
            AttackRef::new(Tactic::Execution, "T1059"),
            AttackRef::new(Tactic::Stealth, "T1027.011"),
        ];
        ATTACK
    }

    fn evaluate(&self, event: &Event) -> Option<Verdict> {
        let Event::ProcessSpawn { filename, exe, .. } = event else {
            return None;
        };
        // Review 61: the file the kernel executed, not the caller's string.
        let filename = exe.path_or(filename);
        if !filename.starts_with("/dev/shm/") {
            return None;
        }
        Some(build_verdict(
            self,
            event,
            ResponseAction::KillProcessTree,
            Severity::High,
            "Process executed from /dev/shm/ — fileless malware indicator",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decision::rules::testutil::spawn;

    #[test]
    fn fires_on_dev_shm() {
        let v = R002ExecFromDevShm
            .evaluate(&spawn("dropper", "/dev/shm/dropper"))
            .expect("fires");
        assert_eq!(v.severity, Severity::High);
        assert_eq!(v.action, ResponseAction::KillProcessTree);
    }

    /// Lab PR 166: the payload's forked children die with it.
    #[test]
    fn r002_kills_the_process_tree() {
        let v = R002ExecFromDevShm
            .evaluate(&spawn("dropper", "/dev/shm/dropper"))
            .expect("fires");
        assert_eq!(v.action, ResponseAction::KillProcessTree);
    }

    #[test]
    fn ignores_other_paths() {
        assert!(R002ExecFromDevShm
            .evaluate(&spawn("bash", "/bin/bash"))
            .is_none());
    }

    #[test]
    fn does_not_match_dev_or_dev_shm_root() {
        // /dev/something else
        assert!(R002ExecFromDevShm
            .evaluate(&spawn("x", "/dev/null"))
            .is_none());
        // The bare directory itself is not a binary — the kernel won't
        // emit an exec event for it, but we still don't want to match
        // pseudo-paths missing the trailing slash.
        assert!(R002ExecFromDevShm
            .evaluate(&spawn("x", "/dev/shmcurious"))
            .is_none());
    }
}
