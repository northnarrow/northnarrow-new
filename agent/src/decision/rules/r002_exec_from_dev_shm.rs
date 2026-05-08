//! R002 — Process executed from `/dev/shm/`.

use common::{Event, ResponseAction, Severity, Verdict};

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

    fn evaluate(&self, event: &Event) -> Option<Verdict> {
        let Event::ProcessSpawn { filename, .. } = event else {
            return None;
        };
        if !filename.starts_with("/dev/shm/") {
            return None;
        }
        Some(build_verdict(
            self,
            event,
            ResponseAction::KillProcess,
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
        assert_eq!(v.action, ResponseAction::KillProcess);
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
