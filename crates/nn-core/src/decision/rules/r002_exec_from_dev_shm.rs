//! R002 — Process executed from `/dev/shm/`.
//!
//! Lab PR 166: the executable is the payload itself, so the response is
//! the tree, as for R001.

use nn_model::{Event, ResponseAction, Severity, Verdict};

use crate::decision::attack::{AttackRef, Tactic};
use crate::decision::{rules::build_verdict, Rule};

#[derive(Debug, Default)]
pub struct R002ExecFromDevShm {
    /// The review of #578 (P3): the system's `ldd` running the loader.
    listing: super::LoaderListing,
}

impl R002ExecFromDevShm {
    /// This rule with the lineage's identity of `ldd` (the review of #578).
    pub fn with_loader_listing(mut self, listing: super::LoaderListing) -> Self {
        self.listing = listing;
        self
    }
}

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
        // Lot 370 (05-3.3): a program the dynamic loader runs from it (the
        // review of #578: one it only lists, Low)
        let listing = self.listing.lists(event);
        if let Some((p, use_)) = crate::decision::rules::loader_staged(event, "/dev/shm/", listing)
        {
            if let Some(v) =
                crate::decision::rules::loader_listed_record(self, event, "/dev/shm/", &p, use_)
            {
                return Some(v);
            }
            return Some(build_verdict(
                self,
                event,
                ResponseAction::KillProcessTree,
                Severity::High,
                &format!(
                    "Process executed from /dev/shm/ through the dynamic loader ({p}) — fileless \
                     malware indicator"
                ),
            ));
        }
        // Review 61: the file the kernel executed, not the caller's string.
        // Lot 355: a file of a user's program image (an AppImage's) is the
        // image's, not staged in its mount point's directory.
        let filename = crate::decision::rules::staging_judged_path(exe, filename)?;
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
        let v = R002ExecFromDevShm::default()
            .evaluate(&spawn("dropper", "/dev/shm/dropper"))
            .expect("fires");
        assert_eq!(v.severity, Severity::High);
        assert_eq!(v.action, ResponseAction::KillProcessTree);
    }

    /// Lab PR 166: the payload's forked children die with it.
    #[test]
    fn r002_kills_the_process_tree() {
        let v = R002ExecFromDevShm::default()
            .evaluate(&spawn("dropper", "/dev/shm/dropper"))
            .expect("fires");
        assert_eq!(v.action, ResponseAction::KillProcessTree);
    }

    #[test]
    fn ignores_other_paths() {
        assert!(R002ExecFromDevShm::default()
            .evaluate(&spawn("bash", "/bin/bash"))
            .is_none());
    }

    #[test]
    fn does_not_match_dev_or_dev_shm_root() {
        // /dev/something else
        assert!(R002ExecFromDevShm::default()
            .evaluate(&spawn("x", "/dev/null"))
            .is_none());
        // The bare directory itself is not a binary — the kernel won't
        // emit an exec event for it, but we still don't want to match
        // pseudo-paths missing the trailing slash.
        assert!(R002ExecFromDevShm::default()
            .evaluate(&spawn("x", "/dev/shmcurious"))
            .is_none());
    }
}
