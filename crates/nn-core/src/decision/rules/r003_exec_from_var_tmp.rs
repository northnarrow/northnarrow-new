//! R003 — Process executed from `/var/tmp/`.
//!
//! Lab PR 166: the executable is the payload itself, so the response is
//! the tree, as for R001.

use nn_model::{Event, ResponseAction, Severity, Verdict};

use crate::decision::attack::{AttackRef, Tactic};
use crate::decision::{rules::build_verdict, Rule};

#[derive(Debug, Default)]
pub struct R003ExecFromVarTmp {
    /// Lot 369: the packaged `go`'s own build output, recorded Low.
    go: super::GoBuilds,
    /// The review of #578 (P3): the system's `ldd` running the loader.
    listing: super::LoaderListing,
}

impl R003ExecFromVarTmp {
    /// This rule with lot 346's identity of `go`'s build output (lot 369).
    pub fn with_go_builds(mut self, go: super::GoBuilds) -> Self {
        self.go = go;
        self
    }

    /// This rule with the lineage's identity of `ldd` (the review of #578).
    pub fn with_loader_listing(mut self, listing: super::LoaderListing) -> Self {
        self.listing = listing;
        self
    }
}

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
        // Lot 370 (05-3.3): a program the dynamic loader runs from it (the
        // review of #578: one it only lists, Low)
        let listing = self.listing.lists(event);
        if let Some((p, use_)) = crate::decision::rules::loader_staged(event, "/var/tmp/", listing)
        {
            if let Some(v) =
                crate::decision::rules::loader_listed_record(self, event, "/var/tmp/", &p, use_)
            {
                return Some(v);
            }
            return Some(build_verdict(
                self,
                event,
                ResponseAction::KillProcessTree,
                Severity::Medium,
                &format!(
                    "Process executed from /var/tmp/ through the dynamic loader ({p}) — \
                     persistent staging location"
                ),
            ));
        }
        // Review 61: the file the kernel executed, not the caller's string.
        // Lot 355: a file of a user's program image (an AppImage's) is the
        // image's, not staged in its mount point's directory.
        let filename = crate::decision::rules::staging_judged_path(exe, filename)?;
        if !filename.starts_with("/var/tmp/") {
            return None;
        }
        // lot 369: `go test`'s binary and `go run`'s program, by identity
        if self.go.runs(event, filename) {
            return Some(super::go_build_record(self, event, "/var/tmp/"));
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
        let v = R003ExecFromVarTmp::default()
            .evaluate(&spawn("loader", "/var/tmp/loader"))
            .expect("fires");
        assert_eq!(v.severity, Severity::Medium);
        assert_eq!(v.action, ResponseAction::KillProcessTree);
    }

    /// Lab PR 166: the payload's forked children die with it.
    #[test]
    fn r003_kills_the_process_tree() {
        let v = R003ExecFromVarTmp::default()
            .evaluate(&spawn("loader", "/var/tmp/loader"))
            .expect("fires");
        assert_eq!(v.action, ResponseAction::KillProcessTree);
    }

    #[test]
    fn ignores_plain_tmp_and_legit_paths() {
        // /tmp/ is R001's job; /usr/bin/ is fine.
        assert!(R003ExecFromVarTmp::default()
            .evaluate(&spawn("x", "/tmp/x"))
            .is_none());
        assert!(R003ExecFromVarTmp::default()
            .evaluate(&spawn("ls", "/usr/bin/ls"))
            .is_none());
    }

    #[test]
    fn does_not_match_var_root_or_lookalikes() {
        assert!(R003ExecFromVarTmp::default()
            .evaluate(&spawn("x", "/var/tmpfoo/x"))
            .is_none());
        assert!(R003ExecFromVarTmp::default()
            .evaluate(&spawn("x", "/var/log/syslog"))
            .is_none());
    }
}
