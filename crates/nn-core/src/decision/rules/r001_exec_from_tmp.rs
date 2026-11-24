//! R001 — Process executed from `/tmp/`.
//!
//! Lab PR 166: the executable is the payload itself, so the response is
//! the tree. A dropper that forks before the verdict lands left its child
//! running the same image under init, and a child that never execs draws
//! no verdict of its own. The tree kill reaps descendants only.

use nn_model::{Event, ResponseAction, Severity, Verdict};

use crate::decision::attack::{AttackRef, Tactic};
use crate::decision::{Rule, rules::build_verdict};

/// Filenames inside `/tmp/` that are NOT considered suspicious.
/// Empty for now; the slot exists so legit tooling (build systems
/// staging compiled artifacts, etc.) can be carved out without
/// touching the rule body.
const TMP_WHITELIST: &[&str] = &[];

#[derive(Debug, Default)]
pub struct R001ExecFromTmp {
    /// Lot 369: the packaged `go`'s own build output, recorded Low.
    go: super::GoBuilds,
    /// The review of #578 (P3): the system's `ldd` running the loader.
    listing: super::LoaderListing,
}

impl R001ExecFromTmp {
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

impl R001ExecFromTmp {
    /// Lot 370 (05-3.3): an exec of the dynamic loader whose program (or a
    /// library it preloads) is in `/tmp/` — or one it runs by a name the
    /// text cannot place. The review of #578: one it only lists or checks
    /// (`--list`, `--verify`, `ldd`) is recorded, never killed — Low when the
    /// agent knows the loader runs none of its code, Medium when it cannot
    /// tell (P3; the re-check, R1-1: glibc's list modes run the libraries
    /// the program names for auditing); a name through a link of `/proc` is
    /// placed by the kernel's identity of the file the loader maps, else not
    /// placed (N1) — a descriptor's link R004 judges; any other name is also
    /// judged where the pump found the file it names (R1-2: a symbolic link
    /// on the way, `/usr/tmp` → `/var/tmp`).
    fn through_the_loader(&self, event: &Event) -> Option<Verdict> {
        use crate::decision::rules::LoaderUse;
        let listing = self.listing.lists(event);
        let code = crate::decision::rules::loader_code(event, listing);
        let staged = crate::decision::rules::loader_staged(event, "/tmp/", listing)
            .filter(|(p, _)| !TMP_WHITELIST.contains(&p.as_str()));
        if let Some((p, LoaderUse::Runs)) = &staged {
            return Some(build_verdict(
                self,
                event,
                ResponseAction::KillProcessTree,
                Severity::Medium,
                &format!(
                    "Process executed from /tmp/ through the dynamic loader ({p}) — common \
                     malware staging location"
                ),
            ));
        }
        // a descriptor's link (or a memfd's name) is R004's, placed or not
        let unplaced = code
            .iter()
            .filter(|(p, _)| {
                !crate::posture::proc_link::reopens_a_descriptor(p)
                    && !p.starts_with("/memfd:")
                    && crate::decision::rules::placed(event, p).is_none()
            })
            // the first of the highest rank
            .fold(None, |best: Option<&(&str, LoaderUse)>, c| match best {
                Some(b) if b.1.rank() >= c.1.rank() => Some(b),
                _ => Some(c),
            });
        // the re-check of #578 (R1-1): a staged program only listed is
        // recorded as such — unless a file the agent cannot place may run
        // more (`--audit=./x --list /tmp/x`: the auditor may be the program)
        if let Some((p, use_)) = staged {
            if unplaced.is_none_or(|u| u.1.rank() <= use_.rank()) {
                return crate::decision::rules::loader_listed_record(
                    self, event, "/tmp/", &p, use_,
                );
            }
        }
        let (unplaced, use_) = unplaced?;
        let (severity, how) = match use_ {
            LoaderUse::Runs => (Severity::Medium, "run"),
            LoaderUse::MayRun(_) => (
                Severity::Medium,
                "listed or checked (it may still run code)",
            ),
            LoaderUse::Lists(_) => (Severity::Low, "listed (not run)"),
        };
        Some(build_verdict(
            self,
            event,
            ResponseAction::Log,
            severity,
            &format!(
                "A program {how} through the dynamic loader by a name the agent cannot place \
                 ({unplaced}: relative to a directory the event does not carry, climbing, or \
                 through a link of /proc the agent could not follow to a file the process maps) \
                 — a staged program is run this way; recorded, not killed"
            ),
        ))
    }
}

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
    fn attack(&self) -> &'static [AttackRef] {
        const ATTACK: &[AttackRef] = &[AttackRef::new(Tactic::Execution, "T1059")];
        ATTACK
    }

    fn evaluate(&self, event: &Event) -> Option<Verdict> {
        let Event::ProcessSpawn { filename, exe, .. } = event else {
            return None;
        };
        // Review 61: the file the kernel executed, not the caller's string.
        // Lot 355: a file of a user's program image (an AppImage's) is the
        // image's, not staged in its mount point's directory.
        let staged = crate::decision::rules::staging_judged_path(exe, filename)
            .filter(|f| f.starts_with("/tmp/") && !TMP_WHITELIST.contains(f));
        let Some(filename) = staged else {
            // Lot 370 (05-3.3): a program the dynamic loader runs (its
            // operand, a `--preload`) is judged as if the kernel had executed
            // it; one the text cannot place (a relative name: the caller's
            // directory is not known) is recorded, not killed. After the
            // image: a staged loader is killed as one.
            return self.through_the_loader(event);
        };
        // lot 369: `go test`'s binary and `go run`'s program, by identity
        if self.go.runs(event, filename) {
            return Some(super::go_build_record(self, event, "/tmp/"));
        }
        Some(build_verdict(
            self,
            event,
            ResponseAction::KillProcessTree,
            Severity::Medium,
            "Process executed from /tmp/ — common malware staging location",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decision::rules::testutil::{spawn, spawn_as};

    /// Review 61: `cd /tmp && ./payload`, a symlink or `..` — the rule
    /// matches the file the kernel executed.
    #[test]
    fn fires_on_the_executed_file_not_the_callers_string() {
        use crate::decision::rules::testutil::spawn_exe;
        for caller in [
            "./payload",
            "/usr/local/bin/notes",
            "/usr/bin/../../tmp/payload",
        ] {
            let event = spawn_exe("payload", caller, "/tmp/payload", 0);
            let v = R001ExecFromTmp::default().evaluate(&event).expect(caller);
            assert_eq!(v.event_filename, "/tmp/payload", "{caller}");
        }
        // and a `/tmp/…` string that resolves elsewhere does not fire
        let event = spawn_exe("ls", "/tmp/ls-link", "/usr/bin/ls", 0);
        assert!(R001ExecFromTmp::default().evaluate(&event).is_none());
    }

    #[test]
    fn fires_on_exec_from_tmp() {
        let event = spawn("payload", "/tmp/payload");
        let v = R001ExecFromTmp::default()
            .evaluate(&event)
            .expect("should fire");
        assert_eq!(v.rule_id, "R001_ExecFromTmp");
        assert_eq!(v.action, ResponseAction::KillProcessTree);
        assert_eq!(v.severity, Severity::Medium);
        assert_eq!(v.event_filename, "/tmp/payload");
    }

    /// Lab PR 166: the payload's forked children die with it.
    #[test]
    fn r001_kills_the_process_tree() {
        for (case, uid) in [0, 998, 1000].into_iter().enumerate() {
            let v = R001ExecFromTmp::default()
                .evaluate(&spawn_as(uid, "payload", "/tmp/payload"))
                .expect("fires");
            assert_eq!(v.action, ResponseAction::KillProcessTree, "case {case}");
        }
    }

    /// Lot 355: a file of a user's program image (an AppImage's program,
    /// served at its runtime's `/tmp/.mount_*`, `USER_IMAGE` by the exec
    /// pump) is the image's: R001, R002 and R003 judge it as the image, not
    /// as staged in the mount point's directory. Unmarked, the same path
    /// fires.
    #[test]
    fn a_user_image_s_program_is_not_staged() {
        use crate::decision::rules::testutil::spawn_exe;
        use crate::decision::rules::{R002ExecFromDevShm, R003ExecFromVarTmp};
        use common::wire::exe::exe_flags::USER_IMAGE;
        let (r1, r3) = (R001ExecFromTmp::default(), R003ExecFromVarTmp::default());
        let rules: [&dyn Rule; 3] = [&r1, &R002ExecFromDevShm::default(), &r3];
        for (rule, dir) in rules.iter().zip(["/tmp", "/dev/shm", "/var/tmp"]) {
            let app = format!("{dir}/.mount_k355ab/AppRun");
            let marked = spawn_exe("AppRun", &app, &app, USER_IMAGE);
            assert!(rule.evaluate(&marked).is_none(), "{dir}");
            let staged = spawn_exe("AppRun", &app, &app, 0);
            assert!(rule.evaluate(&staged).is_some(), "{dir}");
        }
    }

    /// Lot 369: R001's own record of an exec the go identity vouches for
    /// (the packaged `go`'s build output, linked and run by it, for a
    /// person) is Low, not killed — but never for a file unlinked or a memfd
    /// when the kernel ran it, nor (the review of #576, F1) for a file the
    /// kernel did not run by its path (no `KNOWN` canonical path: the
    /// caller's string alone), and never without the identity. The
    /// predicate is asked with the exec's own pid, uid and path.
    #[test]
    fn the_go_build_record_needs_the_identity_and_a_linked_file() {
        use crate::decision::rules::testutil::spawn_exe;
        use common::wire::exe::exe_flags::{DELETED, KNOWN, MEMFD};
        let built = "/tmp/go-build1/b001/calc.test";
        let go = R001ExecFromTmp::default().with_go_builds(super::super::GoBuilds::of_fn(
            |pid, uid, _, image| (pid, uid) == (1234, 1000) && image.contains("go-build"),
        ));
        let v = go
            .evaluate(&spawn_exe("calc.test", built, built, 0))
            .unwrap();
        assert_eq!((v.severity, v.action), (Severity::Low, ResponseAction::Log));
        for flag in [DELETED, MEMFD] {
            let v = go
                .evaluate(&spawn_exe("calc.test", built, built, flag))
                .unwrap();
            assert_eq!(v.action, ResponseAction::KillProcessTree, "{flag:#x}");
            assert_eq!(v.severity, Severity::Medium);
        }
        // the caller's string alone, or a canonical path not yet placed
        let mut unknown = spawn_exe("calc.test", built, built, 0);
        if let Event::ProcessSpawn { exe, .. } = &mut unknown {
            exe.flags &= !KNOWN;
        }
        let mut unplaced = spawn_exe("calc.test", built, "b001/calc.test", 0);
        if let Event::ProcessSpawn { exe, .. } = &mut unplaced {
            exe.root = (9, 9);
        }
        for e in [unknown, unplaced] {
            let v = go.evaluate(&e).unwrap();
            assert_eq!(v.action, ResponseAction::KillProcessTree, "{e:?}");
        }
        let v = R001ExecFromTmp::default()
            .evaluate(&spawn_exe("calc.test", built, built, 0))
            .unwrap();
        assert_eq!(v.action, ResponseAction::KillProcessTree, "no identity");
    }

    #[test]
    fn ignores_legitimate_paths() {
        let event = spawn("ls", "/usr/bin/ls");
        assert!(R001ExecFromTmp::default().evaluate(&event).is_none());
    }

    #[test]
    fn does_not_match_path_named_like_tmp_elsewhere() {
        // `/var/tmp/...` is R003's job, not R001's. `/tmpfoo/...`
        // (no trailing slash) is unrelated.
        assert!(
            R001ExecFromTmp::default()
                .evaluate(&spawn("x", "/var/tmp/x"))
                .is_none()
        );
        assert!(
            R001ExecFromTmp::default()
                .evaluate(&spawn("tmpfoo", "/tmpfoo/payload"))
                .is_none()
        );
    }
}
