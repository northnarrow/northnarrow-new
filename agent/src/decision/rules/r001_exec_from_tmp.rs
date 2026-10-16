//! R001 — Process executed from `/tmp/`.
//!
//! Lab PR 166: the executable is the payload itself, so the response is
//! the tree. A dropper that forks before the verdict lands left its child
//! running the same image under init, and a child that never execs draws
//! no verdict of its own. The tree kill reaps descendants only.

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
        let Event::ProcessSpawn { filename, exe, .. } = event else {
            return None;
        };
        // Review 61: the file the kernel executed, not the caller's string.
        let filename = exe.path_or(filename);
        if !filename.starts_with("/tmp/") {
            return None;
        }
        if TMP_WHITELIST.contains(&filename) {
            return None;
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
            let v = R001ExecFromTmp.evaluate(&event).expect(caller);
            assert_eq!(v.event_filename, "/tmp/payload", "{caller}");
        }
        // and a `/tmp/…` string that resolves elsewhere does not fire
        let event = spawn_exe("ls", "/tmp/ls-link", "/usr/bin/ls", 0);
        assert!(R001ExecFromTmp.evaluate(&event).is_none());
    }

    #[test]
    fn fires_on_exec_from_tmp() {
        let event = spawn("payload", "/tmp/payload");
        let v = R001ExecFromTmp.evaluate(&event).expect("should fire");
        assert_eq!(v.rule_id, "R001_ExecFromTmp");
        assert_eq!(v.action, ResponseAction::KillProcessTree);
        assert_eq!(v.severity, Severity::Medium);
        assert_eq!(v.event_filename, "/tmp/payload");
    }

    /// Lab PR 166: the payload's forked children die with it.
    #[test]
    fn r001_kills_the_process_tree() {
        for uid in [0, 998, 1000] {
            let v = R001ExecFromTmp
                .evaluate(&spawn_as(uid, "payload", "/tmp/payload"))
                .expect("fires");
            assert_eq!(v.action, ResponseAction::KillProcessTree, "uid {uid}");
        }
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
