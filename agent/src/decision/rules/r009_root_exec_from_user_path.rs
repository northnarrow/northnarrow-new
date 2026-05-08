//! R009 — Root execution from a user-writable path.

use common::{Event, ResponseAction, Severity, Verdict};

use crate::decision::{rules::build_verdict, Rule};

/// Path prefixes that are user-writable on a typical Linux system.
const USER_WRITABLE_PREFIXES: &[&str] = &["/home/", "/tmp/", "/var/tmp/"];

pub struct R009RootExecFromUserPath;

impl Rule for R009RootExecFromUserPath {
    fn id(&self) -> &'static str {
        "R009_RootExecFromUserPath"
    }
    fn name(&self) -> &'static str {
        "Root exec from user-writable path"
    }
    fn category(&self) -> &'static str {
        "privilege_escalation"
    }

    fn evaluate(&self, event: &Event) -> Option<Verdict> {
        let Event::ProcessSpawn { uid, filename, .. } = event else {
            return None;
        };
        if *uid != 0 {
            return None;
        }
        if !USER_WRITABLE_PREFIXES
            .iter()
            .any(|p| filename.starts_with(p))
        {
            return None;
        }
        Some(build_verdict(
            self,
            event,
            ResponseAction::KillProcess,
            Severity::High,
            "Root execution from user-writable path — privilege escalation indicator",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decision::rules::testutil::spawn_as;

    #[test]
    fn fires_on_root_in_user_path() {
        for path in ["/home/alice/payload", "/tmp/payload", "/var/tmp/payload"] {
            let v = R009RootExecFromUserPath
                .evaluate(&spawn_as(0, "payload", path))
                .unwrap_or_else(|| panic!("should fire on {path}"));
            assert_eq!(v.action, ResponseAction::KillProcess);
            assert_eq!(v.severity, Severity::High);
        }
    }

    #[test]
    fn ignores_non_root_or_safe_path() {
        // Non-root exec from /tmp is R001's territory, not R009's.
        assert!(R009RootExecFromUserPath
            .evaluate(&spawn_as(1000, "payload", "/tmp/payload"))
            .is_none());
        // Root exec from /usr/bin is fine.
        assert!(R009RootExecFromUserPath
            .evaluate(&spawn_as(0, "ls", "/usr/bin/ls"))
            .is_none());
    }

    #[test]
    fn does_not_match_lookalike_prefixes() {
        // /var/log is not user-writable in the spec.
        assert!(R009RootExecFromUserPath
            .evaluate(&spawn_as(0, "x", "/var/log/syslog"))
            .is_none());
        // "/homefoo/..." is not /home/.
        assert!(R009RootExecFromUserPath
            .evaluate(&spawn_as(0, "x", "/homefoo/x"))
            .is_none());
    }
}
