//! R009 — Root execution from a user-writable path.

use common::{Event, ResponseAction, Severity, Verdict};

use crate::decision::{rules::build_verdict, Rule};
use crate::posture::AuthSessionTracker;

/// Path prefixes that are user-writable on a typical Linux system.
const USER_WRITABLE_PREFIXES: &[&str] = &["/home/", "/tmp/", "/var/tmp/"];

/// External audit PROC-007: R009 killed every root exec from a home or a
/// temporary directory — `sudo ~/deploy.sh`, a vendor installer unpacked
/// in /tmp, an RPM scriptlet in /var/tmp; it once killed `nn-admin`
/// itself. Two lineages are sanctioned and recorded instead, on the
/// boundaries review 52 drew for the FIM rules: an administrator's sudo/su
/// session at a terminal, and a package manager's transaction. A process
/// that became root any other way — the escalation R009 exists for — has
/// neither, and is still killed.
#[derive(Default)]
pub struct R009RootExecFromUserPath {
    lineage: Option<AuthSessionTracker>,
}

impl R009RootExecFromUserPath {
    pub fn new(lineage: AuthSessionTracker) -> Self {
        Self {
            lineage: Some(lineage),
        }
    }

    fn sanctioned(&self, pid: u32) -> bool {
        self.lineage
            .as_ref()
            .is_some_and(|l| l.is_interactive_admin(pid) || l.is_system_daemon_mediated(pid))
    }
}

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
        let Event::ProcessSpawn {
            pid,
            uid,
            filename,
            exe,
            ..
        } = event
        else {
            return None;
        };
        // Review 61: the file the kernel executed, not the caller's string.
        let filename = exe.path_or(filename);
        if *uid != 0 {
            return None;
        }
        if !USER_WRITABLE_PREFIXES
            .iter()
            .any(|p| filename.starts_with(p))
        {
            return None;
        }
        if self.sanctioned(*pid) {
            return Some(build_verdict(
                self,
                event,
                ResponseAction::Log,
                Severity::Low,
                "Root execution from user-writable path in an administrator's sudo/su session \
                 or a package transaction — recorded",
            ));
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
            let v = R009RootExecFromUserPath::default()
                .evaluate(&spawn_as(0, "payload", path))
                .unwrap_or_else(|| panic!("should fire on {path}"));
            assert_eq!(v.action, ResponseAction::KillProcess);
            assert_eq!(v.severity, Severity::High);
        }
    }

    #[test]
    fn ignores_non_root_or_safe_path() {
        // Non-root exec from /tmp is R001's territory, not R009's.
        assert!(R009RootExecFromUserPath::default()
            .evaluate(&spawn_as(1000, "payload", "/tmp/payload"))
            .is_none());
        // Root exec from /usr/bin is fine.
        assert!(R009RootExecFromUserPath::default()
            .evaluate(&spawn_as(0, "ls", "/usr/bin/ls"))
            .is_none());
    }

    #[test]
    fn does_not_match_lookalike_prefixes() {
        // /var/log is not user-writable in the spec.
        assert!(R009RootExecFromUserPath::default()
            .evaluate(&spawn_as(0, "x", "/var/log/syslog"))
            .is_none());
        // "/homefoo/..." is not /home/.
        assert!(R009RootExecFromUserPath::default()
            .evaluate(&spawn_as(0, "x", "/homefoo/x"))
            .is_none());
    }

    /// External audit PROC-007: an administrator's sudo session at a
    /// terminal runs a script from their home — recorded, not killed; the
    /// same exec reached without sudo is still killed.
    #[test]
    fn sudo_session_at_a_terminal_is_recorded_not_killed() {
        let tmp = tempfile::TempDir::new().unwrap();
        for (pid, ppid) in [(700u32, 1u32), (710, 700), (720, 710), (800, 700)] {
            let d = tmp.path().join(pid.to_string());
            std::fs::create_dir_all(&d).unwrap();
            std::fs::write(d.join("loginuid"), "1000").unwrap();
            std::fs::write(
                d.join("stat"),
                format!("{pid} (x) S {ppid} {pid} {pid} 34816 -1 0\n"),
            )
            .unwrap();
        }
        let lineage = AuthSessionTracker::new(tmp.path());
        lineage.ingest_spawn(700, 1, "/usr/bin/bash", 1);
        lineage.ingest_spawn(710, 700, "/usr/bin/sudo", 2);
        lineage.ingest_spawn(720, 710, "/home/alice/deploy.sh", 3);
        lineage.ingest_spawn(800, 700, "/home/alice/deploy.sh", 4);
        let rule = R009RootExecFromUserPath::new(lineage);

        let mut sudo_run = spawn_as(0, "deploy.sh", "/home/alice/deploy.sh");
        let mut other = sudo_run.clone();
        if let Event::ProcessSpawn { pid, ppid, .. } = &mut sudo_run {
            (*pid, *ppid) = (720, 710);
        }
        if let Event::ProcessSpawn { pid, ppid, .. } = &mut other {
            (*pid, *ppid) = (800, 700);
        }
        let v = rule.evaluate(&sudo_run).expect("recorded");
        assert_eq!(v.action, ResponseAction::Log);
        let v = rule.evaluate(&other).expect("fires");
        assert_eq!(v.action, ResponseAction::KillProcess);
    }
}
