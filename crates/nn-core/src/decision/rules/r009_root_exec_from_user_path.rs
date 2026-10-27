//! R009 — Root execution from a user-writable path.

use nn_model::{Event, ResponseAction, Severity, Verdict};

use crate::decision::attack::{AttackRef, Tactic};
use crate::decision::{rules::build_verdict, Rule};
use crate::posture::host::PostureHost;
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
///
/// Lab PR 166: killed with its tree. The executable is the payload itself;
/// a root dropper from `/tmp` that forked at once kept its child running
/// the same image under init (this rule runs ahead of R001, so the lab saw
/// an R009 kill and no R001 verdict). The record of a sanctioned lineage
/// is unchanged.
///
/// Lab PR 175: the package transaction is the FIM rules' and NN-L-NET-008's
/// ([`AuthSessionTracker::in_package_transaction`]: a package manager
/// proper executed by root whose run covers the exec). It was any `mandb`
/// or package manager in the lineage, whoever ran it and however long
/// before — a record that also kept R001, which runs after this rule, from
/// killing the exec.
#[derive(Default)]
pub struct R009RootExecFromUserPath<H: PostureHost> {
    lineage: Option<AuthSessionTracker<H>>,
}

impl<H: PostureHost> R009RootExecFromUserPath<H> {
    pub fn new(lineage: AuthSessionTracker<H>) -> Self {
        Self {
            lineage: Some(lineage),
        }
    }

    fn sanctioned(&self, pid: u32, exec_ns: u64) -> bool {
        self.lineage
            .as_ref()
            .is_some_and(|l| l.is_interactive_admin(pid) || l.in_package_transaction(pid, exec_ns))
    }
}

impl<H: PostureHost> Rule for R009RootExecFromUserPath<H> {
    fn id(&self) -> &'static str {
        "R009_RootExecFromUserPath"
    }
    fn name(&self) -> &'static str {
        "Root exec from user-writable path"
    }
    fn category(&self) -> &'static str {
        "privilege_escalation"
    }
    fn attack(&self) -> &'static [AttackRef] {
        const ATTACK: &[AttackRef] = &[
            AttackRef::new(Tactic::PrivilegeEscalation, "T1548"),
            AttackRef::new(Tactic::PrivilegeEscalation, "T1068"),
        ];
        ATTACK
    }

    fn evaluate(&self, event: &Event) -> Option<Verdict> {
        let Event::ProcessSpawn {
            pid,
            uid,
            filename,
            exe,
            timestamp_ns,
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
        if self.sanctioned(*pid, *timestamp_ns) {
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
            ResponseAction::KillProcessTree,
            Severity::High,
            "Root execution from user-writable path — privilege escalation indicator",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    // R08b (lab PR 251): on the portable test host.
    use crate::posture::host::testing::TestHost as H;
    type AuthSessionTracker = crate::posture::lineage::AuthSessionTracker<H>;
    type R009RootExecFromUserPath = super::R009RootExecFromUserPath<H>;
    use crate::decision::rules::testutil::spawn_as;

    #[test]
    fn fires_on_root_in_user_path() {
        for path in ["/home/alice/payload", "/tmp/payload", "/var/tmp/payload"] {
            let v = R009RootExecFromUserPath::default()
                .evaluate(&spawn_as(0, "payload", path))
                .unwrap_or_else(|| panic!("should fire on {path}"));
            assert_eq!(v.action, ResponseAction::KillProcessTree);
            assert_eq!(v.severity, Severity::High);
        }
    }

    /// Lab PR 166: a root dropper's forked children die with it.
    #[test]
    fn r009_kills_the_process_tree() {
        let v = R009RootExecFromUserPath::default()
            .evaluate(&spawn_as(0, "dropper", "/tmp/dropper"))
            .expect("fires");
        assert_eq!(v.rule_id, "R009_RootExecFromUserPath");
        assert_eq!(v.action, ResponseAction::KillProcessTree);
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
        assert_eq!(v.action, ResponseAction::KillProcessTree);
    }

    /// Lab PR 175: the package transaction is root's package manager while
    /// its run covers the exec. Any `mandb` or package manager in the
    /// lineage was sanctioned — and the record kept R001, which runs after
    /// this rule, from killing the exec.
    #[test]
    fn root_exec_is_sanctioned_only_within_a_root_package_transaction() {
        const S: u64 = 1_000_000_000;
        let tmp = tempfile::TempDir::new().unwrap();
        let lineage = AuthSessionTracker::new(tmp.path());
        // root's mandb (710, running; LD_PRELOAD) → /tmp/payload (711)
        lineage.ingest_exec(710, 1, "/usr/bin/mandb", &[], S, S, 0);
        lineage.ingest_exec(711, 710, "/tmp/payload", &[], 2 * S, 2 * S, 0);
        // root's dpkg (720, running) → a maintainer script's helper (721)
        lineage.ingest_exec(720, 1, "/usr/bin/dpkg", &[], S, S, 0);
        lineage.ingest_exec(721, 720, "/tmp/postinst-helper", &[], 2 * S, 2 * S, 0);
        // root's dpkg (730), gone since its exec at 1 s → a leftover (731)
        // whose child (732) runs a payload from /tmp at 200 s
        lineage.ingest_exec(730, 1, "/usr/bin/dpkg", &[], S, S, 0);
        lineage.ingest_exec(731, 730, "/usr/bin/sh", &[], 2 * S, 2 * S, 0);
        lineage.ingest_exec(732, 731, "/tmp/payload", &[], 200 * S, 200 * S, 0);
        for pid in ["710", "720"] {
            std::fs::create_dir_all(tmp.path().join(pid)).unwrap();
        }
        let rule = R009RootExecFromUserPath::new(lineage);
        let exec = |pid: u32, ppid: u32, path: &str, ts: u64| {
            let mut e = spawn_as(0, "x", path);
            if let Event::ProcessSpawn {
                pid: p,
                ppid: pp,
                timestamp_ns,
                ..
            } = &mut e
            {
                (*p, *pp, *timestamp_ns) = (pid, ppid, ts);
            }
            rule.evaluate(&e).expect("a root exec from /tmp").action
        };
        assert_eq!(
            exec(711, 710, "/tmp/payload", 2 * S),
            ResponseAction::KillProcessTree,
            "under mandb"
        );
        assert_eq!(
            exec(721, 720, "/tmp/postinst-helper", 2 * S),
            ResponseAction::Log,
            "a maintainer script's helper"
        );
        assert_eq!(
            exec(732, 731, "/tmp/payload", 200 * S),
            ResponseAction::KillProcessTree,
            "after the transaction"
        );
    }
}
