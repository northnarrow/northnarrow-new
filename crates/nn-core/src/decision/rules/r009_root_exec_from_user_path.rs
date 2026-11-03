//! R009 — Root execution from a user-writable path.

use std::sync::Arc;

use nn_model::{Event, ResponseAction, Severity, Verdict};

use crate::anti_tamper::trusted_installer::WindowGrant;
use crate::decision::attack::{AttackRef, Tactic};
use crate::decision::host::DecisionHost;
use crate::decision::{rules::build_verdict, Rule};
use crate::posture::host::PostureAgent;
use crate::posture::lineage::AsOf;
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
///
/// Lot 278: a third lineage is recorded at Low — the process tree of the
/// installer a trusted-installer window was granted to
/// ([`WindowGrant::grantee`]: the process that ran `nn-admin
/// trusted-installer-grant`, by its pid and its start), for what it executes
/// after the grant while the window is open: `install.sh --upgrade`,
/// `uninstall.sh` and their children, run from a checkout in a home or an
/// unpacked tree in `/tmp` by automation without a terminal (Ansible
/// `become`, cloud-init, CI). The tree is found by lineage only, never by a
/// name or a path. The script's own exec comes before its window: outside
/// COMBAT it is recorded, not killed — the engine holds R009's kill below
/// COMBAT ([`crate::decision::posture_floor`]).
pub struct R009RootExecFromUserPath<H: DecisionHost> {
    lineage: Option<AuthSessionTracker<H>>,
    window: Option<Arc<<H as PostureAgent>::InstallerWindow>>,
}

impl<H: DecisionHost> Default for R009RootExecFromUserPath<H> {
    fn default() -> Self {
        Self {
            lineage: None,
            window: None,
        }
    }
}

impl<H: DecisionHost> R009RootExecFromUserPath<H> {
    pub fn new(lineage: AuthSessionTracker<H>) -> Self {
        Self {
            lineage: Some(lineage),
            window: None,
        }
    }

    /// Lot 278: the trusted-installer window whose installer's tree is
    /// recorded at Low.
    pub fn with_installer_window(
        mut self,
        window: Option<Arc<<H as PostureAgent>::InstallerWindow>>,
    ) -> Self {
        self.window = window;
        self
    }

    fn sanctioned(&self, pid: u32, exec_ns: u64) -> bool {
        self.lineage.as_ref().is_some_and(|l| {
            // R-F: as of the exec
            let as_of = AsOf::judged(exec_ns);
            l.is_interactive_admin(pid, as_of) || l.in_package_transaction(pid, as_of)
        })
    }

    /// Lot 278: the open window whose installer `pid` is, or descends
    /// from, for an exec at `exec_ns` after the grant.
    fn installer_window(&self, pid: u32, exec_ns: u64) -> Option<WindowGrant> {
        let lineage = self.lineage.as_ref()?;
        let grant = H::installer_grant(self.window.as_deref()?)?;
        let who = grant.grantee?;
        if exec_ns < who.granted_ns {
            return None;
        }
        lineage
            .descends_from(pid, AsOf::judged(exec_ns), who.pid, who.start_ticks)
            .then_some(grant)
    }
}

impl<H: DecisionHost> Rule for R009RootExecFromUserPath<H> {
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
        if let Some(g) = self.installer_window(*pid, *timestamp_ns) {
            let who = g.grantee.map_or(0, |w| w.pid);
            return Some(build_verdict(
                self,
                event,
                ResponseAction::Log,
                Severity::Low,
                &format!(
                    "Root execution from user-writable path by the process tree of the \
                     installer the trusted-installer window was granted to (pid {who}, key \
                     {}, until {}) — recorded",
                    g.key_id, g.expires_at
                ),
            ));
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

    /// Lot 278: the installer a trusted-installer window was granted to
    /// (pid 900, started at tick 5000) runs `install.sh --upgrade` from a
    /// checkout with no terminal (Ansible `become`): what its own tree
    /// executes from the checkout after the grant is recorded at Low, by
    /// lineage — not what it executed before the grant, not a process
    /// outside its tree (a sibling, or a later process given its pid), not
    /// after the window closed, and not with no installer named.
    #[test]
    fn the_installer_s_own_tree_is_recorded_inside_its_window() {
        use crate::anti_tamper::trusted_installer::{WindowGrant, WindowGrantee};
        use crate::posture::host::testing::TestWindow;
        use std::sync::Arc;
        const S: u64 = 1_000_000_000;
        let tmp = tempfile::TempDir::new().unwrap();
        let lineage = AuthSessionTracker::new(tmp.path());
        // ansible's shell (root, no terminal) runs the installer (900)
        lineage.ingest_exec(800, 1, "/usr/bin/python3", &[], S, S, 0);
        lineage.ingest_exec(
            900,
            800,
            "/home/dev/nn/deploy/install.sh",
            &[],
            50 * S,
            50 * S,
            0,
        );
        lineage.ingest_exec(900, 800, "/usr/bin/bash", &[], 50 * S + 1, 50 * S, 0);
        // after the grant (at 51 s) the installer runs the new agent's --version
        lineage.ingest_exec(
            901,
            900,
            "/home/dev/nn/target/release/northnarrow-agent",
            &[],
            52 * S,
            52 * S,
            0,
        );
        // a sibling of the installer, started by ansible: not its tree
        lineage.ingest_exec(
            902,
            800,
            "/home/dev/nn/target/release/northnarrow-agent",
            &[],
            52 * S,
            52 * S,
            0,
        );
        let grant = |open: bool, grantee: Option<WindowGrantee>| {
            Arc::new(TestWindow {
                open,
                grant: Some(WindowGrant {
                    key_id: "c2e8f3da".into(),
                    expires_at: "2026-11-03T21:00:00Z".into(),
                    grantee,
                }),
            })
        };
        let installer = WindowGrantee {
            pid: 900,
            start_ticks: 5_000,
            granted_ns: 51 * S,
        };
        let exec = |rule: &R009RootExecFromUserPath, pid: u32, ppid: u32, path: &str, ts: u64| {
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
            rule.evaluate(&e).expect("a root exec from a home")
        };
        let rule = R009RootExecFromUserPath::new(lineage.clone())
            .with_installer_window(Some(grant(true, Some(installer))));
        let agent = "/home/dev/nn/target/release/northnarrow-agent";
        let v = exec(&rule, 901, 900, agent, 52 * S);
        assert_eq!((v.action, v.severity), (ResponseAction::Log, Severity::Low));
        assert!(
            v.reasoning.contains("granted to (pid 900, key c2e8f3da"),
            "{}",
            v.reasoning
        );
        // the installer's own exec came before its grant
        let v = exec(&rule, 900, 800, "/home/dev/nn/deploy/install.sh", 50 * S);
        assert_eq!(v.action, ResponseAction::KillProcessTree);
        // a sibling is not the installer's tree
        assert_eq!(
            exec(&rule, 902, 800, agent, 52 * S).action,
            ResponseAction::KillProcessTree
        );
        // pid 900 is another process (another start): not the grantee
        let other =
            R009RootExecFromUserPath::new(lineage.clone()).with_installer_window(Some(grant(
                true,
                Some(WindowGrantee {
                    start_ticks: 7_000,
                    ..installer
                }),
            )));
        assert_eq!(
            exec(&other, 901, 900, agent, 52 * S).action,
            ResponseAction::KillProcessTree
        );
        // the window closed, or it names no installer
        let closed = R009RootExecFromUserPath::new(lineage.clone())
            .with_installer_window(Some(grant(false, Some(installer))));
        assert_eq!(
            exec(&closed, 901, 900, agent, 52 * S).action,
            ResponseAction::KillProcessTree
        );
        let nobody =
            R009RootExecFromUserPath::new(lineage).with_installer_window(Some(grant(true, None)));
        assert_eq!(
            exec(&nobody, 901, 900, agent, 52 * S).action,
            ResponseAction::KillProcessTree
        );
    }
}
