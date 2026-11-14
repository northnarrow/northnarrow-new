//! Lot 350 (F2-3): cloud-init's own netcat, on its own unix socket.
//!
//! From cloud-init 24 the units of its boot phases ask each phase through a
//! unix socket of its own, with the distribution's netcat:
//!
//! ```text
//! ExecStart=sh -c 'echo "start" | nc -U /run/cloud-init/share/final.sock | sh'
//! ExecStart=sh -c 'echo "start" | nc -Uu -W1 /run/cloud-init/share/final.sock -s /run/cloud-init/share/final-return.sock | sh'
//! ```
//!
//! (`cloud-init-local`, `cloud-init-network`, `cloud-config` and
//! `cloud-final`; the first line cloud-init 24's, Ubuntu 26.04's, the second
//! cloud-init 25's, Debian 13's: a unix datagram socket). Every boot of a cloud
//! image ran a netcat as root: R005 High and the posture's ExploitAttempt
//! (ENGAGED) on every boot of a homelab's cloud image.
//!
//! [`cloud_init_socket_client`] recognises that one exec, by identity only —
//! each fact from the kernel's records or the process's own `/proc` entry,
//! none from a name the process chose:
//!
//! - the image: the distribution's netcat at its packaged path
//!   ([`NETCAT_IMAGES`]), the very file there (its device and inode, the LSM
//!   program's identity) in a directory only root can write (`ROOT_DIR`), as
//!   root, in PID 1's view of the files;
//! - a unix socket only: exactly one of those argvs for a phase's socket
//!   (and its return socket), the whole argv, not cut — no host, no port,
//!   no other option or socket — and no
//!   inet socket on its standard streams or its parent's (the kernel's read
//!   at the exec; an unread one is not "none");
//! - the unit: the process, by its start, runs in the cgroup of the
//!   cloud-init unit that asks that phase ([`CLOUD_INIT_PHASES`]) — a cgroup
//!   only root places a process in;
//! - the parent: the unit's own `ExecStart=` shell, forked by PID 1 (the
//!   kernel's fork record, through systemd's executor), root's, the packaged
//!   shell's file, with exactly the unit's line — and the netcat its first
//!   exec since that shell forked it.
//!
//! Anything else is judged as before: a netcat with a host or a port, `-e`
//! or `-c`, another socket, run from a session, a service of another unit,
//! a copy of the binary, a later process at the pid, a parent that is not
//! the unit's shell.

use nn_model::Event;

use crate::posture::host::PostureHost;
use crate::posture::lineage::{AsOf, AuthSessionTracker};

/// The cloud-init units (24 and later) and the phase whose socket each
/// one's `ExecStart=` asks (`cloud-init.service` is the network phase's
/// name before 24.3).
pub const CLOUD_INIT_PHASES: &[(&str, &str)] = &[
    ("cloud-config.service", "config"),
    ("cloud-final.service", "final"),
    ("cloud-init-local.service", "local"),
    ("cloud-init-network.service", "network"),
    ("cloud-init.service", "network"),
];

/// Where cloud-init's phase sockets are.
pub const CLOUD_INIT_SOCKET_DIR: &str = "/run/cloud-init/share/";

/// The packaged netcat cloud-init depends on (Debian, Ubuntu:
/// `netcat-openbsd`, `nc` through the alternatives), as the kernel resolves
/// the executed file.
pub const NETCAT_IMAGES: &[&str] = &["/bin/nc.openbsd", "/usr/bin/nc.openbsd"];

/// The packaged `/bin/sh` that runs a unit's `sh -c` line, as the kernel
/// resolves it (dash on Debian and Ubuntu).
pub const UNIT_SHELLS: &[&str] = &["/bin/dash", "/usr/bin/dash"];

/// The phases whose sockets cloud-init's units ask.
const PHASES: &[&str] = &["config", "final", "local", "network"];

/// The arguments after `nc` that a cloud-init phase unit's `ExecStart=` line
/// gives netcat, for the phase's socket `socket` and its return socket
/// `ret` — exactly, every word (no option is read):
/// - cloud-init 24 (Ubuntu 26.04): `nc -U <socket>`;
/// - cloud-init 25 (Debian 13): `nc -Uu -W1 <socket> -s <return socket>` — a
///   unix datagram socket (`-u` with `-U`), its local end `-s` the phase's
///   return socket, one packet back (`-W1`).
fn phase_argvs(socket: &str, ret: &str) -> [Vec<String>; 2] {
    let words = |w: &[&str]| w.iter().map(|w| w.to_string()).collect::<Vec<_>>();
    [
        words(&["-U", socket]),
        words(&["-Uu", "-W1", socket, "-s", ret]),
    ]
}

/// The phase and its socket when `argv` is `nc` and one of
/// [`phase_argvs`]' argument lists for one of [`PHASES`], exactly.
fn phase_of_argv(argv: &[String]) -> Option<(&'static str, String)> {
    let (nc, rest) = argv.split_first()?;
    if nc != "nc" {
        return None;
    }
    PHASES.iter().find_map(|phase| {
        let socket = format!("{CLOUD_INIT_SOCKET_DIR}{phase}.sock");
        let ret = format!("{CLOUD_INIT_SOCKET_DIR}{phase}-return.sock");
        phase_argvs(&socket, &ret)
            .iter()
            .any(|a| a.as_slice() == rest)
            .then_some((*phase, socket))
    })
}

/// `event` is cloud-init's own netcat asking a boot phase on its unix socket
/// (the module's identity, every part of it): what it is, said, or `None`.
pub fn cloud_init_socket_client<H: PostureHost>(
    auth: &AuthSessionTracker<H>,
    event: &Event,
) -> Option<String> {
    cloud_init_check(auth, event).ok()
}

/// [`cloud_init_socket_client`], or the first part of the identity that
/// failed, said (for the agent's journal: R005 names it for a netcat that
/// names cloud-init's socket).
pub fn cloud_init_check<H: PostureHost>(
    auth: &AuthSessionTracker<H>,
    event: &Event,
) -> Result<String, String> {
    use common::wire::exe::exe_flags::{KNOWN, ROOT_DIR};
    let Event::ProcessSpawn {
        pid,
        ppid,
        uid,
        argv,
        argv_truncated,
        exe,
        stdio,
        start_ns,
        timestamp_ns,
        ..
    } = event
    else {
        return Err("not an exec".into());
    };
    let no = |why: &str| Err(why.to_string());
    if *uid != 0 {
        return no("not root's");
    }
    if *argv_truncated {
        return no("its argv was cut");
    }
    if *ppid <= 1 {
        return no("no parent but PID 1");
    }
    // the packaged netcat's own file, from a root-only directory, in PID 1's
    // view of the files
    let image = exe.path.as_str();
    if exe.root != (0, 0) {
        return no("its image is in another mount namespace's view");
    }
    if !NETCAT_IMAGES.contains(&image) {
        return Err(format!("{image} is not the packaged netcat"));
    }
    if !exe.has(KNOWN) {
        return no("no LSM identity of its image");
    }
    if !exe.has(ROOT_DIR) {
        return no("its image is not in a root-only directory (ROOT_DIR)");
    }
    if !auth.is_host_file(image, (exe.dev, exe.ino)) {
        return Err(format!("its image is not the host's file at {image}"));
    }
    // a unix socket of cloud-init's, nothing else on the line or the streams:
    // one of the phase units' argvs exactly
    let Some((phase, socket)) = phase_of_argv(argv) else {
        return no("its argv is none of cloud-init's phase units' (`nc -U <socket>`, `nc -Uu -W1 <socket> -s <return socket>`)");
    };
    let no_inet = |s: &nn_model::StdioSocket| s.read && s.inet_fds == 0;
    if !no_inet(&stdio.own) || !no_inet(&stdio.parent) {
        return Err(format!(
            "an inet stream, or its streams not read (own: read {} inet {:#b}; its parent's: read \
             {} inet {:#b})",
            stdio.own.read, stdio.own.inet_fds, stdio.parent.read, stdio.parent.inet_fds
        ));
    }
    // in the cgroup of the unit that asks this phase
    let Some(unit) = auth.system_service_started(*pid, *start_ns) else {
        return no("no service's cgroup for the process that started at its start");
    };
    if !CLOUD_INIT_PHASES
        .iter()
        .any(|(u, p)| *u == unit && *p == phase)
    {
        return Err(format!(
            "{unit} is no cloud-init unit asking the {phase} phase"
        ));
    }
    // forked by the unit's ExecStart= shell, itself PID 1's
    if exe.fork_parent != *ppid {
        return Err(format!(
            "forked by pid {} (the kernel's record), not by its parent {ppid}",
            exe.fork_parent
        ));
    }
    let as_of = AsOf::judged(*timestamp_ns);
    let Some(shell) = auth.exec_identity(*ppid, as_of) else {
        return Err(format!("its parent {ppid}'s exec is not known"));
    };
    let shell_exe = shell.exe.to_string_lossy();
    if !UNIT_SHELLS.contains(&shell_exe.as_ref()) {
        return Err(format!("its parent runs {shell_exe}, no packaged shell"));
    }
    if !auth.ran_host_file(*ppid, as_of, &shell_exe) {
        return Err(format!(
            "its parent's image is not the host's file at {shell_exe}"
        ));
    }
    if auth.exec_uid(*ppid, as_of) != Some(0) {
        return no("its parent is not root's");
    }
    if auth.fork_parent(*ppid, as_of) != Some(1) {
        return Err(format!(
            "its parent was not forked by PID 1 (the kernel's record: {:?})",
            auth.fork_parent(*ppid, as_of)
        ));
    }
    let line = format!("echo \"start\" | {} | sh", argv.join(" "));
    if !auth.exec_argv_is(*ppid, as_of, &["sh", "-c", &line]) {
        return no("its parent's argv is not the unit's line");
    }
    Ok(format!(
        "cloud-init's {unit} asking its {phase} phase on its unix socket {socket}: the packaged \
         {image} (its device and inode) as root, forked by the unit's own shell (pid {ppid}, \
         PID 1's fork)"
    ))
}

/// Lot 350: the fixtures of cloud-init's boot, for this module's tests and R005's.
#[cfg(test)]
pub(crate) mod tests_support {
    use super::*;
    use crate::posture::host::testing::IdTestHost;
    use common::wire::exe::exe_flags::{KNOWN, ROOT_DIR};
    use nn_model::{ExeIdentity, StdioSocket, StdioSockets};
    use std::fs;
    use std::path::Path;

    pub(crate) type Tracker = AuthSessionTracker<IdTestHost>;
    pub(crate) const S: u64 = 1_000_000_000;
    pub(crate) const TICK: u64 = 10_000_000;
    /// The root filesystem's device as `stat(2)` gives it, and in the
    /// kernel's form, as the exec sensor records an image.
    pub(crate) const STAT_DEV: u64 = 64769;
    pub(crate) const KDEV: u64 = common::wire::exe::kernel_dev(STAT_DEV);
    pub(crate) const NC: &str = "/usr/bin/nc.openbsd";
    pub(crate) const NC_ID: (u64, u64) = (KDEV, 5150);
    pub(crate) const DASH: &str = "/usr/bin/dash";
    pub(crate) const DASH_ID: (u64, u64) = (KDEV, 4141);
    pub(crate) const SOCK: &str = "/run/cloud-init/share/final.sock";
    pub(crate) const SHELL: u32 = 800;
    pub(crate) const NETCAT: u32 = 802;
    /// The netcat's start: tick 3_000 (30 s).
    pub(crate) const NC_START: u64 = 3_000 * TICK + 3_000_000;

    /// Debian 13's cloud-final line (cloud-init 25), and its netcat's argv.
    pub(crate) const LINE_25: &str = "echo \"start\" | nc -Uu -W1 /run/cloud-init/share/final.sock -s /run/cloud-init/share/final-return.sock | sh";
    pub(crate) const ARGV_25: &[&str] = &[
        "nc",
        "-Uu",
        "-W1",
        "/run/cloud-init/share/final.sock",
        "-s",
        "/run/cloud-init/share/final-return.sock",
    ];

    pub(crate) fn line(socket: &str) -> String {
        format!("echo \"start\" | nc -U {socket} | sh")
    }

    pub(crate) fn quiet() -> StdioSocket {
        StdioSocket {
            read: true,
            ..Default::default()
        }
    }

    /// The exec of `exe` (`argv`) by `pid`, child of `ppid`, forked by
    /// `forker`, the image `id`, started at `start`.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn exec(
        pid: u32,
        ppid: u32,
        exe: &str,
        argv: &[&str],
        id: (u64, u64),
        forker: u32,
        start: u64,
    ) -> Event {
        Event::ProcessSpawn {
            pid,
            ppid,
            uid: 0,
            gid: 0,
            comm: exe.rsplit('/').next().unwrap_or(exe).into(),
            filename: exe.into(),
            timestamp_ns: start + 1_000_000,
            argv: argv.iter().map(|a| a.to_string()).collect(),
            parent_comm: String::new(),
            parent_start_ns: 0,
            start_ns: start,
            parent_is_kthread: false,
            exe: ExeIdentity {
                path: exe.into(),
                dev: id.0,
                ino: id.1,
                flags: KNOWN | ROOT_DIR,
                fork_parent: forker,
                ..Default::default()
            },
            argv_truncated: false,
            filename_truncated: false,
            stdio: StdioSockets {
                own: quiet(),
                parent: quiet(),
            },
        }
    }

    /// cloud-final.service's shell (PID 1's fork, the packaged dash, the
    /// unit's line) in a tracker whose `/proc` shows the netcat in the
    /// unit's cgroup, at its start.
    pub(crate) fn cloud_final_host() -> (tempfile::TempDir, Tracker) {
        cloud_final_host_running(&line(SOCK))
    }

    /// Lot 350: cloud-final's shell running `shell_line` (cloud-init 25's,
    /// Debian 13's, [`LINE_25`]).
    pub(crate) fn cloud_final_host_running(shell_line: &str) -> (tempfile::TempDir, Tracker) {
        let tmp = tempfile::TempDir::new().unwrap();
        let t = Tracker::new(tmp.path());
        IdTestHost::set_file_id(NC, Some((STAT_DEV, NC_ID.1)));
        IdTestHost::set_file_id(DASH, Some((STAT_DEV, DASH_ID.1)));
        assert!(t.ingest_spawn_event(&exec(
            SHELL,
            1,
            DASH,
            &["sh", "-c", shell_line],
            DASH_ID,
            1,
            20 * S,
        )));
        proc_entry(
            tmp.path(),
            NETCAT,
            3_000,
            "0::/system.slice/cloud-final.service\n",
        );
        (tmp, t)
    }

    pub(crate) fn proc_entry(root: &Path, pid: u32, ticks: u64, cgroup: &str) {
        let dir = root.join(pid.to_string());
        fs::create_dir_all(&dir).unwrap();
        fs::write(
            dir.join("stat"),
            format!("{pid} (nc) S {SHELL} 1 1 0 -1 4194560 0 0 0 0 0 0 0 0 20 0 1 0 {ticks} 0 0\n"),
        )
        .unwrap();
        fs::write(dir.join("cgroup"), cgroup).unwrap();
    }

    pub(crate) fn netcat(argv: &[&str]) -> Event {
        exec(NETCAT, SHELL, NC, argv, NC_ID, SHELL, NC_START)
    }

    pub(crate) fn with(mut e: Event, f: impl FnOnce(&mut Event)) -> Event {
        f(&mut e);
        e
    }
}

#[cfg(test)]
mod tests {
    use super::tests_support::*;
    use super::*;
    use crate::posture::host::testing::IdTestHost;
    use common::wire::exe::exe_flags::{KNOWN, ROOT_DIR};
    use nn_model::{ExeIdentity, StdioSocket, StdioSockets};
    use std::fs;

    /// Lot 350 (named, F2-3): cloud-final.service's
    /// `sh -c 'echo "start" | nc -U /run/cloud-init/share/final.sock | sh'`
    /// at every boot of a cloud image — the packaged netcat, root's, on the
    /// unit's unix socket, in the unit's cgroup, forked by the unit's shell
    /// — is cloud-init's own: recognised (R005 records it Low, the posture
    /// raises no ExploitAttempt).
    #[test]
    fn cloud_init_s_own_netcat_on_its_unix_socket_is_recognised() {
        let (_tmp, t) = cloud_final_host();
        let said = cloud_init_socket_client(&t, &netcat(&["nc", "-U", SOCK]))
            .expect("cloud-init's own netcat");
        assert!(said.contains("cloud-final.service"), "{said}");
        assert!(said.contains(SOCK), "{said}");
    }

    /// Lot 350 (named, F2-3; the after-round on Debian 13): cloud-init 25's
    /// line — `nc -Uu -W1 <socket> -s <return socket>`, a unix datagram
    /// socket — is recognised the same way; the same words with another
    /// return socket, another phase's, or one word less or more, are not.
    #[test]
    fn cloud_init_25_s_datagram_netcat_is_recognised_too() {
        let (_tmp, t) = cloud_final_host_running(LINE_25);
        let said = cloud_init_socket_client(&t, &netcat(ARGV_25)).expect("cloud-init 25's");
        assert!(said.contains("cloud-final.service"), "{said}");
        let mut other = ARGV_25.to_vec();
        for (at, word) in [
            (5, "/tmp/final-return.sock"),
            (5, "/run/cloud-init/share/config-return.sock"),
            (2, "-W2"),
            (1, "-Uuv"),
            (4, "-l"),
        ] {
            let was = other[at];
            other[at] = word;
            assert_eq!(
                cloud_init_socket_client(&t, &netcat(&other)),
                None,
                "{word}"
            );
            other[at] = was;
        }
        assert_eq!(cloud_init_socket_client(&t, &netcat(&ARGV_25[..5])), None);
        let longer = [ARGV_25, &["203.0.113.7"]].concat();
        assert_eq!(cloud_init_socket_client(&t, &netcat(&longer)), None);
        // the argv is checked on its own, whatever the parent's line says: a
        // unit line giving netcat more words, another name, is no cloud-init's
        for argv in [
            &["nc", "-U", SOCK, "203.0.113.7", "4444"][..],
            &["netcat", "-U", SOCK],
            &["nc", "-Uu", "-W1", SOCK, "-s", SOCK],
        ] {
            let shell_line = format!("echo \"start\" | {} | sh", argv.join(" "));
            let (_tmp, t) = cloud_final_host_running(&shell_line);
            assert_eq!(
                cloud_init_socket_client(&t, &netcat(argv)),
                None,
                "{shell_line}"
            );
        }
        // cloud-init 24's argv under cloud-init 25's line: not the unit's line
        assert_eq!(
            cloud_init_socket_client(&t, &netcat(&["nc", "-U", SOCK])),
            None
        );
    }

    /// Lot 350 (named, F2-3): any other netcat is judged as on `main` —
    /// any inet use (a host and a port, `-e`, `-c`, another option, a
    /// stream on an inet socket, its parent's, streams not read), another
    /// socket, the socket of another phase, another unit's cgroup or a
    /// session's, a later process at the pid, a copy of the binary, an
    /// image without `ROOT_DIR` or in another mount namespace, a user's, a
    /// cut argv, and a parent that is not the unit's shell (another line,
    /// another program, not PID 1's fork, not root's, the netcat not its
    /// first exec since that fork).
    #[test]
    fn any_other_netcat_is_not_cloud_init_s() {
        let (tmp, t) = cloud_final_host();
        let no = |e: &Event, what: &str| {
            assert_eq!(cloud_init_socket_client(&t, e), None, "{what}");
        };
        for argv in [
            &["nc", "203.0.113.7", "4444"][..],
            &["nc", "-U", SOCK, "203.0.113.7"],
            &["nc", "-e", "/bin/sh", SOCK],
            &["nc", "-c", SOCK, "x"],
            &["nc", "-lU", SOCK],
            &["nc", "-U", "/tmp/final.sock"],
            &["nc", "-U", "/run/cloud-init/share/../../tmp/x.sock"],
            &["nc", "-U", "/run/cloud-init/share/config.sock"],
            &["nc", "-U"],
            &["nc", SOCK, "-U"],
        ] {
            no(&netcat(argv), &argv.join(" "));
        }
        let ok = netcat(&["nc", "-U", SOCK]);
        let stdio = |own: StdioSocket, parent: StdioSocket| {
            with(ok.clone(), |e| {
                if let Event::ProcessSpawn { stdio, .. } = e {
                    *stdio = StdioSockets { own, parent };
                }
            })
        };
        let inet = StdioSocket {
            read: true,
            inet_fds: 0b010,
            outbound: true,
            proto: 6,
            ..Default::default()
        };
        no(&stdio(inet, quiet()), "its stdout an inet socket");
        no(
            &stdio(quiet(), inet),
            "its parent's streams on an inet socket",
        );
        no(
            &stdio(StdioSocket::default(), quiet()),
            "its streams not read",
        );
        no(
            &stdio(quiet(), StdioSocket::default()),
            "its parent's streams not read",
        );
        let exe_of = |f: &dyn Fn(&mut ExeIdentity)| {
            with(ok.clone(), |e| {
                if let Event::ProcessSpawn { exe, .. } = e {
                    f(exe);
                }
            })
        };
        no(&exe_of(&|x| x.ino = 9), "a copy of netcat (another inode)");
        no(
            &exe_of(&|x| x.flags = KNOWN),
            "not from a root-only directory",
        );
        no(&exe_of(&|x| x.flags = ROOT_DIR), "no LSM identity");
        no(&exe_of(&|x| x.root = (8, 2)), "in another mount namespace");
        no(
            &exe_of(&|x| x.path = "/usr/bin/ncat".into()),
            "another netcat",
        );
        // another packaged netcat, the very file at its own path
        IdTestHost::set_file_id("/usr/bin/nc.traditional", Some((STAT_DEV, 6000)));
        no(
            &exe_of(&|x| {
                x.path = "/usr/bin/nc.traditional".into();
                x.ino = 6000;
            }),
            "a packaged netcat cloud-init does not run",
        );
        no(
            &exe_of(&|x| x.fork_parent = 0),
            "not its first exec since the fork",
        );
        no(
            &with(ok.clone(), |e| {
                if let Event::ProcessSpawn { uid, .. } = e {
                    *uid = 1000;
                }
            }),
            "a user's",
        );
        no(
            &with(ok.clone(), |e| {
                if let Event::ProcessSpawn { argv_truncated, .. } = e {
                    *argv_truncated = true;
                }
            }),
            "a cut argv",
        );
        // another unit's cgroup, a session's, none, a later process
        for cgroup in [
            "0::/system.slice/ssh.service\n",
            "0::/system.slice/cloud-config.service\n",
            "0::/user.slice/user-1000.slice/session-3.scope\n",
            "0::/\n",
        ] {
            proc_entry(tmp.path(), NETCAT, 3_000, cgroup);
            no(&ok, cgroup);
        }
        proc_entry(
            tmp.path(),
            NETCAT,
            3_100,
            "0::/system.slice/cloud-final.service\n",
        );
        no(&ok, "a later process at the pid");
        fs::remove_dir_all(tmp.path().join(NETCAT.to_string())).unwrap();
        no(&ok, "gone");
        proc_entry(
            tmp.path(),
            NETCAT,
            3_000,
            "0::/system.slice/cloud-final.service\n",
        );
        assert!(cloud_init_socket_client(&t, &ok).is_some(), "restored");
    }

    /// One parent of [`only_the_unit_s_own_shell_vouches_for_its_netcat`]:
    /// what is wrong with it, its argv, its image, its forker, its uid.
    type Case<'a> = (&'a str, &'a [&'a str], (u64, u64), u32, u32);

    /// Lot 350 (F2-3): the parent must be the unit's own `ExecStart=` shell
    /// — the packaged dash, root's, PID 1's fork, with exactly the unit's
    /// line for that socket.
    #[test]
    fn only_the_unit_s_own_shell_vouches_for_its_netcat() {
        let ok_line = line(SOCK);
        let cases: [Case; 6] = [
            (
                "another line",
                &["sh", "-c", "nc -U /run/cloud-init/share/final.sock"],
                DASH_ID,
                1,
                0,
            ),
            (
                "another socket's line",
                &[
                    "sh",
                    "-c",
                    "echo \"start\" | nc -U /run/cloud-init/share/config.sock | sh",
                ],
                DASH_ID,
                1,
                0,
            ),
            ("not PID 1's fork", &["sh", "-c", &ok_line], DASH_ID, 700, 0),
            ("a copy of dash", &["sh", "-c", &ok_line], (KDEV, 77), 1, 0),
            ("a user's shell", &["sh", "-c", &ok_line], DASH_ID, 1, 1000),
            ("python", &["sh", "-c", &ok_line], DASH_ID, 1, 0),
        ];
        for (what, argv, id, forker, uid) in cases {
            let tmp = tempfile::TempDir::new().unwrap();
            let t = Tracker::new(tmp.path());
            IdTestHost::set_file_id(NC, Some((STAT_DEV, NC_ID.1)));
            IdTestHost::set_file_id(DASH, Some((STAT_DEV, DASH_ID.1)));
            IdTestHost::set_file_id("/usr/bin/python3.12", Some((STAT_DEV, 99)));
            let exe = if what == "python" {
                "/usr/bin/python3.12"
            } else {
                DASH
            };
            let id = if what == "python" { (KDEV, 99) } else { id };
            let shell = with(exec(SHELL, 1, exe, argv, id, forker, 20 * S), |e| {
                if let Event::ProcessSpawn { uid: u, .. } = e {
                    *u = uid;
                }
            });
            assert!(t.ingest_spawn_event(&shell));
            proc_entry(
                tmp.path(),
                NETCAT,
                3_000,
                "0::/system.slice/cloud-final.service\n",
            );
            assert_eq!(
                cloud_init_socket_client(&t, &netcat(&["nc", "-U", SOCK])),
                None,
                "{what}"
            );
        }
        // no exec of the parent seen at all
        let tmp = tempfile::TempDir::new().unwrap();
        let t = Tracker::new(tmp.path());
        proc_entry(
            tmp.path(),
            NETCAT,
            3_000,
            "0::/system.slice/cloud-final.service\n",
        );
        assert_eq!(
            cloud_init_socket_client(&t, &netcat(&["nc", "-U", SOCK])),
            None
        );
    }

    /// Every cloud-init unit asks one phase, the one its line names.
    #[test]
    fn each_unit_asks_its_own_phase() {
        let units: Vec<&str> = CLOUD_INIT_PHASES.iter().map(|(u, _)| *u).collect();
        let mut sorted = units.clone();
        sorted.sort_unstable();
        assert_eq!(units, sorted, "sorted for review");
        for (unit, phase) in CLOUD_INIT_PHASES {
            assert!(unit.starts_with("cloud-") && unit.ends_with(".service"));
            assert!(["config", "final", "local", "network"].contains(phase));
        }
    }
}
