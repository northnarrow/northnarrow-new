//! Lab PR 225: security tools switched off — the list, the four kinds of
//! evidence, and what sanctions them.

use std::sync::Arc;

use nn_model::telemetry::{FimEvent, FimOp};
use nn_model::{Event, ExeIdentity};
use tempfile::TempDir;

use super::*;
use crate::posture::host::testing::TestHost as H;

// R08b (lab PR 251): the detector on the portable test host. Its tests of
// the trusted-installer window, which arm and expire the agent's window,
// are the agent's (`impair::host_tests`).
type AuthSessionTracker = crate::posture::lineage::AuthSessionTracker<H>;
type DefenseDetector = super::DefenseDetector<H>;

const S: u64 = 1_000_000_000;

fn spawn(pid: u32, ppid: u32, exe: &str, argv: &[&str]) -> Event {
    Event::ProcessSpawn {
        pid,
        ppid,
        uid: 0,
        gid: 0,
        comm: exe.rsplit('/').next().unwrap().chars().take(15).collect(),
        filename: exe.to_string(),
        timestamp_ns: 100 * S,
        argv: argv.iter().map(|a| a.to_string()).collect(),
        parent_comm: String::new(),
        parent_start_ns: 0,
        start_ns: 0,
        parent_is_kthread: false,
        exe: ExeIdentity::default(),
        argv_truncated: false,
        filename_truncated: false,
        // Lab PR 224: the new image's standard streams (not read here).
        stdio: Default::default(),
    }
}

struct Host {
    _proc: TempDir,
    lineage: AuthSessionTracker,
    det: DefenseDetector,
}

/// A host whose lineage tracker knows a non-interactive root shell (200,
/// under cron 150).
fn host() -> Host {
    let proc = TempDir::new().unwrap();
    let lineage = AuthSessionTracker::new(proc.path());
    lineage.ingest_exec(150, 1, "/usr/sbin/cron", &["cron".into()], S, S, 0);
    lineage.ingest_exec(200, 150, "/usr/bin/bash", &["bash".into()], 2 * S, 2 * S, 0);
    let det = DefenseDetector::with_proc_root(
        Arc::new(SecurityTools::builtin()),
        lineage.clone(),
        None,
        proc.path(),
    );
    Host {
        _proc: proc,
        lineage,
        det,
    }
}

impl Host {
    fn run(&self, pid: u32, ppid: u32, exe: &str, argv: &[&str]) -> Option<Finding> {
        let argv_s: Vec<String> = argv.iter().map(|a| a.to_string()).collect();
        let at = 100 * S + pid as u64;
        self.lineage.ingest_exec(pid, ppid, exe, &argv_s, at, at, 0);
        let mut e = spawn(pid, ppid, exe, argv);
        if let Event::ProcessSpawn { timestamp_ns, .. } = &mut e {
            *timestamp_ns = at;
        }
        self.det.assess(&e)
    }
}

#[test]
fn the_shipped_list_parses_and_names_the_brief_tools() {
    let t = SecurityTools::builtin();
    for name in [
        "auditd",
        "apparmor",
        "ufw",
        "firewalld",
        "nftables",
        "crowdstrike",
        "aliyun-aegis",
    ] {
        assert!(t.tool(name).is_some(), "{name}");
    }
    assert_eq!(t.tool("auditd").unwrap().class, ToolClass::Audit);
    assert_eq!(ToolClass::Audit.attack(), "T1685.004");
    assert_eq!(ToolClass::Firewall.attack(), "T1686");
    assert_eq!(ToolClass::Edr.attack(), "T1685");
    assert!(t.tool_of_unit("auditd.service").is_some());
    assert!(t.tool_of_unit("falcon*").is_some());
    assert!(t.tool_of_unit("nginx").is_none());
    assert_eq!(
        t.tool_of_config("/etc/audit/rules.d/audit.rules")
            .map(|t| t.name.as_str()),
        Some("auditd")
    );
    assert!(t.tool_of_config("/etc/auditx").is_none());
    for bad in [
        "tool x",
        "tool x class=nope",
        "tool x class=edr proc=relative",
        "cmd missing prog",
        "cmd ghost auditctl -e 0",
        "frob x",
    ] {
        assert!(SecurityTools::parse(bad).is_err(), "{bad}");
    }
}

/// MS-25: `systemctl stop auditd`, `auditctl -e 0`, `ufw disable` from a
/// root shell that is no administrator's interactive session — High.
#[test]
fn ms25_commands_are_findings() {
    let h = host();
    let f = h
        .run(
            300,
            200,
            "/usr/bin/systemctl",
            &["systemctl", "stop", "auditd"],
        )
        .expect("systemctl stop auditd");
    assert_eq!(
        (f.rule, f.tool.as_str()),
        (EvaRule::ServiceStopped, "auditd")
    );
    assert!(f.sanctioned.is_none() && f.suspicious.is_none());
    let f = h
        .run(301, 200, "/usr/sbin/auditctl", &["auditctl", "-e", "0"])
        .expect("auditctl -e 0");
    assert_eq!((f.rule, f.tool.as_str()), (EvaRule::SwitchedOff, "auditd"));
    let f = h
        .run(302, 200, "/usr/sbin/ufw", &["ufw", "disable"])
        .expect("ufw disable");
    assert_eq!((f.rule, f.tool.as_str()), (EvaRule::SwitchedOff, "ufw"));
    assert_eq!(f.class, ToolClass::Firewall);
    assert_eq!(h.det.counts().findings, 3);
}

#[test]
fn service_manager_forms() {
    let h = host();
    for (pid, exe, argv, tool) in [
        (
            310,
            "/usr/bin/systemctl",
            vec!["systemctl", "--now", "disable", "apparmor.service"],
            "apparmor",
        ),
        (
            311,
            "/usr/bin/systemctl",
            vec!["systemctl", "mask", "firewalld"],
            "firewalld",
        ),
        (
            312,
            "/usr/bin/systemctl",
            vec!["systemctl", "-s", "KILL", "kill", "falcon-sensor"],
            "crowdstrike",
        ),
        (
            313,
            "/usr/sbin/service",
            vec!["service", "aegis", "stop"],
            "aliyun-aegis",
        ),
        (
            314,
            "/usr/sbin/invoke-rc.d",
            vec!["invoke-rc.d", "rsyslog", "stop"],
            "rsyslog",
        ),
        (
            315,
            "/usr/sbin/update-rc.d",
            vec!["update-rc.d", "-f", "auditd", "remove"],
            "auditd",
        ),
        (
            316,
            "/usr/bin/dash",
            vec!["/bin/sh", "/etc/init.d/auditd", "stop"],
            "auditd",
        ),
        (
            317,
            "/usr/bin/systemctl",
            vec!["systemctl", "disable", "northnarrow-agent"],
            "northnarrow",
        ),
    ] {
        let f = h
            .run(pid, 200, exe, &argv)
            .unwrap_or_else(|| panic!("{argv:?}"));
        assert_eq!(f.tool, tool, "{argv:?}");
    }
    // Not a stop: restart, status, a user unit, an unlisted unit.
    for argv in [
        vec!["systemctl", "restart", "auditd"],
        vec!["systemctl", "status", "auditd"],
        vec!["systemctl", "--user", "stop", "auditd"],
        vec!["systemctl", "stop", "nginx"],
        vec!["systemctl", "start", "ufw"],
    ] {
        assert!(
            h.run(330, 200, "/usr/bin/systemctl", &argv).is_none(),
            "{argv:?}"
        );
    }
    assert!(h
        .run(331, 200, "/usr/sbin/service", &["service", "ufw", "status"])
        .is_none());
}

#[test]
fn switch_off_commands_need_their_arguments() {
    let h = host();
    assert!(h
        .run(340, 200, "/usr/sbin/auditctl", &["auditctl", "-l"])
        .is_none());
    assert!(h
        .run(341, 200, "/usr/sbin/auditctl", &["auditctl", "-e", "1"])
        .is_none());
    assert!(h
        .run(342, 200, "/usr/sbin/auditctl", &["auditctl", "-D"])
        .is_some());
    assert!(h
        .run(343, 200, "/usr/sbin/nft", &["nft", "flush", "ruleset"])
        .is_some());
    assert!(h
        .run(344, 200, "/usr/sbin/nft", &["nft", "list", "ruleset"])
        .is_none());
    // iptables is xtables-nft-multi: named by argv[0].
    let f = h
        .run(345, 200, "/usr/sbin/xtables-nft-multi", &["iptables", "-F"])
        .unwrap();
    assert_eq!(f.tool, "iptables");
    // Lot 282: what a flush of one named chain is depends on the chain's
    // function and on who flushes it (the runtime cases are
    // `a_runtime_flushing_its_own_chain_is_no_switch_off`): from a shell,
    // every chain — a runtime's included — and every table is a switch-off.
    // (each its own pid: the detector memoises a spawn by pid and time)
    for (k, from_a_shell) in [
        &["iptables", "--wait", "-t", "nat", "-F", "CNI-HOSTPORT-DNAT"][..],
        &["ip6tables", "-t", "filter", "--flush", "CNI-ADMIN"][..],
        &["iptables", "-w", "-F", "DOCKER-USER", "-t", "filter"][..],
        &["iptables", "-F", "ufw-user-input"][..],
        &["iptables", "-t", "nat", "-F"][..],
        &["iptables", "-F", "-t", "filter"][..],
        &["ip6tables", "--flush"][..],
        &["iptables", "-w", "-F", "-X"][..],
        &["iptables", "-F", "INPUT"][..],
    ]
    .into_iter()
    .enumerate()
    {
        assert!(
            h.run(
                3480 + k as u32,
                200,
                "/usr/sbin/xtables-nft-multi",
                from_a_shell
            )
            .is_some(),
            "{from_a_shell:?}"
        );
    }
    // the other listed commands are unchanged: an operand after a run that
    // is no flush of iptables still matches (`nft flush ruleset ip`)
    assert!(h
        .run(
            354,
            200,
            "/usr/sbin/nft",
            &["nft", "flush", "ruleset", "ip"]
        )
        .is_some());
    // a policy run in full
    assert!(h
        .run(
            353,
            200,
            "/usr/sbin/xtables-nft-multi",
            &["iptables", "-P", "INPUT", "ACCEPT"]
        )
        .is_some());
    assert!(h
        .run(346, 200, "/usr/sbin/setenforce", &["setenforce", "0"])
        .is_some());
    assert!(h
        .run(347, 200, "/usr/sbin/aa-teardown", &["aa-teardown"])
        .is_some());
}

/// Lot 282 (Tappa Prove P0; lab 04/11 on main: podman's CNI plugin's
/// `iptables -t nat -F CNI-…` was NN-L-EVA-002, and the DefenseImpairment it
/// raised corroborated podman's own mass write into a locked COMBAT that
/// killed podman). A container runtime flushing its own chain — the
/// parent of the `iptables` a runtime program (a CNI plugin, dockerd,
/// podman, netavark, …) in a system tree, installed by a package — switches
/// nothing off. The host firewall's chains (ufw, fail2ban), the filter
/// chains a runtime creates — `DOCKER-USER`, `CNI-ADMIN` (the
/// administrators' rules), `KUBE-FIREWALL` — a built-in chain or a whole
/// table stay a switch-off whoever flushes them; a runtime's chain flushed
/// by a shell, an unpackaged plugin (`/opt/cni/bin`) or an unlisted program
/// in the plugins' directory stays one too.
#[test]
fn a_runtime_flushing_its_own_chain_is_no_switch_off() {
    let h = host();
    let root = TempDir::new().unwrap();
    let info = root.path().join("var/lib/dpkg/info");
    std::fs::create_dir_all(&info).unwrap();
    std::fs::write(root.path().join("var/lib/dpkg/status"), "Package: x\n").unwrap();
    std::fs::write(
        info.join("containernetworking-plugins.list"),
        "/usr/lib/cni\n/usr/lib/cni/bridge\n/usr/lib/cni/portmap\n/usr/lib/cni/extra/helper\n",
    )
    .unwrap();
    std::fs::write(info.join("docker.io.list"), "/usr/sbin/dockerd\n").unwrap();
    // Fedora and RHEL keep the plugins in /usr/libexec/cni
    std::fs::write(
        info.join("containernetworking-plugins-rpm.list"),
        "/usr/libexec/cni/bridge\n",
    )
    .unwrap();
    std::fs::write(info.join("podman.list"), "/usr/bin/podman\n").unwrap();
    let det = DefenseDetector::with_proc_root(
        Arc::new(SecurityTools::builtin()),
        h.lineage.clone(),
        None,
        h._proc.path(),
    )
    .with_program_owners(crate::impact::trust::ProgramOwners::new(root.path()));
    let l = &h.lineage;
    // the runtimes: podman (310) and its CNI plugin (311), dockerd (300);
    // an unpackaged plugin (320), an unlisted program in the plugins'
    // directory (330), a script in it run by a shell (340)
    l.ingest_exec(
        300,
        1,
        "/usr/sbin/dockerd",
        &["dockerd".into()],
        3 * S,
        3 * S,
        0,
    );
    l.ingest_exec(
        310,
        200,
        "/usr/bin/podman",
        &["podman".into()],
        4 * S,
        4 * S,
        0,
    );
    l.ingest_exec(
        311,
        310,
        "/usr/lib/cni/bridge",
        &["bridge".into()],
        5 * S,
        5 * S,
        0,
    );
    l.ingest_exec(
        320,
        310,
        "/opt/cni/bin/bridge",
        &["bridge".into()],
        5 * S,
        5 * S,
        0,
    );
    l.ingest_exec(
        330,
        310,
        "/usr/lib/cni/fake",
        &["fake".into()],
        5 * S,
        5 * S,
        0,
    );
    l.ingest_exec(
        312,
        310,
        "/usr/libexec/cni/bridge",
        &["bridge".into()],
        5 * S,
        5 * S,
        0,
    );
    // a plugin whose own parent cannot be placed (podman's cleanup, run by a
    // conmon that double-forked: lab 04/11, the lot's first run) — its
    // parent is all that is asked
    l.ingest_exec(
        360,
        9999,
        "/usr/lib/cni/portmap",
        &["portmap".into()],
        5 * S,
        5 * S,
        0,
    );
    // a packaged program below the plugins' directory, not in it
    l.ingest_exec(
        350,
        310,
        "/usr/lib/cni/extra/helper",
        &["helper".into()],
        5 * S,
        5 * S,
        0,
    );
    l.ingest_exec(
        340,
        200,
        "/usr/bin/bash",
        &["bash".into(), "/usr/lib/cni/bridge".into()],
        5 * S,
        5 * S,
        0,
    );
    let run = |pid: u32, ppid: u32, argv: &[&str]| {
        let argv_s: Vec<String> = argv.iter().map(|a| a.to_string()).collect();
        let at = 100 * S + pid as u64;
        let ipt = "/usr/sbin/xtables-nft-multi";
        l.ingest_exec(pid, ppid, ipt, &argv_s, at, at, 0);
        let mut e = spawn(pid, ppid, ipt, argv);
        if let Event::ProcessSpawn { timestamp_ns, .. } = &mut e {
            *timestamp_ns = at;
        }
        det.assess(&e)
    };
    let cni = ["iptables", "--wait", "-t", "nat", "-F", "CNI-0a1b2c3d4e5f"];
    // the runtime's own chain, by the runtime: no switch-off
    assert!(
        run(4001, 311, &cni).is_none(),
        "CNI chain by the CNI plugin"
    );
    assert!(run(
        4002,
        311,
        &["ip6tables", "-t", "nat", "--flush", "CNI-DN-0a1b2c"]
    )
    .is_none());
    assert!(
        run(
            4003,
            300,
            &[
                "iptables",
                "--wait",
                "-t",
                "filter",
                "-F",
                "DOCKER-ISOLATION-STAGE-1"
            ]
        )
        .is_none(),
        "dockerd's own chain"
    );
    assert!(run(4004, 300, &["iptables", "-t", "nat", "-F", "DOCKER"]).is_none());
    assert!(run(4005, 310, &["iptables", "-F", "NETAVARK-FORWARD"]).is_none());
    assert!(
        run(4006, 312, &cni).is_none(),
        "the plugin of /usr/libexec/cni"
    );
    assert!(
        run(4007, 360, &cni).is_none(),
        "a plugin whose own parent is unknown"
    );
    // the same chain by anyone else: a switch-off
    assert!(run(4011, 200, &cni).is_some(), "CNI chain by a shell");
    assert!(run(4012, 320, &cni).is_some(), "an unpackaged plugin");
    assert!(
        run(4013, 330, &cni).is_some(),
        "an unlisted program in the plugins' directory"
    );
    assert!(run(4014, 340, &cni).is_some(), "a script run as the plugin");
    assert!(
        run(4015, 350, &cni).is_some(),
        "a program below the plugins' directory"
    );
    // a listed command that is no flush, whatever follows it
    assert!(run(4016, 311, &["nft", "flush", "ruleset", "CNI-0a1b"]).is_some());
    // a host with no package database vouches for nothing
    let bare = TempDir::new().unwrap();
    let det2 = DefenseDetector::with_proc_root(
        Arc::new(SecurityTools::builtin()),
        h.lineage.clone(),
        None,
        h._proc.path(),
    )
    .with_program_owners(crate::impact::trust::ProgramOwners::new(bare.path()));
    let argv_s: Vec<String> = cni.iter().map(|a| a.to_string()).collect();
    let at = 100 * S + 4017;
    l.ingest_exec(4017, 311, "/usr/sbin/xtables-nft-multi", &argv_s, at, at, 0);
    let mut e = spawn(4017, 311, "/usr/sbin/xtables-nft-multi", &cni);
    if let Event::ProcessSpawn { timestamp_ns, .. } = &mut e {
        *timestamp_ns = at;
    }
    assert!(det2.assess(&e).is_some(), "no package database");
    // the firewall's chains, whoever flushes them
    for (k, (ppid, argv)) in [
        (200, &["iptables", "-F", "ufw-user-input"][..]),
        (311, &["iptables", "-F", "ufw-before-input"][..]),
        (300, &["iptables", "-F", "f2b-sshd"][..]),
        (300, &["iptables", "-F", "DOCKER-USER"][..]),
        // the review of #500 (C2): CNI's and kube-proxy's filter chains
        (311, &["iptables", "-t", "filter", "-F", "CNI-ADMIN"][..]),
        (300, &["iptables", "-F", "KUBE-FIREWALL"][..]),
        (311, &["ip6tables", "--flush", "KUBE-FIREWALL"][..]),
        (300, &["iptables", "-F", "INPUT"][..]),
        (311, &["iptables", "-t", "nat", "-F"][..]),
        (300, &["iptables", "-F"][..]),
    ]
    .into_iter()
    .enumerate()
    {
        let f = run(4020 + k as u32, ppid, argv);
        assert!(f.is_some(), "{argv:?} by {ppid}");
        assert_eq!(f.unwrap().rule, EvaRule::SwitchedOff);
    }
}

/// Lot 292: a listed tool that is a script (`fail2ban-server`, Python) is
/// registered from its exec when its interpreter's options are read, and
/// when they are not (what it may run is still looked at: registering a
/// process to watch trusts nothing).
#[test]
fn a_script_tool_is_registered_whatever_its_options() {
    let h = host();
    assert!(h
        .run(
            4960,
            1,
            "/usr/bin/python3.12",
            &[
                "/usr/bin/python3",
                "-s",
                "/usr/bin/fail2ban-server",
                "-xf",
                "start"
            ],
        )
        .is_none());
    assert!(h
        .run(
            4961,
            1,
            "/usr/bin/python3.12",
            &["/usr/bin/python3", "-Z", "/usr/bin/fail2ban-server"],
        )
        .is_none());
    let d = h.det.defenders.lock();
    assert_eq!(d.get(&4960).map(|(t, _)| t.as_str()), Some("fail2ban"));
    assert_eq!(d.get(&4961).map(|(t, _)| t.as_str()), Some("fail2ban"));
}

#[test]
fn kills_of_a_tools_process() {
    let h = host();
    // auditd running as pid 77: registered from its exec.
    assert!(h
        .run(77, 1, "/usr/sbin/auditd", &["/sbin/auditd"])
        .is_none());
    let f = h
        .run(350, 200, "/usr/bin/kill", &["kill", "-9", "77"])
        .expect("kill -9 <auditd>");
    assert_eq!((f.rule, f.tool.as_str()), (EvaRule::Killed, "auditd"));
    assert!(h
        .run(351, 200, "/usr/bin/kill", &["kill", "-0", "77"])
        .is_none());
    assert!(h
        .run(352, 200, "/usr/bin/kill", &["kill", "-9", "78"])
        .is_none());
    let f = h
        .run(353, 200, "/usr/bin/pkill", &["pkill", "-9", "rsyslogd"])
        .unwrap();
    assert_eq!(f.tool, "rsyslog");
    let f = h
        .run(
            354,
            200,
            "/usr/bin/killall",
            &["killall", "-u", "root", "auditd"],
        )
        .unwrap();
    assert_eq!(f.tool, "auditd");
    // The kernel's report of a builtin `kill` (task_kill).
    let f = h
        .det
        .assess(&Event::DefenderSignal {
            pid: 200,
            uid: 0,
            comm: "bash".into(),
            target_pid: 77,
            signal: 19,
            timestamp_ns: 120 * S,
        })
        .unwrap();
    assert_eq!((f.rule, f.pid), (EvaRule::Killed, 200));
    assert!(f.what.contains("signal 19"), "{}", f.what);
}

/// A `Type=forking` daemon (Debian's auditd): the exec'd process forks the
/// daemon and exits, so the pid the exec registered is gone. The `/proc`
/// scans the exec asks for register the daemon's own pid — a builtin
/// `kill -STOP` of a restarted auditd is reported again (lab, MS-25 on
/// debian12).
#[test]
fn a_forking_daemons_own_pid_is_registered_after_its_exec() {
    let h = host();
    let t0 = Instant::now();
    assert!(!h.det.rescan_due(t0));
    assert!(h
        .run(4954, 1, "/usr/sbin/auditd", &["/sbin/auditd"])
        .is_none());
    assert!(h.det.defenders.lock().contains_key(&4954));
    // The daemon, forked (no exec): only /proc names it.
    let d = h._proc.path().join("4955");
    std::fs::create_dir(&d).unwrap();
    crate::posture::host::testing::symlink("/usr/sbin/auditd", d.join("exe")).unwrap();
    std::fs::write(
        d.join("stat"),
        "4955 (auditd) S 1 4955 4955 0 -1 4194560 0 0 0 0 0 0 0 0 20 0 1 0 777 0 0\n",
    )
    .unwrap();
    assert!(!h.det.defenders.lock().contains_key(&4955));
    // Scans fall due after the exec, spaced; then none is left.
    let late = Instant::now() + FORK_RESCAN_AFTER[2] + Duration::from_secs(1);
    assert!(h.det.rescan_due(late));
    assert!(h.det.rescan_if_due(late));
    assert!(h.det.defenders.lock().contains_key(&4955));
    assert!(!h.det.rescan_if_due(late + FORK_RESCAN_SPACING));
    // The kernel's report of a builtin `kill -STOP` of the daemon.
    let f = h
        .det
        .assess(&Event::DefenderSignal {
            pid: 200,
            uid: 0,
            comm: "bash".into(),
            target_pid: 4955,
            signal: 19,
            timestamp_ns: 130 * S,
        })
        .unwrap();
    assert_eq!((f.rule, f.tool.as_str()), (EvaRule::Killed, "auditd"));
    // A burst of tool execs asks for a bounded number of scans.
    for i in 0..10 {
        h.det.schedule_rescan(t0 + Duration::from_millis(i));
    }
    assert!(h.det.rescans.lock().0.len() <= FORK_RESCANS_MAX);
}

/// Lot 311 (N6): a defender whose `stat` shows a `comm` that is not UTF-8
/// is registered with its start — on main its start was unread (`None`),
/// and a later process holding the pid with an unreadable `stat` too
/// passed for it.
#[test]
fn a_defender_whose_comm_is_not_utf8_is_registered_with_its_start() {
    let h = host();
    let d = h._proc.path().join("4956");
    std::fs::create_dir(&d).unwrap();
    crate::posture::host::testing::symlink("/usr/sbin/auditd", d.join("exe")).unwrap();
    std::fs::write(
        d.join("stat"),
        b"4956 (\xff\xfe) S 1 4956 4956 0 -1 4194560 0 0 0 0 0 0 0 0 20 0 1 0 888 0 0\n",
    )
    .unwrap();
    h.det.scan_proc();
    assert_eq!(
        h.det
            .defenders
            .lock()
            .get(&4956)
            .map(|(t, s)| (t.as_str(), *s)),
        Some(("auditd", Some(888)))
    );
}

#[test]
fn config_changes_are_findings_and_paths_are_watched() {
    let h = host();
    let fe = |path: &str, op: FimOp| {
        Event::Fim(FimEvent {
            timestamp_ns: 100 * S,
            path: path.into(),
            op,
            new_sha256: None,
            baseline_sha256: None,
            new_size: None,
            baseline_size: None,
            modifier_exe: None,
            modifier_pid: 200,
            modifier_uid: 0,
            modifier_comm: "bash".into(),
            dest_path: None,
            child_truncated: false,
            wide_coverage: false,
            owner_uid: None,
            reader_dac_capable: false,
            capability: None,
            attrs: None,
            file_key: None,
            is_dir: false,
            moved_in: false,
        })
    };
    let f = h
        .det
        .assess(&fe("/etc/audit/auditd.conf", FimOp::Modified))
        .unwrap();
    assert_eq!(
        (f.rule, f.tool.as_str()),
        (EvaRule::ConfigChanged, "auditd")
    );
    assert!(h
        .det
        .assess(&fe("/etc/ufw/user.rules", FimOp::Deleted))
        .is_some());
    assert!(h
        .det
        .assess(&fe("/etc/audit/auditd.conf", FimOp::Opened))
        .is_none());
    assert!(h.det.assess(&fe("/etc/hosts", FimOp::Modified)).is_none());

    let t = TempDir::new().unwrap();
    let dir = t.path().join("audit");
    std::fs::create_dir(&dir).unwrap();
    std::fs::write(dir.join("auditd.conf"), "x").unwrap();
    std::fs::create_dir(dir.join("rules.d")).unwrap();
    let list = SecurityTools::parse(&format!(
        "tool a class=audit config={}/,{}/missing.conf\n",
        dir.display(),
        t.path().display()
    ))
    .unwrap();
    let paths = list.fim_paths();
    assert!(paths.contains(&dir));
    assert!(paths.contains(&dir.join("auditd.conf")));
    assert!(
        !paths.contains(&dir.join("rules.d")),
        "a subdirectory is listed on its own"
    );
    assert!(paths.contains(&t.path().join("missing.conf")));
}

/// A package transaction and an administrator's interactive session are
/// Low; a script from /tmp is killed with its tree.
#[test]
fn sanctioned_and_suspicious_lineages() {
    let h = host();
    // dpkg as root, its maintainer script stopping auditd on upgrade.
    h.lineage.ingest_exec(
        400,
        200,
        "/usr/bin/dpkg",
        &["dpkg".into(), "-i".into()],
        99 * S,
        99 * S,
        0,
    );
    let f = h
        .run(
            401,
            400,
            "/usr/bin/systemctl",
            &["systemctl", "stop", "auditd"],
        )
        .unwrap();
    assert!(f.sanctioned.is_some(), "{f:?}");
    assert_eq!(h.det.counts().sanctioned, 1);

    h.lineage.ingest_exec(
        500,
        200,
        "/usr/bin/bash",
        &["bash".into(), "/tmp/.x/init.sh".into()],
        99 * S,
        99 * S,
        0,
    );
    let f = h
        .run(
            501,
            500,
            "/usr/bin/systemctl",
            &["systemctl", "stop", "aegis"],
        )
        .unwrap();
    assert!(f.sanctioned.is_none());
    assert_eq!(
        f.suspicious,
        Some((500, "/usr/bin/bash /tmp/.x/init.sh".to_string()))
    );
    // lot 292: an interpreter whose options its table cannot read still
    // shows the staged script it may run — the detection looks at it
    h.lineage.ingest_exec(
        600,
        200,
        "/usr/bin/node",
        &[
            "node".into(),
            "--frobnicate".into(),
            "/tmp/.x/init.js".into(),
        ],
        99 * S,
        99 * S,
        0,
    );
    let f = h
        .run(
            601,
            600,
            "/usr/bin/systemctl",
            &["systemctl", "stop", "aegis"],
        )
        .unwrap();
    assert_eq!(
        f.suspicious,
        Some((600, "/usr/bin/node /tmp/.x/init.js".to_string()))
    );
}

/// The re-check 4 of #539: a lineage cut before PID 1 (here a parent that
/// started after its child: a later process at an exited parent's pid) is
/// not known to the judges that trust it whole; the search for a staged
/// program still reads the hops below the cut.
#[test]
fn a_staged_script_below_a_cut_lineage_is_still_found() {
    let h = host();
    // the process at 899 started after 900 (and executed before the judged
    // exec at 100 s): not 900's parent
    h.lineage.ingest_exec(
        899,
        1,
        "/usr/bin/bash",
        &["bash".into()],
        99 * S + S / 2,
        99 * S + S / 2,
        0,
    );
    h.lineage.ingest_exec(
        900,
        899,
        "/usr/bin/bash",
        &["bash".into(), "/tmp/.x/init.sh".into()],
        99 * S,
        99 * S,
        0,
    );
    let f = h
        .run(
            901,
            900,
            "/usr/bin/systemctl",
            &["systemctl", "stop", "aegis"],
        )
        .unwrap();
    assert!(
        h.lineage.lineage_identities(901, AsOf::Now).is_none(),
        "cut"
    );
    assert_eq!(
        f.suspicious,
        Some((900, "/usr/bin/bash /tmp/.x/init.sh".to_string()))
    );
}

#[test]
fn loading_applies_the_shipped_copy() {
    let t = TempDir::new().unwrap();
    let p = t.path().join("security-tools.v1");
    std::fs::write(&p, BUILTIN_SECURITY_TOOLS_V1).unwrap();
    let (list, source) = SecurityTools::load::<H>(&p);
    assert_eq!(source, DefaultsSource::Disk);
    assert_eq!(list, SecurityTools::builtin());
    std::fs::write(&p, "tool evil class=edr\n").unwrap();
    let (list, source) = SecurityTools::load::<H>(&p);
    assert!(
        matches!(
            source,
            DefaultsSource::Modified {
                loaded_anyway: false,
                ..
            }
        ),
        "{source:?}"
    );
    assert_eq!(
        list,
        SecurityTools::builtin(),
        "an edited list is not applied"
    );
}

/// Review of lab PR 225: the list is pinned to the built-in copy — not
/// signed, no operator overlay — so the unsigned-overlay escape hatch does
/// not apply an edited file either (the loader never reads it).
#[test]
fn an_edited_list_is_never_applied_even_under_the_escape_hatch() {
    let t = TempDir::new().unwrap();
    let p = t.path().join("security-tools.v1");
    std::fs::write(&p, "tool evil class=edr\n").unwrap();
    let (list, source) = crate::config::overlay::load_pinned_defaults::<H, _>(
        "security-tools",
        &p,
        crate::config::overlay::Shipped::new(BUILTIN_SECURITY_TOOLS_V1, &[]),
        |_, text| SecurityTools::parse(text).unwrap_or_else(|_| SecurityTools::builtin()),
    );
    assert_eq!(list, SecurityTools::builtin());
    assert!(
        matches!(
            source,
            DefaultsSource::Modified {
                loaded_anyway: false,
                ..
            }
        ),
        "{source:?}"
    );
}

// ── Lot 316 (external bug hunt, edition 1.4): BUG-86, 89, 96, 106, N4 ─────

mod bug86 {
    //! BUG-86: the three cloud-agent uninstallers the list names as `cmd`
    //! lie in their own tool's `proc=` tree, so their exec is taken for the
    //! tool's process starting (registered, `assess` = None) and
    //! NN-L-EVA-002 never fires for them.
    use super::*;

    #[test]
    fn bug86_a_listed_uninstaller_run_by_a_shell_is_a_switch_off() {
        let h = host();
        let f = h.run(
            360,
            200,
            "/bin/sh",
            &["/bin/sh", "/usr/local/qcloud/YunJing/uninst.sh"],
        );
        let c = h.det.counts();
        let f = f.unwrap_or_else(|| {
            panic!(
                "BUG-86: `sh /usr/local/qcloud/YunJing/uninst.sh`: assess() = None, NN-L-EVA-002 \
                 expected (registered as the tool's process instead: {c:?})"
            )
        });
        assert_eq!(
            (f.rule, f.tool.as_str()),
            (EvaRule::SwitchedOff, "tencent-yunjing")
        );
        assert_eq!(h.det.counts().defenders, 0, "no tool process registered");
    }

    #[test]
    fn bug86_every_listed_uninstaller_in_every_form() {
        let h = host();
        let mut missed = Vec::new();
        let mut pid = 370;
        for script in [
            "/usr/local/qcloud/YunJing/uninst.sh",
            "/usr/local/qcloud/stargate/admin/uninstall.sh",
            "/usr/local/qcloud/monitor/barad/admin/uninstall.sh",
        ] {
            for (exe, argv) in [
                ("/usr/bin/bash", vec!["bash", script]),
                ("/usr/bin/sh", vec!["sh", "-e", script]),
                (script, vec!["/bin/sh", script]),
            ] {
                pid += 1;
                if h.run(pid, 200, exe, &argv).map(|f| f.rule) != Some(EvaRule::SwitchedOff) {
                    missed.push(format!("{exe} {argv:?}"));
                }
            }
        }
        assert!(missed.is_empty(), "BUG-86: no NN-L-EVA-002 for {missed:#?}");
    }

    /// Guard: any other program of the tree is still the tool's process.
    #[test]
    fn bug86_guard_the_tools_own_process_is_registered() {
        let h = host();
        assert!(h
            .run(
                380,
                1,
                "/usr/local/qcloud/YunJing/YDEyes/YDService",
                &["YDService"]
            )
            .is_none());
        assert_eq!(h.det.counts().defenders, 1);
    }
}

mod bug89 {
    //! BUG-89: `pattern_args` takes `-n`, `-o`, `-c` (pkill: --newest,
    //! --oldest, --count) and `-g` (killall: --process-group) as options with
    //! a value (procps-ng 4.0.4 and psmisc 23.7 `--help`, read in the lab:
    //! none takes one), so the process name after them is dropped.
    use super::*;
    use crate::impair::tool_options::SystemTool;

    #[test]
    fn bug89_pkill_and_killall_flags_without_value_keep_the_name() {
        let h = host();
        let mut missed = Vec::new();
        let mut pid = 400;
        for (exe, argv, tool) in [
            ("/usr/bin/pkill", vec!["pkill", "-n", "auditd"], "auditd"),
            ("/usr/bin/pkill", vec!["pkill", "-o", "rsyslogd"], "rsyslog"),
            ("/usr/bin/pkill", vec!["pkill", "-c", "auditd"], "auditd"),
            (
                "/usr/bin/pkill",
                vec!["pkill", "-9", "-n", "auditd"],
                "auditd",
            ),
            (
                "/usr/bin/killall",
                vec!["killall", "-g", "auditd"],
                "auditd",
            ),
        ] {
            pid += 1;
            let got = h.run(pid, 200, exe, &argv);
            if got.as_ref().map(|f| (f.rule, f.tool.as_str())) != Some((EvaRule::Killed, tool)) {
                missed.push(format!("{argv:?} -> {got:?}"));
            }
        }
        assert!(missed.is_empty(), "BUG-89: no NN-L-EVA-003 for {missed:#?}");
    }

    /// The names `argv` gives `tool`, as its table reads them (lot 316:
    /// the hand-written `pattern_args` this guard called is the table now).
    fn pattern_args(tool: SystemTool, argv: &[&str]) -> Vec<String> {
        let a: Vec<String> = argv.iter().map(|s| s.to_string()).collect();
        tool.read(&a, 1)[0]
            .operands
            .iter()
            .map(|s| s.to_string())
            .collect()
    }

    /// Guard: options that do take a value keep it (`pkill -g <pgid>`,
    /// `killall -o <time>`, `killall -n <pid>`, `-u root`).
    #[test]
    fn bug89_guard_valued_options_keep_their_value() {
        let pkill = SystemTool::Pkill;
        assert_eq!(
            pattern_args(pkill, &["pkill", "-g", "auditd", "x"]),
            vec!["x"]
        );
        assert_eq!(
            pattern_args(pkill, &["pkill", "-u", "root", "auditd"]),
            vec!["auditd"]
        );
        let killall = SystemTool::Killall;
        assert_eq!(
            pattern_args(killall, &["killall", "-o", "auditd", "x"]),
            vec!["x"]
        );
        assert_eq!(
            pattern_args(killall, &["killall", "-n", "auditd", "x"]),
            vec!["x"]
        );
        assert_eq!(
            pattern_args(killall, &["killall", "-u", "root", "auditd"]),
            vec!["auditd"]
        );
    }
}

mod bug96 {
    //! BUG-96: inside a valid trusted-installer window, `systemctl stop
    //! northnarrow-agent auditd` is one finding naming the first listed
    //! unit (the agent's), which the window sanctions; auditd, stopped by
    //! the same command, is never High ("The window sanctions nothing of
    //! another tool", the module doc).
    use super::*;
    use crate::anti_tamper::trusted_installer::WindowGrant;
    use crate::posture::host::testing::TestWindow;

    fn open_window(h: &Host) {
        h.det.set_installer_window(Arc::new(TestWindow {
            open: true,
            grant: Some(WindowGrant {
                key_id: "c2e8f3da".to_string(),
                expires_at: "2026-11-11T18:00:00Z".to_string(),
                grantee: None,
            }),
        }));
    }

    #[test]
    fn bug96_window_never_sanctions_auditd_stopped_with_the_agent() {
        let h = host();
        open_window(&h);
        let argv = ["systemctl", "stop", "northnarrow-agent", "auditd"];
        let f = h
            .run(630, 200, "/usr/bin/systemctl", &argv)
            .expect("a finding");
        assert_eq!(f.rule, EvaRule::ServiceStopped);
        assert!(
            f.sanctioned.is_none(),
            "BUG-96: {argv:?} stops auditd inside the window — High as anywhere — but the \
             finding is sanctioned (Low, no DefenseImpairment): {f:?}"
        );
    }

    /// Guard: the reverse order is High on main; the agent's unit alone is
    /// sanctioned by the window.
    #[test]
    fn bug96_guard_reverse_order_and_agent_alone() {
        let h = host();
        open_window(&h);
        let f = h
            .run(
                631,
                200,
                "/usr/bin/systemctl",
                &["systemctl", "stop", "auditd", "northnarrow-agent"],
            )
            .expect("a finding");
        assert!(f.sanctioned.is_none(), "{f:?}");
        let f = h
            .run(
                632,
                200,
                "/usr/bin/systemctl",
                &["systemctl", "stop", "northnarrow-agent"],
            )
            .expect("a finding");
        assert!(f.sanctioned.is_some(), "{f:?}");
    }
}

mod bug106 {
    //! BUG-106: `service_targets` reads systemctl's options with a value from
    //! an incomplete exact-match list: an unlisted one (`-P`,
    //! `--preset-mode`, `--check-inhibitors`, `--kill-who`, `--message`), an
    //! abbreviated long one (`--si`, getopt_long) or a short cluster ending
    //! in one (`-qs KILL`) before the verb moves the verb onto its value.
    use super::*;

    #[test]
    fn bug106_valued_options_before_the_verb_keep_the_verb() {
        let h = host();
        let mut missed = Vec::new();
        let mut pid = 640;
        for (argv, tool) in [
            (vec!["systemctl", "-P", "Id", "stop", "auditd"], "auditd"),
            (
                vec!["systemctl", "--preset-mode", "full", "stop", "auditd"],
                "auditd",
            ),
            (
                vec!["systemctl", "--check-inhibitors", "no", "stop", "auditd"],
                "auditd",
            ),
            (
                vec!["systemctl", "--kill-who", "main", "kill", "auditd"],
                "auditd",
            ),
            (
                vec!["systemctl", "--message", "x", "mask", "northnarrow-agent"],
                "northnarrow",
            ),
            (
                vec!["systemctl", "--si", "KILL", "kill", "auditd"],
                "auditd",
            ),
            (vec!["systemctl", "-qs", "KILL", "kill", "auditd"], "auditd"),
        ] {
            pid += 1;
            let got = h.run(pid, 200, "/usr/bin/systemctl", &argv);
            if got.as_ref().map(|f| (f.rule, f.tool.as_str()))
                != Some((EvaRule::ServiceStopped, tool))
            {
                missed.push(format!("{argv:?} -> {got:?}"));
            }
        }
        assert!(
            missed.is_empty(),
            "BUG-106: no NN-L-EVA-001 for {missed:#?}"
        );
    }

    /// N4 (new in the triage, same family): the switch-off commands were
    /// matched as exact consecutive words, so the long or separate form of a
    /// listed option was no NN-L-EVA-002 (`iptables --policy` is `-P`;
    /// firewall-cmd's argparse reads `--set-default-zone trusted`).
    #[test]
    fn n4_switch_off_long_forms() {
        let h = host();
        let mut missed = Vec::new();
        for (pid, exe, argv) in [
            (
                670,
                "/usr/sbin/iptables",
                vec!["iptables", "--policy", "INPUT", "ACCEPT"],
            ),
            (
                671,
                "/usr/bin/firewall-cmd",
                vec!["firewall-cmd", "--set-default-zone", "trusted"],
            ),
        ] {
            if h.run(pid, 200, exe, &argv).map(|f| f.rule) != Some(EvaRule::SwitchedOff) {
                missed.push(format!("{argv:?}"));
            }
        }
        assert!(missed.is_empty(), "no NN-L-EVA-002 for {missed:#?}");
    }

    /// Guard: the listed forms (existing test, `-s KILL kill falcon-sensor`).
    #[test]
    fn bug106_guard_listed_valued_option() {
        let h = host();
        let f = h
            .run(
                660,
                200,
                "/usr/bin/systemctl",
                &["systemctl", "-s", "KILL", "kill", "falcon-sensor"],
            )
            .expect("a finding");
        assert_eq!(f.tool, "crowdstrike");
    }
}

// ── Lot 316: the mini-hunt — the variants of each fixed bug ─────────────

mod lot316_variants {
    //! Lot 316's mini-hunt (external bug hunt, edition 1.4): other
    //! spellings of BUG-106, BUG-89, BUG-96, BUG-86 and N4, and the benign
    //! commands of an administrator that stay quiet.
    use super::*;
    use crate::anti_tamper::trusted_installer::WindowGrant;
    use crate::posture::host::testing::TestWindow;

    /// `(rule, tool)` of what `argv` run as `exe` is, from pid `pid`.
    fn got(h: &Host, pid: u32, exe: &str, argv: &[&str]) -> Option<(EvaRule, String)> {
        h.run(pid, 200, exe, argv).map(|f| (f.rule, f.tool))
    }

    /// The cases that must be `(rule, tool)`: the ones that are not.
    fn missed(h: &Host, from: u32, cases: &[(&str, &[&str], EvaRule, &str)]) -> Vec<String> {
        let mut out = Vec::new();
        for (k, (exe, argv, rule, tool)) in cases.iter().enumerate() {
            let g = got(h, from + k as u32, exe, argv);
            if g != Some((*rule, tool.to_string())) {
                out.push(format!("{exe} {argv:?} -> {g:?}"));
            }
        }
        out
    }

    const SYSTEMCTL: &str = "/usr/bin/systemctl";

    /// BUG-106's variants: GNU getopt reads an option after the verb as an
    /// option, and with `POSIXLY_CORRECT` (an environment the exec event
    /// does not carry) as a unit — `stop auditd --user` stops the system's
    /// auditd then; the last of `--user`, `--system` is the manager; a
    /// glob systemctl matches against the units in memory.
    #[test]
    fn systemctl_scope_order_and_globs() {
        let h = host();
        let stop = EvaRule::ServiceStopped;
        let m = missed(
            &h,
            7000,
            &[
                (
                    SYSTEMCTL,
                    &["systemctl", "stop", "auditd", "--user"],
                    stop,
                    "auditd",
                ),
                (
                    SYSTEMCTL,
                    &["systemctl", "stop", "-p", "auditd"],
                    stop,
                    "auditd",
                ),
                (
                    SYSTEMCTL,
                    &["systemctl", "--user", "--system", "stop", "auditd"],
                    stop,
                    "auditd",
                ),
                (SYSTEMCTL, &["systemctl", "stop", "*uditd*"], stop, "auditd"),
                (
                    SYSTEMCTL,
                    &["systemctl", "stop", "audit?.service"],
                    stop,
                    "auditd",
                ),
                (
                    SYSTEMCTL,
                    &["systemctl", "kill", "[a]uditd.service"],
                    stop,
                    "auditd",
                ),
                (
                    SYSTEMCTL,
                    &["systemctl", "freeze", "auditd.servic?"],
                    stop,
                    "auditd",
                ),
                (
                    SYSTEMCTL,
                    &["systemctl", "--no-block", "--", "stop", "rsyslog"],
                    stop,
                    "rsyslog",
                ),
                (
                    SYSTEMCTL,
                    &[
                        "systemctl",
                        "--kill-whom=main",
                        "-sSIGKILL",
                        "kill",
                        "falco",
                    ],
                    stop,
                    "falco",
                ),
            ],
        );
        assert!(m.is_empty(), "{m:#?}");
        for (k, argv) in [
            &["systemctl", "--user", "stop", "auditd"][..],
            &["systemctl", "--system", "--user", "stop", "auditd"],
            &["systemctl", "--global", "disable", "auditd"],
            &["systemctl", "stop", "ngin*"],
            &["systemctl", "stop", "audit?"],
        ]
        .into_iter()
        .enumerate()
        {
            assert_eq!(got(&h, 7020 + k as u32, SYSTEMCTL, argv), None, "{argv:?}");
        }
    }

    /// N4's variants: iptables by any of its names (`iptables-nft`,
    /// `iptables-legacy`, the multi-call binaries' `main4`, read from
    /// `argv[1]`), `--flush` by a prefix, nft's command line in one
    /// argument or several, after `--`, among other commands; firewall-cmd's
    /// prefix.
    #[test]
    fn firewall_switch_offs_by_every_name_and_spelling() {
        let h = host();
        let off = EvaRule::SwitchedOff;
        let multi = "/usr/sbin/xtables-nft-multi";
        let m = missed(
            &h,
            7100,
            &[
                (
                    multi,
                    &["xtables-nft-multi", "main4", "-F"],
                    off,
                    "iptables",
                ),
                (
                    multi,
                    &["xtables-nft-multi", "iptables", "--flush"],
                    off,
                    "iptables",
                ),
                (multi, &["iptables-nft", "--fl", "INPUT"], off, "iptables"),
                (
                    multi,
                    &["/usr/sbin/iptables", "-PINPUT", "ACCEPT"],
                    off,
                    "iptables",
                ),
                (multi, &["ip6tables-nft", "-w", "-F"], off, "iptables"),
                (
                    multi,
                    &["xtables-nft-multi", "main6", "--flush"],
                    off,
                    "iptables",
                ),
                (
                    "/usr/sbin/xtables-legacy-multi",
                    &["iptables-legacy", "--policy", "INPUT", "ACCEPT"],
                    off,
                    "iptables",
                ),
                (
                    "/usr/sbin/xtables-legacy-multi",
                    &["x", "main4", "-F"],
                    off,
                    "iptables",
                ),
                ("/usr/sbin/nft", &["nft", "flush ruleset"], off, "nftables"),
                (
                    "/usr/sbin/nft",
                    &["nft", "--", "flush", "ruleset"],
                    off,
                    "nftables",
                ),
                (
                    "/usr/sbin/nft",
                    &["nft", "add table inet x; flush ruleset"],
                    off,
                    "nftables",
                ),
                (
                    "/usr/sbin/nft",
                    &["nft", "list tables\nflush\truleset"],
                    off,
                    "nftables",
                ),
                (
                    "/usr/bin/firewall-cmd",
                    &["firewall-cmd", "--set-def", "trusted"],
                    off,
                    "firewalld",
                ),
                (
                    "/usr/bin/firewall-cmd",
                    &["firewall-cmd", "-q", "--set-default-zone=trusted"],
                    off,
                    "firewalld",
                ),
            ],
        );
        assert!(m.is_empty(), "{m:#?}");
        for (k, (exe, argv)) in [
            (multi, &["iptables-save"][..]),
            (multi, &["xtables-nft-multi", "iptables-translate", "-F"]),
            (multi, &["iptables", "-L", "-n"]),
            ("/usr/sbin/nft", &["nft", "list", "ruleset"]),
            ("/usr/sbin/nft", &["nft", "-f", "/etc/nftables.conf"]),
            ("/usr/sbin/nft", &["nft", "flush", "table", "inet", "x"]),
            (
                "/usr/bin/firewall-cmd",
                &["firewall-cmd", "--set-default-zone=public"],
            ),
            ("/usr/bin/sudo", &["sudo", "iptables", "-F"]),
        ]
        .into_iter()
        .enumerate()
        {
            assert_eq!(got(&h, 7130 + k as u32, exe, argv), None, "{exe} {argv:?}");
        }
    }

    /// BUG-89's variants: pkill's pattern is searched in the name (`pkill
    /// audit` ends auditd: a part at least half of it), `-i` and killall's
    /// `-I` in any case, pkill's
    /// `-f` in the full command line, killall's name with a `/` the
    /// executable; killall's `-signal` with one hyphen.
    #[test]
    fn kill_family_names_as_the_tools_match_them() {
        let h = host();
        let killed = EvaRule::Killed;
        let pkill = "/usr/bin/pkill";
        let killall = "/usr/bin/killall";
        let m = missed(
            &h,
            7200,
            &[
                (pkill, &["pkill", "audit"], killed, "auditd"),
                (pkill, &["pkill", "-i", "AUDITD"], killed, "auditd"),
                (
                    pkill,
                    &["pkill", "-f", "/usr/sbin/auditd"],
                    killed,
                    "auditd",
                ),
                (
                    pkill,
                    &["pkill", "-9", "-f", "sbin/rsyslog"],
                    killed,
                    "rsyslog",
                ),
                (
                    pkill,
                    &["pkill", "--signal=KILL", "-x", "auditd"],
                    killed,
                    "auditd",
                ),
                (killall, &["killall", "/usr/sbin/auditd"], killed, "auditd"),
                (killall, &["killall", "-I", "AUDITD"], killed, "auditd"),
                (
                    killall,
                    &["killall", "-signal", "KILL", "auditd"],
                    killed,
                    "auditd",
                ),
                (killall, &["killall", "-r", "uditd"], killed, "auditd"),
                (
                    killall,
                    &["killall", "/opt/CrowdStrike/falcond"],
                    killed,
                    "crowdstrike",
                ),
                // half of the name, exactly
                (pkill, &["pkill", "dit"], killed, "auditd"),
                // a unit's name, as a process's (as before)
                (pkill, &["pkill", "-x", "aegis"], killed, "aliyun-aegis"),
            ],
        );
        assert!(m.is_empty(), "{m:#?}");
        for (k, (exe, argv)) in [
            (pkill, &["pkill", "-x", "audit"][..]),
            (pkill, &["pkill", "-f", "gunicorn"]),
            (pkill, &["pkill", "/usr/sbin/auditd"]),
            // a part that is less than half of a listed name: anyone's
            (pkill, &["pkill", "-f", "agent"]),
            (pkill, &["pkill", "-f", "server"]),
            (pkill, &["pkill", "log"]),
            (killall, &["killall", "audit"]),
            (killall, &["killall", "nginx"]),
            (killall, &["killall", "-HUP", "nginx"]),
        ]
        .into_iter()
        .enumerate()
        {
            assert_eq!(got(&h, 7230 + k as u32, exe, argv), None, "{exe} {argv:?}");
        }
    }

    /// `kill`'s probes and listings (procps: `-l` prints and exits, `-0` and
    /// `SIGCONT` stop nothing), and an argv whose signal is not known or
    /// that kills in one of its readings;
    /// systemctl's capsule (a user's manager); a 15-byte `comm`.
    #[test]
    fn kill_probes_capsules_and_comm() {
        let h = host();
        assert!(h
            .run(7600, 1, "/usr/sbin/auditd", &["/sbin/auditd"])
            .is_none());
        for (k, argv) in [
            &["kill", "-l", "9", "7600"][..],
            &["kill", "-CONT", "7600"],
            &["kill", "-s", "SIGCONT", "7600"],
            &["kill", "--signal=0", "7600"],
        ]
        .into_iter()
        .enumerate()
        {
            assert_eq!(
                got(&h, 7610 + k as u32, "/usr/bin/kill", argv),
                None,
                "{argv:?}"
            );
        }
        for (k, argv) in [
            &["kill", "-9", "7600"][..],
            &["kill", "--nosuch", "-0", "7600"],
            // GNU getopt reads the `-l` after the pid as a listing; under
            // POSIXLY_CORRECT it is a pid procps refuses — after it killed
            // the one before
            &["kill", "-9", "7600", "-l"],
            &["kill", "-s", "KILL", "7600"],
        ]
        .into_iter()
        .enumerate()
        {
            assert_eq!(
                got(&h, 7620 + k as u32, "/usr/bin/kill", argv),
                Some((EvaRule::Killed, "auditd".to_string())),
                "{argv:?}"
            );
        }
        assert_eq!(
            got(
                &h,
                7630,
                SYSTEMCTL,
                &["systemctl", "-C", "x", "stop", "auditd"]
            ),
            None
        );
        assert_eq!(
            got(
                &h,
                7631,
                "/usr/bin/killall",
                &["killall", "amazon-ssm-agen"]
            ),
            Some((EvaRule::Killed, "amazon-ssm".to_string()))
        );
        assert_eq!(
            got(&h, 7632, "/usr/bin/pkill", &["pkill", "-x", "AUDITD"]),
            None,
            "the case of the name, without -i"
        );
    }

    /// The brief's rule: an option the table does not hold gives the
    /// reader's over-approximation, never `None` — the record says the
    /// options were not understood. What names no listed tool stays quiet.
    #[test]
    fn an_option_no_table_holds_errs_toward_a_detection() {
        let h = host();
        for (k, (exe, argv)) in [
            (
                SYSTEMCTL,
                &["systemctl", "--frobnicate", "x", "stop", "auditd"][..],
            ),
            (SYSTEMCTL, &["systemctl", "-Z", "stop", "auditd"]),
            (
                "/usr/sbin/xtables-nft-multi",
                &["iptables", "-m", "foo", "--foo-bar", "1", "-F"],
            ),
            // an unknown letter, then the flush in the same cluster
            ("/usr/sbin/xtables-nft-multi", &["iptables", "-yF"]),
            // not understood: the name matched every way (a part of it)
            ("/usr/bin/pkill", &["pkill", "--nosuch", "-x", "audit"]),
            ("/usr/bin/pkill", &["pkill", "--nosuch", "auditd"]),
            ("/usr/bin/killall", &["killall", "-Q", "auditd"]),
            (
                "/usr/bin/firewall-cmd",
                &["firewall-cmd", "--nosuch", "--set-default-zone", "trusted"],
            ),
        ]
        .into_iter()
        .enumerate()
        {
            let f = h
                .run(7300 + k as u32, 200, exe, argv)
                .unwrap_or_else(|| panic!("{argv:?}: None"));
            assert!(f.what.contains("options not understood"), "{argv:?}: {f:?}");
        }
        for (k, (exe, argv)) in [
            (
                SYSTEMCTL,
                &["systemctl", "--frobnicate", "status", "auditd"][..],
            ),
            (
                "/usr/sbin/xtables-nft-multi",
                &[
                    "iptables",
                    "-A",
                    "INPUT",
                    "-m",
                    "foo",
                    "--foo-bar",
                    "1",
                    "-j",
                    "ACCEPT",
                ],
            ),
            ("/usr/bin/pkill", &["pkill", "--nosuch", "nginx"]),
        ]
        .into_iter()
        .enumerate()
        {
            assert_eq!(h.run(7320 + k as u32, 200, exe, argv), None, "{argv:?}");
        }
    }

    /// An administrator's everyday commands of these tools stay quiet.
    #[test]
    fn benign_admin_commands_stay_quiet() {
        let h = host();
        let ipt = "/usr/sbin/xtables-nft-multi";
        for (k, (exe, argv)) in [
            (
                SYSTEMCTL,
                &["systemctl", "status", "auditd", "--no-pager"][..],
            ),
            (
                SYSTEMCTL,
                &["systemctl", "--no-pager", "-l", "status", "auditd"],
            ),
            (SYSTEMCTL, &["systemctl", "restart", "auditd"]),
            (SYSTEMCTL, &["systemctl", "reload", "rsyslog"]),
            (SYSTEMCTL, &["systemctl", "is-active", "--quiet", "auditd"]),
            (SYSTEMCTL, &["systemctl", "--user", "stop", "pipewire"]),
            (SYSTEMCTL, &["systemctl", "enable", "--now", "auditd"]),
            (SYSTEMCTL, &["systemctl", "list-units", "--state=failed"]),
            (
                SYSTEMCTL,
                &["systemctl", "show", "-p", "ActiveState", "auditd"],
            ),
            (
                ipt,
                &[
                    "iptables", "-A", "INPUT", "-p", "tcp", "--dport", "22", "-j", "ACCEPT",
                ],
            ),
            (ipt, &["iptables", "-L", "-n", "-v", "--line-numbers"]),
            (ipt, &["iptables", "-S"]),
            (
                ipt,
                &[
                    "iptables",
                    "-t",
                    "nat",
                    "-A",
                    "POSTROUTING",
                    "-o",
                    "eth0",
                    "-j",
                    "MASQUERADE",
                ],
            ),
            (
                ipt,
                &[
                    "iptables",
                    "-I",
                    "INPUT",
                    "1",
                    "-m",
                    "conntrack",
                    "--ctstate",
                    "ESTABLISHED,RELATED",
                    "-j",
                    "ACCEPT",
                ],
            ),
            (
                ipt,
                &[
                    "iptables",
                    "-A",
                    "INPUT",
                    "-j",
                    "LOG",
                    "--log-prefix",
                    "-FW- ",
                ],
            ),
            (ipt, &["iptables", "-P", "INPUT", "DROP"]),
            (ipt, &["ip6tables", "-P", "FORWARD", "DROP"]),
            (
                ipt,
                &[
                    "iptables", "-m", "policy", "--dir", "in", "--pol", "ipsec", "-j", "ACCEPT",
                ],
            ),
            ("/usr/sbin/nft", &["nft", "list", "ruleset"]),
            ("/usr/sbin/nft", &["nft", "-a", "list", "ruleset"]),
            (
                "/usr/sbin/nft",
                &[
                    "nft", "add", "rule", "inet", "filter", "input", "tcp", "dport", "22", "accept",
                ],
            ),
            (
                "/usr/bin/firewall-cmd",
                &["firewall-cmd", "--get-default-zone"],
            ),
            (
                "/usr/bin/firewall-cmd",
                &["firewall-cmd", "--permanent", "--add-service=http"],
            ),
            ("/usr/bin/firewall-cmd", &["firewall-cmd", "--reload"]),
            ("/usr/bin/pkill", &["pkill", "-f", "gunicorn"]),
            ("/usr/bin/pkill", &["pkill", "-HUP", "nginx"]),
            ("/usr/bin/kill", &["kill", "-0", "77"]),
            ("/usr/bin/kill", &["kill", "-s", "0", "77"]),
            ("/usr/bin/kill", &["kill", "-l"]),
        ]
        .into_iter()
        .enumerate()
        {
            assert_eq!(
                h.run(7400 + k as u32, 200, exe, argv),
                None,
                "{exe} {argv:?}"
            );
        }
    }

    /// BUG-96's variants: a window sanctions a stop of the agent's two units
    /// together, nothing that stops another tool's with them — by name, by
    /// glob, by `kill`; and BUG-86's: an uninstaller run as itself.
    #[test]
    fn a_window_sanctions_the_agents_units_only() {
        let h = host();
        h.det.set_installer_window(Arc::new(TestWindow {
            open: true,
            grant: Some(WindowGrant {
                key_id: "c2e8f3da".to_string(),
                expires_at: "2026-11-11T18:00:00Z".to_string(),
                grantee: None,
            }),
        }));
        let f = h
            .run(
                7500,
                200,
                SYSTEMCTL,
                &[
                    "systemctl",
                    "stop",
                    "northnarrow-agent",
                    "northnarrow-watchdog",
                ],
            )
            .expect("a finding");
        assert!(f.sanctioned.is_some(), "{f:?}");
        let f = h
            .run(7501, 200, SYSTEMCTL, &["systemctl", "stop", "northnarrow*"])
            .expect("a finding");
        assert!(f.sanctioned.is_some(), "{f:?}");
        // the review of #548: `condstop` is a stop
        let f = h
            .run(
                7502,
                200,
                SYSTEMCTL,
                &["systemctl", "condstop", "northnarrow-agent"],
            )
            .expect("a finding");
        assert!(f.sanctioned.is_some(), "{f:?}");
        // a mask or a freeze of the agent's own unit: no restart
        for (k, argv) in [
            &["systemctl", "mask", "northnarrow-agent"][..],
            &["systemctl", "freeze", "northnarrow-agent"],
            &["systemctl", "disable", "northnarrow-*"],
        ]
        .into_iter()
        .enumerate()
        {
            let f = h
                .run(7505 + k as u32, 200, SYSTEMCTL, argv)
                .unwrap_or_else(|| panic!("{argv:?}"));
            assert!(f.sanctioned.is_none(), "{argv:?}: {f:?}");
        }
        for (k, argv) in [
            &["systemctl", "stop", "northnarrow-agent", "rsyslog"][..],
            &["systemctl", "kill", "northnarrow-agent", "auditd.service"],
            &["systemctl", "stop", "[an]*"],
            &["systemctl", "stop", "northnarrow-agent", "*uditd*"],
        ]
        .into_iter()
        .enumerate()
        {
            let f = h
                .run(7510 + k as u32, 200, SYSTEMCTL, argv)
                .unwrap_or_else(|| panic!("{argv:?}"));
            assert!(f.sanctioned.is_none(), "{argv:?}: {f:?}");
            assert_ne!(f.tool, AGENT_TOOL, "{argv:?}: {f:?}");
            assert!(f.what.contains("with"), "{argv:?}: {f:?}");
        }
    }

    /// `fnmatch` as systemctl's: `*`, `?`, classes, ranges, negation, and
    /// `\` as itself (`FNM_NOESCAPE`).
    #[test]
    fn unit_globs_match_as_fnmatch() {
        for (p, n, want) in [
            ("*uditd*", "auditd.service", true),
            ("audit?.service", "auditd.service", true),
            ("[a]uditd.service", "auditd.service", true),
            ("[!b]uditd.service", "auditd.service", true),
            ("[^a]uditd.service", "auditd.service", false),
            ("[a-c]uditd.*", "auditd.service", true),
            ("[]a]uditd.service", "auditd.service", true),
            // FNM_NOESCAPE, as systemd matches (the review of #548, F3):
            // `\` is itself
            ("\\auditd.service", "auditd.service", false),
            ("audit?", "auditd.service", false),
            ("*", "auditd.service", true),
            ("[a", "[a", true),
            ("auditd.service?", "auditd.service", false),
            ("a*b*c*d*e*f*g", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", false),
        ] {
            assert_eq!(fnmatch(p, n), want, "{p} {n}");
        }
    }
}

// ── The review of #548 (lot 316's second round) ─────────────────────────

mod rev548 {
    //! The independent review of #548: the glob's cost (F1), systemd's
    //! verbs (F2), its globs (F3), the units' aliases (F4), procps' `kill`
    //! (F8, F9), psmisc's paths (F10), `lt-pkill` (F11), and logrotate's
    //! reload signal (F12).
    use super::*;

    const SC: &str = "/usr/bin/systemctl";

    fn got(h: &Host, pid: u32, exe: &str, argv: &[&str]) -> Option<(EvaRule, String)> {
        h.run(pid, 200, exe, argv).map(|f| (f.rule, f.tool))
    }

    fn stopped(t: &str) -> Option<(EvaRule, String)> {
        Some((EvaRule::ServiceStopped, t.to_string()))
    }

    fn killed(t: &str) -> Option<(EvaRule, String)> {
        Some((EvaRule::Killed, t.to_string()))
    }

    /// F1: a glob of many stars, refused by systemctl, is judged in
    /// microseconds through the detector — it held the decision thread for
    /// hours (158 s at eight stars in a debug build).
    #[test]
    fn a_glob_of_many_stars_is_judged_at_once() {
        let h = host();
        for (k, stars) in [21usize, 64, 200].into_iter().enumerate() {
            let glob = format!("{}Z", "*".repeat(stars));
            let t = std::time::Instant::now();
            assert_eq!(
                got(&h, 9000 + k as u32, SC, &["systemctl", "stop", &glob]),
                None
            );
            let mixed = format!("{}{}", "*a".repeat(stars), "*Z");
            assert_eq!(
                got(&h, 9010 + k as u32, SC, &["systemctl", "stop", &mixed]),
                None
            );
            assert!(
                t.elapsed() < std::time::Duration::from_millis(500),
                "{stars} stars: {:?}",
                t.elapsed()
            );
        }
    }

    /// F2: every verb of systemd's that stops, freezes, signals, disables,
    /// masks, reverts, re-points, reconfigures or cleans a unit is judged.
    #[test]
    fn systemds_verbs_that_reach_a_unit_are_judged() {
        let h = host();
        let mut missed = Vec::new();
        for (k, argv) in [
            &["systemctl", "condstop", "auditd"][..],
            &["systemctl", "clean", "--what=all", "auditd"],
            &["systemctl", "preset", "auditd"],
            &["systemctl", "revert", "auditd"],
            &["systemctl", "edit", "--stdin", "auditd"],
            &["systemctl", "link", "/tmp/x/auditd.service"],
            &["systemctl", "set-property", "auditd", "CPUQuota=1%"],
            &["systemctl", "service-log-target", "auditd", "null"],
            &["systemctl", "service-log-level", "auditd", "emerg"],
            &["systemctl", "bind", "auditd", "/tmp/x", "/etc/audit"],
            &["systemctl", "isolate", "rescue.target"],
            &["systemctl", "isolate", "nn.target"],
            &["systemctl", "rescue"],
            &["systemctl", "emergency"],
            &["systemctl", "preset-all"],
        ]
        .into_iter()
        .enumerate()
        {
            let g = got(&h, 9100 + k as u32, SC, argv);
            if g.as_ref().map(|(r, _)| *r) != Some(EvaRule::ServiceStopped) {
                missed.push(format!("{argv:?} -> {g:?}"));
            }
        }
        assert!(missed.is_empty(), "{missed:#?}");
        assert_eq!(
            got(&h, 9130, SC, &["systemctl", "condstop", "auditd"]),
            stopped("auditd")
        );
        let f = h
            .run(9131, 200, SC, &["systemctl", "isolate", "rescue.target"])
            .unwrap();
        assert!(
            f.what.contains("isolate rescue.target") && f.what.contains("more"),
            "{f:?}"
        );
        // the unit runs again, or the system's usual target: not judged
        for (k, argv) in [
            &["systemctl", "restart", "auditd"][..],
            &["systemctl", "try-restart", "auditd"],
            &["systemctl", "condrestart", "auditd"],
            &["systemctl", "reload-or-restart", "auditd"],
            &["systemctl", "isolate", "multi-user.target"],
            &["systemctl", "isolate", "graphical"],
            &["systemctl", "enable", "--now", "auditd"],
            &["systemctl", "unmask", "auditd"],
            &["systemctl", "set-property", "nginx", "auditd=1"],
        ]
        .into_iter()
        .enumerate()
        {
            assert_eq!(got(&h, 9140 + k as u32, SC, argv), None, "{argv:?}");
        }
    }

    /// F3: a glob as systemd matches it — POSIX classes, a dotted unit with
    /// no type suffix (`snap.amazon-ssm-agent.amazon-ssm-agent`) as a
    /// `.service`, `\` as itself; F4: a unit's alias (rsyslog's
    /// `syslog.service`).
    #[test]
    fn globs_and_aliases_as_systemd_names_units() {
        let h = host();
        for (k, (argv, want)) in [
            (
                &["systemctl", "stop", "[[:alpha:]]uditd.service"][..],
                "auditd",
            ),
            (&["systemctl", "stop", "snap.*.service"], "amazon-ssm"),
            (
                &[
                    "systemctl",
                    "stop",
                    "snap.amazon-ssm-agent.amazon-ssm-agent",
                ],
                "amazon-ssm",
            ),
            (&["systemctl", "stop", "syslog"], "rsyslog"),
            (&["systemctl", "kill", "syslog.service"], "rsyslog"),
            (
                &[
                    "systemctl",
                    "stop",
                    "dbus-org.fedoraproject.FirewallD1.service",
                ],
                "firewalld",
            ),
            (&["service", "syslog", "stop"], "rsyslog"),
        ]
        .into_iter()
        .enumerate()
        {
            let exe = if argv[0] == "service" {
                "/usr/sbin/service"
            } else {
                SC
            };
            assert_eq!(
                got(&h, 9200 + k as u32, exe, argv),
                stopped(want),
                "{argv:?}"
            );
        }
        assert_eq!(
            got(&h, 9220, SC, &["systemctl", "stop", "\\auditd.service"]),
            None,
            "FNM_NOESCAPE"
        );
    }

    /// F8, F9: procps' kill — the last `-s` over the `-SIGNAL` word, a pid
    /// with leading blanks or a `+`; F10: psmisc's killall reads a path as
    /// stat() does; F11: pgrep's binary run as `lt-pkill` is pkill.
    #[test]
    fn kill_pids_paths_and_pkills_name() {
        let h = host();
        assert!(h
            .run(9300, 1, "/usr/sbin/auditd", &["/sbin/auditd"])
            .is_none());
        for (k, argv) in [
            &["kill", "-s", "KILL", "-0", "9300"][..],
            &["kill", "-9", " 9300"],
            &["kill", "-9", "\t+9300"],
        ]
        .into_iter()
        .enumerate()
        {
            assert_eq!(
                got(&h, 9310 + k as u32, "/usr/bin/kill", argv),
                killed("auditd"),
                "{argv:?}"
            );
        }
        // `-0` then `-s 0`: a probe still; a pid with trailing junk is no pid
        assert_eq!(
            got(
                &h,
                9320,
                "/usr/bin/kill",
                &["kill", "-0", "-s", "0", "9300"]
            ),
            None
        );
        assert_eq!(
            got(&h, 9321, "/usr/bin/kill", &["kill", "-9", "9300x"]),
            None
        );
        for (k, p) in [
            "//usr/sbin/auditd",
            "/usr/sbin/./auditd",
            "/usr/bin/../sbin/auditd",
            "/opt/CrowdStrike//falcond",
        ]
        .into_iter()
        .enumerate()
        {
            let want = if p.contains("CrowdStrike") {
                "crowdstrike"
            } else {
                "auditd"
            };
            assert_eq!(
                got(&h, 9330 + k as u32, "/usr/bin/killall", &["killall", p]),
                killed(want),
                "{p}"
            );
        }
        assert_eq!(
            got(&h, 9340, "/usr/bin/pgrep", &["lt-pkill", "auditd"]),
            killed("auditd")
        );
        assert_eq!(got(&h, 9341, "/usr/bin/pgrep", &["pgrep", "auditd"]), None);
        assert_eq!(lexical_path("/a/./b//c/../d"), "/a/b/d");
        assert_eq!(lexical_path("/../x"), "/x");
    }

    /// A process the fixture's `/proc` knows: its start, and the signals it
    /// catches (`SigCgt`).
    fn a_process(h: &Host, pid: u32, start: u64, sigcgt: &str) {
        let d = h._proc.path().join(pid.to_string());
        std::fs::create_dir_all(&d).unwrap();
        std::fs::write(
            d.join("stat"),
            format!(
                "{pid} (x) S 1 {pid} {pid} 0 -1 4194560 0 0 0 0 0 0 0 0 20 0 1 0 {start} 0 0\n"
            ),
        )
        .unwrap();
        std::fs::write(d.join("status"), format!("Name:\tx\nSigCgt:\t{sigcgt}\n")).unwrap();
    }

    /// F12 (the coordinator's decision): a SIGHUP or SIGUSR1 sent by
    /// `systemctl kill` or `kill` to a tool's process that catches it
    /// (`SigCgt`) is a reload — a Low record, no DefenseImpairment;
    /// logrotate's `rsyslog-rotate` sends one every day. To one that does
    /// not catch it, it ends the process: High. Any other signal: High.
    #[test]
    fn a_reload_signal_the_process_catches_is_low() {
        let h = host();
        // rsyslogd catches HUP and USR1 (bits 0 and 9); auditd catches none
        a_process(&h, 9400, 4400, "0000000180014203");
        assert!(h
            .run(9400, 1, "/usr/sbin/rsyslogd", &["/usr/sbin/rsyslogd", "-n"])
            .is_none());
        a_process(&h, 9401, 4401, "0000000000000000");
        assert!(h
            .run(9401, 1, "/usr/sbin/auditd", &["/sbin/auditd"])
            .is_none());
        let low = |pid: u32, exe: &str, argv: &[&str]| {
            let f = h
                .run(pid, 200, exe, argv)
                .unwrap_or_else(|| panic!("{argv:?}"));
            f.sanctioned
        };
        for (k, argv) in [
            &["systemctl", "kill", "-s", "HUP", "rsyslog.service"][..],
            &["systemctl", "kill", "--signal=SIGUSR1", "rsyslog"],
            &["systemctl", "kill", "-s", "1", "rsyslog"],
        ]
        .into_iter()
        .enumerate()
        {
            let s = low(9410 + k as u32, SC, argv);
            assert!(
                s.as_deref().is_some_and(|s| s.contains("SigCgt")),
                "{argv:?}: {s:?}"
            );
        }
        for (k, argv) in [
            &["kill", "-HUP", "9400"][..],
            &["kill", "-s", "USR1", "9400"],
        ]
        .into_iter()
        .enumerate()
        {
            let s = low(9420 + k as u32, "/usr/bin/kill", argv);
            assert!(s.is_some(), "{argv:?}");
        }
        // High: the process does not catch it, another signal, a unit with
        // no registered process, a pid no longer the one registered
        for (k, (exe, argv)) in [
            (SC, &["systemctl", "kill", "-s", "HUP", "auditd"][..]),
            (SC, &["systemctl", "kill", "rsyslog"]),
            (SC, &["systemctl", "kill", "-s", "USR2", "rsyslog"]),
            (SC, &["systemctl", "kill", "-s", "HUP", "rsyslog", "auditd"]),
            (SC, &["systemctl", "kill", "-s", "HUP", "falco"]),
            ("/usr/bin/kill", &["kill", "-HUP", "9401"]),
            ("/usr/bin/kill", &["kill", "-TERM", "9400"]),
            // procps: the last `-s` is the signal
            (
                "/usr/bin/kill",
                &["kill", "-s", "HUP", "-s", "KILL", "9400"],
            ),
            // a stop that names a signal is a stop
            (SC, &["systemctl", "stop", "-s", "HUP", "rsyslog"]),
        ]
        .into_iter()
        .enumerate()
        {
            assert_eq!(low(9430 + k as u32, exe, argv), None, "{argv:?}");
        }
        // the pid now another process (its start changed)
        a_process(&h, 9400, 9999, "0000000180014203");
        assert_eq!(
            low(9440, SC, &["systemctl", "kill", "-s", "HUP", "rsyslog"]),
            None
        );
        assert_eq!(low(9441, "/usr/bin/kill", &["kill", "-HUP", "9400"]), None);
    }
}
