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
/// nothing off. The host firewall's chains (ufw, fail2ban), `DOCKER-USER`
/// (the administrator's rules), a built-in chain or a whole table stay a
/// switch-off whoever flushes them; a runtime's chain flushed by a shell, an
/// unpackaged plugin (`/opt/cni/bin`) or an unlisted program in the plugins'
/// directory stays one too.
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
