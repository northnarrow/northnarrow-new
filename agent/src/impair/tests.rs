//! Lab PR 225: security tools switched off — the list, the four kinds of
//! evidence, and what sanctions them.

use std::sync::Arc;

use common::wire::{FimEvent, FimOp};
use common::{Event, ExeIdentity};
use tempfile::TempDir;

use super::*;
use crate::anti_tamper::trusted_installer::TrustedInstallerOverride;

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
    assert!(h
        .run(346, 200, "/usr/sbin/setenforce", &["setenforce", "0"])
        .is_some());
    assert!(h
        .run(347, 200, "/usr/sbin/aa-teardown", &["aa-teardown"])
        .is_some());
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
    std::os::unix::fs::symlink("/usr/sbin/auditd", d.join("exe")).unwrap();
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

fn installer_window() -> Arc<TrustedInstallerOverride> {
    Arc::new(TrustedInstallerOverride::new(
        None,
        0,
        None,
        std::time::Duration::from_secs(600),
    ))
}

/// Decision of 21/10/2026, case 1: inside a valid signed trusted-installer
/// window a stop or restart of the agent's OWN units is sanctioned — a Low
/// finding naming the window (key id, deadline), which the posture does not
/// count; a disable of them is not a stop or a restart and stays High.
#[test]
fn a_valid_window_sanctions_a_stop_or_restart_of_the_agents_own_units() {
    let h = host();
    let w = installer_window();
    h.det.set_installer_window(Arc::clone(&w));
    w.arm_by(120, std::time::Instant::now(), "c2e8f3da");
    for (pid, argv) in [
        (600, vec!["systemctl", "stop", "northnarrow-agent"]),
        (
            601,
            vec!["systemctl", "kill", "--signal=SIGTERM", "northnarrow-agent"],
        ),
        (
            602,
            vec!["systemctl", "stop", "northnarrow-watchdog.service"],
        ),
        (603, vec!["service", "northnarrow-agent", "stop"]),
    ] {
        let exe = if argv[0] == "service" {
            "/usr/sbin/service"
        } else {
            "/usr/bin/systemctl"
        };
        let f = h
            .run(pid, 200, exe, &argv)
            .unwrap_or_else(|| panic!("{argv:?}"));
        assert_eq!(
            (f.rule, f.tool.as_str()),
            (EvaRule::ServiceStopped, AGENT_TOOL),
            "{argv:?}"
        );
        let why = f
            .sanctioned
            .as_deref()
            .unwrap_or_else(|| panic!("{argv:?}: not sanctioned"));
        assert!(
            why.contains("trusted-installer window of key c2e8f3da (until 20"),
            "{argv:?}: {why}"
        );
    }
    let f = h
        .run(
            604,
            200,
            "/usr/bin/systemctl",
            &["systemctl", "disable", "northnarrow-agent"],
        )
        .unwrap();
    assert!(
        f.sanctioned.is_none(),
        "a disable is no stop or restart: {f:?}"
    );
    // the finding's sanction, for its record
    let e = spawn(
        600,
        200,
        "/usr/bin/systemctl",
        &["systemctl", "stop", "northnarrow-agent"],
    );
    let mut e = e;
    if let Event::ProcessSpawn { timestamp_ns, .. } = &mut e {
        *timestamp_ns = 100 * S + 600;
    }
    assert!(h
        .det
        .sanction_of(&e)
        .is_some_and(|w| w.contains("c2e8f3da")));
}

/// Case 2: a window past its deadline (or never armed) sanctions nothing:
/// the stop of the agent's own unit is High, as outside any window.
#[test]
fn an_expired_window_sanctions_nothing() {
    let h = host();
    let w = installer_window();
    h.det.set_installer_window(Arc::clone(&w));
    let f = h
        .run(
            610,
            200,
            "/usr/bin/systemctl",
            &["systemctl", "stop", "northnarrow-agent"],
        )
        .unwrap();
    assert!(f.sanctioned.is_none(), "no window: {f:?}");
    let long_ago = std::time::Instant::now()
        .checked_sub(std::time::Duration::from_secs(300))
        .expect("monotonic clock past 300 s");
    w.arm_by(60, long_ago, "c2e8f3da");
    let f = h
        .run(
            611,
            200,
            "/usr/bin/systemctl",
            &["systemctl", "stop", "northnarrow-agent"],
        )
        .unwrap();
    assert!(f.sanctioned.is_none(), "expired window: {f:?}");
    assert_eq!(h.det.counts().sanctioned, 0);
}

/// Case 3: our window never sanctions another security tool: auditd, or
/// a cloud agent, stopped inside it is High.
#[test]
fn a_valid_window_never_sanctions_another_tool() {
    let h = host();
    let w = installer_window();
    h.det.set_installer_window(Arc::clone(&w));
    w.arm_by(120, std::time::Instant::now(), "c2e8f3da");
    for (pid, argv) in [
        (620, vec!["systemctl", "stop", "auditd"]),
        (621, vec!["systemctl", "kill", "rsyslog"]),
        (622, vec!["auditctl", "-e", "0"]),
    ] {
        let exe = if argv[0] == "auditctl" {
            "/usr/sbin/auditctl"
        } else {
            "/usr/bin/systemctl"
        };
        let f = h
            .run(pid, 200, exe, &argv)
            .unwrap_or_else(|| panic!("{argv:?}"));
        assert_ne!(f.tool, AGENT_TOOL, "{argv:?}");
        assert!(f.sanctioned.is_none(), "{argv:?}: {f:?}");
    }
}

#[test]
fn loading_applies_the_shipped_copy() {
    let t = TempDir::new().unwrap();
    let p = t.path().join("security-tools.v1");
    std::fs::write(&p, BUILTIN_SECURITY_TOOLS_V1).unwrap();
    let (list, source) = SecurityTools::load(&p);
    assert_eq!(source, DefaultsSource::Disk);
    assert_eq!(list, SecurityTools::builtin());
    std::fs::write(&p, "tool evil class=edr\n").unwrap();
    let (list, source) = SecurityTools::load(&p);
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
    let (list, source) = crate::config::overlay::load_pinned_defaults(
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
