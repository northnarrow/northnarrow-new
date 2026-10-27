//! Lab PR 225 (security tools switched off): the signed trusted-installer
//! window sanctions a stop or restart of the agent's own units — while it
//! is valid, for those units only.
//!
//! R08b (lab PR 251): cut verbatim from `impair`'s tests when the detector
//! moved to nn-core: they arm and expire the agent's window
//! (`anti_tamper::trusted_installer`, its deadline and its key), which the
//! detector reaches through the agent's host. The fixtures they share with
//! the detector's other tests (nn-core's) are copied with them.

use std::sync::Arc;

use nn_model::{Event, ExeIdentity};
use tempfile::TempDir;

use super::*;
use crate::anti_tamper::trusted_installer::TrustedInstallerOverride;
use crate::posture::lineage::AuthSessionTracker;

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
