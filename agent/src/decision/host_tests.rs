//! The engine's tests that need the agent's other modules (R08b, lab PR
//! 251): cut verbatim from the tests of the code that moved to nn-core —
//! the engine's (`decision::tests`: a detect-only executor runs no response
//! a policy enforces; the demo rules' variable is a weakening variable of
//! `self_integrity`) and the security-tool rules' (`rules::evasion`: the
//! agent's own unit stopped inside the agent's signed trusted-installer
//! window). The fixtures they share with the tests that moved are copied
//! with them; the engine is nn-core's, on the agent's host.

use nn_model::{Event, ResponseAction};

use super::rules::testutil::spawn_as;
use super::RuleEngine;

const SEC: u64 = 1_000_000_000;

/// The production engine (`replay::engine`: the shipped lists, an empty
/// `/proc`) under `policy`.
struct Prod {
    _proc: tempfile::TempDir,
    lineage: crate::posture::lineage::AuthSessionTracker,
    engine: RuleEngine,
}

fn prod(policy: &str) -> Prod {
    let proc = tempfile::TempDir::new().unwrap();
    let lineage = crate::posture::lineage::AuthSessionTracker::new(proc.path());
    let engine = super::replay::engine(super::replay::HostParts {
        configs: std::path::Path::new(concat!(env!("NN_REPO_ROOT"), "/configs")),
        proc_root: proc.path(),
        lineage: lineage.clone(),
        ransom: std::sync::Arc::new(crate::impact::RansomTracker::new(lineage.clone())),
        resolvers: Vec::new(),
        policy: super::rule_policy::parse(policy).unwrap(),
    });
    Prod {
        _proc: proc,
        lineage,
        engine,
    }
}

impl Prod {
    fn decide(&self, e: &Event) -> Option<super::combine::Decision> {
        if let Event::ProcessSpawn {
            pid,
            ppid,
            uid,
            filename,
            argv,
            timestamp_ns,
            exe,
            start_ns,
            ..
        } = e
        {
            self.lineage.ingest_exec(
                *pid,
                *ppid,
                exe.path_or(filename),
                argv,
                *timestamp_ns,
                *start_ns,
                *uid,
            );
        }
        self.engine.decide(e)
    }
}

fn fim_event(path: &str, op: nn_model::telemetry::FimOp, pid: u32, uid: u32, ts: u64) -> Event {
    Event::Fim(nn_model::telemetry::FimEvent {
        timestamp_ns: ts,
        path: path.to_string(),
        op,
        new_sha256: None,
        baseline_sha256: None,
        new_size: None,
        baseline_size: None,
        modifier_exe: Some("/home/u/.local/bin/implant".to_string()),
        modifier_pid: pid,
        modifier_uid: uid,
        modifier_comm: "implant".to_string(),
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
}

/// R020's reverse shell: the shell of a web server, stdio on a socket it
/// connected out.
fn reverse_shell(uid: u32, pid: u32) -> Event {
    let mut e = spawn_as(uid, "bash", "/usr/bin/bash");
    if let Event::ProcessSpawn {
        pid: p,
        ppid,
        stdio,
        exe,
        ..
    } = &mut e
    {
        *p = pid;
        *ppid = pid - 1;
        exe.path = "/usr/bin/bash".into();
        stdio.own = nn_model::StdioSocket {
            read: true,
            inet_fds: 3,
            outbound: true,
            proto: 6,
            peer: Some("203.0.113.7:4444".parse().unwrap()),
        };
    }
    e
}

/// External audit PROC-015: the variable is a weakening variable — in the
/// build whose demo rules it releases, and only there (elsewhere nothing
/// reads it).
#[test]
fn the_demo_rules_variable_is_a_weakening_variable() {
    use super::engine::{ALLOW_DEMO_RULES_ENV, DEMO_RULES_BUILD};
    let (_, weakens) = crate::self_integrity::WEAKENING_ENV
        .iter()
        .find(|(name, _)| *name == ALLOW_DEMO_RULES_ENV)
        .expect("NN_ALLOW_DEMO_RULES is in WEAKENING_ENV");
    assert_eq!(weakens("1"), DEMO_RULES_BUILD);
    assert!(!weakens("0"));
    assert!(!weakens(""));
    assert_eq!(DEMO_RULES_BUILD, cfg!(feature = "demo-tappa5"));
}

/// Detect-only still wins over a lifted ceiling: the enforced FIM-004 kill
/// is a `WouldExecute` in a detect-only executor.
#[test]
fn detect_only_wins_over_a_lifted_ceiling() {
    let d = prod("enforce NN-L-FIM-004\n")
        .decide(&fim_event(
            "/home/u/.ssh/authorized_keys",
            nn_model::telemetry::FimOp::Created,
            7003,
            1000,
            10 * SEC,
        ))
        .expect("a decision");
    let exec = crate::response::Executor::with_config(crate::response::ExecutorConfig {
        dry_run: true,
        ..crate::response::ExecutorConfig::default()
    });
    let mut child = std::process::Command::new("sleep")
        .arg("30")
        .spawn()
        .unwrap();
    let r = &d.responses[0];
    assert_eq!(r.action, ResponseAction::KillProcess);
    let report = exec.execute_for_started(r.action.clone(), child.id(), 0, 0, &r.filename);
    assert_eq!(
        report.primary,
        crate::response::ExecutionOutcome::WouldExecute { pid: child.id() }
    );
    assert!(child.try_wait().unwrap().is_none(), "still running");
    child.kill().unwrap();
    child.wait().unwrap();
}

/// `--detect-only` overrides every mode: the executor of a detect-only
/// agent runs no response a policy enforces (it reports `WouldExecute`).
#[test]
fn detect_only_overrides_an_enforced_kill() {
    let p = prod("enforce R020\n");
    let d = p.decide(&reverse_shell(33, 7401)).unwrap();
    assert_eq!(d.responses.len(), 1);
    let exec = crate::response::Executor::with_config(crate::response::ExecutorConfig {
        dry_run: true,
        ..crate::response::ExecutorConfig::default()
    });
    // A real child, so a kill that ran would show.
    let mut child = std::process::Command::new("sleep")
        .arg("30")
        .spawn()
        .unwrap();
    let r = &d.responses[0];
    let report = exec.execute_for_started(r.action.clone(), child.id(), 0, 0, &r.filename);
    assert_eq!(
        report.primary,
        crate::response::ExecutionOutcome::WouldExecute { pid: child.id() }
    );
    assert!(child.try_wait().unwrap().is_none(), "still running");
    child.kill().unwrap();
    child.wait().unwrap();
}

/// The security-tool rules over the agent's trusted-installer window.
mod installer_window {
    use std::sync::Arc;

    use nn_model::{Event, ResponseAction, Severity, Verdict};

    use crate::decision::rules::evasion::evasion_rules;
    use crate::decision::Rule;
    use crate::impair::{DefenseDetector, SecurityTools};
    use crate::posture::lineage::AuthSessionTracker;

    const S: u64 = 1_000_000_000;

    fn spawn(pid: u32, ppid: u32, exe: &str, argv: &[&str]) -> Event {
        Event::ProcessSpawn {
            pid,
            ppid,
            uid: 0,
            gid: 0,
            comm: "x".into(),
            filename: exe.to_string(),
            timestamp_ns: 100 * S + pid as u64,
            argv: argv.iter().map(|a| a.to_string()).collect(),
            parent_comm: String::new(),
            parent_start_ns: 0,
            start_ns: 0,
            parent_is_kthread: false,
            exe: nn_model::ExeIdentity::default(),
            argv_truncated: false,
            filename_truncated: false,
            // Lab PR 224: the new image's standard streams (not read here).
            stdio: Default::default(),
        }
    }

    fn rules() -> (tempfile::TempDir, AuthSessionTracker, Vec<Box<dyn Rule>>) {
        let t = tempfile::TempDir::new().unwrap();
        let l = AuthSessionTracker::new(t.path());
        l.ingest_exec(200, 1, "/usr/bin/bash", &["bash".into()], S, S, 0);
        let d = Arc::new(DefenseDetector::new(
            Arc::new(SecurityTools::builtin()),
            l.clone(),
            None,
        ));
        (t, l, evasion_rules(d))
    }

    fn first(rules: &[Box<dyn Rule>], e: &Event) -> Option<Verdict> {
        rules.iter().find_map(|r| r.evaluate(e))
    }

    /// Decision of 21/10/2026: the agent's own unit stopped inside a valid
    /// signed trusted-installer window is a Low record naming the window;
    /// expired, High again; another tool in the window, High.
    #[test]
    fn eva_001_inside_the_installer_window_is_low_for_the_agents_own_units_only() {
        use crate::anti_tamper::trusted_installer::TrustedInstallerOverride;
        let (_t, l, _) = rules();
        let d = Arc::new(DefenseDetector::new(
            Arc::new(SecurityTools::builtin()),
            l.clone(),
            None,
        ));
        let w = Arc::new(TrustedInstallerOverride::new(
            None,
            0,
            None,
            std::time::Duration::from_secs(600),
        ));
        d.set_installer_window(Arc::clone(&w));
        let rules = evasion_rules(Arc::clone(&d));
        let run = |pid: u32, argv: &[&str]| {
            let argv_s: Vec<String> = argv.iter().map(|a| a.to_string()).collect();
            let at = 100 * S + u64::from(pid);
            l.ingest_exec(pid, 200, "/usr/bin/systemctl", &argv_s, at, at, 0);
            first(&rules, &spawn(pid, 200, "/usr/bin/systemctl", argv)).unwrap()
        };
        w.arm_by(120, std::time::Instant::now(), "c2e8f3da");
        let v = run(
            900,
            &["systemctl", "kill", "--signal=SIGTERM", "northnarrow-agent"],
        );
        assert_eq!(v.rule_id, "NN-L-EVA-001_SecurityServiceStopped");
        assert_eq!(
            (v.action.clone(), v.severity),
            (ResponseAction::Log, Severity::Low)
        );
        assert!(
            v.reasoning.contains("window of key c2e8f3da (until "),
            "{}",
            v.reasoning
        );
        let v = run(901, &["systemctl", "stop", "auditd"]);
        assert_eq!(v.severity, Severity::High, "{}", v.reasoning);
        w.close("test");
        let v = run(
            902,
            &["systemctl", "kill", "--signal=SIGTERM", "northnarrow-agent"],
        );
        assert_eq!(v.severity, Severity::High, "{}", v.reasoning);
    }
}
