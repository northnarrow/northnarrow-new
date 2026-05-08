//! Integration tests for [`crate::decision::RuleEngine`] with the
//! default rule set. Each rule already has unit tests next to its
//! implementation; these cases pin the behaviour of the engine as a
//! whole — composition, ordering, and the empty-engine baseline.

use common::{Event, ResponseAction, Severity};

use super::rules::testutil::{spawn, spawn_as};
use super::rules::{
    R001ExecFromTmp, R002ExecFromDevShm, R003ExecFromVarTmp, R004ExecFromProcSelfFd,
    R005NetcatExec, R006ReverseShellTooling, R007CryptoMiner, R008HiddenHomeBinary,
    R009RootExecFromUserPath, R010BinaryInWebroot,
};
use super::{Rule, RuleEngine};

#[test]
fn default_engine_has_ten_rules() {
    let engine = RuleEngine::with_default_rules();
    assert_eq!(engine.rule_count(), 10);
}

#[test]
fn empty_engine_returns_none() {
    let engine = RuleEngine::new();
    assert!(engine.evaluate(&spawn("ls", "/usr/bin/ls")).is_none());
    assert!(engine.evaluate(&spawn("payload", "/tmp/payload")).is_none());
}

#[test]
fn benign_exec_does_not_fire_anything() {
    let engine = RuleEngine::with_default_rules();
    assert!(engine.evaluate(&spawn("ls", "/usr/bin/ls")).is_none());
    assert!(engine.evaluate(&spawn("bash", "/bin/bash")).is_none());
}

#[test]
fn exec_from_tmp_routes_to_r001() {
    let engine = RuleEngine::with_default_rules();
    let v = engine
        .evaluate(&spawn("payload", "/tmp/payload"))
        .expect("should fire");
    assert_eq!(v.rule_id, "R001_ExecFromTmp");
    assert_eq!(v.action, ResponseAction::KillProcess);
    assert_eq!(v.severity, Severity::Medium);
    assert_eq!(v.event_pid, 1234);
    assert_eq!(v.event_filename, "/tmp/payload");
}

#[test]
fn dev_shm_exec_routes_to_r002() {
    let engine = RuleEngine::with_default_rules();
    let v = engine
        .evaluate(&spawn("dropper", "/dev/shm/dropper"))
        .expect("should fire");
    assert_eq!(v.rule_id, "R002_ExecFromDevShm");
}

#[test]
fn proc_self_fd_takes_priority_over_other_matches() {
    // R004 is registered before R009: a root /proc/self/fd exec must
    // surface as fileless-exec, not as user-path priv-esc.
    let engine = RuleEngine::with_default_rules();
    let v = engine
        .evaluate(&Event::ProcessSpawn {
            pid: 1,
            ppid: 0,
            uid: 0,
            gid: 0,
            comm: "memexec".into(),
            filename: "/proc/self/fd/3".into(),
            timestamp_ns: 0,
        })
        .expect("should fire");
    assert_eq!(v.rule_id, "R004_ExecFromProcSelfFd");
    assert_eq!(v.severity, Severity::Critical);
    assert_eq!(v.action, ResponseAction::KillProcessTree);
}

#[test]
fn root_in_user_path_takes_priority_over_r001() {
    // A root-uid exec from /tmp/ matches both R001 (medium) and R009
    // (high). R009 is registered earlier so it wins.
    let engine = RuleEngine::with_default_rules();
    let v = engine
        .evaluate(&spawn_as(0, "payload", "/tmp/payload"))
        .expect("should fire");
    assert_eq!(v.rule_id, "R009_RootExecFromUserPath");
    assert_eq!(v.severity, Severity::High);
}

#[test]
fn miner_match_routes_to_r007() {
    let engine = RuleEngine::with_default_rules();
    let v = engine
        .evaluate(&spawn("xmrig", "/tmp/xmrig"))
        .expect("should fire");
    assert_eq!(v.rule_id, "R007_CryptoMiner");
    assert_eq!(v.action, ResponseAction::KillProcessTree);
}

#[test]
fn rules_share_consistent_metadata() {
    // Sanity: each rule has a non-empty id, name, and category.
    let rules: Vec<Box<dyn Rule>> = vec![
        Box::new(R001ExecFromTmp),
        Box::new(R002ExecFromDevShm),
        Box::new(R003ExecFromVarTmp),
        Box::new(R004ExecFromProcSelfFd),
        Box::new(R005NetcatExec),
        Box::new(R006ReverseShellTooling),
        Box::new(R007CryptoMiner),
        Box::new(R008HiddenHomeBinary),
        Box::new(R009RootExecFromUserPath),
        Box::new(R010BinaryInWebroot),
    ];
    for r in &rules {
        assert!(!r.id().is_empty());
        assert!(!r.name().is_empty());
        assert!(!r.category().is_empty());
        assert!(r.id().starts_with('R'));
    }
    // Ids must be unique.
    let mut ids: Vec<&str> = rules.iter().map(|r| r.id()).collect();
    ids.sort();
    let dedup_len = {
        let mut d = ids.clone();
        d.dedup();
        d.len()
    };
    assert_eq!(ids.len(), dedup_len);
}

#[test]
fn ordering_is_deterministic() {
    // Same engine, same event → same verdict on every call.
    let engine = RuleEngine::with_default_rules();
    let evt = spawn("payload", "/tmp/payload");
    let a = engine.evaluate(&evt).unwrap().rule_id;
    let b = engine.evaluate(&evt).unwrap().rule_id;
    let c = engine.evaluate(&evt).unwrap().rule_id;
    assert_eq!(a, b);
    assert_eq!(b, c);
}

// Quick smoke: every rule's id appears with the expected string. If a
// rule id is renamed accidentally, this test fails before rule users
// (telemetry, alert dedup, future correlation) silently regress.
#[test]
fn rule_ids_are_pinned() {
    assert_eq!(R001ExecFromTmp.id(), "R001_ExecFromTmp");
    assert_eq!(R002ExecFromDevShm.id(), "R002_ExecFromDevShm");
    assert_eq!(R003ExecFromVarTmp.id(), "R003_ExecFromVarTmp");
    assert_eq!(R004ExecFromProcSelfFd.id(), "R004_ExecFromProcSelfFd");
    assert_eq!(R005NetcatExec.id(), "R005_NetcatExec");
    assert_eq!(R006ReverseShellTooling.id(), "R006_ReverseShellTooling");
    assert_eq!(R007CryptoMiner.id(), "R007_CryptoMiner");
    assert_eq!(R008HiddenHomeBinary.id(), "R008_HiddenHomeBinary");
    assert_eq!(R009RootExecFromUserPath.id(), "R009_RootExecFromUserPath");
    assert_eq!(R010BinaryInWebroot.id(), "R010_BinaryInWebroot");
}
