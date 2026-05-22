//! Integration tests for [`crate::decision::RuleEngine`] with the
//! default rule set. Each rule already has unit tests next to its
//! implementation; these cases pin the behaviour of the engine as a
//! whole — composition, ordering, and the empty-engine baseline.

use common::{Event, ResponseAction, Severity};

use super::rules::testutil::{spawn, spawn_as};
use super::rules::{
    R001ExecFromTmp, R002ExecFromDevShm, R003ExecFromVarTmp, R004ExecFromProcSelfFd,
    R005NetcatExec, R006ReverseShellTooling, R007CryptoMiner, R008HiddenHomeBinary,
    R009RootExecFromUserPath, R010BinaryInWebroot, R011KernelModuleTooling, R012SetcapTooling,
    R013NamespaceEscapeTooling, R014AtBatchScheduling, R015EncodingToolingServiceUid,
    R016DebuggerServiceUid, R017ShellFromNonstandardPath,
};
use super::{Rule, RuleEngine};

/// Tappa 9 C8 / Tappa 9.5 K5 / Tappa 10 N6 / Tappa 10.5 D2..D5: the
/// default rule set covers 8 chain rules (NN-L-CHAIN-001..003 from
/// Tappa 10.5 + NN-L-CHAIN-004..008 cross-PID/N-event from Tappa 10.6
/// D6), 10 Tappa-2 process rules (R001..R010),
/// 7 Tappa-10.5 process rules (R011..R017), 24 FIM rules
/// (NN-L-FIM-001..014 from Tappa 9, NN-L-FIM-015..023 from
/// Tappa 10.5 D3, plus NN-L-FIM-024 anti-tamper bait from Tappa 9.5.1),
/// 4 Tappa-9.5 canary rules (NN-L-CANARY-001..004),
/// and 15 NetFlow rules (NN-L-NET-001..009 from Tappa 10,
/// NN-L-NET-010/011/013/018/019 from Tappa 10.5 D4, plus
/// NN-L-NET-014 DNS-tunnel entropy un-gated by the Tappa 4.1 DNS
/// observability refit) — 67 before T9.5.1, 68 after. Each family
/// matches a distinct `Event` variant set, so the first-match
/// short-circuit is unaffected across families.
#[test]
fn default_engine_has_sixtyeight_rules_across_all_families() {
    let engine = RuleEngine::with_default_rules();
    assert_eq!(engine.rule_count(), 8 + 10 + 7 + 24 + 4 + 15);
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
            argv: Vec::new(),
            parent_comm: String::new(),
            parent_start_ns: 0,
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
    // Tappa 10.5 D2 process rules — instantiated with an empty
    // allowlist (id() is state-independent).
    let al = std::sync::Arc::new(crate::config::comm_allowlist::CommAllowlist::default());
    assert_eq!(
        R011KernelModuleTooling::new(al.clone()).id(),
        "R011_KernelModuleTooling"
    );
    assert_eq!(
        R012SetcapTooling::new(al.clone()).id(),
        "R012_SetcapTooling"
    );
    assert_eq!(
        R013NamespaceEscapeTooling::new(al.clone()).id(),
        "R013_NamespaceEscapeTooling"
    );
    assert_eq!(
        R014AtBatchScheduling::new(al.clone()).id(),
        "R014_AtBatchScheduling"
    );
    assert_eq!(
        R015EncodingToolingServiceUid::new(al.clone()).id(),
        "R015_EncodingToolingServiceUid"
    );
    assert_eq!(
        R016DebuggerServiceUid::new(al.clone()).id(),
        "R016_DebuggerServiceUid"
    );
    assert_eq!(
        R017ShellFromNonstandardPath::new(al).id(),
        "R017_ShellFromNonstandardPath"
    );
}

/// Tappa 10.5 D6 — comprehensive ID pin across EVERY family. The
/// per-family tests (`rule_ids_are_pinned` for process,
/// `chain_rules_builder_returns_eight_rules`, the FIM/canary/net
/// builder tests) each pin their own slice; this walks the FULL
/// `default_rules()` set and asserts the exact sorted list of all 68
/// shipped IDs. Any rename, drop, duplicate, or accidental
/// addition fails here — the immutable-ID contract (decision/mod.rs)
/// covered end-to-end in one place.
///
/// Tappa 4.1 lifted the count 61 → 62 by un-gating NN-L-NET-014
/// (DNS-tunnel entropy). Tappa 10.6 D6 lifts 62 → 67 with the five new
/// cross-PID / N-event chain rules NN-L-CHAIN-004..008. Tappa 9.5.1
/// lifts 67 → 68 with NN-L-FIM-024 (anti-tamper bait).
#[test]
fn default_engine_pins_all_sixtyeight_rule_ids() {
    let rules = super::rules::default_rules();
    let mut ids: Vec<&str> = rules.iter().map(|r| r.id()).collect();
    assert_eq!(
        ids.len(),
        68,
        "engine ships 68 rules after T9.5.1 NN-L-FIM-024"
    );
    ids.sort_unstable();

    let unique: std::collections::BTreeSet<&str> = ids.iter().copied().collect();
    assert_eq!(unique.len(), 68, "all rule IDs must be unique");

    assert_eq!(
        ids,
        vec![
            "NN-L-CANARY-001_FileAccess",
            "NN-L-CANARY-002_ProcessExec",
            "NN-L-CANARY-003_NetworkConnect",
            "NN-L-CANARY-004_CredentialRead",
            "NN-L-CHAIN-001_CredReadThenEgress",
            "NN-L-CHAIN-002_TmpExecThenEgress",
            "NN-L-CHAIN-003_CanaryThenEgress",
            "NN-L-CHAIN-004_CrossPidCredExfil",
            "NN-L-CHAIN-005_CrossPidTmpC2",
            "NN-L-CHAIN-006_CrossPidCanaryExfil",
            "NN-L-CHAIN-007_TmpCredExfilSequence",
            "NN-L-CHAIN-008_CrossPidPrivEscExfil",
            "NN-L-FIM-001_SystemBinaryModified",
            "NN-L-FIM-002_NewSuidBinary",
            "NN-L-FIM-003_SensitiveConfigModified",
            "NN-L-FIM-004_AuthorizedKeysModified",
            "NN-L-FIM-005_LogTruncated",
            "NN-L-FIM-006_OperatorBinaryModified",
            "NN-L-FIM-007_CronDropInCreated",
            "NN-L-FIM-008_KernelModuleModified",
            "NN-L-FIM-009_SystemdUnitDropped",
            "NN-L-FIM-010_RansomwareExtensionRename",
            "NN-L-FIM-011_AwsCredsRead",
            "NN-L-FIM-012_AzureCredsRead",
            "NN-L-FIM-013_GcpCredsRead",
            "NN-L-FIM-014_DockerCredsRead",
            "NN-L-FIM-015_BrowserCredsAccessed",
            "NN-L-FIM-016_PasswordManagerDbAccessed",
            "NN-L-FIM-017_GpgKeyringAccessed",
            "NN-L-FIM-018_LastlogTampered",
            "NN-L-FIM-019_WtmpBtmpTampered",
            "NN-L-FIM-020_ShellHistoryCleared",
            "NN-L-FIM-021_PamModuleModified",
            "NN-L-FIM-022_LdSoPreloadModified",
            "NN-L-FIM-023_SystemdTimerCreated",
            "NN-L-FIM-024_AntiTamperHoneypotModified",
            "NN-L-NET-001_OutboundToBlockedIp",
            "NN-L-NET-002_OutboundToBlockedTld",
            "NN-L-NET-003_BadJa3",
            "NN-L-NET-004_SuspiciousDnsQname",
            "NN-L-NET-005_DnsTxtNullBurst",
            "NN-L-NET-006_UncommonListener",
            "NN-L-NET-007_Rfc1918FromUnusualProc",
            "NN-L-NET-008_OutboundFromTmpExec",
            "NN-L-NET-009_ByteAnomaly",
            "NN-L-NET-010_OutboundToHighRiskC2Port",
            "NN-L-NET-011_PlaintextCredService",
            "NN-L-NET-013_Beacon",
            "NN-L-NET-014_DnsTunnelEntropy",
            "NN-L-NET-018_Rfc1918LateralPort",
            "NN-L-NET-019_WildcardListener",
            "R001_ExecFromTmp",
            "R002_ExecFromDevShm",
            "R003_ExecFromVarTmp",
            "R004_ExecFromProcSelfFd",
            "R005_NetcatExec",
            "R006_ReverseShellTooling",
            "R007_CryptoMiner",
            "R008_HiddenHomeBinary",
            "R009_RootExecFromUserPath",
            "R010_BinaryInWebroot",
            "R011_KernelModuleTooling",
            "R012_SetcapTooling",
            "R013_NamespaceEscapeTooling",
            "R014_AtBatchScheduling",
            "R015_EncodingToolingServiceUid",
            "R016_DebuggerServiceUid",
            "R017_ShellFromNonstandardPath",
        ]
    );
}
