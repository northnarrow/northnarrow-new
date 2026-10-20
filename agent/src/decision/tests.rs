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
/// observability refit) — 67 before T9.5.1, 68 after, 69 after BUG-034
/// R018 (module-load), 70 after NN-L-NET-020 (review 78), 71 after
/// NN-L-FIM-025 (review 86), 72 after NN-L-NET-021 (external audit
/// EBPF-013). Each family matches a distinct `Event` variant
/// set, so the first-match short-circuit is unaffected across families.
/// External audit PROC-010/PROC-009: R007 is registered twice (its
/// exact-name pass near the head, its name-fragment pass after the
/// process kills), so the engine holds 73 rules under 72 ids.
/// External audit PROC-014: the io_uring (NN-L-IOU-001/002) and BPF
/// (NN-L-BPF-001/002) rules, which only the production builder had, are
/// in `default_rules()` too: 77 rules under 76 ids.
#[test]
fn default_engine_has_seventy_six_rules_across_all_families() {
    let engine = RuleEngine::with_default_rules();
    // chain 8 + tappa2 10 (+ R007's second pass) + process 7
    //   + module-load 1 (R018, BUG-034) + io_uring 2 + BPF 2 (PROC-014)
    //   + FIM 25 + canary 4 + net 17
    assert_eq!(
        engine.rule_count(),
        8 + 10 + 1 + 7 + 1 + 2 + 2 + 25 + 4 + 17
    );
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
    assert_eq!(v.action, ResponseAction::KillProcessTree);
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
            start_ns: 0,
            parent_is_kthread: false,
            exe: Default::default(),
            argv_truncated: false,
            filename_truncated: false,
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
    assert_eq!(v.action, ResponseAction::KillProcessTree);
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
        Box::new(R004ExecFromProcSelfFd::default()),
        Box::new(R005NetcatExec),
        Box::new(R006ReverseShellTooling::new(Default::default())),
        Box::new(R007CryptoMiner::new(Default::default())),
        Box::new(R008HiddenHomeBinary),
        Box::new(R009RootExecFromUserPath::default()),
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
    assert_eq!(
        R004ExecFromProcSelfFd::default().id(),
        "R004_ExecFromProcSelfFd"
    );
    assert_eq!(R005NetcatExec.id(), "R005_NetcatExec");
    assert_eq!(
        R006ReverseShellTooling::new(Default::default()).id(),
        "R006_ReverseShellTooling"
    );
    assert_eq!(
        R007CryptoMiner::new(Default::default()).id(),
        "R007_CryptoMiner"
    );
    assert_eq!(
        R007CryptoMiner::name_fragments(Default::default()).id(),
        "R007_CryptoMiner"
    );
    assert_eq!(R008HiddenHomeBinary.id(), "R008_HiddenHomeBinary");
    assert_eq!(
        R009RootExecFromUserPath::default().id(),
        "R009_RootExecFromUserPath"
    );
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
/// lifts 67 → 68 with NN-L-FIM-024 (anti-tamper bait); BUG-034 R018
/// (module-load) lifts 68 → 69; NN-L-NET-020 → 70; NN-L-FIM-025 → 71;
/// NN-L-NET-021 (external audit EBPF-013) → 72; the io_uring and BPF
/// rules, until then in the production builder only (external audit
/// PROC-014) → 76. [`production_engine_pins_all_rule_ids`] holds the
/// production builder to this same list, in the same order.
#[test]
fn default_engine_pins_all_seventy_six_rule_ids() {
    let rules = super::rules::default_rules();
    let mut ids: Vec<&str> = rules.iter().map(|r| r.id()).collect();
    assert_eq!(
        ids.len(),
        77,
        "engine ships 76 rules after the io_uring and BPF rules (external audit PROC-014), \
         R007 in two passes (external audit PROC-010)"
    );
    // External audit PROC-010: R007's two passes share its id; no other
    // id appears twice.
    let r007 = ids.iter().filter(|id| **id == "R007_CryptoMiner").count();
    assert_eq!(r007, 2);
    ids.sort_unstable();
    ids.dedup();

    let unique: std::collections::BTreeSet<&str> = ids.iter().copied().collect();
    assert_eq!(unique.len(), 76, "all rule IDs must be unique");

    assert_eq!(
        ids,
        vec![
            "NN-L-BPF-001_BpfProgramLoaded",
            "NN-L-BPF-002_BpfForeignHandleOrDetach",
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
            "NN-L-FIM-025_FileCapabilityGranted",
            "NN-L-IOU-001_IoUringRingCreated",
            "NN-L-IOU-002_IoUringFileAndNetwork",
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
            "NN-L-NET-020_DnsQueryFlood",
            "NN-L-NET-021_SensorRecordFlood",
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
            "R018_KernelModuleLoad",
        ]
    );
}

// ── External audit PROC-014 / PROC-015: one composition, pinned ──

/// The production engine, built as `main.rs` builds it, over empty
/// operator state (no blocklist, no allowlist entry, an inert installer
/// override) and `lineage`.
fn production_engine(lineage: crate::posture::lineage::AuthSessionTracker) -> RuleEngine {
    use std::sync::Arc;

    use parking_lot::Mutex;

    use crate::config::comm_allowlist::CommAllowlist;
    use crate::net::blocklist::{Ja3Blocklist, NetBlocklist};
    RuleEngine::with_default_rules_and_net(
        Arc::new(NetBlocklist::default()),
        Arc::new(Ja3Blocklist::default()),
        Arc::new(Mutex::new(super::rules::net::DnsBurstWindow::default())),
        Arc::new(CommAllowlist::default()),
        Arc::new(CommAllowlist::default()),
        Arc::new(Mutex::new(super::rules::net::BeaconWindow::default())),
        Arc::new(crate::net::dns_cache::DnsCache::default()),
        crate::anti_tamper::trusted_installer::TrustedInstallerOverride::inert_arc(),
        lineage,
        crate::canary::readers::CanaryReaders::default(),
        Arc::new(Mutex::new(super::correlation::CorrelationStore::new())),
    )
}

/// A lineage cache that reads no host `/proc`, with `execs` ingested as
/// the exec sensor would.
fn lineage_of(
    execs: &[(u32, &str)],
) -> (
    tempfile::TempDir,
    crate::posture::lineage::AuthSessionTracker,
) {
    let tmp = tempfile::TempDir::new().unwrap();
    let t = crate::posture::lineage::AuthSessionTracker::new(tmp.path());
    for (pid, exe) in execs {
        t.ingest_spawn_with_argv(*pid, 1, exe, &[exe.to_string()], 1);
    }
    (tmp, t)
}

/// External audit PROC-014 (NN-AUD-429): the production builder
/// (`default_rules_with_net`, what `main.rs` runs) registers exactly the
/// rules of `default_rules()`, in the same order. The engine tests above
/// and below build `default_rules()`; with this one they hold for the
/// shipped engine too, and a family dropped from either builder (the
/// io_uring and BPF rules were in the production one only) or a rule
/// registered twice fails here.
#[test]
fn production_engine_pins_all_rule_ids() {
    let (_tmp, lineage) = lineage_of(&[]);
    let production = production_engine(lineage);
    let default = RuleEngine::with_default_rules();
    assert_eq!(production.rule_count(), 77);
    assert_eq!(production.rule_ids(), default.rule_ids());
}

/// The family of a rule id: `R` for the process rules (R001..R018), else
/// its `NN-L-<FAMILY>` prefix.
fn family(id: &str) -> &str {
    if id.starts_with('R') {
        return "R";
    }
    let rest = id.strip_prefix("NN-L-").expect("an NN-L- rule id");
    let end = "NN-L-".len() + rest.find('-').expect("NN-L-<FAMILY>-<NNN>");
    &id[..end]
}

/// External audit PROC-014: the order of the families in both builders.
/// The chains that observe precursors come first (Tappa 10.5 D5), the
/// process rules in [`super::rules`]'s `spawn_rules` order (every kill
/// before any record, PROC-009), then R018 and the families of the other
/// event kinds; NN-L-CHAIN-008, a Log, comes last so it never shadows a
/// blocking verdict.
#[test]
fn both_builders_keep_the_family_order() {
    let (_tmp, lineage) = lineage_of(&[]);
    for (name, ids) in [
        ("default_rules", RuleEngine::with_default_rules().rule_ids()),
        ("production", production_engine(lineage).rule_ids()),
    ] {
        let mut runs: Vec<(&str, usize)> = Vec::new();
        for id in &ids {
            match runs.last_mut() {
                Some((f, n)) if *f == family(id) => *n += 1,
                _ => runs.push((family(id), 1)),
            }
        }
        assert_eq!(
            runs,
            vec![
                ("NN-L-CHAIN", 7),
                ("R", 19),
                ("NN-L-IOU", 2),
                ("NN-L-BPF", 2),
                ("NN-L-FIM", 25),
                ("NN-L-CANARY", 4),
                ("NN-L-NET", 17),
                ("NN-L-CHAIN", 1),
            ],
            "{name}"
        );
        let process: Vec<&str> = ids.iter().copied().filter(|id| family(id) == "R").collect();
        assert_eq!(
            process,
            vec![
                "R004_ExecFromProcSelfFd",
                "R007_CryptoMiner",
                "R006_ReverseShellTooling",
                "R009_RootExecFromUserPath",
                "R010_BinaryInWebroot",
                "R011_KernelModuleTooling",
                "R012_SetcapTooling",
                "R013_NamespaceEscapeTooling",
                "R017_ShellFromNonstandardPath",
                "R002_ExecFromDevShm",
                "R001_ExecFromTmp",
                "R003_ExecFromVarTmp",
                "R005_NetcatExec",
                "R007_CryptoMiner",
                "R008_HiddenHomeBinary",
                "R014_AtBatchScheduling",
                "R015_EncodingToolingServiceUid",
                "R016_DebuggerServiceUid",
                "R018_KernelModuleLoad",
            ],
            "{name}"
        );
        assert_eq!(
            ids.last().copied(),
            Some("NN-L-CHAIN-008_CrossPidPrivEscExfil"),
            "{name}"
        );
    }
}

/// External audit PROC-014: an io_uring ring that drives file and network
/// I/O, and a BPF program load or a handle on another program's object,
/// reach their rules through both engines — no other engine test named
/// NN-L-IOU-00x or NN-L-BPF-00x.
#[test]
fn io_uring_and_bpf_events_reach_their_rules_in_both_engines() {
    use common::wire::{BPF_CMD_FOREIGN_GET_FD, IOURING_CLASS_FILE_RW, IOURING_CLASS_NET_CONNECT};
    let ring = |created: bool, classes: u32, last_opcode: u8| Event::IoUring {
        created,
        pid: 4242,
        uid: 1000,
        comm: "loader".into(),
        classes,
        count: 32,
        last_opcode,
        sq_thread: false,
        timestamp_ns: 1,
    };
    let bpf = |cmd: u32, arg: u32| Event::BpfSyscall {
        pid: 4343,
        uid: 0,
        comm: "loader".into(),
        cmd,
        arg,
        timestamp_ns: 1,
    };
    const BPF_PROG_LOAD: u32 = 5;
    let (_tmp, lineage) = lineage_of(&[(4242, "/tmp/.x/loader"), (4343, "/tmp/.x/loader")]);
    for (name, engine) in [
        ("default_rules", RuleEngine::with_default_rules()),
        ("production", production_engine(lineage)),
    ] {
        let cases = [
            (
                ring(true, 0, 0),
                "NN-L-IOU-001_IoUringRingCreated",
                Severity::Low,
            ),
            (
                // file + network, completed by IORING_OP_CONNECT (16)
                ring(false, IOURING_CLASS_FILE_RW | IOURING_CLASS_NET_CONNECT, 16),
                "NN-L-IOU-002_IoUringFileAndNetwork",
                Severity::High,
            ),
            (
                bpf(BPF_PROG_LOAD, 7),
                "NN-L-BPF-001_BpfProgramLoaded",
                Severity::Medium,
            ),
            (
                bpf(BPF_CMD_FOREIGN_GET_FD, 42),
                "NN-L-BPF-002_BpfForeignHandleOrDetach",
                Severity::High,
            ),
        ];
        for (event, rule, severity) in cases {
            let v = engine
                .evaluate(&event)
                .unwrap_or_else(|| panic!("{name}: {rule} did not fire"));
            assert_eq!(v.rule_id, rule, "{name}");
            assert_eq!(v.severity, severity, "{name}: {rule}");
            assert_eq!(v.action, ResponseAction::Log, "{name}: {rule}");
        }
    }
}

/// External audit PROC-015 (NN-AUD-302): a `demo-tappa5` build enforces
/// only in detect-only or with `NN_ALLOW_DEMO_RULES=1`; any other build is
/// never held back.
#[test]
fn a_demo_build_enforces_only_with_the_operators_consent() {
    use super::engine::{demo_rules_gate, ALLOW_DEMO_RULES_ENV};
    // demo build, enforcement: refused without the variable, or with any
    // value other than 1
    for allow in [
        None,
        Some(""),
        Some("0"),
        Some("yes"),
        Some("true"),
        Some(" 1"),
    ] {
        let e = demo_rules_gate(true, false, allow).expect_err(&format!("{allow:?}"));
        assert!(
            e.contains("demo-tappa5") && e.contains(ALLOW_DEMO_RULES_ENV),
            "{e}"
        );
        assert!(e.contains("--detect-only"), "{e}");
    }
    // demo build: detect-only, or the operator's explicit 1
    assert_eq!(demo_rules_gate(true, false, Some("1")), Ok(()));
    assert_eq!(demo_rules_gate(true, true, None), Ok(()));
    assert_eq!(demo_rules_gate(true, true, Some("0")), Ok(()));
    // any other build starts whatever the variable says
    for allow in [None, Some("0"), Some("1")] {
        for detect_only in [false, true] {
            assert_eq!(demo_rules_gate(false, detect_only, allow), Ok(()));
        }
    }
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

/// External audit PROC-015 / PROC-014: the demo build is the production
/// engine with R901..R904 put first, not the demo rules over
/// `default_rules()` (no operator blocklist or allowlist).
#[cfg(feature = "demo-tappa5")]
#[test]
fn the_demo_engine_is_the_production_engine_behind_r901_to_r904() {
    let (_tmp, lineage) = lineage_of(&[]);
    let production = production_engine(lineage.clone()).rule_ids();
    let demo = production_engine(lineage).with_demo_tappa5_first();
    let ids = demo.rule_ids();
    assert_eq!(
        ids[..4],
        [
            "R901_TestBlockOutbound",
            "R902_TestNetworkIsolation",
            "R903_TestQuarantine",
            "R904_TestThrottle",
        ]
    );
    assert_eq!(ids[4..], production[..]);
    let v = demo
        .evaluate(&spawn("payload", "/tmp/payload.block-outbound"))
        .expect("R901");
    assert_eq!(v.rule_id, "R901_TestBlockOutbound");
    // no demo suffix: the production rule
    let v = demo
        .evaluate(&spawn("nn-test-payload", "/tmp/nn-test-payload"))
        .expect("R001");
    assert_eq!(v.rule_id, "R001_ExecFromTmp");
}

// ── External audit PROC-009 / PROC-010: no record stands in for a kill ──

/// A verdict's strength: its action (record < kill < kill the tree), then
/// its severity.
fn strength(v: &common::Verdict) -> (u8, u8) {
    let action = match v.action {
        ResponseAction::Log => 0,
        ResponseAction::KillProcessTree => 2,
        _ => 1,
    };
    (action, v.severity as u8)
}

/// Every process rule's program names, from every kind of place, as
/// root, as a service account and as a user.
fn spawn_fixtures() -> Vec<Event> {
    let comms = [
        "insmod",
        "modprobe",
        "kmod",
        "setcap",
        "nsenter",
        "unshare",
        "runc",
        "at",
        "batch",
        "base64",
        "xxd",
        "openssl",
        "gdb",
        "strace",
        "ltrace",
        "sh",
        "bash",
        "dash",
        "socat",
        "msfvenom",
        "xmrig",
        "xmrig-cleanup",
        "nc",
        "ncat",
        "payload",
        "ls",
    ];
    let dirs = [
        "/tmp/",
        "/var/tmp/",
        "/dev/shm/",
        "/home/alice/",
        "/home/alice/.hidden/",
        "/home/alice/.cache/x/",
        "/home/alice/.cache/go-build/",
        "/home/alice/.config/autostart/",
        "/var/www/html/",
        "/usr/share/nginx/html/",
        "/usr/bin/",
        "/usr/local/bin/",
        "/opt/tools/",
    ];
    let mut out = Vec::new();
    for uid in [0, 998, 1000, 61_500, 65_534, 100_032] {
        for comm in comms {
            for dir in dirs {
                out.push(spawn_as(uid, comm, &format!("{dir}{comm}")));
            }
            out.push(spawn_as(uid, comm, "/proc/self/fd/3"));
        }
    }
    out
}

/// External audit PROC-009: for every exec, the engine's verdict is the
/// strongest any single rule returns — the strongest action, then the
/// highest severity. Before, `/tmp/insmod` was R001 (Medium), not R011
/// (High), and `/home/alice/.hidden/bash` R008's record, not R017's kill.
#[test]
fn the_engine_returns_the_strongest_spawn_verdict() {
    for event in spawn_fixtures() {
        let got = RuleEngine::with_default_rules().evaluate(&event);
        let all: Vec<common::Verdict> = super::rules::default_rules()
            .iter()
            .filter_map(|r| r.evaluate(&event))
            .collect();
        let strongest = all.iter().map(strength).max();
        assert_eq!(
            got.as_ref().map(strength),
            strongest,
            "{event:?}\n  engine: {:?}\n  rules: {:?}",
            got.map(|v| v.rule_id),
            all.iter()
                .map(|v| (&v.rule_id, &v.action, v.severity))
                .collect::<Vec<_>>()
        );
    }
}

/// External audit PROC-009: a kernel-module tool run from a staging
/// directory is R011 (High, T1547.006); it was R001 (Medium).
#[test]
fn staging_kmod_tool_is_r011() {
    let engine = RuleEngine::with_default_rules();
    for path in ["/tmp/insmod", "/var/tmp/insmod"] {
        let v = engine.evaluate(&spawn("insmod", path)).expect(path);
        assert_eq!(v.rule_id, "R011_KernelModuleTooling", "{path}");
        assert_eq!(v.severity, Severity::High, "{path}");
        assert_eq!(v.action, ResponseAction::KillProcessTree, "{path}");
        assert!(v.reasoning.contains("T1547.006"), "{}", v.reasoning);
    }
    let v = engine
        .evaluate(&spawn("nsenter", "/tmp/nsenter"))
        .expect("fires");
    assert_eq!(v.rule_id, "R013_NamespaceEscapeTooling");
}

/// External audit PROC-009: the rules that only record (R014..R016, R005,
/// R008, R007's name fragments) stay behind the staging kills — the
/// audit's first proposal, every R011..R017 ahead, would have turned
/// `/tmp/at` into R014's record.
#[test]
fn a_log_rule_never_shadows_a_staging_kill() {
    let engine = RuleEngine::with_default_rules();
    for (uid, comm, path, rule) in [
        (1000, "at", "/tmp/at", "R001_ExecFromTmp"),
        (998, "base64", "/dev/shm/base64", "R002_ExecFromDevShm"),
        (998, "gdb", "/var/tmp/gdb", "R003_ExecFromVarTmp"),
        (1000, "nc", "/tmp/nc", "R001_ExecFromTmp"),
        (
            1000,
            "xmrig-cleanup",
            "/tmp/xmrig-cleanup",
            "R001_ExecFromTmp",
        ),
        (
            1000,
            "bash",
            "/home/alice/.hidden/bash",
            "R017_ShellFromNonstandardPath",
        ),
    ] {
        let v = engine
            .evaluate(&spawn_as(uid, comm, path))
            .unwrap_or_else(|| panic!("{path}"));
        assert_eq!(v.rule_id, rule, "{path}");
        assert_eq!(v.action, ResponseAction::KillProcessTree, "{path}");
    }
}

/// External audit PROC-010: in the engine, a name that only contains a
/// miner's is recorded where nothing else kills, and the distribution's
/// socat is recorded.
#[test]
fn name_fragments_and_system_socat_are_recorded() {
    let engine = RuleEngine::with_default_rules();
    for (comm, path, rule) in [
        (
            "xmrig-cleanup",
            "/usr/local/bin/xmrig-cleanup",
            "R007_CryptoMiner",
        ),
        ("socat", "/usr/bin/socat", "R006_ReverseShellTooling"),
    ] {
        let v = engine.evaluate(&spawn(comm, path)).expect(path);
        assert_eq!(v.rule_id, rule, "{path}");
        assert_eq!(v.action, ResponseAction::Log, "{path}");
        assert_eq!(v.severity, Severity::High, "{path}");
    }
    let v = engine
        .evaluate(&spawn("xmrig", "/usr/local/bin/xmrig"))
        .expect("fires");
    assert_eq!(v.action, ResponseAction::KillProcessTree);
}

// ── Lab PR 166: an exec whose executable is the payload kills the tree ──

/// The rules whose verdict is about the executed file itself: a staging
/// directory, a user-writable path, a webroot, a copied shell, an
/// offensive tool.
const PAYLOAD_IMAGE_RULES: &[&str] = &[
    "R001_ExecFromTmp",
    "R002_ExecFromDevShm",
    "R003_ExecFromVarTmp",
    "R006_ReverseShellTooling",
    "R009_RootExecFromUserPath",
    "R010_BinaryInWebroot",
    "R017_ShellFromNonstandardPath",
];

/// Lab PR 166: none of these rules kills a single process — a dropper
/// that forked before the verdict kept its child running the payload —
/// and no rule answers an exec from a staging directory with one (the
/// tool rules R011..R013 outrank R001..R003 there). Each rule is seen
/// killing a tree at least once, so the check is not vacuous.
#[test]
fn no_payload_image_rule_kills_a_single_process() {
    let mut killed_a_tree = std::collections::BTreeSet::new();
    for event in spawn_fixtures() {
        let Event::ProcessSpawn { uid, filename, .. } = &event else {
            unreachable!("spawn fixtures are spawns");
        };
        for v in super::rules::default_rules()
            .iter()
            .filter_map(|r| r.evaluate(&event))
        {
            let payload_rule = PAYLOAD_IMAGE_RULES.contains(&v.rule_id.as_str());
            if payload_rule || super::rules::is_staging_path(filename) {
                assert_ne!(
                    v.action,
                    ResponseAction::KillProcess,
                    "{} on {filename} (uid {uid})",
                    v.rule_id
                );
            }
            if payload_rule && v.action == ResponseAction::KillProcessTree {
                killed_a_tree.insert(v.rule_id);
            }
        }
    }
    let expected: std::collections::BTreeSet<String> =
        PAYLOAD_IMAGE_RULES.iter().map(|r| r.to_string()).collect();
    assert_eq!(killed_a_tree, expected);
}

/// External audit PROC-012: in the engine, an encoder or a debugger run by
/// `nobody` or by a `DynamicUser=yes` unit is recorded by R015 or R016; a
/// human user's, and a rootless container's sub-uid's, are not.
#[test]
fn nobody_and_dynamic_user_tools_are_recorded() {
    let engine = RuleEngine::with_default_rules();
    for (uid, comm, rule) in [
        (65_534, "base64", "R015_EncodingToolingServiceUid"),
        (61_500, "openssl", "R015_EncodingToolingServiceUid"),
        (65_534, "gdb", "R016_DebuggerServiceUid"),
        (61_500, "strace", "R016_DebuggerServiceUid"),
    ] {
        let path = format!("/usr/bin/{comm}");
        let v = engine
            .evaluate(&spawn_as(uid, comm, &path))
            .unwrap_or_else(|| panic!("{uid} {comm}"));
        assert_eq!(v.rule_id, rule, "{uid} {comm}");
        assert_eq!(v.action, ResponseAction::Log, "{uid} {comm}");
        assert_eq!(v.severity, Severity::Medium, "{uid} {comm}");
    }
    for uid in [0, 1000, 100_032] {
        for comm in ["base64", "gdb"] {
            let path = format!("/usr/bin/{comm}");
            assert!(
                engine.evaluate(&spawn_as(uid, comm, &path)).is_none(),
                "{uid} {comm}"
            );
        }
    }
}

/// External audit PROC-013: in the engine, a binary in `~/.cache/<dir>/`
/// or `~/.config/<dir>/` is R008's record, the named tool directories stay
/// exempt, and a shell there is still R017's kill.
#[test]
fn a_binary_under_cache_or_config_is_r008() {
    let engine = RuleEngine::with_default_rules();
    for path in [
        "/home/alice/.cache/x/payload",
        "/home/alice/.config/x/payload",
        "/home/alice/.config/systemd/user/payload",
        "/home/alice/.config/autostart/payload",
    ] {
        let v = engine.evaluate(&spawn("payload", path)).expect(path);
        assert_eq!(v.rule_id, "R008_HiddenHomeBinary", "{path}");
        assert_eq!(v.action, ResponseAction::Log, "{path}");
        assert_eq!(v.severity, Severity::Medium, "{path}");
    }
    for path in [
        "/home/alice/.cache/go-build/3f/3f9a-d/hello",
        "/home/alice/.cache/ms-playwright/chromium-1140/chrome-linux/chrome",
        "/home/alice/.config/Code/User/globalStorage/ext/install/bin/clangd",
    ] {
        assert!(engine.evaluate(&spawn("x", path)).is_none(), "{path}");
    }
    let v = engine
        .evaluate(&spawn("bash", "/home/alice/.cache/x/bash"))
        .expect("fires");
    assert_eq!(v.rule_id, "R017_ShellFromNonstandardPath");
    assert_eq!(v.action, ResponseAction::KillProcessTree);
}

/// External audit NETR-016: in the engine, one lookup of a long name with
/// a high-entropy first label (A, AAAA, a retry) is ONE record, -014's;
/// -004 no longer records the leg -014 dropped as a repeat. A name sent
/// again after the dedup window is answered again.
#[test]
fn one_lookup_of_a_tunnel_shaped_name_is_one_record() {
    let engine = RuleEngine::with_default_rules();
    let q = "a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0u1v2w3x4y5z6.exfil.example.com";
    let leg = |qtype: u16, ts_ns: u64| Event::DnsQuery {
        pid: 4321,
        uid: 1000,
        comm: "getent".into(),
        exe: Some("/usr/bin/getent".into()),
        query_name: q.into(),
        query_type: qtype,
        dns_server: [0; 16],
        family: 2,
        timestamp_ns: ts_ns,
        qname_partial: false,
    };
    let t = 1_000_000_000u64;
    let got: Vec<String> = [(1u16, t), (28, t + 5_000_000), (1, t + 130_000_000)]
        .into_iter()
        .filter_map(|(qt, ts)| engine.evaluate(&leg(qt, ts)))
        .map(|v| {
            assert_eq!(v.action, ResponseAction::Log);
            assert_eq!(v.event_pid, 4321);
            v.rule_id
        })
        .collect();
    assert_eq!(got, ["NN-L-NET-014_DnsTunnelEntropy"]);
    let again = engine
        .evaluate(&leg(1, t + 3_000_000_000))
        .expect("a lookup after the window");
    assert_eq!(again.rule_id, "NN-L-NET-014_DnsTunnelEntropy");
}

/// External audit NETR-015: in the boot-time engine (no lineage) a
/// listener record that names its image is judged on it: a staging image
/// on 8080 is recorded, a system daemon's is not.
#[test]
fn a_staging_listener_on_8080_is_recorded() {
    let engine = RuleEngine::with_default_rules();
    let listen = |exe: &str, comm: &str| {
        Event::NetListener(common::wire::NetListenerEvent {
            timestamp_ns: 100,
            family: 2,
            bind_addr: std::net::Ipv4Addr::UNSPECIFIED.into(),
            bind_port: 8080,
            proto: 6,
            pid: 4400,
            uid: 1000,
            comm: comm.into(),
            exe: Some(exe.into()),
        })
    };
    let v = engine
        .evaluate(&listen("/tmp/backdoor", "backdoor"))
        .expect("recorded");
    assert_eq!(v.rule_id, "NN-L-NET-019_WildcardListener");
    assert_eq!(v.action, ResponseAction::Log);
    assert_eq!(v.severity, Severity::Medium);
    assert!(engine
        .evaluate(&listen("/usr/sbin/lighttpd", "lighttpd"))
        .is_none());
}
