//! R13 (lab PR 271): the contract's portable half.

use nn_model::EventClass;

use super::manifest::{
    class_entries, fallbacks_and_missing, source_entries, AttachedOn, CapabilityManifest,
    DenyHooks, ProbeState, SensorEntry, SourceFacts, SourceState, MANIFEST_VERSION,
};
use super::*;

const LSM_SOURCE: SourceContract = SourceContract {
    source: "open_sensor",
    sensors: &["file_open"],
    events: &[
        EventKind::FileOpen,
        EventKind::MassWrite,
        EventKind::DefenderSignal,
    ],
    attach: "lsm:file_open",
    needs_bpf_lsm: true,
    fallbacks: &[Fallback {
        attach: "tracepoint:syscalls/sys_enter_openat",
        when: "the LSM program cannot run",
        costs: "the path read from the caller's memory",
    }],
    sync_verdict: SyncVerdict::None,
    opt_in_verdict: None,
    on_failure: FailureMode::Blind,
    on_failure_detail: "falls back to the tracepoint",
    kernel_budgets: &[],
    truncations: &[Truncation {
        field: "path component",
        max_bytes: 31,
        marked: "cut mark",
    }],
    rings: &["open_sensor"],
    probe: Some("file_open"),
    degradation_sources: &["file_open_sensor"],
    standby_for: None,
};

const STANDBY: SourceContract = SourceContract {
    source: "file_open",
    sensors: &[],
    events: &[EventKind::FileOpen],
    attach: "tracepoint:syscalls/sys_enter_openat",
    needs_bpf_lsm: false,
    fallbacks: &[],
    sync_verdict: SyncVerdict::None,
    opt_in_verdict: None,
    on_failure: FailureMode::FailClosed,
    on_failure_detail: "the start is refused",
    kernel_budgets: &[],
    truncations: &[],
    rings: &["file_open"],
    probe: Some("file_open"),
    degradation_sources: &[],
    standby_for: Some("open_sensor"),
};

const DENY: SourceContract = SourceContract {
    source: "fs_protect",
    sensors: &["deny_hooks"],
    events: &[EventKind::FsProtectDenial],
    attach: "lsm:",
    needs_bpf_lsm: true,
    fallbacks: &[],
    sync_verdict: SyncVerdict::KernelDeny {
        hooks: "16 LSM hooks",
    },
    opt_in_verdict: None,
    on_failure: FailureMode::FailClosed,
    on_failure_detail: "a missing hook refuses the start",
    kernel_budgets: &[KernelBudget {
        allows: "50 a second per CPU",
        counter: "task_denial_rate",
    }],
    truncations: &[],
    rings: &["fs_protect"],
    probe: None,
    degradation_sources: &["anti_tamper"],
    standby_for: None,
};

const DNS: SourceContract = SourceContract {
    source: "dns_query",
    sensors: &["dns", "dns_nss"],
    events: &[EventKind::DnsQuery, EventKind::DnsFlood],
    attach: "kprobe:udp_send_skb",
    needs_bpf_lsm: false,
    fallbacks: &[],
    sync_verdict: SyncVerdict::None,
    opt_in_verdict: None,
    on_failure: FailureMode::Blind,
    on_failure_detail: "",
    kernel_budgets: &[],
    truncations: &[],
    rings: &["dns"],
    probe: Some("dns"),
    degradation_sources: &["dns_sensor"],
    standby_for: None,
};

const GUARD: SourceContract = SourceContract {
    source: "exploit_guard",
    sensors: &["exploit_guard"],
    events: &[EventKind::ExploitPostcondition],
    attach: "lsm:capable",
    needs_bpf_lsm: true,
    fallbacks: &[],
    sync_verdict: SyncVerdict::None,
    opt_in_verdict: None,
    on_failure: FailureMode::Blind,
    on_failure_detail: "",
    kernel_budgets: &[],
    truncations: &[],
    rings: &["exploit_guard"],
    probe: None,
    degradation_sources: &[],
    standby_for: None,
};

fn sample() -> Vec<SourceContract> {
    vec![LSM_SOURCE, STANDBY, DENY, DNS, GUARD]
}

fn note(sensor: &str, attach: &str) -> SensorEntry {
    SensorEntry {
        sensor: sensor.into(),
        attach: attach.into(),
    }
}

fn healthy() -> SourceFacts {
    SourceFacts {
        notes: vec![
            note("file_open", "lsm:file_open (FIM observer)"),
            note("deny_hooks", "lsm: 16 of 16 deny hooks"),
            note("dns", "kprobe:udp_send_skb+udp_v6_send_skb"),
            note("dns_nss", "uprobe:libnss_resolve.so.2"),
            note("exploit_guard", "lsm:capable+bprm_check_security"),
        ],
        lsm_runs: Some(true),
        lsm_why: String::new(),
        probe: vec![
            ("file_open".into(), ProbeState::Seen),
            ("dns".into(), ProbeState::Seen),
        ],
        degradations: Vec::new(),
        terminated: Vec::new(),
    }
}

fn entry<'a>(e: &'a [manifest::SourceEntry], source: &str) -> &'a manifest::SourceEntry {
    e.iter().find(|s| s.source == source).expect(source)
}

/// The list of kinds is the enum's: each kind once, each named as its
/// `Event` variant, each with its class but the derived one.
#[test]
fn every_kind_is_listed_once_with_its_class() {
    let mut names: Vec<&str> = EventKind::ALL.iter().map(|k| k.name()).collect();
    let n = names.len();
    names.sort_unstable();
    names.dedup();
    assert_eq!(names.len(), n);
    assert_eq!(n, 19);
    for k in EventKind::ALL {
        assert_eq!(k.class().is_none(), DERIVED_KINDS.contains(k), "{k:?}");
    }
    assert_eq!(EventKind::FileBurst.class(), Some(EventClass::File));
    assert_eq!(EventKind::DnsFlood.class(), Some(EventClass::Network));
    assert_eq!(EventKind::SensorFlood.class(), Some(EventClass::Tamper));
}

/// One contract per class, in the bus's order, with the bus's queue, its
/// policy and the decision's budget; a class with no source says why.
#[test]
fn each_class_has_its_contract_from_its_sources_and_the_bus() {
    let c = class_contracts(&sample());
    let classes: Vec<EventClass> = c.iter().map(|x| x.class).collect();
    assert_eq!(classes, EventClass::ALL);
    let file = &c[2];
    assert_eq!(file.queue, "P2");
    assert_eq!(file.queue_capacity, 8192);
    assert_eq!(file.decision_budget_ms, 1000);
    assert_eq!(file.sources, ["open_sensor", "file_open"]);
    assert_eq!(file.on_failure, Some(FailureMode::Blind), "the worst");
    assert!(file
        .loss_counters
        .contains(&LossStage::BusQueue(EventClass::File)));
    assert!(!file
        .loss_counters
        .contains(&LossStage::BusQueue(EventClass::Tamper)));
    let tamper = &c[0];
    assert_eq!(tamper.queue, "P0");
    assert_eq!(tamper.decision_budget_ms, 100);
    assert!(matches!(
        tamper.sync_verdict,
        SyncVerdict::KernelDeny { .. }
    ));
    assert!(tamper.loss_counters.contains(&LossStage::KernelBudget));
    let health = &c[4];
    assert!(health.sources.is_empty());
    assert_eq!(health.on_failure, None);
    assert_eq!(health.note, Some(HEALTH_TERMS));
    let numbers: Vec<u8> = tamper.loss_counters.iter().map(|s| s.number()).collect();
    let mut sorted = numbers.clone();
    sorted.sort_unstable();
    assert_eq!(numbers, sorted);
}

/// The check fails for a kind or a class without a source, a source or an
/// attach point twice, an LSM source not on an LSM hook, a standby source
/// of nothing.
#[test]
fn the_check_names_what_has_no_entry() {
    let problems = check(&sample());
    // the sample misses most kinds and the process and network classes
    assert!(
        problems.iter().any(|p| p.contains("ProcessSpawn")),
        "{problems:?}"
    );
    assert!(
        problems.iter().any(|p| p.contains("the process class")),
        "{problems:?}"
    );
    assert!(
        !problems.iter().any(|p| p.contains("FileOpen")),
        "{problems:?}"
    );
    assert!(
        !problems.iter().any(|p| p.contains("CanaryTripped")),
        "derived"
    );
    assert!(
        !problems.iter().any(|p| p.contains("health")),
        "{problems:?}"
    );
    let mut dup = sample();
    dup.push(LSM_SOURCE);
    let p = check(&dup);
    assert!(
        p.iter().any(|x| x == "source open_sensor has two entries"),
        "{p:?}"
    );
    assert!(
        p.iter()
            .any(|x| x == "attach point file_open is in two sources"),
        "{p:?}"
    );
    let mut bad = LSM_SOURCE;
    bad.source = "bad";
    bad.sensors = &[];
    bad.attach = "kprobe:x";
    let p = check(&[bad]);
    assert!(p.iter().any(|x| x.contains("needs the BPF LSM")), "{p:?}");
    let mut orphan = STANDBY;
    orphan.standby_for = Some("nobody");
    let p = check(&[orphan]);
    assert!(p.iter().any(|x| x.contains("fallback of nobody")), "{p:?}");
    let mut derived = DNS;
    derived.events = &[EventKind::CanaryTripped];
    assert!(check(&[derived]).iter().any(|x| x.contains("derived kind")));
    let mut empty = DNS;
    empty.events = &[];
    assert!(check(&[empty]).iter().any(|x| x.contains("sends no kind")));
    // a health source would have to be taken out of the exempt list
    let mut health = DNS;
    health.events = &[];
    assert!(!check(&[health]).iter().any(|x| x.contains("take it out")));
}

/// On a healthy boot every source is on its attach point and ok, the
/// standby one inert, the probe's word on each probed one.
#[test]
fn a_healthy_boot_s_sources_are_ok() {
    let e = source_entries(&sample(), &healthy());
    let open = entry(&e, "open_sensor");
    assert_eq!(
        (open.on, open.state),
        (AttachedOn::Primary, SourceState::Ok)
    );
    assert_eq!(open.probe, Some(ProbeState::Seen));
    let tp = entry(&e, "file_open");
    assert_eq!((tp.on, tp.state), (AttachedOn::None, SourceState::Standby));
    assert_eq!(tp.probe, None);
    assert!(tp.attach.contains("inert"), "{tp:?}");
    let dns = entry(&e, "dns_query");
    assert_eq!(dns.state, SourceState::Ok);
    assert!(dns.why.is_empty(), "{dns:?}");
    assert_eq!(dns.terms.rings, ["dns"]);
    assert_eq!(dns.terms.loss_counters, [1, 3, 4, 5]);
    let (fallbacks, missing) = fallbacks_and_missing(&e, &DenyHooks::default());
    assert!(
        fallbacks.is_empty() && missing.is_empty(),
        "{fallbacks:?} {missing:?}"
    );
    let classes = class_entries(&sample(), &e);
    assert_eq!(classes[2].state, Some(SourceState::Ok));
    assert_eq!(classes[4].state, None, "health: no source");
}

/// `bpf` not in the active LSM list: every LSM source on its attach point
/// is attached and not invoked, with why; the one on its fallback is not,
/// and its standby source carries the events and takes the probe's word.
#[test]
fn without_the_bpf_lsm_the_lsm_sources_are_not_invoked() {
    let mut f = healthy();
    f.lsm_runs = Some(false);
    f.lsm_why = "bpf is not in the active LSM list (capability,apparmor)".into();
    f.notes[0] = note(
        "file_open",
        "tracepoint:syscalls/sys_enter_openat (user memory)",
    );
    f.degradations.push((
        "file_open_sensor".into(),
        "on sys_enter_openat — bpf absent".into(),
    ));
    let e = source_entries(&sample(), &f);
    let deny = entry(&e, "fs_protect");
    assert_eq!(deny.state, SourceState::AttachedNotInvoked);
    assert_eq!(
        deny.why,
        ["bpf is not in the active LSM list (capability,apparmor)"]
    );
    let guard = entry(&e, "exploit_guard");
    assert_eq!(guard.state, SourceState::AttachedNotInvoked);
    let open = entry(&e, "open_sensor");
    assert_eq!(
        (open.on, open.state),
        (AttachedOn::Fallback, SourceState::Ok)
    );
    assert_eq!(open.probe, None, "its events are the standby's");
    assert_eq!(
        open.why,
        ["file_open_sensor: on sys_enter_openat — bpf absent"]
    );
    let tp = entry(&e, "file_open");
    assert_eq!((tp.on, tp.state), (AttachedOn::Primary, SourceState::Ok));
    assert_eq!(tp.probe, Some(ProbeState::Seen));
    let (fallbacks, missing) = fallbacks_and_missing(&e, &DenyHooks::default());
    assert_eq!(
        fallbacks,
        ["open_sensor: tracepoint:syscalls/sys_enter_openat (user memory)"]
    );
    assert_eq!(missing.len(), 2, "{missing:?}");
    assert!(
        missing[0].starts_with("fs_protect: attached, not invoked"),
        "{missing:?}"
    );
    let classes = class_entries(&sample(), &e);
    assert_eq!(classes[0].state, Some(SourceState::AttachedNotInvoked));
}

/// The probe's gap, a source switched off, one not attached, an adapter
/// that ended, an auxiliary attach point missing.
#[test]
fn a_gap_an_off_a_missing_and_an_ended_source() {
    let mut f = healthy();
    f.probe[1].1 = ProbeState::Gap;
    f.notes[4] = note("exploit_guard", "off (--exploit-guard off)");
    f.notes.retain(|n| n.sensor != "dns_nss");
    f.terminated.push("open_sensor".into());
    let e = source_entries(&sample(), &f);
    let dns = entry(&e, "dns_query");
    assert_eq!(dns.state, SourceState::AttachedNotInvoked);
    assert_eq!(dns.probe, Some(ProbeState::Gap));
    assert!(
        dns.why.iter().any(|w| w == "dns_nss: not attached"),
        "{dns:?}"
    );
    assert!(
        dns.why.iter().any(|w| w.contains("telemetry_gap")),
        "{dns:?}"
    );
    let guard = entry(&e, "exploit_guard");
    assert_eq!(
        (guard.on, guard.state),
        (AttachedOn::None, SourceState::DisabledByAdmin)
    );
    let open = entry(&e, "open_sensor");
    assert_eq!(open.state, SourceState::AdapterTerminated);
    let mut f = healthy();
    f.notes.retain(|n| n.sensor != "deny_hooks");
    f.notes[3] = note("exploit_guard", "not attached: no BTF");
    let e = source_entries(&sample(), &f);
    assert_eq!(entry(&e, "fs_protect").state, SourceState::Unavailable);
    assert_eq!(entry(&e, "fs_protect").attach, "not attached");
    assert_eq!(entry(&e, "exploit_guard").state, SourceState::Unavailable);
    let classes = class_entries(&sample(), &e);
    assert_eq!(
        classes[0].state,
        Some(SourceState::Unavailable),
        "the worst"
    );
    // the probe pending until its first round
    let mut f = healthy();
    f.probe[0].1 = ProbeState::Pending;
    let e = source_entries(&sample(), &f);
    assert_eq!(entry(&e, "open_sensor").state, SourceState::Ok);
    assert_eq!(entry(&e, "open_sensor").probe, Some(ProbeState::Pending));
    // the standby source in charge, then its probe's gap and its end
    let mut f = healthy();
    f.notes[0] = note(
        "file_open",
        "tracepoint:syscalls/sys_enter_openat (user memory)",
    );
    f.probe[0].1 = ProbeState::Gap;
    f.terminated.push("file_open".into());
    let e = source_entries(&sample(), &f);
    assert_eq!(
        entry(&e, "open_sensor").state,
        SourceState::Ok,
        "not its gap"
    );
    assert_eq!(entry(&e, "file_open").state, SourceState::AdapterTerminated);
}

fn manifest_of(f: &SourceFacts) -> CapabilityManifest {
    let sources = source_entries(&sample(), f);
    let classes = class_entries(&sample(), &sources);
    let (fallbacks, missing) = fallbacks_and_missing(&sources, &DenyHooks::default());
    let mut m = CapabilityManifest {
        manifest_version: MANIFEST_VERSION,
        agent_version: "0.0.1".into(),
        kernel: "6.8.0".into(),
        btf: true,
        btf_offsets_resolved: 40,
        btf_offsets_drifted: 0,
        btf_offsets_absent: Vec::new(),
        active_lsms: Some("capability,bpf".into()),
        bpf_lsm: "active".into(),
        deny_hooks: DenyHooks::default(),
        deny_self_test: "denied".into(),
        bpf_guard: "enforce".into(),
        sensors: f.notes.clone(),
        host_hardening: Vec::new(),
        detect_only: false,
        degradations: vec!["b".into(), "a".into()],
        trust_level: 3,
        trust_reasons: Vec::new(),
        contract_version: CONTRACT_VERSION,
        sources,
        classes,
        fallbacks,
        missing,
        content: Vec::new(),
        telemetry_probe: "every 60 s".into(),
        settled: false,
        revision: 0,
        hash: String::new(),
        previous_hash: None,
        change: Vec::new(),
    };
    m.settled = m.probe_settled();
    m
}

/// The hash is of what the agent runs with: not of the revision's fields,
/// not of the order of the lists without one; a capability that changes
/// changes it.
#[test]
fn the_content_hash_is_the_capabilities() {
    let m = manifest_of(&healthy());
    let h = m.content_hash();
    assert_eq!(h.len(), 64);
    let mut r = m.clone();
    r.revision = 7;
    r.hash = h.clone();
    r.previous_hash = Some("x".into());
    r.change = vec!["y".into()];
    r.degradations.reverse();
    r.sensors.reverse();
    assert_eq!(r.content_hash(), h);
    let mut f = healthy();
    f.probe[1].1 = ProbeState::Gap;
    assert_ne!(manifest_of(&f).content_hash(), h);
    let mut t = m.clone();
    t.trust_level = 2;
    assert_ne!(t.content_hash(), h);
    assert!(m.settled);
    let mut f = healthy();
    f.probe[0].1 = ProbeState::Pending;
    assert!(!manifest_of(&f).settled);
}

/// What changed between two revisions, one line each.
#[test]
fn a_change_is_named_line_by_line() {
    let before = manifest_of(&healthy());
    let mut f = healthy();
    f.probe[1].1 = ProbeState::Gap;
    f.notes[0] = note(
        "file_open",
        "tracepoint:syscalls/sys_enter_openat (user memory)",
    );
    let mut after = manifest_of(&f);
    after.degradations.push("dns_sensor: x".into());
    after.trust_level = 2;
    after.content.push("netflow-blocklist: built-in".into());
    let lines = after.changes_from(&before);
    assert!(
        lines.contains(&"source dns_query: ok on its attach point (kprobe:udp_send_skb+udp_v6_send_skb) → attached, not invoked on its attach point (kprobe:udp_send_skb+udp_v6_send_skb)".to_string()),
        "{lines:#?}"
    );
    assert!(lines.contains(&"source dns_query: telemetry probe seen → gap".to_string()));
    assert!(lines
        .iter()
        .any(|l| l.starts_with("source open_sensor: ok on its attach point")));
    assert!(lines
        .iter()
        .any(|l| l.starts_with("source file_open: standby on nothing")));
    assert!(lines.contains(&"degradation + dns_sensor: x".to_string()));
    assert!(lines.contains(&"content + netflow-blocklist: built-in".to_string()));
    assert!(lines.contains(&"trust level L3 → L2".to_string()));
    assert!(before.changes_from(&before).is_empty());
    let mut back = before.clone();
    back.degradations.clear();
    assert!(back
        .changes_from(&before)
        .contains(&"degradation - a".to_string()));
    let mut other = before.clone();
    other.kernel = "6.9".into();
    assert_eq!(
        other.changes_from(&before),
        ["the manifest changed (nn-admin capabilities shows it)"]
    );
}

/// The manifest's JSON reads back (the agent's signed row is it).
#[test]
fn the_manifest_round_trips() {
    let m = manifest_of(&healthy());
    let v = serde_json::to_value(&m).unwrap();
    assert_eq!(v["sources"][0]["state"], "ok");
    assert_eq!(v["sources"][0]["on"], "primary");
    assert_eq!(v["sources"][0]["probe"], "seen");
    assert_eq!(v["sources"][0]["terms"]["on_failure"], "blind");
    assert_eq!(v["classes"][2]["class"], "file");
    assert!(v.get("previous_hash").is_none() && v.get("change").is_none());
    let back: CapabilityManifest = serde_json::from_value(v).unwrap();
    assert_eq!(back, m);
    // a row of lab PR 218 (no R13 field) still reads
    let mut old = serde_json::to_value(&m).unwrap();
    for k in [
        "contract_version",
        "sources",
        "classes",
        "fallbacks",
        "missing",
        "content",
        "telemetry_probe",
        "settled",
        "revision",
        "hash",
    ] {
        old.as_object_mut().unwrap().remove(k);
    }
    let back: CapabilityManifest = serde_json::from_value(old).unwrap();
    assert!(back.sources.is_empty() && back.revision == 0);
}
