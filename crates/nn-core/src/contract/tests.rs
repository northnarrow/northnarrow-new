//! R13 (lab PR 271): the contract's portable half.

use nn_model::EventClass;

use super::manifest::{
    class_entries, fallbacks_and_missing, source_entries, AttachedOn, CapabilityManifest,
    DenyHooks, Evidence, HostCheck, ProbeState, SensorEntry, SourceFacts, SourceState, Took,
    WorkerEntry, WorkerState, MANIFEST_VERSION,
};
use super::*;

const OPEN_LSM: &str = "lsm:file_open (FIM observer)";
const OPEN_TP: &str = "tracepoint:syscalls/sys_enter_openat (user memory)";

const LSM_SOURCE: SourceContract = SourceContract {
    source: "open_sensor",
    sensors: &["file_open"],
    events: &[
        EventKind::FileOpen,
        EventKind::MassWrite,
        EventKind::DefenderSignal,
    ],
    attach: OPEN_LSM,
    also: &[],
    needs_bpf_lsm: true,
    lsm_part: None,
    fallbacks: &[Fallback {
        attach: OPEN_TP,
        when: "the LSM program cannot run",
        costs: "the path read from the caller's memory",
        equivalent: false,
        lost: &[EventKind::MassWrite, EventKind::DefenderSignal],
    }],
    sync_verdict: SyncVerdict::None,
    opt_in: None,
    on_failure: FailureMode::Blind,
    on_failure_detail: "falls back to the tracepoint",
    kernel_budgets: &[],
    overhead: &[],
    truncations: &[Truncation {
        field: "path component",
        max_bytes: 31,
        marked: "cut mark",
    }],
    rings: &["open_sensor"],
    probe: Some("file_open"),
    self_tested: false,
    degradation_sources: &["file_open_sensor"],
    standby_for: None,
};

const STANDBY: SourceContract = SourceContract {
    source: "file_open",
    sensors: &[],
    events: &[EventKind::FileOpen],
    attach: OPEN_TP,
    also: &[],
    needs_bpf_lsm: false,
    lsm_part: None,
    fallbacks: &[],
    sync_verdict: SyncVerdict::None,
    opt_in: None,
    on_failure: FailureMode::FailClosed,
    on_failure_detail: "the start is refused",
    kernel_budgets: &[],
    overhead: &[],
    truncations: &[],
    rings: &["file_open"],
    probe: Some("file_open"),
    self_tested: false,
    degradation_sources: &[],
    standby_for: Some("open_sensor"),
};

const DENY: SourceContract = SourceContract {
    source: "fs_protect",
    sensors: &["deny_hooks"],
    events: &[EventKind::FsProtectDenial],
    attach: "lsm:deny hooks",
    also: &[],
    needs_bpf_lsm: true,
    lsm_part: None,
    fallbacks: &[],
    sync_verdict: SyncVerdict::KernelDeny {
        hooks: "16 LSM hooks",
    },
    opt_in: None,
    on_failure: FailureMode::FailClosed,
    on_failure_detail: "a missing hook refuses the start",
    kernel_budgets: &[KernelBudget {
        allows: "50 a second per CPU",
        counter: "task_denial_rate",
    }],
    overhead: &[],
    truncations: &[],
    rings: &["fs_protect"],
    probe: None,
    self_tested: true,
    degradation_sources: &["anti_tamper"],
    standby_for: None,
};

const DNS_SKB: &str = "kprobe:udp_send_skb+udp_v6_send_skb";
const DNS_SENDMSG: &str = "kprobe:udp_sendmsg (user memory, IPv4 only)";

const DNS: SourceContract = SourceContract {
    source: "dns_query",
    sensors: &["dns", "dns_nss"],
    events: &[EventKind::DnsQuery, EventKind::DnsFlood],
    attach: DNS_SKB,
    also: &[],
    needs_bpf_lsm: false,
    lsm_part: None,
    fallbacks: &[Fallback {
        attach: DNS_SENDMSG,
        when: "--dns-sensor sendmsg",
        costs: "the name read from the sender's memory; IPv4 only",
        equivalent: false,
        lost: &[],
    }],
    sync_verdict: SyncVerdict::None,
    opt_in: None,
    on_failure: FailureMode::Blind,
    on_failure_detail: "",
    kernel_budgets: &[],
    overhead: &[],
    truncations: &[],
    rings: &["dns"],
    probe: Some("dns"),
    self_tested: false,
    degradation_sources: &["dns_sensor"],
    standby_for: None,
};

const GUARD_LITE: &str = "lsm:capable, fentry:commit_creds (lite)";
const GUARD_STRICT: &str = "fentry:commit_creds, raw_tp:sys_exit (strict)";

const GUARD: SourceContract = SourceContract {
    source: "exploit_guard",
    sensors: &["exploit_guard"],
    events: &[EventKind::ExploitPostcondition],
    attach: GUARD_LITE,
    also: &[],
    needs_bpf_lsm: true,
    lsm_part: Some("its fentry hooks run"),
    fallbacks: &[Fallback {
        attach: GUARD_STRICT,
        when: "--exploit-guard strict",
        costs: "more overhead",
        equivalent: true,
        lost: &[],
    }],
    sync_verdict: SyncVerdict::None,
    opt_in: None,
    on_failure: FailureMode::Blind,
    on_failure_detail: "",
    kernel_budgets: &[],
    overhead: &[],
    truncations: &[],
    rings: &["exploit_guard"],
    probe: None,
    self_tested: false,
    degradation_sources: &[],
    standby_for: None,
};

const CONNECT: SourceContract = SourceContract {
    source: "tcp_connect",
    sensors: &["tcp_connect"],
    events: &[EventKind::TcpConnect],
    attach: "kprobe:tcp_v4_connect+tcp_v6_connect",
    also: &[],
    needs_bpf_lsm: false,
    lsm_part: None,
    fallbacks: &[],
    sync_verdict: SyncVerdict::None,
    opt_in: Some(OptIn {
        verdict: SyncVerdict::KernelDeny {
            hooks: "LSM socket_connect",
        },
        when: "--net-connect-deny",
        key: "net_connect_deny",
        needs_bpf_lsm: true,
    }),
    on_failure: FailureMode::Blind,
    on_failure_detail: "",
    kernel_budgets: &[],
    overhead: &[],
    truncations: &[],
    rings: &["tcp_connect"],
    probe: None,
    self_tested: false,
    degradation_sources: &[],
    standby_for: None,
};

fn sample() -> Vec<SourceContract> {
    vec![LSM_SOURCE, STANDBY, DENY, DNS, GUARD, CONNECT]
}

fn note(sensor: &str, attach: &str, took: Took) -> SensorEntry {
    SensorEntry {
        sensor: sensor.into(),
        attach: attach.into(),
        took: Some(took),
    }
}

fn whole(sensor: &str, attach: &str) -> SensorEntry {
    note(sensor, attach, Took::Whole)
}

fn set(f: &mut SourceFacts, n: SensorEntry) {
    f.notes.retain(|x| x.sensor != n.sensor);
    f.notes.push(n);
}

fn healthy() -> SourceFacts {
    SourceFacts {
        notes: vec![
            whole("file_open", OPEN_LSM),
            whole("deny_hooks", "lsm:deny hooks"),
            whole("dns", DNS_SKB),
            whole("dns_nss", "uprobe:libnss_resolve.so.2"),
            whole("exploit_guard", GUARD_LITE),
            whole("tcp_connect", "kprobe:tcp_v4_connect+tcp_v6_connect"),
        ],
        lsm_runs: Some(true),
        lsm_why: String::new(),
        probe: vec![
            ("file_open".into(), ProbeState::Seen),
            ("dns".into(), ProbeState::Seen),
        ],
        degradations: Vec::new(),
        terminated: Vec::new(),
        running: None,
        opt_ins: Vec::new(),
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
/// of nothing, a fallback said equivalent that loses events or loses a kind
/// the source does not send, an LSM part of a source without LSM programs.
#[test]
fn the_check_names_what_has_no_entry() {
    let problems = check(&sample());
    // the sample misses most kinds and the process class
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
    assert!(
        !problems.iter().any(|p| p.contains("fallback")),
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
    bad.fallbacks = &[];
    let p = check(&[bad]);
    assert!(p.iter().any(|x| x.contains("needs the BPF LSM")), "{p:?}");
    let mut orphan = STANDBY;
    orphan.standby_for = Some("nobody");
    let p = check(&[orphan]);
    assert!(p.iter().any(|x| x.contains("fallback of nobody")), "{p:?}");
    let mut derived = DNS;
    derived.events = &[EventKind::CanaryTripped];
    derived.fallbacks = &[];
    assert!(check(&[derived]).iter().any(|x| x.contains("derived kind")));
    let mut empty = DNS;
    empty.events = &[];
    empty.fallbacks = &[];
    assert!(check(&[empty]).iter().any(|x| x.contains("sends no kind")));
    let mut liar = LSM_SOURCE;
    liar.fallbacks = &[Fallback {
        attach: OPEN_TP,
        when: "x",
        costs: "y",
        equivalent: true,
        lost: &[EventKind::MassWrite],
    }];
    assert!(check(&[liar])
        .iter()
        .any(|x| x.contains("is equivalent and loses events")));
    let mut stranger = LSM_SOURCE;
    stranger.fallbacks = &[Fallback {
        attach: OPEN_TP,
        when: "x",
        costs: "y",
        equivalent: false,
        lost: &[EventKind::NetFlow],
    }];
    assert!(check(&[stranger])
        .iter()
        .any(|x| x.contains("loses a kind the source does not send")));
    let mut part = DNS;
    part.lsm_part = Some("x");
    assert!(check(&[part])
        .iter()
        .any(|x| x.contains("part of it without the BPF LSM")));
}

/// On a healthy boot every source is on its attach point and ok, the
/// standby one inert, the probe's word on each probed one; what each `ok`
/// rests on is said.
#[test]
fn a_healthy_boot_s_sources_are_ok() {
    let e = source_entries(&sample(), &healthy());
    let open = entry(&e, "open_sensor");
    assert_eq!(
        (open.on, open.state),
        (AttachedOn::Primary, SourceState::Ok)
    );
    assert_eq!(open.probe, Some(ProbeState::Seen));
    assert_eq!(open.evidence, Evidence::Probe);
    let tp = entry(&e, "file_open");
    assert_eq!((tp.on, tp.state), (AttachedOn::None, SourceState::Standby));
    assert_eq!(tp.probe, None);
    assert!(tp.attach.contains("inert"), "{tp:?}");
    let dns = entry(&e, "dns_query");
    assert_eq!(dns.state, SourceState::Ok);
    assert!(dns.why.is_empty(), "{dns:?}");
    let terms = dns.terms.as_ref().unwrap();
    assert_eq!(terms.rings, ["dns"]);
    assert_eq!(terms.loss_counters, [1, 3, 4, 5]);
    assert_eq!(entry(&e, "fs_protect").evidence, Evidence::SelfTest);
    assert_eq!(entry(&e, "tcp_connect").evidence, Evidence::AttachOnly);
    let (fallbacks, missing) = fallbacks_and_missing(&e, &DenyHooks::default());
    assert!(
        fallbacks.is_empty() && missing.is_empty(),
        "{fallbacks:?} {missing:?}"
    );
    let classes = class_entries(&sample(), &e);
    assert_eq!(classes[2].state, Some(SourceState::Ok));
    assert_eq!(classes[4].state, None, "health: no source");
    // the self-test not run (inconclusive): not its evidence
    let mut f = healthy();
    f.lsm_runs = None;
    let e = source_entries(&sample(), &f);
    assert_eq!(entry(&e, "fs_protect").evidence, Evidence::AttachOnly);
}

/// The review of #479, X1: `ok` only for the attach point whole, noted so
/// and exactly; part of it is `partial` with what is missing; a note the
/// contract does not know, or one that does not say how it attached, is
/// `unknown` — never `ok`.
#[test]
fn a_partial_or_an_unknown_attach_is_never_ok() {
    // 12 of 16 deny hooks
    let mut f = healthy();
    set(
        &mut f,
        note(
            "deny_hooks",
            "lsm:deny hooks",
            Took::Partial {
                missing: vec!["inode_link: no BTF".into(), "file_ioctl: refused".into()],
            },
        ),
    );
    let e = source_entries(&sample(), &f);
    let deny = entry(&e, "fs_protect");
    assert_eq!(
        (deny.on, deny.state),
        (AttachedOn::Primary, SourceState::Partial)
    );
    assert_eq!(
        deny.why,
        ["not attached: inode_link: no BTF; file_ioctl: refused"]
    );
    // the dns sensor without IPv6 (dns_sensor.rs's note)
    let mut f = healthy();
    set(
        &mut f,
        note(
            "dns",
            "kprobe:udp_send_skb",
            Took::Partial {
                missing: vec!["udp_v6_send_skb: IPv6 resolvers not observed".into()],
            },
        ),
    );
    let e = source_entries(&sample(), &f);
    assert_eq!(entry(&e, "dns_query").state, SourceState::Partial);
    // a failure worded as nothing the contract knows
    let mut f = healthy();
    set(
        &mut f,
        note(
            "exploit_guard",
            "refused by the verifier: E2BIG",
            Took::Fallback,
        ),
    );
    let e = source_entries(&sample(), &f);
    let g = entry(&e, "exploit_guard");
    assert_eq!(g.state, SourceState::Unknown);
    assert!(g.why[0].contains("does not know"), "{g:?}");
    // "whole", with a note that is not the attach point: not believed
    let mut f = healthy();
    set(&mut f, whole("deny_hooks", "lsm:deny hooks and more"));
    let e = source_entries(&sample(), &f);
    assert_eq!(entry(&e, "fs_protect").state, SourceState::Unknown);
    // a prefix of it, the review's case, is no match either
    let mut f = healthy();
    set(&mut f, whole("dns", "kprobe:udp_send_skb"));
    let e = source_entries(&sample(), &f);
    assert_eq!(entry(&e, "dns_query").state, SourceState::Unknown);
    // a note that does not say how it attached
    let mut f = healthy();
    set(
        &mut f,
        SensorEntry {
            sensor: "tcp_connect".into(),
            attach: "kprobe:tcp_v4_connect+tcp_v6_connect".into(),
            took: None,
        },
    );
    let e = source_entries(&sample(), &f);
    let t = entry(&e, "tcp_connect");
    assert_eq!((t.on, t.state), (AttachedOn::None, SourceState::Unknown));
    // an auxiliary attach point part-attached is said
    let mut f = healthy();
    set(
        &mut f,
        note(
            "dns_nss",
            "uprobe:libnss_resolve.so.2",
            Took::Partial {
                missing: vec!["gethostbyname3_r".into()],
            },
        ),
    );
    let e = source_entries(&sample(), &f);
    let dns = entry(&e, "dns_query");
    assert_eq!(dns.state, SourceState::Ok);
    assert!(
        dns.why[0].contains("not attached: gethostbyname3_r"),
        "{dns:?}"
    );
}

/// The review of #479, K5: the deny and observe hooks not attached are in
/// `missing`, each its line.
#[test]
fn the_hooks_not_attached_are_missing() {
    let deny = DenyHooks {
        expected: 16,
        attached: 14,
        missing: vec!["inode_link: no BTF".into(), "pin root: linked".into()],
        observe_missing: vec!["bpf_syscall_observe: refused".into()],
    };
    let (_, missing) = fallbacks_and_missing(&source_entries(&sample(), &healthy()), &deny);
    assert_eq!(
        missing,
        [
            "deny hook: inode_link: no BTF",
            "deny hook: pin root: linked",
            "observe hook: bpf_syscall_observe: refused",
        ]
    );
}

/// A fallback that covers less is `partial`, naming what it costs and the
/// kinds of events it no longer sends; an equivalent one is `ok`.
#[test]
fn a_fallback_is_ok_only_when_equivalent() {
    let mut f = healthy();
    set(&mut f, note("file_open", OPEN_TP, Took::Fallback));
    let e = source_entries(&sample(), &f);
    let open = entry(&e, "open_sensor");
    assert_eq!(
        (open.on, open.state),
        (AttachedOn::Fallback, SourceState::Partial)
    );
    assert_eq!(
        open.why,
        [
            "on its fallback: the path read from the caller's memory",
            "events not sent on it: MassWrite, DefenderSignal",
        ]
    );
    let (fallbacks, missing) = fallbacks_and_missing(&e, &DenyHooks::default());
    assert_eq!(fallbacks, [format!("open_sensor: {OPEN_TP}")]);
    assert!(
        missing[0].starts_with("open_sensor: partial"),
        "{missing:?}"
    );
    let classes = class_entries(&sample(), &e);
    assert_eq!(
        classes[2].state,
        Some(SourceState::Partial),
        "the file class without its sources"
    );
    let mut f = healthy();
    set(&mut f, note("exploit_guard", GUARD_STRICT, Took::Fallback));
    let e = source_entries(&sample(), &f);
    let g = entry(&e, "exploit_guard");
    assert_eq!((g.on, g.state), (AttachedOn::Fallback, SourceState::Ok));
    let mut f = healthy();
    set(&mut f, note("dns", DNS_SENDMSG, Took::Fallback));
    let e = source_entries(&sample(), &f);
    let dns = entry(&e, "dns_query");
    assert_eq!(dns.state, SourceState::Partial);
    assert_eq!(dns.why.len(), 1, "no kind lost: {dns:?}");
}

/// `bpf` not in the active LSM list: every LSM source on its attach point
/// is attached and not invoked, with why — or partial when part of it runs
/// —; the one on its fallback is not judged by it, and its standby source
/// carries the events and takes the probe's word; an opt-in that needs the
/// BPF LSM is said inert when it is configured.
#[test]
fn without_the_bpf_lsm_the_lsm_sources_are_not_invoked() {
    let mut f = healthy();
    f.lsm_runs = Some(false);
    f.lsm_why = "bpf is not in the active LSM list (capability,apparmor)".into();
    set(&mut f, note("file_open", OPEN_TP, Took::Fallback));
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
    assert_eq!(
        deny.evidence,
        Evidence::AttachOnly,
        "the self-test did not refuse"
    );
    let guard = entry(&e, "exploit_guard");
    assert_eq!(guard.state, SourceState::Partial);
    assert_eq!(
        guard.why,
        ["bpf is not in the active LSM list (capability,apparmor) — its fentry hooks run"]
    );
    let open = entry(&e, "open_sensor");
    assert_eq!(
        (open.on, open.state),
        (AttachedOn::Fallback, SourceState::Partial)
    );
    assert_eq!(open.probe, None, "its events are the standby's");
    assert_eq!(
        open.why[0],
        "file_open_sensor: on sys_enter_openat — bpf absent"
    );
    let tp = entry(&e, "file_open");
    assert_eq!((tp.on, tp.state), (AttachedOn::Primary, SourceState::Ok));
    assert_eq!(tp.probe, Some(ProbeState::Seen));
    assert_eq!(tp.evidence, Evidence::Probe);
    assert_eq!(
        entry(&e, "tcp_connect").state,
        SourceState::Ok,
        "no opt-in set"
    );
    let classes = class_entries(&sample(), &e);
    assert_eq!(classes[0].state, Some(SourceState::AttachedNotInvoked));
    // the connect deny configured: inert, said
    f.opt_ins.push("net_connect_deny".into());
    let e = source_entries(&sample(), &f);
    let t = entry(&e, "tcp_connect");
    assert_eq!(t.state, SourceState::Partial);
    assert_eq!(
        t.why,
        ["the opt-in --net-connect-deny is configured and does not run: bpf is not in the active \
          LSM list (capability,apparmor)"]
    );
    // configured, with the BPF LSM running: nothing to say
    let mut f = healthy();
    f.opt_ins.push("net_connect_deny".into());
    let e = source_entries(&sample(), &f);
    assert_eq!(entry(&e, "tcp_connect").state, SourceState::Ok);
}

/// The probe's gap and its stale word, a source switched off, one not
/// attached, an adapter that ended, an auxiliary attach point missing.
#[test]
fn a_gap_a_stale_word_an_off_a_missing_and_an_ended_source() {
    let mut f = healthy();
    f.probe[1].1 = ProbeState::Gap;
    set(
        &mut f,
        note("exploit_guard", "off (--exploit-guard off)", Took::Off),
    );
    f.notes.retain(|n| n.sensor != "dns_nss");
    f.terminated.push("open_sensor".into());
    let e = source_entries(&sample(), &f);
    let dns = entry(&e, "dns_query");
    assert_eq!(dns.state, SourceState::AttachedNotInvoked);
    assert_eq!(dns.probe, Some(ProbeState::Gap));
    assert_eq!(dns.evidence, Evidence::AttachOnly);
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
    // the review of #479, X2: no round ended for two intervals
    let mut f = healthy();
    f.probe = vec![
        ("file_open".into(), ProbeState::Stale),
        ("dns".into(), ProbeState::Stale),
    ];
    let e = source_entries(&sample(), &f);
    let dns = entry(&e, "dns_query");
    assert_eq!(dns.state, SourceState::Unknown);
    assert_eq!(dns.evidence, Evidence::AttachOnly);
    assert!(dns.why[0].contains("is stale"), "{dns:?}");
    assert_eq!(entry(&e, "open_sensor").state, SourceState::Unknown);
    let mut f = healthy();
    f.notes.retain(|n| n.sensor != "deny_hooks");
    set(
        &mut f,
        note("exploit_guard", "not attached: no BTF", Took::Absent),
    );
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
    assert_eq!(entry(&e, "open_sensor").evidence, Evidence::AttachOnly);
    // the standby source in charge with its probe's gap: not invoked, why
    let mut f = healthy();
    set(&mut f, note("file_open", OPEN_TP, Took::Fallback));
    f.probe[0].1 = ProbeState::Gap;
    let e = source_entries(&sample(), &f);
    let tp = entry(&e, "file_open");
    assert_eq!(tp.state, SourceState::AttachedNotInvoked);
    assert_eq!(tp.probe, Some(ProbeState::Gap));
    assert!(tp.why.iter().any(|w| w.contains("telemetry_gap")), "{tp:?}");
    // the standby source in charge, then its probe's gap and its end
    let mut f = healthy();
    set(&mut f, note("file_open", OPEN_TP, Took::Fallback));
    f.probe[0].1 = ProbeState::Gap;
    f.terminated.push("file_open".into());
    let e = source_entries(&sample(), &f);
    assert_eq!(
        entry(&e, "open_sensor").state,
        SourceState::Partial,
        "its fallback's, not its gap"
    );
    assert_eq!(entry(&e, "file_open").state, SourceState::AdapterTerminated);
}

/// A source on its attach point whose pump or drain the start did not
/// register reads nothing: unavailable, with why; one on a fallback, off or
/// standby is not judged by it, and an unknown list judges nothing.
#[test]
fn a_source_without_its_pump_is_unavailable() {
    let mut f = healthy();
    f.running = Some(vec!["fs_protect".into(), "exploit_guard".into()]);
    let e = source_entries(&sample(), &f);
    let dns = entry(&e, "dns_query");
    assert_eq!(dns.state, SourceState::Unavailable);
    assert!(
        dns.why.iter().any(|w| w.contains("did not start")),
        "{dns:?}"
    );
    assert_eq!(entry(&e, "fs_protect").state, SourceState::Ok);
    assert_eq!(entry(&e, "file_open").state, SourceState::Standby);
    set(&mut f, note("file_open", OPEN_TP, Took::Fallback));
    let e = source_entries(&sample(), &f);
    assert_eq!(
        entry(&e, "open_sensor").state,
        SourceState::Partial,
        "on its fallback: not unavailable"
    );
    let mut f = healthy();
    f.running = None;
    let e = source_entries(&sample(), &f);
    assert_eq!(entry(&e, "dns_query").state, SourceState::Ok);
}

/// A known fallback is matched exactly, even when it begins as the attach
/// point does (the process-spawn tracepoint without its probes).
#[test]
fn a_fallback_that_begins_as_the_attach_point_is_a_fallback() {
    let mut spawn = DNS;
    spawn.source = "process_spawn";
    spawn.sensors = &["process_spawn"];
    spawn.attach = "tracepoint:sched/sched_process_exec";
    spawn.fallbacks = &[Fallback {
        attach: "tracepoint:sched/sched_process_exec (no standard-stream probes: R020 off)",
        when: "the verifier refuses the probes",
        costs: "R020 off",
        equivalent: false,
        lost: &[],
    }];
    spawn.probe = None;
    let mut f = healthy();
    f.notes.push(note(
        "process_spawn",
        "tracepoint:sched/sched_process_exec (no standard-stream probes: R020 off)",
        Took::Fallback,
    ));
    let e = source_entries(&[spawn], &f);
    assert_eq!(
        (e[0].on, e[0].state),
        (AttachedOn::Fallback, SourceState::Partial)
    );
    f.notes.pop();
    f.notes.push(whole(
        "process_spawn",
        "tracepoint:sched/sched_process_exec",
    ));
    let e = source_entries(&[spawn], &f);
    assert_eq!(
        (e[0].on, e[0].state),
        (AttachedOn::Primary, SourceState::Ok)
    );
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
        host_hardening: vec![HostCheck {
            id: "lockdown".into(),
            status: "warn".into(),
            value: "[none]".into(),
        }],
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
        workers: Vec::new(),
        export: None,
        telemetry_probe: "every 60 s".into(),
        settled: false,
        contract_hash: String::new(),
        revision: 0,
        hash: String::new(),
        previous_hash: None,
        change: Vec::new(),
        changes: 0,
        unsigned_changes: 0,
    };
    m.settled = m.probe_settled();
    m.contract_hash = m.contract_hash_now();
    m
}

/// The re-check of #479: a worse state (its row signed at once) told from
/// a better or an equal one (its row waits for the minute).
#[test]
fn a_worse_state_is_told_from_a_better_one() {
    let m = manifest_of(&healthy());
    assert!(!m.worsens_from(&m), "the same");
    let mut r = m.clone();
    r.degradations.reverse();
    r.revision = 4;
    assert!(!r.worsens_from(&m), "an order, a revision: not a state");
    // the probe's gap, then its stale word: worse each; back: better
    let mut f = healthy();
    f.probe[1].1 = ProbeState::Gap;
    let gap = manifest_of(&f);
    assert!(gap.worsens_from(&m));
    assert!(!m.worsens_from(&gap), "back");
    f.probe[1].1 = ProbeState::Stale;
    let stale = manifest_of(&f);
    assert!(stale.worsens_from(&m));
    assert!(
        stale.worsens_from(&gap),
        "the probe stopped: worse than a gap"
    );
    assert!(!m.worsens_from(&stale), "back");
    // the probe's word alone, on a source whose state is already not
    // invoked (the LSM not running)
    let mut f = healthy();
    f.lsm_runs = Some(false);
    let off = manifest_of(&f);
    f.probe[0].1 = ProbeState::Gap;
    let off_gap = manifest_of(&f);
    assert_eq!(
        entry(&off.sources, "file_open").state.rank(),
        entry(&off_gap.sources, "file_open").state.rank(),
        "the same state"
    );
    assert!(off_gap.worsens_from(&off), "its word turned gap");
    // a source on a lesser fallback: worse; back on its attach point: not
    let mut f = healthy();
    set(&mut f, note("dns", DNS_SENDMSG, Took::Fallback));
    let partial = manifest_of(&f);
    assert!(partial.worsens_from(&m));
    assert!(!m.worsens_from(&partial));
    // a source gone; a new source not ok; a new one ok is not worse
    let mut gone = m.clone();
    gone.sources.pop();
    assert!(gone.worsens_from(&m));
    assert!(!m.worsens_from(&gone), "it came back ok");
    let mut back_unknown = m.clone();
    back_unknown.sources.last_mut().unwrap().state = SourceState::Unknown;
    assert!(
        back_unknown.worsens_from(&gone),
        "it came back, not ok (nothing else said it)"
    );
    // one line new in each list, fewer deny hooks, a lower trust level
    let worse: [fn(&mut CapabilityManifest); 9] = [
        |x| x.missing.push("new".into()),
        |x| x.fallbacks.push("new".into()),
        |x| x.degradations.push("new".into()),
        |x| x.content.push("new".into()),
        |x| x.deny_hooks.missing.push("new".into()),
        |x| x.deny_hooks.observe_missing.push("new".into()),
        |x| x.deny_hooks.attached = x.deny_hooks.attached.saturating_sub(1),
        |x| x.trust_level -= 1,
        |x| x.sources[0].state = SourceState::Unknown,
    ];
    let mut base = m.clone();
    base.deny_hooks.attached = 16;
    for (i, w) in worse.iter().enumerate() {
        let mut x = base.clone();
        w(&mut x);
        assert!(x.worsens_from(&base), "change {i}");
        assert!(!base.worsens_from(&x), "change {i}, back");
    }
}

/// The capabilities hash is of what the agent runs with: not of the
/// revision's fields, not of the contract's terms, not of what an upgrade
/// or a new kernel changes alone, not of the order of the lists without
/// one; a capability that changes changes it. The contract's hash moves
/// with the terms, the version and the kernel, not with a capability.
#[test]
fn the_hashes_split_capabilities_from_the_contract() {
    let m = manifest_of(&healthy());
    let h = m.content_hash();
    let c = m.contract_hash_now();
    assert_eq!(h.len(), 64);
    assert_eq!(c.len(), 64);
    let mut r = m.clone();
    r.revision = 7;
    r.hash = h.clone();
    r.previous_hash = Some("x".into());
    r.change = vec!["y".into()];
    r.changes = 3;
    r.unsigned_changes = 2;
    r.degradations.reverse();
    r.sensors.reverse();
    assert_eq!(r.content_hash(), h);
    assert_eq!(r.contract_hash_now(), c);
    // an upgrade, a new kernel, the terms by reference: the contract's
    let mut u = m.clone();
    u.agent_version = "0.0.2".into();
    u.kernel = "6.9.0".into();
    u.btf_offsets_resolved = 41;
    u.host_hardening[0].value = "[integrity]".into();
    u.contract_version = CONTRACT_VERSION + 1;
    u.classes[0].decision_budget_ms = 200;
    if let Some(t) = u.sources[0].terms.as_mut() {
        t.kernel_budgets.push("more".into());
    }
    assert_eq!(u.content_hash(), h, "no capability changed");
    assert_ne!(u.contract_hash_now(), c);
    assert_eq!(m.without_terms().content_hash(), h);
    assert!(m.without_terms().sources.iter().all(|s| s.terms.is_none()));
    // a capability: the capabilities'
    let mut f = healthy();
    f.probe[1].1 = ProbeState::Gap;
    let g = manifest_of(&f);
    assert_ne!(g.content_hash(), h);
    assert_eq!(g.contract_hash_now(), c, "the same contract");
    let mut t = m.clone();
    t.trust_level = 2;
    assert_ne!(t.content_hash(), h);
    let mut w = m.clone();
    w.host_hardening[0].status = "ok".into();
    assert_ne!(w.content_hash(), h, "a host check's status is a capability");
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
    set(&mut f, note("file_open", OPEN_TP, Took::Fallback));
    let mut after = manifest_of(&f);
    after.degradations.push("dns_sensor: x".into());
    after.trust_level = 2;
    after.content.push("netflow-blocklist: built-in".into());
    let lines = after.changes_from(&before);
    assert!(
        lines.contains(&format!("source dns_query: ok on its attach point ({DNS_SKB}) → attached, not invoked on its attach point ({DNS_SKB})")),
        "{lines:#?}"
    );
    assert!(lines.contains(&"source dns_query: telemetry probe seen → gap".to_string()));
    assert!(lines.iter().any(
        |l| l.starts_with("source open_sensor: ok on its attach point")
            && l.contains("→ partial on a fallback")
    ));
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
    other.btf_offsets_absent.push("x".into());
    assert_eq!(
        other.changes_from(&before),
        ["the manifest changed (nn-admin capabilities shows it)"]
    );
    let mut stale = healthy();
    stale.probe[1].1 = ProbeState::Stale;
    assert!(manifest_of(&stale)
        .changes_from(&before)
        .contains(&"source dns_query: telemetry probe seen → stale".to_string()));
}

/// The manifest's JSON reads back (the agent's signed row is it).
#[test]
fn the_manifest_round_trips() {
    let m = manifest_of(&healthy());
    let v = serde_json::to_value(&m).unwrap();
    assert_eq!(v["sources"][0]["state"], "ok");
    assert_eq!(v["sources"][0]["on"], "primary");
    assert_eq!(v["sources"][0]["probe"], "seen");
    assert_eq!(v["sources"][0]["evidence"], "probe");
    assert_eq!(v["sources"][0]["terms"]["on_failure"], "blind");
    assert_eq!(v["sensors"][0]["took"]["as"], "whole");
    assert_eq!(v["classes"][2]["class"], "file");
    assert!(v.get("previous_hash").is_none() && v.get("change").is_none());
    assert!(v.get("changes").is_none() && v.get("unsigned_changes").is_none());
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
        "contract_hash",
        "revision",
        "hash",
    ] {
        old.as_object_mut().unwrap().remove(k);
    }
    for s in old["sensors"].as_array_mut().unwrap() {
        s.as_object_mut().unwrap().remove("took");
    }
    let back: CapabilityManifest = serde_json::from_value(old).unwrap();
    assert!(back.sources.is_empty() && back.revision == 0);
    assert!(back.sensors.iter().all(|s| s.took.is_none()));
    let p: Took = serde_json::from_str(r#"{"as":"partial","missing":["x"]}"#).unwrap();
    assert_eq!(
        p,
        Took::Partial {
            missing: vec!["x".into()]
        }
    );
}

/// R13: the manifest as a change's audit row carries it (revision 1: the
/// terms by the contract's hash), pinned — its fields' names, order and
/// shape, and the two hashes over them (a change of either is a change of
/// what every reader of the audit chain reads, and of every beat's hashes).
#[test]
fn the_manifest_row_and_its_hash_are_pinned() {
    let mut f = healthy();
    f.probe[1].1 = ProbeState::Gap;
    let mut m = manifest_of(&f);
    m.sources.retain(|s| s.source == "dns_query");
    m.classes.retain(|c| c.class == EventClass::Network);
    m.contract_hash = m.contract_hash_now();
    m.hash = m.content_hash();
    m.revision = 1;
    m.previous_hash = Some("ab".repeat(32));
    m.change = vec!["source dns_query: telemetry probe seen → gap".into()];
    m.changes = 2;
    let row = m.without_terms();
    assert_eq!(
        (row.hash.as_str(), row.contract_hash.as_str()),
        MANIFEST_HASHES
    );
    assert_eq!(serde_json::to_string(&row).unwrap(), MANIFEST_JSON);
}

const MANIFEST_HASHES: (&str, &str) = (
    "a718b2c510d027d0e100765799315db68159c50a9b2895b6f8ba506957c00c4f",
    "3e228be2458b5f5b6055dc11189cf28938e7ba1832acb5e55ca18ee65fa671da",
);
const MANIFEST_JSON: &str = r#"{"manifest_version":2,"agent_version":"0.0.1","kernel":"6.8.0","btf":true,"btf_offsets_resolved":40,"btf_offsets_drifted":0,"btf_offsets_absent":[],"active_lsms":"capability,bpf","bpf_lsm":"active","deny_hooks":{"expected":0,"attached":0,"missing":[],"observe_missing":[]},"deny_self_test":"denied","bpf_guard":"enforce","sensors":[{"sensor":"file_open","attach":"lsm:file_open (FIM observer)","took":{"as":"whole"}},{"sensor":"deny_hooks","attach":"lsm:deny hooks","took":{"as":"whole"}},{"sensor":"dns","attach":"kprobe:udp_send_skb+udp_v6_send_skb","took":{"as":"whole"}},{"sensor":"dns_nss","attach":"uprobe:libnss_resolve.so.2","took":{"as":"whole"}},{"sensor":"exploit_guard","attach":"lsm:capable, fentry:commit_creds (lite)","took":{"as":"whole"}},{"sensor":"tcp_connect","attach":"kprobe:tcp_v4_connect+tcp_v6_connect","took":{"as":"whole"}}],"host_hardening":[{"id":"lockdown","status":"warn","value":"[none]"}],"detect_only":false,"degradations":["b","a"],"trust_level":3,"trust_reasons":[],"contract_version":1,"sources":[{"source":"dns_query","classes":["network"],"attach":"kprobe:udp_send_skb+udp_v6_send_skb","on":"primary","state":"attached_not_invoked","why":["telemetry probe: its dns event did not reach the pipeline within the round's deadline (signed telemetry_gap)"],"probe":"gap","evidence":"attach_only"}],"classes":[{"class":"network","queue":"P3","queue_capacity":8192,"when_full":"drop the new event","decision_budget_ms":500,"sources":["dns_query","tcp_connect"],"sync_verdict":"none (the event reports what happened)","on_failure":"blind","loss_counters":[1,3,4,5],"state":"attached_not_invoked"}],"fallbacks":[],"missing":["dns_query: attached, not invoked (kprobe:udp_send_skb+udp_v6_send_skb) — telemetry probe: its dns event did not reach the pipeline within the round's deadline (signed telemetry_gap)"],"content":[],"telemetry_probe":"every 60 s","settled":true,"contract_hash":"3e228be2458b5f5b6055dc11189cf28938e7ba1832acb5e55ca18ee65fa671da","revision":1,"hash":"a718b2c510d027d0e100765799315db68159c50a9b2895b6f8ba506957c00c4f","previous_hash":"abababababababababababababababababababababababababababababababab","change":["source dns_query: telemetry probe seen → gap"],"changes":2}"#;

/// R14a: a worker kind's entry — its state, the sandbox it declared.
fn with_worker(
    m: &CapabilityManifest,
    state: WorkerState,
    sandbox: Option<nn_proto::ipc::SandboxLevel>,
) -> CapabilityManifest {
    let mut m = m.clone();
    m.workers = vec![WorkerEntry {
        kind: "parse".to_string(),
        state,
        why: String::new(),
        kernel_landlock_abi: 4,
        sandbox,
    }];
    m.hash = m.content_hash();
    m
}

fn level(abi: u8) -> nn_proto::ipc::SandboxLevel {
    nn_proto::ipc::SandboxLevel {
        landlock_abi: abi,
        landlock: nn_proto::ipc::LandlockEnforced::Full,
        fs_denied: abi >= 1,
        net_denied: abi >= 4,
        scoped: abi >= 6,
        seccomp: true,
        no_new_privs: true,
        uid: 990,
        gid: 990,
        ..Default::default()
    }
}

/// R14a: a worker kind in a worse state, gone, or sandboxed less is a
/// worse manifest (its row at once), named in `change`; a restart that ends
/// between two builds changes nothing; a ready worker is in the hash.
#[test]
fn a_worker_worse_or_gone_or_less_sandboxed_is_worse_and_named() {
    let base = manifest_of(&healthy());
    let ready = with_worker(&base, WorkerState::Ready, Some(level(4)));
    assert!(!ready.worsens_from(&ready));
    assert_ne!(
        ready.content_hash(),
        base.content_hash(),
        "the worker is in the hash"
    );
    for (state, worse) in [
        (WorkerState::Restarting, true),
        (WorkerState::Disabled, true),
        (WorkerState::Unavailable, true),
        (WorkerState::Stopped, true),
    ] {
        let w = with_worker(&base, state, Some(level(4)));
        assert_eq!(w.worsens_from(&ready), worse, "{state:?}");
        assert!(!ready.worsens_from(&w), "{state:?} → ready is better");
        let lines = w.changes_from(&ready);
        assert!(
            lines
                .iter()
                .any(|l| l.starts_with("worker parse: ready → ") && l.contains(state.name())),
            "{state:?}: {lines:?}"
        );
    }
    assert!(WorkerState::Disabled.rank() > WorkerState::Restarting.rank());
    assert!(WorkerState::Unavailable.rank() > WorkerState::Disabled.rank());
    // gone: worse and named; new and not ready: worse
    assert!(base.worsens_from(&ready));
    assert!(base
        .changes_from(&ready)
        .contains(&"worker parse: gone".to_string()));
    let new_down = with_worker(&base, WorkerState::Unavailable, None);
    assert!(new_down.worsens_from(&base));
    assert!(new_down
        .changes_from(&base)
        .iter()
        .any(|l| l == "worker parse: new (unavailable)"));
    assert!(!ready.worsens_from(&base), "a new ready worker is no loss");
    // the same state, less sandbox: worse, named
    for weaker in [
        level(1),
        {
            let mut l = level(4);
            l.seccomp = false;
            l
        },
        {
            let mut l = level(4);
            l.net_denied = false;
            l
        },
        {
            let mut l = level(4);
            l.fs_denied = false;
            l
        },
    ] {
        let w = with_worker(&base, WorkerState::Ready, Some(weaker));
        assert!(w.worsens_from(&ready), "{w:?}");
        assert!(w
            .changes_from(&ready)
            .iter()
            .any(|l| l.starts_with("worker parse: sandbox ")));
    }
    // a lower ABI alone (the same flags: 4 and 5 deny the same) is worse
    let five = with_worker(&base, WorkerState::Ready, Some(level(5)));
    assert!(ready.worsens_from(&five), "ABI 5 → 4");
    assert!(!five.worsens_from(&ready));
    let scoped = with_worker(&base, WorkerState::Ready, Some(level(6)));
    assert!(!scoped.worsens_from(&ready), "more sandbox is better");
    assert!(ready.worsens_from(&scoped), "and back is worse");
    // the why is shown with the state
    let mut d = with_worker(&base, WorkerState::Disabled, Some(level(4)));
    d.workers[0].why = "5 failures in a row".into();
    assert!(d
        .changes_from(&ready)
        .iter()
        .any(|l| l.ends_with("(5 failures in a row)")));
}
