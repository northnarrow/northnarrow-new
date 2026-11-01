use super::*;
use crate::audit::AgentSigningKey;
use crate::boot::deny_selftest::SelfTestOutcome;
use crate::boot::lsm::BpfLsm;
use crate::boot::trust::TrustInputs;
use nn_core::contract::manifest::{AttachedOn, SourceState};

fn base() -> CapabilityManifest {
    CapabilityManifest {
        manifest_version: MANIFEST_VERSION,
        agent_version: "0.0.1".to_string(),
        kernel: "6.8.0-142-generic".to_string(),
        btf: true,
        btf_offsets_resolved: 41,
        btf_offsets_drifted: 0,
        btf_offsets_absent: Vec::new(),
        active_lsms: Some("lockdown,capability,landlock,yama,apparmor,bpf".to_string()),
        bpf_lsm: "active".to_string(),
        deny_hooks: DenyHooks {
            expected: 19,
            attached: 19,
            missing: Vec::new(),
            observe_missing: Vec::new(),
        },
        deny_self_test: "denied".to_string(),
        bpf_guard: "enforce".to_string(),
        sensors: vec![SensorEntry {
            sensor: "exec".to_string(),
            attach: "lsm:bprm_check_security".to_string(),
        }],
        host_hardening: Vec::new(),
        detect_only: false,
        degradations: Vec::new(),
        trust_level: 3,
        trust_reasons: Vec::new(),
        contract_version: 0,
        sources: Vec::new(),
        classes: Vec::new(),
        fallbacks: Vec::new(),
        missing: Vec::new(),
        content: Vec::new(),
        telemetry_probe: String::new(),
        settled: false,
        revision: 0,
        hash: String::new(),
        previous_hash: None,
        change: Vec::new(),
    }
}

fn open_log(dir: &std::path::Path) -> (Arc<Mutex<AuditLog>>, ed25519_dalek::VerifyingKey) {
    let key = AgentSigningKey::load_or_bootstrap(&dir.join("agent.sig")).unwrap();
    let pk = key.verifying_key();
    (
        Arc::new(Mutex::new(
            AuditLog::open(&dir.join("audit.log"), key, [3u8; 16]).unwrap(),
        )),
        pk,
    )
}

fn rows(dir: &std::path::Path) -> Vec<crate::audit::AuditEntry> {
    std::fs::read_to_string(dir.join("audit.log"))
        .unwrap()
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect()
}

fn inputs(bpf_lsm: BpfLsm, self_test: SelfTestOutcome) -> Inputs {
    let points = AttachPoints::new();
    for s in &nn_linux::sensors::contract::SOURCES {
        if let Some(sensor) = s.sensors.first() {
            points.note(sensor, &format!("{} (test)", s.attach));
        }
    }
    points.note("dns_nss", "uprobe:libnss_resolve.so.2 (test)");
    Inputs {
        base: base(),
        bpf_lsm,
        self_test,
        trust: TrustInputs {
            bpf_lsm: BpfLsm::Active {
                list: "capability,bpf".to_string(),
            },
            deny_expected: 19,
            deny_attached: 19,
            self_test: SelfTestOutcome::Denied,
            detect_only: false,
        },
        attach_points: points,
        probe: None,
        probe_every: None,
        content: None,
        pumps: Some(
            nn_linux::sensors::contract::SOURCES
                .iter()
                .map(|s| s.source.to_string())
                .collect(),
        ),
    }
}

/// Every revision of the registry built so far signed: a report another
/// test made in between is a change of its own.
fn settle(m: &SignedManifest) {
    for _ in 0..8 {
        if m.refresh().is_none() {
            return;
        }
    }
}

/// External review G-12: the manifest is a signed row of the audit chain,
/// whose `extra` is the manifest itself, with its hash (R13); the chain
/// verifies.
#[test]
fn the_manifest_is_a_signed_row_of_the_audit_chain() {
    let dir = tempfile::tempdir().unwrap();
    let (log, pk) = open_log(dir.path());
    let current = SignedManifest::default();
    assert!(current.current_json().is_none(), "nothing signed yet");
    assert!(current.beat().is_none());
    assert_eq!(current.refresh(), None, "no inputs: nothing to build");
    let hash = current.sign(Some(&log), base()).expect("signed");
    let rows = rows(dir.path());
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].op, AUDIT_OP);
    assert_eq!(rows[0].result, "success");
    assert_eq!(rows[0].entry_hash, hash);
    let back: CapabilityManifest = serde_json::from_value(rows[0].extra.clone()).unwrap();
    let mut want = base();
    want.hash = base().content_hash();
    assert_eq!(back, want);
    assert_eq!(back.hash.len(), 64);
    crate::audit::verify_chain(&rows, &pk).expect("the chain verifies");
    let cur: serde_json::Value = serde_json::from_str(&current.current_json().unwrap()).unwrap();
    assert_eq!(cur["entry_hash"], hash);
    assert_eq!(cur["manifest"]["trust_level"], 3);
    assert_eq!(cur["manifest"]["revision"], 0);
    let beat = current.beat().unwrap();
    assert_eq!((beat.hash, beat.revision), (want.hash, 0));
}

/// R13: the boot's manifest states every source of the contract and every
/// class, from the boot's notes; a degradation recorded later and an
/// adapter that ends are signed revisions, each naming what changed and
/// the hash before it; nothing changed signs nothing.
#[test]
fn a_change_while_running_is_a_signed_revision() {
    let dir = tempfile::tempdir().unwrap();
    let (log, pk) = open_log(dir.path());
    let m = SignedManifest::default();
    m.arm(
        Some(&log),
        inputs(
            BpfLsm::Active {
                list: "capability,bpf".to_string(),
            },
            SelfTestOutcome::Denied,
        ),
    );
    let first = m.current().unwrap();
    // the status reply carries it whole, in a frame of at most 64 KiB
    // (`nn_proto::admin_protocol`): the manifest keeps well under half
    let json = m.current_json().unwrap();
    assert!(json.len() < 32 * 1024, "{} bytes", json.len());
    eprintln!("manifest: {} bytes", json.len());
    assert_eq!(
        first.sources.len(),
        nn_linux::sensors::contract::SOURCES.len()
    );
    assert_eq!(first.classes.len(), 5);
    assert_eq!(first.contract_version, nn_core::contract::CONTRACT_VERSION);
    assert_eq!(first.telemetry_probe, "off");
    assert!(first.settled, "no probe: nothing pending");
    let spawn = first
        .sources
        .iter()
        .find(|s| s.source == "process_spawn")
        .unwrap();
    assert_eq!(
        (spawn.on, spawn.state),
        (AttachedOn::Primary, SourceState::Ok)
    );
    let tp = first
        .sources
        .iter()
        .find(|s| s.source == "file_open")
        .unwrap();
    assert_eq!(tp.state, SourceState::Standby);
    settle(&m);
    let before = m.current().unwrap();
    assert_eq!(m.refresh(), None, "nothing changed");
    let detail = format!("r13 test {}", std::process::id());
    crate::boot::degradation::report("r13_test", &detail);
    let rev = m.refresh().expect("a change");
    assert_eq!(rev, before.revision + 1);
    let now = m.current().unwrap();
    assert_eq!(now.previous_hash.as_deref(), Some(before.hash.as_str()));
    assert_ne!(now.hash, before.hash);
    assert!(
        now.change
            .contains(&format!("degradation + r13_test: {detail}")),
        "{:?}",
        now.change
    );
    let rev2 = m.adapters_terminated(&["fim_drain"]).expect("a change");
    assert!(rev2 > rev);
    let now = m.current().unwrap();
    let fim = now
        .sources
        .iter()
        .find(|s| s.source == "fim_drain")
        .unwrap();
    assert_eq!(fim.state, SourceState::AdapterTerminated);
    assert!(now
        .change
        .iter()
        .any(|c| c.starts_with("source fim_drain: ok on its attach point")));
    assert_eq!(m.adapters_terminated(&["fim_drain"]), None, "once");
    let rows = rows(dir.path());
    let changes: Vec<&crate::audit::AuditEntry> =
        rows.iter().filter(|r| r.op == CHANGE_OP).collect();
    assert!(changes.len() >= 2, "{}", changes.len());
    assert_eq!(rows[0].op, AUDIT_OP);
    let last: CapabilityManifest =
        serde_json::from_value(changes.last().unwrap().extra.clone()).unwrap();
    assert_eq!(last.revision, rev2);
    assert_eq!(last.hash, last.content_hash());
    assert_eq!(changes.last().unwrap().result, "detected");
    crate::audit::verify_chain(&rows, &pk).expect("the chain verifies");
    let beat = m.beat().unwrap();
    assert_eq!(beat.revision, rev2);
}

/// R13, EXP-37: `bpf` not in the active LSM list — every BPF LSM source on
/// its attach point is attached and not invoked, with why, and the deny
/// self-test's delivered signal says the same on a list that names `bpf`.
#[test]
fn without_the_bpf_lsm_the_manifest_says_which_hooks_do_not_run() {
    let m = SignedManifest::default();
    m.arm(
        None,
        inputs(
            BpfLsm::Absent {
                list: "lockdown,capability,landlock,yama,apparmor".to_string(),
            },
            SelfTestOutcome::NotDenied,
        ),
    );
    let cur = m.current().unwrap();
    for s in &cur.sources {
        let contract = nn_linux::sensors::contract::source(&s.source).unwrap();
        if contract.needs_bpf_lsm {
            assert_eq!(s.state, SourceState::AttachedNotInvoked, "{s:?}");
            assert!(
                s.why
                    .iter()
                    .any(|w| w.contains("bpf is not in the active LSM list")),
                "{s:?}"
            );
        } else if contract.standby_for.is_none() {
            assert_eq!(s.state, SourceState::Ok, "{s:?}");
        }
    }
    assert!(cur
        .missing
        .iter()
        .any(|l| l.starts_with("fs_protect: attached, not invoked")));
    let m = SignedManifest::default();
    m.arm(
        None,
        inputs(
            BpfLsm::Active {
                list: "capability,bpf".to_string(),
            },
            SelfTestOutcome::NotDenied,
        ),
    );
    let cur = m.current().unwrap();
    let deny = cur
        .sources
        .iter()
        .find(|s| s.source == "fs_protect")
        .unwrap();
    assert_eq!(deny.state, SourceState::AttachedNotInvoked);
    assert!(deny.why.iter().any(|w| w.contains("self-test")), "{deny:?}");
    let m = SignedManifest::default();
    m.arm(
        None,
        inputs(
            BpfLsm::Unknown {
                why: "no securityfs".to_string(),
            },
            SelfTestOutcome::Inconclusive("no child".to_string()),
        ),
    );
    let cur = m.current().unwrap();
    let deny = cur
        .sources
        .iter()
        .find(|s| s.source == "fs_protect")
        .unwrap();
    assert_eq!(deny.state, SourceState::Ok, "not known: not said");
}

/// R13: a list given way to the copy built into the agent is the
/// manifest's content (the overlay gate's record of it).
#[test]
fn a_default_list_in_force_is_the_manifest_s_content() {
    let dir = tempfile::tempdir().unwrap();
    let admin_pub = dir.path().join("admin.pub");
    let gate = Arc::new(crate::config::overlay_auth::OverlayGate::new(
        &admin_pub,
        [1; 16],
        crate::config::overlay_floor::RollbackFloor::default(),
    ));
    gate.report_default_unavailable(
        "netflow-blocklist",
        std::path::Path::new("/usr/share/northnarrow/netflow-blocklist.v1"),
        "not found",
    );
    let mut i = inputs(
        BpfLsm::Active {
            list: "bpf".to_string(),
        },
        SelfTestOutcome::Denied,
    );
    i.content = Some(Arc::clone(&gate));
    let m = SignedManifest::default();
    m.arm(None, i);
    assert_eq!(
        m.current().unwrap().content,
        [
            "netflow-blocklist (/usr/share/northnarrow/netflow-blocklist.v1): unavailable (not \
          found) — the copy built into the agent is in force"
        ]
    );
    settle(&m);
    gate.report_default_modified(
        "netflow-ja3-blocklist",
        std::path::Path::new("/x.v1"),
        "ab",
        "cd",
        false,
    );
    m.refresh().expect("a change");
    let cur = m.current().unwrap();
    assert!(cur
        .change
        .iter()
        .any(|c| c.starts_with("content + netflow-ja3-blocklist (/x.v1): no list")));
}

/// The source files of `rel` paths (from the repository's root), without
/// their test modules.
fn sources_of(rel: &[&str]) -> Vec<(String, String)> {
    let root = std::path::Path::new(env!("NN_REPO_ROOT"));
    rel.iter()
        .map(|r| {
            let text = std::fs::read_to_string(root.join(r)).expect(r);
            let code = match text.find("#[cfg(test)]\nmod tests") {
                Some(i) => text[..i].to_string(),
                None => text,
            };
            (r.to_string(), code)
        })
        .collect()
}

/// The string literal right after `needle` (whitespace skipped), at each of
/// its occurrences; a non-literal argument is skipped.
fn literals_after(code: &str, needle: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut from = 0;
    while let Some(i) = code[from..].find(needle) {
        let rest = code[from + i + needle.len()..].trim_start();
        if let Some(lit) = rest.strip_prefix('"') {
            if let Some(end) = lit.find('"') {
                out.push(lit[..end].to_string());
            }
        }
        from += i + needle.len();
    }
    out
}

/// R13: every source the code starts — a ring's pump registered by the
/// multiplexer, the exploit guard's and the file-open sensor's pumps, the
/// drains the start registers, each bus sender named — has its entry in
/// the sensor contract, and every entry is a source the code starts; every
/// attach point the code notes is a source's. A pump or a note added
/// without its contract fails here.
#[test]
fn every_source_and_attach_point_the_code_starts_has_a_contract_entry() {
    use nn_linux::sensors::contract::{NOT_SOURCES, SOURCES};
    let files = sources_of(&[
        "crates/nn-linux/src/sensors/multiplexer.rs",
        "crates/nn-linux/src/sensors/open_sensor.rs",
        "crates/nn-linux/src/sensors/epg.rs",
        "crates/nn-linux/src/sensors/dns_sensor.rs",
        "crates/nn-linux/src/sensors/exe_identity.rs",
        "agent/src/boot/fim.rs",
        "agent/src/boot/net.rs",
    ]);
    let mut labels: Vec<String> = Vec::new();
    let mut notes: Vec<String> = Vec::new();
    for (_, code) in &files {
        for needle in [
            "for_source(",
            "event_tx_for(",
            "register_pump_thread(",
            "register_pump_handle(",
            "PUMP_LABEL: &str =",
        ] {
            labels.extend(literals_after(code, needle));
        }
        // the multiplexer's pumps: `("label", Pump::…(`
        for marker in ["Pump::Thread(", "Pump::Task("] {
            let mut from = 0;
            while let Some(i) = code[from..].find(marker) {
                let before = code[..from + i].trim_end().trim_end_matches(',').trim_end();
                if let Some(lit) = before.strip_suffix('"') {
                    if let Some(start) = lit.rfind('"') {
                        labels.push(lit[start + 1..].to_string());
                    }
                }
                from += i + marker.len();
            }
        }
        // spawn_ring_pump's label: its first argument
        for call in ["spawn_ring_pump::<", "spawn_ring_pump("] {
            let mut from = 0;
            while let Some(i) = code[from..].find(call) {
                let rest = &code[from + i..];
                if let Some(open) = rest.find('(') {
                    if let Some(lit) = rest[open + 1..].trim_start().strip_prefix('"') {
                        if let Some(end) = lit.find('"') {
                            labels.push(lit[..end].to_string());
                        }
                    }
                }
                from += i + call.len();
            }
        }
        notes.extend(literals_after(code, ".note("));
    }
    labels.sort();
    labels.dedup();
    notes.sort();
    notes.dedup();
    for l in &labels {
        assert!(
            SOURCES.iter().any(|s| s.source == l) || NOT_SOURCES.contains(&l.as_str()),
            "the code starts the source {l}, which has no entry in the sensor contract"
        );
    }
    for s in &SOURCES {
        assert!(
            labels.iter().any(|l| l == s.source),
            "the contract's source {} is no source the code starts ({labels:?})",
            s.source
        );
    }
    // the anti-tamper attach's notes are a list of its own
    let anti_tamper: Vec<String> =
        crate::anti_tamper::attach_notes(&crate::anti_tamper::DenyReport::default())
            .into_iter()
            .map(|(n, _)| n.to_string())
            .collect();
    for n in notes
        .iter()
        .chain(anti_tamper.iter())
        .chain(["fim_observers".to_string()].iter())
    {
        assert!(
            SOURCES.iter().any(|s| s.sensors.contains(&n.as_str())),
            "the code notes the attach point {n}, which no source of the contract names"
        );
    }
    assert!(notes.contains(&"exploit_guard".to_string()), "{notes:?}");
    assert!(notes.contains(&"dns_nss".to_string()), "{notes:?}");
    assert!(labels.contains(&"fim_drain".to_string()), "{labels:?}");
    assert!(labels.contains(&"open_sensor".to_string()), "{labels:?}");
    // and the FIM observers' note is where the start makes it
    assert!(
        files
            .iter()
            .any(|(f, code)| f.ends_with("fim.rs") && code.contains("\"fim_observers\"")),
        "the FIM observers' note moved"
    );
}
