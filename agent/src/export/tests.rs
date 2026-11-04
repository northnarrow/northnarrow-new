//! Lot 276: the export end to end without a process — rows of every
//! exported chain written by the agent's own writers and types, read as the
//! log (`nn_export::wal`, the core's reader), served by the worker's state
//! to its JSONL sink, and the file checked as a receiver checks it
//! (`nn_admin::export::verify`: each record's row signed by the agent's key,
//! each chain continuous) and against the pinned OCSF schema.

use std::path::Path;

use nn_export::wal::{self, Cursor, Limits, Source};
use nn_linux::chain_host_linux::LinuxHost;
use nn_proto::ipc::{ExportChain, ExportRows, ExportSetup, ExportSink, FileSetup, RowPos};

use super::*;
use crate::audit::AgentSigningKey;
use crate::chainlog::{NoProtection, RotatingChainLog, RotationConfig};

const AGENT_ID: [u8; 16] = [0x11; 16];

fn key(dir: &Path) -> AgentSigningKey {
    AgentSigningKey::load_or_bootstrap(&dir.join("agent.sig.key")).unwrap()
}

fn cfg() -> RotationConfig {
    RotationConfig {
        size_cap_bytes: 6 * 1024,
        max_archives: 64,
        file_mode: 0o600,
    }
}

fn detection(i: u64) -> crate::detection_store::DetectionRecord {
    let event = nn_model::Event::ProcessSpawn {
        pid: 4000 + i as u32,
        ppid: 1,
        uid: 1000,
        gid: 1000,
        comm: "payload".into(),
        filename: "/tmp/payload".into(),
        argv: vec!["/tmp/payload".into(), "-x".into()],
        timestamp_ns: 1,
        parent_comm: "bash".into(),
        parent_start_ns: 0,
        start_ns: 0,
        parent_is_kthread: false,
        exe: Default::default(),
        argv_truncated: false,
        filename_truncated: false,
        stdio: Default::default(),
    };
    let verdict = nn_model::Verdict {
        rule_id: "R001_ExecFromTmp".into(),
        rule_name: "Exec from /tmp/ (é)".into(),
        category: "execution".into(),
        action: nn_model::ResponseAction::KillProcess,
        severity: nn_model::Severity::High,
        reasoning: "r".into(),
        event_pid: 1,
        event_filename: "/tmp/payload".into(),
        timestamp_ns: 1,
    };
    crate::detection_store::DetectionRecord::from_rule(
        i,
        "2026-11-03T20:00:00.000000Z".into(),
        &event,
        &verdict,
        nn_model::posture_types::PostureKind::Engaged,
        "KillProcess".into(),
    )
}

fn action(i: u64) -> crate::response::journal::ActionRecord {
    use nn_evidence::action_payload::{ActionIntent, ActionOutcome, ActionResult, ActionRow};
    let intent = i % 2 == 0;
    crate::response::journal::ActionRecord {
        row: if intent {
            ActionRow::Intent
        } else {
            ActionRow::Outcome
        },
        run: "00112233aabbccdd".into(),
        action: i / 2,
        ts: "2026-11-03T20:00:01.000000Z".into(),
        intent: intent.then(|| {
            let mut a = ActionIntent::named("rule", "KillProcessTree", 4242);
            a.why = vec!["R001_ExecFromTmp".into()];
            a
        }),
        outcome: (!intent).then(|| ActionOutcome {
            result: ActionResult::Success,
            outcome: "killed".into(),
            reason: None,
            elapsed_us: 1200,
            intent_written: true,
        }),
        overflow: None,
        noted_by: None,
    }
}

fn flow(i: u64) -> crate::net::drain::NetFlowPayload {
    crate::net::drain::NetFlowPayload {
        ts: "2026-11-03T20:00:02.000000Z".into(),
        flow_id: format!("f{i}"),
        start_ns: 1_000_000,
        end_ns: 9_000_000,
        family: 2,
        src_addr: "10.0.0.2".into(),
        src_port: 40000,
        dst_addr: "93.184.216.34".into(),
        dst_port: 443,
        proto: 6,
        pid: 321,
        uid: 1000,
        comm: "curl".into(),
        exe: Some("/usr/bin/curl".into()),
        bytes_sent: 100,
        bytes_recv: 2000,
        resolved_hostname: Some("example.org".into()),
        ja3: None,
        ja4: None,
        sni: Some("example.org".into()),
        close_reason: 0,
        agent_id: hex::encode(AGENT_ID),
        decision_engine_skipped: false,
    }
}

fn drift(i: u64) -> crate::fim::drain::FimDriftPayload {
    crate::fim::drain::FimDriftPayload {
        ts: "2026-11-03T20:00:03.000000Z".into(),
        path: format!("/etc/conf{i}"),
        op: nn_model::telemetry::FimOp::Modified,
        baseline_sha256: Some("aa".repeat(32)),
        new_sha256: Some("bb".repeat(32)),
        modifier_pid: 77,
        modifier_uid: 0,
        modifier_comm: "vi".into(),
        severity: nn_core::fim::drift::DriftSeverity::High,
        decision_engine_skipped: false,
        skip_reason: String::new(),
        agent_id: hex::encode(AGENT_ID),
        attrs: None,
    }
}

fn write<P>(active: &Path, dir: &Path, rows: impl Iterator<Item = P>)
where
    P: serde::Serialize + serde::de::DeserializeOwned + crate::chainlog::ChainPayload,
{
    let mut log =
        RotatingChainLog::<P>::open(active, key(dir), cfg(), std::sync::Arc::new(NoProtection))
            .unwrap();
    for r in rows {
        log.append_deferred(r).unwrap();
    }
    log.sync().unwrap();
}

fn setup(pk: &ed25519_dalek::VerifyingKey) -> ExportSetup {
    ExportSetup {
        agent_id: hex::encode(AGENT_ID),
        hostname: "lab-host".into(),
        version: "0.0.1".into(),
        pubkey: pk.to_bytes(),
        file: Some(FileSetup {
            max_bytes: 1 << 20,
            max_files: 4,
        }),
        syslog: None,
    }
}

/// Serve every row of `src` after `from` to the worker's file sink, as the
/// controller does (the cursor moved by each answer's ack); the last
/// cursor.
fn export_all(
    w: &mut nn_export::worker::ExportWorker,
    src: &Source,
    from: Cursor,
    pk: &ed25519_dalek::VerifyingKey,
) -> Cursor {
    let mut cur = from;
    loop {
        let b = wal::read_after::<LinuxHost>(
            src,
            &cur,
            false,
            Limits {
                rows: 64,
                bytes: 48 * 1024,
            },
            pk,
        )
        .unwrap();
        if b.rows.is_empty() {
            return b.next.unwrap_or(cur);
        }
        let last = b.rows.last().map(|r| (r.pos(), r.end)).unwrap();
        let hash = b.hashes.last().cloned().unwrap();
        let out = w.rows(&ExportRows {
            sink: ExportSink::File,
            chain: src.chain,
            rows: b.rows,
            budget_ms: 1000,
        });
        assert_eq!(out.acked, Some(last.0), "{out:?}");
        assert_eq!(out.unverified, 0, "every row signed by the agent's key");
        cur = Cursor {
            file: last.0.file,
            line: last.0.line,
            end: last.1,
            hash,
        };
    }
}

#[test]
fn every_chain_exported_verifies_where_it_arrives() {
    let d = tempfile::tempdir().unwrap();
    let state = d.path().join("state");
    let sink = d.path().join("export");
    std::fs::create_dir_all(state.join("detections")).unwrap();
    std::fs::create_dir_all(&sink).unwrap();
    let pk = key(d.path()).verifying_key();
    let det = state.join("detections/detections.jsonl");
    let act = state.join("detections/actions.jsonl");
    let net = state.join("netflow.jsonl");
    let fim = state.join("fim_drift.jsonl");
    let can = state.join("canary_access.jsonl");
    write(&det, d.path(), (1..=40).map(detection));
    write(&act, d.path(), (0..30).map(action));
    write(&net, d.path(), (0..40).map(flow));
    write(&fim, d.path(), (0..30).map(drift));
    {
        let mut log =
            crate::canary::access_log::CanaryAccessDb::open(&can, key(d.path()), AGENT_ID).unwrap();
        for i in 0..5u32 {
            log.append(nn_core::canary::host::CanaryAccessDraft {
                canary_id: format!("c{i}"),
                canary_name: "/home/u/.aws/credentials".into(),
                canary_type: nn_model::CanaryTypeTag::Credential,
                access_kind: nn_model::CanaryAccessKind::FileOpen,
                accessor_pid: 55,
                accessor_uid: 1000,
                accessor_comm: "cat".into(),
                accessor_exe: Some("/usr/bin/cat".into()),
                first_trip: i == 0,
            })
            .unwrap();
        }
    }
    assert!(
        crate::chainlog::earliest_archive(&det).is_some(),
        "the detections rotated: the export crosses its terminators"
    );
    let mut w = nn_export::worker::ExportWorker::new(&sink);
    let out = w.setup(&setup(&pk), &mut |_| false);
    assert_eq!(out.file, nn_proto::ipc::SinkState::Up);
    for (chain, active) in [
        (ExportChain::Detections, &det),
        (ExportChain::Actions, &act),
        (ExportChain::Netflow, &net),
        (ExportChain::FimDrift, &fim),
        (ExportChain::CanaryAccess, &can),
    ] {
        let src = Source {
            chain,
            active: active.clone(),
        };
        let start = wal::initial::<LinuxHost>(&src, true).unwrap();
        let end = export_all(&mut w, &src, start, &pk);
        assert!(end.line > 0, "{chain:?}");
    }
    // the receiver's check of the file
    let file = std::fs::read_to_string(sink.join(nn_export::jsonl::ACTIVE)).unwrap();
    let report = nn_admin::export::verify(file.as_bytes(), &pk).unwrap();
    assert_eq!(report.exit_code(), 0, "{:#?}", report);
    let by: std::collections::BTreeMap<&str, &nn_admin::export::ChainReport> = report
        .chains
        .iter()
        .map(|c| (c.chain.as_str(), c))
        .collect();
    assert_eq!(by["detections"].rows, 40);
    assert_eq!(by["detections"].records, 80, "a finding and a launch each");
    assert_eq!(by["actions"].rows, 30);
    assert_eq!(by["netflow"].rows, 40);
    assert_eq!(by["fim_drift"].rows, 30);
    assert_eq!(by["canary_access"].rows, 5);
    assert_eq!(by["detections"].linked, 39, "linked across the rotations");
    assert_eq!(by["detections"].unlinked_rotations, 0);
    // every record against the pinned schema
    let mut classes = std::collections::BTreeSet::new();
    for line in file.lines() {
        let v: serde_json::Value = serde_json::from_str(line).unwrap();
        let errs = nn_export::schema::check_record(&v);
        assert!(errs.is_empty(), "{}\n{v:#}", errs.join("\n"));
        classes.insert(v["class_uid"].as_u64().unwrap());
    }
    assert_eq!(
        classes.into_iter().collect::<Vec<_>>(),
        vec![1001, 1007, 2004, 4001, 7003],
        "file, process, finding, network, process remediation"
    );
    // at least once: the same rows again are counted, not refused
    let again = format!("{file}{file}");
    let r = nn_admin::export::verify(again.as_bytes(), &pk).unwrap();
    assert_eq!(r.exit_code(), 0);
    assert_eq!(
        r.chains.iter().map(|c| c.duplicates).sum::<u64>(),
        file.lines().count() as u64,
        "each record once more"
    );
    // a record cut out is a break the receiver sees
    let cut: Vec<&str> = file
        .lines()
        .filter(|l| !l.contains("\"uid\":\"11111111111111111111111111111111/netflow/1/7\""))
        .collect();
    let r = nn_admin::export::verify(cut.join("\n").as_bytes(), &pk).unwrap();
    assert_eq!(r.exit_code(), 11, "{:#?}", r.chains);
}

#[test]
fn the_configuration_is_off_without_a_signed_text_on_with_one() {
    assert!(matches!(parse(""), Loaded::Configured(c) if !c.config.enabled));
    let on = parse("enabled = true\nfile = on\n");
    let c = on.on().expect("on");
    assert!(c.ca_pem.is_none());
    assert_eq!(c.sha256.len(), 64);
    assert!(matches!(parse("enabled = maybe"), Loaded::Failed { .. }));
    // a CA that is not the one the text pins
    let d = tempfile::tempdir().unwrap();
    let ca = d.path().join("ca.pem");
    std::fs::write(&ca, b"-----BEGIN CERTIFICATE-----\n").unwrap();
    let text = format!(
        "enabled = true\nsyslog = 127.0.0.1:6514\nsyslog_ca = {}\nsyslog_ca_sha256 = {}\n",
        ca.display(),
        "0".repeat(64)
    );
    assert!(matches!(parse(&text), Loaded::Failed { why, .. } if why.contains("pins")));
    let good = hex::encode(<sha2::Sha256 as sha2::Digest>::digest(
        b"-----BEGIN CERTIFICATE-----\n",
    ));
    let text = text.replace(&"0".repeat(64), &good);
    let c = parse(&text);
    assert_eq!(
        c.on().unwrap().ca_pem.as_deref(),
        Some(&b"-----BEGIN CERTIFICATE-----\n"[..])
    );
    // the handle says what was loaded
    assert!(ExportHandle::new(&Loaded::Absent).is_none());
    let h = ExportHandle::new(&c).unwrap();
    // the review of #499, D4: on, its controller not started — failed,
    // in the status, the beat and the manifest alike, never "on"
    assert_eq!(h.status().state, "failed");
    assert_eq!(h.beat().state, "failed");
    assert_eq!(h.manifest_entry().state, "failed");
    h.set_running(true);
    h.publish("ready".into(), None, Vec::new(), None, 0);
    assert_eq!(h.status().state, "on");
    assert_eq!(
        (h.beat().state.as_str(), h.beat().worker.as_str()),
        ("on", "ready")
    );
    // its worker disabled, or unavailable: degraded at once
    for w in ["disabled", "unavailable"] {
        h.publish(w.into(), None, Vec::new(), None, 0);
        assert_eq!(h.status().state, "degraded", "{w}");
        assert_eq!(h.manifest_entry().state, "degraded", "{w}");
        assert_eq!(h.beat().state, "degraded", "{w}");
    }
    // a restart: on within the grace, degraded past it
    h.publish("ready".into(), None, Vec::new(), None, 0);
    h.publish("backoff".into(), None, Vec::new(), None, 0);
    assert_eq!(h.status().state, "on");
    h.0.live.lock().not_ready_since =
        Some(std::time::Instant::now() - NOT_READY_GRACE - std::time::Duration::from_secs(1));
    h.publish("starting".into(), None, Vec::new(), None, 0);
    assert_eq!(h.status().state, "degraded");
    assert!(h.status().why.unwrap().contains("starting"));
    h.publish("ready".into(), None, Vec::new(), None, 0);
    assert_eq!(h.status().state, "on");
    h.set_running(false);
    assert_eq!(h.beat().state, "failed");
    h.set_running(true);
    assert_eq!(h.lost(), Some(0));
    assert_eq!(
        h.manifest_entry().sinks,
        vec!["syslog 127.0.0.1:6514 (127.0.0.1)"]
    );
    let off = ExportHandle::new(&parse("file = on")).unwrap();
    assert_eq!(off.status().state, "off");
    assert_eq!(off.lost(), None, "stage 8 is not counted when off");
    let refused = ExportHandle::new(&Loaded::Refused).unwrap();
    assert_eq!(refused.beat().state, "refused");
    assert_eq!(
        cursors_path(Path::new("/x/detections/detections.jsonl")),
        Path::new("/x/detections/export-cursors.json")
    );
    let _ = RowPos { file: 0, line: 0 };
}
