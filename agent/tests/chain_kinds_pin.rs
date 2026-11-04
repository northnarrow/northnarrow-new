//! R12c (lab PR 270): the signed lines of the chains R12c adds, pinned —
//! their payload's serialisation and their chain's name in the v3
//! pre-image (`northnarrow/chainlog/<kind>/data/v3`), signed with a fixed key
//! (Ed25519 is deterministic): a change of either is a change of what every
//! reader verifies, and fails here. The rows' own JSON is pinned beside
//! their types (`action_rows_are_pinned`); this pins the line on disk.

use std::sync::Arc;

use northnarrow_agent::audit::{read_signing_key, AgentSigningKey};
use northnarrow_agent::chainlog::{
    line_is_genuine, NoProtection, RotatingChainLog, RotationConfig,
};
use northnarrow_agent::response::journal::{ActionIntent, ActionRecord, ActionRow};

/// RFC 8032 test 1's secret key (as `chain_format_pin`).
const KEY_HEX: &str = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";

fn key() -> AgentSigningKey {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("agent.sig.key");
    std::fs::write(&path, format!("{KEY_HEX}\n")).unwrap();
    read_signing_key(&path).expect("the fixed key")
}

/// The first data line a rotating log of `P` writes for `row`.
fn first_line<P>(row: P) -> String
where
    P: serde::Serialize + serde::de::DeserializeOwned + northnarrow_agent::chainlog::ChainPayload,
{
    let dir = tempfile::tempdir().unwrap();
    let active = dir.path().join("log.jsonl");
    let mut log = RotatingChainLog::<P>::open(
        &active,
        key(),
        RotationConfig {
            size_cap_bytes: u64::MAX,
            max_archives: 2,
            file_mode: 0o600,
        },
        Arc::new(NoProtection),
    )
    .unwrap();
    log.append(row).unwrap();
    let line = std::fs::read_to_string(&active).unwrap();
    let line = line.lines().next().unwrap().to_string();
    assert!(line_is_genuine::<P>(
        line.as_bytes(),
        &key().verifying_key()
    ));
    line
}

/// The actions chain's intent row, as it is signed on disk.
#[test]
fn the_actions_chain_s_line_is_pinned() {
    let mut i = ActionIntent::named("rule", "KillProcessTree", 4242);
    i.start_ns = 1_000_000;
    i.severity = "critical".into();
    i.why = vec!["NN-L-CANARY-001".into()];
    i.queued_us = 120;
    let row = ActionRecord {
        row: ActionRow::Intent,
        run: "00112233aabbccdd".into(),
        action: 7,
        ts: "2026-10-31T23:59:00.000000Z".into(),
        intent: Some(i),
        outcome: None,
        overflow: None,
        noted_by: None,
    };
    assert_eq!(first_line(row), ACTIONS_LINE);
}

/// R12c-2: the heartbeat chain's beat, as it is signed on disk.
#[test]
fn the_heartbeat_chain_s_line_is_pinned() {
    use nn_evidence::heartbeat::{BeatActions, BeatHead, BeatKind, HeartbeatRecord};
    let row = HeartbeatRecord {
        kind: BeatKind::Start,
        seq: 1,
        ts: "2026-11-01T10:00:00.000000Z".into(),
        agent_id: "11".repeat(16),
        run: "00112233aabbccdd".into(),
        boot_id: "b007".into(),
        uptime_ms: 1_500,
        interval_secs: 30,
        version: "0.0.1".into(),
        posture: "observing".into(),
        combat_stage: None,
        trust_level: Some("L3".into()),
        degradations: Vec::new(),
        decision_rounds: 3,
        decision_since_last_ms: 120,
        loss: vec![Some(0), Some(0), Some(0), Some(0), Some(1), None, None],
        actions: BeatActions::default(),
        probe_gaps: Some(0),
        heads: vec![
            BeatHead {
                chain: "audit".into(),
                seq: Some(41),
                hash: "ab".repeat(32),
                ..BeatHead::default()
            },
            BeatHead {
                chain: "actions".into(),
                file: Some(3),
                bytes: Some(8_192),
                hash: "cd".repeat(32),
                ..BeatHead::default()
            },
        ],
        stop_reason: None,
        capabilities: None,
        nodns: None,
    };
    assert_eq!(first_line(row), HEARTBEAT_LINE);
}

/// R13 (lab PR 271): a beat carrying the capability manifest's newest
/// revision — the field appended last, absent from a beat without it (the
/// line above, unchanged).
#[test]
fn the_heartbeat_chain_s_line_with_capabilities_is_pinned() {
    use nn_evidence::heartbeat::{BeatActions, BeatKind, BeatManifest, HeartbeatRecord};
    let row = HeartbeatRecord {
        kind: BeatKind::Beat,
        seq: 2,
        ts: "2026-11-01T10:00:30.000000Z".into(),
        agent_id: "11".repeat(16),
        run: "00112233aabbccdd".into(),
        boot_id: "b007".into(),
        uptime_ms: 31_500,
        interval_secs: 30,
        version: "0.0.1".into(),
        posture: "observing".into(),
        combat_stage: None,
        trust_level: Some("L3".into()),
        degradations: Vec::new(),
        decision_rounds: 63,
        decision_since_last_ms: 120,
        loss: vec![Some(0); 7],
        actions: BeatActions::default(),
        probe_gaps: Some(0),
        heads: Vec::new(),
        stop_reason: None,
        capabilities: Some(BeatManifest {
            hash: "ef".repeat(32),
            revision: 1,
            settled: true,
            contract: Some("c0".repeat(32)),
            contract_version: Some(1),
            kernel: Some("6.8.0-147-generic".into()),
        }),
        nodns: None,
    };
    assert_eq!(first_line(row), HEARTBEAT_CAPABILITIES_LINE);
}

const HEARTBEAT_CAPABILITIES_LINE: &str = r#"{"kind":"beat","seq":2,"ts":"2026-11-01T10:00:30.000000Z","agent_id":"11111111111111111111111111111111","run":"00112233aabbccdd","boot_id":"b007","uptime_ms":31500,"interval_secs":30,"version":"0.0.1","posture":"observing","trust_level":"L3","degradations":[],"decision_rounds":63,"decision_since_last_ms":120,"loss":[0,0,0,0,0,0,0],"actions":{"intents":0,"outcomes":0,"unwritten":0,"interrupted_at_boot":0,"in_flight":0},"probe_gaps":0,"heads":[],"capabilities":{"hash":"efefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefef","revision":1,"settled":true,"contract":"c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0","contract_version":1,"kernel":"6.8.0-147-generic"},"fmt_ver":3,"prev_hash":"0000000000000000000000000000000000000000000000000000000000000000","entry_hash":"d16d3e21aa720e5450b444abe2969766de51352db6d9bba41c9a16624bb0f5c7","agent_sig":"JGt3nFWNkwQUOXpcRX5Tg5ZICDB0Lpq+GTvve2oqJuzNc/LdMIC9s1SXm4Uyv7bwMc1pdgxDv6Is4cJl17xjCg=="}"#;

const HEARTBEAT_LINE: &str = r#"{"kind":"start","seq":1,"ts":"2026-11-01T10:00:00.000000Z","agent_id":"11111111111111111111111111111111","run":"00112233aabbccdd","boot_id":"b007","uptime_ms":1500,"interval_secs":30,"version":"0.0.1","posture":"observing","trust_level":"L3","degradations":[],"decision_rounds":3,"decision_since_last_ms":120,"loss":[0,0,0,0,1,null,null],"actions":{"intents":0,"outcomes":0,"unwritten":0,"interrupted_at_boot":0,"in_flight":0},"probe_gaps":0,"heads":[{"chain":"audit","seq":41,"hash":"abababababababababababababababababababababababababababababababab"},{"chain":"actions","file":3,"bytes":8192,"hash":"cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd"}],"fmt_ver":3,"prev_hash":"0000000000000000000000000000000000000000000000000000000000000000","entry_hash":"0f492909639aaf122a90140c45bb3cc259c41428211d8671524b3aff0ba0d909","agent_sig":"wMXMw/j7E4ct3AQvjMCm0QTwbm0uqy5uG64SF4o5OHlv78dGkJEJ84++0/GKCOl+oFGrXz0cFC/t+cvgyLieDg=="}"#;

const ACTIONS_LINE: &str = r#"{"row":"intent","run":"00112233aabbccdd","action":7,"ts":"2026-10-31T23:59:00.000000Z","intent":{"source":"rule","response":"KillProcessTree","pid":4242,"start_ns":1000000,"severity":"critical","why":["NN-L-CANARY-001"],"queued_us":120},"fmt_ver":3,"prev_hash":"0000000000000000000000000000000000000000000000000000000000000000","entry_hash":"dc9c721c272348656a260e7c88b4faddc291162d8b5530f87ff02c695cb92212","agent_sig":"I/MGmA1RikaJSPM0+hYHHc35Eun2mk9UuH0DhJUh92iBhX2/1mwpvK1G3bsRG+zShfCxNEiwpbnif9tKRlzFBA=="}"#;
