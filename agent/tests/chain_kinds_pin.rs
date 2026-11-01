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

const ACTIONS_LINE: &str = r#"{"row":"intent","run":"00112233aabbccdd","action":7,"ts":"2026-10-31T23:59:00.000000Z","intent":{"source":"rule","response":"KillProcessTree","pid":4242,"start_ns":1000000,"severity":"critical","why":["NN-L-CANARY-001"],"queued_us":120},"fmt_ver":3,"prev_hash":"0000000000000000000000000000000000000000000000000000000000000000","entry_hash":"dc9c721c272348656a260e7c88b4faddc291162d8b5530f87ff02c695cb92212","agent_sig":"I/MGmA1RikaJSPM0+hYHHc35Eun2mk9UuH0DhJUh92iBhX2/1mwpvK1G3bsRG+zShfCxNEiwpbnif9tKRlzFBA=="}"#;
