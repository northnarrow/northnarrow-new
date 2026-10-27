//! Lab PR 249: the chain-format pin of lab PR 241, made again in full
//! through the writers' clock seam.
//!
//! `chain_format_pin.rs` (unchanged) checks that what `main` c7bb346 wrote
//! in `agent/tests/fixtures/chain-pin-v1/` still verifies, and that this
//! code writes the same bytes where nothing in them is a time: the data
//! lines of a rotating log, the head anchor of a fixed snapshot, each audit
//! row re-derived from its own fields. The rows that carry the time they
//! were written — the audit rows, the terminators, the manifest rows —
//! could only be verified: the writers read `Utc::now`.
//!
//! The writers read the time through `nn_evidence::clock::Clock` now (the
//! host's, `Utc::now`, by default). This test gives them a clock that
//! answers, in order, the times `main` wrote in the fixture, writes the
//! fixture's inputs with the fixture's key the way
//! `regenerate_chain_pin_fixtures` wrote them — and gets `main`'s files
//! byte for byte: `audit.log` and the whole rotating set (its three
//! archives with their terminators, the manifest with its `Rotated` and
//! checkpoint rows, the active file). The format is unchanged, and the
//! writers stamp every one of those rows through the clock, exactly once,
//! in the order they are written.

use std::collections::VecDeque;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use chrono::{DateTime, Utc};
use northnarrow_agent::audit::{read_signing_key, AgentSigningKey, AuditEntryDraft, AuditLog};
use northnarrow_agent::audit::{AuditStamps, GENESIS_PREV_HASH};
use northnarrow_agent::chainlog::{ChainPayload, NoProtection, RotatingChainLog, RotationConfig};
use serde::{Deserialize, Serialize};

/// The fixture's key and agent id (`chain_format_pin.rs`).
const KEY_HEX: &str = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";
const AGENT_ID: [u8; 16] = [0x11; 16];

fn fixtures() -> PathBuf {
    PathBuf::from(concat!(
        env!("NN_REPO_ROOT"),
        "/agent/tests/fixtures/chain-pin-v1"
    ))
}

fn key() -> AgentSigningKey {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("agent.sig.key");
    std::fs::write(&path, format!("{KEY_HEX}\n")).unwrap();
    read_signing_key(&path).expect("the fixed key")
}

/// A clock that answers the given times, in order, once each.
struct Script(Mutex<VecDeque<DateTime<Utc>>>);

impl Script {
    fn of(stamps: &[String]) -> Arc<Self> {
        Arc::new(Self(Mutex::new(
            stamps
                .iter()
                .map(|s| DateTime::parse_from_rfc3339(s).unwrap().with_timezone(&Utc))
                .collect(),
        )))
    }

    fn left(&self) -> usize {
        self.0.lock().unwrap().len()
    }
}

impl nn_evidence::clock::Clock for Script {
    fn now(&self) -> DateTime<Utc> {
        self.0
            .lock()
            .unwrap()
            .pop_front()
            .expect("the writer stamped more rows than the fixture holds")
    }
}

/// The pinned rotating log's row (`chain_format_pin.rs`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct PinRow {
    n: u64,
    note: String,
}

impl ChainPayload for PinRow {
    const KIND: &'static str = "pin_rows";
}

fn rows() -> Vec<PinRow> {
    (0..12)
        .map(|n| PinRow {
            n,
            note: format!("row {n}: \"quoted\", tab\t, é, \u{1F512}"),
        })
        .collect()
}

fn rotation() -> RotationConfig {
    RotationConfig {
        size_cap_bytes: 1200,
        max_archives: 8,
        file_mode: 0o600,
    }
}

fn drafts() -> Vec<AuditEntryDraft> {
    vec![
        AuditEntryDraft {
            op: "agent_boot".to_string(),
            extra: serde_json::json!({ "version": "pin", "detect_only": false }),
            key_fp: "agent-self".to_string(),
            cosigner_fps: Vec::new(),
            result: "success".to_string(),
            client_pid: 4242,
            client_uid: 0,
            client_comm: "northnarrow-agent".to_string(),
            client_exe: None,
        },
        AuditEntryDraft {
            op: "unlock".to_string(),
            extra: serde_json::json!({ "reason": "line\nbreak \"q\" \\ é", "n": [1, 2, 3] }),
            key_fp: "a1b2c3d4".to_string(),
            cosigner_fps: vec!["e5f6a7b8".to_string(), "c9d0e1f2".to_string()],
            result: "failure: role denied".to_string(),
            client_pid: 77,
            client_uid: 1000,
            client_comm: "nn-admin".to_string(),
            client_exe: Some("/usr/bin/nn-admin".to_string()),
        },
        AuditEntryDraft {
            op: "agent_stop".to_string(),
            extra: serde_json::json!({ "reason": "sigterm", "uptime_secs": 9 }),
            key_fp: "agent-self".to_string(),
            cosigner_fps: Vec::new(),
            result: "success".to_string(),
            client_pid: 4242,
            client_uid: 0,
            client_comm: "northnarrow-agent".to_string(),
            client_exe: None,
        },
    ]
}

fn lines(path: &Path) -> Vec<serde_json::Value> {
    std::fs::read_to_string(path)
        .unwrap()
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect()
}

/// The times `main` stamped on a fixture file's rows, read from it.
fn ts(v: &serde_json::Value) -> String {
    v["ts"]
        .as_str()
        .or_else(|| v["manifest"]["ts"].as_str())
        .unwrap()
        .to_string()
}

#[test]
fn the_audit_chain_main_wrote_is_written_again_byte_for_byte() {
    let stamps: Vec<String> = lines(&fixtures().join("audit.log"))
        .iter()
        .map(ts)
        .collect();
    assert_eq!(stamps.len(), 3);
    let clock = Script::of(&stamps);
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("audit.log");
    let mut log = AuditLog::open_with(
        &path,
        key(),
        AGENT_ID,
        AuditStamps {
            clock: clock.clone(),
            // No row of the fixture is written by the log about itself.
            self_pid: 1,
        },
    )
    .unwrap();
    assert_eq!(log.last_hash(), GENESIS_PREV_HASH);
    for d in drafts() {
        log.append(d).unwrap();
    }
    drop(log);
    assert_eq!(clock.left(), 0, "one stamp per row");
    assert_eq!(
        std::fs::read_to_string(&path).unwrap(),
        std::fs::read_to_string(fixtures().join("audit.log")).unwrap()
    );
}

#[test]
fn the_rotating_set_main_wrote_is_written_again_byte_for_byte() {
    // The rows that carry a time, in the order the writer stamped them:
    // each rotation's terminator, then its manifest row; the checkpoint.
    let manifest = lines(&fixtures().join("pin.jsonl.manifest.jsonl"));
    assert_eq!(manifest.len(), 4);
    let mut stamps = Vec::new();
    for seq in 1..=3 {
        let archive = lines(&fixtures().join(format!("pin.jsonl.{seq:06}")));
        let terminator = archive.last().unwrap();
        assert!(terminator.get("rotate").is_some(), "{terminator}");
        stamps.push(ts(terminator));
        stamps.push(ts(&manifest[seq - 1]));
    }
    stamps.push(ts(&manifest[3]));
    let mut sorted = stamps.clone();
    sorted.sort();
    assert_eq!(
        stamps, sorted,
        "the fixture's times are in the order written"
    );

    let clock = Script::of(&stamps);
    let dir = tempfile::tempdir().unwrap();
    let active = dir.path().join("pin.jsonl");
    let mut rl = RotatingChainLog::<PinRow>::open_with_clock(
        &active,
        key(),
        rotation(),
        Arc::new(NoProtection),
        clock.clone(),
    )
    .unwrap();
    for r in rows() {
        rl.append(r).unwrap();
    }
    rl.checkpoint().unwrap();
    drop(rl);
    assert_eq!(clock.left(), 0, "one stamp per terminator and manifest row");
    for name in [
        "pin.jsonl",
        "pin.jsonl.000001",
        "pin.jsonl.000002",
        "pin.jsonl.000003",
        "pin.jsonl.manifest.jsonl",
    ] {
        assert_eq!(
            std::fs::read_to_string(dir.path().join(name)).unwrap(),
            std::fs::read_to_string(fixtures().join(name)).unwrap(),
            "{name}"
        );
    }
}
