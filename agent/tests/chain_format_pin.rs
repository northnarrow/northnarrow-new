//! The signed chains' on-disk format, pinned across the Wave 4 restructure
//! (lab PR 241, R04/R05: the evidence chain leaves the agent for
//! `crates/nn-evidence`).
//!
//! `agent/tests/fixtures/chain-pin-v1/` was written by `main` c7bb346's code,
//! before any change of the lot (`regenerate_chain_pin_fixtures` below, run
//! once with `NN_CHAIN_PIN_REGEN` set; never again for v1):
//! - `audit.log`: three rows of the flat audit chain (numbered, an operator
//!   row with cosigners and an executable, escapes in `extra`);
//! - `pin.jsonl*`: a rotating log of [`PinRow`] — sealed archives, a
//!   manifest with its `Rotated` and checkpoint rows, the active file;
//! - `chain_heads.json`: the head anchor with one fixed snapshot.
//!
//! Every build checks two things with the code it has:
//! - what `main` wrote still verifies, in full (`verify_chain_file`,
//!   `verify_log_set`);
//! - what this code writes for the same inputs is `main`'s bytes: the data
//!   lines of a rotating log before its first rotation (no timestamp in
//!   them), the head anchor (a fixed snapshot), and every audit row
//!   re-derived from its own fields (serialisation, hash, signature: Ed25519
//!   is deterministic). Terminators, manifest rows and audit rows carry the
//!   time they were written; they are checked by verification.
//!
//! The test reads only the agent's public paths (`northnarrow_agent::audit`,
//! `chainlog`, `chain_anchor`): the same file passes before and after the
//! move, through the agent's shims.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use northnarrow_agent::audit::{
    read_signing_key, verify_chain_file, verify_entry, AgentSigningKey, AuditEntry,
    AuditEntryDraft, AuditLog,
};
use northnarrow_agent::chain_anchor::{
    is_canonical, AnchoredHead, FileHead, HeadsSnapshot, HeadsStore,
};
use northnarrow_agent::chainlog::{
    verify_log_set, ChainPayload, NoProtection, RotatingChainLog, RotationConfig,
};
use serde::{Deserialize, Serialize};

/// RFC 8032 test 1's secret key: a fixed key, so the fixture's signatures
/// can be made again.
const KEY_HEX: &str = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";
const AGENT_ID: [u8; 16] = [0x11; 16];

fn fixtures() -> PathBuf {
    PathBuf::from(concat!(
        env!("NN_REPO_ROOT"),
        "/agent/tests/fixtures/chain-pin-v1"
    ))
}

/// The fixed key, read as the agent reads its key file (the hex in a file
/// of its own; no key file is kept in the repository, `*.key` is ignored).
fn key() -> AgentSigningKey {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("agent.sig.key");
    std::fs::write(&path, format!("{KEY_HEX}\n")).unwrap();
    read_signing_key(&path).expect("the fixed key")
}

/// One row of the pinned rotating log.
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

/// Four active files' worth: rotates three times, nothing evicted.
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

fn snapshot() -> HeadsSnapshot {
    HeadsSnapshot {
        counter: 3,
        ts: "2026-10-22T08:00:00.000000Z".to_string(),
        agent_id: hex::encode(AGENT_ID),
        second_key_added: true,
        heads: vec![
            AnchoredHead {
                chain: "audit".to_string(),
                path: "/etc/northnarrow/audit.log".to_string(),
                generation: None,
                head: FileHead {
                    bytes: 1234,
                    tail_hash: "ab".repeat(32),
                    seq: Some(2),
                },
            },
            AnchoredHead {
                chain: "pin_rows".to_string(),
                path: "/var/lib/northnarrow/pin.jsonl".to_string(),
                generation: Some(3),
                head: FileHead {
                    bytes: 567,
                    tail_hash: "cd".repeat(32),
                    seq: None,
                },
            },
        ],
    }
}

/// The rotating log's files in `dir`, sorted by name.
fn log_files(dir: &Path) -> Vec<PathBuf> {
    let mut v: Vec<PathBuf> = std::fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.starts_with("pin.jsonl"))
        })
        .collect();
    v.sort();
    v
}

/// Write the fixtures into `$NN_CHAIN_PIN_REGEN` (a directory). Run once on
/// `main` c7bb346 for v1; the committed files are what that code wrote.
/// Without the variable it does nothing: the privileged gate runs every
/// `#[ignore]` test, and this one must not fail it.
#[test]
#[ignore = "writes the fixtures: run once, by hand, on the code they pin"]
fn regenerate_chain_pin_fixtures() {
    let Some(out) = std::env::var_os("NN_CHAIN_PIN_REGEN") else {
        eprintln!("skipped: set NN_CHAIN_PIN_REGEN=<dir> to write the fixtures");
        return;
    };
    let out = PathBuf::from(out);
    std::fs::create_dir_all(&out).unwrap();
    let work = tempfile::tempdir().unwrap();
    let mut log = AuditLog::open(&work.path().join("audit.log"), key(), AGENT_ID).unwrap();
    for d in drafts() {
        log.append(d).unwrap();
    }
    std::fs::copy(work.path().join("audit.log"), out.join("audit.log")).unwrap();
    let active = work.path().join("pin.jsonl");
    let mut rl =
        RotatingChainLog::<PinRow>::open(&active, key(), rotation(), Arc::new(NoProtection))
            .unwrap();
    for r in rows() {
        rl.append(r).unwrap();
    }
    rl.checkpoint().unwrap();
    drop(rl);
    for f in log_files(work.path()) {
        std::fs::copy(&f, out.join(f.file_name().unwrap())).unwrap();
    }
    HeadsStore::write(&out.join("chain_heads.json"), &key(), &snapshot()).unwrap();
}

#[test]
fn the_audit_chain_main_wrote_verifies() {
    let key = key();
    let r = verify_chain_file(&fixtures().join("audit.log"), &key.verifying_key(), None).unwrap();
    assert_eq!(r.broken, None);
    assert_eq!(r.rows, 3);
    assert_eq!(r.first_numbered, Some(0));
    assert_eq!(r.last_seq, Some(2));
    assert_eq!(r.non_canonical_legacy, 0);
}

/// Every row, made again from its own fields: the same serialisation, the
/// same hash (`verify_entry` recomputes it) and the same signature.
#[test]
fn audit_rows_are_made_again_byte_for_byte() {
    let key = key();
    let pk = key.verifying_key();
    let text = std::fs::read_to_string(fixtures().join("audit.log")).unwrap();
    let raws: Vec<&str> = text.lines().collect();
    assert_eq!(raws.len(), 3);
    for (i, raw) in raws.iter().enumerate() {
        let e: AuditEntry = serde_json::from_str(raw).unwrap();
        assert_eq!(
            serde_json::to_string(&e).unwrap(),
            *raw,
            "row {i}: serialisation"
        );
        assert!(is_canonical(&e, raw.as_bytes()), "row {i}: canonical");
        verify_entry(i, &e, &pk).unwrap_or_else(|err| panic!("row {i}: {err}"));
        let digest: [u8; 32] = hex::decode(&e.entry_hash).unwrap().try_into().unwrap();
        assert_eq!(
            B64.encode(key.sign(&digest).to_bytes()),
            e.agent_sig,
            "row {i}: signature"
        );
    }
    let drafts = drafts();
    for (raw, d) in raws.iter().zip(&drafts) {
        let e: AuditEntry = serde_json::from_str(raw).unwrap();
        assert_eq!((e.op.as_str(), &e.extra), (d.op.as_str(), &d.extra));
        assert_eq!(e.agent_id, hex::encode(AGENT_ID));
    }
}

#[test]
fn the_rotating_log_main_wrote_verifies() {
    let key = key();
    let files = log_files(&fixtures());
    let names: Vec<&str> = files
        .iter()
        .map(|p| p.file_name().unwrap().to_str().unwrap())
        .collect();
    assert_eq!(
        names,
        [
            "pin.jsonl",
            "pin.jsonl.000001",
            "pin.jsonl.000002",
            "pin.jsonl.000003",
            "pin.jsonl.manifest.jsonl"
        ]
    );
    let r = verify_log_set::<PinRow>(&fixtures().join("pin.jsonl"), &key.verifying_key()).unwrap();
    assert_eq!(r.archives_verified, 3);
    assert_eq!(r.total_records, 12);
    assert_eq!(r.earliest_retained_seq, 1);
    assert_eq!(r.checkpoints_verified, 1);
    assert_eq!(r.legacy_lines, 0);
}

/// The data lines before the first rotation hold no timestamp: this code
/// writes them as `main` did.
#[test]
fn rotating_data_lines_are_written_byte_for_byte() {
    let dir = tempfile::tempdir().unwrap();
    let active = dir.path().join("pin.jsonl");
    let mut rl =
        RotatingChainLog::<PinRow>::open(&active, key(), rotation(), Arc::new(NoProtection))
            .unwrap();
    for r in rows() {
        rl.append(r).unwrap();
    }
    drop(rl);
    let data = |p: &Path| -> Vec<String> {
        std::fs::read_to_string(p)
            .unwrap()
            .lines()
            .filter(|l| !l.starts_with("{\"rotate\":"))
            .map(str::to_string)
            .collect()
    };
    let main = data(&fixtures().join("pin.jsonl.000001"));
    let now = data(&dir.path().join("pin.jsonl.000001"));
    assert!(main.len() >= 3, "{} data lines", main.len());
    assert_eq!(now, main);
}

#[test]
fn the_head_anchor_is_written_byte_for_byte() {
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("chain_heads.json");
    HeadsStore::write(&p, &key(), &snapshot()).unwrap();
    assert_eq!(
        std::fs::read(&p).unwrap(),
        std::fs::read(fixtures().join("chain_heads.json")).unwrap()
    );
}
