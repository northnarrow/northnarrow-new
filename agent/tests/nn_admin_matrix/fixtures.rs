//! The matrix's fixed inputs: keys from constant seeds, the install's id,
//! admin.pub, the agent's signing key, chains written with a fixed clock,
//! signed overlays with a fixed time, the golden cases' events. Nothing of
//! the host and nothing random: every run writes the same bytes.

use std::collections::VecDeque;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use chrono::{DateTime, Utc};
use ed25519_dalek::{SigningKey, VerifyingKey};
use nn_proto::admin_signed_payload::{sign, verify, OverlayKind, SignedPayload};

use crate::harness::Put;

/// The admin keys' seeds: `key-a` (installed, `all`), `key-b` (installed,
/// `unlock,audit-read`), `key-c` (not installed).
pub const ADMIN_KEYS: [(&str, [u8; 32]); 3] = [
    ("key-a", [0xa1; 32]),
    ("key-b", [0xb2; 32]),
    ("key-c", [0xc3; 32]),
];

/// The agent's audit signing key: RFC 8032 test 1's secret, the key of
/// `agent/tests/fixtures/chain-pin-v1` (whose audit log verifies with it).
pub const AGENT_KEY_HEX: &str = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";
/// Another agent's key: lab PR 256's class of lines signed by another key.
pub const OTHER_AGENT_SEED: [u8; 32] = [0x0d; 32];
/// The install's id (chain-pin-v1's).
pub const AGENT_ID: [u8; 16] = [0x11; 16];
/// The time the matrix's fixtures are signed and stamped at: 2025-06-15,
/// far from any run's clock (`norm`'s `<now>` rule never takes it).
pub const FIXTURE_TS: u64 = 1_750_000_000;

/// The fixture admin keys with their public halves, derived once (an
/// unoptimised build takes milliseconds per derivation).
fn admin_keys() -> &'static [(&'static str, SigningKey, VerifyingKey)] {
    static KEYS: std::sync::OnceLock<Vec<(&'static str, SigningKey, VerifyingKey)>> =
        std::sync::OnceLock::new();
    KEYS.get_or_init(|| {
        ADMIN_KEYS
            .iter()
            .map(|(n, seed)| {
                let k = SigningKey::from_bytes(seed);
                let v = k.verifying_key();
                (*n, k, v)
            })
            .collect()
    })
}

pub fn admin(name: &str) -> SigningKey {
    admin_keys()
        .iter()
        .find(|(n, _, _)| *n == name)
        .unwrap_or_else(|| panic!("no fixture key {name}"))
        .1
        .clone()
}

pub fn agent_key() -> SigningKey {
    SigningKey::from_bytes(&parse_key_hex(AGENT_KEY_HEX).unwrap())
}

pub fn pub_hex(k: &SigningKey) -> String {
    static SEEN: std::sync::OnceLock<Mutex<std::collections::HashMap<[u8; 32], String>>> =
        std::sync::OnceLock::new();
    let seen = SEEN.get_or_init(Default::default);
    if let Some(h) = seen.lock().unwrap().get(&k.to_bytes()) {
        return h.clone();
    }
    let h = hex::encode(k.verifying_key().to_bytes());
    seen.lock().unwrap().insert(k.to_bytes(), h.clone());
    h
}

pub fn fingerprint(vk: &VerifyingKey) -> String {
    use sha2::{Digest, Sha256};
    hex::encode(&Sha256::digest(vk.to_bytes())[..4])
}

pub fn parse_key_hex(s: &str) -> Option<[u8; 32]> {
    hex::decode(s).ok()?.try_into().ok()
}

/// Which fixture key made `sig` over `payload`.
pub fn signer_of(payload: &SignedPayload, sig: &[u8; 64]) -> String {
    for (name, _, vk) in admin_keys() {
        if verify(payload, sig, vk).is_ok() {
            return format!("<sig of {name}>");
        }
    }
    "<sig: by no fixture key>".to_string()
}

/// The files most cases start from: the three admin keys (0600), admin.pub
/// with `key-a` and `key-b`, the install's id.
pub fn base() -> Vec<Put> {
    static BASE: std::sync::OnceLock<Vec<Put>> = std::sync::OnceLock::new();
    BASE.get_or_init(|| {
        let mut v: Vec<Put> = ADMIN_KEYS
            .iter()
            .map(|(n, seed)| Put::file(n, format!("{}\n", hex::encode(seed)), 0o600))
            .collect();
        v.push(Put::file("admin.pub", admin_pub(), 0o644));
        v.push(Put::file(
            "agent_id",
            format!("{}\n", hex::encode(AGENT_ID)),
            0o644,
        ));
        v
    })
    .clone()
}

/// admin.pub as install.sh writes it: a comment, `key-a` with every role,
/// `key-b` with two.
pub fn admin_pub() -> String {
    format!(
        "# admin keys of the nn-admin matrix\n{} all\n{} unlock,audit-read\n",
        pub_hex(&admin("key-a")),
        pub_hex(&admin("key-b"))
    )
}

/// The agent's key and its published public half (`agent.sig.pub`).
pub fn agent_keys() -> Vec<Put> {
    vec![
        Put::file("agent.sig.key", format!("{AGENT_KEY_HEX}\n"), 0o600),
        Put::file(
            "agent.sig.pub",
            format!("{}\n", pub_hex(&agent_key())),
            0o444,
        ),
    ]
}

fn repo(rel: &str) -> PathBuf {
    Path::new(env!("NN_REPO_ROOT")).join(rel)
}

pub fn read_repo(rel: &str) -> Vec<u8> {
    std::fs::read(repo(rel)).unwrap_or_else(|e| panic!("{rel}: {e}"))
}

/// chain-pin-v1's audit log (three rows, signed by [`AGENT_KEY_HEX`]).
pub fn pin_audit_log() -> Vec<u8> {
    read_repo("agent/tests/fixtures/chain-pin-v1/audit.log")
}

/// chain-pin-v1's head anchor.
pub fn pin_heads() -> Vec<u8> {
    read_repo("agent/tests/fixtures/chain-pin-v1/chain_heads.json")
}

// ── chains written with a fixed clock ─────────────────────────────────────

/// A clock that answers one second after another from [`FIXTURE_TS`].
struct Ticks(Mutex<VecDeque<DateTime<Utc>>>);

impl Ticks {
    fn new(n: usize) -> Arc<Self> {
        Arc::new(Ticks(Mutex::new(
            (0..n)
                .map(|i| DateTime::from_timestamp((FIXTURE_TS + i as u64) as i64, 0).unwrap())
                .collect(),
        )))
    }
}

impl nn_evidence::clock::Clock for Ticks {
    fn now(&self) -> DateTime<Utc> {
        self.0
            .lock()
            .unwrap()
            .pop_front()
            .expect("the fixture's clock ran out")
    }
}

fn signing_key_of(seed_hex: &str) -> northnarrow_agent::audit::AgentSigningKey {
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("agent.sig.key");
    std::fs::write(&p, format!("{seed_hex}\n")).unwrap();
    northnarrow_agent::audit::read_signing_key(&p).unwrap()
}

fn other_key_hex() -> String {
    hex::encode(OTHER_AGENT_SEED)
}

/// An audit log of `n` rows signed by the agent key (or another key),
/// stamped by the fixed clock.
pub fn audit_log(n: usize, other_key: bool) -> Vec<u8> {
    memo(&format!("audit_log/{n}/{other_key}"), || {
        audit_log_uncached(n, other_key)
            .into_iter()
            .map(|b| ("audit.log".to_string(), b))
            .collect()
    })
    .remove(0)
    .1
}

fn audit_log_uncached(n: usize, other_key: bool) -> Option<Vec<u8>> {
    use northnarrow_agent::audit::{AuditEntryDraft, AuditLog, AuditStamps};
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("audit.log");
    let key = if other_key {
        signing_key_of(&other_key_hex())
    } else {
        signing_key_of(AGENT_KEY_HEX)
    };
    let mut log = AuditLog::open_with(
        &path,
        key,
        AGENT_ID,
        AuditStamps {
            clock: Ticks::new(n),
            self_pid: 1,
        },
    )
    .unwrap();
    for i in 0..n {
        log.append(AuditEntryDraft {
            op: if i == 0 {
                "agent_boot"
            } else {
                "config_overlay_set"
            }
            .to_string(),
            extra: serde_json::json!({ "n": i, "note": format!("matrix row {i}") }),
            key_fp: if i == 0 {
                "agent-self".to_string()
            } else {
                fingerprint(&admin("key-a").verifying_key())
            },
            cosigner_fps: Vec::new(),
            result: "success".to_string(),
            client_pid: 4242,
            client_uid: 0,
            client_comm: "nn-admin".to_string(),
            client_exe: Some("/usr/bin/nn-admin".to_string()),
        })
        .unwrap();
    }
    drop(log);
    Some(std::fs::read(&path).unwrap())
}

type Files = Vec<(String, Vec<u8>)>;

/// A fixture made once per test process.
fn memo(key: &str, make: impl FnOnce() -> Files) -> Files {
    use std::collections::HashMap;
    use std::sync::OnceLock;
    static CACHE: OnceLock<Mutex<HashMap<String, Files>>> = OnceLock::new();
    let cache = CACHE.get_or_init(|| Mutex::new(HashMap::new()));
    if let Some(v) = cache.lock().unwrap().get(key) {
        return v.clone();
    }
    let v = make();
    cache.lock().unwrap().insert(key.to_string(), v.clone());
    v
}

/// The FIM drift log (a rotating chain: archives, manifest, checkpoint) of
/// `rows` rows, its files by name.
pub fn fim_drift_log(rows: usize, other_key: bool) -> Vec<(String, Vec<u8>)> {
    memo(&format!("fim_drift/{rows}/{other_key}"), || {
        fim_drift_log_uncached(rows, other_key)
    })
}

fn fim_drift_log_uncached(rows: usize, other_key: bool) -> Vec<(String, Vec<u8>)> {
    use northnarrow_agent::chainlog::{NoProtection, RotatingChainLog, RotationConfig};
    use northnarrow_agent::fim::drain::FimDriftPayload;
    let dir = tempfile::tempdir().unwrap();
    let active = dir.path().join("fim_drift.jsonl");
    let key = if other_key {
        signing_key_of(&other_key_hex())
    } else {
        signing_key_of(AGENT_KEY_HEX)
    };
    let mut rl = RotatingChainLog::<FimDriftPayload>::open_with_clock(
        &active,
        key,
        RotationConfig {
            size_cap_bytes: 1500,
            max_archives: 8,
            file_mode: 0o600,
        },
        Arc::new(NoProtection),
        Ticks::new(64),
    )
    .unwrap();
    for i in 0..rows {
        let row: FimDriftPayload = serde_json::from_value(serde_json::json!({
            "ts": "2025-06-15T15:06:40Z",
            "path": format!("/etc/matrix/file{i}"),
            "op": 1,
            "baseline_sha256": "aa".repeat(32),
            "new_sha256": "bb".repeat(32),
            "modifier_pid": 100 + i,
            "modifier_uid": 0,
            "modifier_comm": "vim",
            "severity": "High",
            "agent_id": hex::encode(AGENT_ID),
        }))
        .expect("a FIM drift row");
        rl.append(row).unwrap();
    }
    rl.checkpoint().unwrap();
    drop(rl);
    let mut out: Vec<(String, Vec<u8>)> = std::fs::read_dir(dir.path())
        .unwrap()
        .flatten()
        .map(|e| {
            (
                e.file_name().to_string_lossy().into_owned(),
                std::fs::read(e.path()).unwrap(),
            )
        })
        .collect();
    out.sort();
    out
}

// ── signed overlays ───────────────────────────────────────────────────────

/// `<overlay>.sig` over `content`, signed by `signers` at `ts` for
/// `agent_id`, as `config overlay sign` writes it.
pub fn overlay_sig(
    kind: OverlayKind,
    content: &[u8],
    signers: &[&str],
    ts: u64,
    agent_id: [u8; 16],
) -> String {
    let sha = nn_core::config::overlay_auth::content_sha256(content);
    let payload = SignedPayload::new_config_overlay_set(
        [0x5c; 32],
        ts,
        agent_id,
        kind,
        sha,
        content.len() as u32,
    );
    let sigs: Vec<[u8; 64]> = signers
        .iter()
        .map(|s| sign(&payload, &admin(s)).unwrap())
        .collect();
    nn_core::config::overlay_auth::OverlaySignature::new(payload, &sigs)
        .unwrap()
        .to_json()
        .unwrap()
}

// ── policy test inputs ────────────────────────────────────────────────────

pub const GOLDEN_CASES: &str = "agent/tests/golden/cases";

/// The decision replay's golden cases, by name, in name order.
pub fn golden_cases() -> Vec<(String, Vec<u8>)> {
    memo("golden_cases", golden_cases_uncached)
}

fn golden_cases_uncached() -> Vec<(String, Vec<u8>)> {
    let mut v: Vec<(String, Vec<u8>)> = std::fs::read_dir(repo(GOLDEN_CASES))
        .unwrap()
        .flatten()
        .filter(|e| e.path().extension().is_some_and(|x| x == "json"))
        .map(|e| {
            (
                e.path().file_stem().unwrap().to_string_lossy().into_owned(),
                std::fs::read(e.path()).unwrap(),
            )
        })
        .collect();
    v.sort();
    v
}

/// The golden cases' events, in case order, as one stream: plain (one
/// `Event` per line) or wrapped (`{"event": …}` per line).
pub fn event_stream(wrapped: bool) -> (String, usize) {
    let mut out = String::new();
    let mut n = 0;
    for (_, bytes) in golden_cases() {
        let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        for item in v["items"].as_array().unwrap() {
            if let Some(ev) = item.get("event") {
                n += 1;
                let line = if wrapped {
                    serde_json::json!({ "event": ev })
                } else {
                    ev.clone()
                };
                out.push_str(&serde_json::to_string(&line).unwrap());
                out.push('\n');
            }
        }
    }
    (out, n)
}

/// The per-rule policies of the golden cases that carry one, by case name.
pub fn golden_candidates() -> Vec<(String, String)> {
    golden_cases()
        .into_iter()
        .filter_map(|(name, bytes)| {
            let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
            v.get("policy")
                .and_then(|p| p.as_str())
                .map(|p| (name, p.to_string()))
        })
        .collect()
}

/// The shipped lists `policy test --config-dir` reads (`configs/*.v1`).
pub fn shipped_lists() -> Vec<Put> {
    memo("shipped_lists", || {
        let mut v: Files = std::fs::read_dir(repo("configs"))
            .unwrap()
            .flatten()
            .filter(|e| e.path().is_file())
            .map(|e| {
                (
                    format!("configs/{}", e.file_name().to_string_lossy()),
                    std::fs::read(e.path()).unwrap(),
                )
            })
            .collect();
        v.sort();
        v
    })
    .into_iter()
    .map(|(n, b)| Put::File(n, b, 0o644))
    .collect()
}
