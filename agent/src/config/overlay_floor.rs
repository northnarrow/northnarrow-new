//! External audit LLMR-014 — the rollback floor of the signed overlays,
//! read from the verified audit chain.
//!
//! [`super::overlay_auth::OverlayGate`] refuses an overlay signed earlier
//! than the newest signature the audit chain accepted for its kind: no
//! rollback to a retired exemption. That floor used to come from a
//! plain-JSON read of `audit.log` — no hash or signature checked — and a
//! log that was missing or unreadable gave no floor at all, without a
//! word: removing the log offline brought every retired signature back.
//!
//! Now the floor is what the chain proves:
//!
//! - every entry after the last floor anchor is verified — its link to the
//!   entry before it, its own hash, the agent's signature — and a genuine
//!   `config_overlay_accepted` / `config_overlay_set` raises the floor of
//!   its kind;
//! - an anchor (`overlay_floor_anchor`, written by a boot whose scan
//!   verified [`ANCHOR_EVERY`] entries after the last one) carries the
//!   floor that boot verified and the hash of the entry it verified up to,
//!   so a boot verifies only what came after it;
//! - when the history is gone or does not verify — a log missing or empty
//!   while the agent's signing key exists, a chain that is not intact, a
//!   key that cannot be read — the floor is reset: no overlay signed
//!   before this boot is loaded (a replayed retired signature is always
//!   older), one signed after it is (`nn-admin config overlay set|sign`).
//!   The reset is a signed `integrity_drift`
//!   (`overlay_rollback_floor_unavailable`) carrying the new floor,
//!   written before anything else this boot appends, so it holds at every
//!   later boot: a break with a reset after it is known, a break with none
//!   is found again.
//!
//! Residual: a log cut back offline to an older prefix that verifies, or
//! the key, its public half and the log all removed (what a fresh install
//! looks like), cannot be told apart on the host; nor a chain forged with
//! the key itself, which an offline reader of an unencrypted disk has.
//! That takes an anchor off the host (Tappa 13).

use std::collections::HashMap;
use std::path::Path;

use common::wire::admin_signed_payload::OverlayKind;
use ed25519_dalek::VerifyingKey;
use serde::{Deserialize, Serialize};

use super::overlay_auth::{drift_entry, entry, AUDIT_OP_ACCEPTED, AUDIT_OP_SET};
use crate::audit::{AuditEntry, AuditEntryDraft, GENESIS_PREV_HASH};

/// Audit op of a floor anchor.
pub const AUDIT_OP_ANCHOR: &str = "overlay_floor_anchor";
/// `integrity_drift` kind of a floor reset.
pub const DRIFT_KIND: &str = "overlay_rollback_floor_unavailable";
/// A boot anchors the floor once its scan verified this many entries after
/// the last anchor: what the next boot verifies stays bounded.
pub const ANCHOR_EVERY: usize = 256;
/// Below this many entries to verify, one thread does it.
const PARALLEL_FROM: usize = 1024;

/// The newest accepted signature of one overlay kind, in an anchor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct FloorRecord {
    kind: String,
    sha256: String,
    signed_ts: u64,
}

/// What an anchor carries (its `extra`).
#[derive(Debug, Clone, Serialize, Deserialize)]
struct AnchorExtra {
    /// `entry_hash` of the last entry the boot verified
    /// ([`GENESIS_PREV_HASH`]: the log was empty).
    tail_hash: String,
    /// Entries that boot verified after the anchor before it.
    verified: usize,
    not_before: Option<u64>,
    floor: Vec<FloorRecord>,
}

/// The rollback floor of the signed overlays, as this boot found the chain.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RollbackFloor {
    /// kind → (sha256 hex, signed ts) of the newest signature the chain
    /// accepted (at a boot, or stored by `set`).
    recorded: HashMap<OverlayKind, (String, u64)>,
    /// No overlay signed before this time (unix seconds) is loaded.
    not_before: Option<u64>,
    /// Why this boot reset the floor. `None`: the chain verified, or there
    /// is none yet (a fresh install).
    reset: Option<String>,
    /// `entry_hash` of the last entry of the log: what the next one chains
    /// from (`None`: that line does not read as an entry).
    tail_hash: Option<String>,
    /// Entries verified after the last anchor.
    verified: usize,
}

impl RollbackFloor {
    /// The floor from `audit_log` — read before this boot bootstraps the
    /// key and the log (a log found missing must not look like a fresh
    /// install). Verified with the signing key at `signing_key_file`, or,
    /// when the key is closed to this process (a restart under the previous
    /// instance's hooks, external audit EVD-001), with its public half
    /// (`agent.sig.pub`), which the same hooks keep from being rewritten.
    pub fn scan(audit_log: &Path, signing_key_file: &Path) -> Self {
        let started = std::time::Instant::now();
        let key = match crate::audit::read_signing_key(signing_key_file) {
            Ok(k) => Ok(Some(k.verifying_key())),
            Err(e) if not_found(&e) => Ok(None),
            Err(e) => {
                let public = crate::audit::verifying_key_path(signing_key_file);
                crate::audit::read_verifying_key(&public)
                    .map(Some)
                    .map_err(|p| {
                        format!(
                            "the agent signing key is unreadable ({e:#}) and so is its public half ({p:#})"
                        )
                    })
            }
        };
        let floor = Self::scan_with(audit_log, key, unix_now());
        tracing::info!(
            verified = floor.verified,
            ms = started.elapsed().as_millis() as u64,
            kinds = floor.recorded.len(),
            not_before = ?floor.not_before,
            reset = floor.reset.is_some(),
            "overlay rollback floor read from the verified audit chain"
        );
        floor
    }

    fn scan_with(audit_log: &Path, key: Result<Option<VerifyingKey>, String>, now: u64) -> Self {
        let bytes = match std::fs::read(audit_log) {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Vec::new(),
            Err(e) => {
                return Self::default().reset_at(now, format!("the audit log is unreadable: {e}"))
            }
        };
        let lines = chain_lines(&bytes);
        let tail_hash = match lines.last() {
            None => Some(GENESIS_PREV_HASH.to_string()),
            Some(l) => serde_json::from_slice::<AuditEntry>(l)
                .ok()
                .map(|e| e.entry_hash),
        };
        let bare = Self {
            tail_hash,
            ..Self::default()
        };
        let key = match key {
            Ok(k) => k,
            Err(why) => return bare.reset_at(now, why),
        };
        let key =
            match (key, lines.is_empty()) {
                (Some(k), false) => k,
                // A fresh install: no chain and no key yet.
                (None, true) => return bare,
                (None, false) => return bare.reset_at(
                    now,
                    "the audit chain is there but the agent signing key is not: its signatures \
                     cannot be checked"
                        .to_string(),
                ),
                (Some(_), true) => return bare.reset_at(
                    now,
                    "the audit log is missing or empty while the agent signing key exists: the \
                     chain's history is gone"
                        .to_string(),
                ),
            };
        let (mut floor, broken) = verify(&lines, &key);
        floor.tail_hash = bare.tail_hash;
        match broken {
            Some(why) => floor.reset_at(now, format!("the audit chain does not verify: {why}")),
            None => floor,
        }
    }

    /// The newest accepted signature of `kind`: (sha256 hex, signed ts).
    pub fn recorded(&self, kind: OverlayKind) -> Option<&(String, u64)> {
        self.recorded.get(&kind)
    }

    /// No overlay signed before this time (unix seconds) is loaded.
    pub fn not_before(&self) -> Option<u64> {
        self.not_before
    }

    /// Why this boot reset the floor.
    pub fn reset(&self) -> Option<&str> {
        self.reset.as_deref()
    }

    /// External audit LLMR-014: what this boot records about the floor,
    /// before anything else it appends
    /// ([`super::overlay_auth::OverlayGate::attest_floor`]): the reset, then
    /// a new anchor when the floor was reset or the chain verified
    /// [`ANCHOR_EVERY`] entries past the last anchor.
    pub(crate) fn entries(&self) -> Vec<AuditEntryDraft> {
        let mut out = Vec::new();
        if let Some(why) = &self.reset {
            out.push(drift_entry(serde_json::json!({
                "kind": DRIFT_KIND,
                "detail": why,
                "not_before": self.not_before,
                "at_boot": true,
            })));
        }
        if let Some(tail) = &self.tail_hash {
            if self.reset.is_some() || self.verified >= ANCHOR_EVERY {
                let mut floor: Vec<FloorRecord> = self
                    .recorded
                    .iter()
                    .map(|(kind, (sha, ts))| FloorRecord {
                        kind: kind.keyword().to_string(),
                        sha256: sha.clone(),
                        signed_ts: *ts,
                    })
                    .collect();
                floor.sort_by(|a, b| a.kind.cmp(&b.kind));
                let anchor = AnchorExtra {
                    tail_hash: tail.clone(),
                    verified: self.verified,
                    not_before: self.not_before,
                    floor,
                };
                if let Ok(extra) = serde_json::to_value(anchor) {
                    out.push(entry(AUDIT_OP_ANCHOR, "success", extra));
                }
            }
        }
        out
    }

    /// Reset the floor: nothing signed before now, or before the newest
    /// signature the chain still shows (a clock set back does not reopen
    /// it), is loaded.
    fn reset_at(mut self, now: u64, why: String) -> Self {
        let newest = self.recorded.values().map(|(_, ts)| ts.saturating_add(1));
        let floor = newest
            .chain([now])
            .chain(self.not_before)
            .max()
            .unwrap_or(now);
        self.not_before = Some(floor);
        self.reset = Some(why);
        self
    }

    fn raise(&mut self, kind: OverlayKind, sha: &str, ts: u64) {
        if self
            .recorded
            .get(&kind)
            .map(|(_, t)| ts >= *t)
            .unwrap_or(true)
        {
            self.recorded.insert(kind, (sha.to_string(), ts));
        }
    }

    fn raise_not_before(&mut self, ts: u64) {
        self.not_before = Some(self.not_before.map_or(ts, |t| t.max(ts)));
    }

    fn absorb_anchor(&mut self, anchor: &AnchorExtra) {
        for r in &anchor.floor {
            if let Some(kind) = OverlayKind::from_keyword(&r.kind) {
                self.raise(kind, &r.sha256, r.signed_ts);
            }
        }
        if let Some(t) = anchor.not_before {
            self.raise_not_before(t);
        }
    }

    /// What a genuine entry says about the floor; true for a reset (it
    /// covers a break before it).
    fn absorb(&mut self, e: &AuditEntry) -> bool {
        if (e.op == AUDIT_OP_ACCEPTED || e.op == AUDIT_OP_SET) && e.result == "success" {
            let x = &e.extra;
            if let (Some(kind), Some(sha), Some(ts)) = (
                x.get("kind")
                    .and_then(|k| k.as_str())
                    .and_then(OverlayKind::from_keyword),
                x.get("sha256").and_then(|s| s.as_str()),
                x.get("signed_ts").and_then(|t| t.as_u64()),
            ) {
                self.raise(kind, sha, ts);
            }
            return false;
        }
        if e.op == crate::self_integrity::AUDIT_OP
            && e.extra.get("kind").and_then(|k| k.as_str()) == Some(DRIFT_KIND)
        {
            if let Some(t) = e.extra.get("not_before").and_then(|t| t.as_u64()) {
                self.raise_not_before(t);
                return true;
            }
        }
        false
    }
}

/// The floor the chain in `lines` proves, verified with `key` from the last
/// anchor on, and the break no reset after it accounts for.
fn verify(lines: &[&[u8]], key: &VerifyingKey) -> (RollbackFloor, Option<String>) {
    let mut floor = RollbackFloor::default();
    let mut start = 0;
    let mut prev = GENESIS_PREV_HASH.to_string();
    if let Some((at, anchor)) = last_anchor(lines, key) {
        floor.absorb_anchor(&anchor);
        let from = if anchor.tail_hash == GENESIS_PREV_HASH {
            Some(0)
        } else {
            (0..at)
                .rev()
                .find(|&i| {
                    serde_json::from_slice::<AuditEntry>(lines[i])
                        .is_ok_and(|e| e.entry_hash == anchor.tail_hash)
                })
                .map(|i| i + 1)
        };
        let Some(from) = from else {
            return (
                floor,
                Some(format!(
                    "the floor anchor at entry {at} verified up to an entry that is no longer before it"
                )),
            );
        };
        start = from;
        prev = anchor.tail_hash;
    }
    let region: Vec<Result<AuditEntry, String>> = lines[start..]
        .iter()
        .map(|l| serde_json::from_slice(l).map_err(|e| e.to_string()))
        .collect();
    let checked = check_all(&region, start, key, PARALLEL_FROM);
    let mut last_break: Option<(usize, String)> = None;
    let mut last_reset: Option<usize> = None;
    for (i, (parsed, genuine)) in region.iter().zip(checked).enumerate() {
        let idx = start + i;
        let entry = match parsed {
            Ok(e) => e,
            Err(e) => {
                last_break = Some((idx, format!("entry {idx} is not an audit entry ({e})")));
                prev.clear();
                continue;
            }
        };
        if entry.prev_hash != prev {
            last_break = Some((
                idx,
                format!("entry {idx} does not chain from the one before it"),
            ));
        }
        prev.clone_from(&entry.entry_hash);
        if let Err(why) = genuine {
            last_break = Some((idx, why));
            continue;
        }
        floor.verified += 1;
        if floor.absorb(entry) {
            last_reset = Some(idx);
        }
    }
    let broken = last_break
        .filter(|(at, _)| last_reset.is_none_or(|r| r < *at))
        .map(|(_, why)| why);
    (floor, broken)
}

/// [`crate::audit::verify_entry`] over `region` (entry `start` first), on
/// several threads from `parallel_from` entries — a boot after a long run.
fn check_all(
    region: &[Result<AuditEntry, String>],
    start: usize,
    key: &VerifyingKey,
    parallel_from: usize,
) -> Vec<Result<(), String>> {
    let check = |i: usize, e: &Result<AuditEntry, String>| match e {
        Ok(e) => crate::audit::verify_entry(start + i, e, key).map_err(|e| e.to_string()),
        Err(_) => Ok(()),
    };
    let threads = std::thread::available_parallelism()
        .map_or(1, |n| n.get())
        .min(8);
    if region.len() < parallel_from || threads < 2 {
        return region
            .iter()
            .enumerate()
            .map(|(i, e)| check(i, e))
            .collect();
    }
    let size = region.len().div_ceil(threads);
    std::thread::scope(|s| {
        let parts: Vec<_> = region
            .chunks(size)
            .enumerate()
            .map(|(n, part)| {
                let len = part.len();
                let handle = s.spawn(move || {
                    part.iter()
                        .enumerate()
                        .map(|(i, e)| check(n * size + i, e))
                        .collect::<Vec<_>>()
                });
                (len, handle)
            })
            .collect();
        parts
            .into_iter()
            .flat_map(|(len, handle)| {
                handle
                    .join()
                    .unwrap_or_else(|_| vec![Err("verification failed".to_string()); len])
            })
            .collect()
    })
}

/// The last anchor in `lines` the agent signed: its index and what it says.
fn last_anchor(lines: &[&[u8]], key: &VerifyingKey) -> Option<(usize, AnchorExtra)> {
    lines.iter().enumerate().rev().find_map(|(i, l)| {
        if op_of(l) != Some(AUDIT_OP_ANCHOR.as_bytes()) {
            return None;
        }
        let e: AuditEntry = serde_json::from_slice(l).ok()?;
        if e.op != AUDIT_OP_ANCHOR || crate::audit::verify_entry(i, &e, key).is_err() {
            return None;
        }
        serde_json::from_value::<AnchorExtra>(e.extra)
            .ok()
            .map(|a| (i, a))
    })
}

/// The `op` of a serialised entry, without parsing it: it follows `ts` and
/// `agent_id` within the first bytes (an `"op"` key in `extra` comes later).
fn op_of(line: &[u8]) -> Option<&[u8]> {
    const KEY: &[u8] = b"\"op\":\"";
    let head = &line[..line.len().min(160)];
    let at = head.windows(KEY.len()).position(|w| w == KEY)? + KEY.len();
    let rest = &line[at..];
    let end = rest.iter().position(|&c| c == b'"')?;
    Some(&rest[..end])
}

/// The entries of the log, one per line (empty lines skipped, as the
/// writer's own reader does). A last line cut short is left out unless it
/// reads as an entry: what `chainlog::repair_torn_tail` keeps or drops when
/// the log opens.
fn chain_lines(bytes: &[u8]) -> Vec<&[u8]> {
    let mut lines: Vec<&[u8]> = bytes.split(|&c| c == b'\n').collect();
    // After a final newline the last piece is empty; otherwise it is the
    // unterminated fragment.
    let fragment = lines.pop().filter(|f| !f.is_empty());
    lines.retain(|l| !l.is_empty());
    if let Some(f) = fragment {
        if serde_json::from_slice::<AuditEntry>(f).is_ok() {
            lines.push(f);
        }
    }
    lines
}

fn not_found(e: &anyhow::Error) -> bool {
    e.root_cause()
        .downcast_ref::<std::io::Error>()
        .is_some_and(|io| io.kind() == std::io::ErrorKind::NotFound)
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::{AgentSigningKey, AuditLog};
    use std::path::PathBuf;

    const NOW: u64 = 1_800_000_000;
    const PCA: OverlayKind = OverlayKind::ProcessCommAllowlist;

    /// A real signed chain in a temporary directory.
    struct Chain {
        _dir: tempfile::TempDir,
        audit: PathBuf,
        key: PathBuf,
    }

    impl Chain {
        fn new() -> Self {
            let dir = tempfile::tempdir().unwrap();
            Self {
                audit: dir.path().join("audit.log"),
                key: dir.path().join("agent.sig.key"),
                _dir: dir,
            }
        }

        fn open(&self) -> AuditLog {
            let key = AgentSigningKey::load_or_bootstrap(&self.key).unwrap();
            AuditLog::open(&self.audit, key, [7; 16]).unwrap()
        }

        fn append(&self, op: &str, extra: serde_json::Value) {
            self.open().append(entry(op, "success", extra)).unwrap();
        }

        fn accepted(&self, kind: OverlayKind, ts: u64) {
            self.append(
                AUDIT_OP_ACCEPTED,
                serde_json::json!({ "kind": kind.keyword(), "sha256": "aa", "signed_ts": ts }),
            );
        }

        fn noise(&self, n: usize) {
            let mut log = self.open();
            for i in 0..n {
                log.append(entry(
                    "agent_boot",
                    "success",
                    serde_json::json!({ "n": i }),
                ))
                .unwrap();
            }
        }

        fn verifying_key(&self) -> VerifyingKey {
            crate::audit::read_signing_key(&self.key)
                .unwrap()
                .verifying_key()
        }

        fn scan(&self) -> RollbackFloor {
            RollbackFloor::scan_with(&self.audit, Ok(Some(self.verifying_key())), NOW)
        }

        /// What a boot does: scan, then write the floor entries first.
        fn boot(&self) -> RollbackFloor {
            let floor = self.scan();
            let mut log = self.open();
            for draft in floor.entries() {
                log.append(draft).unwrap();
            }
            floor
        }

        fn lines(&self) -> Vec<String> {
            std::fs::read_to_string(&self.audit)
                .unwrap()
                .lines()
                .map(str::to_string)
                .collect()
        }

        fn write_lines(&self, lines: &[String]) {
            std::fs::write(&self.audit, lines.join("\n") + "\n").unwrap();
        }
    }

    #[test]
    fn a_verified_chain_gives_the_newest_signature_per_kind() {
        let c = Chain::new();
        c.accepted(PCA, 500);
        c.accepted(PCA, 300);
        c.accepted(OverlayKind::FimPaths, 7);
        let f = c.scan();
        assert_eq!(f.reset(), None);
        assert_eq!(f.not_before(), None);
        assert_eq!(f.recorded(PCA), Some(&("aa".to_string(), 500)));
        assert_eq!(f.recorded(OverlayKind::FimPaths).map(|r| r.1), Some(7));
        // nothing to record: no reset, too few entries for an anchor
        assert!(f.entries().is_empty());
    }

    #[test]
    fn a_fresh_install_has_no_floor_and_no_reset() {
        let dir = tempfile::tempdir().unwrap();
        let f = RollbackFloor::scan(&dir.path().join("audit.log"), &dir.path().join("k"));
        assert_eq!(
            f,
            RollbackFloor {
                tail_hash: Some(GENESIS_PREV_HASH.to_string()),
                ..RollbackFloor::default()
            }
        );
    }

    /// The finding: a log removed while the key stays gave no floor.
    #[test]
    fn a_missing_log_with_the_key_present_resets_the_floor() {
        let c = Chain::new();
        c.accepted(PCA, 500);
        std::fs::remove_file(&c.audit).unwrap();
        let f = RollbackFloor::scan(&c.audit, &c.key);
        assert!(
            f.reset().is_some_and(|r| r.contains("history is gone")),
            "{f:?}"
        );
        assert!(f.not_before().is_some_and(|t| t > 1_700_000_000));
        // an empty log is the same
        std::fs::write(&c.audit, "").unwrap();
        assert!(c.scan().reset().is_some());
        assert_eq!(c.scan().not_before(), Some(NOW));
    }

    #[test]
    fn an_edited_or_removed_floor_entry_resets() {
        let c = Chain::new();
        c.accepted(PCA, 500);
        c.noise(2);
        let mut lines = c.lines();
        lines[0] = lines[0].replace("\"signed_ts\":500", "\"signed_ts\":5");
        c.write_lines(&lines);
        let f = c.scan();
        assert!(f.reset().is_some_and(|r| r.contains("entry 0")), "{f:?}");
        assert_eq!(f.not_before(), Some(NOW));
        // removed: the next entry no longer chains
        let c = Chain::new();
        c.noise(1);
        c.accepted(PCA, 500);
        c.noise(1);
        let mut lines = c.lines();
        lines.remove(1);
        c.write_lines(&lines);
        assert!(c
            .scan()
            .reset()
            .is_some_and(|r| r.contains("does not chain")));
    }

    /// Hashes recomputed after removing a floor entry keep the chain linked
    /// but not signed. Every entry after the last anchor is checked, so an
    /// entry the agent appended on top later does not vouch for them.
    #[test]
    fn a_rehashed_history_is_found_under_a_genuine_tail() {
        let c = Chain::new();
        c.accepted(PCA, 500);
        c.noise(2);
        let mut lines = c.lines();
        lines.remove(0);
        let mut prev = GENESIS_PREV_HASH.to_string();
        for l in lines.iter_mut() {
            let mut e: AuditEntry = serde_json::from_str(l).unwrap();
            let sig = std::mem::take(&mut e.agent_sig);
            e.prev_hash = prev.clone();
            e.entry_hash.clear();
            e.entry_hash = hex::encode(crate::audit::compute_entry_hash(&e).unwrap());
            e.agent_sig = sig;
            prev = e.entry_hash.clone();
            *l = serde_json::to_string(&e).unwrap();
        }
        c.write_lines(&lines);
        c.noise(1);
        let f = c.scan();
        assert!(
            f.reset().is_some_and(|r| r.contains("agent_sig invalid")),
            "{f:?}"
        );
        assert_eq!(f.recorded(PCA), None);
    }

    /// The reset written by the boot that found a break covers it at the
    /// next boots: the floor stays where it was set, without a new reset.
    #[test]
    fn a_recorded_reset_covers_its_break_and_holds() {
        let c = Chain::new();
        c.accepted(PCA, 500);
        c.noise(1);
        let mut lines = c.lines();
        lines.remove(0);
        c.write_lines(&lines);
        assert!(c.boot().reset().is_some());
        let again = c.scan();
        assert_eq!(again.reset(), None, "{again:?}");
        assert_eq!(again.not_before(), Some(NOW));
        // a new break after the reset is found again
        c.noise(2);
        let mut lines = c.lines();
        let n = lines.len();
        lines.remove(n - 2);
        c.write_lines(&lines);
        assert!(c.scan().reset().is_some());
    }

    /// After a removed log the reset is the first entry of the new chain:
    /// a log cut back to any entry of that boot still carries it.
    #[test]
    fn a_reset_after_a_removed_log_survives_a_cut_back_log() {
        let c = Chain::new();
        c.accepted(PCA, 500);
        std::fs::remove_file(&c.audit).unwrap();
        c.boot();
        c.noise(3);
        let lines = c.lines();
        c.write_lines(&lines[..1]);
        let f = c.scan();
        assert_eq!(f.reset(), None, "{f:?}");
        assert_eq!(f.not_before(), Some(NOW));
        std::fs::write(&c.audit, "").unwrap();
        assert!(c.scan().reset().is_some());
    }

    #[test]
    fn the_key_gone_with_the_chain_left_resets() {
        let c = Chain::new();
        c.accepted(PCA, 500);
        let f = RollbackFloor::scan_with(&c.audit, Ok(None), NOW);
        assert!(f.reset().is_some_and(|r| r.contains("signing key is not")));
        let f = RollbackFloor::scan_with(&c.audit, Err("unreadable".into()), NOW);
        assert_eq!(f.reset(), Some("unreadable"));
    }

    /// A chain signed with another key (forged with a key of its own) is
    /// not the agent's.
    #[test]
    fn a_chain_signed_by_another_key_resets() {
        let c = Chain::new();
        c.accepted(PCA, 500);
        let other = ed25519_dalek::SigningKey::from_bytes(&[5; 32]).verifying_key();
        let f = RollbackFloor::scan_with(&c.audit, Ok(Some(other)), NOW);
        assert!(f.reset().is_some(), "{f:?}");
    }

    /// A clock set back does not reopen the floor: a reset is never below
    /// the newest signature the chain still shows.
    #[test]
    fn a_reset_is_never_below_the_newest_signature_seen() {
        let c = Chain::new();
        c.accepted(PCA, NOW + 50);
        let mut lines = c.lines();
        lines.push("{not json".to_string());
        c.write_lines(&lines);
        let f = c.scan();
        assert!(f.reset().is_some_and(|r| r.contains("not an audit entry")));
        assert_eq!(f.not_before(), Some(NOW + 51));
    }

    #[test]
    fn a_torn_last_line_is_left_out() {
        let c = Chain::new();
        c.accepted(PCA, 500);
        let good = std::fs::read_to_string(&c.audit).unwrap();
        std::fs::write(&c.audit, format!("{good}{{\"ts\":\"2026-10-14T00:00")).unwrap();
        let f = c.scan();
        assert_eq!(f.reset(), None, "{f:?}");
        assert_eq!(f.recorded(PCA).map(|r| r.1), Some(500));
        // a bad line that is not the last one is not torn: it breaks the chain
        std::fs::write(&c.audit, format!("{{not json\n{good}")).unwrap();
        assert!(c.scan().reset().is_some());
    }

    /// External audit AUT-009, the residual the triage kept
    /// (`recorded_signatures_survives_torn_utf8_tail`): the floor was read
    /// with `read_to_string` before the log's torn tail was repaired, so a
    /// last write cut inside a multi-byte character emptied it for that
    /// boot, without a word. serde_json leaves non-ASCII text unescaped, so
    /// such a cut is a power loss away. The floor is read as bytes and the
    /// fragment left out, as the repair drops it.
    #[test]
    fn the_floor_survives_a_torn_utf8_tail() {
        let c = Chain::new();
        c.append(
            AUDIT_OP_ACCEPTED,
            serde_json::json!({
                "kind": PCA.keyword(), "sha256": "aa", "signed_ts": 500,
                "note": "perché è già così",
            }),
        );
        let mut torn = std::fs::read(&c.audit).unwrap();
        assert!(!torn.is_ascii(), "the entry is stored with its accents");
        // the next write cut between the two bytes of "è" (0xC3 0xA8)
        torn.extend_from_slice(b"{\"ts\":\"2026-10-15T00:00:00Z\",\"note\":\"gi");
        torn.push(0xC3);
        std::fs::write(&c.audit, &torn).unwrap();
        assert!(std::str::from_utf8(&torn).is_err());
        let f = c.scan();
        assert_eq!(f.reset(), None, "{f:?}");
        assert_eq!(f.recorded(PCA).map(|r| r.1), Some(500));
        // once the log opens (the fragment dropped, the repair recorded),
        // the floor is the same
        drop(c.open());
        assert!(std::fs::read_to_string(&c.audit).is_ok());
        let after = c.scan();
        assert_eq!(after.reset(), None, "{after:?}");
        assert_eq!(after.recorded(PCA).map(|r| r.1), Some(500));
    }

    /// A log that is there but cannot be read resets the floor (an ERROR
    /// and a signed record at the boot), never leaves it empty in silence.
    #[test]
    fn an_unreadable_log_resets_the_floor() {
        let c = Chain::new();
        c.accepted(PCA, 500);
        std::fs::remove_file(&c.audit).unwrap();
        std::fs::create_dir(&c.audit).unwrap();
        let f = c.scan();
        assert!(f.reset().is_some_and(|r| r.contains("unreadable")), "{f:?}");
        assert_eq!(f.not_before(), Some(NOW));
        assert!(f.entries().iter().any(|e| e.extra["kind"] == DRIFT_KIND));
    }

    /// The anchor carries the floor it verified: a boot verifies only what
    /// came after it, and an edit before it changes nothing.
    #[test]
    fn an_anchor_bounds_what_the_next_boot_verifies() {
        let c = Chain::new();
        c.accepted(PCA, 500);
        c.noise(ANCHOR_EVERY);
        let first = c.boot();
        assert_eq!(first.verified, ANCHOR_EVERY + 1);
        assert_eq!(first.entries().len(), 1, "an anchor, no reset");
        c.noise(3);
        let next = c.scan();
        assert_eq!(next.reset(), None);
        assert_eq!(next.recorded(PCA).map(|r| r.1), Some(500));
        assert_eq!(next.verified, 4, "the anchor and what follows it");
        let mut lines = c.lines();
        lines[0] = lines[0].replace("\"signed_ts\":500", "\"signed_ts\":5");
        c.write_lines(&lines);
        let after = c.scan();
        assert_eq!(after.reset(), None);
        assert_eq!(after.recorded(PCA).map(|r| r.1), Some(500));
        // a forged anchor at the end is not one: it fails as an entry
        let forged = lines
            .iter()
            .find(|l| l.contains(AUDIT_OP_ANCHOR))
            .unwrap()
            .replace("\"signed_ts\":500", "\"signed_ts\":1");
        lines.push(forged);
        c.write_lines(&lines);
        assert!(c.scan().reset().is_some());
    }

    #[test]
    fn several_threads_check_like_one() {
        let c = Chain::new();
        c.noise(40);
        let mut lines = c.lines();
        lines[33] = lines[33].replace("\"n\":", "\"m\":");
        let region: Vec<Result<AuditEntry, String>> = lines
            .iter()
            .map(|l| serde_json::from_str(l).map_err(|e| e.to_string()))
            .collect();
        let key = c.verifying_key();
        let one = check_all(&region, 0, &key, usize::MAX);
        let many = check_all(&region, 0, &key, 2);
        assert_eq!(one, many);
        assert_eq!(one.iter().filter(|r| r.is_err()).count(), 1);
        assert!(one[33].as_ref().is_err_and(|e| e.contains("entry 33")));
    }

    #[test]
    fn op_of_reads_the_entry_op_not_one_in_extra() {
        let c = Chain::new();
        c.append(
            "rotate_keys_add",
            serde_json::json!({ "op": AUDIT_OP_ANCHOR }),
        );
        let line = c.lines().remove(0);
        assert_eq!(op_of(line.as_bytes()), Some(&b"rotate_keys_add"[..]));
    }
}
