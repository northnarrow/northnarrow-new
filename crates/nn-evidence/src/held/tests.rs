//! Lot 379 (pre-alpha F7-1, F3b-6): what the audit log holds, and when a
//! hold ends. On main nothing was held: `nn-admin status` said
//! `degradations: none` over a cut chain, an unauthorized overlay and a
//! modified default list (Phase 7 §2.7, §2.8).

use std::path::{Path, PathBuf};

use super::*;
use crate::audit::{AgentBuild, AuditEntryDraft, AuditLog};
use crate::chain_anchor::ChainFinding;
use crate::chain_host::testing::{helds, TestKey};

fn paths() -> (tempfile::TempDir, PathBuf, PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let key = dir.path().join("agent.sig.key");
    let log = dir.path().join("audit.log");
    (dir, key, log)
}

fn open(key: &Path, log: &Path) -> AuditLog<TestKey> {
    AuditLog::open(log, TestKey::load_or_bootstrap(key).unwrap(), [1; 16]).unwrap()
}

fn draft(op: &str, result: &str, extra: serde_json::Value) -> AuditEntryDraft {
    AuditEntryDraft {
        op: op.to_string(),
        extra,
        key_fp: "agent-self".to_string(),
        cosigner_fps: Vec::new(),
        result: result.to_string(),
        client_pid: 1,
        client_uid: 0,
        client_comm: "northnarrow-agent".to_string(),
        client_exe: None,
    }
}

fn drift(kind: &str, detail: &str) -> AuditEntryDraft {
    draft(
        INTEGRITY_DRIFT_OP,
        "detected",
        serde_json::json!({ "kind": kind, "detail": detail, "at_boot": true }),
    )
}

fn cleared(kind: &str, detail: &str) -> AuditEntryDraft {
    draft(
        INTEGRITY_CLEARED_OP,
        "cleared",
        serde_json::json!({ "kind": kind, "detail": detail, "at_boot": false }),
    )
}

fn ack(through: u64) -> AuditEntryDraft {
    let mut d = draft(
        ACK_OP,
        "success",
        serde_json::json!({ "through_row": through, "note": "investigated" }),
    );
    d.key_fp = "0a1b2c3d".to_string();
    d
}

fn boot(log: &mut AuditLog<TestKey>) -> u64 {
    let build = AgentBuild {
        version: "0.0.0-test",
        features: Vec::new(),
        bpf_guard_enforce: false,
    };
    log.boot_probe(None, "verified", "attested", &build).unwrap();
    log.rows() - 1
}

fn cut(chain: &str, log_file: &Path) -> AuditEntryDraft {
    ChainFinding::new(
        chain,
        log_file,
        "chain_truncated",
        "the anchored head is not in the file: 3 rows removed",
    )
    .draft()
}

fn kinds(log: &AuditLog<TestKey>) -> Vec<String> {
    log.held()
        .findings()
        .iter()
        .map(|f| format!("{}:{}", f.kind, f.subject))
        .collect()
}

/// The four signed findings Phase 7 saw unseen are held, each by its class.
#[test]
fn the_findings_phase_7_saw_unseen_are_held() {
    for kind in ["chain_truncated", "chain_rewritten", "chain_verify_failed"] {
        assert_eq!(hold_of(kind, "detected"), Hold::UntilAcknowledged, "{kind}");
    }
    for kind in ["unauthorized_overlay", "default_list_modified", "mount_not_canonical"] {
        assert_eq!(hold_of(kind, "detected"), Hold::WhileFound, "{kind}");
    }
    // a finding that failed to repair holds too (a COMBAT chain not torn down)
    assert_eq!(hold_of("combat_reconcile", "failed"), Hold::WhileFound);
    // not findings: a repair, a note, an end
    for result in ["repaired", "recorded", "cleared", "success"] {
        assert_eq!(hold_of("combat_reconcile", result), Hold::NotHeld, "{result}");
    }
    // shown by the registry already, ended by their finders
    for (kind, why) in NOT_HELD_KINDS {
        assert_eq!(hold_of(kind, "detected"), Hold::NotHeld, "{kind}: {why}");
        assert!(!EVIDENCE_KINDS.contains(kind), "{kind} in both lists");
    }
}

/// F7-1, case C2: a cut chain is held across the agent's restarts (the
/// walk at the open) until a signed acknowledgement covers its row; a start
/// does not end it.
#[test]
fn a_cut_chain_is_held_across_a_restart_until_a_signed_acknowledgement() {
    let (_d, key, path) = paths();
    let mut log = open(&key, &path);
    boot(&mut log);
    log.append(cut("detections", &path)).unwrap();
    let row = log.rows() - 1;
    assert_eq!(kinds(&log), ["chain_truncated:detections"]);
    let f = &log.held().findings()[0];
    assert_eq!((f.last_row, f.rows, f.hold), (row, 1, Hold::UntilAcknowledged));
    let line = log.held().lines()[0].clone();
    assert!(line.starts_with("chain_truncated (detections) — signed "), "{line}");
    assert!(line.contains(&format!("(audit row {row})")), "{line}");
    assert!(line.contains("held until acknowledged"), "{line}");
    drop(log);
    // the restart: read again from the chain, and its start ends nothing
    let mut log = open(&key, &path);
    assert_eq!(kinds(&log), ["chain_truncated:detections"]);
    boot(&mut log);
    assert_eq!(kinds(&log), ["chain_truncated:detections"]);
    // the next start's boot verify signs it again: one finding, two rows
    log.append(cut("detections", &path)).unwrap();
    let again = log.rows() - 1;
    let f = &log.held().findings()[0];
    assert_eq!((f.rows, f.last_row), (2, again));
    // an acknowledgement of the first row only does not cover the second
    log.append(ack(row)).unwrap();
    assert_eq!(kinds(&log), ["chain_truncated:detections"]);
    log.append(ack(again)).unwrap();
    assert!(log.held().is_empty(), "{:?}", log.held());
    drop(log);
    assert!(open(&key, &path).held().is_empty());
}

/// An acknowledgement covers the rows before its own, never a later one:
/// one that names a row in the future (or past its own) covers only what
/// was there when it was signed.
#[test]
fn an_acknowledgement_never_covers_a_later_row() {
    let (_d, key, path) = paths();
    let mut log = open(&key, &path);
    log.append(cut("audit", &path)).unwrap();
    log.append(ack(u64::MAX)).unwrap();
    assert!(log.held().is_empty());
    log.append(cut("netflow", &path)).unwrap();
    assert_eq!(kinds(&log), ["chain_truncated:netflow"]);
    drop(log);
    assert_eq!(kinds(&open(&key, &path)), ["chain_truncated:netflow"]);
}

/// F7-1, case (a) and (b): an unauthorized overlay and a modified default
/// list are held while found — until the check signs its end, or the next
/// start (which signs them again if they still hold), or an acknowledgement.
#[test]
fn a_config_finding_is_held_while_found() {
    let (_d, key, path) = paths();
    let mut log = open(&key, &path);
    boot(&mut log);
    let overlay = "process-comm-allowlist (/etc/northnarrow/process-comm-allowlist.local): no \
                   signature file";
    log.append(drift("unauthorized_overlay", overlay)).unwrap();
    log.append(drift("default_list_modified", "fim-paths (/usr/share/northnarrow/fim-paths.v1)"))
        .unwrap();
    assert_eq!(log.held().findings().len(), 2);
    drop(log);
    // held across the restart's open, until its start checks again
    let mut log = open(&key, &path);
    assert_eq!(log.held().findings().len(), 2);
    boot(&mut log);
    assert!(log.held().is_empty(), "{:?}", log.held());
    // still there at that start: signed again, held again
    log.append(drift("unauthorized_overlay", overlay)).unwrap();
    // a cleared row of another detail ends nothing; of its own, ends it
    log.append(cleared("unauthorized_overlay", "another overlay")).unwrap();
    assert_eq!(log.held().findings().len(), 1);
    log.append(cleared("unauthorized_overlay", overlay)).unwrap();
    assert!(log.held().is_empty());
    // or the operator acknowledges it
    log.append(drift("mount_not_canonical", "a bind over /var/lib/northnarrow")).unwrap();
    let row = log.rows() - 1;
    log.append(ack(row)).unwrap();
    assert!(log.held().is_empty());
}

/// A start or a `cleared` row never ends an evidence finding: only an
/// acknowledgement does.
#[test]
fn a_start_or_a_cleared_row_never_ends_an_evidence_finding() {
    let (_d, key, path) = paths();
    let mut log = open(&key, &path);
    let detail = "the last 4194304 bytes do not verify: entry 159: prev_hash";
    let mut verify = drift("chain_verify_failed", detail);
    verify.extra["chain"] = "detections".into();
    log.append(verify).unwrap();
    log.append(cleared("chain_verify_failed", detail)).unwrap();
    boot(&mut log);
    assert_eq!(kinds(&log), ["chain_verify_failed:detections"]);
}

/// A row that ends a hold counts only when its signature verifies with the
/// log's key: one copied in from a log of another key (a line written into
/// the file by hand) launders nothing at the next open.
#[test]
fn a_row_not_signed_by_the_log_s_key_ends_no_hold() {
    let (_d, key, path) = paths();
    let mut log = open(&key, &path);
    log.append(cut("detections", &path)).unwrap();
    let row = log.rows() - 1;
    log.append(drift("unauthorized_overlay", "x.local")).unwrap();
    drop(log);
    // the same rows, signed by another key, appended to the file
    let (_o, other_key, other) = paths();
    let mut forger = open(&other_key, &other);
    for _ in 0..row + 2 {
        forger.append(draft("pad", "success", serde_json::json!({}))).unwrap();
    }
    forger.append(ack(row + 1)).unwrap();
    boot(&mut forger);
    let lines = std::fs::read_to_string(&other).unwrap();
    let forged: Vec<&str> = lines.lines().rev().take(2).collect();
    let mut file = std::fs::OpenOptions::new().append(true).open(&path).unwrap();
    for l in forged.iter().rev() {
        use std::io::Write;
        writeln!(file, "{l}").unwrap();
    }
    drop(file);
    let log = open(&key, &path);
    assert_eq!(
        kinds(&log),
        ["chain_truncated:detections", "unauthorized_overlay:x.local"]
    );
    // the same rows signed by the log's own key do end them (the control)
    drop(log);
    let mut log = open(&key, &path);
    log.append(ack(log.rows() - 1)).unwrap();
    assert!(log.held().is_empty());
}

/// What is not a finding is not held: a degradation the registry shows and
/// ends itself, a repair, a note, a row without a kind.
#[test]
fn rows_that_are_no_finding_are_not_held() {
    let (_d, key, path) = paths();
    let mut log = open(&key, &path);
    log.append(drift("subsystem_degraded", "exec sensor on its fallback")).unwrap();
    log.append(drift("pin_lock_missing", "the lock is gone")).unwrap();
    log.append(drift("profile_downgraded", "alpha after enforcing")).unwrap();
    log.append(draft(
        INTEGRITY_DRIFT_OP,
        "repaired",
        serde_json::json!({ "kind": "combat_reconcile", "detail": "torn down" }),
    ))
    .unwrap();
    log.append(draft(
        INTEGRITY_DRIFT_OP,
        "recorded",
        serde_json::json!({ "kind": "weakening_env", "detail": "NN_X=1" }),
    ))
    .unwrap();
    log.append(draft(
        INTEGRITY_DRIFT_OP,
        "detected",
        serde_json::json!({ "ring": "exec", "dropped_since_last_sample": 3 }),
    ))
    .unwrap();
    assert!(log.held().is_empty(), "{:?}", log.held());
}

/// The host is told what the log holds at every open (nothing included)
/// and at each change — not at a row that changes nothing.
#[test]
fn the_host_is_told_at_the_open_and_at_each_change() {
    let (_d, key, path) = paths();
    let _ = helds::take(&path);
    let mut log = open(&key, &path);
    assert_eq!(helds::take(&path), vec![Vec::<String>::new()]);
    log.append(draft("unlock", "success", serde_json::json!({}))).unwrap();
    assert!(helds::take(&path).is_empty());
    log.append(cut("audit", &path)).unwrap();
    let told = helds::take(&path);
    assert_eq!(told.len(), 1);
    assert!(told[0][0].starts_with("chain_truncated (audit)"), "{told:?}");
    log.append(ack(log.rows() - 1)).unwrap();
    assert_eq!(helds::take(&path), vec![Vec::<String>::new()]);
    // a log kept in memory (a refused start's fallback) tells nothing
    let mut memory = AuditLog::in_memory(TestKey::fresh(), [1; 16]);
    memory.append(cut("audit", &path)).unwrap();
    assert_eq!(memory.held().findings().len(), 1);
    assert!(helds::take(&path).is_empty());
}

/// Past [`MAX_HELD`] findings are counted, not listed, and an
/// acknowledgement through the newest row covers them too.
#[test]
fn past_the_cap_findings_are_counted_and_acknowledged() {
    let (_d, key, path) = paths();
    let mut log = open(&key, &path);
    for i in 0..MAX_HELD + 3 {
        log.append(drift("unit_dropin", &format!("/etc/systemd/system/x.d/{i}.conf")))
            .unwrap();
    }
    assert_eq!(log.held().findings().len(), MAX_HELD);
    assert_eq!(log.held().more(), 3);
    let lines = log.held().lines();
    assert_eq!(lines.len(), MAX_HELD + 1);
    assert!(lines[MAX_HELD].contains("3 more held integrity row(s)"), "{lines:?}");
    let newest = log.held().newest_row().unwrap();
    assert_eq!(newest, log.rows() - 1);
    assert_eq!(log.held().covered_by(newest), MAX_HELD as u64 + 3);
    log.append(ack(newest)).unwrap();
    assert!(log.held().is_empty());
}

/// A detail longer than [`DETAIL_CHARS`] is cut, said with an ellipsis.
#[test]
fn a_long_detail_is_cut() {
    let (_d, key, path) = paths();
    let mut log = open(&key, &path);
    log.append(drift("config_overlay", &"x".repeat(DETAIL_CHARS + 50))).unwrap();
    let f = &log.held().findings()[0];
    assert_eq!(f.detail.chars().count(), DETAIL_CHARS + 1);
    assert!(f.detail.ends_with('…'));
}
