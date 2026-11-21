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
    log.boot_probe(None, "verified", "attested", &build)
        .unwrap();
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
    for kind in [
        "unauthorized_overlay",
        "default_list_modified",
        "mount_not_canonical",
    ] {
        assert_eq!(hold_of(kind, "detected"), Hold::WhileFound, "{kind}");
    }
    // a finding that failed to repair holds too (a COMBAT chain not torn down)
    assert_eq!(hold_of("combat_reconcile", "failed"), Hold::WhileFound);
    // not findings: a repair, a note, an end
    for result in ["repaired", "recorded", "cleared", "success"] {
        assert_eq!(
            hold_of("combat_reconcile", result),
            Hold::NotHeld,
            "{result}"
        );
    }
    // shown by the registry already, ended by their finders
    for (kind, why) in NOT_HELD_KINDS {
        assert_eq!(hold_of(kind, "detected"), Hold::NotHeld, "{kind}: {why}");
        assert!(!EVIDENCE_KINDS.contains(kind), "{kind} in both lists");
    }
}

/// Phase 7b F7-6: a crash or an OOM of the agent (the witness's
/// `role_vacated`, signed by the start that follows it) and the watchdog's
/// death (`watchdog_gone`, then its `cleared` when a new one runs) are held
/// until acknowledged: the restart the death caused, a later start, the
/// round's end of it — none ends it. On main the status said `sensors: OK`
/// after each.
#[test]
fn an_agent_or_watchdog_death_is_held_until_acknowledged() {
    for kind in DEATH_KINDS {
        assert_eq!(hold_of(kind, "detected"), Hold::UntilAcknowledged, "{kind}");
        assert!(!EVIDENCE_KINDS.contains(kind), "{kind} in both lists");
    }
    let (_d, key, path) = paths();
    let mut log = open(&key, &path);
    boot(&mut log);
    let crash = "watchdog 812 at 1795240000: role_vacated: the agent (pid 4410) left its role: \
                 killed by SIGKILL (row hash 0a1b2c3d4e5f6a7b)";
    log.append(drift("witness_row", crash)).unwrap();
    let gone = "the verified watchdog (pid 812) no longer runs; a new watchdog (pid 901) is \
                verified";
    log.append(drift("watchdog_gone", gone)).unwrap();
    log.append(cleared("watchdog_gone", gone)).unwrap();
    log.append(drift(
        "witness_row_uncertified",
        "watchdog 901: witness_opened",
    ))
    .unwrap();
    let line = log.held().lines()[0].clone();
    assert!(
        line.starts_with("witness_row — signed ") && line.contains("held until acknowledged"),
        "{line}"
    );
    drop(log);
    let mut log = open(&key, &path);
    boot(&mut log);
    assert_eq!(
        kinds(&log),
        [
            format!("witness_row:{crash}"),
            format!("watchdog_gone:{gone}"),
            "witness_row_uncertified:watchdog 901: witness_opened".to_string()
        ]
    );
    log.append(ack(log.rows() - 1)).unwrap();
    assert!(log.held().is_empty());
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
    assert_eq!(
        (f.last_row, f.rows, f.hold),
        (row, 1, Hold::UntilAcknowledged)
    );
    let line = log.held().lines()[0].clone();
    assert!(
        line.starts_with("chain_truncated (detections) — signed "),
        "{line}"
    );
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
    let line = log.held().lines()[0].clone();
    assert!(
        line.contains(&format!(
            "signed 2 times since {}, last {} (audit row {again})",
            f.first_ts, f.last_ts
        )),
        "{line}"
    );
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
    log.append(drift(
        "default_list_modified",
        "fim-paths (/usr/share/northnarrow/fim-paths.v1)",
    ))
    .unwrap();
    assert_eq!(log.held().findings().len(), 2);
    let line = log.held().lines()[0].clone();
    assert!(
        line.starts_with("unauthorized_overlay — signed "),
        "the detail is the subject, said once: {line}"
    );
    assert!(
        line.contains("— held while found, or until acknowledged: process-comm-allowlist"),
        "{line}"
    );
    drop(log);
    // held across the restart's open, until its start checks again
    let mut log = open(&key, &path);
    assert_eq!(log.held().findings().len(), 2);
    boot(&mut log);
    assert!(log.held().is_empty(), "{:?}", log.held());
    // still there at that start: signed again, held again
    log.append(drift("unauthorized_overlay", overlay)).unwrap();
    // a cleared row of another detail ends nothing; of its own, ends it
    log.append(cleared("unauthorized_overlay", "another overlay"))
        .unwrap();
    assert_eq!(log.held().findings().len(), 1);
    log.append(cleared("unauthorized_overlay", overlay))
        .unwrap();
    assert!(log.held().is_empty());
    // or the operator acknowledges it
    log.append(drift(
        "mount_not_canonical",
        "a bind over /var/lib/northnarrow",
    ))
    .unwrap();
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
    // a `cleared` naming exactly what it is about ends nothing either
    log.append(cleared("chain_verify_failed", "detections"))
        .unwrap();
    log.append(drift("overlay_rollback_floor_unavailable", "no anchor"))
        .unwrap();
    log.append(cleared("overlay_rollback_floor_unavailable", "no anchor"))
        .unwrap();
    boot(&mut log);
    assert_eq!(
        kinds(&log),
        [
            "chain_verify_failed:detections",
            "overlay_rollback_floor_unavailable:no anchor"
        ]
    );
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
    log.append(drift("unauthorized_overlay", "x.local"))
        .unwrap();
    drop(log);
    // the same rows, signed by another key, appended to the file
    let (_o, other_key, other) = paths();
    let mut forger = open(&other_key, &other);
    for _ in 0..row + 2 {
        forger
            .append(draft("pad", "success", serde_json::json!({})))
            .unwrap();
    }
    forger.append(ack(row + 1)).unwrap();
    boot(&mut forger);
    forger
        .append(cleared("unauthorized_overlay", "x.local"))
        .unwrap();
    let lines = std::fs::read_to_string(&other).unwrap();
    // an acknowledgement, a start and the overlay's end: none genuine here
    let forged: Vec<&str> = lines.lines().rev().take(3).collect();
    let mut file = std::fs::OpenOptions::new()
        .append(true)
        .open(&path)
        .unwrap();
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
    log.append(drift("subsystem_degraded", "exec sensor on its fallback"))
        .unwrap();
    log.append(drift("pin_lock_missing", "the lock is gone"))
        .unwrap();
    log.append(drift("profile_downgraded", "alpha after enforcing"))
        .unwrap();
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
    log.append(draft("unlock", "success", serde_json::json!({})))
        .unwrap();
    // rows that could end a hold, with nothing held: no change, no word
    boot(&mut log);
    let before = log.rows() - 1;
    assert!(helds::take(&path).is_empty());
    log.append(cut("audit", &path)).unwrap();
    let told = helds::take(&path);
    assert_eq!(told.len(), 1);
    assert!(
        told[0][0].starts_with("chain_truncated (audit)"),
        "{told:?}"
    );
    // an acknowledgement that covers nothing, a start, an end of another
    // finding: the evidence finding holds, nothing is told
    log.append(ack(before)).unwrap();
    boot(&mut log);
    log.append(cleared("chain_truncated", "the anchored head"))
        .unwrap();
    assert!(helds::take(&path).is_empty());
    assert_eq!(log.held().findings().len(), 1);
    log.append(ack(log.rows() - 1)).unwrap();
    assert_eq!(helds::take(&path), vec![Vec::<String>::new()]);
    // a log kept in memory (a refused start's fallback) tells nothing
    let mut memory = AuditLog::in_memory(TestKey::fresh(), [1; 16]);
    memory.append(cut("audit", &path)).unwrap();
    assert_eq!(memory.held().findings().len(), 1);
    assert!(helds::take(&path).is_empty());
    assert!(helds::take(Path::new("")).is_empty(), "told under no path");
}

/// Past [`MAX_HELD`] findings are counted, not listed, and an
/// acknowledgement through the newest row covers them too.
#[test]
fn past_the_cap_findings_are_counted_and_acknowledged() {
    let (_d, key, path) = paths();
    let mut log = open(&key, &path);
    for i in 0..MAX_HELD + 3 {
        log.append(drift(
            "unit_dropin",
            &format!("/etc/systemd/system/x.d/{i}.conf"),
        ))
        .unwrap();
    }
    assert_eq!(log.held().findings().len(), MAX_HELD);
    assert_eq!(log.held().more(), 3);
    let lines = log.held().lines();
    assert_eq!(lines.len(), MAX_HELD + 1);
    assert!(
        lines[MAX_HELD].contains("3 more held integrity row(s)"),
        "{lines:?}"
    );
    let newest = log.held().newest_row().unwrap();
    assert_eq!(newest, log.rows() - 1);
    assert_eq!(log.held().covered_by(newest), MAX_HELD as u64 + 3);
    log.append(ack(newest)).unwrap();
    assert!(log.held().is_empty());
    assert_eq!(log.held().newest_row(), None);
    assert!(log.held().lines().is_empty());
    // the found ones counted past the cap end at the next start too
    for i in 0..MAX_HELD + 1 {
        log.append(drift("mount_not_canonical", &format!("/run/x{i}")))
            .unwrap();
    }
    assert_eq!(log.held().more(), 1);
    let lines = log.held().lines();
    assert!(
        lines[MAX_HELD].contains("1 more held integrity row(s)"),
        "{lines:?}"
    );
    boot(&mut log);
    assert!(log.held().is_empty(), "{:?}", log.held());
}

/// A refused start is no start (it checked nothing: the process exits),
/// and a refused acknowledgement acknowledged nothing: neither ends a hold.
#[test]
fn a_refused_start_or_a_refused_acknowledgement_ends_nothing() {
    let (_d, key, path) = paths();
    let mut log = open(&key, &path);
    log.append(drift("unauthorized_overlay", "y.local"))
        .unwrap();
    let row = log.rows() - 1;
    let build = AgentBuild {
        version: "0.0.0-test",
        features: Vec::new(),
        bpf_guard_enforce: false,
    };
    log.boot_refused_by("bpf_lsm", "verified", "attested", "no bpf", &build)
        .unwrap();
    let mut refused = ack(row);
    refused.result = "failure: rejected (nothing held)".to_string();
    log.append(refused).unwrap();
    let mut denied = ack(row);
    denied.result = "failure: role_denied".to_string();
    log.append(denied).unwrap();
    // an acknowledgement without its row says nothing it covers
    let mut bare = ack(row);
    bare.extra = serde_json::json!({ "note": "no row" });
    log.append(bare).unwrap();
    assert_eq!(kinds(&log), ["unauthorized_overlay:y.local"]);
    drop(log);
    assert_eq!(kinds(&open(&key, &path)), ["unauthorized_overlay:y.local"]);
}

/// A detail longer than [`DETAIL_CHARS`] is cut, said with an ellipsis.
#[test]
fn a_long_detail_is_cut() {
    let (_d, key, path) = paths();
    let mut log = open(&key, &path);
    log.append(drift("config_overlay", &"x".repeat(DETAIL_CHARS + 50)))
        .unwrap();
    let f = &log.held().findings()[0];
    assert_eq!(f.detail.chars().count(), DETAIL_CHARS + 1);
    assert!(f.detail.ends_with('…'));
    // at the bound it is whole
    let exact = "y".repeat(DETAIL_CHARS);
    log.append(drift("config_overlay", &exact)).unwrap();
    assert_eq!(log.held().findings()[1].detail, exact);
}

/// The review of #586 (P2-1, its probe 2): a state of the host or a choice
/// of the operator that degrades no sensor is an advisory — listed on its
/// own with its signed row, never among the degradations (`sensors`, the
/// trust level, the manifest). On the PR's head each was held as a
/// degradation: `sensors: DEGRADED` on every default install (the admin key
/// the testers' guide leaves on the host).
#[test]
fn benign_states_are_advisories_not_degradations() {
    let advisories = [
        "admin_key_on_host",
        "sysctl_strict",
        "sysctl_opted_out",
        "agent_stalled",
        "quarantine_index_rebuilt",
    ];
    for k in advisories {
        assert_eq!(hold_of(k, "detected"), Hold::Advisory, "{k}");
    }
    // exactly these: an advisory more is a deliberate change of this test
    let mut table: Vec<&str> = ADVISORY_KINDS.iter().map(|(k, _)| *k).collect();
    table.sort_unstable();
    let mut want = advisories.to_vec();
    want.sort_unstable();
    assert_eq!(table, want);
    let (_d, key, path) = paths();
    let mut log = open(&key, &path);
    helds::take(&path);
    let row = log.rows();
    log.append(drift(
        "admin_key_on_host",
        "/root/northnarrow-admin.key: an admin private key on this host",
    ))
    .unwrap();
    // the default install: no degradation, one advisory with its row
    assert!(log.held().lines().is_empty(), "{:?}", log.held().lines());
    assert_eq!(log.held().more(), 0);
    assert!(!log.held().is_empty(), "kept, as a degradation is");
    let adv = log.held().advisories();
    assert_eq!(adv.len(), 1, "{adv:?}");
    assert!(
        adv[0].starts_with("admin_key_on_host — signed ")
            && adv[0].contains(&format!("(audit row {row})"))
            && adv[0].contains("an advisory, not a degradation"),
        "{}",
        adv[0]
    );
    // the host is told no degradation line for it
    assert!(helds::take(&path).iter().all(|l| l.is_empty()));
    // a real degradation beside it is one line, on its own
    log.append(drift("config_overlay", "/etc/northnarrow/x.local (3 bytes)"))
        .unwrap();
    assert_eq!(log.held().lines().len(), 1);
    assert!(log.held().lines()[0].starts_with("config_overlay — "));
    assert_eq!(log.held().advisories().len(), 1);
    // ended as a degradation while found is: its `cleared`, the next start,
    // an acknowledgement
    log.append(cleared(
        "admin_key_on_host",
        "/root/northnarrow-admin.key: an admin private key on this host",
    ))
    .unwrap();
    assert!(log.held().advisories().is_empty());
    log.append(drift("sysctl_strict", "vm.overcommit_ratio 80")).unwrap();
    boot(&mut log);
    assert!(log.held().is_empty(), "{:?}", log.held());
    log.append(drift("agent_stalled", "the loop stood still 40 s")).unwrap();
    log.append(ack(log.rows() - 1)).unwrap();
    assert!(log.held().is_empty());
}

/// The review of #586 (P2-1): one fact, one line — the host's harmful
/// drop-in is the `host_dropins` degradation's (not held twice), and an
/// overlay the start refused (`unauthorized_overlay`) is not listed again
/// by the round's `config_overlay` of the same file. On the PR's head the
/// lab showed three degradations for two facts.
#[test]
fn a_fact_signed_twice_is_one_line() {
    assert_eq!(hold_of("unit_dropin_harmful", "detected"), Hold::NotHeld);
    let (_d, key, path) = paths();
    let mut log = open(&key, &path);
    log.append(drift(
        "unauthorized_overlay",
        "process-comm-allowlist (/etc/northnarrow/process-comm-allowlist.local): no signature \
         file",
    ))
    .unwrap();
    log.append(drift(
        "config_overlay",
        "/etc/northnarrow/process-comm-allowlist.local (4053 bytes, sha256 a864bcbb…)",
    ))
    .unwrap();
    // another overlay's round finding stays listed
    log.append(drift(
        "config_overlay",
        "/etc/northnarrow/other.local (3 bytes, sha256 00…)",
    ))
    .unwrap();
    let lines = log.held().lines();
    assert_eq!(lines.len(), 2, "{lines:?}");
    assert!(lines[0].starts_with("unauthorized_overlay — "), "{lines:?}");
    // the one line names both rows (an acknowledgement through the newest
    // covers both)
    assert!(
        lines[0].ends_with(&format!(
            "the integrity round signs the same file as config_overlay (audit row {})",
            log.rows() - 2
        )),
        "{lines:?}"
    );
    assert!(lines[1].contains("other.local"), "{lines:?}");
    // the twin is still held: the start ends the refusal, the round's
    // finding of the file still on disk is listed then
    assert_eq!(log.held().findings().len(), 3);
    log.append(drift("unit_dropin_harmful", "/etc/systemd/system/x.d/y.conf"))
        .unwrap();
    assert_eq!(log.held().findings().len(), 3, "not held twice");
}

/// The review of #586 (P2-1): every kind whose finding is integrity
/// relevant — the evidence altered, a death, an attack-class event, a state
/// that weakens what the agent sees or defends — stays a degradation; no
/// kind is in two tables.
#[test]
fn every_integrity_relevant_kind_stays_a_degradation() {
    for k in EVIDENCE_KINDS.iter().chain(DEATH_KINDS).chain(EVENT_KINDS) {
        assert_eq!(hold_of(k, "detected"), Hold::UntilAcknowledged, "{k}");
    }
    for k in DEGRADATION_KINDS {
        assert_eq!(hold_of(k, "detected"), Hold::WhileFound, "{k}");
    }
    for k in [
        "config_overlay",
        "unauthorized_overlay",
        "default_list_modified",
        "weakening_env",
        "weakening_flag",
        "own_dropin_weakening",
        "unit_dropin",
        "unit_dropin_breaks_agent",
        "mount_over_protected",
        "mount_not_canonical",
        "protected_mount_gone",
        "bpf_pin_vanished",
        "foreign_pin",
        "sysctl_restored",
        "sysctl_not_restored",
        "canary_decoy_tampered",
        "bait_missing_at_boot",
        "fuse_aborted",
        "signed_records_failed",
        "witness_unavailable",
        "witness_note_uncertified",
    ] {
        assert_eq!(hold_of(k, "detected"), Hold::WhileFound, "{k}");
    }
    let mut all: Vec<&str> = EVIDENCE_KINDS
        .iter()
        .chain(DEATH_KINDS)
        .chain(EVENT_KINDS)
        .chain(DEGRADATION_KINDS)
        .copied()
        .chain(ADVISORY_KINDS.iter().map(|(k, _)| *k))
        .chain(NOT_HELD_KINDS.iter().map(|(k, _)| *k))
        .collect();
    let n = all.len();
    all.sort_unstable();
    all.dedup();
    assert_eq!(all.len(), n, "a kind in two tables");
    // a kind of another build: the safe side
    assert_eq!(hold_of("k379_a_kind_of_another_build", "detected"), UNKNOWN_KIND);
    assert_eq!(UNKNOWN_KIND, Hold::WhileFound);
}

/// The review of #586 (P3-2, its probe 2): an attack-class event of the
/// run — a forged shutdown marker, the admin socket removed — is not undone
/// by a start, a host reboot included: held until acknowledged. On the PR's
/// head the next `agent_boot` ended both.
#[test]
fn an_attack_class_event_is_held_across_a_reboot_until_acknowledged() {
    let (_d, key, path) = paths();
    let mut log = open(&key, &path);
    log.append(drift(
        "shutdown_marker_rejected",
        "the watchdog refused a shutdown marker",
    ))
    .unwrap();
    log.append(drift(
        "admin_socket_removed",
        "/run/northnarrow/admin.sock removed",
    ))
    .unwrap();
    assert_eq!(log.held().findings().len(), 2);
    drop(log);
    let mut log = open(&key, &path);
    assert_eq!(log.held().findings().len(), 2, "a restart keeps them");
    boot(&mut log);
    assert_eq!(log.held().findings().len(), 2, "a start ends neither");
    assert!(log.held().lines()[0].contains("held until acknowledged"));
    log.append(ack(log.rows() - 1)).unwrap();
    assert!(log.held().is_empty());
}

/// The review of #586 (P3-3, its probe 1): an evidence finding signed past
/// the cap, behind findings a start ends, is listed — its kind, its row,
/// the command that ends it — the newest of those counted in its stead. On
/// the PR's head it was a bare "and 1 more held integrity row(s)" once the
/// next start ended the others.
#[test]
fn an_evidence_finding_past_the_cap_keeps_its_kind_and_row() {
    let (d, key, path) = paths();
    let mut log = open(&key, &path);
    for i in 0..MAX_HELD {
        log.append(drift(
            "unit_dropin",
            &format!("/etc/systemd/system/x.d/{i}.conf"),
        ))
        .unwrap();
    }
    log.append(cut("detections", &d.path().join("detections.jsonl")))
        .unwrap();
    let cut_row = log.rows() - 1;
    assert_eq!(log.held().findings().len(), MAX_HELD);
    assert_eq!(log.held().more(), 1, "the newest while found, counted");
    assert_eq!(log.held().count(), MAX_HELD as u64 + 1);
    boot(&mut log);
    let lines = log.held().lines();
    assert_eq!(log.held().more(), 0, "{lines:?}");
    assert_eq!(lines.len(), 1, "{lines:?}");
    assert!(
        lines[0].starts_with("chain_truncated (detections)")
            && lines[0].contains(&format!("(audit row {cut_row})")),
        "{lines:?}"
    );
    // advisories past the cap: their own counter, never a degradation's
    let (_d, key, path) = paths();
    let mut log = open(&key, &path);
    for i in 0..MAX_HELD + 2 {
        log.append(drift("sysctl_opted_out", &format!("kernel.x{i}")))
            .unwrap();
    }
    assert_eq!(log.held().more(), 0);
    assert!(log.held().lines().is_empty());
    let adv = log.held().advisories();
    assert_eq!(adv.len(), MAX_HELD + 1, "{adv:?}");
    assert!(adv[MAX_HELD].contains("2 more advisory row(s)"), "{adv:?}");
    log.append(ack(log.rows() - 1)).unwrap();
    assert!(log.held().is_empty());
}

/// The review of #586 (P3-4): every part of a held line is bounded — a
/// forged row's kind and chain too, not only its detail.
#[test]
fn a_held_line_s_kind_and_chain_are_cut() {
    let (_d, key, path) = paths();
    let mut log = open(&key, &path);
    let long = "k".repeat(DETAIL_CHARS + 50);
    log.append(draft(
        INTEGRITY_DRIFT_OP,
        "detected",
        serde_json::json!({ "kind": long, "chain": long, "detail": "x" }),
    ))
    .unwrap();
    let f = &log.held().findings()[0];
    assert_eq!(f.kind.chars().count(), DETAIL_CHARS + 1);
    assert_eq!(f.subject.chars().count(), DETAIL_CHARS + 1);
    assert!(log.held().lines()[0].chars().count() < 4 * DETAIL_CHARS);
}
