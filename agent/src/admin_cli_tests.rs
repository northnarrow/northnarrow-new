//! The tests of `admin_cli` that wire the agent's own parts: its signing
//! key and the audit log it signs (`audit read`, `audit verify`, the
//! COMBAT rows of lab PR 245), its chains (`chain verify`), the loaders'
//! checks of an overlay before it is signed, the public half of its key.
//! Wave 4 restructure, R10 (lab PR 259): cut verbatim from the tests of
//! `admin_cli`, which leaves for nn-admin, with a copy of the key-file
//! helper they use; nn-admin depends on neither nn-linux nor the agent.

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use ed25519_dalek::{SigningKey, VerifyingKey};
use tempfile::TempDir;

use crate::admin_cli::*;
use crate::admin_host::AgentAdminHost;
use crate::os_rng::OsRng;

/// A private key file as `nn-admin init` and install.sh leave it: 0600
/// (external audit AUT-002: `read_priv_key` refuses anything looser). A
/// copy of the helper of `admin_cli`'s tests.
fn write_priv_key_file(path: &Path, key: &SigningKey) {
    std::fs::write(path, format!("{}\n", hex::encode(key.to_bytes()))).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
}

/// External audit NN-AUD-095: a carve-out line wider than the floor is
/// refused when it would be signed — offline (`config overlay sign`)
/// and over the socket (`config overlay set`, same `validate_content`).
#[test]
fn wide_carveout_refused_at_signing() {
    use nn_proto::admin_signed_payload::OverlayKind;
    let dir = tempfile::TempDir::new().unwrap();
    let file = dir.path().join("combat-allow.cidrs");
    for wide in [
        "10.0.0.0/0\n",
        "# mgmt\n10.0.0.0/8\n0.0.0.0/0\n",
        "2001:db8::/32\n",
    ] {
        std::fs::write(&file, wide).unwrap();
        let e = read_overlay_for_signing(&AgentAdminHost, OverlayKind::CombatAllow, &file)
            .expect_err(wide)
            .root_cause()
            .to_string();
        assert!(e.contains("too wide"), "{wide}: {e}");
        assert!(
            crate::config::overlay_auth::validate_content(OverlayKind::CombatAllow, wide).is_err()
        );
    }
    std::fs::write(&file, "10.0.0.0/8\n2001:db8:10::/48\n").unwrap();
    assert!(read_overlay_for_signing(&AgentAdminHost, OverlayKind::CombatAllow, &file).is_ok());
}

/// External audit EVD-001: the verifier reads the published public
/// half; without it, a host from before parses the key; it never mints
/// one.
#[test]
fn audit_verify_reads_the_public_half_and_never_mints_a_key() {
    let dir = tempfile::TempDir::new().unwrap();
    let key_path = dir.path().join("agent.sig.key");
    assert!(load_audit_pubkey(&AgentAdminHost, None, &key_path).is_err());
    assert!(!key_path.exists(), "no key minted by a verifier");
    let key = crate::audit::AgentSigningKey::load_or_bootstrap(&key_path).unwrap();
    assert_eq!(
        load_audit_pubkey(&AgentAdminHost, None, &key_path).unwrap(),
        key.verifying_key()
    );
    std::fs::remove_file(crate::audit::verifying_key_path(&key_path)).unwrap();
    assert_eq!(
        load_audit_pubkey(&AgentAdminHost, None, &key_path).unwrap(),
        key.verifying_key()
    );
}

/// External audit MAIN-010 (NN-AUD-252): nn-admin never mints the
/// agent's identity. Before the agent's first start (no `agent_id`) the
/// read verbs — and the signing ones — fail naming the file, and leave
/// nothing behind: the old `load_or_bootstrap` wrote a fresh id that the
/// agent then adopted without a trace.
#[test]
fn cli_verbs_before_the_first_start_fail_and_mint_nothing() {
    let dir = TempDir::new().unwrap();
    let socket = dir.path().join("admin.sock");
    let priv_path = dir.path().join("admin.key");
    write_priv_key_file(&priv_path, &SigningKey::generate(&mut OsRng));
    let missing = dir.path().join("etc/agent_id");
    let overlay = dir.path().join("x.local");
    std::fs::write(&overlay, "/etc/x\n").unwrap();
    let errs: Vec<(&str, anyhow::Error)> = vec![
        (
            "fim status",
            run_fim_status(&socket, &priv_path, &missing).unwrap_err(),
        ),
        (
            "fim report",
            run_fim_report(&socket, &priv_path, &missing, None).unwrap_err(),
        ),
        (
            "canary list",
            run_canary_list(&socket, &priv_path, &missing).unwrap_err(),
        ),
        (
            "net flows",
            run_net_flows(&socket, &priv_path, &missing, None).unwrap_err(),
        ),
        (
            "net listeners",
            run_net_listeners(&socket, &priv_path, &missing).unwrap_err(),
        ),
        (
            "detections",
            run_detections(
                &socket, &priv_path, &missing, 10, None, None, None, None, None, None,
            )
            .unwrap_err(),
        ),
        (
            "trusted-installer-grant",
            run_trusted_installer_grant(&socket, &priv_path, &missing, 60).unwrap_err(),
        ),
        (
            "config overlay sign",
            run_config_overlay_sign(
                &AgentAdminHost,
                &priv_path,
                None,
                &missing,
                nn_proto::admin_signed_payload::OverlayKind::FimPaths,
                &overlay,
                None,
            )
            .unwrap_err(),
        ),
    ];
    for (verb, err) in errs {
        let msg = format!("{err:#}");
        assert!(
            msg.contains(&missing.display().to_string()),
            "[{verb}] {msg}"
        );
        assert!(msg.contains("first start"), "[{verb}] {msg}");
    }
    assert!(!missing.exists(), "no agent_id minted");
    assert!(!missing.parent().unwrap().exists(), "no directory created");
}

// ── Tappa 8 A12 — audit read / verify tests (5) ────────────────

/// Builder helper: bootstrap a fresh agent signing key in `dir`,
/// open an AuditLog at `dir/audit.log`, append `n` sample
/// entries. Returns (key_path, log_path, pubkey, the entries).
fn build_audit_log(
    dir: &TempDir,
    n: usize,
) -> (
    PathBuf,
    PathBuf,
    VerifyingKey,
    Vec<crate::audit::AuditEntry>,
) {
    let key_path = dir.path().join("agent.sig.key");
    let log_path = dir.path().join("audit.log");
    let key = crate::audit::AgentSigningKey::load_or_bootstrap(&key_path).unwrap();
    let pubkey = key.verifying_key();
    let mut log = crate::audit::AuditLog::open(&log_path, key, [0u8; 16]).unwrap();
    let mut entries = Vec::new();
    for i in 0..n {
        let draft = crate::audit::AuditEntryDraft {
            op: format!("test_op_{i}"),
            extra: serde_json::json!({ "seq": i }),
            key_fp: format!("{i:08x}"),
            cosigner_fps: vec![],
            result: "success".to_string(),
            client_pid: 1000 + i as u32,
            client_uid: 0,
            client_comm: "nn-admin".to_string(),
            client_exe: None,
        };
        entries.push(log.append(draft).unwrap());
    }
    (key_path, log_path, pubkey, entries)
}

// ── Test 2 (A12 #2): read with --since filter drops entries
//                    strictly older than the threshold.
#[test]
fn audit_read_since_filter_drops_older_entries() {
    let dir = TempDir::new().unwrap();
    let (_key_path, log_path, _pubkey, entries) = build_audit_log(&dir, 3);
    // since == third entry's ts → exactly one kept (>=, not >);
    // entries[2] passes, entries[0..=1] are dropped.
    let threshold = entries[2].ts.clone();
    let read = |since: &str| {
        let (mut out, mut err) = (Vec::new(), Vec::new());
        let r = audit_read_into(&log_path, Some(since), true, &mut out, &mut err).unwrap();
        assert_eq!(r.skipped, 0);
        assert_eq!(String::from_utf8(out).unwrap().lines().count(), r.rows);
        r.rows
    };
    let n = read(&threshold);
    assert_eq!(
        n, 1,
        "since-threshold equal to entries[2].ts should keep exactly entries[2]"
    );
    // since == "9999-..." → all dropped.
    let n_none = read("9999-99-99T99:99:99Z");
    assert_eq!(n_none, 0);
    // since == "0001-..." → all kept.
    let n_all = read("0001-01-01T00:00:00Z");
    assert_eq!(n_all, 3);
}

// ── Test 3 (A12 #3): verify on an intact chain returns
//                    Success(count).
#[test]
fn audit_verify_intact_chain_returns_success() {
    let dir = TempDir::new().unwrap();
    let (_key_path, log_path, pubkey, _) = build_audit_log(&dir, 4);
    let outcome = run_audit_verify(&log_path, &pubkey).unwrap();
    match outcome {
        AuditVerifyOutcome::Success { entries } => assert_eq!(entries, 4),
        other => panic!("intact chain reported broken: {other:?}"),
    }
}

/// External audit NN-AUD-108: a chain cut below a head recorded
/// earlier still verifies on its own; `--expect-head` / `--min-seq`
/// find the cut (exit 8). Before lab PR 160 `audit verify` had no way
/// to say what the chain must still reach.
#[test]
fn audit_verify_finds_a_cut_below_an_expected_head() {
    let dir = TempDir::new().unwrap();
    let (_key_path, log_path, pubkey, _) = build_audit_log(&dir, 6);
    let body = std::fs::read_to_string(&log_path).unwrap();
    let last: crate::audit::AuditEntry =
        serde_json::from_str(body.lines().last().unwrap()).unwrap();
    let expect = ExpectedHead {
        entry_hash: Some(last.entry_hash.clone()),
        min_seq: last.seq,
    };
    assert!(matches!(
        run_audit_verify_expecting(&log_path, &pubkey, &expect).unwrap(),
        AuditVerifyOutcome::Success { entries: 6 }
    ));
    let kept: String = body.lines().take(4).map(|l| format!("{l}\n")).collect();
    std::fs::write(&log_path, kept).unwrap();
    assert!(matches!(
        run_audit_verify(&log_path, &pubkey).unwrap(),
        AuditVerifyOutcome::Success { entries: 4 }
    ));
    for expect in [
        ExpectedHead {
            entry_hash: Some(last.entry_hash.clone()),
            min_seq: None,
        },
        ExpectedHead {
            entry_hash: None,
            min_seq: last.seq,
        },
    ] {
        assert!(matches!(
            run_audit_verify_expecting(&log_path, &pubkey, &expect).unwrap(),
            AuditVerifyOutcome::HeadNotReached(_)
        ));
    }
}

// ── Test 4 (A12 #4): verify on a tampered chain returns
//                    ChainBroken with the typed error.
#[test]
fn audit_verify_tampered_chain_reports_broken() {
    let dir = TempDir::new().unwrap();
    let (_key_path, log_path, pubkey, _) = build_audit_log(&dir, 2);
    // Rewrite the log: flip the first entry's `result` field
    // post-write — exactly the attack verify_chain catches via
    // EntryHashMismatch.
    let raw = std::fs::read_to_string(&log_path).unwrap();
    let mut lines: Vec<crate::audit::AuditEntry> = raw
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    lines[0].result = "failure: someone-rewrote-this".to_string();
    let mut new_body = String::new();
    for l in &lines {
        new_body.push_str(&serde_json::to_string(l).unwrap());
        new_body.push('\n');
    }
    std::fs::write(&log_path, new_body).unwrap();

    let outcome = run_audit_verify(&log_path, &pubkey).unwrap();
    match outcome {
        AuditVerifyOutcome::ChainBroken(crate::audit::AuditVerifyError::EntryHashMismatch {
            idx: 0,
            ..
        }) => {} // expected
        other => panic!("expected EntryHashMismatch on entry 0; got: {other:?}"),
    }
}

/// External audit MAIN-014 (NN-AUD-256, lab PR 190): three rows, the
/// last torn. `read` stopped at it with an error; it prints the two
/// rows, names line 3 and reports one skipped line (exit 8 in the
/// binary). `verify` reported an I/O-style error (exit 1); it reports
/// two rows verified and the break at line 3.
#[test]
fn three_rows_with_the_last_torn_read_two_and_verify_two() {
    let dir = TempDir::new().unwrap();
    let (_key_path, log_path, pubkey, _) = build_audit_log(&dir, 3);
    let body = std::fs::read_to_string(&log_path).unwrap();
    let rows: Vec<&str> = body.lines().collect();
    let torn = format!(
        "{}\n{}\n{}",
        rows[0],
        rows[1],
        &rows[2][..rows[2].len() / 2]
    );
    std::fs::write(&log_path, torn).unwrap();

    let (mut out, mut err) = (Vec::new(), Vec::new());
    let r = audit_read_into(&log_path, None, true, &mut out, &mut err).unwrap();
    assert_eq!(
        r,
        AuditReadReport {
            rows: 2,
            skipped: 1
        }
    );
    let out = String::from_utf8(out).unwrap();
    assert_eq!(out.lines().collect::<Vec<_>>(), rows[..2].to_vec());
    let err = String::from_utf8(err).unwrap();
    assert!(
        err.contains("line 3 of") && err.contains("cut short"),
        "{err}"
    );

    match run_audit_verify(&log_path, &pubkey).unwrap() {
        AuditVerifyOutcome::ChainBroken(crate::audit::AuditVerifyError::UnreadableLine {
            line: 3,
            verified: 2,
            ..
        }) => {}
        other => panic!("expected the break at line 3 after 2 rows, got {other:?}"),
    }
}

/// Lab PR 245: `combat_stage` rows of both shapes in one chain — the
/// one written before the lot (`"trigger": null`, no offender, no
/// `cause`) and the ones the ladder writes now (the trigger named,
/// `cause`, `offender_details`, an `added`) — are read, exported by
/// `audit read --json` byte for byte, and verified, together.
#[test]
fn combat_rows_before_and_after_lab_pr_245_read_export_and_verify() {
    use crate::combat::{
        Addition, AuditEvidence, CombatStage, LadderEvidence, OffenderId, ProcFacts,
        StageTransition, Via,
    };
    use crate::posture::{CombatCause, TriggerEvidence};
    use nn_model::posture_types::{Confidence, EvidenceClass, TriggerType};
    use std::sync::Arc;

    let dir = TempDir::new().unwrap();
    let log_path = dir.path().join("audit.log");
    let key = crate::audit::AgentSigningKey::load_or_bootstrap(&dir.path().join("agent.sig.key"))
        .unwrap();
    let pubkey = key.verifying_key();
    let log = Arc::new(parking_lot::Mutex::new(
        crate::audit::AuditLog::open(&log_path, key, [0u8; 16]).unwrap(),
    ));
    // Before: the INVESTIGATE row of a COMBAT the posture reached.
    log.lock()
        .append(crate::audit::AuditEntryDraft {
            op: "combat_stage".to_string(),
            extra: serde_json::json!({
                "from": null,
                "offenders": [],
                "reason": "COMBAT entry — investigate first, network up",
                "to": "INVESTIGATE",
                "trigger": null,
            }),
            key_fp: "agent-self".to_string(),
            cosigner_fps: vec![],
            result: "success".to_string(),
            client_pid: 4242,
            client_uid: 0,
            client_comm: "northnarrow-agent".to_string(),
            client_exe: None,
        })
        .unwrap();
    // After: through the ladder's evidence sink.
    let cause = Arc::new(CombatCause::Trigger(TriggerEvidence {
        trigger: TriggerType::ExfiltrationPattern,
        raised: vec![TriggerType::ExfiltrationPattern],
        class: EvidenceClass::Network,
        confidence: Confidence::NeedsCorroboration,
        corroborated_by: vec![(TriggerType::ExploitAttempt, EvidenceClass::Execution)],
        locked: false,
        scope: "login uid 1000".to_string(),
        event_kind: "TcpConnect",
        event_pid: Some(4242),
        event_ns: Some(9),
    }));
    let id = |pid: u32, via: Via| {
        Arc::new(OffenderId {
            pid,
            start_ticks: Some(7),
            start_ns: None,
            seen_ns: Some(9),
            facts: ProcFacts {
                exe: Some("/tmp/.x/p \"q\"\té".to_string()),
                cgroup: Some("/user.slice/user-1000.slice/session-3.scope".to_string()),
            },
            via,
        })
    };
    let ev = AuditEvidence::new(Some(Arc::clone(&log)));
    let stage = CombatStage::Investigate;
    ev.record_stage(&StageTransition {
        from: None,
        to: stage,
        cause: Some(Arc::clone(&cause)),
        offenders: vec![4242],
        details: vec![id(4242, Via::Entry)],
        added: None,
        reason: "COMBAT entry — investigate first, network up".to_string(),
    })
    .unwrap();
    ev.record_stage(&StageTransition {
        from: Some(stage),
        to: stage,
        cause: Some(cause),
        offenders: vec![4242, 4243],
        details: vec![id(4242, Via::Entry), id(4243, Via::LaterEntry)],
        added: Some(Addition {
            offender: id(4243, Via::LaterEntry),
            by: Arc::new(CombatCause::AdminForce {
                signers: vec!["a1b2c3d4".to_string()],
            }),
        }),
        reason: "offender 4243 added by a later COMBAT entry".to_string(),
    })
    .unwrap();

    // Read and exported: every row, byte for byte.
    let (mut out, mut err) = (Vec::new(), Vec::new());
    let r = audit_read_into(&log_path, None, true, &mut out, &mut err).unwrap();
    assert_eq!(
        r,
        AuditReadReport {
            rows: 3,
            skipped: 0
        }
    );
    assert_eq!(
        String::from_utf8(out.clone()).unwrap(),
        std::fs::read_to_string(&log_path).unwrap(),
        "the export is the log's bytes"
    );
    let export = dir.path().join("export.jsonl");
    std::fs::write(&export, &out).unwrap();
    match run_audit_verify(&export, &pubkey).unwrap() {
        AuditVerifyOutcome::Success { entries } => assert_eq!(entries, 3),
        other => panic!("the export does not verify: {other:?}"),
    }
    // What a reader finds in each shape.
    let rows: Vec<crate::audit::AuditEntry> = String::from_utf8(out)
        .unwrap()
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    assert!(rows[0].extra["trigger"].is_null());
    assert!(
        rows[0].extra.get("cause").is_none() && rows[0].extra.get("offender_details").is_none()
    );
    assert_eq!(rows[1].extra["trigger"], "ExfiltrationPattern");
    assert_eq!(
        rows[1].extra["cause"]["corroborated_by"][0]["trigger"],
        "ExploitAttempt"
    );
    assert_eq!(
        rows[1].extra["offender_details"][0]["exe"],
        "/tmp/.x/p \"q\"\té"
    );
    assert_eq!(rows[2].extra["added"]["offender"]["pid"], 4243);
    assert_eq!(rows[2].extra["added"]["by"]["signers"][0], "a1b2c3d4");
    assert_eq!(
        rows[2].extra["trigger"], "ExfiltrationPattern",
        "the episode's"
    );
    // The human view: one line per row, the same columns.
    let (mut human, mut err) = (Vec::new(), Vec::new());
    audit_read_into(&log_path, None, false, &mut human, &mut err).unwrap();
    let human = String::from_utf8(human).unwrap();
    assert_eq!(human.lines().count(), 3);
    assert!(
        human
            .lines()
            .all(|l| l.contains("combat_stage") && l.contains("agent-self success")),
        "{human}"
    );
}

/// MAIN-014: lines that are not rows anywhere in the file — not JSON,
/// not UTF-8, blank lines between rows — hide none of the rows after
/// them; past [`AUDIT_READ_SKIPS_LISTED`] only the count grows.
#[test]
fn audit_read_skips_damaged_lines_and_prints_every_row() {
    let dir = TempDir::new().unwrap();
    let (_key_path, log_path, pubkey, entries) = build_audit_log(&dir, 4);
    let body = std::fs::read_to_string(&log_path).unwrap();
    let rows: Vec<&str> = body.lines().collect();
    let mut damaged = Vec::new();
    damaged.extend_from_slice(format!("{}\n\n", rows[0]).as_bytes());
    for _ in 0..AUDIT_READ_SKIPS_LISTED + 5 {
        damaged.extend_from_slice(b"{\"not\":\"a row\"}\n");
    }
    damaged.extend_from_slice(format!("{}\n", rows[1]).as_bytes());
    damaged.extend_from_slice(b"\xff\xfe\n");
    damaged.extend_from_slice(format!("{}\n{}\n", rows[2], rows[3]).as_bytes());
    std::fs::write(&log_path, &damaged).unwrap();

    let (mut out, mut err) = (Vec::new(), Vec::new());
    let r = audit_read_into(&log_path, None, false, &mut out, &mut err).unwrap();
    assert_eq!(
        r,
        AuditReadReport {
            rows: 4,
            skipped: AUDIT_READ_SKIPS_LISTED + 6
        }
    );
    let out = String::from_utf8(out).unwrap();
    for e in &entries {
        assert!(out.contains(&e.entry_hash), "row {} not printed", e.op);
    }
    let err = String::from_utf8(err).unwrap();
    assert_eq!(err.lines().count(), AUDIT_READ_SKIPS_LISTED);
    assert!(err.starts_with("audit: line 3 of"), "{err}");

    // `since` still filters the rows; the skipped lines are counted
    // whatever their time (they have none).
    let (mut out, mut err) = (Vec::new(), Vec::new());
    let r = audit_read_into(&log_path, Some(&entries[3].ts), true, &mut out, &mut err).unwrap();
    assert_eq!(r.rows, 1);
    assert_eq!(r.skipped, AUDIT_READ_SKIPS_LISTED + 6);

    // `verify` stops at the first of them, line 3, after one row; an
    // expected head does not hide the break.
    let expect = ExpectedHead {
        entry_hash: Some(entries[3].entry_hash.clone()),
        min_seq: None,
    };
    assert!(matches!(
        run_audit_verify_expecting(&log_path, &pubkey, &expect).unwrap(),
        AuditVerifyOutcome::ChainBroken(crate::audit::AuditVerifyError::UnreadableLine {
            line: 3,
            verified: 1,
            ..
        })
    ));
}

/// EVD-017 (NN-AUD-280): `chain verify` over every chain with an empty
/// archive in the detection log reports that chain and goes on — the
/// others and the anchor comparison are still reported.
#[test]
fn chain_verify_reports_the_chains_after_an_archive_without_terminator() {
    let dir = TempDir::new().unwrap();
    let (_key_path, audit, pubkey, _) = build_audit_log(&dir, 2);
    let det = dir.path().join("detections");
    std::fs::create_dir_all(&det).unwrap();
    std::fs::File::create(det.join("detections.jsonl.000001")).unwrap();
    let paths = crate::chains::ChainPaths {
        audit,
        canary_registry: dir.path().join("canaries.jsonl"),
        canary_access: dir.path().join("canary_access.jsonl"),
        detections: det.join("detections.jsonl"),
        status_events: det.join("status_events.jsonl"),
        netflow: dir.path().join("netflow.jsonl"),
        fim_drift: dir.path().join("fim_drift.jsonl"),
    };
    let lines = run_chain_verify(&paths, &dir.path().join("heads.json"), &[], &pubkey);
    let by = |c: &str| lines.iter().find(|l| l.chain == c).cloned();
    let d = by("detections").expect("detections reported");
    assert!(!d.ok && d.detail.contains("no terminator"), "{d:?}");
    for c in [
        "audit",
        "canary_registry",
        "canary_access",
        "status_events",
        "netflow",
        "fim_drift",
        "heads",
    ] {
        assert!(by(c).is_some_and(|l| l.ok), "{c}: {lines:?}");
    }
    assert_eq!(by("audit").unwrap().detail, "2 rows, all numbered");
}

// ── Test 5 (A12 #5): load_audit_pubkey accepts explicit
//                    --agent-pubkey hex AND falls back to the
//                    local signing-key file (zero-config path).
#[test]
fn load_audit_pubkey_explicit_hex_overrides_file_fallback() {
    let dir = TempDir::new().unwrap();
    // 1) Fresh signing key in the tempdir; pubkey from file
    //    matches the one load_audit_pubkey derives.
    let key_path = dir.path().join("agent.sig.key");
    let on_disk_key = crate::audit::AgentSigningKey::load_or_bootstrap(&key_path).unwrap();
    let on_disk_pub = on_disk_key.verifying_key();
    let derived = load_audit_pubkey(&AgentAdminHost, None, &key_path).expect("file fallback");
    assert_eq!(derived.to_bytes(), on_disk_pub.to_bytes());

    // 2) Explicit hex overrides — synthesise a DIFFERENT key,
    //    pass its hex pubkey; load_audit_pubkey must return the
    //    explicit one, NOT the on-disk one. Proves the
    //    explicit-hex path is wired.
    let other = SigningKey::generate(&mut OsRng);
    let other_pub_hex = hex::encode(other.verifying_key().to_bytes());
    let from_hex =
        load_audit_pubkey(&AgentAdminHost, Some(&other_pub_hex), &key_path).expect("explicit hex");
    assert_eq!(from_hex.to_bytes(), other.verifying_key().to_bytes());
    assert_ne!(
        from_hex.to_bytes(),
        on_disk_pub.to_bytes(),
        "explicit hex must NOT silently fall back to the file pubkey"
    );

    // 3) Bad-length hex is rejected with an actionable error.
    let too_short = "deadbeef".repeat(7); // 56 chars, not 64
    let err = load_audit_pubkey(&AgentAdminHost, Some(&too_short), &key_path).unwrap_err();
    let msg = format!("{err:#}");
    assert!(
        msg.contains("64 hex chars"),
        "error must mention the 64-hex-char shape; got: {msg}"
    );
}
