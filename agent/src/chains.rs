//! The agent's signed chains: where each lives (the CLI flags, the
//! built-in paths), how each is verified, and the tasks that anchor their
//! heads and verify them after the start.
//!
//! Wave 4 restructure, R04a (lab PR 241): from `crate::chain_anchor`,
//! unchanged. The format and the checks — row numbers, file heads, the
//! head anchor, the boot check — stay there, for nn-evidence (R05); what is
//! here names the agent's own payloads and modules (the detection store,
//! the FIM and network drains, the canary chains, the admin socket's
//! netflow path) and runs on its runtime (tokio).

use std::path::{Path, PathBuf};
use std::sync::Arc;

use ed25519_dalek::VerifyingKey;
use tracing::{error, info, warn};

use crate::audit::{AuditEntryDraft, AuditLog};
use crate::chain_anchor::{
    canonical_rows, flat_rows, full_audit, non_canonical_note, numbered_summary, Anchor,
    ChainFinding, ChainKind, ChainTarget, ANCHOR_SECS, BOOT_VERIFY_BYTES, CHAIN_VERIFY_OP,
};

fn full_canary_registry(path: &Path, pk: &VerifyingKey) -> Result<String, String> {
    let (rows, raws) = flat_rows::<crate::canary::registry::CanaryToken>(path)?;
    crate::canary::registry::verify_chain(&rows, pk).map_err(|e| e.to_string())?;
    let legacy = canonical_rows(&rows, &raws, |r| r.seq.is_some())?;
    Ok(
        numbered_summary(rows.len(), rows.iter().position(|r| r.seq.is_some()))
            + &non_canonical_note(legacy),
    )
}

fn full_canary_access(path: &Path, pk: &VerifyingKey) -> Result<String, String> {
    let (rows, raws) = flat_rows::<crate::canary::access_log::CanaryAccessEntry>(path)?;
    crate::canary::access_log::verify_chain(&rows, pk).map_err(|e| e.to_string())?;
    let legacy = canonical_rows(&rows, &raws, |r| r.seq.is_some())?;
    Ok(
        numbered_summary(rows.len(), rows.iter().position(|r| r.seq.is_some()))
            + &non_canonical_note(legacy),
    )
}

/// Where the agent's chains live (the CLI flags; `Default`: built-ins).
#[derive(Debug, Clone)]
pub struct ChainPaths {
    pub audit: PathBuf,
    pub canary_registry: PathBuf,
    pub canary_access: PathBuf,
    pub detections: PathBuf,
    pub status_events: PathBuf,
    pub netflow: PathBuf,
    pub fim_drift: PathBuf,
}

impl Default for ChainPaths {
    fn default() -> Self {
        Self {
            audit: crate::audit::DEFAULT_AUDIT_LOG_PATH.into(),
            canary_registry: crate::canary::registry::DEFAULT_REGISTRY_PATH.into(),
            canary_access: crate::canary::access_log::DEFAULT_ACCESS_LOG_PATH.into(),
            detections: crate::detection_store::DEFAULT_DETECTIONS_LOG_PATH.into(),
            status_events: crate::detection_store::DEFAULT_STATUS_EVENTS_LOG_PATH.into(),
            netflow: crate::admin_socket::DEFAULT_NETFLOW_JSONL_PATH.into(),
            fim_drift: crate::fim::drain::DEFAULT_DRIFT_LOG_PATH.into(),
        }
    }
}

impl ChainPaths {
    /// Every chain the agent anchors, in a fixed order.
    pub fn targets(&self) -> Vec<ChainTarget> {
        let flat = |chain, path: &PathBuf, genuine, full| ChainTarget {
            chain,
            path: path.clone(),
            kind: ChainKind::Flat,
            genuine,
            recent: None,
            full,
            payload_kind: None,
        };
        vec![
            flat(
                "audit",
                &self.audit,
                crate::audit::row_is_genuine,
                full_audit,
            ),
            flat(
                "canary_registry",
                &self.canary_registry,
                crate::canary::registry::row_is_genuine,
                full_canary_registry,
            ),
            flat(
                "canary_access",
                &self.canary_access,
                crate::canary::access_log::row_is_genuine,
                full_canary_access,
            ),
            ChainTarget::rotating::<crate::detection_store::DetectionRecord>(
                "detections",
                &self.detections,
            ),
            ChainTarget::rotating::<crate::detection_store::StatusEvent>(
                "status_events",
                &self.status_events,
            ),
            ChainTarget::rotating::<crate::net::drain::NetFlowPayload>("netflow", &self.netflow),
            ChainTarget::rotating::<crate::fim::drain::FimDriftPayload>(
                "fim_drift",
                &self.fim_drift,
            ),
        ]
    }
}

/// External audit NN-AUD-112: the signed chains were never verified in
/// production. After the start, in the background, every rotating log's
/// last [`BOOT_VERIFY_BYTES`] are verified (hash, signature, link); the
/// result is one signed `chain_verify` entry, and each failure an ERROR and
/// a signed `integrity_drift` (`chain_verify_failed`). The flat chains are
/// verified when they open (canary chains) or by the overlay floor scan
/// (audit log); `nn-admin chain verify` checks everything in full.
pub fn spawn_boot_verify(
    targets: Vec<ChainTarget>,
    pk: VerifyingKey,
    audit_log: Option<Arc<parking_lot::Mutex<AuditLog>>>,
) {
    tokio::spawn(async move {
        let started = std::time::Instant::now();
        let results = tokio::task::spawn_blocking(move || {
            targets
                .iter()
                .filter_map(|t| t.recent.map(|r| (t, r)))
                .map(|(t, recent)| {
                    (
                        t.chain,
                        t.path.clone(),
                        recent(&t.path, &pk, BOOT_VERIFY_BYTES),
                    )
                })
                .collect::<Vec<_>>()
        })
        .await;
        let Ok(results) = results else {
            warn!("chain verify: the boot verification task failed");
            return;
        };
        let mut logs = Vec::new();
        let mut failures = Vec::new();
        for (chain, path, r) in results {
            match r {
                Ok(rep) => logs.push(serde_json::json!({
                    "chain": chain,
                    "file": path.display().to_string(),
                    "lines": rep.lines,
                    "bytes": rep.bytes,
                    "whole_file": rep.whole_file,
                    "result": "ok",
                })),
                Err(e) => {
                    logs.push(serde_json::json!({
                        "chain": chain,
                        "file": path.display().to_string(),
                        "result": "broken",
                        "error": e.to_string(),
                    }));
                    failures.push(ChainFinding::new(
                        chain,
                        &path,
                        "chain_verify_failed",
                        format!("the last {BOOT_VERIFY_BYTES} bytes do not verify: {e}"),
                    ));
                }
            }
        }
        let result = if failures.is_empty() { "ok" } else { "broken" };
        info!(
            result,
            ms = started.elapsed().as_millis() as u64,
            logs = logs.len(),
            "chain verify: boot verification of the rotating logs done"
        );
        let Some(log) = audit_log else {
            for f in &failures {
                f.attest(None::<&mut AuditLog>);
            }
            return;
        };
        let mut log = log.lock();
        if let Err(e) = log.append(AuditEntryDraft {
            op: CHAIN_VERIFY_OP.to_string(),
            extra: serde_json::json!({
                "scope": format!("last {BOOT_VERIFY_BYTES} bytes of each rotating log's active file"),
                "logs": logs,
            }),
            key_fp: "agent-self".to_string(),
            cosigner_fps: Vec::new(),
            result: result.to_string(),
            client_pid: std::process::id(),
            client_uid: 0,
            client_comm: "northnarrow-agent".to_string(),
            client_exe: None,
        }) {
            warn!(error = %format!("{e:#}"), "chain verify: result not recorded");
        }
        for f in &failures {
            f.attest(Some(&mut log));
        }
    });
}

/// The signed audit log, for [`report_unverified_rows`].
static READ_AUDIT_LOG: std::sync::OnceLock<Arc<parking_lot::Mutex<AuditLog>>> =
    std::sync::OnceLock::new();
/// Last count reported per file, so a dashboard polling the same forged
/// rows does not write one entry per query.
static REPORTED: std::sync::Mutex<Option<std::collections::HashMap<PathBuf, usize>>> =
    std::sync::Mutex::new(None);

/// Hand the signed audit log to the read paths (from `main`).
pub fn set_audit_log(log: Option<Arc<parking_lot::Mutex<AuditLog>>>) {
    if let Some(l) = log {
        let _ = READ_AUDIT_LOG.set(l);
    }
}

/// External audit NN-AUD-112: a read verb left out `count` rows of `file`
/// that do not verify. ERROR in the journal every time; a signed
/// `integrity_drift` (`chain_lines_unverified`) when the count for that
/// file changed since the last one.
pub fn report_unverified_rows(chain: &str, file: &Path, count: usize) {
    let finding = ChainFinding::new(
        chain,
        file,
        "chain_lines_unverified",
        format!(
            "{count} row(s) served by a read verb fail hash or signature verification: left out"
        ),
    );
    let fresh = REPORTED
        .lock()
        .map(|mut m| {
            let m = m.get_or_insert_with(Default::default);
            m.insert(file.to_path_buf(), count) != Some(count)
        })
        .unwrap_or(true);
    if !fresh {
        error!(chain, file = %file.display(), count, "read verb: rows that do not verify left out");
        return;
    }
    match READ_AUDIT_LOG.get() {
        Some(log) => finding.attest(Some(&mut log.lock())),
        None => finding.attest(None::<&mut AuditLog>),
    }
}

/// Re-anchor every [`ANCHOR_SECS`] the heads that moved.
pub fn spawn(
    anchor: Arc<parking_lot::Mutex<Anchor>>,
    audit_log: Option<Arc<parking_lot::Mutex<AuditLog>>>,
) {
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(std::time::Duration::from_secs(ANCHOR_SECS));
        tick.tick().await; // the boot already anchored
        loop {
            tick.tick().await;
            let second = audit_log
                .as_ref()
                .is_some_and(|l| l.lock().second_key_added());
            let a = Arc::clone(&anchor);
            let r = tokio::task::spawn_blocking(move || {
                let mut a = a.lock();
                a.refresh(false, second).map(|_| a.take_marker())
            })
            .await;
            match r {
                Ok(Ok(marker)) => {
                    if let (Some(d), Some(log)) = (marker, audit_log.as_ref()) {
                        if let Err(e) = log.lock().append(d) {
                            warn!(error = %format!("{e:#}"), "chain heads: start not recorded");
                        }
                    }
                }
                Ok(Err(e)) => warn!(error = %format!("{e:#}"), "chain heads: anchor not written"),
                Err(e) => warn!(error = %e, "chain heads: anchor task failed"),
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::AgentSigningKey;
    use crate::chain_anchor::{boot_check, read_file_head, HEADS_FILE_NAME};
    use serde::{Deserialize, Serialize};
    use tempfile::TempDir;

    fn draft(n: u32) -> AuditEntryDraft {
        AuditEntryDraft {
            op: format!("op_{n}"),
            extra: serde_json::json!({ "n": n }),
            key_fp: "00000000".to_string(),
            cosigner_fps: vec![],
            result: "success".to_string(),
            client_pid: 1,
            client_uid: 0,
            client_comm: "t".to_string(),
            client_exe: None,
        }
    }

    fn key(dir: &TempDir) -> AgentSigningKey {
        AgentSigningKey::load_or_bootstrap(&dir.path().join("agent.sig.key")).unwrap()
    }

    fn paths(dir: &TempDir) -> ChainPaths {
        let p = |n: &str| dir.path().join(n);
        ChainPaths {
            audit: p("audit.log"),
            canary_registry: p("canaries.jsonl"),
            canary_access: p("canary_access.jsonl"),
            detections: p("detections.jsonl"),
            status_events: p("status_events.jsonl"),
            netflow: p("netflow.jsonl"),
            fim_drift: p("fim_drift.jsonl"),
        }
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    struct P {
        ts: String,
        n: u64,
    }

    impl crate::chainlog::ChainPayload for P {
        const KIND: &'static str = "test_log";
    }

    fn rotating_target(path: &Path) -> ChainTarget {
        ChainTarget::rotating::<P>("test_log", path)
    }

    fn rotating_log(
        path: &Path,
        key: AgentSigningKey,
        cap: u64,
    ) -> crate::chainlog::RotatingChainLog<P> {
        crate::chainlog::RotatingChainLog::<P>::open(
            path,
            key,
            crate::chainlog::RotationConfig {
                size_cap_bytes: cap,
                max_archives: 50,
                file_mode: 0o600,
            },
            Arc::new(crate::chainlog::NoProtection),
        )
        .unwrap()
    }

    fn p(n: u64) -> P {
        P {
            ts: format!("2026-10-15T00:00:{n:02}.000000Z"),
            n,
        }
    }

    /// Rewrite line `n` (0-based) of `path` with `"injected":"x"` added.
    fn inject_at(path: &Path, n: usize) {
        let body = std::fs::read_to_string(path).unwrap();
        let mut lines: Vec<String> = body.lines().map(str::to_string).collect();
        lines[n] = format!(
            "{},\"injected\":\"x\"}}",
            lines[n].strip_suffix('}').unwrap()
        );
        std::fs::write(path, lines.join("\n") + "\n").unwrap();
    }

    /// External audit NN-AUD-108: on the code before lab PR 160 a cut
    /// audit log reopened and verified with nothing to say. The head
    /// anchor written before the cut names it at the next boot.
    #[test]
    fn a_cut_audit_log_is_found_at_the_next_boot() {
        let dir = TempDir::new().unwrap();
        let k = key(&dir);
        let pk = k.verifying_key();
        let p = paths(&dir);
        let heads = dir.path().join(HEADS_FILE_NAME);
        let mut log = AuditLog::open(&p.audit, key(&dir), [1; 16]).unwrap();
        for n in 0..10 {
            log.append(draft(n)).unwrap();
        }
        let mut anchor = Anchor::new(heads.clone(), k, [1; 16], p.targets(), None, false);
        anchor.refresh(true, false).unwrap();
        log.append(anchor.take_marker().expect("first snapshot written"))
            .unwrap();
        assert!(anchor.take_marker().is_none());
        assert!(boot_check(&p.targets(), &heads, &pk).findings.is_empty());
        // cut the last rows; the chain that is left verifies
        let body = std::fs::read_to_string(&p.audit).unwrap();
        let full = body.clone();
        let keep: String = body.lines().take(7).map(|l| format!("{l}\n")).collect();
        std::fs::write(&p.audit, keep).unwrap();
        let rows: Vec<crate::audit::AuditEntry> = std::fs::read_to_string(&p.audit)
            .unwrap()
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect();
        crate::audit::verify_chain(&rows, &pk).expect("what is left still verifies");
        let found = boot_check(&p.targets(), &heads, &pk);
        assert_eq!(found.findings.len(), 1, "{:?}", found.findings);
        assert_eq!(found.findings[0].kind, "chain_truncated");
        assert_eq!(found.findings[0].chain, "audit");
        assert!(found.findings[0].detail.contains("row 9"));
        assert!(found.audit_history_lost().is_some());
        assert!(found.second_key_added(), "fails closed");
        // the heads file removed after anchoring started
        std::fs::write(&p.audit, full).unwrap();
        std::fs::remove_file(&heads).unwrap();
        let mut found = boot_check(&p.targets(), &heads, &pk);
        assert!(found.findings.is_empty());
        let started = AuditLog::open(&p.audit, key(&dir), [1; 16])
            .unwrap()
            .anchoring_started();
        assert!(started);
        let f = found.heads_missing(&heads, started).expect("reported");
        assert_eq!(f.kind, "chain_heads_missing");
    }

    #[test]
    fn a_fresh_or_legacy_install_has_nothing_to_report() {
        let dir = TempDir::new().unwrap();
        let pk = key(&dir).verifying_key();
        let p = paths(&dir);
        let heads = dir.path().join(HEADS_FILE_NAME);
        assert!(boot_check(&p.targets(), &heads, &pk).findings.is_empty());
        // legacy rows only, no anchor yet: the upgrade itself
        std::fs::write(&p.audit, "").unwrap();
        assert!(boot_check(&p.targets(), &heads, &pk).findings.is_empty());
    }

    /// External audit NN-AUD-174: before lab PR 160 a canary access log cut
    /// at its end reopened without a word.
    #[test]
    fn a_cut_canary_chain_is_found_at_the_next_boot() {
        let dir = TempDir::new().unwrap();
        let k = key(&dir);
        let pk = k.verifying_key();
        let paths = paths(&dir);
        let heads = dir.path().join(HEADS_FILE_NAME);
        let mut db = crate::canary::access_log::CanaryAccessDb::open(
            &paths.canary_access,
            key(&dir),
            [1; 16],
        )
        .unwrap();
        for n in 0..5 {
            db.append(crate::canary::access_log::CanaryAccessDraft {
                canary_id: format!("c{n}"),
                canary_name: "decoy".into(),
                canary_type: nn_model::CanaryTypeTag::File,
                access_kind: nn_model::CanaryAccessKind::FileOpen,
                accessor_pid: 1,
                accessor_uid: 0,
                accessor_comm: "cat".into(),
                accessor_exe: None,
                first_trip: n == 0,
            })
            .unwrap();
        }
        drop(db);
        Anchor::new(heads.clone(), k, [1; 16], paths.targets(), None, false)
            .refresh(true, false)
            .unwrap();
        let body = std::fs::read_to_string(&paths.canary_access).unwrap();
        let keep: String = body.lines().take(3).map(|l| format!("{l}\n")).collect();
        std::fs::write(&paths.canary_access, keep).unwrap();
        let found = boot_check(&paths.targets(), &heads, &pk);
        assert_eq!(found.findings.len(), 1, "{:?}", found.findings);
        assert_eq!(found.findings[0].chain, "canary_access");
        assert_eq!(found.findings[0].kind, "chain_truncated");
        assert!(found.audit_history_lost().is_none(), "not the audit chain");
    }

    /// EVD-007 (NN-AUD-273): `nn-admin chain verify` refuses a numbered row
    /// not in its canonical bytes in every flat chain (audit, canary
    /// registry, canary access) and a v3 line of a rotating log; the head of
    /// a chain is never such a row. Rows in the old format are named in the
    /// summary. On the starting code all of them verified.
    #[test]
    fn the_full_checks_refuse_a_row_not_in_canonical_form() {
        let dir = TempDir::new().unwrap();
        let k = key(&dir);
        let pk = k.verifying_key();
        let cp = paths(&dir);
        let mut log = AuditLog::open(&cp.audit, k, [1; 16]).unwrap();
        for n in 0..3 {
            log.append(draft(n)).unwrap();
        }
        drop(log);
        let mut reg =
            crate::canary::registry::Registry::open(&cp.canary_registry, key(&dir), [1; 16])
                .unwrap();
        for n in 0..2 {
            reg.deploy(crate::canary::registry::CanaryTokenDraft {
                name: format!("c{n}"),
                canary_type: nn_proto::admin_signed_payload::CanaryTypeWire::File,
                deployment: nn_proto::admin_signed_payload::CanaryDeploymentWire::File {
                    path: format!("/tmp/c{n}"),
                    template: None,
                },
                deployed_by_fp: "00000000".to_string(),
                content: None,
            })
            .unwrap();
        }
        drop(reg);
        let mut acc =
            crate::canary::access_log::CanaryAccessDb::open(&cp.canary_access, key(&dir), [1; 16])
                .unwrap();
        for n in 0..2 {
            acc.append(crate::canary::access_log::CanaryAccessDraft {
                canary_id: format!("id{n}"),
                canary_name: format!("c{n}"),
                canary_type: nn_model::CanaryTypeTag::File,
                access_kind: nn_model::CanaryAccessKind::FileOpen,
                accessor_pid: 1,
                accessor_uid: 0,
                accessor_comm: "cat".to_string(),
                accessor_exe: None,
                first_trip: n == 0,
            })
            .unwrap();
        }
        drop(acc);
        let mut rot = rotating_log(&cp.detections, key(&dir), 1 << 20);
        for n in 0..3 {
            rot.append(p(n)).unwrap();
        }
        drop(rot);
        let mut targets = cp.targets();
        targets[3] = rotating_target(&cp.detections);
        let full = |t: &ChainTarget| (t.full)(&t.path, &pk);
        for t in &targets[..4] {
            let ok = full(t).unwrap();
            assert!(!ok.contains("old format"), "{}: {ok}", t.chain);
        }
        for (i, line) in [(0usize, 1usize), (1, 1), (2, 1), (3, 1)] {
            let t = &targets[i];
            let before = std::fs::read(&t.path).unwrap();
            let head = read_file_head(&t.path, &|l: &[u8]| (t.genuine)(l, &pk))
                .unwrap()
                .unwrap();
            inject_at(&t.path, line);
            let err = full(t).unwrap_err();
            assert!(err.contains("canonical"), "{}: {err}", t.chain);
            if line + 1 == String::from_utf8_lossy(&before).lines().count() {
                assert_ne!(
                    read_file_head(&t.path, &|l: &[u8]| (t.genuine)(l, &pk)).unwrap(),
                    Some(head),
                    "{}: not a head",
                    t.chain
                );
            }
            std::fs::write(&t.path, before).unwrap();
            full(t).unwrap();
        }
    }
}
