//! The exec quarantine's records (lab PR 223): one signed detection record
//! (`NN-L-EXECQ-001`) per decision, in the detection chain, through the
//! per-rule budget like every rule's; signed audit entries for the guard's
//! own events (degradations, recovery at boot, stop).

use std::sync::Arc;

use common::execq::ScanResult;
use common::{Event, ResponseAction, Verdict};
use parking_lot::Mutex;
use tracing::warn;

use super::controller::Recorder;
use super::policy::{Action, Outcome};
use super::{attack_refs, CATEGORY, RULE_ID, RULE_NAME};
use crate::decision::attack::AttackRef;
use crate::detection_store::{DetectionSink, ExecqEvidence};

/// One decision, ready for the detection chain.
#[derive(Debug, Clone)]
pub struct ExecqRecord {
    pub event: Event,
    pub verdict: Verdict,
    pub response: String,
    /// Its ATT&CK references (lab PR 221: typed, of [`super::ATTACK`]).
    pub attack: Vec<AttackRef>,
    pub evidence: ExecqEvidence,
}

impl ExecqRecord {
    pub fn new(
        event: Event,
        path: &str,
        o: &Outcome,
        evidence: ExecqEvidence,
        response: String,
        format: &str,
    ) -> Self {
        let (pid, timestamp_ns) = match &event {
            Event::ExecCheck {
                pid, timestamp_ns, ..
            } => (*pid, *timestamp_ns),
            _ => (0, 0),
        };
        let action = match (o.action, o.quarantine) {
            (Action::Resume, _) => ResponseAction::Log,
            (Action::Kill, true) => ResponseAction::Quarantine,
            (Action::Kill, false) => ResponseAction::KillProcess,
        };
        let reasoning = format!(
            "first sight of an executable in a guarded location ({}): {} — {}",
            evidence.classes.join(", "),
            evidence.verdict,
            o.why
        );
        ExecqRecord {
            verdict: Verdict {
                rule_id: RULE_ID.to_string(),
                rule_name: RULE_NAME.to_string(),
                category: CATEGORY.to_string(),
                action,
                severity: o.severity,
                reasoning,
                event_pid: pid,
                event_filename: path.to_string(),
                timestamp_ns,
            },
            event,
            response,
            attack: attack_refs(format),
            evidence,
        }
    }

    /// The technique ids of [`Self::attack`].
    pub fn techniques(&self) -> Vec<&'static str> {
        self.attack.iter().map(|r| r.technique.as_str()).collect()
    }
}

/// The record's evidence.
pub fn evidence(
    scan: Option<&ScanResult>,
    o: &Outcome,
    enforce: bool,
    held: bool,
    held_ms: u64,
    class: u32,
    notes: &[String],
) -> ExecqEvidence {
    let mut reasons: Vec<String> = scan
        .map(|r| {
            r.reasons
                .iter()
                .map(|x| {
                    if x.weight > 0 {
                        format!("{} (+{}): {}", x.code, x.weight, x.detail)
                    } else {
                        format!("{}: {}", x.code, x.detail)
                    }
                })
                .collect()
        })
        .unwrap_or_default();
    reasons.extend(notes.iter().cloned());
    ExecqEvidence {
        verdict: scan.map_or("none", |r| r.verdict.as_str()).to_string(),
        sha256: scan.map(|r| common::execq::hex32(&r.sha256)),
        format: scan.map(|r| r.format.clone()),
        reasons,
        decision: if enforce {
            o.action.as_str().to_string()
        } else {
            format!("would {}", o.action.as_str())
        },
        basis: o.why.clone(),
        classes: common::wire::execq::class_names(class)
            .into_iter()
            .map(str::to_string)
            .collect(),
        held,
        held_ms,
    }
}

type AuditLog = Arc<Mutex<crate::audit::AuditLog>>;

/// The production recorder: the detection sink (through the per-rule
/// budget) and the signed audit log.
pub struct SinkRecorder {
    pub sink: Option<DetectionSink>,
    pub audit: Option<AuditLog>,
    pub posture: Box<dyn Fn() -> common::posture_types::PostureKind + Send>,
}

impl SinkRecorder {
    fn append(&self, op: &str, extra: serde_json::Value, result: &str) {
        let Some(log) = &self.audit else {
            return;
        };
        let draft = crate::audit::AuditEntryDraft {
            op: op.to_string(),
            extra,
            key_fp: "agent-self".to_string(),
            cosigner_fps: Vec::new(),
            result: result.to_string(),
            client_pid: std::process::id(),
            client_uid: 0,
            client_comm: "northnarrow-agent".to_string(),
            client_exe: None,
        };
        if let Err(e) = log.lock().append(draft) {
            warn!(
                error = format!("{e:#}"),
                op, "exec quarantine audit entry failed"
            );
        }
    }
}

impl Recorder for SinkRecorder {
    fn detection(&self, rec: ExecqRecord) {
        let Some(sink) = &self.sink else {
            return;
        };
        let uid = crate::detection_store::Principal::from_event(&rec.event).uid;
        let admit = crate::detection_budget::admit(RULE_ID, uid, || {
            crate::detection_store::held_sample(&rec.event)
        });
        if let crate::detection_budget::Admit::Record { suppressed_before } = admit {
            warn!(
                rule = RULE_ID,
                severity = ?rec.verdict.severity,
                target_pid = rec.verdict.event_pid,
                target_filename = %common::log_escape::Escaped(&rec.verdict.event_filename),
                verdict = %rec.evidence.verdict,
                decision = %rec.evidence.decision,
                response = %common::log_escape::Escaped(&rec.response),
                "VERDICT (exec quarantine)"
            );
            sink.record_execq(
                &rec.event,
                &rec.verdict,
                (self.posture)(),
                rec.response,
                &rec.attack,
                rec.evidence,
                suppressed_before,
            );
        }
    }

    fn audit(&self, extra: serde_json::Value, result: &str) {
        self.append(super::AUDIT_OP, extra, result);
    }

    fn degraded(&self, detail: &str) {
        self.append(
            crate::self_integrity::AUDIT_OP,
            serde_json::json!({ "kind": "subsystem_degraded", "detail": detail, "at_boot": false }),
            "detected",
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::execq::policy::{decide, Basis, Policy};
    use common::execq::{Reason, ScanVerdict};
    use common::wire::execq::class;

    fn event() -> Event {
        Event::ExecCheck {
            pid: 42,
            ppid: 1,
            uid: 1000,
            comm: "nn-x".into(),
            filename: String::new(),
            timestamp_ns: 9,
            exe: Default::default(),
        }
    }

    #[test]
    fn a_blocked_file_is_a_critical_quarantine_with_its_reasons() {
        let o = decide(&Policy::default(), &Basis::Scanned(ScanVerdict::Malicious));
        let scan = ScanResult {
            id: 1,
            sha256: [0xab; 32],
            size: 10,
            verdict: ScanVerdict::Malicious,
            reasons: vec![
                Reason::new("blocklist", "nn-lab-test-elf", 0),
                Reason::new("elf.static_stripped", "static binary", 2),
            ],
            format: "elf64-x86_64-exec".into(),
            micros: 5,
        };
        let ev = evidence(
            Some(&scan),
            &o,
            true,
            true,
            12,
            class::TMP,
            &["target: image".into()],
        );
        assert_eq!(ev.verdict, "malicious");
        assert_eq!(ev.sha256.as_deref(), Some(&"ab".repeat(32)[..]));
        assert_eq!(ev.reasons[0], "blocklist: nn-lab-test-elf");
        assert_eq!(ev.reasons[1], "elf.static_stripped (+2): static binary");
        assert_eq!(ev.reasons[2], "target: image");
        assert_eq!(ev.classes, ["tmp"]);
        let r = ExecqRecord::new(
            event(),
            "/tmp/nn-x",
            &o,
            ev,
            "killed while held".into(),
            "elf64-x86_64-exec",
        );
        assert_eq!(r.verdict.rule_id, RULE_ID);
        assert_eq!(r.verdict.action, ResponseAction::Quarantine);
        assert_eq!(r.verdict.severity, common::Severity::Critical);
        assert_eq!(r.verdict.event_pid, 42);
        assert_eq!(r.techniques(), ["T1204.002"]);
        assert!(r.verdict.reasoning.contains("block-listed"));
    }

    #[test]
    fn observe_mode_says_would_and_an_expiry_has_no_verdict() {
        let o = decide(
            &Policy {
                enforce: false,
                ..Policy::default()
            },
            &Basis::Expired {
                detail: "no scan verdict".into(),
            },
        );
        let ev = evidence(None, &o, false, false, 2000, class::HOME, &[]);
        assert_eq!(ev.decision, "would resume");
        assert_eq!(ev.verdict, "none");
        assert!(ev.sha256.is_none() && ev.format.is_none());
        assert!(ev.basis.contains("budget expired"));
        let r = ExecqRecord::new(
            event(),
            "/home/u/x",
            &o,
            ev,
            "observe".into(),
            "script:/bin/sh",
        );
        assert_eq!(r.verdict.action, ResponseAction::Log);
        assert_eq!(r.techniques(), ["T1204.002", "T1059.004"]);
    }
}
