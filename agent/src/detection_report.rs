//! The detection budget's reporter task (from `detection_budget`, Wave 4
//! restructure, R08a, lab PR 250).
//!
//! Every [`REPORT_SECS`] it takes what the per-(rule, uid) budget held back
//! — one WARN per pair, one signed `detections_held` audit entry with the
//! counts and samples — and the records the detection store's queue
//! dropped in that window (external audit NN-AUD-111). A tokio task over
//! the agent's audit log and detection sink: it stays in the agent when the
//! budget goes to nn-core, and reads it through `detection_budget::take_held`.

use std::sync::Arc;
use std::time::Duration;

use tracing::warn;

use crate::detection_budget::{self, AUDIT_OP, REPORT_SECS};

/// Report held-back detections every [`REPORT_SECS`]: one WARN per
/// (rule, uid) and one signed audit entry for all of them. External audit
/// NN-AUD-111: in the same window, the records the detection store's queue
/// dropped ([`crate::detection_store::DetectionSink::report_drops`]).
pub fn spawn_reporter(
    audit_log: Option<Arc<parking_lot::Mutex<crate::audit::AuditLog>>>,
    detection_sink: Option<crate::detection_store::DetectionSink>,
) {
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_secs(REPORT_SECS));
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tick.tick().await;
            if let Some(sink) = &detection_sink {
                sink.report_drops(audit_log.as_deref());
            }
            let held = detection_budget::take_held();
            if held.is_empty() {
                continue;
            }
            for h in &held {
                warn!(
                    rule = %h.rule,
                    uid = h.uid,
                    held = h.count,
                    samples = ?h.samples,
                    "detections acted on but not logged or stored (per-rule budget, or repeats \
                     coalesced into a record)"
                );
            }
            let Some(log) = audit_log.as_ref() else {
                continue;
            };
            let draft = crate::audit::AuditEntryDraft {
                op: AUDIT_OP.to_string(),
                extra: serde_json::json!({
                    "window_secs": REPORT_SECS,
                    "held": held
                        .iter()
                        .map(|h| serde_json::json!({
                            "rule": h.rule,
                            "uid": h.uid,
                            "count": h.count,
                            "samples": h.samples,
                        }))
                        .collect::<Vec<_>>(),
                }),
                key_fp: "agent-self".to_string(),
                cosigner_fps: Vec::new(),
                result: "detected".to_string(),
                client_pid: std::process::id(),
                client_uid: 0,
                client_comm: "northnarrow-agent".to_string(),
                client_exe: None,
            };
            if let Err(e) = log.lock().append(draft) {
                warn!(
                    error = format!("{e:#}"),
                    "detections-held audit entry failed"
                );
            }
        }
    });
}
