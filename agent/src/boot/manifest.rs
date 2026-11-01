//! The capability manifest (lab PR 218; external review G-12, G-36; R13,
//! lab PR 271 — plan §3.6, report 06 INI-09 / R4-01;
//! `docs/operator/BOOT_INTEGRITY.md`, `docs/operator/SENSOR_CONTRACT.md`).
//!
//! At every boot, before the event loop, the agent signs what it runs with:
//! the kernel and its BTF, the active LSMs, the deny hooks expected and
//! attached, the deny self-test, each sensor's attach point, the host
//! hardening table, the response mode, the degradations and the trust
//! level — and since R13 each source of the bus and each class of events
//! against the sensor contract (`nn_core::contract`, the Linux values in
//! `nn_linux::sensors::contract`): where it runs (its attach point, a
//! fallback, nothing), its state (ok, standby, disabled, attached and not
//! invoked, unavailable, its adapter ended) and why, the telemetry probe's
//! word on it, its terms; the fallbacks in use and what is missing; the
//! shipped content lists not in force from their file. It is one
//! `capability_manifest` row of the signed audit chain (revision 0).
//!
//! While the agent runs, [`SignedManifest`] builds it again from the same
//! measurements and what changed since — the degradations recorded
//! (`attest_degraded*` and every `degradation::report`), the telemetry
//! probe's rounds, an adapter that ended, a default list given way to — and
//! signs each change as a `capability_manifest_change` row: the next
//! revision, what changed, its hash and the one before. `nn-admin
//! capabilities --key` and `nn-admin status --key` read the newest
//! revision (the status's trust level and degradations are its), and every
//! heartbeat carries its hash: one truth, signed.

use std::sync::Arc;
use std::time::Duration;

use nn_core::contract::manifest::{
    class_entries, fallbacks_and_missing, source_entries, SourceFacts,
};
use nn_evidence::heartbeat::BeatManifest;
use parking_lot::Mutex;
use tracing::{info, warn};

use super::deny_selftest::SelfTestOutcome;
use super::lsm::BpfLsm;
use super::trust::TrustInputs;
use crate::audit::{AuditEntryDraft, AuditLog};

/// The audit op of the boot's manifest row (revision 0).
pub const AUDIT_OP: &str = "capability_manifest";
/// R13: the audit op of a revision signed while the agent runs.
pub const CHANGE_OP: &str = "capability_manifest_change";
/// R13: how often the running agent builds its manifest again (a change
/// is signed within this, plus the registry's own flush of a report made
/// without the audit log, `degradation::FLUSH_PERIOD`).
pub const REFRESH_PERIOD: Duration = Duration::from_secs(5);

/// The manifest's types, nn-core's since R13 (the plan's
/// `contract::CapabilityManifest`).
pub use nn_core::contract::manifest::{
    CapabilityManifest, DenyHooks, HostCheck, SensorEntry, MANIFEST_VERSION,
};

/// R09b shim (lab PR 254; plan §4.1 rule 2, removed in R17): the sensors'
/// attach points are noted by the eBPF loader and the sensors, nn-linux's
/// (R11c, lab PR 264: into the multiplexer's own `AttachPoints`).
pub use nn_linux::boot::manifest::AttachPoints;

/// The host hardening table as the manifest lists it.
pub fn host_checks(checks: &[crate::host_hardening::Check]) -> Vec<HostCheck> {
    checks
        .iter()
        .map(|c| HostCheck {
            id: c.id.to_string(),
            status: serde_json::to_value(c.status)
                .ok()
                .and_then(|v| v.as_str().map(str::to_string))
                .unwrap_or_default(),
            value: c.value.clone(),
        })
        .collect()
}

/// `/proc/sys/kernel/osrelease`, or `unknown`.
pub fn kernel_release() -> String {
    std::fs::read_to_string("/proc/sys/kernel/osrelease")
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|_| "unknown".to_string())
}

/// What every revision is built from: the boot's measurements, and the
/// handles of what changes while the agent runs.
#[derive(Clone)]
pub struct Inputs {
    /// The boot's part of the manifest: what the run does not change (the
    /// kernel, its BTF and LSMs, the deny hooks, the self-test, the BPF
    /// guard, the host hardening, the response mode). The rest is filled at
    /// each build.
    pub base: CapabilityManifest,
    pub bpf_lsm: BpfLsm,
    pub self_test: SelfTestOutcome,
    pub trust: TrustInputs,
    pub attach_points: AttachPoints,
    /// The telemetry probe (`None`: switched off).
    pub probe: Option<crate::telemetry_probe::TelemetryProbe>,
    pub probe_every: Option<Duration>,
    /// The shipped lists given way to the copy built into the agent, or
    /// edited by hand (`report_builtin_defaults`, through the overlay gate).
    pub content: Option<Arc<crate::config::overlay_auth::OverlayGate>>,
    /// The pumps and drains the start registered (`None`: not known).
    pub pumps: Option<Vec<String>>,
}

/// Whether the BPF LSM programs run, and why not (`None`: not known).
fn lsm_runs(bpf_lsm: &BpfLsm, self_test: &SelfTestOutcome) -> (Option<bool>, String) {
    match (bpf_lsm, self_test) {
        (BpfLsm::Absent { list }, _) => (
            Some(false),
            format!(
                "bpf is not in the active LSM list ({list}): its BPF LSM programs attach and the \
                 kernel never runs them"
            ),
        ),
        (_, SelfTestOutcome::NotDenied) => (
            Some(false),
            "the deny self-test's signal was delivered: the BPF LSM programs do not run"
                .to_string(),
        ),
        (_, SelfTestOutcome::Denied) => (Some(true), String::new()),
        (_, SelfTestOutcome::Inconclusive(_)) => (None, String::new()),
    }
}

/// The manifest of `inputs` now, with the adapters that ended.
fn build(inputs: &Inputs, terminated: &[String]) -> CapabilityManifest {
    use crate::boot::degradation;
    let mut m = inputs.base.clone();
    m.manifest_version = MANIFEST_VERSION;
    m.contract_version = nn_core::contract::CONTRACT_VERSION;
    m.degradations = degradation::snapshot();
    let trust = super::trust::current(Some(&inputs.trust)).unwrap_or_else(|| super::trust::Trust {
        level: super::trust::TrustLevel::L0,
        reasons: vec!["the boot measured nothing".to_string()],
    });
    m.trust_level = trust.level.as_u8();
    m.trust_reasons = trust.reasons;
    m.sensors = inputs.attach_points.list();
    let (runs, why) = lsm_runs(&inputs.bpf_lsm, &inputs.self_test);
    let facts = SourceFacts {
        notes: m.sensors.clone(),
        lsm_runs: runs,
        lsm_why: why,
        probe: inputs
            .probe
            .as_ref()
            .map(|p| p.states())
            .unwrap_or_default(),
        degradations: degradation::entries()
            .into_iter()
            .map(|d| (d.source, d.detail))
            .collect(),
        terminated: terminated.to_vec(),
        running: inputs.pumps.clone(),
    };
    let contract = &nn_linux::sensors::contract::SOURCES;
    m.sources = source_entries(contract, &facts);
    m.classes = class_entries(contract, &m.sources);
    (m.fallbacks, m.missing) = fallbacks_and_missing(&m.sources, &m.deny_hooks);
    m.content = inputs
        .content
        .as_ref()
        .map(|g| g.defaults_in_force())
        .unwrap_or_default();
    m.telemetry_probe = match (&inputs.probe, inputs.probe_every) {
        (Some(_), Some(every)) => format!("every {} s", every.as_secs()),
        _ => "off".to_string(),
    };
    m.settled = m.probe_settled();
    m.revision = 0;
    m.hash = String::new();
    m.previous_hash = None;
    m.change = Vec::new();
    m
}

#[derive(Default)]
struct Live {
    inputs: Option<Inputs>,
    audit: Option<Arc<Mutex<AuditLog>>>,
    /// The newest revision and its row's `entry_hash` (`None`: not signed).
    current: Option<(CapabilityManifest, Option<String>)>,
    terminated: Vec<String>,
}

/// The signed manifest of this run, its newest revision (R11c, lab PR 264:
/// the slot the start gives the run phase, which signs into it, and the
/// admin socket, which reads it; R13: it builds and signs the revisions
/// too). Cheap to clone.
#[derive(Clone, Default)]
pub struct SignedManifest(Arc<Mutex<Live>>);

impl SignedManifest {
    /// Sign `manifest` as this boot's (revision 0, op [`AUDIT_OP`]; see
    /// [`sign`]) and keep it here.
    pub fn sign(
        &self,
        audit_log: Option<&Arc<Mutex<AuditLog>>>,
        mut manifest: CapabilityManifest,
    ) -> Option<String> {
        manifest.revision = 0;
        manifest.previous_hash = None;
        manifest.change = Vec::new();
        manifest.hash = manifest.content_hash();
        let entry_hash = sign(audit_log, &manifest);
        let mut live = self.0.lock();
        live.audit = audit_log.cloned();
        live.current = Some((manifest, entry_hash.clone()));
        entry_hash
    }

    /// R13: the boot's manifest built from `inputs` and signed (revision 0);
    /// later revisions are built from the same inputs ([`Self::refresh`]).
    pub fn arm(&self, audit_log: Option<&Arc<Mutex<AuditLog>>>, inputs: Inputs) -> Option<String> {
        let m = build(&inputs, &[]);
        self.0.lock().inputs = Some(inputs);
        self.sign(audit_log, m)
    }

    /// R13: build the manifest again; when its hash moved, sign the change
    /// (op [`CHANGE_OP`]) as the next revision. Returns that revision.
    pub fn refresh(&self) -> Option<u64> {
        let mut live = self.0.lock();
        let inputs = live.inputs.as_ref()?;
        let mut m = build(inputs, &live.terminated);
        let (before, _) = live.current.as_ref()?;
        let hash = m.content_hash();
        if hash == before.hash {
            return None;
        }
        m.change = m.changes_from(before);
        m.revision = before.revision + 1;
        m.previous_hash = Some(before.hash.clone());
        m.hash = hash;
        warn!(
            revision = m.revision,
            hash = %m.hash,
            change = %m.change.join("; "),
            "the capability manifest changed (signed capability_manifest_change)"
        );
        let entry_hash = sign_change(live.audit.as_ref(), &m);
        let revision = m.revision;
        live.current = Some((m, entry_hash));
        Some(revision)
    }

    /// R13: the adapters of `sources` ended (a pump, a drain): their state
    /// in a signed revision, before the agent stops.
    pub fn adapters_terminated(&self, sources: &[&str]) -> Option<u64> {
        {
            let mut live = self.0.lock();
            for s in sources {
                if !live.terminated.iter().any(|t| t == s) {
                    live.terminated.push(s.to_string());
                }
            }
        }
        self.refresh()
    }

    /// The newest revision for `nn-admin capabilities`: one JSON object,
    /// `{"entry_hash": …, "manifest": {…}}`. `None` before the boot signed
    /// it.
    pub fn current_json(&self) -> Option<String> {
        let live = self.0.lock();
        let (m, hash) = live.current.as_ref()?;
        serde_json::to_string(&serde_json::json!({ "entry_hash": hash, "manifest": m })).ok()
    }

    /// The newest revision.
    pub fn current(&self) -> Option<CapabilityManifest> {
        self.0.lock().current.as_ref().map(|(m, _)| m.clone())
    }

    /// R13: what a heartbeat carries of it — the newest revision's hash,
    /// its number, and whether the telemetry probe has had its word.
    pub fn beat(&self) -> Option<BeatManifest> {
        let live = self.0.lock();
        let (m, _) = live.current.as_ref()?;
        Some(BeatManifest {
            hash: m.hash.clone(),
            revision: m.revision,
            settled: m.settled,
        })
    }

    /// R13: build and sign the changes every [`REFRESH_PERIOD`] on the
    /// runtime, from now on.
    pub fn spawn_watcher(&self) {
        let me = self.clone();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(REFRESH_PERIOD);
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            tick.tick().await;
            loop {
                tick.tick().await;
                me.refresh();
            }
        });
    }
}

/// Sign `manifest` in the audit chain as the boot's (when there is one).
/// Returns the row's `entry_hash`.
pub fn sign(
    audit_log: Option<&Arc<Mutex<AuditLog>>>,
    manifest: &CapabilityManifest,
) -> Option<String> {
    let entry_hash = append(audit_log, AUDIT_OP, "success", manifest);
    info!(
        trust_level = manifest.trust_level,
        deny_attached = manifest.deny_hooks.attached,
        deny_expected = manifest.deny_hooks.expected,
        deny_self_test = %manifest.deny_self_test,
        sensors = manifest.sensors.len(),
        sources = manifest.sources.len(),
        fallbacks = manifest.fallbacks.len(),
        missing = manifest.missing.len(),
        degradations = manifest.degradations.len(),
        hash = %manifest.hash,
        entry_hash = entry_hash.as_deref().unwrap_or("(not signed: no audit log)"),
        "capability manifest of this boot"
    );
    entry_hash
}

/// R13: sign a revision made while the agent runs.
fn sign_change(
    audit_log: Option<&Arc<Mutex<AuditLog>>>,
    manifest: &CapabilityManifest,
) -> Option<String> {
    append(audit_log, CHANGE_OP, "detected", manifest)
}

fn append(
    audit_log: Option<&Arc<Mutex<AuditLog>>>,
    op: &str,
    result: &str,
    manifest: &CapabilityManifest,
) -> Option<String> {
    audit_log.and_then(|log| {
        let extra = match serde_json::to_value(manifest) {
            Ok(v) => v,
            Err(e) => {
                warn!(error = %e, "capability manifest not serialisable");
                return None;
            }
        };
        let draft = AuditEntryDraft {
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
        match log.lock().append(draft) {
            Ok(entry) => Some(entry.entry_hash),
            Err(e) => {
                warn!(error = %format!("{e:#}"), op, "capability manifest not recorded in the audit chain");
                None
            }
        }
    })
}

#[cfg(test)]
mod tests;
