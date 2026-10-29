//! The capability manifest (lab PR 218; external review G-12, G-36;
//! `docs/operator/BOOT_INTEGRITY.md`).
//!
//! At every boot, before the event loop, the agent signs what it runs with:
//! the kernel and its BTF, the active LSMs, the deny hooks expected and
//! attached, the deny self-test, each sensor's attach point, the host
//! hardening table, the response mode, the degradations and the trust
//! level. It is one `capability_manifest` row of the signed audit chain
//! (the agent's key, hash-chained: `nn-admin audit verify` checks it), and
//! `nn-admin capabilities --key` reads it back from the running agent with
//! the row's `entry_hash`.

use std::sync::Arc;

use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use tracing::{info, warn};

use crate::audit::{AuditEntryDraft, AuditLog};

/// The audit op of the manifest row.
pub const AUDIT_OP: &str = "capability_manifest";
/// Bumped when a field changes meaning or goes.
pub const MANIFEST_VERSION: u32 = 1;

/// R09b shim (lab PR 254; plan §4.1 rule 2, removed in R17): the sensors'
/// attach points are noted by the eBPF loader and the sensors, nn-linux's.
pub use nn_linux::boot::manifest::{note_sensor, sensors, SensorEntry};

/// The deny hooks of the boot.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DenyHooks {
    pub expected: usize,
    pub attached: usize,
    /// Each missing hook with why, and the failed protection steps.
    pub missing: Vec<String>,
    /// The observe hooks that did not attach.
    pub observe_missing: Vec<String>,
}

/// One row of the host hardening table.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostCheck {
    pub id: String,
    pub status: String,
    pub value: String,
}

/// What this boot runs with.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilityManifest {
    pub manifest_version: u32,
    pub agent_version: String,
    /// `/proc/sys/kernel/osrelease`.
    pub kernel: String,
    /// `/sys/kernel/btf/vmlinux` was there, and the offsets resolved from
    /// it (the drifted ones read at their runtime value; the absent ones
    /// disable the path that needs them).
    pub btf: bool,
    pub btf_offsets_resolved: usize,
    pub btf_offsets_drifted: usize,
    pub btf_offsets_absent: Vec<String>,
    /// `/sys/kernel/security/lsm`, and what it says of `bpf`.
    pub active_lsms: Option<String>,
    pub bpf_lsm: String,
    pub deny_hooks: DenyHooks,
    pub deny_self_test: String,
    /// The BPF map guard enforces or only observes (a debug build).
    pub bpf_guard: String,
    pub sensors: Vec<SensorEntry>,
    pub host_hardening: Vec<HostCheck>,
    pub detect_only: bool,
    pub degradations: Vec<String>,
    pub trust_level: u8,
    pub trust_reasons: Vec<String>,
}

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

/// The signed manifest of this boot and its row's `entry_hash`, for
/// `nn-admin capabilities` (R11c, lab PR 264: the slot the start gives the
/// run phase, which signs into it, and the admin socket, which reads it;
/// it was a process-wide `CURRENT`).
#[derive(Clone, Debug, Default)]
pub struct SignedManifest(Arc<Mutex<Option<Signed>>>);

/// A signed manifest and its row's `entry_hash` (`None`: not signed, no
/// audit log).
type Signed = (CapabilityManifest, Option<String>);

impl SignedManifest {
    /// Sign `manifest` (see [`sign`]) and keep it here.
    pub fn sign(
        &self,
        audit_log: Option<&Arc<Mutex<AuditLog>>>,
        manifest: CapabilityManifest,
    ) -> Option<String> {
        let entry_hash = sign(audit_log, &manifest);
        *self.0.lock() = Some((manifest, entry_hash.clone()));
        entry_hash
    }

    /// The manifest of this boot for `nn-admin capabilities`: one JSON
    /// object, `{"entry_hash": …, "manifest": {…}}`. `None` before the boot
    /// signed it.
    pub fn current_json(&self) -> Option<String> {
        let cur = self.0.lock();
        let (m, hash) = cur.as_ref()?;
        serde_json::to_string(&serde_json::json!({ "entry_hash": hash, "manifest": m })).ok()
    }
}

/// Sign `manifest` in the audit chain (when there is one). Returns the
/// row's `entry_hash`.
pub fn sign(
    audit_log: Option<&Arc<Mutex<AuditLog>>>,
    manifest: &CapabilityManifest,
) -> Option<String> {
    let entry_hash = audit_log.and_then(|log| {
        let extra = match serde_json::to_value(manifest) {
            Ok(v) => v,
            Err(e) => {
                warn!(error = %e, "capability manifest not serialisable");
                return None;
            }
        };
        let draft = AuditEntryDraft {
            op: AUDIT_OP.to_string(),
            extra,
            key_fp: "agent-self".to_string(),
            cosigner_fps: Vec::new(),
            result: "success".to_string(),
            client_pid: std::process::id(),
            client_uid: 0,
            client_comm: "northnarrow-agent".to_string(),
            client_exe: None,
        };
        match log.lock().append(draft) {
            Ok(entry) => Some(entry.entry_hash),
            Err(e) => {
                warn!(error = %format!("{e:#}"), "capability manifest not recorded in the audit chain");
                None
            }
        }
    });
    info!(
        trust_level = manifest.trust_level,
        deny_attached = manifest.deny_hooks.attached,
        deny_expected = manifest.deny_hooks.expected,
        deny_self_test = %manifest.deny_self_test,
        sensors = manifest.sensors.len(),
        degradations = manifest.degradations.len(),
        entry_hash = entry_hash.as_deref().unwrap_or("(not signed: no audit log)"),
        "capability manifest of this boot"
    );
    entry_hash
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::AgentSigningKey;

    fn sample() -> CapabilityManifest {
        CapabilityManifest {
            manifest_version: MANIFEST_VERSION,
            agent_version: "0.0.1".to_string(),
            kernel: "6.8.0-142-generic".to_string(),
            btf: true,
            btf_offsets_resolved: 41,
            btf_offsets_drifted: 0,
            btf_offsets_absent: Vec::new(),
            active_lsms: Some("lockdown,capability,landlock,yama,apparmor,bpf".to_string()),
            bpf_lsm: "active".to_string(),
            deny_hooks: DenyHooks {
                expected: 19,
                attached: 19,
                missing: Vec::new(),
                observe_missing: Vec::new(),
            },
            deny_self_test: "denied".to_string(),
            bpf_guard: "enforce".to_string(),
            sensors: vec![SensorEntry {
                sensor: "exec".to_string(),
                attach: "lsm:bprm_check_security".to_string(),
            }],
            host_hardening: Vec::new(),
            detect_only: false,
            degradations: Vec::new(),
            trust_level: 3,
            trust_reasons: Vec::new(),
        }
    }

    /// External review G-12: the manifest is a signed row of the audit
    /// chain, whose `extra` is the manifest itself; the chain verifies.
    #[test]
    fn the_manifest_is_a_signed_row_of_the_audit_chain() {
        let dir = tempfile::tempdir().unwrap();
        let key_path = dir.path().join("agent.sig");
        let key = AgentSigningKey::load_or_bootstrap(&key_path).unwrap();
        let pk = key.verifying_key();
        let log = Arc::new(Mutex::new(
            AuditLog::open(&dir.path().join("audit.log"), key, [3u8; 16]).unwrap(),
        ));
        let current = SignedManifest::default();
        assert!(current.current_json().is_none(), "nothing signed yet");
        let hash = current.sign(Some(&log), sample()).expect("signed");
        let body = std::fs::read_to_string(dir.path().join("audit.log")).unwrap();
        let rows: Vec<crate::audit::AuditEntry> = body
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].op, AUDIT_OP);
        assert_eq!(rows[0].entry_hash, hash);
        let back: CapabilityManifest = serde_json::from_value(rows[0].extra.clone()).unwrap();
        assert_eq!(back, sample());
        crate::audit::verify_chain(&rows, &pk).expect("the chain verifies");
        let cur: serde_json::Value =
            serde_json::from_str(&current.current_json().unwrap()).unwrap();
        assert_eq!(cur["entry_hash"], hash);
        assert_eq!(cur["manifest"]["trust_level"], 3);
    }
}
