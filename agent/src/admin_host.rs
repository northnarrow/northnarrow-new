//! nn-admin on the agent's host: the agent's implementation of
//! [`nn_admin::host::AdminHost`], which the `nn-admin` binary (this
//! package's shim) passes to nn-admin (Wave 4 restructure, R10, lab PR
//! 259).
//!
//! nn-admin depends on neither nn-linux nor the agent; what it reads of
//! them is bound here, each method the call the operator client made
//! before R10: the hardening checks (nn-linux's `host_hardening`), the
//! agent key's files (`keys`, under the agent's `audit` path), the agent's
//! chains and where they lie under its state directory (`chains`), the
//! overlay gate and its rollback floor (`config::overlay_auth`,
//! `config::overlay_floor`), the loaders' checks of an overlay and the
//! content the agent was built with, the offline engine on the Linux host
//! (`decision::replay`).

use std::path::{Path, PathBuf};

use ed25519_dalek::VerifyingKey;
use nn_admin::host::AdminHost;
use nn_core::config::overlay_auth::Decision;
use nn_core::decision::rule_policy::RulePolicy;
use nn_evidence::chain_anchor::{BootCheck, ChainTarget};
use nn_model::Event;
use nn_proto::admin_signed_payload::OverlayKind;

use crate::chains::ChainPaths;
use crate::config::overlay_auth::OverlayGate;
use crate::config::overlay_floor::RollbackFloor;

/// The agent's host, as nn-admin sees it.
#[derive(Debug, Clone, Copy, Default)]
pub struct AgentAdminHost;

/// The host's hardening checks, as [`crate::host_hardening::run`] found
/// them.
#[derive(Debug, Clone)]
pub struct HostHardening(Vec<crate::host_hardening::Check>);

impl nn_admin::host::HostChecks for HostHardening {
    fn count(&self) -> usize {
        self.0.len()
    }

    fn warn_count(&self) -> usize {
        crate::host_hardening::warn_count(&self.0)
    }

    fn render_table(&self) -> String {
        crate::host_hardening::render_table(&self.0)
    }

    fn to_json_pretty(&self) -> serde_json::Result<String> {
        serde_json::to_string_pretty(&self.0)
    }
}

impl nn_admin::host::Chains for ChainPaths {
    fn targets(&self) -> Vec<ChainTarget> {
        ChainPaths::targets(self)
    }

    fn boot_check(&self, targets: &[ChainTarget], heads: &Path, pk: &VerifyingKey) -> BootCheck {
        crate::chains::boot_check(targets, heads, pk)
    }
}

impl nn_admin::host::RollbackFloor for RollbackFloor {
    fn reset(&self) -> Option<&str> {
        RollbackFloor::reset(self)
    }

    fn not_before(&self) -> Option<u64> {
        RollbackFloor::not_before(self)
    }
}

impl nn_admin::host::OverlayGate for OverlayGate {
    fn check(&self, kind: OverlayKind, path: &Path) -> Decision {
        OverlayGate::check(self, kind, path)
    }
}

impl AdminHost for AgentAdminHost {
    type HostChecks = HostHardening;
    type Chains = ChainPaths;
    type Floor = RollbackFloor;
    type Gate = OverlayGate;

    fn host_checks(&self) -> HostHardening {
        HostHardening(crate::host_hardening::run())
    }

    fn verifying_key_path(&self, key_path: &Path) -> PathBuf {
        crate::audit::verifying_key_path(key_path)
    }

    fn read_verifying_key(&self, path: &Path) -> anyhow::Result<VerifyingKey> {
        crate::audit::read_verifying_key(path)
    }

    fn verifying_key_of_signing_key(&self, path: &Path) -> anyhow::Result<VerifyingKey> {
        crate::audit::read_signing_key(path).map(|key| key.verifying_key())
    }

    /// Where the agent keeps its chains under its state directory (was
    /// `nn-admin chain verify`'s own list).
    fn chains(&self, audit: PathBuf, state_dir: &Path) -> ChainPaths {
        let det = state_dir.join("detections");
        ChainPaths {
            audit,
            canary_registry: state_dir.join("canaries.jsonl"),
            canary_access: state_dir.join("canary_access.jsonl"),
            detections: det.join("detections.jsonl"),
            status_events: det.join("status_events.jsonl"),
            netflow: state_dir.join("netflow.jsonl"),
            fim_drift: state_dir.join("fim_drift.jsonl"),
        }
    }

    fn validate_overlay(&self, kind: OverlayKind, text: &str) -> anyhow::Result<()> {
        crate::config::overlay_auth::validate_content(kind, text)
    }

    fn shipped_default(&self, kind: OverlayKind) -> Option<&'static str> {
        crate::config::overlay_auth::shipped_default(kind)
    }

    fn rollback_floor(&self, audit_log: &Path, signing_key_file: &Path) -> RollbackFloor {
        RollbackFloor::scan(audit_log, signing_key_file)
    }

    fn overlay_gate(
        &self,
        admin_pub: &Path,
        agent_id: [u8; 16],
        floor: RollbackFloor,
    ) -> OverlayGate {
        OverlayGate::new(admin_pub, agent_id, floor)
    }

    fn policy_test(
        &self,
        policy: RulePolicy,
        events: &[Event],
        configs: &Path,
        proc_root: &Path,
    ) -> Vec<serde_json::Value> {
        crate::decision::replay::policy_test(policy, events, configs, proc_root)
    }
}
