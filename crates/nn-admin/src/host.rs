//! What nn-admin needs of the host it runs on and of the agent it
//! administers: the seam the agent binds (Wave 4 restructure, R10, lab PR
//! 259).
//!
//! nn-admin depends on nn-proto, nn-evidence, nn-core and nn-model, not on
//! nn-linux nor on the agent: the plan draws it beside nn-linux, both below
//! the agent (§2.1), and gives it "nn-proto, nn-evidence, nn-core and the
//! host checks" (§2.2); `docs/architecture/module-map.toml` says the same.
//! What it reads of the Linux host — the hardening checks, the agent key's
//! files — is nn-linux's; what it reads of the agent — the list of its
//! chains, the gate that decides which overlays its next start loads and
//! the rollback floor that gate keeps, the loaders' own checks of an
//! overlay, the offline engine on the agent's host — is still the agent's
//! (R04b, R04a/R05's payloads). [`AdminHost`] names them; the agent
//! implements it (`northnarrow_agent::admin_host::AgentAdminHost`) and the
//! `nn-admin` binary, a shim of the agent package, passes it in: the
//! composition binds nn-admin to its host as it binds nn-core's generics to
//! its Linux host.
//!
//! Every method is one call the code made directly before R10, in the same
//! place and order; what it returns is what that call returned.

use std::path::{Path, PathBuf};

use ed25519_dalek::VerifyingKey;
use nn_core::config::overlay_auth::Decision;
use nn_core::decision::rule_policy::RulePolicy;
use nn_evidence::chain_anchor::{BootCheck, ChainTarget};
use nn_model::Event;
use nn_proto::admin_signed_payload::OverlayKind;

/// The host nn-admin runs on and the agent it administers.
pub trait AdminHost {
    /// The host's hardening checks (`host-check`; `status`'s summary line).
    type HostChecks: HostChecks;
    /// The agent's chains, at given paths (`chain verify`).
    type Chains: Chains;
    /// The signed overlays' rollback floor, as the agent's next start reads
    /// it from the verified audit chain.
    type Floor: RollbackFloor;
    /// The signed-overlay gate, as the agent's next start builds it.
    type Gate: OverlayGate;

    /// The host's hardening checks, run now (the agent's
    /// `host_hardening::run`).
    fn host_checks(&self) -> Self::HostChecks;

    /// Where the public half of the agent key at `key_path` is published
    /// (the agent's `keys::verifying_key_path`).
    fn verifying_key_path(&self, key_path: &Path) -> PathBuf;
    /// The published public half at `path` (`keys::read_verifying_key`).
    fn read_verifying_key(&self, path: &Path) -> anyhow::Result<VerifyingKey>;
    /// The public half of the private key file at `path`, read and parsed,
    /// never minted (`keys::read_signing_key`: a host from before the
    /// public half was published).
    fn verifying_key_of_signing_key(&self, path: &Path) -> anyhow::Result<VerifyingKey>;

    /// The agent's chains: the audit log at `audit`, the others where the
    /// agent keeps them under its state directory `state_dir`.
    fn chains(&self, audit: PathBuf, state_dir: &Path) -> Self::Chains;

    /// The check the loader of `kind` applies to `text` (the agent's
    /// `config::overlay_auth::validate_content`): a signature must never
    /// cover content the agent would not load.
    fn validate_overlay(&self, kind: OverlayKind, text: &str) -> anyhow::Result<()>;
    /// The content of `kind` the agent was built with, which needs no
    /// signature (`config::overlay_auth::shipped_default`).
    fn shipped_default(&self, kind: OverlayKind) -> Option<&'static str>;
    /// The rollback floor the audit chain at `audit_log` proves, verified
    /// with the agent key at `signing_key_file` or its public half
    /// (`config::overlay_floor::RollbackFloor::scan`).
    fn rollback_floor(&self, audit_log: &Path, signing_key_file: &Path) -> Self::Floor;
    /// The gate the agent's next start builds from `admin_pub`, its
    /// identity and `floor` (`config::overlay_auth::OverlayGate::new`).
    fn overlay_gate(&self, admin_pub: &Path, agent_id: [u8; 16], floor: Self::Floor) -> Self::Gate;

    /// `policy test`: `events` through the offline engine on the agent's
    /// host under `policy`, the shipped lists read from `configs`, `/proc`
    /// at `proc_root`, one decision per event (`decision::replay::
    /// policy_test`).
    fn policy_test(
        &self,
        policy: RulePolicy,
        events: &[Event],
        configs: &Path,
        proc_root: &Path,
    ) -> Vec<serde_json::Value>;
}

/// The host's hardening checks (the agent's `host_hardening`).
pub trait HostChecks {
    /// How many checks ran.
    fn count(&self) -> usize;
    /// How many warn (`host_hardening::warn_count`).
    fn warn_count(&self) -> usize;
    /// The table `host-check` prints (`host_hardening::render_table`).
    fn render_table(&self) -> String;
    /// The checks as `host-check --json` prints them
    /// (`serde_json::to_string_pretty`).
    fn to_json_pretty(&self) -> serde_json::Result<String>;
}

/// The agent's chains (the agent's `chains::ChainPaths`).
pub trait Chains {
    /// Every chain, in the agent's fixed order (`ChainPaths::targets`).
    fn targets(&self) -> Vec<ChainTarget>;
    /// The chains compared with their anchored heads and checkpoints, read
    /// as the agent reads them (`chains::boot_check`).
    fn boot_check(&self, targets: &[ChainTarget], heads: &Path, pk: &VerifyingKey) -> BootCheck;
}

/// The signed overlays' rollback floor (the agent's
/// `config::overlay_floor::RollbackFloor`).
pub trait RollbackFloor {
    /// Why the next start resets the floor (`RollbackFloor::reset`).
    fn reset(&self) -> Option<&str>;
    /// No overlay signed before this time is loaded
    /// (`RollbackFloor::not_before`).
    fn not_before(&self) -> Option<u64>;
}

/// The signed-overlay gate (the agent's `config::overlay_auth::OverlayGate`).
pub trait OverlayGate {
    /// The boot decision for `kind` read from `path` (`OverlayGate::check`).
    fn check(&self, kind: OverlayKind, path: &Path) -> Decision;
}
