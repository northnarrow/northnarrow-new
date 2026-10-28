//! Tappa 9.5 — Deception layer / canary tokens userland.
//!
//! Modules per design §11:
//!
//! - `registry` (K2, this commit) — deploy + list + burn +
//!   refresh state machine + chained on-disk DB. Reuses the
//!   Tappa 8 B1 audit-log primitives (`AgentSigningKey` +
//!   `GENESIS_PREV_HASH`) the same way Tappa 9 C3 `BaselineDb`
//!   does.
//! - `detector` (K3, follow-up) — inline `process_event` filter
//!   that intercepts `Event::Fim` / `Event::ProcessSpawn` /
//!   `Event::TcpConnect` BEFORE the rule engine sees them (§12 Q9
//!   OPTION B inline-filter lock-in).
//! - `chain_lines` (lab PR 178) — the bounded line reader of the two
//!   chains: a line over the cap or not UTF-8 is skipped and counted.
//! - `network` (lab PR 163) — what a Network canary covers (a decoy
//!   address and port a local process connects to) and its deploy check.
//! - `templates` (K4) — credential-canary content renderer
//!   (5 cred families: AWS / GCP / Azure / SSH priv-key / Git
//!   token) reading from `/etc/northnarrow/canary-templates/`.
//! - Rules NN-L-CANARY-001..004 live in
//!   `agent/src/decision/rules/canary.rs` (K5).

/// R05 shim (lab PR 241; removed in R17): the canary chains' line reader is
/// nn-evidence's.
pub use nn_evidence::chain_lines;
/// R09a shim (lab PR 253; plan §4.1 rule 2, removed in R17): the stores of
/// the canary detector's host — the signed registry and access log, this
/// host's interface addresses, the read-forward set — are nn-linux's, with
/// the host (`canary_host_linux`), which names them.
pub use nn_linux::canary::{access_log, network, read_forward, registry};
/// R08b shim (lab PR 251; plan §4.1 rule 2, removed in R17): the canary
/// detector and its indexes are nn-core's, on the agent's host — its signed
/// registry and access log, its interface addresses, the read-forward set,
/// `stat(2)` and `/proc` (`canary_host_linux`).
pub mod detector {
    pub use crate::canary_host_linux::stat_inode_key;

    /// [`nn_core::canary::detector::Detector`] on the agent's host.
    pub type Detector = nn_core::canary::detector::Detector<crate::chain_host_linux::LinuxHost>;

    /// [`nn_core::canary::detector::CanaryIndexes`] on the agent's host.
    pub type CanaryIndexes =
        nn_core::canary::detector::CanaryIndexes<crate::chain_host_linux::LinuxHost>;
}
/// The detector's tests (R08b, lab PR 251: cut from `detector.rs`; they
/// wire the agent's registry and access log).
#[cfg(test)]
mod detector_tests;
pub mod path_policy;
/// R08a shim (lab PR 250; plan §4.1 rule 2, removed in R17): the readers a
/// File or Credential canary spares are nn-core's; the agent's judge on the
/// lineage cache of the Linux host.
pub mod readers {
    pub use nn_core::canary::readers::*;

    /// [`nn_core::canary::readers::CanaryReaders`] on the agent's host.
    pub type CanaryReaders =
        nn_core::canary::readers::CanaryReaders<crate::chain_host_linux::LinuxHost>;
}
/// R07 shim (lab PR 247; plan §4.1 rule 2, removed in R17): the credential
/// renderer is nn-core's. It reads an operator template through the agent's
/// host (`LinuxHost`), under its old name and signature; the deploy's seed
/// is drawn from the OS RNG here.
pub mod templates {
    pub use nn_core::canary::templates::*;

    use crate::chain_host_linux::LinuxHost;

    /// A fresh content seed (external audit DEC-008): 32 bytes from the OS
    /// RNG, hex. One per deploy and per refresh, recorded in the registry row.
    pub fn new_content_seed() -> String {
        use rand::Rng;
        let mut seed = [0u8; 32];
        crate::os_rng::OsRng.fill_bytes(&mut seed);
        hex::encode(seed)
    }

    /// [`nn_core::canary::templates::render`] on the agent's host.
    pub fn render(
        family: CredFamily,
        seed: &str,
        template_dir: Option<&std::path::Path>,
    ) -> Result<String, RenderError> {
        nn_core::canary::templates::render::<LinuxHost>(family, seed, template_dir)
    }
}

/// The deploy's seed: drawn fresh from the OS for each decoy. R07 (lab PR
/// 247): from `templates`' tests (the renderer's own run on a portable
/// host since); these draw the agent's seeds.
#[cfg(test)]
mod tests {
    use super::templates::{new_content_seed, render, render_file_body, CredFamily};

    const FAMILIES: [CredFamily; 5] = [
        CredFamily::Aws,
        CredFamily::Azure,
        CredFamily::Gcp,
        CredFamily::Docker,
        CredFamily::Generic,
    ];

    /// What would tell an attacker the file is a canary, or whose (as
    /// `templates`' tests).
    const MARKERS: [&str; 5] = ["northnarrow", "canary", "do not use", "decoy", "nn-l-"];

    fn assert_no_marker(what: &str, body: &str) {
        let lower = body.to_lowercase();
        for m in MARKERS {
            assert!(!lower.contains(m), "{what} carries {m:?}: {body}");
        }
    }

    /// External audit DEC-007: the File canary body carries no marker and
    /// no fingerprint, and neither its content nor its size is the same on
    /// every decoy.
    #[test]
    fn file_canary_body_has_no_marker_or_fingerprint() {
        let a = render_file_body(&new_content_seed());
        let b = render_file_body(&new_content_seed());
        for body in [&a, &b] {
            assert!((512..4096).contains(&body.len()));
            assert_no_marker("file body", &String::from_utf8_lossy(body));
            assert!(!String::from_utf8_lossy(body).contains("deadbeef"));
        }
        assert_ne!(a, b, "two deploys, two bodies");
        let seed = "5a".repeat(32);
        assert_eq!(render_file_body(&seed), render_file_body(&seed));
    }

    /// External audit DEC-008: every deploy draws its own seed.
    #[test]
    fn content_seeds_are_fresh() {
        let (a, b) = (new_content_seed(), new_content_seed());
        assert_eq!(a.len(), 64);
        assert_ne!(a, b);
        for family in FAMILIES {
            assert_ne!(
                render(family, &a, None).unwrap(),
                render(family, &b, None).unwrap()
            );
        }
    }
}
