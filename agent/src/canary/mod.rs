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

pub mod access_log;
/// R05 shim (lab PR 241; removed in R17): the canary chains' line reader is
/// nn-evidence's.
pub use nn_evidence::chain_lines;
pub mod detector;
pub mod network;
pub mod path_policy;
pub mod read_forward;
pub mod readers;
pub mod registry;
pub mod templates;

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
