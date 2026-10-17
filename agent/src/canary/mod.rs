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
pub mod chain_lines;
pub mod detector;
pub mod network;
pub mod path_policy;
pub mod read_forward;
pub mod readers;
pub mod registry;
pub mod templates;
