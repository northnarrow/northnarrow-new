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
//!   `Event::NetFlow` BEFORE the rule engine sees them (§12 Q9
//!   OPTION B inline-filter lock-in).
//! - `templates` (K4) — credential-canary content renderer
//!   (5 cred families: AWS / GCP / Azure / SSH priv-key / Git
//!   token) reading from `/etc/northnarrow/canary-templates/`.
//! - Rules NN-L-CANARY-001..004 live in
//!   `agent/src/decision/rules/canary.rs` (K5).

pub mod access_log;
pub mod detector;
pub mod registry;
pub mod templates;
