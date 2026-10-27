//! `nn-evidence` — the signed chains: canonical form, RowSeq, heads,
//! verification and payloads, behind a `Signer` trait.
//!
//! Why a crate of its own: verification without the engine, for nn-admin, the
//! gateway and third parties; no key lives here. The agent's chainlog, audit,
//! chain_anchor, chain_tail, verify_lines and canary chain line reader moved
//! here in R05 (lab PR 241), after R04a cut what they named of the agent: the
//! signing key and the host's file operations are the host's
//! ([`chain_host::ChainSigner`], [`chain_host::ChainHost`]; the agent's are
//! `keys::AgentSigningKey` and `chain_host_linux::LinuxHost`), and the agent's
//! list of its chains is its own (`chains`). `anchored`, which the plan sent
//! here, stays in the agent: it is the Linux host's anchor (`/proc/self/fd`).
//!
//! Created empty by the Wave 4 restructure, R01 (lab PR 239); the crates it may
//! depend on, and the rules of the pure crates, are in
//! docs/architecture/module-map.toml, checked by
//! xtask/tests/workspace_layers.rs.

#![forbid(unsafe_code)]

/// The tamper-evident audit chain (was the agent's `audit`).
pub mod audit;
/// Completeness of the chains: row numbers, file heads, the head anchor, the
/// boot check (was the agent's `chain_anchor`).
pub mod chain_anchor;
/// What the chains need from their host: its file operations and its key.
pub mod chain_host;
/// The canary chains' bounded line reader (was the agent's
/// `canary::chain_lines`).
pub mod chain_lines;
/// Newest-first, bounded read of a chain log (was the agent's `chain_tail`).
pub mod chain_tail;
/// The rotating, signed, hash-chained logs (was the agent's `chainlog`).
pub mod chainlog;
/// The time the writers stamp on their rows (lab PR 249: the host's clock
/// by default, a replay's or a test's when given one).
pub mod clock;
/// The parts of a detection record the rule engine names: its sensor, its
/// ATT&CK tags, its principal (R08b, lab PR 251; cut from the agent's
/// `detection_payload`, which keeps the records).
pub mod detection_payload;
/// The full verifiers' bounded line reader (was the agent's `verify_lines`).
pub mod verify_lines;
