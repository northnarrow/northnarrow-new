//! Tappa 9 — File Integrity Monitoring (FIM) userland.
//!
//! Modules per design §12:
//!
//! - `baseline` (C3, this commit) — compute + persist + verify
//!   the tamper-evident on-disk baseline DB. Reuses the Tappa 8
//!   B1 audit-log primitives.
//! - `drain` (C4) — RingBuf drain + path resolve + baseline
//!   diff + Event::Fim emit. Pending follow-up commit.
//! - Rules NN-L-FIM-001..009 live in
//!   `agent/src/decision/rules/fim.rs` (C5 follow-up commit).

pub mod baseline;
