//! Tappa 9 — File Integrity Monitoring (FIM) userland.
//!
//! Modules per design §12:
//!
//! - `baseline` (C3) — compute + persist + verify the
//!   tamper-evident on-disk baseline DB. Reuses the Tappa 8
//!   B1 audit-log primitives.
//! - `drain` (C4) — RingBuf drain + path resolve + baseline
//!   diff + Event::Fim emit.
//! - `rules` (C5 / C5.1 / C5.3) — NN-L-FIM-001..014.
//! - `paths_config` (C7) — loader + merger for the
//!   `/etc/northnarrow/fim-paths.v1` curated default list and
//!   the `/etc/northnarrow/fim-paths.local` operator overlay
//!   (`+` add, `-` disable per §13 Q7).
//! - `recompute` (C7) — in-process baseline-recompute channel
//!   (C6 deferral): tokio mpsc the admin dispatch fires when an
//!   operator runs `nn-admin fim baseline`. A long-lived task
//!   re-walks every loaded path, computes [`baseline::compute_baseline`],
//!   appends to [`baseline::BaselineDb`], and refreshes the
//!   [`drain::InodePathMap`].

pub mod baseline;
pub mod drain;
pub mod paths_config;
pub mod recompute;
pub mod rules;
