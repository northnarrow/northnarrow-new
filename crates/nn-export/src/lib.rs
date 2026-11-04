//! `nn-export` — the minimal signed export (lot 276; R15's first step,
//! `docs/operator/EXPORT.md`, `docs/architecture/PROCESS_MODEL.md` §11).
//!
//! The agent's signed chains are the write-ahead log: the core reads their
//! rows after a cursor per sink and chain (`wal`) and hands them to the
//! unprivileged `export` worker, which maps each to OCSF 1.9.0 records
//! (`ocsf`) and writes them to a rotating JSONL file (`jsonl`) or to syslog
//! over TLS (`syslog`, `net`, `tls`), and says how many rows are delivered
//! (`worker`). The cursor moves past those only: at least once, every
//! record carrying its signed row.
//!
//! What the core runs: `config`, `wal`. What only the worker runs, in its
//! sandbox: `ocsf`, `jsonl`, `syslog`, `net`, `tls`, `worker`
//! (xtask/tests/export_in_the_worker.rs).

pub mod config;

/// The OCSF version every record names (`ocsf::OCSF_VERSION`), for the
/// core's status and manifest.
pub use ocsf::OCSF_VERSION;

pub mod jsonl;
pub mod net;
pub mod ocsf;
/// The tests' OCSF validator against the pinned schema (the
/// `schema-check` feature: the agent's tests).
#[cfg(any(test, feature = "schema-check"))]
pub mod schema;
pub mod syslog;
pub mod tls;
pub mod wal;
pub mod worker;

#[cfg(test)]
pub(crate) mod testing;
