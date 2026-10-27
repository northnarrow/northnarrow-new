//! `nn-linux` — the Linux adapters: the eBPF loader and sensors, /proc, the
//! actuators, self-defence, systemd, the KeyStore and the sandbox.
//!
//! Why a crate of its own: the one place for aya, /proc, cgroups, netfilter,
//! systemd and keys on disk; another OS would be a sibling crate. The adapters
//! move here in R09. R09a (lab PR 253) moves the utilities the actuators, the
//! self-defence and the hosts stand on: the agent's identity on disk, the
//! anchor of a log's directory, the OS CSPRNG, the external commands with a
//! deadline, the system directories' binaries, the filesystems' identity,
//! the atomic replace of a protected file, the work kept off the async
//! runtime, the async file descriptor.
//!
//! The only crate of the layout where `unsafe` is allowed (no
//! `#![forbid(unsafe_code)]`, R01): its blocks moved verbatim, each with its
//! `SAFETY` comment.
//!
//! The moved modules carry no outer doc comment here: rustdoc would resolve
//! their own `//!` links from this file (nn-core's way, lab PR 250).
//!
//! Created empty by the Wave 4 restructure, R01 (lab PR 239); the crates it may
//! depend on, and the rules of the pure crates, are in
//! docs/architecture/module-map.toml, checked by
//! xtask/tests/workspace_layers.rs.

// The per-install agent identity (`/var/lib/northnarrow/agent_id`), read
// once at boot (R09a, lab PR 253; was the agent's `agent_id`).
pub mod agent_id;

// A log's directory held open, so its path resolves through the descriptor
// taken at start (R09a; was the agent's `anchored`).
pub mod anchored;

// A raw descriptor in tokio's reactor (R09a; was the agent's `async_fd`).
pub mod async_fd;

// Replacing a file the agent protects, without following a planted link
// (R09a; was the agent's `atomic_file`, the path of `antitamper-bpf`'s).
pub mod atomic_file;

// An external command with a deadline (R09a; was the agent's
// `bounded_cmd`).
pub mod bounded_cmd;

// The filesystems the agent's files live on, by identity (R09a; was the
// agent's `fs_type`).
pub mod fs_type;

// The OS CSPRNG as an infallible generator (R09a; was the agent's
// `os_rng`).
pub mod os_rng;

// Blocking work kept off the async runtime's worker threads (R09a; was the
// agent's `runtime`).
pub mod runtime;

// The system directories' binaries, never `$PATH` (R09a; was the agent's
// `trusted_bin`).
pub mod trusted_bin;

// R09a shim (lab PR 253; plan §4.1 rule 2, removed in R17): the path the
// moved identity names for its records in the audit chain.
/// `crate::audit::…`, nn-evidence's.
use nn_evidence::audit;
