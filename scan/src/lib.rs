//! `northnarrow-scan` — the exec quarantine's confined scanner (lab PR 223,
//! EXPERIMENTAL; design `docs/design/EXEC_QUARANTINE.md`).
//!
//! The binary (`src/main.rs`) is what the agent spawns. The library holds
//! what it is made of, testable without a process: the ELF reader
//! ([`elf`]), the heuristics ([`heuristics`]), the engine ([`engine`]), the
//! confinement ([`harden`], [`seccomp`]), the channel ([`ipc`]) and the
//! agent's end of it ([`supervisor`]): the agent links this library for
//! those two only.

pub mod elf;
pub mod engine;
pub mod harden;
pub mod heuristics;
pub mod ipc;
pub mod seccomp;
pub mod supervisor;
#[cfg(feature = "yara")]
mod yara;

/// The descriptor the agent hands the scanner's end of the channel on.
pub const SOCKET_FD: i32 = 3;
