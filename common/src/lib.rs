//! Shared types for the NorthNarrow XDR.
//!
//! This crate defines the canonical wire types crossing the boundary
//! between sensors, the decision engine, and the response executors.
//! Keep it dependency-light: it is consumed by the agent, the CLI, and
//! (eventually) the C2 backend.

#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};

/// Canonical event emitted by a sensor.
///
/// Variants beyond `ProcessSpawn` are placeholders for future tappe
/// (file open, network connect, DNS, etc.) and intentionally unit-shaped
/// for now so the enum compiles before sensors land.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Event {
    ProcessSpawn {
        pid: u32,
        comm: String,
        cmdline: String,
    },
    FileOpen,
    NetworkConnect,
    DnsQuery,
    LsmExec,
}

/// Severity assigned to a verdict.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

/// Action the response layer should take in reaction to a verdict.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ResponseAction {
    Log,
    KillProcess,
    KillProcessTree,
    BlockOutbound,
    FullNetworkIsolation,
    Quarantine,
    ThrottleProcess,
}

/// Decision produced by the engine for a given event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Verdict {
    pub action: ResponseAction,
    pub severity: Severity,
    pub reasoning: String,
}
