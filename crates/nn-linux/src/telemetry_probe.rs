//! The telemetry probe's piece the file-open sensor names, which moves here
//! (Wave 4 restructure, R09b, lab PR 254): the probe files' directory, cut
//! verbatim from the agent's `telemetry_probe`, which re-exports it. The
//! probe itself is R09c's.

/// Directory of the probe files (RuntimeDirectory of the unit).
pub const PROBE_DIR: &str = "/run/northnarrow/probe";
