//! Per-event context handed to the LLM (recent events + host info).
//!
//! `EventContext` is intentionally a plain bag of data — the
//! caller (typically `agent/src/main.rs`) is responsible for
//! aggregating it. RAG hits (`kb_hits`) are specced for a future
//! sub-tappa; in Tappa 6 the field stays at `Vec::new()`.

use common::Event;

/// Contextual information surrounding the focal event.
#[derive(Debug, Clone)]
pub struct EventContext {
    /// Up to 50 correlated events, oldest-first.
    pub recent_events: Vec<Event>,
    /// Stable host metadata.
    pub host_context: HostContext,
}

#[derive(Debug, Clone)]
pub struct HostContext {
    pub hostname: String,
    pub host_id: String,
    pub kernel_version: String,
    pub agent_version: String,
}

impl HostContext {
    /// Best-effort discovery: hostname via `gethostname`, kernel via
    /// `uname -r`, host_id from `/etc/machine-id`, agent_version from
    /// `CARGO_PKG_VERSION`. Any failure falls back to a stable
    /// placeholder so ADE can still emit a verdict.
    pub fn discover() -> Self {
        let hostname =
            read_proc_kernel("/proc/sys/kernel/hostname").unwrap_or_else(|| "unknown".to_string());
        let kernel_version =
            read_proc_kernel("/proc/sys/kernel/osrelease").unwrap_or_else(|| "unknown".to_string());
        let host_id = std::fs::read_to_string("/etc/machine-id")
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| "unknown".to_string());
        Self {
            hostname,
            host_id,
            kernel_version,
            agent_version: env!("CARGO_PKG_VERSION").to_string(),
        }
    }
}

fn read_proc_kernel(path: &str) -> Option<String> {
    std::fs::read_to_string(path)
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}
