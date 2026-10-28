//! The agent's identity on disk, as nn-admin reads it (Tappa 8 design
//! §6.5): the id its signed requests are bound to
//! ([`nn_proto::admin_signed_payload::SignedPayload::agent_id`]), read from
//! `/etc/northnarrow/agent_id` and never minted — only the agent mints, at
//! its first start (nn-linux's `agent_id`); both read the file through
//! [`nn_proto::shutdown_marker::parse_minted_agent_id`].
//!
//! Wave 4 restructure, R10 (lab PR 259): moved from nn-linux's `agent_id`,
//! of which nn-admin was the one caller.

use std::fs;
use std::path::Path;

use anyhow::{anyhow, bail, Context, Result};

/// Width of the raw agent_id in bytes (with the identity types, the audit
/// chain's since R04a, lab PR 241).
pub use nn_evidence::audit::AGENT_ID_LEN;

/// Read an existing agent_id, never minting one (external audit MAIN-010,
/// NN-AUD-252): what `nn-admin` uses. A missing file means the agent has
/// not started yet on this host (or the path is wrong), and an id minted
/// here would be one the agent then adopts without a trace.
pub fn load_existing(path: &Path) -> Result<[u8; AGENT_ID_LEN]> {
    match fs::read_to_string(path) {
        Ok(content) => parse(&content)
            .with_context(|| format!("agent_id file {} present but corrupted", path.display())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => bail!(
            "agent_id not found at {}: the agent creates it at its first start \
             (start northnarrow-agent once, or pass the right --agent-id-file)",
            path.display()
        ),
        Err(e) => Err(anyhow!(e).context(format!("reading agent_id {}", path.display()))),
    }
}

/// The file's id, the all-zero one refused (external audit MAIN-009): the
/// rule the agent's own read takes, nn-proto's.
fn parse(raw: &str) -> Result<[u8; AGENT_ID_LEN]> {
    nn_proto::shutdown_marker::parse_minted_agent_id(raw).map_err(|e| anyhow!(e))
}
