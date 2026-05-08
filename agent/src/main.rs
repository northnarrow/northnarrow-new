//! NorthNarrow agent daemon entrypoint.
//!
//! Tappa 0: tokio runtime + tracing + clean SIGINT shutdown.
//! No sensors, no decisions, no responses yet — those land starting
//! Tappa 1 (eBPF process exec sensor via Aya).

#![forbid(unsafe_code)]

use anyhow::Result;
use tracing::info;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .with_target(false)
        .init();

    info!("NorthNarrow agent starting...");

    tokio::signal::ctrl_c().await?;

    info!("NorthNarrow agent shutting down (SIGINT received).");
    Ok(())
}
