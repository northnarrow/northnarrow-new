//! Systemd readiness notification for the agent daemon (T7.10).
//!
//! The agent's systemd unit is `Type=notify` (see
//! `deploy/systemd/northnarrow-agent.service`), so systemd holds the
//! unit in `activating` until it receives a `READY=1` datagram on
//! `$NOTIFY_SOCKET`. Until this commit the agent never sent it, so
//! systemd marked the start failed at `TimeoutStartSec` (default 90 s)
//! — and because the Tappa-7 anti-tamper LSM hook denies SIGTERM
//! against the agent's own PID, the process kept running while the
//! unit was stuck `failed`, which in turn tripped the watchdog's
//! `BindsTo=northnarrow-agent.service` and tore the supervisor down.
//!
//! The implementation mirrors the watchdog's proven
//! `sd_notify_ready` (`watchdog/src/lib.rs`): a single Unix datagram,
//! no `libsystemd` / `sd-notify` crate dependency. It is duplicated
//! rather than shared because the agent must not depend on the
//! supervisor crate (the dependency arrow points the other way).

use anyhow::{Context, Result};
use tracing::{debug, info};

/// Manual systemd `sd_notify(READY=1)` — sends a single Unix datagram
/// to `$NOTIFY_SOCKET` per the `sd_notify(3)` wire protocol.
///
/// Returns `Ok` WHEN `NOTIFY_SOCKET` is unset (the agent is not
/// running under `Type=notify` — every dev-shell invocation and the
/// whole test suite), so callers can invoke it unconditionally and
/// off-systemd behaviour is a no-op.
pub fn ready() -> Result<()> {
    let sock_path = match std::env::var("NOTIFY_SOCKET") {
        Ok(p) => p,
        Err(_) => {
            debug!(
                target: "agent.sd_notify",
                "NOTIFY_SOCKET unset — not running under systemd Type=notify; skipping"
            );
            return Ok(());
        }
    };
    let sock = std::os::unix::net::UnixDatagram::unbound()
        .context("creating sd_notify datagram socket")?;
    sock.send_to(b"READY=1\n", &sock_path)
        .with_context(|| format!("sending READY=1 to NOTIFY_SOCKET={sock_path}"))?;
    info!(
        target: "agent.sd_notify",
        socket = %sock_path,
        "systemd READY=1 sent"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `ready()` is a no-op (Ok) when `NOTIFY_SOCKET` is unset — the
    /// path every non-systemd invocation takes. Mutating the process
    /// environment is inherently global, so this is the only test in
    /// the module to avoid cross-test races on `NOTIFY_SOCKET`.
    #[test]
    fn ready_is_ok_when_notify_socket_unset() {
        // SAFETY: single-test module; no other test reads/writes
        // NOTIFY_SOCKET concurrently.
        std::env::remove_var("NOTIFY_SOCKET");
        ready().expect("must be Ok when NOTIFY_SOCKET unset");
    }
}
