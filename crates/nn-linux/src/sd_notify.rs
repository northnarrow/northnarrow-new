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
//! A single Unix datagram, no `libsystemd` / `sd-notify` crate
//! dependency: [`antitamper_bpf::sd_notify`], shared with the watchdog. External
//! audit MAIN-016: each crate kept a copy that sent to `$NOTIFY_SOCKET` as
//! a filesystem path, so an abstract socket (`@name`) never got `READY=1`.

use anyhow::{Context, Result};
use tracing::{debug, info};

/// Manual systemd `sd_notify(READY=1)` — sends a single Unix datagram
/// to `$NOTIFY_SOCKET` per the `sd_notify(3)` wire protocol: a path, or
/// `@name` in the abstract namespace.
///
/// Returns `Ok` WHEN `NOTIFY_SOCKET` is unset (the agent is not
/// running under `Type=notify` — every dev-shell invocation and the
/// whole test suite), so callers can invoke it unconditionally and
/// off-systemd behaviour is a no-op. A value it cannot send to is an
/// error, never a silent success.
pub fn ready() -> Result<()> {
    let sent = antitamper_bpf::sd_notify::notify(b"READY=1\n").with_context(|| {
        format!(
            "sending READY=1 to NOTIFY_SOCKET={}",
            std::env::var_os("NOTIFY_SOCKET")
                .unwrap_or_default()
                .to_string_lossy()
        )
    })?;
    match sent {
        Some(socket) => info!(
            target: "agent.sd_notify",
            socket = %socket.to_string_lossy(),
            "systemd READY=1 sent"
        ),
        None => debug!(
            target: "agent.sd_notify",
            "NOTIFY_SOCKET unset — not running under systemd Type=notify; skipping"
        ),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::linux::net::SocketAddrExt;
    use std::os::unix::net::{SocketAddr, UnixDatagram};

    /// `NOTIFY_SOCKET` is process-global: the tests of this module take
    /// turns. No other test of the agent reads it.
    static ENV: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// `ready()` is a no-op (Ok) when `NOTIFY_SOCKET` is unset — the
    /// path every non-systemd invocation takes.
    #[test]
    fn ready_is_ok_when_notify_socket_unset() {
        let _env = ENV.lock().unwrap_or_else(|e| e.into_inner());
        std::env::remove_var("NOTIFY_SOCKET");
        ready().expect("must be Ok when NOTIFY_SOCKET unset");
    }

    /// External audit MAIN-016: under an abstract `NOTIFY_SOCKET`
    /// (`@name`), `READY=1` arrives; a socket nobody listens on is an
    /// error, not a success.
    #[test]
    fn ready_reaches_an_abstract_notify_socket() {
        let _env = ENV.lock().unwrap_or_else(|e| e.into_inner());
        let name = format!("nn-agent-notify-{}", std::process::id());
        let addr = SocketAddr::from_abstract_name(name.as_bytes()).unwrap();
        let listener = UnixDatagram::bind_addr(&addr).unwrap();
        listener
            .set_read_timeout(Some(std::time::Duration::from_secs(2)))
            .unwrap();
        std::env::set_var("NOTIFY_SOCKET", format!("@{name}"));
        let sent = ready();
        let mut buf = [0u8; 64];
        let got = listener.recv(&mut buf).map(|n| buf[..n].to_vec());
        // Lab PR 258 (the watchdog's twin of this test failed so): shut
        // down before it is closed — a child another test spawns holds a
        // copy of the listener's descriptor until its exec, and the socket
        // would live on and take the datagram.
        listener.shutdown(std::net::Shutdown::Both).unwrap();
        drop(listener);
        let refused = ready();
        std::env::remove_var("NOTIFY_SOCKET");
        sent.expect("READY=1 sent");
        assert_eq!(got.expect("a datagram"), b"READY=1\n");
        assert!(refused.is_err(), "nobody listens any more");
    }
}
