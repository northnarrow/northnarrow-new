
/// The stop: the exec guards release what they hold, the BPF self-check
/// is told the links go, the copy guard closes, the signed `agent_stop`,
/// the heads anchored at stop, the pid file and the admin socket removed.
/// A pump that exited is a failure (SNS-001): the watchdog restarts the
/// agent.
fn shutdown(
    cli: &Cli,
    execq_handle: Option<northnarrow_agent::execq::Handle>,
    execpol_handle: Option<northnarrow_agent::execpol::Handle>,
    audit_log: &AuditHandle,
    chain_anchor: &AnchorHandle,
    stopped: Stopped,
) -> Result<()> {
    let Stopped {
        stop_reason,
        loop_started,
    } = stopped;
    // Lab PR 223: nothing stays held by an agent that stops.
    northnarrow_agent::execq::shutdown(execq_handle);
    // Lab PR 226: the kernel keeps the policy until its programs detach.
    northnarrow_agent::execpol::shutdown(execpol_handle);
    // The links go with the agent from here on: the self-check stops
    // reporting them (a spurious signed bpf_link_missing otherwise).
    northnarrow_agent::anti_tamper::bpf_defense::mark_stopping();
    // Lab PR 222: the guard's fanotify group closes first — no open on a
    // protected scope waits on an agent that is leaving.
    northnarrow_agent::cow::shutdown();

    if let Some(log) = &audit_log {
        let uptime = loop_started.elapsed().as_secs();
        match log.lock().stop_entry(stop_reason, uptime) {
            Ok(_) => info!(
                reason = stop_reason,
                uptime_secs = uptime,
                "audit: agent_stop entry appended"
            ),
            Err(e) => warn!(error = format!("{e:#}"), "audit: agent_stop entry failed"),
        }
    }
    // Lab PR 160: the heads as this run leaves them, `agent_stop` included,
    // so a file emptied or cut while the agent is down is found at the
    // next start.
    if let Some(a) = &chain_anchor {
        let second = audit_log
            .as_ref()
            .is_some_and(|l| l.lock().second_key_added());
        match a.lock().refresh(true, second) {
            Ok(_) => info!("chain heads anchored at stop"),
            Err(e) => warn!(
                error = format!("{e:#}"),
                "chain heads: not anchored at stop"
            ),
        }
    }

    // Tappa 7 task 6 #2b-verify: remove our PID file on GRACEFUL
    // shutdown only, so a supervisor/harness reads "file gone =>
    // agent exited cleanly". A crash (panic / SIGKILL — neither
    // reaches here) deliberately leaves it STALE; that is why readers
    // must confirm /proc/<pid> is alive (and is the agent binary)
    // before trusting the contents. Removal failure is logged loudly,
    // never swallowed, but is non-fatal — we are already shutting down.
    if let Some(pid_file) = cli.pid_file.as_deref() {
        match std::fs::remove_file(pid_file) {
            Ok(()) => info!(
                target: "anti-tamper",
                path = %pid_file.display(),
                "pid_file removed on graceful shutdown"
            ),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => debug!(
                target: "anti-tamper",
                path = %pid_file.display(),
                "pid_file already absent at shutdown (nothing to remove)"
            ),
            Err(e) => warn!(
                target: "anti-tamper",
                path = %pid_file.display(),
                error = %e,
                "pid_file removal failed on shutdown (left stale)"
            ),
        }
    }

    // Best-effort socket cleanup so a future agent process can bind
    // without first encountering a stale file. The accept loop is
    // about to be torn down with the runtime, so this race is between
    // tokio's drop-of-the-listener and our unlink — either order
    // leaves the filesystem clean.
    admin_socket::unlink_socket(&cli.admin_socket);

    info!("NorthNarrow agent stopped.");
    if stop_reason == "sensor_pump_exited" {
        // External audit SNS-001: a failure, not a clean stop.
        anyhow::bail!("a sensor pump exited; the agent stopped so the watchdog restarts it");
    }
    Ok(())
}
