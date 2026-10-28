//! The network drain at boot (R11a, lab PR 261: from `main.rs`'s `run`).

use std::sync::Arc;

use northnarrow_agent::net::blocklist::NetBlocklist;
use northnarrow_agent::net::dns_cache::DnsCache;
use northnarrow_agent::net::flow_tracker::FlowTracker;
use northnarrow_agent::posture::AuthSessionTracker;
use northnarrow_agent::sensors::SensorMultiplexer;
use tracing::{error, info, warn};

use super::cli::Cli;
use super::evidence::{drain_ended, AuditHandle};

/// The network drain (Tappa 10 N9): the netflow and listener logs (one that
/// cannot be opened is a signed degradation and the drain runs without it:
/// lab PR 218, P0 C-14), the rules' gate, the open-flow snapshots, the
/// drain task.
#[allow(clippy::too_many_arguments)]
pub(crate) fn start(
    cli: &Cli,
    agent_id: [u8; 16],
    rotation_protection: std::sync::Arc<dyn northnarrow_agent::chainlog::ProtectionManager>,
    netflow_rotation: northnarrow_agent::chainlog::RotationConfig,
    audit_log: &AuditHandle,
    flow_tracker: Arc<parking_lot::Mutex<FlowTracker>>,
    dns_cache: Arc<DnsCache>,
    lineage: &AuthSessionTracker,
    sensor: &mut SensorMultiplexer,
    net_bufs: northnarrow_agent::sensors::multiplexer::NetRingBufs,
    netflow_blocklist: Arc<NetBlocklist>,
    chain_store: Arc<
        parking_lot::Mutex<northnarrow_agent::decision::correlation::CorrelationStore>,
    >,
) {
    // ── Tappa 10 N9 — net drain subsystem boot ─────────────────────
    //
    // Closes the kernel→userland net loop: the multiplexer above
    // has already attached the three N2 BPF programs (kprobe
    // inet_csk_listen_start + fexit tcp_close + kprobe
    // udp_sendmsg_outbound) and surfaced the two new ringbufs in
    // `net_bufs`. Here we:
    //   1. Open the two chained on-disk logs (`netflow.jsonl` +
    //      `netflow_listeners.jsonl`) — same chain shape as the
    //      Tappa 8 audit log + Tappa 9 drift log;
    //   2. spawn `net::drain::drain_loop` against the two ringbufs
    //      with shared `flow_tracker` + `dns_cache` (the
    //      multiplexer's TcpConnect / DnsQuery pumps feed those
    //      from the connect / DNS-query sides);
    //   3. register the spawned handle on the multiplexer so a
    //      clean shutdown aborts it alongside the sensor pumps.
    //
    // Per-step failures are warn-logged and skipped — the agent
    // still boots without net drain (mirrors the FIM degrade-not-
    // fail posture). Without the drain, kernel close + listen
    // events accumulate in the ringbuf until it fills + the
    // verifier-side ringbuf drop counter ticks; NN-L-NET-001..009
    // see zero events but the agent stays up.
    {
        use northnarrow_agent::net::drain::{drain_loop, NetFlowDb, NetListenerDb};

        let netflow_db_opt = match northnarrow_agent::audit::AgentSigningKey::load_or_bootstrap(
            &cli.signing_key_file,
        )
        .and_then(|key| {
            NetFlowDb::open(
                &cli.netflow_file,
                key,
                agent_id,
                std::sync::Arc::clone(&rotation_protection),
                netflow_rotation,
            )
        }) {
            Ok(db) => Some(Arc::new(parking_lot::Mutex::new(db))),
            Err(e) => {
                // Lab PR 218 (external review P0 C-14): the drain no longer
                // stays off for the whole boot (TCP, UDP and listeners
                // blind): it runs without the log, signed.
                error!(
                    error = %e,
                    path = %cli.netflow_file.display(),
                    "netflow log cannot be opened — flows are evaluated by the rules but not \
                     persisted this boot"
                );
                northnarrow_agent::boot::degradation::report_signed(
                    audit_log.as_ref(),
                    "net_drain",
                    &format!(
                        "netflow log {} cannot be opened ({e:#}): flows reach the rules, not \
                         persisted this boot",
                        cli.netflow_file.display()
                    ),
                    true,
                );
                None
            }
        };
        let listener_db_opt = match northnarrow_agent::audit::AgentSigningKey::load_or_bootstrap(
            &cli.signing_key_file,
        )
        .and_then(|key| NetListenerDb::open(&cli.netflow_listeners_file, key, agent_id))
        {
            Ok(mut db) => {
                if let (Some(r), Some(log)) = (db.take_tail_repair(), audit_log.as_ref()) {
                    if let Err(e) = log
                        .lock()
                        .attest_tail_repair(&cli.netflow_listeners_file, &r)
                    {
                        warn!(error = %e, "attesting the listener log repair failed");
                    }
                }
                Some(Arc::new(parking_lot::Mutex::new(db)))
            }
            Err(e) => {
                // External audit NET-003: no longer stops the whole drain —
                // flows and listener events still reach the rules; only the
                // listener log is not written.
                error!(
                    error = %e,
                    path = %cli.netflow_listeners_file.display(),
                    "netflow_listeners log cannot be opened — listener events are \
                     evaluated but not persisted this boot"
                );
                // Lab PR 218: signed, not only an ERROR.
                northnarrow_agent::boot::degradation::report_signed(
                    audit_log.as_ref(),
                    "net_drain",
                    &format!(
                        "netflow_listeners log {} cannot be opened ({e:#}): listener events \
                         reach the rules, not persisted this boot",
                        cli.netflow_listeners_file.display()
                    ),
                    true,
                );
                None
            }
        };
        {
            let netflow_db = netflow_db_opt;
            let listener_db = listener_db_opt;
            let flow_tracker_for_drain = Arc::clone(&flow_tracker);
            let dns_cache_for_drain = Arc::clone(&dns_cache);
            let lineage_for_net = lineage.clone();
            let event_tx = sensor.event_tx();
            let close_rb = net_bufs.close_rb;
            let listen_rb = net_bufs.listen_rb;
            let udp_rb = net_bufs.udp_rb;
            let audit_for_drain = audit_log.clone();
            // External audit NET-019: the per-uid pacing of the rows handed
            // to the rules, with its exemptions (blocklist, chain store).
            let gate = northnarrow_agent::net::limiter::RuleGate::new(
                Arc::clone(&netflow_blocklist),
                Arc::clone(&chain_store),
            );
            // Lab PR 224 (CM-02 b): the open-flow snapshots.
            let snapshot = northnarrow_agent::net::flow_tracker::SnapshotPolicy {
                interval_ns: cli.net_snapshot_interval_secs * 1_000_000_000,
                min_age_ns: cli.net_snapshot_min_age_secs * 1_000_000_000,
                max_per_tick: cli.net_snapshot_max,
            };
            let handle = tokio::spawn(async move {
                let outcome = drain_loop(
                    close_rb,
                    listen_rb,
                    udp_rb,
                    flow_tracker_for_drain,
                    dns_cache_for_drain,
                    netflow_db,
                    listener_db,
                    lineage_for_net,
                    gate,
                    snapshot,
                    event_tx,
                )
                .await;
                drain_ended("net", outcome, audit_for_drain.as_ref());
            });
            sensor.register_pump_handle("net_drain", handle);
            info!("net: drain loop spawned (NET_FLOW_CLOSE_EVENTS + NET_LISTEN_EVENTS)");
        }
    }
}
