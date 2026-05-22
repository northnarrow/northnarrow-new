//! NorthNarrow agent daemon entrypoint.
//!
//! Tappa 4: the agent loads a single eBPF object exposing six
//! programs (process exec, file open, exec validation, TCP v4/v6
//! connect, UDP/DNS) via [`SensorMultiplexer`].
//!
//! Tappa 6 cascades each event through:
//!
//!   sensor → posture.observe → rule_engine
//!     → (match? execute : ade.evaluate → posture.modulate → execute?)
//!
//! ADE is invoked only when the rule engine produces no verdict, so
//! Tappa 3+5 regression behaviour is preserved exactly: `R001` still
//! kills `/tmp/nn-test-payload` before ADE ever sees the event.
//!
//! Sub-tappa 6.5: every event is also fed to the
//! [`PostureMachine`](northnarrow_agent::posture::PostureMachine), a
//! 4-tier defensive posture that persists across events. ADE
//! verdicts are passed through `posture.modulate_verdict` before
//! execution so an ambiguous `Allow` in `OBSERVING` becomes an
//! `Alert` once the posture has lifted to `ALERTED+`.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use clap::Parser;
use common::Event;
use northnarrow_agent::ade::{AdeConfig, AdeEngine, EventContext, HostContext};
use northnarrow_agent::admin_socket::{self, ShutdownSignal};
use northnarrow_agent::agent_id;
use northnarrow_agent::anti_tamper::admin_auth::AdminAuth;
use northnarrow_agent::anti_tamper::network_isolate::{NetworkIsolator, UnlockToken};
use northnarrow_agent::correlation::CorrelationBuffer;
use northnarrow_agent::decision::RuleEngine;
use northnarrow_agent::net::blocklist::{
    Ja3Blocklist, NetBlocklist, DEFAULT_NETFLOW_BLOCKLIST_LOCAL, DEFAULT_NETFLOW_BLOCKLIST_V1,
    DEFAULT_NETFLOW_JA3_BLOCKLIST_LOCAL, DEFAULT_NETFLOW_JA3_BLOCKLIST_V1,
};
use northnarrow_agent::net::dns_cache::DnsCache;
use northnarrow_agent::net::flow_tracker::FlowTracker;
use northnarrow_agent::posture::{CombatEntryHook, CombatReleaseHook, PostureMachine};
use northnarrow_agent::response::Executor;
use northnarrow_agent::sensors::SensorMultiplexer;
use tokio::signal::unix::{signal, SignalKind};
use tracing::{debug, info, warn};
use tracing_subscriber::EnvFilter;

#[derive(Debug, Parser)]
#[command(
    name = "northnarrow-agent",
    version,
    about = "NorthNarrow XDR agent daemon (Linux)."
)]
struct Cli {
    /// Disable the Active Defense Engine (rule engine only).
    #[arg(long = "no-ade", default_value_t = false)]
    no_ade: bool,

    /// Override the GGUF model path used by ADE.
    #[arg(long = "ade-model", value_name = "PATH")]
    ade_model: Option<PathBuf>,

    /// Override the ADE inference timeout (seconds).
    #[arg(long = "ade-timeout", value_name = "SECS")]
    ade_timeout: Option<u64>,

    /// Override the ADE system prompt path.
    #[arg(long = "ade-prompt", value_name = "PATH")]
    ade_prompt: Option<PathBuf>,

    /// Override the rayon worker count candle uses for CPU
    /// inference. Defaults to `physical_cores - 1` (Sub-tappa 6.8).
    /// Setting `RAYON_NUM_THREADS` in the environment takes priority.
    #[arg(long = "ade-threads", value_name = "N")]
    ade_threads: Option<usize>,

    /// Path to the iptables ruleset NetworkIsolator applies on
    /// COMBAT entry. Production install: /etc/northnarrow/combat-rules.v4.
    /// Repo dev path: configs/combat-rules.v4.
    #[arg(
        long = "combat-rules",
        value_name = "PATH",
        default_value = "/etc/northnarrow/combat-rules.v4"
    )]
    combat_rules: PathBuf,

    /// Path to the admin pubkey file. If the file is missing, the
    /// admin socket is not started (the agent still runs, posture
    /// state still moves into Combat on intrusion, network isolation
    /// still engages — but there is no way to release without an
    /// admin pub key, so operators must reboot to clear COMBAT).
    #[arg(
        long = "admin-pub",
        value_name = "PATH",
        default_value = "/etc/northnarrow/admin.pub"
    )]
    admin_pub: PathBuf,

    /// Tappa 8 A3 + A8: per-install agent identity file. The agent
    /// reads (or, on first boot, mints) a 16-byte UUID at this
    /// path; the UUID becomes the third anti-replay layer for the
    /// signed-payload pipeline (design §6.4 layer 3) — a captured
    /// admin signature from one agent install cannot be replayed
    /// against another. Persisted as 32 hex chars + newline at
    /// mode 0644 per design §6.5. Default path mirrors the design
    /// spec; override only for testing or unusual install layouts.
    #[arg(
        long = "agent-id-file",
        value_name = "PATH",
        default_value = "/etc/northnarrow/agent_id"
    )]
    agent_id_file: PathBuf,

    /// Tappa 7 task 6 Watchdog W6: best-effort path to the
    /// watchdog daemon's PID file. If the file exists at agent
    /// startup, the agent reads the PID and includes it in
    /// `PROTECTED_PIDS` alongside its own — the LSM
    /// `task_kill` + `ptrace_access_check` hooks then deny
    /// SIGKILL/SIGTERM/ptrace against the watchdog too, giving
    /// the same anti-tamper coverage to both halves of the
    /// supervisor pair. The agent boots normally if the file
    /// is missing (no watchdog deployed yet) — W6 is purely
    /// additive co-protection.
    #[arg(
        long = "watchdog-pidfile",
        value_name = "PATH",
        default_value = "/run/northnarrow/watchdog.pid"
    )]
    watchdog_pidfile: PathBuf,

    /// Unix-socket path nn-admin connects to. Removed on startup if
    /// it already exists (stale file from prior unclean shutdown).
    #[arg(
        long = "admin-socket",
        value_name = "PATH",
        default_value = "/run/northnarrow/admin.sock"
    )]
    admin_socket: PathBuf,

    /// PHASE_D_003: configurable path of the agent's audit
    /// signing key (Tappa 8 B1). Default mirrors the design's
    /// canonical location. Tests override this to a per-test
    /// tempdir so each test run gets a fresh key without
    /// mutating the host's /etc/northnarrow/ state.
    #[arg(
        long = "signing-key-file",
        value_name = "PATH",
        default_value = northnarrow_agent::audit::DEFAULT_SIGNING_KEY_PATH,
    )]
    signing_key_file: PathBuf,

    /// PHASE_D_003: configurable path of the agent's audit
    /// log (Tappa 8 B1 + B5). Default mirrors the design's
    /// canonical location.
    #[arg(
        long = "audit-log-file",
        value_name = "PATH",
        default_value = northnarrow_agent::audit::DEFAULT_AUDIT_LOG_PATH,
    )]
    audit_log_file: PathBuf,

    /// PHASE_D_003: configurable path of the
    /// shutdown-authorisation marker (Tappa 8 A8). Default is
    /// the design's canonical
    /// `/run/northnarrow/agent.shutdown_authorised`. Tests use
    /// a per-test tempdir so the watchdog can be mocked or
    /// skipped without colliding with a real install.
    #[arg(
        long = "shutdown-marker-file",
        value_name = "PATH",
        default_value = northnarrow_agent::shutdown_marker::DEFAULT_MARKER_PATH,
    )]
    shutdown_marker_file: PathBuf,

    /// Tappa 9 C7: path to the curated default FIM watched-paths
    /// list (`fim-paths.v1` format — one absolute path per line,
    /// `#` comments). install.sh drops this at the default location;
    /// the agent reads + merges with the operator overlay at boot.
    #[arg(
        long = "fim-paths-v1",
        value_name = "PATH",
        default_value = northnarrow_agent::fim::paths_config::DEFAULT_PATHS_V1,
    )]
    fim_paths_v1: PathBuf,

    /// Tappa 9 C7 / §13 Q7: path to the operator overlay.
    /// `+/abs/path` adds, `-/abs/path` disables a default. Optional
    /// — missing file means "no overlay", v1 is used as-is.
    #[arg(
        long = "fim-paths-local",
        value_name = "PATH",
        default_value = northnarrow_agent::fim::paths_config::DEFAULT_PATHS_LOCAL,
    )]
    fim_paths_local: PathBuf,

    /// Tappa 9 C3 / C7: configurable path of the chained FIM
    /// baseline log. Tests override this to a tempdir so each test
    /// run gets a fresh chain.
    #[arg(
        long = "fim-baseline-file",
        value_name = "PATH",
        default_value = northnarrow_agent::fim::baseline::DEFAULT_BASELINE_PATH,
    )]
    fim_baseline_file: PathBuf,

    /// Tappa 9 C4 / C7: configurable path of the chained FIM
    /// drift log. Same per-test override rationale as
    /// `--fim-baseline-file`.
    #[arg(
        long = "fim-drift-file",
        value_name = "PATH",
        default_value = northnarrow_agent::fim::drain::DEFAULT_DRIFT_LOG_PATH,
    )]
    fim_drift_file: PathBuf,

    /// Tappa 9.5 K2 / K6: configurable path of the chained canary
    /// registry log. Tests override this to a tempdir so each test
    /// run gets a fresh chain. Missing file means an empty registry
    /// (no canaries deployed); the K6 admin dispatch path creates
    /// the file lazily on first deploy.
    #[arg(
        long = "canary-registry-file",
        value_name = "PATH",
        default_value = northnarrow_agent::canary::registry::DEFAULT_REGISTRY_PATH,
    )]
    canary_registry_file: PathBuf,

    /// Tappa 9.5 K3 / K6: configurable path of the chained canary
    /// access log. Same per-test override rationale as
    /// `--canary-registry-file`. The K3 detector appends one row
    /// per observed canary access (`mark_tripped` + audit emission
    /// are decoupled).
    #[arg(
        long = "canary-access-file",
        value_name = "PATH",
        default_value = northnarrow_agent::canary::access_log::DEFAULT_ACCESS_LOG_PATH,
    )]
    canary_access_file: PathBuf,

    /// Tappa 9.5 K4 / K6: directory holding the canary template
    /// files (`<family>.tmpl`). The K6 deploy dispatch renders
    /// File + Credential canary bytes from these templates. None
    /// disables canary deploys that require a template (Network
    /// + Process canaries still work — they don't need files).
    #[arg(
        long = "canary-template-dir",
        value_name = "PATH",
        default_value = northnarrow_agent::canary::templates::DEFAULT_TEMPLATE_DIR,
    )]
    canary_template_dir: PathBuf,

    /// Tappa 10 N8: configurable path of the chained NetFlow log.
    /// Same per-test override rationale as `--fim-baseline-file` —
    /// tests point this at a tempdir so each run gets a fresh
    /// chain. The N7 `dispatch_net_flows` admin path reads from
    /// this file; the future N3 flow_tracker emission commit
    /// appends to it. N8 (this commit) bootstraps the file
    /// pre-attach so PROTECTED_INODES has an inode to register
    /// against before LSM hooks come up.
    #[arg(
        long = "netflow-file",
        value_name = "PATH",
        default_value = northnarrow_agent::admin_socket::DEFAULT_NETFLOW_JSONL_PATH,
    )]
    netflow_file: PathBuf,

    /// Tappa 10 N9: configurable path of the chained NetListener
    /// log (`netflow_listeners.jsonl`). Same per-test override
    /// rationale as `--netflow-file` — tests point this at a
    /// tempdir so each run gets a fresh chain. The N9 drain loop
    /// appends one row per observed `inet_csk_listen_start` kernel
    /// event.
    #[arg(
        long = "netflow-listeners-file",
        value_name = "PATH",
        default_value = northnarrow_agent::net::drain::DEFAULT_NETFLOW_LISTENERS_JSONL_PATH,
    )]
    netflow_listeners_file: PathBuf,

    /// Tappa 10 N9: configurable path of the operator-curated
    /// NetFlow IP/CIDR blocklist (default — read at boot, feeds
    /// NN-L-NET-001).
    #[arg(
        long = "netflow-blocklist-v1",
        value_name = "PATH",
        default_value = DEFAULT_NETFLOW_BLOCKLIST_V1,
    )]
    netflow_blocklist_v1: PathBuf,

    /// Tappa 10 N9: configurable path of the operator overlay
    /// for the NetFlow IP/CIDR blocklist (`+` adds, `-` disables
    /// a default entry). Missing file is fine — no overlay.
    #[arg(
        long = "netflow-blocklist-local",
        value_name = "PATH",
        default_value = DEFAULT_NETFLOW_BLOCKLIST_LOCAL,
    )]
    netflow_blocklist_local: PathBuf,

    /// Tappa 10 N9: configurable path of the operator-curated
    /// NetFlow JA3 blocklist (default — read at boot, feeds
    /// NN-L-NET-003). Ships EMPTY per §10 / N8.
    #[arg(
        long = "netflow-ja3-blocklist-v1",
        value_name = "PATH",
        default_value = DEFAULT_NETFLOW_JA3_BLOCKLIST_V1,
    )]
    netflow_ja3_blocklist_v1: PathBuf,

    /// Tappa 10 N9: configurable path of the operator overlay
    /// for the NetFlow JA3 blocklist. Missing file is fine.
    #[arg(
        long = "netflow-ja3-blocklist-local",
        value_name = "PATH",
        default_value = DEFAULT_NETFLOW_JA3_BLOCKLIST_LOCAL,
    )]
    netflow_ja3_blocklist_local: PathBuf,

    /// Tappa 10.5 D2: path to the process-comm allowlist default
    /// (`process-comm-allowlist.v1` — bare comms exempt from the
    /// R011..R017 process rules). install.sh drops this; the agent
    /// reads + merges the operator overlay at boot.
    #[arg(
        long = "process-comm-allowlist-v1",
        value_name = "PATH",
        default_value = northnarrow_agent::config::comm_allowlist::PROCESS_COMM_ALLOWLIST_V1,
    )]
    process_comm_allowlist_v1: PathBuf,

    /// Tappa 10.5 D2: path to the process-comm allowlist operator
    /// overlay (`+comm` adds, `-comm` re-enables detection on a
    /// default). Missing file is fine — no overlay.
    #[arg(
        long = "process-comm-allowlist-local",
        value_name = "PATH",
        default_value = northnarrow_agent::config::comm_allowlist::PROCESS_COMM_ALLOWLIST_LOCAL,
    )]
    process_comm_allowlist_local: PathBuf,

    /// Tappa 10.5 D4: path to the netflow-comm allowlist default
    /// (`netflow-comm-allowlist.v1` — trusted-actor comms the net
    /// rules suppress on). install.sh drops this; the agent reads +
    /// merges the operator overlay at boot.
    #[arg(
        long = "netflow-comm-allowlist-v1",
        value_name = "PATH",
        default_value = northnarrow_agent::config::comm_allowlist::NETFLOW_COMM_ALLOWLIST_V1,
    )]
    netflow_comm_allowlist_v1: PathBuf,

    /// Tappa 10.5 D4: path to the netflow-comm allowlist operator
    /// overlay (`+comm` adds, `-comm` re-enables detection on a
    /// default). Missing file is fine — no overlay.
    #[arg(
        long = "netflow-comm-allowlist-local",
        value_name = "PATH",
        default_value = northnarrow_agent::config::comm_allowlist::NETFLOW_COMM_ALLOWLIST_LOCAL,
    )]
    netflow_comm_allowlist_local: PathBuf,

    /// Optional PID file path. After all anti-tamper LSM hooks are
    /// attached and pinned (the same synchronisation point at which
    /// the "decision engine ready" line is logged), the agent's PID
    /// is written to this path atomically (sibling tempfile + rename,
    /// so a reader never observes a half-written or empty file). On
    /// graceful shutdown the file is removed. Intended for
    /// verification harnesses and process supervisors: the file's
    /// EXISTENCE is itself the readiness signal (it cannot appear
    /// before every hook is live). A stale file from a previous
    /// crashed run is OVERWRITTEN, not respected — so readers must
    /// confirm /proc/<pid> before trusting the contents. Omitting
    /// the flag (the production default) is a no-op: behaviour is
    /// exactly as before, no PID file is touched.
    #[arg(long = "pid-file", value_name = "PATH")]
    pid_file: Option<PathBuf>,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .with_target(false)
        .init();

    info!("NorthNarrow agent starting...");

    if let Err(e) = bump_memlock_rlimit() {
        warn!(error = %e, "failed to raise RLIMIT_MEMLOCK; eBPF maps may fail to allocate");
    }

    // Tappa 8 A14 (B4): bootstrap the four /etc/northnarrow/ files
    // BEFORE the sensor multiplexer attaches the LSM hooks, so the
    // hooks see their inodes in PROTECTED_INODES the moment they
    // fire. agent_id + signing key bootstraps were previously done
    // post-attach (line ~360); moved here so the LSM-protected
    // window starts at boot rather than at "first signed admin op".
    // audit.log is created as a zero-byte placeholder if absent
    // (first append writes the genesis entry).
    if let Err(e) =
        northnarrow_agent::audit::AgentSigningKey::load_or_bootstrap(&cli.signing_key_file)
    {
        warn!(
            error = %e,
            path = %cli.signing_key_file.display(),
            "agent signing key bootstrap failed pre-attach — audit log will be \
             unsigned this boot"
        );
    }
    if let Err(e) =
        northnarrow_agent::anti_tamper::filesystem::bootstrap_audit_log(&cli.audit_log_file)
    {
        warn!(
            error = %e,
            path = %cli.audit_log_file.display(),
            "audit log bootstrap failed pre-attach — file will be lazily created \
             on first append (and protected only from agent restart onwards)"
        );
    }
    // Tappa 9 C7: bootstrap the two FIM logs pre-attach for the
    // same reason audit.log gets it — STATE_PROTECTED_FILES needs
    // an inode to register against before LSM hooks come up. A
    // present file is left untouched (existing chain preserved).
    if let Err(e) =
        northnarrow_agent::anti_tamper::filesystem::bootstrap_fim_log(&cli.fim_baseline_file)
    {
        warn!(
            error = %e,
            path = %cli.fim_baseline_file.display(),
            "fim baseline log bootstrap failed pre-attach — file will be lazily \
             created on first append (and unprotected this boot)"
        );
    }
    if let Err(e) =
        northnarrow_agent::anti_tamper::filesystem::bootstrap_fim_log(&cli.fim_drift_file)
    {
        warn!(
            error = %e,
            path = %cli.fim_drift_file.display(),
            "fim drift log bootstrap failed pre-attach — file will be lazily \
             created on first append (and unprotected this boot)"
        );
    }
    // Tappa 9.5 K7: bootstrap the two canary state logs pre-attach
    // for the same reason as the FIM logs — STATE_PROTECTED_FILES
    // needs an inode to register against before LSM hooks come up.
    // A present file is left untouched (existing canary registry +
    // access chain preserved across restarts).
    if let Err(e) =
        northnarrow_agent::anti_tamper::filesystem::bootstrap_canary_log(&cli.canary_registry_file)
    {
        warn!(
            error = %e,
            path = %cli.canary_registry_file.display(),
            "canary registry log bootstrap failed pre-attach — file will be lazily \
             created on first deploy (and unprotected this boot)"
        );
    }
    if let Err(e) =
        northnarrow_agent::anti_tamper::filesystem::bootstrap_canary_log(&cli.canary_access_file)
    {
        warn!(
            error = %e,
            path = %cli.canary_access_file.display(),
            "canary access log bootstrap failed pre-attach — file will be lazily \
             created on first trip (and unprotected this boot)"
        );
    }
    // Tappa 10 N8: bootstrap the NetFlow chain log pre-attach for
    // the same reason as the FIM + canary logs — STATE_PROTECTED_FILES
    // needs an inode to register against before LSM hooks come up.
    // A present file is left untouched (existing NetFlow chain
    // preserved across restarts). N7's `dispatch_net_flows` already
    // tolerates an absent file, but PROTECTED_INODES does not, so
    // we bootstrap here to close the brief race window on first boot.
    if let Err(e) =
        northnarrow_agent::anti_tamper::filesystem::bootstrap_netflow_log(&cli.netflow_file)
    {
        warn!(
            error = %e,
            path = %cli.netflow_file.display(),
            "netflow log bootstrap failed pre-attach — file will be lazily \
             created on first flow close (and unprotected this boot)"
        );
    }
    // Tappa 10 N9: bootstrap the NetListener chain log pre-attach
    // for the same reason — STATE_PROTECTED_FILES needs an inode
    // before LSM hooks come up. A present file is left untouched.
    if let Err(e) = northnarrow_agent::anti_tamper::filesystem::bootstrap_netflow_listeners_log(
        &cli.netflow_listeners_file,
    ) {
        warn!(
            error = %e,
            path = %cli.netflow_listeners_file.display(),
            "netflow_listeners log bootstrap failed pre-attach — file will be \
             lazily created on first listener event (and unprotected this boot)"
        );
    }
    // agent_id bootstrap moved up from line ~360 so its inode is
    // present in PROTECTED_INODES from boot. The post-attach
    // re-read at line ~360 stays for the SignedPayload wiring path
    // (it just sees the same value we minted here).
    let _ = agent_id::load_or_bootstrap(&cli.agent_id_file).map_err(|e| {
        warn!(
            error = %e,
            path = %cli.agent_id_file.display(),
            "pre-attach agent_id bootstrap failed — post-attach re-read will \
             surface the same error and fall back to zero UUID"
        );
        e
    });

    // Tappa 10 N9 — build the shared net state BEFORE starting the
    // sensor multiplexer so the TcpConnect + DnsQuery pumps can
    // feed the FlowTracker / DnsCache the instant they start
    // pumping. NetWiring is Arc-shared with the net drain task
    // spawned further down.
    let flow_tracker = Arc::new(parking_lot::Mutex::new(FlowTracker::default()));
    let dns_cache = Arc::new(DnsCache::default());
    let net_wiring = northnarrow_agent::sensors::multiplexer::NetWiring {
        flow_tracker: Arc::clone(&flow_tracker),
        dns_cache: Arc::clone(&dns_cache),
    };
    let (mut sensor, net_bufs) = SensorMultiplexer::start_with_net(net_wiring)
        .await
        .context("starting the sensor multiplexer (with net observation)")?;
    info!(
        sensors =
            "process_spawn, file_open, exec_check, tcp_connect_v4, tcp_connect_v6, dns_query, \
                   inet_csk_listen_start, tcp_close, udp_sendmsg_outbound",
        "sensor multiplexer attached (including Tappa 10 N2 net observation programs)"
    );

    // Tappa 7: turn ourselves opaque to kill(2) and ptrace(2) before
    // anything spawns child tasks or holds resources we'd hate to
    // leak. Per-hook failures are logged WARN inside the call and
    // tolerated so the agent still runs on kernels without BPF-LSM.
    //
    // Watchdog W6: if the watchdog daemon is also deployed (its
    // pidfile present at cli.watchdog_pidfile), co-register its
    // PID into PROTECTED_PIDS so the LSM hooks deny kill/ptrace
    // against the watchdog too. WATCHDOG_COMM goes into
    // allowed_comms unconditionally — `evict_stale_pids` only
    // KEEPS entries whose /proc/<pid>/comm matches an allowed
    // name, so even if the watchdog isn't running yet we want
    // its comm in the allowlist to avoid evicting it once it
    // starts. read_watchdog_pid_optional NEVER errors — a
    // missing/garbage pidfile just falls back to agent-only
    // protection (logged).
    let agent_pid = std::process::id();
    let agent_comm = northnarrow_agent::anti_tamper::read_self_comm()
        .context("reading own /proc/self/comm for anti-tamper allowed-comm set")?;
    let mut allowed_comms = std::collections::HashSet::new();
    allowed_comms.insert(agent_comm);
    allowed_comms.insert(northnarrow_agent::anti_tamper::WATCHDOG_COMM.to_string());

    let watchdog_pid =
        northnarrow_agent::anti_tamper::read_watchdog_pid_optional(&cli.watchdog_pidfile);
    let pids: Vec<u32> = match watchdog_pid {
        Some(wpid) => vec![agent_pid, wpid],
        None => vec![agent_pid],
    };
    if let Err(e) = sensor.attach_anti_tamper(&pids, &allowed_comms) {
        warn!(
            error = %e,
            agent_pid,
            watchdog_pid = ?watchdog_pid,
            "anti-tamper setup failed"
        );
    }

    // Tappa 10 N9 — load operator-curated netflow blocklists from
    // disk + thread them into the decision engine. Load failures
    // degrade gracefully (empty list, like N6 net_rules_empty),
    // so a missing/broken file never blocks agent boot. The
    // production deploy bootstrap (N8 install.sh) ships the v1
    // defaults; missing .local overlay is the normal case for a
    // host without operator-specific block additions.
    let netflow_blocklist = Arc::new(
        NetBlocklist::load(&cli.netflow_blocklist_v1, &cli.netflow_blocklist_local).unwrap_or_else(
            |e| {
                warn!(
                    error = %e,
                    v1 = %cli.netflow_blocklist_v1.display(),
                    local = %cli.netflow_blocklist_local.display(),
                    "netflow blocklist load failed — booting with empty blocklist"
                );
                NetBlocklist::empty()
            },
        ),
    );
    let ja3_blocklist = Arc::new(
        Ja3Blocklist::load(
            &cli.netflow_ja3_blocklist_v1,
            &cli.netflow_ja3_blocklist_local,
        )
        .unwrap_or_else(|e| {
            warn!(
                error = %e,
                v1 = %cli.netflow_ja3_blocklist_v1.display(),
                local = %cli.netflow_ja3_blocklist_local.display(),
                "netflow ja3 blocklist load failed — booting with empty blocklist"
            );
            Ja3Blocklist::empty()
        }),
    );
    let burst_window = Arc::new(parking_lot::Mutex::new(
        northnarrow_agent::decision::rules::net::DnsBurstWindow::new(),
    ));

    // Tappa 10.5 D4: per-family netflow comm allowlist (the comm-gated
    // net rules NN-L-NET-006/007/009/010/011/013/018/019 consult it)
    // + the NN-L-NET-013 beacon-timing window. Same fail-soft contract
    // as the netflow blocklists — a missing/broken file boots with an
    // empty allowlist.
    let netflow_comm_allowlist = Arc::new(
        northnarrow_agent::config::comm_allowlist::load_comm_allowlist(
            "netflow-comm-allowlist",
            &cli.netflow_comm_allowlist_v1,
            &cli.netflow_comm_allowlist_local,
        )
        .unwrap_or_else(|e| {
            warn!(
                error = %e,
                v1 = %cli.netflow_comm_allowlist_v1.display(),
                local = %cli.netflow_comm_allowlist_local.display(),
                "netflow-comm allowlist load failed — booting with empty allowlist"
            );
            northnarrow_agent::config::comm_allowlist::CommAllowlist::default()
        }),
    );
    let beacon_window = Arc::new(parking_lot::Mutex::new(
        northnarrow_agent::decision::rules::net::BeaconWindow::new(),
    ));

    // Tappa 10.5 D2: load the process-comm allowlist for the
    // R011..R017 process rules. Same fail-soft contract as the
    // netflow blocklists — a missing/broken file boots with an empty
    // allowlist (the rules then fire purely on their predicates).
    let process_allowlist = Arc::new(
        northnarrow_agent::config::comm_allowlist::load_comm_allowlist(
            "process-comm-allowlist",
            &cli.process_comm_allowlist_v1,
            &cli.process_comm_allowlist_local,
        )
        .unwrap_or_else(|e| {
            warn!(
                error = %e,
                v1 = %cli.process_comm_allowlist_v1.display(),
                local = %cli.process_comm_allowlist_local.display(),
                "process-comm allowlist load failed — booting with empty allowlist"
            );
            northnarrow_agent::config::comm_allowlist::CommAllowlist::default()
        }),
    );

    #[cfg(feature = "demo-tappa5")]
    let engine = RuleEngine::with_default_rules_and_demo_tappa5();
    #[cfg(not(feature = "demo-tappa5"))]
    let engine = RuleEngine::with_default_rules_and_net(
        Arc::clone(&netflow_blocklist),
        Arc::clone(&ja3_blocklist),
        Arc::clone(&burst_window),
        Arc::clone(&process_allowlist),
        Arc::clone(&netflow_comm_allowlist),
        Arc::clone(&beacon_window),
    );
    info!(
        rules = engine.rule_count(),
        demo_tappa5 = cfg!(feature = "demo-tappa5"),
        netflow_blocklist_entries = netflow_blocklist.len(),
        ja3_blocklist_entries = ja3_blocklist.len(),
        process_comm_allowlist_entries = process_allowlist.len(),
        netflow_comm_allowlist_entries = netflow_comm_allowlist.len(),
        "decision engine ready"
    );

    // Tappa 7 task 6 #2b-verify: optional PID file. `attach_anti_tamper`
    // above is fully synchronous (anti_tamper::attach attempts AND pins
    // every LSM hook before it returns — agent/src/anti_tamper/mod.rs),
    // and the "decision engine ready" line has now flushed, so the
    // file's *existence* is a sound readiness gate: anything that sees
    // it knows every hook is attached and self-protection is live.
    //
    // The agent writing its OWN pid is immune to the failure class that
    // sank three external-resolution strategies in docs/verify-2b.sh
    // (989c292 pgrep -P / -x, 6e746c6 /proc/*/exe diff): the sudo+exec
    // process-tree race, TASK_COMM_LEN comm truncation, and pgrep
    // quirks. A write failure here is FATAL by design — a harness or
    // supervisor that asked for a PID file cannot proceed without it,
    // and silently degrading would resurrect exactly the "agent is
    // alive but the watcher can't find it" bug this flag exists to
    // kill. Production never passes --pid-file, so this is inert there.
    if let Some(pid_file) = cli.pid_file.as_deref() {
        write_pid_file(pid_file)
            .with_context(|| format!("writing --pid-file {}", pid_file.display()))?;
    } else {
        debug!("no --pid-file provided; PID file write skipped (production default)");
    }

    let executor = Executor::new();
    info!(
        own_pid = executor.own_pid(),
        protected = executor.protected().len(),
        "response executor ready (KillProcess + KillProcessTree active)"
    );

    let ade_engine = if cli.no_ade {
        info!("ADE disabled by --no-ade");
        None
    } else {
        let mut cfg = AdeConfig::default();
        if let Some(p) = cli.ade_model.clone() {
            cfg.model_path = p;
        }
        if let Some(p) = cli.ade_prompt.clone() {
            cfg.system_prompt_path = p;
        }
        if let Some(secs) = cli.ade_timeout {
            cfg.timeout = Duration::from_secs(secs);
        }
        if let Some(n) = cli.ade_threads {
            cfg.num_threads = Some(n);
        }
        // Sub-tappa 6.8 audit: this is the ONLY AdeEngine::new call
        // in the agent's hot path — model weights, tokenizer, KV
        // state machine and the rayon pool are loaded ONCE at
        // startup and the resulting handle is shared into
        // process_event via Arc<AdeEngine> (cheap to clone). Any
        // future change that constructs a new engine inside the
        // event loop would silently re-pay the ~5 GiB GGUF mmap
        // and the warmup pass, so guard this invariant in review.
        match AdeEngine::new(cfg).await {
            Ok(engine) => {
                info!(
                    backend = engine.backend_name(),
                    model_path = %engine.config().model_path.display(),
                    warmup_latency_ms = engine.warmup_latency_ms(),
                    timeout_s = engine.config().timeout.as_secs(),
                    "ADE engine ready"
                );
                // Tappa 6.9.7 P5 — env-driven RAG canary (default OFF;
                // graceful no-RAG fallback). Uses the existing 6.7
                // `with_rag` seam; logging is inside `open_index_from_env`.
                let engine = match northnarrow_agent::rag::open_index_from_env() {
                    Some(rag) => engine.with_rag(Arc::new(rag)),
                    None => engine,
                };
                Some(Arc::new(engine))
            }
            Err(e) => {
                warn!(?e, "ADE engine unavailable, fallback to rule-only mode");
                None
            }
        }
    };

    let correlation = CorrelationBuffer::with_default_capacity();
    let host = HostContext::discover();

    // Tappa 7 task 7 / Tappa 8: anti-tamper response pipeline. The
    // NetworkIsolator owns the iptables shell-out; engage runs on
    // any non-Combat → Combat edge, release only fires for an
    // Ed25519-verified admin unlock (capability gated via
    // UnlockToken). If the ruleset is missing we WARN-and-continue
    // with no isolator, so the agent still boots in dev environments
    // without /etc/northnarrow/ provisioned.
    let isolator = match NetworkIsolator::new(cli.combat_rules.clone()) {
        Ok(i) => Some(Arc::new(i)),
        Err(e) => {
            warn!(
                error = %e,
                path = %cli.combat_rules.display(),
                "combat ruleset missing; COMBAT entry will not engage network isolation"
            );
            None
        }
    };

    let posture = if let Some(iso) = isolator.as_ref() {
        let iso_engage = Arc::clone(iso);
        let iso_release = Arc::clone(iso);
        let engage_hook: CombatEntryHook = Arc::new(move || {
            if let Err(e) = iso_engage.engage() {
                tracing::error!(error = %e, "COMBAT engage failed; agent continues in degraded mode");
            }
        });
        let release_hook: CombatReleaseHook = Arc::new(move |token: UnlockToken| {
            if let Err(e) = iso_release.release(token) {
                tracing::error!(
                    error = %e,
                    "admin release failed; iptables state may need manual cleanup"
                );
            }
        });
        PostureMachine::new_with_hooks(engage_hook, release_hook)
    } else {
        PostureMachine::new()
    };
    info!("posture state machine initialized (state: OBSERVING)");

    // Tappa 8 A3 + A8: bootstrap (or read) the per-install agent
    // UUID. The value becomes the third anti-replay layer for the
    // signed-payload verify path (design §6.4 layer 3, plumbed in
    // commit A7 via `verify_signed_payload_quorum`). A failure
    // here is non-fatal: the agent falls back to a zero UUID,
    // which means signed-payload submissions whose `agent_id`
    // field is `[0; 16]` will still verify but every other
    // submission will fail `AgentIdMismatch`. We log loudly so
    // the operator sees the bootstrap problem; the legacy
    // unlock/force-posture/status paths are unaffected because
    // they don't touch agent_id.
    let agent_id = match agent_id::load_or_bootstrap(&cli.agent_id_file) {
        Ok(id) => {
            info!(
                target: "agent_id",
                path = %cli.agent_id_file.display(),
                "agent_id ready"
            );
            id
        }
        Err(e) => {
            warn!(
                error = %e,
                path = %cli.agent_id_file.display(),
                "agent_id bootstrap failed; falling back to zero UUID — \
                 signed-payload admin operations will reject all clients"
            );
            [0u8; 16]
        }
    };

    // Tappa 8 A8: shutdown signal — the dispatcher fires it on a
    // successfully-verified `ShutdownRequest` so this main loop
    // can break and the agent can exit cleanly. The same Arc is
    // cloned into `serve_with_marker_path` (Some(...)) and kept
    // here for the select-arm `wait()`.
    let shutdown_signal = ShutdownSignal::new();

    // ── Tappa 9 C7 — FIM subsystem boot ────────────────────────────
    //
    // Order:
    //  1. Load the watched-paths set (v1 default + .local overlay
    //     merge per §13 Q7). A missing v1 just yields an empty
    //     effective set + WARN; the agent stays up so a misconfigured
    //     install is still operator-recoverable.
    //  2. Open the [`BaselineDb`] for the chained baseline log.
    //     Failure here is also tolerated: the recompute channel
    //     stays unwired so admin `fim baseline` returns
    //     `UnknownOperation` rather than crashing.
    //  3. Build the [`BaselineRecomputeChannel`] + spawn the
    //     long-lived recompute task.
    //  4. Fire `RecomputeReason::FirstBootTofu` (§13 Q5 trust-on-
    //     first-use) when the baseline DB is empty AND at least
    //     one path is configured. First-boot trust model is
    //     documented in `docs/operator/TAPPA9_FIM_TRUST_MODEL.md`.
    //  5. Build the [`FimAdminState`] for the admin socket so
    //     `fim baseline` triggers (3) and `fim status` reads the
    //     in-process snapshot.
    let watched_paths_load = match northnarrow_agent::fim::paths_config::load_watched_paths(
        &cli.fim_paths_v1,
        &cli.fim_paths_local,
    ) {
        Ok(load) => load,
        Err(e) => {
            warn!(
                error = %e,
                v1 = %cli.fim_paths_v1.display(),
                local = %cli.fim_paths_local.display(),
                "fim paths-config: load failed — proceeding with empty watched-paths set"
            );
            Default::default()
        }
    };
    let paths_summary = admin_socket::WatchedPathsSummary::from_load(&watched_paths_load);

    let fim_admin_state: Option<Arc<admin_socket::FimAdminState>> = {
        // Re-derive the signing key + agent_id for FIM the same way
        // the audit log does (re-load rather than steal the audit
        // log's clone — they're separate domains with separate Db
        // handles). A failure here downgrades the FIM CLI surface
        // to "scheduled for next restart" + zero-snapshot status.
        let baseline_db_opt = match northnarrow_agent::audit::AgentSigningKey::load_or_bootstrap(
            &cli.signing_key_file,
        ) {
            Ok(key) => {
                match northnarrow_agent::fim::baseline::BaselineDb::open(
                    &cli.fim_baseline_file,
                    key,
                    agent_id,
                ) {
                    Ok(db) => Some(Arc::new(parking_lot::Mutex::new(db))),
                    Err(e) => {
                        warn!(
                            error = %e,
                            path = %cli.fim_baseline_file.display(),
                            "fim baseline DB open failed — admin `fim baseline` will \
                             reject; status snapshot will report zero rows"
                        );
                        None
                    }
                }
            }
            Err(e) => {
                warn!(
                    error = %e,
                    "fim baseline DB needs the agent signing key — load failed; \
                     FIM admin surface degraded"
                );
                None
            }
        };
        match baseline_db_opt {
            Some(baseline_db) => {
                use northnarrow_agent::fim::attach::{
                    attach_observe_programs, populate_watched_paths, take_fs_fim_events_ringbuf,
                };
                use northnarrow_agent::fim::baseline::BaselineCache;
                use northnarrow_agent::fim::drain::{
                    drain_loop, DriftClassifier, DriftRateLimiter, FimDriftDb, InodePathMap,
                };
                use northnarrow_agent::fim::recompute::{
                    run_recompute_task, BaselineRecomputeChannel, RecomputeReason,
                };

                let rate_limiter = Arc::new(DriftRateLimiter::new());

                // Polish #2: populate the per-path baseline cache
                // from the chained baseline log so the drain loop
                // can suppress no-op kernel events (touch -t,
                // permission-set-to-same-value, etc.) — the cache
                // miss path treats the event as a first observation
                // and emits drift normally.
                let baseline_cache = match BaselineCache::load_from_log(&cli.fim_baseline_file) {
                    Ok(c) => {
                        info!(entries = c.len(), "fim: baseline cache loaded");
                        Arc::new(c)
                    }
                    Err(e) => {
                        warn!(
                            error = %e,
                            path = %cli.fim_baseline_file.display(),
                            "fim baseline cache load failed — drain will emit drift \
                             for every kernel event (no-op suppression disabled)"
                        );
                        Arc::new(BaselineCache::new())
                    }
                };

                // C8: attach the 6 fim_*_observe LSM programs +
                // populate WATCHED_PATHS from the effective paths
                // set. populate_watched_paths returns the populated
                // InodePathMap so the drain loop can resolve
                // (dev,ino) → path. Per-step failures are logged
                // WARN inside the helpers — the agent still boots
                // (degrade-not-fail posture matches anti_tamper).
                let btf = match aya::Btf::from_sys_fs() {
                    Ok(b) => Some(b),
                    Err(e) => {
                        warn!(
                            error = %e,
                            "fim: BTF load failed — observe programs cannot attach this boot"
                        );
                        None
                    }
                };
                if let Some(btf) = btf.as_ref() {
                    if let Err(e) = attach_observe_programs(sensor.ebpf_mut(), btf) {
                        warn!(
                            error = %e,
                            "fim: attach_observe_programs returned error — \
                             observe hooks may be partial"
                        );
                    }
                }
                let inode_map = match populate_watched_paths(
                    sensor.ebpf_mut(),
                    &watched_paths_load.effective,
                ) {
                    Ok(m) => m,
                    Err(e) => {
                        warn!(
                            error = %e,
                            "fim: populate_watched_paths failed — drain loop will see \
                             zero (dev,ino) → path mappings; events will warn-and-skip"
                        );
                        Arc::new(InodePathMap::new())
                    }
                };

                // The recompute task snapshots the merged watched-
                // paths set every iteration — operators who edit
                // fim-paths.local and run `nn-admin fim baseline`
                // pick up the new set without an agent restart.
                let mut recompute_chan = BaselineRecomputeChannel::new();
                let sender = recompute_chan.sender();
                let receiver = recompute_chan
                    .take_receiver()
                    .expect("freshly-constructed channel has a receiver");
                let v1_for_snapshot = cli.fim_paths_v1.clone();
                let local_for_snapshot = cli.fim_paths_local.clone();
                tokio::spawn(run_recompute_task(
                    receiver,
                    Arc::clone(&baseline_db),
                    Arc::clone(&baseline_cache),
                    Arc::clone(&inode_map),
                    move || {
                        northnarrow_agent::fim::paths_config::load_watched_paths(
                            &v1_for_snapshot,
                            &local_for_snapshot,
                        )
                        .map(|l| l.effective)
                        .unwrap_or_default()
                    },
                ));

                // C8: open the chained drift log + spawn the drain
                // task. The drain takes ownership of the FS_FIM_EVENTS
                // ringbuf (taken out of the Ebpf object); subsequent
                // map_mut("FS_FIM_EVENTS") calls would return None,
                // which is fine because no other code references the
                // map name.
                let drift_db_for_drain =
                    match northnarrow_agent::audit::AgentSigningKey::load_or_bootstrap(
                        &cli.signing_key_file,
                    )
                    .and_then(|key| FimDriftDb::open(&cli.fim_drift_file, key, agent_id))
                    {
                        Ok(db) => Some(Arc::new(parking_lot::Mutex::new(db))),
                        Err(e) => {
                            warn!(
                                error = %e,
                                path = %cli.fim_drift_file.display(),
                                "fim drift DB open failed — drain loop will not spawn; \
                                 kernel drift events will be dropped this boot"
                            );
                            None
                        }
                    };

                if let Some(drift_db) = drift_db_for_drain {
                    match take_fs_fim_events_ringbuf(sensor.ebpf_mut()) {
                        Ok(rb) => {
                            let classifier = Arc::new(DriftClassifier::new());
                            let rate_limiter_clone = Arc::clone(&rate_limiter);
                            let inode_map_for_drain = Arc::clone(&inode_map);
                            let baseline_cache_for_drain = Arc::clone(&baseline_cache);
                            let event_tx = sensor.event_tx();
                            let handle = tokio::spawn(async move {
                                if let Err(e) = drain_loop(
                                    rb,
                                    inode_map_for_drain,
                                    baseline_cache_for_drain,
                                    drift_db,
                                    classifier,
                                    rate_limiter_clone,
                                    event_tx,
                                )
                                .await
                                {
                                    warn!(
                                        target: "fim.drain",
                                        error = %e,
                                        "fim drain loop exited"
                                    );
                                }
                            });
                            sensor.register_pump_handle(handle);
                            info!("fim: drain loop spawned");
                        }
                        Err(e) => {
                            warn!(
                                error = %e,
                                "fim: take_fs_fim_events_ringbuf failed — drain loop \
                                 not spawned; kernel drift events will be dropped"
                            );
                        }
                    }
                }

                // §13 Q5 TOFU: empty baseline file + non-empty paths
                // set = first boot, fire a recompute. The recompute
                // task is already running (tokio::spawn doesn't
                // block on the future's first poll).
                if baseline_db.lock().last_hash() == northnarrow_agent::audit::GENESIS_PREV_HASH
                    && !watched_paths_load.effective.is_empty()
                {
                    info!(
                        paths = watched_paths_load.effective.len(),
                        "fim: first-boot TOFU baseline triggered (§13 Q5)"
                    );
                    sender.trigger(RecomputeReason::FirstBootTofu);
                }

                Some(Arc::new(admin_socket::FimAdminState {
                    recompute_sender: sender,
                    rate_limiter,
                    paths_summary,
                    baseline_log_path: cli.fim_baseline_file.clone(),
                    drift_log_path: cli.fim_drift_file.clone(),
                }))
            }
            None => None,
        }
    };

    // ── Tappa 9.5.1 — anti-tamper honeypot integrity sweep ─────────
    //
    // After the FIM observe programs are attached (above) and the agent
    // is in PROTECTED_PIDS, verify the NN-L-FIM-024 bait files exist and
    // recreate any missing one from its embedded template. The recreate
    // is an agent write → PROTECTED_PIDS-exempt, so it cannot
    // self-trigger NN-L-FIM-024. A missing bait at boot is itself a
    // tamper signal (Medium); all-present logs at Info.
    match northnarrow_agent::fim::honeypot::check_and_restore() {
        Ok(report) if report.all_present() => {
            info!(
                present = report.present,
                total = report.total,
                "Honeypot integrity: {}/{} present",
                report.present,
                report.total
            );
        }
        Ok(report) => {
            warn!(
                target: "fim.honeypot",
                rule = "NN-L-FIM-024-INTEGRITY",
                severity = "Medium",
                recreated = report.recreated.len(),
                "Honeypot integrity: recreated {} missing bait file(s): {:?}",
                report.recreated.len(),
                report.recreated
            );
        }
        Err(e) => {
            warn!(target: "fim.honeypot", error = %e, "Honeypot integrity sweep failed");
        }
    }

    // ── Tappa 9.5 K6 — canary subsystem boot ───────────────────────
    //
    // Order (mirrors the FIM boot above):
    //  1. Open the [`Registry`] for the chained canary log. Failure
    //     leaves `canary_admin_state` + `canary_detector` as `None`;
    //     the agent stays up, admin `canary` ops return
    //     `UnknownOperation`, and the rule engine sees zero
    //     `Event::CanaryTripped` events.
    //  2. Open the [`CanaryAccessDb`] for the chained access log.
    //     Same degraded-mode policy as the registry.
    //  3. Build empty [`CanaryIndexes`] and call
    //     `rebuild_from_registry` so the K3 detector sees any
    //     canaries deployed in a prior boot.
    //  4. Layer File + Credential paths into `exe_index` via
    //     `add_file_path_index` (the K3 path-based fallback for
    //     FimEvent that doesn't carry (dev, ino) yet — same
    //     pragmatism the K6 dispatch helper uses post-deploy).
    //  5. Construct the [`Detector`] holding all three shared
    //     `Arc<Mutex<_>>` handles + the [`CanaryAdminState`] for
    //     the admin socket.
    let (canary_admin_state, canary_detector): (
        Option<Arc<admin_socket::CanaryAdminState>>,
        Option<Arc<northnarrow_agent::canary::detector::Detector>>,
    ) = {
        let signing_key_for_canary =
            match northnarrow_agent::audit::AgentSigningKey::load_or_bootstrap(
                &cli.signing_key_file,
            ) {
                Ok(key) => Some(key),
                Err(e) => {
                    warn!(
                        error = %e,
                        "canary subsystem needs agent signing key — load failed; \
                         canary admin surface disabled this boot"
                    );
                    None
                }
            };
        let signing_key_for_access =
            northnarrow_agent::audit::AgentSigningKey::load_or_bootstrap(&cli.signing_key_file)
                .ok();
        match (signing_key_for_canary, signing_key_for_access) {
            (Some(reg_key), Some(access_key)) => {
                let registry = match northnarrow_agent::canary::registry::Registry::open(
                    &cli.canary_registry_file,
                    reg_key,
                    agent_id,
                ) {
                    Ok(r) => Some(Arc::new(parking_lot::Mutex::new(r))),
                    Err(e) => {
                        warn!(
                            error = %e,
                            path = %cli.canary_registry_file.display(),
                            "canary registry open failed — admin `canary` ops will \
                             return UnknownOperation; rule engine sees no \
                             CanaryTripped events"
                        );
                        None
                    }
                };
                let access_log = match northnarrow_agent::canary::access_log::CanaryAccessDb::open(
                    &cli.canary_access_file,
                    access_key,
                    agent_id,
                ) {
                    Ok(a) => Some(Arc::new(parking_lot::Mutex::new(a))),
                    Err(e) => {
                        warn!(
                            error = %e,
                            path = %cli.canary_access_file.display(),
                            "canary access log open failed — detector trips will \
                             not be persisted this boot"
                        );
                        None
                    }
                };
                match (registry, access_log) {
                    (Some(registry), Some(access_log)) => {
                        let indexes = Arc::new(parking_lot::Mutex::new(
                            northnarrow_agent::canary::detector::CanaryIndexes::new(),
                        ));
                        // Rebuild indexes from any pre-existing
                        // registry entries. V1.0 inode resolver
                        // returns None — the K3 detector's
                        // path-based exe_index fallback covers
                        // File + Credential (added below); Process
                        // canaries are exe-path keyed (handled by
                        // rebuild_from_registry directly).
                        {
                            use common::wire::admin_signed_payload::CanaryDeploymentWire;
                            let reg = registry.lock();
                            let mut idx = indexes.lock();
                            idx.rebuild_from_registry(&reg, |_| None);
                            for canary in reg.list() {
                                match &canary.deployment {
                                    CanaryDeploymentWire::File { path, .. }
                                    | CanaryDeploymentWire::Credential { path, .. } => {
                                        idx.add_file_path_index(
                                            std::path::PathBuf::from(path),
                                            canary.canary_id.clone(),
                                        );
                                    }
                                    _ => {}
                                }
                            }
                            info!(canaries = idx.len(), "canary indexes rebuilt from registry");
                        }
                        let detector =
                            Arc::new(northnarrow_agent::canary::detector::Detector::new(
                                registry.clone(),
                                access_log,
                                indexes.clone(),
                            ));
                        let admin_state = Arc::new(admin_socket::CanaryAdminState {
                            registry,
                            indexes,
                            registry_log_path: cli.canary_registry_file.clone(),
                            template_dir: Some(cli.canary_template_dir.clone()),
                        });
                        (Some(admin_state), Some(detector))
                    }
                    _ => (None, None),
                }
            }
            _ => (None, None),
        }
    };

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
        .and_then(|key| NetFlowDb::open(&cli.netflow_file, key, agent_id))
        {
            Ok(db) => Some(Arc::new(parking_lot::Mutex::new(db))),
            Err(e) => {
                warn!(
                    error = %e,
                    path = %cli.netflow_file.display(),
                    "netflow DB open failed — net drain loop will not spawn; \
                     kernel flow close events will be dropped this boot"
                );
                None
            }
        };
        let listener_db_opt = match northnarrow_agent::audit::AgentSigningKey::load_or_bootstrap(
            &cli.signing_key_file,
        )
        .and_then(|key| NetListenerDb::open(&cli.netflow_listeners_file, key, agent_id))
        {
            Ok(db) => Some(Arc::new(parking_lot::Mutex::new(db))),
            Err(e) => {
                warn!(
                    error = %e,
                    path = %cli.netflow_listeners_file.display(),
                    "netflow_listeners DB open failed — net drain loop will not \
                     spawn; kernel listen events will be dropped this boot"
                );
                None
            }
        };
        if let (Some(netflow_db), Some(listener_db)) = (netflow_db_opt, listener_db_opt) {
            let flow_tracker_for_drain = Arc::clone(&flow_tracker);
            let dns_cache_for_drain = Arc::clone(&dns_cache);
            let event_tx = sensor.event_tx();
            let close_rb = net_bufs.close_rb;
            let listen_rb = net_bufs.listen_rb;
            let handle = tokio::spawn(async move {
                if let Err(e) = drain_loop(
                    close_rb,
                    listen_rb,
                    flow_tracker_for_drain,
                    dns_cache_for_drain,
                    netflow_db,
                    listener_db,
                    event_tx,
                )
                .await
                {
                    warn!(target: "net.drain", error = %e, "net drain loop exited");
                }
            });
            sensor.register_pump_handle(handle);
            info!("net: drain loop spawned (NET_FLOW_CLOSE_EVENTS + NET_LISTEN_EVENTS)");
        } else {
            warn!(
                "net: drain loop not spawned — see prior warnings for failed \
                 db open(s); kernel net events will accumulate in ringbufs"
            );
        }
    }

    // Optional admin socket: only spawned if admin pubkey config
    // is present. Missing config = no unlock path; the agent still
    // runs but COMBAT can only be cleared by reboot.
    if let Some(iso) = isolator.as_ref() {
        match AdminAuth::load_with_agent_id(&cli.admin_pub, agent_id) {
            Ok(auth) => {
                let auth = Arc::new(auth);
                let posture_clone = posture.clone();
                let iso_clone = Arc::clone(iso);
                let socket_path = cli.admin_socket.clone();
                let signal_for_serve = shutdown_signal.clone();
                // Tappa 8 B5: construct the AuditLog once at boot
                // (post-A14 the file's inode is already in
                // PROTECTED_INODES so an attacker can't replace
                // it underneath us). The signing key is the one
                // bootstrapped pre-attach above; we load it
                // again here to take ownership of the in-memory
                // SigningKey rather than wrap the pre-attach
                // bootstrap result. agent_id is whatever the
                // pre-attach call minted.
                let signing_key_path = cli.signing_key_file.clone();
                let audit_log_path = cli.audit_log_file.clone();
                let audit_log = match northnarrow_agent::audit::AgentSigningKey::load_or_bootstrap(
                    &signing_key_path,
                ) {
                    Ok(key) => {
                        match northnarrow_agent::audit::AuditLog::open(
                            &audit_log_path,
                            key,
                            agent_id,
                        ) {
                            Ok(log) => Some(Arc::new(parking_lot::Mutex::new(log))),
                            Err(e) => {
                                warn!(
                                    error = %e,
                                    "audit log open failed — admin ops will run \
                                     UNAUDITED this boot"
                                );
                                None
                            }
                        }
                    }
                    Err(e) => {
                        warn!(
                            error = %e,
                            "agent signing key reload failed — admin ops will \
                             run UNAUDITED this boot"
                        );
                        None
                    }
                };
                let marker_path = cli.shutdown_marker_file.clone();
                let fim_state_for_serve = fim_admin_state.clone();
                let canary_state_for_serve = canary_admin_state.clone();
                tokio::spawn(async move {
                    if let Err(e) = admin_socket::serve_with_marker_path(
                        socket_path,
                        auth,
                        Arc::new(posture_clone),
                        iso_clone,
                        marker_path,
                        Some(signal_for_serve),
                        audit_log,
                        fim_state_for_serve,
                        canary_state_for_serve,
                    )
                    .await
                    {
                        warn!(error = %e, "admin socket serve loop exited");
                    }
                });
            }
            Err(e) => {
                warn!(
                    error = %e,
                    path = %cli.admin_pub.display(),
                    "admin pub key file missing or invalid; admin socket disabled"
                );
            }
        }
    }

    // Decay loop: walks the posture down (ALERTED→OBSERVING after 1h
    // idle, ENGAGED→ALERTED after 24h idle). COMBAT never decays
    // here; it requires an admin-signed release. The 60 s cadence is
    // a coarse heartbeat, not a precise deadline.
    let posture_decay = posture.clone();
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_secs(60));
        tick.tick().await; // skip the immediate first tick
        loop {
            tick.tick().await;
            if let Some(new_state) = posture_decay.tick_decay() {
                info!(state = %new_state.kind(), "posture decay transition");
            }
        }
    });

    // Install the three shutdown signals up front, before the loop.
    // Re-creating the future inside `select!` every iteration (the
    // old `signal::ctrl_c()` shorthand) re-runs handler registration
    // each tick and interacts badly with `SIG_IGN` inherited from
    // `bash &` + `nohup` (live test 2026-05-12 found SIGINT and
    // SIGHUP silently dropped; only SIGQUIT brought the agent down).
    // A pre-registered `Signal` stream is the documented robust path.
    //
    // SIGTERM is normally caught by the Tappa 7 LSM hook before
    // userland ever sees it; the handler is here for builds running
    // without anti-tamper (kernels lacking `bpf` in their LSM chain).
    let mut sigint = signal(SignalKind::interrupt()).context("installing SIGINT handler")?;
    let mut sigterm = signal(SignalKind::terminate()).context("installing SIGTERM handler")?;
    let mut sighup = signal(SignalKind::hangup()).context("installing SIGHUP handler")?;

    loop {
        tokio::select! {
            evt = sensor.next_event() => match evt {
                Some(e) => process_event(
                    &engine,
                    &executor,
                    ade_engine.as_deref(),
                    &correlation,
                    &host,
                    &posture,
                    // Tappa 9.5 K6: detector handle wired in. When
                    // the canary subsystem boot above failed
                    // (missing signing key, registry open error),
                    // canary_detector is None and process_event
                    // short-circuits to the source event without
                    // canary filtering.
                    canary_detector.as_deref(),
                    e,
                ).await,
                None => {
                    warn!("sensor pump exited; shutting down");
                    break;
                }
            },
            _ = sigint.recv() => {
                info!("SIGINT received; shutting down");
                break;
            }
            _ = sigterm.recv() => {
                info!("SIGTERM received; shutting down");
                break;
            }
            _ = sighup.recv() => {
                info!("SIGHUP received; shutting down");
                break;
            }
            // Tappa 8 A8: admin-authorised graceful shutdown. The
            // dispatcher has already (a) verified the
            // ShutdownRequest quorum, (b) written the on-disk
            // marker the watchdog will honour, and (c) replied
            // Success to the client BEFORE firing this signal.
            // Breaking the loop runs the existing shutdown
            // sequence (ADE stats, pid_file removal, admin socket
            // unlink), then main() returns Ok(()) and the
            // process exits 0.
            //
            // Design note (§10.3 step 4): we deliberately do NOT
            // release the COMBAT iptables ruleset here. "Shutdown
            // of the agent is orthogonal to network state" — the
            // operator's intent is to stop the agent, not to
            // declare the threat over. The next agent boot
            // inherits the existing iptables state and reports
            // COMBAT in `status`; the operator clears it with a
            // separate `nn-admin unlock` after restart if they
            // want.
            _ = shutdown_signal.wait() => {
                info!(
                    target: "admin.shutdown",
                    "admin-authorised shutdown signal received; \
                     beginning graceful exit (COMBAT state preserved \
                     across restart per design §10.3 step 4)"
                );
                break;
            }
        }
    }

    if let Some(ade) = &ade_engine {
        let snap = ade.stats();
        info!(
            total = snap.total_inferences,
            success = snap.successful_verdicts,
            malformed = snap.malformed_outputs,
            timeouts = snap.timeouts,
            backend_errors = snap.backend_errors,
            avg_ms = snap.avg_latency_ms,
            p50_ms = snap.p50_latency_ms,
            p95_ms = snap.p95_latency_ms,
            p99_ms = snap.p99_latency_ms,
            "ADE shutdown stats"
        );
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
    Ok(())
}

/// Categorise + log + evaluate + (maybe) execute.
///
/// Tappa 4 ships five sensors; Tappa 2 rules only match `ProcessSpawn`,
/// so non-spawn events flow through as DEBUG telemetry and bypass the
/// engine. The kill syscalls + verify retries can sleep up to 50 ms,
/// so any execution dispatch goes through `spawn_blocking`.
///
/// Tappa 6: every event also lands in the correlation buffer (so ADE
/// has recent context), and unmatched events get routed through ADE
/// when the engine is enabled.
#[allow(clippy::too_many_arguments)]
async fn process_event(
    engine: &RuleEngine,
    executor: &Executor,
    ade: Option<&AdeEngine>,
    correlation: &CorrelationBuffer,
    host: &HostContext,
    posture: &PostureMachine,
    canary_detector: Option<&northnarrow_agent::canary::detector::Detector>,
    event: Event,
) {
    // Tappa 9.5 (K3): canary precedence over FIM rules per
    // §12 Q9 OPTION B inline-filter lock-in. The detector
    // checks the event against the deployed canary registry;
    // on match, it returns Some(Event::CanaryTripped { … }),
    // marks the canary as tripped (idempotent per §12 Q2),
    // and appends to the canary_access.jsonl chain. We
    // REPLACE the source event with the canary event so
    // downstream (correlation buffer push, posture observer,
    // rule engine) routes through the K5 canary rule family
    // instead of the K9 FIM rule layer.
    //
    // When `canary_detector` is `None` (early-boot path
    // before K6 wires the Detector handle), this is a no-op.
    let event = match canary_detector.and_then(|d| d.process_event(&event)) {
        Some(canary_event) => canary_event,
        None => event,
    };

    // Run posture detection BEFORE we push the focal event into the
    // correlation buffer — the trigger detector counts the focal as
    // a fresh +1 on top of `recent`, and `recent` already containing
    // the focal would double-count it.
    let recent_for_posture = correlation.snapshot();
    if let Some(new_state) = posture.observe(&event, &recent_for_posture) {
        warn!(state = %new_state.kind(), "POSTURE TRANSITION");
    }
    correlation.push(event.clone());

    match &event {
        Event::ProcessSpawn { .. } => info!(event = ?event, "process spawn detected"),
        Event::FileOpen {
            filename,
            comm,
            pid,
            ..
        } => {
            debug!(pid, comm = %comm, filename = %filename, "file open")
        }
        Event::ExecCheck {
            filename,
            comm,
            pid,
            ..
        } => {
            debug!(pid, comm = %comm, filename = %filename, "exec_check")
        }
        Event::TcpConnect {
            dst_addr,
            dst_port,
            family,
            comm,
            pid,
            ..
        } => {
            debug!(
                pid, comm = %comm, family,
                dst = %render_addr(*family, dst_addr),
                dst_port,
                "tcp_connect"
            )
        }
        Event::DnsQuery {
            dns_server,
            family,
            comm,
            pid,
            query_name,
            ..
        } => {
            debug!(
                pid, comm = %comm,
                server = %render_addr(*family, dns_server),
                query = %query_name,
                "dns_query"
            )
        }
        // Tappa 7: kernel-side LSM hook denied a tamper attempt on
        // protected state. The posture machine observed the event
        // at the top of this function and will route it through the
        // ConfirmedIntrusion trigger (anti-tamper denial = strongest
        // possible posture signal, ENGAGED → COMBAT).
        Event::FsProtectDenial {
            pid,
            uid,
            comm,
            target_dev,
            target_ino,
            operation,
            ..
        } => {
            warn!(
                pid, uid, comm = %comm,
                op = %operation,
                target_dev, target_ino,
                "ANTI-TAMPER DENIAL"
            );
            // Short-circuit: a kernel deny is not something the
            // rule engine or ADE LLM should re-evaluate. The
            // posture trigger above is the response; we are done.
            return;
        }
        // Tappa 9 (C4): FIM drift events. The drain loop in
        // agent/src/fim/drain.rs already wrote the chained
        // fim_drift.jsonl audit row + emitted Event::Fim
        // here only if NOT rate-limited (§6.5). Log a one-
        // line summary; the rule engine (C5 NN-L-FIM-001..009)
        // picks up the event via the normal `engine.evaluate`
        // path below.
        Event::Fim(fe) => {
            warn!(
                path = %fe.path,
                op = ?fe.op,
                modifier_pid = fe.modifier_pid,
                modifier_uid = fe.modifier_uid,
                modifier_comm = %fe.modifier_comm,
                "FIM DRIFT"
            );
        }
        // Tappa 9.5 (K3): canary trip events. The K3 inline
        // detector intercepts source events BEFORE they reach
        // this match arm and re-emits as `Event::CanaryTripped`
        // ONLY when a canary fires (§12 Q9 OPTION B inline-
        // filter lock-in). Reaching this arm via the regular
        // event-bus path means a downstream component
        // (correlation snapshot replay, future K6 admin
        // synthetic-event injection) re-fed the canary event;
        // we log + let the K5 rule layer fire the standard
        // KillProcessTree + posture→COMBAT response.
        Event::CanaryTripped {
            canary_id,
            canary_name,
            canary_type,
            access_kind,
            accessor_pid,
            accessor_uid,
            accessor_comm,
            ..
        } => {
            warn!(
                canary_id = %canary_id,
                canary_name = %canary_name,
                canary_type = ?canary_type,
                access_kind = ?access_kind,
                accessor_pid = %accessor_pid,
                accessor_uid = %accessor_uid,
                accessor_comm = %accessor_comm,
                "CANARY TRIPPED"
            );
        }
        // Tappa 10 (N6) — minimal logging arms; the N3 flow
        // tracker + N2 listener kprobe feed these into the rule
        // engine below. Full drain wiring is a follow-up commit.
        Event::NetFlow(nf) => {
            info!(
                pid = %nf.pid,
                comm = %nf.comm,
                dst_addr = %nf.dst_addr,
                dst_port = %nf.dst_port,
                proto = %nf.proto,
                bytes_sent = %nf.bytes_sent,
                "net flow"
            );
        }
        Event::NetListener(nl) => {
            info!(
                pid = %nl.pid,
                comm = %nl.comm,
                bind_addr = %nl.bind_addr,
                bind_port = %nl.bind_port,
                "net listener"
            );
        }
    }

    if let Some(verdict) = engine.evaluate(&event) {
        warn!(
            rule = %verdict.rule_id,
            rule_name = %verdict.rule_name,
            category = %verdict.category,
            action = ?verdict.action,
            severity = ?verdict.severity,
            target_pid = verdict.event_pid,
            target_filename = %verdict.event_filename,
            reasoning = %verdict.reasoning,
            "VERDICT (rule)"
        );

        let exec = executor.clone();
        let action = verdict.action.clone();
        let target_pid = verdict.event_pid;
        let report =
            match tokio::task::spawn_blocking(move || exec.execute(action, target_pid)).await {
                Ok(r) => r,
                Err(e) => {
                    warn!(error = %e, "executor task join failed");
                    return;
                }
            };

        info!(
            action = ?report.action,
            primary = ?report.primary,
            additional_count = report.additional.len(),
            elapsed_us = report.elapsed.as_micros() as u64,
            "EXECUTED"
        );
        return;
    }

    let Some(ade) = ade else {
        return;
    };

    // Only ProcessSpawn / ExecCheck warrant ADE evaluation today;
    // FileOpen / TCP / DNS volumes are too high to feed the LLM and
    // they don't have an immediate executor mapping anyway.
    if !matches!(&event, Event::ProcessSpawn { .. } | Event::ExecCheck { .. }) {
        return;
    }

    debug!("no rule matched, escalating to ADE");
    let context = EventContext {
        recent_events: correlation.get_correlated_default(&event),
        host_context: host.clone(),
    };

    info!("ADE inference started");
    let verdict = match ade.evaluate(&event, &context).await {
        Ok(v) => v,
        Err(e) => {
            warn!(?e, "ADE error, defaulting to log-only");
            return;
        }
    };

    info!(
        latency_ms = verdict.metadata.inference_latency_ms,
        "ADE inference completed"
    );
    warn!(
        action = %verdict.verdict,
        severity = %verdict.severity,
        confidence = verdict.confidence,
        trace_id = %verdict.trace_id,
        reasoning = %verdict.reasoning.step_5_decision,
        "VERDICT (ADE)"
    );

    let raw_action = verdict.verdict;
    let raw_severity = verdict.severity;
    let verdict = posture.modulate_verdict(verdict);
    if verdict.verdict != raw_action || verdict.severity != raw_severity {
        info!(
            posture = %posture.current_kind(),
            from_action = %raw_action,
            from_severity = %raw_severity,
            to_action = %verdict.verdict,
            to_severity = %verdict.severity,
            "verdict modulated by posture"
        );
    }

    if !verdict.requires_execution() {
        info!(action = %verdict.verdict, "ADE verdict logged, no execution needed");
        return;
    }

    let exec = executor.clone();
    let action = verdict.to_response_action();
    let target_pid = match &event {
        Event::ProcessSpawn { pid, .. } | Event::ExecCheck { pid, .. } => *pid,
        _ => return,
    };
    let report = match tokio::task::spawn_blocking(move || exec.execute(action, target_pid)).await {
        Ok(r) => r,
        Err(e) => {
            warn!(error = %e, "executor task join failed");
            return;
        }
    };
    info!(
        action = ?report.action,
        primary = ?report.primary,
        additional_count = report.additional.len(),
        elapsed_us = report.elapsed.as_micros() as u64,
        "EXECUTED (from ADE)"
    );
}

/// Render a 16-byte address according to family (`2` = AF_INET → first
/// 4 bytes; `10` = AF_INET6 → full v6).
fn render_addr(family: u8, bytes: &[u8; 16]) -> String {
    use std::net::{Ipv4Addr, Ipv6Addr};
    if family == 2 {
        Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3]).to_string()
    } else if family == 10 {
        Ipv6Addr::from(*bytes).to_string()
    } else {
        format!("family={family}")
    }
}

/// Atomically publish the current PID to `path` (Tappa 7 task 6
/// #2b-verify). A sibling tempfile is written then `rename(2)`d over
/// the target, so the rename is a same-filesystem atomic swap and a
/// concurrent reader observes either the old file or the complete new
/// one — never a truncated or empty file. The tempfile name carries
/// the PID so two agents misconfigured onto one path cannot corrupt
/// each other's tempfile mid-write. Every error is contextualised and
/// propagated (never swallowed) so the caller can make it fatal and a
/// failing harness can pinpoint which syscall failed.
fn write_pid_file(path: &std::path::Path) -> Result<()> {
    let pid = std::process::id();

    // The tempfile MUST live in the target's directory (same
    // filesystem) for rename(2) to be atomic — derive it from the
    // target, never from /tmp. `with_file_name` preserves the parent.
    let tmp = match path.file_name() {
        Some(name) => {
            let mut t = name.to_os_string();
            t.push(format!(".tmp.{pid}"));
            path.with_file_name(t)
        }
        None => anyhow::bail!(
            "--pid-file path has no file-name component: {}",
            path.display()
        ),
    };

    // `fs::write` create+truncate+write+close in one shot. If the
    // parent directory is missing this fails NotFound here, at
    // startup, loudly — which is the intended behaviour for a
    // misconfigured --pid-file path.
    std::fs::write(&tmp, format!("{pid}\n"))
        .with_context(|| format!("writing PID tempfile {}", tmp.display()))?;

    if let Err(e) = std::fs::rename(&tmp, path) {
        // Don't litter a half-finished tempfile on rename failure.
        let _ = std::fs::remove_file(&tmp);
        return Err(e).with_context(|| {
            format!(
                "atomically renaming PID file {} -> {}",
                tmp.display(),
                path.display()
            )
        });
    }

    info!(
        target: "anti-tamper",
        path = %path.display(),
        pid,
        "pid_file written (atomic tempfile+rename; existence == post-attach readiness gate)"
    );
    Ok(())
}

/// Raise `RLIMIT_MEMLOCK` to infinity so older kernels accept large
/// eBPF map allocations. Best-effort: failure is logged and ignored.
fn bump_memlock_rlimit() -> std::io::Result<()> {
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    // SAFETY: a valid `rlimit` is passed by reference; the kernel only
    // reads from it. Failure is reported via the return code.
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}
