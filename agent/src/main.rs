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
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use clap::Parser;
use common::posture_types::PostureKind;
use common::Event;
use northnarrow_agent::ade::{
    check_ade_memory, AdeConfig, AdeEngine, AdeMemCheck, EventContext, HostContext,
};
use northnarrow_agent::admin_socket::{self, ShutdownSignal};
use northnarrow_agent::agent_id;
use northnarrow_agent::anti_tamper::admin_auth::AdminAuth;
use northnarrow_agent::anti_tamper::btf_revalidate::{
    publish_resolved, resolve_offsets, resolve_tracepoint_fields, RefuseReason, ResolveOutcome,
};
use northnarrow_agent::anti_tamper::network_isolate::{NetworkIsolator, UnlockToken};
use northnarrow_agent::correlation::CorrelationBuffer;
use northnarrow_agent::decision::RuleEngine;
use northnarrow_agent::detection_budget::{self, Admit};
use northnarrow_agent::net::blocklist::{
    Ja3Blocklist, NetBlocklist, DEFAULT_NETFLOW_BLOCKLIST_LOCAL, DEFAULT_NETFLOW_BLOCKLIST_V1,
    DEFAULT_NETFLOW_JA3_BLOCKLIST_LOCAL, DEFAULT_NETFLOW_JA3_BLOCKLIST_V1,
};
use northnarrow_agent::net::dns_cache::DnsCache;
use northnarrow_agent::net::flow_tracker::FlowTracker;
use northnarrow_agent::posture::{
    resolve_verified_watchdog_pid, AuthSessionTracker, CombatEntryHook, CombatReleaseHook,
    ExemptPids, PostureMachine, WatchdogResolution,
};
use northnarrow_agent::response::{Executor, ExecutorConfig};
use northnarrow_agent::sensors::SensorMultiplexer;
use tokio::signal::unix::{signal, SignalKind};
use tracing::{debug, error, info, warn};
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

    /// Detect-only / monitor mode (BUG-033). Detection runs in full and
    /// posture still transitions (OBSERVING→ALERTED→COMBAT is logged for
    /// visibility), but NO enforcement touches the system: every
    /// response action (kill / block / quarantine / throttle /
    /// isolation) and COMBAT-posture network isolation are suppressed
    /// and logged as "would execute". Use for safe rollout / tuning
    /// before arming autonomous response. Also settable via env
    /// `NN_DETECT_ONLY=1` (legacy `NORTHNARROW_DRY_RUN=1` is honoured too).
    #[arg(long = "detect-only", default_value_t = false)]
    detect_only: bool,

    /// Internal: run as the telemetry-probe child (one file open, one DNS
    /// packet, exit). Spawned by the agent itself every
    /// `NN_TELEMETRY_PROBE_SECS`; never meant for operators.
    #[arg(long = "telemetry-probe", hide = true, value_name = "NONCE")]
    telemetry_probe: Option<String>,

    /// Compatibility check only: resolve every kernel struct offset and
    /// enumerator the eBPF programs need against the given BTF file
    /// (`/sys/kernel/btf/vmlinux` of this or another kernel, or a BTF
    /// extracted from a distro kernel package), print the report and
    /// exit — 0 when everything resolves, 2 when a field is missing
    /// (that kernel would be refused at boot), 3 on unreadable/unparseable
    /// BTF. No eBPF is loaded, no root needed. Multi-kernel level 2.
    #[arg(long = "btf-check", value_name = "BTF_FILE")]
    btf_check: Option<PathBuf>,

    /// Lab only (Tappa 10.9 step 0): load the sensor-feasibility probes on
    /// this kernel, exercise them, print the report and exit — 0 when every
    /// required property holds. Root, a `test-privileged` build, and the
    /// installed agent stopped (`deploy/lab/nn-lab.sh sensor-feasibility`).
    #[arg(long = "sensor-feasibility", hide = true)]
    sensor_feasibility: bool,

    /// Print the test and debug cargo features this binary was built with
    /// (comma-separated: `debug-trigger`, `demo-tappa5`, `test-privileged`)
    /// or `none`, and exit. A release build prints `none`; the range
    /// bootstrap refuses to install anything else (external audit
    /// NN-AUD-211).
    #[arg(long = "build-features")]
    build_features: bool,

    /// File-open sensor (Tappa 10.9 step 1). `lsm` (default): the FIM
    /// `file_open` observer classifies every open in the kernel and ships
    /// only the ones a rule reads, counting write-opens for mass write.
    /// `tracepoint`: the previous `sys_enter_openat` sensor, which ships
    /// every open to userland; kept for one soak cycle as a fallback (also
    /// `NN_FILE_OPEN_SENSOR=tracepoint` in a unit drop-in).
    #[arg(
        long = "file-open-sensor",
        env = "NN_FILE_OPEN_SENSOR",
        value_enum,
        default_value_t = FileOpenSensor::Lsm
    )]
    file_open_sensor: FileOpenSensor,

    /// Exec sensor (Tappa 10.9 step 2). `lsm` (default): LSM
    /// `bprm_check_security` reads the file the kernel opened, and the exec
    /// rules match its canonical path (review 61). `tracepoint`: the
    /// previous `sys_enter_execve` sensor, whose rules matched the caller's
    /// string; kept for one soak cycle as a fallback (also
    /// `NN_EXEC_SENSOR=tracepoint` in a unit drop-in).
    #[arg(
        long = "exec-sensor",
        env = "NN_EXEC_SENSOR",
        value_enum,
        default_value_t = ExecSensor::Lsm
    )]
    exec_sensor: ExecSensor,

    /// DNS sensor (Tappa 10.9 step 3). `skb` (default): kprobes on
    /// `udp_send_skb` / `udp_v6_send_skb` read the query from the socket
    /// buffer the kernel built — the name actually sent, IPv4 and IPv6
    /// (reviews 66, 67). `sendmsg`: the previous `udp_sendmsg` kprobe, which
    /// read user memory before the kernel's copy and saw IPv4 only; kept
    /// for one soak cycle as a fallback (also `NN_DNS_SENSOR=sendmsg` in a
    /// unit drop-in).
    #[arg(
        long = "dns-sensor",
        env = "NN_DNS_SENSOR",
        value_enum,
        default_value_t = DnsSensor::Skb
    )]
    dns_sensor: DnsSensor,

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

    /// BUG-031 — the IPv6 (`ip6tables-restore`) ruleset NetworkIsolator
    /// applies on COMBAT entry alongside the v4 one. A missing file
    /// degrades the v6 leg (loud WARN), not the whole COMBAT. Production
    /// install: /etc/northnarrow/combat-rules.v6; repo dev path:
    /// configs/combat-rules.v6.
    #[arg(
        long = "combat-rules-v6",
        value_name = "PATH",
        default_value = "/etc/northnarrow/combat-rules.v6"
    )]
    combat_rules_v6: PathBuf,

    /// Beta Step 4b: opt-in management carve-out CIDR list. Each IPv4
    /// CIDR in this file is allowed through during COMBAT so a remote
    /// operator on a declared management network is not locked out.
    /// Re-read at every COMBAT engage (never cached). Default-empty =
    /// full isolation (no regression).
    #[arg(
        long = "combat-allow-cidrs",
        value_name = "PATH",
        default_value = northnarrow_agent::anti_tamper::combat_allow::DEFAULT_COMBAT_ALLOW_CIDRS
    )]
    combat_allow_cidrs: PathBuf,

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

    /// Beta Step 3: expected install path of the watchdog binary, used
    /// to verify a candidate watchdog PID's `/proc/<pid>/exe` (a
    /// kernel-resolved symlink, not forgeable). Default (review 26): the
    /// `northnarrow-watchdog` next to this agent's own executable —
    /// `/usr/local/bin` for `install.sh`, `/usr/bin` for a package.
    #[arg(long = "watchdog-exe", value_name = "PATH")]
    watchdog_exe: Option<PathBuf>,

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
    /// Install manifest written by `install.sh` (provenance level + hashes
    /// of the installed binaries and eBPF object); the agent re-verifies
    /// itself against it at every boot. Absent: not installed by
    /// `install.sh`, or removed — refused once a boot of this install has
    /// verified against it (external audit DEP-009).
    #[arg(
        long = "install-manifest",
        value_name = "PATH",
        default_value = northnarrow_agent::install_manifest::DEFAULT_INSTALL_MANIFEST_PATH,
    )]
    install_manifest: PathBuf,

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

    /// Tappa 9.0.a: configurable path of the chained detection log
    /// (default `/var/lib/northnarrow/detections/detections.jsonl`).
    /// Same per-test override rationale as `--fim-drift-file`.
    #[arg(
        long = "detections-file",
        value_name = "PATH",
        default_value = northnarrow_agent::detection_store::DEFAULT_DETECTIONS_LOG_PATH,
    )]
    detections_file: PathBuf,

    /// Tappa 9.0.c: configurable path of the chained status-event log
    /// (default `/var/lib/northnarrow/detections/status_events.jsonl`).
    /// The event-sourced triage-status chain, sibling of the detection
    /// log. Same per-test override rationale as `--detections-file`.
    #[arg(
        long = "status-events-file",
        value_name = "PATH",
        default_value = northnarrow_agent::detection_store::DEFAULT_STATUS_EVENTS_LOG_PATH,
    )]
    status_events_file: PathBuf,

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
    /// chain. The net drain appends one row per closed flow; the
    /// `net flows`, `net resolve` and `net fingerprint` admin verbs
    /// read this file and its rotated archives (external audit
    /// NN-AUD-082: they used to read the built-in path whatever this
    /// flag said). Bootstrapped pre-attach so PROTECTED_INODES has an
    /// inode to register against before LSM hooks come up.
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
    /// event; `nn-admin net listeners` reads it.
    #[arg(
        long = "netflow-listeners-file",
        value_name = "PATH",
        default_value = northnarrow_agent::net::drain::DEFAULT_NETFLOW_LISTENERS_JSONL_PATH,
    )]
    netflow_listeners_file: PathBuf,

    /// External audit NN-AUD-108 (lab PR 160): the signed head anchor of
    /// the chains. Default: `chain_heads.json` next to `--audit-log-file`
    /// (`/etc/northnarrow/chain_heads.json`).
    #[arg(long = "chain-heads-file", value_name = "PATH")]
    chain_heads_file: Option<PathBuf>,

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

impl Cli {
    /// `--chain-heads-file`, or `chain_heads.json` next to the audit log it
    /// anchors (an agent run with its own audit log and key, as the
    /// privileged tests do, never touches the installed agent's anchor).
    fn resolved_chain_heads_file(&self) -> PathBuf {
        self.chain_heads_file.clone().unwrap_or_else(|| {
            self.audit_log_file
                .parent()
                .unwrap_or_else(|| std::path::Path::new("."))
                .join(northnarrow_agent::chain_anchor::HEADS_FILE_NAME)
        })
    }

    /// The chains the agent anchors, at the configured paths.
    fn chain_paths(&self) -> northnarrow_agent::chain_anchor::ChainPaths {
        northnarrow_agent::chain_anchor::ChainPaths {
            audit: self.audit_log_file.clone(),
            canary_registry: self.canary_registry_file.clone(),
            canary_access: self.canary_access_file.clone(),
            detections: self.detections_file.clone(),
            status_events: self.status_events_file.clone(),
            netflow: self.netflow_file.clone(),
            fim_drift: self.fim_drift_file.clone(),
        }
    }

    /// `--watchdog-exe`, or the watchdog next to this agent (review 26).
    fn resolved_watchdog_exe(&self) -> PathBuf {
        self.watchdog_exe.clone().unwrap_or_else(|| {
            let own = std::env::current_exe().and_then(|p| p.canonicalize()).ok();
            northnarrow_agent::posture::sibling_watchdog_exe(own.as_deref())
        })
    }
}

/// `--file-open-sensor`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, clap::ValueEnum)]
enum FileOpenSensor {
    Lsm,
    Tracepoint,
}

/// `--exec-sensor`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, clap::ValueEnum)]
enum ExecSensor {
    Lsm,
    Tracepoint,
}

/// `--dns-sensor`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, clap::ValueEnum)]
enum DnsSensor {
    Skb,
    Sendmsg,
}

/// Review 69: the LSM file-open sensor could not be armed, so
/// `sys_enter_openat` (attached, inert until now) starts emitting.
fn open_tracepoint_fallback(sensor: &mut SensorMultiplexer) {
    if let Err(e) =
        northnarrow_agent::sensors::open_sensor::set_tracepoint_emitting(sensor.ebpf_mut(), true)
    {
        error!(
            error = %e,
            "file-open sensor: sys_enter_openat could not be turned on — file opens are NOT observed"
        );
    }
}

/// Tappa 10.9 step 1: switch the file-open sensor to LSM `file_open`, once
/// the FIM observer that hosts it is attached; otherwise (or on
/// `--file-open-sensor tracepoint`) `sys_enter_openat` stays in charge.
fn start_open_sensor(
    sensor: &mut SensorMultiplexer,
    mode: FileOpenSensor,
    fim_attached: &[&str],
    carveout: &[String],
    audit_log: Option<Arc<parking_lot::Mutex<northnarrow_agent::audit::AuditLog>>>,
) {
    use northnarrow_agent::sensors::open_sensor::{
        pump, refresh, take_ringbuf, DepthCapLog, OpenSensorMaps, RuleHealth, RuleInputs, RuleSet,
        RULE_CAPACITY,
    };
    if mode == FileOpenSensor::Tracepoint {
        info!("file-open sensor: tracepoint mode (--file-open-sensor tracepoint) — every open reaches userland");
        return;
    }
    if !fim_attached.contains(&northnarrow_agent::fim::attach::OPEN_SENSOR_PROGRAM) {
        warn!(
            "file-open sensor: its file_open observer is not attached — keeping sys_enter_openat"
        );
        open_tracepoint_fallback(sensor);
        return;
    }
    let rules = RuleSet::build(&RuleInputs::from_host(carveout));
    let mut maps = match OpenSensorMaps::take(sensor.ebpf_mut()) {
        Ok(m) => m,
        Err(e) => {
            warn!(error = %e, "file-open sensor: rule maps unavailable — keeping sys_enter_openat");
            open_tracepoint_fallback(sensor);
            return;
        }
    };
    // External audit SNS-007: every rule that fits is written, the
    // posture's own first; a refused rule degrades the sensor (ERROR, one
    // signed `subsystem_degraded`) and is tried again at every refresh.
    let applied = maps.apply(&rules, None);
    let mut health = RuleHealth::default();
    report_open_rules(&mut health, &applied, audit_log.as_ref(), true);
    let ring = match take_ringbuf(sensor.ebpf_mut()) {
        Ok(r) => r,
        Err(e) => {
            warn!(error = %e, "file-open sensor: ring unavailable — keeping sys_enter_openat");
            open_tracepoint_fallback(sensor);
            return;
        }
    };
    let handle = tokio::spawn(pump(ring, sensor.event_tx()));
    sensor.register_pump_handle(northnarrow_agent::sensors::open_sensor::PUMP_LABEL, handle);
    if let Err(e) = maps.arm(true) {
        warn!(error = %e, "file-open sensor: arming failed — keeping sys_enter_openat");
        open_tracepoint_fallback(sensor);
        return;
    }
    northnarrow_agent::posture::triggers::set_kernel_mass_write(true);
    // Armed: the old tracepoint (every openat to userland) goes. Its link
    // is retired first, or the BPF self-defence would report its absence
    // as tampering.
    let detached = match sensor.ebpf_mut().program_mut("sys_enter_openat") {
        Some(p) => match <&mut aya::programs::TracePoint>::try_from(p) {
            Ok(tp) => {
                if let Ok(info) = tp.info() {
                    northnarrow_agent::anti_tamper::bpf_defense::retire_program_links(info.id());
                }
                tp.unload().is_ok()
            }
            Err(_) => false,
        },
        None => false,
    };
    info!(
        inode_rules = rules.inodes.len(),
        child_rules = rules.children.len(),
        name_rules = rules.names.len(),
        runtime_dirs = rules.runtime.len(),
        rules_failed = applied.failed,
        capacity = ?RULE_CAPACITY,
        skipped = ?rules.skipped,
        sys_enter_openat_detached = detached,
        "file-open sensor armed on LSM file_open (Tappa 10.9 step 1)"
    );
    // New homes, runtime directories (logins) and paths created since:
    // re-registered every minute, against what the maps really hold.
    let carveout = carveout.to_vec();
    let refresher = tokio::spawn(async move {
        let mut current = applied.in_maps;
        let mut depth_cap = DepthCapLog::default();
        let mut tick = tokio::time::interval(Duration::from_secs(60));
        tick.tick().await;
        loop {
            tick.tick().await;
            depth_cap.sample(&maps);
            if let Some(applied) = refresh(&mut maps, &current, &carveout) {
                report_open_rules(&mut health, &applied, audit_log.as_ref(), false);
                current = applied.in_maps;
            }
        }
    });
    sensor.register_pump_handle("open_sensor_rules", refresher);
}

/// External audit SNS-007: the outcome of a rule write, said once per
/// change — refused rules are an ERROR and one signed `subsystem_degraded`
/// (not a WARN every minute), a different count while degraded a WARN, the
/// recovery an INFO.
fn report_open_rules(
    health: &mut northnarrow_agent::sensors::open_sensor::RuleHealth,
    applied: &northnarrow_agent::sensors::open_sensor::Applied,
    audit_log: Option<&Arc<parking_lot::Mutex<northnarrow_agent::audit::AuditLog>>>,
    at_boot: bool,
) {
    use northnarrow_agent::sensors::open_sensor::RuleHealthChange;
    let first = applied.first_error.as_deref().unwrap_or("");
    match health.note(applied) {
        RuleHealthChange::Degraded => {
            error!(
                failed = applied.failed,
                written = applied.inserted,
                generation_failed = applied.generation_failed,
                first_error = %first,
                "file-open sensor: rules NOT all written — coverage is partial (the posture's own \
                 paths go first; the rest is retried every minute)"
            );
            attest_degraded_at(
                audit_log,
                &format!(
                    "file-open sensor rules partially written: {} refused, generation bump {}; \
                     first error: {first}",
                    applied.failed,
                    if applied.generation_failed {
                        "failed"
                    } else {
                        "done"
                    }
                ),
                at_boot,
            );
        }
        RuleHealthChange::Changed => warn!(
            failed = applied.failed,
            first_error = %first,
            "file-open sensor: rules still partially written"
        ),
        RuleHealthChange::Recovered => {
            info!("file-open sensor: every rule written again")
        }
        RuleHealthChange::Same => {}
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    if cli.build_features {
        let features = northnarrow_agent::audit::build_features();
        if features.is_empty() {
            println!("none");
        } else {
            println!("{}", features.join(","));
        }
        std::process::exit(0);
    }
    if let Some(nonce) = cli.telemetry_probe.as_deref() {
        std::process::exit(northnarrow_agent::telemetry_probe::run_child(nonce));
    }
    if let Some(path) = &cli.btf_check {
        std::process::exit(btf_check(path));
    }
    if cli.sensor_feasibility {
        #[cfg(feature = "test-privileged")]
        {
            std::process::exit(northnarrow_agent::sensor_feasibility::run());
        }
        #[cfg(not(feature = "test-privileged"))]
        {
            eprintln!("--sensor-feasibility exists only in lab builds (feature test-privileged)");
            std::process::exit(2);
        }
    }

    // Lab finding (external audit EBPF-001 work): when the log stream is
    // gone — journald@northnarrow stopped, at shutdown or by root — the
    // fmt layer reported the failed write with `eprintln!`, which panics
    // on the same broken pipe; with `panic = "abort"` the agent died at its
    // next log line, and five such deaths tripped the watchdog's ceiling.
    // A lost log line must never cost the agent.
    // External audit Wave 3 (journal line injection, lab PR 167): one event
    // is one journal line whatever it holds, with no colour codes under
    // journald (common::log_escape).
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .with_target(false)
        .with_ansi(common::log_escape::stdout_ansi())
        .with_writer(common::log_escape::stdout_one_line)
        .log_internal_errors(false)
        .init();

    info!("NorthNarrow agent starting...");

    // Boot preflight: prove the embedded eBPF half is real and intact
    // BEFORE doing any work. The build-time staleness guard
    // (agent/build.rs) refuses to embed a *stale* object; this refuses
    // to *start* on an *absent* (placeholder) or *corrupted* one. Fail
    // fast and loud — running without a matching kernel half would
    // silently disable every sensor, the anti-tamper LSM hooks, and
    // R011's PF_KTHREAD signal (the exact blindness that let R011
    // over-fire when a stale .o was embedded by a workspace build).
    northnarrow_agent::sensors::ebpf_object::preflight()
        .context("eBPF object boot preflight failed — refusing to start")?;

    // External audit NN-AUD-098: tracepoint fields left on their compiled
    // offset, attested once the audit log is open.
    let mut tracepoint_degraded: Option<String> = None;
    // Lab PR 164: an LSM hook argument whose position was not resolved,
    // attested once the audit log is open.
    let mut hook_args_degraded: Option<String> = None;

    // BUG-036: revalidate every compiled-in kernel struct offset against
    // the RUNNING kernel's BTF before attaching any program. aya-ebpf has
    // no CO-RE, so these offsets are baked into the eBPF half; if the
    // running kernel's layout differs, the LSM hooks and sensors read the
    // WRONG kernel memory — silently corrupting every decision. Fail
    // CLOSED + LOUD rather than attach hooks that read garbage. Exit 78
    // (EX_CONFIG) so the Restart=no agent unit lands in a VISIBLE `failed`
    // state; the watchdog's 5/60s restart ceiling bounds any respawn.
    match resolve_offsets() {
        ResolveOutcome::Resolved(r) => {
            if r.drifted.is_empty() {
                info!(
                    count = r.values.len(),
                    "BTF offsets resolved from the running kernel — all match the compiled-in values"
                );
            } else {
                info!(
                    count = r.values.len(),
                    drifted = r.drifted.len(),
                    "BTF offsets resolved from the running kernel — layout differs from the build \
                     kernel; the eBPF programs will read the resolved values (multi-kernel, level 1)"
                );
                for m in &r.drifted {
                    info!(
                        offset = m.name,
                        kernel_struct = m.struct_name,
                        compiled = m.expected,
                        runtime = ?m.actual,
                        "  offset resolved"
                    );
                }
            }
            for m in &r.absent {
                let effect = if m.struct_name.starts_with("btrfs_") {
                    "files on btrfs keep the superblock's device in their inode keys, so FIM \
                     and file protection do not match them (review 55)"
                } else if m.struct_name.starts_with("bpf_lsm_") {
                    // Lab PR 164: the programs reading it are not attached;
                    // a missing deny hook refuses the start unless
                    // NN_ANTI_TAMPER_ALLOW_DEGRADED=1.
                    northnarrow_agent::anti_tamper::btf_revalidate::hook_arg_effect(m.struct_name)
                } else {
                    "DNS QNAME decoding needs iov_iter.iter_type + ITER_UBUF/ITER_IOVEC"
                };
                warn!(
                    offset = m.name,
                    kernel_struct = m.struct_name,
                    detail = %m.detail,
                    effect,
                    "optional kernel field absent on this kernel — the dependent sensor path \
                     is disabled"
                );
            }
            info!(
                setattr_dentry_arg = ?r.setattr_dentry_arg(),
                setxattr_dentry_arg = ?r.hook_arg_position("INODE_SETXATTR_DENTRY_ARG"),
                removexattr_dentry_arg = ?r.hook_arg_position("INODE_REMOVEXATTR_DENTRY_ARG"),
                hook_args_checked = r.hook_args_checked,
                optional_deny_hooks = ?r.optional_deny_hooks,
                "LSM hook prototypes read from the running kernel — the fixed-position \
                 arguments are where the programs read them (lab PR 164)"
            );
            hook_args_degraded = r.hook_args_degraded_detail();
            for module in &r.modules_not_loaded {
                info!(
                    module,
                    "kernel module not loaded: no file on this host uses it, its offsets stay \
                     unset (btrfs: inode keys need no subvolume device, review 55)"
                );
            }
            // Tracepoint field offsets come from tracefs, not BTF: the
            // common header differs on vendor kernels (RHEL 9 shifts every
            // field by 4 — the exec sensor read an empty filename there).
            let mut r = r;
            let tp = resolve_tracepoint_fields();
            for (name, compiled, runtime) in &tp.drifted {
                info!(
                    offset = name,
                    compiled,
                    runtime,
                    "tracepoint field offset resolved from tracefs — differs from the build kernel"
                );
            }
            for (root, reason) in &tp.skipped_roots {
                warn!(
                    root = %root,
                    reason = %reason,
                    "tracefs root not used for tracepoint offsets — the filesystem there is not \
                     tracefs (external audit NN-AUD-098)"
                );
            }
            for (name, reason) in &tp.unresolved {
                warn!(
                    offset = name,
                    reason = %reason,
                    "tracepoint field offset NOT resolved — compiled-in value in use; on a kernel \
                     with a different tracepoint header the exec/open sensors read wrong bytes"
                );
            }
            tracepoint_degraded = tp.degraded_detail();
            r.values.extend(tp.values);
            publish_resolved(r);
        }
        ResolveOutcome::SkippedNoBtf { reason } => {
            warn!(
                reason,
                "BTF unavailable — offsets cannot be resolved. The LSM hooks require BTF \
                 to attach, so they will not attach this boot; whatever attaches uses the \
                 compiled-in offsets."
            );
        }
        ResolveOutcome::Refuse(reason) => {
            // sysexits.h EX_CONFIG: a non-zero code systemd surfaces as a
            // `failed` unit (Restart=no ⇒ no auto-restart loop).
            const EX_CONFIG: i32 = 78;
            match reason {
                RefuseReason::Drift(missing) => {
                    error!(
                        count = missing.len(),
                        "BTF offset resolution FAILED — refusing to start. The running \
                         kernel does not expose a field the eBPF programs read, or an LSM \
                         hook's prototype no longer has an argument where its program reads \
                         it; attaching LSM hooks would read the wrong kernel memory (BUG-036)."
                    );
                    for m in &missing {
                        error!(
                            offset = m.name,
                            kernel_struct = m.struct_name,
                            detail = %m.detail,
                            "  field unresolvable"
                        );
                    }
                    error!(
                        "Fail-closed safety gate (BUG-036): this kernel needs a field \
                         variant in common::btf_offsets (multi-kernel, level 2). Exiting {EX_CONFIG}."
                    );
                }
                RefuseReason::ParseError(e) => {
                    error!(
                        error = %e,
                        "BTF present but unparseable — refusing to start. Cannot resolve \
                         kernel offsets, and aya may still attach hooks with unverified \
                         offsets. Fail-closed (BUG-036). Exiting {EX_CONFIG}."
                    );
                }
            }
            std::process::exit(EX_CONFIG);
        }
    }

    // The COMBAT ladder holds a pidfd per attributed offender (external
    // audit CMB-004), up to its cap of 1 024, on top of the agent's own
    // ~140 descriptors: a soft limit of 1 024 (systemd's default) ran out
    // in the lab ("Too many open files" in the quarantine).
    match raise_nofile_rlimit() {
        Ok(n) => info!(open_files = n, "RLIMIT_NOFILE soft limit raised"),
        Err(e) => {
            warn!(error = %e, "failed to raise RLIMIT_NOFILE; a large COMBAT episode may exhaust descriptors")
        }
    }
    if let Err(e) = bump_memlock_rlimit() {
        warn!(error = %e, "failed to raise RLIMIT_MEMLOCK; eBPF maps may fail to allocate");
    }

    // External audit NN-AUD-108 / NN-AUD-109 / NN-AUD-174 (lab PR 160): the
    // chains compared with their anchored heads and manifest checkpoints,
    // before any writer opens them (O(1) per file). The findings are
    // attested once the audit log is open; a cut audit chain resets the
    // overlay rollback floor below.
    let heads_file = cli.resolved_chain_heads_file();
    let chain_targets = cli.chain_paths().targets();
    let mut boot_chains =
        match northnarrow_agent::chain_anchor::boot_verifying_key(&cli.signing_key_file) {
            Some(pk) => {
                northnarrow_agent::chain_anchor::boot_check(&chain_targets, &heads_file, &pk)
            }
            None => {
                info!("chain heads: no agent key yet (fresh install) — nothing anchored to check");
                northnarrow_agent::chain_anchor::BootCheck::default()
            }
        };
    // External audit LLMR-014: the signed overlays' rollback floor, from the
    // audit chain as this boot found it — verified, and read before the key
    // and the log below are bootstrapped (a log found missing must not look
    // like a fresh install).
    let rollback_floor = northnarrow_agent::config::overlay_floor::RollbackFloor::scan(
        &cli.audit_log_file,
        &cli.signing_key_file,
    );
    let rollback_floor = match boot_chains.audit_history_lost() {
        Some(why) => rollback_floor.reset_because(why),
        None => rollback_floor,
    };

    // External audit EBPF-015: the predecessor's pinned deny hooks refuse
    // a new entry in the agent's directories to a process not yet
    // registered — the files bootstrapped below when one is missing, a map
    // pin the eBPF load makes. Register in the pinned PROTECTED_PIDS first;
    // anti_tamper::attach does it again, with the stale-pid scan.
    match northnarrow_agent::anti_tamper::preregister_self(std::path::Path::new(
        northnarrow_agent::anti_tamper::DEFAULT_BPFFS_ROOT,
    )) {
        Ok(true) => info!(
            "anti-tamper: registered in the pinned PROTECTED_PIDS before the bootstraps \
             (a previous agent's hooks are attached)"
        ),
        Ok(false) => {}
        Err(e) => warn!(
            error = format!("{e:#}"),
            "anti-tamper: early registration in PROTECTED_PIDS failed — a file or map pin \
             this boot must recreate before the attach is refused by the previous hooks"
        ),
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
        // External audit EVD-001: on a restart the previous instance's
        // pinned hooks close the key to a process not yet registered (the
        // early registration above failed); the loads after the attach
        // read it.
        let refused = e
            .root_cause()
            .downcast_ref::<std::io::Error>()
            .is_some_and(|io| io.kind() == std::io::ErrorKind::PermissionDenied);
        if refused {
            info!(
                path = %cli.signing_key_file.display(),
                "agent signing key closed to this process until it is registered with the \
                 anti-tamper hooks — read after the attach"
            );
        } else {
            warn!(
                error = %e,
                path = %cli.signing_key_file.display(),
                "agent signing key bootstrap failed pre-attach — audit log will be \
                 unsigned this boot"
            );
        }
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
    // Tappa 9.0.a: bootstrap the detection chainlog pre-attach (creates
    // the detections/ sub-dir + a zero-byte active file) — same inode-
    // registration rationale as the FIM / canary logs.
    if let Err(e) =
        northnarrow_agent::anti_tamper::filesystem::bootstrap_detections_log(&cli.detections_file)
    {
        warn!(
            error = %e,
            path = %cli.detections_file.display(),
            "detections log bootstrap failed pre-attach — file will be lazily \
             created on first detection (and unprotected this boot)"
        );
    }
    // Tappa 9.0.c: bootstrap the status-event chainlog pre-attach (same
    // detections/ dir, sibling of detections.jsonl) — same inode-
    // registration rationale.
    if let Err(e) = northnarrow_agent::anti_tamper::filesystem::bootstrap_status_events_log(
        &cli.status_events_file,
    ) {
        warn!(
            error = %e,
            path = %cli.status_events_file.display(),
            "status-events log bootstrap failed pre-attach — file will be lazily \
             created on first triage (and unprotected this boot)"
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
    // Lab PR 160: the head anchor, for the same inode-registration reason.
    if let Err(e) = northnarrow_agent::anti_tamper::filesystem::bootstrap_chain_heads(&heads_file) {
        warn!(
            error = %e,
            path = %heads_file.display(),
            "chain heads bootstrap failed pre-attach — the anchor is created at its first \
             write (and protected from the next start)"
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
    let boot_agent_id = agent_id::load_or_bootstrap(&cli.agent_id_file)
        .map_err(|e| {
            warn!(
                error = %e,
                path = %cli.agent_id_file.display(),
                "pre-attach agent_id bootstrap failed — post-attach re-read will \
                 surface the same error and fall back to zero UUID"
            );
            e
        })
        .unwrap_or([0u8; 16]);

    // Tappa 10.8 — signed operator overlays: every `*.local` below is read
    // only if an admin key with `config-manage` signed its exact content
    // (`<overlay>.sig`); otherwise the shipped defaults are used for that
    // list and the refusal is recorded once the audit log is open.
    let overlay_gate = Arc::new(northnarrow_agent::config::overlay_auth::OverlayGate::new(
        &cli.admin_pub,
        boot_agent_id,
        rollback_floor,
    ));
    use common::wire::admin_signed_payload::OverlayKind;

    // Process-lineage cache shared by the posture triggers and the FIM
    // rules' package-manager carve-out (review 49): "does this writer
    // descend from dpkg/rpm/dnf?". Fed from Event::ProcessSpawn by the
    // posture trigger detector; reads /proc on a cache miss.
    // External audit POS-003: every cached exec checked against the
    // process its pid names now. External audit NETR-008: built before
    // the sensors so the network pumps name each flow's image with it.
    let lineage = AuthSessionTracker::for_host();

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
        lineage: lineage.clone(),
    };
    // Tappa 10.9 step 2: which exec sensor the multiplexer attaches.
    northnarrow_agent::sensors::exe_identity::want_lsm(cli.exec_sensor == ExecSensor::Lsm);
    // Review 69: `sys_enter_openat` emits from the start only in tracepoint
    // mode; otherwise `start_open_sensor` decides.
    northnarrow_agent::sensors::open_sensor::want_tracepoint(
        cli.file_open_sensor == FileOpenSensor::Tracepoint,
    );
    // Tappa 10.9 step 3: which DNS sensor the multiplexer attaches.
    northnarrow_agent::sensors::dns_sensor::want_skb(cli.dns_sensor == DnsSensor::Skb);
    // External audit DEP-006: the previous boot's program-id list goes before
    // this boot loads anything — its programs are replaced now, and a list
    // that cannot be rewritten must not outlive them (the scripts then fall
    // back to their host-wide wait).
    let own_prog_ids_file = own_prog_ids_file(&cli);
    if let Some(path) = own_prog_ids_file.as_deref() {
        match std::fs::remove_file(path) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => {
                warn!(error = %e, path = %path.display(), "stale BPF program-id list not removed")
            }
        }
    }
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
    // Watchdog W6: the watchdog is protected too. External audit
    // MAIN-001: never on the word of `/run/northnarrow/watchdog.pid` —
    // membership also lets a pid signal the agent and pass every inode
    // deny hook. The watchdog's own entry (it registers itself) is kept
    // below while it runs the installed watchdog binary, and the refresh
    // task (`spawn_watchdog_exempt_refresh`, first round right after
    // boot) registers a pid it has verified by `/proc/<pid>/exe`.
    // External audit ATP-002: entries a previous agent left in the pinned
    // map are kept only while they run the agent's or the watchdog's
    // executable, no longer while they merely call themselves so.
    let agent_pid = std::process::id();
    let keep: Vec<northnarrow_agent::anti_tamper::ExeIdentity> = [
        northnarrow_agent::anti_tamper::ExeIdentity::of_file(std::path::Path::new(
            "/proc/self/exe",
        )),
        northnarrow_agent::anti_tamper::ExeIdentity::of_file(&cli.resolved_watchdog_exe()),
    ]
    .into_iter()
    .flatten()
    .collect();
    let pids = vec![agent_pid];
    // Audit `ebpf-lsm-1`: a deny-hook shortfall is fail-closed (the
    // escape hatch is NN_ANTI_TAMPER_ALLOW_DEGRADED=1, handled inside
    // anti_tamper::attach). A kernel without BPF-LSM is NOT an error
    // here — attach returns Ok after logging that anti-tamper is off.
    sensor.attach_anti_tamper(&pids, &keep).with_context(|| {
        format!(
            "anti-tamper setup failed (agent_pid={agent_pid}) — \
                 refusing to start with a silently-absent protection"
        )
    })?;
    // External audit DEP-006: the ids install.sh / uninstall.sh wait for.
    record_own_prog_ids(own_prog_ids_file.as_deref(), sensor.ebpf_mut());

    // Tappa 10 N9 — load operator-curated netflow blocklists from
    // disk + thread them into the decision engine. Load failures
    // degrade gracefully (empty list, like N6 net_rules_empty),
    // so a missing/broken file never blocks agent boot. The
    // production deploy bootstrap (N8 install.sh) ships the v1
    // defaults; missing .local overlay is the normal case for a
    // host without operator-specific block additions.
    // External audit LLMR-013: every loader gets the overlay's text as the
    // gate verified it (one read), never a path to read again; LLMR-016: a
    // `.v1` that cannot be read gives way to the copy built into the agent,
    // recorded.
    let netflow_blocklist = Arc::new(
        NetBlocklist::load(
            &cli.netflow_blocklist_v1,
            &overlay_gate.verified(OverlayKind::NetflowBlocklist, &cli.netflow_blocklist_local),
        )
        .unwrap_or_else(|e| {
            warn!(
                error = %e,
                v1 = %cli.netflow_blocklist_v1.display(),
                local = %cli.netflow_blocklist_local.display(),
                "netflow blocklist load failed — booting with empty blocklist"
            );
            NetBlocklist::empty()
        }),
    );
    report_builtin_defaults(
        &overlay_gate,
        "netflow-blocklist",
        &cli.netflow_blocklist_v1,
        netflow_blocklist.defaults(),
    );
    let ja3_blocklist = Arc::new(
        Ja3Blocklist::load(
            &cli.netflow_ja3_blocklist_v1,
            &overlay_gate.verified(
                OverlayKind::NetflowJa3Blocklist,
                &cli.netflow_ja3_blocklist_local,
            ),
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
    report_builtin_defaults(
        &overlay_gate,
        "netflow-ja3-blocklist",
        &cli.netflow_ja3_blocklist_v1,
        ja3_blocklist.defaults(),
    );
    // External audit NET-009 (BUG-025): no sensor produces TLS
    // fingerprints, so a JA3 list with entries protects nothing. Said at
    // boot, and in the signed chain once the audit log is open (below).
    northnarrow_agent::net::blocklist::note_ja3_entries(ja3_blocklist.len());
    let ja3_gap = northnarrow_agent::net::blocklist::ja3_coverage_gap(
        ja3_blocklist.len(),
        northnarrow_agent::net::blocklist::TLS_FINGERPRINT_PRODUCER,
    );
    if let Some(gap) = &ja3_gap {
        error!(
            v1 = %cli.netflow_ja3_blocklist_v1.display(),
            local = %cli.netflow_ja3_blocklist_local.display(),
            "{gap}"
        );
    }
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
            northnarrow_agent::config::comm_allowlist::NETFLOW_COMM_ALLOWLIST_SHIPPED,
            &overlay_gate.verified(
                OverlayKind::NetflowCommAllowlist,
                &cli.netflow_comm_allowlist_local,
            ),
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
    report_builtin_defaults(
        &overlay_gate,
        "netflow-comm-allowlist",
        &cli.netflow_comm_allowlist_v1,
        netflow_comm_allowlist.defaults(),
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
            northnarrow_agent::config::comm_allowlist::PROCESS_COMM_ALLOWLIST_SHIPPED,
            &overlay_gate.verified(
                OverlayKind::ProcessCommAllowlist,
                &cli.process_comm_allowlist_local,
            ),
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
    report_builtin_defaults(
        &overlay_gate,
        "process-comm-allowlist",
        &cli.process_comm_allowlist_v1,
        process_allowlist.defaults(),
    );

    // FIM-009 self-upgrade (§15.1): construct the trusted-installer
    // override BEFORE the engine so the NN-L-FIM-009 rule can hold a read
    // handle (wired next commit). The bpffs maps were pinned +
    // boot-zeroed by the sensor multiplexer's anti_tamper::attach above;
    // the audit-chain writer is late-bound below once the AuditLog opens.
    let installer_override =
        northnarrow_agent::anti_tamper::trusted_installer::TrustedInstallerOverride::boot(
            northnarrow_agent::anti_tamper::prepare_pin_root().map(|p| p.to_path_buf()),
            None,
        );

    // External audit NET-019: the chain rules' correlation store, shared
    // with the netflow limiter (a process with a chain precursor always
    // has its flows evaluated).
    let chain_store = Arc::new(parking_lot::Mutex::new(
        northnarrow_agent::decision::correlation::CorrelationStore::new(),
    ));
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
        // FP-3: the SAME DnsCache the DnsQuery pump feeds — NN-L-NET-004/
        // -014 read its reverse index to back-correlate a forwarded leg
        // to the originating process instead of the stub resolver.
        Arc::clone(&dns_cache),
        // FIM-009 self-upgrade (§15.1): the NN-L-FIM-009 rule reads this
        // override; the admin dispatcher arms it on a signed grant.
        Arc::clone(&installer_override),
        lineage.clone(),
        // External audit DEC-005: the built-in readers of whole trees plus
        // the operator's signed canary-readers.local.
        northnarrow_agent::canary::readers::CanaryReaders::load(
            &overlay_gate.verified(
                OverlayKind::CanaryReaders,
                std::path::Path::new(northnarrow_agent::canary::readers::CANARY_READERS_LOCAL),
            ),
            lineage.clone(),
        ),
        Arc::clone(&chain_store),
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
    // sank three external-resolution strategies in the retired #2b
    // harness, docs/verify-2b.sh (989c292 pgrep -P / -x, 6e746c6
    // /proc/*/exe diff): the sudo+exec
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

    // BUG-033 detect-only: resolve the one no-enforcement gate from the
    // CLI flag OR-ed with the env inputs (`from_env` reads
    // `NN_DETECT_ONLY` / legacy `NORTHNARROW_DRY_RUN`). The resolved
    // value drives BOTH the response Executor (via the config) and the
    // COMBAT engage-hook below, so there is exactly one switch.
    let mut exec_cfg = ExecutorConfig::from_env();
    if cli.detect_only {
        exec_cfg.dry_run = true;
    }
    let detect_only = exec_cfg.dry_run;
    // External audit MAIN-008: the signed agent_boot entry says where
    // detect-only came from.
    let detect_only_source: Option<String> = if cli.detect_only {
        Some("--detect-only".to_string())
    } else {
        northnarrow_agent::response::config::detect_only_env()
            .map(|(name, v)| format!("{name}={v}"))
    };
    // External audit CMB-006: an older agent's host-wide nftables blackout
    // (no carve-out, no release, no status) is removed before anything
    // else; host-wide isolation is the COMBAT ladder's alone.
    let legacy_isolation_removed =
        match northnarrow_agent::response::network_isolation::retire_legacy(&exec_cfg) {
            Ok(removed) => {
                if removed {
                    warn!(
                        "removed the host-wide nftables isolation an older agent left \
                         (external audit CMB-006): host-wide isolation is the COMBAT ladder's"
                    );
                }
                removed
            }
            Err(e) => {
                error!(
                    error = %e,
                    "an older agent's host-wide nftables isolation could not be removed — \
                     `nft delete chain inet northnarrow isolation_output` (and isolation_input) \
                     from the console"
                );
                false
            }
        };
    let executor = Executor::with_config(exec_cfg);
    // External audit CMB-019: a kill cgroup an earlier agent left in the
    // middle of a kill (its tree frozen) is finished and removed.
    if !detect_only {
        let removed = northnarrow_agent::response::kill::reap_stale_kill_cgroups(
            &executor.config().blocked_cgroup_dir(),
        );
        if removed > 0 {
            warn!(
                removed,
                "kill cgroups left by an earlier agent were finished and removed"
            );
        }
    }
    // External audit CMB-010: the processes an earlier run moved into the
    // blocked / throttled scopes — the gone ones dropped from the record,
    // the still-contained ones reported (no automatic release after a
    // restart).
    let contained = northnarrow_agent::response::containment::reconcile(executor.config());
    if !contained.still_contained.is_empty() {
        warn!(
            count = contained.still_contained.len(),
            "processes contained by an earlier run are still in the blocked / throttled scopes"
        );
    }
    if detect_only {
        warn!(
            "DETECT-ONLY mode active (--detect-only / NN_DETECT_ONLY / NORTHNARROW_DRY_RUN): \
             detection + posture run normally, but NO response action or COMBAT network \
             isolation will touch the system — verdicts are logged as \"would execute\" only"
        );
    }
    // Capability preflight: the systemd CapabilityBoundingSet is the
    // hard ceiling on what this root process can do. Without CAP_KILL,
    // kill(2) only reaches uid-0 targets, so every KillProcess verdict
    // against a user-owned process would EPERM — in enforcement mode
    // that is a refuse-to-start, not a warning. The other caps only
    // degrade a secondary surface and are reported for the journal.
    match northnarrow_agent::response::caps_preflight::current_missing() {
        Some(missing) if !missing.is_empty() => {
            for name in &missing.names {
                warn!(
                    cap = name,
                    breaks = northnarrow_agent::response::caps_preflight::impact_of(name),
                    "capability missing from effective set"
                );
            }
            if missing.kill_missing && !detect_only {
                anyhow::bail!(
                    "CAP_KILL missing from the effective capability set: KillProcess would \
                     EPERM on every non-root target. Add CAP_KILL to CapabilityBoundingSet= \
                     in northnarrow-agent.service, or start with --detect-only."
                );
            }
        }
        Some(_) => debug!("capability preflight: all required caps present"),
        None => warn!("capability preflight: /proc/self/status unreadable; cannot verify caps"),
    }

    // Host hardening (Tappa 10.8): the anti-tamper holds only while root
    // cannot rewrite the kernel at runtime. One WARN per missing setting,
    // with the fix; `nn-admin host-check` prints the same table.
    {
        let checks = northnarrow_agent::host_hardening::run();
        let warns = northnarrow_agent::host_hardening::warn_count(&checks);
        for c in &checks {
            if c.status == northnarrow_agent::host_hardening::Status::Warn {
                warn!(check = c.id, value = %c.value, fix = c.fix, "host hardening: {}", c.name);
            }
        }
        info!(
            checks = checks.len(),
            warnings = warns,
            "host hardening checks done (nn-admin host-check for the table)"
        );
    }
    // Lab follow-up (lab PR 165): without `nft` the per-process outbound
    // block cannot work. Said once here, and in the signed chain once the
    // audit log is open (below), instead of only at the first block.
    let nft_gap = northnarrow_agent::response::block_outbound::nft_gap_at_boot();
    if let Some(gap) = &nft_gap {
        error!("{gap}");
    }
    info!(
        own_pid = executor.own_pid(),
        protected = executor.protected().len(),
        detect_only,
        "response executor ready (KillProcess + KillProcessTree active)"
    );

    // External audit XAI-001/XAI-009: a RAG canary refused at the ADE load
    // (corpus missing or altered) is recorded once the audit log is open.
    let mut rag_refused: Option<String> = None;
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
        // Beta Step 2b: pre-flight RAM guard. Loading the GGUF peaks
        // ~7 GB RSS; on a VM without that headroom the load OOM-crashes
        // the agent. Refuse the load when MemAvailable can't cover the
        // model size + runtime slack and degrade to detection-only,
        // mirroring the agent's warn-and-continue for an unusable
        // bpffs. (Step 2a's cgroup ceiling is the backstop; this keeps
        // us from ever reaching it on an undersized host.)
        match check_ade_memory(&cfg.model_path) {
            AdeMemCheck::Insufficient {
                available_bytes,
                required_bytes,
            } => {
                warn!(
                    available_mib = available_bytes / (1024 * 1024),
                    required_mib = required_bytes / (1024 * 1024),
                    model = %cfg.model_path.display(),
                    "insufficient free memory to load the ADE model — running \
                     detection-only (rule engine). Run on a host with more RAM, \
                     or pass --no-ade to make this explicit."
                );
                None
            }
            check => {
                if let AdeMemCheck::Unknown { reason } = &check {
                    warn!(%reason, "ADE memory pre-check inconclusive; attempting load anyway");
                }
                load_ade_engine(cfg, &mut rag_refused).await
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
        Ok(i) => Some(Arc::new(
            i.with_allow_cidrs_path(cli.combat_allow_cidrs.clone())
                .with_rules_v6(cli.combat_rules_v6.clone())
                // External audit ATP-001 / DEP-003: the COMBAT files are
                // applied only as shipped or admin-signed.
                .with_overlay_gate(Arc::clone(&overlay_gate)),
        )),
        Err(e) => {
            // ERROR, not WARN: besides losing isolation, no isolator means
            // the admin socket below is never started — nn-admin status /
            // unlock / detections all fail and the watchdog's STATUS ping
            // trips its stuck-recovery restart loop every 30 s.
            error!(
                error = %e,
                path = %cli.combat_rules.display(),
                "combat ruleset missing or invalid: COMBAT entry will NOT engage network \
                 isolation AND the admin socket will NOT be started (nn-admin unusable, \
                 watchdog STATUS ping will fail) — install combat-rules.v4 (configs/) and restart"
            );
            None
        }
    };
    // External audit ATP-014 (NN-AUD-262): the files COMBAT's isolation
    // runs — looked up in the system directories only, never on PATH —
    // named once at boot, or why the isolation could not run.
    if let Some(iso) = isolator.as_ref() {
        match iso.binaries() {
            Ok(files) => info!(binaries = %files, "COMBAT isolation binaries (system directories)"),
            Err(why) => error!(
                error = %why,
                "COMBAT isolation cannot run: no trusted iptables in /usr/sbin, /usr/bin, /sbin or \
                 /bin — a STAGE 3 isolation will fail (install iptables; a copy in /usr/local is \
                 not used)"
            ),
        }
    }

    // The COMBAT graduated-response ladder is constructed once agent_id
    // + the audit log are available (further down). The posture combat
    // hooks reference it through this slot, so an admin-forced COMBAT
    // engages the same ladder as a detector-driven one. The slot is set
    // before the event loop / admin socket start — always populated by
    // the time any COMBAT transition can fire the hooks.
    let ladder_slot: Arc<std::sync::OnceLock<Arc<northnarrow_agent::combat::CombatLadder>>> =
        Arc::new(std::sync::OnceLock::new());

    // Reaching COMBAT now means "enter active-response mode", NOT
    // "isolate". This entry hook engages the graduated ladder at STAGE 1
    // INVESTIGATE (network stays UP); the ladder decides if/when isolation
    // (STAGE 3, last resort) is warranted, honours detect-only internally,
    // and emits the per-stage signed audit trail. It is wired into BOTH
    // the prod (isolator) and dev (no-isolator) posture branches so an
    // admin-forced COMBAT engages the same ladder either way; the detector
    // path additionally feeds the offending PID + firing trigger via
    // `process_event` (an idempotent merge).
    let engage_hook: CombatEntryHook = {
        let ladder_for_entry = Arc::clone(&ladder_slot);
        Arc::new(move || {
            if let Some(ladder) = ladder_for_entry.get() {
                ladder.engage(None, None, Instant::now());
            }
        })
    };

    let exempt = ExemptPids::with_agent(std::process::id());
    // Tappa 10.9 step 1: the file-open sensor applies the operator's
    // mass-write carve-outs in the kernel (same signed overlay, read and
    // verified once for both — external audit LLMR-013).
    let mass_write_overlay = overlay_gate.verified(
        OverlayKind::MassWriteCarveout,
        std::path::Path::new(
            northnarrow_agent::posture::mass_write_overlay::DEFAULT_MASS_WRITE_OVERLAY,
        ),
    );
    let open_sensor_carveout =
        northnarrow_agent::posture::mass_write_overlay::load_mass_write_carveout_extras(
            &mass_write_overlay,
        );
    let posture = if let Some(iso) = isolator.as_ref() {
        // T7.13 (Beta Step 5): the auth-lineage tracker shared with
        // the posture trigger detector. Reads /proc on cache miss;
        // populated live from Event::ProcessSpawn inside
        // TriggerDetector::detect. The dev (no-iptables) branch uses
        // PostureMachine::new() which already constructs a default
        // tracker internally, so this clone is only needed here.
        let auth_tracker = lineage.clone();
        let iso_release = Arc::clone(iso);
        let ladder_for_release = Arc::clone(&ladder_slot);
        let release_hook: CombatReleaseHook = Arc::new(move |token: UnlockToken| {
            // Admin released COMBAT: stand the ladder down (clears the
            // episode + lifts the surgical per-PID soft-egress blocks),
            // THEN tear down any full isolation STAGE 3 had engaged.
            // External audit CMB-012: after every step queued before the
            // stand-down has run, so an ISOLATE taken just before the
            // unlock cannot land after the release.
            if let Some(ladder) = ladder_for_release.get() {
                ladder.stand_down_and_wait(Instant::now(), LADDER_RELEASE_WAIT);
            }
            if let Err(e) = iso_release.release(token) {
                tracing::error!(
                    error = %e,
                    "admin release failed; iptables state may need manual cleanup"
                );
            }
        });
        // Exempt the NorthNarrow stack's own PIDs from posture
        // triggers. The agent's own PID is fixed here; the watchdog's
        // verified PID is filled in by the refresh task spawned below.
        // Without this, the agent's FIM drift logging self-trips the
        // mass-write heuristic into COMBAT at boot, and the watchdog's
        // startup /proc scan trips it too (2026-05-22 sshd-reset
        // diagnosis).
        //
        // T7.13 — also pass the auth-lineage tracker so sudo-mediated
        // PIDs are exempt from sensitive_file_access and the
        // mass-write arm of confirmed_intrusion. Every other
        // COMBAT-tier trigger fires unchanged.
        //
        // BUG-017 P-8 — load the operator-supplemental mass-write
        // path-prefix carve-out from
        // /etc/northnarrow/mass-write-carveout.local. Missing file =
        // empty list (no extra exemptions; hardcoded
        // MASS_WRITE_CARVEOUT_PREFIXES still applies). The list is
        // path-prefix-based (e.g. "/home/<user>/.claude/" for dev
        // tooling), additive on top of the hardcoded kernel-RPC
        // pseudo-FS prefixes. See SECURITY note in
        // mass_write_overlay.rs — DO NOT add /home, /var, /tmp
        // wholesale.
        let mass_write_extras =
            northnarrow_agent::posture::mass_write_overlay::load_mass_write_carveout_extras(
                &mass_write_overlay,
            );
        // BUG-032 — escalation allowlist (count-filter for exfil/lateral).
        // Missing file = empty (fail-secure). Loaded once at boot;
        // reload-on-restart for beta.
        let escalation_allow =
            northnarrow_agent::posture::escalation_allow::EscalationAllowList::load(
                &overlay_gate.verified(
                    OverlayKind::EscalationAllow,
                    std::path::Path::new(
                        northnarrow_agent::posture::escalation_allow::DEFAULT_ESCALATION_ALLOW,
                    ),
                ),
            );
        if !escalation_allow.is_empty() {
            info!(
                entries = escalation_allow.len(),
                "escalation allowlist loaded — count-filter for exfil/lateral (BUG-032)"
            );
        }
        PostureMachine::new_with_hooks_and_exempt_and_auth_and_extras(
            engage_hook,
            release_hook,
            exempt.clone(),
            auth_tracker,
            mass_write_extras,
            escalation_allow,
        )
    } else {
        // Dev / no-isolator build: still wire the ladder hooks so a
        // (detector- or admin-forced) COMBAT engages the same graduated
        // ladder as production. The ladder's actuator finds no isolator,
        // so STAGE 3 degrades to a loud warning instead of an iptables
        // DROP — but INVESTIGATE + NEUTRALIZE still run.
        let ladder_for_release = Arc::clone(&ladder_slot);
        let release_hook: CombatReleaseHook = Arc::new(move |token: UnlockToken| {
            if let Some(ladder) = ladder_for_release.get() {
                ladder.stand_down(Instant::now());
            }
            // No isolator to release in this build; consume the token.
            let _ = token;
        });
        // Same defaults as `new_with_hooks`, but on the shared lineage
        // cache so the FIM package-manager carve-out is fed here too.
        PostureMachine::new_with_hooks_and_exempt_and_auth(
            engage_hook,
            release_hook,
            ExemptPids::default(),
            lineage.clone(),
        )
    };
    // Lab PR 162: inside the trusted-installer window a control-surface
    // tamper (NN-L-FIM-024) does not raise the posture; the rule still acts.
    posture.set_installer_window(Arc::clone(&installer_override));
    info!("posture state machine initialized (state: OBSERVING)");

    // Beta Step 3: keep the watchdog PID exemption fresh. The watchdog
    // starts *after* the agent and may be restarted (systemd
    // Restart=on-failure), so we re-resolve its PID from the pidfile
    // and re-verify /proc/<pid>/exe every 30 s. Verification failure
    // (PID reuse, substituted binary, dead PID) clears the exemption —
    // fail toward over-triggering, never under-triggering. Only wired
    // when the posture machine actually carries the exemption (the
    // dev-mode `PostureMachine::new()` branch has none).
    if isolator.is_some() {
        spawn_watchdog_exempt_refresh(
            exempt.clone(),
            cli.watchdog_pidfile.clone(),
            cli.resolved_watchdog_exe(),
        );
    }
    // External audit EBPF-001: PID 1 may signal the agent at the very end
    // of a shutdown only while it runs the `systemd-shutdown` the hook
    // knows; follow a systemd upgrade that replaces it.
    spawn_shutdown_exe_refresh();

    // Beta Step 4a: reconcile a stale COMBAT chain left by a crash.
    // The agent always boots into OBSERVING, so if the
    // NORTHNARROW_COMBAT chain is already present the previous run died
    // mid-COMBAT and the orphaned iptables chain is now isolating the
    // host with no live posture state behind it (the B3 split-brain).
    // Tear it down and audit it. If an attack is still under way the
    // posture machine will re-engage COMBAT within seconds; an operator
    // can also force it via the admin socket.
    // External audit MAIN-013 (lab PR 180): the outcome is signed once the
    // audit log is open (below); the unsigned jsonl line stays.
    let mut stale_combat: Option<northnarrow_agent::combat::reconcile::StaleChain> = None;
    if let Some(iso) = isolator.as_ref() {
        if posture.current_kind() == PostureKind::Observing {
            match iso.reconcile_stale_chain() {
                Ok(outcome) if outcome.chain_existed => {
                    warn!(
                        rules_removed = outcome.rules_removed,
                        "stale COMBAT chain detected at boot — torn down (likely crash-orphaned). \
                         Re-engage via the admin socket if the threat is still active."
                    );
                    audit_combat_reconcile(outcome.rules_removed);
                    stale_combat =
                        Some(northnarrow_agent::combat::reconcile::StaleChain::TornDown {
                            rules_removed: outcome.rules_removed,
                        });
                }
                Ok(_) => debug!("no stale COMBAT chain at boot (clean)"),
                Err(e) => {
                    warn!(error = %e, "stale COMBAT chain reconcile failed; manual iptables cleanup may be needed");
                    // Without a trusted iptables there is nothing to probe
                    // with (the ERROR above names it): not a failed teardown.
                    if iso.binaries().is_ok() {
                        stale_combat =
                            Some(northnarrow_agent::combat::reconcile::StaleChain::Failed {
                                error: format!("{e:#}"),
                            });
                    }
                }
            }
        }
    }

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

    // Supply chain, runtime half: the binaries running now must be the
    // ones install.sh verified and recorded. Checked before the audit
    // log opens so the agent_boot entry carries the result.
    let integrity = {
        use northnarrow_agent::install_manifest::{
            self, BootHistory, IntegrityOutcome, ALLOW_UNVERIFIED_ENV,
        };
        let own_exe = std::env::current_exe().unwrap_or_else(|_| PathBuf::from("/proc/self/exe"));
        let outcome = install_manifest::check(
            &cli.install_manifest,
            &own_exe,
            northnarrow_agent::sensors::ebpf_object::OBJECT_SHA,
        );
        // External audit DEP-009: a missing manifest is a removal once a
        // boot of this install verified against it — the signed chain is
        // the sentinel, read (only in that case) before the decision.
        let history = match &outcome {
            IntegrityOutcome::NoManifest { .. } => {
                match northnarrow_agent::audit::verified_boot_recorded(&cli.audit_log_file) {
                    Ok(true) => BootHistory::VerifiedBefore,
                    Ok(false) => BootHistory::NeverVerified,
                    Err(e) => {
                        error!(
                            error = format!("{e:#}"),
                            path = %cli.audit_log_file.display(),
                            "audit chain unreadable — cannot show that this install never had a \
                             verified boot; the missing install manifest counts as removed"
                        );
                        BootHistory::Unknown
                    }
                }
            }
            _ => BootHistory::NeverVerified,
        };
        match &outcome {
            IntegrityOutcome::Verified {
                provenance,
                checked,
            } => info!(
                provenance,
                checked,
                manifest = %cli.install_manifest.display(),
                "binary integrity verified against the install manifest"
            ),
            IntegrityOutcome::NoManifest { path } if history == BootHistory::NeverVerified => {
                info!(
                    path = %path.display(),
                    "no install manifest and no verified boot in the audit chain — not installed \
                     by install.sh (a developer run): binaries not re-verified at boot"
                )
            }
            IntegrityOutcome::NoManifest { path } => error!(
                path = %path.display(),
                "install manifest MISSING after a verified boot of this install — it was removed \
                 (install.sh writes it on every install, source trees included)"
            ),
            IntegrityOutcome::NotApplicable { own_exe, bin_dir } => info!(
                own_exe = %own_exe.display(),
                bin_dir,
                "install manifest describes another copy (this binary runs outside bin_dir) — \
                 not compared"
            ),
            IntegrityOutcome::Unreadable { path, reason } => error!(
                path = %path.display(),
                reason,
                "install manifest unreadable — it sits under inode_protect, a broken one is a signal"
            ),
            IntegrityOutcome::Mismatch {
                provenance,
                mismatches,
            } => {
                for m in mismatches {
                    error!(
                        file = %m.name,
                        expected = %m.expected,
                        actual = %m.actual,
                        provenance,
                        "binary integrity MISMATCH — the running file is not the one install.sh \
                         verified and recorded"
                    );
                }
            }
        }
        let allow = std::env::var(ALLOW_UNVERIFIED_ENV).ok();
        if outcome.is_fatal(allow.as_deref(), history) {
            error!(
                "refusing to start: install-manifest check = {} (set {ALLOW_UNVERIFIED_ENV}=1 to \
                 override on a dev host; re-run install.sh to restore a verified install)",
                outcome.label()
            );
            // Leave the refusal in the signed audit chain before exiting.
            let detail = match &outcome {
                IntegrityOutcome::Mismatch { mismatches, .. } => mismatches
                    .iter()
                    .map(|m| format!("{}: expected {} got {}", m.name, m.expected, m.actual))
                    .collect::<Vec<_>>()
                    .join("; "),
                IntegrityOutcome::Unreadable { reason, .. } => reason.clone(),
                IntegrityOutcome::NoManifest { path } => format!(
                    "{} missing ({}) — re-run install.sh",
                    path.display(),
                    if history == BootHistory::VerifiedBefore {
                        "removed after a verified boot of this install"
                    } else {
                        "audit chain unreadable"
                    }
                ),
                _ => String::new(),
            };
            if let Ok(key) =
                northnarrow_agent::audit::AgentSigningKey::load_or_bootstrap(&cli.signing_key_file)
            {
                if let Ok(mut log) =
                    northnarrow_agent::audit::AuditLog::open(&cli.audit_log_file, key, agent_id)
                {
                    overlay_gate.attest_floor(&mut log);
                    match log.boot_refused(outcome.label(), outcome.provenance(), &detail) {
                        Ok(e) => {
                            info!(entry_hash = %e.entry_hash, "refused boot recorded in the audit chain")
                        }
                        Err(e) => error!(
                            error = format!("{e:#}"),
                            "could not record the refused boot in the audit chain"
                        ),
                    }
                }
            }
            std::process::exit(78);
        } else if matches!(
            outcome,
            IntegrityOutcome::Mismatch { .. } | IntegrityOutcome::Unreadable { .. }
        ) || (matches!(outcome, IntegrityOutcome::NoManifest { .. })
            && history != BootHistory::NeverVerified)
        {
            warn!(
                "install-manifest check = {} but {ALLOW_UNVERIFIED_ENV}=1 — continuing (dev override)",
                outcome.label()
            );
        }
        outcome
    };

    // ── Shared audit log + COMBAT graduated-response ladder ─────────
    //
    // The signed, hash-chained audit log is opened ONCE here (now that
    // agent_id is ready) and shared by both the COMBAT ladder (per-stage
    // signed transitions) and the admin socket (admin-op audit). A `None`
    // audit log (open/key failure) degrades to log-only, exactly as the
    // admin-op path already tolerates.
    let mut chain_anchor: Option<Arc<parking_lot::Mutex<northnarrow_agent::chain_anchor::Anchor>>> =
        None;
    let audit_log: Option<Arc<parking_lot::Mutex<northnarrow_agent::audit::AuditLog>>> =
        match northnarrow_agent::audit::AgentSigningKey::load_or_bootstrap(&cli.signing_key_file) {
            Ok(key) => {
                match northnarrow_agent::audit::AuditLog::open(&cli.audit_log_file, key, agent_id) {
                    // Boot write probe (etc-readonly-audit-1): a signed
                    // `agent_boot` entry proves the chain is writable NOW
                    // instead of failing silently at the first COMBAT
                    // transition. Fail-closed in enforcement mode.
                    Ok(mut log) => {
                        // Lab PR 160: anchor the heads as this boot found
                        // them before it appends anything (the snapshot is on
                        // disk before the first numbered row of an upgrade).
                        // A row-number break in the audit chain counts as
                        // lost history there too (ATP-004 fails closed).
                        for f in log.take_open_findings(&cli.audit_log_file) {
                            boot_chains.findings.push(f);
                        }
                        chain_anchor = start_chain_anchor(
                            &cli,
                            &heads_file,
                            &chain_targets,
                            &mut boot_chains,
                            agent_id,
                            &log,
                        );
                        // External audit LLMR-014: the rollback floor's
                        // reset / anchor come first in this boot's entries.
                        overlay_gate.attest_floor(&mut log);
                        // Lab PR 160: what the chain checks found, then the
                        // one-time record of where numbering starts.
                        for f in &boot_chains.findings {
                            f.attest(Some(&mut log));
                        }
                        if let Some(marker) =
                            chain_anchor.as_ref().and_then(|a| a.lock().take_marker())
                        {
                            if let Err(e) = log.append(marker) {
                                warn!(error = %format!("{e:#}"), "chain heads: start not recorded");
                            }
                        }
                        match log.boot_probe(
                            detect_only_source.as_deref(),
                            integrity.label(),
                            integrity.provenance(),
                        ) {
                            Ok(entry) => {
                                info!(
                                    path = %cli.audit_log_file.display(),
                                    entry_hash = %entry.entry_hash,
                                    "audit log writable — agent_boot entry appended"
                                );
                                if let northnarrow_agent::audit::PreviousRun::Abrupt {
                                    booted_at,
                                    last_entry_at,
                                } = log.previous_run()
                                {
                                    warn!(
                                        booted_at = %booted_at,
                                        last_entry_at = %last_entry_at,
                                        "PREVIOUS RUN ENDED ABRUPTLY — the agent that booted then never \
                                         wrote agent_stop: SIGKILL (systemctl kill, cgroup.kill), OOM, \
                                         crash or power loss; recorded in this boot's audit entry"
                                    );
                                }
                                Some(Arc::new(parking_lot::Mutex::new(log)))
                            }
                            Err(e) => {
                                let fatal = northnarrow_agent::audit::audit_failure_is_fatal(
                                    std::env::var(
                                        northnarrow_agent::audit::AUDIT_ALLOW_UNWRITABLE_ENV,
                                    )
                                    .ok()
                                    .as_deref(),
                                );
                                error!(
                                    error = format!("{e:#}"),
                                    path = %cli.audit_log_file.display(),
                                    fatal,
                                    "audit log NOT writable — the signed audit chain would stop here \
                                     (is the directory in the unit's ReadWritePaths?)"
                                );
                                if fatal {
                                    anyhow::bail!(
                                    "audit log {} is not writable: {e:#}. Refusing to run unaudited; \
                                     set {}=1 to start anyway.",
                                    cli.audit_log_file.display(),
                                    northnarrow_agent::audit::AUDIT_ALLOW_UNWRITABLE_ENV
                                );
                                }
                                None
                            }
                        }
                    }
                    Err(e) => {
                        let fatal = northnarrow_agent::audit::audit_failure_is_fatal(
                            std::env::var(northnarrow_agent::audit::AUDIT_ALLOW_UNWRITABLE_ENV)
                                .ok()
                                .as_deref(),
                        );
                        error!(error = format!("{e:#}"), fatal, "audit log open failed — COMBAT stage transitions + admin ops would be UNAUDITED");
                        if fatal {
                            anyhow::bail!(
                                "audit log {} cannot be opened: {e:#}. Refusing to run unaudited; set {}=1 to start anyway.",
                                cli.audit_log_file.display(),
                                northnarrow_agent::audit::AUDIT_ALLOW_UNWRITABLE_ENV
                            );
                        }
                        None
                    }
                }
            }
            Err(e) => {
                warn!(error = format!("{e:#}"), "agent signing key load failed — COMBAT stage transitions + admin ops UNAUDITED this boot");
                None
            }
        };
    // Tappa 10.8 BPF self-defence: the link self-check needs the audit log,
    // which did not exist when the hooks attached.
    northnarrow_agent::anti_tamper::bpf_defense::spawn_link_self_check(audit_log.clone());
    // Tappa 10.8 — overlay decisions taken before the audit log existed.
    overlay_gate.attach_audit_log(audit_log.clone());
    // External audit CMB-017: quarantines are recorded in the signed chain.
    if let Some(audit) = audit_log.as_ref() {
        executor.set_audit_log(Arc::clone(audit));
    }
    // Tappa 10.8 telemetry probe: known events on each sensor, every minute.
    northnarrow_agent::telemetry_probe::spawn(audit_log.clone());
    // Tappa 10.8 adversarial findings: drop-ins, set-property, oom_score_adj, mounts.
    northnarrow_agent::self_integrity::spawn(
        audit_log.clone(),
        cli.watchdog_pidfile.clone(),
        Some(Arc::clone(&overlay_gate)),
    );
    // Lab PR 160: the heads re-anchored as they move, and the bounded
    // verification of the rotating logs in the background
    // (external audit NN-AUD-108, NN-AUD-112).
    if let Some(a) = &chain_anchor {
        northnarrow_agent::chain_anchor::spawn(Arc::clone(a), audit_log.clone());
    }
    northnarrow_agent::chain_anchor::set_audit_log(audit_log.clone());
    if let Some(pk) = northnarrow_agent::chain_anchor::boot_verifying_key(&cli.signing_key_file) {
        northnarrow_agent::chain_anchor::spawn_boot_verify(
            chain_targets.clone(),
            pk,
            audit_log.clone(),
        );
    }
    northnarrow_agent::sensors::ring_drops::set_audit_log(audit_log.clone());
    // External audit NN-AUD-120: a full FIM watch set is attested.
    northnarrow_agent::fim::drain::set_audit_log(audit_log.clone());
    // External audit SNS-009: a security ring that loses events raises
    // ALERTED (TelemetryLoss), outside trusted-installer windows.
    northnarrow_agent::sensors::ring_drops::set_posture(
        posture.clone(),
        Some(Arc::clone(&installer_override)),
    );

    // FIM-009 self-upgrade (§15.1): late-bind the audit-chain writer to
    // the trusted-installer override so its close/expiry records chain.
    if let Some(audit) = audit_log.as_ref() {
        installer_override.set_audit_log(Arc::clone(audit));
    }

    // Build the ladder with the system actuator (real kill / quarantine /
    // per-PID egress / full isolation) + the signed-audit evidence sink,
    // then publish it to the slot the posture combat hooks read. Driven
    // from three places: the combat-entry hook (above), `process_event`
    // (offender context + per-event jump-ahead), and the tick below.
    let ladder = Arc::new(
        northnarrow_agent::combat::CombatLadder::new(
            Box::new(northnarrow_agent::combat::SystemActuator::new(
                executor.clone(),
                isolator.clone(),
                detect_only,
            )),
            Box::new(northnarrow_agent::combat::AuditEvidence::new(
                audit_log.clone(),
            )),
            // Never kill / net-cut PID 1, the agent, its watchdog, or sshd —
            // skip + escalate to ISOLATE instead. Reuses the same `exempt`
            // handle the posture machine holds (so the watchdog PID stays the
            // timer-refreshed value) plus the same `--watchdog-exe` the refresh
            // task verifies against, so the watchdog branch can re-check
            // /proc/<pid>/exe inline at the kill/spare decision.
            Box::new(northnarrow_agent::combat::SystemProtectedProcs::new(
                executor.own_pid(),
                exempt.clone(),
                cli.resolved_watchdog_exe(),
            )),
            northnarrow_agent::combat::LadderConfig::default(),
        )
        // External audit POS-001 (NN-AUD-002): ISOLATE only in a locked COMBAT
        // (non-heuristic evidence, or forced by an administrator).
        .with_isolation_gate({
            let posture = posture.clone();
            move || posture.is_combat_locked()
        })
        // External audit CMB-007: the ladder's side effects (nft, cgroup
        // writes, kills, quarantine, iptables, audit) run on a worker of
        // their own, in order — never on the event loop.
        .with_worker(),
    );
    // External audit POS-001: an unlocked COMBAT decays once quiet; the
    // ladder stands down with it (lifts the per-PID egress blocks).
    {
        let ladder = Arc::clone(&ladder);
        posture.on_combat_decay(Arc::new(move || ladder.stand_down(Instant::now())));
    }
    // combat-avail-2: the same host-critical knowledge the ladder uses to
    // spare attributed offenders must also spare the /proc DESCENDANTS a
    // KillProcessTree walk reaps (an sshd or the watchdog under an
    // offender). The executor was built before the guard existed, so bind
    // it late; ProtectedReason has a static name for the audit row.
    {
        let guard = northnarrow_agent::combat::SystemProtectedProcs::new(
            executor.own_pid(),
            exempt.clone(),
            cli.resolved_watchdog_exe(),
        );
        executor.set_tree_guard(Arc::new(move |pid: u32| {
            use northnarrow_agent::combat::ProtectedProcs;
            guard.protected_reason(pid).map(|r| r.as_str())
        }));
    }
    if ladder_slot.set(Arc::clone(&ladder)).is_err() {
        warn!("COMBAT ladder slot already set — unexpected double-init");
    }
    info!(
        "COMBAT graduated-response ladder armed (INVESTIGATE → NEUTRALIZE → ISOLATE; \
         isolation is last resort)"
    );

    // Fast heartbeat advancing the time-bound INVESTIGATE deadline. The
    // 60 s posture-decay loop is too coarse for the ladder's
    // seconds-scale windows; this 5 s tick is a no-op unless a COMBAT
    // episode is active and its investigate deadline has elapsed.
    let ladder_tick = Arc::clone(&ladder);
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_secs(5));
        tick.tick().await; // skip the immediate first tick
        loop {
            tick.tick().await;
            if HOST_STOPPING.load(std::sync::atomic::Ordering::SeqCst) {
                continue;
            }
            ladder_tick.tick(Instant::now());
        }
    });

    // External audit EBPF-001: the agent now outlives the units' stop jobs
    // and runs until systemd-shutdown's final stage. Ask systemd every 2 s
    // whether the host is stopping: from then on the shutdown's own traffic
    // (logs truncated, services killed, the console written) must not drive
    // the posture or the ladder. Detection goes on.
    if std::path::Path::new(northnarrow_agent::systemd_state::PRIVATE_SOCKET).exists() {
        let ladder_stop = Arc::clone(&ladder);
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(Duration::from_secs(2));
            loop {
                tick.tick().await;
                if systemd_state().await.as_deref() == Some("stopping") {
                    host_stopping(&ladder_stop);
                    break;
                }
            }
        });
    }

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
        &overlay_gate.verified(OverlayKind::FimPaths, &cli.fim_paths_local),
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
    report_builtin_defaults(
        &overlay_gate,
        "fim-paths",
        &cli.fim_paths_v1,
        &watched_paths_load.defaults,
    );
    if legacy_isolation_removed {
        attest_legacy_isolation_removed(audit_log.as_ref());
    }
    if let Some(outcome) = &stale_combat {
        northnarrow_agent::combat::reconcile::attest(audit_log.as_ref(), outcome);
    }
    if let Some(detail) = &tracepoint_degraded {
        attest_degraded(audit_log.as_ref(), detail);
    }
    if let Some(detail) = &hook_args_degraded {
        attest_degraded(audit_log.as_ref(), detail);
    }
    // External audit NET-009: the JA3 list with no producer (see its load).
    if let Some(gap) = &ja3_gap {
        attest_degraded(audit_log.as_ref(), gap);
    }
    // Lab follow-up (lab PR 165): no `nft` for the outbound block (see its
    // check).
    if let Some(gap) = &nft_gap {
        attest_degraded(audit_log.as_ref(), gap);
    }
    if let Some(detail) = &rag_refused {
        attest_degraded(audit_log.as_ref(), detail);
    }
    // External audit EBPF-006: on the `udp_sendmsg` sensor (a kernel
    // without what the socket-buffer programs need, or `--dns-sensor
    // sendmsg`) a query's name is read from the sender's memory before the
    // kernel copies it: the sender can change it in between, so the name
    // recorded and the one sent may differ.
    if !northnarrow_agent::sensors::dns_sensor::skb_active() {
        attest_degraded(
            audit_log.as_ref(),
            "DNS sensor on udp_sendmsg: query names read from the sender's memory, which it \
             can rewrite before the kernel sends them (IPv4 only)",
        );
    }
    // External audit FIMR-001: FIM watching nothing used to show only as
    // `effective=0` in an INFO line.
    if watched_paths_load.effective.is_empty() {
        error!(
            v1 = %cli.fim_paths_v1.display(),
            "fim paths-config: no path to watch — FIM and the anti-tamper baits see nothing"
        );
        attest_degraded(
            audit_log.as_ref(),
            &format!(
                "fim watches no path ({} yields none)",
                cli.fim_paths_v1.display()
            ),
        );
    }
    let paths_summary = admin_socket::WatchedPathsSummary::from_load(&watched_paths_load);

    // BUG-026: ONE shared StateDirProtection for the rotating on-disk logs
    // under /var/lib/northnarrow (netflow + fim_drift share its dance
    // mutex so two concurrent rotations can't race the dir's chattr +i).
    // `take_protected_inodes_map` takes the PROTECTED_INODES handle out of
    // the Ebpf — it MUST run AFTER the anti-tamper bootstrap registered the
    // protected inodes and (THE VM-VALIDATE ITEM, catalog §24) with nothing
    // else mutating that map via the Ebpf handle afterward. If a runtime
    // path (canary deploy / admin) re-registers a protected inode via the
    // Ebpf, switch this to opening the PINNED map by path instead of
    // `take`. On failure the rotating writers don't open (degrade-not-fail).
    let state_protection: Option<
        std::sync::Arc<northnarrow_agent::anti_tamper::filesystem::StateDirProtection>,
    > = match northnarrow_agent::anti_tamper::filesystem::take_protected_inodes_map(
        sensor.ebpf_mut(),
    ) {
        Ok(h) => Some(std::sync::Arc::new(
            northnarrow_agent::anti_tamper::filesystem::StateDirProtection::new(
                std::path::PathBuf::from(northnarrow_agent::anti_tamper::filesystem::STATE_DIR),
                h,
            ),
        )),
        Err(e) => {
            // ERROR, not warn: anti-tamper FS protection of the state logs is
            // compromised (PROTECTED_INODES missing) AND rotation is disabled.
            tracing::error!(
                error = %e,
                "BUG-026: take_protected_inodes_map failed — anti-tamper FS protection of the \
                 state logs is COMPROMISED and on-disk log ROTATION is disabled this boot; \
                 netflow + fim_drift keep logging APPEND-ONLY (the disk-fill vector returns \
                 until a restart recovers anti-tamper)"
            );
            None
        }
    };
    // Degrade-not-fail (BUG-026 ②): if protection is unavailable, keep
    // telemetry flowing — open the writers with NoProtection + rotation
    // DISABLED (append-only) rather than dropping FIM-drift + netflow, the two
    // core telemetry streams. Losing them is the worse failure for an XDR; the
    // disk grows (the original vector) only until a restart recovers
    // anti-tamper. An effectively-infinite cap means the writer never invokes
    // the chattr dance (which would EPERM under `+i` and stall logging).
    let rotation_protection: std::sync::Arc<dyn northnarrow_agent::chainlog::ProtectionManager> =
        match &state_protection {
            // `p.clone()` clones the concrete Arc, then the match arm
            // unsize-coerces it to Arc<dyn> (Arc::clone(p) would infer the
            // wrong type param from the expected `dyn` and mismatch).
            Some(p) => p.clone(),
            None => std::sync::Arc::new(northnarrow_agent::chainlog::NoProtection),
        };
    let rotation_on = state_protection.is_some();
    let cap = |bytes: u64| if rotation_on { bytes } else { u64::MAX };
    // Lab PR 160: the head anchor is created inside the same dance when
    // the state directory is already immutable.
    if let Some(a) = &chain_anchor {
        a.lock().set_protection(rotation_protection.clone());
    }
    // Test/ops knob: NN_FIM_DRIFT_CAP_BYTES overrides the fim_drift active-file
    // rotation cap (default 32 MiB) so rotation can be validated without
    // generating 32 MiB of drift. Unset = default; still gated by rotation_on.
    // External audit MAIN-004: never below 1 MiB, every override logged
    // (and reported as weakening_env by the self-integrity check).
    const FIM_DRIFT_CAP_DEFAULT: u64 = 32 * 1024 * 1024;
    let fim_drift_cap = northnarrow_agent::chainlog::cap_from_env(
        northnarrow_agent::chainlog::FIM_DRIFT_CAP_ENV,
        FIM_DRIFT_CAP_DEFAULT,
    );
    let fim_drift_rotation = northnarrow_agent::chainlog::RotationConfig {
        size_cap_bytes: cap(fim_drift_cap),
        max_archives: 8,
        file_mode: northnarrow_agent::chainlog::STATE_LOG_FILE_MODE,
    };
    let netflow_rotation = northnarrow_agent::chainlog::RotationConfig {
        size_cap_bytes: cap(16 * 1024 * 1024),
        max_archives: 16,
        file_mode: northnarrow_agent::chainlog::STATE_LOG_FILE_MODE,
    };

    // Tappa 9.0.a: open the detection store + spawn its dedicated writer
    // task. Detections are lower-volume than netflow → default 16 MiB ×
    // 8 archives (≈144 MiB budget), overridable via NN_DETECTIONS_CAP_BYTES
    // for rotation validation. Re-load the signing key (separate domain
    // handle, like the FIM block below). Degrade-not-fail: any error here
    // means "no detection persistence this boot", never an agent abort.
    // The writer JoinHandle is detached on drop (tokio keeps the task
    // running); the sink is threaded into the event loop.
    let detection_sink: Option<northnarrow_agent::detection_store::DetectionSink> = {
        let cap_bytes = northnarrow_agent::chainlog::cap_from_env(
            northnarrow_agent::chainlog::DETECTIONS_CAP_ENV,
            northnarrow_agent::detection_store::DEFAULT_DETECTIONS_CAP_BYTES,
        );
        let detections_rotation = northnarrow_agent::chainlog::RotationConfig {
            size_cap_bytes: cap(cap_bytes),
            max_archives: northnarrow_agent::detection_store::DEFAULT_MAX_ARCHIVES,
            file_mode: northnarrow_agent::chainlog::STATE_LOG_FILE_MODE,
        };
        match northnarrow_agent::audit::AgentSigningKey::load_or_bootstrap(&cli.signing_key_file) {
            Ok(key) => match northnarrow_agent::detection_store::open(
                &cli.detections_file,
                key,
                detections_rotation,
                rotation_protection.clone(),
                northnarrow_agent::detection_store::DEFAULT_QUEUE_CAP,
            ) {
                Ok((sink, _writer)) => Some(sink),
                Err(e) => {
                    warn!(
                        error = %e,
                        path = %cli.detections_file.display(),
                        "detection store open failed — detections will NOT persist this boot"
                    );
                    None
                }
            },
            Err(e) => {
                warn!(
                    error = %e,
                    "detection store needs the agent signing key — load failed; \
                     detections will NOT persist this boot"
                );
                None
            }
        }
    };

    // Review 75: detections held back by the per-rule budget, reported.
    // External audit NN-AUD-111: started once the detection store exists,
    // so the same task records the store's queue drops.
    detection_budget::spawn_reporter(audit_log.clone(), detection_sink.clone());

    // Tappa 9.0.c: open the status-event chainlog + build the detection
    // admin state for the admin socket (set-status writes here; the
    // detections read overlays current status from it). Lower-volume
    // than detections → smaller 4 MiB cap, overridable via
    // NN_STATUS_EVENTS_CAP_BYTES. Degrade-not-fail: any error here
    // means "no triage status changes this boot" (the `detections` read
    // still works, showing initial Open), never an agent abort.
    let detection_admin_state: Option<Arc<admin_socket::DetectionAdminState>> = {
        let cap_bytes = northnarrow_agent::chainlog::cap_from_env(
            northnarrow_agent::chainlog::STATUS_EVENTS_CAP_ENV,
            northnarrow_agent::detection_store::DEFAULT_STATUS_EVENTS_CAP_BYTES,
        );
        let status_rotation = northnarrow_agent::chainlog::RotationConfig {
            size_cap_bytes: cap(cap_bytes),
            max_archives: northnarrow_agent::detection_store::DEFAULT_MAX_ARCHIVES,
            file_mode: northnarrow_agent::chainlog::STATE_LOG_FILE_MODE,
        };
        match northnarrow_agent::audit::AgentSigningKey::load_or_bootstrap(&cli.signing_key_file) {
            Ok(key) => match northnarrow_agent::detection_store::open_status_log(
                &cli.status_events_file,
                key,
                status_rotation,
                rotation_protection.clone(),
            ) {
                Ok(log) => Some(Arc::new(admin_socket::DetectionAdminState {
                    status_log: Arc::new(parking_lot::Mutex::new(log)),
                    detections_path: cli.detections_file.clone(),
                    status_events_path: cli.status_events_file.clone(),
                })),
                Err(e) => {
                    warn!(
                        error = %e,
                        path = %cli.status_events_file.display(),
                        "status-event store open failed — detection triage \
                         (set-status) DISABLED this boot"
                    );
                    None
                }
            },
            Err(e) => {
                warn!(
                    error = %e,
                    "status-event store needs the agent signing key — load failed; \
                     detection triage (set-status) DISABLED this boot"
                );
                None
            }
        }
    };

    let fim_admin_state: Option<Arc<admin_socket::FimAdminState>> = {
        // Re-derive the signing key + agent_id for FIM the same way
        // the audit log does (re-load rather than steal the audit
        // log's clone — they're separate domains with separate Db
        // handles). A failure here downgrades the FIM CLI surface
        // to "scheduled for next restart" + zero-snapshot status.
        let mut baseline_pubkey: Option<ed25519_dalek::VerifyingKey> = None;
        let baseline_db_opt = match northnarrow_agent::audit::AgentSigningKey::load_or_bootstrap(
            &cli.signing_key_file,
        ) {
            Ok(key) => {
                baseline_pubkey = Some(key.verifying_key());
                match northnarrow_agent::fim::baseline::BaselineDb::open(
                    &cli.fim_baseline_file,
                    key,
                    agent_id,
                ) {
                    Ok(mut db) => {
                        attest_open_findings(
                            audit_log.as_ref(),
                            &cli.fim_baseline_file,
                            db.take_open_findings(),
                        );
                        Some(Arc::new(parking_lot::Mutex::new(db)))
                    }
                    Err(e) => {
                        // External audit MAIN-003: the sensors, the drain and
                        // every FIM rule still run below; only re-baselining
                        // is off this boot.
                        error!(
                            error = %e,
                            path = %cli.fim_baseline_file.display(),
                            "fim baseline DB open failed — FIM still detects; \
                             `fim baseline` cannot record a new baseline this boot"
                        );
                        attest_degraded(
                            audit_log.as_ref(),
                            &format!("fim baseline database unavailable ({e:#}): re-baselining off this boot"),
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
        {
            {
                use northnarrow_agent::fim::attach::{
                    attach_observe_programs, populate_watched_paths, take_fs_fim_events_ringbuf,
                    take_watched_paths_map,
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
                // External audit FIMP-001: only the verified suffix of the
                // chain may silence an event.
                let loaded = match baseline_pubkey.as_ref() {
                    Some(pk) => BaselineCache::load_verified(&cli.fim_baseline_file, pk),
                    None => Err(anyhow::anyhow!("no agent key to verify the baseline with")),
                };
                let baseline_cache = match loaded {
                    Ok((c, trust)) => {
                        info!(
                            entries = c.len(),
                            rows = trust.rows,
                            untrusted = trust.untrusted,
                            "fim: baseline cache loaded from the verified chain"
                        );
                        if trust.breaks > 0 {
                            error!(
                                breaks = trust.breaks,
                                untrusted = trust.untrusted,
                                path = %cli.fim_baseline_file.display(),
                                "fim: baseline rows that do not verify are kept out of the \
                                 cache — their paths report every change until a new baseline"
                            );
                            attest_degraded(
                                audit_log.as_ref(),
                                &format!(
                                    "{}: {} baseline row(s) behind {} chain break(s) not trusted",
                                    cli.fim_baseline_file.display(),
                                    trust.untrusted,
                                    trust.breaks
                                ),
                            );
                        }
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
                let mut fim_attached: Vec<&'static str> = Vec::new();
                if let Some(btf) = btf.as_ref() {
                    match attach_observe_programs(
                        sensor.ebpf_mut(),
                        btf,
                        cli.file_open_sensor == FileOpenSensor::Lsm,
                    ) {
                        Ok(a) => fim_attached = a,
                        Err(e) => warn!(
                            error = %e,
                            "fim: attach_observe_programs returned error — \
                             observe hooks may be partial"
                        ),
                    }
                }
                start_open_sensor(
                    &mut sensor,
                    cli.file_open_sensor,
                    &fim_attached,
                    &open_sensor_carveout,
                    audit_log.clone(),
                );
                // External audit ATP-013: the FIM observers and the file-open
                // sensor were loaded after the BPF guard registered the
                // agent's objects: their programs and links join the set.
                match northnarrow_agent::anti_tamper::bpf_defense::register_late_objects(
                    sensor.ebpf_mut(),
                ) {
                    Ok(n) => debug!(
                        ids = n,
                        "BPF self-defence: late programs and links registered"
                    ),
                    Err(e) => error!(
                        error = format!("{e:#}"),
                        "BPF self-defence: the FIM and file-open programs NOT registered as the \
                         agent's own — the guard does not refuse handles to them"
                    ),
                }
                record_own_prog_ids(own_prog_ids_file.as_deref(), sensor.ebpf_mut());
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
                // External audit FIMP-011: a FIM that attached no observer, or
                // watches nothing, sees no file change at all. Said in the
                // signed audit chain, not only in an INFO among the boot lines.
                if let Some(shortfall) = northnarrow_agent::fim::attach::coverage_shortfall(
                    fim_attached.len(),
                    northnarrow_agent::fim::attach::FIM_OBSERVE_PROGRAMS.len(),
                    inode_map.len(),
                    watched_paths_load.effective.len(),
                ) {
                    error!(target: "fim", "{shortfall}");
                    attest_degraded(audit_log.as_ref(), &shortfall);
                }

                // BUG-022 — take an OWNED writable handle to WATCHED_PATHS
                // (post-populate) so the drain loop can enroll children of
                // a watched directory on the fly. Best-effort: on failure
                // the drain still runs — create-detection via child-leaf
                // reconstruction still works; only the later in-place edit
                // of a freshly-dropped child would go unwatched.
                let watched_paths_handle = match take_watched_paths_map(sensor.ebpf_mut()) {
                    Ok(h) => Some(Arc::new(parking_lot::Mutex::new(h))),
                    Err(e) => {
                        warn!(
                            error = %e,
                            "fim: take_watched_paths_map failed — runtime child \
                             enrollment disabled this boot"
                        );
                        None
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
                let gate_for_snapshot = Arc::clone(&overlay_gate);
                if let Some(baseline_db) = baseline_db_opt.as_ref() {
                    tokio::spawn(run_recompute_task(
                        receiver,
                        Arc::clone(baseline_db),
                        Arc::clone(&baseline_cache),
                        Arc::clone(&inode_map),
                        watched_paths_handle.clone(),
                        move || {
                            // A signed `fim baseline` re-reads the overlay:
                            // the same signature check as at boot, and the
                            // bytes it verified are the ones applied.
                            let load = northnarrow_agent::fim::paths_config::load_watched_paths(
                                &v1_for_snapshot,
                                &gate_for_snapshot
                                    .verified(OverlayKind::FimPaths, &local_for_snapshot),
                            )
                            .unwrap_or_default();
                            report_builtin_defaults(
                                &gate_for_snapshot,
                                "fim-paths",
                                &v1_for_snapshot,
                                &load.defaults,
                            );
                            load.effective
                        },
                    ));
                } else {
                    // No database to write a baseline into: requests are
                    // refused (logged), detection is not affected.
                    drop(receiver);
                }

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
                    .and_then(|key| {
                        FimDriftDb::open(
                            &cli.fim_drift_file,
                            key,
                            agent_id,
                            std::sync::Arc::clone(&rotation_protection),
                            fim_drift_rotation,
                        )
                    }) {
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
                            let watched_paths_for_drain = watched_paths_handle.clone();
                            // Review 76: only package-manager drift is paced.
                            let lineage_for_drain = lineage.clone();
                            let event_tx = sensor.event_tx();
                            let audit_for_drain = audit_log.clone();
                            let handle = tokio::spawn(async move {
                                let outcome = drain_loop(
                                    rb,
                                    inode_map_for_drain,
                                    baseline_cache_for_drain,
                                    drift_db,
                                    classifier,
                                    rate_limiter_clone,
                                    watched_paths_for_drain,
                                    lineage_for_drain,
                                    event_tx,
                                )
                                .await;
                                drain_ended("fim", outcome, audit_for_drain.as_ref());
                            });
                            sensor.register_pump_handle("fim_drain", handle);
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
                if baseline_db_opt.as_ref().is_some_and(|db| {
                    db.lock().last_hash() == northnarrow_agent::audit::GENESIS_PREV_HASH
                }) && !watched_paths_load.effective.is_empty()
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
                    // External audit DEC-001: shared with the canaries.
                    watch: northnarrow_agent::fim::attach::FimWatch {
                        path_map: Arc::clone(&inode_map),
                        watched_paths: watched_paths_handle.clone(),
                    },
                }))
            }
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
    let report = northnarrow_agent::fim::honeypot::check_and_restore();
    // External audit FIMR-008: a bait re-created here was absent when the
    // watch set was built above, and nothing enrolled it afterwards — after
    // every reboot the tmpfs pair under /run went unwatched until the next
    // agent restart. Watched now.
    if let Some(fim) = fim_admin_state.as_ref() {
        for path in &report.recreated {
            let watched = northnarrow_agent::fim::attach::key_for_path(std::path::Path::new(path))
                .map(|key| {
                    fim.watch.watch(
                        key,
                        path,
                        northnarrow_agent::fim::drain::WatchClass::Configured,
                    )
                });
            if !matches!(watched, Ok(true)) {
                warn!(
                    target: "fim.honeypot",
                    path = %path,
                    "re-created control-surface file could not be watched"
                );
            }
        }
    }
    let rebooted = {
        use northnarrow_agent::fim::honeypot;
        let state_dir = std::path::Path::new(northnarrow_agent::anti_tamper::filesystem::STATE_DIR);
        match honeypot::current_boot_id() {
            Some(now) => {
                let changed = honeypot::boot_changed(state_dir, &now);
                if changed {
                    record_boot_id(state_protection.as_deref(), state_dir, &now);
                }
                changed
            }
            None => true,
        }
    };
    if report.all_present() {
        info!(
            present = report.present,
            total = report.total,
            "Honeypot integrity: {}/{} present",
            report.present,
            report.total
        );
    } else if report.only_volatile_after_reboot(rebooted) {
        // The tmpfs pair is gone after every reboot: expected, not a tamper.
        info!(
            present = report.present,
            total = report.total,
            recreated = ?report.recreated,
            "Honeypot integrity: {}/{} present; the runtime pair re-created after a reboot",
            report.present,
            report.total
        );
    } else {
        warn!(
            target: "fim.honeypot",
            rule = "NN-L-FIM-024-INTEGRITY",
            severity = "Medium",
            present = report.present,
            recreated = report.recreated.len(),
            failed = report.failed.len(),
            replaced = report.replaced.len(),
            "Honeypot integrity: {} present, recreated {:?}, not a file {:?}, unrestorable {:?}",
            report.present,
            report.recreated,
            report.replaced,
            report.failed
        );
        // FIMR-008: in the signed audit chain, not only in the journal.
        attest_bait_integrity(audit_log.as_ref(), &report, rebooted);
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
                    Ok(mut r) => {
                        attest_open_findings(
                            audit_log.as_ref(),
                            &cli.canary_registry_file,
                            r.take_open_findings(),
                        );
                        attest_chain_findings(audit_log.as_ref(), r.take_chain_findings());
                        Some(Arc::new(parking_lot::Mutex::new(r)))
                    }
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
                    Ok(mut a) => {
                        attest_open_findings(
                            audit_log.as_ref(),
                            &cli.canary_access_file,
                            a.take_open_findings(),
                        );
                        attest_chain_findings(audit_log.as_ref(), a.take_chain_findings());
                        Some(Arc::new(parking_lot::Mutex::new(a)))
                    }
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
                        let fim_watch = fim_admin_state.as_ref().map(|f| f.watch.clone());
                        {
                            use northnarrow_agent::canary::registry::{check_decoy, DecoyState};
                            let mut reg = registry.lock();
                            let mut idx = indexes.lock();
                            // External audit DEC-003: inodes resolved at
                            // boot too — they feed read-forward.
                            idx.rebuild_live(&reg);
                            // External audit DEC-001: the FIM boot keeps only
                            // the watches it registers, so the decoys are
                            // watched again here, every boot. External audit
                            // DEC-010: each decoy is first compared with what
                            // its row says was written. One modified, removed
                            // or replaced while the agent was down used to be
                            // adopted in silence: it is an ERROR, and when its
                            // state changed a DecoyCheck row (shown by `canary
                            // list`) and a signed `integrity_drift`. Only a
                            // regular file is watched.
                            let mut unverified = 0usize;
                            for canary in reg.list() {
                                let Some(path) = admin_socket::canary_path(&canary.deployment)
                                else {
                                    continue;
                                };
                                let expected =
                                    canary.content.as_ref().map(|c| c.contents_sha256.as_str());
                                unverified += usize::from(expected.is_none());
                                let check = check_decoy(std::path::Path::new(path), expected);
                                if check.state != DecoyState::Intact {
                                    error!(
                                        canary_id = %canary.canary_id,
                                        name = %common::log_escape::Escaped(&canary.name),
                                        path,
                                        state = check.state.as_str(),
                                        "canary: the decoy is not what was deployed — changed, \
                                         removed or replaced while the agent was not watching it; \
                                         `nn-admin canary refresh` writes it again"
                                    );
                                }
                                match reg.record_decoy_state(&canary.canary_id, check.state) {
                                    Ok(true) => attest_decoy_state(
                                        audit_log.as_ref(),
                                        &canary,
                                        path,
                                        &check,
                                    ),
                                    Ok(false) => {}
                                    Err(e) => {
                                        warn!(
                                            error = %format!("{e:#}"),
                                            path,
                                            "canary: recording the decoy state failed"
                                        );
                                        attest_decoy_state(
                                            audit_log.as_ref(),
                                            &canary,
                                            path,
                                            &check,
                                        );
                                    }
                                }
                                match (check.key, &fim_watch) {
                                    (Some(key), Some(watch)) => {
                                        // External audit NN-AUD-120: a decoy is
                                        // never evicted; a refusal is attested.
                                        if !watch.watch(
                                            key,
                                            path,
                                            northnarrow_agent::fim::drain::WatchClass::Decoy,
                                        ) {
                                            error!(
                                                path,
                                                "canary: the kernel watch map refused the decoy \
                                                 — its opens are not seen"
                                            );
                                        }
                                    }
                                    (Some(_), None) => warn!(
                                        path,
                                        "canary: FIM is not running — decoy opens unseen"
                                    ),
                                    // nothing to watch: reported above
                                    (None, _) => {}
                                }
                            }
                            if unverified > 0 {
                                warn!(
                                    decoys = unverified,
                                    "canary: decoys deployed before their content was recorded — \
                                     only their presence is checked; `nn-admin canary refresh` \
                                     writes them again and records it"
                                );
                            }
                            let read_forward = northnarrow_agent::canary::read_forward::len();
                            info!(
                                canaries = idx.len(),
                                read_forward, "canary indexes rebuilt from registry"
                            );
                        }
                        let detector =
                            Arc::new(northnarrow_agent::canary::detector::Detector::new(
                                registry.clone(),
                                access_log,
                                indexes.clone(),
                            ));
                        let admin_state = Arc::new(admin_socket::CanaryAdminState {
                            fim_watch,
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
                None
            }
        };
        if let Some(netflow_db) = netflow_db_opt {
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
                    event_tx,
                )
                .await;
                drain_ended("net", outcome, audit_for_drain.as_ref());
            });
            sensor.register_pump_handle("net_drain", handle);
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
                // External audit AUT-004: a skipped line is in the signed
                // chain, not only in the journal.
                let skipped = auth.skipped_lines();
                if !skipped.is_empty() {
                    let lines: Vec<String> = skipped
                        .iter()
                        .map(|(n, why)| format!("line {n}: {why}"))
                        .collect();
                    attest_degraded(
                        audit_log.as_ref(),
                        &format!(
                            "{}: {} line(s) skipped, their keys not loaded — {}",
                            cli.admin_pub.display(),
                            skipped.len(),
                            lines.join("; ")
                        ),
                    );
                }
                // External audit ATP-004: the one-key bootstrap is over for
                // good once the signed chain shows a second key was added.
                // Lab PR 160: also when the head anchor carries it, or the
                // audit chain was found cut (it could have held the add).
                if audit_log
                    .as_ref()
                    .is_some_and(|l| l.lock().second_key_added())
                    || chain_anchor
                        .as_ref()
                        .is_some_and(|a| a.lock().second_key_added())
                {
                    auth.mark_bootstrap_consumed();
                }
                let auth = Arc::new(auth);
                let posture_clone = posture.clone();
                let iso_clone = Arc::clone(iso);
                let socket_path = cli.admin_socket.clone();
                let signal_for_serve = shutdown_signal.clone();
                // Tappa 8 B5: the AuditLog is opened ONCE at boot (above,
                // right after agent_id) and shared with the COMBAT ladder;
                // the admin socket takes its own Arc clone. post-A14 the
                // file's inode is already in PROTECTED_INODES so an
                // attacker can't replace it underneath us.
                let audit_log = audit_log.clone();
                let marker_path = cli.shutdown_marker_file.clone();
                let fim_state_for_serve = fim_admin_state.clone();
                let canary_state_for_serve = canary_admin_state.clone();
                // FIM-009 self-upgrade (§15.1): the dispatcher arms this
                // override on a verified TrustedInstallerGrantRequest.
                let installer_override_for_serve = Some(Arc::clone(&installer_override));
                // Tappa 9.0.c: detection triage state (status-event chain).
                let detection_state_for_serve = detection_admin_state.clone();
                // External audit NN-AUD-082: the read verbs serve the
                // files the flags name, not the built-in paths.
                let read_paths_for_serve = Arc::new(admin_socket::AdminReadPaths {
                    fim_drift: cli.fim_drift_file.clone(),
                    netflow: cli.netflow_file.clone(),
                    netflow_listeners: cli.netflow_listeners_file.clone(),
                });
                // External audit CMB-016: the response verbs read the
                // executor's record and vault, and the ladder's stage.
                let response_state_for_serve = Some(Arc::new(admin_socket::ResponseAdminState {
                    config: executor.config().clone(),
                    combat_stage: {
                        let ladder = Arc::clone(&ladder);
                        Arc::new(move || ladder.current_stage().map(|s| s.as_str().to_string()))
                    },
                }));
                // External audit NN-AUD-077: the loop now outlives a
                // transient accept error; if it still ends, the admin plane
                // is gone until a restart — an ERROR and a signed record.
                let audit_log_on_exit = audit_log.clone();
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
                        installer_override_for_serve,
                        detection_state_for_serve,
                        response_state_for_serve,
                        read_paths_for_serve,
                    )
                    .await
                    {
                        error!(
                            error = %e,
                            "admin socket serve loop exited — no unlock, shutdown or key \
                             rotation until the agent restarts"
                        );
                        attest_degraded_at(
                            audit_log_on_exit.as_ref(),
                            &format!("admin socket serve loop exited: {e:#}"),
                            false,
                        );
                    }
                });
            }
            Err(e) => {
                // External audit AUT-004: the agent without its admin
                // socket cannot be unlocked or upgraded — an ERROR and a
                // signed record, not a WARN.
                error!(
                    error = %e,
                    path = %cli.admin_pub.display(),
                    "admin pub key file missing or invalid; admin socket disabled"
                );
                attest_degraded(audit_log.as_ref(), &format!("admin socket disabled: {e:#}"));
            }
        }
    } else {
        error!(
            socket = %cli.admin_socket.display(),
            "admin socket NOT started: no NetworkIsolator (combat ruleset missing, see above) — \
             the watchdog STATUS ping will fail until the ruleset is installed and the agent restarted"
        );
    }

    // Decay loop: walks the posture down (ALERTED→OBSERVING after 1h
    // idle, ENGAGED→ALERTED after 24h idle, and — external audit POS-001 —
    // an unlocked COMBAT, reached on heuristics alone, to ENGAGED after
    // 30 min without a new escalation signal). A locked COMBAT never
    // decays; it requires an admin-signed release. The 60 s cadence is
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

    // External audit ATP-003: the trusted-installer window is closed — and
    // its close recorded — at its deadline, not at the next event. The
    // kernel grant ends at the same deadline by itself; this keeps the
    // in-memory state, the PID-1 stop grant and the audit chain on time,
    // and retries a zeroing that failed.
    let installer_ticker = installer_override.clone();
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_secs(1));
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tick.tick().await;
            installer_ticker.close_if_expired(Instant::now());
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
    // SIGTERM reaches the agent only from itself, the watchdog, PID 1
    // inside a signed trusted-installer window, or `systemd-shutdown` at
    // the end of a shutdown (the task_kill hook refuses everyone else) —
    // and from anyone on a kernel without `bpf` in its LSM chain.
    let mut sigint = signal(SignalKind::interrupt()).context("installing SIGINT handler")?;
    let mut sigterm = signal(SignalKind::terminate()).context("installing SIGTERM handler")?;
    let mut sighup = signal(SignalKind::hangup()).context("installing SIGHUP handler")?;

    // T7.10: the unit is `Type=notify`; tell systemd we are ready now
    // that every subsystem is wired (anti-tamper attached, decision
    // engine + ADE loaded, drains + admin socket spawned, signal
    // handlers installed) and we are about to enter the event loop.
    // Without this, systemd holds the unit `activating` until
    // `TimeoutStartSec` then marks it failed — and the agent's own
    // anti-tamper hook denies the resulting SIGTERM, stranding the
    // unit `failed` while the process runs and dragging the watchdog
    // down via `BindsTo`. No-op when not under systemd (NOTIFY_SOCKET
    // unset), so dev runs and tests are unaffected. Non-fatal: a send
    // failure is logged, not propagated — a healthy agent must not
    // refuse to run just because the readiness ping didn't land.
    if let Err(e) = northnarrow_agent::sd_notify::ready() {
        warn!(error = %e, "sd_notify(READY=1) failed; systemd may report the unit as not-ready");
    }

    // Why the event loop ended — written as the signed `agent_stop` entry
    // below; a run that never writes it is reported by the next boot.
    let loop_started = std::time::Instant::now();
    #[allow(unused_assignments)]
    let mut stop_reason = "unknown";
    // External audit SNS-001: a telemetry task that ended (a dead ring
    // pump, a drain, the open-sensor rule refresher) is checked for here;
    // `next_event()` can never report it.
    let mut pump_check = tokio::time::interval(PUMP_CHECK_PERIOD);
    pump_check.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tokio::select! {
            evt = sensor.next_event() => match evt {
                Some(e) => {
                    // Tappa 10.8 telemetry probe: every event is offered to
                    // the probe tracker before the decision engine.
                    northnarrow_agent::telemetry_probe::observe(&e);
                    process_event(
                    &engine,
                    &executor,
                    ade_engine.as_deref(),
                    &correlation,
                    &host,
                    &posture,
                    &ladder,
                    // Tappa 9.5 K6: detector handle wired in. When
                    // the canary subsystem boot above failed
                    // (missing signing key, registry open error),
                    // canary_detector is None and process_event
                    // short-circuits to the source event without
                    // canary filtering.
                    canary_detector.as_deref(),
                    // FIM-009 self-upgrade (§15.1): lazy TTL expiry sweep.
                    &installer_override,
                    // Tappa 9.0.a: detection-persistence sink (off the hot path).
                    detection_sink.as_ref(),
                    e,
                ).await
                }
                None => {
                    warn!("sensor pump exited; shutting down");
                    stop_reason = "sensor_pump_exited";
                    break;
                }
            },
            _ = pump_check.tick() => {
                #[cfg(feature = "debug-trigger")]
                debug_abort_pump(&sensor, &cli.admin_socket);
                // Lab PR 162: on a quiet host no event runs this sweep.
                if let Some(ade) = ade_engine.as_deref() {
                    escalate_unsettled_exec_checks(
                        ade,
                        &executor,
                        &posture,
                        &correlation,
                        &host,
                        detection_sink.as_ref(),
                    );
                }
                let dead = sensor.finished_pumps();
                if !dead.is_empty() {
                    // A blind sensor is not hidden behind a silent restart:
                    // signed `subsystem_degraded` naming the task, signed
                    // `agent_stop` (`sensor_pump_exited`), non-zero exit, and
                    // the watchdog respawns the agent (its ceiling bounds a
                    // pump that dies at every start).
                    let names = dead.join(", ");
                    error!(
                        pumps = %names,
                        "sensor pump exited — its telemetry is lost; stopping so the watchdog restarts the agent"
                    );
                    attest_degraded_at(
                        audit_log.as_ref(),
                        &format!(
                            "sensor pump exited: {names} (its telemetry was lost; the agent stops for a watchdog restart)"
                        ),
                        false,
                    );
                    stop_reason = "sensor_pump_exited";
                    break;
                }
            }
            _ = sigint.recv() => {
                info!("SIGINT received; shutting down");
                stop_reason = "sigint";
                break;
            }
            _ = sigterm.recv() => {
                // External audit EBPF-001: PID 1's SIGTERM reaches the agent
                // only inside a signed trusted-installer window or from
                // `systemd-shutdown`, the last stage of a shutdown.
                stop_reason = if pid1_is_systemd_shutdown() { "system_shutdown" } else { "sigterm" };
                info!(reason = stop_reason, "SIGTERM received; shutting down");
                break;
            }
            _ = sighup.recv() => {
                info!("SIGHUP received; shutting down");
                stop_reason = "sighup";
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
                stop_reason = "admin_shutdown";
                break;
            }
        }
    }
    // The links go with the agent from here on: the self-check stops
    // reporting them (a spurious signed bpf_link_missing otherwise).
    northnarrow_agent::anti_tamper::bpf_defense::mark_stopping();

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
    if stop_reason == "sensor_pump_exited" {
        // External audit SNS-001: a failure, not a clean stop.
        anyhow::bail!("a sensor pump exited; the agent stopped so the watchdog restarts it");
    }
    Ok(())
}

/// External audit SNS-001: how often the main loop checks that every
/// telemetry task still runs.
const PUMP_CHECK_PERIOD: Duration = Duration::from_secs(5);

/// `debug-trigger` builds only: a file `debug-abort-pump` next to the admin
/// socket, holding a pump label (`fs_protect`), aborts that pump; the next
/// liveness check then stops the agent. Lab check of SNS-001 without a
/// way to kill a task from outside the process.
#[cfg(feature = "debug-trigger")]
fn debug_abort_pump(
    sensor: &northnarrow_agent::sensors::SensorMultiplexer,
    admin_socket: &std::path::Path,
) {
    let Some(dir) = admin_socket.parent() else {
        return;
    };
    let trigger = dir.join("debug-abort-pump");
    let Ok(label) = std::fs::read_to_string(&trigger) else {
        return;
    };
    let _ = std::fs::remove_file(&trigger);
    let label = label.trim();
    let found = sensor.debug_abort_pump(label);
    warn!(
        pump = label,
        found, "debug-trigger: pump aborted on request (lab test of SNS-001)"
    );
}

/// External audit LLMR-002: at most one ADE evaluation in flight, off the
/// event loop.
static ADE_SLOT: std::sync::LazyLock<northnarrow_agent::ade::slot::AdeSlot> =
    std::sync::LazyLock::new(northnarrow_agent::ade::slot::AdeSlot::new);

/// Lab PR 162: the ADE evaluates an exec's `ProcessSpawn`; its `ExecCheck`
/// is held back, and goes to the ADE only when no spawn follows.
static ADE_EXECS: std::sync::LazyLock<northnarrow_agent::ade::exec_pairing::ExecPairing> =
    std::sync::LazyLock::new(northnarrow_agent::ade::exec_pairing::ExecPairing::new);

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
    ladder: &northnarrow_agent::combat::CombatLadder,
    canary_detector: Option<&northnarrow_agent::canary::detector::Detector>,
    // FIM-009 self-upgrade (§15.1): consulted for lazy TTL expiry.
    installer_override: &northnarrow_agent::anti_tamper::trusted_installer::TrustedInstallerOverride,
    // Tappa 9.0.a: detection-persistence sink. `None` ⇒ not persisting
    // this boot (e.g. signing key / store open failed at startup). All
    // record calls are off the hot path (bounded queue + writer task).
    detection_sink: Option<&northnarrow_agent::detection_store::DetectionSink>,
    event: Event,
) {
    // Tappa 10.9 step 2: an exec event's path made absolute before any
    // consumer reads it (review 61).
    let mut event = event;
    northnarrow_agent::sensors::exe_identity::resolve(&mut event);
    // FIM-009 self-upgrade (§15.1): lazy TTL expiry on the event path —
    // if a trusted-installer window has passed its deadline, close it
    // (re-engage the FS pin + audit) before handling this event. A cheap
    // no-op (a single atomic load) when no window is open. No timer:
    // detection already expires exactly at the deadline via the rule's
    // own is_window_open() read; this sweep re-syncs the kernel map.
    installer_override.close_if_expired(Instant::now());

    // External audit EBPF-001: while systemd stops the host, its SIGTERM to
    // the agent and the watchdog is refused until `systemd-shutdown` (the
    // units outlive their stop jobs). Expected, so neither an attempt nor a
    // posture signal.
    if let Event::FsProtectDenial {
        pid: 1,
        operation: common::FsProtectOperation::Signal,
        target_dev: sig,
        target_ino: target,
        ..
    } = &event
    {
        let state = systemd_state().await;
        if state.as_deref() == Some("stopping") {
            info!(
                signal = sig,
                target,
                "systemd is stopping the host — its signal to a protected process is refused \
                 until systemd-shutdown's final stage (expected, not an attempt)"
            );
            host_stopping(ladder);
            return;
        }
        info!(
            signal = sig,
            target,
            systemd_state = state.as_deref().unwrap_or("(no answer)"),
            "signal relayed by systemd outside a trusted-installer window — not a shutdown"
        );
    }

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
    // Lab PR 163: the close of a connection that tripped a network canary
    // belongs to the trip (its row is in the signed netflow log already);
    // judged again, NN-L-CHAIN-003 answered the one access a second time.
    if canary_detector.is_some_and(|d| d.owns_trip_flow(&event)) {
        debug!("close of a network canary trip connection — part of the trip, not judged again");
        return;
    }

    // Run posture detection BEFORE we push the focal event into the
    // correlation buffer — the trigger detector counts the focal as
    // a fresh +1 on top of `recent`, and `recent` already containing
    // the focal would double-count it.
    // Review 72: borrowed under the buffer's read lock, not cloned (up to
    // 1,000 events, for every event, was most of the agent's CPU under an
    // exec burst). Nothing pushes to the buffer until this returns.
    let host_stopping = HOST_STOPPING.load(std::sync::atomic::Ordering::SeqCst);
    if let Some((new_state, firing_trigger)) = (!host_stopping)
        .then(|| correlation.with_recent(|recent| posture.observe(&event, recent)))
        .flatten()
    {
        // BUG-015 observability: include the firing TriggerType so
        // operators can see in the journal what caused a transition.
        // `firing_trigger` is `Some` for any upward crossing and `None`
        // for same-tier re-arms; the latter case still gets a log line
        // because the kind() display alone is enough to follow state.
        warn!(
            state = %new_state.kind(),
            // External audit POS-001: a COMBAT reached on heuristics alone
            // is unlocked — no isolation, and it decays once quiet.
            locked = new_state.is_combat_locked(),
            trigger = ?firing_trigger,
            "POSTURE TRANSITION"
        );
        // On the non-Combat → Combat edge, enrich the ladder with the
        // offending PID + firing trigger. The combat-entry hook has
        // already opened the episode (STAGE 1 INVESTIGATE, network up);
        // this is the idempotent merge that attributes the focal
        // process. Reaching COMBAT does NOT isolate — the ladder does.
        if new_state.kind() == PostureKind::Combat {
            // External audit EBPF-001: init is never an offender — its only
            // containment would be ISOLATE, and the events it owns (a relayed
            // `systemctl`, the console writes of a shutdown) are not its own.
            // External audit CMB-004: with what the event says about the
            // offender (its start, a time it was running) — it identifies
            // the offender after it has exited.
            let (start_ns, seen_ns) =
                northnarrow_agent::posture::triggers::event_owner_seen(&event);
            ladder.engage_with(
                northnarrow_agent::posture::triggers::event_owner_pid(&event).filter(|p| *p > 1),
                start_ns,
                seen_ns,
                firing_trigger,
                Instant::now(),
            );
        }
    }
    // While a COMBAT episode is active, feed every event to the ladder
    // for the jump-ahead check: an offender actively exfiltrating or
    // spawning children DURING INVESTIGATE pre-empts the time-bound
    // deadline and advances straight to NEUTRALIZE.
    if !host_stopping && ladder.current_stage().is_some() {
        ladder.observe(&event, Instant::now());
    }
    correlation.push(event.clone());

    // Review 71: per-event lines for the frequent events (every exec,
    // every flow, every open) are DEBUG. At INFO, an exec burst made
    // journald rate-limit the agent and drop its other lines (boot, sensor
    // arming, verdict context), and every command line on the host, with
    // any secret in its arguments, was copied into the journal. Exec and
    // flow records live in the detection store and the signed netflow log.
    // External audit Wave 3 (journal line injection, lab PR 167): a value
    // another user names (comm, file name, DNS name, the rule text quoting
    // them) is logged through Escaped, quoted when it holds a separator.
    use common::log_escape::Escaped;
    match &event {
        Event::ProcessSpawn { .. } => debug!(event = ?event, "process spawn detected"),
        Event::ModuleLoad {
            method,
            loader_pid,
            loader_comm,
            path,
            ..
        } => info!(
            loader_pid = *loader_pid,
            loader_comm = %Escaped(loader_comm),
            method = ?method,
            path = path.as_deref().unwrap_or("none"),
            "kernel module load detected (BUG-034)"
        ),
        Event::IoUring {
            created,
            pid,
            comm,
            classes,
            count,
            sq_thread,
            ..
        } => info!(
            pid = *pid,
            comm = %Escaped(comm),
            created = *created,
            classes = ?common::io_uring_class_names(*classes),
            count = *count,
            sq_thread = *sq_thread,
            "io_uring activity"
        ),
        Event::BpfSyscall {
            pid,
            comm,
            cmd,
            arg,
            ..
        } => info!(
            pid = *pid,
            comm = %Escaped(comm),
            cmd = common::wire::bpf_cmd_name(*cmd),
            arg = *arg,
            "bpf() syscall by a non-protected process"
        ),
        Event::FileOpen {
            filename,
            comm,
            pid,
            ..
        } => {
            debug!(pid, comm = %Escaped(comm), filename = %Escaped(filename), "file open")
        }
        Event::MassWrite {
            pid,
            comm,
            count,
            filename,
            cgroup_window: true,
            ..
        } => info!(
            pid = *pid,
            comm = %Escaped(comm),
            overwrites = *count,
            last = %Escaped(filename),
            "mass write: overwrite threshold crossed by the processes of one cgroup (counted in the kernel)"
        ),
        Event::MassWrite {
            pid,
            comm,
            count,
            filename,
            ..
        } => info!(
            pid = *pid,
            comm = %Escaped(comm),
            count = *count,
            last = %Escaped(filename),
            "mass write: write-open threshold crossed (counted in the kernel)"
        ),
        Event::ExecCheck {
            filename,
            comm,
            pid,
            ..
        } => {
            debug!(pid, comm = %Escaped(comm), filename = %Escaped(filename), "exec_check")
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
                pid, comm = %Escaped(comm), family,
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
                pid, comm = %Escaped(comm),
                server = %render_addr(*family, dns_server),
                query = %Escaped(query_name),
                "dns_query"
            )
        }
        // Review 78: the rule (NN-L-NET-020) reports it.
        Event::DnsFlood {
            pid,
            comm,
            held,
            uid_level,
            ..
        } => debug!(pid, comm = %Escaped(comm), held, uid_level, "dns_flood"),
        // External audit EBPF-013: the rule (NN-L-NET-021) reports it.
        Event::SensorFlood {
            source,
            pid,
            comm,
            held,
            uid_level,
            ..
        } => debug!(
            pid,
            comm = %Escaped(comm),
            source = source.as_str(),
            held,
            uid_level,
            "sensor_flood"
        ),
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
            // Short-circuit: a kernel deny is not something the
            // rule engine or ADE LLM should re-evaluate. The
            // posture trigger above is the response. The attempt itself
            // is persisted as a signed detection (NN-L-AT-001, Log only:
            // the kernel already refused it) — the adversarial check found
            // refused attempts that left no record in the chain logs.
            use northnarrow_agent::decision::Rule as _;
            let verdict = northnarrow_agent::decision::rules::anti_tamper::NnLAt001AntiTamperDenial
                .evaluate(&event);
            // Review 75: a loop of denied attempts is logged and stored
            // within the rule's budget for that uid.
            let admit = match &verdict {
                Some(v) => budget_admit(&v.rule_id, *uid, &event),
                None => Admit::Record {
                    suppressed_before: 0,
                },
            };
            if admit.record() {
                warn!(
                    pid, uid, comm = %Escaped(comm),
                    op = %operation,
                    target_dev, target_ino,
                    "ANTI-TAMPER DENIAL"
                );
            }
            if let Some(verdict) = verdict {
                if let Admit::Record { suppressed_before } = admit {
                    warn!(
                        rule = %verdict.rule_id,
                        severity = ?verdict.severity,
                        reasoning = %Escaped(&verdict.reasoning),
                        "VERDICT (rule)"
                    );
                    if let Some(sink) = detection_sink {
                        sink.record_rule(
                            &event,
                            &verdict,
                            posture.current_kind(),
                            "denied in kernel (anti-tamper LSM hook)".to_string(),
                            suppressed_before,
                        );
                    }
                }
            }
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
            // BUG-012 (v2): a read (op=Opened) is NOT an integrity
            // drift, so it must never be logged as "FIM DRIFT" — that
            // is semantically wrong and just quieter noise. An Opened
            // event reaches this arm ONLY for a credential path the
            // FIM drain forwarded for the NN-L-FIM-011..017 read rules
            // (every other read is dropped at the drain). It flows
            // silently to `engine.evaluate` below; if a cred-read rule
            // fires, THE RULE emits the alert with proper framing.
            // Only integrity-changing ops get the FIM DRIFT line.
            if fe.op == common::wire::FimOp::Opened {
                debug!(
                    path = %Escaped(&fe.path),
                    modifier_pid = fe.modifier_pid,
                    modifier_comm = %Escaped(&fe.modifier_comm),
                    "fim credential-path read forwarded to rule engine (not drift)"
                );
            } else if budget_admit("FIM-DRIFT", fe.modifier_uid, &event).record() {
                // Review 76: every drift now reaches the rules; its journal
                // line has the per-uid budget (the signed fim_drift.jsonl
                // row is always written).
                warn!(
                    path = %Escaped(&fe.path),
                    op = ?fe.op,
                    modifier_pid = fe.modifier_pid,
                    modifier_uid = fe.modifier_uid,
                    modifier_comm = %Escaped(&fe.modifier_comm),
                    "FIM DRIFT"
                );
            }
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
                canary_name = %Escaped(canary_name),
                canary_type = ?canary_type,
                access_kind = ?access_kind,
                accessor_pid = %accessor_pid,
                accessor_uid = %accessor_uid,
                accessor_comm = %Escaped(accessor_comm),
                "CANARY TRIPPED"
            );
        }
        // Tappa 10 (N6) — minimal logging arms; the N3 flow
        // tracker + N2 listener kprobe feed these into the rule
        // engine below. Full drain wiring is a follow-up commit.
        Event::NetFlow(nf) => {
            debug!(
                pid = %nf.pid,
                comm = %Escaped(&nf.comm),
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
                comm = %Escaped(&nl.comm),
                bind_addr = %nl.bind_addr,
                bind_port = %nl.bind_port,
                "net listener"
            );
        }
    }

    // Lab PR 162: a ProcessSpawn settles its exec's held-back ExecCheck,
    // whatever the rules make of it; then the checks nothing settled
    // within the grace go to the ADE on their own (the pump check sweeps
    // them too, for a quiet host).
    if let Some(ade) = ade {
        ADE_EXECS.note_spawn(&event, Instant::now());
        escalate_unsettled_exec_checks(ade, executor, posture, correlation, host, detection_sink);
    }

    if let Some(verdict) = engine.evaluate(&event) {
        // Review 75: every verdict is acted on; its log lines and its
        // record count against the rule's budget for the acting uid.
        let uid = northnarrow_agent::detection_store::Principal::from_event(&event).uid;
        let admit = budget_admit(&verdict.rule_id, uid, &event);
        if admit.record() {
            warn!(
                rule = %verdict.rule_id,
                rule_name = %verdict.rule_name,
                category = %verdict.category,
                action = ?verdict.action,
                severity = ?verdict.severity,
                target_pid = verdict.event_pid,
                target_filename = %Escaped(&verdict.event_filename),
                reasoning = %Escaped(&verdict.reasoning),
                "VERDICT (rule)"
            );
        }

        let exec = executor.clone();
        let action = verdict.action.clone();
        let target_pid = verdict.event_pid;
        let target_file = verdict.event_filename.clone();
        // External audit CMB-004: what the event says about the process
        // the verdict is about — its start (an exec), the event's time — so
        // a kill does not reach a process that took the PID after the event.
        let (target_start_ns, target_seen_ns) =
            if northnarrow_agent::posture::triggers::event_owner_pid(&event) == Some(target_pid) {
                northnarrow_agent::posture::triggers::event_owner_seen(&event)
            } else {
                (0, 0)
            };
        // A Log verdict runs nothing: no blocking task for it.
        let report = if matches!(action, common::ResponseAction::Log) {
            exec.execute(action, target_pid)
        } else {
            match tokio::task::spawn_blocking(move || {
                exec.execute_for_started(
                    action,
                    target_pid,
                    target_start_ns,
                    target_seen_ns,
                    &target_file,
                )
            })
            .await
            {
                Ok(r) => r,
                Err(e) => {
                    warn!(error = %e, "executor task join failed");
                    return;
                }
            }
        };

        if let Admit::Record { suppressed_before } = admit {
            info!(
                action = ?report.action,
                primary = ?report.primary,
                additional_count = report.additional.len(),
                elapsed_us = report.elapsed.as_micros() as u64,
                "EXECUTED"
            );
            // Tappa 9.0.a: persist the rule detection (off the hot path).
            if let Some(sink) = detection_sink {
                sink.record_rule(
                    &event,
                    &verdict,
                    posture.current_kind(),
                    northnarrow_agent::detection_store::describe_response(&report),
                    suppressed_before,
                );
            }
        }
        return;
    }

    let Some(ade) = ade else {
        return;
    };

    // Only execs warrant ADE evaluation today; FileOpen / TCP / DNS
    // volumes are too high to feed the LLM and they don't have an
    // immediate executor mapping anyway. Lab PR 162: an exec is evaluated
    // as its ProcessSpawn (the child's comm, argv and file); its ExecCheck,
    // read first with the parent's comm, used to take the only slot.
    let Some(event) = ADE_EXECS.admit(event, Instant::now()) else {
        return;
    };

    debug!("no rule matched, escalating to ADE");
    escalate_to_ade(
        ade,
        executor,
        posture,
        correlation,
        host,
        detection_sink,
        event,
    );
}

/// Lab PR 162: the held-back `ExecCheck`s no `ProcessSpawn` settled (an
/// exec that did not complete, or a lost spawn), each offered to the ADE.
fn escalate_unsettled_exec_checks(
    ade: &AdeEngine,
    executor: &Executor,
    posture: &PostureMachine,
    correlation: &CorrelationBuffer,
    host: &HostContext,
    detection_sink: Option<&northnarrow_agent::detection_store::DetectionSink>,
) {
    for event in ADE_EXECS.take_unsettled(Instant::now()) {
        debug!(
            event = ?event,
            "exec check with no process spawn within the grace — offered to ADE on its own"
        );
        escalate_to_ade(
            ade,
            executor,
            posture,
            correlation,
            host,
            detection_sink,
            event,
        );
    }
}

/// Offer `event` to the ADE's evaluation slot.
fn escalate_to_ade(
    ade: &AdeEngine,
    executor: &Executor,
    posture: &PostureMachine,
    correlation: &CorrelationBuffer,
    host: &HostContext,
    detection_sink: Option<&northnarrow_agent::detection_store::DetectionSink>,
    event: Event,
) {
    // External audit LLMR-002: the evaluation leaves the event loop, one
    // at a time (`AdeSlot`). Awaited here, an exec no rule matched held
    // every sensor for up to the inference timeout.
    let (ade, executor, posture) = (ade.clone(), executor.clone(), posture.clone());
    let (correlation, host) = (correlation.clone(), host.clone());
    let detection_sink = detection_sink.cloned();
    ADE_SLOT.try_spawn(async move {
        // External audit XAI-013: the correlated context is selected on the
        // evaluation's task. The selection sanitizes its candidates (about
        // 50 µs each), too slow for every exec on the event loop; an exec
        // skipped while ADE is busy costs nothing. Events pushed after the
        // focal one are not selected, as when it ran at once.
        let context = EventContext {
            recent_events: correlation.get_correlated_default(&event),
            host_context: host,
        };
        evaluate_and_respond(
            &ade,
            &executor,
            &posture,
            detection_sink.as_ref(),
            event,
            context,
        )
        .await;
    });
}

/// External audit LLMR-002: one ADE evaluation and the response to its
/// verdict, on its own task (see [`ADE_SLOT`]).
async fn evaluate_and_respond(
    ade: &AdeEngine,
    executor: &Executor,
    posture: &PostureMachine,
    detection_sink: Option<&northnarrow_agent::detection_store::DetectionSink>,
    event: Event,
    context: EventContext,
) {
    info!("ADE inference started");
    let verdict = match ade.evaluate(&event, &context).await {
        Ok(v) => v,
        // External audit LLMR-003: a timeout or a backend error is recorded
        // as an Escalate (`ade_unavailable`), with no response. It used to
        // leave only this journal line: an event the model never judged
        // left no detection.
        Err(e) => {
            warn!(?e, "ADE error, recording an Escalate with no response");
            ade.escalate_for_error(&event, &e)
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
        // Wave 3 (lab PR 167): the model's text, written from attacker strings.
        reasoning = %common::log_escape::Escaped(&verdict.reasoning.step_5_decision),
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

    use northnarrow_agent::ade::advisory::{self, Disposition};
    let disposition = advisory::disposition(&verdict, advisory::enforce());
    if disposition == Disposition::Record {
        info!(action = %verdict.verdict, "ADE verdict logged, no execution needed");
        // Tappa 9.0.a: persist non-benign ADE verdicts even when no
        // response runs. `Allow` is benign ⇒ not a detection.
        if let Some(sink) = detection_sink {
            if verdict.verdict != common::ade_types::AdeAction::Allow {
                let uid = northnarrow_agent::detection_store::Principal::from_event(&event).uid;
                if let Admit::Record { suppressed_before } = budget_admit("ADE", uid, &event) {
                    sink.record_ade(
                        &event,
                        &verdict,
                        posture.current_kind(),
                        "none".to_string(),
                        suppressed_before,
                    );
                }
            }
        }
        return;
    }

    // Lab PR 134: the ADE is a consultant. A verdict that names a response
    // is recorded as a recommendation — its reasoning in the detection —
    // and nothing runs: the model's input is attacker-written strings.
    // `NN_ADE_ENFORCE=1` (a signed weakening) lets it act.
    if disposition == Disposition::Recommend {
        warn!(
            recommended = %verdict.verdict,
            trace_id = %verdict.trace_id,
            "ADE advisory: the model recommends a response — recorded, not executed"
        );
        if let Some(sink) = detection_sink {
            let uid = northnarrow_agent::detection_store::Principal::from_event(&event).uid;
            if let Admit::Record { suppressed_before } = budget_admit("ADE", uid, &event) {
                sink.record_ade(
                    &event,
                    &verdict,
                    posture.current_kind(),
                    advisory::recommended(&verdict),
                    suppressed_before,
                );
            }
        }
        return;
    }

    let exec = executor.clone();
    let action = verdict.to_response_action();
    // External audit CMB-004: the verdict comes back seconds after the
    // event (the model's evaluation): the kill checks the process against
    // what the event says (its exec's start, or the event's time), so it
    // does not reach a process that took the PID meanwhile.
    let target_pid = match &event {
        Event::ProcessSpawn { pid, .. } | Event::ExecCheck { pid, .. } => *pid,
        _ => return,
    };
    let (target_start_ns, target_seen_ns) =
        northnarrow_agent::posture::triggers::event_owner_seen(&event);
    let report = match tokio::task::spawn_blocking(move || {
        exec.execute_started(action, target_pid, target_start_ns, target_seen_ns)
    })
    .await
    {
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
    // Tappa 9.0.a: persist the ADE detection (a response ran ⇒ non-benign).
    if let Some(sink) = detection_sink {
        let uid = northnarrow_agent::detection_store::Principal::from_event(&event).uid;
        if let Admit::Record { suppressed_before } = budget_admit("ADE", uid, &event) {
            sink.record_ade(
                &event,
                &verdict,
                posture.current_kind(),
                northnarrow_agent::detection_store::describe_response(&report),
                suppressed_before,
            );
        }
    }
}

/// [`detection_budget::admit`], plus one WARN when a (rule, uid) runs out
/// of budget (review 75). The counts of what it held back reach the
/// journal and the audit log through the budget's reporter task.
fn budget_admit(rule: &str, uid: u32, event: &Event) -> Admit {
    let admit = detection_budget::admit(rule, uid, || {
        northnarrow_agent::detection_store::held_sample(event)
    });
    if admit == (Admit::Hold { first: true }) {
        warn!(
            rule,
            uid,
            burst = detection_budget::BURST,
            "detections of this rule and uid exceed the record budget: further ones are acted on \
             and counted, one per second is logged and stored, until the rate falls"
        );
    }
    admit
}

/// Render a 16-byte address according to family (`2` = AF_INET → first
/// 4 bytes; `10` = AF_INET6 → full v6).
fn render_addr(family: u8, bytes: &[u8; 16]) -> String {
    // External audit NET-001: one form in the logs, IPv4-mapped folded.
    if family == 2 || family == 10 {
        common::netaddr::canonical_ip(family, bytes).to_string()
    } else {
        format!("family={family}")
    }
}

/// Construct the single shared [`AdeEngine`], applying the optional
/// env-driven RAG overlay. Returns `None` (rule-only fallback) if the
/// model fails to load. A RAG canary that was requested but refused
/// leaves its reason in `rag_refused`, for the signed audit log.
///
/// Sub-tappa 6.8 audit: this is the ONLY `AdeEngine::new` call in the
/// agent's hot path — model weights, tokenizer, KV state machine and
/// the rayon pool are loaded ONCE at startup and the resulting handle
/// is shared into `process_event` via `Arc<AdeEngine>` (cheap to
/// clone). Any future change that constructs a new engine inside the
/// event loop would silently re-pay the ~5 GiB GGUF mmap and the
/// warmup pass, so guard this invariant in review.
async fn load_ade_engine(
    cfg: AdeConfig,
    rag_refused: &mut Option<String>,
) -> Option<Arc<AdeEngine>> {
    match AdeEngine::new(cfg).await {
        Ok(engine) => {
            info!(
                backend = engine.backend_name(),
                model_path = %engine.config().model_path.display(),
                warmup_latency_ms = engine.warmup_latency_ms(),
                timeout_s = engine.config().timeout.as_secs(),
                advisory = !northnarrow_agent::ade::advisory::enforce(),
                "ADE engine ready"
            );
            // Tappa 6.9.7 P5 — env-driven RAG canary (default OFF;
            // graceful no-RAG fallback). Uses the existing 6.7
            // `with_rag` seam; logging is inside `open_index_from_env`.
            // External audit XAI-001/XAI-009: only the pinned corpus opens.
            let canary = northnarrow_agent::rag::open_index_from_env();
            *rag_refused = canary.refusal().map(str::to_string);
            let engine = match canary.into_engine() {
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
}

/// External audit MAIN-001: remove a former watchdog pid from
/// PROTECTED_PIDS unless it still runs the watchdog binary.
/// `pid` runs the watchdog binary at `watchdog_exe` (same file identity).
fn runs_watchdog_binary(pid: u32, watchdog_exe: &std::path::Path) -> bool {
    use northnarrow_agent::anti_tamper::ExeIdentity;
    let watchdog = ExeIdentity::of_file(watchdog_exe);
    watchdog.is_some() && ExeIdentity::of_process(pid) == watchdog
}

fn withdraw_watchdog_pid(
    bpffs_root: Option<&std::path::Path>,
    pid: u32,
    watchdog_exe: &std::path::Path,
) {
    use northnarrow_agent::anti_tamper::ExeIdentity;
    let watchdog = ExeIdentity::of_file(watchdog_exe);
    if watchdog.is_some() && ExeIdentity::of_process(pid) == watchdog {
        warn!(
            pid,
            "the watchdog pidfile no longer names the running watchdog — keeping it protected"
        );
        return;
    }
    match northnarrow_agent::anti_tamper::evict_protected_pid(bpffs_root, pid) {
        Ok(()) => info!(pid, "former watchdog pid removed from PROTECTED_PIDS"),
        Err(e) => {
            warn!(pid, error = %e, "could not remove a former watchdog pid from PROTECTED_PIDS")
        }
    }
}

/// External audit CMB-006: the removal of an older agent's host-wide
/// nftables isolation at start is recorded in the signed audit chain.
fn attest_legacy_isolation_removed(
    audit_log: Option<&Arc<parking_lot::Mutex<northnarrow_agent::audit::AuditLog>>>,
) {
    let Some(log) = audit_log else {
        return;
    };
    let draft = northnarrow_agent::audit::AuditEntryDraft {
        op: northnarrow_agent::self_integrity::AUDIT_OP.to_string(),
        extra: serde_json::json!({
            "kind": "legacy_isolation_removed",
            "detail": "an older agent's nftables isolation chains (isolation_input, \
                       isolation_output) were found at start and removed",
            "at_boot": true,
        }),
        key_fp: "agent-self".to_string(),
        cosigner_fps: Vec::new(),
        result: "repaired".to_string(),
        client_pid: std::process::id(),
        client_uid: 0,
        client_comm: "northnarrow-agent".to_string(),
        client_exe: None,
    };
    if let Err(e) = log.lock().append(draft) {
        warn!(error = %e, "recording the removed legacy isolation failed");
    }
}

/// External audit FIMR-008: record the boot id the agent runs under, in
/// the immutable state directory — lifted as the log rotation lifts it —
/// and protected against foreign writes as the logs there are.
fn record_boot_id(
    protection: Option<&northnarrow_agent::anti_tamper::filesystem::StateDirProtection>,
    dir: &std::path::Path,
    now: &str,
) {
    use northnarrow_agent::chainlog::ProtectionManager;
    use northnarrow_agent::fim::honeypot;
    let file = dir.join(honeypot::BOOT_ID_FILE);
    let written = match protection {
        Some(p) => {
            if file.exists() {
                // The renamed-over inode leaves the protected set.
                let _ = p.release(&file);
            }
            p.with_mutable_dir(&mut || {
                honeypot::write_boot_id(dir, now).map_err(anyhow::Error::from)
            })
            .and_then(|()| p.register_active(&file))
        }
        None => honeypot::write_boot_id(dir, now).map_err(anyhow::Error::from),
    };
    if let Err(e) = written {
        warn!(
            error = %format!("{e:#}"),
            "recording the boot id failed — the next start will judge missing runtime \
             control-surface files as after a reboot"
        );
    }
}

/// External audit FIMR-008: control-surface files missing, replaced or
/// unrestorable at boot — removed while the agent was not running, or a
/// tmpfs one within the same boot — recorded in the signed audit chain.
fn attest_bait_integrity(
    audit_log: Option<&Arc<parking_lot::Mutex<northnarrow_agent::audit::AuditLog>>>,
    report: &northnarrow_agent::fim::honeypot::HoneypotIntegrityReport,
    rebooted: bool,
) {
    let Some(log) = audit_log else {
        return;
    };
    let draft = northnarrow_agent::audit::AuditEntryDraft {
        op: northnarrow_agent::self_integrity::AUDIT_OP.to_string(),
        extra: serde_json::json!({
            "kind": "bait_missing_at_boot",
            "recreated": report.recreated,
            "replaced": report.replaced,
            "unrestorable": report.failed,
            "rebooted": rebooted,
            "at_boot": true,
        }),
        key_fp: "agent-self".to_string(),
        cosigner_fps: Vec::new(),
        result: "detected".to_string(),
        client_pid: std::process::id(),
        client_uid: 0,
        client_comm: "northnarrow-agent".to_string(),
        client_exe: None,
    };
    if let Err(e) = log.lock().append(draft) {
        warn!(error = %e, "recording the control-surface file check failed");
    }
}

/// External audit DEC-010: a decoy found at boot in a state other than
/// the one recorded, in the signed audit chain: `integrity_drift`
/// (`canary_decoy_missing`, or `canary_decoy_tampered` for a decoy
/// modified, replaced by something not a regular file, or unreadable), and
/// `integrity_drift_cleared` when it is intact again.
fn attest_decoy_state(
    audit_log: Option<&Arc<parking_lot::Mutex<northnarrow_agent::audit::AuditLog>>>,
    canary: &northnarrow_agent::canary::registry::CanaryLiveState,
    path: &str,
    check: &northnarrow_agent::canary::registry::DecoyCheck,
) {
    use northnarrow_agent::canary::registry::DecoyState;
    let Some(log) = audit_log else {
        return;
    };
    let kind = |s: DecoyState| match s {
        DecoyState::Missing => "canary_decoy_missing",
        _ => "canary_decoy_tampered",
    };
    let (op, kind, result) = if check.state == DecoyState::Intact {
        (
            northnarrow_agent::self_integrity::CLEARED_OP,
            kind(canary.decoy_state),
            "cleared",
        )
    } else {
        (
            northnarrow_agent::self_integrity::AUDIT_OP,
            kind(check.state),
            "detected",
        )
    };
    let draft = northnarrow_agent::audit::AuditEntryDraft {
        op: op.to_string(),
        extra: serde_json::json!({
            "kind": kind,
            "canary_id": canary.canary_id,
            "name": canary.name,
            "path": path,
            "state": check.state.as_str(),
            "recorded_state": canary.decoy_state.as_str(),
            "expected_sha256": canary.content.as_ref().map(|c| c.contents_sha256.as_str()),
            "found_sha256": check.found_sha256,
            "at_boot": true,
        }),
        key_fp: "agent-self".to_string(),
        cosigner_fps: Vec::new(),
        result: result.to_string(),
        client_pid: std::process::id(),
        client_uid: 0,
        client_comm: "northnarrow-agent".to_string(),
        client_exe: None,
    };
    if let Err(e) = log.lock().append(draft) {
        warn!(error = %e, "recording the decoy check failed");
    }
}

/// External audit MAIN-003: a subsystem running degraded is recorded in
/// the signed audit chain, not only in the journal.
fn attest_degraded(
    audit_log: Option<&Arc<parking_lot::Mutex<northnarrow_agent::audit::AuditLog>>>,
    detail: &str,
) {
    attest_degraded_at(audit_log, detail, true);
}

/// [`attest_degraded`] for a subsystem that stopped after boot (external
/// audit MAIN-007: a drain loop that returns ends a telemetry stream for
/// the rest of the run).
fn attest_degraded_at(
    audit_log: Option<&Arc<parking_lot::Mutex<northnarrow_agent::audit::AuditLog>>>,
    detail: &str,
    at_boot: bool,
) {
    let Some(log) = audit_log else {
        return;
    };
    let draft = northnarrow_agent::audit::AuditEntryDraft {
        op: northnarrow_agent::self_integrity::AUDIT_OP.to_string(),
        extra: serde_json::json!({ "kind": "subsystem_degraded", "detail": detail, "at_boot": at_boot }),
        key_fp: "agent-self".to_string(),
        cosigner_fps: Vec::new(),
        result: "detected".to_string(),
        client_pid: std::process::id(),
        client_uid: 0,
        client_comm: "northnarrow-agent".to_string(),
        client_exe: None,
    };
    if let Err(e) = log.lock().append(draft) {
        warn!(error = %e, "attesting a degraded subsystem failed");
    }
}

/// A drain loop returned: its telemetry stream is gone for the rest of
/// this run. Per-event errors never end a drain (they are logged and the
/// loop goes on), so this is a tokio I/O failure — recorded in the signed
/// chain, not only as a journal line (external audit MAIN-007).
fn drain_ended(
    stream: &str,
    outcome: std::io::Result<()>,
    audit_log: Option<&Arc<parking_lot::Mutex<northnarrow_agent::audit::AuditLog>>>,
) {
    let why = match outcome {
        Ok(()) => "returned".to_string(),
        Err(e) => format!("failed: {e}"),
    };
    error!(
        stream,
        reason = %why,
        "drain loop ended — this telemetry stream stops until the agent restarts"
    );
    attest_degraded_at(
        audit_log,
        &format!("{stream} drain loop ended ({why}): no {stream} telemetry until restart"),
        false,
    );
}

/// External audit LLMR-016: a default list that could not be read, and
/// gave way to the copy built into the agent, is recorded in the signed
/// chain through the overlay gate (queued until the audit log is open);
/// LLMR-015 (NN-AUD-327): so is one edited by hand, which is not applied.
/// An earlier release's list, superseded by the built-in copy, is a WARN
/// only: what is in force is what shipped.
fn report_builtin_defaults(
    gate: &northnarrow_agent::config::overlay_auth::OverlayGate,
    list: &str,
    v1: &std::path::Path,
    source: &northnarrow_agent::config::overlay::DefaultsSource,
) {
    use northnarrow_agent::config::overlay::DefaultsSource;
    match source {
        DefaultsSource::BuiltIn(why) => gate.report_default_unavailable(list, v1, why),
        DefaultsSource::Modified {
            sha256,
            builtin_sha256,
            loaded_anyway,
        } => gate.report_default_modified(list, v1, sha256, builtin_sha256, *loaded_anyway),
        DefaultsSource::Disk | DefaultsSource::Superseded { .. } => {}
    }
}

/// Lab PR 160: the head anchor of this run, written once now with the heads
/// this boot found (before this boot appends anything). Reports a removed
/// anchor first ([`northnarrow_agent::chain_anchor::BootCheck::heads_missing`]).
fn start_chain_anchor(
    cli: &Cli,
    heads_file: &std::path::Path,
    targets: &[northnarrow_agent::chain_anchor::ChainTarget],
    boot: &mut northnarrow_agent::chain_anchor::BootCheck,
    agent_id: [u8; 16],
    log: &northnarrow_agent::audit::AuditLog,
) -> Option<Arc<parking_lot::Mutex<northnarrow_agent::chain_anchor::Anchor>>> {
    boot.heads_missing(heads_file, log.anchoring_started());
    let key =
        match northnarrow_agent::audit::AgentSigningKey::load_or_bootstrap(&cli.signing_key_file) {
            Ok(k) => k,
            Err(e) => {
                warn!(
                    error = format!("{e:#}"),
                    "chain heads: no signing key — heads not anchored"
                );
                return None;
            }
        };
    let mut anchor = northnarrow_agent::chain_anchor::Anchor::new(
        heads_file.to_path_buf(),
        key,
        agent_id,
        targets.to_vec(),
        boot.previous.clone(),
        log.anchoring_started(),
    );
    let second = log.second_key_added() || boot.second_key_added();
    match anchor.refresh(true, second) {
        Ok(_) => info!(path = %heads_file.display(), "chain heads anchored at start"),
        Err(e) => warn!(
            error = format!("{e:#}"),
            path = %heads_file.display(),
            "chain heads: not anchored at start (retried every few minutes)"
        ),
    }
    Some(Arc::new(parking_lot::Mutex::new(anchor)))
}

/// Lab PR 160: what a chain's open verification found (external audit
/// NN-AUD-174), in the signed audit chain.
fn attest_chain_findings(
    audit_log: Option<&Arc<parking_lot::Mutex<northnarrow_agent::audit::AuditLog>>>,
    findings: Vec<northnarrow_agent::chain_anchor::ChainFinding>,
) {
    if findings.is_empty() {
        return;
    }
    let mut guard = audit_log.map(|l| l.lock());
    for f in &findings {
        f.attest(guard.as_deref_mut());
    }
}

/// External audit DEC-006 / NET-003: what a chain log's open repaired or
/// skipped is recorded in the signed audit chain.
fn attest_open_findings(
    audit_log: Option<&Arc<parking_lot::Mutex<northnarrow_agent::audit::AuditLog>>>,
    file: &std::path::Path,
    (repair, skipped): (Option<northnarrow_agent::chainlog::TailRepair>, usize),
) {
    let Some(log) = audit_log else {
        return;
    };
    let mut log = log.lock();
    if let Some(r) = repair {
        if let Err(e) = log.attest_tail_repair(file, &r) {
            warn!(error = %e, file = %file.display(), "attesting a chain repair failed");
        }
    }
    if skipped > 0 {
        if let Err(e) = log.attest_skipped_lines(file, skipped) {
            warn!(error = %e, file = %file.display(), "attesting skipped chain lines failed");
        }
    }
}

/// Beta Step 3: background task that keeps the watchdog PID slot of
/// `exempt` in sync with the live, exe-verified watchdog.
///
/// Re-resolves every 30 s (the first tick fires immediately so the
/// exemption activates as soon as the watchdog publishes its pidfile).
/// Logs only on a *change* of verified PID so a steady state doesn't
/// flood the journal; any non-`Verified` outcome clears the exemption
/// (fail toward over-triggering).
/// External audit EBPF-001: systemd (PID 1 itself, `SO_PEERCRED`) reported
/// the host as stopping — no posture escalation and no ladder until the
/// process ends at systemd-shutdown's final stage.
static HOST_STOPPING: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// External audit CMB-012: how long the COMBAT release waits for the
/// ladder's queued steps (a NEUTRALIZE of a large tree takes seconds)
/// before it lifts the isolation anyway.
const LADDER_RELEASE_WAIT: std::time::Duration = std::time::Duration::from_secs(30);

/// The host is shutting down: stand the ladder down once and stop
/// escalating (see [`HOST_STOPPING`]).
fn host_stopping(ladder: &northnarrow_agent::combat::CombatLadder) {
    if !HOST_STOPPING.swap(true, std::sync::atomic::Ordering::SeqCst) {
        warn!("host shutting down — active response stood down, detection continues");
        ladder.stand_down(Instant::now());
    }
}

/// What systemd reports the host as (`SystemState`: `running`,
/// `degraded`, `stopping`, …), asked over its private socket from this
/// process ([`northnarrow_agent::systemd_state`]) — only for a signal PID 1
/// relayed and the kernel refused, and every 2 s by the shutdown watch;
/// at most once a second. `None` when
/// systemd does not answer within 1 s, or the socket is not served by
/// PID 1.
async fn systemd_state() -> Option<String> {
    static LAST: parking_lot::Mutex<Option<(Instant, Option<String>)>> =
        parking_lot::Mutex::new(None);
    if let Some((at, state)) = LAST.lock().clone() {
        if at.elapsed() < Duration::from_secs(1) {
            return state;
        }
    }
    let ask = tokio::task::spawn_blocking(|| {
        northnarrow_agent::systemd_state::system_state(
            std::path::Path::new(northnarrow_agent::systemd_state::PRIVATE_SOCKET),
            Duration::from_millis(800),
        )
    });
    let state = match tokio::time::timeout(Duration::from_secs(1), ask).await {
        Ok(Ok(Ok(state))) => Some(state),
        Ok(Ok(Err(e))) => {
            debug!(error = %e, "systemd's state could not be read");
            None
        }
        _ => None,
    };
    *LAST.lock() = Some((Instant::now(), state.clone()));
    state
}

/// PID 1 is `systemd-shutdown` (its comm, truncated to 15 bytes): the
/// machine is in the last stage of a shutdown.
fn pid1_is_systemd_shutdown() -> bool {
    std::fs::read_to_string("/proc/1/comm").is_ok_and(|c| c.trim_end() == "systemd-shutdow")
}

/// External audit EBPF-001: re-record `systemd-shutdown`'s identity every
/// minute (a package upgrade gives it a new inode).
fn spawn_shutdown_exe_refresh() {
    let Some(root) = northnarrow_agent::anti_tamper::prepare_pin_root() else {
        return;
    };
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_secs(60));
        loop {
            tick.tick().await;
            match northnarrow_agent::anti_tamper::refresh_shutdown_exe(root) {
                Ok(Some(k)) => info!(
                    dev = k.dev,
                    ino = k.ino,
                    "anti-tamper: systemd-shutdown changed on disk — final-stage identity updated"
                ),
                Ok(None) => {}
                Err(e) => warn!(
                    error = format!("{e:#}"),
                    "anti-tamper: SHUTDOWN_EXE refresh failed"
                ),
            }
        }
    });
}

fn spawn_watchdog_exempt_refresh(exempt: ExemptPids, pidfile: PathBuf, expected_exe: PathBuf) {
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_secs(30));
        // Last verified PID we stored (`None` == exemption cleared).
        let mut last: Option<u32> = None;
        // A pid the pidfile named while the registered watchdog ran (logged once).
        let mut refused: Option<u32> = None;
        // BUG-011 (PHASE 15.1): resolve the bpffs root once. None ⇒
        // no bpffs ⇒ register_protected_observer is a no-op (it
        // logs the degraded mode internally).
        let bpffs_root = northnarrow_agent::anti_tamper::prepare_pin_root();
        loop {
            tick.tick().await;
            let resolution = resolve_verified_watchdog_pid(&pidfile, &expected_exe);
            let new_pid = match &resolution {
                WatchdogResolution::Verified { pid, .. } => Some(*pid),
                _ => None,
            };
            if new_pid == last {
                // External audit POS-009: the posture exemption follows the
                // start of the process verified now (a restart that drew the
                // same PID).
                if let WatchdogResolution::Verified { pid, start_ticks } = &resolution {
                    exempt.set_watchdog(*pid, *start_ticks);
                }
                continue; // no change — stay quiet on the hot path
            }
            // External audit EBPF-002: one watchdog at a time. While the
            // registered watchdog still runs, a pidfile naming another
            // process — even one running the watchdog binary, possibly with
            // LD_PRELOAD — is not protected: rewritten or mounted over, it
            // would hand a root shell's process the agent's maps.
            if let (Some(prev), Some(p)) = (last, new_pid) {
                if runs_watchdog_binary(prev, &expected_exe) {
                    if refused != Some(p) {
                        warn!(
                            registered = prev,
                            named = p,
                            "the watchdog pidfile names another process while the registered \
                             watchdog runs — not protected"
                        );
                        refused = Some(p);
                    }
                    continue;
                }
            }
            // External audit MAIN-001: PROTECTED_PIDS follows the verified
            // watchdog. The previous pid leaves it once it no longer runs
            // the watchdog binary (dead, or recycled by another program);
            // a deleted or rewritten pidfile alone does not unprotect the
            // watchdog that still runs.
            if let Some(prev) = last {
                withdraw_watchdog_pid(bpffs_root, prev, &expected_exe);
            }
            if let Some(p) = new_pid {
                if let Err(e) =
                    northnarrow_agent::anti_tamper::register_protected_pid(bpffs_root, p)
                {
                    warn!(watchdog_pid = p, error = %e, "PROTECTED_PIDS register of the verified watchdog failed");
                }
                // External audit EBPF-002: the verified watchdog is the
                // live one — no second watchdog binary may load beside it.
                if let Err(e) = northnarrow_agent::anti_tamper::claim_watchdog_role(bpffs_root, p) {
                    debug!(watchdog_pid = p, error = %e, "watchdog role not recorded");
                }
            }
            match &resolution {
                WatchdogResolution::Verified {
                    pid: p,
                    start_ticks,
                } => {
                    // External audit POS-009: with its start time — the
                    // exemption ends with that process, not with its PID.
                    exempt.set_watchdog(*p, *start_ticks);
                    // BUG-011: register the verified watchdog PID
                    // in PROTECTED_OBSERVERS so the kernel
                    // ptrace_access_check hook allows it to read
                    // /proc/<agent>/exe (the watchdog's argv
                    // reconstruction path). Eviction of the prior
                    // verified PID (if any) happens first to keep
                    // the map's set semantics tight — a watchdog
                    // restart with a new PID otherwise leaves the
                    // old PID lingering for whatever else might
                    // recycle it.
                    if let Some(prev) = last {
                        if let Err(e) = northnarrow_agent::anti_tamper::evict_protected_observer(
                            bpffs_root, prev,
                        ) {
                            warn!(
                                pid = prev,
                                error = %e,
                                "BUG-011: failed to evict prior watchdog PID from \
                                 PROTECTED_OBSERVERS (continuing; new PID will still register)"
                            );
                        }
                    }
                    match northnarrow_agent::anti_tamper::register_protected_observer(
                        bpffs_root, *p,
                    ) {
                        Ok(()) => info!(
                            watchdog_pid = *p,
                            start_ticks = *start_ticks,
                            exe = %expected_exe.display(),
                            "watchdog PID verified; exempting it from posture triggers + \
                             registering in PROTECTED_OBSERVERS (BUG-011)"
                        ),
                        Err(e) => warn!(
                            watchdog_pid = *p,
                            error = %e,
                            "BUG-011: PROTECTED_OBSERVERS register failed; watchdog \
                             will still be posture-exempt but ptrace_access_check will deny"
                        ),
                    }
                }
                WatchdogResolution::NotPresent => {
                    exempt.clear_watchdog();
                    // BUG-011: withdraw observer rights on watchdog
                    // teardown so a recycled PID can't inherit them.
                    if let Some(prev) = last {
                        let _ = northnarrow_agent::anti_tamper::evict_protected_observer(
                            bpffs_root, prev,
                        );
                    }
                    info!(
                        pidfile = %pidfile.display(),
                        "watchdog pidfile absent; no watchdog exemption active"
                    );
                }
                WatchdogResolution::InvalidPidfile { reason } => {
                    exempt.clear_watchdog();
                    if let Some(prev) = last {
                        let _ = northnarrow_agent::anti_tamper::evict_protected_observer(
                            bpffs_root, prev,
                        );
                    }
                    warn!(%reason, "watchdog pidfile unparseable; watchdog exemption cleared");
                }
                WatchdogResolution::Unverifiable { pid, reason } => {
                    exempt.clear_watchdog();
                    if let Some(prev) = last {
                        let _ = northnarrow_agent::anti_tamper::evict_protected_observer(
                            bpffs_root, prev,
                        );
                    }
                    warn!(pid, %reason, "watchdog exe verification failed; exemption cleared");
                }
                WatchdogResolution::ExeMismatch { pid, resolved } => {
                    exempt.clear_watchdog();
                    if let Some(prev) = last {
                        let _ = northnarrow_agent::anti_tamper::evict_protected_observer(
                            bpffs_root, prev,
                        );
                    }
                    warn!(
                        pid,
                        resolved = %resolved.display(),
                        expected = %expected_exe.display(),
                        "watchdog PID maps to an unexpected binary (PID reuse or \
                         substitution); exemption refused"
                    );
                }
            }
            last = new_pid;
        }
    });
}

/// Best-effort compatibility record for a Beta Step 4a stale-COMBAT
/// reconcile: one JSONL line in
/// [`northnarrow_agent::combat::reconcile::LOG_PATH`]; a write failure is
/// logged but never fatal — the teardown it records has already happened,
/// and the signed `integrity_drift` (`combat_reconcile`) is the evidence
/// (external audit MAIN-013).
fn audit_combat_reconcile(rules_removed: usize) {
    use northnarrow_agent::combat::reconcile::{append_line, CAP_BYTES, LOG_PATH};
    // BUG-026 B-cap: combat-audit is the lone UNSIGNED / unchained
    // best-effort log (BUG-028). `/var/lib/northnarrow` is `chattr +i`, so
    // a rename-based rotate is a blocked dir-entry op — capped by
    // TRUNCATE-IN-PLACE (a content op, allowed under `+i`).
    if let Err(e) = append_line(std::path::Path::new(LOG_PATH), rules_removed, CAP_BYTES) {
        warn!(error = %e, path = LOG_PATH, "could not write COMBAT reconcile audit line (non-fatal)");
    }
}

/// External audit DEP-006: where the ids of the agent's loaded BPF programs
/// go — next to `--pid-file` (the unit: `/run/northnarrow/bpf-own-ids`).
/// Without `--pid-file` (the e2e fixtures, a manual run) nothing is
/// written, so the installed agent's list is never overwritten by another.
fn own_prog_ids_file(cli: &Cli) -> Option<PathBuf> {
    cli.pid_file
        .as_deref()
        .and_then(std::path::Path::parent)
        .map(|dir| dir.join(northnarrow_agent::anti_tamper::bpf_defense::OWN_IDS_FILE_NAME))
}

/// Write the program-id list (see [`own_prog_ids_file`]); a failure is a
/// WARN: the scripts then fall back to their older, host-wide wait.
fn record_own_prog_ids(path: Option<&std::path::Path>, ebpf: &aya::Ebpf) {
    let Some(path) = path else {
        return;
    };
    match northnarrow_agent::anti_tamper::bpf_defense::write_own_prog_ids(ebpf, path) {
        Ok(n) => debug!(
            path = %path.display(),
            programs = n,
            "own BPF program ids recorded (install.sh / uninstall.sh wait for them)"
        ),
        Err(e) => warn!(
            error = format!("{e:#}"),
            path = %path.display(),
            "own BPF program ids NOT recorded — install.sh --upgrade and uninstall.sh wait on the \
             list written earlier this boot, or fall back to waiting for no LSM program on the host"
        ),
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
    if path.file_name().is_none() {
        anyhow::bail!(
            "--pid-file path has no file-name component: {}",
            path.display()
        );
    }
    // External audit WDG-015 (NN-AUD-364): `/run/northnarrow` is writable
    // by root and outside the inode deny set, and the agent is a process
    // the hooks trust: its temporary file (`agent.pid.tmp.<pid>`, written
    // with `fs::write`) followed a link planted at that predictable name.
    // The AUT-003 writer removes whatever sits at the temporary name and
    // creates it exclusively, then renames it into place. A missing parent
    // directory still fails here, at startup, loudly.
    northnarrow_agent::atomic_file::write_pidfile(path, pid)
        .with_context(|| format!("writing PID file {} (atomic replace)", path.display()))?;

    info!(
        target: "anti-tamper",
        path = %path.display(),
        pid,
        "pid_file written (atomic tempfile+rename; existence == post-attach readiness gate)"
    );
    Ok(())
}

/// Raise the soft `RLIMIT_NOFILE` to the hard limit (at most 65 536).
/// Returns the new soft limit.
fn raise_nofile_rlimit() -> std::io::Result<u64> {
    let mut rlim = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: a valid `rlimit` to fill.
    if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut rlim) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    let want = rlim.rlim_max.min(65_536);
    if rlim.rlim_cur >= want {
        return Ok(rlim.rlim_cur);
    }
    rlim.rlim_cur = want;
    // SAFETY: a valid `rlimit` passed by reference; the kernel only reads it.
    if unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &rlim) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(want)
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

/// `--btf-check`: resolve the runtime offset table against a BTF file and
/// print a one-line verdict plus every drifted or missing entry.
fn btf_check(path: &std::path::Path) -> i32 {
    use northnarrow_agent::anti_tamper::btf_revalidate::resolve_offsets_from;
    match resolve_offsets_from(path) {
        ResolveOutcome::Resolved(r) => {
            println!(
                "btf-check {}: {} — {} slots resolved, {} differ from the build kernel, {} absent, {} hook arguments checked",
                path.display(),
                if r.absent.is_empty() {
                    "SUPPORTED"
                } else {
                    "SUPPORTED (degraded)"
                },
                r.values.len(),
                r.drifted.len(),
                r.absent.len(),
                r.hook_args_checked
            );
            for m in &r.absent {
                let effect = if m.struct_name.starts_with("bpf_lsm_") {
                    format!(
                        "not attached: {} (the agent starts only with NN_ANTI_TAMPER_ALLOW_DEGRADED=1)",
                        northnarrow_agent::anti_tamper::btf_revalidate::hook_arg_effect(m.struct_name)
                    )
                } else {
                    "dependent sensor path disabled".to_string()
                };
                println!(
                    "  absent  {:<34} {:<12} {} — {effect}",
                    m.name, m.struct_name, m.detail
                );
            }
            // Lab PR 174: the deny hooks only some kernels have, counted
            // as expected where the BTF has them.
            for (hook, present) in &r.optional_deny_hooks {
                let verdict = if *present {
                    format!(
                        "present — bpf_lsm_{hook} in the BTF: its deny program attaches and counts as an expected deny hook"
                    )
                } else {
                    format!("absent  — no bpf_lsm_{hook} in the BTF: no deny program on it, not expected")
                };
                println!("  optional {hook:<33} {verdict}");
            }
            for module in &r.modules_not_loaded {
                println!(
                    "  module  {module:<34} no BTF next to the vmlinux file — its types' offsets stay unset (not a degradation)"
                );
            }
            for m in &r.drifted {
                println!(
                    "  drift   {:<34} {:<12} compiled={:<6} runtime={}",
                    m.name,
                    m.struct_name,
                    m.expected,
                    m.actual
                        .map(|v| v.to_string())
                        .unwrap_or_else(|| "?".into())
                );
            }
            0
        }
        ResolveOutcome::SkippedNoBtf { reason } => {
            println!("btf-check {}: UNREADABLE — {reason}", path.display());
            3
        }
        ResolveOutcome::Refuse(RefuseReason::Drift(missing)) => {
            println!(
                "btf-check {}: NOT SUPPORTED — {} field(s)/enumerator(s)/hook argument(s) missing (the agent would refuse to start)",
                path.display(),
                missing.len()
            );
            for m in &missing {
                println!(
                    "  missing {:<34} {:<12} {}",
                    m.name, m.struct_name, m.detail
                );
            }
            2
        }
        ResolveOutcome::Refuse(RefuseReason::ParseError(e)) => {
            println!("btf-check {}: UNPARSEABLE — {e}", path.display());
            3
        }
    }
}
