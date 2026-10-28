
#[derive(Debug, Parser)]
#[command(
    name = "northnarrow-agent",
    version,
    about = "NorthNarrow XDR agent daemon (Linux)."
)]
struct Cli {
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

    /// Internal (lab PR 218): run as the deny self-test child — send one
    /// SIGURG to the parent, exit with what kill(2) said. Spawned by the
    /// agent itself once per boot, right after the deny hooks attach.
    #[arg(long = "deny-self-test", hide = true)]
    deny_self_test: bool,

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

    /// Lab only: load the embedded eBPF object with the agent's loader setup
    /// (maps, BTF offsets armed and frozen), put every program through the
    /// kernel's verifier without attaching any, print per program OK or
    /// REFUSED (the verifier log's tail, instruction counts, stack) and exit
    /// — 0 when every program the agent needs loads. Root and a
    /// `debug-trigger` build (`deploy/lab/nn-lab.sh verifier-check`).
    #[arg(long = "verifier-check", hide = true)]
    verifier_check: bool,

    /// Print the test and debug cargo features this binary was built with
    /// (comma-separated: `debug-trigger`, `demo-tappa5`, `posture-demo`,
    /// `test-privileged`) or `none`, and exit. A release build prints
    /// `none`; the range bootstrap refuses to install anything else
    /// (external audit NN-AUD-211), and so does the release workflow's
    /// check of its artefacts (external audit PROC-015).
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

    /// Exploit post-condition guard (lab PR 219, experimental): a gain of
    /// credentials, namespaces or root the kernel's own mechanisms did not
    /// make for the call (NN-L-EPG-001/002). `lite` (default): no
    /// system-call hooks — the mechanisms are judged on the call in
    /// progress, and a credential changed without one is caught at its
    /// first use (`capable`, exec, a root-only file open). `strict`: the
    /// comparison around every system call (opt-in: hundreds of ns per call
    /// of an unprivileged task; refused below Linux 6.1, a version check).
    /// `off`: not attached, attested
    /// as a degradation (also `NN_EXPLOIT_GUARD=off`, a weakening variable).
    #[arg(
        long = "exploit-guard",
        env = "NN_EXPLOIT_GUARD",
        value_enum,
        default_value_t = ExploitGuard::Lite
    )]
    exploit_guard: ExploitGuard,

    /// What the exploit guard does on a finding. `detect` (default): signed
    /// record, the task continues. `enforce`: SIGKILL in the kernel before
    /// the task returns to user mode (lite's use points also refuse the
    /// use, -EPERM), then the record. `--detect-only` keeps it at detect.
    #[arg(
        long = "exploit-guard-response",
        env = "NN_EXPLOIT_GUARD_RESPONSE",
        value_enum,
        default_value_t = ExploitGuardResponse::Detect
    )]
    exploit_guard_response: ExploitGuardResponse,

    /// Exploit guard: the size of the running variant's task map. Strict:
    /// default `/proc/sys/kernel/pid_max` (every live task fits; not
    /// preallocated). Lite: default `min(pid_max, threads-max)` capped at
    /// 65536 (an LRU map, preallocated, ~150 bytes an entry; up to
    /// 1048576); records it evicts are re-taken, counted and attested (at
    /// most once per 600 s).
    #[arg(long = "exploit-guard-tasks", env = "NN_EXPLOIT_GUARD_TASKS")]
    exploit_guard_tasks: Option<u32>,

    /// Removed in Wave 4 (lab PR 214) with the on-host LLM advisor, as
    /// the four below: accepted so that a unit written for an older agent
    /// still starts, ignored, and named in a WARN at start
    /// ([`northnarrow_agent::removed_settings`]).
    #[arg(long = "no-ade", hide = true)]
    removed_no_ade: bool,
    #[arg(long = "ade-model", hide = true, value_name = "PATH")]
    removed_ade_model: Option<std::ffi::OsString>,
    #[arg(long = "ade-timeout", hide = true, value_name = "SECS")]
    removed_ade_timeout: Option<std::ffi::OsString>,
    #[arg(long = "ade-prompt", hide = true, value_name = "PATH")]
    removed_ade_prompt: Option<std::ffi::OsString>,
    #[arg(long = "ade-threads", hide = true, value_name = "N")]
    removed_ade_threads: Option<std::ffi::OsString>,

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

    /// Lab PR 224 (CM-02 c): refuse in the kernel, with `EPERM`, every
    /// `connect()` to an address of the operator netflow blocklist (LSM
    /// `socket_connect`), before any packet leaves; each refusal is a
    /// signed NN-L-NET-001 record. Off by default: without it NN-L-NET-001
    /// kills the process at the connect, once the connection is made.
    /// Entries wider than /8 (IPv4) or /16 (IPv6), or covering loopback,
    /// stay out of the kernel deny (the rule still judges them). Ignored in
    /// detect-only, which never refuses a connect. Also
    /// `NN_NET_CONNECT_DENY=1` (or `true`, `yes`, `on`; `0`, `false`, `no`,
    /// `off` leave it off).
    #[arg(
        long = "net-connect-deny",
        env = "NN_NET_CONNECT_DENY",
        default_value_t = false,
        value_parser = clap::builder::BoolishValueParser::new()
    )]
    net_connect_deny: bool,

    /// Lab PR 224 (CM-02 b): a TCP flow still open is re-judged every this
    /// many seconds (the rules that need no byte count, with the process's
    /// current image).
    #[arg(
        long = "net-snapshot-interval-secs",
        env = "NN_NET_SNAPSHOT_INTERVAL_SECS",
        value_name = "SECS",
        default_value_t = northnarrow_agent::net::flow_tracker::DEFAULT_SNAPSHOT_SECS,
        value_parser = clap::value_parser!(u64).range(1..=86_400)
    )]
    net_snapshot_interval_secs: u64,

    /// Lab PR 224: a flow is first snapshotted once open this many seconds.
    #[arg(
        long = "net-snapshot-min-age-secs",
        env = "NN_NET_SNAPSHOT_MIN_AGE_SECS",
        value_name = "SECS",
        default_value_t = northnarrow_agent::net::flow_tracker::DEFAULT_SNAPSHOT_SECS,
        value_parser = clap::value_parser!(u64).range(0..=86_400)
    )]
    net_snapshot_min_age_secs: u64,

    /// Lab PR 224: at most this many open-flow snapshots per check (every
    /// 10 s); the others wait for the next one (`net status` counts them).
    #[arg(
        long = "net-snapshot-max",
        env = "NN_NET_SNAPSHOT_MAX",
        value_name = "N",
        default_value_t = northnarrow_agent::net::flow_tracker::DEFAULT_SNAPSHOT_MAX,
        value_parser = clap::builder::RangedU64ValueParser::<usize>::new().range(0..=65_536)
    )]
    net_snapshot_max: usize,

    /// Lab PR 224 (CM-14): NN-L-NET-026 records one process (or the
    /// children of one parent) reaching this many distinct destination
    /// addresses within the scan window.
    #[arg(
        long = "net-scan-hosts",
        env = "NN_NET_SCAN_HOSTS",
        value_name = "N",
        default_value_t = northnarrow_agent::decision::rules::net_fanout::DEFAULT_SCAN_HOSTS,
        value_parser = clap::builder::RangedU64ValueParser::<usize>::new().range(1..=1_000_000)
    )]
    net_scan_hosts: usize,

    /// Lab PR 224: … or this many distinct (address, port) pairs.
    #[arg(
        long = "net-scan-pairs",
        env = "NN_NET_SCAN_PAIRS",
        value_name = "N",
        default_value_t = northnarrow_agent::decision::rules::net_fanout::DEFAULT_SCAN_PAIRS,
        value_parser = clap::builder::RangedU64ValueParser::<usize>::new().range(1..=1_000_000)
    )]
    net_scan_pairs: usize,

    /// Lab PR 224: NN-L-NET-026 kills a process reaching this many distinct
    /// addresses within the window (0: never kill).
    #[arg(
        long = "net-scan-kill-hosts",
        env = "NN_NET_SCAN_KILL_HOSTS",
        value_name = "N",
        default_value_t = northnarrow_agent::decision::rules::net_fanout::DEFAULT_SCAN_KILL_HOSTS,
        value_parser = clap::builder::RangedU64ValueParser::<usize>::new().range(0..=1_000_000)
    )]
    net_scan_kill_hosts: usize,

    /// Lab PR 224: the scan window.
    #[arg(
        long = "net-scan-window-secs",
        env = "NN_NET_SCAN_WINDOW_SECS",
        value_name = "SECS",
        default_value_t = northnarrow_agent::decision::rules::net_fanout::DEFAULT_SCAN_WINDOW_SECS,
        value_parser = clap::value_parser!(u64).range(1..=3_600)
    )]
    net_scan_window_secs: u64,

    /// Lab PR 224: NN-L-NET-027 records this many connects to
    /// authentication services (SSH, Telnet, RDP, VNC) within its window.
    #[arg(
        long = "net-brute-connects",
        env = "NN_NET_BRUTE_CONNECTS",
        value_name = "N",
        default_value_t = northnarrow_agent::decision::rules::net_fanout::DEFAULT_BRUTE_CONNECTS,
        value_parser = clap::builder::RangedU64ValueParser::<usize>::new().range(1..=1_000_000)
    )]
    net_brute_connects: usize,

    /// Lab PR 224: … and kills a process reaching this many (0: never).
    #[arg(
        long = "net-brute-kill-connects",
        env = "NN_NET_BRUTE_KILL_CONNECTS",
        value_name = "N",
        default_value_t = northnarrow_agent::decision::rules::net_fanout::DEFAULT_BRUTE_KILL_CONNECTS,
        value_parser = clap::builder::RangedU64ValueParser::<usize>::new().range(0..=1_000_000)
    )]
    net_brute_kill_connects: usize,

    /// Lab PR 224: the brute-force window.
    #[arg(
        long = "net-brute-window-secs",
        env = "NN_NET_BRUTE_WINDOW_SECS",
        value_name = "SECS",
        default_value_t = northnarrow_agent::decision::rules::net_fanout::DEFAULT_BRUTE_WINDOW_SECS,
        value_parser = clap::value_parser!(u64).range(1..=86_400)
    )]
    net_brute_window_secs: u64,

    /// Lab PR 224: a program (by name, its executable or the script an
    /// interpreter runs, installed in a root-owned system tree) whose
    /// processes and their descendants fan out legitimately — the host's
    /// own monitoring — beside the built-in list; repeatable, or a comma
    /// list in `NN_NET_FANOUT_EXEMPT`.
    #[arg(
        long = "net-fanout-exempt",
        env = "NN_NET_FANOUT_EXEMPT",
        value_name = "PROGRAM",
        value_delimiter = ','
    )]
    net_fanout_exempt: Vec<String>,

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

    /// Lab PR 223 (EXPERIMENTAL): exec quarantine at first sight
    /// (docs/design/EXEC_QUARANTINE.md). `off` (default); `observe`: a new
    /// executable run from a guarded location (/tmp, /var/tmp, /dev/shm, a
    /// home directory, a world-writable directory, a memfd, an unlinked
    /// file) is scanned while it runs and the record says what would have
    /// been done; `enforce`: the kernel holds it before its first
    /// instruction until the scanner and the rule engine have judged it. A
    /// detect-only agent observes.
    #[arg(
        long = "exec-quarantine",
        env = "NN_EXEC_QUARANTINE",
        value_enum,
        default_value_t = northnarrow_agent::execq::Mode::Off
    )]
    exec_quarantine: northnarrow_agent::execq::Mode,

    /// How long a held process waits for its decision before the default
    /// policy applies (100–10000 ms).
    #[arg(
        long = "exec-quarantine-budget-ms",
        env = "NN_EXEC_QUARANTINE_BUDGET_MS",
        value_name = "MS",
        default_value_t = northnarrow_agent::execq::policy::DEFAULT_BUDGET_MS
    )]
    exec_quarantine_budget_ms: u64,

    /// The default policy: what a held process without a verdict within the
    /// budget (or whose file cannot be scanned) gets. Signed either way.
    #[arg(
        long = "exec-quarantine-on-expiry",
        env = "NN_EXEC_QUARANTINE_ON_EXPIRY",
        value_enum,
        default_value_t = northnarrow_agent::execq::Action::Resume
    )]
    exec_quarantine_on_expiry: northnarrow_agent::execq::Action,

    /// What a held process the scanner calls suspicious (heuristics, not a
    /// block-list hit) gets.
    #[arg(
        long = "exec-quarantine-on-suspicious",
        env = "NN_EXEC_QUARANTINE_ON_SUSPICIOUS",
        value_enum,
        default_value_t = northnarrow_agent::execq::Action::Resume
    )]
    exec_quarantine_on_suspicious: northnarrow_agent::execq::Action,

    /// The scanner binary. Default: `northnarrow-scan` next to the agent,
    /// else /usr/local/bin/northnarrow-scan.
    #[arg(long = "exec-quarantine-scanner", value_name = "PATH")]
    exec_quarantine_scanner: Option<PathBuf>,

    /// The account the scanner runs as (install.sh creates it).
    #[arg(
        long = "exec-quarantine-scan-user",
        value_name = "USER",
        default_value = northnarrow_agent::execq::DEFAULT_SCAN_USER
    )]
    exec_quarantine_scan_user: String,

    /// The signed hash list (`block <sha256> [label]` / `allow <sha256>
    /// [label]`), stored with `nn-admin config overlay set execq-hashes`.
    #[arg(
        long = "execq-hashes-local",
        value_name = "PATH",
        default_value = northnarrow_agent::execq::DEFAULT_HASHES_LOCAL
    )]
    execq_hashes_local: PathBuf,

    /// Lab PR 226 (EXPERIMENTAL): synchronous exec policies
    /// (docs/design/EXEC_POLICY.md). `off` (default); `audit`: every exec a
    /// deny cell names (memfd, a deleted file, /dev/shm for services and
    /// sessions in the server profile) is recorded as "would deny" and
    /// runs; `enforce`: it is refused with EACCES before the exec's point
    /// of no return. Quarantine cells hand the exec to --exec-quarantine.
    /// The loader variables (LD_PRELOAD, LD_AUDIT into a staging path) and
    /// the executable mappings of staging files are judged by the same
    /// policy. A detect-only agent audits.
    #[arg(
        long = "exec-policy",
        env = "NN_EXEC_POLICY",
        value_enum,
        default_value_t = northnarrow_agent::execpol::Mode::Off
    )]
    exec_policy: northnarrow_agent::execpol::Mode,

    /// The built-in table the signed overlay starts from: `server`
    /// (default) or `desktop` (a login session's own staging locations
    /// allowed: AppImage, build trees; memfd and deleted files recorded).
    #[arg(
        long = "exec-policy-profile",
        env = "NN_EXEC_POLICY_PROFILE",
        value_enum,
        default_value_t = northnarrow_agent::execpol::Profile::Server
    )]
    exec_policy_profile: northnarrow_agent::execpol::Profile,

    /// The signed policy (`exec <class> <tier> <action>`…), stored with
    /// `nn-admin config overlay set exec-policy`.
    #[arg(
        long = "exec-policy-local",
        value_name = "PATH",
        default_value = northnarrow_agent::execpol::DEFAULT_POLICY_LOCAL
    )]
    exec_policy_local: PathBuf,

    /// Lab PR 236: the signed per-rule response policy (`enforce|alert|audit|off
    /// <rule>`, `exempt <rule> …`), stored with `nn-admin policy set`.
    /// Without it every rule keeps its built-in response.
    #[arg(
        long = "rule-policy-local",
        value_name = "PATH",
        default_value = northnarrow_agent::decision::rule_policy::DEFAULT_LOCAL
    )]
    rule_policy_local: PathBuf,

    /// Do not read the new environment at exec (no LD_PRELOAD / LD_AUDIT /
    /// GLIBC_TUNABLES / history checks). Also `NN_EXEC_POLICY_NO_ENV=1`
    /// (1/0, true/false, yes/no, on/off).
    #[arg(
        long = "exec-policy-no-env",
        env = "NN_EXEC_POLICY_NO_ENV",
        value_parser = clap::builder::BoolishValueParser::new()
    )]
    exec_policy_no_env: bool,

    /// Do not judge executable mappings (`mmap_file`). Also
    /// `NN_EXEC_POLICY_NO_MAP=1` (1/0, true/false, yes/no, on/off).
    #[arg(
        long = "exec-policy-no-map",
        env = "NN_EXEC_POLICY_NO_MAP",
        value_parser = clap::builder::BoolishValueParser::new()
    )]
    exec_policy_no_map: bool,
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
    fn chain_paths(&self) -> northnarrow_agent::chains::ChainPaths {
        northnarrow_agent::chains::ChainPaths {
            audit: self.audit_log_file.clone(),
            canary_registry: self.canary_registry_file.clone(),
            canary_access: self.canary_access_file.clone(),
            detections: self.detections_file.clone(),
            status_events: self.status_events_file.clone(),
            netflow: self.netflow_file.clone(),
            fim_drift: self.fim_drift_file.clone(),
        }
    }

    /// Lab PR 223: the guard's configuration for this boot; a detect-only
    /// agent observes.
    fn execq_config(&self, detect_only: bool) -> northnarrow_agent::execq::Config {
        use northnarrow_agent::execq::{policy, Config, Mode, Policy};
        let mode = match self.exec_quarantine {
            Mode::Enforce if detect_only => Mode::Observe,
            m => m,
        };
        Config {
            mode,
            budget: policy::clamp_budget(self.exec_quarantine_budget_ms),
            policy: Policy {
                on_suspicious: self.exec_quarantine_on_suspicious,
                on_expiry: self.exec_quarantine_on_expiry,
                enforce: mode == Mode::Enforce,
            },
            classes: common::wire::execq::class::ALL,
            scanner: self.exec_quarantine_scanner.clone().unwrap_or_else(|| {
                let own = std::env::current_exe().and_then(|p| p.canonicalize()).ok();
                northnarrow_agent::execq::sibling_scanner_exe(own.as_deref())
            }),
            scan_user: self.exec_quarantine_scan_user.clone(),
            hashes_local: self.execq_hashes_local.clone(),
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

/// `--exploit-guard` (lab PR 219).
#[derive(Clone, Copy, Debug, PartialEq, Eq, clap::ValueEnum)]
enum ExploitGuard {
    Off,
    Lite,
    Strict,
}

impl ExploitGuard {
    fn variant(self) -> northnarrow_agent::sensors::epg::Variant {
        use northnarrow_agent::sensors::epg::Variant;
        match self {
            Self::Off => Variant::Off,
            Self::Lite => Variant::Lite,
            Self::Strict => Variant::Strict,
        }
    }
}

/// `--exploit-guard-response` (lab PR 219).
#[derive(Clone, Copy, Debug, PartialEq, Eq, clap::ValueEnum)]
enum ExploitGuardResponse {
    Detect,
    Enforce,
}

impl ExploitGuardResponse {
    fn response(self) -> northnarrow_agent::sensors::epg::Response {
        use northnarrow_agent::sensors::epg::Response;
        match self {
            Self::Detect => Response::Detect,
            Self::Enforce => Response::Enforce,
        }
    }
}

impl Cli {
    /// The flags of the removed LLM advisor this command line sets, in
    /// the order of [`northnarrow_agent::removed_settings::REMOVED_FLAGS`].
    fn removed_flags(&self) -> Vec<&'static str> {
        let set = [
            self.removed_no_ade,
            self.removed_ade_model.is_some(),
            self.removed_ade_timeout.is_some(),
            self.removed_ade_prompt.is_some(),
            self.removed_ade_threads.is_some(),
        ];
        northnarrow_agent::removed_settings::REMOVED_FLAGS
            .iter()
            .zip(set)
            .filter_map(|(flag, on)| on.then_some(*flag))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Wave 4 (lab PR 214): a unit written for an agent with the LLM
    /// advisor still parses — its flags are accepted, ignored and named.
    #[test]
    fn the_removed_advisor_flags_still_parse_and_are_named() {
        let cli = Cli::try_parse_from([
            "northnarrow-agent",
            "--no-ade",
            "--ade-model",
            "/var/lib/northnarrow/models/m.gguf",
            "--ade-timeout",
            "15",
            "--ade-prompt",
            "dataset/system_prompt_v1.md",
            "--ade-threads",
            "3",
            "--detect-only",
        ])
        .expect("an old unit's command line parses");
        assert_eq!(
            cli.removed_flags(),
            northnarrow_agent::removed_settings::REMOVED_FLAGS
        );
        assert!(cli.detect_only, "the other flags keep their meaning");

        let cli = Cli::try_parse_from(["northnarrow-agent", "--ade-timeout", "not-a-number"])
            .expect("a removed flag's value is not parsed");
        assert_eq!(cli.removed_flags(), ["--ade-timeout"]);

        let cli = Cli::try_parse_from(["northnarrow-agent"]).unwrap();
        assert!(cli.removed_flags().is_empty());
    }

    /// Lab (21/10, debian12): an agent unit with `NN_NET_CONNECT_DENY=1`,
    /// the value the help and the CHANGELOG give, did not start — exit 2,
    /// "invalid value '1' for '--net-connect-deny'" (clap's plain bool
    /// parser takes only `true` / `false` from the environment) — and the
    /// watchdog held. An environment switch reads 1/0, true/false, yes/no,
    /// on/off; anything else is refused, never read as on.
    #[test]
    fn env_switches_read_1_and_0() {
        const SWITCHES: &[(&str, &str)] = &[
            ("NN_NET_CONNECT_DENY", "--net-connect-deny"),
            ("NN_EXEC_POLICY_NO_ENV", "--exec-policy-no-env"),
            ("NN_EXEC_POLICY_NO_MAP", "--exec-policy-no-map"),
        ];
        fn get(cli: &Cli, flag: &str) -> bool {
            match flag {
                "--net-connect-deny" => cli.net_connect_deny,
                "--exec-policy-no-env" => cli.exec_policy_no_env,
                "--exec-policy-no-map" => cli.exec_policy_no_map,
                _ => unreachable!("{flag}"),
            }
        }
        let clear = || {
            for (env, _) in SWITCHES {
                std::env::remove_var(env);
            }
        };
        clear();
        let cli = Cli::try_parse_from(["northnarrow-agent"]).unwrap();
        for (_, flag) in SWITCHES {
            assert!(!get(&cli, flag), "{flag} off by default");
            let cli = Cli::try_parse_from(["northnarrow-agent", flag]).unwrap();
            assert!(get(&cli, flag), "{flag} on the command line");
        }
        for (value, on) in [
            ("1", true),
            ("true", true),
            ("yes", true),
            ("on", true),
            ("0", false),
            ("false", false),
            ("no", false),
            ("off", false),
        ] {
            for (env, flag) in SWITCHES {
                std::env::set_var(env, value);
                let cli = Cli::try_parse_from(["northnarrow-agent"]);
                std::env::remove_var(env);
                let cli = cli.unwrap_or_else(|e| panic!("{env}={value}: {e}"));
                assert_eq!(get(&cli, flag), on, "{env}={value}");
            }
        }
        for (env, _) in SWITCHES {
            std::env::set_var(env, "maybe");
            let r = Cli::try_parse_from(["northnarrow-agent"]);
            std::env::remove_var(env);
            assert!(r.is_err(), "{env}=maybe is refused, not read as on");
        }
        clear();
    }

    /// The removed flags are hidden: `--help` no longer offers them.
    #[test]
    fn the_removed_advisor_flags_are_not_in_the_help() {
        use clap::CommandFactory;
        let help = Cli::command().render_long_help().to_string();
        for flag in northnarrow_agent::removed_settings::REMOVED_FLAGS {
            assert!(!help.contains(flag), "{flag} in:\n{help}");
        }
    }
}
