//! The agent's command line (Wave 4 restructure, R11a, lab PR 261: from
//! `main.rs`): the flags and their environment variables, the paths they
//! resolve to, the value enums, the removed advisor's flags. The one-shot
//! modes it selects are `boot::main`'s.

use std::path::PathBuf;

use clap::Parser;
use northnarrow_agent::net::blocklist::{
    DEFAULT_NETFLOW_BLOCKLIST_LOCAL, DEFAULT_NETFLOW_BLOCKLIST_V1,
    DEFAULT_NETFLOW_JA3_BLOCKLIST_LOCAL, DEFAULT_NETFLOW_JA3_BLOCKLIST_V1,
};

#[derive(Debug, Parser)]
#[command(
    name = "northnarrow-agent",
    version,
    about = "NorthNarrow XDR agent daemon (Linux)."
)]
pub(crate) struct Cli {
    // BUG-033.
    /// Detect-only (monitor) mode. Detection runs in full and the posture
    /// still moves (OBSERVING, ALERTED, COMBAT are logged), but nothing is
    /// enforced: every response (kill, block, quarantine, throttle,
    /// isolation) and the COMBAT network isolation are skipped and logged
    /// as "would execute". Use it to roll out safely, or to tune, before
    /// arming the automatic response. Also `NN_DETECT_ONLY=1` (the older
    /// `NORTHNARROW_DRY_RUN=1` is honoured too).
    #[arg(long = "detect-only", default_value_t = false)]
    pub(crate) detect_only: bool,

    /// Internal: run as the telemetry-probe child (one file open, one DNS
    /// packet, exit). Spawned by the agent itself every
    /// `NN_TELEMETRY_PROBE_SECS`; never meant for operators.
    #[arg(long = "telemetry-probe", hide = true, value_name = "NONCE")]
    pub(crate) telemetry_probe: Option<String>,

    // Lab PR 218.
    /// Internal: run as the deny self-test child — send one SIGURG to the
    /// parent, exit with what kill(2) said. Spawned by the agent itself
    /// once per boot, right after the deny hooks attach.
    #[arg(long = "deny-self-test", hide = true)]
    pub(crate) deny_self_test: bool,

    // Lot 273b.
    /// Internal: the move guard's self-test target — a process the agent
    /// registers as a worker and tries to have moved; it waits to be
    /// killed (30 s at most).
    #[arg(long = "move-guard-self-test-target", hide = true)]
    pub(crate) move_guard_self_test_target: bool,

    // Lot 273b.
    /// Internal: the move guard's self-test mover — write PID to the given
    /// `cgroup.procs`, exit with what write(2) said.
    #[arg(
        long = "move-guard-self-test",
        hide = true,
        num_args = 2,
        value_names = ["CGROUP_PROCS", "PID"]
    )]
    pub(crate) move_guard_self_test: Option<Vec<String>>,

    // Multi-kernel level 2.
    /// Check this agent's compatibility with a kernel, and exit: resolve
    /// every kernel structure field and value the agent's kernel programs
    /// need against the given BTF file (`/sys/kernel/btf/vmlinux` of this
    /// or another kernel, or a BTF extracted from a distribution's kernel
    /// package) and print the report. Exit 0 when everything resolves, 2
    /// when a field is missing (the agent would refuse to start on that
    /// kernel), 3 when the BTF cannot be read or parsed. Loads nothing
    /// into the kernel; needs no root.
    #[arg(long = "btf-check", value_name = "BTF_FILE")]
    pub(crate) btf_check: Option<PathBuf>,

    // Tappa 10.9 step 0.
    /// Lab only: load the sensor-feasibility probes on this kernel,
    /// exercise them, print the report and exit — 0 when every required
    /// property holds. Root, a `test-privileged` build, and the installed
    /// agent stopped (`deploy/lab/nn-lab.sh sensor-feasibility`).
    #[arg(long = "sensor-feasibility", hide = true)]
    pub(crate) sensor_feasibility: bool,

    /// Lab only: load the embedded eBPF object with the agent's loader setup
    /// (maps, BTF offsets armed and frozen), put every program through the
    /// kernel's verifier without attaching any, print per program OK or
    /// REFUSED (the verifier log's tail, instruction counts, stack) and exit
    /// — 0 when every program the agent needs loads. Root and a
    /// `debug-trigger` build (`deploy/lab/nn-lab.sh verifier-check`).
    #[arg(long = "verifier-check", hide = true)]
    pub(crate) verifier_check: bool,

    // The re-review of #497 (RR2): the drop-ins are judged by this build's
    // judge, every one of them whatever its age.
    /// Check the drop-ins of NorthNarrow's systemd units against this
    /// version's rules, whatever their age, and exit. `check` prints each
    /// one the agent would quarantine (`would move <path>: <why>`) and
    /// exits 3 when there is one, 0 when there is none. `quarantine` moves
    /// them to /var/lib/northnarrow/quarantine/dropins (`moved <path> ->
    /// <to>: <why>`) and exits 1 when one could not be moved. `install.sh
    /// --upgrade` runs `check` before it changes anything, and
    /// `quarantine` when given `--accept-dropin-quarantine`.
    #[arg(long = "own-dropins", value_name = "check|quarantine", value_parser = ["check", "quarantine"])]
    pub(crate) own_dropins: Option<String>,

    // The range bootstrap checks it before it installs a binary (external
    // audit NN-AUD-211), and the release workflow on every artefact it
    // builds (external audit PROC-015). The names: `build_info`.
    /// Print the test and debug build features this binary was built with
    /// (comma-separated), or `none`, and exit. A release build prints
    /// `none`; the range bootstrap and the release checks refuse a binary
    /// that prints anything else.
    #[arg(long = "build-features")]
    pub(crate) build_features: bool,

    // Tappa 10.9 step 1: the FIM `file_open` LSM observer; `tracepoint` is
    // the previous `sys_enter_openat` sensor, kept for one soak cycle.
    /// File-open sensor. `lsm` (default): the kernel classifies every open
    /// and sends only the ones a rule reads (and counts the opens for
    /// writing, for mass-write detection). `tracepoint`: the older sensor
    /// that sends every open to user space; a fallback (also
    /// `NN_FILE_OPEN_SENSOR=tracepoint` in a unit drop-in).
    #[arg(
        long = "file-open-sensor",
        env = "NN_FILE_OPEN_SENSOR",
        value_enum,
        default_value_t = FileOpenSensor::Lsm
    )]
    pub(crate) file_open_sensor: FileOpenSensor,

    // Tappa 10.9 step 2: LSM `bprm_check_security` (review 61);
    // `tracepoint` is the previous `sys_enter_execve` sensor, kept for one
    // soak cycle.
    /// Exec sensor. `lsm` (default): the kernel's exec check reads the file
    /// the kernel actually opened, and the exec rules match its canonical
    /// path. `tracepoint`: the older sensor, whose rules matched the path
    /// the caller passed; a fallback (also `NN_EXEC_SENSOR=tracepoint` in a
    /// unit drop-in).
    #[arg(
        long = "exec-sensor",
        env = "NN_EXEC_SENSOR",
        value_enum,
        default_value_t = ExecSensor::Lsm
    )]
    pub(crate) exec_sensor: ExecSensor,

    // Tappa 10.9 step 3: kprobes on `udp_send_skb` / `udp_v6_send_skb`
    // (reviews 66, 67); `sendmsg` is the previous `udp_sendmsg` kprobe,
    // kept for one soak cycle.
    /// DNS sensor. `skb` (default): reads each query from the packet the
    /// kernel built — the name actually sent, over IPv4 and IPv6.
    /// `sendmsg`: the older sensor, which read the caller's memory before
    /// the kernel copied it and saw IPv4 only; a fallback (also
    /// `NN_DNS_SENSOR=sendmsg` in a unit drop-in).
    #[arg(
        long = "dns-sensor",
        env = "NN_DNS_SENSOR",
        value_enum,
        default_value_t = DnsSensor::Skb
    )]
    pub(crate) dns_sensor: DnsSensor,

    // Lab PR 219.
    /// Exploit guard (experimental): catches a gain of credentials,
    /// namespaces or root that the kernel's own mechanisms did not make for
    /// the system call in progress (rules NN-L-EPG-001/002). `lite`
    /// (default): no system-call hooks — the mechanisms are judged on the
    /// call in progress, and a credential changed without one is caught at
    /// its first use (`capable`, exec, a root-only file open). `strict`:
    /// the comparison around every system call (opt-in: hundreds of
    /// nanoseconds per call of an unprivileged task; refused below Linux
    /// 6.1). `off`: not attached, reported as a degradation (also
    /// `NN_EXPLOIT_GUARD=off`, a variable that weakens the protection).
    #[arg(
        long = "exploit-guard",
        env = "NN_EXPLOIT_GUARD",
        value_enum,
        default_value_t = ExploitGuard::Lite
    )]
    pub(crate) exploit_guard: ExploitGuard,

    /// What the exploit guard does on a finding. `detect` (default): a
    /// signed record; the task continues. `enforce`: the kernel kills the
    /// task (SIGKILL) before it returns to user mode (in `lite`, the use
    /// itself is also refused with EPERM), then the record. `--detect-only`
    /// keeps it at `detect`.
    #[arg(
        long = "exploit-guard-response",
        env = "NN_EXPLOIT_GUARD_RESPONSE",
        value_enum,
        default_value_t = ExploitGuardResponse::Detect
    )]
    pub(crate) exploit_guard_response: ExploitGuardResponse,

    /// Exploit guard: how many tasks it tracks. `strict`: default
    /// `/proc/sys/kernel/pid_max` (every live task fits; not
    /// preallocated). `lite`: default `min(pid_max, threads-max)` capped at
    /// 65536 (preallocated, about 150 bytes a task; at most 1048576); when
    /// it is full the oldest entries are evicted and taken again, counted
    /// and reported (at most once every 600 s).
    #[arg(long = "exploit-guard-tasks", env = "NN_EXPLOIT_GUARD_TASKS")]
    pub(crate) exploit_guard_tasks: Option<u32>,

    /// Removed in Wave 4 (lab PR 214) with the on-host LLM advisor, as
    /// the four below: accepted so that a unit written for an older agent
    /// still starts, ignored, and named in a WARN at start
    /// ([`northnarrow_agent::removed_settings`]).
    #[arg(long = "no-ade", hide = true)]
    pub(crate) removed_no_ade: bool,
    #[arg(long = "ade-model", hide = true, value_name = "PATH")]
    pub(crate) removed_ade_model: Option<std::ffi::OsString>,
    #[arg(long = "ade-timeout", hide = true, value_name = "SECS")]
    pub(crate) removed_ade_timeout: Option<std::ffi::OsString>,
    #[arg(long = "ade-prompt", hide = true, value_name = "PATH")]
    pub(crate) removed_ade_prompt: Option<std::ffi::OsString>,
    #[arg(long = "ade-threads", hide = true, value_name = "N")]
    pub(crate) removed_ade_threads: Option<std::ffi::OsString>,

    // NetworkIsolator's IPv4 ruleset. Repo dev path:
    // configs/combat-rules.v4.
    /// The IPv4 firewall ruleset (`iptables-restore` format) applied when
    /// the agent enters COMBAT, to isolate the host from the network.
    #[arg(
        long = "combat-rules",
        value_name = "PATH",
        default_value = "/etc/northnarrow/combat-rules.v4"
    )]
    pub(crate) combat_rules: PathBuf,

    // BUG-031. Repo dev path: configs/combat-rules.v6.
    /// The IPv6 firewall ruleset (`ip6tables-restore` format) applied on
    /// COMBAT alongside the IPv4 one. If the file is missing, IPv6 is not
    /// isolated (a loud warning); the IPv4 isolation still applies.
    #[arg(
        long = "combat-rules-v6",
        value_name = "PATH",
        default_value = "/etc/northnarrow/combat-rules.v6"
    )]
    pub(crate) combat_rules_v6: PathBuf,

    // Beta Step 4b: the opt-in management carve-out (`combat_allow`).
    /// Management networks that stay reachable during COMBAT: a list of
    /// CIDR blocks, one per line, so that a remote operator on a declared
    /// management network is not locked out. Read again each time COMBAT
    /// engages. Empty or missing (the shipped state): full isolation.
    #[arg(
        long = "combat-allow-cidrs",
        value_name = "PATH",
        default_value = northnarrow_agent::anti_tamper::combat_allow::DEFAULT_COMBAT_ALLOW_CIDRS
    )]
    pub(crate) combat_allow_cidrs: PathBuf,

    /// The administrators' public keys, which the agent's admin socket
    /// checks every signed `nn-admin` request against. If the file is
    /// missing the admin socket is not started: the agent still runs,
    /// still enters COMBAT and isolates the network on an intrusion, but
    /// nothing can release COMBAT short of a reboot.
    #[arg(
        long = "admin-pub",
        value_name = "PATH",
        default_value = "/etc/northnarrow/admin.pub"
    )]
    pub(crate) admin_pub: PathBuf,

    // Beta Step 3; the default is the watchdog next to the agent (review
    // 26).
    /// The installed watchdog binary: a process is trusted as the watchdog
    /// only if it runs this file (checked through `/proc/<pid>/exe`).
    /// Default: `northnarrow-watchdog` next to this agent's executable
    /// (`/usr/local/bin` for `install.sh`, `/usr/bin` for a package). It
    /// must not be the agent's own binary: the start is refused.
    #[arg(long = "watchdog-exe", value_name = "PATH")]
    pub(crate) watchdog_exe: Option<PathBuf>,

    // Tappa 8 A3 + A8: the third anti-replay layer of the signed-payload
    // pipeline (design §6.4 layer 3), persisted per design §6.5.
    /// This install's agent id: 16 random bytes (32 hex characters), made
    /// at the first start. Every signed admin request names it, so a
    /// signature made for one install cannot be replayed on another. Keep
    /// it in /etc/northnarrow: another directory is not supported (a
    /// restart is refused).
    #[arg(
        long = "agent-id-file",
        value_name = "PATH",
        default_value = "/etc/northnarrow/agent_id"
    )]
    pub(crate) agent_id_file: PathBuf,

    // Tappa 7 task 6, Watchdog W6: the watchdog's PID joins
    // `PROTECTED_PIDS` (the LSM `task_kill` + `ptrace_access_check`
    // hooks); purely additive co-protection.
    /// The watchdog's PID file (what the watchdog's `--pidfile` writes).
    /// If it exists when the agent starts, the agent protects the watchdog
    /// as it protects itself: kill signals and ptrace against it are
    /// refused in the kernel. A missing file is fine: the agent starts
    /// without a watchdog.
    #[arg(
        long = "watchdog-pidfile",
        value_name = "PATH",
        default_value = "/run/northnarrow/watchdog.pid"
    )]
    pub(crate) watchdog_pidfile: PathBuf,

    /// The Unix socket `nn-admin` connects to. A file left there by an
    /// unclean stop is removed at the start.
    #[arg(
        long = "admin-socket",
        value_name = "PATH",
        default_value = "/run/northnarrow/admin.sock"
    )]
    pub(crate) admin_socket: PathBuf,

    // PHASE_D_003 (Tappa 8 B1): tests point it at a per-test tempdir so
    // each run gets a fresh key without touching /etc/northnarrow.
    /// The agent's signing key, which signs its audit log and its evidence
    /// chains (made at the first start). Keep it in /etc/northnarrow:
    /// another directory is not supported (a restart is refused).
    #[arg(
        long = "signing-key-file",
        value_name = "PATH",
        default_value = northnarrow_agent::audit::DEFAULT_SIGNING_KEY_PATH,
    )]
    pub(crate) signing_key_file: PathBuf,

    // PHASE_D_003 (Tappa 8 B1 + B5).
    /// The agent's signed audit log. Keep it in /etc/northnarrow: another
    /// directory is not supported (a restart is refused).
    #[arg(
        long = "audit-log-file",
        value_name = "PATH",
        default_value = northnarrow_agent::audit::DEFAULT_AUDIT_LOG_PATH,
    )]
    pub(crate) audit_log_file: PathBuf,

    // Hidden: install.sh writes it at the default path; refused once a
    // boot of this install has verified against it (external audit
    // DEP-009).
    /// The install manifest `install.sh` writes (provenance, and the hashes
    /// of the installed binaries and kernel object); the agent checks
    /// itself against it at every start.
    #[arg(
        long = "install-manifest",
        hide = true,
        value_name = "PATH",
        default_value = northnarrow_agent::install_manifest::DEFAULT_INSTALL_MANIFEST_PATH,
    )]
    pub(crate) install_manifest: PathBuf,

    // PHASE_D_003 (Tappa 8 A8). Hidden: the watchdog reads the marker at
    // its own `--shutdown-marker`; tests use a per-test tempdir so the
    // watchdog can be mocked or skipped without colliding with a real
    // install.
    /// The marker the agent leaves when a signed shutdown stops it.
    #[arg(
        long = "shutdown-marker-file",
        hide = true,
        value_name = "PATH",
        default_value = northnarrow_agent::shutdown_marker::DEFAULT_MARKER_PATH,
    )]
    pub(crate) shutdown_marker_file: PathBuf,

    // Tappa 9 C7.
    /// The shipped list of paths the file-integrity monitor (FIM) watches:
    /// one absolute path per line, `#` comments. `install.sh` installs it;
    /// add or disable paths in the local overlay (`--fim-paths-local`).
    #[arg(
        long = "fim-paths-v1",
        value_name = "PATH",
        default_value = northnarrow_agent::fim::paths_config::DEFAULT_PATHS_V1,
    )]
    pub(crate) fim_paths_v1: PathBuf,

    // Tappa 9 C7 / §13 Q7.
    /// The operator's overlay of the FIM paths: `+/abs/path` adds a path,
    /// `-/abs/path` disables a shipped one; stored with `nn-admin config
    /// overlay set fim-paths`. A missing file means no overlay.
    #[arg(
        long = "fim-paths-local",
        value_name = "PATH",
        default_value = northnarrow_agent::fim::paths_config::DEFAULT_PATHS_LOCAL,
    )]
    pub(crate) fim_paths_local: PathBuf,

    // Tappa 9 C3 / C7. Hidden: tests point it at a tempdir so each run gets
    // a fresh chain.
    /// The FIM baseline chain.
    #[arg(
        long = "fim-baseline-file",
        hide = true,
        value_name = "PATH",
        default_value = northnarrow_agent::fim::baseline::DEFAULT_BASELINE_PATH,
    )]
    pub(crate) fim_baseline_file: PathBuf,

    // Tappa 9 C4 / C7: tests point it at a tempdir.
    /// The FIM drift log: the signed chain of the changes to watched files
    /// (`nn-admin fim report` reads it).
    #[arg(
        long = "fim-drift-file",
        value_name = "PATH",
        default_value = northnarrow_agent::fim::drain::DEFAULT_DRIFT_LOG_PATH,
    )]
    pub(crate) fim_drift_file: PathBuf,

    // Tappa 9.0.a. Hidden: tests point it at a tempdir.
    /// The detection chain.
    #[arg(
        long = "detections-file",
        hide = true,
        value_name = "PATH",
        default_value = northnarrow_agent::detection_store::DEFAULT_DETECTIONS_LOG_PATH,
    )]
    pub(crate) detections_file: PathBuf,

    // Lot 374: the watchdog's `--witness-dir`.
    /// The directory of the watchdog's witness chain (created at the start,
    /// protected with the state directory).
    #[arg(
        long = "witness-dir",
        value_name = "DIR",
        default_value = nn_proto::witness::WITNESS_DIR,
    )]
    pub(crate) witness_dir: PathBuf,

    // Tappa 9.0.c: the event-sourced triage-status chain, sibling of the
    // detection log. Hidden: tests point it at a tempdir.
    /// The triage-status chain.
    #[arg(
        long = "status-events-file",
        hide = true,
        value_name = "PATH",
        default_value = northnarrow_agent::detection_store::DEFAULT_STATUS_EVENTS_LOG_PATH,
    )]
    pub(crate) status_events_file: PathBuf,

    // R12c (lab PR 270): sibling of the detection log; tests point it at a
    // tempdir.
    /// The actions log: the signed chain of every response's intent before
    /// it acts and its outcome after.
    #[arg(
        long = "actions-file",
        value_name = "PATH",
        default_value = northnarrow_agent::response::journal::DEFAULT_ACTIONS_LOG_PATH,
    )]
    pub(crate) actions_file: PathBuf,

    // R12c-2 (lab PR 270): tests point it at a tempdir.
    /// The heartbeat log: a signed beat every `NN_HEARTBEAT_SECS` (30 s)
    /// that a verifier on another host reads (`nn-admin heartbeat export`
    /// and `watch`).
    #[arg(
        long = "heartbeat-file",
        value_name = "PATH",
        default_value = northnarrow_agent::heartbeat::DEFAULT_HEARTBEAT_LOG_PATH,
    )]
    pub(crate) heartbeat_file: PathBuf,

    // Tappa 9.5 K2 / K6: a missing file is an empty registry; the K6 admin
    // dispatch creates it on the first deploy. Hidden: tests point it at a
    // tempdir.
    /// The canary registry chain.
    #[arg(
        long = "canary-registry-file",
        hide = true,
        value_name = "PATH",
        default_value = northnarrow_agent::canary::registry::DEFAULT_REGISTRY_PATH,
    )]
    pub(crate) canary_registry_file: PathBuf,

    // Tappa 9.5 K3 / K6: the K3 detector appends one row per canary access.
    // Hidden: tests point it at a tempdir.
    /// The canary access chain.
    #[arg(
        long = "canary-access-file",
        hide = true,
        value_name = "PATH",
        default_value = northnarrow_agent::canary::access_log::DEFAULT_ACCESS_LOG_PATH,
    )]
    pub(crate) canary_access_file: PathBuf,

    // Tappa 9.5 K4 / K6: the K6 deploy dispatch renders the canaries from
    // these templates.
    /// The directory of the canary templates (`<family>.tmpl`) that file
    /// and credential canaries are made from (network and process canaries
    /// need none).
    #[arg(
        long = "canary-template-dir",
        value_name = "PATH",
        default_value = northnarrow_agent::canary::templates::DEFAULT_TEMPLATE_DIR,
    )]
    pub(crate) canary_template_dir: PathBuf,

    // Tappa 10 N8: tests point it at a tempdir. The admin verbs read this
    // file (external audit NN-AUD-082: they used to read the built-in path
    // whatever this flag said). Bootstrapped before the LSM hooks attach,
    // so PROTECTED_INODES has an inode to register.
    /// The network flow log: the signed chain of closed connections, one
    /// row per flow (`nn-admin net flows`, `net resolve` and `net
    /// fingerprint` read it and its rotated archives).
    #[arg(
        long = "netflow-file",
        value_name = "PATH",
        default_value = northnarrow_agent::admin_socket::DEFAULT_NETFLOW_JSONL_PATH,
    )]
    pub(crate) netflow_file: PathBuf,

    // Tappa 10 N9: one row per `inet_csk_listen_start` kernel event.
    // Hidden: tests point it at a tempdir.
    /// The listening-socket chain (`nn-admin net listeners` reads it).
    #[arg(
        long = "netflow-listeners-file",
        hide = true,
        value_name = "PATH",
        default_value = northnarrow_agent::net::drain::DEFAULT_NETFLOW_LISTENERS_JSONL_PATH,
    )]
    pub(crate) netflow_listeners_file: PathBuf,

    // External audit NN-AUD-108 (lab PR 160). Hidden: the default sits
    // next to `--audit-log-file`, which a test run moves with it.
    /// The signed head anchor of the chains. Default: `chain_heads.json`
    /// next to `--audit-log-file`.
    #[arg(long = "chain-heads-file", hide = true, value_name = "PATH")]
    pub(crate) chain_heads_file: Option<PathBuf>,

    // Tappa 10 N9.
    /// The shipped IP/CIDR blocklist that rule NN-L-NET-001 checks
    /// connections against (read at the start); add your own entries in
    /// the local overlay (`--netflow-blocklist-local`).
    #[arg(
        long = "netflow-blocklist-v1",
        value_name = "PATH",
        default_value = DEFAULT_NETFLOW_BLOCKLIST_V1,
    )]
    pub(crate) netflow_blocklist_v1: PathBuf,

    // Tappa 10 N9.
    /// The operator's overlay of the IP/CIDR blocklist: `+` adds an entry,
    /// `-` disables a shipped one; stored with `nn-admin config overlay
    /// set netflow-blocklist`. A missing file means no overlay.
    #[arg(
        long = "netflow-blocklist-local",
        value_name = "PATH",
        default_value = DEFAULT_NETFLOW_BLOCKLIST_LOCAL,
    )]
    pub(crate) netflow_blocklist_local: PathBuf,

    // Tappa 10 N9; ships empty per §10 / N8.
    /// The shipped blocklist of TLS client fingerprints (JA3) that rule
    /// NN-L-NET-003 checks (read at the start; ships empty).
    #[arg(
        long = "netflow-ja3-blocklist-v1",
        value_name = "PATH",
        default_value = DEFAULT_NETFLOW_JA3_BLOCKLIST_V1,
    )]
    pub(crate) netflow_ja3_blocklist_v1: PathBuf,

    // Tappa 10 N9.
    /// The operator's overlay of the JA3 blocklist, stored with `nn-admin
    /// config overlay set netflow-ja3-blocklist`. A missing file means no
    /// overlay.
    #[arg(
        long = "netflow-ja3-blocklist-local",
        value_name = "PATH",
        default_value = DEFAULT_NETFLOW_JA3_BLOCKLIST_LOCAL,
    )]
    pub(crate) netflow_ja3_blocklist_local: PathBuf,

    // Tappa 10.5 D2.
    /// The shipped list of process names (`comm`) that some process rules
    /// do not fire on (the file's header names them). `install.sh`
    /// installs it; the agent reads it with the local overlay at the start.
    #[arg(
        long = "process-comm-allowlist-v1",
        value_name = "PATH",
        default_value = northnarrow_agent::config::comm_allowlist::PROCESS_COMM_ALLOWLIST_V1,
    )]
    pub(crate) process_comm_allowlist_v1: PathBuf,

    // Tappa 10.5 D2.
    /// The operator's overlay of the process-name allowlist: `+comm`
    /// exempts a name, `-comm` re-enables detection on a shipped one;
    /// stored with `nn-admin config overlay set process-comm-allowlist`. A
    /// missing file means no overlay.
    #[arg(
        long = "process-comm-allowlist-local",
        value_name = "PATH",
        default_value = northnarrow_agent::config::comm_allowlist::PROCESS_COMM_ALLOWLIST_LOCAL,
    )]
    pub(crate) process_comm_allowlist_local: PathBuf,

    // Tappa 10.5 D4.
    /// The shipped list of trusted process names (`comm`) the network
    /// rules do not fire on. `install.sh` installs it; the agent reads it
    /// with the local overlay at the start.
    #[arg(
        long = "netflow-comm-allowlist-v1",
        value_name = "PATH",
        default_value = northnarrow_agent::config::comm_allowlist::NETFLOW_COMM_ALLOWLIST_V1,
    )]
    pub(crate) netflow_comm_allowlist_v1: PathBuf,

    // Tappa 10.5 D4.
    /// The operator's overlay of the network process-name allowlist:
    /// `+comm` adds a name, `-comm` re-enables detection on a shipped one;
    /// stored with `nn-admin config overlay set netflow-comm-allowlist`. A
    /// missing file means no overlay.
    #[arg(
        long = "netflow-comm-allowlist-local",
        value_name = "PATH",
        default_value = northnarrow_agent::config::comm_allowlist::NETFLOW_COMM_ALLOWLIST_LOCAL,
    )]
    pub(crate) netflow_comm_allowlist_local: PathBuf,

    // Lab PR 224 (CM-02 c): LSM `socket_connect`.
    /// Refuse in the kernel, with EPERM, every connection to an address of
    /// the IP/CIDR blocklist, before any packet leaves; each refusal is a
    /// signed NN-L-NET-001 record. Off by default: without it NN-L-NET-001
    /// kills the process once the connection is made. Entries wider than
    /// /8 (IPv4) or /16 (IPv6), or covering loopback, are left out of the
    /// kernel's refusal (the rule still judges them). Ignored in
    /// detect-only mode, which never refuses a connection. Also
    /// `NN_NET_CONNECT_DENY=1` (or `true`, `yes`, `on`; `0`, `false`, `no`,
    /// `off` leave it off).
    #[arg(
        long = "net-connect-deny",
        env = "NN_NET_CONNECT_DENY",
        default_value_t = false,
        value_parser = clap::builder::BoolishValueParser::new()
    )]
    pub(crate) net_connect_deny: bool,

    // Lab PR 224 (CM-02 b).
    /// An open TCP connection is judged again every this many seconds (by
    /// the rules that need no byte count, with the process's current
    /// executable).
    #[arg(
        long = "net-snapshot-interval-secs",
        env = "NN_NET_SNAPSHOT_INTERVAL_SECS",
        value_name = "SECS",
        default_value_t = northnarrow_agent::net::flow_tracker::DEFAULT_SNAPSHOT_SECS,
        value_parser = clap::value_parser!(u64).range(1..=86_400)
    )]
    pub(crate) net_snapshot_interval_secs: u64,

    // Lab PR 224.
    /// An open connection is first judged once it has been open this many
    /// seconds.
    #[arg(
        long = "net-snapshot-min-age-secs",
        env = "NN_NET_SNAPSHOT_MIN_AGE_SECS",
        value_name = "SECS",
        default_value_t = northnarrow_agent::net::flow_tracker::DEFAULT_SNAPSHOT_SECS,
        value_parser = clap::value_parser!(u64).range(0..=86_400)
    )]
    pub(crate) net_snapshot_min_age_secs: u64,

    // Lab PR 224.
    /// At most this many open connections are judged per round (every 10
    /// s); the others wait for the next round (`nn-admin net status` counts
    /// them).
    #[arg(
        long = "net-snapshot-max",
        env = "NN_NET_SNAPSHOT_MAX",
        value_name = "N",
        default_value_t = northnarrow_agent::net::flow_tracker::DEFAULT_SNAPSHOT_MAX,
        value_parser = clap::builder::RangedU64ValueParser::<usize>::new().range(0..=65_536)
    )]
    pub(crate) net_snapshot_max: usize,

    // Lab PR 224 (CM-14).
    /// Scan detection (rule NN-L-NET-026): record one process (or the
    /// children of one parent) that reaches this many distinct destination
    /// addresses within the scan window.
    #[arg(
        long = "net-scan-hosts",
        env = "NN_NET_SCAN_HOSTS",
        value_name = "N",
        default_value_t = northnarrow_agent::decision::rules::net_fanout::DEFAULT_SCAN_HOSTS,
        value_parser = clap::builder::RangedU64ValueParser::<usize>::new().range(1..=1_000_000)
    )]
    pub(crate) net_scan_hosts: usize,

    // Lab PR 224.
    /// Scan detection: also record one process (or the children of one
    /// parent) that reaches this many distinct (address, port) pairs within
    /// the scan window.
    #[arg(
        long = "net-scan-pairs",
        env = "NN_NET_SCAN_PAIRS",
        value_name = "N",
        default_value_t = northnarrow_agent::decision::rules::net_fanout::DEFAULT_SCAN_PAIRS,
        value_parser = clap::builder::RangedU64ValueParser::<usize>::new().range(1..=1_000_000)
    )]
    pub(crate) net_scan_pairs: usize,

    // Lab PR 224: the kill is held behind the per-rule response policy.
    /// Scan detection: kill a process that reaches this many distinct
    /// addresses within the scan window (0: never). The kill is held, and
    /// only recorded, unless the rule policy (`nn-admin policy set`) says
    /// `enforce` for NN-L-NET-026.
    #[arg(
        long = "net-scan-kill-hosts",
        env = "NN_NET_SCAN_KILL_HOSTS",
        value_name = "N",
        default_value_t = northnarrow_agent::decision::rules::net_fanout::DEFAULT_SCAN_KILL_HOSTS,
        value_parser = clap::builder::RangedU64ValueParser::<usize>::new().range(0..=1_000_000)
    )]
    pub(crate) net_scan_kill_hosts: usize,

    // Lab PR 224.
    /// Scan detection: the scan window, in seconds.
    #[arg(
        long = "net-scan-window-secs",
        env = "NN_NET_SCAN_WINDOW_SECS",
        value_name = "SECS",
        default_value_t = northnarrow_agent::decision::rules::net_fanout::DEFAULT_SCAN_WINDOW_SECS,
        value_parser = clap::value_parser!(u64).range(1..=3_600)
    )]
    pub(crate) net_scan_window_secs: u64,

    // Lab PR 224.
    /// Brute-force detection (rule NN-L-NET-027): record one process (or
    /// the children of one parent) that makes this many connections to
    /// login services (SSH, Telnet, RDP, VNC) within the brute-force
    /// window, to one host or to many.
    #[arg(
        long = "net-brute-connects",
        env = "NN_NET_BRUTE_CONNECTS",
        value_name = "N",
        default_value_t = northnarrow_agent::decision::rules::net_fanout::DEFAULT_BRUTE_CONNECTS,
        value_parser = clap::builder::RangedU64ValueParser::<usize>::new().range(1..=1_000_000)
    )]
    pub(crate) net_brute_connects: usize,

    // Lab PR 224: the kill is held behind the per-rule response policy.
    /// Brute-force detection: kill a process that makes this many (0:
    /// never). The kill is held, and only recorded, unless the rule policy
    /// (`nn-admin policy set`) says `enforce` for NN-L-NET-027.
    #[arg(
        long = "net-brute-kill-connects",
        env = "NN_NET_BRUTE_KILL_CONNECTS",
        value_name = "N",
        default_value_t = northnarrow_agent::decision::rules::net_fanout::DEFAULT_BRUTE_KILL_CONNECTS,
        value_parser = clap::builder::RangedU64ValueParser::<usize>::new().range(0..=1_000_000)
    )]
    pub(crate) net_brute_kill_connects: usize,

    // Lab PR 224.
    /// Brute-force detection: the brute-force window, in seconds.
    #[arg(
        long = "net-brute-window-secs",
        env = "NN_NET_BRUTE_WINDOW_SECS",
        value_name = "SECS",
        default_value_t = northnarrow_agent::decision::rules::net_fanout::DEFAULT_BRUTE_WINDOW_SECS,
        value_parser = clap::value_parser!(u64).range(1..=86_400)
    )]
    pub(crate) net_brute_window_secs: u64,

    // Lab PR 224.
    /// A program whose processes and their descendants legitimately reach
    /// many hosts (the host's own monitoring), exempt from scan and
    /// brute-force detection beside the built-in list: the name of its
    /// executable, or of the script an interpreter runs, installed in a
    /// root-owned system directory. Repeatable, or a comma-separated list
    /// in `NN_NET_FANOUT_EXEMPT`.
    #[arg(
        long = "net-fanout-exempt",
        env = "NN_NET_FANOUT_EXEMPT",
        value_name = "PROGRAM",
        value_delimiter = ','
    )]
    pub(crate) net_fanout_exempt: Vec<String>,

    /// The agent's PID file. It is written atomically once every
    /// protection hook is attached (when "decision engine ready" is
    /// logged), so its existence is the readiness signal for supervisors
    /// and test harnesses, and it is removed at a clean stop. A file left
    /// by a crashed run is overwritten, not trusted: check /proc/<pid>
    /// before trusting its contents. The shipped unit passes
    /// /run/northnarrow/agent.pid; the list of the agent's kernel program
    /// ids and the records of refused starts (boot-refusals/) are written
    /// beside it. Without this option none of them is written.
    #[arg(long = "pid-file", value_name = "PATH")]
    pub(crate) pid_file: Option<PathBuf>,

    // Lab PR 223 (docs/design/EXEC_QUARANTINE.md).
    /// Exec quarantine at first sight (experimental). `off` (default).
    /// `observe`: a new executable run from a guarded location (/tmp,
    /// /var/tmp, /dev/shm, a home directory, a world-writable directory, a
    /// memfd, a deleted file) is scanned while it runs, and the record
    /// says what would have been done. `enforce`: the kernel holds it
    /// before its first instruction until the scanner and the rules have
    /// judged it. A detect-only agent only observes.
    #[arg(
        long = "exec-quarantine",
        env = "NN_EXEC_QUARANTINE",
        value_enum,
        default_value_t = northnarrow_agent::execq::Mode::Off
    )]
    pub(crate) exec_quarantine: northnarrow_agent::execq::Mode,

    /// How long a held process waits for its verdict, in milliseconds
    /// (100 to 10000), before `--exec-quarantine-on-expiry` applies.
    #[arg(
        long = "exec-quarantine-budget-ms",
        env = "NN_EXEC_QUARANTINE_BUDGET_MS",
        value_name = "MS",
        default_value_t = northnarrow_agent::execq::policy::DEFAULT_BUDGET_MS
    )]
    pub(crate) exec_quarantine_budget_ms: u64,

    /// What a held process gets when no verdict comes within the budget
    /// (or its file cannot be scanned). Signed either way.
    #[arg(
        long = "exec-quarantine-on-expiry",
        env = "NN_EXEC_QUARANTINE_ON_EXPIRY",
        value_enum,
        default_value_t = northnarrow_agent::execq::Action::Resume
    )]
    pub(crate) exec_quarantine_on_expiry: northnarrow_agent::execq::Action,

    /// What a held process gets when the scanner calls it suspicious
    /// (heuristics, not a blocklist hit).
    #[arg(
        long = "exec-quarantine-on-suspicious",
        env = "NN_EXEC_QUARANTINE_ON_SUSPICIOUS",
        value_enum,
        default_value_t = northnarrow_agent::execq::Action::Resume
    )]
    pub(crate) exec_quarantine_on_suspicious: northnarrow_agent::execq::Action,

    /// The exec quarantine's scanner binary. Default: `northnarrow-scan`
    /// next to the agent, else /usr/local/bin/northnarrow-scan.
    #[arg(long = "exec-quarantine-scanner", value_name = "PATH")]
    pub(crate) exec_quarantine_scanner: Option<PathBuf>,

    /// The account the scanner runs as (`install.sh` creates it).
    #[arg(
        long = "exec-quarantine-scan-user",
        value_name = "USER",
        default_value = northnarrow_agent::execq::DEFAULT_SCAN_USER
    )]
    pub(crate) exec_quarantine_scan_user: String,

    /// The exec quarantine's signed hash list (`block <sha256> [label]` /
    /// `allow <sha256> [label]`), stored with `nn-admin config overlay set
    /// execq-hashes`.
    #[arg(
        long = "execq-hashes-local",
        value_name = "PATH",
        default_value = northnarrow_agent::execq::DEFAULT_HASHES_LOCAL
    )]
    pub(crate) execq_hashes_local: PathBuf,

    // Lab PR 226 (docs/design/EXEC_POLICY.md).
    /// Exec policy (experimental): rules applied to an exec before it
    /// runs. `off` (default). `audit`: every exec the policy denies (a
    /// memfd, a deleted file, /dev/shm for services and sessions in the
    /// server profile) is recorded as "would deny" and runs. `enforce`: it
    /// is refused with EACCES before the exec takes effect. Execs the
    /// policy quarantines are handed to `--exec-quarantine`. The loader
    /// variables (LD_PRELOAD, LD_AUDIT pointing into a staging location)
    /// and the executable mappings of staged files are judged by the same
    /// policy. A detect-only agent only audits.
    #[arg(
        long = "exec-policy",
        env = "NN_EXEC_POLICY",
        value_enum,
        default_value_t = northnarrow_agent::execpol::Mode::Off
    )]
    pub(crate) exec_policy: northnarrow_agent::execpol::Mode,

    /// The built-in exec policy the signed policy starts from: `server`
    /// (default) or `desktop` (a login session's own staging locations
    /// allowed: AppImage, build trees; memfd and deleted files recorded).
    #[arg(
        long = "exec-policy-profile",
        env = "NN_EXEC_POLICY_PROFILE",
        value_enum,
        default_value_t = northnarrow_agent::execpol::Profile::Server
    )]
    pub(crate) exec_policy_profile: northnarrow_agent::execpol::Profile,

    /// The signed exec policy (`exec <class> <tier> <action>`…), stored
    /// with `nn-admin config overlay set exec-policy`.
    #[arg(
        long = "exec-policy-local",
        value_name = "PATH",
        default_value = northnarrow_agent::execpol::DEFAULT_POLICY_LOCAL
    )]
    pub(crate) exec_policy_local: PathBuf,

    // Lab PR 236.
    /// The signed per-rule response policy (`enforce|alert|audit|off
    /// <rule>`, `exempt <rule> …`), stored with `nn-admin policy set`.
    /// Without it every rule keeps its built-in response.
    #[arg(
        long = "rule-policy-local",
        value_name = "PATH",
        default_value = northnarrow_agent::decision::rule_policy::DEFAULT_LOCAL
    )]
    pub(crate) rule_policy_local: PathBuf,

    // Lot 275.
    /// The signed allowlist of rule NN-L-NET-028 (a connection to a public
    /// address the process did not look up in DNS): the addresses and CIDR
    /// blocks it does not judge, one per line, stored with `nn-admin config
    /// overlay set nodns-allow`.
    #[arg(
        long = "nodns-allow-local",
        value_name = "PATH",
        default_value = northnarrow_agent::decision::rules::net_nodns::DEFAULT_ALLOW_LOCAL
    )]
    pub(crate) nodns_allow_local: PathBuf,

    // Lot 341 (alpha 2/4).
    /// The signed response profile (`profile = alpha|enforcing`), stored
    /// with `nn-admin config overlay set profile`; it applies at the next
    /// start and wins over the install's profile. Without it: the install's
    /// profile (`install.sh` writes `alpha` on a fresh install), else
    /// `enforcing`.
    #[arg(
        long = "profile-local",
        value_name = "PATH",
        default_value = nn_core::response::profile::DEFAULT_LOCAL
    )]
    pub(crate) profile_local: PathBuf,

    /// Exec policy: do not read the new program's environment at exec (no
    /// LD_PRELOAD, LD_AUDIT, GLIBC_TUNABLES or history checks). Also
    /// `NN_EXEC_POLICY_NO_ENV=1` (1/0, true/false, yes/no, on/off).
    #[arg(
        long = "exec-policy-no-env",
        env = "NN_EXEC_POLICY_NO_ENV",
        value_parser = clap::builder::BoolishValueParser::new()
    )]
    pub(crate) exec_policy_no_env: bool,

    /// Exec policy: do not judge executable file mappings (`mmap`). Also
    /// `NN_EXEC_POLICY_NO_MAP=1` (1/0, true/false, yes/no, on/off).
    #[arg(
        long = "exec-policy-no-map",
        env = "NN_EXEC_POLICY_NO_MAP",
        value_parser = clap::builder::BoolishValueParser::new()
    )]
    pub(crate) exec_policy_no_map: bool,
}

impl Cli {
    /// `--chain-heads-file`, or `chain_heads.json` next to the audit log it
    /// anchors (an agent run with its own audit log and key, as the
    /// privileged tests do, never touches the installed agent's anchor).
    pub(crate) fn resolved_chain_heads_file(&self) -> PathBuf {
        self.chain_heads_file.clone().unwrap_or_else(|| {
            self.audit_log_file
                .parent()
                .unwrap_or_else(|| std::path::Path::new("."))
                .join(northnarrow_agent::chain_anchor::HEADS_FILE_NAME)
        })
    }

    /// Lab PR 265 (review #466 F4-bis): the chains whose signed rows say
    /// that this install had a signing identity — the audit log, the
    /// chains the agent anchors, the FIM baseline and the listener log —
    /// with the key's name, the install's id and the head anchor
    /// (`boot::checks::signing_identity`).
    pub(crate) fn identity_paths(&self) -> northnarrow_agent::boot::continuity::IdentityPaths {
        let p = self.chain_paths();
        northnarrow_agent::boot::continuity::IdentityPaths {
            signing_key: self.signing_key_file.clone(),
            agent_id: self.agent_id_file.clone(),
            audit_log: self.audit_log_file.clone(),
            heads: self.resolved_chain_heads_file(),
            chains: vec![
                p.audit,
                p.canary_registry,
                p.canary_access,
                p.detections,
                p.status_events,
                p.netflow,
                p.fim_drift,
                p.actions,
                p.heartbeat,
                self.fim_baseline_file.clone(),
                self.netflow_listeners_file.clone(),
            ],
        }
    }

    /// Lab PR 265 (review #466 F4-bis): the directories of the files that
    /// make this agent — its key, identity, administrators' keys, install
    /// manifest, head anchor and chains — for `boot::checks::agent_mounts`,
    /// which adds `/etc/northnarrow` and `/var/lib/northnarrow` itself.
    pub(crate) fn state_dirs(&self) -> Vec<PathBuf> {
        let heads = self.resolved_chain_heads_file();
        let ids = self.identity_paths();
        let mut files: Vec<&std::path::Path> = vec![
            &self.signing_key_file,
            &self.agent_id_file,
            &self.admin_pub,
            &self.install_manifest,
            &heads,
        ];
        files.extend(ids.chains.iter().map(PathBuf::as_path));
        let mut dirs: Vec<PathBuf> = Vec::new();
        for f in files {
            let d = match f.parent() {
                Some(d) if !d.as_os_str().is_empty() => d.to_path_buf(),
                _ => PathBuf::from("."),
            };
            if !dirs.contains(&d) {
                dirs.push(d);
            }
        }
        dirs
    }

    /// The chains the agent anchors, at the configured paths.
    pub(crate) fn chain_paths(&self) -> northnarrow_agent::chains::ChainPaths {
        northnarrow_agent::chains::ChainPaths {
            audit: self.audit_log_file.clone(),
            canary_registry: self.canary_registry_file.clone(),
            canary_access: self.canary_access_file.clone(),
            detections: self.detections_file.clone(),
            status_events: self.status_events_file.clone(),
            netflow: self.netflow_file.clone(),
            fim_drift: self.fim_drift_file.clone(),
            actions: self.actions_file.clone(),
            heartbeat: self.heartbeat_file.clone(),
        }
    }

    /// Lab PR 223: the guard's configuration for this boot; a detect-only
    /// agent observes.
    pub(crate) fn execq_config(&self, detect_only: bool) -> northnarrow_agent::execq::Config {
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
                let own = antitamper_bpf::kernel_roots::current_exe()
                    .and_then(|p| p.canonicalize())
                    .ok();
                northnarrow_agent::execq::sibling_scanner_exe(own.as_deref())
            }),
            scan_user: self.exec_quarantine_scan_user.clone(),
            hashes_local: self.execq_hashes_local.clone(),
        }
    }

    /// `--watchdog-exe`, or the watchdog next to this agent (review 26).
    pub(crate) fn resolved_watchdog_exe(&self) -> PathBuf {
        self.watchdog_exe.clone().unwrap_or_else(|| {
            let own = antitamper_bpf::kernel_roots::current_exe()
                .and_then(|p| p.canonicalize())
                .ok();
            northnarrow_agent::posture::sibling_watchdog_exe(own.as_deref())
        })
    }

    /// Lot 348 (the re-check of #554, P3): `own` ([`Self::own_exes`])
    /// refused when `--watchdog-exe` names the agent's own executable (the
    /// same device and inode) — the `bpf` hook's watchdog role, the
    /// stale-pid scan's second executable and the posture's verified
    /// watchdog would then be any process running the agent's binary.
    /// `--watchdog-exe` is root's setting (the unit's command line); this
    /// keeps a mistyped one from starting an agent whose two roles are one.
    pub(crate) fn refuse_one_binary_in_both_roles(
        &self,
        own: &northnarrow_agent::anti_tamper::OwnExes,
    ) -> anyhow::Result<()> {
        if own.agent.is_some() && own.agent == own.watchdog {
            anyhow::bail!(
                "--watchdog-exe {} is the agent's own executable: the watchdog must be another \
                 binary (refusing to start with the agent's and the watchdog's roles one)",
                self.resolved_watchdog_exe().display()
            );
        }
        Ok(())
    }

    /// The agent's executable and the watchdog's ([`Self::resolved_watchdog_exe`]),
    /// by device and inode: the stale-pid scan of `PROTECTED_PIDS` and the
    /// `bpf` hook's roles take this one value (lot 344, #554's KVM suites).
    pub(crate) fn own_exes(&self) -> northnarrow_agent::anti_tamper::OwnExes {
        use northnarrow_agent::anti_tamper::{ExeIdentity, OwnExes};
        OwnExes {
            agent: ExeIdentity::of_process(std::process::id()),
            watchdog: ExeIdentity::of_file(&self.resolved_watchdog_exe()),
        }
    }
}

/// `--file-open-sensor`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, clap::ValueEnum)]
pub(crate) enum FileOpenSensor {
    Lsm,
    Tracepoint,
}

/// `--exec-sensor`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, clap::ValueEnum)]
pub(crate) enum ExecSensor {
    Lsm,
    Tracepoint,
}

/// `--dns-sensor`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, clap::ValueEnum)]
pub(crate) enum DnsSensor {
    Skb,
    Sendmsg,
}

/// `--exploit-guard` (lab PR 219).
#[derive(Clone, Copy, Debug, PartialEq, Eq, clap::ValueEnum)]
pub(crate) enum ExploitGuard {
    Off,
    Lite,
    Strict,
}

impl ExploitGuard {
    pub(crate) fn variant(self) -> northnarrow_agent::sensors::epg::Variant {
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
pub(crate) enum ExploitGuardResponse {
    Detect,
    Enforce,
}

impl ExploitGuardResponse {
    pub(crate) fn response(self) -> northnarrow_agent::sensors::epg::Response {
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
    pub(crate) fn removed_flags(&self) -> Vec<&'static str> {
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

/// Held by the tests that parse a command line (R11a, lab PR 261): its
/// flags read the process environment, which `env_switches_read_1_and_0`
/// sets, and in the library's test binary they run beside its other
/// tests (in the binary's they were three).
#[cfg(test)]
pub(crate) static TEST_ENV: parking_lot::Mutex<()> = parking_lot::Mutex::new(());

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::*;

    /// Lab PR 265 (the review of #468, M5): the identity the start looks
    /// for and the directories it checks are every state file of the
    /// command line — the installed agent's paths by default, the test's
    /// with its flags: each chain, the key, the id, the head anchor; each
    /// file's directory, the administrators' keys' and the manifest's too.
    #[test]
    fn the_identity_and_the_state_dirs_are_every_state_file() {
        let _env = TEST_ENV.lock();
        let cli = Cli::try_parse_from(["northnarrow-agent"]).expect("the defaults");
        let ids = cli.identity_paths();
        assert_eq!(ids.signing_key, Path::new("/etc/northnarrow/agent.sig.key"));
        assert_eq!(ids.agent_id, Path::new("/etc/northnarrow/agent_id"));
        assert_eq!(ids.heads, Path::new("/etc/northnarrow/chain_heads.json"));
        // the review of #473: the audit log named, and among the chains
        assert_eq!(ids.audit_log, Path::new("/etc/northnarrow/audit.log"));
        assert!(ids.chains.contains(&ids.audit_log));
        let mut chains: Vec<String> = ids.chains.iter().map(|p| p.display().to_string()).collect();
        chains.sort();
        assert_eq!(
            chains,
            [
                "/etc/northnarrow/audit.log",
                "/var/lib/northnarrow/canaries.jsonl",
                "/var/lib/northnarrow/canary_access.jsonl",
                "/var/lib/northnarrow/detections/actions.jsonl",
                "/var/lib/northnarrow/detections/detections.jsonl",
                "/var/lib/northnarrow/detections/status_events.jsonl",
                "/var/lib/northnarrow/fim_baseline.jsonl",
                "/var/lib/northnarrow/fim_drift.jsonl",
                "/var/lib/northnarrow/heartbeat.jsonl",
                "/var/lib/northnarrow/netflow.jsonl",
                "/var/lib/northnarrow/netflow_listeners.jsonl",
            ]
        );
        let mut dirs: Vec<String> = cli
            .state_dirs()
            .iter()
            .map(|p| p.display().to_string())
            .collect();
        dirs.sort();
        assert_eq!(
            dirs,
            [
                "/etc/northnarrow",
                "/var/lib/northnarrow",
                "/var/lib/northnarrow/detections",
            ]
        );

        let d = std::path::PathBuf::from("/srv/t");
        let flag = |f: &str, name: &str| [f.to_string(), d.join(name).display().to_string()];
        let mut args = vec!["northnarrow-agent".to_string()];
        for (f, name) in [
            ("--signing-key-file", "k/agent.sig.key"),
            ("--agent-id-file", "id/agent_id"),
            ("--admin-pub", "admin/admin.pub"),
            ("--install-manifest", "m/install-manifest.json"),
            ("--audit-log-file", "a/audit.log"),
            ("--chain-heads-file", "h/chain_heads.json"),
            ("--detections-file", "c/detections.jsonl"),
            ("--status-events-file", "c/status_events.jsonl"),
            ("--actions-file", "c/actions.jsonl"),
            ("--heartbeat-file", "c/heartbeat.jsonl"),
            ("--netflow-file", "c/netflow.jsonl"),
            ("--netflow-listeners-file", "c/netflow_listeners.jsonl"),
            ("--fim-baseline-file", "f/fim_baseline.jsonl"),
            ("--fim-drift-file", "f/fim_drift.jsonl"),
            ("--canary-registry-file", "y/canaries.jsonl"),
            ("--canary-access-file", "y/canary_access.jsonl"),
        ] {
            args.extend(flag(f, name));
        }
        let cli = Cli::try_parse_from(&args).expect("a test's command line");
        let ids = cli.identity_paths();
        assert_eq!(ids.heads, d.join("h/chain_heads.json"));
        // R12c (lab PR 270): the actions chain is the tenth, R12c-2's
        // heartbeat the eleventh
        assert_eq!(ids.chains.len(), 11);
        assert!(
            ids.chains.iter().all(|c| c.starts_with(&d)),
            "{:?}",
            ids.chains
        );
        let mut dirs: Vec<String> = cli
            .state_dirs()
            .iter()
            .map(|p| p.strip_prefix(&d).unwrap().display().to_string())
            .collect();
        dirs.sort();
        assert_eq!(dirs, ["a", "admin", "c", "f", "h", "id", "k", "m", "y"]);
    }

    /// Lot 344 (#554's KVM suites): the `bpf` hook knew the watchdog as the
    /// agent's sibling `northnarrow-watchdog` while the agent verified the
    /// one `--watchdog-exe` names — that watchdog's start took the agent's
    /// pins as a foreign process (NN-L-BPF-002 High). Both now read the one
    /// identity: the file `--watchdog-exe` names, and this executable.
    #[test]
    fn the_hook_s_watchdog_is_the_watchdog_the_agent_verifies() {
        use northnarrow_agent::anti_tamper::ExeIdentity;
        let _env = TEST_ENV.lock();
        let dir = tempfile::tempdir().unwrap();
        let wd = dir.path().join("northnarrow-watchdog-elsewhere");
        std::fs::write(&wd, b"a watchdog").unwrap();
        let cli = Cli::try_parse_from([
            "northnarrow-agent".as_ref(),
            "--watchdog-exe".as_ref(),
            wd.as_os_str(),
        ])
        .expect("a test's command line");
        let own = cli.own_exes();
        assert_eq!(own.watchdog, ExeIdentity::of_file(&wd));
        assert!(own.watchdog.is_some());
        assert_eq!(
            own.agent,
            ExeIdentity::of_file(&std::env::current_exe().unwrap())
        );
        assert!(own.agent.is_some());
        assert_ne!(own.agent, own.watchdog);
        // the stale-pid scan keeps exactly these two
        assert_eq!(own.keep(), [own.agent.unwrap(), own.watchdog.unwrap()]);
    }

    /// Lot 348 (named; the re-check of #554, P3): `--watchdog-exe` naming
    /// the agent's own executable is refused at the start; another binary
    /// is not.
    #[test]
    fn a_watchdog_exe_that_is_the_agent_s_own_binary_is_refused() {
        let _env = TEST_ENV.lock();
        let me = std::env::current_exe().unwrap();
        let cli = Cli::try_parse_from([
            "northnarrow-agent".as_ref(),
            "--watchdog-exe".as_ref(),
            me.as_os_str(),
        ])
        .expect("a test's command line");
        let err = cli
            .refuse_one_binary_in_both_roles(&cli.own_exes())
            .expect_err("the agent's own binary");
        assert!(
            err.to_string().contains("the agent's own executable"),
            "{err}"
        );
        // a link to it is the same file
        let dir = tempfile::tempdir().unwrap();
        let link = dir.path().join("northnarrow-watchdog");
        std::os::unix::fs::symlink(&me, &link).unwrap();
        let cli = Cli::try_parse_from([
            "northnarrow-agent".as_ref(),
            "--watchdog-exe".as_ref(),
            link.as_os_str(),
        ])
        .expect("a test's command line");
        assert!(cli
            .refuse_one_binary_in_both_roles(&cli.own_exes())
            .is_err());
        // CONTROL: another file
        let wd = dir.path().join("northnarrow-watchdog-elsewhere");
        std::fs::write(&wd, b"a watchdog").unwrap();
        let cli = Cli::try_parse_from([
            "northnarrow-agent".as_ref(),
            "--watchdog-exe".as_ref(),
            wd.as_os_str(),
        ])
        .expect("a test's command line");
        assert!(cli.refuse_one_binary_in_both_roles(&cli.own_exes()).is_ok());
    }

    /// Wave 4 (lab PR 214): a unit written for an agent with the LLM
    /// advisor still parses — its flags are accepted, ignored and named.
    #[test]
    fn the_removed_advisor_flags_still_parse_and_are_named() {
        let _env = TEST_ENV.lock();
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
        let _env = TEST_ENV.lock();
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
        let _env = TEST_ENV.lock();
        use clap::CommandFactory;
        let help = Cli::command().render_long_help().to_string();
        for flag in northnarrow_agent::removed_settings::REMOVED_FLAGS {
            assert!(!help.contains(flag), "{flag} in:\n{help}");
        }
    }

    /// `[env: NAME=VALUE]` as `[env: NAME]`: what the process environment
    /// holds is not the help's text.
    fn without_env_values(help: &str) -> String {
        let mut out = String::new();
        for line in help.lines() {
            let mut rest = line;
            while let Some(i) = rest.find("[env: ") {
                let (head, tail) = rest.split_at(i + "[env: ".len());
                out.push_str(head);
                let name_end = tail.find(['=', ']']).unwrap_or(tail.len());
                out.push_str(&tail[..name_end]);
                rest = &tail[name_end..];
                if rest.starts_with('=') {
                    // the `]` that ends the line or opens the next `[…]`
                    let close = rest
                        .match_indices(']')
                        .map(|(j, _)| j)
                        .find(|&j| j + 1 == rest.len() || rest[j + 1..].starts_with(" ["))
                        .unwrap_or(rest.len());
                    rest = &rest[close..];
                }
            }
            out.push_str(rest);
            out.push('\n');
        }
        out
    }

    #[test]
    fn env_values_are_left_out_of_the_help() {
        assert_eq!(
            without_env_values("  [env: NN_X=]\n  [env: NN_Y=a]b] [default: c]\n  [env: NN_Z]\n"),
            "  [env: NN_X]\n  [env: NN_Y] [default: c]\n  [env: NN_Z]\n"
        );
    }

    /// Lot 377: what `northnarrow-agent --help` prints is the checked-in
    /// `agent/tests/golden/help/northnarrow-agent.txt`, so a change of what
    /// an operator reads is a reviewed change of that file, and
    /// xtask/tests/operator_help.rs holds that file to the operator's
    /// language. `NN_BLESS_HELP=1` writes the file instead.
    #[test]
    fn the_help_is_the_checked_in_text() {
        use clap::CommandFactory;
        // the env-backed flags read the process environment
        let _env = TEST_ENV.lock();
        let help = without_env_values(&Cli::command().render_long_help().to_string());
        // the crate's own `tests/` (one literal: the lab gate's path scan
        // takes a join of a `tests` path for the repository's top-level tree)
        let path = Path::new(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/golden/help/northnarrow-agent.txt"
        ));
        if std::env::var_os("NN_BLESS_HELP").is_some_and(|v| v == "1") {
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, &help).unwrap();
            return;
        }
        let want = std::fs::read_to_string(path).unwrap_or_default();
        if help != want {
            let line = help
                .lines()
                .zip(want.lines())
                .position(|(a, b)| a != b)
                .unwrap_or_else(|| help.lines().count().min(want.lines().count()));
            panic!(
                "northnarrow-agent --help is not {} (first difference at line {}: {:?} is \
                 now {:?}); regenerate it with `NN_BLESS_HELP=1 cargo test -p \
                 northnarrow-agent --lib the_help_is_the_checked_in_text` and review the diff",
                path.display(),
                line + 1,
                want.lines().nth(line).unwrap_or("<end of file>"),
                help.lines().nth(line).unwrap_or("<end of output>"),
            );
        }
    }
}
