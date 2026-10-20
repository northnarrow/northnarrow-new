//! `nn-admin` — administrative client for the northnarrow-agent.
//!
//! Thin clap dispatcher over the per-subcommand functions in
//! [`northnarrow_agent::admin_cli`]. All real logic, including the
//! sync Unix-socket transport and the keypair file format, lives
//! there.
//!
//! Exit codes (stable contract; do not renumber):
//! - 0  success
//! - 1  generic startup failure (bad args, file I/O, missing keys)
//! - 2  unlock/shutdown: server rejected the signature
//! - 3  unlock/shutdown: server reports no pending challenge
//! - 4  unlock/shutdown: rate-limited (retry_after_secs printed)
//! - 5  unlock/shutdown/status: transport / protocol failure
//!   (Tappa 8 A9 also folds TimestampSkew, AgentIdMismatch,
//!   UnknownOperation, ProtocolVersionUnsupported here — all
//!   "operator must investigate environment / config / version
//!   mismatch before retrying" failures)
//! - 6  shutdown: quorum not met (too few distinct valid sigs)
//!   (NEW in Tappa 8 A9 per design §5.3)
//! - 7  shutdown: role check failed (key valid but lacks `shutdown`)
//!   (NEW in Tappa 8 A9 per design §5.3); unlock: the key lacks `unlock`
//!   (lab PR 217, the signed unlock)
//! - 8  evidence missing or altered: `audit verify` (a row that does not
//!   verify, a line that is not a row, a head not reached), `chain verify`
//!   (any BROKEN line; every chain is still reported), `audit read` (lines
//!   that are not audit rows were skipped and named; every row was
//!   printed; external audit MAIN-014, lab PR 190). See
//!   docs/operator/EVIDENCE_CHAINS.md, "Exit codes of the verifiers".
//! - 9  canary burn/refresh: no such canary; response release/restore:
//!   the agent verified the request and did nothing (reason printed);
//!   unlock, force-posture out of COMBAT: the agent verified the request
//!   and could not release the isolation — the tables read back still hold
//!   the COMBAT chain, the posture stays COMBAT (lab PR 217; reason printed)
//! - 141 stdout (or stderr) closed before everything was written —
//!   `nn-admin status | head -1` (128 + SIGPIPE, lab PR 188)
//!
//! Air-gapped split flow (`unlock --request-only` writing a
//! challenge file, plus a separate `nn-admin sign` offline) is on
//! the V1.1 roadmap. Today only the inline `unlock --key <PATH>`
//! shape is supported; see the --help text on the unlock subcommand.
//! Since lab PR 217 it signs an `OperationCode::Unlock` payload (the agent
//! refuses the older signature over the bare nonce): this `nn-admin`
//! cannot unlock an agent older than lab PR 217 — use that agent's own.

use std::io::IsTerminal;
use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};

use northnarrow_agent::admin_cli::{
    load_audit_pubkey, run_audit_read, run_audit_verify_expecting, run_canary_burn,
    run_canary_deploy, run_canary_list, run_canary_refresh, run_chain_verify, run_fim_baseline,
    run_fim_report, run_fim_status, run_force_posture, run_init, run_rotate_keys_add,
    run_rotate_keys_revoke, run_shutdown, run_status, run_trusted_installer_grant, run_unlock,
    run_verify_keys, AuditVerifyOutcome, CanaryBurnOutcome, CanaryDeployOutcome, CanaryDeploySpec,
    CanaryListOutcome, CanaryRefreshOutcome, DetectionSetStatusOutcome, ExpectedHead,
    FimBaselineOutcome, FimReportOutcome, FimStatusOutcome, ForcePostureOutcome, NetJsonlOutcome,
    NetResolveOutcome, RotateKeysOutcome, ShutdownOutcome, StatusOutcome,
    TrustedInstallerGrantOutcome, UnlockOutcome, VerifyKeysOutcome, AUDIT_READ_SKIPS_LISTED,
};

/// Lab follow-up (lab PR 188): the exit status when stdout (or stderr) was
/// closed before nn-admin wrote everything — `nn-admin status | head -1`,
/// `| grep -m1 …`. 128 + SIGPIPE, what a shell reports for a tool the
/// signal ends; never 0, so `set -o pipefail` does not take a cut-short
/// `audit verify` for a pass.
const EXIT_CLOSED_PIPE: u8 = 141;

/// Lab follow-up (lab PR 188): every line nn-admin prints goes through here
/// (the `println!` family below is shadowed for this crate). Rust ignores
/// SIGPIPE, so a write to a pipe whose reader has gone fails with EPIPE, and
/// std's `println!` panics on it — `panic = "abort"` in the release profile:
/// `nn-admin status | grep -m1 …` exited 134 with a panic message. A closed
/// pipe now ends the command quietly with [`EXIT_CLOSED_PIPE`]; another
/// error writing stdout is reported on stderr and exits 1; one writing
/// stderr has nowhere to be reported and is dropped.
fn emit(to_stderr: bool, args: std::fmt::Arguments<'_>, newline: bool) {
    let written = if to_stderr {
        write_out(&mut std::io::stderr().lock(), args, newline)
    } else {
        write_out(&mut std::io::stdout().lock(), args, newline)
    };
    match written {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::BrokenPipe => {
            std::process::exit(EXIT_CLOSED_PIPE.into())
        }
        Err(_) if to_stderr => {}
        Err(e) => {
            use std::io::Write;
            let _ = writeln!(std::io::stderr(), "nn-admin: writing stdout: {e}");
            std::process::exit(1)
        }
    }
}

/// One `print!` / `println!` to `w`, flushed so a closed pipe surfaces at
/// the write that met it (see [`emit`]).
fn write_out(
    w: &mut impl std::io::Write,
    args: std::fmt::Arguments<'_>,
    newline: bool,
) -> std::io::Result<()> {
    w.write_fmt(args)?;
    if newline {
        w.write_all(b"\n")?;
    }
    w.flush()
}

/// Lab follow-up (lab PR 188): the error of a write to a closed pipe — what
/// [`run_audit_read`] returns when its reader goes — wherever it sits in the
/// chain.
fn is_closed_pipe(e: &anyhow::Error) -> bool {
    e.chain().any(|c| {
        c.downcast_ref::<std::io::Error>()
            .is_some_and(|io| io.kind() == std::io::ErrorKind::BrokenPipe)
    })
}

// Lab follow-up (lab PR 188): std's printing macros panic on a write error;
// these shadow them in this crate and write through `emit`.
macro_rules! println {
    () => {
        $crate::emit(false, format_args!(""), true)
    };
    ($($arg:tt)*) => {
        $crate::emit(false, format_args!($($arg)*), true)
    };
}
macro_rules! print {
    ($($arg:tt)*) => {
        $crate::emit(false, format_args!($($arg)*), false)
    };
}
macro_rules! eprintln {
    () => {
        $crate::emit(true, format_args!(""), true)
    };
    ($($arg:tt)*) => {
        $crate::emit(true, format_args!($($arg)*), true)
    };
}

const DEFAULT_SOCKET: &str = "/run/northnarrow/admin.sock";
const DEFAULT_PUB_PATH: &str = "/etc/northnarrow/admin.pub";
const DEFAULT_AUDIT_LOG_PATH: &str = "/etc/northnarrow/audit.log";
const DEFAULT_SIGNING_KEY_PATH: &str = "/etc/northnarrow/agent.sig.key";
/// Default path of the per-install agent UUID. Must match
/// `Cli::agent_id_file` in `agent/src/main.rs` so nn-admin and the
/// agent read the same on-disk source of truth (design §6.5).
const DEFAULT_AGENT_ID_PATH: &str = "/etc/northnarrow/agent_id";
/// Operator-chosen default per design §10.2 — 30 s is the typical
/// "drain in-flight work" window before the watchdog deadline.
const DEFAULT_GRACE_SECS: u32 = 30;
/// FIM-009 self-upgrade (§15.1) default override window — short by
/// design (just enough to run install.sh + `systemctl restart`).
/// Clamped client-side to the agent's
/// `MAX_TRUSTED_INSTALLER_WINDOW_SECS` (600 s) ceiling.
const DEFAULT_TRUSTED_INSTALLER_WINDOW_SECS: u32 = 120;

#[derive(Parser, Debug)]
#[command(name = "nn-admin", version, about = "NorthNarrow admin CLI")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand, Debug)]
enum Cmd {
    /// Generate a fresh Ed25519 keypair, install the public half
    /// into the agent's admin.pub, and write the private half to
    /// disk for the admin to safeguard. NB: V1 has no air-gapped
    /// split flow — keep the private key on a hardware token or
    /// removable medium and use `nn-admin unlock --key` only on
    /// machines you trust.
    Init {
        /// Where to write the private key (mode 0600). Refuses to
        /// overwrite an existing file unless --force is also given.
        #[arg(long = "priv-out")]
        priv_out: PathBuf,
        /// Public key file to append to. Created mode 0644 if
        /// missing; left untouched if already present (the new key
        /// is appended).
        #[arg(long = "pub-append", default_value = DEFAULT_PUB_PATH)]
        pub_append: PathBuf,
        /// Overwrite an existing private-key file. Off by default
        /// so a typo can't silently shred the operator's only key.
        #[arg(long)]
        force: bool,
    },

    /// Release COMBAT: sign an `unlock` payload over a server-issued
    /// challenge (with this install's agent_id and the time) and submit it.
    /// Succeeds only when the agent tore the isolation down and read the
    /// tables back clear; otherwise exit 9 with what is still in place (the
    /// posture stays COMBAT).
    ///
    /// V1.1 will add a split offline flow; for now this command
    /// must run on a host with both the private key and a route
    /// to the agent's admin socket. An agent older than lab PR 217
    /// needs the nn-admin of its own release.
    Unlock {
        /// Path to the hex-encoded private key file written by
        /// `nn-admin init`. Its admin.pub line needs the `unlock` role.
        #[arg(long)]
        key: PathBuf,
        #[arg(long = "agent-id-file", default_value = DEFAULT_AGENT_ID_PATH)]
        agent_id_file: PathBuf,
        #[arg(long, default_value = DEFAULT_SOCKET)]
        socket: PathBuf,
    },

    /// Print current posture + network isolation state. Add --json
    /// to get a machine-readable response for scripting. Without --key the
    /// agent answers the posture, the isolation, the last admin action and
    /// the COMBAT stage and lock (external audit ASK-009); --key signs the
    /// request and adds the telemetry: ring drops and rejected records, the
    /// response mode (detect-only), the COMBAT evidence gaps.
    Status {
        #[arg(long, default_value = DEFAULT_SOCKET)]
        socket: PathBuf,
        #[arg(long)]
        json: bool,
        /// A key with `audit-read` or `telemetry-read`: the signed read,
        /// telemetry included (one audit row per request).
        #[arg(long)]
        key: Option<PathBuf>,
        #[arg(long = "agent-id-file", default_value = DEFAULT_AGENT_ID_PATH)]
        agent_id_file: PathBuf,
    },

    /// Host hardening checks (Tappa 10.8): kernel lockdown, module
    /// signature enforcement, Secure Boot, unprivileged BPF, kexec, IMA,
    /// BPF LSM, single bpffs mount — the settings that keep root from
    /// rewriting the kernel at runtime, which is the only way around the
    /// agent's anti-tamper. Reads /sys and /proc only; no socket needed.
    /// Exit 0 with no warnings, 2 with warnings (`--json` for scripting).
    HostCheck {
        #[arg(long)]
        json: bool,
    },

    /// Tappa 9.0.b — read the last N persisted detections
    /// (newest-first) over the admin socket. Requires a key carrying
    /// the low-privilege `telemetry-read` role — read-only telemetry,
    /// no COMBAT/control authority. The records stream as JSONL on
    /// stdout (so `| jq` works); a summary goes to stderr.
    Detections {
        /// Path to the operator's `telemetry-read`-role admin private
        /// key.
        #[arg(long)]
        key: PathBuf,
        /// Maximum records to return — the bounded "last N". The agent
        /// caps this server-side and may further truncate to fit the
        /// wire frame.
        #[arg(long, default_value_t = northnarrow_agent::detection_store::DEFAULT_DETECTIONS_LIMIT as u32)]
        limit: u32,
        /// Inclusive lower time bound (UNIX seconds): keep detections
        /// recorded at or after this instant.
        #[arg(long)]
        since: Option<u64>,
        /// Inclusive upper time bound (UNIX seconds): keep detections
        /// recorded at or before this instant.
        #[arg(long)]
        until: Option<u64>,
        /// Keep detections at or above this severity rung.
        #[arg(long = "min-severity", value_enum)]
        min_severity: Option<SeverityArg>,
        /// Exact-match the triage status.
        #[arg(long, value_enum)]
        status: Option<StatusArg>,
        /// Exact-match the originating sensor.
        #[arg(long, value_enum)]
        sensor: Option<SensorArg>,
        /// Substring filter on what a detection names: its executable
        /// (exec sensors), its file (file sensors) or the acting
        /// process's name (`comm`, every sensor). A record is kept when
        /// any of them contains the text, e.g. `--path /usr/bin/curl`,
        /// `--path /etc/cron.d/` or `--path curl`.
        #[arg(long)]
        path: Option<String>,
        #[arg(long = "agent-id-file", default_value = DEFAULT_AGENT_ID_PATH)]
        agent_id_file: PathBuf,
        #[arg(long, default_value = DEFAULT_SOCKET)]
        socket: PathBuf,
    },

    /// Tappa 9.0.c — change a persisted detection's triage status over
    /// the admin socket. Requires a key carrying the `triage` role
    /// (which also subsumes `telemetry-read`, so a triage key can both
    /// read detections and re-status them). Event-sourced: the agent
    /// appends a signed status-change event to a separate chain and
    /// never mutates the detection log; the new status surfaces on the
    /// next `nn-admin detections` read.
    DetectionSetStatus {
        /// Path to the operator's `triage`-role admin private key.
        #[arg(long)]
        key: PathBuf,
        /// The detection id to re-status (from a prior `detections`
        /// read). Must reference an existing detection.
        #[arg(long)]
        id: u64,
        /// The new triage status. `open` is not a valid target (it is
        /// the initial state); the lifecycle only moves forward.
        #[arg(long, value_enum)]
        status: StatusTargetArg,
        /// Optional free-text triage note recorded on the event.
        #[arg(long)]
        note: Option<String>,
        #[arg(long = "agent-id-file", default_value = DEFAULT_AGENT_ID_PATH)]
        agent_id_file: PathBuf,
        #[arg(long, default_value = DEFAULT_SOCKET)]
        socket: PathBuf,
    },

    /// Parse the installed admin.pub, count valid keys, print
    /// fingerprints. Local-only — does not touch the agent socket.
    VerifyKeys {
        #[arg(long, default_value = DEFAULT_PUB_PATH)]
        path: PathBuf,
    },

    /// Tappa 8 A9 — signed agent shutdown (design §10).
    ///
    /// Submits a 2-of-N quorum-signed shutdown request. The agent
    /// verifies through every Tappa 8 layer (nonce binding,
    /// timestamp skew, agent_id binding, signature verify,
    /// distinct-key tally, role check), atomically writes the
    /// watchdog's shutdown-authorisation marker, replies Success,
    /// then exits cleanly. The watchdog (when present) reads the
    /// marker on the agent's pidfd POLLIN and stands down rather
    /// than respawning.
    ///
    /// BOTH keys are required — the quorum requires two distinct
    /// admin keys installed in admin.pub, at least one of them with
    /// the `shutdown` role; the other may be any installed key,
    /// whatever its roles (design §3.3), so every installed key is a
    /// control credential. Same key for both args fails server-side as
    /// QuorumNotMet { required: 2, provided: 1 } because the
    /// server tallies distinct fingerprints. The `--agent-id-file`
    /// path defaults to the design's canonical location; override
    /// only if `nn-admin` is run on a host where the file lives
    /// elsewhere (e.g., SSH-forwarded socket with a separate
    /// copy of the file).
    Shutdown {
        /// Path to the operator's primary admin private key.
        #[arg(long)]
        key: PathBuf,
        /// Path to a second, DISTINCT admin private key
        /// (co-signer): any key installed in admin.pub. The quorum
        /// verify requires distinct fingerprints — passing the same
        /// key as both arms will be rejected by the agent.
        #[arg(long = "cosign-key")]
        cosign_key: PathBuf,
        /// Path to the agent's per-install UUID file (design §6.5).
        /// nn-admin reads this to bind the signed payload to the
        /// specific agent install — a captured signature from
        /// agent-A cannot be replayed against agent-B.
        #[arg(long = "agent-id-file", default_value = DEFAULT_AGENT_ID_PATH)]
        agent_id_file: PathBuf,
        /// Grace period (seconds) the operator gives the agent
        /// to drain in-flight work before the watchdog's
        /// stand-down deadline expires. Capped at 300 s per
        /// design §10.2.
        #[arg(long = "grace-secs", default_value_t = DEFAULT_GRACE_SECS)]
        grace_secs: u32,
        #[arg(long, default_value = DEFAULT_SOCKET)]
        socket: PathBuf,
    },

    /// Tappa 8 A10 — production signed force-posture (design
    /// §4 + §12.2).
    ///
    /// Drives the agent's posture state machine to `target` via
    /// the full Tappa 8 verify path (nonce binding, timestamp
    /// skew, agent_id binding, signature verify, role check).
    /// 1-of-N quorum — only `--key` is required. The admin.pub
    /// line for that key MUST include the `force-posture` role, and
    /// also `unlock` to leave COMBAT.
    ///
    /// NOT the preferred path out of COMBAT. `nn-admin unlock`
    /// carries clearer audit semantics ("admin acknowledged
    /// COMBAT release") than a force-posture COMBAT → anything;
    /// use unlock when releasing COMBAT.
    ///
    /// Distinct from `nn-admin debug force-posture` (the
    /// integration-test path gated by the `debug-trigger` Cargo
    /// feature). Both subcommands stay; production uses this one.
    ForcePosture {
        /// Target posture state.
        #[arg(value_enum)]
        target: ForcePostureTargetArg,
        /// Path to the operator's admin private key (role
        /// `force-posture` required in admin.pub).
        #[arg(long)]
        key: PathBuf,
        /// Path to the agent's per-install UUID file (design §6.5).
        #[arg(long = "agent-id-file", default_value = DEFAULT_AGENT_ID_PATH)]
        agent_id_file: PathBuf,
        #[arg(long, default_value = DEFAULT_SOCKET)]
        socket: PathBuf,
    },

    /// Tappa 8 A13 — atomically add or revoke an admin key in
    /// `/etc/northnarrow/admin.pub` (design §7.2 + §7.3). Both
    /// `add` and `revoke` need a 2-of-N quorum signed by two
    /// distinct installed admin keys, at least one of them carrying
    /// the `rotate-keys` role; the other may be any installed key,
    /// whatever its roles (design §3.3) — custody every installed
    /// key as a control credential. `add` grants only roles one of
    /// the two signers holds. On
    /// success the agent rewrites the file via tmpfile +
    /// `rename(2)` and reloads its in-memory key set so the next
    /// challenge already sees the change.
    ///
    /// Operator workflow per design §7.2:
    ///   1. `nn-admin init --priv-out new.key --bootstrap-only`
    ///      on a trusted host.
    ///   2. Transfer the **public** key (out-of-band).
    ///   3. `nn-admin rotate-keys add --new-pubkey <hex>
    ///      --new-roles unlock,audit-read --key … --cosign-key …`
    RotateKeys {
        #[command(subcommand)]
        sub: RotateKeysCmd,
    },

    /// Tappa 8 A12 — read or verify the tamper-evident audit log
    /// (design §9). Two subcommands: `read` streams entries from
    /// the on-disk JSONL log, `verify` runs the SHA-256 hash
    /// chain + per-entry Ed25519 signature recomputation through
    /// `northnarrow_agent::audit::verify_chain`.
    ///
    /// `audit verify` exits 8 (per design §5.3) on a broken chain,
    /// 0 on success — distinct from the other admin commands so
    /// CI can act on chain integrity specifically. An empty /
    /// missing log file is "0 entries, success" (not an error).
    Audit {
        #[command(subcommand)]
        sub: AuditCmd,
    },

    /// External audit NN-AUD-112 (lab PR 160) — verify every signed chain
    /// in full, offline: the audit log and the canary chains (hashes,
    /// signatures, links, row numbers), the rotating logs with their
    /// archives, manifest and checkpoints, then the files against the
    /// signed head anchor. Exits 8 when a chain is broken or shorter than
    /// its anchored head, 0 when everything verifies. Reads the files
    /// directly (root: they are 0600 or under 0700 directories).
    Chain {
        #[command(subcommand)]
        sub: ChainCmd,
    },

    /// Tappa 9 C6 — FIM operator surface. `fim baseline` queues
    /// a re-compute of the watched-paths SHA-256 baseline
    /// (signed payload, single-sig `fim-manage` role per §13 Q6).
    /// `fim report [--since <unix-ts>]` reads the chained drift
    /// log (signed payload, single-sig `fim-read` role).
    Fim {
        #[command(subcommand)]
        sub: FimCmd,
    },

    /// Tappa 9.5 K6 — deception canary operator surface.
    /// `canary deploy` installs a new canary (File / Process /
    /// Network / Credential variants), `canary list` streams the
    /// chained registry log, `canary burn` permanently retires a
    /// canary, `canary refresh` re-renders the on-disk artefact.
    /// Authorisation: `canary-read` for `list`; `canary-manage`
    /// for `deploy` / `burn` / `refresh` (§12 Q7 SPLIT lock-in).
    Canary {
        #[command(subcommand)]
        sub: CanaryCmd,
    },

    /// Tappa 10 N7 — network observability operator surface.
    /// `net flows` reads the chained netflow log,
    /// `net listeners` snapshots active listeners,
    /// `net resolve <ip>` looks up DNS attribution,
    /// `net fingerprint --flow-id <hex>` dumps JA3/JA4.
    /// All four are `Role::NetRead` (1-of-N quorum per §13 Q6).
    Net {
        #[command(subcommand)]
        sub: NetCmd,
    },

    /// FIM-009 self-upgrade (§15.1) — arm the trusted-installer
    /// override for an in-place agent upgrade. Submits a 1-of-N (M=1)
    /// quorum-signed grant; the admin.pub line for `--key` MUST carry
    /// the `trusted-installer` role. While the window is open the
    /// agent's FS pin is suspended (so install.sh can replace the
    /// protected binary) AND a write to the agent's OWN systemd units
    /// is downgraded from kill to an audit Log. The window is bounded
    /// by --window-secs (clamped to the agent's 600 s ceiling) and by
    /// the next agent restart. Operator flow: grant → install.sh →
    /// `systemctl restart` → signed `fim baseline`.
    TrustedInstallerGrant {
        /// Path to the operator's `trusted-installer`-role admin
        /// private key.
        #[arg(long)]
        key: PathBuf,
        /// Override window in seconds. Clamped to the agent's 600 s
        /// ceiling. Keep it short — just long enough to run install.sh
        /// and restart the unit.
        #[arg(long = "window-secs", default_value_t = DEFAULT_TRUSTED_INSTALLER_WINDOW_SECS)]
        window_secs: u32,
        /// Path to the agent's per-install UUID file (design §6.5) —
        /// binds the signed grant to this specific agent install.
        #[arg(long = "agent-id-file", default_value = DEFAULT_AGENT_ID_PATH)]
        agent_id_file: PathBuf,
        #[arg(long, default_value = DEFAULT_SOCKET)]
        socket: PathBuf,
    },

    /// External audit CMB-016 — undo what the response layer did:
    /// `response status` lists the processes the agent holds in its
    /// containment scopes, the quarantine vault and the COMBAT stage
    /// (`audit-read`); `response release` returns a
    /// contained process to the cgroup it came from and `response restore`
    /// writes a quarantined file back out of the vault (`response-manage`).
    /// The agent does the work and records it in the signed audit log.
    Response {
        #[command(subcommand)]
        sub: ResponseCmd,
    },

    /// Tappa 10.8 — operator configuration the agent loads only when an
    /// admin key signed it (`config overlay set|sign|status`).
    Config {
        #[command(subcommand)]
        sub: ConfigCmd,
    },

    /// Debug-only: force the agent's posture state machine into a
    /// chosen state. Only compiled when the `debug-trigger` Cargo
    /// feature is on.
    #[cfg(feature = "debug-trigger")]
    Debug {
        #[command(subcommand)]
        sub: DebugCmd,
    },
}

#[derive(Subcommand, Debug)]
enum ResponseCmd {
    /// What the response layer holds on this host: contained processes
    /// (scope, the cgroup each came from, whether the pid still names that
    /// process), quarantined files, the COMBAT stage. Read-only.
    Status {
        /// A key with `audit-read`.
        #[arg(long)]
        key: PathBuf,
        #[arg(long = "agent-id-file", default_value = DEFAULT_AGENT_ID_PATH)]
        agent_id_file: PathBuf,
        #[arg(long, default_value = DEFAULT_SOCKET)]
        socket: PathBuf,
    },
    /// Release a process the agent blocked or throttled back to the cgroup
    /// it came from (never the root cgroup; only while the pid still names
    /// the process that was moved). During an open COMBAT episode the
    /// ladder may contain it again.
    Release {
        #[arg(long)]
        pid: u32,
        /// A key with `response-manage`.
        #[arg(long)]
        key: PathBuf,
        #[arg(long = "agent-id-file", default_value = DEFAULT_AGENT_ID_PATH)]
        agent_id_file: PathBuf,
        #[arg(long, default_value = DEFAULT_SOCKET)]
        socket: PathBuf,
    },
    /// Write a quarantined file back out of the vault, to the path it was
    /// taken from unless --to says otherwise. A new file only (never over
    /// an existing one, never through a link), mode 0600, outside the
    /// protected prefixes; the vault keeps the entry. The file may be
    /// malware: restore it to inspect it, not to run it.
    Restore {
        /// The 32-hex vault id (`nn-admin response status`).
        #[arg(long = "vault-id")]
        vault_id: String,
        /// Absolute destination; the directory must exist.
        #[arg(long)]
        to: Option<String>,
        /// A key with `response-manage`.
        #[arg(long)]
        key: PathBuf,
        #[arg(long = "agent-id-file", default_value = DEFAULT_AGENT_ID_PATH)]
        agent_id_file: PathBuf,
        #[arg(long, default_value = DEFAULT_SOCKET)]
        socket: PathBuf,
    },
}

#[derive(Subcommand, Debug)]
enum ConfigCmd {
    /// Operator overlays (`/etc/northnarrow/*.local`): allowlists,
    /// blocklists, FIM paths, posture carve-outs. The agent loads one only
    /// if a key with the `config-manage` role signed its exact content
    /// (`<overlay>.sig`); otherwise it boots on the shipped defaults for
    /// that list and records the refusal.
    Overlay {
        #[command(subcommand)]
        sub: OverlayCmd,
    },
}

#[derive(Subcommand, Debug)]
enum OverlayCmd {
    /// Sign an overlay and store it through the running agent (role
    /// `config-manage`). The agent writes the overlay and its signature;
    /// it takes effect at the next agent start.
    Set {
        /// fim-paths, process-comm-allowlist, netflow-comm-allowlist,
        /// netflow-blocklist, netflow-ja3-blocklist, mass-write-carveout,
        /// escalation-allow, canary-readers.
        kind: String,
        /// The overlay content to store.
        #[arg(long)]
        file: PathBuf,
        #[arg(long)]
        key: PathBuf,
        /// Optional second signer.
        #[arg(long = "cosign-key")]
        cosign_key: Option<PathBuf>,
        #[arg(long = "agent-id-file", default_value = DEFAULT_AGENT_ID_PATH)]
        agent_id_file: PathBuf,
        #[arg(long, default_value = DEFAULT_SOCKET)]
        socket: PathBuf,
    },
    /// Sign an overlay offline and write `<file>.sig` (or `--out`). For
    /// upgrades and hosts where the agent is stopped; with the agent
    /// running, use `set`.
    Sign {
        kind: String,
        #[arg(long)]
        file: PathBuf,
        #[arg(long)]
        key: PathBuf,
        #[arg(long = "cosign-key")]
        cosign_key: Option<PathBuf>,
        #[arg(long = "agent-id-file", default_value = DEFAULT_AGENT_ID_PATH)]
        agent_id_file: PathBuf,
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// Which overlays are present and whether each one would be loaded at
    /// the next agent start (exit 1 if any present overlay is not).
    Status {
        #[arg(long, default_value = "/etc/northnarrow")]
        dir: PathBuf,
        #[arg(long = "admin-pub", default_value = DEFAULT_PUB_PATH)]
        admin_pub: PathBuf,
        #[arg(long = "agent-id-file", default_value = DEFAULT_AGENT_ID_PATH)]
        agent_id_file: PathBuf,
        #[arg(long = "audit-log", default_value = DEFAULT_AUDIT_LOG_PATH)]
        audit_log: PathBuf,
        /// The agent's audit signing key the chain is verified with (its
        /// public half `agent.sig.pub` when the key is closed to readers).
        #[arg(long = "agent-sig-key", default_value = DEFAULT_SIGNING_KEY_PATH)]
        agent_sig_key: PathBuf,
    },
}

#[derive(Subcommand, Debug)]
enum RotateKeysCmd {
    /// Install a new admin key. Requires --new-pubkey (64 hex
    /// chars) and --new-roles (CSV of role keywords, the same the
    /// agent accepts in admin.pub: unlock, shutdown, force-posture,
    /// rotate-keys, audit-read, fim-manage, fim-read, canary-read,
    /// canary-manage, net-read, net-manage, trusted-installer,
    /// telemetry-read, triage, all).
    Add {
        /// 64-hex-char Ed25519 verifying key to install.
        #[arg(long = "new-pubkey")]
        new_pubkey: String,
        /// Comma-separated role allowlist for the new key. At
        /// least one role required. Maps to design §3.2 roles. Each
        /// role must be held by one of the signing keys (`all` only
        /// by a key holding `all`).
        #[arg(long = "new-roles", default_value = "unlock,audit-read")]
        new_roles: String,
        /// Path to the operator's primary admin private key. This
        /// key or the co-signer must carry the `rotate-keys` role.
        #[arg(long)]
        key: PathBuf,
        /// Path to a SECOND, DISTINCT admin private key (co-signer):
        /// any key installed in admin.pub, whatever its roles.
        #[arg(long = "cosign-key")]
        cosign_key: PathBuf,
        #[arg(long = "agent-id-file", default_value = DEFAULT_AGENT_ID_PATH)]
        agent_id_file: PathBuf,
        #[arg(long, default_value = DEFAULT_SOCKET)]
        socket: PathBuf,
    },
    /// Remove the admin.pub line whose pubkey 8-hex-char
    /// fingerprint matches `--fingerprint` (the same value
    /// `nn-admin verify-keys` prints). Refuses to revoke the
    /// last remaining key.
    Revoke {
        /// 8-hex-char fingerprint of the key to revoke.
        #[arg(long)]
        fingerprint: String,
        #[arg(long)]
        key: PathBuf,
        #[arg(long = "cosign-key")]
        cosign_key: PathBuf,
        #[arg(long = "agent-id-file", default_value = DEFAULT_AGENT_ID_PATH)]
        agent_id_file: PathBuf,
        #[arg(long, default_value = DEFAULT_SOCKET)]
        socket: PathBuf,
    },
}

#[derive(Subcommand, Debug)]
enum AuditCmd {
    /// Stream the audit log to stdout, optionally filtered by
    /// timestamp. Default output is a compact human-readable
    /// summary; `--json` emits one canonical JSON object per line
    /// (matches the on-disk JSONL exactly).
    ///
    /// Who acted: the key fingerprint (`key_fp`, `cosigner_fps`) is the
    /// operator's identity. `client_pid`/`client_uid` come from the
    /// kernel (SO_PEERCRED); `client_comm` is the name the connecting
    /// process gave itself, which any process chooses; `client_exe`
    /// (rows from lab PR 179 on) is the program the kernel says it ran.
    ///
    /// A line that is not an audit row (cut, not JSON, not UTF-8, over
    /// 16 MiB) is skipped and named on stderr with its line number; every
    /// row before and after it is printed, and the exit code is 8. The
    /// rows are not verified here: `audit verify` does that.
    Read {
        /// Path to the audit log file (default
        /// /etc/northnarrow/audit.log).
        #[arg(long, default_value = DEFAULT_AUDIT_LOG_PATH)]
        path: PathBuf,
        /// Optional ISO-8601 / RFC-3339 timestamp threshold;
        /// entries whose `ts` is lexicographically `>=` this
        /// value are kept (the field's fixed-width format makes
        /// string comparison equivalent to instant comparison).
        #[arg(long)]
        since: Option<String>,
        /// Emit one canonical JSON object per line instead of
        /// the human summary.
        #[arg(long)]
        json: bool,
    },

    /// Replay the chain in `--from <path>` through
    /// [`northnarrow_agent::audit::verify_chain_file`]. Loads the
    /// verifying key either from `--agent-pubkey <hex>` (off-host
    /// verification with the pubkey conveyed out-of-band) or from
    /// the local `--agent-sig-key <path>` (default
    /// /etc/northnarrow/agent.sig.key — zero-config on the agent
    /// host, requires sudo to read the mode-0400 file).
    ///
    /// Exit 8 at the first row that does not verify or the first line
    /// that is not a row, named with its line number and the rows
    /// verified before it; one pass, one line in memory at a time.
    Verify {
        /// Path to a JSONL chain file (export from `audit read
        /// --json` or the on-disk log itself).
        #[arg(long)]
        from: PathBuf,
        /// Explicit 64-hex-char Ed25519 pubkey of the agent's
        /// audit signing key. Set this when running off-host
        /// (the auditor doesn't have access to the agent's
        /// `agent.sig.key`).
        #[arg(long = "agent-pubkey")]
        agent_pubkey: Option<String>,
        /// Local signing-key file the verifier derives the
        /// pubkey from when `--agent-pubkey` is not given. Mode
        /// 0400 — usually requires sudo.
        #[arg(long = "agent-sig-key", default_value = DEFAULT_SIGNING_KEY_PATH)]
        agent_sig_key: PathBuf,
        /// External audit NN-AUD-108: an `entry_hash` the chain must still
        /// hold (a head recorded earlier: a `chain.head` journal line
        /// forwarded off the host, or `chain verify` output kept there).
        /// Exit 8 when it is gone: rows were cut from the end.
        #[arg(long = "expect-head")]
        expect_head: Option<String>,
        /// The chain must hold a row numbered at least this (`seq`).
        #[arg(long = "min-seq")]
        min_seq: Option<u64>,
    },
}

/// The chains `nn-admin chain verify --log` names.
#[derive(Clone, Copy, Debug, PartialEq, Eq, clap::ValueEnum)]
enum ChainName {
    Audit,
    CanaryRegistry,
    CanaryAccess,
    Detections,
    StatusEvents,
    Netflow,
    FimDrift,
    All,
}

impl ChainName {
    fn key(self) -> Option<&'static str> {
        Some(match self {
            ChainName::Audit => "audit",
            ChainName::CanaryRegistry => "canary_registry",
            ChainName::CanaryAccess => "canary_access",
            ChainName::Detections => "detections",
            ChainName::StatusEvents => "status_events",
            ChainName::Netflow => "netflow",
            ChainName::FimDrift => "fim_drift",
            ChainName::All => return None,
        })
    }
}

#[derive(Subcommand, Debug)]
enum ChainCmd {
    /// Verify the chains in full (default: all of them).
    Verify {
        /// A chain to verify; repeat for several. Default: all.
        #[arg(long = "log", value_enum)]
        log: Vec<ChainName>,
        /// The state directory holding the canary chains and the rotating
        /// logs (`detections/` below it).
        #[arg(long = "state-dir", default_value = "/var/lib/northnarrow")]
        state_dir: PathBuf,
        /// The audit log.
        #[arg(long = "audit-log", default_value = DEFAULT_AUDIT_LOG_PATH)]
        audit_log: PathBuf,
        /// The head anchor (default: `chain_heads.json` next to
        /// `--audit-log`).
        #[arg(long = "heads")]
        heads: Option<PathBuf>,
        /// Explicit 64-hex-char agent pubkey (off-host verification).
        #[arg(long = "agent-pubkey")]
        agent_pubkey: Option<String>,
        /// Signing-key file whose published `agent.sig.pub` (next to it)
        /// gives the pubkey when `--agent-pubkey` is not set.
        #[arg(long = "agent-sig-key", default_value = DEFAULT_SIGNING_KEY_PATH)]
        agent_sig_key: PathBuf,
    },
}

#[derive(Subcommand, Debug)]
enum FimCmd {
    /// Queue a baseline (re)compute. Signed payload, single-sig
    /// `fim-manage` role per §13 Q6. V1.0 semantics: success
    /// schedules the recompute for the next agent restart
    /// (lazy — baseline is a "snapshot of trust" workflow op,
    /// not a security gate).
    Baseline {
        /// Path to the operator's `fim-manage`-role admin
        /// private key.
        #[arg(long)]
        key: PathBuf,
        #[arg(long = "agent-id-file", default_value = DEFAULT_AGENT_ID_PATH)]
        agent_id_file: PathBuf,
        #[arg(long, default_value = DEFAULT_SOCKET)]
        socket: PathBuf,
    },

    /// Stream the chained drift log to stdout, newest rows first
    /// (rotated archives included). Signed payload, single-sig
    /// `fim-read` role. `--since <unix-ts>` filters server-side;
    /// the reply holds the newest rows that fit half
    /// MAX_FRAME_BODY — exit prints a truncation hint when older
    /// rows were left out.
    Report {
        /// Path to the operator's `fim-read`-role admin
        /// private key.
        #[arg(long)]
        key: PathBuf,
        /// Unix-timestamp lower bound. Entries with `ts >=
        /// since` are returned.
        #[arg(long)]
        since: Option<u64>,
        #[arg(long = "agent-id-file", default_value = DEFAULT_AGENT_ID_PATH)]
        agent_id_file: PathBuf,
        #[arg(long, default_value = DEFAULT_SOCKET)]
        socket: PathBuf,
    },

    /// Print the in-process FIM status snapshot: watched-paths
    /// summary (effective / added / disabled-default counts),
    /// baseline + drift chain row counts, last baseline ts,
    /// token-bucket state for the §6.5 hierarchical rate-limiter
    /// (`high_remaining/cap` + `medium_remaining/cap`). Read-only,
    /// signed payload, single-sig `fim-read` role.
    Status {
        /// Path to the operator's `fim-read`-role admin
        /// private key.
        #[arg(long)]
        key: PathBuf,
        #[arg(long = "agent-id-file", default_value = DEFAULT_AGENT_ID_PATH)]
        agent_id_file: PathBuf,
        #[arg(long, default_value = DEFAULT_SOCKET)]
        socket: PathBuf,
    },
}

#[derive(Subcommand, Debug)]
enum CanaryCmd {
    /// Install a new canary (`canary-manage` role). One of four
    /// variants — `file`, `process`, `network`, `credential`. The
    /// server renders the on-disk artefact (for file + credential
    /// canaries) and prints the per-canary stable id on success.
    Deploy {
        /// Operator-chosen human label (e.g. "honeypot-aws-creds").
        /// Free-form; appears in audit + alerts.
        #[arg(long)]
        name: String,
        #[command(subcommand)]
        kind: CanaryDeployKindCmd,
        #[arg(long)]
        key: PathBuf,
        #[arg(long = "agent-id-file", default_value = DEFAULT_AGENT_ID_PATH)]
        agent_id_file: PathBuf,
        #[arg(long, default_value = DEFAULT_SOCKET)]
        socket: PathBuf,
    },

    /// Stream the chained canary registry log, newest rows first
    /// (`canary-read` role). Output mirrors `fim report`: JSONL on
    /// stdout, a 1-line summary on stderr.
    List {
        #[arg(long)]
        key: PathBuf,
        #[arg(long = "agent-id-file", default_value = DEFAULT_AGENT_ID_PATH)]
        agent_id_file: PathBuf,
        #[arg(long, default_value = DEFAULT_SOCKET)]
        socket: PathBuf,
    },

    /// Permanently retire a canary by id (`canary-manage` role).
    /// File / credential artefacts are unlinked, network
    /// listeners closed, process canaries terminated. The K3
    /// detector stops firing for the burned id immediately.
    Burn {
        /// The per-canary stable id printed by `canary deploy`
        /// or `canary list`.
        #[arg(long = "canary-id")]
        canary_id: String,
        #[arg(long)]
        key: PathBuf,
        #[arg(long = "agent-id-file", default_value = DEFAULT_AGENT_ID_PATH)]
        agent_id_file: PathBuf,
        #[arg(long, default_value = DEFAULT_SOCKET)]
        socket: PathBuf,
    },

    /// Re-render a canary's on-disk artefact (`canary-manage`
    /// role). §12 Q2 MANUAL lock-in: no auto-refresh; the
    /// operator must run this explicitly when a canary's bytes
    /// would otherwise grow stale.
    Refresh {
        #[arg(long = "canary-id")]
        canary_id: String,
        #[arg(long)]
        key: PathBuf,
        #[arg(long = "agent-id-file", default_value = DEFAULT_AGENT_ID_PATH)]
        agent_id_file: PathBuf,
        #[arg(long, default_value = DEFAULT_SOCKET)]
        socket: PathBuf,
    },
}

/// `nn-admin canary deploy <kind> ...` — distinct subcommand per
/// canary type so clap can enforce the per-type required flags
/// (e.g. `process` needs `--fake-arg0`, `network` needs
/// `--bind-addr/--bind-port`) at parse time, not at server-side
/// validation time.
#[derive(Subcommand, Debug)]
enum CanaryDeployKindCmd {
    /// Plain file canary. The server creates a placeholder file
    /// at `--path` (current K4 template renders sentinel bytes).
    File {
        /// Absolute on-disk path the canary file should occupy.
        #[arg(long)]
        path: String,
    },
    /// Process canary. The server materialises a fake binary at
    /// `--path` and advertises `--fake-arg0` as its argv[0].
    Process {
        #[arg(long)]
        path: String,
        /// What the canary binary should report as argv[0]
        /// (mirrors what `ps` shows).
        #[arg(long = "fake-arg0")]
        fake_arg0: String,
    },
    /// Network canary: a decoy destination. A local process that
    /// connects to `--bind-addr:--bind-port` trips it (NN-L-CANARY-003);
    /// `0.0.0.0` / `::` is the port at any address of this host. The
    /// agent opens no listener, and a connection from another host is
    /// not seen. Refused when a listener on this host serves the port.
    Network {
        #[arg(long = "bind-addr")]
        bind_addr: String,
        #[arg(long = "bind-port")]
        bind_port: u16,
    },
    /// Credential canary. Same shape as `file` plus a required
    /// `--cred-family` selecting which K4 template renders the
    /// fake credential bytes (e.g. "aws", "docker", "kube").
    Credential {
        #[arg(long)]
        path: String,
        #[arg(long = "cred-family")]
        cred_family: String,
    },
}

impl From<CanaryDeployKindCmd> for CanaryDeploySpec {
    fn from(k: CanaryDeployKindCmd) -> Self {
        match k {
            CanaryDeployKindCmd::File { path } => CanaryDeploySpec::File { path },
            CanaryDeployKindCmd::Process { path, fake_arg0 } => {
                CanaryDeploySpec::Process { path, fake_arg0 }
            }
            CanaryDeployKindCmd::Network {
                bind_addr,
                bind_port,
            } => CanaryDeploySpec::Network {
                bind_addr,
                bind_port,
            },
            CanaryDeployKindCmd::Credential { path, cred_family } => {
                CanaryDeploySpec::Credential { path, cred_family }
            }
        }
    }
}

/// Tappa 10 N7 — net subcommand surface (mirrors FimCmd shape).
#[derive(Subcommand, Debug)]
enum NetCmd {
    /// What the network observation covers now: netflow rows held back
    /// from the rules by the per-uid pacing, pending connects evicted,
    /// the network rings' drops, the network rules that cannot fire in
    /// this build or are blind (a resolver on DNS over TLS), and the rows
    /// no DNS or TLS reader sees into (DoT, QUIC). Signed since external
    /// audit ASK-009: give --key (without it the agent withholds them).
    Status {
        #[arg(long, default_value = DEFAULT_SOCKET)]
        socket: PathBuf,
        #[arg(long)]
        json: bool,
        /// A key with `audit-read` or `telemetry-read` (one audit row per
        /// request).
        #[arg(long)]
        key: Option<PathBuf>,
        #[arg(long = "agent-id-file", default_value = DEFAULT_AGENT_ID_PATH)]
        agent_id_file: PathBuf,
    },

    /// Stream the chained netflow log, newest rows first (rotated
    /// archives included). `--since-unix <ts>` filters server-side;
    /// the reply holds the newest rows that fit one frame.
    Flows {
        /// Path to the operator's `net-read`-role admin
        /// private key.
        #[arg(long)]
        key: PathBuf,
        /// UNIX-timestamp lower bound; entries with `ts >=
        /// since` are returned.
        #[arg(long = "since-unix")]
        since_unix: Option<u64>,
        #[arg(long = "agent-id-file", default_value = DEFAULT_AGENT_ID_PATH)]
        agent_id_file: PathBuf,
        #[arg(long, default_value = DEFAULT_SOCKET)]
        socket: PathBuf,
    },

    /// Stream the listener log, newest rows first: one row per
    /// `listen()` the agent observed. Listen events, not a snapshot
    /// of the sockets open now (a closed listener stays listed).
    Listeners {
        #[arg(long)]
        key: PathBuf,
        #[arg(long = "agent-id-file", default_value = DEFAULT_AGENT_ID_PATH)]
        agent_id_file: PathBuf,
        #[arg(long, default_value = DEFAULT_SOCKET)]
        socket: PathBuf,
    },

    /// The hostname the agent attributed to the newest retained
    /// flow to this destination IP (netflow log), and when that
    /// flow was recorded. Nothing printed when no retained flow to
    /// it carries a name.
    Resolve {
        /// Target IP address (v4 or v6, string form).
        #[arg(long)]
        ip: String,
        #[arg(long)]
        key: PathBuf,
        #[arg(long = "agent-id-file", default_value = DEFAULT_AGENT_ID_PATH)]
        agent_id_file: PathBuf,
        #[arg(long, default_value = DEFAULT_SOCKET)]
        socket: PathBuf,
    },

    /// The netflow rows of a flow_id, with their `ja3` / `ja4` /
    /// `sni` (null: not captured — the ClientHello capture is not
    /// wired yet). No row: the flow is not in the retained log.
    Fingerprint {
        /// 32-hex-char per-flow stable ID from a prior
        /// `net flows` row.
        #[arg(long = "flow-id")]
        flow_id: String,
        #[arg(long)]
        key: PathBuf,
        #[arg(long = "agent-id-file", default_value = DEFAULT_AGENT_ID_PATH)]
        agent_id_file: PathBuf,
        #[arg(long, default_value = DEFAULT_SOCKET)]
        socket: PathBuf,
    },
}

/// Tappa 9.0.b — `--min-severity` filter for `nn-admin detections`.
/// The wire string is the canonical lowercase form the agent parses.
#[derive(clap::ValueEnum, Clone, Debug)]
enum SeverityArg {
    Low,
    Medium,
    High,
    Critical,
}

impl SeverityArg {
    fn as_wire(&self) -> &'static str {
        match self {
            SeverityArg::Low => "low",
            SeverityArg::Medium => "medium",
            SeverityArg::High => "high",
            SeverityArg::Critical => "critical",
        }
    }
}

/// Tappa 9.0.b — `--status` triage-state filter for `detections`.
/// Tappa 9.0.c reshaped the lifecycle: the old `closed` rung was
/// replaced by the richer `investigating` / `resolved` /
/// `false-positive` triage states. All five are filterable.
#[derive(clap::ValueEnum, Clone, Debug)]
enum StatusArg {
    Open,
    Acknowledged,
    Investigating,
    Resolved,
    FalsePositive,
}

impl StatusArg {
    fn as_wire(&self) -> &'static str {
        match self {
            StatusArg::Open => "open",
            StatusArg::Acknowledged => "acknowledged",
            StatusArg::Investigating => "investigating",
            StatusArg::Resolved => "resolved",
            StatusArg::FalsePositive => "false-positive",
        }
    }
}

/// Tappa 9.0.c — settable triage TARGET for `detection-set-status`.
/// Distinct from [`StatusArg`]: `open` is the initial state a detection
/// is recorded in, NOT a target an operator transitions TO, so it is
/// deliberately absent here (the lifecycle only moves forward).
#[derive(clap::ValueEnum, Clone, Debug)]
enum StatusTargetArg {
    Acknowledged,
    Investigating,
    Resolved,
    FalsePositive,
}

impl StatusTargetArg {
    fn as_wire(&self) -> &'static str {
        match self {
            StatusTargetArg::Acknowledged => "acknowledged",
            StatusTargetArg::Investigating => "investigating",
            StatusTargetArg::Resolved => "resolved",
            StatusTargetArg::FalsePositive => "false-positive",
        }
    }
}

/// Tappa 9.0.b — `--sensor` filter for `detections`. Mirrors the
/// agent-side `Sensor` taxonomy.
#[derive(clap::ValueEnum, Clone, Debug)]
enum SensorArg {
    Exec,
    File,
    ModuleLoad,
    Network,
    AntiTamper,
    Canary,
}

impl SensorArg {
    fn as_wire(&self) -> &'static str {
        match self {
            SensorArg::Exec => "exec",
            SensorArg::File => "file",
            SensorArg::ModuleLoad => "module-load",
            SensorArg::Network => "network",
            SensorArg::AntiTamper => "anti-tamper",
            SensorArg::Canary => "canary",
        }
    }
}

#[cfg(feature = "debug-trigger")]
#[derive(Subcommand, Debug)]
enum DebugCmd {
    ForcePosture {
        #[arg(value_enum)]
        state: DebugStateArg,
        #[arg(long, default_value = DEFAULT_SOCKET)]
        socket: PathBuf,
    },
}

#[cfg(feature = "debug-trigger")]
#[derive(clap::ValueEnum, Clone, Debug)]
enum DebugStateArg {
    Observing,
    Alerted,
    Engaged,
    Combat,
}

#[cfg(feature = "debug-trigger")]
impl From<DebugStateArg> for common::wire::admin_protocol::DebugForcePosture {
    fn from(s: DebugStateArg) -> Self {
        use common::wire::admin_protocol::DebugForcePosture::*;
        match s {
            DebugStateArg::Observing => Observing,
            DebugStateArg::Alerted => Alerted,
            DebugStateArg::Engaged => Engaged,
            DebugStateArg::Combat => Combat,
        }
    }
}

/// Production force-posture target enum (Tappa 8 A10). Always
/// compiled (NOT feature-gated like [`DebugStateArg`]) because
/// production force-posture is a first-class operator command.
#[derive(clap::ValueEnum, Clone, Copy, Debug)]
enum ForcePostureTargetArg {
    Observing,
    Alerted,
    Engaged,
    Combat,
}

impl From<ForcePostureTargetArg> for common::posture_types::PostureKind {
    fn from(t: ForcePostureTargetArg) -> Self {
        use common::posture_types::PostureKind::*;
        match t {
            ForcePostureTargetArg::Observing => Observing,
            ForcePostureTargetArg::Alerted => Alerted,
            ForcePostureTargetArg::Engaged => Engaged,
            ForcePostureTargetArg::Combat => Combat,
        }
    }
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Init {
            priv_out,
            pub_append,
            force,
        } => exit_from_anyhow(handle_init(&priv_out, &pub_append, force)),
        Cmd::Unlock {
            key,
            agent_id_file,
            socket,
        } => match run_unlock(&socket, &key, &agent_id_file) {
            Ok(outcome) => exit_from_unlock(outcome),
            Err(e) => {
                eprintln!("unlock: {e:#}");
                ExitCode::from(5)
            }
        },
        Cmd::Detections {
            key,
            limit,
            since,
            until,
            min_severity,
            status,
            sensor,
            path,
            agent_id_file,
            socket,
        } => match northnarrow_agent::admin_cli::run_detections(
            &socket,
            &key,
            &agent_id_file,
            limit,
            since,
            until,
            min_severity.map(|s| s.as_wire().to_string()),
            status.map(|s| s.as_wire().to_string()),
            sensor.map(|s| s.as_wire().to_string()),
            path,
        ) {
            Ok(outcome) => exit_from_detections(outcome),
            Err(e) => {
                eprintln!("detections: {e:#}");
                ExitCode::from(5)
            }
        },
        Cmd::DetectionSetStatus {
            key,
            id,
            status,
            note,
            agent_id_file,
            socket,
        } => match northnarrow_agent::admin_cli::run_detection_set_status(
            &socket,
            &key,
            &agent_id_file,
            id,
            status.as_wire().to_string(),
            note,
        ) {
            Ok(outcome) => exit_from_detection_set_status(outcome),
            Err(e) => {
                eprintln!("detection-set-status: {e:#}");
                ExitCode::from(5)
            }
        },
        Cmd::HostCheck { json } => {
            let checks = northnarrow_agent::host_hardening::run();
            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&checks).unwrap_or_else(|_| "[]".to_string())
                );
            } else {
                print!(
                    "{}",
                    northnarrow_agent::host_hardening::render_table(&checks)
                );
            }
            if northnarrow_agent::host_hardening::warn_count(&checks) == 0 {
                ExitCode::SUCCESS
            } else {
                ExitCode::from(2)
            }
        }
        Cmd::Status {
            socket,
            json,
            key,
            agent_id_file,
        } => match read_status(&socket, key.as_deref(), &agent_id_file, "status") {
            Ok(out) => {
                print_status(&out, json);
                if !json {
                    let checks = northnarrow_agent::host_hardening::run();
                    let warns = northnarrow_agent::host_hardening::warn_count(&checks);
                    println!(
                        "host hardening : {} check(s), {warns} warning(s){}",
                        checks.len(),
                        if warns > 0 {
                            " — see `nn-admin host-check`"
                        } else {
                            ""
                        }
                    );
                }
                ExitCode::SUCCESS
            }
            Err(code) => code,
        },
        Cmd::VerifyKeys { path } => match run_verify_keys(&path) {
            Ok(out) => print_verify_keys(&out),
            Err(e) => {
                eprintln!("verify-keys: {e:#}");
                ExitCode::from(1)
            }
        },
        Cmd::Shutdown {
            key,
            cosign_key,
            agent_id_file,
            grace_secs,
            socket,
        } => match run_shutdown(&socket, &key, &cosign_key, &agent_id_file, grace_secs) {
            Ok(outcome) => exit_from_shutdown(outcome, grace_secs),
            Err(e) => {
                // Startup-class failures (file I/O on key/agent_id,
                // grace_secs over cap, transport failure) all land
                // here from `run_shutdown`'s anyhow Err. Map to
                // exit 5 (transport) since that's the "operator
                // must investigate" exit — `1` is reserved for
                // generic startup failure and we want shutdown
                // failures to be distinguishable from "couldn't
                // even launch nn-admin."
                eprintln!("shutdown: {e:#}");
                ExitCode::from(5)
            }
        },
        Cmd::ForcePosture {
            target,
            key,
            agent_id_file,
            socket,
        } => {
            let target_kind = target.into();
            match run_force_posture(&socket, &key, &agent_id_file, target_kind) {
                Ok(outcome) => exit_from_force_posture(outcome, target_kind),
                Err(e) => {
                    // Same exit-5 rationale as Shutdown: startup-
                    // class errors are operator-investigation,
                    // distinguishable from exit 1 (clap parse
                    // failure / didn't even launch).
                    eprintln!("force-posture: {e:#}");
                    ExitCode::from(5)
                }
            }
        }
        Cmd::RotateKeys {
            sub:
                RotateKeysCmd::Add {
                    new_pubkey,
                    new_roles,
                    key,
                    cosign_key,
                    agent_id_file,
                    socket,
                },
        } => {
            let roles = match parse_roles_csv(&new_roles) {
                Ok(r) => r,
                Err(e) => {
                    eprintln!("rotate-keys add: {e:#}");
                    return ExitCode::from(1);
                }
            };
            match run_rotate_keys_add(
                &socket,
                &key,
                &cosign_key,
                &agent_id_file,
                &new_pubkey,
                &roles,
            ) {
                Ok(out) => exit_from_rotate_keys(out, "rotate-keys add"),
                Err(e) => {
                    eprintln!("rotate-keys add: {e:#}");
                    ExitCode::from(5)
                }
            }
        }
        Cmd::RotateKeys {
            sub:
                RotateKeysCmd::Revoke {
                    fingerprint,
                    key,
                    cosign_key,
                    agent_id_file,
                    socket,
                },
        } => match run_rotate_keys_revoke(&socket, &key, &cosign_key, &agent_id_file, &fingerprint)
        {
            Ok(out) => exit_from_rotate_keys(out, "rotate-keys revoke"),
            Err(e) => {
                eprintln!("rotate-keys revoke: {e:#}");
                ExitCode::from(5)
            }
        },
        Cmd::Audit {
            sub: AuditCmd::Read { path, since, json },
        } => match run_audit_read(&path, since.as_deref(), json) {
            Ok(r) => {
                // Summary goes to stderr so `audit read --json |
                // jq` keeps a clean JSONL stream on stdout. Match
                // the `audit: ...` prefix convention from §5.3.
                eprintln!("audit: {} entries read from {}", r.rows, path.display());
                if r.skipped > 0 {
                    // External audit MAIN-014 (NN-AUD-256, lab PR 190):
                    // every row was printed; the lines that are not rows
                    // were named above. Exit 8: the file is not an intact
                    // chain.
                    if r.skipped > AUDIT_READ_SKIPS_LISTED {
                        eprintln!(
                            "audit: {} more skipped line(s) not listed",
                            r.skipped - AUDIT_READ_SKIPS_LISTED
                        );
                    }
                    eprintln!(
                        "audit: {} line(s) skipped: not audit rows — the log is damaged; run \
                         `nn-admin audit verify` and see docs/operator/EVIDENCE_CHAINS.md",
                        r.skipped
                    );
                    ExitCode::from(8)
                } else {
                    ExitCode::SUCCESS
                }
            }
            // Lab PR 188: `audit read | head` — the reader went.
            Err(e) if is_closed_pipe(&e) => ExitCode::from(EXIT_CLOSED_PIPE),
            Err(e) => {
                eprintln!("audit: {e:#}");
                ExitCode::from(1)
            }
        },
        Cmd::Audit {
            sub:
                AuditCmd::Verify {
                    from,
                    agent_pubkey,
                    agent_sig_key,
                    expect_head,
                    min_seq,
                },
        } => match load_audit_pubkey(agent_pubkey.as_deref(), &agent_sig_key) {
            Ok(pubkey) => match run_audit_verify_expecting(
                &from,
                &pubkey,
                &ExpectedHead {
                    entry_hash: expect_head,
                    min_seq,
                },
            ) {
                Ok(AuditVerifyOutcome::Success { entries }) => {
                    println!("audit: {entries} entries, hash chain intact, all sigs valid");
                    ExitCode::SUCCESS
                }
                Ok(AuditVerifyOutcome::ChainBroken(err)) => {
                    eprintln!("audit: chain broken — {err}");
                    // Exit code 8 per design §5.3: "audit
                    // verification failed (hash chain broken)".
                    ExitCode::from(8)
                }
                Ok(AuditVerifyOutcome::HeadNotReached(why)) => {
                    eprintln!("audit: chain cut — {why}");
                    ExitCode::from(8)
                }
                Err(e) => {
                    eprintln!("audit: {e:#}");
                    ExitCode::from(1)
                }
            },
            Err(e) => {
                eprintln!("audit: {e:#}");
                ExitCode::from(1)
            }
        },
        Cmd::Chain {
            sub:
                ChainCmd::Verify {
                    log,
                    state_dir,
                    audit_log,
                    heads,
                    agent_pubkey,
                    agent_sig_key,
                },
        } => match load_audit_pubkey(agent_pubkey.as_deref(), &agent_sig_key) {
            Ok(pubkey) => {
                let only: Vec<String> = if log.contains(&ChainName::All) {
                    Vec::new()
                } else {
                    log.iter()
                        .filter_map(|l| l.key())
                        .map(str::to_string)
                        .collect()
                };
                let det = state_dir.join("detections");
                let paths = northnarrow_agent::chain_anchor::ChainPaths {
                    audit: audit_log,
                    canary_registry: state_dir.join("canaries.jsonl"),
                    canary_access: state_dir.join("canary_access.jsonl"),
                    detections: det.join("detections.jsonl"),
                    status_events: det.join("status_events.jsonl"),
                    netflow: state_dir.join("netflow.jsonl"),
                    fim_drift: state_dir.join("fim_drift.jsonl"),
                };
                let heads = heads.unwrap_or_else(|| {
                    paths
                        .audit
                        .parent()
                        .unwrap_or_else(|| std::path::Path::new("."))
                        .join(northnarrow_agent::chain_anchor::HEADS_FILE_NAME)
                });
                let lines = run_chain_verify(&paths, &heads, &only, &pubkey);
                let mut broken = 0;
                for l in &lines {
                    if l.ok {
                        println!("OK      {:<16} {}: {}", l.chain, l.file, l.detail);
                    } else {
                        broken += 1;
                        println!("BROKEN  {:<16} {}: {}", l.chain, l.file, l.detail);
                    }
                }
                if broken > 0 {
                    eprintln!(
                        "chain: {broken} problem(s) — evidence missing or altered; see the \
                         operator runbook (docs/operator/EVIDENCE_CHAINS.md)"
                    );
                    ExitCode::from(8)
                } else {
                    ExitCode::SUCCESS
                }
            }
            Err(e) => {
                eprintln!("chain: {e:#}");
                ExitCode::from(1)
            }
        },
        Cmd::Fim {
            sub:
                FimCmd::Baseline {
                    key,
                    agent_id_file,
                    socket,
                },
        } => match run_fim_baseline(&socket, &key, &agent_id_file) {
            Ok(outcome) => exit_from_fim_baseline(outcome),
            Err(e) => {
                eprintln!("fim baseline: {e:#}");
                ExitCode::from(5)
            }
        },
        Cmd::Fim {
            sub:
                FimCmd::Report {
                    key,
                    since,
                    agent_id_file,
                    socket,
                },
        } => match run_fim_report(&socket, &key, &agent_id_file, since) {
            Ok(outcome) => exit_from_fim_report(outcome),
            Err(e) => {
                eprintln!("fim report: {e:#}");
                ExitCode::from(5)
            }
        },
        Cmd::Fim {
            sub:
                FimCmd::Status {
                    key,
                    agent_id_file,
                    socket,
                },
        } => match run_fim_status(&socket, &key, &agent_id_file) {
            Ok(outcome) => exit_from_fim_status(outcome),
            Err(e) => {
                eprintln!("fim status: {e:#}");
                ExitCode::from(5)
            }
        },
        Cmd::Canary {
            sub:
                CanaryCmd::Deploy {
                    name,
                    kind,
                    key,
                    agent_id_file,
                    socket,
                },
        } => {
            let spec: CanaryDeploySpec = kind.into();
            match run_canary_deploy(&socket, &key, &agent_id_file, name, spec) {
                Ok(outcome) => exit_from_canary_deploy(outcome),
                Err(e) => {
                    eprintln!("canary deploy: {e:#}");
                    ExitCode::from(5)
                }
            }
        }
        Cmd::Canary {
            sub:
                CanaryCmd::List {
                    key,
                    agent_id_file,
                    socket,
                },
        } => match run_canary_list(&socket, &key, &agent_id_file) {
            Ok(outcome) => exit_from_canary_list(outcome),
            Err(e) => {
                eprintln!("canary list: {e:#}");
                ExitCode::from(5)
            }
        },
        Cmd::Canary {
            sub:
                CanaryCmd::Burn {
                    canary_id,
                    key,
                    agent_id_file,
                    socket,
                },
        } => match run_canary_burn(&socket, &key, &agent_id_file, canary_id) {
            Ok(outcome) => exit_from_canary_burn(outcome),
            Err(e) => {
                eprintln!("canary burn: {e:#}");
                ExitCode::from(5)
            }
        },
        Cmd::Canary {
            sub:
                CanaryCmd::Refresh {
                    canary_id,
                    key,
                    agent_id_file,
                    socket,
                },
        } => match run_canary_refresh(&socket, &key, &agent_id_file, canary_id) {
            Ok(outcome) => exit_from_canary_refresh(outcome),
            Err(e) => {
                eprintln!("canary refresh: {e:#}");
                ExitCode::from(5)
            }
        },

        // ── Tappa 10 N7 — net subcommands ─────────────────────────
        Cmd::Net {
            sub:
                NetCmd::Status {
                    socket,
                    json,
                    key,
                    agent_id_file,
                },
        } => match read_status(&socket, key.as_deref(), &agent_id_file, "net status") {
            Ok(out) => {
                print_net_status(&out, json);
                ExitCode::SUCCESS
            }
            Err(code) => code,
        },
        Cmd::Net {
            sub:
                NetCmd::Flows {
                    key,
                    since_unix,
                    agent_id_file,
                    socket,
                },
        } => match northnarrow_agent::admin_cli::run_net_flows(
            &socket,
            &key,
            &agent_id_file,
            since_unix,
        ) {
            Ok(outcome) => exit_from_net_jsonl(outcome, "net flows"),
            Err(e) => {
                eprintln!("net flows: {e:#}");
                ExitCode::from(5)
            }
        },
        Cmd::Net {
            sub:
                NetCmd::Listeners {
                    key,
                    agent_id_file,
                    socket,
                },
        } => match northnarrow_agent::admin_cli::run_net_listeners(&socket, &key, &agent_id_file) {
            Ok(outcome) => exit_from_net_jsonl(outcome, "net listeners"),
            Err(e) => {
                eprintln!("net listeners: {e:#}");
                ExitCode::from(5)
            }
        },
        Cmd::Net {
            sub:
                NetCmd::Resolve {
                    ip,
                    key,
                    agent_id_file,
                    socket,
                },
        } => match northnarrow_agent::admin_cli::run_net_resolve(&socket, &key, &agent_id_file, ip)
        {
            Ok(outcome) => exit_from_net_resolve(outcome),
            Err(e) => {
                eprintln!("net resolve: {e:#}");
                ExitCode::from(5)
            }
        },
        Cmd::Net {
            sub:
                NetCmd::Fingerprint {
                    flow_id,
                    key,
                    agent_id_file,
                    socket,
                },
        } => match northnarrow_agent::admin_cli::run_net_fingerprint(
            &socket,
            &key,
            &agent_id_file,
            flow_id,
        ) {
            Ok(outcome) => exit_from_net_jsonl(outcome, "net fingerprint"),
            Err(e) => {
                eprintln!("net fingerprint: {e:#}");
                ExitCode::from(5)
            }
        },

        Cmd::Response { sub } => run_response_cmd(sub),
        Cmd::Config {
            sub: ConfigCmd::Overlay { sub },
        } => run_overlay_cmd(sub),
        Cmd::TrustedInstallerGrant {
            key,
            window_secs,
            agent_id_file,
            socket,
        } => {
            // Clamp client-side to the agent's ceiling (the agent also
            // clamps; this gives the operator a clear message instead
            // of a silent server-side reduction).
            let max =
                northnarrow_agent::anti_tamper::trusted_installer::MAX_TRUSTED_INSTALLER_WINDOW_SECS;
            let clamped = window_secs.clamp(1, max);
            if clamped != window_secs {
                eprintln!(
                    "trusted-installer-grant: --window-secs {window_secs} clamped to {clamped} \
                     (agent ceiling)"
                );
            }
            match run_trusted_installer_grant(&socket, &key, &agent_id_file, clamped) {
                Ok(outcome) => exit_from_trusted_installer_grant(outcome, clamped),
                Err(e) => {
                    eprintln!("trusted-installer-grant: {e:#}");
                    ExitCode::from(5)
                }
            }
        }

        #[cfg(feature = "debug-trigger")]
        Cmd::Debug {
            sub: DebugCmd::ForcePosture { state, socket },
        } => match northnarrow_agent::admin_cli::run_debug_force_posture(&socket, state.into()) {
            Ok(()) => {
                println!("debug: posture forced.");
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("debug: {e:#}");
                ExitCode::from(5)
            }
        },
    }
}

fn handle_init(
    priv_out: &std::path::Path,
    pub_append: &std::path::Path,
    force: bool,
) -> anyhow::Result<()> {
    let out = run_init(priv_out, pub_append, force)?;
    println!(
        "init: keypair generated.\n\
         private key : {}\n\
         appended to : {}\n\
         fingerprint : {}\n\
         \n\
         Record the fingerprint above — it is the short identifier the\n\
         agent prints in logs whenever this key is used.",
        out.priv_path.display(),
        out.pub_path.display(),
        out.fingerprint
    );
    Ok(())
}

fn exit_from_anyhow(r: anyhow::Result<()>) -> ExitCode {
    match r {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("{e:#}");
            ExitCode::from(1)
        }
    }
}

fn exit_from_force_posture(
    outcome: ForcePostureOutcome,
    target: common::posture_types::PostureKind,
) -> ExitCode {
    let tty = std::io::stdout().is_terminal();
    match outcome {
        ForcePostureOutcome::Success => {
            println!(
                "{}",
                colorize(
                    &format!("force-posture: agent posture set to {target:?}"),
                    "32",
                    tty
                )
            );
            ExitCode::SUCCESS
        }
        ForcePostureOutcome::InvalidSignature => {
            eprintln!(
                "{}",
                colorize(
                    "force-posture: invalid signature (key not in admin.pub, or wrong bytes)",
                    "31",
                    tty
                )
            );
            ExitCode::from(2)
        }
        ForcePostureOutcome::NoPendingChallenge => {
            eprintln!(
                "{}",
                colorize(
                    "force-posture: no pending challenge (server state out of sync — retry)",
                    "31",
                    tty
                )
            );
            ExitCode::from(3)
        }
        ForcePostureOutcome::RateLimited { retry_after_secs } => {
            eprintln!(
                "{}",
                colorize(
                    &format!("force-posture: rate limited; retry after {retry_after_secs}s"),
                    "33",
                    tty
                )
            );
            ExitCode::from(4)
        }
        ForcePostureOutcome::QuorumNotMet { required, provided } => {
            // For force-posture, required is always 1 (1-of-N
            // quorum). Hitting QuorumNotMet here means the single
            // sig didn't verify under any pubkey — same operator
            // hint as InvalidSignature, but distinct exit code so
            // automation can tell them apart.
            eprintln!(
                "{}",
                colorize(
                    &format!(
                        "force-posture: quorum not met ({provided}/{required}). \
                         The submitted key doesn't match any line in admin.pub."
                    ),
                    "31",
                    tty
                )
            );
            ExitCode::from(6)
        }
        ForcePostureOutcome::RoleDenied => {
            eprintln!(
                "{}",
                colorize(
                    "force-posture: role denied (key verified but lacks the \
                     `force-posture` role in admin.pub, or the target leaves \
                     COMBAT and the key lacks `unlock` — add the role to the \
                     line's role list, e.g. `<hex>  force-posture,unlock`, or \
                     use `nn-admin unlock`)",
                    "31",
                    tty
                )
            );
            ExitCode::from(7)
        }
        ForcePostureOutcome::TimestampSkew {
            server_ts,
            max_skew_secs,
        } => {
            eprintln!(
                "{}",
                colorize(
                    &format!(
                        "force-posture: clock skew (server_ts={server_ts}, max ±{max_skew_secs}s). \
                         NTP-sync this host and the agent host, then retry."
                    ),
                    "31",
                    tty
                )
            );
            ExitCode::from(5)
        }
        ForcePostureOutcome::AgentIdMismatch => {
            eprintln!(
                "{}",
                colorize(
                    "force-posture: agent_id mismatch (the --agent-id-file \
                     content doesn't match the agent's bootstrapped UUID).",
                    "31",
                    tty
                )
            );
            ExitCode::from(5)
        }
        ForcePostureOutcome::UnknownOperation => {
            eprintln!(
                "{}",
                colorize(
                    "force-posture: unknown operation (protocol misuse — \
                     likely a version mismatch between nn-admin and the agent)",
                    "31",
                    tty
                )
            );
            ExitCode::from(5)
        }
        ForcePostureOutcome::ActionFailed => {
            // Lab PR 217 (NN-AUD-243 residue).
            eprintln!(
                "{}",
                colorize(
                    "force-posture: verified, but leaving COMBAT failed — the isolation was NOT \
                     released (read back) and the posture stays COMBAT; see `nn-admin status` \
                     and the agent journal, then retry or use `nn-admin unlock`",
                    "31",
                    tty
                )
            );
            ExitCode::from(9)
        }
        ForcePostureOutcome::ProtocolVersionUnsupported { server_version } => {
            eprintln!(
                "{}",
                colorize(
                    &format!(
                        "force-posture: protocol version unsupported (server \
                         speaks up to v{server_version}; nn-admin is newer)"
                    ),
                    "31",
                    tty
                )
            );
            ExitCode::from(5)
        }
    }
}

fn exit_from_shutdown(outcome: ShutdownOutcome, grace_secs: u32) -> ExitCode {
    let tty = std::io::stdout().is_terminal();
    match outcome {
        ShutdownOutcome::Success => {
            // Two-line UX per design §10.5: collect-confirmation
            // then ack-confirmation. The fingerprint roll-up
            // ("8a1c2f3e+7b5d4ce0") shown in the design is the
            // agent's audit-log job (A11+) — we don't have the
            // matched fingerprints client-side here.
            println!(
                "{}",
                colorize("shutdown: 2 signatures collected; quorum met", "32", tty)
            );
            println!(
                "{}",
                colorize(
                    &format!(
                        "shutdown: agent acknowledged (grace {grace_secs}s); \
                         watchdog will stand down on next pidfd POLLIN"
                    ),
                    "32",
                    tty
                )
            );
            ExitCode::SUCCESS
        }
        ShutdownOutcome::InvalidSignature => {
            eprintln!(
                "{}",
                colorize(
                    "shutdown: invalid signature (key not in admin.pub, or wrong bytes)",
                    "31",
                    tty
                )
            );
            ExitCode::from(2)
        }
        ShutdownOutcome::NoPendingChallenge => {
            eprintln!(
                "{}",
                colorize(
                    "shutdown: no pending challenge (server state out of sync — retry)",
                    "31",
                    tty
                )
            );
            ExitCode::from(3)
        }
        ShutdownOutcome::RateLimited { retry_after_secs } => {
            eprintln!(
                "{}",
                colorize(
                    &format!("shutdown: rate limited; retry after {retry_after_secs}s"),
                    "33",
                    tty
                )
            );
            ExitCode::from(4)
        }
        ShutdownOutcome::QuorumNotMet { required, provided } => {
            eprintln!(
                "{}",
                colorize(
                    &format!(
                        "shutdown: quorum not met ({provided}/{required} distinct \
                         valid signatures). Co-signer key may be wrong, the same \
                         key may have been passed to --key and --cosign-key, or \
                         the second sig may not verify."
                    ),
                    "31",
                    tty
                )
            );
            ExitCode::from(6)
        }
        ShutdownOutcome::RoleDenied => {
            eprintln!(
                "{}",
                colorize(
                    "shutdown: role denied (one of the keys verified but lacks \
                     the `shutdown` role in admin.pub — check the line's role list)",
                    "31",
                    tty
                )
            );
            ExitCode::from(7)
        }
        ShutdownOutcome::TimestampSkew {
            server_ts,
            max_skew_secs,
        } => {
            eprintln!(
                "{}",
                colorize(
                    &format!(
                        "shutdown: clock skew (server_ts={server_ts}, max ±{max_skew_secs}s). \
                         NTP-sync this host and the agent host, then retry."
                    ),
                    "31",
                    tty
                )
            );
            ExitCode::from(5)
        }
        ShutdownOutcome::AgentIdMismatch => {
            eprintln!(
                "{}",
                colorize(
                    "shutdown: agent_id mismatch (the --agent-id-file content \
                     doesn't match the agent's bootstrapped UUID — check the \
                     path, or copy the file from the agent host).",
                    "31",
                    tty
                )
            );
            ExitCode::from(5)
        }
        ShutdownOutcome::UnknownOperation => {
            eprintln!(
                "{}",
                colorize(
                    "shutdown: unknown operation (protocol misuse — likely a \
                     version mismatch between nn-admin and the agent)",
                    "31",
                    tty
                )
            );
            ExitCode::from(5)
        }
        ShutdownOutcome::ProtocolVersionUnsupported { server_version } => {
            eprintln!(
                "{}",
                colorize(
                    &format!(
                        "shutdown: protocol version unsupported (server speaks \
                         up to v{server_version}; nn-admin is newer — downgrade \
                         nn-admin or upgrade the agent)"
                    ),
                    "31",
                    tty
                )
            );
            ExitCode::from(5)
        }
    }
}

/// `IPv4 isolated, IPv6 clear` — the agent's per-family state (lab PR 217).
fn families_line(v4: bool, v6: bool) -> String {
    let one = |isolated: bool| if isolated { "isolated" } else { "clear" };
    format!("IPv4 {}, IPv6 {}", one(v4), one(v6))
}

fn exit_from_unlock(outcome: UnlockOutcome) -> ExitCode {
    let tty = std::io::stdout().is_terminal();
    match outcome {
        UnlockOutcome::Success {
            message,
            isolation_v4,
            isolation_v6,
        } => {
            println!("{}", colorize("unlock: success", "32", tty));
            println!("  {message}");
            println!(
                "  network isolation: {}",
                families_line(isolation_v4, isolation_v6)
            );
            ExitCode::SUCCESS
        }
        UnlockOutcome::ReleaseFailed {
            message,
            isolation_v4,
            isolation_v6,
        } => {
            // Lab PR 217 (NN-AUD-243 residue): verified, not carried out.
            eprintln!(
                "{}",
                colorize(
                    "unlock: verified, but the isolation was NOT released — the posture stays \
                     COMBAT",
                    "31",
                    tty
                )
            );
            eprintln!("  {message}");
            eprintln!(
                "  network isolation: {}",
                families_line(isolation_v4, isolation_v6)
            );
            eprintln!(
                "  retry the unlock; if the teardown keeps failing, remove the \
                 NORTHNARROW_COMBAT chain by hand (docs/operator/COMBAT_RECOVERY.md) and unlock \
                 again"
            );
            ExitCode::from(9)
        }
        UnlockOutcome::InvalidSignature => {
            eprintln!("{}", colorize("unlock: invalid signature", "31", tty));
            ExitCode::from(2)
        }
        UnlockOutcome::NoPendingChallenge => {
            eprintln!(
                "{}",
                colorize(
                    "unlock: no pending challenge (server state out of sync?)",
                    "31",
                    tty
                )
            );
            ExitCode::from(3)
        }
        UnlockOutcome::RateLimited { retry_after_secs } => {
            eprintln!(
                "{}",
                colorize(
                    &format!("unlock: rate limited; retry after {retry_after_secs}s"),
                    "33",
                    tty
                )
            );
            ExitCode::from(4)
        }
        UnlockOutcome::RoleDenied => {
            eprintln!(
                "{}",
                colorize(
                    "unlock: role denied — the key's admin.pub line does not carry `unlock`",
                    "31",
                    tty
                )
            );
            ExitCode::from(7)
        }
        UnlockOutcome::Refused(result) => {
            eprintln!(
                "{}",
                colorize(
                    &format!(
                        "unlock: refused ({result:?}) — check the host clock and that \
                         --agent-id-file is this agent's"
                    ),
                    "31",
                    tty
                )
            );
            ExitCode::from(5)
        }
    }
}

/// External audit ASK-009 (lab PR 213): the unsigned `status`, or with
/// `key` the signed telemetry verb. `Err` is the exit code, the reason
/// already printed: 5 transport, 7 a key with neither read role, the
/// usual codes of a refused signed request otherwise.
fn read_status(
    socket: &std::path::Path,
    key: Option<&std::path::Path>,
    agent_id_file: &std::path::Path,
    op: &str,
) -> Result<StatusOutcome, ExitCode> {
    use common::wire::admin_protocol::AdminResult;
    let Some(key) = key else {
        return run_status(socket).map_err(|e| {
            eprintln!("{op}: {e:#}");
            ExitCode::from(5)
        });
    };
    match northnarrow_agent::admin_cli::run_telemetry_status(socket, key, agent_id_file) {
        Ok(Ok(out)) => Ok(out),
        Ok(Err(AdminResult::RoleDenied)) => {
            eprintln!(
                "{op}: role denied (the key holds neither `audit-read` nor `telemetry-read`)"
            );
            Err(ExitCode::from(7))
        }
        Ok(Err(refused)) => Err(exit_from_admin_result(op, refused)),
        Err(e) => {
            eprintln!("{op}: {e:#}");
            Err(ExitCode::from(5))
        }
    }
}

/// External audit ASK-009 (lab PR 213): an unsigned reply whose telemetry
/// the agent withheld (an agent older than lab PR 213 still fills it in).
fn telemetry_withheld(out: &StatusOutcome) -> bool {
    !out.telemetry_signed
        && out.ringbuf_drops_total.is_none()
        && out.ringbuf_rejected_total.is_none()
        && out.netflow_rows_skipped_total.is_none()
        && out.netflow_pending_evicted_total.is_none()
        && out.net_inactive_rules.is_none()
        && out.flow_sock_pending.is_none()
        && out.flow_sock_capacity.is_none()
        && out.flow_sock_forgotten_min.is_none()
        && out.detect_only.is_none()
        && out.detect_only_source.is_none()
        && out.combat_evidence_unrecorded.is_none()
        && out.net_dot_rows_total.is_none()
        && out.net_quic_rows_total.is_none()
        && out.deny_fail_open_total.is_none()
}

/// The line that replaces the telemetry in an unsigned reply.
fn withheld_line(label: &str, what: &str, cmd: &str) -> String {
    format!(
        "{label}: withheld from the unsigned status ({what}) — `nn-admin {cmd} --key <key>` \
         with `audit-read` or `telemetry-read` reads them, signed"
    )
}

/// External audit NET-019 / NET-012 / NET-009: `nn-admin net status`.
fn print_net_status(out: &StatusOutcome, json: bool) {
    let net_ring = |name: &str| {
        matches!(
            name,
            "tcp_connect" | "tcp_close" | "udp" | "listen" | "listen_rate" | "dns" | "dns_rate"
        )
    };
    let drops: Vec<&(String, u64)> = out
        .ringbuf_drops
        .iter()
        .filter(|(n, _)| net_ring(n))
        .collect();
    let opt = |v: Option<u64>| v.map_or_else(|| "null".to_string(), |v| v.to_string());
    if json {
        let drops: Vec<String> = drops
            .iter()
            .map(|(n, c)| format!("\"{}\":{c}", n.replace('"', "")))
            .collect();
        println!(
            "{{\"netflow_rows_skipped_total\":{},\"netflow_pending_evicted_total\":{},\"ringbuf_drops\":{{{}}},\"net_inactive_rules\":{},\"flow_sock_pending\":{},\"flow_sock_capacity\":{},\"flow_sock_forgotten_min\":{},\"net_dot_rows_total\":{},\"net_dot_rows_resolver\":{},\"net_quic_rows_total\":{},\"telemetry_signed\":{}}}",
            opt(out.netflow_rows_skipped_total),
            opt(out.netflow_pending_evicted_total),
            drops.join(","),
            // Lab PR 207: every control character escaped too (an entry can
            // name a configuration file).
            serde_json::to_string(&out.net_inactive_rules).unwrap_or_else(|_| "null".to_string()),
            opt(out.flow_sock_pending),
            opt(out.flow_sock_capacity),
            opt(out.flow_sock_forgotten_min),
            opt(out.net_dot_rows_total),
            opt(out.net_dot_rows_resolver),
            opt(out.net_quic_rows_total),
            out.telemetry_signed,
        );
        return;
    }
    if telemetry_withheld(out) {
        println!(
            "{}",
            withheld_line(
                "network telemetry                     ",
                "netflow pacing and evictions, FLOW_SOCK_MAP, network ring drops, inactive \
                 network rules, DNS over TLS and QUIC rows",
                "net status"
            )
        );
        return;
    }
    match out.netflow_rows_skipped_total {
        Some(n) => println!(
            "netflow rows held back from the rules : {n} (written with decision_engine_skipped; \
             per-uid pacing)"
        ),
        None => println!("netflow rows held back from the rules : (agent predates the counter)"),
    }
    match out.netflow_pending_evicted_total {
        Some(n) => println!("pending connects evicted at capacity  : {n}"),
        None => println!("pending connects evicted at capacity  : (agent predates the counter)"),
    }
    println!("{}", flow_sock_line(out));
    if drops.is_empty() {
        println!("network ring drops                    : none");
    } else {
        for (n, c) in drops {
            println!("network ring drops                    : {n} {c}");
        }
    }
    match &out.net_inactive_rules {
        Some(rules) if rules.is_empty() => {
            println!("inactive network rules                : none")
        }
        Some(rules) => {
            for r in rules {
                println!("inactive network rule                 : {r}");
            }
        }
        None => println!("inactive network rules                : (agent predates the field)"),
    }
    for line in encrypted_flow_lines(out) {
        println!("{line}");
    }
}

/// External audit NET-017 (lab PR 207): the traffic whose names and
/// handshakes no rule reads, for `net status`.
fn encrypted_flow_lines(out: &StatusOutcome) -> Vec<String> {
    let label = |l: &str| format!("{l:<38}: ");
    let mut lines = Vec::new();
    match (out.net_dot_rows_total, out.net_dot_rows_resolver) {
        (Some(0), _) => lines.push(format!(
            "{}0 since boot",
            label("DNS over TLS rows (TCP/853)")
        )),
        (Some(total), resolver) => {
            let resolver = resolver.unwrap_or(0).min(total);
            lines.push(format!(
                "{}{total} since boot — {resolver} by the local resolver (its upstream), {} by \
                 other processes (they resolve names past the resolver); no DNS rule reads \
                 the names they carry",
                label("DNS over TLS rows (TCP/853)"),
                total - resolver
            ));
        }
        (None, _) => lines.push(format!(
            "{}(agent predates the counter)",
            label("DNS over TLS rows (TCP/853)")
        )),
    }
    match out.net_quic_rows_total {
        Some(0) => lines.push(format!("{}0 since boot", label("QUIC rows (UDP/443)"))),
        Some(n) => lines.push(format!(
            "{}{n} since boot — HTTP/3: no TLS handshake (JA3, JA4, SNI) can be read from \
             them; addresses, ports and bytes are recorded",
            label("QUIC rows (UDP/443)")
        )),
        None => lines.push(format!(
            "{}(agent predates the counter)",
            label("QUIC rows (UDP/443)")
        )),
    }
    lines.push(format!(
        "{}not counted — HTTPS to a resolver on TCP/443 looks like any web traffic",
        label("DNS over HTTPS")
    ));
    lines
}

/// Lab PR 164: the kernel's connect→close socket map, for `net status`.
fn flow_sock_line(out: &StatusOutcome) -> String {
    match (out.flow_sock_pending, out.flow_sock_capacity) {
        (Some(p), Some(c)) if c > 0 => {
            let mut line = format!(
                "kernel FLOW_SOCK_MAP                  : {p} sockets without their close yet, \
                 of {c} ({} %)",
                p.min(c) * 100 / c
            );
            match out.flow_sock_forgotten_min {
                Some(f) if f > 0 => line.push_str(&format!(
                    "; at least {f} forgotten (their closes are not recorded)"
                )),
                _ => {}
            }
            line
        }
        _ => "kernel FLOW_SOCK_MAP                  : (unknown: agent predates the counters)"
            .to_string(),
    }
}

/// External audit CMB-018 (lab PR 193): whether the agent enforces, and
/// what set detect-only. The signed `agent_boot` entry records the same.
fn response_mode_line(out: &StatusOutcome, tty: bool) -> String {
    match (out.detect_only, &out.detect_only_source) {
        (Some(true), source) => format!(
            "response mode     : {} ({}) — no response action and no COMBAT isolation touch the system",
            colorize("DETECT-ONLY", "33", tty),
            source.as_deref().unwrap_or("source not reported")
        ),
        (Some(false), _) => format!("response mode     : {}", colorize("enforcing", "32", tty)),
        (None, _) => "response mode     : (not reported: the agent has no response executor)".to_string(),
    }
}

/// External audit CMB-027 (lab PR 193): the COMBAT stage transitions the
/// signed audit log did not get when they happened.
fn combat_evidence_line(out: &StatusOutcome, tty: bool) -> String {
    match (
        out.combat_evidence_unrecorded,
        out.combat_evidence_pending,
        out.combat_evidence_dropped,
    ) {
        (None, _, _) => {
            "combat evidence   : (not reported: the agent has no COMBAT ladder)".to_string()
        }
        (Some(0), _, _) => format!(
            "combat evidence   : {} — every COMBAT stage transition is in the signed audit log",
            colorize("complete", "32", tty)
        ),
        (Some(n), pending, dropped) => format!(
            "combat evidence   : {} stage transition(s) not written to the signed audit log when they \
             happened — {} queued for a late write, {} dropped (never written); see the agent ERRORs",
            colorize(&n.to_string(), "31", tty),
            pending.unwrap_or(0),
            dropped.unwrap_or(0)
        ),
    }
}

/// Lab PR 215: operations the anti-tamper deny hooks let through
/// undecided (a kernel read a hook needed failed), for `status`.
fn deny_fail_open_line(out: &StatusOutcome, tty: bool) -> String {
    match out.deny_fail_open_total {
        None => "deny fail-open    : (not counted: the agent reads no DENY_FAIL_OPEN counters)"
            .to_string(),
        Some(0) => format!("deny fail-open    : {}", colorize("0", "32", tty)),
        Some(t) => {
            let per: Vec<String> = out
                .deny_fail_open
                .iter()
                .map(|(n, c)| format!("{n} {c}"))
                .collect();
            format!(
                "deny fail-open    : {} ({}) — operations a deny hook let through undecided \
                 since boot (a kernel read it needed failed); see the agent WARNs and the signed \
                 deny_fail_open entries",
                colorize(&t.to_string(), "31", tty),
                per.join(", ")
            )
        }
    }
}

fn print_status(out: &StatusOutcome, json: bool) {
    if json {
        // Hand-rolled JSON to avoid a serde_json dep at the binary
        // surface; the fields are stable and trivially escapable.
        let drops: Vec<String> = out
            .ringbuf_drops
            .iter()
            .map(|(n, c)| format!("\"{}\":{c}", n.replace('"', "")))
            .collect();
        let rejected: Vec<String> = out
            .ringbuf_rejected
            .iter()
            .map(|(n, c)| format!("\"{}\":{c}", n.replace('"', "")))
            .collect();
        let fail_open: Vec<String> = out
            .deny_fail_open
            .iter()
            .map(|(n, c)| format!("\"{}\":{c}", n.replace('"', "")))
            .collect();
        let opt = |v: Option<u64>| v.map_or_else(|| "null".to_string(), |n| n.to_string());
        println!(
            "{{\"posture\":\"{:?}\",\"network_isolation_engaged\":{},\"network_isolation_v4\":{},\"network_isolation_v6\":{},\"last_admin_action_secs_ago\":{},\"ringbuf_drops_total\":{},\"ringbuf_drops\":{{{}}},\"combat_stage\":{},\"combat_locked\":{},\"ringbuf_rejected_total\":{},\"ringbuf_rejected\":{{{}}},\"detect_only\":{},\"detect_only_source\":{},\"combat_evidence_unrecorded\":{},\"combat_evidence_pending\":{},\"combat_evidence_dropped\":{},\"deny_fail_open_total\":{},\"deny_fail_open\":{{{}}},\"telemetry_signed\":{}}}",
            out.posture,
            out.network_isolation_engaged,
            // Lab PR 217 (capability C18).
            out.network_isolation_v4
                .map_or_else(|| "null".to_string(), |b| b.to_string()),
            out.network_isolation_v6
                .map_or_else(|| "null".to_string(), |b| b.to_string()),
            match out.last_admin_action_secs_ago {
                Some(s) => s.to_string(),
                None => "null".to_string(),
            },
            match out.ringbuf_drops_total {
                Some(t) => t.to_string(),
                None => "null".to_string(),
            },
            drops.join(","),
            match &out.combat_stage {
                Some(st) => format!("\"{}\"", st.replace('"', "")),
                None => "null".to_string(),
            },
            match out.combat_locked {
                Some(l) => l.to_string(),
                None => "null".to_string(),
            },
            match out.ringbuf_rejected_total {
                Some(t) => t.to_string(),
                None => "null".to_string(),
            },
            rejected.join(","),
            // External audit CMB-018 / CMB-027 (lab PR 193).
            out.detect_only
                .map_or_else(|| "null".to_string(), |d| d.to_string()),
            serde_json::to_string(&out.detect_only_source).unwrap_or_else(|_| "null".to_string()),
            opt(out.combat_evidence_unrecorded),
            opt(out.combat_evidence_pending),
            opt(out.combat_evidence_dropped),
            // Lab PR 215.
            opt(out.deny_fail_open_total),
            fail_open.join(","),
            out.telemetry_signed,
        );
        return;
    }
    let tty = std::io::stdout().is_terminal();
    println!("posture           : {:?}", out.posture);
    let iso = if out.network_isolation_engaged {
        colorize("ENGAGED", "31", tty)
    } else {
        colorize("clear", "32", tty)
    };
    // Lab PR 217 (capability C18): per IP family, as read back — an IPv6
    // hole no longer hides behind "ENGAGED".
    match (out.network_isolation_v4, out.network_isolation_v6) {
        (Some(v4), Some(v6)) => {
            println!("network isolation : {iso} ({})", families_line(v4, v6))
        }
        _ => println!("network isolation : {iso}"),
    }
    // External audit CMB-016: where the COMBAT ladder stands.
    match (&out.combat_stage, out.combat_locked) {
        (Some(st), locked) => println!(
            "combat stage      : {}{}",
            colorize(st, "31", tty),
            if locked == Some(true) {
                " (locked: `nn-admin unlock` to release)"
            } else {
                ""
            }
        ),
        (None, Some(true)) => println!("combat stage      : (none) — COMBAT locked"),
        (None, Some(false)) => println!("combat stage      : (no episode)"),
        (None, None) => println!("combat stage      : (agent predates the field)"),
    }
    let withheld = telemetry_withheld(out);
    if !withheld {
        println!("{}", response_mode_line(out, tty));
        println!("{}", combat_evidence_line(out, tty));
    }
    match out.last_admin_action_secs_ago {
        Some(s) => println!("last admin action : {s}s ago"),
        None => println!("last admin action : (none since agent start)"),
    }
    if withheld {
        // External audit ASK-009 (lab PR 213).
        println!(
            "{}",
            withheld_line(
                "telemetry         ",
                "response mode, COMBAT evidence, ring drops and rejected records, deny \
                 fail-opens",
                "status"
            )
        );
        return;
    }
    match out.ringbuf_drops_total {
        None => println!("ringbuf drops     : (agent predates the counter)"),
        Some(0) => println!("ringbuf drops     : {}", colorize("0", "32", tty)),
        Some(t) => {
            let per: Vec<String> = out
                .ringbuf_drops
                .iter()
                .map(|(n, c)| format!("{n} {c}"))
                .collect();
            println!(
                "ringbuf drops     : {} ({}) — events lost since boot, see the agent WARNs",
                colorize(&t.to_string(), "31", tty),
                per.join(", ")
            );
        }
    }
    // External audit SNS-008: records a pump could not decode.
    match out.ringbuf_rejected_total {
        None => println!("ringbuf rejected  : (agent predates the counter)"),
        Some(0) => println!("ringbuf rejected  : {}", colorize("0", "32", tty)),
        Some(t) => {
            let per: Vec<String> = out
                .ringbuf_rejected
                .iter()
                .map(|(n, c)| format!("{n} {c}"))
                .collect();
            println!(
                "ringbuf rejected  : {} ({}) — malformed records since boot (a desynced ring), see the agent WARNs",
                colorize(&t.to_string(), "31", tty),
                per.join(", ")
            );
        }
    }
    println!("{}", deny_fail_open_line(out, tty));
}

fn print_verify_keys(out: &VerifyKeysOutcome) -> ExitCode {
    for (line, why) in &out.skipped {
        eprintln!("verify-keys: line {line} is not a key (the agent skips it): {why}");
    }
    if out.fingerprints.is_empty() {
        eprintln!("verify-keys: no valid pub keys installed");
        return ExitCode::from(1);
    }
    println!("verify-keys: {} valid key(s)", out.fingerprints.len());
    for (fp, roles) in out.fingerprints.iter().zip(&out.roles) {
        println!("  {fp}  {roles}");
    }
    // A checker: a skipped line is a failure even when other keys load.
    if out.skipped.is_empty() {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(1)
    }
}

/// Wrap `s` in an ANSI SGR colour code when stdout is a terminal,
/// otherwise return it unchanged. Keeping this inline avoids a
/// `colored` / `owo-colors` dependency for one call site.
fn colorize(s: &str, sgr: &str, tty: bool) -> String {
    if tty {
        format!("\x1b[{sgr}m{s}\x1b[0m")
    } else {
        s.to_string()
    }
}

/// Parse a CSV role list (`unlock,audit-read`, …) into the wire
/// [`common::wire::admin_signed_payload::Role`] enum. Empty input
/// is rejected — A13's `add` flow requires at least one role.
///
/// External audit AUT-013: the list is checked by the agent's own
/// admin.pub parser, so an empty entry (`unlock,,audit-read`,
/// `unlock,`) is refused with the agent's words instead of being
/// skipped; spaces around an entry are still trimmed (a convenience
/// of the command line, the agent writes the list without them).
fn parse_roles_csv(s: &str) -> anyhow::Result<Vec<common::wire::admin_signed_payload::Role>> {
    use anyhow::bail;
    if s.trim().is_empty() {
        bail!("--new-roles must list at least one role keyword");
    }
    // Review `admin-cli-roles-1`: delegate to the agent's admin.pub
    // keyword table so `rotate-keys add --new-roles` can grant EVERY
    // role the agent understands (fim-*, canary-*, net-*, triage, …),
    // not the five-keyword subset this CLI used to hard-code — which
    // made canary-manage / fim-manage ungrantable from the CLI.
    let tight: Vec<&str> = s.split(',').map(str::trim).collect();
    northnarrow_agent::anti_tamper::admin_auth::parse_role_list(&tight.join(","))
        .map_err(|e| anyhow::anyhow!("--new-roles: {e}"))
}

/// Map a [`RotateKeysOutcome`] to a stable exit code (mirrors
/// `exit_from_shutdown`'s contract: Success=0, transport/
/// timestamp/agentid/unknown-op all under exit 5, distinct
/// security failures get 2/4/6/7 per design §5.3).
fn exit_from_rotate_keys(outcome: RotateKeysOutcome, op_label: &str) -> ExitCode {
    let tty = std::io::stdout().is_terminal();
    match outcome {
        RotateKeysOutcome::Success => {
            println!("{}", colorize(&format!("{op_label}: success"), "32", tty));
            ExitCode::SUCCESS
        }
        RotateKeysOutcome::InvalidSignature => {
            eprintln!(
                "{}",
                colorize(
                    &format!(
                        "{op_label}: refused — invalid signature, key already present, \
                         fingerprint already held by another key, key not found, fingerprint \
                         matching several keys, or last-key guard (the agent's journal says \
                         which)"
                    ),
                    "31",
                    tty
                )
            );
            ExitCode::from(2)
        }
        RotateKeysOutcome::NoPendingChallenge => {
            eprintln!("{op_label}: no pending challenge (retry)");
            ExitCode::from(3)
        }
        RotateKeysOutcome::RateLimited { retry_after_secs } => {
            eprintln!("{op_label}: rate limited; retry after {retry_after_secs}s");
            ExitCode::from(4)
        }
        RotateKeysOutcome::QuorumNotMet { required, provided } => {
            eprintln!("{op_label}: quorum not met ({provided}/{required})");
            ExitCode::from(6)
        }
        RotateKeysOutcome::RoleDenied => {
            eprintln!(
                "{op_label}: role denied (no submitted key holds the `rotate-keys` \
                 role in admin.pub, or the new key asks for a role no signer holds)"
            );
            ExitCode::from(7)
        }
        RotateKeysOutcome::TimestampSkew {
            server_ts,
            max_skew_secs,
        } => {
            eprintln!(
                "{op_label}: clock skew (server_ts={server_ts}, max ±{max_skew_secs}s); NTP-sync and retry"
            );
            ExitCode::from(5)
        }
        RotateKeysOutcome::AgentIdMismatch => {
            eprintln!("{op_label}: agent_id mismatch (--agent-id-file points at the wrong agent)");
            ExitCode::from(5)
        }
        RotateKeysOutcome::UnknownOperation => {
            eprintln!(
                "{op_label}: server rejected operation (op_extra mismatch or no config path)"
            );
            ExitCode::from(5)
        }
        RotateKeysOutcome::ProtocolVersionUnsupported { server_version } => {
            eprintln!(
                "{op_label}: server speaks protocol v{server_version}; this nn-admin is newer"
            );
            ExitCode::from(5)
        }
    }
}

/// C6: map [`FimBaselineOutcome`] to a stable exit code.
/// Mirrors the rotate-keys mapping (0=success, 2=invalid-sig,
/// 4=rate-limited, 5=transport/clock/agent-id/unknown-op,
/// 6=quorum, 7=role).
fn exit_from_fim_baseline(outcome: FimBaselineOutcome) -> ExitCode {
    let tty = std::io::stdout().is_terminal();
    match outcome {
        FimBaselineOutcome::Success => {
            println!("{}", colorize("fim baseline: success", "32", tty));
            ExitCode::SUCCESS
        }
        FimBaselineOutcome::InvalidSignature => {
            eprintln!("fim baseline: invalid signature");
            ExitCode::from(2)
        }
        FimBaselineOutcome::NoPendingChallenge => {
            eprintln!("fim baseline: no pending challenge (retry)");
            ExitCode::from(3)
        }
        FimBaselineOutcome::RateLimited { retry_after_secs } => {
            eprintln!("fim baseline: rate limited; retry after {retry_after_secs}s");
            ExitCode::from(4)
        }
        FimBaselineOutcome::QuorumNotMet { required, provided } => {
            eprintln!("fim baseline: quorum not met ({provided}/{required})");
            ExitCode::from(6)
        }
        FimBaselineOutcome::RoleDenied => {
            eprintln!(
                "fim baseline: role denied (the submitted key lacks `fim-manage` in admin.pub)"
            );
            ExitCode::from(7)
        }
        FimBaselineOutcome::TimestampSkew {
            server_ts,
            max_skew_secs,
        } => {
            eprintln!(
                "fim baseline: clock skew (server_ts={server_ts}, max ±{max_skew_secs}s); NTP-sync and retry"
            );
            ExitCode::from(5)
        }
        FimBaselineOutcome::AgentIdMismatch => {
            eprintln!("fim baseline: agent_id mismatch");
            ExitCode::from(5)
        }
        FimBaselineOutcome::UnknownOperation => {
            eprintln!("fim baseline: server rejected operation");
            ExitCode::from(5)
        }
        FimBaselineOutcome::ProtocolVersionUnsupported { server_version } => {
            eprintln!("fim baseline: server speaks protocol v{server_version}");
            ExitCode::from(5)
        }
    }
}

/// FIM-009 self-upgrade (§15.1): map [`TrustedInstallerGrantOutcome`]
/// to a stable exit code — same contract as [`exit_from_fim_baseline`]
/// (0 success; 2 bad-sig; 3 no-challenge; 4 rate-limited; 5 transport/
/// skew/agent-id/unknown-op/version; 6 quorum; 7 role-denied).
fn overlay_kind_arg(kind: &str) -> Option<common::wire::admin_signed_payload::OverlayKind> {
    let k = common::wire::admin_signed_payload::OverlayKind::from_keyword(kind);
    if k.is_none() {
        let all: Vec<&str> = common::wire::admin_signed_payload::OverlayKind::ALL
            .iter()
            .map(|k| k.keyword())
            .collect();
        eprintln!(
            "config overlay: unknown overlay `{kind}` — one of: {}",
            all.join(", ")
        );
    }
    k
}

/// Exit code of a signed verb that the agent refused before doing
/// anything (authentication, role, version).
fn exit_from_admin_result(op: &str, r: common::wire::admin_protocol::AdminResult) -> ExitCode {
    use common::wire::admin_protocol::AdminResult;
    let (code, why) = match r {
        AdminResult::Success => (0, String::new()),
        AdminResult::InvalidSignature => (2, "invalid signature".to_string()),
        AdminResult::NoPendingChallenge => (3, "no pending challenge (retry)".to_string()),
        AdminResult::RateLimited { retry_after_secs } => {
            (4, format!("rate limited; retry after {retry_after_secs}s"))
        }
        AdminResult::QuorumNotMet { required, provided } => {
            (6, format!("quorum not met ({provided}/{required})"))
        }
        AdminResult::RoleDenied => (7, "role denied".to_string()),
        AdminResult::UnknownOperation => (
            5,
            "the agent does not run this verb (older agent, or the response layer is not wired)"
                .to_string(),
        ),
        other => (5, format!("{other:?}")),
    };
    if code != 0 {
        eprintln!("{op}: {why}");
    }
    ExitCode::from(code)
}

/// External audit CMB-016: `nn-admin response status|release|restore`.
/// Exit 0 when done, 9 when the agent verified the request and did nothing
/// (not contained, refused destination: the reason is printed), the usual
/// codes otherwise (2 signature, 3 challenge, 4 rate limit, 5 transport /
/// version, 7 role).
fn run_response_cmd(sub: ResponseCmd) -> ExitCode {
    use common::wire::admin_protocol::AdminResult;
    use northnarrow_agent::admin_cli::{
        run_response_release, run_response_restore, run_response_status, ResponseActionOutcome,
    };
    let finish = |op: &str, r: anyhow::Result<ResponseActionOutcome>| match r {
        Ok(o) if o.done => {
            println!("{op}: {}", o.message);
            ExitCode::SUCCESS
        }
        Ok(o) if o.result == AdminResult::Success => {
            eprintln!("{op}: not done: {}", o.message);
            ExitCode::from(9)
        }
        Ok(o) => exit_from_admin_result(op, o.result),
        Err(e) => {
            eprintln!("{op}: {e:#}");
            ExitCode::from(5)
        }
    };
    match sub {
        ResponseCmd::Status {
            key,
            agent_id_file,
            socket,
        } => match run_response_status(&socket, &key, &agent_id_file) {
            Ok(r) if r.result == AdminResult::Success => {
                println!(
                    "combat stage      : {}{}",
                    r.combat_stage.as_deref().unwrap_or("(no episode)"),
                    match r.combat_locked {
                        Some(true) => " (locked)",
                        _ => "",
                    }
                );
                println!("contained         : {}", r.contained_total);
                for c in &r.contained {
                    println!(
                        "  pid {:<8} {:<9} from {}  since {}  {}",
                        c.pid,
                        c.scope,
                        if c.origin.is_empty() { "?" } else { &c.origin },
                        c.since,
                        if c.running {
                            "running"
                        } else {
                            "gone (or another process)"
                        }
                    );
                }
                if r.contained.len() < r.contained_total as usize {
                    println!(
                        "  … {} older not shown",
                        r.contained_total as usize - r.contained.len()
                    );
                }
                println!("quarantined       : {}", r.quarantined_total);
                for q in &r.quarantined {
                    println!(
                        "  {}  {} bytes  at {}  from {}",
                        q.vault_id, q.size_bytes, q.captured_at, q.original_path
                    );
                }
                if r.quarantined.len() < r.quarantined_total as usize {
                    println!(
                        "  … {} older not shown",
                        r.quarantined_total as usize - r.quarantined.len()
                    );
                }
                ExitCode::SUCCESS
            }
            Ok(r) => exit_from_admin_result("response status", r.result),
            Err(e) => {
                eprintln!("response status: {e:#}");
                ExitCode::from(5)
            }
        },
        ResponseCmd::Release {
            pid,
            key,
            agent_id_file,
            socket,
        } => finish(
            "response release",
            run_response_release(&socket, &key, &agent_id_file, pid),
        ),
        ResponseCmd::Restore {
            vault_id,
            to,
            key,
            agent_id_file,
            socket,
        } => finish(
            "response restore",
            run_response_restore(&socket, &key, &agent_id_file, vault_id, to),
        ),
    }
}

fn run_overlay_cmd(sub: OverlayCmd) -> ExitCode {
    use northnarrow_agent::admin_cli::{run_config_overlay_set, run_config_overlay_sign};
    use northnarrow_agent::config::overlay_auth::{Decision, OverlayGate};
    match sub {
        OverlayCmd::Set {
            kind,
            file,
            key,
            cosign_key,
            agent_id_file,
            socket,
        } => {
            let Some(kind) = overlay_kind_arg(&kind) else {
                return ExitCode::from(2);
            };
            match run_config_overlay_set(
                &socket,
                &key,
                cosign_key.as_deref(),
                &agent_id_file,
                kind,
                &file,
            ) {
                Ok(o) if o.stored => {
                    println!("config overlay set: {}", o.message);
                    ExitCode::SUCCESS
                }
                Ok(o) if o.result == common::wire::admin_protocol::AdminResult::Success => {
                    eprintln!("config overlay set: refused by the agent: {}", o.message);
                    ExitCode::from(6)
                }
                Ok(o) => {
                    eprintln!("config overlay set: {:?} ({})", o.result, o.message);
                    ExitCode::from(match o.result {
                        common::wire::admin_protocol::AdminResult::RoleDenied => 7,
                        common::wire::admin_protocol::AdminResult::InvalidSignature => 2,
                        _ => 5,
                    })
                }
                Err(e) => {
                    eprintln!("config overlay set: {e:#}");
                    ExitCode::from(5)
                }
            }
        }
        OverlayCmd::Sign {
            kind,
            file,
            key,
            cosign_key,
            agent_id_file,
            out,
        } => {
            let Some(kind) = overlay_kind_arg(&kind) else {
                return ExitCode::from(2);
            };
            match run_config_overlay_sign(
                &key,
                cosign_key.as_deref(),
                &agent_id_file,
                kind,
                &file,
                out.as_deref(),
            ) {
                Ok(p) => {
                    println!(
                        "config overlay sign: {} written (the agent verifies it at its next start)",
                        p.display()
                    );
                    ExitCode::SUCCESS
                }
                Err(e) => {
                    eprintln!("config overlay sign: {e:#}");
                    ExitCode::from(5)
                }
            }
        }
        OverlayCmd::Status {
            dir,
            admin_pub,
            agent_id_file,
            audit_log,
            agent_sig_key,
        } => {
            let agent_id = match northnarrow_agent::agent_id::load_existing(&agent_id_file) {
                Ok(a) => a,
                Err(e) => {
                    eprintln!("config overlay status: {e:#}");
                    return ExitCode::from(5);
                }
            };
            // External audit LLMR-014: the floor the verified chain proves.
            let floor = northnarrow_agent::config::overlay_floor::RollbackFloor::scan(
                &audit_log,
                &agent_sig_key,
            );
            if let Some(why) = floor.reset() {
                println!(
                    "{:<24} reset at the next start: {why} — an overlay signed before it is not loaded",
                    "rollback-floor"
                );
            } else if let Some(not_before) = floor.not_before() {
                println!(
                    "{:<24} reset at {not_before} (audit chain found gone or broken): an overlay signed before it is not loaded",
                    "rollback-floor"
                );
            }
            let gate = OverlayGate::new(&admin_pub, agent_id, floor);
            let mut unsigned = 0;
            for kind in common::wire::admin_signed_payload::OverlayKind::ALL {
                let path = dir.join(kind.file_name());
                match gate.check(kind, &path) {
                    Decision::Absent => println!(
                        "{:<24} {}",
                        kind.keyword(),
                        if path.exists() {
                            "shipped default"
                        } else {
                            "absent"
                        }
                    ),
                    Decision::Accepted {
                        signed_ts, key_fps, ..
                    } => {
                        println!(
                            "{:<24} signed (ts {signed_ts}, keys {}){}",
                            kind.keyword(),
                            key_fps.join(","),
                            carveout_lines_dropped(kind, &path)
                        )
                    }
                    Decision::Refused { reason, .. } => {
                        unsigned += 1;
                        println!(
                            "{:<24} NOT LOADED at the next start: {reason}{}",
                            kind.keyword(),
                            if northnarrow_agent::config::overlay_auth::shipped_default(kind)
                                .is_some()
                            {
                                " — COMBAT applies the built-in content"
                            } else {
                                ""
                            }
                        )
                    }
                }
            }
            if unsigned > 0 {
                ExitCode::from(1)
            } else {
                ExitCode::SUCCESS
            }
        }
    }
}

/// External audit NN-AUD-095: a carve-out signed before the prefix floor
/// keeps its signature, but COMBAT skips each line the floor refuses —
/// said here, on the same status line (install.sh reads its first two
/// words).
fn carveout_lines_dropped(
    kind: common::wire::admin_signed_payload::OverlayKind,
    path: &std::path::Path,
) -> String {
    if kind != common::wire::admin_signed_payload::OverlayKind::CombatAllow {
        return String::new();
    }
    let Ok(text) = std::fs::read_to_string(path) else {
        return String::new();
    };
    let load = northnarrow_agent::anti_tamper::combat_allow::parse_allow_text(&text);
    match load.warnings.as_slice() {
        [] => String::new(),
        [only] => format!(" — 1 line skipped at COMBAT engage: {only}"),
        [first, rest @ ..] => format!(
            " — {} lines skipped at COMBAT engage: {first} (and {} more)",
            rest.len() + 1,
            rest.len()
        ),
    }
}

fn exit_from_trusted_installer_grant(
    outcome: TrustedInstallerGrantOutcome,
    window_secs: u32,
) -> ExitCode {
    let tty = std::io::stdout().is_terminal();
    match outcome {
        TrustedInstallerGrantOutcome::Success => {
            println!(
                "{}",
                colorize(
                    &format!(
                        "trusted-installer-grant: override armed for {window_secs}s — FS pin \
                         suspended; the agent's own systemd-unit writes are downgraded to an \
                         audit Log. Run install.sh + `systemctl restart` now; the window closes \
                         at the deadline or on restart, whichever comes first."
                    ),
                    "32",
                    tty
                )
            );
            ExitCode::SUCCESS
        }
        TrustedInstallerGrantOutcome::InvalidSignature => {
            eprintln!(
                "trusted-installer-grant: invalid signature (key not in admin.pub, or wrong bytes)"
            );
            ExitCode::from(2)
        }
        TrustedInstallerGrantOutcome::NoPendingChallenge => {
            eprintln!("trusted-installer-grant: no pending challenge (retry)");
            ExitCode::from(3)
        }
        TrustedInstallerGrantOutcome::RateLimited { retry_after_secs } => {
            eprintln!("trusted-installer-grant: rate limited; retry after {retry_after_secs}s");
            ExitCode::from(4)
        }
        TrustedInstallerGrantOutcome::QuorumNotMet { required, provided } => {
            eprintln!("trusted-installer-grant: quorum not met ({provided}/{required})");
            ExitCode::from(6)
        }
        TrustedInstallerGrantOutcome::RoleDenied => {
            eprintln!(
                "trusted-installer-grant: role denied (the submitted key lacks the \
                 `trusted-installer` role in admin.pub — add it to the line's role list)"
            );
            ExitCode::from(7)
        }
        TrustedInstallerGrantOutcome::TimestampSkew {
            server_ts,
            max_skew_secs,
        } => {
            eprintln!(
                "trusted-installer-grant: clock skew (server_ts={server_ts}, max ±{max_skew_secs}s); \
                 NTP-sync this host and the agent host, then retry"
            );
            ExitCode::from(5)
        }
        TrustedInstallerGrantOutcome::AgentIdMismatch => {
            eprintln!(
                "trusted-installer-grant: agent_id mismatch (the --agent-id-file content doesn't \
                 match the agent's bootstrapped UUID)"
            );
            ExitCode::from(5)
        }
        TrustedInstallerGrantOutcome::UnknownOperation => {
            eprintln!("trusted-installer-grant: server rejected operation");
            ExitCode::from(5)
        }
        TrustedInstallerGrantOutcome::ProtocolVersionUnsupported { server_version } => {
            eprintln!("trusted-installer-grant: server speaks protocol v{server_version}");
            ExitCode::from(5)
        }
    }
}

/// C6: map [`FimReportOutcome`] to an exit code AND stream
/// the JSONL body to stdout on success. The summary line goes
/// to STDERR so `nn-admin fim report | jq` keeps a clean
/// JSONL stream on stdout (mirrors `nn-admin audit read
/// --json | jq`).
fn exit_from_fim_report(outcome: FimReportOutcome) -> ExitCode {
    match outcome {
        FimReportOutcome::Success {
            entries_jsonl,
            entries_count,
            entries_truncated,
        } => {
            // Stream verbatim — the body is already \n-terminated
            // JSONL from the server (the dispatch appends \n per
            // entry in read_fim_drift_jsonl).
            print!("{entries_jsonl}");
            if entries_truncated {
                eprintln!(
                    "fim report: {entries_count} entries (truncated; pass --since <unix-ts> to narrow)"
                );
            } else {
                eprintln!("fim report: {entries_count} entries");
            }
            ExitCode::SUCCESS
        }
        FimReportOutcome::InvalidSignature => {
            eprintln!("fim report: invalid signature");
            ExitCode::from(2)
        }
        FimReportOutcome::NoPendingChallenge => {
            eprintln!("fim report: no pending challenge (retry)");
            ExitCode::from(3)
        }
        FimReportOutcome::RateLimited { retry_after_secs } => {
            eprintln!("fim report: rate limited; retry after {retry_after_secs}s");
            ExitCode::from(4)
        }
        FimReportOutcome::RoleDenied => {
            eprintln!("fim report: role denied (the submitted key lacks `fim-read`)");
            ExitCode::from(7)
        }
        FimReportOutcome::TimestampSkew {
            server_ts,
            max_skew_secs,
        } => {
            eprintln!("fim report: clock skew (server_ts={server_ts}, max ±{max_skew_secs}s)");
            ExitCode::from(5)
        }
        FimReportOutcome::AgentIdMismatch => {
            eprintln!("fim report: agent_id mismatch");
            ExitCode::from(5)
        }
        FimReportOutcome::UnknownOperation => {
            eprintln!("fim report: server rejected operation");
            ExitCode::from(5)
        }
        FimReportOutcome::ProtocolVersionUnsupported { server_version } => {
            eprintln!("fim report: server speaks protocol v{server_version}");
            ExitCode::from(5)
        }
        FimReportOutcome::Transport => {
            eprintln!("fim report: unexpected server reply");
            ExitCode::from(5)
        }
    }
}

/// C7: map [`FimStatusOutcome`] to an exit code AND print the
/// snapshot to stdout on success. Stable exit shape mirrors
/// [`exit_from_fim_baseline`] / [`exit_from_fim_report`] so
/// operator scripts can branch on `$?` without parsing text.
fn exit_from_fim_status(outcome: FimStatusOutcome) -> ExitCode {
    match outcome {
        FimStatusOutcome::Success {
            watched_paths_count,
            disabled_default_count,
            added_path_count,
            last_baseline_ts,
            baseline_entries_total,
            drift_entries_total,
            high_remaining,
            high_cap_per_min,
            medium_remaining,
            medium_cap_per_min,
            bucket_window_resets_in_secs,
        } => {
            println!("fim status:");
            println!(
                "  paths-watched: {watched_paths_count} \
                 (added {added_path_count}, disabled-default {disabled_default_count})"
            );
            if last_baseline_ts.is_empty() {
                println!(
                    "  baseline: 0 entries (no chain yet — first-boot TOFU pending or no \
                     paths configured)"
                );
            } else {
                println!(
                    "  baseline: {baseline_entries_total} entries (last ts: {last_baseline_ts})"
                );
            }
            println!("  drift:    {drift_entries_total} entries");
            println!(
                "  rate-limit (Q4): high {high_remaining}/{high_cap_per_min}, \
                 medium {medium_remaining}/{medium_cap_per_min}, \
                 window resets in {bucket_window_resets_in_secs}s \
                 (Critical: uncapped — §13 Q4 lock-in)"
            );
            ExitCode::SUCCESS
        }
        FimStatusOutcome::InvalidSignature => {
            eprintln!("fim status: invalid signature");
            ExitCode::from(2)
        }
        FimStatusOutcome::NoPendingChallenge => {
            eprintln!("fim status: no pending challenge (retry)");
            ExitCode::from(3)
        }
        FimStatusOutcome::RateLimited { retry_after_secs } => {
            eprintln!("fim status: rate limited; retry after {retry_after_secs}s");
            ExitCode::from(4)
        }
        FimStatusOutcome::RoleDenied => {
            eprintln!("fim status: role denied (the submitted key lacks `fim-read`)");
            ExitCode::from(7)
        }
        FimStatusOutcome::TimestampSkew {
            server_ts,
            max_skew_secs,
        } => {
            eprintln!("fim status: clock skew (server_ts={server_ts}, max ±{max_skew_secs}s)");
            ExitCode::from(5)
        }
        FimStatusOutcome::AgentIdMismatch => {
            eprintln!("fim status: agent_id mismatch");
            ExitCode::from(5)
        }
        FimStatusOutcome::UnknownOperation => {
            eprintln!("fim status: server rejected operation");
            ExitCode::from(5)
        }
        FimStatusOutcome::ProtocolVersionUnsupported { server_version } => {
            eprintln!("fim status: server speaks protocol v{server_version}");
            ExitCode::from(5)
        }
        FimStatusOutcome::Transport => {
            eprintln!("fim status: unexpected server reply");
            ExitCode::from(5)
        }
    }
}

/// K6: map [`CanaryDeployOutcome`] to a stable exit code.
/// Mirrors the FIM exit-code shape (0=success, 2=invalid-sig,
/// 4=rate-limited, 5=transport/clock/agent-id/unknown-op,
/// 6=quorum, 7=role) so operator scripts can branch on `$?`
/// across the FIM + canary surfaces.
fn exit_from_canary_deploy(outcome: CanaryDeployOutcome) -> ExitCode {
    let tty = std::io::stdout().is_terminal();
    match outcome {
        CanaryDeployOutcome::Success { canary_id } => {
            println!(
                "{}",
                colorize(&format!("canary deploy: success ({canary_id})"), "32", tty)
            );
            ExitCode::SUCCESS
        }
        CanaryDeployOutcome::InvalidSignature => {
            eprintln!("canary deploy: invalid signature");
            ExitCode::from(2)
        }
        CanaryDeployOutcome::NoPendingChallenge => {
            eprintln!("canary deploy: no pending challenge (retry)");
            ExitCode::from(3)
        }
        CanaryDeployOutcome::RateLimited { retry_after_secs } => {
            eprintln!("canary deploy: rate limited; retry after {retry_after_secs}s");
            ExitCode::from(4)
        }
        CanaryDeployOutcome::QuorumNotMet { required, provided } => {
            eprintln!("canary deploy: quorum not met ({provided}/{required})");
            ExitCode::from(6)
        }
        CanaryDeployOutcome::RoleDenied => {
            eprintln!(
                "canary deploy: role denied (the submitted key lacks `canary-manage` in admin.pub)"
            );
            ExitCode::from(7)
        }
        CanaryDeployOutcome::TimestampSkew {
            server_ts,
            max_skew_secs,
        } => {
            eprintln!(
                "canary deploy: clock skew (server_ts={server_ts}, max ±{max_skew_secs}s); NTP-sync and retry"
            );
            ExitCode::from(5)
        }
        CanaryDeployOutcome::AgentIdMismatch => {
            eprintln!("canary deploy: agent_id mismatch");
            ExitCode::from(5)
        }
        CanaryDeployOutcome::UnknownOperation => {
            eprintln!("canary deploy: server rejected operation");
            ExitCode::from(5)
        }
        CanaryDeployOutcome::ProtocolVersionUnsupported { server_version } => {
            eprintln!("canary deploy: server speaks protocol v{server_version}");
            ExitCode::from(5)
        }
        CanaryDeployOutcome::Transport => {
            eprintln!("canary deploy: unexpected server reply");
            ExitCode::from(5)
        }
    }
}

/// K6: map [`CanaryListOutcome`] to an exit code AND stream the
/// JSONL body to stdout on success. Summary line goes to stderr
/// (matches `fim report`) so `nn-admin canary list | jq` works.
fn exit_from_canary_list(outcome: CanaryListOutcome) -> ExitCode {
    match outcome {
        CanaryListOutcome::Success {
            entries_jsonl,
            entries_count,
            entries_truncated,
        } => {
            print!("{entries_jsonl}");
            if entries_truncated {
                eprintln!("canary list: {entries_count} entries (truncated)");
            } else {
                eprintln!("canary list: {entries_count} entries");
            }
            ExitCode::SUCCESS
        }
        CanaryListOutcome::InvalidSignature => {
            eprintln!("canary list: invalid signature");
            ExitCode::from(2)
        }
        CanaryListOutcome::NoPendingChallenge => {
            eprintln!("canary list: no pending challenge (retry)");
            ExitCode::from(3)
        }
        CanaryListOutcome::RateLimited { retry_after_secs } => {
            eprintln!("canary list: rate limited; retry after {retry_after_secs}s");
            ExitCode::from(4)
        }
        CanaryListOutcome::RoleDenied => {
            eprintln!("canary list: role denied (the submitted key lacks `canary-read`)");
            ExitCode::from(7)
        }
        CanaryListOutcome::TimestampSkew {
            server_ts,
            max_skew_secs,
        } => {
            eprintln!("canary list: clock skew (server_ts={server_ts}, max ±{max_skew_secs}s)");
            ExitCode::from(5)
        }
        CanaryListOutcome::AgentIdMismatch => {
            eprintln!("canary list: agent_id mismatch");
            ExitCode::from(5)
        }
        CanaryListOutcome::UnknownOperation => {
            eprintln!("canary list: server rejected operation");
            ExitCode::from(5)
        }
        CanaryListOutcome::ProtocolVersionUnsupported { server_version } => {
            eprintln!("canary list: server speaks protocol v{server_version}");
            ExitCode::from(5)
        }
        CanaryListOutcome::Transport => {
            eprintln!("canary list: unexpected server reply");
            ExitCode::from(5)
        }
    }
}

/// K6: map [`CanaryBurnOutcome`] to an exit code. Adds a new
/// shared exit-code 9 for "canary id not found" — distinct from
/// the FIM family because the canary surface is the only one
/// where the operator-supplied id can validly be missing
/// server-side (deploys go via the server; burns reference an
/// id the operator typed).
fn exit_from_canary_burn(outcome: CanaryBurnOutcome) -> ExitCode {
    let tty = std::io::stdout().is_terminal();
    match outcome {
        CanaryBurnOutcome::Success => {
            println!("{}", colorize("canary burn: success", "32", tty));
            ExitCode::SUCCESS
        }
        CanaryBurnOutcome::InvalidSignature => {
            eprintln!("canary burn: invalid signature");
            ExitCode::from(2)
        }
        CanaryBurnOutcome::NoPendingChallenge => {
            eprintln!("canary burn: no pending challenge (retry)");
            ExitCode::from(3)
        }
        CanaryBurnOutcome::RateLimited { retry_after_secs } => {
            eprintln!("canary burn: rate limited; retry after {retry_after_secs}s");
            ExitCode::from(4)
        }
        CanaryBurnOutcome::QuorumNotMet { required, provided } => {
            eprintln!("canary burn: quorum not met ({provided}/{required})");
            ExitCode::from(6)
        }
        CanaryBurnOutcome::RoleDenied => {
            eprintln!("canary burn: role denied (key lacks `canary-manage`)");
            ExitCode::from(7)
        }
        CanaryBurnOutcome::TimestampSkew {
            server_ts,
            max_skew_secs,
        } => {
            eprintln!("canary burn: clock skew (server_ts={server_ts}, max ±{max_skew_secs}s)");
            ExitCode::from(5)
        }
        CanaryBurnOutcome::AgentIdMismatch => {
            eprintln!("canary burn: agent_id mismatch");
            ExitCode::from(5)
        }
        CanaryBurnOutcome::UnknownOperation => {
            eprintln!("canary burn: server rejected operation");
            ExitCode::from(5)
        }
        CanaryBurnOutcome::NotFound => {
            eprintln!("canary burn: no canary with that id (check `nn-admin canary list`)");
            ExitCode::from(9)
        }
        CanaryBurnOutcome::ProtocolVersionUnsupported { server_version } => {
            eprintln!("canary burn: server speaks protocol v{server_version}");
            ExitCode::from(5)
        }
        CanaryBurnOutcome::Transport => {
            eprintln!("canary burn: unexpected server reply");
            ExitCode::from(5)
        }
    }
}

/// K6: map [`CanaryRefreshOutcome`] to an exit code. Same shape
/// as [`exit_from_canary_burn`] (both ops are
/// `canary-manage`-role mutations keyed by canary_id).
fn exit_from_canary_refresh(outcome: CanaryRefreshOutcome) -> ExitCode {
    let tty = std::io::stdout().is_terminal();
    match outcome {
        CanaryRefreshOutcome::Success => {
            println!("{}", colorize("canary refresh: success", "32", tty));
            ExitCode::SUCCESS
        }
        CanaryRefreshOutcome::InvalidSignature => {
            eprintln!("canary refresh: invalid signature");
            ExitCode::from(2)
        }
        CanaryRefreshOutcome::NoPendingChallenge => {
            eprintln!("canary refresh: no pending challenge (retry)");
            ExitCode::from(3)
        }
        CanaryRefreshOutcome::RateLimited { retry_after_secs } => {
            eprintln!("canary refresh: rate limited; retry after {retry_after_secs}s");
            ExitCode::from(4)
        }
        CanaryRefreshOutcome::QuorumNotMet { required, provided } => {
            eprintln!("canary refresh: quorum not met ({provided}/{required})");
            ExitCode::from(6)
        }
        CanaryRefreshOutcome::RoleDenied => {
            eprintln!("canary refresh: role denied (key lacks `canary-manage`)");
            ExitCode::from(7)
        }
        CanaryRefreshOutcome::TimestampSkew {
            server_ts,
            max_skew_secs,
        } => {
            eprintln!("canary refresh: clock skew (server_ts={server_ts}, max ±{max_skew_secs}s)");
            ExitCode::from(5)
        }
        CanaryRefreshOutcome::AgentIdMismatch => {
            eprintln!("canary refresh: agent_id mismatch");
            ExitCode::from(5)
        }
        CanaryRefreshOutcome::UnknownOperation => {
            eprintln!("canary refresh: server rejected operation");
            ExitCode::from(5)
        }
        CanaryRefreshOutcome::NotFound => {
            eprintln!("canary refresh: no canary with that id (check `nn-admin canary list`)");
            ExitCode::from(9)
        }
        CanaryRefreshOutcome::ProtocolVersionUnsupported { server_version } => {
            eprintln!("canary refresh: server speaks protocol v{server_version}");
            ExitCode::from(5)
        }
        CanaryRefreshOutcome::Transport => {
            eprintln!("canary refresh: unexpected server reply");
            ExitCode::from(5)
        }
    }
}

/// Tappa 10 N7 — shared exit handler for net subcommands that
/// return JSONL bodies (flows / listeners / fingerprint). Stable
/// exit shape mirrors [`exit_from_fim_report`].
fn exit_from_net_jsonl(outcome: NetJsonlOutcome, op: &str) -> ExitCode {
    match outcome {
        NetJsonlOutcome::Success {
            entries_jsonl,
            entries_count,
            entries_truncated,
        } => {
            print!("{entries_jsonl}");
            if entries_truncated {
                eprintln!(
                    "{op}: {entries_count} entries (truncated; pass --since-unix <ts> to narrow)"
                );
            } else {
                eprintln!("{op}: {entries_count} entries");
            }
            ExitCode::SUCCESS
        }
        NetJsonlOutcome::InvalidSignature => {
            eprintln!("{op}: invalid signature");
            ExitCode::from(2)
        }
        NetJsonlOutcome::NoPendingChallenge => {
            eprintln!("{op}: no pending challenge (retry)");
            ExitCode::from(3)
        }
        NetJsonlOutcome::RateLimited { retry_after_secs } => {
            eprintln!("{op}: rate limited; retry after {retry_after_secs}s");
            ExitCode::from(4)
        }
        NetJsonlOutcome::RoleDenied => {
            eprintln!("{op}: role denied (the submitted key lacks `net-read`)");
            ExitCode::from(7)
        }
        NetJsonlOutcome::TimestampSkew {
            server_ts,
            max_skew_secs,
        } => {
            eprintln!("{op}: clock skew (server_ts={server_ts}, max ±{max_skew_secs}s)");
            ExitCode::from(5)
        }
        NetJsonlOutcome::AgentIdMismatch => {
            eprintln!("{op}: agent_id mismatch");
            ExitCode::from(5)
        }
        NetJsonlOutcome::UnknownOperation => {
            eprintln!("{op}: server rejected operation");
            ExitCode::from(5)
        }
        NetJsonlOutcome::ProtocolVersionUnsupported { server_version } => {
            eprintln!("{op}: server speaks protocol v{server_version}");
            ExitCode::from(5)
        }
        NetJsonlOutcome::Transport => {
            eprintln!("{op}: unexpected server reply");
            ExitCode::from(5)
        }
    }
}

/// Tappa 9.0.b — exit handler for `nn-admin detections`. Reuses the
/// shared [`NetJsonlOutcome`] (the reply shape is identical to the
/// chain-style net reads), but prints detection-specific summary +
/// role-denied wording. JSONL records → stdout, summary → stderr.
fn exit_from_detections(outcome: NetJsonlOutcome) -> ExitCode {
    let op = "detections";
    match outcome {
        NetJsonlOutcome::Success {
            entries_jsonl,
            entries_count,
            entries_truncated,
        } => {
            print!("{entries_jsonl}");
            if entries_truncated {
                eprintln!(
                    "{op}: {entries_count} records \
                     (truncated to fit the wire frame; narrow with \
                     --limit / --since / --min-severity / a filter)"
                );
            } else {
                eprintln!("{op}: {entries_count} records");
            }
            ExitCode::SUCCESS
        }
        NetJsonlOutcome::InvalidSignature => {
            eprintln!("{op}: invalid signature");
            ExitCode::from(2)
        }
        NetJsonlOutcome::NoPendingChallenge => {
            eprintln!("{op}: no pending challenge (retry)");
            ExitCode::from(3)
        }
        NetJsonlOutcome::RateLimited { retry_after_secs } => {
            eprintln!("{op}: rate limited; retry after {retry_after_secs}s");
            ExitCode::from(4)
        }
        NetJsonlOutcome::RoleDenied => {
            eprintln!("{op}: role denied (the submitted key lacks `telemetry-read`)");
            ExitCode::from(7)
        }
        NetJsonlOutcome::TimestampSkew {
            server_ts,
            max_skew_secs,
        } => {
            eprintln!("{op}: clock skew (server_ts={server_ts}, max ±{max_skew_secs}s)");
            ExitCode::from(5)
        }
        NetJsonlOutcome::AgentIdMismatch => {
            eprintln!("{op}: agent_id mismatch");
            ExitCode::from(5)
        }
        NetJsonlOutcome::UnknownOperation => {
            eprintln!("{op}: server rejected operation");
            ExitCode::from(5)
        }
        NetJsonlOutcome::ProtocolVersionUnsupported { server_version } => {
            eprintln!("{op}: server speaks protocol v{server_version}");
            ExitCode::from(5)
        }
        NetJsonlOutcome::Transport => {
            eprintln!("{op}: unexpected server reply");
            ExitCode::from(5)
        }
    }
}

/// Tappa 9.0.c — exit handler for `nn-admin detection-set-status`.
/// Success prints the id + new status; `NotFound` gets a precise hint.
fn exit_from_detection_set_status(outcome: DetectionSetStatusOutcome) -> ExitCode {
    let op = "detection-set-status";
    let tty = std::io::stdout().is_terminal();
    match outcome {
        DetectionSetStatusOutcome::Success { id, new_status } => {
            println!(
                "{}",
                colorize(&format!("{op}: detection {id} → {new_status}"), "32", tty)
            );
            ExitCode::SUCCESS
        }
        DetectionSetStatusOutcome::InvalidSignature => {
            eprintln!("{op}: invalid signature");
            ExitCode::from(2)
        }
        DetectionSetStatusOutcome::NoPendingChallenge => {
            eprintln!("{op}: no pending challenge (retry)");
            ExitCode::from(3)
        }
        DetectionSetStatusOutcome::RateLimited { retry_after_secs } => {
            eprintln!("{op}: rate limited; retry after {retry_after_secs}s");
            ExitCode::from(4)
        }
        DetectionSetStatusOutcome::QuorumNotMet { required, provided } => {
            eprintln!("{op}: quorum not met ({provided}/{required})");
            ExitCode::from(6)
        }
        DetectionSetStatusOutcome::RoleDenied => {
            eprintln!("{op}: role denied (the submitted key lacks `triage`)");
            ExitCode::from(7)
        }
        DetectionSetStatusOutcome::TimestampSkew {
            server_ts,
            max_skew_secs,
        } => {
            eprintln!("{op}: clock skew (server_ts={server_ts}, max ±{max_skew_secs}s)");
            ExitCode::from(5)
        }
        DetectionSetStatusOutcome::AgentIdMismatch => {
            eprintln!("{op}: agent_id mismatch");
            ExitCode::from(5)
        }
        DetectionSetStatusOutcome::NotFound => {
            // The agent folds several non-auth rejections into this one
            // signal (UnknownOperation): an out-of-range id, AND a
            // server-side persistence failure (e.g. disk full / I/O
            // error appending the status-event chain). Word it so the
            // operator is NOT falsely told the detection is gone and
            // knows the change was NOT applied — check the store + the
            // agent log, then retry.
            eprintln!(
                "{op}: change not applied — no detection with that id (check `nn-admin detections`)"
            );
            ExitCode::from(9)
        }
        DetectionSetStatusOutcome::PersistFailed { id } => {
            // chain-persist-1: machine-distinguishable from NotFound —
            // the id exists and the request was authorised, but the
            // status-event chain append failed on the agent.
            eprintln!(
                "{op}: change NOT recorded for detection {id} — the agent could not append the \
                 status-event chain (disk full / I/O error?); see the agent log, then retry"
            );
            ExitCode::from(10)
        }
        DetectionSetStatusOutcome::ProtocolVersionUnsupported { server_version } => {
            eprintln!("{op}: server speaks protocol v{server_version}");
            ExitCode::from(5)
        }
        DetectionSetStatusOutcome::Transport => {
            eprintln!("{op}: unexpected server reply");
            ExitCode::from(5)
        }
    }
}

/// Tappa 10 N7 — exit handler for `nn-admin net resolve`.
/// Single-record reply, distinct shape from the JSONL ops.
fn exit_from_net_resolve(outcome: NetResolveOutcome) -> ExitCode {
    match outcome {
        NetResolveOutcome::Success {
            qname,
            queried_at_unix_ts,
        } => {
            match qname {
                Some(name) => {
                    println!("{name}");
                    if let Some(ts) = queried_at_unix_ts {
                        eprintln!("net resolve: queried_at_unix_ts={ts}");
                    } else {
                        eprintln!("net resolve: queried_at_unix_ts=unknown");
                    }
                }
                None => {
                    eprintln!("net resolve: no retained flow to that address carries a hostname");
                }
            }
            ExitCode::SUCCESS
        }
        NetResolveOutcome::InvalidSignature => {
            eprintln!("net resolve: invalid signature");
            ExitCode::from(2)
        }
        NetResolveOutcome::NoPendingChallenge => {
            eprintln!("net resolve: no pending challenge (retry)");
            ExitCode::from(3)
        }
        NetResolveOutcome::RateLimited { retry_after_secs } => {
            eprintln!("net resolve: rate limited; retry after {retry_after_secs}s");
            ExitCode::from(4)
        }
        NetResolveOutcome::RoleDenied => {
            eprintln!("net resolve: role denied (key lacks `net-read`)");
            ExitCode::from(7)
        }
        NetResolveOutcome::TimestampSkew {
            server_ts,
            max_skew_secs,
        } => {
            eprintln!("net resolve: clock skew (server_ts={server_ts}, max ±{max_skew_secs}s)");
            ExitCode::from(5)
        }
        NetResolveOutcome::AgentIdMismatch => {
            eprintln!("net resolve: agent_id mismatch");
            ExitCode::from(5)
        }
        NetResolveOutcome::UnknownOperation => {
            eprintln!("net resolve: server rejected operation (not an IP address?)");
            ExitCode::from(5)
        }
        NetResolveOutcome::ProtocolVersionUnsupported { server_version } => {
            eprintln!("net resolve: server speaks protocol v{server_version}");
            ExitCode::from(5)
        }
        NetResolveOutcome::Transport => {
            eprintln!("net resolve: unexpected server reply");
            ExitCode::from(5)
        }
    }
}

#[cfg(test)]
mod roles_csv_tests {
    use super::parse_roles_csv;
    use common::wire::admin_signed_payload::Role;

    /// Review `admin-cli-roles-1`: every keyword the agent accepts in
    /// admin.pub is grantable from the CLI, not just the legacy five.
    #[test]
    fn grants_every_agent_role_keyword() {
        let roles = parse_roles_csv("canary-manage, fim-manage,net-read,triage").unwrap();
        assert_eq!(
            roles,
            vec![
                Role::CanaryManage,
                Role::FimManage,
                Role::NetRead,
                Role::Triage
            ]
        );
        assert_eq!(
            parse_roles_csv("unlock,audit-read").unwrap(),
            vec![Role::Unlock, Role::AuditRead]
        );
        assert_eq!(parse_roles_csv("all").unwrap(), vec![Role::All]);
    }

    #[test]
    fn rejects_unknown_empty_and_dedupes() {
        assert!(parse_roles_csv("canary-admin").is_err());
        assert!(parse_roles_csv(" , ").is_err());
        assert!(parse_roles_csv("").is_err());
        assert_eq!(
            parse_roles_csv("unlock,unlock").unwrap(),
            vec![Role::Unlock]
        );
    }

    /// External audit AUT-013: an empty entry is refused, as the agent
    /// refuses it in admin.pub, with the agent's words; it was skipped.
    #[test]
    fn rejects_an_empty_entry_like_the_agent() {
        for list in [
            "unlock,,audit-read",
            "unlock,",
            ",unlock",
            "unlock, ,audit-read",
        ] {
            let e = parse_roles_csv(list).expect_err(list).to_string();
            assert!(
                e.contains("role list has empty entry (leading/trailing/double comma)"),
                "{list}: {e}"
            );
            let agent =
                common::admin_quorum::parse_role_list(&list.replace(' ', "")).expect_err(list);
            assert!(e.ends_with(&agent), "{list}: {e} / {agent}");
        }
        assert_eq!(
            parse_roles_csv(" unlock , audit-read ").unwrap(),
            vec![Role::Unlock, Role::AuditRead],
            "spaces around an entry are trimmed"
        );
    }
}

/// External audit AUT-007: the quorum help says what the agent checks —
/// one signer holds the role, the co-signer may be any installed key.
#[cfg(test)]
mod quorum_help_tests {
    use super::Cli;
    use clap::CommandFactory;

    fn long_help(path: &[&str]) -> String {
        let mut cmd = Cli::command();
        let mut sub = &mut cmd;
        for name in path {
            sub = sub.find_subcommand_mut(name).expect(name);
        }
        let text = sub.render_long_help().to_string();
        text.split_whitespace().collect::<Vec<_>>().join(" ")
    }

    #[test]
    fn co_signer_help_matches_the_quorum_rule() {
        let add = long_help(&["rotate-keys", "add"]);
        assert!(!add.contains("also `rotate-keys` role"), "{add}");
        assert!(
            !add.contains("(must carry the `rotate-keys` role)"),
            "{add}"
        );
        assert!(
            add.contains("any key installed in admin.pub, whatever its roles"),
            "{add}"
        );
        let rotate = long_help(&["rotate-keys"]);
        assert!(
            rotate.contains("at least one of them carrying the `rotate-keys` role"),
            "{rotate}"
        );
        let shutdown = long_help(&["shutdown"]);
        assert!(
            !shutdown.contains("each with the `shutdown` role"),
            "{shutdown}"
        );
        assert!(
            shutdown.contains("at least one of them with the `shutdown` role"),
            "{shutdown}"
        );
    }
}

#[cfg(test)]
mod flow_sock_line_tests {
    use super::{
        combat_evidence_line, deny_fail_open_line, encrypted_flow_lines, flow_sock_line,
        response_mode_line, telemetry_withheld, withheld_line,
    };
    use northnarrow_agent::admin_cli::StatusOutcome;

    fn outcome(
        pending: Option<u64>,
        capacity: Option<u64>,
        forgotten: Option<u64>,
    ) -> StatusOutcome {
        StatusOutcome {
            posture: common::posture_types::PostureKind::Observing,
            network_isolation_engaged: false,
            last_admin_action_secs_ago: None,
            ringbuf_drops_total: None,
            ringbuf_drops: Vec::new(),
            combat_stage: None,
            combat_locked: None,
            ringbuf_rejected_total: None,
            ringbuf_rejected: Vec::new(),
            netflow_rows_skipped_total: None,
            netflow_pending_evicted_total: None,
            net_inactive_rules: None,
            flow_sock_pending: pending,
            flow_sock_capacity: capacity,
            flow_sock_forgotten_min: forgotten,
            detect_only: None,
            detect_only_source: None,
            combat_evidence_unrecorded: None,
            combat_evidence_pending: None,
            combat_evidence_dropped: None,
            net_dot_rows_total: None,
            net_dot_rows_resolver: None,
            net_quic_rows_total: None,
            deny_fail_open_total: None,
            deny_fail_open: Vec::new(),
            network_isolation_v4: None,
            network_isolation_v6: None,
            telemetry_signed: true,
        }
    }

    /// Lab PR 215: `status` reports the operations the deny hooks let
    /// through undecided, per hook, and says when the agent counts none.
    #[test]
    fn status_reports_the_deny_fail_opens() {
        let mut o = outcome(None, None, None);
        assert!(
            deny_fail_open_line(&o, false).contains("not counted"),
            "{}",
            deny_fail_open_line(&o, false)
        );
        o.deny_fail_open_total = Some(0);
        assert_eq!(deny_fail_open_line(&o, false), "deny fail-open    : 0");
        o.deny_fail_open_total = Some(3);
        o.deny_fail_open = vec![("file_open".to_string(), 2), ("bpf".to_string(), 1)];
        let l = deny_fail_open_line(&o, false);
        assert!(
            l.starts_with("deny fail-open    : 3 (file_open 2, bpf 1) — operations a deny hook")
                && l.contains("deny_fail_open entries"),
            "{l}"
        );
        // the unsigned reply of an agent older than lab PR 213 fills it in
        o.telemetry_signed = false;
        assert!(!telemetry_withheld(&o));
    }

    /// External audit ASK-009 (lab PR 213): an unsigned reply of this agent
    /// carries no telemetry — said as withheld, with the command that reads
    /// it, not as "agent predates the counter". A signed reply, or an older
    /// agent's unsigned one that still fills the counters, is printed as
    /// before.
    #[test]
    fn an_unsigned_reply_says_the_telemetry_is_withheld() {
        let mut o = outcome(None, None, None);
        o.telemetry_signed = false;
        assert!(telemetry_withheld(&o));
        let l = withheld_line("telemetry         ", "ring drops", "status");
        assert!(
            l.starts_with("telemetry         : withheld from the unsigned status (ring drops)")
                && l.contains("`nn-admin status --key <key>`")
                && l.contains("`audit-read` or `telemetry-read`"),
            "{l}"
        );
        // signed: printed as the agent sent it, even with fields unset
        o.telemetry_signed = true;
        assert!(!telemetry_withheld(&o));
        // an agent older than lab PR 213 answers the unsigned status in full
        o.telemetry_signed = false;
        o.ringbuf_drops_total = Some(0);
        assert!(!telemetry_withheld(&o));
    }

    /// External audit NET-017 (lab PR 207): `net status` says what the DoT
    /// and QUIC rows mean, splits the resolver's DoT from the others', and
    /// says DoH is not counted.
    #[test]
    fn net_status_reports_the_encrypted_flows() {
        let mut o = outcome(None, None, None);
        let l = encrypted_flow_lines(&o);
        assert_eq!(l.len(), 3);
        assert!(l[0].starts_with("DNS over TLS rows (TCP/853)           : (agent predates"));
        assert!(l[1].contains("(agent predates the counter)"));
        assert!(l[2].starts_with("DNS over HTTPS") && l[2].contains("not counted"));
        o.net_dot_rows_total = Some(12);
        o.net_dot_rows_resolver = Some(10);
        o.net_quic_rows_total = Some(40);
        let l = encrypted_flow_lines(&o);
        assert!(
            l[0].contains(": 12 since boot — 10 by the local resolver")
                && l[0].contains("2 by other processes")
                && l[0].contains("no DNS rule reads"),
            "{}",
            l[0]
        );
        assert!(l[1].contains(": 40 since boot — HTTP/3"), "{}", l[1]);
        o.net_dot_rows_total = Some(0);
        o.net_quic_rows_total = Some(0);
        let l = encrypted_flow_lines(&o);
        assert!(l[0].ends_with(": 0 since boot") && l[1].ends_with(": 0 since boot"));
        // A resolver count above the total (never sent) does not underflow.
        o.net_dot_rows_total = Some(1);
        o.net_dot_rows_resolver = Some(5);
        assert!(encrypted_flow_lines(&o)[0].contains("1 by the local resolver"));
    }

    /// Lab PR 164: occupancy, and the forgotten sockets once beyond capacity.
    #[test]
    fn net_status_reports_the_kernel_socket_map() {
        let l = flow_sock_line(&outcome(Some(6_553), Some(65_536), Some(0)));
        assert!(
            l.contains("6553 sockets without their close yet, of 65536 (9 %)"),
            "{l}"
        );
        assert!(!l.contains("forgotten"));
        let l = flow_sock_line(&outcome(Some(70_000), Some(65_536), Some(4_464)));
        assert!(
            l.contains("(100 %)") && l.contains("at least 4464 forgotten"),
            "{l}"
        );
        let l = flow_sock_line(&outcome(None, None, None));
        assert!(l.contains("unknown"), "{l}");
    }

    /// External audit CMB-018 (lab PR 193): `nn-admin status` tells an
    /// enforcing agent from a detect-only one and names the source.
    #[test]
    fn status_shows_the_response_mode_and_its_source() {
        let mut o = outcome(None, None, None);
        o.detect_only = Some(true);
        o.detect_only_source = Some("NN_DETECT_ONLY=1".to_string());
        let l = response_mode_line(&o, false);
        assert!(
            l.contains("DETECT-ONLY (NN_DETECT_ONLY=1)") && l.contains("no response action"),
            "{l}"
        );
        o.detect_only = Some(false);
        o.detect_only_source = None;
        assert!(response_mode_line(&o, false).ends_with(": enforcing"));
        o.detect_only = None;
        assert!(response_mode_line(&o, false).contains("not reported"));
    }

    /// External audit CMB-027 (lab PR 193): what the signed audit log lacks.
    #[test]
    fn status_shows_the_unrecorded_combat_transitions() {
        let mut o = outcome(None, None, None);
        assert!(combat_evidence_line(&o, false).contains("not reported"));
        o.combat_evidence_unrecorded = Some(0);
        o.combat_evidence_pending = Some(0);
        o.combat_evidence_dropped = Some(0);
        assert!(combat_evidence_line(&o, false).contains("complete"));
        o.combat_evidence_unrecorded = Some(3);
        o.combat_evidence_pending = Some(1);
        let l = combat_evidence_line(&o, false);
        assert!(
            l.contains("3 stage transition(s)")
                && l.contains("1 queued for a late write, 0 dropped"),
            "{l}"
        );
    }
}
