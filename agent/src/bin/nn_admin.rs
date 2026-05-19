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
//!   (NEW in Tappa 8 A9 per design §5.3)
//!
//! Air-gapped split flow (`unlock --request-only` writing a
//! challenge file, plus a separate `nn-admin sign` offline) is on
//! the V1.1 roadmap. Today only the inline `unlock --key <PATH>`
//! shape is supported; see the --help text on the unlock subcommand.

use std::io::IsTerminal;
use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};

use northnarrow_agent::admin_cli::{
    load_audit_pubkey, run_audit_read, run_audit_verify, run_force_posture, run_init,
    run_shutdown, run_status, run_unlock, run_verify_keys, AuditVerifyOutcome,
    ForcePostureOutcome, ShutdownOutcome, StatusOutcome, UnlockOutcome, VerifyKeysOutcome,
};

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

    /// Sign a server-issued challenge and submit the result.
    ///
    /// V1.1 will add a split offline flow; for now this command
    /// must run on a host with both the private key and a route
    /// to the agent's admin socket.
    Unlock {
        /// Path to the hex-encoded private key file written by
        /// `nn-admin init`.
        #[arg(long)]
        key: PathBuf,
        #[arg(long, default_value = DEFAULT_SOCKET)]
        socket: PathBuf,
    },

    /// Print current posture + network isolation state. Add --json
    /// to get a machine-readable response for scripting.
    Status {
        #[arg(long, default_value = DEFAULT_SOCKET)]
        socket: PathBuf,
        #[arg(long)]
        json: bool,
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
    /// admin keys, each with the `shutdown` role (per admin.pub
    /// allowlist). Same key for both args fails server-side as
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
        /// (co-signer). The quorum verify requires distinct
        /// fingerprints — passing the same key as both arms
        /// will be rejected by the agent.
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
    /// line for that key MUST include the `force-posture` role.
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
enum AuditCmd {
    /// Stream the audit log to stdout, optionally filtered by
    /// timestamp. Default output is a compact human-readable
    /// summary; `--json` emits one canonical JSON object per line
    /// (matches the on-disk JSONL exactly).
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
    /// [`northnarrow_agent::audit::verify_chain`]. Loads the
    /// verifying key either from `--agent-pubkey <hex>` (off-host
    /// verification with the pubkey conveyed out-of-band) or from
    /// the local `--agent-sig-key <path>` (default
    /// /etc/northnarrow/agent.sig.key — zero-config on the agent
    /// host, requires sudo to read the mode-0400 file).
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
    },
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
        Cmd::Unlock { key, socket } => match run_unlock(&socket, &key) {
            Ok(outcome) => exit_from_unlock(outcome),
            Err(e) => {
                eprintln!("unlock: {e:#}");
                ExitCode::from(5)
            }
        },
        Cmd::Status { socket, json } => match run_status(&socket) {
            Ok(out) => {
                print_status(&out, json);
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("status: {e:#}");
                ExitCode::from(5)
            }
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
        Cmd::Audit {
            sub: AuditCmd::Read { path, since, json },
        } => match run_audit_read(&path, since.as_deref(), json) {
            Ok(n) => {
                // Summary goes to stderr so `audit read --json |
                // jq` keeps a clean JSONL stream on stdout. Match
                // the `audit: ...` prefix convention from §5.3.
                eprintln!("audit: {n} entries read from {}", path.display());
                ExitCode::SUCCESS
            }
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
                },
        } => match load_audit_pubkey(agent_pubkey.as_deref(), &agent_sig_key) {
            Ok(pubkey) => match run_audit_verify(&from, &pubkey) {
                Ok(AuditVerifyOutcome::Success { entries }) => {
                    println!(
                        "audit: {entries} entries, hash chain intact, all sigs valid"
                    );
                    ExitCode::SUCCESS
                }
                Ok(AuditVerifyOutcome::ChainBroken(err)) => {
                    eprintln!("audit: chain broken — {err}");
                    // Exit code 8 per design §5.3: "audit
                    // verification failed (hash chain broken)".
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
                    &format!(
                        "force-posture: rate limited; retry after {retry_after_secs}s"
                    ),
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
                     `force-posture` role in admin.pub — add it to the line's \
                     role list, e.g. `<hex>  force-posture,unlock`)",
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
                colorize(
                    "shutdown: 2 signatures collected; quorum met",
                    "32",
                    tty
                )
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
                    &format!(
                        "shutdown: rate limited; retry after {retry_after_secs}s"
                    ),
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

fn exit_from_unlock(outcome: UnlockOutcome) -> ExitCode {
    let tty = std::io::stdout().is_terminal();
    match outcome {
        UnlockOutcome::Success => {
            println!("{}", colorize("unlock: success", "32", tty));
            ExitCode::SUCCESS
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
    }
}

fn print_status(out: &StatusOutcome, json: bool) {
    if json {
        // Hand-rolled JSON to avoid a serde_json dep at the binary
        // surface; the fields are stable and trivially escapable.
        println!(
            "{{\"posture\":\"{:?}\",\"network_isolation_engaged\":{},\"last_admin_action_secs_ago\":{}}}",
            out.posture,
            out.network_isolation_engaged,
            match out.last_admin_action_secs_ago {
                Some(s) => s.to_string(),
                None => "null".to_string(),
            }
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
    println!("network isolation : {iso}");
    match out.last_admin_action_secs_ago {
        Some(s) => println!("last admin action : {s}s ago"),
        None => println!("last admin action : (none since agent start)"),
    }
}

fn print_verify_keys(out: &VerifyKeysOutcome) -> ExitCode {
    if out.fingerprints.is_empty() {
        eprintln!("verify-keys: no valid pub keys installed");
        return ExitCode::from(1);
    }
    println!("verify-keys: {} valid key(s)", out.fingerprints.len());
    for fp in &out.fingerprints {
        println!("  {fp}");
    }
    ExitCode::SUCCESS
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
