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
//! - 2  unlock: server rejected the signature
//! - 3  unlock: server reports no pending challenge
//! - 4  unlock: rate-limited (retry_after_secs printed)
//! - 5  unlock or status: transport / protocol failure
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
    run_init, run_status, run_unlock, run_verify_keys, StatusOutcome, UnlockOutcome,
    VerifyKeysOutcome,
};

const DEFAULT_SOCKET: &str = "/run/northnarrow/admin.sock";
const DEFAULT_PUB_PATH: &str = "/etc/northnarrow/admin.pub";

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

    /// Debug-only: force the agent's posture state machine into a
    /// chosen state. Only compiled when the `debug-trigger` Cargo
    /// feature is on.
    #[cfg(feature = "debug-trigger")]
    Debug {
        #[command(subcommand)]
        sub: DebugCmd,
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
