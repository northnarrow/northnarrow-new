//! NorthNarrow control CLI.
//!
//! Tappa 0: subcommand skeleton only, and not shipped (the release
//! tarball and packages carry the agent, the watchdog and `nn-admin`).
//! The operator CLI is `nn-admin` (`nn-admin status`, `nn-admin unlock`,
//! …). External audit WDG-016 (NN-AUD-365): the stubs printed "Not
//! implemented yet" on stdout and exited 0, so a script calling
//! `northnarrow isolate` took it for done; each one now says so on stderr
//! and exits 69 (`EX_UNAVAILABLE`).

#![forbid(unsafe_code)]

use std::process::ExitCode;

use clap::{Parser, Subcommand};

/// `EX_UNAVAILABLE` (sysexits.h): the service the command asks for is
/// not there.
const EX_UNAVAILABLE: u8 = 69;

#[derive(Parser, Debug)]
#[command(
    name = "northnarrow",
    version,
    about = "NorthNarrow control CLI (not implemented: use nn-admin)",
    long_about = None,
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Show the agent's current status (not implemented: `nn-admin status`).
    Status,
    /// List recent alerts produced by the decision engine (not implemented).
    Alerts,
    /// Force network isolation on this host (not implemented).
    Isolate,
    /// Recover a host from supervised isolation using a signed token (not
    /// implemented: `nn-admin unlock`).
    Recover,
}

impl Command {
    fn name(&self) -> &'static str {
        match self {
            Command::Status => "status",
            Command::Alerts => "alerts",
            Command::Isolate => "isolate",
            Command::Recover => "recover",
        }
    }
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    eprintln!(
        "northnarrow {}: not implemented; nothing was done (the operator CLI is nn-admin)",
        cli.command.name()
    );
    ExitCode::from(EX_UNAVAILABLE)
}
