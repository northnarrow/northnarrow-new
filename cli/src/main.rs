//! NorthNarrow control CLI.
//!
//! Tappa 0: subcommand skeleton only. Real wiring lands as Tappe 7-8
//! deliver the daemon control plane and the supervised-recovery flow.

#![forbid(unsafe_code)]

use clap::{Parser, Subcommand};

#[derive(Parser, Debug)]
#[command(
    name = "northnarrow",
    version,
    about = "NorthNarrow control CLI",
    long_about = None,
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Show the agent's current status.
    Status,
    /// List recent alerts produced by the decision engine.
    Alerts,
    /// Force network isolation on this host.
    Isolate,
    /// Recover a host from supervised isolation using a signed token.
    Recover,
}

fn main() {
    let cli = Cli::parse();
    match cli.command {
        Command::Status => println!("status: Not implemented yet"),
        Command::Alerts => println!("alerts: Not implemented yet"),
        Command::Isolate => println!("isolate: Not implemented yet"),
        Command::Recover => println!("recover: Not implemented yet"),
    }
}
