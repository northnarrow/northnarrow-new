//! Test/ops tool: verify an on-disk fim_drift chainlog end-to-end — every
//! sealed archive + the active file, across the terminator/meta-chain
//! boundaries (`verify_log_set`). Superseded by `nn-admin chain verify`
//! (external audit NN-AUD-112, lab PR 160), which covers every chain; kept
//! for development. Reads the published public half (`agent.sig.pub` next
//! to the key path), never the private key, and never mints one. That
//! public half is the host's own: to verify against a key kept off the
//! host, use `nn-admin chain verify --log fim-drift --agent-pubkey <hex>`.
//!
//! Build it as yourself and run only the built binary as root (external
//! audit WDG-R11, NN-AUD-377): a `cargo` run under `sudo` compiles, and
//! runs the build scripts of the whole dependency graph, as root.
//!
//!   cargo build --release -p northnarrow-agent --example verify_chainlog
//!   sudo ./target/release/examples/verify_chainlog \
//!       /var/lib/northnarrow/fim_drift.jsonl [/etc/northnarrow/agent.sig.key]
//!
//! Exits 0 + prints the `LogSetReport` on success; 1 + the error on failure.

use std::path::Path;

use northnarrow_agent::chainlog::verify_log_set;
use northnarrow_agent::fim::drain::FimDriftPayload;

fn main() {
    let mut args = std::env::args().skip(1);
    let active = args
        .next()
        .expect("usage: verify_chainlog <active_path> [signing_key_path]");
    let key_path = args
        .next()
        .unwrap_or_else(|| "/etc/northnarrow/agent.sig.key".to_string());

    let pub_path = northnarrow_agent::audit::verifying_key_path(Path::new(&key_path));
    let pubkey = northnarrow_agent::audit::read_verifying_key(&pub_path)
        .unwrap_or_else(|e| panic!("reading {}: {e:#}", pub_path.display()));

    match verify_log_set::<FimDriftPayload>(Path::new(&active), &pubkey) {
        Ok(rep) => {
            println!(
                "VERIFY OK  active={active}  earliest_retained_seq={}  archives_verified={}  total_records={}  checkpoints_verified={}",
                rep.earliest_retained_seq, rep.archives_verified, rep.total_records, rep.checkpoints_verified
            );
        }
        Err(e) => {
            eprintln!("VERIFY FAILED  active={active}\n  {e}");
            std::process::exit(1);
        }
    }
}
