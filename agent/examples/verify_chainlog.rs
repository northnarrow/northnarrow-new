//! Test/ops tool: verify an on-disk fim_drift chainlog end-to-end — every
//! sealed archive + the active file, across the terminator/meta-chain
//! boundaries (`verify_log_set`) — using the agent's signing key to recover
//! the verifying key. Confirms BUG-026's signed-chain integrity on the real
//! on-disk log.
//!
//!   sudo cargo run -p northnarrow-agent --example verify_chainlog -- \
//!       /var/lib/northnarrow/fim_drift.jsonl [/etc/northnarrow/agent.sig.key]
//!
//! Exits 0 + prints the `LogSetReport` on success; 1 + the error on failure.

use std::path::Path;

use northnarrow_agent::audit::AgentSigningKey;
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

    // The key already exists in production; `load_or_bootstrap` just loads it.
    let key = AgentSigningKey::load_or_bootstrap(Path::new(&key_path))
        .unwrap_or_else(|e| panic!("loading signing key {key_path}: {e:#}"));
    let pubkey = key.verifying_key();

    match verify_log_set::<FimDriftPayload>(Path::new(&active), &pubkey) {
        Ok(rep) => {
            println!(
                "VERIFY OK  active={active}  earliest_retained_seq={}  archives_verified={}  total_records={}",
                rep.earliest_retained_seq, rep.archives_verified, rep.total_records
            );
        }
        Err(e) => {
            eprintln!("VERIFY FAILED  active={active}\n  {e}");
            std::process::exit(1);
        }
    }
}
