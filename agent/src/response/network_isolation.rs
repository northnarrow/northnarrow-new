//! External audit CMB-006: the retired `FullNetworkIsolation` blackout.
//!
//! Until CMB-006 this module installed a host-wide isolation of its own: a
//! pair of nftables chains (`isolation_input` / `isolation_output`, policy
//! drop) in the agent's table, reachable from an ADE verdict. It had no
//! management carve-out (and no established-traffic rule on output, so an
//! operator's open SSH session died too), no release verb and no status
//! line; nothing re-read its flag at boot. Host-wide isolation is the
//! COMBAT ladder's alone ([`crate::anti_tamper::network_isolate`]), and the
//! executor refuses the action. What remains is the cleanup of what an
//! older agent may have left: the two chains — the per-process blocks
//! share the table and stay — and the flag file.

use std::fs;
use std::io::ErrorKind;
use std::process::{Command, Stdio};

use super::{block_outbound::nft_apply, config::ExecutorConfig};

/// The chains the retired blackout installed in the agent's table.
const LEGACY_CHAINS: [&str; 2] = ["isolation_input", "isolation_output"];

/// Remove the retired blackout's chains and flag file, if an older agent
/// left them. `Ok(true)` when something was removed. Recovery, not a
/// response: it runs in detect-only mode too.
pub fn retire_legacy(cfg: &ExecutorConfig) -> std::io::Result<bool> {
    let mut removed = false;
    for chain in LEGACY_CHAINS {
        if chain_exists(&cfg.nft_table, chain) {
            nft_apply(&legacy_cleanup_script(&cfg.nft_table, chain))?;
            removed = true;
        }
    }
    // The flag itself is inert (nothing ever read it), and the state
    // directory is immutable while the agent runs: a flag that cannot go
    // is reported, not a failure of the cleanup.
    match fs::remove_file(&cfg.isolation_flag_file) {
        Ok(()) => removed = true,
        Err(e) if e.kind() == ErrorKind::NotFound => {}
        Err(e) => tracing::warn!(
            path = %cfg.isolation_flag_file.display(),
            error = %e,
            "the retired isolation's flag file could not be removed (inert)"
        ),
    }
    Ok(removed)
}

/// `nft` script removing one legacy chain (a base chain must be emptied
/// before it is deleted).
fn legacy_cleanup_script(table: &str, chain: &str) -> String {
    format!("flush chain inet {table} {chain}\ndelete chain inet {table} {chain}\n")
}

fn chain_exists(table: &str, chain: &str) -> bool {
    Command::new("nft")
        .args(["list", "chain", "inet", table, chain])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn the_cleanup_removes_only_the_isolation_chains() {
        let s = legacy_cleanup_script("northnarrow", "isolation_output");
        assert_eq!(
            s,
            "flush chain inet northnarrow isolation_output\n\
             delete chain inet northnarrow isolation_output\n"
        );
        assert!(
            !s.contains("delete table"),
            "the per-process blocks share the table"
        );
    }

    #[test]
    fn a_left_flag_file_is_removed_once() {
        let tmp = TempDir::new().unwrap();
        let mut cfg = ExecutorConfig::for_test(tmp.path());
        // a table no host has: no chain to find
        cfg.nft_table = "northnarrow_test_absent".into();
        fs::write(&cfg.isolation_flag_file, b"").unwrap();
        assert!(retire_legacy(&cfg).unwrap());
        assert!(!cfg.isolation_flag_file.exists());
        assert!(!retire_legacy(&cfg).unwrap(), "nothing left");
    }
}
