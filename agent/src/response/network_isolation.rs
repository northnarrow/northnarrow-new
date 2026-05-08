//! `FullNetworkIsolation` — host-wide network blackout.
//!
//! Installs an `nftables` ruleset that drops every packet on
//! `input` and `output` except: loopback, established/related
//! return traffic, and an explicit list of C2 endpoints (Tappa 5
//! ships an empty list — the real C2 lands in Tappa 13).
//!
//! Persistence: a flag file at
//! [`ExecutorConfig::isolation_flag_file`] survives agent restarts.
//! When the agent boots, if the flag exists it should re-apply the
//! ruleset before doing anything else (wired in Tappa 8 with the
//! crypto seal; for now [`is_engaged`] just reports the state).
//!
//! No live integration test runs in CI or local dev sessions — it
//! would cut the operator's SSH. The dry-run unit tests verify the
//! ruleset shape and the persistence-flag lifecycle.

use std::fs;
use std::io::ErrorKind;

use tracing::{info, warn};

use super::{block_outbound::nft_apply, config::ExecutorConfig, ExecutionOutcome};

/// Apply the isolation ruleset and write the persistence flag.
pub fn engage(cfg: &ExecutorConfig) -> ExecutionOutcome {
    if cfg.dry_run {
        info!("dry-run: would engage full network isolation");
        return ExecutionOutcome::NetworkIsolated;
    }

    if let Err(e) = nft_apply(&isolation_ruleset(cfg)) {
        warn!(error = %e, "failed to apply isolation ruleset");
        return ExecutionOutcome::Failed {
            pid: 0,
            errno: e.raw_os_error().unwrap_or(0),
        };
    }
    if let Err(e) = write_flag(cfg) {
        warn!(error = %e, "failed to write isolation flag");
        return ExecutionOutcome::Failed {
            pid: 0,
            errno: e.raw_os_error().unwrap_or(0),
        };
    }
    info!(c2 = ?cfg.c2_endpoints, "host network isolated");
    ExecutionOutcome::NetworkIsolated
}

/// Remove the ruleset (flush our table) and clear the flag. Used by
/// the integration test and by the future recovery CLI.
pub fn disengage(cfg: &ExecutorConfig) -> std::io::Result<()> {
    if cfg.dry_run {
        return Ok(());
    }
    let cleanup = format!("delete table inet {table}\n", table = cfg.nft_table);
    // `delete table` errors out if the table doesn't exist; tolerate
    // that case so disengage is idempotent.
    if let Err(e) = nft_apply(&cleanup) {
        warn!(error = %e, "delete table errored (likely not present)");
    }
    match fs::remove_file(&cfg.isolation_flag_file) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
    }
}

/// True if the persistence flag is on disk. Cheap fs check; no
/// kernel state inspection.
pub fn is_engaged(cfg: &ExecutorConfig) -> bool {
    cfg.isolation_flag_file.exists()
}

/// Build the full isolation ruleset. Pure function: easy to unit
/// test, easy to inspect in PR diffs.
pub fn isolation_ruleset(cfg: &ExecutorConfig) -> String {
    let mut rs = String::new();
    rs.push_str(&format!("add table inet {table}\n", table = cfg.nft_table));
    rs.push_str(&format!(
        "add chain inet {table} isolation_input {{ type filter hook input priority -100; policy drop; }}\n",
        table = cfg.nft_table
    ));
    rs.push_str(&format!(
        "add chain inet {table} isolation_output {{ type filter hook output priority -100; policy drop; }}\n",
        table = cfg.nft_table
    ));
    rs.push_str(&format!(
        "flush chain inet {table} isolation_input\n",
        table = cfg.nft_table
    ));
    rs.push_str(&format!(
        "flush chain inet {table} isolation_output\n",
        table = cfg.nft_table
    ));

    // INPUT: lo + ESTABLISHED,RELATED.
    rs.push_str(&format!(
        "add rule inet {table} isolation_input iif lo accept comment \"NN-iso lo-in\"\n",
        table = cfg.nft_table
    ));
    rs.push_str(&format!(
        "add rule inet {table} isolation_input ct state established,related accept comment \"NN-iso ctrack-in\"\n",
        table = cfg.nft_table
    ));

    // OUTPUT: lo + DNS to systemd-resolved + each C2 endpoint.
    rs.push_str(&format!(
        "add rule inet {table} isolation_output oif lo accept comment \"NN-iso lo-out\"\n",
        table = cfg.nft_table
    ));
    rs.push_str(&format!(
        "add rule inet {table} isolation_output ip daddr 127.0.0.53 udp dport 53 accept comment \"NN-iso local-DNS\"\n",
        table = cfg.nft_table
    ));
    for ep in &cfg.c2_endpoints {
        // `ep` is "addr:port"; nft wants them split.
        if let Some((addr, port)) = ep.rsplit_once(':') {
            rs.push_str(&format!(
                "add rule inet {table} isolation_output ip daddr {addr} tcp dport {port} accept comment \"NN-iso C2\"\n",
                table = cfg.nft_table
            ));
        }
    }
    rs
}

fn write_flag(cfg: &ExecutorConfig) -> std::io::Result<()> {
    if let Some(parent) = cfg.isolation_flag_file.parent() {
        if let Err(e) = fs::create_dir_all(parent) {
            if e.kind() != ErrorKind::AlreadyExists {
                return Err(e);
            }
        }
    }
    fs::write(&cfg.isolation_flag_file, b"engaged\n")?;
    set_root_only(&cfg.isolation_flag_file);
    Ok(())
}

/// Best-effort `chmod 0600` so a non-root account can't read the
/// flag's existence side-channel-style. Failure here is non-fatal.
fn set_root_only(path: &std::path::Path) {
    use std::os::unix::fs::PermissionsExt;
    if let Ok(meta) = fs::metadata(path) {
        let mut perms = meta.permissions();
        perms.set_mode(0o600);
        let _ = fs::set_permissions(path, perms);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn cfg_for(tmp: &TempDir) -> ExecutorConfig {
        let mut c = ExecutorConfig::for_test(tmp.path());
        c.dry_run = true;
        c
    }

    #[test]
    fn ruleset_blocks_input_and_output_by_default_and_allows_loopback() {
        let cfg = cfg_for(&TempDir::new().unwrap());
        let r = isolation_ruleset(&cfg);
        assert!(r.contains("isolation_input"));
        assert!(r.contains("isolation_output"));
        assert!(r.contains("policy drop"));
        assert!(r.contains("iif lo accept"));
        assert!(r.contains("oif lo accept"));
        assert!(r.contains("ct state established,related accept"));
    }

    #[test]
    fn ruleset_allows_explicit_c2_endpoints() {
        let mut cfg = cfg_for(&TempDir::new().unwrap());
        cfg.c2_endpoints = vec!["198.51.100.42:443".to_string()];
        let r = isolation_ruleset(&cfg);
        assert!(r.contains("ip daddr 198.51.100.42 tcp dport 443 accept"));
    }

    #[test]
    fn empty_c2_list_means_no_egress_at_all() {
        let cfg = cfg_for(&TempDir::new().unwrap());
        let r = isolation_ruleset(&cfg);
        assert!(!r.contains("tcp dport"), "no C2 → no tcp accept rules");
    }

    #[test]
    fn engage_dry_run_does_not_write_flag() {
        let tmp = TempDir::new().unwrap();
        let cfg = cfg_for(&tmp);
        let out = engage(&cfg);
        assert_eq!(out, ExecutionOutcome::NetworkIsolated);
        assert!(!is_engaged(&cfg));
    }

    #[test]
    fn flag_lifecycle_write_then_remove() {
        let tmp = TempDir::new().unwrap();
        let mut cfg = cfg_for(&tmp);
        cfg.dry_run = false;
        // Skip nft path: just exercise the flag write/clear directly.
        write_flag(&cfg).expect("write");
        assert!(is_engaged(&cfg));
        // Mode is 0600.
        use std::os::unix::fs::PermissionsExt;
        let mode = fs::metadata(&cfg.isolation_flag_file)
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600);
        // Tear down via direct fs op (mirrors what disengage() does
        // in dry_run = false but without invoking nft).
        fs::remove_file(&cfg.isolation_flag_file).unwrap();
        assert!(!is_engaged(&cfg));
    }
}
