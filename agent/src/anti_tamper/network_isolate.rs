//! COMBAT-state network isolation (Tappa 7 task 7 / Tappa 8).
//!
//! On COMBAT entry the [`PostureMachine`](crate::posture::PostureMachine)
//! fires a hook that invokes [`NetworkIsolator::engage`], which shells
//! out to `iptables-restore` with the pre-built ruleset at
//! `configs/combat-rules.v4`. The ruleset drops every packet on
//! `INPUT`, `OUTPUT`, and `FORWARD` except loopback — there is
//! intentionally no management-port carve-out, so recovery requires
//! physical access plus an Ed25519-signed admin unlock (see
//! `admin_auth.rs`, landing in a later commit).
//!
//! `release()` is omitted from this commit; it ships alongside the
//! [`UnlockToken`] capability type so the API can only be used by
//! code that proved a signature first.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};

use anyhow::{anyhow, Context, Result};
use tracing::info;

/// `iptables-restore` lookup name. Resolved via `PATH` by
/// [`std::process::Command`]; we do not pin an absolute path because
/// Ubuntu / Debian / Alpine all install it under different prefixes
/// (`/usr/sbin/` vs `/sbin/`).
const DEFAULT_RESTORE_BIN: &str = "iptables-restore";

/// COMBAT-state network isolator. Cheap to construct (no I/O beyond
/// a path-exists check); the expensive work happens in
/// [`Self::engage`].
#[derive(Debug)]
pub struct NetworkIsolator {
    is_isolated: AtomicBool,
    rules_path: PathBuf,
    restore_bin: PathBuf,
}

impl NetworkIsolator {
    /// Build an isolator that will apply `rules_path` via the
    /// system's `iptables-restore`. Fails fast if the ruleset is
    /// missing — we want the agent to refuse to start rather than
    /// reach COMBAT and discover the ruleset has been deleted.
    pub fn new(rules_path: PathBuf) -> Result<Self> {
        if !rules_path.exists() {
            return Err(anyhow!("combat ruleset {} not found", rules_path.display()));
        }
        Ok(Self {
            is_isolated: AtomicBool::new(false),
            rules_path,
            restore_bin: PathBuf::from(DEFAULT_RESTORE_BIN),
        })
    }

    /// Test-only constructor that lets unit tests substitute a benign
    /// binary (e.g. `/usr/bin/cat`) for `iptables-restore`, so
    /// engagement can be exercised without root or real firewall
    /// changes.
    #[cfg(test)]
    fn new_with_bin(rules_path: PathBuf, restore_bin: PathBuf) -> Result<Self> {
        Ok(Self {
            is_isolated: AtomicBool::new(false),
            rules_path,
            restore_bin,
        })
    }

    /// Apply the combat ruleset. Idempotent: re-engaging shells out
    /// again, which is intentional — if an attacker has flushed
    /// iptables between our calls, re-asserting the ruleset is
    /// exactly what we want.
    pub fn engage(&self) -> Result<()> {
        run_iptables_restore(&self.restore_bin, &self.rules_path)
            .context("iptables-restore failed during COMBAT engage")?;
        self.is_isolated.store(true, Ordering::SeqCst);
        info!(
            rules = %self.rules_path.display(),
            "COMBAT: network isolated (loopback only)"
        );
        Ok(())
    }

    pub fn is_engaged(&self) -> bool {
        self.is_isolated.load(Ordering::SeqCst)
    }
}

/// Spawn `bin`, pipe the contents of `rules` to its stdin, and treat
/// a non-zero exit as a hard failure.
fn run_iptables_restore(bin: &Path, rules: &Path) -> Result<()> {
    use std::io::Write;
    let rules_data =
        std::fs::read(rules).with_context(|| format!("reading {}", rules.display()))?;

    let mut child = Command::new(bin)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .with_context(|| format!("spawning {}", bin.display()))?;

    {
        let stdin = child
            .stdin
            .as_mut()
            .ok_or_else(|| anyhow!("failed to capture {} stdin", bin.display()))?;
        // `iptables-restore` reads everything from stdin then exits.
        // A non-reading mock (e.g. `true`) would EPIPE here; we use
        // `cat` in tests precisely because it drains stdin reliably.
        stdin
            .write_all(&rules_data)
            .with_context(|| format!("writing ruleset to {} stdin", bin.display()))?;
    }

    let output = child
        .wait_with_output()
        .with_context(|| format!("waiting for {}", bin.display()))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(anyhow!(
            "{} exited {}: {}",
            bin.display(),
            output.status,
            stderr.trim()
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Absolute path to `configs/combat-rules.v4` in the repo. Tests
    /// run with `CARGO_MANIFEST_DIR` set to the agent crate root.
    fn combat_rules_path() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("configs")
            .join("combat-rules.v4")
    }

    #[test]
    fn rejects_missing_rules_file() {
        let err = NetworkIsolator::new(PathBuf::from("/nonexistent/combat-rules.v4")).unwrap_err();
        assert!(
            err.to_string().contains("not found"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn engage_is_idempotent_with_mock_bin() {
        // /usr/bin/cat reads stdin to EOF and exits 0 — a faithful
        // stand-in for iptables-restore minus the actual firewall side
        // effects. Skip the test on hosts that don't have cat (none
        // we ship on, but defensive).
        let cat = PathBuf::from("/usr/bin/cat");
        if !cat.exists() {
            eprintln!("/usr/bin/cat missing; skipping");
            return;
        }
        let iso = NetworkIsolator::new_with_bin(combat_rules_path(), cat).unwrap();
        assert!(!iso.is_engaged(), "fresh isolator must not be engaged");
        iso.engage().expect("first engage");
        assert!(iso.is_engaged());
        // Second engage: still Ok, still engaged. Idempotent at the
        // observable-state level.
        iso.engage().expect("second engage");
        assert!(iso.is_engaged());
    }

    #[test]
    fn engage_propagates_non_zero_exit() {
        // /bin/false exits 1 with no stdin behaviour we depend on;
        // engage() must surface the failure.
        let bin = PathBuf::from("/bin/false");
        if !bin.exists() {
            eprintln!("/bin/false missing; skipping");
            return;
        }
        let iso = NetworkIsolator::new_with_bin(combat_rules_path(), bin).unwrap();
        let err = iso.engage().unwrap_err();
        assert!(
            err.to_string().contains("iptables-restore failed"),
            "unexpected error: {err}"
        );
        assert!(
            !iso.is_engaged(),
            "engaged flag must stay false after failure"
        );
    }

    #[test]
    fn combat_rules_v4_parses_with_iptables_restore() {
        // Acceptance criterion #6: `iptables-restore --test` accepts
        // our ruleset. Gated on the binary being installed so a
        // dev machine without iptables doesn't fail the suite.
        let bin = "iptables-restore";
        if Command::new(bin).arg("--version").output().is_err() {
            eprintln!("{bin} not installed; skipping syntax check");
            return;
        }
        let rules = std::fs::read(combat_rules_path()).expect("reading configs/combat-rules.v4");
        let mut child = Command::new(bin)
            .arg("--test")
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn iptables-restore --test");
        use std::io::Write;
        child
            .stdin
            .as_mut()
            .unwrap()
            .write_all(&rules)
            .expect("write rules");
        let output = child.wait_with_output().expect("wait");
        if !output.status.success() {
            // Non-zero with no permission error = real syntax bug.
            // Permission errors (no NET_ADMIN, no root) trip a
            // recognisable substring; treat those as skip.
            let stderr = String::from_utf8_lossy(&output.stderr);
            if stderr.contains("Permission denied") || stderr.contains("must be run as root") {
                eprintln!("iptables-restore needs privileges; skipping: {stderr}");
                return;
            }
            panic!(
                "iptables-restore --test rejected combat-rules.v4: status={} stderr={}",
                output.status, stderr
            );
        }
    }
}
