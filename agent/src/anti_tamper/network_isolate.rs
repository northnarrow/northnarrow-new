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

/// `iptables` lookup name. Used by [`NetworkIsolator::release`] to
/// undo what `iptables-restore` applied. Same PATH-resolution
/// rationale as [`DEFAULT_RESTORE_BIN`].
const DEFAULT_IPTABLES_BIN: &str = "iptables";

/// Name of the chain that `configs/combat-rules.v4` creates.
#[allow(dead_code)]
const COMBAT_CHAIN: &str = "NORTHNARROW_COMBAT";

/// Capability token proving that an Ed25519-signed admin unlock has
/// been verified. The only way to construct one is via
/// [`mint_unlock_token`], which is `pub(in crate::anti_tamper)` —
/// callers outside this module subtree cannot mint a token, so they
/// cannot call [`NetworkIsolator::release`]. The type-system makes
/// the capability requirement non-bypassable.
///
/// `_private: ()` is a zero-sized private field; outside the
/// defining module, `UnlockToken { _private: () }` will not compile
/// (E0451: field `_private` is private).
#[derive(Debug)]
pub struct UnlockToken {
    _private: (),
}

/// Mint a fresh [`UnlockToken`]. Intentionally `pub(in
/// crate::anti_tamper)` so only sibling modules under `anti_tamper`
/// (notably `admin_auth.rs`, landing in a later commit) can mint
/// one. `main.rs`, the posture machine, and any external caller
/// cannot.
#[allow(
    dead_code,
    reason = "minted from admin_auth in commit #6 once the Ed25519 verify pipeline lands"
)]
pub(in crate::anti_tamper) fn mint_unlock_token() -> UnlockToken {
    UnlockToken { _private: () }
}

/// COMBAT-state network isolator. Cheap to construct (no I/O beyond
/// a path-exists check); the expensive work happens in
/// [`Self::engage`].
#[derive(Debug)]
pub struct NetworkIsolator {
    is_isolated: AtomicBool,
    rules_path: PathBuf,
    restore_bin: PathBuf,
    #[allow(dead_code)]
    iptables_bin: PathBuf,
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
            iptables_bin: PathBuf::from(DEFAULT_IPTABLES_BIN),
        })
    }

    /// Test-only constructor that lets unit tests substitute benign
    /// binaries for the real `iptables-restore` / `iptables`. Tests
    /// commonly pass `/usr/bin/cat` (drains stdin, exits 0) for
    /// `restore_bin` and `/bin/true` (exits 0 unconditionally) for
    /// `iptables_bin`, exercising the success path without root or
    /// real firewall side effects.
    #[cfg(test)]
    fn new_with_bin(
        rules_path: PathBuf,
        restore_bin: PathBuf,
        iptables_bin: PathBuf,
    ) -> Result<Self> {
        Ok(Self {
            is_isolated: AtomicBool::new(false),
            rules_path,
            restore_bin,
            iptables_bin,
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

    /// Tear down the combat ruleset. Requires a verified
    /// [`UnlockToken`] — the type system enforces that this method
    /// can only be reached via the Ed25519 admin path.
    ///
    /// `pub(crate)` because the agent crate's own admin pipeline is
    /// the only legitimate caller. The spec snippet `iptables -F &&
    /// iptables -X` is incomplete: `-X` refuses to remove a chain
    /// still referenced from `INPUT`/`OUTPUT`/`FORWARD`, so we delete
    /// the jump rules in those base chains first. Each command
    /// tolerates "rule does not exist" / "no chain by that name"
    /// stderr so calling `release()` on an already-released
    /// isolator is a no-op rather than an error.
    /// Promoted from `pub(crate)` in commit #2 to `pub` here so the
    /// binary crate (`main.rs`) can construct the
    /// `combat_release_hook` closure. The capability invariant is
    /// unchanged: `release` requires an [`UnlockToken`] by value and
    /// `mint_unlock_token` is still `pub(in crate::anti_tamper)`,
    /// so no external caller can fabricate a token to slip past this.
    pub fn release(&self, _: UnlockToken) -> Result<()> {
        for base in ["INPUT", "OUTPUT", "FORWARD"] {
            run_iptables_idempotent(&self.iptables_bin, &["-D", base, "-j", COMBAT_CHAIN])
                .with_context(|| format!("removing {COMBAT_CHAIN} jump from {base}"))?;
        }
        run_iptables_idempotent(&self.iptables_bin, &["-F", COMBAT_CHAIN])
            .with_context(|| format!("flushing chain {COMBAT_CHAIN}"))?;
        run_iptables_idempotent(&self.iptables_bin, &["-X", COMBAT_CHAIN])
            .with_context(|| format!("deleting chain {COMBAT_CHAIN}"))?;
        self.is_isolated.store(false, Ordering::SeqCst);
        info!(target: "anti_tamper.network_isolation.released", "COMBAT: network isolation released");
        Ok(())
    }

    pub fn is_engaged(&self) -> bool {
        self.is_isolated.load(Ordering::SeqCst)
    }
}

/// Run `iptables` with `args` and treat non-zero exits as success
/// when stderr indicates the rule or chain was already absent. This
/// makes [`NetworkIsolator::release`] idempotent without needing a
/// separate "is this chain present?" probe per command.
#[allow(dead_code)]
fn run_iptables_idempotent(bin: &Path, args: &[&str]) -> Result<()> {
    let output = Command::new(bin)
        .args(args)
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .output()
        .with_context(|| format!("spawning {} {}", bin.display(), args.join(" ")))?;
    if output.status.success() {
        return Ok(());
    }
    let stderr = String::from_utf8_lossy(&output.stderr);
    // `iptables -D` emits this when the rule is already gone:
    //   "iptables: Bad rule (does a matching rule exist in that chain?)."
    // `iptables -F`/`-X` emits this when the chain is already gone:
    //   "iptables: No chain/target/match by that name."
    if stderr.contains("does a matching rule exist") || stderr.contains("No chain/target/match") {
        return Ok(());
    }
    Err(anyhow!(
        "{} {} exited {}: {}",
        bin.display(),
        args.join(" "),
        output.status,
        stderr.trim()
    ))
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

    /// Convenience: build a NetworkIsolator with `/usr/bin/cat` for
    /// the restore side and `/bin/true` for the iptables side — the
    /// "success path" mock used by most tests.
    fn mock_success_isolator() -> Option<NetworkIsolator> {
        let cat = PathBuf::from("/usr/bin/cat");
        let truebin = PathBuf::from("/bin/true");
        if !cat.exists() || !truebin.exists() {
            eprintln!("/usr/bin/cat or /bin/true missing; skipping");
            return None;
        }
        Some(NetworkIsolator::new_with_bin(combat_rules_path(), cat, truebin).unwrap())
    }

    #[test]
    fn engage_is_idempotent_with_mock_bin() {
        // /usr/bin/cat reads stdin to EOF and exits 0 — a faithful
        // stand-in for iptables-restore minus the actual firewall side
        // effects.
        let iso = match mock_success_isolator() {
            Some(i) => i,
            None => return,
        };
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
        let iso =
            NetworkIsolator::new_with_bin(combat_rules_path(), bin, PathBuf::from("/bin/true"))
                .unwrap();
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
    fn release_signature_requires_unlock_token() {
        // Compile-time assertion: `release` takes `UnlockToken` by
        // value. If the signature ever drifts (e.g. someone weakens
        // the cap requirement to `bool` or `&str`), this coercion
        // fails to type-check and the build breaks.
        let _: fn(&NetworkIsolator, UnlockToken) -> Result<()> = NetworkIsolator::release;
    }

    #[test]
    fn release_clears_engaged_state() {
        let iso = match mock_success_isolator() {
            Some(i) => i,
            None => return,
        };
        iso.engage().expect("engage");
        assert!(iso.is_engaged());
        iso.release(mint_unlock_token()).expect("release");
        assert!(!iso.is_engaged(), "release must clear is_isolated");
    }

    #[test]
    fn release_is_idempotent() {
        let iso = match mock_success_isolator() {
            Some(i) => i,
            None => return,
        };
        iso.engage().expect("engage");
        iso.release(mint_unlock_token()).expect("first release");
        // Calling release a second time on a no-op state must also
        // succeed — /bin/true returns 0 unconditionally, so we're
        // really testing that we don't panic / double-error here.
        iso.release(mint_unlock_token()).expect("second release");
        assert!(!iso.is_engaged());
    }

    #[test]
    fn release_propagates_iptables_failure_other_than_missing_rule() {
        // /bin/false produces empty stderr and exits 1, which is NOT
        // the "doesn't exist" pattern run_iptables_idempotent swallows.
        // release() must surface the failure.
        let bin = PathBuf::from("/bin/false");
        if !bin.exists() {
            eprintln!("/bin/false missing; skipping");
            return;
        }
        let iso =
            NetworkIsolator::new_with_bin(combat_rules_path(), PathBuf::from("/usr/bin/cat"), bin)
                .unwrap();
        let err = iso.release(mint_unlock_token()).unwrap_err();
        // The first `iptables -D INPUT …` call fails; the wrap is
        // "removing NORTHNARROW_COMBAT jump from INPUT".
        assert!(
            err.to_string().contains("NORTHNARROW_COMBAT"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn unlock_token_is_zero_sized() {
        // The capability has zero runtime cost — it exists purely to
        // gate `release` at the type system. Asserting the size keeps
        // future refactors from accidentally growing it.
        assert_eq!(std::mem::size_of::<UnlockToken>(), 0);
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
