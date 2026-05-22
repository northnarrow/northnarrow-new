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
use tracing::{info, warn};

use super::combat_allow;

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
const COMBAT_CHAIN: &str = "NORTHNARROW_COMBAT";

/// Marker line in `configs/combat-rules.v4` that [`NetworkIsolator::engage`]
/// replaces with the management carve-out ACCEPT rules (Beta Step 4b).
/// Placed inside the chain, immediately before its catch-all DROP.
const CARVE_OUT_MARKER: &str = "# >>> NORTHNARROW_MGMT_CARVEOUT <<<";

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
    /// Beta Step 4b: opt-in management carve-out CIDR list, re-read at
    /// every `engage()` (never cached) so an operator can add an
    /// emergency CIDR from a local console mid-COMBAT.
    allow_cidrs_path: PathBuf,
    restore_bin: PathBuf,
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
            allow_cidrs_path: combat_allow::default_path(),
            restore_bin: PathBuf::from(DEFAULT_RESTORE_BIN),
            iptables_bin: PathBuf::from(DEFAULT_IPTABLES_BIN),
        })
    }

    /// Override the management carve-out CIDR file path (Beta Step 4b).
    /// `main.rs` wires this from `--combat-allow-cidrs`.
    pub fn with_allow_cidrs_path(mut self, path: PathBuf) -> Self {
        self.allow_cidrs_path = path;
        self
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
            allow_cidrs_path: combat_allow::default_path(),
            restore_bin,
            iptables_bin,
        })
    }

    /// Apply the combat ruleset. Idempotent: re-engaging shells out
    /// again, which is intentional — if an attacker has flushed
    /// iptables between our calls, re-asserting the ruleset is
    /// exactly what we want.
    pub fn engage(&self) -> Result<()> {
        let (ruleset, carved) = self.build_engaged_ruleset()?;
        run_iptables_restore_data(&self.restore_bin, ruleset.as_bytes())
            .context("iptables-restore failed during COMBAT engage")?;
        self.is_isolated.store(true, Ordering::SeqCst);
        if carved.is_empty() {
            info!(
                rules = %self.rules_path.display(),
                "COMBAT: network isolated (loopback only)"
            );
        } else {
            // WARN so the carve-out is conspicuous in the audit trail:
            // these CIDRs survive isolation, which is exactly the kind
            // of thing an operator reviewing a COMBAT event must see.
            warn!(
                rules = %self.rules_path.display(),
                allow_cidrs = ?carved,
                count = carved.len(),
                "COMBAT: network isolated WITH management carve-out — the listed CIDR(s) are NOT dropped"
            );
        }
        Ok(())
    }

    /// Build the ruleset to feed `iptables-restore`: the base
    /// `combat-rules.v4` with the management carve-out (Beta Step 4b)
    /// spliced in ahead of the catch-all DROP. Returns the rendered
    /// ruleset and the list of IPv4 CIDRs actually carved out (for
    /// logging). Re-reads the allow file every call — never cached.
    fn build_engaged_ruleset(&self) -> Result<(String, Vec<String>)> {
        let base = std::fs::read_to_string(&self.rules_path)
            .with_context(|| format!("reading {}", self.rules_path.display()))?;

        let load = combat_allow::load_allow_cidrs(&self.allow_cidrs_path);
        if let Some(reason) = &load.read_error {
            // The default-secure case is an absent/empty file, so this
            // is expected on most hosts — debug, not warn.
            tracing::debug!(
                allow_file = %self.allow_cidrs_path.display(),
                reason = %reason,
                "COMBAT: no management carve-out applied (allow file absent/unreadable — fail-secure)"
            );
        }
        for w in &load.warnings {
            warn!(
                allow_file = %self.allow_cidrs_path.display(),
                reject = %w,
                "COMBAT carve-out: skipping malformed allow entry (fail-secure — entry ignored)"
            );
        }
        for e in load.entries.iter().filter(|e| e.is_ipv6) {
            info!(
                cidr = %e.raw,
                "COMBAT carve-out: IPv6 entry noted but NOT applied — COMBAT isolation is IPv4-only"
            );
        }

        let accept_block = combat_allow::generate_accept_rules(&load.entries, COMBAT_CHAIN);
        let carved = combat_allow::ipv4_raw(&load.entries);
        Ok((splice_carveout(&base, &accept_block), carved))
    }

    /// Beta Step 4a: tear down a STALE COMBAT chain left over from a
    /// crash. Called once at boot when posture is `OBSERVING` — if the
    /// `NORTHNARROW_COMBAT` chain exists, the agent died mid-COMBAT and
    /// systemd/the watchdog restarted it; the orphaned chain would
    /// otherwise keep the host isolated with no live posture state
    /// backing it (the B3 split-brain). Reuses the idempotent teardown
    /// path; a no-op (and cheap) when no chain is present.
    pub fn reconcile_stale_chain(&self) -> Result<ReconcileOutcome> {
        let listed = Command::new(&self.iptables_bin)
            .args(["-S", COMBAT_CHAIN])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .with_context(|| format!("probing for stale {COMBAT_CHAIN} chain"))?;
        if !listed.status.success() {
            // Non-zero = chain absent (the normal clean-boot case).
            return Ok(ReconcileOutcome {
                chain_existed: false,
                rules_removed: 0,
            });
        }
        let rules_removed = count_chain_rules(&String::from_utf8_lossy(&listed.stdout));
        self.tear_down_chain()
            .context("tearing down stale COMBAT chain")?;
        self.is_isolated.store(false, Ordering::SeqCst);
        Ok(ReconcileOutcome {
            chain_existed: true,
            rules_removed,
        })
    }

    /// Idempotent chain teardown shared by [`Self::release`] and
    /// [`Self::reconcile_stale_chain`]: delete the jump rules from the
    /// base chains first (`-X` refuses a still-referenced chain), then
    /// flush and delete the chain. Each step swallows "already gone".
    fn tear_down_chain(&self) -> Result<()> {
        for base in ["INPUT", "OUTPUT", "FORWARD"] {
            run_iptables_idempotent(&self.iptables_bin, &["-D", base, "-j", COMBAT_CHAIN])
                .with_context(|| format!("removing {COMBAT_CHAIN} jump from {base}"))?;
        }
        run_iptables_idempotent(&self.iptables_bin, &["-F", COMBAT_CHAIN])
            .with_context(|| format!("flushing chain {COMBAT_CHAIN}"))?;
        run_iptables_idempotent(&self.iptables_bin, &["-X", COMBAT_CHAIN])
            .with_context(|| format!("deleting chain {COMBAT_CHAIN}"))?;
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
        self.tear_down_chain()?;
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

/// Outcome of [`NetworkIsolator::reconcile_stale_chain`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReconcileOutcome {
    /// Whether a stale `NORTHNARROW_COMBAT` chain was found at boot.
    pub chain_existed: bool,
    /// Count of `-A` rules the chain held before teardown (audit detail).
    pub rules_removed: usize,
}

/// Count the appended (`-A`) rules in `iptables -S CHAIN` output. The
/// chain-create line (`-N CHAIN`) and any policy line are excluded.
fn count_chain_rules(iptables_s_output: &str) -> usize {
    iptables_s_output
        .lines()
        .filter(|l| l.trim_start().starts_with("-A "))
        .count()
}

/// Splice the management carve-out ACCEPT block into the base ruleset.
///
/// Primary path: replace the [`CARVE_OUT_MARKER`] line. If an operator
/// stripped the marker from a customised ruleset, fall back to
/// inserting before the chain's catch-all DROP, then before `COMMIT`,
/// so the carve-out is never silently dropped on the floor. An empty
/// block removes the marker line and changes nothing else.
fn splice_carveout(base: &str, accept_block: &str) -> String {
    let accept_lines: Vec<&str> = accept_block.lines().collect();

    // Primary: marker replacement.
    if base.lines().any(|l| l.trim() == CARVE_OUT_MARKER) {
        let mut out: Vec<String> = Vec::new();
        for line in base.lines() {
            if line.trim() == CARVE_OUT_MARKER {
                out.extend(accept_lines.iter().map(|s| s.to_string()));
            } else {
                out.push(line.to_string());
            }
        }
        return finish(out);
    }

    // Fallback: no marker → insert before the first DROP, else COMMIT.
    let mut out: Vec<String> = Vec::new();
    let mut inserted = accept_lines.is_empty();
    for line in base.lines() {
        if !inserted && (line.contains("-j DROP") || line.trim() == "COMMIT") {
            out.extend(accept_lines.iter().map(|s| s.to_string()));
            inserted = true;
        }
        out.push(line.to_string());
    }
    if !inserted {
        out.extend(accept_lines.iter().map(|s| s.to_string()));
    }
    finish(out)
}

fn finish(lines: Vec<String>) -> String {
    let mut s = lines.join("\n");
    s.push('\n');
    s
}

/// Spawn `bin`, pipe `rules_data` to its stdin, and treat a non-zero
/// exit as a hard failure.
fn run_iptables_restore_data(bin: &Path, rules_data: &[u8]) -> Result<()> {
    use std::io::Write;

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
            .write_all(rules_data)
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
    fn count_chain_rules_counts_only_appends() {
        let s = "-N NORTHNARROW_COMBAT\n\
                 -A NORTHNARROW_COMBAT -i lo -j RETURN\n\
                 -A NORTHNARROW_COMBAT -o lo -j RETURN\n\
                 -A NORTHNARROW_COMBAT -j DROP\n";
        assert_eq!(count_chain_rules(s), 3);
        assert_eq!(count_chain_rules(""), 0);
    }

    #[test]
    fn splice_marker_replacement_inserts_block() {
        let base = "*filter\n\
                    -A NORTHNARROW_COMBAT -o lo -j RETURN\n\
                    # >>> NORTHNARROW_MGMT_CARVEOUT <<<\n\
                    -A NORTHNARROW_COMBAT -j DROP\nCOMMIT\n";
        let block = "-A NORTHNARROW_COMBAT -s 10.0.0.0/8 -j ACCEPT\n";
        let out = splice_carveout(base, block);
        assert!(out.contains("-s 10.0.0.0/8 -j ACCEPT"));
        // Marker line is gone; ACCEPT precedes the DROP.
        assert!(!out.contains("NORTHNARROW_MGMT_CARVEOUT"));
        let accept_at = out.find("-s 10.0.0.0/8").unwrap();
        let drop_at = out.find("-j DROP").unwrap();
        assert!(accept_at < drop_at, "ACCEPT must come before DROP");
    }

    #[test]
    fn splice_empty_block_just_removes_marker() {
        let base = "*filter\n# >>> NORTHNARROW_MGMT_CARVEOUT <<<\n-A C -j DROP\nCOMMIT\n";
        let out = splice_carveout(base, "");
        assert!(!out.contains("NORTHNARROW_MGMT_CARVEOUT"));
        assert!(out.contains("-A C -j DROP"));
    }

    #[test]
    fn splice_without_marker_falls_back_before_drop() {
        let base = "*filter\n-A C -i lo -j RETURN\n-A C -j DROP\nCOMMIT\n";
        let block = "-A C -s 192.168.0.0/16 -j ACCEPT\n";
        let out = splice_carveout(base, block);
        let accept_at = out.find("192.168.0.0/16").unwrap();
        let drop_at = out.find("-j DROP").unwrap();
        assert!(accept_at < drop_at);
    }

    #[test]
    fn engage_with_allow_file_injects_carveout() {
        let iso = match mock_success_isolator() {
            Some(i) => i,
            None => return,
        };
        // Point the isolator at a temp allow file with one v4 CIDR.
        let tmp = std::env::temp_dir().join(format!("nn-allow-{}.cidrs", std::process::id()));
        std::fs::write(&tmp, "# mgmt\n10.10.0.0/16\n2001:db8::/32\n").unwrap();
        let iso = iso.with_allow_cidrs_path(tmp.clone());
        let (ruleset, carved) = iso.build_engaged_ruleset().expect("build");
        assert_eq!(carved, vec!["10.10.0.0/16".to_string()], "only the v4 CIDR is carved");
        assert!(ruleset.contains("-A NORTHNARROW_COMBAT -s 10.10.0.0/16 -j ACCEPT"));
        assert!(ruleset.contains("-A NORTHNARROW_COMBAT -d 10.10.0.0/16 -j ACCEPT"));
        // v6 entry must NOT produce an iptables (v4) rule.
        assert!(!ruleset.contains("2001:db8"));
        let _ = std::fs::remove_file(&tmp);
    }

    #[test]
    fn engage_without_allow_file_is_loopback_only() {
        let iso = match mock_success_isolator() {
            Some(i) => i,
            None => return,
        };
        // Default allow path almost certainly absent in the test env →
        // fail-secure empty carve-out.
        let (ruleset, carved) = iso.build_engaged_ruleset().expect("build");
        assert!(carved.is_empty());
        assert!(!ruleset.contains("-j ACCEPT"));
        assert!(ruleset.contains("-A NORTHNARROW_COMBAT -j DROP"));
    }

    #[test]
    fn reconcile_reports_absent_chain_with_mock() {
        // /bin/false stands in for `iptables -S CHAIN` returning
        // non-zero (chain absent) — reconcile must report not-existed
        // and do nothing.
        let falsebin = PathBuf::from("/bin/false");
        if !falsebin.exists() {
            return;
        }
        let iso = NetworkIsolator::new_with_bin(
            combat_rules_path(),
            PathBuf::from("/usr/bin/cat"),
            falsebin,
        )
        .unwrap();
        let outcome = iso.reconcile_stale_chain().expect("reconcile");
        assert!(!outcome.chain_existed);
        assert_eq!(outcome.rules_removed, 0);
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
