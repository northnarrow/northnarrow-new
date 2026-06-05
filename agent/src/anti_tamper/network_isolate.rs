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

/// BUG-031 — `ip6tables-restore` / `ip6tables` lookup names for the v6
/// isolation mirror. Same PATH rationale as the v4 binaries.
const DEFAULT_RESTORE_BIN_V6: &str = "ip6tables-restore";
const DEFAULT_IPTABLES_BIN_V6: &str = "ip6tables";

/// Default install path for the v6 ruleset (`--combat-rules-v6`).
const DEFAULT_RULES_V6: &str = "/etc/northnarrow/combat-rules.v6";

/// Name of the chain that `combat-rules.v4` / `combat-rules.v6` create.
/// The SAME chain name is used on both the v4 and v6 `filter` tables.
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
    /// BUG-031 — v6 isolation mirror: the `combat-rules.v6` ruleset path
    /// (`--combat-rules-v6`) + the `ip6tables-restore` / `ip6tables`
    /// binaries. The v6 leg is best-effort: a missing ruleset or absent
    /// `ip6tables` leaves IPv6 un-isolated with a loud WARN (v4 still
    /// applies), not a refused COMBAT.
    rules_path_v6: PathBuf,
    restore_bin_v6: PathBuf,
    ip6tables_bin: PathBuf,
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
            rules_path_v6: PathBuf::from(DEFAULT_RULES_V6),
            restore_bin_v6: PathBuf::from(DEFAULT_RESTORE_BIN_V6),
            ip6tables_bin: PathBuf::from(DEFAULT_IPTABLES_BIN_V6),
        })
    }

    /// Override the management carve-out CIDR file path (Beta Step 4b).
    /// `main.rs` wires this from `--combat-allow-cidrs`.
    pub fn with_allow_cidrs_path(mut self, path: PathBuf) -> Self {
        self.allow_cidrs_path = path;
        self
    }

    /// BUG-031 — override the v6 ruleset path. `main.rs` wires this from
    /// `--combat-rules-v6`. A missing file makes the v6 leg degrade
    /// (loud WARN), not fail — unlike the v4 ruleset, which `new()`
    /// requires.
    pub fn with_rules_v6(mut self, path: PathBuf) -> Self {
        self.rules_path_v6 = path;
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
            // v6 fields default to the same (benign) test binaries +
            // ruleset so existing v4 tests exercise the v6 legs harmlessly
            // (`/bin/true` / `/usr/bin/cat`). v6-specific tests pass the
            // same ctor.
            rules_path_v6: rules_path.clone(),
            restore_bin_v6: restore_bin.clone(),
            ip6tables_bin: iptables_bin.clone(),
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
        // BUG-041: the restore inserts our jump on top; a re-engage would
        // stack a duplicate. Trim to exactly one — windowless (only
        // deletes extras, always leaves >= 1 jump). Runs AFTER the
        // restore `?`, so it never acts on a zero-jump table from a
        // failed restore.
        dedup_jumps(&self.iptables_bin).context("deduplicating v4 COMBAT jumps")?;
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
        // BUG-031 — v6 mirror, best-effort. An attack is already detected;
        // refusing the whole COMBAT because v6 isn't provisioned would mean
        // NO isolation (v4 included), letting the attack proceed. Isolate
        // v4 + WARN loudly on any v6 hole.
        self.engage_v6();
        Ok(())
    }

    /// BUG-031 — apply the v6 isolation ruleset via `ip6tables-restore`.
    /// Best-effort + loud: a missing `combat-rules.v6` or absent
    /// `ip6tables` leaves IPv6 un-isolated with a WARN, never failing the
    /// (v4) engage.
    fn engage_v6(&self) {
        match self.build_engaged_ruleset_v6() {
            Ok(None) => warn!(
                rules_v6 = %self.rules_path_v6.display(),
                "COMBAT: combat-rules.v6 absent — IPv6 NOT isolated this COMBAT (v4 applied; provision the v6 ruleset to close the gap)"
            ),
            Ok(Some((ruleset, carved))) => {
                match run_iptables_restore_data(&self.restore_bin_v6, ruleset.as_bytes()) {
                    Ok(()) => {
                        // BUG-041: dedup our v6 jumps (best-effort — a dup
                        // is harmless, both isolate; v4 already succeeded).
                        if let Err(e) = dedup_jumps(&self.ip6tables_bin) {
                            warn!(error = %e, "COMBAT: v6 jump dedup failed (best-effort; isolation intact)");
                        }
                        if carved.is_empty() {
                            info!(
                                rules_v6 = %self.rules_path_v6.display(),
                                "COMBAT: IPv6 isolated (NDP/MLD preserved, loopback only)"
                            );
                        } else {
                            warn!(
                                rules_v6 = %self.rules_path_v6.display(),
                                allow_cidrs = ?carved,
                                count = carved.len(),
                                "COMBAT: IPv6 isolated WITH management carve-out — the listed CIDR(s) are NOT dropped"
                            );
                        }
                    }
                    Err(e) => warn!(
                        error = %e,
                        "COMBAT: ip6tables-restore FAILED — IPv6 NOT isolated this COMBAT (v4 applied; ip6tables absent or errored)"
                    ),
                }
            }
            Err(e) => warn!(
                error = %e,
                "COMBAT: building the v6 ruleset failed — IPv6 NOT isolated this COMBAT"
            ),
        }
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
        // BUG-031: IPv6 carve-out entries are no longer inert — they are
        // applied to the v6 chain by `build_engaged_ruleset_v6` below.

        let accept_block = combat_allow::generate_accept_rules(&load.entries, COMBAT_CHAIN);
        let carved = combat_allow::ipv4_raw(&load.entries);
        Ok((splice_carveout(&base, &accept_block), carved))
    }

    /// BUG-031 — v6 sibling of [`Self::build_engaged_ruleset`]. Returns
    /// `Ok(None)` when `combat-rules.v6` is absent (the v6 leg then
    /// degrades with a WARN). Splices the IPv6 carve-out entries — which
    /// the v4 path parses but ignores — ahead of the v6 catch-all DROP.
    fn build_engaged_ruleset_v6(&self) -> Result<Option<(String, Vec<String>)>> {
        let base = match std::fs::read_to_string(&self.rules_path_v6) {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => {
                return Err(anyhow::Error::new(e))
                    .with_context(|| format!("reading {}", self.rules_path_v6.display()))
            }
        };
        // The allow file's read errors + malformed-line warnings were
        // already surfaced by the v4 builder (engage() runs v4 first);
        // here we just take the validated entries.
        let load = combat_allow::load_allow_cidrs(&self.allow_cidrs_path);
        let accept_block = combat_allow::generate_accept_rules_v6(&load.entries, COMBAT_CHAIN);
        let carved = combat_allow::ipv6_raw(&load.entries);
        Ok(Some((splice_carveout(&base, &accept_block), carved)))
    }

    /// Beta Step 4a: tear down a STALE COMBAT chain left over from a
    /// crash. Called once at boot when posture is `OBSERVING` — if the
    /// `NORTHNARROW_COMBAT` chain exists, the agent died mid-COMBAT and
    /// systemd/the watchdog restarted it; the orphaned chain would
    /// otherwise keep the host isolated with no live posture state
    /// backing it (the B3 split-brain). Reuses the idempotent teardown
    /// path; a no-op (and cheap) when no chain is present.
    pub fn reconcile_stale_chain(&self) -> Result<ReconcileOutcome> {
        let v4 = probe_chain(&self.iptables_bin)
            .with_context(|| format!("probing for stale {COMBAT_CHAIN} v4 chain"))?;
        // BUG-031: a mid-COMBAT crash can leave a stale v6 chain too —
        // probe it INDEPENDENTLY so a v6-only orphan is still detected
        // (the v6 edition of the B3 split-brain). Best-effort: ip6tables
        // absent ⇒ treat as no v6 chain.
        let v6 = probe_chain(&self.ip6tables_bin).unwrap_or(None);
        if v4.is_none() && v6.is_none() {
            // Neither chain present (the normal clean-boot case).
            return Ok(ReconcileOutcome {
                chain_existed: false,
                rules_removed: 0,
            });
        }
        let rules_removed = v4.unwrap_or(0) + v6.unwrap_or(0);
        // tear_down_chain clears BOTH tables (best-effort on v6).
        self.tear_down_chain()
            .context("tearing down stale COMBAT chain(s)")?;
        self.is_isolated.store(false, Ordering::SeqCst);
        Ok(ReconcileOutcome {
            chain_existed: true,
            rules_removed,
        })
    }

    /// Idempotent chain teardown shared by [`Self::release`] and
    /// [`Self::reconcile_stale_chain`]. Clears `COMBAT_CHAIN` on BOTH the
    /// v4 and v6 tables (BUG-031). v4 is the critical path (errors
    /// propagate); the v6 leg is best-effort + WARN, so a v4-only host
    /// (no `ip6tables`) still releases cleanly. Because release() and
    /// reconcile() both delegate here, the v6 teardown covers both.
    fn tear_down_chain(&self) -> Result<()> {
        tear_down_one(&self.iptables_bin)?;
        if let Err(e) = tear_down_one(&self.ip6tables_bin) {
            warn!(
                error = %e,
                "COMBAT release: v6 chain teardown failed (best-effort; v4 cleared)"
            );
        }
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
    if already_gone(&stderr) {
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

/// Does a failed `iptables`/`ip6tables` `stderr` mean the target was
/// already gone (the idempotent goal)? Messages vary by backend:
///   `-D` rule already gone (legacy):
///     "iptables: Bad rule (does a matching rule exist in that chain?)."
///   `-F`/`-X` chain already gone (legacy):
///     "iptables: No chain/target/match by that name."
///   `-D <jump>` whose target chain is absent (nf_tables, BUG-031):
///     "… (nf_tables): Chain 'NORTHNARROW_COMBAT' does not exist"
/// The last is the v4/v6 case where one table has no chain while the
/// other does — `tear_down_one` runs on both, so the absent-table legs
/// must be no-ops. A "Device or resource busy" (chain still referenced)
/// is deliberately NOT here — that's a real error, not "already gone".
fn already_gone(stderr: &str) -> bool {
    stderr.contains("does a matching rule exist")
        || stderr.contains("No chain/target/match")
        || stderr.contains("does not exist")
}

/// Outcome of [`NetworkIsolator::reconcile_stale_chain`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReconcileOutcome {
    /// Whether a stale `NORTHNARROW_COMBAT` chain was found at boot.
    pub chain_existed: bool,
    /// Count of `-A` rules the chain held before teardown (audit detail).
    pub rules_removed: usize,
}

/// Idempotent teardown of `COMBAT_CHAIN` on `bin`'s table (BUG-031):
/// remove the jumps from the base chains first (`-X` refuses a
/// still-referenced chain), then flush + delete. Each step tolerates
/// "already gone". Parameterized by `bin` so the v4 (`iptables`) and v6
/// (`ip6tables`) tables share one implementation.
fn tear_down_one(bin: &Path) -> Result<()> {
    for base in ["INPUT", "OUTPUT", "FORWARD"] {
        run_iptables_idempotent(bin, &["-D", base, "-j", COMBAT_CHAIN])
            .with_context(|| format!("removing {COMBAT_CHAIN} jump from {base}"))?;
    }
    run_iptables_idempotent(bin, &["-F", COMBAT_CHAIN])
        .with_context(|| format!("flushing chain {COMBAT_CHAIN}"))?;
    run_iptables_idempotent(bin, &["-X", COMBAT_CHAIN])
        .with_context(|| format!("deleting chain {COMBAT_CHAIN}"))?;
    Ok(())
}

/// Probe whether `COMBAT_CHAIN` exists on `bin`'s table.
/// `Ok(Some(n))` = present with `n` `-A` rules, `Ok(None)` = absent
/// (non-zero exit), `Err` = the binary could not be run (BUG-031: the
/// v6 caller treats that as "no v6 chain").
fn probe_chain(bin: &Path) -> Result<Option<usize>> {
    let listed = Command::new(bin)
        .args(["-S", COMBAT_CHAIN])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .with_context(|| format!("running {} -S {COMBAT_CHAIN}", bin.display()))?;
    if !listed.status.success() {
        return Ok(None);
    }
    Ok(Some(count_chain_rules(&String::from_utf8_lossy(&listed.stdout))))
}

/// BUG-041 — after an additive `-I … 1` engage, ensure exactly ONE
/// `-j COMBAT_CHAIN` jump remains in each base chain (a re-engage would
/// otherwise stack a duplicate). Windowless: only ever DELETEs extras,
/// leaving >= 1 jump in place at all times — never a no-jump moment.
/// Must run AFTER a successful restore (so the count is >= 1).
fn dedup_jumps(bin: &Path) -> Result<()> {
    for base in ["INPUT", "OUTPUT", "FORWARD"] {
        let listed = Command::new(bin)
            .args(["-S", base])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .with_context(|| format!("listing {base} to dedup {COMBAT_CHAIN} jumps"))?;
        if !listed.status.success() {
            continue; // base chain unreadable — skip (best-effort)
        }
        let n = count_jumps(&String::from_utf8_lossy(&listed.stdout));
        // Delete (n - 1) extras, keeping exactly one. `1..n` is empty when
        // n <= 1, so this never deletes below one jump.
        for _ in 1..n {
            run_iptables_idempotent(bin, &["-D", base, "-j", COMBAT_CHAIN])
                .with_context(|| format!("removing duplicate {COMBAT_CHAIN} jump from {base}"))?;
        }
    }
    Ok(())
}

/// Count `-j COMBAT_CHAIN` jump rules in `iptables -S <base>` output.
fn count_jumps(iptables_s_output: &str) -> usize {
    let needle = format!("-j {COMBAT_CHAIN}");
    iptables_s_output.lines().filter(|l| l.contains(&needle)).count()
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
        // BUG-041: ADDITIVE — never flush the operator's table. The dump
        // rebuilds only our own declared chain (`:NORTHNARROW_COMBAT`)
        // and inserts our jumps (`-I … 1`); every operator chain/rule is
        // left untouched.
        .arg("--noflush")
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

    // BUG-031: the idempotent-teardown classifier must recognize the
    // "already gone" messages across backends — including nf_tables'
    // "Chain '…' does not exist" (the v4/v6-absent-table case) — while
    // NOT swallowing a real "resource busy" (chain still referenced).
    #[test]
    fn already_gone_recognizes_backend_messages() {
        assert!(already_gone(
            "iptables: Bad rule (does a matching rule exist in that chain?)."
        ));
        assert!(already_gone("iptables: No chain/target/match by that name."));
        assert!(already_gone(
            "iptables v1.8.10 (nf_tables): Chain 'NORTHNARROW_COMBAT' does not exist"
        ));
        assert!(!already_gone(
            "ip6tables v1.8.10 (nf_tables):  CHAIN_DEL failed (Device or resource busy): chain NORTHNARROW_COMBAT"
        ));
    }

    // BUG-041: the dedup counts only OUR jumps (so it trims duplicates to
    // one without touching operator rules in the same base chain).
    #[test]
    fn count_jumps_counts_our_jumps_only() {
        let two = "-P INPUT ACCEPT\n\
                   -A INPUT -j NORTHNARROW_COMBAT\n\
                   -A INPUT -p tcp -m tcp --dport 22 -j ACCEPT\n\
                   -A INPUT -j NORTHNARROW_COMBAT\n";
        assert_eq!(count_jumps(two), 2, "two NN jumps; operator ACCEPT not counted");
        assert_eq!(count_jumps("-A INPUT -j NORTHNARROW_COMBAT\n"), 1);
        assert_eq!(count_jumps("-P INPUT ACCEPT\n-A INPUT -j ACCEPT\n"), 0);
    }

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
    /// A mock `iptables-restore`: a tiny script that drains stdin to EOF
    /// and exits 0, IGNORING its args — so it tolerates the `--noflush`
    /// flag (BUG-041) that `cat` rejects as an unknown option, while
    /// still avoiding the EPIPE a non-reading mock (`/bin/true`) hits.
    fn mock_restore_bin() -> Option<PathBuf> {
        use std::io::Write;
        use std::os::unix::fs::PermissionsExt;
        use std::sync::atomic::{AtomicU32, Ordering};
        // UNIQUE per call: tests run in parallel; a shared path would let
        // one test's File::create (truncate) collide with another test
        // exec'ing it (ETXTBSY / a truncated script → EPIPE on the write).
        static N: AtomicU32 = AtomicU32::new(0);
        let path = std::env::temp_dir().join(format!(
            "nn-test-mock-restore-{}-{}.sh",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ));
        let mut f = std::fs::File::create(&path).ok()?;
        f.write_all(b"#!/bin/sh\ncat >/dev/null 2>&1\nexit 0\n").ok()?;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).ok()?;
        Some(path)
    }

    fn mock_success_isolator() -> Option<NetworkIsolator> {
        let restore = mock_restore_bin()?;
        let truebin = PathBuf::from("/bin/true");
        if !truebin.exists() {
            eprintln!("/bin/true missing; skipping");
            return None;
        }
        Some(NetworkIsolator::new_with_bin(combat_rules_path(), restore, truebin).unwrap())
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
        // Hermetic (§26 test-debt fix): point at a guaranteed-ABSENT
        // allow path so the carve-out is the fail-secure empty set,
        // regardless of whether the host has a real
        // /etc/northnarrow/combat-allow.cidrs provisioned. The old test
        // read `combat_allow::default_path()` directly — it passed on a
        // clean dev box but failed on a deployed VM (where the live mgmt
        // carve-out file exists → `carved` non-empty). Mirrors the temp
        // allow-path pattern the sibling carve-out test already uses.
        let absent = std::env::temp_dir().join(format!("nn-absent-allow-{}.cidrs", std::process::id()));
        let _ = std::fs::remove_file(&absent);
        let iso = iso.with_allow_cidrs_path(absent);
        let (ruleset, carved) = iso.build_engaged_ruleset().expect("build");
        assert!(carved.is_empty(), "absent allow file must yield empty carve-out, got {carved:?}");
        // Loopback-only isolation: the only ACCEPTs are the two lo rules
        // (the additive model uses `-i/-o lo -j ACCEPT`, NOT RETURN — see
        // configs/combat-rules.v4 header); NO management carve-out CIDR
        // ACCEPT (`-s`/`-d <cidr> -j ACCEPT`) was spliced in, and the
        // carve-out marker was consumed.
        assert!(
            ruleset.contains("-A NORTHNARROW_COMBAT -i lo -j ACCEPT")
                && ruleset.contains("-A NORTHNARROW_COMBAT -o lo -j ACCEPT"),
            "loopback ACCEPT rules must be present: {ruleset}"
        );
        assert!(
            !ruleset.contains(" -s ") && !ruleset.contains(" -d "),
            "no management carve-out CIDR ACCEPT expected with an absent allow file: {ruleset}"
        );
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
        // BUG-041: production engages with `--noflush` (additive); test the
        // same way so the `-I … 1` jumps + `:NORTHNARROW_COMBAT` rebuild
        // are validated as they're actually applied.
        let mut child = Command::new(bin)
            .args(["--test", "--noflush"])
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
