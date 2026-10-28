//! COMBAT-state network isolation (Tappa 7 task 7 / Tappa 8).
//!
//! On COMBAT entry the [`PostureMachine`](nn_core::posture::PostureMachine)
//! fires a hook that invokes [`NetworkIsolator::engage`], which shells
//! out to `iptables-restore` with the pre-built ruleset at
//! `configs/combat-rules.v4`. The ruleset drops every packet on
//! `INPUT`, `OUTPUT`, and `FORWARD` except loopback — there is
//! intentionally no management-port carve-out, so recovery requires
//! physical access plus an Ed25519-signed admin unlock (see
//! `admin_auth.rs`, landing in a later commit).
//!
//! `release()` requires the [`UnlockToken`] capability type, so the API
//! can only be used by code that proved a signature first.
//!
//! ## Truthful state (lab PR 217, capability C18)
//!
//! The isolation is kept per IP family ([`Family`]): a family is isolated
//! only once its table was read back (`iptables -S` / `ip6tables -S`) after
//! an engage and found holding the COMBAT chain with its catch-all DROP and
//! every jump into it; it is clear again only once a release read the table
//! back without the chain or any jump. [`NetworkIsolator::engage`] and
//! [`NetworkIsolator::release`] return what they found, per family
//! ([`IsolationReport`]), and every iptables / ip6tables invocation is
//! waited for at most [`crate::bounded_cmd::EXTERNAL_CMD_TIMEOUT`].

use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};

use anyhow::{anyhow, Context, Result};
use tracing::{error, info, warn};

use super::combat_allow;
use crate::bounded_cmd::{run_bounded, EXTERNAL_CMD_TIMEOUT};
use crate::trusted_bin::{self, SystemBin};

/// `iptables-restore` lookup name. External audit ATP-014 (NN-AUD-262):
/// looked up in the system directories only ([`crate::trusted_bin`]), not
/// on the `PATH` the agent inherited — whose first entries under systemd
/// are `/usr/local/sbin:/usr/local/bin`. Ubuntu, Debian and the RHEL
/// family install it in `/usr/sbin` (`/sbin` on a split `/usr`).
const DEFAULT_RESTORE_BIN: &str = "iptables-restore";

/// `iptables` lookup name. Used by [`NetworkIsolator::release`] to
/// undo what `iptables-restore` applied. Looked up like
/// [`DEFAULT_RESTORE_BIN`].
const DEFAULT_IPTABLES_BIN: &str = "iptables";

/// BUG-031 — `ip6tables-restore` / `ip6tables` lookup names for the v6
/// isolation mirror. Looked up like the v4 binaries.
const DEFAULT_RESTORE_BIN_V6: &str = "ip6tables-restore";
const DEFAULT_IPTABLES_BIN_V6: &str = "ip6tables";

/// A binary COMBAT runs. External audit ATP-014 (NN-AUD-262): in
/// production a name, looked up in the system directories at each use and
/// run as the verified file ([`trusted_bin::resolve`]); a lookup that fails
/// is an error of the step (no `PATH` fallback). Tests run a fixed mock
/// (R09a, lab PR 253: the agent's too, through this crate's `test-util`).
#[derive(Debug, Clone)]
enum Bin {
    System(&'static str),
    #[cfg(any(test, feature = "test-util"))]
    Fixed(PathBuf),
}

impl Bin {
    /// The command to run, and the file it runs (for the log).
    fn command(&self) -> Result<(Command, PathBuf)> {
        match self {
            Bin::System(name) => {
                let bin: SystemBin = trusted_bin::resolve(name)
                    .map_err(|e| anyhow!("{e} (external audit ATP-014: no PATH lookup)"))?;
                Ok((bin.command(), bin.exe().to_path_buf()))
            }
            #[cfg(any(test, feature = "test-util"))]
            Bin::Fixed(path) => Ok((Command::new(path), path.clone())),
        }
    }
}

impl std::fmt::Display for Bin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Bin::System(name) => f.write_str(name),
            #[cfg(any(test, feature = "test-util"))]
            Bin::Fixed(path) => write!(f, "{}", path.display()),
        }
    }
}

/// Default install path for the v6 ruleset (`--combat-rules-v6`).
const DEFAULT_RULES_V6: &str = "/etc/northnarrow/combat-rules.v6";

/// Name of the chain that `combat-rules.v4` / `combat-rules.v6` create.
/// The SAME chain name is used on both the v4 and v6 `filter` tables.
const COMBAT_CHAIN: &str = "NORTHNARROW_COMBAT";

/// Marker line in `configs/combat-rules.v4` that [`NetworkIsolator::engage`]
/// replaces with the management carve-out ACCEPT rules (Beta Step 4b).
/// Placed inside the chain, immediately before its catch-all DROP.
pub const CARVE_OUT_MARKER: &str = "# >>> NORTHNARROW_MGMT_CARVEOUT <<<";

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

// R08c (lab PR 252): an IP family and what an engage or a release found in
// its table are the vocabulary the COMBAT ladder records and decides on
// (ISOLATE done, retried or a hole), and the ladder moves to nn-core: cut
// verbatim into nn-core's `anti_tamper::network_isolate`, here under their
// names. The isolator — iptables, the read-back, the carve-out, the release
// on the unlock token — stays here (nn-linux, R09).
pub use nn_core::anti_tamper::network_isolate::{Family, FamilyOutcome, IsolationReport};

/// COMBAT-state network isolator. Cheap to construct (no I/O beyond
/// a path-exists check); the expensive work happens in
/// [`Self::engage`].
#[derive(Debug)]
pub struct NetworkIsolator {
    /// Lab PR 217: per family — true only after a read-back found the
    /// COMBAT ruleset in that table (one flag for both used to say
    /// "isolated" with IPv6 open).
    isolated_v4: AtomicBool,
    isolated_v6: AtomicBool,
    rules_path: PathBuf,
    /// Beta Step 4b: opt-in management carve-out CIDR list, re-read at
    /// every `engage()` (never cached) so an operator can add an
    /// emergency CIDR from a local console mid-COMBAT.
    allow_cidrs_path: PathBuf,
    restore_bin: Bin,
    iptables_bin: Bin,
    /// BUG-031 — v6 isolation mirror: the `combat-rules.v6` ruleset path
    /// (`--combat-rules-v6`) + the `ip6tables-restore` / `ip6tables`
    /// binaries. The v6 leg is best-effort: a missing ruleset or absent
    /// `ip6tables` leaves IPv6 un-isolated with a loud WARN (v4 still
    /// applies), not a refused COMBAT.
    rules_path_v6: PathBuf,
    restore_bin_v6: Bin,
    ip6tables_bin: Bin,
    /// External audit ATP-001 / DEP-003: who vouches for the three files
    /// COMBAT reads ([`Self::trusted_source`]). `None` (tests, tools):
    /// the files are trusted as they are. R09a (lab PR 253): the agent's
    /// signed-overlay gate, through nn-core's `Vouch`.
    gate: Option<std::sync::Arc<dyn nn_core::config::overlay_auth::Vouch>>,
    /// Lab PR 217: how long each iptables / ip6tables invocation may take
    /// ([`EXTERNAL_CMD_TIMEOUT`]).
    cmd_timeout: std::time::Duration,
}

/// The rulesets and carve-out the agent was built with — what COMBAT
/// applies when a file on disk is missing or not vouched for.
pub const BUILTIN_RULES_V4: &str =
    include_str!(concat!(env!("NN_REPO_ROOT"), "/configs/combat-rules.v4"));
/// See [`BUILTIN_RULES_V4`].
pub const BUILTIN_RULES_V6: &str =
    include_str!(concat!(env!("NN_REPO_ROOT"), "/configs/combat-rules.v6"));
/// See [`BUILTIN_RULES_V4`]: comments only, no network spared.
pub const BUILTIN_ALLOW: &str =
    include_str!(concat!(env!("NN_REPO_ROOT"), "/configs/combat-allow.cidrs"));

/// What a COMBAT ruleset must keep to still isolate: the filter table, the
/// COMBAT chain and its catch-all DROP, the INPUT and OUTPUT jumps into
/// it, and COMMIT. Checked before a ruleset can be signed.
pub fn validate_ruleset(text: &str) -> Result<()> {
    let lines: Vec<&str> = text
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .collect();
    let has = |pred: &dyn Fn(&str) -> bool| lines.iter().any(|l| pred(l));
    let jump = format!("-j {COMBAT_CHAIN}");
    let checks: [(&str, bool); 6] = [
        ("*filter", has(&|l| l == "*filter")),
        (
            "the COMBAT chain",
            has(&|l| l.starts_with(&format!(":{COMBAT_CHAIN}"))),
        ),
        (
            "its catch-all DROP",
            has(&|l| l == format!("-A {COMBAT_CHAIN} -j DROP")),
        ),
        (
            "the INPUT jump",
            has(&|l| l.contains("INPUT") && l.ends_with(&jump)),
        ),
        (
            "the OUTPUT jump",
            has(&|l| l.contains("OUTPUT") && l.ends_with(&jump)),
        ),
        ("COMMIT", has(&|l| l == "COMMIT")),
    ];
    for (what, ok) in checks {
        if !ok {
            return Err(anyhow!(
                "COMBAT ruleset lacks {what} — it would not isolate"
            ));
        }
    }
    Ok(())
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
            isolated_v4: AtomicBool::new(false),
            isolated_v6: AtomicBool::new(false),
            rules_path,
            allow_cidrs_path: combat_allow::default_path(),
            restore_bin: Bin::System(DEFAULT_RESTORE_BIN),
            iptables_bin: Bin::System(DEFAULT_IPTABLES_BIN),
            rules_path_v6: PathBuf::from(DEFAULT_RULES_V6),
            restore_bin_v6: Bin::System(DEFAULT_RESTORE_BIN_V6),
            ip6tables_bin: Bin::System(DEFAULT_IPTABLES_BIN_V6),
            gate: None,
            cmd_timeout: EXTERNAL_CMD_TIMEOUT,
        })
    }

    /// External audit ATP-014 (NN-AUD-262): the files COMBAT will run, for
    /// the boot log — each name with the verified file it resolves to, or
    /// why there is none. `Err` when a v4 binary (the critical leg) cannot
    /// be run.
    pub fn binaries(&self) -> std::result::Result<String, String> {
        let mut found = Vec::new();
        let mut missing = Vec::new();
        for (bin, critical) in [
            (&self.restore_bin, true),
            (&self.iptables_bin, true),
            (&self.restore_bin_v6, false),
            (&self.ip6tables_bin, false),
        ] {
            match bin.command() {
                Ok((_, exe)) => found.push(format!("{bin}={}", exe.display())),
                Err(e) if critical => missing.push(format!("{e:#}")),
                Err(e) => found.push(format!("{bin}: {e:#}")),
            }
        }
        if missing.is_empty() {
            Ok(found.join(", "))
        } else {
            Err(missing.join("; "))
        }
    }

    /// External audit ATP-001 / DEP-003: vouch for the COMBAT files with
    /// the signed-overlay gate ([`Self::trusted_source`]). R09a (lab PR
    /// 253): the gate is nn-core's [`Vouch`](nn_core::config::overlay_auth::Vouch),
    /// the agent's `OverlayGate`.
    pub fn with_overlay_gate<G: nn_core::config::overlay_auth::Vouch + 'static>(
        mut self,
        gate: std::sync::Arc<G>,
    ) -> Self {
        self.gate = Some(gate);
        self
    }

    /// External audit ATP-001 / DEP-003: the content COMBAT may apply for
    /// `kind` read from `path`. A root process could rewrite the rulesets
    /// so COMBAT dropped nothing, delete them so engage failed, or add its
    /// own network to the carve-out — and the agent still logged "network
    /// isolated". Now the file is applied only when it is the shipped
    /// content or carries an admin `config-manage` signature for its exact
    /// content (the overlay gate, which logs and records a refusal);
    /// otherwise, or when the file is missing, the built-in content is.
    ///
    /// External audit LLMR-013: what is applied is the text the gate read
    /// and verified. This read the file first, let the gate verify a second
    /// read, and applied the first: a root process able to pause the
    /// agent's `open()` could make the two differ at every engage, and
    /// COMBAT would apply a ruleset nobody signed while it logged the host
    /// isolated.
    fn trusted_source(
        &self,
        kind: nn_proto::admin_signed_payload::OverlayKind,
        path: &std::path::Path,
        builtin: &'static str,
    ) -> String {
        use nn_core::config::overlay_auth::Verified;
        let Some(gate) = &self.gate else {
            return match std::fs::read_to_string(path) {
                Ok(t) => t,
                Err(e) => {
                    warn!(
                        file = %path.display(),
                        error = %e,
                        "COMBAT: file unreadable — applying the built-in content"
                    );
                    builtin.to_string()
                }
            };
        };
        match gate.verified(kind, path) {
            Verified::Content { text, .. } => text,
            Verified::ShippedDefault => builtin.to_string(),
            Verified::Missing => {
                warn!(
                    file = %path.display(),
                    "COMBAT: file missing — applying the built-in content"
                );
                builtin.to_string()
            }
            Verified::Refused => {
                error!(
                    file = %path.display(),
                    "COMBAT: file not vouched for (modified without an admin signature) — \
                     applying the built-in content instead"
                );
                builtin.to_string()
            }
        }
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
    #[cfg(any(test, feature = "test-util"))]
    pub fn new_with_bin(
        rules_path: PathBuf,
        restore_bin: PathBuf,
        iptables_bin: PathBuf,
    ) -> Result<Self> {
        Ok(Self {
            isolated_v4: AtomicBool::new(false),
            isolated_v6: AtomicBool::new(false),
            // v6 fields default to the same (benign) test binaries +
            // ruleset so existing v4 tests exercise the v6 legs harmlessly
            // (`/bin/true` / `/usr/bin/cat`). v6-specific tests pass the
            // same ctor.
            rules_path_v6: rules_path.clone(),
            restore_bin_v6: Bin::Fixed(restore_bin.clone()),
            ip6tables_bin: Bin::Fixed(iptables_bin.clone()),
            rules_path,
            allow_cidrs_path: combat_allow::default_path(),
            restore_bin: Bin::Fixed(restore_bin),
            iptables_bin: Bin::Fixed(iptables_bin),
            gate: None,
            cmd_timeout: EXTERNAL_CMD_TIMEOUT,
        })
    }

    /// Apply the combat ruleset, IPv4 and IPv6, and read each table back.
    /// Idempotent: re-engaging shells out again, which is intentional — if
    /// an attacker has flushed iptables between our calls, re-asserting the
    /// ruleset is exactly what we want.
    ///
    /// Lab PR 217 (capability C18): what is returned — and what the state
    /// says — is what the read-back found, per family. A family is isolated
    /// only when its table holds the COMBAT chain, its catch-all DROP and
    /// every jump into it after the restore; a restore that exited non-zero
    /// over a table still holding an earlier engage's ruleset is isolated
    /// too (the restore's error is logged). The v6 leg stays best-effort
    /// (BUG-031: an attack is under way; refusing all isolation because v6
    /// is not provisioned would let it proceed), and it is no longer silent:
    /// its outcome is in the report, the signed record and `nn-admin
    /// status`, and a v6 failure is retried by the ladder like a v4 one. Both
    /// legs are attempted whatever the other's outcome.
    pub fn engage(&self) -> IsolationReport {
        let v4 = match self.build_engaged_ruleset() {
            Ok((ruleset, carved)) => self.engage_family(Family::V4, &ruleset, &carved),
            Err(e) => {
                self.set_isolated(Family::V4, false);
                FamilyOutcome::Failed(format!("building the v4 ruleset: {e:#}"))
            }
        };
        let v6 = match self.build_engaged_ruleset_v6() {
            Ok(None) => {
                warn!(
                    rules_v6 = %self.rules_path_v6.display(),
                    "COMBAT: combat-rules.v6 absent — IPv6 NOT isolated this COMBAT (provision \
                     the v6 ruleset to close the gap)"
                );
                FamilyOutcome::Unavailable(format!(
                    "{} absent: no v6 ruleset provisioned",
                    self.rules_path_v6.display()
                ))
            }
            Ok(Some((ruleset, carved))) => self.engage_family(Family::V6, &ruleset, &carved),
            Err(e) => {
                warn!(error = %e, "COMBAT: building the v6 ruleset failed — IPv6 NOT isolated this COMBAT");
                FamilyOutcome::Failed(format!("building the v6 ruleset: {e:#}"))
            }
        };
        IsolationReport { v4, v6 }
    }

    /// One family's engage: restore, read back, record. See [`Self::engage`].
    fn engage_family(&self, family: Family, ruleset: &str, carved: &[String]) -> FamilyOutcome {
        let (restore_bin, list_bin) = self.bins(family);
        if family == Family::V6 {
            // No trusted ip6tables on this host: nothing can be applied (the
            // v4 leg names its own binaries' gap as a failure — it is the
            // isolation).
            if let Err(e) = restore_bin.command().and(list_bin.command()) {
                warn!(error = %format!("{e:#}"), "COMBAT: IPv6 NOT isolated — no ip6tables to apply the v6 ruleset with");
                return FamilyOutcome::Unavailable(format!("{e:#}"));
            }
        }
        let restored = run_iptables_restore_data(restore_bin, ruleset.as_bytes(), self.cmd_timeout);
        // Lab follow-up (lab PR 188): a restore that exits 0 is not proof
        // that the ruleset is in. Root can point the `iptables-restore`
        // link (or its `/etc/alternatives` entry) at another root-owned
        // system binary — `/usr/bin/true` passes the trusted-binary checks
        // of ATP-014 — and the isolation was a no-op logged as "network
        // isolated", visible only in `restore_bin`. The table is read back
        // (`iptables -S`): the chain must hold its catch-all DROP and every
        // base chain the ruleset jumps from must jump into it. Otherwise the
        // family is not isolated, and is not reported so. Lab PR 217: the v6
        // table likewise, and after a failed restore too (the state follows
        // the table, not the exit code).
        if let Err(gaps) = verify_isolation(list_bin, ruleset, self.cmd_timeout) {
            self.set_isolated(family, false);
            let why = match &restored {
                Ok(exe) => format!(
                    "isolation not in place after {} exited 0: {gaps} — {} is NOT isolated",
                    exe.display(),
                    family.label()
                ),
                Err(e) => format!(
                    "{restore_bin} failed: {e:#}; read back: {gaps} — {} is NOT isolated",
                    family.label()
                ),
            };
            error!(family = family.label(), why = %why, "COMBAT: isolation NOT in place");
            return FamilyOutcome::Failed(why);
        }
        // External audit ATP-006 (NN-AUD-259): the ruleset is in, so the
        // family is isolated — recorded before anything else can fail.
        self.set_isolated(family, true);
        if let Err(e) = &restored {
            warn!(
                family = family.label(),
                error = %format!("{e:#}"),
                "COMBAT: the restore failed, but the table still holds the COMBAT ruleset of an \
                 earlier engage — isolated"
            );
        }
        // BUG-041: the restore inserts our jump on top; a re-engage would
        // stack a duplicate. Trim to exactly one — windowless (only
        // deletes extras, always leaves >= 1 jump). Runs AFTER the
        // read-back, so it never acts on a zero-jump table. A failure
        // leaves a duplicate jump, which isolates like the first and which
        // the teardown removes too (`remove_jumps`): an ERROR, not a failed
        // engage.
        if let Err(e) = dedup_jumps(list_bin, self.cmd_timeout) {
            error!(
                family = family.label(),
                error = %format!("{e:#}"),
                "COMBAT: isolated, but the jump dedup failed — a duplicate jump may be left (it \
                 isolates too; the release removes every jump)"
            );
        }
        let restore_exe = restored
            .as_ref()
            .map(|e| e.display().to_string())
            .unwrap_or_default();
        if carved.is_empty() {
            info!(
                family = family.label(),
                restore_bin = %restore_exe,
                "COMBAT: network isolated (loopback only; IPv6: NDP/MLD preserved)"
            );
        } else {
            // WARN so the carve-out is conspicuous in the audit trail:
            // these CIDRs survive isolation, which is exactly the kind
            // of thing an operator reviewing a COMBAT event must see.
            warn!(
                family = family.label(),
                restore_bin = %restore_exe,
                allow_cidrs = ?carved,
                count = carved.len(),
                "COMBAT: network isolated WITH management carve-out — the listed CIDR(s) are NOT dropped"
            );
        }
        FamilyOutcome::Done
    }

    /// The restore and the list/edit binary of `family`.
    fn bins(&self, family: Family) -> (&Bin, &Bin) {
        match family {
            Family::V4 => (&self.restore_bin, &self.iptables_bin),
            Family::V6 => (&self.restore_bin_v6, &self.ip6tables_bin),
        }
    }

    fn flag(&self, family: Family) -> &AtomicBool {
        match family {
            Family::V4 => &self.isolated_v4,
            Family::V6 => &self.isolated_v6,
        }
    }

    fn set_isolated(&self, family: Family, isolated: bool) {
        self.flag(family).store(isolated, Ordering::SeqCst);
    }

    /// Lab PR 217: whether `family` is isolated, as its table was last read
    /// back.
    pub fn is_isolated(&self, family: Family) -> bool {
        self.flag(family).load(Ordering::SeqCst)
    }

    /// Lab PR 217: run each iptables / ip6tables invocation with `timeout`
    /// instead of [`EXTERNAL_CMD_TIMEOUT`] (tests).
    #[cfg(test)]
    fn with_cmd_timeout(mut self, timeout: std::time::Duration) -> Self {
        self.cmd_timeout = timeout;
        self
    }

    /// Build the ruleset to feed `iptables-restore`: the base
    /// `combat-rules.v4` with the management carve-out (Beta Step 4b)
    /// spliced in ahead of the catch-all DROP. Returns the rendered
    /// ruleset and the list of IPv4 CIDRs actually carved out (for
    /// logging). Re-reads the allow file every call — never cached.
    pub fn build_engaged_ruleset(&self) -> Result<(String, Vec<String>)> {
        use nn_proto::admin_signed_payload::OverlayKind;
        let base = self.trusted_source(
            OverlayKind::CombatRulesV4,
            &self.rules_path,
            BUILTIN_RULES_V4,
        );

        let load = self.trusted_allow();
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
                "COMBAT carve-out: skipping an allow entry, malformed or too wide (fail-secure — \
                 entry ignored; external audit NN-AUD-095)"
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
        use nn_proto::admin_signed_payload::OverlayKind;
        // External audit DEP-003: a missing v6 ruleset no longer leaves
        // IPv6 open when the built-in one can be applied (with a gate).
        if self.gate.is_none() && !self.rules_path_v6.exists() {
            return Ok(None);
        }
        let base = self.trusted_source(
            OverlayKind::CombatRulesV6,
            &self.rules_path_v6,
            BUILTIN_RULES_V6,
        );
        // The allow file's read errors + malformed-line warnings were
        // already surfaced by the v4 builder (engage() runs v4 first);
        // here we just take the validated entries.
        let load = self.trusted_allow();
        let accept_block = combat_allow::generate_accept_rules_v6(&load.entries, COMBAT_CHAIN);
        let carved = combat_allow::ipv6_raw(&load.entries);
        Ok(Some((splice_carveout(&base, &accept_block), carved)))
    }

    /// The management carve-out, vouched for like the rulesets: an
    /// unsigned change spares no network (the built-in list is empty).
    ///
    /// External audit NN-AUD-095: with a gate, the file is read only
    /// through it. A file absent at an `exists()` check used to be read
    /// ungated, so one created between the check and the read was applied
    /// unsigned; the gate already answers a missing file with the built-in
    /// list.
    pub fn trusted_allow(&self) -> combat_allow::AllowLoad {
        use nn_proto::admin_signed_payload::OverlayKind;
        if self.gate.is_none() {
            return combat_allow::load_allow_cidrs(&self.allow_cidrs_path);
        }
        let text = self.trusted_source(
            OverlayKind::CombatAllow,
            &self.allow_cidrs_path,
            BUILTIN_ALLOW,
        );
        combat_allow::parse_allow_text(&text)
    }

    /// Beta Step 4a: tear down a STALE COMBAT chain left over from a
    /// crash. Called once at boot when posture is `OBSERVING` — if the
    /// `NORTHNARROW_COMBAT` chain exists, the agent died mid-COMBAT and
    /// systemd/the watchdog restarted it; the orphaned chain would
    /// otherwise keep the host isolated with no live posture state
    /// backing it (the B3 split-brain). Reuses the idempotent teardown
    /// path; a no-op (and cheap) when no chain is present.
    ///
    /// Lab PR 217: a teardown that does not leave the tables clear, read
    /// back, is an `Err`, and the family whose table still holds the chain
    /// is reported isolated (`nn-admin status`) — the boot state used to
    /// say "not isolated" whatever the table held. A signed `unlock` retries
    /// it.
    pub fn reconcile_stale_chain(&self) -> Result<ReconcileOutcome> {
        let v4 = probe_chain(&self.iptables_bin, self.cmd_timeout)
            .with_context(|| format!("probing for stale {COMBAT_CHAIN} v4 chain"))?;
        // BUG-031: a mid-COMBAT crash can leave a stale v6 chain too —
        // probe it INDEPENDENTLY so a v6-only orphan is still detected
        // (the v6 edition of the B3 split-brain). Best-effort: ip6tables
        // absent ⇒ treat as no v6 chain.
        let v6 = probe_chain(&self.ip6tables_bin, self.cmd_timeout).unwrap_or(None);
        if v4.is_none() && v6.is_none() {
            // Neither chain present (the normal clean-boot case).
            return Ok(ReconcileOutcome {
                chain_existed: false,
                rules_removed: 0,
            });
        }
        let rules_removed = v4.unwrap_or(0) + v6.unwrap_or(0);
        let report = self.tear_down_and_verify();
        if !report.complete() {
            return Err(anyhow!(
                "tearing down stale COMBAT chain(s): {}",
                report.summary("cleared")
            ));
        }
        Ok(ReconcileOutcome {
            chain_existed: true,
            rules_removed,
        })
    }

    /// Idempotent teardown shared by [`Self::release`] and
    /// [`Self::reconcile_stale_chain`], on BOTH tables (BUG-031), each read
    /// back afterwards (lab PR 217). A host without `ip6tables` (or without
    /// an IPv6 filter table) releases cleanly: its v6 leg is unavailable,
    /// not failed — unless this agent had isolated it.
    fn tear_down_and_verify(&self) -> IsolationReport {
        IsolationReport {
            v4: self.release_family(Family::V4),
            v6: self.release_family(Family::V6),
        }
    }

    /// One family's teardown, then its table read back: [`FamilyOutcome::Done`]
    /// only when neither the chain nor a jump into it is listed. The state
    /// follows the read-back: still listed is still isolated.
    fn release_family(&self, family: Family) -> FamilyOutcome {
        let (_, bin) = self.bins(family);
        let was = self.is_isolated(family);
        if let Err(e) = bin.command() {
            let why = format!("{e:#}");
            return if was {
                FamilyOutcome::Failed(format!(
                    "{why} — the isolation applied earlier cannot be removed"
                ))
            } else {
                FamilyOutcome::Unavailable(why)
            };
        }
        let torn = tear_down_one(bin, self.cmd_timeout);
        match read_back_cleared(bin, self.cmd_timeout) {
            Cleared::Clear => {
                self.set_isolated(family, false);
                if let Err(e) = torn {
                    // The read-back is the truth: e.g. a `-X` that raced a
                    // concurrent delete.
                    info!(
                        family = family.label(),
                        error = %format!("{e:#}"),
                        "COMBAT release: a teardown step failed, but the table is clear"
                    );
                }
                FamilyOutcome::Done
            }
            Cleared::Present { left, isolating } => {
                // The state says whether the family still drops: a chain
                // left without any jump into it (a `-X` refused after the
                // jumps went) is not a release, and not an isolation either.
                self.set_isolated(family, isolating);
                let step = torn.err().map(|e| format!("{e:#}; ")).unwrap_or_default();
                let effect = if isolating {
                    "the family is still isolated"
                } else {
                    "the family no longer drops (the chain is not jumped to, or no longer \
                     reaches its DROP)"
                };
                FamilyOutcome::Failed(format!("{step}read back: {left} — {effect}"))
            }
            // The IPv4 table always exists where COMBAT runs: one that
            // cannot be listed is a failure — nothing shows it is clear. An
            // IPv6 one the kernel does not have is unavailable, unless this
            // agent had isolated it.
            Cleared::Unreadable(why) if was || family == Family::V4 => {
                let step = torn.err().map(|e| format!("{e:#}; ")).unwrap_or_default();
                FamilyOutcome::Failed(format!(
                    "{step}the table cannot be read back ({why}) — nothing shows the COMBAT \
                     chain is gone"
                ))
            }
            Cleared::Unreadable(why) => FamilyOutcome::Unavailable(why),
        }
    }

    /// Tear down the combat ruleset. Requires a verified
    /// [`UnlockToken`] — the type system enforces that this method
    /// can only be reached via the Ed25519 admin path.
    ///
    /// The spec snippet `iptables -F && iptables -X` is incomplete: `-X`
    /// refuses to remove a chain still referenced from
    /// `INPUT`/`OUTPUT`/`FORWARD`, so we delete the jump rules in those
    /// base chains first. Each command tolerates "rule does not exist" /
    /// "no chain by that name" stderr so calling `release()` on an
    /// already-released isolator is a no-op rather than an error.
    ///
    /// Lab PR 217 (NN-AUD-243 residue, capability C17): the outcome is
    /// what the tables hold afterwards, read back per family — the caller
    /// answers the operator from it ([`IsolationReport::complete`]). An exit
    /// status of `iptables -X` used to be the whole proof, and the release
    /// hook dropped even that.
    ///
    /// `pub` so the binary crate (`main.rs`) can construct the
    /// `combat_release_hook` closure. The capability invariant is
    /// unchanged: `release` requires an [`UnlockToken`] by value and
    /// `mint_unlock_token` is still `pub(in crate::anti_tamper)`,
    /// so no external caller can fabricate a token to slip past this.
    pub fn release(&self, _: UnlockToken) -> IsolationReport {
        let report = self.tear_down_and_verify();
        if report.complete() {
            info!(
                target: "anti_tamper.network_isolation.released",
                outcome = %report.summary("cleared"),
                "COMBAT: network isolation released (tables read back clear)"
            );
        } else {
            error!(
                target: "anti_tamper.network_isolation.released",
                outcome = %report.summary("cleared"),
                "COMBAT: network isolation NOT released — a table still holds the COMBAT chain, \
                 or cannot be read back"
            );
        }
        report
    }

    /// Either family isolated (lab PR 217: [`Self::is_isolated`] per family).
    pub fn is_engaged(&self) -> bool {
        self.is_isolated(Family::V4) || self.is_isolated(Family::V6)
    }
}

/// What a family's table holds of COMBAT after a teardown.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Cleared {
    /// Neither the chain nor a jump into it is listed.
    Clear,
    /// What is still listed (`left`), and whether it still isolates: the
    /// chain reaches its catch-all DROP and INPUT and OUTPUT jump into it.
    Present { left: String, isolating: bool },
    /// The table could not be listed (no such table, the binary failed).
    Unreadable(String),
}

/// Lab PR 217: read `bin`'s table back after a teardown.
fn read_back_cleared(bin: &Bin, timeout: std::time::Duration) -> Cleared {
    let chain = match list_rules(bin, COMBAT_CHAIN, timeout) {
        Ok(c) => c,
        Err(e) => return Cleared::Unreadable(format!("{e:#}")),
    };
    let mut left = Vec::new();
    let mut unreadable = Vec::new();
    let mut jumps: Vec<(&str, Option<usize>)> = Vec::new();
    if chain.is_some() {
        left.push(format!("the {COMBAT_CHAIN} chain is still listed"));
    }
    for base in ["INPUT", "OUTPUT", "FORWARD"] {
        match list_rules(bin, base, timeout) {
            Ok(Some(listing)) => {
                let n = count_jumps(&listing);
                if n > 0 {
                    left.push(format!("{n} jump(s) into {COMBAT_CHAIN} still in {base}"));
                }
                jumps.push((base, Some(n)));
            }
            Ok(None) => {
                unreadable.push(format!("{base} could not be listed"));
                jumps.push((base, None));
            }
            Err(e) => return Cleared::Unreadable(format!("{e:#}")),
        }
    }
    if !left.is_empty() {
        // INPUT and OUTPUT are what every COMBAT ruleset jumps from
        // (`validate_ruleset`).
        let required: Vec<(&str, Option<usize>)> =
            jumps.into_iter().filter(|(b, _)| *b != "FORWARD").collect();
        Cleared::Present {
            left: left.join("; "),
            isolating: isolation_gaps(chain.as_deref(), &required).is_ok(),
        }
    } else if !unreadable.is_empty() {
        Cleared::Unreadable(unreadable.join("; "))
    } else {
        Cleared::Clear
    }
}

/// Run `iptables` with `args` and treat non-zero exits as success
/// when stderr indicates the rule or chain was already absent. This
/// makes [`NetworkIsolator::release`] idempotent without needing a
/// separate "is this chain present?" probe per command.
fn run_iptables_idempotent(bin: &Bin, args: &[&str], timeout: std::time::Duration) -> Result<()> {
    let (mut cmd, _) = bin.command()?;
    cmd.args(args);
    let what = format!("{bin} {}", args.join(" "));
    // Lab PR 217: waited for at most `timeout`.
    let output =
        run_bounded(cmd, None, timeout, &what).with_context(|| format!("running {what}"))?;
    if output.status.success() {
        return Ok(());
    }
    let stderr = String::from_utf8_lossy(&output.stderr);
    if already_gone(&stderr) {
        return Ok(());
    }
    Err(anyhow!(
        "{bin} {} exited {}: {}",
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
fn tear_down_one(bin: &Bin, timeout: std::time::Duration) -> Result<()> {
    for base in ["INPUT", "OUTPUT", "FORWARD"] {
        remove_jumps(bin, base, timeout)
            .with_context(|| format!("removing {COMBAT_CHAIN} jump from {base}"))?;
    }
    run_iptables_idempotent(bin, &["-F", COMBAT_CHAIN], timeout)
        .with_context(|| format!("flushing chain {COMBAT_CHAIN}"))?;
    run_iptables_idempotent(bin, &["-X", COMBAT_CHAIN], timeout)
        .with_context(|| format!("deleting chain {COMBAT_CHAIN}"))?;
    Ok(())
}

/// Probe whether `COMBAT_CHAIN` exists on `bin`'s table.
/// `Ok(Some(n))` = present with `n` `-A` rules, `Ok(None)` = absent
/// (non-zero exit), `Err` = the binary could not be run (BUG-031: the
/// v6 caller treats that as "no v6 chain").
fn probe_chain(bin: &Bin, timeout: std::time::Duration) -> Result<Option<usize>> {
    Ok(list_rules(bin, COMBAT_CHAIN, timeout)?.map(|listed| count_chain_rules(&listed)))
}

/// `bin -S chain`: the rules listed, `None` when the listing exits non-zero
/// (no such chain); `Err` when the binary could not be run, or did not
/// answer within `timeout` (lab PR 217).
fn list_rules(bin: &Bin, chain: &str, timeout: std::time::Duration) -> Result<Option<String>> {
    let (mut cmd, _) = bin.command()?;
    cmd.args(["-S", chain]);
    let what = format!("{bin} -S {chain}");
    let listed =
        run_bounded(cmd, None, timeout, &what).with_context(|| format!("running {what}"))?;
    if !listed.status.success() {
        return Ok(None);
    }
    Ok(Some(String::from_utf8_lossy(&listed.stdout).into_owned()))
}

/// Lab follow-up (lab PR 188): the base chains the applied ruleset jumps
/// from into [`COMBAT_CHAIN`] — INPUT and OUTPUT always (what
/// [`validate_ruleset`] requires of any ruleset COMBAT applies, the built-in
/// one included), FORWARD when the ruleset declares its jump.
fn jump_bases(ruleset: &str) -> Vec<&'static str> {
    let jump = format!("-j {COMBAT_CHAIN}");
    let declared = |base: &str| {
        ruleset.lines().map(str::trim).any(|l| {
            !l.starts_with('#') && l.ends_with(&jump) && l.split_whitespace().nth(1) == Some(base)
        })
    };
    ["INPUT", "OUTPUT", "FORWARD"]
        .into_iter()
        .filter(|base| *base != "FORWARD" || declared(base))
        .collect()
}

/// Lab follow-up (lab PR 188): what keeps a restored COMBAT ruleset from
/// isolating, read from `iptables -S`: `chain` is the listing of
/// [`COMBAT_CHAIN`] (`None`: no such chain), `jumps` the jumps into it
/// counted per base chain (`None`: the base chain could not be listed).
/// The chain must reach its catch-all DROP — no unconditional ACCEPT or
/// RETURN ahead of it — and every base chain must jump into it. `Err`
/// names each gap.
fn isolation_gaps(
    chain: Option<&str>,
    jumps: &[(&str, Option<usize>)],
) -> std::result::Result<(), String> {
    let mut gaps = Vec::new();
    match chain {
        None => gaps.push(format!("no {COMBAT_CHAIN} chain")),
        Some(listing) => {
            let prefix = format!("-A {COMBAT_CHAIN} -j ");
            let unconditional = listing
                .lines()
                .filter_map(|l| l.trim().strip_prefix(prefix.as_str()))
                .find(|target| matches!(*target, "DROP" | "ACCEPT" | "RETURN"));
            match unconditional {
                Some("DROP") => {}
                Some(other) => gaps.push(format!(
                    "an unconditional {other} ahead of the catch-all DROP in {COMBAT_CHAIN}"
                )),
                None => gaps.push(format!("no catch-all DROP in {COMBAT_CHAIN}")),
            }
        }
    }
    for (base, n) in jumps {
        match n {
            None => gaps.push(format!("{base} could not be listed")),
            Some(0) => gaps.push(format!("no {base} jump into {COMBAT_CHAIN}")),
            Some(_) => {}
        }
    }
    if gaps.is_empty() {
        Ok(())
    } else {
        Err(gaps.join("; "))
    }
}

/// Lab follow-up (lab PR 188): read the table back after a restore of
/// `ruleset` ([`isolation_gaps`]). `Err` names the gaps, or why the table
/// could not be read (not isolated either: nothing shows that it is).
fn verify_isolation(
    bin: &Bin,
    ruleset: &str,
    timeout: std::time::Duration,
) -> std::result::Result<(), String> {
    let read = |chain: &str| list_rules(bin, chain, timeout).map_err(|e| format!("{e:#}"));
    let chain = read(COMBAT_CHAIN)?;
    let mut jumps = Vec::new();
    for base in jump_bases(ruleset) {
        jumps.push((base, read(base)?.map(|listed| count_jumps(&listed))));
    }
    isolation_gaps(chain.as_deref(), &jumps)
}

/// BUG-041 — after an additive `-I … 1` engage, ensure exactly ONE
/// `-j COMBAT_CHAIN` jump remains in each base chain (a re-engage would
/// otherwise stack a duplicate). Windowless: only ever DELETEs extras,
/// leaving >= 1 jump in place at all times — never a no-jump moment.
/// Must run AFTER a successful restore (so the count is >= 1).
fn dedup_jumps(bin: &Bin, timeout: std::time::Duration) -> Result<()> {
    for base in ["INPUT", "OUTPUT", "FORWARD"] {
        let Some(n) = list_jumps(bin, base, timeout)
            .with_context(|| format!("listing {base} to dedup {COMBAT_CHAIN} jumps"))?
        else {
            continue; // base chain unreadable — skip (best-effort)
        };
        // Delete (n - 1) extras, keeping exactly one. `1..n` is empty when
        // n <= 1, so this never deletes below one jump.
        for _ in 1..n {
            run_iptables_idempotent(bin, &["-D", base, "-j", COMBAT_CHAIN], timeout)
                .with_context(|| format!("removing duplicate {COMBAT_CHAIN} jump from {base}"))?;
        }
    }
    Ok(())
}

/// The `-j COMBAT_CHAIN` jumps in `base` (`iptables -S base`); `None` when
/// the listing exits non-zero (base chain unreadable).
fn list_jumps(bin: &Bin, base: &str, timeout: std::time::Duration) -> Result<Option<usize>> {
    Ok(list_rules(bin, base, timeout)?.map(|listed| count_jumps(&listed)))
}

/// External audit ATP-006 (NN-AUD-259): remove EVERY jump into
/// `COMBAT_CHAIN` from `base` — one per jump `-S` lists, at least one
/// (idempotent: "already gone" is success). A dedup that failed at engage
/// leaves a second jump, and `-X` refuses a chain still referenced: a
/// single `-D` let the release flush the chain (the host back on the
/// network) and then fail, with the isolation still reported.
fn remove_jumps(bin: &Bin, base: &str, timeout: std::time::Duration) -> Result<()> {
    let n = list_jumps(bin, base, timeout)
        .ok()
        .flatten()
        .unwrap_or(1)
        .max(1);
    for _ in 0..n {
        run_iptables_idempotent(bin, &["-D", base, "-j", COMBAT_CHAIN], timeout)?;
    }
    Ok(())
}

/// Count `-j COMBAT_CHAIN` jump rules in `iptables -S <base>` output.
fn count_jumps(iptables_s_output: &str) -> usize {
    let needle = format!("-j {COMBAT_CHAIN}");
    iptables_s_output
        .lines()
        .filter(|l| l.contains(&needle))
        .count()
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
pub fn splice_carveout(base: &str, accept_block: &str) -> String {
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
/// exit as a hard failure. Returns the file that ran (the log names it).
/// Lab PR 217: waited for at most `timeout`.
fn run_iptables_restore_data(
    bin: &Bin,
    rules_data: &[u8],
    timeout: std::time::Duration,
) -> Result<PathBuf> {
    let (mut cmd, exe) = bin.command()?;
    // BUG-041: ADDITIVE — never flush the operator's table. The dump
    // rebuilds only our own declared chain (`:NORTHNARROW_COMBAT`)
    // and inserts our jumps (`-I … 1`); every operator chain/rule is
    // left untouched.
    cmd.arg("--noflush");
    let what = format!("{bin} ({})", exe.display());
    let output = run_bounded(cmd, Some(rules_data), timeout, &what)
        .with_context(|| format!("running {what}"))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(anyhow!(
            "{bin} ({}) exited {}: {}",
            exe.display(),
            output.status,
            stderr.trim()
        ));
    }
    Ok(exe)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Stdio;

    // BUG-031: the idempotent-teardown classifier must recognize the
    // "already gone" messages across backends — including nf_tables'
    // "Chain '…' does not exist" (the v4/v6-absent-table case) — while
    // NOT swallowing a real "resource busy" (chain still referenced).
    #[test]
    fn already_gone_recognizes_backend_messages() {
        assert!(already_gone(
            "iptables: Bad rule (does a matching rule exist in that chain?)."
        ));
        assert!(already_gone(
            "iptables: No chain/target/match by that name."
        ));
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
        assert_eq!(
            count_jumps(two),
            2,
            "two NN jumps; operator ACCEPT not counted"
        );
        assert_eq!(count_jumps("-A INPUT -j NORTHNARROW_COMBAT\n"), 1);
        assert_eq!(count_jumps("-P INPUT ACCEPT\n-A INPUT -j ACCEPT\n"), 0);
    }

    /// Absolute path to `configs/combat-rules.v4` in the repo. Tests
    /// run with `CARGO_MANIFEST_DIR` set to the agent crate root.
    fn combat_rules_path() -> PathBuf {
        PathBuf::from(env!("NN_REPO_ROOT"))
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
        mock_script("#!/bin/sh\ncat >/dev/null 2>&1\nexit 0\n")
    }

    /// A mock binary running the shell `body` (see [`mock_restore_bin`]).
    fn mock_script(body: &str) -> Option<PathBuf> {
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
        f.write_all(body.as_bytes()).ok()?;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).ok()?;
        drop(f);
        // ETXTBSY guard: the test harness runs tests on parallel threads.
        // If ANOTHER thread fork()s (Command::spawn) while our write fd
        // above is still open, the child inherits that fd until it
        // exec()s — and the kernel refuses to exec a file that anyone
        // holds open for writing ("Text file busy"). Probe-exec the
        // (harmless) script until that transient window has closed so
        // the real test spawn never trips over it.
        for _ in 0..200 {
            match Command::new(&path)
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()
            {
                Ok(_) => break,
                Err(e) if e.raw_os_error() == Some(libc::ETXTBSY) => {
                    std::thread::sleep(std::time::Duration::from_millis(5));
                }
                Err(_) => return None,
            }
        }
        Some(path)
    }

    /// A mock `iptables` whose `-S` lists the table an applied COMBAT
    /// ruleset leaves (the chain with its catch-all DROP, one jump per base
    /// chain) and whose other calls succeed: the read-back after the restore
    /// (lab PR 188) finds the isolation in place.
    fn mock_engaged_iptables() -> Option<PathBuf> {
        mock_script(
            "#!/bin/sh\n\
             case \"$1\" in\n\
             -S) case \"$2\" in\n\
                 NORTHNARROW_COMBAT) echo '-N NORTHNARROW_COMBAT'; echo '-A NORTHNARROW_COMBAT -i lo -j ACCEPT';\n\
                     echo '-A NORTHNARROW_COMBAT -j DROP' ;;\n\
                 *) echo \"-P $2 ACCEPT\"; echo \"-A $2 -j NORTHNARROW_COMBAT\" ;;\n\
                 esac ;;\n\
             esac\n\
             exit 0\n",
        )
    }

    fn mock_success_isolator() -> Option<NetworkIsolator> {
        let restore = mock_restore_bin()?;
        let iptables = mock_engaged_iptables()?;
        Some(NetworkIsolator::new_with_bin(combat_rules_path(), restore, iptables).unwrap())
    }

    /// Lab PR 217: the reason a family failed, or a panic naming the report.
    fn failure(outcome: &FamilyOutcome) -> String {
        match outcome {
            FamilyOutcome::Failed(why) => why.clone(),
            other => panic!("expected a failure, got {other:?}"),
        }
    }

    /// Lab PR 217: a fake filter table — an `iptables-restore` and an
    /// `iptables` that keep the COMBAT chain and the jumps into it in a
    /// directory, with the failures a test asks for (`fail("restore")`,
    /// `fail("X")`, `fail("D")`, `fail("all")`, `fail("hang")`).
    struct FakeTable {
        dir: tempfile::TempDir,
        restore: PathBuf,
        iptables: PathBuf,
    }

    impl FakeTable {
        fn new() -> Option<Self> {
            let dir = tempfile::tempdir().ok()?;
            let st = dir.path().display().to_string();
            let restore = mock_script(&format!(
                "#!/bin/sh\n\
                 st={st}\n\
                 cat >/dev/null\n\
                 [ -f \"$st/fail_hang\" ] && sleep 30\n\
                 [ -f \"$st/fail_restore\" ] && {{ echo 'iptables-restore: line 4 failed' >&2; exit 1; }}\n\
                 printf -- '-A NORTHNARROW_COMBAT -i lo -j ACCEPT\\n-A NORTHNARROW_COMBAT -j DROP\\n' > \"$st/chain\"\n\
                 for b in INPUT OUTPUT FORWARD; do n=$(cat \"$st/$b\" 2>/dev/null || echo 0); echo $((n+1)) > \"$st/$b\"; done\n\
                 exit 0\n"
            ))?;
            let iptables = mock_script(&format!(
                "#!/bin/sh\n\
                 st={st}\n\
                 busy='iptables v1.8.10 (nf_tables): CHAIN_DEL failed (Device or resource busy): chain NORTHNARROW_COMBAT'\n\
                 [ -f \"$st/fail_hang\" ] && sleep 30\n\
                 [ -f \"$st/fail_all\" ] && {{ echo \"iptables: can't initialize iptables table 'filter'\" >&2; exit 4; }}\n\
                 jumps() {{ cat \"$st/$1\" 2>/dev/null || echo 0; }}\n\
                 case \"$1\" in\n\
                 -S) if [ \"$2\" = NORTHNARROW_COMBAT ]; then\n\
                       [ -f \"$st/chain\" ] || {{ echo 'iptables: No chain/target/match by that name.' >&2; exit 1; }}\n\
                       echo '-N NORTHNARROW_COMBAT'; cat \"$st/chain\"; exit 0\n\
                     fi\n\
                     echo \"-P $2 ACCEPT\"; i=0; n=$(jumps \"$2\")\n\
                     while [ $i -lt $n ]; do echo \"-A $2 -j NORTHNARROW_COMBAT\"; i=$((i+1)); done; exit 0 ;;\n\
                 -D) [ -f \"$st/fail_D\" ] && {{ echo 'iptables: Resource temporarily unavailable.' >&2; exit 4; }}\n\
                     n=$(jumps \"$2\"); if [ \"$n\" -gt 0 ]; then echo $((n-1)) > \"$st/$2\"; exit 0; fi\n\
                     echo 'iptables: Bad rule (does a matching rule exist in that chain?).' >&2; exit 1 ;;\n\
                 -F) [ -f \"$st/chain\" ] || {{ echo 'iptables: No chain/target/match by that name.' >&2; exit 1; }}\n\
                     : > \"$st/chain\"; exit 0 ;;\n\
                 -X) [ -f \"$st/fail_X\" ] && {{ echo \"$busy\" >&2; exit 1; }}\n\
                     for b in INPUT OUTPUT FORWARD; do [ \"$(jumps $b)\" -eq 0 ] || {{ echo \"$busy\" >&2; exit 1; }}; done\n\
                     [ -f \"$st/chain\" ] || {{ echo 'iptables: No chain/target/match by that name.' >&2; exit 1; }}\n\
                     rm -f \"$st/chain\"; exit 0 ;;\n\
                 esac\n\
                 exit 0\n"
            ))?;
            // `mock_script` ran each once (its ETXTBSY probe): an empty
            // table again.
            for f in ["chain", "INPUT", "OUTPUT", "FORWARD"] {
                let _ = std::fs::remove_file(dir.path().join(f));
            }
            Some(Self {
                dir,
                restore,
                iptables,
            })
        }

        fn fail(&self, what: &str) {
            std::fs::write(self.dir.path().join(format!("fail_{what}")), "").unwrap();
        }

        fn heal(&self, what: &str) {
            let _ = std::fs::remove_file(self.dir.path().join(format!("fail_{what}")));
        }

        /// A COMBAT chain left in the table, `jumps` jumps per base chain.
        fn seed(&self, jumps: usize) {
            std::fs::write(
                self.dir.path().join("chain"),
                "-A NORTHNARROW_COMBAT -j DROP\n",
            )
            .unwrap();
            for b in ["INPUT", "OUTPUT", "FORWARD"] {
                std::fs::write(self.dir.path().join(b), format!("{jumps}\n")).unwrap();
            }
        }

        fn has_chain(&self) -> bool {
            self.dir.path().join("chain").exists()
        }

        fn jumps(&self, base: &str) -> usize {
            std::fs::read_to_string(self.dir.path().join(base))
                .map(|s| s.trim().parse().unwrap())
                .unwrap_or(0)
        }
    }

    /// Lab PR 217: an isolator over two fake tables, v4 and v6.
    fn fake_isolator() -> Option<(NetworkIsolator, FakeTable, FakeTable)> {
        let (v4, v6) = (FakeTable::new()?, FakeTable::new()?);
        let iso = NetworkIsolator::new_with_bin(
            combat_rules_path(),
            v4.restore.clone(),
            v4.iptables.clone(),
        )
        .unwrap();
        let iso = NetworkIsolator {
            restore_bin_v6: Bin::Fixed(v6.restore.clone()),
            ip6tables_bin: Bin::Fixed(v6.iptables.clone()),
            ..iso
        };
        Some((iso, v4, v6))
    }

    /// Lab PR 217 (capability C18): the state is per IP family — an
    /// `ip6tables-restore` that fails leaves IPv4 isolated and IPv6 reported
    /// NOT isolated, and the report says so. One flag for both said the host
    /// isolated with IPv6 open, and the v6 failure was only a WARN.
    #[test]
    fn a_failing_ip6tables_is_reported_per_family() {
        let Some((iso, v4, v6)) = fake_isolator() else {
            return;
        };
        v6.fail("restore");
        let report = iso.engage();
        assert!(report.engaged(), "{report:?}");
        assert!(!report.complete(), "a family failed: {report:?}");
        assert_eq!(report.v4, FamilyOutcome::Done);
        assert!(failure(&report.v6).contains("line 4 failed"), "{report:?}");
        assert!(iso.is_isolated(Family::V4));
        assert!(!iso.is_isolated(Family::V6), "IPv6 is NOT isolated");
        assert!(iso.is_engaged(), "either family");
        assert!(report.summary("isolated").contains("IPv6: FAILED"));
        assert!(v4.has_chain() && !v6.has_chain());
        // the retry, once ip6tables works: both isolated, one jump each
        v6.heal("restore");
        let report = iso.engage();
        assert!(report.complete(), "{report:?}");
        assert!(iso.is_isolated(Family::V6));
        assert_eq!(
            v4.jumps("INPUT"),
            1,
            "the re-engage's duplicate jump is trimmed"
        );
    }

    /// Lab PR 217 (NN-AUD-243 residue): a teardown that leaves the chain in
    /// the table is not a release: the read-back says what is left, and only
    /// a later release that clears it reports it clear. The state says
    /// whether the family still drops — the jumps refused (`-D`) leave it
    /// isolated; the chain refused (`-X`) after the jumps went leaves it
    /// listed but no longer dropping. The release used to be judged by exit
    /// codes, and the hook dropped even that.
    #[test]
    fn a_teardown_that_leaves_the_chain_is_not_a_release() {
        let Some((iso, v4, v6)) = fake_isolator() else {
            return;
        };
        assert!(iso.engage().complete());
        v4.fail("D");
        let report = iso.release(mint_unlock_token());
        assert!(!report.complete(), "{report:?}");
        let why = failure(&report.v4);
        assert!(why.contains("Resource temporarily unavailable"), "{why}");
        assert!(why.contains("still isolated"), "{why}");
        assert_eq!(report.v6, FamilyOutcome::Done);
        assert!(iso.is_isolated(Family::V4), "the jumps are in: isolated");
        assert!(!iso.is_isolated(Family::V6));
        assert!(v4.has_chain() && !v6.has_chain());
        v4.heal("D");
        v4.fail("X");
        let report = iso.release(mint_unlock_token());
        let why = failure(&report.v4);
        assert!(why.contains("Device or resource busy"), "{why}");
        assert!(why.contains("chain is still listed"), "{why}");
        assert!(why.contains("no longer drops"), "{why}");
        assert!(
            !iso.is_isolated(Family::V4),
            "listed without a jump: not an isolation"
        );
        assert!(v4.has_chain());
        v4.heal("X");
        let report = iso.release(mint_unlock_token());
        assert!(report.complete(), "{report:?}");
        assert!(!iso.is_engaged());
        assert!(!v4.has_chain());
        // and a v6 teardown failure is a failure too (it was a WARN)
        assert!(iso.engage().complete());
        v6.fail("D");
        let report = iso.release(mint_unlock_token());
        assert!(failure(&report.v6).contains("still isolated"), "{report:?}");
        assert!(!iso.is_isolated(Family::V4) && iso.is_isolated(Family::V6));
    }

    /// Lab PR 217 (capability C18): every iptables / ip6tables invocation is
    /// bounded — a binary that hangs fails the step at the deadline, it does
    /// not hold the ladder's worker.
    #[test]
    fn a_hung_iptables_times_out() {
        let Some((iso, v4, v6)) = fake_isolator() else {
            return;
        };
        let iso = iso.with_cmd_timeout(std::time::Duration::from_millis(300));
        v4.fail("hang");
        v6.fail("hang");
        let start = std::time::Instant::now();
        let report = iso.engage();
        assert!(!report.engaged());
        assert!(
            failure(&report.v4).contains("did not exit within"),
            "{report:?}"
        );
        let report = iso.release(mint_unlock_token());
        assert!(!report.complete());
        assert!(
            start.elapsed() < std::time::Duration::from_secs(20),
            "bounded: {:?}",
            start.elapsed()
        );
    }

    /// Lab PR 217: a stale chain the boot teardown cannot remove is an
    /// error, and the family is reported isolated — the boot state said
    /// "not isolated" whatever the table held.
    #[test]
    fn a_stale_chain_left_in_place_is_reported_isolated() {
        let Some((iso, v4, _v6)) = fake_isolator() else {
            return;
        };
        v4.seed(1);
        v4.fail("D");
        let err = format!("{:#}", iso.reconcile_stale_chain().unwrap_err());
        assert!(err.contains("IPv4: FAILED"), "{err}");
        assert!(iso.is_isolated(Family::V4));
        v4.heal("D");
        let out = iso.reconcile_stale_chain().expect("cleared");
        assert!(!out.chain_existed || out.rules_removed <= 1);
        assert!(!iso.is_engaged());
    }

    /// Lab follow-up (lab PR 188): a restore that exits 0 and applies
    /// nothing — the `iptables-restore` link pointed at `/usr/bin/true`
    /// (here a script that drains its stdin and exits 0) — is not an
    /// isolation: `engage` fails naming the gaps, and the host is not
    /// reported isolated. Before, `engage` was `Ok` and `is_engaged` true.
    #[test]
    fn a_restore_that_applies_nothing_is_not_an_isolation() {
        let (Some(restore), Some(no_chain)) = (
            mock_restore_bin(),
            mock_script(
                "#!/bin/sh\n\
                 case \"$1 $2\" in\n\
                 '-S NORTHNARROW_COMBAT') echo \"iptables: chain 'NORTHNARROW_COMBAT' does not exist\" >&2; exit 1 ;;\n\
                 -S*) echo \"-P $2 ACCEPT\"; echo \"-A $2 -p tcp --dport 22 -j ACCEPT\" ;;\n\
                 esac\n\
                 exit 0\n",
            ),
        ) else {
            return;
        };
        let iso =
            NetworkIsolator::new_with_bin(combat_rules_path(), restore.clone(), no_chain).unwrap();
        let err = failure(&iso.engage().v4);
        assert!(err.contains("NOT isolated"), "{err}");
        for gap in [
            "no NORTHNARROW_COMBAT chain",
            "no INPUT jump",
            "no OUTPUT jump",
            "no FORWARD jump",
        ] {
            assert!(err.contains(gap), "{gap}: {err}");
        }
        assert!(!iso.is_engaged());
        // `iptables` itself pointed at a no-op: every listing empty
        let truebin = PathBuf::from("/bin/true");
        if truebin.exists() {
            let iso = NetworkIsolator::new_with_bin(combat_rules_path(), restore, truebin).unwrap();
            let err = failure(&iso.engage().v4);
            assert!(err.contains("no catch-all DROP"), "{err}");
            assert!(!iso.is_engaged());
        }
    }

    /// Lab follow-up (lab PR 188): an engaged isolator whose re-engage finds
    /// the table emptied (flushed, and the restore a no-op) no longer
    /// reports the host isolated.
    #[test]
    fn a_reengage_that_finds_the_table_empty_clears_the_state() {
        let Some(iso) = mock_success_isolator() else {
            return;
        };
        assert!(iso.engage().complete());
        assert!(iso.is_engaged());
        let truebin = PathBuf::from("/bin/true");
        if !truebin.exists() {
            return;
        }
        let iso = NetworkIsolator {
            iptables_bin: Bin::Fixed(truebin),
            ..iso
        };
        assert!(!iso.engage().engaged());
        assert!(
            !iso.is_isolated(Family::V4),
            "the host is no longer isolated"
        );
    }

    /// Lab follow-up (lab PR 188): the v6 leg is read back too, and stays
    /// best-effort — a v6 table without the ruleset leaves the v4 isolation
    /// engaged. Lab PR 217: and it is reported, per family.
    #[test]
    fn a_v6_table_without_the_ruleset_keeps_the_v4_isolation() {
        let Some(iso) = mock_success_isolator() else {
            return;
        };
        let truebin = PathBuf::from("/bin/true");
        if !truebin.exists() {
            return;
        }
        let iso = NetworkIsolator {
            ip6tables_bin: Bin::Fixed(truebin),
            ..iso
        };
        let report = iso.engage();
        assert!(report.engaged(), "v4 isolated: {report:?}");
        assert!(!report.complete());
        assert!(failure(&report.v6).contains("no catch-all DROP"));
        assert!(iso.is_isolated(Family::V4) && !iso.is_isolated(Family::V6));
    }

    /// Lab follow-up (lab PR 188): what the read-back accepts and refuses.
    #[test]
    fn isolation_gaps_read_the_listing() {
        let all = [
            ("INPUT", Some(1)),
            ("OUTPUT", Some(2)),
            ("FORWARD", Some(1)),
        ];
        let applied = "-N NORTHNARROW_COMBAT\n\
                       -A NORTHNARROW_COMBAT -i lo -j ACCEPT\n\
                       -A NORTHNARROW_COMBAT -s 10.0.0.0/8 -j ACCEPT\n\
                       -A NORTHNARROW_COMBAT -j LOG\n\
                       -A NORTHNARROW_COMBAT -j DROP\n";
        assert_eq!(isolation_gaps(Some(applied), &all), Ok(()));
        let no_drop = "-N NORTHNARROW_COMBAT\n-A NORTHNARROW_COMBAT -i lo -j ACCEPT\n";
        assert_eq!(
            isolation_gaps(Some(no_drop), &all),
            Err("no catch-all DROP in NORTHNARROW_COMBAT".to_string())
        );
        let accept_first = "-N NORTHNARROW_COMBAT\n\
                            -A NORTHNARROW_COMBAT -j ACCEPT\n\
                            -A NORTHNARROW_COMBAT -j DROP\n";
        let gaps = isolation_gaps(Some(accept_first), &all).unwrap_err();
        assert!(gaps.contains("unconditional ACCEPT ahead"), "{gaps}");
        let return_first = "-A NORTHNARROW_COMBAT -j RETURN\n-A NORTHNARROW_COMBAT -j DROP\n";
        assert!(isolation_gaps(Some(return_first), &all).is_err());
        let gaps = isolation_gaps(
            Some(applied),
            &[("INPUT", Some(0)), ("OUTPUT", None), ("FORWARD", Some(1))],
        )
        .unwrap_err();
        assert_eq!(
            gaps,
            "no INPUT jump into NORTHNARROW_COMBAT; OUTPUT could not be listed"
        );
        assert_eq!(
            isolation_gaps(None, &[]),
            Err("no NORTHNARROW_COMBAT chain".to_string())
        );
    }

    /// Lab follow-up (lab PR 188): the base chains checked are the ones the
    /// ruleset jumps from — INPUT and OUTPUT whatever it says.
    #[test]
    fn jump_bases_follow_the_ruleset() {
        assert_eq!(
            jump_bases(BUILTIN_RULES_V4),
            vec!["INPUT", "OUTPUT", "FORWARD"]
        );
        assert_eq!(
            jump_bases(BUILTIN_RULES_V6),
            vec!["INPUT", "OUTPUT", "FORWARD"]
        );
        let no_forward = "*filter\n:NORTHNARROW_COMBAT - [0:0]\n-A NORTHNARROW_COMBAT -j DROP\n\
                          -I INPUT 1 -j NORTHNARROW_COMBAT\n-I OUTPUT 1 -j NORTHNARROW_COMBAT\n\
                          # -I FORWARD 1 -j NORTHNARROW_COMBAT\nCOMMIT\n";
        assert_eq!(jump_bases(no_forward), vec!["INPUT", "OUTPUT"]);
    }

    /// Lab follow-up of lab PR 176 (lab PR 188): every binary COMBAT runs is
    /// on the shipped FIM list, under the name the isolation looks up — the
    /// `iptables-restore` / `ip6tables-restore` links included, so a link or
    /// `/etc/alternatives` entry re-pointed at another binary is drift of a
    /// watched path (the watch follows the chain to its target).
    #[test]
    fn the_isolation_binaries_are_on_the_fim_list() {
        let listed: std::collections::BTreeSet<&str> = crate::fim::paths_config::BUILTIN_PATHS_V1
            .lines()
            .map(str::trim)
            .collect();
        let iso = NetworkIsolator::new(combat_rules_path()).unwrap();
        for bin in [
            &iso.restore_bin,
            &iso.iptables_bin,
            &iso.restore_bin_v6,
            &iso.ip6tables_bin,
        ] {
            let Bin::System(name) = bin else {
                panic!("{bin:?}")
            };
            let path = format!("/usr/sbin/{name}");
            assert!(listed.contains(path.as_str()), "{path} not in fim-paths.v1");
        }
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
        assert!(iso.engage().complete(), "first engage");
        assert!(iso.is_engaged());
        // Second engage: still complete, still engaged. Idempotent at the
        // observable-state level.
        assert!(iso.engage().complete(), "second engage");
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
        let err = failure(&iso.engage().v4);
        assert!(
            err.contains("failed") && err.contains("NOT isolated"),
            "unexpected error: {err}"
        );
        assert!(
            !iso.is_engaged(),
            "engaged flag must stay false after failure"
        );
    }

    /// External audit ATP-006 (NN-AUD-259): the restore succeeded, so the
    /// host is isolated — a failed jump dedup (a duplicate listed, its
    /// `-D` refused) is logged, and `engage` is `Ok` with the state
    /// isolated. Before, `engage` returned the dedup's error with
    /// `is_engaged()` false while the ruleset was in.
    #[test]
    fn engage_survives_a_failed_dedup() {
        let (Some(restore), Some(iptables)) = (
            mock_restore_bin(),
            mock_script(
                "#!/bin/sh\n\
                 case \"$1 $2\" in\n\
                 '-S NORTHNARROW_COMBAT') echo '-A NORTHNARROW_COMBAT -j DROP'; exit 0 ;;\n\
                 -S*) echo \"-A $2 -j NORTHNARROW_COMBAT\"; echo \"-A $2 -j NORTHNARROW_COMBAT\"; exit 0 ;;\n\
                 -D*) echo 'iptables: Resource temporarily unavailable.' >&2; exit 4 ;;\n\
                 esac\n\
                 exit 0\n",
            ),
        ) else {
            return;
        };
        let iso = NetworkIsolator::new_with_bin(combat_rules_path(), restore, iptables).unwrap();
        assert!(iso.engage().engaged(), "the restore succeeded: engaged");
        assert!(iso.is_engaged(), "the host is isolated: reported so");
        // a failed restore is still not engaged
        let bin = PathBuf::from("/bin/false");
        if bin.exists() {
            let failed =
                NetworkIsolator::new_with_bin(combat_rules_path(), bin, PathBuf::from("/bin/true"))
                    .unwrap();
            assert!(!failed.engage().engaged());
            assert!(!failed.is_engaged());
        }
    }

    /// External audit ATP-006 (NN-AUD-259): a duplicate jump the dedup left
    /// is removed by the release, so the chain can be deleted. One `-D` per
    /// base chain used to leave it, and `-X` failed ("Device or resource
    /// busy") after the flush had already put the host back on the
    /// network.
    #[test]
    fn release_removes_every_jump() {
        let Some((iso, v4, _v6)) = fake_isolator() else {
            return;
        };
        // two jumps per base chain, as a failed dedup leaves them
        v4.seed(2);
        let report = iso.release(mint_unlock_token());
        assert!(
            report.complete(),
            "every jump removed, the chain deleted: {report:?}"
        );
        for base in ["INPUT", "OUTPUT", "FORWARD"] {
            assert_eq!(v4.jumps(base), 0, "{base}");
        }
        assert!(!v4.has_chain());
        // idempotent: nothing left, the release still succeeds
        assert!(
            iso.release(mint_unlock_token()).complete(),
            "second release"
        );
    }

    /// External audit ATP-014 (NN-AUD-262): the production isolator runs
    /// names looked up in the system directories, never a `PATH` search;
    /// the boot line names the files, or says why one cannot run.
    #[test]
    fn production_binaries_are_system_lookups() {
        let iso = NetworkIsolator::new(combat_rules_path()).unwrap();
        for (bin, name) in [
            (&iso.restore_bin, "iptables-restore"),
            (&iso.iptables_bin, "iptables"),
            (&iso.restore_bin_v6, "ip6tables-restore"),
            (&iso.ip6tables_bin, "ip6tables"),
        ] {
            assert!(matches!(bin, Bin::System(n) if *n == name), "{bin:?}");
        }
        match iso.binaries() {
            Ok(line) => {
                for exe in line
                    .split(", ")
                    .filter_map(|f| f.split_once('='))
                    .map(|(_, e)| e)
                {
                    assert!(
                        crate::trusted_bin::SYSTEM_BIN_DIRS
                            .iter()
                            .any(|d| exe.starts_with(d)),
                        "{line}"
                    );
                }
            }
            Err(why) => assert!(why.contains("/usr/sbin, /usr/bin, /sbin, /bin"), "{why}"),
        }
    }

    #[test]
    fn release_signature_requires_unlock_token() {
        // Compile-time assertion: `release` takes `UnlockToken` by
        // value. If the signature ever drifts (e.g. someone weakens
        // the cap requirement to `bool` or `&str`), this coercion
        // fails to type-check and the build breaks.
        let _: fn(&NetworkIsolator, UnlockToken) -> IsolationReport = NetworkIsolator::release;
    }

    #[test]
    fn release_clears_engaged_state() {
        let Some((iso, _v4, _v6)) = fake_isolator() else {
            return;
        };
        assert!(iso.engage().complete());
        assert!(iso.is_engaged());
        assert!(iso.release(mint_unlock_token()).complete());
        assert!(!iso.is_engaged(), "release must clear the isolation state");
    }

    /// The release of a table that holds no COMBAT chain is a release (read
    /// back clear), however often it runs.
    #[test]
    fn release_is_idempotent() {
        let Some((iso, _v4, _v6)) = fake_isolator() else {
            return;
        };
        assert!(iso.engage().complete());
        assert!(iso.release(mint_unlock_token()).complete(), "first release");
        assert!(
            iso.release(mint_unlock_token()).complete(),
            "second release"
        );
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
        let report = iso.release(mint_unlock_token());
        // The first `iptables -D INPUT …` call fails; the wrap is
        // "removing NORTHNARROW_COMBAT jump from INPUT". Lab PR 217: and the
        // table cannot be read back — not a release.
        let err = failure(&report.v4);
        assert!(
            err.contains("NORTHNARROW_COMBAT"),
            "unexpected error: {err}"
        );
        assert!(err.contains("cannot be read back"), "{err}");
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
        std::fs::write(&tmp, "# mgmt\n10.10.0.0/16\n2001:db8::/48\n").unwrap();
        let iso = iso.with_allow_cidrs_path(tmp.clone());
        let (ruleset, carved) = iso.build_engaged_ruleset().expect("build");
        assert_eq!(
            carved,
            vec!["10.10.0.0/16".to_string()],
            "only the v4 CIDR is carved"
        );
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
        let absent =
            std::env::temp_dir().join(format!("nn-absent-allow-{}.cidrs", std::process::id()));
        let _ = std::fs::remove_file(&absent);
        let iso = iso.with_allow_cidrs_path(absent);
        let (ruleset, carved) = iso.build_engaged_ruleset().expect("build");
        assert!(
            carved.is_empty(),
            "absent allow file must yield empty carve-out, got {carved:?}"
        );
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
