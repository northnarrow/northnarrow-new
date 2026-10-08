//! Boot-time capability preflight for the response executor.
//!
//! The agent runs as root under a systemd `CapabilityBoundingSet=`
//! (deploy/systemd/northnarrow-agent.service). That set is the HARD
//! ceiling on what root can do inside the unit, so a capability
//! missing from it silently turns a response action into `EPERM`:
//!
//! - `CAP_KILL` — `kill(2)` from a sender WITHOUT it may only signal
//!   processes whose uid matches the sender's. Root without `CAP_KILL`
//!   can therefore kill root processes only; every KillProcess /
//!   KillProcessTree verdict against a user-owned process fails. That
//!   is the product's primary response, so its absence in enforcement
//!   mode is a refuse-to-start condition, not a log line.
//! - the others are reported (warn) so an operator sees the degraded
//!   surface in the journal at boot instead of at incident time.
//!
//! Reads `CapEff` from `/proc/self/status` (no extra crate, no
//! syscall wrapper): a 64-bit hex mask, bit N = capability N.

use std::fmt;

/// Capability bit numbers (linux/capability.h).
const CAP_DAC_OVERRIDE: u32 = 1;
const CAP_KILL: u32 = 5;
const CAP_LINUX_IMMUTABLE: u32 = 9;
const CAP_NET_ADMIN: u32 = 12;
const CAP_SYS_PTRACE: u32 = 19;
const CAP_PERFMON: u32 = 38;
const CAP_BPF: u32 = 39;

/// Every capability the enforcement path relies on, with the action
/// that breaks without it (for the boot log).
const REQUIRED: &[(u32, &str, &str)] = &[
    (
        CAP_KILL,
        "CAP_KILL",
        "KillProcess/KillProcessTree on non-root targets",
    ),
    (
        CAP_NET_ADMIN,
        "CAP_NET_ADMIN",
        "COMBAT network isolation (iptables-restore)",
    ),
    (
        CAP_SYS_PTRACE,
        "CAP_SYS_PTRACE",
        "/proc/<pid>/exe resolution for quarantine + lineage",
    ),
    (
        CAP_DAC_OVERRIDE,
        "CAP_DAC_OVERRIDE",
        "quarantine of binaries in restrictive-perm dirs",
    ),
    (
        CAP_LINUX_IMMUTABLE,
        "CAP_LINUX_IMMUTABLE",
        "chattr +i on /var/lib/northnarrow",
    ),
    (CAP_BPF, "CAP_BPF", "eBPF map/program load"),
    (CAP_PERFMON, "CAP_PERFMON", "BPF-LSM / tracing attach"),
];

/// Outcome of the preflight: which required capabilities are absent
/// from the effective set.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct MissingCaps {
    pub names: Vec<&'static str>,
    pub kill_missing: bool,
}

impl MissingCaps {
    pub fn is_empty(&self) -> bool {
        self.names.is_empty()
    }
}

impl fmt::Display for MissingCaps {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.names.join(", "))
    }
}

/// Parse the `CapEff:` line out of a `/proc/<pid>/status` body.
pub fn parse_cap_eff(status: &str) -> Option<u64> {
    status
        .lines()
        .find_map(|l| l.strip_prefix("CapEff:"))
        .and_then(|hex| u64::from_str_radix(hex.trim(), 16).ok())
}

/// Compare an effective-capability mask against [`REQUIRED`].
pub fn missing_from_mask(cap_eff: u64) -> MissingCaps {
    let mut out = MissingCaps::default();
    for &(bit, name, _) in REQUIRED {
        if cap_eff & (1u64 << bit) == 0 {
            out.names.push(name);
            if bit == CAP_KILL {
                out.kill_missing = true;
            }
        }
    }
    out
}

/// Human-readable "what breaks" line for the boot log.
pub fn impact_of(name: &str) -> &'static str {
    REQUIRED
        .iter()
        .find(|(_, n, _)| *n == name)
        .map(|(_, _, impact)| *impact)
        .unwrap_or("unknown")
}

/// Read this process's effective capabilities. `None` when
/// `/proc/self/status` is unreadable or has no `CapEff` line (not
/// Linux, or a sandbox hiding procfs) — callers treat that as
/// "cannot verify" and only warn.
pub fn current_missing() -> Option<MissingCaps> {
    let status = std::fs::read_to_string("/proc/self/status").ok()?;
    parse_cap_eff(&status).map(missing_from_mask)
}

#[cfg(test)]
mod tests {
    use super::*;

    const FULL_ROOT: u64 = 0x0000_01ff_ffff_ffff;
    /// The deploy unit's set BEFORE the CAP_KILL fix:
    /// BPF PERFMON NET_ADMIN LINUX_IMMUTABLE SYS_PTRACE DAC_OVERRIDE.
    const OLD_UNIT: u64 = (1 << CAP_BPF)
        | (1 << CAP_PERFMON)
        | (1 << CAP_NET_ADMIN)
        | (1 << CAP_LINUX_IMMUTABLE)
        | (1 << CAP_SYS_PTRACE)
        | (1 << CAP_DAC_OVERRIDE);

    #[test]
    fn parses_cap_eff_line() {
        let body = "Name:\tx\nCapInh:\t0000000000000000\nCapPrm:\t000001ffffffffff\nCapEff:\t000001ffffffffff\nCapBnd:\t0\n";
        assert_eq!(parse_cap_eff(body), Some(FULL_ROOT));
        assert_eq!(parse_cap_eff("Name:\tx\n"), None);
    }

    #[test]
    fn full_root_is_not_missing_anything() {
        assert!(missing_from_mask(FULL_ROOT).is_empty());
    }

    #[test]
    fn old_unit_set_is_missing_exactly_cap_kill() {
        let m = missing_from_mask(OLD_UNIT);
        assert_eq!(m.names, vec!["CAP_KILL"]);
        assert!(m.kill_missing);
    }

    #[test]
    fn unit_set_with_cap_kill_passes() {
        let m = missing_from_mask(OLD_UNIT | (1 << CAP_KILL));
        assert!(m.is_empty(), "{m}");
        assert!(!m.kill_missing);
    }

    #[test]
    fn unprivileged_reports_everything() {
        let m = missing_from_mask(0);
        assert_eq!(m.names.len(), REQUIRED.len());
        assert!(m.kill_missing);
        assert_eq!(impact_of("CAP_KILL"), REQUIRED[0].2);
    }

    #[test]
    fn current_process_is_readable_on_linux() {
        // Only asserts that procfs parsing works for the live process;
        // the actual set depends on how the test runner was launched.
        assert!(current_missing().is_some());
    }
}
