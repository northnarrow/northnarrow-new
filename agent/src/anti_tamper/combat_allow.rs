//! COMBAT management carve-out allowlist (Beta Step 4b).
//!
//! By default COMBAT drops every non-loopback packet, which can lock a
//! remote operator out of a host that escalated while they had no local
//! console. This module loads an OPT-IN list of management CIDRs from
//! `/etc/northnarrow/combat-allow.cidrs` that [`engage`] splices into
//! the ruleset as `ACCEPT` rules *ahead of* the catch-all DROP, so SSH
//! / management traffic to and from those networks survives isolation.
//!
//! [`engage`]: super::network_isolate::NetworkIsolator::engage
//!
//! Design rules (operator-confirmed):
//!
//! - **Default-secure.** The file ships empty; an empty (or missing)
//!   file reproduces today's no-carve-out behaviour exactly.
//! - **Re-read at engage time**, never cached at startup — an operator
//!   can add an emergency CIDR from a local console mid-COMBAT and the
//!   next (idempotent) engage picks it up.
//! - **Fail-secure.** An unreadable file yields an EMPTY allowlist
//!   (full isolation), never an open one. Individual malformed lines
//!   are skipped with a warning — a typo can only *remove* an ACCEPT,
//!   never widen one.
//! - **No SSH-source auto-detect.** The operator must declare the admin
//!   CIDR explicitly; we never infer it from the live SSH session
//!   (that would let an attacker mid-session carve themselves out).
//!
//! IPv4 only: the COMBAT ruleset is `iptables` (v4); COMBAT does not
//! currently isolate IPv6 at all, so a v6 management network needs no
//! carve-out. v6 entries are validated and accepted but emit no rule
//! (with an informational log from the caller).

use std::net::IpAddr;
use std::path::{Path, PathBuf};

/// Default deploy path of the management carve-out CIDR list.
pub const DEFAULT_COMBAT_ALLOW_CIDRS: &str = "/etc/northnarrow/combat-allow.cidrs";

/// A validated management-allow entry: a single IP or a CIDR range,
/// kept as the original string for direct hand-off to `iptables -s/-d`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AllowCidr {
    /// The trimmed entry exactly as it will be passed to iptables.
    pub raw: String,
    /// True for an IPv6 entry (no v4 ruleset injection — see module docs).
    pub is_ipv6: bool,
}

/// Outcome of loading the allow file. `warnings` collects per-line
/// rejects; `read_error` is set (and `entries` empty) when the file
/// itself could not be read.
#[derive(Debug, Default, Clone)]
pub struct AllowLoad {
    pub entries: Vec<AllowCidr>,
    pub warnings: Vec<String>,
    pub read_error: Option<String>,
}

/// Validate one line as a bare IP or `IP/prefix` CIDR.
pub fn validate_entry(line: &str) -> Result<AllowCidr, String> {
    let (addr_str, prefix) = match line.split_once('/') {
        Some((a, p)) => {
            let prefix: u8 = p
                .parse()
                .map_err(|_| format!("invalid prefix length in `{line}`"))?;
            (a, Some(prefix))
        }
        None => (line, None),
    };
    let addr: IpAddr = addr_str
        .parse()
        .map_err(|_| format!("invalid IP address in `{line}`"))?;
    let max_prefix = if addr.is_ipv6() { 128 } else { 32 };
    if let Some(p) = prefix {
        if p > max_prefix {
            return Err(format!(
                "prefix /{p} out of range for {} in `{line}` (max /{max_prefix})",
                if addr.is_ipv6() { "IPv6" } else { "IPv4" }
            ));
        }
    }
    Ok(AllowCidr {
        raw: line.to_string(),
        is_ipv6: addr.is_ipv6(),
    })
}

/// Parse allow-file text (blank lines + `#` comments ignored).
pub fn parse_allow_text(text: &str) -> AllowLoad {
    let mut load = AllowLoad::default();
    for raw_line in text.lines() {
        let line = match raw_line.split('#').next() {
            Some(l) => l.trim(),
            None => raw_line.trim(),
        };
        if line.is_empty() {
            continue;
        }
        match validate_entry(line) {
            Ok(entry) => load.entries.push(entry),
            Err(e) => load.warnings.push(e),
        }
    }
    load
}

/// Load + validate the allow file. Fail-secure: a missing or unreadable
/// file yields an empty allowlist (`read_error` records why), never an
/// open one.
pub fn load_allow_cidrs(path: &Path) -> AllowLoad {
    match std::fs::read_to_string(path) {
        Ok(text) => parse_allow_text(&text),
        Err(e) => AllowLoad {
            entries: Vec::new(),
            warnings: Vec::new(),
            read_error: Some(format!("reading {}: {e}", path.display())),
        },
    }
}

/// Generate the `iptables-restore` ACCEPT lines for the IPv4 entries,
/// to be spliced into `chain` ahead of its DROP. Each network is
/// allowed both inbound (`-s`) and outbound (`-d`) so an SSH session
/// to/from it survives. IPv6 entries emit nothing (see module docs).
/// Returns an empty string when there are no IPv4 entries.
pub fn generate_accept_rules(entries: &[AllowCidr], chain: &str) -> String {
    let mut out = String::new();
    for e in entries.iter().filter(|e| !e.is_ipv6) {
        out.push_str(&format!("-A {chain} -s {} -j ACCEPT\n", e.raw));
        out.push_str(&format!("-A {chain} -d {} -j ACCEPT\n", e.raw));
    }
    out
}

/// Convenience for logging: the IPv4 entries actually carved out.
pub fn ipv4_raw(entries: &[AllowCidr]) -> Vec<String> {
    entries
        .iter()
        .filter(|e| !e.is_ipv6)
        .map(|e| e.raw.clone())
        .collect()
}

/// Default path as a [`PathBuf`].
pub fn default_path() -> PathBuf {
    PathBuf::from(DEFAULT_COMBAT_ALLOW_CIDRS)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_ipv4_host_and_cidr() {
        assert!(validate_entry("10.0.0.5").is_ok());
        let c = validate_entry("10.0.0.0/8").unwrap();
        assert!(!c.is_ipv6);
        assert_eq!(c.raw, "10.0.0.0/8");
    }

    #[test]
    fn validates_ipv6() {
        let c = validate_entry("2001:db8::/32").unwrap();
        assert!(c.is_ipv6);
    }

    #[test]
    fn rejects_bad_address_and_prefix() {
        assert!(validate_entry("not-an-ip").is_err());
        assert!(validate_entry("10.0.0.0/33").is_err()); // v4 prefix too big
        assert!(validate_entry("2001:db8::/129").is_err()); // v6 prefix too big
        assert!(validate_entry("10.0.0.0/abc").is_err());
    }

    #[test]
    fn parse_skips_comments_and_blank_keeps_valid() {
        let text = "\
# management network\n\
10.0.0.0/24\n\
\n\
   192.168.1.10   # jump host\n\
garbage-line\n\
2001:db8::/48\n";
        let load = parse_allow_text(text);
        assert_eq!(load.entries.len(), 3, "two v4 + one v6 valid");
        assert_eq!(load.warnings.len(), 1, "one malformed line");
        // Trailing inline comment is stripped.
        assert!(load.entries.iter().any(|e| e.raw == "192.168.1.10"));
    }

    #[test]
    fn generate_emits_two_rules_per_ipv4_none_for_ipv6() {
        let entries = parse_allow_text("10.0.0.0/24\n2001:db8::/48\n").entries;
        let rules = generate_accept_rules(&entries, "NORTHNARROW_COMBAT");
        let lines: Vec<&str> = rules.lines().collect();
        assert_eq!(lines.len(), 2, "v4 → -s + -d; v6 → nothing");
        assert_eq!(lines[0], "-A NORTHNARROW_COMBAT -s 10.0.0.0/24 -j ACCEPT");
        assert_eq!(lines[1], "-A NORTHNARROW_COMBAT -d 10.0.0.0/24 -j ACCEPT");
    }

    #[test]
    fn empty_input_generates_nothing() {
        assert_eq!(generate_accept_rules(&[], "C"), "");
        assert!(parse_allow_text("# only a comment\n\n").entries.is_empty());
    }

    #[test]
    fn missing_file_is_fail_secure_empty() {
        let load = load_allow_cidrs(Path::new("/nonexistent/combat-allow.cidrs"));
        assert!(load.entries.is_empty());
        assert!(load.read_error.is_some());
    }
}
