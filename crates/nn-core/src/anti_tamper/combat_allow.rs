//! COMBAT management carve-out allowlist (Beta Step 4b).
//!
//! By default COMBAT drops every non-loopback packet, which can lock a
//! remote operator out of a host that escalated while they had no local
//! console. This module loads an OPT-IN list of management CIDRs from
//! `/etc/northnarrow/combat-allow.cidrs` that `engage` splices into
//! the ruleset as `ACCEPT` rules *ahead of* the catch-all DROP, so SSH
//! / management traffic to and from those networks survives isolation.
//!
//! (`engage`: the agent's `anti_tamper::network_isolate::NetworkIsolator`.)
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
//!   are skipped with a warning. A prefix is a typo away from the whole
//!   address space (`10.0.0.0/0` for `/8`), which would make COMBAT
//!   isolate nothing; external audit NN-AUD-095: a line wider than
//!   [`MIN_PREFIX_V4`] / [`MIN_PREFIX_V6`], or naming the unspecified or a
//!   multicast address, is skipped the same way. A skipped line narrows
//!   the carve-out, never widens it; `config overlay set` refuses it.
//! - **No SSH-source auto-detect.** The operator must declare the admin
//!   CIDR explicitly; we never infer it from the live SSH session
//!   (that would let an attacker mid-session carve themselves out).
//!
//! Both families (BUG-031): COMBAT isolates IPv4 with `iptables` and IPv6
//! with `ip6tables`; [`generate_accept_rules`] emits the IPv4 entries'
//! ACCEPT rules and [`generate_accept_rules_v6`] the IPv6 ones, each
//! spliced into its family's chain.

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

/// External audit NN-AUD-095: the widest IPv4 carve-out, a /8.
pub const MIN_PREFIX_V4: u8 = 8;
/// External audit NN-AUD-095: the widest IPv6 carve-out, a /48 (one
/// site); a /32 is a whole provider allocation.
pub const MIN_PREFIX_V6: u8 = 48;

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
    let family = if addr.is_ipv6() { "IPv6" } else { "IPv4" };
    let max_prefix = if addr.is_ipv6() { 128 } else { 32 };
    let min_prefix = if addr.is_ipv6() {
        MIN_PREFIX_V6
    } else {
        MIN_PREFIX_V4
    };
    let p = prefix.unwrap_or(max_prefix);
    if p > max_prefix {
        return Err(format!(
            "prefix /{p} out of range for {family} in `{line}` (max /{max_prefix})"
        ));
    }
    // External audit NN-AUD-095: the ACCEPT rules go ahead of the DROP, so
    // a wide entry undoes the isolation.
    if p < min_prefix {
        return Err(format!(
            "prefix /{p} too wide for a management carve-out in `{line}` (at most /{min_prefix} \
             for {family}): it would undo COMBAT isolation"
        ));
    }
    let network = mask(addr, p);
    if addr.is_unspecified() || network.is_unspecified() {
        return Err(format!(
            "unspecified address in `{line}`: not a management network"
        ));
    }
    if addr.is_multicast() || network.is_multicast() {
        return Err(format!(
            "multicast address in `{line}`: not a management network"
        ));
    }
    Ok(AllowCidr {
        raw: line.to_string(),
        is_ipv6: addr.is_ipv6(),
    })
}

/// `addr` with the host bits past `prefix` cleared.
fn mask(addr: IpAddr, prefix: u8) -> IpAddr {
    match addr {
        IpAddr::V4(a) => {
            let m = u32::MAX.checked_shl(32 - u32::from(prefix)).unwrap_or(0);
            IpAddr::V4((u32::from(a) & m).into())
        }
        IpAddr::V6(a) => {
            let m = u128::MAX.checked_shl(128 - u32::from(prefix)).unwrap_or(0);
            IpAddr::V6((u128::from(a) & m).into())
        }
    }
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
/// to/from it survives. IPv6 entries go to [`generate_accept_rules_v6`].
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

/// BUG-031 — v6 sibling of [`generate_accept_rules`]: the
/// `ip6tables-restore` ACCEPT lines for the IPv6 carve-out entries
/// (which the v4 generator skips). Same `-s`/`-d` shape — `ip6tables-
/// restore` accepts identical syntax with v6 addresses. Empty when
/// there are no IPv6 entries.
pub fn generate_accept_rules_v6(entries: &[AllowCidr], chain: &str) -> String {
    let mut out = String::new();
    for e in entries.iter().filter(|e| e.is_ipv6) {
        out.push_str(&format!("-A {chain} -s {} -j ACCEPT\n", e.raw));
        out.push_str(&format!("-A {chain} -d {} -j ACCEPT\n", e.raw));
    }
    out
}

/// Convenience for logging: the IPv6 entries actually carved out.
pub fn ipv6_raw(entries: &[AllowCidr]) -> Vec<String> {
    entries
        .iter()
        .filter(|e| e.is_ipv6)
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
        let c = validate_entry("2001:db8:10::/48").unwrap();
        assert!(c.is_ipv6);
        assert!(validate_entry("2001:db8::7").unwrap().is_ipv6);
    }

    /// External audit NN-AUD-095: a prefix wider than the floor is refused
    /// (`10.0.0.0/0` for `/8` would carve out every address); the floor
    /// itself and anything narrower pass.
    #[test]
    fn rejects_prefixes_below_the_floor() {
        for wide in [
            "10.0.0.0/0",
            "10.0.0.0/1",
            "10.0.0.0/7",
            "128.0.0.0/1",
            "2001:db8::/0",
            "2001:db8::/32",
            "2001:db8::/47",
        ] {
            let e = validate_entry(wide).expect_err(wide);
            assert!(e.contains("too wide"), "{wide}: {e}");
        }
        for ok in [
            "10.0.0.0/8",
            "10.0.0.0/24",
            "192.168.1.10",
            "198.51.100.7/32",
            "2001:db8:10::/48",
            "2001:db8:10::/64",
        ] {
            assert!(validate_entry(ok).is_ok(), "{ok}");
        }
    }

    /// External audit NN-AUD-095: the unspecified address (with or without
    /// a prefix, or as the network a prefix leaves) and multicast are not
    /// management networks.
    #[test]
    fn rejects_unspecified_and_multicast() {
        for bad in [
            "0.0.0.0",
            "0.0.0.0/0",
            "0.0.0.0/8",
            "0.1.2.3/8",
            "::",
            "::/0",
            "::/64",
            "224.0.0.1",
            "239.1.0.0/16",
            "ff02::1",
            "ff00::/48",
        ] {
            assert!(validate_entry(bad).is_err(), "{bad}");
        }
        assert!(parse_allow_text("0.0.0.0/0\n::/0\n10.0.0.0/8\n")
            .entries
            .iter()
            .all(|e| e.raw == "10.0.0.0/8"));
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

    // BUG-031: the v6 generator is the mirror — v6 entries → two rules,
    // v4 → nothing. Together with the v4 test, every entry is applied to
    // exactly one table (no entry dropped, none double-applied).
    /// External audit CMB-015: the shipped file with an IPv6 line added
    /// produces the ip6tables ACCEPT rules.
    #[test]
    fn the_shipped_file_with_an_ipv6_line_carves_out_ipv6() {
        let shipped = include_str!(concat!(env!("NN_REPO_ROOT"), "/configs/combat-allow.cidrs"));
        let load = parse_allow_text(&format!("{shipped}\n2001:db8:10::/48\n"));
        let v6 = generate_accept_rules_v6(&load.entries, "NORTHNARROW_COMBAT");
        assert!(
            v6.contains("-A NORTHNARROW_COMBAT -s 2001:db8:10::/48 -j ACCEPT"),
            "{v6}"
        );
        assert!(
            v6.contains("-A NORTHNARROW_COMBAT -d 2001:db8:10::/48 -j ACCEPT"),
            "{v6}"
        );
        assert!(generate_accept_rules(&load.entries, "NORTHNARROW_COMBAT").is_empty());
    }

    /// External audit CMB-015: the shipped comments no longer say COMBAT
    /// isolation is IPv4-only.
    #[test]
    fn the_shipped_docs_do_not_call_isolation_ipv4_only() {
        for (name, text) in [
            (
                "configs/combat-allow.cidrs",
                include_str!(concat!(env!("NN_REPO_ROOT"), "/configs/combat-allow.cidrs")),
            ),
            (
                "docs/operator/COMBAT_RECOVERY.md",
                include_str!(concat!(
                    env!("NN_REPO_ROOT"),
                    "/docs/operator/COMBAT_RECOVERY.md"
                )),
            ),
        ] {
            assert!(!text.contains("IPv4-only"), "{name} still says IPv4-only");
        }
    }

    #[test]
    fn generate_v6_emits_two_rules_per_ipv6_none_for_ipv4() {
        let entries = parse_allow_text("10.0.0.0/24\nfd00:1:2::/48\n").entries;
        let rules = generate_accept_rules_v6(&entries, "NORTHNARROW_COMBAT");
        let lines: Vec<&str> = rules.lines().collect();
        assert_eq!(lines.len(), 2, "v6 → -s + -d; v4 → nothing");
        assert_eq!(lines[0], "-A NORTHNARROW_COMBAT -s fd00:1:2::/48 -j ACCEPT");
        assert_eq!(lines[1], "-A NORTHNARROW_COMBAT -d fd00:1:2::/48 -j ACCEPT");
        assert_eq!(ipv6_raw(&entries), vec!["fd00:1:2::/48".to_string()]);
    }

    /// External audit WDG-R06 (NN-AUD-372): the property the
    /// `combat_allow` fuzz target asserts, on fixed valid input. Every
    /// generated line is exactly `-A <chain> -s|-d <entry> -j ACCEPT`, the
    /// entry one that validates, two lines per entry in its family's
    /// block, so no allow-file content becomes another rule.
    #[test]
    fn accept_rules_shape_holds_on_valid_input() {
        let text = "10.0.0.0/24\n192.168.1.10\n172.16.0.0/12 # vpn\n2001:db8::/48\nfd00::1\n";
        let load = parse_allow_text(text);
        assert_eq!(load.entries.len(), 5, "{:?}", load.warnings);
        for (block, v6) in [
            (
                generate_accept_rules(&load.entries, "NORTHNARROW_COMBAT"),
                false,
            ),
            (
                generate_accept_rules_v6(&load.entries, "NORTHNARROW_COMBAT"),
                true,
            ),
        ] {
            let family: Vec<&AllowCidr> = load.entries.iter().filter(|e| e.is_ipv6 == v6).collect();
            let lines: Vec<&str> = block.lines().collect();
            assert_eq!(lines.len(), 2 * family.len(), "{block}");
            for (i, line) in lines.iter().enumerate() {
                let parts: Vec<&str> = line.split(' ').collect();
                assert_eq!(parts.len(), 6, "{line:?}");
                assert_eq!((parts[0], parts[1]), ("-A", "NORTHNARROW_COMBAT"));
                assert_eq!(parts[2], if i % 2 == 0 { "-s" } else { "-d" });
                assert_eq!(parts[3], family[i / 2].raw);
                assert!(validate_entry(parts[3]).is_ok(), "{line:?}");
                assert_eq!((parts[4], parts[5]), ("-j", "ACCEPT"));
            }
        }
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
