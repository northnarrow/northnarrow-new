//! Escalation allowlist (BUG-032) — process×destination tuples that
//! exclude *known-legit* network activity from the COMBAT-tier
//! `exfiltration_pattern` / `lateral_movement` thresholds.
//!
//! This is the *complement* to corroboration: corroboration stops a
//! single blunt signal from auto-isolating, but a legit actor that
//! genuinely shows TWO distinct COMBAT behaviours (e.g. config-mgmt
//! fanning out SSH internally AND pulling from public repos = lateral +
//! exfil) would corroborate *itself*. The allowlist closes that
//! dual-behaviour false positive.
//!
//! ## Count-filter, NOT whole-trigger suppress
//!
//! A matching connection is EXCLUDED FROM THE THRESHOLD COUNT — it does
//! not suppress the trigger wholesale. So 19 connections to an
//! allowlisted update mirror + 1 to a C2 leaves the C2 connection
//! counted: the heuristic still fires on the real exfil, and legit
//! mirror traffic merely cannot inflate the count.
//!
//! ## Why the destination is the load-bearing half
//!
//! `comm` is the kernel's 15-char-truncated process name — spoofable
//! and ambiguous. A match therefore requires BOTH `comm` AND the
//! destination CIDR: an attacker naming their process `apt` but
//! exfiltrating to their own C2 (not in the mirror CIDR) does not match
//! the destination half, so the C2 traffic is still counted and still
//! escalates. The CIDR is primary; `comm` only narrows it.
//!
//! ## Known owned limit (BUG-032)
//!
//! Because the filter keys on the destination, an attacker who abuses
//! an *allowlisted destination itself* as C2 (e.g. exfil to a GitHub
//! repo when GitHub ranges are allowlisted) rides under the filter for
//! that traffic. Inherent to any destination allowlist; a sophisticated
//! edge, noted as an owned limit rather than widened-for.
//!
//! ## File format (fail-secure, line-based — matches combat-allow.cidrs)
//!
//! ```text
//! # <trigger> <comm|comm*> <dst-cidr> [port|*]
//! # trigger ∈ { exfil, lateral }
//! # comm: exact (<= 15 chars — the kernel truncates to TASK_COMM_LEN)
//! #       OR a trailing-'*' prefix glob. Use the PREFIX form for any
//! #       process name longer than 15 chars (e.g. `systemd-resolved`
//! #       → `systemd-resolv*`), or an Exact entry silently never
//! #       matches the truncated comm.
//! exfil    apt         91.189.91.0/24    443
//! lateral  ansible*    10.0.0.0/8        22
//! ```
//! Missing/unreadable file = empty allowlist (fail-secure, never an open
//! default). Malformed lines are skipped with a WARN.

use std::net::IpAddr;
use std::path::Path;

use tracing::warn;

/// Default path for the operator-supplemental escalation allowlist.
/// Missing/unreadable = empty allowlist (fail-secure). `main.rs` loads
/// this at boot into the [`crate::posture::triggers::TriggerDetector`].
pub const DEFAULT_ESCALATION_ALLOW: &str = "/etc/northnarrow/escalation-allow.local";

/// Which COMBAT-tier heuristic an entry filters. Only the two network
/// heuristics are allowlistable — the file/process ones (persistence,
/// confirmed-intrusion) are not destination-keyed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AllowTrigger {
    Exfil,
    Lateral,
}

impl AllowTrigger {
    fn parse(s: &str) -> Option<Self> {
        match s {
            "exfil" => Some(Self::Exfil),
            "lateral" => Some(Self::Lateral),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum CommMatch {
    Exact(String),
    Prefix(String),
}

impl CommMatch {
    fn matches(&self, comm: &str) -> bool {
        match self {
            CommMatch::Exact(s) => s == comm,
            CommMatch::Prefix(p) => comm.starts_with(p.as_str()),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct AllowEntry {
    trigger: AllowTrigger,
    comm: CommMatch,
    net: IpAddr,
    prefix: u8,
    /// `None` = any port.
    port: Option<u16>,
}

impl AllowEntry {
    fn matches(&self, trigger: AllowTrigger, comm: &str, addr: &IpAddr, port: u16) -> bool {
        self.trigger == trigger
            && self.comm.matches(comm)
            && self.port.map_or(true, |p| p == port)
            && cidr_contains(&self.net, self.prefix, addr)
    }
}

/// Loaded escalation allowlist. Empty by default (fail-secure).
#[derive(Debug, Clone, Default)]
pub struct EscalationAllowList {
    entries: Vec<AllowEntry>,
}

impl EscalationAllowList {
    pub fn empty() -> Self {
        Self::default()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Fail-secure load. Missing/unreadable → empty (logged on a
    /// non-NotFound error). Malformed lines → skipped with a WARN.
    pub fn load(path: &Path) -> Self {
        match std::fs::read_to_string(path) {
            Ok(text) => {
                let (list, warnings) = Self::parse(&text);
                for w in &warnings {
                    warn!(
                        path = %path.display(),
                        reject = %w,
                        "escalation-allow: skipping malformed entry (fail-secure — ignored)"
                    );
                }
                list
            }
            Err(e) => {
                if e.kind() != std::io::ErrorKind::NotFound {
                    warn!(
                        error = %e,
                        path = %path.display(),
                        "escalation-allow: read failed — empty allowlist this boot (fail-secure)"
                    );
                }
                Self::empty()
            }
        }
    }

    /// Parse text → (list, per-line warnings). `pub` for unit tests.
    /// Blank lines + `#` comments ignored.
    pub fn parse(text: &str) -> (Self, Vec<String>) {
        let mut entries = Vec::new();
        let mut warnings = Vec::new();
        for raw in text.lines() {
            let line = raw.split('#').next().unwrap_or("").trim();
            if line.is_empty() {
                continue;
            }
            match parse_entry(line) {
                Ok(e) => entries.push(e),
                Err(why) => warnings.push(why),
            }
        }
        (Self { entries }, warnings)
    }

    /// Should a connection by `comm` to `(dst_addr, family, port)` be
    /// EXCLUDED from `trigger`'s threshold count? (count-filter — see
    /// the module docs). `false` for an empty allowlist (the common
    /// case), so the hot path is a cheap length check.
    pub fn excludes(
        &self,
        trigger: AllowTrigger,
        comm: &str,
        dst_addr: &[u8; 16],
        family: u8,
        port: u16,
    ) -> bool {
        if self.entries.is_empty() {
            return false;
        }
        let addr = to_ipaddr(dst_addr, family);
        self.entries
            .iter()
            .any(|e| e.matches(trigger, comm, &addr, port))
    }
}

fn parse_entry(line: &str) -> Result<AllowEntry, String> {
    let mut it = line.split_whitespace();
    let trig = it.next().ok_or_else(|| format!("empty entry `{line}`"))?;
    let trigger = AllowTrigger::parse(trig)
        .ok_or_else(|| format!("unknown trigger `{trig}` in `{line}` (expect exfil|lateral)"))?;
    let comm_raw = it.next().ok_or_else(|| format!("missing comm in `{line}`"))?;
    let comm = if let Some(pfx) = comm_raw.strip_suffix('*') {
        CommMatch::Prefix(pfx.to_string())
    } else {
        CommMatch::Exact(comm_raw.to_string())
    };
    let cidr = it.next().ok_or_else(|| format!("missing cidr in `{line}`"))?;
    let (net, prefix) = parse_cidr(cidr).map_err(|e| format!("{e} in `{line}`"))?;
    let port = match it.next() {
        None | Some("*") => None,
        Some(p) => Some(
            p.parse::<u16>()
                .map_err(|_| format!("invalid port `{p}` in `{line}`"))?,
        ),
    };
    if it.next().is_some() {
        return Err(format!("trailing tokens in `{line}`"));
    }
    Ok(AllowEntry {
        trigger,
        comm,
        net,
        prefix,
        port,
    })
}

fn parse_cidr(s: &str) -> Result<(IpAddr, u8), String> {
    let (addr_str, prefix) = match s.split_once('/') {
        Some((a, p)) => {
            let pfx: u8 = p.parse().map_err(|_| format!("invalid prefix `{s}`"))?;
            (a, Some(pfx))
        }
        None => (s, None),
    };
    let addr: IpAddr = addr_str
        .parse()
        .map_err(|_| format!("invalid IP `{s}`"))?;
    let max = if addr.is_ipv6() { 128 } else { 32 };
    let prefix = prefix.unwrap_or(max);
    if prefix > max {
        return Err(format!("prefix /{prefix} out of range `{s}`"));
    }
    Ok((addr, prefix))
}

/// Build an `IpAddr` from the wire `[u8; 16]` dst + family (AF_INET=2 →
/// the first 4 bytes; else treat as IPv6).
fn to_ipaddr(dst: &[u8; 16], family: u8) -> IpAddr {
    use std::net::{Ipv4Addr, Ipv6Addr};
    if family == 2 {
        IpAddr::V4(Ipv4Addr::new(dst[0], dst[1], dst[2], dst[3]))
    } else {
        IpAddr::V6(Ipv6Addr::from(*dst))
    }
}

/// v4/v6 CIDR containment (same masking as `net::blocklist`). Cross-
/// family comparisons are always false.
fn cidr_contains(net: &IpAddr, prefix: u8, addr: &IpAddr) -> bool {
    match (net, addr) {
        (IpAddr::V4(n), IpAddr::V4(a)) => {
            if prefix > 32 {
                return false;
            }
            let mask = if prefix == 0 { 0 } else { u32::MAX << (32 - prefix) };
            (u32::from(*n) & mask) == (u32::from(*a) & mask)
        }
        (IpAddr::V6(n), IpAddr::V6(a)) => {
            if prefix > 128 {
                return false;
            }
            let mask = if prefix == 0 {
                0
            } else {
                u128::MAX << (128 - prefix)
            };
            (u128::from(*n) & mask) == (u128::from(*a) & mask)
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v4(a: u8, b: u8, c: u8, d: u8) -> [u8; 16] {
        let mut x = [0u8; 16];
        x[0] = a;
        x[1] = b;
        x[2] = c;
        x[3] = d;
        x
    }

    #[test]
    fn parses_and_excludes_mirror_but_not_c2() {
        let (list, warns) = EscalationAllowList::parse(
            "exfil apt 91.189.91.0/24 443\nexfil * 140.82.112.0/20 443\n",
        );
        assert!(warns.is_empty(), "{warns:?}");
        assert_eq!(list.len(), 2);
        // apt → an Ubuntu mirror on 443: excluded from the count.
        assert!(list.excludes(AllowTrigger::Exfil, "apt", &v4(91, 189, 91, 7), 2, 443));
        // same comm, a C2 outside the mirror CIDR: still counted.
        assert!(!list.excludes(AllowTrigger::Exfil, "apt", &v4(203, 0, 113, 5), 2, 443));
        // github range, any comm.
        assert!(list.excludes(AllowTrigger::Exfil, "git-remote-https", &v4(140, 82, 121, 3), 2, 443));
    }

    #[test]
    fn spoofed_comm_to_non_allowlisted_dst_still_counts() {
        // Attacker names their process "apt" but exfils to their own C2
        // (not in any mirror CIDR): the destination half fails → not
        // excluded → still counted → still escalates.
        let (list, _) = EscalationAllowList::parse("exfil apt 91.189.91.0/24 443\n");
        assert!(!list.excludes(AllowTrigger::Exfil, "apt", &v4(8, 8, 8, 8), 2, 443));
    }

    #[test]
    fn prefix_comm_matches_long_names_exact_does_not() {
        let (list, _) = EscalationAllowList::parse("lateral ansible* 10.0.0.0/8 22\n");
        // "ansible-playbook" (>15) — the kernel truncates the real comm,
        // but the prefix form matches the truncated form regardless.
        assert!(list.excludes(AllowTrigger::Lateral, "ansible-playbo", &v4(10, 1, 2, 3), 2, 22));
        // An Exact entry for a >15-char name would never match a
        // truncated comm — documented in the file header.
        let (exact, _) = EscalationAllowList::parse("lateral systemd-resolved 10.0.0.0/8 53\n");
        assert!(!exact.excludes(AllowTrigger::Lateral, "systemd-resolv", &v4(10, 0, 0, 1), 2, 53));
    }

    #[test]
    fn trigger_class_and_port_are_scoped() {
        let (list, _) = EscalationAllowList::parse("exfil apt 91.189.91.0/24 443\n");
        // wrong trigger class (lateral vs exfil) → not excluded.
        assert!(!list.excludes(AllowTrigger::Lateral, "apt", &v4(91, 189, 91, 7), 2, 443));
        // wrong port → not excluded.
        assert!(!list.excludes(AllowTrigger::Exfil, "apt", &v4(91, 189, 91, 7), 2, 80));
    }

    #[test]
    fn malformed_lines_warn_and_skip_fail_secure() {
        let (list, warns) = EscalationAllowList::parse(
            "exfil apt 91.189.91.0/24 443\n\
             bogus apt 10.0.0.0/8\n\
             exfil apt not-an-ip 443\n\
             # comment\n",
        );
        assert_eq!(list.len(), 1, "only the valid line is kept");
        assert_eq!(warns.len(), 2, "two malformed lines warned");
    }

    #[test]
    fn empty_list_excludes_nothing() {
        let list = EscalationAllowList::empty();
        assert!(!list.excludes(AllowTrigger::Exfil, "apt", &v4(91, 189, 91, 7), 2, 443));
    }
}
