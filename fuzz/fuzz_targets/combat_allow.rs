#![no_main]
//! COMBAT management carve-out: `combat-allow.cidrs` (operator text) →
//! validated addresses → `iptables-restore` ACCEPT lines spliced into the
//! operator's `combat-rules` body. Beyond "never panics":
//! - no input reaches a rule line except as one validated address: every
//!   generated line is exactly `-A <chain> -s|-d <cidr> -j ACCEPT`, two
//!   per entry of the block's family (none lost, none in the other table);
//! - checked here apart from the validator (NN-AUD-095): no carve-out is
//!   wider than a /8 (IPv4) or a /48 (IPv6), unspecified or multicast;
//! - the splice keeps every line of the base ruleset (only the marker
//!   line is replaced) and every generated line, whatever the base.
//!
//! Input: allow-file text, a NUL byte, then a base ruleset.
use std::net::IpAddr;

use libfuzzer_sys::fuzz_target;
use northnarrow_agent::anti_tamper::combat_allow::{
    generate_accept_rules, generate_accept_rules_v6, parse_allow_text, validate_entry,
};
use northnarrow_agent::fuzz_api::{combat_splice_carveout, COMBAT_CARVE_OUT_MARKER};

const CHAIN: &str = "NORTHNARROW_COMBAT";

/// The carve-out's address and prefix, read without the validator.
fn network(cidr: &str) -> (IpAddr, u8) {
    let (addr, prefix) = cidr
        .split_once('/')
        .map_or((cidr, None), |(a, p)| (a, Some(p)));
    let addr: IpAddr = addr.parse().expect("an address");
    let max = if addr.is_ipv6() { 128 } else { 32 };
    (addr, prefix.map_or(max, |p| p.parse().expect("a prefix")))
}

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let (allow, base) = text.split_once('\0').unwrap_or((text, ""));
    let load = parse_allow_text(allow);
    for (block, v6) in [
        (generate_accept_rules(&load.entries, CHAIN), false),
        (generate_accept_rules_v6(&load.entries, CHAIN), true),
    ] {
        let entries = load.entries.iter().filter(|e| e.is_ipv6 == v6).count();
        assert_eq!(block.lines().count(), 2 * entries, "{block:?}");
        for line in block.lines() {
            let parts: Vec<&str> = line.split(' ').collect();
            assert_eq!(parts.len(), 6, "{line:?}");
            assert_eq!((parts[0], parts[1]), ("-A", CHAIN), "{line:?}");
            assert!(parts[2] == "-s" || parts[2] == "-d", "{line:?}");
            assert!(validate_entry(parts[3]).is_ok(), "{line:?}");
            assert_eq!((parts[4], parts[5]), ("-j", "ACCEPT"), "{line:?}");
            let (addr, prefix) = network(parts[3]);
            assert_eq!(addr.is_ipv6(), v6, "{line:?} in the other family's table");
            assert!(prefix >= if v6 { 48 } else { 8 }, "{line:?} is too wide");
            assert!(!addr.is_unspecified() && !addr.is_multicast(), "{line:?}");
        }
        let spliced = combat_splice_carveout(base, &block);
        // compared without a trailing CR: the splice re-terminates every
        // line with LF, which turns a bare-CR line into a CRLF ending
        let out: Vec<&str> = spliced.lines().map(|l| l.trim_end_matches('\r')).collect();
        for want in base.lines().filter(|l| l.trim() != COMBAT_CARVE_OUT_MARKER) {
            let want = want.trim_end_matches('\r');
            assert!(out.contains(&want), "base line lost: {want:?}");
        }
        for want in block.lines() {
            assert!(out.contains(&want), "accept line lost: {want:?}");
        }
    }
});
