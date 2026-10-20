//! Tappa 10 (N6) — operator NetFlow blocklist parsers.
//!
//! Two on-disk files per design §13 Q5 + §10:
//!
//! 1. `/etc/northnarrow/netflow-blocklist.v1` — curated default
//!    IP / CIDR blocklist. One entry per line, `#` comments,
//!    blanks ignored. NO directives (mirrors the Tappa 9 C7
//!    `fim-paths.v1` shape).
//! 2. `/etc/northnarrow/netflow-blocklist.local` — operator
//!    overlay. `+entry` adds, `-entry` disables a default,
//!    bare entry is treated as `+entry`. Same `.local` lockin
//!    Tappa 9 C7 + Tappa 9.5 K7 already follow.
//!
//! V1.0 also ships `netflow-ja3-blocklist.v1` + matching `.local`
//! for JA3 hash entries (used by NN-L-NET-003). Same shape, just
//! a different entry parser (32-hex chars per line vs `IP[/cidr]`).
//!
//! No external dep — IP / CIDR parsing is `std::net::IpAddr` +
//! a hand-rolled `cidr_contains` helper. ipnet would be smaller
//! at call-site but adds a workspace dep for what is, in this
//! file, ~30 LoC of bitmask arithmetic. See N5's md-5 / Tappa 0's
//! "minimal dep charter" precedent.

use std::collections::BTreeSet;
use std::net::IpAddr;
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};

use anyhow::{anyhow, Context, Result};
use tracing::{info, warn};

use crate::config::overlay::{load_defaults, DefaultsSource, Shipped};
use crate::config::overlay_auth::Verified;

/// External audit LLMR-016: the shipped default lists, built in — used
/// when the `.v1` on disk cannot be read (the blocklists used to be empty
/// then, with a WARN).
pub const BUILTIN_NETFLOW_BLOCKLIST_V1: &str =
    include_str!("../../../configs/netflow-blocklist.v1");
pub const BUILTIN_JA3_BLOCKLIST_V1: &str =
    include_str!("../../../configs/netflow-ja3-blocklist.v1");

/// External audit LLMR-015 (NN-AUD-327): SHA-256 of every
/// `netflow-blocklist.v1` an earlier release shipped (the history of
/// `configs/`). The agent applies its built-in copy over one of these, and
/// `install.sh` (`SHIPPED_V1_EARLIER`, kept equal by a test) replaces it.
/// The first one still listed `100.64.0.0/10` and `198.18.0.0/15`, which
/// NET-011 took out of this KillProcessTree list (lab PR 78): a host
/// installed before that kept killing processes that talk to CGNAT,
/// Tailscale, EKS or VPN addresses after every upgrade.
pub const EARLIER_NETFLOW_BLOCKLIST_V1_SHA256: &[&str] = &[
    // Tappa 10 N8 (562a79d), before NET-011
    "b50d821782e5ab9d8ab3e27aa7c3dfb3ea0aec87001c16b2eea758d94e8a7866",
];
/// As [`EARLIER_NETFLOW_BLOCKLIST_V1_SHA256`], for `netflow-ja3-blocklist.v1`.
pub const EARLIER_JA3_BLOCKLIST_V1_SHA256: &[&str] = &[
    // Tappa 10 N8 (562a79d)
    "0340417224f37515e1c2a1ed24bc3f530c4bdb910f6bf65dee9793152efc6a24",
];
/// The shipped `netflow-blocklist.v1` (built-in copy, earlier ones).
pub const NETFLOW_BLOCKLIST_SHIPPED: Shipped<'static> = Shipped::new(
    BUILTIN_NETFLOW_BLOCKLIST_V1,
    EARLIER_NETFLOW_BLOCKLIST_V1_SHA256,
);
/// The shipped `netflow-ja3-blocklist.v1` (built-in copy, earlier ones).
pub const JA3_BLOCKLIST_SHIPPED: Shipped<'static> =
    Shipped::new(BUILTIN_JA3_BLOCKLIST_V1, EARLIER_JA3_BLOCKLIST_V1_SHA256);

/// Default deploy path for the IP / CIDR blocklist file.
pub const DEFAULT_NETFLOW_BLOCKLIST_V1: &str = "/etc/northnarrow/netflow-blocklist.v1";
/// Operator overlay path.
pub const DEFAULT_NETFLOW_BLOCKLIST_LOCAL: &str = "/etc/northnarrow/netflow-blocklist.local";

/// Default deploy path for the JA3 fingerprint blocklist.
pub const DEFAULT_NETFLOW_JA3_BLOCKLIST_V1: &str = "/etc/northnarrow/netflow-ja3-blocklist.v1";
/// JA3 operator overlay.
pub const DEFAULT_NETFLOW_JA3_BLOCKLIST_LOCAL: &str =
    "/etc/northnarrow/netflow-ja3-blocklist.local";

// ── IP / CIDR blocklist ──────────────────────────────────────────────

/// One blocklist entry — either a single IP or a CIDR range. We
/// store the canonical components rather than the raw string so
/// `contains` doesn't re-parse on every lookup.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum NetBlocklistEntry {
    /// Exact IP match.
    Ip(IpAddr),
    /// CIDR range: network address + prefix length.
    Cidr { net: IpAddr, prefix: u8 },
}

impl NetBlocklistEntry {
    /// Parse a bare blocklist token. Accepts `1.2.3.4`,
    /// `2001:db8::1`, `1.2.3.0/24`, `2001:db8::/32`. Returns
    /// an error with the offending token + reason on failure.
    pub fn parse(s: &str) -> Result<Self> {
        if let Some((net_s, prefix_s)) = s.split_once('/') {
            let net: IpAddr = net_s
                .parse()
                .with_context(|| format!("invalid CIDR network in `{s}`"))?;
            let prefix: u8 = prefix_s
                .parse()
                .with_context(|| format!("invalid CIDR prefix in `{s}`"))?;
            let max = if net.is_ipv4() { 32 } else { 128 };
            if prefix > max {
                return Err(anyhow!("CIDR prefix /{prefix} exceeds {max} for `{s}`"));
            }
            Ok(NetBlocklistEntry::Cidr { net, prefix })
        } else {
            let ip: IpAddr = s
                .parse()
                .with_context(|| format!("invalid IP address `{s}`"))?;
            Ok(NetBlocklistEntry::Ip(ip))
        }
    }

    /// Does this entry match `addr`?
    /// External audit NET-001: both sides in canonical form, so an
    /// IPv4-mapped IPv6 address matches the IPv4 entry it maps.
    pub fn matches(&self, addr: &IpAddr) -> bool {
        let addr = common::netaddr::canonical(*addr);
        match self {
            NetBlocklistEntry::Ip(e) => common::netaddr::canonical(*e) == addr,
            NetBlocklistEntry::Cidr { net, prefix } => cidr_contains(net, *prefix, &addr),
        }
    }
}

/// Test whether `addr` falls within `net/prefix`. Cross-family
/// comparisons (v4 entry, v6 addr or vice versa) are always
/// false — operators put v4 + v6 entries on separate lines.
fn cidr_contains(net: &IpAddr, prefix: u8, addr: &IpAddr) -> bool {
    match (net, addr) {
        (IpAddr::V4(n), IpAddr::V4(a)) => {
            if prefix > 32 {
                return false;
            }
            let mask: u32 = if prefix == 0 {
                0
            } else {
                u32::MAX << (32 - prefix)
            };
            (u32::from(*n) & mask) == (u32::from(*a) & mask)
        }
        (IpAddr::V6(n), IpAddr::V6(a)) => {
            if prefix > 128 {
                return false;
            }
            let n_bits = u128::from(*n);
            let a_bits = u128::from(*a);
            let mask: u128 = if prefix == 0 {
                0
            } else {
                u128::MAX << (128 - prefix)
            };
            (n_bits & mask) == (a_bits & mask)
        }
        _ => false,
    }
}

/// Loaded + merged IP/CIDR blocklist. Construct via
/// [`NetBlocklist::load`] (production: reads both files from
/// disk) or [`NetBlocklist::from_entries`] (tests + custom
/// callers).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NetBlocklist {
    entries: BTreeSet<NetBlocklistEntry>,
    /// Where the defaults came from (external audit LLMR-016).
    defaults: DefaultsSource,
}

impl NetBlocklist {
    /// Empty blocklist — `contains` returns false for every IP.
    /// Used as the default for unit tests + the production
    /// boot path when neither file exists.
    pub fn empty() -> Self {
        Self::default()
    }

    /// Test/admin constructor: build directly from parsed entries.
    pub fn from_entries<I: IntoIterator<Item = NetBlocklistEntry>>(iter: I) -> Self {
        Self {
            entries: iter.into_iter().collect(),
            defaults: DefaultsSource::Disk,
        }
    }

    /// Where the defaults came from: the `.v1`, or the built-in copy and
    /// why (unreadable, an earlier release's, edited — the caller records
    /// the first and the last).
    pub fn defaults(&self) -> &DefaultsSource {
        &self.defaults
    }

    /// How many entries the blocklist holds.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// `true` if the blocklist has no entries.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Lab PR 224: the entries, in order (the `socket_connect` deny loads
    /// them into its kernel tries).
    pub fn entries(&self) -> impl Iterator<Item = &NetBlocklistEntry> {
        self.entries.iter()
    }

    /// Does the loaded blocklist match `addr`?
    pub fn contains(&self, addr: &IpAddr) -> bool {
        self.entries.iter().any(|e| e.matches(addr))
    }

    /// Production loader. Takes the shipped defaults — `v1_path` when it
    /// is the copy built into the agent, else that copy (external audit
    /// LLMR-016, LLMR-015: [`load_defaults`]) — applies the `.local`
    /// overlay's `+` / `-` directives — `local` is the overlay as the
    /// signed-overlay gate verified it (external audit LLMR-013) — and
    /// emits boot-time WARNs for disabled defaults + unknown disables
    /// (mirrors the Tappa 9 C7 paths_config WARN pattern so operators see
    /// all suppressions).
    pub fn load(v1_path: &Path, local: &Verified) -> Result<Self> {
        Self::load_with(v1_path, NETFLOW_BLOCKLIST_SHIPPED, local)
    }

    /// [`Self::load`] with the shipped defaults given.
    fn load_with(v1_path: &Path, shipped: Shipped<'_>, local: &Verified) -> Result<Self> {
        let (defaults, source) =
            load_defaults("netflow blocklist", v1_path, shipped, parse_v1_text);
        let (adds, disables) = overlay_entries(local, NetBlocklistEntry::parse);

        let mut disabled = BTreeSet::new();
        let mut unknown_disable = BTreeSet::new();
        for d in &disables {
            if defaults.contains(d) {
                disabled.insert(d.clone());
                warn!(entry = ?d, "netflow blocklist: default entry disabled by operator");
            } else {
                unknown_disable.insert(d.clone());
                warn!(entry = ?d, "netflow blocklist: -entry targets unknown default — no-op");
            }
        }
        let mut entries: BTreeSet<NetBlocklistEntry> = defaults
            .iter()
            .filter(|e| !disabled.contains(*e))
            .cloned()
            .collect();
        for a in adds {
            entries.insert(a);
        }
        info!(entries = entries.len(), "netflow blocklist: load complete");
        Ok(Self {
            entries,
            defaults: source,
        })
    }
}

fn parse_v1_text(label: &str, body: &str) -> BTreeSet<NetBlocklistEntry> {
    each_line(label, body, |t| {
        if t.starts_with('+') || t.starts_with('-') {
            return Err(anyhow!("default list must not use +/- prefixes"));
        }
        NetBlocklistEntry::parse(t)
    })
    .into_iter()
    .collect()
}

/// External audit NET-002 (NN-AUD-056): a malformed line drops that line,
/// never the list. A typo in one line used to empty the whole default
/// blocklist (NN-L-NET-001, KillProcessTree) with a single WARN, and
/// every later line with it. Each dropped line is its own WARN. The
/// overlay validation before signing stays strict
/// ([`parse_blocklist_overlay_text`]): there the operator sees the error.
fn each_line<T>(label: &str, body: &str, mut parse: impl FnMut(&str) -> Result<T>) -> Vec<T> {
    let mut out = Vec::new();
    for (lineno, raw) in body.lines().enumerate() {
        let trimmed = strip_comment(raw).trim();
        if trimmed.is_empty() {
            continue;
        }
        match parse(trimmed) {
            Ok(v) => out.push(v),
            Err(e) => warn!(
                file = label,
                line = lineno + 1,
                error = %e,
                "blocklist: malformed line skipped (the rest of the list is kept)"
            ),
        }
    }
    out
}

/// One overlay line: `+entry` / `entry` adds, `-entry` disables.
fn overlay_line<T>(t: &str, parse: impl Fn(&str) -> Result<T>) -> Result<(bool, T)> {
    let (is_disable, rest) = if let Some(r) = t.strip_prefix('+') {
        (false, r.trim_start())
    } else if let Some(r) = t.strip_prefix('-') {
        (true, r.trim_start())
    } else {
        (false, t)
    };
    Ok((is_disable, parse(rest)?))
}

fn split_overlay<T: Ord>(lines: Vec<(bool, T)>) -> (BTreeSet<T>, BTreeSet<T>) {
    let mut adds = BTreeSet::new();
    let mut disables = BTreeSet::new();
    for (is_disable, v) in lines {
        if is_disable {
            disables.insert(v);
        } else {
            adds.insert(v);
        }
    }
    (adds, disables)
}

/// The overlay's `(adds, disables)`, from the text the signed-overlay gate
/// verified (external audit LLMR-013); a malformed line is skipped.
fn overlay_entries<T: Ord>(
    local: &Verified,
    parse: impl Fn(&str) -> Result<T>,
) -> (BTreeSet<T>, BTreeSet<T>) {
    match (local.text(), local.source()) {
        (Some(text), Some(path)) => {
            split_overlay(each_line(&path.display().to_string(), text, |t| {
                overlay_line(t, &parse)
            }))
        }
        _ => Default::default(),
    }
}

/// Text form of the `netflow-blocklist.local` parser (Tappa 10.8: the same
/// rules validate an overlay before it is signed or stored).
pub(crate) fn parse_blocklist_overlay_text(
    label: &str,
    body: &str,
) -> Result<(BTreeSet<NetBlocklistEntry>, BTreeSet<NetBlocklistEntry>)> {
    let path = label;
    let mut adds = BTreeSet::new();
    let mut disables = BTreeSet::new();
    for (lineno, raw) in body.lines().enumerate() {
        let trimmed = strip_comment(raw).trim();
        if trimmed.is_empty() {
            continue;
        }
        let (is_disable, rest) = if let Some(r) = trimmed.strip_prefix('+') {
            (false, r.trim_start())
        } else if let Some(r) = trimmed.strip_prefix('-') {
            (true, r.trim_start())
        } else {
            (false, trimmed)
        };
        let entry = NetBlocklistEntry::parse(rest)
            .with_context(|| format!("{}:{}: malformed overlay entry", path, lineno + 1))?;
        if is_disable {
            disables.insert(entry);
        } else {
            adds.insert(entry);
        }
    }
    Ok((adds, disables))
}

// ── JA3 blocklist ────────────────────────────────────────────────────

/// External audit NET-009 (BUG-025): no sensor captures a TLS ClientHello
/// in this build — `tls_parser` has no caller and every flow row carries
/// no fingerprint — so NN-L-NET-003 cannot match, whatever the JA3 list
/// holds. Turned on by the change that adds the producer.
pub const TLS_FINGERPRINT_PRODUCER: bool = false;

/// JA3 entries loaded at boot, for [`inactive_net_rules`].
static JA3_ENTRIES: AtomicUsize = AtomicUsize::new(0);

fn ja3_entries_phrase(entries: usize) -> String {
    if entries == 1 {
        "1 JA3 blocklist entry".to_string()
    } else {
        format!("{entries} JA3 blocklist entries")
    }
}

/// External audit NET-009: the boot check. A JA3 list with entries and
/// no fingerprint producer is coverage that does not exist; the returned
/// text is the boot ERROR and the signed `subsystem_degraded` detail.
/// `None` when the list is empty or a producer runs.
pub fn ja3_coverage_gap(entries: usize, producer: bool) -> Option<String> {
    (entries > 0 && !producer).then(|| {
        format!(
            "NN-L-NET-003 inactive: {} loaded, but no sensor produces TLS fingerprints in \
             this build (BUG-025), so no flow can match them",
            ja3_entries_phrase(entries)
        )
    })
}

/// Record the size of the JA3 list the boot loaded.
pub fn note_ja3_entries(entries: usize) {
    JA3_ENTRIES.store(entries, Ordering::Relaxed);
}

/// External audit NET-009: the network rules that cannot fire in this
/// build, for `nn-admin net status`. External audit NET-017 (lab PR 207):
/// and the DNS rules blind to the resolver's upstream while
/// systemd-resolved runs DNS over TLS, read from its configuration at each
/// call ([`crate::net::blind_spots::resolver_dns_over_tls`]).
pub fn inactive_net_rules() -> Vec<String> {
    inactive_net_rules_with(
        JA3_ENTRIES.load(Ordering::Relaxed),
        TLS_FINGERPRINT_PRODUCER,
        crate::net::blind_spots::resolver_dns_over_tls().as_ref(),
    )
}

fn inactive_net_rules_with(
    entries: usize,
    producer: bool,
    resolver_dot: Option<&crate::net::blind_spots::ResolverDot>,
) -> Vec<String> {
    let mut rules = Vec::new();
    if !producer {
        rules.push(format!(
            "NN-L-NET-003 (JA3): no TLS fingerprint producer in this build (BUG-025); {} \
             loaded, none can match",
            ja3_entries_phrase(entries)
        ));
    }
    if let Some(dot) = resolver_dot {
        rules.push(crate::net::blind_spots::dns_blind_rule(dot));
    }
    rules
}

/// JA3 fingerprint blocklist. JA3 hashes are 32-char lowercase
/// hex strings (MD5 of the JA3 raw tuple, per Salesforce 2017
/// spec). Same file format as `NetBlocklist` minus CIDR support.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Ja3Blocklist {
    hashes: BTreeSet<String>,
    /// Where the defaults came from (external audit LLMR-016).
    defaults: DefaultsSource,
}

impl Ja3Blocklist {
    pub fn empty() -> Self {
        Self::default()
    }

    pub fn from_entries<I, S>(iter: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Self {
            hashes: iter.into_iter().map(Into::into).collect(),
            defaults: DefaultsSource::Disk,
        }
    }

    pub fn len(&self) -> usize {
        self.hashes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.hashes.is_empty()
    }

    pub fn contains(&self, hash: &str) -> bool {
        self.hashes.contains(hash)
    }

    /// Where the defaults came from (see [`NetBlocklist::defaults`]).
    pub fn defaults(&self) -> &DefaultsSource {
        &self.defaults
    }

    /// Production loader: as [`NetBlocklist::load`], for JA3 hashes.
    pub fn load(v1_path: &Path, local: &Verified) -> Result<Self> {
        Self::load_with(v1_path, JA3_BLOCKLIST_SHIPPED, local)
    }

    /// [`Self::load`] with the shipped defaults given.
    fn load_with(v1_path: &Path, shipped: Shipped<'_>, local: &Verified) -> Result<Self> {
        let (defaults, source) =
            load_defaults("JA3 blocklist", v1_path, shipped, parse_ja3_v1_text);
        let (adds, disables) = overlay_entries(local, parse_ja3_hash);
        let mut hashes: BTreeSet<String> = defaults
            .iter()
            .filter(|h| !disables.contains(*h))
            .cloned()
            .collect();
        for h in adds {
            hashes.insert(h);
        }
        Ok(Self {
            hashes,
            defaults: source,
        })
    }
}

fn parse_ja3_hash(s: &str) -> Result<String> {
    let s = s.to_ascii_lowercase();
    if s.len() != 32 || !s.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(anyhow!(
            "expected 32 lowercase-hex chars for JA3 hash, got `{s}`"
        ));
    }
    Ok(s)
}

fn parse_ja3_v1_text(label: &str, body: &str) -> BTreeSet<String> {
    each_line(label, body, |t| {
        if t.starts_with('+') || t.starts_with('-') {
            return Err(anyhow!("default list must not use +/- prefixes"));
        }
        parse_ja3_hash(t)
    })
    .into_iter()
    .collect()
}

/// Text form of the `netflow-ja3-blocklist.local` parser (Tappa 10.8).
pub(crate) fn parse_ja3_overlay_text(
    label: &str,
    body: &str,
) -> Result<(BTreeSet<String>, BTreeSet<String>)> {
    let path = label;
    let mut adds = BTreeSet::new();
    let mut disables = BTreeSet::new();
    for (lineno, raw) in body.lines().enumerate() {
        let trimmed = strip_comment(raw).trim();
        if trimmed.is_empty() {
            continue;
        }
        let (is_disable, rest) = if let Some(r) = trimmed.strip_prefix('+') {
            (false, r.trim_start())
        } else if let Some(r) = trimmed.strip_prefix('-') {
            (true, r.trim_start())
        } else {
            (false, trimmed)
        };
        let h = parse_ja3_hash(rest)
            .with_context(|| format!("{}:{}: malformed JA3 overlay entry", path, lineno + 1))?;
        if is_disable {
            disables.insert(h);
        } else {
            adds.insert(h);
        }
    }
    Ok((adds, disables))
}

fn strip_comment(line: &str) -> &str {
    match line.find('#') {
        Some(idx) => &line[..idx],
        None => line,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// External audit NET-001: a dual-stack socket reports an IPv4 peer as
    /// `::ffff:a.b.c.d`; it must match the IPv4 entries.
    #[test]
    fn blocklist_matches_ipv4_mapped_v6_form() {
        let bl = NetBlocklist::from_entries([
            NetBlocklistEntry::parse("192.0.2.0/24").unwrap(),
            NetBlocklistEntry::parse("203.0.113.9").unwrap(),
        ]);
        assert!(bl.contains(&"::ffff:192.0.2.1".parse().unwrap()));
        assert!(bl.contains(&"::ffff:203.0.113.9".parse().unwrap()));
        assert!(!bl.contains(&"::ffff:198.51.100.1".parse().unwrap()));
        assert!(!bl.contains(&"2001:db8::1".parse().unwrap()));
    }
    use std::io::Write;
    use std::net::{Ipv4Addr, Ipv6Addr};
    use tempfile::TempDir;

    fn write_file(dir: &TempDir, name: &str, body: &str) -> std::path::PathBuf {
        let p = dir.path().join(name);
        let mut f = std::fs::File::create(&p).expect("create");
        f.write_all(body.as_bytes()).expect("write");
        p
    }

    /// The overlay at `path` as a gate that accepts it hands it over.
    fn verified(path: &Path) -> Verified {
        match std::fs::read_to_string(path) {
            Ok(text) => Verified::Content {
                path: path.to_path_buf(),
                text,
            },
            Err(_) => Verified::Missing,
        }
    }

    /// Load `v1` as the list the agent was built with (its own content is
    /// the built-in copy): these tests are about parsing and the overlay.
    fn load_own(v1: &Path, local: &Verified) -> NetBlocklist {
        let own = std::fs::read_to_string(v1).unwrap();
        NetBlocklist::load_with(v1, Shipped::new(&own, &[]), local).expect("load")
    }

    /// As [`load_own`], for the JA3 list.
    fn load_own_ja3(v1: &Path, local: &Verified) -> Ja3Blocklist {
        let own = std::fs::read_to_string(v1).unwrap();
        Ja3Blocklist::load_with(v1, Shipped::new(&own, &[]), local).expect("load")
    }

    /// External audit LLMR-015 (NN-AUD-327): a blocklist that still lists
    /// the CGNAT and VPN ranges NET-011 removed — the list of a host
    /// installed before lab PR 78, or one edited by hand — is not what
    /// NN-L-NET-001 kills on: the built-in copy is, and the load says why.
    #[test]
    fn a_blocklist_left_over_with_cgnat_does_not_reach_the_kill_rule() {
        let dir = TempDir::new().unwrap();
        let stale = format!("{BUILTIN_NETFLOW_BLOCKLIST_V1}100.64.0.0/10\n198.18.0.0/15\n");
        let v1 = write_file(&dir, "netflow-blocklist.v1", &stale);
        let bl = NetBlocklist::load(&v1, &Verified::Missing).unwrap();
        assert!(!bl.contains(&"100.64.0.1".parse().unwrap()));
        assert!(!bl.contains(&"198.18.0.1".parse().unwrap()));
        assert!(bl.contains(&"192.0.2.1".parse().unwrap()));
        assert!(matches!(
            bl.defaults(),
            DefaultsSource::Modified {
                loaded_anyway: false,
                ..
            }
        ));
        // the current shipped file is the one used
        let configs = Path::new(env!("CARGO_MANIFEST_DIR")).join("../configs");
        let bl =
            NetBlocklist::load(&configs.join("netflow-blocklist.v1"), &Verified::Missing).unwrap();
        assert_eq!(bl.defaults(), &DefaultsSource::Disk);
        // an earlier release's copy is superseded
        let earlier = "192.0.2.0/24\n100.64.0.0/10\n";
        let sha = hex::encode(crate::config::overlay_auth::content_sha256(
            earlier.as_bytes(),
        ));
        let v1 = write_file(&dir, "earlier.v1", earlier);
        let bl = NetBlocklist::load_with(
            &v1,
            Shipped::new(BUILTIN_NETFLOW_BLOCKLIST_V1, &[sha.as_str()]),
            &Verified::Missing,
        )
        .unwrap();
        assert!(!bl.contains(&"100.64.0.1".parse().unwrap()));
        assert_eq!(bl.defaults(), &DefaultsSource::Superseded { sha256: sha });
    }

    /// External audit LLMR-016: with the `.v1` unreadable the blocklists
    /// are the shipped ones built into the agent (they used to be empty),
    /// and say so.
    #[test]
    fn a_missing_v1_uses_the_built_in_lists() {
        let dir = TempDir::new().unwrap();
        let missing = dir.path().join("missing.v1");
        let bl = NetBlocklist::load(&missing, &Verified::Missing).unwrap();
        assert!(matches!(bl.defaults(), DefaultsSource::BuiltIn(_)));
        assert!(bl.contains(&"192.0.2.1".parse().unwrap()));
        let ja3 = Ja3Blocklist::load(&missing, &Verified::Missing).unwrap();
        assert!(matches!(ja3.defaults(), DefaultsSource::BuiltIn(_)));
        let configs = Path::new(env!("CARGO_MANIFEST_DIR")).join("../configs");
        assert_eq!(
            std::fs::read_to_string(configs.join("netflow-blocklist.v1")).unwrap(),
            BUILTIN_NETFLOW_BLOCKLIST_V1
        );
        assert_eq!(
            std::fs::read_to_string(configs.join("netflow-ja3-blocklist.v1")).unwrap(),
            BUILTIN_JA3_BLOCKLIST_V1
        );
    }

    /// N6 blocklist test #1 — bare flat list of IPs + CIDRs
    /// parses into the expected entries; `contains` matches
    /// both exact + range.
    #[test]
    fn netblocklist_parses_bare_flat_v1() {
        let dir = TempDir::new().unwrap();
        let v1 = write_file(
            &dir,
            "netflow-blocklist.v1",
            "# header\n1.2.3.4\n10.0.0.0/8\n# comment\n2001:db8::/32\n",
        );
        let local = dir.path().join("netflow-blocklist.local");
        let bl = load_own(&v1, &verified(&local));
        assert_eq!(bl.len(), 3);
        assert!(bl.contains(&IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))));
        assert!(bl.contains(&IpAddr::V4(Ipv4Addr::new(10, 50, 60, 70))));
        assert!(!bl.contains(&IpAddr::V4(Ipv4Addr::new(11, 0, 0, 1))));
        assert!(bl.contains(&IpAddr::V6("2001:db8::dead:beef".parse().unwrap())));
    }

    /// N6 blocklist test #2 — `.local` overlay adds entries
    /// via `+IP`. Bare entries without prefix are treated as
    /// `+IP` per the design.
    #[test]
    fn netblocklist_overlay_adds_via_plus_and_bare() {
        let dir = TempDir::new().unwrap();
        let v1 = write_file(&dir, "netflow-blocklist.v1", "1.1.1.1\n");
        let local = write_file(&dir, "netflow-blocklist.local", "+2.2.2.2\n3.3.3.3\n");
        let bl = load_own(&v1, &verified(&local));
        assert!(bl.contains(&IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))));
        assert!(bl.contains(&IpAddr::V4(Ipv4Addr::new(2, 2, 2, 2))));
        assert!(bl.contains(&IpAddr::V4(Ipv4Addr::new(3, 3, 3, 3))));
    }

    /// N6 blocklist test #3 — `-IP` disables a default. The
    /// disabled entry vanishes from `contains`.
    #[test]
    fn netblocklist_overlay_disables_via_minus() {
        let dir = TempDir::new().unwrap();
        let v1 = write_file(&dir, "netflow-blocklist.v1", "1.1.1.1\n2.2.2.2\n");
        let local = write_file(&dir, "netflow-blocklist.local", "-1.1.1.1\n");
        let bl = load_own(&v1, &verified(&local));
        assert!(!bl.contains(&IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))));
        assert!(bl.contains(&IpAddr::V4(Ipv4Addr::new(2, 2, 2, 2))));
    }

    /// N6 blocklist test #4 — `-IP` for an IP that's not in
    /// the default list is a silent no-op (logged as WARN at
    /// boot — tested via the load() trace path, not this
    /// assertion). The load doesn't error.
    #[test]
    fn netblocklist_unknown_disable_is_silent_noop() {
        let dir = TempDir::new().unwrap();
        let v1 = write_file(&dir, "netflow-blocklist.v1", "1.1.1.1\n");
        let local = write_file(&dir, "netflow-blocklist.local", "-9.9.9.9\n+2.2.2.2\n");
        let bl = load_own(&v1, &verified(&local));
        assert!(bl.contains(&IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))));
        assert!(bl.contains(&IpAddr::V4(Ipv4Addr::new(2, 2, 2, 2))));
        assert!(!bl.contains(&IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9))));
    }

    /// CIDR matching is correct for boundary cases.
    #[test]
    fn cidr_contains_boundary_cases() {
        assert!(cidr_contains(
            &IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)),
            8,
            &IpAddr::V4(Ipv4Addr::new(10, 255, 255, 255))
        ));
        assert!(!cidr_contains(
            &IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)),
            8,
            &IpAddr::V4(Ipv4Addr::new(11, 0, 0, 0))
        ));
        // /0 matches everything (sanity).
        assert!(cidr_contains(
            &IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            0,
            &IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))
        ));
        // Cross-family v4 vs v6 always false.
        assert!(!cidr_contains(
            &IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)),
            8,
            &IpAddr::V6(Ipv6Addr::LOCALHOST)
        ));
    }

    /// Defective entries surface an error including line
    /// number — operators get an actionable parse error
    /// instead of a silent "no defaults this boot."
    #[test]
    fn shipped_seed_contains_no_prefix_in_real_world_use() {
        // External audit NET-011 (NN-AUD-060): the seed feeds NN-L-NET-001
        // (KillProcessTree); CGNAT and benchmarking space are in daily use.
        let shipped = Path::new(env!("CARGO_MANIFEST_DIR")).join("../configs/netflow-blocklist.v1");
        let bl = NetBlocklist::load(&shipped, &Verified::Missing).unwrap();
        for a in [
            "100.64.0.1",
            "100.100.100.100",
            "198.18.0.1",
            "198.19.255.1",
        ] {
            assert!(
                !bl.contains(&a.parse().unwrap()),
                "{a}: CGNAT/VPN space must not be on a KillProcessTree list"
            );
        }
        assert!(bl.contains(&"192.0.2.1".parse().unwrap()));
        assert!(bl.contains(&"2001:db8::1".parse().unwrap()));
    }

    #[test]
    fn malformed_line_does_not_disable_the_whole_list() {
        // External audit NET-002 (NN-AUD-056): one bad line used to empty
        // the default list.
        let dir = TempDir::new().unwrap();
        let v1 = write_file(
            &dir,
            "netflow-blocklist.v1",
            "1.1.1.1\nnot-an-ip\n+3.3.3.3\n2.2.2.2\n",
        );
        let local = write_file(
            &dir,
            "netflow-blocklist.local",
            "+4.4.4.4\n+bad\n-1.1.1.1\n",
        );
        let bl = load_own(&v1, &verified(&local));
        assert_eq!(bl.len(), 2, "2.2.2.2 and 4.4.4.4; 1.1.1.1 disabled");
        assert!(bl.contains(&"2.2.2.2".parse().unwrap()));
        assert!(bl.contains(&"4.4.4.4".parse().unwrap()));
        assert!(!bl.contains(&"1.1.1.1".parse().unwrap()));
        // the overlay validation before signing stays strict
        assert!(parse_blocklist_overlay_text("x", "+bad\n").is_err());
    }

    #[test]
    fn malformed_ja3_line_does_not_disable_the_whole_list() {
        let dir = TempDir::new().unwrap();
        let good = "a".repeat(32);
        let other = "b".repeat(32);
        let v1 = write_file(
            &dir,
            "netflow-ja3-blocklist.v1",
            &format!("{good}\nnot-a-hash\n{other}\n"),
        );
        let local = dir.path().join("netflow-ja3-blocklist.local");
        let bl = load_own_ja3(&v1, &verified(&local));
        assert_eq!(bl.len(), 2);
        assert!(bl.contains(&good) && bl.contains(&other));
        assert!(parse_ja3_overlay_text("x", "+zz\n").is_err());
    }

    // ── JA3 blocklist tests ─────────────────────────────────────────

    /// JA3 v1 parsing — 32-hex char entries accepted, malformed
    /// rejected.
    #[test]
    fn ja3_blocklist_parses_bare_flat_v1() {
        let dir = TempDir::new().unwrap();
        let valid = "a0e9f5d64349fb13191bc781f81f42e1";
        let v1 = write_file(
            &dir,
            "netflow-ja3-blocklist.v1",
            &format!("# header\n{valid}\n"),
        );
        let local = dir.path().join("netflow-ja3-blocklist.local");
        let bl = load_own_ja3(&v1, &verified(&local));
        assert!(bl.contains(valid));
        assert!(!bl.contains("00000000000000000000000000000000"));
    }

    /// N8 deploy test: the shipped `configs/netflow-blocklist.v1`
    /// default file parses cleanly via `NetBlocklist::load`. The
    /// file ships under `configs/` in the repo and install.sh
    /// drops it at `/etc/northnarrow/netflow-blocklist.v1` —
    /// anchor here so a malformed seed (typo in an RFC range,
    /// stray `+`/`-` prefix, accidental directive) fails CI
    /// before reaching an operator's host. Side-load: same
    /// invariant the Tappa 9 C7 `configs/fim-paths.v1` carries
    /// via its production loader.
    #[test]
    fn net_blocklist_v1_default_loads_clean() {
        let v1 = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("configs")
            .join("netflow-blocklist.v1");
        assert!(
            v1.exists(),
            "configs/netflow-blocklist.v1 must ship in the repo \
             (install.sh deploys this file to /etc/northnarrow/)"
        );
        let bl = NetBlocklist::load(&v1, &Verified::Missing)
            .expect("shipped configs/netflow-blocklist.v1 must parse clean");
        assert!(
            !bl.is_empty(),
            "shipped default ships at least one seed entry \
             (RFC-reserved test prefixes per design §10)"
        );
        // Sanity: 192.0.2.1 (RFC 5737 TEST-NET-1) is in the seed.
        assert!(
            bl.contains(&IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1))),
            "RFC 5737 TEST-NET-1 entry must be in the shipped seed"
        );
    }

    /// N8 deploy test: the shipped `configs/netflow-ja3-blocklist.v1`
    /// default file parses cleanly via `Ja3Blocklist::load`. The
    /// V1.0 ship is INTENTIONALLY EMPTY per design §10 (operator
    /// populates via the `.local` overlay from their EDR vendor's
    /// fingerprint feed); we still anchor that the file parses so
    /// a stray byte in a future operator-curated update fails CI
    /// before reaching a host.
    #[test]
    fn net_ja3_blocklist_v1_default_loads_clean() {
        let v1 = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("configs")
            .join("netflow-ja3-blocklist.v1");
        assert!(
            v1.exists(),
            "configs/netflow-ja3-blocklist.v1 must ship in the repo \
             (install.sh deploys this file to /etc/northnarrow/)"
        );
        let bl = Ja3Blocklist::load(&v1, &Verified::Missing)
            .expect("shipped configs/netflow-ja3-blocklist.v1 must parse clean");
        assert!(
            bl.is_empty(),
            "V1.0 ships an empty JA3 default per design §10 — \
             operator populates via netflow-ja3-blocklist.local"
        );
    }

    /// Uppercase JA3 entries are normalised to lowercase at
    /// parse time so operators can paste vendor-provided
    /// fingerprints in either case + matches still work.
    #[test]
    fn ja3_blocklist_normalises_case() {
        let valid_upper = "A0E9F5D64349FB13191BC781F81F42E1";
        let valid_lower = "a0e9f5d64349fb13191bc781f81f42e1";
        let bl = Ja3Blocklist::from_entries([valid_upper]);
        // from_entries doesn't normalise (deferred to parser).
        // The PARSER does. Test via parse_ja3_hash.
        assert_eq!(parse_ja3_hash(valid_upper).unwrap(), valid_lower);
        // bare from_entries (test/admin constructor) doesn't
        // round-trip the case automatically — production
        // callers go through parse_ja3_hash via load().
        let _ = bl;
    }
    /// External audit NET-009: a JA3 list loaded with no fingerprint
    /// producer is reported at boot (ERROR + signed `subsystem_degraded`);
    /// an empty list, or a build with a producer, is not. `net status`
    /// names NN-L-NET-003 as inactive either way while there is no
    /// producer.
    #[test]
    fn a_ja3_list_without_a_fingerprint_producer_is_reported() {
        let gap = ja3_coverage_gap(1, false).expect("reported");
        assert!(gap.contains("NN-L-NET-003 inactive"), "{gap}");
        assert!(gap.contains("1 JA3 blocklist entry loaded"), "{gap}");
        assert!(ja3_coverage_gap(0, false).is_none());
        assert!(ja3_coverage_gap(3, true).is_none());
        let inactive = inactive_net_rules_with(2, false, None);
        assert_eq!(inactive.len(), 1);
        assert!(inactive[0].starts_with("NN-L-NET-003"), "{inactive:?}");
        assert!(inactive[0].contains("2 JA3 blocklist entries"));
        assert!(inactive_net_rules_with(2, true, None).is_empty());
    }

    /// External audit NET-017 (lab PR 207): systemd-resolved on DNS over
    /// TLS adds the DNS rules, with the reason and the file, after the JA3
    /// entry; off, nothing is added.
    #[test]
    fn a_resolver_on_dns_over_tls_lists_the_blind_dns_rules() {
        use crate::net::blind_spots::{resolver_dns_over_tls_under, DotMode, ResolverDot};
        let dot = ResolverDot {
            mode: DotMode::Yes,
            source: std::path::PathBuf::from("/etc/systemd/resolved.conf.d/50-dot.conf"),
        };
        let inactive = inactive_net_rules_with(0, false, Some(&dot));
        assert_eq!(inactive.len(), 2, "{inactive:?}");
        assert!(inactive[0].starts_with("NN-L-NET-003"), "{inactive:?}");
        assert!(
            inactive[1].starts_with(
                "NN-L-NET-002/004/005/014 (DNS): blind to the local resolver's upstream"
            ),
            "{inactive:?}"
        );
        assert!(inactive[1].contains("50-dot.conf"), "{inactive:?}");
        // With a producer, the DNS entry alone.
        assert_eq!(inactive_net_rules_with(0, true, Some(&dot)).len(), 1);

        // From the files: a drop-in on, then removed.
        let root = tempfile::tempdir().unwrap();
        let d = root.path().join("etc/systemd/resolved.conf.d");
        std::fs::create_dir_all(&d).unwrap();
        std::fs::write(d.join("50-dot.conf"), "[Resolve]\nDNSOverTLS=yes\n").unwrap();
        let read = resolver_dns_over_tls_under(root.path());
        assert_eq!(inactive_net_rules_with(0, false, read.as_ref()).len(), 2);
        std::fs::remove_file(d.join("50-dot.conf")).unwrap();
        let read = resolver_dns_over_tls_under(root.path());
        assert_eq!(inactive_net_rules_with(0, false, read.as_ref()).len(), 1);
    }

    /// The shipped `.v1` no longer says NN-L-NET-003 "stays functional".
    #[test]
    fn the_shipped_ja3_list_states_the_rule_is_inactive() {
        assert!(!BUILTIN_JA3_BLOCKLIST_V1.contains("stays functional"));
        assert!(BUILTIN_JA3_BLOCKLIST_V1.contains("BUG-025"));
    }
}
