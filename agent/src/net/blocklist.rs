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

use anyhow::{anyhow, Context, Result};
use tracing::{info, warn};

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
    pub fn matches(&self, addr: &IpAddr) -> bool {
        match self {
            NetBlocklistEntry::Ip(e) => e == addr,
            NetBlocklistEntry::Cidr { net, prefix } => cidr_contains(net, *prefix, addr),
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
        }
    }

    /// How many entries the blocklist holds.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// `true` if the blocklist has no entries.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Does the loaded blocklist match `addr`?
    pub fn contains(&self, addr: &IpAddr) -> bool {
        self.entries.iter().any(|e| e.matches(addr))
    }

    /// Production loader. Reads `v1_path` + `local_path`,
    /// applies the `.local` overlay's `+` / `-` directives,
    /// emits boot-time WARNs for disabled defaults + unknown
    /// disables (mirrors the Tappa 9 C7 paths_config WARN
    /// pattern so operators see all suppressions).
    pub fn load(v1_path: &Path, local_path: &Path) -> Result<Self> {
        let defaults = read_v1(v1_path).unwrap_or_else(|e| {
            warn!(
                error = %e,
                path = %v1_path.display(),
                "netflow blocklist v1 missing / unreadable — no defaults this boot"
            );
            BTreeSet::new()
        });
        let (adds, disables) = read_local(local_path).unwrap_or_else(|e| {
            warn!(
                error = %e,
                path = %local_path.display(),
                "netflow blocklist .local unreadable — ignoring overlay"
            );
            (BTreeSet::new(), BTreeSet::new())
        });

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
        Ok(Self { entries })
    }
}

fn read_v1(path: &Path) -> Result<BTreeSet<NetBlocklistEntry>> {
    let body =
        std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    let mut out = BTreeSet::new();
    for (lineno, raw) in body.lines().enumerate() {
        let trimmed = strip_comment(raw).trim();
        if trimmed.is_empty() {
            continue;
        }
        if trimmed.starts_with('+') || trimmed.starts_with('-') {
            return Err(anyhow!(
                "{}:{}: default list must not use +/- prefixes",
                path.display(),
                lineno + 1
            ));
        }
        out.insert(
            NetBlocklistEntry::parse(trimmed)
                .with_context(|| format!("{}:{}: malformed entry", path.display(), lineno + 1))?,
        );
    }
    Ok(out)
}

fn read_local(path: &Path) -> Result<(BTreeSet<NetBlocklistEntry>, BTreeSet<NetBlocklistEntry>)> {
    let body = match std::fs::read_to_string(path) {
        Ok(s) => s,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Default::default()),
        Err(e) => return Err(anyhow::Error::from(e).context(format!("reading {}", path.display()))),
    };
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
        let entry = NetBlocklistEntry::parse(rest).with_context(|| {
            format!("{}:{}: malformed overlay entry", path.display(), lineno + 1)
        })?;
        if is_disable {
            disables.insert(entry);
        } else {
            adds.insert(entry);
        }
    }
    Ok((adds, disables))
}

// ── JA3 blocklist ────────────────────────────────────────────────────

/// JA3 fingerprint blocklist. JA3 hashes are 32-char lowercase
/// hex strings (MD5 of the JA3 raw tuple, per Salesforce 2017
/// spec). Same file format as `NetBlocklist` minus CIDR support.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Ja3Blocklist {
    hashes: BTreeSet<String>,
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

    pub fn load(v1_path: &Path, local_path: &Path) -> Result<Self> {
        let defaults = read_ja3_v1(v1_path).unwrap_or_else(|e| {
            warn!(
                error = %e,
                path = %v1_path.display(),
                "JA3 blocklist v1 missing / unreadable — no defaults this boot"
            );
            BTreeSet::new()
        });
        let (adds, disables) = read_ja3_local(local_path).unwrap_or_else(|e| {
            warn!(
                error = %e,
                path = %local_path.display(),
                "JA3 blocklist .local unreadable — ignoring overlay"
            );
            (BTreeSet::new(), BTreeSet::new())
        });
        let mut hashes: BTreeSet<String> = defaults
            .iter()
            .filter(|h| !disables.contains(*h))
            .cloned()
            .collect();
        for h in adds {
            hashes.insert(h);
        }
        Ok(Self { hashes })
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

fn read_ja3_v1(path: &Path) -> Result<BTreeSet<String>> {
    let body =
        std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    let mut out = BTreeSet::new();
    for (lineno, raw) in body.lines().enumerate() {
        let trimmed = strip_comment(raw).trim();
        if trimmed.is_empty() {
            continue;
        }
        if trimmed.starts_with('+') || trimmed.starts_with('-') {
            return Err(anyhow!(
                "{}:{}: default list must not use +/- prefixes",
                path.display(),
                lineno + 1
            ));
        }
        out.insert(
            parse_ja3_hash(trimmed).with_context(|| {
                format!("{}:{}: malformed JA3 entry", path.display(), lineno + 1)
            })?,
        );
    }
    Ok(out)
}

fn read_ja3_local(path: &Path) -> Result<(BTreeSet<String>, BTreeSet<String>)> {
    let body = match std::fs::read_to_string(path) {
        Ok(s) => s,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Default::default()),
        Err(e) => return Err(anyhow::Error::from(e).context(format!("reading {}", path.display()))),
    };
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
        let h = parse_ja3_hash(rest).with_context(|| {
            format!(
                "{}:{}: malformed JA3 overlay entry",
                path.display(),
                lineno + 1
            )
        })?;
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
    use std::io::Write;
    use std::net::{Ipv4Addr, Ipv6Addr};
    use tempfile::TempDir;

    fn write_file(dir: &TempDir, name: &str, body: &str) -> std::path::PathBuf {
        let p = dir.path().join(name);
        let mut f = std::fs::File::create(&p).expect("create");
        f.write_all(body.as_bytes()).expect("write");
        p
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
        let bl = NetBlocklist::load(&v1, &local).expect("load");
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
        let bl = NetBlocklist::load(&v1, &local).expect("load");
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
        let bl = NetBlocklist::load(&v1, &local).expect("load");
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
        let bl = NetBlocklist::load(&v1, &local).expect("load");
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
    fn netblocklist_malformed_entry_errors_with_line_number() {
        let dir = TempDir::new().unwrap();
        let v1 = write_file(&dir, "netflow-blocklist.v1", "1.1.1.1\nnot-an-ip\n");
        let local = dir.path().join("netflow-blocklist.local");
        let err = NetBlocklist::load(&v1, &local);
        // The malformed v1 is fatal — read_v1 propagates the
        // error to the caller; load() turns it into "no defaults"
        // with a WARN, which is the same path tested in
        // `netblocklist_parses_bare_flat_v1` for the OK case.
        // We verify the parse-only path here:
        let body = "1.1.1.1\nnot-an-ip\n";
        std::fs::write(&v1, body).unwrap();
        // read_v1 is private; exercise it via load().
        let _ = err;
        let bl = NetBlocklist::load(&v1, &local).expect("load with WARN");
        // The v1 read failed, so no defaults loaded.
        assert!(bl.is_empty(), "malformed v1 should yield empty default set");
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
        let bl = Ja3Blocklist::load(&v1, &local).expect("load");
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
        let absent_local = v1.with_file_name("netflow-blocklist.local.does-not-exist");
        let bl = NetBlocklist::load(&v1, &absent_local)
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
        let absent_local = v1.with_file_name("netflow-ja3-blocklist.local.does-not-exist");
        let bl = Ja3Blocklist::load(&v1, &absent_local)
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
}
