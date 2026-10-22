//! Lab PR 224 (CM-02 d): the host's configured DNS resolvers.
//!
//! NN-L-NET-008 and NN-L-CHAIN-002/005 leave a staged image's flow to
//! port 53 alone: a dropper resolving a name is not the egress that
//! matters. The exemption ignored the protocol and the destination
//! (research defect D1), so an implant in `/tmp` with its C2 on TCP/53 to
//! its own server passed all three. A port-53 flow is now exempt only
//! when it goes to one of the resolvers the host is configured with: the
//! `nameserver` lines of `/etc/resolv.conf` and, on a host running
//! systemd-resolved, of `/run/systemd/resolve/resolv.conf` (its upstream
//! servers; `/etc/resolv.conf` then names the stub `127.0.0.53`).
//!
//! The files are re-read when their size or modification time changed,
//! looked at most every [`REFRESH`] (DHCP and VPN clients rewrite them).
//! A file that cannot be read contributes no resolver: the exemption then
//! narrows, it never widens.

use std::collections::BTreeSet;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

use parking_lot::RwLock;

/// The files read on a host.
pub const RESOLV_CONF_PATHS: &[&str] = &["/etc/resolv.conf", "/run/systemd/resolve/resolv.conf"];

/// How often the files' metadata is looked at.
pub const REFRESH: Duration = Duration::from_secs(5);

/// The DNS port.
pub const DNS_PORT: u16 = 53;

/// Most `nameserver` lines kept per file (glibc uses three; a longer list
/// is not a resolver configuration).
const MAX_PER_FILE: usize = 16;

/// The addresses of the `nameserver` lines of a `resolv.conf` text, in
/// order, canonical (an IPv4-mapped IPv6 address as IPv4), without
/// duplicates. A zone index (`fe80::1%eth0`) is dropped; a line whose
/// address does not parse, a comment (`#`, `;`), any other keyword and
/// lines past the [`MAX_PER_FILE`]th address are ignored.
pub fn parse_resolv_conf(text: &str) -> Vec<IpAddr> {
    let mut out = Vec::new();
    for line in text.lines() {
        let line = line.trim_start();
        if line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        let mut words = line.split_whitespace();
        if words.next() != Some("nameserver") {
            continue;
        }
        let Some(addr) = words.next() else {
            continue;
        };
        let addr = addr.split('%').next().unwrap_or(addr);
        let Ok(ip) = addr.parse::<IpAddr>() else {
            continue;
        };
        let ip = nn_model::netaddr::canonical(ip);
        if !out.contains(&ip) {
            out.push(ip);
        }
        if out.len() >= MAX_PER_FILE {
            break;
        }
    }
    out
}

/// What a file looked like when last read.
type Stamp = Option<(SystemTime, u64)>;

fn stamp(path: &Path) -> Stamp {
    let m = std::fs::metadata(path).ok()?;
    Some((m.modified().ok()?, m.len()))
}

/// Bound on a file read (a resolv.conf is a few hundred bytes).
const MAX_FILE_BYTES: u64 = 64 * 1024;

fn read_bounded(path: &Path) -> Option<String> {
    use std::io::Read;
    let f = std::fs::File::open(path).ok()?;
    let mut s = String::new();
    f.take(MAX_FILE_BYTES).read_to_string(&mut s).ok()?;
    Some(s)
}

struct State {
    set: BTreeSet<IpAddr>,
    stamps: Vec<Stamp>,
    checked: Option<Instant>,
}

/// The resolver set the rules consult ([`HostResolvers::contains`]).
pub struct HostResolvers {
    /// Files read; empty for a fixed set.
    files: Vec<PathBuf>,
    state: RwLock<State>,
}

impl HostResolvers {
    /// The host's set (production).
    pub fn for_host() -> Arc<Self> {
        Self::from_files(RESOLV_CONF_PATHS.iter().map(PathBuf::from).collect())
    }

    /// The set read from `files` (fixture directories in tests).
    pub fn from_files(files: Vec<PathBuf>) -> Arc<Self> {
        let r = Self {
            files,
            state: RwLock::new(State {
                set: BTreeSet::new(),
                stamps: Vec::new(),
                checked: None,
            }),
        };
        r.refresh(Instant::now());
        Arc::new(r)
    }

    /// A fixed set (tests, the boot-time rule set).
    pub fn fixed(addrs: impl IntoIterator<Item = IpAddr>) -> Arc<Self> {
        Arc::new(Self {
            files: Vec::new(),
            state: RwLock::new(State {
                set: addrs
                    .into_iter()
                    .map(nn_model::netaddr::canonical)
                    .collect(),
                stamps: Vec::new(),
                checked: None,
            }),
        })
    }

    /// No resolver: every port-53 flow is judged like any other.
    pub fn none() -> Arc<Self> {
        Self::fixed([])
    }

    /// `addr` is a configured resolver.
    pub fn contains(&self, addr: &IpAddr) -> bool {
        if !self.files.is_empty() {
            let due = self
                .state
                .read()
                .checked
                .is_none_or(|t| t.elapsed() >= REFRESH);
            if due {
                self.refresh(Instant::now());
            }
        }
        self.state
            .read()
            .set
            .contains(&nn_model::netaddr::canonical(*addr))
    }

    /// The set now (status, logs).
    pub fn snapshot(&self) -> Vec<IpAddr> {
        self.state.read().set.iter().copied().collect()
    }

    fn refresh(&self, now: Instant) {
        if self.files.is_empty() {
            return;
        }
        let stamps: Vec<Stamp> = self.files.iter().map(|p| stamp(p)).collect();
        let mut st = self.state.write();
        st.checked = Some(now);
        if st.stamps == stamps && !st.stamps.is_empty() {
            return;
        }
        let mut set = BTreeSet::new();
        for path in &self.files {
            if let Some(text) = read_bounded(path) {
                set.extend(parse_resolv_conf(&text));
            }
        }
        st.set = set;
        st.stamps = stamps;
    }
}

/// A flow to the DNS port of a configured resolver: the resolution a
/// staged image may make (NN-L-NET-008, NN-L-CHAIN-002/005).
pub fn is_resolver_flow(nf: &nn_model::telemetry::NetFlowEvent, resolvers: &HostResolvers) -> bool {
    nf.dst_port == DNS_PORT && resolvers.contains(&nf.dst_addr)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nameserver_lines_are_read_and_everything_else_ignored() {
        let text = "# Generated by NetworkManager\n\
                    search lan\n\
                    nameserver 127.0.0.53\n\
                    options edns0 trust-ad\n\
                    ;nameserver 10.0.0.9\n\
                    \tnameserver   192.0.2.53   # trailing\n\
                    nameserver fe80::1%eth0\n\
                    nameserver ::ffff:198.51.100.53\n\
                    nameserver not-an-address\n\
                    nameserver\n\
                    nameserver 127.0.0.53\n";
        let got = parse_resolv_conf(text);
        assert_eq!(
            got,
            vec![
                "127.0.0.53".parse::<IpAddr>().unwrap(),
                "192.0.2.53".parse().unwrap(),
                "fe80::1".parse().unwrap(),
                "198.51.100.53".parse().unwrap(),
            ]
        );
    }

    #[test]
    fn at_most_sixteen_resolvers_per_file() {
        let text: String = (1..=40)
            .map(|i| format!("nameserver 10.0.0.{i}\n"))
            .collect();
        assert_eq!(parse_resolv_conf(&text).len(), 16);
    }

    /// The set follows a rewrite of the file (DHCP, a VPN client).
    #[test]
    fn the_set_follows_the_files() {
        let dir = tempfile::tempdir().unwrap();
        let a = dir.path().join("resolv.conf");
        let b = dir.path().join("missing.conf");
        std::fs::write(&a, "nameserver 192.0.2.53\n").unwrap();
        let r = HostResolvers::from_files(vec![a.clone(), b]);
        assert!(r.contains(&"192.0.2.53".parse().unwrap()));
        assert!(!r.contains(&"127.0.0.1".parse().unwrap()));
        std::fs::write(&a, "nameserver 198.51.100.1\nnameserver 198.51.100.2\n").unwrap();
        r.refresh(Instant::now());
        assert_eq!(
            r.snapshot(),
            vec![
                "198.51.100.1".parse::<IpAddr>().unwrap(),
                "198.51.100.2".parse().unwrap()
            ]
        );
        // An unreadable file narrows the set, never widens it.
        std::fs::remove_file(&a).unwrap();
        r.refresh(Instant::now());
        assert!(r.snapshot().is_empty());
    }

    #[test]
    fn an_ipv4_mapped_destination_matches_its_resolver() {
        let r = HostResolvers::fixed(["192.0.2.53".parse().unwrap()]);
        assert!(r.contains(&"::ffff:192.0.2.53".parse().unwrap()));
        assert!(!HostResolvers::none().contains(&"192.0.2.53".parse().unwrap()));
    }
}
