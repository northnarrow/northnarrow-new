//! The network canaries' addresses (NN-L-CANARY-003, lab PR 163): the
//! address side of a canary, whether a connect reaches it, the destination
//! a connect record names, one port's canaries. The agent's
//! `canary::network` says why a canary is a destination; it keeps what
//! reads the host (its interface addresses, its TCP listeners) and the
//! deploy check, and re-exports these.
//!
//! Wave 4 restructure, R08b (lab PR 251): cut verbatim from the agent's
//! `canary::network` when the canary detector, which reads them, moved
//! here; `as_connected` is `pub` (the agent's interface addresses read it).

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use nn_model::netaddr::{canonical, AF_INET, AF_INET6};

/// The address side of a network canary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CanaryAddr {
    /// One address, canonical (an IPv4-mapped IPv6 address is its IPv4
    /// address).
    Exact(IpAddr),
    /// `0.0.0.0`: every IPv4 address of this host.
    AnyV4,
    /// `::`: every address of this host, IPv4 included.
    Any,
}

impl CanaryAddr {
    /// The canary address `--bind-addr` names; `None` when it is not an IP
    /// address.
    pub fn parse(s: &str) -> Option<Self> {
        let addr = canonical(s.trim().parse::<IpAddr>().ok()?);
        Some(match addr {
            IpAddr::V4(a) if a.is_unspecified() => CanaryAddr::AnyV4,
            IpAddr::V6(a) if a.is_unspecified() => CanaryAddr::Any,
            a => CanaryAddr::Exact(a),
        })
    }

    /// Whether a connect to `dst` (canonical) reaches this canary.
    /// `is_local` says whether an address is one of this host's; it is
    /// called only for a wildcard canary and a destination that is not a
    /// loopback address.
    pub fn covers(self, dst: IpAddr, is_local: &dyn Fn(IpAddr) -> bool) -> bool {
        let dst = as_connected(dst);
        match self {
            CanaryAddr::Exact(a) => a == dst,
            CanaryAddr::AnyV4 => dst.is_ipv4() && (dst.is_loopback() || is_local(dst)),
            CanaryAddr::Any => dst.is_loopback() || is_local(dst),
        }
    }

    /// Exact canaries first: when an exact and a wildcard canary both
    /// cover a connect, the trip names the exact one.
    fn is_exact(self) -> bool {
        matches!(self, CanaryAddr::Exact(_))
    }
}

/// Linux connects a destination of `0.0.0.0` (`::`) to the loopback
/// address of its family.
pub fn as_connected(dst: IpAddr) -> IpAddr {
    match dst {
        IpAddr::V4(a) if a.is_unspecified() => IpAddr::V4(Ipv4Addr::LOCALHOST),
        IpAddr::V6(a) if a.is_unspecified() => IpAddr::V6(Ipv6Addr::LOCALHOST),
        a => a,
    }
}

/// The destination a connect record names, canonical; `None` when the
/// record is not the one to judge. A dual-stack socket connecting to an
/// IPv4-mapped address goes through `tcp_v6_connect`, which calls
/// `tcp_v4_connect`: the sensor reports that connect twice, and only the
/// IPv4 record is judged (one access, one row).
pub fn connect_destination(family: u8, bytes: &[u8; 16]) -> Option<IpAddr> {
    match family {
        AF_INET => Some(IpAddr::V4(Ipv4Addr::new(
            bytes[0], bytes[1], bytes[2], bytes[3],
        ))),
        AF_INET6 => {
            let v6 = Ipv6Addr::from(*bytes);
            v6.to_ipv4_mapped().is_none().then_some(IpAddr::V6(v6))
        }
        _ => None,
    }
}

/// One port's network canaries, exact ones first.
#[derive(Debug, Default)]
pub(crate) struct PortCanaries(Vec<(CanaryAddr, String)>);

impl PortCanaries {
    pub(crate) fn push(&mut self, addr: CanaryAddr, canary_id: String) {
        let at = if addr.is_exact() {
            self.0.iter().take_while(|(a, _)| a.is_exact()).count()
        } else {
            self.0.len()
        };
        self.0.insert(at, (addr, canary_id));
    }

    pub(crate) fn find(&self, dst: IpAddr, is_local: &dyn Fn(IpAddr) -> bool) -> Option<&str> {
        self.0
            .iter()
            .find(|(a, _)| a.covers(dst, is_local))
            .map(|(_, id)| id.as_str())
    }

    pub(crate) fn len(&self) -> usize {
        self.0.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn v4(a: [u8; 4]) -> [u8; 16] {
        let mut b = [0u8; 16];
        b[..4].copy_from_slice(&a);
        b
    }

    const NOT_LOCAL: &dyn Fn(IpAddr) -> bool = &|_| false;

    #[test]
    fn bind_addresses_parse_to_exact_or_wildcard() {
        assert_eq!(
            CanaryAddr::parse("100.64.0.9"),
            Some(CanaryAddr::Exact(ip("100.64.0.9")))
        );
        assert_eq!(
            CanaryAddr::parse(" ::ffff:100.64.0.9 "),
            Some(CanaryAddr::Exact(ip("100.64.0.9"))),
            "an IPv4-mapped address is its IPv4 address"
        );
        assert_eq!(CanaryAddr::parse("0.0.0.0"), Some(CanaryAddr::AnyV4));
        assert_eq!(CanaryAddr::parse("::"), Some(CanaryAddr::Any));
        assert_eq!(CanaryAddr::parse("db.internal"), None);
        assert_eq!(CanaryAddr::parse("100.64.0.9:4444"), None);
        assert_eq!(CanaryAddr::parse(""), None);
    }

    #[test]
    fn an_exact_canary_covers_its_address_only() {
        let c = CanaryAddr::Exact(ip("100.64.0.9"));
        assert!(c.covers(ip("100.64.0.9"), NOT_LOCAL));
        assert!(!c.covers(ip("100.64.0.10"), NOT_LOCAL));
        assert!(!c.covers(ip("127.0.0.1"), &|_| true));
        // a connect to 0.0.0.0 reaches 127.0.0.1
        let lo = CanaryAddr::Exact(ip("127.0.0.1"));
        assert!(lo.covers(ip("0.0.0.0"), NOT_LOCAL));
        assert!(!lo.covers(ip("127.0.0.2"), NOT_LOCAL));
        assert!(CanaryAddr::Exact(ip("::1")).covers(ip("::"), NOT_LOCAL));
    }

    #[test]
    fn a_wildcard_canary_covers_this_hosts_addresses_only() {
        let local = |a: IpAddr| a == ip("100.64.0.9") || a == ip("fd00::9");
        let v4 = CanaryAddr::AnyV4;
        for dst in ["127.0.0.1", "127.3.2.1", "0.0.0.0", "100.64.0.9"] {
            assert!(v4.covers(ip(dst), &local), "{dst}");
        }
        for dst in ["100.64.0.10", "192.0.2.7", "::1", "fd00::9"] {
            assert!(!v4.covers(ip(dst), &local), "{dst}");
        }
        let any = CanaryAddr::Any;
        for dst in ["127.0.0.1", "::1", "::", "fd00::9", "100.64.0.9"] {
            assert!(any.covers(ip(dst), &local), "{dst}");
        }
        for dst in ["192.0.2.7", "2001:db8::1"] {
            assert!(!any.covers(ip(dst), &local), "{dst}");
        }
    }

    #[test]
    fn a_v4_mapped_connect_is_judged_on_its_ipv4_record() {
        assert_eq!(
            connect_destination(AF_INET, &v4([100, 64, 0, 9])),
            Some(ip("100.64.0.9"))
        );
        let mapped: Ipv6Addr = "::ffff:100.64.0.9".parse().unwrap();
        assert_eq!(connect_destination(AF_INET6, &mapped.octets()), None);
        let real: Ipv6Addr = "fd00::9".parse().unwrap();
        assert_eq!(
            connect_destination(AF_INET6, &real.octets()),
            Some(ip("fd00::9"))
        );
        assert_eq!(connect_destination(1, &[0u8; 16]), None);
    }

    #[test]
    fn exact_canaries_are_found_before_wildcard_ones() {
        let mut port = PortCanaries::default();
        port.push(CanaryAddr::Any, "wild".into());
        port.push(CanaryAddr::Exact(ip("127.0.0.1")), "lo".into());
        port.push(CanaryAddr::Exact(ip("100.64.0.9")), "dummy".into());
        assert_eq!(port.find(ip("127.0.0.1"), NOT_LOCAL), Some("lo"));
        assert_eq!(port.find(ip("100.64.0.9"), NOT_LOCAL), Some("dummy"));
        assert_eq!(port.find(ip("::1"), NOT_LOCAL), Some("wild"));
        assert_eq!(port.find(ip("192.0.2.7"), NOT_LOCAL), None);
        assert_eq!(port.len(), 3);
    }
}
