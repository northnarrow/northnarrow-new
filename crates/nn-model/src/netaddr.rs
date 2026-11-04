//! Network addresses as the kernel records them: a family and 16 bytes.
//!
//! External audit NET-001 (NN-AUD-005): a dual-stack `AF_INET6` socket
//! that reaches an IPv4 peer reports it as the IPv4-mapped IPv6 address
//! `::ffff:a.b.c.d`. Every consumer compared that form with IPv4 entries
//! (blocklists, RFC 1918, loopback) and never matched, so any process
//! could reach a blocked IPv4 address, or an internal one, unseen. The
//! canonical form maps it back to the IPv4 address: one representation
//! for logs, rules and flows.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// `AF_INET` as the kernel records it.
pub const AF_INET: u8 = 2;
/// `AF_INET6` as the kernel records it.
pub const AF_INET6: u8 = 10;

/// The address a wire record names (`family`, 16 bytes), canonical: an
/// IPv4-mapped IPv6 address is the IPv4 address it maps. Only the mapped
/// form is folded: `to_ipv4()` would also turn `::1` into `0.0.0.1`.
pub fn canonical_ip(family: u8, bytes: &[u8; 16]) -> IpAddr {
    if family == AF_INET {
        IpAddr::V4(Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3]))
    } else {
        canonical(IpAddr::V6(Ipv6Addr::from(*bytes)))
    }
}

/// `addr` in canonical form (see [`canonical_ip`]).
pub fn canonical(addr: IpAddr) -> IpAddr {
    match addr {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(addr, IpAddr::V4),
        v4 => v4,
    }
}

/// `true` when `addr` is internal address space: RFC 1918 (`10/8`,
/// `172.16/12`, `192.168/16`), IPv6 unique-local (`fc00::/7`) or IPv6
/// link-local (`fe80::/10`). An IPv4-mapped address is judged as the IPv4
/// address it maps.
///
/// External audit NETR-007: the lateral-movement rules (NN-L-NET-007/018)
/// judged IPv6 as never internal, so SMB/RDP/WinRM/VNC to a ULA or
/// link-local peer drew nothing; the posture already had this notion
/// (BUG-039). One predicate now serves both. CGNAT (`100.64/10`) and IPv4
/// link-local (`169.254/16`) stay out on purpose (NET-011 keeps CGNAT off
/// the kill path).
pub fn is_internal(addr: IpAddr) -> bool {
    match canonical(addr) {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            o[0] == 10 || (o[0] == 172 && (16..=31).contains(&o[1])) || (o[0] == 192 && o[1] == 168)
        }
        IpAddr::V6(v6) => {
            let s0 = v6.segments()[0];
            (s0 & 0xfe00) == 0xfc00 // fc00::/7, unique-local
                || (s0 & 0xffc0) == 0xfe80 // fe80::/10, link-local
        }
    }
}

/// Lot 275 (NN-L-NET-028): `true` when `addr` is a destination outside the
/// host and its local networks — not loopback, unspecified, multicast or
/// broadcast, not [`is_internal`] (RFC 1918, unique-local, IPv6
/// link-local), not IPv4 link-local (`169.254/16`), CGNAT (`100.64/10`),
/// `0/8`, the reserved `240/4`, the benchmark `198.18/15`, nor IPv6
/// site-local (`fec0::/10`). The documentation ranges (`192.0.2/24`,
/// `198.51.100/24`, `203.0.113/24`, `2001:db8::/32`) count as public: no LAN
/// uses them, and the rule's benign lab test connects to one. An
/// IPv4-mapped address is judged as the IPv4 address it maps.
pub fn is_public(addr: IpAddr) -> bool {
    let addr = canonical(addr);
    if addr.is_loopback() || addr.is_unspecified() || addr.is_multicast() || is_internal(addr) {
        return false;
    }
    match addr {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            !(v4.is_broadcast()
                || o[0] == 0
                || (o[0] == 169 && o[1] == 254)
                || (o[0] == 100 && (o[1] & 0xc0) == 64)
                || o[0] >= 240
                || (o[0] == 198 && (o[1] & 0xfe) == 18))
        }
        IpAddr::V6(v6) => (v6.segments()[0] & 0xffc0) != 0xfec0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mapped_v6_is_the_v4_it_maps() {
        let mut b = [0u8; 16];
        b[10] = 0xff;
        b[11] = 0xff;
        b[12..].copy_from_slice(&[192, 0, 2, 1]);
        assert_eq!(
            canonical_ip(AF_INET6, &b),
            "192.0.2.1".parse::<IpAddr>().unwrap()
        );
        let mut v4 = [0u8; 16];
        v4[..4].copy_from_slice(&[10, 0, 0, 1]);
        assert_eq!(
            canonical_ip(AF_INET, &v4),
            "10.0.0.1".parse::<IpAddr>().unwrap()
        );
        // ::1 and a real v6 address stay v6
        let lo: IpAddr = "::1".parse().unwrap();
        assert_eq!(canonical(lo), lo);
        let v6: IpAddr = "2001:db8::1".parse().unwrap();
        assert_eq!(canonical(v6), v6);
    }

    /// Lot 275: the destinations NN-L-NET-028 judges.
    #[test]
    fn public_is_outside_the_host_and_its_networks() {
        let p = |s: &str| s.parse::<IpAddr>().unwrap();
        for a in [
            "8.8.8.8",
            "1.1.1.1",
            "203.0.113.5",
            "198.51.100.1",
            "192.0.2.1",
            "100.63.255.255",
            "100.128.0.1",
            "169.253.1.1",
            "198.17.0.1",
            "198.20.0.1",
            "223.255.255.254",
            "::ffff:8.8.8.8",
            "2001:db8::1",
            "2606:4700::1111",
            "fbff::1",
            "fe7f::1",
        ] {
            assert!(is_public(p(a)), "{a} is public");
        }
        for a in [
            "127.0.0.1",
            "127.0.0.53",
            "0.0.0.0",
            "0.1.2.3",
            "10.0.0.1",
            "172.16.0.1",
            "192.168.1.1",
            "100.64.0.1",
            "100.127.255.255",
            "169.254.169.254",
            "198.18.0.1",
            "198.19.255.255",
            "224.0.0.251",
            "239.255.255.250",
            "240.0.0.1",
            "255.255.255.255",
            "::",
            "::1",
            "::ffff:10.0.0.5",
            "::ffff:127.0.0.1",
            "fd00::1",
            "fe80::1",
            "fec0::1",
            "feff::1",
            "ff02::1",
        ] {
            assert!(!is_public(p(a)), "{a} is not public");
        }
    }

    #[test]
    fn internal_covers_rfc1918_ula_and_link_local() {
        let p = |s: &str| s.parse::<IpAddr>().unwrap();
        for a in [
            "10.0.0.5",
            "172.16.0.1",
            "172.31.255.255",
            "192.168.1.1",
            "::ffff:10.0.0.5",
            "fd00::2",
            "fc00::1",
            "fe80::1",
            "febf::1",
        ] {
            assert!(is_internal(p(a)), "{a} is internal");
        }
        for a in [
            "8.8.8.8",
            "172.32.0.1",
            "100.64.0.1",
            "169.254.1.1",
            "::ffff:8.8.8.8",
            "::1",
            "2001:db8::1",
            "fec0::1",
        ] {
            assert!(!is_internal(p(a)), "{a} is not internal");
        }
    }
}
