//! Network canaries (NN-L-CANARY-003): a decoy address and TCP port that
//! no legitimate process connects to. Lab PR 163.
//!
//! ## As built
//!
//! Design §5.3 has the agent listen on the canary's port and trip on
//! `accept()`. No sensor observes an accept: the `tcp_close` fexit drops
//! passive sockets (review 79), and an accepted connection names no local
//! process for the KillProcessTree response, which a remote peer does not
//! have. The canary is the destination instead: the connect kprobe
//! (`tcp_v4_connect` / `tcp_v6_connect`, `Event::TcpConnect`) reports a
//! local process connecting to the canary's address and port, and that
//! process is the accessor — as the opener of a File canary and the
//! executor of a Process canary are. The agent opens no listener (no new
//! socket reachable from the network, no listener the NET rules would
//! judge); the connect is reported at its start, whether or not anything
//! answers, before any byte is sent.
//!
//! What it does not cover: a connection from another host (no accept
//! sensor), a UDP datagram to the port, and the lure of a port that
//! `ss -tlnp` shows. The operator places the destination where an intruder
//! finds it (a configuration file, a hosts entry, an ssh config).
//!
//! - `--bind-addr` one address: a connect to that address and port. It may
//!   be an address of this host (a loopback or dummy-interface address) or
//!   one no host uses.
//! - `--bind-addr 0.0.0.0` / `::`: a connect to the port at any address of
//!   this host (loopback, `0.0.0.0`/`::`, the interfaces' addresses), IPv4
//!   only for `0.0.0.0`, both families for `::` (a `[::]` listener is
//!   dual-stack by default). A connect to the port on another host is not
//!   a trip.
//!
//! A deploy is refused when a TCP listener on this host would receive the
//! canary's connections: every client of that service would trip it.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::{Duration, Instant};

use nn_model::netaddr::canonical;
use parking_lot::Mutex;

// R08b (lab PR 251): the canary's address, what a connect reaches and one
// port's canaries are nn-core's (`nn_core::canary::network`), with the
// detector that reads them; this module keeps what reads the host — its
// interface addresses, its TCP listeners — and the deploy check.
use nn_core::canary::network::as_connected;
pub use nn_core::canary::network::{connect_destination, CanaryAddr};

/// How long the interface addresses read for a wildcard canary are reused.
const LOCAL_ADDRS_TTL: Duration = Duration::from_secs(1);

/// The host's interface addresses, for the wildcard canaries; read at
/// most once per [`LOCAL_ADDRS_TTL`], and only when a connect reaches a
/// wildcard canary's port at an address that is not a loopback one.
#[derive(Default)]
pub struct LocalAddrs {
    cache: Mutex<Option<(Instant, Vec<IpAddr>)>>,
}

impl LocalAddrs {
    pub fn contains(&self, addr: IpAddr) -> bool {
        let addr = as_connected(canonical(addr));
        if addr.is_loopback() {
            return true;
        }
        let mut cache = self.cache.lock();
        let fresh = cache
            .as_ref()
            .is_some_and(|(at, _)| at.elapsed() < LOCAL_ADDRS_TTL);
        if !fresh {
            *cache = Some((Instant::now(), interface_addrs()));
        }
        cache.as_ref().is_some_and(|(_, v)| v.contains(&addr))
    }
}

/// Every address assigned to an interface of this host (`getifaddrs`),
/// canonical. Empty when the call fails.
pub fn interface_addrs() -> Vec<IpAddr> {
    let mut out = Vec::new();
    let mut head: *mut libc::ifaddrs = std::ptr::null_mut();
    // SAFETY: `head` is a valid out-pointer; the list is freed below.
    if unsafe { libc::getifaddrs(&mut head) } != 0 {
        return out;
    }
    let mut cur = head;
    while !cur.is_null() {
        // SAFETY: `cur` is a node of the list getifaddrs returned, alive
        // until freeifaddrs.
        let ifa = unsafe { &*cur };
        if !ifa.ifa_addr.is_null() {
            // SAFETY: a non-null `ifa_addr` points to a sockaddr whose
            // family says which sockaddr it is.
            match i32::from(unsafe { (*ifa.ifa_addr).sa_family }) {
                libc::AF_INET => {
                    // SAFETY: AF_INET: the sockaddr is a sockaddr_in.
                    let sin = unsafe { &*(ifa.ifa_addr as *const libc::sockaddr_in) };
                    out.push(IpAddr::V4(Ipv4Addr::from(u32::from_be(
                        sin.sin_addr.s_addr,
                    ))));
                }
                libc::AF_INET6 => {
                    // SAFETY: AF_INET6: the sockaddr is a sockaddr_in6.
                    let sin6 = unsafe { &*(ifa.ifa_addr as *const libc::sockaddr_in6) };
                    out.push(canonical(IpAddr::V6(Ipv6Addr::from(
                        sin6.sin6_addr.s6_addr,
                    ))));
                }
                _ => {}
            }
        }
        cur = ifa.ifa_next;
    }
    // SAFETY: `head` came from a successful getifaddrs and is freed once.
    unsafe { libc::freeifaddrs(head) };
    out
}

/// The TCP listeners of a `/proc/net/tcp` (`v6 = false`) or
/// `/proc/net/tcp6` table: `(address, port)` of each socket in state
/// LISTEN (`0A`). The kernel prints each 32-bit word of the address as a
/// native-endian integer.
pub fn parse_listeners(table: &str, v6: bool) -> Vec<(IpAddr, u16)> {
    table
        .lines()
        .skip(1)
        .filter_map(|line| {
            let mut fields = line.split_whitespace();
            let local = fields.nth(1)?;
            if fields.nth(1)? != "0A" {
                return None;
            }
            let (addr, port) = local.split_once(':')?;
            Some((
                decode_proc_addr(addr, v6)?,
                u16::from_str_radix(port, 16).ok()?,
            ))
        })
        .collect()
}

fn decode_proc_addr(hex: &str, v6: bool) -> Option<IpAddr> {
    let words = if v6 { 4 } else { 1 };
    if hex.len() != words * 8 {
        return None;
    }
    let mut bytes = [0u8; 16];
    for i in 0..words {
        let w = u32::from_str_radix(hex.get(i * 8..i * 8 + 8)?, 16).ok()?;
        bytes[i * 4..i * 4 + 4].copy_from_slice(&w.to_ne_bytes());
    }
    Some(if v6 {
        canonical(IpAddr::V6(Ipv6Addr::from(bytes)))
    } else {
        IpAddr::V4(Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3]))
    })
}

/// The TCP listeners of this host's network namespace. A missing
/// `/proc/net/tcp6` (IPv6 disabled) holds none.
pub fn listeners() -> std::io::Result<Vec<(IpAddr, u16)>> {
    let mut out = parse_listeners(&std::fs::read_to_string("/proc/net/tcp")?, false);
    match std::fs::read_to_string("/proc/net/tcp6") {
        Ok(t) => out.extend(parse_listeners(&t, true)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }
    Ok(out)
}

/// Whether a listener at `listener` takes connections the canary covers.
fn takes_connections_of(
    canary: CanaryAddr,
    listener: IpAddr,
    is_local: &dyn Fn(IpAddr) -> bool,
) -> bool {
    let l = canonical(listener);
    match canary {
        CanaryAddr::Any => true,
        // an IPv4 listener, or a dual-stack `[::]` one
        CanaryAddr::AnyV4 => l.is_ipv4() || l.is_unspecified(),
        CanaryAddr::Exact(a) => {
            l == a
                || (l.is_unspecified()
                    && (l.is_ipv6() || a.is_ipv4())
                    && (a.is_loopback() || is_local(a)))
        }
    }
}

/// The deploy check of a network canary, against the listeners given:
/// the address parses, the port can be connected to, and no listener on
/// this host would take the canary's connections.
pub fn check_deployable_against(
    bind_addr: &str,
    port: u16,
    listeners: &[(IpAddr, u16)],
    is_local: &dyn Fn(IpAddr) -> bool,
) -> Result<CanaryAddr, String> {
    let addr = CanaryAddr::parse(bind_addr)
        .ok_or_else(|| format!("`{bind_addr}` is not an IP address"))?;
    if port == 0 {
        return Err("port 0 cannot be connected to".to_string());
    }
    if let Some((l, _)) = listeners
        .iter()
        .find(|(l, p)| *p == port && takes_connections_of(addr, *l, is_local))
    {
        return Err(format!(
            "a TCP listener on {l} port {port} takes the canary's connections: each of its \
             clients would trip the canary (a network canary is a destination nothing uses)"
        ));
    }
    Ok(addr)
}

/// [`check_deployable_against`] this host's listeners and addresses.
pub fn check_deployable(bind_addr: &str, port: u16) -> Result<CanaryAddr, String> {
    let listeners = listeners().map_err(|e| format!("cannot read the TCP listeners: {e}"))?;
    let local = LocalAddrs::default();
    check_deployable_against(bind_addr, port, &listeners, &|a| local.contains(a))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[cfg(target_endian = "little")]
    #[test]
    fn proc_net_tcp_listeners_parse() {
        let tcp = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n\
   0: 0100007F:0CEA 00000000:0000 0A 00000000:00000000 00:00000000 00000000   999        0 23118 1 0 100 0 0 10 0\n\
   1: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1840 1 0 100 0 0 10 0\n\
   2: 0F02000A:0016 0100000A:D2F4 01 00000000:00000000 02:0009B79C 00000000     0        0 4410 4 0 20 4 29 10 -1\n";
        assert_eq!(
            parse_listeners(tcp, false),
            vec![(ip("127.0.0.1"), 3306), (ip("0.0.0.0"), 22)],
            "the established row (st 01) is not a listener"
        );
        let tcp6 = "  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n\
   0: 00000000000000000000000000000000:0016 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1842 1 0 100 0 0 10 0\n\
   1: 00000000000000000000000001000000:1F90 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 9001 1 0 100 0 0 10 0\n";
        assert_eq!(
            parse_listeners(tcp6, true),
            vec![(ip("::"), 22), (ip("::1"), 8080)]
        );
    }

    #[test]
    fn this_hosts_listeners_include_one_just_bound() {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        let found = listeners().unwrap();
        assert!(
            found.contains(&(ip("127.0.0.1"), port)),
            "127.0.0.1:{port} not in {found:?}"
        );
    }

    #[test]
    fn a_deploy_where_a_listener_takes_the_connections_is_refused() {
        let local = |a: IpAddr| a == ip("100.64.0.9");
        let listeners = [
            (ip("0.0.0.0"), 22),
            (ip("127.0.0.1"), 3306),
            (ip("::"), 8080),
            (ip("::1"), 9000),
        ];
        let check = |addr: &str, port| check_deployable_against(addr, port, &listeners, &local);
        // refused: the listener takes them
        for (addr, port) in [
            ("100.64.0.9", 22),
            ("127.0.0.1", 22),
            ("127.0.0.1", 3306),
            ("0.0.0.0", 3306),
            ("100.64.0.9", 8080),
            ("0.0.0.0", 8080),
            ("::", 9000),
            ("::1", 9000),
        ] {
            assert!(check(addr, port).is_err(), "{addr}:{port}");
        }
        // accepted: nothing here takes them
        for (addr, port) in [
            ("100.64.0.9", 4444),
            ("192.0.2.7", 22),    // not this host: the wildcard sshd never sees it
            ("100.64.0.9", 3306), // 3306 listens on 127.0.0.1 only
            ("0.0.0.0", 9000),    // ::1 takes no IPv4 connection
            ("::", 4444),
        ] {
            assert!(check(addr, port).is_ok(), "{addr}:{port}");
        }
        assert!(check("db.internal", 4444)
            .unwrap_err()
            .contains("not an IP"));
        assert!(check("100.64.0.9", 0).unwrap_err().contains("port 0"));
    }

    #[test]
    fn local_addrs_hold_loopback_and_an_interface_address() {
        let local = LocalAddrs::default();
        assert!(local.contains(ip("127.0.0.1")));
        assert!(local.contains(ip("::1")));
        assert!(local.contains(ip("0.0.0.0")));
        assert!(!local.contains(ip("192.0.2.7")), "TEST-NET-1 is nobody's");
        if let Some(a) = interface_addrs().into_iter().find(|a| !a.is_loopback()) {
            assert!(local.contains(a), "{a}");
        }
    }
}
