//! Lot 275 (C12/C07): NN-L-NET-028 — "no DNS, no connect", per lineage.
//!
//! Design: `research/ideas-2026-10-30/ideas-verdict.md`, item 1 (I2 merged
//! with idea 8). Legitimate software nearly always looks a name up before
//! it connects; an implant often does not (an address in its code: Unit 42
//! found a direct-to-IP connection in 45% of the C2 samples it measured).
//! A TCP connect or a UDP send to a **public** address that the DNS
//! evidence does not bind to the process or an ancestor is a detection.
//! Bound (`crate::net::resolved`, review of #495): an address of a DNS
//! response the process or an ancestor received itself (a datagram from
//! port 53, its question's chain only), or of a response a system resolver
//! received (its executable and a system uid) for a name the process or an
//! ancestor asked within [`crate::net::resolved::ASK_WINDOW_SECS`]. The
//! connect pump and the net drain compute what the DNS
//! evidence says of the destination (`nn_model::telemetry::DnsResolution`,
//! from `crate::net::resolved`), and this rule judges it.
//!
//! - Alert first: `Medium` when no process on the host resolved the address
//!   (`Unresolved`), `Low` when only another lineage did (`OtherLineage`: a
//!   shared CDN address, or an address handed over from another process).
//!   The kill of the process (`KillProcess`) is held behind the per-rule
//!   response policy ([`super::super::response_policy::NODNS_KILL`]), off by
//!   default; the policy refuses `enforce NN-L-NET-028` for now
//!   ([`crate::decision::rule_policy::ENFORCE_REFUSED`], review of #495: an
//!   answer can be missing for benign reasons the agent cannot see).
//! - Not judged: a destination that is not public
//!   ([`nn_model::netaddr::is_public`]: loopback, RFC 1918, ULA, link-local,
//!   CGNAT, multicast…), a configured resolver (`resolv.conf`'s
//!   `nameserver`s, systemd-resolved's upstream servers), an address of the
//!   signed allowlist `nodns-allow.local` ([`NoDnsAllowlist`]), a
//!   destination whose evidence is `Unknown` (the process predates the DNS
//!   response sensor, a name it asked was answered unseen or incompletely,
//!   DNS records were held back or lost, the DNS pumps had not caught up)
//!   or `Lineage`.
//! - Once per process and destination per [`DEDUP_SECS`]: a UDP flow's rows
//!   come once a second.
//! - The per-rule policy's exemptions (an executable with its digest, a
//!   uid, a unit) apply as to every rule; the comm allowlist does not (a
//!   process names itself).

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;

use nn_model::telemetry::{DnsResolution, FlowPhase, NetFlowEvent};
use nn_model::{Event, ResponseAction, Severity, Verdict};
use parking_lot::Mutex;

use crate::decision::attack::{AttackRef, Tactic};
use crate::decision::bounded::LazyLru;
use crate::decision::Rule;
use crate::net::resolvers::HostResolvers;

/// The rule's id.
pub const RULE_ID: &str = "NN-L-NET-028_ConnectWithoutDns";
/// A process and destination are recorded once per this window.
pub const DEDUP_SECS: u64 = 600;
/// Process and destination pairs remembered for the dedup.
const DEDUP_MAX: usize = 16_384;
/// Entries of the allowlist (a bound on the per-connect cost).
pub const MAX_ALLOW_ENTRIES: usize = 4096;
/// Where the agent reads the signed allowlist.
pub const DEFAULT_ALLOW_LOCAL: &str = "/etc/northnarrow/nodns-allow.local";

const IPPROTO_TCP: u8 = 6;
const IPPROTO_UDP: u8 = 17;
const SEC: u64 = 1_000_000_000;

/// The signed allowlist `nodns-allow.local`: one address or CIDR block a
/// line (`203.0.113.7`, `198.51.100.0/24`, `2001:db8::/48`), `#` comments.
/// Any bad line refuses the whole file — the gate signs only content that
/// parses, and the agent loads only a signed file.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NoDnsAllowlist {
    nets: Vec<(IpAddr, u8)>,
}

impl NoDnsAllowlist {
    pub fn empty() -> Self {
        Self::default()
    }

    /// Parse the file's text; `Err((line, why))` for the first bad line.
    pub fn parse(text: &str) -> Result<Self, (usize, String)> {
        let mut nets = Vec::new();
        for (i, raw) in text.lines().enumerate() {
            let line = raw.split_once('#').map_or(raw, |(c, _)| c).trim();
            if line.is_empty() {
                continue;
            }
            let err = |why: String| (i + 1, why);
            if nets.len() == MAX_ALLOW_ENTRIES {
                return Err(err(format!("more than {MAX_ALLOW_ENTRIES} entries")));
            }
            let (addr, len) = match line.split_once('/') {
                Some((a, l)) => (a, Some(l)),
                None => (line, None),
            };
            let addr: IpAddr = addr
                .parse()
                .map_err(|_| err(format!("{line}: not an address or CIDR block")))?;
            let addr = nn_model::netaddr::canonical(addr);
            let max = if addr.is_ipv4() { 32 } else { 128 };
            let len: u8 = match len {
                None => max,
                Some(l) => l
                    .parse::<u8>()
                    .ok()
                    .filter(|l| *l <= max)
                    .ok_or_else(|| err(format!("{line}: a prefix length of 0 to {max}")))?,
            };
            // a block that covers half the address space or more is the rule
            // turned off: say `off NN-L-NET-028` in the rule policy instead
            if len < 8 {
                return Err(err(format!(
                    "{line}: a block of /{len} exempts most of the Internet — turn the rule off \
                     in the per-rule policy instead"
                )));
            }
            nets.push((mask(addr, len), len));
        }
        Ok(Self { nets })
    }

    pub fn len(&self) -> usize {
        self.nets.len()
    }

    pub fn is_empty(&self) -> bool {
        self.nets.is_empty()
    }

    /// `addr` is in one of the blocks.
    pub fn contains(&self, addr: &IpAddr) -> bool {
        let addr = nn_model::netaddr::canonical(*addr);
        self.nets
            .iter()
            .any(|(net, len)| net.is_ipv4() == addr.is_ipv4() && mask(addr, *len) == *net)
    }
}

/// `addr` with its bits past `len` cleared.
fn mask(addr: IpAddr, len: u8) -> IpAddr {
    match addr {
        IpAddr::V4(v4) => {
            let bits = u32::from(v4);
            let m = if len == 0 {
                0
            } else {
                u32::MAX << (32 - u32::from(len))
            };
            IpAddr::V4((bits & m).into())
        }
        IpAddr::V6(v6) => {
            let bits = u128::from(v6);
            let m = if len == 0 {
                0
            } else {
                u128::MAX << (128 - u32::from(len))
            };
            IpAddr::V6((bits & m).into())
        }
    }
}

/// NN-L-NET-028.
pub struct NnLNet028ConnectWithoutDns {
    resolvers: Arc<HostResolvers>,
    allow: Arc<NoDnsAllowlist>,
    seen: Mutex<Seen>,
}

#[derive(Default)]
struct Seen {
    last: HashMap<(u32, u64, IpAddr), u64>,
    order: LazyLru<(u32, u64, IpAddr)>,
}

impl NnLNet028ConnectWithoutDns {
    pub fn new(resolvers: Arc<HostResolvers>, allow: Arc<NoDnsAllowlist>) -> Self {
        Self {
            resolvers,
            allow,
            seen: Mutex::new(Seen::default()),
        }
    }

    /// The flow's row this rule judges: a TCP flow's connect-time row, a
    /// UDP row (one a second per destination).
    fn judged_row(nf: &NetFlowEvent) -> bool {
        match nf.proto {
            IPPROTO_TCP => nf.phase == FlowPhase::Connect,
            IPPROTO_UDP => nf.phase == FlowPhase::Closed,
            _ => false,
        }
    }

    /// First time in the window for this process and destination.
    fn first_in_window(&self, nf: &NetFlowEvent) -> bool {
        let key = (nf.pid, nf.proc_start_ns, nf.dst_addr);
        let now = nf.start_ns;
        let mut s = self.seen.lock();
        if let Some(t) = s.last.get(&key) {
            if now >= *t && now - *t < DEDUP_SECS * SEC {
                return false;
            }
        }
        s.last.insert(key, now);
        s.order.touch(key);
        while s.order.len() > DEDUP_MAX {
            if let Some(k) = s.order.pop_oldest() {
                s.last.remove(&k);
            }
        }
        true
    }
}

impl Rule for NnLNet028ConnectWithoutDns {
    fn id(&self) -> &'static str {
        RULE_ID
    }
    fn name(&self) -> &'static str {
        "Connect to a public address the process's lineage did not resolve"
    }
    fn category(&self) -> &'static str {
        super::net::CATEGORY_MEDIUM
    }
    fn attack(&self) -> &'static [AttackRef] {
        const ATTACK: &[AttackRef] = &[
            AttackRef::new(Tactic::CommandAndControl, "T1071"),
            AttackRef::new(Tactic::CommandAndControl, "T1105"),
        ];
        ATTACK
    }
    fn evaluate(&self, event: &Event) -> Option<Verdict> {
        let Event::NetFlow(nf) = event else {
            return None;
        };
        if !Self::judged_row(nf) || !nf.dns_resolution.not_resolved_by_lineage() {
            return None;
        }
        let dst = nf.dst_addr;
        if !nn_model::netaddr::is_public(dst)
            || self.resolvers.contains(&dst)
            || self.allow.contains(&dst)
        {
            return None;
        }
        if !self.first_in_window(nf) {
            return None;
        }
        let proto = if nf.proto == IPPROTO_TCP {
            "TCP"
        } else {
            "UDP"
        };
        let (severity, why) = match nf.dns_resolution {
            DnsResolution::OtherLineage => (
                Severity::Low,
                "only a system resolver's response for another lineage named it, not one for \
                 this process nor an ancestor",
            ),
            _ => (
                Severity::Medium,
                "no DNS response the process or an ancestor received, nor a system resolver's \
                 for a name they asked, named it",
            ),
        };
        let image = nf.exe.as_deref().unwrap_or(nf.comm.as_str());
        let v = Verdict {
            rule_id: RULE_ID.to_string(),
            rule_name: self.name().to_string(),
            category: self.category().to_string(),
            action: ResponseAction::KillProcess,
            severity,
            reasoning: format!(
                "{image} (pid {}, uid {}) sent a {proto} connection to {dst} port {} with no DNS \
                 lookup behind it: {why} (a direct-to-IP connect, the way an address in an \
                 implant's code reaches its C2)",
                nf.pid, nf.uid, nf.dst_port
            ),
            event_pid: nf.pid,
            event_filename: nf.comm.clone(),
            timestamp_ns: nf.start_ns,
        };
        Some(crate::decision::response_policy::NODNS_KILL.hold(v))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    fn flow(dst: IpAddr, proto: u8, phase: FlowPhase, res: DnsResolution) -> Event {
        Event::NetFlow(NetFlowEvent {
            start_ns: 100 * SEC,
            end_ns: 0,
            family: if dst.is_ipv4() { 2 } else { 10 },
            src_addr: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            src_port: 0,
            dst_addr: dst,
            dst_port: 443,
            proto,
            pid: 4242,
            uid: 1000,
            comm: "implant".into(),
            exe: Some("/tmp/implant".into()),
            proc_start_ns: 50 * SEC,
            bytes_sent: 0,
            bytes_recv: 0,
            resolved_hostname: None,
            tls_fingerprint: None,
            flow_id: String::new(),
            close_reason: 0,
            phase,
            observed_ns: 100 * SEC,
            dns_resolution: res,
        })
    }

    fn rule() -> NnLNet028ConnectWithoutDns {
        NnLNet028ConnectWithoutDns::new(HostResolvers::none(), Arc::new(NoDnsAllowlist::empty()))
    }

    const C2: IpAddr = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 5));

    /// A literal-IP connect nobody resolved: Medium, its kill held.
    #[test]
    fn a_connect_to_an_unresolved_public_address_is_recorded_its_kill_held() {
        let v = rule()
            .evaluate(&flow(C2, 6, FlowPhase::Connect, DnsResolution::Unresolved))
            .expect("fires");
        assert_eq!(v.severity, Severity::Medium);
        assert_eq!(v.action, ResponseAction::Log, "held by default");
        assert!(v.reasoning.contains("/tmp/implant") && v.reasoning.contains("203.0.113.5"));
        assert!(v.reasoning.contains("held back"), "{}", v.reasoning);
        assert_eq!(v.event_pid, 4242);
        // the switch on (the per-rule policy's `enforce`): the kill
        let held = crate::decision::response_policy::take_held().expect("held");
        assert_eq!(held.action, ResponseAction::KillProcess);
    }

    /// Resolved by another lineage only: Low.
    #[test]
    fn another_lineage_s_resolution_is_low() {
        let v = rule()
            .evaluate(&flow(
                C2,
                6,
                FlowPhase::Connect,
                DnsResolution::OtherLineage,
            ))
            .unwrap();
        assert_eq!(v.severity, Severity::Low);
        assert!(
            v.reasoning.contains("for another lineage"),
            "{}",
            v.reasoning
        );
    }

    /// The lineage's own resolution, an unknown one, an unjudged row: no.
    #[test]
    fn resolved_unknown_or_unjudged_is_no_match() {
        for res in [
            DnsResolution::Lineage,
            DnsResolution::Unknown,
            DnsResolution::NotJudged,
        ] {
            assert!(rule()
                .evaluate(&flow(C2, 6, FlowPhase::Connect, res))
                .is_none());
        }
    }

    /// UDP rows and IPv6 are judged; the TCP close, snapshots and refused
    /// connects are not (the connect row was).
    #[test]
    fn udp_and_ipv6_are_judged_the_other_phases_are_not() {
        let v6 = IpAddr::V6("2001:db8::5".parse::<Ipv6Addr>().unwrap());
        assert!(rule()
            .evaluate(&flow(C2, 17, FlowPhase::Closed, DnsResolution::Unresolved))
            .is_some());
        assert!(rule()
            .evaluate(&flow(v6, 6, FlowPhase::Connect, DnsResolution::Unresolved))
            .is_some());
        for (proto, phase) in [
            (6, FlowPhase::Closed),
            (6, FlowPhase::Snapshot),
            (6, FlowPhase::Denied),
            (17, FlowPhase::Connect),
            (1, FlowPhase::Connect),
        ] {
            assert!(
                rule()
                    .evaluate(&flow(C2, proto, phase, DnsResolution::Unresolved))
                    .is_none(),
                "{proto} {phase:?}"
            );
        }
    }

    /// LAN and the other non-public ranges, a configured resolver and the
    /// signed allowlist are exempt.
    #[test]
    fn lan_resolvers_and_the_allowlist_are_exempt() {
        for a in [
            "10.1.2.3",
            "192.168.0.10",
            "127.0.0.1",
            "fd00::1",
            "100.64.1.1",
            "169.254.169.254",
        ] {
            let addr: IpAddr = a.parse().unwrap();
            assert!(
                rule()
                    .evaluate(&flow(
                        addr,
                        6,
                        FlowPhase::Connect,
                        DnsResolution::Unresolved
                    ))
                    .is_none(),
                "{a}"
            );
        }
        let resolver = IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9));
        let r = NnLNet028ConnectWithoutDns::new(
            HostResolvers::fixed([resolver]),
            Arc::new(NoDnsAllowlist::parse("198.51.100.0/24\n2001:db8:1::/48 # mirror\n").unwrap()),
        );
        assert!(r
            .evaluate(&flow(
                resolver,
                6,
                FlowPhase::Connect,
                DnsResolution::Unresolved
            ))
            .is_none());
        for a in ["198.51.100.77", "2001:db8:1::9"] {
            assert!(
                r.evaluate(&flow(
                    a.parse().unwrap(),
                    6,
                    FlowPhase::Connect,
                    DnsResolution::Unresolved
                ))
                .is_none(),
                "{a}"
            );
        }
        // outside the blocks: judged
        assert!(r
            .evaluate(&flow(C2, 6, FlowPhase::Connect, DnsResolution::Unresolved))
            .is_some());
    }

    /// Once per process and destination per window.
    #[test]
    fn once_per_process_and_destination_per_window() {
        let r = rule();
        let mk = |t: u64, dst: IpAddr, pid: u32| {
            let mut e = flow(dst, 17, FlowPhase::Closed, DnsResolution::Unresolved);
            if let Event::NetFlow(nf) = &mut e {
                nf.start_ns = t;
                nf.pid = pid;
            }
            e
        };
        assert!(r.evaluate(&mk(100 * SEC, C2, 1)).is_some());
        assert!(r.evaluate(&mk(101 * SEC, C2, 1)).is_none());
        assert!(
            r.evaluate(&mk(101 * SEC, C2, 2)).is_some(),
            "another process"
        );
        let other = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 6));
        assert!(
            r.evaluate(&mk(101 * SEC, other, 1)).is_some(),
            "another destination"
        );
        assert!(r
            .evaluate(&mk((100 + DEDUP_SECS - 1) * SEC, C2, 1))
            .is_none());
        assert!(r.evaluate(&mk((100 + DEDUP_SECS) * SEC, C2, 1)).is_some());
    }

    #[test]
    fn the_allowlist_parses_strictly() {
        let l = NoDnsAllowlist::parse(
            "# mirrors\n203.0.113.7\n198.51.100.0/24\n::ffff:192.0.2.1\n\n2001:db8::/32\n",
        )
        .unwrap();
        assert_eq!(l.len(), 4);
        assert!(l.contains(&"203.0.113.7".parse().unwrap()));
        assert!(!l.contains(&"203.0.113.8".parse().unwrap()));
        assert!(
            l.contains(&"192.0.2.1".parse().unwrap()),
            "mapped form folded"
        );
        assert!(l.contains(&"::ffff:198.51.100.200".parse().unwrap()));
        assert!(l.contains(&"2001:db8:ffff::1".parse().unwrap()));
        assert!(!l.contains(&"2001:db9::1".parse().unwrap()));
        for (bad, line) in [
            ("203.0.113.7\nnot-an-ip\n", 2),
            ("10.0.0.0/33\n", 1),
            ("10.0.0.0/x\n", 1),
            ("0.0.0.0/0\n", 1),
            ("::/0\n", 1),
            ("1.0.0.0/7\n", 1),
            ("example.com\n", 1),
        ] {
            assert_eq!(NoDnsAllowlist::parse(bad).unwrap_err().0, line, "{bad}");
        }
        assert!(NoDnsAllowlist::parse("1.0.0.0/8\n").is_ok());
        let many: String = (0..=MAX_ALLOW_ENTRIES)
            .map(|i| format!("198.51.{}.{}\n", i / 256, i % 256))
            .collect();
        assert!(NoDnsAllowlist::parse(&many).is_err());
        assert!(NoDnsAllowlist::empty().is_empty());
    }

    #[test]
    fn mask_clears_the_host_bits() {
        assert_eq!(
            mask("203.0.113.77".parse().unwrap(), 24),
            "203.0.113.0".parse::<IpAddr>().unwrap()
        );
        assert_eq!(
            mask("203.0.113.77".parse().unwrap(), 32),
            "203.0.113.77".parse::<IpAddr>().unwrap()
        );
        assert_eq!(
            mask("203.0.113.77".parse().unwrap(), 0),
            "0.0.0.0".parse::<IpAddr>().unwrap()
        );
        assert_eq!(
            mask("2001:db8::1".parse().unwrap(), 32),
            "2001:db8::".parse::<IpAddr>().unwrap()
        );
        assert_eq!(
            mask("2001:db8::1".parse().unwrap(), 0),
            "::".parse::<IpAddr>().unwrap()
        );
    }
}
