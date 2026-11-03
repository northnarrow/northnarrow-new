//! Lot 275 (C07 1→2, C12): which process resolved which address — the
//! state of NN-L-NET-028 ("no DNS, no connect").
//!
//! Merged design of `research/ideas-2026-10-30/ideas-verdict.md`, item 1:
//! the binding is per lineage, the host-wide table its complement.
//!
//! - **Names** (host-wide): every DNS response the response sensor reads
//!   gives its question's name, its CNAME chain and its addresses, each
//!   held for its TTL, at least [`NAME_FLOOR_SECS`] (the 300 s Palo Alto
//!   uses for its "direct to IP" detection) and at most [`NAME_CAP_SECS`].
//!   A response with no address (NXDOMAIN, an empty answer) is remembered
//!   as answered.
//! - **Bindings** (per process): `(pid, address)` — the process received a
//!   response naming the address ([`ResolvedTable::on_answer`]: the stub
//!   resolver's answer reaches the application), or asked for a name whose
//!   response named it ([`ResolvedTable::on_query`] and the askers of
//!   [`ResolvedTable::on_answer`]: a query through systemd-resolved's NSS
//!   module, whose upstream answer the resolver receives). A binding lasts
//!   for the name's TTL (the floor at least) and then for
//!   [`BIND_IDLE_SECS`] past each use, so a daemon that resolved its peers
//!   once (an NTP client, a database client) keeps them while it uses them.
//! - **The "IP in the name" heuristic**: an address that its own name spells
//!   (`1-2-3-4.nip.io`, `1.2.3.4.sslip.io`, `01020304.…`) binds nothing — a
//!   name that only encodes an address is a connect to that address.
//!
//! [`ResolvedTable::check`] answers for a connect: a binding of the process
//! or of an ancestor ([`DnsResolution::Lineage`]); else a name the lineage
//! asked for recently whose response was never seen, or DNS records of the
//! lineage held back by the kernel's budgets ([`DnsResolution::Unknown`]);
//! else an address another process resolved ([`DnsResolution::OtherLineage`]);
//! else [`DnsResolution::Unresolved`]. A binding counts for a process only
//! when it was made after the process started (a pid outlives its process,
//! external audit NET-016).
//!
//! Every map is bounded ([`MAX_NAMES`], [`MAX_ADDRS`], [`MAX_BINDINGS`],
//! [`MAX_ASKS`]); past a bound the oldest goes, counted
//! ([`Counters::evicted`]).

use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;

use nn_model::telemetry::DnsResolution;
use parking_lot::Mutex;

use crate::decision::bounded::LazyLru;

const SEC: u64 = 1_000_000_000;
/// The least a name's addresses are held after its response.
pub const NAME_FLOOR_SECS: u64 = 300;
/// The most (a day: a longer TTL is held this long).
pub const NAME_CAP_SECS: u64 = 86_400;
/// A binding lasts this long past each use.
pub const BIND_IDLE_SECS: u64 = 7_200;
/// A response binds the processes that asked for its name this recently.
pub const ASK_WINDOW_SECS: u64 = 10;
/// A name asked for this recently and never answered (as seen) makes the
/// lineage's judgement unknown; so do records of it the budgets held.
pub const UNSEEN_WINDOW_SECS: u64 = NAME_FLOOR_SECS;
/// CNAME hops followed from a name to its addresses.
pub const MAX_CHAIN: usize = 8;

pub const MAX_NAMES: usize = 32_768;
pub const MAX_ADDRS: usize = 65_536;
pub const MAX_BINDINGS: usize = 131_072;
pub const MAX_ASKS: usize = 16_384;
/// Recent names kept per process for the unseen-response test.
const ASKS_PER_PID: usize = 64;
const MAX_ASKING_PIDS: usize = 4096;
const MAX_HELD_PIDS: usize = 4096;

/// One A, AAAA or CNAME record of a response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Record {
    Addr {
        name: String,
        ttl: u32,
        addr: IpAddr,
    },
    Cname {
        name: String,
        ttl: u32,
        target: String,
    },
}

/// A decoded response ([`ResolvedTable::on_answer`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Answer<'a> {
    /// The receiving process.
    pub pid: u32,
    /// The receive (`CLOCK_MONOTONIC` ns).
    pub ts_ns: u64,
    pub qname: &'a str,
    pub records: &'a [Record],
}

/// What the table did, for `nn-admin` and the tests.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Counters {
    pub answers: u64,
    pub bindings: u64,
    /// Addresses a name spelled, not bound ("IP in the name").
    pub ip_in_name: u64,
    pub evicted: u64,
    pub checks: u64,
}

#[derive(Debug, Default)]
struct NameEntry {
    /// Address → when it stops counting.
    addrs: HashMap<IpAddr, u64>,
    /// CNAME target → when it stops counting.
    cnames: HashMap<String, u64>,
    /// When the name stops counting as answered.
    answered_until: u64,
}

#[derive(Debug, Clone, Copy)]
struct Binding {
    made_ns: u64,
    until_ns: u64,
}

#[derive(Default)]
struct Inner {
    names: HashMap<String, NameEntry>,
    /// Address → when no name holds it any more (host-wide).
    addrs: HashMap<IpAddr, u64>,
    addr_order: LazyLru<IpAddr>,
    bindings: HashMap<(u32, IpAddr), Binding>,
    binding_order: LazyLru<(u32, IpAddr)>,
    /// `(name, pid, ts)`, oldest first: the askers a response binds.
    askers: VecDeque<(String, u32, u64)>,
    /// pid → its recent names `(name, ts)`, for the unseen-response test.
    asks: HashMap<u32, VecDeque<(String, u64)>>,
    asking_order: LazyLru<u32>,
    /// pid → the last time the kernel held one of its DNS records back.
    held: HashMap<u32, u64>,
    held_order: LazyLru<u32>,
    /// A DNS record the pumps could not decode (the parse worker down)
    /// until then: the evidence is incomplete for every process.
    degraded_until: u64,
    counters: Counters,
}

impl std::fmt::Debug for Inner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Inner")
            .field("names", &self.names.len())
            .field("addrs", &self.addrs.len())
            .field("bindings", &self.bindings.len())
            .field("askers", &self.askers.len())
            .field("counters", &self.counters)
            .finish()
    }
}

/// The table; `I` is what the agent's DNS response pump keeps with it for
/// the connects to wait on (the agent's `DnsIngest`), held and handed out
/// as [`super::dns_cache::DnsCache`] does.
#[derive(Debug)]
pub struct ResolvedTable<I> {
    inner: Mutex<Inner>,
    /// When the DNS response sensor started (`CLOCK_MONOTONIC` ns); 0 while
    /// it does not run.
    sensor_since_ns: std::sync::atomic::AtomicU64,
    ingest: I,
}

impl<I: Default> Default for ResolvedTable<I> {
    fn default() -> Self {
        Self {
            inner: Mutex::new(Inner::default()),
            sensor_since_ns: std::sync::atomic::AtomicU64::new(0),
            ingest: I::default(),
        }
    }
}

/// `name` as the tables key it: ASCII lower case, no trailing dot.
fn key(name: &str) -> String {
    name.strip_suffix('.').unwrap_or(name).to_ascii_lowercase()
}

/// The TTL a name's records are held for, in ns.
fn hold_ns(ttl: u32) -> u64 {
    u64::from(ttl).clamp(NAME_FLOOR_SECS, NAME_CAP_SECS) * SEC
}

/// The address is spelled by `name` ("IP in the name": nip.io, sslip.io and
/// the like): its dotted or dashed form as labels of the name, or its
/// 8-digit hexadecimal form as a label; an IPv6 address's dashed form.
pub fn name_spells(name: &str, addr: IpAddr) -> bool {
    let name = key(name);
    let labels: Vec<&str> = name.split('.').collect();
    match addr {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            let parts: Vec<String> = o.iter().map(u8::to_string).collect();
            let hex = format!("{:02x}{:02x}{:02x}{:02x}", o[0], o[1], o[2], o[3]);
            // `1-2-3-4`, `app-1-2-3-4` (a label ending in the dashed form)
            let dashed = labels.iter().any(|l| {
                let p: Vec<&str> = l.split('-').collect();
                p.len() >= 4 && p[p.len() - 4..] == parts[..]
            });
            dashed || labels.contains(&hex.as_str()) || labels.windows(4).any(|w| w == parts)
        }
        IpAddr::V6(v6) => {
            let dashed = v6.to_string().replace(':', "-");
            labels.iter().any(|l| l.ends_with(&dashed))
        }
    }
}

impl<I: Default> ResolvedTable<I> {
    pub fn new() -> Self {
        Self::default()
    }

    /// How far the DNS response pump has fed the table (the agent's).
    pub fn ingest(&self) -> &I {
        &self.ingest
    }

    /// The DNS response sensor started at `now_ns` (`0`: it stopped).
    pub fn set_sensor_since(&self, now_ns: u64) {
        self.sensor_since_ns
            .store(now_ns, std::sync::atomic::Ordering::Release);
    }

    /// When the DNS response sensor started; `None` while it does not run.
    pub fn sensor_since(&self) -> Option<u64> {
        match self
            .sensor_since_ns
            .load(std::sync::atomic::Ordering::Acquire)
        {
            0 => None,
            t => Some(t),
        }
    }

    pub fn counters(&self) -> Counters {
        self.inner.lock().counters
    }

    /// A response `a.pid` received: its names and addresses held
    /// host-wide, its addresses bound to the receiver and to the processes
    /// that asked for one of its names in the last [`ASK_WINDOW_SECS`].
    pub fn on_answer(&self, a: &Answer<'_>) {
        let mut g = self.inner.lock();
        g.counters.answers += 1;
        let qname = key(a.qname);
        // the chain's names, the question's first
        let mut chain: Vec<String> = vec![qname.clone()];
        let mut addrs: Vec<(IpAddr, u64)> = Vec::new();
        for r in a.records {
            match r {
                Record::Addr { name, ttl, addr } => {
                    let until = a.ts_ns.saturating_add(hold_ns(*ttl));
                    let n = key(name);
                    let e = g.names.entry(n.clone()).or_default();
                    let slot = e
                        .addrs
                        .entry(nn_model::netaddr::canonical(*addr))
                        .or_insert(0);
                    *slot = (*slot).max(until);
                    e.answered_until = e.answered_until.max(until);
                    if !chain.contains(&n) {
                        chain.push(n);
                    }
                    addrs.push((nn_model::netaddr::canonical(*addr), until));
                }
                Record::Cname { name, ttl, target } => {
                    let until = a.ts_ns.saturating_add(hold_ns(*ttl));
                    let (n, t) = (key(name), key(target));
                    let e = g.names.entry(n.clone()).or_default();
                    let slot = e.cnames.entry(t.clone()).or_insert(0);
                    *slot = (*slot).max(until);
                    e.answered_until = e.answered_until.max(until);
                    for x in [n, t] {
                        if !chain.contains(&x) {
                            chain.push(x);
                        }
                    }
                }
            }
        }
        // the question was answered, an address or not
        let floor = a.ts_ns.saturating_add(NAME_FLOOR_SECS * SEC);
        let q = g.names.entry(qname).or_default();
        q.answered_until = q.answered_until.max(floor);
        // an address one of the chain's names spells binds nothing
        let before = addrs.len();
        addrs.retain(|(addr, _)| !chain.iter().any(|n| name_spells(n, *addr)));
        g.counters.ip_in_name += (before - addrs.len()) as u64;
        for (addr, until) in &addrs {
            let slot = g.addrs.entry(*addr).or_insert(0);
            *slot = (*slot).max(*until);
            g.addr_order.touch(*addr);
        }
        // the receiver, and the recent askers of one of the chain's names
        let since = a.ts_ns.saturating_sub(ASK_WINDOW_SECS * SEC);
        let mut pids: Vec<u32> = vec![a.pid];
        for (n, pid, t) in g.askers.iter().rev() {
            if *t < since {
                break;
            }
            if *t <= a.ts_ns && chain.contains(n) && !pids.contains(pid) {
                pids.push(*pid);
            }
        }
        for pid in pids {
            for (addr, until) in &addrs {
                Self::bind(&mut g, pid, *addr, a.ts_ns, *until);
            }
        }
        Self::bound(&mut g);
    }

    /// `pid` asked for `name` at `ts_ns` (a datagram to port 53, or a
    /// lookup through systemd-resolved's NSS module). The name's addresses,
    /// if a response for it was seen and still holds, are bound to it now;
    /// otherwise a response to come binds it.
    pub fn on_query(&self, pid: u32, name: &str, ts_ns: u64) {
        let n = key(name);
        if n.is_empty() {
            return;
        }
        let mut g = self.inner.lock();
        g.askers.push_back((n.clone(), pid, ts_ns));
        while g.askers.len() > MAX_ASKS {
            g.askers.pop_front();
            g.counters.evicted += 1;
        }
        let retain = ts_ns.saturating_sub(UNSEEN_WINDOW_SECS * SEC);
        while g.askers.front().is_some_and(|(_, _, t)| *t < retain) {
            g.askers.pop_front();
        }
        {
            let q = g.asks.entry(pid).or_default();
            q.push_back((n.clone(), ts_ns));
            while q.len() > ASKS_PER_PID {
                q.pop_front();
            }
        }
        g.asking_order.touch(pid);
        while g.asking_order.len() > MAX_ASKING_PIDS {
            if let Some(old) = g.asking_order.pop_oldest() {
                g.asks.remove(&old);
                g.counters.evicted += 1;
            }
        }
        for (addr, until) in Self::addresses_of(&g, &n, ts_ns) {
            Self::bind(&mut g, pid, addr, ts_ns, until);
        }
        Self::bound(&mut g);
    }

    /// The kernel held DNS records of `pid` back at `ts_ns` (its DNS query
    /// or response budget): its lineage's judgement is unknown for a while.
    pub fn note_held(&self, pid: u32, ts_ns: u64) {
        let mut g = self.inner.lock();
        let slot = g.held.entry(pid).or_insert(0);
        *slot = (*slot).max(ts_ns);
        g.held_order.touch(pid);
        while g.held_order.len() > MAX_HELD_PIDS {
            if let Some(old) = g.held_order.pop_oldest() {
                g.held.remove(&old);
            }
        }
    }

    /// A DNS record received at `ts_ns` could not be decoded (the parse
    /// worker did not answer): for [`UNSEEN_WINDOW_SECS`] a connect no
    /// binding covers is unknown, for every process — the response may
    /// have named it.
    pub fn note_undecoded(&self, ts_ns: u64) {
        let mut g = self.inner.lock();
        g.degraded_until = g
            .degraded_until
            .max(ts_ns.saturating_add(UNSEEN_WINDOW_SECS * SEC));
    }

    /// The addresses `name` resolves to at `now_ns`, through at most
    /// [`MAX_CHAIN`] CNAMEs, with when each stops counting.
    fn addresses_of(g: &Inner, name: &str, now_ns: u64) -> Vec<(IpAddr, u64)> {
        let mut out = Vec::new();
        let mut frontier = vec![name.to_string()];
        let mut seen: Vec<String> = Vec::new();
        for _ in 0..=MAX_CHAIN {
            let mut next = Vec::new();
            for n in frontier {
                if seen.contains(&n) {
                    continue;
                }
                if let Some(e) = g.names.get(&n) {
                    for (a, until) in &e.addrs {
                        if *until >= now_ns && !name_spells(&n, *a) && !name_spells(name, *a) {
                            out.push((*a, *until));
                        }
                    }
                    for (t, until) in &e.cnames {
                        if *until >= now_ns {
                            next.push(t.clone());
                        }
                    }
                }
                seen.push(n);
            }
            if next.is_empty() {
                break;
            }
            frontier = next;
        }
        out
    }

    fn bind(g: &mut Inner, pid: u32, addr: IpAddr, made_ns: u64, until_ns: u64) {
        let b = g
            .bindings
            .entry((pid, addr))
            .or_insert(Binding { made_ns, until_ns });
        b.made_ns = b.made_ns.min(made_ns);
        b.until_ns = b.until_ns.max(until_ns);
        g.binding_order.touch((pid, addr));
        g.counters.bindings += 1;
    }

    /// The maps back within their bounds, the oldest out first.
    fn bound(g: &mut Inner) {
        while g.binding_order.len() > MAX_BINDINGS {
            if let Some(k) = g.binding_order.pop_oldest() {
                g.bindings.remove(&k);
                g.counters.evicted += 1;
            }
        }
        while g.addr_order.len() > MAX_ADDRS {
            if let Some(a) = g.addr_order.pop_oldest() {
                g.addrs.remove(&a);
                g.counters.evicted += 1;
            }
        }
        if g.names.len() > MAX_NAMES {
            // the expired first; then the soonest to expire
            let now = g
                .names
                .values()
                .map(|e| e.answered_until)
                .max()
                .unwrap_or(0);
            let horizon = now.saturating_sub(NAME_FLOOR_SECS * SEC);
            let before = g.names.len();
            g.names.retain(|_, e| e.answered_until >= horizon);
            if g.names.len() > MAX_NAMES {
                let mut by_end: Vec<(u64, String)> = g
                    .names
                    .iter()
                    .map(|(k, e)| (e.answered_until, k.clone()))
                    .collect();
                by_end.sort_unstable();
                let excess = g.names.len() - MAX_NAMES * 9 / 10;
                for (_, k) in by_end.into_iter().take(excess) {
                    g.names.remove(&k);
                }
            }
            g.counters.evicted += (before - g.names.len()) as u64;
        }
    }

    /// What the DNS evidence says of a connect to `addr` at `now_ns` by
    /// `pid`, which started at `start_ns` (0: unknown). `ancestors` names
    /// its lineage, nearest first, each with its start (0: unknown) — read
    /// only when the process's own binding misses. A binding found is used:
    /// it lasts [`BIND_IDLE_SECS`] more.
    pub fn check(
        &self,
        pid: u32,
        start_ns: u64,
        addr: IpAddr,
        now_ns: u64,
        ancestors: impl FnOnce() -> Vec<(u32, u64)>,
    ) -> DnsResolution {
        let addr = nn_model::netaddr::canonical(addr);
        let mut g = self.inner.lock();
        g.counters.checks += 1;
        if Self::use_binding(&mut g, pid, start_ns, addr, now_ns) {
            return DnsResolution::Lineage;
        }
        drop(g);
        let mut members = vec![(pid, start_ns)];
        members.extend(ancestors());
        let mut g = self.inner.lock();
        for (p, s) in members.iter().skip(1) {
            if Self::use_binding(&mut g, *p, *s, addr, now_ns) {
                return DnsResolution::Lineage;
            }
        }
        if now_ns <= g.degraded_until {
            return DnsResolution::Unknown;
        }
        let since = now_ns.saturating_sub(UNSEEN_WINDOW_SECS * SEC);
        for (p, s) in &members {
            let from = since.max(*s);
            if g.held.get(p).is_some_and(|t| *t >= from && *t <= now_ns) {
                return DnsResolution::Unknown;
            }
            let unseen = g.asks.get(p).is_some_and(|q| {
                q.iter().any(|(n, t)| {
                    *t >= from
                        && *t <= now_ns
                        && !g.names.get(n).is_some_and(|e| e.answered_until >= *t)
                })
            });
            if unseen {
                return DnsResolution::Unknown;
            }
        }
        if g.addrs.get(&addr).is_some_and(|until| *until >= now_ns) {
            DnsResolution::OtherLineage
        } else {
            DnsResolution::Unresolved
        }
    }

    fn use_binding(g: &mut Inner, pid: u32, start_ns: u64, addr: IpAddr, now_ns: u64) -> bool {
        let Some(b) = g.bindings.get_mut(&(pid, addr)) else {
            return false;
        };
        if b.made_ns < start_ns || b.until_ns < now_ns || b.made_ns > now_ns {
            return false;
        }
        b.until_ns = b.until_ns.max(now_ns.saturating_add(BIND_IDLE_SECS * SEC));
        g.binding_order.touch((pid, addr));
        true
    }

    /// Test/diagnostic: bindings, names and addresses held.
    pub fn sizes(&self) -> (usize, usize, usize) {
        let g = self.inner.lock();
        (g.bindings.len(), g.names.len(), g.addrs.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    type Table = ResolvedTable<()>;

    const C2: IpAddr = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 5));
    const WEB: IpAddr = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 7));
    const T0: u64 = 1_000 * SEC;

    fn a(name: &str, ttl: u32, addr: IpAddr) -> Record {
        Record::Addr {
            name: name.into(),
            ttl,
            addr,
        }
    }

    fn answer(t: &Table, pid: u32, ts: u64, qname: &str, records: &[Record]) {
        t.on_answer(&Answer {
            pid,
            ts_ns: ts,
            qname,
            records,
        });
    }

    fn none() -> Vec<(u32, u64)> {
        Vec::new()
    }

    /// The stub path: the application receives the response itself.
    #[test]
    fn a_process_that_received_the_response_resolved_the_address() {
        let t = Table::new();
        answer(
            &t,
            42,
            T0,
            "www.example.com",
            &[a("www.example.com", 60, WEB)],
        );
        assert_eq!(t.check(42, 1, WEB, T0 + SEC, none), DnsResolution::Lineage);
        // another process: someone resolved it, not its lineage
        assert_eq!(
            t.check(43, 1, WEB, T0 + SEC, none),
            DnsResolution::OtherLineage
        );
        // an address nobody resolved
        assert_eq!(
            t.check(42, 1, C2, T0 + SEC, none),
            DnsResolution::Unresolved
        );
    }

    /// An ancestor's binding counts; a sibling's does not.
    #[test]
    fn the_lineage_is_the_process_and_its_ancestors() {
        let t = Table::new();
        answer(&t, 10, T0, "repo.example", &[a("repo.example", 60, WEB)]);
        let parent = || vec![(10, 1)];
        assert_eq!(
            t.check(11, T0 + 1, WEB, T0 + 2, parent),
            DnsResolution::Lineage
        );
        let other = || vec![(12, 1)];
        assert_eq!(
            t.check(13, T0 + 1, WEB, T0 + 2, other),
            DnsResolution::OtherLineage
        );
    }

    /// External audit NET-016: a binding made before the process started is
    /// an earlier holder's of the pid.
    #[test]
    fn a_binding_older_than_the_process_is_not_its_own() {
        let t = Table::new();
        answer(&t, 42, T0, "a.example", &[a("a.example", 60, WEB)]);
        assert_eq!(
            t.check(42, T0 + 5, WEB, T0 + 10, none),
            DnsResolution::OtherLineage
        );
        assert_eq!(t.check(42, 0, WEB, T0 + 10, none), DnsResolution::Lineage);
    }

    /// nss-resolve: the application asks through varlink (its query is the
    /// NSS record), systemd-resolved receives the upstream response — the
    /// asker is bound, whichever comes first.
    #[test]
    fn a_name_asked_through_the_resolver_binds_its_asker_in_either_order() {
        let t = Table::new();
        const RESOLVED: u32 = 500;
        // query first
        t.on_query(42, "api.example", T0);
        answer(
            &t,
            RESOLVED,
            T0 + 20_000_000,
            "api.example",
            &[a("api.example", 30, WEB)],
        );
        assert_eq!(t.check(42, 1, WEB, T0 + SEC, none), DnsResolution::Lineage);
        // response first (another pump read it sooner), then the query
        answer(&t, RESOLVED, T0, "b.example", &[a("b.example", 30, C2)]);
        t.on_query(77, "B.Example.", T0 + 1);
        assert_eq!(t.check(77, 1, C2, T0 + SEC, none), DnsResolution::Lineage);
        // an asker outside the window is not bound by the response
        t.on_query(88, "late.example", T0);
        answer(
            &t,
            RESOLVED,
            T0 + (ASK_WINDOW_SECS + 1) * SEC,
            "late.example",
            &[a(
                "late.example",
                30,
                IpAddr::V4(Ipv4Addr::new(192, 0, 2, 9)),
            )],
        );
        assert_eq!(
            t.check(
                88,
                1,
                IpAddr::V4(Ipv4Addr::new(192, 0, 2, 9)),
                T0 + 20 * SEC,
                none
            ),
            DnsResolution::OtherLineage
        );
    }

    /// A CNAME chain: the asker of the first name is bound to the addresses
    /// of the last.
    #[test]
    fn a_cname_chain_leads_to_its_addresses() {
        let t = Table::new();
        let recs = [
            Record::Cname {
                name: "www.shop.example".into(),
                ttl: 300,
                target: "shop.cdn.example".into(),
            },
            a("shop.cdn.example", 20, WEB),
        ];
        answer(&t, 500, T0, "www.shop.example", &recs);
        // a later lookup of the first name, served from the resolver's cache
        t.on_query(42, "www.shop.example", T0 + 30 * SEC);
        assert_eq!(
            t.check(42, 1, WEB, T0 + 31 * SEC, none),
            DnsResolution::Lineage
        );
    }

    /// A binding lasts for the TTL (300 s at least), then 2 h past each use.
    #[test]
    fn a_binding_lasts_while_it_is_used() {
        let t = Table::new();
        answer(&t, 42, T0, "ntp.example", &[a("ntp.example", 5, WEB)]);
        // within the 300 s floor
        assert_eq!(
            t.check(42, 1, WEB, T0 + 299 * SEC, none),
            DnsResolution::Lineage
        );
        // used: still bound an hour later, and again after that
        assert_eq!(
            t.check(42, 1, WEB, T0 + 3_600 * SEC, none),
            DnsResolution::Lineage
        );
        assert_eq!(
            t.check(42, 1, WEB, T0 + 7_000 * SEC, none),
            DnsResolution::Lineage
        );
        // unused past the idle time: gone
        let t2 = Table::new();
        answer(&t2, 42, T0, "x.example", &[a("x.example", 5, WEB)]);
        assert_eq!(
            t2.check(42, 1, WEB, T0 + 301 * SEC, none),
            DnsResolution::Unresolved
        );
    }

    /// "IP in the name": an address its name spells binds nothing.
    #[test]
    fn an_address_its_name_spells_is_a_direct_connect() {
        for (name, addr) in [
            ("203-0-113-5.nip.io", C2),
            ("x-203-0-113-5.nip.io", C2),
            ("203.0.113.5.sslip.io", C2),
            ("cb007105.nip.io", C2),
            (
                "2001-db8--7.sslip.io",
                IpAddr::V6("2001:db8::7".parse::<Ipv6Addr>().unwrap()),
            ),
        ] {
            assert!(name_spells(name, addr), "{name}");
            let t = Table::new();
            answer(&t, 42, T0, name, &[a(name, 60, addr)]);
            assert_eq!(
                t.check(42, 1, addr, T0 + SEC, none),
                DnsResolution::Unresolved,
                "{name}"
            );
            assert_eq!(t.counters().ip_in_name, 1);
        }
        for (name, addr) in [
            ("www.example.com", C2),
            ("203-0-113-6.nip.io", C2),
            ("5.113.0.203.in-addr.arpa", C2),
        ] {
            assert!(!name_spells(name, addr), "{name}");
        }
        // through a CNAME the spelled address binds nothing either
        let t = Table::new();
        let recs = [
            Record::Cname {
                name: "c2.example".into(),
                ttl: 60,
                target: "203-0-113-5.nip.io".into(),
            },
            a("203-0-113-5.nip.io", 60, C2),
        ];
        answer(&t, 42, T0, "c2.example", &recs);
        assert_eq!(
            t.check(42, 1, C2, T0 + SEC, none),
            DnsResolution::Unresolved
        );
    }

    /// A name the lineage asked whose response was never seen (a resolver's
    /// cache from before the sensor, DNS over TLS upstream), or DNS records
    /// it had held back: the judgement is unknown — not an alert.
    #[test]
    fn an_unseen_response_or_held_records_make_it_unknown() {
        let t = Table::new();
        t.on_query(42, "cached.example", T0);
        assert_eq!(t.check(42, 1, C2, T0 + SEC, none), DnsResolution::Unknown);
        // once the response is seen and does not name the address: unresolved
        answer(
            &t,
            500,
            T0 + 2 * SEC,
            "cached.example",
            &[a("cached.example", 60, WEB)],
        );
        assert_eq!(
            t.check(42, 1, C2, T0 + 3 * SEC, none),
            DnsResolution::Unresolved
        );
        // an NXDOMAIN is an answer too
        t.on_query(43, "nope.example", T0);
        answer(&t, 500, T0 + SEC, "nope.example", &[]);
        assert_eq!(
            t.check(43, 1, C2, T0 + 2 * SEC, none),
            DnsResolution::Unresolved
        );
        // the old unseen ask no longer counts past the window
        let t = Table::new();
        t.on_query(42, "cached.example", T0);
        assert_eq!(
            t.check(42, 1, C2, T0 + (UNSEEN_WINDOW_SECS + 1) * SEC, none),
            DnsResolution::Unresolved
        );
        // held records
        let t = Table::new();
        t.note_held(42, T0);
        assert_eq!(t.check(42, 1, C2, T0 + SEC, none), DnsResolution::Unknown);
        assert_eq!(
            t.check(43, 1, C2, T0 + SEC, || vec![(42, 1)]),
            DnsResolution::Unknown
        );
        // ... held before the process started are an earlier holder's
        assert_eq!(
            t.check(42, T0 + 1, C2, T0 + SEC, none),
            DnsResolution::Unresolved
        );
    }

    /// A record the pumps could not decode (the parse worker down): what
    /// no binding covers is unknown for a while, for every process.
    #[test]
    fn an_undecoded_record_makes_the_unbound_unknown_for_a_while() {
        let t = Table::new();
        answer(&t, 42, T0, "a.example", &[a("a.example", 60, WEB)]);
        t.note_undecoded(T0 + SEC);
        assert_eq!(
            t.check(7, 1, C2, T0 + 2 * SEC, none),
            DnsResolution::Unknown
        );
        assert_eq!(
            t.check(42, 1, WEB, T0 + 2 * SEC, none),
            DnsResolution::Lineage,
            "bound"
        );
        let after = T0 + SEC + UNSEEN_WINDOW_SECS * SEC + 1;
        assert_eq!(t.check(7, 1, C2, after, none), DnsResolution::Unresolved);
    }

    /// The process's own binding answers without its lineage being read.
    #[test]
    fn the_lineage_is_read_only_on_a_miss() {
        let t = Table::new();
        answer(&t, 42, T0, "a.example", &[a("a.example", 60, WEB)]);
        let read = std::cell::Cell::new(false);
        let anc = || {
            read.set(true);
            Vec::new()
        };
        assert_eq!(t.check(42, 1, WEB, T0 + SEC, anc), DnsResolution::Lineage);
        assert!(!read.get());
    }

    /// IPv6 and an IPv4-mapped connect.
    #[test]
    fn families_and_the_mapped_form() {
        let t = Table::new();
        let v6: IpAddr = "2606:4700::1111".parse().unwrap();
        answer(
            &t,
            42,
            T0,
            "one.example",
            &[a("one.example", 60, v6), a("one.example", 60, WEB)],
        );
        assert_eq!(t.check(42, 1, v6, T0 + SEC, none), DnsResolution::Lineage);
        let mapped: IpAddr = "::ffff:198.51.100.7".parse().unwrap();
        assert_eq!(
            t.check(42, 1, mapped, T0 + SEC, none),
            DnsResolution::Lineage
        );
    }

    /// The maps stay within their bounds; the evictions are counted.
    #[test]
    fn the_tables_are_bounded() {
        let t = Table::new();
        for i in 0..(MAX_BINDINGS as u32 / 64 + 10) {
            let recs: Vec<Record> = (0..64u32)
                .map(|j| {
                    a(
                        "n.example",
                        60,
                        IpAddr::V4(Ipv4Addr::from(0x0a00_0000 + i * 64 + j)),
                    )
                })
                .collect();
            answer(
                &t,
                i % 7,
                T0 + u64::from(i),
                &format!("n{i}.example"),
                &recs,
            );
        }
        let (b, _, ad) = t.sizes();
        assert!(b <= MAX_BINDINGS, "{b}");
        assert!(ad <= MAX_ADDRS, "{ad}");
        assert!(t.counters().evicted > 0);
        for i in 0..(MAX_ASKS + 100) {
            t.on_query(i as u32, &format!("q{i}.example"), T0);
        }
        assert!(t.inner.lock().askers.len() <= MAX_ASKS);
        assert!(t.inner.lock().asks.len() <= MAX_ASKING_PIDS);
    }

    #[test]
    fn the_sensor_start_is_kept() {
        let t = Table::new();
        assert_eq!(t.sensor_since(), None);
        t.set_sensor_since(T0);
        assert_eq!(t.sensor_since(), Some(T0));
        t.set_sensor_since(0);
        assert_eq!(t.sensor_since(), None);
    }
}
