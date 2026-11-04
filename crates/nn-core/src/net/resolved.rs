//! Lot 275 (C07 1→2, C12): which process resolved which address — the
//! state of NN-L-NET-028 ("no DNS, no connect").
//!
//! Merged design of `research/ideas-2026-10-30/ideas-verdict.md`, item 1:
//! the binding is per lineage, the host-wide table its complement.
//!
//! - **The question's chain only** (review of #495, D4): of a response's
//!   records, those whose owner is the question's name or a target of the
//!   chain's CNAMEs (bailiwick); any other record is ignored, counted
//!   ([`Counters::out_of_chain`]).
//! - **Names** (host-wide): a response a system resolver received
//!   ([`is_system_resolver`]: its executable, of a fixed list in the
//!   system tree, and a system uid — never a process name) gives its
//!   question's name, its CNAME chain and its addresses, each held for its
//!   TTL, at least [`NAME_FLOOR_SECS`] (the 300 s Palo Alto uses for its
//!   "direct to IP" detection) and at most [`NAME_CAP_SECS`]. A response
//!   with no address (NXDOMAIN, an empty answer) is remembered as
//!   answered; an incomplete one (D1: cut by the sensor, the server's TC
//!   bit, a malformed record) is not — its question stays asked and not
//!   answered, its records bind. A response any other process received
//!   (a datagram from port 53 to it) binds that process only.
//! - **Bindings** (per process): `(pid, address)` — the process received a
//!   response naming the address ([`ResolvedTable::on_answer`]: the stub
//!   resolver's answer reaches the application), or asked for a name whose
//!   response a system resolver received ([`ResolvedTable::on_query`] and
//!   the askers of [`ResolvedTable::on_answer`]: a query through
//!   systemd-resolved's NSS module, whose upstream answer the resolver
//!   receives). A binding lasts
//!   for the name's TTL (the floor at least) and then for
//!   [`BIND_IDLE_SECS`] past each use, so a daemon that resolved its peers
//!   once (an NTP client, a database client) keeps them while it uses them.
//! - **The "IP in the name" heuristic**: an address that its own name spells
//!   (`1-2-3-4.nip.io`, `1.2.3.4.sslip.io`, `01020304.…`) binds nothing — a
//!   name that only encodes an address is a connect to that address.
//!
//! [`ResolvedTable::check`] answers for a connect: a binding of the process
//! or of an ancestor ([`DnsResolution::Lineage`]); else a name the lineage
//! asked for recently whose response was never seen whole, DNS records of
//! the lineage held back by the kernel's budgets, a host-wide degradation
//! ([`ResolvedTable::note_undecoded`]: an undecoded record, a user's held
//! records, a ring's or a budget's loss), or a binding of a process whose
//! start is not known ([`DnsResolution::Unknown`]); else an address a
//! system resolver resolved for another lineage
//! ([`DnsResolution::OtherLineage`]); else [`DnsResolution::Unresolved`]. A
//! binding counts for a process only when it was made after the process
//! started (a pid outlives its process, external audit NET-016), and only
//! when that start is known (review of #495, N2).
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
    /// Every record of the response read (review of #495, D1): not cut by
    /// the sensor, no TC bit, no malformed record.
    pub complete: bool,
    /// A system resolver received it ([`is_system_resolver`], D4): its
    /// names go host-wide and bind the processes that asked for them.
    pub resolver: bool,
}

/// The system resolvers' executables (review of #495, D4; its second
/// review, R1): a response one of them receives counts host-wide.
pub const SYSTEM_RESOLVER_EXES: &[&str] = &[
    "/usr/lib/systemd/systemd-resolved",
    "/lib/systemd/systemd-resolved",
    "/usr/sbin/dnsmasq",
    "/usr/bin/dnsmasq",
    "/usr/sbin/nscd",
    "/usr/sbin/unbound",
    "/usr/sbin/named",
    "/usr/sbin/pdns_recursor",
    "/usr/sbin/kresd",
];

/// The receiver of a response may be a system resolver: its executable (the
/// image the kernel executed, as the spawn cache knows it) is one of
/// [`SYSTEM_RESOLVER_EXES`], and its uid one of the host's resolver users
/// (`resolver_uids`: the dedicated accounts of `RESOLVER_USERS` in the
/// host's `/etc/passwd`), never root. A path alone is never an identity
/// (the second review of #495, R1): the caller also requires the process to
/// run in the host's mount namespace, where that path names the host's
/// file — a container's `/usr/sbin/dnsmasq`, any program at that path in a
/// namespace of its own, is not one. Never by process name.
pub fn is_system_resolver(exe: Option<&str>, uid: u32, resolver_uids: &[u32]) -> bool {
    uid != 0
        && resolver_uids.contains(&uid)
        && exe.is_some_and(|e| SYSTEM_RESOLVER_EXES.contains(&e))
}

/// Why NN-L-NET-028's DNS evidence was lost for every process (the second
/// review of #495, R2): the cause of a signed `nodns_coverage_lost`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CoverageCause {
    /// A DNS record the parse worker did not decode.
    Undecoded,
    /// A user's DNS records the kernel's budget held back.
    UserHeld,
    /// A DNS ring or budget lost records (its `RING_DROPS` slots grew, or
    /// cannot be read).
    Losses,
    /// A connect judged before the DNS pumps had read the records made
    /// before it (its barrier's wait ended first).
    Barrier,
}

impl CoverageCause {
    pub const ALL: [CoverageCause; 4] = [
        CoverageCause::Undecoded,
        CoverageCause::UserHeld,
        CoverageCause::Losses,
        CoverageCause::Barrier,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            CoverageCause::Undecoded => "undecoded",
            CoverageCause::UserHeld => "user_held",
            CoverageCause::Losses => "dns_losses",
            CoverageCause::Barrier => "barrier",
        }
    }
}

/// A loss of NN-L-NET-028's coverage, to be signed: its cause, the process
/// or user that caused it when known, when.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CoverageLoss {
    pub cause: CoverageCause,
    pub pid: Option<u32>,
    pub uid: Option<u32>,
    pub ts_ns: u64,
    /// How long the evidence stays degraded for every process (0: the one
    /// connect only, a barrier's).
    pub window_secs: u64,
}

/// A cause's loss is signed at most this often (the second review of #495,
/// R2: rate-limited, one per cause per window).
pub const COVERAGE_RECORD_EVERY_SECS: u64 = UNSEEN_WINDOW_SECS;

/// NN-L-NET-028's judgements by outcome, and the unknown ones by reason
/// (the second review of #495, R2: carried by the heartbeat).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Judgements {
    pub lineage: u64,
    pub other_lineage: u64,
    pub unresolved: u64,
    /// The evidence degraded for every process (undecoded, a user's held
    /// records, DNS losses).
    pub unknown_degraded: u64,
    /// The lineage's own DNS records held back.
    pub unknown_held: u64,
    /// A name the lineage asked whose response was never seen whole.
    pub unknown_unseen: u64,
    /// A binding of a process whose start is not known.
    pub unknown_start: u64,
    /// The DNS pumps had not read the records made before the connect.
    pub unknown_barrier: u64,
    /// The DNS response sensor does not run.
    pub unknown_sensor: u64,
    /// The process predates the sensor, or its start is not known.
    pub unknown_older: u64,
    /// `nodns_coverage_lost` records queued to be signed.
    pub coverage_records: u64,
}

/// What the table did, for `nn-admin` and the tests.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Counters {
    pub answers: u64,
    pub bindings: u64,
    /// Records outside the question's chain, ignored (D4).
    pub out_of_chain: u64,
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

/// Why a judgement outside [`ResolvedTable::check`] is unknown.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnknownWhy {
    /// The DNS response sensor does not run.
    Sensor,
    /// The DNS pumps had not caught up.
    Barrier,
    /// The process predates the sensor, or its start is not known.
    Older,
}

/// What a member's binding of an address says ([`ResolvedTable::check`]).
enum Bind {
    /// Made after the process started, still held: used.
    Used,
    /// It exists, but the process's start is not known (N2).
    StartUnknown,
    None,
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
    /// pid → its recent names `(name, ts, answered)`, for the
    /// unseen-response test: `answered` when a whole response the process
    /// received itself answered it (a resolver's answers a name host-wide).
    asks: HashMap<u32, VecDeque<(String, u64, bool)>>,
    asking_order: LazyLru<u32>,
    /// pid → the last time the kernel held one of its DNS records back.
    held: HashMap<u32, u64>,
    held_order: LazyLru<u32>,
    /// A DNS record the pumps could not decode (the parse worker down)
    /// until then: the evidence is incomplete for every process.
    degraded_until: u64,
    counters: Counters,
    judgements: Judgements,
    /// Coverage losses to be signed, and when each cause was last queued.
    coverage: Vec<CoverageLoss>,
    coverage_last: HashMap<CoverageCause, u64>,
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

    /// NN-L-NET-028's judgements so far.
    pub fn judgements(&self) -> Judgements {
        self.inner.lock().judgements
    }

    /// A judgement made outside [`Self::check`] (the host's: no sensor, the
    /// barrier, a process older than the sensor), counted.
    pub fn count_unknown(&self, why: UnknownWhy) {
        let mut g = self.inner.lock();
        let j = &mut g.judgements;
        match why {
            UnknownWhy::Sensor => j.unknown_sensor += 1,
            UnknownWhy::Barrier => j.unknown_barrier += 1,
            UnknownWhy::Older => j.unknown_older += 1,
        }
    }

    /// The coverage losses queued since the last call, to be signed.
    pub fn take_coverage_losses(&self) -> Vec<CoverageLoss> {
        std::mem::take(&mut self.inner.lock().coverage)
    }

    /// NN-L-NET-028's evidence is lost for every process from `ts_ns`
    /// (`window_secs` long; 0: no window, one connect's — the barrier's),
    /// for `cause`, by `pid` or `uid` when known: queued to be signed at
    /// most once a cause per [`COVERAGE_RECORD_EVERY_SECS`].
    pub fn note_coverage_lost(
        &self,
        cause: CoverageCause,
        pid: Option<u32>,
        uid: Option<u32>,
        ts_ns: u64,
    ) {
        let window_secs = if cause == CoverageCause::Barrier {
            0
        } else {
            UNSEEN_WINDOW_SECS
        };
        let mut g = self.inner.lock();
        if window_secs > 0 {
            g.degraded_until = g
                .degraded_until
                .max(ts_ns.saturating_add(window_secs * SEC));
        }
        let due = g
            .coverage_last
            .get(&cause)
            .is_none_or(|last| ts_ns < *last || ts_ns - *last >= COVERAGE_RECORD_EVERY_SECS * SEC);
        if due {
            g.coverage_last.insert(cause, ts_ns);
            g.coverage.push(CoverageLoss {
                cause,
                pid,
                uid,
                ts_ns,
                window_secs,
            });
            g.judgements.coverage_records += 1;
        }
    }

    /// A response `a.pid` received. Of its records, those of the question's
    /// chain (D4). A system resolver's ([`Answer::resolver`]): its names and
    /// addresses held host-wide, its addresses bound to the receiver and to
    /// the processes that asked for one of the chain's names in the last
    /// [`ASK_WINDOW_SECS`]. Any other process's: its addresses bound to it
    /// only. A whole response answers its question (host-wide for a
    /// resolver's, for the receiver's own asks otherwise); an incomplete one
    /// (D1) does not: the question stays asked and unanswered, for the
    /// receiver too, so a connect its records do not cover is unknown.
    pub fn on_answer(&self, a: &Answer<'_>) {
        let mut g = self.inner.lock();
        g.counters.answers += 1;
        let qname = key(a.qname);
        // the chain's names, the question's first, through its CNAMEs in
        // any order of the records
        let mut chain: Vec<String> = vec![qname.clone()];
        let mut kept = vec![false; a.records.len()];
        loop {
            let mut grew = false;
            for (i, r) in a.records.iter().enumerate() {
                if kept[i] {
                    continue;
                }
                match r {
                    Record::Addr { name, .. } if chain.contains(&key(name)) => {
                        kept[i] = true;
                    }
                    Record::Cname { name, target, .. } if chain.contains(&key(name)) => {
                        kept[i] = true;
                        let t = key(target);
                        if !chain.contains(&t) && chain.len() <= MAX_CHAIN {
                            chain.push(t);
                            grew = true;
                        }
                    }
                    _ => {}
                }
            }
            if !grew {
                break;
            }
        }
        g.counters.out_of_chain += kept.iter().filter(|k| !**k).count() as u64;
        let mut addrs: Vec<(IpAddr, u64)> = Vec::new();
        for (r, _) in a.records.iter().zip(&kept).filter(|(_, k)| **k) {
            match r {
                Record::Addr { name, ttl, addr } => {
                    let until = a.ts_ns.saturating_add(hold_ns(*ttl));
                    let addr = nn_model::netaddr::canonical(*addr);
                    if a.resolver {
                        let e = g.names.entry(key(name)).or_default();
                        let slot = e.addrs.entry(addr).or_insert(0);
                        *slot = (*slot).max(until);
                        if a.complete {
                            e.answered_until = e.answered_until.max(until);
                        }
                    }
                    addrs.push((addr, until));
                }
                Record::Cname { name, ttl, target } => {
                    if a.resolver {
                        let until = a.ts_ns.saturating_add(hold_ns(*ttl));
                        let e = g.names.entry(key(name)).or_default();
                        let slot = e.cnames.entry(key(target)).or_insert(0);
                        *slot = (*slot).max(until);
                        if a.complete {
                            e.answered_until = e.answered_until.max(until);
                        }
                    }
                }
            }
        }
        // the question was answered, an address or not — when it was whole
        if a.resolver && a.complete {
            let floor = a.ts_ns.saturating_add(NAME_FLOOR_SECS * SEC);
            let q = g.names.entry(qname.clone()).or_default();
            q.answered_until = q.answered_until.max(floor);
        }
        // an address one of the chain's names spells binds nothing
        let before = addrs.len();
        addrs.retain(|(addr, _)| !chain.iter().any(|n| name_spells(n, *addr)));
        g.counters.ip_in_name += (before - addrs.len()) as u64;
        if a.resolver {
            for (addr, until) in &addrs {
                let slot = g.addrs.entry(*addr).or_insert(0);
                *slot = (*slot).max(*until);
                g.addr_order.touch(*addr);
            }
        }
        // the receiver, and — a resolver's response — the askers of one of
        // the chain's names within the window either side: an asker before
        // the response waits for it; one after it (its pump read first) was
        // answered from the resolver's cache, with these addresses
        let mut pids: Vec<u32> = vec![a.pid];
        if a.resolver {
            let since = a.ts_ns.saturating_sub(ASK_WINDOW_SECS * SEC);
            let until = a.ts_ns.saturating_add(ASK_WINDOW_SECS * SEC);
            for (n, pid, t) in g.askers.iter().rev() {
                if *t < since {
                    break;
                }
                if *t <= until && chain.contains(n) && !pids.contains(pid) {
                    pids.push(*pid);
                }
            }
        }
        for pid in pids {
            for (addr, until) in &addrs {
                Self::bind(&mut g, pid, *addr, a.ts_ns, *until);
            }
        }
        // the receiver's own asks: answered by a whole response; an
        // incomplete one leaves its question asked and unanswered
        if a.complete {
            if let Some(q) = g.asks.get_mut(&a.pid) {
                for (n, t, answered) in q.iter_mut() {
                    if *t <= a.ts_ns && chain.contains(n) {
                        *answered = true;
                    }
                }
            }
        } else {
            Self::ask(&mut g, a.pid, &qname, a.ts_ns);
        }
        Self::bound(&mut g);
    }

    /// `pid`'s ask of `n` at `ts_ns`, unanswered, in its recent names.
    fn ask(g: &mut Inner, pid: u32, n: &str, ts_ns: u64) {
        {
            let q = g.asks.entry(pid).or_default();
            q.push_back((n.to_string(), ts_ns, false));
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
        Self::ask(&mut g, pid, &n, ts_ns);
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

    /// The DNS evidence is incomplete for every process from about `ts_ns`
    /// for [`UNSEEN_WINDOW_SECS`]: a record the parse worker did not
    /// decode, a user's records the kernel's budgets held back, a DNS ring
    /// or budget that lost records (review of #495, D3) — a connect no
    /// binding covers is unknown, for every process: a lost response may
    /// have named it.
    pub fn note_undecoded(&self, ts_ns: u64) {
        self.note_coverage_lost(CoverageCause::Undecoded, None, None, ts_ns);
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
        let mut start_unknown = false;
        match Self::use_binding(&mut g, pid, start_ns, addr, now_ns) {
            Bind::Used => {
                g.judgements.lineage += 1;
                return DnsResolution::Lineage;
            }
            Bind::StartUnknown => start_unknown = true,
            Bind::None => {}
        }
        drop(g);
        let mut members = vec![(pid, start_ns)];
        members.extend(ancestors());
        let mut g = self.inner.lock();
        for (p, s) in members.iter().skip(1) {
            match Self::use_binding(&mut g, *p, *s, addr, now_ns) {
                Bind::Used => {
                    g.judgements.lineage += 1;
                    return DnsResolution::Lineage;
                }
                Bind::StartUnknown => start_unknown = true,
                Bind::None => {}
            }
        }
        // N2: a binding of a member whose start is not known may be an
        // earlier holder's of its pid: neither used nor ignored
        if start_unknown {
            g.judgements.unknown_start += 1;
            return DnsResolution::Unknown;
        }
        if now_ns <= g.degraded_until {
            g.judgements.unknown_degraded += 1;
            return DnsResolution::Unknown;
        }
        let since = now_ns.saturating_sub(UNSEEN_WINDOW_SECS * SEC);
        for (p, s) in &members {
            let from = since.max(*s);
            if g.held.get(p).is_some_and(|t| *t >= from && *t <= now_ns) {
                g.judgements.unknown_held += 1;
                return DnsResolution::Unknown;
            }
            let unseen = g.asks.get(p).is_some_and(|q| {
                q.iter().any(|(n, t, answered)| {
                    *t >= from
                        && *t <= now_ns
                        && !*answered
                        && !g.names.get(n).is_some_and(|e| e.answered_until >= *t)
                })
            });
            if unseen {
                g.judgements.unknown_unseen += 1;
                return DnsResolution::Unknown;
            }
        }
        if g.addrs.get(&addr).is_some_and(|until| *until >= now_ns) {
            g.judgements.other_lineage += 1;
            DnsResolution::OtherLineage
        } else {
            g.judgements.unresolved += 1;
            DnsResolution::Unresolved
        }
    }

    fn use_binding(g: &mut Inner, pid: u32, start_ns: u64, addr: IpAddr, now_ns: u64) -> Bind {
        let Some(b) = g.bindings.get_mut(&(pid, addr)) else {
            return Bind::None;
        };
        if b.made_ns < start_ns || b.until_ns < now_ns || b.made_ns > now_ns {
            return Bind::None;
        }
        if start_ns == 0 {
            return Bind::StartUnknown;
        }
        b.until_ns = b.until_ns.max(now_ns.saturating_add(BIND_IDLE_SECS * SEC));
        g.binding_order.touch((pid, addr));
        Bind::Used
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

    /// A whole response a system resolver received (the tests' default:
    /// its names host-wide).
    fn answer(t: &Table, pid: u32, ts: u64, qname: &str, records: &[Record]) {
        answer_as(t, pid, ts, qname, records, true, true);
    }

    fn answer_as(
        t: &Table,
        pid: u32,
        ts: u64,
        qname: &str,
        records: &[Record],
        complete: bool,
        resolver: bool,
    ) {
        t.on_answer(&Answer {
            pid,
            ts_ns: ts,
            qname,
            records,
            complete,
            resolver,
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
        // N2 (review of #495): a start not known may be another holder's:
        // the binding is neither used nor ignored
        assert_eq!(t.check(42, 0, WEB, T0 + 10, none), DnsResolution::Unknown);
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
        // an asker whose query was read before an earlier response (the
        // pumps' order): bound by it, as by a response from a cache
        t.on_query(55, "c.example", T0 + 2 * SEC);
        answer(
            &t,
            RESOLVED,
            T0 + SEC,
            "c.example",
            &[a("c.example", 30, WEB)],
        );
        assert_eq!(
            t.check(55, 1, WEB, T0 + 3 * SEC, none),
            DnsResolution::Lineage
        );
        // ... but not one that asked past the window after it
        t.on_query(56, "d.example", T0 + 20 * SEC);
        answer(&t, RESOLVED, T0, "d.example", &[a("d.example", 30, C2)]);
        assert_eq!(
            t.check(56, 1, C2, T0 + 21 * SEC, none),
            DnsResolution::OtherLineage
        );
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
            let owner = format!("n{i}.example");
            let recs: Vec<Record> = (0..64u32)
                .map(|j| {
                    a(
                        &owner,
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

    // ── review of #495 ───────────────────────────────────────────────

    const A1: IpAddr = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1));
    const A2: IpAddr = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 2));

    /// D1 (the reviewer's probe P1, which passed on the PR's first head): a
    /// response cut after A1 (the sensor's 512-byte cap, the server's TC
    /// bit, a malformed record) binds A1, but its question stays asked and
    /// unanswered — A2, past the cut, is unknown, never unresolved; for the
    /// receiver as for a resolver's askers.
    #[test]
    fn an_incomplete_response_binds_what_it_read_and_answers_nothing() {
        let t = Table::new();
        t.on_query(42, "big.example", T0);
        assert_eq!(t.check(42, 1, A2, T0 + SEC, none), DnsResolution::Unknown);
        answer_as(
            &t,
            42,
            T0 + 1,
            "big.example",
            &[a("big.example", 60, A1)],
            false,
            false,
        );
        assert_eq!(t.check(42, 1, A1, T0 + SEC, none), DnsResolution::Lineage);
        assert_eq!(t.check(42, 1, A2, T0 + SEC, none), DnsResolution::Unknown);
        // the receiver's query unseen: its incomplete response is an ask
        let t = Table::new();
        answer_as(
            &t,
            43,
            T0,
            "big.example",
            &[a("big.example", 60, A1)],
            false,
            false,
        );
        assert_eq!(t.check(43, 1, A2, T0 + SEC, none), DnsResolution::Unknown);
        // a resolver's incomplete response: its asker bound to A1, A2 unknown
        let t = Table::new();
        t.on_query(44, "big.example", T0);
        answer_as(
            &t,
            500,
            T0 + 1,
            "big.example",
            &[a("big.example", 60, A1)],
            false,
            true,
        );
        assert_eq!(t.check(44, 1, A1, T0 + SEC, none), DnsResolution::Lineage);
        assert_eq!(t.check(44, 1, A2, T0 + SEC, none), DnsResolution::Unknown);
        // the same, whole: A2 nobody resolved
        let t = Table::new();
        t.on_query(44, "big.example", T0);
        answer_as(
            &t,
            500,
            T0 + 1,
            "big.example",
            &[a("big.example", 60, A1)],
            true,
            true,
        );
        assert_eq!(
            t.check(44, 1, A2, T0 + SEC, none),
            DnsResolution::Unresolved
        );
    }

    /// D4 (probe P3): a record outside the question's chain is ignored — not
    /// held host-wide, bound to no one — even in a resolver's response.
    #[test]
    fn a_record_outside_the_question_chain_binds_nothing() {
        for resolver in [false, true] {
            let t = Table::new();
            answer_as(
                &t,
                666,
                T0,
                "x.attacker.example",
                &[a("www.victim.example", 60, C2)],
                true,
                resolver,
            );
            assert_eq!(t.counters().out_of_chain, 1);
            assert_eq!(
                t.check(666, 1, C2, T0 + SEC, none),
                DnsResolution::Unresolved
            );
            // another lineage asks the name later: its answer was never seen
            t.on_query(777, "www.victim.example", T0 + 60 * SEC);
            assert_eq!(
                t.check(777, 1, C2, T0 + 61 * SEC, none),
                DnsResolution::Unknown,
                "resolver {resolver}"
            );
            // and nobody resolved C2
            assert_eq!(
                t.check(888, 1, C2, T0 + 61 * SEC, none),
                DnsResolution::Unresolved,
                "resolver {resolver}"
            );
        }
        // the chain in any order of the records: a CNAME after its A
        let t = Table::new();
        answer_as(
            &t,
            42,
            T0,
            "www.shop.example",
            &[
                a("edge.cdn.example", 60, WEB),
                Record::Cname {
                    name: "www.shop.example".into(),
                    ttl: 60,
                    target: "edge.cdn.example".into(),
                },
                a("other.example", 60, C2),
            ],
            true,
            false,
        );
        assert_eq!(t.check(42, 1, WEB, T0 + SEC, none), DnsResolution::Lineage);
        assert_eq!(
            t.check(42, 1, C2, T0 + SEC, none),
            DnsResolution::Unresolved
        );
        assert_eq!(t.counters().out_of_chain, 1);
    }

    /// D4 (probe P3b): a response any process received binds that process
    /// only — not the askers of its name, not host-wide; a system
    /// resolver's binds its askers and holds its names.
    #[test]
    fn only_a_resolver_s_response_binds_others() {
        let t = Table::new();
        t.on_query(777, "www.victim.example", T0);
        answer_as(
            &t,
            666,
            T0 + 2 * SEC,
            "www.victim.example",
            &[a("www.victim.example", 60, C2)],
            true,
            false,
        );
        assert_eq!(
            t.check(666, 1, C2, T0 + 3 * SEC, none),
            DnsResolution::Lineage
        );
        assert_eq!(
            t.check(777, 1, C2, T0 + 3 * SEC, none),
            DnsResolution::Unknown
        );
        assert_eq!(
            t.check(888, 1, C2, T0 + 3 * SEC, none),
            DnsResolution::Unresolved
        );
        // a later asker gets nothing from it either
        t.on_query(999, "www.victim.example", T0 + 20 * SEC);
        assert_eq!(
            t.check(999, 1, C2, T0 + 21 * SEC, none),
            DnsResolution::Unknown
        );
        // the receiver's own whole response answered its own ask
        t.on_query(321, "self.example", T0);
        answer_as(
            &t,
            321,
            T0 + 1,
            "self.example",
            &[a("self.example", 60, WEB)],
            true,
            false,
        );
        assert_eq!(
            t.check(321, 1, C2, T0 + SEC, none),
            DnsResolution::Unresolved
        );
        // the resolver's: the asker bound, the name held, others see it
        let t = Table::new();
        t.on_query(777, "www.victim.example", T0);
        answer_as(
            &t,
            500,
            T0 + 2 * SEC,
            "www.victim.example",
            &[a("www.victim.example", 60, C2)],
            true,
            true,
        );
        assert_eq!(
            t.check(777, 1, C2, T0 + 3 * SEC, none),
            DnsResolution::Lineage
        );
        assert_eq!(
            t.check(888, 1, C2, T0 + 3 * SEC, none),
            DnsResolution::OtherLineage
        );
    }

    /// D4 and R1: a system resolver is its executable, of the fixed list,
    /// run by one of the host's resolver users — never root, never another
    /// uid, never a name, never a user's copy (the caller adds the host's
    /// mount namespace).
    #[test]
    fn a_system_resolver_is_its_executable_and_a_resolver_user() {
        let users = [101, 120];
        assert!(is_system_resolver(
            Some("/usr/lib/systemd/systemd-resolved"),
            101,
            &users
        ));
        for exe in [
            "/usr/sbin/named",
            "/usr/sbin/pdns_recursor",
            "/usr/sbin/kresd",
        ] {
            assert!(is_system_resolver(Some(exe), 120, &users), "{exe}");
        }
        // root is no resolver user, even listed
        assert!(!is_system_resolver(Some("/usr/sbin/dnsmasq"), 0, &[0, 101]));
        // a system uid that is no resolver user (www-data running dnsmasq)
        assert!(!is_system_resolver(Some("/usr/sbin/dnsmasq"), 33, &users));
        assert!(!is_system_resolver(
            Some("/home/u/systemd-resolved"),
            101,
            &users
        ));
        assert!(!is_system_resolver(Some("systemd-resolved"), 101, &users));
        assert!(!is_system_resolver(None, 101, &users));
        assert!(!is_system_resolver(Some("/usr/sbin/unbound"), 101, &[]));
    }

    /// N2: a binding of an ancestor whose start is not known is neither used
    /// nor ignored: unknown.
    #[test]
    fn a_binding_of_a_member_of_unknown_start_is_unknown() {
        let t = Table::new();
        answer(&t, 10, T0, "repo.example", &[a("repo.example", 60, WEB)]);
        assert_eq!(
            t.check(11, T0 + 1, WEB, T0 + 2, || vec![(10, 0)]),
            DnsResolution::Unknown
        );
        assert_eq!(
            t.check(11, T0 + 1, WEB, T0 + 2, || vec![(10, 1)]),
            DnsResolution::Lineage
        );
    }

    /// RC6 (the review's mutation): the host-wide degradation lasts
    /// exactly [`UNSEEN_WINDOW_SECS`] past the record.
    #[test]
    fn the_degradation_ends_at_its_window() {
        let t = Table::new();
        t.note_undecoded(T0);
        let end = T0 + UNSEEN_WINDOW_SECS * SEC;
        assert_eq!(t.check(42, 1, C2, end, none), DnsResolution::Unknown);
        assert_eq!(t.check(42, 1, C2, end + 1, none), DnsResolution::Unresolved);
        assert_eq!(t.check(42, 1, C2, T0 - SEC, none), DnsResolution::Unknown);
    }

    /// The second review of #495, R2: a loss of coverage for every process
    /// is queued to be signed with its cause and who caused it, at most once
    /// a cause per window; a barrier's degrades nothing beyond its connect.
    #[test]
    fn a_coverage_loss_is_queued_once_a_cause_a_window() {
        let t = Table::new();
        t.note_coverage_lost(CoverageCause::UserHeld, Some(42), Some(1000), T0);
        t.note_coverage_lost(CoverageCause::UserHeld, Some(43), Some(1000), T0 + SEC);
        t.note_coverage_lost(CoverageCause::Losses, None, None, T0 + SEC);
        t.note_coverage_lost(CoverageCause::Barrier, Some(44), None, T0 + 2 * SEC);
        let q = t.take_coverage_losses();
        assert_eq!(
            q.iter()
                .map(|l| (l.cause, l.pid, l.uid, l.window_secs))
                .collect::<Vec<_>>(),
            vec![
                (
                    CoverageCause::UserHeld,
                    Some(42),
                    Some(1000),
                    UNSEEN_WINDOW_SECS
                ),
                (CoverageCause::Losses, None, None, UNSEEN_WINDOW_SECS),
                (CoverageCause::Barrier, Some(44), None, 0),
            ]
        );
        assert!(t.take_coverage_losses().is_empty(), "taken once");
        // a window later: the cause again
        let next = T0 + COVERAGE_RECORD_EVERY_SECS * SEC;
        t.note_coverage_lost(CoverageCause::UserHeld, Some(45), Some(1001), next - 1);
        assert!(
            t.take_coverage_losses().is_empty(),
            "still within the window"
        );
        t.note_coverage_lost(CoverageCause::UserHeld, Some(45), Some(1001), next);
        assert_eq!(t.take_coverage_losses().len(), 1);
        assert_eq!(t.judgements().coverage_records, 4);
        // the degradation: every process unknown until the window's end
        assert_eq!(t.check(7, 1, C2, next + SEC, none), DnsResolution::Unknown);
        // a barrier alone degrades nothing
        let t = Table::new();
        t.note_coverage_lost(CoverageCause::Barrier, Some(44), None, T0);
        assert_eq!(t.check(7, 1, C2, T0 + SEC, none), DnsResolution::Unresolved);
        assert_eq!(
            CoverageCause::ALL.map(CoverageCause::as_str),
            ["undecoded", "user_held", "dns_losses", "barrier"]
        );
    }

    /// R2: the judgements, counted by outcome and, the unknown ones, by
    /// reason.
    #[test]
    fn the_judgements_are_counted_by_outcome_and_reason() {
        let t = Table::new();
        answer(&t, 10, T0, "a.example", &[a("a.example", 60, WEB)]);
        assert_eq!(t.check(10, 1, WEB, T0 + 1, none), DnsResolution::Lineage);
        assert_eq!(
            t.check(11, 1, WEB, T0 + 1, none),
            DnsResolution::OtherLineage
        );
        assert_eq!(t.check(11, 1, C2, T0 + 1, none), DnsResolution::Unresolved);
        assert_eq!(t.check(10, 0, WEB, T0 + 1, none), DnsResolution::Unknown);
        t.on_query(12, "never.example", T0);
        assert_eq!(t.check(12, 1, C2, T0 + 1, none), DnsResolution::Unknown);
        t.note_held(13, T0);
        assert_eq!(t.check(13, 1, C2, T0 + 1, none), DnsResolution::Unknown);
        t.count_unknown(UnknownWhy::Sensor);
        t.count_unknown(UnknownWhy::Barrier);
        t.count_unknown(UnknownWhy::Older);
        t.note_undecoded(T0);
        assert_eq!(t.check(14, 1, C2, T0 + 1, none), DnsResolution::Unknown);
        let j = t.judgements();
        assert_eq!((j.lineage, j.other_lineage, j.unresolved), (1, 1, 1));
        assert_eq!(
            (
                j.unknown_start,
                j.unknown_unseen,
                j.unknown_held,
                j.unknown_sensor,
                j.unknown_barrier,
                j.unknown_older,
                j.unknown_degraded
            ),
            (1, 1, 1, 1, 1, 1, 1)
        );
    }
}
