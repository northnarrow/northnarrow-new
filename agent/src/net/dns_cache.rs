//! Tappa 10 (N4) — userland DNS resolution cache.
//!
//! Provides the PID-keyed back-correlation that lets the N3 flow
//! tracker attribute outbound flows to a DNS QNAME without an
//! active DNS-response observer. Design §6.2 V1.0 narrative:
//! we record DNS QUERY intent from the existing Tappa 4 BPF
//! (`udp_sendmsg` filtered to dport 53) and back-correlate at
//! connect time by picking the most-recent same-PID query
//! within the §13 Q3 5-minute window.
//!
//! The §6.2 design type hints at a `HashMap<(pid, IpAddr),
//! (qname, qtype, ts_ns)>` keying — that's the V1.1 shape after
//! a DNS-response observer lands and we can index by resolved IP
//! directly. V1.0 ships the per-pid recent-query queue + the
//! reply parser as a forward-compat utility (so the V1.1 wire-up
//! is just plugging the observer into [`parse_a_records`] /
//! [`parse_aaaa_records`]).
//!
//! Q3 5-minute window is **hard-coded** in V1.0 per the lock-in
//! ("Operator-tunable in V1.1 via net.dns_cache_ttl_secs"). The
//! TTL constant lives at [`DEFAULT_TTL_SECS`].
//!
//! Concurrency: the cache holds its hot map behind a
//! `parking_lot::Mutex` so callers can share via `Arc<DnsCache>`
//! across the multi-task drain loop the future commits land.
//!
//! External audit NET-016 (NN-AUD-167): a PID is not a process. The
//! kernel hands a freed PID to the next process within the 300 s window,
//! so [`DnsCache::lookup_for_connect`] takes the connecting process's
//! start (read at connect time) and ignores the queries made before it —
//! a previous holder's. External audit NET-006 (NN-AUD-164):
//! [`DnsCache::originator_for`] names an originator only when exactly one
//! process asked a local stub resolver for the name.

use std::collections::{HashMap, VecDeque};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use parking_lot::Mutex;
use tokio::sync::Notify;

/// Per design §13 Q3 + §6.2: 300 s (5 minutes) of attribution
/// window. Hard-coded in V1.0; V1.1 introduces
/// `net.dns_cache_ttl_secs` in `/etc/northnarrow/config.toml`.
pub const DEFAULT_TTL_SECS: u64 = 300;

/// Default per-PID cap on retained recent queries. Bounded so a
/// pathologically chatty resolver (e.g. dig spam) can't grow the
/// cache without limit. 1024 covers normal browser tab-storms +
/// CI build DNS lookups comfortably.
pub const DEFAULT_MAX_PER_PID: usize = 1024;

/// FP-3 (NN-L-NET-004/-005/-014 originator attribution) reverse-index
/// retention. The `qname → (pid, ts)` index that
/// [`DnsCache::originator_for`] scans serves a deliberately TIGHT
/// back-correlation window (≤2 s — the forwarder's upstream leg and the
/// originator's stub query are microseconds apart), so it does NOT need
/// the 300 s connect-attribution TTL. A short retention also bounds
/// memory: DGA/tunnelling qnames are unique-by-construction (they never
/// repeat), so without aggressive pruning the reverse index would grow
/// one entry per distinct lookup. 30 s is generous headroom over the
/// 2 s window while keeping the retained set small.
pub const REVERSE_RETAIN_SECS: u64 = 30;

/// Hard cap on reverse-index entries — a backstop against a query
/// storm filling the 30 s window faster than retention prunes it.
/// FIFO-evicts the oldest; the newest (and thus the entries the ≤2 s
/// back-correlation actually reads) are always retained. ~16 K entries
/// × ~64 B ≈ 1 MiB worst case.
const REVERSE_MAX_ENTRIES: usize = 16_384;
/// Hard cap on DISTINCT pids retained in the forward map (soak 2026-10-11).
/// `by_pid` was only ever trimmed per pid, inside `lookup_for_connect`,
/// so every short-lived process that resolved a name — one `getent` per
/// second in the soak generator; cron jobs, `curl`, `ssh`, package
/// managers on a real host — left a key behind for the life of the agent
/// (~1 MB/h on the AlmaLinux 9 soak). Pids past the TTL are now pruned
/// opportunistically every [`PRUNE_EVERY`] inserts, and when the map is
/// still above this cap the pid with the oldest newest-query is evicted.
/// 4096 pids × ≤ `max_per_pid` queries is the worst case an attribution
/// window of 300 s can legitimately hold on a busy host.
pub const DEFAULT_MAX_PIDS: usize = 4096;
/// Insert interval between full-map stale-pid prunes (an O(pids) scan).
const PRUNE_EVERY: u32 = 256;

/// External audit NET-004: hard cap on the queries retained across all
/// pids. The pid cap bounded the keys, not the memory: 4096 pids × 1024
/// queries × a name of up to 253 bytes is over a gigabyte, within reach of
/// an unprivileged process sending to port 53 from short-lived children.
/// 65 536 queries are ~20 MiB at worst. Past the cap the oldest query of
/// the pid holding the most goes — the flooder's, not a quiet process's
/// one recent lookup.
pub const MAX_TOTAL_ENTRIES: usize = 65_536;

/// One observed DNS query (PRE-response, V1.0). The same PID
/// might issue many queries within the TTL window; we keep the
/// most-recent N (`max_per_pid`).
#[derive(Debug, Clone, PartialEq, Eq)]
struct RecentQuery {
    qname: String,
    /// Query type (`A=1`, `AAAA=28`, etc.). Surfaced verbatim
    /// in case rules want to differentiate v4-resolved vs v6-
    /// resolved attribution.
    #[allow(dead_code)]
    qtype: u16,
    /// Monotonic-clock ns at the time the kernel observed the
    /// `udp_sendmsg` to port 53. Same clock source as the rest
    /// of the event pipeline.
    ts_ns: u64,
}

/// One FP-3 reverse-index observation.
#[derive(Debug, Clone)]
struct ReverseEntry {
    qname: String,
    pid: u32,
    ts_ns: u64,
    /// Where the query was sent (external audit NET-006): only a query to
    /// a local stub resolver can be the originator of a forwarded leg.
    server: IpAddr,
}

#[derive(Debug, Default)]
struct DnsCacheInner {
    /// PID → recent queries, oldest at the front. Changed only through
    /// [`DnsCacheInner::push`], [`DnsCacheInner::retain_pids`] and
    /// [`DnsCacheInner::remove_pid`], which keep `total` right.
    by_pid: HashMap<u32, VecDeque<RecentQuery>>,
    /// Queries held in `by_pid` (external audit NET-004).
    total: usize,
    /// Inserts since the last stale-pid prune (see [`PRUNE_EVERY`]).
    inserts_since_prune: u32,
    /// FP-3 reverse index: recent [`ReverseEntry`] observations in
    /// insertion order (≈ monotonic `ts_ns`, single-writer drain),
    /// pruned to [`REVERSE_RETAIN_SECS`] / [`REVERSE_MAX_ENTRIES`].
    /// [`DnsCache::originator_for`] scans this for the one *other* PID
    /// that asked a local stub for a given qname — the
    /// forwarder-aware back-correlation that lets NN-L-NET-004/-014
    /// attribute a forwarded leg to the originating process instead of
    /// the resolver. Distinct from `by_pid` (forward, 300 s
    /// connect-attribution); this one is reverse + short-lived.
    recent_by_time: VecDeque<ReverseEntry>,
}

/// PID-keyed DNS query cache. Construct once at agent boot,
/// share via `Arc<DnsCache>`; both ingest sites (Event::DnsQuery
/// drain) and lookup sites (flow tracker on_tcp_connect ↔
/// on_tcp_close) take `&self` and lock the inner map internally.
#[derive(Debug)]
pub struct DnsCache {
    inner: Mutex<DnsCacheInner>,
    ttl_ns: u64,
    max_per_pid: usize,
    /// FP-3 reverse-index retention (ns). See [`REVERSE_RETAIN_SECS`].
    reverse_retain_ns: u64,
    /// Lab PR 229: how far the DNS pump has read its ring.
    ingest: DnsIngest,
}

/// Lab PR 229: the longest a lookup waits for the DNS pump, counted from
/// the record it attributes (its kernel time). A record older than that
/// waits for nothing: the pump has had that long to read the queries made
/// before it.
pub const INGEST_WAIT: Duration = Duration::from_millis(250);

/// Lab PR 229: how far the DNS pump has read the `DNS_QUERY_EVENTS` ring,
/// so that a DNS attribution reads the cache after the queries made before
/// the connect it attributes.
///
/// The queries, the connects and the closes come on three rings, read by
/// three tasks. A close (or a connect) read before the pump had read the
/// query of the same process found no name: `resolved_hostname` was `null`
/// whenever the pump ran later than the net drain — the CI flake of
/// `net_outbound_connect_records_flow_with_dns_attribution` on Ubuntu
/// 24.04 (run 39602279581), where nothing else differs between a run that
/// names the host and one that does not. A process's query is in the ring
/// before its `sendmsg` returns, so before its connect and its close are
/// timed: once the pump has run its ring empty in a pass that began at or
/// after a record's time, the cache holds every query that record's
/// process made before it.
///
/// [`Self::caught_up`] waits for such a pass, asking the pump for one, at
/// most [`INGEST_WAIT`] from the record's time; with no pump running it
/// does not wait. The pump marks each pass ([`Self::pass_ended`]).
#[derive(Debug, Default)]
pub struct DnsIngest {
    /// `CLOCK_MONOTONIC` when the pump began its last pass that ran the
    /// ring empty; 0 before the first.
    drained_from_ns: AtomicU64,
    /// The pump runs ([`IngestClaim`]).
    pump: AtomicBool,
    /// A lookup asks the pump for a pass.
    wanted: Notify,
    /// A pass ended, or the pump stopped.
    passed: Notify,
}

impl DnsIngest {
    /// Whether a pass that began at or after `ts_ns` has ended.
    pub fn covers(&self, ts_ns: u64) -> bool {
        self.drained_from_ns.load(Ordering::Acquire) >= ts_ns
    }

    /// Pump side: a pass that began at `began_ns` (read before its first
    /// record) ran the ring empty.
    pub fn pass_ended(&self, began_ns: u64) {
        self.drained_from_ns.fetch_max(began_ns, Ordering::AcqRel);
        self.passed.notify_waiters();
    }

    /// Pump side: resolves when a lookup has asked for a pass.
    pub async fn wanted(&self) {
        self.wanted.notified().await
    }

    /// Wait until the cache holds the queries made before a record timed
    /// `ts_ns` (`CLOCK_MONOTONIC`, the kernel's): `true` then, `false` when
    /// the wait ended first (no pump, or [`INGEST_WAIT`] since the record)
    /// — the lookup then reads what the cache holds, as before.
    pub async fn caught_up(&self, ts_ns: u64) -> bool {
        if self.covers(ts_ns) {
            return true;
        }
        let age = Duration::from_nanos(monotonic_ns().saturating_sub(ts_ns));
        let Some(left) = INGEST_WAIT.checked_sub(age) else {
            return false;
        };
        let deadline = tokio::time::Instant::now() + left;
        loop {
            let passed = self.passed.notified();
            tokio::pin!(passed);
            passed.as_mut().enable();
            if self.covers(ts_ns) {
                return true;
            }
            if !self.pump.load(Ordering::Acquire) {
                return false;
            }
            self.wanted.notify_one();
            if tokio::time::timeout_at(deadline, passed).await.is_err() {
                return self.covers(ts_ns);
            }
        }
    }
}

/// Lab PR 229: held by the DNS pump while it runs; a lookup waits for
/// passes only then.
#[derive(Debug)]
pub struct IngestClaim(Arc<DnsCache>);

impl IngestClaim {
    pub fn new(cache: Arc<DnsCache>) -> Self {
        cache.ingest.pump.store(true, Ordering::Release);
        Self(cache)
    }
}

impl Drop for IngestClaim {
    fn drop(&mut self) {
        self.0.ingest.pump.store(false, Ordering::Release);
        self.0.ingest.passed.notify_waiters();
    }
}

/// `CLOCK_MONOTONIC` in ns: `bpf_ktime_get_ns`'s clock, the records' clock.
pub fn monotonic_ns() -> u64 {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: a valid clock id and a timespec to fill.
    unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) };
    ts.tv_sec as u64 * 1_000_000_000 + ts.tv_nsec as u64
}

impl Default for DnsCache {
    fn default() -> Self {
        Self::new(DEFAULT_TTL_SECS, DEFAULT_MAX_PER_PID)
    }
}

impl DnsCacheInner {
    /// Append a query for `pid`, keeping its queue to `max_per_pid` and
    /// every queue together to `max_total`.
    fn push(&mut self, pid: u32, q: RecentQuery, max_per_pid: usize, max_total: usize) {
        let queue = self.by_pid.entry(pid).or_default();
        queue.push_back(q);
        self.total += 1;
        while queue.len() > max_per_pid {
            queue.pop_front();
            self.total -= 1;
        }
        while self.total > max_total {
            let Some(heaviest) = self
                .by_pid
                .iter()
                .max_by_key(|(_, q)| q.len())
                .map(|(pid, _)| *pid)
            else {
                break;
            };
            let empty = match self.by_pid.get_mut(&heaviest) {
                Some(q) => {
                    if q.pop_front().is_some() {
                        self.total -= 1;
                    }
                    q.is_empty()
                }
                None => break,
            };
            if empty {
                self.by_pid.remove(&heaviest);
            }
        }
    }

    /// Keep the pids `keep` accepts.
    fn retain_pids(&mut self, mut keep: impl FnMut(&VecDeque<RecentQuery>) -> bool) {
        let mut dropped = 0;
        self.by_pid.retain(|_, q| {
            let k = keep(q);
            if !k {
                dropped += q.len();
            }
            k
        });
        self.total -= dropped;
    }

    fn remove_pid(&mut self, pid: u32) {
        if let Some(q) = self.by_pid.remove(&pid) {
            self.total -= q.len();
        }
    }
}

impl DnsCache {
    /// Custom-bound constructor for tests + future V1.1 config
    /// surface. Production callers should use [`Self::default`]
    /// (300 s TTL, 1024 per-pid). The FP-3 reverse-index retention is
    /// fixed at [`REVERSE_RETAIN_SECS`] regardless of `ttl_secs` — it
    /// serves the tight ≤2 s back-correlation window, not the 300 s
    /// connect-attribution window.
    pub fn new(ttl_secs: u64, max_per_pid: usize) -> Self {
        Self {
            inner: Mutex::new(DnsCacheInner::default()),
            ttl_ns: ttl_secs.saturating_mul(1_000_000_000),
            max_per_pid,
            reverse_retain_ns: REVERSE_RETAIN_SECS.saturating_mul(1_000_000_000),
            ingest: DnsIngest::default(),
        }
    }

    /// Lab PR 229: how far the DNS pump has fed this cache.
    pub fn ingest(&self) -> &DnsIngest {
        &self.ingest
    }

    /// Record a DNS query observation: `pid` sent `qname` to `server`
    /// (the datagram's destination). Called by the DNS pump on every
    /// `Event::DnsQuery`. FIFO eviction kicks in past `max_per_pid`.
    pub fn on_dns_query(&self, pid: u32, qname: String, qtype: u16, server: IpAddr, ts_ns: u64) {
        let mut g = self.inner.lock();
        g.push(
            pid,
            RecentQuery {
                qname: qname.clone(),
                qtype,
                ts_ns,
            },
            self.max_per_pid,
            MAX_TOTAL_ENTRIES,
        );
        // FP-3 reverse index: record (qname, pid, ts) for forwarder-aware
        // originator back-correlation, then prune by the short retention
        // window + the hard size cap so unique DGA qnames can't grow it.
        g.inserts_since_prune += 1;
        if g.inserts_since_prune >= PRUNE_EVERY || g.by_pid.len() > DEFAULT_MAX_PIDS {
            g.inserts_since_prune = 0;
            Self::prune_pids(&mut g, ts_ns, self.ttl_ns);
        }
        g.recent_by_time.push_back(ReverseEntry {
            qname,
            pid,
            ts_ns,
            server: nn_model::netaddr::canonical(server),
        });
        let cutoff = ts_ns.saturating_sub(self.reverse_retain_ns);
        while g.recent_by_time.front().is_some_and(|e| e.ts_ns < cutoff) {
            g.recent_by_time.pop_front();
        }
        while g.recent_by_time.len() > REVERSE_MAX_ENTRIES {
            g.recent_by_time.pop_front();
        }
    }

    /// FP-3 forwarder-aware back-correlation. Returns the one PID *other
    /// than* `exclude_pid` that asked a local stub resolver for `qname`
    /// within `window_ns` of `now_ns`, or `None`.
    ///
    /// NN-L-NET-004/-014 call this when a tripped DnsQuery's *sender* is
    /// a known forwarder/stub resolver (e.g. `systemd-resolved`): the
    /// resolver must never be the kill target, so we look back through
    /// the reverse index for the process whose own (loopback-stub) query
    /// of the same qname triggered the forward. `exclude_pid` drops the
    /// forwarder's own just-recorded entry from consideration.
    ///
    /// External audit NET-006 (NN-AUD-164): the newest PID that sent the
    /// same name used to win, so a process that made a chosen victim ask
    /// for a name, then asked for it itself (or the other way round),
    /// picked which PID the verdict named. A candidate now
    /// - sent its query to a loopback address (a local stub; a query sent
    ///   elsewhere did not go through the forwarder);
    /// - matches the name ignoring ASCII case (DNS names are
    ///   case-insensitive, and a forwarder using DNS 0x20 changes the
    ///   case of its upstream leg);
    /// - is the only one: two distinct PIDs is an ambiguous attribution,
    ///   and `None` — the caller logs instead of acting.
    ///
    /// `None` is the safe outcome — Varlink/`nss-resolve` (the
    /// originator never sent UDP/53), a host acting as a LAN resolver
    /// (the client is remote, no local PID), an originator in another
    /// network namespace that reaches the resolver on a non-loopback
    /// address, an ambiguous name, or a cache miss all return `None`,
    /// and the caller downgrades to `Log` rather than acting on the
    /// resolver.
    ///
    /// The `window_ns` is the caller's tight correlation window (≤2 s),
    /// kept far below the reverse-index retention so a stale same-qname
    /// entry from an earlier unrelated PID can't be mis-attributed.
    pub fn originator_for(
        &self,
        qname: &str,
        now_ns: u64,
        window_ns: u64,
        exclude_pid: u32,
    ) -> Option<u32> {
        let mut g = self.inner.lock();
        // Opportunistic retain-window prune (keeps the scanned set small
        // even if no insert has happened recently).
        let retain_cutoff = now_ns.saturating_sub(self.reverse_retain_ns);
        while g
            .recent_by_time
            .front()
            .is_some_and(|e| e.ts_ns < retain_cutoff)
        {
            g.recent_by_time.pop_front();
        }
        let win_cutoff = now_ns.saturating_sub(window_ns);
        let mut originator = None;
        for e in g.recent_by_time.iter().filter(|e| {
            e.ts_ns >= win_cutoff
                && e.ts_ns <= now_ns
                && e.pid != exclude_pid
                && is_local_stub(&e.server)
                && e.qname.eq_ignore_ascii_case(qname)
        }) {
            match originator {
                None => originator = Some(e.pid),
                Some(pid) if pid == e.pid => {}
                Some(_) => return None,
            }
        }
        originator
    }

    /// V1.0 back-correlation lookup. Returns the qname of the
    /// most-recent query this `pid` issued at or before
    /// `now_ns`, provided it's still within the TTL window
    /// (`now_ns - ts_ns <= DEFAULT_TTL_SECS`). `None` for
    /// cache miss (no prior query / window expired / different
    /// PID).
    ///
    /// The "most recent" tie-breaker matters because a single
    /// process can issue multiple resolutions in close
    /// succession (a browser opening a page with sub-resources);
    /// the latest qname is the strongest candidate for the
    /// outbound connect that just fired.
    ///
    /// Also opportunistically prunes expired entries for this
    /// PID — keeps memory bounded under long-lived agent runs.
    /// Drop every pid whose NEWEST query is older than the TTL (its
    /// entries could never attribute a connect again), then, if the map
    /// is still above [`DEFAULT_MAX_PIDS`], evict the pids with the
    /// oldest newest-query until it fits. Called from `on_dns_query`
    /// every [`PRUNE_EVERY`] inserts, so the amortised cost per query is
    /// a fraction of a scan.
    fn prune_pids(g: &mut DnsCacheInner, now_ns: u64, ttl_ns: u64) {
        let cutoff = now_ns.saturating_sub(ttl_ns);
        g.retain_pids(|q| q.back().is_some_and(|e| e.ts_ns >= cutoff));
        while g.by_pid.len() > DEFAULT_MAX_PIDS {
            let oldest = g
                .by_pid
                .iter()
                .min_by_key(|(_, q)| q.back().map(|e| e.ts_ns).unwrap_or(0))
                .map(|(pid, _)| *pid);
            match oldest {
                Some(pid) => g.remove_pid(pid),
                None => break,
            }
        }
    }

    /// The name `pid` most recently asked for at or before `now_ns`
    /// (the connect), within the TTL. `proc_start_ns` is the connecting
    /// process's start, or a time before it (`CLOCK_MONOTONIC`, read at
    /// connect time; 0 = unknown): a query older than that was made by an
    /// earlier holder of the PID and is not this process's (external
    /// audit NET-016, NN-AUD-167). With the start unknown (the process
    /// gone before the connect was read) the PID alone decides, as before.
    pub fn lookup_for_connect(&self, pid: u32, now_ns: u64, proc_start_ns: u64) -> Option<String> {
        let g = self.inner.lock();
        let q = g.by_pid.get(&pid)?;
        // Saturate on underflow (monotonic clock jitter on the dev VM can
        // push `now_ns < ttl_ns`). NET-016: nothing older than the
        // process is its own.
        let cutoff = now_ns.saturating_sub(self.ttl_ns).max(proc_start_ns);
        // External audit NET-005 (NN-AUD-059): the newest query at or
        // before the connect, walking back. The caller passes the
        // connect's time and looks up when the flow CLOSES, so a query
        // the pid issued meanwhile is newer than the connect; reading
        // only the back of the queue returned nothing then. No pruning
        // here either: `now_ns` is in the past, and a cut from it could
        // drop what an older flow still needs (`prune_pids` runs on
        // inserts).
        q.iter()
            .rev()
            .find(|e| e.ts_ns <= now_ns)
            .filter(|e| e.ts_ns >= cutoff)
            .map(|e| e.qname.clone())
    }

    /// Test/diagnostic — number of pids with at least one
    /// retained query. Production callers don't use this.
    #[cfg(test)]
    fn tracked_pids(&self) -> usize {
        self.inner.lock().by_pid.len()
    }

    /// Test/diagnostic — queries retained across all pids, as counted and
    /// as held.
    #[cfg(test)]
    fn totals(&self) -> (usize, usize) {
        let g = self.inner.lock();
        (g.total, g.by_pid.values().map(|q| q.len()).sum())
    }

    /// Test/diagnostic — number of queries currently retained
    /// for `pid`.
    #[cfg(test)]
    fn entries_for(&self, pid: u32) -> usize {
        self.inner
            .lock()
            .by_pid
            .get(&pid)
            .map(|q| q.len())
            .unwrap_or(0)
    }
}

/// A local stub resolver's address: `127.0.0.0/8` or `::1` (external
/// audit NET-006). `server` is canonical (an IPv4-mapped address folded).
fn is_local_stub(server: &IpAddr) -> bool {
    server.is_loopback()
}

// ── DNS reply parser (forward-compat utility for V1.1) ───────────────
//
// RFC 1035 wire format walker. V1.0 doesn't have a DNS-response
// observer; these parsers ship now as a standalone utility so the
// V1.1 commit that wires up the observer is a pure plumbing change.
// Kept, not deleted, though nothing in production calls it (external
// audit NET-013, NET-015): the `dns_records` fuzz target exercises it,
// and it now reads names as the system resolver does, so the observer
// that lands on it inherits a conforming parser.
//
// We handle:
//   * the 12-byte header,
//   * a single QUESTION section (compressed-name + qtype + qclass),
//   * the ANSWER section with name (label OR pointer per §4.1.4),
//     16-bit TYPE / CLASS, 32-bit TTL, 16-bit RDLENGTH, RDATA.
//
// Names are held to RFC 1035: a length octet is a label (top bits
// `00`, so at most 63 bytes) or a pointer (`11`) into the message; `01`
// and `10` are reserved and refused; a name is at most 255 octets on
// the wire (external audit NET-015, NN-AUD-334). Read past, they would
// shift the walk off the records the resolver applies.
//
// We DON'T handle:
//   * Multi-question messages (V1.0+ resolvers always send 1
//     question per query; observed real-world traffic is 100%
//     single-question).
//   * Recursive name decompression (we only need to SKIP names
//     in answers — A/AAAA RDATA is positional, no name decoding
//     required).
//   * EDNS / DNSSEC RR types (out of V1.0 scope per design §6.3).

const DNS_TYPE_A: u16 = 1;
const DNS_TYPE_AAAA: u16 = 28;
const DNS_HEADER_LEN: usize = 12;
/// Compressed-name pointer marker — RFC 1035 §4.1.4: the top
/// two bits of a label-length byte are set when the byte +
/// next byte together encode a 14-bit offset to elsewhere in
/// the message.
const DNS_NAME_POINTER_MASK: u8 = 0xC0;
/// The top two bits of a length octet: `00` label, `11` pointer, `01`
/// and `10` reserved (RFC 1035 §4.1.4; the `01` extended labels of
/// RFC 2671 are deprecated by RFC 6891 §5).
const DNS_LABEL_KIND_MASK: u8 = 0xC0;
/// RFC 1035 §2.3.4 / §3.1: a name is at most 255 octets in wire form,
/// its length octets and the root label included.
const DNS_MAX_NAME_WIRE_LEN: usize = 255;
/// The shortest resource record: a one-octet name (the root, or half of
/// nothing — a pointer is two) and TYPE, CLASS, TTL, RDLENGTH.
const DNS_MIN_RR_LEN: usize = 1 + 2 + 2 + 4 + 2;

/// Parser cursor + state. Wraps the byte stream so the
/// `advance_*` helpers stay bounded — every helper rejects
/// reads past `bytes.len()` instead of panicking on slice OOB.
struct DnsPacket<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> DnsPacket<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, pos: 0 }
    }

    /// Bytes left after `pos`. The bounds are `need > remaining()`, as in
    /// the TLS parser's cursor: `pos + need` can wrap (external audit
    /// NET-015).
    fn remaining(&self) -> usize {
        self.bytes.len().saturating_sub(self.pos)
    }

    fn read_u16(&mut self) -> Option<u16> {
        if 2 > self.remaining() {
            return None;
        }
        let v = u16::from_be_bytes([self.bytes[self.pos], self.bytes[self.pos + 1]]);
        self.pos += 2;
        Some(v)
    }

    fn read_u32(&mut self) -> Option<u32> {
        if 4 > self.remaining() {
            return None;
        }
        let v = u32::from_be_bytes([
            self.bytes[self.pos],
            self.bytes[self.pos + 1],
            self.bytes[self.pos + 2],
            self.bytes[self.pos + 3],
        ]);
        self.pos += 4;
        Some(v)
    }

    fn read_bytes(&mut self, n: usize) -> Option<&'a [u8]> {
        if n > self.remaining() {
            return None;
        }
        let b = &self.bytes[self.pos..self.pos + n];
        self.pos += n;
        Some(b)
    }

    /// Skip a DNS name in-place. Names are either:
    ///   * a sequence of length-prefixed labels terminated by
    ///     a zero byte, OR
    ///   * a 2-byte pointer (top 2 bits == 11) referencing an
    ///     earlier name in the message — consumes 2 bytes and
    ///     advances no further (we don't follow the pointer
    ///     because we don't need the decoded name for A/AAAA
    ///     RDATA), but it must point inside the message.
    ///
    /// `None` for a reserved length octet (`0x40..=0xBF`: a label over
    /// 63 bytes or the `01` / `10` prefixes), a name over 255 octets, or
    /// a read past the message (external audit NET-015, NN-AUD-334).
    fn skip_name(&mut self) -> Option<()> {
        let mut wire_len = 0usize;
        loop {
            let b = *self.bytes.get(self.pos)?;
            match b & DNS_LABEL_KIND_MASK {
                0x00 => {
                    // Label: 1-byte length (at most 63 by its prefix) +
                    // that many bytes; the zero length is the root.
                    let label_len = b as usize;
                    wire_len += 1 + label_len;
                    if wire_len > DNS_MAX_NAME_WIRE_LEN || 1 + label_len > self.remaining() {
                        return None;
                    }
                    self.pos += 1 + label_len;
                    if label_len == 0 {
                        return Some(());
                    }
                }
                DNS_NAME_POINTER_MASK => {
                    // 2-byte pointer; we don't follow it.
                    let lo = *self.bytes.get(self.pos + 1)?;
                    let offset = (usize::from(b & !DNS_LABEL_KIND_MASK) << 8) | usize::from(lo);
                    if offset >= self.bytes.len() {
                        return None;
                    }
                    self.pos += 2;
                    return Some(());
                }
                _ => return None,
            }
        }
    }
}

/// Parse `packet` as a DNS response message and return every
/// IPv4 address found in an A-record answer. Returns an empty
/// `Vec` on any parse failure — defensive callers can treat
/// "no A records" + "malformed packet" the same way (both mean
/// "no v4 attribution available"). For surfacing parse errors,
/// the test suite uses [`try_parse_answers`].
pub fn parse_a_records(packet: &[u8]) -> Vec<Ipv4Addr> {
    let answers = try_parse_answers(packet).unwrap_or_default();
    answers
        .into_iter()
        .filter_map(|a| match a {
            DnsAnswer::A(ip) => Some(ip),
            _ => None,
        })
        .collect()
}

/// Parse `packet` and return IPv6 AAAA-record addresses. Same
/// "Vec on success, empty Vec on failure" contract as
/// [`parse_a_records`].
pub fn parse_aaaa_records(packet: &[u8]) -> Vec<Ipv6Addr> {
    let answers = try_parse_answers(packet).unwrap_or_default();
    answers
        .into_iter()
        .filter_map(|a| match a {
            DnsAnswer::Aaaa(ip) => Some(ip),
            _ => None,
        })
        .collect()
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum DnsAnswer {
    A(Ipv4Addr),
    Aaaa(Ipv6Addr),
    /// CNAME, MX, TXT, etc. — preserved so the parser can step
    /// over the RDATA correctly, but not exposed in the
    /// caller-visible API.
    Other,
}

/// Parser entry-point — surfaces None on any malformed-packet
/// failure. The public [`parse_a_records`] + [`parse_aaaa_records`]
/// flatten this to an empty Vec; tests use `try_parse_answers`
/// directly to distinguish "no records" from "parse error."
fn try_parse_answers(packet: &[u8]) -> Option<Vec<DnsAnswer>> {
    if packet.len() < DNS_HEADER_LEN {
        return None;
    }
    let mut p = DnsPacket::new(packet);
    // Header: id(2) + flags(2) + qdcount(2) + ancount(2) +
    // nscount(2) + arcount(2). We need the qd + an counts.
    let _id = p.read_u16()?;
    let _flags = p.read_u16()?;
    let qdcount = p.read_u16()?;
    let ancount = p.read_u16()?;
    let _nscount = p.read_u16()?;
    let _arcount = p.read_u16()?;
    // Skip QUESTION section(s).
    for _ in 0..qdcount {
        p.skip_name()?;
        let _qtype = p.read_u16()?;
        let _qclass = p.read_u16()?;
    }
    // Parse ANSWER section. External audit NET-013 (NN-AUD-332):
    // `ancount` comes off the wire; sized by it, a 12-byte message
    // reserved over a megabyte.
    let mut out = Vec::with_capacity(answer_capacity(ancount, p.remaining()));
    for _ in 0..ancount {
        p.skip_name()?;
        let rtype = p.read_u16()?;
        let _class = p.read_u16()?;
        let _ttl = p.read_u32()?;
        let rdlen = p.read_u16()? as usize;
        let rdata = p.read_bytes(rdlen)?;
        out.push(match rtype {
            DNS_TYPE_A if rdlen == 4 => {
                DnsAnswer::A(Ipv4Addr::new(rdata[0], rdata[1], rdata[2], rdata[3]))
            }
            DNS_TYPE_AAAA if rdlen == 16 => {
                let mut b = [0u8; 16];
                b.copy_from_slice(rdata);
                DnsAnswer::Aaaa(Ipv6Addr::from(b))
            }
            _ => DnsAnswer::Other,
        });
    }
    Some(out)
}

/// The answers `remaining` bytes can hold, at most `ancount`.
fn answer_capacity(ancount: u16, remaining: usize) -> usize {
    usize::from(ancount).min(remaining / DNS_MIN_RR_LEN)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Lab PR 229: a close read before the DNS pump read its process's
    /// query attributed no name (the CI flake of the DNS attribution e2e).
    /// The lookup now waits for a pass of the pump begun after the
    /// record — asked for, as the pump is idle — and finds the name.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_lookup_waits_for_the_query_the_pump_has_not_read_yet() {
        let cache = Arc::new(DnsCache::default());
        let claim = IngestClaim::new(Arc::clone(&cache));
        // the helper's query, still in the ring; then its connect
        let query_ns = monotonic_ns();
        let connect_ns = query_ns + 1_000;
        assert_eq!(
            cache.lookup_for_connect(42, connect_ns, 0),
            None,
            "the race"
        );
        // the DNS pump: idle until asked, then a pass
        let pump = {
            let cache = Arc::clone(&cache);
            tokio::spawn(async move {
                cache.ingest().wanted().await;
                let began = monotonic_ns();
                cache.on_dns_query(42, "foo.example.invalid".into(), 1, STUB, query_ns);
                cache.ingest().pass_ended(began);
            })
        };
        let t0 = std::time::Instant::now();
        assert!(cache.ingest().caught_up(connect_ns).await);
        assert!(t0.elapsed() < INGEST_WAIT, "it did not wait out the bound");
        assert_eq!(
            cache.lookup_for_connect(42, connect_ns, 0).as_deref(),
            Some("foo.example.invalid")
        );
        pump.await.unwrap();
        // a later record of the same instant is covered: no new pass asked
        assert!(cache.ingest().covers(connect_ns));
        drop(claim);
    }

    /// Lab PR 229: the wait is bounded. With no pump it does not wait; a
    /// pump that does not answer is waited for until [`INGEST_WAIT`] after
    /// the record, and a record older than that does not wait at all.
    #[tokio::test]
    async fn the_wait_for_the_pump_is_bounded() {
        let cache = Arc::new(DnsCache::default());
        let t0 = std::time::Instant::now();
        assert!(!cache.ingest().caught_up(monotonic_ns()).await, "no pump");
        assert!(t0.elapsed() < Duration::from_millis(50));

        let claim = IngestClaim::new(Arc::clone(&cache));
        let stale = monotonic_ns() - INGEST_WAIT.as_nanos() as u64 - 1;
        let t0 = std::time::Instant::now();
        assert!(!cache.ingest().caught_up(stale).await, "an old record");
        assert!(t0.elapsed() < Duration::from_millis(50));

        // a stalled pump: the record is 200 ms old, the wait ends ~50 ms on
        let ts = monotonic_ns() - 200_000_000;
        let t0 = std::time::Instant::now();
        assert!(!cache.ingest().caught_up(ts).await);
        let waited = t0.elapsed();
        assert!(
            waited >= Duration::from_millis(30) && waited < INGEST_WAIT,
            "{waited:?}"
        );

        // a pump that stops releases its waiters at once
        let waiter = {
            let cache = Arc::clone(&cache);
            tokio::spawn(async move { cache.ingest().caught_up(monotonic_ns()).await })
        };
        tokio::time::sleep(Duration::from_millis(10)).await;
        let t0 = std::time::Instant::now();
        drop(claim);
        assert!(!waiter.await.unwrap());
        assert!(t0.elapsed() < Duration::from_millis(100));
    }

    /// External audit NET-004: a query flood stays under the global cap,
    /// counted right, and evicts the flooder's queries — not a quiet
    /// process's one recent lookup.
    #[test]
    fn a_query_flood_stays_under_the_global_cap_and_spares_quiet_pids() {
        let c = DnsCache::new(300, DEFAULT_MAX_PER_PID);
        let long = "a".repeat(200);
        c.on_dns_query(7, "quiet.example.com".into(), 1, STUB, 1);
        for pid in 1000..1100u32 {
            for k in 0..DEFAULT_MAX_PER_PID {
                c.on_dns_query(pid, format!("{k}.{long}"), 1, STUB, 2 + k as u64);
            }
        }
        let (counted, held) = c.totals();
        assert_eq!(counted, held);
        assert!(held <= MAX_TOTAL_ENTRIES, "{held}");
        assert_eq!(
            c.lookup_for_connect(7, 5, 0),
            Some("quiet.example.com".into())
        );
    }

    /// The count stays right when stale pids are pruned and when the pid
    /// cap evicts.
    #[test]
    fn the_global_count_follows_every_removal() {
        let c = DnsCache::new(1, 4);
        for pid in 0..10u32 {
            for k in 0..6 {
                c.on_dns_query(pid, format!("n{k}.example"), 1, STUB, 1);
            }
        }
        assert_eq!(c.totals(), (40, 40), "4 per pid kept");
        // two seconds on: the stale pids go at the next prune
        for k in 0..PRUNE_EVERY {
            c.on_dns_query(99, format!("late{k}.example"), 1, STUB, 3_000_000_000);
        }
        let (counted, held) = c.totals();
        assert_eq!(counted, held);
        assert_eq!(held, 4);
    }

    /// External audit NET-005 (NN-AUD-059): a query the pid issued after
    /// the connect must not hide the one before it.
    #[test]
    fn lookup_ignores_queries_issued_after_the_connect() {
        let c = DnsCache::default();
        c.on_dns_query(42, "c2.example".into(), 1, STUB, 10 * ONE_SEC_NS);
        c.on_dns_query(42, "noise.example".into(), 1, STUB, 30 * ONE_SEC_NS);
        assert_eq!(
            c.lookup_for_connect(42, 20 * ONE_SEC_NS, 0).as_deref(),
            Some("c2.example")
        );
        assert_eq!(
            c.lookup_for_connect(42, 31 * ONE_SEC_NS, 0).as_deref(),
            Some("noise.example")
        );
        assert_eq!(c.lookup_for_connect(42, 5 * ONE_SEC_NS, 0), None);
    }

    /// Soak 2026-10-11 regression: one short-lived pid per query must not
    /// grow the forward map forever. After the TTL every dead pid is
    /// gone; the live one survives.
    #[test]
    fn stale_pids_are_pruned_after_ttl() {
        let c = DnsCache::new(300, 1024);
        let sec = 1_000_000_000u64;
        // 2000 distinct pids, one query each, 1 s apart (~33 min span)
        for i in 0..2000u64 {
            c.on_dns_query(10_000 + i as u32, format!("h{i}.example"), 1, STUB, i * sec);
        }
        // every pid older than 300 s is prunable; the opportunistic prune
        // runs every PRUNE_EVERY inserts, so the map is bounded by
        // ~300 live pids + one prune interval
        assert!(
            c.tracked_pids() <= 300 + PRUNE_EVERY as usize,
            "{}",
            c.tracked_pids()
        );
        // a pid whose newest query is within the TTL is still served
        assert_eq!(
            c.lookup_for_connect(10_000 + 1999, 1999 * sec + sec, 0),
            Some("h1999.example".to_string())
        );
        // one well inside the TTL window but pruned by age is gone
        assert_eq!(c.entries_for(10_000), 0);
    }

    /// Many live pids inside the TTL: the hard cap holds and the newest
    /// pids are the survivors.
    #[test]
    fn distinct_pid_cap_evicts_the_oldest() {
        let c = DnsCache::new(300, 1024);
        let ms = 1_000_000u64;
        for i in 0..(DEFAULT_MAX_PIDS as u64 + 1000) {
            c.on_dns_query(
                20_000 + i as u32,
                "same.example".to_string(),
                1,
                STUB,
                i * ms,
            );
        }
        assert!(c.tracked_pids() <= DEFAULT_MAX_PIDS, "{}", c.tracked_pids());
        let newest = 20_000 + DEFAULT_MAX_PIDS as u32 + 999;
        assert_eq!(c.entries_for(newest), 1);
        assert_eq!(c.entries_for(20_000), 0);
    }
    use std::sync::Arc;
    use std::thread;

    const ONE_SEC_NS: u64 = 1_000_000_000;
    /// A local stub resolver (`systemd-resolved`'s listener).
    const STUB: IpAddr = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 53));
    /// An upstream server: where a forwarder's leg, or a direct query, goes.
    const UPSTREAM: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 53));

    /// N4 test #1 — happy-path attribution. A DNS query at T,
    /// connect from the same PID within the 300 s window,
    /// `lookup_for_connect` returns the qname.
    #[test]
    fn dns_cache_resolves_pid_ip_to_domain_within_window() {
        let c = DnsCache::default();
        c.on_dns_query(1234, "example.com".into(), 1, STUB, 1_000 * ONE_SEC_NS);
        assert_eq!(
            c.lookup_for_connect(1234, 1_001 * ONE_SEC_NS, 0).as_deref(),
            Some("example.com")
        );
    }

    /// N4 test #2 — TTL expiry. Query at T, connect at T + 301 s
    /// (1 s past window) → cache miss. The lookup no longer prunes
    /// (external audit NET-005: its `now` is the connect's, in the past);
    /// `prune_pids` does, on inserts.
    #[test]
    fn dns_cache_misses_after_5min_ttl_expiry() {
        let c = DnsCache::default();
        c.on_dns_query(1234, "example.com".into(), 1, STUB, 0);
        let now = (DEFAULT_TTL_SECS + 1) * ONE_SEC_NS;
        assert!(c.lookup_for_connect(1234, now, 0).is_none());
        // a connect inside the window still finds it: the read kept it
        assert_eq!(
            c.lookup_for_connect(1234, ONE_SEC_NS, 0).as_deref(),
            Some("example.com")
        );
    }

    /// N4 test #3 — per-PID FIFO eviction. With cap=3,
    /// 4 successive queries leave the OLDEST one out + the
    /// 3 most-recent in. lookup returns the latest.
    #[test]
    fn dns_cache_evicts_oldest_when_per_pid_capacity_full() {
        let c = DnsCache::new(DEFAULT_TTL_SECS, 3);
        for (i, name) in ["a.com", "b.com", "c.com", "d.com"].iter().enumerate() {
            c.on_dns_query(7, (*name).into(), 1, STUB, (i as u64 + 1) * ONE_SEC_NS);
        }
        assert_eq!(c.entries_for(7), 3, "FIFO must cap at max_per_pid");
        // Most-recent wins.
        assert_eq!(
            c.lookup_for_connect(7, 10 * ONE_SEC_NS, 0).as_deref(),
            Some("d.com")
        );
    }

    /// N4 test #4 — parser extracts A records from a real
    /// DNS response packet (`example.com → 93.184.216.34`).
    /// Wire bytes hand-built per RFC 1035 so the test isn't
    /// dependent on an external resolver.
    #[test]
    fn dns_query_parser_extracts_a_record_responses() {
        let pkt = build_response_a("example.com", Ipv4Addr::new(93, 184, 216, 34));
        let ips = parse_a_records(&pkt);
        assert_eq!(ips, vec![Ipv4Addr::new(93, 184, 216, 34)]);
        // AAAA parser on the same packet returns empty (no
        // AAAA answers).
        assert!(parse_aaaa_records(&pkt).is_empty());
    }

    /// N4 test #5 — parser extracts AAAA records. Same shape
    /// as test #4 with a v6 target.
    #[test]
    fn dns_query_parser_handles_aaaa_v6_responses() {
        let v6 = Ipv6Addr::new(0x2606, 0x2800, 0x220, 0x1, 0x248, 0x1893, 0x25c8, 0x1946);
        let pkt = build_response_aaaa("example.com", v6);
        assert_eq!(parse_aaaa_records(&pkt), vec![v6]);
        assert!(parse_a_records(&pkt).is_empty());
    }

    /// A response for `1.2.3.4` whose question and answer names are
    /// `name_wire` (raw wire bytes, root label included).
    fn response_with_name(name_wire: &[u8]) -> Vec<u8> {
        let mut p = Vec::new();
        write_header(&mut p, 1);
        p.extend_from_slice(name_wire);
        p.extend_from_slice(&1u16.to_be_bytes()); // qtype=A
        p.extend_from_slice(&1u16.to_be_bytes()); // qclass=IN
        p.extend_from_slice(name_wire);
        p.extend_from_slice(&1u16.to_be_bytes()); // type=A
        p.extend_from_slice(&1u16.to_be_bytes()); // class=IN
        p.extend_from_slice(&60u32.to_be_bytes()); // ttl
        p.extend_from_slice(&4u16.to_be_bytes()); // rdlen
        p.extend_from_slice(&[1, 2, 3, 4]);
        p
    }

    /// Wire form of labels of the given lengths (filled with `a`), then
    /// the root label.
    fn name_of_labels(lengths: &[u8]) -> Vec<u8> {
        let mut n = Vec::new();
        for &len in lengths {
            n.push(len);
            n.extend(std::iter::repeat_n(b'a', usize::from(len)));
        }
        n.push(0);
        n
    }

    /// External audit NET-015 (NN-AUD-334): a length octet with the
    /// reserved prefixes `01` and `10` is refused, not read as a label of
    /// up to 191 bytes — the walk would leave the records the resolver
    /// applies. The same packet with a legal label parses.
    #[test]
    fn reserved_label_prefix_is_rejected() {
        let ok = response_with_name(&name_of_labels(&[7, 3]));
        assert_eq!(parse_a_records(&ok), vec![Ipv4Addr::new(1, 2, 3, 4)]);
        for prefix in [0x41u8, 0x7F, 0x80, 0xBF] {
            let name = name_of_labels(&[prefix]);
            let pkt = response_with_name(&name);
            assert!(parse_a_records(&pkt).is_empty(), "{prefix:#04x}");
            assert!(try_parse_answers(&pkt).is_none(), "{prefix:#04x}");
        }
    }

    /// External audit NET-015: a label is at most 63 bytes (64 is the
    /// first value of the reserved `01` prefix) and a name at most 255
    /// octets on the wire.
    #[test]
    fn label_over_63_is_rejected() {
        let max_label = response_with_name(&name_of_labels(&[63]));
        assert_eq!(parse_a_records(&max_label).len(), 1);
        let over = response_with_name(&name_of_labels(&[64]));
        assert!(parse_a_records(&over).is_empty());

        // 3 × (1 + 63) + (1 + 62) + 1 = 256 octets; one byte less is 255.
        let too_long = response_with_name(&name_of_labels(&[63, 63, 63, 62]));
        assert!(parse_a_records(&too_long).is_empty());
        let longest = response_with_name(&name_of_labels(&[63, 63, 63, 61]));
        assert_eq!(parse_a_records(&longest).len(), 1);
    }

    /// A compressed answer name (`0xC00C`, the question's name: the usual
    /// response form) parses; a pointer outside the message does not.
    #[test]
    fn answer_name_pointers_must_point_inside_the_message() {
        let mut pkt = build_response_a("example.com", Ipv4Addr::new(9, 9, 9, 9));
        let answer_at = DNS_HEADER_LEN + "example.com".len() + 2 + 4;
        let rest = pkt.split_off(answer_at + "example.com".len() + 2);
        pkt.truncate(answer_at);
        pkt.extend_from_slice(&[0xC0, 0x0C]);
        pkt.extend_from_slice(&rest);
        assert_eq!(parse_a_records(&pkt), vec![Ipv4Addr::new(9, 9, 9, 9)]);
        pkt[answer_at..answer_at + 2].copy_from_slice(&[0xFF, 0xFF]);
        assert!(parse_a_records(&pkt).is_empty());
    }

    /// External audit NET-013 (NN-AUD-332): the answer vector is sized by
    /// what the message can hold, not by `ancount`. A 12-byte header
    /// claiming 65,535 answers reserves nothing; a short message claiming
    /// them is malformed.
    #[test]
    fn huge_ancount_in_a_short_packet_allocates_little() {
        assert_eq!(answer_capacity(u16::MAX, 0), 0);
        assert_eq!(answer_capacity(u16::MAX, 3 * DNS_MIN_RR_LEN + 10), 3);
        assert_eq!(answer_capacity(2, 4096), 2);

        let mut header_only = vec![0u8; DNS_HEADER_LEN];
        header_only[6..8].copy_from_slice(&u16::MAX.to_be_bytes());
        assert!(parse_a_records(&header_only).is_empty());
        assert!(try_parse_answers(&header_only).is_none());

        let mut one_answer = build_response_a("example.com", Ipv4Addr::new(1, 1, 1, 1));
        one_answer[6..8].copy_from_slice(&u16::MAX.to_be_bytes());
        assert!(parse_a_records(&one_answer).is_empty());
    }

    /// Lab PR 242 (R06 of the Wave 4 restructure): what the reply parser
    /// makes of bytes, pinned on `main` before it moved from the agent to
    /// nn-parse and unchanged after — on the `dns_records` fuzz seeds and
    /// regression the answers each holds, and on a corpus of hostile inputs
    /// (every prefix and mutants of those and of this module's responses) a
    /// SHA-256 over everything each input parses to.
    mod output_pins {
        use super::*;
        use sha2::{Digest as _, Sha256};

        /// The fuzz job's inputs for `dns_records`: a response with A, AAAA
        /// and CNAME answers, the QNAME a sensor copies, and the NN-AUD-185
        /// regression (a dot inside a label).
        const INPUTS: [(&str, &[u8]); 3] = [
            (
                "seeds/response-a-aaaa-cname",
                include_bytes!(concat!(
                    env!("NN_REPO_ROOT"),
                    "/fuzz/seeds/dns_records/response-a-aaaa-cname.bin"
                )),
            ),
            (
                "seeds/sensor-qname-then-type",
                include_bytes!(concat!(
                    env!("NN_REPO_ROOT"),
                    "/fuzz/seeds/dns_records/sensor-qname-then-type.bin"
                )),
            ),
            (
                "regressions/nn-aud-185-dot-inside-label",
                include_bytes!(concat!(
                    env!("NN_REPO_ROOT"),
                    "/fuzz/regressions/dns_records/nn-aud-185-dot-inside-label.bin"
                )),
            ),
        ];

        /// Everything the parser makes of `bytes`: the answers (or the
        /// refusal) and what the two public parsers return.
        fn render(bytes: &[u8]) -> String {
            format!(
                "{:?} a={:?} aaaa={:?}",
                try_parse_answers(bytes),
                parse_a_records(bytes),
                parse_aaaa_records(bytes)
            )
        }

        /// Protects: the fuzz inputs parse to the same answers wherever the
        /// parser lives.
        #[test]
        fn the_fuzz_inputs_parse_to_the_pinned_answers() {
            let want = [
                concat!(
                    "Some([A(93.184.216.34), Aaaa(2606:2800:220:1:248:1893:25c8:1946), Other]) ",
                    "a=[93.184.216.34] aaaa=[2606:2800:220:1:248:1893:25c8:1946]"
                ),
                "None a=[] aaaa=[]",
                "None a=[] aaaa=[]",
            ];
            for ((name, bytes), want) in INPUTS.iter().zip(want) {
                assert_eq!(render(bytes), want, "{name}");
            }
        }

        /// Every prefix of each fuzz input and of this module's responses
        /// (A, AAAA, the longest name, a compressed answer name), then 500
        /// mutants of each: one to four bytes set to 0x00, 0xFF, 0xC0 or a
        /// random value, a third of them then cut short — from a fixed
        /// xorshift stream.
        fn hostile_corpus() -> Vec<Vec<u8>> {
            let mut bases: Vec<Vec<u8>> = INPUTS.iter().map(|(_, b)| b.to_vec()).collect();
            bases.push(build_response_a(
                "example.com",
                Ipv4Addr::new(93, 184, 216, 34),
            ));
            bases.push(build_response_aaaa(
                "example.com",
                Ipv6Addr::new(0x2606, 0x2800, 0x220, 0x1, 0x248, 0x1893, 0x25c8, 0x1946),
            ));
            bases.push(response_with_name(&name_of_labels(&[63, 63, 63, 61])));
            let mut compressed = build_response_a("example.com", Ipv4Addr::new(9, 9, 9, 9));
            let answer_at = DNS_HEADER_LEN + "example.com".len() + 2 + 4;
            let rest = compressed.split_off(answer_at + "example.com".len() + 2);
            compressed.truncate(answer_at);
            compressed.extend_from_slice(&[0xC0, 0x0C]);
            compressed.extend_from_slice(&rest);
            bases.push(compressed);
            let mut state = 0x9E37_79B9_7F4A_7C15u64;
            let mut next = move || {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                state
            };
            let mut out = Vec::new();
            for base in &bases {
                out.extend((0..=base.len()).map(|n| base[..n].to_vec()));
                for _ in 0..500 {
                    let mut m = base.clone();
                    for _ in 0..(1 + next() % 4) {
                        let at = (next() as usize) % m.len();
                        m[at] = match next() % 5 {
                            0 => 0x00,
                            1 => 0xFF,
                            2 => 0xC0,
                            _ => next() as u8,
                        };
                    }
                    if next() % 3 == 0 {
                        let keep = (next() as usize) % m.len();
                        m.truncate(keep);
                    }
                    out.push(m);
                }
            }
            out
        }

        /// Protects: hostile bytes parse to the same answers wherever the
        /// parser lives — the corpus's renderings in order, hashed; the
        /// counts say refusals, empty and non-empty answers are covered.
        #[test]
        fn a_hostile_corpus_parses_to_the_pinned_digest() {
            let mut all = String::new();
            let (mut refused, mut empty, mut answered) = (0usize, 0usize, 0usize);
            for input in hostile_corpus() {
                match try_parse_answers(&input) {
                    None => refused += 1,
                    Some(a) if a.is_empty() => empty += 1,
                    Some(_) => answered += 1,
                }
                all.push_str(&render(&input));
                all.push('\n');
            }
            assert_eq!((refused, empty, answered), (3186, 8, 1160));
            assert_eq!(
                hex::encode(Sha256::digest(all.as_bytes())),
                "f57c8bf29ddfbb0e042c11dac53d985d1bfe32f1abcacbc6ff3e1b63209de873"
            );
        }
    }

    /// N4 test #6 — concurrent insert/lookup is safe. Spawn N
    /// threads, each inserting + looking up for its own PID;
    /// no deadlock + all PIDs eventually resolve. This anchors
    /// the `Arc<DnsCache>` use case.
    #[test]
    fn dns_cache_concurrent_insert_lookup_safe() {
        let c = Arc::new(DnsCache::default());
        let mut handles = Vec::new();
        for pid in 1..=8u32 {
            let c = c.clone();
            handles.push(thread::spawn(move || {
                let name = format!("pid-{pid}.example.com");
                c.on_dns_query(pid, name.clone(), 1, STUB, ONE_SEC_NS);
                let got = c.lookup_for_connect(pid, 2 * ONE_SEC_NS, 0);
                assert_eq!(got.as_deref(), Some(name.as_str()));
            }));
        }
        for h in handles {
            h.join().expect("worker thread panicked");
        }
        assert_eq!(c.tracked_pids(), 8);
    }

    /// N4 test #7 — PIDs don't cross-contaminate. A query
    /// from pid=A must NOT surface in a lookup for pid=B.
    /// Otherwise multi-process hosts (e.g. a browser tab +
    /// a curl) would mis-attribute.
    #[test]
    fn dns_cache_does_not_cross_contaminate_pids() {
        let c = DnsCache::default();
        c.on_dns_query(100, "alice.example.com".into(), 1, STUB, ONE_SEC_NS);
        c.on_dns_query(200, "bob.example.com".into(), 1, STUB, ONE_SEC_NS);
        assert_eq!(
            c.lookup_for_connect(100, 2 * ONE_SEC_NS, 0).as_deref(),
            Some("alice.example.com")
        );
        assert_eq!(
            c.lookup_for_connect(200, 2 * ONE_SEC_NS, 0).as_deref(),
            Some("bob.example.com")
        );
        assert!(c.lookup_for_connect(300, 2 * ONE_SEC_NS, 0).is_none());
    }

    /// N4 test #8 — most-recent qname wins the back-correlation
    /// tie-break. The §6.2 V1.0 heuristic relies on this:
    /// when a single PID issues `cdn.example.com` then
    /// `images.example.com` in quick succession, the
    /// subsequent connect attributes to the LATEST query.
    #[test]
    fn dns_cache_most_recent_query_wins_back_correlation() {
        let c = DnsCache::default();
        c.on_dns_query(42, "cdn.example.com".into(), 1, STUB, ONE_SEC_NS);
        c.on_dns_query(42, "images.example.com".into(), 1, STUB, 2 * ONE_SEC_NS);
        assert_eq!(
            c.lookup_for_connect(42, 3 * ONE_SEC_NS, 0).as_deref(),
            Some("images.example.com")
        );
    }

    // ── FP-3 reverse-index (originator_for) ────────────────────────

    /// FP-3 #1 — forwarded-leg back-correlation. The originator (pid
    /// 1000) issues the qname to the loopback stub; the forwarder (pid
    /// 673) then re-issues the SAME qname upstream. `originator_for`,
    /// excluding the forwarder, returns the originator.
    #[test]
    fn originator_for_back_correlates_forwarded_leg_to_originator() {
        let c = DnsCache::default();
        let q = "ZGVhZGJlZWY.exfil.example.com";
        // Originator's stub query first…
        c.on_dns_query(1000, q.into(), 1, STUB, 1_000 * ONE_SEC_NS);
        // …then the forwarder's upstream leg, microseconds later.
        c.on_dns_query(673, q.into(), 1, UPSTREAM, 1_000 * ONE_SEC_NS + 5_000);
        // Excluding the forwarder, the originator is recovered.
        assert_eq!(
            c.originator_for(q, 1_000 * ONE_SEC_NS + 10_000, 2 * ONE_SEC_NS, 673),
            Some(1000)
        );
    }

    /// FP-3 #2 — no attributable originator. Only the forwarder ever
    /// issued the qname (the Varlink/`nss-resolve` case (C), or a host
    /// acting as a LAN resolver for a remote client). Excluding the
    /// forwarder leaves nothing → `None`, and the caller downgrades to
    /// `Log` rather than killing the resolver.
    #[test]
    fn originator_for_returns_none_when_only_forwarder_issued() {
        let c = DnsCache::default();
        let q = "high-entropy-label.attacker.net";
        c.on_dns_query(673, q.into(), 1, UPSTREAM, 5 * ONE_SEC_NS);
        assert!(c
            .originator_for(q, 5 * ONE_SEC_NS + 1_000, 2 * ONE_SEC_NS, 673)
            .is_none());
    }

    /// FP-3 #3 — the tight window rejects a stale same-qname entry. An
    /// originator's query 10 s in the past must NOT be back-correlated
    /// to a forwarded leg now, because the ≤2 s window has elapsed —
    /// this is the §6.6 stale-attribution guard.
    #[test]
    fn originator_for_ignores_stale_entry_outside_window() {
        let c = DnsCache::default();
        let q = "shared.example.com";
        c.on_dns_query(1000, q.into(), 1, STUB, ONE_SEC_NS);
        // Forward leg now, 10 s later — well outside the 2 s window.
        let now = 11 * ONE_SEC_NS;
        c.on_dns_query(673, q.into(), 1, UPSTREAM, now);
        assert!(c.originator_for(q, now, 2 * ONE_SEC_NS, 673).is_none());
    }

    /// External audit NET-006 (NN-AUD-164): two distinct PIDs asked the
    /// stub for the name inside the window — which one the forwarded leg
    /// came from is unknown, and the newest no longer wins: `None`, and
    /// the caller downgrades to `Log`. One PID asking twice (A + AAAA, a
    /// retry) is still one originator.
    #[test]
    fn ambiguous_originator_downgrades() {
        let c = DnsCache::default();
        let q = "dup.example.com";
        c.on_dns_query(100, q.into(), 1, STUB, ONE_SEC_NS);
        c.on_dns_query(200, q.into(), 1, STUB, ONE_SEC_NS + 500_000);
        c.on_dns_query(673, q.into(), 1, UPSTREAM, ONE_SEC_NS + 600_000);
        assert_eq!(
            c.originator_for(q, 2 * ONE_SEC_NS, 2 * ONE_SEC_NS, 673),
            None
        );

        let one = DnsCache::default();
        one.on_dns_query(100, q.into(), 1, STUB, ONE_SEC_NS);
        one.on_dns_query(100, q.into(), 28, STUB, ONE_SEC_NS + 100_000);
        one.on_dns_query(673, q.into(), 1, UPSTREAM, ONE_SEC_NS + 600_000);
        assert_eq!(
            one.originator_for(q, 2 * ONE_SEC_NS, 2 * ONE_SEC_NS, 673),
            Some(100)
        );
    }

    /// External audit NET-006: DNS names are case-insensitive, and a
    /// forwarder using DNS 0x20 mixes the case of its upstream leg.
    #[test]
    fn originator_ignores_case() {
        let c = DnsCache::default();
        c.on_dns_query(
            1000,
            "zgvhzgjlzwy.exfil.example.com".into(),
            1,
            STUB,
            ONE_SEC_NS,
        );
        let leg = "ZgVhZGjLzWy.ExFiL.eXaMpLe.CoM";
        c.on_dns_query(673, leg.into(), 1, UPSTREAM, ONE_SEC_NS + 5_000);
        assert_eq!(
            c.originator_for(leg, ONE_SEC_NS + 10_000, 2 * ONE_SEC_NS, 673),
            Some(1000)
        );
    }

    /// External audit NET-006: only a query sent to a local stub resolver
    /// can have caused the forwarder's leg. A process that sent the same
    /// name straight upstream is not the originator — and does not make
    /// the stub's one asker ambiguous either.
    #[test]
    fn originator_requires_a_stub_query() {
        let q = "c2.example.com";
        let c = DnsCache::default();
        c.on_dns_query(1000, q.into(), 1, UPSTREAM, ONE_SEC_NS);
        c.on_dns_query(673, q.into(), 1, UPSTREAM, ONE_SEC_NS + 5_000);
        assert_eq!(
            c.originator_for(q, ONE_SEC_NS + 10_000, 2 * ONE_SEC_NS, 673),
            None
        );

        // the stub's asker is named; the direct one beside it does not count
        let c = DnsCache::default();
        c.on_dns_query(1000, q.into(), 1, STUB, ONE_SEC_NS);
        c.on_dns_query(2000, q.into(), 1, UPSTREAM, ONE_SEC_NS + 1_000);
        c.on_dns_query(673, q.into(), 1, UPSTREAM, ONE_SEC_NS + 5_000);
        assert_eq!(
            c.originator_for(q, ONE_SEC_NS + 10_000, 2 * ONE_SEC_NS, 673),
            Some(1000)
        );

        // every loopback address is a local stub: 127.0.0.0/8, ::1 and the
        // IPv4-mapped form
        for stub in ["127.0.0.1", "127.0.0.54", "::1", "::ffff:127.0.0.53"] {
            let c = DnsCache::default();
            c.on_dns_query(1000, q.into(), 1, stub.parse().unwrap(), ONE_SEC_NS);
            assert_eq!(
                c.originator_for(q, ONE_SEC_NS + 10_000, 2 * ONE_SEC_NS, 673),
                Some(1000),
                "{stub}"
            );
        }
    }

    // ── External audit NET-016 (NN-AUD-167): the PID's holder ───────

    /// The process that asked for `old.onion` exited and its PID went to
    /// another process, which connects to an address it never resolved:
    /// the connect is not attributed the previous holder's name. A query
    /// the new holder made itself is.
    #[test]
    fn a_recycled_pid_does_not_inherit_queries() {
        let c = DnsCache::default();
        // previous holder of pid 4242
        c.on_dns_query(4242, "old.onion".into(), 1, UPSTREAM, 10 * ONE_SEC_NS);
        // the new holder started at 40 s and connects at 50 s
        let new_start = 40 * ONE_SEC_NS;
        assert_eq!(c.lookup_for_connect(4242, 50 * ONE_SEC_NS, new_start), None);
        // its own query is its own
        c.on_dns_query(4242, "own.example".into(), 1, STUB, 45 * ONE_SEC_NS);
        assert_eq!(
            c.lookup_for_connect(4242, 50 * ONE_SEC_NS, new_start)
                .as_deref(),
            Some("own.example")
        );
        // the previous holder's own connect (before the new start) still
        // gets its name: the start passed is that process's
        assert_eq!(
            c.lookup_for_connect(4242, 11 * ONE_SEC_NS, 5 * ONE_SEC_NS)
                .as_deref(),
            Some("old.onion")
        );
    }

    /// A query made at the start itself is the process's (a bound below
    /// the start is what the caller passes); a start unknown (0) leaves
    /// the PID alone to decide, as before.
    #[test]
    fn a_query_at_the_start_counts_and_an_unknown_start_falls_back() {
        let c = DnsCache::default();
        c.on_dns_query(7, "x.example".into(), 1, STUB, 40 * ONE_SEC_NS);
        assert_eq!(
            c.lookup_for_connect(7, 41 * ONE_SEC_NS, 40 * ONE_SEC_NS)
                .as_deref(),
            Some("x.example")
        );
        assert_eq!(
            c.lookup_for_connect(7, 41 * ONE_SEC_NS, 0).as_deref(),
            Some("x.example")
        );
    }

    // ── DNS wire-format test helpers ───────────────────────────────

    /// Build a minimal DNS response packet containing one A
    /// record for `qname` → `ip`. RFC 1035 wire format:
    /// header(12) + question + answer.
    fn build_response_a(qname: &str, ip: Ipv4Addr) -> Vec<u8> {
        let mut p = Vec::new();
        write_header(&mut p, 1);
        write_name(&mut p, qname);
        p.extend_from_slice(&1u16.to_be_bytes()); // qtype=A
        p.extend_from_slice(&1u16.to_be_bytes()); // qclass=IN
                                                  // Answer
        write_name(&mut p, qname);
        p.extend_from_slice(&1u16.to_be_bytes()); // type=A
        p.extend_from_slice(&1u16.to_be_bytes()); // class=IN
        p.extend_from_slice(&60u32.to_be_bytes()); // ttl
        p.extend_from_slice(&4u16.to_be_bytes()); // rdlen
        p.extend_from_slice(&ip.octets());
        p
    }

    /// Same as [`build_response_a`] but emits a single AAAA
    /// (qtype=28) answer.
    fn build_response_aaaa(qname: &str, ip: Ipv6Addr) -> Vec<u8> {
        let mut p = Vec::new();
        write_header(&mut p, 1);
        write_name(&mut p, qname);
        p.extend_from_slice(&28u16.to_be_bytes()); // qtype=AAAA
        p.extend_from_slice(&1u16.to_be_bytes()); // qclass=IN
        write_name(&mut p, qname);
        p.extend_from_slice(&28u16.to_be_bytes()); // type=AAAA
        p.extend_from_slice(&1u16.to_be_bytes()); // class=IN
        p.extend_from_slice(&60u32.to_be_bytes()); // ttl
        p.extend_from_slice(&16u16.to_be_bytes()); // rdlen
        p.extend_from_slice(&ip.octets());
        p
    }

    /// DNS header: id=0, flags=0x8180 (standard query response,
    /// no error), 1 question, `ancount` answers, 0 ns, 0 ar.
    fn write_header(p: &mut Vec<u8>, ancount: u16) {
        p.extend_from_slice(&0u16.to_be_bytes()); // id
        p.extend_from_slice(&0x8180u16.to_be_bytes()); // flags
        p.extend_from_slice(&1u16.to_be_bytes()); // qdcount
        p.extend_from_slice(&ancount.to_be_bytes()); // ancount
        p.extend_from_slice(&0u16.to_be_bytes()); // nscount
        p.extend_from_slice(&0u16.to_be_bytes()); // arcount
    }

    /// Encode a domain name as a sequence of length-prefixed
    /// labels terminated by a zero byte. No compression — the
    /// parser handles pointer-form names too but the test
    /// fixtures emit fully-spelled-out names so the wire bytes
    /// are dead-simple to reason about.
    fn write_name(p: &mut Vec<u8>, name: &str) {
        for label in name.split('.') {
            p.push(label.len() as u8);
            p.extend_from_slice(label.as_bytes());
        }
        p.push(0);
    }
}
