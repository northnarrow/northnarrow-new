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
use std::net::IpAddr;
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

// ── DNS reply parser (nn-parse) ─────────────────────────────────────
//
// R06 of the Wave 4 restructure (lab PR 242): the reply parser and its
// tests moved to nn-parse's `dns_records`. Re-exported here for the paths
// the fuzz targets and `fuzz_api` name (until R17).
pub use nn_parse::dns_records::{parse_a_records, parse_aaaa_records};

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

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
}
