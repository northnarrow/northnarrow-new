//! Lab PR 229: the DNS pump's ingest — how far it has read the
//! `DNS_QUERY_EVENTS` ring, and how a lookup waits for the queries made
//! before the record it attributes (tokio's `Notify`, `CLOCK_MONOTONIC`).
//!
//! R08b (lab PR 251): cut verbatim from `net::dns_cache` when the cache's
//! state moved to nn-core with the rules that read it. The agent's
//! `net::dns_cache::DnsCache` is nn-core's cache carrying this ingest
//! ([`DnsIngest`]); the pump marks its passes on it, the net drain waits on
//! it, as before.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::Notify;

use crate::net::dns_cache::DnsCache;

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
        cache.ingest().pump.store(true, Ordering::Release);
        Self(cache)
    }
}

impl Drop for IngestClaim {
    fn drop(&mut self) {
        self.0.ingest().pump.store(false, Ordering::Release);
        self.0.ingest().passed.notify_waiters();
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

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use super::*;

    /// A local stub resolver (`systemd-resolved`'s listener).
    const STUB: IpAddr = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 53));

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
}
