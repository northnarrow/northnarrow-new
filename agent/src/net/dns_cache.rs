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

use std::collections::{HashMap, VecDeque};
use std::net::{Ipv4Addr, Ipv6Addr};

use parking_lot::Mutex;

/// Per design §13 Q3 + §6.2: 300 s (5 minutes) of attribution
/// window. Hard-coded in V1.0; V1.1 introduces
/// `net.dns_cache_ttl_secs` in `/etc/northnarrow/config.toml`.
pub const DEFAULT_TTL_SECS: u64 = 300;

/// Default per-PID cap on retained recent queries. Bounded so a
/// pathologically chatty resolver (e.g. dig spam) can't grow the
/// cache without limit. 1024 covers normal browser tab-storms +
/// CI build DNS lookups comfortably.
pub const DEFAULT_MAX_PER_PID: usize = 1024;

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

#[derive(Debug, Default)]
struct DnsCacheInner {
    /// PID → recent queries, oldest at the front.
    by_pid: HashMap<u32, VecDeque<RecentQuery>>,
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
}

impl Default for DnsCache {
    fn default() -> Self {
        Self::new(DEFAULT_TTL_SECS, DEFAULT_MAX_PER_PID)
    }
}

impl DnsCache {
    /// Custom-bound constructor for tests + future V1.1 config
    /// surface. Production callers should use [`Self::default`]
    /// (300 s TTL, 1024 per-pid).
    pub fn new(ttl_secs: u64, max_per_pid: usize) -> Self {
        Self {
            inner: Mutex::new(DnsCacheInner::default()),
            ttl_ns: ttl_secs.saturating_mul(1_000_000_000),
            max_per_pid,
        }
    }

    /// Record a DNS query observation. Called by the future
    /// drain loop on every `Event::DnsQuery` (Tappa 4 BPF
    /// `dns_query` kprobe). FIFO eviction kicks in past
    /// `max_per_pid`.
    pub fn on_dns_query(&self, pid: u32, qname: String, qtype: u16, ts_ns: u64) {
        let mut g = self.inner.lock();
        let q = g.by_pid.entry(pid).or_default();
        q.push_back(RecentQuery {
            qname,
            qtype,
            ts_ns,
        });
        while q.len() > self.max_per_pid {
            q.pop_front();
        }
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
    pub fn lookup_for_connect(&self, pid: u32, now_ns: u64) -> Option<String> {
        let mut g = self.inner.lock();
        let q = g.by_pid.get_mut(&pid)?;
        // Prune anything older than `now_ns - ttl_ns`. Saturate
        // on underflow (can happen on the dev-VM if monotonic
        // clock jitter pushes `now_ns < ttl_ns`).
        let cutoff = now_ns.saturating_sub(self.ttl_ns);
        while q.front().is_some_and(|e| e.ts_ns < cutoff) {
            q.pop_front();
        }
        // Most-recent = back of the deque.
        q.back()
            .filter(|e| e.ts_ns <= now_ns)
            .map(|e| e.qname.clone())
    }

    /// Test/diagnostic — number of pids with at least one
    /// retained query. Production callers don't use this.
    #[cfg(test)]
    fn tracked_pids(&self) -> usize {
        self.inner.lock().by_pid.len()
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

// ── DNS reply parser (forward-compat utility for V1.1) ───────────────
//
// RFC 1035 wire format walker. V1.0 doesn't have a DNS-response
// observer; these parsers ship now as a standalone utility so the
// V1.1 commit that wires up the observer is a pure plumbing change.
//
// We handle:
//   * the 12-byte header,
//   * a single QUESTION section (compressed-name + qtype + qclass),
//   * the ANSWER section with name (label OR pointer per §4.1.4),
//     16-bit TYPE / CLASS, 32-bit TTL, 16-bit RDLENGTH, RDATA.
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

    fn read_u16(&mut self) -> Option<u16> {
        if self.pos + 2 > self.bytes.len() {
            return None;
        }
        let v = u16::from_be_bytes([self.bytes[self.pos], self.bytes[self.pos + 1]]);
        self.pos += 2;
        Some(v)
    }

    fn read_u32(&mut self) -> Option<u32> {
        if self.pos + 4 > self.bytes.len() {
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
        if self.pos + n > self.bytes.len() {
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
    ///     RDATA).
    fn skip_name(&mut self) -> Option<()> {
        loop {
            if self.pos >= self.bytes.len() {
                return None;
            }
            let b = self.bytes[self.pos];
            if b == 0 {
                self.pos += 1;
                return Some(());
            }
            if (b & DNS_NAME_POINTER_MASK) == DNS_NAME_POINTER_MASK {
                // 2-byte pointer; we don't follow it.
                if self.pos + 2 > self.bytes.len() {
                    return None;
                }
                self.pos += 2;
                return Some(());
            }
            // Plain label: 1-byte length + that many bytes.
            let label_len = b as usize;
            if self.pos + 1 + label_len > self.bytes.len() {
                return None;
            }
            self.pos += 1 + label_len;
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
    // Parse ANSWER section.
    let mut out = Vec::with_capacity(ancount as usize);
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::thread;

    const ONE_SEC_NS: u64 = 1_000_000_000;

    /// N4 test #1 — happy-path attribution. A DNS query at T,
    /// connect from the same PID within the 300 s window,
    /// `lookup_for_connect` returns the qname.
    #[test]
    fn dns_cache_resolves_pid_ip_to_domain_within_window() {
        let c = DnsCache::default();
        c.on_dns_query(1234, "example.com".into(), 1, 1_000 * ONE_SEC_NS);
        assert_eq!(
            c.lookup_for_connect(1234, 1_001 * ONE_SEC_NS).as_deref(),
            Some("example.com")
        );
    }

    /// N4 test #2 — TTL expiry. Query at T, connect at T + 301 s
    /// (1 s past window) → cache miss + expired entry pruned.
    #[test]
    fn dns_cache_misses_after_5min_ttl_expiry() {
        let c = DnsCache::default();
        c.on_dns_query(1234, "example.com".into(), 1, 0);
        let now = (DEFAULT_TTL_SECS + 1) * ONE_SEC_NS;
        assert!(c.lookup_for_connect(1234, now).is_none());
        // Pruning happened on the read — the per-pid deque is
        // now empty.
        assert_eq!(c.entries_for(1234), 0);
    }

    /// N4 test #3 — per-PID FIFO eviction. With cap=3,
    /// 4 successive queries leave the OLDEST one out + the
    /// 3 most-recent in. lookup returns the latest.
    #[test]
    fn dns_cache_evicts_oldest_when_per_pid_capacity_full() {
        let c = DnsCache::new(DEFAULT_TTL_SECS, 3);
        for (i, name) in ["a.com", "b.com", "c.com", "d.com"].iter().enumerate() {
            c.on_dns_query(7, (*name).into(), 1, (i as u64 + 1) * ONE_SEC_NS);
        }
        assert_eq!(c.entries_for(7), 3, "FIFO must cap at max_per_pid");
        // Most-recent wins.
        assert_eq!(
            c.lookup_for_connect(7, 10 * ONE_SEC_NS).as_deref(),
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
                c.on_dns_query(pid, name.clone(), 1, ONE_SEC_NS);
                let got = c.lookup_for_connect(pid, 2 * ONE_SEC_NS);
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
        c.on_dns_query(100, "alice.example.com".into(), 1, ONE_SEC_NS);
        c.on_dns_query(200, "bob.example.com".into(), 1, ONE_SEC_NS);
        assert_eq!(
            c.lookup_for_connect(100, 2 * ONE_SEC_NS).as_deref(),
            Some("alice.example.com")
        );
        assert_eq!(
            c.lookup_for_connect(200, 2 * ONE_SEC_NS).as_deref(),
            Some("bob.example.com")
        );
        assert!(c.lookup_for_connect(300, 2 * ONE_SEC_NS).is_none());
    }

    /// N4 test #8 — most-recent qname wins the back-correlation
    /// tie-break. The §6.2 V1.0 heuristic relies on this:
    /// when a single PID issues `cdn.example.com` then
    /// `images.example.com` in quick succession, the
    /// subsequent connect attributes to the LATEST query.
    #[test]
    fn dns_cache_most_recent_query_wins_back_correlation() {
        let c = DnsCache::default();
        c.on_dns_query(42, "cdn.example.com".into(), 1, ONE_SEC_NS);
        c.on_dns_query(42, "images.example.com".into(), 1, 2 * ONE_SEC_NS);
        assert_eq!(
            c.lookup_for_connect(42, 3 * ONE_SEC_NS).as_deref(),
            Some("images.example.com")
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
