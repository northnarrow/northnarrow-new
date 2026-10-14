//! Tappa 10 (N6) + Tappa 10.5 (D4) — Network Observability
//! detection rules NN-L-NET-001..019.
//!
//! Tappa 10 N6 shipped 9 rules (001..009). Tappa 10.5 D4 adds 5
//! (010 high-risk C2 port, 011 plaintext-cred service, 013 stateful
//! beacon detector, 018 RFC1918 lateral-movement port, 019
//! wildcard-bind listener) and switches the comm-gated rules off
//! their former inline `const` allowlists onto the shared per-family
//! `netflow-comm-allowlist` (§13 Q3). Tappa 4.1 un-gates NN-L-NET-014
//! (DNS-tunnel entropy) now the DNS observability refit populates the
//! QNAME; NN-L-NET-015 (fast-flux) stays gated — it needs DNS-response
//! observation (a separate V1.1 sensor), not just the query-path refit.
//!
//! Rules consume `Event::NetFlow` / `Event::NetListener` /
//! `Event::DnsQuery`. Tappa 10 N6 severity + action mapping verbatim
//! from design §7:
//!
//! | ID  | Severity | Action                | Source event       |
//! |---- |----------|-----------------------|--------------------|
//! | 001 | Critical | KillProcessTree+COMBAT| NetFlow            |
//! | 002 | High     | KillProcess + ENGAGED | NetFlow            |
//! | 003 | Critical | KillProcessTree+COMBAT| NetFlow            |
//! | 004 | High     | KillProcess + ENGAGED | DnsQuery           |
//! | 005 | High     | ENGAGED + log         | DnsQuery (window)  |
//! | 006 | Medium   | ALERTED               | NetListener        |
//! | 007 | Medium   | ALERTED               | NetFlow            |
//! | 008 | High     | KillProcess + ENGAGED | NetFlow            |
//! | 009 | High     | ENGAGED + log         | NetFlow            |
//!
//! ## Critical-rate-limit lock-in (§13 Q4)
//!
//! NN-L-NET-001 + NN-L-NET-003 are tagged Critical with the
//! "never throttled by the NetFlow rate limiter" invariant.
//! The decision engine's bucketing path (§6.5, future commit)
//! consults [`Rule::category`] for the tier; rules in the
//! `"net_critical"` category bypass the bucket.
//!
//! ## State-bearing rules
//!
//! Most rules are pure functions of the event. Three carry state:
//!
//! - NN-L-NET-001 holds an `Arc<NetBlocklist>` (operator-loaded
//!   IP/CIDR list).
//! - NN-L-NET-003 holds an `Arc<Ja3Blocklist>` (operator-loaded
//!   JA3 hashes).
//! - NN-L-NET-005 holds an `Arc<Mutex<DnsBurstWindow>>` (per-PID
//!   rolling 60s counter of TXT/NULL queries).
//!
//! All three take `&self` everywhere (interior mutability via
//! `Mutex` for -005). [`net_rules`] takes the shared state as
//! parameters; the default factory [`net_rules_empty`] supplies
//! empty blocklists + a fresh burst window for boot + tests.

use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;
use std::sync::Arc;

use common::{Event, ResponseAction, Severity, Verdict};
use parking_lot::Mutex;

use crate::config::comm_allowlist::{CommAllowlist, Judgement};
use crate::decision::Rule;
use crate::net::blocklist::{Ja3Blocklist, NetBlocklist};
use crate::net::dns_cache::DnsCache;

// ── Category tags ────────────────────────────────────────────────────

/// Critical-tier NetFlow rules — NEVER throttled by the §6.5
/// rate limiter per §13 Q4 lock-in. The future bucket-aware
/// emitter checks for this category string.
pub const CATEGORY_CRITICAL: &str = "net_critical";
/// High-tier NetFlow rules — subject to the 200/min bucket.
pub const CATEGORY_HIGH: &str = "net_high";
/// Medium-tier NetFlow rules — subject to the 1000/min bucket.
pub const CATEGORY_MEDIUM: &str = "net_medium";

// ── Operator comm allowlist (per-family, §13 Q3) ─────────────────────
//
// Tappa 10.5 D4 switch-over: the comm-gated net rules
// (NN-L-NET-006/007/009 + the D4 additions -010/-011/-013/-018/-019)
// no longer carry per-rule inline `const` allowlists. They share the
// ONE per-family `netflow-comm-allowlist` (design §13 Q3) threaded in
// as an `Arc<CommAllowlist>` (loaded by `main.rs` from
// `/etc/northnarrow/netflow-comm-allowlist.{v1,local}` via the D1
// loader). [`NETFLOW_COMM_ALLOWLIST_DEFAULTS`] below is the in-code
// mirror of the shipped `configs/netflow-comm-allowlist.v1` — the
// UNION of the three former inline sets (LISTENER + RFC1918 +
// HIGH_VOLUME). It seeds [`net_rules_empty`] (boot-before-load +
// tests) so behaviour is preserved: every comm previously exempt for
// any single rule stays exempt for the family. Per §13 Q3, rules that
// need finer scope encode it in their predicate, not in a separate
// file.

/// In-code mirror of the shipped `configs/netflow-comm-allowlist.v1`
/// (the union of the former per-rule inline sets). Used to seed the
/// allowlist for [`net_rules_empty`] + tests; production reads the
/// on-disk file via the D1 loader.
pub const NETFLOW_COMM_ALLOWLIST_DEFAULTS: &[&str] = &[
    "apache2",
    "apt",
    "chronyd",
    "containerd",
    "curl",
    "dnf",
    "dnsmasq",
    "dockerd",
    "git",
    "httpd",
    "kubelet",
    "nginx",
    "node_exporter",
    "ntpd",
    "ping",
    "podman",
    "rsync",
    "scp",
    "ssh",
    "sshd",
    "systemd-network",
    "systemd-resolve",
    "wget",
    "yum",
];

/// Common-ports allowlist for NN-L-NET-006 / -019: a listener on any
/// of these ports is NEVER flagged regardless of comm.
const LISTENER_COMMON_PORTS: &[u16] = &[22, 53, 80, 443, 8080, 8443];

/// Blocked TLD list for NN-L-NET-002. Hard-coded V1.0 set;
/// operator-tunable in V1.1.
const BLOCKED_TLDS: &[&str] = &[".onion", ".bit"];

/// NN-L-NET-008 — dst_port whitelist (DNS-only path is the
/// LEGITIMATE outbound from /tmp/ — a dropper resolving
/// alongside its own DNS-tunneling). All other ports trip.
const TMP_EXEC_ALLOWED_PORTS: &[u16] = &[53];

/// NN-L-NET-009 — byte-count threshold for "anomalously
/// large flow." 100 MiB = 104_857_600 bytes.
const HIGH_VOLUME_BYTES_SENT: u64 = 100 * 1024 * 1024;

// ── Tappa 10.5 D4 port sets ──────────────────────────────────────────

/// NN-L-NET-010 — high-risk C2 / tooling default ports. A flow to
/// one of these from a non-allowlisted comm is a strong C2 indicator
/// (T1571 Non-Standard Port). 4444 Metasploit default, 1080 SOCKS,
/// 6667/6697 IRC (classic botnet C2), 9001 Tor OR.
const HIGH_RISK_C2_PORTS: &[u16] = &[4444, 1080, 6667, 6697, 9001];

/// NN-L-NET-011 — plaintext-credential service ports: FTP (21) +
/// Telnet (23). Both transmit credentials in the clear (T1071).
const PLAINTEXT_CRED_PORTS: &[u16] = &[21, 23];

/// NN-L-NET-018 — lateral-movement service ports reached over an
/// internal RFC1918 destination: 445 SMB, 3389 RDP, 5985 WinRM,
/// 5900 VNC (T1021 Remote Services).
const LATERAL_MOVEMENT_PORTS: &[u16] = &[445, 3389, 5985, 5900];

// ── DNS qtypes (RFC 1035 + RFC 4034) ─────────────────────────────────

const DNS_QTYPE_TXT: u16 = 16;
const DNS_QTYPE_NULL: u16 = 10;

// ── NN-L-NET-005 burst-window state ──────────────────────────────────

/// Sliding window for NN-L-NET-005.
const DNS_BURST_WINDOW_NS: u64 = 60 * 1_000_000_000;

/// Idle-key eviction cadence for the stateful windows below. The
/// per-key `VecDeque`s are trimmed on every observe, but the OUTER
/// map only ever gained keys (one per PID / per `(pid, dst)` flow):
/// on a long-lived agent that is unbounded growth (audit
/// `catchall-1`). Every N observes — or as soon as the map exceeds
/// `STATEFUL_MAP_SOFT_CAP` keys — drop every key whose newest sample
/// has already fallen out of its window. Amortised O(1) per observe.
const STATEFUL_EVICT_EVERY: u32 = 256;
const STATEFUL_MAP_SOFT_CAP: usize = 4096;

/// Drop every key whose most recent sample is older than `cutoff`.
fn evict_idle_keys<K>(map: &mut HashMap<K, VecDeque<u64>>, cutoff: u64) {
    map.retain(|_, q| q.back().is_some_and(|&t| t >= cutoff));
}

/// 60-second per-PID TXT/NULL query counter. NN-L-NET-005 fires
/// when `count > 50` for a given PID over a sliding 60s window.
#[derive(Debug, Default)]
pub struct DnsBurstWindow {
    per_pid: HashMap<u32, VecDeque<u64>>,
    observes: u32,
}

impl DnsBurstWindow {
    pub fn new() -> Self {
        Self::default()
    }

    /// Observe one TXT/NULL query. Returns the count of queries
    /// from `pid` still within the 60s window AFTER this insert.
    pub fn observe(&mut self, pid: u32, ts_ns: u64) -> usize {
        let cutoff = ts_ns.saturating_sub(DNS_BURST_WINDOW_NS);
        self.observes = self.observes.wrapping_add(1);
        if self.observes % STATEFUL_EVICT_EVERY == 0 || self.per_pid.len() > STATEFUL_MAP_SOFT_CAP {
            evict_idle_keys(&mut self.per_pid, cutoff);
        }
        let q = self.per_pid.entry(pid).or_default();
        while q.front().is_some_and(|&t| t < cutoff) {
            q.pop_front();
        }
        q.push_back(ts_ns);
        q.len()
    }

    /// Number of PIDs currently tracked (test/metrics hook).
    pub fn tracked_keys(&self) -> usize {
        self.per_pid.len()
    }
}

// ── NN-L-NET-013 beacon-timing state ─────────────────────────────────

/// Keep at most the last N flow-start timestamps per `(pid,
/// dst_addr)` so the beacon detector can measure inter-arrival
/// regularity without unbounded growth.
const BEACON_MAX_SAMPLES: usize = 8;
/// Need at least this many flows (→ `BEACON_MIN_SAMPLES - 1`
/// intervals) before judging periodicity. 4 flows = 3 intervals.
const BEACON_MIN_SAMPLES: usize = 4;
/// Drop samples older than this so a long-idle pair doesn't blend
/// stale timings into a fresh burst (1 hour).
const BEACON_WINDOW_NS: u64 = 3600 * 1_000_000_000;
/// Ignore sub-second inter-arrival means — that's chatty
/// connection churn (e.g. a connection-per-request HTTP client),
/// not a periodic beacon.
const BEACON_MIN_MEAN_INTERVAL_NS: f64 = 1_000_000_000.0;
/// Low-jitter threshold: a coefficient of variation
/// (stddev / mean of the intervals) at or below this is "regular
/// enough" to call a beacon. A cron job with a randomised sleep or
/// human-driven traffic sits well above this.
const BEACON_MAX_CV: f64 = 0.15;

/// Per-`(pid, dst_addr)` sliding window of recent flow-start
/// timestamps. NN-L-NET-013 calls [`BeaconWindow::observe`] on each
/// outbound flow; it returns `true` when the inter-arrival pattern
/// for that pair is periodic with low jitter (classic C2 beacon).
/// Mirrors the [`DnsBurstWindow`] stateful-rule precedent (design
/// §3.5-A): `&mut self` behind an `Arc<Mutex<_>>` shared by the
/// single rule instance.
#[derive(Debug, Default)]
pub struct BeaconWindow {
    per_flow: HashMap<(u32, IpAddr), VecDeque<u64>>,
    observes: u32,
}

impl BeaconWindow {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record an outbound flow start for `(pid, dst)` at `ts_ns` and
    /// report whether the pair now exhibits a low-jitter periodic
    /// pattern. Returns `false` until at least [`BEACON_MIN_SAMPLES`]
    /// flows have accumulated within [`BEACON_WINDOW_NS`].
    pub fn observe(&mut self, pid: u32, dst: IpAddr, ts_ns: u64) -> bool {
        let cutoff = ts_ns.saturating_sub(BEACON_WINDOW_NS);
        self.observes = self.observes.wrapping_add(1);
        if self.observes % STATEFUL_EVICT_EVERY == 0 || self.per_flow.len() > STATEFUL_MAP_SOFT_CAP
        {
            evict_idle_keys(&mut self.per_flow, cutoff);
        }
        let q = self.per_flow.entry((pid, dst)).or_default();
        while q.front().is_some_and(|&t| t < cutoff) {
            q.pop_front();
        }
        q.push_back(ts_ns);
        while q.len() > BEACON_MAX_SAMPLES {
            q.pop_front();
        }
        if q.len() < BEACON_MIN_SAMPLES {
            return false;
        }
        Self::is_periodic(q)
    }

    /// Number of `(pid, dst)` flows currently tracked (test/metrics hook).
    pub fn tracked_keys(&self) -> usize {
        self.per_flow.len()
    }

    /// Low-jitter test over consecutive inter-arrival intervals:
    /// mean above the chatter floor AND coefficient of variation
    /// (stddev / mean) at or below [`BEACON_MAX_CV`].
    fn is_periodic(samples: &VecDeque<u64>) -> bool {
        let intervals: Vec<f64> = samples
            .iter()
            .zip(samples.iter().skip(1))
            .map(|(a, b)| b.saturating_sub(*a) as f64)
            .collect();
        if intervals.is_empty() {
            return false;
        }
        let n = intervals.len() as f64;
        let mean = intervals.iter().sum::<f64>() / n;
        if mean < BEACON_MIN_MEAN_INTERVAL_NS {
            return false;
        }
        let variance = intervals.iter().map(|x| (x - mean).powi(2)).sum::<f64>() / n;
        let cv = variance.sqrt() / mean;
        cv <= BEACON_MAX_CV
    }
}

// ── Common verdict helpers ───────────────────────────────────────────

fn net_verdict(
    rule: &dyn Rule,
    action: ResponseAction,
    severity: Severity,
    reasoning: &str,
    event_pid: u32,
    event_filename: String,
    timestamp_ns: u64,
) -> Verdict {
    Verdict {
        rule_id: rule.id().to_string(),
        rule_name: rule.name().to_string(),
        category: rule.category().to_string(),
        action,
        severity,
        reasoning: reasoning.to_string(),
        event_pid,
        event_filename,
        timestamp_ns,
    }
}

// ── NN-L-NET-001 — Outbound to blocked IP/CIDR ───────────────────────

/// Outbound to operator-blocked IP/CIDR — design §7. Critical
/// + KillProcessTree + posture→COMBAT. NEVER throttled per Q4.
pub struct NnLNet001OutboundToBlockedIp {
    blocklist: Arc<NetBlocklist>,
}

impl NnLNet001OutboundToBlockedIp {
    pub fn new(blocklist: Arc<NetBlocklist>) -> Self {
        Self { blocklist }
    }
}

impl Rule for NnLNet001OutboundToBlockedIp {
    fn id(&self) -> &'static str {
        "NN-L-NET-001_OutboundToBlockedIp"
    }
    fn name(&self) -> &'static str {
        "Outbound to operator-blocked IP/CIDR"
    }
    fn category(&self) -> &'static str {
        CATEGORY_CRITICAL
    }
    fn evaluate(&self, event: &Event) -> Option<Verdict> {
        let Event::NetFlow(nf) = event else {
            return None;
        };
        if !self.blocklist.contains(&nf.dst_addr) {
            return None;
        }
        Some(net_verdict(
            self,
            ResponseAction::KillProcessTree,
            Severity::Critical,
            "Outbound flow to operator-blocked IP/CIDR — \
             kill the process tree + posture → COMBAT",
            nf.pid,
            nf.comm.clone(),
            nf.start_ns,
        ))
    }
}

// ── NN-L-NET-002 — Outbound to blocked TLD ───────────────────────────

/// Outbound to a blocked TLD (`.onion`, `.bit`). The qname comes
/// via N4 DNS attribution (`NetFlowEvent.resolved_hostname`). If
/// the connection went to an IP literal OR the DNS cache missed,
/// the rule can't fire — there's no hostname to inspect.
pub struct NnLNet002OutboundToBlockedTld;

impl Rule for NnLNet002OutboundToBlockedTld {
    fn id(&self) -> &'static str {
        "NN-L-NET-002_OutboundToBlockedTld"
    }
    fn name(&self) -> &'static str {
        "Outbound to operator-blocked TLD"
    }
    fn category(&self) -> &'static str {
        CATEGORY_HIGH
    }
    fn evaluate(&self, event: &Event) -> Option<Verdict> {
        let Event::NetFlow(nf) = event else {
            return None;
        };
        let host = nf.resolved_hostname.as_deref()?;
        let host_lower = host.to_ascii_lowercase();
        let matched = BLOCKED_TLDS.iter().any(|tld| host_lower.ends_with(tld));
        if !matched {
            return None;
        }
        Some(net_verdict(
            self,
            ResponseAction::KillProcess,
            Severity::High,
            "Outbound DNS resolution to a blocked TLD — \
             kill the connecting process + posture → ENGAGED",
            nf.pid,
            nf.comm.clone(),
            nf.start_ns,
        ))
    }
}

// ── NN-L-NET-003 — JA3 threat-actor match ────────────────────────────

/// JA3 hash matches an operator-curated threat-actor blocklist.
/// Critical + KillProcessTree + posture→COMBAT. NEVER throttled
/// per Q4 (documented C2 indicator).
pub struct NnLNet003BadJa3 {
    blocklist: Arc<Ja3Blocklist>,
}

impl NnLNet003BadJa3 {
    pub fn new(blocklist: Arc<Ja3Blocklist>) -> Self {
        Self { blocklist }
    }
}

impl Rule for NnLNet003BadJa3 {
    fn id(&self) -> &'static str {
        "NN-L-NET-003_BadJa3"
    }
    fn name(&self) -> &'static str {
        "JA3 fingerprint matches threat-actor blocklist"
    }
    fn category(&self) -> &'static str {
        CATEGORY_CRITICAL
    }
    fn evaluate(&self, event: &Event) -> Option<Verdict> {
        let Event::NetFlow(nf) = event else {
            return None;
        };
        let fp = nf.tls_fingerprint.as_ref()?;
        if !self.blocklist.contains(&fp.ja3) {
            return None;
        }
        Some(net_verdict(
            self,
            ResponseAction::KillProcessTree,
            Severity::Critical,
            "TLS JA3 fingerprint matches operator threat-actor \
             blocklist — kill the process tree + posture → COMBAT",
            nf.pid,
            nf.comm.clone(),
            nf.start_ns,
        ))
    }
}

// ── FP-3 DNS originator attribution (NN-L-NET-004/-005/-014) ─────────
//
// A DnsQuery's recorded `pid` is whoever called `udp_sendmsg` to port
// 53. On the standard split-resolver host that's TWO different things:
//
//   * the ORIGINATOR's own query to the loopback stub (127.0.0.53), and
//   * the local forwarder (`systemd-resolved`) relaying it UPSTREAM.
//
// Both surface as `Event::DnsQuery`; the forwarded leg carries the
// resolver's PID. NN-L-NET-004/-014 act with `KillProcess`, so a qname
// predicate that trips on the forwarded leg would SIGKILL the host's DNS
// (see docs/findings/NN-L-NET-004_dns_originator_attribution.md). This
// layer classifies the SENDER by its kernel-resolved exe and re-routes
// attribution so the resolver is never the kill target.

/// Known DNS forwarder / stub-resolver program names. A DnsQuery whose
/// sender exe basename is in this set is treated as a FORWARDED leg, not
/// the originator.
///
/// Matched on the basename of the kernel-resolved `/proc/<pid>/exe`
/// (robust across distro install paths) — NEVER on `comm`. `comm` is
/// `prctl(PR_SET_NAME)`-spoofable, and here a comm check would hand a
/// forged resolver KILL-IMMUNITY (an attacker setting
/// `comm=systemd-resolve` would dodge the kill); the exe symlink is not
/// forgeable from userspace. This is the same exe-over-comm discipline
/// `combat/protected.rs` and `posture/lineage.rs` enforce.
const KNOWN_RESOLVER_PROGRAMS: &[&str] = &[
    "systemd-resolved",
    "systemd-resolve",
    "named",
    "unbound",
    "dnsmasq",
    "dnscrypt-proxy",
    "pdns_recursor",
    "kresd",
    "stubby",
    "connmand",
];

/// DNS originator back-correlation window — deliberately TIGHT (≤2 s)
/// versus the DNS cache's 300 s connect-attribution TTL. The forwarder's
/// upstream leg and the originator's stub query are microseconds apart,
/// so 2 s captures the real originator while refusing a stale same-qname
/// entry from an unrelated earlier PID (finding §6.6).
const DNS_ORIGINATOR_WINDOW_NS: u64 = 2 * 1_000_000_000;

/// Is the DnsQuery sender a known forwarder/stub resolver? Basename
/// match on the resolved exe; a `None` exe (resolve miss) is NOT a
/// forwarder — fail toward today's behaviour (act on the sender).
fn sender_is_forwarder(exe: Option<&str>) -> bool {
    let Some(path) = exe else { return false };
    let base = path.rsplit('/').next().unwrap_or(path);
    KNOWN_RESOLVER_PROGRAMS.contains(&base)
}

/// Where a tripped DnsQuery predicate (NN-L-NET-004/-014) should be
/// attributed once forwarder-awareness is applied.
enum DnsAttribution {
    /// Act on this PID with this display label. Either the sender itself
    /// (originator-issued: direct upstream OR the originator's own stub
    /// query) or a back-correlated originator (forwarded leg whose
    /// originator was found in the cache).
    Act { pid: u32, label: String },
    /// Forwarded leg with NO attributable originator (Varlink/
    /// `nss-resolve` case (C), a host acting as a LAN resolver, or a
    /// cache miss). The suspicious qname is still surfaced but the
    /// verdict MUST downgrade to `Log` — never act on the forwarder.
    Downgrade { forwarder_pid: u32, label: String },
}

impl DnsAttribution {
    /// The PID the resulting verdict targets — the (back-correlated or
    /// originator-issued) originator for `Act`, the forwarder for a
    /// Log-only `Downgrade`. FP-5 keys its dedup on THIS pid so the
    /// originator's own stub query and the resolver's back-correlated
    /// forwarded leg — both routed to the same originator — collapse into
    /// one verdict (see [`DnsQnameDedupWindow`]).
    fn target_pid(&self) -> u32 {
        match self {
            DnsAttribution::Act { pid, .. } => *pid,
            DnsAttribution::Downgrade { forwarder_pid, .. } => *forwarder_pid,
        }
    }
}

/// Forwarder-aware attribution shared by NN-L-NET-004/-014. Given a
/// tripped DnsQuery, decide who the verdict targets:
///
///   * sender is NOT a forwarder → act on the sender (today's behaviour;
///     covers the no-forwarder direct host AND the originator's own stub
///     query on a split-resolver host);
///   * sender IS a forwarder, originator back-correlated → act on the
///     originator PID (correct kill target, resolver spared);
///   * sender IS a forwarder, no originator → downgrade to `Log`.
fn attribute_dns_query(
    dns_cache: &DnsCache,
    sender_pid: u32,
    sender_comm: &str,
    sender_exe: Option<&str>,
    query_name: &str,
    now_ns: u64,
) -> DnsAttribution {
    if !sender_is_forwarder(sender_exe) {
        return DnsAttribution::Act {
            pid: sender_pid,
            label: sender_comm.to_string(),
        };
    }
    // Forwarded leg — the resolver must never be the kill target.
    match dns_cache.originator_for(query_name, now_ns, DNS_ORIGINATOR_WINDOW_NS, sender_pid) {
        Some(orig) => DnsAttribution::Act {
            pid: orig,
            label: format!(
                "pid {orig} (DNS originator of {query_name}, forwarded by {sender_comm})"
            ),
        },
        None => DnsAttribution::Downgrade {
            forwarder_pid: sender_pid,
            label: format!("{query_name} (forwarded by {sender_comm}; originator unattributable)"),
        },
    }
}

// ── FP-5 per-(originator, qname) qname-shape dedup (NN-L-NET-004/-014) ─
//
// ONE logical lookup (`getent hosts <name>`) fans out into several
// DnsQuery events: glibc issues A + AAAA (+ retries), and on a
// split-resolver host each of those has TWO legs — the originator's own
// stub query to 127.0.0.53 AND the forwarder's upstream leg, which FP-3
// back-correlates to the SAME originator. The qname-shape rules
// (-004 long/base64, -014 entropy) inspect only the qname, so every one
// of those events yields an IDENTICAL verdict targeting the originator —
// the live finding saw ONE `getent` raise 8 NN-L-NET-004 verdicts (4
// direct+forwarded pairs ~130 ms apart). This layer collapses them: at
// most ONE verdict per (attributed originator, qname) per window.
//
// Per-qname, NOT per-pid: distinct qnames each still fire, so a DGA
// spraying many distinct names stays fully visible (that IS the signal),
// and a genuine re-lookup after the window fires again. Same shape as the
// NN-L-NET-005 [`DnsBurstWindow`] / FP-4's
// [`CronEditWindow`](crate::fim::rules::CronEditWindow) precedent.

/// FP-5 dedup window: at most one qname-shape verdict per
/// `(attributed originator pid, qname)` within this span. Sized to the
/// originator back-correlation window ([`DNS_ORIGINATOR_WINDOW_NS`]) — a
/// single logical lookup's legs land microseconds apart and the live
/// fan-out spanned ~130 ms, so 2 s coalesces the burst while a re-lookup
/// seconds later still surfaces.
const DNS_QNAME_DEDUP_WINDOW_NS: u64 = 2 * 1_000_000_000;

/// Hash a qname to the `u64` half of the dedup key. The qname is dynamic
/// (unlike FP-4's `&'static` cron-directory bucket), so keying on a hash
/// keeps the key `Copy` and allocation-free on the hot path — no owned
/// `String` per suspicious event. `DefaultHasher` is fixed-seeded, so the
/// mapping is stable within the process; cross-process stability is
/// irrelevant (the state is in-memory and per-engine). A 64-bit collision
/// inside one pid's 2 s window is astronomically unlikely.
fn hash_qname(qname: &str) -> u64 {
    use std::hash::{Hash, Hasher};
    let mut h = std::collections::hash_map::DefaultHasher::new();
    qname.hash(&mut h);
    h.finish()
}

/// FP-5 dedup state for the per-qname shape rules (NN-L-NET-004/-014).
/// Mirrors the [`DnsBurstWindow`] / `CronEditWindow` stateful-rule
/// precedent: `&mut self` behind an `Arc<Mutex<_>>`, clocked by the
/// event-carried `timestamp_ns` (no syscall clock — the rule stays a pure
/// function of the event + its own state).
///
/// Each rule holds its OWN window: a qname that trips both -004 and -014
/// must still yield one verdict from EACH, so the two rules deliberately
/// never share a window (no cross-suppression).
#[derive(Debug, Default)]
pub struct DnsQnameDedupWindow {
    /// `(attributed_originator_pid, qname_hash)` → ns of the last verdict
    /// we FIRED for it. The value is the `u64` hash, not the qname
    /// `String`, so the key is `Copy` and never allocates.
    last_fired: HashMap<(u32, u64), u64>,
}

impl DnsQnameDedupWindow {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a suspicious-qname hit for `(pid, qname_hash)` at `ts_ns`
    /// and report whether the rule should FIRE. `true` for the first hit
    /// on a pair (and the first after the window lapses); `false` for a
    /// repeat inside the window. The window is anchored on the last FIRE
    /// (a suppressed repeat does NOT extend it), so a sustained drip still
    /// surfaces roughly once per [`DNS_QNAME_DEDUP_WINDOW_NS`] rather than
    /// being silenced outright. Prunes aged pairs on every call, so the
    /// map only ever holds pairs touched within the last window
    /// (suspicious qnames are rare — in steady state it is empty).
    pub fn observe(&mut self, pid: u32, qname_hash: u64, ts_ns: u64) -> bool {
        // Drop pairs whose last fire is older than the window. This both
        // bounds the map AND makes "present after prune ⇒ still within the
        // window ⇒ suppress" hold, so the check below is a plain lookup.
        self.last_fired
            .retain(|_, &mut last| ts_ns.saturating_sub(last) < DNS_QNAME_DEDUP_WINDOW_NS);
        let key = (pid, qname_hash);
        if self.last_fired.contains_key(&key) {
            return false;
        }
        self.last_fired.insert(key, ts_ns);
        true
    }
}

// ── NN-L-NET-014 corroboration (external audit NETR-002) ──────────────

/// How long the distinct high-entropy labels of one process under one
/// parent domain add up.
pub const DNS_TUNNEL_WINDOW_NS: u64 = 60 * 1_000_000_000;
/// Distinct high-entropy first labels under one parent domain, from one
/// process, within [`DNS_TUNNEL_WINDOW_NS`], that make a tunnel.
pub const DNS_TUNNEL_DISTINCT_LABELS: usize = 8;
/// Bound on the `(pid, parent)` pairs held at once.
const DNS_TUNNEL_MAX_PAIRS: usize = 4096;

/// External audit NETR-002: a DNS tunnel (iodine, dnscat2, exfiltration
/// over DNS) carries its payload in a NEW label per query — dozens a
/// second under the attacker's domain. A host resolves a UUID-named bucket
/// or a hashed load-balancer name a handful of times: one high-entropy
/// label is not a tunnel (the lab killed `python3` for
/// `my-company-prod-backups-archive.s3.amazonaws.com`, 4.0 bits/char).
#[derive(Default)]
pub struct DnsTunnelCorroboration {
    /// `(attributed pid, parent-domain hash)` → `(first seen ns, label
    /// hash)` of the distinct labels in the window, at most
    /// [`DNS_TUNNEL_DISTINCT_LABELS`].
    seen: HashMap<(u32, u64), Vec<(u64, u64)>>,
}

impl DnsTunnelCorroboration {
    /// Record `label_hash` under `(pid, parent_hash)` at `ts_ns` and return
    /// how many distinct labels the pair has within the window, this one
    /// included. A new pair beyond the bound is judged on its own (1).
    pub fn observe(&mut self, pid: u32, parent_hash: u64, label_hash: u64, ts_ns: u64) -> usize {
        self.seen.retain(|_, labels| {
            labels.retain(|(t, _)| ts_ns.saturating_sub(*t) < DNS_TUNNEL_WINDOW_NS);
            !labels.is_empty()
        });
        let key = (pid, parent_hash);
        if !self.seen.contains_key(&key) && self.seen.len() >= DNS_TUNNEL_MAX_PAIRS {
            return 1;
        }
        let labels = self.seen.entry(key).or_default();
        if !labels.iter().any(|(_, h)| *h == label_hash) {
            if labels.len() >= DNS_TUNNEL_DISTINCT_LABELS {
                labels.remove(0);
            }
            labels.push((ts_ns, label_hash));
        }
        labels.len()
    }
}

// ── NN-L-NET-004 — Suspicious DNS qname ──────────────────────────────

/// Unusually long DNS qname (> 60 chars), recorded. Per design §7.
///
/// External audit NETR-002: this rule used to KILL the sender of any name
/// over 60 characters or whose first label was 20+ characters of the
/// base64 alphabet — which every LDH label of that length is: S3 buckets
/// and storage accounts, CDN and load-balancer names, Kubernetes service
/// and pod FQDNs, ACME challenges; its own tests killed `curl` and
/// `getent`. A label that carries an encoded payload is NN-L-NET-014's
/// (Shannon entropy over a ≥ 25-char label); length alone is recorded.
///
/// FP-3: holds the shared `Arc<DnsCache>` so a forwarded-leg trip can be
/// back-correlated to the originating process — a `KillProcess` verdict
/// must never land on the local stub resolver.
pub struct NnLNet004SuspiciousDnsQname {
    dns_cache: Arc<DnsCache>,
    /// FP-5: rule-private dedup of repeated (originator, qname) verdicts.
    dedup: Arc<Mutex<DnsQnameDedupWindow>>,
}

impl NnLNet004SuspiciousDnsQname {
    pub fn new(dns_cache: Arc<DnsCache>) -> Self {
        Self {
            dns_cache,
            dedup: Arc::new(Mutex::new(DnsQnameDedupWindow::new())),
        }
    }
}

impl Rule for NnLNet004SuspiciousDnsQname {
    fn id(&self) -> &'static str {
        "NN-L-NET-004_SuspiciousDnsQname"
    }
    fn name(&self) -> &'static str {
        "Unusually long DNS qname (recorded)"
    }
    fn category(&self) -> &'static str {
        CATEGORY_HIGH
    }
    fn evaluate(&self, event: &Event) -> Option<Verdict> {
        let Event::DnsQuery {
            pid,
            comm,
            exe,
            query_name,
            timestamp_ns,
            qname_partial,
            ..
        } = event
        else {
            return None;
        };
        let long = query_name.len() > 60;
        if !long {
            // Tappa 10.9 step 3: the name does not end in the kernel's
            // linear copy — sent in pieces (MSG_MORE / UDP_CORK), with UDP
            // GSO or zero copy, or not DNS at all. A resolver sends a query
            // in one piece. Recorded for one soak cycle, never killed. (A
            // prefix that is already long is judged below like a whole
            // name: the name sent is at least that.)
            if *qname_partial
                && self
                    .dedup
                    .lock()
                    .observe(*pid, hash_qname(query_name), *timestamp_ns)
            {
                return Some(net_verdict(
                    self,
                    ResponseAction::Log,
                    Severity::High,
                    "DNS query whose name does not end in the kernel's linear copy — \
                     sent in pieces (MSG_MORE / UDP_CORK), with UDP GSO or zero copy, \
                     or not DNS at all; resolvers send a query in one piece \
                     (tunnelling-evasion shape)",
                    *pid,
                    comm.clone(),
                    *timestamp_ns,
                ));
            }
            return None;
        }
        let reason = "DNS qname is unusually long (>60 chars) — recorded; an encoded payload \
                      in a label is NN-L-NET-014's (entropy)";
        // FP-3: forwarder-aware attribution. An originator-issued query
        // kills the sender (as before); a forwarded leg back-correlates
        // to the originator, or downgrades to Log when none is found —
        // never KillProcess the local stub resolver.
        let attribution = attribute_dns_query(
            &self.dns_cache,
            *pid,
            comm,
            exe.as_deref(),
            query_name,
            *timestamp_ns,
        );
        // FP-5: collapse ONE logical lookup's fan-out (A+AAAA+retries ×
        // originator stub + back-correlated forwarded leg) into a single
        // verdict. Key on the ATTRIBUTED pid so the direct and forwarded
        // legs — both routed to the originator — dedup together; distinct
        // qnames/pids, or the same pair after the window, still fire.
        if !self.dedup.lock().observe(
            attribution.target_pid(),
            hash_qname(query_name),
            *timestamp_ns,
        ) {
            return None;
        }
        Some(match attribution {
            DnsAttribution::Act { pid, label } => net_verdict(
                self,
                ResponseAction::Log,
                Severity::Medium,
                reason,
                pid,
                label,
                *timestamp_ns,
            ),
            DnsAttribution::Downgrade {
                forwarder_pid,
                label,
            } => net_verdict(
                self,
                ResponseAction::Log,
                Severity::Medium,
                "Unusually long DNS qname observed on a forwarded leg with no \
                 attributable originator (Varlink/nss-resolve, LAN-resolver, \
                 or correlation miss) — surfaced as Log; the local resolver \
                 is NOT the originator and must not be killed",
                forwarder_pid,
                label,
                *timestamp_ns,
            ),
        })
    }
}

// ── NN-L-NET-005 — DNS TXT/NULL burst (tunnelling shape) ─────────────

/// DNS qtype TXT/NULL burst — >50 such queries from the same PID
/// in 60s. State-bearing: holds an `Arc<Mutex<DnsBurstWindow>>`.
pub struct NnLNet005DnsBurst {
    window: Arc<Mutex<DnsBurstWindow>>,
    threshold: usize,
}

impl NnLNet005DnsBurst {
    pub fn new(window: Arc<Mutex<DnsBurstWindow>>) -> Self {
        Self {
            window,
            threshold: 50,
        }
    }
}

impl Rule for NnLNet005DnsBurst {
    fn id(&self) -> &'static str {
        "NN-L-NET-005_DnsTxtNullBurst"
    }
    fn name(&self) -> &'static str {
        "DNS TXT/NULL burst (tunnelling shape)"
    }
    fn category(&self) -> &'static str {
        CATEGORY_HIGH
    }
    fn evaluate(&self, event: &Event) -> Option<Verdict> {
        let Event::DnsQuery {
            pid,
            comm,
            exe,
            query_type,
            timestamp_ns,
            ..
        } = event
        else {
            return None;
        };
        if *query_type != DNS_QTYPE_TXT && *query_type != DNS_QTYPE_NULL {
            return None;
        }
        // FP-3: do NOT count a forwarded leg under the resolver's PID.
        // The forwarder relays EVERY local TXT/NULL lookup, so counting
        // its upstream legs would (a) smear the per-PID burst under the
        // resolver — the mis-attribution this fix targets — and (b)
        // double-count case-B queries already tallied under the
        // originator's own stub query. The originator's own query (sender
        // is NOT the forwarder) is still counted and attributed normally.
        // Residual: a Varlink/nss-resolve burst (no originator stub
        // query) goes uncounted here — the documented case-(C) gap; -005
        // is Log-only and the connect-side NetFlow rules still apply.
        if sender_is_forwarder(exe.as_deref()) {
            return None;
        }
        let count = self.window.lock().observe(*pid, *timestamp_ns);
        if count <= self.threshold {
            return None;
        }
        Some(net_verdict(
            self,
            ResponseAction::Log,
            Severity::High,
            "DNS TXT/NULL burst — possible DNS tunnelling. \
             >50 queries from this PID in the last 60 s; \
             posture → ENGAGED",
            *pid,
            comm.clone(),
            *timestamp_ns,
        ))
    }
}

// ── NN-L-NET-006 — New listener on uncommon port ─────────────────────

/// New TCP listener on a port outside the common-ports allowlist
/// AND from a comm outside the listener-allowlist. Forensic
/// signal (Q6 lock-in: track every listener; rule-side filter
/// here).
pub struct NnLNet006UncommonListener {
    allowlist: Arc<CommAllowlist>,
}

impl NnLNet006UncommonListener {
    pub fn new(allowlist: Arc<CommAllowlist>) -> Self {
        Self { allowlist }
    }
}

impl Rule for NnLNet006UncommonListener {
    fn id(&self) -> &'static str {
        "NN-L-NET-006_UncommonListener"
    }
    fn name(&self) -> &'static str {
        "New listener on uncommon port"
    }
    fn category(&self) -> &'static str {
        CATEGORY_MEDIUM
    }
    fn evaluate(&self, event: &Event) -> Option<Verdict> {
        let Event::NetListener(nl) = event else {
            return None;
        };
        if LISTENER_COMMON_PORTS.contains(&nl.bind_port) {
            return None;
        }
        let judged = self.allowlist.judge(nl.pid, &nl.comm);
        if judged == Judgement::Allowed {
            return None;
        }
        Some(judged.apply(
            net_verdict(
                self,
                ResponseAction::Log,
                Severity::Medium,
                "Process opened a TCP listener on an uncommon port \
             without operator allowlist coverage — posture → ALERTED",
                nl.pid,
                nl.comm.clone(),
                nl.timestamp_ns,
            ),
            &nl.comm,
        ))
    }
}

// ── NN-L-NET-007 — Outbound to RFC1918 from unusual process ──────────

/// Outbound to RFC1918 (10/8, 172.16/12, 192.168/16) from a comm
/// not in the internal-ops allowlist — lateral-movement
/// indicator.
pub struct NnLNet007Rfc1918FromUnusualProc {
    allowlist: Arc<CommAllowlist>,
}

impl NnLNet007Rfc1918FromUnusualProc {
    pub fn new(allowlist: Arc<CommAllowlist>) -> Self {
        Self { allowlist }
    }

    fn is_rfc1918(addr: &IpAddr) -> bool {
        match addr {
            IpAddr::V4(v4) => {
                let o = v4.octets();
                o[0] == 10
                    || (o[0] == 172 && (16..=31).contains(&o[1]))
                    || (o[0] == 192 && o[1] == 168)
            }
            IpAddr::V6(_) => false,
        }
    }
}

impl Rule for NnLNet007Rfc1918FromUnusualProc {
    fn id(&self) -> &'static str {
        "NN-L-NET-007_Rfc1918FromUnusualProc"
    }
    fn name(&self) -> &'static str {
        "Outbound to RFC1918 from non-allowlist process"
    }
    fn category(&self) -> &'static str {
        CATEGORY_MEDIUM
    }
    fn evaluate(&self, event: &Event) -> Option<Verdict> {
        let Event::NetFlow(nf) = event else {
            return None;
        };
        if !Self::is_rfc1918(&nf.dst_addr) {
            return None;
        }
        let judged = self.allowlist.judge(nf.pid, &nf.comm);
        if judged == Judgement::Allowed {
            return None;
        }
        Some(judged.apply(
            net_verdict(
                self,
                ResponseAction::Log,
                Severity::Medium,
                "Outbound to an internal RFC1918 destination from a comm \
             outside the operator allowlist — possible lateral movement; \
             posture → ALERTED",
                nf.pid,
                nf.comm.clone(),
                nf.start_ns,
            ),
            &nf.comm,
        ))
    }
}

// ── NN-L-NET-008 — Outbound from /tmp/ exec ──────────────────────────

/// Exe under `/tmp/` outbound to a port other than 53. Pairs
/// with R001 (exec from /tmp/) on the network side — a dropper
/// reaching out for second-stage payload.
pub struct NnLNet008OutboundFromTmpExec;

impl Rule for NnLNet008OutboundFromTmpExec {
    fn id(&self) -> &'static str {
        "NN-L-NET-008_OutboundFromTmpExec"
    }
    fn name(&self) -> &'static str {
        "Outbound from /tmp/ exec to non-resolver"
    }
    fn category(&self) -> &'static str {
        CATEGORY_HIGH
    }
    fn evaluate(&self, event: &Event) -> Option<Verdict> {
        let Event::NetFlow(nf) = event else {
            return None;
        };
        let exe = nf.exe.as_deref()?;
        if !exe.starts_with("/tmp/") {
            return None;
        }
        if TMP_EXEC_ALLOWED_PORTS.contains(&nf.dst_port) {
            return None;
        }
        Some(net_verdict(
            self,
            ResponseAction::KillProcess,
            Severity::High,
            "Process executed from /tmp/ initiated outbound to a non-DNS \
             port — likely dropper fetching second-stage payload; \
             kill the process + posture → ENGAGED",
            nf.pid,
            nf.comm.clone(),
            nf.start_ns,
        ))
    }
}

// ── NN-L-NET-009 — Byte-count anomaly ────────────────────────────────

/// `bytes_sent > 100 MiB` on a single flow from a comm outside
/// the high-volume allowlist. Possible exfiltration.
///
/// Review 74: a UDP flow row is one kernel emission — one datagram before
/// review 73, at most about 1 MiB since — so no single UDP row can cross
/// the threshold, and UDP exfiltration of any volume never fired. UDP rows
/// are summed per (pid, destination) over [`UDP_VOLUME_WINDOW_NS`].
pub struct NnLNet009ByteAnomaly {
    allowlist: Arc<CommAllowlist>,
    udp: Mutex<UdpVolume>,
}

impl NnLNet009ByteAnomaly {
    pub fn new(allowlist: Arc<CommAllowlist>) -> Self {
        Self {
            allowlist,
            udp: Mutex::new(UdpVolume::default()),
        }
    }
}

/// Window over which NET-009 sums a (pid, destination)'s UDP bytes.
const UDP_VOLUME_WINDOW_NS: u64 = 600 * 1_000_000_000;
/// Destinations tracked at once; the oldest window goes first.
const UDP_VOLUME_MAX_KEYS: usize = 4096;

/// Review 74: UDP bytes per (pid, dst addr, dst port): window start,
/// bytes in the window, and whether the window already fired.
#[derive(Default)]
struct UdpVolume {
    keys: HashMap<(u32, IpAddr, u16), (u64, u64, bool)>,
}

impl UdpVolume {
    /// Add a row's bytes. Returns the window's total the first time it
    /// exceeds [`HIGH_VOLUME_BYTES_SENT`].
    fn add(&mut self, key: (u32, IpAddr, u16), ts_ns: u64, bytes: u64) -> Option<u64> {
        if !self.keys.contains_key(&key) && self.keys.len() >= UDP_VOLUME_MAX_KEYS {
            self.keys
                .retain(|_, (start, _, _)| ts_ns.saturating_sub(*start) <= UDP_VOLUME_WINDOW_NS);
            if self.keys.len() >= UDP_VOLUME_MAX_KEYS {
                if let Some(oldest) = self
                    .keys
                    .iter()
                    .min_by_key(|(_, (start, _, _))| *start)
                    .map(|(k, _)| *k)
                {
                    self.keys.remove(&oldest);
                }
            }
        }
        let e = self.keys.entry(key).or_insert((ts_ns, 0, false));
        if ts_ns.saturating_sub(e.0) > UDP_VOLUME_WINDOW_NS {
            *e = (ts_ns, 0, false);
        }
        e.1 = e.1.saturating_add(bytes);
        if !e.2 && e.1 > HIGH_VOLUME_BYTES_SENT {
            e.2 = true;
            return Some(e.1);
        }
        None
    }
}

impl Rule for NnLNet009ByteAnomaly {
    fn id(&self) -> &'static str {
        "NN-L-NET-009_ByteAnomaly"
    }
    fn name(&self) -> &'static str {
        "Flow byte-count anomaly (possible exfiltration)"
    }
    fn category(&self) -> &'static str {
        CATEGORY_HIGH
    }
    fn evaluate(&self, event: &Event) -> Option<Verdict> {
        let Event::NetFlow(nf) = event else {
            return None;
        };
        if nf.proto == 17 {
            // Review 74: sum the UDP rows of this (pid, destination). The
            // allowlist is judged once the sum crosses the threshold
            // (external audit NET-010: on exec identity, which costs more
            // than a comm lookup per row).
            let total = self.udp.lock().add(
                (nf.pid, nf.dst_addr, nf.dst_port),
                nf.start_ns,
                nf.bytes_sent,
            )?;
            let reasoning = format!(
                "UDP: {} MiB sent to {}:{} within 10 minutes from a non-allowlist \
                 comm — possible exfiltration over UDP; posture → ENGAGED",
                total >> 20,
                nf.dst_addr,
                nf.dst_port
            );
            let judged = self.allowlist.judge(nf.pid, &nf.comm);
            if judged == Judgement::Allowed {
                return None;
            }
            return Some(judged.apply(
                net_verdict(
                    self,
                    ResponseAction::Log,
                    Severity::High,
                    &reasoning,
                    nf.pid,
                    nf.comm.clone(),
                    nf.start_ns,
                ),
                &nf.comm,
            ));
        }
        if nf.bytes_sent <= HIGH_VOLUME_BYTES_SENT {
            return None;
        }
        let judged = self.allowlist.judge(nf.pid, &nf.comm);
        if judged == Judgement::Allowed {
            return None;
        }
        Some(judged.apply(
            net_verdict(
                self,
                ResponseAction::Log,
                Severity::High,
                "Outbound flow exceeded 100 MiB sent from a non-allowlist \
             comm — possible exfiltration; posture → ENGAGED",
                nf.pid,
                nf.comm.clone(),
                nf.start_ns,
            ),
            &nf.comm,
        ))
    }
}

// ── NN-L-NET-010 — Outbound to high-risk C2 port ─────────────────────

/// Outbound flow to a high-risk C2 / tooling default port
/// ([`HIGH_RISK_C2_PORTS`]) from a non-allowlisted comm. MITRE
/// T1571 (Non-Standard Port). High + KillProcess.
pub struct NnLNet010OutboundToHighRiskC2Port {
    allowlist: Arc<CommAllowlist>,
}

impl NnLNet010OutboundToHighRiskC2Port {
    pub fn new(allowlist: Arc<CommAllowlist>) -> Self {
        Self { allowlist }
    }
}

impl Rule for NnLNet010OutboundToHighRiskC2Port {
    fn id(&self) -> &'static str {
        "NN-L-NET-010_OutboundToHighRiskC2Port"
    }
    fn name(&self) -> &'static str {
        "Outbound to high-risk C2 port"
    }
    fn category(&self) -> &'static str {
        CATEGORY_HIGH
    }
    fn evaluate(&self, event: &Event) -> Option<Verdict> {
        let Event::NetFlow(nf) = event else {
            return None;
        };
        if !HIGH_RISK_C2_PORTS.contains(&nf.dst_port) {
            return None;
        }
        let judged = self.allowlist.judge(nf.pid, &nf.comm);
        if judged == Judgement::Allowed {
            return None;
        }
        Some(judged.apply(
            net_verdict(
                self,
                ResponseAction::KillProcess,
                Severity::High,
                "Outbound to a high-risk C2 / tooling-default port (e.g. 4444 \
             Metasploit, 6667 IRC, 9001 Tor) from a non-allowlisted comm \
             — likely C2 (T1571); kill the process + posture → ENGAGED",
                nf.pid,
                nf.comm.clone(),
                nf.start_ns,
            ),
            &nf.comm,
        ))
    }
}

// ── NN-L-NET-011 — Plaintext-credential service flow ─────────────────

/// Outbound flow to a plaintext-credential service port (FTP 21 /
/// Telnet 23) from a non-allowlisted comm. MITRE T1071. Medium +
/// Log — these legacy protocols still appear in benign environments,
/// so surface for review rather than kill.
pub struct NnLNet011PlaintextCredService {
    allowlist: Arc<CommAllowlist>,
}

impl NnLNet011PlaintextCredService {
    pub fn new(allowlist: Arc<CommAllowlist>) -> Self {
        Self { allowlist }
    }
}

impl Rule for NnLNet011PlaintextCredService {
    fn id(&self) -> &'static str {
        "NN-L-NET-011_PlaintextCredService"
    }
    fn name(&self) -> &'static str {
        "Plaintext-credential service flow (FTP/Telnet)"
    }
    fn category(&self) -> &'static str {
        CATEGORY_MEDIUM
    }
    fn evaluate(&self, event: &Event) -> Option<Verdict> {
        let Event::NetFlow(nf) = event else {
            return None;
        };
        if !PLAINTEXT_CRED_PORTS.contains(&nf.dst_port) {
            return None;
        }
        let judged = self.allowlist.judge(nf.pid, &nf.comm);
        if judged == Judgement::Allowed {
            return None;
        }
        Some(judged.apply(
            net_verdict(
                self,
                ResponseAction::Log,
                Severity::Medium,
                "Outbound to a plaintext-credential service (FTP 21 / Telnet 23) \
             from a non-allowlisted comm — credentials transit in clear \
             (T1071); posture → ALERTED",
                nf.pid,
                nf.comm.clone(),
                nf.start_ns,
            ),
            &nf.comm,
        ))
    }
}

// ── NN-L-NET-013 — Periodic-beacon detector (stateful) ───────────────

/// Stateful C2-beacon detector: fires when outbound flows to the
/// same `(pid, dst_addr)` arrive at regular, low-jitter intervals
/// (design §6.3 / §3.5-A; precedent [`DnsBurstWindow`] / NN-L-NET-005).
/// MITRE T1071 (Application Layer Protocol) / T1029 (Scheduled
/// Transfer). High + Log (the periodicity is the signal; the
/// operator decides whether to act, so we don't auto-kill a flow
/// that may be a long-lived legitimate poller that slipped the
/// allowlist). Allowlisted comms are skipped BEFORE observation so a
/// legitimate periodic client (ntpd/chronyd/node_exporter) never
/// pollutes the window.
pub struct NnLNet013Beacon {
    window: Arc<Mutex<BeaconWindow>>,
    allowlist: Arc<CommAllowlist>,
}

impl NnLNet013Beacon {
    pub fn new(window: Arc<Mutex<BeaconWindow>>, allowlist: Arc<CommAllowlist>) -> Self {
        Self { window, allowlist }
    }
}

impl Rule for NnLNet013Beacon {
    fn id(&self) -> &'static str {
        "NN-L-NET-013_Beacon"
    }
    fn name(&self) -> &'static str {
        "Periodic outbound beacon (low jitter)"
    }
    fn category(&self) -> &'static str {
        CATEGORY_HIGH
    }
    fn evaluate(&self, event: &Event) -> Option<Verdict> {
        let Event::NetFlow(nf) = event else {
            return None;
        };
        let is_beacon = self.window.lock().observe(nf.pid, nf.dst_addr, nf.start_ns);
        if !is_beacon {
            return None;
        }
        // External audit NET-010 (NN-AUD-006): the allowlist is judged on
        // exec identity, once a beacon is seen (it costs more than a comm
        // lookup per flow). A trusted periodic client's flows now seed the
        // window too; the window is bounded.
        let judged = self.allowlist.judge(nf.pid, &nf.comm);
        if judged == Judgement::Allowed {
            return None;
        }
        Some(judged.apply(
            net_verdict(
                self,
                ResponseAction::Log,
                Severity::High,
                "Periodic low-jitter outbound flows to a single destination \
                 from one process — C2-beacon timing pattern (T1071/T1029); \
                 posture → ENGAGED",
                nf.pid,
                nf.comm.clone(),
                nf.start_ns,
            ),
            &nf.comm,
        ))
    }
}

// ── NN-L-NET-018 — RFC1918 outbound on a lateral-movement port ───────

/// Outbound to an internal RFC1918 destination on a lateral-movement
/// service port ([`LATERAL_MOVEMENT_PORTS`]) from a non-allowlisted
/// comm. MITRE T1021 (Remote Services). High + KillProcess — the
/// port-specific High refinement of the broad Medium NN-L-NET-007
/// (§13 Q10 documents the intentional overlap; this rule is ordered
/// BEFORE -007 so the High verdict wins for the lateral-port case).
pub struct NnLNet018Rfc1918LateralPort {
    allowlist: Arc<CommAllowlist>,
}

impl NnLNet018Rfc1918LateralPort {
    pub fn new(allowlist: Arc<CommAllowlist>) -> Self {
        Self { allowlist }
    }
}

impl Rule for NnLNet018Rfc1918LateralPort {
    fn id(&self) -> &'static str {
        "NN-L-NET-018_Rfc1918LateralPort"
    }
    fn name(&self) -> &'static str {
        "RFC1918 outbound on lateral-movement port"
    }
    fn category(&self) -> &'static str {
        CATEGORY_HIGH
    }
    fn evaluate(&self, event: &Event) -> Option<Verdict> {
        let Event::NetFlow(nf) = event else {
            return None;
        };
        if !NnLNet007Rfc1918FromUnusualProc::is_rfc1918(&nf.dst_addr) {
            return None;
        }
        if !LATERAL_MOVEMENT_PORTS.contains(&nf.dst_port) {
            return None;
        }
        let judged = self.allowlist.judge(nf.pid, &nf.comm);
        if judged == Judgement::Allowed {
            return None;
        }
        Some(judged.apply(
            net_verdict(
                self,
                ResponseAction::KillProcess,
                Severity::High,
                "Outbound to an internal RFC1918 host on a lateral-movement \
             port (445 SMB / 3389 RDP / 5985 WinRM / 5900 VNC) from a \
             non-allowlisted comm — lateral movement (T1021); kill the \
             process + posture → ENGAGED",
                nf.pid,
                nf.comm.clone(),
                nf.start_ns,
            ),
            &nf.comm,
        ))
    }
}

// ── NN-L-NET-019 — Wildcard-bind listener on uncommon port ───────────

/// New listener bound to the wildcard address (`0.0.0.0` or `::`) on
/// an uncommon port from a non-allowlisted comm. MITRE T1571.
/// Medium severity with a Log action — the network-exposed
/// refinement of NN-L-NET-006 (a wildcard bind exposes the port
/// off-host, unlike a loopback bind). Ordered BEFORE -006 so a
/// wildcard bind attributes here.
pub struct NnLNet019WildcardListener {
    allowlist: Arc<CommAllowlist>,
}

impl NnLNet019WildcardListener {
    pub fn new(allowlist: Arc<CommAllowlist>) -> Self {
        Self { allowlist }
    }

    fn is_wildcard(addr: &IpAddr) -> bool {
        match addr {
            IpAddr::V4(v4) => v4.is_unspecified(),
            IpAddr::V6(v6) => v6.is_unspecified(),
        }
    }
}

impl Rule for NnLNet019WildcardListener {
    fn id(&self) -> &'static str {
        "NN-L-NET-019_WildcardListener"
    }
    fn name(&self) -> &'static str {
        "Wildcard-bind listener on uncommon port"
    }
    fn category(&self) -> &'static str {
        CATEGORY_MEDIUM
    }
    fn evaluate(&self, event: &Event) -> Option<Verdict> {
        let Event::NetListener(nl) = event else {
            return None;
        };
        if !Self::is_wildcard(&nl.bind_addr) {
            return None;
        }
        if LISTENER_COMMON_PORTS.contains(&nl.bind_port) {
            return None;
        }
        let judged = self.allowlist.judge(nl.pid, &nl.comm);
        if judged == Judgement::Allowed {
            return None;
        }
        Some(judged.apply(
            net_verdict(
                self,
                ResponseAction::Log,
                Severity::Medium,
                "New listener bound to the wildcard address on an uncommon \
             port from a non-allowlisted comm — network-exposed backdoor \
             surface (T1571); posture → ALERTED",
                nl.pid,
                nl.comm.clone(),
                nl.timestamp_ns,
            ),
            &nl.comm,
        ))
    }
}

// ── NN-L-NET-020 — DNS query flood (review 78) ─────────────────────

/// Window over which [`NnLNet020DnsQueryFlood`] sums held-back queries.
const DNS_FLOOD_WINDOW_NS: u64 = 10 * 1_000_000_000;
/// Held-back queries in a window that make it fire.
const DNS_FLOOD_MIN_HELD: u64 = 256;
/// Processes and users tracked at most; when full, ended windows go.
const DNS_FLOOD_MAX_KEYS: usize = 4096;

/// NN-L-NET-020 — a process, or a user across its processes, sent DNS
/// queries well beyond the kernel's DNS budget (review 78). The queries
/// over the budget are not recorded, so the DNS rules (NN-L-NET-004,
/// -005, -014) never see them: a flood could carry a tunnel. Within the
/// budget (64 queries, then 128 per second, per process; 2,048 then 1,024
/// per second per user) every query is recorded; beyond it, the process
/// is reported here (MITRE T1071.004). The local resolvers' users are
/// exempt in the kernel.
/// (uid, pid — 0 for the user's budget) → (window start, held, fired).
type HeldWindows = HashMap<(u32, u32), (u64, u64, bool)>;

pub struct NnLNet020DnsQueryFlood {
    held: Mutex<HeldWindows>,
}

impl NnLNet020DnsQueryFlood {
    pub fn new() -> Self {
        Self {
            held: Mutex::new(HashMap::new()),
        }
    }
}

impl Default for NnLNet020DnsQueryFlood {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for NnLNet020DnsQueryFlood {
    fn id(&self) -> &'static str {
        "NN-L-NET-020_DnsQueryFlood"
    }
    fn name(&self) -> &'static str {
        "DNS queries beyond the kernel's DNS budget"
    }
    fn category(&self) -> &'static str {
        CATEGORY_HIGH
    }
    fn evaluate(&self, event: &Event) -> Option<Verdict> {
        let Event::DnsFlood {
            pid,
            uid,
            comm,
            held,
            uid_level,
            timestamp_ns,
            ..
        } = event
        else {
            return None;
        };
        let key = (*uid, if *uid_level { 0 } else { *pid });
        let sum = {
            let mut map = self.held.lock();
            if map.len() >= DNS_FLOOD_MAX_KEYS && !map.contains_key(&key) {
                map.retain(|_, w| timestamp_ns.saturating_sub(w.0) < DNS_FLOOD_WINDOW_NS);
                if map.len() >= DNS_FLOOD_MAX_KEYS {
                    map.clear();
                }
            }
            let w = map.entry(key).or_insert((*timestamp_ns, 0, false));
            if timestamp_ns.saturating_sub(w.0) >= DNS_FLOOD_WINDOW_NS {
                *w = (*timestamp_ns, 0, false);
            }
            w.1 += u64::from(*held);
            if w.2 || w.1 < DNS_FLOOD_MIN_HELD {
                return None;
            }
            w.2 = true;
            w.1
        };
        let scope = if *uid_level { "its user's" } else { "its own" };
        Some(net_verdict(
            self,
            ResponseAction::Log,
            Severity::High,
            &format!(
                "{comm} (pid {pid}, uid {uid}) sent at least {sum} DNS queries beyond {scope} \
                 DNS budget within 10 seconds: those queries were not recorded, so a DNS tunnel \
                 could hide among them (T1071.004)"
            ),
            *pid,
            comm.clone(),
            *timestamp_ns,
        ))
    }
}

// ── NN-L-NET-014 — DNS qname high-entropy label (tunnelling) ────────

/// DNS-tunnelling refinement (MITRE T1071.004). Where NN-L-NET-004
/// keys on the *base64 charset* + raw length, this rule measures the
/// **Shannon entropy** of the leftmost label, so it also catches
/// hex / base32 / custom-alphabet encodings that 004's charset gate
/// misses. Encoded/compressed exfil payloads pack near-maximal
/// per-character entropy; ordinary hostnames (even long CDN ones) sit
/// well below the threshold.
///
/// Unblocked by the Tappa 4.1 DNS observability refit — the kprobe now
/// extracts the QNAME for connected-UDP resolution (glibc), so this
/// rule finally has a populated `query_name` to score. (NN-L-NET-015
/// fast-flux stays gated: it needs DNS-*response* observation, a
/// separate V1.1 sensor — see decision/rules module docs.)
///
/// FP-3: holds the shared `Arc<DnsCache>` for the same forwarder-aware
/// attribution as NN-L-NET-004 — a `KillProcess` verdict on a forwarded
/// leg must be re-routed to the originator, never the stub resolver.
pub struct NnLNet014DnsTunnelEntropy {
    dns_cache: Arc<DnsCache>,
    /// FP-5: rule-private dedup of repeated (originator, qname) verdicts.
    /// Separate from -004's window — a qname that trips both must still
    /// raise one verdict from EACH rule.
    dedup: Arc<Mutex<DnsQnameDedupWindow>>,
    /// External audit NETR-002: distinct high-entropy labels per
    /// (originator, parent domain) — the kill needs a tunnel's volume.
    corroboration: Arc<Mutex<DnsTunnelCorroboration>>,
}

impl NnLNet014DnsTunnelEntropy {
    pub fn new(dns_cache: Arc<DnsCache>) -> Self {
        Self {
            dns_cache,
            dedup: Arc::new(Mutex::new(DnsQnameDedupWindow::new())),
            corroboration: Arc::new(Mutex::new(DnsTunnelCorroboration::default())),
        }
    }

    /// Minimum first-label length to consider — short labels can't
    /// carry a meaningful payload and their entropy estimate is noisy.
    /// Most legitimate labels also sit below this.
    const MIN_LABEL_LEN: usize = 25;
    /// Bits-per-character threshold. Random base32 ≈ 5.0, base64 ≈ 6.0,
    /// hex ≈ 4.0 — and a varied 30-character name of English words
    /// reaches 4.0 too (`my-company-prod-backups-archive`): the shape
    /// alone does not tell a payload from a long legitimate name, so a
    /// single label is recorded and the kill takes
    /// [`DNS_TUNNEL_DISTINCT_LABELS`] of them under one parent domain
    /// (external audit NETR-002).
    const ENTROPY_BITS: f64 = 3.8;

    /// Shannon entropy (bits/byte) of `s` over its observed byte
    /// distribution. `0.0` for the empty string.
    fn shannon_entropy(s: &str) -> f64 {
        if s.is_empty() {
            return 0.0;
        }
        let mut counts = [0u32; 256];
        for &b in s.as_bytes() {
            counts[b as usize] += 1;
        }
        let len = s.len() as f64;
        let mut h = 0.0;
        for &c in counts.iter() {
            if c == 0 {
                continue;
            }
            let p = c as f64 / len;
            h -= p * p.log2();
        }
        h
    }
}

impl Rule for NnLNet014DnsTunnelEntropy {
    fn id(&self) -> &'static str {
        "NN-L-NET-014_DnsTunnelEntropy"
    }
    fn name(&self) -> &'static str {
        "DNS qname high-entropy label (tunnelling)"
    }
    fn category(&self) -> &'static str {
        CATEGORY_HIGH
    }
    fn evaluate(&self, event: &Event) -> Option<Verdict> {
        let Event::DnsQuery {
            pid,
            comm,
            exe,
            query_name,
            timestamp_ns,
            ..
        } = event
        else {
            return None;
        };
        // Score the leftmost label — tunnelling encodes payload there,
        // the domain suffix stays normal.
        let first_label = query_name.split('.').next().unwrap_or(query_name);
        if first_label.len() < Self::MIN_LABEL_LEN {
            return None;
        }
        let entropy = Self::shannon_entropy(first_label);
        if entropy < Self::ENTROPY_BITS {
            return None;
        }
        // FP-3: forwarder-aware attribution (see NN-L-NET-004).
        let attribution = attribute_dns_query(
            &self.dns_cache,
            *pid,
            comm,
            exe.as_deref(),
            query_name,
            *timestamp_ns,
        );
        // FP-5: -014 is a per-qname shape rule (one verdict per scored
        // qname), structurally identical to -004 — the SAME logical-lookup
        // fan-out applies, so dedup it the same way, keyed on the
        // attributed pid + qname. (-014 owns its window; a qname tripping
        // both -004 and -014 still fires once per rule.)
        if !self.dedup.lock().observe(
            attribution.target_pid(),
            hash_qname(query_name),
            *timestamp_ns,
        ) {
            return None;
        }
        // External audit NETR-002: a tunnel is many distinct encoded labels
        // under one parent domain; one is recorded.
        let parent = query_name.split_once('.').map(|(_, p)| p).unwrap_or("");
        let distinct = self.corroboration.lock().observe(
            attribution.target_pid(),
            hash_qname(parent),
            hash_qname(first_label),
            *timestamp_ns,
        );
        let tunnel = distinct >= DNS_TUNNEL_DISTINCT_LABELS;
        Some(match attribution {
            DnsAttribution::Act { pid, label } if tunnel => net_verdict(
                self,
                ResponseAction::KillProcess,
                Severity::High,
                "DNS tunnel: distinct high-entropy first labels under one parent domain \
                 from one process within a minute — encoded payload per query \
                 (DNS tunnelling / exfil, T1071.004); posture → ENGAGED",
                pid,
                label,
                *timestamp_ns,
            ),
            DnsAttribution::Act { pid, label } => net_verdict(
                self,
                ResponseAction::Log,
                Severity::Medium,
                "DNS first label with high Shannon entropy over a long label — \
                 recorded; a tunnel carries a new one per query under the same \
                 parent domain (the kill takes several within a minute)",
                pid,
                label,
                *timestamp_ns,
            ),
            DnsAttribution::Downgrade {
                forwarder_pid,
                label,
            } => net_verdict(
                self,
                ResponseAction::Log,
                if tunnel {
                    Severity::High
                } else {
                    Severity::Medium
                },
                "High-entropy DNS label observed on a forwarded leg with no \
                 attributable originator (Varlink/nss-resolve, LAN-resolver, \
                 or correlation miss) — surfaced as Log; the local resolver \
                 is NOT the originator and must not be killed",
                forwarder_pid,
                label,
                *timestamp_ns,
            ),
        })
    }
}

// ── Factory ──────────────────────────────────────────────────────────

/// Build the NN-L-NET rules with operator-loaded blocklists, the
/// per-family comm allowlist (Tappa 10.5 D4), and freshly-allocated
/// stateful windows. Production `main.rs` constructs these from disk
/// via [`NetBlocklist::load`] / [`Ja3Blocklist::load`] /
/// `comm_allowlist::load_comm_allowlist` (each overlay as the signed-overlay
/// gate verified it) and shares them via `Arc`.
///
/// Evaluation order: Critical first (never throttled), then the D4
/// High/Medium additions BEFORE the broad Tappa 10 catch-alls so the
/// specific refinements win first-match (NN-L-NET-018 before -007,
/// NN-L-NET-019 before -006 — §13 Q10 documented overlaps).
#[allow(clippy::too_many_arguments)]
pub fn net_rules(
    blocklist: Arc<NetBlocklist>,
    ja3_blocklist: Arc<Ja3Blocklist>,
    burst_window: Arc<Mutex<DnsBurstWindow>>,
    comm_allowlist: Arc<CommAllowlist>,
    beacon_window: Arc<Mutex<BeaconWindow>>,
    dns_cache: Arc<DnsCache>,
) -> Vec<Box<dyn Rule>> {
    vec![
        // Critical first.
        Box::new(NnLNet001OutboundToBlockedIp::new(blocklist)),
        Box::new(NnLNet003BadJa3::new(ja3_blocklist)),
        // Tappa 10 High/DNS rules whose predicates don't overlap the
        // D4 additions. FP-3: -004/-014 take the shared DNS cache for
        // forwarder-aware originator back-correlation.
        Box::new(NnLNet002OutboundToBlockedTld),
        Box::new(NnLNet004SuspiciousDnsQname::new(Arc::clone(&dns_cache))),
        Box::new(NnLNet005DnsBurst::new(burst_window)),
        // Tappa 4.1 DNS observability refit — entropy-based tunnelling
        // detector, unblocked now the kprobe extracts the QNAME.
        Box::new(NnLNet014DnsTunnelEntropy::new(dns_cache)),
        // Tappa 10.5 D4 additions — specific refinements ordered
        // BEFORE the broad Tappa 10 catch-alls (-006 / -007).
        Box::new(NnLNet010OutboundToHighRiskC2Port::new(Arc::clone(
            &comm_allowlist,
        ))),
        Box::new(NnLNet011PlaintextCredService::new(Arc::clone(
            &comm_allowlist,
        ))),
        Box::new(NnLNet013Beacon::new(
            beacon_window,
            Arc::clone(&comm_allowlist),
        )),
        Box::new(NnLNet018Rfc1918LateralPort::new(Arc::clone(
            &comm_allowlist,
        ))),
        Box::new(NnLNet019WildcardListener::new(Arc::clone(&comm_allowlist))),
        // Review 78: no comm allowlist — the kernel exempts the resolvers.
        Box::new(NnLNet020DnsQueryFlood::new()),
        // Broad Tappa 10 catch-alls last among the comm-gated rules.
        Box::new(NnLNet006UncommonListener::new(Arc::clone(&comm_allowlist))),
        Box::new(NnLNet007Rfc1918FromUnusualProc::new(Arc::clone(
            &comm_allowlist,
        ))),
        Box::new(NnLNet008OutboundFromTmpExec),
        Box::new(NnLNet009ByteAnomaly::new(comm_allowlist)),
    ]
}

/// Empty-blocklist / default-allowlist convenience for boot + tests.
/// The comm allowlist is seeded from
/// [`NETFLOW_COMM_ALLOWLIST_DEFAULTS`] (the in-code mirror of the
/// shipped `configs/netflow-comm-allowlist.v1`) so the switch-over
/// from the former inline `const` sets is behaviour-preserving — the
/// same comms stay exempt with no operator file present. Production
/// `main.rs` instead loads the on-disk file via the D1 loader.
pub fn net_rules_empty() -> Vec<Box<dyn Rule>> {
    net_rules(
        Arc::new(NetBlocklist::empty()),
        Arc::new(Ja3Blocklist::empty()),
        Arc::new(Mutex::new(DnsBurstWindow::new())),
        Arc::new(CommAllowlist::from_iter_owned(
            NETFLOW_COMM_ALLOWLIST_DEFAULTS
                .iter()
                .map(|s| s.to_string()),
        )),
        Arc::new(Mutex::new(BeaconWindow::new())),
        Arc::new(DnsCache::default()),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use common::wire::{NetFlowEvent, NetListenerEvent, TlsFingerprint};
    use common::ResponseAction;
    use std::net::{Ipv4Addr, Ipv6Addr};

    /// Default-seeded comm allowlist (the shipped union) for the
    /// comm-gated rule tests — matches what `net_rules_empty` /
    /// production boot supply.
    fn al() -> Arc<CommAllowlist> {
        Arc::new(CommAllowlist::from_iter_owned(
            NETFLOW_COMM_ALLOWLIST_DEFAULTS
                .iter()
                .map(|s| s.to_string()),
        ))
    }

    fn v4(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(a, b, c, d))
    }

    /// Build a baseline NetFlow event with sensible defaults.
    /// Callers override the fields each test cares about.
    fn flow(dst: IpAddr, dst_port: u16, comm: &str) -> Event {
        Event::NetFlow(NetFlowEvent {
            start_ns: 1_000,
            end_ns: 2_000,
            family: if dst.is_ipv4() { 2 } else { 10 },
            src_addr: v4(192, 0, 2, 10),
            src_port: 54321,
            dst_addr: dst,
            dst_port,
            proto: 6,
            pid: 1234,
            uid: 1000,
            comm: comm.to_string(),
            exe: Some(format!("/usr/bin/{comm}")),
            bytes_sent: 1024,
            bytes_recv: 2048,
            resolved_hostname: None,
            tls_fingerprint: None,
            flow_id: "abc".to_string(),
            close_reason: 0,
        })
    }

    fn dns_event(pid: u32, qname: &str, qtype: u16) -> Event {
        // Originator-issued query (sender exe is a normal client binary,
        // not a resolver) — the common case.
        dns_event_full(pid, qname, qtype, "curl", Some("/usr/bin/curl"), 100)
    }

    /// Full DnsQuery builder so FP-3 tests can vary the sender exe
    /// (forwarder vs originator) and the timestamp.
    fn dns_event_full(
        pid: u32,
        qname: &str,
        qtype: u16,
        comm: &str,
        exe: Option<&str>,
        ts_ns: u64,
    ) -> Event {
        Event::DnsQuery {
            pid,
            uid: 1000,
            comm: comm.to_string(),
            exe: exe.map(str::to_string),
            query_name: qname.to_string(),
            query_type: qtype,
            dns_server: [0; 16],
            family: 2,
            timestamp_ns: ts_ns,
            qname_partial: false,
        }
    }

    fn listener(port: u16, comm: &str) -> Event {
        Event::NetListener(NetListenerEvent {
            timestamp_ns: 100,
            family: 2,
            bind_addr: v4(0, 0, 0, 0),
            bind_port: port,
            proto: 6,
            pid: 5555,
            uid: 1000,
            comm: comm.to_string(),
            exe: Some(format!("/usr/bin/{comm}")),
        })
    }

    // ── NN-L-NET-001 ─────────────────────────────────────────────

    #[test]
    fn net_001_fires_on_blocklist_match() {
        let bl = Arc::new(NetBlocklist::from_entries([
            crate::net::blocklist::NetBlocklistEntry::Cidr {
                net: v4(192, 0, 2, 0),
                prefix: 24,
            },
        ]));
        let rule = NnLNet001OutboundToBlockedIp::new(bl);
        let v = rule
            .evaluate(&flow(v4(192, 0, 2, 42), 443, "curl"))
            .expect("blocklist hit");
        assert_eq!(v.severity, Severity::Critical);
        assert_eq!(v.action, ResponseAction::KillProcessTree);
        assert_eq!(v.category, CATEGORY_CRITICAL);
    }

    #[test]
    fn net_001_does_not_fire_on_clean_destination() {
        let rule = NnLNet001OutboundToBlockedIp::new(Arc::new(NetBlocklist::empty()));
        assert!(rule.evaluate(&flow(v4(8, 8, 8, 8), 443, "curl")).is_none());
    }

    // ── NN-L-NET-002 ─────────────────────────────────────────────

    #[test]
    fn net_002_fires_on_onion_tld() {
        let rule = NnLNet002OutboundToBlockedTld;
        let mut e = flow(v4(8, 8, 8, 8), 443, "curl");
        if let Event::NetFlow(nf) = &mut e {
            nf.resolved_hostname = Some("badactor.onion".to_string());
        }
        let v = rule.evaluate(&e).expect("blocked TLD");
        assert_eq!(v.severity, Severity::High);
        assert_eq!(v.action, ResponseAction::KillProcess);
    }

    #[test]
    fn net_002_does_not_fire_on_normal_domain() {
        let rule = NnLNet002OutboundToBlockedTld;
        let mut e = flow(v4(8, 8, 8, 8), 443, "curl");
        if let Event::NetFlow(nf) = &mut e {
            nf.resolved_hostname = Some("example.com".to_string());
        }
        assert!(rule.evaluate(&e).is_none());
    }

    #[test]
    fn net_002_no_hostname_no_fire() {
        // IP-literal connect (no DNS attribution) means rule can't
        // fire — we don't have a hostname to inspect.
        let rule = NnLNet002OutboundToBlockedTld;
        assert!(rule.evaluate(&flow(v4(8, 8, 8, 8), 443, "curl")).is_none());
    }

    // ── NN-L-NET-003 ─────────────────────────────────────────────

    #[test]
    fn net_003_fires_on_ja3_blocklist_match() {
        let hash = "deadbeefcafe00112233445566778899";
        let bl = Arc::new(Ja3Blocklist::from_entries([hash]));
        let rule = NnLNet003BadJa3::new(bl);
        let mut e = flow(v4(8, 8, 8, 8), 443, "evilbin");
        if let Event::NetFlow(nf) = &mut e {
            nf.tls_fingerprint = Some(TlsFingerprint {
                ja3: hash.to_string(),
                ja3_raw: "771,...".to_string(),
                ja4: "t13d_xx".to_string(),
                sni: None,
                alpn: vec![],
            });
        }
        let v = rule.evaluate(&e).expect("JA3 hit");
        assert_eq!(v.severity, Severity::Critical);
        assert_eq!(v.category, CATEGORY_CRITICAL);
    }

    #[test]
    fn net_003_does_not_fire_on_unknown_ja3() {
        let bl = Arc::new(Ja3Blocklist::from_entries(["aa".repeat(16)]));
        let rule = NnLNet003BadJa3::new(bl);
        let mut e = flow(v4(8, 8, 8, 8), 443, "curl");
        if let Event::NetFlow(nf) = &mut e {
            nf.tls_fingerprint = Some(TlsFingerprint {
                ja3: "bb".repeat(16),
                ja3_raw: "".to_string(),
                ja4: "".to_string(),
                sni: None,
                alpn: vec![],
            });
        }
        assert!(rule.evaluate(&e).is_none());
    }

    // ── NN-L-NET-004 ─────────────────────────────────────────────

    /// FP-3 helper — a -004 rule backed by a fresh empty DNS cache.
    fn net_004() -> NnLNet004SuspiciousDnsQname {
        NnLNet004SuspiciousDnsQname::new(Arc::new(DnsCache::default()))
    }

    /// FP-3 helper — a -014 rule backed by a fresh empty DNS cache.
    fn net_014() -> NnLNet014DnsTunnelEntropy {
        NnLNet014DnsTunnelEntropy::new(Arc::new(DnsCache::default()))
    }

    #[test]
    fn net_004_records_a_long_qname() {
        let rule = net_004();
        let long = format!("{}.example.com", "a".repeat(80));
        let v = rule.evaluate(&dns_event(1, &long, 1)).expect("long qname");
        assert_eq!(v.action, ResponseAction::Log);
        assert_eq!(v.severity, Severity::Medium);
    }

    /// External audit NETR-002: names a host resolves every day — a first
    /// label of 20+ LDH characters, or a long FQDN — are never a kill.
    #[test]
    fn net_004_never_kills_long_cloud_and_cluster_names() {
        let rule = net_004();
        for (pid, q) in [
            (11, "my-company-prod-backups.s3.amazonaws.com"),
            (
                12,
                "internal-payments-api-1234567890.eu-west-1.elb.amazonaws.com",
            ),
            (13, "myaccountstorage2024prod.blob.core.windows.net"),
            (
                14,
                "payments-api-7d4f8b9c6-x2kq9.payments.svc.cluster.local",
            ),
            (
                15,
                "_acme-challenge.payments-gateway-production.example.org",
            ),
            (16, "ZGVhZGJlZWZmZmZmZmZmZmNhZmU=.example.com"),
        ] {
            if let Some(v) = rule.evaluate(&dns_event(pid, q, 1)) {
                assert_eq!(v.action, ResponseAction::Log, "{q}");
            }
        }
        let long = "payments-api-7d4f8b9c6-x2kq9.payments-namespace.svc.cluster.local";
        assert!(long.len() > 60);
        let v = rule.evaluate(&dns_event(17, long, 1)).expect("recorded");
        assert_eq!(v.action, ResponseAction::Log);
    }

    #[test]
    fn net_004_does_not_fire_on_normal_qname() {
        let rule = net_004();
        assert!(rule.evaluate(&dns_event(1, "example.com", 1)).is_none());
    }

    fn partial(e: Event) -> Event {
        let mut e = e;
        if let Event::DnsQuery { qname_partial, .. } = &mut e {
            *qname_partial = true;
        }
        e
    }

    /// Tappa 10.9 step 3: a name that does not end in the kernel's linear
    /// copy (a query sent in pieces) is recorded, never killed; once per
    /// (pid, name) like the other NET-004 verdicts.
    #[test]
    fn net_004_logs_a_partial_name() {
        let rule = net_004();
        let v = rule
            .evaluate(&partial(dns_event(7, "x", 0)))
            .expect("partial name");
        assert_eq!(v.action, ResponseAction::Log);
        assert_eq!(v.severity, Severity::High);
        assert!(v.reasoning.contains("in pieces"));
        assert!(rule.evaluate(&partial(dns_event(7, "x", 0))).is_none());
    }

    /// A partial prefix is recorded like any partial name (external audit
    /// NETR-002: no shape of a name is a kill for this rule).
    #[test]
    fn net_004_records_a_partial_prefix() {
        let rule = net_004();
        let q = "ZGVhZGJlZWZmZmZmZmZmZmNhZmU";
        let v = rule
            .evaluate(&partial(dns_event(8, q, 0)))
            .expect("partial prefix");
        assert_eq!(v.action, ResponseAction::Log);
    }

    // ── NN-L-NET-014 (DNS-tunnel entropy) ────────────────────────

    #[test]
    fn net_014_records_a_single_high_entropy_label() {
        let rule = net_014();
        // 40-char near-uniform alphanumeric first label (entropy well
        // above 3.8) + a normal suffix — the encoded-payload shape, once.
        let q = "a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0.exfil.example.com";
        let v = rule
            .evaluate(&dns_event(7, q, 1))
            .expect("high-entropy label should be recorded");
        assert_eq!(v.rule_id, "NN-L-NET-014_DnsTunnelEntropy");
        assert_eq!(v.action, ResponseAction::Log);
        assert_eq!(v.severity, Severity::Medium);
    }

    /// External audit NETR-002: names the lab saw killed — a bucket of
    /// English words, a hashed load balancer, a UUID-named bucket — are
    /// recorded at most, one by one.
    #[test]
    fn net_014_never_kills_a_long_legitimate_name_on_its_own() {
        let rule = net_014();
        for (pid, q) in [
            (21, "my-company-prod-backups-archive.s3.amazonaws.com"),
            (
                22,
                "internal-payments-api-1234567890.eu-west-1.elb.amazonaws.com",
            ),
            (23, "3f2504e04f8911d39a0c0305e82c3301.s3.amazonaws.com"),
        ] {
            if let Some(v) = rule.evaluate(&dns_event(pid, q, 1)) {
                assert_eq!(v.action, ResponseAction::Log, "{q}");
            }
        }
    }

    /// A tunnel: a new encoded label per query under the attacker's domain.
    /// The kill comes with the DNS_TUNNEL_DISTINCT_LABELS-th within the
    /// window; other parents and other processes do not add up.
    #[test]
    fn net_014_kills_a_tunnel_of_distinct_labels_under_one_parent() {
        let rule = net_014();
        let label = |i: usize| format!("{i:02}q7v3k9x2m4p8r6t1w5y0z3b7c9d2f4h6j8l0n");
        for i in 0..DNS_TUNNEL_DISTINCT_LABELS - 1 {
            // the same process under another parent, and another process
            // under the same parent, never reach the threshold
            let other_parent = format!("{}.cdn.example.net", label(i));
            let v = rule
                .evaluate(&dns_event(31, &other_parent, 1))
                .expect("recorded");
            assert_eq!(v.action, ResponseAction::Log);
            let other_pid = format!("{}.t.attacker.example", label(i));
            let v = rule
                .evaluate(&dns_event(32, &other_pid, 1))
                .expect("recorded");
            assert_eq!(v.action, ResponseAction::Log);
        }
        let mut last = None;
        for i in 0..DNS_TUNNEL_DISTINCT_LABELS {
            let q = format!("{}.t.attacker.example", label(100 + i));
            last = rule.evaluate(&dns_event(33, &q, 1));
            if i + 1 < DNS_TUNNEL_DISTINCT_LABELS {
                assert_eq!(last.as_ref().unwrap().action, ResponseAction::Log);
            }
        }
        let v = last.expect("tunnel verdict");
        assert_eq!(v.action, ResponseAction::KillProcess);
        assert_eq!(v.severity, Severity::High);
        assert_eq!(v.event_pid, 33);
    }

    #[test]
    fn dns_tunnel_corroboration_forgets_after_the_window() {
        let mut c = DnsTunnelCorroboration::default();
        for i in 0..(DNS_TUNNEL_DISTINCT_LABELS as u64 - 1) {
            assert_eq!(c.observe(1, 7, i, i), i as usize + 1);
        }
        // a repeat of a known label adds nothing
        assert_eq!(c.observe(1, 7, 0, 10), DNS_TUNNEL_DISTINCT_LABELS - 1);
        // past the window only the new label counts
        assert_eq!(c.observe(1, 7, 99, DNS_TUNNEL_WINDOW_NS + 100), 1);
    }

    #[test]
    fn net_014_ignores_short_label() {
        let rule = net_014();
        // High-entropy but under the 25-char minimum.
        assert!(rule
            .evaluate(&dns_event(7, "a1b2c3d4e5.example.com", 1))
            .is_none());
    }

    #[test]
    fn net_014_ignores_low_entropy_long_label() {
        let rule = net_014();
        // 40 chars but only two symbols → entropy = 1.0, far below 3.8.
        let q = format!("{}.example.com", "ab".repeat(20));
        assert!(rule.evaluate(&dns_event(7, &q, 1)).is_none());
    }

    #[test]
    fn net_014_ignores_normal_hostname() {
        let rule = net_014();
        // Ordinary hostnames have short, low-entropy first labels.
        assert!(rule.evaluate(&dns_event(7, "www.example.com", 1)).is_none());
        assert!(rule
            .evaluate(&dns_event(7, "api.northnarrow.io", 1))
            .is_none());
    }

    #[test]
    fn net_014_shannon_entropy_bounds() {
        // All-identical bytes carry zero entropy.
        assert_eq!(NnLNet014DnsTunnelEntropy::shannon_entropy("aaaaaaaa"), 0.0);
        // A perfectly uniform 4-symbol distribution = log2(4) = 2.0.
        assert!(
            (NnLNet014DnsTunnelEntropy::shannon_entropy("abcd") - 2.0).abs() < 1e-9,
            "uniform 4-symbol entropy must be 2.0 bits/char"
        );
    }

    // ── NN-L-NET-005 ─────────────────────────────────────────────

    #[test]
    fn net_005_fires_on_txt_burst_over_threshold() {
        let win = Arc::new(Mutex::new(DnsBurstWindow::new()));
        let rule = NnLNet005DnsBurst::new(win);
        // Fire 51 TXT queries within the 60s window.
        let mut last: Option<Verdict> = None;
        for i in 0..51 {
            last = rule.evaluate(&dns_event(99, "x.com", DNS_QTYPE_TXT));
            let _ = i;
        }
        let v = last.expect("51st TXT must fire");
        assert_eq!(v.severity, Severity::High);
    }

    #[test]
    fn net_005_ignores_non_txt_qtypes() {
        let win = Arc::new(Mutex::new(DnsBurstWindow::new()));
        let rule = NnLNet005DnsBurst::new(win);
        // 100 A-record queries — must not fire (qtype != TXT/NULL).
        for _ in 0..100 {
            assert!(rule.evaluate(&dns_event(99, "x.com", 1)).is_none());
        }
    }

    // ── FP-3 DNS originator attribution (family: -004/-005/-014) ──

    /// A resolver exe path whose basename `systemd-resolved` is in
    /// [`KNOWN_RESOLVER_PROGRAMS`] — i.e. a forwarded leg.
    const RESOLVER_EXE: &str = "/usr/lib/systemd/systemd-resolved";

    /// FP-3 helper-unit — basename matching identifies a forwarder
    /// regardless of install path, and a non-resolver / `None` exe is
    /// NOT a forwarder (fail toward acting on the sender).
    #[test]
    fn fp3_sender_is_forwarder_matches_resolver_basename_only() {
        assert!(sender_is_forwarder(Some(RESOLVER_EXE)));
        assert!(sender_is_forwarder(Some("/lib/systemd/systemd-resolved")));
        assert!(sender_is_forwarder(Some("/usr/sbin/dnsmasq")));
        assert!(!sender_is_forwarder(Some("/usr/bin/curl")));
        assert!(!sender_is_forwarder(None));
    }

    /// FP-3 — originator-issued query (direct case A, or the
    /// originator's own stub query): -004 records the SENDER (external
    /// audit NETR-002: recorded, no longer killed).
    #[test]
    fn fp3_004_originator_issued_records_sender() {
        let rule = net_004();
        let long = format!("{}.example.com", "a".repeat(80));
        let e = dns_event_full(4242, &long, 1, "curl", Some("/usr/bin/curl"), 1_000);
        let v = rule.evaluate(&e).expect("originator query fires");
        assert_eq!(v.action, ResponseAction::Log);
        assert_eq!(v.event_pid, 4242, "recorded against the originating sender");
    }

    /// FP-3 — forwarded leg with a back-correlatable originator (the
    /// split-resolver case B): -004 attributes the record to the
    /// ORIGINATOR's PID, never the resolver.
    #[test]
    fn fp3_004_forwarded_leg_back_correlates_to_originator() {
        let cache = Arc::new(DnsCache::default());
        let long = format!("{}.example.com", "a".repeat(80));
        // Originator (firefox, pid 5000) issued the stub query first.
        cache.on_dns_query(5000, long.clone(), 1, 1_000);
        let rule = NnLNet004SuspiciousDnsQname::new(Arc::clone(&cache));
        // The forwarder (systemd-resolved, pid 673) relays it upstream.
        let leg = dns_event_full(673, &long, 1, "systemd-resolved", Some(RESOLVER_EXE), 1_500);
        let v = rule.evaluate(&leg).expect("forwarded leg still surfaces");
        assert_eq!(v.action, ResponseAction::Log);
        assert_eq!(v.event_pid, 5000, "verdict attributed to the originator");
        assert_ne!(v.event_pid, 673, "the resolver is never the target");
    }

    /// FP-3 — forwarded leg with NO attributable originator (Varlink
    /// case C, LAN-resolver, or cache miss): -004 downgrades to Log and
    /// names the resolver only as the forwarder — it is NOT killed.
    #[test]
    fn fp3_004_forwarded_leg_without_originator_downgrades_to_log() {
        // Empty cache → no originator on record.
        let rule = net_004();
        let long = format!("{}.example.com", "a".repeat(80));
        let leg = dns_event_full(673, &long, 1, "systemd-resolved", Some(RESOLVER_EXE), 2_000);
        let v = rule.evaluate(&leg).expect("qname still surfaced");
        assert_eq!(
            v.action,
            ResponseAction::Log,
            "no originator → Log, never kill the forwarder"
        );
        assert_eq!(
            v.event_pid, 673,
            "logged against the forwarder, but only Log"
        );
    }

    /// FP-3 — same forwarder-aware downgrade applies to -014 (entropy):
    /// the attribution lives at the DnsQuery layer, not per-rule.
    #[test]
    fn fp3_014_forwarded_leg_without_originator_downgrades_to_log() {
        let rule = net_014();
        let q = "a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0.exfil.example.com";
        let leg = dns_event_full(673, q, 1, "systemd-resolved", Some(RESOLVER_EXE), 3_000);
        let v = rule.evaluate(&leg).expect("entropy still surfaced");
        assert_eq!(v.action, ResponseAction::Log);
        assert_eq!(v.rule_id, "NN-L-NET-014_DnsTunnelEntropy");
    }

    /// FP-3 — -014 back-correlates a forwarded leg to the originator
    /// just like -004.
    #[test]
    fn fp3_014_forwarded_leg_back_correlates_to_originator() {
        let cache = Arc::new(DnsCache::default());
        let q = "a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0.exfil.example.com";
        cache.on_dns_query(8080, q.into(), 1, 4_000);
        let rule = NnLNet014DnsTunnelEntropy::new(Arc::clone(&cache));
        let leg = dns_event_full(673, q, 1, "systemd-resolved", Some(RESOLVER_EXE), 4_200);
        let v = rule.evaluate(&leg).expect("forwarded entropy leg surfaces");
        // one label: recorded (NETR-002), against the originator
        assert_eq!(v.action, ResponseAction::Log);
        assert_eq!(v.event_pid, 8080, "attributed to the originator");
    }

    /// FP-3 — -005 does NOT count a forwarded leg under the resolver's
    /// PID: 100 TXT legs from the forwarder never trip the burst (the
    /// FP). An originator's own TXT burst still fires.
    #[test]
    fn fp3_005_skips_forwarded_leg_but_fires_on_originator() {
        let win = Arc::new(Mutex::new(DnsBurstWindow::new()));
        let rule = NnLNet005DnsBurst::new(win);
        // 100 forwarded TXT legs (sender = systemd-resolved): never fire.
        for i in 0..100u64 {
            let leg = dns_event_full(
                673,
                "x.com",
                DNS_QTYPE_TXT,
                "systemd-resolved",
                Some(RESOLVER_EXE),
                10_000 + i,
            );
            assert!(
                rule.evaluate(&leg).is_none(),
                "forwarded legs must not accumulate under the resolver"
            );
        }
        // The actual originator (curl) tripping its own burst still fires.
        let mut last: Option<Verdict> = None;
        for i in 0..51u64 {
            let q = dns_event_full(
                99,
                "x.com",
                DNS_QTYPE_TXT,
                "curl",
                Some("/usr/bin/curl"),
                20_000 + i,
            );
            last = rule.evaluate(&q);
        }
        let v = last.expect("originator burst fires");
        assert_eq!(v.event_pid, 99);
    }

    // ── FP-5 per-(originator, qname) qname-shape dedup (-004/-014) ─

    /// FP-5 — ONE logical lookup fans out into A + AAAA + a retry for the
    /// same name under the same originator; the qname-shape rule emits
    /// exactly ONE verdict for the burst (the live finding's 8→1 collapse).
    #[test]
    fn fp5_004_same_pid_qname_burst_yields_one_verdict() {
        let rule = net_004();
        let long = format!("{}.example.com", "a".repeat(80));
        // (qtype, ts_ns): A, then AAAA 5 ms later, then an A retry 130 ms
        // later — getent's real fan-out, one originator (pid 1122). The
        // dedup ignores qtype (the qname-shape rule does too), so A+AAAA
        // collapse.
        let legs = [(1u16, 0u64), (28, 5_000_000), (1, 130_000_000)];
        let fired = legs
            .iter()
            .filter(|&&(qt, ts)| {
                rule.evaluate(&dns_event_full(
                    1122,
                    &long,
                    qt,
                    "getent",
                    Some("/usr/bin/getent"),
                    ts,
                ))
                .is_some()
            })
            .count();
        assert_eq!(
            fired, 1,
            "A+AAAA+retry for one qname collapse to a single verdict"
        );
    }

    /// FP-5 — the finding's exact shape: the originator's own stub query
    /// AND the resolver's back-correlated forwarded leg (FP-3 routes both
    /// to the SAME originator pid) collapse into ONE verdict. Proves the
    /// dedup keys on the ATTRIBUTED pid, not the raw sender.
    #[test]
    fn fp5_004_direct_and_back_correlated_forwarded_leg_collapse() {
        let cache = Arc::new(DnsCache::default());
        let long = format!("{}.example.com", "a".repeat(80));
        // Originator (getent, pid 1122) on record so the forwarded leg
        // back-correlates to it.
        cache.on_dns_query(1122, long.clone(), 1, 0);
        let rule = NnLNet004SuspiciousDnsQname::new(Arc::clone(&cache));
        // Direct leg — the originator's own stub query (sender = 1122, not
        // a resolver) → Act on 1122 → fires.
        let direct = dns_event_full(1122, &long, 1, "getent", Some("/usr/bin/getent"), 0);
        let v = rule.evaluate(&direct).expect("direct originator leg fires");
        assert_eq!(v.event_pid, 1122);
        // Forwarded leg ~130 ms later (sender = resolver) → back-correlates
        // to 1122 → SAME (pid, qname) key → suppressed.
        let fwd = dns_event_full(
            673,
            &long,
            1,
            "systemd-resolved",
            Some(RESOLVER_EXE),
            130_000_000,
        );
        assert!(
            rule.evaluate(&fwd).is_none(),
            "back-correlated forwarded leg collapses into the originator's verdict"
        );
    }

    /// FP-5 — distinct qnames are distinct signals: a DGA spraying many
    /// names must stay fully visible. N names → N verdicts (per-qname, NOT
    /// per-pid).
    #[test]
    fn fp5_004_distinct_qnames_each_fire() {
        let rule = net_004();
        for i in 0..5u32 {
            // 80-char first label, distinct per i, all under one pid.
            let q = format!("{}{i:02}.example.com", "a".repeat(78));
            assert!(
                rule.evaluate(&dns_event_full(
                    1122,
                    &q,
                    1,
                    "getent",
                    Some("/usr/bin/getent"),
                    u64::from(i) * 1_000_000,
                ))
                .is_some(),
                "distinct qname #{i} must fire"
            );
        }
    }

    /// FP-5 — the dedup suppresses a burst, it never silences a rule: a
    /// genuine re-lookup of the same name AFTER the window fires again.
    #[test]
    fn fp5_004_relookup_after_window_fires_again() {
        let rule = net_004();
        let long = format!("{}.example.com", "a".repeat(80));
        let ev = |ts| dns_event_full(1122, &long, 1, "getent", Some("/usr/bin/getent"), ts);
        let t0 = 1_000_000_000u64;
        assert!(rule.evaluate(&ev(t0)).is_some(), "first lookup fires");
        assert!(
            rule.evaluate(&ev(t0 + DNS_QNAME_DEDUP_WINDOW_NS - 1))
                .is_none(),
            "repeat inside the window is suppressed"
        );
        assert!(
            rule.evaluate(&ev(t0 + DNS_QNAME_DEDUP_WINDOW_NS + 1))
                .is_some(),
            "re-lookup after the window fires again"
        );
    }

    /// FP-5 — the dedup applies to -014 (entropy) too: it is a per-qname
    /// shape rule (one verdict per scored qname), so the same A+AAAA+retry
    /// fan-out collapses to one verdict.
    #[test]
    fn fp5_014_same_pid_qname_burst_yields_one_verdict() {
        let rule = net_014();
        let q = "a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0.exfil.example.com";
        let legs = [(1u16, 0u64), (28, 5_000_000), (1, 130_000_000)];
        let fired = legs
            .iter()
            .filter(|&&(qt, ts)| {
                rule.evaluate(&dns_event_full(
                    1122,
                    q,
                    qt,
                    "getent",
                    Some("/usr/bin/getent"),
                    ts,
                ))
                .is_some()
            })
            .count();
        assert_eq!(fired, 1, "-014 collapses the A+AAAA+retry burst too");
    }

    /// FP-5 — -004 and -014 hold SEPARATE dedup windows: a qname that
    /// trips both still yields one verdict from EACH (no cross-suppression).
    #[test]
    fn fp5_004_and_014_do_not_cross_suppress() {
        let r4 = net_004();
        let r14 = net_014();
        // First label is long (>60 total) AND high-entropy → trips both.
        let q = "a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0u1v2w3x4y5z6.exfil.example.com";
        let e = dns_event_full(1122, q, 1, "getent", Some("/usr/bin/getent"), 0);
        assert!(r4.evaluate(&e).is_some(), "-004 fires");
        assert!(
            r14.evaluate(&e).is_some(),
            "-014 fires on the same event — the windows are independent"
        );
    }

    // ── NN-L-NET-006 ─────────────────────────────────────────────

    #[test]
    fn net_006_fires_on_uncommon_port_non_allowlist_comm() {
        let rule = NnLNet006UncommonListener::new(al());
        let v = rule
            .evaluate(&listener(4444, "evilbin"))
            .expect("4444 + evilbin must fire");
        assert_eq!(v.severity, Severity::Medium);
    }

    #[test]
    fn net_006_does_not_fire_on_allowlist_comm() {
        let rule = NnLNet006UncommonListener::new(al());
        assert!(rule.evaluate(&listener(4444, "sshd")).is_none());
    }

    #[test]
    fn net_006_does_not_fire_on_common_port() {
        let rule = NnLNet006UncommonListener::new(al());
        assert!(rule.evaluate(&listener(443, "anycomm")).is_none());
    }

    // ── NN-L-NET-007 ─────────────────────────────────────────────

    #[test]
    fn net_007_fires_on_rfc1918_non_allowlist() {
        let rule = NnLNet007Rfc1918FromUnusualProc::new(al());
        let v = rule
            .evaluate(&flow(v4(10, 0, 0, 5), 443, "evilbin"))
            .expect("10/8 + evilbin");
        assert_eq!(v.severity, Severity::Medium);
    }

    #[test]
    fn net_007_does_not_fire_on_rfc1918_allowlist() {
        let rule = NnLNet007Rfc1918FromUnusualProc::new(al());
        assert!(rule.evaluate(&flow(v4(10, 0, 0, 5), 22, "ssh")).is_none());
    }

    #[test]
    fn net_007_does_not_fire_on_public_destination() {
        let rule = NnLNet007Rfc1918FromUnusualProc::new(al());
        assert!(rule
            .evaluate(&flow(v4(8, 8, 8, 8), 443, "evilbin"))
            .is_none());
        // IPv6 also doesn't match (V1.0 scope: RFC1918 is v4-only).
        assert!(rule
            .evaluate(&flow(IpAddr::V6(Ipv6Addr::LOCALHOST), 443, "evilbin"))
            .is_none());
    }

    // ── NN-L-NET-008 ─────────────────────────────────────────────

    #[test]
    fn net_008_fires_on_tmp_exec_outbound() {
        let rule = NnLNet008OutboundFromTmpExec;
        let mut e = flow(v4(1, 2, 3, 4), 443, "payload");
        if let Event::NetFlow(nf) = &mut e {
            nf.exe = Some("/tmp/payload".to_string());
        }
        let v = rule.evaluate(&e).expect("tmp-exec outbound");
        assert_eq!(v.severity, Severity::High);
    }

    #[test]
    fn net_008_does_not_fire_on_tmp_exec_to_dns() {
        let rule = NnLNet008OutboundFromTmpExec;
        let mut e = flow(v4(1, 2, 3, 4), 53, "payload");
        if let Event::NetFlow(nf) = &mut e {
            nf.exe = Some("/tmp/payload".to_string());
        }
        assert!(rule.evaluate(&e).is_none());
    }

    #[test]
    fn net_008_does_not_fire_on_system_exec() {
        let rule = NnLNet008OutboundFromTmpExec;
        // /usr/bin/curl outbound — not /tmp/, doesn't fire.
        assert!(rule.evaluate(&flow(v4(1, 2, 3, 4), 443, "curl")).is_none());
    }

    // ── NN-L-NET-009 ─────────────────────────────────────────────

    #[test]
    fn net_009_fires_on_large_flow_from_non_allowlist() {
        let rule = NnLNet009ByteAnomaly::new(al());
        let mut e = flow(v4(8, 8, 8, 8), 443, "evilbin");
        if let Event::NetFlow(nf) = &mut e {
            nf.bytes_sent = HIGH_VOLUME_BYTES_SENT + 1;
        }
        let v = rule.evaluate(&e).expect("100 MiB + evilbin");
        assert_eq!(v.severity, Severity::High);
    }

    #[test]
    fn net_009_does_not_fire_on_allowlist_comm() {
        let rule = NnLNet009ByteAnomaly::new(al());
        let mut e = flow(v4(8, 8, 8, 8), 443, "rsync");
        if let Event::NetFlow(nf) = &mut e {
            nf.bytes_sent = 5 * 1024 * 1024 * 1024;
        }
        assert!(rule.evaluate(&e).is_none());
    }

    const SEC_NS: u64 = 1_000_000_000;

    /// A UDP row from the flow tracker: `bytes` sent at `ts_ns`.
    fn udp_row(pid: u32, dst_port: u16, comm: &str, bytes: u64, ts_ns: u64) -> Event {
        let mut e = flow(v4(203, 0, 113, 7), dst_port, comm);
        if let Event::NetFlow(nf) = &mut e {
            nf.proto = 17;
            nf.pid = pid;
            nf.bytes_sent = bytes;
            nf.start_ns = ts_ns;
            nf.end_ns = ts_ns;
            nf.bytes_recv = 0;
        }
        e
    }

    /// Review 74: no UDP row exceeds ~1 MiB, so NET-009 sums them per
    /// (pid, destination): it fires once when 100 MiB are crossed.
    #[test]
    fn net_009_sums_udp_rows_per_destination() {
        let rule = NnLNet009ByteAnomaly::new(al());
        let mib = 1024 * 1024;
        let mut fired = 0;
        for i in 0..150u64 {
            if rule
                .evaluate(&udp_row(77, 9999, "evilbin", mib, i * 100_000_000))
                .is_some()
            {
                fired += 1;
                assert!(i >= 100, "fired at row {i}, before 100 MiB");
            }
        }
        assert_eq!(fired, 1, "once per window");
        // Another destination of the same process starts from zero.
        assert!(rule
            .evaluate(&udp_row(77, 9998, "evilbin", mib, 20 * SEC_NS))
            .is_none());
    }

    fn dns_flood(pid: u32, uid: u32, held: u32, uid_level: bool, ts: u64) -> Event {
        Event::DnsFlood {
            pid,
            uid,
            comm: "flooder".to_string(),
            exe: None,
            held,
            uid_level,
            timestamp_ns: ts,
        }
    }

    /// Review 78: held-back queries are summed per process over 10 s; the
    /// rule fires once per window at 256, and a new window starts over.
    #[test]
    fn net_020_sums_held_queries_per_process_and_window() {
        const SEC: u64 = 1_000_000_000;
        let rule = NnLNet020DnsQueryFlood::new();
        assert!(rule.evaluate(&dns_flood(10, 1000, 200, false, 0)).is_none());
        // Another process of the same user has its own sum.
        assert!(rule
            .evaluate(&dns_flood(11, 1000, 200, false, SEC))
            .is_none());
        let v = rule
            .evaluate(&dns_flood(10, 1000, 100, false, 2 * SEC))
            .expect("300 held within 10 s");
        assert_eq!(v.rule_id, "NN-L-NET-020_DnsQueryFlood");
        assert_eq!(v.action, ResponseAction::Log);
        assert_eq!(v.event_pid, 10);
        assert!(v.reasoning.contains("300"));
        // Once per window.
        assert!(rule
            .evaluate(&dns_flood(10, 1000, 500, false, 3 * SEC))
            .is_none());
        // A new window starts over.
        assert!(rule
            .evaluate(&dns_flood(10, 1000, 100, false, 12 * SEC))
            .is_none());
        assert!(rule
            .evaluate(&dns_flood(10, 1000, 200, false, 13 * SEC))
            .is_some());
    }

    /// The user's budget is summed per user, whichever process reports it.
    #[test]
    fn net_020_user_budget_is_summed_per_user() {
        let rule = NnLNet020DnsQueryFlood::new();
        assert!(rule.evaluate(&dns_flood(20, 1000, 150, true, 0)).is_none());
        let v = rule
            .evaluate(&dns_flood(21, 1000, 150, true, 1))
            .expect("300 held by the user's processes");
        assert!(v.reasoning.contains("its user's"));
        // Another user is apart.
        assert!(rule.evaluate(&dns_flood(22, 1001, 150, true, 2)).is_none());
    }

    #[test]
    fn net_009_udp_window_and_allowlist() {
        let rule = NnLNet009ByteAnomaly::new(al());
        let mib = 1024 * 1024;
        // 60 MiB, then 60 MiB more 11 minutes later: two windows, no fire.
        assert!(rule
            .evaluate(&udp_row(5, 4000, "evilbin", 60 * mib, 0))
            .is_none());
        assert!(rule
            .evaluate(&udp_row(5, 4000, "evilbin", 60 * mib, 660 * SEC_NS))
            .is_none());
        // An allowlisted comm is never summed.
        assert!(rule
            .evaluate(&udp_row(6, 4000, "rsync", 200 * mib, 0))
            .is_none());
    }

    #[test]
    fn net_009_does_not_fire_under_threshold() {
        let rule = NnLNet009ByteAnomaly::new(al());
        // 99 MiB (under 100 MiB threshold).
        let mut e = flow(v4(8, 8, 8, 8), 443, "evilbin");
        if let Event::NetFlow(nf) = &mut e {
            nf.bytes_sent = 99 * 1024 * 1024;
        }
        assert!(rule.evaluate(&e).is_none());
    }

    // ── Builder + invariants ────────────────────────────────────

    /// Required builder test — the factory returns 16 net rules
    /// (Tappa 10 N6 shipped 9; Tappa 10.5 D4 adds 5:
    /// NN-L-NET-010/011/013/018/019; review 78 adds NN-L-NET-020).
    /// Future rule additions must update this assertion.
    #[test]
    fn net_rules_builder_returns_16_rules() {
        let rules = net_rules_empty();
        assert_eq!(
            rules.len(),
            16,
            "N6 9 + D4 5 + T4.1 DNS-tunnel-entropy 1 + DNS flood 1 = 16 net rules"
        );
    }

    /// All Critical-tier rules use `CATEGORY_CRITICAL` so the
    /// future §6.5 rate-limiter bypass path can identify them
    /// without per-rule ID matching. The §13 Q4 lock-in
    /// ("Critical-uncapped") is what this category tag enables.
    #[test]
    fn critical_rules_use_critical_category() {
        let rules = net_rules_empty();
        let critical_ids: Vec<&str> = rules
            .iter()
            .filter(|r| r.category() == CATEGORY_CRITICAL)
            .map(|r| r.id())
            .collect();
        // Per design §7, NN-L-NET-001 + NN-L-NET-003 are the
        // two Critical rules.
        assert_eq!(
            critical_ids.len(),
            2,
            "exactly 2 Critical rules: {critical_ids:?}"
        );
        assert!(
            critical_ids.contains(&"NN-L-NET-001_OutboundToBlockedIp"),
            "001 must be Critical"
        );
        assert!(
            critical_ids.contains(&"NN-L-NET-003_BadJa3"),
            "003 must be Critical"
        );
    }

    /// Q4 rate-limit lock-in — Critical rules are categorised
    /// such that the future bucket-aware emitter can bypass
    /// them. This test pins the category-tag contract from the
    /// rule side; the emitter side will assert "events from
    /// CATEGORY_CRITICAL rules skip the bucket" once the
    /// rate-limiter ships.
    #[test]
    fn critical_rule_category_anchors_rate_limit_bypass() {
        // The contract: any future rule that lands at Critical
        // severity MUST use CATEGORY_CRITICAL. If a maintainer
        // adds NN-L-NET-010 at Critical with a different
        // category, this test fails + forces a documented
        // override (or a category update).
        let rules = net_rules_empty();
        // Construct a synthetic event per rule + verify any
        // Critical verdict carries CATEGORY_CRITICAL.
        // We exercise the two known Criticals here:
        let bl = Arc::new(NetBlocklist::from_entries([
            crate::net::blocklist::NetBlocklistEntry::Ip(v4(1, 2, 3, 4)),
        ]));
        let ja3_bl = Arc::new(Ja3Blocklist::from_entries(["aa".repeat(16)]));
        let net_001 = NnLNet001OutboundToBlockedIp::new(bl);
        let net_003 = NnLNet003BadJa3::new(ja3_bl);

        let v1 = net_001
            .evaluate(&flow(v4(1, 2, 3, 4), 443, "x"))
            .expect("001 fires");
        assert_eq!(v1.severity, Severity::Critical);
        assert_eq!(v1.category, CATEGORY_CRITICAL);

        let mut e = flow(v4(8, 8, 8, 8), 443, "x");
        if let Event::NetFlow(nf) = &mut e {
            nf.tls_fingerprint = Some(TlsFingerprint {
                ja3: "aa".repeat(16),
                ja3_raw: "".to_string(),
                ja4: "".to_string(),
                sni: None,
                alpn: vec![],
            });
        }
        let v3 = net_003.evaluate(&e).expect("003 fires");
        assert_eq!(v3.severity, Severity::Critical);
        assert_eq!(v3.category, CATEGORY_CRITICAL);

        let _ = rules; // keep the imports honest
    }

    // ════════════════════════════════════════════════════════════════
    // Tappa 10.5 D4 — new rules NN-L-NET-010/011/018/019 (stateless)
    // + NN-L-NET-013 (stateful beacon). Per §13 Q8: stateless rules
    // get positive/negative/allowlist coverage; the stateful beacon
    // gets bespoke timing pairs.
    // ════════════════════════════════════════════════════════════════

    fn flow_pid(pid: u32, dst: IpAddr, dst_port: u16, comm: &str, start_ns: u64) -> Event {
        Event::NetFlow(NetFlowEvent {
            start_ns,
            end_ns: start_ns + 1_000,
            family: if dst.is_ipv4() { 2 } else { 10 },
            src_addr: v4(192, 0, 2, 10),
            src_port: 54321,
            dst_addr: dst,
            dst_port,
            proto: 6,
            pid,
            uid: 1000,
            comm: comm.to_string(),
            exe: Some(format!("/usr/bin/{comm}")),
            bytes_sent: 1024,
            bytes_recv: 2048,
            resolved_hostname: None,
            tls_fingerprint: None,
            flow_id: "abc".to_string(),
            close_reason: 0,
        })
    }

    fn listener_bind(addr: IpAddr, port: u16, comm: &str) -> Event {
        Event::NetListener(NetListenerEvent {
            timestamp_ns: 100,
            family: if addr.is_ipv4() { 2 } else { 10 },
            bind_addr: addr,
            bind_port: port,
            proto: 6,
            pid: 5555,
            uid: 1000,
            comm: comm.to_string(),
            exe: Some(format!("/usr/bin/{comm}")),
        })
    }

    // ── NN-L-NET-010 — high-risk C2 port ────────────────────────────

    #[test]
    fn net_010_fires_on_c2_port_non_allowlist() {
        let rule = NnLNet010OutboundToHighRiskC2Port::new(al());
        let v = rule
            .evaluate(&flow(v4(8, 8, 8, 8), 4444, "evilbin"))
            .expect("4444 + evilbin must fire");
        assert_eq!(v.severity, Severity::High);
        assert_eq!(v.action, ResponseAction::KillProcess);
    }

    #[test]
    fn net_010_does_not_fire_on_common_port_or_allowlist() {
        let rule = NnLNet010OutboundToHighRiskC2Port::new(al());
        // 443 is not a high-risk port.
        assert!(rule
            .evaluate(&flow(v4(8, 8, 8, 8), 443, "evilbin"))
            .is_none());
        // 4444 but allowlisted comm (curl is in the default union).
        assert!(rule.evaluate(&flow(v4(8, 8, 8, 8), 4444, "curl")).is_none());
    }

    // ── NN-L-NET-011 — plaintext-cred service ───────────────────────

    #[test]
    fn net_011_fires_on_plaintext_port_non_allowlist() {
        let rule = NnLNet011PlaintextCredService::new(al());
        for port in [21, 23] {
            let v = rule
                .evaluate(&flow(v4(203, 0, 113, 5), port, "evilbin"))
                .unwrap_or_else(|| panic!("port {port} must fire"));
            assert_eq!(v.severity, Severity::Medium);
            assert_eq!(v.action, ResponseAction::Log);
        }
    }

    #[test]
    fn net_011_does_not_fire_on_non_plaintext_or_allowlist() {
        let rule = NnLNet011PlaintextCredService::new(al());
        assert!(rule
            .evaluate(&flow(v4(203, 0, 113, 5), 443, "evilbin"))
            .is_none());
        assert!(rule
            .evaluate(&flow(v4(203, 0, 113, 5), 21, "ssh"))
            .is_none());
    }

    // ── NN-L-NET-018 — RFC1918 lateral-movement port ────────────────

    #[test]
    fn net_018_fires_on_rfc1918_lateral_port_non_allowlist() {
        let rule = NnLNet018Rfc1918LateralPort::new(al());
        for port in [445, 3389, 5985, 5900] {
            let v = rule
                .evaluate(&flow(v4(10, 0, 0, 9), port, "evilbin"))
                .unwrap_or_else(|| panic!("RFC1918:{port} must fire"));
            assert_eq!(v.severity, Severity::High);
            assert_eq!(v.action, ResponseAction::KillProcess);
        }
    }

    #[test]
    fn net_018_does_not_fire_on_public_dst_or_nonlateral_or_allowlist() {
        let rule = NnLNet018Rfc1918LateralPort::new(al());
        // Public dst on a lateral port — not internal, so -018 abstains.
        assert!(rule
            .evaluate(&flow(v4(8, 8, 8, 8), 445, "evilbin"))
            .is_none());
        // RFC1918 but a non-lateral port.
        assert!(rule
            .evaluate(&flow(v4(10, 0, 0, 9), 443, "evilbin"))
            .is_none());
        // RFC1918 lateral port but allowlisted comm.
        assert!(rule
            .evaluate(&flow(v4(10, 0, 0, 9), 445, "rsync"))
            .is_none());
    }

    // ── NN-L-NET-019 — wildcard-bind listener ───────────────────────

    #[test]
    fn net_019_fires_on_wildcard_uncommon_port_non_allowlist() {
        let rule = NnLNet019WildcardListener::new(al());
        let v = rule
            .evaluate(&listener_bind(v4(0, 0, 0, 0), 4444, "evilbin"))
            .expect("0.0.0.0:4444 + evilbin must fire");
        assert_eq!(v.severity, Severity::Medium);
        assert_eq!(v.action, ResponseAction::Log);
        // IPv6 wildcard also matches.
        assert!(rule
            .evaluate(&listener_bind(
                IpAddr::V6(Ipv6Addr::UNSPECIFIED),
                4444,
                "evilbin"
            ))
            .is_some());
    }

    #[test]
    fn net_019_does_not_fire_on_loopback_common_port_or_allowlist() {
        let rule = NnLNet019WildcardListener::new(al());
        // Loopback bind is not wildcard-exposed — -019 abstains (-006
        // handles the non-wildcard uncommon-port case).
        assert!(rule
            .evaluate(&listener_bind(v4(127, 0, 0, 1), 4444, "evilbin"))
            .is_none());
        // Wildcard but common port.
        assert!(rule
            .evaluate(&listener_bind(v4(0, 0, 0, 0), 443, "evilbin"))
            .is_none());
        // Wildcard uncommon port but allowlisted comm.
        assert!(rule
            .evaluate(&listener_bind(v4(0, 0, 0, 0), 4444, "nginx"))
            .is_none());
    }

    // ── NN-L-NET-013 — beacon detector (bespoke stateful pairs) ─────

    const SEC: u64 = 1_000_000_000;

    #[test]
    fn net_013_fires_on_low_jitter_periodic_flow() {
        let rule = NnLNet013Beacon::new(Arc::new(Mutex::new(BeaconWindow::new())), al());
        let dst = v4(203, 0, 113, 7);
        // Five flows exactly 60s apart (zero jitter). The first
        // BEACON_MIN_SAMPLES-1 don't have enough samples; the 4th+
        // should detect the beacon.
        let mut fired = false;
        for i in 0..5u64 {
            let r = rule.evaluate(&flow_pid(4242, dst, 443, "evilbin", i * 60 * SEC));
            if r.is_some() {
                fired = true;
            }
        }
        assert!(fired, "periodic low-jitter flow must trip the beacon");
    }

    #[test]
    fn net_013_does_not_fire_on_high_jitter_flow() {
        let rule = NnLNet013Beacon::new(Arc::new(Mutex::new(BeaconWindow::new())), al());
        let dst = v4(203, 0, 113, 7);
        // Irregular intervals (10s, 600s, 5s, 700s, 12s) — a legit
        // bursty / cron-with-random-sleep pattern, high CV.
        let starts = [0u64, 10, 610, 615, 1315, 1327];
        let mut fired = false;
        for s in starts {
            if rule
                .evaluate(&flow_pid(4242, dst, 443, "evilbin", s * SEC))
                .is_some()
            {
                fired = true;
            }
        }
        assert!(!fired, "high-jitter flow must NOT trip the beacon");
    }

    #[test]
    fn net_013_does_not_fire_on_too_few_flows() {
        let rule = NnLNet013Beacon::new(Arc::new(Mutex::new(BeaconWindow::new())), al());
        let dst = v4(203, 0, 113, 7);
        // Only 3 flows (< BEACON_MIN_SAMPLES) — never enough to judge.
        for i in 0..3u64 {
            assert!(rule
                .evaluate(&flow_pid(4242, dst, 443, "evilbin", i * 60 * SEC))
                .is_none());
        }
    }

    #[test]
    fn net_013_respects_per_pid_and_per_dst_isolation() {
        let rule = NnLNet013Beacon::new(Arc::new(Mutex::new(BeaconWindow::new())), al());
        let dst = v4(203, 0, 113, 7);
        // Interleave two PIDs each with too few flows for their own
        // (pid,dst) key — neither should fire even though the COMBINED
        // event count exceeds the threshold.
        let mut fired = false;
        for i in 0..3u64 {
            for pid in [100u32, 200u32] {
                if rule
                    .evaluate(&flow_pid(pid, dst, 443, "evilbin", i * 60 * SEC))
                    .is_some()
                {
                    fired = true;
                }
            }
        }
        assert!(
            !fired,
            "per-(pid,dst) isolation must prevent a cross-PID false beacon"
        );
    }

    #[test]
    fn net_013_skips_allowlisted_comm() {
        let rule = NnLNet013Beacon::new(Arc::new(Mutex::new(BeaconWindow::new())), al());
        let dst = v4(203, 0, 113, 7);
        // chronyd is a legitimate periodic client — allowlisted, so
        // even a perfectly periodic pattern never fires.
        for i in 0..6u64 {
            assert!(rule
                .evaluate(&flow_pid(4242, dst, 443, "chronyd", i * 60 * SEC))
                .is_none());
        }
    }
    #[test]
    fn dns_burst_window_evicts_idle_pids() {
        let mut w = DnsBurstWindow::new();
        let t0: u64 = 1_000 * 1_000_000_000;
        // 5000 distinct PIDs, one query each, all at t0: the soft cap
        // (4096) is exceeded, so the next observe at t0 + 61 s must
        // sweep every one of them (their newest sample is outside the
        // 60 s window).
        for pid in 1..=5_000u32 {
            w.observe(pid, t0);
        }
        assert!(w.tracked_keys() >= 4096);
        let later = t0 + 61 * 1_000_000_000;
        w.observe(7, later);
        assert_eq!(w.tracked_keys(), 1, "only the live PID must remain");
        assert_eq!(w.observe(7, later + 1), 2);
    }

    #[test]
    fn dns_burst_window_periodic_sweep_without_cap() {
        let mut w = DnsBurstWindow::new();
        let t0: u64 = 1_000 * 1_000_000_000;
        for pid in 1..=100u32 {
            w.observe(pid, t0);
        }
        assert_eq!(w.tracked_keys(), 100);
        // Drive the observe counter across a multiple of
        // STATEFUL_EVICT_EVERY with a single live PID far in the future.
        let later = t0 + 120 * 1_000_000_000;
        for _ in 0..STATEFUL_EVICT_EVERY {
            w.observe(42, later);
        }
        assert_eq!(w.tracked_keys(), 1);
    }

    #[test]
    fn beacon_window_evicts_idle_flows() {
        let mut w = BeaconWindow::new();
        let t0: u64 = 10_000 * 1_000_000_000;
        let dst: IpAddr = "203.0.113.9".parse().unwrap();
        for pid in 1..=5_000u32 {
            w.observe(pid, dst, t0);
        }
        assert!(w.tracked_keys() >= 4096);
        let later = t0 + BEACON_WINDOW_NS + 1;
        w.observe(1, dst, later);
        assert_eq!(w.tracked_keys(), 1, "only the live flow must remain");
    }

    // ── external audit NET-010 (NN-AUD-006) — allowlist by exec identity ──

    /// The shipped allowlist judged on exec identity, with `execs`
    /// ingested as the exec sensor would (pid, exe, argv).
    fn identity_al(execs: &[(u32, &str, &[&str])]) -> (tempfile::TempDir, Arc<CommAllowlist>) {
        let tmp = tempfile::TempDir::new().unwrap();
        let t = crate::posture::lineage::AuthSessionTracker::new(tmp.path());
        for (pid, exe, argv) in execs {
            let argv: Vec<String> = argv.iter().map(|a| a.to_string()).collect();
            t.ingest_spawn_with_argv(*pid, 1, exe, &argv, 1);
        }
        (tmp, Arc::new(al().as_ref().clone().with_identity(t)))
    }

    fn with_pid(mut e: Event, pid: u32) -> Event {
        match &mut e {
            Event::NetFlow(nf) => nf.pid = pid,
            Event::NetListener(nl) => nl.pid = pid,
            _ => {}
        }
        e
    }

    #[test]
    fn a_spoofed_comm_no_longer_suppresses_the_network_rules() {
        let (_tmp, al) = identity_al(&[
            // python renamed to `nginx` with prctl: an inline program
            (500, "/usr/bin/python3.12", &["python3", "-c", "x"]),
            // the real nginx
            (501, "/usr/sbin/nginx", &["nginx"]),
        ]);
        let listen = NnLNet006UncommonListener::new(Arc::clone(&al));
        let v = listen
            .evaluate(&with_pid(listener(31337, "nginx"), 500))
            .expect("a listener named nginx that is not nginx fires");
        assert!(v.reasoning.contains("named 'nginx'"), "{}", v.reasoning);
        assert!(listen
            .evaluate(&with_pid(listener(31337, "nginx"), 501))
            .is_none());

        // NN-L-NET-010 (KillProcess): never seen → recorded, not acted on
        let c2 = NnLNet010OutboundToHighRiskC2Port::new(Arc::clone(&al));
        let v = c2
            .evaluate(&with_pid(flow(v4(198, 51, 100, 7), 4444, "curl"), 599))
            .expect("fires");
        assert_eq!(v.action, ResponseAction::Log);
        assert!(v.reasoning.contains("could not be read"), "{}", v.reasoning);
        // the same send from a process that is not curl is acted on
        let (_tmp2, al2) = identity_al(&[(600, "/tmp/curl", &["/tmp/curl"])]);
        let v = NnLNet010OutboundToHighRiskC2Port::new(al2)
            .evaluate(&with_pid(flow(v4(198, 51, 100, 7), 4444, "curl"), 600))
            .expect("fires");
        assert_eq!(v.action, ResponseAction::KillProcess);
        assert!(v.reasoning.contains("something else"), "{}", v.reasoning);
    }
}
