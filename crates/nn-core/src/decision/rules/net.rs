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
//! External audit NET-019: the §6.5 pacing sits in the net drain, per
//! uid, before any rule runs, so it cannot read a verdict's tier; it
//! instead never holds back a flow that meets the predicate of a rule
//! that kills ([`may_meet_a_kill_rule`]: NN-L-NET-001, -002, -003,
//! -008, -010, -018) or of a process with a chain precursor.
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
use std::hash::{BuildHasher, Hash, RandomState};
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};

use nn_model::telemetry::FlowPhase;
use nn_model::{Event, ResponseAction, Severity, Verdict};
use parking_lot::Mutex;

use crate::config::comm_allowlist::{CommAllowlist, Judgement};
use crate::decision::attack::{AttackRef, Tactic};
use crate::decision::bounded::{LazyLru, LossCounter};
use crate::decision::host::DecisionHost;
use crate::decision::Rule;
use crate::net::blocklist::{Ja3Blocklist, NetBlocklist};
use crate::net::dns_cache::DnsCache;
use crate::posture::host::PostureHost;

// ── Category tags ────────────────────────────────────────────────────

/// Critical-tier NetFlow rules — NEVER throttled by the §6.5
/// rate limiter per §13 Q4 lock-in (see the module docs for how the
/// per-uid pacing keeps that).
pub const CATEGORY_CRITICAL: &str = "net_critical";
/// High-tier NetFlow rules.
pub const CATEGORY_HIGH: &str = "net_high";
/// Medium-tier NetFlow rules.
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

/// Common ports for NN-L-NET-006 / -019: a listener on one of these is
/// not flagged when its program is one root installed
/// ([`common_port_service`]).
///
/// External audit NETR-015 (NN-AUD-298): the port alone used to exempt
/// it, so any process of any user serving 8080 or 8443 — a binary from
/// `/tmp`, `python3 /tmp/x.py` — was never recorded.
const LISTENER_COMMON_PORTS: &[u16] = &[22, 53, 80, 443, 8080, 8443];

/// Blocked TLD list for NN-L-NET-002. Hard-coded V1.0 set;
/// operator-tunable in V1.1.
const BLOCKED_TLDS: &[&str] = &[".onion", ".bit"];

/// NN-L-NET-009 — byte-count threshold for "anomalously
/// large flow." 100 MiB = 104_857_600 bytes.
const HIGH_VOLUME_BYTES_SENT: u64 = 100 * 1024 * 1024;

// ── Tappa 10.5 D4 port sets ──────────────────────────────────────────

/// NN-L-NET-010 — high-risk C2 / tooling default ports. A flow to
/// one of these from a non-allowlisted comm is a strong C2 indicator
/// (T1571 Non-Standard Port). 4444 Metasploit default, 1080 SOCKS,
/// 6667/6697 IRC (classic botnet C2), 9001 Tor OR.
///
/// External audit NETR-015 asked for 443 here too. Not done: this rule
/// kills, so 443 (or any common port) would kill every client outside the
/// comm allowlist. C2 over 443 is answered by the destination (-001,
/// -002), the image (-008), the beacon (-013) and the chains
/// (NN-L-CHAIN-002/005/007).
const HIGH_RISK_C2_PORTS: &[u16] = &[4444, 1080, 6667, 6697, 9001];

/// NN-L-NET-011 — plaintext-credential service ports: FTP (21) +
/// Telnet (23). Both transmit credentials in the clear (T1071).
const PLAINTEXT_CRED_PORTS: &[u16] = &[21, 23];

/// NN-L-NET-018 — lateral-movement service ports reached over an
/// internal destination (RFC 1918, IPv6 ULA or link-local): 445 SMB, 3389 RDP, 5985 WinRM,
/// 5900 VNC (T1021 Remote Services).
const LATERAL_MOVEMENT_PORTS: &[u16] = &[445, 3389, 5985, 5900];

// ── DNS qtypes (RFC 1035 + RFC 4034) ─────────────────────────────────

const DNS_QTYPE_TXT: u16 = 16;
const DNS_QTYPE_NULL: u16 = 10;

// ── NN-L-NET-005 burst-window state ──────────────────────────────────

/// Sliding window for NN-L-NET-005.
const DNS_BURST_WINDOW_NS: u64 = 60 * 1_000_000_000;

/// Idle-key sweep cadence for the stateful windows below: every N
/// observes, drop every key whose newest sample has left its window
/// (audit `catchall-1`).
///
/// External audit NETR-005: the sweep also ran on EVERY observe once a map
/// held more than 4096 keys, and dropped only idle keys, so the "cap" was
/// none: a connection spray by any user grew the map for an hour and made
/// every flow pay a full scan under the rule's mutex. The sweep is now
/// periodic only, and each window has a hard cap enforced in O(1) by a
/// recency queue ([`LazyLru`]): at the cap the least recently updated key
/// goes. An active beacon or burst refreshes its key on every sample, so a
/// spray's one-shot keys go first; a key evicted while still inside its
/// window is counted ([`LossCounter`]) and WARNed at most once a minute.
const STATEFUL_EVICT_EVERY: u32 = 256;

/// NN-L-NET-005: PIDs tracked at once.
pub const DNS_BURST_MAX_PIDS: usize = 4096;
/// NN-L-NET-013: `(pid, dst)` pairs tracked at once.
pub const BEACON_MAX_FLOWS: usize = 16_384;
/// NN-L-NET-013: destinations tracked per PID. A process reaching hundreds
/// of destinations within the hour is a scanner or a crawler, not a beacon;
/// beyond the quota its own least recently used destination goes (and is
/// counted), so it cannot push other processes' keys out.
pub const BEACON_MAX_DSTS_PER_PID: usize = 256;
/// NN-L-NET-013: at eviction, up to this many keys holding two samples or
/// more (a beacon in the making) are moved to the back instead, so a
/// spray of one-shot destinations goes first. Bounded: O(1) per insert.
const BEACON_SECOND_CHANCES: usize = 8;

static DNS_BURST_LIVE_EVICTIONS: AtomicU64 = AtomicU64::new(0);
static BEACON_LIVE_EVICTIONS: AtomicU64 = AtomicU64::new(0);
static BEACON_QUOTA_EVICTIONS: AtomicU64 = AtomicU64::new(0);
static DNS_TUNNEL_LIVE_EVICTIONS: AtomicU64 = AtomicU64::new(0);

/// External audit NETR-005: keys still inside their window that the
/// network rule windows evicted for room, process-wide (NN-L-NET-005,
/// NN-L-NET-013, NN-L-NET-014's corroboration), plus NN-L-NET-013's
/// per-process quota evictions.
pub fn net_window_evictions_total() -> u64 {
    DNS_BURST_LIVE_EVICTIONS.load(Ordering::Relaxed)
        + BEACON_LIVE_EVICTIONS.load(Ordering::Relaxed)
        + BEACON_QUOTA_EVICTIONS.load(Ordering::Relaxed)
        + DNS_TUNNEL_LIVE_EVICTIONS.load(Ordering::Relaxed)
        // Lab PR 224: the fan-out windows (NN-L-NET-026/027).
        + super::net_fanout::fanout_window_evictions_total()
}

/// Per-key sliding windows of sample timestamps, in recency order.
struct TimedWindows<K> {
    map: HashMap<K, VecDeque<u64>>,
    order: LazyLru<K>,
}

impl<K> Default for TimedWindows<K> {
    fn default() -> Self {
        Self {
            map: HashMap::new(),
            order: LazyLru::default(),
        }
    }
}

impl<K: Copy + Eq + Hash> TimedWindows<K> {
    fn len(&self) -> usize {
        self.map.len()
    }

    fn contains(&self, key: &K) -> bool {
        self.map.contains_key(key)
    }

    /// Drop every key whose newest sample is older than `cutoff`, telling
    /// `on_drop` about each one.
    fn sweep(&mut self, cutoff: u64, mut on_drop: impl FnMut(&K)) {
        let Self { map, order } = self;
        map.retain(|k, q| {
            let keep = q.back().is_some_and(|&t| t >= cutoff);
            if !keep {
                order.remove(k);
                on_drop(k);
            }
            keep
        });
    }

    /// Remove the least recently sampled key; `true` with it when its
    /// newest sample is still at or after `cutoff` (state that mattered).
    fn pop_oldest(&mut self, cutoff: u64) -> Option<(K, bool)> {
        let key = self.order.pop_oldest()?;
        let live = self
            .map
            .remove(&key)
            .is_some_and(|q| q.back().is_some_and(|&t| t >= cutoff));
        Some((key, live))
    }

    fn remove(&mut self, key: &K) {
        self.map.remove(key);
        self.order.remove(key);
    }

    /// [`Self::pop_oldest`], but up to `chances` keys for which `keep`
    /// holds are moved to the back first.
    fn pop_oldest_sparing(
        &mut self,
        cutoff: u64,
        chances: usize,
        keep: impl Fn(&VecDeque<u64>) -> bool,
    ) -> Option<(K, bool)> {
        for _ in 0..chances {
            let key = self.order.pop_oldest()?;
            if self.map.get(&key).is_some_and(&keep) {
                self.order.touch(key);
            } else {
                let live = self
                    .map
                    .remove(&key)
                    .is_some_and(|q| q.back().is_some_and(|&t| t >= cutoff));
                return Some((key, live));
            }
        }
        self.pop_oldest(cutoff)
    }

    fn samples(&self, key: &K) -> usize {
        self.map.get(key).map_or(0, VecDeque::len)
    }

    /// Add a sample for `key` at `ts_ns` (moving it to the back of the
    /// recency order), drop its samples older than `cutoff`, and return
    /// its window.
    fn sample(&mut self, key: K, ts_ns: u64, cutoff: u64) -> &mut VecDeque<u64> {
        self.order.touch(key);
        let q = self.map.entry(key).or_default();
        while q.front().is_some_and(|&t| t < cutoff) {
            q.pop_front();
        }
        q.push_back(ts_ns);
        q
    }
}

/// 60-second per-PID TXT/NULL query counter. NN-L-NET-005 fires
/// when `count > 50` for a given PID over a sliding 60s window.
pub struct DnsBurstWindow {
    per_pid: TimedWindows<u32>,
    observes: u32,
    lost: LossCounter,
}

impl Default for DnsBurstWindow {
    fn default() -> Self {
        Self {
            per_pid: TimedWindows::default(),
            observes: 0,
            lost: LossCounter::new(&DNS_BURST_LIVE_EVICTIONS),
        }
    }
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
        if self.observes.is_multiple_of(STATEFUL_EVICT_EVERY) {
            self.per_pid.sweep(cutoff, |_| {});
        }
        if !self.per_pid.contains(&pid) {
            while self.per_pid.len() >= DNS_BURST_MAX_PIDS {
                let Some((victim, live)) = self.per_pid.pop_oldest(cutoff) else {
                    break;
                };
                if live && self.lost.bump() {
                    tracing::warn!(
                        pid = victim,
                        evicted = self.lost.count(),
                        cap = DNS_BURST_MAX_PIDS,
                        "NN-L-NET-005 window full: evicted a process still inside \
                         its 60 s TXT/NULL window"
                    );
                }
            }
        }
        self.per_pid.sample(pid, ts_ns, cutoff).len()
    }

    /// Number of PIDs currently tracked (test/metrics hook).
    pub fn tracked_keys(&self) -> usize {
        self.per_pid.len()
    }

    /// Live keys evicted for room by this window.
    pub fn live_evictions(&self) -> u64 {
        self.lost.count()
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
pub struct BeaconWindow {
    per_flow: TimedWindows<(u32, IpAddr)>,
    /// The destinations each PID holds in `per_flow`, in recency order
    /// (external audit NETR-005: the per-process quota).
    per_pid: HashMap<u32, LazyLru<IpAddr>>,
    observes: u32,
    lost: LossCounter,
    over_quota: LossCounter,
}

impl Default for BeaconWindow {
    fn default() -> Self {
        Self {
            per_flow: TimedWindows::default(),
            per_pid: HashMap::new(),
            observes: 0,
            lost: LossCounter::new(&BEACON_LIVE_EVICTIONS),
            over_quota: LossCounter::new(&BEACON_QUOTA_EVICTIONS),
        }
    }
}

impl BeaconWindow {
    pub fn new() -> Self {
        Self::default()
    }

    /// Forget `dst` in `pid`'s quota, and the PID once it holds none.
    fn forget_dst(per_pid: &mut HashMap<u32, LazyLru<IpAddr>>, pid: u32, dst: &IpAddr) {
        if let Some(l) = per_pid.get_mut(&pid) {
            l.remove(dst);
            if l.is_empty() {
                per_pid.remove(&pid);
            }
        }
    }

    /// Make room for a new `(pid, dst)` key: first within `pid`'s quota,
    /// then under the global cap.
    fn make_room(&mut self, pid: u32, cutoff: u64) {
        if let Some(l) = self.per_pid.get_mut(&pid) {
            while l.len() >= BEACON_MAX_DSTS_PER_PID {
                let mut victim = None;
                for _ in 0..=BEACON_SECOND_CHANCES {
                    let Some(old) = l.pop_oldest() else { break };
                    victim = Some(old);
                    if self.per_flow.samples(&(pid, old)) < 2 {
                        break;
                    }
                    l.touch(old);
                }
                let Some(old) = victim else { break };
                l.remove(&old);
                self.per_flow.remove(&(pid, old));
                if self.over_quota.bump() {
                    tracing::debug!(
                        pid,
                        evicted = self.over_quota.count(),
                        quota = BEACON_MAX_DSTS_PER_PID,
                        "NN-L-NET-013: a process over its destination quota \
                         (scanner shape); its least recent destination dropped"
                    );
                }
            }
        }
        while self.per_flow.len() >= BEACON_MAX_FLOWS {
            let Some(((vpid, vdst), live)) =
                self.per_flow
                    .pop_oldest_sparing(cutoff, BEACON_SECOND_CHANCES, |q| q.len() >= 2)
            else {
                break;
            };
            Self::forget_dst(&mut self.per_pid, vpid, &vdst);
            if live && self.lost.bump() {
                tracing::warn!(
                    pid = vpid,
                    evicted = self.lost.count(),
                    cap = BEACON_MAX_FLOWS,
                    "NN-L-NET-013 window full: evicted a destination still inside \
                     its one-hour window"
                );
            }
        }
    }

    /// Record an outbound flow start for `(pid, dst)` at `ts_ns` and
    /// report whether the pair now exhibits a low-jitter periodic
    /// pattern. Returns `false` until at least [`BEACON_MIN_SAMPLES`]
    /// flows have accumulated within [`BEACON_WINDOW_NS`].
    pub fn observe(&mut self, pid: u32, dst: IpAddr, ts_ns: u64) -> bool {
        let cutoff = ts_ns.saturating_sub(BEACON_WINDOW_NS);
        self.observes = self.observes.wrapping_add(1);
        if self.observes.is_multiple_of(STATEFUL_EVICT_EVERY) {
            let per_pid = &mut self.per_pid;
            self.per_flow
                .sweep(cutoff, |(p, d)| Self::forget_dst(per_pid, *p, d));
        }
        if !self.per_flow.contains(&(pid, dst)) {
            self.make_room(pid, cutoff);
        }
        self.per_pid
            .entry(pid)
            .or_insert_with(|| LazyLru::with_compact_floor(4))
            .touch(dst);
        let q = self.per_flow.sample((pid, dst), ts_ns, cutoff);
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

    /// Live keys evicted under the global cap.
    pub fn live_evictions(&self) -> u64 {
        self.lost.count()
    }

    /// Keys dropped by the per-process quota.
    pub fn quota_evictions(&self) -> u64 {
        self.over_quota.count()
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
    fn attack(&self) -> &'static [AttackRef] {
        const ATTACK: &[AttackRef] = &[
            AttackRef::new(Tactic::CommandAndControl, "T1071"),
            AttackRef::new(Tactic::CommandAndControl, "T1095"),
        ];
        ATTACK
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
    fn attack(&self) -> &'static [AttackRef] {
        const ATTACK: &[AttackRef] = &[AttackRef::new(Tactic::CommandAndControl, "T1090.003")];
        ATTACK
    }
    fn evaluate(&self, event: &Event) -> Option<Verdict> {
        let Event::NetFlow(nf) = event else {
            return None;
        };
        // Lab PR 224: every phase of a flow (connect, open snapshot,
        // close); a refused connect is NN-L-NET-001's alone.
        if nf.phase == FlowPhase::Denied {
            return None;
        }
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
    fn attack(&self) -> &'static [AttackRef] {
        const ATTACK: &[AttackRef] = &[AttackRef::new(Tactic::CommandAndControl, "T1573.002")];
        ATTACK
    }
    fn evaluate(&self, event: &Event) -> Option<Verdict> {
        let Event::NetFlow(nf) = event else {
            return None;
        };
        // Lab PR 224: judged on the closed flow only (byte counts, or a
        // record the netflow pacing applies to), once.
        if nf.phase != FlowPhase::Closed {
            return None;
        }
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
/// External audit NET-017 (lab PR 207): `net::blind_spots` tells the local
/// resolver's DNS-over-TLS rows from the other processes' with it.
pub fn sender_is_forwarder(exe: Option<&str>) -> bool {
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
fn attribute_dns_query<I: Default>(
    dns_cache: &DnsCache<I>,
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
// (-014 entropy, -004 long name) inspect only the qname, so every one
// of those events yields an IDENTICAL verdict targeting the originator —
// the live finding saw ONE `getent` raise 8 NN-L-NET-004 verdicts (4
// direct+forwarded pairs ~130 ms apart). This layer collapses them: at
// most ONE verdict per (attributed originator, qname) per window, from
// the two rules together (external audit NETR-016: [`net_rules`] hands
// both the same window).
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

/// External audit NETR-012: `(pid, qname)` pairs the dedup window holds
/// at once.
pub const DNS_QNAME_DEDUP_MAX_PAIRS: usize = 4096;

/// External audit NETR-012: the keys of [`hash_qname`], drawn once per
/// process.
static QNAME_HASH_KEYS: OnceLock<RandomState> = OnceLock::new();

/// Hash a qname (or one of its labels) to a `u64` key half: the dedup
/// window's, and NN-L-NET-014's corroboration's for the parent domain and
/// the first label. Keying on a hash keeps the keys `Copy` and
/// allocation-free on the hot path — no owned `String` per suspicious
/// event.
///
/// External audit NETR-012: this was `DefaultHasher::new()`, SipHash with
/// fixed keys, so anyone could compute offline a name that collides with
/// another and have its verdict dropped as a repeat. The keys are now
/// random, drawn once per process ([`RandomState`]): the mapping is stable
/// within the process and cannot be computed outside it. The state is
/// in-memory and per-engine, so nothing needs it stable across restarts.
fn hash_qname(qname: &str) -> u64 {
    QNAME_HASH_KEYS
        .get_or_init(RandomState::new)
        .hash_one(qname)
}

/// FP-5 dedup state for the qname-shape rules (NN-L-NET-004/-014).
/// Mirrors the [`DnsBurstWindow`] / `CronEditWindow` stateful-rule
/// precedent: `&mut self` behind an `Arc<Mutex<_>>`, clocked by the
/// event-carried `timestamp_ns` (no syscall clock — the rule stays a pure
/// function of the event + its own state).
///
/// External audit NETR-016: the two rules share ONE window
/// ([`net_rules`]). Since lab PR 140 -014 runs before -004, so when -014
/// dropped a repeated leg as a duplicate it returned `None` and the
/// first-match engine handed the leg to -004, which recorded it: two
/// records per lookup for a long high-entropy name. With one window, a
/// name either rule answered is not answered again within the window.
///
/// External audit NETR-012: the map used to be swept in full on every
/// call and had no bound but the window. It is swept every
/// [`STATEFUL_EVICT_EVERY`] calls, a lookup compares the stored time (an
/// entry past the window never suppresses a verdict), and at
/// [`DNS_QNAME_DEDUP_MAX_PAIRS`] the pair fired least recently goes
/// ([`LazyLru`]). Losing a pair costs at most one repeated record, never
/// a verdict, so the evictions are not counted with the windows' losses
/// ([`net_window_evictions_total`]).
#[derive(Default)]
pub struct DnsQnameDedupWindow {
    /// `(attributed_originator_pid, qname_hash)` → ns of the last verdict
    /// FIRED for it. The value is the `u64` hash, not the qname `String`,
    /// so the key is `Copy` and never allocates.
    last_fired: HashMap<(u32, u64), u64>,
    /// The pairs of `last_fired`, least recently fired first.
    order: LazyLru<(u32, u64)>,
    observes: u32,
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
    /// being silenced outright.
    pub fn observe(&mut self, pid: u32, qname_hash: u64, ts_ns: u64) -> bool {
        let in_window = |last: u64| ts_ns.saturating_sub(last) < DNS_QNAME_DEDUP_WINDOW_NS;
        self.observes = self.observes.wrapping_add(1);
        if self.observes.is_multiple_of(STATEFUL_EVICT_EVERY) {
            let Self {
                last_fired, order, ..
            } = self;
            last_fired.retain(|k, &mut last| {
                let keep = in_window(last);
                if !keep {
                    order.remove(k);
                }
                keep
            });
        }
        let key = (pid, qname_hash);
        match self.last_fired.get(&key) {
            Some(&last) if in_window(last) => return false,
            Some(_) => {}
            None => {
                while self.last_fired.len() >= DNS_QNAME_DEDUP_MAX_PAIRS {
                    let Some(victim) = self.order.pop_oldest() else {
                        break;
                    };
                    self.last_fired.remove(&victim);
                }
            }
        }
        self.last_fired.insert(key, ts_ns);
        self.order.touch(key);
        true
    }

    /// Pairs currently held (test/metrics hook).
    pub fn tracked_pairs(&self) -> usize {
        self.last_fired.len()
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
pub const DNS_TUNNEL_MAX_PAIRS: usize = 4096;

type TunnelPair = (u32, u64);

/// External audit NETR-002: a DNS tunnel (iodine, dnscat2, exfiltration
/// over DNS) carries its payload in a NEW label per query — dozens a
/// second under the attacker's domain. A host resolves a UUID-named bucket
/// or a hashed load-balancer name a handful of times: one high-entropy
/// label is not a tunnel (the lab killed `python3` for
/// `my-company-prod-backups-archive.s3.amazonaws.com`, 4.0 bits/char).
///
/// External audit NETR-005: once 4096 pairs were held, a new pair was
/// judged on its own (1) — and the map was swept on every call. About 70
/// high-entropy queries a second under distinct parent domains kept it
/// full, and NN-L-NET-014's kill never fired for anyone else. A new pair
/// is never refused now: at the bound the least recently updated pair
/// holding a single label goes first (a spray's one-shot pairs), then the
/// least recently updated pair of several labels, counted. A tunnel
/// refreshes its pair on every query.
pub struct DnsTunnelCorroboration {
    /// `(attributed pid, parent-domain hash)` → `(first seen ns, label
    /// hash)` of the distinct labels in the window, at most
    /// [`DNS_TUNNEL_DISTINCT_LABELS`].
    seen: HashMap<TunnelPair, Vec<(u64, u64)>>,
    /// Pairs holding one label, in recency order.
    single: LazyLru<TunnelPair>,
    /// Pairs holding several labels, in recency order.
    multi: LazyLru<TunnelPair>,
    observes: u32,
    lost: LossCounter,
}

impl Default for DnsTunnelCorroboration {
    fn default() -> Self {
        Self {
            seen: HashMap::new(),
            single: LazyLru::default(),
            multi: LazyLru::default(),
            observes: 0,
            lost: LossCounter::new(&DNS_TUNNEL_LIVE_EVICTIONS),
        }
    }
}

impl DnsTunnelCorroboration {
    /// Record `label_hash` under `(pid, parent_hash)` at `ts_ns` and return
    /// how many distinct labels the pair has within the window, this one
    /// included.
    pub fn observe(&mut self, pid: u32, parent_hash: u64, label_hash: u64, ts_ns: u64) -> usize {
        let in_window = |t: u64| ts_ns.saturating_sub(t) < DNS_TUNNEL_WINDOW_NS;
        self.observes = self.observes.wrapping_add(1);
        if self.observes.is_multiple_of(STATEFUL_EVICT_EVERY) {
            let Self {
                seen,
                single,
                multi,
                ..
            } = self;
            seen.retain(|k, labels| {
                labels.retain(|(t, _)| in_window(*t));
                let keep = !labels.is_empty();
                if !keep {
                    single.remove(k);
                    multi.remove(k);
                }
                keep
            });
        }
        let key = (pid, parent_hash);
        if !self.seen.contains_key(&key) {
            while self.seen.len() >= DNS_TUNNEL_MAX_PAIRS {
                let victim = match self.single.pop_oldest() {
                    Some(k) => (k, false),
                    None => match self.multi.pop_oldest() {
                        Some(k) => (k, true),
                        None => break,
                    },
                };
                self.seen.remove(&victim.0);
                if victim.1 && self.lost.bump() {
                    tracing::warn!(
                        pid = victim.0 .0,
                        evicted = self.lost.count(),
                        cap = DNS_TUNNEL_MAX_PAIRS,
                        "NN-L-NET-014 corroboration full: evicted a process/domain \
                         pair holding several high-entropy labels"
                    );
                }
            }
        }
        let labels = self.seen.entry(key).or_default();
        labels.retain(|(t, _)| in_window(*t));
        if !labels.iter().any(|(_, h)| *h == label_hash) {
            if labels.len() >= DNS_TUNNEL_DISTINCT_LABELS {
                labels.remove(0);
            }
            labels.push((ts_ns, label_hash));
        }
        let n = labels.len();
        if n >= 2 {
            self.single.remove(&key);
            self.multi.touch(key);
        } else {
            self.multi.remove(&key);
            self.single.touch(key);
        }
        n
    }

    /// Pairs currently held (test/metrics hook).
    pub fn tracked_pairs(&self) -> usize {
        self.seen.len()
    }

    /// Pairs of several labels evicted for room.
    pub fn live_evictions(&self) -> u64 {
        self.lost.count()
    }
}

// ── NN-L-NET-004 — Suspicious DNS qname ──────────────────────────────

/// Unusually long DNS qname (> 60 chars), or a name sent in pieces,
/// recorded. Per design §7.
///
/// External audit NETR-002: this rule used to KILL the sender of any name
/// over 60 characters or whose first label was 20+ characters of the
/// base64 alphabet — which every LDH label of that length is: S3 buckets
/// and storage accounts, CDN and load-balancer names, Kubernetes service
/// and pod FQDNs, ACME challenges; its own tests killed `curl` and
/// `getent`. A label that carries an encoded payload is NN-L-NET-014's
/// (Shannon entropy over a ≥ 25-char label); length alone is recorded.
///
/// External audit NETR-016: -014 runs first (lab PR 140, PROC-009), so
/// this rule sees only the names -014 did not answer — a long name whose
/// first label is under 25 characters or of low entropy, a name sent in
/// pieces — and shares -014's dedup window, so one lookup gets one
/// verdict from the two.
///
/// FP-3: holds the shared `Arc<DnsCache>` so a forwarded-leg trip can be
/// back-correlated to the originating process — a verdict is never
/// attributed to the local stub resolver.
pub struct NnLNet004SuspiciousDnsQname<H: DecisionHost> {
    dns_cache: Arc<DnsCache<H::DnsIngest>>,
    /// FP-5: dedup of repeated (originator, qname) verdicts, shared with
    /// NN-L-NET-014 in [`net_rules`] (NETR-016).
    dedup: Arc<Mutex<DnsQnameDedupWindow>>,
}

impl<H: DecisionHost> NnLNet004SuspiciousDnsQname<H> {
    /// The rule with a dedup window of its own (tests).
    pub fn new(dns_cache: Arc<DnsCache<H::DnsIngest>>) -> Self {
        Self::with_dedup(dns_cache, Arc::new(Mutex::new(DnsQnameDedupWindow::new())))
    }

    /// External audit NETR-016: the rule over `dedup`, the window
    /// NN-L-NET-014 holds too.
    pub fn with_dedup(
        dns_cache: Arc<DnsCache<H::DnsIngest>>,
        dedup: Arc<Mutex<DnsQnameDedupWindow>>,
    ) -> Self {
        Self { dns_cache, dedup }
    }
}

impl<H: DecisionHost> Rule for NnLNet004SuspiciousDnsQname<H> {
    fn id(&self) -> &'static str {
        "NN-L-NET-004_SuspiciousDnsQname"
    }
    fn name(&self) -> &'static str {
        "Unusually long DNS qname (recorded)"
    }
    fn category(&self) -> &'static str {
        CATEGORY_HIGH
    }
    fn attack(&self) -> &'static [AttackRef] {
        const ATTACK: &[AttackRef] = &[AttackRef::new(Tactic::CommandAndControl, "T1071.004")];
        ATTACK
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
        // NETR-016: the window is -014's too, so a leg -014 dropped as a
        // repeat of its own verdict is dropped here as well.
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
    fn attack(&self) -> &'static [AttackRef] {
        const ATTACK: &[AttackRef] = &[AttackRef::new(Tactic::CommandAndControl, "T1071.004")];
        ATTACK
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

// ── NN-L-NET-006 / -019 — the common-port exemption (NETR-015) ───────

/// External audit NETR-015 (NN-AUD-298): whether a listener on one of the
/// [`LISTENER_COMMON_PORTS`] is a service a root-owned tree installed
/// ([`ExecIdentity::is_installed_program`]: the executable, and the script
/// an interpreter runs, in a system tree), so NN-L-NET-006 and -019 leave
/// it alone. `None`: not a common port. `Some(false)`: a common port
/// served by any other program — a binary from `/tmp` or a home,
/// `python3 /tmp/x.py`, `python3 -m http.server`, a program whose
/// executable cannot be read — which the rules judge as on any other
/// port. nginx, sshd or named on their usual ports stay quiet.
///
/// The identity is read from the process lineage (the spawn cache, else
/// `/proc`; the listener record carries no executable). With no lineage
/// (tests, the boot-time rule set) the record's own `exe` is judged, and
/// with none either the port alone exempts, as before.
///
/// [`ExecIdentity::is_installed_program`]: crate::posture::lineage::ExecIdentity::is_installed_program
fn common_port_service<H: PostureHost>(
    nl: &nn_model::telemetry::NetListenerEvent,
    lineage: Option<&crate::posture::lineage::AuthSessionTracker<H>>,
) -> Option<bool> {
    if !LISTENER_COMMON_PORTS.contains(&nl.bind_port) {
        return None;
    }
    let identity = match lineage {
        Some(t) => t.exec_identity(nl.pid),
        None => match nl.exe.as_deref() {
            Some(exe) => Some(crate::posture::lineage::ExecIdentity {
                exe: exe.into(),
                script: None,
            }),
            None => return Some(true),
        },
    };
    Some(identity.is_some_and(|id| id.is_installed_program()))
}

/// Where NN-L-NET-006 / -019 say the listener is: on a common port, why
/// that did not exempt it (NETR-015).
fn listener_port_text(nl: &nn_model::telemetry::NetListenerEvent, common: bool) -> String {
    if common {
        format!(
            "on port {}, a common service port, from a program not installed in a \
             root-owned system tree (its executable, or the script an interpreter runs, \
             lies elsewhere or cannot be read)",
            nl.bind_port
        )
    } else {
        "on an uncommon port".to_string()
    }
}

// ── NN-L-NET-006 — New listener on uncommon port ─────────────────────

/// New TCP listener on a port outside the common ports — or on one of
/// them from a program outside the root-owned system trees (external
/// audit NETR-015, [`common_port_service`]) — AND from a comm outside the
/// listener-allowlist. Forensic signal (Q6 lock-in: track every listener;
/// rule-side filter here).
pub struct NnLNet006UncommonListener<H: PostureHost> {
    allowlist: Arc<CommAllowlist<H>>,
    /// NETR-015: where the common-port exemption reads the listener's
    /// program. `None`: the record's `exe`.
    lineage: Option<crate::posture::lineage::AuthSessionTracker<H>>,
}

impl<H: PostureHost> NnLNet006UncommonListener<H> {
    pub fn new(allowlist: Arc<CommAllowlist<H>>) -> Self {
        Self {
            allowlist,
            lineage: None,
        }
    }

    /// External audit NETR-015: the common-port exemption judged on the
    /// program `lineage` reports for the listener.
    pub fn with_lineage(
        mut self,
        lineage: Option<crate::posture::lineage::AuthSessionTracker<H>>,
    ) -> Self {
        self.lineage = lineage;
        self
    }
}

impl<H: PostureHost> Rule for NnLNet006UncommonListener<H> {
    fn id(&self) -> &'static str {
        "NN-L-NET-006_UncommonListener"
    }
    fn name(&self) -> &'static str {
        "New listener on uncommon port"
    }
    fn category(&self) -> &'static str {
        CATEGORY_MEDIUM
    }
    fn attack(&self) -> &'static [AttackRef] {
        const ATTACK: &[AttackRef] = &[AttackRef::new(Tactic::CommandAndControl, "T1571")];
        ATTACK
    }
    fn evaluate(&self, event: &Event) -> Option<Verdict> {
        let Event::NetListener(nl) = event else {
            return None;
        };
        let common = common_port_service(nl, self.lineage.as_ref());
        if common == Some(true) {
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
                &format!(
                    "Process opened a TCP listener {} without operator allowlist coverage \
                     — posture → ALERTED",
                    listener_port_text(nl, common.is_some())
                ),
                nl.pid,
                nl.comm.clone(),
                nl.timestamp_ns,
            ),
            &nl.comm,
        ))
    }
}

// ── NN-L-NET-007 — Outbound to RFC1918 from unusual process ──────────

/// Outbound to internal address space (RFC 1918 10/8, 172.16/12,
/// 192.168/16; IPv6 ULA fc00::/7 and link-local fe80::/10) from a comm
/// not in the internal-ops allowlist — lateral-movement indicator.
pub struct NnLNet007Rfc1918FromUnusualProc<H: PostureHost> {
    allowlist: Arc<CommAllowlist<H>>,
}

impl<H: PostureHost> NnLNet007Rfc1918FromUnusualProc<H> {
    pub fn new(allowlist: Arc<CommAllowlist<H>>) -> Self {
        Self { allowlist }
    }

    /// External audit NETR-007: RFC 1918, IPv6 unique-local and
    /// link-local — IPv6 used to be never internal, so lateral movement
    /// over ULA or link-local drew neither this rule nor NN-L-NET-018.
    fn is_internal(addr: &IpAddr) -> bool {
        nn_model::netaddr::is_internal(*addr)
    }
}

impl<H: PostureHost> Rule for NnLNet007Rfc1918FromUnusualProc<H> {
    fn id(&self) -> &'static str {
        "NN-L-NET-007_Rfc1918FromUnusualProc"
    }
    fn name(&self) -> &'static str {
        "Outbound to RFC1918 from non-allowlist process"
    }
    fn category(&self) -> &'static str {
        CATEGORY_MEDIUM
    }
    fn attack(&self) -> &'static [AttackRef] {
        const ATTACK: &[AttackRef] = &[
            AttackRef::new(Tactic::LateralMovement, "T1021"),
            AttackRef::new(Tactic::Discovery, "T1046"),
        ];
        ATTACK
    }
    fn evaluate(&self, event: &Event) -> Option<Verdict> {
        let Event::NetFlow(nf) = event else {
            return None;
        };
        // Lab PR 224: judged on the closed flow only (byte counts, or a
        // record the netflow pacing applies to), once.
        if nf.phase != FlowPhase::Closed {
            return None;
        }
        if !Self::is_internal(&nf.dst_addr) {
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
                "Outbound to an internal destination (RFC 1918, IPv6 ULA or \
             link-local) from a comm outside the operator allowlist — possible lateral movement; \
             posture → ALERTED",
                nf.pid,
                nf.comm.clone(),
                nf.start_ns,
            ),
            &nf.comm,
        ))
    }
}

// ── NN-L-NET-008 — Outbound from a staging-directory exec ───────────

/// The connecting process's image lies under a staging directory
/// ([`STAGING_PREFIXES`](crate::decision::rules::STAGING_PREFIXES):
/// `/tmp/`, `/var/tmp/`, `/dev/shm/`) and the flow goes to a port other
/// than 53. Pairs with R001–R003 on the network side — a dropper reaching
/// out for its second stage.
///
/// External audit NETR-008: no production flow row carried `exe`, so this
/// rule returned at its first line and never fired, and it checked
/// `/tmp/` only. R001–R003 kill the process that ran the exec, not its
/// tree: a dropper that forks first leaves a child that never execs —
/// no exec event, no `TmpExec` precursor — running the staged image, and
/// its egress went unjudged. The image is now named at connect time
/// (`AuthSessionTracker::image_path`, spawn cache then `/proc`), with the
/// lineage cache as a fallback here for a row without one. A process of a
/// package transaction (the review-49 carve-out) is recorded, not killed.
///
/// Lab PR 175: the carve-out trusted any process with a package manager
/// or `mandb` in its lineage, whoever ran it and however long ago. `mandb`
/// and the package managers are not set-id: a user ran one with
/// `LD_PRELOAD`, had it fork a program from `/tmp`, and that program's
/// call out was recorded instead of killed. It is now the transaction of
/// the FIM rules' carve-out
/// ([`AuthSessionTracker::in_package_transaction`](crate::posture::lineage::AuthSessionTracker::in_package_transaction)):
/// a package manager proper executed by root whose run covers the
/// connect.
///
/// Lab PR 224 (CM-02 d, research defect D1): the one flow left alone used
/// to be any flow to port 53, whatever the protocol and the server — an
/// implant with its C2 on TCP/53 passed. It is now a flow to the DNS port
/// (UDP or TCP) of a resolver the host is configured with
/// ([`crate::net::resolvers::is_resolver_flow`]). Judged at the connect
/// and on open-flow snapshots too. The new match — port 53 of a server
/// that is no configured resolver — has its kill held behind the per-rule
/// policy ([`crate::decision::response_policy::PORT_53_KILL`], off).
pub struct NnLNet008OutboundFromTmpExec<H: PostureHost> {
    lineage: Option<crate::posture::lineage::AuthSessionTracker<H>>,
    resolvers: Arc<crate::net::resolvers::HostResolvers>,
}

impl<H: PostureHost> NnLNet008OutboundFromTmpExec<H> {
    /// With no configured resolver: no port-53 flow is exempt.
    pub fn new(lineage: Option<crate::posture::lineage::AuthSessionTracker<H>>) -> Self {
        Self {
            lineage,
            resolvers: crate::net::resolvers::HostResolvers::none(),
        }
    }

    /// Lab PR 224: the resolvers whose DNS port a staged image may reach.
    pub fn with_resolvers(mut self, resolvers: Arc<crate::net::resolvers::HostResolvers>) -> Self {
        self.resolvers = resolvers;
        self
    }
}

impl<H: PostureHost> Rule for NnLNet008OutboundFromTmpExec<H> {
    fn id(&self) -> &'static str {
        "NN-L-NET-008_OutboundFromTmpExec"
    }
    fn name(&self) -> &'static str {
        "Outbound from a staging-directory exec to non-resolver"
    }
    fn category(&self) -> &'static str {
        CATEGORY_HIGH
    }
    fn attack(&self) -> &'static [AttackRef] {
        const ATTACK: &[AttackRef] = &[AttackRef::new(Tactic::CommandAndControl, "T1105")];
        ATTACK
    }
    fn evaluate(&self, event: &Event) -> Option<Verdict> {
        let Event::NetFlow(nf) = event else {
            return None;
        };
        // Lab PR 224: every phase of a flow (connect, open snapshot,
        // close); a refused connect is NN-L-NET-001's alone.
        if nf.phase == FlowPhase::Denied {
            return None;
        }
        if crate::net::resolvers::is_resolver_flow(nf, &self.resolvers) {
            return None;
        }
        let looked_up;
        let exe = match nf.exe.as_deref() {
            Some(exe) => exe,
            None => {
                looked_up = self.lineage.as_ref()?.image_path(nf.pid)?;
                looked_up.as_str()
            }
        };
        if !crate::decision::rules::is_staging_path(exe) {
            return None;
        }
        if self
            .lineage
            .as_ref()
            .is_some_and(|l| l.in_package_transaction(nf.pid, nf.start_ns))
        {
            return Some(net_verdict(
                self,
                ResponseAction::Log,
                Severity::High,
                "Process running from a staging directory (/tmp, /var/tmp, /dev/shm) \
                 opened an outbound flow other than a lookup at a configured resolver; \
                 it runs in a package transaction \
                 (a package manager executed by root, still running or just ended), \
                 so it is recorded, not killed",
                nf.pid,
                nf.comm.clone(),
                nf.start_ns,
            ));
        }
        let v = net_verdict(
            self,
            ResponseAction::KillProcess,
            Severity::High,
            "Process running from a staging directory (/tmp, /var/tmp, /dev/shm) \
             initiated outbound other than a lookup at a configured resolver — likely \
             dropper fetching second-stage payload or C2 (TCP/53 to its own server \
             included); kill the process + posture → ENGAGED",
            nf.pid,
            nf.comm.clone(),
            nf.start_ns,
        );
        // Port 53 was exempt before lab PR 224: its kill there is held behind
        // the per-rule policy (off by default); the other ports kill as before.
        Some(crate::decision::response_policy::hold_port_53(nf, v))
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
pub struct NnLNet009ByteAnomaly<H: PostureHost> {
    allowlist: Arc<CommAllowlist<H>>,
    udp: Mutex<UdpVolume>,
}

impl<H: PostureHost> NnLNet009ByteAnomaly<H> {
    pub fn new(allowlist: Arc<CommAllowlist<H>>) -> Self {
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

impl<H: PostureHost> Rule for NnLNet009ByteAnomaly<H> {
    fn id(&self) -> &'static str {
        "NN-L-NET-009_ByteAnomaly"
    }
    fn name(&self) -> &'static str {
        "Flow byte-count anomaly (possible exfiltration)"
    }
    fn category(&self) -> &'static str {
        CATEGORY_HIGH
    }
    fn attack(&self) -> &'static [AttackRef] {
        const ATTACK: &[AttackRef] = &[
            AttackRef::new(Tactic::Exfiltration, "T1048"),
            AttackRef::new(Tactic::Exfiltration, "T1041"),
        ];
        ATTACK
    }
    fn evaluate(&self, event: &Event) -> Option<Verdict> {
        let Event::NetFlow(nf) = event else {
            return None;
        };
        // Lab PR 224: judged on the closed flow only (byte counts, or a
        // record the netflow pacing applies to), once.
        if nf.phase != FlowPhase::Closed {
            return None;
        }
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
pub struct NnLNet010OutboundToHighRiskC2Port<H: PostureHost> {
    allowlist: Arc<CommAllowlist<H>>,
}

impl<H: PostureHost> NnLNet010OutboundToHighRiskC2Port<H> {
    pub fn new(allowlist: Arc<CommAllowlist<H>>) -> Self {
        Self { allowlist }
    }
}

impl<H: PostureHost> Rule for NnLNet010OutboundToHighRiskC2Port<H> {
    fn id(&self) -> &'static str {
        "NN-L-NET-010_OutboundToHighRiskC2Port"
    }
    fn name(&self) -> &'static str {
        "Outbound to high-risk C2 port"
    }
    fn category(&self) -> &'static str {
        CATEGORY_HIGH
    }
    fn attack(&self) -> &'static [AttackRef] {
        const ATTACK: &[AttackRef] = &[
            AttackRef::new(Tactic::CommandAndControl, "T1571"),
            AttackRef::new(Tactic::CommandAndControl, "T1090"),
        ];
        ATTACK
    }
    fn evaluate(&self, event: &Event) -> Option<Verdict> {
        let Event::NetFlow(nf) = event else {
            return None;
        };
        // Lab PR 224: every phase of a flow (connect, open snapshot,
        // close); a refused connect is NN-L-NET-001's alone.
        if nf.phase == FlowPhase::Denied {
            return None;
        }
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
pub struct NnLNet011PlaintextCredService<H: PostureHost> {
    allowlist: Arc<CommAllowlist<H>>,
}

impl<H: PostureHost> NnLNet011PlaintextCredService<H> {
    pub fn new(allowlist: Arc<CommAllowlist<H>>) -> Self {
        Self { allowlist }
    }
}

impl<H: PostureHost> Rule for NnLNet011PlaintextCredService<H> {
    fn id(&self) -> &'static str {
        "NN-L-NET-011_PlaintextCredService"
    }
    fn name(&self) -> &'static str {
        "Plaintext-credential service flow (FTP/Telnet)"
    }
    fn category(&self) -> &'static str {
        CATEGORY_MEDIUM
    }
    fn attack(&self) -> &'static [AttackRef] {
        const ATTACK: &[AttackRef] = &[
            AttackRef::new(Tactic::CommandAndControl, "T1071.002"),
            AttackRef::new(Tactic::LateralMovement, "T1021"),
        ];
        ATTACK
    }
    fn evaluate(&self, event: &Event) -> Option<Verdict> {
        let Event::NetFlow(nf) = event else {
            return None;
        };
        // Lab PR 224: judged on the closed flow only (byte counts, or a
        // record the netflow pacing applies to), once.
        if nf.phase != FlowPhase::Closed {
            return None;
        }
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
pub struct NnLNet013Beacon<H: PostureHost> {
    window: Arc<Mutex<BeaconWindow>>,
    allowlist: Arc<CommAllowlist<H>>,
}

impl<H: PostureHost> NnLNet013Beacon<H> {
    pub fn new(window: Arc<Mutex<BeaconWindow>>, allowlist: Arc<CommAllowlist<H>>) -> Self {
        Self { window, allowlist }
    }
}

impl<H: PostureHost> Rule for NnLNet013Beacon<H> {
    fn id(&self) -> &'static str {
        "NN-L-NET-013_Beacon"
    }
    fn name(&self) -> &'static str {
        "Periodic outbound beacon (low jitter)"
    }
    fn category(&self) -> &'static str {
        CATEGORY_HIGH
    }
    fn attack(&self) -> &'static [AttackRef] {
        const ATTACK: &[AttackRef] = &[
            AttackRef::new(Tactic::CommandAndControl, "T1071"),
            AttackRef::new(Tactic::Exfiltration, "T1029"),
        ];
        ATTACK
    }
    fn evaluate(&self, event: &Event) -> Option<Verdict> {
        let Event::NetFlow(nf) = event else {
            return None;
        };
        // Lab PR 224: judged on the closed flow only (byte counts, or a
        // record the netflow pacing applies to), once.
        if nf.phase != FlowPhase::Closed {
            return None;
        }
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

/// Outbound to an internal destination (RFC 1918, IPv6 ULA or
/// link-local; external audit NETR-007) on a lateral-movement service
/// port ([`LATERAL_MOVEMENT_PORTS`]) from a non-allowlisted
/// comm. MITRE T1021 (Remote Services). High + KillProcess — the
/// port-specific High refinement of the broad Medium NN-L-NET-007
/// (§13 Q10 documents the intentional overlap; this rule is ordered
/// BEFORE -007 so the High verdict wins for the lateral-port case).
pub struct NnLNet018Rfc1918LateralPort<H: PostureHost> {
    allowlist: Arc<CommAllowlist<H>>,
}

impl<H: PostureHost> NnLNet018Rfc1918LateralPort<H> {
    pub fn new(allowlist: Arc<CommAllowlist<H>>) -> Self {
        Self { allowlist }
    }
}

impl<H: PostureHost> Rule for NnLNet018Rfc1918LateralPort<H> {
    fn id(&self) -> &'static str {
        "NN-L-NET-018_Rfc1918LateralPort"
    }
    fn name(&self) -> &'static str {
        "RFC1918 outbound on lateral-movement port"
    }
    fn category(&self) -> &'static str {
        CATEGORY_HIGH
    }
    fn attack(&self) -> &'static [AttackRef] {
        const ATTACK: &[AttackRef] = &[
            AttackRef::new(Tactic::LateralMovement, "T1021.002"),
            AttackRef::new(Tactic::LateralMovement, "T1021.001"),
            AttackRef::new(Tactic::LateralMovement, "T1021.006"),
            AttackRef::new(Tactic::LateralMovement, "T1021.005"),
        ];
        ATTACK
    }
    fn evaluate(&self, event: &Event) -> Option<Verdict> {
        let Event::NetFlow(nf) = event else {
            return None;
        };
        // Lab PR 224: every phase of a flow (connect, open snapshot,
        // close); a refused connect is NN-L-NET-001's alone.
        if nf.phase == FlowPhase::Denied {
            return None;
        }
        if !NnLNet007Rfc1918FromUnusualProc::<H>::is_internal(&nf.dst_addr) {
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
                "Outbound to an internal host (RFC 1918, IPv6 ULA or link-local) \
             on a lateral-movement port (445 SMB / 3389 RDP / 5985 WinRM / 5900 VNC) from a \
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
pub struct NnLNet019WildcardListener<H: PostureHost> {
    allowlist: Arc<CommAllowlist<H>>,
    /// NETR-015: as NN-L-NET-006's.
    lineage: Option<crate::posture::lineage::AuthSessionTracker<H>>,
}

impl<H: PostureHost> NnLNet019WildcardListener<H> {
    pub fn new(allowlist: Arc<CommAllowlist<H>>) -> Self {
        Self {
            allowlist,
            lineage: None,
        }
    }

    /// External audit NETR-015: as
    /// [`NnLNet006UncommonListener::with_lineage`].
    pub fn with_lineage(
        mut self,
        lineage: Option<crate::posture::lineage::AuthSessionTracker<H>>,
    ) -> Self {
        self.lineage = lineage;
        self
    }

    fn is_wildcard(addr: &IpAddr) -> bool {
        match addr {
            IpAddr::V4(v4) => v4.is_unspecified(),
            IpAddr::V6(v6) => v6.is_unspecified(),
        }
    }
}

impl<H: PostureHost> Rule for NnLNet019WildcardListener<H> {
    fn id(&self) -> &'static str {
        "NN-L-NET-019_WildcardListener"
    }
    fn name(&self) -> &'static str {
        "Wildcard-bind listener on uncommon port"
    }
    fn category(&self) -> &'static str {
        CATEGORY_MEDIUM
    }
    fn attack(&self) -> &'static [AttackRef] {
        const ATTACK: &[AttackRef] = &[AttackRef::new(Tactic::CommandAndControl, "T1571")];
        ATTACK
    }
    fn evaluate(&self, event: &Event) -> Option<Verdict> {
        let Event::NetListener(nl) = event else {
            return None;
        };
        if !Self::is_wildcard(&nl.bind_addr) {
            return None;
        }
        let common = common_port_service(nl, self.lineage.as_ref());
        if common == Some(true) {
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
                &format!(
                    "New listener bound to the wildcard address {} from a non-allowlisted \
                     comm — network-exposed backdoor surface (T1571); posture → ALERTED",
                    listener_port_text(nl, common.is_some())
                ),
                nl.pid,
                nl.comm.clone(),
                nl.timestamp_ns,
            ),
            &nl.comm,
        ))
    }
}

// ── NN-L-NET-020 — DNS query flood (review 78) ─────────────────────

/// Window over which the flood rules sum held-back records.
const FLOOD_WINDOW_NS: u64 = 10 * 1_000_000_000;
/// Held-back records in a window that make a flood rule fire.
const FLOOD_MIN_HELD: u64 = 256;
/// Keys tracked at most per flood rule; when full, ended windows go.
const FLOOD_MAX_KEYS: usize = 4096;

/// Per-key sums of records a kernel budget held back, over
/// [`FLOOD_WINDOW_NS`] windows (review 78; shared with NN-L-NET-021 since
/// external audit EBPF-013). key → (window start, held, fired).
struct HeldWindows<K> {
    map: Mutex<HashMap<K, (u64, u64, bool)>>,
}

impl<K: Eq + Hash> HeldWindows<K> {
    fn new() -> Self {
        Self {
            map: Mutex::new(HashMap::new()),
        }
    }

    /// Add `held` to `key`'s window; `Some(sum)` the first time the window
    /// reaches [`FLOOD_MIN_HELD`].
    fn add(&self, key: K, held: u32, timestamp_ns: u64) -> Option<u64> {
        let mut map = self.map.lock();
        if map.len() >= FLOOD_MAX_KEYS && !map.contains_key(&key) {
            map.retain(|_, w| timestamp_ns.saturating_sub(w.0) < FLOOD_WINDOW_NS);
            if map.len() >= FLOOD_MAX_KEYS {
                map.clear();
            }
        }
        let w = map.entry(key).or_insert((timestamp_ns, 0, false));
        if timestamp_ns.saturating_sub(w.0) >= FLOOD_WINDOW_NS {
            *w = (timestamp_ns, 0, false);
        }
        w.1 += u64::from(held);
        if w.2 || w.1 < FLOOD_MIN_HELD {
            return None;
        }
        w.2 = true;
        Some(w.1)
    }
}

/// NN-L-NET-020 — a process, or a user across its processes, sent DNS
/// queries well beyond the kernel's DNS budget (review 78). The queries
/// over the budget are not recorded, so the DNS rules (NN-L-NET-004,
/// -005, -014) never see them: a flood could carry a tunnel. Within the
/// budget (64 queries, then 128 per second, per process; 2,048 then 1,024
/// per second per user) every query is recorded; beyond it, the process
/// is reported here (MITRE T1071.004). The local resolvers' users are
/// exempt in the kernel.
pub struct NnLNet020DnsQueryFlood {
    /// (uid, pid — 0 for the user's budget).
    held: HeldWindows<(u32, u32)>,
}

impl NnLNet020DnsQueryFlood {
    pub fn new() -> Self {
        Self {
            held: HeldWindows::new(),
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
    fn attack(&self) -> &'static [AttackRef] {
        const ATTACK: &[AttackRef] = &[AttackRef::new(Tactic::CommandAndControl, "T1071.004")];
        ATTACK
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
        let sum = self.held.add(key, *held, *timestamp_ns)?;
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

// ── NN-L-NET-021 — listener / io_uring record flood (EBPF-013) ──────

/// NN-L-NET-021 — external audit EBPF-013: a process, or a user across
/// its processes, called `listen()` or `io_uring_setup()` well beyond the
/// kernel's record budget for that sensor. Both sensors share a small ring
/// with other records (the listener ring; the io_uring activity records),
/// so an unprivileged loop could push another process's records out and
/// leave only an anonymous drop counter. The kernel now records every
/// call within the budget (64, then 128 per second, per process; 512,
/// then 256 per second, per user), holds back the rest, and the next
/// record carries the count. This rule names the process that floods
/// (ATT&CK T1685 Disable or Modify Tools, its `attack()`: T1562.006
/// Indicator Blocking until v19).
///
/// One rule for both sensors: the mechanism, the threshold and the
/// response are the same, and the verdict names the sensor. Kept apart
/// from NN-L-NET-020, whose reasoning is DNS-specific (a hidden tunnel).
pub struct NnLNet021SensorRecordFlood {
    /// (sensor, uid, pid — 0 for the user's budget).
    held: HeldWindows<(nn_model::FloodSource, u32, u32)>,
}

impl NnLNet021SensorRecordFlood {
    pub fn new() -> Self {
        Self {
            held: HeldWindows::new(),
        }
    }
}

impl Default for NnLNet021SensorRecordFlood {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for NnLNet021SensorRecordFlood {
    fn id(&self) -> &'static str {
        "NN-L-NET-021_SensorRecordFlood"
    }
    fn name(&self) -> &'static str {
        "listen() or io_uring_setup() calls beyond the kernel's record budget"
    }
    fn category(&self) -> &'static str {
        CATEGORY_HIGH
    }
    fn attack(&self) -> &'static [AttackRef] {
        const ATTACK: &[AttackRef] = &[AttackRef::new(Tactic::DefenseImpairment, "T1685")];
        ATTACK
    }
    fn evaluate(&self, event: &Event) -> Option<Verdict> {
        let Event::SensorFlood {
            source,
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
        let key = (*source, *uid, if *uid_level { 0 } else { *pid });
        let sum = self.held.add(key, *held, *timestamp_ns)?;
        let scope = if *uid_level { "its user's" } else { "its own" };
        let (calls, records) = match source {
            nn_model::FloodSource::Listen => ("listen() calls", "listener records"),
            nn_model::FloodSource::IoUringCreate => {
                ("io_uring_setup() calls", "io_uring ring-creation records")
            }
        };
        Some(net_verdict(
            self,
            ResponseAction::Log,
            Severity::High,
            &format!(
                "{comm} (pid {pid}, uid {uid}) made at least {sum} {calls} beyond {scope} \
                 record budget within 10 seconds: those calls were not recorded, and a flood \
                 like this can push other processes' {records} out of the kernel ring"
            ),
            *pid,
            comm.clone(),
            *timestamp_ns,
        ))
    }
}

// ── NN-L-NET-014 — DNS qname high-entropy label (tunnelling) ────────

/// DNS-tunnelling detector (MITRE T1071.004). It measures the **Shannon
/// entropy** of the leftmost label (25 characters or more), whatever its
/// alphabet: hex, base32, base64 or a custom one. Encoded/compressed exfil
/// payloads pack near-maximal per-character entropy; ordinary hostnames
/// (even long CDN ones) sit well below the threshold.
///
/// External audit NETR-016: since lab PR 140 (PROC-009) this rule runs
/// before NN-L-NET-004, whatever the name's length. It records a single
/// high-entropy label and kills the sender of a tunnel's shape
/// ([`DNS_TUNNEL_DISTINCT_LABELS`] distinct labels under one parent domain
/// within [`DNS_TUNNEL_WINDOW_NS`]); -004 records the long names and the
/// names sent in pieces it did not answer. The two share one dedup window
/// ([`DnsQnameDedupWindow`]), so a lookup's legs give one verdict.
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
pub struct NnLNet014DnsTunnelEntropy<H: DecisionHost> {
    dns_cache: Arc<DnsCache<H::DnsIngest>>,
    /// FP-5: dedup of repeated (originator, qname) verdicts, shared with
    /// NN-L-NET-004 in [`net_rules`] (NETR-016).
    dedup: Arc<Mutex<DnsQnameDedupWindow>>,
    /// External audit NETR-002: distinct high-entropy labels per
    /// (originator, parent domain) — the kill needs a tunnel's volume.
    corroboration: Arc<Mutex<DnsTunnelCorroboration>>,
}

impl<H: DecisionHost> NnLNet014DnsTunnelEntropy<H> {
    /// The rule with a dedup window of its own (tests).
    pub fn new(dns_cache: Arc<DnsCache<H::DnsIngest>>) -> Self {
        Self::with_dedup(dns_cache, Arc::new(Mutex::new(DnsQnameDedupWindow::new())))
    }

    /// External audit NETR-016: the rule over `dedup`, the window
    /// NN-L-NET-004 holds too.
    pub fn with_dedup(
        dns_cache: Arc<DnsCache<H::DnsIngest>>,
        dedup: Arc<Mutex<DnsQnameDedupWindow>>,
    ) -> Self {
        Self {
            dns_cache,
            dedup,
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

impl<H: DecisionHost> Rule for NnLNet014DnsTunnelEntropy<H> {
    fn id(&self) -> &'static str {
        "NN-L-NET-014_DnsTunnelEntropy"
    }
    fn name(&self) -> &'static str {
        "DNS qname high-entropy label (tunnelling)"
    }
    fn category(&self) -> &'static str {
        CATEGORY_HIGH
    }
    fn attack(&self) -> &'static [AttackRef] {
        const ATTACK: &[AttackRef] = &[AttackRef::new(Tactic::CommandAndControl, "T1071.004")];
        ATTACK
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
        // attributed pid + qname. NETR-016: the window is -004's too —
        // the repeated leg this drops falls through to -004, which drops
        // it as well instead of recording it. A repeat adds no label to
        // the corroboration, so dropping it before costs the kill nothing.
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

// ── NetFlow pacing guard (external audit NET-019) ───────────────────

/// External audit NET-019: whether a flow meets the predicate of a
/// NetFlow rule that kills — NN-L-NET-001 (blocklisted destination),
/// -002 (blocked TLD), -003 (any TLS fingerprint), -008 (image in a
/// staging directory, a lookup at a configured resolver included), -010
/// (high-risk C2 port), -018 (internal host on a lateral-movement port) —
/// allowlists and carve-outs aside, so a superset. The netflow drain never holds such a row back from the
/// rules (`net::limiter`). Kept next to the rules so a change to one of
/// these predicates is made here too; the test
/// `every_killing_netflow_verdict_is_guarded` checks the superset.
pub fn may_meet_a_kill_rule(
    nf: &nn_model::telemetry::NetFlowEvent,
    blocklist: &NetBlocklist,
) -> bool {
    if blocklist.contains(&nf.dst_addr) || nf.tls_fingerprint.is_some() {
        return true;
    }
    if nf.resolved_hostname.as_deref().is_some_and(|h| {
        let h = h.to_ascii_lowercase();
        BLOCKED_TLDS.iter().any(|tld| h.ends_with(tld))
    }) {
        return true;
    }
    if HIGH_RISK_C2_PORTS.contains(&nf.dst_port) {
        return true;
    }
    if LATERAL_MOVEMENT_PORTS.contains(&nf.dst_port) && nn_model::netaddr::is_internal(nf.dst_addr)
    {
        return true;
    }
    // Lab PR 224: a superset — the resolver exemption of NN-L-NET-008 is
    // not applied here, so a staged image's DNS flow is never held back.
    nf.exe
        .as_deref()
        .is_some_and(crate::decision::rules::is_staging_path)
}

// ── Factory ──────────────────────────────────────────────────────────

/// Lab PR 224: the host state and the thresholds the network and chain
/// rules read besides the operator lists: the configured resolvers (the
/// port-53 exemption of NN-L-NET-008 and NN-L-CHAIN-002/005) and the
/// fan-out thresholds (NN-L-NET-026/027).
#[derive(Clone)]
pub struct NetRuleConfig {
    pub resolvers: Arc<crate::net::resolvers::HostResolvers>,
    pub fanout: Arc<super::net_fanout::FanoutConfig>,
}

impl Default for NetRuleConfig {
    /// No configured resolver (no port-53 flow exempt) and the default
    /// thresholds: the boot-time and test rule sets.
    fn default() -> Self {
        Self {
            resolvers: crate::net::resolvers::HostResolvers::none(),
            fanout: Arc::new(super::net_fanout::FanoutConfig::default()),
        }
    }
}

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
/// NN-L-NET-019 before -006 — §13 Q10 documented overlaps). External
/// audit PROC-009: within an event type, every rule that kills comes
/// before any that only records — a record never stands in for a kill.
#[allow(clippy::too_many_arguments)]
pub fn net_rules<H: DecisionHost>(
    blocklist: Arc<NetBlocklist>,
    ja3_blocklist: Arc<Ja3Blocklist>,
    burst_window: Arc<Mutex<DnsBurstWindow>>,
    comm_allowlist: Arc<CommAllowlist<H>>,
    beacon_window: Arc<Mutex<BeaconWindow>>,
    dns_cache: Arc<DnsCache<H::DnsIngest>>,
    // External audit NETR-008: NN-L-NET-008's image fallback and its
    // package-manager carve-out. `None` (tests, boot-before-load): no
    // fallback and no carve-out.
    lineage: Option<crate::posture::lineage::AuthSessionTracker<H>>,
    // Lab PR 224: the resolvers and the fan-out thresholds.
    config: NetRuleConfig,
    // Lab PR 224: the ancestry the fan-out rules count a parent's children
    // through (the chains' store). `None`: per process only.
    correlation: Option<Arc<Mutex<crate::decision::correlation::CorrelationStore<H>>>>,
) -> Vec<Box<dyn Rule>> {
    let dns_shape_dedup = Arc::new(Mutex::new(DnsQnameDedupWindow::new()));
    let fanout = super::net_fanout::fanout_rules(super::net_fanout::FanoutContext::new(
        Arc::clone(&config.fanout),
        correlation,
        lineage.clone(),
    ));
    let mut rules: Vec<Box<dyn Rule>> = vec![
        // Critical first.
        Box::new(NnLNet001OutboundToBlockedIp::new(blocklist)),
        Box::new(NnLNet003BadJa3::new(ja3_blocklist)),
        // Tappa 10 High/DNS rules whose predicates don't overlap the
        // D4 additions. FP-3: -004/-014 take the shared DNS cache for
        // forwarder-aware originator back-correlation.
        Box::new(NnLNet002OutboundToBlockedTld),
        // Tappa 4.1 DNS observability refit — entropy-based tunnelling
        // detector, unblocked now the kprobe extracts the QNAME.
        // External audit PROC-009 (the same class, in the network rules):
        // ahead of -004 and -005, which only record. Behind -004 it never
        // saw a name over 60 characters — most tunnels' — so its
        // corroboration never reached the kill.
        // External audit NETR-016: one dedup window for the two, so one
        // lookup's legs give one verdict, not one from each.
        Box::new(NnLNet014DnsTunnelEntropy::<H>::with_dedup(
            Arc::clone(&dns_cache),
            Arc::clone(&dns_shape_dedup),
        )),
        Box::new(NnLNet004SuspiciousDnsQname::<H>::with_dedup(
            dns_cache,
            dns_shape_dedup,
        )),
        Box::new(NnLNet005DnsBurst::new(burst_window)),
        // Tappa 10.5 D4 additions — specific refinements ordered
        // BEFORE the broad Tappa 10 catch-alls (-006 / -007).
        // External audit PROC-009: every NetFlow rule that kills (-010,
        // -018, -008) before any that only records (-011, -013, -007,
        // -009): a staging-dir process reaching port 21, an internal host
        // or a beacon's period was recorded, not killed by -008, and a
        // beacon to a lateral port, by -018.
        Box::new(NnLNet010OutboundToHighRiskC2Port::new(Arc::clone(
            &comm_allowlist,
        ))),
        Box::new(NnLNet018Rfc1918LateralPort::new(Arc::clone(
            &comm_allowlist,
        ))),
        Box::new(
            NnLNet008OutboundFromTmpExec::new(lineage.clone())
                .with_resolvers(Arc::clone(&config.resolvers)),
        ),
    ];
    // Lab PR 224 (CM-14): the fan-out rules, which kill at their kill
    // tier, before the record-only rules; they read connect attempts and
    // UDP rows, which no rule above answers but for a kill.
    rules.extend(fanout);
    rules.extend::<Vec<Box<dyn Rule>>>(vec![
        Box::new(NnLNet011PlaintextCredService::new(Arc::clone(
            &comm_allowlist,
        ))),
        Box::new(NnLNet013Beacon::new(
            beacon_window,
            Arc::clone(&comm_allowlist),
        )),
        Box::new(
            NnLNet019WildcardListener::new(Arc::clone(&comm_allowlist))
                .with_lineage(lineage.clone()),
        ),
        // Review 78: no comm allowlist — the kernel exempts the resolvers.
        Box::new(NnLNet020DnsQueryFlood::new()),
        // External audit EBPF-013: no comm allowlist either — the budget
        // keeps every real listener and ring creation.
        Box::new(NnLNet021SensorRecordFlood::new()),
        // Broad Tappa 10 catch-alls last among the comm-gated rules.
        Box::new(NnLNet006UncommonListener::new(Arc::clone(&comm_allowlist)).with_lineage(lineage)),
        Box::new(NnLNet007Rfc1918FromUnusualProc::new(Arc::clone(
            &comm_allowlist,
        ))),
        Box::new(NnLNet009ByteAnomaly::new(comm_allowlist)),
    ]);
    rules
}

/// Empty-blocklist / default-allowlist convenience for boot + tests.
/// The comm allowlist is seeded from
/// [`NETFLOW_COMM_ALLOWLIST_DEFAULTS`] (the in-code mirror of the
/// shipped `configs/netflow-comm-allowlist.v1`) so the switch-over
/// from the former inline `const` sets is behaviour-preserving — the
/// same comms stay exempt with no operator file present. Production
/// `main.rs` instead loads the on-disk file via the D1 loader.
pub fn net_rules_empty<H: DecisionHost>() -> Vec<Box<dyn Rule>> {
    net_rules(
        Arc::new(NetBlocklist::empty()),
        Arc::new(Ja3Blocklist::empty()),
        Arc::new(Mutex::new(DnsBurstWindow::new())),
        Arc::new(CommAllowlist::<H>::from_iter_owned(
            NETFLOW_COMM_ALLOWLIST_DEFAULTS
                .iter()
                .map(|s| s.to_string()),
        )),
        Arc::new(Mutex::new(BeaconWindow::new())),
        Arc::new(DnsCache::default()),
        None,
        NetRuleConfig::default(),
        None,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    // R08b (lab PR 251): on the portable test host.
    use crate::posture::host::testing::TestHost as H;
    type CommAllowlist = crate::config::comm_allowlist::CommAllowlist<H>;
    type DnsCache = crate::net::dns_cache::DnsCache<()>;
    type NnLNet004SuspiciousDnsQname = super::NnLNet004SuspiciousDnsQname<H>;
    type NnLNet006UncommonListener = super::NnLNet006UncommonListener<H>;
    type NnLNet007Rfc1918FromUnusualProc = super::NnLNet007Rfc1918FromUnusualProc<H>;
    type NnLNet008OutboundFromTmpExec = super::NnLNet008OutboundFromTmpExec<H>;
    type NnLNet009ByteAnomaly = super::NnLNet009ByteAnomaly<H>;
    type NnLNet010OutboundToHighRiskC2Port = super::NnLNet010OutboundToHighRiskC2Port<H>;
    type NnLNet011PlaintextCredService = super::NnLNet011PlaintextCredService<H>;
    type NnLNet013Beacon = super::NnLNet013Beacon<H>;
    type NnLNet018Rfc1918LateralPort = super::NnLNet018Rfc1918LateralPort<H>;
    type NnLNet019WildcardListener = super::NnLNet019WildcardListener<H>;
    type NnLNet014DnsTunnelEntropy = super::NnLNet014DnsTunnelEntropy<H>;
    use nn_model::telemetry::{NetFlowEvent, NetListenerEvent, TlsFingerprint};
    use nn_model::ResponseAction;
    use std::net::{Ipv4Addr, Ipv6Addr};
    fn net_rules_empty() -> Vec<Box<dyn Rule>> {
        super::net_rules_empty::<H>()
    }

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
            proc_start_ns: 0,
            bytes_sent: 1024,
            bytes_recv: 2048,
            resolved_hostname: None,
            tls_fingerprint: None,
            flow_id: "abc".to_string(),
            close_reason: 0,
            phase: Default::default(),
            observed_ns: 0,
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
        cache.on_dns_query(5000, long.clone(), 1, [127, 0, 0, 53].into(), 1_000);
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
        cache.on_dns_query(8080, q.into(), 1, [127, 0, 0, 53].into(), 4_000);
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
        cache.on_dns_query(1122, long.clone(), 1, [127, 0, 0, 53].into(), 0);
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

    /// External audit NETR-016 (this test said the reverse before): -004
    /// and -014 share ONE dedup window in [`net_rules`]. A qname that trips
    /// both is answered by -014, which runs first; the next leg, which -014
    /// drops as a repeat and the first-match engine hands to -004, is
    /// dropped there too instead of becoming a second record.
    #[test]
    fn fp5_004_and_014_share_one_window() {
        let cache = Arc::new(DnsCache::default());
        let window = Arc::new(Mutex::new(DnsQnameDedupWindow::new()));
        let r14 = NnLNet014DnsTunnelEntropy::with_dedup(Arc::clone(&cache), Arc::clone(&window));
        let r4 = NnLNet004SuspiciousDnsQname::with_dedup(cache, window);
        // First label is long (>60 total) AND high-entropy → trips both.
        let q = "a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0u1v2w3x4y5z6.exfil.example.com";
        let leg = |ts| dns_event_full(1122, q, 1, "getent", Some("/usr/bin/getent"), ts);
        assert!(r14.evaluate(&leg(0)).is_some(), "-014 answers the lookup");
        assert!(r14.evaluate(&leg(5_000_000)).is_none(), "its repeat leg");
        assert!(
            r4.evaluate(&leg(5_000_000)).is_none(),
            "-004 does not record the leg -014 dropped"
        );
        // Each rule alone still records the name (separate windows).
        assert!(net_004().evaluate(&leg(0)).is_some());
        assert!(net_014().evaluate(&leg(0)).is_some());
    }

    // ── External audit NETR-012 — keyed hash, bounded dedup window ──────

    /// The qname hash is keyed per process: not the fixed-key mapping
    /// anyone can compute offline (`DefaultHasher::new()`), stable within
    /// the process, different under other keys.
    #[test]
    fn qname_hash_is_keyed_per_process() {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::Hasher;
        for q in [
            "a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6.exfil.example.com",
            "example.com",
            "",
        ] {
            let mut fixed = DefaultHasher::new();
            q.hash(&mut fixed);
            assert_ne!(hash_qname(q), fixed.finish(), "fixed keys for {q:?}");
            assert_eq!(hash_qname(q), hash_qname(q), "stable for {q:?}");
            let (a, b) = (RandomState::new(), RandomState::new());
            assert_ne!(a.hash_one(q), b.hash_one(q), "two key sets for {q:?}");
        }
    }

    /// A spray of distinct suspicious names keeps the window at its cap;
    /// a repeat inside the window is still dropped, one after it fires,
    /// and the periodic sweep empties what the window left behind.
    #[test]
    fn dedup_window_is_bounded_under_a_name_spray() {
        let mut w = DnsQnameDedupWindow::new();
        let t0 = 1_000_000_000u64;
        let n = 100_000u64;
        for i in 0..n {
            assert!(w.observe(7, hash_qname(&format!("{i}.spray.example")), t0 + i));
        }
        assert_eq!(w.tracked_pairs(), DNS_QNAME_DEDUP_MAX_PAIRS);
        let last = hash_qname(&format!("{}.spray.example", n - 1));
        let t_last = t0 + n - 1;
        assert!(!w.observe(7, last, t_last + 1), "a repeat inside 2 s");
        assert!(
            !w.observe(7, last, t_last + DNS_QNAME_DEDUP_WINDOW_NS - 1),
            "still inside"
        );
        assert!(
            w.observe(7, last, t_last + DNS_QNAME_DEDUP_WINDOW_NS),
            "a repeat after 2 s fires"
        );
        // Past the window, the next sweep drops every stale pair.
        let later = t_last + 3 * DNS_QNAME_DEDUP_WINDOW_NS;
        for i in 0..u64::from(STATEFUL_EVICT_EVERY) {
            w.observe(8, hash_qname(&format!("{i}.later.example")), later);
        }
        assert!(
            w.tracked_pairs() <= STATEFUL_EVICT_EVERY as usize,
            "{}",
            w.tracked_pairs()
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
        // IPv6 loopback is not internal address space.
        assert!(rule
            .evaluate(&flow(IpAddr::V6(Ipv6Addr::LOCALHOST), 443, "evilbin"))
            .is_none());
    }

    // ── external audit NETR-007 — IPv6 internal space ──

    #[test]
    fn net_018_fires_on_ula_lateral_port() {
        let rule = NnLNet018Rfc1918LateralPort::new(al());
        for (dst, port) in [
            ("fd00::2", 445),
            ("fe80::1", 3389),
            ("::ffff:10.0.0.5", 5985),
        ] {
            let v = rule
                .evaluate(&flow(dst.parse().unwrap(), port, "evilbin"))
                .unwrap_or_else(|| panic!("{dst}:{port} is lateral movement"));
            assert_eq!(v.action, ResponseAction::KillProcess);
        }
        // a global IPv6 peer is not internal
        assert!(rule
            .evaluate(&flow("2606:4700::1".parse().unwrap(), 445, "evilbin"))
            .is_none());
    }

    #[test]
    fn net_007_fires_on_link_local() {
        let rule = NnLNet007Rfc1918FromUnusualProc::new(al());
        let v = rule
            .evaluate(&flow("fe80::1".parse().unwrap(), 443, "evilbin"))
            .expect("link-local is internal");
        assert_eq!(v.severity, Severity::Medium);
        assert!(rule
            .evaluate(&flow("fd12:3456::7".parse().unwrap(), 8080, "evilbin"))
            .is_some());
        // CGNAT stays out (NET-011)
        assert!(rule
            .evaluate(&flow(v4(100, 64, 0, 1), 443, "evilbin"))
            .is_none());
    }

    // ── NN-L-NET-008 ─────────────────────────────────────────────

    #[test]
    fn net_008_fires_on_tmp_exec_outbound() {
        let rule = NnLNet008OutboundFromTmpExec::new(None);
        let mut e = flow(v4(1, 2, 3, 4), 443, "payload");
        if let Event::NetFlow(nf) = &mut e {
            nf.exe = Some("/tmp/payload".to_string());
        }
        let v = rule.evaluate(&e).expect("tmp-exec outbound");
        assert_eq!(v.severity, Severity::High);
    }

    /// Lab PR 224: a lookup at a configured resolver stays allowed.
    #[test]
    fn net_008_does_not_fire_on_tmp_exec_to_a_configured_resolver() {
        let rule = NnLNet008OutboundFromTmpExec::new(None).with_resolvers(
            crate::net::resolvers::HostResolvers::fixed([v4(1, 2, 3, 4)]),
        );
        let mut e = flow(v4(1, 2, 3, 4), 53, "payload");
        if let Event::NetFlow(nf) = &mut e {
            nf.exe = Some("/tmp/payload".to_string());
        }
        assert!(rule.evaluate(&e).is_none());
    }

    /// Lab PR 224 (research defect D1): TCP/53 from a staged image to a
    /// server the host is not configured with — an implant's C2 on the DNS
    /// port — fires; the starting tree let every port-53 flow through. That
    /// match is new: its kill is held behind the per-rule policy (High,
    /// recorded, `Log`); another port still kills.
    #[test]
    fn net_008_fires_on_port_53_to_a_server_that_is_no_configured_resolver() {
        let rule = NnLNet008OutboundFromTmpExec::new(None).with_resolvers(
            crate::net::resolvers::HostResolvers::fixed([v4(127, 0, 0, 53)]),
        );
        let mut e = flow(v4(127, 0, 0, 1), 53, "payload");
        if let Event::NetFlow(nf) = &mut e {
            nf.exe = Some("/var/tmp/nn-ms/c53".to_string());
        }
        let v = rule.evaluate(&e).expect("TCP/53 to its own server");
        assert_eq!(v.severity, Severity::High);
        assert_eq!(v.action, ResponseAction::Log);
        assert!(
            v.reasoning
                .contains("[held back: the kill for a flow to port 53"),
            "{}",
            v.reasoning
        );
        let mut other = e.clone();
        if let Event::NetFlow(nf) = &mut other {
            nf.dst_port = 8053;
        }
        assert_eq!(
            rule.evaluate(&other).unwrap().action,
            ResponseAction::KillProcess
        );
        // and at the connect, while the flow is open
        if let Event::NetFlow(nf) = &mut e {
            nf.phase = FlowPhase::Connect;
        }
        assert!(rule.evaluate(&e).is_some());
        // a refused connect is NN-L-NET-001's alone
        if let Event::NetFlow(nf) = &mut e {
            nf.phase = FlowPhase::Denied;
        }
        assert!(rule.evaluate(&e).is_none());
    }

    fn flow_from(exe: Option<&str>, pid: u32, port: u16) -> Event {
        let mut e = flow(v4(100, 64, 0, 9), port, "payload");
        if let Event::NetFlow(nf) = &mut e {
            nf.exe = exe.map(str::to_string);
            nf.pid = pid;
        }
        e
    }

    /// External audit NETR-008: one staging set; `/run/user` and home stay out.
    #[test]
    fn net_008_covers_every_staging_directory() {
        let rule = NnLNet008OutboundFromTmpExec::new(None);
        for exe in ["/tmp/x", "/var/tmp/x", "/dev/shm/x", "/dev/shm/x (deleted)"] {
            let v = rule
                .evaluate(&flow_from(Some(exe), 1, 443))
                .unwrap_or_else(|| panic!("{exe} fires"));
            assert_eq!(v.action, ResponseAction::KillProcess);
        }
        for exe in ["/run/user/1000/x", "/home/u/x", "/usr/bin/x", "/tmpx/y"] {
            assert!(
                rule.evaluate(&flow_from(Some(exe), 1, 443)).is_none(),
                "{exe}"
            );
        }
    }

    /// External audit NETR-008: production rows carried no `exe`, so the
    /// rule never fired. A row without one is judged on the image the
    /// lineage cache names — here a forked dropper child that never exec'd,
    /// whose `/proc/<pid>/exe` is the (unlinked) staged image.
    #[test]
    fn net_008_judges_the_connecting_process_image() {
        let tmp = tempfile::TempDir::new().unwrap();
        let dir = tmp.path().join("4242");
        std::fs::create_dir(&dir).unwrap();
        crate::posture::host::testing::symlink("/dev/shm/dropper (deleted)", dir.join("exe"))
            .unwrap();
        let lineage = crate::posture::lineage::AuthSessionTracker::<H>::new(tmp.path());
        let rule = NnLNet008OutboundFromTmpExec::new(Some(lineage));
        let v = rule
            .evaluate(&flow_from(None, 4242, 8080))
            .expect("the staged image connects");
        assert_eq!(v.action, ResponseAction::KillProcess);
        assert_eq!(v.event_pid, 4242);
        // Lab PR 224: port 53 to a server that is no configured resolver is
        // judged like any port; an unknown process is not guessed at
        assert!(rule.evaluate(&flow_from(None, 4242, 53)).is_some());
        assert!(rule.evaluate(&flow_from(None, 4243, 8080)).is_none());
    }

    /// External audit NETR-008: the review-49 carve-out — a package
    /// transaction's scriptlet staged in /var/tmp is recorded, not killed.
    #[test]
    fn net_008_spares_a_package_transaction() {
        let tmp = tempfile::TempDir::new().unwrap();
        let lineage = crate::posture::lineage::AuthSessionTracker::<H>::new(tmp.path());
        lineage.ingest_spawn(700, 1, "/usr/bin/dnf", 1);
        lineage.ingest_spawn(701, 700, "/var/tmp/rpm-tmp.Ab12Cd", 2);
        lineage.ingest_spawn(800, 1, "/var/tmp/stage2", 3);
        let rule = NnLNet008OutboundFromTmpExec::new(Some(lineage));
        let v = rule.evaluate(&flow_from(None, 701, 443)).expect("recorded");
        assert_eq!(v.action, ResponseAction::Log);
        let v = rule.evaluate(&flow_from(None, 800, 443)).expect("fires");
        assert_eq!(v.action, ResponseAction::KillProcess);
    }

    /// Lab PR 175: the carve-out is the package transaction of the FIM
    /// rules, bound to root and to the transaction's run. Before, any
    /// process with `mandb` or a package manager in its lineage was
    /// recorded: a user's program from `/tmp`, forked by a `mandb` or a
    /// `dpkg --version` run with `LD_PRELOAD` (neither is set-id), and a
    /// process a transaction left behind long after it ended.
    #[test]
    fn net_008_kills_a_staged_process_outside_a_root_transaction() {
        const S: u64 = 1_000_000_000;
        let tmp = tempfile::TempDir::new().unwrap();
        let running = |pid: u32| std::fs::create_dir_all(tmp.path().join(pid.to_string())).unwrap();
        let lineage = crate::posture::lineage::AuthSessionTracker::<H>::new(tmp.path());
        // the user's shell (900) → mandb (910, running) → /tmp/payload (911)
        lineage.ingest_exec(910, 900, "/usr/bin/mandb", &[], S, S, 1000);
        lineage.ingest_exec(911, 910, "/tmp/payload", &[], 2 * S, 2 * S, 1000);
        running(910);
        // the user's dpkg --version (920, running) → /tmp/payload (921)
        lineage.ingest_exec(920, 900, "/usr/bin/dpkg", &[], S, S, 1000);
        lineage.ingest_exec(921, 920, "/tmp/payload", &[], 2 * S, 2 * S, 1000);
        running(920);
        // root's dpkg, gone since its exec at 1 s → /tmp/helper (931)
        lineage.ingest_exec(930, 1, "/usr/bin/dpkg", &[], S, S, 0);
        lineage.ingest_exec(931, 930, "/tmp/helper", &[], 2 * S, 2 * S, 0);
        // root's dnf, running → its scriptlet in /var/tmp (941)
        lineage.ingest_exec(940, 1, "/usr/bin/dnf", &[], S, S, 0);
        lineage.ingest_exec(941, 940, "/var/tmp/rpm-tmp.Ab12Cd", &[], 2 * S, 2 * S, 0);
        running(940);
        let rule = NnLNet008OutboundFromTmpExec::new(Some(lineage));
        let at = |pid: u32, ts: u64| {
            let mut e = flow_from(None, pid, 443);
            if let Event::NetFlow(nf) = &mut e {
                nf.start_ns = ts;
                nf.end_ns = ts + 1_000;
            }
            rule.evaluate(&e).expect("a staged image connects").action
        };
        assert_eq!(at(911, 3 * S), ResponseAction::KillProcess, "under mandb");
        assert_eq!(at(921, 3 * S), ResponseAction::KillProcess, "a user's dpkg");
        assert_eq!(
            at(931, 30 * S),
            ResponseAction::Log,
            "within the transaction"
        );
        assert_eq!(at(931, 120 * S), ResponseAction::KillProcess, "after it");
        assert_eq!(at(941, 600 * S), ResponseAction::Log, "dnf still runs");
    }

    #[test]
    fn net_008_does_not_fire_on_system_exec() {
        let rule = NnLNet008OutboundFromTmpExec::new(None);
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

    fn sensor_flood(
        source: nn_model::FloodSource,
        pid: u32,
        uid: u32,
        held: u32,
        uid_level: bool,
        ts: u64,
    ) -> Event {
        Event::SensorFlood {
            source,
            pid,
            uid,
            comm: "looper".to_string(),
            exe: None,
            held,
            uid_level,
            timestamp_ns: ts,
        }
    }

    /// External audit EBPF-013: held-back listen() calls are summed per
    /// process over 10 s; the rule names the looping process once per
    /// window at 256.
    #[test]
    fn net_021_names_the_listen_flooder_once_per_window() {
        use nn_model::FloodSource::Listen;
        const SEC: u64 = 1_000_000_000;
        let rule = NnLNet021SensorRecordFlood::new();
        assert!(rule
            .evaluate(&sensor_flood(Listen, 30, 1000, 200, false, 0))
            .is_none());
        let v = rule
            .evaluate(&sensor_flood(Listen, 30, 1000, 100, false, SEC))
            .expect("300 held within 10 s");
        assert_eq!(v.rule_id, "NN-L-NET-021_SensorRecordFlood");
        assert_eq!(v.action, ResponseAction::Log);
        assert_eq!(v.event_pid, 30);
        assert!(v.reasoning.contains("300 listen() calls"));
        assert!(v.reasoning.contains("its own"));
        assert!(rule
            .evaluate(&sensor_flood(Listen, 30, 1000, 500, false, 2 * SEC))
            .is_none());
        // A new window starts over.
        assert!(rule
            .evaluate(&sensor_flood(Listen, 30, 1000, 300, false, 12 * SEC))
            .is_some());
        // The rule ignores DNS floods (NN-L-NET-020's) and records.
        assert!(rule
            .evaluate(&dns_flood(30, 1000, 10_000, false, 13 * SEC))
            .is_none());
    }

    /// The two sensors are summed apart, and the user's budget per user.
    #[test]
    fn net_021_sums_per_sensor_and_user() {
        use nn_model::FloodSource::{IoUringCreate, Listen};
        let rule = NnLNet021SensorRecordFlood::new();
        assert!(rule
            .evaluate(&sensor_flood(Listen, 40, 1000, 200, false, 0))
            .is_none());
        assert!(rule
            .evaluate(&sensor_flood(IoUringCreate, 40, 1000, 200, false, 1))
            .is_none());
        let v = rule
            .evaluate(&sensor_flood(IoUringCreate, 40, 1000, 100, false, 2))
            .expect("300 ring creations held");
        assert!(v.reasoning.contains("io_uring_setup()"));
        assert!(rule
            .evaluate(&sensor_flood(Listen, 41, 1000, 150, true, 3))
            .is_none());
        let v = rule
            .evaluate(&sensor_flood(Listen, 42, 1000, 150, true, 4))
            .expect("300 held by the user's processes");
        assert!(v.reasoning.contains("its user's"));
        assert!(rule
            .evaluate(&sensor_flood(Listen, 43, 1001, 150, true, 5))
            .is_none());
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

    /// Required builder test — the factory returns 17 net rules
    /// (Tappa 10 N6 shipped 9; Tappa 10.5 D4 adds 5:
    /// NN-L-NET-010/011/013/018/019; review 78 adds NN-L-NET-020;
    /// external audit EBPF-013 adds NN-L-NET-021).
    /// Future rule additions must update this assertion.
    #[test]
    fn net_rules_builder_returns_19_rules() {
        let rules = net_rules_empty();
        assert_eq!(
            rules.len(),
            19,
            "N6 9 + D4 5 + T4.1 DNS-tunnel-entropy 1 + DNS flood 1 + sensor flood 1 \
             + lab PR 224 fan-out 2 = 19 net rules"
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
            proc_start_ns: 0,
            bytes_sent: 1024,
            bytes_recv: 2048,
            resolved_hostname: None,
            tls_fingerprint: None,
            flow_id: "abc".to_string(),
            close_reason: 0,
            phase: Default::default(),
            observed_ns: 0,
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

    // ── External audit NETR-015 — the common-port exemption ─────────

    /// A lineage that saw `execs` (pid, exe, argv) executed; any other pid
    /// has no readable executable.
    fn lineage_of(
        execs: &[(u32, &str, &[&str])],
    ) -> (
        tempfile::TempDir,
        crate::posture::lineage::AuthSessionTracker<H>,
    ) {
        let tmp = tempfile::TempDir::new().unwrap();
        let t = crate::posture::lineage::AuthSessionTracker::<H>::new(tmp.path());
        for (pid, exe, argv) in execs {
            let argv: Vec<String> = argv.iter().map(|a| a.to_string()).collect();
            t.ingest_spawn_with_argv(*pid, 1, exe, &argv, 1);
        }
        (tmp, t)
    }

    /// Lab PR 224 (CM-02 d, research defect D9): an allowlisted transfer
    /// tool keeps its exemption while its lineage is clean and loses it
    /// when a precursor is there — the dropper's `curl` to a C2 port is
    /// recorded at the rule's severity (its kill held behind the per-rule
    /// policy: the starting tree exempted both), the administrator's is not.
    #[test]
    fn a_transfer_tool_is_exempt_only_while_its_lineage_is_clean() {
        let tmp = tempfile::TempDir::new().unwrap();
        let lineage = crate::posture::lineage::AuthSessionTracker::<H>::new(tmp.path());
        lineage.ingest_spawn(8100, 1, "/usr/bin/curl", 1);
        lineage.ingest_spawn(8101, 1, "/usr/bin/curl", 1);
        let allow = Arc::new(
            al().as_ref()
                .clone()
                .with_identity(lineage)
                .with_conditional(
                    super::super::transfer_tools::TRANSFER_TOOLS,
                    Arc::new(|pid| (pid == 8101).then_some("an exec from a staging directory")),
                ),
        );
        let rule = NnLNet010OutboundToHighRiskC2Port::new(allow);
        let row = |pid: u32| {
            let mut e = flow(v4(198, 51, 100, 9), 4444, "curl");
            if let Event::NetFlow(nf) = &mut e {
                nf.pid = pid;
            }
            e
        };
        assert!(rule.evaluate(&row(8100)).is_none(), "the tool itself");
        let v = rule.evaluate(&row(8101)).expect("the dropper's tool");
        assert_eq!(v.action, ResponseAction::Log);
        assert!(
            v.reasoning
                .contains("[held back: the kill of an allowlisted transfer tool"),
            "{}",
            v.reasoning
        );
        assert!(
            v.reasoning
                .contains("transfer tool, but its lineage holds an exec from a staging"),
            "{}",
            v.reasoning
        );
    }

    /// The production rule set over `lineage`: the allowlist judged on
    /// exec identity, as `default_rules_with_net` builds it.
    fn rules_over(lineage: &crate::posture::lineage::AuthSessionTracker<H>) -> Vec<Box<dyn Rule>> {
        net_rules(
            Arc::new(NetBlocklist::empty()),
            Arc::new(Ja3Blocklist::empty()),
            Arc::new(Mutex::new(DnsBurstWindow::new())),
            Arc::new(al().as_ref().clone().with_identity(lineage.clone())),
            Arc::new(Mutex::new(BeaconWindow::new())),
            Arc::new(DnsCache::default()),
            Some(lineage.clone()),
            NetRuleConfig::default(),
            None,
        )
    }

    fn listener_of(pid: u32, addr: IpAddr, port: u16, comm: &str) -> Event {
        let mut e = listener_bind(addr, port, comm);
        if let Event::NetListener(nl) = &mut e {
            nl.pid = pid;
            // As the drain fills it: the listener record names no image.
            nl.exe = None;
        }
        e
    }

    /// External audit NETR-015: a program outside the root-owned trees on
    /// 8080 or 8443 — a staging image, a script from `/tmp`, a module run
    /// with `-m`, one named like nginx, one whose image cannot be read —
    /// is recorded by -019 (wildcard) or -006 (loopback), as on any other
    /// port. Before, the port alone exempted it.
    #[test]
    fn a_common_port_listener_from_a_staging_image_is_recorded() {
        let (_tmp, lineage) = lineage_of(&[
            (700, "/tmp/backdoor", &["/tmp/backdoor"]),
            (701, "/usr/bin/python3.12", &["python3", "/tmp/x.py"]),
            (
                702,
                "/usr/bin/python3.12",
                &["python3", "-m", "http.server", "8080"],
            ),
            (703, "/tmp/nginx", &["nginx"]),
            (
                704,
                "/home/dev/.nvm/versions/node/v22.11.0/bin/node",
                &["node", "server.js"],
            ),
        ]);
        let rules = rules_over(&lineage);
        for (pid, comm) in [
            (700, "backdoor"),
            (701, "python3"),
            (702, "python3"),
            (703, "nginx"),
            (704, "node"),
            (799, "gone"),
        ] {
            for port in [8080, 8443, 80] {
                for (addr, rule) in [
                    (v4(0, 0, 0, 0), "NN-L-NET-019_WildcardListener"),
                    (v4(127, 0, 0, 1), "NN-L-NET-006_UncommonListener"),
                ] {
                    let v = first_match(&rules, &listener_of(pid, addr, port, comm))
                        .unwrap_or_else(|| panic!("pid {pid} {comm} on {addr}:{port}"));
                    assert_eq!(v.rule_id, rule, "pid {pid} on {addr}:{port}");
                    assert_eq!(v.action, ResponseAction::Log);
                    assert_eq!(v.severity, Severity::Medium);
                    assert!(
                        v.reasoning
                            .contains(&format!("on port {port}, a common service port")),
                        "{}",
                        v.reasoning
                    );
                }
            }
        }
    }

    /// External audit NETR-015: a program a root-owned tree installed stays
    /// quiet on its usual port, whatever its name; and on an uncommon port
    /// nothing changed.
    #[test]
    fn a_system_daemon_on_a_common_port_is_quiet() {
        let (_tmp, lineage) = lineage_of(&[
            (800, "/usr/sbin/nginx", &["nginx"]),
            (801, "/usr/sbin/sshd", &["sshd"]),
            (
                802,
                "/usr/bin/python3.12",
                &["python3", "/usr/bin/gunicorn"],
            ),
            (804, "/tmp/backdoor", &["/tmp/backdoor"]),
        ]);
        let rules = rules_over(&lineage);
        for (pid, port, comm) in [
            (800, 8080, "nginx"),
            (800, 443, "nginx"),
            (801, 22, "sshd"),
            (802, 8443, "gunicorn"),
        ] {
            for addr in [v4(0, 0, 0, 0), v4(127, 0, 0, 1)] {
                assert!(
                    first_match(&rules, &listener_of(pid, addr, port, comm)).is_none(),
                    "pid {pid} {comm} on {addr}:{port}"
                );
            }
        }
        // An uncommon port: the allowlist decides, as before.
        assert!(first_match(&rules, &listener_of(800, v4(0, 0, 0, 0), 9999, "nginx")).is_none());
        let v = first_match(&rules, &listener_of(804, v4(0, 0, 0, 0), 9999, "backdoor"))
            .expect("recorded");
        assert!(
            v.reasoning.contains("on an uncommon port"),
            "{}",
            v.reasoning
        );
        // Without a lineage (tests, the boot-time set) the record's own
        // image is judged; with none either, the port exempts as before.
        let r = NnLNet019WildcardListener::new(al());
        let mut e = listener_bind(v4(0, 0, 0, 0), 8080, "backdoor");
        if let Event::NetListener(nl) = &mut e {
            nl.exe = Some("/tmp/backdoor".into());
        }
        assert!(r.evaluate(&e).is_some());
        if let Event::NetListener(nl) = &mut e {
            nl.exe = None;
        }
        assert!(r.evaluate(&e).is_none());
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
    fn dns_burst_window_periodic_sweep_drops_idle_pids() {
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
        assert_eq!(w.live_evictions(), 0, "idle keys are not losses");
    }

    // ── external audit NETR-005 — hard caps on the rule windows ──

    /// A PID spray (one TXT query per fresh PID, all inside the window)
    /// never grows the map past its cap, and the PID that keeps querying
    /// keeps its count: it refreshes its key, the spray's keys go first.
    /// Before the fix the map held every PID (the cap was soft) and each
    /// observe swept it in full.
    #[test]
    fn dns_burst_window_keeps_the_active_pid_under_a_pid_spray() {
        let mut w = DnsBurstWindow::new();
        let t0: u64 = 1_000 * SEC;
        let mut next = 10_000u32;
        let mut count = 0;
        for i in 0..60u64 {
            count = w.observe(7, t0 + i * SEC / 2);
            for _ in 0..1_000 {
                w.observe(next, t0 + i * SEC / 2);
                next += 1;
            }
            assert!(
                w.tracked_keys() <= DNS_BURST_MAX_PIDS,
                "{}",
                w.tracked_keys()
            );
        }
        assert_eq!(count, 60, "the active PID keeps all its queries");
        assert!(w.live_evictions() > 0, "the spray's evictions are counted");
    }

    #[test]
    fn beacon_window_is_bounded_with_live_keys() {
        let mut w = BeaconWindow::new();
        let t0: u64 = 10_000 * SEC;
        // 20,000 live (pid, dst) keys from distinct PIDs, all inside the hour
        for i in 0..20_000u32 {
            let dst = IpAddr::V4(Ipv4Addr::from(0x0aff_0000 + i));
            w.observe(100_000 + i, dst, t0 + u64::from(i));
        }
        assert_eq!(w.tracked_keys(), BEACON_MAX_FLOWS);
        assert_eq!(w.live_evictions(), (20_000 - BEACON_MAX_FLOWS) as u64);
        // the quota map follows the flows it indexes
        assert_eq!(w.per_pid.len(), BEACON_MAX_FLOWS);
    }

    /// One process beacons every 60 s, then sprays 1,000 SYNs over a /16
    /// after each beacon: its quota keeps it to BEACON_MAX_DSTS_PER_PID
    /// keys, the beacon (two samples or more) is spared while the one-shot
    /// destinations go, and other processes' keys are never pushed out.
    #[test]
    fn beacon_window_quota_keeps_a_beacon_under_a_scan() {
        let mut w = BeaconWindow::new();
        let t0: u64 = 10_000 * SEC;
        let c2 = v4(100, 64, 0, 9);
        let other = v4(100, 64, 0, 10);
        w.observe(2, other, t0);
        let mut target = 0u32;
        let mut beacon = false;
        for i in 0..6u64 {
            let t = t0 + i * 60 * SEC;
            beacon = w.observe(1, c2, t);
            if i < 1 {
                continue;
            }
            for _ in 0..1_000 {
                target += 1;
                let dst = IpAddr::V4(Ipv4Addr::from(0x0aff_0000 + target));
                w.observe(1, dst, t + 1);
            }
        }
        assert!(beacon, "the periodic C2 flow is still recognised");
        assert!(w.tracked_keys() <= BEACON_MAX_DSTS_PER_PID + 1);
        assert!(w.quota_evictions() > 0);
        assert!(
            w.per_flow.contains(&(2, other)),
            "another process keeps its key"
        );
    }

    #[test]
    fn beacon_window_evicts_idle_flows() {
        let mut w = BeaconWindow::new();
        let t0: u64 = 10_000 * 1_000_000_000;
        let dst: IpAddr = "203.0.113.9".parse().unwrap();
        for pid in 1..=5_000u32 {
            w.observe(pid, dst, t0);
        }
        let later = t0 + BEACON_WINDOW_NS + 1;
        for _ in 0..STATEFUL_EVICT_EVERY {
            w.observe(1, dst, later);
        }
        assert_eq!(w.tracked_keys(), 1, "only the live flow must remain");
        assert_eq!(w.per_pid.len(), 1);
    }

    /// External audit NETR-005 (the NETR-002 corroboration): with the pair
    /// bound reached, a new pair used to be judged on its own (1) forever.
    #[test]
    fn tunnel_corroboration_counts_a_tunnel_when_full() {
        let mut c = DnsTunnelCorroboration::default();
        for parent in 0..DNS_TUNNEL_MAX_PAIRS as u64 {
            c.observe(1, parent, parent, 1);
        }
        assert_eq!(c.tracked_pairs(), DNS_TUNNEL_MAX_PAIRS);
        let mut n = 0;
        for label in 0..DNS_TUNNEL_DISTINCT_LABELS as u64 {
            n = c.observe(2, 999_999, label, 2 + label);
        }
        assert_eq!(n, DNS_TUNNEL_DISTINCT_LABELS);
        assert_eq!(c.tracked_pairs(), DNS_TUNNEL_MAX_PAIRS);
    }

    /// Single-label pairs go before pairs of several labels: a spray of
    /// one-shot parents cannot reset a tunnel in progress.
    #[test]
    fn tunnel_corroboration_evicts_single_label_pairs_first() {
        let mut c = DnsTunnelCorroboration::default();
        assert_eq!(c.observe(9, 77, 1, 1), 1);
        assert_eq!(c.observe(9, 77, 2, 2), 2);
        for parent in 0..(3 * DNS_TUNNEL_MAX_PAIRS) as u64 {
            c.observe(1, 1_000 + parent, parent, 3);
        }
        assert_eq!(c.observe(9, 77, 3, 4), 3, "the tunnel's labels survived");
        assert_eq!(c.live_evictions(), 0);
    }

    /// The lab probe in a unit: one process keeps the corroboration full
    /// with high-entropy labels under distinct parent domains while another
    /// runs a tunnel. Before the fix the tunnel was recorded only (Log).
    #[test]
    fn net_014_kills_a_tunnel_beside_a_parent_domain_spray() {
        let rule = net_014();
        let label = |i: usize| format!("{i:05}q7v3k9x2m4p8r6t1w5y0z3b7c9d2f4h6j8l0n");
        for i in 0..DNS_TUNNEL_MAX_PAIRS + 100 {
            let q = format!("{}.p{i}.spray.example", label(i));
            let v = rule.evaluate(&dns_event(40, &q, 1)).expect("recorded");
            assert_eq!(v.action, ResponseAction::Log);
        }
        let mut last = None;
        for i in 0..DNS_TUNNEL_DISTINCT_LABELS {
            let q = format!("{}.t.attacker.example", label(90_000 + i));
            last = rule.evaluate(&dns_event(41, &q, 1));
        }
        let v = last.expect("tunnel verdict");
        assert_eq!(v.action, ResponseAction::KillProcess);
        assert_eq!(v.event_pid, 41);
    }

    // ── external audit NET-010 (NN-AUD-006) — allowlist by exec identity ──

    /// The shipped allowlist judged on exec identity, with `execs`
    /// ingested as the exec sensor would (pid, exe, argv).
    fn identity_al(execs: &[(u32, &str, &[&str])]) -> (tempfile::TempDir, Arc<CommAllowlist>) {
        let tmp = tempfile::TempDir::new().unwrap();
        let t = crate::posture::lineage::AuthSessionTracker::<H>::new(tmp.path());
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

    // ── External audit PROC-009: no record stands in for a kill ────────

    /// What first-match returns over `rules`, as the engine does.
    fn first_match(rules: &[Box<dyn Rule>], e: &Event) -> Option<Verdict> {
        rules.iter().find_map(|r| r.evaluate(e))
    }

    fn strength(v: &Verdict) -> (u8, u8) {
        let action = match v.action {
            ResponseAction::Log => 0,
            ResponseAction::KillProcessTree => 2,
            _ => 1,
        };
        (action, v.severity as u8)
    }

    /// External audit PROC-009 (the same class in the network rules): for
    /// a flow, first match is the strongest verdict any one rule returns.
    /// A staging-dir process reaching an internal host or port 21 was
    /// NN-L-NET-007's or -011's record, not -008's kill.
    #[test]
    fn no_netflow_record_shadows_a_kill() {
        for exe in ["/tmp/payload", "/dev/shm/payload", "/usr/bin/payload"] {
            for dst in [v4(10, 0, 0, 5), v4(8, 8, 8, 8)] {
                for port in [21, 23, 443, 445, 4444, 8080] {
                    let mut e = flow(dst, port, "payload");
                    if let Event::NetFlow(nf) = &mut e {
                        nf.exe = Some(exe.to_string());
                    }
                    let got = first_match(&net_rules_empty(), &e);
                    let strongest = net_rules_empty()
                        .iter()
                        .filter_map(|r| r.evaluate(&e))
                        .map(|v| strength(&v))
                        .max();
                    assert_eq!(
                        got.as_ref().map(strength),
                        strongest,
                        "{exe} -> {dst}:{port}: {:?}",
                        got.map(|v| v.rule_id)
                    );
                }
            }
        }
    }

    /// External audit PROC-009: NN-L-NET-013 (a record) ran before -018:
    /// once a process's flows to an internal SMB port fell into a period,
    /// the beacon record replaced the lateral-movement kill.
    #[test]
    fn a_beacon_never_shadows_a_lateral_movement_kill() {
        let rules = net_rules_empty();
        for i in 0..10u64 {
            let e = flow_pid(
                4242,
                v4(10, 0, 0, 5),
                445,
                "payload",
                1 + i * 60_000_000_000,
            );
            let v = first_match(&rules, &e).expect("a verdict per flow");
            assert_eq!(
                v.action,
                ResponseAction::KillProcess,
                "flow {i}: {}",
                v.rule_id
            );
        }
    }

    /// External audit PROC-009: NN-L-NET-004 (a record of any name over 60
    /// characters) ran before -014, which therefore never saw most tunnels'
    /// names, and its corroborated kill never came.
    #[test]
    fn a_tunnel_of_long_names_reaches_the_tunnel_kill() {
        let rules = net_rules_empty();
        let label = |i: usize| format!("{i:02}q7v3k9x2m4p8r6t1w5y0z3b7c9d2f4h6j8l0n");
        let mut actions = Vec::new();
        for i in 0..DNS_TUNNEL_DISTINCT_LABELS {
            let q = format!("{}.t.attacker-tunnel.example", label(i));
            assert!(q.len() > 60, "{q}");
            let v = first_match(&rules, &dns_event(33, &q, 1)).expect("recorded");
            actions.push((v.rule_id, v.action));
        }
        assert_eq!(
            actions.last(),
            Some(&(
                "NN-L-NET-014_DnsTunnelEntropy".to_string(),
                ResponseAction::KillProcess
            )),
            "{actions:?}"
        );
        // A long name without an encoded label is still -004's record.
        let v = first_match(
            &rules,
            &dns_event(
                34,
                "www.internal-payments-api-production.eu-west-1.elb.amazonaws.com",
                1,
            ),
        )
        .expect("recorded");
        assert_eq!(v.rule_id, "NN-L-NET-004_SuspiciousDnsQname");
        assert_eq!(v.action, ResponseAction::Log);
    }

    // ── External audit NETR-016 / NETR-011 — the DNS name-shape family ──

    /// External audit NETR-016: one `getent` on a split-resolver host —
    /// A and AAAA, each as the originator's stub query and the resolver's
    /// forwarded leg, and a retry — gives ONE verdict from -014 and -004
    /// together, attributed to the originator. For a long high-entropy
    /// name it gave two: -014 dropped the repeat legs, and the first-match
    /// engine handed one of them to -004, which recorded it.
    #[test]
    fn one_lookup_fanout_yields_one_dns_shape_verdict() {
        let cache = Arc::new(DnsCache::default());
        let rules = net_rules(
            Arc::new(NetBlocklist::empty()),
            Arc::new(Ja3Blocklist::empty()),
            Arc::new(Mutex::new(DnsBurstWindow::new())),
            al(),
            Arc::new(Mutex::new(BeaconWindow::new())),
            Arc::clone(&cache),
            None,
            NetRuleConfig::default(),
            None,
        );
        let names = [
            // long AND a high-entropy first label: both shapes
            (
                "a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0u1v2w3x4y5z6.exfil.example.com",
                "NN-L-NET-014_DnsTunnelEntropy",
            ),
            // long only
            (
                "www.internal-payments-api-production.eu-west-1.elb.amazonaws.com",
                "NN-L-NET-004_SuspiciousDnsQname",
            ),
            // a high-entropy label in a short name
            (
                "q7v3k9x2m4p8r6t1w5y0z3b7c9d2.example.com",
                "NN-L-NET-014_DnsTunnelEntropy",
            ),
        ];
        for (n, (q, rule)) in names.iter().enumerate() {
            let t = (n as u64 + 1) * 10 * DNS_QNAME_DEDUP_WINDOW_NS;
            // (stub leg?, qtype, offset): getent's A and AAAA, the
            // resolver forwarding each, and an A retry with its leg.
            let legs = [
                (true, 1u16, 0u64),
                (true, 28, 5_000_000),
                (false, 1, 6_000_000),
                (false, 28, 11_000_000),
                (true, 1, 130_000_000),
                (false, 1, 131_000_000),
            ];
            let mut verdicts = Vec::new();
            for (stub, qtype, off) in legs {
                let ts = t + off;
                let e = if stub {
                    cache.on_dns_query(1122, q.to_string(), qtype, [127, 0, 0, 53].into(), ts);
                    dns_event_full(1122, q, qtype, "getent", Some("/usr/bin/getent"), ts)
                } else {
                    dns_event_full(673, q, qtype, "systemd-resolved", Some(RESOLVER_EXE), ts)
                };
                verdicts.extend(first_match(&rules, &e));
            }
            let got: Vec<_> = verdicts
                .iter()
                .map(|v| (v.rule_id.as_str(), v.event_pid))
                .collect();
            assert_eq!(got, [(*rule, 1122)], "{q}");
        }
    }

    /// External audit NETR-016: a hex label (4 bits per character, outside
    /// the base64-shaped gate -004 once had) is -014's, in a long name as in
    /// a short one: -004 never answers it first.
    #[test]
    fn a_hex_label_is_answered_by_014_first() {
        let rules = net_rules_empty();
        let hex = "0123456789abcdef".repeat(2);
        for (i, q) in [
            format!("{hex}.exfil.attacker-tunnel.example.com"),
            format!("{hex}.t.example"),
        ]
        .iter()
        .enumerate()
        {
            let v = first_match(&rules, &dns_event(50 + i as u32, q, 1)).expect("answered");
            assert_eq!(v.rule_id, "NN-L-NET-014_DnsTunnelEntropy", "{q}");
            assert_eq!(v.action, ResponseAction::Log, "{q}");
        }
    }

    /// External audit NETR-011 (fixed in lab PR 140; the audit's case): a
    /// process already over NN-L-NET-005's TXT burst threshold still gets
    /// -014's tunnel kill — the burst record never stands in for it.
    #[test]
    fn a_txt_burst_never_shadows_the_tunnel_kill() {
        let rules = net_rules_empty();
        let mut burst = 0;
        for i in 0..60u64 {
            let e = dns_event_full(
                61,
                &format!("t{i}.example.com"),
                DNS_QTYPE_TXT,
                "curl",
                Some("/usr/bin/curl"),
                1 + i,
            );
            if first_match(&rules, &e).is_some_and(|v| v.rule_id == "NN-L-NET-005_DnsTxtNullBurst")
            {
                burst += 1;
            }
        }
        assert!(burst > 0, "the burst is recorded");
        let mut last = None;
        for i in 0..DNS_TUNNEL_DISTINCT_LABELS {
            let q = format!("{i:02}q7v3k9x2m4p8r6t1w5y0z3b7c9d2f4h6.t.attacker-tunnel.example");
            let e = dns_event_full(
                61,
                &q,
                DNS_QTYPE_TXT,
                "curl",
                Some("/usr/bin/curl"),
                100 + i as u64,
            );
            let v = first_match(&rules, &e).expect("answered");
            assert_eq!(v.rule_id, "NN-L-NET-014_DnsTunnelEntropy", "{q}");
            last = Some(v.action);
        }
        assert_eq!(last, Some(ResponseAction::KillProcess));
    }

    /// External audit NET-019: every NetFlow verdict that kills is on a
    /// flow [`may_meet_a_kill_rule`] marks, so the netflow limiter never
    /// holds one back from the rules. Each rule is run on its own (no
    /// first match) over a grid of flows.
    #[test]
    fn every_killing_netflow_verdict_is_guarded() {
        let bl = NetBlocklist::from_entries([crate::net::blocklist::NetBlocklistEntry::Cidr {
            net: v4(198, 51, 100, 0),
            prefix: 24,
        }]);
        let rules = net_rules(
            Arc::new(bl.clone()),
            Arc::new(Ja3Blocklist::from_entries(["aa".repeat(16)])),
            Arc::new(Mutex::new(DnsBurstWindow::new())),
            Arc::new(CommAllowlist::default()),
            Arc::new(Mutex::new(BeaconWindow::new())),
            Arc::new(DnsCache::default()),
            None,
            NetRuleConfig::default(),
            None,
        );
        let addrs = [
            v4(198, 51, 100, 7),
            v4(10, 0, 0, 5),
            v4(100, 64, 0, 1),
            v4(8, 8, 8, 8),
            v4(127, 0, 0, 1),
            IpAddr::V6("fd00::5".parse().unwrap()),
        ];
        let ports = [21, 22, 53, 80, 443, 445, 1080, 3389, 4444, 5900, 8080, 9001];
        let exes = [
            Some("/usr/bin/curl"),
            Some("/tmp/x"),
            Some("/dev/shm/y"),
            None,
        ];
        let hosts = [None, Some("a.ONION"), Some("example.com")];
        let fp = TlsFingerprint {
            ja3: "aa".repeat(16),
            ja4: "t13d".to_string(),
            ja3_raw: String::new(),
            sni: None,
            alpn: Vec::new(),
        };
        let (mut kills, mut guarded_only) = (0, 0);
        let mut ts = 0u64;
        for addr in addrs {
            for port in ports {
                for exe in exes {
                    for host in hosts {
                        for tls in [None, Some(fp.clone())] {
                            ts += 1_000_000_000;
                            let Event::NetFlow(mut nf) = flow(addr, port, "nnprobe") else {
                                unreachable!()
                            };
                            nf.exe = exe.map(str::to_string);
                            nf.resolved_hostname = host.map(str::to_string);
                            nf.tls_fingerprint = tls;
                            nf.start_ns = ts;
                            nf.end_ns = ts + 1;
                            let guarded = may_meet_a_kill_rule(&nf, &bl);
                            let ev = Event::NetFlow(nf);
                            let kill = rules.iter().filter_map(|r| r.evaluate(&ev)).any(|v| {
                                matches!(
                                    v.action,
                                    ResponseAction::KillProcess | ResponseAction::KillProcessTree
                                )
                            });
                            if kill {
                                kills += 1;
                                assert!(guarded, "{ev:?}");
                            } else if guarded {
                                guarded_only += 1;
                            }
                        }
                    }
                }
            }
        }
        assert!(kills > 100, "the grid reaches the killing rules: {kills}");
        assert!(guarded_only < kills, "{guarded_only} vs {kills}");
        // An ordinary flow is not guarded: the limiter may hold it back.
        let Event::NetFlow(nf) = flow(v4(8, 8, 8, 8), 443, "curl") else {
            unreachable!()
        };
        assert!(!may_meet_a_kill_rule(&nf, &bl));
    }
}
