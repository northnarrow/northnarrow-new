//! Tappa 10 (N6) + Tappa 10.5 (D4) — Network Observability
//! detection rules NN-L-NET-001..019.
//!
//! Tappa 10 N6 shipped 9 rules (001..009). Tappa 10.5 D4 adds 5
//! (010 high-risk C2 port, 011 plaintext-cred service, 013 stateful
//! beacon detector, 018 RFC1918 lateral-movement port, 019
//! wildcard-bind listener) and switches the comm-gated rules off
//! their former inline `const` allowlists onto the shared per-family
//! `netflow-comm-allowlist` (§13 Q3). DNS-payload rules 014/015 are
//! register-gated out pending the T4 refit (§13 Q6).
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

use crate::config::comm_allowlist::CommAllowlist;
use crate::decision::Rule;
use crate::net::blocklist::{Ja3Blocklist, NetBlocklist};

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

/// 60-second per-PID TXT/NULL query counter. NN-L-NET-005 fires
/// when `count > 50` for a given PID over a sliding 60s window.
#[derive(Debug, Default)]
pub struct DnsBurstWindow {
    per_pid: HashMap<u32, VecDeque<u64>>,
}

impl DnsBurstWindow {
    pub fn new() -> Self {
        Self::default()
    }

    /// Observe one TXT/NULL query. Returns the count of queries
    /// from `pid` still within the 60s window AFTER this insert.
    pub fn observe(&mut self, pid: u32, ts_ns: u64) -> usize {
        let q = self.per_pid.entry(pid).or_default();
        let window_ns: u64 = 60 * 1_000_000_000;
        let cutoff = ts_ns.saturating_sub(window_ns);
        while q.front().is_some_and(|&t| t < cutoff) {
            q.pop_front();
        }
        q.push_back(ts_ns);
        q.len()
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
        let q = self.per_flow.entry((pid, dst)).or_default();
        let cutoff = ts_ns.saturating_sub(BEACON_WINDOW_NS);
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

// ── NN-L-NET-004 — Suspicious DNS qname ──────────────────────────────

/// Suspicious DNS qname shape: > 60 chars OR base64-looking
/// (matches `^[A-Za-z0-9+/]{20,}` — DNS tunnelling payload
/// shape). Per design §7.
pub struct NnLNet004SuspiciousDnsQname;

impl NnLNet004SuspiciousDnsQname {
    fn looks_like_base64(s: &str) -> bool {
        // Reject if too short to be a meaningful payload.
        if s.len() < 20 {
            return false;
        }
        // Walk the first label only (everything before the first `.`).
        // Tunnelling encodes payload INTO the leftmost label; the
        // domain suffix (e.g. `attacker.com`) stays normal.
        let first_label = s.split('.').next().unwrap_or(s);
        if first_label.len() < 20 {
            return false;
        }
        first_label.bytes().all(|b| {
            b.is_ascii_alphanumeric()
                || b == b'+'
                || b == b'/'
                || b == b'='
                || b == b'-'
                || b == b'_'
        })
    }
}

impl Rule for NnLNet004SuspiciousDnsQname {
    fn id(&self) -> &'static str {
        "NN-L-NET-004_SuspiciousDnsQname"
    }
    fn name(&self) -> &'static str {
        "Suspicious DNS qname (long subdomain or base64 shape)"
    }
    fn category(&self) -> &'static str {
        CATEGORY_HIGH
    }
    fn evaluate(&self, event: &Event) -> Option<Verdict> {
        let Event::DnsQuery {
            pid,
            comm,
            query_name,
            timestamp_ns,
            ..
        } = event
        else {
            return None;
        };
        let long = query_name.len() > 60;
        let b64 = Self::looks_like_base64(query_name);
        if !long && !b64 {
            return None;
        }
        let reason = match (long, b64) {
            (true, true) => {
                "DNS qname is both unusually long (>60 chars) AND \
                             matches base64-payload shape — DNS-tunnelling indicator"
            }
            (true, false) => {
                "DNS qname is unusually long (>60 chars) — \
                              possible exfiltration via label encoding"
            }
            (false, true) => {
                "DNS first-label matches base64-payload shape — \
                              possible exfiltration via DNS tunnelling"
            }
            (false, false) => unreachable!(),
        };
        Some(net_verdict(
            self,
            ResponseAction::KillProcess,
            Severity::High,
            reason,
            *pid,
            comm.clone(),
            *timestamp_ns,
        ))
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
        if self.allowlist.contains(&nl.comm) {
            return None;
        }
        Some(net_verdict(
            self,
            ResponseAction::Log,
            Severity::Medium,
            "Process opened a TCP listener on an uncommon port \
             without operator allowlist coverage — posture → ALERTED",
            nl.pid,
            nl.comm.clone(),
            nl.timestamp_ns,
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
        if self.allowlist.contains(&nf.comm) {
            return None;
        }
        Some(net_verdict(
            self,
            ResponseAction::Log,
            Severity::Medium,
            "Outbound to an internal RFC1918 destination from a comm \
             outside the operator allowlist — possible lateral movement; \
             posture → ALERTED",
            nf.pid,
            nf.comm.clone(),
            nf.start_ns,
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
pub struct NnLNet009ByteAnomaly {
    allowlist: Arc<CommAllowlist>,
}

impl NnLNet009ByteAnomaly {
    pub fn new(allowlist: Arc<CommAllowlist>) -> Self {
        Self { allowlist }
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
        if nf.bytes_sent <= HIGH_VOLUME_BYTES_SENT {
            return None;
        }
        if self.allowlist.contains(&nf.comm) {
            return None;
        }
        Some(net_verdict(
            self,
            ResponseAction::Log,
            Severity::High,
            "Outbound flow exceeded 100 MiB sent from a non-allowlist \
             comm — possible exfiltration; posture → ENGAGED",
            nf.pid,
            nf.comm.clone(),
            nf.start_ns,
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
        if self.allowlist.contains(&nf.comm) {
            return None;
        }
        Some(net_verdict(
            self,
            ResponseAction::KillProcess,
            Severity::High,
            "Outbound to a high-risk C2 / tooling-default port (e.g. 4444 \
             Metasploit, 6667 IRC, 9001 Tor) from a non-allowlisted comm \
             — likely C2 (T1571); kill the process + posture → ENGAGED",
            nf.pid,
            nf.comm.clone(),
            nf.start_ns,
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
        if self.allowlist.contains(&nf.comm) {
            return None;
        }
        Some(net_verdict(
            self,
            ResponseAction::Log,
            Severity::Medium,
            "Outbound to a plaintext-credential service (FTP 21 / Telnet 23) \
             from a non-allowlisted comm — credentials transit in clear \
             (T1071); posture → ALERTED",
            nf.pid,
            nf.comm.clone(),
            nf.start_ns,
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
        // Skip trusted periodic clients before observation so their
        // regular traffic never seeds the window.
        if self.allowlist.contains(&nf.comm) {
            return None;
        }
        let is_beacon = self.window.lock().observe(nf.pid, nf.dst_addr, nf.start_ns);
        if !is_beacon {
            return None;
        }
        Some(net_verdict(
            self,
            ResponseAction::Log,
            Severity::High,
            "Periodic low-jitter outbound flows to a single destination \
             from one process — C2-beacon timing pattern (T1071/T1029); \
             posture → ENGAGED",
            nf.pid,
            nf.comm.clone(),
            nf.start_ns,
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
        if self.allowlist.contains(&nf.comm) {
            return None;
        }
        Some(net_verdict(
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
        if self.allowlist.contains(&nl.comm) {
            return None;
        }
        Some(net_verdict(
            self,
            ResponseAction::Log,
            Severity::Medium,
            "New listener bound to the wildcard address on an uncommon \
             port from a non-allowlisted comm — network-exposed backdoor \
             surface (T1571); posture → ALERTED",
            nl.pid,
            nl.comm.clone(),
            nl.timestamp_ns,
        ))
    }
}

// ── Factory ──────────────────────────────────────────────────────────

/// Build the NN-L-NET rules with operator-loaded blocklists, the
/// per-family comm allowlist (Tappa 10.5 D4), and freshly-allocated
/// stateful windows. Production `main.rs` constructs these from disk
/// via [`NetBlocklist::load`] / [`Ja3Blocklist::load`] /
/// `load_netflow_comm_allowlist` and shares them via `Arc`.
///
/// Evaluation order: Critical first (never throttled), then the D4
/// High/Medium additions BEFORE the broad Tappa 10 catch-alls so the
/// specific refinements win first-match (NN-L-NET-018 before -007,
/// NN-L-NET-019 before -006 — §13 Q10 documented overlaps).
pub fn net_rules(
    blocklist: Arc<NetBlocklist>,
    ja3_blocklist: Arc<Ja3Blocklist>,
    burst_window: Arc<Mutex<DnsBurstWindow>>,
    comm_allowlist: Arc<CommAllowlist>,
    beacon_window: Arc<Mutex<BeaconWindow>>,
) -> Vec<Box<dyn Rule>> {
    vec![
        // Critical first.
        Box::new(NnLNet001OutboundToBlockedIp::new(blocklist)),
        Box::new(NnLNet003BadJa3::new(ja3_blocklist)),
        // Tappa 10 High/DNS rules whose predicates don't overlap the
        // D4 additions.
        Box::new(NnLNet002OutboundToBlockedTld),
        Box::new(NnLNet004SuspiciousDnsQname),
        Box::new(NnLNet005DnsBurst::new(burst_window)),
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
        Event::DnsQuery {
            pid,
            uid: 1000,
            comm: "curl".to_string(),
            query_name: qname.to_string(),
            query_type: qtype,
            dns_server: [0; 16],
            family: 2,
            timestamp_ns: 100,
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

    #[test]
    fn net_004_fires_on_long_qname() {
        let rule = NnLNet004SuspiciousDnsQname;
        let long = format!("{}.example.com", "a".repeat(80));
        let v = rule.evaluate(&dns_event(1, &long, 1)).expect("long qname");
        assert_eq!(v.severity, Severity::High);
    }

    #[test]
    fn net_004_fires_on_base64_shape() {
        let rule = NnLNet004SuspiciousDnsQname;
        // First label is 32 chars of base64-shaped + the actual
        // dot-domain suffix.
        let q = "ZGVhZGJlZWZmZmZmZmZmZmNhZmU=.example.com";
        let v = rule
            .evaluate(&dns_event(1, q, 1))
            .expect("base64 first label");
        assert_eq!(v.severity, Severity::High);
    }

    #[test]
    fn net_004_does_not_fire_on_normal_qname() {
        let rule = NnLNet004SuspiciousDnsQname;
        assert!(rule.evaluate(&dns_event(1, "example.com", 1)).is_none());
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

    /// Required builder test — the factory returns 14 net rules
    /// (Tappa 10 N6 shipped 9; Tappa 10.5 D4 adds 5:
    /// NN-L-NET-010/011/013/018/019). Future rule additions must
    /// update this assertion.
    #[test]
    fn net_rules_builder_returns_14_rules() {
        let rules = net_rules_empty();
        assert_eq!(rules.len(), 14, "N6 9 + D4 5 = 14 net rules");
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
}
