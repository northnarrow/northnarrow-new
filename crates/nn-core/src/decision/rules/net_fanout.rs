//! NN-L-NET-026 / NN-L-NET-027 — outbound fan-out: scanning and brute
//! force (lab PR 224, CM-14).
//!
//! A connect scan (nmap `-sT`, a Python or shell sweep, the spreaders of
//! Mirai-style botnets) and an outbound brute force (Hydra, the SSH
//! spreaders of TeamTNT and Kinsing) left one TCP row per closed socket
//! and no rule counted them: the posture raised Reconnaissance, nothing
//! was recorded. Both rules count connect ATTEMPTS (`Event::TcpConnect`,
//! emitted at the connect, before the outcome: a refused port counts) and
//! UDP sends (`Event::NetFlow`, UDP rows), in a sliding window, for each
//! process and for the direct children of each parent — a loop of `nc -z`
//! is one process per port, its shell the scanner.
//!
//! - **NN-L-NET-026 ScanFanOut** (MITRE T1046 Network Service Discovery):
//!   [`FanoutConfig::scan_hosts`] distinct destination addresses or
//!   [`FanoutConfig::scan_pairs`] distinct (address, port) pairs within
//!   [`FanoutConfig::scan_window_ns`] — High, recorded; a process reaching
//!   [`FanoutConfig::scan_kill_hosts`] distinct addresses — High,
//!   `KillProcess`, held behind the per-rule policy
//!   ([`FanoutConfig::scan_kill`]).
//! - **NN-L-NET-027 OutboundAuthBruteforce** (MITRE T1110 Brute Force):
//!   [`FanoutConfig::brute_connects`] connects to the authentication
//!   services of [`AUTH_PORTS`] within [`FanoutConfig::brute_window_ns`],
//!   to one host or spread over many — High, recorded; a process reaching
//!   [`FanoutConfig::brute_kill_connects`] — High, `KillProcess`, held
//!   behind the per-rule policy ([`FanoutConfig::brute_kill`]).
//!
//! Both kills are new (lab PR 224): by the decision of 21/10/2026 they are
//! held behind the per-rule response policy ([`response_policy`], off by
//! default) — past the kill threshold the verdict is High, recorded, action
//! `Log`, its reasoning saying the kill was held.
//!
//! ATT&CK 20.0 ids of the pinned table ([`Rule::attack`]).
//! A record comes before a kill (research mitigation); the children of a
//! parent are only recorded, never killed (the parent may be an
//! administrator's shell). One record per tier and window episode: a key
//! re-arms once its counts fall below half the record thresholds.
//!
//! The host's own monitoring and orchestration are exempt **by lineage**:
//! a key whose process (or parent) is, or descends from, a program of
//! [`DEFAULT_FANOUT_EXEMPT`] or of the operator's `--net-fanout-exempt`
//! list: the name of the executable (or script) the kernel ran, counted
//! only when that file lies in a root-owned system tree
//! ([`ExecIdentity::is_client`](crate::posture::lineage::ExecIdentity::is_client)),
//! never the `comm` a process sets for itself. The network comm allowlist does not apply: its
//! `ssh` would hide the brute force it is.
//!
//! Bounded: [`MAX_KEYS`] keys, [`MAX_SAMPLES_PER_KEY`] samples per key and
//! [`MAX_TOTAL_SAMPLES`] in all; past them the least recently sampled key
//! goes, counted in `net_window_evictions_total`.

use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use nn_model::telemetry::FlowPhase;
use nn_model::{Event, ResponseAction, Severity, Verdict};
use parking_lot::Mutex;

use crate::decision::attack::{AttackRef, Tactic};
use crate::decision::bounded::{LazyLru, LossCounter};
use crate::decision::correlation::CorrelationStore;
use crate::decision::response_policy::{self, PolicySwitch};
use crate::decision::Rule;
use crate::posture::host::PostureHost;
use crate::posture::lineage::AuthSessionTracker;

/// Authentication services an outbound brute force aims at: SSH (22,
/// 2222), Telnet (23, and 2323 of the IoT spreaders), RDP (3389), VNC
/// (5900).
pub const AUTH_PORTS: &[u16] = &[22, 23, 2222, 2323, 3389, 5900];

/// Programs that legitimately fan out, exempt with their descendants:
/// monitoring and health checks, orchestration over SSH, mail relays.
pub const DEFAULT_FANOUT_EXEMPT: &[&str] = &[
    "prometheus",
    "blackbox_exporter",
    "zabbix_agentd",
    "zabbix_agent2",
    "zabbix_server",
    "zabbix_proxy",
    "nagios",
    "nagios4",
    "icinga2",
    "nrpe",
    "telegraf",
    "collectd",
    "netdata",
    "monit",
    "check_mk_agent",
    "sensu-agent",
    "datadog-agent",
    "consul",
    "kubelet",
    "kube-proxy",
    "haproxy",
    "keepalived",
    "ansible",
    "ansible-playbook",
    "salt-ssh",
    "parallel-ssh",
    "pssh",
    "clush",
    "smtp",
    "exim4",
];

/// Keys tracked at once (processes and parents).
pub const MAX_KEYS: usize = 4096;
/// Samples kept per key (above every default threshold).
pub const MAX_SAMPLES_PER_KEY: usize = 1024;
/// Samples kept in all.
pub const MAX_TOTAL_SAMPLES: usize = 262_144;

static FANOUT_LIVE_EVICTIONS: AtomicU64 = AtomicU64::new(0);

/// Keys the fan-out windows evicted for room, process-wide.
pub fn fanout_window_evictions_total() -> u64 {
    FANOUT_LIVE_EVICTIONS.load(Ordering::Relaxed)
}

/// The thresholds (agent flags `--net-scan-*`, `--net-brute-*`,
/// `--net-fanout-exempt`; environment `NN_NET_SCAN_HOSTS` …).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FanoutConfig {
    pub scan_window_ns: u64,
    pub scan_hosts: usize,
    pub scan_pairs: usize,
    /// 0: never kill.
    pub scan_kill_hosts: usize,
    pub brute_window_ns: u64,
    pub brute_connects: usize,
    /// 0: never kill.
    pub brute_kill_connects: usize,
    /// Programs exempt with their descendants, beside
    /// [`DEFAULT_FANOUT_EXEMPT`].
    pub exempt: Vec<String>,
    /// NN-L-NET-026's kill past [`Self::scan_kill_hosts`], held behind the
    /// per-rule policy ([`response_policy::NET_026_KILL`], off).
    pub scan_kill: PolicySwitch,
    /// NN-L-NET-027's kill past [`Self::brute_kill_connects`], held
    /// likewise ([`response_policy::NET_027_KILL`], off).
    pub brute_kill: PolicySwitch,
}

/// Defaults (research CM-14).
pub const DEFAULT_SCAN_WINDOW_SECS: u64 = 60;
pub const DEFAULT_SCAN_HOSTS: usize = 64;
pub const DEFAULT_SCAN_PAIRS: usize = 256;
pub const DEFAULT_SCAN_KILL_HOSTS: usize = 512;
pub const DEFAULT_BRUTE_WINDOW_SECS: u64 = 300;
pub const DEFAULT_BRUTE_CONNECTS: usize = 20;
pub const DEFAULT_BRUTE_KILL_CONNECTS: usize = 100;

impl Default for FanoutConfig {
    fn default() -> Self {
        Self {
            scan_window_ns: DEFAULT_SCAN_WINDOW_SECS * 1_000_000_000,
            scan_hosts: DEFAULT_SCAN_HOSTS,
            scan_pairs: DEFAULT_SCAN_PAIRS,
            scan_kill_hosts: DEFAULT_SCAN_KILL_HOSTS,
            brute_window_ns: DEFAULT_BRUTE_WINDOW_SECS * 1_000_000_000,
            brute_connects: DEFAULT_BRUTE_CONNECTS,
            brute_kill_connects: DEFAULT_BRUTE_KILL_CONNECTS,
            exempt: Vec::new(),
            scan_kill: response_policy::NET_026_KILL,
            brute_kill: response_policy::NET_027_KILL,
        }
    }
}

impl FanoutConfig {
    /// Whether value `v` of the environment variable `name` makes the rules
    /// detect less than the defaults: a higher count, a shorter window, a
    /// kill tier turned off (0), or a value the agent cannot read. For the
    /// self-integrity report of the `NN_NET_*` variables.
    pub fn value_weakens(name: &str, v: &str) -> bool {
        let Ok(n) = v.trim().parse::<u64>() else {
            // Unparsable: the agent refuses it at start; report it anyway.
            return true;
        };
        match name {
            "NN_NET_SCAN_HOSTS" => n > DEFAULT_SCAN_HOSTS as u64,
            "NN_NET_SCAN_PAIRS" => n > DEFAULT_SCAN_PAIRS as u64,
            "NN_NET_SCAN_KILL_HOSTS" => n == 0 || n > DEFAULT_SCAN_KILL_HOSTS as u64,
            "NN_NET_SCAN_WINDOW_SECS" => n < DEFAULT_SCAN_WINDOW_SECS,
            "NN_NET_BRUTE_CONNECTS" => n > DEFAULT_BRUTE_CONNECTS as u64,
            "NN_NET_BRUTE_KILL_CONNECTS" => n == 0 || n > DEFAULT_BRUTE_KILL_CONNECTS as u64,
            "NN_NET_BRUTE_WINDOW_SECS" => n < DEFAULT_BRUTE_WINDOW_SECS,
            _ => false,
        }
    }
}

/// Who a sample counts for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum Key {
    /// The connecting process.
    Proc(u32),
    /// The direct children of this parent, together.
    Children(u32),
}

impl Key {
    fn pid(&self) -> u32 {
        match self {
            Key::Proc(p) | Key::Children(p) => *p,
        }
    }
}

/// One key's sliding window.
#[derive(Default)]
struct Window {
    samples: VecDeque<(u64, IpAddr, u16)>,
    hosts: HashMap<IpAddr, u32>,
    pairs: HashMap<(IpAddr, u16), u32>,
    /// Tier 1 (record) and tier 2 (kill) given in this episode.
    recorded: bool,
    killed: bool,
    /// The exemption, once looked up for this episode.
    exempt: Option<bool>,
}

impl Window {
    fn drop_front(&mut self) {
        if let Some((_, h, p)) = self.samples.pop_front() {
            dec(&mut self.hosts, h);
            dec(&mut self.pairs, (h, p));
        }
    }

    fn push(&mut self, ts: u64, h: IpAddr, p: u16, window_ns: u64) {
        while self
            .samples
            .front()
            .is_some_and(|(t, _, _)| ts.saturating_sub(*t) > window_ns)
        {
            self.drop_front();
        }
        self.samples.push_back((ts, h, p));
        *self.hosts.entry(h).or_default() += 1;
        *self.pairs.entry((h, p)).or_default() += 1;
        while self.samples.len() > MAX_SAMPLES_PER_KEY {
            self.drop_front();
        }
    }
}

fn dec<K: Eq + std::hash::Hash>(m: &mut HashMap<K, u32>, k: K) {
    if let Some(c) = m.get_mut(&k) {
        *c -= 1;
        if *c == 0 {
            m.remove(&k);
        }
    }
}

/// The windows of one rule.
struct Windows {
    keys: HashMap<Key, Window>,
    order: LazyLru<Key>,
    total: usize,
    lost: LossCounter,
}

impl Default for Windows {
    fn default() -> Self {
        Self {
            keys: HashMap::new(),
            order: LazyLru::new(),
            total: 0,
            lost: LossCounter::new(&FANOUT_LIVE_EVICTIONS),
        }
    }
}

impl Windows {
    /// Add a sample for `key`; the window it is in, after.
    fn sample(&mut self, key: Key, ts: u64, h: IpAddr, p: u16, window_ns: u64) -> &mut Window {
        if !self.keys.contains_key(&key) {
            while self.keys.len() >= MAX_KEYS {
                if !self.evict_one() {
                    break;
                }
            }
        }
        self.order.touch(key);
        let w = self.keys.entry(key).or_default();
        let before = w.samples.len();
        w.push(ts, h, p, window_ns);
        self.total = (self.total + w.samples.len()).saturating_sub(before);
        while self.total > MAX_TOTAL_SAMPLES {
            // never the key just sampled while others remain
            let Some(victim) = self.order.pop_oldest() else {
                break;
            };
            if victim == key {
                self.order.touch(victim);
                if self.keys.len() == 1 {
                    break;
                }
                continue;
            }
            self.remove(victim);
        }
        self.keys.get_mut(&key).expect("just inserted")
    }

    fn evict_one(&mut self) -> bool {
        let Some(victim) = self.order.pop_oldest() else {
            return false;
        };
        self.remove(victim);
        true
    }

    fn remove(&mut self, key: Key) {
        if let Some(w) = self.keys.remove(&key) {
            self.total = self.total.saturating_sub(w.samples.len());
            if !w.samples.is_empty() && self.lost.bump() {
                tracing::warn!(
                    pid = key.pid(),
                    evicted = self.lost.count(),
                    cap = MAX_KEYS,
                    "NN-L-NET-026/027 fan-out windows full: evicted a key still inside its window"
                );
            }
        }
    }

    #[cfg(test)]
    fn tracked(&self) -> usize {
        self.keys.len()
    }
}

/// What a connect or a send gives the windows: who, where, when.
struct Sample {
    pid: u32,
    comm: String,
    dst: IpAddr,
    port: u16,
    ts: u64,
    proto: &'static str,
}

fn sample_of(event: &Event) -> Option<Sample> {
    match event {
        Event::TcpConnect {
            pid,
            comm,
            family,
            dst_addr,
            dst_port,
            timestamp_ns,
            ..
        } => Some(Sample {
            pid: *pid,
            comm: comm.clone(),
            dst: nn_model::netaddr::canonical_ip(*family, dst_addr),
            port: *dst_port,
            ts: *timestamp_ns,
            proto: "tcp",
        }),
        // UDP: one row per send key (TCP is counted at its connect).
        Event::NetFlow(nf) if nf.proto == 17 && nf.phase == FlowPhase::Closed => Some(Sample {
            pid: nf.pid,
            comm: nf.comm.clone(),
            dst: nf.dst_addr,
            port: nf.dst_port,
            ts: nf.start_ns,
            proto: "udp",
        }),
        _ => None,
    }
}

/// `tcp 127.0.0.2:9 attempt` / `udp …:… closed`, the detection record's
/// `network` field for these rules.
pub fn attempt_text(event: &Event) -> Option<String> {
    let s = sample_of(event)?;
    let phase = if s.proto == "tcp" {
        "attempt"
    } else {
        "closed"
    };
    Some(format!(
        "{} {} {phase}",
        s.proto,
        std::net::SocketAddr::new(s.dst, s.port)
    ))
}

/// The state both rules share: the parent lookup and the exemption.
#[derive(Clone)]
pub struct FanoutContext<H: PostureHost> {
    config: Arc<FanoutConfig>,
    /// The ancestry tree (`parent_of`).
    store: Option<Arc<Mutex<CorrelationStore<H>>>>,
    /// Exec identities for the exemption.
    lineage: Option<AuthSessionTracker<H>>,
    agent_pid: u32,
}

impl<H: PostureHost> FanoutContext<H> {
    pub fn new(
        config: Arc<FanoutConfig>,
        store: Option<Arc<Mutex<CorrelationStore<H>>>>,
        lineage: Option<AuthSessionTracker<H>>,
    ) -> Self {
        Self {
            config,
            store,
            lineage,
            agent_pid: std::process::id(),
        }
    }

    /// The keys a sample of `pid` counts for.
    fn keys(&self, pid: u32) -> Vec<Key> {
        let mut out = vec![Key::Proc(pid)];
        if let Some(parent) = self
            .store
            .as_ref()
            .and_then(|s| s.lock().ancestry().parent_of(pid))
        {
            if parent > 1 && parent != self.agent_pid && parent != pid {
                out.push(Key::Children(parent));
            }
        }
        out
    }

    /// `pid` is the agent, or it (or an ancestor) runs a fan-out program.
    fn is_exempt(&self, pid: u32) -> bool {
        if pid == self.agent_pid {
            return true;
        }
        let Some(lineage) = &self.lineage else {
            return false;
        };
        let mut names: Vec<&str> = DEFAULT_FANOUT_EXEMPT.to_vec();
        names.extend(self.config.exempt.iter().map(String::as_str));
        lineage
            .actor_in_lineage(pid, |id| id.is_client(&names))
            .is_some()
    }
}

fn verdict(
    rule: &dyn Rule,
    action: ResponseAction,
    pid: u32,
    comm: String,
    ts: u64,
    reasoning: String,
) -> Verdict {
    Verdict {
        rule_id: rule.id().to_string(),
        rule_name: rule.name().to_string(),
        category: rule.category().to_string(),
        action,
        severity: Severity::High,
        reasoning,
        event_pid: pid,
        event_filename: comm,
        timestamp_ns: ts,
    }
}

fn who(key: Key, comm: &str) -> String {
    match key {
        Key::Proc(p) => format!("process '{comm}' (pid {p})"),
        Key::Children(p) => format!("the direct children of pid {p} (the last one '{comm}')"),
    }
}

// ── NN-L-NET-026 — ScanFanOut ────────────────────────────────────────

pub struct NnLNet026ScanFanOut<H: PostureHost> {
    ctx: FanoutContext<H>,
    windows: Mutex<Windows>,
}

impl<H: PostureHost> NnLNet026ScanFanOut<H> {
    pub fn new(ctx: FanoutContext<H>) -> Self {
        Self {
            ctx,
            windows: Mutex::new(Windows::default()),
        }
    }
}

impl<H: PostureHost> Rule for NnLNet026ScanFanOut<H> {
    fn id(&self) -> &'static str {
        "NN-L-NET-026_ScanFanOut"
    }
    fn name(&self) -> &'static str {
        "Outbound connects to many hosts or ports (scan fan-out)"
    }
    fn category(&self) -> &'static str {
        super::net::CATEGORY_HIGH
    }
    fn attack(&self) -> &'static [AttackRef] {
        const ATTACK: &[AttackRef] = &[AttackRef::new(Tactic::Discovery, "T1046")];
        ATTACK
    }
    fn evaluate(&self, event: &Event) -> Option<Verdict> {
        let s = sample_of(event)?;
        let c = &self.ctx.config;
        let keys = self.ctx.keys(s.pid);
        let mut out = None;
        let mut windows = self.windows.lock();
        for key in keys {
            let w = windows.sample(key, s.ts, s.dst, s.port, c.scan_window_ns);
            let (hosts, pairs) = (w.hosts.len(), w.pairs.len());
            if hosts * 2 < c.scan_hosts && pairs * 2 < c.scan_pairs {
                // Below half: a new episode.
                w.recorded = false;
                w.killed = false;
                w.exempt = None;
                continue;
            }
            let kill = matches!(key, Key::Proc(_))
                && c.scan_kill_hosts > 0
                && hosts >= c.scan_kill_hosts
                && !w.killed;
            let record = !w.recorded && (hosts >= c.scan_hosts || pairs >= c.scan_pairs);
            if out.is_some() || !(kill || record) {
                continue;
            }
            let exempt = *w
                .exempt
                .get_or_insert_with(|| self.ctx.is_exempt(key.pid()));
            if exempt {
                continue;
            }
            w.recorded = true;
            let window_s = c.scan_window_ns / 1_000_000_000;
            if kill {
                w.killed = true;
                out = Some(c.scan_kill.hold(verdict(
                    self,
                    ResponseAction::KillProcess,
                    key.pid(),
                    s.comm.clone(),
                    s.ts,
                    format!(
                        "{} reached {hosts} distinct destination addresses within {window_s} s \
                         (kill threshold {}) — a network scanner (T1046 Network Service \
                         Discovery); kill the process",
                        who(key, &s.comm),
                        c.scan_kill_hosts
                    ),
                )));
            } else {
                out = Some(verdict(
                    self,
                    ResponseAction::Log,
                    key.pid(),
                    s.comm.clone(),
                    s.ts,
                    format!(
                        "{} reached {hosts} distinct destination addresses and {pairs} distinct \
                         (address, port) pairs within {window_s} s (thresholds {} / {}) — a \
                         connect scan (T1046 Network Service Discovery); recorded, the kill \
                         threshold is {} addresses for one process",
                        who(key, &s.comm),
                        c.scan_hosts,
                        c.scan_pairs,
                        c.scan_kill_hosts
                    ),
                ));
            }
        }
        out
    }
}

// ── NN-L-NET-027 — OutboundAuthBruteforce ────────────────────────────

pub struct NnLNet027OutboundAuthBruteforce<H: PostureHost> {
    ctx: FanoutContext<H>,
    windows: Mutex<Windows>,
}

impl<H: PostureHost> NnLNet027OutboundAuthBruteforce<H> {
    pub fn new(ctx: FanoutContext<H>) -> Self {
        Self {
            ctx,
            windows: Mutex::new(Windows::default()),
        }
    }
}

impl<H: PostureHost> Rule for NnLNet027OutboundAuthBruteforce<H> {
    fn id(&self) -> &'static str {
        "NN-L-NET-027_OutboundAuthBruteforce"
    }
    fn name(&self) -> &'static str {
        "Repeated outbound connects to authentication services (brute force)"
    }
    fn category(&self) -> &'static str {
        super::net::CATEGORY_HIGH
    }
    fn attack(&self) -> &'static [AttackRef] {
        const ATTACK: &[AttackRef] = &[AttackRef::new(Tactic::CredentialAccess, "T1110")];
        ATTACK
    }
    fn evaluate(&self, event: &Event) -> Option<Verdict> {
        let s = sample_of(event)?;
        if s.proto != "tcp" || !AUTH_PORTS.contains(&s.port) {
            return None;
        }
        let c = &self.ctx.config;
        let keys = self.ctx.keys(s.pid);
        let mut out = None;
        let mut windows = self.windows.lock();
        for key in keys {
            let w = windows.sample(key, s.ts, s.dst, s.port, c.brute_window_ns);
            let (connects, hosts) = (w.samples.len(), w.hosts.len());
            if connects * 2 < c.brute_connects {
                w.recorded = false;
                w.killed = false;
                w.exempt = None;
                continue;
            }
            let kill = matches!(key, Key::Proc(_))
                && c.brute_kill_connects > 0
                && connects >= c.brute_kill_connects
                && !w.killed;
            let record = !w.recorded && connects >= c.brute_connects;
            if out.is_some() || !(kill || record) {
                continue;
            }
            let exempt = *w
                .exempt
                .get_or_insert_with(|| self.ctx.is_exempt(key.pid()));
            if exempt {
                continue;
            }
            w.recorded = true;
            let window_s = c.brute_window_ns / 1_000_000_000;
            let (action, tail) = if kill {
                w.killed = true;
                (
                    ResponseAction::KillProcess,
                    format!("kill threshold {}; kill the process", c.brute_kill_connects),
                )
            } else {
                (
                    ResponseAction::Log,
                    format!(
                        "threshold {}; recorded, the kill threshold is {} for one process",
                        c.brute_connects, c.brute_kill_connects
                    ),
                )
            };
            out = Some(c.brute_kill.hold(verdict(
                self,
                action,
                key.pid(),
                s.comm.clone(),
                s.ts,
                format!(
                    "{} made {connects} connects to authentication services (SSH, Telnet, \
                     RDP, VNC ports) on {hosts} host(s) within {window_s} s ({tail}) — an \
                     outbound brute force or credential spraying (T1110 Brute Force)",
                    who(key, &s.comm)
                ),
            )));
        }
        out
    }
}

/// Both rules over one context.
pub fn fanout_rules<H: PostureHost>(ctx: FanoutContext<H>) -> Vec<Box<dyn Rule>> {
    vec![
        Box::new(NnLNet026ScanFanOut::new(ctx.clone())),
        Box::new(NnLNet027OutboundAuthBruteforce::new(ctx)),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    // R08b (lab PR 251): on the portable test host.
    use crate::posture::host::testing::TestHost as H;
    type AuthSessionTracker = crate::posture::lineage::AuthSessionTracker<H>;
    type CorrelationStore = crate::decision::correlation::CorrelationStore<H>;
    type FanoutContext = super::FanoutContext<H>;
    type NnLNet026ScanFanOut = super::NnLNet026ScanFanOut<H>;
    type NnLNet027OutboundAuthBruteforce = super::NnLNet027OutboundAuthBruteforce<H>;

    fn connect(pid: u32, dst: [u8; 4], port: u16, ts: u64) -> Event {
        let mut a = [0u8; 16];
        a[..4].copy_from_slice(&dst);
        Event::TcpConnect {
            pid,
            uid: 1000,
            comm: "nn-ms-scan".into(),
            family: 2,
            src_addr: [0; 16],
            src_port: 0,
            dst_addr: a,
            dst_port: port,
            timestamp_ns: ts,
        }
    }

    fn ctx(config: FanoutConfig) -> FanoutContext {
        FanoutContext::new(Arc::new(config), None, None)
    }

    const S: u64 = 1_000_000_000;

    /// MS-21: one process sweeping 127.0.0.2…127.0.0.200 port 9 — a
    /// record at the 64th host, then nothing more in the episode; a
    /// second process sweeping 600 addresses is killed at the 512th.
    #[test]
    fn a_sweep_is_recorded_then_killed_at_the_kill_threshold() {
        let r = NnLNet026ScanFanOut::new(ctx(FanoutConfig::default()));
        let mut verdicts = Vec::new();
        for i in 0..199u32 {
            let host = 2 + i;
            if let Some(v) = r.evaluate(&connect(
                100,
                [127, 0, (host >> 8) as u8, host as u8],
                9,
                S + u64::from(i) * 1_000_000,
            )) {
                verdicts.push((i, v));
            }
        }
        assert_eq!(verdicts.len(), 1, "one record per episode");
        let (at, v) = &verdicts[0];
        assert_eq!(*at, 63, "the 64th distinct host");
        assert_eq!(v.rule_id, "NN-L-NET-026_ScanFanOut");
        assert_eq!(v.severity, Severity::High);
        assert_eq!(v.action, ResponseAction::Log);
        assert_eq!(v.event_pid, 100);

        let mut kills = Vec::new();
        for i in 0..600u32 {
            let host = 257 + i;
            if let Some(v) = r.evaluate(&connect(
                200,
                [127, 0, (host >> 8) as u8, host as u8],
                9,
                S + u64::from(i) * 1_000_000,
            )) {
                kills.push((i, v.action));
            }
        }
        // The kill tier is held behind the per-rule policy (off): a second
        // record at the 512th host, action Log.
        assert_eq!(kills[0], (63, ResponseAction::Log));
        assert_eq!(kills[1], (511, ResponseAction::Log));
        assert_eq!(kills.len(), 2);

        // With the switch on (Phase 2's per-rule policy), it kills.
        let r = NnLNet026ScanFanOut::new(ctx(FanoutConfig {
            scan_kill: response_policy::NET_026_KILL.enabled(),
            ..FanoutConfig::default()
        }));
        let mut kills = Vec::new();
        for i in 0..600u32 {
            let host = 257 + i;
            if let Some(v) = r.evaluate(&connect(
                200,
                [127, 0, (host >> 8) as u8, host as u8],
                9,
                S + u64::from(i) * 1_000_000,
            )) {
                kills.push((i, v.action, v.reasoning));
            }
        }
        assert_eq!(kills[1].0, 511);
        assert_eq!(kills[1].1, ResponseAction::KillProcess);
        assert!(!kills[1].2.contains("held back"), "{}", kills[1].2);
    }

    /// A port scan of one host: 256 distinct (host, port) pairs.
    #[test]
    fn a_port_scan_of_one_host_is_recorded_on_the_pairs() {
        let r = NnLNet026ScanFanOut::new(ctx(FanoutConfig::default()));
        let mut first = None;
        for port in 1..=400u16 {
            if let Some(v) = r.evaluate(&connect(300, [127, 0, 0, 1], port, S + u64::from(port))) {
                first.get_or_insert((port, v));
            }
        }
        let (port, v) = first.expect("recorded");
        assert_eq!(port, 256);
        assert_eq!(v.action, ResponseAction::Log);
    }

    /// The window slides: 64 hosts over two minutes, one a second, is not
    /// a scan; and a browser's many connections to one CDN host never are.
    #[test]
    fn slow_fan_out_and_one_host_bursts_are_not_scans() {
        let r = NnLNet026ScanFanOut::new(ctx(FanoutConfig::default()));
        for i in 0..64u32 {
            assert!(r
                .evaluate(&connect(
                    400,
                    [10, 0, 0, i as u8],
                    443,
                    S + u64::from(i) * 2 * S
                ))
                .is_none());
        }
        for i in 0..400u64 {
            assert!(r
                .evaluate(&connect(401, [192, 0, 2, 80], 443, S + i))
                .is_none());
        }
    }

    /// The children of one parent are counted together (a shell loop of
    /// `nc -z`), recorded, never killed.
    #[test]
    fn a_loop_of_one_shot_children_is_the_parents_scan() {
        let store = Arc::new(Mutex::new(CorrelationStore::new()));
        for child in 1000..1700u32 {
            store.lock().observe_spawn(child, 900, 0);
        }
        let r = NnLNet026ScanFanOut::new(FanoutContext::new(
            Arc::new(FanoutConfig::default()),
            Some(Arc::clone(&store)),
            None,
        ));
        let mut verdicts = Vec::new();
        for (n, child) in (1000..1700u32).enumerate() {
            let host = n as u32 + 2;
            if let Some(v) = r.evaluate(&connect(
                child,
                [127, 0, (host >> 8) as u8, host as u8],
                9,
                S + n as u64,
            )) {
                verdicts.push(v);
            }
        }
        assert_eq!(verdicts.len(), 1, "{verdicts:?}");
        assert_eq!(verdicts[0].event_pid, 900);
        assert_eq!(verdicts[0].action, ResponseAction::Log);
        assert!(verdicts[0].reasoning.contains("direct children of pid 900"));
    }

    /// MS-21: 25 connects to 127.0.0.1:22 — recorded at the 20th; 100
    /// from one process are killed.
    #[test]
    fn repeated_ssh_connects_are_a_brute_force() {
        let r = NnLNet027OutboundAuthBruteforce::new(ctx(FanoutConfig::default()));
        let mut got = Vec::new();
        for i in 0..120u64 {
            if let Some(v) = r.evaluate(&connect(500, [127, 0, 0, 1], 22, S + i * S / 10)) {
                got.push((i, v.action));
            }
        }
        // The kill tier is held behind the per-rule policy (off).
        assert_eq!(
            got,
            vec![(19, ResponseAction::Log), (99, ResponseAction::Log)]
        );
        let r = NnLNet027OutboundAuthBruteforce::new(ctx(FanoutConfig {
            brute_kill: response_policy::NET_027_KILL.enabled(),
            ..FanoutConfig::default()
        }));
        let mut got = Vec::new();
        for i in 0..120u64 {
            if let Some(v) = r.evaluate(&connect(500, [127, 0, 0, 1], 22, S + i * S / 10)) {
                got.push((i, v.action));
            }
        }
        assert_eq!(
            got,
            vec![(19, ResponseAction::Log), (99, ResponseAction::KillProcess)]
        );
        // Not an auth port: nothing.
        let r = NnLNet027OutboundAuthBruteforce::new(ctx(FanoutConfig::default()));
        for i in 0..50u64 {
            assert!(r
                .evaluate(&connect(501, [127, 0, 0, 1], 443, S + i))
                .is_none());
        }
    }

    /// The thresholds are the configured ones; a kill tier at 0 is off.
    #[test]
    fn thresholds_come_from_the_config() {
        let r = NnLNet027OutboundAuthBruteforce::new(ctx(FanoutConfig {
            brute_connects: 5,
            brute_kill_connects: 0,
            ..FanoutConfig::default()
        }));
        let mut got = Vec::new();
        for i in 0..200u64 {
            if let Some(v) = r.evaluate(&connect(600, [127, 0, 0, 1], 2222, S + i)) {
                got.push((i, v.action));
            }
        }
        assert_eq!(got, vec![(4, ResponseAction::Log)]);
    }

    /// The host's monitoring is exempt by lineage: a check its daemon
    /// runs (a child of `zabbix_agentd`, by exec identity), not a process
    /// that only names itself so.
    #[test]
    fn monitoring_is_exempt_by_lineage_not_by_name() {
        let tmp = tempfile::TempDir::new().unwrap();
        let l = AuthSessionTracker::new(tmp.path());
        l.ingest_spawn_with_argv(
            700,
            1,
            "/usr/sbin/zabbix_agentd",
            &["/usr/sbin/zabbix_agentd".into()],
            1,
        );
        l.ingest_spawn_with_argv(
            701,
            700,
            "/usr/lib/zabbix/check_tcp",
            &["check_tcp".into()],
            2,
        );
        l.ingest_spawn_with_argv(702, 1, "/tmp/zabbix_agentd", &["zabbix_agentd".into()], 3);
        let r = NnLNet026ScanFanOut::new(FanoutContext::new(
            Arc::new(FanoutConfig::default()),
            None,
            Some(l),
        ));
        let mut exempt = 0;
        let mut named = 0;
        for i in 0..100u32 {
            if r.evaluate(&connect(701, [10, 1, 0, i as u8], 10050, S + u64::from(i)))
                .is_some()
            {
                exempt += 1;
            }
            if r.evaluate(&connect(702, [10, 2, 0, i as u8], 10050, S + u64::from(i)))
                .is_some()
            {
                named += 1;
            }
        }
        assert_eq!(exempt, 0);
        assert_eq!(named, 1);
    }

    /// Bounded: the keys past the cap go, least recently sampled first.
    #[test]
    fn the_windows_are_bounded() {
        let mut w = Windows::default();
        for pid in 0..(MAX_KEYS as u32 + 10) {
            w.sample(Key::Proc(pid), S, "10.0.0.1".parse().unwrap(), 1, 60 * S);
        }
        assert_eq!(w.tracked(), MAX_KEYS);
        let k = Key::Proc(7_777_777);
        for i in 0..(MAX_SAMPLES_PER_KEY as u64 + 50) {
            w.sample(k, S + i, "10.0.0.2".parse().unwrap(), i as u16, 60 * S);
        }
        assert_eq!(w.keys[&k].samples.len(), MAX_SAMPLES_PER_KEY);
        assert!(w.total <= MAX_TOTAL_SAMPLES);
    }

    #[test]
    fn a_setting_weakens_when_it_detects_less() {
        assert!(FanoutConfig::value_weakens("NN_NET_SCAN_HOSTS", "100"));
        assert!(!FanoutConfig::value_weakens("NN_NET_SCAN_HOSTS", "32"));
        assert!(FanoutConfig::value_weakens("NN_NET_SCAN_KILL_HOSTS", "0"));
        assert!(FanoutConfig::value_weakens("NN_NET_SCAN_WINDOW_SECS", "10"));
        assert!(!FanoutConfig::value_weakens(
            "NN_NET_BRUTE_WINDOW_SECS",
            "600"
        ));
        assert!(FanoutConfig::value_weakens("NN_NET_BRUTE_CONNECTS", "x"));
    }

    #[test]
    fn the_record_names_the_attempt() {
        assert_eq!(
            attempt_text(&connect(1, [127, 0, 0, 2], 9, 1)).as_deref(),
            Some("tcp 127.0.0.2:9 attempt")
        );
    }
}
