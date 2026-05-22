//! Trigger detection — decides which [`TriggerType`]s a
//! `(focal_event, recent_events)` pair raises.
//!
//! The detector is stateless: every decision is a pure function of
//! the inputs. State (decay timers, transition log, last-fired
//! timestamps) lives in [`super::PostureMachine`].
//!
//! Design choices:
//!
//! - We mirror the Tappa-2 rule heuristics where possible
//!   (`R005_NetcatExec`, `R006_ReverseShellTooling`,
//!   `R001_ExecFromTmp`/`R002_ExecFromDevShm`) so the posture
//!   machine sees the same exploit/intrusion signal that the rule
//!   engine eventually fires on, *before* the rule executes — this
//!   is what lets a single confirmed exploit shift posture before
//!   the verdict is even computed.
//! - "Recon" is a count of *distinct* destination ports from the
//!   same pid within the lookback window, not a raw event count.
//!   nmap localhost generates 1000 dst_port hits from one pid; that
//!   shape is what we want to flag, not e.g. a chatty browser
//!   refreshing the same socket.
//! - We never look at command-line arguments because the eBPF
//!   sensors don't carry them. LOLBAS detection therefore relies
//!   on the parent/child comm pair (`curl` → `bash`) and not on
//!   pipeline syntax.

use std::collections::HashSet;

use common::posture_types::TriggerType;
use common::Event;

use super::exempt::ExemptPids;

/// Recon window: 3+ distinct dst_port from same pid in 10 min.
pub(super) const RECON_WINDOW_NS: u64 = 10 * 60 * 1_000_000_000;
pub(super) const RECON_DISTINCT_PORTS_MIN: usize = 3;

/// Heavy recon: 10+ distinct dst_port from same pid in 1 h.
pub(super) const HEAVY_RECON_WINDOW_NS: u64 = 60 * 60 * 1_000_000_000;
pub(super) const HEAVY_RECON_DISTINCT_PORTS_MIN: usize = 10;

/// DGA-like DNS: 5+ suspicious queries from same pid in 5 min.
pub(super) const DNS_DGA_WINDOW_NS: u64 = 5 * 60 * 1_000_000_000;
pub(super) const DNS_DGA_QUERIES_MIN: usize = 5;
pub(super) const DNS_DGA_MIN_LABEL_LEN: usize = 16;

/// Mass encryption / mass write: 20+ writes from same pid in 60 s.
pub(super) const MASS_WRITE_WINDOW_NS: u64 = 60 * 1_000_000_000;
pub(super) const MASS_WRITE_MIN: usize = 20;

/// Lateral movement: 3+ distinct internal hosts on admin ports in 10 min.
pub(super) const LATERAL_WINDOW_NS: u64 = 10 * 60 * 1_000_000_000;
pub(super) const LATERAL_DISTINCT_DST_MIN: usize = 3;

/// Exfiltration: 20+ external 80/443 connects from same pid in 5 min.
pub(super) const EXFIL_WINDOW_NS: u64 = 5 * 60 * 1_000_000_000;
pub(super) const EXFIL_MIN_EVENTS: usize = 20;

const NETCAT_COMMS: &[&str] = &["nc", "ncat", "netcat", "nc.openbsd", "nc.traditional"];
const OFFSEC_COMMS: &[&str] = &["socat", "msfvenom", "meterpreter", "sliver", "havoc"];
const RECON_TOOL_COMMS: &[&str] = &["nmap", "masscan", "rustscan", "zmap", "unicornscan"];
const NETLOAD_COMMS: &[&str] = &["curl", "wget", "fetch"];
const SHELL_COMMS: &[&str] = &["sh", "bash", "dash", "zsh", "ksh"];
const ADMIN_PORTS: &[u16] = &[22, 3389, 445, 5985, 5986];

const SENSITIVE_FILES: &[&str] = &["/etc/passwd", "/etc/shadow", "/etc/sudoers"];
const CRITICAL_FILES_PREFIXES: &[&str] = &[
    "/etc/sshd_config",
    "/etc/ssh/sshd_config",
    "/etc/crontab",
    "/etc/sudoers.d/",
    "/etc/pam.d/",
    "/root/.ssh/",
];
const PERSISTENCE_PREFIXES: &[&str] = &[
    "/etc/cron.d/",
    "/etc/cron.hourly/",
    "/etc/cron.daily/",
    "/etc/cron.weekly/",
    "/etc/cron.monthly/",
    "/var/spool/cron/",
    "/etc/systemd/system/",
    "/etc/init.d/",
    "/root/.bashrc",
    "/root/.bash_profile",
    "/root/.profile",
];

/// Stateless detector — see module docs.
///
/// `exempt` holds the NorthNarrow stack's own PIDs (agent + verified
/// watchdog), when known. The defender must
/// never classify its *own* I/O as adversary behaviour: the agent
/// appends to its state logs (`fim_drift.jsonl`, `fim_baseline.jsonl`,
/// `netflow.jsonl`, the audit chain, …) on every observed event, and
/// the observe-only `file_open` sensor reports those writes straight
/// back into the event stream. Without this guard a fresh boot's FIM
/// drift logging alone is >20 write-opens from one PID inside the
/// 60 s window, which trips [`confirmed_intrusion`]'s mass-write /
/// ransomware heuristic and drives posture all the way to COMBAT —
/// engaging network isolation against a host that is doing nothing
/// wrong (see 2026-05-22 sshd-reset diagnosis). Tamper attempts on
/// the agent's state by *other* PIDs are still caught: the inode
/// LSM hooks deny them and surface an `FsProtectDenial`, which
/// `confirmed_intrusion` treats as COMBAT-tier on its own.
#[derive(Debug, Default, Clone)]
pub struct TriggerDetector {
    /// PIDs belonging to the NorthNarrow process stack (agent + the
    /// verified watchdog) whose events must never raise a trigger.
    exempt: ExemptPids,
}

impl TriggerDetector {
    pub fn new() -> Self {
        Self::default()
    }

    /// Construct a detector that ignores events attributed to the
    /// agent's own PID. See the struct docs for why self-exclusion is
    /// required.
    pub fn with_self_pid(pid: u32) -> Self {
        Self {
            exempt: ExemptPids::with_agent(pid),
        }
    }

    /// Construct a detector with an explicit, shared [`ExemptPids`]
    /// (Beta Step 3) so the agent *and* the verified watchdog PID are
    /// both excluded, the latter refreshed live by `main.rs`.
    pub fn with_exempt(exempt: ExemptPids) -> Self {
        Self { exempt }
    }

    /// Inspect `(event, recent)` and return every trigger raised.
    ///
    /// The result is in escalation order (the strongest trigger
    /// last) so the caller can `iter().last()` for the dominant
    /// signal or fold them all into the audit log.
    pub fn detect(&self, event: &Event, recent: &[Event]) -> Vec<TriggerType> {
        // Stack-exclusion: never raise a trigger on the NorthNarrow
        // stack's own events (the agent — PR #123 — and the verified
        // watchdog — Beta Step 3). The agent's continuous state-log
        // writes, and the watchdog's reads of /proc/<agent>, the bpffs
        // map and /run/northnarrow, would otherwise self-trip the
        // mass-write / sensitive-access heuristics on a benign host.
        // `recent` is left untouched — the per-pid counters inside the
        // heuristics only ever match the focal pid, so a stack-owned
        // event in `recent` cannot inflate a non-stack focal's count.
        if let Some(pid) = event_owner_pid(event) {
            if self.exempt.is_exempt(pid) {
                return Vec::new();
            }
        }

        let mut hits: Vec<TriggerType> = Vec::new();

        // OBSERVING -> ALERTED tier
        if recon_pattern(event, recent) {
            hits.push(TriggerType::Reconnaissance);
        }
        if suspicious_dns(event, recent) {
            hits.push(TriggerType::SuspiciousDns);
        }
        if sensitive_file_access(event) {
            hits.push(TriggerType::SensitiveFileAccess);
        }
        if lolbas_pattern(event, recent) {
            hits.push(TriggerType::Lolbas);
        }

        // ALERTED -> ENGAGED tier
        if exploit_attempt(event) {
            hits.push(TriggerType::ExploitAttempt);
        }
        if heavy_recon(event, recent) {
            hits.push(TriggerType::HeavyReconnaissance);
        }
        if critical_file_modification(event) {
            hits.push(TriggerType::CriticalFileModification);
        }

        // ENGAGED -> COMBAT tier
        if confirmed_intrusion(event, recent) {
            hits.push(TriggerType::ConfirmedIntrusion);
        }
        if persistence_mechanism(event) {
            hits.push(TriggerType::PersistenceMechanism);
        }
        if lateral_movement(event, recent) {
            hits.push(TriggerType::LateralMovement);
        }
        if exfiltration_pattern(event, recent) {
            hits.push(TriggerType::ExfiltrationPattern);
        }

        hits
    }
}

fn within(focal_ts: u64, ts: u64, window_ns: u64) -> bool {
    focal_ts.saturating_sub(ts) <= window_ns
}

/// PID an event is attributed to, for self-exclusion. Variants the
/// agent itself never originates (e.g. `CanaryTripped`, `NetFlow`,
/// `NetListener`) return `None` so they are never filtered.
fn event_owner_pid(event: &Event) -> Option<u32> {
    match event {
        Event::ProcessSpawn { pid, .. }
        | Event::FileOpen { pid, .. }
        | Event::ExecCheck { pid, .. }
        | Event::TcpConnect { pid, .. }
        | Event::DnsQuery { pid, .. }
        | Event::FsProtectDenial { pid, .. } => Some(*pid),
        _ => None,
    }
}

fn recon_pattern(focal: &Event, recent: &[Event]) -> bool {
    if let Event::ProcessSpawn { comm, .. } = focal {
        if RECON_TOOL_COMMS.iter().any(|c| comm == c) {
            return true;
        }
    }
    let Event::TcpConnect {
        pid: focal_pid,
        timestamp_ns: focal_ts,
        ..
    } = focal
    else {
        return false;
    };
    distinct_dst_ports_in_window(*focal_pid, *focal_ts, recent, RECON_WINDOW_NS)
        + 1 // include the focal event itself
        >= RECON_DISTINCT_PORTS_MIN
}

fn heavy_recon(focal: &Event, recent: &[Event]) -> bool {
    let Event::TcpConnect {
        pid: focal_pid,
        timestamp_ns: focal_ts,
        ..
    } = focal
    else {
        return false;
    };
    distinct_dst_ports_in_window(*focal_pid, *focal_ts, recent, HEAVY_RECON_WINDOW_NS) + 1
        >= HEAVY_RECON_DISTINCT_PORTS_MIN
}

fn distinct_dst_ports_in_window(
    pid: u32,
    focal_ts: u64,
    recent: &[Event],
    window_ns: u64,
) -> usize {
    let mut ports: HashSet<u16> = HashSet::new();
    for e in recent {
        if let Event::TcpConnect {
            pid: p,
            dst_port,
            timestamp_ns,
            ..
        } = e
        {
            if *p == pid && within(focal_ts, *timestamp_ns, window_ns) {
                ports.insert(*dst_port);
            }
        }
    }
    ports.len()
}

fn suspicious_dns(focal: &Event, recent: &[Event]) -> bool {
    let Event::DnsQuery {
        pid: focal_pid,
        query_name,
        timestamp_ns: focal_ts,
        ..
    } = focal
    else {
        return false;
    };
    if !looks_dga(query_name) {
        return false;
    }
    let mut count = 1usize; // include focal
    for e in recent {
        if let Event::DnsQuery {
            pid,
            query_name: q,
            timestamp_ns,
            ..
        } = e
        {
            if *pid == *focal_pid
                && looks_dga(q)
                && within(*focal_ts, *timestamp_ns, DNS_DGA_WINDOW_NS)
            {
                count += 1;
            }
        }
    }
    count >= DNS_DGA_QUERIES_MIN
}

/// Lightweight DGA-shape heuristic.
///
/// We treat a name as DGA-like if its longest single label is at
/// least [`DNS_DGA_MIN_LABEL_LEN`] characters, has a high digit/letter
/// mix, and has no vowel-heavy structure. This is intentionally
/// coarse: a real DGA classifier is a separate engine; here we just
/// need a signal strong enough to drive a posture nudge.
fn looks_dga(name: &str) -> bool {
    let longest = name.split('.').map(str::len).max().unwrap_or(0);
    if longest < DNS_DGA_MIN_LABEL_LEN {
        return false;
    }
    let label = name.split('.').max_by_key(|s| s.len()).unwrap_or(name);
    let total = label.len();
    if total == 0 {
        return false;
    }
    let digits = label.chars().filter(|c| c.is_ascii_digit()).count();
    let vowels = label
        .chars()
        .filter(|c| matches!(c.to_ascii_lowercase(), 'a' | 'e' | 'i' | 'o' | 'u'))
        .count();
    let vowel_ratio = vowels as f64 / total as f64;
    let digit_ratio = digits as f64 / total as f64;
    // Either "lots of digits" or "very low vowel rate" looks
    // unnatural for an English-derived hostname.
    digit_ratio >= 0.20 || vowel_ratio < 0.20
}

fn sensitive_file_access(focal: &Event) -> bool {
    let Event::FileOpen { uid, filename, .. } = focal else {
        return false;
    };
    // root (uid=0) and system users (1..1000) are excluded — these
    // accesses are routine. We only flag when a regular user reaches
    // for the credential files.
    if *uid < 1000 {
        return false;
    }
    SENSITIVE_FILES.iter().any(|f| filename == f)
}

fn lolbas_pattern(focal: &Event, recent: &[Event]) -> bool {
    let Event::ProcessSpawn {
        comm: child_comm,
        ppid,
        ..
    } = focal
    else {
        return false;
    };
    if !SHELL_COMMS.iter().any(|c| child_comm == c) {
        return false;
    }
    // Find a recent ProcessSpawn whose pid == focal.ppid and whose
    // comm matches a network-loader.
    recent.iter().any(|e| match e {
        Event::ProcessSpawn { pid, comm, .. } => {
            *pid == *ppid && NETLOAD_COMMS.iter().any(|c| comm == c)
        }
        _ => false,
    })
}

fn exploit_attempt(focal: &Event) -> bool {
    let Event::ProcessSpawn { comm, .. } = focal else {
        return false;
    };
    NETCAT_COMMS.iter().any(|c| comm == c) || OFFSEC_COMMS.iter().any(|c| comm == c)
}

fn critical_file_modification(focal: &Event) -> bool {
    let Event::FileOpen {
        filename, flags, ..
    } = focal
    else {
        return false;
    };
    if !is_write_open(*flags) {
        return false;
    }
    CRITICAL_FILES_PREFIXES
        .iter()
        .any(|p| filename == p || filename.starts_with(p))
}

fn confirmed_intrusion(focal: &Event, recent: &[Event]) -> bool {
    // Tappa 7: a denied FS-tamper attempt is, by definition, a
    // confirmed intrusion — root tried to disable or destroy agent
    // state. Single event raises the posture all the way to COMBAT.
    if let Event::FsProtectDenial { .. } = focal {
        return true;
    }
    if let Event::ProcessSpawn { filename, .. } | Event::ExecCheck { filename, .. } = focal {
        if filename.starts_with("/tmp/") || filename.starts_with("/dev/shm/") {
            return true;
        }
    }
    // Mass-write / encryption-pattern: many writes from same pid in
    // a short window.
    if let Event::FileOpen {
        pid: focal_pid,
        flags,
        timestamp_ns: focal_ts,
        ..
    } = focal
    {
        if is_write_open(*flags) {
            let mut count = 1usize;
            for e in recent {
                if let Event::FileOpen {
                    pid,
                    flags: f,
                    timestamp_ns,
                    ..
                } = e
                {
                    if *pid == *focal_pid
                        && is_write_open(*f)
                        && within(*focal_ts, *timestamp_ns, MASS_WRITE_WINDOW_NS)
                    {
                        count += 1;
                    }
                }
            }
            if count >= MASS_WRITE_MIN {
                return true;
            }
        }
    }
    false
}

fn persistence_mechanism(focal: &Event) -> bool {
    let Event::FileOpen {
        filename, flags, ..
    } = focal
    else {
        return false;
    };
    if !is_write_open(*flags) {
        return false;
    }
    PERSISTENCE_PREFIXES
        .iter()
        .any(|p| filename == p || filename.starts_with(p))
}

fn lateral_movement(focal: &Event, recent: &[Event]) -> bool {
    let Event::TcpConnect {
        pid: focal_pid,
        family,
        dst_addr,
        dst_port,
        timestamp_ns: focal_ts,
        ..
    } = focal
    else {
        return false;
    };
    if !ADMIN_PORTS.contains(dst_port) {
        return false;
    }
    if *family != 2 || !is_rfc1918(dst_addr) {
        return false;
    }
    let mut hosts: HashSet<[u8; 4]> = HashSet::new();
    hosts.insert([dst_addr[0], dst_addr[1], dst_addr[2], dst_addr[3]]);
    for e in recent {
        if let Event::TcpConnect {
            pid,
            family: fam,
            dst_addr: dst,
            dst_port: dp,
            timestamp_ns,
            ..
        } = e
        {
            if *pid == *focal_pid
                && *fam == 2
                && ADMIN_PORTS.contains(dp)
                && is_rfc1918(dst)
                && within(*focal_ts, *timestamp_ns, LATERAL_WINDOW_NS)
            {
                hosts.insert([dst[0], dst[1], dst[2], dst[3]]);
            }
        }
    }
    hosts.len() >= LATERAL_DISTINCT_DST_MIN
}

fn exfiltration_pattern(focal: &Event, recent: &[Event]) -> bool {
    let Event::TcpConnect {
        pid: focal_pid,
        family,
        dst_addr,
        dst_port,
        timestamp_ns: focal_ts,
        ..
    } = focal
    else {
        return false;
    };
    if *family != 2 {
        return false;
    }
    if !matches!(*dst_port, 80 | 443) {
        return false;
    }
    if is_rfc1918(dst_addr) {
        return false;
    }
    let mut count = 1usize;
    for e in recent {
        if let Event::TcpConnect {
            pid,
            family: fam,
            dst_addr: dst,
            dst_port: dp,
            timestamp_ns,
            ..
        } = e
        {
            if *pid == *focal_pid
                && *fam == 2
                && matches!(*dp, 80 | 443)
                && !is_rfc1918(dst)
                && within(*focal_ts, *timestamp_ns, EXFIL_WINDOW_NS)
            {
                count += 1;
            }
        }
    }
    count >= EXFIL_MIN_EVENTS
}

fn is_rfc1918(addr: &[u8; 16]) -> bool {
    let a = addr[0];
    let b = addr[1];
    matches!((a, b), (10, _) | (172, 16..=31) | (192, 168))
}

fn is_write_open(flags: u32) -> bool {
    // O_WRONLY = 1, O_RDWR = 2 in glibc/Linux. Mask to access mode.
    let access = flags & 0b11;
    access == 1 || access == 2
}

#[cfg(test)]
pub(super) mod testutil {
    use super::*;

    pub fn spawn(pid: u32, ppid: u32, comm: &str, filename: &str, ts: u64) -> Event {
        Event::ProcessSpawn {
            pid,
            ppid,
            uid: 1000,
            gid: 1000,
            comm: comm.into(),
            filename: filename.into(),
            timestamp_ns: ts,
            argv: Vec::new(),
            parent_comm: String::new(),
            parent_start_ns: 0,
        }
    }

    pub fn file_open(pid: u32, uid: u32, filename: &str, flags: u32, ts: u64) -> Event {
        Event::FileOpen {
            pid,
            uid,
            gid: uid,
            comm: "x".into(),
            filename: filename.into(),
            flags,
            timestamp_ns: ts,
        }
    }

    pub fn tcp_v4(pid: u32, dst: [u8; 4], dst_port: u16, ts: u64) -> Event {
        let mut a = [0u8; 16];
        a[..4].copy_from_slice(&dst);
        Event::TcpConnect {
            pid,
            uid: 1000,
            comm: "x".into(),
            family: 2,
            src_addr: [0u8; 16],
            src_port: 0,
            dst_addr: a,
            dst_port,
            timestamp_ns: ts,
        }
    }

    pub fn dns(pid: u32, name: &str, ts: u64) -> Event {
        Event::DnsQuery {
            pid,
            uid: 1000,
            comm: "x".into(),
            query_name: name.into(),
            query_type: 1,
            dns_server: [0u8; 16],
            family: 2,
            timestamp_ns: ts,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::testutil::*;
    use super::*;

    #[test]
    fn recon_fires_on_three_distinct_ports_same_pid() {
        let det = TriggerDetector::new();
        let recent = vec![
            tcp_v4(42, [127, 0, 0, 1], 22, 100),
            tcp_v4(42, [127, 0, 0, 1], 80, 200),
        ];
        let focal = tcp_v4(42, [127, 0, 0, 1], 443, 300);
        let hits = det.detect(&focal, &recent);
        assert!(hits.contains(&TriggerType::Reconnaissance));
    }

    #[test]
    fn recon_does_not_fire_on_same_port_repeatedly() {
        let det = TriggerDetector::new();
        let recent = vec![
            tcp_v4(42, [127, 0, 0, 1], 80, 100),
            tcp_v4(42, [127, 0, 0, 1], 80, 200),
        ];
        let focal = tcp_v4(42, [127, 0, 0, 1], 80, 300);
        let hits = det.detect(&focal, &recent);
        assert!(!hits.contains(&TriggerType::Reconnaissance));
    }

    #[test]
    fn recon_fires_on_known_scanner_comm() {
        let det = TriggerDetector::new();
        let focal = spawn(42, 1, "nmap", "/usr/bin/nmap", 1);
        let hits = det.detect(&focal, &[]);
        assert!(hits.contains(&TriggerType::Reconnaissance));
    }

    #[test]
    fn suspicious_dns_fires_on_dga_burst() {
        let det = TriggerDetector::new();
        let mut recent = Vec::new();
        for i in 0..6u64 {
            recent.push(dns(7, "x9k2lqw1pq3z9aaaa.example.org", i * 1_000_000_000));
        }
        let focal = dns(7, "z2k9pqw1lp3z9aaaa.example.org", 7_000_000_000);
        let hits = det.detect(&focal, &recent);
        assert!(hits.contains(&TriggerType::SuspiciousDns));
    }

    #[test]
    fn sensitive_file_access_fires_on_user_reading_shadow() {
        let det = TriggerDetector::new();
        let focal = file_open(42, 1001, "/etc/shadow", 0, 1);
        let hits = det.detect(&focal, &[]);
        assert!(hits.contains(&TriggerType::SensitiveFileAccess));
    }

    #[test]
    fn sensitive_file_access_skips_root_and_system_uids() {
        let det = TriggerDetector::new();
        for uid in [0, 1, 999] {
            let focal = file_open(42, uid, "/etc/shadow", 0, 1);
            let hits = det.detect(&focal, &[]);
            assert!(!hits.contains(&TriggerType::SensitiveFileAccess));
        }
    }

    #[test]
    fn lolbas_fires_on_curl_then_bash_child() {
        let det = TriggerDetector::new();
        let recent = vec![spawn(50, 1, "curl", "/usr/bin/curl", 1)];
        let focal = spawn(51, 50, "bash", "/usr/bin/bash", 2);
        let hits = det.detect(&focal, &recent);
        assert!(hits.contains(&TriggerType::Lolbas));
    }

    #[test]
    fn exploit_attempt_fires_on_netcat() {
        let det = TriggerDetector::new();
        let focal = spawn(42, 1, "ncat", "/usr/bin/ncat", 1);
        let hits = det.detect(&focal, &[]);
        assert!(hits.contains(&TriggerType::ExploitAttempt));
    }

    #[test]
    fn exploit_attempt_fires_on_offsec_tooling() {
        let det = TriggerDetector::new();
        let focal = spawn(42, 1, "msfvenom", "/usr/local/bin/msfvenom", 1);
        let hits = det.detect(&focal, &[]);
        assert!(hits.contains(&TriggerType::ExploitAttempt));
    }

    #[test]
    fn critical_file_modification_fires_on_sshd_config_write() {
        let det = TriggerDetector::new();
        let focal = file_open(42, 1001, "/etc/ssh/sshd_config", 1, 1);
        let hits = det.detect(&focal, &[]);
        assert!(hits.contains(&TriggerType::CriticalFileModification));
    }

    #[test]
    fn critical_file_modification_does_not_fire_on_read() {
        let det = TriggerDetector::new();
        let focal = file_open(42, 1001, "/etc/ssh/sshd_config", 0, 1);
        let hits = det.detect(&focal, &[]);
        assert!(!hits.contains(&TriggerType::CriticalFileModification));
    }

    #[test]
    fn confirmed_intrusion_fires_on_exec_from_tmp() {
        let det = TriggerDetector::new();
        let focal = spawn(42, 1, "evil", "/tmp/evil", 1);
        let hits = det.detect(&focal, &[]);
        assert!(hits.contains(&TriggerType::ConfirmedIntrusion));
    }

    #[test]
    fn confirmed_intrusion_fires_on_any_fs_protect_denial() {
        // Tappa 7: a kernel-side denial of root's tamper attempt is
        // by definition a confirmed intrusion — push posture all
        // the way to COMBAT on a single event.
        let det = TriggerDetector::new();
        let focal = Event::FsProtectDenial {
            pid: 9999,
            uid: 0,
            comm: "rm".into(),
            target_dev: 64_770,
            target_ino: 12345,
            operation: common::FsProtectOperation::Unlink,
            timestamp_ns: 1,
        };
        let hits = det.detect(&focal, &[]);
        assert!(
            hits.contains(&TriggerType::ConfirmedIntrusion),
            "expected ConfirmedIntrusion, got {:?}",
            hits
        );
    }

    #[test]
    fn persistence_fires_on_cron_d_write() {
        let det = TriggerDetector::new();
        let focal = file_open(42, 1001, "/etc/cron.d/backdoor", 1, 1);
        let hits = det.detect(&focal, &[]);
        assert!(hits.contains(&TriggerType::PersistenceMechanism));
    }

    #[test]
    fn lateral_movement_fires_on_three_internal_ssh_targets() {
        let det = TriggerDetector::new();
        let recent = vec![
            tcp_v4(42, [10, 0, 0, 1], 22, 100),
            tcp_v4(42, [10, 0, 0, 2], 22, 200),
        ];
        let focal = tcp_v4(42, [10, 0, 0, 3], 22, 300);
        let hits = det.detect(&focal, &recent);
        assert!(hits.contains(&TriggerType::LateralMovement));
    }

    // ── 2026-05-22 self-trigger regression ────────────────────────────
    //
    // The agent appends to its own state logs on every observed event;
    // the observe-only `file_open` sensor reports those writes back into
    // the stream. >=MASS_WRITE_MIN of them in the 60 s window from one
    // PID used to self-trip ConfirmedIntrusion → COMBAT at boot,
    // isolating the network on a benign host. `with_self_pid` excludes
    // the agent's own events.

    const AGENT_PID: u32 = 4242;

    /// Build MASS_WRITE_MIN write-opens to the agent's drift log from
    /// `pid`, the exact shape of a fresh-boot FIM-logging burst.
    fn self_write_burst(pid: u32) -> (Event, Vec<Event>) {
        let path = "/var/lib/northnarrow/fim_drift.jsonl";
        let recent: Vec<Event> = (0..(MASS_WRITE_MIN as u64))
            .map(|i| file_open(pid, 0, path, 1, i + 1))
            .collect();
        let focal = file_open(pid, 0, path, 1, MASS_WRITE_MIN as u64 + 1);
        (focal, recent)
    }

    #[test]
    fn mass_write_self_trips_combat_without_exclusion() {
        // Documents the bug: a plain detector counts the agent's own
        // burst and fires ConfirmedIntrusion (COMBAT-tier).
        let det = TriggerDetector::new();
        let (focal, recent) = self_write_burst(AGENT_PID);
        let hits = det.detect(&focal, &recent);
        assert!(
            hits.contains(&TriggerType::ConfirmedIntrusion),
            "baseline (no self-pid) must still count the burst: {hits:?}"
        );
    }

    #[test]
    fn mass_write_does_not_fire_on_agents_own_writes() {
        // The fix: a detector that knows the agent's PID ignores the
        // agent's own state-log burst entirely.
        let det = TriggerDetector::with_self_pid(AGENT_PID);
        let (focal, recent) = self_write_burst(AGENT_PID);
        let hits = det.detect(&focal, &recent);
        assert!(
            hits.is_empty(),
            "agent's own writes must raise no triggers, got {hits:?}"
        );
    }

    #[test]
    fn mass_write_still_fires_on_other_pid_when_self_excluded() {
        // Self-exclusion must not blind us to a real attacker: an
        // identical burst from a different PID still trips COMBAT.
        let det = TriggerDetector::with_self_pid(AGENT_PID);
        let attacker = AGENT_PID + 1;
        let (focal, recent) = self_write_burst(attacker);
        let hits = det.detect(&focal, &recent);
        assert!(
            hits.contains(&TriggerType::ConfirmedIntrusion),
            "a non-agent mass-write must still fire: {hits:?}"
        );
    }

    #[test]
    fn fs_protect_denial_still_fires_when_self_excluded() {
        // Tamper on the agent's own files by another PID is denied by
        // the LSM and surfaced as FsProtectDenial — self-exclusion must
        // not suppress it (it is keyed on the *toucher's* PID, not the
        // agent's).
        let det = TriggerDetector::with_self_pid(AGENT_PID);
        let focal = Event::FsProtectDenial {
            pid: AGENT_PID + 7,
            uid: 0,
            comm: "rm".into(),
            target_dev: 64_770,
            target_ino: 12345,
            operation: common::FsProtectOperation::Unlink,
            timestamp_ns: 1,
        };
        let hits = det.detect(&focal, &[]);
        assert!(hits.contains(&TriggerType::ConfirmedIntrusion), "{hits:?}");
    }
}
