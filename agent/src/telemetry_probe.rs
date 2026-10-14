//! Continuous telemetry probe (Tappa 10.8).
//!
//! Coverage as a product function, not only as a lab test: every
//! [`DEFAULT_INTERVAL_SECS`] the agent runs a child of its own binary
//! (`northnarrow-agent --telemetry-probe <nonce>`) that produces one known,
//! harmless event per probed sensor — an **exec** (the child itself), a
//! **file open** of `/run/northnarrow/probe/<nonce>` and a **DNS query**
//! for `<nonce>.probe.northnarrow.invalid` sent to the loopback resolver
//! port — and checks that each one reaches its own event pipeline within
//! [`DEADLINE_SECS`]. A sensor that stays silent is a **telemetry gap**:
//! ERROR in the journal and a signed audit entry (`telemetry_gap`), once per
//! gap, with `telemetry_restored` when the sensor is seen again. A hook that
//! was detached, a ring that stopped being drained or a kernel that
//! silently broke a tracepoint layout is caught in a minute instead of at
//! the next incident.
//!
//! The probe child is the agent binary, so the exec is one of a root-owned
//! binary from its install path with an ordinary argv; the probe file is a
//! dedicated directory, not one of the honeypot paths; the DNS packet goes
//! to 127.0.0.1:53 whether or not a resolver listens there (the sensor
//! hooks the send, not the answer). None of the three trips a rule.
//!
//! Tap: [`observe`] is called on every event before the decision engine
//! (`main.rs` event loop) and is a few comparisons when a round is open,
//! nothing otherwise. Disabled with `NN_TELEMETRY_PROBE_SECS=0`.

use std::net::UdpSocket;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use common::Event;
use parking_lot::Mutex;
use tracing::{debug, error, info, warn};

use crate::audit::{AuditEntryDraft, AuditLog};

/// Seconds between rounds; `0` disables the probe.
pub const INTERVAL_ENV: &str = "NN_TELEMETRY_PROBE_SECS";
pub const DEFAULT_INTERVAL_SECS: u64 = 60;
/// First round after boot (sensors and consumers must be up).
pub const FIRST_ROUND_SECS: u64 = 20;
/// Seconds a probed event has to reach the pipeline.
pub const DEADLINE_SECS: u64 = 5;
/// Directory of the probe files (RuntimeDirectory of the unit).
pub const PROBE_DIR: &str = "/run/northnarrow/probe";
/// The child's argv[1]; `argv[2]` is the nonce.
pub const PROBE_FLAG: &str = "--telemetry-probe";
/// Suffix of the probed DNS name (`.invalid` is reserved, never resolves).
pub const DNS_SUFFIX: &str = ".probe.northnarrow.invalid";
pub const AUDIT_OP_GAP: &str = "telemetry_gap";
pub const AUDIT_OP_RESTORED: &str = "telemetry_restored";

/// The sensors a round probes, in slot order.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Sensor {
    Exec = 0,
    FileOpen = 1,
    Dns = 2,
}

impl Sensor {
    pub const ALL: [Sensor; 3] = [Sensor::Exec, Sensor::FileOpen, Sensor::Dns];

    pub fn name(self) -> &'static str {
        match self {
            Sensor::Exec => "exec",
            Sensor::FileOpen => "file_open",
            Sensor::Dns => "dns",
        }
    }
}

/// One open round: the nonce the child carries and what has been seen.
struct Round {
    nonce: String,
    seen: [bool; 3],
}

#[derive(Default)]
struct State {
    round: Option<Round>,
    /// Sensors currently in a gap (an audit entry was written; the next
    /// hit writes `telemetry_restored`).
    in_gap: [bool; 3],
    /// Rounds completed.
    rounds: u64,
}

static TRACKER: OnceLock<Arc<Mutex<State>>> = OnceLock::new();
static GAPS_TOTAL: AtomicU64 = AtomicU64::new(0);

/// Round nonce: 40 low bits of the clock and the pid, hex, at most 16
/// characters. It is the first DNS label of the probed name, and a label of
/// 20+ alphanumerics is what NN-L-NET-004 called a base64 payload until
/// external audit NETR-002 (the first lab run tripped it with a 4-digit
/// pid) — the probe must never fire a rule: it stays below NN-L-NET-014's
/// 25-character label and NN-L-NET-004's 60-character name.
pub fn make_nonce(nanos: u64, pid: u32) -> String {
    format!("{:x}{:x}", nanos & 0xFF_FFFF_FFFF, pid & 0xFF_FFFF)
}

/// Probe file of a round.
pub fn probe_file(nonce: &str) -> PathBuf {
    PathBuf::from(PROBE_DIR).join(nonce)
}

/// Probed DNS name of a round.
pub fn dns_name(nonce: &str) -> String {
    format!("{nonce}{DNS_SUFFIX}")
}

/// Which probed sensor, if any, an event belongs to.
pub fn matches(event: &Event, nonce: &str) -> Option<Sensor> {
    match event {
        Event::ProcessSpawn { argv, .. } => {
            if argv.len() >= 3 && argv[1] == PROBE_FLAG && argv[2] == nonce {
                Some(Sensor::Exec)
            } else {
                None
            }
        }
        Event::FileOpen { filename, .. } => {
            if filename.as_str() == probe_file(nonce).to_string_lossy() {
                Some(Sensor::FileOpen)
            } else {
                None
            }
        }
        Event::DnsQuery { query_name, .. } => {
            if query_name
                .trim_end_matches('.')
                .eq_ignore_ascii_case(&dns_name(nonce))
            {
                Some(Sensor::Dns)
            } else {
                None
            }
        }
        _ => None,
    }
}

/// Event tap: called for every event before the decision engine.
pub fn observe(event: &Event) {
    let Some(tracker) = TRACKER.get() else {
        return;
    };
    let mut st = tracker.lock();
    let Some(round) = st.round.as_mut() else {
        return;
    };
    if let Some(sensor) = matches(event, &round.nonce) {
        round.seen[sensor as usize] = true;
    }
}

/// Telemetry gaps since boot (all sensors, all rounds).
pub fn gaps_total() -> u64 {
    GAPS_TOTAL.load(Ordering::Relaxed)
}

/// Round interval from the environment (`None` = disabled).
pub fn interval_from_env() -> Option<Duration> {
    match std::env::var(INTERVAL_ENV) {
        Ok(v) => match v.trim().parse::<u64>() {
            Ok(0) => None,
            Ok(secs) => Some(Duration::from_secs(secs.max(DEADLINE_SECS + 1))),
            Err(_) => Some(Duration::from_secs(DEFAULT_INTERVAL_SECS)),
        },
        Err(_) => Some(Duration::from_secs(DEFAULT_INTERVAL_SECS)),
    }
}

/// Does this value of [`INTERVAL_ENV`] weaken the probe? It does when it
/// switches the probe off (any spelling of 0) or spaces the rounds out
/// beyond the default; a value that does not parse keeps the default.
pub fn interval_weakens(value: &str) -> bool {
    value
        .trim()
        .parse::<u64>()
        .is_ok_and(|secs| secs == 0 || secs > DEFAULT_INTERVAL_SECS)
}

/// Start the periodic probe (from `main`, once the audit log exists).
pub fn spawn(audit_log: Option<Arc<Mutex<AuditLog>>>) {
    let Some(every) = interval_from_env() else {
        info!(env = INTERVAL_ENV, "telemetry probe disabled");
        return;
    };
    if let Err(e) = std::fs::create_dir_all(PROBE_DIR) {
        warn!(error = %e, dir = PROBE_DIR, "telemetry probe: cannot create the probe directory — probe disabled");
        return;
    }
    let tracker = Arc::new(Mutex::new(State::default()));
    if TRACKER.set(tracker.clone()).is_err() {
        return;
    }
    info!(
        every_secs = every.as_secs(),
        deadline_secs = DEADLINE_SECS,
        sensors = ?Sensor::ALL.iter().map(|s| s.name()).collect::<Vec<_>>(),
        "telemetry probe armed — a silent sensor becomes a telemetry_gap audit entry"
    );
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_secs(FIRST_ROUND_SECS)).await;
        loop {
            run_round(&tracker, audit_log.as_ref()).await;
            // ±20 %: a round cannot be predicted and dodged.
            tokio::time::sleep(crate::self_integrity::jittered(every)).await;
        }
    });
}

async fn run_round(tracker: &Arc<Mutex<State>>, audit_log: Option<&Arc<Mutex<AuditLog>>>) {
    let nonce = make_nonce(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0),
        std::process::id(),
    );
    let file = probe_file(&nonce);
    if let Err(e) = std::fs::write(&file, b"nn-telemetry-probe\n") {
        warn!(error = %e, path = %file.display(), "telemetry probe: cannot write the probe file — round skipped");
        return;
    }
    tracker.lock().round = Some(Round {
        nonce: nonce.clone(),
        seen: [false; 3],
    });
    let started = Instant::now();
    let exe = match std::env::current_exe() {
        Ok(p) => p,
        Err(e) => {
            warn!(error = %e, "telemetry probe: current_exe unknown — round skipped");
            tracker.lock().round = None;
            let _ = std::fs::remove_file(&file);
            return;
        }
    };
    let spawned = Command::new(&exe)
        .arg(PROBE_FLAG)
        .arg(&nonce)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn();
    let mut child = match spawned {
        Ok(c) => c,
        Err(e) => {
            warn!(error = %e, exe = %exe.display(), "telemetry probe: cannot spawn the probe child — round skipped");
            tracker.lock().round = None;
            let _ = std::fs::remove_file(&file);
            return;
        }
    };
    // Reap the child off the async thread; it exits in milliseconds.
    let _ = tokio::task::spawn_blocking(move || child.wait()).await;
    // Wait for the pipeline, up to the deadline.
    loop {
        if tracker
            .lock()
            .round
            .as_ref()
            .map(|r| r.seen.iter().all(|s| *s))
            .unwrap_or(true)
            || started.elapsed() >= Duration::from_secs(DEADLINE_SECS)
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    let _ = std::fs::remove_file(&file);
    let (seen, in_gap_before) = {
        let mut st = tracker.lock();
        let seen = st.round.take().map(|r| r.seen).unwrap_or([false; 3]);
        st.rounds += 1;
        let before = st.in_gap;
        for s in Sensor::ALL {
            st.in_gap[s as usize] = !seen[s as usize];
        }
        (seen, before)
    };
    let latency_ms = started.elapsed().as_millis() as u64;
    for s in Sensor::ALL {
        let i = s as usize;
        match (seen[i], in_gap_before[i]) {
            (true, false) => debug!(sensor = s.name(), latency_ms, "telemetry probe: seen"),
            (true, true) => {
                info!(
                    sensor = s.name(),
                    "telemetry probe: sensor RESTORED — events flow again"
                );
                audit(audit_log, AUDIT_OP_RESTORED, s, &nonce, latency_ms);
            }
            (false, true) => {
                GAPS_TOTAL.fetch_add(1, Ordering::Relaxed);
                error!(
                    sensor = s.name(),
                    nonce, "telemetry probe: sensor still SILENT (gap continues)"
                );
            }
            (false, false) => {
                GAPS_TOTAL.fetch_add(1, Ordering::Relaxed);
                error!(
                    sensor = s.name(),
                    nonce,
                    deadline_secs = DEADLINE_SECS,
                    "TELEMETRY GAP — a probed event never reached the pipeline: hook detached, ring not drained \
                     or layout broken on this kernel"
                );
                audit(audit_log, AUDIT_OP_GAP, s, &nonce, latency_ms);
            }
        }
    }
}

fn audit(
    log: Option<&Arc<Mutex<AuditLog>>>,
    op: &str,
    sensor: Sensor,
    nonce: &str,
    latency_ms: u64,
) {
    let Some(log) = log else {
        return;
    };
    let draft = AuditEntryDraft {
        op: op.to_string(),
        extra: serde_json::json!({
            "sensor": sensor.name(),
            "nonce": nonce,
            "deadline_secs": DEADLINE_SECS,
            "latency_ms": latency_ms,
            "gaps_total": gaps_total(),
        }),
        key_fp: "agent-self".to_string(),
        cosigner_fps: Vec::new(),
        result: if op == AUDIT_OP_GAP {
            "detected"
        } else {
            "success"
        }
        .to_string(),
        client_pid: std::process::id(),
        client_uid: 0,
        client_comm: "northnarrow-agent".to_string(),
    };
    if let Err(e) = log.lock().append(draft) {
        warn!(
            error = format!("{e:#}"),
            op, "telemetry probe: audit entry failed"
        );
    }
}

/// The child's side (`northnarrow-agent --telemetry-probe <nonce>`): one
/// file open and one DNS packet, then exit. Errors are ignored on purpose —
/// a sensor is probed by the attempt, not by the outcome.
pub fn run_child(nonce: &str) -> i32 {
    let _ = std::fs::read(probe_file(nonce));
    if let Ok(sock) = UdpSocket::bind("127.0.0.1:0") {
        let _ = sock.set_write_timeout(Some(Duration::from_millis(500)));
        let _ = sock.send_to(&dns_query_packet(&dns_name(nonce)), "127.0.0.1:53");
    }
    0
}

/// Minimal DNS query (A, IN) for `name`, wire format.
pub fn dns_query_packet(name: &str) -> Vec<u8> {
    let mut p = Vec::with_capacity(32 + name.len());
    p.extend_from_slice(&[0x4e, 0x4e, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0]); // id, RD, QDCOUNT=1
    for label in name.split('.').filter(|l| !l.is_empty()) {
        let bytes = label.as_bytes();
        let n = bytes.len().min(63);
        p.push(n as u8);
        p.extend_from_slice(&bytes[..n]);
    }
    p.push(0);
    p.extend_from_slice(&[0, 1, 0, 1]); // QTYPE A, QCLASS IN
    p
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spawn_event(argv: &[&str]) -> Event {
        Event::ProcessSpawn {
            pid: 1,
            ppid: 1,
            uid: 0,
            gid: 0,
            comm: "northnarrow-age".into(),
            filename: "/usr/local/bin/northnarrow-agent".into(),
            timestamp_ns: 0,
            argv: argv.iter().map(|s| s.to_string()).collect(),
            parent_comm: "northnarrow-age".into(),
            parent_start_ns: 0,
            start_ns: 0,
            parent_is_kthread: false,
            exe: Default::default(),
        }
    }

    #[test]
    fn matcher_recognises_the_three_probes_and_nothing_else() {
        let n = "abc123";
        assert_eq!(
            matches(&spawn_event(&["northnarrow-agent", PROBE_FLAG, n]), n),
            Some(Sensor::Exec)
        );
        assert_eq!(
            matches(&spawn_event(&["northnarrow-agent", PROBE_FLAG, "other"]), n),
            None
        );
        assert_eq!(matches(&spawn_event(&["ls"]), n), None);
        let fo = Event::FileOpen {
            pid: 1,
            uid: 0,
            gid: 0,
            comm: "x".into(),
            filename: format!("{PROBE_DIR}/{n}"),
            flags: 0,
            timestamp_ns: 0,
            path_from_user: false,
        };
        assert_eq!(matches(&fo, n), Some(Sensor::FileOpen));
        let dns = Event::DnsQuery {
            pid: 1,
            uid: 0,
            comm: "x".into(),
            exe: None,
            query_name: format!("{n}{DNS_SUFFIX}.").to_uppercase(),
            query_type: 1,
            dns_server: [0u8; 16],
            family: 2,
            timestamp_ns: 0,
            qname_partial: false,
        };
        assert_eq!(matches(&dns, n), Some(Sensor::Dns));
    }

    #[test]
    fn probe_name_stays_below_the_dns_tunnel_rule() {
        // worst case: all 40 clock bits and a 24-bit pid set
        let n = make_nonce(u64::MAX, u32::MAX);
        assert!(n.len() <= 16, "{n}");
        let name = dns_name(&n);
        assert!(
            name.split('.').next().unwrap().len() < 20,
            "below NN-L-NET-014's label length"
        );
        assert!(name.len() <= 60, "NN-L-NET-004 length");
    }

    #[test]
    fn dns_packet_is_well_formed() {
        let p = dns_query_packet("ab.probe.northnarrow.invalid");
        assert_eq!(&p[..12], &[0x4e, 0x4e, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0]);
        assert_eq!(p[12], 2);
        assert_eq!(&p[13..15], b"ab");
        assert_eq!(p[15], 5);
        assert_eq!(&p[p.len() - 5..], &[0, 0, 1, 0, 1]);
    }

    #[test]
    fn interval_env_zero_disables() {
        std::env::set_var(INTERVAL_ENV, "0");
        assert!(interval_from_env().is_none());
        std::env::set_var(INTERVAL_ENV, "3");
        assert_eq!(
            interval_from_env(),
            Some(Duration::from_secs(DEADLINE_SECS + 1))
        );
        std::env::remove_var(INTERVAL_ENV);
        assert_eq!(
            interval_from_env(),
            Some(Duration::from_secs(DEFAULT_INTERVAL_SECS))
        );
    }
}
