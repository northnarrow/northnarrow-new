//! Continuous telemetry probe (Tappa 10.8).
//!
//! Coverage as a product function, not only as a lab test: every
//! [`DEFAULT_INTERVAL_SECS`] the agent runs a child of its own binary
//! (`northnarrow-agent --telemetry-probe <nonce>`) that produces one known,
//! harmless event per probed sensor — an **exec** (the child itself), a
//! **file open** of `/run/northnarrow/probe/<nonce>` and a **DNS datagram**
//! naming `<nonce>.probe.northnarrow.invalid` sent to the loopback resolver
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
//! dedicated directory, not one of the honeypot paths; the DNS datagram goes
//! to 127.0.0.1:53 whether or not a resolver listens there (the sensor
//! hooks the send, not the answer). None of the three trips a rule.
//!
//! External audit EVD-015 (NN-AUD-278): the datagram must not reach a name
//! server off the host. It used to be a recursive query (`RD`) with a nonce
//! made of the clock and the agent's pid: a forwarding resolver on
//! 127.0.0.1:53 (dnsmasq, BIND in forward mode) passed it upstream every
//! minute, a beacon naming the product, its pid and the time. Now:
//!
//! - the nonce is 64 bits from the OS random source ([`make_nonce`]);
//! - the datagram is flagged as a **response** (`QR`=1, `RD`=0,
//!   [`dns_probe_packet`]): a name server drops a response that arrives on
//!   its query port instead of answering or forwarding it (dnsmasq,
//!   unbound, BIND and systemd-resolved do; the lab checks dnsmasq). Both
//!   DNS sensors skip the 12-byte header and read the name only
//!   (`agent-ebpf/src/dns_skb.rs`, `dns_query.rs`): the flags change
//!   nothing they see;
//! - it is sent from 127.0.0.1 to 127.0.0.1 ([`PROBE_DNS_SOURCE`],
//!   [`PROBE_DNS_DEST`]): loopback is never routed off the host, and a
//!   packet with a loopback source that a NAT rule redirected elsewhere is
//!   dropped as a martian.
//!
//! `MSG_PROBE` (the audit's proposal: the kernel runs `udp_sendmsg` but
//! builds no packet) is not used: `ip_make_skb`/`ip6_make_skb` return no
//! buffer for it (5.15, 6.1, 6.8, 6.12), so `udp_send_skb`, where the
//! default sensor reads the query, is never called and every round would
//! be a DNS telemetry gap. A TEST-NET destination is not used either: it is
//! routed through the default gateway, off the host.
//!
//! Tap: [`observe`] is called on every event before the decision engine
//! (the agent's event loop) and is a few comparisons when a round is open,
//! nothing otherwise. Disabled with `NN_TELEMETRY_PROBE_SECS=0`.

use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, UdpSocket};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use nn_model::Event;
use parking_lot::Mutex;
use rand::rngs::SysRng;
use rand::TryRng;
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
/// Where the probe's DNS datagram goes: the loopback resolver port. Port 53
/// is the sensor's filter; loopback keeps the datagram on the host.
pub const PROBE_DNS_DEST: SocketAddrV4 = SocketAddrV4::new(Ipv4Addr::LOCALHOST, 53);
/// The address the probe child sends from (any free port).
pub const PROBE_DNS_SOURCE: SocketAddrV4 = SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0);
/// Random bytes in a round nonce (16 hex characters).
pub const NONCE_BYTES: usize = 8;
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

/// Round nonce: [`NONCE_BYTES`] bytes from the OS random source, lowercase
/// hex, 16 characters; `None` when the source fails (the round is skipped).
/// External audit EVD-015 (NN-AUD-278): it was the clock and the agent's
/// pid, which the probed name carried to any resolver that saw it.
///
/// It is the first DNS label of the probed name, and a label of 20+
/// alphanumerics is what NN-L-NET-004 called a base64 payload until
/// external audit NETR-002 (the first lab run tripped it with a 4-digit
/// pid) — the probe must never fire a rule: it stays below NN-L-NET-014's
/// 25-character label and NN-L-NET-004's 60-character name.
pub fn make_nonce() -> Option<String> {
    let mut b = [0u8; NONCE_BYTES];
    SysRng.try_fill_bytes(&mut b).ok()?;
    Some(hex::encode(b))
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
    let Some(nonce) = make_nonce() else {
        warn!("telemetry probe: the OS random source failed — round skipped");
        return;
    };
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
        client_exe: None,
    };
    if let Err(e) = log.lock().append(draft) {
        warn!(
            error = format!("{e:#}"),
            op, "telemetry probe: audit entry failed"
        );
    }
}

/// The child's side (`northnarrow-agent --telemetry-probe <nonce>`): one
/// file open and one DNS datagram, then exit. Errors are ignored on purpose
/// — a sensor is probed by the attempt, not by the outcome.
pub fn run_child(nonce: &str) -> i32 {
    let _ = std::fs::read(probe_file(nonce));
    let _ = send_dns_probe(&dns_name(nonce), SocketAddr::V4(PROBE_DNS_DEST));
    0
}

/// Send the probe datagram for `name` to `to` from [`PROBE_DNS_SOURCE`].
/// `to` is [`PROBE_DNS_DEST`] outside the tests.
pub fn send_dns_probe(name: &str, to: SocketAddr) -> std::io::Result<usize> {
    let sock = UdpSocket::bind(PROBE_DNS_SOURCE)?;
    sock.set_write_timeout(Some(Duration::from_millis(500)))?;
    sock.send_to(&dns_probe_packet(name), to)
}

/// `QR`: the message is a response (header byte 2, bit 7).
pub const DNS_FLAG_QR: u8 = 0x80;
/// `RD`: recursion desired (header byte 2, bit 0).
pub const DNS_FLAG_RD: u8 = 0x01;

/// The probe's DNS message for `name` (A, IN), wire format. External audit
/// EVD-015 (NN-AUD-278): flagged as a response with no recursion asked
/// (`QR`=1, `RD`=0, no answer records), so a name server that receives it
/// on its query port discards it instead of answering or forwarding it.
/// The DNS sensors read the name after the header, never the flags. Also
/// used by `--sensor-feasibility` (`sensor_feasibility::exercise_dns`).
pub fn dns_probe_packet(name: &str) -> Vec<u8> {
    let mut p = Vec::with_capacity(32 + name.len());
    // id, flags (QR, opcode QUERY, RD clear, rcode 0), QDCOUNT=1, no records
    p.extend_from_slice(&[0x4e, 0x4e, DNS_FLAG_QR, 0x00, 0, 1, 0, 0, 0, 0, 0, 0]);
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
            argv_truncated: false,
            filename_truncated: false,
            stdio: Default::default(),
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
            kernel_class: 0,
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
        let n = make_nonce().unwrap();
        assert!(n.len() <= 16, "{n}");
        let name = dns_name(&n);
        assert!(
            name.split('.').next().unwrap().len() < 20,
            "below NN-L-NET-014's label length"
        );
        assert!(name.len() <= 60, "NN-L-NET-004 length");
    }

    /// External audit EVD-015 (NN-AUD-278): the nonce is random — no pid,
    /// no clock in a name a resolver may see.
    #[test]
    fn nonce_is_random_not_pid_or_clock() {
        let a = make_nonce().unwrap();
        let b = make_nonce().unwrap();
        assert_ne!(a, b);
        for n in [&a, &b] {
            assert_eq!(n.len(), 2 * NONCE_BYTES, "{n}");
            assert!(n
                .bytes()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
        }
        // 64 random bits: two nonces sharing the pid's hex tail is a
        // 1-in-2^24 accident at most, a clock-and-pid nonce always does it
        let pid = format!("{:x}", std::process::id() & 0xFF_FFFF);
        assert!(
            !(a.ends_with(&pid) && b.ends_with(&pid)),
            "nonce carries the pid: {a} {b}"
        );
    }

    #[test]
    fn dns_packet_is_well_formed() {
        let p = dns_probe_packet("ab.probe.northnarrow.invalid");
        assert_eq!(&p[..12], &[0x4e, 0x4e, 0x80, 0, 0, 1, 0, 0, 0, 0, 0, 0]);
        assert_eq!(p[12], 2);
        assert_eq!(&p[13..15], b"ab");
        assert_eq!(p[15], 5);
        assert_eq!(&p[p.len() - 5..], &[0, 0, 1, 0, 1]);
    }

    /// External audit EVD-015 (NN-AUD-278): a name server must discard the
    /// probe, not answer or forward it — a response (`QR`), no recursion
    /// asked (`RD` clear), no answer records.
    #[test]
    fn probe_packet_is_a_response_no_resolver_forwards() {
        let p = dns_probe_packet(&dns_name("0123456789abcdef"));
        assert_eq!(p[2] & DNS_FLAG_QR, DNS_FLAG_QR, "QR set");
        assert_eq!(p[2] & DNS_FLAG_RD, 0, "RD clear");
        assert_eq!(p[2] & 0x78, 0, "opcode QUERY");
        assert_eq!(
            &p[4..12],
            &[0, 1, 0, 0, 0, 0, 0, 0],
            "one question, no records"
        );
    }

    /// External audit EVD-015 (NN-AUD-278): the datagram goes from loopback
    /// to loopback port 53 and carries the probed name after the header,
    /// where the sensors read it.
    #[test]
    fn probe_datagram_stays_on_loopback_and_carries_the_name() {
        assert!(PROBE_DNS_DEST.ip().is_loopback());
        assert_eq!(PROBE_DNS_DEST.port(), 53, "the sensors' filter");
        assert!(PROBE_DNS_SOURCE.ip().is_loopback());
        let listener = UdpSocket::bind("127.0.0.1:0").unwrap();
        listener
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let name = dns_name("0123456789abcdef");
        let sent = send_dns_probe(&name, listener.local_addr().unwrap()).unwrap();
        let mut buf = [0u8; 512];
        let (n, from) = listener.recv_from(&mut buf).unwrap();
        assert_eq!(n, sent);
        assert!(from.ip().is_loopback(), "{from}");
        assert_eq!(&buf[..n], &dns_probe_packet(&name)[..]);
        assert_eq!(buf[2] & DNS_FLAG_QR, DNS_FLAG_QR);
        assert_eq!(&buf[13..29], b"0123456789abcdef");
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
