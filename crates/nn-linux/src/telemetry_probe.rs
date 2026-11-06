//! Continuous telemetry probe (Tappa 10.8), the sensor self-test since lot
//! 280c: every source of the sensor contract proves it is alive, every
//! round.
//!
//! Coverage as a product function, not only as a lab test: every
//! [`DEFAULT_INTERVAL_SECS`] (±20 %) the agent runs a child of its own
//! binary (`northnarrow-agent --telemetry-probe <nonce>`) that makes one
//! known, harmless event per source ([`Sensor`]) and checks that each one
//! reaches its own event pipeline within [`DEADLINE_SECS`]:
//!
//! - **exec** and **exec check**: the child's own exec (`process_spawn`'s
//!   `sched_process_exec`, `exec_check`'s `bprm_check_security`);
//! - **file open**: a read of `/run/northnarrow/probe/<nonce>`
//!   (`open_sensor`, or the `file_open` tracepoint on its fallback);
//! - **DNS**: a datagram naming `<nonce>.probe.northnarrow.invalid` sent to
//!   the loopback resolver port (`dns_query`);
//! - **network**: a listener on a loopback port (`net_drain`'s listen
//!   kprobe), a connect to it (`tcp_connect`), its accept (`net_inbound`),
//!   a TLS ClientHello as the connection's first send (`tls_hello`);
//! - **io_uring**: a ring of one entry made and closed (`io_uring`);
//! - **bpf**: a one-entry array map made and closed (`bpf_syscall`);
//! - **FIM**: a file created in the probe directory, which the FIM watches
//!   (`fim_drain`);
//! - **deny**: a signal to the agent and a file created in
//!   `/etc/northnarrow`, both refused by the deny hooks (`fs_protect`).
//!
//! Three sources have no cheap, harmless event, and get a check of their
//! attach instead ([`Sensor::live`] false): `module_load` (loading a module
//! is neither), whose programs must still be linked and whose loads must
//! account for every module new in `/proc/modules` since the last round;
//! `exploit_guard` (its event is an exploit's post-condition) and
//! `dns_answer` (its event is a response from port 53, which the unit
//! cannot bind: no `CAP_NET_BIND_SERVICE`; a query to a real resolver is
//! what external audit EVD-015 forbids), whose programs must still be
//! linked.
//!
//! A source whose event does not come (or whose check fails) is **missed**:
//! a signed degradation at once (`subsystem_degraded`, source
//! [`DEGRADATION_SOURCE`], the sensor and the step named), the manifest's
//! word `missed` (the source `unknown`); missed in two rounds in a row it
//! is an **alert** ([`AUDIT_OP_ALERT`], ERROR in the journal, the word
//! `gap`, the source `attached_not_invoked`); seen again, the degradation
//! is withdrawn and the return signed ([`AUDIT_OP_RESTORED`]). A step that
//! cannot run on this host (io_uring switched off, a trusted-installer
//! window open — the deny hooks refuse nothing then, by design) is `not
//! exercised`: the round says nothing of that source.
//!
//! The self-test's events are **taken** before the decision engine
//! ([`TelemetryProbe::observe`], the decision thread's first step): they
//! never reach the rules, the posture or the detection store. A taken
//! event is the child's own (its pid, within its lifetime — the child is
//! reaped by the agent, so its pid cannot be reused before), of the shape
//! its step makes (the round's nonce, a loopback address, the expected
//! target), and at most as many as the step makes: anything else the child
//! did is judged as any process's. The network and FIM drains skip the
//! child's rows in their signed logs ([`SelfTestTag`]), so the export never
//! carries them as real flows or drift.
//!
//! The probe child is the agent binary, so the exec is one of a root-owned
//! binary from its install path with an ordinary argv; the probe files are
//! a dedicated directory, not one of the honeypot paths; the DNS datagram
//! goes to 127.0.0.1:53 whether or not a resolver listens there (the sensor
//! hooks the send, not the answer).
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
//! Tap: [`TelemetryProbe::observe`] is called on every event before the
//! decision engine (the agent's decision thread) and is a few comparisons
//! when a round is open (one counter for a module load), nothing otherwise.
//! Disabled with `NN_TELEMETRY_PROBE_SECS=0`.

use std::collections::HashSet;
use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, TcpListener, TcpStream, UdpSocket};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use nn_model::{Event, FsProtectOperation};
use parking_lot::Mutex;
use rand::rngs::SysRng;
use rand::TryRng;
use tracing::{debug, error, info, warn};

use crate::audit::{AuditEntryDraft, AuditLog};
use nn_core::contract::manifest::ProbeState;

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
/// Lot 280c: the source of the signed degradation a missed round is
/// (`subsystem_degraded`, the sensor and the step in its detail).
pub const DEGRADATION_SOURCE: &str = "sensor_selftest";
/// Lot 280c: two rounds in a row missed a sensor.
pub const AUDIT_OP_ALERT: &str = "sensor_selftest_alert";
/// Lot 280c: a sensor missed is seen again.
pub const AUDIT_OP_RESTORED: &str = "sensor_selftest_restored";
/// The directory the deny step creates a file in: the agent's
/// configuration directory, registered `NOCREATE` and not `chattr +i` (the
/// state directory is: there the kernel refuses a create before any LSM
/// hook runs, and the deny would never be exercised).
pub const DENY_DIR: &str = crate::anti_tamper::filesystem::CONFIG_DIR;
/// The signal the deny step sends the agent (ignored by default, no
/// handler: let through by a blind hook, it changes nothing).
pub const DENY_SIGNAL: i32 = libc::SIGURG;
/// The round's budget (lot 280c): the child's CPU time and the agent's own
/// checks, per round. The lab measured at most 3.9 ms of the child's CPU
/// and 6.5 ms of the agent's checks a round on Ubuntu 24.04, 2.6 and 3.1 ms
/// on 22.04, over ten rounds each (`docs/roadmap/CAPABILITY_PROGRAM.md`,
/// lot 280c); a round over it is a signed degradation until a round is
/// back under.
pub const ROUND_CPU_BUDGET: Duration = Duration::from_millis(50);
/// How long the child may run before it is killed (its steps take
/// milliseconds; every socket wait in it is bounded below this).
pub const CHILD_TIMEOUT: Duration = Duration::from_secs(3);
/// A journal line with the rounds' cost every this many rounds.
pub const SUMMARY_EVERY: u64 = 10;
/// The go byte the parent writes once the child's pid is recorded: every
/// step.
pub const GO_ALL: u8 = b'g';
/// The go byte while a trusted-installer window is open: the deny steps
/// skipped (nothing is refused in a window, by design).
pub const GO_NO_DENY: u8 = b'w';

/// The sources a round exercises, in slot order: the live tests first,
/// then the attach checks.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Sensor {
    Exec = 0,
    FileOpen = 1,
    Dns = 2,
    ExecCheck = 3,
    TcpConnect = 4,
    NetListen = 5,
    NetInbound = 6,
    TlsHello = 7,
    IoUring = 8,
    Bpf = 9,
    Fim = 10,
    Deny = 11,
    ModuleLoad = 12,
    ExploitGuard = 13,
    DnsAnswer = 14,
}

/// How many sensors a round has a word on.
pub const SENSORS: usize = 15;

impl Sensor {
    pub const ALL: [Sensor; SENSORS] = [
        Sensor::Exec,
        Sensor::FileOpen,
        Sensor::Dns,
        Sensor::ExecCheck,
        Sensor::TcpConnect,
        Sensor::NetListen,
        Sensor::NetInbound,
        Sensor::TlsHello,
        Sensor::IoUring,
        Sensor::Bpf,
        Sensor::Fim,
        Sensor::Deny,
        Sensor::ModuleLoad,
        Sensor::ExploitGuard,
        Sensor::DnsAnswer,
    ];

    /// The word's name (the contract's `SourceContract::probe`).
    pub const fn name(self) -> &'static str {
        match self {
            Sensor::Exec => "exec",
            Sensor::FileOpen => "file_open",
            Sensor::Dns => "dns",
            Sensor::ExecCheck => "exec_check",
            Sensor::TcpConnect => "tcp_connect",
            Sensor::NetListen => "net_listen",
            Sensor::NetInbound => "net_inbound",
            Sensor::TlsHello => "tls_hello",
            Sensor::IoUring => "io_uring",
            Sensor::Bpf => "bpf",
            Sensor::Fim => "fim",
            Sensor::Deny => "deny",
            Sensor::ModuleLoad => "module_load",
            Sensor::ExploitGuard => "exploit_guard",
            Sensor::DnsAnswer => "dns_answer",
        }
    }

    /// The contract's source it speaks for (the first; `file_open` speaks
    /// for `open_sensor` and its standby `file_open` tracepoint).
    pub const fn source(self) -> &'static str {
        match self {
            Sensor::Exec => "process_spawn",
            Sensor::FileOpen => "open_sensor",
            Sensor::Dns => "dns_query",
            Sensor::ExecCheck => "exec_check",
            Sensor::TcpConnect => "tcp_connect",
            Sensor::NetListen => "net_drain",
            Sensor::NetInbound => "net_inbound",
            Sensor::TlsHello => "tls_hello",
            Sensor::IoUring => "io_uring",
            Sensor::Bpf => "bpf_syscall",
            Sensor::Fim => "fim_drain",
            Sensor::Deny => "fs_protect",
            Sensor::ModuleLoad => "module_load",
            Sensor::ExploitGuard => "exploit_guard",
            Sensor::DnsAnswer => "dns_answer",
        }
    }

    /// What the round does for it (the signed degradation names it).
    pub const fn step(self) -> &'static str {
        match self {
            Sensor::Exec => "the probe child's exec",
            Sensor::FileOpen => "a read of the probe file",
            Sensor::Dns => "a DNS datagram to 127.0.0.1:53",
            Sensor::ExecCheck => "the probe child's exec (bprm_check_security)",
            Sensor::TcpConnect => "a connect to the child's loopback listener",
            Sensor::NetListen => "a listen() on a loopback port",
            Sensor::NetInbound => "the accept of that connection",
            Sensor::TlsHello => "a ClientHello as the connection's first send",
            Sensor::IoUring => "an io_uring of one entry made and closed",
            Sensor::Bpf => "a one-entry BPF array map made and closed",
            Sensor::Fim => "a file created in the watched probe directory",
            Sensor::Deny => "a signal to the agent and a file created in /etc/northnarrow, refused",
            Sensor::ModuleLoad => {
                "its programs linked, and a load reported for each module new in /proc/modules"
            }
            Sensor::ExploitGuard => "its programs linked (attach check)",
            Sensor::DnsAnswer => "its programs linked (attach check)",
        }
    }

    /// A live event exercises it; `false`: an attach check.
    pub const fn live(self) -> bool {
        !matches!(
            self,
            Sensor::ModuleLoad | Sensor::ExploitGuard | Sensor::DnsAnswer
        )
    }

    /// The program names (prefixes) an attach check reads, as the agent's
    /// program-id list names them (`anti_tamper::bpf_defense`).
    pub const fn programs(self) -> &'static [&'static str] {
        match self {
            Sensor::ModuleLoad => &["module_read_file_observe", "module_load_data_observe"],
            Sensor::ExploitGuard => &["epg_"],
            Sensor::DnsAnswer => &["dns_answer_"],
            _ => &[],
        }
    }
}

/// The slot of the network rows the child's connection and datagram leave
/// (`NetFlow`): taken, never a sensor's word.
const SLOT_FLOW: usize = SENSORS;
const SLOTS: usize = SENSORS + 1;

/// At most this many events of a slot are taken per round: what the step
/// makes (the exec check: one per binfmt pass; the file opens: the probe
/// file and the FIM file; io_uring: the creation and an activity record;
/// the inbound accept and its close; the two deny refusals; the rows of
/// the two TCP sockets and the datagram).
const fn take_max(slot: usize) -> u8 {
    match slot {
        s if s == Sensor::FileOpen as usize => 3,
        s if s == Sensor::Dns as usize => 2,
        s if s == Sensor::NetInbound as usize => 2,
        s if s == Sensor::IoUring as usize => 2,
        s if s == Sensor::Fim as usize => 2,
        s if s == Sensor::Deny as usize => 2,
        SLOT_FLOW => 4,
        _ => 1,
    }
}

/// `CLOCK_MONOTONIC` in nanoseconds, the clock of `bpf_ktime_get_ns` (the
/// events' `timestamp_ns`).
pub fn monotonic_ns() -> u64 {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: a valid clock id and a timespec to fill.
    unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) };
    ts.tv_sec as u64 * 1_000_000_000 + ts.tv_nsec as u64
}

/// The probe child's lifetime: its pid from its spawn to its reap, on the
/// events' clock (`until_ns` is `u64::MAX` while it runs). The agent reaps
/// the child itself: its pid is not reused before `until_ns`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Window {
    pub pid: u32,
    pub from_ns: u64,
    pub until_ns: u64,
}

impl Window {
    /// `pid`'s, at `ts_ns`.
    pub fn holds(&self, pid: u32, ts_ns: u64) -> bool {
        self.pid != 0 && pid == self.pid && self.from_ns <= ts_ns && ts_ns <= self.until_ns
    }
}

/// Lot 280c: the self-test child's lifetimes (this round's and the one
/// before), for the drains that write signed logs before the bus: a row of
/// the child (`is_self_test`) is not written as a real flow, listener or
/// drift — the export never carries it — and is counted. Clones share it.
#[derive(Clone, Default)]
pub struct SelfTestTag {
    windows: Arc<Mutex<[Window; 2]>>,
    skipped: Arc<AtomicU64>,
}

impl SelfTestTag {
    /// A row or record of `pid` at `ts_ns` is the self-test child's.
    pub fn is_self_test(&self, pid: u32, ts_ns: u64) -> bool {
        self.windows.lock().iter().any(|w| w.holds(pid, ts_ns))
    }

    /// [`Self::is_self_test`], and counted when it is (the caller skips
    /// the row).
    pub fn skip(&self, pid: u32, ts_ns: u64) -> bool {
        let is = self.is_self_test(pid, ts_ns);
        if is {
            self.skipped.fetch_add(1, Ordering::Relaxed);
        }
        is
    }

    /// The rows skipped since the start.
    pub fn skipped(&self) -> u64 {
        self.skipped.load(Ordering::Relaxed)
    }

    /// Tests only: a tag whose child is `w`.
    #[cfg(any(test, feature = "test-util"))]
    pub fn for_tests(w: Window) -> Self {
        let t = Self::default();
        t.open(w);
        t
    }

    fn open(&self, w: Window) {
        let mut ws = self.windows.lock();
        ws[1] = ws[0];
        ws[0] = w;
    }

    fn close(&self, until_ns: u64) {
        self.windows.lock()[0].until_ns = until_ns;
    }
}

/// What the matcher needs of a round.
#[derive(Clone, Debug, Default)]
struct RoundId {
    nonce: String,
    /// The agent: the child's parent.
    agent_pid: u32,
    /// The path the child is executed by (`bprm->filename`).
    exe: String,
    child: Window,
    /// `(dev, ino)` of [`DENY_DIR`], kernel form.
    deny_dir: Option<(u64, u64)>,
}

/// One open round: what has been seen, and taken.
#[derive(Clone, Debug, Default)]
struct Round {
    id: RoundId,
    seen: [bool; SENSORS],
    /// The deny step's two refusals: the signal's, the create's.
    deny: [bool; 2],
    taken: [u8; SLOTS],
}

/// What a taken event is: its slot, the sensor it speaks for (none for a
/// row the step also makes) and, for the deny, which refusal.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Taken {
    slot: usize,
    sensor: Option<Sensor>,
    deny_part: Option<usize>,
}

fn taken(sensor: Sensor) -> Option<Taken> {
    Some(Taken {
        slot: sensor as usize,
        sensor: Some(sensor),
        deny_part: None,
    })
}

/// A loopback address in the kernel's 16-byte form of `family`.
fn loopback_raw(family: u8, addr: &[u8]) -> bool {
    if addr.len() < 16 {
        return false;
    }
    match family {
        2 => addr[0] == 127,
        10 => {
            (addr[..15].iter().all(|b| *b == 0) && addr[15] == 1)
                || (addr[..10].iter().all(|b| *b == 0)
                    && addr[10] == 0xff
                    && addr[11] == 0xff
                    && addr[12] == 127)
        }
        _ => false,
    }
}

/// The probe file of a round the FIM step creates.
pub fn fim_file(nonce: &str) -> PathBuf {
    PathBuf::from(PROBE_DIR).join(format!("{nonce}.fim"))
}

/// The file the deny step tries to create.
pub fn deny_file(nonce: &str) -> PathBuf {
    PathBuf::from(DENY_DIR).join(format!(".nn-selftest-{nonce}"))
}

/// Whether `e` is one of the round's own events, and which.
fn classify(e: &Event, id: &RoundId) -> Option<Taken> {
    let w = &id.child;
    match e {
        Event::ProcessSpawn { argv, ppid, .. } => (argv.len() >= 3
            && argv[1] == PROBE_FLAG
            && argv[2] == id.nonce
            && *ppid == id.agent_pid)
            .then(|| taken(Sensor::Exec))
            .flatten(),
        Event::ExecCheck {
            pid,
            ppid,
            filename,
            timestamp_ns,
            ..
        } => {
            // its event can reach the tap before the spawn returns the
            // child's pid: the agent's child, the agent's path, the round
            (*ppid == id.agent_pid
                && *filename == id.exe
                && (w.pid == 0 || *pid == w.pid)
                && w.from_ns <= *timestamp_ns
                && *timestamp_ns <= w.until_ns)
                .then(|| taken(Sensor::ExecCheck))
                .flatten()
        }
        Event::FileOpen { filename, .. } => {
            if filename.as_str() == probe_file(&id.nonce).to_string_lossy() {
                taken(Sensor::FileOpen)
            } else if filename.as_str() == fim_file(&id.nonce).to_string_lossy() {
                Some(Taken {
                    slot: Sensor::FileOpen as usize,
                    sensor: None,
                    deny_part: None,
                })
            } else {
                None
            }
        }
        Event::DnsQuery { query_name, .. } => query_name
            .trim_end_matches('.')
            .eq_ignore_ascii_case(&dns_name(&id.nonce))
            .then(|| taken(Sensor::Dns))
            .flatten(),
        Event::TcpConnect {
            pid,
            family,
            dst_addr,
            timestamp_ns,
            ..
        } => (w.holds(*pid, *timestamp_ns) && loopback_raw(*family, dst_addr))
            .then(|| taken(Sensor::TcpConnect))
            .flatten(),
        Event::NetListener(l) => (w.holds(l.pid, l.timestamp_ns) && l.bind_addr.is_loopback())
            .then(|| taken(Sensor::NetListen))
            .flatten(),
        Event::NetInbound(f) => (w.holds(f.pid, f.start_ns.max(f.end_ns))
            && f.src_addr.is_loopback()
            && f.dst_addr.is_loopback())
        .then(|| taken(Sensor::NetInbound))
        .flatten(),
        Event::TlsClientHello(h) => (w.holds(h.pid, h.timestamp_ns) && h.dst_addr.is_loopback())
            .then(|| taken(Sensor::TlsHello))
            .flatten(),
        Event::IoUring {
            pid,
            created,
            timestamp_ns,
            ..
        } => w.holds(*pid, *timestamp_ns).then(|| Taken {
            slot: Sensor::IoUring as usize,
            sensor: created.then_some(Sensor::IoUring),
            deny_part: None,
        }),
        Event::BpfSyscall {
            pid,
            cmd,
            timestamp_ns,
            ..
        } => (w.holds(*pid, *timestamp_ns) && *cmd == common::bpf_cmd::BPF_MAP_CREATE)
            .then(|| taken(Sensor::Bpf))
            .flatten(),
        Event::Fim(f) => (w.holds(f.modifier_pid, f.timestamp_ns)
            && f.path.starts_with(&format!("{PROBE_DIR}/")))
        .then(|| taken(Sensor::Fim))
        .flatten(),
        Event::FsProtectDenial {
            pid,
            operation,
            target_dev,
            target_ino,
            timestamp_ns,
            ..
        } => {
            if !w.holds(*pid, *timestamp_ns) {
                return None;
            }
            let part = match operation {
                FsProtectOperation::Signal
                    if *target_dev == DENY_SIGNAL as u64 && *target_ino == id.agent_pid as u64 =>
                {
                    0
                }
                FsProtectOperation::Create if id.deny_dir == Some((*target_dev, *target_ino)) => 1,
                _ => return None,
            };
            Some(Taken {
                slot: Sensor::Deny as usize,
                sensor: Some(Sensor::Deny),
                deny_part: Some(part),
            })
        }
        Event::NetFlow(f) => (w.holds(f.pid, f.start_ns.max(f.end_ns)) && f.dst_addr.is_loopback())
            .then_some(Taken {
                slot: SLOT_FLOW,
                sensor: None,
                deny_part: None,
            }),
        _ => None,
    }
}

impl Round {
    fn new(id: RoundId) -> Self {
        Round {
            id,
            ..Round::default()
        }
    }

    /// Take `e` when it is the round's own and its slot has room; counted
    /// as seen when `count` (an open round; a late event of the round
    /// before is taken, not counted).
    fn take(&mut self, e: &Event, count: bool) -> bool {
        let Some(t) = classify(e, &self.id) else {
            return false;
        };
        if self.taken[t.slot] >= take_max(t.slot) {
            return false;
        }
        self.taken[t.slot] += 1;
        if let (true, Some(s)) = (count, t.sensor) {
            match t.deny_part {
                Some(p) => {
                    self.deny[p] = true;
                    self.seen[s as usize] = self.deny.iter().all(|d| *d);
                }
                None => self.seen[s as usize] = true,
            }
        }
        true
    }
}

/// A sensor's round.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Outcome {
    Seen,
    /// Missed, and why (its step's own words).
    Missed(String),
    /// Its step could not run here, and why.
    NotExercised(String),
}

/// What a round's outcomes make the probe sign (pure: [`apply`]).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Note {
    /// The first round missed: the signed degradation.
    Degraded {
        sensor: Sensor,
        detail: String,
    },
    /// The second round in a row: the alert.
    Alert {
        sensor: Sensor,
        detail: String,
    },
    /// Missed again past the alert (the journal only).
    StillSilent {
        sensor: Sensor,
        rounds: u32,
    },
    /// Seen after `rounds` missed: the degradation withdrawn, the return
    /// signed.
    Restored {
        sensor: Sensor,
        rounds: u32,
    },
    /// Its step could not run (the journal, once until it runs again).
    NotExercised {
        sensor: Sensor,
        why: String,
    },
    /// The round's cost over its budget, or back under it.
    OverBudget {
        detail: String,
    },
    BackUnderBudget,
}

/// The probe's memory between rounds.
#[derive(Default)]
struct State {
    round: Option<Round>,
    /// The round before, whose late events are still taken.
    last: Option<Round>,
    /// Each sensor's word since its first round (`None`: pending).
    word: [Option<ProbeState>; SENSORS],
    /// Rounds in a row each sensor was missed.
    misses: [u32; SENSORS],
    /// The detail of each sensor's open degradation (withdrawn at its
    /// return).
    degraded: [Option<String>; SENSORS],
    /// The sensors whose step could not run, last round.
    not_exercised: [bool; SENSORS],
    /// The open over-budget degradation's detail.
    over_budget: Option<String>,
    /// Rounds completed, and when the last one ended.
    rounds: u64,
    last_round: Option<Instant>,
    /// Late events of an ended round taken since the start.
    late_taken: u64,
    /// The module check: the module names of the last round, and the loads
    /// counted until then.
    modules: Option<HashSet<String>>,
    loads_at_round: u64,
    /// The cost of the rounds since the last summary.
    cost: CostWindow,
}

/// The cost of a window of rounds (the journal's summary).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CostWindow {
    pub rounds: u64,
    pub all_seen: u64,
    pub child_cpu_us_max: u64,
    pub checks_us_max: u64,
    pub latency_ms_max: u64,
}

static GAPS_TOTAL: AtomicU64 = AtomicU64::new(0);

/// The running probe (R11c, lab PR 264): what [`spawn`] gives the start,
/// whose decision thread offers it every event ([`Self::observe`]). It was a
/// process-wide `TRACKER` the spawn set and a free `observe` read.
#[derive(Clone)]
pub struct TelemetryProbe {
    tracker: Arc<Mutex<State>>,
    /// The rounds' period and the probe's start (the review of #479, X2:
    /// its word goes stale when no round ends).
    every: Duration,
    started: Instant,
    /// Lot 280c: the child's lifetimes, for the drains.
    tag: SelfTestTag,
    /// Lot 280c: the module loads the tap counted (every `ModuleLoad`).
    loads: Arc<AtomicU64>,
    /// Lot 280c: the FIM's watch, once the FIM drain runs (the probe
    /// directory is watched through it).
    fim: Arc<Mutex<Option<crate::fim::attach::FimWatch>>>,
    /// Lot 280c: the sources whose pump or drain runs (`None`: not known
    /// yet — every one is expected): a sensor whose source does not run is
    /// not exercised, its absence the manifest's own word.
    running: Arc<Mutex<Option<Vec<String>>>>,
}

/// How long the probe's word holds without a round ending (the review of
/// #479, X2): two of its longest intervals (the ±20 % jitter's top) and
/// the round's deadline — 149 s at the default 60 s. A round that never
/// starts (its file not written, the random source failing, the child not
/// spawned) leaves nothing ended: past this the word is `Stale`.
pub fn stale_after(every: Duration) -> Duration {
    every * 12 / 5 + Duration::from_secs(DEADLINE_SECS)
}

impl TelemetryProbe {
    fn new(every: Duration) -> Self {
        TelemetryProbe {
            tracker: Arc::new(Mutex::new(State::default())),
            every,
            started: Instant::now(),
            tag: SelfTestTag::default(),
            loads: Arc::new(AtomicU64::new(0)),
            fim: Arc::new(Mutex::new(None)),
            running: Arc::new(Mutex::new(None)),
        }
    }

    /// Lot 280c: the sources whose pump or drain the start registered (the
    /// start's arming, once every drain runs).
    pub fn set_running(&self, sources: &[&str]) {
        *self.running.lock() = Some(sources.iter().map(|s| s.to_string()).collect());
    }

    /// Whether `sensor`'s source runs (or is not known not to).
    fn source_runs(&self, sensor: Sensor) -> bool {
        let running = self.running.lock();
        let Some(list) = running.as_ref() else {
            return true;
        };
        let has = |s: &str| list.iter().any(|x| x == s);
        match sensor {
            // the open sensor, or the tracepoint that carries its events
            Sensor::FileOpen => has("open_sensor") || has("file_open"),
            s => has(s.source()),
        }
    }

    /// R13 (lab PR 271), lot 280c: the self-test's word on each sensor, for
    /// the capability manifest — `Pending` until its first round, then
    /// `Seen`, `Missed` (one round), `Gap` (two or more in a row) or
    /// `NotExercised`; `Stale` for all when no round has ended for
    /// [`stale_after`] (the review of #479, X2).
    pub fn states(&self) -> Vec<(String, ProbeState)> {
        self.states_at(Instant::now())
    }

    fn states_at(&self, now: Instant) -> Vec<(String, ProbeState)> {
        let st = self.tracker.lock();
        let quiet_since = st
            .last_round
            .unwrap_or(self.started + Duration::from_secs(FIRST_ROUND_SECS));
        let stale = now.saturating_duration_since(quiet_since) > stale_after(self.every);
        Sensor::ALL
            .iter()
            .map(|s| {
                let state = if stale {
                    ProbeState::Stale
                } else {
                    st.word[*s as usize].unwrap_or(ProbeState::Pending)
                };
                (s.name().to_string(), state)
            })
            .collect()
    }

    /// Rounds ended since the start.
    pub fn rounds(&self) -> u64 {
        self.tracker.lock().rounds
    }

    /// Lot 280c: the child's lifetimes, for the drains' signed logs.
    pub fn tag(&self) -> SelfTestTag {
        self.tag.clone()
    }

    /// Lot 280c: the FIM drain runs — the probe directory is watched
    /// through `watch` (the FIM step's file is created there). `false`
    /// when the kernel map refused it: the FIM step is not exercised.
    pub fn watch_fim(&self, watch: crate::fim::attach::FimWatch) -> bool {
        let ok = match crate::fim::attach::key_for_path(Path::new(PROBE_DIR)) {
            Ok(key) => watch.watch(key, PROBE_DIR, crate::fim::drain::WatchClass::Configured),
            Err(e) => {
                warn!(error = format!("{e:#}"), dir = PROBE_DIR, "sensor self-test: the probe directory cannot be watched — the FIM step is not exercised");
                false
            }
        };
        if ok {
            *self.fim.lock() = Some(watch);
        }
        ok
    }

    /// Event tap: called for every event before the decision engine.
    /// `true`: the event is the self-test's own, taken — the caller does
    /// not judge it (lot 280c: never the rules, the posture or the
    /// detection store).
    pub fn observe(&self, event: &Event) -> bool {
        if let Event::ModuleLoad { .. } = event {
            self.loads.fetch_add(1, Ordering::Relaxed);
            return false;
        }
        let mut st = self.tracker.lock();
        if let Some(round) = st.round.as_mut() {
            if round.take(event, true) {
                return true;
            }
        }
        if let Some(last) = st.last.as_mut() {
            if last.take(event, false) {
                st.late_taken += 1;
                return true;
            }
        }
        false
    }

    /// The round ends: each sensor's outcome from what it saw, the child's
    /// report, the window and the attach checks; the state's words, and
    /// what to sign (the round kept for its late events). Returns the
    /// notes, whether no sensor was missed, and the degradations still
    /// open.
    fn close_round(
        &self,
        report: &ChildReport,
        window: bool,
        checks: &[(Sensor, Outcome)],
        cpu: Duration,
    ) -> (Vec<Note>, bool, Vec<String>) {
        let mut st = self.tracker.lock();
        let round = st.round.take();
        #[allow(unused_mut)]
        let mut seen = round.as_ref().map(|r| r.seen).unwrap_or_default();
        #[cfg(feature = "debug-trigger")]
        debug_blind(&mut seen);
        let outs = outcomes(&seen, report, window, checks, &|s| self.source_runs(s));
        let notes = apply(&mut st, &outs, cpu);
        st.last = round;
        let all_seen = !outs.iter().any(|o| matches!(o, Outcome::Missed(_)));
        (notes, all_seen, open_details(&st))
    }

    /// Tests only: the open round ends as [`run_round`] ends it — the
    /// child's `report`, no window, the attach checks `checks`, `cpu` —
    /// and what it found is signed into `audit_log`.
    #[cfg(any(test, feature = "test-util"))]
    pub fn end_round_for_tests(
        &self,
        report: &ChildReport,
        checks: &[(Sensor, Outcome)],
        cpu: Duration,
        audit_log: Option<&Arc<Mutex<AuditLog>>>,
    ) -> Vec<Note> {
        let nonce = self
            .tracker
            .lock()
            .round
            .as_ref()
            .map(|r| r.id.nonce.clone())
            .unwrap_or_default();
        let (notes, _, open) = self.close_round(report, false, checks, cpu);
        sign(&notes, &nonce, &open, audit_log);
        notes
    }

    /// Tests only: a round open for `nonce`, its child `child` (the agent:
    /// `agent_pid`, its path `exe`, the deny directory `deny_dir`).
    #[cfg(any(test, feature = "test-util"))]
    pub fn for_tests(every: Duration) -> Self {
        Self::new(every)
    }

    #[cfg(any(test, feature = "test-util"))]
    pub fn open_round_for_tests(
        &self,
        nonce: &str,
        agent_pid: u32,
        exe: &str,
        child: Window,
        deny_dir: Option<(u64, u64)>,
    ) {
        self.tracker.lock().round = Some(Round::new(RoundId {
            nonce: nonce.to_string(),
            agent_pid,
            exe: exe.to_string(),
            child,
            deny_dir,
        }));
        self.tag.open(child);
    }

    /// Tests only: the sensors the open round has seen.
    #[cfg(any(test, feature = "test-util"))]
    pub fn seen_for_tests(&self) -> Vec<Sensor> {
        let st = self.tracker.lock();
        Sensor::ALL
            .into_iter()
            .filter(|s| st.round.as_ref().is_some_and(|r| r.seen[*s as usize]))
            .collect()
    }
}

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

/// Rounds missed since boot (all sensors, all rounds): the beats'
/// `probe_gaps`.
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

/// What the rounds read of the host (lot 280c).
#[derive(Clone, Default)]
pub struct SelfTestEnv {
    /// Whether a trusted-installer window is open (the deny steps are not
    /// exercised then: nothing is refused in a window).
    pub window_open: Option<Arc<dyn Fn() -> bool + Send + Sync>>,
    /// The agent's program-id list (`bpf-own-ids`), for the attach checks.
    pub own_ids_file: Option<PathBuf>,
    /// The bpffs pin root (the pinned links).
    pub pin_root: Option<PathBuf>,
}

/// Start the periodic probe (the start's late binding, once the audit log
/// exists); the running probe, for the event loop (`None`: disabled).
pub fn spawn(audit_log: Option<Arc<Mutex<AuditLog>>>, env: SelfTestEnv) -> Option<TelemetryProbe> {
    let Some(every) = interval_from_env() else {
        info!(env = INTERVAL_ENV, "telemetry probe disabled");
        return None;
    };
    if let Err(e) = std::fs::create_dir_all(PROBE_DIR) {
        warn!(error = %e, dir = PROBE_DIR, "telemetry probe: cannot create the probe directory — probe disabled");
        return None;
    }
    let probe = TelemetryProbe::new(every);
    info!(
        every_secs = every.as_secs(),
        deadline_secs = DEADLINE_SECS,
        sensors = ?Sensor::ALL.iter().map(|s| s.name()).collect::<Vec<_>>(),
        "sensor self-test armed — every source proves it is alive each round; a missed one is a signed \
         sensor_selftest degradation, two in a row an alert"
    );
    let running = probe.clone();
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_secs(FIRST_ROUND_SECS)).await;
        loop {
            run_round(&running, &env, audit_log.as_ref()).await;
            // ±20 %: a round cannot be predicted and dodged.
            tokio::time::sleep(crate::self_integrity::jittered(every)).await;
        }
    });
    Some(probe)
}

/// The `(dev, ino)` of `path` in the kernel's form (an event's target).
fn kernel_key(path: &Path) -> Option<(u64, u64)> {
    crate::fim::attach::key_for_path(path)
        .ok()
        .map(|k| (k.dev, k.ino))
}

/// The child's report of its steps: one `step=result` line each.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ChildReport(Vec<(String, String)>);

impl ChildReport {
    pub fn parse(text: &str) -> Self {
        ChildReport(
            text.lines()
                .filter_map(|l| l.split_once('='))
                .map(|(k, v)| (k.trim().to_string(), v.trim().to_string()))
                .collect(),
        )
    }

    fn get(&self, step: &str) -> Option<&str> {
        self.0
            .iter()
            .find(|(k, _)| k == step)
            .map(|(_, v)| v.as_str())
    }
}

/// The child's report on `sensor`'s step: `None` when it ran, `Some(why)`
/// when it could not (not exercised), or `Err(why)` when it ran and failed
/// in a way that is a miss by itself (a deny step not refused).
fn step_result(sensor: Sensor, report: &ChildReport) -> Result<Option<String>, String> {
    let keys: &[&str] = match sensor {
        Sensor::FileOpen => &["file"],
        Sensor::Dns => &["dns"],
        Sensor::TcpConnect | Sensor::NetListen | Sensor::NetInbound | Sensor::TlsHello => &["tcp"],
        Sensor::IoUring => &["io_uring"],
        Sensor::Bpf => &["bpf"],
        Sensor::Fim => &["fim"],
        Sensor::Deny => &["deny_signal", "deny_create"],
        _ => &[],
    };
    for k in keys {
        match report.get(k) {
            None => return Ok(Some(format!("the child did not report its {k} step"))),
            Some("ok") | Some("refused") => {}
            Some("done") => {
                return Err(format!(
                    "its {k} step was not refused: the deny hook is attached and did not run"
                ))
            }
            Some(other) => return Ok(Some(format!("{k}: {other}"))),
        }
    }
    Ok(None)
}

/// Each sensor's outcome from what the round saw (`seen`), the child's
/// report, the window and the attach checks (`checks`, the outcomes of the
/// sensors that are not live).
pub fn outcomes(
    seen: &[bool; SENSORS],
    report: &ChildReport,
    window_open: bool,
    checks: &[(Sensor, Outcome)],
    runs: &dyn Fn(Sensor) -> bool,
) -> [Outcome; SENSORS] {
    let mut out: [Outcome; SENSORS] = std::array::from_fn(|_| Outcome::Seen);
    for s in Sensor::ALL {
        let i = s as usize;
        out[i] = if !runs(s) {
            Outcome::NotExercised(format!(
                "its source ({}) does not run on this host: the manifest says why",
                s.source()
            ))
        } else if !s.live() {
            checks
                .iter()
                .find(|(c, _)| *c == s)
                .map(|(_, o)| o.clone())
                .unwrap_or_else(|| Outcome::NotExercised("its check did not run".to_string()))
        } else if s == Sensor::Deny && window_open {
            Outcome::NotExercised(
                "a trusted-installer window is open: the deny hooks refuse nothing in it"
                    .to_string(),
            )
        } else {
            match step_result(s, report) {
                Err(why) => Outcome::Missed(why),
                Ok(Some(why)) => Outcome::NotExercised(why),
                Ok(None) if seen[i] => Outcome::Seen,
                Ok(None) => Outcome::Missed(format!(
                    "its event did not reach the pipeline within {DEADLINE_SECS} s"
                )),
            }
        };
    }
    out
}

/// The signed degradation's detail of a missed `sensor` (stable for its
/// episode: the first miss's words are kept until its return).
pub fn degradation_detail(sensor: Sensor, why: &str) -> String {
    format!(
        "{} ({}): self-test step `{}` missed — {why}",
        sensor.name(),
        sensor.source(),
        sensor.step()
    )
}

/// One round's outcomes into the state, and what to sign (pure).
fn apply(st: &mut State, outcomes: &[Outcome; SENSORS], cpu: Duration) -> Vec<Note> {
    let mut notes = Vec::new();
    for s in Sensor::ALL {
        let i = s as usize;
        match &outcomes[i] {
            Outcome::Seen => {
                if st.misses[i] > 0 {
                    notes.push(Note::Restored {
                        sensor: s,
                        rounds: st.misses[i],
                    });
                }
                st.misses[i] = 0;
                st.degraded[i] = None;
                st.not_exercised[i] = false;
                st.word[i] = Some(ProbeState::Seen);
            }
            Outcome::Missed(why) => {
                st.misses[i] += 1;
                st.not_exercised[i] = false;
                GAPS_TOTAL.fetch_add(1, Ordering::Relaxed);
                match st.misses[i] {
                    1 => {
                        let detail = degradation_detail(s, why);
                        st.degraded[i] = Some(detail.clone());
                        notes.push(Note::Degraded { sensor: s, detail });
                        st.word[i] = Some(ProbeState::Missed);
                    }
                    2 => {
                        notes.push(Note::Alert {
                            sensor: s,
                            detail: degradation_detail(s, why),
                        });
                        st.word[i] = Some(ProbeState::Gap);
                    }
                    n => {
                        notes.push(Note::StillSilent {
                            sensor: s,
                            rounds: n,
                        });
                        st.word[i] = Some(ProbeState::Gap);
                    }
                }
            }
            Outcome::NotExercised(why) => {
                if !st.not_exercised[i] {
                    notes.push(Note::NotExercised {
                        sensor: s,
                        why: why.clone(),
                    });
                }
                st.not_exercised[i] = true;
                // a miss open before stays open: its degradation holds
                if st.misses[i] == 0 {
                    st.word[i] = Some(ProbeState::NotExercised);
                }
            }
        }
    }
    if cpu > ROUND_CPU_BUDGET {
        if st.over_budget.is_none() {
            let detail = format!(
                "the round's cost: {} us of CPU (the child and the agent's checks), over its budget \
                 of {} us",
                cpu.as_micros(),
                ROUND_CPU_BUDGET.as_micros()
            );
            st.over_budget = Some(detail.clone());
            notes.push(Note::OverBudget { detail });
        }
    } else if st.over_budget.take().is_some() {
        notes.push(Note::BackUnderBudget);
    }
    st.rounds += 1;
    st.last_round = Some(Instant::now());
    notes
}

/// The details of the degradations still open (a withdrawal keeps them).
fn open_details(st: &State) -> Vec<String> {
    st.degraded
        .iter()
        .flatten()
        .cloned()
        .chain(st.over_budget.clone())
        .collect()
}

async fn run_round(
    probe: &TelemetryProbe,
    env: &SelfTestEnv,
    audit_log: Option<&Arc<Mutex<AuditLog>>>,
) {
    #[cfg(feature = "debug-trigger")]
    if debug_skip() {
        return;
    }
    let Some(nonce) = make_nonce() else {
        warn!("telemetry probe: the OS random source failed — round skipped");
        return;
    };
    let file = probe_file(&nonce);
    if let Err(e) = std::fs::write(&file, b"nn-telemetry-probe\n") {
        warn!(error = %e, path = %file.display(), "telemetry probe: cannot write the probe file — round skipped");
        return;
    }
    let exe = match std::env::current_exe() {
        Ok(p) => p,
        Err(e) => {
            warn!(error = %e, "telemetry probe: current_exe unknown — round skipped");
            let _ = std::fs::remove_file(&file);
            return;
        }
    };
    let window_open = || env.window_open.as_ref().is_some_and(|f| f());
    let window_before = window_open();
    let from_ns = monotonic_ns();
    let started = Instant::now();
    {
        let mut st = probe.tracker.lock();
        st.round = Some(Round::new(RoundId {
            nonce: nonce.clone(),
            agent_pid: std::process::id(),
            exe: exe.to_string_lossy().into_owned(),
            child: Window {
                pid: 0,
                from_ns,
                until_ns: u64::MAX,
            },
            deny_dir: kernel_key(Path::new(DENY_DIR)),
        }));
    }
    let spawned = Command::new(&exe)
        .arg(PROBE_FLAG)
        .arg(&nonce)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn();
    let mut child = match spawned {
        Ok(c) => c,
        Err(e) => {
            warn!(error = %e, exe = %exe.display(), "telemetry probe: cannot spawn the probe child — round skipped");
            probe.tracker.lock().round = None;
            let _ = std::fs::remove_file(&file);
            return;
        }
    };
    let pid = child.id();
    {
        let w = Window {
            pid,
            from_ns,
            until_ns: u64::MAX,
        };
        if let Some(r) = probe.tracker.lock().round.as_mut() {
            r.id.child = w;
        }
        probe.tag.open(w);
    }
    // The pid is recorded: the child may begin (the deny steps skipped in a
    // window). A child whose stdin cannot be written ends at once.
    if let Some(mut stdin) = child.stdin.take() {
        let go = if window_before { GO_NO_DENY } else { GO_ALL };
        let _ = stdin.write_all(&[go]);
    }
    let mut stdout = child.stdout.take();
    // Reap the child off the async thread, with its CPU time; it exits in
    // milliseconds (killed past CHILD_TIMEOUT).
    let reaped = tokio::task::spawn_blocking(move || reap(pid, CHILD_TIMEOUT))
        .await
        .ok()
        .flatten();
    let until_ns = monotonic_ns();
    if let Some(r) = probe.tracker.lock().round.as_mut() {
        r.id.child.until_ns = until_ns;
    }
    probe.tag.close(until_ns);
    let mut text = String::new();
    if let Some(out) = stdout.as_mut() {
        let _ = out.take(4096).read_to_string(&mut text);
    }
    drop(child);
    let report = ChildReport::parse(&text);
    let window = window_before || window_open();
    // Wait for the pipeline, up to the deadline: every live step that ran.
    let expected: Vec<Sensor> = Sensor::ALL
        .into_iter()
        .filter(|s| {
            s.live()
                && matches!(step_result(*s, &report), Ok(None))
                && !(*s == Sensor::Deny && window)
        })
        .collect();
    loop {
        let all = probe
            .tracker
            .lock()
            .round
            .as_ref()
            .is_none_or(|r| expected.iter().all(|s| r.seen[*s as usize]));
        if all || started.elapsed() >= Duration::from_secs(DEADLINE_SECS) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let latency = started.elapsed();
    // The attach checks and the module count (the agent's own cost).
    let checks_started = Instant::now();
    let checks = attach_checks(probe, env);
    let checks_cost = checks_started.elapsed();
    let child_cpu = reaped.map(|(_, cpu)| cpu).unwrap_or_default();
    let (notes, words_all_seen, open) =
        probe.close_round(&report, window, &checks, child_cpu + checks_cost);
    {
        let mut st = probe.tracker.lock();
        st.cost.rounds += 1;
        st.cost.all_seen += u64::from(words_all_seen);
        st.cost.child_cpu_us_max = st.cost.child_cpu_us_max.max(child_cpu.as_micros() as u64);
        st.cost.checks_us_max = st.cost.checks_us_max.max(checks_cost.as_micros() as u64);
        st.cost.latency_ms_max = st.cost.latency_ms_max.max(latency.as_millis() as u64);
        if st.cost.rounds >= SUMMARY_EVERY {
            let c = std::mem::take(&mut st.cost);
            info!(
                rounds = c.rounds,
                all_seen = c.all_seen,
                child_cpu_us_max = c.child_cpu_us_max,
                checks_us_max = c.checks_us_max,
                latency_ms_max = c.latency_ms_max,
                late_taken = st.late_taken,
                rows_skipped = probe.tag.skipped(),
                budget_us = ROUND_CPU_BUDGET.as_micros() as u64,
                "sensor self-test: the rounds' cost (child CPU, the agent's checks, the slowest \
                 event)"
            );
        }
    }
    debug!(
        nonce,
        all_seen = words_all_seen,
        child_cpu_us = child_cpu.as_micros() as u64,
        checks_us = checks_cost.as_micros() as u64,
        latency_ms = latency.as_millis() as u64,
        "sensor self-test: round ended"
    );
    sign(&notes, &nonce, &open, audit_log);
    // The round's files; the deny step's only when its create was not
    // refused (the agent is exempt: it removes it).
    let _ = std::fs::remove_file(&file);
    let _ = std::fs::remove_file(fim_file(&nonce));
    if report.get("deny_create") == Some("done") {
        let _ = std::fs::remove_file(deny_file(&nonce));
    }
}

/// Wait for `pid` (the probe child) at most `timeout`, killing it past
/// that; its status and its CPU time (user and system). `None` when it
/// could not be waited for.
fn reap(pid: u32, timeout: Duration) -> Option<(i32, Duration)> {
    let pid = pid as libc::pid_t;
    let deadline = Instant::now() + timeout;
    let mut killed = false;
    loop {
        let mut status: libc::c_int = 0;
        // SAFETY: a zeroed rusage for the kernel to fill.
        let mut ru: libc::rusage = unsafe { std::mem::zeroed() };
        let flags = if killed { 0 } else { libc::WNOHANG };
        // SAFETY: our own child's pid, valid out-pointers.
        let r = unsafe { libc::wait4(pid, &mut status, flags, &mut ru) };
        if r == pid {
            let tv = |t: libc::timeval| {
                Duration::from_secs(t.tv_sec as u64) + Duration::from_micros(t.tv_usec as u64)
            };
            return Some((status, tv(ru.ru_utime) + tv(ru.ru_stime)));
        }
        if r < 0 {
            return None;
        }
        if !killed && Instant::now() >= deadline {
            // SAFETY: our own child, not reaped yet: the pid is its.
            unsafe { libc::kill(pid, libc::SIGKILL) };
            killed = true;
            continue;
        }
        std::thread::sleep(Duration::from_millis(2));
    }
}

/// The attach checks of the sensors that are not live, and the module
/// count (the kernel's module list against the loads the tap counted).
fn attach_checks(probe: &TelemetryProbe, env: &SelfTestEnv) -> Vec<(Sensor, Outcome)> {
    let own = env
        .own_ids_file
        .as_ref()
        .and_then(|p| std::fs::read_to_string(p).ok());
    let live: HashSet<u32> = crate::anti_tamper::bpf_defense::live_links(env.pin_root.as_deref())
        .into_iter()
        .filter(|(_, prog)| *prog != 0)
        .map(|(_, prog)| prog)
        .collect();
    let mut out: Vec<(Sensor, Outcome)> = Sensor::ALL
        .into_iter()
        .filter(|s| !s.live())
        .map(|s| {
            let o = match &own {
                Some(text) => attach_check(s, text, &live),
                None => Outcome::NotExercised(
                    "the agent's program-id list (bpf-own-ids) is not readable".to_string(),
                ),
            };
            (s, o)
        })
        .collect();
    // module_load: and every module new in the kernel's list reported
    let loads = probe.loads.load(Ordering::Relaxed);
    let now = std::fs::read_to_string("/proc/modules")
        .ok()
        .map(|t| module_names(&t));
    let mut st = probe.tracker.lock();
    let verdict = match (&st.modules, &now) {
        (Some(before), Some(now)) => {
            module_count_check(before, now, loads.saturating_sub(st.loads_at_round))
        }
        _ => None,
    };
    if now.is_some() {
        st.modules = now;
        st.loads_at_round = loads;
    }
    drop(st);
    if let Some(why) = verdict {
        if let Some(slot) = out.iter_mut().find(|(s, _)| *s == Sensor::ModuleLoad) {
            if !matches!(slot.1, Outcome::Missed(_)) {
                slot.1 = Outcome::Missed(why);
            }
        }
    }
    out
}

/// The names of the modules in `/proc/modules`' text.
pub fn module_names(text: &str) -> HashSet<String> {
    text.lines()
        .filter_map(|l| l.split_whitespace().next())
        .map(str::to_string)
        .collect()
}

/// The module count's verdict: `Some(why)` when more modules are new in
/// the kernel's list than loads were reported since the last round (a
/// load the sensor did not see); a module that left or a load that did not
/// end in a new module is no miss.
pub fn module_count_check(
    before: &HashSet<String>,
    now: &HashSet<String>,
    loads: u64,
) -> Option<String> {
    let mut new: Vec<&String> = now.difference(before).collect();
    if new.len() as u64 <= loads {
        return None;
    }
    new.sort();
    Some(format!(
        "{} module(s) new in /proc/modules since the last round ({}), {loads} load(s) reported",
        new.len(),
        new.iter()
            .take(8)
            .map(|s| s.as_str())
            .collect::<Vec<_>>()
            .join(", ")
    ))
}

/// The attach check of `sensor` (pure): each of its programs in the
/// agent's program-id list (`<id> <name> [kept]` lines) has a live link
/// (`live`: the programs some link of the agent runs).
pub fn attach_check(sensor: Sensor, own_ids: &str, live: &HashSet<u32>) -> Outcome {
    let mut found = 0;
    for line in own_ids.lines() {
        let mut f = line.split_whitespace();
        let (Some(id), Some(name)) = (f.next(), f.next()) else {
            continue;
        };
        let Ok(id) = id.parse::<u32>() else {
            continue;
        };
        if !sensor.programs().iter().any(|p| name.starts_with(p)) {
            continue;
        }
        found += 1;
        if !live.contains(&id) {
            return Outcome::Missed(format!(
                "its program {name} (id {id}) is loaded and no link of the agent runs it: detached"
            ));
        }
    }
    if found == 0 {
        Outcome::NotExercised("no program of it is loaded (off, or not on this kernel)".to_string())
    } else {
        Outcome::Seen
    }
}

/// Sign what a round found: the degradations, the alerts, the returns.
fn sign(notes: &[Note], nonce: &str, open: &[String], audit_log: Option<&Arc<Mutex<AuditLog>>>) {
    let mut withdraw = false;
    for n in notes {
        match n {
            Note::Degraded { sensor, detail } => {
                error!(
                    sensor = sensor.name(),
                    source = sensor.source(),
                    step = sensor.step(),
                    nonce,
                    "SENSOR SELF-TEST MISSED — the sensor's own event (or check) did not come this \
                     round: hook detached, ring not drained, or layout broken on this kernel"
                );
                crate::boot::degradation::report_signed(
                    audit_log,
                    DEGRADATION_SOURCE,
                    detail,
                    false,
                );
            }
            Note::Alert { sensor, detail } => {
                error!(
                    sensor = sensor.name(),
                    source = sensor.source(),
                    nonce,
                    "SENSOR SELF-TEST ALERT — two rounds in a row missed this sensor: it is blind"
                );
                audit(
                    audit_log,
                    AUDIT_OP_ALERT,
                    "detected",
                    serde_json::json!({
                        "sensor": sensor.name(),
                        "source": sensor.source(),
                        "step": sensor.step(),
                        "rounds_missed": 2,
                        "detail": detail,
                        "nonce": nonce,
                        "deadline_secs": DEADLINE_SECS,
                        "missed_total": gaps_total(),
                    }),
                );
            }
            Note::StillSilent { sensor, rounds } => error!(
                sensor = sensor.name(),
                rounds,
                nonce,
                "sensor self-test: the sensor is still silent"
            ),
            Note::Restored { sensor, rounds } => {
                info!(
                    sensor = sensor.name(),
                    rounds_missed = rounds,
                    "sensor self-test: sensor RESTORED — its event comes again"
                );
                withdraw = true;
                audit(
                    audit_log,
                    AUDIT_OP_RESTORED,
                    "success",
                    serde_json::json!({
                        "sensor": sensor.name(),
                        "source": sensor.source(),
                        "rounds_missed": rounds,
                        "nonce": nonce,
                    }),
                );
            }
            Note::NotExercised { sensor, why } => warn!(
                sensor = sensor.name(),
                source = sensor.source(),
                why,
                "sensor self-test: this sensor's step cannot run here — its rounds say nothing of it"
            ),
            Note::OverBudget { detail } => {
                warn!(detail, "sensor self-test: the round is over its budget");
                crate::boot::degradation::report_signed(
                    audit_log,
                    DEGRADATION_SOURCE,
                    detail,
                    false,
                );
            }
            Note::BackUnderBudget => withdraw = true,
        }
    }
    if withdraw {
        crate::boot::degradation::withdraw(DEGRADATION_SOURCE, open);
    }
}

/// `debug-trigger` builds only (R13, the review of #479, X2: the lab's
/// round that never starts): while `/run/northnarrow/debug-probe-skip`
/// exists, each round returns before it starts, as one whose probe file
/// cannot be written.
#[cfg(feature = "debug-trigger")]
fn debug_skip() -> bool {
    let skip = std::path::Path::new(PROBE_DIR)
        .parent()
        .is_some_and(|d| d.join("debug-probe-skip").exists());
    if skip {
        warn!("debug-trigger: the telemetry probe's round does not start");
    }
    skip
}

/// `debug-trigger` builds only (R13, lab PR 271: the lab's runtime change
/// of the capability manifest): while `/run/northnarrow/debug-probe-blind`
/// names a sensor ([`Sensor::name`]; whitespace between several), each
/// round counts that sensor's event as not seen — a miss, signed as one,
/// until the file goes.
#[cfg(feature = "debug-trigger")]
fn debug_blind(seen: &mut [bool; SENSORS]) {
    let Some(dir) = std::path::Path::new(PROBE_DIR).parent() else {
        return;
    };
    let Ok(names) = std::fs::read_to_string(dir.join("debug-probe-blind")) else {
        return;
    };
    for s in Sensor::ALL {
        if names.split_whitespace().any(|n| n == s.name()) {
            seen[s as usize] = false;
            warn!(
                sensor = s.name(),
                "debug-trigger: the telemetry probe counts this sensor as silent"
            );
        }
    }
}

fn audit(log: Option<&Arc<Mutex<AuditLog>>>, op: &str, result: &str, extra: serde_json::Value) {
    let Some(log) = log else {
        return;
    };
    let draft = AuditEntryDraft {
        op: op.to_string(),
        extra,
        key_fp: "agent-self".to_string(),
        cosigner_fps: Vec::new(),
        result: result.to_string(),
        client_pid: std::process::id(),
        client_uid: 0,
        client_comm: "northnarrow-agent".to_string(),
        client_exe: None,
    };
    if let Err(e) = log.lock().append(draft) {
        warn!(
            error = format!("{e:#}"),
            op, "sensor self-test: audit entry failed"
        );
    }
}

/// The child's side (`northnarrow-agent --telemetry-probe <nonce>`): waits
/// for the parent's go byte (its pid recorded), makes each step's event,
/// prints one `step=result` line per step, and exits. The file read is
/// probed by the attempt, not by its outcome; a step that could not be
/// made says why (its sensor is then not exercised, not missed), and a
/// child that ends before its report leaves its steps not exercised.
pub fn run_child(nonce: &str) -> i32 {
    let mut go = [0u8; 1];
    if !matches!(std::io::stdin().read(&mut go), Ok(1)) {
        return 2;
    }
    let mut out = String::new();
    // the open is the step, whatever it answers
    let _ = std::fs::read(probe_file(nonce));
    out.push_str("file=ok\n");
    let dns = match send_dns_probe(&dns_name(nonce), SocketAddr::V4(PROBE_DNS_DEST)) {
        Ok(_) => "ok".to_string(),
        Err(e) => errno_word(&e),
    };
    out.push_str(&format!("dns={dns}\n"));
    out.push_str(&format!("tcp={}\n", tcp_steps(nonce)));
    out.push_str(&format!("io_uring={}\n", io_uring_step()));
    out.push_str(&format!("bpf={}\n", bpf_step()));
    out.push_str(&format!("fim={}\n", fim_step(nonce)));
    if go[0] == GO_ALL {
        out.push_str(&format!("deny_signal={}\n", deny_signal_step()));
        out.push_str(&format!("deny_create={}\n", deny_create_step(nonce)));
    } else {
        out.push_str("deny_signal=skipped: a trusted-installer window is open\n");
        out.push_str("deny_create=skipped: a trusted-installer window is open\n");
    }
    print!("{out}");
    let _ = std::io::stdout().flush();
    0
}

fn errno_word(e: &std::io::Error) -> String {
    format!(
        "skipped: {}",
        e.raw_os_error()
            .map_or_else(|| e.to_string(), |n| format!("errno {n} ({e})"))
    )
}

/// A listener on a loopback port, a connect to it, its accept, a
/// ClientHello as the connection's first send; everything closed.
fn tcp_steps(nonce: &str) -> String {
    let listener = match TcpListener::bind((Ipv4Addr::LOCALHOST, 0)) {
        Ok(l) => l,
        Err(e) => return errno_word(&e),
    };
    let addr = match listener.local_addr() {
        Ok(a) => a,
        Err(e) => return errno_word(&e),
    };
    let mut client = match TcpStream::connect_timeout(&addr, Duration::from_millis(500)) {
        Ok(c) => c,
        Err(e) => return errno_word(&e),
    };
    let server = match listener.accept() {
        Ok((s, _)) => s,
        Err(e) => return errno_word(&e),
    };
    let _ = client.set_write_timeout(Some(Duration::from_millis(500)));
    if let Err(e) = client.write_all(&client_hello(&dns_name(nonce))) {
        return errno_word(&e);
    }
    drop(client);
    drop(server);
    drop(listener);
    "ok".to_string()
}

/// A minimal TLS 1.2-shaped ClientHello for `host` (one cipher suite, the
/// server-name extension): the tls_hello sensor's shape (content type 22,
/// version 3.x, handshake type 1) and what the parse worker fingerprints.
pub fn client_hello(host: &str) -> Vec<u8> {
    let host = &host.as_bytes()[..host.len().min(200)];
    let mut sni = Vec::new();
    // server_name list: one host_name
    let entry_len = 3 + host.len();
    sni.extend_from_slice(&(entry_len as u16).to_be_bytes());
    sni.push(0);
    sni.extend_from_slice(&(host.len() as u16).to_be_bytes());
    sni.extend_from_slice(host);
    let mut ext = Vec::new();
    ext.extend_from_slice(&[0x00, 0x00]);
    ext.extend_from_slice(&(sni.len() as u16).to_be_bytes());
    ext.extend_from_slice(&sni);
    let mut body = Vec::new();
    body.extend_from_slice(&[0x03, 0x03]);
    body.extend_from_slice(&[0x4e; 32]);
    body.push(0); // no session id
    body.extend_from_slice(&[0x00, 0x02, 0x13, 0x01]); // TLS_AES_128_GCM_SHA256
    body.extend_from_slice(&[0x01, 0x00]); // null compression
    body.extend_from_slice(&(ext.len() as u16).to_be_bytes());
    body.extend_from_slice(&ext);
    let mut hs = vec![0x01];
    hs.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]);
    hs.extend_from_slice(&body);
    let mut rec = vec![0x16, 0x03, 0x01];
    rec.extend_from_slice(&(hs.len() as u16).to_be_bytes());
    rec.extend_from_slice(&hs);
    rec
}

/// `struct io_uring_params`: 120 bytes, zeroed (the kernel fills it).
const IO_URING_PARAMS_LEN: usize = 120;

/// An io_uring of one entry, made and closed.
fn io_uring_step() -> String {
    let mut params = [0u8; IO_URING_PARAMS_LEN];
    // SAFETY: io_uring_setup(entries, params): a zeroed params buffer of
    // the struct's size; the fd it returns is closed below.
    let fd = unsafe {
        libc::syscall(
            libc::SYS_io_uring_setup,
            1u32,
            params.as_mut_ptr() as *mut libc::c_void,
        )
    };
    if fd < 0 {
        return errno_word(&std::io::Error::last_os_error());
    }
    // SAFETY: the fd the kernel just returned, ours alone.
    unsafe { libc::close(fd as libc::c_int) };
    "ok".to_string()
}

/// `union bpf_attr` for `BPF_MAP_CREATE`, up to `map_name` and the fields
/// after it the kernel reads as zero.
const BPF_MAP_ATTR_WORDS: usize = 18;
const BPF_MAP_TYPE_ARRAY: u32 = 2;

/// A one-entry BPF array map, made and closed.
fn bpf_step() -> String {
    let mut attr = [0u32; BPF_MAP_ATTR_WORDS];
    attr[0] = BPF_MAP_TYPE_ARRAY;
    attr[1] = 4; // key_size
    attr[2] = 4; // value_size
    attr[3] = 1; // max_entries
                 // SAFETY: bpf(BPF_MAP_CREATE, attr, size): a fully initialised attr of
                 // the size passed; the fd it returns is closed below.
    let fd = unsafe {
        libc::syscall(
            libc::SYS_bpf,
            common::bpf_cmd::BPF_MAP_CREATE as libc::c_long,
            attr.as_ptr() as *const libc::c_void,
            std::mem::size_of_val(&attr) as u32,
        )
    };
    if fd < 0 {
        return errno_word(&std::io::Error::last_os_error());
    }
    // SAFETY: the fd the kernel just returned, ours alone.
    unsafe { libc::close(fd as libc::c_int) };
    "ok".to_string()
}

/// A file created in the probe directory (watched by the FIM).
fn fim_step(nonce: &str) -> String {
    match std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(fim_file(nonce))
    {
        Ok(mut f) => {
            let _ = f.write_all(b"nn-selftest\n");
            "ok".to_string()
        }
        Err(e) => errno_word(&e),
    }
}

/// [`DENY_SIGNAL`] to the agent (the parent): `refused` (EPERM: the
/// `task_kill` deny ran), `done` (delivered: it did not).
fn deny_signal_step() -> String {
    // SAFETY: plain libc calls.
    let parent = unsafe { libc::getppid() };
    if parent <= 1 {
        return "skipped: no parent".to_string();
    }
    // SAFETY: a signal to our parent, the agent.
    let r = unsafe { libc::kill(parent, DENY_SIGNAL) };
    if r == 0 {
        return "done".to_string();
    }
    let e = std::io::Error::last_os_error();
    if e.raw_os_error() == Some(libc::EPERM) {
        "refused".to_string()
    } else {
        errno_word(&e)
    }
}

/// A file created in [`DENY_DIR`]: `refused` (EPERM: the `inode_create`
/// deny ran), `done` (created: it did not — the agent removes it).
fn deny_create_step(nonce: &str) -> String {
    match std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(deny_file(nonce))
    {
        Ok(_) => "done".to_string(),
        Err(e) if e.raw_os_error() == Some(libc::EPERM) => "refused".to_string(),
        Err(e) => errno_word(&e),
    }
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

/// Tests only: what one round's child makes, as the pipeline decodes it —
/// `agent` its parent, `exe` its path, `child` its pid, `ts` a time within
/// its lifetime, `deny_dir` the deny directory's `(dev, ino)`. The live
/// steps' events (one each, the deny's two) and the rows the steps also
/// make (the second file open, the inbound close, the flows).
#[cfg(any(test, feature = "test-util"))]
pub fn round_events_for_tests(
    nonce: &str,
    agent: u32,
    exe: &str,
    child: u32,
    ts: u64,
    deny_dir: (u64, u64),
) -> Vec<(Option<Sensor>, Event)> {
    use serde_json::json;
    let lo4 = |last: u8| -> [u8; 16] {
        let mut a = [0u8; 16];
        a[..4].copy_from_slice(&[127, 0, 0, last]);
        a
    };
    let flow =
        |start: u64, end: u64, dst_port: u16, proto: u8| -> nn_model::telemetry::NetFlowEvent {
            serde_json::from_value(json!({
                "start_ns": start, "end_ns": end, "family": 2,
                "src_addr": "127.0.0.1", "src_port": 40000, "dst_addr": "127.0.0.1",
                "dst_port": dst_port, "proto": proto, "pid": child, "uid": 0,
                "comm": "northnarrow-age", "exe": null, "bytes_sent": 0, "bytes_recv": 0,
                "resolved_hostname": null, "tls_fingerprint": null, "flow_id": "00",
            }))
            .expect("a flow")
        };
    let comm = || "northnarrow-age".to_string();
    vec![
        (
            Some(Sensor::Exec),
            Event::ProcessSpawn {
                pid: child,
                ppid: agent,
                uid: 0,
                gid: 0,
                comm: comm(),
                filename: exe.to_string(),
                timestamp_ns: ts,
                argv: vec![exe.to_string(), PROBE_FLAG.to_string(), nonce.to_string()],
                parent_comm: comm(),
                parent_start_ns: 0,
                start_ns: ts,
                parent_is_kthread: false,
                exe: Default::default(),
                argv_truncated: false,
                filename_truncated: false,
                stdio: Default::default(),
            },
        ),
        (
            Some(Sensor::ExecCheck),
            Event::ExecCheck {
                pid: child,
                ppid: agent,
                uid: 0,
                comm: comm(),
                filename: exe.to_string(),
                timestamp_ns: ts,
                exe: Default::default(),
            },
        ),
        (
            Some(Sensor::FileOpen),
            Event::FileOpen {
                pid: child,
                uid: 0,
                gid: 0,
                comm: comm(),
                filename: probe_file(nonce).to_string_lossy().into_owned(),
                flags: 0,
                timestamp_ns: ts,
                path_from_user: false,
                kernel_class: 0,
            },
        ),
        (
            None,
            Event::FileOpen {
                pid: child,
                uid: 0,
                gid: 0,
                comm: comm(),
                filename: fim_file(nonce).to_string_lossy().into_owned(),
                flags: 0o101,
                timestamp_ns: ts,
                path_from_user: false,
                kernel_class: 0,
            },
        ),
        (
            Some(Sensor::Dns),
            Event::DnsQuery {
                pid: child,
                uid: 0,
                comm: comm(),
                exe: None,
                query_name: format!("{}.", dns_name(nonce)),
                query_type: 1,
                dns_server: lo4(1),
                family: 2,
                timestamp_ns: ts,
                qname_partial: false,
            },
        ),
        (
            Some(Sensor::TcpConnect),
            Event::TcpConnect {
                pid: child,
                uid: 0,
                comm: comm(),
                family: 2,
                src_addr: lo4(1),
                src_port: 40000,
                dst_addr: lo4(1),
                dst_port: 40001,
                timestamp_ns: ts,
            },
        ),
        (
            Some(Sensor::NetListen),
            Event::NetListener(
                serde_json::from_value(json!({
                    "timestamp_ns": ts, "family": 2, "bind_addr": "127.0.0.1",
                    "bind_port": 40001, "proto": 6, "pid": child, "uid": 0,
                    "comm": "northnarrow-age", "exe": null,
                }))
                .expect("a listener"),
            ),
        ),
        (
            Some(Sensor::NetInbound),
            Event::NetInbound(flow(ts, 0, 40001, 6)),
        ),
        (None, Event::NetInbound(flow(ts, ts + 1, 40001, 6))),
        (
            Some(Sensor::TlsHello),
            Event::TlsClientHello(
                serde_json::from_value(json!({
                    "timestamp_ns": ts, "pid": child, "uid": 0, "comm": "northnarrow-age",
                    "family": 2, "dst_addr": "127.0.0.1", "dst_port": 40001,
                    "flow_start_ns": ts, "outcome": "complete", "fingerprint": null,
                    "send_len": 80, "truncated": false,
                }))
                .expect("a hello"),
            ),
        ),
        (
            Some(Sensor::IoUring),
            Event::IoUring {
                created: true,
                pid: child,
                uid: 0,
                comm: comm(),
                classes: 0,
                count: 1,
                last_opcode: 0,
                sq_thread: false,
                timestamp_ns: ts,
            },
        ),
        (
            Some(Sensor::Bpf),
            Event::BpfSyscall {
                pid: child,
                uid: 0,
                comm: comm(),
                cmd: common::bpf_cmd::BPF_MAP_CREATE,
                arg: 2,
                timestamp_ns: ts,
            },
        ),
        (
            Some(Sensor::Fim),
            Event::Fim(
                serde_json::from_value(json!({
                    "timestamp_ns": ts, "path": fim_file(nonce).to_string_lossy(),
                    "op": common::wire::FIM_OP_CREATED, "new_sha256": null,
                    "baseline_sha256": null, "modifier_exe": null, "modifier_pid": child,
                    "modifier_uid": 0, "modifier_comm": "northnarrow-age",
                }))
                .expect("a FIM event"),
            ),
        ),
        (
            Some(Sensor::Deny),
            Event::FsProtectDenial {
                pid: child,
                uid: 0,
                comm: comm(),
                target_dev: DENY_SIGNAL as u64,
                target_ino: agent as u64,
                operation: FsProtectOperation::Signal,
                timestamp_ns: ts,
            },
        ),
        (
            Some(Sensor::Deny),
            Event::FsProtectDenial {
                pid: child,
                uid: 0,
                comm: comm(),
                target_dev: deny_dir.0,
                target_ino: deny_dir.1,
                operation: FsProtectOperation::Create,
                timestamp_ns: ts,
            },
        ),
        (None, Event::NetFlow(flow(ts, ts + 2, 40001, 6))),
        (None, Event::NetFlow(flow(ts, ts + 3, 53, 17))),
    ]
}

#[cfg(test)]
mod tests;
