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
//! - **deny** (lot 302, [`deny`]): one harmless attempt per deny hook
//!   against targets of the self-test's own — a process it starts and
//!   protects, a directory and files it protects, the BPF guard's own
//!   objects — never the agent: each must be refused and its refusal reach
//!   the pipeline. `fs_protect`'s word is the round's refusals arriving;
//!   each hook has its own (a signed `deny_selftest` degradation, then an
//!   alert).
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

use nn_model::Event;
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
/// step; the deny self-test's plan follows it ([`deny::Plan`], lot 302),
/// to the end of the child's standard input.
pub const GO_ALL: u8 = b'g';
/// The go byte while a trusted-installer window is open: the deny steps
/// skipped (nothing is refused in a window, by design).
pub const GO_NO_DENY: u8 = b'w';
/// Lot 302: the most bytes of plan the child reads.
const PLAN_MAX: u64 = 4096;

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
            Sensor::Deny => {
                "one attempt per deny hook on the self-test's own targets, its refusals reaching \
                 the pipeline (each hook's word: the deny self-test)"
            }
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
            Sensor::ModuleLoad => &[
                "module_read_file_observe",
                "module_load_data_observe",
                "module_write_observe",
            ],
            Sensor::ExploitGuard => &["epg_"],
            Sensor::DnsAnswer => &["dns_answer_"],
            _ => &[],
        }
    }
}

/// The slot of the network rows the child's connection and datagram leave
/// (`NetFlow`): taken, never a sensor's word.
const SLOT_FLOW: usize = SENSORS;
/// Lot 302: the slot of the child's other rows of the deny steps (the opens
/// of the self-test's files, of the target's `/proc` and of the throwaway
/// cgroup; the bpf() calls by a relative path): taken, never a word.
const SLOT_DENY_EXTRA: usize = SENSORS + 1;
/// Lot 302: the slot of the target process's exec (its spawn and its exec
/// check).
const SLOT_TARGET: usize = SENSORS + 2;
const SLOTS: usize = SENSORS + 3;

/// At most this many events of a slot are taken per round: what the step
/// makes (the exec check: one per binfmt pass; the file opens: the probe
/// file and the FIM file; io_uring: the creation and an activity record;
/// the inbound accept and its close; the rows of the two TCP sockets and
/// the datagram; lot 302: the deny steps' opens and relative bpf() calls,
/// the target's spawn and exec check — the deny refusals are matched one
/// each, [`deny::DenyExpect`]).
const fn take_max(slot: usize) -> u8 {
    match slot {
        s if s == Sensor::FileOpen as usize => 3,
        s if s == Sensor::Dns as usize => 2,
        s if s == Sensor::NetInbound as usize => 2,
        s if s == Sensor::IoUring as usize => 2,
        s if s == Sensor::Fim as usize => 2,
        SLOT_FLOW => 4,
        SLOT_DENY_EXTRA => 8,
        SLOT_TARGET => 2,
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

    /// Lot 302: [`Self::holds`], or `pid` may be its while its pid is not
    /// known yet (an exec's events can reach the tap before the spawn
    /// returns the pid).
    fn holds_or_pending(&self, pid: u32, ts_ns: u64) -> bool {
        (self.pid == 0 || pid == self.pid) && self.from_ns <= ts_ns && ts_ns <= self.until_ns
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
    /// Lot 302: the deny self-test's target process (its pid from its
    /// spawn; [`Window::default`]: none this round).
    target: Window,
    /// Lot 302: the refusals the round expects, and the child's other rows
    /// of the deny steps (`None`: no deny attempt this round).
    deny: Option<deny::DenyExpect>,
}

/// One open round: what has been seen, and taken.
#[derive(Clone, Debug, Default)]
struct Round {
    id: RoundId,
    seen: [bool; SENSORS],
    /// Lot 302: each deny hook's refusal arrived.
    deny_seen: [bool; deny::HOOK_COUNT],
    taken: [u8; SLOTS],
}

/// What a taken event is: its slot and the sensor it speaks for (none for
/// a row the step also makes).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Taken {
    slot: usize,
    sensor: Option<Sensor>,
}

fn taken(sensor: Sensor) -> Option<Taken> {
    Some(Taken {
        slot: sensor as usize,
        sensor: Some(sensor),
    })
}

/// A row the steps make, taken in `slot` (never a sensor's word).
fn row(slot: usize) -> Option<Taken> {
    Some(Taken { slot, sensor: None })
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

/// Whether `e` is one of the round's own events, and which (the deny
/// refusals are matched by [`Round::take`], one each).
fn classify(e: &Event, id: &RoundId) -> Option<Taken> {
    let w = &id.child;
    match e {
        Event::ProcessSpawn {
            argv,
            ppid,
            pid,
            timestamp_ns,
            ..
        } => {
            if argv.len() >= 3
                && argv[1] == PROBE_FLAG
                && argv[2] == id.nonce
                && *ppid == id.agent_pid
            {
                taken(Sensor::Exec)
            } else if argv.len() >= 2
                && argv[1] == deny::TARGET_FLAG
                && *ppid == id.agent_pid
                && id.target.holds_or_pending(*pid, *timestamp_ns)
            {
                // lot 302: the deny self-test's target
                row(SLOT_TARGET)
            } else {
                None
            }
        }
        Event::ExecCheck {
            pid,
            ppid,
            filename,
            timestamp_ns,
            ..
        } => {
            if *ppid != id.agent_pid || *filename != id.exe {
                return None;
            }
            // lot 302: the target's, started before the child: before its
            // window
            if id.target.holds_or_pending(*pid, *timestamp_ns) && *timestamp_ns < w.from_ns {
                return row(SLOT_TARGET);
            }
            // its event can reach the tap before the spawn returns the
            // child's pid: the agent's child, the agent's path, the round
            ((w.pid == 0 || *pid == w.pid)
                && (id.target.pid == 0 || *pid != id.target.pid)
                && w.from_ns <= *timestamp_ns
                && *timestamp_ns <= w.until_ns)
                .then(|| taken(Sensor::ExecCheck))
                .flatten()
        }
        Event::FileOpen {
            filename,
            pid,
            timestamp_ns,
            ..
        } => {
            if filename.as_str() == probe_file(&id.nonce).to_string_lossy() {
                taken(Sensor::FileOpen)
            } else if filename.as_str() == fim_file(&id.nonce).to_string_lossy() {
                row(Sensor::FileOpen as usize)
            } else if id.deny.as_ref().is_some_and(|d| {
                w.holds(*pid, *timestamp_ns) && d.paths.iter().any(|p| filename.starts_with(p))
            }) {
                // lot 302: the deny steps' opens
                row(SLOT_DENY_EXTRA)
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
        }),
        Event::BpfSyscall {
            pid,
            cmd,
            timestamp_ns,
            ..
        } => {
            if !w.holds(*pid, *timestamp_ns) {
                None
            } else if *cmd == common::bpf_cmd::BPF_MAP_CREATE {
                taken(Sensor::Bpf)
            } else if *cmd == common::bpf_cmd::BPF_OBJ_GET && id.deny.is_some() {
                // lot 302: the bpf_map and bpf_prog steps' relative paths,
                // which the bpf() hook records and lets through
                row(SLOT_DENY_EXTRA)
            } else {
                None
            }
        }
        Event::Fim(f) => (w.holds(f.modifier_pid, f.timestamp_ns)
            && f.path.starts_with(&format!("{PROBE_DIR}/")))
        .then(|| taken(Sensor::Fim))
        .flatten(),
        Event::NetFlow(f) => (w.holds(f.pid, f.start_ns.max(f.end_ns)) && f.dst_addr.is_loopback())
            .then_some(Taken {
                slot: SLOT_FLOW,
                sensor: None,
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
    /// before is taken, not counted). Lot 302: a refusal of the child's is
    /// taken when it is one the deny steps expect, not matched yet — the
    /// hook's word, and `fs_protect`'s (the round's refusals arrive).
    fn take(&mut self, e: &Event, count: bool) -> bool {
        if let Event::FsProtectDenial {
            pid, timestamp_ns, ..
        } = e
        {
            if !self.id.child.holds(*pid, *timestamp_ns) {
                return false;
            }
            let Some(d) = self.id.deny.as_ref() else {
                return false;
            };
            let Some(k) = d.matches(e, &self.deny_seen) else {
                return false;
            };
            let slot = d.records[k].slot;
            self.deny_seen[slot] = true;
            if count {
                self.seen[Sensor::Deny as usize] = true;
            }
            return true;
        }
        let Some(t) = classify(e, &self.id) else {
            return false;
        };
        if self.taken[t.slot] >= take_max(t.slot) {
            return false;
        }
        self.taken[t.slot] += 1;
        if let (true, Some(s)) = (count, t.sensor) {
            self.seen[s as usize] = true;
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
    /// Lot 302: the deny self-test's words and episodes.
    deny: deny::State,
    /// Lot 302: the self-test's protected targets (`None`: not made yet,
    /// or to be made again — a round let an attempt through).
    deny_keys: Option<deny::TargetKeys>,
    /// Lot 302: why the targets could not be made (journal once).
    deny_unready: Option<String>,
}

/// The cost of a window of rounds (the journal's summary).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CostWindow {
    pub rounds: u64,
    pub all_seen: u64,
    pub child_cpu_us_max: u64,
    pub checks_us_max: u64,
    pub latency_ms_max: u64,
    /// Lot 302: rounds whose every attempted deny hook was refused and
    /// reported, and the most hooks a round attempted.
    pub deny_all_refused: u64,
    pub deny_attempted_max: u64,
}

static GAPS_TOTAL: AtomicU64 = AtomicU64::new(0);

/// Lot 302: what the round's deny self-test hands its end.
#[derive(Clone, Debug, Default)]
pub struct DenyRoundEnd {
    /// Each hook's plan ([`deny::plan_hooks`]): attempted, or why not
    /// (another length: none was).
    pub planned: Vec<Result<(), String>>,
    /// Each hook's link state ([`deny::link_state`]; `None`: the agent's
    /// program-id list is not readable).
    pub links: Option<Vec<Option<Result<(), String>>>>,
}

/// What a round's end gives the signer and the summary.
struct RoundEnd {
    notes: Vec<Note>,
    all_seen: bool,
    open: Vec<String>,
    deny_notes: Vec<deny::Note>,
    deny_open: Vec<String>,
    deny_attempted: u64,
    deny_all_refused: bool,
}

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
    /// what to sign (the round kept for its late events). Lot 302: and each
    /// deny hook's, from the plan, the child's words and the refusals that
    /// arrived (`deny`).
    fn close_round(
        &self,
        report: &ChildReport,
        window: bool,
        checks: &[(Sensor, Outcome)],
        cpu: Duration,
        deny: &DenyRoundEnd,
    ) -> RoundEnd {
        let mut st = self.tracker.lock();
        let round = st.round.take();
        #[allow(unused_mut)]
        let mut seen = round.as_ref().map(|r| r.seen).unwrap_or_default();
        let deny_seen = round.as_ref().map(|r| r.deny_seen).unwrap_or_default();
        #[cfg(feature = "debug-trigger")]
        debug_blind(&mut seen);
        let outs = outcomes(&seen, report, window, checks, &|s| self.source_runs(s));
        let notes = apply(&mut st, &outs, cpu);
        let planned: Vec<Result<(), String>> = if deny.planned.len() == deny::HOOK_COUNT {
            deny.planned.clone()
        } else {
            vec![Err("no deny attempt was planned this round".to_string()); deny::HOOK_COUNT]
        };
        let douts = deny::outcomes(&planned, report, &deny_seen, deny.links.as_deref(), window);
        let deny_notes = st.deny.apply(&douts);
        st.last = round;
        let attempted: Vec<usize> = (0..deny::HOOK_COUNT)
            .filter(|i| planned[*i].is_ok())
            .collect();
        RoundEnd {
            all_seen: !outs.iter().any(|o| matches!(o, Outcome::Missed(_))),
            notes,
            open: open_details(&st),
            deny_all_refused: !window
                && attempted
                    .iter()
                    .all(|i| matches!(douts[*i], deny::Outcome::Seen)),
            deny_attempted: if window { 0 } else { attempted.len() as u64 },
            deny_notes,
            deny_open: st.deny.open_details(),
        }
    }

    /// Lot 302: each deny hook's word (`pending` before its first round).
    pub fn deny_states(&self) -> Vec<(String, ProbeState)> {
        let st = self.tracker.lock();
        deny::HOOKS
            .iter()
            .enumerate()
            .map(|(i, h)| {
                (
                    h.hook.to_string(),
                    st.deny.word[i].unwrap_or(ProbeState::Pending),
                )
            })
            .collect()
    }

    /// Tests only: the open round ends as [`run_round`] ends it — the
    /// child's `report`, no window, the attach checks `checks`, `cpu`, the
    /// deny hooks the open round expects attempted (no link state) — and
    /// what it found is signed into `audit_log`. The sensors' notes, then
    /// the deny hooks'.
    #[cfg(any(test, feature = "test-util"))]
    pub fn end_round_for_tests(
        &self,
        report: &ChildReport,
        checks: &[(Sensor, Outcome)],
        cpu: Duration,
        audit_log: Option<&Arc<Mutex<AuditLog>>>,
    ) -> (Vec<Note>, Vec<deny::Note>) {
        let (nonce, planned) = {
            let st = self.tracker.lock();
            let r = st.round.as_ref();
            let slots: Vec<usize> = r
                .and_then(|r| r.id.deny.as_ref())
                .map(|d| d.records.iter().map(|e| e.slot).collect())
                .unwrap_or_default();
            let planned = (0..deny::HOOK_COUNT)
                .map(|i| {
                    if slots.contains(&i) {
                        Ok(())
                    } else {
                        Err("not attempted in this test".to_string())
                    }
                })
                .collect();
            (r.map(|r| r.id.nonce.clone()).unwrap_or_default(), planned)
        };
        let end = self.close_round(
            report,
            false,
            checks,
            cpu,
            &DenyRoundEnd {
                planned,
                links: None,
            },
        );
        sign(&end.notes, &nonce, &end.open, audit_log);
        deny::sign(&end.deny_notes, &nonce, &end.deny_open, audit_log);
        (end.notes, end.deny_notes)
    }

    /// Tests only: a probe that never runs a round.
    #[cfg(any(test, feature = "test-util"))]
    pub fn for_tests(every: Duration) -> Self {
        Self::new(every)
    }

    /// Tests only: a round open for `nonce`, its child `child` (the agent:
    /// `agent_pid`, its path `exe`), the deny refusals it expects `deny`
    /// (lot 302: their target process's window open for the round).
    #[cfg(any(test, feature = "test-util"))]
    pub fn open_round_for_tests(
        &self,
        nonce: &str,
        agent_pid: u32,
        exe: &str,
        child: Window,
        deny: Option<deny::DenyExpect>,
    ) {
        let target = deny.as_ref().map_or_else(Window::default, |d| Window {
            pid: d.target,
            from_ns: 0,
            until_ns: u64::MAX,
        });
        self.tracker.lock().round = Some(Round::new(RoundId {
            nonce: nonce.to_string(),
            agent_pid,
            exe: exe.to_string(),
            child,
            target,
            deny,
        }));
        self.tag.open(child);
    }

    /// Tests only: the deny hooks whose refusal the open round has seen.
    #[cfg(any(test, feature = "test-util"))]
    pub fn deny_seen_for_tests(&self) -> Vec<&'static str> {
        let st = self.tracker.lock();
        deny::HOOKS
            .iter()
            .enumerate()
            .filter(|(i, _)| st.round.as_ref().is_some_and(|r| r.deny_seen[*i]))
            .map(|(_, h)| h.hook)
            .collect()
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
    /// The bpffs pin root (the pinned links; lot 302: the protected pids
    /// and inodes the deny self-test's targets are registered in).
    pub pin_root: Option<PathBuf>,
    /// Lot 302: the kernel's mark of the round's child (its refusals
    /// outside the denials' budgets).
    pub mark: Option<deny::SelfTestMark>,
    /// Lot 302: the BPF guard enforces (its handle refusals are
    /// attempted).
    pub bpf_enforce: bool,
    /// Lot 302: `debug-trigger` builds only — the denials' budgets, spent
    /// before a round while `/run/northnarrow/debug-deny-budget-spent`
    /// exists (`None` otherwise).
    pub budget: Option<deny::BudgetSpender>,
}

/// Lot 302: the program-id list and the agent's live links, read once a
/// round (the deny self-test's plan and the attach checks).
struct AttachView {
    own: Option<String>,
    live: HashSet<u32>,
}

impl AttachView {
    fn read(env: &SelfTestEnv) -> Self {
        AttachView {
            own: env
                .own_ids_file
                .as_ref()
                .and_then(|p| std::fs::read_to_string(p).ok()),
            live: crate::anti_tamper::bpf_defense::live_links(env.pin_root.as_deref())
                .into_iter()
                .filter(|(_, prog)| *prog != 0)
                .map(|(_, prog)| prog)
                .collect(),
        }
    }

    /// Each deny hook's link state (`None`: the list is not readable).
    fn deny_links(&self) -> Option<Vec<Option<Result<(), String>>>> {
        let own = self.own.as_deref()?;
        Some(
            deny::HOOKS
                .iter()
                .map(|h| deny::link_state(h.programs, own, &self.live))
                .collect(),
        )
    }
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
/// in a way that is a miss by itself. Lot 302: `fs_protect`'s step is the
/// deny attempts' — it ran when one of them was refused (each hook's word
/// is the deny self-test's: a hook let through is its miss, not the
/// source's).
fn step_result(sensor: Sensor, report: &ChildReport) -> Result<Option<String>, String> {
    if sensor == Sensor::Deny {
        let refused = report
            .0
            .iter()
            .any(|(k, v)| k.starts_with("deny.") && matches!(v.as_str(), "refused" | "sent"));
        return Ok((!refused).then(|| {
            "no deny attempt was refused this round: each hook's word (the deny self-test) says \
             why"
            .to_string()
        }));
    }
    let keys: &[&str] = match sensor {
        Sensor::FileOpen => &["file"],
        Sensor::Dns => &["dns"],
        Sensor::TcpConnect | Sensor::NetListen | Sensor::NetInbound | Sensor::TlsHello => &["tcp"],
        Sensor::IoUring => &["io_uring"],
        Sensor::Bpf => &["bpf"],
        Sensor::Fim => &["fim"],
        _ => &[],
    };
    for k in keys {
        match report.get(k) {
            None => return Ok(Some(format!("the child did not report its {k} step"))),
            Some("ok") => {}
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
    #[cfg(feature = "debug-trigger")]
    debug_detach(env.pin_root.as_deref());
    let started = Instant::now();
    // Lot 302: the program-id list and the links, once: the deny hooks'
    // plan now, the attach checks at the end (the agent's own cost)
    let view_started = Instant::now();
    let view = AttachView::read(env);
    let links = view.deny_links();
    let mut checks_cost = view_started.elapsed();
    {
        let mut st = probe.tracker.lock();
        st.round = Some(Round::new(RoundId {
            nonce: nonce.clone(),
            agent_pid: std::process::id(),
            exe: exe.to_string_lossy().into_owned(),
            // the child's window opens at its spawn (the target's exec, before
            // it, is not the child's)
            child: Window {
                pid: 0,
                from_ns: u64::MAX,
                until_ns: u64::MAX,
            },
            target: Window::default(),
            deny: None,
        }));
    }
    // Lot 302: the deny self-test's targets and plan (none in a window)
    let deny_run = (!window_before).then(|| prepare_deny(probe, env, &exe, links.as_deref()));
    let planned: Vec<Result<(), String>> = deny_run
        .as_ref()
        .map(|d| d.planned.clone())
        .unwrap_or_default();
    // the child's window opens before its exec (its exec check can reach
    // the tap before the spawn returns its pid; the target's, before this)
    let from_ns = monotonic_ns();
    if let Some(r) = probe.tracker.lock().round.as_mut() {
        r.id.child.from_ns = from_ns;
    }
    let mut cmd = Command::new(&exe);
    cmd.arg(PROBE_FLAG)
        .arg(&nonce)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    if let Some(raw) = deny_run.as_ref().and_then(DenyRun::write_fd) {
        hand_over_write_fd(&mut cmd, raw);
    }
    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => {
            warn!(error = %e, exe = %exe.display(), "telemetry probe: cannot spawn the probe child — round skipped");
            probe.tracker.lock().round = None;
            if let Some(d) = deny_run {
                d.finish().await;
            }
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
    // Lot 302: the kernel's mark of the child — its refusals recorded
    // outside the denials' budgets and dedup — before it may begin
    let marked = deny_run.is_some() && env.mark.as_ref().is_some_and(|m| m.set(pid));
    if deny_run.is_some() && !marked {
        warn!(
            pid,
            "deny self-test: the kernel's mark of the child is not set — its refusals go \
             through the denials' budgets this round"
        );
    }
    #[cfg(feature = "debug-trigger")]
    if deny_run.is_some() {
        debug_spend_budgets(env);
    }
    // The pid is recorded: the child may begin (the deny steps skipped in a
    // window). A child whose stdin cannot be written ends at once.
    if let Some(mut stdin) = child.stdin.take() {
        let mut go = vec![if window_before { GO_NO_DENY } else { GO_ALL }];
        if let Some(d) = &deny_run {
            go.extend_from_slice(d.plan.render().as_bytes());
        }
        let _ = stdin.write_all(&go);
    }
    let mut stdout = child.stdout.take();
    // Reap the child off the async thread, with its CPU time; it exits in
    // milliseconds (killed past CHILD_TIMEOUT).
    let reaped = tokio::task::spawn_blocking(move || reap(pid, CHILD_TIMEOUT))
        .await
        .ok()
        .flatten();
    if marked && env.mark.as_ref().is_some_and(|m| !m.set(0)) {
        error!(
            pid,
            "deny self-test: the kernel's mark of the reaped child could not be cleared"
        );
    }
    let until_ns = monotonic_ns();
    if let Some(r) = probe.tracker.lock().round.as_mut() {
        r.id.child.until_ns = until_ns;
    }
    probe.tag.close(until_ns);
    // the target ended (killed, reaped, evicted) and its cgroup removed
    let target_cpu = match deny_run {
        Some(d) => d.finish().await,
        None => Duration::ZERO,
    };
    if let Some(r) = probe.tracker.lock().round.as_mut() {
        r.id.target.until_ns = r.id.target.until_ns.min(monotonic_ns());
    }
    let mut text = String::new();
    if let Some(out) = stdout.as_mut() {
        let _ = out.take(4096).read_to_string(&mut text);
    }
    drop(child);
    let report = ChildReport::parse(&text);
    let window = window_before || window_open();
    // Wait for the pipeline, up to the deadline: every live step that ran,
    // every deny attempt refused (lot 302).
    let expected: Vec<Sensor> = Sensor::ALL
        .into_iter()
        .filter(|s| {
            s.live()
                && matches!(step_result(*s, &report), Ok(None))
                && !(*s == Sensor::Deny && window)
        })
        .collect();
    let deny_expected: Vec<usize> = (0..deny::HOOK_COUNT)
        .filter(|i| {
            planned.get(*i).is_some_and(Result::is_ok)
                && matches!(
                    report.get(&format!("deny.{}", deny::HOOKS[*i].hook)),
                    Some("refused") | Some("sent")
                )
        })
        .collect();
    loop {
        let all = probe.tracker.lock().round.as_ref().is_none_or(|r| {
            expected.iter().all(|s| r.seen[*s as usize])
                && deny_expected.iter().all(|i| r.deny_seen[*i])
        });
        if all || started.elapsed() >= Duration::from_secs(DEADLINE_SECS) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let latency = started.elapsed();
    // The attach checks and the module count (the agent's own cost).
    let checks_started = Instant::now();
    let checks = attach_checks(probe, &view);
    checks_cost += checks_started.elapsed();
    let child_cpu = reaped.map(|(_, cpu)| cpu).unwrap_or_default() + target_cpu;
    let end = probe.close_round(
        &report,
        window,
        &checks,
        child_cpu + checks_cost,
        &DenyRoundEnd {
            planned: planned.clone(),
            links,
        },
    );
    {
        let mut st = probe.tracker.lock();
        st.cost.rounds += 1;
        st.cost.all_seen += u64::from(end.all_seen);
        st.cost.child_cpu_us_max = st.cost.child_cpu_us_max.max(child_cpu.as_micros() as u64);
        st.cost.checks_us_max = st.cost.checks_us_max.max(checks_cost.as_micros() as u64);
        st.cost.latency_ms_max = st.cost.latency_ms_max.max(latency.as_millis() as u64);
        st.cost.deny_all_refused += u64::from(end.deny_all_refused);
        st.cost.deny_attempted_max = st.cost.deny_attempted_max.max(end.deny_attempted);
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
                deny_all_refused = c.deny_all_refused,
                deny_attempted_max = c.deny_attempted_max,
                budget_us = ROUND_CPU_BUDGET.as_micros() as u64,
                "sensor self-test: the rounds' cost (child CPU with the deny target's, the \
                 agent's checks, the slowest event; the rounds whose every deny attempt was \
                 refused and reported)"
            );
        }
    }
    debug!(
        nonce,
        all_seen = end.all_seen,
        deny_attempted = end.deny_attempted,
        deny_all_refused = end.deny_all_refused,
        child_cpu_us = child_cpu.as_micros() as u64,
        checks_us = checks_cost.as_micros() as u64,
        latency_ms = latency.as_millis() as u64,
        "sensor self-test: round ended"
    );
    sign(&end.notes, &nonce, &end.open, audit_log);
    deny::sign(&end.deny_notes, &nonce, &end.deny_open, audit_log);
    // The round's files; lot 302: the deny targets made again at the next
    // round when an attempt on them went through
    let _ = std::fs::remove_file(&file);
    let _ = std::fs::remove_file(fim_file(&nonce));
    let touched = deny::HOOKS.iter().enumerate().any(|(i, h)| {
        planned.get(i).is_some_and(Result::is_ok)
            && matches!(
                h.check,
                deny::Check::Attempt {
                    expect: deny::Expect::Dir | deny::Expect::File(_),
                    ..
                }
            )
            && report.get(&format!("deny.{}", h.hook)) != Some("refused")
    });
    if touched {
        probe.tracker.lock().deny_keys = None;
    }
}

/// Lot 302: a round's deny self-test — its target process, the protected
/// file's descriptor handed to the child, the throwaway cgroup, the plan.
struct DenyRun {
    target: Option<deny::TargetProcess>,
    wfd: Option<std::fs::File>,
    cgroup: Option<PathBuf>,
    planned: Vec<Result<(), String>>,
    plan: deny::Plan,
}

impl DenyRun {
    fn write_fd(&self) -> Option<std::os::fd::RawFd> {
        use std::os::fd::AsRawFd;
        self.wfd.as_ref().map(|f| f.as_raw_fd())
    }

    /// The target ended (its CPU time), the descriptor closed, the cgroup
    /// removed.
    async fn finish(self) -> Duration {
        drop(self.wfd);
        let cpu = match self.target {
            Some(t) => tokio::task::spawn_blocking(move || t.end())
                .await
                .unwrap_or_default(),
            None => Duration::ZERO,
        };
        if let Some(c) = self.cgroup {
            let _ = std::fs::remove_dir(&c);
        }
        cpu
    }
}

/// Lot 302: the protected file's descriptor at [`deny::WRITE_FD`] in the
/// child (`dup2` between the fork and the exec: no other child inherits
/// it).
fn hand_over_write_fd(cmd: &mut Command, raw: std::os::fd::RawFd) {
    use std::os::unix::process::CommandExt;
    // SAFETY: dup2 and fcntl are async-signal-safe; `raw` stays open in the
    // parent until the spawn has returned.
    unsafe {
        cmd.pre_exec(move || {
            if raw == deny::WRITE_FD {
                let fl = libc::fcntl(raw, libc::F_GETFD);
                if fl < 0 || libc::fcntl(raw, libc::F_SETFD, fl & !libc::FD_CLOEXEC) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
            } else if libc::dup2(raw, deny::WRITE_FD) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
}

/// Lot 302: the round's deny self-test made ready — the targets (made and
/// protected again when an attempt went through), the target process
/// started and protected, the protected file opened for the child, the
/// throwaway cgroup where the move guard runs, each hook planned — and the
/// refusals the round's tap expects.
fn prepare_deny(
    probe: &TelemetryProbe,
    env: &SelfTestEnv,
    exe: &Path,
    links: Option<&[Option<Result<(), String>>]>,
) -> DenyRun {
    let dir = Path::new(deny::TARGET_DIR);
    let keys = {
        let mut st = probe.tracker.lock();
        let intact = st
            .deny_keys
            .as_ref()
            .is_some_and(|k| deny::targets_intact(dir, k));
        if !intact {
            // the previous targets' keys out first (made again below)
            if let (Some(old), Some(root)) = (st.deny_keys.take(), env.pin_root.as_deref()) {
                if let Err(why) = deny::release_targets(root, &old) {
                    warn!(
                        why,
                        "deny self-test: the previous targets' keys not released"
                    );
                }
            }
            match env.pin_root.as_deref() {
                None => {
                    st.deny_unready =
                        Some("no bpffs pin root: no protected target can be registered".into())
                }
                Some(root) => match deny::prepare_targets(dir, Some(root)) {
                    Ok(k) => {
                        st.deny_keys = Some(k);
                        st.deny_unready = None;
                    }
                    Err(why) => {
                        if st.deny_unready.as_deref() != Some(why.as_str()) {
                            warn!(why, "deny self-test: its targets could not be made");
                        }
                        st.deny_unready = Some(why);
                    }
                },
            }
        }
        st.deny_keys.clone()
    };
    // the target's window open before its exec (its events can reach the
    // tap before the spawn returns its pid)
    let target_from = monotonic_ns();
    if let Some(r) = probe.tracker.lock().round.as_mut() {
        r.id.target = Window {
            pid: 0,
            from_ns: target_from,
            until_ns: u64::MAX,
        };
    }
    let target =
        env.pin_root
            .as_deref()
            .and_then(|root| match deny::TargetProcess::start(exe, root) {
                Ok(t) => Some(t),
                Err(why) => {
                    warn!(why, "deny self-test: no target process this round");
                    None
                }
            });
    let target_pid = target.as_ref().map_or(0, deny::TargetProcess::pid);
    let mut planned = deny::plan_hooks(links, env.bpf_enforce, target.is_some(), keys.is_some());
    let linked = |hook: &str| {
        deny::slot_of(hook)
            .and_then(|i| links.and_then(|l| l.get(i).cloned().flatten()))
            .is_some_and(|r| r.is_ok())
    };
    let set_err = |planned: &mut Vec<Result<(), String>>, hook: &str, why: &str| {
        if let Some(i) = deny::slot_of(hook) {
            if planned[i].is_ok() {
                planned[i] = Err(why.to_string());
            }
        }
    };
    let move_hook = crate::anti_tamper::cgroup_guard::MOVE_DENY_HOOK;
    let cgroup = if target.is_some() && linked(move_hook) {
        deny::make_move_cgroup()
    } else {
        None
    };
    if cgroup.is_none() {
        set_err(
            &mut planned,
            move_hook,
            "no throwaway cgroup this round (no target, the move guard not linked, or no cgroup \
             v2 root)",
        );
    }
    let wfd = keys.as_ref().and_then(|_| {
        std::fs::OpenOptions::new()
            .append(true)
            .open(dir.join(deny::file::WRITE_FD))
            .ok()
    });
    if wfd.is_none() {
        set_err(
            &mut planned,
            "file_permission",
            "the protected file could not be opened for the child",
        );
    }
    let bpffs = env.pin_root.as_deref().and_then(|r| {
        Some((
            r.parent()?.to_path_buf(),
            r.file_name()?.to_string_lossy().into_owned(),
        ))
    });
    if bpffs.is_none() {
        for h in ["bpf_map", "bpf_prog"] {
            set_err(&mut planned, h, "no bpffs pin root");
        }
    }
    let hooks: Vec<usize> = (0..deny::HOOK_COUNT)
        .filter(|i| planned[*i].is_ok())
        .collect();
    let expect = deny::DenyExpect::new(
        &hooks,
        &keys.clone().unwrap_or_default(),
        target_pid,
        cgroup.as_deref(),
    );
    if let Some(r) = probe.tracker.lock().round.as_mut() {
        r.id.target = if target_pid != 0 {
            Window {
                pid: target_pid,
                from_ns: target_from,
                until_ns: u64::MAX,
            }
        } else {
            Window::default()
        };
        r.id.deny = Some(expect);
    }
    DenyRun {
        plan: deny::Plan {
            target: target_pid,
            dir: dir.to_path_buf(),
            hooks,
            write_fd: wfd.is_some(),
            move_procs: cgroup.as_ref().map(|c| c.join("cgroup.procs")),
            bpffs,
        },
        target,
        wfd,
        cgroup,
        planned,
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
fn attach_checks(probe: &TelemetryProbe, view: &AttachView) -> Vec<(Sensor, Outcome)> {
    let mut out: Vec<(Sensor, Outcome)> = Sensor::ALL
        .into_iter()
        .filter(|s| !s.live())
        .map(|s| {
            let o = match &view.own {
                Some(text) => attach_check(s, text, &view.live),
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

/// `debug-trigger` builds only (lot 302, the lab's deny self-test check):
/// while `/run/northnarrow/debug-deny-detach` names deny hooks
/// ([`deny::HookTest::hook`]; whitespace between several), each round
/// starts by unpinning their `link_<hook>` from the pin root — the hook
/// really detached (the agent holds no other reference to it) until the
/// next start re-attaches it.
#[cfg(feature = "debug-trigger")]
fn debug_detach(pin_root: Option<&Path>) {
    let (Some(root), Some(dir)) = (pin_root, Path::new(PROBE_DIR).parent()) else {
        return;
    };
    let Ok(names) = std::fs::read_to_string(dir.join("debug-deny-detach")) else {
        return;
    };
    for hook in names.split_whitespace() {
        let (_, link) = antitamper_bpf::lsm_pin_paths(root, hook);
        if std::fs::symlink_metadata(&link).is_err() {
            continue;
        }
        match std::fs::remove_file(&link) {
            Ok(()) => warn!(
                hook,
                pin = %link.display(),
                "debug-trigger: a deny hook's link unpinned on purpose — the hook is detached"
            ),
            Err(e) => warn!(hook, error = %e, "debug-trigger: the deny hook's link not unpinned"),
        }
    }
}

/// `debug-trigger` builds only (lot 302, the lab's deny self-test check):
/// while `/run/northnarrow/debug-deny-budget-spent` exists, the denials'
/// per-CPU budgets are spent on every CPU right before the child begins —
/// a flood's effect, without the flood: the child's refusals must still
/// arrive, none counted as held back.
#[cfg(feature = "debug-trigger")]
fn debug_spend_budgets(env: &SelfTestEnv) {
    let Some(dir) = Path::new(PROBE_DIR).parent() else {
        return;
    };
    if !dir.join("debug-deny-budget-spent").exists() {
        return;
    }
    match env.budget.as_ref().map(|b| b.spend(monotonic_ns())) {
        Some(Ok(())) => {
            warn!("debug-trigger: the denials' budgets spent on every CPU before the round")
        }
        Some(Err(e)) => warn!(error = e, "debug-trigger: the denials' budgets not spent"),
        None => warn!("debug-trigger: no handle on the denials' budgets"),
    }
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
    // lot 302: the deny self-test's plan, to the end of the input
    let mut plan_text = String::new();
    if go[0] == GO_ALL {
        let _ = std::io::stdin()
            .take(PLAN_MAX)
            .read_to_string(&mut plan_text);
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
    // lot 302: one attempt per deny hook, on the self-test's own targets
    // (none in a trusted-installer window: nothing is refused in it)
    if go[0] == GO_ALL {
        out.push_str(&deny::run_steps(nonce, &deny::Plan::parse(&plan_text)));
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
/// its lifetime, `deny` the refusals its deny attempts make (lot 302). The
/// live steps' events (one each; one refusal per deny hook, `fs_protect`'s)
/// and the rows the steps also make (the second file open, the inbound
/// close, the flows; the deny steps' opens and relative bpf() call, the
/// target's spawn and exec check).
#[cfg(any(test, feature = "test-util"))]
pub fn round_events_for_tests(
    nonce: &str,
    agent: u32,
    exe: &str,
    child: u32,
    ts: u64,
    deny: Option<&deny::DenyExpect>,
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
    let mut events = vec![
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
        (None, Event::NetFlow(flow(ts, ts + 2, 40001, 6))),
        (None, Event::NetFlow(flow(ts, ts + 3, 53, 17))),
    ];
    if let Some(d) = deny {
        events.extend(deny_events_for_tests(agent, exe, child, ts, d));
    }
    events
}

/// Tests only: lot 302 — one refusal of `child` per record `deny` expects
/// (a field it leaves open: the ptrace mode 9, the object id 1234), the
/// rows the deny steps make (an open in the self-test directory, one of the
/// target's memory, a relative `BPF_OBJ_GET`) and the target's exec.
#[cfg(any(test, feature = "test-util"))]
pub fn deny_events_for_tests(
    agent: u32,
    exe: &str,
    child: u32,
    ts: u64,
    deny: &deny::DenyExpect,
) -> Vec<(Option<Sensor>, Event)> {
    let comm = || "northnarrow-age".to_string();
    let mut v: Vec<(Option<Sensor>, Event)> = deny
        .records
        .iter()
        .map(|e| {
            (
                Some(Sensor::Deny),
                Event::FsProtectDenial {
                    pid: child,
                    uid: 0,
                    comm: comm(),
                    target_dev: e.dev.unwrap_or(9),
                    target_ino: e.ino.unwrap_or(1234),
                    operation: e.op,
                    timestamp_ns: ts,
                    would_deny: false,
                },
            )
        })
        .collect();
    let open = |filename: String| Event::FileOpen {
        pid: child,
        uid: 0,
        gid: 0,
        comm: comm(),
        filename,
        flags: 1,
        timestamp_ns: ts,
        path_from_user: false,
        kernel_class: 0,
    };
    v.push((
        None,
        open(format!("{}/{}", deny::TARGET_DIR, deny::file::WRITE_OPEN)),
    ));
    v.push((None, open(format!("/proc/{}/mem", deny.target))));
    v.push((
        None,
        Event::BpfSyscall {
            pid: child,
            uid: 0,
            comm: comm(),
            cmd: common::bpf_cmd::BPF_OBJ_GET,
            arg: 0,
            timestamp_ns: ts,
        },
    ));
    if deny.target != 0 {
        v.push((
            None,
            Event::ProcessSpawn {
                pid: deny.target,
                ppid: agent,
                uid: 0,
                gid: 0,
                comm: comm(),
                filename: exe.to_string(),
                timestamp_ns: ts,
                argv: vec![exe.to_string(), deny::TARGET_FLAG.to_string()],
                parent_comm: comm(),
                parent_start_ns: 0,
                start_ns: ts,
                parent_is_kthread: false,
                exe: Default::default(),
                argv_truncated: false,
                filename_truncated: false,
                stdio: Default::default(),
            },
        ));
    }
    v
}

pub mod deny;

#[cfg(test)]
mod tests;
