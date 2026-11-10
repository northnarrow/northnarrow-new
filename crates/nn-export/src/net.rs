//! The syslog sink's connection (lot 276): TCP to an IP and a port, TLS
//! 1.3 (`tls`), RFC 5425 frames (`syslog`), driven without blocking and
//! within each request's budget — a receiver that is down, slow, silent or
//! hostile costs the worker at most its budget per request, and never the
//! agent anything (the core waits on the worker's answer, not the
//! receiver).
//!
//! Delivery: syslog over TLS has no acknowledgement of its own. A row is
//! delivered once every byte of its records' ciphertext has been
//! acknowledged by the receiver's TCP (`SIOCOUTQ`: the bytes the socket
//! sent and the peer has not acknowledged) and the connection then stayed
//! up for [`SETTLE`]: a receiver that stops with bytes it has not read
//! resets the connection (its kernel answers a close with unread data by
//! `RST`), and every row that had not settled is written again on the next
//! connection — at least once, never a row cut in a stream. What a
//! receiver's process read and then lost (a crash before it wrote them,
//! after the settle) is the loss this cannot see.
//!
//! Raw system calls only — `socket` (TCP, non-blocking), `connect`,
//! `ppoll`, `getsockopt(SO_ERROR)`, `ioctl(SIOCOUTQ)`, `sendto` with
//! `MSG_NOSIGNAL` and no address, `recvfrom` with no flag and no address,
//! `close` — the worker's seccomp allowlist names exactly these.

use std::collections::{HashMap, VecDeque};
use std::io::{self, Read, Write};
use std::net::SocketAddr;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::sync::Arc;
use std::time::{Duration, Instant};

use nn_proto::ipc::{ExportChain, SinkFault, SinkState};
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, ClientConnection};

use crate::tls;

/// No TCP connection within this: the receiver is down for this try.
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
/// No TLS session within this of the connect: a receiver that accepts and
/// stays silent.
pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
/// Rows written and none acknowledged for this long: a receiver that does
/// not read; the connection is dropped and the rows written again.
pub const STALL_TIMEOUT: Duration = Duration::from_secs(30);
/// Bytes of records written and not yet acknowledged: beyond them nothing
/// more is written until acknowledgements come.
pub const MAX_IN_FLIGHT: usize = 1 << 20;
/// A connection is closed and another one opened once it carried this
/// many bytes (and none is in flight): no flow of the worker's grows past
/// it.
pub const MAX_CONNECTION_BYTES: u64 = 64 << 20;
/// Bytes a receiver may send the worker (it has nothing to say on a
/// syslog connection but TLS' own): more, and the connection is dropped.
pub const MAX_PEER_BYTES: u64 = 64 * 1024;
/// The longest a request waits for acknowledgements after its last write.
pub const ACK_WAIT: Duration = Duration::from_millis(100);
/// How long a row's bytes stay acknowledged by the receiver's TCP, on a
/// connection still up, before the row counts as delivered: a receiver
/// that closes with bytes it has not read resets the connection, and the
/// rows that had not settled are written again (at least once).
pub const SETTLE: Duration = Duration::from_secs(1);
/// The backoff's ceiling.
pub const MAX_BACKOFF: Duration = Duration::from_secs(60);

/// The sink's bounds (the constants above; the tests shorten them).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    pub connect: Duration,
    pub handshake: Duration,
    pub stall: Duration,
    pub ack_wait: Duration,
    pub in_flight: usize,
    pub connection_bytes: u64,
    pub peer_bytes: u64,
    pub settle: Duration,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            connect: CONNECT_TIMEOUT,
            handshake: HANDSHAKE_TIMEOUT,
            stall: STALL_TIMEOUT,
            ack_wait: ACK_WAIT,
            in_flight: MAX_IN_FLIGHT,
            connection_bytes: MAX_CONNECTION_BYTES,
            peer_bytes: MAX_PEER_BYTES,
            settle: SETTLE,
        }
    }
}

/// `SIOCOUTQ` (`TIOCOUTQ`): the bytes the socket sent and the peer has not
/// acknowledged (TCP: `write_seq - snd_una`).
pub const SIOCOUTQ: libc::c_ulong = libc::TIOCOUTQ as libc::c_ulong;

/// `socket(2)`'s type for the receiver: TCP, non-blocking, close-on-exec.
pub const SOCK_FLAGS: libc::c_int = libc::SOCK_STREAM | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC;

fn errno() -> i32 {
    io::Error::last_os_error()
        .raw_os_error()
        .unwrap_or(libc::EIO)
}

/// A non-blocking TCP socket.
#[derive(Debug)]
pub struct Socket(OwnedFd);

fn sockaddr(addr: &SocketAddr) -> (libc::sockaddr_storage, libc::socklen_t) {
    // SAFETY: an all-zero sockaddr_storage is valid.
    let mut ss: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
    let len = match addr {
        SocketAddr::V4(a) => {
            let sin = libc::sockaddr_in {
                sin_family: libc::AF_INET as libc::sa_family_t,
                sin_port: a.port().to_be(),
                sin_addr: libc::in_addr {
                    s_addr: u32::from(*a.ip()).to_be(),
                },
                sin_zero: [0; 8],
            };
            // SAFETY: sockaddr_in fits in sockaddr_storage.
            unsafe { std::ptr::write((&mut ss as *mut libc::sockaddr_storage).cast(), sin) };
            std::mem::size_of::<libc::sockaddr_in>()
        }
        SocketAddr::V6(a) => {
            let sin6 = libc::sockaddr_in6 {
                sin6_family: libc::AF_INET6 as libc::sa_family_t,
                sin6_port: a.port().to_be(),
                sin6_flowinfo: 0,
                sin6_addr: libc::in6_addr {
                    s6_addr: a.ip().octets(),
                },
                sin6_scope_id: a.scope_id(),
            };
            // SAFETY: sockaddr_in6 fits in sockaddr_storage.
            unsafe { std::ptr::write((&mut ss as *mut libc::sockaddr_storage).cast(), sin6) };
            std::mem::size_of::<libc::sockaddr_in6>()
        }
    };
    (ss, len as libc::socklen_t)
}

impl Socket {
    /// A socket, its connect started (`EINPROGRESS` is the usual answer).
    pub fn connect(addr: &SocketAddr) -> Result<Self, i32> {
        let family = if addr.is_ipv4() {
            libc::AF_INET
        } else {
            libc::AF_INET6
        };
        // SAFETY: socket with integer arguments.
        let fd = unsafe { libc::socket(family, SOCK_FLAGS, 0) };
        if fd < 0 {
            return Err(errno());
        }
        // SAFETY: a descriptor we just opened and own.
        let s = Socket(unsafe { OwnedFd::from_raw_fd(fd) });
        let (ss, len) = sockaddr(addr);
        // SAFETY: connect with a valid address of `len` bytes.
        let rc = unsafe {
            libc::connect(
                s.0.as_raw_fd(),
                (&ss as *const libc::sockaddr_storage).cast(),
                len,
            )
        };
        if rc != 0 && errno() != libc::EINPROGRESS {
            return Err(errno());
        }
        Ok(s)
    }

    /// The connect's result once the socket is writable (`SO_ERROR`).
    pub fn connect_result(&self) -> Result<(), i32> {
        let mut err: libc::c_int = 0;
        let mut len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
        // SAFETY: getsockopt into a c_int of the given size.
        let rc = unsafe {
            libc::getsockopt(
                self.0.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_ERROR,
                (&mut err as *mut libc::c_int).cast(),
                &mut len,
            )
        };
        match (rc, err) {
            (0, 0) => Ok(()),
            (0, e) => Err(e),
            _ => Err(errno()),
        }
    }

    /// Bytes sent and not acknowledged by the peer.
    pub fn unacked(&self) -> Result<u64, i32> {
        let mut n: libc::c_int = 0;
        // SAFETY: ioctl(SIOCOUTQ) into a c_int.
        if unsafe { libc::ioctl(self.0.as_raw_fd(), SIOCOUTQ as _, &mut n) } != 0 {
            return Err(errno());
        }
        Ok(n.max(0) as u64)
    }

    /// Wait for `events` until `until` (`ppoll`); the events that came (0
    /// at the deadline).
    pub fn wait(&self, events: libc::c_short, until: Instant) -> Result<libc::c_short, i32> {
        loop {
            let left = until.saturating_duration_since(Instant::now());
            let ts = libc::timespec {
                tv_sec: left.as_secs() as libc::time_t,
                tv_nsec: left.subsec_nanos() as libc::c_long,
            };
            let mut p = libc::pollfd {
                fd: self.0.as_raw_fd(),
                events,
                revents: 0,
            };
            // SAFETY: ppoll on one pollfd, a timespec, no signal mask.
            let rc = unsafe {
                libc::syscall(
                    libc::SYS_ppoll,
                    &mut p as *mut libc::pollfd,
                    1 as libc::nfds_t,
                    &ts as *const libc::timespec,
                    std::ptr::null::<libc::sigset_t>(),
                    0usize,
                )
            };
            if rc < 0 {
                let e = errno();
                if e == libc::EINTR {
                    continue;
                }
                return Err(e);
            }
            return Ok(if rc == 0 { 0 } else { p.revents });
        }
    }
}

impl Read for &Socket {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        // SAFETY: recvfrom into a live buffer, no address.
        let n = unsafe {
            libc::recvfrom(
                self.0.as_raw_fd(),
                buf.as_mut_ptr().cast(),
                buf.len(),
                0,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        };
        if n < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(n as usize)
    }
}

impl Write for &Socket {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        // SAFETY: sendto from a live buffer, no address.
        let n = unsafe {
            libc::sendto(
                self.0.as_raw_fd(),
                buf.as_ptr().cast(),
                buf.len(),
                libc::MSG_NOSIGNAL,
                std::ptr::null(),
                0,
            )
        };
        if n < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(n as usize)
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// A row written into the stream, its acknowledgement awaited.
#[derive(Debug, Clone)]
struct Flight {
    chain: ExportChain,
    pos: (u64, u64),
    bytes: usize,
    /// The stream's ciphertext offset its last byte is at, once flushed.
    end: Option<u64>,
    records: u32,
    unverified: bool,
    /// When the receiver's TCP acknowledged its last byte.
    acked_at: Option<Instant>,
}

#[derive(Debug)]
struct Conn {
    sock: Socket,
    tls: Option<ClientConnection>,
    started: Instant,
    /// Ciphertext bytes the socket took.
    sent: u64,
    /// Rows written, in order: not acknowledged by TCP yet, or acknowledged
    /// and settling.
    flights: VecDeque<Flight>,
    /// The bytes of the flights not acknowledged by TCP yet.
    in_flight: usize,
    /// The last row written into this connection, per chain.
    committed: HashMap<ExportChain, (u64, u64)>,
    /// When the oldest bytes still waiting for an acknowledgement began to
    /// wait: the last acknowledgement, the session's start, or (lot 299,
    /// BUG-20) the first write after a time with nothing waiting — what
    /// [`Limits::stall`] counts from.
    last_progress: Instant,
    peer_bytes: u64,
    established: bool,
}

/// What one row gives the stream: its frames, its records, whether its
/// signature verified.
pub struct Framed {
    pub frames: Vec<Vec<u8>>,
    pub records: u32,
    pub verified: bool,
}

/// A request's result on the syslog sink, for one chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Delivered {
    /// The newest row delivered (every row before it too).
    pub acked: Option<(u64, u64)>,
    /// The newest row written into the sink (`>= acked`).
    pub committed: Option<(u64, u64)>,
    /// The records and unverified rows delivered since the last answer.
    pub records: u32,
    pub unverified: u32,
    pub state: SinkState,
    pub fault: Option<SinkFault>,
    pub retry_ms: u32,
}

/// Counters for the status (the worker's own; the core's are signed).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Stats {
    pub connects: u64,
    pub sessions: u64,
    pub resets: u64,
    pub bytes: u64,
    /// Rows acknowledged by the receiver's TCP and written again because
    /// the connection failed before they settled.
    pub unsettled_lost: u64,
}

/// The syslog sink.
#[derive(Debug)]
pub struct SyslogSink {
    addr: SocketAddr,
    name: ServerName<'static>,
    config: Arc<ClientConfig>,
    conn: Option<Conn>,
    failures: u32,
    retry_at: Option<Instant>,
    fault: Option<SinkFault>,
    /// The last row delivered per chain, kept across connections.
    acked: HashMap<ExportChain, (u64, u64)>,
    /// Records and unverified rows delivered and not reported yet, per chain.
    unreported: HashMap<ExportChain, (u32, u32)>,
    limits: Limits,
    pub stats: Stats,
}

/// The backoff after `failures` in a row: 1, 2, 4 … 60 s.
pub fn backoff(failures: u32) -> Duration {
    let s = 1u64 << failures.saturating_sub(1).min(6);
    Duration::from_secs(s).min(MAX_BACKOFF)
}

impl SyslogSink {
    pub fn new(addr: SocketAddr, server_name: &str, ca_pem: &[u8]) -> Result<Self, SinkFault> {
        Ok(Self {
            addr,
            name: tls::server_name(server_name)?,
            config: tls::client_config(ca_pem)?,
            conn: None,
            failures: 0,
            retry_at: None,
            fault: None,
            acked: HashMap::new(),
            unreported: HashMap::new(),
            limits: Limits::default(),
            stats: Stats::default(),
        })
    }

    /// Other bounds (the tests').
    pub fn with_limits(mut self, limits: Limits) -> Self {
        self.limits = limits;
        self
    }

    /// The connection failed: what it held and had not settled is written
    /// again on the next one.
    fn fail(&mut self, fault: SinkFault, now: Instant) {
        if let Some(c) = self.conn.take() {
            self.stats.resets += 1;
            self.stats.unsettled_lost +=
                c.flights.iter().filter(|f| f.acked_at.is_some()).count() as u64;
        }
        self.failures = self.failures.saturating_add(1);
        self.retry_at = Some(now + backoff(self.failures));
        self.fault = Some(fault);
    }

    fn state(&self, now: Instant) -> (SinkState, u32) {
        match (&self.conn, self.retry_at) {
            (Some(c), _) if c.tls.as_ref().is_some_and(|t| !t.is_handshaking()) => {
                (SinkState::Up, 0)
            }
            (Some(_), _) => (SinkState::Connecting, 0),
            // rounded up: a wait that is left is never said to be none
            (None, Some(t)) if t > now => (
                SinkState::Down,
                (t.duration_since(now).as_millis() + 1).min(u128::from(u32::MAX)) as u32,
            ),
            (None, _) if self.fault.is_some() => (SinkState::Down, 0),
            (None, _) => (SinkState::Connecting, 0),
        }
    }

    /// Bring the connection up within `deadline`: `Ok(true)` once the TLS
    /// session is established.
    fn establish(&mut self, deadline: Instant) -> Result<bool, SinkFault> {
        let now = Instant::now();
        if self.conn.is_none() {
            if self.retry_at.is_some_and(|t| t > now) {
                return Ok(false);
            }
            self.stats.connects += 1;
            let sock = Socket::connect(&self.addr).map_err(SinkFault::Connect)?;
            self.conn = Some(Conn {
                sock,
                tls: None,
                started: now,
                sent: 0,
                flights: VecDeque::new(),
                in_flight: 0,
                committed: HashMap::new(),
                last_progress: now,
                peer_bytes: 0,
                established: false,
            });
        }
        let name = self.name.clone();
        let config = Arc::clone(&self.config);
        let lim = self.limits;
        let c = self.conn.as_mut().ok_or(SinkFault::Closed)?;
        if c.tls.is_none() {
            let until = deadline.min(c.started + lim.connect);
            let ev = c.sock.wait(libc::POLLOUT, until).map_err(SinkFault::Io)?;
            if ev == 0 {
                if Instant::now() >= c.started + lim.connect {
                    return Err(SinkFault::ConnectTimeout);
                }
                return Ok(false);
            }
            c.sock.connect_result().map_err(SinkFault::Connect)?;
            let mut tls = ClientConnection::new(config, name).map_err(|_| SinkFault::BadTrust)?;
            // the sink's own bound holds what rustls buffers: the bytes not
            // yet acknowledged are at most `Limits::in_flight` and one row's
            // frames — and a record may pass rustls' default 64 KiB, whose
            // `write_all` would fail against a slow receiver (found by the
            // tests of lot 276's mutations)
            tls.set_buffer_limit(None);
            c.tls = Some(tls);
        }
        loop {
            let t = c.tls.as_mut().ok_or(SinkFault::Closed)?;
            if !t.is_handshaking() {
                if !c.established {
                    c.established = true;
                    c.last_progress = Instant::now();
                    self.stats.sessions += 1;
                }
                return Ok(true);
            }
            flush(c)?;
            let t = c.tls.as_mut().ok_or(SinkFault::Closed)?;
            if !t.is_handshaking() {
                continue;
            }
            let until = deadline.min(c.started + lim.handshake);
            let want = if t.wants_write() {
                libc::POLLIN | libc::POLLOUT
            } else {
                libc::POLLIN
            };
            let ev = c.sock.wait(want, until).map_err(SinkFault::Io)?;
            if ev == 0 {
                if Instant::now() >= c.started + lim.handshake {
                    return Err(SinkFault::HandshakeTimeout);
                }
                return Ok(false);
            }
            pump_in(c, lim.peer_bytes)?;
        }
    }

    /// Write the `rows` of `chain` not written yet (the core sends the rows
    /// after the last one this sink said it committed, or again from its
    /// cursor), and gather what is delivered, within `deadline`. `framed`
    /// is asked only of rows it writes.
    pub fn rows<R>(
        &mut self,
        chain: ExportChain,
        rows: &[R],
        pos: impl Fn(&R) -> (u64, u64),
        mut framed: impl FnMut(&R) -> Framed,
        deadline: Instant,
    ) -> Delivered {
        let result = self.drive(chain, rows, &pos, &mut framed, deadline);
        let now = Instant::now();
        if let Err(f) = result {
            self.fail(f, now);
        }
        let acked = self.acked.get(&chain).copied();
        let committed = self
            .conn
            .as_ref()
            .and_then(|c| c.committed.get(&chain).copied())
            .max(acked);
        let (records, unverified) = self.unreported.remove(&chain).unwrap_or((0, 0));
        let (state, retry_ms) = self.state(now);
        Delivered {
            acked,
            committed,
            records,
            unverified,
            state,
            fault: if state == SinkState::Up {
                None
            } else {
                self.fault
            },
            retry_ms,
        }
    }

    fn drive<R>(
        &mut self,
        chain: ExportChain,
        rows: &[R],
        pos: &impl Fn(&R) -> (u64, u64),
        framed: &mut impl FnMut(&R) -> Framed,
        deadline: Instant,
    ) -> Result<(), SinkFault> {
        let lim = self.limits;
        // a connection that carried its share closes once everything on it
        // settled; the next request opens another
        if self.conn.as_ref().is_some_and(|c| {
            c.sent >= lim.connection_bytes && c.flights.is_empty() && c.established
        }) {
            if let Some(mut c) = self.conn.take() {
                if let Some(t) = c.tls.as_mut() {
                    t.send_close_notify();
                }
                let _ = flush(&mut c);
            }
        }
        if !self.establish(deadline)? {
            return Ok(());
        }
        let acked_to = self.acked.get(&chain).copied();
        let c = self.conn.as_mut().ok_or(SinkFault::Closed)?;
        pump_in(c, lim.peer_bytes)?;
        let mut wrote = false;
        // Lot 299 (external bug hunt, edition 1.2: BUG-20): a stall is rows
        // written and none acknowledged for `lim.stall`. On a session with
        // nothing waiting, the first row written starts that count: an idle
        // session's last progress may be older than the stall, and its
        // first row was cut `ack_wait` after its write (reset, backoff, the
        // row written twice).
        let idle = !c.flights.iter().any(|f| f.acked_at.is_none());
        for r in rows {
            let p = pos(r);
            let written = c.committed.get(&chain).copied().max(acked_to);
            if written.is_some_and(|w| p <= w) {
                continue;
            }
            // a connection that carried its share takes no more: it closes
            // once what it holds settled
            if c.in_flight >= lim.in_flight
                || c.sent >= lim.connection_bytes
                || Instant::now() >= deadline
            {
                break;
            }
            let f = framed(r);
            let t = c.tls.as_mut().ok_or(SinkFault::Closed)?;
            let mut bytes = 0;
            for frame in &f.frames {
                t.writer().write_all(frame).map_err(|_| SinkFault::Closed)?;
                bytes += frame.len();
            }
            c.flights.push_back(Flight {
                chain,
                pos: p,
                bytes,
                end: None,
                records: f.records,
                unverified: !f.verified,
                acked_at: None,
            });
            c.in_flight += bytes;
            c.committed.insert(chain, p);
            if idle && !wrote {
                c.last_progress = Instant::now();
            }
            wrote = true;
            if !flush(c)? {
                // the socket is full: what is written waits for it
                let _ = c
                    .sock
                    .wait(libc::POLLOUT, deadline.min(Instant::now() + lim.ack_wait));
                if !flush(c)? {
                    break;
                }
            }
        }
        // acknowledgements: at once from a near receiver; a slow one's, and
        // the settling, are gathered by the next requests
        let wait_until =
            deadline.min(Instant::now() + if wrote { lim.ack_wait } else { Duration::ZERO });
        loop {
            flush(self.conn.as_mut().ok_or(SinkFault::Closed)?)?;
            if self.collect_acks()? {
                self.failures = 0;
                self.fault = None;
                self.retry_at = None;
            }
            let c = self.conn.as_mut().ok_or(SinkFault::Closed)?;
            let waiting = c.flights.iter().any(|f| f.acked_at.is_none());
            if !waiting || Instant::now() >= wait_until {
                if waiting && c.last_progress.elapsed() >= lim.stall {
                    return Err(SinkFault::Io(libc::ETIMEDOUT));
                }
                return Ok(());
            }
            let ev = c
                .sock
                .wait(
                    libc::POLLIN,
                    wait_until.min(Instant::now() + Duration::from_millis(5)),
                )
                .map_err(SinkFault::Io)?;
            if ev != 0 {
                pump_in(c, lim.peer_bytes)?;
            }
        }
    }

    /// Note the flights the receiver's TCP acknowledged, and deliver those
    /// that settled: acknowledged at least [`Limits::settle`] ago on a
    /// connection that is still up. A receiver that closes with bytes it has
    /// not read resets the connection (`RST`): what had not settled is
    /// written again. Whether anything progressed.
    fn collect_acks(&mut self) -> Result<bool, SinkFault> {
        let lim = self.limits;
        let c = self.conn.as_mut().ok_or(SinkFault::Closed)?;
        let unacked = c.sock.unacked().map_err(SinkFault::Io)?;
        let acked_bytes = c.sent.saturating_sub(unacked);
        let now = Instant::now();
        let mut moved = false;
        for f in c.flights.iter_mut().filter(|f| f.acked_at.is_none()) {
            match f.end {
                Some(end) if end <= acked_bytes => {
                    f.acked_at = Some(now);
                    c.in_flight -= f.bytes;
                    c.last_progress = now;
                    moved = true;
                }
                _ => break,
            }
        }
        while let Some(f) = c.flights.front() {
            if !f
                .acked_at
                .is_some_and(|t| now.duration_since(t) >= lim.settle)
            {
                break;
            }
            let Some(f) = c.flights.pop_front() else {
                break;
            };
            self.stats.bytes += f.bytes as u64;
            self.acked.insert(f.chain, f.pos);
            let u = self.unreported.entry(f.chain).or_insert((0, 0));
            u.0 = u.0.saturating_add(f.records);
            u.1 = u.1.saturating_add(u32::from(f.unverified));
            moved = true;
        }
        Ok(moved)
    }

    /// The sink's state now, for a setup's answer.
    pub fn now_state(&self) -> SinkState {
        self.state(Instant::now()).0
    }
}

/// Hand rustls' pending ciphertext to the socket: `Ok(true)` when none is
/// left (and every row written so far has its end in the stream).
fn flush(c: &mut Conn) -> Result<bool, SinkFault> {
    let Some(t) = c.tls.as_mut() else {
        return Ok(true);
    };
    while t.wants_write() {
        match t.write_tls(&mut &c.sock) {
            Ok(n) => c.sent += n as u64,
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => return Ok(false),
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(SinkFault::Io(e.raw_os_error().unwrap_or(libc::EIO))),
        }
    }
    for f in c.flights.iter_mut().filter(|f| f.end.is_none()) {
        f.end = Some(c.sent);
    }
    Ok(true)
}

/// Read what the receiver sent: TLS' own messages (its session tickets, an
/// alert, its close), and any application data, dropped and counted.
fn pump_in(c: &mut Conn, max_peer: u64) -> Result<(), SinkFault> {
    let Some(t) = c.tls.as_mut() else {
        return Ok(());
    };
    loop {
        match t.read_tls(&mut &c.sock) {
            Ok(0) => return Err(SinkFault::Closed),
            Ok(_) => {
                let st = t
                    .process_new_packets()
                    .map_err(|e| SinkFault::Tls(tls::classify(&e)))?;
                let mut buf = [0u8; 4096];
                loop {
                    match t.reader().read(&mut buf) {
                        Ok(0) => return Err(SinkFault::Closed),
                        Ok(n) => {
                            c.peer_bytes += n as u64;
                            if c.peer_bytes > max_peer {
                                return Err(SinkFault::PeerData);
                            }
                        }
                        Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                        Err(_) => return Err(SinkFault::Closed),
                    }
                }
                if st.peer_has_closed() {
                    return Err(SinkFault::Closed);
                }
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => return Ok(()),
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(SinkFault::Io(e.raw_os_error().unwrap_or(libc::EIO))),
        }
    }
}

#[cfg(test)]
mod tests;
