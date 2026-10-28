//! The admin socket's transport (R11d, lab PR 263: from
//! `admin_socket.rs`): the bind and the accept loop, the table of
//! connections, the peer's credentials and identity, the framing, and the
//! loop of one connection — read a frame, have it dispatched and audited
//! off the runtime, write the reply.

use std::collections::HashMap;
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use parking_lot::Mutex;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;
use tokio::sync::Notify;
use tracing::{error, info, warn};

use nn_proto::admin_protocol::{decode_frame, encode_frame, AdminMessage, MAX_FRAME_BODY};

use super::audit::{emit_audit_for, AuditClient, DispatchNotes};
use super::handlers::{dispatch, Wired};
use super::{
    socket_watch, status_polls, AdminReadPaths, CanaryAdminState, DetectionAdminState,
    FimAdminState, ResponseAdminState, ShutdownSignal, StatusPolls,
};
use crate::anti_tamper::admin_auth::{AdminAuth, ConnAuth};
use crate::anti_tamper::network_isolate::NetworkIsolator;
use crate::anti_tamper::trusted_installer::TrustedInstallerOverride;
use crate::audit::AuditLog;
use crate::posture::PostureMachine;
use crate::shutdown_marker::DEFAULT_MARKER_PATH;

/// Bind the admin socket and run the accept loop forever. Returns
/// only on a listener error that is not transient (external audit
/// NN-AUD-077: EMFILE, ENFILE, ENOBUFS, ENOMEM, ECONNABORTED and EINTR
/// back off and retry); the caller records that the admin plane is gone.
///
/// On startup an existing socket file at `socket_path` is silently
/// removed before `bind` — the previous agent process may have died
/// without cleaning up, and leaving a stale socket would cause
/// `bind` to return `EADDRINUSE`.
pub async fn serve(
    socket_path: PathBuf,
    auth: Arc<AdminAuth>,
    posture: Arc<PostureMachine>,
    isolator: Arc<NetworkIsolator>,
) -> Result<()> {
    // The shutdown-marker path is fixed per design §10.3 in
    // production. `serve_with_marker_path` lets tests substitute
    // a tempdir path; production serve() pins the canonical one.
    // Legacy `serve` callers (those that predate A8's
    // ShutdownSignal) get None — the dispatcher still writes the
    // marker, the in-process exit signal is just not delivered.
    // Audit log also None for legacy callers (predates B5);
    // production callers use `serve_with_audit_log` which threads
    // the audit-log writer into every dispatch.
    serve_with_marker_path(
        socket_path,
        auth,
        posture,
        isolator,
        PathBuf::from(DEFAULT_MARKER_PATH),
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        Arc::default(),
        Arc::default(),
    )
    .await
}

/// Tappa 8 B5 production entry-point — accepts an
/// `Arc<Mutex<AuditLog>>` so every successful (and failed)
/// signed admin op emits a chained audit-log entry. main.rs
/// constructs the AuditLog once at boot from the agent signing
/// key bootstrapped in B1; the lock is held only during one
/// `append` call (microseconds) so contention is negligible.
pub async fn serve_with_audit_log(
    socket_path: PathBuf,
    auth: Arc<AdminAuth>,
    posture: Arc<PostureMachine>,
    isolator: Arc<NetworkIsolator>,
    marker_path: PathBuf,
    shutdown_signal: Option<ShutdownSignal>,
    audit_log: Arc<Mutex<AuditLog>>,
) -> Result<()> {
    serve_with_marker_path(
        socket_path,
        auth,
        posture,
        isolator,
        marker_path,
        shutdown_signal,
        Some(audit_log),
        None,
        None,
        None,
        None,
        None,
        Arc::default(),
        Arc::default(),
    )
    .await
}

/// Tappa 9 C7 production entry-point — extends
/// [`serve_with_audit_log`] with the FIM state bundle. main.rs
/// constructs an [`FimAdminState`] at boot from the recompute
/// channel sender, the drift-rate-limiter handle, and the
/// watched-paths summary, then hands an `Arc` clone here. The
/// admin socket forwards a borrow to dispatch so
/// `FimBaselineRequest` triggers the recompute channel and
/// `FimStatusRequest` returns the in-process snapshot.
#[allow(clippy::too_many_arguments)]
pub async fn serve_with_fim_state(
    socket_path: PathBuf,
    auth: Arc<AdminAuth>,
    posture: Arc<PostureMachine>,
    isolator: Arc<NetworkIsolator>,
    marker_path: PathBuf,
    shutdown_signal: Option<ShutdownSignal>,
    audit_log: Option<Arc<Mutex<AuditLog>>>,
    fim_state: Arc<FimAdminState>,
) -> Result<()> {
    serve_with_marker_path(
        socket_path,
        auth,
        posture,
        isolator,
        marker_path,
        shutdown_signal,
        audit_log,
        Some(fim_state),
        None,
        None,
        None,
        None,
        Arc::default(),
        Arc::default(),
    )
    .await
}

/// Tappa 9.5 K6 production entry-point — adds the canary
/// admin state bundle alongside fim state. main.rs constructs
/// the [`CanaryAdminState`] (registry + indexes + log path)
/// at boot via the same [`Detector::new`] handles fed to
/// `process_event`.
#[allow(clippy::too_many_arguments)]
pub async fn serve_with_canary_state(
    socket_path: PathBuf,
    auth: Arc<AdminAuth>,
    posture: Arc<PostureMachine>,
    isolator: Arc<NetworkIsolator>,
    marker_path: PathBuf,
    shutdown_signal: Option<ShutdownSignal>,
    audit_log: Option<Arc<Mutex<AuditLog>>>,
    fim_state: Option<Arc<FimAdminState>>,
    canary_state: Arc<CanaryAdminState>,
) -> Result<()> {
    serve_with_marker_path(
        socket_path,
        auth,
        posture,
        isolator,
        marker_path,
        shutdown_signal,
        audit_log,
        fim_state,
        Some(canary_state),
        None,
        None,
        None,
        Arc::default(),
        Arc::default(),
    )
    .await
}

/// Test-injectable variant of [`serve`] that lets the caller
/// substitute the shutdown-marker file path (so unit tests can
/// land the marker in a tempdir instead of `/run/northnarrow/`,
/// which requires root and is process-global) AND optionally pass
/// a [`ShutdownSignal`] — when present, the dispatcher fires it
/// after a successful marker write so the agent's main loop can
/// break and exit cleanly (Tappa 8 A8). When `None`, the
/// dispatcher still writes the marker but no in-process signal is
/// delivered (legacy + test callers that don't care).
#[allow(clippy::too_many_arguments)]
pub async fn serve_with_marker_path(
    socket_path: PathBuf,
    auth: Arc<AdminAuth>,
    posture: Arc<PostureMachine>,
    isolator: Arc<NetworkIsolator>,
    marker_path: PathBuf,
    shutdown_signal: Option<ShutdownSignal>,
    audit_log: Option<Arc<Mutex<AuditLog>>>,
    fim_state: Option<Arc<FimAdminState>>,
    canary_state: Option<Arc<CanaryAdminState>>,
    // FIM-009 self-upgrade (§15.1): shared override armed by a verified
    // TrustedInstallerGrantRequest. None on legacy serve paths.
    installer_override: Option<Arc<TrustedInstallerOverride>>,
    // Tappa 9.0.c: status-event chain handle + paths for the detection
    // triage verbs (set-status write + read overlay). None on legacy /
    // test serve paths that don't wire the detection store.
    detection_state: Option<Arc<DetectionAdminState>>,
    // External audit CMB-016: the response verbs' state. None on legacy /
    // test serve paths.
    response_state: Option<Arc<ResponseAdminState>>,
    // External audit NN-AUD-082: the files the read verbs serve.
    read_paths: Arc<AdminReadPaths>,
    // External audit ASK-009 (lab PR 213): the unsigned status polling, per
    // peer, and the registered watchdog it leaves out.
    status_polls: Arc<StatusPolls>,
) -> Result<()> {
    // A stale socket (or anything else but a directory) at the path is
    // removed without following a link; the mode is forced to 0600 so a
    // slack umask never widens the socket (socket_watch::bind).
    let (mut listener, bound) = socket_watch::bind(&socket_path)?;
    info!(
        path = %socket_path.display(),
        "admin socket listening (mode 0600)"
    );
    // External audit WDG-007 (NN-AUD-358): the path is outside the deny
    // hooks; a socket removed or replaced while the agent runs is a signed
    // finding and is bound again at the next check.
    let mut watch = socket_watch::SocketWatch::new(socket_path.clone(), bound);
    let mut check = tokio::time::interval(socket_watch::SOCKET_CHECK_EVERY);
    check.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    check.tick().await;

    // External audit NN-AUD-077: a bounded table of connections, and an
    // accept loop that outlives a transient error.
    let slots = ConnSlots::new(ConnLimits::DEFAULT);
    let mut accept_backoff = AcceptBackoff::default();
    let mut refused_log = LogEvery::new(LOG_EVERY);
    let mut evicted_log = LogEvery::new(LOG_EVERY);
    // External audit ASK-012 (NN-AUD-238): who may connect.
    let own_euid = own_euid(&socket_path);
    let mut foreign = ForeignPeers::new(socket_path.clone(), own_euid);
    loop {
        let accepted = tokio::select! {
            accepted = listener.accept() => accepted,
            _ = check.tick() => {
                if let Some(rebound) = watch.check(audit_log.as_ref()) {
                    listener = rebound;
                }
                continue;
            }
        };
        let stream = match accepted {
            Ok((stream, _)) => {
                accept_backoff.reset();
                stream
            }
            Err(e) if accept_error_is_transient(&e) => {
                accept_backoff.pause(&e).await;
                continue;
            }
            Err(e) => return Err(e).context("accepting admin connection"),
        };
        // External audit ASK-012 (NN-AUD-238): the peer's credentials are
        // checked before it gets anything — a slot, an eviction, a reply.
        let cred = match screen_peer(stream.as_raw_fd(), own_euid) {
            Ok(cred) => cred,
            Err(refusal) => {
                foreign.refuse(&refusal, stream.as_raw_fd(), audit_log.as_ref());
                drop(stream);
                continue;
            }
        };
        let Some(slot) = slots.admit() else {
            // Every slot is mid-request (none is waiting on its peer):
            // drop the newcomer rather than grow without bound.
            if let Some(suppressed) = refused_log.ready() {
                warn!(
                    max = MAX_ADMIN_CONNECTIONS,
                    suppressed, "admin connection refused: every slot is serving a request"
                );
            }
            drop(stream);
            continue;
        };
        if slot.made_room {
            if let Some(suppressed) = evicted_log.ready() {
                warn!(
                    max = MAX_ADMIN_CONNECTIONS,
                    closed = suppressed + 1,
                    "admin connection table full: closed the longest-waiting connections \
                     to admit new ones"
                );
            }
        }
        let auth = Arc::clone(&auth);
        let posture = Arc::clone(&posture);
        let isolator = Arc::clone(&isolator);
        let marker_path = marker_path.clone();
        let shutdown_signal = shutdown_signal.clone();
        let audit_log = audit_log.clone();
        let fim_state = fim_state.clone();
        let canary_state = canary_state.clone();
        let installer_override = installer_override.clone();
        let detection_state = detection_state.clone();
        let response_state = response_state.clone();
        let read_paths = Arc::clone(&read_paths);
        let status_polls = Arc::clone(&status_polls);
        tokio::spawn(async move {
            if let Err(e) = handle_connection(
                stream,
                cred,
                slot,
                &auth,
                &posture,
                &isolator,
                &marker_path,
                shutdown_signal.as_ref(),
                audit_log.as_ref(),
                fim_state.as_ref(),
                canary_state.as_ref(),
                installer_override.as_ref(),
                detection_state.as_ref(),
                response_state.as_ref(),
                &read_paths,
                &status_polls,
            )
            .await
            {
                warn!(error = ?e, "admin connection handler errored");
            }
        });
    }
}

/// Helper for `main.rs` shutdown — best-effort unlink, no error on
/// missing file (the listener may already have been dropped). The socket's
/// watch stops first (external audit WDG-007), so the agent does not bind
/// it again on its way out.
///
/// External audit ASK-014 (NN-AUD-240): the name is removed without
/// following a link (`lstat`, then `unlink`) — `exists()` follows one, so a
/// dangling link at the path was left behind.
pub fn unlink_socket(path: &Path) {
    socket_watch::retire(path);
    if let Err(e) = socket_watch::clear(path) {
        warn!(
            error = format!("{e:#}"),
            path = %path.display(),
            "failed to unlink admin socket on shutdown"
        );
    }
}

/// External audit NN-AUD-077: connections served at once. nn-admin and
/// the watchdog open one at a time; 32 leaves room for a dashboard and
/// operators while bounding the fds and buffers the admin plane can take
/// from the agent (systemd's default soft limit is 1024).
pub(super) const MAX_ADMIN_CONNECTIONS: usize = 32;

/// Time a peer gets to send each request. nn-admin and the watchdog send
/// at once (nn-admin's own timeout is 5 s); an interactive or hardware-token
/// signing flow would need a longer one.
const FRAME_READ_TIMEOUT: Duration = Duration::from_secs(10);

/// Time a peer gets to take each reply.
const FRAME_WRITE_TIMEOUT: Duration = Duration::from_secs(5);

/// How often a repeated accept or refusal warning is logged.
const LOG_EVERY: Duration = Duration::from_secs(10);

#[derive(Debug, Clone, Copy)]
pub(super) struct ConnLimits {
    pub(super) max_conns: usize,
    pub(super) read_timeout: Duration,
    pub(super) write_timeout: Duration,
}

impl ConnLimits {
    pub(super) const DEFAULT: Self = Self {
        max_conns: MAX_ADMIN_CONNECTIONS,
        read_timeout: FRAME_READ_TIMEOUT,
        write_timeout: FRAME_WRITE_TIMEOUT,
    };
}

/// External audit NN-AUD-077: the table of live admin connections.
///
/// A plain semaphore would let [`MAX_ADMIN_CONNECTIONS`] connections that
/// never send anything lock nn-admin and the watchdog out until the read
/// timeout — and a root peer can reconnect as fast as they are closed. So
/// a full table makes room for a newcomer by closing the connection that
/// has waited longest on its peer (to send a request, or to take a reply).
/// A legitimate client waits on itself only for microseconds; a slow or
/// idle one is the first to go. Only when every connection is mid-request
/// is the newcomer refused.
pub(super) struct ConnSlots {
    limits: ConnLimits,
    table: Mutex<SlotTable>,
}

#[derive(Default)]
struct SlotTable {
    next_id: u64,
    live: HashMap<u64, SlotEntry>,
}

struct SlotEntry {
    /// `Some(since)` while the connection waits on its peer; `None` while
    /// it serves a request.
    waiting_since: Option<Instant>,
    evict: Arc<Notify>,
}

impl ConnSlots {
    pub(super) fn new(limits: ConnLimits) -> Arc<Self> {
        Arc::new(Self {
            limits,
            table: Mutex::new(SlotTable::default()),
        })
    }

    /// A slot for a new connection, closing the longest-waiting one when
    /// the table is full; `None` when every connection is mid-request.
    pub(super) fn admit(self: &Arc<Self>) -> Option<ConnSlot> {
        let mut table = self.table.lock();
        let made_room = table.live.len() >= self.limits.max_conns;
        if made_room {
            let (_, victim) = table
                .live
                .iter()
                .filter_map(|(id, e)| e.waiting_since.map(|since| (since, *id)))
                .min()?;
            if let Some(entry) = table.live.remove(&victim) {
                entry.evict.notify_one();
            }
        }
        let id = table.next_id;
        table.next_id = table.next_id.wrapping_add(1);
        let evict = Arc::new(Notify::new());
        table.live.insert(
            id,
            SlotEntry {
                waiting_since: Some(Instant::now()),
                evict: Arc::clone(&evict),
            },
        );
        Some(ConnSlot {
            id,
            slots: Arc::clone(self),
            evict,
            made_room,
        })
    }

    #[cfg(test)]
    pub(super) fn live(&self) -> usize {
        self.table.lock().live.len()
    }
}

/// One connection's place in [`ConnSlots`]; leaving the table on drop.
pub(super) struct ConnSlot {
    id: u64,
    slots: Arc<ConnSlots>,
    evict: Arc<Notify>,
    /// Another connection was closed to admit this one.
    pub(super) made_room: bool,
}

impl ConnSlot {
    fn limits(&self) -> ConnLimits {
        self.slots.limits
    }

    /// From now on the connection waits on its peer — evictable. `false`
    /// when it was already evicted.
    pub(super) fn waiting(&self) -> bool {
        self.set_waiting(Some(Instant::now()))
    }

    /// The connection serves a request — not evictable. `false` when it
    /// was already evicted.
    pub(super) fn busy(&self) -> bool {
        self.set_waiting(None)
    }

    fn set_waiting(&self, since: Option<Instant>) -> bool {
        match self.slots.table.lock().live.get_mut(&self.id) {
            Some(entry) => {
                entry.waiting_since = since;
                true
            }
            None => false,
        }
    }

    /// Resolves when a newcomer took this connection's place.
    pub(super) async fn evicted(&self) {
        self.evict.notified().await;
    }
}

impl Drop for ConnSlot {
    fn drop(&mut self) {
        self.slots.table.lock().live.remove(&self.id);
    }
}

/// External audit NN-AUD-077: the `accept()` errors that say nothing about
/// the listener — the fd table or kernel memory is short, or one peer gave
/// up — and must not end the admin plane.
pub(super) fn accept_error_is_transient(e: &std::io::Error) -> bool {
    matches!(
        e.raw_os_error(),
        Some(
            libc::EMFILE
                | libc::ENFILE
                | libc::ENOBUFS
                | libc::ENOMEM
                | libc::ECONNABORTED
                | libc::EINTR
        )
    )
}

/// Back-off for a failing `accept()`: 100 ms doubling to 1 s, reset by the
/// next accepted connection; the warning is logged at most every
/// [`LOG_EVERY`].
struct AcceptBackoff {
    delay: Duration,
    log: LogEvery,
}

impl AcceptBackoff {
    const FIRST: Duration = Duration::from_millis(100);
    const MAX: Duration = Duration::from_secs(1);

    async fn pause(&mut self, e: &std::io::Error) {
        if let Some(suppressed) = self.log.ready() {
            warn!(
                error = %e,
                retry_in_ms = self.delay.as_millis() as u64,
                suppressed,
                "admin socket accept failed; backing off — the socket stays open"
            );
        }
        tokio::time::sleep(self.delay).await;
        self.delay = (self.delay * 2).min(Self::MAX);
    }

    fn reset(&mut self) {
        self.delay = Self::FIRST;
    }
}

impl Default for AcceptBackoff {
    fn default() -> Self {
        Self {
            delay: Self::FIRST,
            log: LogEvery::new(LOG_EVERY),
        }
    }
}

/// At most one log line per `every`; [`Self::ready`] returns how many
/// were suppressed since the last one.
struct LogEvery {
    every: Duration,
    last: Option<Instant>,
    suppressed: u64,
}

impl LogEvery {
    fn new(every: Duration) -> Self {
        Self {
            every,
            last: None,
            suppressed: 0,
        }
    }

    fn ready(&mut self) -> Option<u64> {
        let now = Instant::now();
        if self
            .last
            .is_some_and(|t| now.duration_since(t) < self.every)
        {
            self.suppressed += 1;
            return None;
        }
        self.last = Some(now);
        Some(std::mem::take(&mut self.suppressed))
    }
}

/// Drive one connection until the client closes the stream. Each
/// iteration reads exactly one frame and writes exactly one reply;
/// the `nn-admin unlock` flow uses two iterations (challenge then
/// unlock) and then closes.
///
/// External audit NN-AUD-077: the peer gets the slot's read timeout to
/// send each request and its write timeout to take each reply, and the
/// connection ends when a newcomer evicts it. External audit NN-AUD-078 /
/// NN-AUD-079: the connection's challenge and failure count live in a
/// [`ConnAuth`]; a connection that used up its failures is closed after
/// the reply.
#[allow(clippy::too_many_arguments)]
pub(super) async fn handle_connection(
    mut stream: UnixStream,
    cred: PeerCred,
    slot: ConnSlot,
    auth: &AdminAuth,
    posture: &PostureMachine,
    isolator: &NetworkIsolator,
    marker_path: &Path,
    shutdown_signal: Option<&ShutdownSignal>,
    audit_log: Option<&Arc<Mutex<AuditLog>>>,
    fim_state: Option<&Arc<FimAdminState>>,
    canary_state: Option<&Arc<CanaryAdminState>>,
    installer_override: Option<&Arc<TrustedInstallerOverride>>,
    detection_state: Option<&Arc<DetectionAdminState>>,
    response_state: Option<&Arc<ResponseAdminState>>,
    read_paths: &AdminReadPaths,
    status_polls: &StatusPolls,
) -> Result<()> {
    // The peer's identity once per connection — the audit log wants
    // pid/uid/comm/exe of the caller, and a single connection never
    // changes peers mid-stream (SO_PEERCRED is fixed at connect time).
    let client = peer_identity(stream.as_raw_fd(), &cred);
    let auth = ConnAuth::new(auth);
    let ctx = Wired {
        posture,
        isolator,
        marker_path,
        shutdown_signal,
        fim_state: fim_state.map(|s| s.as_ref()),
        canary_state: canary_state.map(|s| s.as_ref()),
        installer_override: installer_override.map(|s| s.as_ref()),
        detection_state: detection_state.map(|s| s.as_ref()),
        response_state: response_state.map(|s| s.as_ref()),
        read_paths,
    };
    let limits = slot.limits();
    loop {
        if !slot.waiting() {
            return Ok(());
        }
        let read = tokio::time::timeout(limits.read_timeout, read_frame(&mut stream));
        let msg = tokio::select! {
            () = slot.evicted() => {
                // Logged, rate-limited, by the accept loop.
                tracing::debug!(
                    client_pid = client.pid,
                    "admin connection closed to make room for a new one"
                );
                return Ok(());
            }
            read = read => match read {
                Err(_) => {
                    // Debug: a peer opening connections at will must not
                    // turn each into a journal line.
                    tracing::debug!(
                        client_pid = client.pid,
                        timeout_secs = limits.read_timeout.as_secs(),
                        "admin connection closed: no request within the timeout"
                    );
                    return Ok(());
                }
                Ok(frame) => match frame? {
                    Some(m) => m,
                    None => return Ok(()),
                },
            },
        };
        if !slot.busy() {
            return Ok(());
        }
        // External audit ASK-005 (NN-AUD-236): the request's work — the
        // bounded file reads, the per-row signature checks, the chain
        // appends and the audit row's fsync under the audit mutex — runs
        // off the runtime's worker, so the sensors' drains, the telemetry
        // probe and the other connections keep running meanwhile. This
        // task waits for it: one request at a time per connection, the
        // reply written after its audit row, as before. No lock is held
        // across an `.await`.
        let reply = crate::runtime::off_the_runtime(|| {
            serve_request(&msg, &auth, ctx, &client, audit_log, status_polls)
        });
        if !slot.waiting() {
            return Ok(());
        }
        // Biased to the write: a reply the peer can take at once is
        // delivered even if a newcomer is evicting this connection.
        let write = tokio::time::timeout(limits.write_timeout, write_frame(&mut stream, &reply));
        tokio::select! {
            biased;
            written = write => {
                written.map_err(|_| {
                    anyhow::anyhow!("admin reply not taken within {:?}", limits.write_timeout)
                })??;
            }
            () = slot.evicted() => return Ok(()),
        }
        if auth.exhausted() {
            warn!(
                client_pid = client.pid,
                client_comm = %nn_model::log_escape::Escaped(&client.comm),
                "admin connection closed after repeated signature failures"
            );
            return Ok(());
        }
    }
}

/// One request's way from its frame to its reply, every request alike:
/// `dispatch` (a signed verb verified by `verify::signed`, then its
/// handler; the unsigned ones answered as they are), then the signed
/// audit row of the request and its reply (`emit_audit_for`, accepted and
/// refused alike), then, for the unsigned `status`, its peer's count.
/// `handle_connection` runs it off the runtime and writes the reply after
/// its row.
pub(super) fn serve_request(
    msg: &AdminMessage,
    auth: &ConnAuth<'_>,
    ctx: Wired<'_>,
    client: &AuditClient,
    audit_log: Option<&Arc<Mutex<AuditLog>>>,
    status_polls: &StatusPolls,
) -> AdminMessage {
    let mut matched_fps: Vec<String> = Vec::new();
    let mut notes = DispatchNotes::default();
    let reply = dispatch(msg.clone(), auth, ctx, client, &mut matched_fps, &mut notes);
    emit_audit_for(msg, &reply, client, audit_log, &matched_fps, &notes);
    // External audit ASK-009 (lab PR 213): the unsigned status, one
    // signed row per peer per hour.
    if matches!(msg, AdminMessage::Status(_)) {
        note_status_poll(status_polls, client, audit_log);
    }
    reply
}

/// External audit ASK-009 (lab PR 213): count an unsigned `status` and
/// append the `status_polled` row that opens its peer's window. A failed
/// append is a WARN; the reply is sent anyway, as for the other rows.
pub(super) fn note_status_poll(
    polls: &StatusPolls,
    client: &AuditClient,
    audit_log: Option<&Arc<Mutex<AuditLog>>>,
) {
    let Some(audit_log) = audit_log else {
        return;
    };
    let Some(draft) = polls.note(client, Instant::now()) else {
        return;
    };
    if let Err(e) = audit_log.lock().append(draft) {
        warn!(
            error = %e,
            op = status_polls::STATUS_POLLED_OP,
            "audit log append failed — status_polled row missing"
        );
    }
}

/// A peer's `SO_PEERCRED`: the credentials of the process (the thread)
/// that called `connect()`, fixed at that moment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct PeerCred {
    pub pid: u32,
    pub uid: u32,
    pub gid: u32,
}

/// External audit ASK-012 (NN-AUD-238): why a connection was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PeerRefusal {
    /// `getsockopt(SO_PEERCRED)` failed with this errno.
    Unreadable(i32),
    /// The kernel returned this many bytes, not a whole `struct ucred`.
    ShortCred(usize),
    /// A uid that may not use the admin plane.
    ForeignUid(PeerCred),
}

/// External audit ASK-012 (NN-AUD-238): the uids that may use the admin
/// plane — root, and the agent's own euid. In production the agent runs
/// as root, so that is uid 0 alone (`nn-admin`, the watchdog, COMBAT
/// recovery all run as root); the own euid lets an agent started as a
/// user (the unit tests) serve that user. The socket's mode 0600 stays
/// the first gate; this one holds when the mode or the directory was
/// changed. When V1.1 widens the socket to a service group, it becomes
/// "uid 0 or a member of that group".
pub(crate) fn peer_allowed(cred: &PeerCred, own_euid: u32) -> bool {
    cred.uid == 0 || cred.uid == own_euid
}

/// `getsockopt(SO_PEERCRED)` on `fd`. A failure, or a reply shorter or
/// longer than a `struct ucred`, is a refusal: the credentials used to
/// fall back to uid 0.
pub(super) fn peer_cred(fd: std::os::unix::io::RawFd) -> Result<PeerCred, PeerRefusal> {
    let mut cred = libc::ucred {
        pid: 0,
        uid: 0,
        gid: 0,
    };
    let want = std::mem::size_of::<libc::ucred>();
    let mut len = want as libc::socklen_t;
    // SAFETY: `cred` is a repr(C) ucred of `len` bytes that getsockopt
    // fills; `len` is passed by &mut so the kernel reports what it wrote.
    let rc = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&mut cred as *mut libc::ucred).cast::<libc::c_void>(),
            &mut len,
        )
    };
    if rc != 0 {
        let errno = std::io::Error::last_os_error()
            .raw_os_error()
            .unwrap_or(libc::EIO);
        return Err(PeerRefusal::Unreadable(errno));
    }
    if len as usize != want {
        return Err(PeerRefusal::ShortCred(len as usize));
    }
    Ok(PeerCred {
        pid: cred.pid as u32,
        uid: cred.uid,
        gid: cred.gid,
    })
}

/// External audit ASK-012: the peer on `fd`, if it may use the admin plane.
pub(super) fn screen_peer(
    fd: std::os::unix::io::RawFd,
    own_euid: u32,
) -> Result<PeerCred, PeerRefusal> {
    let cred = peer_cred(fd)?;
    if peer_allowed(&cred, own_euid) {
        Ok(cred)
    } else {
        Err(PeerRefusal::ForeignUid(cred))
    }
}

/// The agent's own euid ([`peer_allowed`]).
fn own_euid(socket_path: &Path) -> u32 {
    #[cfg(test)]
    if let Some(euid) = super::tests::own_euid_override(socket_path) {
        return euid;
    }
    let _ = socket_path;
    // SAFETY: geteuid has no preconditions and cannot fail.
    unsafe { libc::geteuid() }
}

/// `SO_PEERPIDFD` (Linux 6.5, asm-generic value; `libc` does not export
/// it yet): a pidfd on the peer itself.
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
const SO_PEERPIDFD: libc::c_int = 77;

/// A pidfd on the peer, to tell whether `/proc/<pid>` still described it
/// after it was read.
enum PeerPidfd {
    Open(std::os::fd::OwnedFd),
    /// The peer had exited (no process left to read).
    Gone,
    /// No pidfd (out of descriptors): `/proc` read unchecked, as before.
    Unavailable,
}

fn peer_pidfd(sock: std::os::unix::io::RawFd, pid: u32) -> PeerPidfd {
    use std::os::fd::FromRawFd;
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    {
        let mut fd: libc::c_int = -1;
        let mut len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
        // SAFETY: an int-sized out-parameter of `len` bytes.
        let rc = unsafe {
            libc::getsockopt(
                sock,
                libc::SOL_SOCKET,
                SO_PEERPIDFD,
                (&mut fd as *mut libc::c_int).cast::<libc::c_void>(),
                &mut len,
            )
        };
        if rc == 0 && fd >= 0 {
            // SAFETY: the kernel installed this descriptor for us.
            return PeerPidfd::Open(unsafe { std::os::fd::OwnedFd::from_raw_fd(fd) });
        }
        match std::io::Error::last_os_error().raw_os_error() {
            // Before 6.5: fall back to pidfd_open by pid.
            Some(libc::ENOPROTOOPT) => {}
            // The peer has no live process (reaped): never look the pid
            // up again, another process may hold it.
            Some(libc::EINVAL | libc::ESRCH | libc::ENODATA) => return PeerPidfd::Gone,
            _ => return PeerPidfd::Unavailable,
        }
    }
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    let _ = sock;
    // pidfd_open(pid): the process holding the pid now. The window between
    // the peer's exit and this call is where a reused pid could be read;
    // `SO_PEERPIDFD` closes it from 6.5.
    match crate::response::proc_ref::pidfd_open(pid) {
        // SAFETY: pidfd_open returned this fd to us; we own it.
        Ok(fd) => PeerPidfd::Open(unsafe { std::os::fd::OwnedFd::from_raw_fd(fd) }),
        Err(e) if e.raw_os_error() == Some(libc::ESRCH) => PeerPidfd::Gone,
        Err(_) => PeerPidfd::Unavailable,
    }
}

/// External audit ASK-013 (NN-AUD-239): `comm` and `exe` of the peer on
/// `sock`, read from `/proc/<pid>` while a pidfd on the peer holds its
/// pid: a peer that exited before the reads were checked is `<exited>`
/// (its pid could already name another process), never whatever holds
/// the pid now. Failure to read is degrade-not-fail: the audit row is
/// still written, with `<unknown>` / no exe.
pub(super) fn peer_identity(sock: std::os::unix::io::RawFd, cred: &PeerCred) -> AuditClient {
    let mut client = AuditClient {
        pid: cred.pid,
        uid: cred.uid,
        comm: "<unknown>".to_string(),
        exe: None,
    };
    // pid 0: a peer in a pid namespace this one cannot see.
    if cred.pid == 0 {
        return client;
    }
    let pidfd = peer_pidfd(sock, cred.pid);
    if matches!(pidfd, PeerPidfd::Gone) {
        client.comm = "<exited>".to_string();
        return client;
    }
    let pid = cred.pid;
    let comm = std::fs::read_to_string(format!("/proc/{pid}/comm"))
        .ok()
        .map(|s| s.trim_end_matches('\n').to_string())
        .filter(|s| !s.is_empty());
    let exe = std::fs::read_link(format!("/proc/{pid}/exe"))
        .ok()
        .map(|p| p.to_string_lossy().into_owned());
    if let PeerPidfd::Open(fd) = &pidfd {
        // Exited (zombie included): the reads may describe another process.
        if crate::response::proc_ref::pidfd_exited(fd) {
            client.comm = "<exited>".to_string();
            return client;
        }
    }
    if let Some(comm) = comm {
        client.comm = comm;
    }
    client.exe = exe;
    client
}

/// The signed kind of a refused admin peer (external audit ASK-012).
pub const FOREIGN_PEER_KIND: &str = "admin_socket_foreign_peer";

/// External audit ASK-012 (NN-AUD-238): refused peers, reported. The
/// socket is created 0600 in a 0700 directory, so a peer of another uid
/// means the mode, the owner or the directory was changed: one signed
/// `integrity_drift` (`admin_socket_foreign_peer`) per
/// [`crate::self_integrity::REREPORT_SECS`], the refusals in between
/// counted into the next one and logged at most every [`LOG_EVERY`]. A
/// refused connection is closed without a reply.
struct ForeignPeers {
    socket_path: PathBuf,
    own_euid: u32,
    log: LogEvery,
    last_signed: Option<Instant>,
    unsigned: u32,
}

impl ForeignPeers {
    fn new(socket_path: PathBuf, own_euid: u32) -> Self {
        Self {
            socket_path,
            own_euid,
            log: LogEvery::new(LOG_EVERY),
            last_signed: None,
            unsigned: 0,
        }
    }

    fn refuse(
        &mut self,
        refusal: &PeerRefusal,
        sock: std::os::unix::io::RawFd,
        audit_log: Option<&Arc<Mutex<AuditLog>>>,
    ) {
        use crate::self_integrity::{self, Finding};
        let now = Instant::now();
        let due = self.last_signed.is_none_or(|t| {
            now.duration_since(t) >= Duration::from_secs(self_integrity::REREPORT_SECS)
        });
        if due {
            let mut detail = self.describe(refusal, sock);
            if self.unsigned > 0 {
                detail.push_str(&format!(
                    " ({} more refusal(s) since the last record)",
                    self.unsigned
                ));
            }
            // The audit row's append and fsync, off the accept loop's worker.
            crate::runtime::off_the_runtime(|| {
                self_integrity::report_event(
                    audit_log,
                    &Finding {
                        kind: FOREIGN_PEER_KIND,
                        detail,
                    },
                )
            });
            self.last_signed = Some(now);
            self.unsigned = 0;
        } else {
            self.unsigned = self.unsigned.saturating_add(1);
            if let Some(suppressed) = self.log.ready() {
                error!(
                    kind = FOREIGN_PEER_KIND,
                    detail = %self.describe(refusal, sock),
                    suppressed,
                    "INTEGRITY DRIFT — admin connection refused again (signed with the next \
                     record, at most one per {} s)",
                    self_integrity::REREPORT_SECS
                );
            }
        }
    }

    fn describe(&self, refusal: &PeerRefusal, sock: std::os::unix::io::RawFd) -> String {
        let path = self.socket_path.display();
        let allowed = if self.own_euid == 0 {
            "uid 0".to_string()
        } else {
            format!("uid 0 and the agent's uid {}", self.own_euid)
        };
        match refusal {
            PeerRefusal::ForeignUid(cred) => {
                let who = peer_identity(sock, cred);
                format!(
                    "{path}: a connection from uid {} gid {} (pid {}, comm {:?} as the peer \
                     names itself, exe {}) was refused without a reply: only {allowed} may use \
                     the admin plane. The socket is created 0600 in a 0700 directory, so its \
                     mode, its owner or its directory was changed",
                    cred.uid,
                    cred.gid,
                    cred.pid,
                    who.comm,
                    who.exe.as_deref().unwrap_or("unknown"),
                )
            }
            PeerRefusal::Unreadable(errno) => format!(
                "{path}: a connection was refused without a reply: its peer's credentials \
                 could not be read (SO_PEERCRED: {})",
                std::io::Error::from_raw_os_error(*errno)
            ),
            PeerRefusal::ShortCred(len) => format!(
                "{path}: a connection was refused without a reply: SO_PEERCRED returned {len} \
                 of {} bytes",
                std::mem::size_of::<libc::ucred>()
            ),
        }
    }
}

async fn read_frame(stream: &mut UnixStream) -> Result<Option<AdminMessage>> {
    let mut header = [0u8; 4];
    match stream.read_exact(&mut header).await {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e).context("reading frame length header"),
    }
    let body_len = u32::from_be_bytes(header) as usize;
    if body_len > MAX_FRAME_BODY {
        anyhow::bail!("advertised frame body {body_len} > limit {MAX_FRAME_BODY}");
    }
    let mut body = vec![0u8; body_len];
    stream
        .read_exact(&mut body)
        .await
        .context("reading frame body")?;
    let mut full = Vec::with_capacity(4 + body_len);
    full.extend_from_slice(&header);
    full.extend_from_slice(&body);
    let (msg, _) = decode_frame(&full)
        .map_err(|e| anyhow::anyhow!("decode_frame: {e}"))?
        .ok_or_else(|| anyhow::anyhow!("decode_frame returned None on complete buffer"))?;
    Ok(Some(msg))
}

async fn write_frame(stream: &mut UnixStream, msg: &AdminMessage) -> Result<()> {
    let bytes = encode_frame(msg).map_err(|e| anyhow::anyhow!("encode_frame: {e}"))?;
    stream
        .write_all(&bytes)
        .await
        .context("writing frame to admin socket")?;
    Ok(())
}
