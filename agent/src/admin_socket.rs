//! Admin socket server (Tappa 7 task 7 / Tappa 8).
//!
//! Tokio-driven `UnixListener` that accepts connections from the
//! `nn-admin` client, dispatches [`AdminMessage`] variants, and
//! plumbs verified unlocks through to
//! [`PostureMachine::admin_release_combat_with_token`].
//!
//! Boot-time invariant: a stale socket file from a previous unclean
//! shutdown is unlinked before `bind`. Permissions are forced to
//! `0600` immediately after bind — clients run as root so we don't
//! need the `northnarrow` group carve-out V1.1 will eventually
//! introduce.
//!
//! Per-connection handler is one request/one reply, then the client
//! closes the stream. The `nn-admin unlock` flow performs a second
//! request on the same stream (challenge → unlock), so the handler
//! loops on EOF instead of close-after-first-reply.
//!
//! External audit NN-AUD-077: a transient `accept()` error (EMFILE,
//! ECONNABORTED, …) backs off and retries instead of ending the admin
//! plane; at most [`MAX_ADMIN_CONNECTIONS`] connections are served at
//! once, and a full table makes room by closing the connection that has
//! waited longest on its peer; a peer gets [`FRAME_READ_TIMEOUT`] to send
//! each request and [`FRAME_WRITE_TIMEOUT`] to take each reply. External
//! audit NN-AUD-078 / NN-AUD-079: the challenge and the failure count live
//! with the connection ([`ConnAuth`]).

use std::collections::HashMap;
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use parking_lot::Mutex;
use std::os::unix::fs::PermissionsExt;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use tracing::{info, warn};

use common::wire::admin_protocol::{
    decode_frame, encode_frame, AdminMessage, AdminResult, CanaryBurnRequest, CanaryDeployRequest,
    CanaryDeployResponse, CanaryListRequest, CanaryListResponse, CanaryRefreshRequest, Challenge,
    ConfigOverlaySetRequest, ConfigOverlaySetResponse, DetectionSetStatusRequest,
    DetectionSetStatusResponse, DetectionsRequest, DetectionsResponse, FimBaselineRequest,
    FimReportRequest, FimReportResponse, FimStatusRequest, FimStatusResponse, ForcePostureRequest,
    NetFingerprintRequest, NetFingerprintResponse, NetFlowsRequest, NetFlowsResponse,
    NetListenersRequest, NetListenersResponse, NetResolveRequest, NetResolveResponse,
    ResponseReleaseRequest, ResponseReleaseResponse, ResponseRestoreRequest,
    ResponseRestoreResponse, ResponseStatusRequest, ResponseStatusResponse, RotateKeysAddRequest,
    RotateKeysRevokeRequest, ShutdownRequest, StatusResponse, TrustedInstallerGrantRequest,
    UnlockResult, MAX_FRAME_BODY,
};
use common::wire::admin_signed_payload::{OperationCode, OperationExtra, Role};
use common::wire::{FS_PROTECT_MUTATE, FS_PROTECT_WRITE};
use ed25519_dalek::VerifyingKey;
use sha2::{Digest, Sha256};

use crate::anti_tamper::admin_auth::{AdminAuth, AdminAuthError, ConnAuth};
use crate::anti_tamper::network_isolate::NetworkIsolator;
use crate::anti_tamper::trusted_installer::TrustedInstallerOverride;
use crate::audit::{AuditEntryDraft, AuditLog};
use crate::canary::detector::CanaryIndexes;
use crate::canary::registry::{
    CanaryToken, CanaryTokenDraft, DecoyContent, Registry, RegistryError,
};
use crate::chainlog::RotatingChainLog;
use crate::detection_store::{Principal, StatusEvent};
use crate::fim::drain::DriftRateLimiter;
use crate::fim::recompute::{BaselineRecomputeSender, RecomputeReason};
use crate::posture::{AdminReleaseError, PostureMachine};
use crate::shutdown_marker::{self, ShutdownMarker, DEFAULT_MARKER_PATH};

use tokio::sync::Notify;

/// Cross-task signal that an admin-authorised shutdown has been
/// accepted by the dispatcher. Tappa 8 A8 wires this between the
/// admin-socket dispatcher (which writes the on-disk marker for
/// the watchdog AND fires this signal for the in-process main
/// loop) and `main.rs`'s tokio select loop (which awaits this
/// signal and breaks the loop on fire).
///
/// Holds an [`Arc<Notify>`] so a single-producer / single-consumer
/// fire-once pattern is natural: dispatcher calls [`Self::fire`]
/// after a successful marker write; main loop calls [`Self::wait`]
/// in its select. Re-firing the signal is a no-op once a waiter
/// has already observed it (the underlying [`Notify`] is one-shot
/// per `notified()` future).
///
/// Cloning is cheap (Arc bump) so production main.rs hands a
/// clone to [`serve_with_marker_path`] while keeping its own
/// clone for the select arm.
#[derive(Debug, Clone, Default)]
pub struct ShutdownSignal {
    inner: Arc<Notify>,
}

impl ShutdownSignal {
    /// Build a fresh signal. The Arc bump on [`Self::clone`] is
    /// the canonical way to share one signal between producer
    /// (dispatcher) and consumer (main loop).
    pub fn new() -> Self {
        Self::default()
    }

    /// Wake exactly one waiter on [`Self::wait`]. Safe to call
    /// before any waiter exists — `Notify::notify_one` is
    /// "permitted" semantics: the next `notified()` future
    /// returns immediately. Idempotent fires past the first are
    /// coalesced (we only fire once per shutdown anyway).
    pub fn fire(&self) {
        self.inner.notify_one();
    }

    /// Suspend until [`Self::fire`] has been (or already was)
    /// called. Used by main.rs's tokio select loop as a fourth
    /// arm alongside the three signal handlers.
    pub async fn wait(&self) {
        self.inner.notified().await;
    }
}

/// Tappa 9 C7 — FIM admin-socket state bundle. Threaded through
/// dispatch so two newly-wired ops can run:
///
/// - `FimBaselineRequest` triggers the in-process recompute
///   channel rather than just logging "scheduled for next restart"
///   (C6 deferral closure).
/// - `FimStatusRequest` reads the in-process snapshot
///   (token-bucket counts, paths-watched count, baseline +
///   drift chain lengths, last baseline ts) and returns it.
///
/// All fields are `Arc`-shared with main.rs's other tokio tasks
/// (the recompute task + the future drain loop). Construction
/// happens once at boot; the admin socket gets an `Arc<FimAdminState>`
/// it never mutates.
#[derive(Clone)]
pub struct FimAdminState {
    /// Recompute channel sender. `dispatch_fim_baseline` fires
    /// `RecomputeReason::AdminRequest` here on a successful
    /// quorum verify. The boot-time recompute task (see
    /// [`crate::fim::recompute::run_recompute_task`]) consumes
    /// the request and re-walks every watched path.
    pub recompute_sender: BaselineRecomputeSender,
    /// Token-bucket state for the §6.5 hierarchical rate-limiter.
    /// `dispatch_fim_status` snapshots the remaining counts +
    /// window-reset timer for operator visibility.
    pub rate_limiter: Arc<DriftRateLimiter>,
    /// Watched-paths summary captured at boot (after the
    /// `fim-paths.local` overlay merge). Cheap-to-clone counts
    /// for the status response.
    pub paths_summary: WatchedPathsSummary,
    /// Path to the on-disk baseline log. Status reads the file's
    /// row count + last `ts` for the snapshot. Empty (or non-
    /// existent) file means zero rows + empty ts.
    pub baseline_log_path: PathBuf,
    /// Path to the on-disk drift log. Same shape as
    /// `baseline_log_path` — read for the row count only.
    pub drift_log_path: PathBuf,
    /// External audit DEC-001: the drain's watch handles, shared with the
    /// canary subsystem.
    pub watch: crate::fim::attach::FimWatch,
}

/// `Copy`-able subset of [`crate::fim::paths_config::WatchedPathsLoad`]
/// — just the operator-visible counts that the status response
/// surfaces. Owning the counts here (rather than reading the
/// `BTreeSet`s every time) keeps the admin-socket path
/// allocation-free.
#[derive(Debug, Clone, Copy, Default)]
pub struct WatchedPathsSummary {
    pub watched_paths_count: u32,
    pub disabled_default_count: u32,
    pub added_path_count: u32,
}

impl WatchedPathsSummary {
    /// Build from a [`crate::fim::paths_config::WatchedPathsLoad`].
    pub fn from_load(load: &crate::fim::paths_config::WatchedPathsLoad) -> Self {
        Self {
            watched_paths_count: load.effective.len() as u32,
            disabled_default_count: load.disabled.len() as u32,
            added_path_count: load.added.len() as u32,
        }
    }
}

/// Tappa 9.5 K6 — canary admin-socket state bundle. Threaded
/// through dispatch so the 4 canary admin ops (deploy / list /
/// burn / refresh) can mutate the K2 registry + the K3
/// detector indexes from a single signed admin call.
///
/// All fields are `Arc`-shared with the K3 [`Detector`] that
/// main.rs hands into `process_event` — same handle, so an
/// admin `canary deploy` immediately becomes visible to the
/// detector's hot-path lookups on the next inbound
/// `Event::Fim` / `Event::ProcessSpawn`. The Indexes lock
/// width on rebuild is ~µs per deployed canary (operator
/// scale, ~10-50 deployments per host).
#[derive(Clone)]
pub struct CanaryAdminState {
    /// External audit DEC-001: the FIM's watch handles, to watch a decoy
    /// at deploy and stop at burn. `None` when FIM is not running.
    pub fim_watch: Option<crate::fim::attach::FimWatch>,
    /// K2 registry handle (shared with the K3 detector).
    /// dispatch_canary_deploy / burn / refresh take the
    /// write-lock; dispatch_canary_list takes the read-lock
    /// via `Registry::list()`.
    pub registry: Arc<Mutex<Registry>>,
    /// K3 hot-path indexes (shared with the K3 detector).
    /// Rebuilt by every successful deploy / burn / refresh so
    /// the detector's `is_canary_*` lookups see the new state
    /// immediately. Indexes rebuild reads the registry's live
    /// set + a stat-based inode_resolver (filled on
    /// File/Credential canaries; `None` returner for
    /// Process/Network).
    pub indexes: Arc<Mutex<CanaryIndexes>>,
    /// Path to the on-disk K2 registry log
    /// (`/var/lib/northnarrow/canaries.jsonl`). dispatch_canary_list
    /// reads the chain JSONL from here, returns it in the
    /// `CanaryListResponse::entries_jsonl` field with the
    /// truncation flag (same shape as `FimReportResponse`).
    pub registry_log_path: PathBuf,
    /// Operator-overrideable template directory for the K4
    /// cred-canary renderer. Defaults to
    /// `/etc/northnarrow/canary-templates/`; tests inject a
    /// tempdir for isolation. `None` means "built-in only" —
    /// the K4 renderer's `include_str!` defaults handle that
    /// case cleanly.
    pub template_dir: Option<PathBuf>,
}

/// Tappa 9.0.c — detection-triage admin-socket state bundle. Threaded
/// through dispatch so `DetectionSetStatus` can append a
/// [`StatusEvent`] to the status-event chain, and `Detections` can
/// overlay the current (event-sourced) status onto the records it
/// returns. main.rs constructs this at boot from the agent signing
/// key + the same anti-tamper protection handle the detection store
/// uses.
#[derive(Clone)]
pub struct DetectionAdminState {
    /// Open status-event chainlog (`status_events.jsonl`).
    /// `dispatch_detection_set_status` locks it and appends + fsyncs a
    /// single `StatusEvent` synchronously on the handler thread (triage
    /// is human-initiated + low-frequency, NOT the hot path — so no
    /// off-thread writer like the 9.0.a detection sink). `&mut` for
    /// `append`, hence the `Mutex`.
    pub status_log: Arc<Mutex<RotatingChainLog<StatusEvent>>>,
    /// Path to `detections.jsonl`. `dispatch_detection_set_status`
    /// reads its max id for the `id <= max` validity guard;
    /// `dispatch_detections` reads its records.
    pub detections_path: PathBuf,
    /// Path to `status_events.jsonl`. `dispatch_detections` builds the
    /// `{id -> current status}` overlay from here.
    pub status_events_path: PathBuf,
}

/// External audit CMB-016 — what the response verbs (`nn-admin response
/// status / release / restore`) need: the executor's configuration (the
/// containment record, the quarantine vault, the cgroup root) and a reader
/// of the COMBAT ladder's stage. main.rs builds it at boot; without it the
/// verbs answer `UnknownOperation`, as the canary verbs do without theirs.
#[derive(Clone)]
pub struct ResponseAdminState {
    pub config: crate::response::ExecutorConfig,
    /// The ladder's stage while a COMBAT episode is open, else `None`.
    pub combat_stage: Arc<dyn Fn() -> Option<String> + Send + Sync>,
}

/// External audit NN-AUD-082 — the files the read verbs serve, from the
/// agent's command line (`--fim-drift-file`, `--netflow-file`,
/// `--netflow-listeners-file`); `fim report` and `net flows` used to read
/// the built-in paths whatever the flags said. Always present, unlike
/// [`FimAdminState`] (absent when FIM is down). `Default` is the built-in
/// paths, for tests and the legacy serve entry points.
#[derive(Debug, Clone)]
pub struct AdminReadPaths {
    pub fim_drift: PathBuf,
    pub netflow: PathBuf,
    pub netflow_listeners: PathBuf,
}

impl Default for AdminReadPaths {
    fn default() -> Self {
        Self {
            fim_drift: PathBuf::from(crate::fim::drain::DEFAULT_DRIFT_LOG_PATH),
            netflow: PathBuf::from(DEFAULT_NETFLOW_JSONL_PATH),
            netflow_listeners: PathBuf::from(
                crate::net::drain::DEFAULT_NETFLOW_LISTENERS_JSONL_PATH,
            ),
        }
    }
}

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
) -> Result<()> {
    if socket_path.exists() {
        std::fs::remove_file(&socket_path)
            .with_context(|| format!("unlinking stale socket {}", socket_path.display()))?;
    }
    if let Some(parent) = socket_path.parent() {
        if !parent.as_os_str().is_empty() && !parent.exists() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("creating socket parent dir {}", parent.display()))?;
        }
    }
    let listener = UnixListener::bind(&socket_path)
        .with_context(|| format!("binding admin socket {}", socket_path.display()))?;
    // bind() honours umask; force 0600 explicitly so a slack umask
    // never widens the socket. root:root remains via ownership of
    // the bind() syscall (V1.1 will tighten to root:northnarrow 0660).
    std::fs::set_permissions(&socket_path, std::fs::Permissions::from_mode(0o600))
        .with_context(|| format!("chmod 0600 {}", socket_path.display()))?;
    info!(
        path = %socket_path.display(),
        "admin socket listening (mode 0600)"
    );

    // External audit NN-AUD-077: a bounded table of connections, and an
    // accept loop that outlives a transient error.
    let slots = ConnSlots::new(ConnLimits::DEFAULT);
    let mut accept_backoff = AcceptBackoff::default();
    let mut refused_log = LogEvery::new(LOG_EVERY);
    let mut evicted_log = LogEvery::new(LOG_EVERY);
    loop {
        let stream = match listener.accept().await {
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
        tokio::spawn(async move {
            if let Err(e) = handle_connection(
                stream,
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
            )
            .await
            {
                warn!(error = ?e, "admin connection handler errored");
            }
        });
    }
}

/// Helper for `main.rs` shutdown — best-effort unlink, no error on
/// missing file (the listener may already have been dropped).
pub fn unlink_socket(path: &Path) {
    if path.exists() {
        if let Err(e) = std::fs::remove_file(path) {
            warn!(error = ?e, path = %path.display(), "failed to unlink admin socket on shutdown");
        }
    }
}

/// External audit NN-AUD-077: connections served at once. nn-admin and
/// the watchdog open one at a time; 32 leaves room for a dashboard and
/// operators while bounding the fds and buffers the admin plane can take
/// from the agent (systemd's default soft limit is 1024).
const MAX_ADMIN_CONNECTIONS: usize = 32;

/// Time a peer gets to send each request. nn-admin and the watchdog send
/// at once (nn-admin's own timeout is 5 s); an interactive or hardware-token
/// signing flow would need a longer one.
const FRAME_READ_TIMEOUT: Duration = Duration::from_secs(10);

/// Time a peer gets to take each reply.
const FRAME_WRITE_TIMEOUT: Duration = Duration::from_secs(5);

/// How often a repeated accept or refusal warning is logged.
const LOG_EVERY: Duration = Duration::from_secs(10);

#[derive(Debug, Clone, Copy)]
struct ConnLimits {
    max_conns: usize,
    read_timeout: Duration,
    write_timeout: Duration,
}

impl ConnLimits {
    const DEFAULT: Self = Self {
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
struct ConnSlots {
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
    fn new(limits: ConnLimits) -> Arc<Self> {
        Arc::new(Self {
            limits,
            table: Mutex::new(SlotTable::default()),
        })
    }

    /// A slot for a new connection, closing the longest-waiting one when
    /// the table is full; `None` when every connection is mid-request.
    fn admit(self: &Arc<Self>) -> Option<ConnSlot> {
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
    fn live(&self) -> usize {
        self.table.lock().live.len()
    }
}

/// One connection's place in [`ConnSlots`]; leaving the table on drop.
struct ConnSlot {
    id: u64,
    slots: Arc<ConnSlots>,
    evict: Arc<Notify>,
    /// Another connection was closed to admit this one.
    made_room: bool,
}

impl ConnSlot {
    fn limits(&self) -> ConnLimits {
        self.slots.limits
    }

    /// From now on the connection waits on its peer — evictable. `false`
    /// when it was already evicted.
    fn waiting(&self) -> bool {
        self.set_waiting(Some(Instant::now()))
    }

    /// The connection serves a request — not evictable. `false` when it
    /// was already evicted.
    fn busy(&self) -> bool {
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
    async fn evicted(&self) {
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
fn accept_error_is_transient(e: &std::io::Error) -> bool {
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
async fn handle_connection(
    mut stream: UnixStream,
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
) -> Result<()> {
    // Capture peer creds once per connection — the audit log
    // wants pid/uid/comm of the caller, and a single connection
    // never changes peers mid-stream (SO_PEERCRED is fixed at
    // accept time).
    let client = peer_creds(&stream);
    let auth = ConnAuth::new(auth);
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
        let mut matched_fps: Vec<String> = Vec::new();
        let reply = dispatch(
            msg.clone(),
            &auth,
            posture,
            isolator,
            marker_path,
            shutdown_signal,
            fim_state.map(|s| s.as_ref()),
            canary_state.map(|s| s.as_ref()),
            installer_override.map(|s| s.as_ref()),
            detection_state.map(|s| s.as_ref()),
            response_state.map(|s| s.as_ref()),
            read_paths,
            &client,
            &mut matched_fps,
        );
        emit_audit_for(&msg, &reply, &client, audit_log, &matched_fps);
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
                client_comm = %client.comm,
                "admin connection closed after repeated signature failures"
            );
            return Ok(());
        }
    }
}

/// Read the current wall-clock as UNIX seconds for the
/// `verify_signed_payload_quorum` skew check. Production-only
/// helper; tests can call the verify path directly with an
/// injected `server_now_unix_secs` value.
fn now_unix_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

// ── Tappa 8 B5 — SO_PEERCRED + audit-log emission ─────────────────

/// Triple of `(pid, uid, comm)` captured from a Unix-socket peer
/// via `SO_PEERCRED` + `/proc/<pid>/comm`. The audit log's
/// per-entry `client_*` fields (design §9.1) come from here so
/// every admin operation records WHO connected, not just which
/// key signed.
#[derive(Debug, Clone)]
pub(crate) struct AuditClient {
    pub pid: u32,
    pub uid: u32,
    pub comm: String,
}

impl AuditClient {
    /// Pre-attach unknown sentinel for callers that haven't (or
    /// can't) capture peer creds — wire-test mock servers fall
    /// back here so the audit-emit path is exercised even
    /// without a real Unix socket.
    fn unknown() -> Self {
        Self {
            pid: 0,
            uid: 0,
            comm: "<unknown>".to_string(),
        }
    }
}

/// Read `SO_PEERCRED` from `stream` to recover the peer's PID +
/// UID, then read `/proc/<pid>/comm` for the executable name. All
/// three feed the audit log's `client_*` fields. Failure to read
/// any one is degrade-not-fail — the audit entry is still
/// written, just with `<unknown>` markers; an audit row with
/// missing client info is more useful than no audit row at all.
fn peer_creds(stream: &UnixStream) -> AuditClient {
    let fd = stream.as_raw_fd();
    // SAFETY: ucred is repr(C), getsockopt fills `pid`, `uid`,
    // `gid` if it succeeds. We pass `len` by &mut so the kernel
    // can tell us the actual returned length.
    let mut cred = libc::ucred {
        pid: 0,
        uid: 0,
        gid: 0,
    };
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
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
        return AuditClient::unknown();
    }
    let pid = cred.pid as u32;
    let uid = cred.uid;
    let comm = std::fs::read_to_string(format!("/proc/{pid}/comm"))
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "<unknown>".to_string());
    AuditClient { pid, uid, comm }
}

/// Inspect the (request, reply) pair after `dispatch` returns
/// and append a single audit-log entry if the message was an
/// auditable admin operation (challenge/status are not
/// auditable — they're plumbing). On any audit failure, log
/// plus continue: the operator's authorised action MUST succeed
/// even if the audit log is temporarily unwritable (design §9
/// states "the entry is the receipt; the action is the action").
// PHASE_D_004: `matched_fps` is the dispatch_* fns' `fps_out`
// values — empty for the legacy `Unlock` path (still goes
// through the non-payload verify) and for failure paths;
// populated for successful signed-payload ops.
fn emit_audit_for(
    msg: &AdminMessage,
    reply: &AdminMessage,
    client: &AuditClient,
    audit_log: Option<&Arc<Mutex<AuditLog>>>,
    matched_fps: &[String],
) {
    let Some(audit_log) = audit_log else {
        return;
    };
    let (op, extra, result, cosigner_count) = match (msg, reply) {
        (AdminMessage::Unlock(_), AdminMessage::UnlockResult(r)) => {
            ("unlock", serde_json::json!({}), unlock_result_str(r), 0)
        }
        (AdminMessage::ShutdownRequest(req), AdminMessage::ShutdownResult(r)) => {
            let grace = match &req.payload.extra {
                OperationExtra::Shutdown(s) => s.grace_secs,
                _ => 0,
            };
            (
                "shutdown",
                serde_json::json!({ "grace_secs": grace }),
                audit_result_str(*r),
                req.signatures.len().saturating_sub(1),
            )
        }
        (AdminMessage::ForcePostureRequest(req), AdminMessage::ForcePostureResult(r)) => {
            let target = match &req.payload.extra {
                OperationExtra::ForcePosture(f) => format!("{:?}", f.target),
                _ => "?".to_string(),
            };
            (
                "force_posture",
                serde_json::json!({ "target": target }),
                audit_result_str(*r),
                req.signatures.len().saturating_sub(1),
            )
        }
        (AdminMessage::RotateKeysAddRequest(req), AdminMessage::RotateKeysAddResult(r)) => {
            let new_fp = match &req.payload.extra {
                OperationExtra::RotateKeysAdd(extra) => {
                    hex::encode(&Sha256::digest(extra.new_pubkey)[..4])
                }
                _ => String::new(),
            };
            (
                "rotate_keys_add",
                serde_json::json!({ "new_key_fp": new_fp }),
                audit_result_str(*r),
                req.signatures.len().saturating_sub(1),
            )
        }
        (AdminMessage::RotateKeysRevokeRequest(req), AdminMessage::RotateKeysRevokeResult(r)) => {
            let target_fp = match &req.payload.extra {
                OperationExtra::RotateKeysRevoke(extra) => hex::encode(extra.fingerprint),
                _ => String::new(),
            };
            (
                "rotate_keys_revoke",
                serde_json::json!({ "target_fp": target_fp }),
                audit_result_str(*r),
                req.signatures.len().saturating_sub(1),
            )
        }
        // C6: FIM admin ops. Both are 1-of-N so cosigner_count
        // is 0 (saturating_sub on a 1-element signatures vec).
        (AdminMessage::FimBaselineRequest(req), AdminMessage::FimBaselineResult(r)) => (
            "fim_baseline",
            serde_json::json!({}),
            audit_result_str(*r),
            req.signatures.len().saturating_sub(1),
        ),
        (AdminMessage::FimReportRequest(req), AdminMessage::FimReportResponse(resp)) => {
            let since = match &req.payload.extra {
                OperationExtra::FimReport(extra) => extra.since_unix_ts,
                _ => None,
            };
            (
                "fim_report",
                serde_json::json!({
                    "since_unix_ts": since,
                    "entries_count": resp.entries_count,
                    "truncated": resp.entries_truncated,
                }),
                audit_result_str(resp.result),
                req.signatures.len().saturating_sub(1),
            )
        }
        // C7: fim_status. Extra captures the snapshot counts so an
        // off-host audit reader can answer "at the moment the
        // operator ran status, what did the agent report?" without
        // needing a parallel time-series collector.
        (AdminMessage::FimStatusRequest(req), AdminMessage::FimStatusResponse(resp)) => (
            "fim_status",
            serde_json::json!({
                "watched_paths_count": resp.watched_paths_count,
                "disabled_default_count": resp.disabled_default_count,
                "added_path_count": resp.added_path_count,
                "baseline_entries_total": resp.baseline_entries_total,
                "drift_entries_total": resp.drift_entries_total,
            }),
            audit_result_str(resp.result),
            req.signatures.len().saturating_sub(1),
        ),
        // K6: 4 canary admin ops. Each row carries the canary_id
        // for the chain (deploy populates it from the response;
        // burn/refresh from the request's extra). Operator
        // `nn-admin audit read` greps by canary_id for the
        // lifecycle trail across the audit chain + the K2
        // registry chain.
        (AdminMessage::CanaryDeployRequest(req), AdminMessage::CanaryDeployResponse(resp)) => {
            let (name, family) = match &req.payload.extra {
                OperationExtra::CanaryDeploy(e) => {
                    let family = match &e.deployment {
                        common::wire::admin_signed_payload::CanaryDeploymentWire::Credential {
                            cred_family,
                            ..
                        } => cred_family.clone(),
                        _ => String::new(),
                    };
                    (e.name.clone(), family)
                }
                _ => (String::new(), String::new()),
            };
            (
                "canary_deploy",
                serde_json::json!({
                    "name": name,
                    "canary_id": resp.canary_id,
                    "cred_family": family,
                }),
                audit_result_str(resp.result),
                req.signatures.len().saturating_sub(1),
            )
        }
        (AdminMessage::CanaryListRequest(req), AdminMessage::CanaryListResponse(resp)) => (
            "canary_list",
            serde_json::json!({
                "entries_count": resp.entries_count,
                "truncated": resp.entries_truncated,
            }),
            audit_result_str(resp.result),
            req.signatures.len().saturating_sub(1),
        ),
        (AdminMessage::CanaryBurnRequest(req), AdminMessage::CanaryBurnResult(r)) => {
            let canary_id = match &req.payload.extra {
                OperationExtra::CanaryBurn(e) => e.canary_id.clone(),
                _ => String::new(),
            };
            (
                "canary_burn",
                serde_json::json!({ "canary_id": canary_id }),
                audit_result_str(*r),
                req.signatures.len().saturating_sub(1),
            )
        }
        (AdminMessage::CanaryRefreshRequest(req), AdminMessage::CanaryRefreshResult(r)) => {
            let canary_id = match &req.payload.extra {
                OperationExtra::CanaryRefresh(e) => e.canary_id.clone(),
                _ => String::new(),
            };
            (
                "canary_refresh",
                serde_json::json!({ "canary_id": canary_id }),
                audit_result_str(*r),
                req.signatures.len().saturating_sub(1),
            )
        }
        // N7: 4 net admin ops. Each row carries the response
        // counters / qname slot so an off-host audit reader sees
        // the same "what did the operator just learn?" detail
        // that fim_report + fim_status capture for their domain.
        (AdminMessage::NetFlowsRequest(req), AdminMessage::NetFlowsResponse(resp)) => {
            use common::wire::admin_signed_payload::NetFlowsExtra;
            let since = match &req.payload.extra {
                OperationExtra::NetFlows(NetFlowsExtra { since_unix_ts }) => *since_unix_ts,
                _ => None,
            };
            (
                "net_flows",
                serde_json::json!({
                    "since_unix_ts": since,
                    "entries_count": resp.entries_count,
                    "truncated": resp.entries_truncated,
                }),
                audit_result_str(resp.result),
                req.signatures.len().saturating_sub(1),
            )
        }
        (AdminMessage::NetListenersRequest(req), AdminMessage::NetListenersResponse(resp)) => (
            "net_listeners",
            serde_json::json!({
                "entries_count": resp.entries_count,
                "truncated": resp.entries_truncated,
            }),
            audit_result_str(resp.result),
            req.signatures.len().saturating_sub(1),
        ),
        (AdminMessage::NetResolveRequest(req), AdminMessage::NetResolveResponse(resp)) => {
            use common::wire::admin_signed_payload::NetResolveExtra;
            let ip = match &req.payload.extra {
                OperationExtra::NetResolve(NetResolveExtra { ip }) => ip.clone(),
                _ => String::new(),
            };
            (
                "net_resolve",
                serde_json::json!({
                    "ip": ip,
                    "resolved": resp.qname.is_some(),
                }),
                audit_result_str(resp.result),
                req.signatures.len().saturating_sub(1),
            )
        }
        (AdminMessage::NetFingerprintRequest(req), AdminMessage::NetFingerprintResponse(resp)) => {
            use common::wire::admin_signed_payload::NetFingerprintExtra;
            let flow_id = match &req.payload.extra {
                OperationExtra::NetFingerprint(NetFingerprintExtra { flow_id }) => flow_id.clone(),
                _ => String::new(),
            };
            (
                "net_fingerprint",
                serde_json::json!({
                    "flow_id": flow_id,
                    "entries_count": resp.entries_count,
                    "truncated": resp.entries_truncated,
                }),
                audit_result_str(resp.result),
                req.signatures.len().saturating_sub(1),
            )
        }
        // FIM-009 self-upgrade (§15.1) — the trusted-installer grant
        // ARM record (the close/expiry record is written by the
        // override itself, not on an admin op).
        (
            AdminMessage::TrustedInstallerGrantRequest(req),
            AdminMessage::TrustedInstallerGrantResult(r),
        ) => {
            let window = match &req.payload.extra {
                OperationExtra::TrustedInstallerGrant(e) => e.window_secs,
                _ => 0,
            };
            (
                "trusted_installer_grant",
                serde_json::json!({ "window_secs": window }),
                audit_result_str(*r),
                req.signatures.len().saturating_sub(1),
            )
        }
        // Tappa 10.8 — signed overlay store. `result` is `success` only when
        // the overlay and its signature were written: the boot check reads
        // these rows as the newest accepted signature per kind (rollback
        // guard), so a verified-but-refused request must not count.
        (AdminMessage::ConfigOverlaySetRequest(req), AdminMessage::ConfigOverlaySetResponse(r)) => {
            let (kind, sha, len) = match &req.payload.extra {
                OperationExtra::ConfigOverlaySet(e) => (
                    e.kind.keyword(),
                    e.sha256
                        .iter()
                        .map(|b| format!("{b:02x}"))
                        .collect::<String>(),
                    e.len,
                ),
                _ => ("unknown", String::new(), 0),
            };
            let result = if r.stored {
                "success".to_string()
            } else if r.result == AdminResult::Success {
                format!("failure: rejected ({})", r.message)
            } else {
                audit_result_str(r.result)
            };
            (
                crate::config::overlay_auth::AUDIT_OP_SET,
                serde_json::json!({
                    "kind": kind,
                    "sha256": sha,
                    "signed_ts": req.payload.ts,
                    "bytes": len,
                    "detail": r.message,
                }),
                result,
                req.signatures.len().saturating_sub(1),
            )
        }
        // Tappa 9.0.b — detections read. The extra captures the
        // operator's filters + the response counters so an off-host
        // audit reader sees exactly what was asked for and how much
        // was returned (mirrors the fim_report / net_flows rows).
        (AdminMessage::DetectionsRequest(req), AdminMessage::DetectionsResponse(resp)) => {
            let extra = match &req.payload.extra {
                OperationExtra::Detections(e) => serde_json::json!({
                    "limit": e.limit,
                    "since_unix_ts": e.since_unix_ts,
                    "until_unix_ts": e.until_unix_ts,
                    "min_severity": e.min_severity,
                    "status": e.status,
                    "sensor": e.sensor,
                    "path": e.path,
                    "entries_count": resp.entries_count,
                    "truncated": resp.entries_truncated,
                }),
                _ => serde_json::json!({}),
            };
            (
                "detections",
                extra,
                audit_result_str(resp.result),
                req.signatures.len().saturating_sub(1),
            )
        }
        // Tappa 9.0.c — detection triage status change. Records the
        // target id + new status + note + the auth result so an
        // off-host audit reader sees the full triage history (the
        // status-event chain is the data-of-record; this is the
        // who/when receipt alongside it).
        (
            AdminMessage::DetectionSetStatusRequest(req),
            AdminMessage::DetectionSetStatusResponse(resp),
        ) => {
            let extra = match &req.payload.extra {
                OperationExtra::DetectionSetStatus(e) => serde_json::json!({
                    "id": e.id,
                    "new_status": e.new_status,
                    "note": e.note,
                }),
                _ => serde_json::json!({}),
            };
            (
                "detection_set_status",
                extra,
                audit_result_str(resp.result),
                req.signatures.len().saturating_sub(1),
            )
        }
        // External audit CMB-016 — undoing a response. A verified request
        // that did nothing (no record of the pid, a refused destination)
        // is recorded with why, not as a success.
        (AdminMessage::ResponseStatusRequest(req), AdminMessage::ResponseStatusResponse(r)) => (
            "response_status",
            serde_json::json!({
                "contained_total": r.contained_total,
                "quarantined_total": r.quarantined_total,
                "combat_stage": r.combat_stage,
            }),
            audit_result_str(r.result),
            req.signatures.len().saturating_sub(1),
        ),
        (AdminMessage::ResponseReleaseRequest(req), AdminMessage::ResponseReleaseResponse(r)) => {
            let pid = match &req.payload.extra {
                OperationExtra::ResponseRelease(e) => Some(e.pid),
                _ => None,
            };
            (
                "response_release",
                serde_json::json!({ "pid": pid, "by": "admin", "detail": r.message }),
                verified_result_str(r.result, r.released, &r.message),
                req.signatures.len().saturating_sub(1),
            )
        }
        (AdminMessage::ResponseRestoreRequest(req), AdminMessage::ResponseRestoreResponse(r)) => {
            let (vault_id, to) = match &req.payload.extra {
                OperationExtra::ResponseRestore(e) => (e.vault_id.clone(), e.to.clone()),
                _ => (String::new(), None),
            };
            (
                "response_restore",
                serde_json::json!({
                    "vault_id": vault_id,
                    "to": to,
                    "path": r.path,
                    "detail": r.message,
                }),
                verified_result_str(r.result, r.restored, &r.message),
                req.signatures.len().saturating_sub(1),
            )
        }
        // Non-auditable: ChallengeRequest, Status, the debug
        // path. Server-only reply variants reaching dispatch are
        // out-of-spec and already logged; no audit row.
        _ => return,
    };
    // PHASE_D_004: split matched_fps into primary + cosigners.
    // matched_fps is in admin.pub index-order — the first slot
    // is the canonical "key_fp" (primary signer), the rest are
    // cosigners. Empty matched_fps (legacy Unlock path / failure
    // paths) falls back to empty strings — the same shape B5
    // shipped, so audit-verify of an existing chain still parses.
    let (key_fp, cosigner_fps): (String, Vec<String>) = if matched_fps.is_empty() {
        (String::new(), vec![String::new(); cosigner_count])
    } else {
        let mut iter = matched_fps.iter().cloned();
        let primary = iter.next().unwrap_or_default();
        (primary, iter.collect())
    };
    let draft = AuditEntryDraft {
        op: op.to_string(),
        extra,
        key_fp,
        cosigner_fps,
        result,
        client_pid: client.pid,
        client_uid: client.uid,
        client_comm: client.comm.clone(),
    };
    let mut log = audit_log.lock();
    if let Err(e) = log.append(draft) {
        warn!(
            error = %e,
            op,
            "audit log append failed — admin op succeeded, audit row missing"
        );
    }
}

/// Map a legacy [`UnlockResult`] (predates the Tappa 8 A7
/// `AdminResult` superset) to the same `"success"` /
/// `"failure: <reason>"` shape audit entries use.
fn unlock_result_str(r: &UnlockResult) -> String {
    match r {
        UnlockResult::Success => "success".to_string(),
        UnlockResult::InvalidSignature => "failure: invalid_signature".to_string(),
        UnlockResult::NoPendingChallenge => "failure: no_pending_challenge".to_string(),
        UnlockResult::RateLimited { retry_after_secs } => {
            format!("failure: rate_limited (retry_after_secs={retry_after_secs})")
        }
    }
}

/// The audit `result` of a verb that can be verified and still do nothing:
/// `success` only when it was done.
fn verified_result_str(r: AdminResult, done: bool, message: &str) -> String {
    if done {
        "success".to_string()
    } else if r == AdminResult::Success {
        format!("failure: rejected ({message})")
    } else {
        audit_result_str(r)
    }
}

/// Map an [`AdminResult`] to the audit-log `result` field shape
/// from design §9.1: `"success"` or `"failure: <reason>"`.
fn audit_result_str(r: AdminResult) -> String {
    match r {
        AdminResult::Success => "success".to_string(),
        AdminResult::InvalidSignature => "failure: invalid_signature".to_string(),
        AdminResult::NoPendingChallenge => "failure: no_pending_challenge".to_string(),
        AdminResult::RateLimited { retry_after_secs } => {
            format!("failure: rate_limited (retry_after_secs={retry_after_secs})")
        }
        AdminResult::QuorumNotMet { required, provided } => {
            format!("failure: quorum_not_met (required={required}, provided={provided})")
        }
        AdminResult::RoleDenied => "failure: role_denied".to_string(),
        AdminResult::TimestampSkew {
            server_ts,
            max_skew_secs,
        } => format!(
            "failure: timestamp_skew (server_ts={server_ts}, max_skew_secs={max_skew_secs})"
        ),
        AdminResult::AgentIdMismatch => "failure: agent_id_mismatch".to_string(),
        AdminResult::UnknownOperation => "failure: unknown_operation".to_string(),
        AdminResult::ProtocolVersionUnsupported { server_version } => {
            format!("failure: protocol_version_unsupported (server_version={server_version})")
        }
    }
}

/// Synchronous request→reply mapping. All AdminAuth + PostureMachine
/// methods are sync; we don't `await` between read and write inside
/// `handle_connection`, so the dispatch itself can stay sync.
#[allow(clippy::too_many_arguments)]
fn dispatch(
    msg: AdminMessage,
    auth: &ConnAuth<'_>,
    posture: &PostureMachine,
    isolator: &NetworkIsolator,
    marker_path: &Path,
    shutdown_signal: Option<&ShutdownSignal>,
    fim_state: Option<&FimAdminState>,
    canary_state: Option<&CanaryAdminState>,
    installer_override: Option<&TrustedInstallerOverride>,
    detection_state: Option<&DetectionAdminState>,
    response_state: Option<&ResponseAdminState>,
    read_paths: &AdminReadPaths,
    client: &AuditClient,
    fps_out: &mut Vec<String>,
) -> AdminMessage {
    match msg {
        AdminMessage::ChallengeRequest(_) => match auth.issue_challenge() {
            Ok(nonce) => AdminMessage::Challenge(Challenge { nonce }),
            // Rate-limited at the challenge-issuance gate. The
            // protocol reuses `UnlockResult::RateLimited` here
            // because the wire surface has no dedicated
            // ChallengeResponse error variant; clients treat any
            // `RateLimited` reply as "back off and retry later"
            // regardless of which request prompted it.
            Err(AdminAuthError::RateLimited { retry_after_secs }) => {
                AdminMessage::UnlockResult(UnlockResult::RateLimited { retry_after_secs })
            }
            // No-pending / invalid-sig don't apply to challenge
            // issuance, but the typed error enum requires all arms.
            Err(other) => {
                warn!(error = ?other, "unexpected error path during issue_challenge");
                AdminMessage::UnlockResult(UnlockResult::InvalidSignature)
            }
        },

        AdminMessage::Unlock(req) => {
            let result = match auth.verify_unlock(&req.signature) {
                Ok(token) => match posture.admin_release_combat_with_token(token) {
                    Ok(_) => UnlockResult::Success,
                    // Admin unlock when not in Combat is idempotent
                    // success from the operator's perspective —
                    // there's nothing to release. AdminAuth has
                    // already cleared its failure counter on the
                    // successful verify, so this also gives a clean
                    // path to clear rate-limit state if the operator
                    // got locked out during a non-Combat scare.
                    Err(AdminReleaseError::NotInCombat) => UnlockResult::Success,
                    Err(other) => {
                        warn!(error = ?other, "admin_release_combat_with_token errored unexpectedly");
                        UnlockResult::Success
                    }
                },
                Err(AdminAuthError::InvalidSignature) => UnlockResult::InvalidSignature,
                Err(AdminAuthError::NoPendingChallenge) => UnlockResult::NoPendingChallenge,
                Err(AdminAuthError::RateLimited { retry_after_secs }) => {
                    UnlockResult::RateLimited { retry_after_secs }
                }
                // Tappa 8 A5 introduces RoleDenied; the wire layer
                // currently has no dedicated variant for it
                // (UnlockResult predates A5). A7 lands the new
                // AdminResult enum with a real RoleDenied wire
                // variant; until then, surface as InvalidSignature
                // — the operator-facing detail is in the agent's
                // own journald `anti_tamper.admin_auth.verify_failure`
                // line (reason="role_denied", key_fingerprint, …).
                // For an `unlock` request specifically, RoleDenied
                // is also vanishingly rare: every legacy admin.pub
                // line gets `Role::Unlock` in its default allowlist,
                // so this arm only fires when an operator has
                // deliberately written a line without `unlock`.
                Err(AdminAuthError::RoleDenied { .. }) => UnlockResult::InvalidSignature,
                // Tappa 8 A6 introduces QuorumNotMet. The legacy
                // Unlock wire path is strictly 1-of-N (verify_unlock
                // delegates to verify_with_role, not verify_quorum)
                // so this arm is exhaustiveness-only — it can
                // never fire from `Unlock` dispatch in practice.
                // Mapped to InvalidSignature on the wire for the
                // same reason as RoleDenied: UnlockResult predates
                // A6, and A7's AdminResult will carry the proper
                // QuorumNotMet { required, provided } variant.
                Err(AdminAuthError::QuorumNotMet { .. }) => UnlockResult::InvalidSignature,
                // Tappa 8 A7 introduces additional AdminAuthError
                // variants used exclusively by
                // `verify_signed_payload_quorum` (the SignedPayload
                // path consumed by `ShutdownRequest`, not by
                // legacy `Unlock`). These arms are exhaustiveness-
                // only — the legacy `verify_unlock` →
                // `verify_with_role` path can never produce them.
                // Mapped to `UnlockResult::InvalidSignature`
                // because the legacy wire surface has no
                // dedicated variant; A7's `AdminResult` (consumed
                // by `ShutdownRequest`) is the proper home for the
                // distinct semantics.
                Err(AdminAuthError::TimestampSkew { .. })
                | Err(AdminAuthError::AgentIdMismatch)
                | Err(AdminAuthError::NonceMismatch)
                | Err(AdminAuthError::UnknownOperation { .. })
                | Err(AdminAuthError::PayloadVerify(_)) => UnlockResult::InvalidSignature,
            };
            AdminMessage::UnlockResult(result)
        }

        AdminMessage::Status(_) => AdminMessage::StatusResponse(StatusResponse {
            posture: posture.current_kind(),
            network_isolation_engaged: isolator.is_engaged(),
            last_admin_action_secs_ago: posture.last_admin_action_secs_ago(),
            ringbuf_drops_total: Some(crate::sensors::ring_drops::total()),
            ringbuf_drops: Some(crate::sensors::ring_drops::snapshot_nonzero()),
            // External audit CMB-016: where the COMBAT ladder stands.
            combat_stage: response_state.and_then(|s| (s.combat_stage)()),
            combat_locked: Some(posture.is_combat_locked()),
            // External audit SNS-008: malformed records the pumps rejected.
            ringbuf_rejected_total: Some(crate::sensors::reject::total()),
            ringbuf_rejected: Some(crate::sensors::reject::snapshot()),
            // External audit NET-019 / NET-012 / NET-009: `nn-admin net status`.
            netflow_rows_skipped_total: Some(crate::net::limiter::rows_skipped_total()),
            netflow_pending_evicted_total: Some(crate::net::flow_tracker::pending_evictions_total()),
            net_inactive_rules: Some(crate::net::blocklist::inactive_net_rules()),
            // Lab PR 164: the kernel's connect→close socket map.
            flow_sock_pending: crate::sensors::flow_sock::snapshot().map(|o| o.pending),
            flow_sock_capacity: crate::sensors::flow_sock::snapshot().map(|o| o.capacity),
            flow_sock_forgotten_min: crate::sensors::flow_sock::snapshot().map(|o| o.forgotten_min),
        }),

        AdminMessage::ShutdownRequest(req) => AdminMessage::ShutdownResult(dispatch_shutdown(
            req,
            auth,
            marker_path,
            shutdown_signal,
            fps_out,
        )),

        AdminMessage::ForcePostureRequest(req) => {
            AdminMessage::ForcePostureResult(dispatch_force_posture(req, auth, posture, fps_out))
        }

        AdminMessage::RotateKeysAddRequest(req) => {
            AdminMessage::RotateKeysAddResult(dispatch_rotate_keys_add(req, auth, fps_out))
        }

        AdminMessage::RotateKeysRevokeRequest(req) => {
            AdminMessage::RotateKeysRevokeResult(dispatch_rotate_keys_revoke(req, auth, fps_out))
        }

        AdminMessage::FimBaselineRequest(req) => {
            AdminMessage::FimBaselineResult(dispatch_fim_baseline(req, auth, fim_state, fps_out))
        }

        AdminMessage::FimReportRequest(req) => {
            AdminMessage::FimReportResponse(dispatch_fim_report(req, auth, read_paths, fps_out))
        }

        AdminMessage::FimStatusRequest(req) => {
            AdminMessage::FimStatusResponse(dispatch_fim_status(req, auth, fim_state, fps_out))
        }

        AdminMessage::CanaryDeployRequest(req) => AdminMessage::CanaryDeployResponse(
            dispatch_canary_deploy(req, auth, canary_state, fps_out),
        ),

        AdminMessage::CanaryListRequest(req) => {
            AdminMessage::CanaryListResponse(dispatch_canary_list(req, auth, canary_state, fps_out))
        }

        AdminMessage::CanaryBurnRequest(req) => {
            AdminMessage::CanaryBurnResult(dispatch_canary_burn(req, auth, canary_state, fps_out))
        }

        AdminMessage::CanaryRefreshRequest(req) => AdminMessage::CanaryRefreshResult(
            dispatch_canary_refresh(req, auth, canary_state, fps_out),
        ),

        // Tappa 10 N7 — net admin ops.
        AdminMessage::NetFlowsRequest(req) => {
            AdminMessage::NetFlowsResponse(dispatch_net_flows(req, auth, read_paths, fps_out))
        }
        AdminMessage::NetListenersRequest(req) => AdminMessage::NetListenersResponse(
            dispatch_net_listeners(req, auth, read_paths, fps_out),
        ),
        AdminMessage::NetResolveRequest(req) => {
            AdminMessage::NetResolveResponse(dispatch_net_resolve(req, auth, read_paths, fps_out))
        }
        AdminMessage::NetFingerprintRequest(req) => AdminMessage::NetFingerprintResponse(
            dispatch_net_fingerprint(req, auth, read_paths, fps_out),
        ),

        // FIM-009 self-upgrade (§15.1) — signed trusted-installer grant.
        AdminMessage::TrustedInstallerGrantRequest(req) => {
            AdminMessage::TrustedInstallerGrantResult(dispatch_trusted_installer_grant(
                req,
                auth,
                installer_override,
                fps_out,
            ))
        }
        AdminMessage::ConfigOverlaySetRequest(req) => {
            AdminMessage::ConfigOverlaySetResponse(dispatch_config_overlay_set(req, auth, fps_out))
        }

        // Tappa 9.0.b — signed detections read (read-only,
        // Role::TelemetryRead, or Triage via subsumption). Overlays the
        // event-sourced current status from the status-event chain
        // (9.0.c) onto the returned records.
        AdminMessage::DetectionsRequest(req) => AdminMessage::DetectionsResponse(
            dispatch_detections(req, auth, detection_state, fps_out),
        ),

        // Tappa 9.0.c — signed detection triage status-change
        // (Role::Triage). Appends a StatusEvent to the status-event
        // chain; detections.jsonl is never mutated.
        AdminMessage::DetectionSetStatusRequest(req) => AdminMessage::DetectionSetStatusResponse(
            dispatch_detection_set_status(req, auth, detection_state, client, fps_out),
        ),

        // External audit CMB-016 — undoing a response.
        AdminMessage::ResponseStatusRequest(req) => AdminMessage::ResponseStatusResponse(
            dispatch_response_status(req, auth, posture, response_state, fps_out),
        ),
        AdminMessage::ResponseReleaseRequest(req) => AdminMessage::ResponseReleaseResponse(
            dispatch_response_release(req, auth, response_state, fps_out),
        ),
        AdminMessage::ResponseRestoreRequest(req) => AdminMessage::ResponseRestoreResponse(
            dispatch_response_restore(req, auth, response_state, fps_out),
        ),

        // Server-only variants — clients sending these are speaking
        // out-of-spec. Reply with a benign sentinel; the connection
        // closes naturally on the next read EOF.
        AdminMessage::Challenge(_)
        | AdminMessage::UnlockResult(_)
        | AdminMessage::StatusResponse(_)
        | AdminMessage::ShutdownResult(_)
        | AdminMessage::ForcePostureResult(_)
        | AdminMessage::RotateKeysAddResult(_)
        | AdminMessage::RotateKeysRevokeResult(_)
        | AdminMessage::FimBaselineResult(_)
        | AdminMessage::FimReportResponse(_)
        | AdminMessage::FimStatusResponse(_)
        | AdminMessage::CanaryDeployResponse(_)
        | AdminMessage::CanaryListResponse(_)
        | AdminMessage::CanaryBurnResult(_)
        | AdminMessage::CanaryRefreshResult(_)
        | AdminMessage::NetFlowsResponse(_)
        | AdminMessage::NetListenersResponse(_)
        | AdminMessage::NetResolveResponse(_)
        | AdminMessage::NetFingerprintResponse(_)
        | AdminMessage::TrustedInstallerGrantResult(_)
        | AdminMessage::DetectionsResponse(_)
        | AdminMessage::DetectionSetStatusResponse(_)
        | AdminMessage::ConfigOverlaySetResponse(_)
        | AdminMessage::ResponseStatusResponse(_)
        | AdminMessage::ResponseReleaseResponse(_)
        | AdminMessage::ResponseRestoreResponse(_) => {
            warn!("client sent server-only message variant; ignoring");
            AdminMessage::UnlockResult(UnlockResult::NoPendingChallenge)
        }

        #[cfg(feature = "debug-trigger")]
        AdminMessage::DebugForcePosture(state) => {
            let target = match state {
                common::wire::admin_protocol::DebugForcePosture::Observing => {
                    common::posture_types::PostureKind::Observing
                }
                common::wire::admin_protocol::DebugForcePosture::Alerted => {
                    common::posture_types::PostureKind::Alerted
                }
                common::wire::admin_protocol::DebugForcePosture::Engaged => {
                    common::posture_types::PostureKind::Engaged
                }
                common::wire::admin_protocol::DebugForcePosture::Combat => {
                    common::posture_types::PostureKind::Combat
                }
            };
            posture.force_state_for_test(target);
            AdminMessage::DebugForcePostureAck
        }

        #[cfg(feature = "debug-trigger")]
        AdminMessage::DebugForcePostureAck => {
            warn!("client sent DebugForcePostureAck; ignoring");
            AdminMessage::UnlockResult(UnlockResult::NoPendingChallenge)
        }
    }
}

/// Handle one [`ShutdownRequest`] (Tappa 8 A7, design §10.3).
/// On verify success, atomically write the shutdown-authorisation
/// marker (so the watchdog will stand down when it observes the
/// agent's pidfd POLLIN — design §10.4) and return
/// [`AdminResult::Success`]. On verify failure, surface the
/// corresponding [`AdminResult`] variant; the marker is NOT
/// written, so the watchdog will respawn the agent normally if
/// the dispatcher later exits for any reason.
///
/// Note: this commit (A7) intentionally does NOT trigger the
/// agent's graceful exit. The dispatcher writes the marker and
/// replies; the actual `std::process::exit(0)` is part of A8's
/// integration story (which wires a shutdown channel from the
/// dispatcher → main.rs → the agent's tokio runtime). For now,
/// the cross-component contract is "marker on disk = the agent
/// authorised this exit"; production E2E will be exercised once
/// A8 lands the main-loop integration.
// PHASE_D_004: `fps_out` is an out-parameter populated on the
// success path with the 8-hex-char fingerprints of every
// matched signer. dispatch() reads this for emit_audit_for
// so the audit chain records WHICH operators authorised each
// signed action.
fn dispatch_shutdown(
    req: ShutdownRequest,
    auth: &ConnAuth<'_>,
    marker_path: &Path,
    shutdown_signal: Option<&ShutdownSignal>,
    fps_out: &mut Vec<String>,
) -> AdminResult {
    // Per §10.3 step 1: quorum verify (2-of-N including ≥1
    // Role::Shutdown). The integrated verify path
    // (verify_signed_payload_quorum) chains nonce-binding +
    // op-tag check + agent_id check + ±60s skew check + per-sig
    // verify_strict + distinct-key tally + role check, returning
    // the precise error so we can map to the wire variant.
    let server_now = now_unix_secs();
    let sigs: Vec<[u8; 64]> = req.signatures.iter().map(|s| s.signature).collect();

    let verify_outcome = auth.verify_signed_payload_quorum(
        &req.payload,
        &sigs,
        2,
        &[Role::Shutdown],
        OperationCode::Shutdown,
        server_now,
    );

    let (_token, matched_fps) = match verify_outcome {
        Ok(t) => t,
        Err(AdminAuthError::NoPendingChallenge) => return AdminResult::NoPendingChallenge,
        Err(AdminAuthError::NonceMismatch) => return AdminResult::InvalidSignature,
        Err(AdminAuthError::UnknownOperation { .. }) => return AdminResult::UnknownOperation,
        Err(AdminAuthError::AgentIdMismatch) => return AdminResult::AgentIdMismatch,
        Err(AdminAuthError::TimestampSkew {
            server_ts,
            max_skew_secs,
        }) => {
            return AdminResult::TimestampSkew {
                server_ts,
                max_skew_secs,
            };
        }
        Err(AdminAuthError::InvalidSignature) => return AdminResult::InvalidSignature,
        Err(AdminAuthError::QuorumNotMet { required, provided }) => {
            return AdminResult::QuorumNotMet { required, provided };
        }
        Err(AdminAuthError::RoleDenied { .. }) => return AdminResult::RoleDenied,
        Err(AdminAuthError::RateLimited { retry_after_secs }) => {
            return AdminResult::RateLimited { retry_after_secs };
        }
        Err(AdminAuthError::PayloadVerify(e)) => {
            warn!(error = ?e, "shutdown payload verify failed at common layer");
            return AdminResult::InvalidSignature;
        }
    };
    *fps_out = matched_fps;

    // Per §10.3 step 2: the marker carries what the admins signed and
    // this agent's pid, so the watchdog can verify it against admin.pub
    // as we just did (external audit WDG-001) — a marker it cannot
    // verify makes it respawn us.
    let grace_secs = match &req.payload.extra {
        common::wire::admin_signed_payload::OperationExtra::Shutdown(s) => s.grace_secs,
        // Other extras can't reach here — verify_signed_payload_quorum
        // already enforced expected_op = Shutdown, which implies the
        // extra variant via SignedPayload's op/extra invariant.
        // Belt-and-suspenders default keeps the match exhaustive.
        _ => 30,
    };
    let grace_deadline_unix_ts = server_now.saturating_add(u64::from(grace_secs));
    let marker = match ShutdownMarker::new(&req.payload, &sigs, std::process::id()) {
        Ok(m) => m,
        Err(e) => {
            warn!(error = ?e, "encoding the shutdown marker failed");
            return AdminResult::InvalidSignature;
        }
    };

    // Per §10.3 step 2 (atomic write): tmpfile + fsync + rename.
    if let Err(e) = shutdown_marker::write_marker(marker_path, &marker) {
        warn!(
            error = ?e,
            marker_path = %marker_path.display(),
            "failed to write shutdown-authorisation marker — refusing to ack"
        );
        // Refuse to ack the operator — without the marker, the
        // watchdog won't stand down and we'd just respawn after
        // exit. Surface as InvalidSignature so the client retries.
        return AdminResult::InvalidSignature;
    }

    info!(
        target: "admin.shutdown",
        grace_secs,
        grace_deadline_unix_ts,
        marker_path = %marker_path.display(),
        "shutdown authorised — marker written, watchdog will stand down on next pidfd POLLIN"
    );

    // Tappa 8 A8: signal the agent's main loop that an
    // admin-authorised shutdown has begun. The marker is already on
    // disk (the watchdog's cross-component contract) BEFORE we fire
    // here, so the ordering is: disk → in-process signal → wire
    // reply. If the signal is `None` (legacy `serve()` callers or
    // tests that aren't exercising the exit path), we still wrote
    // the marker — the contract with the watchdog is intact, only
    // the in-process exit is uninstrumented.
    if let Some(sig) = shutdown_signal {
        sig.fire();
    }

    AdminResult::Success
}

/// Tappa 8 A10 — handle one [`ForcePostureRequest`] (design §4 +
/// §12.2). Distinct from the existing `cfg(debug-trigger)`
/// `DebugForcePosture` arm: that one bypasses every authentication
/// layer for integration testing; this one runs the full Tappa-8
/// verify path AND honours the role allowlist.
///
/// Quorum semantics: 1-of-N per §3.3 (unlike shutdown's 2-of-N).
/// Required role: [`Role::ForcePosture`]. Expected op tag:
/// [`OperationCode::ForcePosture`]. The signed payload's `extra`
/// MUST be [`OperationExtra::ForcePosture { target }`]; any other
/// extra variant trips the op/extra invariant check inside
/// [`crate::anti_tamper::admin_auth::ConnAuth::verify_signed_payload_quorum`]
/// (Tappa 8 A7) and surfaces as `UnknownOperation` on the wire.
///
/// On verify success, mutates the posture machine to the requested
/// target via [`PostureMachine::admin_force_state_with_token`]
/// (Tappa 8 A10), which fires the COMBAT entry/release hooks per
/// §12.2 if the direction crosses the COMBAT boundary.
///
/// External audit NN-AUD-083: leaving COMBAT this way releases the
/// containment exactly like `unlock`, so it also needs a signer that
/// holds [`Role::Unlock`]. The posture machine checks it under its own
/// state lock (an autonomous COMBAT entry may land between this
/// dispatcher and the transition); a refusal answers `RoleDenied`.
/// Entering COMBAT stays 1-of-N `force-posture` (POS-001: the
/// administrator forces it).
fn dispatch_force_posture(
    req: ForcePostureRequest,
    auth: &ConnAuth<'_>,
    posture: &PostureMachine,
    fps_out: &mut Vec<String>,
) -> AdminResult {
    let server_now = now_unix_secs();
    let sigs: Vec<[u8; 64]> = req.signatures.iter().map(|s| s.signature).collect();

    let verify_outcome = auth.verify_signed_payload_quorum_keys(
        &req.payload,
        &sigs,
        1, // 1-of-N per §3.3
        &[Role::ForcePosture],
        OperationCode::ForcePosture,
        server_now,
    );

    let signers = match verify_outcome {
        Ok(v) => v,
        Err(AdminAuthError::NoPendingChallenge) => return AdminResult::NoPendingChallenge,
        Err(AdminAuthError::NonceMismatch) => return AdminResult::InvalidSignature,
        Err(AdminAuthError::UnknownOperation { .. }) => return AdminResult::UnknownOperation,
        Err(AdminAuthError::AgentIdMismatch) => return AdminResult::AgentIdMismatch,
        Err(AdminAuthError::TimestampSkew {
            server_ts,
            max_skew_secs,
        }) => {
            return AdminResult::TimestampSkew {
                server_ts,
                max_skew_secs,
            };
        }
        Err(AdminAuthError::InvalidSignature) => return AdminResult::InvalidSignature,
        Err(AdminAuthError::QuorumNotMet { required, provided }) => {
            return AdminResult::QuorumNotMet { required, provided };
        }
        Err(AdminAuthError::RoleDenied { .. }) => return AdminResult::RoleDenied,
        Err(AdminAuthError::RateLimited { retry_after_secs }) => {
            return AdminResult::RateLimited { retry_after_secs };
        }
        Err(AdminAuthError::PayloadVerify(e)) => {
            warn!(error = ?e, "force-posture payload verify failed at common layer");
            return AdminResult::InvalidSignature;
        }
    };
    *fps_out = signers.fingerprints;
    // External audit NN-AUD-083: may this request release COMBAT?
    let may_release = signers.keys.iter().any(|k| k.authorizes(Role::Unlock));

    // Extract the target from the verified payload. The op/extra
    // invariant inside verify_signed_payload_quorum already
    // guarantees this is the ForcePosture variant — but a
    // belt-and-suspenders match keeps the compiler exhaustive and
    // surfaces a clear UnknownOperation if a future refactor ever
    // breaks the invariant.
    let target = match &req.payload.extra {
        OperationExtra::ForcePosture(extra) => extra.target,
        other => {
            warn!(
                extra = ?other,
                "force-posture payload extra is not ForcePosture variant — \
                 op/extra invariant breach"
            );
            return AdminResult::UnknownOperation;
        }
    };

    // Drive the posture mutation through the capability-gated path.
    // `admin_force_state_with_token` consumes the token, fires
    // hooks per §12.2, and returns the post-transition state. It
    // refuses COMBAT → non-COMBAT without `may_release`; any other
    // error shape maps to InvalidSignature defensively.
    match posture.admin_force_state_with_token(signers.token, target, may_release) {
        Ok(state) => {
            info!(
                target: "admin.force_posture",
                from = ?state.kind(),
                to = ?target,
                "production force-posture applied"
            );
            AdminResult::Success
        }
        Err(AdminReleaseError::NeedsUnlock) => {
            warn!(
                target: "admin.force_posture",
                to = ?target,
                signer_fp = %fps_out.first().map(String::as_str).unwrap_or(""),
                "force-posture out of COMBAT refused: no signer holds the `unlock` role"
            );
            AdminResult::RoleDenied
        }
        Err(e) => {
            warn!(
                error = ?e,
                target = ?target,
                "admin_force_state_with_token errored unexpectedly"
            );
            AdminResult::InvalidSignature
        }
    }
}

/// at-authz-1 verify-item 1: re-register the rotated admin.pub inode in
/// `PROTECTED_INODES` after a rotate-keys rewrite. The atomic rewrite does
/// tmp-write + `rename(2)`, installing a NEW inode the boot-time
/// `register_etc_files` never saw — so without this every deny hook (the
/// five existing + the at-authz-1 write-open deny) lapses on the rotated
/// admin.pub until the next agent restart, silently reopening the gap.
/// Best-effort + loud on failure: a failure means the file is unprotected
/// until restart, NOT that the (already-committed-on-disk) rotation should
/// be reported as failed. Called right after the rename(2), before the
/// in-memory reload, so a reload failure cannot skip it.
fn reregister_admin_pub_after_rotate(
    config_path: &Path,
    old_inode_key: Option<common::wire::InodeKey>,
) {
    if let Err(e) = crate::anti_tamper::filesystem::reregister_protected_file(
        crate::anti_tamper::prepare_pin_root(),
        config_path,
        old_inode_key,
        FS_PROTECT_MUTATE | FS_PROTECT_WRITE,
    ) {
        warn!(
            error = ?e,
            "rotate-keys: re-registering rotated admin.pub inode in PROTECTED_INODES \
             FAILED — admin.pub is UNPROTECTED against tamper until the next agent restart"
        );
    }
}

/// Tappa 10.8 — handle one [`ConfigOverlaySetRequest`]: verify the
/// 1-of-N quorum carrying `Role::ConfigManage` (single-use challenge, skew,
/// agent_id), check that `content` is exactly what was signed and parses as
/// that overlay kind, then write the overlay and its `.sig` where the agent
/// reads it at boot. Takes effect at the next agent start.
fn dispatch_config_overlay_set(
    req: ConfigOverlaySetRequest,
    auth: &ConnAuth<'_>,
    fps_out: &mut Vec<String>,
) -> ConfigOverlaySetResponse {
    use crate::config::overlay_auth;
    const CONFIG_OVERLAY_QUORUM: u8 = 1;
    let refuse = |result: AdminResult, message: String| ConfigOverlaySetResponse {
        result,
        stored: false,
        message,
    };
    let sigs: Vec<[u8; 64]> = req.signatures.iter().map(|s| s.signature).collect();
    let (_token, matched_fps) = match auth.verify_signed_payload_quorum(
        &req.payload,
        &sigs,
        CONFIG_OVERLAY_QUORUM,
        &[Role::ConfigManage],
        OperationCode::ConfigOverlaySet,
        now_unix_secs(),
    ) {
        Ok(t) => t,
        Err(e) => {
            let r = map_admin_auth_error(e, "config-overlay-set");
            return refuse(r, "signature verification failed".to_string());
        }
    };
    *fps_out = matched_fps;
    let OperationExtra::ConfigOverlaySet(extra) = &req.payload.extra else {
        return refuse(
            AdminResult::UnknownOperation,
            "not a config-overlay payload".to_string(),
        );
    };
    if req.content.len() > common::wire::admin_protocol::MAX_OVERLAY_BYTES {
        return refuse(
            AdminResult::Success,
            format!(
                "content larger than {} bytes",
                common::wire::admin_protocol::MAX_OVERLAY_BYTES
            ),
        );
    }
    if overlay_auth::content_sha256(req.content.as_bytes()) != extra.sha256
        || req.content.len() != extra.len as usize
    {
        return refuse(
            AdminResult::Success,
            "content does not match the signed hash".to_string(),
        );
    }
    if let Err(e) = overlay_auth::validate_content(extra.kind, &req.content) {
        return refuse(
            AdminResult::Success,
            format!("content does not parse: {e:#}"),
        );
    }
    let config_dir = auth
        .config_path()
        .and_then(|p| p.parent())
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("/etc/northnarrow"));
    let target = overlay_auth::configured_path(extra.kind, &config_dir);
    let sig = match overlay_auth::OverlaySignature::new(req.payload.clone(), &sigs) {
        Ok(s) => s,
        Err(e) => return refuse(AdminResult::Success, format!("{e:#}")),
    };
    match overlay_auth::store(&target, &req.content, &sig) {
        Ok(sig_file) => {
            info!(
                target: "admin.config_overlay",
                kind = extra.kind.keyword(),
                path = %target.display(),
                signer_fp = %fps_out.first().map(String::as_str).unwrap_or(""),
                "signed overlay stored — takes effect at the next agent start"
            );
            ConfigOverlaySetResponse {
                result: AdminResult::Success,
                stored: true,
                message: format!(
                    "{} and {} written; restart the agent to apply (systemctl restart northnarrow-agent)",
                    target.display(),
                    sig_file.display()
                ),
            }
        }
        Err(e) => refuse(
            AdminResult::Success,
            format!("writing the overlay failed: {e:#}"),
        ),
    }
}

/// Tappa 8 A13 — handle one [`RotateKeysAddRequest`] (design
/// §7.2). Verifies 2-of-N quorum carrying `Role::RotateKeys`,
/// atomically appends a new line to `admin.pub`, and reloads
/// the in-memory key set so the next challenge already sees
/// the addition.
///
/// `AdminAuth::config_path()` MUST be `Some` — production
/// `AdminAuth::load_with_agent_id` always sets it; test builders
/// that go through `build_*` don't, and trying to rotate keys
/// against an in-memory-only auth surfaces as a clear log line
/// + `AdminResult::UnknownOperation`.
///
/// External audit NN-AUD-084: the new key's roles must be a subset of
/// what the matched signers hold, else `AdminResult::RoleDenied` and
/// admin.pub is untouched.
fn dispatch_rotate_keys_add(
    req: RotateKeysAddRequest,
    auth: &ConnAuth<'_>,
    fps_out: &mut Vec<String>,
) -> AdminResult {
    // BUG-013 (PHASE 15.1): bootstrap-mode 1-of-N gate. Consulted
    // BEFORE verify_signed_payload_quorum so the relaxed min_distinct
    // (1) goes into the verify call. The gate is evaluated against the
    // key set in memory (one key), the signed chain (no second key ever
    // added) and the sentinel + nonce on disk; ALL must hold, and any
    // other outcome falls through to the permanent 2-of-N path. See
    // `crate::anti_tamper::bootstrap` for the full security argument.
    let bootstrap_armed = match auth.config_path() {
        Some(admin_pub_path) => {
            let paths = crate::anti_tamper::bootstrap::BootstrapPaths::default_paths(
                admin_pub_path.to_path_buf(),
            );
            // External audit ATP-004: the keys in memory, and the
            // consumption recorded in the signed chain.
            matches!(
                crate::anti_tamper::bootstrap::evaluate_loaded(
                    &paths,
                    &auth.loaded_admin_pub(),
                    auth.bootstrap_consumed(),
                ),
                crate::anti_tamper::bootstrap::BootstrapGate::Armed
            )
        }
        // In-memory test builders have no config_path; bootstrap
        // gate is structurally inapplicable. Fall through to the
        // existing 2-of-N path.
        None => false,
    };
    let min_distinct: u8 = if bootstrap_armed { 1 } else { 2 };

    let server_now = now_unix_secs();
    let sigs: Vec<[u8; 64]> = req.signatures.iter().map(|s| s.signature).collect();

    let signers = match auth.verify_signed_payload_quorum_keys(
        &req.payload,
        &sigs,
        min_distinct, // 2-of-N normally; 1-of-N when bootstrap-armed (BUG-013)
        &[Role::RotateKeys],
        OperationCode::RotateKeysAdd,
        server_now,
    ) {
        Ok(v) => v,
        Err(e) => return map_admin_auth_error(e, "rotate-keys-add"),
    };
    *fps_out = signers.fingerprints;

    let (new_pubkey_bytes, roles) = match &req.payload.extra {
        OperationExtra::RotateKeysAdd(extra) => (extra.new_pubkey, extra.roles.clone()),
        other => {
            warn!(
                extra = ?other,
                "rotate-keys-add payload extra is not RotateKeysAdd variant"
            );
            return AdminResult::UnknownOperation;
        }
    };

    // External audit NN-AUD-084: the new key may hold only roles its
    // signers hold, the bootstrap 1-of-N path included — a key with only
    // `rotate-keys` used to mint an `all` key.
    if let Some(beyond) = role_beyond_signers(&roles, &signers.keys) {
        warn!(
            target: "admin.rotate_keys",
            role = ?beyond,
            requested = ?roles,
            bootstrap_armed,
            "rotate-keys add refused: the new key would hold a role none of its signers holds"
        );
        return AdminResult::RoleDenied;
    }

    let Some(config_path) = auth.config_path() else {
        warn!(
            "rotate-keys-add: AdminAuth has no config_path — agent was loaded \
             via in-memory builder, rotation requires a real admin.pub file"
        );
        return AdminResult::UnknownOperation;
    };
    let config_path = config_path.to_path_buf();
    // at-authz-1 verify-item 1: capture the CURRENT admin.pub inode before
    // the rename-based rewrite installs a new one, so we can drop the stale
    // key from PROTECTED_INODES afterwards.
    let old_inode_key = crate::fim::attach::key_for_path(&config_path).ok();

    let new_pubkey = match VerifyingKey::from_bytes(&new_pubkey_bytes) {
        Ok(vk) => vk,
        Err(e) => {
            warn!(error = ?e, "rotate-keys-add: new_pubkey not a valid Ed25519 key");
            return AdminResult::InvalidSignature;
        }
    };

    match crate::anti_tamper::admin_auth::atomic_rewrite_admin_pub_add(
        &config_path,
        &new_pubkey,
        &roles,
    ) {
        Ok(()) => {}
        Err(crate::anti_tamper::admin_auth::RotateKeysError::KeyAlreadyPresent { fingerprint }) => {
            warn!(
                target: "admin.rotate_keys",
                fingerprint,
                "rotate-keys-add rejected: pubkey already present"
            );
            return AdminResult::InvalidSignature;
        }
        Err(e) => {
            warn!(error = ?e, "rotate-keys-add: atomic rewrite failed");
            return AdminResult::InvalidSignature;
        }
    }

    // at-authz-1 verify-item 1: re-register the rotated inode NOW, after the
    // rename(2) committed the new on-disk inode but BEFORE the reload — the
    // protection property depends only on the on-disk inode, not the
    // in-memory key reload (which has its own reachable failure path below).
    // Re-registering after the reload would skip it on a reload failure and
    // silently leave the rotated admin.pub unprotected until restart.
    reregister_admin_pub_after_rotate(&config_path, old_inode_key);

    if let Err(e) = auth.reload(&config_path) {
        warn!(error = ?e, "rotate-keys-add: admin.pub rewrite succeeded but reload failed");
        return AdminResult::InvalidSignature;
    }

    // BUG-013 (PHASE 15.1): if we entered this dispatch via the
    // bootstrap-armed 1-of-N relaxation, scrub the sentinel now that
    // the add is complete. Best-effort: any failure leaves a stale
    // sentinel that the NEXT dispatch will scrub via the
    // BootstrapAlreadyComplete arm (admin.pub now has ≥2 keys, so
    // `evaluate` will remove it). If the gate was NOT armed (i.e.
    // we took the normal 2-of-N path), there's nothing to clean up.
    if bootstrap_armed {
        let paths =
            crate::anti_tamper::bootstrap::BootstrapPaths::default_paths(config_path.clone());
        if let Err(e) = crate::anti_tamper::bootstrap::complete(&paths) {
            warn!(
                error = ?e,
                "BUG-013: post-bootstrap sentinel scrub failed (next dispatch will retry)"
            );
        }
    }

    // External audit ATP-004: a second key exists now — no later admin.pub
    // with one key re-arms the bootstrap in this run (the next boots read
    // the signed chain).
    auth.mark_bootstrap_consumed();
    info!(
        target: "admin.rotate_keys",
        new_key_fp = %hex::encode(crate::anti_tamper::admin_auth::fingerprint_bytes(&new_pubkey)),
        role_count = roles.len(),
        bootstrap_armed,
        "rotate-keys add: admin.pub updated + in-memory keys reloaded"
    );
    AdminResult::Success
}

/// External audit NN-AUD-084: the first role a key added with `roles`
/// would hold that none of `signers` holds ([`AdminKey::authorizes`], so
/// `all` needs a signer holding `all`). An empty list is written as a
/// pubkey-only line, which loads with the default roles — those are
/// checked.
///
/// [`AdminKey::authorizes`]: common::admin_quorum::AdminKey::authorizes
fn role_beyond_signers(roles: &[Role], signers: &[common::admin_quorum::AdminKey]) -> Option<Role> {
    let defaults;
    let granted = if roles.is_empty() {
        defaults = common::admin_quorum::default_roles();
        &defaults[..]
    } else {
        roles
    };
    granted
        .iter()
        .copied()
        .find(|role| !signers.iter().any(|k| k.authorizes(*role)))
}

/// Tappa 8 A13 — handle one [`RotateKeysRevokeRequest`] (design
/// §7.2 + §7.3). Symmetric to [`dispatch_rotate_keys_add`]: 2-of-N
/// quorum with `Role::RotateKeys`, atomic file rewrite removing
/// the matched line, in-memory reload. Refuses to revoke the
/// LAST remaining key — that would soft-brick the agent
/// (`AdminResult::InvalidSignature` rather than a dedicated
/// variant; the operator-facing detail is in the agent's own log).
fn dispatch_rotate_keys_revoke(
    req: RotateKeysRevokeRequest,
    auth: &ConnAuth<'_>,
    fps_out: &mut Vec<String>,
) -> AdminResult {
    let server_now = now_unix_secs();
    let sigs: Vec<[u8; 64]> = req.signatures.iter().map(|s| s.signature).collect();

    let (_token, matched_fps) = match auth.verify_signed_payload_quorum(
        &req.payload,
        &sigs,
        2, // 2-of-N per §3.3
        &[Role::RotateKeys],
        OperationCode::RotateKeysRevoke,
        server_now,
    ) {
        Ok(t) => t,
        Err(e) => return map_admin_auth_error(e, "rotate-keys-revoke"),
    };
    *fps_out = matched_fps;

    let target_fp = match &req.payload.extra {
        OperationExtra::RotateKeysRevoke(extra) => extra.fingerprint,
        other => {
            warn!(
                extra = ?other,
                "rotate-keys-revoke payload extra is not RotateKeysRevoke variant"
            );
            return AdminResult::UnknownOperation;
        }
    };

    let Some(config_path) = auth.config_path() else {
        warn!(
            "rotate-keys-revoke: AdminAuth has no config_path — agent was loaded \
             via in-memory builder, rotation requires a real admin.pub file"
        );
        return AdminResult::UnknownOperation;
    };
    let config_path = config_path.to_path_buf();
    // at-authz-1 verify-item 1: capture the CURRENT admin.pub inode before
    // the rename-based rewrite installs a new one.
    let old_inode_key = crate::fim::attach::key_for_path(&config_path).ok();

    match crate::anti_tamper::admin_auth::atomic_rewrite_admin_pub_revoke(&config_path, target_fp) {
        Ok(()) => {}
        Err(crate::anti_tamper::admin_auth::RotateKeysError::KeyNotFound { fingerprint }) => {
            warn!(
                target: "admin.rotate_keys",
                fingerprint,
                "rotate-keys-revoke rejected: no matching pubkey"
            );
            return AdminResult::InvalidSignature;
        }
        Err(crate::anti_tamper::admin_auth::RotateKeysError::LastKey) => {
            warn!(
                target: "admin.rotate_keys",
                "rotate-keys-revoke rejected: would remove the last admin key \
                 (soft-brick guard — add a replacement key first)"
            );
            return AdminResult::InvalidSignature;
        }
        Err(e) => {
            warn!(error = ?e, "rotate-keys-revoke: atomic rewrite failed");
            return AdminResult::InvalidSignature;
        }
    }

    // at-authz-1 verify-item 1: re-register BEFORE the reload (see the add
    // path) — protection of the new on-disk inode must not be gated on the
    // in-memory reload's reachable failure path.
    reregister_admin_pub_after_rotate(&config_path, old_inode_key);

    if let Err(e) = auth.reload(&config_path) {
        warn!(
            error = ?e,
            "rotate-keys-revoke: admin.pub rewrite succeeded but reload failed"
        );
        return AdminResult::InvalidSignature;
    }

    info!(
        target: "admin.rotate_keys",
        revoked_fp = %hex::encode(target_fp),
        "rotate-keys revoke: admin.pub updated + in-memory keys reloaded"
    );
    AdminResult::Success
}

// PHASE_D_004: `fps_out` populated on success with the matched
// signer fingerprint (1-of-N quorum → one fingerprint).
//
/// Tappa 9 C6 → C7 — handle one [`FimBaselineRequest`] (design §6.1 +
/// §13 Q6). Verifies 1-of-N quorum carrying `Role::FimManage`,
/// then fires the in-process recompute channel so the running
/// agent re-walks every watched path without an operator-driven
/// restart (C7 closes C6's lazy deferral). When the agent boots
/// WITHOUT a recompute channel — every legacy `serve_with_*`
/// callsite that hasn't migrated to `serve_with_fim_state` —
/// the dispatcher falls back to the C6 info-log shape ("scheduled
/// for next restart") so legacy unit-test fixtures stay green.
fn dispatch_fim_baseline(
    req: FimBaselineRequest,
    auth: &ConnAuth<'_>,
    fim_state: Option<&FimAdminState>,
    fps_out: &mut Vec<String>,
) -> AdminResult {
    let server_now = now_unix_secs();
    let sigs: Vec<[u8; 64]> = req.signatures.iter().map(|s| s.signature).collect();

    let (_token, matched_fps) = match auth.verify_signed_payload_quorum(
        &req.payload,
        &sigs,
        1, // 1-of-N per §13 Q6 (workflow gate, not security gate)
        &[Role::FimManage],
        OperationCode::FimBaseline,
        server_now,
    ) {
        Ok(t) => t,
        Err(e) => return map_admin_auth_error(e, "fim-baseline"),
    };
    *fps_out = matched_fps;

    // The payload's extra MUST be FimBaseline (op/extra invariant
    // already enforced inside verify_signed_payload_quorum).
    if !matches!(&req.payload.extra, OperationExtra::FimBaseline(_)) {
        warn!(
            extra = ?req.payload.extra,
            "fim-baseline payload extra is not FimBaseline variant"
        );
        return AdminResult::UnknownOperation;
    }

    match fim_state {
        Some(state) => {
            let queued = state
                .recompute_sender
                .trigger(RecomputeReason::AdminRequest);
            info!(
                target: "admin.fim_baseline",
                signer_fp = %fps_out.first().map(String::as_str).unwrap_or(""),
                queued,
                "fim baseline requested — recompute channel fired"
            );
        }
        None => {
            info!(
                target: "admin.fim_baseline",
                signer_fp = %fps_out.first().map(String::as_str).unwrap_or(""),
                "fim baseline requested — recompute scheduled for next agent restart \
                 (legacy serve_with_marker_path path; production main.rs uses \
                 serve_with_fim_state)"
            );
        }
    }
    AdminResult::Success
}

/// FIM-009 self-upgrade (§15.1) — handle one
/// [`TrustedInstallerGrantRequest`]. Verifies the signed grant (M=1
/// quorum carrying [`Role::TrustedInstaller`], with the full nonce +
/// agent_id + skew binding the standard `verify_signed_payload_quorum`
/// enforces), then arms the TTL'd FS-pin override + the NN-L-FIM-009
/// own-unit detection downgrade for the (clamped) signed window. The
/// ARM is recorded in the audit chain by `emit_audit_for`; the
/// close/expiry record is written by the override itself.
///
/// M=1 today — like COMBAT reactivation — but expressed through
/// `min_distinct` so a future hardening can require co-signers without
/// touching this dispatcher.
fn dispatch_trusted_installer_grant(
    req: TrustedInstallerGrantRequest,
    auth: &ConnAuth<'_>,
    installer_override: Option<&TrustedInstallerOverride>,
    fps_out: &mut Vec<String>,
) -> AdminResult {
    // Required distinct signatures (M of N). 1 today; raise to harden.
    const TRUSTED_INSTALLER_QUORUM: u8 = 1;

    let server_now = now_unix_secs();
    let sigs: Vec<[u8; 64]> = req.signatures.iter().map(|s| s.signature).collect();

    let (_token, matched_fps) = match auth.verify_signed_payload_quorum(
        &req.payload,
        &sigs,
        TRUSTED_INSTALLER_QUORUM,
        &[Role::TrustedInstaller],
        OperationCode::TrustedInstallerGrant,
        server_now,
    ) {
        Ok(t) => t,
        Err(e) => return map_admin_auth_error(e, "trusted-installer-grant"),
    };
    *fps_out = matched_fps;

    // The op/extra invariant is already enforced inside
    // verify_signed_payload_quorum; this pulls the signed window out.
    let window_secs = match &req.payload.extra {
        OperationExtra::TrustedInstallerGrant(extra) => extra.window_secs,
        other => {
            warn!(
                extra = ?other,
                "trusted-installer-grant payload extra is not TrustedInstallerGrant variant"
            );
            return AdminResult::UnknownOperation;
        }
    };

    match installer_override {
        Some(ov) => {
            let window = ov.arm(window_secs, Instant::now());
            info!(
                target: "admin.trusted_installer_grant",
                signer_fp = %fps_out.first().map(String::as_str).unwrap_or(""),
                window_secs = window.as_secs(),
                "trusted-installer override ARMED via signed grant (FIM-009 §15.1)"
            );
            AdminResult::Success
        }
        None => {
            // Legacy serve path with no override wired — verified but
            // nothing to arm. Surface as UnknownOperation so a stale
            // test fixture doesn't read as a successful arm.
            warn!(
                target: "admin.trusted_installer_grant",
                "trusted-installer grant verified but no override wired (legacy serve path)"
            );
            AdminResult::UnknownOperation
        }
    }
}

/// Tappa 9 C7 — handle one [`FimStatusRequest`] (closes the C6
/// deferral). Verifies 1-of-N quorum carrying `Role::FimRead` and
/// returns the in-process snapshot. Read-only — no disk-side
/// effects. When `fim_state` is `None` (legacy serve path) the
/// snapshot is zeroed and the result is `UnknownOperation` so a
/// stale test fixture doesn't accidentally serve stale data; the
/// production code path always supplies state via
/// `serve_with_fim_state`.
fn dispatch_fim_status(
    req: FimStatusRequest,
    auth: &ConnAuth<'_>,
    fim_state: Option<&FimAdminState>,
    fps_out: &mut Vec<String>,
) -> FimStatusResponse {
    let server_now = now_unix_secs();
    let sigs: Vec<[u8; 64]> = req.signatures.iter().map(|s| s.signature).collect();

    let (_token, matched_fps) = match auth.verify_signed_payload_quorum(
        &req.payload,
        &sigs,
        1, // 1-of-N per §13 Q6
        &[Role::FimRead],
        OperationCode::FimStatus,
        server_now,
    ) {
        Ok(t) => t,
        Err(e) => return empty_fim_status(map_admin_auth_error(e, "fim-status")),
    };
    *fps_out = matched_fps;

    if !matches!(&req.payload.extra, OperationExtra::FimStatus(_)) {
        warn!(
            extra = ?req.payload.extra,
            "fim-status payload extra is not FimStatus variant"
        );
        return empty_fim_status(AdminResult::UnknownOperation);
    }

    let state = match fim_state {
        Some(s) => s,
        None => {
            warn!("fim-status: agent boot did not wire FimAdminState — returning empty snapshot");
            return empty_fim_status(AdminResult::UnknownOperation);
        }
    };

    let (high_remaining, medium_remaining, bucket_window_resets_in_secs) =
        state.rate_limiter.snapshot();
    let (baseline_entries_total, last_baseline_ts) =
        count_and_last_ts_jsonl(&state.baseline_log_path);
    let (drift_entries_total, _) = count_and_last_ts_jsonl(&state.drift_log_path);

    info!(
        target: "admin.fim_status",
        signer_fp = %fps_out.first().map(String::as_str).unwrap_or(""),
        watched = state.paths_summary.watched_paths_count,
        baseline_total = baseline_entries_total,
        drift_total = drift_entries_total,
        "fim status served"
    );

    FimStatusResponse {
        result: AdminResult::Success,
        watched_paths_count: state.paths_summary.watched_paths_count,
        disabled_default_count: state.paths_summary.disabled_default_count,
        added_path_count: state.paths_summary.added_path_count,
        last_baseline_ts,
        baseline_entries_total,
        drift_entries_total,
        high_remaining,
        high_cap_per_min: state.rate_limiter.high_cap_per_min(),
        medium_remaining,
        medium_cap_per_min: state.rate_limiter.medium_cap_per_min(),
        bucket_window_resets_in_secs,
    }
}

/// Build a zero/empty [`FimStatusResponse`] carrying the supplied
/// auth `result`. Used by both the auth-failure path and the
/// "agent boot didn't wire FIM state" fallback.
fn empty_fim_status(result: AdminResult) -> FimStatusResponse {
    FimStatusResponse {
        result,
        watched_paths_count: 0,
        disabled_default_count: 0,
        added_path_count: 0,
        last_baseline_ts: String::new(),
        baseline_entries_total: 0,
        drift_entries_total: 0,
        high_remaining: 0,
        high_cap_per_min: 0,
        medium_remaining: 0,
        medium_cap_per_min: 0,
        bucket_window_resets_in_secs: 0,
    }
}

/// Count JSONL rows + return the `ts` of the last row in a
/// chained log file at `path`. Missing file → `(0, "")`. Used by
/// `dispatch_fim_status` for the baseline + drift counts; the
/// chain integrity is already enforced at append time, so a
/// best-effort line-count is appropriate here (verify happens at
/// the dedicated `verify_chain` paths, not at every status query).
fn count_and_last_ts_jsonl(path: &Path) -> (u32, String) {
    use std::io::BufRead;
    let f = match std::fs::OpenOptions::new().read(true).open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return (0, String::new()),
        Err(e) => {
            warn!(
                error = %e,
                path = %path.display(),
                "fim-status: jsonl read failed — reporting (0, empty)"
            );
            return (0, String::new());
        }
    };
    let reader = std::io::BufReader::new(f);
    let mut count = 0u32;
    let mut last_ts = String::new();
    for line in reader.lines() {
        let Ok(line) = line else {
            continue;
        };
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        count = count.saturating_add(1);
        if let Some(ts) = extract_ts_field(trimmed) {
            last_ts = ts;
        }
    }
    (count, last_ts)
}

/// Tappa 9 C6 — handle one [`FimReportRequest`] (design §6.3 +
/// §13 Q6). Verifies 1-of-N quorum carrying `Role::FimRead`,
/// reads the drift log from disk, returns the chained JSONL
/// body (or a truncation flag if the chain exceeds the wire
/// frame budget). Filtering by `since_unix_ts` from the
/// payload's extra keeps entries whose `ts` field is `>=`
/// the threshold (lexicographic ISO-8601 compare, valid
/// because the format is fixed-width).
///
/// External audit NN-AUD-080/082: the drift log configured by
/// `--fim-drift-file` (not the built-in path), newest rows first,
/// rotated archives included ([`read_tail_jsonl`]).
fn dispatch_fim_report(
    req: FimReportRequest,
    auth: &ConnAuth<'_>,
    read_paths: &AdminReadPaths,
    fps_out: &mut Vec<String>,
) -> FimReportResponse {
    use common::wire::admin_signed_payload::FimReportExtra;

    let server_now = now_unix_secs();
    let sigs: Vec<[u8; 64]> = req.signatures.iter().map(|s| s.signature).collect();

    let (_token, matched_fps) = match auth.verify_signed_payload_quorum(
        &req.payload,
        &sigs,
        1, // 1-of-N per §13 Q6
        &[Role::FimRead],
        OperationCode::FimReport,
        server_now,
    ) {
        Ok(t) => t,
        Err(e) => {
            return FimReportResponse {
                result: map_admin_auth_error(e, "fim-report"),
                entries_jsonl: String::new(),
                entries_count: 0,
                entries_truncated: false,
            };
        }
    };
    *fps_out = matched_fps;

    let since = match &req.payload.extra {
        OperationExtra::FimReport(FimReportExtra { since_unix_ts }) => *since_unix_ts,
        _ => {
            warn!("fim-report payload extra is not FimReport variant");
            return FimReportResponse {
                result: AdminResult::UnknownOperation,
                entries_jsonl: String::new(),
                entries_count: 0,
                entries_truncated: false,
            };
        }
    };

    let (entries_jsonl, entries_count, entries_truncated) =
        read_tail_jsonl(&read_paths.fim_drift, since, None, usize::MAX);
    info!(
        target: "admin.fim_report",
        signer_fp = %fps_out.first().map(String::as_str).unwrap_or(""),
        entries = entries_count,
        truncated = entries_truncated,
        "fim report served"
    );
    FimReportResponse {
        result: AdminResult::Success,
        entries_jsonl,
        entries_count,
        entries_truncated,
    }
}

/// Half a frame: the rest of a read verb's response fits in the other
/// half.
const READ_VERB_SOFT_CAP: usize = MAX_FRAME_BODY / 2;

/// External audit NN-AUD-080: the body of a read verb — the newest rows
/// of the chain log whose active file is `path` (the active file, then
/// its rotated archives), newest first, within [`READ_VERB_SOFT_CAP`] and
/// `max_rows`. With `since` (UNIX seconds), rows whose `ts` is earlier are
/// left out. `keep` selects rows by their raw line. Returns `(jsonl_body,
/// count, truncated)`; `truncated` means older matching rows were left
/// out. The read bounds are in [`crate::chain_tail`].
fn read_tail_jsonl(
    path: &Path,
    since: Option<u64>,
    keep: Option<&dyn Fn(&str) -> bool>,
    max_rows: usize,
) -> (String, u32, bool) {
    let since = since.map(format_iso8601_unix);
    let tail = crate::chain_tail::read_chain_tail(
        path,
        &crate::chain_tail::TailQuery {
            since: since.as_deref(),
            keep,
            soft_cap: READ_VERB_SOFT_CAP,
            max_rows,
        },
    );
    (tail.jsonl, tail.count, tail.truncated)
}

fn format_iso8601_unix(unix_ts: u64) -> String {
    use chrono::TimeZone;
    chrono::Utc
        .timestamp_opt(unix_ts as i64, 0)
        .single()
        .map(|dt| dt.format("%Y-%m-%dT%H:%M:%S").to_string())
        .unwrap_or_else(|| "1970-01-01T00:00:00".to_string())
}

/// Extract the `ts` field from a JSONL drift entry without a
/// full JSON parse. Returns the string between the value's
/// opening + closing `"` quotes. Returns `None` on a malformed
/// line — the caller treats that as "include the entry" to
/// avoid silently dropping evidence the operator might need.
fn extract_ts_field(line: &str) -> Option<String> {
    // Expected shape: {"ts":"<iso8601>", ...
    // We find `"ts":"` and then the next `"`.
    let key = "\"ts\":\"";
    let start = line.find(key)? + key.len();
    let end = line[start..].find('"')?;
    Some(line[start..start + end].to_string())
}

// ── External audit CMB-016 — undoing a response ───────────────────

fn empty_response_status(result: AdminResult) -> ResponseStatusResponse {
    ResponseStatusResponse {
        result,
        contained: Vec::new(),
        contained_total: 0,
        quarantined: Vec::new(),
        quarantined_total: 0,
        combat_stage: None,
        combat_locked: None,
    }
}

/// `nn-admin response status`: the processes the agent holds in its
/// `blocked` / `throttled` scopes (the containment record, with whether
/// the pid still names the process moved), the quarantine vault, and the
/// COMBAT stage. Read-only; `audit-read`, the role every key carries by
/// default, so the operator who undoes a response sees what there is to
/// undo.
fn dispatch_response_status(
    req: ResponseStatusRequest,
    auth: &ConnAuth<'_>,
    posture: &PostureMachine,
    state: Option<&ResponseAdminState>,
    fps_out: &mut Vec<String>,
) -> ResponseStatusResponse {
    use common::wire::admin_protocol::{
        ContainedProcessWire, QuarantinedFileWire, MAX_RESPONSE_STATUS_ROWS,
    };
    let sigs: Vec<[u8; 64]> = req.signatures.iter().map(|s| s.signature).collect();
    let (_token, matched_fps) = match auth.verify_signed_payload_quorum(
        &req.payload,
        &sigs,
        1,
        &[Role::AuditRead],
        OperationCode::ResponseStatus,
        now_unix_secs(),
    ) {
        Ok(t) => t,
        Err(e) => return empty_response_status(map_admin_auth_error(e, "response-status")),
    };
    *fps_out = matched_fps;
    if !matches!(&req.payload.extra, OperationExtra::ResponseStatus(_)) {
        warn!("response-status payload extra is not ResponseStatus variant");
        return empty_response_status(AdminResult::UnknownOperation);
    }
    let Some(state) = state else {
        warn!("response-status: agent boot did not wire ResponseAdminState");
        return empty_response_status(AdminResult::UnknownOperation);
    };
    let records = crate::response::containment::load(&state.config);
    let contained_total = records.len() as u32;
    let contained = records
        .iter()
        .rev()
        .take(MAX_RESPONSE_STATUS_ROWS)
        .map(|c| {
            let now = crate::response::proc_ref::proc_start_ticks(c.pid);
            ContainedProcessWire {
                pid: c.pid,
                scope: c.scope.clone(),
                origin: c.origin.clone(),
                since: c.since,
                running: now.is_some() && (c.start_ticks.is_none() || now == c.start_ticks),
            }
        })
        .collect();
    let vault = crate::response::quarantine::list_vault(&state.config);
    let quarantined_total = vault.len() as u32;
    let quarantined = vault
        .into_iter()
        .rev()
        .take(MAX_RESPONSE_STATUS_ROWS)
        .map(|e| QuarantinedFileWire {
            vault_id: e.vault_id,
            // a path is at most PATH_MAX; keep the reply inside a frame
            original_path: e.original_path.chars().take(512).collect(),
            size_bytes: e.size_bytes,
            captured_at: e.captured_at,
        })
        .collect();
    ResponseStatusResponse {
        result: AdminResult::Success,
        contained,
        contained_total,
        quarantined,
        quarantined_total,
        combat_stage: (state.combat_stage)(),
        combat_locked: Some(posture.is_combat_locked()),
    }
}

/// `nn-admin response release --pid N`: write a process the agent
/// contained back to the cgroup it came from, by its containment record
/// (external audit CMB-010: never the root cgroup, and only while the pid
/// still names the process moved). `response-manage`.
fn dispatch_response_release(
    req: ResponseReleaseRequest,
    auth: &ConnAuth<'_>,
    state: Option<&ResponseAdminState>,
    fps_out: &mut Vec<String>,
) -> ResponseReleaseResponse {
    let refuse = |result: AdminResult, message: String| ResponseReleaseResponse {
        result,
        released: false,
        message,
    };
    let sigs: Vec<[u8; 64]> = req.signatures.iter().map(|s| s.signature).collect();
    let (_token, matched_fps) = match auth.verify_signed_payload_quorum(
        &req.payload,
        &sigs,
        1,
        &[Role::ResponseManage],
        OperationCode::ResponseRelease,
        now_unix_secs(),
    ) {
        Ok(t) => t,
        Err(e) => return refuse(map_admin_auth_error(e, "response-release"), String::new()),
    };
    *fps_out = matched_fps;
    let OperationExtra::ResponseRelease(extra) = &req.payload.extra else {
        warn!("response-release payload extra is not ResponseRelease variant");
        return refuse(AdminResult::UnknownOperation, String::new());
    };
    let pid = extra.pid;
    let Some(state) = state else {
        warn!("response-release: agent boot did not wire ResponseAdminState");
        return refuse(AdminResult::UnknownOperation, String::new());
    };
    let records: Vec<_> = crate::response::containment::load(&state.config)
        .into_iter()
        .filter(|c| c.pid == pid)
        .collect();
    if records.is_empty() {
        return refuse(
            AdminResult::Success,
            format!("pid {pid} is not contained by this agent (no containment record)"),
        );
    }
    let mut released = false;
    let mut parts = Vec::new();
    for rec in records {
        let outcome = match rec.scope.as_str() {
            "blocked" => crate::response::block_outbound::release_blocked_pid(
                pid,
                rec.start_ticks,
                &state.config,
            ),
            "throttled" => {
                crate::response::throttle::release_pid(pid, rec.start_ticks, &state.config)
            }
            other => {
                parts.push(format!("{other}: unknown scope, left as it is"));
                continue;
            }
        };
        match outcome {
            Ok(crate::response::containment::Release::Released) => {
                released = true;
                parts.push(format!(
                    "{}: released to {}",
                    rec.scope,
                    if rec.origin.is_empty() {
                        "?"
                    } else {
                        &rec.origin
                    }
                ));
            }
            Ok(crate::response::containment::Release::Skipped(why)) => {
                parts.push(format!("{}: skipped ({why})", rec.scope));
            }
            Err(e) => parts.push(format!("{}: failed ({e})", rec.scope)),
        }
    }
    let message = parts.join("; ");
    info!(
        target: "admin.response_release",
        signer_fp = %fps_out.first().map(String::as_str).unwrap_or(""),
        pid,
        released,
        detail = %message,
        "response release"
    );
    ResponseReleaseResponse {
        result: AdminResult::Success,
        released,
        message,
    }
}

/// `nn-admin response restore --vault-id ID [--to PATH]`: write a
/// quarantined file back out of the vault — to the path it was taken from
/// unless `--to` says otherwise; never over an existing file, through a
/// link, or under a protected prefix (external audit CMB-026). The entry
/// stays in the vault. `response-manage`: a restore can put malware back.
fn dispatch_response_restore(
    req: ResponseRestoreRequest,
    auth: &ConnAuth<'_>,
    state: Option<&ResponseAdminState>,
    fps_out: &mut Vec<String>,
) -> ResponseRestoreResponse {
    let refuse = |result: AdminResult, message: String| ResponseRestoreResponse {
        result,
        restored: false,
        path: String::new(),
        message,
    };
    let sigs: Vec<[u8; 64]> = req.signatures.iter().map(|s| s.signature).collect();
    let (_token, matched_fps) = match auth.verify_signed_payload_quorum(
        &req.payload,
        &sigs,
        1,
        &[Role::ResponseManage],
        OperationCode::ResponseRestore,
        now_unix_secs(),
    ) {
        Ok(t) => t,
        Err(e) => return refuse(map_admin_auth_error(e, "response-restore"), String::new()),
    };
    *fps_out = matched_fps;
    let OperationExtra::ResponseRestore(extra) = &req.payload.extra else {
        warn!("response-restore payload extra is not ResponseRestore variant");
        return refuse(AdminResult::UnknownOperation, String::new());
    };
    let Some(state) = state else {
        warn!("response-restore: agent boot did not wire ResponseAdminState");
        return refuse(AdminResult::UnknownOperation, String::new());
    };
    match crate::response::quarantine::restore_entry(
        &extra.vault_id,
        extra.to.as_deref(),
        &state.config,
    ) {
        Ok(path) => {
            let path = path.to_string_lossy().into_owned();
            warn!(
                target: "admin.response_restore",
                signer_fp = %fps_out.first().map(String::as_str).unwrap_or(""),
                vault_id = %extra.vault_id,
                path = %path,
                "quarantined file restored by an administrator (mode 0600)"
            );
            ResponseRestoreResponse {
                result: AdminResult::Success,
                restored: true,
                message: format!("restored to {path} (mode 0600); the vault keeps the entry"),
                path,
            }
        }
        Err(e) => {
            warn!(vault_id = %extra.vault_id, error = %e, "response-restore refused");
            refuse(AdminResult::Success, e.to_string())
        }
    }
}

/// Shared mapper from [`AdminAuthError`] to the wire
/// [`AdminResult`]. Identical to the inline matches in
/// dispatch_shutdown / dispatch_force_posture; factored out by
/// A13 because dispatch_rotate_keys_add / _revoke would
/// duplicate the same 11-arm match otherwise.
fn map_admin_auth_error(e: AdminAuthError, op_for_log: &str) -> AdminResult {
    match e {
        AdminAuthError::NoPendingChallenge => AdminResult::NoPendingChallenge,
        AdminAuthError::NonceMismatch => AdminResult::InvalidSignature,
        AdminAuthError::UnknownOperation { .. } => AdminResult::UnknownOperation,
        AdminAuthError::AgentIdMismatch => AdminResult::AgentIdMismatch,
        AdminAuthError::TimestampSkew {
            server_ts,
            max_skew_secs,
        } => AdminResult::TimestampSkew {
            server_ts,
            max_skew_secs,
        },
        AdminAuthError::InvalidSignature => AdminResult::InvalidSignature,
        AdminAuthError::QuorumNotMet { required, provided } => {
            AdminResult::QuorumNotMet { required, provided }
        }
        AdminAuthError::RoleDenied { .. } => AdminResult::RoleDenied,
        AdminAuthError::RateLimited { retry_after_secs } => {
            AdminResult::RateLimited { retry_after_secs }
        }
        AdminAuthError::PayloadVerify(pe) => {
            warn!(op = op_for_log, error = ?pe, "payload verify failed at common layer");
            AdminResult::InvalidSignature
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

// ── Tappa 9.5 K6 — canary admin dispatch handlers ───────────────────

/// Rebuild the K3 detector's hot-path indexes from the K2
/// registry snapshot. Called by every successful canary
/// deploy / burn / refresh dispatch so the detector sees the
/// new state on the next inbound `Event::Fim` /
/// `Event::ProcessSpawn`. The `inode_resolver` closure
/// stats() each File/Credential canary path to populate the
/// inode_index — files that don't yet exist (deploy race)
/// fall back to the path-based exe_index pathway K3 already
/// uses (V1.0 pragmatism documented in K3 module doc).
/// The decoy path of a File or Credential canary.
pub fn canary_path(
    deployment: &common::wire::admin_signed_payload::CanaryDeploymentWire,
) -> Option<&str> {
    use common::wire::admin_signed_payload::CanaryDeploymentWire;
    match deployment {
        CanaryDeploymentWire::File { path, .. } | CanaryDeploymentWire::Credential { path, .. } => {
            Some(path)
        }
        _ => None,
    }
}

/// External audit DEC-001: watch a decoy's inode through the FIM. External
/// audit NN-AUD-120 (FIMP-008): `false` when it cannot be — the kernel
/// watch map refused it (full of entries that are never evicted, or
/// absent), or the FIM is not running — and the deploy is refused: a decoy
/// whose opens are not seen never trips, and the deploy used to answer
/// Success with only a WARN in the journal.
fn watch_decoy(state: &CanaryAdminState, key: common::wire::InodeKey, path: &str) -> bool {
    match &state.fim_watch {
        Some(watch) => {
            if watch.watch(key, path, crate::fim::drain::WatchClass::Decoy) {
                return true;
            }
            tracing::error!(
                path,
                "canary: the kernel watch map refused the decoy (full, or absent) — its opens \
                 would not be seen; deploy refused"
            );
            false
        }
        None => {
            tracing::error!(
                path,
                "canary: FIM is not running — the decoy's opens would not be seen; deploy refused"
            );
            false
        }
    }
}

/// What a decoy's inode was watched as before the deploy watched it: a
/// decoy written over a watched file (a credential canary at a watched
/// credential path) keeps that file's inode.
type PriorWatch = Option<(String, crate::fim::drain::WatchClass)>;

fn prior_watch(state: &CanaryAdminState, key: common::wire::InodeKey) -> PriorWatch {
    let watch = state.fim_watch.as_ref()?;
    Some((watch.path_map.lookup(&key)?, watch.path_map.class_of(&key)?))
}

/// Undo the watch of a decoy the deploy did not keep: the inode goes back
/// to what it was watched as, or stops being watched (the drain must not
/// name an inode the kernel does not report).
fn undo_decoy_watch(state: &CanaryAdminState, key: common::wire::InodeKey, prior: PriorWatch) {
    let Some(watch) = &state.fim_watch else {
        return;
    };
    match prior {
        Some((path, class)) => {
            let _ = watch.path_map.insert_as(key, path, class);
        }
        None => watch.unwatch(key),
    }
}

fn rebuild_canary_indexes(state: &CanaryAdminState) {
    // External audit DEC-003: the same rebuild the boot runs.
    let mut idx = state.indexes.lock();
    let reg = state.registry.lock();
    idx.rebuild_live(&reg);
}

/// dispatch_canary_deploy — verify 1-of-N quorum with
/// Role::CanaryManage, render template (for Credential
/// canaries) + write the canary file to disk (for
/// File/Credential), call Registry::deploy, rebuild indexes,
/// return the freshly-allocated canary_id. Per §12 Q1
/// EXPLICIT-PER-HOST lock-in: this is the ONLY way canaries
/// get on-host (no default deployments).
fn dispatch_canary_deploy(
    req: CanaryDeployRequest,
    auth: &ConnAuth<'_>,
    state: Option<&CanaryAdminState>,
    fps_out: &mut Vec<String>,
) -> CanaryDeployResponse {
    use common::wire::admin_signed_payload::OperationExtra;

    let server_now = now_unix_secs();
    let sigs: Vec<[u8; 64]> = req.signatures.iter().map(|s| s.signature).collect();
    let (_token, matched_fps) = match auth.verify_signed_payload_quorum(
        &req.payload,
        &sigs,
        1,
        &[Role::CanaryManage],
        OperationCode::CanaryDeploy,
        server_now,
    ) {
        Ok(t) => t,
        Err(e) => {
            return CanaryDeployResponse {
                result: map_admin_auth_error(e, "canary-deploy"),
                canary_id: String::new(),
            };
        }
    };
    *fps_out = matched_fps;

    let extra = match &req.payload.extra {
        OperationExtra::CanaryDeploy(e) => e.clone(),
        _ => {
            warn!("canary-deploy payload extra is not CanaryDeploy variant");
            return CanaryDeployResponse {
                result: AdminResult::UnknownOperation,
                canary_id: String::new(),
            };
        }
    };

    let state = match state {
        Some(s) => s,
        None => {
            warn!("canary-deploy: agent boot did not wire CanaryAdminState — rejecting");
            return CanaryDeployResponse {
                result: AdminResult::UnknownOperation,
                canary_id: String::new(),
            };
        }
    };

    let primary_fp = fps_out.first().cloned().unwrap_or_default();

    // Lab PR 163: a network canary trips on a connect to its address and
    // port (`canary::network`). One whose address is not an IP address
    // could never trip, and one where a listener on this host takes the
    // connections would trip on every client of that service.
    if let common::wire::admin_signed_payload::CanaryDeploymentWire::Network {
        bind_addr,
        bind_port,
    } = &extra.deployment
    {
        if let Err(why) = crate::canary::network::check_deployable(bind_addr, *bind_port) {
            warn!(
                signer_fp = %primary_fp,
                bind_addr = %bind_addr,
                bind_port = *bind_port,
                reason = %why,
                "canary-deploy: REFUSED — network canary"
            );
            return CanaryDeployResponse {
                result: AdminResult::UnknownOperation,
                canary_id: String::new(),
            };
        }
    }

    // For File + Credential types: render the file content +
    // write to the deployment path. The K3 detector matches
    // on the resulting inode (after rebuild_canary_indexes
    // stats it).
    let (decoy, content) = match materialise_canary_file(&extra.deployment, state) {
        Ok(m) => m,
        Err(e) => {
            warn!(
                error = %format!("{e:#}"),
                signer_fp = %primary_fp,
                "canary-deploy: REFUSED — file materialisation failed (path policy or I/O)"
            );
            return CanaryDeployResponse {
                result: AdminResult::UnknownOperation,
                canary_id: String::new(),
            };
        }
    };

    // External audit DEC-001: have the kernel report the decoy's opens,
    // and the drain name them — a decoy outside the FIM path list was
    // never watched, so it never tripped. NN-AUD-120: watched before it is
    // registered; one that cannot be watched is refused, not registered.
    let prior = decoy.and_then(|key| prior_watch(state, key));
    if let (Some(key), Some(path)) = (decoy, canary_path(&extra.deployment)) {
        if !watch_decoy(state, key, path) {
            undo_decoy_watch(state, key, prior.clone());
            warn!(
                signer_fp = %primary_fp,
                path,
                "canary-deploy: REFUSED — the decoy cannot be watched; the file written at the \
                 path is left in place (remove it, or deploy again once the FIM watches)"
            );
            return CanaryDeployResponse {
                result: AdminResult::UnknownOperation,
                canary_id: String::new(),
            };
        }
    }

    // Deploy via the K2 registry. Allocates the canary_id +
    // appends the Deploy row to the chain.
    let draft = CanaryTokenDraft {
        name: extra.name.clone(),
        canary_type: extra.canary_type,
        deployment: extra.deployment.clone(),
        deployed_by_fp: primary_fp.clone(),
        content,
    };
    let entry = {
        let mut reg = state.registry.lock();
        match reg.deploy(draft) {
            Ok(e) => e,
            Err(e) => {
                warn!(error = %e, "canary registry deploy failed");
                // not a canary: its decoy is not watched as one either
                if let Some(key) = decoy {
                    undo_decoy_watch(state, key, prior);
                }
                return CanaryDeployResponse {
                    result: AdminResult::UnknownOperation,
                    canary_id: String::new(),
                };
            }
        }
    };

    // Refresh the K3 detector's hot-path indexes so the new
    // canary is visible to the next inbound event.
    rebuild_canary_indexes(state);

    info!(
        target: "admin.canary_deploy",
        signer_fp = %primary_fp,
        canary_id = %entry.canary_id,
        canary_name = %entry.name,
        "canary deployed"
    );
    CanaryDeployResponse {
        result: AdminResult::Success,
        canary_id: entry.canary_id,
    }
}

/// Write the canary file to its deployment path: for a `Credential`
/// canary the K4 template of its `cred_family`, for a `File` canary
/// [`crate::canary::templates::render_file_body`]. Both from a fresh
/// random seed (external audit DEC-008: it used to be `<operator key
/// fingerprint>:<path>`, which printed the fingerprint into the decoy
/// and gave every host the same credential), with no marker in the bytes
/// (DEC-007: the File body used to name the product, the operator key
/// and the rule). Returns the decoy's inode and what it was written with
/// — its SHA-256 and seed, for the registry row (DEC-010). Process +
/// Network canaries write nothing: `(None, None)`.
fn materialise_canary_file(
    deployment: &common::wire::admin_signed_payload::CanaryDeploymentWire,
    state: &CanaryAdminState,
) -> Result<(Option<common::wire::InodeKey>, Option<DecoyContent>)> {
    use crate::canary::templates::{new_content_seed, render, render_file_body, CredFamily};
    use common::wire::admin_signed_payload::CanaryDeploymentWire;
    let seed = new_content_seed();
    let (path, body) = match deployment {
        CanaryDeploymentWire::File { path, .. } => (path, render_file_body(&seed)),
        CanaryDeploymentWire::Credential { path, cred_family } => {
            let family = CredFamily::from_wire(cred_family)
                .map_err(|e| anyhow::anyhow!("unknown cred_family `{cred_family}`: {e}"))?;
            let body = render(family, &seed, state.template_dir.as_deref())
                .map_err(|e| anyhow::anyhow!("rendering cred canary: {e}"))?;
            (path, body.into_bytes())
        }
        // Process + Network canaries: no file materialisation
        // at deploy time. The operator places a Process canary's
        // binary; a Network canary opens no listener (lab PR 163,
        // `canary::network`).
        CanaryDeploymentWire::Process { .. } | CanaryDeploymentWire::Network { .. } => {
            return Ok((None, None))
        }
    };
    // canary-path-1 / external audit DEC-002: policy check, then a walk
    // that follows no symlink (write_canary_checked).
    let decoy = crate::canary::path_policy::write_canary_checked(path, &body)?;
    let content = DecoyContent {
        contents_sha256: hex::encode(Sha256::digest(&body)),
        content_seed: Some(seed),
    };
    Ok((Some(decoy_key(&decoy)?), Some(content)))
}

/// `nn-admin canary refresh`: re-arm the canary, and write its File /
/// Credential decoy again from a new seed (external audit DEC-008: a
/// refresh used to leave a burned credential in place). The write goes
/// to the same inode when the decoy is there (`O_TRUNC`), else creates
/// it, and the decoy is watched before the Refresh row records it — as
/// a deploy (NN-AUD-120). A decoy that cannot be written or watched
/// refuses the refresh: the canary stays as recorded.
fn refresh_canary(
    state: &CanaryAdminState,
    canary_id: &str,
    refreshed_by_fp: &str,
) -> Result<CanaryToken> {
    let deployment = state
        .registry
        .lock()
        .get(canary_id)
        .ok_or(RegistryError::CanaryIdNotFound)?
        .deployment;
    let (decoy, content) = materialise_canary_file(&deployment, state)?;
    if let (Some(key), Some(path)) = (decoy, canary_path(&deployment)) {
        if !watch_decoy(state, key, path) {
            anyhow::bail!("the decoy written again at {path} cannot be watched");
        }
    }
    state
        .registry
        .lock()
        .refresh(canary_id, refreshed_by_fp, content)
}

/// External audit DEC-001: the kernel's `(dev, ino)` of the decoy just
/// written, read from its open file — no second path resolution.
fn decoy_key(decoy: &std::fs::File) -> Result<common::wire::InodeKey> {
    use std::os::unix::fs::MetadataExt;
    let m = decoy.metadata()?;
    Ok(common::wire::InodeKey {
        dev: crate::fim::attach::stat_dev_to_kernel_dev(m.dev()),
        ino: m.ino(),
    })
}

/// dispatch_canary_list — verify 1-of-N quorum with
/// `Role::CanaryRead`, read the chained registry log from
/// disk, return the JSONL body with the standard truncation
/// flag (same shape as `dispatch_fim_report`). External audit
/// NN-AUD-080: newest rows first, so a long history no longer
/// hides the latest deploy, trip or burn.
fn dispatch_canary_list(
    req: CanaryListRequest,
    auth: &ConnAuth<'_>,
    state: Option<&CanaryAdminState>,
    fps_out: &mut Vec<String>,
) -> CanaryListResponse {
    use common::wire::admin_signed_payload::OperationExtra;

    let server_now = now_unix_secs();
    let sigs: Vec<[u8; 64]> = req.signatures.iter().map(|s| s.signature).collect();
    let (_token, matched_fps) = match auth.verify_signed_payload_quorum(
        &req.payload,
        &sigs,
        1,
        &[Role::CanaryRead],
        OperationCode::CanaryList,
        server_now,
    ) {
        Ok(t) => t,
        Err(e) => {
            return CanaryListResponse {
                result: map_admin_auth_error(e, "canary-list"),
                entries_jsonl: String::new(),
                entries_count: 0,
                entries_truncated: false,
            };
        }
    };
    *fps_out = matched_fps;
    if !matches!(&req.payload.extra, OperationExtra::CanaryList(_)) {
        warn!("canary-list payload extra is not CanaryList variant");
        return CanaryListResponse {
            result: AdminResult::UnknownOperation,
            entries_jsonl: String::new(),
            entries_count: 0,
            entries_truncated: false,
        };
    }

    let log_path = match state {
        Some(s) => s.registry_log_path.clone(),
        None => {
            warn!("canary-list: agent boot did not wire CanaryAdminState");
            return CanaryListResponse {
                result: AdminResult::UnknownOperation,
                entries_jsonl: String::new(),
                entries_count: 0,
                entries_truncated: false,
            };
        }
    };
    let (entries_jsonl, entries_count, entries_truncated) =
        read_tail_jsonl(&log_path, None, None, usize::MAX);
    info!(
        target: "admin.canary_list",
        signer_fp = %fps_out.first().map(String::as_str).unwrap_or(""),
        entries = entries_count,
        truncated = entries_truncated,
        "canary list served"
    );
    CanaryListResponse {
        result: AdminResult::Success,
        entries_jsonl,
        entries_count,
        entries_truncated,
    }
}

/// dispatch_canary_burn — verify 1-of-N quorum with
/// `Role::CanaryManage`, call Registry::burn, rebuild indexes
/// so the K3 detector stops matching on the burned canary.
fn dispatch_canary_burn(
    req: CanaryBurnRequest,
    auth: &ConnAuth<'_>,
    state: Option<&CanaryAdminState>,
    fps_out: &mut Vec<String>,
) -> AdminResult {
    use common::wire::admin_signed_payload::OperationExtra;

    let server_now = now_unix_secs();
    let sigs: Vec<[u8; 64]> = req.signatures.iter().map(|s| s.signature).collect();
    let (_token, matched_fps) = match auth.verify_signed_payload_quorum(
        &req.payload,
        &sigs,
        1,
        &[Role::CanaryManage],
        OperationCode::CanaryBurn,
        server_now,
    ) {
        Ok(t) => t,
        Err(e) => return map_admin_auth_error(e, "canary-burn"),
    };
    *fps_out = matched_fps;

    let canary_id = match &req.payload.extra {
        OperationExtra::CanaryBurn(e) => e.canary_id.clone(),
        _ => {
            warn!("canary-burn payload extra is not CanaryBurn variant");
            return AdminResult::UnknownOperation;
        }
    };
    let state = match state {
        Some(s) => s,
        None => {
            warn!("canary-burn: agent boot did not wire CanaryAdminState");
            return AdminResult::UnknownOperation;
        }
    };
    let primary_fp = fps_out.first().cloned().unwrap_or_default();
    let (result, decoy) = {
        let mut reg = state.registry.lock();
        let decoy = reg
            .list()
            .iter()
            .find(|c| c.canary_id == canary_id)
            .and_then(|c| canary_path(&c.deployment).map(str::to_string));
        (reg.burn(&canary_id, &primary_fp), decoy)
    };
    match result {
        Ok(_) => {
            // External audit DEC-001: a burned decoy is no longer watched.
            if let (Some(path), Some(watch)) = (decoy, &state.fim_watch) {
                if let Ok(key) = crate::fim::attach::key_for_path(std::path::Path::new(&path)) {
                    watch.unwatch(key);
                }
            }
            rebuild_canary_indexes(state);
            info!(
                target: "admin.canary_burn",
                signer_fp = %primary_fp,
                canary_id = %canary_id,
                "canary burned"
            );
            AdminResult::Success
        }
        Err(e) => {
            // Distinguish "canary not found" from systemic
            // errors. K2 surfaces CanaryIdNotFound as a typed
            // variant; map to a recognisable AdminResult so
            // the operator gets actionable feedback.
            if let Some(RegistryError::CanaryIdNotFound) = e.downcast_ref::<RegistryError>() {
                warn!(canary_id = %canary_id, "canary-burn: canary_id not found");
                AdminResult::UnknownOperation
            } else {
                warn!(error = %e, "canary registry burn failed");
                AdminResult::UnknownOperation
            }
        }
    }
}

/// dispatch_canary_refresh — verify 1-of-N quorum with
/// `Role::CanaryManage`, write the decoy again and call
/// Registry::refresh ([`refresh_canary`]), rebuild indexes (the
/// decoy may be a new inode).
fn dispatch_canary_refresh(
    req: CanaryRefreshRequest,
    auth: &ConnAuth<'_>,
    state: Option<&CanaryAdminState>,
    fps_out: &mut Vec<String>,
) -> AdminResult {
    use common::wire::admin_signed_payload::OperationExtra;

    let server_now = now_unix_secs();
    let sigs: Vec<[u8; 64]> = req.signatures.iter().map(|s| s.signature).collect();
    let (_token, matched_fps) = match auth.verify_signed_payload_quorum(
        &req.payload,
        &sigs,
        1,
        &[Role::CanaryManage],
        OperationCode::CanaryRefresh,
        server_now,
    ) {
        Ok(t) => t,
        Err(e) => return map_admin_auth_error(e, "canary-refresh"),
    };
    *fps_out = matched_fps;

    let canary_id = match &req.payload.extra {
        OperationExtra::CanaryRefresh(e) => e.canary_id.clone(),
        _ => {
            warn!("canary-refresh payload extra is not CanaryRefresh variant");
            return AdminResult::UnknownOperation;
        }
    };
    let state = match state {
        Some(s) => s,
        None => {
            warn!("canary-refresh: agent boot did not wire CanaryAdminState");
            return AdminResult::UnknownOperation;
        }
    };
    let primary_fp = fps_out.first().cloned().unwrap_or_default();
    let result = refresh_canary(state, &canary_id, &primary_fp);
    match result {
        Ok(_) => {
            rebuild_canary_indexes(state);
            info!(
                target: "admin.canary_refresh",
                signer_fp = %primary_fp,
                canary_id = %canary_id,
                "canary refreshed (tripped flag cleared; a file decoy written again)"
            );
            AdminResult::Success
        }
        Err(e) => {
            if let Some(RegistryError::CanaryIdNotFound) = e.downcast_ref::<RegistryError>() {
                AdminResult::UnknownOperation
            } else {
                warn!(error = %format!("{e:#}"), "canary refresh failed");
                AdminResult::UnknownOperation
            }
        }
    }
}

// ── Tappa 10 N7 — net admin dispatches ────────────────────────────
//
// Four dispatches mirroring the FIM C6 + canary K6 shape:
//   * Auth via `verify_signed_payload_quorum` (1-of-N per §13 Q6).
//   * Op-extra-variant defensive check.
//   * Emit audit-grade `info!` line with the matched signer fp.
//   * External audit NN-AUD-081: every verb answers from the
//     chained logs the net drain writes (`netflow.jsonl`,
//     `netflow_listeners.jsonl`, at the paths in
//     [`AdminReadPaths`]); none answers an empty Success
//     without having read them.

/// Default on-disk location of the chained NetFlow log (design
/// §4.4 + §10). The Tappa 10 N8 deploy commit drops a zero-byte
/// placeholder here via `install.sh` + `bootstrap_netflow_log` at
/// agent startup. `dispatch_net_flows` tolerates the file being
/// absent — returns empty body + 0 count without erroring.
pub const DEFAULT_NETFLOW_JSONL_PATH: &str = "/var/lib/northnarrow/netflow.jsonl";

/// `net flows`: the newest rows of the netflow log at
/// `--netflow-file` (external audit NN-AUD-082), active file then
/// archives, newest first (NN-AUD-080).
fn dispatch_net_flows(
    req: NetFlowsRequest,
    auth: &ConnAuth<'_>,
    read_paths: &AdminReadPaths,
    fps_out: &mut Vec<String>,
) -> NetFlowsResponse {
    use common::wire::admin_signed_payload::NetFlowsExtra;

    let server_now = now_unix_secs();
    let sigs: Vec<[u8; 64]> = req.signatures.iter().map(|s| s.signature).collect();
    let (_token, matched_fps) = match auth.verify_signed_payload_quorum(
        &req.payload,
        &sigs,
        1,
        &[Role::NetRead],
        OperationCode::NetFlows,
        server_now,
    ) {
        Ok(t) => t,
        Err(e) => {
            return NetFlowsResponse {
                result: map_admin_auth_error(e, "net-flows"),
                entries_jsonl: String::new(),
                entries_count: 0,
                entries_truncated: false,
            };
        }
    };
    *fps_out = matched_fps;

    let since = match &req.payload.extra {
        OperationExtra::NetFlows(NetFlowsExtra { since_unix_ts }) => *since_unix_ts,
        _ => {
            warn!("net-flows payload extra is not NetFlows variant");
            return NetFlowsResponse {
                result: AdminResult::UnknownOperation,
                entries_jsonl: String::new(),
                entries_count: 0,
                entries_truncated: false,
            };
        }
    };

    let (entries_jsonl, entries_count, entries_truncated) =
        read_tail_jsonl(&read_paths.netflow, since, None, usize::MAX);
    info!(
        target: "admin.net_flows",
        signer_fp = %fps_out.first().map(String::as_str).unwrap_or(""),
        entries = entries_count,
        truncated = entries_truncated,
        "net flows served"
    );
    NetFlowsResponse {
        result: AdminResult::Success,
        entries_jsonl,
        entries_count,
        entries_truncated,
    }
}

/// An auth-failure / empty [`DetectionsResponse`] carrying `result`.
/// Also used for the "filter recognised nothing" success path.
fn empty_detections(result: AdminResult) -> DetectionsResponse {
    DetectionsResponse {
        result,
        entries_jsonl: String::new(),
        entries_count: 0,
        entries_truncated: false,
    }
}

/// Tappa 9.0.b — handle one [`DetectionsRequest`]. Verifies the
/// 1-of-N signed-payload quorum carrying [`Role::TelemetryRead`]
/// (read != control: this NEVER accepts a control-only key, and the
/// read-only key it does accept can never `unlock`), then reads the
/// last N persisted detections from the chainlog — newest-first, with
/// the operator's optional filters applied — and returns them as a
/// JSONL body. The read is bounded (see
/// [`crate::detection_store::read_last_n`]); the body is capped at the
/// wire soft cap and `entries_truncated` is set if the matching set
/// would overflow the frame. Like the FIM/net read verbs, the store
/// path is the build-default constant, so no extra serve-time state is
/// threaded.
fn dispatch_detections(
    req: DetectionsRequest,
    auth: &ConnAuth<'_>,
    det_state: Option<&DetectionAdminState>,
    fps_out: &mut Vec<String>,
) -> DetectionsResponse {
    use crate::detection_store::{self, DetectionFilter};
    const SOFT_CAP: usize = MAX_FRAME_BODY / 2;

    let server_now = now_unix_secs();
    let sigs: Vec<[u8; 64]> = req.signatures.iter().map(|s| s.signature).collect();
    let (_token, matched_fps) = match auth.verify_signed_payload_quorum(
        &req.payload,
        &sigs,
        1, // 1-of-N: a read verb, like fim-report / net-flows.
        // Role::TelemetryRead — a Triage key also satisfies this via
        // the 9.0.c subsumption (triage subsumes read), so a triage-
        // only key can read the detections it triages.
        &[Role::TelemetryRead],
        OperationCode::Detections,
        server_now,
    ) {
        Ok(t) => t,
        Err(e) => return empty_detections(map_admin_auth_error(e, "detections")),
    };
    *fps_out = matched_fps;

    let extra = match &req.payload.extra {
        OperationExtra::Detections(e) => e,
        _ => {
            warn!("detections payload extra is not Detections variant");
            return empty_detections(AdminResult::UnknownOperation);
        }
    };

    // Build the typed filter. A provided-but-unrecognised enum filter
    // can match nothing, so we short-circuit to an empty success
    // rather than silently dropping the constraint and widening the
    // result (the CLI restricts these to valid values; this is the
    // defensive server-side path).
    let mut filter = DetectionFilter {
        since_unix: extra.since_unix_ts.map(|s| s as i64),
        until_unix: extra.until_unix_ts.map(|s| s as i64),
        comm_substr: extra.path.clone().filter(|s| !s.is_empty()),
        ..Default::default()
    };
    if let Some(s) = &extra.min_severity {
        match detection_store::parse_severity_filter(s) {
            Some(v) => filter.min_severity = Some(v),
            None => {
                warn!(value = %s, "detections: unrecognised min_severity filter — empty result");
                return empty_detections(AdminResult::Success);
            }
        }
    }
    if let Some(s) = &extra.status {
        match crate::detection_store::DetectionStatus::parse_filter(s) {
            Some(v) => filter.status = Some(v),
            None => {
                warn!(value = %s, "detections: unrecognised status filter — empty result");
                return empty_detections(AdminResult::Success);
            }
        }
    }
    if let Some(s) = &extra.sensor {
        match crate::detection_store::Sensor::parse_filter(s) {
            Some(v) => filter.sensor = Some(v),
            None => {
                warn!(value = %s, "detections: unrecognised sensor filter — empty result");
                return empty_detections(AdminResult::Success);
            }
        }
    }

    let limit = if extra.limit == 0 {
        detection_store::DEFAULT_DETECTIONS_LIMIT
    } else {
        (extra.limit as usize).min(detection_store::MAX_DETECTIONS_LIMIT)
    };

    // Resolve the store paths from the wired state when present (honours
    // a custom --detections-file); fall back to the build defaults so
    // the legacy/test path (no DetectionAdminState) still reads the
    // canonical location — an absent file simply yields no records / no
    // overlay. The read OVERLAYS the event-sourced current status from
    // the status-event chain onto each record (9.0.c).
    let (detections_path, status_events_path) = match det_state {
        Some(s) => (s.detections_path.clone(), s.status_events_path.clone()),
        None => (
            std::path::PathBuf::from(detection_store::DEFAULT_DETECTIONS_LOG_PATH),
            std::path::PathBuf::from(detection_store::DEFAULT_STATUS_EVENTS_LOG_PATH),
        ),
    };
    // External audit NN-AUD-112: the rows served are verified with the
    // agent key (the status log holds it); a row that does not verify is
    // left out, logged and recorded in the signed chain.
    let pubkey = det_state.map(|s| s.status_log.lock().verifying_key());
    let (records, unverified) = detection_store::read_last_n_overlaid_verified(
        &detections_path,
        &status_events_path,
        limit,
        &filter,
        pubkey.as_ref(),
    );
    if unverified > 0 {
        crate::chain_anchor::report_unverified_rows("detections", &detections_path, unverified);
    }

    // Serialise newest-first, bounding the body at the wire soft cap.
    // The records are already newest-first, so truncation drops the
    // oldest of the matching set — a dashboard wants the freshest.
    let mut entries_jsonl = String::new();
    let mut entries_count = 0u32;
    let mut entries_truncated = false;
    for record in &records {
        let Ok(line) = serde_json::to_string(record) else {
            continue;
        };
        if entries_jsonl.len() + line.len() + 1 > SOFT_CAP {
            entries_truncated = true;
            break;
        }
        entries_jsonl.push_str(&line);
        entries_jsonl.push('\n');
        entries_count += 1;
    }
    info!(
        target: "admin.detections",
        signer_fp = %fps_out.first().map(String::as_str).unwrap_or(""),
        entries = entries_count,
        truncated = entries_truncated,
        "detections served"
    );
    DetectionsResponse {
        result: AdminResult::Success,
        entries_jsonl,
        entries_count,
        entries_truncated,
    }
}

/// An auth-failure / not-found / unavailable
/// [`DetectionSetStatusResponse`] carrying `result`, echoing the
/// requested `id`, with an empty status string.
fn fail_set_status(result: AdminResult, id: u64) -> DetectionSetStatusResponse {
    DetectionSetStatusResponse {
        result,
        id,
        new_status: String::new(),
        persist_failed: false,
    }
}

/// Tappa 9.0.c — handle one [`DetectionSetStatusRequest`]. Verifies the
/// 1-of-N signed-payload quorum carrying [`Role::Triage`] (control
/// roles do NOT implicitly authorise set-status, and a
/// telemetry-read-only key is RoleDenied — read != triage), validates
/// the target id against the detection store's max id (cheap
/// `1 <= id <= max` guard; an out-of-range id is a clean "not found",
/// folded into `UnknownOperation` like the K6 canary-burn contract),
/// parses the target status string, then appends a signed
/// [`StatusEvent`] to the status-event chain SYNCHRONOUSLY (triage is
/// human-initiated + low-frequency, not the hot path — no off-thread
/// writer). The detection chain (`detections.jsonl`) is never mutated;
/// status is event-sourced and derived at read time.
fn dispatch_detection_set_status(
    req: DetectionSetStatusRequest,
    auth: &ConnAuth<'_>,
    det_state: Option<&DetectionAdminState>,
    client: &AuditClient,
    fps_out: &mut Vec<String>,
) -> DetectionSetStatusResponse {
    use crate::detection_store::{self, DetectionStatus};

    // Recover the requested id up front so every reply (including auth
    // failures) echoes it. Only meaningful for the matching extra
    // variant; 0 otherwise (an op/extra mismatch is rejected anyway).
    let req_id = match &req.payload.extra {
        OperationExtra::DetectionSetStatus(e) => e.id,
        _ => 0,
    };

    let server_now = now_unix_secs();
    let sigs: Vec<[u8; 64]> = req.signatures.iter().map(|s| s.signature).collect();
    let (_token, matched_fps) = match auth.verify_signed_payload_quorum(
        &req.payload,
        &sigs,
        1, // 1-of-N: a single triage operator suffices.
        &[Role::Triage],
        OperationCode::DetectionSetStatus,
        server_now,
    ) {
        Ok(t) => t,
        Err(e) => return fail_set_status(map_admin_auth_error(e, "detection_set_status"), req_id),
    };
    *fps_out = matched_fps;

    let extra = match &req.payload.extra {
        OperationExtra::DetectionSetStatus(e) => e,
        _ => {
            warn!("detection-set-status payload extra is not DetectionSetStatus variant");
            return fail_set_status(AdminResult::UnknownOperation, req_id);
        }
    };

    // The status-event store must be wired (it isn't on a degraded boot
    // where the detection store failed to open). Without it set-status
    // cannot persist — surface UnknownOperation (mirrors the canary
    // "registry None → UnknownOperation" degraded contract).
    let Some(state) = det_state else {
        warn!("detection-set-status: detection store not wired this boot");
        return fail_set_status(AdminResult::UnknownOperation, extra.id);
    };

    // Parse the target status. `open` and unknown strings are rejected
    // (`open` is the initial state, not a settable triage target).
    let Some(new_status) = DetectionStatus::parse_settable(&extra.new_status) else {
        warn!(value = %extra.new_status, "detection-set-status: invalid target status");
        return fail_set_status(AdminResult::UnknownOperation, extra.id);
    };

    // Validity guard: the id must reference an existing detection.
    // Cheap `1 <= id <= max` check (full existence scan deferred). An
    // out-of-range id folds into UnknownOperation → the CLI renders it
    // as a clean "detection not found".
    let max_id = detection_store::max_detection_id(&state.detections_path);
    if extra.id == 0 || extra.id > max_id {
        warn!(
            id = extra.id,
            max_id, "detection-set-status: id out of range (not found)"
        );
        return fail_set_status(AdminResult::UnknownOperation, extra.id);
    }

    // Append the StatusEvent synchronously (append + fsync happen inside
    // the chainlog). The principal is the SO_PEERCRED admin caller —
    // the local operator process that initiated the change.
    let event = StatusEvent {
        detection_id: extra.id,
        new_status,
        ts: detection_store::now_ts(),
        principal: Principal {
            pid: client.pid,
            comm: client.comm.clone(),
            uid: client.uid,
            ppid: None,
        },
        note: extra.note.clone().filter(|s| !s.is_empty()),
    };
    {
        let mut log = state.status_log.lock();
        if let Err(e) = log.append(event) {
            warn!(
                error = %e,
                id = extra.id,
                "detection-set-status: status-event append failed (change not persisted)"
            );
            // chain-persist-1: flag the persistence failure so the CLI
            // can tell it apart from "not found" (same AdminResult).
            let mut resp = fail_set_status(AdminResult::UnknownOperation, extra.id);
            resp.persist_failed = true;
            return resp;
        }
    }
    info!(
        target: "admin.detection_set_status",
        signer_fp = %fps_out.first().map(String::as_str).unwrap_or(""),
        id = extra.id,
        new_status = new_status.as_str(),
        "detection triage status updated",
    );
    DetectionSetStatusResponse {
        result: AdminResult::Success,
        id: extra.id,
        new_status: new_status.as_str().to_string(),
        persist_failed: false,
    }
}

/// `net listeners`: the newest rows of the listener log at
/// `--netflow-listeners-file` — one row per `listen()` the agent saw
/// (`inet_csk_listen_start`), newest first. Listen events, not a snapshot
/// of the sockets open now: a closed listener stays in the log. External
/// audit NN-AUD-081: this verb answered Success with an empty body while
/// the log was being written.
fn dispatch_net_listeners(
    req: NetListenersRequest,
    auth: &ConnAuth<'_>,
    read_paths: &AdminReadPaths,
    fps_out: &mut Vec<String>,
) -> NetListenersResponse {
    let server_now = now_unix_secs();
    let sigs: Vec<[u8; 64]> = req.signatures.iter().map(|s| s.signature).collect();
    let (_token, matched_fps) = match auth.verify_signed_payload_quorum(
        &req.payload,
        &sigs,
        1,
        &[Role::NetRead],
        OperationCode::NetListeners,
        server_now,
    ) {
        Ok(t) => t,
        Err(e) => {
            return NetListenersResponse {
                result: map_admin_auth_error(e, "net-listeners"),
                entries_jsonl: String::new(),
                entries_count: 0,
                entries_truncated: false,
            };
        }
    };
    *fps_out = matched_fps;

    if !matches!(&req.payload.extra, OperationExtra::NetListeners(_)) {
        warn!("net-listeners payload extra is not NetListeners variant");
        return NetListenersResponse {
            result: AdminResult::UnknownOperation,
            entries_jsonl: String::new(),
            entries_count: 0,
            entries_truncated: false,
        };
    }

    let (entries_jsonl, entries_count, entries_truncated) =
        read_tail_jsonl(&read_paths.netflow_listeners, None, None, usize::MAX);
    info!(
        target: "admin.net_listeners",
        signer_fp = %fps_out.first().map(String::as_str).unwrap_or(""),
        entries = entries_count,
        truncated = entries_truncated,
        "net listeners served"
    );
    NetListenersResponse {
        result: AdminResult::Success,
        entries_jsonl,
        entries_count,
        entries_truncated,
    }
}

/// The fields of a netflow row the `net resolve` / `net fingerprint`
/// filters look at (serde ignores the others).
#[derive(serde::Deserialize)]
struct NetflowRowView {
    #[serde(default)]
    ts: String,
    #[serde(default)]
    flow_id: String,
    #[serde(default)]
    dst_addr: String,
    resolved_hostname: Option<String>,
}

fn netflow_row_view(line: &str) -> Option<NetflowRowView> {
    serde_json::from_str(line).ok()
}

/// `net resolve <ip>`: the hostname the agent attributed (DNS cache, same
/// process) to the newest retained netflow row whose destination is `ip`,
/// and when that row was written. External audit NN-AUD-081: this verb
/// answered Success with no name without reading anything; it now answers
/// from the netflow log, and `qname: None` means no retained flow to that
/// address carries a name. An address that does not parse is refused.
fn dispatch_net_resolve(
    req: NetResolveRequest,
    auth: &ConnAuth<'_>,
    read_paths: &AdminReadPaths,
    fps_out: &mut Vec<String>,
) -> NetResolveResponse {
    use common::wire::admin_signed_payload::NetResolveExtra;

    let server_now = now_unix_secs();
    let sigs: Vec<[u8; 64]> = req.signatures.iter().map(|s| s.signature).collect();
    let (_token, matched_fps) = match auth.verify_signed_payload_quorum(
        &req.payload,
        &sigs,
        1,
        &[Role::NetRead],
        OperationCode::NetResolve,
        server_now,
    ) {
        Ok(t) => t,
        Err(e) => {
            return NetResolveResponse {
                result: map_admin_auth_error(e, "net-resolve"),
                qname: None,
                queried_at_unix_ts: None,
            };
        }
    };
    *fps_out = matched_fps;

    let refused = NetResolveResponse {
        result: AdminResult::UnknownOperation,
        qname: None,
        queried_at_unix_ts: None,
    };
    let ip_query = match &req.payload.extra {
        OperationExtra::NetResolve(NetResolveExtra { ip }) => ip.clone(),
        _ => {
            warn!("net-resolve payload extra is not NetResolve variant");
            return refused;
        }
    };
    let Ok(target) = ip_query.trim().parse::<std::net::IpAddr>() else {
        warn!(ip = %ip_query, "net-resolve: not an IP address");
        return refused;
    };
    let target = target.to_canonical();
    // Substring pre-filter, then the parsed check (an IPv4 target also
    // matches an IPv4-mapped IPv6 destination).
    let needle = target.to_string();
    let keep = |line: &str| {
        line.contains(&needle)
            && netflow_row_view(line).is_some_and(|r| {
                r.dst_addr
                    .parse::<std::net::IpAddr>()
                    .is_ok_and(|a| a.to_canonical() == target)
                    && r.resolved_hostname
                        .as_deref()
                        .is_some_and(|h| !h.is_empty())
            })
    };
    let (body, _, _) = read_tail_jsonl(&read_paths.netflow, None, Some(&keep), 1);
    let newest = body.lines().next().and_then(netflow_row_view);
    let qname = newest.as_ref().and_then(|r| r.resolved_hostname.clone());
    let queried_at_unix_ts = newest.as_ref().and_then(|r| {
        chrono::DateTime::parse_from_rfc3339(&r.ts)
            .ok()
            .and_then(|t| u64::try_from(t.timestamp()).ok())
    });
    info!(
        target: "admin.net_resolve",
        signer_fp = %fps_out.first().map(String::as_str).unwrap_or(""),
        ip = %target,
        found = qname.is_some(),
        "net resolve served"
    );
    NetResolveResponse {
        result: AdminResult::Success,
        qname,
        queried_at_unix_ts,
    }
}

/// `net fingerprint <flow_id>`: the netflow rows of that flow (active
/// file and archives, newest first), with their `ja3` / `ja4` / `sni`.
/// External audit NN-AUD-081: this verb answered Success with an empty
/// body without reading anything. The rows are returned whether or not
/// they carry a fingerprint: the ClientHello capture that fills those
/// fields is not wired (`FlowTracker::attach_tls`), so a filter on them
/// would always answer empty. A null field says "not captured"; an empty
/// body says the flow is not in the retained log. A flow id that is not
/// 1 to 64 hex digits is refused.
fn dispatch_net_fingerprint(
    req: NetFingerprintRequest,
    auth: &ConnAuth<'_>,
    read_paths: &AdminReadPaths,
    fps_out: &mut Vec<String>,
) -> NetFingerprintResponse {
    use common::wire::admin_signed_payload::NetFingerprintExtra;

    let server_now = now_unix_secs();
    let sigs: Vec<[u8; 64]> = req.signatures.iter().map(|s| s.signature).collect();
    let (_token, matched_fps) = match auth.verify_signed_payload_quorum(
        &req.payload,
        &sigs,
        1,
        &[Role::NetRead],
        OperationCode::NetFingerprint,
        server_now,
    ) {
        Ok(t) => t,
        Err(e) => {
            return NetFingerprintResponse {
                result: map_admin_auth_error(e, "net-fingerprint"),
                entries_jsonl: String::new(),
                entries_count: 0,
                entries_truncated: false,
            };
        }
    };
    *fps_out = matched_fps;

    let refused = NetFingerprintResponse {
        result: AdminResult::UnknownOperation,
        entries_jsonl: String::new(),
        entries_count: 0,
        entries_truncated: false,
    };
    let flow_id = match &req.payload.extra {
        OperationExtra::NetFingerprint(NetFingerprintExtra { flow_id }) => flow_id.clone(),
        _ => {
            warn!("net-fingerprint payload extra is not NetFingerprint variant");
            return refused;
        }
    };
    let flow_id = flow_id.trim().to_ascii_lowercase();
    if flow_id.is_empty() || flow_id.len() > 64 || !flow_id.bytes().all(|b| b.is_ascii_hexdigit()) {
        warn!(flow_id = %flow_id, "net-fingerprint: flow id is not hex");
        return refused;
    }
    let keep = |line: &str| {
        line.contains(&flow_id) && netflow_row_view(line).is_some_and(|r| r.flow_id == flow_id)
    };
    let (entries_jsonl, entries_count, entries_truncated) =
        read_tail_jsonl(&read_paths.netflow, None, Some(&keep), usize::MAX);
    info!(
        target: "admin.net_fingerprint",
        signer_fp = %fps_out.first().map(String::as_str).unwrap_or(""),
        flow_id = %flow_id,
        entries = entries_count,
        truncated = entries_truncated,
        "net fingerprint served"
    );
    NetFingerprintResponse {
        result: AdminResult::Success,
        entries_jsonl,
        entries_count,
        entries_truncated,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::admin_cli::{run_status, run_unlock, run_verify_keys};
    use common::posture_types::PostureKind;
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;
    use std::io::Write;
    use std::path::PathBuf;
    use std::time::Duration;
    use tempfile::TempDir;
    use tokio::task::JoinHandle;

    /// Spin up a tokio task running the admin server against a tempdir
    /// socket. Returns the socket path, the JoinHandle (for assertion
    /// of liveness), and the Arcs the server is using.
    struct ServerHarness {
        _dir: TempDir,
        socket: PathBuf,
        _task: JoinHandle<()>,
        posture: Arc<PostureMachine>,
        isolator: Arc<NetworkIsolator>,
    }

    fn rules_path() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("configs")
            .join("combat-rules.v4")
    }

    async fn spawn_server(signing: &SigningKey) -> ServerHarness {
        let dir = TempDir::new().unwrap();
        let socket = dir.path().join("admin.sock");
        let rules = rules_path();

        // Build AdminAuth from a tempfile holding the signing key's
        // public half; use a 5 s rate-limit window for the rate-limit
        // test (default 5 min would still work but slows nothing down
        // since we're below threshold).
        let pub_path = dir.path().join("admin.pub");
        std::fs::write(
            &pub_path,
            format!("{}\n", hex::encode(signing.verifying_key().to_bytes())),
        )
        .unwrap();
        let auth = Arc::new(AdminAuth::load(&pub_path).unwrap());

        // NetworkIsolator with mock binaries — no root needed.
        let isolator = Arc::new(
            crate::anti_tamper::network_isolate::NetworkIsolator::new(rules.clone()).unwrap(),
        );

        let posture = Arc::new(PostureMachine::new());

        let auth_c = Arc::clone(&auth);
        let posture_c = Arc::clone(&posture);
        let isolator_c = Arc::clone(&isolator);
        let socket_c = socket.clone();
        let task = tokio::spawn(async move {
            let _ = serve(socket_c, auth_c, posture_c, isolator_c).await;
        });

        // Spin until the socket file appears — bind happens inside
        // serve(), and tests connecting too early would race the
        // accept() loop.
        for _ in 0..50 {
            if socket.exists() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }

        ServerHarness {
            _dir: dir,
            socket,
            _task: task,
            posture,
            isolator,
        }
    }

    fn write_priv_key(dir: &TempDir, signing: &SigningKey) -> PathBuf {
        let p = dir.path().join("admin.key");
        let mut f = std::fs::File::create(&p).unwrap();
        writeln!(f, "{}", hex::encode(signing.to_bytes())).unwrap();
        // The CLI refuses a key group or others can read (external audit
        // AUT-002), as `nn-admin init` never writes one.
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600)).unwrap();
        p
    }

    #[tokio::test]
    async fn status_request_round_trip() {
        let signing = SigningKey::generate(&mut OsRng);
        let h = spawn_server(&signing).await;
        // run_status is sync — call via spawn_blocking so we don't
        // block the test's tokio worker on the unix socket read.
        let socket = h.socket.clone();
        let out = tokio::task::spawn_blocking(move || run_status(&socket).unwrap())
            .await
            .unwrap();
        assert_eq!(out.posture, PostureKind::Observing);
        assert!(!out.network_isolation_engaged);
        assert!(out.last_admin_action_secs_ago.is_none());
    }

    #[tokio::test]
    async fn end_to_end_unlock_cycle_clears_combat() {
        let signing = SigningKey::generate(&mut OsRng);
        let h = spawn_server(&signing).await;

        // Drive posture to Combat via a real ConfirmedIntrusion event.
        // We can't fire the engage hook because PostureMachine::new()
        // wires no hook in this test, so we set isolator state by
        // hand to mirror what main.rs would do.
        // (NetworkIsolator has no force-engage API; use the public
        // engage() with the mock binaries instead — the harness was
        // built with the real rules path + system iptables-restore,
        // which on a test machine without root will fail. Skip this
        // particular test if the engage shell-out fails.)
        if h.isolator.engage().is_err() {
            eprintln!("iptables-restore unavailable / not root; skipping end-to-end test");
            return;
        }
        // Hand-build a ConfirmedIntrusion-class event (exec from /tmp,
        // non-root UID) — the posture trigger detector classifies any
        // such exec as ConfirmedIntrusion and slams the machine into
        // Combat. posture/triggers/testutil is `pub(super)`-scoped so
        // not reachable from this module; hand-rolled is fine for one
        // event.
        use common::Event;
        let intrusion = Event::ProcessSpawn {
            pid: 100,
            ppid: 1,
            uid: 1000,
            gid: 1000,
            comm: "evil".into(),
            filename: "/tmp/payload".into(),
            timestamp_ns: 500,
            argv: Vec::new(),
            parent_comm: String::new(),
            parent_start_ns: 0,
            start_ns: 0,
            parent_is_kthread: false,
            exe: Default::default(),
        };
        h.posture.observe(&intrusion, &[]);
        assert_eq!(h.posture.current_kind(), PostureKind::Combat);

        let priv_path = write_priv_key(&h._dir, &signing);
        let socket = h.socket.clone();
        let outcome = tokio::task::spawn_blocking(move || run_unlock(&socket, &priv_path).unwrap())
            .await
            .unwrap();
        assert!(matches!(outcome, crate::admin_cli::UnlockOutcome::Success));
        // Posture dropped to Alerted; isolator state left engaged
        // because we don't wire a release hook in this harness
        // (commit #6 main.rs wiring does that — this test exercises
        // the protocol layer, not the full hook chain).
        assert_eq!(h.posture.current_kind(), PostureKind::Alerted);
    }

    #[tokio::test]
    async fn unlock_invalid_signature_propagates() {
        let signing = SigningKey::generate(&mut OsRng);
        let h = spawn_server(&signing).await;

        // Privkey on disk is for a DIFFERENT keypair → server
        // rejects the signature.
        let other = SigningKey::generate(&mut OsRng);
        let priv_path = write_priv_key(&h._dir, &other);
        let socket = h.socket.clone();
        let outcome = tokio::task::spawn_blocking(move || run_unlock(&socket, &priv_path).unwrap())
            .await
            .unwrap();
        assert!(matches!(
            outcome,
            crate::admin_cli::UnlockOutcome::InvalidSignature
        ));
    }

    #[tokio::test]
    async fn server_recreates_stale_socket_on_startup() {
        // Pre-create a stale socket file on disk; serve() must
        // unlink it before bind() rather than fail with EADDRINUSE.
        let dir = TempDir::new().unwrap();
        let socket = dir.path().join("admin.sock");
        std::fs::File::create(&socket).unwrap(); // not a real socket — bind would fail
        assert!(socket.exists());

        let signing = SigningKey::generate(&mut OsRng);
        let pub_path = dir.path().join("admin.pub");
        std::fs::write(
            &pub_path,
            format!("{}\n", hex::encode(signing.verifying_key().to_bytes())),
        )
        .unwrap();
        let auth = Arc::new(AdminAuth::load(&pub_path).unwrap());
        let isolator = Arc::new(NetworkIsolator::new(rules_path()).unwrap());
        let posture = Arc::new(PostureMachine::new());

        let socket_c = socket.clone();
        let task = tokio::spawn(async move {
            let _ = serve(socket_c, auth, posture, isolator).await;
        });

        // Wait for the new socket to appear (means stale-unlink ran).
        for _ in 0..50 {
            if socket.exists() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert!(socket.exists());

        // Smoke check: a status round-trip works. The socket path
        // appears at bind(2), a few instructions BEFORE listen(2): a
        // connect in that window gets ECONNREFUSED, so retry briefly
        // instead of unwrapping the first attempt (flake seen under
        // parallel test load).
        let socket_c = socket.clone();
        let out = tokio::task::spawn_blocking(move || {
            let mut last = None;
            for _ in 0..50 {
                match run_status(&socket_c) {
                    Ok(out) => return out,
                    Err(e) => {
                        last = Some(e);
                        std::thread::sleep(Duration::from_millis(100));
                    }
                }
            }
            panic!("status round-trip never succeeded: {last:?}");
        })
        .await
        .unwrap();
        assert_eq!(out.posture, PostureKind::Observing);

        task.abort();
    }

    #[test]
    fn verify_keys_helper_compiles_and_runs() {
        // Sanity: the admin_cli helper is reachable from this test
        // module (cross-module compile check). No real wiring needed.
        let dir = TempDir::new().unwrap();
        let p = dir.path().join("admin.pub");
        std::fs::write(&p, "# comment only\n").unwrap();
        let out = run_verify_keys(&p).expect("verify");
        assert!(out.fingerprints.is_empty());
    }

    // ── A7: signed shutdown — mock-server e2e ──────────────────────

    use common::wire::admin_protocol::{AdminResult, KeyedSignature, ShutdownRequest};
    use common::wire::admin_signed_payload::{sign, SignedPayload};

    /// Spin up a [`serve_with_marker_path`] task plus two
    /// admin keypairs, both holding `Role::Shutdown` so the
    /// 2-of-N quorum is satisfiable. Returns:
    /// - the socket path,
    /// - the marker file path (in the tempdir, NOT the
    ///   process-global `/run/northnarrow/`),
    /// - both signing keys + their pubkeys,
    /// - the bootstrapped `agent_id`,
    /// - the JoinHandle so the test can cancel the server.
    async fn spawn_shutdown_server() -> (
        TempDir,
        PathBuf,
        PathBuf,
        SigningKey,
        SigningKey,
        [u8; 16],
        JoinHandle<()>,
    ) {
        let dir = TempDir::new().unwrap();
        let socket = dir.path().join("admin.sock");
        let marker_path = dir.path().join("agent.shutdown_authorised");
        let pub_path = dir.path().join("admin.pub");
        let rules = rules_path();

        let signing_a = SigningKey::generate(&mut OsRng);
        let signing_b = SigningKey::generate(&mut OsRng);
        std::fs::write(
            &pub_path,
            format!(
                "{} shutdown,unlock\n{} shutdown,unlock\n",
                hex::encode(signing_a.verifying_key().to_bytes()),
                hex::encode(signing_b.verifying_key().to_bytes()),
            ),
        )
        .unwrap();

        let agent_id: [u8; 16] = [0x7Eu8; 16];
        let auth = Arc::new(AdminAuth::load_with_agent_id(&pub_path, agent_id).expect("load"));
        let isolator = Arc::new(NetworkIsolator::new(rules).unwrap());
        let posture = Arc::new(PostureMachine::new());

        let auth_c = Arc::clone(&auth);
        let posture_c = Arc::clone(&posture);
        let isolator_c = Arc::clone(&isolator);
        let socket_c = socket.clone();
        let marker_c = marker_path.clone();
        let task = tokio::spawn(async move {
            let _ = serve_with_marker_path(
                socket_c,
                auth_c,
                posture_c,
                isolator_c,
                marker_c,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                Arc::default(),
            )
            .await;
        });

        // Wait for the socket to appear.
        for _ in 0..50 {
            if socket.exists() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }

        (
            dir,
            socket,
            marker_path,
            signing_a,
            signing_b,
            agent_id,
            task,
        )
    }

    /// Read+decode one frame from a UnixStream. Mock-server-friendly
    /// reader used only by the A7 test (the production reader is
    /// `read_frame` above, which is async tokio-only).
    fn sync_read_frame(stream: &mut std::os::unix::net::UnixStream) -> AdminMessage {
        use std::io::Read;
        let mut header = [0u8; 4];
        stream.read_exact(&mut header).expect("read hdr");
        let body_len = u32::from_be_bytes(header) as usize;
        let mut body = vec![0u8; body_len];
        stream.read_exact(&mut body).expect("read body");
        let mut full = Vec::with_capacity(4 + body_len);
        full.extend_from_slice(&header);
        full.extend_from_slice(&body);
        let (msg, _) = decode_frame(&full).expect("decode").expect("complete");
        msg
    }

    fn sync_write_frame(stream: &mut std::os::unix::net::UnixStream, msg: &AdminMessage) {
        use std::io::Write;
        let bytes = encode_frame(msg).expect("encode");
        stream.write_all(&bytes).expect("write");
    }

    /// Required A7 mock-server e2e: a full ShutdownRequest cycle
    /// with two valid signatures from two distinct keys, both
    /// carrying the Shutdown role. The dispatcher must reply
    /// `AdminResult::Success` AND write a well-formed marker at
    /// the agreed path; the marker's `grace_deadline_unix_ts`
    /// must equal `server_now + grace_secs`.
    #[tokio::test]
    async fn shutdown_request_writes_marker_and_replies_success() {
        let (_dir, socket, marker_path, signing_a, signing_b, agent_id, task) =
            spawn_shutdown_server().await;

        // Build the SignedPayload: shutdown op + nonce from
        // server challenge + current wall-clock ts + agent_id.
        let socket_c = socket.clone();
        let agent_id_c = agent_id;
        let marker_c = marker_path.clone();
        let result = tokio::task::spawn_blocking(move || {
            let mut stream = std::os::unix::net::UnixStream::connect(&socket_c).unwrap();
            stream.set_read_timeout(Some(Duration::from_secs(5))).ok();
            stream.set_write_timeout(Some(Duration::from_secs(5))).ok();

            // Step 1: request a challenge.
            sync_write_frame(
                &mut stream,
                &AdminMessage::ChallengeRequest(common::wire::admin_protocol::ChallengeRequest {}),
            );
            let nonce = match sync_read_frame(&mut stream) {
                AdminMessage::Challenge(c) => c.nonce,
                other => panic!("expected Challenge, got {other:?}"),
            };

            // Step 2: build the SignedPayload and sign with both
            // keys. ts = current wall-clock (in-window for the
            // ±60s skew check).
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs();
            let payload =
                SignedPayload::new_shutdown(nonce, now, agent_id_c, /* grace_secs */ 30);
            let sig_a: [u8; 64] = sign(&payload, &signing_a).expect("sign a");
            let sig_b: [u8; 64] = sign(&payload, &signing_b).expect("sign b");

            // Step 3: submit the ShutdownRequest.
            sync_write_frame(
                &mut stream,
                &AdminMessage::ShutdownRequest(ShutdownRequest {
                    payload,
                    signatures: vec![
                        KeyedSignature { signature: sig_a },
                        KeyedSignature { signature: sig_b },
                    ],
                }),
            );

            // Step 4: assert the dispatcher replied Success and
            // wrote a well-formed marker.
            let reply = sync_read_frame(&mut stream);
            assert!(
                matches!(reply, AdminMessage::ShutdownResult(AdminResult::Success)),
                "expected ShutdownResult(Success), got {reply:?}"
            );
            let marker = shutdown_marker::read_marker(&marker_c)
                .expect("read")
                .expect("marker present after Success");
            assert_eq!(marker.agent_pid, std::process::id());

            // External audit TST-003: the watchdog's half of the contract.
            // The marker verifies against the admin keys, and the same
            // marker with its signatures replaced does not.
            use common::shutdown_marker::{verify, Expectation, Rejection};
            let keys: Vec<common::admin_quorum::AdminKey> = [&signing_a, &signing_b]
                .iter()
                .map(|sk| common::admin_quorum::AdminKey {
                    key: sk.verifying_key(),
                    roles: vec![Role::Shutdown],
                })
                .collect();
            let exp = Expectation {
                keys: &keys,
                agent_id: agent_id_c,
                agent_pid: std::process::id(),
                agent_started: None,
                now,
            };
            let ok = verify(&marker, &exp, |_| false).expect("the watchdog accepts it");
            assert_eq!(ok.nonce, nonce);
            let mut forged = marker.clone();
            let stranger = ed25519_dalek::SigningKey::from_bytes(&[0xEE; 32]);
            let fake = SignedPayload::new_shutdown(nonce, now, agent_id_c, 30);
            forged.signatures = vec![hex::encode(sign(&fake, &stranger).unwrap()); 2];
            assert!(matches!(
                verify(&forged, &exp, |_| false),
                Err(Rejection::Quorum(_))
            ));
        })
        .await;

        task.abort();
        result.expect("test panic");
    }

    // ── A8: shutdown-signal abstraction + integration ──────────────

    /// Required A8 test (signal abstraction): a freshly-fired
    /// signal wakes a waiter that started suspended BEFORE the
    /// fire. Standard Notify-semantics anchor — proves the
    /// abstraction is correct on the "consumer started first"
    /// path that production main.rs follows.
    #[tokio::test]
    async fn shutdown_signal_wakes_waiter_started_before_fire() {
        let signal = ShutdownSignal::new();
        let consumer = signal.clone();
        let waiter = tokio::spawn(async move {
            tokio::time::timeout(Duration::from_secs(2), consumer.wait())
                .await
                .expect("wait must complete within 2s after fire")
        });
        // Brief sleep ensures the waiter is parked inside
        // `notified()` before we fire — exercises the
        // "wake an already-suspended waiter" path.
        tokio::time::sleep(Duration::from_millis(20)).await;
        signal.fire();
        waiter.await.expect("waiter task");
    }

    /// Required A8 test (signal abstraction): fire-then-wait —
    /// `Notify::notify_one` is permitted-semantics, so a waiter
    /// that suspends AFTER the fire still returns immediately.
    /// This is the path the integration test below exercises
    /// (the dispatcher fires before the client returns from
    /// `connect()`, but main.rs may not yet be parked in its
    /// select loop).
    #[tokio::test]
    async fn shutdown_signal_wakes_waiter_started_after_fire() {
        let signal = ShutdownSignal::new();
        signal.fire();
        tokio::time::timeout(Duration::from_secs(2), signal.wait())
            .await
            .expect("wait after fire must complete immediately");
    }

    /// Required A8 test (signal abstraction): two clones of the
    /// same signal observe the SAME fire — the underlying Arc
    /// guarantees the production "main.rs holds one Arc + serve
    /// holds the other" topology is correct.
    #[tokio::test]
    async fn shutdown_signal_clones_share_one_arc() {
        let signal_a = ShutdownSignal::new();
        let signal_b = signal_a.clone();
        signal_a.fire();
        tokio::time::timeout(Duration::from_secs(2), signal_b.wait())
            .await
            .expect("fire on clone A wakes wait on clone B");
    }

    /// Required A8 integration test: a full ShutdownRequest →
    /// marker write → signal fire round-trip. Builds on the A7
    /// e2e infrastructure; the assertion that's new in A8 is
    /// that the signal fires (via `wait()` completing within a
    /// bounded budget) AFTER the dispatcher replies Success.
    #[tokio::test]
    async fn shutdown_request_fires_in_process_shutdown_signal() {
        let dir = TempDir::new().unwrap();
        let socket = dir.path().join("admin.sock");
        let marker_path = dir.path().join("agent.shutdown_authorised");
        let pub_path = dir.path().join("admin.pub");
        let rules = rules_path();

        let signing_a = SigningKey::generate(&mut OsRng);
        let signing_b = SigningKey::generate(&mut OsRng);
        std::fs::write(
            &pub_path,
            format!(
                "{} shutdown,unlock\n{} shutdown,unlock\n",
                hex::encode(signing_a.verifying_key().to_bytes()),
                hex::encode(signing_b.verifying_key().to_bytes()),
            ),
        )
        .unwrap();

        let agent_id: [u8; 16] = [0xA8u8; 16];
        let auth = Arc::new(AdminAuth::load_with_agent_id(&pub_path, agent_id).expect("load"));
        let isolator = Arc::new(NetworkIsolator::new(rules).unwrap());
        let posture = Arc::new(PostureMachine::new());

        // A8: build the shutdown signal, hand a clone to serve.
        let signal = ShutdownSignal::new();
        let signal_for_serve = signal.clone();

        let auth_c = Arc::clone(&auth);
        let posture_c = Arc::clone(&posture);
        let isolator_c = Arc::clone(&isolator);
        let socket_c = socket.clone();
        let marker_c = marker_path.clone();
        let task = tokio::spawn(async move {
            let _ = serve_with_marker_path(
                socket_c,
                auth_c,
                posture_c,
                isolator_c,
                marker_c,
                Some(signal_for_serve),
                None,
                None,
                None,
                None,
                None,
                None,
                Arc::default(),
            )
            .await;
        });

        // Wait for socket bind.
        for _ in 0..50 {
            if socket.exists() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }

        // Client thread submits a valid ShutdownRequest.
        let socket_c = socket.clone();
        let agent_id_c = agent_id;
        tokio::task::spawn_blocking(move || {
            let mut stream = std::os::unix::net::UnixStream::connect(&socket_c).unwrap();
            stream.set_read_timeout(Some(Duration::from_secs(5))).ok();
            stream.set_write_timeout(Some(Duration::from_secs(5))).ok();
            sync_write_frame(
                &mut stream,
                &AdminMessage::ChallengeRequest(common::wire::admin_protocol::ChallengeRequest {}),
            );
            let nonce = match sync_read_frame(&mut stream) {
                AdminMessage::Challenge(c) => c.nonce,
                other => panic!("expected Challenge, got {other:?}"),
            };
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs();
            let payload = SignedPayload::new_shutdown(nonce, now, agent_id_c, 30);
            let sig_a: [u8; 64] = sign(&payload, &signing_a).expect("sign a");
            let sig_b: [u8; 64] = sign(&payload, &signing_b).expect("sign b");
            sync_write_frame(
                &mut stream,
                &AdminMessage::ShutdownRequest(ShutdownRequest {
                    payload,
                    signatures: vec![
                        KeyedSignature { signature: sig_a },
                        KeyedSignature { signature: sig_b },
                    ],
                }),
            );
            let reply = sync_read_frame(&mut stream);
            assert!(
                matches!(reply, AdminMessage::ShutdownResult(AdminResult::Success)),
                "expected ShutdownResult(Success), got {reply:?}"
            );
        })
        .await
        .expect("client task");

        // The signal MUST have fired by the time the dispatcher
        // returned Success (it fires immediately after the marker
        // write, before the reply is sent). 2 s upper bound on the
        // wait is generous — in practice this returns in < 1 ms.
        tokio::time::timeout(Duration::from_secs(2), signal.wait())
            .await
            .expect("shutdown signal must fire within 2s of Success");

        task.abort();
    }

    // ── Tappa 8 B5 — audit emission unit tests ─────────────────────

    /// Build an in-memory AuditLog rooted in `dir`, return its
    /// path + the Arc<Mutex<>> wrapped log. B5 dispatch wiring
    /// passes this Arc through; tests poke at the underlying
    /// file to verify emission.
    fn build_test_audit_log(dir: &TempDir) -> (PathBuf, Arc<Mutex<AuditLog>>) {
        let key_path = dir.path().join("agent.sig.key");
        let log_path = dir.path().join("audit.log");
        let key = crate::audit::AgentSigningKey::load_or_bootstrap(&key_path).unwrap();
        let log = AuditLog::open(&log_path, key, [0u8; 16]).unwrap();
        (log_path, Arc::new(Mutex::new(log)))
    }

    fn read_audit_entries(log_path: &Path) -> Vec<crate::audit::AuditEntry> {
        std::fs::read_to_string(log_path)
            .ok()
            .unwrap_or_default()
            .lines()
            .filter(|l| !l.is_empty())
            .map(|l| serde_json::from_str(l).expect("parse audit line"))
            .collect()
    }

    fn fake_client() -> AuditClient {
        AuditClient {
            pid: 12345,
            uid: 1000,
            comm: "nn-admin".to_string(),
        }
    }

    /// B5 test #1: Unlock success emits one audit row with
    /// op="unlock" + result="success" + the fake client triple.
    #[test]
    fn audit_emits_on_unlock_success() {
        let dir = TempDir::new().unwrap();
        let (log_path, audit) = build_test_audit_log(&dir);
        let req = AdminMessage::Unlock(common::wire::admin_protocol::UnlockRequest {
            signature: [0; 64],
        });
        let reply = AdminMessage::UnlockResult(UnlockResult::Success);
        emit_audit_for(&req, &reply, &fake_client(), Some(&audit), &[]);
        let entries = read_audit_entries(&log_path);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].op, "unlock");
        assert_eq!(entries[0].result, "success");
        assert_eq!(entries[0].client_pid, 12345);
        assert_eq!(entries[0].client_uid, 1000);
        assert_eq!(entries[0].client_comm, "nn-admin");
        // First entry chains off the genesis hash (B1 invariant).
        assert_eq!(entries[0].prev_hash, crate::audit::GENESIS_PREV_HASH);
    }

    /// B5 test #2: Shutdown success records grace_secs in
    /// `extra` and the cosigner-count comes from the signatures
    /// vec (len - 1, since the first is the primary signer).
    #[test]
    fn audit_emits_on_shutdown_success_with_grace_extra() {
        use common::wire::admin_protocol::KeyedSignature;
        use common::wire::admin_signed_payload::SignedPayload;
        let dir = TempDir::new().unwrap();
        let (log_path, audit) = build_test_audit_log(&dir);
        let payload = SignedPayload::new_shutdown([0x11; 32], 1_700_000_000, [0x22; 16], 45);
        let req = AdminMessage::ShutdownRequest(ShutdownRequest {
            payload,
            signatures: vec![
                KeyedSignature { signature: [0; 64] },
                KeyedSignature { signature: [1; 64] },
            ],
        });
        let reply = AdminMessage::ShutdownResult(AdminResult::Success);
        emit_audit_for(&req, &reply, &fake_client(), Some(&audit), &[]);
        let entries = read_audit_entries(&log_path);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].op, "shutdown");
        assert_eq!(entries[0].result, "success");
        assert_eq!(entries[0].extra, serde_json::json!({ "grace_secs": 45 }));
        // 2 sigs → 1 cosigner.
        assert_eq!(entries[0].cosigner_fps.len(), 1);
    }

    /// B5 test #3: ForcePosture failure (RoleDenied) emits a
    /// row with op="force_posture", result starting with
    /// "failure: role_denied", and the requested target in
    /// `extra`. Failures audit the SAME way as successes — the
    /// chain captures attempts, not just wins.
    #[test]
    fn audit_emits_on_force_posture_failure() {
        use common::posture_types::PostureKind;
        use common::wire::admin_protocol::KeyedSignature;
        use common::wire::admin_signed_payload::SignedPayload;
        let dir = TempDir::new().unwrap();
        let (log_path, audit) = build_test_audit_log(&dir);
        let payload = SignedPayload::new_force_posture(
            [0x11; 32],
            1_700_000_000,
            [0x22; 16],
            PostureKind::Combat,
        );
        let req = AdminMessage::ForcePostureRequest(ForcePostureRequest {
            payload,
            signatures: vec![KeyedSignature { signature: [0; 64] }],
        });
        let reply = AdminMessage::ForcePostureResult(AdminResult::RoleDenied);
        emit_audit_for(&req, &reply, &fake_client(), Some(&audit), &[]);
        let entries = read_audit_entries(&log_path);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].op, "force_posture");
        assert!(entries[0].result.starts_with("failure: role_denied"));
        assert_eq!(entries[0].extra, serde_json::json!({ "target": "Combat" }));
    }

    /// B5 test #4: Two sequential RotateKeysAdd emissions
    /// chain correctly (second.prev_hash == first.entry_hash) —
    /// proves the in-memory AuditLog state survives across
    /// dispatch calls held behind the Mutex. Non-auditable
    /// messages (ChallengeRequest, Status) are also exercised
    /// to assert they do NOT emit rows.
    #[test]
    fn audit_chains_rotate_keys_add_emissions_and_skips_non_auditable() {
        use common::wire::admin_protocol::{ChallengeRequest, KeyedSignature, StatusRequest};
        use common::wire::admin_signed_payload::{Role, SignedPayload};
        let dir = TempDir::new().unwrap();
        let (log_path, audit) = build_test_audit_log(&dir);

        // Non-auditable: ChallengeRequest reply (Challenge nonce).
        let challenge_req = AdminMessage::ChallengeRequest(ChallengeRequest {});
        let challenge_reply = AdminMessage::Challenge(Challenge { nonce: [0; 32] });
        emit_audit_for(
            &challenge_req,
            &challenge_reply,
            &fake_client(),
            Some(&audit),
            &[],
        );
        // Non-auditable: Status request.
        let status_req = AdminMessage::Status(StatusRequest {});
        let status_reply = AdminMessage::StatusResponse(StatusResponse {
            posture: common::posture_types::PostureKind::Observing,
            network_isolation_engaged: false,
            last_admin_action_secs_ago: None,
            ringbuf_drops_total: None,
            ringbuf_drops: None,
            combat_stage: None,
            combat_locked: None,
            ringbuf_rejected_total: None,
            ringbuf_rejected: None,
            netflow_rows_skipped_total: None,
            netflow_pending_evicted_total: None,
            net_inactive_rules: None,
            flow_sock_pending: None,
            flow_sock_capacity: None,
            flow_sock_forgotten_min: None,
        });
        emit_audit_for(
            &status_req,
            &status_reply,
            &fake_client(),
            Some(&audit),
            &[],
        );

        let after_skips = read_audit_entries(&log_path);
        assert_eq!(
            after_skips.len(),
            0,
            "challenge/status MUST NOT produce audit rows"
        );

        // Two auditable RotateKeysAdd calls.
        let payload_a = SignedPayload::new_rotate_keys_add(
            [0x11; 32],
            1_700_000_000,
            [0x22; 16],
            [0xAA; 32],
            vec![Role::Unlock],
        );
        let req_a = AdminMessage::RotateKeysAddRequest(RotateKeysAddRequest {
            payload: payload_a,
            signatures: vec![KeyedSignature { signature: [0; 64] }],
        });
        // PHASE_D_004: pass non-empty matched_fps to exercise
        // the new fingerprint-threading path. Two distinct
        // fps for the two ops so the chain test below can
        // assert non-empty + distinct values per row.
        emit_audit_for(
            &req_a,
            &AdminMessage::RotateKeysAddResult(AdminResult::Success),
            &fake_client(),
            Some(&audit),
            &["aaaaaaaa".to_string(), "bbbbbbbb".to_string()],
        );

        let payload_b = SignedPayload::new_rotate_keys_add(
            [0x33; 32],
            1_700_000_001,
            [0x22; 16],
            [0xBB; 32],
            vec![Role::Unlock],
        );
        let req_b = AdminMessage::RotateKeysAddRequest(RotateKeysAddRequest {
            payload: payload_b,
            signatures: vec![KeyedSignature { signature: [1; 64] }],
        });
        emit_audit_for(
            &req_b,
            &AdminMessage::RotateKeysAddResult(AdminResult::Success),
            &fake_client(),
            Some(&audit),
            &["cccccccc".to_string(), "dddddddd".to_string()],
        );

        let entries = read_audit_entries(&log_path);
        assert_eq!(entries.len(), 2, "two rotate_keys_add emissions");
        assert_eq!(entries[0].op, "rotate_keys_add");
        assert_eq!(entries[1].op, "rotate_keys_add");
        // CHAIN INVARIANT: second.prev_hash == first.entry_hash.
        assert_eq!(
            entries[1].prev_hash, entries[0].entry_hash,
            "second emission must chain off first"
        );
        // The two new_key_fp values differ (different new_pubkey).
        assert_ne!(entries[0].extra, entries[1].extra);
        // PHASE_D_004: fingerprints now flow through. First
        // emission's key_fp = "aaaaaaaa" + cosigner_fps = ["bbbbbbbb"];
        // second = "cccccccc" + ["dddddddd"].
        assert_eq!(entries[0].key_fp, "aaaaaaaa");
        assert_eq!(entries[0].cosigner_fps, vec!["bbbbbbbb".to_string()]);
        assert_eq!(entries[1].key_fp, "cccccccc");
        assert_eq!(entries[1].cosigner_fps, vec!["dddddddd".to_string()]);
    }

    // ── PHASE_D_004 — fingerprint-threading focused test ──────────

    /// PHASE_D_004 dispatch-level proof: when an empty
    /// `matched_fps` slice is passed (B5 backwards-compat / the
    /// legacy Unlock path), the audit row gets empty strings —
    /// same shape B5 originally shipped. Guards against an
    /// accidental "always populate from fps" regression that
    /// would break the legacy path.
    #[test]
    fn audit_empty_matched_fps_preserves_b5_empty_string_shape() {
        let dir = TempDir::new().unwrap();
        let (log_path, audit) = build_test_audit_log(&dir);
        let req = AdminMessage::Unlock(common::wire::admin_protocol::UnlockRequest {
            signature: [0; 64],
        });
        let reply = AdminMessage::UnlockResult(UnlockResult::Success);
        emit_audit_for(&req, &reply, &fake_client(), Some(&audit), &[]);
        let entries = read_audit_entries(&log_path);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].key_fp, "");
        assert!(entries[0].cosigner_fps.iter().all(String::is_empty));
    }

    // ── C6 — fim baseline / report audit emission tests ────────

    /// C6 audit test #1: FimBaselineRequest + Success result
    /// emit one audit row with op="fim_baseline",
    /// result="success", populated key_fp from matched_fps.
    #[test]
    fn audit_emits_on_fim_baseline_success() {
        use common::wire::admin_protocol::{FimBaselineRequest, KeyedSignature};
        use common::wire::admin_signed_payload::SignedPayload;
        let dir = TempDir::new().unwrap();
        let (log_path, audit) = build_test_audit_log(&dir);
        let payload = SignedPayload::new_fim_baseline([0x11; 32], 1_700_000_000, [0x22; 16]);
        let req = AdminMessage::FimBaselineRequest(FimBaselineRequest {
            payload,
            signatures: vec![KeyedSignature { signature: [0; 64] }],
        });
        let reply = AdminMessage::FimBaselineResult(AdminResult::Success);
        emit_audit_for(
            &req,
            &reply,
            &fake_client(),
            Some(&audit),
            &["aaaaaaaa".to_string()],
        );
        let entries = read_audit_entries(&log_path);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].op, "fim_baseline");
        assert_eq!(entries[0].result, "success");
        assert_eq!(entries[0].key_fp, "aaaaaaaa");
        // 1-of-N quorum → 0 cosigners.
        assert!(entries[0].cosigner_fps.is_empty());
    }

    /// C6 audit test #2: FimReportRequest + Success response
    /// emit one row with the extra carrying entries_count +
    /// truncated flag (operator-visible in `nn-admin audit
    /// read`).
    #[test]
    fn audit_emits_on_fim_report_success_with_extra() {
        use common::wire::admin_protocol::{FimReportRequest, FimReportResponse, KeyedSignature};
        use common::wire::admin_signed_payload::SignedPayload;
        let dir = TempDir::new().unwrap();
        let (log_path, audit) = build_test_audit_log(&dir);
        let payload = SignedPayload::new_fim_report(
            [0x33; 32],
            1_700_000_000,
            [0x44; 16],
            Some(1_700_000_000),
        );
        let req = AdminMessage::FimReportRequest(FimReportRequest {
            payload,
            signatures: vec![KeyedSignature { signature: [0; 64] }],
        });
        let reply = AdminMessage::FimReportResponse(FimReportResponse {
            result: AdminResult::Success,
            entries_jsonl: "{\"ts\":\"2026-05-20T00:00:00Z\"}\n".to_string(),
            entries_count: 1,
            entries_truncated: false,
        });
        emit_audit_for(
            &req,
            &reply,
            &fake_client(),
            Some(&audit),
            &["bbbbbbbb".to_string()],
        );
        let entries = read_audit_entries(&log_path);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].op, "fim_report");
        assert_eq!(entries[0].result, "success");
        assert_eq!(entries[0].key_fp, "bbbbbbbb");
        // Extra surfaces entries_count + truncated flag for
        // operator visibility via `nn-admin audit read`.
        assert_eq!(entries[0].extra["entries_count"], 1);
        assert_eq!(entries[0].extra["truncated"], false);
        assert_eq!(entries[0].extra["since_unix_ts"], 1_700_000_000);
    }

    /// C7 audit test: FimStatusRequest + Success response emits one
    /// row with op="fim_status", result="success", populated key_fp,
    /// AND the extra carrying the snapshot counts. This anchors the
    /// audit-emit arm wired in C7 so a future refactor that drops
    /// it would surface as a test failure rather than silently
    /// missing fim-status from the audit chain.
    #[test]
    fn audit_emits_on_fim_status_success_with_extra() {
        use common::wire::admin_protocol::{FimStatusRequest, FimStatusResponse, KeyedSignature};
        use common::wire::admin_signed_payload::SignedPayload;
        let dir = TempDir::new().unwrap();
        let (log_path, audit) = build_test_audit_log(&dir);
        let payload = SignedPayload::new_fim_status([0x77; 32], 1_700_000_000, [0x88; 16]);
        let req = AdminMessage::FimStatusRequest(FimStatusRequest {
            payload,
            signatures: vec![KeyedSignature { signature: [0; 64] }],
        });
        let reply = AdminMessage::FimStatusResponse(FimStatusResponse {
            result: AdminResult::Success,
            watched_paths_count: 142,
            disabled_default_count: 3,
            added_path_count: 5,
            last_baseline_ts: "2026-05-20T08:14:02.123456Z".to_string(),
            baseline_entries_total: 142,
            drift_entries_total: 17,
            high_remaining: 42,
            high_cap_per_min: 50,
            medium_remaining: 87,
            medium_cap_per_min: 100,
            bucket_window_resets_in_secs: 23,
        });
        emit_audit_for(
            &req,
            &reply,
            &fake_client(),
            Some(&audit),
            &["cccccccc".to_string()],
        );
        let entries = read_audit_entries(&log_path);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].op, "fim_status");
        assert_eq!(entries[0].result, "success");
        assert_eq!(entries[0].key_fp, "cccccccc");
        // Extra surfaces the snapshot counts.
        assert_eq!(entries[0].extra["watched_paths_count"], 142);
        assert_eq!(entries[0].extra["disabled_default_count"], 3);
        assert_eq!(entries[0].extra["added_path_count"], 5);
        assert_eq!(entries[0].extra["baseline_entries_total"], 142);
        assert_eq!(entries[0].extra["drift_entries_total"], 17);
    }

    /// C6 audit test #3: a fim-baseline RoleDenied result still
    /// emits an audit row (failures audit the same way as
    /// successes — the chain captures attempts).
    #[test]
    fn audit_emits_on_fim_baseline_failure_role_denied() {
        use common::wire::admin_protocol::{FimBaselineRequest, KeyedSignature};
        use common::wire::admin_signed_payload::SignedPayload;
        let dir = TempDir::new().unwrap();
        let (log_path, audit) = build_test_audit_log(&dir);
        let payload = SignedPayload::new_fim_baseline([0x55; 32], 1_700_000_000, [0x66; 16]);
        let req = AdminMessage::FimBaselineRequest(FimBaselineRequest {
            payload,
            signatures: vec![KeyedSignature { signature: [0; 64] }],
        });
        let reply = AdminMessage::FimBaselineResult(AdminResult::RoleDenied);
        emit_audit_for(&req, &reply, &fake_client(), Some(&audit), &[]);
        let entries = read_audit_entries(&log_path);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].op, "fim_baseline");
        assert!(entries[0].result.starts_with("failure: role_denied"));
    }

    // ── Tappa 9.5 K6 — canary admin audit + dispatch tests ─────

    /// K6 audit test #1: a CanaryDeployRequest + Success
    /// response emits one row with op="canary_deploy",
    /// result="success", populated key_fp, AND the extra
    /// carrying the allocated canary_id + name + cred_family.
    /// Anchors the audit emit arm so future refactors that drop
    /// it surface as a test failure rather than silently missing
    /// canary lifecycle from the audit chain.
    #[test]
    fn audit_emits_on_canary_deploy_success_with_canary_id_extra() {
        use common::wire::admin_protocol::KeyedSignature;
        use common::wire::admin_signed_payload::{
            CanaryDeploymentWire, CanaryTypeWire, SignedPayload,
        };
        let dir = TempDir::new().unwrap();
        let (log_path, audit) = build_test_audit_log(&dir);
        let payload = SignedPayload::new_canary_deploy(
            [0x10; 32],
            1_700_000_000,
            [0x20; 16],
            "honeypot-aws".to_string(),
            CanaryTypeWire::Credential,
            CanaryDeploymentWire::Credential {
                path: "/var/lib/northnarrow/canaries/aws.creds".to_string(),
                cred_family: "aws".to_string(),
            },
        );
        let req = AdminMessage::CanaryDeployRequest(CanaryDeployRequest {
            payload,
            signatures: vec![KeyedSignature { signature: [0; 64] }],
        });
        let reply = AdminMessage::CanaryDeployResponse(CanaryDeployResponse {
            result: AdminResult::Success,
            canary_id: "abc123def4567890".to_string(),
        });
        emit_audit_for(
            &req,
            &reply,
            &fake_client(),
            Some(&audit),
            &["dddddddd".to_string()],
        );
        let entries = read_audit_entries(&log_path);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].op, "canary_deploy");
        assert_eq!(entries[0].result, "success");
        assert_eq!(entries[0].key_fp, "dddddddd");
        assert_eq!(entries[0].extra["name"], "honeypot-aws");
        assert_eq!(entries[0].extra["canary_id"], "abc123def4567890");
        assert_eq!(entries[0].extra["cred_family"], "aws");
    }

    /// K6 audit test #2: a CanaryListRequest + Success response
    /// emits one row with the extra carrying entries_count +
    /// truncated flag (matches the FimReport audit shape).
    #[test]
    fn audit_emits_on_canary_list_success_with_entries_count_extra() {
        use common::wire::admin_protocol::KeyedSignature;
        use common::wire::admin_signed_payload::SignedPayload;
        let dir = TempDir::new().unwrap();
        let (log_path, audit) = build_test_audit_log(&dir);
        let payload = SignedPayload::new_canary_list([0x30; 32], 1_700_000_000, [0x40; 16]);
        let req = AdminMessage::CanaryListRequest(CanaryListRequest {
            payload,
            signatures: vec![KeyedSignature { signature: [0; 64] }],
        });
        let reply = AdminMessage::CanaryListResponse(CanaryListResponse {
            result: AdminResult::Success,
            entries_jsonl: "{\"op\":\"deploy\"}\n".to_string(),
            entries_count: 3,
            entries_truncated: false,
        });
        emit_audit_for(
            &req,
            &reply,
            &fake_client(),
            Some(&audit),
            &["eeeeeeee".to_string()],
        );
        let entries = read_audit_entries(&log_path);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].op, "canary_list");
        assert_eq!(entries[0].extra["entries_count"], 3);
        assert_eq!(entries[0].extra["truncated"], false);
    }

    /// K6 audit test #3: a CanaryBurnRequest + Success result
    /// emits one row with canary_id from the request's extra
    /// (NOT from the reply — burn replies are bare AdminResult).
    #[test]
    fn audit_emits_on_canary_burn_success_with_canary_id_extra() {
        use common::wire::admin_protocol::KeyedSignature;
        use common::wire::admin_signed_payload::SignedPayload;
        let dir = TempDir::new().unwrap();
        let (log_path, audit) = build_test_audit_log(&dir);
        let payload = SignedPayload::new_canary_burn(
            [0x50; 32],
            1_700_000_000,
            [0x60; 16],
            "burnedidhex0000".to_string(),
        );
        let req = AdminMessage::CanaryBurnRequest(CanaryBurnRequest {
            payload,
            signatures: vec![KeyedSignature { signature: [0; 64] }],
        });
        let reply = AdminMessage::CanaryBurnResult(AdminResult::Success);
        emit_audit_for(
            &req,
            &reply,
            &fake_client(),
            Some(&audit),
            &["ffffffff".to_string()],
        );
        let entries = read_audit_entries(&log_path);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].op, "canary_burn");
        assert_eq!(entries[0].result, "success");
        assert_eq!(entries[0].extra["canary_id"], "burnedidhex0000");
    }

    /// K6 audit test #4: a CanaryRefreshRequest + Success result
    /// emits one row with canary_id from the request's extra.
    /// Same shape as the burn test — both ops are CanaryManage
    /// mutations keyed by canary_id.
    #[test]
    fn audit_emits_on_canary_refresh_success_with_canary_id_extra() {
        use common::wire::admin_protocol::KeyedSignature;
        use common::wire::admin_signed_payload::SignedPayload;
        let dir = TempDir::new().unwrap();
        let (log_path, audit) = build_test_audit_log(&dir);
        let payload = SignedPayload::new_canary_refresh(
            [0x70; 32],
            1_700_000_000,
            [0x80; 16],
            "refreshedidhex0".to_string(),
        );
        let req = AdminMessage::CanaryRefreshRequest(CanaryRefreshRequest {
            payload,
            signatures: vec![KeyedSignature { signature: [0; 64] }],
        });
        let reply = AdminMessage::CanaryRefreshResult(AdminResult::Success);
        emit_audit_for(
            &req,
            &reply,
            &fake_client(),
            Some(&audit),
            &["aaaa1111".to_string()],
        );
        let entries = read_audit_entries(&log_path);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].op, "canary_refresh");
        assert_eq!(entries[0].result, "success");
        assert_eq!(entries[0].extra["canary_id"], "refreshedidhex0");
    }

    /// K6 audit test #5: a canary-deploy RoleDenied result still
    /// emits an audit row (failures audit the same way as
    /// successes — chains capture attempts, not just successes).
    #[test]
    fn audit_emits_on_canary_deploy_failure_role_denied() {
        use common::wire::admin_protocol::KeyedSignature;
        use common::wire::admin_signed_payload::{
            CanaryDeploymentWire, CanaryTypeWire, SignedPayload,
        };
        let dir = TempDir::new().unwrap();
        let (log_path, audit) = build_test_audit_log(&dir);
        let payload = SignedPayload::new_canary_deploy(
            [0x90; 32],
            1_700_000_000,
            [0xa0; 16],
            "denied".to_string(),
            CanaryTypeWire::File,
            CanaryDeploymentWire::File {
                path: "/tmp/x".to_string(),
                template: None,
            },
        );
        let req = AdminMessage::CanaryDeployRequest(CanaryDeployRequest {
            payload,
            signatures: vec![KeyedSignature { signature: [0; 64] }],
        });
        let reply = AdminMessage::CanaryDeployResponse(CanaryDeployResponse {
            result: AdminResult::RoleDenied,
            canary_id: String::new(),
        });
        emit_audit_for(&req, &reply, &fake_client(), Some(&audit), &[]);
        let entries = read_audit_entries(&log_path);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].op, "canary_deploy");
        assert!(entries[0].result.starts_with("failure: role_denied"));
    }

    /// Build an [`AdminAuth`] backed by a tempdir admin.pub file
    /// holding a single key with the supplied roles. Used by the
    /// K6 dispatch tests to construct an auth handle without
    /// spinning up the full server harness. The TempDir is
    /// returned alongside so the test keeps it alive for the
    /// lifetime of the AdminAuth (load reads the file once, but
    /// keeping the dir scoped is the cleaner contract).
    fn build_auth_with_roles(
        signing: &SigningKey,
        roles: &str,
        agent_id: [u8; 16],
    ) -> (AdminAuth, TempDir) {
        let dir = TempDir::new().unwrap();
        let pub_path = dir.path().join("admin.pub");
        std::fs::write(
            &pub_path,
            format!(
                "{}  {roles}\n",
                hex::encode(signing.verifying_key().to_bytes())
            ),
        )
        .unwrap();
        let auth = AdminAuth::load_with_agent_id(&pub_path, agent_id).unwrap();
        (auth, dir)
    }

    /// A canary state over a temp registry and a FIM watch backed by a
    /// stand-in kernel map.
    fn canary_state(dir: &TempDir) -> CanaryAdminState {
        let key =
            crate::audit::AgentSigningKey::load_or_bootstrap(&dir.path().join("agent.sig.key"))
                .unwrap();
        let registry_log_path = dir.path().join("canaries.jsonl");
        let registry = Registry::open(&registry_log_path, key, [0u8; 16]).unwrap();
        CanaryAdminState {
            fim_watch: Some(crate::fim::attach::FimWatch {
                path_map: Arc::new(crate::fim::drain::InodePathMap::new()),
                watched_paths: Some(Arc::new(Mutex::new(
                    crate::fim::attach::WatchedPathsHandle::fake(64),
                ))),
            }),
            registry: Arc::new(Mutex::new(registry)),
            indexes: Arc::new(Mutex::new(CanaryIndexes::new())),
            registry_log_path,
            template_dir: None,
        }
    }

    /// What `dispatch_canary_deploy` does after the signature check.
    fn deploy_canary(
        state: &CanaryAdminState,
        deployment: common::wire::admin_signed_payload::CanaryDeploymentWire,
    ) -> CanaryToken {
        use common::wire::admin_signed_payload::{CanaryDeploymentWire, CanaryTypeWire};
        let canary_type = match &deployment {
            CanaryDeploymentWire::Credential { .. } => CanaryTypeWire::Credential,
            _ => CanaryTypeWire::File,
        };
        let (decoy, content) = materialise_canary_file(&deployment, state).unwrap();
        assert!(watch_decoy(
            state,
            decoy.unwrap(),
            canary_path(&deployment).unwrap()
        ));
        state
            .registry
            .lock()
            .deploy(CanaryTokenDraft {
                // the id is the name and the second: one name per deploy
                name: crate::canary::templates::new_content_seed()[..12].to_string(),
                canary_type,
                deployment,
                deployed_by_fp: "deadbeef".to_string(),
                content,
            })
            .unwrap()
    }

    /// External audit DEC-008: the content seed was `<operator fp>:<path>`,
    /// so the same operator deploying at the same path — on this host or
    /// any other — wrote the same credential, and the fingerprint into it.
    /// DEC-010: the row records the SHA-256 of what was written.
    #[test]
    fn two_deploys_same_operator_same_path_render_differently() {
        use common::wire::admin_signed_payload::CanaryDeploymentWire;
        let dir = TempDir::new().unwrap();
        let state = canary_state(&dir);
        let path = dir.path().join("home/u/.docker/config.json");
        let path_s = path.to_string_lossy().to_string();
        for deployment in [
            CanaryDeploymentWire::Credential {
                path: path_s.clone(),
                cred_family: "docker".to_string(),
            },
            CanaryDeploymentWire::File {
                path: path_s.clone(),
                template: None,
            },
        ] {
            let first = deploy_canary(&state, deployment.clone());
            let body1 = std::fs::read(&path).unwrap();
            let second = deploy_canary(&state, deployment);
            let body2 = std::fs::read(&path).unwrap();
            assert_ne!(body1, body2, "two deploys, two contents");
            assert_ne!(first.content_seed, second.content_seed);
            assert_eq!(
                second.contents_sha256.as_deref(),
                Some(hex::encode(Sha256::digest(&body2)).as_str())
            );
            for body in [&body1, &body2] {
                let text = String::from_utf8_lossy(body).to_lowercase();
                for m in ["deadbeef", "northnarrow", "canary", "nn-l-"] {
                    assert!(!text.contains(m), "decoy carries {m:?}");
                }
            }
        }
    }

    /// External audit DEC-008: a refresh writes the decoy again from a new
    /// seed, in place (the inode, which is what is watched, stays), and
    /// the Refresh row records it; it used to leave a burned credential
    /// in place.
    #[test]
    fn refresh_rotates_credential_content() {
        use common::wire::admin_signed_payload::CanaryDeploymentWire;
        use std::os::unix::fs::MetadataExt;
        let dir = TempDir::new().unwrap();
        let state = canary_state(&dir);
        let path = dir.path().join("creds");
        let deployed = deploy_canary(
            &state,
            CanaryDeploymentWire::Credential {
                path: path.to_string_lossy().to_string(),
                cred_family: "aws".to_string(),
            },
        );
        let id = deployed.canary_id.clone();
        let (body1, ino1) = (
            std::fs::read(&path).unwrap(),
            std::fs::metadata(&path).unwrap().ino(),
        );
        state
            .registry
            .lock()
            .mark_tripped(&id, Some("acc".to_string()))
            .unwrap();
        let row = refresh_canary(&state, &id, "11111111").unwrap();
        let body2 = std::fs::read(&path).unwrap();
        assert_ne!(body1, body2, "the credential is a new one");
        assert_eq!(std::fs::metadata(&path).unwrap().ino(), ino1, "same inode");
        assert_eq!(
            row.contents_sha256.as_deref(),
            Some(hex::encode(Sha256::digest(&body2)).as_str())
        );
        assert_ne!(row.content_seed, deployed.content_seed);
        assert_eq!(
            row.decoy_state,
            Some(crate::canary::registry::DecoyState::Intact)
        );
        assert!(state.registry.lock().is_armed(&id));

        // a decoy gone since is written again, and watched
        std::fs::remove_file(&path).unwrap();
        refresh_canary(&state, &id, "11111111").unwrap();
        let key = crate::fim::attach::key_for_path(&path).unwrap();
        let watch = state.fim_watch.as_ref().unwrap();
        assert_eq!(
            watch.path_map.class_of(&key),
            Some(crate::fim::drain::WatchClass::Decoy)
        );
        // an unknown canary is refused as before
        let err = refresh_canary(&state, "nope", "11111111").unwrap_err();
        assert!(matches!(
            err.downcast_ref::<RegistryError>(),
            Some(RegistryError::CanaryIdNotFound)
        ));
    }

    /// K6 dispatch test #1: dispatch_canary_deploy short-circuits
    /// to UnknownOperation when the boot path didn't wire the
    /// CanaryAdminState (e.g. signing-key load failed, registry
    /// open failed). The pre-state check fires AFTER quorum
    /// verification — caller still gets the standardised
    /// AdminResult::UnknownOperation shape so existing exit-code
    /// mapping in the CLI works without a new variant.
    #[test]
    fn dispatch_canary_deploy_without_state_returns_unknown_operation() {
        use common::wire::admin_protocol::KeyedSignature;
        use common::wire::admin_signed_payload::{
            CanaryDeploymentWire, CanaryTypeWire, SignedPayload,
        };
        let signing = SigningKey::generate(&mut OsRng);
        let agent_id = [0xa0; 16];
        let (auth, _dir) = build_auth_with_roles(&signing, "canary-manage", agent_id);
        let auth = ConnAuth::new(&auth);
        let nonce = auth.issue_challenge().unwrap();
        let payload = SignedPayload::new_canary_deploy(
            nonce,
            now_unix_secs(),
            agent_id,
            "n".to_string(),
            CanaryTypeWire::File,
            CanaryDeploymentWire::File {
                path: "/tmp/x".to_string(),
                template: None,
            },
        );
        let sig: [u8; 64] = common::wire::admin_signed_payload::sign(&payload, &signing).unwrap();
        let req = CanaryDeployRequest {
            payload,
            signatures: vec![KeyedSignature { signature: sig }],
        };
        let mut fps = Vec::new();
        let resp = dispatch_canary_deploy(req, &auth, None, &mut fps);
        assert!(matches!(resp.result, AdminResult::UnknownOperation));
        assert!(resp.canary_id.is_empty());
    }

    /// Lab PR 163: a network canary deploy is checked before it is
    /// registered — an address that is not an IP address could never trip,
    /// and a port a listener on this host serves would trip on each of its
    /// clients. Both were registered as they came. An accepted one is in
    /// the detector's index at once.
    #[test]
    fn a_network_canary_deploy_is_checked_then_indexed() {
        use common::wire::admin_protocol::KeyedSignature;
        use common::wire::admin_signed_payload::{
            CanaryDeploymentWire, CanaryTypeWire, SignedPayload,
        };
        let signing = SigningKey::generate(&mut OsRng);
        let agent_id = [0xa1; 16];
        let (auth, _auth_dir) = build_auth_with_roles(&signing, "canary-manage", agent_id);
        let auth = ConnAuth::new(&auth);
        let dir = TempDir::new().unwrap();
        let state = canary_state(&dir);
        let deploy = |bind_addr: &str, bind_port: u16| {
            let nonce = auth.issue_challenge().unwrap();
            let payload = SignedPayload::new_canary_deploy(
                nonce,
                now_unix_secs(),
                agent_id,
                format!("decoy-{bind_port}"),
                CanaryTypeWire::Network,
                CanaryDeploymentWire::Network {
                    bind_addr: bind_addr.to_string(),
                    bind_port,
                },
            );
            let sig = common::wire::admin_signed_payload::sign(&payload, &signing).unwrap();
            let req = CanaryDeployRequest {
                payload,
                signatures: vec![KeyedSignature { signature: sig }],
            };
            dispatch_canary_deploy(req, &auth, Some(&state), &mut Vec::new())
        };
        let served = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let served_port = served.local_addr().unwrap().port();
        for (addr, port) in [
            ("db.internal", 4444),
            ("127.0.0.1", 0),
            ("127.0.0.1", served_port),
        ] {
            let resp = deploy(addr, port);
            assert!(
                matches!(resp.result, AdminResult::UnknownOperation),
                "{addr}:{port} must be refused"
            );
        }
        assert!(
            state.registry.lock().list().is_empty(),
            "nothing registered"
        );

        let free_port = {
            let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            l.local_addr().unwrap().port()
        };
        let resp = deploy("127.0.0.1", free_port);
        assert!(matches!(resp.result, AdminResult::Success));
        let lo = "127.0.0.1".parse().unwrap();
        assert_eq!(
            state
                .indexes
                .lock()
                .is_canary_destination(lo, free_port, &|_| false),
            Some(resp.canary_id.as_str())
        );
        drop(served);
    }

    /// K6 dispatch test #2: dispatch_canary_list short-circuits
    /// to UnknownOperation when no CanaryAdminState is wired.
    /// Same protection as deploy.
    #[test]
    fn dispatch_canary_list_without_state_returns_unknown_operation() {
        use common::wire::admin_protocol::KeyedSignature;
        use common::wire::admin_signed_payload::SignedPayload;
        let signing = SigningKey::generate(&mut OsRng);
        let agent_id = [0xb0; 16];
        let (auth, _dir) = build_auth_with_roles(&signing, "canary-read", agent_id);
        let auth = ConnAuth::new(&auth);
        let nonce = auth.issue_challenge().unwrap();
        let payload = SignedPayload::new_canary_list(nonce, now_unix_secs(), agent_id);
        let sig: [u8; 64] = common::wire::admin_signed_payload::sign(&payload, &signing).unwrap();
        let req = CanaryListRequest {
            payload,
            signatures: vec![KeyedSignature { signature: sig }],
        };
        let mut fps = Vec::new();
        let resp = dispatch_canary_list(req, &auth, None, &mut fps);
        assert!(matches!(resp.result, AdminResult::UnknownOperation));
        assert_eq!(resp.entries_count, 0);
        assert!(resp.entries_jsonl.is_empty());
    }

    /// K6 dispatch test #3: dispatch_canary_burn short-circuits
    /// to UnknownOperation when no CanaryAdminState is wired.
    #[test]
    fn dispatch_canary_burn_without_state_returns_unknown_operation() {
        use common::wire::admin_protocol::KeyedSignature;
        use common::wire::admin_signed_payload::SignedPayload;
        let signing = SigningKey::generate(&mut OsRng);
        let agent_id = [0xc0; 16];
        let (auth, _dir) = build_auth_with_roles(&signing, "canary-manage", agent_id);
        let auth = ConnAuth::new(&auth);
        let nonce = auth.issue_challenge().unwrap();
        let payload = SignedPayload::new_canary_burn(
            nonce,
            now_unix_secs(),
            agent_id,
            "doesnotexist".to_string(),
        );
        let sig: [u8; 64] = common::wire::admin_signed_payload::sign(&payload, &signing).unwrap();
        let req = CanaryBurnRequest {
            payload,
            signatures: vec![KeyedSignature { signature: sig }],
        };
        let mut fps = Vec::new();
        let r = dispatch_canary_burn(req, &auth, None, &mut fps);
        assert!(matches!(r, AdminResult::UnknownOperation));
    }

    /// K6 dispatch test #4: dispatch_canary_refresh
    /// short-circuits to UnknownOperation when no
    /// CanaryAdminState is wired.
    #[test]
    fn dispatch_canary_refresh_without_state_returns_unknown_operation() {
        use common::wire::admin_protocol::KeyedSignature;
        use common::wire::admin_signed_payload::SignedPayload;
        let signing = SigningKey::generate(&mut OsRng);
        let agent_id = [0xd0; 16];
        let (auth, _dir) = build_auth_with_roles(&signing, "canary-manage", agent_id);
        let auth = ConnAuth::new(&auth);
        let nonce = auth.issue_challenge().unwrap();
        let payload = SignedPayload::new_canary_refresh(
            nonce,
            now_unix_secs(),
            agent_id,
            "doesnotexist".to_string(),
        );
        let sig: [u8; 64] = common::wire::admin_signed_payload::sign(&payload, &signing).unwrap();
        let req = CanaryRefreshRequest {
            payload,
            signatures: vec![KeyedSignature { signature: sig }],
        };
        let mut fps = Vec::new();
        let r = dispatch_canary_refresh(req, &auth, None, &mut fps);
        assert!(matches!(r, AdminResult::UnknownOperation));
    }

    // ── External audit CMB-016 — undoing a response ────────────────

    fn keyed(
        payload: &common::wire::admin_signed_payload::SignedPayload,
        signing: &SigningKey,
    ) -> Vec<common::wire::admin_protocol::KeyedSignature> {
        vec![common::wire::admin_protocol::KeyedSignature {
            signature: common::wire::admin_signed_payload::sign(payload, signing).unwrap(),
        }]
    }

    /// The response state over a temp tree (the containment record, the
    /// vault, the cgroup root) with enforcement on, and a fixed stage.
    fn response_state(dir: &TempDir) -> ResponseAdminState {
        ResponseAdminState {
            config: crate::response::ExecutorConfig {
                dry_run: false,
                ..crate::response::ExecutorConfig::for_test(dir.path())
            },
            combat_stage: Arc::new(|| Some("NEUTRALIZE".to_string())),
        }
    }

    fn status_req(
        signing: &SigningKey,
        auth: &ConnAuth<'_>,
        agent_id: [u8; 16],
    ) -> ResponseStatusRequest {
        use common::wire::admin_signed_payload::SignedPayload;
        let payload = SignedPayload::new_response_status(
            auth.issue_challenge().unwrap(),
            now_unix_secs(),
            agent_id,
        );
        let signatures = keyed(&payload, signing);
        ResponseStatusRequest {
            payload,
            signatures,
        }
    }

    fn release_req(
        signing: &SigningKey,
        auth: &ConnAuth<'_>,
        agent_id: [u8; 16],
        pid: u32,
    ) -> ResponseReleaseRequest {
        use common::wire::admin_signed_payload::SignedPayload;
        let payload = SignedPayload::new_response_release(
            auth.issue_challenge().unwrap(),
            now_unix_secs(),
            agent_id,
            pid,
        );
        let signatures = keyed(&payload, signing);
        ResponseReleaseRequest {
            payload,
            signatures,
        }
    }

    fn restore_req(
        signing: &SigningKey,
        auth: &ConnAuth<'_>,
        agent_id: [u8; 16],
        vault_id: &str,
        to: Option<String>,
    ) -> ResponseRestoreRequest {
        use common::wire::admin_signed_payload::SignedPayload;
        let payload = SignedPayload::new_response_restore(
            auth.issue_challenge().unwrap(),
            now_unix_secs(),
            agent_id,
            vault_id.to_string(),
            to,
        );
        let signatures = keyed(&payload, signing);
        ResponseRestoreRequest {
            payload,
            signatures,
        }
    }

    /// External audit CMB-016: `response status` is read-only, for
    /// `audit-read`; a control role alone is denied.
    #[test]
    fn dispatch_response_status_needs_a_read_role() {
        let signing = SigningKey::generate(&mut OsRng);
        let agent_id = [0x16; 16];
        let dir = TempDir::new().unwrap();
        let state = response_state(&dir);
        let posture = PostureMachine::new();
        let (auth, _d) = build_auth_with_roles(&signing, "unlock,force-posture", agent_id);
        let auth = ConnAuth::new(&auth);
        let r = dispatch_response_status(
            status_req(&signing, &auth, agent_id),
            &auth,
            &posture,
            Some(&state),
            &mut Vec::new(),
        );
        assert!(matches!(r.result, AdminResult::RoleDenied));
        assert!(r.contained.is_empty() && r.quarantined.is_empty());

        for role in ["audit-read", "response-manage,audit-read", "all"] {
            let (auth, _d) = build_auth_with_roles(&signing, role, agent_id);
            let auth = ConnAuth::new(&auth);
            let mut fps = Vec::new();
            let r = dispatch_response_status(
                status_req(&signing, &auth, agent_id),
                &auth,
                &posture,
                Some(&state),
                &mut fps,
            );
            assert!(matches!(r.result, AdminResult::Success), "{role}");
            assert!(!fps.is_empty());
        }
        // no state wired: UnknownOperation, as the canary verbs
        let (auth, _d) = build_auth_with_roles(&signing, "audit-read", agent_id);
        let auth = ConnAuth::new(&auth);
        let r = dispatch_response_status(
            status_req(&signing, &auth, agent_id),
            &auth,
            &posture,
            None,
            &mut Vec::new(),
        );
        assert!(matches!(r.result, AdminResult::UnknownOperation));
    }

    /// External audit CMB-016: the status lists the containment record
    /// (with whether the pid still names that process), the vault and the
    /// COMBAT stage.
    #[test]
    fn dispatch_response_status_lists_contained_and_quarantined() {
        use crate::response::containment::{record, Contained};
        let signing = SigningKey::generate(&mut OsRng);
        let agent_id = [0x17; 16];
        let dir = TempDir::new().unwrap();
        let state = response_state(&dir);
        let me = std::process::id();
        record(
            &state.config,
            Contained {
                pid: me,
                start_ticks: crate::response::proc_ref::proc_start_ticks(me),
                scope: "blocked".into(),
                origin: "/user.slice/test.scope".into(),
                since: 1,
            },
        )
        .unwrap();
        record(
            &state.config,
            Contained {
                pid: me,
                start_ticks: Some(1),
                scope: "throttled".into(),
                origin: "/x".into(),
                since: 2,
            },
        )
        .unwrap();
        let payload = dir.path().join("dropper");
        std::fs::write(&payload, b"bad bytes").unwrap();
        let handle = crate::response::quarantine::ExeHandle::open(&payload).unwrap();
        let out = crate::response::quarantine::quarantine_handle(&handle, 4242, &state.config);
        assert!(matches!(
            out,
            crate::response::ExecutionOutcome::Quarantined { .. }
        ));

        let (auth, _d) = build_auth_with_roles(&signing, "audit-read", agent_id);
        let auth = ConnAuth::new(&auth);
        let r = dispatch_response_status(
            status_req(&signing, &auth, agent_id),
            &auth,
            &PostureMachine::new(),
            Some(&state),
            &mut Vec::new(),
        );
        assert!(matches!(r.result, AdminResult::Success));
        assert_eq!(r.contained_total, 2);
        let blocked = r.contained.iter().find(|c| c.scope == "blocked").unwrap();
        assert!(blocked.running, "same start time: the process moved");
        let throttled = r.contained.iter().find(|c| c.scope == "throttled").unwrap();
        assert!(
            !throttled.running,
            "another start time: not the process moved"
        );
        assert_eq!(r.quarantined_total, 1);
        assert_eq!(r.quarantined[0].original_path, payload.to_string_lossy());
        assert_eq!(r.quarantined[0].size_bytes, 9);
        assert_eq!(r.combat_stage.as_deref(), Some("NEUTRALIZE"));
        assert_eq!(r.combat_locked, Some(false));
    }

    /// External audit CMB-016: `response release` needs `response-manage`;
    /// a read role is denied and nothing is touched.
    #[test]
    fn dispatch_response_release_needs_response_manage() {
        let signing = SigningKey::generate(&mut OsRng);
        let agent_id = [0x18; 16];
        let dir = TempDir::new().unwrap();
        let state = response_state(&dir);
        for role in ["audit-read", "unlock", "canary-manage"] {
            let (auth, _d) = build_auth_with_roles(&signing, role, agent_id);
            let auth = ConnAuth::new(&auth);
            let r = dispatch_response_release(
                release_req(&signing, &auth, agent_id, 4242),
                &auth,
                Some(&state),
                &mut Vec::new(),
            );
            assert!(matches!(r.result, AdminResult::RoleDenied), "{role}");
            assert!(!r.released);
        }
    }

    /// External audit CMB-016: with the role, a pid the agent did not
    /// contain is answered plainly, and nothing is written to any cgroup.
    #[test]
    fn dispatch_response_release_of_an_uncontained_pid_says_so() {
        let signing = SigningKey::generate(&mut OsRng);
        let agent_id = [0x19; 16];
        let dir = TempDir::new().unwrap();
        let state = response_state(&dir);
        std::fs::create_dir_all(&state.config.cgroup_root).unwrap();
        std::fs::write(state.config.cgroup_root.join("cgroup.procs"), b"").unwrap();
        let (auth, _d) = build_auth_with_roles(&signing, "response-manage", agent_id);
        let auth = ConnAuth::new(&auth);
        let mut fps = Vec::new();
        let r = dispatch_response_release(
            release_req(&signing, &auth, agent_id, 4242),
            &auth,
            Some(&state),
            &mut fps,
        );
        assert!(matches!(r.result, AdminResult::Success));
        assert!(!r.released);
        assert!(
            r.message.contains("not contained by this agent"),
            "{}",
            r.message
        );
        assert!(!fps.is_empty());
        assert_eq!(
            std::fs::read_to_string(state.config.cgroup_root.join("cgroup.procs")).unwrap(),
            "",
            "never the root cgroup"
        );
        // a record whose process is not in the scope: skipped, not released
        crate::response::containment::record(
            &state.config,
            crate::response::containment::Contained {
                pid: 4242,
                start_ticks: Some(1),
                scope: "blocked".into(),
                origin: "/system.slice/x.service".into(),
                since: 1,
            },
        )
        .unwrap();
        let r = dispatch_response_release(
            release_req(&signing, &auth, agent_id, 4242),
            &auth,
            Some(&state),
            &mut Vec::new(),
        );
        assert!(matches!(r.result, AdminResult::Success));
        assert!(!r.released);
        assert!(r.message.contains("skipped"), "{}", r.message);
        let r = dispatch_response_release(
            release_req(&signing, &auth, agent_id, 4242),
            &auth,
            None,
            &mut Vec::new(),
        );
        assert!(matches!(r.result, AdminResult::UnknownOperation));
    }

    /// External audit CMB-016: a payload whose extra is another verb's is
    /// refused, whatever the role.
    #[test]
    fn dispatch_response_verbs_refuse_a_mismatched_extra() {
        use common::wire::admin_signed_payload::{
            OperationExtra, ResponseRestoreExtra, SignedPayload,
        };
        let signing = SigningKey::generate(&mut OsRng);
        let agent_id = [0x1a; 16];
        let dir = TempDir::new().unwrap();
        let state = response_state(&dir);
        let (auth, _d) = build_auth_with_roles(&signing, "all", agent_id);
        let auth = ConnAuth::new(&auth);
        let mut payload = SignedPayload::new_response_release(
            auth.issue_challenge().unwrap(),
            now_unix_secs(),
            agent_id,
            4242,
        );
        payload.extra = OperationExtra::ResponseRestore(ResponseRestoreExtra {
            vault_id: "0".repeat(32),
            to: None,
        });
        let signatures = keyed(&payload, &signing);
        let r = dispatch_response_release(
            ResponseReleaseRequest {
                payload,
                signatures,
            },
            &auth,
            Some(&state),
            &mut Vec::new(),
        );
        assert!(!matches!(r.result, AdminResult::Success), "{:?}", r.result);
        assert!(!r.released);

        let mut payload = SignedPayload::new_response_restore(
            auth.issue_challenge().unwrap(),
            now_unix_secs(),
            agent_id,
            "0".repeat(32),
            None,
        );
        payload.op = OperationCode::ResponseStatus;
        let signatures = keyed(&payload, &signing);
        let r = dispatch_response_restore(
            ResponseRestoreRequest {
                payload,
                signatures,
            },
            &auth,
            Some(&state),
            &mut Vec::new(),
        );
        assert!(!matches!(r.result, AdminResult::Success), "{:?}", r.result);
        assert!(!r.restored);
    }

    /// External audit CMB-016 / CMB-026: `response restore` needs
    /// `response-manage`; with it the file comes back (mode 0600, the vault
    /// keeps it), and a traversing vault id is refused.
    #[test]
    fn dispatch_response_restore_is_gated_and_restores() {
        let signing = SigningKey::generate(&mut OsRng);
        let agent_id = [0x1b; 16];
        let dir = TempDir::new().unwrap();
        let state = response_state(&dir);
        let payload = dir.path().join("dropper");
        std::fs::write(&payload, b"bad bytes").unwrap();
        let handle = crate::response::quarantine::ExeHandle::open(&payload).unwrap();
        let crate::response::ExecutionOutcome::Quarantined { vault_id, .. } =
            crate::response::quarantine::quarantine_handle(&handle, 4242, &state.config)
        else {
            panic!("not quarantined");
        };
        assert!(!payload.exists());

        let (auth, _d) = build_auth_with_roles(&signing, "audit-read", agent_id);
        let auth = ConnAuth::new(&auth);
        let r = dispatch_response_restore(
            restore_req(&signing, &auth, agent_id, &vault_id, None),
            &auth,
            Some(&state),
            &mut Vec::new(),
        );
        assert!(matches!(r.result, AdminResult::RoleDenied));
        assert!(!payload.exists(), "nothing restored without the role");

        let (auth, _d) = build_auth_with_roles(&signing, "response-manage", agent_id);
        let auth = ConnAuth::new(&auth);
        let r = dispatch_response_restore(
            restore_req(&signing, &auth, agent_id, "../../etc/shadow", None),
            &auth,
            Some(&state),
            &mut Vec::new(),
        );
        assert!(matches!(r.result, AdminResult::Success));
        assert!(!r.restored);
        assert!(r.message.contains("32 hex digits"), "{}", r.message);

        let r = dispatch_response_restore(
            restore_req(&signing, &auth, agent_id, &vault_id, None),
            &auth,
            Some(&state),
            &mut Vec::new(),
        );
        assert!(r.restored, "{}", r.message);
        assert_eq!(r.path, payload.to_string_lossy());
        assert_eq!(std::fs::read(&payload).unwrap(), b"bad bytes");
        assert_eq!(
            std::fs::metadata(&payload).unwrap().permissions().mode() & 0o777,
            0o600
        );
        // never over an existing file
        let r = dispatch_response_restore(
            restore_req(&signing, &auth, agent_id, &vault_id, None),
            &auth,
            Some(&state),
            &mut Vec::new(),
        );
        assert!(!r.restored);
        assert_eq!(
            crate::response::quarantine::list_vault(&state.config).len(),
            1
        );
    }

    /// External audit CMB-016: a verified release that did nothing is in
    /// the audit chain as a rejection with why, not as a success.
    #[test]
    fn audit_records_a_release_that_did_nothing_as_rejected() {
        use common::wire::admin_signed_payload::SignedPayload;
        let dir = TempDir::new().unwrap();
        let (log_path, audit) = build_test_audit_log(&dir);
        let req = AdminMessage::ResponseReleaseRequest(ResponseReleaseRequest {
            payload: SignedPayload::new_response_release([1; 32], 1_700_000_000, [2; 16], 77),
            signatures: Vec::new(),
        });
        let reply = AdminMessage::ResponseReleaseResponse(ResponseReleaseResponse {
            result: AdminResult::Success,
            released: false,
            message: "pid 77 is not contained by this agent".to_string(),
        });
        emit_audit_for(&req, &reply, &fake_client(), Some(&audit), &["ab".into()]);
        let entries = read_audit_entries(&log_path);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].op, "response_release");
        assert!(entries[0].result.starts_with("failure: rejected"));
        assert_eq!(entries[0].extra["pid"], 77);
    }

    // ── Tappa 10 N7 — net admin dispatch + audit tests ────────────

    /// N7 dispatch test #1 — `net flows` with a `net-read` key
    /// returns Success + empty body when `netflow.jsonl` is
    /// absent. Exercises the auth + extra-parse + empty-
    /// file-tolerance paths.
    #[test]
    fn dispatch_net_flows_returns_empty_success_when_log_absent() {
        use common::wire::admin_protocol::KeyedSignature;
        use common::wire::admin_signed_payload::SignedPayload;
        use ed25519_dalek::SigningKey;
        use rand::rngs::OsRng;
        let signing = SigningKey::generate(&mut OsRng);
        let agent_id = [0xAA; 16];
        let (auth, _dir) = build_auth_with_roles(&signing, "net-read", agent_id);
        let auth = ConnAuth::new(&auth);
        let nonce = auth.issue_challenge().unwrap();
        let payload = SignedPayload::new_net_flows(nonce, now_unix_secs(), agent_id, None);
        let sig: [u8; 64] = common::wire::admin_signed_payload::sign(&payload, &signing).unwrap();
        let req = NetFlowsRequest {
            payload,
            signatures: vec![KeyedSignature { signature: sig }],
        };
        let mut fps = Vec::new();
        let empty = TempDir::new().unwrap();
        let resp = dispatch_net_flows(req, &auth, &read_paths_in(empty.path()), &mut fps);
        assert!(matches!(resp.result, AdminResult::Success));
        assert_eq!(resp.entries_count, 0);
        assert!(!resp.entries_truncated);
        assert!(!fps.is_empty(), "matched signer fp must be captured");
    }

    /// N7 dispatch test #2 — `net flows` with a key that lacks
    /// `net-read` returns `RoleDenied`. Anchors the role gate.
    #[test]
    fn dispatch_net_flows_role_denied_without_net_read() {
        use common::wire::admin_protocol::KeyedSignature;
        use common::wire::admin_signed_payload::SignedPayload;
        use ed25519_dalek::SigningKey;
        use rand::rngs::OsRng;
        let signing = SigningKey::generate(&mut OsRng);
        let agent_id = [0xBB; 16];
        // Key carries `unlock` only — not `net-read`.
        let (auth, _dir) = build_auth_with_roles(&signing, "unlock", agent_id);
        let auth = ConnAuth::new(&auth);
        let nonce = auth.issue_challenge().unwrap();
        let payload = SignedPayload::new_net_flows(nonce, now_unix_secs(), agent_id, None);
        let sig: [u8; 64] = common::wire::admin_signed_payload::sign(&payload, &signing).unwrap();
        let req = NetFlowsRequest {
            payload,
            signatures: vec![KeyedSignature { signature: sig }],
        };
        let mut fps = Vec::new();
        let resp = dispatch_net_flows(req, &auth, &AdminReadPaths::default(), &mut fps);
        assert!(matches!(resp.result, AdminResult::RoleDenied));
    }

    // ── External audit NN-AUD-080/081/082 — read verbs ─────────────

    /// The read verbs' files, in `dir`.
    fn read_paths_in(dir: &Path) -> AdminReadPaths {
        AdminReadPaths {
            fim_drift: dir.join("fim_drift.jsonl"),
            netflow: dir.join("netflow.jsonl"),
            netflow_listeners: dir.join("netflow_listeners.jsonl"),
        }
    }

    fn append_lines(path: &Path, lines: impl IntoIterator<Item = String>) {
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .unwrap();
        for l in lines {
            writeln!(f, "{l}").unwrap();
        }
    }

    /// `2026-10-15T10:MM:SS` for row `i` (one row per second).
    fn row_ts(i: u64) -> String {
        format!("2026-10-15T10:{:02}:{:02}", i / 60, i % 60)
    }

    fn row_unix(i: u64) -> u64 {
        use chrono::TimeZone;
        chrono::Utc
            .with_ymd_and_hms(2026, 10, 15, 10, 0, 0)
            .unwrap()
            .timestamp() as u64
            + i
    }

    /// A netflow row in the drain's field order.
    fn flow_row(i: u64, flow_id: &str, dst: &str, host: Option<&str>) -> String {
        let host = host.map_or("null".to_string(), |h| format!("\"{h}\""));
        format!(
            "{{\"ts\":\"{}.000000Z\",\"flow_id\":\"{flow_id}\",\"start_ns\":{i},\"end_ns\":{i},\
             \"family\":2,\"src_addr\":\"10.0.0.5\",\"src_port\":40000,\"dst_addr\":\"{dst}\",\
             \"dst_port\":443,\"proto\":6,\"pid\":1000,\"uid\":1000,\"comm\":\"curl\",\"exe\":null,\
             \"bytes_sent\":1,\"bytes_recv\":1,\"resolved_hostname\":{host},\"ja3\":null,\
             \"ja4\":null,\"sni\":null,\"close_reason\":0,\"agent_id\":\"00\",\"fmt_ver\":2,\
             \"prev_hash\":\"p\",\"entry_hash\":\"e{i}\",\"agent_sig\":\"s\"}}",
            row_ts(i)
        )
    }

    fn row_numbers(body: &str) -> Vec<u64> {
        body.lines()
            .map(|l| {
                serde_json::from_str::<serde_json::Value>(l).unwrap()["start_ns"]
                    .as_u64()
                    .unwrap()
            })
            .collect()
    }

    /// A key with `roles` and a fresh challenge nonce.
    fn read_verb_key(roles: &str) -> (SigningKey, AdminAuth, TempDir, [u8; 16]) {
        let signing = SigningKey::generate(&mut OsRng);
        let agent_id = [0x39; 16];
        let (auth, dir) = build_auth_with_roles(&signing, roles, agent_id);
        (signing, auth, dir, agent_id)
    }

    fn one_sig(
        payload: &common::wire::admin_signed_payload::SignedPayload,
        signing: &SigningKey,
    ) -> Vec<common::wire::admin_protocol::KeyedSignature> {
        vec![common::wire::admin_protocol::KeyedSignature {
            signature: common::wire::admin_signed_payload::sign(payload, signing).unwrap(),
        }]
    }

    fn net_flows(dir: &Path, since: Option<u64>) -> NetFlowsResponse {
        use common::wire::admin_signed_payload::SignedPayload;
        let (signing, auth, _k, agent_id) = read_verb_key("net-read");
        let auth = ConnAuth::new(&auth);
        let nonce = auth.issue_challenge().unwrap();
        let payload = SignedPayload::new_net_flows(nonce, now_unix_secs(), agent_id, since);
        let req = NetFlowsRequest {
            signatures: one_sig(&payload, &signing),
            payload,
        };
        dispatch_net_flows(req, &auth, &read_paths_in(dir), &mut Vec::new())
    }

    fn fim_report(dir: &Path) -> FimReportResponse {
        use common::wire::admin_signed_payload::SignedPayload;
        let (signing, auth, _k, agent_id) = read_verb_key("fim-read");
        let auth = ConnAuth::new(&auth);
        let nonce = auth.issue_challenge().unwrap();
        let payload = SignedPayload::new_fim_report(nonce, now_unix_secs(), agent_id, None);
        let req = FimReportRequest {
            signatures: one_sig(&payload, &signing),
            payload,
        };
        dispatch_fim_report(req, &auth, &read_paths_in(dir), &mut Vec::new())
    }

    /// External audit NN-AUD-082: `fim report` reads `--fim-drift-file`,
    /// not the built-in path.
    #[test]
    fn fim_report_reads_configured_path() {
        let dir = TempDir::new().unwrap();
        append_lines(
            &dir.path().join("fim_drift.jsonl"),
            (0..2).map(|i| format!("{{\"ts\":\"{}.000000Z\",\"start_ns\":{i}}}", row_ts(i))),
        );
        let resp = fim_report(dir.path());
        assert!(matches!(resp.result, AdminResult::Success));
        assert_eq!(resp.entries_count, 2);
        assert_eq!(row_numbers(&resp.entries_jsonl), vec![1, 0]);
    }

    /// External audit NN-AUD-080: over half a frame, `fim report` keeps
    /// the NEWEST rows, newest first, and says older ones were left out.
    #[test]
    fn fim_report_truncation_keeps_newest() {
        let dir = TempDir::new().unwrap();
        append_lines(
            &dir.path().join("fim_drift.jsonl"),
            (0..3000).map(|i| {
                format!(
                    "{{\"ts\":\"{}.000000Z\",\"start_ns\":{i},\"path\":\"/etc/watched-{i}\"}}",
                    row_ts(i)
                )
            }),
        );
        let resp = fim_report(dir.path());
        assert!(resp.entries_truncated);
        let n = row_numbers(&resp.entries_jsonl);
        assert_eq!(n.first(), Some(&2999), "the newest row comes first");
        assert!(
            n.windows(2).all(|w| w[0] == w[1] + 1),
            "a contiguous newest run"
        );
        assert!(resp.entries_jsonl.len() <= READ_VERB_SOFT_CAP);
    }

    /// External audit NN-AUD-082: `net flows` reads `--netflow-file`.
    #[test]
    fn net_flows_reads_configured_path() {
        let dir = TempDir::new().unwrap();
        append_lines(
            &dir.path().join("netflow.jsonl"),
            (0..3).map(|i| flow_row(i, "aa", "192.0.2.1", None)),
        );
        let resp = net_flows(dir.path(), None);
        assert!(matches!(resp.result, AdminResult::Success));
        assert_eq!(row_numbers(&resp.entries_jsonl), vec![2, 1, 0]);
        assert!(!resp.entries_truncated);
    }

    /// External audit NN-AUD-080: with `--since`, `net flows` goes on into
    /// the rotated archive while its rows are recent enough.
    #[test]
    fn net_flows_since_reads_into_archives() {
        let dir = TempDir::new().unwrap();
        append_lines(
            &dir.path().join("netflow.jsonl.000001"),
            (0..5).map(|i| flow_row(i, "aa", "192.0.2.1", None)),
        );
        append_lines(
            &dir.path().join("netflow.jsonl.000001"),
            ["{\"rotate\":{\"fmt_ver\":2,\"this_seq\":1},\"ts\":\"x\"}".to_string()],
        );
        append_lines(
            &dir.path().join("netflow.jsonl"),
            (5..7).map(|i| flow_row(i, "aa", "192.0.2.1", None)),
        );
        let resp = net_flows(dir.path(), Some(row_unix(3)));
        assert_eq!(row_numbers(&resp.entries_jsonl), vec![6, 5, 4, 3]);
        assert!(!resp.entries_truncated);
        let all = net_flows(dir.path(), None);
        assert_eq!(row_numbers(&all.entries_jsonl), vec![6, 5, 4, 3, 2, 1, 0]);
    }

    /// External audit NN-AUD-081: `net listeners` serves the listener log
    /// (it answered Success with an empty body).
    #[test]
    fn net_listeners_serves_listener_log() {
        use common::wire::admin_signed_payload::SignedPayload;
        let dir = TempDir::new().unwrap();
        append_lines(
            &dir.path().join("netflow_listeners.jsonl"),
            (0..3).map(|i| {
                format!(
                    "{{\"ts\":\"{}.000000Z\",\"start_ns\":{i},\"bind_addr\":\"0.0.0.0\",\
                     \"bind_port\":{}}}",
                    row_ts(i),
                    8765 + i
                )
            }),
        );
        let (signing, auth, _k, agent_id) = read_verb_key("net-read");
        let auth = ConnAuth::new(&auth);
        let nonce = auth.issue_challenge().unwrap();
        let payload = SignedPayload::new_net_listeners(nonce, now_unix_secs(), agent_id);
        let req = NetListenersRequest {
            signatures: one_sig(&payload, &signing),
            payload,
        };
        let mut fps = Vec::new();
        let resp = dispatch_net_listeners(req, &auth, &read_paths_in(dir.path()), &mut fps);
        assert!(matches!(resp.result, AdminResult::Success));
        assert_eq!(resp.entries_count, 3);
        assert_eq!(row_numbers(&resp.entries_jsonl), vec![2, 1, 0]);
        assert!(!fps.is_empty());
    }

    fn net_fingerprint(dir: &Path, flow_id: &str) -> NetFingerprintResponse {
        use common::wire::admin_signed_payload::SignedPayload;
        let (signing, auth, _k, agent_id) = read_verb_key("net-read");
        let auth = ConnAuth::new(&auth);
        let nonce = auth.issue_challenge().unwrap();
        let payload =
            SignedPayload::new_net_fingerprint(nonce, now_unix_secs(), agent_id, flow_id.into());
        let req = NetFingerprintRequest {
            signatures: one_sig(&payload, &signing),
            payload,
        };
        dispatch_net_fingerprint(req, &auth, &read_paths_in(dir), &mut Vec::new())
    }

    /// External audit NN-AUD-081: `net fingerprint` returns that flow's
    /// rows from the active file and the archives (it answered Success with
    /// an empty body); a malformed id is refused.
    #[test]
    fn net_fingerprint_finds_flow_by_id() {
        let dir = TempDir::new().unwrap();
        let id = "0123456789abcdef0123456789abcdef";
        append_lines(
            &dir.path().join("netflow.jsonl.000001"),
            [
                flow_row(0, id, "192.0.2.1", None),
                flow_row(1, "ff", "192.0.2.1", None),
            ],
        );
        append_lines(
            &dir.path().join("netflow.jsonl"),
            [
                flow_row(2, "ff", "192.0.2.1", None),
                flow_row(3, id, "192.0.2.1", None),
                // Another flow whose id contains this one is not it.
                flow_row(4, &format!("{id}00"), "192.0.2.1", None),
            ],
        );
        let resp = net_fingerprint(dir.path(), &id.to_ascii_uppercase());
        assert!(matches!(resp.result, AdminResult::Success));
        assert_eq!(row_numbers(&resp.entries_jsonl), vec![3, 0]);
        let none = net_fingerprint(dir.path(), "abcd");
        assert!(matches!(none.result, AdminResult::Success));
        assert_eq!(none.entries_count, 0);
        for bad in ["", "xyz", "../etc/shadow"] {
            let r = net_fingerprint(dir.path(), bad);
            assert!(matches!(r.result, AdminResult::UnknownOperation), "{bad:?}");
        }
    }

    fn net_resolve(dir: &Path, ip: &str) -> NetResolveResponse {
        use common::wire::admin_signed_payload::SignedPayload;
        let (signing, auth, _k, agent_id) = read_verb_key("net-read");
        let auth = ConnAuth::new(&auth);
        let nonce = auth.issue_challenge().unwrap();
        let payload = SignedPayload::new_net_resolve(nonce, now_unix_secs(), agent_id, ip.into());
        let req = NetResolveRequest {
            signatures: one_sig(&payload, &signing),
            payload,
        };
        dispatch_net_resolve(req, &auth, &read_paths_in(dir), &mut Vec::new())
    }

    /// External audit NN-AUD-081: `net resolve` answers from the netflow
    /// rows — the name of the newest retained flow to that address — and
    /// refuses an address that does not parse (it answered Success with no
    /// name without reading anything).
    #[test]
    fn net_resolve_answers_from_netflow_rows() {
        let dir = TempDir::new().unwrap();
        append_lines(
            &dir.path().join("netflow.jsonl.000001"),
            [
                flow_row(0, "a0", "198.51.100.7", Some("old.example")),
                flow_row(1, "a1", "::ffff:10.1.2.3", Some("mapped.example")),
            ],
        );
        append_lines(
            &dir.path().join("netflow.jsonl"),
            [
                flow_row(2, "a2", "198.51.100.7", Some("new.example")),
                flow_row(3, "a3", "198.51.100.7", None),
                flow_row(4, "a4", "198.51.100.70", Some("other.example")),
            ],
        );
        let r = net_resolve(dir.path(), "198.51.100.7");
        assert!(matches!(r.result, AdminResult::Success));
        assert_eq!(r.qname.as_deref(), Some("new.example"));
        assert_eq!(r.queried_at_unix_ts, Some(row_unix(2)));
        let mapped = net_resolve(dir.path(), "10.1.2.3");
        assert_eq!(mapped.qname.as_deref(), Some("mapped.example"));
        let unknown = net_resolve(dir.path(), "203.0.113.9");
        assert!(matches!(unknown.result, AdminResult::Success));
        assert!(unknown.qname.is_none());
        let bad = net_resolve(dir.path(), "not-an-ip");
        assert!(matches!(bad.result, AdminResult::UnknownOperation));
    }

    // ── Tappa 9.0.b — detections read dispatch + auth-gating tests ──

    /// Build a signed `DetectionsRequest` for the dispatch tests.
    fn signed_detections_req(
        signing: &SigningKey,
        nonce: [u8; 32],
        agent_id: [u8; 16],
    ) -> DetectionsRequest {
        use common::wire::admin_protocol::KeyedSignature;
        use common::wire::admin_signed_payload::SignedPayload;
        let payload = SignedPayload::new_detections(
            nonce,
            now_unix_secs(),
            agent_id,
            10,
            None,
            None,
            None,
            None,
            None,
            None,
        );
        let sig: [u8; 64] = common::wire::admin_signed_payload::sign(&payload, signing).unwrap();
        DetectionsRequest {
            payload,
            signatures: vec![KeyedSignature { signature: sig }],
        }
    }

    /// A `telemetry-read` key is ACCEPTED for `detections`: the verify
    /// path returns Success and captures the signer fingerprint. (The
    /// store at the default path is unreadable from the test env, so
    /// the body is legitimately empty — we assert the auth outcome,
    /// not the record count.)
    #[test]
    fn dispatch_detections_accepts_telemetry_read() {
        let signing = SigningKey::generate(&mut OsRng);
        let agent_id = [0xE0; 16];
        let (auth, _dir) = build_auth_with_roles(&signing, "telemetry-read", agent_id);
        let auth = ConnAuth::new(&auth);
        let nonce = auth.issue_challenge().unwrap();
        let req = signed_detections_req(&signing, nonce, agent_id);
        let mut fps = Vec::new();
        let resp = dispatch_detections(req, &auth, None, &mut fps);
        assert!(
            matches!(resp.result, AdminResult::Success),
            "telemetry-read key must be accepted for detections, got {:?}",
            resp.result
        );
        assert!(!fps.is_empty(), "matched signer fp must be captured");
    }

    /// A key carrying only `unlock` (a control role, NOT
    /// `telemetry-read`) is REJECTED for `detections` with RoleDenied
    /// — control does not imply read.
    #[test]
    fn dispatch_detections_role_denied_without_telemetry_read() {
        let signing = SigningKey::generate(&mut OsRng);
        let agent_id = [0xE1; 16];
        let (auth, _dir) = build_auth_with_roles(&signing, "unlock", agent_id);
        let auth = ConnAuth::new(&auth);
        let nonce = auth.issue_challenge().unwrap();
        let req = signed_detections_req(&signing, nonce, agent_id);
        let mut fps = Vec::new();
        let resp = dispatch_detections(req, &auth, None, &mut fps);
        assert!(matches!(resp.result, AdminResult::RoleDenied));
    }

    /// A key carrying a DIFFERENT read role (`fim-read`) is still
    /// REJECTED for `detections` — telemetry-read is its own gate, not
    /// satisfied by any read role.
    #[test]
    fn dispatch_detections_role_denied_with_wrong_read_role() {
        let signing = SigningKey::generate(&mut OsRng);
        let agent_id = [0xE2; 16];
        let (auth, _dir) = build_auth_with_roles(&signing, "fim-read", agent_id);
        let auth = ConnAuth::new(&auth);
        let nonce = auth.issue_challenge().unwrap();
        let req = signed_detections_req(&signing, nonce, agent_id);
        let mut fps = Vec::new();
        let resp = dispatch_detections(req, &auth, None, &mut fps);
        assert!(matches!(resp.result, AdminResult::RoleDenied));
    }

    /// `Role::All` (break-glass) also satisfies the detections gate —
    /// the super-role subsumes telemetry-read like every other role.
    #[test]
    fn dispatch_detections_accepts_role_all() {
        let signing = SigningKey::generate(&mut OsRng);
        let agent_id = [0xE3; 16];
        let (auth, _dir) = build_auth_with_roles(&signing, "all", agent_id);
        let auth = ConnAuth::new(&auth);
        let nonce = auth.issue_challenge().unwrap();
        let req = signed_detections_req(&signing, nonce, agent_id);
        let mut fps = Vec::new();
        let resp = dispatch_detections(req, &auth, None, &mut fps);
        assert!(matches!(resp.result, AdminResult::Success));
    }

    /// Tappa 9.0.c — a `triage` key is ACCEPTED for `detections`
    /// (triage subsumes telemetry-read): a triage-only key can read the
    /// detections it triages.
    #[test]
    fn dispatch_detections_accepts_triage() {
        let signing = SigningKey::generate(&mut OsRng);
        let agent_id = [0xE4; 16];
        let (auth, _dir) = build_auth_with_roles(&signing, "triage", agent_id);
        let auth = ConnAuth::new(&auth);
        let nonce = auth.issue_challenge().unwrap();
        let req = signed_detections_req(&signing, nonce, agent_id);
        let mut fps = Vec::new();
        let resp = dispatch_detections(req, &auth, None, &mut fps);
        assert!(
            matches!(resp.result, AdminResult::Success),
            "triage key must be accepted for detections (subsumes read), got {:?}",
            resp.result
        );
    }

    // ── Tappa 9.0.c — detection-set-status dispatch + auth-gating ────

    /// Build a signed `DetectionSetStatusRequest` for the dispatch
    /// tests.
    fn signed_set_status_req(
        signing: &SigningKey,
        nonce: [u8; 32],
        agent_id: [u8; 16],
        id: u64,
        status: &str,
    ) -> DetectionSetStatusRequest {
        use common::wire::admin_protocol::KeyedSignature;
        use common::wire::admin_signed_payload::{sign, SignedPayload};
        let payload = SignedPayload::new_detection_set_status(
            nonce,
            now_unix_secs(),
            agent_id,
            id,
            status.to_string(),
            None,
        );
        let sig: [u8; 64] = sign(&payload, signing).unwrap();
        DetectionSetStatusRequest {
            payload,
            signatures: vec![KeyedSignature { signature: sig }],
        }
    }

    /// A `DetectionAdminState` backed by a tempdir: writes `max_id`
    /// detection lines (minimal `{"id":N}` shape — enough for the
    /// `max_detection_id` boot-read guard) and opens a real signed
    /// status-event chain. Returns the state + the TempDir (kept alive
    /// by the caller so the files survive the test).
    fn detection_state_with_max_id(max_id: u64) -> (DetectionAdminState, TempDir) {
        let dir = TempDir::new().unwrap();
        let det_path = dir.path().join("detections.jsonl");
        let evt_path = dir.path().join("status_events.jsonl");
        let body: String = (1..=max_id).map(|n| format!("{{\"id\":{n}}}\n")).collect();
        std::fs::write(&det_path, body).unwrap();
        let key_path = dir.path().join("agent.sig.key");
        let key = crate::audit::AgentSigningKey::load_or_bootstrap(&key_path).unwrap();
        let log = crate::detection_store::open_status_log(
            &evt_path,
            key,
            crate::chainlog::RotationConfig::default(),
            Arc::new(crate::chainlog::NoProtection),
        )
        .unwrap();
        let state = DetectionAdminState {
            status_log: Arc::new(Mutex::new(log)),
            detections_path: det_path,
            status_events_path: evt_path,
        };
        (state, dir)
    }

    fn test_client() -> AuditClient {
        AuditClient {
            pid: 4321,
            uid: 0,
            comm: "nn-admin".to_string(),
        }
    }

    /// A `triage` key is ACCEPTED for set-status: the ack echoes the id
    /// and new status, the signer fp is captured, and the change is
    /// PERSISTED to the status-event chain (read back via
    /// `latest_status_for_ids`). A second change on the same id then
    /// wins (latest-wins), proving the event-sourced semantics through
    /// the real signed-write path.
    #[test]
    fn dispatch_set_status_accepts_triage_and_persists_latest() {
        let signing = SigningKey::generate(&mut OsRng);
        let agent_id = [0xF0; 16];
        let (auth, _dir) = build_auth_with_roles(&signing, "triage", agent_id);
        let auth = ConnAuth::new(&auth);
        let (state, _sdir) = detection_state_with_max_id(3);

        let nonce = auth.issue_challenge().unwrap();
        let req = signed_set_status_req(&signing, nonce, agent_id, 2, "acknowledged");
        let mut fps = Vec::new();
        let resp =
            dispatch_detection_set_status(req, &auth, Some(&state), &test_client(), &mut fps);
        assert!(
            matches!(resp.result, AdminResult::Success),
            "triage key must be accepted for set-status, got {:?}",
            resp.result
        );
        assert_eq!(resp.id, 2);
        assert_eq!(resp.new_status, "acknowledged");
        assert!(!fps.is_empty(), "matched signer fp must be captured");

        // Second change on the SAME id — latest must win.
        let nonce2 = auth.issue_challenge().unwrap();
        let req2 = signed_set_status_req(&signing, nonce2, agent_id, 2, "resolved");
        let resp2 =
            dispatch_detection_set_status(req2, &auth, Some(&state), &test_client(), &mut fps);
        assert!(matches!(resp2.result, AdminResult::Success));

        // The status-event chain now resolves id 2 → Resolved (latest).
        let wanted: std::collections::HashSet<u64> = [2u64].into_iter().collect();
        let map = crate::detection_store::latest_status_for_ids(&state.status_events_path, &wanted);
        assert_eq!(
            map.get(&2),
            Some(&crate::detection_store::DetectionStatus::Resolved),
            "latest status event wins through the signed chain"
        );
    }

    /// A `telemetry-read`-only key is REJECTED for set-status with
    /// RoleDenied — read does NOT imply triage (the one-directional
    /// subsumption). This is the core `read != triage` gate.
    #[test]
    fn dispatch_set_status_role_denied_for_telemetry_read_only() {
        let signing = SigningKey::generate(&mut OsRng);
        let agent_id = [0xF1; 16];
        let (auth, _dir) = build_auth_with_roles(&signing, "telemetry-read", agent_id);
        let auth = ConnAuth::new(&auth);
        let (state, _sdir) = detection_state_with_max_id(3);
        let nonce = auth.issue_challenge().unwrap();
        let req = signed_set_status_req(&signing, nonce, agent_id, 2, "resolved");
        let mut fps = Vec::new();
        let resp =
            dispatch_detection_set_status(req, &auth, Some(&state), &test_client(), &mut fps);
        assert!(matches!(resp.result, AdminResult::RoleDenied));
    }

    /// A control-only key (`unlock`) is REJECTED for set-status —
    /// control authority does NOT confer triage.
    #[test]
    fn dispatch_set_status_role_denied_for_control_only() {
        let signing = SigningKey::generate(&mut OsRng);
        let agent_id = [0xF2; 16];
        let (auth, _dir) = build_auth_with_roles(&signing, "unlock", agent_id);
        let auth = ConnAuth::new(&auth);
        let (state, _sdir) = detection_state_with_max_id(3);
        let nonce = auth.issue_challenge().unwrap();
        let req = signed_set_status_req(&signing, nonce, agent_id, 1, "acknowledged");
        let mut fps = Vec::new();
        let resp =
            dispatch_detection_set_status(req, &auth, Some(&state), &test_client(), &mut fps);
        assert!(matches!(resp.result, AdminResult::RoleDenied));
    }

    /// An id beyond the store's max id is a clean "not found" — folded
    /// into UnknownOperation (the CLI maps it back to a precise hint).
    /// Auth still passes (triage key), so this isolates the id guard.
    #[test]
    fn dispatch_set_status_not_found_for_id_above_max() {
        let signing = SigningKey::generate(&mut OsRng);
        let agent_id = [0xF3; 16];
        let (auth, _dir) = build_auth_with_roles(&signing, "triage", agent_id);
        let auth = ConnAuth::new(&auth);
        let (state, _sdir) = detection_state_with_max_id(3);
        let nonce = auth.issue_challenge().unwrap();
        // id 99 > max id 3 → not found.
        let req = signed_set_status_req(&signing, nonce, agent_id, 99, "resolved");
        let mut fps = Vec::new();
        let resp =
            dispatch_detection_set_status(req, &auth, Some(&state), &test_client(), &mut fps);
        assert!(
            matches!(resp.result, AdminResult::UnknownOperation),
            "id > max must be a clean not-found (UnknownOperation), got {:?}",
            resp.result
        );
        assert_eq!(resp.id, 99, "the not-found reply echoes the requested id");
    }

    /// id 0 is never a valid detection id (ids start at 1) → not found.
    #[test]
    fn dispatch_set_status_not_found_for_id_zero() {
        let signing = SigningKey::generate(&mut OsRng);
        let agent_id = [0xF4; 16];
        let (auth, _dir) = build_auth_with_roles(&signing, "triage", agent_id);
        let auth = ConnAuth::new(&auth);
        let (state, _sdir) = detection_state_with_max_id(3);
        let nonce = auth.issue_challenge().unwrap();
        let req = signed_set_status_req(&signing, nonce, agent_id, 0, "resolved");
        let mut fps = Vec::new();
        let resp =
            dispatch_detection_set_status(req, &auth, Some(&state), &test_client(), &mut fps);
        assert!(matches!(resp.result, AdminResult::UnknownOperation));
    }

    /// With no `DetectionAdminState` wired (degraded boot — the
    /// detection store failed to open), set-status short-circuits to
    /// UnknownOperation AFTER quorum verification (auth still runs), so
    /// the CLI's standard exit mapping works without a new variant.
    #[test]
    fn dispatch_set_status_without_state_returns_unknown_operation() {
        let signing = SigningKey::generate(&mut OsRng);
        let agent_id = [0xF5; 16];
        let (auth, _dir) = build_auth_with_roles(&signing, "triage", agent_id);
        let auth = ConnAuth::new(&auth);
        let nonce = auth.issue_challenge().unwrap();
        let req = signed_set_status_req(&signing, nonce, agent_id, 1, "resolved");
        let mut fps = Vec::new();
        let resp = dispatch_detection_set_status(req, &auth, None, &test_client(), &mut fps);
        assert!(matches!(resp.result, AdminResult::UnknownOperation));
    }

    // ── FIM-009 self-upgrade (§15.1) — trusted-installer grant dispatch ──

    /// Build a signed `TrustedInstallerGrantRequest` for the dispatch
    /// tests. Ed25519 signatures are deterministic, so a replay test can
    /// reproduce the exact bytes by calling this twice with one nonce.
    fn signed_grant_req(
        signing: &ed25519_dalek::SigningKey,
        nonce: [u8; 32],
        agent_id: [u8; 16],
        window_secs: u32,
        ts: u64,
    ) -> TrustedInstallerGrantRequest {
        use common::wire::admin_protocol::KeyedSignature;
        use common::wire::admin_signed_payload::{sign, SignedPayload};
        let payload = SignedPayload::new_trusted_installer_grant(nonce, ts, agent_id, window_secs);
        let sig: [u8; 64] = sign(&payload, signing).unwrap();
        TrustedInstallerGrantRequest {
            payload,
            signatures: vec![KeyedSignature { signature: sig }],
        }
    }

    fn test_override() -> TrustedInstallerOverride {
        // No bpffs (map writes are no-ops); the in-memory window still
        // opens so is_window_open() reflects a successful arm.
        TrustedInstallerOverride::new(None, 0, None, std::time::Duration::from_secs(600))
    }

    /// Happy path: a valid M=1 grant carrying `trusted-installer` arms
    /// the override and captures the signer fingerprint for the audit.
    #[test]
    fn dispatch_trusted_installer_grant_arms_on_valid_m1() {
        use ed25519_dalek::SigningKey;
        use rand::rngs::OsRng;
        let signing = SigningKey::generate(&mut OsRng);
        let agent_id = [0x1a; 16];
        let (auth, _dir) = build_auth_with_roles(&signing, "trusted-installer", agent_id);
        let auth = ConnAuth::new(&auth);
        let nonce = auth.issue_challenge().unwrap();
        let req = signed_grant_req(&signing, nonce, agent_id, 120, now_unix_secs());
        let ov = test_override();
        let mut fps = Vec::new();
        let resp = dispatch_trusted_installer_grant(req, &auth, Some(&ov), &mut fps);
        assert!(matches!(resp, AdminResult::Success));
        assert!(
            ov.is_window_open(),
            "a valid grant opens the override window"
        );
        assert_eq!(
            fps.len(),
            1,
            "signer fingerprint captured for the audit chain"
        );
    }

    /// A signature from a key NOT in admin.pub is rejected; the override
    /// stays disarmed.
    #[test]
    fn dispatch_trusted_installer_grant_bad_signature_rejected() {
        use ed25519_dalek::SigningKey;
        use rand::rngs::OsRng;
        let signing = SigningKey::generate(&mut OsRng);
        let other = SigningKey::generate(&mut OsRng);
        let agent_id = [0x1b; 16];
        let (auth, _dir) = build_auth_with_roles(&signing, "trusted-installer", agent_id);
        let auth = ConnAuth::new(&auth);
        let nonce = auth.issue_challenge().unwrap();
        // Signed by `other` — valid op/nonce/agent_id, but no admin key matches.
        let req = signed_grant_req(&other, nonce, agent_id, 120, now_unix_secs());
        let ov = test_override();
        let mut fps = Vec::new();
        let resp = dispatch_trusted_installer_grant(req, &auth, Some(&ov), &mut fps);
        assert!(matches!(resp, AdminResult::InvalidSignature));
        assert!(
            !ov.is_window_open(),
            "a bad signature never arms the override"
        );
    }

    /// A grant whose `agent_id` doesn't match this install is rejected
    /// (cross-agent replay defence) before the override is touched.
    #[test]
    fn dispatch_trusted_installer_grant_wrong_agent_id_rejected() {
        use ed25519_dalek::SigningKey;
        use rand::rngs::OsRng;
        let signing = SigningKey::generate(&mut OsRng);
        let agent_id = [0x1c; 16];
        let (auth, _dir) = build_auth_with_roles(&signing, "trusted-installer", agent_id);
        let auth = ConnAuth::new(&auth);
        let nonce = auth.issue_challenge().unwrap();
        // Payload binds a DIFFERENT agent_id (and is validly signed over it).
        let req = signed_grant_req(&signing, nonce, [0xff; 16], 120, now_unix_secs());
        let ov = test_override();
        let mut fps = Vec::new();
        let resp = dispatch_trusted_installer_grant(req, &auth, Some(&ov), &mut fps);
        assert!(matches!(resp, AdminResult::AgentIdMismatch));
        assert!(!ov.is_window_open());
    }

    /// A captured grant cannot be replayed: the challenge nonce is
    /// single-use, so re-sending the same signed request after a
    /// successful arm yields `NoPendingChallenge`.
    #[test]
    fn dispatch_trusted_installer_grant_replayed_nonce_rejected() {
        use ed25519_dalek::SigningKey;
        use rand::rngs::OsRng;
        let signing = SigningKey::generate(&mut OsRng);
        let agent_id = [0x1d; 16];
        let (auth, _dir) = build_auth_with_roles(&signing, "trusted-installer", agent_id);
        let auth = ConnAuth::new(&auth);
        let nonce = auth.issue_challenge().unwrap();
        let now = now_unix_secs();
        let ov = test_override();
        let mut fps = Vec::new();
        // First presentation succeeds.
        let first = signed_grant_req(&signing, nonce, agent_id, 120, now);
        assert!(matches!(
            dispatch_trusted_installer_grant(first, &auth, Some(&ov), &mut fps),
            AdminResult::Success
        ));
        // Exact-byte replay (deterministic Ed25519) — nonce already consumed.
        let replay = signed_grant_req(&signing, nonce, agent_id, 120, now);
        let resp = dispatch_trusted_installer_grant(replay, &auth, Some(&ov), &mut fps);
        assert!(matches!(resp, AdminResult::NoPendingChallenge));
    }

    /// A correctly-signed grant from a key lacking `trusted-installer`
    /// is RoleDenied; the override stays disarmed.
    #[test]
    fn dispatch_trusted_installer_grant_role_denied_without_role() {
        use ed25519_dalek::SigningKey;
        use rand::rngs::OsRng;
        let signing = SigningKey::generate(&mut OsRng);
        let agent_id = [0x1e; 16];
        // Key carries `audit-read` only.
        let (auth, _dir) = build_auth_with_roles(&signing, "audit-read", agent_id);
        let auth = ConnAuth::new(&auth);
        let nonce = auth.issue_challenge().unwrap();
        let req = signed_grant_req(&signing, nonce, agent_id, 120, now_unix_secs());
        let ov = test_override();
        let mut fps = Vec::new();
        let resp = dispatch_trusted_installer_grant(req, &auth, Some(&ov), &mut fps);
        assert!(matches!(resp, AdminResult::RoleDenied));
        assert!(!ov.is_window_open());
    }

    /// A grant whose timestamp is outside the ±skew window is rejected
    /// (captured-signature replay across a clock window).
    #[test]
    fn dispatch_trusted_installer_grant_skewed_ts_rejected() {
        use ed25519_dalek::SigningKey;
        use rand::rngs::OsRng;
        let signing = SigningKey::generate(&mut OsRng);
        let agent_id = [0x1f; 16];
        let (auth, _dir) = build_auth_with_roles(&signing, "trusted-installer", agent_id);
        let auth = ConnAuth::new(&auth);
        let nonce = auth.issue_challenge().unwrap();
        // 100_000s in the past — well outside the ±60s window.
        let skewed_ts = now_unix_secs().saturating_sub(100_000);
        let req = signed_grant_req(&signing, nonce, agent_id, 120, skewed_ts);
        let ov = test_override();
        let mut fps = Vec::new();
        let resp = dispatch_trusted_installer_grant(req, &auth, Some(&ov), &mut fps);
        assert!(matches!(resp, AdminResult::TimestampSkew { .. }));
        assert!(!ov.is_window_open());
    }

    /// A verified grant with no override wired (legacy serve path)
    /// returns `UnknownOperation` rather than silently succeeding.
    #[test]
    fn dispatch_trusted_installer_grant_without_override_unknown_operation() {
        use ed25519_dalek::SigningKey;
        use rand::rngs::OsRng;
        let signing = SigningKey::generate(&mut OsRng);
        let agent_id = [0x20; 16];
        let (auth, _dir) = build_auth_with_roles(&signing, "trusted-installer", agent_id);
        let auth = ConnAuth::new(&auth);
        let nonce = auth.issue_challenge().unwrap();
        let req = signed_grant_req(&signing, nonce, agent_id, 120, now_unix_secs());
        let mut fps = Vec::new();
        let resp = dispatch_trusted_installer_grant(req, &auth, None, &mut fps);
        assert!(matches!(resp, AdminResult::UnknownOperation));
    }

    /// N7 audit test — a successful NetFlowsRequest +
    /// NetFlowsResponse emits one row with `op="net_flows"` +
    /// the `entries_count` + `truncated` extra, mirroring the
    /// fim_report shape.
    #[test]
    fn audit_emits_on_net_flows_success_with_counts_extra() {
        use common::wire::admin_protocol::{KeyedSignature, NetFlowsRequest, NetFlowsResponse};
        use common::wire::admin_signed_payload::SignedPayload;
        let dir = TempDir::new().unwrap();
        let (log_path, audit) = build_test_audit_log(&dir);
        let payload =
            SignedPayload::new_net_flows([0x77; 32], 1_700_000_000, [0x88; 16], Some(1_700_000));
        let req = AdminMessage::NetFlowsRequest(NetFlowsRequest {
            payload,
            signatures: vec![KeyedSignature { signature: [0; 64] }],
        });
        let reply = AdminMessage::NetFlowsResponse(NetFlowsResponse {
            result: AdminResult::Success,
            entries_jsonl: String::new(),
            entries_count: 3,
            entries_truncated: false,
        });
        emit_audit_for(
            &req,
            &reply,
            &fake_client(),
            Some(&audit),
            &["aabbccdd".to_string()],
        );
        let entries = read_audit_entries(&log_path);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].op, "net_flows");
        assert_eq!(entries[0].result, "success");
        assert_eq!(entries[0].key_fp, "aabbccdd");
        assert_eq!(entries[0].extra["entries_count"], 3);
        assert_eq!(entries[0].extra["since_unix_ts"], 1_700_000);
    }

    // ── External audit NN-AUD-077: connection limits ───────────────

    #[test]
    fn full_slot_table_evicts_the_longest_waiting_connection() {
        let slots = ConnSlots::new(ConnLimits {
            max_conns: 2,
            ..ConnLimits::DEFAULT
        });
        let a = slots.admit().unwrap();
        std::thread::sleep(Duration::from_millis(2));
        let b = slots.admit().unwrap();
        assert!(b.busy(), "b is serving a request");
        let c = slots.admit().expect("a waiting connection makes room");
        assert!(c.made_room && !b.made_room);
        assert!(!a.waiting(), "a, the only waiting one, was evicted");
        assert!(b.busy() && c.waiting());
        assert_eq!(slots.live(), 2);
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .unwrap();
        rt.block_on(async {
            tokio::time::timeout(Duration::from_secs(1), a.evicted())
                .await
                .expect("the evicted connection is told");
        });
        drop(c);
        assert_eq!(slots.live(), 1);
    }

    #[test]
    fn full_slot_table_of_busy_connections_refuses_a_newcomer() {
        let slots = ConnSlots::new(ConnLimits {
            max_conns: 1,
            ..ConnLimits::DEFAULT
        });
        let a = slots.admit().unwrap();
        assert!(a.busy());
        assert!(slots.admit().is_none());
        drop(a);
        assert!(slots.admit().is_some(), "a dropped slot is free again");
    }

    #[test]
    fn transient_accept_errors_are_the_documented_set() {
        for errno in [
            libc::EMFILE,
            libc::ENFILE,
            libc::ENOBUFS,
            libc::ENOMEM,
            libc::ECONNABORTED,
            libc::EINTR,
        ] {
            assert!(accept_error_is_transient(
                &std::io::Error::from_raw_os_error(errno)
            ));
        }
        assert!(!accept_error_is_transient(
            &std::io::Error::from_raw_os_error(libc::EBADF)
        ));
        assert!(!accept_error_is_transient(
            &std::io::Error::from_raw_os_error(libc::EINVAL)
        ));
    }

    /// `handle_connection` on one end of a socket pair, with `limits`.
    fn spawn_conn_handler(
        limits: ConnLimits,
    ) -> (
        tokio::net::UnixStream,
        JoinHandle<Result<()>>,
        Arc<ConnSlots>,
    ) {
        let (client, server) = UnixStream::pair().unwrap();
        let slots = ConnSlots::new(limits);
        let slot = slots.admit().unwrap();
        let task = tokio::spawn(async move {
            let dir = TempDir::new().unwrap();
            let pub_path = dir.path().join("admin.pub");
            let signing = SigningKey::generate(&mut OsRng);
            std::fs::write(
                &pub_path,
                format!("{}\n", hex::encode(signing.verifying_key().to_bytes())),
            )
            .unwrap();
            let auth = AdminAuth::load(&pub_path).unwrap();
            let isolator = NetworkIsolator::new(rules_path()).unwrap();
            let posture = PostureMachine::new();
            let marker = dir.path().join("marker");
            handle_connection(
                server,
                slot,
                &auth,
                &posture,
                &isolator,
                &marker,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                &AdminReadPaths::default(),
            )
            .await
        });
        (client, task, slots)
    }

    /// External audit NN-AUD-077: a peer that sends nothing, or announces
    /// a frame and stalls, is closed after the read timeout (it used to
    /// hold its fd and buffer forever).
    #[tokio::test]
    async fn idle_connection_closed_after_timeout() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let limits = ConnLimits {
            read_timeout: Duration::from_millis(200),
            ..ConnLimits::DEFAULT
        };
        for stall_mid_frame in [false, true] {
            let (mut client, task, slots) = spawn_conn_handler(limits);
            if stall_mid_frame {
                client.write_all(&100u32.to_be_bytes()).await.unwrap();
                client.write_all(&[0u8; 10]).await.unwrap();
            }
            let mut buf = [0u8; 1];
            let n = tokio::time::timeout(Duration::from_secs(5), client.read(&mut buf))
                .await
                .expect("the server must close a connection that sends no request")
                .unwrap();
            assert_eq!(n, 0, "EOF (stall_mid_frame={stall_mid_frame})");
            task.await
                .unwrap()
                .expect("a timed-out peer is not an error");
            assert_eq!(slots.live(), 0, "the slot is free again");
        }
    }

    /// External audit NN-AUD-077: a peer that sends requests but never
    /// takes the replies is closed after the write timeout.
    #[tokio::test]
    async fn reply_never_taken_closes_after_write_timeout() {
        use tokio::io::AsyncWriteExt;
        let limits = ConnLimits {
            write_timeout: Duration::from_millis(200),
            ..ConnLimits::DEFAULT
        };
        let (client, task, slots) = spawn_conn_handler(limits);
        let (_read_half, mut write_half) = client.into_split();
        let frame = encode_frame(&AdminMessage::Status(
            common::wire::admin_protocol::StatusRequest {},
        ))
        .unwrap();
        let writer = tokio::spawn(async move {
            for _ in 0..20_000 {
                if write_half.write_all(&frame).await.is_err() {
                    break;
                }
            }
        });
        let outcome = tokio::time::timeout(Duration::from_secs(10), task)
            .await
            .expect("the handler must give up on a peer that takes no reply")
            .unwrap();
        let err = outcome.expect_err("a reply not taken ends the connection");
        assert!(format!("{err:#}").contains("not taken"), "{err:#}");
        assert_eq!(slots.live(), 0);
        writer.abort();
    }

    fn connect_retrying(socket: &Path) -> std::os::unix::net::UnixStream {
        for _ in 0..50 {
            if let Ok(s) = std::os::unix::net::UnixStream::connect(socket) {
                s.set_read_timeout(Some(Duration::from_secs(5))).ok();
                s.set_write_timeout(Some(Duration::from_secs(5))).ok();
                return s;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        panic!("cannot connect to {}", socket.display());
    }

    /// `true` when the server has closed `stream` (EOF or reset).
    fn peer_closed(stream: &std::os::unix::net::UnixStream) -> bool {
        use std::io::Read;
        stream
            .set_read_timeout(Some(Duration::from_millis(100)))
            .unwrap();
        let mut buf = [0u8; 1];
        match (&*stream).read(&mut buf) {
            Ok(0) => true,
            Ok(_) => false,
            Err(e) => !matches!(
                e.kind(),
                std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
            ),
        }
    }

    /// External audit NN-AUD-077: more idle connections than the table
    /// holds do not lock out a legitimate client — the longest-waiting
    /// ones are closed to make room, so the agent never holds more than
    /// MAX_ADMIN_CONNECTIONS of them.
    #[tokio::test]
    async fn connections_over_cap_evict_idle_status_still_answers() {
        let signing = SigningKey::generate(&mut OsRng);
        let h = spawn_server(&signing).await;
        let socket = h.socket.clone();
        tokio::task::spawn_blocking(move || {
            let extra = 8;
            let idle: Vec<_> = (0..MAX_ADMIN_CONNECTIONS + extra)
                .map(|_| connect_retrying(&socket))
                .collect();
            std::thread::sleep(Duration::from_millis(300));
            let status =
                run_status(&socket).expect("status answers while idle peers fill the table");
            assert_eq!(status.posture, PostureKind::Observing);
            let closed = idle.iter().filter(|s| peer_closed(s)).count();
            assert!(
                closed > extra,
                "the {extra} over the cap and one more for status are closed, got {closed}"
            );
            assert!(idle.len() - closed <= MAX_ADMIN_CONNECTIONS);
        })
        .await
        .unwrap();
    }

    // ── External audit NN-AUD-078 / NN-AUD-079: per-connection auth ─

    fn sync_challenge(stream: &mut std::os::unix::net::UnixStream) -> [u8; 32] {
        sync_write_frame(
            stream,
            &AdminMessage::ChallengeRequest(common::wire::admin_protocol::ChallengeRequest {}),
        );
        match sync_read_frame(stream) {
            AdminMessage::Challenge(c) => c.nonce,
            other => panic!("expected Challenge, got {other:?}"),
        }
    }

    fn sync_unlock(
        stream: &mut std::os::unix::net::UnixStream,
        signing: &SigningKey,
        nonce: &[u8; 32],
    ) -> UnlockResult {
        use ed25519_dalek::Signer;
        sync_write_frame(
            stream,
            &AdminMessage::Unlock(common::wire::admin_protocol::UnlockRequest {
                signature: signing.sign(nonce).to_bytes(),
            }),
        );
        match sync_read_frame(stream) {
            AdminMessage::UnlockResult(r) => r,
            other => panic!("expected UnlockResult, got {other:?}"),
        }
    }

    /// External audit NN-AUD-078: two clients interleaving challenge and
    /// signed request on their own connections both succeed (the shared
    /// slot used to give the first `InvalidSignature` and the second
    /// `NoPendingChallenge`).
    #[tokio::test]
    async fn challenge_on_other_connection_does_not_invalidate_mine() {
        let signing = SigningKey::generate(&mut OsRng);
        let h = spawn_server(&signing).await;
        let socket = h.socket.clone();
        tokio::task::spawn_blocking(move || {
            let mut a = connect_retrying(&socket);
            let mut b = connect_retrying(&socket);
            let nonce_a = sync_challenge(&mut a);
            let nonce_b = sync_challenge(&mut b);
            assert!(matches!(
                sync_unlock(&mut a, &signing, &nonce_a),
                UnlockResult::Success
            ));
            assert!(matches!(
                sync_unlock(&mut b, &signing, &nonce_b),
                UnlockResult::Success
            ));
        })
        .await
        .unwrap();
    }

    /// External audit NN-AUD-078: a client flooding unauthenticated
    /// `ChallengeRequest`s (and burning its own challenge) does not break
    /// a concurrent 2-of-N signed request.
    #[tokio::test]
    async fn challenge_flood_does_not_break_signed_request() {
        let (_dir, socket, marker_path, signing_a, signing_b, agent_id, task) =
            spawn_shutdown_server().await;
        let result = tokio::task::spawn_blocking(move || {
            let mut operator = connect_retrying(&socket);
            let mut flooder = connect_retrying(&socket);
            let nonce = sync_challenge(&mut operator);
            for _ in 0..50 {
                sync_challenge(&mut flooder);
            }
            // The flooder consumes its own challenge with a bogus request.
            let bogus = SignedPayload::new_shutdown([0u8; 32], now_unix_secs(), agent_id, 30);
            sync_write_frame(
                &mut flooder,
                &AdminMessage::ShutdownRequest(ShutdownRequest {
                    payload: bogus,
                    signatures: vec![KeyedSignature { signature: [0; 64] }],
                }),
            );
            let _ = sync_read_frame(&mut flooder);

            let payload = SignedPayload::new_shutdown(nonce, now_unix_secs(), agent_id, 30);
            sync_write_frame(
                &mut operator,
                &AdminMessage::ShutdownRequest(ShutdownRequest {
                    signatures: vec![
                        KeyedSignature {
                            signature: sign(&payload, &signing_a).unwrap(),
                        },
                        KeyedSignature {
                            signature: sign(&payload, &signing_b).unwrap(),
                        },
                    ],
                    payload,
                }),
            );
            let reply = sync_read_frame(&mut operator);
            assert!(
                matches!(reply, AdminMessage::ShutdownResult(AdminResult::Success)),
                "{reply:?}"
            );
            assert!(marker_path.exists());
        })
        .await;
        task.abort();
        result.expect("test panic");
    }

    /// External audit NN-AUD-079: the third failed signature on one
    /// connection is answered `RateLimited` and the connection is closed;
    /// another connection is not rate-limited (the agent-wide counter used
    /// to block every client for five minutes).
    #[tokio::test]
    async fn third_failure_closes_connection_and_spares_others() {
        let signing = SigningKey::generate(&mut OsRng);
        let stranger = SigningKey::generate(&mut OsRng);
        let h = spawn_server(&signing).await;
        let socket = h.socket.clone();
        tokio::task::spawn_blocking(move || {
            use crate::anti_tamper::admin_auth::MAX_AUTH_FAILURES_PER_CONNECTION;
            let mut hostile = connect_retrying(&socket);
            for attempt in 1..=MAX_AUTH_FAILURES_PER_CONNECTION {
                let nonce = sync_challenge(&mut hostile);
                let r = sync_unlock(&mut hostile, &stranger, &nonce);
                if attempt < MAX_AUTH_FAILURES_PER_CONNECTION {
                    assert!(matches!(r, UnlockResult::InvalidSignature), "{r:?}");
                } else {
                    assert!(matches!(r, UnlockResult::RateLimited { .. }), "{r:?}");
                }
            }
            // A further request on that connection gets no reply.
            use std::io::Write;
            let frame = encode_frame(&AdminMessage::ChallengeRequest(
                common::wire::admin_protocol::ChallengeRequest {},
            ))
            .unwrap();
            let _ = hostile.write_all(&frame);
            assert!(peer_closed(&hostile), "the connection is closed");

            let mut operator = connect_retrying(&socket);
            let nonce = sync_challenge(&mut operator);
            assert!(matches!(
                sync_unlock(&mut operator, &signing, &nonce),
                UnlockResult::Success
            ));
        })
        .await
        .unwrap();
    }

    // ── External audit NN-AUD-083: force-posture out of COMBAT ─────

    fn force_posture_req(
        auth: &ConnAuth<'_>,
        signing: &SigningKey,
        agent_id: [u8; 16],
        target: PostureKind,
    ) -> ForcePostureRequest {
        let payload = SignedPayload::new_force_posture(
            auth.issue_challenge().unwrap(),
            now_unix_secs(),
            agent_id,
            target,
        );
        let signatures = keyed(&payload, signing);
        ForcePostureRequest {
            payload,
            signatures,
        }
    }

    /// POS-001's path stays: a `force-posture`-only key may still force
    /// COMBAT (1-of-N).
    #[test]
    fn force_posture_into_combat_with_force_posture_only_key() {
        let signing = SigningKey::generate(&mut OsRng);
        let agent_id = [0x83; 16];
        let (auth, _d) = build_auth_with_roles(&signing, "force-posture", agent_id);
        let auth = ConnAuth::new(&auth);
        let posture = PostureMachine::new();
        let r = dispatch_force_posture(
            force_posture_req(&auth, &signing, agent_id, PostureKind::Combat),
            &auth,
            &posture,
            &mut Vec::new(),
        );
        assert!(matches!(r, AdminResult::Success), "{r:?}");
        assert_eq!(posture.current_kind(), PostureKind::Combat);
        assert!(posture.is_combat_locked());
    }

    /// External audit NN-AUD-083: a key with only `force-posture` cannot
    /// leave COMBAT (it released the containment like `unlock`); a key
    /// that also holds `unlock` can.
    #[test]
    fn force_posture_from_combat_needs_unlock_role() {
        let signing = SigningKey::generate(&mut OsRng);
        let agent_id = [0x83; 16];
        let (auth, _d) = build_auth_with_roles(&signing, "force-posture", agent_id);
        let auth = ConnAuth::new(&auth);
        let posture = PostureMachine::new();
        let r = dispatch_force_posture(
            force_posture_req(&auth, &signing, agent_id, PostureKind::Combat),
            &auth,
            &posture,
            &mut Vec::new(),
        );
        assert!(matches!(r, AdminResult::Success), "{r:?}");

        for target in [
            PostureKind::Observing,
            PostureKind::Alerted,
            PostureKind::Engaged,
        ] {
            let mut fps = Vec::new();
            let r = dispatch_force_posture(
                force_posture_req(&auth, &signing, agent_id, target),
                &auth,
                &posture,
                &mut fps,
            );
            assert!(matches!(r, AdminResult::RoleDenied), "{target:?}: {r:?}");
            assert_eq!(posture.current_kind(), PostureKind::Combat);
            assert!(posture.is_combat_locked());
            assert_eq!(fps.len(), 1, "the refused signer is on the audit row");
        }
        assert!(!auth.exhausted(), "a role refusal is not a failure");

        let (auth, _d) = build_auth_with_roles(&signing, "force-posture,unlock", agent_id);
        let auth = ConnAuth::new(&auth);
        let r = dispatch_force_posture(
            force_posture_req(&auth, &signing, agent_id, PostureKind::Engaged),
            &auth,
            &posture,
            &mut Vec::new(),
        );
        assert!(matches!(r, AdminResult::Success), "{r:?}");
        assert_eq!(posture.current_kind(), PostureKind::Engaged);
    }

    // ── External audit NN-AUD-084: rotate-keys add confinement ─────

    /// admin.pub in a tempdir with two signers carrying `roles_a` and
    /// `roles_b`.
    fn rotate_keys_fixture(
        roles_a: &str,
        roles_b: &str,
        agent_id: [u8; 16],
    ) -> (TempDir, PathBuf, SigningKey, SigningKey, AdminAuth) {
        let dir = TempDir::new().unwrap();
        let pub_path = dir.path().join("admin.pub");
        let a = SigningKey::generate(&mut OsRng);
        let b = SigningKey::generate(&mut OsRng);
        std::fs::write(
            &pub_path,
            format!(
                "{} {roles_a}\n{} {roles_b}\n",
                hex::encode(a.verifying_key().to_bytes()),
                hex::encode(b.verifying_key().to_bytes()),
            ),
        )
        .unwrap();
        let auth = AdminAuth::load_with_agent_id(&pub_path, agent_id).unwrap();
        (dir, pub_path, a, b, auth)
    }

    fn rotate_add_req(
        auth: &ConnAuth<'_>,
        signers: [&SigningKey; 2],
        agent_id: [u8; 16],
        roles: Vec<Role>,
    ) -> RotateKeysAddRequest {
        let new_key = SigningKey::generate(&mut OsRng);
        let payload = SignedPayload::new_rotate_keys_add(
            auth.issue_challenge().unwrap(),
            now_unix_secs(),
            agent_id,
            new_key.verifying_key().to_bytes(),
            roles,
        );
        let signatures = signers
            .iter()
            .map(|s| KeyedSignature {
                signature: sign(&payload, s).unwrap(),
            })
            .collect();
        RotateKeysAddRequest {
            payload,
            signatures,
        }
    }

    /// External audit NN-AUD-084: two `unlock,rotate-keys` signers cannot
    /// give the new key a role neither holds — not even through an empty
    /// list, which loads as `unlock,audit-read` — and admin.pub is left
    /// as it was; a subset goes through.
    #[test]
    fn rotate_keys_add_refuses_roles_beyond_signers() {
        let agent_id = [0x84; 16];
        let (_dir, pub_path, a, b, auth) =
            rotate_keys_fixture("unlock,rotate-keys", "unlock,rotate-keys", agent_id);
        let auth = ConnAuth::new(&auth);
        let before = std::fs::read_to_string(&pub_path).unwrap();
        for roles in [
            vec![Role::Unlock, Role::Shutdown],
            vec![Role::TrustedInstaller],
            vec![Role::All],
            vec![],
        ] {
            let r = dispatch_rotate_keys_add(
                rotate_add_req(&auth, [&a, &b], agent_id, roles.clone()),
                &auth,
                &mut Vec::new(),
            );
            assert!(matches!(r, AdminResult::RoleDenied), "{roles:?}: {r:?}");
            assert_eq!(std::fs::read_to_string(&pub_path).unwrap(), before);
        }
        let r = dispatch_rotate_keys_add(
            rotate_add_req(
                &auth,
                [&a, &b],
                agent_id,
                vec![Role::Unlock, Role::RotateKeys],
            ),
            &auth,
            &mut Vec::new(),
        );
        assert!(matches!(r, AdminResult::Success), "{r:?}");
        assert_eq!(auth.key_fingerprints_snapshot().len(), 3);
    }

    /// External audit NN-AUD-084: `all` needs a signer that holds `all`;
    /// holding every other role is not enough.
    #[test]
    fn rotate_keys_add_all_needs_all_signer() {
        let agent_id = [0x84; 16];
        let every_role = "unlock,shutdown,force-posture,rotate-keys,audit-read,trusted-installer,\
                          config-manage,response-manage";
        let (_dir, pub_path, a, b, auth) = rotate_keys_fixture(every_role, "rotate-keys", agent_id);
        let auth = ConnAuth::new(&auth);
        let before = std::fs::read_to_string(&pub_path).unwrap();
        let r = dispatch_rotate_keys_add(
            rotate_add_req(&auth, [&a, &b], agent_id, vec![Role::All]),
            &auth,
            &mut Vec::new(),
        );
        assert!(matches!(r, AdminResult::RoleDenied), "{r:?}");
        assert_eq!(std::fs::read_to_string(&pub_path).unwrap(), before);

        let (_dir, _pub_path, a, b, auth) = rotate_keys_fixture("all", "rotate-keys", agent_id);
        let auth = ConnAuth::new(&auth);
        let r = dispatch_rotate_keys_add(
            rotate_add_req(&auth, [&a, &b], agent_id, vec![Role::All]),
            &auth,
            &mut Vec::new(),
        );
        assert!(matches!(r, AdminResult::Success), "{r:?}");
    }

    /// External audit NN-AUD-084: no bootstrap exception — the 1-of-N
    /// bootstrap signer goes through the same check (it has no branch on
    /// the gate) and delegates the roles it holds, nothing more.
    #[test]
    fn bootstrap_add_delegates_signer_roles() {
        let signer = common::admin_quorum::AdminKey {
            key: SigningKey::generate(&mut OsRng).verifying_key(),
            roles: vec![Role::Unlock, Role::RotateKeys, Role::TrustedInstaller],
        };
        let one = std::slice::from_ref(&signer);
        assert_eq!(
            role_beyond_signers(&[Role::Unlock, Role::TrustedInstaller], one),
            None
        );
        assert_eq!(role_beyond_signers(&[Role::RotateKeys], one), None);
        assert_eq!(role_beyond_signers(&[Role::All], one), Some(Role::All));
        assert_eq!(
            role_beyond_signers(&[Role::Shutdown], one),
            Some(Role::Shutdown)
        );
        // A pubkey-only line loads as `unlock,audit-read`.
        assert_eq!(role_beyond_signers(&[], one), Some(Role::AuditRead));
    }
}
