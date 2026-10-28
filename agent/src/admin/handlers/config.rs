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
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;
use tracing::{error, info, warn};

use common::wire::{FS_PROTECT_MUTATE, FS_PROTECT_WRITE};
use ed25519_dalek::VerifyingKey;
use nn_proto::admin_protocol::{
    decode_frame, encode_frame, AdminMessage, AdminResult, CanaryBurnRequest, CanaryDeployRequest,
    CanaryDeployResponse, CanaryListRequest, CanaryListResponse, CanaryRefreshRequest, Challenge,
    ConfigOverlaySetRequest, ConfigOverlaySetResponse, DetectionSetStatusRequest,
    DetectionSetStatusResponse, DetectionsRequest, DetectionsResponse, FimBaselineRequest,
    FimReportRequest, FimReportResponse, FimStatusRequest, FimStatusResponse, ForcePostureRequest,
    NetFingerprintRequest, NetFingerprintResponse, NetFlowsRequest, NetFlowsResponse,
    NetListenersRequest, NetListenersResponse, NetResolveRequest, NetResolveResponse,
    RemediateRansomwareRequest, RemediateRansomwareResponse, ResponseReleaseRequest,
    ResponseReleaseResponse, ResponseRestoreRequest, ResponseRestoreResponse,
    ResponseStatusRequest, ResponseStatusResponse, RotateKeysAddRequest, RotateKeysRevokeRequest,
    ShutdownRequest, SignedUnlockRequest, SignedUnlockResponse, StatusResponse,
    TelemetryStatusRequest, TelemetryStatusResponse, TrustedInstallerGrantRequest, UnlockResult,
    MAX_FRAME_BODY,
};
use nn_proto::admin_signed_payload::{OperationCode, OperationExtra, Role};
use sha2::{Digest, Sha256};

use crate::anti_tamper::admin_auth::{AdminAuth, AdminAuthError, ConnAuth};
use crate::anti_tamper::network_isolate::{Family, NetworkIsolator};
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

/// External audit WDG-007: the socket's identity and its watch.
pub mod socket_watch;

/// External audit ASK-009 (lab PR 213): the unsigned `status` polling,
/// summarised in the signed audit log.
pub mod status_polls;
pub use status_polls::StatusPolls;

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
    /// External audit CMB-018: what set detect-only (`--detect-only` or
    /// `NAME=value`), as the signed `agent_boot` entry records it; `None`
    /// when enforcing. `config.dry_run` is the mode itself.
    pub detect_only_source: Option<String>,
    /// External audit CMB-027: the ladder's transitions the signed audit
    /// log did not get when they happened.
    pub combat_evidence: Arc<dyn Fn() -> crate::combat::EvidenceCounts + Send + Sync>,
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

/// A row the agent writes from one admin frame fits the line caps of the
/// chain readers: the operator's strings come from one signed frame of at
/// most `MAX_FRAME_BODY`, a JSON escape is at most six bytes for one, and
/// the rest of a row is bounded (hashes, signature, ids, a `PATH_MAX`
/// executable). The caps are the readers' (`verify_lines`, the canary
/// chains' `chain_lines`), the frame bound the admin protocol's; the agent,
/// which writes the rows and sees both, holds the two to each other.
/// R04a (lab PR 241): these assertions were in `verify_lines` and
/// `canary::chain_lines`, the only names of the admin protocol in the
/// evidence code (nn-evidence and nn-proto are siblings, plan §2.1).
const _: () = assert!(
    crate::verify_lines::MAX_VERIFY_LINE_BYTES
        >= 6 * (nn_proto::admin_protocol::MAX_FRAME_BODY + 4096) + 64 * 1024,
    "a row the agent can write must fit the verifiers' line cap"
);
const _: () = assert!(
    crate::canary::chain_lines::MAX_CHAIN_LINE_BYTES
        >= 6 * (nn_proto::admin_protocol::MAX_FRAME_BODY + 4096) + 64 * 1024,
    "a row the agent can write must fit the chain line cap"
);

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
            let mut matched_fps: Vec<String> = Vec::new();
            let mut notes = DispatchNotes::default();
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
                &mut notes,
            );
            emit_audit_for(&msg, &reply, &client, audit_log, &matched_fps, &notes);
            // External audit ASK-009 (lab PR 213): the unsigned status, one
            // signed row per peer per hour.
            if matches!(msg, AdminMessage::Status(_)) {
                note_status_poll(status_polls, &client, audit_log);
            }
            reply
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

/// External audit ASK-009 (lab PR 213): count an unsigned `status` and
/// append the `status_polled` row that opens its peer's window. A failed
/// append is a WARN; the reply is sent anyway, as for the other rows.
fn note_status_poll(
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

/// Who connected, as the audit log records it: `(pid, uid)` from
/// `SO_PEERCRED`, `comm` and `exe` from `/proc/<pid>`. The audit log's
/// per-entry `client_*` fields (design §9.1) come from here so every
/// admin operation records WHO connected, not just which key signed.
#[derive(Debug, Clone)]
pub(crate) struct AuditClient {
    pub pid: u32,
    pub uid: u32,
    /// `/proc/<pid>/comm`. Self-reported (external audit ASK-013,
    /// NN-AUD-239): the name the peer gave itself, which any process
    /// chooses (`prctl(PR_SET_NAME)`). `<exited>` when the peer was gone
    /// before it could be read, `<unknown>` when it could not be read.
    pub comm: String,
    /// `/proc/<pid>/exe`: the program the kernel says the peer runs
    /// (external audit ASK-013). `None` when it could not be read.
    pub exe: Option<String>,
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
fn peer_cred(fd: std::os::unix::io::RawFd) -> Result<PeerCred, PeerRefusal> {
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
fn screen_peer(fd: std::os::unix::io::RawFd, own_euid: u32) -> Result<PeerCred, PeerRefusal> {
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
    if let Some(euid) = tests::own_euid_override(socket_path) {
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
fn peer_identity(sock: std::os::unix::io::RawFd, cred: &PeerCred) -> AuditClient {
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

/// What a dispatcher learned that neither the request nor the reply
/// carries, for the audit row. Filled by `dispatch`, read by
/// [`emit_audit_for`]; next to the signers' fingerprints (`matched_fps`).
#[derive(Debug, Default)]
struct DispatchNotes {
    /// External audit ASK-015: the posture a force-posture left, when the
    /// transition was applied (also a no-op to the same state). `None`
    /// when it was refused: the state did not change.
    force_from: Option<nn_model::posture_types::PostureKind>,
    /// Lab PR 217: a force-posture out of COMBAT — what its release
    /// released, or why it did not (the posture then stayed COMBAT).
    force_release: Option<std::result::Result<String, String>>,
}

/// Inspect the (request, reply) pair after `dispatch` returns
/// and append a single audit-log entry if the message was an
/// auditable admin operation (challenge/status are not
/// auditable — they're plumbing). On any audit failure, log
/// plus continue: the operator's authorised action MUST succeed
/// even if the audit log is temporarily unwritable (design §9
/// states "the entry is the receipt; the action is the action").
// PHASE_D_004: `matched_fps` is the dispatch_* fns' `fps_out`
// values — empty for the legacy `Unlock` (refused since lab PR 217,
// verified by no one) and for failure paths; populated for successful
// signed-payload ops, the signed unlock included (lab PR 217: its row
// names the signer).
fn emit_audit_for(
    msg: &AdminMessage,
    reply: &AdminMessage,
    client: &AuditClient,
    audit_log: Option<&Arc<Mutex<AuditLog>>>,
    matched_fps: &[String],
    notes: &DispatchNotes,
) {
    let Some(audit_log) = audit_log else {
        return;
    };
    let (op, extra, result, cosigner_count) = match (msg, reply) {
        // Lab PR 217: refused (`failure: legacy_protocol_refused`) — the
        // row says which protocol was used.
        (AdminMessage::Unlock(_), AdminMessage::UnlockResult(r)) => (
            "unlock",
            serde_json::json!({ "protocol": "legacy" }),
            unlock_result_str(r),
            0,
        ),
        // Lab PR 217 (NN-AUD-243 residue, capability C17): `success` only
        // when the release was carried out and the tables read back clear;
        // a verified request whose teardown failed is a failure with why,
        // and the row names the signer (`key_fp`).
        (AdminMessage::SignedUnlockRequest(req), AdminMessage::SignedUnlockResponse(r)) => (
            "unlock",
            serde_json::json!({
                "protocol": "signed",
                "released": r.released,
                "isolation_v4": r.isolation_v4,
                "isolation_v6": r.isolation_v6,
                "detail": r.message,
            }),
            match r.result {
                AdminResult::Success if r.released => "success".to_string(),
                AdminResult::Success | AdminResult::ActionFailed => {
                    format!("failure: release_failed ({})", r.message)
                }
                other => audit_result_str(other),
            },
            req.signatures.len().saturating_sub(1),
        ),
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
            // External audit ASK-015: the state left, when the force was
            // applied; a refused one changed nothing and has no `from`.
            let mut extra = serde_json::json!({ "target": target });
            if let Some(from) = notes.force_from {
                extra["from"] = serde_json::Value::String(format!("{from:?}"));
            }
            // Lab PR 217: leaving COMBAT released the containment — or did
            // not, and the posture stayed COMBAT.
            let result = match &notes.force_release {
                Some(Ok(released)) => {
                    extra["release"] = serde_json::Value::String(released.clone());
                    audit_result_str(*r)
                }
                Some(Err(why)) => {
                    extra["release"] = serde_json::Value::String(why.clone());
                    format!("failure: release_failed ({why})")
                }
                None => audit_result_str(*r),
            };
            (
                "force_posture",
                extra,
                result,
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
                        nn_proto::admin_signed_payload::CanaryDeploymentWire::Credential {
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
            use nn_proto::admin_signed_payload::NetFlowsExtra;
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
            use nn_proto::admin_signed_payload::NetResolveExtra;
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
            use nn_proto::admin_signed_payload::NetFingerprintExtra;
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
        // External audit ASK-009 (lab PR 213): who read the telemetry the
        // unsigned status withholds. The counters themselves are not copied
        // into the row.
        (AdminMessage::TelemetryStatusRequest(req), AdminMessage::TelemetryStatusResponse(r)) => (
            "telemetry_status",
            serde_json::json!({}),
            audit_result_str(r.result),
            req.signatures.len().saturating_sub(1),
        ),
        // Lab PR 222: the verb's own row; every file it touched has a
        // `cow_restore` row of its own, signed before this one.
        (
            AdminMessage::RemediateRansomwareRequest(req),
            AdminMessage::RemediateRansomwareResponse(r),
        ) => {
            let (pid, since, dry_run) = match &req.payload.extra {
                OperationExtra::RemediateRansomware(e) => (e.pid, e.since_unix, e.dry_run),
                _ => (None, None, false),
            };
            (
                "remediate_ransomware",
                serde_json::json!({
                    "pid": pid,
                    "since_unix": since,
                    "dry_run": dry_run,
                    "files": r.rows_total,
                    "restored": r.restored,
                    "recreated": r.recreated,
                    "kept_both": r.kept_both,
                    "unchanged": r.unchanged,
                    "refused": r.refused,
                    "skipped": r.skipped,
                    "detail": r.message,
                }),
                verified_result_str(r.result, r.done, &r.message),
                req.signatures.len().saturating_sub(1),
            )
        }
        // Non-auditable here: ChallengeRequest, the debug path. The unsigned
        // Status is summarised per peer by `StatusPolls` (external audit
        // ASK-009). Server-only reply variants reaching dispatch are
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
        client_exe: client.exe.clone(),
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
        UnlockResult::LegacyProtocolRefused => "failure: legacy_protocol_refused".to_string(),
    }
}

/// Lab PR 217 (NN-AUD-243 residue, capability C17) — handle one signed
/// `unlock` (`OperationCode::Unlock`, 1-of-N, `Role::Unlock`): verify, run
/// the release through the posture — the ladder stood down, the iptables
/// teardown read back per family — and answer what it did.
///
/// `Success` only when the release was carried out and the tables read
/// back clear (or there was nothing to release); a verified request whose
/// teardown did not leave them clear is [`AdminResult::ActionFailed`] with
/// why, and the posture stays COMBAT (external audit ASK-017 / NN-AUD-243:
/// this was `Success`, recorded "success", whatever the teardown did). The
/// signer's fingerprint goes to the audit row.
fn dispatch_signed_unlock(
    req: SignedUnlockRequest,
    auth: &ConnAuth<'_>,
    posture: &PostureMachine,
    isolator: &NetworkIsolator,
    fps_out: &mut Vec<String>,
) -> SignedUnlockResponse {
    let reply = |result: AdminResult, released: bool, message: String| SignedUnlockResponse {
        result,
        released,
        isolation_v4: isolator.is_isolated(Family::V4),
        isolation_v6: isolator.is_isolated(Family::V6),
        message,
    };
    let sigs: Vec<[u8; 64]> = req.signatures.iter().map(|s| s.signature).collect();
    let (token, matched_fps) = match auth.verify_signed_payload_quorum(
        &req.payload,
        &sigs,
        1,
        &[Role::Unlock],
        OperationCode::Unlock,
        now_unix_secs(),
    ) {
        Ok(v) => v,
        Err(e) => {
            let r = map_admin_auth_error(e, "unlock");
            return reply(r, false, "signature verification failed".to_string());
        }
    };
    *fps_out = matched_fps;
    let signer = fps_out.first().cloned().unwrap_or_default();
    match posture.admin_release_combat_with_token(token) {
        Ok(out) => {
            let message = if out.left_combat {
                format!(
                    "COMBAT released, posture {}: {}",
                    out.state.kind(),
                    out.detail
                )
            } else {
                format!(
                    "not in COMBAT (posture {}): {}",
                    out.state.kind(),
                    out.detail
                )
            };
            info!(
                target: "admin.unlock",
                signer_fp = %signer,
                outcome = %message,
                "signed unlock carried out"
            );
            reply(AdminResult::Success, true, message)
        }
        Err(e) => {
            error!(
                target: "admin.unlock",
                signer_fp = %signer,
                error = %e,
                "signed unlock verified, but the isolation was NOT released — answering a \
                 failure; the posture stays {}",
                posture.current_kind()
            );
            let why = match e {
                AdminReleaseError::ReleaseFailed(why) => why,
                other => other.to_string(),
            };
            reply(
                AdminResult::ActionFailed,
                false,
                format!(
                    "the isolation was NOT released, the posture stays {}: {why}",
                    posture.current_kind()
                ),
            )
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
        AdminResult::ActionFailed => "failure: action_failed".to_string(),
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
    notes: &mut DispatchNotes,
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

        // Lab PR 217 (NN-AUD-243 residue, capability C17): the legacy unlock
        // — a signature over the bare nonce, no operation, install or time
        // bound to it, its audit row unable to name the signer — no longer
        // releases COMBAT. Refused outright, whatever it carries: a
        // compatibility switch would be a downgrade of the one operation
        // that lifts the host's isolation, and the `nn-admin` that signs the
        // payload ships in the same release as this agent. The connection's
        // challenge is spent; the refusal is audited.
        AdminMessage::Unlock(_) => {
            auth.discard_challenge();
            error!(
                target: "admin.unlock",
                "legacy unlock (signature over the bare nonce) REFUSED — sign an \
                 `OperationCode::Unlock` payload: use the nn-admin of this agent's release \
                 (`nn-admin unlock --key … --agent-id-file …`)"
            );
            AdminMessage::UnlockResult(UnlockResult::LegacyProtocolRefused)
        }

        AdminMessage::SignedUnlockRequest(req) => AdminMessage::SignedUnlockResponse(
            dispatch_signed_unlock(req, auth, posture, isolator, fps_out),
        ),

        // External audit ASK-009 (lab PR 213): unsigned, what the watchdog
        // and COMBAT recovery need; the telemetry is the signed verb's.
        AdminMessage::Status(_) => {
            AdminMessage::StatusResponse(public_status(posture, isolator, response_state))
        }

        AdminMessage::TelemetryStatusRequest(req) => AdminMessage::TelemetryStatusResponse(
            dispatch_telemetry_status(req, auth, posture, isolator, response_state, fps_out),
        ),

        // Lab PR 216: unsigned, the event loop's round count — the
        // watchdog's check that the loop moves, not only this socket.
        AdminMessage::LoopProgress(_) => {
            AdminMessage::LoopProgressResponse(crate::loop_progress::snapshot())
        }

        AdminMessage::ShutdownRequest(req) => AdminMessage::ShutdownResult(dispatch_shutdown(
            req,
            auth,
            marker_path,
            shutdown_signal,
            fps_out,
        )),

        AdminMessage::ForcePostureRequest(req) => AdminMessage::ForcePostureResult(
            dispatch_force_posture(req, auth, posture, fps_out, notes),
        ),

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
        // Lab PR 222 — restore from the copy-on-first-write journal.
        AdminMessage::RemediateRansomwareRequest(req) => AdminMessage::RemediateRansomwareResponse(
            dispatch_remediate_ransomware(req, auth, fps_out),
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
        | AdminMessage::ResponseRestoreResponse(_)
        | AdminMessage::TelemetryStatusResponse(_)
        | AdminMessage::LoopProgressResponse(_)
        | AdminMessage::SignedUnlockResponse(_)
        | AdminMessage::RemediateRansomwareResponse(_) => {
            warn!("client sent server-only message variant; ignoring");
            AdminMessage::UnlockResult(UnlockResult::NoPendingChallenge)
        }

        #[cfg(feature = "debug-trigger")]
        AdminMessage::DebugForcePosture(state) => {
            let target = match state {
                nn_proto::admin_protocol::DebugForcePosture::Observing => {
                    nn_model::posture_types::PostureKind::Observing
                }
                nn_proto::admin_protocol::DebugForcePosture::Alerted => {
                    nn_model::posture_types::PostureKind::Alerted
                }
                nn_proto::admin_protocol::DebugForcePosture::Engaged => {
                    nn_model::posture_types::PostureKind::Engaged
                }
                nn_proto::admin_protocol::DebugForcePosture::Combat => {
                    nn_model::posture_types::PostureKind::Combat
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
        Err(AdminAuthError::TooManySignatures { .. }) => return AdminResult::InvalidSignature,
        Err(AdminAuthError::PayloadVerify(e)) => {
            warn!(error = ?e, "shutdown payload verify failed at common layer");
            return AdminResult::InvalidSignature;
        }
    };

    // Per §10.3 step 2: the marker carries what the admins signed and
    // this agent's pid, so the watchdog can verify it against admin.pub
    // as we just did (external audit WDG-001) — a marker it cannot
    // verify makes it respawn us.
    //
    // External audit AUT-001: the verify above refuses a payload whose
    // extra is not a shutdown's (`admin_signed_payload::check_op`); it
    // only checked the op tag, and this fallback stood down with a grace
    // nobody signed. A payload that reaches here otherwise is refused.
    let grace_secs = match &req.payload.extra {
        OperationExtra::Shutdown(s) => s.grace_secs,
        other => {
            error!(
                extra = ?other.op_code(),
                "shutdown payload extra is not a shutdown's after verify — refused"
            );
            return AdminResult::UnknownOperation;
        }
    };
    *fps_out = matched_fps;
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
///
/// External audit ASK-015: the journal line and the audit row (through
/// `notes.force_from`) name the state the force left, as the posture
/// machine read it under its lock; they named the state it entered.
fn dispatch_force_posture(
    req: ForcePostureRequest,
    auth: &ConnAuth<'_>,
    posture: &PostureMachine,
    fps_out: &mut Vec<String>,
    notes: &mut DispatchNotes,
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
        Err(AdminAuthError::TooManySignatures { .. }) => return AdminResult::InvalidSignature,
        Err(AdminAuthError::PayloadVerify(e)) => {
            warn!(error = ?e, "force-posture payload verify failed at common layer");
            return AdminResult::InvalidSignature;
        }
    };
    *fps_out = signers.fingerprints;
    // External audit NN-AUD-083: may this request release COMBAT?
    let may_release = signers.keys.iter().any(|k| k.authorizes(Role::Unlock));

    // Extract the target from the verified payload. The verify checks
    // the op/extra invariant (`admin_signed_payload::check_op`, external
    // audit AUT-001 — before it, only the op tag was checked and this
    // match was the only guard), so this is the ForcePosture variant; the
    // match keeps the compiler exhaustive and refuses with
    // UnknownOperation if a future refactor ever breaks the invariant.
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
    // `admin_force_state_signed_by` consumes the token, fires
    // hooks per §12.2, and returns the state it left and the
    // post-transition state. It refuses COMBAT → non-COMBAT without
    // `may_release`; any other error shape maps to InvalidSignature
    // defensively. Lab PR 245: a COMBAT it enters names the keys that
    // signed the order as its cause, in the ladder's signed rows.
    match posture.admin_force_state_signed_by(signers.token, target, may_release, fps_out.clone()) {
        Ok(outcome) => {
            notes.force_from = Some(outcome.from);
            notes.force_release = outcome.release.map(Ok);
            info!(
                target: "admin.force_posture",
                from = ?outcome.from,
                to = ?outcome.state.kind(),
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
        // Lab PR 217 (NN-AUD-243 residue): leaving COMBAT released nothing
        // the tables confirm — the posture stays COMBAT, and the reply says
        // the request was not carried out (it was `Success`).
        Err(AdminReleaseError::ReleaseFailed(why)) => {
            error!(
                target: "admin.force_posture",
                to = ?target,
                why = %why,
                "force-posture out of COMBAT verified, but the isolation was NOT released — \
                 the posture stays COMBAT"
            );
            notes.force_release = Some(Err(why));
            AdminResult::ActionFailed
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
    if req.content.len() > nn_proto::admin_protocol::MAX_OVERLAY_BYTES {
        return refuse(
            AdminResult::Success,
            format!(
                "content larger than {} bytes",
                nn_proto::admin_protocol::MAX_OVERLAY_BYTES
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
    match crate::config::overlay_install::store(&target, &req.content, &sig) {
        // Lab PR 236: the per-rule policy is put in force at once, between
        // two events; the signed `config_overlay_set` row records it
        // (`applied` in its detail).
        Ok(sig_file) if extra.kind == nn_proto::admin_signed_payload::OverlayKind::RulePolicy => {
            use crate::decision::rule_policy as rp;
            let boot = rp::boot_policy(Some((&target, &req.content)));
            let summary = boot.policy.summary();
            let source = boot.policy.source.clone();
            let previous = rp::install_global(boot.policy);
            warn!(
                target: "admin.config_overlay",
                path = %target.display(),
                source = %source,
                summary = %summary,
                previous = %previous.source,
                signer_fp = %fps_out.first().map(String::as_str).unwrap_or(""),
                "signed per-rule response policy stored and applied"
            );
            ConfigOverlaySetResponse {
                result: AdminResult::Success,
                stored: true,
                message: format!(
                    "{} and {} written; applied now ({summary}; replaces {})",
                    target.display(),
                    sig_file.display(),
                    previous.source
                ),
            }
        }
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
