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
        // External audit AUT-006: a different key already has this
        // fingerprint; the wire keeps `InvalidSignature`.
        Err(crate::anti_tamper::admin_auth::RotateKeysError::FingerprintCollision {
            fingerprint,
        }) => {
            warn!(
                target: "admin.rotate_keys",
                fingerprint,
                "rotate-keys-add rejected: a different admin.pub key has the same fingerprint \
                 (revocation by fingerprint would be ambiguous)"
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
/// [`AdminKey::authorizes`]: nn_proto::admin_quorum::AdminKey::authorizes
fn role_beyond_signers(
    roles: &[Role],
    signers: &[nn_proto::admin_quorum::AdminKey],
) -> Option<Role> {
    let defaults;
    let granted = if roles.is_empty() {
        defaults = nn_proto::admin_quorum::default_roles();
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
        // External audit AUT-006: the fingerprint names several keys;
        // nothing was removed.
        Err(crate::anti_tamper::admin_auth::RotateKeysError::AmbiguousFingerprint {
            fingerprint,
            matches,
        }) => {
            warn!(
                target: "admin.rotate_keys",
                fingerprint,
                matches,
                "rotate-keys-revoke rejected: the fingerprint matches several different \
                 admin.pub keys; admin.pub left untouched"
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
            let window = ov.arm_by(
                window_secs,
                Instant::now(),
                fps_out.first().map(String::as_str).unwrap_or("(unknown)"),
            );
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
    use nn_proto::admin_signed_payload::FimReportExtra;

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
    let tail = crate::chain_tail::read_chain_tail::<crate::chain_host_linux::LinuxHost>(
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
    use nn_proto::admin_protocol::{
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

/// The whole status, telemetry included: the reply to the signed
/// [`TelemetryStatusRequest`] (external audit ASK-009, lab PR 213).
fn telemetry_status(
    posture: &PostureMachine,
    isolator: &NetworkIsolator,
    response_state: Option<&ResponseAdminState>,
) -> StatusResponse {
    let evidence = response_state.map(|s| (s.combat_evidence)());
    let encrypted = crate::net::blind_spots::encrypted_flows();
    let trust = crate::boot::trust::current();
    let execq = crate::execq::snapshot();
    let ransom = crate::impact::published_counts();
    let defense = crate::impair::published_counts();
    let execpol = crate::execpol::snapshot();
    StatusResponse {
        posture: posture.current_kind(),
        network_isolation_engaged: isolator.is_engaged(),
        // Lab PR 217 (capability C18): per IP family, as read back.
        network_isolation_v4: Some(isolator.is_isolated(Family::V4)),
        network_isolation_v6: Some(isolator.is_isolated(Family::V6)),
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
        net_inactive_rules: Some(crate::net::blind_spots::inactive_net_rules()),
        // Lab PR 164: the kernel's connect→close socket map.
        flow_sock_pending: crate::sensors::flow_sock::snapshot().map(|o| o.pending),
        flow_sock_capacity: crate::sensors::flow_sock::snapshot().map(|o| o.capacity),
        flow_sock_forgotten_min: crate::sensors::flow_sock::snapshot().map(|o| o.forgotten_min),
        // External audit CMB-018: an enforcing agent and a detect-only
        // one no longer look the same.
        detect_only: response_state.map(|s| s.config.dry_run),
        detect_only_source: response_state.and_then(|s| s.detect_only_source.clone()),
        // External audit CMB-027: what the signed audit log lacks.
        combat_evidence_unrecorded: evidence.map(|c| c.unrecorded),
        combat_evidence_pending: evidence.map(|c| c.pending),
        combat_evidence_dropped: evidence.map(|c| c.dropped),
        // External audit NET-017 (lab PR 207): the rows no DNS or TLS
        // reader sees into.
        net_dot_rows_total: Some(encrypted.dot),
        net_dot_rows_resolver: Some(encrypted.dot_resolver),
        net_quic_rows_total: Some(encrypted.quic),
        // Lab PR 215: operations a deny hook let through undecided.
        deny_fail_open_total: crate::anti_tamper::fail_open::total(),
        deny_fail_open: crate::anti_tamper::fail_open::total()
            .map(|_| crate::anti_tamper::fail_open::snapshot_nonzero()),
        // Lab PR 218: the trust level now, the degradations of this run and
        // the boot's signed capability manifest.
        trust_level: trust.as_ref().map(|t| t.level.as_u8()),
        trust_reasons: trust.map(|t| t.reasons),
        degradations: Some(crate::boot::degradation::snapshot()),
        capability_manifest: crate::boot::manifest::current_json(),
        // Lab PR 219: the exploit post-condition guard.
        exploit_guard: Some(crate::sensors::epg::status()),
        // Lab PR 222: the copy-on-first-write guard.
        cow_guard: crate::cow::status(),
        // Lab PR 223 (EXPERIMENTAL): the exec quarantine.
        execq_state: Some(execq.state),
        execq_held_total: Some(execq.held),
        execq_resumed_total: Some(execq.resumed),
        execq_killed_total: Some(execq.killed),
        execq_quarantined_total: Some(execq.quarantined),
        execq_defaulted_total: Some(execq.defaulted),
        execq_known_identity_total: Some(execq.known_identity),
        execq_known_hash_total: Some(execq.known_hash),
        execq_not_held_total: Some(execq.not_held),
        execq_scanner_deaths_total: Some(execq.scanner_deaths),
        // Lab PR 224 (CM-02): connect-time verdicts, open-flow snapshots,
        // the optional kernel connect deny.
        net_connect_verdicts_total: Some(crate::decision::engine::connect_verdicts_total()),
        net_flow_snapshots_total: Some(crate::net::flow_tracker::snapshots_total()),
        net_flow_snapshots_deferred_total: Some(
            crate::net::flow_tracker::snapshots_deferred_total(),
        ),
        net_connect_denied_total: crate::sensors::connect_deny::denied_total(),
        // Lab PR 225: the ransomware signal and the security tools.
        ransomware_decisive_total: ransom.map(|c| c.decisive),
        ransomware_signals_total: ransom.map(|c| c.signals),
        ransomware_trusted_total: ransom.map(|c| c.trusted),
        ransomware_samplings_total: ransom.map(|c| c.samplings),
        defense_tamper_total: defense.map(|c| c.findings),
        defense_tamper_sanctioned_total: defense.map(|c| c.sanctioned),
        defense_tools_watched: defense.map(|c| c.defenders),
        // Lab PR 226 (EXPERIMENTAL): the exec policy.
        execpol_state: Some(execpol.state),
        execpol_denied_total: Some(execpol.denied),
        execpol_would_deny_total: Some(execpol.would_deny),
        execpol_quarantine_total: Some(execpol.quarantine),
        execpol_quarantine_inactive_total: Some(execpol.quarantine_inactive),
        execpol_env_denied_total: Some(execpol.env_denied),
        execpol_env_recorded_total: Some(execpol.env_recorded),
        execpol_map_denied_total: Some(execpol.map_denied),
        execpol_map_recorded_total: Some(execpol.map_recorded),
        execq_script_refused_total: Some(execq.script_refused),
    }
}

/// External audit ASK-009 (lab PR 213): the reply to the unsigned `status`
/// — the posture, the isolation, the last admin action and where the COMBAT
/// ladder stands, what the watchdog and COMBAT recovery read. The
/// telemetry (ring drops and rejected records, netflow pacing and
/// evictions, `FLOW_SOCK_MAP`, the inactive network rules, detect-only, the
/// COMBAT evidence gaps, the encrypted-flow counts) is not even computed:
/// it told a local root without an admin key how much the agent was losing
/// — the feedback of a ring flood — and is the signed verb's.
fn public_status(
    posture: &PostureMachine,
    isolator: &NetworkIsolator,
    response_state: Option<&ResponseAdminState>,
) -> StatusResponse {
    StatusResponse::public(
        posture.current_kind(),
        isolator.is_engaged(),
        posture.last_admin_action_secs_ago(),
        response_state.and_then(|s| (s.combat_stage)()),
        Some(posture.is_combat_locked()),
    )
    // Lab PR 217 (capability C18): the isolation per IP family, public.
    .with_isolation_families(
        isolator.is_isolated(Family::V4),
        isolator.is_isolated(Family::V6),
    )
}

/// The read roles the signed telemetry verb accepts, either one: the
/// `audit-read` every key carries by default (the bootstrap key of
/// `install.sh` included), and the `telemetry-read` of a dashboard key
/// (`triage` and `all` imply it). The counters are no more than what an
/// `audit-read` key already reads in the signed audit log.
const TELEMETRY_STATUS_ROLES: [Role; 2] = [Role::AuditRead, Role::TelemetryRead];

/// `nn-admin status --key` / `nn-admin net status --key` (external audit
/// ASK-009, lab PR 213): the whole status, 1-of-N, `audit-read` or
/// `telemetry-read` ([`TELEMETRY_STATUS_ROLES`]); one audit row per request.
fn dispatch_telemetry_status(
    req: TelemetryStatusRequest,
    auth: &ConnAuth<'_>,
    posture: &PostureMachine,
    isolator: &NetworkIsolator,
    response_state: Option<&ResponseAdminState>,
    fps_out: &mut Vec<String>,
) -> TelemetryStatusResponse {
    let refuse = |result| TelemetryStatusResponse {
        result,
        status: None,
    };
    let sigs: Vec<[u8; 64]> = req.signatures.iter().map(|s| s.signature).collect();
    // No role in the quorum check (it would want each listed role): the
    // signer's roles are checked below, any one of the two.
    let signers = match auth.verify_signed_payload_quorum_keys(
        &req.payload,
        &sigs,
        1,
        &[],
        OperationCode::TelemetryStatus,
        now_unix_secs(),
    ) {
        Ok(v) => v,
        Err(e) => return refuse(map_admin_auth_error(e, "telemetry-status")),
    };
    *fps_out = signers.fingerprints;
    if !signers
        .keys
        .iter()
        .any(|k| TELEMETRY_STATUS_ROLES.iter().any(|r| k.authorizes(*r)))
    {
        warn!(
            target: "anti_tamper.admin_auth.verify_failure",
            reason = "role_denied",
            required = "audit-read or telemetry-read",
            "telemetry-status refused: the signer holds neither read role"
        );
        return refuse(AdminResult::RoleDenied);
    }
    if !matches!(&req.payload.extra, OperationExtra::TelemetryStatus(_)) {
        warn!("telemetry-status payload extra is not TelemetryStatus variant");
        return refuse(AdminResult::UnknownOperation);
    }
    TelemetryStatusResponse {
        result: AdminResult::Success,
        status: Some(telemetry_status(posture, isolator, response_state)),
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
        detail = %nn_model::log_escape::Escaped(&message),
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
                path = %nn_model::log_escape::Escaped(&path),
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

/// Lab PR 222: `nn-admin remediate ransomware --pid N | --since TS
/// [--dry-run]` (`response-manage`): restore, from the copy-on-first-write
/// journal, the files the process tree rewrote (or every file copied since
/// the time). The agent does the work under the rules of
/// [`crate::cow::restore`] and signs one `cow_restore` row per file.
fn dispatch_remediate_ransomware(
    req: RemediateRansomwareRequest,
    auth: &ConnAuth<'_>,
    fps_out: &mut Vec<String>,
) -> RemediateRansomwareResponse {
    let refuse = |result: AdminResult, message: String| RemediateRansomwareResponse {
        result,
        done: false,
        message,
        rows: Vec::new(),
        rows_total: 0,
        restored: 0,
        recreated: 0,
        kept_both: 0,
        unchanged: 0,
        refused: 0,
        skipped: 0,
    };
    let sigs: Vec<[u8; 64]> = req.signatures.iter().map(|s| s.signature).collect();
    let (_token, matched_fps) = match auth.verify_signed_payload_quorum(
        &req.payload,
        &sigs,
        1,
        &[Role::ResponseManage],
        OperationCode::RemediateRansomware,
        now_unix_secs(),
    ) {
        Ok(t) => t,
        Err(e) => {
            return refuse(
                map_admin_auth_error(e, "remediate-ransomware"),
                String::new(),
            )
        }
    };
    *fps_out = matched_fps;
    let OperationExtra::RemediateRansomware(extra) = &req.payload.extra else {
        warn!("remediate-ransomware payload extra is not RemediateRansomware variant");
        return refuse(AdminResult::UnknownOperation, String::new());
    };
    let key_fp = fps_out.first().cloned().unwrap_or_default();
    let report = match crate::cow::admin_restore(extra.pid, extra.since_unix, extra.dry_run, key_fp)
    {
        Ok(r) => r,
        Err(why) => return refuse(AdminResult::Success, why),
    };
    if let Some(why) = report.refusal.clone() {
        return refuse(AdminResult::Success, why);
    }
    let total = report.rows.len();
    // Keep the reply inside a frame: at most REMEDIATE_ROWS_MAX rows and
    // about 48 KiB of them (a path is up to PATH_MAX).
    let mut budget = 48 * 1024usize;
    let mut rows = Vec::new();
    for r in &report.rows {
        let clip = |s: &str| s.chars().take(512).collect::<String>();
        let row = nn_proto::admin_protocol::CowRestoreRow {
            path: clip(&r.path),
            action: r.action.clone(),
            entry: r.entry,
            detail: clip(&r.detail),
            beside: r.beside.as_deref().map(clip),
            evidence: r.evidence.as_deref().map(clip),
            sha256_original: r.sha256_original.clone(),
            sha256_after: r.sha256_after.clone(),
        };
        let cost = row.path.len()
            + row.detail.len()
            + row.beside.as_ref().map_or(0, |s| s.len())
            + row.evidence.as_ref().map_or(0, |s| s.len())
            + 200;
        if rows.len() >= nn_proto::admin_protocol::REMEDIATE_ROWS_MAX || cost > budget {
            break;
        }
        budget -= cost;
        rows.push(row);
    }
    let done = if extra.dry_run {
        report.restored + report.recreated + report.kept_both > 0
    } else {
        report.restored + report.recreated > 0
    };
    let message = format!(
        "{}{} file(s): {} restored in place, {} recreated, {} kept both, {} unchanged, {} refused, {} skipped{}",
        if extra.dry_run { "dry run — " } else { "" },
        total,
        report.restored,
        report.recreated,
        report.kept_both,
        report.unchanged,
        report.refused,
        report.skipped,
        if rows.len() < total {
            format!(" ({} listed; every file is in the signed audit log)", rows.len())
        } else {
            String::new()
        }
    );
    warn!(
        target: "admin.remediate_ransomware",
        signer_fp = %fps_out.first().map(String::as_str).unwrap_or(""),
        pid = ?extra.pid,
        since = ?extra.since_unix,
        dry_run = extra.dry_run,
        detail = %message,
        "remediate ransomware"
    );
    RemediateRansomwareResponse {
        result: AdminResult::Success,
        done,
        message,
        rows,
        rows_total: total as u32,
        restored: report.restored,
        recreated: report.recreated,
        kept_both: report.kept_both,
        unchanged: report.unchanged,
        refused: report.refused,
        skipped: report.skipped,
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
        // External audit AUT-005: no wire variant of its own; the journal
        // line of the verify names it.
        AdminAuthError::TooManySignatures { .. } => AdminResult::InvalidSignature,
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
    deployment: &nn_proto::admin_signed_payload::CanaryDeploymentWire,
) -> Option<&str> {
    use nn_proto::admin_signed_payload::CanaryDeploymentWire;
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
    use nn_proto::admin_signed_payload::OperationExtra;

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

    // External audit DEC-015 (lab PR 178): a File / Credential path is
    // judged, written, recorded and watched in its normal form (`//`
    // folded) — the deny prefixes used to be matched on the raw string.
    let mut extra = extra;
    extra.deployment = match crate::canary::path_policy::normalised_deployment(&extra.deployment) {
        Ok(d) => d,
        Err(e) => {
            warn!(
                error = %format!("{e:#}"),
                signer_fp = %primary_fp,
                "canary-deploy: REFUSED — canary path"
            );
            return CanaryDeployResponse {
                result: AdminResult::UnknownOperation,
                canary_id: String::new(),
            };
        }
    };

    // Lab PR 163: a network canary trips on a connect to its address and
    // port (`canary::network`). One whose address is not an IP address
    // could never trip, and one where a listener on this host takes the
    // connections would trip on every client of that service.
    if let nn_proto::admin_signed_payload::CanaryDeploymentWire::Network {
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
        canary_name = %nn_model::log_escape::Escaped(&entry.name),
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
    deployment: &nn_proto::admin_signed_payload::CanaryDeploymentWire,
    state: &CanaryAdminState,
) -> Result<(Option<common::wire::InodeKey>, Option<DecoyContent>)> {
    use crate::canary::templates::{new_content_seed, render, render_file_body, CredFamily};
    use nn_proto::admin_signed_payload::CanaryDeploymentWire;
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
    use nn_proto::admin_signed_payload::OperationExtra;

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
    use nn_proto::admin_signed_payload::OperationExtra;

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
    use nn_proto::admin_signed_payload::OperationExtra;

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
    use nn_proto::admin_signed_payload::NetFlowsExtra;

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
    use nn_proto::admin_signed_payload::NetResolveExtra;

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
    use nn_proto::admin_signed_payload::NetFingerprintExtra;

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
