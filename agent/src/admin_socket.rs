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

use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, Result};
use parking_lot::Mutex;
use std::os::unix::fs::PermissionsExt;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use tracing::{info, warn};

use common::wire::admin_protocol::{
    decode_frame, encode_frame, AdminMessage, AdminResult, CanaryBurnRequest, CanaryDeployRequest,
    CanaryDeployResponse, CanaryListRequest, CanaryListResponse, CanaryRefreshRequest, Challenge,
    FimBaselineRequest, FimReportRequest, FimReportResponse, FimStatusRequest, FimStatusResponse,
    ForcePostureRequest, NetFingerprintRequest, NetFingerprintResponse, NetFlowsRequest,
    NetFlowsResponse, NetListenersRequest, NetListenersResponse, NetResolveRequest,
    NetResolveResponse, RotateKeysAddRequest, RotateKeysRevokeRequest, ShutdownRequest,
    StatusResponse, UnlockResult, MAX_FRAME_BODY,
};
use common::wire::admin_signed_payload::{OperationCode, OperationExtra, Role};
use ed25519_dalek::VerifyingKey;
use sha2::{Digest, Sha256};

use crate::anti_tamper::admin_auth::{AdminAuth, AdminAuthError};
use crate::anti_tamper::network_isolate::NetworkIsolator;
use crate::audit::{AuditEntryDraft, AuditLog};
use crate::canary::detector::CanaryIndexes;
use crate::canary::registry::{CanaryTokenDraft, Registry, RegistryError};
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

/// Bind the admin socket and run the accept loop forever. Returns
/// only on a fatal listener error (`accept()` returning `Err`); the
/// agent's main loop is expected to also exit on the same condition.
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

    loop {
        let (stream, _) = listener
            .accept()
            .await
            .context("accepting admin connection")?;
        let auth = Arc::clone(&auth);
        let posture = Arc::clone(&posture);
        let isolator = Arc::clone(&isolator);
        let marker_path = marker_path.clone();
        let shutdown_signal = shutdown_signal.clone();
        let audit_log = audit_log.clone();
        let fim_state = fim_state.clone();
        let canary_state = canary_state.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_connection(
                stream,
                &auth,
                &posture,
                &isolator,
                &marker_path,
                shutdown_signal.as_ref(),
                audit_log.as_ref(),
                fim_state.as_ref(),
                canary_state.as_ref(),
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

/// Drive one connection until the client closes the stream. Each
/// iteration reads exactly one frame and writes exactly one reply;
/// the `nn-admin unlock` flow uses two iterations (challenge then
/// unlock) and then closes.
#[allow(clippy::too_many_arguments)]
async fn handle_connection(
    mut stream: UnixStream,
    auth: &AdminAuth,
    posture: &PostureMachine,
    isolator: &NetworkIsolator,
    marker_path: &Path,
    shutdown_signal: Option<&ShutdownSignal>,
    audit_log: Option<&Arc<Mutex<AuditLog>>>,
    fim_state: Option<&Arc<FimAdminState>>,
    canary_state: Option<&Arc<CanaryAdminState>>,
) -> Result<()> {
    // Capture peer creds once per connection — the audit log
    // wants pid/uid/comm of the caller, and a single connection
    // never changes peers mid-stream (SO_PEERCRED is fixed at
    // accept time).
    let client = peer_creds(&stream);
    loop {
        let msg = match read_frame(&mut stream).await? {
            Some(m) => m,
            None => return Ok(()),
        };
        let mut matched_fps: Vec<String> = Vec::new();
        let reply = dispatch(
            msg.clone(),
            auth,
            posture,
            isolator,
            marker_path,
            shutdown_signal,
            fim_state.map(|s| s.as_ref()),
            canary_state.map(|s| s.as_ref()),
            &mut matched_fps,
        );
        emit_audit_for(&msg, &reply, &client, audit_log, &matched_fps);
        write_frame(&mut stream, &reply).await?;
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
    auth: &AdminAuth,
    posture: &PostureMachine,
    isolator: &NetworkIsolator,
    marker_path: &Path,
    shutdown_signal: Option<&ShutdownSignal>,
    fim_state: Option<&FimAdminState>,
    canary_state: Option<&CanaryAdminState>,
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
            AdminMessage::FimReportResponse(dispatch_fim_report(req, auth, fps_out))
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
            AdminMessage::NetFlowsResponse(dispatch_net_flows(req, auth, fps_out))
        }
        AdminMessage::NetListenersRequest(req) => {
            AdminMessage::NetListenersResponse(dispatch_net_listeners(req, auth, fps_out))
        }
        AdminMessage::NetResolveRequest(req) => {
            AdminMessage::NetResolveResponse(dispatch_net_resolve(req, auth, fps_out))
        }
        AdminMessage::NetFingerprintRequest(req) => {
            AdminMessage::NetFingerprintResponse(dispatch_net_fingerprint(req, auth, fps_out))
        }

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
        | AdminMessage::NetFingerprintResponse(_) => {
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
    auth: &AdminAuth,
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

    // Per §10.3 step 2: build the marker. entry_hash is the
    // SHA-256 over signing_digest(payload) — a stable opaque
    // token until A11's audit hash chain replaces it with the
    // actual audit-log entry hash. grace_deadline = now + grace.
    let grace_secs = match &req.payload.extra {
        common::wire::admin_signed_payload::OperationExtra::Shutdown(s) => s.grace_secs,
        // Other extras can't reach here — verify_signed_payload_quorum
        // already enforced expected_op = Shutdown, which implies the
        // extra variant via SignedPayload's op/extra invariant.
        // Belt-and-suspenders default keeps the match exhaustive.
        _ => 30,
    };
    let grace_deadline_unix_ts = server_now.saturating_add(u64::from(grace_secs));

    let digest = match common::wire::admin_signed_payload::signing_digest(&req.payload) {
        Ok(d) => d,
        Err(e) => {
            warn!(error = ?e, "computing signing digest for marker entry_hash failed");
            return AdminResult::InvalidSignature;
        }
    };
    let mut hasher = Sha256::new();
    hasher.update(digest);
    let entry_hash = hex::encode(hasher.finalize());

    let marker = ShutdownMarker {
        entry_hash,
        grace_deadline_unix_ts,
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
/// [`crate::anti_tamper::admin_auth::AdminAuth::verify_signed_payload_quorum`]
/// (Tappa 8 A7) and surfaces as `UnknownOperation` on the wire.
///
/// On verify success, mutates the posture machine to the requested
/// target via [`PostureMachine::admin_force_state_with_token`]
/// (Tappa 8 A10), which fires the COMBAT entry/release hooks per
/// §12.2 if the direction crosses the COMBAT boundary.
fn dispatch_force_posture(
    req: ForcePostureRequest,
    auth: &AdminAuth,
    posture: &PostureMachine,
    fps_out: &mut Vec<String>,
) -> AdminResult {
    let server_now = now_unix_secs();
    let sigs: Vec<[u8; 64]> = req.signatures.iter().map(|s| s.signature).collect();

    let verify_outcome = auth.verify_signed_payload_quorum(
        &req.payload,
        &sigs,
        1, // 1-of-N per §3.3
        &[Role::ForcePosture],
        OperationCode::ForcePosture,
        server_now,
    );

    let (token, matched_fps) = match verify_outcome {
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
            warn!(error = ?e, "force-posture payload verify failed at common layer");
            return AdminResult::InvalidSignature;
        }
    };
    *fps_out = matched_fps;

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
    // hooks per §12.2, and returns the post-transition state.
    // Today the method's signature is infallible (no error variant
    // produced — any → any is allowed) but we map any future error
    // shape to InvalidSignature defensively.
    match posture.admin_force_state_with_token(token, target) {
        Ok(state) => {
            info!(
                target: "admin.force_posture",
                from = ?state.kind(),
                to = ?target,
                "production force-posture applied"
            );
            AdminResult::Success
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
fn dispatch_rotate_keys_add(
    req: RotateKeysAddRequest,
    auth: &AdminAuth,
    fps_out: &mut Vec<String>,
) -> AdminResult {
    // BUG-013 (PHASE 15.1): bootstrap-mode 1-of-N gate. Consulted
    // BEFORE verify_signed_payload_quorum so the relaxed min_distinct
    // (1) goes into the verify call. The gate is evaluated against
    // on-disk state (sentinel + nonce + admin.pub key count) and ALL
    // three anti-downgrade conditions must hold; any other outcome
    // falls through to the permanent 2-of-N path. See
    // `crate::anti_tamper::bootstrap` for the full security argument.
    let bootstrap_armed = match auth.config_path() {
        Some(admin_pub_path) => {
            let paths = crate::anti_tamper::bootstrap::BootstrapPaths::default_paths(
                admin_pub_path.to_path_buf(),
            );
            matches!(
                crate::anti_tamper::bootstrap::evaluate(&paths),
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

    let (_token, matched_fps) = match auth.verify_signed_payload_quorum(
        &req.payload,
        &sigs,
        min_distinct, // 2-of-N normally; 1-of-N when bootstrap-armed (BUG-013)
        &[Role::RotateKeys],
        OperationCode::RotateKeysAdd,
        server_now,
    ) {
        Ok(t) => t,
        Err(e) => return map_admin_auth_error(e, "rotate-keys-add"),
    };
    *fps_out = matched_fps;

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

    let Some(config_path) = auth.config_path() else {
        warn!(
            "rotate-keys-add: AdminAuth has no config_path — agent was loaded \
             via in-memory builder, rotation requires a real admin.pub file"
        );
        return AdminResult::UnknownOperation;
    };
    let config_path = config_path.to_path_buf();

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

    info!(
        target: "admin.rotate_keys",
        new_key_fp = %hex::encode(crate::anti_tamper::admin_auth::fingerprint_bytes(&new_pubkey)),
        role_count = roles.len(),
        bootstrap_armed,
        "rotate-keys add: admin.pub updated + in-memory keys reloaded"
    );
    AdminResult::Success
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
    auth: &AdminAuth,
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
    auth: &AdminAuth,
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
    auth: &AdminAuth,
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
/// payload's extra is best-effort: the dispatcher walks the
/// chain in order and yields entries whose `ts` field is `>=`
/// the threshold (lexicographic ISO-8601 compare, valid
/// because the format is fixed-width).
fn dispatch_fim_report(
    req: FimReportRequest,
    auth: &AdminAuth,
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
        read_fim_drift_jsonl(crate::fim::drain::DEFAULT_DRIFT_LOG_PATH, since);
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

/// Read the drift log at `path` and return `(jsonl_body,
/// count, truncated_flag)`. Filter rule: keep entries whose
/// `ts` field is lexicographically `>=` the supplied `since`
/// (UNIX-ts encoded as ISO-8601, falls back to "include all"
/// when `since` is None). Caps the wire-side body at half of
/// MAX_FRAME_BODY so the rest of the FimReportResponse envelope
/// fits comfortably in one frame. On overflow, sets
/// `truncated=true` and stops appending; the operator can
/// narrow via the CLI's `--since` flag.
fn read_fim_drift_jsonl(path: &str, since: Option<u64>) -> (String, u32, bool) {
    use std::io::{BufRead, BufReader};
    const SOFT_CAP: usize = MAX_FRAME_BODY / 2;
    let f = match std::fs::OpenOptions::new().read(true).open(path) {
        Ok(f) => f,
        Err(_) => return (String::new(), 0, false),
    };
    let reader = BufReader::new(f);
    let since_str = since.map(format_iso8601_unix);
    let mut out = String::new();
    let mut count = 0u32;
    let mut truncated = false;
    for line in reader.lines() {
        let Ok(line) = line else { continue };
        if line.is_empty() {
            continue;
        }
        if let Some(threshold) = &since_str {
            // Coarse pass: substring-match the first ts field
            // rather than parse JSON. Format §4.2 puts ts as
            // the first field, so the second `"` opens the
            // ISO timestamp string.
            if let Some(ts_value) = extract_ts_field(&line) {
                if ts_value.as_str() < threshold.as_str() {
                    continue;
                }
            }
        }
        if out.len() + line.len() + 1 > SOFT_CAP {
            truncated = true;
            break;
        }
        out.push_str(&line);
        out.push('\n');
        count += 1;
    }
    (out, count, truncated)
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
fn rebuild_canary_indexes(state: &CanaryAdminState) {
    use common::wire::admin_signed_payload::CanaryDeploymentWire;
    use common::wire::InodeKey;
    use std::os::unix::fs::MetadataExt;
    use std::path::Path;

    // The K3 detector's `is_canary_exe` HashMap also serves
    // as the File/Credential path lookup (per the K3 V1.0
    // pragmatism note). We populate it here from the
    // deployment.path of every File + Credential canary AND
    // from the deployment.path of every Process canary. The
    // rebuild_from_registry helper's match arms only populate
    // exe_index for Process today, so K6 has to layer the
    // File/Credential paths in after the rebuild.
    let mut idx = state.indexes.lock();
    let reg = state.registry.lock();
    idx.rebuild_from_registry(&reg, |path: &Path| {
        std::fs::symlink_metadata(path).ok().map(|m| {
            let st_dev = m.dev();
            let major = libc::major(st_dev) as u64;
            let minor = libc::minor(st_dev) as u64;
            InodeKey {
                dev: (major << 20) | minor,
                ino: m.ino(),
            }
        })
    });
    // Layer File + Credential paths into the exe_index so the
    // K3 path-based fallback matches. The K3 V1.0 detector
    // uses the same `exe_index` HashMap for both Process exe
    // paths AND File/Credential paths.
    for canary in reg.list() {
        match &canary.deployment {
            CanaryDeploymentWire::File { path, .. }
            | CanaryDeploymentWire::Credential { path, .. } => {
                idx.add_file_path_index(path.into(), canary.canary_id.clone());
            }
            _ => {}
        }
    }
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
    auth: &AdminAuth,
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

    // For File + Credential types: render the file content +
    // write to the deployment path. The K3 detector matches
    // on the resulting inode (after rebuild_canary_indexes
    // stats it).
    let primary_fp = fps_out.first().cloned().unwrap_or_default();
    if let Err(e) = materialise_canary_file(&extra.deployment, state, &primary_fp) {
        warn!(
            error = %e,
            "canary-deploy: file materialisation failed"
        );
        return CanaryDeployResponse {
            result: AdminResult::UnknownOperation,
            canary_id: String::new(),
        };
    }

    // Deploy via the K2 registry. Allocates the canary_id +
    // appends the Deploy row to the chain.
    let draft = CanaryTokenDraft {
        name: extra.name.clone(),
        canary_type: extra.canary_type,
        deployment: extra.deployment.clone(),
        deployed_by_fp: primary_fp.clone(),
    };
    let entry = {
        let mut reg = state.registry.lock();
        match reg.deploy(draft) {
            Ok(e) => e,
            Err(e) => {
                warn!(error = %e, "canary registry deploy failed");
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

/// Write the canary file to its deployment path. For
/// `Credential` types, renders the K4 template content for
/// the operator's chosen `cred_family`. For plain `File`
/// types, writes a placeholder body that operators can
/// later override via a future K6.1 `--content-file` flag —
/// V1.0 ships an explicit marker so the operator's `cat`
/// of the file (which would trip the canary) shows a
/// readable "this is a NorthNarrow canary" comment.
/// Process + Network canaries return Ok(()) — they don't
/// materialise a file at deploy time.
fn materialise_canary_file(
    deployment: &common::wire::admin_signed_payload::CanaryDeploymentWire,
    state: &CanaryAdminState,
    deployed_by_fp: &str,
) -> Result<()> {
    use crate::canary::templates::{render, CredFamily};
    use common::wire::admin_signed_payload::CanaryDeploymentWire;
    match deployment {
        CanaryDeploymentWire::File { path, .. } => {
            // File canary content placeholder. Operator can
            // overwrite via a future --content-file flag. K7
            // install.sh will ship a sample template
            // `configs/canary-templates/file_placeholder.tmpl`
            // for operators who want richer content.
            let body = format!(
                "# NorthNarrow XDR canary file.\n\
                 # Deployed by operator key fp {deployed_by_fp}.\n\
                 # Any access to this file triggers NN-L-CANARY-001.\n"
            );
            ensure_parent_dir(std::path::Path::new(path))?;
            std::fs::write(path, body)
                .map_err(|e| anyhow::anyhow!("writing file canary {path}: {e}"))?;
            Ok(())
        }
        CanaryDeploymentWire::Credential { path, cred_family } => {
            let family = CredFamily::from_wire(cred_family)
                .map_err(|e| anyhow::anyhow!("unknown cred_family `{cred_family}`: {e}"))?;
            // Render with the future canary_id (the registry's
            // compute_canary_id is deterministic per (name +
            // deployed_at_unix); we can't predict deployed_at_unix
            // pre-deploy, so use the deployed_by_fp + path as a
            // stable seed surrogate). K2 registry will re-seed
            // with the real canary_id post-deploy; the on-disk
            // content uses this earlier seed but the K3 detector
            // matches on inode/path not on content.
            let seed = format!("{deployed_by_fp}:{path}");
            let body = render(family, &seed, state.template_dir.as_deref())
                .map_err(|e| anyhow::anyhow!("rendering cred canary: {e}"))?;
            ensure_parent_dir(std::path::Path::new(path))?;
            std::fs::write(path, body)
                .map_err(|e| anyhow::anyhow!("writing cred canary {path}: {e}"))?;
            Ok(())
        }
        // Process + Network canaries: no file materialisation
        // at deploy time. K7 install.sh / K8 e2e set up the
        // binary placement + listener spawn separately.
        CanaryDeploymentWire::Process { .. } | CanaryDeploymentWire::Network { .. } => Ok(()),
    }
}

fn ensure_parent_dir(path: &std::path::Path) -> Result<()> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() && !parent.exists() {
            std::fs::create_dir_all(parent)
                .map_err(|e| anyhow::anyhow!("creating parent dir {}: {e}", parent.display()))?;
        }
    }
    Ok(())
}

/// dispatch_canary_list — verify 1-of-N quorum with
/// `Role::CanaryRead`, read the chained registry log from
/// disk, return the JSONL body with the standard truncation
/// flag (same shape as `dispatch_fim_report`).
fn dispatch_canary_list(
    req: CanaryListRequest,
    auth: &AdminAuth,
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
    let (entries_jsonl, entries_count, entries_truncated) = read_jsonl_chain(&log_path);
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

/// Generic chain reader matching the `dispatch_fim_report`
/// truncation contract. Returns `(jsonl_body, count, truncated)`.
/// Used for canary chains (no `--since` filter today;
/// canary registries are small enough that operators always
/// want the full chain).
fn read_jsonl_chain(path: &std::path::Path) -> (String, u32, bool) {
    use std::io::{BufRead, BufReader};
    const SOFT_CAP: usize = MAX_FRAME_BODY / 2;
    let f = match std::fs::OpenOptions::new().read(true).open(path) {
        Ok(f) => f,
        Err(_) => return (String::new(), 0, false),
    };
    let reader = BufReader::new(f);
    let mut out = String::new();
    let mut count = 0u32;
    let mut truncated = false;
    for line in reader.lines() {
        let Ok(line) = line else { continue };
        if line.is_empty() {
            continue;
        }
        if out.len() + line.len() + 1 > SOFT_CAP {
            truncated = true;
            break;
        }
        out.push_str(&line);
        out.push('\n');
        count += 1;
    }
    (out, count, truncated)
}

/// dispatch_canary_burn — verify 1-of-N quorum with
/// `Role::CanaryManage`, call Registry::burn, rebuild indexes
/// so the K3 detector stops matching on the burned canary.
fn dispatch_canary_burn(
    req: CanaryBurnRequest,
    auth: &AdminAuth,
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
    let result = {
        let mut reg = state.registry.lock();
        reg.burn(&canary_id, &primary_fp)
    };
    match result {
        Ok(_) => {
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
/// `Role::CanaryManage`, call Registry::refresh, rebuild
/// indexes (the registry mutation isn't index-shape-changing
/// but we rebuild for consistency).
fn dispatch_canary_refresh(
    req: CanaryRefreshRequest,
    auth: &AdminAuth,
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
    let result = {
        let mut reg = state.registry.lock();
        reg.refresh(&canary_id, &primary_fp)
    };
    match result {
        Ok(_) => {
            rebuild_canary_indexes(state);
            info!(
                target: "admin.canary_refresh",
                signer_fp = %primary_fp,
                canary_id = %canary_id,
                "canary refreshed (tripped flag cleared)"
            );
            AdminResult::Success
        }
        Err(e) => {
            if let Some(RegistryError::CanaryIdNotFound) = e.downcast_ref::<RegistryError>() {
                AdminResult::UnknownOperation
            } else {
                warn!(error = %e, "canary registry refresh failed");
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
//   * V1.0 stubs for listener/resolve/fingerprint dispatches:
//     return empty bodies. The wire shape ships now; the data
//     sources are wired in N8 and beyond.

/// Default on-disk location of the chained NetFlow log (design
/// §4.4 + §10). The Tappa 10 N8 deploy commit drops a zero-byte
/// placeholder here via `install.sh` + `bootstrap_netflow_log` at
/// agent startup. `dispatch_net_flows` tolerates the file being
/// absent — returns empty body + 0 count without erroring.
pub const DEFAULT_NETFLOW_JSONL_PATH: &str = "/var/lib/northnarrow/netflow.jsonl";

fn dispatch_net_flows(
    req: NetFlowsRequest,
    auth: &AdminAuth,
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

    // Re-use the FIM-drift JSONL reader (same on-disk shape: one
    // chained row per line, optional `ts` lexicographic filter).
    // N3 emission into `netflow.jsonl` is wired in a future
    // commit; until then, the read returns (empty, 0, false).
    let (entries_jsonl, entries_count, entries_truncated) =
        read_fim_drift_jsonl(DEFAULT_NETFLOW_JSONL_PATH, since);
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

fn dispatch_net_listeners(
    req: NetListenersRequest,
    auth: &AdminAuth,
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

    // V1.0 stub: the userland listener snapshot wiring is a
    // future commit (the N2 BPF program emits into
    // NET_LISTEN_EVENTS but no userland drain stores them
    // for admin-CLI consumption yet). Return Success + empty
    // body so the wire surface is exercised + audited.
    info!(
        target: "admin.net_listeners",
        signer_fp = %fps_out.first().map(String::as_str).unwrap_or(""),
        "net listeners served (V1.0 empty stub)"
    );
    NetListenersResponse {
        result: AdminResult::Success,
        entries_jsonl: String::new(),
        entries_count: 0,
        entries_truncated: false,
    }
}

fn dispatch_net_resolve(
    req: NetResolveRequest,
    auth: &AdminAuth,
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

    let ip_query = match &req.payload.extra {
        OperationExtra::NetResolve(NetResolveExtra { ip }) => ip.clone(),
        _ => {
            warn!("net-resolve payload extra is not NetResolve variant");
            return NetResolveResponse {
                result: AdminResult::UnknownOperation,
                qname: None,
                queried_at_unix_ts: None,
            };
        }
    };

    // V1.0 stub: the back-correlation N4 cache doesn't index by
    // resolved IP (no DNS-response observer yet — V1.1 ships
    // that). Return Success + `qname = None`. The wire shape is
    // ready; V1.1 plumbs DnsCache::lookup_for_ip into this slot.
    info!(
        target: "admin.net_resolve",
        signer_fp = %fps_out.first().map(String::as_str).unwrap_or(""),
        ip = %ip_query,
        "net resolve served (V1.0: no V1.1 DNS-response observer)"
    );
    NetResolveResponse {
        result: AdminResult::Success,
        qname: None,
        queried_at_unix_ts: None,
    }
}

fn dispatch_net_fingerprint(
    req: NetFingerprintRequest,
    auth: &AdminAuth,
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

    let flow_id = match &req.payload.extra {
        OperationExtra::NetFingerprint(NetFingerprintExtra { flow_id }) => flow_id.clone(),
        _ => {
            warn!("net-fingerprint payload extra is not NetFingerprint variant");
            return NetFingerprintResponse {
                result: AdminResult::UnknownOperation,
                entries_jsonl: String::new(),
                entries_count: 0,
                entries_truncated: false,
            };
        }
    };

    // V1.0 stub. Future commit wires the N3 FlowTracker's
    // in-process fingerprint cache (or reads netflow.jsonl
    // rows whose `tls_fingerprint` is populated).
    info!(
        target: "admin.net_fingerprint",
        signer_fp = %fps_out.first().map(String::as_str).unwrap_or(""),
        flow_id = %flow_id,
        "net fingerprint served (V1.0 empty stub)"
    );
    NetFingerprintResponse {
        result: AdminResult::Success,
        entries_jsonl: String::new(),
        entries_count: 0,
        entries_truncated: false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::admin_cli::{run_status, run_unlock, run_verify_keys};
    use crate::anti_tamper::admin_auth::DEFAULT_RATE_LIMIT_WINDOW;
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
        let _ = DEFAULT_RATE_LIMIT_WINDOW; // keep import alive for non-rate-limit tests

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

        // Smoke check: a status round-trip works.
        let socket_c = socket.clone();
        let out = tokio::task::spawn_blocking(move || run_status(&socket_c).unwrap())
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
                socket_c, auth_c, posture_c, isolator_c, marker_c, None, None, None, None,
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
            assert_eq!(marker.entry_hash.len(), 64);
            // grace_deadline = now + 30s; allow ±2s drift around
            // the system clock read at sign time vs dispatch time.
            let expected = now + 30;
            assert!(
                marker.grace_deadline_unix_ts.abs_diff(expected) <= 2,
                "grace_deadline_unix_ts={} expected ~{}",
                marker.grace_deadline_unix_ts,
                expected
            );

            // Suppress unused-key warnings from the move closure.
            let _ = (signing_a, signing_b);
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

    // ── Tappa 10 N7 — net admin dispatch + audit tests ────────────

    /// N7 dispatch test #1 — `net flows` with a `net-read` key
    /// returns Success + empty body when `netflow.jsonl` is
    /// absent (the V1.0 default — N3 emission into the file is
    /// future scope). Exercises the auth + extra-parse + empty-
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
        let nonce = auth.issue_challenge().unwrap();
        let payload = SignedPayload::new_net_flows(nonce, now_unix_secs(), agent_id, None);
        let sig: [u8; 64] = common::wire::admin_signed_payload::sign(&payload, &signing).unwrap();
        let req = NetFlowsRequest {
            payload,
            signatures: vec![KeyedSignature { signature: sig }],
        };
        let mut fps = Vec::new();
        let resp = dispatch_net_flows(req, &auth, &mut fps);
        assert!(matches!(resp.result, AdminResult::Success));
        // V1.0: netflow.jsonl doesn't exist at the default path
        // in this test env, so the body is empty.
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
        let nonce = auth.issue_challenge().unwrap();
        let payload = SignedPayload::new_net_flows(nonce, now_unix_secs(), agent_id, None);
        let sig: [u8; 64] = common::wire::admin_signed_payload::sign(&payload, &signing).unwrap();
        let req = NetFlowsRequest {
            payload,
            signatures: vec![KeyedSignature { signature: sig }],
        };
        let mut fps = Vec::new();
        let resp = dispatch_net_flows(req, &auth, &mut fps);
        assert!(matches!(resp.result, AdminResult::RoleDenied));
    }

    /// N7 dispatch test #3 — `net resolve` returns Success +
    /// `qname: None` for V1.0 (DNS-response observer is V1.1).
    #[test]
    fn dispatch_net_resolve_returns_none_qname_in_v1_0() {
        use common::wire::admin_protocol::KeyedSignature;
        use common::wire::admin_signed_payload::SignedPayload;
        use ed25519_dalek::SigningKey;
        use rand::rngs::OsRng;
        let signing = SigningKey::generate(&mut OsRng);
        let agent_id = [0xCC; 16];
        let (auth, _dir) = build_auth_with_roles(&signing, "net-read", agent_id);
        let nonce = auth.issue_challenge().unwrap();
        let payload =
            SignedPayload::new_net_resolve(nonce, now_unix_secs(), agent_id, "1.2.3.4".to_string());
        let sig: [u8; 64] = common::wire::admin_signed_payload::sign(&payload, &signing).unwrap();
        let req = NetResolveRequest {
            payload,
            signatures: vec![KeyedSignature { signature: sig }],
        };
        let mut fps = Vec::new();
        let resp = dispatch_net_resolve(req, &auth, &mut fps);
        assert!(matches!(resp.result, AdminResult::Success));
        assert!(resp.qname.is_none(), "V1.0 always returns qname=None");
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
}
