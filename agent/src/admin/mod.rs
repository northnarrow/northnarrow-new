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
