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

use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, Result};
use std::os::unix::fs::PermissionsExt;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use tracing::{info, warn};

use common::wire::admin_protocol::{
    decode_frame, encode_frame, AdminMessage, AdminResult, Challenge, ForcePostureRequest,
    RotateKeysAddRequest, RotateKeysRevokeRequest, ShutdownRequest, StatusResponse,
    UnlockResult, MAX_FRAME_BODY,
};
use common::wire::admin_signed_payload::{OperationCode, OperationExtra, Role};
use ed25519_dalek::VerifyingKey;
use sha2::{Digest, Sha256};

use crate::anti_tamper::admin_auth::{AdminAuth, AdminAuthError};
use crate::anti_tamper::network_isolate::NetworkIsolator;
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
    serve_with_marker_path(
        socket_path,
        auth,
        posture,
        isolator,
        PathBuf::from(DEFAULT_MARKER_PATH),
        None,
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
pub async fn serve_with_marker_path(
    socket_path: PathBuf,
    auth: Arc<AdminAuth>,
    posture: Arc<PostureMachine>,
    isolator: Arc<NetworkIsolator>,
    marker_path: PathBuf,
    shutdown_signal: Option<ShutdownSignal>,
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
        tokio::spawn(async move {
            if let Err(e) = handle_connection(
                stream,
                &auth,
                &posture,
                &isolator,
                &marker_path,
                shutdown_signal.as_ref(),
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
async fn handle_connection(
    mut stream: UnixStream,
    auth: &AdminAuth,
    posture: &PostureMachine,
    isolator: &NetworkIsolator,
    marker_path: &Path,
    shutdown_signal: Option<&ShutdownSignal>,
) -> Result<()> {
    loop {
        let msg = match read_frame(&mut stream).await? {
            Some(m) => m,
            None => return Ok(()),
        };
        let reply = dispatch(msg, auth, posture, isolator, marker_path, shutdown_signal);
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

/// Synchronous request→reply mapping. All AdminAuth + PostureMachine
/// methods are sync; we don't `await` between read and write inside
/// `handle_connection`, so the dispatch itself can stay sync.
fn dispatch(
    msg: AdminMessage,
    auth: &AdminAuth,
    posture: &PostureMachine,
    isolator: &NetworkIsolator,
    marker_path: &Path,
    shutdown_signal: Option<&ShutdownSignal>,
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

        AdminMessage::ShutdownRequest(req) => {
            AdminMessage::ShutdownResult(dispatch_shutdown(
                req,
                auth,
                marker_path,
                shutdown_signal,
            ))
        }

        AdminMessage::ForcePostureRequest(req) => {
            AdminMessage::ForcePostureResult(dispatch_force_posture(req, auth, posture))
        }

        AdminMessage::RotateKeysAddRequest(req) => {
            AdminMessage::RotateKeysAddResult(dispatch_rotate_keys_add(req, auth))
        }

        AdminMessage::RotateKeysRevokeRequest(req) => {
            AdminMessage::RotateKeysRevokeResult(dispatch_rotate_keys_revoke(req, auth))
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
        | AdminMessage::RotateKeysRevokeResult(_) => {
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
fn dispatch_shutdown(
    req: ShutdownRequest,
    auth: &AdminAuth,
    marker_path: &Path,
    shutdown_signal: Option<&ShutdownSignal>,
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

    let _token = match verify_outcome {
        Ok(token) => token,
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

    let token = match verify_outcome {
        Ok(token) => token,
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
fn dispatch_rotate_keys_add(req: RotateKeysAddRequest, auth: &AdminAuth) -> AdminResult {
    let server_now = now_unix_secs();
    let sigs: Vec<[u8; 64]> = req.signatures.iter().map(|s| s.signature).collect();

    let _token = match auth.verify_signed_payload_quorum(
        &req.payload,
        &sigs,
        2, // 2-of-N per §3.3
        &[Role::RotateKeys],
        OperationCode::RotateKeysAdd,
        server_now,
    ) {
        Ok(t) => t,
        Err(e) => return map_admin_auth_error(e, "rotate-keys-add"),
    };

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

    info!(
        target: "admin.rotate_keys",
        new_key_fp = %hex::encode(crate::anti_tamper::admin_auth::fingerprint_bytes(&new_pubkey)),
        role_count = roles.len(),
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
fn dispatch_rotate_keys_revoke(req: RotateKeysRevokeRequest, auth: &AdminAuth) -> AdminResult {
    let server_now = now_unix_secs();
    let sigs: Vec<[u8; 64]> = req.signatures.iter().map(|s| s.signature).collect();

    let _token = match auth.verify_signed_payload_quorum(
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

    match crate::anti_tamper::admin_auth::atomic_rewrite_admin_pub_revoke(
        &config_path,
        target_fp,
    ) {
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

    use common::wire::admin_protocol::{
        AdminResult, KeyedSignature, ShutdownRequest,
    };
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
    async fn spawn_shutdown_server(
    ) -> (
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
        let auth = Arc::new(
            AdminAuth::load_with_agent_id(&pub_path, agent_id).expect("load"),
        );
        let isolator = Arc::new(NetworkIsolator::new(rules).unwrap());
        let posture = Arc::new(PostureMachine::new());

        let auth_c = Arc::clone(&auth);
        let posture_c = Arc::clone(&posture);
        let isolator_c = Arc::clone(&isolator);
        let socket_c = socket.clone();
        let marker_c = marker_path.clone();
        let task = tokio::spawn(async move {
            let _ = serve_with_marker_path(
                socket_c, auth_c, posture_c, isolator_c, marker_c, None,
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

        (dir, socket, marker_path, signing_a, signing_b, agent_id, task)
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
                &AdminMessage::ChallengeRequest(
                    common::wire::admin_protocol::ChallengeRequest {},
                ),
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
        let auth = Arc::new(
            AdminAuth::load_with_agent_id(&pub_path, agent_id).expect("load"),
        );
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
                &AdminMessage::ChallengeRequest(
                    common::wire::admin_protocol::ChallengeRequest {},
                ),
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
}
