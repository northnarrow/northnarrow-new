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
    decode_frame, encode_frame, AdminMessage, Challenge, StatusResponse, UnlockResult,
    MAX_FRAME_BODY,
};

use crate::anti_tamper::admin_auth::{AdminAuth, AdminAuthError};
use crate::anti_tamper::network_isolate::NetworkIsolator;
use crate::posture::{AdminReleaseError, PostureMachine};

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
        tokio::spawn(async move {
            if let Err(e) = handle_connection(stream, &auth, &posture, &isolator).await {
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
) -> Result<()> {
    loop {
        let msg = match read_frame(&mut stream).await? {
            Some(m) => m,
            None => return Ok(()),
        };
        let reply = dispatch(msg, auth, posture, isolator);
        write_frame(&mut stream, &reply).await?;
    }
}

/// Synchronous request→reply mapping. All AdminAuth + PostureMachine
/// methods are sync; we don't `await` between read and write inside
/// `handle_connection`, so the dispatch itself can stay sync.
fn dispatch(
    msg: AdminMessage,
    auth: &AdminAuth,
    posture: &PostureMachine,
    isolator: &NetworkIsolator,
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
            };
            AdminMessage::UnlockResult(result)
        }

        AdminMessage::Status(_) => AdminMessage::StatusResponse(StatusResponse {
            posture: posture.current_kind(),
            network_isolation_engaged: isolator.is_engaged(),
            last_admin_action_secs_ago: posture.last_admin_action_secs_ago(),
        }),

        // Server-only variants — clients sending these are speaking
        // out-of-spec. Reply with a benign sentinel; the connection
        // closes naturally on the next read EOF.
        AdminMessage::Challenge(_)
        | AdminMessage::UnlockResult(_)
        | AdminMessage::StatusResponse(_) => {
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
}
