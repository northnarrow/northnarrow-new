//! The admin socket's tests (R11d, lab PR 263: `admin_socket.rs`'s
//! `mod tests`, whole), over every part of the module.

use super::audit::*;
use super::handlers::canary::*;
use super::handlers::detections::*;
use super::handlers::fim::*;
use super::handlers::installer::*;
use super::handlers::keys::*;
use super::handlers::net::*;
use super::handlers::posture::*;
use super::handlers::read::*;
use super::handlers::response::*;
use super::handlers::shutdown::*;
use super::handlers::status::*;
use super::handlers::unlock::*;
use super::handlers::*;
use super::transport::*;
use super::verify::*;
use super::*;

use std::os::unix::io::AsRawFd;
use std::path::Path;
use std::sync::Arc;

use anyhow::Result;
use parking_lot::Mutex;

use nn_proto::admin_protocol::{
    decode_frame, encode_frame, AdminMessage, CanaryBurnRequest, CanaryDeployRequest,
    CanaryDeployResponse, CanaryListRequest, CanaryListResponse, CanaryRefreshRequest, Challenge,
    DetectionSetStatusRequest, DetectionsRequest, FimReportRequest, FimReportResponse,
    ForcePostureRequest, NetFingerprintRequest, NetFingerprintResponse, NetFlowsRequest,
    NetFlowsResponse, NetListenersRequest, NetResolveRequest, NetResolveResponse,
    ResponseReleaseRequest, ResponseReleaseResponse, ResponseRestoreRequest, ResponseStatusRequest,
    RotateKeysAddRequest, SignedUnlockRequest, StatusResponse, TelemetryStatusRequest,
    TelemetryStatusResponse, TrustedInstallerGrantRequest, UnlockResult,
};
use nn_proto::admin_signed_payload::{OperationCode, OperationExtra, Role};

use crate::admin_cli::{run_status, run_unlock, run_verify_keys};
use crate::anti_tamper::admin_auth::{AdminAuth, ConnAuth};
use crate::anti_tamper::network_isolate::NetworkIsolator;
use crate::anti_tamper::trusted_installer::TrustedInstallerOverride;
use crate::audit::AuditLog;
use crate::canary::registry::{CanaryToken, CanaryTokenDraft, RegistryError};
use crate::os_rng::OsRng;
use crate::posture::PostureMachine;
use crate::shutdown_marker;
use ed25519_dalek::SigningKey;
use nn_model::posture_types::PostureKind;
use sha2::{Digest, Sha256};
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::time::Duration;
use tempfile::TempDir;
use tokio::net::UnixStream;
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
    /// Lab PR 217: the install the signed requests are bound to, and
    /// the file `nn-admin` reads it from.
    agent_id: [u8; 16],
    agent_id_path: PathBuf,
}

/// The install id of the [`spawn_server`] harness.
const HARNESS_AGENT_ID: [u8; 16] = [0x7a; 16];

pub(super) fn rules_path() -> PathBuf {
    PathBuf::from(env!("NN_REPO_ROOT"))
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
    let auth = Arc::new(AdminAuth::load_with_agent_id(&pub_path, HARNESS_AGENT_ID).unwrap());
    let agent_id_path = dir.path().join("agent_id");
    std::fs::write(
        &agent_id_path,
        format!("{}\n", hex::encode(HARNESS_AGENT_ID)),
    )
    .unwrap();

    // NetworkIsolator with mock binaries — no root needed.
    let isolator =
        Arc::new(crate::anti_tamper::network_isolate::NetworkIsolator::new(rules.clone()).unwrap());

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
        agent_id: HARNESS_AGENT_ID,
        agent_id_path,
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

/// External audit WDG-007 (NN-AUD-358): root could remove the admin
/// socket (`/run/northnarrow` is outside the deny hooks) and nn-admin
/// was dead until the agent restarted. The serve loop binds it again
/// within one check, and `status` answers on the new socket.
#[tokio::test]
async fn a_removed_admin_socket_is_bound_again_and_answers() {
    let signing = SigningKey::generate(&mut OsRng);
    let h = spawn_server(&signing).await;
    let first = std::fs::symlink_metadata(&h.socket).unwrap();
    std::fs::remove_file(&h.socket).unwrap();
    let deadline =
        std::time::Instant::now() + socket_watch::SOCKET_CHECK_EVERY + Duration::from_secs(10);
    while !h.socket.exists() {
        assert!(
            std::time::Instant::now() < deadline,
            "the admin socket was not bound again"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    use std::os::unix::fs::MetadataExt;
    let again = std::fs::symlink_metadata(&h.socket).unwrap();
    assert_ne!(again.ino(), first.ino());
    assert_eq!(again.mode() & 0o777, 0o600);
    let socket = h.socket.clone();
    let out = tokio::task::spawn_blocking(move || run_status(&socket).unwrap())
        .await
        .unwrap();
    assert_eq!(out.posture, PostureKind::Observing);
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
    if !h.isolator.engage().engaged() {
        eprintln!("iptables-restore unavailable / not root; skipping end-to-end test");
        return;
    }
    // Hand-build a ConfirmedIntrusion-class event (exec from /tmp,
    // non-root UID) — the posture trigger detector classifies any
    // such exec as ConfirmedIntrusion and slams the machine into
    // Combat. posture/triggers/testutil is `pub(super)`-scoped so
    // not reachable from this module; hand-rolled is fine for one
    // event.
    use nn_model::Event;
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
        argv_truncated: false,
        filename_truncated: false,
        stdio: Default::default(),
    };
    h.posture.observe(&intrusion, &[]);
    assert_eq!(h.posture.current_kind(), PostureKind::Combat);

    let priv_path = write_priv_key(&h._dir, &signing);
    let socket = h.socket.clone();
    let agent_id_path = h.agent_id_path.clone();
    let outcome = tokio::task::spawn_blocking(move || {
        run_unlock(&socket, &priv_path, &agent_id_path).unwrap()
    })
    .await
    .unwrap();
    assert!(matches!(
        outcome,
        crate::admin_cli::UnlockOutcome::Success { .. }
    ));
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
    let agent_id_path = h.agent_id_path.clone();
    let outcome = tokio::task::spawn_blocking(move || {
        run_unlock(&socket, &priv_path, &agent_id_path).unwrap()
    })
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

use nn_proto::admin_protocol::{AdminResult, KeyedSignature, ShutdownRequest};
use nn_proto::admin_signed_payload::{sign, SignedPayload};

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
            &AdminMessage::ChallengeRequest(nn_proto::admin_protocol::ChallengeRequest {}),
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
        let payload = SignedPayload::new_shutdown(nonce, now, agent_id_c, /* grace_secs */ 30);
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
        use nn_proto::shutdown_marker::{verify, Expectation, Rejection};
        let keys: Vec<nn_proto::admin_quorum::AdminKey> = [&signing_a, &signing_b]
            .iter()
            .map(|sk| nn_proto::admin_quorum::AdminKey {
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
            &AdminMessage::ChallengeRequest(nn_proto::admin_protocol::ChallengeRequest {}),
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
pub(super) fn build_test_audit_log(dir: &TempDir) -> (PathBuf, Arc<Mutex<AuditLog>>) {
    let key_path = dir.path().join("agent.sig.key");
    let log_path = dir.path().join("audit.log");
    let key = crate::audit::AgentSigningKey::load_or_bootstrap(&key_path).unwrap();
    let log = AuditLog::open(&log_path, key, [0u8; 16]).unwrap();
    (log_path, Arc::new(Mutex::new(log)))
}

pub(super) fn read_audit_entries(log_path: &Path) -> Vec<crate::audit::AuditEntry> {
    std::fs::read_to_string(log_path)
        .ok()
        .unwrap_or_default()
        .lines()
        .filter(|l| !l.is_empty())
        .map(|l| serde_json::from_str(l).expect("parse audit line"))
        .collect()
}

pub(super) fn fake_client() -> AuditClient {
    AuditClient {
        pid: 12345,
        uid: 1000,
        comm: "nn-admin".to_string(),
        exe: Some("/usr/local/bin/nn-admin".to_string()),
    }
}

/// A request's context with no subsystem wired: the posture, the
/// isolator, the marker's path and the read verbs' files only.
pub(super) fn bare_context<'a>(
    posture: &'a PostureMachine,
    isolator: &'a NetworkIsolator,
    marker_path: &'a Path,
    read_paths: &'a AdminReadPaths,
) -> Wired<'a> {
    Wired {
        posture,
        isolator,
        marker_path,
        shutdown_signal: None,
        fim_state: None,
        canary_state: None,
        installer_override: None,
        detection_state: None,
        response_state: None,
        read_paths,
    }
}

/// B5 test #1: Unlock success emits one audit row with
/// op="unlock" + result="success" + the fake client triple.
#[test]
fn audit_emits_on_unlock_success() {
    let dir = TempDir::new().unwrap();
    let (log_path, audit) = build_test_audit_log(&dir);
    let req = AdminMessage::Unlock(nn_proto::admin_protocol::UnlockRequest { signature: [0; 64] });
    let reply = AdminMessage::UnlockResult(UnlockResult::Success);
    emit_audit_for(
        &req,
        &reply,
        &fake_client(),
        Some(&audit),
        &[],
        &DispatchNotes::default(),
    );
    let entries = read_audit_entries(&log_path);
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].op, "unlock");
    assert_eq!(entries[0].result, "success");
    assert_eq!(entries[0].client_pid, 12345);
    assert_eq!(entries[0].client_uid, 1000);
    assert_eq!(entries[0].client_comm, "nn-admin");
    // External audit ASK-013: the kernel's record of the program too.
    assert_eq!(
        entries[0].client_exe.as_deref(),
        Some("/usr/local/bin/nn-admin")
    );
    // First entry chains off the genesis hash (B1 invariant).
    assert_eq!(entries[0].prev_hash, crate::audit::GENESIS_PREV_HASH);
}

/// B5 test #2: Shutdown success records grace_secs in
/// `extra` and the cosigner-count comes from the signatures
/// vec (len - 1, since the first is the primary signer).
#[test]
fn audit_emits_on_shutdown_success_with_grace_extra() {
    use nn_proto::admin_protocol::KeyedSignature;
    use nn_proto::admin_signed_payload::SignedPayload;
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
    emit_audit_for(
        &req,
        &reply,
        &fake_client(),
        Some(&audit),
        &[],
        &DispatchNotes::default(),
    );
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
    use nn_model::posture_types::PostureKind;
    use nn_proto::admin_protocol::KeyedSignature;
    use nn_proto::admin_signed_payload::SignedPayload;
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
    emit_audit_for(
        &req,
        &reply,
        &fake_client(),
        Some(&audit),
        &[],
        &DispatchNotes::default(),
    );
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
    use nn_proto::admin_protocol::{ChallengeRequest, KeyedSignature, StatusRequest};
    use nn_proto::admin_signed_payload::{Role, SignedPayload};
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
        &DispatchNotes::default(),
    );
    // Non-auditable: Status request.
    let status_req = AdminMessage::Status(StatusRequest {});
    let status_reply = AdminMessage::StatusResponse(StatusResponse {
        posture: nn_model::posture_types::PostureKind::Observing,
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
        detect_only: None,
        detect_only_source: None,
        combat_evidence_unrecorded: None,
        combat_evidence_pending: None,
        combat_evidence_dropped: None,
        net_dot_rows_total: None,
        net_dot_rows_resolver: None,
        net_quic_rows_total: None,
        deny_fail_open_total: None,
        deny_fail_open: None,
        network_isolation_v4: None,
        network_isolation_v6: None,
        trust_level: None,
        trust_reasons: None,
        degradations: None,
        capability_manifest: None,
        exploit_guard: None,
        cow_guard: None,
        execq_state: None,
        execq_held_total: None,
        execq_resumed_total: None,
        execq_killed_total: None,
        execq_quarantined_total: None,
        execq_defaulted_total: None,
        execq_known_identity_total: None,
        execq_known_hash_total: None,
        execq_not_held_total: None,
        execq_scanner_deaths_total: None,
        net_connect_verdicts_total: None,
        net_flow_snapshots_total: None,
        net_flow_snapshots_deferred_total: None,
        net_connect_denied_total: None,
        ransomware_decisive_total: None,
        ransomware_signals_total: None,
        ransomware_trusted_total: None,
        ransomware_samplings_total: None,
        defense_tamper_total: None,
        defense_tamper_sanctioned_total: None,
        defense_tools_watched: None,
        execpol_state: None,
        execpol_denied_total: None,
        execpol_would_deny_total: None,
        execpol_quarantine_total: None,
        execpol_quarantine_inactive_total: None,
        execpol_env_denied_total: None,
        execpol_env_recorded_total: None,
        execpol_map_denied_total: None,
        execpol_map_recorded_total: None,
        execq_script_refused_total: None,
    });
    emit_audit_for(
        &status_req,
        &status_reply,
        &fake_client(),
        Some(&audit),
        &[],
        &DispatchNotes::default(),
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
        &DispatchNotes::default(),
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
        &DispatchNotes::default(),
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
    let req = AdminMessage::Unlock(nn_proto::admin_protocol::UnlockRequest { signature: [0; 64] });
    let reply = AdminMessage::UnlockResult(UnlockResult::Success);
    emit_audit_for(
        &req,
        &reply,
        &fake_client(),
        Some(&audit),
        &[],
        &DispatchNotes::default(),
    );
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
    use nn_proto::admin_protocol::{FimBaselineRequest, KeyedSignature};
    use nn_proto::admin_signed_payload::SignedPayload;
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
        &DispatchNotes::default(),
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
    use nn_proto::admin_protocol::{FimReportRequest, FimReportResponse, KeyedSignature};
    use nn_proto::admin_signed_payload::SignedPayload;
    let dir = TempDir::new().unwrap();
    let (log_path, audit) = build_test_audit_log(&dir);
    let payload =
        SignedPayload::new_fim_report([0x33; 32], 1_700_000_000, [0x44; 16], Some(1_700_000_000));
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
        &DispatchNotes::default(),
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
    use nn_proto::admin_protocol::{FimStatusRequest, FimStatusResponse, KeyedSignature};
    use nn_proto::admin_signed_payload::SignedPayload;
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
        &DispatchNotes::default(),
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
    use nn_proto::admin_protocol::{FimBaselineRequest, KeyedSignature};
    use nn_proto::admin_signed_payload::SignedPayload;
    let dir = TempDir::new().unwrap();
    let (log_path, audit) = build_test_audit_log(&dir);
    let payload = SignedPayload::new_fim_baseline([0x55; 32], 1_700_000_000, [0x66; 16]);
    let req = AdminMessage::FimBaselineRequest(FimBaselineRequest {
        payload,
        signatures: vec![KeyedSignature { signature: [0; 64] }],
    });
    let reply = AdminMessage::FimBaselineResult(AdminResult::RoleDenied);
    emit_audit_for(
        &req,
        &reply,
        &fake_client(),
        Some(&audit),
        &[],
        &DispatchNotes::default(),
    );
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
    use nn_proto::admin_protocol::KeyedSignature;
    use nn_proto::admin_signed_payload::{CanaryDeploymentWire, CanaryTypeWire, SignedPayload};
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
        &DispatchNotes::default(),
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
    use nn_proto::admin_protocol::KeyedSignature;
    use nn_proto::admin_signed_payload::SignedPayload;
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
        &DispatchNotes::default(),
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
    use nn_proto::admin_protocol::KeyedSignature;
    use nn_proto::admin_signed_payload::SignedPayload;
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
        &DispatchNotes::default(),
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
    use nn_proto::admin_protocol::KeyedSignature;
    use nn_proto::admin_signed_payload::SignedPayload;
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
        &DispatchNotes::default(),
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
    use nn_proto::admin_protocol::KeyedSignature;
    use nn_proto::admin_signed_payload::{CanaryDeploymentWire, CanaryTypeWire, SignedPayload};
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
    emit_audit_for(
        &req,
        &reply,
        &fake_client(),
        Some(&audit),
        &[],
        &DispatchNotes::default(),
    );
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
    let key = crate::audit::AgentSigningKey::load_or_bootstrap(&dir.path().join("agent.sig.key"))
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
    deployment: nn_proto::admin_signed_payload::CanaryDeploymentWire,
) -> CanaryToken {
    use nn_proto::admin_signed_payload::{CanaryDeploymentWire, CanaryTypeWire};
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
    use nn_proto::admin_signed_payload::CanaryDeploymentWire;
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
    use nn_proto::admin_signed_payload::CanaryDeploymentWire;
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
    use nn_proto::admin_protocol::KeyedSignature;
    use nn_proto::admin_signed_payload::{CanaryDeploymentWire, CanaryTypeWire, SignedPayload};
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
    let sig: [u8; 64] = nn_proto::admin_signed_payload::sign(&payload, &signing).unwrap();
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
    use nn_proto::admin_protocol::KeyedSignature;
    use nn_proto::admin_signed_payload::{CanaryDeploymentWire, CanaryTypeWire, SignedPayload};
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
        let sig = nn_proto::admin_signed_payload::sign(&payload, &signing).unwrap();
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
    use nn_proto::admin_protocol::KeyedSignature;
    use nn_proto::admin_signed_payload::SignedPayload;
    let signing = SigningKey::generate(&mut OsRng);
    let agent_id = [0xb0; 16];
    let (auth, _dir) = build_auth_with_roles(&signing, "canary-read", agent_id);
    let auth = ConnAuth::new(&auth);
    let nonce = auth.issue_challenge().unwrap();
    let payload = SignedPayload::new_canary_list(nonce, now_unix_secs(), agent_id);
    let sig: [u8; 64] = nn_proto::admin_signed_payload::sign(&payload, &signing).unwrap();
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
    use nn_proto::admin_protocol::KeyedSignature;
    use nn_proto::admin_signed_payload::SignedPayload;
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
    let sig: [u8; 64] = nn_proto::admin_signed_payload::sign(&payload, &signing).unwrap();
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
    use nn_proto::admin_protocol::KeyedSignature;
    use nn_proto::admin_signed_payload::SignedPayload;
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
    let sig: [u8; 64] = nn_proto::admin_signed_payload::sign(&payload, &signing).unwrap();
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
    payload: &nn_proto::admin_signed_payload::SignedPayload,
    signing: &SigningKey,
) -> Vec<nn_proto::admin_protocol::KeyedSignature> {
    vec![nn_proto::admin_protocol::KeyedSignature {
        signature: nn_proto::admin_signed_payload::sign(payload, signing).unwrap(),
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
        detect_only_source: None,
        combat_evidence: Arc::new(crate::combat::EvidenceCounts::default),
    }
}

fn status_req(
    signing: &SigningKey,
    auth: &ConnAuth<'_>,
    agent_id: [u8; 16],
) -> ResponseStatusRequest {
    use nn_proto::admin_signed_payload::SignedPayload;
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
    use nn_proto::admin_signed_payload::SignedPayload;
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
    use nn_proto::admin_signed_payload::SignedPayload;
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

/// External audit ASK-009 (lab PR 213): a signed `status --key`
/// request.
fn telemetry_req(
    signing: &SigningKey,
    auth: &ConnAuth<'_>,
    agent_id: [u8; 16],
) -> TelemetryStatusRequest {
    use nn_proto::admin_signed_payload::SignedPayload;
    let payload = SignedPayload::new_telemetry_status(
        auth.issue_challenge().unwrap(),
        now_unix_secs(),
        agent_id,
    );
    let signatures = keyed(&payload, signing);
    TelemetryStatusRequest {
        payload,
        signatures,
    }
}

/// External audit CMB-018 / CMB-027 (lab PR 193): `status` tells an
/// enforcing agent from a detect-only one, names what set detect-only,
/// and says what the signed audit log lacks of the COMBAT ladder —
/// through the signed telemetry verb since external audit ASK-009
/// (lab PR 213).
#[test]
fn status_reports_detect_only_and_combat_evidence() {
    let signing = SigningKey::generate(&mut OsRng);
    let dir = TempDir::new().unwrap();
    let (auth, _d) = build_auth_with_roles(&signing, "audit-read", [0x1c; 16]);
    let auth = ConnAuth::new(&auth);
    let isolator = NetworkIsolator::new(rules_path()).unwrap();
    let posture = PostureMachine::new();
    let marker = dir.path().join("marker");
    let status = |state: Option<&ResponseAdminState>| match dispatch(
        AdminMessage::TelemetryStatusRequest(telemetry_req(&signing, &auth, [0x1c; 16])),
        &auth,
        Wired {
            response_state: state,
            ..bare_context(&posture, &isolator, &marker, &AdminReadPaths::default())
        },
        &fake_client(),
        &mut Vec::new(),
        &mut DispatchNotes::default(),
    ) {
        AdminMessage::TelemetryStatusResponse(TelemetryStatusResponse {
            result: AdminResult::Success,
            status: Some(r),
        }) => r,
        other => panic!("{other:?}"),
    };

    let mut detect = response_state(&dir);
    detect.config.dry_run = true;
    detect.detect_only_source = Some("NN_DETECT_ONLY=1".to_string());
    detect.combat_evidence = Arc::new(|| crate::combat::EvidenceCounts {
        unrecorded: 3,
        pending: 1,
        dropped: 0,
    });
    let r = status(Some(&detect));
    assert_eq!(r.detect_only, Some(true));
    assert_eq!(r.detect_only_source.as_deref(), Some("NN_DETECT_ONLY=1"));
    assert_eq!(
        (
            r.combat_evidence_unrecorded,
            r.combat_evidence_pending,
            r.combat_evidence_dropped
        ),
        (Some(3), Some(1), Some(0))
    );

    let r = status(Some(&response_state(&dir)));
    assert_eq!(r.detect_only, Some(false));
    assert_eq!(r.detect_only_source, None);
    assert_eq!(r.combat_evidence_unrecorded, Some(0));
    // External audit NET-017 (lab PR 207): the encrypted-flow counters
    // are always reported (the resolver's DoT rows are among the DoT
    // rows).
    let (dot, resolver, quic) = (
        r.net_dot_rows_total.expect("dot"),
        r.net_dot_rows_resolver.expect("resolver"),
        r.net_quic_rows_total,
    );
    assert!(resolver <= dot && quic.is_some());
    // Lab PR 215: no eBPF object in a unit test, so the fail-open
    // counters are not read — "not counted", never a 0.
    assert_eq!(r.deny_fail_open_total, None);
    assert_eq!(r.deny_fail_open, None);
    // Lab PR 223: the exec quarantine is always reported (off here).
    assert_eq!(r.execq_state.as_deref(), Some("off"));
    assert!(r.execq_held_total.is_some());
    // Lab PR 226: the exec policy too.
    assert_eq!(r.execpol_state.as_deref(), Some("off"));
    assert!(r.execpol_denied_total.is_some());

    // No response state (no executor): not known, not "enforcing".
    let r = status(None);
    assert_eq!(r.detect_only, None);
    assert_eq!(r.combat_evidence_unrecorded, None);
}

/// External audit ASK-009 (lab PR 213): the unsigned `status` answers
/// the posture, the isolation, the last admin action and the COMBAT
/// stage and lock — what the watchdog and COMBAT recovery read — and
/// withholds the telemetry (`ringbuf_drops_total == None`), whatever
/// the agent holds.
#[test]
fn the_unsigned_status_withholds_the_telemetry() {
    use nn_proto::admin_protocol::StatusRequest;
    let signing = SigningKey::generate(&mut OsRng);
    let dir = TempDir::new().unwrap();
    let (auth, _d) = build_auth_with_roles(&signing, "audit-read", [0x1d; 16]);
    let auth = ConnAuth::new(&auth);
    let isolator = NetworkIsolator::new(rules_path()).unwrap();
    let posture = PostureMachine::new();
    let marker = dir.path().join("marker");
    let mut detect = response_state(&dir);
    detect.config.dry_run = true;
    detect.detect_only_source = Some("--detect-only".to_string());
    let mut fps = Vec::new();
    let r = match dispatch(
        AdminMessage::Status(StatusRequest {}),
        &auth,
        Wired {
            response_state: Some(&detect),
            ..bare_context(&posture, &isolator, &marker, &AdminReadPaths::default())
        },
        &fake_client(),
        &mut fps,
        &mut DispatchNotes::default(),
    ) {
        AdminMessage::StatusResponse(r) => r,
        other => panic!("{other:?}"),
    };
    assert_eq!(r.posture, nn_model::posture_types::PostureKind::Observing);
    assert!(!r.network_isolation_engaged);
    assert_eq!(r.combat_stage.as_deref(), Some("NEUTRALIZE"));
    assert_eq!(r.combat_locked, Some(false));
    assert_eq!(r.ringbuf_drops_total, None);
    assert_eq!(r.ringbuf_rejected_total, None);
    assert_eq!(r.netflow_rows_skipped_total, None);
    assert_eq!(r.net_inactive_rules, None);
    assert_eq!(r.detect_only, None, "detect-only is telemetry too");
    assert_eq!(r.combat_evidence_unrecorded, None);
    assert_eq!(r.net_dot_rows_total, None);
    assert_eq!(r.deny_fail_open_total, None);
    assert!(r.telemetry_withheld());
    assert!(fps.is_empty(), "no signature on the unsigned status");
}

/// External audit ASK-009 (lab PR 213): the signed telemetry verb
/// accepts `audit-read` (every key's default, the install key's) or
/// `telemetry-read` (and `triage`, `all`, which imply it); a key with
/// neither is RoleDenied and gets no status. Each request is one audit
/// row naming the signer, the counters not copied.
#[test]
fn the_signed_telemetry_status_needs_a_read_role() {
    let dir = TempDir::new().unwrap();
    let (log_path, audit) = build_test_audit_log(&dir);
    let isolator = NetworkIsolator::new(rules_path()).unwrap();
    let posture = PostureMachine::new();
    let state = response_state(&dir);
    let agent_id = [0x1e; 16];
    let cases = [
        ("audit-read", AdminResult::Success),
        ("telemetry-read", AdminResult::Success),
        ("triage", AdminResult::Success),
        ("all", AdminResult::Success),
        (
            "unlock,force-posture,config-manage",
            AdminResult::RoleDenied,
        ),
    ];
    for (roles, expected) in cases {
        let signing = SigningKey::generate(&mut OsRng);
        let (auth, _d) = build_auth_with_roles(&signing, roles, agent_id);
        let auth = ConnAuth::new(&auth);
        let req = telemetry_req(&signing, &auth, agent_id);
        let msg = AdminMessage::TelemetryStatusRequest(req.clone());
        let mut fps = Vec::new();
        let r = dispatch_telemetry_status(req, &auth, &posture, &isolator, Some(&state), &mut fps);
        assert_eq!(r.result, expected, "{roles}");
        match expected {
            AdminResult::Success => {
                let st = r.status.as_ref().expect("the whole status");
                assert!(st.ringbuf_drops_total.is_some(), "{roles}");
                // Lab PR 218: the degradations are the signed verb's.
                assert!(st.degradations.is_some(), "{roles}");
                assert_eq!(st.detect_only, Some(false));
                assert_eq!(st.combat_stage.as_deref(), Some("NEUTRALIZE"));
            }
            _ => assert!(r.status.is_none(), "{roles}: nothing on a refusal"),
        }
        assert_eq!(fps.len(), 1, "{roles}: the signer is named");
        emit_audit_for(
            &msg,
            &AdminMessage::TelemetryStatusResponse(r),
            &fake_client(),
            Some(&audit),
            &fps,
            &DispatchNotes::default(),
        );
    }
    let rows = read_audit_entries(&log_path);
    assert_eq!(rows.len(), cases.len());
    for (row, (roles, expected)) in rows.iter().zip(cases) {
        assert_eq!(row.op, "telemetry_status");
        assert_eq!(
            row.extra,
            serde_json::json!({}),
            "the counters are not copied"
        );
        assert!(!row.key_fp.is_empty(), "{roles}");
        let want = if expected == AdminResult::Success {
            "success"
        } else {
            "failure: role_denied"
        };
        assert_eq!(row.result, want, "{roles}");
    }
}

/// The signed verb refuses a payload signed for another operation (a
/// `response status` signature replayed as a telemetry read).
#[test]
fn the_signed_telemetry_status_refuses_another_operation() {
    let signing = SigningKey::generate(&mut OsRng);
    let agent_id = [0x1f; 16];
    let (auth, _d) = build_auth_with_roles(&signing, "audit-read", agent_id);
    let auth = ConnAuth::new(&auth);
    let other = status_req(&signing, &auth, agent_id);
    let req = TelemetryStatusRequest {
        payload: other.payload,
        signatures: other.signatures,
    };
    let isolator = NetworkIsolator::new(rules_path()).unwrap();
    let posture = PostureMachine::new();
    let mut fps = Vec::new();
    let r = dispatch_telemetry_status(req, &auth, &posture, &isolator, None, &mut fps);
    assert_eq!(r.result, AdminResult::UnknownOperation);
    assert!(r.status.is_none());
}

/// External audit ASK-009 (lab PR 213): a burst of 100 unsigned
/// `status` from one peer is one signed `status_polled` row; the
/// registered watchdog's pings are none.
#[test]
fn a_burst_of_unsigned_status_is_one_signed_row() {
    let dir = TempDir::new().unwrap();
    let (log_path, audit) = build_test_audit_log(&dir);
    let me = std::process::id();
    let exempt = crate::posture::ExemptPids::with_agent(1);
    let start = std::fs::read_to_string(format!("/proc/{me}/stat"))
        .ok()
        .and_then(|s| s.rsplit_once(')').map(|(_, r)| r.to_string()))
        .and_then(|r| r.split_whitespace().nth(19).map(str::to_string))
        .and_then(|v| v.parse::<u64>().ok())
        .expect("own start time");
    exempt.set_watchdog(me, start);
    let polls = StatusPolls::new(exempt);
    for _ in 0..100 {
        note_status_poll(&polls, &fake_client(), Some(&audit));
    }
    let watchdog = AuditClient {
        pid: me,
        uid: 0,
        comm: "northnarrow-wat".to_string(),
        exe: None,
    };
    for _ in 0..20 {
        note_status_poll(&polls, &watchdog, Some(&audit));
    }
    let rows = read_audit_entries(&log_path);
    assert_eq!(
        rows.len(),
        1,
        "one row for the burst, none for the watchdog"
    );
    assert_eq!(rows[0].op, "status_polled");
    assert_eq!(rows[0].client_pid, 12345);
    assert_eq!(rows[0].client_comm, "nn-admin");
    assert_eq!(rows[0].result, "success");
    assert!(rows[0].key_fp.is_empty());
    // Without an audit log nothing is counted or written.
    note_status_poll(&polls, &fake_client(), None);
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
    use nn_proto::admin_signed_payload::{OperationExtra, ResponseRestoreExtra, SignedPayload};
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
    use nn_proto::admin_signed_payload::SignedPayload;
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
    emit_audit_for(
        &req,
        &reply,
        &fake_client(),
        Some(&audit),
        &["ab".into()],
        &DispatchNotes::default(),
    );
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
    use crate::os_rng::OsRng;
    use ed25519_dalek::SigningKey;
    use nn_proto::admin_protocol::KeyedSignature;
    use nn_proto::admin_signed_payload::SignedPayload;
    let signing = SigningKey::generate(&mut OsRng);
    let agent_id = [0xAA; 16];
    let (auth, _dir) = build_auth_with_roles(&signing, "net-read", agent_id);
    let auth = ConnAuth::new(&auth);
    let nonce = auth.issue_challenge().unwrap();
    let payload = SignedPayload::new_net_flows(nonce, now_unix_secs(), agent_id, None);
    let sig: [u8; 64] = nn_proto::admin_signed_payload::sign(&payload, &signing).unwrap();
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
    use crate::os_rng::OsRng;
    use ed25519_dalek::SigningKey;
    use nn_proto::admin_protocol::KeyedSignature;
    use nn_proto::admin_signed_payload::SignedPayload;
    let signing = SigningKey::generate(&mut OsRng);
    let agent_id = [0xBB; 16];
    // Key carries `unlock` only — not `net-read`.
    let (auth, _dir) = build_auth_with_roles(&signing, "unlock", agent_id);
    let auth = ConnAuth::new(&auth);
    let nonce = auth.issue_challenge().unwrap();
    let payload = SignedPayload::new_net_flows(nonce, now_unix_secs(), agent_id, None);
    let sig: [u8; 64] = nn_proto::admin_signed_payload::sign(&payload, &signing).unwrap();
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
    payload: &nn_proto::admin_signed_payload::SignedPayload,
    signing: &SigningKey,
) -> Vec<nn_proto::admin_protocol::KeyedSignature> {
    vec![nn_proto::admin_protocol::KeyedSignature {
        signature: nn_proto::admin_signed_payload::sign(payload, signing).unwrap(),
    }]
}

fn net_flows(dir: &Path, since: Option<u64>) -> NetFlowsResponse {
    use nn_proto::admin_signed_payload::SignedPayload;
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
    use nn_proto::admin_signed_payload::SignedPayload;
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
    use nn_proto::admin_signed_payload::SignedPayload;
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
    use nn_proto::admin_signed_payload::SignedPayload;
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
    use nn_proto::admin_signed_payload::SignedPayload;
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
    use nn_proto::admin_protocol::KeyedSignature;
    use nn_proto::admin_signed_payload::SignedPayload;
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
    let sig: [u8; 64] = nn_proto::admin_signed_payload::sign(&payload, signing).unwrap();
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
    use nn_proto::admin_protocol::KeyedSignature;
    use nn_proto::admin_signed_payload::{sign, SignedPayload};
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
        exe: None,
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
    let resp = dispatch_detection_set_status(req, &auth, Some(&state), &test_client(), &mut fps);
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
    let resp2 = dispatch_detection_set_status(req2, &auth, Some(&state), &test_client(), &mut fps);
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
    let resp = dispatch_detection_set_status(req, &auth, Some(&state), &test_client(), &mut fps);
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
    let resp = dispatch_detection_set_status(req, &auth, Some(&state), &test_client(), &mut fps);
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
    let resp = dispatch_detection_set_status(req, &auth, Some(&state), &test_client(), &mut fps);
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
    let resp = dispatch_detection_set_status(req, &auth, Some(&state), &test_client(), &mut fps);
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
    use nn_proto::admin_protocol::KeyedSignature;
    use nn_proto::admin_signed_payload::{sign, SignedPayload};
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
    use crate::os_rng::OsRng;
    use ed25519_dalek::SigningKey;
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
    use crate::os_rng::OsRng;
    use ed25519_dalek::SigningKey;
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
    use crate::os_rng::OsRng;
    use ed25519_dalek::SigningKey;
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
    use crate::os_rng::OsRng;
    use ed25519_dalek::SigningKey;
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
    use crate::os_rng::OsRng;
    use ed25519_dalek::SigningKey;
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
    use crate::os_rng::OsRng;
    use ed25519_dalek::SigningKey;
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
    use crate::os_rng::OsRng;
    use ed25519_dalek::SigningKey;
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
    use nn_proto::admin_protocol::{KeyedSignature, NetFlowsRequest, NetFlowsResponse};
    use nn_proto::admin_signed_payload::SignedPayload;
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
        &DispatchNotes::default(),
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
    let cred = peer_cred(server.as_raw_fd()).unwrap();
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
            cred,
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
            &StatusPolls::default(),
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
        nn_proto::admin_protocol::StatusRequest {},
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
        let status = run_status(&socket).expect("status answers while idle peers fill the table");
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
        &AdminMessage::ChallengeRequest(nn_proto::admin_protocol::ChallengeRequest {}),
    );
    match sync_read_frame(stream) {
        AdminMessage::Challenge(c) => c.nonce,
        other => panic!("expected Challenge, got {other:?}"),
    }
}

/// Lab PR 217: the signed unlock (`OperationCode::Unlock`) over
/// `nonce`, for `agent_id`; the reply's result.
fn sync_unlock(
    stream: &mut std::os::unix::net::UnixStream,
    signing: &SigningKey,
    nonce: &[u8; 32],
    agent_id: [u8; 16],
) -> AdminResult {
    let payload = SignedPayload::new_unlock(*nonce, now_unix_secs(), agent_id);
    sync_write_frame(
        stream,
        &AdminMessage::SignedUnlockRequest(SignedUnlockRequest {
            signatures: vec![KeyedSignature {
                signature: sign(&payload, signing).unwrap(),
            }],
            payload,
        }),
    );
    match sync_read_frame(stream) {
        AdminMessage::SignedUnlockResponse(r) => r.result,
        other => panic!("expected SignedUnlockResponse, got {other:?}"),
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
    let id = h.agent_id;
    tokio::task::spawn_blocking(move || {
        let mut a = connect_retrying(&socket);
        let mut b = connect_retrying(&socket);
        let nonce_a = sync_challenge(&mut a);
        let nonce_b = sync_challenge(&mut b);
        assert_eq!(
            sync_unlock(&mut a, &signing, &nonce_a, id),
            AdminResult::Success
        );
        assert_eq!(
            sync_unlock(&mut b, &signing, &nonce_b, id),
            AdminResult::Success
        );
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
    let id = h.agent_id;
    tokio::task::spawn_blocking(move || {
        use crate::anti_tamper::admin_auth::MAX_AUTH_FAILURES_PER_CONNECTION;
        let mut hostile = connect_retrying(&socket);
        for attempt in 1..=MAX_AUTH_FAILURES_PER_CONNECTION {
            let nonce = sync_challenge(&mut hostile);
            let r = sync_unlock(&mut hostile, &stranger, &nonce, id);
            if attempt < MAX_AUTH_FAILURES_PER_CONNECTION {
                assert_eq!(r, AdminResult::InvalidSignature);
            } else {
                assert!(matches!(r, AdminResult::RateLimited { .. }), "{r:?}");
            }
        }
        // A further request on that connection gets no reply.
        use std::io::Write;
        let frame = encode_frame(&AdminMessage::ChallengeRequest(
            nn_proto::admin_protocol::ChallengeRequest {},
        ))
        .unwrap();
        let _ = hostile.write_all(&frame);
        assert!(peer_closed(&hostile), "the connection is closed");

        let mut operator = connect_retrying(&socket);
        let nonce = sync_challenge(&mut operator);
        assert_eq!(
            sync_unlock(&mut operator, &signing, &nonce, id),
            AdminResult::Success
        );
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
        &mut DispatchNotes::default(),
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
        &mut DispatchNotes::default(),
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
            &mut DispatchNotes::default(),
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
        &mut DispatchNotes::default(),
    );
    assert!(matches!(r, AdminResult::Success), "{r:?}");
    assert_eq!(posture.current_kind(), PostureKind::Engaged);
}

/// External audit ASK-015: leaving COMBAT by force-posture, the
/// audit row (and the journal line, from the same value) names COMBAT as `from` — they named
/// the state entered (`from=Observing to=Observing`), and the row had
/// only the target.
#[test]
fn force_posture_records_the_state_it_left() {
    let signing = SigningKey::generate(&mut OsRng);
    let agent_id = [0x15; 16];
    let (auth, _d) = build_auth_with_roles(&signing, "force-posture,unlock", agent_id);
    let auth = ConnAuth::new(&auth);
    let posture = PostureMachine::new();
    let dir = TempDir::new().unwrap();
    let (log_path, audit) = build_test_audit_log(&dir);
    let force = |target: PostureKind| {
        let req = force_posture_req(&auth, &signing, agent_id, target);
        let mut fps = Vec::new();
        let mut notes = DispatchNotes::default();
        let r = dispatch_force_posture(req.clone(), &auth, &posture, &mut fps, &mut notes);
        assert!(matches!(r, AdminResult::Success), "{target:?}: {r:?}");
        emit_audit_for(
            &AdminMessage::ForcePostureRequest(req),
            &AdminMessage::ForcePostureResult(r),
            &fake_client(),
            Some(&audit),
            &fps,
            &notes,
        );
    };
    force(PostureKind::Combat);
    assert_eq!(posture.current_kind(), PostureKind::Combat);

    // The journal line and the audit row both print `outcome.from`; the
    // signed row is the evidence, so it is what this test reads (a
    // captured tracing line was flaky under parallel tests: a callsite's
    // interest is process-wide).
    force(PostureKind::Observing);
    assert_eq!(posture.current_kind(), PostureKind::Observing);

    let entries = read_audit_entries(&log_path);
    assert_eq!(entries.len(), 2);
    assert_eq!(
        entries[0].extra,
        serde_json::json!({ "target": "Combat", "from": "Observing" })
    );
    assert_eq!(
        entries[1].extra,
        serde_json::json!({ "target": "Observing", "from": "Combat" })
    );
    assert_eq!(entries[1].result, "success");
}

/// External audit ASK-015: a refused force changed nothing; its row
/// has the target and no `from`.
#[test]
fn a_refused_force_posture_has_no_from() {
    let signing = SigningKey::generate(&mut OsRng);
    let agent_id = [0x15; 16];
    let (auth, _d) = build_auth_with_roles(&signing, "force-posture", agent_id);
    let auth = ConnAuth::new(&auth);
    let posture = PostureMachine::new();
    let mut notes = DispatchNotes::default();
    let r = dispatch_force_posture(
        force_posture_req(&auth, &signing, agent_id, PostureKind::Combat),
        &auth,
        &posture,
        &mut Vec::new(),
        &mut notes,
    );
    assert!(matches!(r, AdminResult::Success), "{r:?}");
    assert_eq!(notes.force_from, Some(PostureKind::Observing));

    let mut notes = DispatchNotes::default();
    let r = dispatch_force_posture(
        force_posture_req(&auth, &signing, agent_id, PostureKind::Observing),
        &auth,
        &posture,
        &mut Vec::new(),
        &mut notes,
    );
    assert!(matches!(r, AdminResult::RoleDenied), "{r:?}");
    assert_eq!(notes.force_from, None);
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
    let signer = nn_proto::admin_quorum::AdminKey {
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

// ── Lab PR 179: admin socket peers and request cost ─────────────

/// Socket paths whose server takes another uid for its own (the
/// external audit ASK-012 tests: the test runs as one user, so the
/// only way to be a "foreign" peer is a server that does not admit
/// that user).
static OWN_EUID_OVERRIDE: Mutex<Vec<(PathBuf, u32)>> = Mutex::new(Vec::new());

pub(super) fn own_euid_override(path: &Path) -> Option<u32> {
    OWN_EUID_OVERRIDE
        .lock()
        .iter()
        .find(|(p, _)| p == path)
        .map(|(_, euid)| *euid)
}

fn test_euid() -> u32 {
    // SAFETY: geteuid has no preconditions and cannot fail.
    unsafe { libc::geteuid() }
}

/// A server on `dir/admin.sock` with an audit log; `own_euid` set
/// replaces the agent's euid for the peer check.
async fn spawn_audited_server(
    dir: &TempDir,
    own_euid: Option<u32>,
) -> (PathBuf, PathBuf, Arc<Mutex<AuditLog>>, JoinHandle<()>) {
    let socket = dir.path().join("admin.sock");
    if let Some(euid) = own_euid {
        OWN_EUID_OVERRIDE.lock().push((socket.clone(), euid));
    }
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
    let (log_path, audit) = build_test_audit_log(dir);
    let audit_c = Arc::clone(&audit);
    let socket_c = socket.clone();
    let marker = dir.path().join("marker");
    let task = tokio::spawn(async move {
        let _ =
            serve_with_audit_log(socket_c, auth, posture, isolator, marker, None, audit_c).await;
    });
    for _ in 0..200 {
        if socket.exists() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    (socket, log_path, audit, task)
}

fn foreign_peer_rows(log_path: &Path) -> Vec<String> {
    read_audit_entries(log_path)
        .into_iter()
        .filter(|e| e.op == crate::self_integrity::AUDIT_OP && e.extra["kind"] == FOREIGN_PEER_KIND)
        .map(|e| e.extra["detail"].as_str().unwrap_or_default().to_string())
        .collect()
}

/// External audit ASK-012 (NN-AUD-238): uid 0 and the agent's own
/// euid may use the admin plane, no one else.
#[test]
fn peer_allowed_is_root_or_the_agents_own_uid() {
    let cred = |uid| PeerCred {
        pid: 1,
        uid,
        gid: uid,
    };
    assert!(peer_allowed(&cred(0), 0));
    assert!(peer_allowed(&cred(0), 1000));
    assert!(peer_allowed(&cred(1000), 1000));
    assert!(!peer_allowed(&cred(1000), 0));
    assert!(!peer_allowed(&cred(65534), 0));
    assert!(!peer_allowed(&cred(65534), 1000));
}

/// External audit ASK-012: `SO_PEERCRED` that cannot be read was
/// `AuditClient::unknown()` — uid 0, root. It is a refusal now.
#[test]
fn unreadable_peer_credentials_are_refused_not_taken_for_root() {
    let f = tempfile::tempfile().unwrap();
    assert_eq!(
        screen_peer(f.as_raw_fd(), 0),
        Err(PeerRefusal::Unreadable(libc::ENOTSOCK))
    );
    // A socket pair: the peer is this process.
    let (a, _b) = std::os::unix::net::UnixStream::pair().unwrap();
    let me = test_euid();
    let cred = screen_peer(a.as_raw_fd(), me).expect("our own uid is admitted");
    assert_eq!(cred.uid, me);
    assert_eq!(cred.pid, std::process::id());
    if me != 0 {
        assert_eq!(
            screen_peer(a.as_raw_fd(), 0),
            Err(PeerRefusal::ForeignUid(cred)),
            "another user, for an agent running as root"
        );
    }
}

/// External audit ASK-012 (NN-AUD-238): a peer whose uid may not use
/// the admin plane is closed without a reply (it used to be served
/// whatever its uid), the refusal is one signed `integrity_drift`
/// (`admin_socket_foreign_peer`) and the next refusals within the
/// re-report window add no row. Unprivileged: the server is told the
/// agent's uid is another one (as root, uid 0 is always admitted —
/// the privileged e2e covers that case with a real other uid).
#[tokio::test]
async fn a_peer_of_another_uid_is_refused_and_recorded() {
    let me = test_euid();
    if me == 0 {
        eprintln!("running as root: uid 0 is always admitted; see the privileged e2e");
        return;
    }
    let dir = TempDir::new().unwrap();
    let (socket, log_path, _audit, _task) =
        spawn_audited_server(&dir, Some(me.wrapping_add(1))).await;
    for _ in 0..3 {
        let s = socket.clone();
        let refused = tokio::task::spawn_blocking(move || run_status(&s))
            .await
            .unwrap();
        assert!(refused.is_err(), "no reply to a foreign uid: {refused:?}");
    }
    let rows = foreign_peer_rows(&log_path);
    assert_eq!(rows.len(), 1, "{rows:?}");
    assert!(
        rows[0].contains(&format!("a connection from uid {me} ")),
        "{}",
        rows[0]
    );
    assert!(
        rows[0].contains("was refused without a reply"),
        "{}",
        rows[0]
    );
    assert!(
        rows[0].contains(&std::process::id().to_string()),
        "{}",
        rows[0]
    );
}

/// The control: the same server answers a peer of its own uid, and
/// the audit row of a signed request names the peer's executable
/// (external audit ASK-013), here this test binary.
#[tokio::test]
async fn the_agents_own_uid_is_served_and_its_exe_recorded() {
    let dir = TempDir::new().unwrap();
    let (socket, log_path, _audit, _task) = spawn_audited_server(&dir, None).await;
    let s = socket.clone();
    let out = tokio::task::spawn_blocking(move || run_status(&s))
        .await
        .unwrap()
        .expect("status answered");
    assert_eq!(out.posture, PostureKind::Observing);
    // An unlock with no challenge: refused, and audited.
    let s = socket.clone();
    tokio::task::spawn_blocking(move || {
        use std::io::Write;
        let mut c = std::os::unix::net::UnixStream::connect(&s).unwrap();
        let req =
            AdminMessage::Unlock(nn_proto::admin_protocol::UnlockRequest { signature: [0; 64] });
        c.write_all(&encode_frame(&req).unwrap()).unwrap();
        let _ = sync_read_frame(&mut c);
    })
    .await
    .unwrap();
    let rows = read_audit_entries(&log_path);
    let unlock = rows.iter().find(|e| e.op == "unlock").expect("unlock row");
    let me = std::fs::read_link("/proc/self/exe").unwrap();
    assert_eq!(
        unlock.client_exe.as_deref(),
        Some(me.to_string_lossy().as_ref())
    );
    assert_eq!(unlock.client_pid, std::process::id());
    assert!(foreign_peer_rows(&log_path).is_empty());
}

/// External audit ASK-013 (NN-AUD-239): a peer that is gone by the
/// time it is looked at is `<exited>` — never the name of whatever
/// holds its pid by then.
#[test]
fn an_exited_peer_is_recorded_as_exited() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("p.sock");
    let listener = std::os::unix::net::UnixListener::bind(&path).unwrap();
    // The address, built before the fork: the child makes only
    // async-signal-safe calls (socket, connect, _exit).
    // SAFETY: sockaddr_un is plain data; all-zero is a valid value.
    let mut addr: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    addr.sun_family = libc::AF_UNIX as libc::sa_family_t;
    let bytes = path.as_os_str().as_encoded_bytes();
    assert!(bytes.len() < addr.sun_path.len());
    for (d, s) in addr.sun_path.iter_mut().zip(bytes) {
        *d = *s as libc::c_char;
    }
    let len = std::mem::size_of::<libc::sockaddr_un>() as libc::socklen_t;
    // SAFETY: the child calls only async-signal-safe functions on
    // memory prepared before the fork, then _exit.
    let pid = unsafe { libc::fork() };
    assert!(pid >= 0);
    if pid == 0 {
        unsafe {
            let fd = libc::socket(libc::AF_UNIX, libc::SOCK_STREAM, 0);
            let rc = libc::connect(fd, (&addr as *const libc::sockaddr_un).cast(), len);
            libc::_exit(if rc == 0 { 0 } else { 1 });
        }
    }
    let mut status = 0;
    // SAFETY: our own child.
    assert_eq!(unsafe { libc::waitpid(pid, &mut status, 0) }, pid);
    assert!(libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0);
    // The child connected and was reaped; its connection waits in the
    // backlog.
    let (conn, _) = listener.accept().unwrap();
    let cred = peer_cred(conn.as_raw_fd()).unwrap();
    let who = peer_identity(conn.as_raw_fd(), &cred);
    assert_eq!(who.comm, "<exited>", "{who:?}");
    assert_eq!(who.exe, None);
    // A live peer (this process, through a pair) is read.
    let (a, _b) = std::os::unix::net::UnixStream::pair().unwrap();
    let cred = peer_cred(a.as_raw_fd()).unwrap();
    let who = peer_identity(a.as_raw_fd(), &cred);
    assert_ne!(who.comm, "<exited>");
    assert_eq!(
        who.exe.as_deref(),
        Some(
            std::fs::read_link("/proc/self/exe")
                .unwrap()
                .to_string_lossy()
                .as_ref()
        )
    );
}

/// External audit ASK-005 (NN-AUD-236): a request whose audit row
/// waits (here on the audit mutex, as on a slow fsync) no longer holds
/// the runtime's worker: with one worker, a ticker task keeps running
/// meanwhile. The request was handled on the worker itself, which then
/// ran nothing else until the row was written.
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn a_slow_request_does_not_stop_the_runtimes_other_tasks() {
    use std::sync::atomic::{AtomicU64, Ordering};
    let dir = TempDir::new().unwrap();
    let (socket, log_path, audit, _task) = spawn_audited_server(&dir, None).await;
    let ticks = Arc::new(AtomicU64::new(0));
    let t = Arc::clone(&ticks);
    let ticker = tokio::spawn(async move {
        let mut every = tokio::time::interval(Duration::from_millis(10));
        loop {
            every.tick().await;
            t.fetch_add(1, Ordering::Relaxed);
        }
    });
    // The audit mutex held for 700 ms by another thread.
    let (locked_tx, locked_rx) = std::sync::mpsc::channel();
    let holder = std::thread::spawn(move || {
        let guard = audit.lock();
        locked_tx.send(()).unwrap();
        std::thread::sleep(Duration::from_millis(700));
        drop(guard);
    });
    locked_rx.recv().unwrap();
    // An auditable request (an unlock without a challenge).
    let s = socket.clone();
    let client = std::thread::spawn(move || {
        use std::io::Write;
        let mut c = std::os::unix::net::UnixStream::connect(&s).unwrap();
        let req =
            AdminMessage::Unlock(nn_proto::admin_protocol::UnlockRequest { signature: [0; 64] });
        c.write_all(&encode_frame(&req).unwrap()).unwrap();
        sync_read_frame(&mut c)
    });
    // The test body runs on the `block_on` thread, not on the worker.
    std::thread::sleep(Duration::from_millis(150));
    let before = ticks.load(Ordering::Relaxed);
    std::thread::sleep(Duration::from_millis(300));
    let during = ticks.load(Ordering::Relaxed) - before;
    holder.join().unwrap();
    let reply = client.join().unwrap();
    ticker.abort();
    assert!(
        matches!(reply, AdminMessage::UnlockResult(_)),
        "the request is still answered: {reply:?}"
    );
    assert!(
        read_audit_entries(&log_path)
            .iter()
            .any(|e| e.op == "unlock"),
        "and audited before its reply"
    );
    assert!(
        during >= 5,
        "the ticker advanced {during} times in 300 ms while a request waited on the audit log"
    );
}

/// External audit ASK-014 (NN-AUD-240): a dangling link at the socket
/// path does not keep the admin plane from coming up (lab PR 170's
/// bind), a missing parent is created 0700, and the agent's unlink at
/// shutdown removes a dangling link too (`exists()` followed it and
/// left it there).
#[tokio::test]
async fn a_dangling_link_at_the_socket_path_is_replaced_and_unlinked() {
    use std::os::unix::fs::{FileTypeExt, MetadataExt};
    let dir = TempDir::new().unwrap();
    let run = dir.path().join("run/northnarrow");
    std::fs::create_dir_all(&run).unwrap();
    let socket = run.join("admin.sock");
    std::os::unix::fs::symlink(dir.path().join("nowhere"), &socket).unwrap();
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
    let s = socket.clone();
    let task = tokio::spawn(async move {
        let _ = serve(s, auth, posture, isolator).await;
    });
    for _ in 0..200 {
        if std::fs::symlink_metadata(&socket).is_ok_and(|m| m.file_type().is_socket()) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let s = socket.clone();
    let out = tokio::task::spawn_blocking(move || run_status(&s))
        .await
        .unwrap()
        .expect("bound over the dangling link, and answering");
    assert_eq!(out.posture, PostureKind::Observing);
    task.abort();

    // A missing parent: created closed to others.
    let fresh = dir.path().join("fresh/northnarrow/admin.sock");
    let (_l, _id) = socket_watch::bind(&fresh).unwrap();
    let parent = std::fs::metadata(fresh.parent().unwrap()).unwrap();
    assert_eq!(parent.mode() & 0o777, 0o700);

    // Shutdown: the link is removed, not followed.
    let victim = dir.path().join("victim");
    std::fs::write(&victim, "keep").unwrap();
    std::fs::remove_file(&socket).unwrap();
    std::os::unix::fs::symlink(dir.path().join("nowhere"), &socket).unwrap();
    unlink_socket(&socket);
    assert!(
        std::fs::symlink_metadata(&socket).is_err(),
        "the dangling link is gone"
    );
    std::os::unix::fs::symlink(&victim, &socket).unwrap();
    unlink_socket(&socket);
    assert!(std::fs::symlink_metadata(&socket).is_err());
    assert_eq!(std::fs::read_to_string(&victim).unwrap(), "keep");
}

// ── External audit, Wave 3: signed-request verification (lab PR 192) ──

/// A posture in a locked COMBAT whose release hook fails while `fail`
/// is set (the iptables teardown that does not take) — lab PR 217.
fn combat_with_release_hook(fail: Arc<std::sync::atomic::AtomicBool>) -> PostureMachine {
    let hook: crate::posture::CombatReleaseHook = Arc::new(move |_token, _scope| {
        if fail.load(std::sync::atomic::Ordering::SeqCst) {
            Err(
                "IPv4: FAILED (read back: the NORTHNARROW_COMBAT chain is still listed); \
                 IPv6: cleared (read back)"
                    .to_string(),
            )
        } else {
            Ok("IPv4: cleared (read back); IPv6: cleared (read back)".to_string())
        }
    });
    let posture = PostureMachine::new_with_hooks(Arc::new(|_| {}), hook);
    posture
        .admin_force_state_with_token(
            crate::anti_tamper::_test_mint_unlock_token(),
            PostureKind::Combat,
            true,
        )
        .unwrap();
    assert!(posture.is_combat_locked());
    posture
}

/// Lab PR 217 (NN-AUD-243 residue, capability C17): a verified signed
/// unlock whose teardown does not leave the tables clear is answered as
/// a failure (`ActionFailed`), the posture stays COMBAT, and the audit
/// row records the failure with the signer's fingerprint; once the
/// teardown works, the same verb succeeds and the row says so. It was
/// `Success` and "success" whatever the teardown did, with no `key_fp`.
#[test]
fn a_signed_unlock_whose_teardown_fails_is_a_failure() {
    let signing = SigningKey::generate(&mut OsRng);
    let agent_id = [0x3d; 16];
    let (auth, _d) = build_auth_with_roles(&signing, "unlock", agent_id);
    let auth = ConnAuth::new(&auth);
    let isolator = NetworkIsolator::new(rules_path()).unwrap();
    let fail = Arc::new(std::sync::atomic::AtomicBool::new(true));
    let posture = combat_with_release_hook(Arc::clone(&fail));
    let dir = TempDir::new().unwrap();
    let (log_path, audit) = build_test_audit_log(&dir);
    let fp = hex::encode(crate::anti_tamper::admin_auth::fingerprint_bytes(
        &signing.verifying_key(),
    ));
    let unlock = |auth: &ConnAuth<'_>| {
        let payload =
            SignedPayload::new_unlock(auth.issue_challenge().unwrap(), now_unix_secs(), agent_id);
        let req = SignedUnlockRequest {
            signatures: keyed(&payload, &signing),
            payload,
        };
        let mut fps = Vec::new();
        let reply = dispatch_signed_unlock(req.clone(), auth, &posture, &isolator, &mut fps);
        emit_audit_for(
            &AdminMessage::SignedUnlockRequest(req),
            &AdminMessage::SignedUnlockResponse(reply.clone()),
            &fake_client(),
            Some(&audit),
            &fps,
            &DispatchNotes::default(),
        );
        reply
    };

    let reply = unlock(&auth);
    assert_eq!(reply.result, AdminResult::ActionFailed, "{reply:?}");
    assert!(!reply.released);
    assert!(reply.message.contains("still listed"), "{}", reply.message);
    assert_eq!(posture.current_kind(), PostureKind::Combat, "COMBAT stays");
    let rows = read_audit_entries(&log_path);
    assert_eq!(rows[0].op, "unlock");
    assert!(
        rows[0].result.starts_with("failure: release_failed"),
        "{}",
        rows[0].result
    );
    assert_eq!(rows[0].key_fp, fp, "the row names the signer");
    assert_eq!(rows[0].extra["protocol"], "signed");
    assert_eq!(rows[0].extra["released"], false);

    fail.store(false, std::sync::atomic::Ordering::SeqCst);
    let reply = unlock(&auth);
    assert_eq!(reply.result, AdminResult::Success, "{reply:?}");
    assert!(reply.released);
    assert_eq!(posture.current_kind(), PostureKind::Alerted);
    let rows = read_audit_entries(&log_path);
    assert_eq!(rows[1].result, "success");
    assert_eq!(rows[1].key_fp, fp);
    // a key without the `unlock` role is refused before any release
    let other = SigningKey::generate(&mut OsRng);
    let (auth2, _d2) = build_auth_with_roles(&other, "audit-read", agent_id);
    let auth2 = ConnAuth::new(&auth2);
    let payload =
        SignedPayload::new_unlock(auth2.issue_challenge().unwrap(), now_unix_secs(), agent_id);
    let reply = dispatch_signed_unlock(
        SignedUnlockRequest {
            signatures: keyed(&payload, &other),
            payload,
        },
        &auth2,
        &posture,
        &isolator,
        &mut Vec::new(),
    );
    assert_eq!(reply.result, AdminResult::RoleDenied);
    assert!(!reply.released);
}

/// Lab PR 217 (capability C17): the legacy unlock — a valid signature
/// over the bare nonce, by a key holding `unlock` — no longer releases
/// COMBAT: refused with its own reply, audited as a failure, the
/// challenge spent. It used to release, and its row had no `key_fp`.
#[test]
fn the_legacy_unlock_is_refused_and_audited() {
    use ed25519_dalek::Signer;
    let signing = SigningKey::generate(&mut OsRng);
    let agent_id = [0x3e; 16];
    let (auth, _d) = build_auth_with_roles(&signing, "unlock", agent_id);
    let auth = ConnAuth::new(&auth);
    let isolator = NetworkIsolator::new(rules_path()).unwrap();
    let fail = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let posture = combat_with_release_hook(fail);
    let dir = TempDir::new().unwrap();
    let (log_path, audit) = build_test_audit_log(&dir);
    let nonce = auth.issue_challenge().unwrap();
    let req = AdminMessage::Unlock(nn_proto::admin_protocol::UnlockRequest {
        signature: signing.sign(&nonce).to_bytes(),
    });
    let mut fps = Vec::new();
    let reply = dispatch(
        req.clone(),
        &auth,
        bare_context(
            &posture,
            &isolator,
            &dir.path().join("marker"),
            &AdminReadPaths::default(),
        ),
        &fake_client(),
        &mut fps,
        &mut DispatchNotes::default(),
    );
    assert_eq!(
        reply,
        AdminMessage::UnlockResult(UnlockResult::LegacyProtocolRefused)
    );
    assert_eq!(posture.current_kind(), PostureKind::Combat, "not released");
    emit_audit_for(
        &req,
        &reply,
        &fake_client(),
        Some(&audit),
        &fps,
        &DispatchNotes::default(),
    );
    let rows = read_audit_entries(&log_path);
    assert_eq!(rows[0].op, "unlock");
    assert_eq!(rows[0].result, "failure: legacy_protocol_refused");
    assert_eq!(rows[0].extra["protocol"], "legacy");
    // the challenge is spent: a signed request on it finds none
    let payload = SignedPayload::new_unlock(nonce, now_unix_secs(), agent_id);
    let reply = dispatch_signed_unlock(
        SignedUnlockRequest {
            signatures: keyed(&payload, &signing),
            payload,
        },
        &auth,
        &posture,
        &isolator,
        &mut Vec::new(),
    );
    assert_eq!(reply.result, AdminResult::NoPendingChallenge);
}

/// Lab PR 217 (NN-AUD-243 residue): a force-posture out of COMBAT whose
/// release fails is not carried out — `ActionFailed`, COMBAT stays, the
/// row says why.
#[test]
fn a_force_posture_out_of_combat_whose_release_fails_is_a_failure() {
    let signing = SigningKey::generate(&mut OsRng);
    let agent_id = [0x3f; 16];
    let (auth, _d) = build_auth_with_roles(&signing, "force-posture,unlock", agent_id);
    let auth = ConnAuth::new(&auth);
    let fail = Arc::new(std::sync::atomic::AtomicBool::new(true));
    let posture = combat_with_release_hook(fail);
    let dir = TempDir::new().unwrap();
    let (log_path, audit) = build_test_audit_log(&dir);
    let req = force_posture_req(&auth, &signing, agent_id, PostureKind::Observing);
    let mut fps = Vec::new();
    let mut notes = DispatchNotes::default();
    let r = dispatch_force_posture(req.clone(), &auth, &posture, &mut fps, &mut notes);
    assert_eq!(r, AdminResult::ActionFailed);
    assert_eq!(posture.current_kind(), PostureKind::Combat);
    emit_audit_for(
        &AdminMessage::ForcePostureRequest(req),
        &AdminMessage::ForcePostureResult(r),
        &fake_client(),
        Some(&audit),
        &fps,
        &notes,
    );
    let rows = read_audit_entries(&log_path);
    assert_eq!(rows[0].op, "force_posture");
    assert!(
        rows[0].result.starts_with("failure: release_failed"),
        "{}",
        rows[0].result
    );
    assert!(rows[0].extra.get("from").is_none(), "nothing changed");
}

/// External audit AUT-001: a shutdown request whose payload carries an
/// `unlock` extra under the `shutdown` op, signed by two keys holding
/// `shutdown`, is refused (`UnknownOperation`), writes no marker and
/// names no signer. It used to verify (only the op tag was checked),
/// and `dispatch_shutdown` fell back to a 30 s grace nobody signed.
#[test]
fn dispatch_shutdown_refuses_an_extra_that_is_not_a_shutdown() {
    use nn_proto::admin_protocol::{KeyedSignature, ShutdownRequest};
    use nn_proto::admin_signed_payload::{sign, SignedPayload, UnlockExtra};
    let agent_id = [0xc4; 16];
    let sks = [
        SigningKey::from_bytes(&[0x31; 32]),
        SigningKey::from_bytes(&[0x32; 32]),
    ];
    let dir = TempDir::new().unwrap();
    let pub_path = dir.path().join("admin.pub");
    std::fs::write(
        &pub_path,
        sks.iter()
            .map(|sk| {
                format!(
                    "{} shutdown,unlock\n",
                    hex::encode(sk.verifying_key().to_bytes())
                )
            })
            .collect::<String>(),
    )
    .unwrap();
    let auth = AdminAuth::load_with_agent_id(&pub_path, agent_id).unwrap();
    let auth = ConnAuth::new(&auth);
    let marker_path = dir.path().join("agent.shutdown_authorised");

    let nonce = auth.issue_challenge().unwrap();
    let payload = SignedPayload {
        op: OperationCode::Shutdown,
        nonce,
        ts: now_unix_secs(),
        agent_id,
        extra: OperationExtra::Unlock(UnlockExtra {}),
    };
    let signatures = sks
        .iter()
        .map(|sk| KeyedSignature {
            signature: sign(&payload, sk).unwrap(),
        })
        .collect();
    let mut fps = Vec::new();
    let result = dispatch_shutdown(
        ShutdownRequest {
            payload,
            signatures,
        },
        &auth,
        &marker_path,
        None,
        &mut fps,
    );
    assert_eq!(result, AdminResult::UnknownOperation);
    assert!(!marker_path.exists(), "no marker for a mismatched payload");
    assert!(fps.is_empty());
}
