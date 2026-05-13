//! Library half of the `nn-admin` CLI binary.
//!
//! The binary at `src/bin/nn_admin.rs` is a thin clap dispatcher.
//! All real logic lives here so it can be unit-tested without
//! shelling out to a compiled binary. Each `run_*` function takes
//! its inputs explicitly and returns a typed outcome; mapping to
//! process exit codes happens in the binary.
//!
//! Transport: a one-shot synchronous request/response over the Unix
//! socket at `/run/northnarrow/admin.sock`. We deliberately avoid
//! pulling tokio into the CLI — there's no concurrency to schedule
//! and `std::os::unix::net::UnixStream` keeps startup latency tiny.
//!
//! Air-gapped flow (split request → offline sign → submit) is on
//! the V1.1 roadmap; today only the all-in-one `unlock --key <PATH>`
//! path exists.

use std::fs::OpenOptions;
use std::io::{Read, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};

use common::wire::admin_protocol::{
    decode_frame, encode_frame, AdminMessage, ChallengeRequest, StatusRequest, UnlockRequest,
    UnlockResult,
};

// ── public outcome types ────────────────────────────────────────────

/// Result of `nn-admin unlock`. Mapped to exit codes in the binary
/// (Success=0, InvalidSignature=2, NoPendingChallenge=3,
/// RateLimited=4, Transport=5).
#[derive(Debug)]
pub enum UnlockOutcome {
    Success,
    InvalidSignature,
    NoPendingChallenge,
    RateLimited { retry_after_secs: u32 },
}

#[derive(Debug)]
pub struct StatusOutcome {
    pub posture: common::posture_types::PostureKind,
    pub network_isolation_engaged: bool,
    pub last_admin_action_secs_ago: Option<u64>,
}

#[derive(Debug)]
pub struct VerifyKeysOutcome {
    pub fingerprints: Vec<String>,
}

#[derive(Debug)]
pub struct InitOutcome {
    pub fingerprint: String,
    pub priv_path: PathBuf,
    pub pub_path: PathBuf,
}

// ── commands ────────────────────────────────────────────────────────

/// Generate a fresh Ed25519 keypair; write the private key to
/// `priv_out` (mode 0600, fail if it exists unless `force`); append
/// the public key to `pub_append` with a comment header.
pub fn run_init(priv_out: &Path, pub_append: &Path, force: bool) -> Result<InitOutcome> {
    let signing = SigningKey::generate(&mut OsRng);
    let verifying = signing.verifying_key();
    let fp = pubkey_fingerprint(&verifying);

    // Private key: 64 hex chars + newline. Mode 0600. create_new
    // unless --force overrides; if --force, truncate.
    let mut opts = OpenOptions::new();
    opts.write(true).mode(0o600);
    if force {
        opts.create(true).truncate(true);
    } else {
        opts.create_new(true);
    }
    let mut f = opts
        .open(priv_out)
        .with_context(|| format!("writing private key to {}", priv_out.display()))?;
    let priv_hex = hex::encode(signing.to_bytes());
    writeln!(f, "{priv_hex}").context("writing private key bytes")?;
    drop(f);

    // Public key: append-or-create with mode 0644. We do NOT chmod
    // an existing file — preserving the operator's stricter perms
    // if they tightened them.
    let mut p = OpenOptions::new()
        .append(true)
        .create(true)
        .mode(0o644)
        .open(pub_append)
        .with_context(|| format!("appending pub key to {}", pub_append.display()))?;
    let ts = current_utc_iso8601();
    writeln!(
        p,
        "# nn-admin generated {ts} (fingerprint {fp})\n{}",
        hex::encode(verifying.to_bytes())
    )
    .context("writing pub key bytes")?;

    Ok(InitOutcome {
        fingerprint: fp,
        priv_path: priv_out.to_path_buf(),
        pub_path: pub_append.to_path_buf(),
    })
}

/// Full unlock flow: connect, request challenge, sign, submit
/// signature, return outcome.
pub fn run_unlock(socket: &Path, key_path: &Path) -> Result<UnlockOutcome> {
    let signing = read_priv_key(key_path)?;
    let mut stream = connect_socket(socket)?;

    write_frame(
        &mut stream,
        &AdminMessage::ChallengeRequest(ChallengeRequest {}),
    )?;
    let nonce = match read_frame(&mut stream)? {
        AdminMessage::Challenge(c) => c.nonce,
        other => bail!("unexpected server reply to ChallengeRequest: {other:?}"),
    };

    let sig: [u8; 64] = signing.sign(&nonce).to_bytes();
    write_frame(
        &mut stream,
        &AdminMessage::Unlock(UnlockRequest { signature: sig }),
    )?;
    let result = match read_frame(&mut stream)? {
        AdminMessage::UnlockResult(r) => r,
        other => bail!("unexpected server reply to UnlockRequest: {other:?}"),
    };

    Ok(match result {
        UnlockResult::Success => UnlockOutcome::Success,
        UnlockResult::InvalidSignature => UnlockOutcome::InvalidSignature,
        UnlockResult::NoPendingChallenge => UnlockOutcome::NoPendingChallenge,
        UnlockResult::RateLimited { retry_after_secs } => {
            UnlockOutcome::RateLimited { retry_after_secs }
        }
    })
}

/// Status query — round-trip a `StatusRequest`/`StatusResponse`.
pub fn run_status(socket: &Path) -> Result<StatusOutcome> {
    let mut stream = connect_socket(socket)?;
    write_frame(&mut stream, &AdminMessage::Status(StatusRequest {}))?;
    let resp = match read_frame(&mut stream)? {
        AdminMessage::StatusResponse(s) => s,
        other => bail!("unexpected server reply to StatusRequest: {other:?}"),
    };
    Ok(StatusOutcome {
        posture: resp.posture,
        network_isolation_engaged: resp.network_isolation_engaged,
        last_admin_action_secs_ago: resp.last_admin_action_secs_ago,
    })
}

/// Local-only: parse `path` and report fingerprints. No socket
/// involved.
pub fn run_verify_keys(path: &Path) -> Result<VerifyKeysOutcome> {
    let content =
        std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    let mut fingerprints = Vec::new();
    for (idx, raw) in content.lines().enumerate() {
        let line_no = idx + 1;
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if line.len() != 64 {
            bail!(
                "{}:{}: pub key must be 64 hex chars (got {})",
                path.display(),
                line_no,
                line.len()
            );
        }
        let bytes = hex::decode(line)
            .map_err(|e| anyhow!("{}:{}: invalid hex ({e})", path.display(), line_no))?;
        let arr: [u8; 32] = bytes.try_into().expect("hex pre-validated");
        let vk = VerifyingKey::from_bytes(&arr)
            .map_err(|e| anyhow!("{}:{}: not a valid pubkey ({e})", path.display(), line_no))?;
        fingerprints.push(pubkey_fingerprint(&vk));
    }
    Ok(VerifyKeysOutcome { fingerprints })
}

/// Debug-only: send a `DebugForcePosture` request. Only available
/// when both this crate and `common` are built with the
/// `debug-trigger` Cargo feature.
#[cfg(feature = "debug-trigger")]
pub fn run_debug_force_posture(
    socket: &Path,
    state: common::wire::admin_protocol::DebugForcePosture,
) -> Result<()> {
    let mut stream = connect_socket(socket)?;
    write_frame(&mut stream, &AdminMessage::DebugForcePosture(state))?;
    match read_frame(&mut stream)? {
        AdminMessage::DebugForcePostureAck => Ok(()),
        other => bail!("unexpected reply to DebugForcePosture: {other:?}"),
    }
}

// ── helpers ─────────────────────────────────────────────────────────

/// 8-hex-char fingerprint: first 4 bytes of SHA-256 over the raw
/// pubkey. Identical convention to `ssh-keygen`'s short fingerprints
/// minus the formatting.
pub fn pubkey_fingerprint(vk: &VerifyingKey) -> String {
    let mut h = Sha256::new();
    h.update(vk.to_bytes());
    let digest = h.finalize();
    hex::encode(&digest[..4])
}

fn read_priv_key(path: &Path) -> Result<SigningKey> {
    let raw = std::fs::read_to_string(path)
        .with_context(|| format!("reading private key {}", path.display()))?;
    let line = raw
        .lines()
        .find(|l| !l.trim().is_empty())
        .ok_or_else(|| anyhow!("private key file {} is empty", path.display()))?;
    let line = line.trim();
    if line.len() != 64 {
        bail!(
            "private key must be 64 hex chars (got {}): {}",
            line.len(),
            path.display()
        );
    }
    let bytes = hex::decode(line).map_err(|e| anyhow!("private key hex decode failed: {e}"))?;
    let arr: [u8; 32] = bytes.try_into().expect("hex pre-validated");
    Ok(SigningKey::from_bytes(&arr))
}

fn connect_socket(path: &Path) -> Result<UnixStream> {
    let stream =
        UnixStream::connect(path).with_context(|| format!("connecting to {}", path.display()))?;
    // 5 s read/write timeout — defends against an agent that
    // accepted the connection but never replies. The whole round
    // trip is sub-millisecond on a healthy system.
    stream.set_read_timeout(Some(Duration::from_secs(5))).ok();
    stream.set_write_timeout(Some(Duration::from_secs(5))).ok();
    Ok(stream)
}

fn write_frame(stream: &mut UnixStream, msg: &AdminMessage) -> Result<()> {
    let bytes = encode_frame(msg).map_err(|e| anyhow!("encode_frame: {e}"))?;
    stream.write_all(&bytes).context("writing frame")?;
    Ok(())
}

fn read_frame(stream: &mut UnixStream) -> Result<AdminMessage> {
    // Buffered length-prefix read: pull the 4-byte header, then the
    // body in one read_exact. decode_frame ratifies size limits.
    let mut header = [0u8; 4];
    stream
        .read_exact(&mut header)
        .context("reading frame length header")?;
    let body_len = u32::from_be_bytes(header) as usize;
    if body_len > common::wire::admin_protocol::MAX_FRAME_BODY {
        bail!(
            "advertised frame body {body_len} > limit {}",
            common::wire::admin_protocol::MAX_FRAME_BODY
        );
    }
    let mut body = vec![0u8; body_len];
    stream.read_exact(&mut body).context("reading frame body")?;

    // Re-assemble + dispatch through decode_frame so the parsing
    // path matches the encoder's exactly.
    let mut full = Vec::with_capacity(4 + body_len);
    full.extend_from_slice(&header);
    full.extend_from_slice(&body);
    match decode_frame(&full).map_err(|e| anyhow!("decode_frame: {e}"))? {
        Some((msg, _)) => Ok(msg),
        None => bail!("decode_frame returned None on a complete buffer (impossible)"),
    }
}

fn current_utc_iso8601() -> String {
    chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string()
}

// ── tests ───────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use common::posture_types::PostureKind;
    use common::wire::admin_protocol::{Challenge, StatusResponse};
    use std::os::unix::net::UnixListener;
    use std::thread;
    use tempfile::TempDir;

    // ── init / verify-keys (no socket) ─────────────────────────────

    #[test]
    fn cli_init_generates_valid_keypair() {
        let dir = TempDir::new().unwrap();
        let priv_path = dir.path().join("admin.key");
        let pub_path = dir.path().join("admin.pub");
        let outcome = run_init(&priv_path, &pub_path, false).expect("init");
        assert_eq!(outcome.fingerprint.len(), 8);

        // Parse the private key back and sign / verify a test message
        // to prove the file content is functional.
        let signing = read_priv_key(&priv_path).expect("re-read priv");
        let msg = b"roundtrip-canary";
        let sig = signing.sign(msg);
        let vk = signing.verifying_key();
        vk.verify_strict(msg, &sig).expect("self-verify");
    }

    #[test]
    fn cli_init_appends_to_existing_pub_file() {
        let dir = TempDir::new().unwrap();
        let priv1 = dir.path().join("admin1.key");
        let priv2 = dir.path().join("admin2.key");
        let pub_path = dir.path().join("admin.pub");

        // Seed the pub file with an existing key + comment.
        std::fs::write(
            &pub_path,
            "# pre-existing\n\
             1111111111111111111111111111111111111111111111111111111111111111\n",
        )
        .unwrap();

        run_init(&priv1, &pub_path, false).unwrap();
        run_init(&priv2, &pub_path, false).unwrap();

        let content = std::fs::read_to_string(&pub_path).unwrap();
        // Existing line still there.
        assert!(
            content.contains("1111111111111111111111111111111111111111111111111111111111111111")
        );
        // Two new fingerprint comments added.
        assert_eq!(content.matches("# nn-admin generated").count(), 2);
    }

    #[test]
    fn cli_init_rejects_existing_priv_file_without_force() {
        let dir = TempDir::new().unwrap();
        let priv_path = dir.path().join("admin.key");
        let pub_path = dir.path().join("admin.pub");
        std::fs::write(&priv_path, "already here").unwrap();
        let err = run_init(&priv_path, &pub_path, false).unwrap_err();
        assert!(
            err.to_string().contains("writing private key"),
            "expected priv-write error, got: {err}"
        );
    }

    #[test]
    fn cli_init_force_overwrites_priv_file() {
        let dir = TempDir::new().unwrap();
        let priv_path = dir.path().join("admin.key");
        let pub_path = dir.path().join("admin.pub");
        std::fs::write(&priv_path, "old garbage that is not 64 hex chars").unwrap();
        run_init(&priv_path, &pub_path, true).expect("force overwrite");
        let content = std::fs::read_to_string(&priv_path).unwrap();
        // 64 hex chars + newline.
        assert_eq!(content.trim().len(), 64);
    }

    #[test]
    fn cli_verify_keys_counts_correctly() {
        let dir = TempDir::new().unwrap();
        let pub_path = dir.path().join("admin.pub");
        // Three valid keys, two comments, one blank line.
        let signing1 = SigningKey::generate(&mut OsRng);
        let signing2 = SigningKey::generate(&mut OsRng);
        let signing3 = SigningKey::generate(&mut OsRng);
        let content = format!(
            "# header\n{k1}\n\n# middle\n{k2}\n{k3}\n",
            k1 = hex::encode(signing1.verifying_key().to_bytes()),
            k2 = hex::encode(signing2.verifying_key().to_bytes()),
            k3 = hex::encode(signing3.verifying_key().to_bytes())
        );
        std::fs::write(&pub_path, content).unwrap();
        let out = run_verify_keys(&pub_path).expect("verify");
        assert_eq!(out.fingerprints.len(), 3);
        for fp in &out.fingerprints {
            assert_eq!(fp.len(), 8);
        }
    }

    #[test]
    fn cli_verify_keys_errors_on_empty_file() {
        let dir = TempDir::new().unwrap();
        let pub_path = dir.path().join("admin.pub");
        std::fs::write(&pub_path, "# only comments\n\n").unwrap();
        let out = run_verify_keys(&pub_path).expect("verify");
        assert_eq!(out.fingerprints.len(), 0);
        // The binary maps fingerprints.is_empty() → exit code 1.
    }

    #[test]
    fn cli_verify_keys_errors_on_malformed_hex() {
        let dir = TempDir::new().unwrap();
        let pub_path = dir.path().join("admin.pub");
        std::fs::write(&pub_path, "not-64-hex-chars\n").unwrap();
        let err = run_verify_keys(&pub_path).unwrap_err();
        assert!(err.to_string().contains(":1:"), "got: {err}");
    }

    // ── socket commands (mock server) ──────────────────────────────

    /// Spawn a synchronous mock server on `socket_path`. The closure
    /// is given the inbound `AdminMessage`s one at a time (via the
    /// returned channel) and replies via `write_frame`. The handle
    /// is joined at test-drop to surface any panics.
    fn spawn_mock_server<F>(socket_path: &Path, handler: F) -> thread::JoinHandle<()>
    where
        F: FnOnce(&mut UnixStream) + Send + 'static,
    {
        // `UnixListener::bind` is synchronous — by the time it returns
        // the socket is ready for `connect()`, so the client thread
        // does not need a separate readiness signal.
        let listener = UnixListener::bind(socket_path).expect("bind");
        thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept");
            handler(&mut stream);
        })
    }

    /// Helper to mirror the server-side framing used by the agent.
    fn server_write_frame(stream: &mut UnixStream, msg: &AdminMessage) {
        let bytes = encode_frame(msg).expect("encode");
        stream.write_all(&bytes).expect("write");
    }

    fn server_read_frame(stream: &mut UnixStream) -> AdminMessage {
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

    #[test]
    fn cli_unlock_happy_path() {
        let dir = TempDir::new().unwrap();
        let socket = dir.path().join("admin.sock");
        let priv_path = dir.path().join("admin.key");
        let signing = SigningKey::generate(&mut OsRng);
        std::fs::write(&priv_path, format!("{}\n", hex::encode(signing.to_bytes()))).unwrap();

        let vk = signing.verifying_key();
        let nonce = [0x11u8; 32];

        let server = spawn_mock_server(&socket, move |stream| {
            // Expect ChallengeRequest → reply Challenge.
            match server_read_frame(stream) {
                AdminMessage::ChallengeRequest(_) => {}
                other => panic!("expected ChallengeRequest, got {other:?}"),
            }
            server_write_frame(stream, &AdminMessage::Challenge(Challenge { nonce }));

            // Expect Unlock(sig). Verify sig matches the nonce we just
            // sent, so the test exercises the real signing path.
            let unlock = match server_read_frame(stream) {
                AdminMessage::Unlock(u) => u,
                other => panic!("expected Unlock, got {other:?}"),
            };
            let sig = ed25519_dalek::Signature::from_bytes(&unlock.signature);
            vk.verify_strict(&nonce, &sig)
                .expect("client sig must verify");

            server_write_frame(stream, &AdminMessage::UnlockResult(UnlockResult::Success));
        });

        let outcome = run_unlock(&socket, &priv_path).expect("unlock");
        assert!(matches!(outcome, UnlockOutcome::Success));
        server.join().unwrap();
    }

    #[test]
    fn cli_unlock_propagates_rate_limited() {
        let dir = TempDir::new().unwrap();
        let socket = dir.path().join("admin.sock");
        let priv_path = dir.path().join("admin.key");
        let signing = SigningKey::generate(&mut OsRng);
        std::fs::write(&priv_path, format!("{}\n", hex::encode(signing.to_bytes()))).unwrap();

        let server = spawn_mock_server(&socket, move |stream| {
            match server_read_frame(stream) {
                AdminMessage::ChallengeRequest(_) => {}
                other => panic!("got {other:?}"),
            }
            server_write_frame(
                stream,
                &AdminMessage::Challenge(Challenge { nonce: [0u8; 32] }),
            );
            let _ = server_read_frame(stream); // Unlock
            server_write_frame(
                stream,
                &AdminMessage::UnlockResult(UnlockResult::RateLimited {
                    retry_after_secs: 42,
                }),
            );
        });

        let outcome = run_unlock(&socket, &priv_path).expect("unlock");
        match outcome {
            UnlockOutcome::RateLimited { retry_after_secs } => {
                assert_eq!(retry_after_secs, 42);
            }
            other => panic!("expected RateLimited, got {other:?}"),
        }
        server.join().unwrap();
    }

    #[test]
    fn cli_unlock_propagates_invalid_signature() {
        let dir = TempDir::new().unwrap();
        let socket = dir.path().join("admin.sock");
        let priv_path = dir.path().join("admin.key");
        let signing = SigningKey::generate(&mut OsRng);
        std::fs::write(&priv_path, format!("{}\n", hex::encode(signing.to_bytes()))).unwrap();

        let server = spawn_mock_server(&socket, move |stream| {
            let _ = server_read_frame(stream);
            server_write_frame(
                stream,
                &AdminMessage::Challenge(Challenge { nonce: [0u8; 32] }),
            );
            let _ = server_read_frame(stream);
            server_write_frame(
                stream,
                &AdminMessage::UnlockResult(UnlockResult::InvalidSignature),
            );
        });
        let outcome = run_unlock(&socket, &priv_path).expect("unlock");
        assert!(matches!(outcome, UnlockOutcome::InvalidSignature));
        server.join().unwrap();
    }

    #[test]
    fn cli_status_returns_server_response() {
        let dir = TempDir::new().unwrap();
        let socket = dir.path().join("admin.sock");

        let server = spawn_mock_server(&socket, |stream| {
            match server_read_frame(stream) {
                AdminMessage::Status(_) => {}
                other => panic!("got {other:?}"),
            }
            server_write_frame(
                stream,
                &AdminMessage::StatusResponse(StatusResponse {
                    posture: PostureKind::Combat,
                    network_isolation_engaged: true,
                    last_admin_action_secs_ago: Some(123),
                }),
            );
        });
        let out = run_status(&socket).expect("status");
        assert_eq!(out.posture, PostureKind::Combat);
        assert!(out.network_isolation_engaged);
        assert_eq!(out.last_admin_action_secs_ago, Some(123));
        server.join().unwrap();
    }

    #[test]
    fn pubkey_fingerprint_is_deterministic() {
        let signing = SigningKey::generate(&mut OsRng);
        let vk = signing.verifying_key();
        let a = pubkey_fingerprint(&vk);
        let b = pubkey_fingerprint(&vk);
        assert_eq!(a, b);
        assert_eq!(a.len(), 8);
        // Differs for a different key, with overwhelming probability.
        let other = SigningKey::generate(&mut OsRng).verifying_key();
        assert_ne!(pubkey_fingerprint(&other), a);
    }
}
