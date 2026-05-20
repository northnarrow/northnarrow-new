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

use common::posture_types::PostureKind;
use common::wire::admin_protocol::{
    decode_frame, encode_frame, AdminMessage, AdminResult, ChallengeRequest, ForcePostureRequest,
    KeyedSignature, ShutdownRequest, StatusRequest, UnlockRequest, UnlockResult,
};
use common::wire::admin_signed_payload::{sign, SignedPayload};

use crate::agent_id::{self, AGENT_ID_LEN};

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

/// Result of `nn-admin force-posture` (Tappa 8 A10, design §4 +
/// §12.2). Mirrors [`ShutdownOutcome`] variant-for-variant — the
/// underlying wire reply is the shared [`AdminResult`] enum, so
/// the exit-code mapping is identical to shutdown's. Distinct
/// type so the binary's exit-mapper can format
/// force-posture-specific operator hints.
#[derive(Debug)]
pub enum ForcePostureOutcome {
    Success,
    InvalidSignature,
    NoPendingChallenge,
    RateLimited { retry_after_secs: u32 },
    QuorumNotMet { required: u8, provided: u8 },
    RoleDenied,
    TimestampSkew { server_ts: u64, max_skew_secs: u32 },
    AgentIdMismatch,
    UnknownOperation,
    ProtocolVersionUnsupported { server_version: u16 },
}

/// Result of `nn-admin shutdown` (Tappa 8 A9, design §5.1 + §10).
/// Mapped to the binary's exit codes per the design §5.3 contract:
/// - Success=0 (clean acknowledgement; the agent will exit and the
///   watchdog will stand down)
/// - InvalidSignature=2 (legacy code; also catches the rare
///   misconfigured admin.pub line case)
/// - NoPendingChallenge=3 (server state out of sync — retry)
/// - RateLimited=4 (server-side throttle hit)
/// - Transport=5 (covers TimestampSkew / AgentIdMismatch /
///   UnknownOperation / ProtocolVersionUnsupported — all are
///   environment / config / version-mismatch issues the operator
///   must investigate before retrying)
/// - QuorumNotMet=6 (NEW per design §5.3 — too few distinct sigs)
/// - RoleDenied=7 (NEW per design §5.3 — keys present but lack
///   the `shutdown` role; check admin.pub)
#[derive(Debug)]
pub enum ShutdownOutcome {
    Success,
    InvalidSignature,
    NoPendingChallenge,
    RateLimited { retry_after_secs: u32 },
    QuorumNotMet { required: u8, provided: u8 },
    RoleDenied,
    TimestampSkew { server_ts: u64, max_skew_secs: u32 },
    AgentIdMismatch,
    UnknownOperation,
    ProtocolVersionUnsupported { server_version: u16 },
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

/// Tappa 8 A9 — full signed-shutdown CLI flow.
///
/// Wire path (design §10):
/// 1. Connect to `socket`.
/// 2. Send a `ChallengeRequest`; receive a `Challenge { nonce }`.
/// 3. Read `agent_id` from the local `agent_id_path` — the same
///    file the agent's `main.rs` reads at startup
///    (`/etc/northnarrow/agent_id` per design §6.5). nn-admin is
///    typically run on the same host (or through an SSH-forwarded
///    socket per §8.1), so a local read is the source of truth.
/// 4. Build a [`SignedPayload`] for `OperationCode::Shutdown` with
///    the nonce, current wall-clock ts, agent_id, and the
///    operator's `grace_secs`.
/// 5. Sign the payload with BOTH private keys (one nonce signed
///    by both — the simpler per-§13 A9 row resolution).
/// 6. Submit one `ShutdownRequest` carrying both signatures.
/// 7. Parse the `ShutdownResult(AdminResult)` reply into a typed
///    [`ShutdownOutcome`] for the binary to map to an exit code.
///
/// Both keys are REQUIRED — the agent's quorum verify (A6+A7)
/// requires `min_distinct >= 2` for shutdown. Passing the same
/// key as both `key` and `cosign_key` will fail server-side with
/// `QuorumNotMet { required: 2, provided: 1 }` (the server tallies
/// distinct fingerprints).
///
/// `grace_secs` is clamped to the design §10.2 maximum of 300 (5
/// min). A value larger than the cap is rejected at parse time
/// rather than silently truncated.
pub fn run_shutdown(
    socket: &Path,
    key_path: &Path,
    cosign_key_path: &Path,
    agent_id_path: &Path,
    grace_secs: u32,
) -> Result<ShutdownOutcome> {
    const MAX_GRACE_SECS: u32 = 300;
    if grace_secs > MAX_GRACE_SECS {
        bail!(
            "grace_secs {grace_secs} exceeds design §10.2 cap of {MAX_GRACE_SECS}"
        );
    }

    // Read both keys + the agent_id BEFORE opening the socket so a
    // typo'd path fails fast instead of holding the agent's
    // dispatcher connection while we error.
    let signing_a = read_priv_key(key_path)?;
    let signing_b = read_priv_key(cosign_key_path)?;
    let agent_id_arr =
        agent_id::load_or_bootstrap(agent_id_path).with_context(|| {
            format!(
                "reading agent_id at {} (nn-admin must run on the agent host \
                 or have the file copied / SSH-forwarded — design §6.5)",
                agent_id_path.display()
            )
        })?;
    // Compile-time guarantee that the wire shape matches the file
    // shape — if a future hardening tappa changes either width the
    // build breaks before we ship a mismatched signer.
    const _: () = assert!(AGENT_ID_LEN == 16);

    let mut stream = connect_socket(socket)?;

    write_frame(
        &mut stream,
        &AdminMessage::ChallengeRequest(ChallengeRequest {}),
    )?;
    let nonce = match read_frame(&mut stream)? {
        AdminMessage::Challenge(c) => c.nonce,
        other => bail!("unexpected server reply to ChallengeRequest: {other:?}"),
    };

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    let payload =
        SignedPayload::new_shutdown(nonce, now, agent_id_arr, grace_secs);
    let sig_a: [u8; 64] = sign(&payload, &signing_a)
        .map_err(|e| anyhow!("signing payload with primary key: {e}"))?;
    let sig_b: [u8; 64] = sign(&payload, &signing_b)
        .map_err(|e| anyhow!("signing payload with cosign key: {e}"))?;

    write_frame(
        &mut stream,
        &AdminMessage::ShutdownRequest(ShutdownRequest {
            payload,
            signatures: vec![
                KeyedSignature { signature: sig_a },
                KeyedSignature { signature: sig_b },
            ],
        }),
    )?;

    let result = match read_frame(&mut stream)? {
        AdminMessage::ShutdownResult(r) => r,
        other => bail!("unexpected server reply to ShutdownRequest: {other:?}"),
    };

    Ok(match result {
        AdminResult::Success => ShutdownOutcome::Success,
        AdminResult::InvalidSignature => ShutdownOutcome::InvalidSignature,
        AdminResult::NoPendingChallenge => ShutdownOutcome::NoPendingChallenge,
        AdminResult::RateLimited { retry_after_secs } => {
            ShutdownOutcome::RateLimited { retry_after_secs }
        }
        AdminResult::QuorumNotMet { required, provided } => {
            ShutdownOutcome::QuorumNotMet { required, provided }
        }
        AdminResult::RoleDenied => ShutdownOutcome::RoleDenied,
        AdminResult::TimestampSkew {
            server_ts,
            max_skew_secs,
        } => ShutdownOutcome::TimestampSkew {
            server_ts,
            max_skew_secs,
        },
        AdminResult::AgentIdMismatch => ShutdownOutcome::AgentIdMismatch,
        AdminResult::UnknownOperation => ShutdownOutcome::UnknownOperation,
        AdminResult::ProtocolVersionUnsupported { server_version } => {
            ShutdownOutcome::ProtocolVersionUnsupported { server_version }
        }
    })
}

/// Tappa 8 A10 — full signed-production-force-posture CLI flow.
///
/// Wire path (design §4 + §12.2): challenge → sign → submit →
/// parse. Single signature (1-of-N quorum per §3.3). Required
/// admin.pub role: `force-posture` (parsed by A5's allowlist).
///
/// Allowed transitions: any → any (the agent's
/// `admin_force_state_with_token` accepts every PostureKind). The
/// design notes that this is **NOT** the preferred path out of
/// COMBAT — use `nn-admin unlock` instead, which carries clearer
/// audit semantics ("admin acknowledged COMBAT release") than a
/// force-posture from COMBAT to anything.
///
/// Distinct from `nn-admin debug force-posture`, which is the
/// integration-test path gated by the `debug-trigger` Cargo
/// feature. Both subcommands stay; production uses this one.
pub fn run_force_posture(
    socket: &Path,
    key_path: &Path,
    agent_id_path: &Path,
    target: PostureKind,
) -> Result<ForcePostureOutcome> {
    let signing = read_priv_key(key_path)?;
    let agent_id_arr =
        agent_id::load_or_bootstrap(agent_id_path).with_context(|| {
            format!(
                "reading agent_id at {} (nn-admin must run on the agent host \
                 or have the file copied / SSH-forwarded — design §6.5)",
                agent_id_path.display()
            )
        })?;
    const _: () = assert!(AGENT_ID_LEN == 16);

    let mut stream = connect_socket(socket)?;

    write_frame(
        &mut stream,
        &AdminMessage::ChallengeRequest(ChallengeRequest {}),
    )?;
    let nonce = match read_frame(&mut stream)? {
        AdminMessage::Challenge(c) => c.nonce,
        other => bail!("unexpected server reply to ChallengeRequest: {other:?}"),
    };

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    let payload =
        SignedPayload::new_force_posture(nonce, now, agent_id_arr, target);
    let sig: [u8; 64] = sign(&payload, &signing)
        .map_err(|e| anyhow!("signing force-posture payload: {e}"))?;

    write_frame(
        &mut stream,
        &AdminMessage::ForcePostureRequest(ForcePostureRequest {
            payload,
            signatures: vec![KeyedSignature { signature: sig }],
        }),
    )?;

    let result = match read_frame(&mut stream)? {
        AdminMessage::ForcePostureResult(r) => r,
        other => bail!(
            "unexpected server reply to ForcePostureRequest: {other:?}"
        ),
    };

    Ok(match result {
        AdminResult::Success => ForcePostureOutcome::Success,
        AdminResult::InvalidSignature => ForcePostureOutcome::InvalidSignature,
        AdminResult::NoPendingChallenge => ForcePostureOutcome::NoPendingChallenge,
        AdminResult::RateLimited { retry_after_secs } => {
            ForcePostureOutcome::RateLimited { retry_after_secs }
        }
        AdminResult::QuorumNotMet { required, provided } => {
            ForcePostureOutcome::QuorumNotMet { required, provided }
        }
        AdminResult::RoleDenied => ForcePostureOutcome::RoleDenied,
        AdminResult::TimestampSkew {
            server_ts,
            max_skew_secs,
        } => ForcePostureOutcome::TimestampSkew {
            server_ts,
            max_skew_secs,
        },
        AdminResult::AgentIdMismatch => ForcePostureOutcome::AgentIdMismatch,
        AdminResult::UnknownOperation => ForcePostureOutcome::UnknownOperation,
        AdminResult::ProtocolVersionUnsupported { server_version } => {
            ForcePostureOutcome::ProtocolVersionUnsupported { server_version }
        }
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

// ── Tappa 8 A13 — rotate-keys add / revoke ──────────────────────────

/// Outcome of `nn-admin rotate-keys {add,revoke}`. Mirrors
/// [`ShutdownOutcome`] (same wire surface — 2-of-N quorum,
/// `Role::RotateKeys` requirement); kept as a separate enum so
/// the binary can render distinct human messages.
#[derive(Debug)]
pub enum RotateKeysOutcome {
    Success,
    InvalidSignature,
    NoPendingChallenge,
    RateLimited { retry_after_secs: u32 },
    QuorumNotMet { required: u8, provided: u8 },
    RoleDenied,
    TimestampSkew { server_ts: u64, max_skew_secs: u32 },
    AgentIdMismatch,
    UnknownOperation,
    ProtocolVersionUnsupported { server_version: u16 },
}

/// `nn-admin rotate-keys add` — submit a 2-of-N quorum-signed
/// request to install `new_pubkey` (with the given role
/// allowlist) into the agent's `admin.pub`. The agent atomically
/// rewrites the file + reloads its in-memory key set so the next
/// challenge already sees the addition (design §7.2).
///
/// Two keys are required — distinct fingerprints, both carrying
/// `Role::RotateKeys`. Same wire flow as `run_shutdown`: read
/// keys, get nonce, build SignedPayload, sign with both,
/// transmit.
pub fn run_rotate_keys_add(
    socket: &Path,
    key_path: &Path,
    cosign_key_path: &Path,
    agent_id_path: &Path,
    new_pubkey_hex: &str,
    roles: &[common::wire::admin_signed_payload::Role],
) -> Result<RotateKeysOutcome> {
    let new_pubkey_bytes = parse_pubkey_hex(new_pubkey_hex)?;

    let signing_a = read_priv_key(key_path)?;
    let signing_b = read_priv_key(cosign_key_path)?;
    let agent_id_arr = agent_id::load_or_bootstrap(agent_id_path).with_context(|| {
        format!("reading agent_id at {}", agent_id_path.display())
    })?;
    const _: () = assert!(AGENT_ID_LEN == 16);

    let mut stream = connect_socket(socket)?;
    write_frame(
        &mut stream,
        &AdminMessage::ChallengeRequest(ChallengeRequest {}),
    )?;
    let nonce = match read_frame(&mut stream)? {
        AdminMessage::Challenge(c) => c.nonce,
        other => bail!("unexpected reply to ChallengeRequest: {other:?}"),
    };
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    let payload = SignedPayload::new_rotate_keys_add(
        nonce,
        now,
        agent_id_arr,
        new_pubkey_bytes,
        roles.to_vec(),
    );
    let sig_a: [u8; 64] =
        sign(&payload, &signing_a).map_err(|e| anyhow!("signing payload with primary key: {e}"))?;
    let sig_b: [u8; 64] =
        sign(&payload, &signing_b).map_err(|e| anyhow!("signing payload with cosign key: {e}"))?;

    write_frame(
        &mut stream,
        &AdminMessage::RotateKeysAddRequest(
            common::wire::admin_protocol::RotateKeysAddRequest {
                payload,
                signatures: vec![
                    KeyedSignature { signature: sig_a },
                    KeyedSignature { signature: sig_b },
                ],
            },
        ),
    )?;

    let result = match read_frame(&mut stream)? {
        AdminMessage::RotateKeysAddResult(r) => r,
        other => bail!("unexpected reply to RotateKeysAddRequest: {other:?}"),
    };
    Ok(map_admin_result_to_rotate(result))
}

/// `nn-admin rotate-keys revoke` — submit a 2-of-N quorum-signed
/// request to remove the line whose pubkey fingerprint matches
/// `fingerprint_hex` (8 hex chars / 4 bytes). The agent refuses
/// to revoke the last key — operators must add a replacement
/// first (design §7.2).
pub fn run_rotate_keys_revoke(
    socket: &Path,
    key_path: &Path,
    cosign_key_path: &Path,
    agent_id_path: &Path,
    fingerprint_hex: &str,
) -> Result<RotateKeysOutcome> {
    let target_fp = parse_fingerprint_hex(fingerprint_hex)?;
    let signing_a = read_priv_key(key_path)?;
    let signing_b = read_priv_key(cosign_key_path)?;
    let agent_id_arr = agent_id::load_or_bootstrap(agent_id_path).with_context(|| {
        format!("reading agent_id at {}", agent_id_path.display())
    })?;
    const _: () = assert!(AGENT_ID_LEN == 16);

    let mut stream = connect_socket(socket)?;
    write_frame(
        &mut stream,
        &AdminMessage::ChallengeRequest(ChallengeRequest {}),
    )?;
    let nonce = match read_frame(&mut stream)? {
        AdminMessage::Challenge(c) => c.nonce,
        other => bail!("unexpected reply to ChallengeRequest: {other:?}"),
    };
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    let payload =
        SignedPayload::new_rotate_keys_revoke(nonce, now, agent_id_arr, target_fp);
    let sig_a: [u8; 64] =
        sign(&payload, &signing_a).map_err(|e| anyhow!("signing payload with primary key: {e}"))?;
    let sig_b: [u8; 64] =
        sign(&payload, &signing_b).map_err(|e| anyhow!("signing payload with cosign key: {e}"))?;

    write_frame(
        &mut stream,
        &AdminMessage::RotateKeysRevokeRequest(
            common::wire::admin_protocol::RotateKeysRevokeRequest {
                payload,
                signatures: vec![
                    KeyedSignature { signature: sig_a },
                    KeyedSignature { signature: sig_b },
                ],
            },
        ),
    )?;

    let result = match read_frame(&mut stream)? {
        AdminMessage::RotateKeysRevokeResult(r) => r,
        other => bail!("unexpected reply to RotateKeysRevokeRequest: {other:?}"),
    };
    Ok(map_admin_result_to_rotate(result))
}

fn parse_pubkey_hex(s: &str) -> Result<[u8; 32]> {
    let trimmed = s.trim();
    if trimmed.len() != 64 {
        bail!("--new-pubkey must be 64 hex chars (got {})", trimmed.len());
    }
    let bytes = hex::decode(trimmed)
        .map_err(|e| anyhow!("--new-pubkey is not valid hex: {e}"))?;
    let arr: [u8; 32] = bytes.try_into().expect("hex pre-validated to 32 bytes");
    // Reject all-zero pubkeys (not a valid Ed25519 point) early so
    // the agent doesn't have to.
    VerifyingKey::from_bytes(&arr)
        .map_err(|e| anyhow!("--new-pubkey is not a valid Ed25519 pubkey: {e}"))?;
    Ok(arr)
}

fn parse_fingerprint_hex(s: &str) -> Result<[u8; 4]> {
    let trimmed = s.trim();
    if trimmed.len() != 8 {
        bail!(
            "--fingerprint must be 8 hex chars (got {}); the value matches \
             `nn-admin verify-keys` output",
            trimmed.len()
        );
    }
    let bytes = hex::decode(trimmed)
        .map_err(|e| anyhow!("--fingerprint is not valid hex: {e}"))?;
    let arr: [u8; 4] = bytes.try_into().expect("hex pre-validated to 4 bytes");
    Ok(arr)
}

fn map_admin_result_to_rotate(r: AdminResult) -> RotateKeysOutcome {
    match r {
        AdminResult::Success => RotateKeysOutcome::Success,
        AdminResult::InvalidSignature => RotateKeysOutcome::InvalidSignature,
        AdminResult::NoPendingChallenge => RotateKeysOutcome::NoPendingChallenge,
        AdminResult::RateLimited { retry_after_secs } => {
            RotateKeysOutcome::RateLimited { retry_after_secs }
        }
        AdminResult::QuorumNotMet { required, provided } => {
            RotateKeysOutcome::QuorumNotMet { required, provided }
        }
        AdminResult::RoleDenied => RotateKeysOutcome::RoleDenied,
        AdminResult::TimestampSkew {
            server_ts,
            max_skew_secs,
        } => RotateKeysOutcome::TimestampSkew {
            server_ts,
            max_skew_secs,
        },
        AdminResult::AgentIdMismatch => RotateKeysOutcome::AgentIdMismatch,
        AdminResult::UnknownOperation => RotateKeysOutcome::UnknownOperation,
        AdminResult::ProtocolVersionUnsupported { server_version } => {
            RotateKeysOutcome::ProtocolVersionUnsupported { server_version }
        }
    }
}

// ── Tappa 8 A12 — audit read / audit verify ─────────────────────────

/// Outcome of `nn-admin audit verify`. Mapped to exit codes in
/// the binary (Success=0, ChainBroken=8 per design §5.3).
#[derive(Debug)]
pub enum AuditVerifyOutcome {
    /// Chain verified end-to-end. `entries` is the count walked
    /// (printed to the operator so they know how much they
    /// audited).
    Success { entries: usize },
    /// Chain failed at the carried index. The typed
    /// [`crate::audit::AuditVerifyError`] is preserved so the
    /// caller can print the specific failure mode (prev_hash
    /// mismatch, entry_hash mismatch, signature invalid,
    /// malformed field). Exit code 8.
    ChainBroken(crate::audit::AuditVerifyError),
}

/// `nn-admin audit read` — stream the audit log to stdout. Reads
/// the on-disk JSONL log at `log_path` (default
/// `/etc/northnarrow/audit.log`), optionally filtered by `since`
/// (ISO-8601 timestamp string; entries whose `ts` is
/// lexicographically `>=` are kept — RFC-3339 ISO strings sort
/// the same way as the underlying instants because the format
/// is fixed-width).
///
/// Output is one entry per line:
/// - **Human (default)**: a tabular `ts op key_fp result` line
///   plus the full JSON dump beside it. Compact enough for a
///   `less`-style scroll, complete enough for an operator to
///   not need a second tool.
/// - **JSON (`json=true`)**: one canonical JSON object per
///   line. Matches the on-disk JSONL exactly; the field set
///   round-trips with [`crate::audit::AuditEntry`].
///
/// Returns the number of entries written so the binary can print
/// `audit: N entries read`.
pub fn run_audit_read(log_path: &Path, since: Option<&str>, json: bool) -> Result<usize> {
    use std::io::{BufRead, BufReader, Write};
    let f = match std::fs::OpenOptions::new().read(true).open(log_path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            // Empty/absent log is a valid state (fresh install,
            // no admin ops yet). Print nothing, return 0 — the
            // binary's summary line communicates the count.
            return Ok(0);
        }
        Err(e) => return Err(anyhow!(e).context(format!("opening {}", log_path.display()))),
    };
    let reader = BufReader::new(f);
    let stdout = std::io::stdout();
    let mut out = stdout.lock();
    let mut count = 0usize;
    for (idx, line) in reader.lines().enumerate() {
        let line = line.with_context(|| format!("reading line {} of {}", idx + 1, log_path.display()))?;
        if line.is_empty() {
            continue;
        }
        let entry: crate::audit::AuditEntry = serde_json::from_str(&line).with_context(|| {
            format!(
                "parsing audit-log line {} of {} as JSON",
                idx + 1,
                log_path.display()
            )
        })?;
        if let Some(threshold) = since {
            if entry.ts.as_str() < threshold {
                continue;
            }
        }
        if json {
            // Re-serialise to canonical form (drops any extra
            // whitespace the file might have, normalises field
            // order to the struct order).
            let canonical = serde_json::to_string(&entry)
                .map_err(|e| anyhow!("re-serialising audit entry: {e}"))?;
            writeln!(out, "{canonical}").context("writing stdout")?;
        } else {
            // Human-friendly compact summary; entry.result may be
            // long ("failure: …") so we don't pad it.
            writeln!(
                out,
                "{} {:<16} {} {} {}",
                entry.ts, entry.op, entry.key_fp, entry.result, entry.entry_hash
            )
            .context("writing stdout")?;
        }
        count += 1;
    }
    Ok(count)
}

/// `nn-admin audit verify` — replay the chain in `from_path`
/// through [`crate::audit::verify_chain`] using `pubkey`.
/// Returns [`AuditVerifyOutcome::Success`] with the entry count
/// or [`AuditVerifyOutcome::ChainBroken`] carrying the typed
/// failure.
///
/// An empty / missing file is `Success { entries: 0 }` — there's
/// nothing to verify and that is not an error condition; the
/// exit-8 contract per §5.3 is reserved for an *actually-broken*
/// chain.
pub fn run_audit_verify(from_path: &Path, pubkey: &VerifyingKey) -> Result<AuditVerifyOutcome> {
    use std::io::{BufRead, BufReader};
    let f = match std::fs::OpenOptions::new().read(true).open(from_path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Ok(AuditVerifyOutcome::Success { entries: 0 });
        }
        Err(e) => return Err(anyhow!(e).context(format!("opening {}", from_path.display()))),
    };
    let reader = BufReader::new(f);
    let mut entries: Vec<crate::audit::AuditEntry> = Vec::new();
    for (idx, line) in reader.lines().enumerate() {
        let line = line.with_context(|| {
            format!("reading line {} of {}", idx + 1, from_path.display())
        })?;
        if line.is_empty() {
            continue;
        }
        let entry: crate::audit::AuditEntry = serde_json::from_str(&line).with_context(|| {
            format!(
                "parsing audit-log line {} of {} as JSON",
                idx + 1,
                from_path.display()
            )
        })?;
        entries.push(entry);
    }
    match crate::audit::verify_chain(&entries, pubkey) {
        Ok(()) => Ok(AuditVerifyOutcome::Success {
            entries: entries.len(),
        }),
        Err(e) => Ok(AuditVerifyOutcome::ChainBroken(e)),
    }
}

/// Load an agent verifying key for `audit verify`. Prefers an
/// explicit `--agent-pubkey <hex>` (32 bytes / 64 hex chars,
/// optionally trailing newline) when present; otherwise reads
/// the local signing-key file at `key_path` and derives the
/// public half. The latter is the zero-config path on the
/// agent host (operator runs `sudo nn-admin audit verify
/// --from /etc/northnarrow/audit.log`); the former is the
/// off-host path (auditor receives the pubkey hex via an
/// out-of-band channel).
pub fn load_audit_pubkey(
    explicit_hex: Option<&str>,
    key_path: &Path,
) -> Result<VerifyingKey> {
    if let Some(hex_str) = explicit_hex {
        let trimmed = hex_str.trim();
        if trimmed.len() != 64 {
            bail!(
                "--agent-pubkey must be 64 hex chars (got {})",
                trimmed.len()
            );
        }
        let bytes = hex::decode(trimmed)
            .map_err(|e| anyhow!("--agent-pubkey is not valid hex: {e}"))?;
        let arr: [u8; 32] = bytes.try_into().expect("hex pre-validated to 32 bytes");
        return VerifyingKey::from_bytes(&arr)
            .map_err(|e| anyhow!("--agent-pubkey is not a valid Ed25519 pubkey: {e}"));
    }
    let key = crate::audit::AgentSigningKey::load_or_bootstrap(key_path).with_context(|| {
        format!(
            "deriving agent pubkey from signing key file {}; pass --agent-pubkey \
             <hex> when verifying off-host",
            key_path.display()
        )
    })?;
    Ok(key.verifying_key())
}

// ── Tappa 9 C6 — nn-admin fim baseline / report ────────────────────

/// Outcome of `nn-admin fim baseline`. Mirrors
/// [`ForcePostureOutcome`] (same 1-of-N quorum shape +
/// AdminResult mapping); kept as a separate enum so the
/// binary can render distinct human messages.
#[derive(Debug)]
pub enum FimBaselineOutcome {
    Success,
    InvalidSignature,
    NoPendingChallenge,
    RateLimited { retry_after_secs: u32 },
    QuorumNotMet { required: u8, provided: u8 },
    RoleDenied,
    TimestampSkew { server_ts: u64, max_skew_secs: u32 },
    AgentIdMismatch,
    UnknownOperation,
    ProtocolVersionUnsupported { server_version: u16 },
}

/// Outcome of `nn-admin fim report`. Success carries the
/// chained JSONL body the binary streams to stdout.
#[derive(Debug)]
pub enum FimReportOutcome {
    Success {
        entries_jsonl: String,
        entries_count: u32,
        entries_truncated: bool,
    },
    InvalidSignature,
    NoPendingChallenge,
    RateLimited { retry_after_secs: u32 },
    RoleDenied,
    TimestampSkew { server_ts: u64, max_skew_secs: u32 },
    AgentIdMismatch,
    UnknownOperation,
    ProtocolVersionUnsupported { server_version: u16 },
    Transport,
}

fn map_admin_result_to_baseline(r: common::wire::admin_protocol::AdminResult) -> FimBaselineOutcome {
    use common::wire::admin_protocol::AdminResult;
    match r {
        AdminResult::Success => FimBaselineOutcome::Success,
        AdminResult::InvalidSignature => FimBaselineOutcome::InvalidSignature,
        AdminResult::NoPendingChallenge => FimBaselineOutcome::NoPendingChallenge,
        AdminResult::RateLimited { retry_after_secs } => {
            FimBaselineOutcome::RateLimited { retry_after_secs }
        }
        AdminResult::QuorumNotMet { required, provided } => {
            FimBaselineOutcome::QuorumNotMet { required, provided }
        }
        AdminResult::RoleDenied => FimBaselineOutcome::RoleDenied,
        AdminResult::TimestampSkew {
            server_ts,
            max_skew_secs,
        } => FimBaselineOutcome::TimestampSkew {
            server_ts,
            max_skew_secs,
        },
        AdminResult::AgentIdMismatch => FimBaselineOutcome::AgentIdMismatch,
        AdminResult::UnknownOperation => FimBaselineOutcome::UnknownOperation,
        AdminResult::ProtocolVersionUnsupported { server_version } => {
            FimBaselineOutcome::ProtocolVersionUnsupported { server_version }
        }
    }
}

fn map_response_to_fim_report(
    resp: common::wire::admin_protocol::FimReportResponse,
) -> FimReportOutcome {
    use common::wire::admin_protocol::AdminResult;
    match resp.result {
        AdminResult::Success => FimReportOutcome::Success {
            entries_jsonl: resp.entries_jsonl,
            entries_count: resp.entries_count,
            entries_truncated: resp.entries_truncated,
        },
        AdminResult::InvalidSignature => FimReportOutcome::InvalidSignature,
        AdminResult::NoPendingChallenge => FimReportOutcome::NoPendingChallenge,
        AdminResult::RateLimited { retry_after_secs } => {
            FimReportOutcome::RateLimited { retry_after_secs }
        }
        AdminResult::RoleDenied => FimReportOutcome::RoleDenied,
        AdminResult::TimestampSkew {
            server_ts,
            max_skew_secs,
        } => FimReportOutcome::TimestampSkew {
            server_ts,
            max_skew_secs,
        },
        AdminResult::AgentIdMismatch => FimReportOutcome::AgentIdMismatch,
        AdminResult::QuorumNotMet { .. } => FimReportOutcome::InvalidSignature,
        AdminResult::UnknownOperation => FimReportOutcome::UnknownOperation,
        AdminResult::ProtocolVersionUnsupported { server_version } => {
            FimReportOutcome::ProtocolVersionUnsupported { server_version }
        }
    }
}

/// `nn-admin fim baseline` — submit a 1-of-N quorum-signed
/// request to recompute the FIM baseline. Per §13 Q6 baseline
/// is a workflow op (not a security gate), so single-sig with
/// the `fim-manage` role is sufficient.
pub fn run_fim_baseline(
    socket: &Path,
    key_path: &Path,
    agent_id_path: &Path,
) -> Result<FimBaselineOutcome> {
    use common::wire::admin_protocol::FimBaselineRequest;

    let signing = read_priv_key(key_path)?;
    let agent_id_arr = agent_id::load_or_bootstrap(agent_id_path)
        .with_context(|| format!("reading agent_id at {}", agent_id_path.display()))?;
    const _: () = assert!(AGENT_ID_LEN == 16);

    let mut stream = connect_socket(socket)?;
    write_frame(
        &mut stream,
        &AdminMessage::ChallengeRequest(ChallengeRequest {}),
    )?;
    let nonce = match read_frame(&mut stream)? {
        AdminMessage::Challenge(c) => c.nonce,
        other => bail!("unexpected reply to ChallengeRequest: {other:?}"),
    };
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let payload = SignedPayload::new_fim_baseline(nonce, now, agent_id_arr);
    let sig: [u8; 64] = sign(&payload, &signing)
        .map_err(|e| anyhow!("signing fim-baseline payload: {e}"))?;

    write_frame(
        &mut stream,
        &AdminMessage::FimBaselineRequest(FimBaselineRequest {
            payload,
            signatures: vec![KeyedSignature { signature: sig }],
        }),
    )?;
    let result = match read_frame(&mut stream)? {
        AdminMessage::FimBaselineResult(r) => r,
        other => bail!("unexpected reply to FimBaselineRequest: {other:?}"),
    };
    Ok(map_admin_result_to_baseline(result))
}

/// `nn-admin fim report` — submit a 1-of-N quorum-signed
/// request to read the chained drift log. `since_unix_ts`
/// filters server-side; `None` returns the full chain (capped
/// at half of MAX_FRAME_BODY — the response carries
/// `entries_truncated=true` when the cap fires, and the CLI
/// surfaces it to the operator as `"... pass --since <ts> to
/// narrow"`).
pub fn run_fim_report(
    socket: &Path,
    key_path: &Path,
    agent_id_path: &Path,
    since_unix_ts: Option<u64>,
) -> Result<FimReportOutcome> {
    use common::wire::admin_protocol::FimReportRequest;

    let signing = read_priv_key(key_path)?;
    let agent_id_arr = agent_id::load_or_bootstrap(agent_id_path)
        .with_context(|| format!("reading agent_id at {}", agent_id_path.display()))?;
    const _: () = assert!(AGENT_ID_LEN == 16);

    let mut stream = connect_socket(socket)?;
    write_frame(
        &mut stream,
        &AdminMessage::ChallengeRequest(ChallengeRequest {}),
    )?;
    let nonce = match read_frame(&mut stream)? {
        AdminMessage::Challenge(c) => c.nonce,
        other => bail!("unexpected reply to ChallengeRequest: {other:?}"),
    };
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let payload = SignedPayload::new_fim_report(nonce, now, agent_id_arr, since_unix_ts);
    let sig: [u8; 64] = sign(&payload, &signing)
        .map_err(|e| anyhow!("signing fim-report payload: {e}"))?;

    write_frame(
        &mut stream,
        &AdminMessage::FimReportRequest(FimReportRequest {
            payload,
            signatures: vec![KeyedSignature { signature: sig }],
        }),
    )?;
    let reply = read_frame(&mut stream)?;
    match reply {
        AdminMessage::FimReportResponse(resp) => Ok(map_response_to_fim_report(resp)),
        other => Ok({
            let _ = other;
            FimReportOutcome::Transport
        }),
    }
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

    // ── A9: nn-admin shutdown — mock-server tests ──────────────────

    use common::wire::admin_protocol::AdminResult;
    use common::wire::admin_signed_payload::verify;

    /// Write a 16-byte agent_id to a tempdir file in the canonical
    /// format. Returns both the path and the raw bytes so the test
    /// can verify the client signed with the expected value.
    fn write_agent_id_file(dir: &TempDir, raw: &[u8; 16]) -> PathBuf {
        let p = dir.path().join("agent_id");
        std::fs::write(&p, format!("{}\n", hex::encode(raw))).unwrap();
        p
    }

    /// Run `mock_server_fn` in a thread bound to `socket_path`,
    /// while `client_fn` runs in the foreground. Joins the server
    /// thread at the end so any server-side panic is surfaced.
    fn run_with_mock_server<S, C, R>(
        socket_path: &Path,
        mock_server_fn: S,
        client_fn: C,
    ) -> R
    where
        S: FnOnce(&mut UnixStream) + Send + 'static,
        C: FnOnce() -> R,
    {
        let server = spawn_mock_server(socket_path, mock_server_fn);
        let out = client_fn();
        server.join().expect("mock server panicked");
        out
    }

    /// Required A9 test 1 (happy path): a 2-of-N submission with
    /// distinct valid keys + Shutdown role + matching agent_id + in-
    /// window ts must round-trip to ShutdownOutcome::Success. Also
    /// proves the client actually signs the SignedPayload (the
    /// mock server verifies BOTH sigs against the served nonce-
    /// bound digest).
    #[test]
    fn cli_shutdown_happy_path_round_trip() {
        let dir = TempDir::new().unwrap();
        let socket = dir.path().join("admin.sock");
        let priv_a = dir.path().join("admin_a.key");
        let priv_b = dir.path().join("admin_b.key");
        let signing_a = SigningKey::generate(&mut OsRng);
        let signing_b = SigningKey::generate(&mut OsRng);
        std::fs::write(&priv_a, format!("{}\n", hex::encode(signing_a.to_bytes()))).unwrap();
        std::fs::write(&priv_b, format!("{}\n", hex::encode(signing_b.to_bytes()))).unwrap();
        let agent_id: [u8; 16] = [0x9Au8; 16];
        let agent_id_path = write_agent_id_file(&dir, &agent_id);

        let vk_a = signing_a.verifying_key();
        let vk_b = signing_b.verifying_key();
        let socket_for_client = socket.clone();
        let nonce = [0x33u8; 32];

        let outcome = run_with_mock_server(
            &socket,
            move |stream| {
                // Step 1: server replies with a fixed nonce.
                match server_read_frame(stream) {
                    AdminMessage::ChallengeRequest(_) => {}
                    other => panic!("expected ChallengeRequest, got {other:?}"),
                }
                server_write_frame(
                    stream,
                    &AdminMessage::Challenge(
                        common::wire::admin_protocol::Challenge { nonce },
                    ),
                );

                // Step 2: server receives ShutdownRequest, verifies
                // both signatures actually verify under the served
                // nonce + agent_id binding.
                let req = match server_read_frame(stream) {
                    AdminMessage::ShutdownRequest(r) => r,
                    other => panic!("expected ShutdownRequest, got {other:?}"),
                };
                assert_eq!(req.payload.nonce, nonce, "payload.nonce must echo served nonce");
                assert_eq!(req.payload.agent_id, agent_id, "payload.agent_id must match the file");
                assert_eq!(req.signatures.len(), 2, "exactly 2 sigs in quorum");
                // Both sigs verify against the SAME payload — the
                // design's "one nonce signed by both" resolution.
                verify(&req.payload, &req.signatures[0].signature, &vk_a)
                    .expect("sig_a must verify under key A");
                verify(&req.payload, &req.signatures[1].signature, &vk_b)
                    .expect("sig_b must verify under key B");

                // Step 3: server replies Success.
                server_write_frame(
                    stream,
                    &AdminMessage::ShutdownResult(AdminResult::Success),
                );
            },
            || run_shutdown(&socket_for_client, &priv_a, &priv_b, &agent_id_path, 30),
        );

        let outcome = outcome.expect("client should not error");
        assert!(matches!(outcome, ShutdownOutcome::Success));
    }

    /// Required A9 test 2 (server quorum-not-met → client outcome):
    /// the server replies QuorumNotMet { required: 2, provided: 1 };
    /// the client maps it to ShutdownOutcome::QuorumNotMet with the
    /// counts preserved.
    #[test]
    fn cli_shutdown_propagates_quorum_not_met() {
        let dir = TempDir::new().unwrap();
        let socket = dir.path().join("admin.sock");
        let priv_a = dir.path().join("admin_a.key");
        let priv_b = dir.path().join("admin_b.key");
        let signing_a = SigningKey::generate(&mut OsRng);
        let signing_b = SigningKey::generate(&mut OsRng);
        std::fs::write(&priv_a, format!("{}\n", hex::encode(signing_a.to_bytes()))).unwrap();
        std::fs::write(&priv_b, format!("{}\n", hex::encode(signing_b.to_bytes()))).unwrap();
        let agent_id_path = write_agent_id_file(&dir, &[0u8; 16]);

        let socket_for_client = socket.clone();
        let outcome = run_with_mock_server(
            &socket,
            move |stream| {
                let _ = server_read_frame(stream);
                server_write_frame(
                    stream,
                    &AdminMessage::Challenge(
                        common::wire::admin_protocol::Challenge { nonce: [0u8; 32] },
                    ),
                );
                let _ = server_read_frame(stream);
                server_write_frame(
                    stream,
                    &AdminMessage::ShutdownResult(AdminResult::QuorumNotMet {
                        required: 2,
                        provided: 1,
                    }),
                );
            },
            || run_shutdown(&socket_for_client, &priv_a, &priv_b, &agent_id_path, 30),
        )
        .expect("client should not error");
        match outcome {
            ShutdownOutcome::QuorumNotMet { required, provided } => {
                assert_eq!(required, 2);
                assert_eq!(provided, 1);
            }
            other => panic!("expected QuorumNotMet{{2,1}}, got {other:?}"),
        }
    }

    /// Required A9 test 3 (server role-denied → client outcome):
    /// the operator's keys verified but neither carries the
    /// `shutdown` role in admin.pub. Client surfaces RoleDenied.
    #[test]
    fn cli_shutdown_propagates_role_denied() {
        let dir = TempDir::new().unwrap();
        let socket = dir.path().join("admin.sock");
        let priv_a = dir.path().join("admin_a.key");
        let priv_b = dir.path().join("admin_b.key");
        let signing_a = SigningKey::generate(&mut OsRng);
        let signing_b = SigningKey::generate(&mut OsRng);
        std::fs::write(&priv_a, format!("{}\n", hex::encode(signing_a.to_bytes()))).unwrap();
        std::fs::write(&priv_b, format!("{}\n", hex::encode(signing_b.to_bytes()))).unwrap();
        let agent_id_path = write_agent_id_file(&dir, &[0u8; 16]);

        let socket_for_client = socket.clone();
        let outcome = run_with_mock_server(
            &socket,
            move |stream| {
                let _ = server_read_frame(stream);
                server_write_frame(
                    stream,
                    &AdminMessage::Challenge(
                        common::wire::admin_protocol::Challenge { nonce: [0u8; 32] },
                    ),
                );
                let _ = server_read_frame(stream);
                server_write_frame(
                    stream,
                    &AdminMessage::ShutdownResult(AdminResult::RoleDenied),
                );
            },
            || run_shutdown(&socket_for_client, &priv_a, &priv_b, &agent_id_path, 30),
        )
        .expect("client should not error");
        assert!(matches!(outcome, ShutdownOutcome::RoleDenied));
    }

    /// Required A9 test 4 (client-side input validation):
    /// grace_secs over the design §10.2 cap of 300 is rejected
    /// before any socket I/O — surfaces an anyhow Err with a
    /// message mentioning the cap. This is the only "client
    /// rejects the operator's request before talking to the
    /// server" path; every other client-side error wraps a
    /// server-side AdminResult.
    #[test]
    fn cli_shutdown_rejects_grace_over_cap_without_socket_io() {
        let dir = TempDir::new().unwrap();
        // Real files but a NON-EXISTENT socket: proves we didn't
        // try to connect (would have errored with "connection
        // refused" not "grace_secs ...").
        let priv_a = dir.path().join("admin_a.key");
        let priv_b = dir.path().join("admin_b.key");
        std::fs::write(
            &priv_a,
            format!("{}\n", hex::encode(SigningKey::generate(&mut OsRng).to_bytes())),
        )
        .unwrap();
        std::fs::write(
            &priv_b,
            format!("{}\n", hex::encode(SigningKey::generate(&mut OsRng).to_bytes())),
        )
        .unwrap();
        let agent_id_path = write_agent_id_file(&dir, &[0u8; 16]);
        let socket = dir.path().join("never_bound.sock");

        let err = run_shutdown(&socket, &priv_a, &priv_b, &agent_id_path, 9999)
            .unwrap_err();
        let s = format!("{err:#}");
        assert!(
            s.contains("grace_secs"),
            "error must mention grace_secs cap, got: {s}"
        );
        assert!(
            s.contains("300"),
            "error must mention the 300 s design cap, got: {s}"
        );
    }

    // ── Tappa 8 A12 — audit read / verify tests (5) ────────────────

    /// Builder helper: bootstrap a fresh agent signing key in `dir`,
    /// open an AuditLog at `dir/audit.log`, append `n` sample
    /// entries. Returns (key_path, log_path, pubkey, the entries).
    fn build_audit_log(
        dir: &TempDir,
        n: usize,
    ) -> (PathBuf, PathBuf, VerifyingKey, Vec<crate::audit::AuditEntry>) {
        let key_path = dir.path().join("agent.sig.key");
        let log_path = dir.path().join("audit.log");
        let key = crate::audit::AgentSigningKey::load_or_bootstrap(&key_path).unwrap();
        let pubkey = key.verifying_key();
        let mut log = crate::audit::AuditLog::open(&log_path, key, [0u8; 16]).unwrap();
        let mut entries = Vec::new();
        for i in 0..n {
            let draft = crate::audit::AuditEntryDraft {
                op: format!("test_op_{i}"),
                extra: serde_json::json!({ "seq": i }),
                key_fp: format!("{i:08x}"),
                cosigner_fps: vec![],
                result: "success".to_string(),
                client_pid: 1000 + i as u32,
                client_uid: 0,
                client_comm: "nn-admin".to_string(),
            };
            entries.push(log.append(draft).unwrap());
        }
        (key_path, log_path, pubkey, entries)
    }

    // ── Test 1 (A12 #1): read on a missing log returns 0 with no
    //                    spurious error (fresh install state).
    #[test]
    fn audit_read_missing_log_returns_zero() {
        let dir = TempDir::new().unwrap();
        let nowhere = dir.path().join("does-not-exist.jsonl");
        let n = run_audit_read(&nowhere, None, false).expect("missing log is not an error");
        assert_eq!(n, 0);
    }

    // ── Test 2 (A12 #2): read with --since filter drops entries
    //                    strictly older than the threshold.
    #[test]
    fn audit_read_since_filter_drops_older_entries() {
        let dir = TempDir::new().unwrap();
        let (_key_path, log_path, _pubkey, entries) = build_audit_log(&dir, 3);
        // since == third entry's ts → exactly one kept (>=, not >);
        // entries[2] passes, entries[0..=1] are dropped.
        let threshold = entries[2].ts.clone();
        let n = run_audit_read(&log_path, Some(&threshold), true).unwrap();
        assert_eq!(
            n, 1,
            "since-threshold equal to entries[2].ts should keep exactly entries[2]"
        );
        // since == "9999-..." → all dropped.
        let n_none = run_audit_read(&log_path, Some("9999-99-99T99:99:99Z"), true).unwrap();
        assert_eq!(n_none, 0);
        // since == "0001-..." → all kept.
        let n_all = run_audit_read(&log_path, Some("0001-01-01T00:00:00Z"), true).unwrap();
        assert_eq!(n_all, 3);
    }

    // ── Test 3 (A12 #3): verify on an intact chain returns
    //                    Success(count).
    #[test]
    fn audit_verify_intact_chain_returns_success() {
        let dir = TempDir::new().unwrap();
        let (_key_path, log_path, pubkey, _) = build_audit_log(&dir, 4);
        let outcome = run_audit_verify(&log_path, &pubkey).unwrap();
        match outcome {
            AuditVerifyOutcome::Success { entries } => assert_eq!(entries, 4),
            AuditVerifyOutcome::ChainBroken(e) => {
                panic!("intact chain reported broken: {e:?}");
            }
        }
    }

    // ── Test 4 (A12 #4): verify on a tampered chain returns
    //                    ChainBroken with the typed error.
    #[test]
    fn audit_verify_tampered_chain_reports_broken() {
        let dir = TempDir::new().unwrap();
        let (_key_path, log_path, pubkey, _) = build_audit_log(&dir, 2);
        // Rewrite the log: flip the first entry's `result` field
        // post-write — exactly the attack verify_chain catches via
        // EntryHashMismatch.
        let raw = std::fs::read_to_string(&log_path).unwrap();
        let mut lines: Vec<crate::audit::AuditEntry> = raw
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect();
        lines[0].result = "failure: someone-rewrote-this".to_string();
        let mut new_body = String::new();
        for l in &lines {
            new_body.push_str(&serde_json::to_string(l).unwrap());
            new_body.push('\n');
        }
        std::fs::write(&log_path, new_body).unwrap();

        let outcome = run_audit_verify(&log_path, &pubkey).unwrap();
        match outcome {
            AuditVerifyOutcome::ChainBroken(crate::audit::AuditVerifyError::EntryHashMismatch {
                idx: 0,
                ..
            }) => {} // expected
            other => panic!("expected EntryHashMismatch on entry 0; got: {other:?}"),
        }
    }

    // ── Test 5 (A12 #5): load_audit_pubkey accepts explicit
    //                    --agent-pubkey hex AND falls back to the
    //                    local signing-key file (zero-config path).
    #[test]
    fn load_audit_pubkey_explicit_hex_overrides_file_fallback() {
        let dir = TempDir::new().unwrap();
        // 1) Fresh signing key in the tempdir; pubkey from file
        //    matches the one load_audit_pubkey derives.
        let key_path = dir.path().join("agent.sig.key");
        let on_disk_key =
            crate::audit::AgentSigningKey::load_or_bootstrap(&key_path).unwrap();
        let on_disk_pub = on_disk_key.verifying_key();
        let derived = load_audit_pubkey(None, &key_path).expect("file fallback");
        assert_eq!(derived.to_bytes(), on_disk_pub.to_bytes());

        // 2) Explicit hex overrides — synthesise a DIFFERENT key,
        //    pass its hex pubkey; load_audit_pubkey must return the
        //    explicit one, NOT the on-disk one. Proves the
        //    explicit-hex path is wired.
        let other = SigningKey::generate(&mut OsRng);
        let other_pub_hex = hex::encode(other.verifying_key().to_bytes());
        let from_hex =
            load_audit_pubkey(Some(&other_pub_hex), &key_path).expect("explicit hex");
        assert_eq!(from_hex.to_bytes(), other.verifying_key().to_bytes());
        assert_ne!(
            from_hex.to_bytes(),
            on_disk_pub.to_bytes(),
            "explicit hex must NOT silently fall back to the file pubkey"
        );

        // 3) Bad-length hex is rejected with an actionable error.
        let too_short = "deadbeef".repeat(7); // 56 chars, not 64
        let err = load_audit_pubkey(Some(&too_short), &key_path).unwrap_err();
        let msg = format!("{err:#}");
        assert!(
            msg.contains("64 hex chars"),
            "error must mention the 64-hex-char shape; got: {msg}"
        );
    }
}
