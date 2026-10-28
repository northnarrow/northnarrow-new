//! Library half of the `nn-admin` CLI binary.
//!
//! The command line, [`crate::cli`] (the agent's `src/bin/nn_admin.rs`
//! until R10, lab PR 259), is a thin clap dispatcher. All real logic lives
//! here so it can be unit-tested without shelling out to a compiled
//! binary. Each `run_*` function takes its inputs explicitly and returns a
//! typed outcome; mapping to process exit codes happens in [`crate::cli`].
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
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use ed25519_dalek::{SigningKey, VerifyingKey};
use sha2::{Digest, Sha256};

use nn_model::posture_types::PostureKind;
use nn_proto::admin_protocol::{
    decode_frame, encode_frame, AdminMessage, AdminResult, CanaryBurnRequest, CanaryDeployRequest,
    CanaryListRequest, CanaryRefreshRequest, ChallengeRequest, ForcePostureRequest, KeyedSignature,
    ShutdownRequest, StatusRequest,
};
use nn_proto::admin_signed_payload::{sign, CanaryDeploymentWire, CanaryTypeWire, SignedPayload};

use crate::agent_id::{self, AGENT_ID_LEN};
use crate::host::{AdminHost, Chains};
use crate::os_rng::OsRng;

// ── public outcome types ────────────────────────────────────────────

/// Result of `nn-admin unlock`. Mapped to exit codes in the binary
/// (Success=0, InvalidSignature=2, NoPendingChallenge=3,
/// RateLimited=4, Transport/Refused=5, RoleDenied=7, ReleaseFailed=9).
///
/// Lab PR 217 (NN-AUD-243 residue, capability C17): the unlock is a signed
/// `OperationCode::Unlock` payload, and `Success` means the agent released
/// the containment and read the tables back clear; `ReleaseFailed` is a
/// verified request whose teardown did not take (the posture stays COMBAT).
/// `isolation_v4` / `isolation_v6` are the agent's per-family state after
/// the call.
#[derive(Debug)]
pub enum UnlockOutcome {
    Success {
        message: String,
        isolation_v4: bool,
        isolation_v6: bool,
    },
    ReleaseFailed {
        message: String,
        isolation_v4: bool,
        isolation_v6: bool,
    },
    InvalidSignature,
    NoPendingChallenge,
    RateLimited {
        retry_after_secs: u32,
    },
    /// The key verified but does not hold the `unlock` role.
    RoleDenied,
    /// Refused for another reason (clock skew, another install's
    /// agent_id, …): the reply as the agent sent it.
    Refused(AdminResult),
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
    RateLimited {
        retry_after_secs: u32,
    },
    QuorumNotMet {
        required: u8,
        provided: u8,
    },
    RoleDenied,
    TimestampSkew {
        server_ts: u64,
        max_skew_secs: u32,
    },
    AgentIdMismatch,
    UnknownOperation,
    ProtocolVersionUnsupported {
        server_version: u16,
    },
    /// Lab PR 217: verified, and leaving COMBAT released nothing the agent
    /// could read back — the posture stays COMBAT.
    ActionFailed,
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
    pub posture: nn_model::posture_types::PostureKind,
    pub network_isolation_engaged: bool,
    /// Lab PR 217 (capability C18): the isolation per IP family, as the
    /// agent read the tables back (`None`: agent predates the fields).
    pub network_isolation_v4: Option<bool>,
    pub network_isolation_v6: Option<bool>,
    pub last_admin_action_secs_ago: Option<u64>,
    /// Ring-buffer drops since boot (`None`: agent predates the field).
    pub ringbuf_drops_total: Option<u64>,
    pub ringbuf_drops: Vec<(String, u64)>,
    /// External audit CMB-016: the COMBAT ladder's stage while an episode
    /// is open (`None` outside one, or from an agent older than the field).
    pub combat_stage: Option<String>,
    /// Whether the COMBAT is locked (`None`: agent predates the field).
    pub combat_locked: Option<bool>,
    /// External audit SNS-008: malformed ring records rejected since boot
    /// (`None`: agent predates the counter).
    pub ringbuf_rejected_total: Option<u64>,
    pub ringbuf_rejected: Vec<(String, u64)>,
    /// External audit NET-019: netflow rows held back from the rules since
    /// boot (`None`: agent predates the counter).
    pub netflow_rows_skipped_total: Option<u64>,
    /// External audit NET-012: pending connects evicted at capacity.
    pub netflow_pending_evicted_total: Option<u64>,
    /// External audit NET-009: network rules that cannot fire, with why
    /// (`None`: agent predates the field).
    pub net_inactive_rules: Option<Vec<String>>,
    /// Lab PR 164: the kernel's `FLOW_SOCK_MAP` — sockets held without
    /// their close seen, capacity, sockets forgotten at least (`None`:
    /// agent predates the fields, or runs without the counters).
    pub flow_sock_pending: Option<u64>,
    pub flow_sock_capacity: Option<u64>,
    pub flow_sock_forgotten_min: Option<u64>,
    /// External audit CMB-018 (lab PR 193): detect-only, and what set it
    /// (`None`: no response state on the agent).
    pub detect_only: Option<bool>,
    pub detect_only_source: Option<String>,
    /// External audit CMB-027 (lab PR 193): COMBAT stage transitions the
    /// signed audit log did not get when they happened (since boot), the
    /// ones still queued for a late write, the ones dropped (`None`: no
    /// COMBAT ladder on the agent).
    pub combat_evidence_unrecorded: Option<u64>,
    pub combat_evidence_pending: Option<u64>,
    pub combat_evidence_dropped: Option<u64>,
    /// External audit NET-017 (lab PR 207): netflow rows to TCP/853 (DNS
    /// over TLS) since boot, of those the local resolver's, and rows to
    /// UDP/443 (QUIC) (`None`: agent predates the counters).
    pub net_dot_rows_total: Option<u64>,
    pub net_dot_rows_resolver: Option<u64>,
    pub net_quic_rows_total: Option<u64>,
    /// Lab PR 215: operations the anti-tamper deny hooks let through
    /// undecided since boot, and per hook (`None`: not counted by the
    /// agent, or an agent older than the field).
    pub deny_fail_open_total: Option<u64>,
    pub deny_fail_open: Vec<(String, u64)>,
    /// Lab PR 218: the trust level (0..=3) and why it is below L3, every
    /// degradation of this run, the boot's signed capability manifest
    /// (`None`: withheld from the unsigned status, or an agent older than
    /// the fields).
    pub trust_level: Option<u8>,
    pub trust_reasons: Vec<String>,
    pub degradations: Option<Vec<String>>,
    pub capability_manifest: Option<String>,
    /// Lab PR 219: the exploit post-condition guard's mode and counters
    /// (`None`: agent predates it, or the unsigned `status`).
    pub exploit_guard: Option<nn_proto::admin_protocol::ExploitGuardStatus>,
    /// Lab PR 222: the copy-on-first-write guard (`None`: withheld, or an
    /// agent without it).
    pub cow_guard: Option<nn_proto::admin_protocol::CowGuardStatus>,
    /// Lab PR 223 (EXPERIMENTAL): the exec quarantine's state and counts
    /// (`StatusResponse::execq_*`; `None`: withheld, or an agent before
    /// the fields).
    pub execq_state: Option<String>,
    pub execq_held_total: Option<u64>,
    pub execq_resumed_total: Option<u64>,
    pub execq_killed_total: Option<u64>,
    pub execq_quarantined_total: Option<u64>,
    pub execq_defaulted_total: Option<u64>,
    pub execq_known_identity_total: Option<u64>,
    pub execq_known_hash_total: Option<u64>,
    pub execq_not_held_total: Option<u64>,
    pub execq_scanner_deaths_total: Option<u64>,
    /// Lab PR 224 (CM-02): verdicts given at connect, open-flow snapshots
    /// judged and deferred, connects refused by the `socket_connect` deny
    /// (`None`: agent predates the counters; the last one also when the
    /// deny is off).
    pub net_connect_verdicts_total: Option<u64>,
    pub net_flow_snapshots_total: Option<u64>,
    pub net_flow_snapshots_deferred_total: Option<u64>,
    pub net_connect_denied_total: Option<u64>,
    /// Lab PR 225: the ransomware signal and the security tools
    /// (`StatusResponse`'s fields of the same names).
    pub ransomware_decisive_total: Option<u64>,
    pub ransomware_signals_total: Option<u64>,
    pub ransomware_trusted_total: Option<u64>,
    pub ransomware_samplings_total: Option<u64>,
    pub defense_tamper_total: Option<u64>,
    pub defense_tamper_sanctioned_total: Option<u64>,
    pub defense_tools_watched: Option<u64>,
    /// Lab PR 226 (EXPERIMENTAL): the exec policy's state and counts
    /// (`StatusResponse::execpol_*`).
    pub execpol_state: Option<String>,
    pub execpol_denied_total: Option<u64>,
    pub execpol_would_deny_total: Option<u64>,
    pub execpol_quarantine_total: Option<u64>,
    pub execpol_quarantine_inactive_total: Option<u64>,
    pub execpol_env_denied_total: Option<u64>,
    pub execpol_env_recorded_total: Option<u64>,
    pub execpol_map_denied_total: Option<u64>,
    pub execpol_map_recorded_total: Option<u64>,
    pub execq_script_refused_total: Option<u64>,
    /// External audit ASK-009 (lab PR 213): the reply of the signed
    /// telemetry verb (`--key`). `false` for the unsigned `status`, whose
    /// telemetry fields the agent leaves `None` — withheld, not unknown.
    pub telemetry_signed: bool,
}

#[derive(Debug)]
pub struct VerifyKeysOutcome {
    pub fingerprints: Vec<String>,
    /// External audit MAIN-005: each key's roles, as the agent reads them
    /// (parallel to `fingerprints`).
    pub roles: Vec<String>,
    /// `(line number, reason)` of the lines that are not a key — the agent
    /// skips them (external audit AUT-004).
    pub skipped: Vec<(usize, String)>,
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
    // unless --force overrides; if --force, truncate — never through a
    // link, and with the mode reset (external audit AUT-002: an existing
    // 0644 file kept its mode).
    let mut opts = OpenOptions::new();
    opts.write(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    if force {
        opts.create(true).truncate(true);
    } else {
        opts.create_new(true);
    }
    let mut f = opts
        .open(priv_out)
        .with_context(|| format!("writing private key to {}", priv_out.display()))?;
    f.set_permissions(std::fs::Permissions::from_mode(0o600))
        .with_context(|| format!("setting mode 0600 on {}", priv_out.display()))?;
    let priv_hex = zeroize::Zeroizing::new(hex::encode(signing.to_bytes()));
    writeln!(f, "{}", priv_hex.as_str()).context("writing private key bytes")?;
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

/// Full unlock flow: connect, request challenge, sign an
/// `OperationCode::Unlock` payload (the challenge, the time, this install's
/// agent_id — lab PR 217, NN-AUD-243 residue: it was a signature over the
/// bare nonce, which the agent now refuses), submit, return the outcome.
///
/// An agent older than lab PR 217 does not know the signed unlock: it
/// closes the connection, and the error says to use the `nn-admin` of its
/// release.
pub fn run_unlock(socket: &Path, key_path: &Path, agent_id_path: &Path) -> Result<UnlockOutcome> {
    use nn_proto::admin_protocol::SignedUnlockRequest;
    let reply = signed_request(
        socket,
        key_path,
        agent_id_path,
        SignedPayload::new_unlock,
        |payload, signatures| {
            AdminMessage::SignedUnlockRequest(SignedUnlockRequest {
                payload,
                signatures,
            })
        },
    )
    .context(
        "the signed unlock got no reply — an agent older than this nn-admin (before lab PR \
         217) does not know it: unlock it with the nn-admin of its own release",
    )?;
    let r = match reply {
        AdminMessage::SignedUnlockResponse(r) => r,
        other => bail!(
            "unexpected reply to the signed unlock: {other:?} (an agent older than lab PR 217 \
             does not know it: use the nn-admin of its release)"
        ),
    };
    Ok(match r.result {
        AdminResult::Success if r.released => UnlockOutcome::Success {
            message: r.message,
            isolation_v4: r.isolation_v4,
            isolation_v6: r.isolation_v6,
        },
        AdminResult::Success | AdminResult::ActionFailed => UnlockOutcome::ReleaseFailed {
            message: r.message,
            isolation_v4: r.isolation_v4,
            isolation_v6: r.isolation_v6,
        },
        AdminResult::InvalidSignature => UnlockOutcome::InvalidSignature,
        AdminResult::NoPendingChallenge => UnlockOutcome::NoPendingChallenge,
        AdminResult::RateLimited { retry_after_secs } => {
            UnlockOutcome::RateLimited { retry_after_secs }
        }
        AdminResult::RoleDenied => UnlockOutcome::RoleDenied,
        other => UnlockOutcome::Refused(other),
    })
}

/// Status query — round-trip a `StatusRequest`/`StatusResponse`. Since
/// external audit ASK-009 (lab PR 213) the agent answers only the posture,
/// the isolation, the last admin action and the COMBAT stage and lock;
/// [`run_telemetry_status`] reads the rest.
pub fn run_status(socket: &Path) -> Result<StatusOutcome> {
    let mut stream = connect_socket(socket)?;
    write_frame(&mut stream, &AdminMessage::Status(StatusRequest {}))?;
    let resp = match read_frame(&mut stream)? {
        AdminMessage::StatusResponse(s) => s,
        other => bail!("unexpected server reply to StatusRequest: {other:?}"),
    };
    Ok(status_outcome(resp, false))
}

/// External audit ASK-009 (lab PR 213): `nn-admin status --key` /
/// `net status --key` — the signed read of the whole status, telemetry
/// included (`audit-read` or `telemetry-read`, 1-of-N). `Ok(Err(result))`
/// when the agent refused the request.
pub fn run_telemetry_status(
    socket: &Path,
    key_path: &Path,
    agent_id_path: &Path,
) -> Result<std::result::Result<StatusOutcome, AdminResult>> {
    use nn_proto::admin_protocol::TelemetryStatusRequest;
    match signed_request(
        socket,
        key_path,
        agent_id_path,
        SignedPayload::new_telemetry_status,
        |payload, signatures| {
            AdminMessage::TelemetryStatusRequest(TelemetryStatusRequest {
                payload,
                signatures,
            })
        },
    )? {
        AdminMessage::TelemetryStatusResponse(r) => match (r.result, r.status) {
            (AdminResult::Success, Some(status)) => Ok(Ok(status_outcome(status, true))),
            (AdminResult::Success, None) => {
                bail!("the agent accepted the telemetry request but sent no status")
            }
            (refused, _) => Ok(Err(refused)),
        },
        // An agent older than the verb cannot decode it: it closes the
        // connection, or answers with a sentinel.
        other => bail!(
            "unexpected reply to TelemetryStatusRequest: {other:?} (an agent older than \
             lab PR 213 has no signed telemetry verb: run `status` without --key)"
        ),
    }
}

/// A status reply as the CLI prints it; `signed` says which verb it came
/// from.
fn status_outcome(resp: nn_proto::admin_protocol::StatusResponse, signed: bool) -> StatusOutcome {
    StatusOutcome {
        posture: resp.posture,
        network_isolation_engaged: resp.network_isolation_engaged,
        network_isolation_v4: resp.network_isolation_v4,
        network_isolation_v6: resp.network_isolation_v6,
        last_admin_action_secs_ago: resp.last_admin_action_secs_ago,
        ringbuf_drops_total: resp.ringbuf_drops_total,
        ringbuf_drops: resp.ringbuf_drops.unwrap_or_default(),
        combat_stage: resp.combat_stage,
        combat_locked: resp.combat_locked,
        ringbuf_rejected_total: resp.ringbuf_rejected_total,
        ringbuf_rejected: resp.ringbuf_rejected.unwrap_or_default(),
        netflow_rows_skipped_total: resp.netflow_rows_skipped_total,
        netflow_pending_evicted_total: resp.netflow_pending_evicted_total,
        net_inactive_rules: resp.net_inactive_rules,
        flow_sock_pending: resp.flow_sock_pending,
        flow_sock_capacity: resp.flow_sock_capacity,
        flow_sock_forgotten_min: resp.flow_sock_forgotten_min,
        detect_only: resp.detect_only,
        detect_only_source: resp.detect_only_source,
        combat_evidence_unrecorded: resp.combat_evidence_unrecorded,
        combat_evidence_pending: resp.combat_evidence_pending,
        combat_evidence_dropped: resp.combat_evidence_dropped,
        net_dot_rows_total: resp.net_dot_rows_total,
        net_dot_rows_resolver: resp.net_dot_rows_resolver,
        net_quic_rows_total: resp.net_quic_rows_total,
        deny_fail_open_total: resp.deny_fail_open_total,
        deny_fail_open: resp.deny_fail_open.unwrap_or_default(),
        trust_level: resp.trust_level,
        trust_reasons: resp.trust_reasons.unwrap_or_default(),
        degradations: resp.degradations,
        capability_manifest: resp.capability_manifest,
        exploit_guard: resp.exploit_guard,
        cow_guard: resp.cow_guard,
        execq_state: resp.execq_state,
        execq_held_total: resp.execq_held_total,
        execq_resumed_total: resp.execq_resumed_total,
        execq_killed_total: resp.execq_killed_total,
        execq_quarantined_total: resp.execq_quarantined_total,
        execq_defaulted_total: resp.execq_defaulted_total,
        execq_known_identity_total: resp.execq_known_identity_total,
        execq_known_hash_total: resp.execq_known_hash_total,
        execq_not_held_total: resp.execq_not_held_total,
        execq_scanner_deaths_total: resp.execq_scanner_deaths_total,
        net_connect_verdicts_total: resp.net_connect_verdicts_total,
        net_flow_snapshots_total: resp.net_flow_snapshots_total,
        net_flow_snapshots_deferred_total: resp.net_flow_snapshots_deferred_total,
        net_connect_denied_total: resp.net_connect_denied_total,
        ransomware_decisive_total: resp.ransomware_decisive_total,
        ransomware_signals_total: resp.ransomware_signals_total,
        ransomware_trusted_total: resp.ransomware_trusted_total,
        ransomware_samplings_total: resp.ransomware_samplings_total,
        defense_tamper_total: resp.defense_tamper_total,
        defense_tamper_sanctioned_total: resp.defense_tamper_sanctioned_total,
        defense_tools_watched: resp.defense_tools_watched,
        execpol_state: resp.execpol_state,
        execpol_denied_total: resp.execpol_denied_total,
        execpol_would_deny_total: resp.execpol_would_deny_total,
        execpol_quarantine_total: resp.execpol_quarantine_total,
        execpol_quarantine_inactive_total: resp.execpol_quarantine_inactive_total,
        execpol_env_denied_total: resp.execpol_env_denied_total,
        execpol_env_recorded_total: resp.execpol_env_recorded_total,
        execpol_map_denied_total: resp.execpol_map_denied_total,
        execpol_map_recorded_total: resp.execpol_map_recorded_total,
        execq_script_refused_total: resp.execq_script_refused_total,
        telemetry_signed: signed,
    }
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
        bail!("grace_secs {grace_secs} exceeds design §10.2 cap of {MAX_GRACE_SECS}");
    }

    // Read both keys + the agent_id BEFORE opening the socket so a
    // typo'd path fails fast instead of holding the agent's
    // dispatcher connection while we error.
    let signing_a = read_priv_key(key_path)?;
    let signing_b = read_priv_key(cosign_key_path)?;
    let agent_id_arr = agent_id::load_existing(agent_id_path).with_context(|| {
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

    let payload = SignedPayload::new_shutdown(nonce, now, agent_id_arr, grace_secs);
    let sig_a: [u8; 64] =
        sign(&payload, &signing_a).map_err(|e| anyhow!("signing payload with primary key: {e}"))?;
    let sig_b: [u8; 64] =
        sign(&payload, &signing_b).map_err(|e| anyhow!("signing payload with cosign key: {e}"))?;

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
        // Lab PR 217: no reply of this operation; out of spec.
        AdminResult::ActionFailed => ShutdownOutcome::UnknownOperation,
    })
}

/// Tappa 8 A10 — full signed-production-force-posture CLI flow.
///
/// Wire path (design §4 + §12.2): challenge → sign → submit →
/// parse. Single signature (1-of-N quorum per §3.3). Required
/// admin.pub role: `force-posture` (parsed by A5's allowlist).
///
/// Allowed transitions: any → any, except that leaving COMBAT also
/// needs the `unlock` role on the signing key (external audit
/// NN-AUD-083; otherwise `RoleDenied`). The
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
    let agent_id_arr = agent_id::load_existing(agent_id_path).with_context(|| {
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

    let payload = SignedPayload::new_force_posture(nonce, now, agent_id_arr, target);
    let sig: [u8; 64] =
        sign(&payload, &signing).map_err(|e| anyhow!("signing force-posture payload: {e}"))?;

    write_frame(
        &mut stream,
        &AdminMessage::ForcePostureRequest(ForcePostureRequest {
            payload,
            signatures: vec![KeyedSignature { signature: sig }],
        }),
    )?;

    let result = match read_frame(&mut stream)? {
        AdminMessage::ForcePostureResult(r) => r,
        other => bail!("unexpected server reply to ForcePostureRequest: {other:?}"),
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
        AdminResult::ActionFailed => ForcePostureOutcome::ActionFailed,
    })
}

/// Local-only: parse `path` and report fingerprints. No socket
/// involved.
pub fn run_verify_keys(path: &Path) -> Result<VerifyKeysOutcome> {
    let content =
        std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    // External audit MAIN-005: the agent's own parser — a key line may carry
    // its role list (`<hex> unlock,audit-read`, as install.sh writes it),
    // which a check for exactly 64 characters refused.
    let parsed = nn_proto::admin_quorum::parse_admin_pub_lenient(&content);
    let fingerprints = parsed
        .keys
        .iter()
        .map(|k| pubkey_fingerprint(&k.key))
        .collect();
    let roles = parsed
        .keys
        .iter()
        .map(|k| {
            k.roles
                .iter()
                .map(|r| nn_proto::admin_quorum::role_keyword(*r))
                .collect::<Vec<_>>()
                .join(",")
        })
        .collect();
    Ok(VerifyKeysOutcome {
        fingerprints,
        roles,
        skipped: parsed.skipped,
    })
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
/// Two keys are required — distinct fingerprints, at least one
/// carrying `Role::RotateKeys`; the other may be any installed key
/// (design §3.3, external audit AUT-007). Same wire flow as `run_shutdown`: read
/// keys, get nonce, build SignedPayload, sign with both,
/// transmit.
pub fn run_rotate_keys_add(
    socket: &Path,
    key_path: &Path,
    cosign_key_path: &Path,
    agent_id_path: &Path,
    new_pubkey_hex: &str,
    roles: &[nn_proto::admin_signed_payload::Role],
) -> Result<RotateKeysOutcome> {
    let new_pubkey_bytes = parse_pubkey_hex(new_pubkey_hex)?;

    let signing_a = read_priv_key(key_path)?;
    let signing_b = read_priv_key(cosign_key_path)?;
    let agent_id_arr = agent_id::load_existing(agent_id_path)?;
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
        &AdminMessage::RotateKeysAddRequest(nn_proto::admin_protocol::RotateKeysAddRequest {
            payload,
            signatures: vec![
                KeyedSignature { signature: sig_a },
                KeyedSignature { signature: sig_b },
            ],
        }),
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
    let agent_id_arr = agent_id::load_existing(agent_id_path)?;
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

    let payload = SignedPayload::new_rotate_keys_revoke(nonce, now, agent_id_arr, target_fp);
    let sig_a: [u8; 64] =
        sign(&payload, &signing_a).map_err(|e| anyhow!("signing payload with primary key: {e}"))?;
    let sig_b: [u8; 64] =
        sign(&payload, &signing_b).map_err(|e| anyhow!("signing payload with cosign key: {e}"))?;

    write_frame(
        &mut stream,
        &AdminMessage::RotateKeysRevokeRequest(nn_proto::admin_protocol::RotateKeysRevokeRequest {
            payload,
            signatures: vec![
                KeyedSignature { signature: sig_a },
                KeyedSignature { signature: sig_b },
            ],
        }),
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
    let bytes = hex::decode(trimmed).map_err(|e| anyhow!("--new-pubkey is not valid hex: {e}"))?;
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
    let bytes = hex::decode(trimmed).map_err(|e| anyhow!("--fingerprint is not valid hex: {e}"))?;
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
        // Lab PR 217: no reply of this operation; out of spec.
        AdminResult::ActionFailed => RotateKeysOutcome::UnknownOperation,
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
    /// External audit NN-AUD-108: the chain verifies but does not reach a
    /// head recorded earlier (`--expect-head`, `--min-seq`): rows were cut
    /// from its end. Exit code 8.
    HeadNotReached(String),
}

/// External audit NN-AUD-108: what `audit verify` must still find — a head
/// taken earlier from the journal (`chain.head` lines) or an off-host copy.
#[derive(Debug, Clone, Default)]
pub struct ExpectedHead {
    /// An `entry_hash` that must still be in the chain.
    pub entry_hash: Option<String>,
    /// The chain must hold a row numbered at least this.
    pub min_seq: Option<u64>,
}

/// What `nn-admin audit read` read.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct AuditReadReport {
    /// Rows written to stdout (those `since` kept).
    pub rows: usize,
    /// Lines that are not audit rows, skipped; each is named on stderr. Any
    /// is exit 8: the file is not an intact chain.
    pub skipped: usize,
}

/// Skipped lines named one by one on stderr; past this only the count.
pub const AUDIT_READ_SKIPS_LISTED: usize = 100;

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
/// External audit MAIN-014 (NN-AUD-256, lab PR 190): a line that is not an
/// audit row (cut, not JSON, not UTF-8, over
/// [`crate::verify_lines::MAX_VERIFY_LINE_BYTES`]) stopped the read with an
/// error, and every row after it went unseen. It is skipped, named on stderr
/// with its number (the first [`AUDIT_READ_SKIPS_LISTED`]), and counted in
/// [`AuditReadReport::skipped`]; the read goes on to the end of the file,
/// one bounded line in memory at a time. The rows are not verified here
/// (`audit verify` does that).
pub fn run_audit_read(log_path: &Path, since: Option<&str>, json: bool) -> Result<AuditReadReport> {
    let stdout = std::io::stdout();
    let stderr = std::io::stderr();
    audit_read_into(
        log_path,
        since,
        json,
        &mut stdout.lock(),
        &mut stderr.lock(),
    )
}

/// [`run_audit_read`] into `out` (the rows) and `err` (the skipped lines).
pub fn audit_read_into(
    log_path: &Path,
    since: Option<&str>,
    json: bool,
    out: &mut dyn std::io::Write,
    err: &mut dyn std::io::Write,
) -> Result<AuditReadReport> {
    let mut report = AuditReadReport::default();
    let f = match std::fs::OpenOptions::new().read(true).open(log_path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            // Empty/absent log is a valid state (fresh install,
            // no admin ops yet). Print nothing, return 0 — the
            // binary's summary line communicates the count.
            return Ok(report);
        }
        Err(e) => return Err(anyhow!(e).context(format!("opening {}", log_path.display()))),
    };
    let mut lines = crate::verify_lines::VerifyLines::new(std::io::BufReader::new(f));
    loop {
        let at = lines.offset();
        let line = lines
            .next_line()
            .with_context(|| format!("reading {} after byte {at}", log_path.display()))?;
        let Some(line) = line else {
            break;
        };
        if line.is_empty() {
            continue;
        }
        let entry = line.text().and_then(|t| {
            serde_json::from_str::<crate::audit::AuditEntry>(t).map_err(|e| {
                if line.newline {
                    format!("not an audit row: {e}")
                } else {
                    format!("the last line, cut short (no newline): {e}")
                }
            })
        });
        let entry = match entry {
            Ok(entry) => entry,
            Err(reason) => {
                report.skipped += 1;
                if report.skipped <= AUDIT_READ_SKIPS_LISTED {
                    writeln!(
                        err,
                        "audit: line {} of {} skipped: {reason}",
                        line.number,
                        log_path.display()
                    )
                    .context("writing stderr")?;
                }
                continue;
            }
        };
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
        report.rows += 1;
    }
    Ok(report)
}

/// `nn-admin audit verify` — replay the chain in `from_path`
/// through [`crate::audit::verify_chain_file`] using `pubkey`.
/// Returns [`AuditVerifyOutcome::Success`] with the entry count
/// or [`AuditVerifyOutcome::ChainBroken`] carrying the typed
/// failure.
///
/// An empty / missing file is `Success { entries: 0 }` — there's
/// nothing to verify and that is not an error condition; the
/// exit-8 contract per §5.3 is reserved for an *actually-broken*
/// chain.
pub fn run_audit_verify(from_path: &Path, pubkey: &VerifyingKey) -> Result<AuditVerifyOutcome> {
    run_audit_verify_expecting(from_path, pubkey, &ExpectedHead::default())
}

/// [`run_audit_verify`], then the chain must still reach `expect`.
///
/// External audit MAIN-014 (NN-AUD-256, lab PR 190): one streaming pass
/// ([`crate::audit::ChainVerifier`]) with the expected-head checks folded
/// in. Every row was kept in memory, and the file was read a second time
/// whole for `expect`; a line that is not a row was an error (exit 1), and
/// is now [`AuditVerifyOutcome::ChainBroken`] with
/// [`crate::audit::AuditVerifyError::UnreadableLine`] (exit 8).
pub fn run_audit_verify_expecting(
    from_path: &Path,
    pubkey: &VerifyingKey,
    expect: &ExpectedHead,
) -> Result<AuditVerifyOutcome> {
    let report = crate::audit::verify_chain_file(from_path, pubkey, expect.entry_hash.as_deref())
        .with_context(|| format!("reading {}", from_path.display()))?;
    if let Some(e) = report.broken {
        return Ok(AuditVerifyOutcome::ChainBroken(e));
    }
    if let Some(h) = &expect.entry_hash {
        if !report.head_seen {
            return Ok(AuditVerifyOutcome::HeadNotReached(format!(
                "no entry has entry_hash {h}: the chain ends before that head"
            )));
        }
    }
    if let Some(min) = expect.min_seq {
        let last = report.last_seq;
        if last.is_none_or(|s| s < min) {
            return Ok(AuditVerifyOutcome::HeadNotReached(format!(
                "the last numbered row is {last:?}, below the expected {min}: rows were cut"
            )));
        }
    }
    Ok(AuditVerifyOutcome::Success {
        entries: report.rows,
    })
}

/// One chain's result in `nn-admin chain verify`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChainVerifyLine {
    /// `audit`, `detections`, … or `heads` for the anchor comparison.
    pub chain: String,
    pub file: String,
    pub ok: bool,
    pub detail: String,
}

/// External audit NN-AUD-112: `nn-admin chain verify` — every chain in
/// full (the rotating logs with [`nn_evidence::chainlog::verify_log_set`],
/// archives, manifest and checkpoints included; the flat chains with their
/// row numbers), then the files against the head anchor `heads` when it
/// exists. `only`: chain names to check (empty: all). `paths`: the agent's
/// chains, through its host (R10, lab PR 259: [`Chains`]).
pub fn run_chain_verify<C: Chains>(
    paths: &C,
    heads: &Path,
    only: &[String],
    pubkey: &VerifyingKey,
) -> Vec<ChainVerifyLine> {
    let targets: Vec<_> = paths
        .targets()
        .into_iter()
        .filter(|t| only.is_empty() || only.iter().any(|o| o == t.chain))
        .collect();
    let mut out: Vec<ChainVerifyLine> = targets
        .iter()
        .map(|t| {
            let r = (t.full)(&t.path, pubkey);
            ChainVerifyLine {
                chain: t.chain.to_string(),
                file: t.path.display().to_string(),
                ok: r.is_ok(),
                detail: r.unwrap_or_else(|e| e),
            }
        })
        .collect();
    let check = paths.boot_check(&targets, heads, pubkey);
    for f in &check.findings {
        out.push(ChainVerifyLine {
            chain: f.chain.clone(),
            file: f.file.display().to_string(),
            ok: false,
            detail: format!("{}: {}", f.kind, f.detail),
        });
    }
    let anchored = match &check.previous {
        Some(s) => format!(
            "{} head(s) anchored at {}, all reached",
            s.heads.len(),
            s.ts
        ),
        None => "no head anchor to compare with".to_string(),
    };
    if check.findings.is_empty() {
        out.push(ChainVerifyLine {
            chain: "heads".to_string(),
            file: heads.display().to_string(),
            ok: true,
            detail: anchored,
        });
    }
    out
}

/// Load an agent verifying key for `audit verify`. Prefers an
/// explicit `--agent-pubkey <hex>` (32 bytes / 64 hex chars,
/// optionally trailing newline) when present; otherwise reads
/// the local signing-key file at `key_path` and derives the
/// public half. The latter is the zero-config path on the
/// agent host (operator runs `sudo nn-admin audit verify
/// --from /etc/northnarrow/audit.log`); the former is the
/// off-host path (auditor receives the pubkey hex via an
/// out-of-band channel). The key's files are the agent's, read through its
/// host (R10, lab PR 259: [`AdminHost`]).
pub fn load_audit_pubkey<H: AdminHost>(
    host: &H,
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
        let bytes =
            hex::decode(trimmed).map_err(|e| anyhow!("--agent-pubkey is not valid hex: {e}"))?;
        let arr: [u8; 32] = bytes.try_into().expect("hex pre-validated to 32 bytes");
        return VerifyingKey::from_bytes(&arr)
            .map_err(|e| anyhow!("--agent-pubkey is not a valid Ed25519 pubkey: {e}"));
    }
    // External audit EVD-001: the public half the agent publishes; the
    // private key is closed to every reader outside the agent's family.
    // A host from before it has only the key: parsed, never minted (a
    // verifier must not create the key it checks against).
    let pub_path = host.verifying_key_path(key_path);
    if pub_path.exists() {
        return host.read_verifying_key(&pub_path);
    }
    let key = host
        .verifying_key_of_signing_key(key_path)
        .with_context(|| {
            format!(
                "no {} — deriving the agent pubkey from the signing key file {} (refused \
             once the agent protects it); pass --agent-pubkey <hex> when verifying off-host",
                pub_path.display(),
                key_path.display()
            )
        })?;
    Ok(key)
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
    RateLimited {
        retry_after_secs: u32,
    },
    RoleDenied,
    TimestampSkew {
        server_ts: u64,
        max_skew_secs: u32,
    },
    AgentIdMismatch,
    UnknownOperation,
    ProtocolVersionUnsupported {
        server_version: u16,
    },
    Transport,
}

fn map_admin_result_to_baseline(r: nn_proto::admin_protocol::AdminResult) -> FimBaselineOutcome {
    use nn_proto::admin_protocol::AdminResult;
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
        // Lab PR 217: no reply of this operation; out of spec.
        AdminResult::ActionFailed => FimBaselineOutcome::UnknownOperation,
    }
}

fn map_response_to_fim_report(
    resp: nn_proto::admin_protocol::FimReportResponse,
) -> FimReportOutcome {
    use nn_proto::admin_protocol::AdminResult;
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
        // Lab PR 217: no reply of this operation; out of spec.
        AdminResult::ActionFailed => FimReportOutcome::Transport,
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
    use nn_proto::admin_protocol::FimBaselineRequest;

    let signing = read_priv_key(key_path)?;
    let agent_id_arr = agent_id::load_existing(agent_id_path)?;
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
    let sig: [u8; 64] =
        sign(&payload, &signing).map_err(|e| anyhow!("signing fim-baseline payload: {e}"))?;

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

/// Outcome of `nn-admin fim status`. Success carries the live
/// in-process snapshot fields the CLI renders to the operator.
#[derive(Debug)]
pub enum FimStatusOutcome {
    Success {
        watched_paths_count: u32,
        disabled_default_count: u32,
        added_path_count: u32,
        last_baseline_ts: String,
        baseline_entries_total: u32,
        drift_entries_total: u32,
        high_remaining: u32,
        high_cap_per_min: u32,
        medium_remaining: u32,
        medium_cap_per_min: u32,
        bucket_window_resets_in_secs: u32,
    },
    InvalidSignature,
    NoPendingChallenge,
    RateLimited {
        retry_after_secs: u32,
    },
    RoleDenied,
    TimestampSkew {
        server_ts: u64,
        max_skew_secs: u32,
    },
    AgentIdMismatch,
    UnknownOperation,
    ProtocolVersionUnsupported {
        server_version: u16,
    },
    Transport,
}

fn map_response_to_fim_status(
    resp: nn_proto::admin_protocol::FimStatusResponse,
) -> FimStatusOutcome {
    use nn_proto::admin_protocol::AdminResult;
    match resp.result {
        AdminResult::Success => FimStatusOutcome::Success {
            watched_paths_count: resp.watched_paths_count,
            disabled_default_count: resp.disabled_default_count,
            added_path_count: resp.added_path_count,
            last_baseline_ts: resp.last_baseline_ts,
            baseline_entries_total: resp.baseline_entries_total,
            drift_entries_total: resp.drift_entries_total,
            high_remaining: resp.high_remaining,
            high_cap_per_min: resp.high_cap_per_min,
            medium_remaining: resp.medium_remaining,
            medium_cap_per_min: resp.medium_cap_per_min,
            bucket_window_resets_in_secs: resp.bucket_window_resets_in_secs,
        },
        AdminResult::InvalidSignature => FimStatusOutcome::InvalidSignature,
        AdminResult::NoPendingChallenge => FimStatusOutcome::NoPendingChallenge,
        AdminResult::RateLimited { retry_after_secs } => {
            FimStatusOutcome::RateLimited { retry_after_secs }
        }
        AdminResult::RoleDenied => FimStatusOutcome::RoleDenied,
        AdminResult::TimestampSkew {
            server_ts,
            max_skew_secs,
        } => FimStatusOutcome::TimestampSkew {
            server_ts,
            max_skew_secs,
        },
        AdminResult::AgentIdMismatch => FimStatusOutcome::AgentIdMismatch,
        AdminResult::QuorumNotMet { .. } => FimStatusOutcome::InvalidSignature,
        AdminResult::UnknownOperation => FimStatusOutcome::UnknownOperation,
        AdminResult::ProtocolVersionUnsupported { server_version } => {
            FimStatusOutcome::ProtocolVersionUnsupported { server_version }
        }
        // Lab PR 217: no reply of this operation; out of spec.
        AdminResult::ActionFailed => FimStatusOutcome::Transport,
    }
}

/// `nn-admin fim status` — submit a 1-of-N quorum-signed
/// request and pretty-print the in-process snapshot
/// (token-bucket counts, watched-paths summary, last baseline ts,
/// chain entry totals). Read-only — no on-disk side effects.
pub fn run_fim_status(
    socket: &Path,
    key_path: &Path,
    agent_id_path: &Path,
) -> Result<FimStatusOutcome> {
    use nn_proto::admin_protocol::FimStatusRequest;

    let signing = read_priv_key(key_path)?;
    let agent_id_arr = agent_id::load_existing(agent_id_path)?;
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
    let payload = SignedPayload::new_fim_status(nonce, now, agent_id_arr);
    let sig: [u8; 64] =
        sign(&payload, &signing).map_err(|e| anyhow!("signing fim-status payload: {e}"))?;

    write_frame(
        &mut stream,
        &AdminMessage::FimStatusRequest(FimStatusRequest {
            payload,
            signatures: vec![KeyedSignature { signature: sig }],
        }),
    )?;
    let reply = read_frame(&mut stream)?;
    match reply {
        AdminMessage::FimStatusResponse(resp) => Ok(map_response_to_fim_status(resp)),
        other => Ok({
            let _ = other;
            FimStatusOutcome::Transport
        }),
    }
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
    use nn_proto::admin_protocol::FimReportRequest;

    let signing = read_priv_key(key_path)?;
    let agent_id_arr = agent_id::load_existing(agent_id_path)?;
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
    let sig: [u8; 64] =
        sign(&payload, &signing).map_err(|e| anyhow!("signing fim-report payload: {e}"))?;

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

// ── Tappa 9.5 K6 — nn-admin canary deploy/list/burn/refresh ─────

/// Operator-facing deployment input for `nn-admin canary deploy`.
/// Mirrors the on-wire [`CanaryDeploymentWire`] variants but uses
/// owned strings + a flat shape so the clap layer can build it
/// without reaching into common.
#[derive(Debug, Clone)]
pub enum CanaryDeploySpec {
    File { path: String },
    Process { path: String, fake_arg0: String },
    Network { bind_addr: String, bind_port: u16 },
    Credential { path: String, cred_family: String },
}

impl CanaryDeploySpec {
    fn to_wire(&self) -> (CanaryTypeWire, CanaryDeploymentWire) {
        match self {
            CanaryDeploySpec::File { path } => (
                CanaryTypeWire::File,
                CanaryDeploymentWire::File {
                    path: path.clone(),
                    template: None,
                },
            ),
            CanaryDeploySpec::Process { path, fake_arg0 } => (
                CanaryTypeWire::Process,
                CanaryDeploymentWire::Process {
                    path: path.clone(),
                    fake_arg0: fake_arg0.clone(),
                },
            ),
            CanaryDeploySpec::Network {
                bind_addr,
                bind_port,
            } => (
                CanaryTypeWire::Network,
                CanaryDeploymentWire::Network {
                    bind_addr: bind_addr.clone(),
                    bind_port: *bind_port,
                },
            ),
            CanaryDeploySpec::Credential { path, cred_family } => (
                CanaryTypeWire::Credential,
                CanaryDeploymentWire::Credential {
                    path: path.clone(),
                    cred_family: cred_family.clone(),
                },
            ),
        }
    }
}

/// Outcome of `nn-admin canary deploy` (K6 — auth via
/// `Role::CanaryManage`, single-sig 1-of-N quorum per §12 Q7).
/// Success carries the per-canary stable id the server allocated.
#[derive(Debug)]
pub enum CanaryDeployOutcome {
    Success { canary_id: String },
    InvalidSignature,
    NoPendingChallenge,
    RateLimited { retry_after_secs: u32 },
    QuorumNotMet { required: u8, provided: u8 },
    RoleDenied,
    TimestampSkew { server_ts: u64, max_skew_secs: u32 },
    AgentIdMismatch,
    UnknownOperation,
    ProtocolVersionUnsupported { server_version: u16 },
    Transport,
}

/// Outcome of `nn-admin canary list` (read-only — auth via
/// `Role::CanaryRead`, single-sig 1-of-N quorum). Success carries
/// the chained registry JSONL body (capped at half MAX_FRAME_BODY;
/// `entries_truncated` flips when the cap fires).
#[derive(Debug)]
pub enum CanaryListOutcome {
    Success {
        entries_jsonl: String,
        entries_count: u32,
        entries_truncated: bool,
    },
    InvalidSignature,
    NoPendingChallenge,
    RateLimited {
        retry_after_secs: u32,
    },
    RoleDenied,
    TimestampSkew {
        server_ts: u64,
        max_skew_secs: u32,
    },
    AgentIdMismatch,
    UnknownOperation,
    ProtocolVersionUnsupported {
        server_version: u16,
    },
    Transport,
}

/// Outcome of `nn-admin canary burn` (auth via
/// `Role::CanaryManage`). No body — server replies with
/// [`AdminResult`] inside `CanaryBurnResult`.
#[derive(Debug)]
pub enum CanaryBurnOutcome {
    Success,
    InvalidSignature,
    NoPendingChallenge,
    RateLimited { retry_after_secs: u32 },
    QuorumNotMet { required: u8, provided: u8 },
    RoleDenied,
    TimestampSkew { server_ts: u64, max_skew_secs: u32 },
    AgentIdMismatch,
    UnknownOperation,
    NotFound,
    ProtocolVersionUnsupported { server_version: u16 },
    Transport,
}

/// Outcome of `nn-admin canary refresh` (auth via
/// `Role::CanaryManage`). Same shape as
/// [`CanaryBurnOutcome`].
#[derive(Debug)]
pub enum CanaryRefreshOutcome {
    Success,
    InvalidSignature,
    NoPendingChallenge,
    RateLimited { retry_after_secs: u32 },
    QuorumNotMet { required: u8, provided: u8 },
    RoleDenied,
    TimestampSkew { server_ts: u64, max_skew_secs: u32 },
    AgentIdMismatch,
    UnknownOperation,
    NotFound,
    ProtocolVersionUnsupported { server_version: u16 },
    Transport,
}

fn map_response_to_canary_deploy(
    resp: nn_proto::admin_protocol::CanaryDeployResponse,
) -> CanaryDeployOutcome {
    match resp.result {
        AdminResult::Success => CanaryDeployOutcome::Success {
            canary_id: resp.canary_id,
        },
        AdminResult::InvalidSignature => CanaryDeployOutcome::InvalidSignature,
        AdminResult::NoPendingChallenge => CanaryDeployOutcome::NoPendingChallenge,
        AdminResult::RateLimited { retry_after_secs } => {
            CanaryDeployOutcome::RateLimited { retry_after_secs }
        }
        AdminResult::QuorumNotMet { required, provided } => {
            CanaryDeployOutcome::QuorumNotMet { required, provided }
        }
        AdminResult::RoleDenied => CanaryDeployOutcome::RoleDenied,
        AdminResult::TimestampSkew {
            server_ts,
            max_skew_secs,
        } => CanaryDeployOutcome::TimestampSkew {
            server_ts,
            max_skew_secs,
        },
        AdminResult::AgentIdMismatch => CanaryDeployOutcome::AgentIdMismatch,
        AdminResult::UnknownOperation => CanaryDeployOutcome::UnknownOperation,
        AdminResult::ProtocolVersionUnsupported { server_version } => {
            CanaryDeployOutcome::ProtocolVersionUnsupported { server_version }
        }
        // Lab PR 217: no reply of this operation; out of spec.
        AdminResult::ActionFailed => CanaryDeployOutcome::Transport,
    }
}

fn map_response_to_canary_list(
    resp: nn_proto::admin_protocol::CanaryListResponse,
) -> CanaryListOutcome {
    match resp.result {
        AdminResult::Success => CanaryListOutcome::Success {
            entries_jsonl: resp.entries_jsonl,
            entries_count: resp.entries_count,
            entries_truncated: resp.entries_truncated,
        },
        AdminResult::InvalidSignature => CanaryListOutcome::InvalidSignature,
        AdminResult::NoPendingChallenge => CanaryListOutcome::NoPendingChallenge,
        AdminResult::RateLimited { retry_after_secs } => {
            CanaryListOutcome::RateLimited { retry_after_secs }
        }
        AdminResult::RoleDenied => CanaryListOutcome::RoleDenied,
        AdminResult::TimestampSkew {
            server_ts,
            max_skew_secs,
        } => CanaryListOutcome::TimestampSkew {
            server_ts,
            max_skew_secs,
        },
        AdminResult::AgentIdMismatch => CanaryListOutcome::AgentIdMismatch,
        AdminResult::QuorumNotMet { .. } => CanaryListOutcome::InvalidSignature,
        AdminResult::UnknownOperation => CanaryListOutcome::UnknownOperation,
        AdminResult::ProtocolVersionUnsupported { server_version } => {
            CanaryListOutcome::ProtocolVersionUnsupported { server_version }
        }
        // Lab PR 217: no reply of this operation; out of spec.
        AdminResult::ActionFailed => CanaryListOutcome::Transport,
    }
}

fn map_admin_result_to_canary_burn(r: AdminResult) -> CanaryBurnOutcome {
    match r {
        AdminResult::Success => CanaryBurnOutcome::Success,
        AdminResult::InvalidSignature => CanaryBurnOutcome::InvalidSignature,
        AdminResult::NoPendingChallenge => CanaryBurnOutcome::NoPendingChallenge,
        AdminResult::RateLimited { retry_after_secs } => {
            CanaryBurnOutcome::RateLimited { retry_after_secs }
        }
        AdminResult::QuorumNotMet { required, provided } => {
            CanaryBurnOutcome::QuorumNotMet { required, provided }
        }
        AdminResult::RoleDenied => CanaryBurnOutcome::RoleDenied,
        AdminResult::TimestampSkew {
            server_ts,
            max_skew_secs,
        } => CanaryBurnOutcome::TimestampSkew {
            server_ts,
            max_skew_secs,
        },
        AdminResult::AgentIdMismatch => CanaryBurnOutcome::AgentIdMismatch,
        // K6: the server folds RegistryError::CanaryIdNotFound into
        // AdminResult::UnknownOperation so V1.0 doesn't need a
        // dedicated wire variant. The CLI translates that back into
        // a dedicated NotFound outcome so the operator gets the
        // right hint ("no canary with that id; check `canary list`").
        AdminResult::UnknownOperation => CanaryBurnOutcome::NotFound,
        AdminResult::ProtocolVersionUnsupported { server_version } => {
            CanaryBurnOutcome::ProtocolVersionUnsupported { server_version }
        }
        // Lab PR 217: no reply of this operation; out of spec.
        AdminResult::ActionFailed => CanaryBurnOutcome::Transport,
    }
}

fn map_admin_result_to_canary_refresh(r: AdminResult) -> CanaryRefreshOutcome {
    match r {
        AdminResult::Success => CanaryRefreshOutcome::Success,
        AdminResult::InvalidSignature => CanaryRefreshOutcome::InvalidSignature,
        AdminResult::NoPendingChallenge => CanaryRefreshOutcome::NoPendingChallenge,
        AdminResult::RateLimited { retry_after_secs } => {
            CanaryRefreshOutcome::RateLimited { retry_after_secs }
        }
        AdminResult::QuorumNotMet { required, provided } => {
            CanaryRefreshOutcome::QuorumNotMet { required, provided }
        }
        AdminResult::RoleDenied => CanaryRefreshOutcome::RoleDenied,
        AdminResult::TimestampSkew {
            server_ts,
            max_skew_secs,
        } => CanaryRefreshOutcome::TimestampSkew {
            server_ts,
            max_skew_secs,
        },
        AdminResult::AgentIdMismatch => CanaryRefreshOutcome::AgentIdMismatch,
        AdminResult::UnknownOperation => CanaryRefreshOutcome::NotFound,
        AdminResult::ProtocolVersionUnsupported { server_version } => {
            CanaryRefreshOutcome::ProtocolVersionUnsupported { server_version }
        }
        // Lab PR 217: no reply of this operation; out of spec.
        AdminResult::ActionFailed => CanaryRefreshOutcome::Transport,
    }
}

/// `nn-admin canary deploy` — quorum-signed (`Role::CanaryManage`)
/// op to install a new canary token. The agent renders the
/// template (for File/Credential), writes the on-disk artefact,
/// persists the registry row, rebuilds K3 indexes, and emits an
/// audit row. Returns the per-canary stable id on success.
pub fn run_canary_deploy(
    socket: &Path,
    key_path: &Path,
    agent_id_path: &Path,
    name: String,
    spec: CanaryDeploySpec,
) -> Result<CanaryDeployOutcome> {
    let signing = read_priv_key(key_path)?;
    let agent_id_arr = agent_id::load_existing(agent_id_path)?;
    const _: () = assert!(AGENT_ID_LEN == 16);

    let (canary_type, deployment) = spec.to_wire();

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
        SignedPayload::new_canary_deploy(nonce, now, agent_id_arr, name, canary_type, deployment);
    let sig: [u8; 64] =
        sign(&payload, &signing).map_err(|e| anyhow!("signing canary-deploy payload: {e}"))?;

    write_frame(
        &mut stream,
        &AdminMessage::CanaryDeployRequest(CanaryDeployRequest {
            payload,
            signatures: vec![KeyedSignature { signature: sig }],
        }),
    )?;
    match read_frame(&mut stream)? {
        AdminMessage::CanaryDeployResponse(resp) => Ok(map_response_to_canary_deploy(resp)),
        other => Ok({
            let _ = other;
            CanaryDeployOutcome::Transport
        }),
    }
}

/// `nn-admin canary list` — read-only, signed payload
/// (`Role::CanaryRead`). Server returns the chained registry log
/// as JSONL with truncation flag (same shape as `fim report`).
pub fn run_canary_list(
    socket: &Path,
    key_path: &Path,
    agent_id_path: &Path,
) -> Result<CanaryListOutcome> {
    let signing = read_priv_key(key_path)?;
    let agent_id_arr = agent_id::load_existing(agent_id_path)?;
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
    let payload = SignedPayload::new_canary_list(nonce, now, agent_id_arr);
    let sig: [u8; 64] =
        sign(&payload, &signing).map_err(|e| anyhow!("signing canary-list payload: {e}"))?;

    write_frame(
        &mut stream,
        &AdminMessage::CanaryListRequest(CanaryListRequest {
            payload,
            signatures: vec![KeyedSignature { signature: sig }],
        }),
    )?;
    match read_frame(&mut stream)? {
        AdminMessage::CanaryListResponse(resp) => Ok(map_response_to_canary_list(resp)),
        other => Ok({
            let _ = other;
            CanaryListOutcome::Transport
        }),
    }
}

/// `nn-admin canary burn` — quorum-signed (`Role::CanaryManage`)
/// op to mark a canary as burned (on-disk artefact deleted for
/// File/Credential; listener dropped for Network; process
/// terminated for Process). The agent persists the burn into the
/// registry chain + rebuilds K3 indexes so the detector stops
/// firing for that canary_id.
pub fn run_canary_burn(
    socket: &Path,
    key_path: &Path,
    agent_id_path: &Path,
    canary_id: String,
) -> Result<CanaryBurnOutcome> {
    let signing = read_priv_key(key_path)?;
    let agent_id_arr = agent_id::load_existing(agent_id_path)?;
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
    let payload = SignedPayload::new_canary_burn(nonce, now, agent_id_arr, canary_id);
    let sig: [u8; 64] =
        sign(&payload, &signing).map_err(|e| anyhow!("signing canary-burn payload: {e}"))?;

    write_frame(
        &mut stream,
        &AdminMessage::CanaryBurnRequest(CanaryBurnRequest {
            payload,
            signatures: vec![KeyedSignature { signature: sig }],
        }),
    )?;
    match read_frame(&mut stream)? {
        AdminMessage::CanaryBurnResult(r) => Ok(map_admin_result_to_canary_burn(r)),
        other => Ok({
            let _ = other;
            CanaryBurnOutcome::Transport
        }),
    }
}

/// `nn-admin canary refresh` — quorum-signed (`Role::CanaryManage`)
/// op to re-render a canary's on-disk artefact (rotating its
/// template-derived bytes). §12 Q2 MANUAL lock-in: no auto-refresh;
/// the operator MUST run this explicitly when staleness would
/// undermine the deception.
pub fn run_canary_refresh(
    socket: &Path,
    key_path: &Path,
    agent_id_path: &Path,
    canary_id: String,
) -> Result<CanaryRefreshOutcome> {
    let signing = read_priv_key(key_path)?;
    let agent_id_arr = agent_id::load_existing(agent_id_path)?;
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
    let payload = SignedPayload::new_canary_refresh(nonce, now, agent_id_arr, canary_id);
    let sig: [u8; 64] =
        sign(&payload, &signing).map_err(|e| anyhow!("signing canary-refresh payload: {e}"))?;

    write_frame(
        &mut stream,
        &AdminMessage::CanaryRefreshRequest(CanaryRefreshRequest {
            payload,
            signatures: vec![KeyedSignature { signature: sig }],
        }),
    )?;
    match read_frame(&mut stream)? {
        AdminMessage::CanaryRefreshResult(r) => Ok(map_admin_result_to_canary_refresh(r)),
        other => Ok({
            let _ = other;
            CanaryRefreshOutcome::Transport
        }),
    }
}

/// Debug-only: send a `DebugForcePosture` request. Only available
/// when both this crate and `common` are built with the
/// `debug-trigger` Cargo feature.
#[cfg(feature = "debug-trigger")]
pub fn run_debug_force_posture(
    socket: &Path,
    state: nn_proto::admin_protocol::DebugForcePosture,
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

/// External audit AUT-002: an admin key file group- or other-accessible,
/// or owned by another user, is refused — OpenSSH's rule for identity
/// files. `NN_ADMIN_ALLOW_LOOSE_KEY=1` accepts it anyway: a key on a vfat
/// stick shows 0644/0755, and COMBAT recovery must not stop at a mode bit.
pub const ALLOW_LOOSE_KEY_ENV: &str = "NN_ADMIN_ALLOW_LOOSE_KEY";

fn read_priv_key(path: &Path) -> Result<SigningKey> {
    use std::os::unix::fs::MetadataExt;
    use zeroize::Zeroizing;
    if std::env::var(ALLOW_LOOSE_KEY_ENV).as_deref() != Ok("1") {
        let meta = std::fs::metadata(path)
            .with_context(|| format!("reading private key {}", path.display()))?;
        if meta.mode() & 0o077 != 0 {
            bail!(
                "private key {} is accessible to group or others (mode {:o}): `chmod 600` it \
                 (or set {ALLOW_LOOSE_KEY_ENV}=1 for read-only media)",
                path.display(),
                meta.mode() & 0o7777
            );
        }
        // R10 (lab PR 259): rustix's safe wrapper of geteuid(2), which has
        // no preconditions and cannot fail (nn-admin forbids unsafe code).
        let euid = rustix::process::geteuid().as_raw();
        if meta.uid() != euid {
            bail!(
                "private key {} belongs to uid {}, not to this user (uid {euid})",
                path.display(),
                meta.uid()
            );
        }
    }
    // The key's bytes are wiped when these go out of scope.
    let raw = Zeroizing::new(
        std::fs::read_to_string(path)
            .with_context(|| format!("reading private key {}", path.display()))?,
    );
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
    let bytes = Zeroizing::new(
        hex::decode(line).map_err(|e| anyhow!("private key hex decode failed: {e}"))?,
    );
    let mut arr = Zeroizing::new([0u8; 32]);
    arr.copy_from_slice(&bytes);
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
    if body_len > nn_proto::admin_protocol::MAX_FRAME_BODY {
        bail!(
            "advertised frame body {body_len} > limit {}",
            nn_proto::admin_protocol::MAX_FRAME_BODY
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

// ── Tappa 10 N7 — nn-admin net subcommands ─────────────────────────
//
// Four operator-facing helpers mirroring the FIM C6 + canary K6
// CLI shape:
//
//   * `run_net_flows`        — reads the chained `netflow.jsonl`,
//                              optional `--since-unix` filter.
//   * `run_net_listeners`    — the listener log (listen events).
//   * `run_net_resolve`      — DNS-attribution lookup for an IP,
//                              from the netflow rows.
//   * `run_net_fingerprint`  — the netflow rows of one flow_id.
//
// The agent returns the newest rows first (external audit
// NN-AUD-080).
//
// All four are 1-of-N quorum, `Role::NetRead`. The CLI streams
// the JSONL body to stdout + a summary line to stderr (so
// `nn-admin net flows | jq` works out-of-box, same shape as
// `nn-admin fim report`).

/// Shared outcome shape across the three chain-style net ops
/// (flows / listeners / fingerprint). NetResolve uses its own
/// outcome — the single-record reply doesn't fit the chain
/// shape.
#[derive(Debug)]
pub enum NetJsonlOutcome {
    Success {
        entries_jsonl: String,
        entries_count: u32,
        entries_truncated: bool,
    },
    InvalidSignature,
    NoPendingChallenge,
    RateLimited {
        retry_after_secs: u32,
    },
    RoleDenied,
    TimestampSkew {
        server_ts: u64,
        max_skew_secs: u32,
    },
    AgentIdMismatch,
    UnknownOperation,
    ProtocolVersionUnsupported {
        server_version: u16,
    },
    Transport,
}

/// Outcome of `nn-admin net resolve <ip>`. Success carries the
/// hostname attributed to the newest retained flow to that IP and
/// when that flow was recorded; `qname: None` when no retained flow
/// to it carries a name.
#[derive(Debug)]
pub enum NetResolveOutcome {
    Success {
        qname: Option<String>,
        queried_at_unix_ts: Option<u64>,
    },
    InvalidSignature,
    NoPendingChallenge,
    RateLimited {
        retry_after_secs: u32,
    },
    RoleDenied,
    TimestampSkew {
        server_ts: u64,
        max_skew_secs: u32,
    },
    AgentIdMismatch,
    UnknownOperation,
    ProtocolVersionUnsupported {
        server_version: u16,
    },
    Transport,
}

fn map_admin_result_to_net_jsonl(
    result: nn_proto::admin_protocol::AdminResult,
    entries_jsonl: String,
    entries_count: u32,
    entries_truncated: bool,
) -> NetJsonlOutcome {
    use nn_proto::admin_protocol::AdminResult;
    match result {
        AdminResult::Success => NetJsonlOutcome::Success {
            entries_jsonl,
            entries_count,
            entries_truncated,
        },
        AdminResult::InvalidSignature => NetJsonlOutcome::InvalidSignature,
        AdminResult::NoPendingChallenge => NetJsonlOutcome::NoPendingChallenge,
        AdminResult::RateLimited { retry_after_secs } => {
            NetJsonlOutcome::RateLimited { retry_after_secs }
        }
        AdminResult::RoleDenied => NetJsonlOutcome::RoleDenied,
        AdminResult::QuorumNotMet { .. } => NetJsonlOutcome::InvalidSignature,
        AdminResult::TimestampSkew {
            server_ts,
            max_skew_secs,
        } => NetJsonlOutcome::TimestampSkew {
            server_ts,
            max_skew_secs,
        },
        AdminResult::AgentIdMismatch => NetJsonlOutcome::AgentIdMismatch,
        AdminResult::UnknownOperation => NetJsonlOutcome::UnknownOperation,
        AdminResult::ProtocolVersionUnsupported { server_version } => {
            NetJsonlOutcome::ProtocolVersionUnsupported { server_version }
        }
        // Lab PR 217: no reply of this operation; out of spec.
        AdminResult::ActionFailed => NetJsonlOutcome::Transport,
    }
}

/// `nn-admin net flows [--since-unix N]` — read the chained
/// netflow.jsonl. 1-of-N, `Role::NetRead`.
pub fn run_net_flows(
    socket: &Path,
    key_path: &Path,
    agent_id_path: &Path,
    since_unix_ts: Option<u64>,
) -> Result<NetJsonlOutcome> {
    use nn_proto::admin_protocol::NetFlowsRequest;

    let signing = read_priv_key(key_path)?;
    let agent_id_arr = agent_id::load_existing(agent_id_path)?;

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
    let payload = SignedPayload::new_net_flows(nonce, now, agent_id_arr, since_unix_ts);
    let sig: [u8; 64] =
        sign(&payload, &signing).map_err(|e| anyhow!("signing net-flows payload: {e}"))?;
    write_frame(
        &mut stream,
        &AdminMessage::NetFlowsRequest(NetFlowsRequest {
            payload,
            signatures: vec![KeyedSignature { signature: sig }],
        }),
    )?;
    match read_frame(&mut stream)? {
        AdminMessage::NetFlowsResponse(resp) => Ok(map_admin_result_to_net_jsonl(
            resp.result,
            resp.entries_jsonl,
            resp.entries_count,
            resp.entries_truncated,
        )),
        _ => Ok(NetJsonlOutcome::Transport),
    }
}

/// Tappa 9.0.b — `nn-admin detections` — read the last N persisted
/// detections (newest-first) from the detection chainlog, with
/// optional filters. 1-of-N, `Role::TelemetryRead`. Reuses
/// [`NetJsonlOutcome`] (the shared JSONL-read outcome) since the reply
/// shape is identical. The enum filters are passed through as
/// already-canonical lowercase strings (the CLI restricts them); the
/// agent parses + applies them server-side.
#[allow(clippy::too_many_arguments)]
pub fn run_detections(
    socket: &Path,
    key_path: &Path,
    agent_id_path: &Path,
    limit: u32,
    since_unix_ts: Option<u64>,
    until_unix_ts: Option<u64>,
    min_severity: Option<String>,
    status: Option<String>,
    sensor: Option<String>,
    path: Option<String>,
) -> Result<NetJsonlOutcome> {
    use nn_proto::admin_protocol::DetectionsRequest;

    let signing = read_priv_key(key_path)?;
    let agent_id_arr = agent_id::load_existing(agent_id_path)?;

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
    let payload = SignedPayload::new_detections(
        nonce,
        now,
        agent_id_arr,
        limit,
        since_unix_ts,
        until_unix_ts,
        min_severity,
        status,
        sensor,
        path,
    );
    let sig: [u8; 64] =
        sign(&payload, &signing).map_err(|e| anyhow!("signing detections payload: {e}"))?;
    write_frame(
        &mut stream,
        &AdminMessage::DetectionsRequest(DetectionsRequest {
            payload,
            signatures: vec![KeyedSignature { signature: sig }],
        }),
    )?;
    match read_frame(&mut stream)? {
        AdminMessage::DetectionsResponse(resp) => Ok(map_admin_result_to_net_jsonl(
            resp.result,
            resp.entries_jsonl,
            resp.entries_count,
            resp.entries_truncated,
        )),
        _ => Ok(NetJsonlOutcome::Transport),
    }
}

/// Outcome of `nn-admin detection-set-status` (auth via `Role::Triage`,
/// 1-of-N). `Success` echoes the id + new status the agent persisted.
/// `NotFound` covers every non-auth rejection the agent folds into
/// `UnknownOperation` (no dedicated wire variant, like the K6
/// canary-burn contract): an out-of-range id (`id == 0` / `id > max`),
/// AND a server-side persistence failure (the status-event append
/// errored — e.g. disk full / I/O error). The CLI therefore renders it
/// as "change not applied — not found, or not persisted; retry" rather
/// than asserting the detection is gone. (A future wire revision could
/// split these with a dedicated internal-error result.)
#[derive(Debug)]
pub enum DetectionSetStatusOutcome {
    Success {
        id: u64,
        new_status: String,
    },
    InvalidSignature,
    NoPendingChallenge,
    RateLimited {
        retry_after_secs: u32,
    },
    QuorumNotMet {
        required: u8,
        provided: u8,
    },
    RoleDenied,
    TimestampSkew {
        server_ts: u64,
        max_skew_secs: u32,
    },
    AgentIdMismatch,
    NotFound,
    /// The request was valid but the agent could not append the
    /// status-event (chain-persist-1): the change was NOT recorded.
    PersistFailed {
        id: u64,
    },
    ProtocolVersionUnsupported {
        server_version: u16,
    },
    Transport,
}

fn map_response_to_set_status(
    resp: nn_proto::admin_protocol::DetectionSetStatusResponse,
) -> DetectionSetStatusOutcome {
    use DetectionSetStatusOutcome as O;
    match resp.result {
        AdminResult::Success => O::Success {
            id: resp.id,
            new_status: resp.new_status,
        },
        AdminResult::InvalidSignature => O::InvalidSignature,
        AdminResult::NoPendingChallenge => O::NoPendingChallenge,
        AdminResult::RateLimited { retry_after_secs } => O::RateLimited { retry_after_secs },
        AdminResult::QuorumNotMet { required, provided } => O::QuorumNotMet { required, provided },
        AdminResult::RoleDenied => O::RoleDenied,
        AdminResult::TimestampSkew {
            server_ts,
            max_skew_secs,
        } => O::TimestampSkew {
            server_ts,
            max_skew_secs,
        },
        AdminResult::AgentIdMismatch => O::AgentIdMismatch,
        // Agent folds the non-auth rejections into UnknownOperation
        // (mirrors canary-burn): an out-of-range id, the not-wired
        // degraded boot, an invalid target status, AND a status-event
        // persistence failure. The NotFound outcome is rendered as a
        // "not applied — not found / not persisted; retry" message so
        // a transient write failure isn't misreported as a gone id.
        AdminResult::UnknownOperation if resp.persist_failed => O::PersistFailed { id: resp.id },
        AdminResult::UnknownOperation => O::NotFound,
        AdminResult::ProtocolVersionUnsupported { server_version } => {
            O::ProtocolVersionUnsupported { server_version }
        }
        // Lab PR 217: no reply of this operation; out of spec.
        AdminResult::ActionFailed => O::Transport,
    }
}

/// Tappa 9.0.c — `nn-admin detection-set-status` — change a persisted
/// detection's triage status (`Open` → `Acknowledged` → `Investigating`
/// → `Resolved` / `FalsePositive`). 1-of-N, `Role::Triage`. The new
/// status is passed as a canonical lowercase string (the CLI restricts
/// it via a value-enum); the agent appends a signed `StatusEvent` to
/// the status-event chain and never mutates the detection chain.
pub fn run_detection_set_status(
    socket: &Path,
    key_path: &Path,
    agent_id_path: &Path,
    id: u64,
    new_status: String,
    note: Option<String>,
) -> Result<DetectionSetStatusOutcome> {
    use nn_proto::admin_protocol::DetectionSetStatusRequest;

    let signing = read_priv_key(key_path)?;
    let agent_id_arr = agent_id::load_existing(agent_id_path)?;

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
        SignedPayload::new_detection_set_status(nonce, now, agent_id_arr, id, new_status, note);
    let sig: [u8; 64] = sign(&payload, &signing)
        .map_err(|e| anyhow!("signing detection-set-status payload: {e}"))?;
    write_frame(
        &mut stream,
        &AdminMessage::DetectionSetStatusRequest(DetectionSetStatusRequest {
            payload,
            signatures: vec![KeyedSignature { signature: sig }],
        }),
    )?;
    match read_frame(&mut stream)? {
        AdminMessage::DetectionSetStatusResponse(resp) => Ok(map_response_to_set_status(resp)),
        _ => Ok(DetectionSetStatusOutcome::Transport),
    }
}

/// `nn-admin net listeners` — the listener log, newest rows first
/// (listen events, not a snapshot of open sockets).
pub fn run_net_listeners(
    socket: &Path,
    key_path: &Path,
    agent_id_path: &Path,
) -> Result<NetJsonlOutcome> {
    use nn_proto::admin_protocol::NetListenersRequest;

    let signing = read_priv_key(key_path)?;
    let agent_id_arr = agent_id::load_existing(agent_id_path)?;

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
    let payload = SignedPayload::new_net_listeners(nonce, now, agent_id_arr);
    let sig: [u8; 64] =
        sign(&payload, &signing).map_err(|e| anyhow!("signing net-listeners payload: {e}"))?;
    write_frame(
        &mut stream,
        &AdminMessage::NetListenersRequest(NetListenersRequest {
            payload,
            signatures: vec![KeyedSignature { signature: sig }],
        }),
    )?;
    match read_frame(&mut stream)? {
        AdminMessage::NetListenersResponse(resp) => Ok(map_admin_result_to_net_jsonl(
            resp.result,
            resp.entries_jsonl,
            resp.entries_count,
            resp.entries_truncated,
        )),
        _ => Ok(NetJsonlOutcome::Transport),
    }
}

/// `nn-admin net resolve <ip>` — DNS attribution lookup.
pub fn run_net_resolve(
    socket: &Path,
    key_path: &Path,
    agent_id_path: &Path,
    ip: String,
) -> Result<NetResolveOutcome> {
    use nn_proto::admin_protocol::{AdminResult, NetResolveRequest};

    let signing = read_priv_key(key_path)?;
    let agent_id_arr = agent_id::load_existing(agent_id_path)?;

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
    let payload = SignedPayload::new_net_resolve(nonce, now, agent_id_arr, ip);
    let sig: [u8; 64] =
        sign(&payload, &signing).map_err(|e| anyhow!("signing net-resolve payload: {e}"))?;
    write_frame(
        &mut stream,
        &AdminMessage::NetResolveRequest(NetResolveRequest {
            payload,
            signatures: vec![KeyedSignature { signature: sig }],
        }),
    )?;
    match read_frame(&mut stream)? {
        AdminMessage::NetResolveResponse(resp) => Ok(match resp.result {
            AdminResult::Success => NetResolveOutcome::Success {
                qname: resp.qname,
                queried_at_unix_ts: resp.queried_at_unix_ts,
            },
            AdminResult::InvalidSignature => NetResolveOutcome::InvalidSignature,
            AdminResult::NoPendingChallenge => NetResolveOutcome::NoPendingChallenge,
            AdminResult::RateLimited { retry_after_secs } => {
                NetResolveOutcome::RateLimited { retry_after_secs }
            }
            AdminResult::RoleDenied => NetResolveOutcome::RoleDenied,
            AdminResult::QuorumNotMet { .. } => NetResolveOutcome::InvalidSignature,
            AdminResult::TimestampSkew {
                server_ts,
                max_skew_secs,
            } => NetResolveOutcome::TimestampSkew {
                server_ts,
                max_skew_secs,
            },
            AdminResult::AgentIdMismatch => NetResolveOutcome::AgentIdMismatch,
            AdminResult::UnknownOperation => NetResolveOutcome::UnknownOperation,
            AdminResult::ProtocolVersionUnsupported { server_version } => {
                NetResolveOutcome::ProtocolVersionUnsupported { server_version }
            }
            // Lab PR 217: no reply of this operation; out of spec.
            AdminResult::ActionFailed => NetResolveOutcome::Transport,
        }),
        _ => Ok(NetResolveOutcome::Transport),
    }
}

/// `nn-admin net fingerprint --flow-id <hex>` — the netflow rows of
/// that flow, with their JA3/JA4/SNI fields.
pub fn run_net_fingerprint(
    socket: &Path,
    key_path: &Path,
    agent_id_path: &Path,
    flow_id: String,
) -> Result<NetJsonlOutcome> {
    use nn_proto::admin_protocol::NetFingerprintRequest;

    let signing = read_priv_key(key_path)?;
    let agent_id_arr = agent_id::load_existing(agent_id_path)?;

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
    let payload = SignedPayload::new_net_fingerprint(nonce, now, agent_id_arr, flow_id);
    let sig: [u8; 64] =
        sign(&payload, &signing).map_err(|e| anyhow!("signing net-fingerprint payload: {e}"))?;
    write_frame(
        &mut stream,
        &AdminMessage::NetFingerprintRequest(NetFingerprintRequest {
            payload,
            signatures: vec![KeyedSignature { signature: sig }],
        }),
    )?;
    match read_frame(&mut stream)? {
        AdminMessage::NetFingerprintResponse(resp) => Ok(map_admin_result_to_net_jsonl(
            resp.result,
            resp.entries_jsonl,
            resp.entries_count,
            resp.entries_truncated,
        )),
        _ => Ok(NetJsonlOutcome::Transport),
    }
}

// ── tests ───────────────────────────────────────────────────────────

// ── FIM-009 self-upgrade (§15.1) — nn-admin trusted-installer-grant ─

/// Outcome of `nn-admin trusted-installer-grant`. Same 1-of-N quorum +
/// `AdminResult` shape as [`FimBaselineOutcome`]; kept distinct so the
/// binary renders its own human messages + exit codes.
#[derive(Debug)]
pub enum TrustedInstallerGrantOutcome {
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

fn map_admin_result_to_trusted_installer(
    r: nn_proto::admin_protocol::AdminResult,
) -> TrustedInstallerGrantOutcome {
    use nn_proto::admin_protocol::AdminResult;
    match r {
        AdminResult::Success => TrustedInstallerGrantOutcome::Success,
        AdminResult::InvalidSignature => TrustedInstallerGrantOutcome::InvalidSignature,
        AdminResult::NoPendingChallenge => TrustedInstallerGrantOutcome::NoPendingChallenge,
        AdminResult::RateLimited { retry_after_secs } => {
            TrustedInstallerGrantOutcome::RateLimited { retry_after_secs }
        }
        AdminResult::QuorumNotMet { required, provided } => {
            TrustedInstallerGrantOutcome::QuorumNotMet { required, provided }
        }
        AdminResult::RoleDenied => TrustedInstallerGrantOutcome::RoleDenied,
        AdminResult::TimestampSkew {
            server_ts,
            max_skew_secs,
        } => TrustedInstallerGrantOutcome::TimestampSkew {
            server_ts,
            max_skew_secs,
        },
        AdminResult::AgentIdMismatch => TrustedInstallerGrantOutcome::AgentIdMismatch,
        AdminResult::UnknownOperation => TrustedInstallerGrantOutcome::UnknownOperation,
        AdminResult::ProtocolVersionUnsupported { server_version } => {
            TrustedInstallerGrantOutcome::ProtocolVersionUnsupported { server_version }
        }
        // Lab PR 217: no reply of this operation; out of spec.
        AdminResult::ActionFailed => TrustedInstallerGrantOutcome::UnknownOperation,
    }
}

/// `nn-admin trusted-installer-grant` — submit a 1-of-N (M=1)
/// quorum-signed grant that arms the FIM-009 trusted-installer override
/// for `window_secs` (the agent clamps to its 600 s ceiling). Single-sig
/// with the `trusted-installer` role per §15.1. Mirrors
/// [`run_fim_baseline`]'s transport (challenge → sign → send).
pub fn run_trusted_installer_grant(
    socket: &Path,
    key_path: &Path,
    agent_id_path: &Path,
    window_secs: u32,
) -> Result<TrustedInstallerGrantOutcome> {
    use nn_proto::admin_protocol::TrustedInstallerGrantRequest;

    let signing = read_priv_key(key_path)?;
    let agent_id_arr = agent_id::load_existing(agent_id_path)?;
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
    let payload = SignedPayload::new_trusted_installer_grant(nonce, now, agent_id_arr, window_secs);
    let sig: [u8; 64] = sign(&payload, &signing)
        .map_err(|e| anyhow!("signing trusted-installer-grant payload: {e}"))?;

    write_frame(
        &mut stream,
        &AdminMessage::TrustedInstallerGrantRequest(TrustedInstallerGrantRequest {
            payload,
            signatures: vec![KeyedSignature { signature: sig }],
        }),
    )?;
    let result = match read_frame(&mut stream)? {
        AdminMessage::TrustedInstallerGrantResult(r) => r,
        other => bail!("unexpected reply to TrustedInstallerGrantRequest: {other:?}"),
    };
    Ok(map_admin_result_to_trusted_installer(result))
}

// ── External audit CMB-016 — undoing a response ────────────────────────

/// Outcome of `nn-admin response status`: the reply as the agent sent it
/// (the lists are empty unless `result` is `Success`).
pub type ResponseStatusOutcome = nn_proto::admin_protocol::ResponseStatusResponse;

/// Outcome of `nn-admin response release` / `restore`. `done` is false
/// when the request was verified but nothing was done (`message` says
/// why); `path` is where a restore wrote the file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResponseActionOutcome {
    pub result: AdminResult,
    pub done: bool,
    pub path: Option<String>,
    pub message: String,
}

/// Challenge, sign `build(nonce, ts, agent_id)` with `key_path`, send the
/// request `wrap` makes of it, return the reply.
fn signed_request(
    socket: &Path,
    key_path: &Path,
    agent_id_path: &Path,
    build: impl FnOnce([u8; 32], u64, [u8; 16]) -> SignedPayload,
    wrap: impl FnOnce(SignedPayload, Vec<KeyedSignature>) -> AdminMessage,
) -> Result<AdminMessage> {
    signed_request_waiting(socket, key_path, agent_id_path, build, wrap, None)
}

/// [`signed_request`], waiting up to `reply_timeout` for the reply to the
/// request itself (a restore of many files takes longer than 5 s).
fn signed_request_waiting(
    socket: &Path,
    key_path: &Path,
    agent_id_path: &Path,
    build: impl FnOnce([u8; 32], u64, [u8; 16]) -> SignedPayload,
    wrap: impl FnOnce(SignedPayload, Vec<KeyedSignature>) -> AdminMessage,
    reply_timeout: Option<Duration>,
) -> Result<AdminMessage> {
    let signing = read_priv_key(key_path)?;
    let agent_id_arr = agent_id::load_existing(agent_id_path)?;
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
    let payload = build(nonce, now, agent_id_arr);
    let sig = sign(&payload, &signing).map_err(|e| anyhow!("signing payload: {e}"))?;
    write_frame(
        &mut stream,
        &wrap(payload, vec![KeyedSignature { signature: sig }]),
    )?;
    if let Some(t) = reply_timeout {
        stream.set_read_timeout(Some(t)).ok();
    }
    read_frame(&mut stream)
}

/// Lab PR 222: `nn-admin remediate ransomware --pid N | --since TS
/// [--dry-run]` (role `response-manage`): the agent restores the files from
/// the copy-on-first-write journal. Waits up to 10 minutes for the reply.
pub fn run_remediate_ransomware(
    socket: &Path,
    key_path: &Path,
    agent_id_path: &Path,
    pid: Option<u32>,
    since_unix: Option<u64>,
    dry_run: bool,
) -> Result<nn_proto::admin_protocol::RemediateRansomwareResponse> {
    use nn_proto::admin_protocol::RemediateRansomwareRequest;
    match signed_request_waiting(
        socket,
        key_path,
        agent_id_path,
        |n, ts, id| SignedPayload::new_remediate_ransomware(n, ts, id, pid, since_unix, dry_run),
        |payload, signatures| {
            AdminMessage::RemediateRansomwareRequest(RemediateRansomwareRequest {
                payload,
                signatures,
            })
        },
        Some(Duration::from_secs(600)),
    )? {
        AdminMessage::RemediateRansomwareResponse(r) => Ok(r),
        other => bail!(
            "unexpected reply to RemediateRansomwareRequest: {other:?} (an agent older than lab PR \
             222 has no remediate verb)"
        ),
    }
}

/// `nn-admin response status` (role `audit-read`):
/// the processes the agent holds in its containment scopes, the
/// quarantine vault, the COMBAT stage.
pub fn run_response_status(
    socket: &Path,
    key_path: &Path,
    agent_id_path: &Path,
) -> Result<ResponseStatusOutcome> {
    use nn_proto::admin_protocol::ResponseStatusRequest;
    match signed_request(
        socket,
        key_path,
        agent_id_path,
        SignedPayload::new_response_status,
        |payload, signatures| {
            AdminMessage::ResponseStatusRequest(ResponseStatusRequest {
                payload,
                signatures,
            })
        },
    )? {
        AdminMessage::ResponseStatusResponse(r) => Ok(r),
        other => bail!("unexpected reply to ResponseStatusRequest: {other:?}"),
    }
}

/// `nn-admin response release --pid N` (role `response-manage`): the agent
/// writes the process back to the cgroup it came from.
pub fn run_response_release(
    socket: &Path,
    key_path: &Path,
    agent_id_path: &Path,
    pid: u32,
) -> Result<ResponseActionOutcome> {
    use nn_proto::admin_protocol::ResponseReleaseRequest;
    match signed_request(
        socket,
        key_path,
        agent_id_path,
        |n, ts, id| SignedPayload::new_response_release(n, ts, id, pid),
        |payload, signatures| {
            AdminMessage::ResponseReleaseRequest(ResponseReleaseRequest {
                payload,
                signatures,
            })
        },
    )? {
        AdminMessage::ResponseReleaseResponse(r) => Ok(ResponseActionOutcome {
            result: r.result,
            done: r.released,
            path: None,
            message: r.message,
        }),
        other => bail!("unexpected reply to ResponseReleaseRequest: {other:?}"),
    }
}

/// `nn-admin response restore --vault-id ID [--to PATH]` (role
/// `response-manage`): the agent decrypts the vault entry to a new file —
/// the original path by default.
pub fn run_response_restore(
    socket: &Path,
    key_path: &Path,
    agent_id_path: &Path,
    vault_id: String,
    to: Option<String>,
) -> Result<ResponseActionOutcome> {
    use nn_proto::admin_protocol::ResponseRestoreRequest;
    match signed_request(
        socket,
        key_path,
        agent_id_path,
        |n, ts, id| SignedPayload::new_response_restore(n, ts, id, vault_id, to),
        |payload, signatures| {
            AdminMessage::ResponseRestoreRequest(ResponseRestoreRequest {
                payload,
                signatures,
            })
        },
    )? {
        AdminMessage::ResponseRestoreResponse(r) => Ok(ResponseActionOutcome {
            result: r.result,
            done: r.restored,
            path: (!r.path.is_empty()).then_some(r.path),
            message: r.message,
        }),
        other => bail!("unexpected reply to ResponseRestoreRequest: {other:?}"),
    }
}

// ── Tappa 10.8 — signed operator overlays ──────────────────────────────

/// Outcome of `nn-admin config overlay set`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigOverlaySetOutcome {
    pub result: AdminResult,
    pub stored: bool,
    pub message: String,
}

/// Read and check an overlay before signing it: size, the loader's own
/// parse rules, SHA-256 and length of the exact bytes. Public for the
/// agent's tests of the loaders' rules (R10, lab PR 259), which are the
/// agent's, through its host.
pub fn read_overlay_for_signing<H: AdminHost>(
    host: &H,
    kind: nn_proto::admin_signed_payload::OverlayKind,
    file: &Path,
) -> Result<(String, [u8; 32], u32)> {
    let content = std::fs::read_to_string(file)
        .with_context(|| format!("reading overlay {}", file.display()))?;
    if content.len() > nn_proto::admin_protocol::MAX_OVERLAY_BYTES {
        bail!(
            "{} is {} bytes; overlays are limited to {} bytes",
            file.display(),
            content.len(),
            nn_proto::admin_protocol::MAX_OVERLAY_BYTES
        );
    }
    host.validate_overlay(kind, &content).with_context(|| {
        format!(
            "{} does not parse as a {} overlay",
            file.display(),
            kind.keyword()
        )
    })?;
    let sha = crate::config::overlay_auth::content_sha256(content.as_bytes());
    let len = content.len() as u32;
    Ok((content, sha, len))
}

fn sign_all(payload: &SignedPayload, key: &Path, cosign: Option<&Path>) -> Result<Vec<[u8; 64]>> {
    let mut out =
        vec![sign(payload, &read_priv_key(key)?)
            .map_err(|e| anyhow!("signing overlay payload: {e}"))?];
    if let Some(c) = cosign {
        out.push(
            sign(payload, &read_priv_key(c)?)
                .map_err(|e| anyhow!("co-signing overlay payload: {e}"))?,
        );
    }
    Ok(out)
}

/// `nn-admin config overlay set`: sign the overlay over the agent's
/// challenge and hand it to the running agent, which writes it (and its
/// `.sig`) where it reads overlays at boot.
pub fn run_config_overlay_set<H: AdminHost>(
    host: &H,
    socket: &Path,
    key_path: &Path,
    cosign_path: Option<&Path>,
    agent_id_path: &Path,
    kind: nn_proto::admin_signed_payload::OverlayKind,
    file: &Path,
) -> Result<ConfigOverlaySetOutcome> {
    use nn_proto::admin_protocol::ConfigOverlaySetRequest;
    let (content, sha, len) = read_overlay_for_signing(host, kind, file)?;
    let agent_id_arr = agent_id::load_existing(agent_id_path)?;
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
    let payload = SignedPayload::new_config_overlay_set(nonce, now, agent_id_arr, kind, sha, len);
    let sigs = sign_all(&payload, key_path, cosign_path)?;
    write_frame(
        &mut stream,
        &AdminMessage::ConfigOverlaySetRequest(ConfigOverlaySetRequest {
            payload,
            signatures: sigs
                .into_iter()
                .map(|signature| KeyedSignature { signature })
                .collect(),
            content,
        }),
    )?;
    match read_frame(&mut stream)? {
        AdminMessage::ConfigOverlaySetResponse(r) => Ok(ConfigOverlaySetOutcome {
            result: r.result,
            stored: r.stored,
            message: r.message,
        }),
        other => bail!("unexpected reply to ConfigOverlaySetRequest: {other:?}"),
    }
}

/// `nn-admin config overlay sign`: sign an overlay offline (no agent
/// needed) and write `<file>.sig` or `out`. The nonce is random: a stored
/// signature is ordered by its timestamp, not by a server challenge.
pub fn run_config_overlay_sign<H: AdminHost>(
    host: &H,
    key_path: &Path,
    cosign_path: Option<&Path>,
    agent_id_path: &Path,
    kind: nn_proto::admin_signed_payload::OverlayKind,
    file: &Path,
    out: Option<&Path>,
) -> Result<PathBuf> {
    use rand::Rng;
    let (_content, sha, len) = read_overlay_for_signing(host, kind, file)?;
    let agent_id_arr = agent_id::load_existing(agent_id_path)?;
    let mut nonce = [0u8; 32];
    OsRng.fill_bytes(&mut nonce);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let payload = SignedPayload::new_config_overlay_set(nonce, now, agent_id_arr, kind, sha, len);
    let sigs = sign_all(&payload, key_path, cosign_path)?;
    let sig = crate::config::overlay_auth::OverlaySignature::new(payload, &sigs)?;
    let target = out
        .map(Path::to_path_buf)
        .unwrap_or_else(|| crate::config::overlay_auth::sig_path(file));
    std::fs::write(&target, sig.to_json()?)
        .with_context(|| format!("writing {}", target.display()))?;
    Ok(target)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::Signer;

    /// A private key file as `nn-admin init` and install.sh leave it: 0600
    /// (external audit AUT-002: `read_priv_key` refuses anything looser).
    fn write_priv_key_file(path: &Path, key: &SigningKey) {
        std::fs::write(path, format!("{}\n", hex::encode(key.to_bytes()))).unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    use nn_model::posture_types::PostureKind;
    use nn_proto::admin_protocol::{Challenge, StatusResponse};
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
    fn cli_verify_keys_reports_bad_line_keeps_others() {
        let dir = TempDir::new().unwrap();
        let pub_path = dir.path().join("admin.pub");
        let good = hex::encode(SigningKey::generate(&mut OsRng).verifying_key().to_bytes());
        std::fs::write(&pub_path, format!("not-64-hex-chars\n{good}\n")).unwrap();
        let out = run_verify_keys(&pub_path).expect("verify");
        assert_eq!(out.fingerprints.len(), 1);
        assert_eq!(out.skipped.len(), 1);
        assert_eq!(out.skipped[0].0, 1, "names the line");
    }

    /// External audit AUT-002.
    #[test]
    fn read_priv_key_refuses_group_readable() {
        let dir = TempDir::new().unwrap();
        let p = dir.path().join("admin.key");
        let k = SigningKey::generate(&mut OsRng);
        std::fs::write(&p, format!("{}\n", hex::encode(k.to_bytes()))).unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o644)).unwrap();
        let err = read_priv_key(&p).unwrap_err();
        assert!(err.to_string().contains("chmod 600"), "{err}");
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(read_priv_key(&p).unwrap().to_bytes(), k.to_bytes());
    }

    /// External audit AUT-002: `init --force` over a 0644 file leaves a
    /// 0600 one, and never writes through a link.
    #[test]
    fn run_init_force_resets_mode() {
        use std::os::unix::fs::MetadataExt;
        let dir = TempDir::new().unwrap();
        let key = dir.path().join("admin.key");
        std::fs::write(&key, "old").unwrap();
        std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o644)).unwrap();
        run_init(&key, &dir.path().join("admin.pub"), true).unwrap();
        assert_eq!(std::fs::metadata(&key).unwrap().mode() & 0o7777, 0o600);
        let victim = dir.path().join("victim");
        std::fs::write(&victim, "KEEP").unwrap();
        let link = dir.path().join("link.key");
        std::os::unix::fs::symlink(&victim, &link).unwrap();
        assert!(run_init(&link, &dir.path().join("admin2.pub"), true).is_err());
        assert_eq!(std::fs::read_to_string(&victim).unwrap(), "KEEP");
    }

    /// External audit MAIN-005: the line shape install.sh writes.
    #[test]
    fn cli_verify_keys_accepts_role_token_and_prints_roles() {
        let dir = TempDir::new().unwrap();
        let pub_path = dir.path().join("admin.pub");
        let k = hex::encode(SigningKey::generate(&mut OsRng).verifying_key().to_bytes());
        std::fs::write(
            &pub_path,
            format!("{k} unlock,audit-read,trusted-installer\n"),
        )
        .unwrap();
        let out = run_verify_keys(&pub_path).expect("verify");
        assert_eq!(out.fingerprints.len(), 1);
        assert!(out.skipped.is_empty());
        assert!(
            out.roles[0].contains("trusted-installer"),
            "{:?}",
            out.roles
        );
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
        use nn_proto::admin_protocol::SignedUnlockResponse;
        use nn_proto::admin_signed_payload::{verify, OperationCode};
        let dir = TempDir::new().unwrap();
        let socket = dir.path().join("admin.sock");
        let priv_path = dir.path().join("admin.key");
        let signing = SigningKey::generate(&mut OsRng);
        write_priv_key_file(&priv_path, &signing);
        let agent_id = [0x42u8; 16];
        let agent_id_path = write_agent_id_file(&dir, &agent_id);

        let vk = signing.verifying_key();
        let nonce = [0x11u8; 32];

        let server = spawn_mock_server(&socket, move |stream| {
            // Expect ChallengeRequest → reply Challenge.
            match server_read_frame(stream) {
                AdminMessage::ChallengeRequest(_) => {}
                other => panic!("expected ChallengeRequest, got {other:?}"),
            }
            server_write_frame(stream, &AdminMessage::Challenge(Challenge { nonce }));

            // Lab PR 217: a signed `Unlock` payload over that challenge and
            // this install — never a signature over the bare nonce.
            let req = match server_read_frame(stream) {
                AdminMessage::SignedUnlockRequest(r) => r,
                other => panic!("expected SignedUnlockRequest, got {other:?}"),
            };
            assert_eq!(req.payload.op, OperationCode::Unlock);
            assert_eq!(req.payload.nonce, nonce);
            assert_eq!(req.payload.agent_id, agent_id);
            assert_eq!(req.signatures.len(), 1);
            verify(&req.payload, &req.signatures[0].signature, &vk)
                .expect("client sig must verify");

            server_write_frame(
                stream,
                &AdminMessage::SignedUnlockResponse(SignedUnlockResponse {
                    result: AdminResult::Success,
                    released: true,
                    isolation_v4: false,
                    isolation_v6: false,
                    message: "COMBAT released".to_string(),
                }),
            );
        });

        let outcome = run_unlock(&socket, &priv_path, &agent_id_path).expect("unlock");
        match outcome {
            UnlockOutcome::Success {
                message,
                isolation_v4,
                isolation_v6,
            } => {
                assert_eq!(message, "COMBAT released");
                assert!(!isolation_v4 && !isolation_v6);
            }
            other => panic!("expected Success, got {other:?}"),
        }
        server.join().unwrap();
    }

    /// Lab PR 217 (NN-AUD-243 residue): a verified unlock whose teardown
    /// did not take is a failure for the CLI — never a success — with the
    /// agent's reason and its per-family state; so is a `Success` that says
    /// nothing was released.
    #[test]
    fn cli_unlock_reports_a_failed_release() {
        use nn_proto::admin_protocol::SignedUnlockResponse;
        for (result, released) in [
            (AdminResult::ActionFailed, false),
            (AdminResult::Success, false),
        ] {
            let dir = TempDir::new().unwrap();
            let socket = dir.path().join("admin.sock");
            let priv_path = dir.path().join("admin.key");
            write_priv_key_file(&priv_path, &SigningKey::generate(&mut OsRng));
            let agent_id_path = write_agent_id_file(&dir, &[0x42u8; 16]);
            let server = spawn_mock_server(&socket, move |stream| {
                let _ = server_read_frame(stream);
                server_write_frame(
                    stream,
                    &AdminMessage::Challenge(Challenge { nonce: [0u8; 32] }),
                );
                let _ = server_read_frame(stream);
                server_write_frame(
                    stream,
                    &AdminMessage::SignedUnlockResponse(SignedUnlockResponse {
                        result,
                        released,
                        isolation_v4: false,
                        isolation_v6: true,
                        message: "IPv6: FAILED (read back: the chain is still listed)".into(),
                    }),
                );
            });
            match run_unlock(&socket, &priv_path, &agent_id_path).expect("unlock") {
                UnlockOutcome::ReleaseFailed {
                    message,
                    isolation_v4,
                    isolation_v6,
                } => {
                    assert!(message.contains("IPv6"), "{message}");
                    assert!(!isolation_v4 && isolation_v6);
                }
                other => panic!("{result:?}/{released}: expected ReleaseFailed, got {other:?}"),
            }
            server.join().unwrap();
        }
    }

    /// FIM-009 self-upgrade (§15.1): the `trusted-installer-grant`
    /// client signs over the SignedPayload digest (op tag + window
    /// inside the signed scope) and submits it; a Success reply maps to
    /// `TrustedInstallerGrantOutcome::Success`. Exercises the real
    /// challenge → sign → send path against a mock server that verifies
    /// the signature + the signed window.
    #[test]
    fn cli_trusted_installer_grant_happy_path() {
        use nn_proto::admin_signed_payload::{signing_digest, OperationExtra};
        let dir = TempDir::new().unwrap();
        let socket = dir.path().join("admin.sock");
        let priv_path = dir.path().join("admin.key");
        let agent_id_path = write_agent_id_file(&dir, &[0x33u8; 16]);
        let signing = SigningKey::generate(&mut OsRng);
        write_priv_key_file(&priv_path, &signing);
        let vk = signing.verifying_key();
        let nonce = [0x33u8; 32];

        let server = spawn_mock_server(&socket, move |stream| {
            match server_read_frame(stream) {
                AdminMessage::ChallengeRequest(_) => {}
                other => panic!("expected ChallengeRequest, got {other:?}"),
            }
            server_write_frame(stream, &AdminMessage::Challenge(Challenge { nonce }));

            let req = match server_read_frame(stream) {
                AdminMessage::TrustedInstallerGrantRequest(r) => r,
                other => panic!("expected TrustedInstallerGrantRequest, got {other:?}"),
            };
            // The window rides inside the signed scope.
            match &req.payload.extra {
                OperationExtra::TrustedInstallerGrant(e) => assert_eq!(e.window_secs, 120),
                other => panic!("expected TrustedInstallerGrant extra, got {other:?}"),
            }
            // The signature must verify over the payload's signing digest.
            let digest = signing_digest(&req.payload).expect("digest");
            let sig = ed25519_dalek::Signature::from_bytes(&req.signatures[0].signature);
            vk.verify_strict(&digest, &sig)
                .expect("client sig must verify over the signing digest");

            server_write_frame(
                stream,
                &AdminMessage::TrustedInstallerGrantResult(AdminResult::Success),
            );
        });

        let outcome = run_trusted_installer_grant(&socket, &priv_path, &agent_id_path, 120)
            .expect("trusted-installer-grant");
        assert!(matches!(outcome, TrustedInstallerGrantOutcome::Success));
        server.join().unwrap();
    }

    /// A RoleDenied reply (key lacks `trusted-installer`) maps through
    /// to the distinct outcome → exit code 7 in the binary.
    #[test]
    fn cli_trusted_installer_grant_propagates_role_denied() {
        let dir = TempDir::new().unwrap();
        let socket = dir.path().join("admin.sock");
        let priv_path = dir.path().join("admin.key");
        let agent_id_path = write_agent_id_file(&dir, &[0x33u8; 16]);
        let signing = SigningKey::generate(&mut OsRng);
        write_priv_key_file(&priv_path, &signing);

        let server = spawn_mock_server(&socket, move |stream| {
            let _ = server_read_frame(stream); // ChallengeRequest
            server_write_frame(
                stream,
                &AdminMessage::Challenge(Challenge { nonce: [0u8; 32] }),
            );
            let _ = server_read_frame(stream); // TrustedInstallerGrantRequest
            server_write_frame(
                stream,
                &AdminMessage::TrustedInstallerGrantResult(AdminResult::RoleDenied),
            );
        });

        let outcome = run_trusted_installer_grant(&socket, &priv_path, &agent_id_path, 120)
            .expect("trusted-installer-grant");
        assert!(matches!(outcome, TrustedInstallerGrantOutcome::RoleDenied));
        server.join().unwrap();
    }

    #[test]
    fn cli_unlock_propagates_rate_limited() {
        let dir = TempDir::new().unwrap();
        let socket = dir.path().join("admin.sock");
        let priv_path = dir.path().join("admin.key");
        let signing = SigningKey::generate(&mut OsRng);
        write_priv_key_file(&priv_path, &signing);

        let server = spawn_mock_server(&socket, move |stream| {
            match server_read_frame(stream) {
                AdminMessage::ChallengeRequest(_) => {}
                other => panic!("got {other:?}"),
            }
            server_write_frame(
                stream,
                &AdminMessage::Challenge(Challenge { nonce: [0u8; 32] }),
            );
            let _ = server_read_frame(stream); // SignedUnlockRequest
            server_write_frame(
                stream,
                &AdminMessage::SignedUnlockResponse(
                    nn_proto::admin_protocol::SignedUnlockResponse {
                        result: AdminResult::RateLimited {
                            retry_after_secs: 42,
                        },
                        released: false,
                        isolation_v4: true,
                        isolation_v6: true,
                        message: String::new(),
                    },
                ),
            );
        });

        let agent_id_path = write_agent_id_file(&dir, &[0x42u8; 16]);
        let outcome = run_unlock(&socket, &priv_path, &agent_id_path).expect("unlock");
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
        write_priv_key_file(&priv_path, &signing);

        let server = spawn_mock_server(&socket, move |stream| {
            let _ = server_read_frame(stream);
            server_write_frame(
                stream,
                &AdminMessage::Challenge(Challenge { nonce: [0u8; 32] }),
            );
            let _ = server_read_frame(stream);
            server_write_frame(
                stream,
                &AdminMessage::SignedUnlockResponse(
                    nn_proto::admin_protocol::SignedUnlockResponse {
                        result: AdminResult::InvalidSignature,
                        released: false,
                        isolation_v4: true,
                        isolation_v6: false,
                        message: "signature verification failed".into(),
                    },
                ),
            );
        });
        let agent_id_path = write_agent_id_file(&dir, &[0x42u8; 16]);
        let outcome = run_unlock(&socket, &priv_path, &agent_id_path).expect("unlock");
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
                    ringbuf_drops_total: None,
                    ringbuf_drops: None,
                    combat_stage: Some("ISOLATE".to_string()),
                    combat_locked: Some(true),
                    ringbuf_rejected_total: Some(2),
                    ringbuf_rejected: Some(vec![("open_sensor".to_string(), 2)]),
                    netflow_rows_skipped_total: Some(7),
                    netflow_pending_evicted_total: Some(0),
                    net_inactive_rules: Some(vec!["NN-L-NET-003 (JA3)".to_string()]),
                    flow_sock_pending: Some(70_000),
                    flow_sock_capacity: Some(65_536),
                    flow_sock_forgotten_min: Some(4_464),
                    detect_only: Some(true),
                    detect_only_source: Some("--detect-only".to_string()),
                    combat_evidence_unrecorded: Some(2),
                    combat_evidence_pending: Some(1),
                    combat_evidence_dropped: Some(0),
                    net_dot_rows_total: Some(4),
                    net_dot_rows_resolver: Some(3),
                    net_quic_rows_total: Some(9),
                    deny_fail_open_total: Some(2),
                    deny_fail_open: Some(vec![("inode_rename".to_string(), 2)]),
                    network_isolation_v4: None,
                    network_isolation_v6: None,
                    trust_level: None,
                    trust_reasons: None,
                    degradations: None,
                    capability_manifest: None,
                    exploit_guard: Some(nn_proto::admin_protocol::ExploitGuardStatus {
                        mode: "lite detect".to_string(),
                        checked_total: 50,
                        skipped_privileged_total: 20,
                        anomalies_total: 0,
                        kills_total: 0,
                        untracked_total: 0,
                        use_checks_total: 0,
                        denied_total: 0,
                    }),
                    cow_guard: None,
                    execq_state: Some("enforce".to_string()),
                    execq_held_total: Some(1),
                    execq_resumed_total: Some(2),
                    execq_killed_total: Some(3),
                    execq_quarantined_total: Some(4),
                    execq_defaulted_total: Some(5),
                    execq_known_identity_total: Some(6),
                    execq_known_hash_total: Some(7),
                    execq_not_held_total: Some(8),
                    execq_scanner_deaths_total: Some(9),
                    net_connect_verdicts_total: Some(11),
                    net_flow_snapshots_total: Some(60),
                    net_flow_snapshots_deferred_total: Some(1),
                    net_connect_denied_total: None,
                    ransomware_decisive_total: Some(1),
                    ransomware_signals_total: Some(2),
                    ransomware_trusted_total: Some(3),
                    ransomware_samplings_total: Some(4),
                    defense_tamper_total: Some(5),
                    defense_tamper_sanctioned_total: Some(6),
                    defense_tools_watched: Some(7),
                    execpol_state: Some("enforce; 1 partial".to_string()),
                    execpol_denied_total: Some(11),
                    execpol_would_deny_total: Some(12),
                    execpol_quarantine_total: Some(13),
                    execpol_quarantine_inactive_total: Some(14),
                    execpol_env_denied_total: Some(15),
                    execpol_env_recorded_total: Some(16),
                    execpol_map_denied_total: Some(17),
                    execpol_map_recorded_total: Some(18),
                    execq_script_refused_total: Some(19),
                }),
            );
        });
        let out = run_status(&socket).expect("status");
        // Lab PR 223: the exec quarantine's fields.
        assert_eq!(out.execq_state.as_deref(), Some("enforce"));
        assert_eq!(out.execq_held_total, Some(1));
        assert_eq!(out.execq_scanner_deaths_total, Some(9));
        // Lab PR 226: the exec policy's fields.
        assert_eq!(out.execpol_state.as_deref(), Some("enforce; 1 partial"));
        assert_eq!(out.execpol_denied_total, Some(11));
        assert_eq!(out.execpol_map_recorded_total, Some(18));
        assert_eq!(out.combat_stage.as_deref(), Some("ISOLATE"));
        assert_eq!(out.combat_locked, Some(true));
        assert_eq!(out.ringbuf_rejected_total, Some(2));
        // External audit NET-019 / NET-009: the `net status` fields.
        assert_eq!(out.netflow_rows_skipped_total, Some(7));
        assert_eq!(out.netflow_pending_evicted_total, Some(0));
        // Lab PR 164: the kernel socket map's occupancy.
        assert_eq!(out.flow_sock_pending, Some(70_000));
        assert_eq!(out.flow_sock_capacity, Some(65_536));
        assert_eq!(out.flow_sock_forgotten_min, Some(4_464));
        assert_eq!(
            out.net_inactive_rules.as_deref(),
            Some(&["NN-L-NET-003 (JA3)".to_string()][..])
        );
        assert_eq!(out.ringbuf_rejected, vec![("open_sensor".to_string(), 2)]);
        // External audit CMB-018 / CMB-027 (lab PR 193).
        assert_eq!(out.detect_only, Some(true));
        assert_eq!(out.detect_only_source.as_deref(), Some("--detect-only"));
        assert_eq!(
            (
                out.combat_evidence_unrecorded,
                out.combat_evidence_pending,
                out.combat_evidence_dropped
            ),
            (Some(2), Some(1), Some(0))
        );
        // External audit NET-017 (lab PR 207).
        assert_eq!(
            (
                out.net_dot_rows_total,
                out.net_dot_rows_resolver,
                out.net_quic_rows_total
            ),
            (Some(4), Some(3), Some(9))
        );
        // Lab PR 215.
        assert_eq!(out.deny_fail_open_total, Some(2));
        assert_eq!(out.deny_fail_open, vec![("inode_rename".to_string(), 2)]);
        // Lab PR 219: the exploit guard.
        let g = out.exploit_guard.as_ref().expect("exploit guard");
        assert_eq!((g.mode.as_str(), g.checked_total), ("lite detect", 50));
        // Lab PR 224 (CM-02).
        assert_eq!(
            (
                out.net_connect_verdicts_total,
                out.net_flow_snapshots_total,
                out.net_flow_snapshots_deferred_total,
                out.net_connect_denied_total
            ),
            (Some(11), Some(60), Some(1), None)
        );
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

    use nn_proto::admin_protocol::AdminResult;
    use nn_proto::admin_signed_payload::verify;

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
    fn run_with_mock_server<S, C, R>(socket_path: &Path, mock_server_fn: S, client_fn: C) -> R
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
        write_priv_key_file(&priv_a, &signing_a);
        write_priv_key_file(&priv_b, &signing_b);
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
                    &AdminMessage::Challenge(nn_proto::admin_protocol::Challenge { nonce }),
                );

                // Step 2: server receives ShutdownRequest, verifies
                // both signatures actually verify under the served
                // nonce + agent_id binding.
                let req = match server_read_frame(stream) {
                    AdminMessage::ShutdownRequest(r) => r,
                    other => panic!("expected ShutdownRequest, got {other:?}"),
                };
                assert_eq!(
                    req.payload.nonce, nonce,
                    "payload.nonce must echo served nonce"
                );
                assert_eq!(
                    req.payload.agent_id, agent_id,
                    "payload.agent_id must match the file"
                );
                assert_eq!(req.signatures.len(), 2, "exactly 2 sigs in quorum");
                // Both sigs verify against the SAME payload — the
                // design's "one nonce signed by both" resolution.
                verify(&req.payload, &req.signatures[0].signature, &vk_a)
                    .expect("sig_a must verify under key A");
                verify(&req.payload, &req.signatures[1].signature, &vk_b)
                    .expect("sig_b must verify under key B");

                // Step 3: server replies Success.
                server_write_frame(stream, &AdminMessage::ShutdownResult(AdminResult::Success));
            },
            || run_shutdown(&socket_for_client, &priv_a, &priv_b, &agent_id_path, 30),
        );

        let outcome = outcome.expect("client should not error");
        assert!(matches!(outcome, ShutdownOutcome::Success));
    }

    /// External audit CMB-016: `response restore` signs the vault id and
    /// destination into the payload and maps the agent's reply.
    #[test]
    fn cli_response_restore_signs_the_extra_and_maps_the_reply() {
        use nn_proto::admin_signed_payload::OperationExtra;
        let dir = TempDir::new().unwrap();
        let socket = dir.path().join("admin.sock");
        let key = dir.path().join("admin.key");
        let signing = SigningKey::generate(&mut OsRng);
        write_priv_key_file(&key, &signing);
        let agent_id_path = write_agent_id_file(&dir, &[0x5Au8; 16]);
        let vk = signing.verifying_key();
        let socket_for_client = socket.clone();
        let outcome = run_with_mock_server(
            &socket,
            move |stream| {
                let _ = server_read_frame(stream);
                server_write_frame(
                    stream,
                    &AdminMessage::Challenge(nn_proto::admin_protocol::Challenge {
                        nonce: [7u8; 32],
                    }),
                );
                let req = match server_read_frame(stream) {
                    AdminMessage::ResponseRestoreRequest(r) => r,
                    other => panic!("expected ResponseRestoreRequest, got {other:?}"),
                };
                verify(&req.payload, &req.signatures[0].signature, &vk).expect("signed");
                match &req.payload.extra {
                    OperationExtra::ResponseRestore(e) => {
                        assert_eq!(e.vault_id, "ab".repeat(16));
                        assert_eq!(e.to.as_deref(), Some("/tmp/out"));
                    }
                    other => panic!("extra {other:?}"),
                }
                server_write_frame(
                    stream,
                    &AdminMessage::ResponseRestoreResponse(
                        nn_proto::admin_protocol::ResponseRestoreResponse {
                            result: AdminResult::Success,
                            restored: true,
                            path: "/tmp/out".to_string(),
                            message: "restored".to_string(),
                        },
                    ),
                );
            },
            || {
                run_response_restore(
                    &socket_for_client,
                    &key,
                    &agent_id_path,
                    "ab".repeat(16),
                    Some("/tmp/out".to_string()),
                )
            },
        );
        let o = outcome.expect("client should not error");
        assert!(o.done);
        assert_eq!(o.path.as_deref(), Some("/tmp/out"));
    }

    /// External audit ASK-009 (lab PR 213): `status --key` signs a
    /// `TelemetryStatus` payload over the challenge and returns the whole
    /// status, marked signed; a refusal is returned as the agent's result.
    #[test]
    fn cli_telemetry_status_signs_and_maps_the_reply() {
        use nn_proto::admin_protocol::{StatusResponse, TelemetryStatusResponse};
        use nn_proto::admin_signed_payload::{OperationCode, OperationExtra};
        let dir = TempDir::new().unwrap();
        let socket = dir.path().join("admin.sock");
        let key = dir.path().join("admin.key");
        let signing = SigningKey::generate(&mut OsRng);
        write_priv_key_file(&key, &signing);
        let agent_id_path = write_agent_id_file(&dir, &[0x5Au8; 16]);
        for refuse in [false, true] {
            let vk = signing.verifying_key();
            let socket_for_client = socket.clone();
            let _ = std::fs::remove_file(&socket);
            let outcome = run_with_mock_server(
                &socket,
                move |stream| {
                    let _ = server_read_frame(stream);
                    server_write_frame(
                        stream,
                        &AdminMessage::Challenge(nn_proto::admin_protocol::Challenge {
                            nonce: [9u8; 32],
                        }),
                    );
                    let req = match server_read_frame(stream) {
                        AdminMessage::TelemetryStatusRequest(r) => r,
                        other => panic!("expected TelemetryStatusRequest, got {other:?}"),
                    };
                    verify(&req.payload, &req.signatures[0].signature, &vk).expect("signed");
                    assert_eq!(req.payload.op, OperationCode::TelemetryStatus);
                    assert_eq!(req.payload.nonce, [9u8; 32]);
                    assert!(matches!(
                        req.payload.extra,
                        OperationExtra::TelemetryStatus(_)
                    ));
                    let mut status = StatusResponse::public(
                        PostureKind::Alerted,
                        false,
                        None,
                        None,
                        Some(false),
                    );
                    status.ringbuf_drops_total = Some(17);
                    status.detect_only = Some(false);
                    server_write_frame(
                        stream,
                        &AdminMessage::TelemetryStatusResponse(if refuse {
                            TelemetryStatusResponse {
                                result: AdminResult::RoleDenied,
                                status: None,
                            }
                        } else {
                            TelemetryStatusResponse {
                                result: AdminResult::Success,
                                status: Some(status),
                            }
                        }),
                    );
                },
                || run_telemetry_status(&socket_for_client, &key, &agent_id_path),
            );
            let outcome = outcome.expect("client should not error");
            if refuse {
                assert_eq!(outcome.unwrap_err(), AdminResult::RoleDenied);
            } else {
                let out = outcome.expect("signed status");
                assert!(out.telemetry_signed);
                assert_eq!(out.ringbuf_drops_total, Some(17));
                assert_eq!(out.detect_only, Some(false));
                assert_eq!(out.posture, PostureKind::Alerted);
            }
        }
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
        write_priv_key_file(&priv_a, &signing_a);
        write_priv_key_file(&priv_b, &signing_b);
        let agent_id_path = write_agent_id_file(&dir, &[0x21u8; 16]);

        let socket_for_client = socket.clone();
        let outcome = run_with_mock_server(
            &socket,
            move |stream| {
                let _ = server_read_frame(stream);
                server_write_frame(
                    stream,
                    &AdminMessage::Challenge(nn_proto::admin_protocol::Challenge {
                        nonce: [0u8; 32],
                    }),
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
        write_priv_key_file(&priv_a, &signing_a);
        write_priv_key_file(&priv_b, &signing_b);
        let agent_id_path = write_agent_id_file(&dir, &[0x21u8; 16]);

        let socket_for_client = socket.clone();
        let outcome = run_with_mock_server(
            &socket,
            move |stream| {
                let _ = server_read_frame(stream);
                server_write_frame(
                    stream,
                    &AdminMessage::Challenge(nn_proto::admin_protocol::Challenge {
                        nonce: [0u8; 32],
                    }),
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
            format!(
                "{}\n",
                hex::encode(SigningKey::generate(&mut OsRng).to_bytes())
            ),
        )
        .unwrap();
        std::fs::write(
            &priv_b,
            format!(
                "{}\n",
                hex::encode(SigningKey::generate(&mut OsRng).to_bytes())
            ),
        )
        .unwrap();
        let agent_id_path = write_agent_id_file(&dir, &[0x21u8; 16]);
        let socket = dir.path().join("never_bound.sock");

        let err = run_shutdown(&socket, &priv_a, &priv_b, &agent_id_path, 9999).unwrap_err();
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

    // ── Test 1 (A12 #1): read on a missing log returns 0 with no
    //                    spurious error (fresh install state).
    #[test]
    fn audit_read_missing_log_returns_zero() {
        let dir = TempDir::new().unwrap();
        let nowhere = dir.path().join("does-not-exist.jsonl");
        let n = run_audit_read(&nowhere, None, false).expect("missing log is not an error");
        assert_eq!(n, AuditReadReport::default());
    }
    /// chain-persist-1: a persistence failure must not masquerade as
    /// "detection not found" — the wire flag maps to its own outcome.
    #[test]
    fn set_status_persist_failure_is_distinguishable_from_not_found() {
        use nn_proto::admin_protocol::DetectionSetStatusResponse;
        let not_found = DetectionSetStatusResponse {
            result: AdminResult::UnknownOperation,
            id: 7,
            new_status: String::new(),
            persist_failed: false,
        };
        assert!(matches!(
            map_response_to_set_status(not_found),
            DetectionSetStatusOutcome::NotFound
        ));
        let persist = DetectionSetStatusResponse {
            result: AdminResult::UnknownOperation,
            id: 7,
            new_status: String::new(),
            persist_failed: true,
        };
        assert!(matches!(
            map_response_to_set_status(persist),
            DetectionSetStatusOutcome::PersistFailed { id: 7 }
        ));
    }
}
