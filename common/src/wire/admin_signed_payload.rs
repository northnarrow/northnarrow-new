//! Signed administrative payload for Tappa 8 operations
//! (`docs/design/TAPPA8_ED25519_ADMIN_OVERRIDE_DESIGN.md` §6.3).
//!
//! Every operation that mutates protected agent state — `unlock`,
//! `shutdown`, `force-posture`, `rotate-keys`, `audit-read` — carries
//! an Ed25519 signature over a [`SignedPayload`]. Putting the
//! operation **inside** the signed scope (rather than signing only
//! the server nonce as the legacy unlock path does) prevents
//! cross-operation signature replay: a signature minted for `unlock`
//! cannot be presented in a `shutdown` frame even if the wire
//! variants happened to overlap byte-for-byte.
//!
//! ## Signed bytes
//!
//! The bytes the Ed25519 key signs are
//!
//! ```text
//! signing_input = SHA-512(SIGNED_PAYLOAD_DOMAIN_SEP || cbor(SignedPayload))
//! ```
//!
//! — i.e. a 64-byte digest, not the raw CBOR. Pre-hashing reduces the
//! signing surface to a fixed-size constant regardless of how big
//! `extra` is, and the explicit byte-string domain separator
//! [`SIGNED_PAYLOAD_DOMAIN_SEP`] (`b"northnarrow.admin.v1"`) makes a
//! signature on an admin payload computationally distinct from
//! signatures over any other NorthNarrow payload type that might
//! exist in the future. Verification re-serialises locally and
//! re-hashes; we never trust a peer-supplied digest.
//!
//! ## Wire shape
//!
//! ```text
//! SignedPayload = {
//!     op:        OperationCode (u8 discriminant on the wire),
//!     nonce:     [u8; 32],   // server-issued, one-shot
//!     ts:        u64,        // client wall-clock, seconds since epoch
//!     agent_id:  [u8; 16],   // agent install UUID (design §6.5)
//!     extra:     OperationExtra,
//! }
//! ```
//!
//! The serialisation format is CBOR (RFC 8949) via `ciborium`.
//! Deterministic re-encoding of the same Rust value is a load-bearing
//! property (verification compares bytes after re-serialisation); see
//! the `cbor_encoding_is_deterministic` test for the regression
//! anchor.
//!
//! ## Why this commit doesn't wire anything to the dispatcher
//!
//! A2 is the value-and-verify layer only. The agent's `admin_socket`
//! dispatcher continues to handle the existing `Unlock` /
//! `ChallengeRequest` / `Status` variants with the pre-Tappa-8
//! signing semantics. The dispatcher gains a code path that consumes
//! `SignedPayload` when commit A7 lands `AdminMessage::ShutdownRequest`
//! and the new operations actually arrive on the wire.
//!
//! ## Threat-model note (design §1.3 row "Off-host attacker with a
//! ## captured nonce + old signature")
//!
//! The signed payload binds (a) the server-issued nonce, (b) a
//! client-supplied timestamp the server checks against its own clock
//! in A4, and (c) the per-agent install UUID. A captured signature
//! is rejected by at least one of these three layers on every
//! plausible replay attempt — same-host (nonce already consumed),
//! later-boot (timestamp skew), different-host (`agent_id` mismatch).

use alloc::string::String;
use alloc::vec::Vec;

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey, SIGNATURE_LENGTH};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha512};

use crate::posture_types::PostureKind;

/// Domain-separation prefix mixed into the SHA-512 input before the
/// CBOR-encoded payload. Format is `northnarrow.<scope>.v<version>`;
/// bump the trailing `v1` only when the signing rules themselves
/// change in a backward-incompatible way (NOT when adding a new
/// [`OperationCode`] variant — the existing scheme already covers
/// new ops by virtue of `op` being inside the signed scope).
pub const SIGNED_PAYLOAD_DOMAIN_SEP: &[u8] = b"northnarrow.admin.v1";

/// Length of the SHA-512 digest the Ed25519 key actually signs.
pub const SIGNING_DIGEST_LEN: usize = 64;

/// Numeric operation tag carried in [`SignedPayload::op`]. Values are
/// **stable on the wire** — never renumber. New operations append to
/// the bottom of the enum and pick the next free discriminant. The
/// `serde(into = "u8", try_from = "u8")` attribute pair makes the
/// wire form a bare `u8`, so the CBOR shape matches the design spec
/// (`op: u8`) while Rust retains the type-safety of the enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(into = "u8", try_from = "u8")]
#[repr(u8)]
pub enum OperationCode {
    Unlock = 1,
    Shutdown = 2,
    ForcePosture = 3,
    RotateKeysAdd = 4,
    RotateKeysRevoke = 5,
    AuditRead = 6,
    /// Tappa 9 (C1) — operator-initiated FIM baseline
    /// (re)computation. Authorised by `Role::FimManage`.
    FimBaseline = 7,
    /// Tappa 9 (C1) — operator-initiated read of the chained
    /// `fim_drift.jsonl`. Authorised by `Role::FimRead`.
    FimReport = 8,
    /// Tappa 9 (C7) — operator-initiated read of in-process FIM
    /// state: token-bucket counts, paths watched, last baseline
    /// timestamp. No on-disk side effects. Authorised by
    /// `Role::FimRead` (read-only).
    FimStatus = 9,
}

impl From<OperationCode> for u8 {
    fn from(op: OperationCode) -> Self {
        op as u8
    }
}

impl TryFrom<u8> for OperationCode {
    type Error = SignedPayloadError;
    fn try_from(v: u8) -> Result<Self, Self::Error> {
        match v {
            1 => Ok(Self::Unlock),
            2 => Ok(Self::Shutdown),
            3 => Ok(Self::ForcePosture),
            4 => Ok(Self::RotateKeysAdd),
            5 => Ok(Self::RotateKeysRevoke),
            6 => Ok(Self::AuditRead),
            7 => Ok(Self::FimBaseline),
            8 => Ok(Self::FimReport),
            9 => Ok(Self::FimStatus),
            other => Err(SignedPayloadError::UnknownOperationCode(other)),
        }
    }
}

/// Admin-key role tag carried in [`RotateKeysAddExtra::roles`] and
/// (in commit A5) parsed out of `/etc/northnarrow/admin.pub` lines.
/// Same wire-stability rules as [`OperationCode`].
///
/// Role-to-operation mapping (design §4 table):
/// - `Unlock` authorises `unlock`
/// - `Shutdown` authorises `shutdown` (quorum member)
/// - `ForcePosture` authorises `force-posture`
/// - `RotateKeys` authorises `rotate-keys add`/`revoke` (quorum member)
/// - `AuditRead` authorises `audit-read`
/// - `All` is the break-glass role — authorises any of the above
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(into = "u8", try_from = "u8")]
#[repr(u8)]
pub enum Role {
    Unlock = 1,
    Shutdown = 2,
    ForcePosture = 3,
    RotateKeys = 4,
    AuditRead = 5,
    /// Tappa 9 (C1) — authorises `fim baseline` (compute + write
    /// new baseline rows) AND the `disable:` list in
    /// `fim-paths.local` (Q7 resolution). Operationally the
    /// higher-privilege FIM role.
    FimManage = 6,
    /// Tappa 9 (C1) — authorises `fim status` + `fim report`
    /// (read the chained drift log + acknowledge entries). The
    /// lower-privilege FIM role; defaults to operators who hold
    /// `AuditRead` since FIM read is the same trust level.
    FimRead = 7,
    All = 255,
}

impl From<Role> for u8 {
    fn from(r: Role) -> Self {
        r as u8
    }
}

impl TryFrom<u8> for Role {
    type Error = SignedPayloadError;
    fn try_from(v: u8) -> Result<Self, Self::Error> {
        match v {
            1 => Ok(Self::Unlock),
            2 => Ok(Self::Shutdown),
            3 => Ok(Self::ForcePosture),
            4 => Ok(Self::RotateKeys),
            5 => Ok(Self::AuditRead),
            6 => Ok(Self::FimManage),
            7 => Ok(Self::FimRead),
            255 => Ok(Self::All),
            other => Err(SignedPayloadError::UnknownRole(other)),
        }
    }
}

/// Op-specific signed-scope fields for [`OperationCode::Unlock`].
/// Empty today — the nonce + ts + agent_id binding in the outer
/// [`SignedPayload`] is sufficient. Kept as a named struct (not a
/// unit variant) so a future field addition is backward-compatible
/// at the CBOR level.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct UnlockExtra {}

/// Op-specific signed-scope fields for [`OperationCode::Shutdown`].
/// `grace_secs` is the operator-chosen window the agent will use to
/// drain work before exit (design §10.2, default 30, cap 300).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShutdownExtra {
    pub grace_secs: u32,
}

/// Op-specific signed-scope fields for
/// [`OperationCode::ForcePosture`] (design §12.2). The target state
/// is fully arbitrary — the production rule is that any
/// state→state transition is allowed under the `force-posture` role,
/// and the audit log captures both source and target.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ForcePostureExtra {
    pub target: PostureKind,
}

/// Op-specific signed-scope fields for [`OperationCode::RotateKeysAdd`]
/// (design §7.2). `new_pubkey` is the raw 32-byte Ed25519 verifying
/// key to install. `roles` is the (non-empty) role allowlist the
/// new key is being installed with.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RotateKeysAddExtra {
    pub new_pubkey: [u8; 32],
    pub roles: Vec<Role>,
}

/// Op-specific signed-scope fields for
/// [`OperationCode::RotateKeysRevoke`] (design §7.3). `fingerprint`
/// is the 4-byte short form `SHA-256(pubkey)[..4]` already used by
/// the existing `nn-admin verify-keys` output.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct RotateKeysRevokeExtra {
    pub fingerprint: [u8; 4],
}

/// Op-specific signed-scope fields for [`OperationCode::AuditRead`]
/// (design §5.2, §9.3). `since_unix_ts` is the lower-bound filter
/// for the streamed export; `None` means "from genesis."
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct AuditReadExtra {
    pub since_unix_ts: Option<u64>,
}

/// Op-specific signed-scope fields for [`OperationCode::FimBaseline`]
/// (Tappa 9 design §5 + §6.1). Empty today — the agent's default
/// behaviour is to rebaseline every path in `WATCHED_PATHS`. A
/// future field could narrow to a single path; kept as a named
/// struct (not a unit variant) so a future addition is backward-
/// compatible at the CBOR level.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct FimBaselineExtra {}

/// Op-specific signed-scope fields for [`OperationCode::FimReport`]
/// (Tappa 9 design §6.3 + §9). `since_unix_ts` filters the streamed
/// drift log to events at-or-after the threshold; `None` means
/// "from genesis."
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct FimReportExtra {
    pub since_unix_ts: Option<u64>,
}

/// Op-specific signed-scope fields for [`OperationCode::FimStatus`]
/// (Tappa 9 C7 — C6 deferral). Empty today; the response carries
/// the entire status snapshot. Kept as a named struct (not a unit
/// variant) so a future filter field can be added without an op
/// renumber.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct FimStatusExtra {}

/// Discriminated union of every op-specific extra. The variant order
/// MUST track [`OperationCode`] (Unlock, Shutdown, …); a SignedPayload
/// whose `op` and `extra` variants disagree is well-formed at the
/// CBOR layer but considered semantically invalid by [`verify`] (see
/// `verify_rejects_op_extra_mismatch` for the regression test).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum OperationExtra {
    Unlock(UnlockExtra),
    Shutdown(ShutdownExtra),
    ForcePosture(ForcePostureExtra),
    RotateKeysAdd(RotateKeysAddExtra),
    RotateKeysRevoke(RotateKeysRevokeExtra),
    AuditRead(AuditReadExtra),
    /// Tappa 9 (C1). Pairs with [`OperationCode::FimBaseline`].
    FimBaseline(FimBaselineExtra),
    /// Tappa 9 (C1). Pairs with [`OperationCode::FimReport`].
    FimReport(FimReportExtra),
    /// Tappa 9 (C7). Pairs with [`OperationCode::FimStatus`].
    FimStatus(FimStatusExtra),
}

impl OperationExtra {
    /// The [`OperationCode`] that this extra variant is paired with.
    /// Used by [`verify`] to enforce the op/extra invariant before
    /// running the Ed25519 check.
    pub fn op_code(&self) -> OperationCode {
        match self {
            OperationExtra::Unlock(_) => OperationCode::Unlock,
            OperationExtra::Shutdown(_) => OperationCode::Shutdown,
            OperationExtra::ForcePosture(_) => OperationCode::ForcePosture,
            OperationExtra::RotateKeysAdd(_) => OperationCode::RotateKeysAdd,
            OperationExtra::RotateKeysRevoke(_) => OperationCode::RotateKeysRevoke,
            OperationExtra::AuditRead(_) => OperationCode::AuditRead,
            OperationExtra::FimBaseline(_) => OperationCode::FimBaseline,
            OperationExtra::FimReport(_) => OperationCode::FimReport,
            OperationExtra::FimStatus(_) => OperationCode::FimStatus,
        }
    }
}

/// The full signed-scope value. Re-serialised locally by [`verify`]
/// before re-hashing, so the wire bytes for `extra`/`op`/etc. cannot
/// be tweaked to slip an alternative CBOR encoding past the
/// signature check.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedPayload {
    pub op: OperationCode,
    pub nonce: [u8; 32],
    pub ts: u64,
    pub agent_id: [u8; 16],
    pub extra: OperationExtra,
}

/// Errors from the [`SignedPayload`] sign/verify path. Surfaced
/// distinctly so the dispatcher in A7 can map them to the
/// `AdminResult` variants in design §6.6.
#[derive(Debug)]
pub enum SignedPayloadError {
    /// CBOR (de)serialisation failed. In practice this only fires
    /// in [`verify`] when the local re-serialise path encounters a
    /// `serde` impl bug — well-formed payloads built via the public
    /// constructors should never trip it.
    Cbor(String),
    /// Ed25519 signature verification rejected the bytes.
    InvalidSignature,
    /// [`SignedPayload::op`] and [`OperationExtra`]'s variant tag
    /// disagree. The CBOR layer cannot enforce this on its own
    /// (both fields independently round-trip), so [`verify`] checks
    /// it explicitly.
    OperationExtraMismatch {
        op: OperationCode,
        extra_op: OperationCode,
    },
    /// A peer wire byte did not match any known [`OperationCode`]
    /// discriminant. Bubbles up out of `OperationCode::try_from`
    /// during `serde` deserialisation.
    UnknownOperationCode(u8),
    /// A peer wire byte did not match any known [`Role`]
    /// discriminant.
    UnknownRole(u8),
}

impl core::fmt::Display for SignedPayloadError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Cbor(e) => write!(f, "CBOR (de)serialisation failed: {e}"),
            Self::InvalidSignature => write!(f, "Ed25519 signature verification failed"),
            Self::OperationExtraMismatch { op, extra_op } => write!(
                f,
                "op/extra mismatch: payload.op={op:?} but extra is for {extra_op:?}"
            ),
            Self::UnknownOperationCode(v) => write!(f, "unknown operation code {v}"),
            Self::UnknownRole(v) => write!(f, "unknown role {v}"),
        }
    }
}

impl std::error::Error for SignedPayloadError {}

/// Build the 64-byte SHA-512 digest that the Ed25519 key signs.
/// Caller-facing helper for unit tests and for the off-host
/// `nn-admin audit verify` path; production sign/verify go through
/// [`sign`] / [`verify`].
pub fn signing_digest(payload: &SignedPayload) -> Result<[u8; SIGNING_DIGEST_LEN], SignedPayloadError> {
    let cbor = encode_cbor(payload)?;
    let mut h = Sha512::new();
    h.update(SIGNED_PAYLOAD_DOMAIN_SEP);
    h.update(&cbor);
    let out = h.finalize();
    let mut digest = [0u8; SIGNING_DIGEST_LEN];
    digest.copy_from_slice(&out);
    Ok(digest)
}

/// CBOR-encode `payload` for hashing / wire transport. Centralised so
/// every caller produces the same byte sequence for the same Rust
/// value — that determinism is exactly what makes
/// `signing_digest(payload)` reproducible across the client and the
/// server. See `cbor_encoding_is_deterministic` for the regression
/// anchor.
pub fn encode_cbor(payload: &SignedPayload) -> Result<Vec<u8>, SignedPayloadError> {
    let mut buf = Vec::new();
    ciborium::ser::into_writer(payload, &mut buf)
        .map_err(|e| SignedPayloadError::Cbor(alloc::format!("encode: {e}")))?;
    Ok(buf)
}

/// CBOR-decode bytes back into a [`SignedPayload`]. Used by the
/// `nn-admin audit verify` flow and by future v1 dispatcher work.
pub fn decode_cbor(buf: &[u8]) -> Result<SignedPayload, SignedPayloadError> {
    ciborium::de::from_reader(buf)
        .map_err(|e| SignedPayloadError::Cbor(alloc::format!("decode: {e}")))
}

/// Produce a 64-byte Ed25519 signature over the
/// [`SIGNED_PAYLOAD_DOMAIN_SEP`]-separated SHA-512 digest of
/// `payload`. The caller is responsible for transmitting both the
/// payload and the signature; the server reconstructs `payload`,
/// re-runs [`signing_digest`], and calls [`verify`].
pub fn sign(
    payload: &SignedPayload,
    signing_key: &SigningKey,
) -> Result<[u8; SIGNATURE_LENGTH], SignedPayloadError> {
    let digest = signing_digest(payload)?;
    let sig: Signature = signing_key.sign(&digest);
    Ok(sig.to_bytes())
}

/// Verify `signature` against `payload` under `verifying_key`.
///
/// The verification re-serialises `payload` locally and re-hashes
/// before calling `ed25519-dalek`'s `verify_strict` — so a peer
/// cannot alter the wire bytes between hashing and Ed25519 without
/// breaking the signature. The op/extra invariant is checked first
/// because a mismatch indicates malformed input regardless of the
/// signature outcome and surfaces a more actionable error.
pub fn verify(
    payload: &SignedPayload,
    signature: &[u8; SIGNATURE_LENGTH],
    verifying_key: &VerifyingKey,
) -> Result<(), SignedPayloadError> {
    let extra_op = payload.extra.op_code();
    if payload.op != extra_op {
        return Err(SignedPayloadError::OperationExtraMismatch {
            op: payload.op,
            extra_op,
        });
    }
    let digest = signing_digest(payload)?;
    let sig = Signature::from_bytes(signature);
    verifying_key
        .verify_strict(&digest, &sig)
        .map_err(|_| SignedPayloadError::InvalidSignature)
}

/// Cheap constructor: build an `UnlockExtra`-carrying payload from
/// the four shared fields. Mirror constructors for the other ops can
/// be added when their consuming commits (A7+) need them.
impl SignedPayload {
    pub fn new_unlock(nonce: [u8; 32], ts: u64, agent_id: [u8; 16]) -> Self {
        Self {
            op: OperationCode::Unlock,
            nonce,
            ts,
            agent_id,
            extra: OperationExtra::Unlock(UnlockExtra {}),
        }
    }

    pub fn new_shutdown(
        nonce: [u8; 32],
        ts: u64,
        agent_id: [u8; 16],
        grace_secs: u32,
    ) -> Self {
        Self {
            op: OperationCode::Shutdown,
            nonce,
            ts,
            agent_id,
            extra: OperationExtra::Shutdown(ShutdownExtra { grace_secs }),
        }
    }

    pub fn new_force_posture(
        nonce: [u8; 32],
        ts: u64,
        agent_id: [u8; 16],
        target: PostureKind,
    ) -> Self {
        Self {
            op: OperationCode::ForcePosture,
            nonce,
            ts,
            agent_id,
            extra: OperationExtra::ForcePosture(ForcePostureExtra { target }),
        }
    }

    pub fn new_rotate_keys_add(
        nonce: [u8; 32],
        ts: u64,
        agent_id: [u8; 16],
        new_pubkey: [u8; 32],
        roles: Vec<Role>,
    ) -> Self {
        Self {
            op: OperationCode::RotateKeysAdd,
            nonce,
            ts,
            agent_id,
            extra: OperationExtra::RotateKeysAdd(RotateKeysAddExtra { new_pubkey, roles }),
        }
    }

    pub fn new_rotate_keys_revoke(
        nonce: [u8; 32],
        ts: u64,
        agent_id: [u8; 16],
        fingerprint: [u8; 4],
    ) -> Self {
        Self {
            op: OperationCode::RotateKeysRevoke,
            nonce,
            ts,
            agent_id,
            extra: OperationExtra::RotateKeysRevoke(RotateKeysRevokeExtra { fingerprint }),
        }
    }

    pub fn new_audit_read(
        nonce: [u8; 32],
        ts: u64,
        agent_id: [u8; 16],
        since_unix_ts: Option<u64>,
    ) -> Self {
        Self {
            op: OperationCode::AuditRead,
            nonce,
            ts,
            agent_id,
            extra: OperationExtra::AuditRead(AuditReadExtra { since_unix_ts }),
        }
    }

    /// Tappa 9 (C1) — `fim baseline` signed payload constructor.
    /// The `FimBaselineExtra` is empty today (default-construct) —
    /// the agent rebaselines every path in WATCHED_PATHS. Future
    /// fields could narrow to a single path; kept as a constructor
    /// rather than an `extra` parameter so the call-site shape
    /// matches the other ops.
    pub fn new_fim_baseline(nonce: [u8; 32], ts: u64, agent_id: [u8; 16]) -> Self {
        Self {
            op: OperationCode::FimBaseline,
            nonce,
            ts,
            agent_id,
            extra: OperationExtra::FimBaseline(FimBaselineExtra {}),
        }
    }

    /// Tappa 9 (C1) — `fim report` signed payload constructor.
    /// `since_unix_ts` filters the streamed drift log; `None`
    /// means "from genesis." Mirrors [`Self::new_audit_read`].
    pub fn new_fim_report(
        nonce: [u8; 32],
        ts: u64,
        agent_id: [u8; 16],
        since_unix_ts: Option<u64>,
    ) -> Self {
        Self {
            op: OperationCode::FimReport,
            nonce,
            ts,
            agent_id,
            extra: OperationExtra::FimReport(FimReportExtra { since_unix_ts }),
        }
    }

    /// Tappa 9 (C7) — `fim status` signed payload constructor.
    /// Read-only op surfacing the in-process FIM state snapshot;
    /// extra is empty since the response carries the entire
    /// snapshot.
    pub fn new_fim_status(nonce: [u8; 32], ts: u64, agent_id: [u8; 16]) -> Self {
        Self {
            op: OperationCode::FimStatus,
            nonce,
            ts,
            agent_id,
            extra: OperationExtra::FimStatus(FimStatusExtra {}),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;

    /// Deterministic keypair: the same bytes every run, so test
    /// failures are reproducible without an `OsRng` dep in `common`.
    fn fixed_keypair() -> (SigningKey, VerifyingKey) {
        let signing = SigningKey::from_bytes(&[0x42; 32]);
        let verifying = signing.verifying_key();
        (signing, verifying)
    }

    fn nonce() -> [u8; 32] {
        [0xAB; 32]
    }
    fn agent_id() -> [u8; 16] {
        [0xCD; 16]
    }
    const TS: u64 = 1_710_000_000;

    /// Helper: build one [`SignedPayload`] per [`OperationCode`] so
    /// each test can iterate over all operations in one place.
    /// Tappa 9 (C1) grew the array from 6 to 8 with `FimBaseline`
    /// and `FimReport`; Tappa 9 (C7) added `FimStatus`.
    fn one_payload_per_op() -> [SignedPayload; 9] {
        [
            SignedPayload::new_unlock(nonce(), TS, agent_id()),
            SignedPayload::new_shutdown(nonce(), TS, agent_id(), 30),
            SignedPayload::new_force_posture(nonce(), TS, agent_id(), PostureKind::Alerted),
            SignedPayload::new_rotate_keys_add(
                nonce(),
                TS,
                agent_id(),
                [0x77; 32],
                vec![Role::Unlock, Role::AuditRead],
            ),
            SignedPayload::new_rotate_keys_revoke(nonce(), TS, agent_id(), [0x11, 0x22, 0x33, 0x44]),
            SignedPayload::new_audit_read(nonce(), TS, agent_id(), Some(1_700_000_000)),
            SignedPayload::new_fim_baseline(nonce(), TS, agent_id()),
            SignedPayload::new_fim_report(nonce(), TS, agent_id(), Some(1_700_000_000)),
            SignedPayload::new_fim_status(nonce(), TS, agent_id()),
        ]
    }

    // ── A2 required tests ──────────────────────────────────────────

    /// Required A2 test 1 (covers "one per op"): sign + verify
    /// round-trip for every [`OperationCode`]. Proves the typed
    /// constructors agree with the op/extra invariant and the
    /// digest/signature pipeline.
    #[test]
    fn sign_and_verify_round_trip_for_every_operation_code() {
        let (signing, verifying) = fixed_keypair();
        for payload in one_payload_per_op() {
            let sig = sign(&payload, &signing).expect("sign");
            verify(&payload, &sig, &verifying).expect("verify");
        }
    }

    /// Required A2 test 2 (covers "tamper-detection"): mutating ANY
    /// shared field of the payload after signing must break
    /// verification. Exercises four representative mutations per op
    /// (nonce, ts, agent_id, op) — the op mutation is the most
    /// interesting because it's also what cross-op replay would do.
    #[test]
    fn verify_rejects_tampered_payload_fields() {
        let (signing, verifying) = fixed_keypair();
        let original = SignedPayload::new_shutdown(nonce(), TS, agent_id(), 30);
        let sig = sign(&original, &signing).expect("sign");

        // Sanity: untouched payload verifies.
        verify(&original, &sig, &verifying).expect("baseline verify");

        // Flip nonce.
        let mut bad_nonce = original.clone();
        bad_nonce.nonce[0] ^= 0x01;
        assert!(matches!(
            verify(&bad_nonce, &sig, &verifying),
            Err(SignedPayloadError::InvalidSignature)
        ));

        // Bump ts.
        let mut bad_ts = original.clone();
        bad_ts.ts = bad_ts.ts.wrapping_add(1);
        assert!(matches!(
            verify(&bad_ts, &sig, &verifying),
            Err(SignedPayloadError::InvalidSignature)
        ));

        // Replace agent_id (different host).
        let mut bad_agent = original.clone();
        bad_agent.agent_id[0] ^= 0xFF;
        assert!(matches!(
            verify(&bad_agent, &sig, &verifying),
            Err(SignedPayloadError::InvalidSignature)
        ));

        // Cross-op replay: change the op tag while keeping the same
        // extra. The op/extra invariant trips FIRST, surfacing the
        // mismatch — and the signature would also reject it after,
        // but the explicit mismatch error is the more actionable
        // signal for the dispatcher.
        let mut bad_op = original.clone();
        bad_op.op = OperationCode::Unlock;
        match verify(&bad_op, &sig, &verifying) {
            Err(SignedPayloadError::OperationExtraMismatch { op, extra_op }) => {
                assert_eq!(op, OperationCode::Unlock);
                assert_eq!(extra_op, OperationCode::Shutdown);
            }
            other => panic!("expected OperationExtraMismatch, got {other:?}"),
        }
    }

    /// Required A2 test 3 (covers "tamper-detection" via signature
    /// bytes): flipping ANY bit of the signature must break verify.
    /// Tests the boundary bytes (0, mid, last) so a regression that
    /// only checked a prefix would catch.
    #[test]
    fn verify_rejects_tampered_signature_bytes() {
        let (signing, verifying) = fixed_keypair();
        let payload = SignedPayload::new_unlock(nonce(), TS, agent_id());
        let sig = sign(&payload, &signing).expect("sign");

        for idx in [0usize, SIGNATURE_LENGTH / 2, SIGNATURE_LENGTH - 1] {
            let mut bad = sig;
            bad[idx] ^= 0x01;
            match verify(&payload, &bad, &verifying) {
                Err(SignedPayloadError::InvalidSignature) => {}
                other => panic!("flip at byte {idx}: expected InvalidSignature, got {other:?}"),
            }
        }
    }

    /// Required A2 test 4 (covers "cbor-stability"): two encodes of
    /// the same Rust value MUST produce byte-identical CBOR. This is
    /// the load-bearing property [`verify`] depends on — the
    /// re-serialise-then-hash path only catches tampering when the
    /// re-serialised bytes match the originally-signed bytes exactly.
    #[test]
    fn cbor_encoding_is_deterministic() {
        for payload in one_payload_per_op() {
            let bytes_1 = encode_cbor(&payload).expect("encode 1");
            let bytes_2 = encode_cbor(&payload).expect("encode 2");
            assert_eq!(
                bytes_1, bytes_2,
                "non-deterministic CBOR for {:?}",
                payload.op
            );
            // Round-trip through decode_cbor lands at the same value.
            let decoded = decode_cbor(&bytes_1).expect("decode");
            assert_eq!(decoded, payload);
        }
    }

    // ── Supplementary tests (defence in depth) ─────────────────────

    /// Signing with key A and verifying with B's pubkey fails — the
    /// signature is a property of the keypair, not the payload alone.
    #[test]
    fn verify_rejects_signature_from_wrong_keypair() {
        let (signing_a, _) = fixed_keypair();
        let signing_b = SigningKey::from_bytes(&[0x99; 32]);
        let verifying_b = signing_b.verifying_key();

        let payload = SignedPayload::new_unlock(nonce(), TS, agent_id());
        let sig_a = sign(&payload, &signing_a).expect("sign with A");

        match verify(&payload, &sig_a, &verifying_b) {
            Err(SignedPayloadError::InvalidSignature) => {}
            other => panic!("expected InvalidSignature, got {other:?}"),
        }
    }

    /// The domain separator is mixed in BEFORE the CBOR — proving
    /// that hash(domain || cbor) ≠ hash(other_domain || cbor) keeps
    /// signatures over admin payloads cryptographically distinct
    /// from any future NorthNarrow signed-payload scheme.
    #[test]
    fn signing_digest_changes_when_domain_separator_changes() {
        let payload = SignedPayload::new_unlock(nonce(), TS, agent_id());
        let digest_real = signing_digest(&payload).expect("digest");

        // Recompute the digest with a hand-changed domain separator.
        let cbor = encode_cbor(&payload).expect("encode");
        let mut h = Sha512::new();
        h.update(b"northnarrow.NOTadmin.v1"); // different prefix, same length isn't even required
        h.update(&cbor);
        let digest_alt = h.finalize();

        assert_ne!(
            digest_real.as_slice(),
            digest_alt.as_slice(),
            "domain separator change must change the digest"
        );
    }

    /// Discriminant freeze: the numeric wire values of
    /// [`OperationCode`] are part of the protocol contract. A future
    /// renumber would silently misroute operations.
    #[test]
    fn operation_code_discriminants_are_stable_on_the_wire() {
        let cases = [
            (OperationCode::Unlock, 1u8),
            (OperationCode::Shutdown, 2),
            (OperationCode::ForcePosture, 3),
            (OperationCode::RotateKeysAdd, 4),
            (OperationCode::RotateKeysRevoke, 5),
            (OperationCode::AuditRead, 6),
            // Tappa 9 (C1) additions — APPENDED, never renumber.
            (OperationCode::FimBaseline, 7),
            (OperationCode::FimReport, 8),
            // Tappa 9 (C7) — APPENDED, never renumber.
            (OperationCode::FimStatus, 9),
        ];
        for (op, expected) in cases {
            assert_eq!(u8::from(op), expected, "{op:?}");
            assert_eq!(
                OperationCode::try_from(expected).expect("known code"),
                op
            );
        }
        // Out-of-range bytes surface as UnknownOperationCode.
        match OperationCode::try_from(0u8) {
            Err(SignedPayloadError::UnknownOperationCode(0)) => {}
            other => panic!("expected UnknownOperationCode(0), got {other:?}"),
        }
        match OperationCode::try_from(99u8) {
            Err(SignedPayloadError::UnknownOperationCode(99)) => {}
            other => panic!("expected UnknownOperationCode(99), got {other:?}"),
        }
    }

    /// Same discriminant-freeze guard for [`Role`], including the
    /// non-contiguous `All = 255` value.
    #[test]
    fn role_discriminants_are_stable_on_the_wire() {
        let cases = [
            (Role::Unlock, 1u8),
            (Role::Shutdown, 2),
            (Role::ForcePosture, 3),
            (Role::RotateKeys, 4),
            (Role::AuditRead, 5),
            // Tappa 9 (C1) additions — APPENDED, never renumber.
            (Role::FimManage, 6),
            (Role::FimRead, 7),
            (Role::All, 255),
        ];
        for (r, expected) in cases {
            assert_eq!(u8::from(r), expected, "{r:?}");
            assert_eq!(Role::try_from(expected).expect("known role"), r);
        }
        match Role::try_from(100u8) {
            Err(SignedPayloadError::UnknownRole(100)) => {}
            other => panic!("expected UnknownRole(100), got {other:?}"),
        }
    }

    /// A hand-constructed payload with the `op` field deliberately
    /// out of sync with the `extra` variant must be rejected by
    /// [`verify`] BEFORE the Ed25519 path runs — the dispatcher in
    /// A7 will rely on this so the audit log can record a precise
    /// "operation/extra mismatch" reason rather than a vague
    /// "InvalidSignature."
    #[test]
    fn verify_rejects_op_extra_mismatch_before_signature_check() {
        // Build a malformed payload by hand (the constructors won't
        // let you produce one).
        let payload = SignedPayload {
            op: OperationCode::Unlock,
            nonce: nonce(),
            ts: TS,
            agent_id: agent_id(),
            extra: OperationExtra::Shutdown(ShutdownExtra { grace_secs: 0 }),
        };

        // Use a real key + signature so the InvalidSignature path
        // would also have a "valid" path to follow — we want to
        // prove the mismatch check fires FIRST.
        let (signing, verifying) = fixed_keypair();
        let sig = signing.sign(&signing_digest(&payload).unwrap()).to_bytes();

        match verify(&payload, &sig, &verifying) {
            Err(SignedPayloadError::OperationExtraMismatch { op, extra_op }) => {
                assert_eq!(op, OperationCode::Unlock);
                assert_eq!(extra_op, OperationCode::Shutdown);
            }
            other => panic!("expected OperationExtraMismatch first, got {other:?}"),
        }
    }

    /// C1 + C7 test — focused coverage of the three FIM
    /// [`SignedPayload`] constructors (`new_fim_baseline` +
    /// `new_fim_report` + `new_fim_status`): each produces a
    /// payload whose `op` agrees with its `extra` variant tag,
    /// signs + verifies against a fresh keypair, and round-trips
    /// through cbor without bit-level drift. The other tests in
    /// this module pick up the new ops automatically via
    /// `one_payload_per_op`, but this anchors them explicitly so
    /// a future refactor that drops them from the helper still
    /// leaves the wire coverage intact.
    #[test]
    fn new_fim_constructors_round_trip_sign_and_verify() {
        let (signing, verifying) = fixed_keypair();
        for payload in [
            SignedPayload::new_fim_baseline(nonce(), TS, agent_id()),
            SignedPayload::new_fim_report(nonce(), TS, agent_id(), Some(1_700_000_000)),
            SignedPayload::new_fim_status(nonce(), TS, agent_id()),
        ] {
            // op/extra invariant holds by construction.
            assert_eq!(payload.op, payload.extra.op_code());
            // Sign-verify round-trip.
            let digest = signing_digest(&payload).expect("digest");
            let sig = signing.sign(&digest).to_bytes();
            verify(&payload, &sig, &verifying).expect("verify");
            // Cbor round-trip (no field-order drift).
            let bytes = {
                let mut v = Vec::new();
                ciborium::ser::into_writer(&payload, &mut v).expect("cbor encode");
                v
            };
            let restored: SignedPayload =
                ciborium::de::from_reader(&bytes[..]).expect("cbor decode");
            assert_eq!(restored, payload);
        }
    }
}
