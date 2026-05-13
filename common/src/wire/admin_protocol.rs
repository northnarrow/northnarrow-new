//! nn-admin ↔ agent wire protocol (Tappa 7 task 7 / Tappa 8).
//!
//! Carried over a length-delimited postcard stream on
//! `/run/northnarrow/admin.sock`. The frame layout is:
//!
//! ```text
//! ┌─────────────┬──────────────────────────┐
//! │ length: u32 │ postcard-encoded message │
//! │ (big-endian)│                          │
//! └─────────────┴──────────────────────────┘
//! ```
//!
//! [`encode_frame`] / [`decode_frame`] hide that layout from callers
//! so the agent's tokio socket reader and the CLI client can share
//! one implementation.
//!
//! Why postcard: small (~50 KB compiled), no_std-friendly (this
//! module is std-only today, but if any future protocol type needs
//! to flow into the kernel half it stays workable), deterministic
//! encoding (varint-based, but stable across versions of the crate).

use serde::{Deserialize, Serialize};
use serde_big_array::BigArray;

use crate::posture_types::PostureKind;

/// Cryptographic-quality random nonce minted by the server and
/// returned to the client. The client must sign exactly these 32
/// bytes (no domain-separation prefix in V1; see `admin_auth.rs`
/// when it lands).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Challenge {
    pub nonce: [u8; 32],
}

/// Ed25519 detached signature over the most recently issued
/// [`Challenge::nonce`]. Pure-Ed25519 sigs are 64 bytes regardless
/// of message length; the `BigArray` helper exists because stable
/// serde's auto-derive only covers `[T; N]` up to N=32.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnlockRequest {
    #[serde(with = "BigArray")]
    pub signature: [u8; 64],
}

/// Outcome of [`UnlockRequest`] verification.
///
/// `Success` mints an [`UnlockToken`](../../../agent/src/anti_tamper/network_isolate.rs)
/// inside the agent and calls `NetworkIsolator::release` plus
/// `PostureMachine::admin_release_combat_with_token`. Every other
/// variant leaves the lockdown in place.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum UnlockResult {
    Success,
    InvalidSignature,
    NoPendingChallenge,
    RateLimited { retry_after_secs: u32 },
}

/// Trigger payload for "issue me a fresh challenge nonce". Empty
/// today; reserved as a struct so future fields (client version,
/// requested key fingerprint) can be added without an AdminMessage
/// variant bump.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct ChallengeRequest {}

/// `status` query payload. Empty today; reserved as a struct (not a
/// unit variant) so future read-only fields can be added without an
/// AdminMessage variant bump.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct StatusRequest {}

/// `status` reply payload — posture + network state + a rough
/// "last admin action" timer for the operator. `None` means no
/// admin action has been observed since the agent started.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct StatusResponse {
    pub posture: PostureKind,
    pub network_isolation_engaged: bool,
    pub last_admin_action_secs_ago: Option<u64>,
}

/// Debug-only escape hatch: forces the agent's posture state machine
/// into the named state. Used by the integration test harness; never
/// available in production builds. Gated by the `debug-trigger`
/// Cargo feature on both this crate and the agent.
#[cfg(feature = "debug-trigger")]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DebugForcePosture {
    Observing,
    Alerted,
    Engaged,
    Combat,
}

/// One side's complete protocol surface. Client requests and server
/// responses are unified into a single enum so the framing helpers
/// can serialize either with no duplication.
///
/// Wire ordering note: the postcard discriminant is a varint over
/// the variant index. We never reorder variants — appending only.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AdminMessage {
    // ── client → server ────────────────────────────────────────
    /// "Mint me a fresh nonce." Triggers [`Challenge`] reply.
    ChallengeRequest(ChallengeRequest),
    /// "Here is my Ed25519 sig over the last nonce." Triggers
    /// [`UnlockResult`] reply.
    Unlock(UnlockRequest),
    /// "Tell me the agent's posture + network state." Triggers
    /// [`StatusResponse`] reply.
    Status(StatusRequest),
    /// Debug-only: force a posture transition. Triggers an empty
    /// [`AdminMessage::DebugForcePostureAck`] reply on success.
    #[cfg(feature = "debug-trigger")]
    DebugForcePosture(DebugForcePosture),

    // ── server → client ────────────────────────────────────────
    Challenge(Challenge),
    UnlockResult(UnlockResult),
    StatusResponse(StatusResponse),
    #[cfg(feature = "debug-trigger")]
    DebugForcePostureAck,
}

/// Hard ceiling on a single frame's body length. Defends the
/// receiver against a malicious peer that advertises a 4 GB length
/// to make us allocate. 64 KiB is several orders of magnitude over
/// any legitimate AdminMessage today.
pub const MAX_FRAME_BODY: usize = 64 * 1024;

/// Errors that can occur when encoding or decoding a frame.
#[derive(Debug)]
pub enum FrameError {
    /// `decode_frame` saw a length header larger than
    /// [`MAX_FRAME_BODY`]. We never trust an attacker-controlled
    /// length blindly.
    BodyTooLarge { advertised: usize, limit: usize },
    /// The postcard payload failed to deserialize. Either the bytes
    /// were truncated mid-encode or the peer is speaking a
    /// different schema version.
    Postcard(postcard::Error),
    /// The frame body was larger than [`MAX_FRAME_BODY`] at encode
    /// time. Should never happen with real AdminMessages.
    EncodedBodyTooLarge { size: usize, limit: usize },
}

impl core::fmt::Display for FrameError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            FrameError::BodyTooLarge { advertised, limit } => {
                write!(f, "advertised frame body {advertised} > limit {limit}")
            }
            FrameError::EncodedBodyTooLarge { size, limit } => {
                write!(f, "encoded frame body {size} > limit {limit}")
            }
            FrameError::Postcard(e) => write!(f, "postcard decode failed: {e}"),
        }
    }
}

impl std::error::Error for FrameError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            FrameError::Postcard(e) => Some(e),
            _ => None,
        }
    }
}

impl From<postcard::Error> for FrameError {
    fn from(e: postcard::Error) -> Self {
        FrameError::Postcard(e)
    }
}

/// Serialize `msg` as a length-prefixed frame ready to be written to
/// a stream socket.
pub fn encode_frame(msg: &AdminMessage) -> Result<Vec<u8>, FrameError> {
    let body = postcard::to_allocvec(msg)?;
    if body.len() > MAX_FRAME_BODY {
        return Err(FrameError::EncodedBodyTooLarge {
            size: body.len(),
            limit: MAX_FRAME_BODY,
        });
    }
    let mut out = Vec::with_capacity(4 + body.len());
    out.extend_from_slice(&(body.len() as u32).to_be_bytes());
    out.extend_from_slice(&body);
    Ok(out)
}

/// Try to decode one frame from the head of `buf`.
///
/// Returns:
/// - `Ok(Some((msg, n)))` if a complete frame was parsed, where `n`
///   is the number of bytes consumed (caller should drop the first
///   `n` bytes from its buffer).
/// - `Ok(None)` if `buf` is too short — caller should read more
///   bytes from the socket and call again with the extended buffer.
/// - `Err(FrameError)` for fatal protocol violations (oversized
///   advertised body, postcard decode failure).
pub fn decode_frame(buf: &[u8]) -> Result<Option<(AdminMessage, usize)>, FrameError> {
    if buf.len() < 4 {
        return Ok(None);
    }
    let len = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
    if len > MAX_FRAME_BODY {
        return Err(FrameError::BodyTooLarge {
            advertised: len,
            limit: MAX_FRAME_BODY,
        });
    }
    if buf.len() < 4 + len {
        return Ok(None);
    }
    let body = &buf[4..4 + len];
    let msg: AdminMessage = postcard::from_bytes(body)?;
    Ok(Some((msg, 4 + len)))
}

/// Compile-time assertion that an Ed25519 signature is exactly 64
/// bytes — if dalek ever changes its sig encoding (it won't), this
/// const evaluation fails the build before any runtime test fires.
const _: () = {
    if core::mem::size_of::<UnlockRequest>() != 64 {
        panic!("UnlockRequest must be exactly 64 bytes — Ed25519 sig size");
    }
};

#[cfg(test)]
mod tests {
    use super::*;

    fn roundtrip(msg: AdminMessage) {
        let bytes = encode_frame(&msg).expect("encode");
        let (decoded, consumed) = decode_frame(&bytes)
            .expect("decode")
            .expect("complete frame");
        assert_eq!(decoded, msg);
        assert_eq!(consumed, bytes.len());
    }

    #[test]
    fn roundtrip_challenge_request() {
        roundtrip(AdminMessage::ChallengeRequest(ChallengeRequest {}));
    }

    #[test]
    fn roundtrip_challenge() {
        roundtrip(AdminMessage::Challenge(Challenge { nonce: [0xAB; 32] }));
    }

    #[test]
    fn roundtrip_unlock_request() {
        roundtrip(AdminMessage::Unlock(UnlockRequest {
            signature: [0xCD; 64],
        }));
    }

    #[test]
    fn roundtrip_unlock_result_success() {
        roundtrip(AdminMessage::UnlockResult(UnlockResult::Success));
    }

    #[test]
    fn roundtrip_unlock_result_rate_limited() {
        roundtrip(AdminMessage::UnlockResult(UnlockResult::RateLimited {
            retry_after_secs: 300,
        }));
    }

    #[test]
    fn roundtrip_unlock_result_invalid_signature() {
        roundtrip(AdminMessage::UnlockResult(UnlockResult::InvalidSignature));
    }

    #[test]
    fn roundtrip_unlock_result_no_pending_challenge() {
        roundtrip(AdminMessage::UnlockResult(UnlockResult::NoPendingChallenge));
    }

    #[test]
    fn roundtrip_status_request() {
        roundtrip(AdminMessage::Status(StatusRequest {}));
    }

    #[test]
    fn roundtrip_status_response_with_recent_action() {
        roundtrip(AdminMessage::StatusResponse(StatusResponse {
            posture: PostureKind::Combat,
            network_isolation_engaged: true,
            last_admin_action_secs_ago: Some(42),
        }));
    }

    #[test]
    fn roundtrip_status_response_no_admin_action() {
        roundtrip(AdminMessage::StatusResponse(StatusResponse {
            posture: PostureKind::Observing,
            network_isolation_engaged: false,
            last_admin_action_secs_ago: None,
        }));
    }

    #[test]
    fn decode_returns_none_on_short_header() {
        // Less than 4 bytes — even the length header isn't complete.
        for n in 0..4 {
            let buf = vec![0u8; n];
            let res = decode_frame(&buf).expect("no fatal error on short header");
            assert!(res.is_none(), "expected None for {n}-byte buffer");
        }
    }

    #[test]
    fn decode_returns_none_on_partial_body() {
        // Encode a full frame, then feed every prefix of it shorter
        // than the full length to decode_frame. Every prefix must
        // return Ok(None) — never an error, never a spurious decode.
        let full = encode_frame(&AdminMessage::Challenge(Challenge { nonce: [0xEF; 32] })).unwrap();
        for n in 4..full.len() {
            let res = decode_frame(&full[..n]).expect("no fatal error on partial body");
            assert!(
                res.is_none(),
                "expected None for {n}-byte prefix of {}-byte frame",
                full.len()
            );
        }
        // The full frame decodes.
        let (msg, consumed) = decode_frame(&full).unwrap().unwrap();
        assert_eq!(consumed, full.len());
        assert!(matches!(msg, AdminMessage::Challenge(_)));
    }

    #[test]
    fn decode_rejects_oversized_advertised_body() {
        // Hand-craft a length header that exceeds MAX_FRAME_BODY.
        let mut buf = vec![0u8; 4];
        let bad_len = (MAX_FRAME_BODY as u32) + 1;
        buf[..4].copy_from_slice(&bad_len.to_be_bytes());
        // We never even reach reading the body — the size check fires.
        let err = decode_frame(&buf).unwrap_err();
        match err {
            FrameError::BodyTooLarge { advertised, limit } => {
                assert_eq!(advertised, MAX_FRAME_BODY + 1);
                assert_eq!(limit, MAX_FRAME_BODY);
            }
            other => panic!("expected BodyTooLarge, got {other:?}"),
        }
    }

    #[test]
    fn decode_consumes_exactly_one_frame_when_buffer_has_extra() {
        // Concat two frames in one buffer; decode_frame must return
        // only the first and report the right consumed-bytes count.
        let a = encode_frame(&AdminMessage::ChallengeRequest(ChallengeRequest {})).unwrap();
        let b = encode_frame(&AdminMessage::Status(StatusRequest {})).unwrap();
        let mut joined = Vec::new();
        joined.extend_from_slice(&a);
        joined.extend_from_slice(&b);

        let (first, n1) = decode_frame(&joined).unwrap().unwrap();
        assert_eq!(first, AdminMessage::ChallengeRequest(ChallengeRequest {}));
        assert_eq!(n1, a.len());

        let (second, n2) = decode_frame(&joined[n1..]).unwrap().unwrap();
        assert_eq!(second, AdminMessage::Status(StatusRequest {}));
        assert_eq!(n2, b.len());
    }

    #[test]
    fn unlock_request_is_exactly_64_bytes() {
        // The const_ assertion at the top of the file already guards
        // this at compile time; this runtime test exists so that a
        // regression shows up immediately as a unit-test failure
        // rather than a less-obvious build error.
        assert_eq!(core::mem::size_of::<UnlockRequest>(), 64);
    }

    #[test]
    fn challenge_nonce_is_exactly_32_bytes() {
        assert_eq!(core::mem::size_of::<Challenge>(), 32);
    }

    #[cfg(not(feature = "debug-trigger"))]
    #[test]
    fn debug_variant_absent_when_feature_off() {
        // Pure compile-test: enumerate every AdminMessage variant
        // exhaustively in a match. If the debug variant slipped in
        // without the feature gate, the match would lose its
        // exhaustiveness and the test would fail to compile.
        fn _exhaust(m: AdminMessage) {
            match m {
                AdminMessage::ChallengeRequest(_)
                | AdminMessage::Unlock(_)
                | AdminMessage::Status(_)
                | AdminMessage::Challenge(_)
                | AdminMessage::UnlockResult(_)
                | AdminMessage::StatusResponse(_) => {}
            }
        }
    }

    #[cfg(feature = "debug-trigger")]
    #[test]
    fn roundtrip_debug_force_posture() {
        roundtrip(AdminMessage::DebugForcePosture(DebugForcePosture::Combat));
        roundtrip(AdminMessage::DebugForcePostureAck);
    }
}
