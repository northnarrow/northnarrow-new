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
//!
//! ## Protocol versioning (Tappa 8 commit A1)
//!
//! The wire body has historically been a bare postcard-encoded
//! [`AdminMessage`]; adding a variant is a hard breaking change for
//! every peer that doesn't yet know about it. To allow staged
//! rollouts (newer agent vs older `nn-admin`, or the reverse) the
//! Tappa 8 design (`docs/design/TAPPA8_ED25519_ADMIN_OVERRIDE_DESIGN.md`
//! §6.2) wraps the body in a [`VersionedAdminMessage`] envelope:
//!
//! ```text
//! ┌─────────────┬─────────────────┬───────────────────────────┐
//! │ length: u32 │ version: u16    │ postcard(AdminMessage)    │
//! │ (big-endian)│ (postcard varint│                           │
//! │             │  inside body)   │                           │
//! └─────────────┴─────────────────┴───────────────────────────┘
//! ```
//!
//! [`PROTOCOL_VERSION`] is the highest version this build understands.
//! A peer that decodes a frame whose `version` exceeds its
//! `PROTOCOL_VERSION` returns
//! [`FrameError::ProtocolVersionUnsupported`] and closes the
//! connection — the rule is *forward-incompatible, backward-tolerant*.
//!
//! During the Tappa-8.x release cycle the agent also accepts the
//! legacy unframed `AdminMessage` body (the v0 wire shape) for the
//! variants that historically reached the server (`ChallengeRequest`,
//! `Unlock`, `Status`). Use [`decode_versioned_or_legacy_frame`] for
//! that tolerance; the strict decoder [`decode_versioned_frame`]
//! rejects anything that is not a well-formed v1 envelope. The legacy
//! tolerance window is documented to close once every shipped
//! `nn-admin` is known to be on v1.
//!
//! ### Why this commit doesn't switch existing call sites
//!
//! [`encode_frame`] / [`decode_frame`] continue to work and remain the
//! production wire format. Commit A1 adds the v1 envelope types and
//! framing helpers but does not rewire `admin_socket.rs` or
//! `admin_cli.rs`; that integration is part of later A-series commits
//! (notably A7 when `ShutdownRequest` lands and the v1 envelope
//! becomes the only sensible way to express the new variants). This
//! keeps A1 a pure additive change with zero behavioural impact on
//! the existing unlock/status/challenge paths.

use alloc::vec::Vec;

use serde::{Deserialize, Serialize};
use serde_big_array::BigArray;

use crate::posture_types::PostureKind;
use crate::wire::admin_signed_payload::SignedPayload;

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

/// Tappa 8 commit A7 — superset reply enum for the new wire
/// operations (Shutdown today; ForcePosture / RotateKeys /
/// AuditRead in subsequent sprints). The legacy
/// [`UnlockResult`] is preserved unchanged so existing unlock
/// callers stay byte-identical.
///
/// Variant set mirrors design §6.6 verbatim. Add new variants by
/// APPENDING to preserve postcard discriminants.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AdminResult {
    Success,
    InvalidSignature,
    NoPendingChallenge,
    RateLimited {
        retry_after_secs: u32,
    },
    /// Signature verifies but the matched key's allowlist does
    /// not include the operation's required role (A5).
    RoleDenied,
    /// Multi-signature quorum was short of `required` distinct
    /// valid signatures (A6).
    QuorumNotMet {
        required: u8,
        provided: u8,
    },
    /// `payload.ts` was outside the server's ±skew window (A4).
    TimestampSkew {
        server_ts: u64,
        max_skew_secs: u32,
    },
    /// `payload.agent_id` did not match the agent's bootstrapped
    /// install UUID (A3).
    AgentIdMismatch,
    /// `payload.op` was not the operation expected on this wire
    /// variant (e.g., a `ShutdownRequest` carrying `op=Unlock`).
    UnknownOperation,
    /// `version > PROTOCOL_VERSION` on the envelope (A1).
    ProtocolVersionUnsupported {
        server_version: u16,
    },
}

/// One signature in a multi-sig quorum submission. Wrapped in a
/// named struct so `Vec<KeyedSignature>` serialises via serde's
/// auto-derive (a bare `Vec<[u8; 64]>` would need a custom
/// `with = "BigArray"`-equivalent at the Vec level). The struct
/// is also a forward extension point — a future hardening tappa
/// may add a `fingerprint_hint: [u8; 4]` field to let the agent
/// route the per-signature verify faster on large key sets.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyedSignature {
    #[serde(with = "BigArray")]
    pub signature: [u8; 64],
}

impl From<[u8; 64]> for KeyedSignature {
    fn from(signature: [u8; 64]) -> Self {
        Self { signature }
    }
}

/// Tappa 8 commit A7 — signed shutdown request (design §10.2).
/// Carries the full [`SignedPayload`] (with `op = Shutdown`) plus
/// the multi-signature quorum (min 2-of-N, ≥1 carrying
/// `Role::Shutdown` per §3.3). Signatures are Ed25519 over
/// `signing_digest(payload)` — not over the raw nonce, unlike
/// the legacy [`UnlockRequest`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShutdownRequest {
    pub payload: SignedPayload,
    pub signatures: Vec<KeyedSignature>,
}

/// Tappa 8 commit A10 — signed production force-posture request
/// (design §4 + §12.2). Carries the full [`SignedPayload`] (with
/// `op = ForcePosture` and `extra = ForcePosture { target }`) plus
/// a single signature — force-posture is 1-of-N per §3.3, unlike
/// shutdown's 2-of-N. `Vec<KeyedSignature>` is reused for shape
/// consistency with `ShutdownRequest`; the agent's quorum verify
/// enforces `min_distinct=1` so a single signature is sufficient.
///
/// **Distinct from `DebugForcePosture`** (the existing
/// `cfg(feature = "debug-trigger")` test variant): that path
/// bypasses every authentication layer for integration testing,
/// while this variant runs the full Tappa-8 verify path (nonce
/// binding, timestamp skew, agent_id binding, signature verify,
/// role check). Both variants stay; production callers use this
/// one, test infrastructure keeps using the debug one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ForcePostureRequest {
    pub payload: SignedPayload,
    pub signatures: Vec<KeyedSignature>,
}

/// Tappa 8 commit A13 — signed key-rotation **add** request
/// (design §7.2). Carries the full [`SignedPayload`] with
/// `op = RotateKeysAdd` and `extra = RotateKeysAdd { new_pubkey,
/// roles }`, plus a 2-of-N quorum (≥1 carrying
/// [`common::wire::admin_signed_payload::Role::RotateKeys`] per
/// §3.3). On verify, the agent atomically appends a new line to
/// `/etc/northnarrow/admin.pub` (tmpfile + fsync + `rename(2)`)
/// and reloads its in-memory key set so the next challenge
/// already sees the new key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RotateKeysAddRequest {
    pub payload: SignedPayload,
    pub signatures: Vec<KeyedSignature>,
}

/// Tappa 8 commit A13 — signed key-rotation **revoke** request
/// (design §7.2 + §7.3). Same quorum requirements as
/// [`RotateKeysAddRequest`]; the agent removes the line whose
/// pubkey fingerprint matches the carried `fingerprint` from
/// `admin.pub` (atomic rewrite) and reloads. Revoking the last
/// remaining key is rejected at dispatch with
/// [`AdminResult::InvalidSignature`] — losing the last key would
/// soft-brick the agent (no one can unlock or shutdown
/// thereafter), so the operator must `add` a replacement first.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RotateKeysRevokeRequest {
    pub payload: SignedPayload,
    pub signatures: Vec<KeyedSignature>,
}

/// Tappa 9 commit C6 — signed FIM baseline (re)compute request
/// (design §6.1 + §13 Q6). Carries the full [`SignedPayload`]
/// (with `op = FimBaseline` and `extra = FimBaseline {}`) plus
/// a single signature — 1-of-N per §13 Q6 ("baseline is a
/// workflow op, not a security gate"). Required role:
/// [`common::wire::admin_signed_payload::Role::FimManage`].
/// `Vec<KeyedSignature>` is reused for shape consistency with
/// the other Tappa-8 ops; the agent's quorum verify enforces
/// `min_distinct=1`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FimBaselineRequest {
    pub payload: SignedPayload,
    pub signatures: Vec<KeyedSignature>,
}

/// Tappa 9 commit C6 — signed FIM drift-log read request
/// (design §6.3 + §13 Q6). Carries `op = FimReport` with the
/// optional `since_unix_ts` filter in
/// [`common::wire::admin_signed_payload::FimReportExtra`].
/// 1-of-N quorum (single-sig, `Role::FimRead` — the
/// lower-privilege FIM role). Reply on the success path is a
/// [`FimReportResponse`] carrying the JSONL-encoded chain
/// rather than the bare [`AdminResult`] superset — the chain
/// IS the response payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FimReportRequest {
    pub payload: SignedPayload,
    pub signatures: Vec<KeyedSignature>,
}

/// Tappa 9 commit C7 — signed FIM in-process status request
/// (C6 deferral). 1-of-N quorum (single-sig, `Role::FimRead`).
/// Read-only: surfaces token-bucket counts, watched-path count,
/// last baseline ts. No on-disk side effects.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FimStatusRequest {
    pub payload: SignedPayload,
    pub signatures: Vec<KeyedSignature>,
}

/// Tappa 9 commit C7 — `FimStatus` reply payload. On success
/// carries the live in-process snapshot. On failure, `result`
/// carries the auth/quorum/role error and the other fields are
/// zero/empty.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FimStatusResponse {
    /// Auth result — `Success` when the snapshot fields follow.
    pub result: AdminResult,
    /// Effective watched-paths set size (after `fim-paths.local`
    /// add+disable merge per §13 Q7). The headline operator
    /// summary line.
    pub watched_paths_count: u32,
    /// Default-list paths the operator overlay disabled. Surfaces
    /// the §13 Q7 lock-in ("no silent hiding") to the CLI.
    pub disabled_default_count: u32,
    /// Operator-added paths (overlay `+` lines or bare-path lines).
    pub added_path_count: u32,
    /// ISO-8601 `ts` of the most recent `BaselineEntry` row, or
    /// empty when the baseline DB is empty (pre-TOFU first boot,
    /// or pre-C7 deploy).
    pub last_baseline_ts: String,
    /// Total `BaselineEntry` rows the chain currently holds.
    pub baseline_entries_total: u32,
    /// Total `FimDriftEntry` rows the chain currently holds.
    pub drift_entries_total: u32,
    /// Current token-bucket state for the §6.5 hierarchical
    /// rate-limiter. `Critical` is always uncapped per §13 Q4
    /// lock-in; the snapshot reports `high_remaining` and
    /// `medium_remaining` against the configured caps.
    pub high_remaining: u32,
    pub high_cap_per_min: u32,
    pub medium_remaining: u32,
    pub medium_cap_per_min: u32,
    /// Seconds until the current 60-second token-bucket window
    /// rolls over. `0` immediately after a roll. Helps the
    /// operator decide whether observed throttling is about to
    /// release on its own.
    pub bucket_window_resets_in_secs: u32,
}

/// Tappa 9 commit C6 — `FimReport` reply payload. On success
/// carries the chain entries the operator's `nn-admin fim
/// report` reads + the count for the summary line. On
/// failure, `result` carries the auth/quorum/role error
/// shape consistent with the other Tappa-8 ops; `entries_jsonl`
/// is then empty.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FimReportResponse {
    /// Auth result — `Success` when the chain follows.
    pub result: AdminResult,
    /// Chained drift-log entries in their canonical on-disk
    /// JSONL form (one entry per line, `\n`-separated).
    /// Empty on auth failure. Bounded by
    /// [`MAX_FRAME_BODY`] minus a few bytes of envelope; the
    /// agent's dispatch caps the export length and surfaces
    /// truncation in `entries_truncated`.
    pub entries_jsonl: String,
    /// Number of entries returned. Lets the CLI print a
    /// summary line without re-parsing the JSONL body.
    pub entries_count: u32,
    /// `true` if the agent's dispatch truncated the body
    /// because the full chain exceeded the wire-frame
    /// budget. CLI surfaces this as
    /// `"... (truncated; pass --since <ts> to narrow)"`.
    pub entries_truncated: bool,
}

/// Tappa 9.5 commit K6 — signed canary deploy request. Carries
/// `op = CanaryDeploy` with the operator's chosen canary name +
/// type + deployment payload in
/// [`common::wire::admin_signed_payload::CanaryDeployExtra`].
/// 1-of-N quorum, `Role::CanaryManage` (§12 Q7 split-role
/// lock-in).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CanaryDeployRequest {
    pub payload: SignedPayload,
    pub signatures: Vec<KeyedSignature>,
}

/// Tappa 9.5 commit K6 — `CanaryDeploy` reply payload. Success
/// carries the freshly-allocated `canary_id` so the operator can
/// reference the deployment in future burn / refresh ops; on
/// failure, `result` carries the auth/quorum/role error and
/// `canary_id` is empty.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CanaryDeployResponse {
    pub result: AdminResult,
    /// 32-hex-char per-canary stable ID from the K2 registry.
    /// Empty on auth failure.
    pub canary_id: String,
}

/// Tappa 9.5 commit K6 — signed canary list request. 1-of-N
/// quorum, `Role::CanaryRead` (read-only lower-privilege role
/// per §12 Q7).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CanaryListRequest {
    pub payload: SignedPayload,
    pub signatures: Vec<KeyedSignature>,
}

/// Tappa 9.5 commit K6 — `CanaryList` reply payload. Same
/// truncation-aware shape as `FimReportResponse` — the chained
/// registry rows go in `entries_jsonl` (one row per line);
/// `entries_count` lets the CLI render a summary line without
/// re-parsing; `entries_truncated` surfaces when the body
/// exceeded the wire-frame budget.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CanaryListResponse {
    pub result: AdminResult,
    pub entries_jsonl: String,
    pub entries_count: u32,
    pub entries_truncated: bool,
}

/// Tappa 9.5 commit K6 — signed canary burn request. 1-of-N
/// quorum, `Role::CanaryManage`. The `canary_id` field rides
/// in [`common::wire::admin_signed_payload::CanaryBurnExtra`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CanaryBurnRequest {
    pub payload: SignedPayload,
    pub signatures: Vec<KeyedSignature>,
}

/// Tappa 9.5 commit K6 — signed canary refresh request. 1-of-N
/// quorum, `Role::CanaryManage`. Per §12 Q2 MANUAL-ONLY lock-in
/// — only operator action clears the `tripped` flag.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CanaryRefreshRequest {
    pub payload: SignedPayload,
    pub signatures: Vec<KeyedSignature>,
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
///
/// `Copy` is intentionally NOT derived: Tappa 8 A7's
/// [`ShutdownRequest`] variant carries a `Vec<KeyedSignature>` for
/// the quorum payload, which is heap-backed and therefore not
/// `Copy`. Existing callers all consume `AdminMessage` by move
/// (encoder/decoder paths) or by `&` (test exhaustiveness checks),
/// so dropping `Copy` is source-compatible.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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

    // ── Tappa 8 commit A7 — appended last to preserve every
    //    prior variant's postcard discriminant. New variants in
    //    future Tappa-8 commits (force-posture production,
    //    rotate-keys, audit-read) likewise append below.
    /// Signed shutdown request (design §10.2). Triggers
    /// [`AdminMessage::ShutdownResult`] reply.
    ShutdownRequest(ShutdownRequest),
    /// Reply to [`AdminMessage::ShutdownRequest`]. Uses the
    /// superset [`AdminResult`] so future Tappa 8 wire variants
    /// can be added without bumping the wire schema.
    ShutdownResult(AdminResult),
    /// Tappa 8 commit A10 — signed production force-posture
    /// request (design §4 + §12.2). Triggers
    /// [`AdminMessage::ForcePostureResult`] reply. Distinct from
    /// the existing `cfg(debug-trigger)` `DebugForcePosture`
    /// variant; both stay.
    ForcePostureRequest(ForcePostureRequest),
    /// Reply to [`AdminMessage::ForcePostureRequest`].
    ForcePostureResult(AdminResult),
    /// Tappa 8 commit A13 — signed key-rotation add request.
    /// Triggers [`AdminMessage::RotateKeysAddResult`].
    RotateKeysAddRequest(RotateKeysAddRequest),
    /// Reply to [`AdminMessage::RotateKeysAddRequest`].
    RotateKeysAddResult(AdminResult),
    /// Tappa 8 commit A13 — signed key-rotation revoke request.
    /// Triggers [`AdminMessage::RotateKeysRevokeResult`].
    RotateKeysRevokeRequest(RotateKeysRevokeRequest),
    /// Reply to [`AdminMessage::RotateKeysRevokeRequest`].
    RotateKeysRevokeResult(AdminResult),
    /// Tappa 9 commit C6 — signed FIM baseline (re)compute
    /// request. Triggers [`AdminMessage::FimBaselineResult`].
    FimBaselineRequest(FimBaselineRequest),
    /// Reply to [`AdminMessage::FimBaselineRequest`].
    FimBaselineResult(AdminResult),
    /// Tappa 9 commit C6 — signed FIM drift-log read request.
    /// Triggers [`AdminMessage::FimReportResponse`].
    FimReportRequest(FimReportRequest),
    /// Reply to [`AdminMessage::FimReportRequest`] — carries
    /// the chained JSONL body on success.
    FimReportResponse(FimReportResponse),
    /// Tappa 9 commit C7 — signed FIM in-process status request
    /// (C6 deferral). Triggers [`AdminMessage::FimStatusResponse`].
    FimStatusRequest(FimStatusRequest),
    /// Reply to [`AdminMessage::FimStatusRequest`] — carries the
    /// live status snapshot.
    FimStatusResponse(FimStatusResponse),
    /// Tappa 9.5 commit K6 — signed canary deploy request.
    /// Triggers [`AdminMessage::CanaryDeployResponse`].
    CanaryDeployRequest(CanaryDeployRequest),
    /// Reply to [`AdminMessage::CanaryDeployRequest`] — carries
    /// the freshly-allocated `canary_id` on success.
    CanaryDeployResponse(CanaryDeployResponse),
    /// Tappa 9.5 commit K6 — signed canary list request.
    /// Triggers [`AdminMessage::CanaryListResponse`].
    CanaryListRequest(CanaryListRequest),
    /// Reply to [`AdminMessage::CanaryListRequest`] — carries
    /// the chained registry JSONL body on success.
    CanaryListResponse(CanaryListResponse),
    /// Tappa 9.5 commit K6 — signed canary burn request.
    /// Triggers [`AdminMessage::CanaryBurnResult`].
    CanaryBurnRequest(CanaryBurnRequest),
    /// Reply to [`AdminMessage::CanaryBurnRequest`]. Uses the
    /// bare `AdminResult` superset; no per-op state to surface
    /// beyond success/failure.
    CanaryBurnResult(AdminResult),
    /// Tappa 9.5 commit K6 — signed canary refresh request.
    /// Triggers [`AdminMessage::CanaryRefreshResult`].
    CanaryRefreshRequest(CanaryRefreshRequest),
    /// Reply to [`AdminMessage::CanaryRefreshRequest`]. Bare
    /// `AdminResult` — same rationale as `CanaryBurnResult`.
    CanaryRefreshResult(AdminResult),
}

/// Hard ceiling on a single frame's body length. Defends the
/// receiver against a malicious peer that advertises a 4 GB length
/// to make us allocate. 64 KiB is several orders of magnitude over
/// any legitimate AdminMessage today.
pub const MAX_FRAME_BODY: usize = 64 * 1024;

/// Highest wire-protocol version this build understands. See the
/// module doc-comment "Protocol versioning" section for the envelope
/// shape; see the design doc §6.2 for the migration policy.
///
/// Incrementing this is a coordinated change: the new value MUST
/// only be set once every reachable peer (agent + every shipped
/// `nn-admin`) has been updated to *decode* it. Encoders may
/// continue to emit the older value indefinitely.
pub const PROTOCOL_VERSION: u16 = 1;

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
    /// A [`VersionedAdminMessage`] decoded successfully but carried a
    /// `version` greater than [`PROTOCOL_VERSION`]. The peer is from
    /// a newer release than this build can speak; we close the
    /// connection rather than guess at the payload semantics. The
    /// server-side error mapping turns this into the
    /// `ProtocolVersionUnsupported` `AdminResult` variant for the
    /// client (design §6.6).
    ProtocolVersionUnsupported { received: u16, supported: u16 },
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
            FrameError::ProtocolVersionUnsupported {
                received,
                supported,
            } => write!(
                f,
                "protocol version {received} unsupported (this build speaks up to {supported})"
            ),
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

/// V1 envelope around any [`AdminMessage`]. Carried as the body of a
/// length-prefixed frame, exactly like a bare `AdminMessage` body was
/// in v0 (see the module doc-comment "Protocol versioning" section).
///
/// Encoders set `version` to [`PROTOCOL_VERSION`]; decoders accept
/// any `version` in `1..=PROTOCOL_VERSION` (the v0 wire shape — a
/// bare `AdminMessage` body — is recognised separately by
/// [`decode_versioned_or_legacy_frame`] and reported as
/// `version == 0`). A peer that receives `version > PROTOCOL_VERSION`
/// returns [`FrameError::ProtocolVersionUnsupported`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VersionedAdminMessage {
    pub version: u16,
    pub message: AdminMessage,
}

impl VersionedAdminMessage {
    /// Build a fresh v1 envelope at the current [`PROTOCOL_VERSION`].
    /// The single recommended constructor for encoders so callers
    /// can't accidentally hard-code an older version constant.
    pub fn current(message: AdminMessage) -> Self {
        Self {
            version: PROTOCOL_VERSION,
            message,
        }
    }
}

/// Serialize `msg` as a length-prefixed v1 envelope. Mirror of
/// [`encode_frame`] for the new envelope type.
pub fn encode_versioned_frame(msg: &VersionedAdminMessage) -> Result<Vec<u8>, FrameError> {
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

/// Strict v1 decode: returns `Ok(Some((envelope, consumed)))` only
/// for a well-formed [`VersionedAdminMessage`] whose `version` is
/// `1..=PROTOCOL_VERSION` AND whose body postcard-decodes with no
/// trailing bytes.
///
/// Strict consumption is load-bearing for the v0 fallback in
/// [`decode_versioned_or_legacy_frame`]: a v0 frame whose first byte
/// happens to parse as a valid `version` varint must be rejected
/// here so the caller can retry the legacy decoder.
pub fn decode_versioned_frame(
    buf: &[u8],
) -> Result<Option<(VersionedAdminMessage, usize)>, FrameError> {
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
    // take_from_bytes returns the parsed value plus the unused tail;
    // we require the tail to be empty so a v0 frame with happenstance
    // bytes can't slip through as a "valid v1 envelope plus garbage."
    let (envelope, tail) = postcard::take_from_bytes::<VersionedAdminMessage>(body)?;
    if !tail.is_empty() {
        return Err(FrameError::Postcard(
            postcard::Error::DeserializeUnexpectedEnd,
        ));
    }
    if envelope.version > PROTOCOL_VERSION {
        return Err(FrameError::ProtocolVersionUnsupported {
            received: envelope.version,
            supported: PROTOCOL_VERSION,
        });
    }
    Ok(Some((envelope, 4 + len)))
}

/// V1-first decode with one-cycle legacy tolerance: tries
/// [`decode_versioned_frame`] first; on a postcard-level failure
/// retries as a bare [`AdminMessage`] (the v0 wire shape) and
/// returns a synthetic envelope with `version == 0`.
///
/// `ProtocolVersionUnsupported`, `BodyTooLarge`, and short-buffer
/// returns are **not** masked — they reflect either a genuinely
/// newer peer or a malformed/incomplete frame, neither of which is
/// the v0 case.
///
/// Use this on the agent's listener during the Tappa-8.x migration
/// window. Switch back to [`decode_versioned_frame`] (strict) once
/// every shipped `nn-admin` has been confirmed on v1.
pub fn decode_versioned_or_legacy_frame(
    buf: &[u8],
) -> Result<Option<(VersionedAdminMessage, usize)>, FrameError> {
    match decode_versioned_frame(buf) {
        Ok(some) => Ok(some),
        // Genuinely-newer peer: don't mask, surface the rejection.
        Err(e @ FrameError::ProtocolVersionUnsupported { .. }) => Err(e),
        // Frame-layer issues: surface as-is (caller is on the wrong
        // protocol, not on the wrong version).
        Err(e @ FrameError::BodyTooLarge { .. }) => Err(e),
        Err(e @ FrameError::EncodedBodyTooLarge { .. }) => Err(e),
        // Postcard-level failure → try the v0 wire shape. If that
        // also fails, surface the v0 error (the original v1 error is
        // less informative because we ruled v1 out by trying).
        Err(FrameError::Postcard(_)) => {
            let (msg, consumed) = match decode_frame(buf)? {
                Some(pair) => pair,
                None => return Ok(None),
            };
            Ok(Some((
                VersionedAdminMessage {
                    version: 0,
                    message: msg,
                },
                consumed,
            )))
        }
    }
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
                | AdminMessage::StatusResponse(_)
                | AdminMessage::ShutdownRequest(_)
                | AdminMessage::ShutdownResult(_)
                | AdminMessage::ForcePostureRequest(_)
                | AdminMessage::ForcePostureResult(_)
                | AdminMessage::RotateKeysAddRequest(_)
                | AdminMessage::RotateKeysAddResult(_)
                | AdminMessage::RotateKeysRevokeRequest(_)
                | AdminMessage::RotateKeysRevokeResult(_)
                | AdminMessage::FimBaselineRequest(_)
                | AdminMessage::FimBaselineResult(_)
                | AdminMessage::FimReportRequest(_)
                | AdminMessage::FimReportResponse(_)
                | AdminMessage::FimStatusRequest(_)
                | AdminMessage::FimStatusResponse(_)
                | AdminMessage::CanaryDeployRequest(_)
                | AdminMessage::CanaryDeployResponse(_)
                | AdminMessage::CanaryListRequest(_)
                | AdminMessage::CanaryListResponse(_)
                | AdminMessage::CanaryBurnRequest(_)
                | AdminMessage::CanaryBurnResult(_)
                | AdminMessage::CanaryRefreshRequest(_)
                | AdminMessage::CanaryRefreshResult(_) => {}
            }
        }
    }

    #[cfg(feature = "debug-trigger")]
    #[test]
    fn roundtrip_debug_force_posture() {
        roundtrip(AdminMessage::DebugForcePosture(DebugForcePosture::Combat));
        roundtrip(AdminMessage::DebugForcePostureAck);
    }

    // ── A13: RotateKeys{Add,Revoke}Request wire round-trip ──────────

    /// A13 wire test #1: encoding a `RotateKeysAddRequest` and
    /// decoding it back yields the exact same struct. Anchors the
    /// CBOR / postcard wire shape against accidental field
    /// reordering (which would silently break signature verify
    /// because the payload pre-image is re-serialised before
    /// hashing).
    #[test]
    fn roundtrip_rotate_keys_add_request() {
        use crate::wire::admin_signed_payload::{Role, SignedPayload};
        let payload = SignedPayload::new_rotate_keys_add(
            [0x11; 32],
            1_700_000_000,
            [0x22; 16],
            [0x33; 32],
            vec![Role::Unlock],
        );
        roundtrip(AdminMessage::RotateKeysAddRequest(RotateKeysAddRequest {
            payload,
            signatures: vec![
                KeyedSignature {
                    signature: [0x55; 64],
                },
                KeyedSignature {
                    signature: [0x77; 64],
                },
            ],
        }));
        roundtrip(AdminMessage::RotateKeysAddResult(AdminResult::Success));
    }

    /// A13 wire test #2: same for `RotateKeysRevokeRequest`.
    #[test]
    fn roundtrip_rotate_keys_revoke_request() {
        use crate::wire::admin_signed_payload::SignedPayload;
        let payload =
            SignedPayload::new_rotate_keys_revoke([0x88; 32], 1_700_000_000, [0x99; 16], [0xAA; 4]);
        roundtrip(AdminMessage::RotateKeysRevokeRequest(
            RotateKeysRevokeRequest {
                payload,
                signatures: vec![
                    KeyedSignature {
                        signature: [0xCC; 64],
                    },
                    KeyedSignature {
                        signature: [0xEE; 64],
                    },
                ],
            },
        ));
        roundtrip(AdminMessage::RotateKeysRevokeResult(AdminResult::Success));
    }

    // ── C6: FimBaseline / FimReport wire round-trip ─────────────

    /// C6 wire test #1: `FimBaselineRequest` encodes + decodes
    /// without bit-level drift. 1-of-N quorum so one signature.
    #[test]
    fn roundtrip_fim_baseline_request() {
        use crate::wire::admin_signed_payload::SignedPayload;
        let payload = SignedPayload::new_fim_baseline([0x11; 32], 1_700_000_000, [0x22; 16]);
        roundtrip(AdminMessage::FimBaselineRequest(FimBaselineRequest {
            payload,
            signatures: vec![KeyedSignature {
                signature: [0x55; 64],
            }],
        }));
        roundtrip(AdminMessage::FimBaselineResult(AdminResult::Success));
    }

    /// C6 wire test #2: `FimReportRequest` + `FimReportResponse`
    /// round-trip including the JSONL body + truncation flag.
    #[test]
    fn roundtrip_fim_report_request_and_response() {
        use crate::wire::admin_signed_payload::SignedPayload;
        let payload = SignedPayload::new_fim_report(
            [0x33; 32],
            1_700_000_000,
            [0x44; 16],
            Some(1_700_000_000),
        );
        roundtrip(AdminMessage::FimReportRequest(FimReportRequest {
            payload,
            signatures: vec![KeyedSignature {
                signature: [0x77; 64],
            }],
        }));
        roundtrip(AdminMessage::FimReportResponse(FimReportResponse {
            result: AdminResult::Success,
            entries_jsonl: r#"{"ts":"2026-05-20T00:00:00Z","path":"/etc/passwd"}"#.to_string(),
            entries_count: 1,
            entries_truncated: false,
        }));
        // Auth-failure variant: empty body + non-Success result.
        roundtrip(AdminMessage::FimReportResponse(FimReportResponse {
            result: AdminResult::RoleDenied,
            entries_jsonl: String::new(),
            entries_count: 0,
            entries_truncated: false,
        }));
    }

    // ── C7: FimStatus wire round-trip ──────────────────────────

    /// C7 wire test: `FimStatusRequest` + `FimStatusResponse`
    /// round-trip including the full snapshot fields. The
    /// auth-failure variant is also covered so dispatch's
    /// "result-carries-error, fields-zero" contract is anchored.
    #[test]
    fn roundtrip_fim_status_request_and_response() {
        use crate::wire::admin_signed_payload::SignedPayload;
        let payload = SignedPayload::new_fim_status([0xAA; 32], 1_700_000_000, [0xBB; 16]);
        roundtrip(AdminMessage::FimStatusRequest(FimStatusRequest {
            payload,
            signatures: vec![KeyedSignature {
                signature: [0xCC; 64],
            }],
        }));
        roundtrip(AdminMessage::FimStatusResponse(FimStatusResponse {
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
        }));
        // Auth-failure variant: empty + zero fields.
        roundtrip(AdminMessage::FimStatusResponse(FimStatusResponse {
            result: AdminResult::RoleDenied,
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
        }));
    }

    // ── K6: canary admin op wire round-trips ───────────────────

    /// K6 wire test #1: `CanaryDeployRequest` +
    /// `CanaryDeployResponse` round-trip including the
    /// canary_id surfaced on success + the auth-failure variant
    /// (empty canary_id when result != Success).
    #[test]
    fn roundtrip_canary_deploy_request_and_response() {
        use crate::wire::admin_signed_payload::{
            CanaryDeploymentWire, CanaryTypeWire, SignedPayload,
        };
        let payload = SignedPayload::new_canary_deploy(
            [0x10; 32],
            1_700_000_000,
            [0x20; 16],
            "test_canary".to_string(),
            CanaryTypeWire::File,
            CanaryDeploymentWire::File {
                path: "/tmp/decoy.txt".to_string(),
                template: None,
            },
        );
        roundtrip(AdminMessage::CanaryDeployRequest(CanaryDeployRequest {
            payload,
            signatures: vec![KeyedSignature { signature: [0x33; 64] }],
        }));
        roundtrip(AdminMessage::CanaryDeployResponse(CanaryDeployResponse {
            result: AdminResult::Success,
            canary_id: "9f3c8a01b2c3d4e5f6a7b8c9d0e1f2a3".to_string(),
        }));
        roundtrip(AdminMessage::CanaryDeployResponse(CanaryDeployResponse {
            result: AdminResult::RoleDenied,
            canary_id: String::new(),
        }));
    }

    /// K6 wire test #2: `CanaryListRequest` +
    /// `CanaryListResponse` round-trip including the truncation
    /// flag + the auth-failure variant (empty body).
    #[test]
    fn roundtrip_canary_list_request_and_response() {
        use crate::wire::admin_signed_payload::SignedPayload;
        let payload = SignedPayload::new_canary_list([0x44; 32], 1_700_000_000, [0x55; 16]);
        roundtrip(AdminMessage::CanaryListRequest(CanaryListRequest {
            payload,
            signatures: vec![KeyedSignature { signature: [0x77; 64] }],
        }));
        roundtrip(AdminMessage::CanaryListResponse(CanaryListResponse {
            result: AdminResult::Success,
            entries_jsonl: r#"{"ts":"2026-05-20T00:00:00Z","canary_id":"abc"}"#.to_string(),
            entries_count: 1,
            entries_truncated: true,
        }));
        roundtrip(AdminMessage::CanaryListResponse(CanaryListResponse {
            result: AdminResult::RoleDenied,
            entries_jsonl: String::new(),
            entries_count: 0,
            entries_truncated: false,
        }));
    }

    /// K6 wire test #3: `CanaryBurnRequest` + `CanaryBurnResult`
    /// round-trip. Both burn + refresh use the bare AdminResult
    /// superset for their reply — same shape, anchored together.
    #[test]
    fn roundtrip_canary_burn_and_refresh_request_response() {
        use crate::wire::admin_signed_payload::SignedPayload;
        let burn_payload = SignedPayload::new_canary_burn(
            [0xAA; 32],
            1_700_000_000,
            [0xBB; 16],
            "9f3c8a01b2c3d4e5f6a7b8c9d0e1f2a3".to_string(),
        );
        roundtrip(AdminMessage::CanaryBurnRequest(CanaryBurnRequest {
            payload: burn_payload,
            signatures: vec![KeyedSignature { signature: [0xCC; 64] }],
        }));
        roundtrip(AdminMessage::CanaryBurnResult(AdminResult::Success));

        let refresh_payload = SignedPayload::new_canary_refresh(
            [0xDD; 32],
            1_700_000_000,
            [0xEE; 16],
            "9f3c8a01b2c3d4e5f6a7b8c9d0e1f2a3".to_string(),
        );
        roundtrip(AdminMessage::CanaryRefreshRequest(CanaryRefreshRequest {
            payload: refresh_payload,
            signatures: vec![KeyedSignature { signature: [0xFF; 64] }],
        }));
        roundtrip(AdminMessage::CanaryRefreshResult(AdminResult::RoleDenied));
    }

    // ── A1: VersionedAdminMessage envelope (Tappa 8 design §6.2) ────

    /// Required A1 test 1: encode + strict-decode round-trip.
    /// Exercises every server-reachable client variant so the
    /// envelope is proven to wrap the same payloads the server
    /// already handles in the legacy path.
    #[test]
    fn versioned_envelope_round_trips_through_strict_decoder() {
        let payloads = [
            AdminMessage::ChallengeRequest(ChallengeRequest {}),
            AdminMessage::Unlock(UnlockRequest {
                signature: [0xAB; 64],
            }),
            AdminMessage::Status(StatusRequest {}),
        ];
        for msg in payloads {
            let envelope = VersionedAdminMessage::current(msg);
            assert_eq!(envelope.version, PROTOCOL_VERSION);
            let bytes = encode_versioned_frame(&envelope).expect("encode");
            let (decoded, consumed) = decode_versioned_frame(&bytes)
                .expect("decode")
                .expect("complete frame");
            assert_eq!(decoded, envelope);
            assert_eq!(consumed, bytes.len(), "must consume the full frame");
        }
    }

    /// Required A1 test 2: v0 tolerance. A legacy unframed
    /// `AdminMessage` body (produced by [`encode_frame`]) must decode
    /// through [`decode_versioned_or_legacy_frame`] as
    /// `VersionedAdminMessage { version: 0, message: <original> }`.
    /// Tests all three server-reachable client variants because they
    /// are the historical Tappa-8.x backward-compat surface (see
    /// design §6.2 migration path).
    #[test]
    fn versioned_or_legacy_decodes_v0_unframed_payloads_as_version_zero() {
        let payloads = [
            AdminMessage::ChallengeRequest(ChallengeRequest {}),
            AdminMessage::Unlock(UnlockRequest {
                signature: [0xCD; 64],
            }),
            AdminMessage::Status(StatusRequest {}),
        ];
        for msg in payloads {
            let v0_bytes = encode_frame(&msg).expect("encode v0");
            let (envelope, consumed) = decode_versioned_or_legacy_frame(&v0_bytes)
                .expect("compat decode")
                .expect("complete frame");
            assert_eq!(envelope.version, 0, "v0 frame must surface as version=0");
            assert_eq!(envelope.message, msg);
            assert_eq!(consumed, v0_bytes.len());
        }
    }

    /// Required A1 test 3: future-version reject. An envelope whose
    /// `version` exceeds [`PROTOCOL_VERSION`] must produce
    /// [`FrameError::ProtocolVersionUnsupported`] — never a silent
    /// best-effort decode of the inner message.
    #[test]
    fn versioned_decoder_rejects_future_protocol_version() {
        // Build a future-version envelope by hand: postcard happily
        // encodes any u16 we put in the field, so we can simulate "a
        // peer one version ahead of us" without needing to redefine
        // PROTOCOL_VERSION.
        let future = VersionedAdminMessage {
            version: PROTOCOL_VERSION + 1,
            message: AdminMessage::Status(StatusRequest {}),
        };
        let bytes = encode_versioned_frame(&future).expect("encode");

        // Strict decoder rejects.
        match decode_versioned_frame(&bytes) {
            Err(FrameError::ProtocolVersionUnsupported {
                received,
                supported,
            }) => {
                assert_eq!(received, PROTOCOL_VERSION + 1);
                assert_eq!(supported, PROTOCOL_VERSION);
            }
            other => panic!("expected ProtocolVersionUnsupported, got {other:?}"),
        }
        // Compat decoder also rejects: a future version is NOT a v0
        // case, so the legacy fallback must not mask the error.
        match decode_versioned_or_legacy_frame(&bytes) {
            Err(FrameError::ProtocolVersionUnsupported { received, .. }) => {
                assert_eq!(received, PROTOCOL_VERSION + 1);
            }
            other => panic!("expected ProtocolVersionUnsupported, got {other:?}"),
        }
    }

    /// Required A1 test 4: malformed envelopes. Covers the three
    /// FrameError surfaces the new decoder can hit:
    /// (a) advertised body length exceeds MAX_FRAME_BODY,
    /// (b) buffer is shorter than the advertised length
    ///     (incremental-buffer case → Ok(None)),
    /// (c) body bytes do not postcard-decode as either v1 or v0
    ///     (compat decoder surfaces the v0 postcard error).
    #[test]
    fn versioned_decoder_handles_malformed_envelope() {
        // (a) Oversized advertised length — same defence as
        // decode_frame; covered for the v1 path so a hostile peer
        // can't blow past it by sending a versioned frame instead.
        let mut bad = vec![0u8; 4];
        bad[..4].copy_from_slice(&((MAX_FRAME_BODY as u32) + 1).to_be_bytes());
        match decode_versioned_frame(&bad) {
            Err(FrameError::BodyTooLarge { advertised, limit }) => {
                assert_eq!(advertised, MAX_FRAME_BODY + 1);
                assert_eq!(limit, MAX_FRAME_BODY);
            }
            other => panic!("expected BodyTooLarge, got {other:?}"),
        }
        // Same defence on the compat path.
        match decode_versioned_or_legacy_frame(&bad) {
            Err(FrameError::BodyTooLarge { .. }) => {}
            other => panic!("expected BodyTooLarge, got {other:?}"),
        }

        // (b) Partial frame: encode a real envelope and then feed
        // every too-short prefix to the decoder. Every prefix must
        // return Ok(None) — never a fatal error, never a spurious
        // decode (mirrors the v0 short-body contract).
        let full = encode_versioned_frame(&VersionedAdminMessage::current(AdminMessage::Status(
            StatusRequest {},
        )))
        .unwrap();
        for n in 0..full.len() {
            let res = decode_versioned_frame(&full[..n]).expect("partial is not fatal");
            assert!(res.is_none(), "partial {n}/{} must be None", full.len());
        }

        // (c) Body bytes are not decodable as either v1 OR v0. We
        // hand-build a frame whose body is junk that neither shape
        // will accept (top-bit set on the first varint byte without a
        // continuation byte, then random tail). The compat path
        // tries v1, errors, then tries v0, errors again, then
        // surfaces the v0 postcard error.
        let mut junk_body = vec![0x80u8]; // varint continuation expected but absent
        junk_body.extend_from_slice(&[0xAA, 0xBB, 0xCC]);
        let mut junk_frame = Vec::with_capacity(4 + junk_body.len());
        junk_frame.extend_from_slice(&(junk_body.len() as u32).to_be_bytes());
        junk_frame.extend_from_slice(&junk_body);
        let err = decode_versioned_or_legacy_frame(&junk_frame).unwrap_err();
        assert!(
            matches!(err, FrameError::Postcard(_)),
            "expected Postcard error, got {err:?}"
        );
    }

    /// Supplementary: the strict decoder rejects a v0 frame outright.
    /// Documents the contract that the strict path is "v1 only" and
    /// the compat path is the one to use during migration.
    #[test]
    fn versioned_strict_decoder_does_not_accept_v0_unlock_as_v1() {
        let v0_unlock = encode_frame(&AdminMessage::Unlock(UnlockRequest {
            signature: [0u8; 64],
        }))
        .unwrap();
        // The exact error shape depends on how postcard parses the
        // signature bytes when re-interpreted as `version + message`;
        // what matters is that the decoder does NOT return Ok(Some(_))
        // — that would mean a silent misinterpretation.
        match decode_versioned_frame(&v0_unlock) {
            Ok(None) => {
                panic!("strict decoder claimed v0 frame is an incomplete v1 frame");
            }
            Ok(Some(_)) => {
                panic!("strict decoder silently accepted v0 frame as v1");
            }
            Err(_) => { /* expected: v0 bytes don't parse as a strict v1 envelope */ }
        }
    }

    /// Supplementary: `VersionedAdminMessage::current` always builds
    /// at the current `PROTOCOL_VERSION`. Guards against a future
    /// refactor that pins it to a stale constant.
    #[test]
    fn versioned_current_constructor_uses_protocol_version_constant() {
        let env = VersionedAdminMessage::current(AdminMessage::Status(StatusRequest {}));
        assert_eq!(env.version, PROTOCOL_VERSION);
    }
}
