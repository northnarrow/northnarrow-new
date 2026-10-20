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
    RateLimited {
        retry_after_secs: u32,
    },
    /// Lab PR 217 (NN-AUD-243 residue, capability C17): the agent no longer
    /// releases COMBAT on a signature over the bare nonce — no operation,
    /// install or time is bound to it, and its audit row could not name the
    /// signer. The release is [`AdminMessage::SignedUnlockRequest`]. An
    /// `nn-admin` older than the variant cannot decode this reply and reports
    /// a protocol error (exit 5); it never reads a success.
    LegacyProtocolRefused,
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
    /// Lab PR 217: the request verified, and the agent could not carry it
    /// out — a release whose iptables teardown did not leave the tables
    /// clear, read back. Nothing was reported done. An `nn-admin` older than
    /// the variant cannot decode the reply (a protocol error, exit 5).
    ActionFailed,
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

/// Tappa 9.0.b — signed detections read request. Carries
/// `op = Detections` with the bounded "last N" cap + optional
/// filters (since/until time bounds, min_severity, status, sensor,
/// path) in
/// [`common::wire::admin_signed_payload::DetectionsExtra`].
/// 1-of-N quorum (single-sig, `Role::TelemetryRead` — the
/// lowest-privilege read-only role). Reply on the success path is a
/// [`DetectionsResponse`] carrying the JSONL-encoded detection
/// records rather than the bare [`AdminResult`] superset.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DetectionsRequest {
    pub payload: SignedPayload,
    pub signatures: Vec<KeyedSignature>,
}

/// Tappa 9.0.b — `Detections` reply payload. On success carries the
/// persisted detection records (one per line, `\n`-separated JSONL),
/// **newest-first**, plus the count for the CLI summary line. The
/// records are the `DetectionRecord` payloads (the agent unwraps the
/// chain envelope before serialising), so the `nn-admin` client
/// deserialises them directly without seeing the chain framing — and
/// the wire/`common` layer never has to depend on the agent-side
/// `DetectionRecord` type. On failure, `result` carries the
/// auth/quorum/role error and `entries_jsonl` is empty. Mirrors the
/// [`FimReportResponse`] / net-read truncation contract.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DetectionsResponse {
    /// Auth result — `Success` when the records follow.
    pub result: AdminResult,
    /// Detection records, newest-first, in JSONL form. Empty on auth
    /// failure (and legitimately empty when nothing matches / the
    /// store has no records yet). Bounded by [`MAX_FRAME_BODY`] / 2;
    /// the agent stops appending and sets `entries_truncated` if the
    /// matching set would overflow the frame.
    pub entries_jsonl: String,
    /// Number of records in `entries_jsonl`.
    pub entries_count: u32,
    /// `true` if the agent truncated the body to fit the wire frame.
    /// CLI surfaces this as `"... (truncated; narrow with --limit /
    /// --since / a filter)"`.
    pub entries_truncated: bool,
}

/// Tappa 9.0.c — signed detection triage status-change request.
/// Carries `op = DetectionSetStatus` with the target detection id +
/// new status (lowercase string) + optional note in
/// [`common::wire::admin_signed_payload::DetectionSetStatusExtra`].
/// 1-of-N quorum (single-sig, `Role::Triage`). On verify the agent
/// appends a `StatusEvent` to the SEPARATE `status_events.jsonl`
/// signed chain (event-sourced; `detections.jsonl` is never mutated)
/// and replies with a [`DetectionSetStatusResponse`] ack.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DetectionSetStatusRequest {
    pub payload: SignedPayload,
    pub signatures: Vec<KeyedSignature>,
}

/// Tappa 9.0.c — `DetectionSetStatus` reply ack. On success carries
/// the detection id that was updated and the new status as a lowercase
/// string (echoing what the agent persisted). On failure, `result`
/// carries the auth/quorum/role error; `id` echoes the requested id
/// and `new_status` is empty. A `result` of
/// [`AdminResult::UnknownOperation`] doubles as the "detection not
/// found" (id out of range) signal — the CLI maps it back to a
/// dedicated not-found message (mirrors the K6 canary-burn contract).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DetectionSetStatusResponse {
    /// Auth/validation result — `Success` when the event was persisted.
    pub result: AdminResult,
    /// The detection id the request targeted (echoed on both paths).
    pub id: u64,
    /// The new status as a lowercase string on success; empty on
    /// failure.
    pub new_status: String,
    /// Audit `chain-persist-1`: `true` when the request was valid and
    /// authorised but the status-event APPEND failed (disk full, I/O
    /// error, chain fsync) — the change was NOT recorded. Distinguishes
    /// that case from "detection not found" on the wire, which both
    /// report `result = UnknownOperation`. Additive: older agents omit
    /// it (`false`).
    #[serde(default)]
    pub persist_failed: bool,
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

// ── Tappa 10 N7 — network observability admin ops ─────────────────
//
// Four operator-facing admin ops mirroring the Tappa 9 C6 FIM CLI
// shape + the Tappa 9.5 K6 canary CLI shape. All four are 1-of-N
// quorum (workflow gates, not security gates) authorised by
// `Role::NetRead` per design §9 + §13 Q6 lock-in (single-sig
// admin reads remain the operator-ergonomics standard).
//
// V1.0 dispatch semantics:
//   * `NetFlowsRequest` reads `/var/lib/northnarrow/netflow.jsonl`
//     when present (returns empty if the chain doesn't exist yet);
//     the N7 commit ships the wire shape + auth surface, the
//     drain that populates the chain is N8/follow-up.
//   * `NetListenersRequest` returns the in-process listener
//     snapshot. V1.0 ships the wire shape + empty stub; the
//     userland listener cache wiring is a future commit.
//   * `NetResolveRequest` carries the IP the operator wants the
//     DNS attribution for. V1.0 returns `qname: None` because
//     the back-correlation cache doesn't store resolved IPs
//     (V1.1 DNS-response observer fills this in).
//   * `NetFingerprintRequest` returns recent JA3/JA4 fingerprints
//     observed by the agent. V1.0 stub returns empty; persistence
//     wiring is a future commit.
//
// Every response shares the FimReport-style `entries_jsonl` +
// `entries_count` + `entries_truncated` triple (except NetResolve
// which is a single-record reply).

/// Tappa 10 (N7) — signed NetFlow chain read request (design §9 +
/// §13 Q6). Carries `op = NetFlows` with the optional
/// `since_unix_ts` filter in
/// [`crate::wire::admin_signed_payload::NetFlowsExtra`]. 1-of-N,
/// `Role::NetRead`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetFlowsRequest {
    pub payload: SignedPayload,
    pub signatures: Vec<KeyedSignature>,
}

/// Tappa 10 (N7) — `NetFlows` reply payload. Same truncation-aware
/// shape as `FimReportResponse` — the chained `netflow.jsonl` rows
/// go in `entries_jsonl` (one row per line); `entries_count` for
/// the summary line; `entries_truncated` signals overflow.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetFlowsResponse {
    pub result: AdminResult,
    pub entries_jsonl: String,
    pub entries_count: u32,
    pub entries_truncated: bool,
}

/// Tappa 10 (N7) — signed listener-snapshot request. 1-of-N,
/// `Role::NetRead`. Carries `op = NetListeners` with the empty
/// [`crate::wire::admin_signed_payload::NetListenersExtra`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetListenersRequest {
    pub payload: SignedPayload,
    pub signatures: Vec<KeyedSignature>,
}

/// Tappa 10 (N7) — `NetListeners` reply payload. Same truncation
/// triple as `NetFlowsResponse`. Each row is one [`crate::wire::
/// NetListenerEvent`] in its canonical JSONL form.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetListenersResponse {
    pub result: AdminResult,
    pub entries_jsonl: String,
    pub entries_count: u32,
    pub entries_truncated: bool,
}

/// Tappa 10 (N7) — signed DNS-attribution lookup request. Carries
/// `op = NetResolve` with the target IP in
/// [`crate::wire::admin_signed_payload::NetResolveExtra::ip`].
/// 1-of-N, `Role::NetRead`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetResolveRequest {
    pub payload: SignedPayload,
    pub signatures: Vec<KeyedSignature>,
}

/// Tappa 10 (N7) — `NetResolve` reply payload. Single-shot reply
/// (not chain-shaped). `qname` is `None` when the DNS cache has
/// no attribution for the requested IP, OR when V1.1's DNS-response
/// observer hasn't shipped yet (V1.0 always returns `None`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetResolveResponse {
    pub result: AdminResult,
    /// Resolved hostname (V1.1+) or `None` (V1.0 always, AND
    /// V1.1+ on cache miss).
    pub qname: Option<String>,
    /// UNIX timestamp when the resolution was observed. `None`
    /// when `qname` is None.
    pub queried_at_unix_ts: Option<u64>,
}

/// Tappa 10 (N7) — signed TLS fingerprint dump request. 1-of-N,
/// `Role::NetRead`. Carries `op = NetFingerprint` with the
/// optional `flow_id` filter in
/// [`crate::wire::admin_signed_payload::NetFingerprintExtra`]
/// (V1.0 returns the recent fingerprints regardless of the
/// filter; V1.1 will honor it).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetFingerprintRequest {
    pub payload: SignedPayload,
    pub signatures: Vec<KeyedSignature>,
}

/// Tappa 10 (N7) — `NetFingerprint` reply payload. Same shape as
/// `NetFlowsResponse` — each row is one [`crate::wire::TlsFingerprint`]
/// observation alongside the flow_id it was extracted from.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetFingerprintResponse {
    pub result: AdminResult,
    pub entries_jsonl: String,
    pub entries_count: u32,
    pub entries_truncated: bool,
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
///
/// External audit ASK-009 (lab PR 213): the unsigned `status` carries only
/// what the watchdog and COMBAT recovery need — `posture`,
/// `network_isolation_engaged`, `last_admin_action_secs_ago`,
/// `combat_stage`, `combat_locked` ([`StatusResponse::public`]), and since
/// lab PR 217 `network_isolation_v4` / `network_isolation_v6`. Every
/// other field (the ring drops and rejected records, the netflow pacing and
/// evictions, `FLOW_SOCK_MAP`, the inactive network rules, detect-only, the
/// COMBAT evidence gaps, the encrypted-flow counts) is `None` there and is
/// served by the signed [`TelemetryStatusRequest`] (`audit-read` or
/// `telemetry-read`): a local root without an admin key no longer reads how
/// much the agent is losing. The shape is unchanged; a field appended later
/// is telemetry unless decided otherwise.
///
/// Compatibility (lab PR 193, pinned by the tests
/// `an_older_nn_admin_reads_a_newer_status_reply` and
/// `a_newer_nn_admin_cannot_read_an_older_status_reply`): fields are only
/// appended. An `nn-admin` older than the agent reads the fields it knows
/// (postcard ignores the bytes after them). The reverse does not hold:
/// postcard carries no field count, so `#[serde(default)]` never fills a
/// trailing field an older agent did not send — the reply fails to
/// decode (the watchdog's ping decodes it too, and then fails). The
/// "`None` from an agent older than the field" notes below describe a
/// self-describing decoder; over the admin socket, upgrade the agent with
/// (or before) `nn-admin` and the watchdog.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StatusResponse {
    pub posture: PostureKind,
    pub network_isolation_engaged: bool,
    pub last_admin_action_secs_ago: Option<u64>,
    /// Ring-buffer events dropped since boot, all rings (Tappa 10.8).
    /// `None` from an agent older than the field.
    #[serde(default)]
    pub ringbuf_drops_total: Option<u64>,
    /// `(ring name, dropped)` for the rings that dropped something.
    #[serde(default)]
    pub ringbuf_drops: Option<Vec<(String, u64)>>,
    /// External audit CMB-016: the COMBAT ladder's stage (`INVESTIGATE` /
    /// `NEUTRALIZE` / `ISOLATE`) while an episode is open, else `None`.
    /// `None` also from an agent older than the field.
    #[serde(default)]
    pub combat_stage: Option<String>,
    /// External audit CMB-016: whether the COMBAT is locked (it then needs
    /// a signed `unlock`; an unlocked one decays on its own). `None` from
    /// an agent older than the field.
    #[serde(default)]
    pub combat_locked: Option<bool>,
    /// External audit SNS-008: malformed ring records the agent rejected
    /// since boot (a desynced ring), all rings. `None` from an agent older
    /// than the field.
    #[serde(default)]
    pub ringbuf_rejected_total: Option<u64>,
    /// `(ring, rejected)` for the rings that rejected a record.
    #[serde(default)]
    pub ringbuf_rejected: Option<Vec<(String, u64)>>,
    /// External audit NET-019: netflow rows held back from the rules by
    /// the per-uid pacing since boot (written with
    /// `decision_engine_skipped`). `None` from an agent older than the
    /// field.
    #[serde(default)]
    pub netflow_rows_skipped_total: Option<u64>,
    /// External audit NET-012: pending connects the flow tracker evicted
    /// at capacity since boot. `None` from an agent older than the field.
    #[serde(default)]
    pub netflow_pending_evicted_total: Option<u64>,
    /// External audit NET-009: the network rules that cannot fire in this
    /// build, each with the reason. `None` from an agent older than the
    /// field.
    #[serde(default)]
    pub net_inactive_rules: Option<Vec<String>>,
    /// Lab PR 164: outbound sockets the kernel's `FLOW_SOCK_MAP` holds
    /// without their close seen yet (open sessions and forgotten ones),
    /// its capacity, and the sockets it forgot at least (beyond the
    /// capacity: their closes are not recorded). `None` from an agent
    /// older than the fields, or without the counters.
    #[serde(default)]
    pub flow_sock_pending: Option<u64>,
    #[serde(default)]
    pub flow_sock_capacity: Option<u64>,
    #[serde(default)]
    pub flow_sock_forgotten_min: Option<u64>,
    /// External audit CMB-018 (lab PR 193): whether the agent runs
    /// detect-only — no response action and no COMBAT isolation touches
    /// the system — and what set it (`--detect-only` or `NAME=value` of the
    /// environment variable), as its signed `agent_boot` entry records.
    /// `None` when the agent has no response state (no executor).
    #[serde(default)]
    pub detect_only: Option<bool>,
    #[serde(default)]
    pub detect_only_source: Option<String>,
    /// External audit CMB-027 (lab PR 193): COMBAT stage transitions the
    /// signed audit log did not get when they happened, since boot; of
    /// those, the ones still queued for a late write, and the ones dropped
    /// from the full queue (never written). `None` without a COMBAT ladder.
    #[serde(default)]
    pub combat_evidence_unrecorded: Option<u64>,
    #[serde(default)]
    pub combat_evidence_pending: Option<u64>,
    #[serde(default)]
    pub combat_evidence_dropped: Option<u64>,
    /// External audit NET-017 (lab PR 207): netflow rows recorded since
    /// boot to TCP/853 (DNS over TLS: the names they carry reach no DNS
    /// rule), of those the rows of a known local resolver program (by
    /// image: its upstream), and rows to UDP/443 (QUIC: no TLS handshake
    /// can be read from them). Appended after lab PR 193's fields; `None`
    /// from an agent older than the fields (see the compatibility note
    /// above: a newer `nn-admin` cannot decode an older agent's reply).
    #[serde(default)]
    pub net_dot_rows_total: Option<u64>,
    #[serde(default)]
    pub net_dot_rows_resolver: Option<u64>,
    #[serde(default)]
    pub net_quic_rows_total: Option<u64>,
    /// Lab PR 215: operations the anti-tamper deny hooks let through
    /// undecided since boot (a kernel read a hook needed failed), all
    /// hooks; `None` when the agent does not read the counters (an eBPF
    /// object without `DENY_FAIL_OPEN`) and from an agent older than the
    /// field. Appended after lab PR 207's fields (see the compatibility
    /// note above).
    #[serde(default)]
    pub deny_fail_open_total: Option<u64>,
    /// `(hook, fail-opens)` for the hooks that failed open.
    #[serde(default)]
    pub deny_fail_open: Option<Vec<(String, u64)>>,
    /// Lab PR 217 (capability C18): the COMBAT isolation per IP family, as
    /// the agent's state holds it — set only after the table was read back
    /// (`iptables -S` / `ip6tables -S`) following an engage, cleared only
    /// after a release read back clear. `network_isolation_engaged` is
    /// either of them. Public, like the isolation flag: COMBAT recovery
    /// needs to know an IPv6 hole. `None` from an agent older than the
    /// fields (see the compatibility note above).
    #[serde(default)]
    pub network_isolation_v4: Option<bool>,
    #[serde(default)]
    pub network_isolation_v6: Option<bool>,
    /// Lab PR 218 (external review G-12): the trust level, 0 to 3 (L0 no
    /// enforcement … L3 every mandatory deny hook attached and
    /// self-tested, nothing degraded), recomputed with the degradations
    /// recorded since the boot, and why it is below L3. `None` before the
    /// boot measured it. Appended after lab PR 215's and 217's fields
    /// (which follow lab PR 207's); telemetry (the signed verb only).
    #[serde(default)]
    pub trust_level: Option<u8>,
    #[serde(default)]
    pub trust_reasons: Option<Vec<String>>,
    /// Lab PR 218 (external review P0 C-13 / G-11): every degradation of
    /// this run (a sensor on its fallback, a hook not attached, a stream not
    /// persisted…), each also signed in the audit chain.
    #[serde(default)]
    pub degradations: Option<Vec<String>>,
    /// Lab PR 218: this boot's signed capability manifest, one JSON object
    /// `{"entry_hash": …, "manifest": {…}}` (`nn-admin capabilities`).
    /// `None` before the boot signed it.
    #[serde(default)]
    pub capability_manifest: Option<String>,
    /// Lab PR 219: the exploit post-condition guard — its mode and its
    /// kernel counters since boot. Appended after lab PR 218's fields
    /// (which follow lab PR 215's, 217's and 207's); `None` from an older
    /// agent, and in the unsigned `status` (telemetry).
    #[serde(default)]
    pub exploit_guard: Option<ExploitGuardStatus>,
    /// Lab PR 222: the copy-on-first-write guard (its state, scopes, copies
    /// and skips). Appended after lab PR 219's `exploit_guard` (which
    /// follows lab PR 218's, 217's, 215's and 207's fields); telemetry
    /// (`None` in the unsigned reply, and from an agent without the guard's
    /// code).
    #[serde(default)]
    pub cow_guard: Option<CowGuardStatus>,
    /// Lab PR 223 (EXPERIMENTAL): the exec quarantine — `off`, `enforce`,
    /// `observe`, or `degraded: <why>` — and its counts since boot:
    /// processes the kernel held; resumed, killed, files quarantined;
    /// decided by the default policy (budget expired, file not scannable);
    /// execs the kernel let through on an identity already judged; resumed
    /// on content judged clean earlier; candidates not held (observe mode,
    /// a stale heartbeat, a full ring, a refused signal); scanner deaths.
    /// Appended after lab PR 222's `cow_guard` (lab PR 219's
    /// `exploit_guard`, 218's, 217's, 215's and 207's fields before it);
    /// telemetry (`None` in the unsigned reply).
    #[serde(default)]
    pub execq_state: Option<String>,
    #[serde(default)]
    pub execq_held_total: Option<u64>,
    #[serde(default)]
    pub execq_resumed_total: Option<u64>,
    #[serde(default)]
    pub execq_killed_total: Option<u64>,
    #[serde(default)]
    pub execq_quarantined_total: Option<u64>,
    #[serde(default)]
    pub execq_defaulted_total: Option<u64>,
    #[serde(default)]
    pub execq_known_identity_total: Option<u64>,
    #[serde(default)]
    pub execq_known_hash_total: Option<u64>,
    #[serde(default)]
    pub execq_not_held_total: Option<u64>,
    #[serde(default)]
    pub execq_scanner_deaths_total: Option<u64>,
    /// Lab PR 224 (CM-02): verdicts given to a TCP flow at its connect,
    /// while it was open, since boot; open-flow snapshots the rules
    /// re-judged (long-lived flows, every snapshot interval), and those
    /// due but deferred to a later tick by the per-tick bound; connects
    /// the optional `socket_connect` deny refused in the kernel (`None`
    /// when the deny is off). Appended after lab PR 223's `execq_*` (the
    /// fields of lab PRs 215 to 223 before them, after lab PR 207's); `None`
    /// from an agent older than the fields.
    #[serde(default)]
    pub net_connect_verdicts_total: Option<u64>,
    #[serde(default)]
    pub net_flow_snapshots_total: Option<u64>,
    #[serde(default)]
    pub net_flow_snapshots_deferred_total: Option<u64>,
    #[serde(default)]
    pub net_connect_denied_total: Option<u64>,
}

/// Lab PR 219: the exploit post-condition guard in `nn-admin status`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExploitGuardStatus {
    /// `detect`, `enforce`, `off`, `unavailable: <reason>`, `not started`.
    pub mode: String,
    /// Calls judged at `sys_exit`.
    pub checked_total: u64,
    /// `sys_enter`s of fully privileged tasks (not judged).
    pub skipped_privileged_total: u64,
    /// Anomalies found (recorded or over a task's record budget).
    pub anomalies_total: u64,
    /// Tasks sent `SIGKILL` (enforce).
    pub kills_total: u64,
    /// Tasks the task map could not keep: strict's new tasks a full map
    /// left untracked, or lite's records its LRU map evicted (re-taken at
    /// the next hook: degraded evidence). One variant runs at a time.
    pub untracked_total: u64,
    /// Lite: privilege uses judged (`capable`, exec, guarded `file_open`).
    pub use_checks_total: u64,
    /// Lite enforce: uses refused (`-EPERM`).
    pub denied_total: u64,
}

impl StatusResponse {
    /// Lab PR 217: [`Self::public`] with the isolation per IP family (and
    /// `network_isolation_engaged` set to either of them).
    pub fn with_isolation_families(mut self, v4: bool, v6: bool) -> Self {
        self.network_isolation_engaged = v4 || v6;
        self.network_isolation_v4 = Some(v4);
        self.network_isolation_v6 = Some(v6);
        self
    }

    /// External audit ASK-009 (lab PR 213): the reply to the unsigned
    /// `status` — the posture, the isolation, the last admin action and the
    /// COMBAT stage and lock, the telemetry withheld (`None`; the signed
    /// [`TelemetryStatusRequest`] serves it). Every field is named here, so
    /// a field appended to the struct must be placed on one side or the
    /// other.
    pub fn public(
        posture: PostureKind,
        network_isolation_engaged: bool,
        last_admin_action_secs_ago: Option<u64>,
        combat_stage: Option<String>,
        combat_locked: Option<bool>,
    ) -> Self {
        Self {
            posture,
            network_isolation_engaged,
            last_admin_action_secs_ago,
            combat_stage,
            combat_locked,
            ringbuf_drops_total: None,
            ringbuf_drops: None,
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
        }
    }

    /// The fields [`Self::public`] withholds are all `None` (an unsigned
    /// reply of this build, or of an agent older than all of them).
    pub fn telemetry_withheld(&self) -> bool {
        let mut public = Self::public(
            self.posture,
            self.network_isolation_engaged,
            self.last_admin_action_secs_ago,
            self.combat_stage.clone(),
            self.combat_locked,
        );
        // Lab PR 217: public fields, passed through.
        public.network_isolation_v4 = self.network_isolation_v4;
        public.network_isolation_v6 = self.network_isolation_v6;
        *self == public
    }
}

/// External audit ASK-009 (lab PR 213): the postcard index of
/// [`AdminMessage::StatusResponse`], the first byte of its frame body. The
/// same with and without `debug-trigger` (pinned by
/// `production_discriminants_do_not_depend_on_debug_trigger`).
pub const STATUS_RESPONSE_INDEX: u32 = 5;

/// The two leading fields of a [`StatusResponse`]: every agent has sent
/// them first and always will (fields are only appended).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct StatusLiveness {
    pub posture: PostureKind,
    pub network_isolation_engaged: bool,
}

/// Why a reply body is not a status reply ([`decode_status_liveness`]).
#[derive(Debug)]
pub enum StatusLivenessError {
    /// The body does not start with a variant index and the two leading
    /// fields.
    Postcard(postcard::Error),
    /// Another variant than [`AdminMessage::StatusResponse`].
    NotAStatusResponse { index: u32 },
}

impl core::fmt::Display for StatusLivenessError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Postcard(e) => write!(f, "not a status reply: {e}"),
            Self::NotAStatusResponse { index } => write!(
                f,
                "unexpected reply variant {index} (wanted StatusResponse, {STATUS_RESPONSE_INDEX})"
            ),
        }
    }
}

impl std::error::Error for StatusLivenessError {}

/// External audit ASK-009 (lab PR 213): the watchdog's view of a `status`
/// reply — its variant index and its two leading fields, the rest ignored.
/// A ping then does not depend on the fields appended to [`StatusResponse`]
/// since the agent was built: a watchdog newer than the agent reads an
/// older agent's reply (a full decode fails on the fields the older agent
/// did not send: postcard has no field count), and one older reads a newer
/// agent's. `body` is the frame body, after the 4-byte length.
pub fn decode_status_liveness(body: &[u8]) -> Result<StatusLiveness, StatusLivenessError> {
    let (index, rest) =
        postcard::take_from_bytes::<u32>(body).map_err(StatusLivenessError::Postcard)?;
    if index != STATUS_RESPONSE_INDEX {
        return Err(StatusLivenessError::NotAStatusResponse { index });
    }
    postcard::take_from_bytes::<StatusLiveness>(rest)
        .map(|(liveness, _)| liveness)
        .map_err(StatusLivenessError::Postcard)
}

/// Lab PR 216: the postcard index of [`AdminMessage::LoopProgressResponse`]
/// (pinned by `production_discriminants_do_not_depend_on_debug_trigger`).
pub const LOOP_PROGRESS_RESPONSE_INDEX: u32 = 53;

/// Lab PR 216: the watchdog's read of a [`LoopProgressResponse`] frame
/// body — the variant index, then the fields it knows; fields a newer agent
/// appends are trailing bytes, ignored. Another variant is
/// [`StatusLivenessError::NotAStatusResponse`] with its index.
pub fn decode_loop_progress(body: &[u8]) -> Result<LoopProgressResponse, StatusLivenessError> {
    let (index, rest) =
        postcard::take_from_bytes::<u32>(body).map_err(StatusLivenessError::Postcard)?;
    if index != LOOP_PROGRESS_RESPONSE_INDEX {
        return Err(StatusLivenessError::NotAStatusResponse { index });
    }
    postcard::take_from_bytes::<LoopProgressResponse>(rest)
        .map(|(progress, _)| progress)
        .map_err(StatusLivenessError::Postcard)
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
/// FIM-009 self-upgrade (§15.1) — signed trusted-installer grant
/// request. Carries the full [`SignedPayload`] (`op =
/// TrustedInstallerGrant`, `extra = TrustedInstallerGrant { window_secs
/// }`) plus the signature quorum. Verified 1-of-N (M=1) today — like
/// COMBAT reactivation — but expressed through the quorum path so M can
/// be raised without re-architecting. Required role:
/// [`common::wire::admin_signed_payload::Role::TrustedInstaller`]. On
/// verify the agent arms the TTL'd FS-pin override and downgrades
/// NN-L-FIM-009 for its OWN units for the (clamped) window's duration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrustedInstallerGrantRequest {
    pub payload: SignedPayload,
    pub signatures: Vec<KeyedSignature>,
}

/// Largest overlay `nn-admin config overlay set` carries (fits the frame
/// with the payload and two signatures). Overlays are short lists.
pub const MAX_OVERLAY_BYTES: usize = 32 * 1024;

/// Tappa 10.8 — store a signed operator overlay. `payload` is a
/// `ConfigOverlaySet` payload (kind + SHA-256 + length of `content`) signed
/// over the server challenge; `content` is the overlay text. The agent
/// verifies the quorum (role `config-manage`, 1-of-N), checks that
/// `content` matches the signed hash and parses as that overlay kind, then
/// writes the overlay and its signature file itself. It takes effect at the
/// next agent start.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfigOverlaySetRequest {
    pub payload: SignedPayload,
    pub signatures: Vec<KeyedSignature>,
    pub content: String,
}

/// Reply to [`ConfigOverlaySetRequest`]. `result` is the authentication
/// outcome; `stored` says whether the overlay and its signature were
/// written (a verified request can still be refused: content that does not
/// match the signed hash or does not parse as that overlay kind);
/// `message` names the files written, or why nothing was.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfigOverlaySetResponse {
    pub result: AdminResult,
    pub stored: bool,
    pub message: String,
}

// ── External audit CMB-016 — undoing a response ───────────────────
//
// Three signed verbs, 1-of-N: `response status` (read-only, `audit-read`),
// `response release` and `response restore` (`response-manage`). The agent runs them; nothing is done by the CLI.

/// Most rows of each list a [`ResponseStatusResponse`] carries (the
/// newest); the totals say how many there are.
pub const MAX_RESPONSE_STATUS_ROWS: usize = 100;

/// Signed `response status` request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResponseStatusRequest {
    pub payload: SignedPayload,
    pub signatures: Vec<KeyedSignature>,
}

/// One process the agent moved into its `blocked` or `throttled` scope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContainedProcessWire {
    pub pid: u32,
    /// `blocked` or `throttled`.
    pub scope: String,
    /// The cgroup it came from (`/system.slice/foo.service`).
    pub origin: String,
    /// Unix time of the move.
    pub since: u64,
    /// The pid still names the process that was moved (same start time).
    pub running: bool,
}

/// One entry of the quarantine vault.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QuarantinedFileWire {
    pub vault_id: String,
    pub original_path: String,
    pub size_bytes: u64,
    pub captured_at: u64,
}

/// Reply to [`ResponseStatusRequest`]. The lists are empty unless
/// `result` is `Success`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResponseStatusResponse {
    pub result: AdminResult,
    pub contained: Vec<ContainedProcessWire>,
    pub contained_total: u32,
    pub quarantined: Vec<QuarantinedFileWire>,
    pub quarantined_total: u32,
    /// As in [`StatusResponse::combat_stage`].
    pub combat_stage: Option<String>,
    /// As in [`StatusResponse::combat_locked`].
    pub combat_locked: Option<bool>,
}

/// Signed `response release` request (`ResponseReleaseExtra { pid }`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResponseReleaseRequest {
    pub payload: SignedPayload,
    pub signatures: Vec<KeyedSignature>,
}

/// Reply to [`ResponseReleaseRequest`]. `released` is true when the
/// process went back to the cgroup it came from; `message` says what was
/// done, or why not.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResponseReleaseResponse {
    pub result: AdminResult,
    pub released: bool,
    pub message: String,
}

/// Signed `response restore` request (`ResponseRestoreExtra { vault_id,
/// to }`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResponseRestoreRequest {
    pub payload: SignedPayload,
    pub signatures: Vec<KeyedSignature>,
}

/// Reply to [`ResponseRestoreRequest`]. `path` is where the file was
/// written when `restored`; `message` says why not otherwise.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResponseRestoreResponse {
    pub result: AdminResult,
    pub restored: bool,
    pub path: String,
    pub message: String,
}

/// External audit ASK-009 (lab PR 213) — signed `status --key` /
/// `net status --key`: the telemetry the unsigned `status` withholds.
/// 1-of-N, `audit-read` or `telemetry-read`; one audit row per request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TelemetryStatusRequest {
    pub payload: SignedPayload,
    pub signatures: Vec<KeyedSignature>,
}

/// Reply to [`TelemetryStatusRequest`]: `status` is the whole
/// [`StatusResponse`], the telemetry filled in, when `result` is
/// `Success`, else `None`. Last field, so the fields later appended to
/// [`StatusResponse`] stay at the end of the body.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TelemetryStatusResponse {
    pub result: AdminResult,
    pub status: Option<StatusResponse>,
}

/// Lab PR 216 (capability C23): the watchdog's event-loop progress query.
/// Unsigned, read-only, sent on the connection of its STATUS ping right
/// after the status reply. The STATUS reply proves only that the admin
/// socket's task answers; it runs beside the agent's event loop on the
/// multi-thread runtime, so a loop that stands still behind a blocked
/// `process_event` answered every ping. Empty, like [`StatusRequest`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct LoopProgressRequest {}

/// Reply to [`LoopProgressRequest`]: how many times the agent's event loop
/// has gone round since the agent started (0 until it is entered: the agent
/// is still starting), and how long ago (milliseconds) the last round
/// began — since the agent started while `iterations` is 0. The loop goes
/// round at least every 5 s on an idle host (its telemetry-task check), so
/// a counter that does not move over three pings 30 s apart is a loop
/// that stands still. Fields are only appended.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct LoopProgressResponse {
    pub iterations: u64,
    pub since_last_ms: u64,
}

/// Lab PR 217 (NN-AUD-243 residue, capability C17) — signed `unlock`: the
/// release of COMBAT, signed over a [`SignedPayload`] with
/// `op = Unlock` (`extra = Unlock {}`) like every other admin operation —
/// the challenge, the time, the install and the operation inside the signed
/// scope — 1-of-N, `Role::Unlock`. Replaces [`UnlockRequest`] (a signature
/// over the bare nonce), which the agent now refuses
/// ([`UnlockResult::LegacyProtocolRefused`]). The audit row of the release
/// names the signer's fingerprint.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedUnlockRequest {
    pub payload: SignedPayload,
    pub signatures: Vec<KeyedSignature>,
}

/// Lab PR 222 — the copy-on-first-write guard, as `status --key` shows it
/// ([`StatusResponse::cow_guard`]). Telemetry: withheld by the unsigned
/// `status`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CowGuardStatus {
    /// `off` (no signed `cow-guard.local`, or `enabled = false`),
    /// `running`, `failed: <why>` (configured, could not start), `stopped:
    /// <why>` (it stopped after the start: the group was closed).
    pub state: String,
    /// Where the writers' open flags come from (`proc_syscall`, or why
    /// they cannot be read: every open is then treated as a write).
    pub flags_source: String,
    /// Restores run on their own when COMBAT neutralizes ransomware.
    pub auto_restore: bool,
    pub scopes: Vec<CowScopeStatus>,
    /// Counters since the start, by name (copies, skips by reason, answer
    /// latencies in microseconds, restores) — named, so a counter added
    /// later needs no new field.
    pub counters: Vec<(String, u64)>,
}

/// One protected scope of [`CowGuardStatus`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CowScopeStatus {
    pub path: String,
    /// `dirs`, `mount` or `filesystem`.
    pub mark: String,
    pub journal: String,
    /// `reflink` when the journal's filesystem shares extents (`FICLONE`
    /// worked at the start), else `copy` (files up to the copy cap).
    pub copy_method: String,
    /// Directories marked (`dirs`), else 1.
    pub marks: u64,
    pub budget_bytes: u64,
    pub used_bytes: u64,
    pub entries: u64,
    pub objects: u64,
}

/// Signed `remediate ransomware` request (`RemediateRansomwareExtra`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RemediateRansomwareRequest {
    pub payload: SignedPayload,
    pub signatures: Vec<KeyedSignature>,
}

/// Reply to [`SignedUnlockRequest`]. `result` is `Success` only when the
/// release was carried out and read back — the COMBAT chain gone from both
/// tables (`iptables -S` / `ip6tables -S`) — and [`AdminResult::ActionFailed`]
/// when the request verified but the teardown did not leave the tables
/// clear (the posture then stays COMBAT); any other value is the
/// authentication refusal. `released` repeats it; `isolation_v4` /
/// `isolation_v6` are what the agent's per-family isolation state says after
/// the call; `message` names what was done, or why not.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedUnlockResponse {
    pub result: AdminResult,
    pub released: bool,
    pub isolation_v4: bool,
    pub isolation_v6: bool,
    pub message: String,
}

/// One file of a restore: what was done with it and why.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CowRestoreRow {
    pub path: String,
    /// `restored_in_place`, `recreated`, `kept_both`, `unchanged`,
    /// `refused`, `skipped` (a dry run says what it would do, prefixed
    /// `would_`).
    pub action: String,
    /// The journal entry restored from.
    pub entry: u64,
    pub detail: String,
    /// Where the original was written when both were kept.
    pub beside: Option<String>,
    /// Where an encrypted copy the attack left (renamed) was moved.
    pub evidence: Option<String>,
    pub sha256_original: String,
    /// SHA-256 of the file after the restore (`None`: not written).
    pub sha256_after: Option<String>,
}

/// Reply to [`RemediateRansomwareRequest`]. `rows` lists the first files
/// (at most [`REMEDIATE_ROWS_MAX`]); every file has its own signed audit
/// row (`cow_restore`) whatever the list shows. `done`: something was
/// restored (or, in a dry run, would be).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RemediateRansomwareResponse {
    pub result: AdminResult,
    pub done: bool,
    pub message: String,
    pub rows: Vec<CowRestoreRow>,
    pub rows_total: u32,
    pub restored: u32,
    pub recreated: u32,
    pub kept_both: u32,
    pub unchanged: u32,
    pub refused: u32,
    pub skipped: u32,
}

/// Files listed in a [`RemediateRansomwareResponse`] (the frame body is
/// 64 KiB at most).
pub const REMEDIATE_ROWS_MAX: usize = 120;

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

    // ── server → client ────────────────────────────────────────
    Challenge(Challenge),
    UnlockResult(UnlockResult),
    StatusResponse(StatusResponse),

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
    /// Tappa 10 (N7) — signed NetFlows chain read request.
    /// Triggers [`AdminMessage::NetFlowsResponse`].
    NetFlowsRequest(NetFlowsRequest),
    /// Reply to [`AdminMessage::NetFlowsRequest`] — carries the
    /// chained JSONL body + truncation flag.
    NetFlowsResponse(NetFlowsResponse),
    /// Tappa 10 (N7) — signed listener snapshot request.
    /// Triggers [`AdminMessage::NetListenersResponse`].
    NetListenersRequest(NetListenersRequest),
    /// Reply to [`AdminMessage::NetListenersRequest`] —
    /// listener-snapshot JSONL body.
    NetListenersResponse(NetListenersResponse),
    /// Tappa 10 (N7) — signed DNS-attribution lookup request.
    /// Triggers [`AdminMessage::NetResolveResponse`].
    NetResolveRequest(NetResolveRequest),
    /// Reply to [`AdminMessage::NetResolveRequest`] — single-
    /// shot reply carrying the resolved qname or `None`.
    NetResolveResponse(NetResolveResponse),
    /// Tappa 10 (N7) — signed TLS fingerprint dump request.
    /// Triggers [`AdminMessage::NetFingerprintResponse`].
    NetFingerprintRequest(NetFingerprintRequest),
    /// Reply to [`AdminMessage::NetFingerprintRequest`] —
    /// fingerprint-observation JSONL body.
    NetFingerprintResponse(NetFingerprintResponse),
    /// FIM-009 self-upgrade (§15.1) — signed trusted-installer grant
    /// request. Triggers [`AdminMessage::TrustedInstallerGrantResult`].
    TrustedInstallerGrantRequest(TrustedInstallerGrantRequest),
    /// Reply to [`AdminMessage::TrustedInstallerGrantRequest`]. Bare
    /// [`AdminResult`] superset (success / verify-failure variants).
    TrustedInstallerGrantResult(AdminResult),
    /// Tappa 9.0.b — signed detections read request. Triggers
    /// [`AdminMessage::DetectionsResponse`].
    DetectionsRequest(DetectionsRequest),
    /// Reply to [`AdminMessage::DetectionsRequest`] — the persisted
    /// detection records (newest-first JSONL body) on success.
    DetectionsResponse(DetectionsResponse),
    /// Tappa 9.0.c — signed detection triage status-change request.
    /// Triggers [`AdminMessage::DetectionSetStatusResponse`].
    DetectionSetStatusRequest(DetectionSetStatusRequest),
    /// Reply to [`AdminMessage::DetectionSetStatusRequest`] — the ack
    /// (id + new status) on success.
    DetectionSetStatusResponse(DetectionSetStatusResponse),
    /// Tappa 10.8 — signed overlay store request. Triggers
    /// [`AdminMessage::ConfigOverlaySetResult`].
    ConfigOverlaySetRequest(ConfigOverlaySetRequest),
    /// Reply to [`AdminMessage::ConfigOverlaySetRequest`].
    ConfigOverlaySetResponse(ConfigOverlaySetResponse),
    /// External audit CMB-016 — signed read of what the response layer
    /// holds. Triggers [`AdminMessage::ResponseStatusResponse`].
    ResponseStatusRequest(ResponseStatusRequest),
    /// Reply to [`AdminMessage::ResponseStatusRequest`].
    ResponseStatusResponse(ResponseStatusResponse),
    /// External audit CMB-016 — signed release of a contained process.
    /// Triggers [`AdminMessage::ResponseReleaseResponse`].
    ResponseReleaseRequest(ResponseReleaseRequest),
    /// Reply to [`AdminMessage::ResponseReleaseRequest`].
    ResponseReleaseResponse(ResponseReleaseResponse),
    /// External audit CMB-016 — signed restore of a quarantined file.
    /// Triggers [`AdminMessage::ResponseRestoreResponse`].
    ResponseRestoreRequest(ResponseRestoreRequest),
    /// Reply to [`AdminMessage::ResponseRestoreRequest`].
    ResponseRestoreResponse(ResponseRestoreResponse),
    /// External audit ASK-009 (lab PR 213) — signed read of the telemetry
    /// the unsigned `status` withholds. Triggers
    /// [`AdminMessage::TelemetryStatusResponse`].
    TelemetryStatusRequest(TelemetryStatusRequest),
    /// Reply to [`AdminMessage::TelemetryStatusRequest`].
    TelemetryStatusResponse(TelemetryStatusResponse),
    /// Lab PR 216 — unsigned event-loop progress query (the watchdog's,
    /// after its STATUS ping). Triggers
    /// [`AdminMessage::LoopProgressResponse`]. An agent older than the
    /// variant cannot decode it and closes the connection; the watchdog
    /// then relies on the STATUS answer alone, as before.
    LoopProgress(LoopProgressRequest),
    /// Reply to [`AdminMessage::LoopProgress`].
    LoopProgressResponse(LoopProgressResponse),
    /// Lab PR 217 — signed release of COMBAT (`OperationCode::Unlock`).
    /// Triggers [`AdminMessage::SignedUnlockResponse`]. An agent older than
    /// the variant cannot decode it and closes the connection.
    SignedUnlockRequest(SignedUnlockRequest),
    /// Reply to [`AdminMessage::SignedUnlockRequest`].
    SignedUnlockResponse(SignedUnlockResponse),
    /// Lab PR 222 — signed restore from the copy-on-first-write journal.
    /// Triggers [`AdminMessage::RemediateRansomwareResponse`].
    RemediateRansomwareRequest(RemediateRansomwareRequest),
    /// Reply to [`AdminMessage::RemediateRansomwareRequest`].
    RemediateRansomwareResponse(RemediateRansomwareResponse),

    // ── debug-only, LAST (external audit ASK-016, lab PR 170) ─────
    // A `cfg` variant shifts the postcard discriminant of every variant
    // after it: in the middle of the enum, a `debug-trigger` build (the
    // lab's) read a production peer's `StatusResponse` as another variant
    // — a lab agent's watchdog built without the feature never saw a ping
    // answered. New production variants go ABOVE this block.
    /// Debug-only: force a posture transition. Triggers an empty
    /// [`AdminMessage::DebugForcePostureAck`] reply on success.
    #[cfg(feature = "debug-trigger")]
    DebugForcePosture(DebugForcePosture),
    /// Debug-only reply to [`AdminMessage::DebugForcePosture`].
    #[cfg(feature = "debug-trigger")]
    DebugForcePostureAck,
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

    /// External audit ASK-016 (lab PR 170): the postcard discriminant of
    /// the production variants is the same with and without
    /// `debug-trigger` (the first byte of the encoding is the variant
    /// index); the debug-only variants come last. Run in both feature sets
    /// (CI: `cargo test -p northnarrow-common --features debug-trigger`).
    #[test]
    fn production_discriminants_do_not_depend_on_debug_trigger() {
        let first = |m: &AdminMessage| postcard::to_allocvec(m).unwrap()[0];
        assert_eq!(first(&AdminMessage::Status(StatusRequest {})), 2);
        // after both debug-only variants in the old order: it moved by 2
        // there (StatusResponse, the watchdog's, by 1)
        assert_eq!(
            first(&AdminMessage::ShutdownResult(AdminResult::RoleDenied)),
            7,
            "ShutdownResult"
        );
        let restore = AdminMessage::ResponseRestoreResponse(ResponseRestoreResponse {
            result: AdminResult::RoleDenied,
            restored: false,
            path: String::new(),
            message: String::new(),
        });
        assert_eq!(first(&restore), 49, "ResponseRestoreResponse");
        // External audit ASK-009 (lab PR 213): the signed telemetry verb,
        // appended after it.
        let telemetry = AdminMessage::TelemetryStatusResponse(TelemetryStatusResponse {
            result: AdminResult::RoleDenied,
            status: None,
        });
        assert_eq!(first(&telemetry), 51, "TelemetryStatusResponse");
        // Lab PR 216: the watchdog's event-loop progress query, appended.
        assert_eq!(
            first(&AdminMessage::LoopProgress(LoopProgressRequest {})),
            52,
            "LoopProgress"
        );
        assert_eq!(
            first(&AdminMessage::LoopProgressResponse(
                LoopProgressResponse::default()
            )) as u32,
            LOOP_PROGRESS_RESPONSE_INDEX,
            "LoopProgressResponse, the watchdog's progress decode"
        );
        // Lab PR 217: the signed unlock, appended after lab PR 216's pair.
        let unlock_request = AdminMessage::SignedUnlockRequest(SignedUnlockRequest {
            payload: SignedPayload::new_unlock([0; 32], 0, [0; 16]),
            signatures: Vec::new(),
        });
        assert_eq!(first(&unlock_request), 54, "SignedUnlockRequest");
        let unlock = AdminMessage::SignedUnlockResponse(SignedUnlockResponse {
            result: AdminResult::ActionFailed,
            released: false,
            isolation_v4: true,
            isolation_v6: false,
            message: String::new(),
        });
        assert_eq!(first(&unlock), 55, "SignedUnlockResponse");
        // Lab PR 222: the signed restore of the copy-on-first-write
        // journal, appended after lab PR 217's pair.
        let remediate = AdminMessage::RemediateRansomwareRequest(RemediateRansomwareRequest {
            payload: SignedPayload::new_remediate_ransomware(
                [0; 32],
                0,
                [0; 16],
                Some(1),
                None,
                true,
            ),
            signatures: Vec::new(),
        });
        assert_eq!(first(&remediate), 56, "RemediateRansomwareRequest");
        let remediated = AdminMessage::RemediateRansomwareResponse(RemediateRansomwareResponse {
            result: AdminResult::RoleDenied,
            done: false,
            message: String::new(),
            rows: Vec::new(),
            rows_total: 0,
            restored: 0,
            recreated: 0,
            kept_both: 0,
            unchanged: 0,
            refused: 0,
            skipped: 0,
        });
        assert_eq!(first(&remediated), 57, "the last production variant");
        assert_eq!(
            first(&AdminMessage::StatusResponse(StatusResponse::public(
                PostureKind::Observing,
                false,
                None,
                None,
                None
            ))) as u32,
            STATUS_RESPONSE_INDEX,
            "the watchdog's liveness decode"
        );
        #[cfg(feature = "debug-trigger")]
        {
            assert_eq!(
                first(&AdminMessage::DebugForcePosture(DebugForcePosture::Combat)),
                58
            );
            assert_eq!(first(&AdminMessage::DebugForcePostureAck), 59);
        }
    }

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
        }));
    }

    #[test]
    fn roundtrip_status_response_no_admin_action() {
        roundtrip(AdminMessage::StatusResponse(StatusResponse {
            posture: PostureKind::Observing,
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
                | AdminMessage::CanaryRefreshResult(_)
                | AdminMessage::NetFlowsRequest(_)
                | AdminMessage::NetFlowsResponse(_)
                | AdminMessage::NetListenersRequest(_)
                | AdminMessage::NetListenersResponse(_)
                | AdminMessage::NetResolveRequest(_)
                | AdminMessage::NetResolveResponse(_)
                | AdminMessage::NetFingerprintRequest(_)
                | AdminMessage::NetFingerprintResponse(_)
                | AdminMessage::TrustedInstallerGrantRequest(_)
                | AdminMessage::TrustedInstallerGrantResult(_)
                | AdminMessage::DetectionsRequest(_)
                | AdminMessage::DetectionsResponse(_)
                | AdminMessage::DetectionSetStatusRequest(_)
                | AdminMessage::DetectionSetStatusResponse(_)
                | AdminMessage::ConfigOverlaySetRequest(_)
                | AdminMessage::ConfigOverlaySetResponse(_)
                | AdminMessage::ResponseStatusRequest(_)
                | AdminMessage::ResponseStatusResponse(_)
                | AdminMessage::ResponseReleaseRequest(_)
                | AdminMessage::ResponseReleaseResponse(_)
                | AdminMessage::ResponseRestoreRequest(_)
                | AdminMessage::ResponseRestoreResponse(_)
                | AdminMessage::TelemetryStatusRequest(_)
                | AdminMessage::TelemetryStatusResponse(_)
                | AdminMessage::LoopProgress(_)
                | AdminMessage::LoopProgressResponse(_)
                | AdminMessage::SignedUnlockRequest(_)
                | AdminMessage::SignedUnlockResponse(_)
                | AdminMessage::RemediateRansomwareRequest(_)
                | AdminMessage::RemediateRansomwareResponse(_) => {}
            }
        }
    }

    /// FIM-009 self-upgrade (§15.1): the trusted-installer grant request
    /// survives a wire round-trip. The signed pre-image is re-serialised
    /// before verify, so a field-order drift would silently break
    /// signature verification — this anchors the CBOR/postcard shape.
    /// External audit CMB-016: the COMBAT fields survive the wire.
    #[test]
    fn roundtrip_status_response_with_combat_stage() {
        roundtrip(AdminMessage::StatusResponse(StatusResponse {
            posture: PostureKind::Combat,
            network_isolation_engaged: false,
            last_admin_action_secs_ago: None,
            ringbuf_drops_total: Some(0),
            ringbuf_drops: Some(Vec::new()),
            combat_stage: Some("NEUTRALIZE".to_string()),
            combat_locked: Some(true),
            ringbuf_rejected_total: Some(3),
            ringbuf_rejected: Some(vec![("open_sensor".to_string(), 3)]),
            netflow_rows_skipped_total: Some(5),
            netflow_pending_evicted_total: Some(2),
            net_inactive_rules: Some(vec!["NN-L-NET-003 (JA3)".to_string()]),
            flow_sock_pending: Some(70_000),
            flow_sock_capacity: Some(65_536),
            flow_sock_forgotten_min: Some(4_464),
            detect_only: Some(true),
            detect_only_source: Some("NN_DETECT_ONLY=1".to_string()),
            combat_evidence_unrecorded: Some(3),
            combat_evidence_pending: Some(1),
            combat_evidence_dropped: Some(0),
            net_dot_rows_total: Some(12),
            net_dot_rows_resolver: Some(10),
            net_quic_rows_total: Some(40),
            deny_fail_open_total: Some(3),
            deny_fail_open: Some(vec![("file_open".to_string(), 3)]),
            network_isolation_v4: None,
            network_isolation_v6: None,
            trust_level: None,
            trust_reasons: None,
            degradations: None,
            capability_manifest: None,
            exploit_guard: Some(ExploitGuardStatus {
                mode: "lite enforce".to_string(),
                checked_total: 1_000,
                skipped_privileged_total: 400,
                anomalies_total: 1,
                kills_total: 1,
                untracked_total: 0,
                use_checks_total: 0,
                denied_total: 0,
            }),
            cow_guard: Some(CowGuardStatus {
                state: "running".to_string(),
                flags_source: "proc_syscall".to_string(),
                auto_restore: false,
                scopes: vec![CowScopeStatus {
                    path: "/srv".to_string(),
                    mark: "dirs".to_string(),
                    journal: "/srv/.northnarrow-cow".to_string(),
                    copy_method: "copy".to_string(),
                    marks: 12,
                    budget_bytes: 1 << 30,
                    used_bytes: 4096,
                    entries: 3,
                    objects: 2,
                }],
                counters: vec![("copies_reflink".to_string(), 2)],
            }),
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
            net_connect_verdicts_total: Some(4),
            net_flow_snapshots_total: Some(120),
            net_flow_snapshots_deferred_total: Some(0),
            net_connect_denied_total: Some(2),
        }));
    }

    /// The status reply as it was before lab PR 193 (lab PR 164's last
    /// field), for the compatibility pins.
    #[derive(Debug, PartialEq, Serialize, Deserialize)]
    struct StatusResponseLabPr164 {
        posture: PostureKind,
        network_isolation_engaged: bool,
        last_admin_action_secs_ago: Option<u64>,
        ringbuf_drops_total: Option<u64>,
        ringbuf_drops: Option<Vec<(String, u64)>>,
        combat_stage: Option<String>,
        combat_locked: Option<bool>,
        ringbuf_rejected_total: Option<u64>,
        ringbuf_rejected: Option<Vec<(String, u64)>>,
        netflow_rows_skipped_total: Option<u64>,
        netflow_pending_evicted_total: Option<u64>,
        net_inactive_rules: Option<Vec<String>>,
        flow_sock_pending: Option<u64>,
        flow_sock_capacity: Option<u64>,
        flow_sock_forgotten_min: Option<u64>,
    }

    fn status_with_lab193_fields() -> StatusResponse {
        StatusResponse {
            posture: PostureKind::Combat,
            network_isolation_engaged: false,
            last_admin_action_secs_ago: Some(7),
            ringbuf_drops_total: Some(0),
            ringbuf_drops: Some(Vec::new()),
            combat_stage: Some("ISOLATE".to_string()),
            combat_locked: Some(true),
            ringbuf_rejected_total: Some(0),
            ringbuf_rejected: Some(Vec::new()),
            netflow_rows_skipped_total: Some(0),
            netflow_pending_evicted_total: Some(0),
            net_inactive_rules: Some(Vec::new()),
            flow_sock_pending: None,
            flow_sock_capacity: None,
            flow_sock_forgotten_min: None,
            detect_only: Some(true),
            detect_only_source: Some("--detect-only".to_string()),
            combat_evidence_unrecorded: Some(2),
            combat_evidence_pending: Some(2),
            combat_evidence_dropped: Some(0),
            net_dot_rows_total: Some(3),
            net_dot_rows_resolver: Some(2),
            net_quic_rows_total: Some(5),
            deny_fail_open_total: Some(1),
            deny_fail_open: Some(vec![("bpf".to_string(), 1)]),
            network_isolation_v4: None,
            network_isolation_v6: None,
            trust_level: Some(2),
            trust_reasons: Some(vec!["1 degradation(s) recorded".to_string()]),
            degradations: Some(vec!["dns_sensor: IPv6 resolvers not observed".to_string()]),
            capability_manifest: Some("{\"entry_hash\":\"ab\",\"manifest\":{}}".to_string()),
            exploit_guard: Some(ExploitGuardStatus {
                mode: "lite enforce".to_string(),
                checked_total: 1_000,
                skipped_privileged_total: 400,
                anomalies_total: 1,
                kills_total: 1,
                untracked_total: 0,
                use_checks_total: 0,
                denied_total: 0,
            }),
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
        }
    }

    /// Lab PR 218: the trust level, its reasons, the degradations and the
    /// capability manifest are appended after lab PR 215's and 217's
    /// fields, which follow lab PR 207's — an
    /// `nn-admin` or watchdog of lab PR 207 reads every field it knows from
    /// a newer agent's reply, and the new fields are its last bytes.
    #[test]
    fn a_lab207_nn_admin_reads_a_lab218_status_reply() {
        let new = status_with_lab193_fields();
        let body = postcard::to_allocvec(&new).unwrap();
        let old: StatusResponseLabPr207 = postcard::from_bytes(&body).unwrap();
        assert_eq!(old.net_quic_rows_total, Some(5));
        assert_eq!(old.detect_only_source.as_deref(), Some("--detect-only"));
        let prefix = postcard::to_allocvec(&old).unwrap();
        assert!(body.starts_with(&prefix) && body.len() > prefix.len());
        let back: StatusResponse = postcard::from_bytes(&body).unwrap();
        assert_eq!(back.trust_level, Some(2));
        assert_eq!(back.degradations, new.degradations);
        assert_eq!(back.capability_manifest, new.capability_manifest);
    }

    /// The limit, pinned for these fields too: an `nn-admin` of lab PR 218
    /// cannot decode a lab PR 207 agent's reply (upgrade the agent first).
    #[test]
    fn a_lab218_nn_admin_cannot_read_a_lab207_status_reply() {
        let new = status_with_lab193_fields();
        let old = StatusResponseLabPr207 {
            posture: new.posture,
            network_isolation_engaged: new.network_isolation_engaged,
            last_admin_action_secs_ago: new.last_admin_action_secs_ago,
            ringbuf_drops_total: new.ringbuf_drops_total,
            ringbuf_drops: new.ringbuf_drops.clone(),
            combat_stage: new.combat_stage.clone(),
            combat_locked: new.combat_locked,
            ringbuf_rejected_total: new.ringbuf_rejected_total,
            ringbuf_rejected: new.ringbuf_rejected.clone(),
            netflow_rows_skipped_total: new.netflow_rows_skipped_total,
            netflow_pending_evicted_total: new.netflow_pending_evicted_total,
            net_inactive_rules: new.net_inactive_rules.clone(),
            flow_sock_pending: new.flow_sock_pending,
            flow_sock_capacity: new.flow_sock_capacity,
            flow_sock_forgotten_min: new.flow_sock_forgotten_min,
            detect_only: new.detect_only,
            detect_only_source: new.detect_only_source.clone(),
            combat_evidence_unrecorded: new.combat_evidence_unrecorded,
            combat_evidence_pending: new.combat_evidence_pending,
            combat_evidence_dropped: new.combat_evidence_dropped,
            net_dot_rows_total: new.net_dot_rows_total,
            net_dot_rows_resolver: new.net_dot_rows_resolver,
            net_quic_rows_total: new.net_quic_rows_total,
        };
        let body = postcard::to_allocvec(&old).unwrap();
        assert!(postcard::from_bytes::<StatusResponse>(&body).is_err());
    }

    /// Lab PR 218: the new fields are telemetry — the unsigned reply sends
    /// none of them.
    #[test]
    fn the_trust_level_and_degradations_are_withheld_from_the_public_status() {
        let public = StatusResponse::public(PostureKind::Observing, false, None, None, Some(false));
        assert_eq!(public.trust_level, None);
        assert_eq!(public.degradations, None);
        assert_eq!(public.capability_manifest, None);
        assert!(public.telemetry_withheld());
        let mut full = status_with_lab193_fields();
        assert!(!full.telemetry_withheld());
        full = StatusResponse {
            trust_level: Some(3),
            ..StatusResponse::public(full.posture, false, None, None, Some(false))
        };
        assert!(!full.telemetry_withheld(), "a trust level is telemetry");
    }

    /// External audit CMB-018 / CMB-027 (lab PR 193): an `nn-admin` older
    /// than the agent decodes the reply — the new fields are trailing bytes
    /// it ignores — inside the frame too.
    #[test]
    fn an_older_nn_admin_reads_a_newer_status_reply() {
        let new = status_with_lab193_fields();
        let body = postcard::to_allocvec(&new).unwrap();
        let old: StatusResponseLabPr164 = postcard::from_bytes(&body).unwrap();
        assert_eq!(old.combat_stage.as_deref(), Some("ISOLATE"));
        assert_eq!(old.combat_locked, Some(true));
        assert_eq!(old.last_admin_action_secs_ago, Some(7));
        assert_eq!(old.flow_sock_forgotten_min, None);
        // The frame an older client reads: same variant index, same prefix.
        let frame = encode_frame(&AdminMessage::StatusResponse(new)).unwrap();
        assert_eq!(&frame[5..], &body[..], "variant byte, then the struct");
    }

    /// The limit, pinned: postcard has no field count, so an `nn-admin`
    /// newer than the agent cannot decode an older agent's reply —
    /// `serde(default)` does not apply to a missing trailing field.
    #[test]
    fn a_newer_nn_admin_cannot_read_an_older_status_reply() {
        let old = StatusResponseLabPr164 {
            posture: PostureKind::Observing,
            network_isolation_engaged: false,
            last_admin_action_secs_ago: None,
            ringbuf_drops_total: Some(0),
            ringbuf_drops: Some(Vec::new()),
            combat_stage: None,
            combat_locked: Some(false),
            ringbuf_rejected_total: Some(0),
            ringbuf_rejected: Some(Vec::new()),
            netflow_rows_skipped_total: Some(0),
            netflow_pending_evicted_total: Some(0),
            net_inactive_rules: Some(Vec::new()),
            flow_sock_pending: None,
            flow_sock_capacity: None,
            flow_sock_forgotten_min: None,
        };
        let body = postcard::to_allocvec(&old).unwrap();
        assert!(postcard::from_bytes::<StatusResponse>(&body).is_err());
    }

    /// The status reply as lab PR 193 left it (its last field
    /// `combat_evidence_dropped`), for the lab PR 207 pins.
    #[derive(Debug, PartialEq, Serialize, Deserialize)]
    struct StatusResponseLabPr193 {
        posture: PostureKind,
        network_isolation_engaged: bool,
        last_admin_action_secs_ago: Option<u64>,
        ringbuf_drops_total: Option<u64>,
        ringbuf_drops: Option<Vec<(String, u64)>>,
        combat_stage: Option<String>,
        combat_locked: Option<bool>,
        ringbuf_rejected_total: Option<u64>,
        ringbuf_rejected: Option<Vec<(String, u64)>>,
        netflow_rows_skipped_total: Option<u64>,
        netflow_pending_evicted_total: Option<u64>,
        net_inactive_rules: Option<Vec<String>>,
        flow_sock_pending: Option<u64>,
        flow_sock_capacity: Option<u64>,
        flow_sock_forgotten_min: Option<u64>,
        detect_only: Option<bool>,
        detect_only_source: Option<String>,
        combat_evidence_unrecorded: Option<u64>,
        combat_evidence_pending: Option<u64>,
        combat_evidence_dropped: Option<u64>,
    }

    /// External audit NET-017 (lab PR 207): the three counters are appended
    /// after lab PR 193's fields — an `nn-admin` or watchdog of lab PR 193
    /// reads every field it knows from a newer agent's reply, the DNS
    /// blind-spot entry of `net_inactive_rules` included (no new field).
    #[test]
    fn a_lab193_nn_admin_reads_a_lab207_status_reply() {
        let mut new = status_with_lab193_fields();
        new.net_inactive_rules = Some(vec![
            "NN-L-NET-002/004/005/014 (DNS): blind to the local resolver's upstream".to_string(),
        ]);
        let body = postcard::to_allocvec(&new).unwrap();
        let old: StatusResponseLabPr193 = postcard::from_bytes(&body).unwrap();
        assert_eq!(old.combat_evidence_dropped, Some(0));
        assert_eq!(old.detect_only_source.as_deref(), Some("--detect-only"));
        assert_eq!(old.net_inactive_rules, new.net_inactive_rules);
        // The new fields are the reply's last bytes.
        let prefix = postcard::to_allocvec(&old).unwrap();
        assert!(body.starts_with(&prefix) && body.len() > prefix.len());
    }

    /// The limit, pinned for these fields too: an `nn-admin` (or watchdog)
    /// of lab PR 207 cannot decode a lab PR 193 agent's reply.
    #[test]
    fn a_lab207_nn_admin_cannot_read_a_lab193_status_reply() {
        let new = status_with_lab193_fields();
        let old = StatusResponseLabPr193 {
            posture: new.posture,
            network_isolation_engaged: new.network_isolation_engaged,
            last_admin_action_secs_ago: new.last_admin_action_secs_ago,
            ringbuf_drops_total: new.ringbuf_drops_total,
            ringbuf_drops: new.ringbuf_drops.clone(),
            combat_stage: new.combat_stage.clone(),
            combat_locked: new.combat_locked,
            ringbuf_rejected_total: new.ringbuf_rejected_total,
            ringbuf_rejected: new.ringbuf_rejected.clone(),
            netflow_rows_skipped_total: new.netflow_rows_skipped_total,
            netflow_pending_evicted_total: new.netflow_pending_evicted_total,
            net_inactive_rules: new.net_inactive_rules.clone(),
            flow_sock_pending: new.flow_sock_pending,
            flow_sock_capacity: new.flow_sock_capacity,
            flow_sock_forgotten_min: new.flow_sock_forgotten_min,
            detect_only: new.detect_only,
            detect_only_source: new.detect_only_source.clone(),
            combat_evidence_unrecorded: new.combat_evidence_unrecorded,
            combat_evidence_pending: new.combat_evidence_pending,
            combat_evidence_dropped: new.combat_evidence_dropped,
        };
        let body = postcard::to_allocvec(&old).unwrap();
        assert!(postcard::from_bytes::<StatusResponse>(&body).is_err());
    }

    /// The status reply as lab PR 207 left it (its last field
    /// `net_quic_rows_total`), for the lab PR 215, 218 and 224 pins.
    #[derive(Debug, PartialEq, Serialize, Deserialize)]
    struct StatusResponseLabPr207 {
        posture: PostureKind,
        network_isolation_engaged: bool,
        last_admin_action_secs_ago: Option<u64>,
        ringbuf_drops_total: Option<u64>,
        ringbuf_drops: Option<Vec<(String, u64)>>,
        combat_stage: Option<String>,
        combat_locked: Option<bool>,
        ringbuf_rejected_total: Option<u64>,
        ringbuf_rejected: Option<Vec<(String, u64)>>,
        netflow_rows_skipped_total: Option<u64>,
        netflow_pending_evicted_total: Option<u64>,
        net_inactive_rules: Option<Vec<String>>,
        flow_sock_pending: Option<u64>,
        flow_sock_capacity: Option<u64>,
        flow_sock_forgotten_min: Option<u64>,
        detect_only: Option<bool>,
        detect_only_source: Option<String>,
        combat_evidence_unrecorded: Option<u64>,
        combat_evidence_pending: Option<u64>,
        combat_evidence_dropped: Option<u64>,
        net_dot_rows_total: Option<u64>,
        net_dot_rows_resolver: Option<u64>,
        net_quic_rows_total: Option<u64>,
    }

    /// Lab PR 215: the fail-open counters are appended after lab PR 207's
    /// fields — an `nn-admin` of lab PR 207 reads every field it knows
    /// from a newer agent's reply, and the new fields are the last bytes.
    #[test]
    fn a_lab207_nn_admin_reads_a_lab215_status_reply() {
        let new = status_with_lab193_fields();
        let body = postcard::to_allocvec(&new).unwrap();
        let old: StatusResponseLabPr207 = postcard::from_bytes(&body).unwrap();
        assert_eq!(old.net_quic_rows_total, Some(5));
        assert_eq!(old.combat_stage.as_deref(), Some("ISOLATE"));
        let prefix = postcard::to_allocvec(&old).unwrap();
        assert!(body.starts_with(&prefix) && body.len() > prefix.len());
    }

    /// The limit, pinned for these fields too: an `nn-admin` of lab PR 215
    /// cannot decode a lab PR 207 agent's reply (the watchdog's ping can:
    /// it reads the two leading fields only).
    #[test]
    fn a_lab215_nn_admin_cannot_read_a_lab207_status_reply() {
        let new = status_with_lab193_fields();
        let old = StatusResponseLabPr207 {
            posture: new.posture,
            network_isolation_engaged: new.network_isolation_engaged,
            last_admin_action_secs_ago: new.last_admin_action_secs_ago,
            ringbuf_drops_total: new.ringbuf_drops_total,
            ringbuf_drops: new.ringbuf_drops.clone(),
            combat_stage: new.combat_stage.clone(),
            combat_locked: new.combat_locked,
            ringbuf_rejected_total: new.ringbuf_rejected_total,
            ringbuf_rejected: new.ringbuf_rejected.clone(),
            netflow_rows_skipped_total: new.netflow_rows_skipped_total,
            netflow_pending_evicted_total: new.netflow_pending_evicted_total,
            net_inactive_rules: new.net_inactive_rules.clone(),
            flow_sock_pending: new.flow_sock_pending,
            flow_sock_capacity: new.flow_sock_capacity,
            flow_sock_forgotten_min: new.flow_sock_forgotten_min,
            detect_only: new.detect_only,
            detect_only_source: new.detect_only_source.clone(),
            combat_evidence_unrecorded: new.combat_evidence_unrecorded,
            combat_evidence_pending: new.combat_evidence_pending,
            combat_evidence_dropped: new.combat_evidence_dropped,
            net_dot_rows_total: new.net_dot_rows_total,
            net_dot_rows_resolver: new.net_dot_rows_resolver,
            net_quic_rows_total: new.net_quic_rows_total,
        };
        let body = postcard::to_allocvec(&old).unwrap();
        assert!(postcard::from_bytes::<StatusResponse>(&body).is_err());
        assert_eq!(
            decode_status_liveness(&status_body(&old)).unwrap().posture,
            PostureKind::Combat
        );
    }

    /// Lab PR 224: the connect-verdict, snapshot and connect-deny counters
    /// are appended after lab PR 223's fields (lab PRs 215 to 223 append
    /// after lab PR 207's) — an `nn-admin` or watchdog of lab PR 207 reads
    /// every field it knows from a newer reply, and the new counters are the
    /// reply's last bytes.
    #[test]
    fn a_lab207_nn_admin_reads_a_lab224_status_reply() {
        let mut new = status_with_lab193_fields();
        new.net_connect_verdicts_total = Some(3);
        new.net_flow_snapshots_total = Some(9);
        new.net_flow_snapshots_deferred_total = Some(1);
        new.net_connect_denied_total = None;
        let body = postcard::to_allocvec(&new).unwrap();
        let old: StatusResponseLabPr207 = postcard::from_bytes(&body).unwrap();
        assert_eq!(old.net_quic_rows_total, Some(5));
        assert_eq!(old.net_dot_rows_resolver, Some(2));
        let prefix = postcard::to_allocvec(&old).unwrap();
        assert!(body.starts_with(&prefix) && body.len() > prefix.len());
        let back: StatusResponse = postcard::from_bytes(&body).unwrap();
        assert_eq!(back, new);
    }

    /// The status reply of the first agents (Tappa 7): three fields.
    #[derive(Debug, PartialEq, Serialize, Deserialize)]
    struct StatusResponseTappa7 {
        posture: PostureKind,
        network_isolation_engaged: bool,
        last_admin_action_secs_ago: Option<u64>,
    }

    /// A frame body as an agent of that shape sends it: the variant index,
    /// then the struct.
    fn status_body<T: Serialize>(status: &T) -> Vec<u8> {
        let mut body = vec![STATUS_RESPONSE_INDEX as u8];
        body.extend(postcard::to_allocvec(status).unwrap());
        body
    }

    /// External audit ASK-009 (lab PR 213): the watchdog's ping reads the
    /// variant and the two leading fields only, so it reads the reply of an
    /// agent older than the fields this build knows (where the full decode
    /// fails, `a_lab207_nn_admin_cannot_read_a_lab193_status_reply`), of
    /// this build (public or full) and of the first agents.
    #[test]
    fn the_watchdog_reads_every_status_reply_shape() {
        let full = status_with_lab193_fields();
        let current = encode_frame(&AdminMessage::StatusResponse(full.clone())).unwrap();
        let lab193 = StatusResponseLabPr193 {
            posture: PostureKind::Engaged,
            network_isolation_engaged: true,
            last_admin_action_secs_ago: None,
            ringbuf_drops_total: Some(4),
            ringbuf_drops: Some(vec![("exec".to_string(), 4)]),
            combat_stage: None,
            combat_locked: Some(false),
            ringbuf_rejected_total: Some(0),
            ringbuf_rejected: Some(Vec::new()),
            netflow_rows_skipped_total: Some(0),
            netflow_pending_evicted_total: Some(0),
            net_inactive_rules: Some(Vec::new()),
            flow_sock_pending: None,
            flow_sock_capacity: None,
            flow_sock_forgotten_min: None,
            detect_only: Some(false),
            detect_only_source: None,
            combat_evidence_unrecorded: Some(0),
            combat_evidence_pending: Some(0),
            combat_evidence_dropped: Some(0),
        };
        let first = StatusResponseTappa7 {
            posture: PostureKind::Alerted,
            network_isolation_engaged: false,
            last_admin_action_secs_ago: Some(3),
        };
        let public = encode_frame(&AdminMessage::StatusResponse(StatusResponse::public(
            PostureKind::Observing,
            false,
            None,
            None,
            Some(false),
        )))
        .unwrap();
        let read = |body: &[u8]| decode_status_liveness(body).expect("a status reply");
        assert_eq!(
            read(&current[4..]),
            StatusLiveness {
                posture: PostureKind::Combat,
                network_isolation_engaged: false
            }
        );
        assert_eq!(read(&public[4..]).posture, PostureKind::Observing);
        let old = read(&status_body(&lab193));
        assert_eq!(old.posture, PostureKind::Engaged);
        assert!(old.network_isolation_engaged);
        assert_eq!(read(&status_body(&first)).posture, PostureKind::Alerted);
        // Trailing bytes of fields appended after this build: ignored.
        let mut longer = current[4..].to_vec();
        longer.extend([1, 7, 1, 9]);
        assert_eq!(read(&longer).posture, PostureKind::Combat);
    }

    /// Anything else is not an answer to the ping: another variant (the
    /// signed telemetry reply included), an empty or cut body.
    #[test]
    fn the_watchdog_refuses_what_is_not_a_status_reply() {
        let other = encode_frame(&AdminMessage::UnlockResult(UnlockResult::Success)).unwrap();
        assert!(matches!(
            decode_status_liveness(&other[4..]),
            Err(StatusLivenessError::NotAStatusResponse { index: 4 })
        ));
        let telemetry = encode_frame(&AdminMessage::TelemetryStatusResponse(
            TelemetryStatusResponse {
                result: AdminResult::Success,
                status: Some(status_with_lab193_fields()),
            },
        ))
        .unwrap();
        assert!(matches!(
            decode_status_liveness(&telemetry[4..]),
            Err(StatusLivenessError::NotAStatusResponse { index: 51 })
        ));
        assert!(matches!(
            decode_status_liveness(&[]),
            Err(StatusLivenessError::Postcard(_))
        ));
        // the index and the posture, without the isolation flag
        assert!(matches!(
            decode_status_liveness(&[STATUS_RESPONSE_INDEX as u8, 0]),
            Err(StatusLivenessError::Postcard(_))
        ));
        // a posture index no build has
        assert!(decode_status_liveness(&[STATUS_RESPONSE_INDEX as u8, 9, 0]).is_err());
    }

    /// Lab PR 216: the watchdog reads the loop progress reply by its index
    /// and the fields it knows; a newer agent's appended fields are
    /// ignored, any other reply is refused.
    #[test]
    fn the_watchdog_reads_the_loop_progress() {
        let reply = encode_frame(&AdminMessage::LoopProgressResponse(LoopProgressResponse {
            iterations: 300,
            since_last_ms: 1_250,
        }))
        .unwrap();
        let got = decode_loop_progress(&reply[4..]).expect("a progress reply");
        assert_eq!(got.iterations, 300);
        assert_eq!(got.since_last_ms, 1_250);
        let mut newer = reply[4..].to_vec();
        newer.extend([1, 9]);
        assert_eq!(decode_loop_progress(&newer).unwrap(), got);
        let status = encode_frame(&AdminMessage::StatusResponse(StatusResponse::public(
            PostureKind::Observing,
            false,
            None,
            None,
            None,
        )))
        .unwrap();
        assert!(matches!(
            decode_loop_progress(&status[4..]),
            Err(StatusLivenessError::NotAStatusResponse { index }) if index == STATUS_RESPONSE_INDEX
        ));
        assert!(decode_loop_progress(&[]).is_err());
        assert!(decode_loop_progress(&[LOOP_PROGRESS_RESPONSE_INDEX as u8, 1]).is_err());
        roundtrip(AdminMessage::LoopProgress(LoopProgressRequest {}));
        roundtrip(AdminMessage::LoopProgressResponse(LoopProgressResponse {
            iterations: u64::MAX,
            since_last_ms: 0,
        }));
    }

    /// External audit ASK-009 (lab PR 213): the unsigned reply withholds
    /// every telemetry field; the public ones pass through.
    #[test]
    fn the_public_status_withholds_the_telemetry() {
        let public = StatusResponse::public(
            PostureKind::Combat,
            true,
            Some(12),
            Some("ISOLATE".to_string()),
            Some(true),
        );
        assert!(public.telemetry_withheld());
        assert_eq!(public.posture, PostureKind::Combat);
        assert!(public.network_isolation_engaged);
        assert_eq!(public.last_admin_action_secs_ago, Some(12));
        assert_eq!(public.combat_stage.as_deref(), Some("ISOLATE"));
        assert_eq!(public.combat_locked, Some(true));
        assert_eq!(public.ringbuf_drops_total, None);
        assert_eq!(public.ringbuf_rejected_total, None);
        assert_eq!(public.net_inactive_rules, None);
        assert_eq!(public.detect_only, None);
        assert_eq!(public.combat_evidence_unrecorded, None);
        assert_eq!(public.net_quic_rows_total, None);
        assert_eq!(public.deny_fail_open_total, None);
        assert_eq!(public.deny_fail_open, None);
        assert_eq!(public.exploit_guard, None);
        assert_eq!(public.execq_state, None);
        assert_eq!(public.execq_held_total, None);
        assert_eq!(public.net_connect_verdicts_total, None);
        assert_eq!(public.net_flow_snapshots_total, None);
        assert_eq!(public.net_flow_snapshots_deferred_total, None);
        assert_eq!(public.net_connect_denied_total, None);
        assert!(!status_with_lab193_fields().telemetry_withheld());
        // Same shape: an older nn-admin or watchdog reads it.
        let body = postcard::to_allocvec(&public).unwrap();
        let old: StatusResponseLabPr164 = postcard::from_bytes(&body).unwrap();
        assert_eq!(old.ringbuf_drops_total, None);
        assert_eq!(old.combat_locked, Some(true));
    }

    /// External audit ASK-009 (lab PR 213): the signed telemetry verb and
    /// its reply survive a wire round-trip.
    #[test]
    fn roundtrip_telemetry_status_verb() {
        use crate::wire::admin_signed_payload::SignedPayload;
        roundtrip(AdminMessage::TelemetryStatusRequest(
            TelemetryStatusRequest {
                payload: SignedPayload::new_telemetry_status([0x44; 32], 1_700_000_000, [0x55; 16]),
                signatures: vec![KeyedSignature {
                    signature: [0x66; 64],
                }],
            },
        ));
        roundtrip(AdminMessage::TelemetryStatusResponse(
            TelemetryStatusResponse {
                result: AdminResult::Success,
                status: Some(status_with_lab193_fields()),
            },
        ));
        roundtrip(AdminMessage::TelemetryStatusResponse(
            TelemetryStatusResponse {
                result: AdminResult::RoleDenied,
                status: None,
            },
        ));
    }

    /// Lab PR 217: the signed unlock and its reply survive a wire round-trip;
    /// the appended reply variants keep every earlier discriminant
    /// (`UnlockResult::LegacyProtocolRefused` after `RateLimited`,
    /// `AdminResult::ActionFailed` after `ProtocolVersionUnsupported`).
    #[test]
    fn roundtrip_signed_unlock_verb() {
        use crate::wire::admin_signed_payload::SignedPayload;
        roundtrip(AdminMessage::SignedUnlockRequest(SignedUnlockRequest {
            payload: SignedPayload::new_unlock([0x44; 32], 1_700_000_000, [0x55; 16]),
            signatures: vec![KeyedSignature {
                signature: [0x66; 64],
            }],
        }));
        for (result, released) in [
            (AdminResult::Success, true),
            (AdminResult::ActionFailed, false),
            (AdminResult::RoleDenied, false),
        ] {
            roundtrip(AdminMessage::SignedUnlockResponse(SignedUnlockResponse {
                result,
                released,
                isolation_v4: !released,
                isolation_v6: false,
                message: "IPv4: chain gone; IPv6: chain still listed".to_string(),
            }));
        }
        roundtrip(AdminMessage::UnlockResult(
            UnlockResult::LegacyProtocolRefused,
        ));
        let tag = |r: UnlockResult| postcard::to_allocvec(&r).unwrap()[0];
        assert_eq!(tag(UnlockResult::Success), 0);
        assert_eq!(
            tag(UnlockResult::RateLimited {
                retry_after_secs: 1
            }),
            3
        );
        assert_eq!(tag(UnlockResult::LegacyProtocolRefused), 4);
        let tag = |r: AdminResult| postcard::to_allocvec(&r).unwrap()[0];
        assert_eq!(tag(AdminResult::UnknownOperation), 8);
        assert_eq!(
            tag(AdminResult::ProtocolVersionUnsupported { server_version: 1 }),
            9
        );
        assert_eq!(tag(AdminResult::ActionFailed), 10);
    }

    /// Lab PR 217: the isolation per IP family is appended to the status —
    /// public, passed through by the unsigned reply — and an `nn-admin` of
    /// lab PR 213 reads every byte before it (the two fields follow lab PR
    /// 215's; the fields appended after them — lab PR 218's four, 219's
    /// and 222's one each, 223's ten, 224's four — are `None` in a public
    /// reply).
    #[test]
    fn the_status_carries_the_isolation_per_family() {
        let public = StatusResponse::public(PostureKind::Combat, false, None, None, Some(true))
            .with_isolation_families(true, false);
        assert!(public.network_isolation_engaged, "either family");
        assert_eq!(public.network_isolation_v4, Some(true));
        assert_eq!(public.network_isolation_v6, Some(false));
        assert!(public.telemetry_withheld(), "public fields, not telemetry");
        let with = postcard::to_allocvec(&public).unwrap();
        let mut without = public.clone();
        without.network_isolation_v4 = None;
        without.network_isolation_v6 = None;
        let without = postcard::to_allocvec(&without).unwrap();
        // None is one byte each; Some(bool) two. The fields appended after
        // them (one `None` byte each here) are the last bytes of both: lab
        // PR 218's four, lab PR 219's `exploit_guard`, lab PR 222's
        // `cow_guard`, lab PR 223's ten `execq_*`, lab PR 224's four
        // counters.
        let tail = 4 + 1 + 1 + 10 + 4;
        let prefix = without.len() - 2 - tail;
        assert_eq!(with.len(), without.len() + 2);
        assert_eq!(&with[..prefix], &without[..prefix]);
        assert_eq!(&with[with.len() - tail..], &without[without.len() - tail..]);
        let old: StatusResponseLabPr164 = postcard::from_bytes(&with).unwrap();
        assert!(old.network_isolation_engaged);
        roundtrip(AdminMessage::StatusResponse(public));
    }

    /// External audit CMB-016: the three response verbs and their replies
    /// survive a wire round-trip, signed extras included.
    #[test]
    fn roundtrip_response_verbs() {
        use crate::wire::admin_signed_payload::SignedPayload;
        let sigs = vec![KeyedSignature {
            signature: [0x66; 64],
        }];
        roundtrip(AdminMessage::ResponseStatusRequest(ResponseStatusRequest {
            payload: SignedPayload::new_response_status([0x44; 32], 1_700_000_000, [0x55; 16]),
            signatures: sigs.clone(),
        }));
        roundtrip(AdminMessage::ResponseStatusResponse(
            ResponseStatusResponse {
                result: AdminResult::Success,
                contained: vec![ContainedProcessWire {
                    pid: 4242,
                    scope: "blocked".to_string(),
                    origin: "/system.slice/foo.service".to_string(),
                    since: 1_700_000_000,
                    running: true,
                }],
                contained_total: 1,
                quarantined: vec![QuarantinedFileWire {
                    vault_id: "0123456789abcdef0123456789abcdef".to_string(),
                    original_path: "/tmp/payload".to_string(),
                    size_bytes: 12,
                    captured_at: 1_700_000_001,
                }],
                quarantined_total: 1,
                combat_stage: Some("INVESTIGATE".to_string()),
                combat_locked: Some(false),
            },
        ));
        roundtrip(AdminMessage::ResponseReleaseRequest(
            ResponseReleaseRequest {
                payload: SignedPayload::new_response_release(
                    [0x44; 32],
                    1_700_000_000,
                    [0x55; 16],
                    4242,
                ),
                signatures: sigs.clone(),
            },
        ));
        roundtrip(AdminMessage::ResponseReleaseResponse(
            ResponseReleaseResponse {
                result: AdminResult::Success,
                released: false,
                message: "pid 4242 is not contained by this agent".to_string(),
            },
        ));
        roundtrip(AdminMessage::ResponseRestoreRequest(
            ResponseRestoreRequest {
                payload: SignedPayload::new_response_restore(
                    [0x44; 32],
                    1_700_000_000,
                    [0x55; 16],
                    "0123456789abcdef0123456789abcdef".to_string(),
                    None,
                ),
                signatures: sigs,
            },
        ));
        roundtrip(AdminMessage::ResponseRestoreResponse(
            ResponseRestoreResponse {
                result: AdminResult::RoleDenied,
                restored: false,
                path: String::new(),
                message: String::new(),
            },
        ));
    }

    /// Lab PR 222: the remediate verb survives the wire, and a full reply
    /// (the most rows it lists, long paths) fits a frame.
    #[test]
    fn roundtrip_remediate_ransomware_and_its_largest_reply_fits() {
        use crate::wire::admin_signed_payload::SignedPayload;
        roundtrip(AdminMessage::RemediateRansomwareRequest(
            RemediateRansomwareRequest {
                payload: SignedPayload::new_remediate_ransomware(
                    [0x44; 32],
                    1_700_000_000,
                    [0x55; 16],
                    Some(4242),
                    None,
                    true,
                ),
                signatures: vec![KeyedSignature {
                    signature: [0x66; 64],
                }],
            },
        ));
        let row = |i: usize| CowRestoreRow {
            path: format!("/home/alice/Documents/projects/a-fairly-long-name/file-{i:05}.docx"),
            action: "restored_in_place".to_string(),
            entry: i as u64,
            detail: "the attack's writes only".to_string(),
            beside: None,
            evidence: Some(format!(
                "/srv/.northnarrow-cow/evidence/{i}-file-{i:05}.docx.locked"
            )),
            sha256_original: "ab".repeat(32),
            sha256_after: Some("ab".repeat(32)),
        };
        let reply = AdminMessage::RemediateRansomwareResponse(RemediateRansomwareResponse {
            result: AdminResult::Success,
            done: true,
            message: "restored 120 of 5000 files".to_string(),
            rows: (0..REMEDIATE_ROWS_MAX).map(row).collect(),
            rows_total: 5000,
            restored: 4000,
            recreated: 900,
            kept_both: 50,
            unchanged: 40,
            refused: 5,
            skipped: 5,
        });
        roundtrip(reply.clone());
        let frame = encode_frame(&reply).expect("the largest reply encodes");
        assert!(frame.len() <= MAX_FRAME_BODY + 4, "{} bytes", frame.len());
    }

    #[test]
    fn roundtrip_trusted_installer_grant_request() {
        use crate::wire::admin_signed_payload::SignedPayload;
        let payload =
            SignedPayload::new_trusted_installer_grant([0x44; 32], 1_700_000_000, [0x55; 16], 120);
        roundtrip(AdminMessage::TrustedInstallerGrantRequest(
            TrustedInstallerGrantRequest {
                payload,
                signatures: vec![KeyedSignature {
                    signature: [0x66; 64],
                }],
            },
        ));
        roundtrip(AdminMessage::TrustedInstallerGrantResult(
            AdminResult::Success,
        ));
    }

    /// Tappa 9.0.b: the `Detections` request + response survive a wire
    /// round-trip. The signed pre-image (with its optional string
    /// filters) is re-serialised before verify, so a field-order drift
    /// would silently break signature verification — this anchors the
    /// CBOR/postcard shape, including the `DetectionsExtra` filters.
    #[test]
    fn roundtrip_detections_request_and_response() {
        use crate::wire::admin_signed_payload::SignedPayload;
        let payload = SignedPayload::new_detections(
            [0x44; 32],
            1_700_000_000,
            [0x55; 16],
            25,
            Some(1_699_000_000),
            Some(1_700_000_000),
            Some("high".to_string()),
            Some("open".to_string()),
            Some("network".to_string()),
            Some("sshd".to_string()),
        );
        roundtrip(AdminMessage::DetectionsRequest(DetectionsRequest {
            payload,
            signatures: vec![KeyedSignature {
                signature: [0x66; 64],
            }],
        }));
        roundtrip(AdminMessage::DetectionsResponse(DetectionsResponse {
            result: AdminResult::Success,
            entries_jsonl: "{\"id\":2,\"ts\":\"2026-06-09T12:00:00.000000Z\"}\n".to_string(),
            entries_count: 1,
            entries_truncated: false,
        }));
    }

    /// Tappa 9.0.c: the `DetectionSetStatus` request + response survive
    /// a wire round-trip. The signed pre-image (id + status string +
    /// optional note) is re-serialised before verify, so a field-order
    /// drift would silently break signature verification — this anchors
    /// the CBOR/postcard shape, including the success ack + the
    /// auth-failure (empty new_status, non-Success result) variant.
    #[test]
    fn roundtrip_detection_set_status_request_and_response() {
        use crate::wire::admin_signed_payload::SignedPayload;
        let payload = SignedPayload::new_detection_set_status(
            [0x44; 32],
            1_700_000_000,
            [0x55; 16],
            42,
            "resolved".to_string(),
            Some("benign cron job".to_string()),
        );
        roundtrip(AdminMessage::DetectionSetStatusRequest(
            DetectionSetStatusRequest {
                payload,
                signatures: vec![KeyedSignature {
                    signature: [0x66; 64],
                }],
            },
        ));
        roundtrip(AdminMessage::DetectionSetStatusResponse(
            DetectionSetStatusResponse {
                result: AdminResult::Success,
                id: 42,
                new_status: "resolved".to_string(),
                persist_failed: false,
            },
        ));
        roundtrip(AdminMessage::DetectionSetStatusResponse(
            DetectionSetStatusResponse {
                result: AdminResult::RoleDenied,
                id: 42,
                new_status: String::new(),
                persist_failed: false,
            },
        ));
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
            signatures: vec![KeyedSignature {
                signature: [0x33; 64],
            }],
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
            signatures: vec![KeyedSignature {
                signature: [0x77; 64],
            }],
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
            signatures: vec![KeyedSignature {
                signature: [0xCC; 64],
            }],
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
            signatures: vec![KeyedSignature {
                signature: [0xFF; 64],
            }],
        }));
        roundtrip(AdminMessage::CanaryRefreshResult(AdminResult::RoleDenied));
    }

    /// N7 wire test #1 — NetFlowsRequest + NetFlowsResponse
    /// round-trip via postcard.
    #[test]
    fn net_flows_round_trips() {
        let payload =
            SignedPayload::new_net_flows([0x11; 32], 1_700_000_000, [0x22; 16], Some(1_700_000));
        roundtrip(AdminMessage::NetFlowsRequest(NetFlowsRequest {
            payload,
            signatures: vec![KeyedSignature {
                signature: [0x33; 64],
            }],
        }));
        roundtrip(AdminMessage::NetFlowsResponse(NetFlowsResponse {
            result: AdminResult::Success,
            entries_jsonl: "{\"flow_id\":\"abc\"}\n".to_string(),
            entries_count: 1,
            entries_truncated: false,
        }));
        roundtrip(AdminMessage::NetFlowsResponse(NetFlowsResponse {
            result: AdminResult::RoleDenied,
            entries_jsonl: String::new(),
            entries_count: 0,
            entries_truncated: false,
        }));
    }

    /// N7 wire test #2 — NetListenersRequest + NetListenersResponse.
    #[test]
    fn net_listeners_round_trips() {
        let payload = SignedPayload::new_net_listeners([0x44; 32], 1_700_000_000, [0x55; 16]);
        roundtrip(AdminMessage::NetListenersRequest(NetListenersRequest {
            payload,
            signatures: vec![KeyedSignature {
                signature: [0x66; 64],
            }],
        }));
        roundtrip(AdminMessage::NetListenersResponse(NetListenersResponse {
            result: AdminResult::Success,
            entries_jsonl: String::new(),
            entries_count: 0,
            entries_truncated: false,
        }));
    }

    /// N7 wire test #3 — NetResolveRequest + NetResolveResponse.
    #[test]
    fn net_resolve_round_trips() {
        let payload = SignedPayload::new_net_resolve(
            [0x77; 32],
            1_700_000_000,
            [0x88; 16],
            "8.8.8.8".to_string(),
        );
        roundtrip(AdminMessage::NetResolveRequest(NetResolveRequest {
            payload,
            signatures: vec![KeyedSignature {
                signature: [0x99; 64],
            }],
        }));
        roundtrip(AdminMessage::NetResolveResponse(NetResolveResponse {
            result: AdminResult::Success,
            qname: Some("example.com".to_string()),
            queried_at_unix_ts: Some(1_700_000_000),
        }));
        roundtrip(AdminMessage::NetResolveResponse(NetResolveResponse {
            result: AdminResult::Success,
            qname: None,
            queried_at_unix_ts: None,
        }));
    }

    /// N7 wire test #4 — NetFingerprintRequest + NetFingerprintResponse.
    #[test]
    fn net_fingerprint_round_trips() {
        let payload = SignedPayload::new_net_fingerprint(
            [0xAA; 32],
            1_700_000_000,
            [0xBB; 16],
            "9f3c1a2b4d5e6f70a1b2c3d4e5f60718".to_string(),
        );
        roundtrip(AdminMessage::NetFingerprintRequest(NetFingerprintRequest {
            payload,
            signatures: vec![KeyedSignature {
                signature: [0xCC; 64],
            }],
        }));
        roundtrip(AdminMessage::NetFingerprintResponse(
            NetFingerprintResponse {
                result: AdminResult::Success,
                entries_jsonl: String::new(),
                entries_count: 0,
                entries_truncated: false,
            },
        ));
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
