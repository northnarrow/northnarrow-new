//! Admin authentication (Tappa 7 task 7 / Tappa 8).
//!
//! The only way to leave COMBAT in production is for an admin to
//! sign a server-issued challenge with their Ed25519 private key.
//! [`AdminAuth`] handles the server side of that exchange:
//!
//! 1. Load N admin pubkeys from `/etc/northnarrow/admin.pub`. Each
//!    line is `<hex64-pubkey> [<role,role,...>]` (Tappa 8 A5); the
//!    optional role token controls which Tappa 8 operations the key
//!    authorises. A pubkey-only line gets the default allowlist
//!    [`Role::Unlock`] + [`Role::AuditRead`] — backward-compatible
//!    with every admin.pub file written before A5.
//! 2. Mint a 32-byte cryptographic nonce on demand
//!    ([`ConnAuth::issue_challenge`]).
//! 3. Verify a 64-byte Ed25519 signature over that nonce against
//!    every loaded pubkey AND check the matched key's role
//!    allowlist against the operation being authorised
//!    ([`ConnAuth::verify_with_role`]; the legacy
//!    [`ConnAuth::verify_unlock`] is a thin wrapper that requires
//!    [`Role::Unlock`] for backward-compat).
//! 4. On success, mint an [`UnlockToken`] via the capability gate in
//!    `network_isolate.rs`.
//!
//! External audit NN-AUD-078 / NN-AUD-079: the challenge and the failure
//! count belong to ONE admin-socket connection ([`ConnAuth`]), not to the
//! agent. A client asking for a challenge cannot replace or consume the
//! challenge another connection is about to sign, and failures on one
//! connection do not lock out another. A connection that fails
//! [`MAX_AUTH_FAILURES_PER_CONNECTION`] signature checks is answered
//! `RateLimited` and closed. Role-mismatch failures deliberately do
//! **not** count — a legitimate operator using a correctly-signed key with
//! an insufficient role is a configuration error, not an attack signal.
//! Ed25519 cannot be brute-forced; the limit only bounds the work one
//! client gets per connection.
//!
//! The nonce is single-use — it is consumed inside the verify path
//! regardless of outcome. A failed attempt forces the client to
//! request a fresh challenge AND counts against its connection.

use std::cell::Cell;
use std::path::{Path, PathBuf};
use std::sync::atomic::Ordering;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, Context, Result};
use ed25519_dalek::{Signature, VerifyingKey};
use nn_proto::admin_quorum::{self, distinct_matches, quorum_decision, QuorumDecision};
use nn_proto::admin_signed_payload::{self, Role, SignedPayload, SignedPayloadError};
use parking_lot::RwLock;
use rand::Rng;
use sha2::{Digest, Sha256};
use thiserror::Error;
use tracing::{info, warn};

use super::network_isolate::{mint_unlock_token, UnlockToken};
use crate::os_rng::OsRng;

/// External audit NN-AUD-079: failed signature checks one admin-socket
/// connection may make. The one that reaches this count is answered
/// `RateLimited` and the socket server closes the connection.
pub const MAX_AUTH_FAILURES_PER_CONNECTION: u32 = 3;

/// `retry_after_secs` of that `RateLimited` reply. Only the connection is
/// closed, so a new one may retry at once; a non-zero value keeps the
/// "never advertise retry in 0 s" convention of the wire variant.
const CONNECTION_RETRY_AFTER_SECS: u32 = 1;

#[cfg(test)]
use admin_quorum::default_roles;

/// Reasons [`ConnAuth::issue_challenge`] / [`ConnAuth::verify_with_role`]
/// can refuse, carrying the user-facing detail needed to translate
/// into an [`UnlockResult`](nn_proto::admin_protocol::UnlockResult)
/// or the broader Tappa 8 [`AdminResult`](docs/design/TAPPA8_…)
/// shape (design §6.6).
#[derive(Debug, Error)]
pub enum AdminAuthError {
    #[error("rate limited: retry after {retry_after_secs}s")]
    RateLimited { retry_after_secs: u32 },
    #[error("no pending challenge")]
    NoPendingChallenge,
    #[error("invalid signature")]
    InvalidSignature,
    /// Signature verifies under one of the loaded pubkeys, but that
    /// key's role allowlist does not include the operation's
    /// required role. The 8-hex-char fingerprint identifies which
    /// key — the audit log records it so an operator can find the
    /// misconfigured admin.pub line.
    #[error("admin key {key_fingerprint} not authorised for {required_role:?}")]
    RoleDenied {
        key_fingerprint: String,
        required_role: Role,
    },
    /// Quorum verify (Tappa 8 A6, design §3.3) collected fewer
    /// distinct valid signatures than the operation requires.
    /// `provided` counts only signatures that matched a loaded
    /// admin pubkey AND came from a distinct key from any
    /// previously matched signature in the same submission.
    /// `required` mirrors the design §6.6 wire variant's
    /// `required` field. This error does **not** count against
    /// the connection — a quorum shortfall is operator UX
    /// (a co-signer hasn't replied yet), not an attack signal.
    #[error("quorum not met: {provided} distinct valid signatures (need {required})")]
    QuorumNotMet { required: u8, provided: u8 },
    /// Tappa 8 A7: `payload.ts` was outside the server's ±skew
    /// window. Mirrors `AdminResult::TimestampSkew` in the wire
    /// layer. Returned by [`ConnAuth::verify_signed_payload_quorum`]
    /// (and any future SignedPayload-consuming verify path).
    /// Does NOT count against the connection — clock skew
    /// is an operator-environment issue, not an attack signal.
    #[error("timestamp outside ±{max_skew_secs}s window (server_ts={server_ts})")]
    TimestampSkew { server_ts: u64, max_skew_secs: u32 },
    /// Tappa 8 A7: `payload.agent_id` did not match the agent's
    /// bootstrapped install UUID — a captured signature was
    /// replayed against a different agent install (design §6.4
    /// layer 3). Counts against the connection: this can only happen
    /// from a deliberate attack (legitimate clients always read
    /// `agent_id` from the same agent's `status` reply before
    /// signing).
    #[error("agent_id mismatch")]
    AgentIdMismatch,
    /// Tappa 8 A7: `payload.nonce` did not match the outstanding
    /// challenge nonce — a signed-payload submission whose
    /// nonce-binding was forged or stale. Counts against the
    /// connection; this is an attack signal under the same
    /// rationale as `InvalidSignature`.
    #[error("nonce mismatch")]
    NonceMismatch,
    /// Tappa 8 A7: `payload.op` was not the operation expected
    /// on this wire variant (e.g., a `ShutdownRequest` carrying
    /// `op = Unlock`). Surfaces design §6.6
    /// `AdminResult::UnknownOperation`. Counts against the
    /// connection — a wire-shape mismatch can only come from a
    /// confused or hostile client.
    ///
    /// External audit AUT-001: also a payload whose `extra` belongs to
    /// another operation than its `op`
    /// ([`admin_signed_payload::check_op`]); `got` is then `payload.op`
    /// and the journal line names the extra's operation.
    #[error("unknown operation: payload.op={got:?} expected {expected:?}")]
    UnknownOperation {
        expected: nn_proto::admin_signed_payload::OperationCode,
        got: nn_proto::admin_signed_payload::OperationCode,
    },
    /// External audit AUT-005: more signatures than
    /// [`admin_quorum::MAX_SUBMITTED_SIGNATURES`] in one submission,
    /// refused before any is checked. Counts against the connection: no
    /// in-repo client sends more than two. Answered `InvalidSignature` on
    /// the wire (no new variant).
    #[error("{submitted} signatures submitted, at most {max} accepted", max = admin_quorum::MAX_SUBMITTED_SIGNATURES)]
    TooManySignatures { submitted: usize },
    /// Tappa 8 A7: signing-payload CBOR / hashing failed during
    /// verify. Wraps the underlying `SignedPayloadError` from
    /// `nn_proto::admin_signed_payload`. In practice this
    /// only fires on malformed input that already passed CBOR
    /// decode at the frame layer.
    #[error("signed payload error: {0}")]
    PayloadVerify(#[from] SignedPayloadError),
}

/// One loaded admin pubkey plus its parsed role allowlist
/// ([`admin_quorum::AdminKey`], shared with the watchdog since external
/// audit WDG-001).
type KeyEntry = admin_quorum::AdminKey;

/// Server-side admin authenticator.
///
/// Each entry of `pub_keys` pairs a verifying key with the operations
/// its operator is authorised to trigger ([`Role`] enum from
/// [`nn_proto::admin_signed_payload`]). External audit NN-AUD-078 /
/// NN-AUD-079: no challenge and no failure count live here — they belong
/// to the connection ([`ConnAuth`]), the only way to verify a live request.
#[derive(Debug)]
pub struct AdminAuth {
    /// Tappa 8 A13: behind an `RwLock` so the dispatcher can
    /// hot-swap the key set after a successful `rotate-keys
    /// add`/`revoke` without rebuilding the whole `AdminAuth`
    /// behind its `Arc`. Verify paths take a brief read lock;
    /// rotation takes a write lock (one-shot, microseconds).
    /// `RwLock` over `Mutex` because verify is the hot path —
    /// many concurrent admin requests reading should never
    /// serialise on each other.
    pub_keys: RwLock<Vec<KeyEntry>>,
    /// Per-install agent identity (Tappa 8 A3). Bootstrapped by
    /// [`crate::agent_id::load_or_bootstrap`] and passed in via
    /// [`Self::load_with_agent_id`]. The legacy [`Self::load`]
    /// defaults to `[0u8; 16]` for backward compatibility — that
    /// matters only for the new
    /// [`ConnAuth::verify_signed_payload_quorum`] path; the legacy
    /// `verify_unlock` / `verify_with_role` / `verify_quorum`
    /// surfaces never touch this field.
    agent_id: [u8; 16],
    /// Tappa 8 A13: source path of the `admin.pub` file this
    /// instance was loaded from. `None` for test builders that
    /// constructed the auth in-memory; `Some` for production
    /// `load_with_agent_id` callers. The rotate-keys dispatch
    /// path uses this to know where to atomically rewrite +
    /// reload on a successful rotation. A test build calling
    /// `dispatch_rotate_keys_add` without a config_path gets a
    /// clear "no on-disk config" error rather than a silent
    /// no-op.
    config_path: Option<PathBuf>,
    /// External audit ATP-004: the `admin.pub` bytes the keys above were
    /// parsed from (load / reload), so the bootstrap gate judges the keys
    /// the agent uses, not a file re-read at request time (a bind mount
    /// or a rewrite could present a one-key file).
    loaded_admin_pub: RwLock<Vec<u8>>,
    /// External audit AUT-004: the lines of that file that are not a key.
    skipped_lines: RwLock<Vec<(usize, String)>>,
    /// External audit ATP-004: a second key was added once (the signed
    /// audit chain shows a `rotate_keys_add`, or this run added one): the
    /// 1-of-N bootstrap relaxation never applies again.
    bootstrap_consumed: std::sync::atomic::AtomicBool,
}

impl AdminAuth {
    /// Parse `config_path` — one line per admin key, format
    /// `<hex64-pubkey> [<role,role,...>]`. Blank lines and lines
    /// starting with `#` are skipped. At least one valid key is
    /// required; an empty file is a startup error, not a
    /// "anybody can unlock" silent-default.
    ///
    /// Tappa 8 A5: lines without a role token get the
    /// [`default_roles`] allowlist (`unlock,audit-read`), which
    /// preserves the behaviour of every admin.pub written before
    /// A5 — those pubkey-only lines authorise unlock exactly as
    /// they did pre-A5.
    ///
    /// Tappa 8 A7: defaults `agent_id` to `[0u8; 16]`. The new
    /// SignedPayload-consuming verify
    /// ([`ConnAuth::verify_signed_payload_quorum`]) compares incoming
    /// `payload.agent_id` against this field; production code
    /// should use [`Self::load_with_agent_id`] to bind the real
    /// install UUID (bootstrapped via
    /// [`crate::agent_id::load_or_bootstrap`]). Existing
    /// `verify_unlock` / `verify_with_role` / `verify_quorum`
    /// paths are unaffected.
    pub fn load(config_path: &Path) -> Result<Self> {
        Self::load_with_agent_id(config_path, [0u8; 16])
    }

    /// Like [`Self::load`] but also binds the agent's
    /// bootstrapped install UUID (design §6.5). Production agent
    /// startup (`main.rs`) is the intended caller; the value is
    /// the return of [`crate::agent_id::load_or_bootstrap`].
    pub fn load_with_agent_id(config_path: &Path, agent_id: [u8; 16]) -> Result<Self> {
        let content = std::fs::read_to_string(config_path)
            .with_context(|| format!("reading {}", config_path.display()))?;

        // External audit AUT-004: a malformed line costs its own key, not
        // the admin socket.
        let parsed = admin_quorum::parse_admin_pub_lenient(&content);
        report_skipped(config_path, &parsed.skipped);
        let pub_keys = parsed.keys;

        if pub_keys.is_empty() {
            let skipped: Vec<String> = parsed
                .skipped
                .iter()
                .map(|(n, why)| format!("{}:{n}: {why}", config_path.display()))
                .collect();
            return Err(anyhow!(
                "{}: no admin pub keys found (need at least one){}",
                config_path.display(),
                if skipped.is_empty() {
                    String::new()
                } else {
                    format!("; skipped {}", skipped.join("; "))
                }
            ));
        }

        let mut auth = Self::build_entries_with_agent_id(pub_keys, agent_id);
        *auth.loaded_admin_pub.write() = content.as_bytes().to_vec();
        *auth.skipped_lines.write() = parsed.skipped;
        // A13: remember the file we loaded from so the
        // rotate-keys dispatcher can atomically rewrite + reload
        // without an extra path threading through `dispatch()`.
        auth.config_path = Some(config_path.to_path_buf());
        Ok(auth)
    }

    /// The bootstrapped agent install UUID (Tappa 8 A3 + A7
    /// wiring). Exposed so the dispatcher / future Tappa 8 callers
    /// can read it back (e.g., to surface in `status` replies).
    pub fn agent_id(&self) -> [u8; 16] {
        self.agent_id
    }

    /// Path of the `admin.pub` file this auth was loaded from,
    /// if any. Tappa 8 A13 rotate-keys uses it to know where to
    /// atomically rewrite. `None` for in-memory test builds.
    pub fn config_path(&self) -> Option<&Path> {
        self.config_path.as_deref()
    }

    /// Tappa 8 A13: re-parse `admin.pub` and swap the in-memory
    /// key set in one write-lock window. Used by the rotate-keys
    /// dispatcher after a successful atomic rewrite so the next
    /// challenge already sees the new key set (design §7.2 step
    /// 5). The empty-file guard mirrors [`Self::load_with_agent_id`]
    /// — a rotation that wipes the file is rejected at the
    /// dispatch layer; defending in depth here keeps the
    /// in-memory state non-empty.
    pub fn reload(&self, config_path: &Path) -> Result<()> {
        let content = std::fs::read_to_string(config_path)
            .with_context(|| format!("reading {}", config_path.display()))?;
        let parsed = admin_quorum::parse_admin_pub_lenient(&content);
        report_skipped(config_path, &parsed.skipped);
        let new_keys = parsed.keys;
        if new_keys.is_empty() {
            return Err(anyhow!(
                "{}: refusing to reload an empty admin.pub (would soft-brick the agent)",
                config_path.display()
            ));
        }
        *self.pub_keys.write() = new_keys;
        *self.loaded_admin_pub.write() = content.into_bytes();
        *self.skipped_lines.write() = parsed.skipped;
        Ok(())
    }

    /// External audit AUT-004: the `admin.pub` lines the last load or
    /// reload skipped, `(line number, reason)` — for the signed record.
    pub fn skipped_lines(&self) -> Vec<(usize, String)> {
        self.skipped_lines.read().clone()
    }

    /// Test-only: snapshot the current in-memory key fingerprints.
    /// Lets reload tests assert "after reload, the new key is
    /// present" without exposing `KeyEntry` to test code.
    #[cfg(any(test, feature = "test-util"))]
    pub fn key_fingerprints_snapshot(&self) -> Vec<String> {
        self.pub_keys
            .read()
            .iter()
            .map(|e| fingerprint(&e.key))
            .collect()
    }

    /// Wrap pre-existing verifying keys in the [`default_roles`]
    /// allowlist and build an authenticator. Kept for test
    /// ergonomics — production callers go through [`Self::load`]
    /// (which parses roles per-line and calls
    /// [`Self::build_entries`] directly) so the line parser is
    /// exercised end-to-end. The signature is stable across A5 so
    /// every pre-A5 test still compiles.
    #[cfg(test)]
    fn build(pub_keys: Vec<VerifyingKey>) -> Self {
        let entries = pub_keys
            .into_iter()
            .map(|key| KeyEntry {
                key,
                roles: default_roles(),
            })
            .collect();
        Self::build_entries(entries)
    }

    /// Lower-level builder used by tests that want to pin custom
    /// role allowlists per key without going through admin.pub
    /// parsing. Defaults `agent_id` to `[0u8; 16]` — call
    /// [`Self::build_entries_with_agent_id`] to bind a specific
    /// UUID (only matters for `verify_signed_payload_quorum`).
    /// Production callers go through [`Self::load_with_agent_id`].
    #[cfg(test)]
    fn build_entries(pub_keys: Vec<KeyEntry>) -> Self {
        Self::build_entries_with_agent_id(pub_keys, [0u8; 16])
    }

    /// Lowest-level builder, used by [`Self::load_with_agent_id`].
    fn build_entries_with_agent_id(pub_keys: Vec<KeyEntry>, agent_id: [u8; 16]) -> Self {
        Self {
            pub_keys: RwLock::new(pub_keys),
            agent_id,
            config_path: None,
            loaded_admin_pub: RwLock::new(Vec::new()),
            skipped_lines: RwLock::new(Vec::new()),
            bootstrap_consumed: std::sync::atomic::AtomicBool::new(false),
        }
    }

    /// External audit ATP-004: the `admin.pub` bytes the in-memory keys
    /// came from.
    pub fn loaded_admin_pub(&self) -> Vec<u8> {
        self.loaded_admin_pub.read().clone()
    }

    /// External audit ATP-004: whether the bootstrap relaxation was used
    /// up (see the field).
    pub fn bootstrap_consumed(&self) -> bool {
        self.bootstrap_consumed.load(Ordering::SeqCst)
    }

    /// Record that the bootstrap relaxation is used up — at boot from the
    /// signed audit chain, and after a second key is added.
    pub fn mark_bootstrap_consumed(&self) {
        self.bootstrap_consumed.store(true, Ordering::SeqCst);
    }

    /// Verify `signature` over `nonce` — the challenge one connection
    /// issued and has just consumed ([`ConnAuth`]) — AND check that the
    /// matched key's role allowlist includes `required_role` (or
    /// [`Role::All`], the break-glass super-role). On success, mint an
    /// [`UnlockToken`]. A role mismatch returns
    /// [`AdminAuthError::RoleDenied`], which [`ConnAuth`] does not count
    /// as a failure (legit operator picked the wrong key, not an attack
    /// signal).
    ///
    /// Constant-time iteration is preserved across the per-key
    /// signature scan: the loop does NOT short-circuit on the
    /// first match, so per-attempt cost depends on the number of
    /// installed keys but not on which key matched (or whether
    /// any matched at all). Role lookup happens once after the
    /// loop on the matched index — that's an O(1) check on a
    /// short Vec, no side-channel relative to key position.
    fn verify_with_role_with_nonce(
        &self,
        nonce: &[u8; 32],
        signature: &[u8; 64],
        required_role: Role,
    ) -> std::result::Result<UnlockToken, AdminAuthError> {
        let sig = Signature::from_bytes(signature);

        // A13: snapshot the keys behind a read lock for the
        // duration of the verify. Rotate-keys takes a write
        // lock; verifies serialise only against the rare
        // rotation, never against each other.
        let pub_keys = self.pub_keys.read();

        // Constant-time across keys (no short-circuit) — record
        // the matched index so we can check the matched key's
        // role allowlist after the loop. ed25519-dalek's
        // `verify_strict` is itself constant-time.
        let mut matched_idx: Option<usize> = None;
        for (idx, entry) in pub_keys.iter().enumerate() {
            if entry.key.verify_strict(nonce, &sig).is_ok() {
                matched_idx = Some(idx);
                // intentionally NOT `break` — preserve constant-time iteration
            }
        }

        match matched_idx {
            Some(idx) => {
                let entry = &pub_keys[idx];
                if entry.authorizes(required_role) {
                    info!(
                        target: "anti_tamper.admin_auth.verify_success",
                        key_fingerprint = %fingerprint(&entry.key),
                        required_role = ?required_role,
                        "admin signature verified, unlock token minted"
                    );
                    Ok(mint_unlock_token())
                } else {
                    // Role mismatch — not counted as a failure. A
                    // correctly-signed but under-privileged request is
                    // a config mistake by a legitimate operator, not an
                    // attack signal.
                    let fp = fingerprint(&entry.key);
                    warn!(
                        target: "anti_tamper.admin_auth.verify_failure",
                        reason = "role_denied",
                        key_fingerprint = %fp,
                        required_role = ?required_role,
                        "admin signature verified but key not authorised for operation"
                    );
                    Err(AdminAuthError::RoleDenied {
                        key_fingerprint: fp,
                        required_role,
                    })
                }
            }
            None => {
                warn!(
                    target: "anti_tamper.admin_auth.verify_failure",
                    reason = "invalid_sig",
                    "admin signature verification failed"
                );
                Err(AdminAuthError::InvalidSignature)
            }
        }
    }

    /// Verify a multi-signature **quorum** submission over `nonce` (see
    /// [`Self::verify_with_role_with_nonce`]). Each signature in
    /// `signatures` is verified independently; the agent tallies
    /// **distinct** matched pubkey indices (per design §3.3, two
    /// signatures from the same key count as one) and accepts the
    /// submission iff:
    /// - at least `min_distinct` distinct keys verified, AND
    /// - each role in `role_requirements` is carried by at least
    ///   one of the matched keys ([`Role::All`] satisfies any
    ///   required role).
    ///
    /// Failure-mode mapping (matches the design §6.6 wire variants):
    /// - `signatures.is_empty()` OR `0 < matched < min_distinct`
    ///   → [`AdminAuthError::QuorumNotMet`] (not a failure — a quorum
    ///   shortfall is operator UX, not an attack signal).
    /// - non-empty `signatures` with zero valid matches →
    ///   [`AdminAuthError::InvalidSignature`] (counted by [`ConnAuth`]
    ///   — the only way to land here is to submit signatures that
    ///   verify under no loaded pubkey, which is an attack indicator).
    /// - `min_distinct` keys matched but no matched key carries a
    ///   required role → [`AdminAuthError::RoleDenied`] (not a
    ///   failure — same rationale as A5).
    /// - all checks pass → [`UnlockToken`] is minted.
    ///
    /// **Constant-time iteration property:** for each submitted
    /// signature, the inner per-key loop does NOT short-circuit on
    /// match (same property as [`Self::verify_with_role_with_nonce`]).
    /// The outer per-signature loop iterates every submitted signature
    /// regardless of how many have already matched — so the total
    /// verification cost is `O(signatures × pub_keys)` regardless
    /// of which sigs verify or in which order.
    fn verify_quorum_with_nonce(
        &self,
        nonce: &[u8; 32],
        signatures: &[[u8; 64]],
        min_distinct: u8,
        role_requirements: &[Role],
    ) -> std::result::Result<UnlockToken, AdminAuthError> {
        debug_assert!(
            min_distinct >= 1,
            "verify_quorum: min_distinct must be >= 1 (got {min_distinct}); \
             0 would mint a token with no signature"
        );

        // External audit AUT-005: an oversized submission is refused
        // before any signature is checked.
        check_signature_count(signatures.len())?;

        // A13: snapshot the keys behind a read lock for the
        // duration of the verify; see verify_with_role_with_nonce for
        // the rationale.
        let pub_keys = self.pub_keys.read();

        // Which key each submitted signature verified against (the
        // constant-time scan keeps the last match, no early break), then
        // the shared quorum rule (`quorum_decision`, proved with Kani).
        let per_signature =
            admin_quorum::match_signatures(&pub_keys, nonce, signatures).map_err(|e| {
                AdminAuthError::TooManySignatures {
                    submitted: e.submitted,
                }
            })?;
        let distinct = distinct_matches(&per_signature).len().min(u8::MAX as usize) as u8;
        match quorum_decision(
            &per_signature,
            |idx, role| pub_keys[idx].authorizes(role),
            min_distinct,
            role_requirements,
        ) {
            QuorumDecision::Accept => {}
            // Zero matches + non-empty submission = attack signal. Zero
            // matches + empty submission = operator UX (not counted).
            QuorumDecision::NoValidSignature => {
                warn!(
                    target: "anti_tamper.admin_auth.verify_failure",
                    reason = "invalid_sig",
                    submitted = signatures.len(),
                    "admin quorum verify: zero valid signatures in non-empty submission"
                );
                return Err(AdminAuthError::InvalidSignature);
            }
            QuorumDecision::QuorumNotMet { required, provided } => {
                warn!(
                    target: "anti_tamper.admin_auth.verify_failure",
                    reason = "quorum_not_met",
                    required,
                    provided,
                    "admin quorum verify: insufficient distinct valid signatures"
                );
                return Err(AdminAuthError::QuorumNotMet { required, provided });
            }
            // The first missing role, with the first matched key's
            // fingerprint as the audit breadcrumb (locked semantics).
            QuorumDecision::RoleDenied { role, first } => {
                let fp = fingerprint(&pub_keys[first].key);
                warn!(
                    target: "anti_tamper.admin_auth.verify_failure",
                    reason = "role_denied",
                    required_role = ?role,
                    matched_count = distinct,
                    first_matched_fingerprint = %fp,
                    "admin quorum verify: required role not carried by any matched key"
                );
                return Err(AdminAuthError::RoleDenied {
                    key_fingerprint: fp,
                    required_role: role,
                });
            }
        }

        info!(
            target: "anti_tamper.admin_auth.verify_success",
            distinct,
            required = min_distinct,
            role_count = role_requirements.len(),
            "admin quorum verified, unlock token minted"
        );
        Ok(mint_unlock_token())
    }

    /// Verify a payload that was signed earlier and STORED (Tappa 10.8:
    /// the `.sig` next to an operator overlay), at agent boot.
    ///
    /// Same signature, quorum, role, op and `agent_id` checks as
    /// [`ConnAuth::verify_signed_payload_quorum`], without the parts that only
    /// make sense for a live request: no challenge nonce is consumed, no
    /// timestamp skew window applies (the caller orders stored signatures
    /// by `ts` to refuse a rollback), and no connection failure counter
    /// is touched (a bad file at boot is not a brute-force attempt).
    /// Returns the fingerprints of the matched keys. External audit
    /// AUT-001 / AUT-005: the same op/extra check
    /// ([`admin_signed_payload::check_op`]) and signature cap as the live
    /// path.
    pub fn verify_stored_payload(
        &self,
        payload: &SignedPayload,
        signatures: &[[u8; 64]],
        min_distinct: u8,
        role_requirements: &[Role],
        expected_op: admin_signed_payload::OperationCode,
    ) -> std::result::Result<Vec<String>, AdminAuthError> {
        if min_distinct == 0 {
            return Err(AdminAuthError::QuorumNotMet {
                required: 0,
                provided: 0,
            });
        }
        if admin_signed_payload::check_op(payload, expected_op).is_err() {
            return Err(AdminAuthError::UnknownOperation {
                expected: expected_op,
                got: payload.op,
            });
        }
        check_signature_count(signatures.len())?;
        if payload.agent_id != self.agent_id {
            return Err(AdminAuthError::AgentIdMismatch);
        }
        let digest = admin_signed_payload::signing_digest(payload)?;
        let pub_keys = self.pub_keys.read();
        let per_signature = admin_quorum::match_signatures(&pub_keys, &digest, signatures)
            .map_err(|e| AdminAuthError::TooManySignatures {
                submitted: e.submitted,
            })?;
        let matched = distinct_matches(&per_signature);
        if matched.is_empty() {
            return Err(AdminAuthError::InvalidSignature);
        }
        let distinct: u8 = matched.len().min(u8::MAX as usize) as u8;
        if distinct < min_distinct {
            return Err(AdminAuthError::QuorumNotMet {
                required: min_distinct,
                provided: distinct,
            });
        }
        for &required in role_requirements {
            if !matched
                .iter()
                .any(|&idx| pub_keys[idx].authorizes(required))
            {
                return Err(AdminAuthError::RoleDenied {
                    key_fingerprint: fingerprint(&pub_keys[matched[0]].key),
                    required_role: required,
                });
            }
        }
        Ok(matched
            .iter()
            .map(|&idx| fingerprint(&pub_keys[idx].key))
            .collect())
    }

    /// Tappa 8 A7 — full signed-payload quorum verify, integrating
    /// every prior A-sprint commit:
    /// - A2: signatures are over `signing_digest(payload)` (not
    ///   over the raw nonce), so the operation tag is inside the
    ///   signed scope (cross-op replay defence).
    /// - A3 + A7: `payload.agent_id` must match the agent's
    ///   bootstrapped install UUID — captured signatures can't
    ///   be replayed across agents.
    /// - A4: `payload.ts` must be within ±[`MAX_TIMESTAMP_SKEW_SECS`]
    ///   of `server_now_unix_secs` — captured signatures can't
    ///   be replayed across an unrealistic clock window.
    /// - A5: each matched key's role allowlist must satisfy
    ///   `role_requirements`.
    /// - A6: distinct-key tally must meet `min_distinct`.
    ///
    /// `expected_nonce` is the challenge the connection issued and has
    /// just consumed ([`ConnAuth`]); `payload.nonce` must equal it.
    ///
    /// Failure-mode summary (matching design §6.6 wire variants; "counted"
    /// means [`ConnAuth`] counts it against the connection):
    /// - `NonceMismatch` → payload nonce ≠ the connection's challenge
    ///   (counted — attack signal).
    /// - `UnknownOperation` → `payload.op` is not the expected
    ///   one for this wire variant, or its `extra` is another
    ///   operation's ([`admin_signed_payload::check_op`], external audit
    ///   AUT-001; counted). Checked first, before any Ed25519 work.
    /// - `TooManySignatures` → more than
    ///   [`admin_quorum::MAX_SUBMITTED_SIGNATURES`] signatures (external
    ///   audit AUT-005; counted), before any signature is checked.
    /// - `AgentIdMismatch` → `payload.agent_id` ≠ `self.agent_id`
    ///   (counted).
    /// - `TimestampSkew` → outside ±60 s window (not counted —
    ///   operator-clock issue).
    /// - `QuorumNotMet` → fewer distinct valid signatures than
    ///   `min_distinct` (not counted — operator UX).
    /// - `InvalidSignature` → zero valid matches in non-empty
    ///   submission (counted).
    /// - `RoleDenied` → matched keys are short of a required
    ///   role (not counted).
    /// - Success → mint `UnlockToken`.
    ///
    /// PHASE_D_004: the success arm carries the 8-hex-char fingerprints
    /// of every matched key, primary first by index order in
    /// `admin.pub`. The dispatch layer threads these into the audit
    /// log's `key_fp` / `cosigner_fps` fields so the chain records WHICH
    /// operator(s) authorised each signed action.
    ///
    /// External audit NN-AUD-083 / NN-AUD-084: it also carries the
    /// matched keys themselves (key and roles), read under the same lock
    /// as the signature scan, so a dispatcher can confine what the
    /// operation does to what its signers hold. A 4-byte fingerprint
    /// looked up later must not drive authorization, and a reload can
    /// happen in between.
    #[allow(clippy::too_many_arguments)]
    fn verify_signed_payload_quorum_with_nonce(
        &self,
        expected_nonce: &[u8; 32],
        payload: &SignedPayload,
        signatures: &[[u8; 64]],
        min_distinct: u8,
        role_requirements: &[Role],
        expected_op: admin_signed_payload::OperationCode,
        server_now_unix_secs: u64,
    ) -> std::result::Result<VerifiedSigners, AdminAuthError> {
        debug_assert!(
            min_distinct >= 1,
            "verify_signed_payload_quorum: min_distinct must be >= 1 \
             (got {min_distinct}); 0 would mint a token with no signature"
        );

        // Operation tag must match what this wire variant expects, and
        // the extra must be that operation's (external audit AUT-001: only
        // the tag was checked here, and the dispatchers took the extra on
        // trust). Cheap field check first — surfaces a clear "wrong wire
        // shape" error before we burn an Ed25519 verify on it.
        if admin_signed_payload::check_op(payload, expected_op).is_err() {
            warn!(
                target: "anti_tamper.admin_auth.verify_failure",
                reason = "unknown_operation",
                expected = ?expected_op,
                got = ?payload.op,
                extra = ?payload.extra.op_code(),
                "signed-payload op tag or extra does not match the request"
            );
            return Err(AdminAuthError::UnknownOperation {
                expected: expected_op,
                got: payload.op,
            });
        }

        // External audit AUT-005: an oversized submission is refused
        // before any hashing or signature check.
        check_signature_count(signatures.len())?;

        // Nonce binding: payload must reference THE nonce the
        // server issued on this connection. A forged payload that
        // names some other nonce can't replay an old signature here.
        if payload.nonce != *expected_nonce {
            warn!(
                target: "anti_tamper.admin_auth.verify_failure",
                reason = "nonce_mismatch",
                "signed-payload nonce does not match outstanding challenge"
            );
            return Err(AdminAuthError::NonceMismatch);
        }

        // Agent-ID binding (design §6.4 layer 3). A captured
        // signature from agent-A is rejected against agent-B.
        if payload.agent_id != self.agent_id {
            warn!(
                target: "anti_tamper.admin_auth.verify_failure",
                reason = "agent_id_mismatch",
                "signed-payload agent_id does not match this agent install"
            );
            return Err(AdminAuthError::AgentIdMismatch);
        }

        // Timestamp skew (design §6.4 layer 2). Pure predicate
        // from A4 — not counted on failure (operator clock issue,
        // not attack).
        if let Err(TimestampSkewError::OutOfWindow {
            server_ts,
            max_skew_secs,
        }) = check_timestamp_skew(payload.ts, server_now_unix_secs, MAX_TIMESTAMP_SKEW_SECS)
        {
            warn!(
                target: "anti_tamper.admin_auth.verify_failure",
                reason = "timestamp_skew",
                server_ts,
                client_ts = payload.ts,
                max_skew_secs,
                "signed-payload timestamp outside skew window"
            );
            return Err(AdminAuthError::TimestampSkew {
                server_ts,
                max_skew_secs,
            });
        }

        // Compute the per-signature verification message: the
        // SHA-512 over `domain_sep || cbor(payload)` from A2.
        let digest = admin_signed_payload::signing_digest(payload)?;

        // A13: snapshot the keys behind a read lock for the
        // duration of the per-signature scan.
        let pub_keys = self.pub_keys.read();

        // Per-signature constant-time scan (same machinery as
        // verify_quorum_with_nonce, except the message bytes are the
        // SignedPayload digest instead of the raw nonce), then the shared
        // quorum rule.
        let per_signature = admin_quorum::match_signatures(&pub_keys, &digest, signatures)
            .map_err(|e| AdminAuthError::TooManySignatures {
                submitted: e.submitted,
            })?;
        let matched = distinct_matches(&per_signature);
        let distinct = matched.len().min(u8::MAX as usize) as u8;
        match quorum_decision(
            &per_signature,
            |idx, role| pub_keys[idx].authorizes(role),
            min_distinct,
            role_requirements,
        ) {
            QuorumDecision::Accept => {}
            // Zero matches + non-empty submission = attack signal.
            QuorumDecision::NoValidSignature => {
                warn!(
                    target: "anti_tamper.admin_auth.verify_failure",
                    reason = "invalid_sig",
                    submitted = signatures.len(),
                    "signed-payload quorum verify: zero valid signatures"
                );
                return Err(AdminAuthError::InvalidSignature);
            }
            QuorumDecision::QuorumNotMet { required, provided } => {
                warn!(
                    target: "anti_tamper.admin_auth.verify_failure",
                    reason = "quorum_not_met",
                    required,
                    provided,
                    "signed-payload quorum verify: insufficient distinct valid signatures"
                );
                return Err(AdminAuthError::QuorumNotMet { required, provided });
            }
            QuorumDecision::RoleDenied { role, first } => {
                let fp = fingerprint(&pub_keys[first].key);
                warn!(
                    target: "anti_tamper.admin_auth.verify_failure",
                    reason = "role_denied",
                    required_role = ?role,
                    matched_count = distinct,
                    first_matched_fingerprint = %fp,
                    "signed-payload quorum verify: required role not carried by any matched key"
                );
                return Err(AdminAuthError::RoleDenied {
                    key_fingerprint: fp,
                    required_role: role,
                });
            }
        }

        // All checks pass. PHASE_D_004: the matched-key fingerprints (in
        // matched-order, which is admin.pub index-order via the per-sig
        // scan above) for the audit log, and the matched keys themselves.
        let fingerprints: Vec<String> = matched
            .iter()
            .map(|&idx| fingerprint(&pub_keys[idx].key))
            .collect();
        let keys: Vec<KeyEntry> = matched.iter().map(|&idx| pub_keys[idx].clone()).collect();
        info!(
            target: "anti_tamper.admin_auth.verify_success",
            op = ?expected_op,
            distinct,
            required = min_distinct,
            role_count = role_requirements.len(),
            "signed-payload quorum verified, unlock token minted"
        );
        Ok(VerifiedSigners {
            token: mint_unlock_token(),
            fingerprints,
            keys,
        })
    }
}

/// What a successful signed-payload verify yields: the capability token,
/// the matched keys' fingerprints (for the audit log) and the matched
/// keys with their roles (external audit NN-AUD-083 / NN-AUD-084).
#[derive(Debug)]
pub struct VerifiedSigners {
    pub token: UnlockToken,
    pub fingerprints: Vec<String>,
    pub keys: Vec<KeyEntry>,
}

/// A fresh 32-byte challenge from OS entropy. `OsRng` is deliberately
/// preferred over `rand::rng()` (`ThreadRng`) — for security primitives
/// we want the OS CSPRNG directly, not a userland-cached source.
fn mint_challenge_nonce() -> [u8; 32] {
    let mut nonce = [0u8; 32];
    OsRng.fill_bytes(&mut nonce);
    nonce
}

/// External audit NN-AUD-078 / NN-AUD-079: the authentication state of
/// ONE admin-socket connection — its outstanding challenge and the
/// signature checks it has failed. The socket server builds one per
/// connection; it is the only way to verify a live request.
///
/// The challenge used to be a single agent-wide slot that any client
/// could overwrite with an unauthenticated `ChallengeRequest`, and the
/// failure count was agent-wide too: a polling dashboard broke a
/// concurrent `unlock` with `NonceMismatch`, and three bad signatures from
/// anyone blocked every client for five minutes. Every in-repo client
/// fetches the challenge and submits the signed request on the same
/// stream, so binding both to the connection costs them nothing.
///
/// Dereferences to the [`AdminAuth`] it was built from, for the key-set
/// accessors (`config_path`, `reload`, `agent_id`, …).
#[derive(Debug)]
pub struct ConnAuth<'a> {
    auth: &'a AdminAuth,
    nonce: Cell<Option<[u8; 32]>>,
    failures: Cell<u32>,
}

impl<'a> ConnAuth<'a> {
    pub fn new(auth: &'a AdminAuth) -> Self {
        Self {
            auth,
            nonce: Cell::new(None),
            failures: Cell::new(0),
        }
    }

    /// Mint a challenge for this connection, replacing the one it asked
    /// for before (if any). Refused once the connection has used up its
    /// failures.
    pub fn issue_challenge(&self) -> std::result::Result<[u8; 32], AdminAuthError> {
        if self.exhausted() {
            return Err(AdminAuthError::RateLimited {
                retry_after_secs: CONNECTION_RETRY_AFTER_SECS,
            });
        }
        let nonce = mint_challenge_nonce();
        self.nonce.set(Some(nonce));
        info!(
            target: "anti_tamper.admin_auth.challenge_issued",
            "admin challenge issued (32-byte nonce)"
        );
        Ok(nonce)
    }

    /// Verify `signature` over this connection's challenge, requiring
    /// [`Role::Unlock`]. Every admin.pub line — including pubkey-only
    /// lines from before A5 — has `unlock` in its allowlist by default.
    pub fn verify_unlock(
        &self,
        signature: &[u8; 64],
    ) -> std::result::Result<UnlockToken, AdminAuthError> {
        self.verify_with_role(signature, Role::Unlock)
    }

    /// See `AdminAuth::verify_with_role_with_nonce`. The challenge is
    /// consumed whatever the outcome.
    pub fn verify_with_role(
        &self,
        signature: &[u8; 64],
        required_role: Role,
    ) -> std::result::Result<UnlockToken, AdminAuthError> {
        let nonce = self.take_challenge()?;
        let outcome = self
            .auth
            .verify_with_role_with_nonce(&nonce, signature, required_role);
        self.count(outcome)
    }

    /// See `AdminAuth::verify_quorum_with_nonce`.
    pub fn verify_quorum(
        &self,
        signatures: &[[u8; 64]],
        min_distinct: u8,
        role_requirements: &[Role],
    ) -> std::result::Result<UnlockToken, AdminAuthError> {
        let nonce = self.take_challenge()?;
        let outcome =
            self.auth
                .verify_quorum_with_nonce(&nonce, signatures, min_distinct, role_requirements);
        self.count(outcome)
    }

    /// See `AdminAuth::verify_signed_payload_quorum_with_nonce`. Returns
    /// the token and the matched keys' fingerprints.
    pub fn verify_signed_payload_quorum(
        &self,
        payload: &SignedPayload,
        signatures: &[[u8; 64]],
        min_distinct: u8,
        role_requirements: &[Role],
        expected_op: admin_signed_payload::OperationCode,
        server_now_unix_secs: u64,
    ) -> std::result::Result<(UnlockToken, Vec<String>), AdminAuthError> {
        self.verify_signed_payload_quorum_keys(
            payload,
            signatures,
            min_distinct,
            role_requirements,
            expected_op,
            server_now_unix_secs,
        )
        .map(|v| (v.token, v.fingerprints))
    }

    /// [`Self::verify_signed_payload_quorum`] that also returns the
    /// matched keys with their roles (external audit NN-AUD-083 /
    /// NN-AUD-084).
    pub fn verify_signed_payload_quorum_keys(
        &self,
        payload: &SignedPayload,
        signatures: &[[u8; 64]],
        min_distinct: u8,
        role_requirements: &[Role],
        expected_op: admin_signed_payload::OperationCode,
        server_now_unix_secs: u64,
    ) -> std::result::Result<VerifiedSigners, AdminAuthError> {
        let nonce = self.take_challenge()?;
        let outcome = self.auth.verify_signed_payload_quorum_with_nonce(
            &nonce,
            payload,
            signatures,
            min_distinct,
            role_requirements,
            expected_op,
            server_now_unix_secs,
        );
        self.count(outcome)
    }

    /// Lab PR 217: spend the connection's challenge without a verify — a
    /// request the agent refuses outright (the legacy unlock) still uses it
    /// up, as every request does.
    pub fn discard_challenge(&self) {
        let _ = self.nonce.take();
    }

    /// `true` once the connection has failed
    /// [`MAX_AUTH_FAILURES_PER_CONNECTION`] signature checks: the server
    /// closes it after the reply.
    pub fn exhausted(&self) -> bool {
        self.failures.get() >= MAX_AUTH_FAILURES_PER_CONNECTION
    }

    /// The connection's challenge, consumed (single use, whatever the
    /// outcome of the verify).
    fn take_challenge(&self) -> std::result::Result<[u8; 32], AdminAuthError> {
        if self.exhausted() {
            return Err(AdminAuthError::RateLimited {
                retry_after_secs: CONNECTION_RETRY_AFTER_SECS,
            });
        }
        self.nonce.take().ok_or_else(|| {
            warn!(
                target: "anti_tamper.admin_auth.verify_failure",
                reason = "no_pending_challenge",
                "admin verify with no outstanding challenge on this connection"
            );
            AdminAuthError::NoPendingChallenge
        })
    }

    /// Count a failed signature check against the connection. The one
    /// that uses up the budget is answered `RateLimited` (the reason is
    /// in the journal line the verify already wrote).
    fn count<T>(
        &self,
        outcome: std::result::Result<T, AdminAuthError>,
    ) -> std::result::Result<T, AdminAuthError> {
        let Err(e) = outcome else {
            return outcome;
        };
        if !counts_as_failure(&e) {
            return Err(e);
        }
        let failures = self.failures.get().saturating_add(1);
        self.failures.set(failures);
        if failures < MAX_AUTH_FAILURES_PER_CONNECTION {
            return Err(e);
        }
        warn!(
            target: "anti_tamper.admin_auth.verify_failure",
            reason = "connection_failure_budget",
            failures,
            last = %e,
            "admin connection failed {failures} signature checks; answering RateLimited and closing it"
        );
        Err(AdminAuthError::RateLimited {
            retry_after_secs: CONNECTION_RETRY_AFTER_SECS,
        })
    }
}

impl std::ops::Deref for ConnAuth<'_> {
    type Target = AdminAuth;

    fn deref(&self) -> &AdminAuth {
        self.auth
    }
}

/// The verify outcomes that are an attack signal (a signature or a binding
/// that does not hold) rather than operator UX (missing challenge, quorum
/// shortfall, wrong role, clock skew).
fn counts_as_failure(e: &AdminAuthError) -> bool {
    matches!(
        e,
        AdminAuthError::InvalidSignature
            | AdminAuthError::NonceMismatch
            | AdminAuthError::AgentIdMismatch
            | AdminAuthError::UnknownOperation { .. }
            | AdminAuthError::TooManySignatures { .. }
    )
}

/// External audit AUT-005: [`admin_quorum::check_submission_size`] as an
/// [`AdminAuthError`], with the journal line every refusal of a verify
/// writes.
fn check_signature_count(submitted: usize) -> std::result::Result<(), AdminAuthError> {
    admin_quorum::check_submission_size(submitted).map_err(|e| {
        warn!(
            target: "anti_tamper.admin_auth.verify_failure",
            reason = "too_many_signatures",
            submitted = e.submitted,
            max = admin_quorum::MAX_SUBMITTED_SIGNATURES,
            "admin verify: submission over the signature cap, no signature checked"
        );
        AdminAuthError::TooManySignatures {
            submitted: e.submitted,
        }
    })
}

// ────────────────────────────────────────────────────────────────────
// Tappa 8 sub-sprint A commit A5 — admin.pub role allowlist parser
// (§3.2). Helpers consumed by AdminAuth::load above.
// ────────────────────────────────────────────────────────────────────

/// External audit AUT-004: a skipped `admin.pub` line is an ERROR, each.
fn report_skipped(config_path: &Path, skipped: &[(usize, String)]) {
    for (line, reason) in skipped {
        tracing::error!(
            path = %config_path.display(),
            line,
            reason = %reason,
            "admin.pub line skipped — its key is not loaded (the other keys are)"
        );
    }
}

/// Parse one already-trimmed, non-comment, non-blank admin.pub
/// line into a [`KeyEntry`] ([`admin_quorum::parse_admin_line`]).
fn parse_admin_line(line: &str) -> Result<KeyEntry> {
    admin_quorum::parse_admin_line(line).map_err(|e| anyhow!(e))
}

/// Parse a comma-separated role list (e.g. `"unlock,audit-read"`)
/// ([`admin_quorum::parse_role_list`]).
pub fn parse_role_list(s: &str) -> Result<Vec<Role>> {
    admin_quorum::parse_role_list(s).map_err(|e| anyhow!(e))
}

/// Parse one role keyword ([`admin_quorum::parse_role_keyword`]).
pub fn parse_role_keyword(s: &str) -> Result<Role> {
    admin_quorum::parse_role_keyword(s).map_err(|e| anyhow!(e))
}

/// 8-hex-char pubkey fingerprint: first 4 bytes of SHA-256 over the
/// raw pubkey. Same convention as `nn-admin verify-keys` output and
/// nn-admin's `admin_cli::pubkey_fingerprint` — duplicated here rather than
/// imported so admin_auth stays free of an admin_cli dependency.
/// Used in log/audit context (`RoleDenied` carries this).
fn fingerprint(vk: &VerifyingKey) -> String {
    let mut h = Sha256::new();
    h.update(vk.to_bytes());
    let digest = h.finalize();
    hex::encode(&digest[..4])
}

/// 4-byte short fingerprint used by [`RotateKeysRevokeExtra`]
/// (design §7.3). Same SHA-256 prefix the hex `fingerprint`
/// helper formats; this returns the raw bytes for wire-side
/// comparisons.
pub fn fingerprint_bytes(vk: &VerifyingKey) -> [u8; 4] {
    let mut h = Sha256::new();
    h.update(vk.to_bytes());
    let digest = h.finalize();
    [digest[0], digest[1], digest[2], digest[3]]
}

// ────────────────────────────────────────────────────────────────────
// Tappa 8 sub-sprint B commit B3 (A13) — atomic admin.pub rewrite
// ────────────────────────────────────────────────────────────────────

/// Outcome of an [`atomic_rewrite_admin_pub_add`] /
/// [`atomic_rewrite_admin_pub_revoke`] call. Surfaced distinctly
/// (rather than via `anyhow::Error`) so the dispatcher can map
/// each variant to the right [`nn_proto::admin_protocol::AdminResult`]
/// without string-matching.
#[derive(Debug, thiserror::Error)]
pub enum RotateKeysError {
    /// The new pubkey requested by `rotate-keys add` already
    /// matches a line in `admin.pub`. Idempotent operations
    /// would silently succeed here; we reject so the operator
    /// notices an unexpected duplicate (a common cause is two
    /// admins trying to add the same out-of-band-shared key).
    #[error("pubkey {fingerprint} already present in admin.pub")]
    KeyAlreadyPresent { fingerprint: String },
    /// External audit AUT-006: `rotate-keys add` of a key whose 4-byte
    /// fingerprint is already held by a DIFFERENT `admin.pub` key. It used
    /// to be refused as "already present"; it is refused, named: once in,
    /// `rotate-keys revoke` (which names a key by that fingerprint) could
    /// not tell the two apart.
    #[error(
        "pubkey has fingerprint {fingerprint}, already held by a different admin.pub key \
         (a fingerprint collision: revocation by fingerprint would be ambiguous)"
    )]
    FingerprintCollision { fingerprint: String },
    /// The fingerprint requested by `rotate-keys revoke`
    /// doesn't match any line in `admin.pub`.
    #[error("no admin.pub line matches fingerprint {fingerprint}")]
    KeyNotFound { fingerprint: String },
    /// External audit AUT-006: the fingerprint requested by `rotate-keys
    /// revoke` matches `matches` DIFFERENT keys. Every matching line used
    /// to be dropped; the file is left untouched. Since `add` refuses a
    /// colliding key, such a pair comes only from a hand-written
    /// `admin.pub` (or one written before this check), and a hand edit
    /// settles it.
    #[error(
        "fingerprint {fingerprint} matches {matches} different admin.pub keys; \
         refusing to revoke (the request cannot say which)"
    )]
    AmbiguousFingerprint { fingerprint: String, matches: usize },
    /// Refusing to revoke the last remaining key — would
    /// soft-brick the agent (no operator could subsequently
    /// unlock or shutdown). Operators must add a replacement
    /// first.
    #[error("refusing to revoke the last remaining admin key")]
    LastKey,
    /// Anything else: I/O on the tmpfile, rename failure, etc.
    #[error("admin.pub rewrite I/O: {0}")]
    Io(#[from] std::io::Error),
}

/// Atomically rewrite `admin.pub` to APPEND a new key line.
/// Reads the current file, builds a fresh line for the new
/// pubkey plus its roles, writes the full body to a tmpfile,
/// fsyncs, then renames over the original. Crash between fsync
/// and rename is safe (the old file is intact); crash after
/// rename is safe (the new file is durable).
///
/// External audit AUT-006: the same key already in the file is
/// `KeyAlreadyPresent`; a different key with the same 4-byte fingerprint
/// is `FingerprintCollision` (the 32 key bytes are compared, not only the
/// fingerprint).
pub fn atomic_rewrite_admin_pub_add(
    config_path: &Path,
    new_pubkey: &VerifyingKey,
    roles: &[Role],
) -> std::result::Result<(), RotateKeysError> {
    let body = std::fs::read_to_string(config_path).map_err(RotateKeysError::Io)?;
    let new_fp = fingerprint(new_pubkey);
    let mut collision = false;
    for raw in body.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Ok(entry) = parse_admin_line(line) {
            if entry.key.to_bytes() == new_pubkey.to_bytes() {
                return Err(RotateKeysError::KeyAlreadyPresent {
                    fingerprint: new_fp,
                });
            }
            collision |= fingerprint(&entry.key) == new_fp;
        }
    }
    if collision {
        return Err(RotateKeysError::FingerprintCollision {
            fingerprint: new_fp,
        });
    }
    let mut new_body = body;
    if !new_body.is_empty() && !new_body.ends_with('\n') {
        new_body.push('\n');
    }
    new_body.push_str(&hex::encode(new_pubkey.to_bytes()));
    if !roles.is_empty() {
        new_body.push(' ');
        new_body.push_str(&format_role_list(roles));
    }
    new_body.push('\n');
    write_admin_pub_atomically(config_path, &new_body)?;
    Ok(())
}

/// Atomically rewrite `admin.pub` to REMOVE the line whose
/// pubkey fingerprint matches `target_fp` (4 raw bytes). See
/// [`atomic_rewrite_admin_pub_add`] for the durability story.
/// `LastKey` is returned if removing the line would leave the
/// file empty — design §7.2 "operators must `add` a replacement
/// first" contract.
///
/// External audit AUT-006: the fingerprint must name ONE key. Several
/// lines of that same key are all removed, as before; lines of two
/// different keys sharing the 4 bytes are `AmbiguousFingerprint`, and the
/// file is not touched.
pub fn atomic_rewrite_admin_pub_revoke(
    config_path: &Path,
    target_fp: [u8; 4],
) -> std::result::Result<(), RotateKeysError> {
    let body = std::fs::read_to_string(config_path).map_err(RotateKeysError::Io)?;
    let target_hex = hex::encode(target_fp);
    let mut out = String::new();
    let mut kept_keys = 0usize;
    let mut removed: Vec<[u8; 32]> = Vec::new();
    for raw in body.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            // Preserve blank / comment lines unchanged.
            out.push_str(raw);
            out.push('\n');
            continue;
        }
        if let Ok(entry) = parse_admin_line(line) {
            if fingerprint(&entry.key) == target_hex {
                let key = entry.key.to_bytes();
                if !removed.contains(&key) {
                    removed.push(key);
                }
                continue;
            }
            kept_keys += 1;
        }
        out.push_str(raw);
        out.push('\n');
    }
    if removed.is_empty() {
        return Err(RotateKeysError::KeyNotFound {
            fingerprint: target_hex,
        });
    }
    if removed.len() > 1 {
        return Err(RotateKeysError::AmbiguousFingerprint {
            fingerprint: target_hex,
            matches: removed.len(),
        });
    }
    if kept_keys == 0 {
        return Err(RotateKeysError::LastKey);
    }
    write_admin_pub_atomically(config_path, &out)?;
    Ok(())
}

/// Serialise a role allowlist back to the on-disk comma-form
/// (`unlock,shutdown,force-posture`). Inverse of
/// [`parse_role_list`]; only used by
/// [`atomic_rewrite_admin_pub_add`].
fn format_role_list(roles: &[Role]) -> String {
    let parts: Vec<&'static str> = roles.iter().map(|r| role_keyword(*r)).collect();
    parts.join(",")
}

/// The keyword of a role as `admin.pub` and the CLI write it: nn-proto's
/// (Wave 4 restructure, R09a, lab PR 253: the role parse is nn-proto's,
/// plan §2.4), under its path here.
pub use nn_proto::admin_quorum::role_keyword;

fn write_admin_pub_atomically(config_path: &Path, body: &str) -> std::io::Result<()> {
    // 0644 matches the pre-rotation admin.pub layout (design §6.5 / §8.1:
    // world-readable so non-root admin tools can inspect, root-only
    // writable). External audit AUT-003: never through a planted link.
    crate::atomic_file::replace(config_path, body.as_bytes(), 0o644)
}

// ────────────────────────────────────────────────────────────────────
// Tappa 8 sub-sprint A commit A4 — timestamp skew check (§6.4 layer 2)
// ────────────────────────────────────────────────────────────────────

/// Maximum allowed difference, in seconds, between the client's
/// `SignedPayload.ts` field and the server's wall-clock. ±60 s per
/// design §6.4 layer 2 — wide enough to tolerate non-NTP-synced
/// hosts and brief network latency, narrow enough that a captured
/// signature with an unaltered `ts` cannot be replayed minutes
/// later. A future hardening tappa could tighten this to ±10 s
/// once every customer deploys NTP; for V1.0 the operator-friendly
/// width wins.
pub const MAX_TIMESTAMP_SKEW_SECS: u32 = 60;

/// Returned by [`check_timestamp_skew`] when the client's `ts` is
/// outside the ± [`MAX_TIMESTAMP_SKEW_SECS`] window. Mirrors the
/// design §6.6 `AdminResult::TimestampSkew { server_ts,
/// max_skew_secs }` wire variant — `server_ts` lets the client
/// re-NTP-sync and retry without having to guess the server's
/// clock.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum TimestampSkewError {
    #[error("timestamp outside ±{max_skew_secs}s window (server_ts={server_ts})")]
    OutOfWindow { server_ts: u64, max_skew_secs: u32 },
}

/// Source of "now" for the timestamp skew check. Abstracted as a
/// trait so unit tests inject a deterministic value via
/// [`FixedClock`] without `unsafe` or thread-local time-mocking.
///
/// **Monotonic-aware note** (design §13 row A4): the skew check
/// compares two **wall clocks** — the client's `SignedPayload.ts`
/// and the server's `SystemTime::now()` — because the comparison
/// is cross-host. `CLOCK_MONOTONIC` is wrong here: it cannot be
/// compared across machines. The trait exists so test code (which
/// must be deterministic) and production code (which must read the
/// real wall clock) can both ride one verify path.
pub trait Clock: Send + Sync {
    /// Seconds since the Unix epoch as a `u64`. The skew check is
    /// integer-only on seconds; sub-second precision is irrelevant
    /// at the ±60 s window scale.
    fn now_unix_secs(&self) -> u64;
}

/// Production [`Clock`] backed by `SystemTime::now()` →
/// `CLOCK_REALTIME` on Linux. Wall-clock-based and therefore
/// subject to NTP step + manual operator adjustment; that exposure
/// is documented in §6.4 layer 2 ("server rejects `ts` outside a
/// ± 60 s window relative to its own clock") and is bounded by the
/// nonce single-use property (layer 1) and the agent_id binding
/// (layer 3, A3/A7).
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now_unix_secs(&self) -> u64 {
        // Pre-1970 system time is impossible in any production
        // deployment; default to 0 if a misconfigured host
        // surfaces one — the skew check will then reject every
        // valid client timestamp until the operator fixes the
        // clock, which is the desired fail-closed behaviour.
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    }
}

/// Pure timestamp-skew predicate. The caller supplies both
/// timestamps and the window width; this function does no I/O and
/// no clock-reading. Designed so the wiring site in A7's verify
/// path looks like
///
/// ```text
/// check_timestamp_skew(
///     payload.ts,
///     clock.now_unix_secs(),
///     MAX_TIMESTAMP_SKEW_SECS,
/// )?;
/// ```
///
/// and is trivially test-injectable via [`FixedClock`].
///
/// Boundary semantics: a difference **equal to** `max_skew_secs`
/// is accepted (`<=` check); one second past is rejected. Locked
/// in the `accepts_exact_boundary_seconds` test.
pub fn check_timestamp_skew(
    client_ts: u64,
    server_ts: u64,
    max_skew_secs: u32,
) -> Result<(), TimestampSkewError> {
    // `abs_diff` is the unsigned-safe absolute difference; it
    // never underflows even when client_ts < server_ts by a wide
    // margin (e.g. client at 0 from a botched bootstrap).
    let diff = client_ts.abs_diff(server_ts);
    if diff > u64::from(max_skew_secs) {
        Err(TimestampSkewError::OutOfWindow {
            server_ts,
            max_skew_secs,
        })
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    // ── quorum_decision (the rule; proved by Kani in kani_proofs) ─────

    fn carries(roles: &'static [&'static [Role]]) -> impl Fn(usize, Role) -> bool {
        move |k, r| roles[k].contains(&r)
    }

    #[test]
    fn quorum_threshold_zero_never_accepts_without_a_signature() {
        let d = quorum_decision(&[], carries(&[]), 0, &[]);
        assert_eq!(
            d,
            QuorumDecision::QuorumNotMet {
                required: 1,
                provided: 0
            }
        );
    }

    #[test]
    fn quorum_counts_a_key_once_however_many_signatures() {
        let roles: &[&[Role]] = &[&[Role::Unlock], &[Role::Unlock]];
        let same_key_twice = [Some(0), Some(0)];
        assert_eq!(
            quorum_decision(&same_key_twice, carries(roles), 2, &[Role::Unlock]),
            QuorumDecision::QuorumNotMet {
                required: 2,
                provided: 1
            }
        );
        let two_keys = [Some(1), None, Some(0)];
        assert_eq!(
            quorum_decision(&two_keys, carries(roles), 2, &[Role::Unlock]),
            QuorumDecision::Accept
        );
    }

    #[test]
    fn quorum_reports_no_valid_signature_only_for_a_non_empty_submission() {
        assert_eq!(
            quorum_decision(&[None, None], carries(&[]), 1, &[]),
            QuorumDecision::NoValidSignature
        );
    }

    #[test]
    fn quorum_role_denied_names_the_missing_role_and_the_first_match() {
        let roles: &[&[Role]] = &[&[Role::Unlock], &[Role::Shutdown]];
        assert_eq!(
            quorum_decision(
                &[None, Some(1), Some(0)],
                carries(roles),
                2,
                &[Role::Unlock, Role::TrustedInstaller]
            ),
            QuorumDecision::RoleDenied {
                role: Role::TrustedInstaller,
                first: 1
            }
        );
    }
    use std::io::Write;
    use tempfile::NamedTempFile;

    fn make_keypair() -> (SigningKey, VerifyingKey) {
        let signing = SigningKey::generate(&mut OsRng);
        let verifying = signing.verifying_key();
        (signing, verifying)
    }

    fn write_config(lines: &[&str]) -> NamedTempFile {
        let mut f = NamedTempFile::new().unwrap();
        for l in lines {
            writeln!(f, "{l}").unwrap();
        }
        f
    }

    // ── load() ─────────────────────────────────────────────────────

    #[test]
    fn load_rejects_empty_file() {
        let f = write_config(&[]);
        let err = AdminAuth::load(f.path()).unwrap_err();
        assert!(err.to_string().contains("no admin pub keys"), "got: {err}");
    }

    #[test]
    fn load_skips_malformed_line_keeps_valid_keys() {
        let (_, vk) = make_keypair();
        let good = hex::encode(vk.to_bytes());
        // Comment + good + bad on line 3: external audit AUT-004 — the bad
        // line costs its own key, not the admin socket.
        let f = write_config(&["# header", &good, "not-hex-at-all-zz"]);
        let auth = AdminAuth::load(f.path()).expect("the good key loads");
        assert_eq!(auth.pub_keys.read().len(), 1);
        let skipped = auth.skipped_lines();
        assert_eq!(skipped.len(), 1);
        assert_eq!(skipped[0].0, 3, "names line 3");
    }

    #[test]
    fn load_rejects_wrong_length_hex() {
        let f = write_config(&["deadbeef"]); // 8 chars, not 64
        let err = AdminAuth::load(f.path()).unwrap_err();
        assert!(err.to_string().contains("64 hex chars"), "got: {err}");
    }

    // Note: a `load_rejects_invalid_curve_point` test was attempted
    // but ed25519-dalek 2.x's `VerifyingKey::from_bytes` is permissive
    // — small-order / non-canonical checks live in `verify_strict`,
    // not at parse time. The malformed-hex and wrong-length tests
    // above already cover the load-error paths we care about.

    #[test]
    fn load_skips_comments_and_blank_lines() {
        let (_, vk) = make_keypair();
        let hex = hex::encode(vk.to_bytes());
        let f = write_config(&["# top comment", "", "   ", &hex, "# trailing", ""]);
        let auth = AdminAuth::load(f.path()).expect("should load");
        assert_eq!(auth.pub_keys.read().len(), 1);
    }

    #[test]
    fn load_accepts_multiple_keys() {
        let (_, k1) = make_keypair();
        let (_, k2) = make_keypair();
        let (_, k3) = make_keypair();
        let f = write_config(&[
            &hex::encode(k1.to_bytes()),
            &hex::encode(k2.to_bytes()),
            &hex::encode(k3.to_bytes()),
        ]);
        let auth = AdminAuth::load(f.path()).expect("load");
        assert_eq!(auth.pub_keys.read().len(), 3);
    }

    // ── issue_challenge ────────────────────────────────────────────

    #[test]
    fn issue_challenge_returns_32_bytes_of_entropy() {
        let (_, vk) = make_keypair();
        let auth = AdminAuth::build(vec![vk]);
        let auth = ConnAuth::new(&auth);
        let n1 = auth.issue_challenge().expect("issue");
        let n2 = auth.issue_challenge().expect("issue");
        // Two random 32-byte nonces colliding has probability 2^-256.
        // Distinct values is the right assertion.
        assert_ne!(n1, n2);
        assert_eq!(n1.len(), 32);
    }

    #[test]
    fn issue_challenge_overwrites_previous_pending() {
        let (signing, vk) = make_keypair();
        let auth = AdminAuth::build(vec![vk]);
        let auth = ConnAuth::new(&auth);
        let stale = auth.issue_challenge().unwrap();
        let fresh = auth.issue_challenge().unwrap();
        assert_ne!(stale, fresh);

        // Signing the stale nonce now fails — pending was replaced.
        let stale_sig = signing.sign(&stale).to_bytes();
        let err = auth.verify_unlock(&stale_sig).unwrap_err();
        assert!(matches!(err, AdminAuthError::InvalidSignature));
    }

    // ── verify_unlock ──────────────────────────────────────────────

    #[test]
    fn verify_unlock_succeeds_with_valid_signature() {
        let (signing, vk) = make_keypair();
        let auth = AdminAuth::build(vec![vk]);
        let auth = ConnAuth::new(&auth);
        let nonce = auth.issue_challenge().unwrap();
        let sig: [u8; 64] = signing.sign(&nonce).to_bytes();
        let _token = auth.verify_unlock(&sig).expect("verify should succeed");
        // Token minted; the cap-pattern test in network_isolate.rs
        // already proves the token can only originate here.
    }

    #[test]
    fn verify_unlock_fails_with_invalid_signature() {
        let (_, vk) = make_keypair();
        let (other_signing, _) = make_keypair();
        let auth = AdminAuth::build(vec![vk]);
        let auth = ConnAuth::new(&auth);
        let nonce = auth.issue_challenge().unwrap();
        // Sign the right nonce with the WRONG private key.
        let bad_sig: [u8; 64] = other_signing.sign(&nonce).to_bytes();
        let err = auth.verify_unlock(&bad_sig).unwrap_err();
        assert!(matches!(err, AdminAuthError::InvalidSignature));
    }

    #[test]
    fn verify_unlock_consumes_nonce_even_on_failure() {
        let (signing, vk) = make_keypair();
        let (other_signing, _) = make_keypair();
        let auth = AdminAuth::build(vec![vk]);
        let auth = ConnAuth::new(&auth);
        let nonce = auth.issue_challenge().unwrap();

        // First attempt: wrong key → fail, nonce consumed.
        let bad_sig: [u8; 64] = other_signing.sign(&nonce).to_bytes();
        assert!(matches!(
            auth.verify_unlock(&bad_sig),
            Err(AdminAuthError::InvalidSignature)
        ));

        // Second attempt with the RIGHT signature must now fail with
        // NoPendingChallenge — proving the nonce was consumed by the
        // failed attempt rather than left lying around.
        let good_sig: [u8; 64] = signing.sign(&nonce).to_bytes();
        let err = auth.verify_unlock(&good_sig).unwrap_err();
        assert!(matches!(err, AdminAuthError::NoPendingChallenge));
    }

    #[test]
    fn verify_unlock_with_no_outstanding_challenge() {
        let (signing, vk) = make_keypair();
        let auth = AdminAuth::build(vec![vk]);
        let auth = ConnAuth::new(&auth);
        let dummy_msg = [0u8; 32];
        let sig: [u8; 64] = signing.sign(&dummy_msg).to_bytes();
        let err = auth.verify_unlock(&sig).unwrap_err();
        assert!(matches!(err, AdminAuthError::NoPendingChallenge));
    }

    #[test]
    fn verify_unlock_works_with_secondary_key() {
        // Three pubkeys installed; only the third one's private key
        // signs. Must verify regardless of position.
        let (_, k1) = make_keypair();
        let (_, k2) = make_keypair();
        let (s3, k3) = make_keypair();
        let auth = AdminAuth::build(vec![k1, k2, k3]);
        let auth = ConnAuth::new(&auth);
        let nonce = auth.issue_challenge().unwrap();
        let sig: [u8; 64] = s3.sign(&nonce).to_bytes();
        let _ = auth.verify_unlock(&sig).expect("third key should verify");
    }

    // ── per-connection challenge and failure budget ───────────────

    /// External audit NN-AUD-078: a challenge issued to another
    /// connection neither replaces nor consumes mine.
    #[test]
    fn challenge_on_other_connection_does_not_invalidate_mine() {
        let (signing, vk) = make_keypair();
        let auth = AdminAuth::build(vec![vk]);
        let mine = ConnAuth::new(&auth);
        let other = ConnAuth::new(&auth);
        let nonce = mine.issue_challenge().unwrap();
        for _ in 0..8 {
            other.issue_challenge().unwrap();
        }
        // The other connection consumes ITS challenge with a bad signature.
        let _ = other.verify_unlock(&[0u8; 64]);
        let sig: [u8; 64] = signing.sign(&nonce).to_bytes();
        mine.verify_unlock(&sig)
            .expect("my challenge must survive another connection's requests");
    }

    /// External audit NN-AUD-079: the connection that fails
    /// MAX_AUTH_FAILURES_PER_CONNECTION signature checks is answered
    /// `RateLimited` on the last one and gets no further challenge.
    #[test]
    fn third_failure_exhausts_the_connection() {
        let (_, vk) = make_keypair();
        let (other, _) = make_keypair();
        let auth = AdminAuth::build(vec![vk]);
        let auth = ConnAuth::new(&auth);

        for attempt in 1..=MAX_AUTH_FAILURES_PER_CONNECTION {
            let nonce = auth.issue_challenge().unwrap();
            let bad: [u8; 64] = other.sign(&nonce).to_bytes();
            let err = auth.verify_unlock(&bad).unwrap_err();
            if attempt < MAX_AUTH_FAILURES_PER_CONNECTION {
                assert!(matches!(err, AdminAuthError::InvalidSignature), "{err:?}");
                assert!(!auth.exhausted());
            } else {
                assert!(
                    matches!(err, AdminAuthError::RateLimited { retry_after_secs } if retry_after_secs > 0),
                    "{err:?}"
                );
            }
        }
        assert!(auth.exhausted());
        assert!(matches!(
            auth.issue_challenge(),
            Err(AdminAuthError::RateLimited { .. })
        ));
    }

    /// External audit NN-AUD-079: failures on one connection do not
    /// rate-limit another — the old agent-wide counter let anyone lock
    /// every operator out by sending three bad signatures.
    #[test]
    fn failures_on_one_connection_do_not_rate_limit_another() {
        let (signing, vk) = make_keypair();
        let (other, _) = make_keypair();
        let auth = AdminAuth::build(vec![vk]);
        let hostile = ConnAuth::new(&auth);
        for _ in 0..MAX_AUTH_FAILURES_PER_CONNECTION {
            let nonce = hostile.issue_challenge().unwrap();
            let _ = hostile.verify_unlock(&other.sign(&nonce).to_bytes());
        }
        assert!(hostile.exhausted());

        let operator = ConnAuth::new(&auth);
        let nonce = operator
            .issue_challenge()
            .expect("another connection is not rate-limited");
        operator
            .verify_unlock(&signing.sign(&nonce).to_bytes())
            .expect("and its signature verifies");
    }

    /// Operator-UX outcomes (no challenge, quorum shortfall, wrong role)
    /// never use up the connection's budget.
    #[test]
    fn operator_ux_errors_do_not_count_against_the_connection() {
        let (signing, vk) = make_keypair();
        let auth = AdminAuth::build(vec![vk]);
        let auth = ConnAuth::new(&auth);
        for _ in 0..5 {
            assert!(matches!(
                auth.verify_unlock(&[0u8; 64]),
                Err(AdminAuthError::NoPendingChallenge)
            ));
            let nonce = auth.issue_challenge().unwrap();
            assert!(matches!(
                auth.verify_with_role(&signing.sign(&nonce).to_bytes(), Role::Shutdown),
                Err(AdminAuthError::RoleDenied { .. })
            ));
        }
        assert_eq!(auth.failures.get(), 0);
        assert!(!auth.exhausted());
    }

    // ── A4: timestamp skew check (§6.4 layer 2) ────────────────────

    /// Deterministic [`Clock`] for skew tests. Lets one helper
    /// produce repeatable "now" values without coupling to wall
    /// time. Lives in the test module — production callers use
    /// [`SystemClock`].
    #[derive(Debug, Clone, Copy)]
    struct FixedClock(u64);
    impl Clock for FixedClock {
        fn now_unix_secs(&self) -> u64 {
            self.0
        }
    }

    /// Required A4 test 1 ("in-window"): client and server
    /// timestamps that are equal — and ones that differ by any
    /// amount up to and including the cap — must verify Ok.
    /// Includes the symmetric past/future variants explicitly so a
    /// regression that accidentally inverts the sign of `diff`
    /// would still fail this test.
    #[test]
    fn check_timestamp_skew_accepts_in_window_offsets() {
        let server = FixedClock(1_710_000_000);
        // Exact match.
        check_timestamp_skew(
            server.now_unix_secs(),
            server.now_unix_secs(),
            MAX_TIMESTAMP_SKEW_SECS,
        )
        .expect("equal timestamps are in-window");
        // Client one second in the future.
        check_timestamp_skew(
            server.now_unix_secs() + 1,
            server.now_unix_secs(),
            MAX_TIMESTAMP_SKEW_SECS,
        )
        .expect("client +1s is in-window");
        // Client one second in the past.
        check_timestamp_skew(
            server.now_unix_secs() - 1,
            server.now_unix_secs(),
            MAX_TIMESTAMP_SKEW_SECS,
        )
        .expect("client -1s is in-window");
        // Mid-window (±30 s).
        check_timestamp_skew(
            server.now_unix_secs() + 30,
            server.now_unix_secs(),
            MAX_TIMESTAMP_SKEW_SECS,
        )
        .expect("client +30s is in-window");
        check_timestamp_skew(
            server.now_unix_secs() - 30,
            server.now_unix_secs(),
            MAX_TIMESTAMP_SKEW_SECS,
        )
        .expect("client -30s is in-window");
    }

    /// Required A4 test 2 ("future-skew"): a client timestamp more
    /// than [`MAX_TIMESTAMP_SKEW_SECS`] in the future must surface
    /// `OutOfWindow` carrying the server's `ts` and the window width
    /// so the client can re-NTP-sync and retry.
    #[test]
    fn check_timestamp_skew_rejects_future_skew_beyond_cap() {
        let server_now = 1_710_000_000u64;
        let client_ts = server_now + u64::from(MAX_TIMESTAMP_SKEW_SECS) + 1; // one second past cap
        match check_timestamp_skew(client_ts, server_now, MAX_TIMESTAMP_SKEW_SECS) {
            Err(TimestampSkewError::OutOfWindow {
                server_ts,
                max_skew_secs,
            }) => {
                assert_eq!(server_ts, server_now);
                assert_eq!(max_skew_secs, MAX_TIMESTAMP_SKEW_SECS);
            }
            other => panic!("expected OutOfWindow, got {other:?}"),
        }
        // Far-future stress: should still be OutOfWindow, not panic.
        check_timestamp_skew(server_now + 86_400, server_now, MAX_TIMESTAMP_SKEW_SECS)
            .expect_err("client one day ahead must reject");
    }

    /// Required A4 test 3 ("past-skew"): symmetric to test 2 —
    /// far-past client timestamps reject identically. Important
    /// because a captured-and-stored signature from yesterday's
    /// session would hit exactly this case.
    #[test]
    fn check_timestamp_skew_rejects_past_skew_beyond_cap() {
        let server_now = 1_710_000_000u64;
        let client_ts = server_now - u64::from(MAX_TIMESTAMP_SKEW_SECS) - 1;
        match check_timestamp_skew(client_ts, server_now, MAX_TIMESTAMP_SKEW_SECS) {
            Err(TimestampSkewError::OutOfWindow {
                server_ts,
                max_skew_secs,
            }) => {
                assert_eq!(server_ts, server_now);
                assert_eq!(max_skew_secs, MAX_TIMESTAMP_SKEW_SECS);
            }
            other => panic!("expected OutOfWindow, got {other:?}"),
        }
        // Far-past stress: client timestamp at zero (bootstrapped
        // host with no RTC) must reject, not silently accept.
        check_timestamp_skew(0, server_now, MAX_TIMESTAMP_SKEW_SECS)
            .expect_err("client_ts = 0 must reject when server is in 2026");
    }

    /// Required A4 test 4 ("exact-boundary"): a difference of
    /// exactly [`MAX_TIMESTAMP_SKEW_SECS`] is accepted (`<=`);
    /// one second further is rejected. Locks the boundary
    /// semantics against a future `>` vs `>=` swap.
    #[test]
    fn check_timestamp_skew_exact_boundary_inclusive() {
        let server_now = 1_710_000_000u64;
        let cap = u64::from(MAX_TIMESTAMP_SKEW_SECS);

        // Future side: exactly +cap is in, +cap+1 is out.
        check_timestamp_skew(server_now + cap, server_now, MAX_TIMESTAMP_SKEW_SECS)
            .expect("exactly +cap must be in-window");
        check_timestamp_skew(server_now + cap + 1, server_now, MAX_TIMESTAMP_SKEW_SECS)
            .expect_err("cap+1 must reject");

        // Past side: exactly -cap is in, -cap-1 is out.
        check_timestamp_skew(server_now - cap, server_now, MAX_TIMESTAMP_SKEW_SECS)
            .expect("exactly -cap must be in-window");
        check_timestamp_skew(server_now - cap - 1, server_now, MAX_TIMESTAMP_SKEW_SECS)
            .expect_err("-cap-1 must reject");
    }

    // ── Supplementary tests ────────────────────────────────────────

    /// `SystemClock` returns a value that is plausibly recent
    /// (post-2025, pre-2100). Smoke test that the production
    /// clock impl is wired to the wall clock, not stubbed to 0.
    #[test]
    fn system_clock_returns_plausible_unix_seconds() {
        let now = SystemClock.now_unix_secs();
        const Y2025: u64 = 1_735_689_600; // 2025-01-01 UTC
        const Y2100: u64 = 4_102_444_800; // 2100-01-01 UTC
        assert!(
            now > Y2025 && now < Y2100,
            "SystemClock returned implausible timestamp: {now}"
        );
    }

    /// The `Clock` trait abstraction is the test-injection seam.
    /// Demonstrate that a [`FixedClock`] can be swapped in for
    /// `SystemClock` and produces deterministic skew outcomes —
    /// this is the pattern A7's verify path will use when it
    /// finally consumes a `SignedPayload.ts`.
    #[test]
    fn fixed_clock_drives_skew_check_deterministically() {
        let clock = FixedClock(1_710_000_000);
        // In-window: client matches the fixed server time.
        check_timestamp_skew(
            clock.now_unix_secs(),
            clock.now_unix_secs(),
            MAX_TIMESTAMP_SKEW_SECS,
        )
        .expect("FixedClock baseline");
        // Out-of-window: future skew at the same fixed server time.
        check_timestamp_skew(
            clock.now_unix_secs() + 1_000,
            clock.now_unix_secs(),
            MAX_TIMESTAMP_SKEW_SECS,
        )
        .expect_err("FixedClock far-future");
    }

    /// The default cap is exactly 60 seconds per design §6.4
    /// layer 2 — a future relaxation to 120 s or tightening to
    /// 10 s is an intentional product decision, not a casual
    /// constant tweak. Locked here to make any change visible
    /// in the diff.
    #[test]
    fn max_timestamp_skew_constant_matches_design_spec() {
        assert_eq!(
            MAX_TIMESTAMP_SKEW_SECS, 60,
            "design §6.4 layer 2 mandates ±60s — change requires a roadmap update"
        );
    }

    // ── A5: per-key role allowlist (§3.2) ──────────────────────────

    /// Required A5 test (parse + default): a pubkey-only admin.pub
    /// line (no role token) gets the [`default_roles`] allowlist,
    /// guaranteeing backward compat for every admin.pub written
    /// before A5.
    #[test]
    fn load_parses_pubkey_only_assigns_default_roles() {
        let (_, vk) = make_keypair();
        let f = write_config(&[&hex::encode(vk.to_bytes())]);
        let auth = AdminAuth::load(f.path()).expect("load");
        assert_eq!(auth.pub_keys.read().len(), 1);
        let entry = &auth.pub_keys.read()[0];
        assert_eq!(entry.roles, default_roles());
        assert_eq!(entry.roles, vec![Role::Unlock, Role::AuditRead]);
    }

    /// Required A5 test (parse + single role): a single-role line
    /// extracts exactly that one role — no surprise additions, no
    /// default-roles fallback.
    #[test]
    fn load_parses_pubkey_with_single_role() {
        let (_, vk) = make_keypair();
        let line = format!("{} shutdown", hex::encode(vk.to_bytes()));
        let f = write_config(&[&line]);
        let auth = AdminAuth::load(f.path()).expect("load");
        assert_eq!(auth.pub_keys.read()[0].roles, vec![Role::Shutdown]);
    }

    /// Required A5 test (parse + multi-role): comma-separated role
    /// list preserves order and dedupes duplicates.
    #[test]
    fn load_parses_pubkey_with_multi_role_list() {
        let (_, vk) = make_keypair();
        let line = format!(
            "{} unlock,shutdown,audit-read,unlock",
            hex::encode(vk.to_bytes())
        );
        let f = write_config(&[&line]);
        let auth = AdminAuth::load(f.path()).expect("load");
        // Duplicate `unlock` is collapsed; order of first
        // appearance is preserved.
        assert_eq!(
            auth.pub_keys.read()[0].roles,
            vec![Role::Unlock, Role::Shutdown, Role::AuditRead]
        );
    }

    /// Required A5 test (each role): every role keyword from the
    /// §3.2 list parses to its expected [`Role`] discriminant —
    /// including the non-contiguous `all = 255` super-role.
    #[test]
    fn load_parses_every_role_keyword_in_design_spec_3_2() {
        let cases = [
            ("unlock", Role::Unlock),
            ("shutdown", Role::Shutdown),
            ("force-posture", Role::ForcePosture),
            ("rotate-keys", Role::RotateKeys),
            ("audit-read", Role::AuditRead),
            // Tappa 9 (C1) — same wire-keyword shape operators
            // see in admin.pub lines + CLI.
            ("fim-manage", Role::FimManage),
            ("fim-read", Role::FimRead),
            // Tappa 9.5 (K1) — design §12 Q7 split-role lock-in.
            ("canary-read", Role::CanaryRead),
            ("canary-manage", Role::CanaryManage),
            // Tappa 10 (N1) — Network Observability split-role
            // pair; design §9 reserved roles 8..=9 for these but
            // K1 won them. Per append-only, NetRead / NetManage
            // are now 10 / 11 (admin.pub keyword shape stable).
            ("net-read", Role::NetRead),
            ("net-manage", Role::NetManage),
            // FIM-009 self-upgrade (§15.1).
            ("trusted-installer", Role::TrustedInstaller),
            // Tappa 9.0.b — read-only telemetry role.
            ("telemetry-read", Role::TelemetryRead),
            // Tappa 9.0.c — triage role (subsumes telemetry-read).
            ("triage", Role::Triage),
            ("config-manage", Role::ConfigManage),
            ("response-manage", Role::ResponseManage),
            ("all", Role::All),
        ];
        for (keyword, expected) in cases {
            let (_, vk) = make_keypair();
            let line = format!("{} {keyword}", hex::encode(vk.to_bytes()));
            let f = write_config(&[&line]);
            let auth = AdminAuth::load(f.path())
                .unwrap_or_else(|e| panic!("load failed for `{keyword}`: {e}"));
            assert_eq!(
                auth.pub_keys.read()[0].roles,
                vec![expected],
                "keyword `{keyword}` should map to {expected:?}"
            );
        }
    }

    /// Required A5 test (malformed - unknown role): a typo'd role
    /// keyword surfaces a parse error with the line number and the
    /// bad token, not a silent fallback to default roles (which
    /// would mask an operator misconfiguration).
    #[test]
    fn load_rejects_unknown_role_keyword_with_line_number() {
        let (_, vk) = make_keypair();
        let line = format!("{} unlock,doesnotexist", hex::encode(vk.to_bytes()));
        let f = write_config(&["# header", &line]);
        let err = AdminAuth::load(f.path()).unwrap_err();
        let s = format!("{err:#}");
        assert!(s.contains(":2:"), "error should reference line 2, got: {s}");
        assert!(
            s.contains("doesnotexist"),
            "error should mention the bad role, got: {s}"
        );
    }

    /// Required A5 test (malformed - separator): the common
    /// operator typo of using spaces instead of commas between
    /// roles surfaces as an explicit "third token" error rather
    /// than silently using only the first role.
    #[test]
    fn load_rejects_space_separated_roles_with_actionable_message() {
        let (_, vk) = make_keypair();
        // "unlock audit-read" is two tokens, not one role list.
        let line = format!("{} unlock audit-read", hex::encode(vk.to_bytes()));
        let f = write_config(&[&line]);
        let err = AdminAuth::load(f.path()).unwrap_err();
        let s = format!("{err:#}");
        assert!(
            s.contains("comma-separated"),
            "error should explain the comma requirement, got: {s}"
        );
    }

    /// Required A5 test (verify role-match): a key whose
    /// allowlist contains the required role successfully authorises
    /// the operation. Uses `Role::AuditRead` because the default
    /// allowlist includes it — this also documents that
    /// `verify_with_role` works for non-Unlock roles.
    #[test]
    fn verify_with_role_succeeds_when_key_authorises_required_role() {
        let (signing, vk) = make_keypair();
        let auth = AdminAuth::build(vec![vk]);
        let auth = ConnAuth::new(&auth);
        let nonce = auth.issue_challenge().unwrap();
        let sig: [u8; 64] = signing.sign(&nonce).to_bytes();
        // Default roles include AuditRead, so this must succeed.
        let _ = auth
            .verify_with_role(&sig, Role::AuditRead)
            .expect("default roles include AuditRead — should succeed");
    }

    /// Required A5 test (verify role-mismatch): a correctly-signed
    /// request whose required role is NOT in the matched key's
    /// allowlist returns [`AdminAuthError::RoleDenied`] carrying
    /// the matched key's fingerprint AND the required role —
    /// audit-log-ready.
    #[test]
    fn verify_with_role_returns_role_denied_when_key_lacks_role() {
        let (signing, vk) = make_keypair();
        // Default roles are {Unlock, AuditRead} — they do NOT
        // include Shutdown. A correctly-signed Shutdown request
        // must surface RoleDenied, not InvalidSignature.
        let auth = AdminAuth::build(vec![vk]);
        let auth = ConnAuth::new(&auth);
        let nonce = auth.issue_challenge().unwrap();
        let sig: [u8; 64] = signing.sign(&nonce).to_bytes();
        let err = auth.verify_with_role(&sig, Role::Shutdown).unwrap_err();
        match err {
            AdminAuthError::RoleDenied {
                key_fingerprint,
                required_role,
            } => {
                assert_eq!(required_role, Role::Shutdown);
                assert_eq!(
                    key_fingerprint.len(),
                    8,
                    "fingerprint should be 8 hex chars (SHA-256 prefix)"
                );
                assert_eq!(key_fingerprint, fingerprint(&vk));
            }
            other => panic!("expected RoleDenied, got {other:?}"),
        }
        // Rate-limit counter MUST NOT have been incremented: the
        // request was a config error, not an attack signal.
        assert_eq!(
            auth.failures.get(),
            0,
            "RoleDenied must not count toward rate-limit"
        );
    }

    // ── Supplementary A5 tests ─────────────────────────────────────

    /// [`Role::All`] is the break-glass super-role — a key whose
    /// allowlist contains `all` authorises every required role
    /// without exception. Locks the design §3.2 contract against
    /// a future regression that adds an "all except X" carve-out.
    #[test]
    fn role_all_authorises_every_required_role() {
        let (signing, vk) = make_keypair();
        let entry = KeyEntry {
            key: vk,
            roles: vec![Role::All],
        };
        let auth = AdminAuth::build_entries(vec![entry]);
        let auth = ConnAuth::new(&auth);
        for role in [
            Role::Unlock,
            Role::Shutdown,
            Role::ForcePosture,
            Role::RotateKeys,
            Role::AuditRead,
        ] {
            let nonce = auth.issue_challenge().unwrap();
            let sig: [u8; 64] = signing.sign(&nonce).to_bytes();
            auth.verify_with_role(&sig, role)
                .unwrap_or_else(|e| panic!("Role::All should authorise {role:?}: {e:?}"));
        }
    }

    /// Tappa 9.0.b — the read/control trust gradient at the auth
    /// layer: a key whose ONLY role is `telemetry-read` is denied the
    /// control op `unlock`. The signature over the nonce is valid and
    /// the key IS loaded, so the refusal is [`AdminAuthError::RoleDenied`]
    /// (carrying the required role + fingerprint), NOT
    /// `InvalidSignature` — and it must not count toward the rate
    /// limit (a config-level refusal, not an attack). This is the
    /// `read != control` guarantee a telemetry-read-only dashboard key
    /// must satisfy.
    #[test]
    fn telemetry_read_only_key_is_role_denied_for_unlock() {
        let (signing, vk) = make_keypair();
        let entry = KeyEntry {
            key: vk,
            roles: vec![Role::TelemetryRead],
        };
        let auth = AdminAuth::build_entries(vec![entry]);
        let auth = ConnAuth::new(&auth);
        let nonce = auth.issue_challenge().unwrap();
        let sig: [u8; 64] = signing.sign(&nonce).to_bytes();
        match auth.verify_with_role(&sig, Role::Unlock).unwrap_err() {
            AdminAuthError::RoleDenied { required_role, .. } => {
                assert_eq!(required_role, Role::Unlock);
            }
            other => panic!("expected RoleDenied for telemetry-read key, got {other:?}"),
        }
        assert_eq!(
            auth.failures.get(),
            0,
            "RoleDenied must not count toward rate-limit"
        );
    }

    /// Tappa 9.0.c — the triage role SUBSUMES telemetry-read: a key
    /// whose only role is `triage` authorises a `TelemetryRead`
    /// requirement (so a triage-only key can read the detections it
    /// triages). The subsumption is one-directional — the converse is
    /// covered by `telemetry_read_only_key_is_role_denied_for_triage`.
    #[test]
    fn triage_key_authorises_telemetry_read_requirement() {
        let (signing, vk) = make_keypair();
        let entry = KeyEntry {
            key: vk,
            roles: vec![Role::Triage],
        };
        let auth = AdminAuth::build_entries(vec![entry]);
        let auth = ConnAuth::new(&auth);
        let nonce = auth.issue_challenge().unwrap();
        let sig: [u8; 64] = signing.sign(&nonce).to_bytes();
        auth.verify_with_role(&sig, Role::TelemetryRead)
            .expect("triage role must subsume telemetry-read");
    }

    /// Tappa 9.0.c — the subsumption is one-directional: a
    /// `telemetry-read`-only key is RoleDenied for a `Triage`
    /// requirement (read does NOT imply triage). This is the
    /// gate `DetectionSetStatus` relies on — a read-only dashboard
    /// key cannot change a detection's status.
    #[test]
    fn telemetry_read_only_key_is_role_denied_for_triage() {
        let (signing, vk) = make_keypair();
        let entry = KeyEntry {
            key: vk,
            roles: vec![Role::TelemetryRead],
        };
        let auth = AdminAuth::build_entries(vec![entry]);
        let auth = ConnAuth::new(&auth);
        let nonce = auth.issue_challenge().unwrap();
        let sig: [u8; 64] = signing.sign(&nonce).to_bytes();
        match auth.verify_with_role(&sig, Role::Triage).unwrap_err() {
            AdminAuthError::RoleDenied { required_role, .. } => {
                assert_eq!(required_role, Role::Triage);
            }
            other => panic!("expected RoleDenied for telemetry-read key, got {other:?}"),
        }
        assert_eq!(
            auth.failures.get(),
            0,
            "RoleDenied must not count toward rate-limit"
        );
    }

    /// The pre-A5 [`ConnAuth::verify_unlock`] entry point is now
    /// a wrapper around `verify_with_role(sig, Role::Unlock)` and
    /// behaves byte-identically for every legacy admin.pub line
    /// (default roles include Unlock). Anchor for the backward-
    /// compat guarantee called out in `verify_unlock`'s doc-comment.
    #[test]
    fn verify_unlock_is_backward_compatible_with_pre_a5_admin_pub() {
        let (signing, vk) = make_keypair();
        let auth = AdminAuth::build(vec![vk]);
        let auth = ConnAuth::new(&auth);
        let nonce = auth.issue_challenge().unwrap();
        let sig: [u8; 64] = signing.sign(&nonce).to_bytes();
        let _token = auth
            .verify_unlock(&sig)
            .expect("pre-A5 admin.pub must continue to authorise unlock");
    }

    // ── A6: k-of-n quorum verify (§3.3) ────────────────────────────

    /// Build an AdminAuth with N keys, each carrying the provided
    /// roles. Returns the auth + the signing keys (in the same
    /// order as their entries) so tests can mint signatures for
    /// specific keys deterministically.
    fn build_auth_with_keyed_roles(per_key_roles: &[Vec<Role>]) -> (AdminAuth, Vec<SigningKey>) {
        let mut entries = Vec::with_capacity(per_key_roles.len());
        let mut signers = Vec::with_capacity(per_key_roles.len());
        for roles in per_key_roles {
            let (signing, verifying) = make_keypair();
            entries.push(KeyEntry {
                key: verifying,
                roles: roles.clone(),
            });
            signers.push(signing);
        }
        let auth = AdminAuth::build_entries(entries);
        (auth, signers)
    }

    /// Required A6 test 1 (success path): two signatures from two
    /// distinct admin keys, both with the required role, meet a
    /// 2-of-N quorum and mint a token.
    #[test]
    fn verify_quorum_succeeds_with_two_distinct_keys_carrying_required_role() {
        let (auth, signers) = build_auth_with_keyed_roles(&[
            vec![Role::Shutdown, Role::Unlock],
            vec![Role::Shutdown, Role::AuditRead],
        ]);
        let auth = ConnAuth::new(&auth);
        let nonce = auth.issue_challenge().unwrap();
        let sigs = [
            signers[0].sign(&nonce).to_bytes(),
            signers[1].sign(&nonce).to_bytes(),
        ];
        auth.verify_quorum(&sigs, 2, &[Role::Shutdown])
            .expect("2-of-N with role met must succeed");
    }

    /// Required A6 test 2 (insufficient distinct): one valid
    /// signature when min_distinct = 2 surfaces QuorumNotMet
    /// carrying { required: 2, provided: 1 } — does NOT trip
    /// rate-limit (a co-signer simply hasn't replied yet).
    #[test]
    fn verify_quorum_rejects_insufficient_distinct_signatures_without_rate_limit() {
        let (auth, signers) =
            build_auth_with_keyed_roles(&[vec![Role::Shutdown], vec![Role::Shutdown]]);
        let auth = ConnAuth::new(&auth);
        let nonce = auth.issue_challenge().unwrap();
        let sigs = [signers[0].sign(&nonce).to_bytes()];
        match auth.verify_quorum(&sigs, 2, &[Role::Shutdown]) {
            Err(AdminAuthError::QuorumNotMet { required, provided }) => {
                assert_eq!(required, 2);
                assert_eq!(provided, 1);
            }
            other => panic!("expected QuorumNotMet{{2,1}}, got {other:?}"),
        }
        // Rate-limit counter MUST stay at zero — operator UX
        // event, not attack signal.
        assert_eq!(
            auth.failures.get(),
            0,
            "QuorumNotMet must not count toward rate-limit"
        );
    }

    /// Required A6 test 3 (distinct-key tally): two signatures
    /// from the SAME key count as one distinct match. A 2-of-N
    /// quorum cannot be satisfied by one operator submitting two
    /// copies of their own signature.
    #[test]
    fn verify_quorum_tallies_distinct_keys_not_signatures() {
        let (auth, signers) =
            build_auth_with_keyed_roles(&[vec![Role::Shutdown], vec![Role::Shutdown]]);
        let auth = ConnAuth::new(&auth);
        let nonce = auth.issue_challenge().unwrap();
        // Same signing key, twice.
        let sig0: [u8; 64] = signers[0].sign(&nonce).to_bytes();
        let sigs = [sig0, sig0];
        match auth.verify_quorum(&sigs, 2, &[Role::Shutdown]) {
            Err(AdminAuthError::QuorumNotMet { required, provided }) => {
                assert_eq!(required, 2);
                assert_eq!(
                    provided, 1,
                    "two sigs from one key must tally as 1 distinct"
                );
            }
            other => panic!("expected QuorumNotMet{{2,1}}, got {other:?}"),
        }
    }

    /// Required A6 test 4 (role-requirement satisfied by one
    /// signer): the role requirement is per-quorum, not per-signer.
    /// One key carries `RotateKeys`, the second carries only
    /// `Unlock` — but the 2-of-N submission with `[RotateKeys]`
    /// required succeeds because AT LEAST ONE matched key has it.
    #[test]
    fn verify_quorum_role_requirement_satisfied_by_any_one_matched_key() {
        let (auth, signers) = build_auth_with_keyed_roles(&[
            vec![Role::RotateKeys, Role::Unlock], // the rotate-keys-bearing co-signer
            vec![Role::Unlock],                   // the "any second admin" co-signer
        ]);
        let auth = ConnAuth::new(&auth);
        let nonce = auth.issue_challenge().unwrap();
        let sigs = [
            signers[0].sign(&nonce).to_bytes(),
            signers[1].sign(&nonce).to_bytes(),
        ];
        auth.verify_quorum(&sigs, 2, &[Role::RotateKeys])
            .expect("rotate-keys carried by one of two matched keys must satisfy");
    }

    /// Required A6 test 5 (role-requirement NOT met): two valid
    /// signatures from distinct keys, but neither key carries the
    /// required role. Surfaces RoleDenied (not QuorumNotMet) so
    /// the operator's UX hint is "wrong key, not too few keys."
    #[test]
    fn verify_quorum_returns_role_denied_when_no_matched_key_carries_required_role() {
        let (auth, signers) = build_auth_with_keyed_roles(&[
            vec![Role::Unlock, Role::AuditRead],
            vec![Role::Unlock, Role::AuditRead],
        ]);
        let auth = ConnAuth::new(&auth);
        let nonce = auth.issue_challenge().unwrap();
        let sigs = [
            signers[0].sign(&nonce).to_bytes(),
            signers[1].sign(&nonce).to_bytes(),
        ];
        match auth.verify_quorum(&sigs, 2, &[Role::Shutdown]) {
            Err(AdminAuthError::RoleDenied { required_role, .. }) => {
                assert_eq!(required_role, Role::Shutdown);
            }
            other => panic!("expected RoleDenied(Shutdown), got {other:?}"),
        }
        // RoleDenied also must not trip the rate-limit counter —
        // legit operator with the wrong key, not attack.
        assert_eq!(auth.failures.get(), 0);
    }

    /// Required A6 test 6 (counts only valid signatures): a
    /// submission mixing valid and garbage signatures counts only
    /// the validly-matching ones toward quorum. A 2-of-N quorum
    /// with one valid + one garbage sig fails as QuorumNotMet
    /// (provided=1), NOT as InvalidSignature.
    #[test]
    fn verify_quorum_counts_only_valid_matching_signatures() {
        let (auth, signers) =
            build_auth_with_keyed_roles(&[vec![Role::Shutdown], vec![Role::Shutdown]]);
        let auth = ConnAuth::new(&auth);
        let nonce = auth.issue_challenge().unwrap();
        let valid: [u8; 64] = signers[0].sign(&nonce).to_bytes();
        let garbage: [u8; 64] = [0u8; 64];
        let sigs = [valid, garbage];
        match auth.verify_quorum(&sigs, 2, &[Role::Shutdown]) {
            Err(AdminAuthError::QuorumNotMet { required, provided }) => {
                assert_eq!(required, 2);
                assert_eq!(provided, 1);
            }
            other => panic!("expected QuorumNotMet{{2,1}}, got {other:?}"),
        }
        // Submission HAD a garbage sig but ALSO had a valid one
        // — so it's not an "all-invalid" attack signal. Rate-limit
        // counter must stay zero.
        assert_eq!(auth.failures.get(), 0);
    }

    // ── Supplementary A6 tests ─────────────────────────────────────

    /// A non-empty submission whose every signature is garbage
    /// IS an attack signal — InvalidSignature surfaces and the
    /// rate-limit counter increments.
    #[test]
    fn verify_quorum_all_garbage_signatures_trips_rate_limit() {
        let (auth, _) = build_auth_with_keyed_roles(&[vec![Role::Shutdown]]);
        let auth = ConnAuth::new(&auth);
        let _nonce = auth.issue_challenge().unwrap();
        let sigs = [[0u8; 64], [1u8; 64]];
        match auth.verify_quorum(&sigs, 1, &[]) {
            Err(AdminAuthError::InvalidSignature) => {}
            other => panic!("expected InvalidSignature, got {other:?}"),
        }
        assert_eq!(
            auth.failures.get(),
            1,
            "all-garbage submission must count toward rate-limit"
        );
    }

    /// An empty signature submission surfaces QuorumNotMet (NOT
    /// InvalidSignature) and does NOT trip the rate-limit
    /// counter — a no-op submission can't be an attack.
    #[test]
    fn verify_quorum_rejects_empty_submission_as_quorum_not_met_no_rate_limit() {
        let (auth, _) = build_auth_with_keyed_roles(&[vec![Role::Shutdown]]);
        let auth = ConnAuth::new(&auth);
        let _nonce = auth.issue_challenge().unwrap();
        match auth.verify_quorum(&[], 2, &[Role::Shutdown]) {
            Err(AdminAuthError::QuorumNotMet { required, provided }) => {
                assert_eq!(required, 2);
                assert_eq!(provided, 0);
            }
            other => panic!("expected QuorumNotMet{{2,0}}, got {other:?}"),
        }
        assert_eq!(auth.failures.get(), 0);
    }

    /// [`Role::All`] satisfies any required role in a quorum
    /// check — same semantics as single-key verify_with_role.
    /// Useful for break-glass operators whose key holds `all`.
    #[test]
    fn verify_quorum_role_all_satisfies_any_required_role() {
        let (auth, signers) = build_auth_with_keyed_roles(&[vec![Role::All], vec![Role::Unlock]]);
        let auth = ConnAuth::new(&auth);
        let nonce = auth.issue_challenge().unwrap();
        let sigs = [
            signers[0].sign(&nonce).to_bytes(),
            signers[1].sign(&nonce).to_bytes(),
        ];
        // Required role is RotateKeys — only the All-key satisfies.
        auth.verify_quorum(&sigs, 2, &[Role::RotateKeys])
            .expect("Role::All must satisfy RotateKeys role requirement");
    }

    // ── A13 (B3) — rotate-keys atomic rewrite + reload ─────────────

    /// A13 test #1: `atomic_rewrite_admin_pub_add` appends a new
    /// line for a previously-unknown pubkey and preserves all
    /// existing lines verbatim. Idempotency rejection (same key
    /// added twice) returns `KeyAlreadyPresent`.
    #[test]
    fn rotate_keys_add_appends_and_rejects_duplicate() {
        let dir = tempfile::TempDir::new().unwrap();
        let admin_pub = dir.path().join("admin.pub");
        let primary = SigningKey::generate(&mut OsRng);
        std::fs::write(
            &admin_pub,
            format!(
                "{} unlock,rotate-keys\n",
                hex::encode(primary.verifying_key().to_bytes())
            ),
        )
        .unwrap();

        let new_key = SigningKey::generate(&mut OsRng);
        atomic_rewrite_admin_pub_add(
            &admin_pub,
            &new_key.verifying_key(),
            &[Role::Unlock, Role::AuditRead],
        )
        .expect("first add should succeed");

        let body = std::fs::read_to_string(&admin_pub).unwrap();
        assert_eq!(body.lines().count(), 2, "file body: {body}");
        assert!(body.contains(&hex::encode(primary.verifying_key().to_bytes())));
        assert!(body.contains(&hex::encode(new_key.verifying_key().to_bytes())));
        assert!(body.contains("unlock,audit-read"));

        let err =
            atomic_rewrite_admin_pub_add(&admin_pub, &new_key.verifying_key(), &[Role::Unlock])
                .expect_err("second add of the same key must reject");
        assert!(matches!(err, RotateKeysError::KeyAlreadyPresent { .. }));
    }

    /// A13 test #2: `atomic_rewrite_admin_pub_revoke` removes
    /// the matching line, KeyNotFound when the fingerprint is
    /// absent, LastKey when removing would empty the file.
    #[test]
    fn rotate_keys_revoke_removes_line_and_guards_last_key() {
        let dir = tempfile::TempDir::new().unwrap();
        let admin_pub = dir.path().join("admin.pub");
        let key_a = SigningKey::generate(&mut OsRng);
        let key_b = SigningKey::generate(&mut OsRng);
        std::fs::write(
            &admin_pub,
            format!(
                "{} unlock\n{} unlock,rotate-keys\n",
                hex::encode(key_a.verifying_key().to_bytes()),
                hex::encode(key_b.verifying_key().to_bytes()),
            ),
        )
        .unwrap();

        // Revoke key_a — succeeds; file now has only key_b.
        let fp_a = fingerprint_bytes(&key_a.verifying_key());
        atomic_rewrite_admin_pub_revoke(&admin_pub, fp_a).expect("revoke of key_a");
        let body = std::fs::read_to_string(&admin_pub).unwrap();
        assert_eq!(body.lines().count(), 1);
        assert!(body.contains(&hex::encode(key_b.verifying_key().to_bytes())));
        assert!(!body.contains(&hex::encode(key_a.verifying_key().to_bytes())));

        // Revoke a bogus fingerprint — KeyNotFound.
        let err = atomic_rewrite_admin_pub_revoke(&admin_pub, [0xAA; 4])
            .expect_err("bogus fingerprint must error");
        assert!(matches!(err, RotateKeysError::KeyNotFound { .. }));

        // Revoke the last remaining key — LastKey guard fires.
        let fp_b = fingerprint_bytes(&key_b.verifying_key());
        let err = atomic_rewrite_admin_pub_revoke(&admin_pub, fp_b)
            .expect_err("revoking the last key must error");
        assert!(matches!(err, RotateKeysError::LastKey));
        // File body must be intact when LastKey fires (no atomic
        // rewrite occurred).
        let still = std::fs::read_to_string(&admin_pub).unwrap();
        assert!(still.contains(&hex::encode(key_b.verifying_key().to_bytes())));
    }

    /// A13 test #3: `AdminAuth::reload` re-parses the file and
    /// hot-swaps the in-memory key set so the next verify sees
    /// the new keys. Round-trip: load → snapshot fingerprints →
    /// rewrite file (add a key) → reload → snapshot → assert new
    /// key present.
    #[test]
    fn admin_auth_reload_picks_up_rewritten_keys() {
        let dir = tempfile::TempDir::new().unwrap();
        let admin_pub = dir.path().join("admin.pub");
        let primary = SigningKey::generate(&mut OsRng);
        std::fs::write(
            &admin_pub,
            format!(
                "{} unlock,rotate-keys\n",
                hex::encode(primary.verifying_key().to_bytes())
            ),
        )
        .unwrap();
        let auth = AdminAuth::load(&admin_pub).expect("load");
        let before = auth.key_fingerprints_snapshot();
        assert_eq!(before.len(), 1);

        // Rewrite the file via the new helper.
        let new_key = SigningKey::generate(&mut OsRng);
        atomic_rewrite_admin_pub_add(&admin_pub, &new_key.verifying_key(), &[Role::Unlock])
            .expect("rewrite");
        auth.reload(&admin_pub).expect("reload");

        let after = auth.key_fingerprints_snapshot();
        assert_eq!(after.len(), 2, "after reload: {after:?}");
        let new_fp = fingerprint(&new_key.verifying_key());
        assert!(
            after.contains(&new_fp),
            "new_fp {new_fp} missing in {after:?}"
        );
    }

    /// A13 test #4: `reload` refuses to swap in an empty key set
    /// (soft-brick guard). Mirrors the load() guard so the
    /// invariant `pub_keys.is_empty() == false` holds across the
    /// AdminAuth lifetime.
    #[test]
    fn admin_auth_reload_rejects_empty_admin_pub() {
        let dir = tempfile::TempDir::new().unwrap();
        let admin_pub = dir.path().join("admin.pub");
        let primary = SigningKey::generate(&mut OsRng);
        std::fs::write(
            &admin_pub,
            format!(
                "{} unlock\n",
                hex::encode(primary.verifying_key().to_bytes())
            ),
        )
        .unwrap();
        let auth = AdminAuth::load(&admin_pub).expect("load");

        // Truncate to empty (the LastKey guard prevents this in
        // production, but a manual operator edit could).
        std::fs::write(&admin_pub, "").unwrap();
        let err = auth.reload(&admin_pub).expect_err("empty file must reject");
        let msg = format!("{err:#}");
        assert!(
            msg.contains("empty admin.pub") || msg.contains("soft-brick"),
            "reload error must mention empty/soft-brick; got: {msg}"
        );
        // In-memory key set is UNCHANGED — verify still works
        // against the original key.
        let snap = auth.key_fingerprints_snapshot();
        assert_eq!(snap.len(), 1);
    }

    // ── PHASE_D_004 — verify_signed_payload_quorum returns fps ────

    /// PHASE_D_004 surface test: on success, verify returns
    /// the matched-key fingerprints in admin.pub index-order.
    /// 2-of-N quorum with two distinct signing keys → two
    /// distinct fingerprints in the returned Vec, primary
    /// signer first. The audit-log dispatch layer relies on
    /// this ordering for its `key_fp` / `cosigner_fps` split.
    #[test]
    fn verify_signed_payload_quorum_returns_matched_fingerprints() {
        use nn_proto::admin_signed_payload::{
            sign as sign_payload, signing_digest, OperationCode, SignedPayload,
        };
        // Build a 2-of-N auth with both keys carrying Shutdown
        // role + a stable agent_id we can pass to the payload.
        let agent_id = [0x77; 16];
        let signers: Vec<SigningKey> = (0..2).map(|_| SigningKey::generate(&mut OsRng)).collect();
        let entries: Vec<KeyEntry> = signers
            .iter()
            .map(|s| KeyEntry {
                key: s.verifying_key(),
                roles: vec![Role::Shutdown],
            })
            .collect();
        let auth = AdminAuth::build_entries_with_agent_id(entries, agent_id);
        let auth = ConnAuth::new(&auth);
        let nonce = auth.issue_challenge().unwrap();
        let payload = SignedPayload::new_shutdown(nonce, 1_700_000_000, agent_id, 10);
        // Sanity: signing_digest is non-empty.
        let _ = signing_digest(&payload).expect("digest");
        let sigs: Vec<[u8; 64]> = signers
            .iter()
            .map(|s| sign_payload(&payload, s).expect("sign"))
            .collect();

        let (_token, fps) = auth
            .verify_signed_payload_quorum(
                &payload,
                &sigs,
                2,
                &[Role::Shutdown],
                OperationCode::Shutdown,
                1_700_000_000,
            )
            .expect("verify must succeed");
        // Two distinct 8-hex fingerprints.
        assert_eq!(fps.len(), 2, "expected 2 matched fps, got {fps:?}");
        assert_ne!(fps[0], fps[1], "fps must be distinct: {fps:?}");
        for fp in &fps {
            assert_eq!(fp.len(), 8, "fp must be 8 hex chars: {fp}");
            assert!(
                fp.chars().all(|c| c.is_ascii_hexdigit()),
                "fp must be hex: {fp}"
            );
        }
        // The fingerprints match the two installed pubkeys
        // (order-independent — verify reports in admin.pub
        // index-order, which equals signer-vec order here).
        let expected: Vec<String> = signers
            .iter()
            .map(|s| fingerprint(&s.verifying_key()))
            .collect();
        for fp in &fps {
            assert!(
                expected.contains(fp),
                "fp {fp} not in expected set {expected:?}"
            );
        }

        // External audit NN-AUD-083 / NN-AUD-084: the `_keys` variant also
        // hands back the matched keys with their roles.
        let nonce = auth.issue_challenge().unwrap();
        let payload = SignedPayload::new_shutdown(nonce, 1_700_000_000, agent_id, 10);
        let sigs: Vec<[u8; 64]> = vec![sign_payload(&payload, &signers[1]).expect("sign")];
        let verified = auth
            .verify_signed_payload_quorum_keys(
                &payload,
                &sigs,
                1,
                &[Role::Shutdown],
                OperationCode::Shutdown,
                1_700_000_000,
            )
            .expect("verify must succeed");
        assert_eq!(verified.keys.len(), 1);
        assert_eq!(verified.keys[0].key, signers[1].verifying_key());
        assert_eq!(verified.keys[0].roles, vec![Role::Shutdown]);
        assert_eq!(
            verified.fingerprints,
            vec![fingerprint(&signers[1].verifying_key())]
        );
    }

    // ── External audit, Wave 3: signed-request verification (lab PR 192) ──

    /// Two keys whose 4-byte fingerprints collide (SHA-256 prefix
    /// `e78e8469`), found by a birthday search over these seeds: a real
    /// collision, no test hook.
    fn colliding_keys() -> (SigningKey, SigningKey) {
        let seed = |i: u64| {
            let mut s = [0x46u8; 32];
            s[..8].copy_from_slice(&i.to_le_bytes());
            s
        };
        let a = SigningKey::from_bytes(&seed(57_696));
        let b = SigningKey::from_bytes(&seed(60_119));
        assert_ne!(a.verifying_key(), b.verifying_key());
        assert_eq!(
            fingerprint_bytes(&a.verifying_key()),
            fingerprint_bytes(&b.verifying_key())
        );
        (a, b)
    }

    fn pub_hex(sk: &SigningKey) -> String {
        hex::encode(sk.verifying_key().to_bytes())
    }

    /// External audit AUT-006: a revoke whose fingerprint names two
    /// different keys removes nothing (both used to go); the file is byte
    /// for byte as it was and both keys still load. One key listed on two
    /// lines is still one key: both lines go, as before.
    #[test]
    fn revoke_refuses_ambiguous_fingerprint() {
        let (a, b) = colliding_keys();
        let c = SigningKey::from_bytes(&[3; 32]);
        let dir = tempfile::TempDir::new().unwrap();
        let admin_pub = dir.path().join("admin.pub");
        let body = format!(
            "# admins\n{} unlock,rotate-keys\n{} unlock\n{} shutdown\n",
            pub_hex(&a),
            pub_hex(&b),
            pub_hex(&c)
        );
        std::fs::write(&admin_pub, &body).unwrap();
        match atomic_rewrite_admin_pub_revoke(&admin_pub, fingerprint_bytes(&a.verifying_key())) {
            Err(RotateKeysError::AmbiguousFingerprint {
                fingerprint,
                matches,
            }) => {
                assert_eq!(fingerprint, "e78e8469");
                assert_eq!(matches, 2);
            }
            other => panic!("expected AmbiguousFingerprint, got {other:?}"),
        }
        assert_eq!(std::fs::read_to_string(&admin_pub).unwrap(), body);
        let auth = AdminAuth::load(&admin_pub).unwrap();
        assert_eq!(auth.key_fingerprints_snapshot().len(), 3);

        let body = format!(
            "{} unlock\n{} unlock,audit-read\n{} shutdown\n",
            pub_hex(&a),
            pub_hex(&a),
            pub_hex(&c)
        );
        std::fs::write(&admin_pub, &body).unwrap();
        atomic_rewrite_admin_pub_revoke(&admin_pub, fingerprint_bytes(&a.verifying_key()))
            .expect("one key on two lines is not ambiguous");
        let after = std::fs::read_to_string(&admin_pub).unwrap();
        assert_eq!(after, format!("{} shutdown\n", pub_hex(&c)));
    }

    /// External audit AUT-006: adding a key whose fingerprint another key
    /// already holds is refused as a collision, not as "already present";
    /// adding the very same key is still `KeyAlreadyPresent`. Neither
    /// touches the file.
    #[test]
    fn add_names_a_fingerprint_collision() {
        let (a, b) = colliding_keys();
        let dir = tempfile::TempDir::new().unwrap();
        let admin_pub = dir.path().join("admin.pub");
        let body = format!("{} unlock,rotate-keys\n", pub_hex(&a));
        std::fs::write(&admin_pub, &body).unwrap();
        let err = atomic_rewrite_admin_pub_add(&admin_pub, &b.verifying_key(), &[Role::Unlock])
            .expect_err("a colliding key must be refused");
        assert!(
            matches!(&err, RotateKeysError::FingerprintCollision { fingerprint } if fingerprint == "e78e8469"),
            "{err:?}"
        );
        assert!(err.to_string().contains("collision"), "{err}");
        let err = atomic_rewrite_admin_pub_add(&admin_pub, &a.verifying_key(), &[Role::Unlock])
            .expect_err("the same key twice must be refused");
        assert!(
            matches!(err, RotateKeysError::KeyAlreadyPresent { .. }),
            "{err:?}"
        );
        assert_eq!(std::fs::read_to_string(&admin_pub).unwrap(), body);
    }

    /// Two keys holding `shutdown` (and `unlock`), bound to `agent_id`.
    fn shutdown_pair(agent_id: [u8; 16]) -> (AdminAuth, [SigningKey; 2]) {
        let sks = [
            SigningKey::from_bytes(&[0x21; 32]),
            SigningKey::from_bytes(&[0x22; 32]),
        ];
        let entries = sks
            .iter()
            .map(|sk| KeyEntry {
                key: sk.verifying_key(),
                roles: vec![Role::Shutdown, Role::Unlock],
            })
            .collect();
        (
            AdminAuth::build_entries_with_agent_id(entries, agent_id),
            sks,
        )
    }

    /// External audit AUT-001: a payload whose `op` is the request's but
    /// whose `extra` is another operation's is refused before any
    /// signature is checked — `UnknownOperation`, no token, counted — on
    /// the live path (only the tag was checked) as on the stored one.
    #[test]
    fn verify_signed_payload_quorum_rejects_op_extra_mismatch() {
        use nn_proto::admin_signed_payload::{
            sign as sign_payload, OperationCode, OperationExtra, UnlockExtra,
        };
        const T: u64 = 1_700_000_000;
        let agent_id = [0x5a; 16];
        let (auth, sks) = shutdown_pair(agent_id);
        let conn = ConnAuth::new(&auth);
        let nonce = conn.issue_challenge().unwrap();
        let payload = SignedPayload {
            op: OperationCode::Shutdown,
            nonce,
            ts: T,
            agent_id,
            extra: OperationExtra::Unlock(UnlockExtra {}),
        };
        let sigs: Vec<[u8; 64]> = sks
            .iter()
            .map(|sk| sign_payload(&payload, sk).unwrap())
            .collect();
        match conn.verify_signed_payload_quorum_keys(
            &payload,
            &sigs,
            2,
            &[Role::Shutdown],
            OperationCode::Shutdown,
            T,
        ) {
            Err(AdminAuthError::UnknownOperation { expected, got }) => {
                assert_eq!(expected, OperationCode::Shutdown);
                assert_eq!(got, OperationCode::Shutdown);
            }
            other => panic!("expected UnknownOperation, got {other:?}"),
        }
        assert_eq!(conn.failures.get(), 1, "an op/extra mismatch is counted");
        assert!(matches!(
            auth.verify_stored_payload(
                &payload,
                &sigs,
                2,
                &[Role::Shutdown],
                OperationCode::Shutdown
            ),
            Err(AdminAuthError::UnknownOperation { .. })
        ));
    }

    /// External audit AUT-005: more than `MAX_SUBMITTED_SIGNATURES`
    /// signatures — every one of them valid — are refused before any is
    /// checked, and the refusal is counted; the cap itself is accepted.
    /// The same on the nonce-only quorum and the stored-payload paths.
    #[test]
    fn verify_quorum_rejects_submission_over_signature_cap() {
        use nn_proto::admin_signed_payload::{sign as sign_payload, OperationCode};
        const T: u64 = 1_700_000_000;
        let cap = admin_quorum::MAX_SUBMITTED_SIGNATURES;
        let agent_id = [0x5b; 16];
        let (auth, sks) = shutdown_pair(agent_id);
        let conn = ConnAuth::new(&auth);
        let submission = |payload: &SignedPayload, n: usize| -> Vec<[u8; 64]> {
            sks.iter()
                .map(|sk| sign_payload(payload, sk).unwrap())
                .cycle()
                .take(n)
                .collect()
        };

        let nonce = conn.issue_challenge().unwrap();
        let payload = SignedPayload::new_shutdown(nonce, T, agent_id, 10);
        let over = submission(&payload, cap + 1);
        match conn.verify_signed_payload_quorum_keys(
            &payload,
            &over,
            2,
            &[Role::Shutdown],
            OperationCode::Shutdown,
            T,
        ) {
            Err(AdminAuthError::TooManySignatures { submitted }) => assert_eq!(submitted, cap + 1),
            other => panic!("expected TooManySignatures, got {other:?}"),
        }
        assert_eq!(conn.failures.get(), 1, "the refusal is counted");
        assert!(matches!(
            auth.verify_stored_payload(
                &payload,
                &over,
                2,
                &[Role::Shutdown],
                OperationCode::Shutdown
            ),
            Err(AdminAuthError::TooManySignatures { .. })
        ));

        let nonce = conn.issue_challenge().unwrap();
        let payload = SignedPayload::new_shutdown(nonce, T, agent_id, 10);
        let at_cap = submission(&payload, cap);
        let verified = conn
            .verify_signed_payload_quorum_keys(
                &payload,
                &at_cap,
                2,
                &[Role::Shutdown],
                OperationCode::Shutdown,
                T,
            )
            .expect("a submission at the cap is checked as before");
        assert_eq!(verified.keys.len(), 2);

        let nonce = conn.issue_challenge().unwrap();
        let over: Vec<[u8; 64]> = sks
            .iter()
            .map(|sk| sk.sign(&nonce).to_bytes())
            .cycle()
            .take(cap + 1)
            .collect();
        assert!(matches!(
            conn.verify_quorum(&over, 2, &[Role::Shutdown]),
            Err(AdminAuthError::TooManySignatures { .. })
        ));
        assert_eq!(conn.failures.get(), 2);
    }
}
