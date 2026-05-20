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
//!    ([`AdminAuth::issue_challenge`]).
//! 3. Verify a 64-byte Ed25519 signature over that nonce against
//!    every loaded pubkey AND check the matched key's role
//!    allowlist against the operation being authorised
//!    ([`AdminAuth::verify_with_role`]; the legacy
//!    [`AdminAuth::verify_unlock`] is a thin wrapper that requires
//!    [`Role::Unlock`] for backward-compat).
//! 4. On success, mint an [`UnlockToken`] via the capability gate in
//!    `network_isolate.rs`. On invalid-signature failure, increment
//!    a rate-limit counter; three failures inside a 5-minute window
//!    block further challenge issuance. Role-mismatch failures
//!    deliberately do **not** trip the rate limiter — a legitimate
//!    operator using a correctly-signed key with an insufficient
//!    role is a configuration error, not an attack signal.
//!
//! The nonce is single-use — it is consumed inside the verify path
//! regardless of outcome. A failed attempt forces the attacker to
//! request a fresh challenge AND to incur a rate-limit hit.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, Context, Result};
use common::wire::admin_signed_payload::{self, Role, SignedPayload, SignedPayloadError};
use ed25519_dalek::{Signature, VerifyingKey};
use parking_lot::{Mutex, RwLock};
use rand::rngs::OsRng;
use rand::RngCore;
use sha2::{Digest, Sha256};
use thiserror::Error;
use tracing::{info, warn};

use super::network_isolate::{mint_unlock_token, UnlockToken};

/// Production rate-limit window — three failures inside this period
/// pause new challenge issuance until the window slides past the
/// oldest failure.
pub const DEFAULT_RATE_LIMIT_WINDOW: Duration = Duration::from_secs(5 * 60);

/// Failures inside [`DEFAULT_RATE_LIMIT_WINDOW`] that trigger the
/// throttle. Verify itself is NOT rate-limited; only the entrance
/// gate (`issue_challenge`) is.
pub const RATE_LIMIT_THRESHOLD: u32 = 3;

/// Hex length of an Ed25519 pubkey (32 bytes × 2 nibbles).
const PUBKEY_HEX_LEN: usize = 64;

/// Default role allowlist applied to admin.pub lines that omit the
/// role token. `unlock` is the legacy-compat baseline (every key
/// could perform unlock before A5); `audit-read` is the safe
/// read-only complement per design §3.2 ("on-call minimum").
fn default_roles() -> Vec<Role> {
    vec![Role::Unlock, Role::AuditRead]
}

/// Reasons [`AdminAuth::issue_challenge`] / [`AdminAuth::verify_with_role`]
/// can refuse, carrying the user-facing detail needed to translate
/// into an [`UnlockResult`](common::wire::admin_protocol::UnlockResult)
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
    /// `required` field. This error does **not** increment the
    /// rate-limit counter — a quorum shortfall is operator UX
    /// (a co-signer hasn't replied yet), not an attack signal.
    #[error("quorum not met: {provided} distinct valid signatures (need {required})")]
    QuorumNotMet { required: u8, provided: u8 },
    /// Tappa 8 A7: `payload.ts` was outside the server's ±skew
    /// window. Mirrors `AdminResult::TimestampSkew` in the wire
    /// layer. Returned by [`AdminAuth::verify_signed_payload_quorum`]
    /// (and any future SignedPayload-consuming verify path).
    /// Does NOT increment the rate-limit counter — clock skew
    /// is an operator-environment issue, not an attack signal.
    #[error("timestamp outside ±{max_skew_secs}s window (server_ts={server_ts})")]
    TimestampSkew { server_ts: u64, max_skew_secs: u32 },
    /// Tappa 8 A7: `payload.agent_id` did not match the agent's
    /// bootstrapped install UUID — a captured signature was
    /// replayed against a different agent install (design §6.4
    /// layer 3). Rate-limit IS incremented: this can only happen
    /// from a deliberate attack (legitimate clients always read
    /// `agent_id` from the same agent's `status` reply before
    /// signing).
    #[error("agent_id mismatch")]
    AgentIdMismatch,
    /// Tappa 8 A7: `payload.nonce` did not match the outstanding
    /// challenge nonce — a signed-payload submission whose
    /// nonce-binding was forged or stale. Rate-limit IS
    /// incremented; this is an attack signal under the same
    /// rationale as `InvalidSignature`.
    #[error("nonce mismatch")]
    NonceMismatch,
    /// Tappa 8 A7: `payload.op` was not the operation expected
    /// on this wire variant (e.g., a `ShutdownRequest` carrying
    /// `op = Unlock`). Surfaces design §6.6
    /// `AdminResult::UnknownOperation`. Rate-limit IS
    /// incremented — a wire-shape mismatch can only come from a
    /// confused or hostile client.
    #[error("unknown operation: payload.op={got:?} expected {expected:?}")]
    UnknownOperation {
        expected: common::wire::admin_signed_payload::OperationCode,
        got: common::wire::admin_signed_payload::OperationCode,
    },
    /// Tappa 8 A7: signing-payload CBOR / hashing failed during
    /// verify. Wraps the underlying `SignedPayloadError` from
    /// `common::wire::admin_signed_payload`. In practice this
    /// only fires on malformed input that already passed CBOR
    /// decode at the frame layer.
    #[error("signed payload error: {0}")]
    PayloadVerify(#[from] SignedPayloadError),
}

/// One loaded admin pubkey plus its parsed role allowlist. Stored
/// inside [`AdminAuth`]; the type is intentionally crate-private
/// because the only legitimate construction path is
/// [`AdminAuth::load`] (line parser) or the test-only `build`
/// helper (defaults the roles to [`default_roles`]).
#[derive(Debug, Clone)]
struct KeyEntry {
    key: VerifyingKey,
    roles: Vec<Role>,
}

impl KeyEntry {
    /// `true` iff the key may authorise an operation whose required
    /// role is `required`. [`Role::All`] is the break-glass
    /// super-role and unconditionally satisfies any required role
    /// (design §3.2 "break-glass key (kept offline)" pattern).
    fn authorizes(&self, required: Role) -> bool {
        self.roles.iter().any(|r| *r == required || *r == Role::All)
    }
}

/// Server-side admin authenticator.
///
/// `pub_keys` is read-only after construction so we never need a
/// lock for verification — only the nonce slot, the failure counter,
/// and the last-failure timestamp are mutable. Each entry pairs a
/// verifying key with the operations its operator is authorised to
/// trigger ([`Role`] enum from [`common::wire::admin_signed_payload`]).
///
/// The `rate_limit_window` field is the one deviation from the
/// spec's struct layout: tests need to override the 5-minute
/// production window with something like 100 ms to run in a sane
/// amount of time. Production callers use [`AdminAuth::load`]
/// which pins the field to [`DEFAULT_RATE_LIMIT_WINDOW`].
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
    pending_challenge: Mutex<Option<[u8; 32]>>,
    failure_count: AtomicU32,
    last_failure: Mutex<Option<Instant>>,
    rate_limit_window: Duration,
    /// Per-install agent identity (Tappa 8 A3). Bootstrapped by
    /// [`crate::agent_id::load_or_bootstrap`] and passed in via
    /// [`Self::load_with_agent_id`]. The legacy [`Self::load`]
    /// defaults to `[0u8; 16]` for backward compatibility — that
    /// matters only for the new
    /// [`Self::verify_signed_payload_quorum`] path; the legacy
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
    /// ([`Self::verify_signed_payload_quorum`]) compares incoming
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

        let mut pub_keys = Vec::new();
        for (idx, raw) in content.lines().enumerate() {
            let line_no = idx + 1;
            let line = raw.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let entry = parse_admin_line(line)
                .map_err(|e| anyhow!("{}:{}: {e}", config_path.display(), line_no))?;
            pub_keys.push(entry);
        }

        if pub_keys.is_empty() {
            return Err(anyhow!(
                "{}: no admin pub keys found (need at least one)",
                config_path.display()
            ));
        }

        let mut auth =
            Self::build_entries_with_agent_id(pub_keys, DEFAULT_RATE_LIMIT_WINDOW, agent_id);
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
        let mut new_keys = Vec::new();
        for (idx, raw) in content.lines().enumerate() {
            let line_no = idx + 1;
            let line = raw.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let entry = parse_admin_line(line)
                .map_err(|e| anyhow!("{}:{}: {e}", config_path.display(), line_no))?;
            new_keys.push(entry);
        }
        if new_keys.is_empty() {
            return Err(anyhow!(
                "{}: refusing to reload an empty admin.pub (would soft-brick the agent)",
                config_path.display()
            ));
        }
        *self.pub_keys.write() = new_keys;
        Ok(())
    }

    /// Test-only: snapshot the current in-memory key fingerprints.
    /// Lets reload tests assert "after reload, the new key is
    /// present" without exposing `KeyEntry` to test code.
    #[cfg(test)]
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
    fn build(pub_keys: Vec<VerifyingKey>, rate_limit_window: Duration) -> Self {
        let entries = pub_keys
            .into_iter()
            .map(|key| KeyEntry {
                key,
                roles: default_roles(),
            })
            .collect();
        Self::build_entries(entries, rate_limit_window)
    }

    /// Lower-level builder used by tests that want to pin custom
    /// role allowlists per key without going through admin.pub
    /// parsing. Defaults `agent_id` to `[0u8; 16]` — call
    /// [`Self::build_entries_with_agent_id`] to bind a specific
    /// UUID (only matters for `verify_signed_payload_quorum`).
    /// Production callers go through [`Self::load_with_agent_id`].
    #[cfg(test)]
    fn build_entries(pub_keys: Vec<KeyEntry>, rate_limit_window: Duration) -> Self {
        Self::build_entries_with_agent_id(pub_keys, rate_limit_window, [0u8; 16])
    }

    /// Lowest-level builder, used by [`Self::load_with_agent_id`].
    fn build_entries_with_agent_id(
        pub_keys: Vec<KeyEntry>,
        rate_limit_window: Duration,
        agent_id: [u8; 16],
    ) -> Self {
        Self {
            pub_keys: RwLock::new(pub_keys),
            pending_challenge: Mutex::new(None),
            failure_count: AtomicU32::new(0),
            last_failure: Mutex::new(None),
            rate_limit_window,
            agent_id,
            config_path: None,
        }
    }

    /// Test-only constructor that overrides the rate-limit window so
    /// the failure-window tests don't have to wait five minutes.
    #[cfg(test)]
    fn new_with_window(pub_keys: Vec<VerifyingKey>, window: Duration) -> Self {
        Self::build(pub_keys, window)
    }

    /// Mint a 32-byte challenge from OS entropy and store it as the
    /// outstanding nonce. Fails fast if the rate limiter is currently
    /// throttling — the caller should propagate `RateLimited` to the
    /// admin so they back off, not silently issue an unsignable nonce.
    pub fn issue_challenge(&self) -> std::result::Result<[u8; 32], AdminAuthError> {
        if let Some(retry_after_secs) = self.check_rate_limit() {
            warn!(
                target: "anti_tamper.admin_auth.verify_failure",
                reason = "rate_limited",
                retry_after_secs,
                "admin challenge issuance rate-limited"
            );
            return Err(AdminAuthError::RateLimited { retry_after_secs });
        }

        let mut nonce = [0u8; 32];
        // `OsRng` is deliberately preferred over `rand::thread_rng()`
        // here — for security primitives we want the OS CSPRNG
        // directly, not a userland-cached source.
        OsRng.fill_bytes(&mut nonce);
        *self.pending_challenge.lock() = Some(nonce);
        info!(
            target: "anti_tamper.admin_auth.challenge_issued",
            "admin challenge issued (32-byte nonce)"
        );
        Ok(nonce)
    }

    /// Verify `signature` against the outstanding nonce, requiring
    /// the matched key to authorise [`Role::Unlock`]. Thin wrapper
    /// over [`Self::verify_with_role`]; preserved as a separate
    /// method so the legacy COMBAT-release call path (admin_socket
    /// dispatcher, pre-A7) compiles unchanged.
    ///
    /// Every admin.pub line — including pubkey-only lines from
    /// before A5 — has [`Role::Unlock`] in its allowlist by
    /// default, so this method's behaviour is byte-identical to
    /// the pre-A5 implementation for every legacy admin.pub.
    pub fn verify_unlock(
        &self,
        signature: &[u8; 64],
    ) -> std::result::Result<UnlockToken, AdminAuthError> {
        self.verify_with_role(signature, Role::Unlock)
    }

    /// Verify `signature` against the outstanding nonce AND check
    /// that the matched key's role allowlist includes
    /// `required_role` (or [`Role::All`], the break-glass
    /// super-role). On success, mint an [`UnlockToken`]; on
    /// invalid-signature failure, increment the rate-limit
    /// counter; on role-mismatch, return [`AdminAuthError::RoleDenied`]
    /// **without** incrementing rate limit (legit operator picked
    /// the wrong key, not an attack signal).
    ///
    /// The nonce is consumed unconditionally — even a failed
    /// verify invalidates it. That forces an attacker who guessed
    /// wrong to roundtrip another challenge AND eat a rate-limit
    /// hit.
    ///
    /// Constant-time iteration is preserved across the per-key
    /// signature scan: the loop does NOT short-circuit on the
    /// first match, so per-attempt cost depends on the number of
    /// installed keys but not on which key matched (or whether
    /// any matched at all). Role lookup happens once after the
    /// loop on the matched index — that's an O(1) check on a
    /// short Vec, no side-channel relative to key position.
    pub fn verify_with_role(
        &self,
        signature: &[u8; 64],
        required_role: Role,
    ) -> std::result::Result<UnlockToken, AdminAuthError> {
        let nonce = match self.pending_challenge.lock().take() {
            Some(n) => n,
            None => {
                warn!(
                    target: "anti_tamper.admin_auth.verify_failure",
                    reason = "no_pending_challenge",
                    "admin verify with no outstanding challenge"
                );
                return Err(AdminAuthError::NoPendingChallenge);
            }
        };

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
            if entry.key.verify_strict(&nonce, &sig).is_ok() {
                matched_idx = Some(idx);
                // intentionally NOT `break` — preserve constant-time iteration
            }
        }

        match matched_idx {
            Some(idx) => {
                let entry = &pub_keys[idx];
                if entry.authorizes(required_role) {
                    self.failure_count.store(0, Ordering::SeqCst);
                    *self.last_failure.lock() = None;
                    info!(
                        target: "anti_tamper.admin_auth.verify_success",
                        key_fingerprint = %fingerprint(&entry.key),
                        required_role = ?required_role,
                        "admin signature verified, unlock token minted"
                    );
                    Ok(mint_unlock_token())
                } else {
                    // Role mismatch — do NOT increment failure
                    // counter. A correctly-signed but
                    // under-privileged request is a config
                    // mistake by a legitimate operator, not an
                    // attack signal; counting it would lock the
                    // operator out under rate-limit.
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
                self.failure_count.fetch_add(1, Ordering::SeqCst);
                *self.last_failure.lock() = Some(Instant::now());
                warn!(
                    target: "anti_tamper.admin_auth.verify_failure",
                    reason = "invalid_sig",
                    "admin signature verification failed"
                );
                Err(AdminAuthError::InvalidSignature)
            }
        }
    }

    /// Verify a multi-signature **quorum** submission against the
    /// outstanding nonce. Each signature in `signatures` is verified
    /// independently; the agent tallies **distinct** matched pubkey
    /// indices (per design §3.3, two signatures from the same key
    /// count as one) and accepts the submission iff:
    /// - at least `min_distinct` distinct keys verified, AND
    /// - each role in `role_requirements` is carried by at least
    ///   one of the matched keys ([`Role::All`] satisfies any
    ///   required role).
    ///
    /// Failure-mode mapping (matches the design §6.6 wire variants
    /// A7 will introduce):
    /// - `signatures.is_empty()` OR `0 < matched < min_distinct`
    ///   → [`AdminAuthError::QuorumNotMet`] (no rate-limit hit —
    ///   a quorum shortfall is operator UX, not an attack signal).
    /// - non-empty `signatures` with zero valid matches →
    ///   [`AdminAuthError::InvalidSignature`] (rate-limit hit —
    ///   the only way to land here is to submit signatures that
    ///   verify under no loaded pubkey, which is an attack
    ///   indicator).
    /// - `min_distinct` keys matched but no matched key carries a
    ///   required role → [`AdminAuthError::RoleDenied`]
    ///   (no rate-limit hit — same rationale as A5).
    /// - all checks pass → [`UnlockToken`] is minted; the nonce
    ///   was consumed at the top of this method (single-use,
    ///   regardless of outcome).
    ///
    /// **Constant-time iteration property:** for each submitted
    /// signature, the inner per-key loop does NOT short-circuit on
    /// match (same property as [`Self::verify_with_role`]). The
    /// outer per-signature loop iterates every submitted signature
    /// regardless of how many have already matched — so the total
    /// verification cost is `O(signatures × pub_keys)` regardless
    /// of which sigs verify or in which order.
    ///
    /// **Forward note (A7):** signatures here are over the raw
    /// 32-byte outstanding nonce, mirroring [`Self::verify_with_role`].
    /// A7 will introduce wire variants (`ShutdownRequest`, etc.)
    /// that carry a [`SignedPayload`](common::wire::admin_signed_payload::SignedPayload)
    /// and signatures over its
    /// [`signing_digest`](common::wire::admin_signed_payload::signing_digest);
    /// the quorum-verify machinery here stays unchanged — only the
    /// caller-supplied "message to verify against" swaps from
    /// `nonce[..]` to `signing_digest(payload)[..]`. That refactor
    /// can be a pure parameter swap because both shapes produce a
    /// fixed-size byte slice over which `verify_strict` operates.
    pub fn verify_quorum(
        &self,
        signatures: &[[u8; 64]],
        min_distinct: u8,
        role_requirements: &[Role],
    ) -> std::result::Result<UnlockToken, AdminAuthError> {
        debug_assert!(
            min_distinct >= 1,
            "verify_quorum: min_distinct must be >= 1 (got {min_distinct}); \
             0 would mint a token with no signature"
        );

        let nonce = match self.pending_challenge.lock().take() {
            Some(n) => n,
            None => {
                warn!(
                    target: "anti_tamper.admin_auth.verify_failure",
                    reason = "no_pending_challenge",
                    "admin quorum verify with no outstanding challenge"
                );
                return Err(AdminAuthError::NoPendingChallenge);
            }
        };

        // A13: snapshot the keys behind a read lock for the
        // duration of the verify; see verify_with_role for the
        // rationale.
        let pub_keys = self.pub_keys.read();

        // Tally distinct matched pubkey indices across every
        // submitted signature.
        let mut matched: Vec<usize> = Vec::new();
        for sig_bytes in signatures {
            let sig = Signature::from_bytes(sig_bytes);
            let mut this_match: Option<usize> = None;
            for (idx, entry) in pub_keys.iter().enumerate() {
                if entry.key.verify_strict(&nonce, &sig).is_ok() {
                    this_match = Some(idx);
                    // intentionally no break — preserve constant-time
                }
            }
            if let Some(idx) = this_match {
                if !matched.contains(&idx) {
                    matched.push(idx);
                }
            }
        }

        // Zero matches + non-empty submission = attack signal. Zero
        // matches + empty submission = operator UX (no rate-limit).
        if matched.is_empty() && !signatures.is_empty() {
            self.failure_count.fetch_add(1, Ordering::SeqCst);
            *self.last_failure.lock() = Some(Instant::now());
            warn!(
                target: "anti_tamper.admin_auth.verify_failure",
                reason = "invalid_sig",
                submitted = signatures.len(),
                "admin quorum verify: zero valid signatures in non-empty submission"
            );
            return Err(AdminAuthError::InvalidSignature);
        }

        // Cap at u8::MAX — a realistic admin install ships with
        // single-digit admin keys, so this saturating cast never
        // bites in practice.
        let distinct: u8 = matched.len().min(u8::MAX as usize) as u8;
        if distinct < min_distinct {
            warn!(
                target: "anti_tamper.admin_auth.verify_failure",
                reason = "quorum_not_met",
                required = min_distinct,
                provided = distinct,
                "admin quorum verify: insufficient distinct valid signatures"
            );
            return Err(AdminAuthError::QuorumNotMet {
                required: min_distinct,
                provided: distinct,
            });
        }

        // Role check: every required role must be carried by AT
        // LEAST ONE matched key. Order of role_requirements is
        // irrelevant — the loop short-circuits on the first
        // missing role and returns its fingerprint; tests assert
        // this is the FIRST missing role, locked semantics.
        for &required in role_requirements {
            let satisfied = matched
                .iter()
                .any(|&idx| pub_keys[idx].authorizes(required));
            if !satisfied {
                // Surface the first matched key's fingerprint —
                // it's the most useful audit-log breadcrumb when
                // the operator sees "RoleDenied: which key?"
                let fp = fingerprint(&pub_keys[matched[0]].key);
                warn!(
                    target: "anti_tamper.admin_auth.verify_failure",
                    reason = "role_denied",
                    required_role = ?required,
                    matched_count = distinct,
                    first_matched_fingerprint = %fp,
                    "admin quorum verify: required role not carried by any matched key"
                );
                return Err(AdminAuthError::RoleDenied {
                    key_fingerprint: fp,
                    required_role: required,
                });
            }
        }

        // All checks pass — mint the token. Reset failure state on
        // success (consistent with verify_with_role).
        self.failure_count.store(0, Ordering::SeqCst);
        *self.last_failure.lock() = None;
        info!(
            target: "anti_tamper.admin_auth.verify_success",
            distinct,
            required = min_distinct,
            role_count = role_requirements.len(),
            "admin quorum verified, unlock token minted"
        );
        Ok(mint_unlock_token())
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
    /// The outstanding nonce is consumed at the top of this
    /// method (single-use, regardless of outcome) AND
    /// `payload.nonce` must equal that nonce — same nonce-binding
    /// the legacy [`Self::verify_unlock`] enforces, surfaced as
    /// `NonceMismatch` for the SignedPayload path.
    ///
    /// Failure-mode summary (matching design §6.6 wire variants):
    /// - `NoPendingChallenge` → no challenge has been issued.
    /// - `NonceMismatch` → payload nonce ≠ outstanding nonce
    ///   (rate-limit++ — attack signal).
    /// - `UnknownOperation` → `payload.op` is not the expected
    ///   one for this wire variant (rate-limit++).
    /// - `AgentIdMismatch` → `payload.agent_id` ≠ `self.agent_id`
    ///   (rate-limit++).
    /// - `TimestampSkew` → outside ±60 s window (no rate-limit —
    ///   operator-clock issue).
    /// - `QuorumNotMet` → fewer distinct valid signatures than
    ///   `min_distinct` (no rate-limit — operator UX).
    /// - `InvalidSignature` → zero valid matches in non-empty
    ///   submission (rate-limit++).
    /// - `RoleDenied` → matched keys are short of a required
    ///   role (no rate-limit).
    /// - Success → mint `UnlockToken`.
    ///
    /// Caller pattern (production dispatcher, A7):
    /// ```ignore
    /// let now = SystemClock.now_unix_secs();
    /// auth.verify_signed_payload_quorum(
    ///     &req.payload,
    ///     &sigs,
    ///     2,                        // shutdown quorum
    ///     &[Role::Shutdown],        // §3.3 role requirement
    ///     OperationCode::Shutdown,  // expected op
    ///     now,
    /// )?;
    /// ```
    /// PHASE_D_004: the success arm returns `(UnlockToken,
    /// Vec<String>)` where the `Vec` is the 8-hex-char
    /// fingerprints of every matched key, primary first by index
    /// order in `admin.pub`. The dispatch layer threads these
    /// into the audit log's `key_fp` / `cosigner_fps` fields so
    /// the chain records WHICH operator(s) authorised each
    /// signed action.
    pub fn verify_signed_payload_quorum(
        &self,
        payload: &SignedPayload,
        signatures: &[[u8; 64]],
        min_distinct: u8,
        role_requirements: &[Role],
        expected_op: admin_signed_payload::OperationCode,
        server_now_unix_secs: u64,
    ) -> std::result::Result<(UnlockToken, Vec<String>), AdminAuthError> {
        debug_assert!(
            min_distinct >= 1,
            "verify_signed_payload_quorum: min_distinct must be >= 1 \
             (got {min_distinct}); 0 would mint a token with no signature"
        );

        // Consume the outstanding nonce up front (single-use,
        // regardless of subsequent failure). Mirrors verify_quorum.
        let nonce = match self.pending_challenge.lock().take() {
            Some(n) => n,
            None => {
                warn!(
                    target: "anti_tamper.admin_auth.verify_failure",
                    reason = "no_pending_challenge",
                    "signed-payload quorum verify with no outstanding challenge"
                );
                return Err(AdminAuthError::NoPendingChallenge);
            }
        };

        // Operation tag must match what this wire variant expects.
        // Cheap field check first — surfaces a clear "wrong wire
        // shape" error before we burn an Ed25519 verify on it.
        if payload.op != expected_op {
            self.failure_count.fetch_add(1, Ordering::SeqCst);
            *self.last_failure.lock() = Some(Instant::now());
            warn!(
                target: "anti_tamper.admin_auth.verify_failure",
                reason = "unknown_operation",
                expected = ?expected_op,
                got = ?payload.op,
                "signed-payload op tag mismatch"
            );
            return Err(AdminAuthError::UnknownOperation {
                expected: expected_op,
                got: payload.op,
            });
        }

        // Nonce binding: payload must reference THE nonce the
        // server issued. A forged payload that names some other
        // nonce can't replay an old signature here.
        if payload.nonce != nonce {
            self.failure_count.fetch_add(1, Ordering::SeqCst);
            *self.last_failure.lock() = Some(Instant::now());
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
            self.failure_count.fetch_add(1, Ordering::SeqCst);
            *self.last_failure.lock() = Some(Instant::now());
            warn!(
                target: "anti_tamper.admin_auth.verify_failure",
                reason = "agent_id_mismatch",
                "signed-payload agent_id does not match this agent install"
            );
            return Err(AdminAuthError::AgentIdMismatch);
        }

        // Timestamp skew (design §6.4 layer 2). Pure predicate
        // from A4 — no rate-limit increment on failure (operator
        // clock issue, not attack).
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

        // Per-signature constant-time scan, distinct-key tally
        // (same machinery as verify_quorum, except the message
        // bytes are the SignedPayload digest instead of the raw
        // nonce — that's the parameter swap A6's forward note
        // promised).
        let mut matched: Vec<usize> = Vec::new();
        for sig_bytes in signatures {
            let sig = Signature::from_bytes(sig_bytes);
            let mut this_match: Option<usize> = None;
            for (idx, entry) in pub_keys.iter().enumerate() {
                if entry.key.verify_strict(&digest, &sig).is_ok() {
                    this_match = Some(idx);
                    // intentionally no break — constant-time
                }
            }
            if let Some(idx) = this_match {
                if !matched.contains(&idx) {
                    matched.push(idx);
                }
            }
        }

        // Zero matches + non-empty submission = attack signal.
        if matched.is_empty() && !signatures.is_empty() {
            self.failure_count.fetch_add(1, Ordering::SeqCst);
            *self.last_failure.lock() = Some(Instant::now());
            warn!(
                target: "anti_tamper.admin_auth.verify_failure",
                reason = "invalid_sig",
                submitted = signatures.len(),
                "signed-payload quorum verify: zero valid signatures"
            );
            return Err(AdminAuthError::InvalidSignature);
        }

        let distinct: u8 = matched.len().min(u8::MAX as usize) as u8;
        if distinct < min_distinct {
            warn!(
                target: "anti_tamper.admin_auth.verify_failure",
                reason = "quorum_not_met",
                required = min_distinct,
                provided = distinct,
                "signed-payload quorum verify: insufficient distinct valid signatures"
            );
            return Err(AdminAuthError::QuorumNotMet {
                required: min_distinct,
                provided: distinct,
            });
        }

        // Role check (same as verify_quorum).
        for &required in role_requirements {
            let satisfied = matched
                .iter()
                .any(|&idx| pub_keys[idx].authorizes(required));
            if !satisfied {
                let fp = fingerprint(&pub_keys[matched[0]].key);
                warn!(
                    target: "anti_tamper.admin_auth.verify_failure",
                    reason = "role_denied",
                    required_role = ?required,
                    matched_count = distinct,
                    first_matched_fingerprint = %fp,
                    "signed-payload quorum verify: required role not carried by any matched key"
                );
                return Err(AdminAuthError::RoleDenied {
                    key_fingerprint: fp,
                    required_role: required,
                });
            }
        }

        // All checks pass.
        self.failure_count.store(0, Ordering::SeqCst);
        *self.last_failure.lock() = None;
        // PHASE_D_004: collect the matched-key fingerprints (in
        // matched-order, which is admin.pub index-order via the
        // per-sig scan above) for the audit log.
        let matched_fps: Vec<String> = matched
            .iter()
            .map(|&idx| fingerprint(&pub_keys[idx].key))
            .collect();
        info!(
            target: "anti_tamper.admin_auth.verify_success",
            op = ?expected_op,
            distinct,
            required = min_distinct,
            role_count = role_requirements.len(),
            "signed-payload quorum verified, unlock token minted"
        );
        Ok((mint_unlock_token(), matched_fps))
    }

    /// Inspect rate-limit state and reset the counter when the
    /// window has slid past the most recent failure. Returns
    /// `Some(retry_after_secs)` if currently throttled, `None`
    /// otherwise.
    fn check_rate_limit(&self) -> Option<u32> {
        let now = Instant::now();
        let mut last = self.last_failure.lock();
        match *last {
            None => None,
            Some(t) if now.saturating_duration_since(t) >= self.rate_limit_window => {
                // Window elapsed — clear state, fresh start.
                self.failure_count.store(0, Ordering::SeqCst);
                *last = None;
                None
            }
            Some(t) if self.failure_count.load(Ordering::SeqCst) >= RATE_LIMIT_THRESHOLD => {
                let elapsed = now.saturating_duration_since(t);
                let remaining = self.rate_limit_window.saturating_sub(elapsed);
                // +1 so we never advertise "retry in 0s" while still throttled.
                Some(remaining.as_secs() as u32 + 1)
            }
            Some(_) => None,
        }
    }
}

// ────────────────────────────────────────────────────────────────────
// Tappa 8 sub-sprint A commit A5 — admin.pub role allowlist parser
// (§3.2). Helpers consumed by AdminAuth::load above.
// ────────────────────────────────────────────────────────────────────

/// Parse one already-trimmed, non-comment, non-blank admin.pub
/// line into a [`KeyEntry`]. Whitespace-tokenised: the first token
/// is the hex pubkey, the optional second token is the
/// comma-separated role list. A third+ token is an error (catches
/// the common operator mistake of forgetting the comma between
/// roles, e.g. `<hex>  unlock audit-read`).
fn parse_admin_line(line: &str) -> Result<KeyEntry> {
    let mut parts = line.split_whitespace();
    let hex_token = parts.next().ok_or_else(|| {
        // split_whitespace on a non-empty trimmed input always
        // yields at least one item, so this is structurally
        // unreachable; we name the error anyway because
        // unwrap()-in-the-load-loop would be a worse failure mode.
        anyhow!("line is empty after trimming (should have been skipped)")
    })?;
    if hex_token.len() != PUBKEY_HEX_LEN {
        return Err(anyhow!(
            "pub key must be {PUBKEY_HEX_LEN} hex chars (got {})",
            hex_token.len()
        ));
    }
    let raw_bytes = hex::decode(hex_token).map_err(|e| anyhow!("invalid hex: {e}"))?;
    let key_bytes: [u8; 32] = raw_bytes
        .try_into()
        .expect("hex decode length pre-validated to 64 chars");
    let key = VerifyingKey::from_bytes(&key_bytes)
        .map_err(|e| anyhow!("not a valid Ed25519 pubkey: {e}"))?;

    let roles = match parts.next() {
        None => default_roles(),
        Some(role_list) => parse_role_list(role_list)?,
    };
    if parts.next().is_some() {
        return Err(anyhow!(
            "unexpected token after role list — roles must be \
             comma-separated within a single token (no spaces)"
        ));
    }
    Ok(KeyEntry { key, roles })
}

/// Parse a comma-separated role list (e.g. `"unlock,audit-read"`)
/// into a [`Vec<Role>`]. Empty list / single trailing comma / leading
/// comma are all errors — the canonical writer emits a tight list.
/// Duplicate roles inside the list are deduped before returning via
/// linear scan (the list is at most 6 elements long, smaller than
/// any reasonable hash table overhead).
fn parse_role_list(s: &str) -> Result<Vec<Role>> {
    if s.is_empty() {
        return Err(anyhow!("role list is empty"));
    }
    let mut out: Vec<Role> = Vec::new();
    for token in s.split(',') {
        if token.is_empty() {
            return Err(anyhow!(
                "role list has empty entry (leading/trailing/double comma)"
            ));
        }
        let role = parse_role_keyword(token)?;
        if !out.contains(&role) {
            out.push(role);
        }
    }
    Ok(out)
}

/// Map one role keyword to its [`Role`]. Keywords mirror the
/// design §3.2 list verbatim — case-sensitive lowercase. The
/// `all` keyword maps to [`Role::All`], which authorises every
/// operation (break-glass).
///
/// Tappa 9 (C1) added the `fim-read` / `fim-manage` keywords;
/// Tappa 9.5 (K1) added `canary-read` / `canary-manage` per
/// design §12 Q7 split-role lock-in. The list MUST stay in
/// sync with [`role_keyword`] (the emit-side helper) — the
/// `load_parses_every_role_keyword_in_design_spec_3_2` test
/// anchors that invariant.
fn parse_role_keyword(s: &str) -> Result<Role> {
    match s {
        "unlock" => Ok(Role::Unlock),
        "shutdown" => Ok(Role::Shutdown),
        "force-posture" => Ok(Role::ForcePosture),
        "rotate-keys" => Ok(Role::RotateKeys),
        "audit-read" => Ok(Role::AuditRead),
        "fim-manage" => Ok(Role::FimManage),
        "fim-read" => Ok(Role::FimRead),
        "canary-read" => Ok(Role::CanaryRead),
        "canary-manage" => Ok(Role::CanaryManage),
        "all" => Ok(Role::All),
        other => Err(anyhow!(
            "unknown role `{other}` — expected one of: \
             unlock, shutdown, force-posture, rotate-keys, audit-read, \
             fim-manage, fim-read, canary-read, canary-manage, all"
        )),
    }
}

/// 8-hex-char pubkey fingerprint: first 4 bytes of SHA-256 over the
/// raw pubkey. Same convention as `nn-admin verify-keys` output and
/// `admin_cli::pubkey_fingerprint` — duplicated here rather than
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
/// each variant to the right [`common::wire::admin_protocol::AdminResult`]
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
    /// The fingerprint requested by `rotate-keys revoke`
    /// doesn't match any line in `admin.pub`.
    #[error("no admin.pub line matches fingerprint {fingerprint}")]
    KeyNotFound { fingerprint: String },
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
pub fn atomic_rewrite_admin_pub_add(
    config_path: &Path,
    new_pubkey: &VerifyingKey,
    roles: &[Role],
) -> std::result::Result<(), RotateKeysError> {
    let body = std::fs::read_to_string(config_path).map_err(RotateKeysError::Io)?;
    let new_fp = fingerprint(new_pubkey);
    for raw in body.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Ok(entry) = parse_admin_line(line) {
            if fingerprint(&entry.key) == new_fp {
                return Err(RotateKeysError::KeyAlreadyPresent {
                    fingerprint: new_fp,
                });
            }
        }
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
pub fn atomic_rewrite_admin_pub_revoke(
    config_path: &Path,
    target_fp: [u8; 4],
) -> std::result::Result<(), RotateKeysError> {
    let body = std::fs::read_to_string(config_path).map_err(RotateKeysError::Io)?;
    let target_hex = hex::encode(target_fp);
    let mut out = String::new();
    let mut kept_keys = 0usize;
    let mut removed = false;
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
                removed = true;
                continue;
            }
            kept_keys += 1;
        }
        out.push_str(raw);
        out.push('\n');
    }
    if !removed {
        return Err(RotateKeysError::KeyNotFound {
            fingerprint: target_hex,
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

fn role_keyword(r: Role) -> &'static str {
    match r {
        Role::Unlock => "unlock",
        Role::Shutdown => "shutdown",
        Role::ForcePosture => "force-posture",
        Role::RotateKeys => "rotate-keys",
        Role::AuditRead => "audit-read",
        // Tappa 9 (C1) additions — same wire-byte keyword
        // shape operators see in admin.pub lines + CLI.
        Role::FimManage => "fim-manage",
        Role::FimRead => "fim-read",
        // Tappa 9.5 (K1) — design §12 Q7 split-role lock-in.
        Role::CanaryRead => "canary-read",
        Role::CanaryManage => "canary-manage",
        Role::All => "all",
    }
}

fn write_admin_pub_atomically(config_path: &Path, body: &str) -> std::io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut tmp = config_path.as_os_str().to_owned();
    tmp.push(".tmp");
    let tmp_path = PathBuf::from(tmp);
    {
        // 0644 matches the pre-rotation admin.pub layout (design
        // §6.5 / §8.1: world-readable so non-root admin tools can
        // inspect, root-only writable).
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o644)
            .open(&tmp_path)?;
        f.write_all(body.as_bytes())?;
        f.sync_all()?;
    }
    std::fs::rename(&tmp_path, config_path)
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
/// ```ignore
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
    fn load_rejects_malformed_line_with_line_number() {
        let (_, vk) = make_keypair();
        let good = hex::encode(vk.to_bytes());
        // Comment + good + bad on line 3
        let f = write_config(&["# header", &good, "not-hex-at-all-zz"]);
        let err = AdminAuth::load(f.path()).unwrap_err();
        let s = err.to_string();
        assert!(s.contains(":3:"), "expected line 3 in error, got: {s}");
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
        let auth = AdminAuth::build(vec![vk], DEFAULT_RATE_LIMIT_WINDOW);
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
        let auth = AdminAuth::build(vec![vk], DEFAULT_RATE_LIMIT_WINDOW);
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
        let auth = AdminAuth::build(vec![vk], DEFAULT_RATE_LIMIT_WINDOW);
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
        let auth = AdminAuth::build(vec![vk], DEFAULT_RATE_LIMIT_WINDOW);
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
        let auth = AdminAuth::build(vec![vk], DEFAULT_RATE_LIMIT_WINDOW);
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
        let auth = AdminAuth::build(vec![vk], DEFAULT_RATE_LIMIT_WINDOW);
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
        let auth = AdminAuth::build(vec![k1, k2, k3], DEFAULT_RATE_LIMIT_WINDOW);
        let nonce = auth.issue_challenge().unwrap();
        let sig: [u8; 64] = s3.sign(&nonce).to_bytes();
        let _ = auth.verify_unlock(&sig).expect("third key should verify");
    }

    // ── rate limit ─────────────────────────────────────────────────

    #[test]
    fn rate_limit_triggers_after_3_failures() {
        let (_, vk) = make_keypair();
        let (other, _) = make_keypair();
        let auth = AdminAuth::new_with_window(vec![vk], Duration::from_secs(5 * 60));

        for _ in 0..RATE_LIMIT_THRESHOLD {
            let nonce = auth.issue_challenge().unwrap();
            let bad: [u8; 64] = other.sign(&nonce).to_bytes();
            assert!(auth.verify_unlock(&bad).is_err());
        }

        // 4th challenge attempt must hit the gate.
        let err = auth.issue_challenge().unwrap_err();
        match err {
            AdminAuthError::RateLimited { retry_after_secs } => {
                assert!(retry_after_secs > 0, "retry_after must be positive");
                assert!(
                    retry_after_secs <= 5 * 60 + 1,
                    "retry_after must not exceed window+1: {retry_after_secs}"
                );
            }
            other => panic!("expected RateLimited, got {other:?}"),
        }
    }

    #[test]
    fn rate_limit_resets_after_window() {
        let (_, vk) = make_keypair();
        let (other, _) = make_keypair();
        // 100 ms window so the test runs in ~150 ms total.
        let window = Duration::from_millis(100);
        let auth = AdminAuth::new_with_window(vec![vk], window);

        for _ in 0..RATE_LIMIT_THRESHOLD {
            let nonce = auth.issue_challenge().unwrap();
            let bad: [u8; 64] = other.sign(&nonce).to_bytes();
            let _ = auth.verify_unlock(&bad);
        }
        // Throttled.
        assert!(matches!(
            auth.issue_challenge(),
            Err(AdminAuthError::RateLimited { .. })
        ));

        // Wait past the window.
        std::thread::sleep(window + Duration::from_millis(20));

        // Counter has slid past; a fresh challenge issues.
        assert!(auth.issue_challenge().is_ok());
    }

    #[test]
    fn rate_limit_counter_resets_on_successful_verify() {
        let (signing, vk) = make_keypair();
        let (other, _) = make_keypair();
        let auth = AdminAuth::new_with_window(vec![vk], Duration::from_secs(5 * 60));

        // Two failures — under threshold.
        for _ in 0..2 {
            let nonce = auth.issue_challenge().unwrap();
            let bad: [u8; 64] = other.sign(&nonce).to_bytes();
            let _ = auth.verify_unlock(&bad);
        }
        // Successful verify resets the counter.
        let nonce = auth.issue_challenge().unwrap();
        let good: [u8; 64] = signing.sign(&nonce).to_bytes();
        let _ = auth.verify_unlock(&good).expect("verify");

        // Three more failures from a clean slate — still allowed
        // (i.e., the counter really did reset; otherwise we'd hit
        // the gate after just one more).
        for _ in 0..2 {
            let nonce = auth.issue_challenge().unwrap();
            let bad: [u8; 64] = other.sign(&nonce).to_bytes();
            let _ = auth.verify_unlock(&bad);
        }
        // 3rd failure trips the gate, but 1+2 should not.
        assert!(auth.issue_challenge().is_ok());
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
        let auth = AdminAuth::build(vec![vk], DEFAULT_RATE_LIMIT_WINDOW);
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
        let auth = AdminAuth::build(vec![vk], DEFAULT_RATE_LIMIT_WINDOW);
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
            auth.failure_count.load(Ordering::SeqCst),
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
        let auth = AdminAuth::build_entries(vec![entry], DEFAULT_RATE_LIMIT_WINDOW);
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

    /// The pre-A5 [`AdminAuth::verify_unlock`] entry point is now
    /// a wrapper around `verify_with_role(sig, Role::Unlock)` and
    /// behaves byte-identically for every legacy admin.pub line
    /// (default roles include Unlock). Anchor for the backward-
    /// compat guarantee called out in `verify_unlock`'s doc-comment.
    #[test]
    fn verify_unlock_is_backward_compatible_with_pre_a5_admin_pub() {
        let (signing, vk) = make_keypair();
        let auth = AdminAuth::build(vec![vk], DEFAULT_RATE_LIMIT_WINDOW);
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
        let auth = AdminAuth::build_entries(entries, DEFAULT_RATE_LIMIT_WINDOW);
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
            auth.failure_count.load(Ordering::SeqCst),
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
        assert_eq!(auth.failure_count.load(Ordering::SeqCst), 0);
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
        assert_eq!(auth.failure_count.load(Ordering::SeqCst), 0);
    }

    // ── Supplementary A6 tests ─────────────────────────────────────

    /// A non-empty submission whose every signature is garbage
    /// IS an attack signal — InvalidSignature surfaces and the
    /// rate-limit counter increments.
    #[test]
    fn verify_quorum_all_garbage_signatures_trips_rate_limit() {
        let (auth, _) = build_auth_with_keyed_roles(&[vec![Role::Shutdown]]);
        let _nonce = auth.issue_challenge().unwrap();
        let sigs = [[0u8; 64], [1u8; 64]];
        match auth.verify_quorum(&sigs, 1, &[]) {
            Err(AdminAuthError::InvalidSignature) => {}
            other => panic!("expected InvalidSignature, got {other:?}"),
        }
        assert_eq!(
            auth.failure_count.load(Ordering::SeqCst),
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
        let _nonce = auth.issue_challenge().unwrap();
        match auth.verify_quorum(&[], 2, &[Role::Shutdown]) {
            Err(AdminAuthError::QuorumNotMet { required, provided }) => {
                assert_eq!(required, 2);
                assert_eq!(provided, 0);
            }
            other => panic!("expected QuorumNotMet{{2,0}}, got {other:?}"),
        }
        assert_eq!(auth.failure_count.load(Ordering::SeqCst), 0);
    }

    /// [`Role::All`] satisfies any required role in a quorum
    /// check — same semantics as single-key verify_with_role.
    /// Useful for break-glass operators whose key holds `all`.
    #[test]
    fn verify_quorum_role_all_satisfies_any_required_role() {
        let (auth, signers) = build_auth_with_keyed_roles(&[vec![Role::All], vec![Role::Unlock]]);
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
        use common::wire::admin_signed_payload::{
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
        let auth =
            AdminAuth::build_entries_with_agent_id(entries, DEFAULT_RATE_LIMIT_WINDOW, agent_id);
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
    }
}
