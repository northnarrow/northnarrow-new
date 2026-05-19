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

use std::path::Path;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, Context, Result};
use common::wire::admin_signed_payload::Role;
use ed25519_dalek::{Signature, VerifyingKey};
use parking_lot::Mutex;
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
        self.roles
            .iter()
            .any(|r| *r == required || *r == Role::All)
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
    pub_keys: Vec<KeyEntry>,
    pending_challenge: Mutex<Option<[u8; 32]>>,
    failure_count: AtomicU32,
    last_failure: Mutex<Option<Instant>>,
    rate_limit_window: Duration,
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
    pub fn load(config_path: &Path) -> Result<Self> {
        let content = std::fs::read_to_string(config_path)
            .with_context(|| format!("reading {}", config_path.display()))?;

        let mut pub_keys = Vec::new();
        for (idx, raw) in content.lines().enumerate() {
            let line_no = idx + 1;
            let line = raw.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let entry = parse_admin_line(line).map_err(|e| {
                anyhow!("{}:{}: {e}", config_path.display(), line_no)
            })?;
            pub_keys.push(entry);
        }

        if pub_keys.is_empty() {
            return Err(anyhow!(
                "{}: no admin pub keys found (need at least one)",
                config_path.display()
            ));
        }

        Ok(Self::build_entries(pub_keys, DEFAULT_RATE_LIMIT_WINDOW))
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

    /// Lower-level builder consumed by [`Self::load`] (which has
    /// already parsed roles per-line) and by tests that want to
    /// pin custom role allowlists per key.
    fn build_entries(pub_keys: Vec<KeyEntry>, rate_limit_window: Duration) -> Self {
        Self {
            pub_keys,
            pending_challenge: Mutex::new(None),
            failure_count: AtomicU32::new(0),
            last_failure: Mutex::new(None),
            rate_limit_window,
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

        // Constant-time across keys (no short-circuit) — record
        // the matched index so we can check the matched key's
        // role allowlist after the loop. ed25519-dalek's
        // `verify_strict` is itself constant-time.
        let mut matched_idx: Option<usize> = None;
        for (idx, entry) in self.pub_keys.iter().enumerate() {
            if entry.key.verify_strict(&nonce, &sig).is_ok() {
                matched_idx = Some(idx);
                // intentionally NOT `break` — preserve constant-time iteration
            }
        }

        match matched_idx {
            Some(idx) => {
                let entry = &self.pub_keys[idx];
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
    let raw_bytes =
        hex::decode(hex_token).map_err(|e| anyhow!("invalid hex: {e}"))?;
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
fn parse_role_keyword(s: &str) -> Result<Role> {
    match s {
        "unlock" => Ok(Role::Unlock),
        "shutdown" => Ok(Role::Shutdown),
        "force-posture" => Ok(Role::ForcePosture),
        "rotate-keys" => Ok(Role::RotateKeys),
        "audit-read" => Ok(Role::AuditRead),
        "all" => Ok(Role::All),
        other => Err(anyhow!(
            "unknown role `{other}` — expected one of: \
             unlock, shutdown, force-posture, rotate-keys, audit-read, all"
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
    #[error(
        "timestamp outside ±{max_skew_secs}s window (server_ts={server_ts})"
    )]
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
        assert_eq!(auth.pub_keys.len(), 1);
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
        assert_eq!(auth.pub_keys.len(), 3);
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
        check_timestamp_skew(server.now_unix_secs(), server.now_unix_secs(), MAX_TIMESTAMP_SKEW_SECS)
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
            Err(TimestampSkewError::OutOfWindow { server_ts, max_skew_secs }) => {
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
            Err(TimestampSkewError::OutOfWindow { server_ts, max_skew_secs }) => {
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
        check_timestamp_skew(clock.now_unix_secs(), clock.now_unix_secs(), MAX_TIMESTAMP_SKEW_SECS)
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
        assert_eq!(auth.pub_keys.len(), 1);
        let entry = &auth.pub_keys[0];
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
        assert_eq!(auth.pub_keys[0].roles, vec![Role::Shutdown]);
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
            auth.pub_keys[0].roles,
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
            ("all", Role::All),
        ];
        for (keyword, expected) in cases {
            let (_, vk) = make_keypair();
            let line = format!("{} {keyword}", hex::encode(vk.to_bytes()));
            let f = write_config(&[&line]);
            let auth = AdminAuth::load(f.path())
                .unwrap_or_else(|e| panic!("load failed for `{keyword}`: {e}"));
            assert_eq!(
                auth.pub_keys[0].roles,
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
        assert!(
            s.contains(":2:"),
            "error should reference line 2, got: {s}"
        );
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
}
