//! Admin authentication (Tappa 7 task 7 / Tappa 8).
//!
//! The only way to leave COMBAT in production is for an admin to
//! sign a server-issued challenge with their Ed25519 private key.
//! [`AdminAuth`] handles the server side of that exchange:
//!
//! 1. Load N admin pubkeys from `/etc/northnarrow/admin.pub`
//!    (one hex-encoded 32-byte key per line, `#` comments allowed).
//! 2. Mint a 32-byte cryptographic nonce on demand
//!    ([`AdminAuth::issue_challenge`]).
//! 3. Verify a 64-byte Ed25519 signature over that nonce against
//!    every loaded pubkey ([`AdminAuth::verify_unlock`]).
//! 4. On success, mint an [`UnlockToken`] via the capability gate in
//!    `network_isolate.rs`. On failure, increment a rate-limit
//!    counter; three failures inside a 5-minute window block
//!    further challenge issuance.
//!
//! The nonce is single-use — it is consumed inside `verify_unlock`
//! regardless of outcome. A failed attempt forces the attacker to
//! request a fresh challenge AND to incur a rate-limit hit.

use std::path::Path;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant};

use anyhow::{anyhow, Context, Result};
use ed25519_dalek::{Signature, VerifyingKey};
use parking_lot::Mutex;
use rand::rngs::OsRng;
use rand::RngCore;
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

/// Reasons [`AdminAuth::issue_challenge`] / [`AdminAuth::verify_unlock`]
/// can refuse, carrying the user-facing detail needed to translate
/// into an [`UnlockResult`](common::wire::admin_protocol::UnlockResult).
#[derive(Debug, Error)]
pub enum AdminAuthError {
    #[error("rate limited: retry after {retry_after_secs}s")]
    RateLimited { retry_after_secs: u32 },
    #[error("no pending challenge")]
    NoPendingChallenge,
    #[error("invalid signature")]
    InvalidSignature,
}

/// Server-side admin authenticator.
///
/// `pub_keys` is read-only after construction so we never need a
/// lock for verification — only the nonce slot, the failure counter,
/// and the last-failure timestamp are mutable.
///
/// The `rate_limit_window` field is the one deviation from the
/// spec's struct layout: tests need to override the 5-minute
/// production window with something like 100 ms to run in a sane
/// amount of time. Production callers use [`AdminAuth::load`]
/// which pins the field to [`DEFAULT_RATE_LIMIT_WINDOW`].
#[derive(Debug)]
pub struct AdminAuth {
    pub_keys: Vec<VerifyingKey>,
    pending_challenge: Mutex<Option<[u8; 32]>>,
    failure_count: AtomicU32,
    last_failure: Mutex<Option<Instant>>,
    rate_limit_window: Duration,
}

impl AdminAuth {
    /// Parse `config_path` — one hex-encoded pubkey per line, `#`
    /// comments, blank lines OK — and build an authenticator. At
    /// least one valid key is required; an empty file is a startup
    /// error, not a "anybody can unlock" silent-default.
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
            if line.len() != PUBKEY_HEX_LEN {
                return Err(anyhow!(
                    "{}:{}: pub key must be {} hex chars (got {})",
                    config_path.display(),
                    line_no,
                    PUBKEY_HEX_LEN,
                    line.len()
                ));
            }
            let raw_bytes = hex::decode(line)
                .map_err(|e| anyhow!("{}:{}: invalid hex ({e})", config_path.display(), line_no))?;
            let key_bytes: [u8; 32] = raw_bytes
                .try_into()
                .expect("hex decode length pre-validated to 64 chars");
            let vk = VerifyingKey::from_bytes(&key_bytes).map_err(|e| {
                anyhow!(
                    "{}:{}: not a valid Ed25519 pubkey ({e})",
                    config_path.display(),
                    line_no
                )
            })?;
            pub_keys.push(vk);
        }

        if pub_keys.is_empty() {
            return Err(anyhow!(
                "{}: no admin pub keys found (need at least one)",
                config_path.display()
            ));
        }

        Ok(Self::build(pub_keys, DEFAULT_RATE_LIMIT_WINDOW))
    }

    fn build(pub_keys: Vec<VerifyingKey>, rate_limit_window: Duration) -> Self {
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

    /// Verify `signature` against the outstanding nonce. On success,
    /// mint an [`UnlockToken`]; on failure, increment the rate-limit
    /// counter so repeated probing eventually trips the gate.
    ///
    /// The nonce is consumed unconditionally — even a failed verify
    /// invalidates it. That forces an attacker who guessed wrong to
    /// roundtrip another challenge AND eat a rate-limit hit.
    pub fn verify_unlock(
        &self,
        signature: &[u8; 64],
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

        // Verify against every loaded pubkey without short-circuiting.
        // ed25519-dalek's `verify_strict` is itself constant-time;
        // this loop keeps the per-attempt cost dependent on the
        // number of installed keys but NOT on which key matched,
        // closing a minor side-channel on key rotation.
        let mut ok = false;
        for key in &self.pub_keys {
            if key.verify_strict(&nonce, &sig).is_ok() {
                ok = true;
            }
        }

        if ok {
            self.failure_count.store(0, Ordering::SeqCst);
            *self.last_failure.lock() = None;
            info!(
                target: "anti_tamper.admin_auth.verify_success",
                "admin signature verified, unlock token minted"
            );
            Ok(mint_unlock_token())
        } else {
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
}
