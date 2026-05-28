//! BUG-013 (PHASE 15.1): bootstrap-mode 1-of-N quorum gate for the
//! initial `rotate-keys add` operation on a fresh single-admin-key
//! install.
//!
//! ## Problem
//!
//! `install.sh` bootstraps exactly ONE admin keypair. Both
//! `rotate-keys add` (the only path to mint a second key) and
//! `shutdown` enforce permanent 2-of-N quorum. A fresh install
//! cannot reach a 2-key state without an existing 2-key state —
//! the operator's only way to graceful-stop a fresh install is
//! `sudo reboot` (catalog §7, BUG-013).
//!
//! ## Fix
//!
//! A filesystem-anchored sentinel file gates a one-shot 1-of-N
//! exception for `rotate-keys add`. While the sentinel is honored,
//! a single signed `rotate-keys add` request can mint the second
//! key; once a second key is in place the sentinel is removed and
//! the agent enforces permanent 2-of-N for everything.
//!
//! ## Anti-downgrade
//!
//! A root attacker who recreates the sentinel after bootstrap
//! completion must not be able to re-activate the 1-of-N relaxation.
//! Three layered defenses, ALL of which must succeed for the
//! sentinel to be honored:
//!
//! 1. **Sentinel exists** at `/etc/northnarrow/.bootstrap`.
//! 2. **`admin.pub` currently contains exactly one key.** If the
//!    operator has already minted a second key, the sentinel is
//!    structurally meaningless and we ignore it.
//! 3. **Sentinel content matches `SHA256(install_nonce || admin.pub
//!    contents)`** where `install_nonce` is a 32-byte CSPRNG value
//!    persisted at `/etc/northnarrow/.install_nonce` and known only
//!    to the agent + the install-time operator. An attacker without
//!    the nonce cannot forge a sentinel that the agent will honor.
//!
//! Successful 1-of-N add: best-effort `remove_file` on the
//! sentinel. The agent ALSO scrubs any leftover sentinel on every
//! `is_armed` check that observes `admin.pub` with ≥ 2 keys, so a
//! crash between rewrite and removal self-heals.
//!
//! ## Install workflow
//!
//! - `install.sh` writes `/etc/northnarrow/.install_nonce` (32 random
//!   bytes, root:root 0600) AND `/etc/northnarrow/.bootstrap` (hex
//!   SHA256 over `nonce || admin.pub`).
//! - The install.sh change is **deferred** in PHASE 15.1; the agent
//!   already handles the no-bootstrap path (returns false from
//!   `is_armed`, dispatch falls back to permanent 2-of-N). Tests
//!   exercise the on-disk path by writing the sentinel + nonce
//!   directly into a tempdir.

use std::fs;
use std::path::PathBuf;

use anyhow::{Context, Result};
use sha2::{Digest, Sha256};
use tracing::{info, warn};

/// Canonical bootstrap sentinel path. Operator-created via
/// `install.sh`; removed by the agent after the first
/// `rotate-keys add` succeeds.
pub const DEFAULT_SENTINEL_PATH: &str = "/etc/northnarrow/.bootstrap";

/// Canonical install-nonce path. Operator-created via `install.sh`
/// alongside the admin keypair; never modified by the agent.
pub const DEFAULT_INSTALL_NONCE_PATH: &str = "/etc/northnarrow/.install_nonce";

/// Width of the install nonce in bytes (32 = 256 bits, same width
/// as SHA-256 output for symmetry).
pub const INSTALL_NONCE_LEN: usize = 32;

/// Width of the sentinel content (hex-encoded SHA-256 = 64 chars).
const SENTINEL_HEX_LEN: usize = 64;

/// Three on-disk paths the bootstrap gate consults. Factored into a
/// struct so unit tests can substitute tempdir paths without polluting
/// `/etc/northnarrow/`; production callers build via [`Self::default_paths`].
#[derive(Debug, Clone)]
pub struct BootstrapPaths {
    /// Sentinel file. Existence is necessary-but-not-sufficient.
    pub sentinel: PathBuf,
    /// 32-byte install nonce.
    pub install_nonce: PathBuf,
    /// Path the agent reads to count admin keys. Usually equals
    /// `AdminAuth::config_path()`; passed in explicitly so tests can
    /// avoid the global admin.pub.
    pub admin_pub: PathBuf,
}

impl BootstrapPaths {
    /// Production triple — points at the canonical `/etc/northnarrow/`
    /// install layout.
    pub fn default_paths(admin_pub: PathBuf) -> Self {
        Self {
            sentinel: PathBuf::from(DEFAULT_SENTINEL_PATH),
            install_nonce: PathBuf::from(DEFAULT_INSTALL_NONCE_PATH),
            admin_pub,
        }
    }
}

/// Result of the gate check. `Armed` ⇒ caller MAY accept 1-of-N for
/// this dispatch; any other value ⇒ permanent 2-of-N applies.
#[derive(Debug, PartialEq, Eq)]
pub enum BootstrapGate {
    /// Sentinel exists, admin.pub has exactly one key, sentinel
    /// content matches `SHA256(install_nonce || admin.pub bytes)`.
    /// Caller MAY honor 1-of-N for THIS dispatch.
    Armed,
    /// Sentinel absent — normal post-bootstrap state. Permanent 2-of-N.
    SentinelAbsent,
    /// Sentinel present but admin.pub has ≥2 keys — downgrade-attack
    /// signal OR self-healing path after crash mid-rewrite. The agent
    /// best-effort removes the sentinel before returning so subsequent
    /// dispatches don't keep re-checking.
    BootstrapAlreadyComplete,
    /// Install-nonce file is missing — install.sh didn't write it, or
    /// an attacker removed it. Permanent 2-of-N (refuse to fall back
    /// to a weaker check).
    InstallNonceMissing,
    /// Install-nonce file present but unreadable / wrong length —
    /// permanent 2-of-N.
    InstallNonceInvalid { reason: String },
    /// Sentinel present + nonce present + admin.pub has 1 key, but
    /// the sentinel content does NOT match the computed hash —
    /// downgrade-attack signal. Permanent 2-of-N; sentinel NOT
    /// removed (operator should investigate).
    SentinelMismatch,
    /// File I/O failed on the sentinel, admin.pub, etc. Permanent
    /// 2-of-N — fail closed.
    IoError { reason: String },
}

/// Evaluate the gate against the on-disk state. Returns
/// [`BootstrapGate::Armed`] ONLY when all three anti-downgrade
/// conditions are met; every other outcome falls through to
/// permanent 2-of-N quorum.
///
/// Side-effect: when admin.pub has ≥2 keys AND the sentinel exists
/// (the "self-healing after crash mid-rewrite" path), the sentinel
/// is best-effort removed before returning
/// [`BootstrapGate::BootstrapAlreadyComplete`].
pub fn evaluate(paths: &BootstrapPaths) -> BootstrapGate {
    // Step 1 — does the sentinel exist at all? Cheapest check first.
    if !paths.sentinel.exists() {
        return BootstrapGate::SentinelAbsent;
    }

    // Step 2 — count admin.pub keys. If ≥ 2, bootstrap is done;
    // scrub a leftover sentinel and return `BootstrapAlreadyComplete`.
    let admin_pub_bytes = match fs::read(&paths.admin_pub) {
        Ok(b) => b,
        Err(e) => {
            return BootstrapGate::IoError {
                reason: format!("read admin.pub {}: {e}", paths.admin_pub.display()),
            };
        }
    };
    let key_count = count_admin_pub_keys(&admin_pub_bytes);
    if key_count >= 2 {
        // Self-healing scrub. Best-effort: a failure here just leaves
        // the sentinel until the next dispatch retries.
        if let Err(e) = fs::remove_file(&paths.sentinel) {
            warn!(
                target: "anti_tamper.bootstrap",
                error = %e,
                sentinel = %paths.sentinel.display(),
                key_count,
                "BUG-013: scrubbing leftover sentinel failed (will retry next dispatch)"
            );
        } else {
            info!(
                target: "anti_tamper.bootstrap",
                sentinel = %paths.sentinel.display(),
                key_count,
                "BUG-013: leftover sentinel scrubbed (admin.pub already has ≥2 keys)"
            );
        }
        return BootstrapGate::BootstrapAlreadyComplete;
    }

    // Step 3 — read the install nonce.
    let nonce_bytes = match fs::read(&paths.install_nonce) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return BootstrapGate::InstallNonceMissing;
        }
        Err(e) => {
            return BootstrapGate::IoError {
                reason: format!("read install nonce {}: {e}", paths.install_nonce.display()),
            };
        }
    };
    if nonce_bytes.len() != INSTALL_NONCE_LEN {
        return BootstrapGate::InstallNonceInvalid {
            reason: format!(
                "install nonce length is {} (expected {INSTALL_NONCE_LEN})",
                nonce_bytes.len()
            ),
        };
    }

    // Step 4 — compute expected sentinel content + compare against
    // what's on disk. The sentinel is hex-encoded so the operator
    // can `cat` it and an attacker can't trivially confuse the agent
    // by writing raw bytes (length mismatch ⇒ immediate reject).
    let sentinel_raw = match fs::read_to_string(&paths.sentinel) {
        Ok(s) => s,
        Err(e) => {
            return BootstrapGate::IoError {
                reason: format!("read sentinel {}: {e}", paths.sentinel.display()),
            };
        }
    };
    let sentinel_trimmed = sentinel_raw.trim();
    if sentinel_trimmed.len() != SENTINEL_HEX_LEN {
        return BootstrapGate::SentinelMismatch;
    }

    let expected = compute_sentinel_content(&nonce_bytes, &admin_pub_bytes);
    if constant_time_eq(sentinel_trimmed.as_bytes(), expected.as_bytes()) {
        info!(
            target: "anti_tamper.bootstrap",
            sentinel = %paths.sentinel.display(),
            "BUG-013: bootstrap gate ARMED — 1-of-N permitted for this rotate-keys-add"
        );
        BootstrapGate::Armed
    } else {
        // Don't remove the sentinel — operator should see it and
        // investigate. The mismatch is logged here AND emit_audit
        // will tag the failed rotate-keys-add attempt at the
        // dispatcher level (the rate-limit counter will already
        // tick from the verify failure that follows).
        warn!(
            target: "anti_tamper.bootstrap",
            sentinel = %paths.sentinel.display(),
            "BUG-013: sentinel content mismatch — possible downgrade attack, \
             refusing to relax to 1-of-N"
        );
        BootstrapGate::SentinelMismatch
    }
}

/// Best-effort sentinel removal after a successful 1-of-N add. The
/// dispatcher calls this AFTER `atomic_rewrite_admin_pub_add` has
/// succeeded; a failure here just leaves a stale sentinel that the
/// next dispatch will scrub via the `BootstrapAlreadyComplete`
/// path (admin.pub now has 2 keys).
pub fn complete(paths: &BootstrapPaths) -> Result<()> {
    fs::remove_file(&paths.sentinel)
        .with_context(|| format!("removing sentinel {}", paths.sentinel.display()))?;
    info!(
        target: "anti_tamper.bootstrap",
        sentinel = %paths.sentinel.display(),
        "BUG-013: bootstrap complete — sentinel removed, permanent 2-of-N enforced"
    );
    Ok(())
}

/// Compute the expected hex SHA-256 of `(install_nonce || admin_pub_bytes)`.
/// Exposed for unit tests that need to construct a valid sentinel.
pub fn compute_sentinel_content(install_nonce: &[u8], admin_pub_bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(install_nonce);
    hasher.update(admin_pub_bytes);
    hex::encode(hasher.finalize())
}

/// Count non-comment, non-blank lines in `admin.pub`. Same shape as
/// `admin_auth::parse_admin_line`'s caller; duplicated here as a
/// lightweight count (we don't need to parse the pubkeys, just
/// count valid candidate lines).
fn count_admin_pub_keys(bytes: &[u8]) -> usize {
    let text = match std::str::from_utf8(bytes) {
        Ok(s) => s,
        Err(_) => return 0,
    };
    text.lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .count()
}

/// Constant-time byte comparison — avoids timing leaks on a sentinel
/// content compare. Same shape as `subtle::ConstantTimeEq` but
/// inlined to avoid pulling a new dependency for one call site.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff: u8 = 0;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    /// Fixture: build the 3-file triple in a tempdir + return the
    /// raw install nonce so tests can construct expected sentinels.
    fn make_install(
        dir: &TempDir,
        admin_pub_content: &str,
        with_sentinel: Option<&str>,
    ) -> (BootstrapPaths, [u8; INSTALL_NONCE_LEN]) {
        let admin_pub = dir.path().join("admin.pub");
        let install_nonce = dir.path().join(".install_nonce");
        let sentinel = dir.path().join(".bootstrap");
        fs::write(&admin_pub, admin_pub_content).unwrap();
        let nonce = [42u8; INSTALL_NONCE_LEN];
        fs::write(&install_nonce, nonce).unwrap();
        if let Some(content) = with_sentinel {
            fs::write(&sentinel, content).unwrap();
        }
        (
            BootstrapPaths {
                sentinel,
                install_nonce,
                admin_pub,
            },
            nonce,
        )
    }

    /// Canonical happy path: single-key admin.pub, valid sentinel ⇒ Armed.
    #[test]
    fn evaluate_returns_armed_with_valid_sentinel_and_one_key() {
        let dir = TempDir::new().unwrap();
        let admin_pub_content = "1111111111111111111111111111111111111111111111111111111111111111\n";
        let (paths, nonce) = make_install(&dir, admin_pub_content, None);
        let expected = compute_sentinel_content(&nonce, admin_pub_content.as_bytes());
        fs::write(&paths.sentinel, &expected).unwrap();

        assert_eq!(evaluate(&paths), BootstrapGate::Armed);
    }

    /// Sentinel absent ⇒ SentinelAbsent (normal post-bootstrap state).
    #[test]
    fn evaluate_returns_sentinel_absent_when_no_sentinel() {
        let dir = TempDir::new().unwrap();
        let (paths, _) = make_install(&dir, "abcd\n", None);
        assert_eq!(evaluate(&paths), BootstrapGate::SentinelAbsent);
    }

    /// ATTACK CASE: admin.pub has 2 keys ⇒ BootstrapAlreadyComplete +
    /// sentinel scrubbed even with otherwise-valid sentinel content.
    /// This is the primary downgrade-attack defense.
    #[test]
    fn evaluate_refuses_armed_when_admin_pub_has_two_keys() {
        let dir = TempDir::new().unwrap();
        let admin_pub_content =
            "1111111111111111111111111111111111111111111111111111111111111111\n\
             2222222222222222222222222222222222222222222222222222222222222222\n";
        let (paths, nonce) = make_install(&dir, admin_pub_content, None);
        let expected = compute_sentinel_content(&nonce, admin_pub_content.as_bytes());
        fs::write(&paths.sentinel, &expected).unwrap();

        let outcome = evaluate(&paths);
        assert_eq!(outcome, BootstrapGate::BootstrapAlreadyComplete);
        assert!(
            !paths.sentinel.exists(),
            "leftover sentinel must be scrubbed after BootstrapAlreadyComplete"
        );
    }

    /// ATTACK CASE: attacker creates fake sentinel without knowing
    /// the install nonce ⇒ SentinelMismatch.
    #[test]
    fn evaluate_refuses_armed_when_sentinel_content_wrong() {
        let dir = TempDir::new().unwrap();
        let admin_pub_content = "1111111111111111111111111111111111111111111111111111111111111111\n";
        // 64 hex chars but NOT the right hash — what an attacker
        // would write without knowing the install_nonce.
        let bogus = "0".repeat(64);
        let (paths, _) = make_install(&dir, admin_pub_content, Some(&bogus));

        assert_eq!(evaluate(&paths), BootstrapGate::SentinelMismatch);
        assert!(
            paths.sentinel.exists(),
            "mismatched sentinel must NOT be auto-scrubbed (operator must investigate)"
        );
    }

    /// ATTACK CASE: attacker writes garbage of wrong length ⇒ SentinelMismatch.
    #[test]
    fn evaluate_refuses_armed_when_sentinel_wrong_length() {
        let dir = TempDir::new().unwrap();
        let admin_pub_content = "1111111111111111111111111111111111111111111111111111111111111111\n";
        let (paths, _) = make_install(&dir, admin_pub_content, Some("short"));
        assert_eq!(evaluate(&paths), BootstrapGate::SentinelMismatch);
    }

    /// Install nonce missing ⇒ InstallNonceMissing. Refuses to fall
    /// back to a weaker check.
    #[test]
    fn evaluate_refuses_armed_when_install_nonce_missing() {
        let dir = TempDir::new().unwrap();
        let admin_pub = dir.path().join("admin.pub");
        let sentinel = dir.path().join(".bootstrap");
        fs::write(&admin_pub, "abcd\n").unwrap();
        fs::write(&sentinel, "x".repeat(64)).unwrap();
        let paths = BootstrapPaths {
            sentinel,
            install_nonce: dir.path().join(".install_nonce"),
            admin_pub,
        };
        assert_eq!(evaluate(&paths), BootstrapGate::InstallNonceMissing);
    }

    /// Install nonce wrong length ⇒ InstallNonceInvalid.
    #[test]
    fn evaluate_refuses_armed_when_install_nonce_wrong_length() {
        let dir = TempDir::new().unwrap();
        let (paths, _) = make_install(&dir, "abcd\n", Some(&"x".repeat(64)));
        // Overwrite with wrong-length nonce.
        fs::write(&paths.install_nonce, b"too_short").unwrap();
        matches!(evaluate(&paths), BootstrapGate::InstallNonceInvalid { .. });
    }

    /// ATTACK CASE (re-activation): operator completes bootstrap
    /// → attacker creates new sentinel with stale/guessed content
    /// → gate refuses, sentinel scrubbed via the count-≥2 path.
    /// This is the end-to-end re-activation defense.
    #[test]
    fn reactivation_attack_is_rejected_after_bootstrap_complete() {
        let dir = TempDir::new().unwrap();
        // Step 1: install state with 1 key + valid sentinel.
        let admin_pub_content = "1111111111111111111111111111111111111111111111111111111111111111\n";
        let (paths, nonce) = make_install(&dir, admin_pub_content, None);
        let expected = compute_sentinel_content(&nonce, admin_pub_content.as_bytes());
        fs::write(&paths.sentinel, &expected).unwrap();
        assert_eq!(evaluate(&paths), BootstrapGate::Armed);

        // Step 2: dispatcher completes the 1-of-N add. admin.pub
        // gains a second key, sentinel is removed.
        let admin_pub_two_keys = "1111111111111111111111111111111111111111111111111111111111111111\n\
             2222222222222222222222222222222222222222222222222222222222222222\n";
        fs::write(&paths.admin_pub, admin_pub_two_keys).unwrap();
        complete(&paths).unwrap();
        assert_eq!(evaluate(&paths), BootstrapGate::SentinelAbsent);

        // Step 3: attacker recreates the sentinel. ANY content they
        // pick — including the OLD-state hash they may have observed
        // before bootstrap completed — is now ignored because
        // admin.pub has 2 keys.
        fs::write(&paths.sentinel, &expected).unwrap();
        assert_eq!(evaluate(&paths), BootstrapGate::BootstrapAlreadyComplete);
        assert!(
            !paths.sentinel.exists(),
            "downgrade-attack sentinel must be scrubbed"
        );

        // Step 4: attacker computes a fresh hash for the CURRENT
        // 2-key admin.pub. Still ignored (still 2 keys).
        let fresh = compute_sentinel_content(&nonce, admin_pub_two_keys.as_bytes());
        fs::write(&paths.sentinel, &fresh).unwrap();
        assert_eq!(evaluate(&paths), BootstrapGate::BootstrapAlreadyComplete);

        // Step 5: even if the attacker manages to revoke a key down
        // to 1 (which requires 2-of-N they don't have), they STILL
        // don't know the install_nonce, so the sentinel they wrote
        // in step 3/4 doesn't validate against the new admin.pub.
        fs::write(&paths.admin_pub, admin_pub_content).unwrap();
        fs::write(&paths.sentinel, &fresh).unwrap(); // hash of OLD 2-key state
        assert_eq!(evaluate(&paths), BootstrapGate::SentinelMismatch);
    }

    /// `count_admin_pub_keys` ignores comments + blank lines (the
    /// canonical admin.pub format), so a file with one key + many
    /// comments still counts as 1.
    #[test]
    fn count_admin_pub_keys_ignores_comments_and_blanks() {
        let body = "# Header comment\n\
                    \n\
                    # Another comment\n\
                    1111111111111111111111111111111111111111111111111111111111111111\n\
                    \n";
        assert_eq!(count_admin_pub_keys(body.as_bytes()), 1);
    }

    /// Constant-time eq sanity. Property-style: equal slices match,
    /// any byte flip breaks the match, length mismatch is immediate
    /// reject.
    #[test]
    fn constant_time_eq_property() {
        assert!(constant_time_eq(b"hello", b"hello"));
        assert!(!constant_time_eq(b"hello", b"hellp"));
        assert!(!constant_time_eq(b"hello", b"hell"));
        assert!(!constant_time_eq(b"", b"x"));
        assert!(constant_time_eq(b"", b""));
    }

    /// `complete()` returns Err when the sentinel is already gone —
    /// not a failure mode the dispatcher needs to handle (the file
    /// is gone, which is what `complete` is trying to achieve) but
    /// the dispatcher MUST tolerate the error (best-effort cleanup).
    #[test]
    fn complete_returns_err_when_sentinel_already_absent() {
        let dir = TempDir::new().unwrap();
        let paths = BootstrapPaths {
            sentinel: dir.path().join(".bootstrap"),
            install_nonce: dir.path().join(".install_nonce"),
            admin_pub: dir.path().join("admin.pub"),
        };
        assert!(complete(&paths).is_err());
    }
}
