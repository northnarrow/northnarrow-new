//! The drift's provisional classification (Tappa 9, C4; design §6.5, Q4):
//! the severity tier the FIM drain gives a drift before any rule judges
//! it, the classifier that assigns it from the operation and the path, and
//! the per-tier token bucket that paces the drift a package transaction
//! writes (review 76). Critical is never throttled.
//!
//! R08b (lab PR 251): cut verbatim from the agent's `fim::drain` (the plan's
//! "classificazione del drift", R08b), which re-exports it and keeps the
//! ring, the path map, the hashes and the drift log. The tier is a field
//! of the drift log's signed rows: its serialised form is unchanged (the
//! derives moved with it).

use std::time::{Duration, Instant};

use nn_model::telemetry::FimOp;
use serde::{Deserialize, Serialize};

// ── severity tier (Q4) ─────────────────────────────────────────────

/// Provisional severity assigned by the drain to feed the §6.5
/// token bucket. C5's rule engine may upgrade or refine, but
/// the drain has to commit to a tier *before* the rule fires
/// because the bucket gate is upstream of the decision engine.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DriftSeverity {
    /// Never throttled — Q4 lock-in. Reserved for ops that the
    /// classifier can already prove are evasion techniques
    /// (e.g., a hardlink-create into a user-writable dir on a
    /// SUID-root inode). The drain stays conservative: most
    /// events go to High or Medium, Critical only when the
    /// classifier has high-confidence signal.
    Critical,
    /// 50 events/minute per process under default Q4
    /// configuration.
    High,
    /// 100 events/minute per process under default Q4
    /// configuration.
    Medium,
}

/// Default per-tier emission caps from §13 Q4 resolution.
/// Owner-tunable via `/etc/northnarrow/config.toml` in future
/// commits; the defaults here are the design's recommendation.
pub const DEFAULT_HIGH_PER_MIN: u32 = 50;
pub const DEFAULT_MEDIUM_PER_MIN: u32 = 100;

// ── classifier ─────────────────────────────────────────────────────

/// Pure FimOp + path → DriftSeverity assignment. Conservative:
/// the drain only escalates to Critical when the signal is
/// unambiguous (hardlink-into-user-writable-dir per §13 Q2);
/// everything else is High (op-driven) or Medium (default).
/// C5 rules may upgrade by re-classifying the FimEvent based
/// on per-path policy.
#[derive(Debug, Default)]
pub struct DriftClassifier;

impl DriftClassifier {
    pub fn new() -> Self {
        Self
    }

    /// Classify `(op, path)`. The path is informational (used
    /// only for the Linked-into-user-writable-dir heuristic);
    /// classification is otherwise op-only so C5's rule engine
    /// retains full path-policy authority.
    pub fn classify(&self, op: FimOp, path: &str) -> DriftSeverity {
        // External audit FIMR-005: a path a Critical rule guards is never
        // throttled (§6.5, Q4), whatever the op — a modification of
        // /usr/sbin/sshd was "Medium" here. Since review 76 only a package
        // transaction's drift is paced at all.
        if op != FimOp::Opened && crate::fim::rules::is_critical_rule_path(path) {
            return DriftSeverity::Critical;
        }
        match op {
            // Hardlink into a user-writable dir on a SUID-root
            // inode is the §13 Q2 evasion path — never throttle.
            // The drain doesn't know the inode's SUID bit here
            // (the BPF program only sent (dev,ino) + op); the
            // classifier escalates based on the LINK DESTINATION
            // path (which the path map resolves before this call).
            FimOp::Linked if is_user_writable_prefix(path) => DriftSeverity::Critical,
            // Deletion + creation are high-signal — a file that
            // appears or disappears in a watched dir is rarely a
            // benign event.
            FimOp::Deleted | FimOp::Created | FimOp::Linked => DriftSeverity::High,
            // Modified + Renamed are noisier (package upgrades
            // generate dozens) — default to Medium so the
            // bucket can throttle them without losing High
            // tokens.
            FimOp::Modified | FimOp::Renamed => DriftSeverity::Medium,
            // Review 86: a capability grant comes from the file-open
            // sensor, never from the drift ring; never throttled.
            FimOp::CapabilitySet => DriftSeverity::Critical,
            // Wave 2 (TST-004): a permission or ownership change is
            // rarer than a content change and as telling.
            FimOp::AttrChanged => DriftSeverity::High,
            // C5.2: FimOp::Opened fires on every open of a
            // watched inode. Default to Medium so legitimate
            // periodic reads (cloud-CLI tools, monitoring
            // agents) can be rate-limited. C5.3 rules
            // (NN-L-FIM-011..014) classify cred-path reads
            // separately + the rule fires regardless of the
            // bucket — Critical-tier path-rule severity comes
            // from the rule, not this classifier.
            FimOp::Opened => DriftSeverity::Medium,
        }
    }
}

fn is_user_writable_prefix(path: &str) -> bool {
    path.starts_with("/tmp/")
        || path.starts_with("/var/tmp/")
        || path.starts_with("/dev/shm/")
        || path.starts_with("/home/")
}

// ── rate limiter (Q4 hierarchical token bucket) ────────────────────

/// Hierarchical token-bucket per `DriftSeverity` tier. Critical
/// is never throttled (per Q4 lock-in). High + Medium have
/// independent buckets that refill linearly over a 60s window.
/// [`process_drift`] spends them only on drift written by a package
/// manager (review 76).
///
/// Thread-safety: a single `Mutex` wraps the bucket state. The
/// async drain loop holds the lock for microseconds per drift
/// — sub-millisecond contention even under burst load. A
/// `parking_lot::Mutex`, for fairness and no poisoning: a panic
/// while it was held cannot turn every later drift into a second
/// one (external audit NN-AUD-293 FIMP-014: it was a
/// `std::sync::Mutex` with `.expect("… poisoned")` on each lock,
/// against this note).
pub struct DriftRateLimiter {
    state: parking_lot::Mutex<BucketState>,
    high_per_min: u32,
    medium_per_min: u32,
}

struct BucketState {
    high_remaining: u32,
    medium_remaining: u32,
    window_started: Instant,
}

impl DriftRateLimiter {
    /// Build with default Q4 caps (`DEFAULT_HIGH_PER_MIN` +
    /// `DEFAULT_MEDIUM_PER_MIN`).
    pub fn new() -> Self {
        Self::with_caps(DEFAULT_HIGH_PER_MIN, DEFAULT_MEDIUM_PER_MIN)
    }

    /// Build with explicit caps. Test-friendly + operator-
    /// override-friendly.
    pub fn with_caps(high_per_min: u32, medium_per_min: u32) -> Self {
        Self {
            state: parking_lot::Mutex::new(BucketState {
                high_remaining: high_per_min,
                medium_remaining: medium_per_min,
                window_started: Instant::now(),
            }),
            high_per_min,
            medium_per_min,
        }
    }

    /// Try to consume one token for `severity`. Returns
    /// `Ok(())` if the event may pass through to the decision
    /// engine, or `Err(reason)` if the bucket is empty and the
    /// event should be suppressed (audit chain still records).
    ///
    /// `now` is injected so tests can advance time deterministically
    /// without sleeping. Production callers pass `Instant::now()`.
    pub fn try_consume_with_now(
        &self,
        severity: DriftSeverity,
        now: Instant,
    ) -> Result<(), String> {
        let mut s = self.state.lock();
        // Window roll-over — when 60s elapsed since the window
        // started, refill both buckets to full and reset the
        // anchor. Single mutex lock window keeps this race-free.
        if now.duration_since(s.window_started) >= Duration::from_secs(60) {
            s.high_remaining = self.high_per_min;
            s.medium_remaining = self.medium_per_min;
            s.window_started = now;
        }
        match severity {
            DriftSeverity::Critical => Ok(()), // Q4: never throttled
            DriftSeverity::High => {
                if s.high_remaining > 0 {
                    s.high_remaining -= 1;
                    Ok(())
                } else {
                    Err("rate_limit:tier_high".to_string())
                }
            }
            DriftSeverity::Medium => {
                if s.medium_remaining > 0 {
                    s.medium_remaining -= 1;
                    Ok(())
                } else {
                    Err("rate_limit:tier_medium".to_string())
                }
            }
        }
    }

    /// Production wrapper around `try_consume_with_now` that
    /// pins `now = Instant::now()`. Most callers use this.
    pub fn try_consume(&self, severity: DriftSeverity) -> Result<(), String> {
        self.try_consume_with_now(severity, Instant::now())
    }

    /// C7 — read-only snapshot of bucket state for the
    /// `nn-admin fim status` reply. Returns
    /// `(high_remaining, medium_remaining, secs_until_window_resets)`.
    /// Holds the mutex for microseconds (three field reads + an
    /// arithmetic on `Instant`); same lock-contention budget as
    /// `try_consume`.
    pub fn snapshot(&self) -> (u32, u32, u32) {
        let s = self.state.lock();
        let elapsed = Instant::now().duration_since(s.window_started);
        let remaining_secs = Duration::from_secs(60)
            .checked_sub(elapsed)
            .map(|d| d.as_secs() as u32)
            .unwrap_or(0);
        (s.high_remaining, s.medium_remaining, remaining_secs)
    }

    /// C7 — configured High-tier cap. Surfaced in
    /// `FimStatusResponse` so the CLI can render
    /// `<remaining>/<cap>` ratios.
    pub fn high_cap_per_min(&self) -> u32 {
        self.high_per_min
    }

    /// C7 — configured Medium-tier cap. Same rationale as
    /// [`Self::high_cap_per_min`].
    pub fn medium_cap_per_min(&self) -> u32 {
        self.medium_per_min
    }
}

impl Default for DriftRateLimiter {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;

    /// External audit FIMR-005: a path a Critical rule guards is never
    /// throttled, whatever the op (a read is not drift).
    #[test]
    fn critical_rule_paths_are_never_throttled() {
        let c = DriftClassifier::new();
        let rl = DriftRateLimiter::new();
        for path in [
            "/usr/sbin/sshd",
            "/usr/bin/sudo",
            "/bin/login",
            "/usr/lib/x86_64-linux-gnu/libc.so.6",
            "/lib/modules/6.8.0/kernel/x.ko",
            "/usr/lib/x86_64-linux-gnu/security/pam_unix.so",
            "/etc/ld.so.preload",
            crate::fim::rules::HONEYPOT_PATHS[0],
        ] {
            for op in [
                FimOp::Modified,
                FimOp::Renamed,
                FimOp::Created,
                FimOp::Deleted,
            ] {
                assert_eq!(
                    c.classify(op, path),
                    DriftSeverity::Critical,
                    "{op:?} {path}"
                );
            }
        }
        // the buckets spent, a Critical drift still goes through
        while rl.try_consume(DriftSeverity::Medium).is_ok() {}
        while rl.try_consume(DriftSeverity::High).is_ok() {}
        assert!(rl
            .try_consume(c.classify(FimOp::Modified, "/usr/sbin/sshd"))
            .is_ok());
        assert_eq!(
            c.classify(FimOp::Opened, "/usr/sbin/sshd"),
            DriftSeverity::Medium
        );
    }

    #[test]
    fn classifier_assigns_provisional_severity() {
        let c = DriftClassifier::new();
        // Modified + Renamed → Medium (noisy under upgrades).
        assert_eq!(
            c.classify(FimOp::Modified, "/etc/ssh/sshd_config"),
            DriftSeverity::Medium
        );
        assert_eq!(
            c.classify(FimOp::Renamed, "/etc/passwd"),
            DriftSeverity::Medium
        );
        // Created + Deleted → High (high-signal).
        assert_eq!(
            c.classify(FimOp::Created, "/etc/cron.d/x"),
            DriftSeverity::High
        );
        assert_eq!(
            c.classify(FimOp::Deleted, "/etc/shadow"),
            DriftSeverity::High
        );
        // Linked to non-user-writable → High.
        assert_eq!(
            c.classify(FimOp::Linked, "/usr/local/bin/x"),
            DriftSeverity::High
        );
        // Linked INTO user-writable → Critical (§13 Q2 evasion path).
        assert_eq!(
            c.classify(FimOp::Linked, "/tmp/.x"),
            DriftSeverity::Critical
        );
        assert_eq!(
            c.classify(FimOp::Linked, "/var/tmp/x"),
            DriftSeverity::Critical
        );
        assert_eq!(
            c.classify(FimOp::Linked, "/dev/shm/y"),
            DriftSeverity::Critical
        );
        assert_eq!(
            c.classify(FimOp::Linked, "/home/alice/.x"),
            DriftSeverity::Critical
        );
        // C5.2: Opened defaults to Medium so legitimate
        // periodic cred-CLI reads can be rate-limited; the
        // C5.3 NN-L-FIM-011..014 rules upgrade to High at the
        // rule layer when the path actually matches a cred
        // file.
        assert_eq!(
            c.classify(FimOp::Opened, "/root/.aws/credentials"),
            DriftSeverity::Medium
        );
        assert_eq!(
            c.classify(FimOp::Opened, "/etc/passwd"),
            DriftSeverity::Medium
        );
    }

    // ── C4 test 3: RateLimiter never throttles Critical ─────────────

    #[test]
    fn rate_limiter_never_throttles_critical() {
        let rl = DriftRateLimiter::with_caps(1, 1);
        // Even after exhausting Medium + High, Critical flows.
        let _ = rl.try_consume(DriftSeverity::High);
        let _ = rl.try_consume(DriftSeverity::Medium);
        let _ = rl.try_consume(DriftSeverity::High); // exhausted
        let _ = rl.try_consume(DriftSeverity::Medium); // exhausted
        for _ in 0..100 {
            rl.try_consume(DriftSeverity::Critical)
                .expect("Critical must NEVER throttle (Q4 lock-in)");
        }
    }

    // ── C4 test 4: RateLimiter throttles Medium after N/min ─────────

    #[test]
    fn rate_limiter_throttles_medium_then_refills_after_window() {
        let rl = DriftRateLimiter::with_caps(50, 100);
        let t0 = Instant::now();
        // First 100 Medium pass.
        for i in 0..100 {
            rl.try_consume_with_now(DriftSeverity::Medium, t0)
                .unwrap_or_else(|e| panic!("Medium #{i} unexpectedly throttled: {e}"));
        }
        // 101st throttles.
        let err = rl
            .try_consume_with_now(DriftSeverity::Medium, t0)
            .expect_err("Medium #101 must throttle");
        assert_eq!(err, "rate_limit:tier_medium");
        // Advance past window — bucket refills.
        let later = t0 + Duration::from_secs(61);
        rl.try_consume_with_now(DriftSeverity::Medium, later)
            .expect("Medium after window roll-over must pass");
    }

    // ── C4 test 5: RateLimiter throttles High independently ─────────

    #[test]
    fn rate_limiter_high_and_medium_have_independent_buckets() {
        let rl = DriftRateLimiter::with_caps(2, 100);
        let t0 = Instant::now();
        // Exhaust High.
        rl.try_consume_with_now(DriftSeverity::High, t0).unwrap();
        rl.try_consume_with_now(DriftSeverity::High, t0).unwrap();
        assert!(rl.try_consume_with_now(DriftSeverity::High, t0).is_err());
        // Medium is independent — still full.
        for _ in 0..50 {
            rl.try_consume_with_now(DriftSeverity::Medium, t0).unwrap();
        }
    }

    /// External audit NN-AUD-293 (FIMP-014): a panic while the limiter's
    /// lock was held poisoned the `std::sync::Mutex`, and every later drift
    /// panicked at `.expect("… poisoned")` (with `panic = "abort"`, the
    /// agent). The lock is a `parking_lot::Mutex`: released on the unwind,
    /// never poisoned.
    #[test]
    fn rate_limiter_keeps_working_after_a_panic_under_its_lock() {
        let rl = Arc::new(DriftRateLimiter::with_caps(2, 2));
        let held = Arc::clone(&rl);
        let died = std::thread::spawn(move || {
            let _guard = held.state.lock();
            panic!("a drain task dies holding the limiter (expected by this test)");
        })
        .join();
        assert!(died.is_err());
        rl.try_consume(DriftSeverity::High)
            .expect("the limiter still answers");
        let (high, medium, _) = rl.snapshot();
        assert_eq!((high, medium), (1, 2));
    }
}
