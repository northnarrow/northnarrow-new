//! What the exec quarantine does with a held process (lab PR 223): the
//! decision table and the time budget, pure and unit-tested. The controller
//! ([`super::controller`]) gathers the inputs and carries the outcome out.
//!
//! | basis | action | cached | severity |
//! |---|---|---|---|
//! | scanned clean | resume | yes | Low |
//! | trusted (allow list, package database) | resume | yes | Low |
//! | known hash (content judged clean before) | resume | yes | — (no record) |
//! | suspicious | `on_suspicious` (resume) | if resumed | Medium resumed, High killed |
//! | malicious (block list) | kill + quarantine | no | Critical |
//! | unscanned, unreachable, budget expired | `on_expiry` (resume) | no | Medium |
//! | left stopped by an agent that died | resume | no | Medium |
//!
//! The defaults in this lot resume and alert; every row is a signed
//! detection record except the known-hash one (its first sight was).

use std::time::{Duration, Instant};

use common::execq::ScanVerdict;
use common::wire::execq::known_verdict;
use common::Severity;

/// What is done to the held process.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum Action {
    /// `SIGCONT`.
    Resume,
    /// `SIGKILL` (and the file quarantined when the basis is a block-list
    /// hit or a suspicious verdict).
    Kill,
}

impl Action {
    pub fn as_str(self) -> &'static str {
        match self {
            Action::Resume => "resume",
            Action::Kill => "kill",
        }
    }
}

/// The configured choices.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Policy {
    pub on_suspicious: Action,
    pub on_expiry: Action,
    /// Enforce mode: the process is held and the action carried out.
    /// Observe mode: the process runs; the outcome is recorded as what
    /// would have been done.
    pub enforce: bool,
}

impl Default for Policy {
    fn default() -> Self {
        Policy {
            on_suspicious: Action::Resume,
            on_expiry: Action::Resume,
            enforce: true,
        }
    }
}

/// Why a decision is made.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Basis {
    /// The scanner's verdict.
    Scanned(ScanVerdict),
    /// The package database lists the file and its content matches.
    Package { manager: &'static str },
    /// Content judged clean earlier in this agent's run (another path).
    KnownHash,
    /// No verdict within the budget (the scanner was slow, down or busy,
    /// or the rule engine had not judged the exec yet).
    Expired { detail: String },
    /// The file could not be handed to the scanner (a script whose path
    /// no longer names the executed inode, a memfd script).
    Unreachable { detail: String },
    /// Found stopped at boot: the previous agent died before deciding.
    Recovered,
}

/// The decision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Outcome {
    pub action: Action,
    /// Quarantine the file (with a kill).
    pub quarantine: bool,
    /// The `EXECQ_KNOWN` verdict to cache the identity under, if any.
    pub cache: Option<u32>,
    /// Keep the digest as known-clean content.
    pub known_clean: bool,
    /// A detection record is written.
    pub record: bool,
    pub severity: Severity,
    /// One phrase for the record (`scanned clean`, `budget expired: …`).
    pub why: String,
}

pub fn decide(policy: &Policy, basis: &Basis) -> Outcome {
    let resume =
        |cache: Option<u32>, known_clean: bool, record: bool, severity, why: String| Outcome {
            action: Action::Resume,
            quarantine: false,
            cache,
            known_clean,
            record,
            severity,
            why,
        };
    let fallback = |why: String| Outcome {
        action: policy.on_expiry,
        quarantine: false,
        cache: None,
        known_clean: false,
        record: true,
        severity: Severity::Medium,
        why,
    };
    match basis {
        Basis::Scanned(ScanVerdict::Clean) => resume(
            Some(known_verdict::CLEAN),
            true,
            true,
            Severity::Low,
            "scanned clean".into(),
        ),
        Basis::Scanned(ScanVerdict::Trusted) => resume(
            Some(known_verdict::CLEAN),
            true,
            true,
            Severity::Low,
            "trusted by the signed allow list".into(),
        ),
        Basis::Package { manager } => resume(
            Some(known_verdict::CLEAN),
            true,
            true,
            Severity::Low,
            format!("trusted: {manager} lists the file with this content"),
        ),
        Basis::KnownHash => resume(
            Some(known_verdict::CLEAN),
            true,
            false,
            Severity::Low,
            "content judged clean earlier".into(),
        ),
        Basis::Scanned(ScanVerdict::Suspicious) => match policy.on_suspicious {
            Action::Resume => resume(
                Some(known_verdict::RESUMED),
                false,
                true,
                Severity::Medium,
                "suspicious, resumed by policy (on-suspicious resume)".into(),
            ),
            Action::Kill => Outcome {
                action: Action::Kill,
                quarantine: true,
                cache: None,
                known_clean: false,
                record: true,
                severity: Severity::High,
                why: "suspicious, killed by policy (on-suspicious kill)".into(),
            },
        },
        Basis::Scanned(ScanVerdict::Malicious) => Outcome {
            action: Action::Kill,
            quarantine: true,
            cache: None,
            known_clean: false,
            record: true,
            severity: Severity::Critical,
            why: "block-listed content".into(),
        },
        Basis::Scanned(ScanVerdict::Unscanned) => fallback(format!(
            "not scanned, default policy ({})",
            policy.on_expiry.as_str()
        )),
        Basis::Expired { detail } => fallback(format!(
            "decision budget expired ({detail}), default policy ({})",
            policy.on_expiry.as_str()
        )),
        Basis::Unreachable { detail } => fallback(format!(
            "file not scannable ({detail}), default policy ({})",
            policy.on_expiry.as_str()
        )),
        Basis::Recovered => Outcome {
            action: Action::Resume,
            quarantine: false,
            cache: None,
            known_clean: false,
            record: true,
            severity: Severity::Medium,
            why: "left stopped by an agent that exited before deciding; resumed at boot".into(),
        },
    }
}

/// Where a held process stands against its budget.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Gate {
    /// Received from the kernel.
    pub since: Instant,
    pub budget: Duration,
    /// The kernel stopped it (enforce mode, signal sent).
    pub stopped: bool,
    /// The scanner answered (or no scan is needed).
    pub verdict: bool,
    /// The rule engine has judged its `ProcessSpawn`: a kill the rules
    /// decide lands before the resume. Not waited for an unheld process.
    pub spawn_judged: bool,
}

/// What the controller does next with a held process.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Next {
    /// Decide now.
    Decide,
    /// Nothing yet; look again by this instant at the latest.
    Wait(Instant),
    /// The budget ran out: the default policy.
    Expired,
}

impl Gate {
    pub fn deadline(&self) -> Instant {
        self.since + self.budget
    }

    pub fn next(&self, now: Instant) -> Next {
        let ready = self.verdict && (self.spawn_judged || !self.stopped);
        if ready {
            Next::Decide
        } else if now >= self.deadline() {
            Next::Expired
        } else {
            Next::Wait(self.deadline())
        }
    }

    /// What the expiry record says was missing.
    pub fn missing(&self) -> String {
        match (self.verdict, self.spawn_judged || !self.stopped) {
            (false, false) => "no scan verdict, exec not yet judged by the rules".into(),
            (false, true) => "no scan verdict".into(),
            (true, false) => "exec not yet judged by the rules".into(),
            (true, true) => "nothing".into(),
        }
    }
}

/// `--exec-quarantine-budget-ms` clamped to what a held process may wait.
pub fn clamp_budget(ms: u64) -> Duration {
    Duration::from_millis(ms.clamp(MIN_BUDGET_MS, MAX_BUDGET_MS))
}

pub const DEFAULT_BUDGET_MS: u64 = 2000;
pub const MIN_BUDGET_MS: u64 = 100;
pub const MAX_BUDGET_MS: u64 = 10_000;

#[cfg(test)]
mod tests {
    use super::*;

    fn p(on_suspicious: Action, on_expiry: Action) -> Policy {
        Policy {
            on_suspicious,
            on_expiry,
            enforce: true,
        }
    }

    #[test]
    fn the_decision_table() {
        let d = Policy::default();
        let o = decide(&d, &Basis::Scanned(ScanVerdict::Clean));
        assert_eq!(
            (o.action, o.cache, o.record, o.known_clean),
            (Action::Resume, Some(known_verdict::CLEAN), true, true)
        );
        assert_eq!(o.severity, Severity::Low);
        let o = decide(&d, &Basis::Scanned(ScanVerdict::Malicious));
        assert_eq!(
            (o.action, o.quarantine, o.cache),
            (Action::Kill, true, None)
        );
        assert_eq!(o.severity, Severity::Critical);
        let o = decide(&d, &Basis::KnownHash);
        assert!(!o.record && o.action == Action::Resume && o.cache.is_some());
        let o = decide(&d, &Basis::Package { manager: "dpkg" });
        assert!(o.record && o.known_clean && o.why.contains("dpkg"));
        let o = decide(&d, &Basis::Scanned(ScanVerdict::Trusted));
        assert_eq!(o.cache, Some(known_verdict::CLEAN));
    }

    /// The defaults of this lot resume and alert.
    #[test]
    fn suspicious_follows_its_policy() {
        let o = decide(&Policy::default(), &Basis::Scanned(ScanVerdict::Suspicious));
        assert_eq!(o.action, Action::Resume);
        assert_eq!(o.cache, Some(known_verdict::RESUMED));
        assert!(!o.known_clean, "suspicious content is never known-clean");
        assert_eq!(o.severity, Severity::Medium);
        let o = decide(
            &p(Action::Kill, Action::Resume),
            &Basis::Scanned(ScanVerdict::Suspicious),
        );
        assert_eq!(
            (o.action, o.quarantine, o.cache),
            (Action::Kill, true, None)
        );
        assert_eq!(o.severity, Severity::High);
    }

    #[test]
    fn expiry_unscanned_and_unreachable_take_the_default_policy() {
        for basis in [
            Basis::Expired {
                detail: "no scan verdict".into(),
            },
            Basis::Unreachable {
                detail: "memfd script".into(),
            },
            Basis::Scanned(ScanVerdict::Unscanned),
        ] {
            let o = decide(&Policy::default(), &basis);
            assert_eq!(o.action, Action::Resume, "{basis:?}");
            assert!(o.record && o.cache.is_none() && !o.known_clean, "{basis:?}");
            assert!(o.why.contains("default policy (resume)"), "{}", o.why);
            let k = decide(&p(Action::Resume, Action::Kill), &basis);
            assert_eq!(k.action, Action::Kill);
            assert!(!k.quarantine, "no verdict, nothing to quarantine for");
        }
        let o = decide(&p(Action::Kill, Action::Kill), &Basis::Recovered);
        assert_eq!(o.action, Action::Resume, "never kill blind at boot");
    }

    #[test]
    fn the_budget_gate() {
        let t0 = Instant::now();
        let mut g = Gate {
            since: t0,
            budget: Duration::from_secs(2),
            stopped: true,
            verdict: false,
            spawn_judged: false,
        };
        assert_eq!(g.next(t0), Next::Wait(t0 + Duration::from_secs(2)));
        g.verdict = true;
        assert_eq!(g.next(t0), Next::Wait(g.deadline()), "the rules first");
        assert_eq!(g.missing(), "exec not yet judged by the rules");
        g.spawn_judged = true;
        assert_eq!(g.next(t0), Next::Decide);
        g.verdict = false;
        assert_eq!(
            g.next(t0 + Duration::from_millis(1999)),
            Next::Wait(g.deadline())
        );
        assert_eq!(g.next(t0 + Duration::from_secs(2)), Next::Expired);
        assert_eq!(g.missing(), "no scan verdict");
        // an unheld process does not wait for the rules
        let g = Gate {
            stopped: false,
            verdict: true,
            spawn_judged: false,
            ..g
        };
        assert_eq!(g.next(t0), Next::Decide);
    }

    #[test]
    fn the_budget_is_clamped() {
        assert_eq!(clamp_budget(0), Duration::from_millis(MIN_BUDGET_MS));
        assert_eq!(clamp_budget(2000), Duration::from_secs(2));
        assert_eq!(clamp_budget(u64::MAX), Duration::from_millis(MAX_BUDGET_MS));
    }
}
