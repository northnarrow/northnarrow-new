//! The trust level (lab PR 218; external review G-12;
//! `docs/operator/BOOT_INTEGRITY.md`, "Trust levels").
//!
//! How far this run's protection is measured, from the boot's own checks:
//!
//! - **L3** — enforcing and verified: `bpf` in the active LSMs, every
//!   mandatory deny hook attached and armed, the deny self-test refused its
//!   signal, the response enforcing, and nothing degraded.
//! - **L2** — enforcing and verified as L3, with at least one degradation
//!   recorded (a sensor on its fallback, an observe hook missing, a stream
//!   not persisted, a capability missing…) or detect-only.
//! - **L1** — enforcement partial or not verified: a mandatory deny hook
//!   missing (a start under the degraded-mode opt-in) or the self-test
//!   inconclusive.
//! - **L0** — no enforcement: `bpf` not in the active LSMs, the self-test's
//!   signal delivered, or no deny hook attached.
//!
//! The host's own hardening (lockdown, Secure Boot, IMA, module signatures)
//! is not in the level: it is listed next to it in the capability manifest
//! ([`super::manifest`]), signed at every boot. The level `nn-admin status
//! --key` shows is recomputed with the degradations recorded since the boot;
//! the manifest keeps the boot's.

use std::sync::OnceLock;

use serde::Serialize;

use super::deny_selftest::SelfTestOutcome;
use super::lsm::BpfLsm;

/// L0 to L3.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub enum TrustLevel {
    L0 = 0,
    L1 = 1,
    L2 = 2,
    L3 = 3,
}

impl TrustLevel {
    pub fn as_u8(self) -> u8 {
        self as u8
    }

    pub fn name(self) -> &'static str {
        match self {
            TrustLevel::L0 => "L0",
            TrustLevel::L1 => "L1",
            TrustLevel::L2 => "L2",
            TrustLevel::L3 => "L3",
        }
    }

    pub fn meaning(self) -> &'static str {
        match self {
            TrustLevel::L0 => "no enforcement",
            TrustLevel::L1 => "enforcement partial or not verified",
            TrustLevel::L2 => "enforcing and verified, degraded",
            TrustLevel::L3 => "enforcing and verified",
        }
    }
}

/// What the boot measured.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TrustInputs {
    pub bpf_lsm: BpfLsm,
    /// Mandatory deny hooks the boot expected (16, plus the optional ones
    /// the kernel has) and attached and armed.
    pub deny_expected: usize,
    pub deny_attached: usize,
    pub self_test: SelfTestOutcome,
    pub detect_only: bool,
}

/// A level and why it is not L3.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Trust {
    pub level: TrustLevel,
    pub reasons: Vec<String>,
}

/// The level of `inputs` with `degradations` recorded.
pub fn compute(inputs: &TrustInputs, degradations: usize) -> Trust {
    let mut level = TrustLevel::L3;
    let mut reasons = Vec::new();
    let mut cap = |at: TrustLevel, why: String| {
        level = level.min(at);
        reasons.push(why);
    };
    match &inputs.bpf_lsm {
        BpfLsm::Absent { list } => cap(
            TrustLevel::L0,
            format!("`bpf` is not in the active LSM list ({list})"),
        ),
        BpfLsm::Unknown { why } => cap(
            TrustLevel::L2,
            format!("the active LSM list could not be read ({why})"),
        ),
        BpfLsm::Active { .. } => {}
    }
    match &inputs.self_test {
        SelfTestOutcome::Denied => {}
        SelfTestOutcome::NotDenied => cap(
            TrustLevel::L0,
            "deny self-test: the signal was delivered — the deny hooks do not run".to_string(),
        ),
        SelfTestOutcome::Inconclusive(why) => cap(
            TrustLevel::L1,
            format!("deny self-test inconclusive: {why}"),
        ),
    }
    if inputs.deny_attached == 0 {
        cap(TrustLevel::L0, "no deny hook attached".to_string());
    } else if inputs.deny_attached < inputs.deny_expected {
        cap(
            TrustLevel::L1,
            format!(
                "{} of {} mandatory deny hooks attached",
                inputs.deny_attached, inputs.deny_expected
            ),
        );
    }
    if inputs.detect_only {
        cap(
            TrustLevel::L2,
            "detect-only: no response action runs".to_string(),
        );
    }
    if degradations > 0 {
        cap(
            TrustLevel::L2,
            format!("{degradations} degradation(s) recorded (nn-admin status --key lists them)"),
        );
    }
    Trust { level, reasons }
}

static BOOT_INPUTS: OnceLock<TrustInputs> = OnceLock::new();

/// The boot's measurements, once, after the self-test.
pub fn set_boot_inputs(inputs: TrustInputs) {
    let _ = BOOT_INPUTS.set(inputs);
}

pub fn boot_inputs() -> Option<&'static TrustInputs> {
    BOOT_INPUTS.get()
}

/// The level now: the boot's measurements and the degradations recorded
/// since. `None` before the self-test ran.
pub fn current() -> Option<Trust> {
    BOOT_INPUTS
        .get()
        .map(|i| compute(i, super::degradation::count()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn verified() -> TrustInputs {
        TrustInputs {
            bpf_lsm: BpfLsm::Active {
                list: "capability,bpf".to_string(),
            },
            deny_expected: 18,
            deny_attached: 18,
            self_test: SelfTestOutcome::Denied,
            detect_only: false,
        }
    }

    #[test]
    fn every_mandatory_hook_attached_and_self_tested_is_l3() {
        let t = compute(&verified(), 0);
        assert_eq!(t.level, TrustLevel::L3);
        assert!(t.reasons.is_empty());
    }

    #[test]
    fn a_degradation_or_detect_only_is_l2() {
        let t = compute(&verified(), 2);
        assert_eq!(t.level, TrustLevel::L2);
        assert!(t.reasons[0].contains("2 degradation"), "{t:?}");
        let mut i = verified();
        i.detect_only = true;
        assert_eq!(compute(&i, 0).level, TrustLevel::L2);
    }

    #[test]
    fn a_missing_deny_hook_or_an_inconclusive_self_test_is_l1() {
        let mut i = verified();
        i.deny_attached = 15;
        let t = compute(&i, 1);
        assert_eq!(t.level, TrustLevel::L1);
        assert!(t.reasons.iter().any(|r| r.contains("15 of 18")), "{t:?}");
        let mut i = verified();
        i.self_test = SelfTestOutcome::Inconclusive("no child".to_string());
        assert_eq!(compute(&i, 0).level, TrustLevel::L1);
    }

    /// External review AR-09 / G-12: hooks attached but not run are no
    /// enforcement, whatever the attach counted.
    #[test]
    fn no_bpf_lsm_or_a_delivered_signal_is_l0() {
        let mut i = verified();
        i.bpf_lsm = BpfLsm::Absent {
            list: "capability,apparmor".to_string(),
        };
        i.self_test = SelfTestOutcome::NotDenied;
        let t = compute(&i, 0);
        assert_eq!(t.level, TrustLevel::L0);
        assert_eq!(t.reasons.len(), 2, "{t:?}");
        let mut i = verified();
        i.self_test = SelfTestOutcome::NotDenied;
        assert_eq!(compute(&i, 0).level, TrustLevel::L0);
        let mut i = verified();
        i.deny_attached = 0;
        assert_eq!(compute(&i, 0).level, TrustLevel::L0);
    }

    #[test]
    fn levels_are_ordered_and_named() {
        assert!(TrustLevel::L0 < TrustLevel::L1 && TrustLevel::L2 < TrustLevel::L3);
        assert_eq!(TrustLevel::L2.as_u8(), 2);
        assert_eq!(TrustLevel::L0.name(), "L0");
    }
}
