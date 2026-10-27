//! Lab PR 225 (CM-16): the ransomware rules, over the shared
//! [`RansomTracker`](crate::impact::RansomTracker).
//!
//! | Id | Event | Fires when | Action / severity |
//! |---|---|---|---|
//! | NN-L-IMP-001 | `MassWrite`, `FileBurst` | two shapes of ransomware for one actor within the window (decisive) | KillProcessTree of the actor, held behind the per-rule policy (Log until it is on) / Critical |
//! | NN-L-IMP-002 | `FileBurst` (renames) | a burst of renames to one new extension of an encryptor's shape, alone | Log / High |
//!
//! NN-L-IMP-001's kill is new (lab PR 225): by the decision of 21/10/2026
//! it is held behind the per-rule response policy
//! ([`response_policy::IMP_001_KILL`], off by default) — a Critical record,
//! action `Log` — and so is its posture trigger's COMBAT without
//! corroboration.
//!
//! ATT&CK v20: T1486 (Data Encrypted for Impact), tactic Impact (TA0040).
//! The single shapes keep their level: the rewrites raise the posture's
//! mass-write arm (ENGAGED) and no verdict, the deletions nothing.

use std::sync::Arc;

use nn_model::{Event, ResponseAction, Severity, Verdict};

use crate::decision::attack::{AttackRef, Tactic};
use crate::decision::host::DecisionHost;
use crate::decision::response_policy::{self, PolicySwitch};
use crate::decision::Rule;
use crate::impact::RansomTracker;

/// ATT&CK v20 technique of both rules.
pub const ATTACK_T1486: &str = "T1486";

/// Lab PR 221's typed mapping of both rules: Impact / T1486.
const ATTACK: &[AttackRef] = &[AttackRef::new(Tactic::Impact, ATTACK_T1486)];

fn burst_of(event: &Event) -> Option<(&str, u64)> {
    match event {
        Event::MassWrite {
            filename,
            timestamp_ns,
            ..
        }
        | Event::FileBurst {
            filename,
            timestamp_ns,
            ..
        } => Some((filename.as_str(), *timestamp_ns)),
        _ => None,
    }
}

/// NN-L-IMP-001: the decisive combination.
pub struct NnLImp001RansomwareEncryption<H: DecisionHost> {
    tracker: Arc<RansomTracker<H>>,
    /// The kill of the actor's tree ([`response_policy::IMP_001_KILL`]).
    kill: PolicySwitch,
}

impl<H: DecisionHost> NnLImp001RansomwareEncryption<H> {
    pub fn new(tracker: Arc<RansomTracker<H>>) -> Self {
        Self {
            tracker,
            kill: response_policy::IMP_001_KILL,
        }
    }

    /// This rule with its kill switch set to `kill` (tests; the per-rule
    /// policy in Phase 2).
    pub fn with_kill(self, kill: PolicySwitch) -> Self {
        Self { kill, ..self }
    }
}

impl<H: DecisionHost> Rule for NnLImp001RansomwareEncryption<H> {
    fn id(&self) -> &'static str {
        "NN-L-IMP-001_RansomwareEncryption"
    }
    fn name(&self) -> &'static str {
        "Ransomware encryption: two shapes of one process tree"
    }
    fn category(&self) -> &'static str {
        "impact_ransomware"
    }
    fn attack(&self) -> &'static [AttackRef] {
        ATTACK
    }
    fn evaluate(&self, event: &Event) -> Option<Verdict> {
        let (file, ts) = burst_of(event)?;
        let a = self.tracker.assess(event)?;
        if !a.decisive {
            return None;
        }
        Some(self.kill.hold(Verdict {
            rule_id: self.id().to_string(),
            rule_name: self.name().to_string(),
            category: self.category().to_string(),
            action: ResponseAction::KillProcessTree,
            severity: Severity::Critical,
            reasoning: format!(
                "Ransomware encryption (ATT&CK {ATTACK_T1486}): {} by {} (pid {}, writer \
                 pid {}; {}). Two shapes of one actor within {} s: kill its process tree",
                a.describe(),
                a.program,
                a.actor,
                a.writer,
                a.why,
                crate::impact::RANSOM_WINDOW_NS / 1_000_000_000
            ),
            event_pid: a.actor,
            event_filename: file.to_string(),
            timestamp_ns: ts,
        }))
    }
}

/// NN-L-IMP-002: a burst of renames to one new extension, of an
/// encryptor's shape, as the only shape so far — a record.
pub struct NnLImp002RenameExtensionBurst<H: DecisionHost> {
    tracker: Arc<RansomTracker<H>>,
}

impl<H: DecisionHost> NnLImp002RenameExtensionBurst<H> {
    pub fn new(tracker: Arc<RansomTracker<H>>) -> Self {
        Self { tracker }
    }
}

impl<H: DecisionHost> Rule for NnLImp002RenameExtensionBurst<H> {
    fn id(&self) -> &'static str {
        "NN-L-IMP-002_RenameExtensionBurst"
    }
    fn name(&self) -> &'static str {
        "Burst of renames to a new extension"
    }
    fn category(&self) -> &'static str {
        "impact_ransomware"
    }
    fn attack(&self) -> &'static [AttackRef] {
        ATTACK
    }
    fn evaluate(&self, event: &Event) -> Option<Verdict> {
        if !matches!(
            event,
            Event::FileBurst {
                kind: nn_model::FileBurstKind::RenameExtension,
                ..
            }
        ) {
            return None;
        }
        let (file, ts) = burst_of(event)?;
        let a = self.tracker.assess(event)?;
        if !a.rename_burst || a.decisive || a.trusted.is_some() {
            return None;
        }
        Some(Verdict {
            rule_id: self.id().to_string(),
            rule_name: self.name().to_string(),
            category: self.category().to_string(),
            action: ResponseAction::Log,
            severity: Severity::High,
            reasoning: format!(
                "Burst of renames to a new extension (ATT&CK {ATTACK_T1486}): {} by {} (pid {}; \
                 {}). One shape of ransomware: recorded; with a second one (rewrites, \
                 ciphertext, deletions) NN-L-IMP-001 kills",
                a.describe(),
                a.program,
                a.actor,
                a.why
            ),
            event_pid: a.writer,
            event_filename: file.to_string(),
            timestamp_ns: ts,
        })
    }
}

/// Both rules, NN-L-IMP-001 first (first match wins).
pub fn impact_rules<H: DecisionHost>(tracker: Arc<RansomTracker<H>>) -> Vec<Box<dyn Rule>> {
    vec![
        Box::new(NnLImp001RansomwareEncryption::new(Arc::clone(&tracker))),
        Box::new(NnLImp002RenameExtensionBurst::new(tracker)),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    // R08b (lab PR 251): on the portable test host.
    use crate::posture::host::testing::TestHost as H;
    type AuthSessionTracker = crate::posture::lineage::AuthSessionTracker<H>;
    type RansomTracker = crate::impact::RansomTracker<H>;
    type ProgramOwners = crate::impact::trust::ProgramOwners<H>;
    type NnLImp001RansomwareEncryption = super::NnLImp001RansomwareEncryption<H>;
    type NnLImp002RenameExtensionBurst = super::NnLImp002RenameExtensionBurst<H>;
    use crate::impact::entropy::{Sample, Sampler};
    use nn_model::FileBurstKind;

    const S: u64 = 1_000_000_000;

    /// Every sampled file is ciphertext-like.
    struct Cipher;
    impl Sampler for Cipher {
        fn sample(&self, _path: &str, _since: std::time::Duration) -> Sample {
            Sample {
                examined: 4,
                high: 4,
                containers: 0,
            }
        }
        fn sample_copies(&self, copy: &str, _: &str, since: std::time::Duration) -> Sample {
            self.sample(copy, since)
        }
    }

    fn tracker() -> (tempfile::TempDir, Arc<RansomTracker>) {
        let t = tempfile::TempDir::new().unwrap();
        let l = AuthSessionTracker::new(t.path());
        l.ingest_exec(200, 1, "/usr/bin/bash", &["bash".into()], S, S, 0);
        l.ingest_exec(
            300,
            200,
            "/usr/bin/python3",
            &["python3".into(), "/srv/nn-malsim/ransom-sim.py".into()],
            2 * S,
            2 * S,
            0,
        );
        let owners = ProgramOwners::new(t.path().join("no-db"));
        (
            t,
            Arc::new(RansomTracker::with(l, owners, Arc::new(Cipher))),
        )
    }

    fn renames(ts: u64) -> Event {
        Event::FileBurst {
            pid: 300,
            uid: 0,
            comm: "python3".into(),
            kind: FileBurstKind::RenameExtension,
            count: 20,
            appended: 20,
            sources: 0,
            filename: "/srv/nn-malsim/f020.locked".into(),
            timestamp_ns: ts,
        }
    }

    /// Lab PR 225: the decisive combination is a Critical verdict on the
    /// actor's tree (here the renames and the ciphertext they left); its
    /// kill is held behind the per-rule policy, off by default.
    #[test]
    fn imp001_kills_the_actors_tree_on_two_shapes() {
        let (_t, tr) = tracker();
        let e = renames(10 * S);
        let held = NnLImp001RansomwareEncryption::new(Arc::clone(&tr))
            .evaluate(&e)
            .expect("decisive");
        assert_eq!(held.action, ResponseAction::Log);
        assert_eq!(held.severity, Severity::Critical);
        assert!(
            held.reasoning.contains("[held back: the kill"),
            "{}",
            held.reasoning
        );
        let (_t, tr) = tracker();
        let v = NnLImp001RansomwareEncryption::new(Arc::clone(&tr))
            .with_kill(response_policy::IMP_001_KILL.enabled())
            .evaluate(&e)
            .expect("decisive");
        assert_eq!(v.rule_id, "NN-L-IMP-001_RansomwareEncryption");
        assert_eq!(v.action, ResponseAction::KillProcessTree);
        assert_eq!(v.severity, Severity::Critical);
        assert_eq!(v.event_pid, 300);
        assert!(v.reasoning.contains("T1486"), "{}", v.reasoning);
        assert!(v.reasoning.contains("ransom-sim.py"), "{}", v.reasoning);
        // IMP-002 stays quiet on a decisive event.
        assert!(NnLImp002RenameExtensionBurst::new(tr)
            .evaluate(&e)
            .is_none());
    }

    /// One shape alone: the rename burst is recorded (Log High), no kill;
    /// a rewrite burst alone draws no verdict (the posture's mass-write
    /// arm keeps it).
    #[test]
    fn imp002_records_a_lone_rename_burst() {
        struct Plain;
        impl Sampler for Plain {
            fn sample(&self, _: &str, _: std::time::Duration) -> Sample {
                Sample::default()
            }
            fn sample_copies(&self, _: &str, _: &str, _: std::time::Duration) -> Sample {
                Sample::default()
            }
        }
        let t = tempfile::TempDir::new().unwrap();
        let l = AuthSessionTracker::new(t.path());
        l.ingest_exec(300, 1, "/home/u/rn", &["rn".into()], S, S, 1000);
        let tr = Arc::new(RansomTracker::with(
            l,
            ProgramOwners::new(t.path().join("no-db")),
            Arc::new(Plain),
        ));
        let e = renames(10 * S);
        assert!(NnLImp001RansomwareEncryption::new(Arc::clone(&tr))
            .evaluate(&e)
            .is_none());
        let v = NnLImp002RenameExtensionBurst::new(Arc::clone(&tr))
            .evaluate(&e)
            .expect("a record");
        assert_eq!(
            (v.action, v.severity),
            (ResponseAction::Log, Severity::High)
        );
        let rewrites = Event::MassWrite {
            pid: 300,
            uid: 1000,
            comm: "rn".into(),
            count: 20,
            filename: "/home/u/x".into(),
            timestamp_ns: 500 * S,
            overwrites: true,
            cgroup_window: false,
        };
        let rules = impact_rules(tr);
        assert!(rules.iter().all(|r| r.evaluate(&rewrites).is_none()));
    }
}
