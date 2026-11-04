//! Lot 278: the posture a rule's built-in kill needs, and every rule that
//! kills in OBSERVING.
//!
//! The engine judges each event in the posture the agent judged it in
//! ([`super::RuleEngine::decide_in`]). A rule of [`KILL_FLOORS`] whose
//! built-in verdict is a kill keeps its severity, its signed record and its
//! ATT&CK mapping below its floor; its action is `Log`, and its reasoning
//! says what was held and why ([`super::response_policy::hold_below_posture`]).
//! A signed per-rule `enforce` gives the kill back in every posture: where
//! the operator's policy says so, the rule kills.
//!
//! **R009** (root exec from a home, `/tmp` or `/var/tmp`) kills from COMBAT
//! up. Its base rate of legitimate matches is that of root automation run
//! from a checkout or an unpacked tree — `install.sh --upgrade`,
//! `uninstall.sh`, Ansible `become` without a terminal, cloud-init, CI —
//! and the script's own exec comes before any window it can open. Holding
//! the kill in OBSERVING only would not end that: any exec from `/tmp`
//! (a build's `conftest`, the installer's own exec from an unpacked tree)
//! raises ENGAGED, for 24 hours (`StagingExec`, never corroboration), so
//! the second run of the same installer would be killed. COMBAT is reached
//! on corroborated or decisive evidence only. The record stays High.
//!
//! **R001 and R003 on root's exec** wait for COMBAT too: a root exec from
//! `/tmp` or `/var/tmp` is R009's to decide (PROC-007: "R009 stays ahead of
//! the staging rules"). They used to reach the same answer through the
//! legacy ceiling under R009's first match; held by the posture on their
//! own, their record is the same whatever order a late chain completion
//! takes on the bus. A non-root exec from those directories is killed as
//! before, in every posture.
//!
//! This is the decision of 03/11/2026 (`docs/operator/RULE_POLICY.md` §1,
//! "Decision record"): for these three cases only, it changes the decision
//! of 21/10/2026 and external audit POS-015. A posture hold counts as a
//! switch's for the legacy first match ([`super::combine::apply_policy`]):
//! it never stands in for another rule's kill of the same exec (R011–R013
//! and R017 kill a root exec from `/tmp` or a home in every posture).
//!
//! **Every other kill in OBSERVING** is listed in [`OBSERVING_KILLS`], with
//! why it may run there: the kills that existed before Wave 4 (lab PR 214),
//! which the founder-delegated decision of 21/10/2026 kept as they were
//! (`response_policy`: "A kill that existed before (same rule, same match)
//! is not held"; rule kills are orthogonal to the posture,
//! `docs/design/POSTURE_FSM_V2_REDESIGN.md` §6, and R001..R003 kill "whatever
//! the posture", external audit POS-015); and the two Wave 4 rules whose
//! kill is an opt-in the operator makes (the exploit guard's kernel kill in
//! enforce mode, the exec quarantine's). Every kill Wave 4 added to a rule
//! is held by a switch in every posture until the signed policy enables it
//! (`response_policy`). A test holds the list to the rule catalogue: a new
//! rule that can kill must be classified here.

use nn_model::posture_types::PostureKind;
use nn_model::{Event, ResponseAction, Verdict};

use super::response_policy::hold_below_posture;

/// R009's id.
pub const R009_ID: &str = "R009_RootExecFromUserPath";

/// A rule whose built-in kill runs only from a posture up.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KillFloor {
    pub rule_id: &'static str,
    /// The lowest posture its built-in kill runs in.
    pub floor: PostureKind,
    /// Only the kill of an exec by root (uid 0): the rule kills any other
    /// exec in every posture.
    pub root_only: bool,
    /// What the hold holds, named in the record's reasoning and `held`.
    pub held: &'static str,
}

/// The rules whose built-in kill needs a posture (lot 278).
pub const KILL_FLOORS: &[KillFloor] = &[
    KillFloor {
        rule_id: R009_ID,
        floor: PostureKind::Combat,
        root_only: false,
        held: "the kill of the root exec's process tree (R009, lot 278)",
    },
    KillFloor {
        rule_id: "R001_ExecFromTmp",
        floor: PostureKind::Combat,
        root_only: true,
        held: "the kill of root's exec from /tmp: R009's to decide (lot 278)",
    },
    KillFloor {
        rule_id: "R003_ExecFromVarTmp",
        floor: PostureKind::Combat,
        root_only: true,
        held: "the kill of root's exec from /var/tmp: R009's to decide (lot 278)",
    },
];

/// The floor of `rule_id`'s built-in kill, if it has one.
pub fn kill_floor(rule_id: &str) -> Option<&'static KillFloor> {
    KILL_FLOORS.iter().find(|f| f.rule_id == rule_id)
}

/// `v`, `rule_id`'s verdict on `event` judged in `posture`: as the rule
/// built it, or, for a kill below the rule's floor (of an exec by root, for
/// a floor of root's execs only), held.
pub fn hold(rule_id: &str, v: Verdict, posture: PostureKind, event: &Event) -> Verdict {
    match kill_floor(rule_id) {
        Some(f)
            if is_kill(&v.action)
                && posture < f.floor
                && (!f.root_only || matches!(event, Event::ProcessSpawn { uid: 0, .. })) =>
        {
            hold_below_posture(v, f.held, posture, f.floor)
        }
        _ => v,
    }
}

fn is_kill(a: &ResponseAction) -> bool {
    matches!(
        a,
        ResponseAction::KillProcess | ResponseAction::KillProcessTree
    )
}

/// Why a rule's kill may run in OBSERVING.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObservingKill {
    /// The rule killed before Wave 4 (lab PR 214), and the decision of
    /// 21/10/2026 kept its kill as it was.
    BeforeWave4,
    /// Wave 4: the kernel's own kill, in the mode the operator turns on
    /// (the exploit post-condition guard's enforce mode, lab PR 219: detect
    /// by default). The rule records it; it asks the executor for nothing.
    KernelEnforceOptIn,
    /// Wave 4: the exec quarantine's kill, only with `--exec-quarantine`
    /// (lab PR 223, experimental, off by default).
    ExecQuarantineOptIn,
}

/// Every rule of the catalogue whose verdict can be a kill, but those of
/// [`KILL_FLOORS`] whose every kill has a floor: why its kill may run in
/// OBSERVING (for R001 and R003: a non-root exec's).
pub const OBSERVING_KILLS: &[(&str, ObservingKill)] = {
    use ObservingKill::*;
    &[
        // Process
        ("R001_ExecFromTmp", BeforeWave4),
        ("R002_ExecFromDevShm", BeforeWave4),
        ("R003_ExecFromVarTmp", BeforeWave4),
        ("R004_ExecFromProcSelfFd", BeforeWave4),
        ("R006_ReverseShellTooling", BeforeWave4),
        ("R007_CryptoMiner", BeforeWave4),
        ("R010_BinaryInWebroot", BeforeWave4),
        // Lot 279: the match narrowed to what no package vouches for (a
        // vouched-for load is R011's own record); no kill added.
        ("R011_KernelModuleTooling", BeforeWave4),
        ("R012_SetcapTooling", BeforeWave4),
        ("R013_NamespaceEscapeTooling", BeforeWave4),
        ("R017_ShellFromNonstandardPath", BeforeWave4),
        ("R018_KernelModuleLoad", BeforeWave4),
        ("NN-L-EXECQ-001_FirstSightQuarantine", ExecQuarantineOptIn),
        // File integrity and file access
        ("NN-L-FIM-001_SystemBinaryModified", BeforeWave4),
        ("NN-L-FIM-002_NewSuidBinary", BeforeWave4),
        ("NN-L-FIM-003_SensitiveConfigModified", BeforeWave4),
        ("NN-L-FIM-004_AuthorizedKeysModified", BeforeWave4),
        ("NN-L-FIM-007_CronDropInCreated", BeforeWave4),
        ("NN-L-FIM-008_KernelModuleModified", BeforeWave4),
        ("NN-L-FIM-009_SystemdUnitDropped", BeforeWave4),
        ("NN-L-FIM-010_RansomwareExtensionRename", BeforeWave4),
        ("NN-L-FIM-011_AwsCredsRead", BeforeWave4),
        ("NN-L-FIM-012_AzureCredsRead", BeforeWave4),
        ("NN-L-FIM-013_GcpCredsRead", BeforeWave4),
        ("NN-L-FIM-014_DockerCredsRead", BeforeWave4),
        ("NN-L-FIM-015_BrowserCredsAccessed", BeforeWave4),
        ("NN-L-FIM-016_PasswordManagerDbAccessed", BeforeWave4),
        ("NN-L-FIM-017_GpgKeyringAccessed", BeforeWave4),
        ("NN-L-FIM-018_LastlogTampered", BeforeWave4),
        ("NN-L-FIM-019_WtmpBtmpTampered", BeforeWave4),
        ("NN-L-FIM-021_PamModuleModified", BeforeWave4),
        ("NN-L-FIM-022_LdSoPreloadModified", BeforeWave4),
        ("NN-L-FIM-023_SystemdTimerCreated", BeforeWave4),
        ("NN-L-FIM-024_AntiTamperHoneypotModified", BeforeWave4),
        // Network
        ("NN-L-NET-001_OutboundToBlockedIp", BeforeWave4),
        ("NN-L-NET-002_OutboundToBlockedTld", BeforeWave4),
        ("NN-L-NET-003_BadJa3", BeforeWave4),
        ("NN-L-NET-008_OutboundFromTmpExec", BeforeWave4),
        ("NN-L-NET-010_OutboundToHighRiskC2Port", BeforeWave4),
        ("NN-L-NET-014_DnsTunnelEntropy", BeforeWave4),
        ("NN-L-NET-018_Rfc1918LateralPort", BeforeWave4),
        // Canary, chain, exploit guard
        ("NN-L-CANARY-001_FileAccess", BeforeWave4),
        ("NN-L-CANARY-002_ProcessExec", BeforeWave4),
        ("NN-L-CANARY-003_NetworkConnect", BeforeWave4),
        ("NN-L-CANARY-004_CredentialRead", BeforeWave4),
        ("NN-L-CHAIN-001_CredReadThenEgress", BeforeWave4),
        ("NN-L-CHAIN-002_TmpExecThenEgress", BeforeWave4),
        ("NN-L-CHAIN-003_CanaryThenEgress", BeforeWave4),
        ("NN-L-CHAIN-004_CrossPidCredExfil", BeforeWave4),
        ("NN-L-CHAIN-005_CrossPidTmpC2", BeforeWave4),
        ("NN-L-CHAIN-006_CrossPidCanaryExfil", BeforeWave4),
        ("NN-L-CHAIN-007_TmpCredExfilSequence", BeforeWave4),
        ("NN-L-EPG-001_CredentialPostcondition", KernelEnforceOptIn),
        (
            "NN-L-EPG-002_NamespaceRootPostcondition",
            KernelEnforceOptIn,
        ),
    ]
};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decision::catalogue;
    use crate::decision::response_policy::take_held;
    use nn_model::Severity;

    fn kill(rule: &str) -> Verdict {
        Verdict {
            rule_id: rule.to_string(),
            rule_name: "x".into(),
            category: "x".into(),
            action: ResponseAction::KillProcessTree,
            severity: Severity::High,
            reasoning: "why".into(),
            event_pid: 7,
            event_filename: "/tmp/x".into(),
            timestamp_ns: 1,
        }
    }

    /// Every rule the catalogue says can kill is either held below a floor
    /// in every case or listed, with why its kill may run in OBSERVING —
    /// once; a floor of root's execs only is listed too.
    #[test]
    fn every_rule_that_can_kill_is_classified() {
        let can_kill: std::collections::BTreeSet<&str> = catalogue::docs()
            .filter(|d| d.actions.iter().any(is_kill))
            .map(|d| d.id)
            .collect();
        let mut listed = std::collections::BTreeSet::new();
        for id in KILL_FLOORS
            .iter()
            .filter(|f| !f.root_only)
            .map(|f| f.rule_id)
            .chain(OBSERVING_KILLS.iter().map(|(id, _)| *id))
        {
            assert!(listed.insert(id), "{id} listed twice");
        }
        assert_eq!(can_kill, listed);
        for f in KILL_FLOORS.iter().filter(|f| f.root_only) {
            assert!(
                OBSERVING_KILLS.iter().any(|(id, _)| *id == f.rule_id),
                "{}: its non-root kill runs in OBSERVING",
                f.rule_id
            );
        }
    }

    /// R009's kill runs in COMBAT only; below it the verdict is a held
    /// record (`Log`, High kept) that names the posture, and the engine
    /// learns what was held, by the posture.
    #[test]
    fn r009_kills_in_combat_only() {
        for posture in [
            PostureKind::Observing,
            PostureKind::Alerted,
            PostureKind::Engaged,
        ] {
            take_held();
            let v = hold(R009_ID, kill(R009_ID), posture, &root_exec());
            assert_eq!(v.action, ResponseAction::Log, "{posture}");
            assert_eq!(v.severity, Severity::High);
            assert!(v.reasoning.starts_with("why [held back: the kill"));
            assert!(v.reasoning.contains(&format!("the posture is {posture}")));
            let h = take_held().expect("held");
            assert!(h.by_posture);
            assert_eq!(h.action, ResponseAction::KillProcessTree);
            assert_eq!(h.reasoning, "why");
        }
        take_held();
        let v = hold(R009_ID, kill(R009_ID), PostureKind::Combat, &root_exec());
        assert_eq!(v.action, ResponseAction::KillProcessTree);
        assert!(take_held().is_none());
    }

    /// R001 and R003 wait for COMBAT on root's exec only; no other rule is
    /// held by the posture, and a record stays a record.
    #[test]
    fn only_the_floors_hold() {
        take_held();
        for rule in ["R001_ExecFromTmp", "R003_ExecFromVarTmp"] {
            let v = hold(rule, kill(rule), PostureKind::Observing, &user_exec());
            assert_eq!(v.action, ResponseAction::KillProcessTree, "{rule}");
            assert!(take_held().is_none());
            let v = hold(rule, kill(rule), PostureKind::Engaged, &root_exec());
            assert_eq!(v.action, ResponseAction::Log, "{rule}");
            assert!(take_held().expect("held").by_posture);
            let v = hold(rule, kill(rule), PostureKind::Combat, &root_exec());
            assert_eq!(v.action, ResponseAction::KillProcessTree, "{rule}");
        }
        let v = hold(
            "R002_ExecFromDevShm",
            kill("R002_ExecFromDevShm"),
            PostureKind::Observing,
            &root_exec(),
        );
        assert_eq!(v.action, ResponseAction::KillProcessTree);
        let mut log = kill(R009_ID);
        log.action = ResponseAction::Log;
        let v = hold(R009_ID, log, PostureKind::Observing, &root_exec());
        assert_eq!(v.action, ResponseAction::Log);
        assert_eq!(v.reasoning, "why");
        assert!(take_held().is_none());
    }

    /// A record is never held: `hold_below_posture` leaves a `Log` as it
    /// is and tells the engine nothing.
    #[test]
    fn a_record_is_not_held_below_a_posture() {
        take_held();
        let mut log = kill(R009_ID);
        log.action = ResponseAction::Log;
        let v = crate::decision::response_policy::hold_below_posture(
            log,
            "x",
            PostureKind::Observing,
            PostureKind::Combat,
        );
        assert_eq!(
            (v.action, v.reasoning.as_str()),
            (ResponseAction::Log, "why")
        );
        assert!(take_held().is_none());
    }

    fn root_exec() -> Event {
        crate::decision::rules::testutil::spawn_as(0, "x", "/tmp/x")
    }

    fn user_exec() -> Event {
        crate::decision::rules::testutil::spawn_as(1000, "x", "/tmp/x")
    }
}
