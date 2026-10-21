//! NN-L-EPG — the exploit post-condition guard's findings (lab PR 219,
//! experimental). Issued outside the engine by `process_event`, like
//! NN-L-AT-001: the kernel already responded (enforce mode: `SIGKILL` at the
//! hook, before the task returned to user mode) or deliberately did not
//! (detect mode: the task continues). Neither rule asks the executor for
//! anything.
//!
//! - **NN-L-EPG-001** — credentials (MITRE ATT&CK T1068, Exploitation for
//!   Privilege Escalation): a task that was not fully privileged gained a
//!   uid, a gid, a capability or another user namespace with no
//!   `commit_creds`, or through `commit_creds` on behalf of a system call
//!   that never makes that change.
//! - **NN-L-EPG-002** — namespaces and root (T1611, Escape to Host): its
//!   `nsproxy`, `fs_struct` or root replaced with no mechanism, or by a
//!   mechanism on behalf of a call that never switches them.
//!
//! Both are Critical, except lite's degraded evidence (`baseline_lost`: a
//! task's record was evicted from the task map and re-taken holding
//! privilege nothing attributes to a mechanism), which is High and never
//! refused or killed. The posture trigger (`ExploitPostcondition`, kernel
//! evidence) reaches COMBAT only with corroboration while the guard is
//! experimental (design note, "Response").

use common::{EpgKind, Event, ResponseAction, Severity, Verdict};

use crate::decision::{rules::build_verdict, Rule};

/// Credential post-condition (T1068).
pub struct NnLEpg001CredentialPostcondition;

/// Namespace / root post-condition (T1611).
pub struct NnLEpg002NamespaceRootPostcondition;

pub const EPG_001_ID: &str = "NN-L-EPG-001_CredentialPostcondition";
pub const EPG_002_ID: &str = "NN-L-EPG-002_NamespaceRootPostcondition";

/// The predicate the rules and the posture trigger share.
pub fn is_exploit_postcondition(event: &Event) -> bool {
    matches!(event, Event::ExploitPostcondition { .. })
}

/// The rule that records `event` (`None` for any other event).
pub fn rule_for(event: &Event) -> Option<&'static dyn Rule> {
    match event {
        Event::ExploitPostcondition { kind, .. } if kind.is_credential() => {
            Some(&NnLEpg001CredentialPostcondition)
        }
        Event::ExploitPostcondition { .. } => Some(&NnLEpg002NamespaceRootPostcondition),
        _ => None,
    }
}

/// The response line of the signed record.
pub fn response_line(event: &Event) -> String {
    let Event::ExploitPostcondition {
        killed,
        kill_failed,
        variant,
        caught_at,
        baseline_lost,
        ..
    } = event
    else {
        return String::new();
    };
    let at = caught_at.as_str();
    let v = variant.as_str();
    if *baseline_lost {
        format!(
            "recorded only (degraded evidence: the task's record was lost and re-taken at {at}; \
             exploit guard {v} never refuses or kills for it)"
        )
    } else if *killed && caught_at.is_use_point() {
        format!("refused (-EPERM) and killed in kernel at {at} (exploit guard {v}, enforce)")
    } else if *killed {
        format!(
            "killed in kernel (SIGKILL from {at}, before the return to user mode; exploit guard \
             {v}, enforce)"
        )
    } else if *kill_failed {
        format!(
            "enforce: the kernel could not send SIGKILL from {at} — the task was NOT stopped{}",
            if caught_at.is_use_point() {
                " (the use was refused)"
            } else {
                ""
            }
        )
    } else {
        format!("recorded only (exploit guard {v}, detect, caught at {at}): the task continues")
    }
}

fn mechanisms(bits: u32) -> String {
    use common::epg::mech;
    let mut v = Vec::new();
    if bits & mech::COMMIT_CREDS != 0 {
        v.push("commit_creds");
    }
    if bits & mech::SWITCH_NS != 0 {
        v.push("switch_task_namespaces");
    }
    if bits & mech::SET_FS_ROOT != 0 {
        v.push("set_fs_root");
    }
    if v.is_empty() {
        "none".to_string()
    } else {
        v.join("+")
    }
}

fn verdict(rule: &dyn Rule, event: &Event, technique: &str) -> Option<Verdict> {
    let Event::ExploitPostcondition {
        kind,
        killed,
        kill_failed,
        abi,
        syscall,
        mechanisms: mech_bits,
        before,
        after,
        mnt_ns,
        pid_ns,
        net_ns,
        cred_replaced,
        root_changed,
        fs_changed,
        exit_bypassed,
        injected,
        variant,
        caught_at,
        baseline_lost,
        rebaselined,
        ..
    } = event
    else {
        return None;
    };
    if *baseline_lost {
        return Some(degraded_verdict(rule, event, technique));
    }
    let mut reasoning = String::new();
    if *injected {
        reasoning.push_str(
            "LAB INJECTION (debug build, NN_EPG_INJECT_COMM): no credential, namespace or root \
             changed — ",
        );
    }
    reasoning += &format!(
        "exploit post-condition ({technique}): {} — caught at {} ({}), call {}, mechanisms {}; \
         before [{}] → after [{}]",
        kind.describe(),
        caught_at.as_str(),
        variant.as_str(),
        abi.describe_call(*syscall),
        mechanisms(*mech_bits),
        before.summary(),
        after.summary(),
    );
    if *cred_replaced && kind.is_credential() {
        reasoning.push_str("; another struct cred (pointer replaced)");
    } else if kind.is_credential() && *kind != EpgKind::CredFromSyscall {
        reasoning.push_str("; the same struct cred, written in place");
    }
    if mnt_ns.0 != mnt_ns.1 || pid_ns.0 != pid_ns.1 || net_ns.0 != net_ns.1 {
        reasoning.push_str(&format!(
            "; namespaces mnt {}→{} pid {}→{} net {}→{}",
            mnt_ns.0, mnt_ns.1, pid_ns.0, pid_ns.1, net_ns.0, net_ns.1
        ));
    }
    if *root_changed {
        reasoning.push_str("; filesystem root changed");
    }
    if *fs_changed {
        reasoning.push_str("; fs_struct replaced");
    }
    if *exit_bypassed {
        reasoning.push_str("; the previous call never reached sys_exit");
    }
    if *rebaselined {
        reasoning.push_str(
            "; compared with a snapshot re-taken after the task map lost the task's record \
             (what it held at that re-take was not attributed)",
        );
    }
    reasoning.push_str(if *killed && caught_at.is_use_point() {
        "; the use refused (-EPERM) and SIGKILL sent in kernel"
    } else if *killed {
        "; SIGKILL sent in kernel before the return to user mode"
    } else if *kill_failed {
        "; enforce mode but SIGKILL could not be sent"
    } else {
        "; detect mode: recorded, not stopped"
    });
    reasoning.push_str("; posture → ENGAGED (COMBAT with corroboration)");
    let action = if *killed {
        ResponseAction::KillProcess
    } else {
        ResponseAction::Log
    };
    Some(build_verdict(
        rule,
        event,
        action,
        Severity::Critical,
        &reasoning,
    ))
}

/// Lite's degraded evidence: the task's record was lost (the LRU task map
/// evicted it, or the fork-time insert failed) and re-taken at this hook;
/// the credential it holds there holds privilege, and nothing tells a
/// legitimate change made while the record was missing from a write in
/// place. High, recorded only: the kernel never refuses or kills for it.
fn degraded_verdict(rule: &dyn Rule, event: &Event, technique: &str) -> Verdict {
    let mut reasoning = String::from(
        "DEGRADED EVIDENCE — the exploit guard's task map lost this task's record and re-took \
         it here: ",
    );
    if let Event::ExploitPostcondition {
        abi,
        syscall,
        after,
        variant,
        caught_at,
        ..
    } = event
    {
        reasoning += &format!(
            "at {} ({}), call {}, the task holds [{}], privilege that no mechanism the guard saw \
             gave it — a legitimate change made while the record was missing, or a credential \
             written in place ({technique}); not established as an exploit. Never refused or \
             killed for this (an eviction a flood can cause must not stop legitimate tasks); \
             the loss is counted and attested (nn-admin status --key: task records lost). Look for \
             what filled the task map (a burst of tasks) and what this task did next",
            caught_at.as_str(),
            variant.as_str(),
            abi.describe_call(*syscall),
            after.summary(),
        );
    }
    reasoning.push_str("; posture → ENGAGED (COMBAT with corroboration)");
    build_verdict(rule, event, ResponseAction::Log, Severity::High, &reasoning)
}

impl Rule for NnLEpg001CredentialPostcondition {
    fn id(&self) -> &'static str {
        EPG_001_ID
    }
    fn name(&self) -> &'static str {
        "Credentials gained without a legitimate kernel transition"
    }
    fn category(&self) -> &'static str {
        "privilege_escalation"
    }
    fn evaluate(&self, event: &Event) -> Option<Verdict> {
        match event {
            Event::ExploitPostcondition { kind, .. } if kind.is_credential() => {
                verdict(self, event, "T1068")
            }
            _ => None,
        }
    }
}

impl Rule for NnLEpg002NamespaceRootPostcondition {
    fn id(&self) -> &'static str {
        EPG_002_ID
    }
    fn name(&self) -> &'static str {
        "Namespaces or root left without a legitimate kernel transition"
    }
    fn category(&self) -> &'static str {
        "escape_to_host"
    }
    fn evaluate(&self, event: &Event) -> Option<Verdict> {
        match event {
            Event::ExploitPostcondition { kind, .. } if !kind.is_credential() => {
                verdict(self, event, "T1611")
            }
            _ => None,
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use common::{CredView, SyscallAbi};

    pub(crate) fn epg_event(kind: EpgKind, killed: bool) -> Event {
        let user = CredView {
            uid: 1000,
            gid: 1000,
            suid: 1000,
            sgid: 1000,
            euid: 1000,
            egid: 1000,
            fsuid: 1000,
            fsgid: 1000,
            cap_permitted: 0,
            cap_effective: 0,
            user_ns: 4026531837,
        };
        let mut root = user;
        root.uid = 0;
        root.euid = 0;
        root.fsuid = 0;
        Event::ExploitPostcondition {
            kind,
            killed,
            kill_failed: false,
            pid: 4242,
            tid: 4242,
            uid: 1000,
            comm: "credflip".to_string(),
            abi: SyscallAbi::X64,
            syscall: common::epg::nr::WRITE,
            mechanisms: 0,
            before: user,
            after: root,
            mnt_ns: (4026531841, 4026531841),
            pid_ns: (4026531836, 4026531836),
            net_ns: (4026531840, 4026531840),
            cred_replaced: false,
            root_changed: false,
            fs_changed: false,
            exit_bypassed: false,
            timestamp_ns: 7,
            injected: false,
            variant: common::GuardVariant::Strict,
            caught_at: common::CatchPoint::SysExit,
            baseline_lost: false,
            rebaselined: false,
        }
    }

    /// Lab PR 219: an in-place credential write in detect mode is a
    /// Critical NN-L-EPG-001 Log (recorded, the task continues), with the
    /// call, the ids before and after and T1068 in the reasoning.
    #[test]
    fn credential_write_in_detect_mode_is_a_critical_log() {
        let ev = epg_event(EpgKind::CredNoMechanism, false);
        let v = NnLEpg001CredentialPostcondition
            .evaluate(&ev)
            .expect("fires");
        assert_eq!(v.rule_id, EPG_001_ID);
        assert_eq!(v.severity, Severity::Critical);
        assert_eq!(v.action, ResponseAction::Log);
        assert_eq!(v.event_pid, 4242, "attributed to the task");
        for want in [
            "T1068",
            "write (1)",
            "uid=1000",
            "uid=0",
            "written in place",
            "detect mode",
        ] {
            assert!(v.reasoning.contains(want), "{want}: {}", v.reasoning);
        }
        assert!(NnLEpg002NamespaceRootPostcondition.evaluate(&ev).is_none());
        assert_eq!(rule_for(&ev).map(|r| r.id()), Some(EPG_001_ID));
        assert!(
            response_line(&ev).contains("strict, detect, caught at sys_exit"),
            "{}",
            response_line(&ev)
        );
    }

    /// Enforce mode: the kernel killed the task; the verdict says so and the
    /// record's response line does too. Nothing is left for the executor.
    #[test]
    fn enforce_kill_is_recorded_as_a_kernel_kill() {
        let mut ev = epg_event(EpgKind::CredFromSyscall, true);
        if let Event::ExploitPostcondition {
            syscall,
            mechanisms,
            cred_replaced,
            ..
        } = &mut ev
        {
            *syscall = common::epg::nr::IOCTL;
            *mechanisms = common::epg::mech::COMMIT_CREDS;
            *cred_replaced = true;
        }
        let v = NnLEpg001CredentialPostcondition
            .evaluate(&ev)
            .expect("fires");
        assert_eq!(v.severity, Severity::Critical);
        assert_eq!(v.action, ResponseAction::KillProcess);
        for want in [
            "ioctl (16)",
            "commit_creds",
            "pointer replaced",
            "SIGKILL sent in kernel",
        ] {
            assert!(v.reasoning.contains(want), "{want}: {}", v.reasoning);
        }
        assert!(response_line(&ev).starts_with("killed in kernel"));
    }

    /// Lab PR 219, lite: a write in place caught at its first capable(),
    /// refused and killed in enforce; the record names the mode and the use
    /// point.
    #[test]
    fn lite_use_point_records_name_the_mode_and_the_point() {
        let mut ev = epg_event(EpgKind::CredNoMechanism, true);
        if let Event::ExploitPostcondition {
            variant, caught_at, ..
        } = &mut ev
        {
            *variant = common::GuardVariant::Lite;
            *caught_at = common::CatchPoint::Capable;
        }
        let v = NnLEpg001CredentialPostcondition
            .evaluate(&ev)
            .expect("fires");
        assert_eq!(v.severity, Severity::Critical);
        assert_eq!(v.action, ResponseAction::KillProcess);
        for want in ["caught at capable() (lite)", "refused (-EPERM)"] {
            assert!(v.reasoning.contains(want), "{want}: {}", v.reasoning);
        }
        assert_eq!(
            response_line(&ev),
            "refused (-EPERM) and killed in kernel at capable() (exploit guard lite, enforce)"
        );
        if let Event::ExploitPostcondition {
            killed, caught_at, ..
        } = &mut ev
        {
            *killed = false;
            *caught_at = common::CatchPoint::Exec;
        }
        assert!(
            response_line(&ev).contains("lite, detect, caught at exec"),
            "{}",
            response_line(&ev)
        );
    }

    /// A namespace or root finding is NN-L-EPG-002 (T1611), Critical.
    #[test]
    fn namespace_escape_is_epg_002() {
        let mut ev = epg_event(EpgKind::NsNoMechanism, false);
        if let Event::ExploitPostcondition {
            mnt_ns,
            after,
            before,
            root_changed,
            ..
        } = &mut ev
        {
            *mnt_ns = (4026532500, 4026531841);
            *after = *before;
            *root_changed = true;
        }
        let v = NnLEpg002NamespaceRootPostcondition
            .evaluate(&ev)
            .expect("fires");
        assert_eq!(v.rule_id, EPG_002_ID);
        assert_eq!(v.severity, Severity::Critical);
        assert_eq!(v.action, ResponseAction::Log);
        for want in [
            "T1611",
            "mnt 4026532500→4026531841",
            "filesystem root changed",
        ] {
            assert!(v.reasoning.contains(want), "{want}: {}", v.reasoning);
        }
        assert!(NnLEpg001CredentialPostcondition.evaluate(&ev).is_none());
        for k in [
            EpgKind::NsFromSyscall,
            EpgKind::RootNoMechanism,
            EpgKind::RootFromSyscall,
            EpgKind::FsSwapped,
        ] {
            assert_eq!(
                rule_for(&epg_event(k, false)).map(|r| r.id()),
                Some(EPG_002_ID)
            );
        }
        for k in [
            EpgKind::CredNoMechanism,
            EpgKind::CredFromSyscall,
            EpgKind::CredBetweenSyscalls,
            EpgKind::CredOutsideSyscall,
            EpgKind::Unknown(200),
        ] {
            assert_eq!(
                rule_for(&epg_event(k, false)).map(|r| r.id()),
                Some(EPG_001_ID)
            );
        }
    }

    #[test]
    fn a_failed_kill_is_not_reported_as_one() {
        let mut ev = epg_event(EpgKind::CredBetweenSyscalls, false);
        if let Event::ExploitPostcondition {
            kill_failed,
            exit_bypassed,
            ..
        } = &mut ev
        {
            *kill_failed = true;
            *exit_bypassed = true;
        }
        let v = NnLEpg001CredentialPostcondition
            .evaluate(&ev)
            .expect("fires");
        assert_eq!(v.action, ResponseAction::Log);
        assert!(v.reasoning.contains("could not be sent"), "{}", v.reasoning);
        assert!(
            v.reasoning.contains("never reached sys_exit"),
            "{}",
            v.reasoning
        );
        assert!(response_line(&ev).contains("NOT stopped"));
    }

    /// Lab PR 219, lite on an LRU task map: a record evicted and re-taken
    /// holding privilege is degraded evidence — NN-L-EPG-001 at High, Log,
    /// whatever the response mode, saying what is and is not known; a later
    /// finding against the re-taken snapshot stays Critical and says where
    /// its `before` came from.
    #[test]
    fn a_lost_baseline_is_degraded_evidence() {
        let mut ev = epg_event(EpgKind::CredNoMechanism, false);
        if let Event::ExploitPostcondition {
            before,
            after,
            variant,
            caught_at,
            baseline_lost,
            rebaselined,
            ..
        } = &mut ev
        {
            *before = *after;
            *variant = common::GuardVariant::Lite;
            *caught_at = common::CatchPoint::Capable;
            *baseline_lost = true;
            *rebaselined = true;
        }
        let v = NnLEpg001CredentialPostcondition
            .evaluate(&ev)
            .expect("fires");
        assert_eq!(v.rule_id, EPG_001_ID);
        assert_eq!(v.severity, Severity::High);
        assert_eq!(v.action, ResponseAction::Log);
        for want in [
            "DEGRADED EVIDENCE",
            "lost this task's record",
            "capable() (lite)",
            "uid=0",
            "not established as an exploit",
            "Never refused or killed",
            "T1068",
        ] {
            assert!(v.reasoning.contains(want), "{want}: {}", v.reasoning);
        }
        assert!(NnLEpg002NamespaceRootPostcondition.evaluate(&ev).is_none());
        assert!(
            response_line(&ev).starts_with("recorded only (degraded evidence"),
            "{}",
            response_line(&ev)
        );
        assert!(is_exploit_postcondition(&ev), "the posture still sees it");

        // later, a gain against the re-taken snapshot: full evidence
        let mut ev = epg_event(EpgKind::CredNoMechanism, true);
        if let Event::ExploitPostcondition {
            variant,
            caught_at,
            rebaselined,
            ..
        } = &mut ev
        {
            *variant = common::GuardVariant::Lite;
            *caught_at = common::CatchPoint::FileOpen;
            *rebaselined = true;
        }
        let v = NnLEpg001CredentialPostcondition
            .evaluate(&ev)
            .expect("fires");
        assert_eq!(v.severity, Severity::Critical);
        assert_eq!(v.action, ResponseAction::KillProcess);
        assert!(
            v.reasoning.contains("re-taken after the task map lost"),
            "{}",
            v.reasoning
        );
        assert!(!v.reasoning.contains("DEGRADED"), "{}", v.reasoning);
    }

    /// The lab's injected anomaly says so first, so no reader takes it for
    /// a real finding.
    #[test]
    fn an_injected_anomaly_is_marked() {
        let mut ev = epg_event(EpgKind::CredNoMechanism, false);
        if let Event::ExploitPostcondition { injected, .. } = &mut ev {
            *injected = true;
        }
        let v = NnLEpg001CredentialPostcondition
            .evaluate(&ev)
            .expect("fires");
        assert!(v.reasoning.starts_with("LAB INJECTION"), "{}", v.reasoning);
    }

    #[test]
    fn other_events_are_not_the_guards() {
        let ev = crate::decision::rules::testutil::spawn("sudo", "/usr/bin/sudo");
        assert!(rule_for(&ev).is_none());
        assert!(!is_exploit_postcondition(&ev));
        assert!(NnLEpg001CredentialPostcondition.evaluate(&ev).is_none());
        assert!(NnLEpg002NamespaceRootPostcondition.evaluate(&ev).is_none());
    }
}
