//! [`SystemActuator`] — the production [`CombatActuator`]: the
//! side-effecting operations the ladder performs, on the system.
//!
//! It drives the existing [`Executor`](crate::response::Executor) (kill,
//! quarantine, per-PID egress block) and
//! [`NetworkIsolator`](crate::anti_tamper::network_isolate::NetworkIsolator)
//! (full isolation). Detect-only (`--detect-only`) is honoured: the
//! executor already suppresses its own actions and returns
//! [`WouldExecute`](crate::response::ExecutionOutcome::WouldExecute);
//! [`SystemActuator::isolate`] adds the matching guard for the isolator,
//! which has no internal dry-run gate (V1 gated it in `main.rs`).
//!
//! Lab PR 217 (capability C17): NEUTRALIZE and ISOLATE report what they did
//! — per offender ([`NeutralizeReport`]) and per IP family, read back
//! ([`IsolateOutcome`]) — and the ladder signs it.
//!
//! R08c (lab PR 252): the trait and the outcomes are nn-core's
//! (`combat::actuator`, the ladder's), here under their names. This file
//! keeps the Linux actuator — the executor, the isolator, `/proc` — on the
//! agent's host's captures (`ProcRef`), for nn-linux (R09).

use std::sync::Arc;

use tracing::{info, warn};

use nn_model::ResponseAction;

pub use nn_core::combat::actuator::{
    CombatActuator, IsolateOutcome, NeutralizeOutcome, NeutralizeReport, OffenderOutcome, SoftBlock,
};

use super::offender::ProcFacts;
use crate::anti_tamper::network_isolate::NetworkIsolator;
use crate::chain_host_linux::LinuxHost;
use crate::response::journal::{ActionIntent, ActionJournal, ActionResult, Intent};
use crate::response::proc_ref::ProcRef;
use crate::response::quarantine::ExeHandle;
use crate::response::{block_outbound, ExecutionOutcome, ExecutionReport, Executor};

/// Production actuator: real executor + optional network isolator.
///
/// R12c (lab PR 270): every action it carries out — a soft egress block and
/// its release, each offender's kill tree, each binary's quarantine, the
/// isolation — is bracketed by the `actions` chain: a signed intent row
/// before, the outcome after (`journal`). The ladder's own signed stage
/// rows (the audit log: evidence before enforcement, CMB-027) say why.
pub struct SystemActuator {
    executor: Executor,
    isolator: Option<Arc<NetworkIsolator>>,
    detect_only: bool,
    journal: ActionJournal,
}

impl SystemActuator {
    pub fn new(
        executor: Executor,
        isolator: Option<Arc<NetworkIsolator>>,
        detect_only: bool,
        journal: ActionJournal,
    ) -> Self {
        Self {
            executor,
            isolator,
            detect_only,
            journal,
        }
    }

    /// The signed intent of one of the ladder's actions.
    fn intent(&self, response: &str, pid: u32, stage: &str) -> Intent {
        let mut i = ActionIntent::named("combat", response, pid);
        i.severity = "critical".to_string();
        i.why = vec![format!("COMBAT {stage}")];
        self.journal.intent(i)
    }

    /// An executor report as the action's signed outcome.
    fn finish(intent: Intent, report: &ExecutionReport) {
        let (result, text, reason) = crate::response::journal_outcome(report);
        intent.finish(result, text, reason);
    }

    /// Map a kill outcome to "did we contain this offender?". `Killed` /
    /// `AlreadyGone` are containment; `WouldExecute` is detect-only (we
    /// *would* have, and isolation is suppressed too, so don't pretend
    /// uncontainable). Everything else (Refused = below the protection
    /// floor, PermissionDenied = kernel/LSM protected, Failed =
    /// `ETIMEDOUT` still-alive / other) is uncontainable.
    fn contained(outcome: &ExecutionOutcome) -> bool {
        matches!(
            outcome,
            ExecutionOutcome::Killed { .. }
                | ExecutionOutcome::AlreadyGone { .. }
                | ExecutionOutcome::WouldExecute { .. }
        )
    }

    /// External audit CMB-002: why the descendants of a kill tree (its
    /// `additional` outcomes) are not contained, or `None` when every one
    /// is.
    fn tree_not_contained(descendants: &[ExecutionOutcome]) -> Option<String> {
        let mut spared = Vec::new();
        let mut alive = Vec::new();
        let mut truncated = None;
        for o in descendants.iter().filter(|o| !Self::contained(o)) {
            match o {
                ExecutionOutcome::Refused { pid, reason } => {
                    spared.push(format!("{pid} ({reason})"))
                }
                ExecutionOutcome::TreeTruncated { limit, .. } => truncated = Some(*limit),
                other => alive.push(format!("{other:?}")),
            }
        }
        if spared.is_empty() && alive.is_empty() && truncated.is_none() {
            return None;
        }
        let mut parts = Vec::new();
        if !alive.is_empty() {
            parts.push(format!("descendants not killed: {}", alive.join(", ")));
        }
        if !spared.is_empty() {
            parts.push(format!(
                "descendants spared by the host-critical guard: {}",
                spared.join(", ")
            ));
        }
        if let Some(limit) = truncated {
            parts.push(format!(
                "the tree walk stopped at {limit} descendants; the rest were not reached"
            ));
        }
        Some(parts.join("; "))
    }

    /// Lab PR 217 (capability C17): one offender's kill report as its
    /// signed outcome — contained or not, and the kill's outcome or why
    /// not. External audit CMB-002: the whole tree, not only its root. A
    /// descendant still running — not killed, spared by the host-critical
    /// guard, or beyond a walk cut short — is a threat the process level
    /// did not contain. (Lab PR 243: a function of its own, so the golden
    /// replay's host reports through the same words.)
    pub fn kill_outcome(report: &ExecutionReport) -> (bool, String) {
        if !Self::contained(&report.primary) {
            (false, format!("kill outcome {:?}", report.primary))
        } else if let Some(reason) = Self::tree_not_contained(&report.additional) {
            (false, reason)
        } else {
            (
                true,
                format!(
                    "{:?} ({} descendant(s) handled)",
                    report.primary,
                    report.additional.len()
                ),
            )
        }
    }

    /// Review 87: what became of an offender's binary, from the
    /// quarantine's outcome (lab PR 243: a function of its own, as
    /// [`Self::kill_outcome`]).
    pub fn quarantine_text(pid: u32, outcome: &ExecutionOutcome) -> String {
        match outcome {
            ExecutionOutcome::Quarantined { .. } => "quarantined".to_string(),
            // lot 312 (review F1): its inode neutralized in place
            ExecutionOutcome::QuarantinedInPlace {
                detail,
                complete: true,
                ..
            } => format!("quarantined: {detail}"),
            ExecutionOutcome::QuarantinedInPlace { detail, .. } => {
                warn!(
                    target: "combat.actuator",
                    pid,
                    detail = %detail,
                    "NEUTRALIZE: binary quarantine partial (re-exec prevention degraded)"
                );
                format!("partially quarantined: {detail} (re-exec prevention degraded)")
            }
            ExecutionOutcome::AlreadyGone { .. } => "binary already gone".to_string(),
            ExecutionOutcome::WouldExecute { .. } => {
                "detect-only: would be quarantined".to_string()
            }
            other => {
                warn!(
                    target: "combat.actuator",
                    pid,
                    outcome = ?other,
                    "NEUTRALIZE: binary quarantine did not complete (re-exec prevention degraded)"
                );
                format!("NOT quarantined: {other:?} (re-exec prevention degraded)")
            }
        }
    }

    /// Lot 312 (BUG-90): what NEUTRALIZE says of an offender whose binary
    /// it holds no handle to — the process gone before it was opened
    /// (`Ok`), or the open failed (`Err`, said: it read "no binary on disk").
    pub fn no_binary_text(pid: u32, opened: std::io::Result<()>) -> String {
        match opened {
            Ok(()) => NO_BINARY.to_string(),
            Err(e) => {
                warn!(
                    target: "combat.actuator",
                    pid,
                    error = %e,
                    "NEUTRALIZE: the offender's binary could not be opened — not quarantined"
                );
                format!(
                    "NOT quarantined: its binary could not be opened ({e}) (re-exec prevention \
                     degraded)"
                )
            }
        }
    }

    /// External audit CMB-014: what a soft egress block's outcome means for
    /// the ladder (lab PR 243: a function of its own, as
    /// [`Self::kill_outcome`]).
    pub fn soft_block_of(outcome: ExecutionOutcome) -> SoftBlock {
        match outcome {
            ExecutionOutcome::Blocked { .. } => SoftBlock::Blocked,
            ExecutionOutcome::WouldExecute { .. } => SoftBlock::NotNeeded("detect-only"),
            ExecutionOutcome::AlreadyGone { .. } => SoftBlock::NotNeeded("process already exited"),
            ExecutionOutcome::Failed { errno: 0, .. } => {
                SoftBlock::Failed("block failed: nft rejected the drop ruleset".to_string())
            }
            ExecutionOutcome::Failed { errno, .. } => SoftBlock::Failed(format!(
                "block failed: {} — is nftables (`nft`) installed?",
                std::io::Error::from_raw_os_error(errno)
            )),
            other => SoftBlock::Failed(format!("{other:?}")),
        }
    }
}

/// Review 87: an offender whose binary NEUTRALIZE could not take, the
/// process gone before its binary was opened (lab PR 243: named, for the
/// golden replay's host). Lot 312 (BUG-90): it said "no binary on disk",
/// which the binary of an exited process usually is not; one deleted while
/// it ran is now opened and judged by its inode (`binary already gone` once
/// no name of it is left).
pub const NO_BINARY: &str =
    "binary not quarantined: the process exited before NEUTRALIZE could open it";

/// What ISOLATE answers in detect-only (lab PR 243: named, as
/// [`NO_BINARY`]).
pub const DETECT_ONLY_ISOLATE: &str = "detect-only: iptables NOT applied (no enforcement)";

impl CombatActuator<LinuxHost> for SystemActuator {
    /// `/proc/<pid>/exe` and `/proc/<pid>/cgroup`, read while the pidfd
    /// says the process runs and the PID still has its start — checked
    /// again after the reads (the PID cannot change hands before the
    /// process is reaped). Reads only: detect-only reads them too.
    fn describe(&self, target: &ProcRef) -> ProcFacts {
        if !target.still_named_by_pid() {
            return ProcFacts::default();
        }
        let facts = read_proc_facts(std::path::Path::new("/proc"), target.pid());
        if target.still_named_by_pid() {
            facts
        } else {
            ProcFacts::default()
        }
    }

    fn begin_episode(&self) {
        block_outbound::forget_applied_ruleset();
    }

    fn soft_egress_block(&self, target: &ProcRef) -> SoftBlock {
        let pid = target.pid();
        // External audit CMB-004: the cgroup write takes a PID — only
        // while it still names the attributed process.
        if !self.detect_only && !target.still_named_by_pid() {
            if let Some(errno) = target.capture_errno() {
                return SoftBlock::Failed(format!(
                    "the process could not be captured: {}",
                    std::io::Error::from_raw_os_error(errno)
                ));
            }
            return SoftBlock::NotNeeded("process already exited");
        }
        let intent = self.intent("BlockOutbound", pid, "INVESTIGATE: soft egress block");
        let report = self
            .executor
            .execute(ResponseAction::BlockOutbound, pid, &intent);
        Self::finish(intent, &report);
        info!(
            target: "combat.actuator",
            pid,
            outcome = ?report.primary,
            "INVESTIGATE soft egress: per-PID outbound block (host channels preserved)"
        );
        Self::soft_block_of(report.primary)
    }

    fn soft_egress_clear(&self, target: &ProcRef) {
        if self.detect_only {
            return;
        }
        let pid = target.pid();
        if !target.is_live() {
            info!(target: "combat.actuator", pid, "soft egress not released: the process has exited");
            return;
        }
        let intent = self.intent("Release", pid, "stand-down: soft egress released");
        let released =
            block_outbound::release_blocked_pid(pid, target.start_ticks(), self.executor.config());
        match &released {
            Ok(block_outbound::Release::Released) => {
                intent.finish(ActionResult::Success, "released".to_string(), None)
            }
            Ok(block_outbound::Release::Skipped(why)) => intent.finish(
                ActionResult::NotRun,
                "left as it is".to_string(),
                Some((*why).to_string()),
            ),
            Err(e) => intent.finish(
                ActionResult::Failure,
                "release failed".to_string(),
                Some(e.to_string()),
            ),
        }
        if let Ok(r) = &released {
            self.executor.record_release(pid, "blocked", r);
        }
        match released {
            Ok(block_outbound::Release::Released) => {
                info!(target: "combat.actuator", pid, "soft egress released")
            }
            Ok(block_outbound::Release::Skipped(why)) => info!(
                target: "combat.actuator",
                pid,
                why,
                "soft egress not released (left as it is)"
            ),
            Err(e) => {
                warn!(target: "combat.actuator", pid, error = %e, "soft-egress unblock failed")
            }
        }
    }

    fn neutralize(&self, offenders: &[Arc<ProcRef>]) -> NeutralizeReport {
        if offenders.is_empty() {
            // `NeutralizeReport::outcome` says why that is uncontainable.
            return NeutralizeReport::default();
        }

        // Review 87: the binaries are looked up before the kill. After
        // it `/proc/<pid>/exe` is gone, and the quarantine by pid that
        // ran here found nothing every time (AlreadyGone). External audit
        // CMB-001: opened, not named — the inode stays the one the process
        // ran whatever becomes of its path before the quarantine.
        // External audit CMB-004: only while the PID still names the
        // attributed process.
        // Lot 312 (BUG-90): a binary that could not be opened is said so —
        // the error was dropped and read "no binary on disk".
        let binaries: Vec<(u32, std::io::Result<Option<ExeHandle>>)> = offenders
            .iter()
            .map(|r| {
                let exe = if r.still_named_by_pid() {
                    binary_of(r.pid())
                } else {
                    Ok(None)
                };
                (r.pid(), exe)
            })
            .collect();

        // First pass: kill every offending tree. Lab PR 217: an offender
        // that cannot be contained is recorded and the next one is still
        // killed — this returned at the first one, leaving the others
        // running and their binaries in place.
        let mut outcomes: Vec<OffenderOutcome> = Vec::with_capacity(offenders.len());
        for r in offenders {
            let pid = r.pid();
            let intent = self.intent("KillProcessTree", pid, "NEUTRALIZE");
            let report = self
                .executor
                .execute_on(ResponseAction::KillProcessTree, r, &intent);
            Self::finish(intent, &report);
            let (contained, kill) = Self::kill_outcome(&report);
            if contained {
                info!(
                    target: "combat.actuator",
                    pid,
                    outcome = ?report.primary,
                    children = report.additional.len(),
                    "NEUTRALIZE: killed offending process tree"
                );
            } else {
                warn!(
                    target: "combat.actuator",
                    pid,
                    why = %kill,
                    "NEUTRALIZE: offender NOT contained — the other offenders are still handled"
                );
            }
            outcomes.push(OffenderOutcome {
                pid,
                contained,
                kill,
                quarantine: String::new(),
            });
        }

        // Second pass: quarantine the binaries so a surviving parent /
        // supervisor cannot re-exec them — every offender's, contained or
        // not. A quarantine failure does NOT force isolation (a contained
        // process is already dead), but it is in the offender's outcome.
        let mut done: Vec<((u64, u64), u32)> = Vec::new();
        for (slot, (pid, binary)) in outcomes.iter_mut().zip(binaries) {
            let binary = match binary {
                Ok(Some(handle)) => Ok(handle),
                other => Err(Self::no_binary_text(pid, other.map(|_| ()))),
            };
            slot.quarantine = match binary {
                Err(text) => text,
                Ok(handle) => match done.iter().find(|(k, _)| *k == handle.key()) {
                    Some((_, first)) => format!("same binary as pid {first}"),
                    None => {
                        let intent = self.intent("Quarantine", pid, "NEUTRALIZE");
                        let report = self.executor.quarantine_handle(&handle, pid, &intent);
                        Self::finish(intent, &report);
                        done.push((handle.key(), pid));
                        Self::quarantine_text(pid, &report.primary)
                    }
                },
            };
        }

        NeutralizeReport {
            offenders: outcomes,
        }
    }

    fn isolate(&self) -> IsolateOutcome {
        if self.detect_only {
            warn!(
                target: "combat.actuator",
                "DETECT-ONLY: STAGE 3 reached — would engage full network isolation; \
                 iptables NOT applied (no enforcement)"
            );
            return IsolateOutcome::NotApplied(DETECT_ONLY_ISOLATE.to_string());
        }
        match &self.isolator {
            Some(iso) => {
                let intent = self.intent("Isolate", 0, "ISOLATE");
                let report = iso.engage(&intent);
                let (result, reason) = if report.complete() {
                    (ActionResult::Success, None)
                } else if report.engaged() {
                    (
                        ActionResult::Partial,
                        Some("a family is not isolated (the ladder retries)".to_string()),
                    )
                } else {
                    (
                        ActionResult::Failure,
                        Some("the host is not isolated (the ladder retries)".to_string()),
                    )
                };
                intent.finish(result, report.summary("isolated"), reason);
                if !report.engaged() {
                    tracing::error!(
                        target: "combat.actuator",
                        outcome = %report.summary("isolated"),
                        "COMBAT isolate failed — the host is NOT isolated (the ladder retries)"
                    );
                } else if !report.complete() {
                    tracing::error!(
                        target: "combat.actuator",
                        outcome = %report.summary("isolated"),
                        "COMBAT isolate partial — a family is NOT isolated (the ladder retries)"
                    );
                }
                IsolateOutcome::Applied(report)
            }
            None => {
                warn!(
                    target: "combat.actuator",
                    "STAGE 3 reached but no network isolator configured — cannot isolate \
                     (dev build without /etc/northnarrow/ provisioned)"
                );
                IsolateOutcome::NotApplied(
                    "no network isolator in this build (combat ruleset not provisioned)"
                        .to_string(),
                )
            }
        }
    }

    fn is_dry_run(&self) -> bool {
        self.detect_only
    }
}

/// Lab PR 245: what `<proc_root>/<pid>` says of a process the ladder
/// attributes — `exe` as the kernel resolves it (` (deleted)` kept) and the
/// cgroup that places it ([`super::offender::cgroup_path`]), each within
/// [`super::offender::MAX_PATH_SHOWN`] bytes. The caller makes sure the pid
/// still names the process it means (a pidfd, checked after the reads).
pub fn read_proc_facts(proc_root: &std::path::Path, pid: u32) -> ProcFacts {
    use super::offender::{cgroup_path, shown};
    let dir = proc_root.join(pid.to_string());
    let exe = std::fs::read_link(dir.join("exe"))
        .ok()
        .map(|p| shown(&p.to_string_lossy()));
    let cgroup = crate::state_read::read_state(dir.join("cgroup"))
        .ok()
        .and_then(|text| cgroup_path(&text).map(shown));
    ProcFacts { exe, cgroup }
}

/// Review 87: the file a process runs, opened before it is killed.
/// `Ok(None)` once it has exited. Lot 312 (BUG-90): a binary deleted while
/// it ran is opened too — the quarantine decides on its inode whether any
/// name of it is left — and an error is kept, not read as "none".
fn binary_of(pid: u32) -> std::io::Result<Option<ExeHandle>> {
    ExeHandle::of_pid(pid)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::response::config::ExecutorConfig;

    /// Lab PR 245: the executable and the cgroup as `/proc` gives them; a
    /// deleted binary keeps its suffix; a pid with nothing to read gives
    /// nothing.
    #[test]
    fn proc_facts_read_the_exe_and_the_cgroup() {
        let tmp = tempfile::TempDir::new().unwrap();
        let d = tmp.path().join("4242");
        std::fs::create_dir_all(&d).unwrap();
        std::os::unix::fs::symlink("/tmp/.x/payload (deleted)", d.join("exe")).unwrap();
        std::fs::write(d.join("cgroup"), "0::/system.slice/apache2.service\n").unwrap();
        let f = read_proc_facts(tmp.path(), 4242);
        assert_eq!(f.exe.as_deref(), Some("/tmp/.x/payload (deleted)"));
        assert_eq!(f.cgroup.as_deref(), Some("/system.slice/apache2.service"));
        assert_eq!(read_proc_facts(tmp.path(), 4243), ProcFacts::default());
    }

    /// Lot 311: a cgroup a user named with bytes that are not UTF-8 (in the
    /// subtree systemd delegates to it) is still shown in the ladder's row,
    /// its bytes replaced. On main the read failed and the row had none.
    #[test]
    fn proc_facts_show_a_cgroup_whose_name_is_not_utf8() {
        let tmp = tempfile::TempDir::new().unwrap();
        let d = tmp.path().join("4242");
        std::fs::create_dir_all(&d).unwrap();
        std::fs::write(
            d.join("cgroup"),
            b"0::/user.slice/user-1000.slice/user@1000.service/app.slice/\xff\xfe.scope\n",
        )
        .unwrap();
        let f = read_proc_facts(tmp.path(), 4242);
        assert_eq!(
            f.cgroup.as_deref(),
            Some("/user.slice/user-1000.slice/user@1000.service/app.slice/\u{fffd}\u{fffd}.scope")
        );
    }

    /// External audit CMB-002: a tree is contained only when every
    /// descendant is — not killed, spared by the guard, or past a walk cut
    /// short each make it uncontainable, with the cause in the reason.
    #[test]
    fn tree_containment_counts_every_descendant() {
        use ExecutionOutcome as O;
        assert_eq!(
            SystemActuator::tree_not_contained(&[
                O::Killed { pid: 8 },
                O::AlreadyGone { pid: 9 },
                O::WouldExecute { pid: 10 }
            ]),
            None
        );
        let r = SystemActuator::tree_not_contained(&[
            O::Killed { pid: 8 },
            O::PermissionDenied { pid: 9, errno: 1 },
        ])
        .unwrap();
        assert!(r.contains("not killed") && r.contains("pid: 9"), "{r}");
        let r = SystemActuator::tree_not_contained(&[O::Refused {
            pid: 11,
            reason: "ssh-service(sshd)",
        }])
        .unwrap();
        assert!(
            r.contains("spared") && r.contains("11 (ssh-service(sshd))"),
            "{r}"
        );
        let r = SystemActuator::tree_not_contained(&[
            O::Killed { pid: 8 },
            O::TreeTruncated {
                pid: 7,
                limit: 1000,
            },
        ])
        .unwrap();
        assert!(r.contains("stopped at 1000"), "{r}");
    }

    /// External audit CMB-002: the root killed while a descendant lives
    /// on is not "contained" — here the guard spares the child.
    #[test]
    fn neutralize_escalates_when_a_descendant_survives() {
        let tmp = tempfile::TempDir::new().unwrap();
        let mut parent = std::process::Command::new("sh")
            .args(["-c", "sleep 60 & echo $!; wait"])
            .stdout(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        let mut line = String::new();
        std::io::BufRead::read_line(
            &mut std::io::BufReader::new(parent.stdout.take().unwrap()),
            &mut line,
        )
        .unwrap();
        let child: u32 = line.trim().parse().unwrap();
        let cfg = ExecutorConfig {
            dry_run: false,
            ..ExecutorConfig::for_test(&tmp.path().join("state"))
        };
        let exec = Executor::with_config(cfg);
        exec.set_tree_guard(std::sync::Arc::new(move |pid: u32| {
            (pid == child).then_some(crate::response::kill::Spare::process("test-guard"))
        }));
        let actuator = SystemActuator::new(exec, None, false, ActionJournal::memory());
        let outcome = actuator
            .neutralize(&[Arc::new(ProcRef::open(parent.id()))])
            .outcome();
        let _ = parent.wait();
        // SAFETY: plain kill(2) on our own child.
        unsafe { libc::kill(child as i32, libc::SIGKILL) };
        match outcome {
            NeutralizeOutcome::Uncontainable { reason } => {
                assert!(
                    reason.contains(&format!("{child} (test-guard)")),
                    "{reason}"
                )
            }
            other => panic!("a surviving descendant must not count as contained: {other:?}"),
        }
    }

    /// Lab PR 217 (capability C17): the first offender cannot be contained
    /// (the guard spares its child) — the second is still killed, and the
    /// report has an outcome for each. NEUTRALIZE used to return at the
    /// first one: the second kept running and nothing recorded it.
    #[test]
    fn neutralize_handles_every_offender_past_one_it_cannot_contain() {
        let tmp = tempfile::TempDir::new().unwrap();
        let mut first = std::process::Command::new("sh")
            .args(["-c", "sleep 60 & echo $!; wait"])
            .stdout(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        let mut line = String::new();
        std::io::BufRead::read_line(
            &mut std::io::BufReader::new(first.stdout.take().unwrap()),
            &mut line,
        )
        .unwrap();
        let spared: u32 = line.trim().parse().unwrap();
        let mut second = std::process::Command::new("sleep")
            .arg("60")
            .spawn()
            .unwrap();
        let cfg = ExecutorConfig {
            dry_run: false,
            ..ExecutorConfig::for_test(&tmp.path().join("state"))
        };
        let exec = Executor::with_config(cfg);
        exec.set_tree_guard(std::sync::Arc::new(move |pid: u32| {
            (pid == spared).then_some(crate::response::kill::Spare::process("test-guard"))
        }));
        let actuator = SystemActuator::new(exec, None, false, ActionJournal::memory());
        let report = actuator.neutralize(&[
            Arc::new(ProcRef::open(first.id())),
            Arc::new(ProcRef::open(second.id())),
        ]);
        let _ = first.wait();
        // the second offender was killed: it is reaped at once
        let mut reaped = None;
        for _ in 0..200 {
            reaped = second.try_wait().unwrap();
            if reaped.is_some() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        if reaped.is_none() {
            let _ = second.kill();
        }
        // SAFETY: plain kill(2) on our own grandchild.
        unsafe { libc::kill(spared as i32, libc::SIGKILL) };
        assert!(
            reaped.is_some(),
            "the second offender must be killed: {report:?}"
        );
        assert_eq!(report.offenders.len(), 2, "{report:?}");
        assert!(!report.offenders[0].contained, "{report:?}");
        assert!(
            report.offenders[0]
                .kill
                .contains(&format!("{spared} (test-guard)")),
            "{report:?}"
        );
        assert!(report.offenders[1].contained, "{report:?}");
        assert_eq!(report.offenders[1].pid, second.id());
        match report.outcome() {
            NeutralizeOutcome::Uncontainable { reason } => {
                assert!(
                    reason.starts_with(&format!("pid {}:", first.id())),
                    "{reason}"
                );
                assert!(
                    !reason.contains(&format!("pid {}:", second.id())),
                    "{reason}"
                );
            }
            other => panic!("one offender is not contained: {other:?}"),
        }
    }

    /// Review 87: NEUTRALIZE kills the offender, then quarantines the
    /// binary it ran, looked up before the kill. The quarantine by pid
    /// that ran after the kill found `/proc/<pid>/exe` gone every time.
    #[test]
    fn neutralize_quarantines_the_offenders_binary() {
        let tmp = tempfile::TempDir::new().unwrap();
        let mal = tmp.path().join("mal");
        std::fs::copy("/bin/sleep", &mal).unwrap();
        // ETXTBSY: another test thread's fork may still hold the copy's
        // write descriptor for an instant.
        let mut child = (0..200)
            .find_map(
                |_| match std::process::Command::new(&mal).arg("60").spawn() {
                    Ok(c) => Some(c),
                    Err(e) if e.raw_os_error() == Some(libc::ETXTBSY) => {
                        std::thread::sleep(std::time::Duration::from_millis(5));
                        None
                    }
                    Err(e) => panic!("spawn {}: {e}", mal.display()),
                },
            )
            .expect("the copied binary runs");
        let pid = child.id();
        // the exec has replaced the image before NEUTRALIZE reads it
        for _ in 0..100 {
            if binary_of(pid)
                .ok()
                .flatten()
                .and_then(|h| h.current_path())
                .as_deref()
                == Some(mal.as_path())
            {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        // for_test is detect-only; this test enforces, on its own child,
        // with every path under the temp dir.
        let cfg = ExecutorConfig {
            dry_run: false,
            ..ExecutorConfig::for_test(&tmp.path().join("state"))
        };
        let vault = cfg.quarantine_dir.join("vault");
        let actuator = SystemActuator::new(
            Executor::with_config(cfg),
            None,
            false,
            ActionJournal::memory(),
        );
        let report = actuator.neutralize(&[Arc::new(ProcRef::open(pid))]);
        assert!(
            matches!(report.outcome(), NeutralizeOutcome::Contained),
            "{report:?}"
        );
        assert_eq!(report.offenders[0].quarantine, "quarantined");
        let _ = child.wait();
        assert!(!mal.exists(), "the offender's binary must be quarantined");
        let bins = std::fs::read_dir(&vault)
            .unwrap()
            .filter(|e| {
                e.as_ref()
                    .unwrap()
                    .path()
                    .extension()
                    .is_some_and(|x| x == "bin")
            })
            .count();
        assert_eq!(bins, 1);
    }

    /// Lot 312 (BUG-90): a binary NEUTRALIZE could not open is said so —
    /// the error was dropped and the row read "no binary on disk".
    #[test]
    fn a_binary_that_could_not_be_opened_is_said_so() {
        let t =
            SystemActuator::no_binary_text(7, Err(std::io::Error::from_raw_os_error(libc::EACCES)));
        assert!(
            t.starts_with("NOT quarantined: its binary could not be opened (Permission denied"),
            "{t}"
        );
        assert_eq!(SystemActuator::no_binary_text(7, Ok(())), NO_BINARY);
        assert!(!NO_BINARY.contains("no binary on disk"));
    }
}
