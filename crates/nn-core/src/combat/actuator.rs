//! [`CombatActuator`] — the side-effecting operations the ladder
//! performs, behind a trait so [`super::CombatLadder`] is unit-testable
//! without touching the real kill / nftables / iptables machinery.
//!
//! The production implementation is the agent's `SystemActuator`: it
//! drives the agent's executor (kill, quarantine, per-PID egress block) and
//! network isolator (full isolation), and honours detect-only
//! (`--detect-only`) in both.
//!
//! Lab PR 217 (capability C17): NEUTRALIZE and ISOLATE report what they did
//! — per offender ([`NeutralizeReport`]) and per IP family, read back
//! ([`IsolateOutcome`]) — and the ladder signs it.
//!
//! R08c (lab PR 252): the trait and the outcomes it reports, cut verbatim
//! from the agent's `combat::actuator`, which re-exports them and keeps
//! `SystemActuator` for nn-linux (R09). The actuator acts on the processes
//! its host captured ([`CombatHost::Proc`]); by default it captures one as
//! its host does ([`CombatHost::open_for_event`]) and compares one with an
//! event as the capture does ([`Capture::matches_event`]).

use std::sync::Arc;

use super::host::{Capture, CombatHost};
use super::offender::ProcFacts;
use crate::anti_tamper::network_isolate::IsolationReport;

/// Outcome of a STAGE-2 neutralization attempt — the signal the ladder
/// uses to decide whether STAGE 3 (isolation) is necessary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NeutralizeOutcome {
    /// Every offender was killed (or had already exited) and the binary
    /// quarantined. The threat is contained at the process level; the
    /// host stays on the network.
    Contained,
    /// Lot 370 (F10-1): the no-enforcement gate (the `alpha` profile,
    /// `--detect-only`) — every offender *would* have been killed and its
    /// binary quarantined, and nothing was: the processes still run. Never
    /// [`Self::Contained`]: the ladder signs it as a would-have, says so,
    /// and tells no one the offenders were contained (it counted as
    /// contained, and the signed outcome read `success`, "N contained").
    WouldHaveContained,
    /// At least one offender could not be neutralized — kernel/LSM
    /// protected (`EPERM`), below the kill floor, still alive after
    /// SIGKILL + verify (respawning / unkillable), or no offender could
    /// be attributed at all. The host must be isolated (STAGE 3).
    Uncontainable { reason: String },
}

/// Lot 370 (F10-1): what NEUTRALIZE's kill did to one offender's tree.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Containment {
    /// The process and its tree are gone: killed, or already exited.
    Contained,
    /// The no-enforcement gate: the kill was approved and not carried out
    /// — the process runs. Not contained, and not a failure to contain.
    WouldHave,
    /// Not contained: refused (below the protection floor), denied by the
    /// kernel, still alive after the kill, a descendant left running.
    NotContained,
}

/// Lab PR 217 (capability C17): what NEUTRALIZE did to one offender.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OffenderOutcome {
    pub pid: u32,
    /// Lot 370 (F10-1): contained (killed, already gone), would have been
    /// (the no-enforcement gate: nothing was done), or not contained. A
    /// would-have counted as contained.
    pub containment: Containment,
    /// The kill's outcome, or why the offender is not contained.
    pub kill: String,
    /// What became of its binary: quarantined, nothing to quarantine, or
    /// why not.
    pub quarantine: String,
}

/// Lab PR 217 (capability C17): NEUTRALIZE's outcome for EVERY offender it
/// was handed. It stopped at the first one it could not contain: the
/// offenders after it were neither killed nor had their binary
/// quarantined, and nothing said so.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct NeutralizeReport {
    pub offenders: Vec<OffenderOutcome>,
}

impl OffenderOutcome {
    /// The offender is contained — killed, or already gone. Never a
    /// would-have (lot 370, F10-1).
    pub fn contained(&self) -> bool {
        self.containment == Containment::Contained
    }

    /// The no-enforcement gate held the kill: nothing was done to it.
    pub fn would_have(&self) -> bool {
        self.containment == Containment::WouldHave
    }
}

impl NeutralizeReport {
    /// What the ladder decides on: contained only when every offender is
    /// (and there was one); otherwise why, for each one that is not. Lot
    /// 370 (F10-1): when none is uncontained and the gate held a kill, a
    /// would-have — never contained, though the ladder decides on it as it
    /// would on a containment (no ISOLATE for it).
    pub fn outcome(&self) -> NeutralizeOutcome {
        if self.offenders.is_empty() {
            // No process attributed — we cannot contain a threat at the
            // process level, so isolation is the proportionate fallback.
            return NeutralizeOutcome::Uncontainable {
                reason: "no offending process attributed — cannot contain at process level"
                    .to_string(),
            };
        }
        let not: Vec<String> = self
            .offenders
            .iter()
            .filter(|o| o.containment == Containment::NotContained)
            .map(|o| format!("pid {}: {}", o.pid, o.kill))
            .collect();
        if not.is_empty() && self.offenders.iter().any(OffenderOutcome::would_have) {
            NeutralizeOutcome::WouldHaveContained
        } else if not.is_empty() {
            NeutralizeOutcome::Contained
        } else {
            NeutralizeOutcome::Uncontainable {
                reason: not.join("; "),
            }
        }
    }

    /// Every offender with the same verdict (test actuators).
    pub fn uniform(pids: &[u32], outcome: &NeutralizeOutcome) -> Self {
        let (containment, kill, quarantine) = match outcome {
            NeutralizeOutcome::Contained => (Containment::Contained, "killed", "quarantined"),
            NeutralizeOutcome::WouldHaveContained => (
                Containment::WouldHave,
                "would have: KillProcessTree",
                "detect-only: would be quarantined",
            ),
            NeutralizeOutcome::Uncontainable { reason } => {
                (Containment::NotContained, reason.as_str(), "quarantined")
            }
        };
        Self {
            offenders: pids
                .iter()
                .map(|&pid| OffenderOutcome {
                    pid,
                    containment,
                    kill: kill.to_string(),
                    quarantine: quarantine.to_string(),
                })
                .collect(),
        }
    }
}

/// Lab PR 217 (capability C17): what STAGE 3 did. ISOLATE was marked done
/// before it acted and its outcome was only logged; it is now this, read
/// back from the tables, and the ladder records and retries from it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IsolateOutcome {
    /// The isolator ran; per IP family, what the tables hold after it.
    Applied(IsolationReport),
    /// Nothing was applied, and nothing will be: no isolator in this
    /// build.
    NotApplied(String),
    /// Lot 370 (F10-1): the no-enforcement gate (the `alpha` profile,
    /// `--detect-only`): the isolation was decided and not applied — the
    /// host stays on the network. Signed as a would-have, not a failure.
    WouldHave(String),
}

/// Outcome of a STAGE-1 soft egress block. External audit CMB-014: it
/// was only logged, so a block that never took effect (no `nft` on the
/// host) counted as containment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SoftBlock {
    /// The process's outbound traffic is dropped.
    Blocked,
    /// Nothing to contain, nothing to undo: detect-only, or the process
    /// had already exited.
    NotNeeded(&'static str),
    /// The block did not take effect.
    Failed(String),
    /// Lot 312 (review F2): the process is in the blocked scope and its
    /// new sockets are dropped, but sockets it opened before the move (or
    /// is passed later from outside the scope) are not: contained in part.
    /// Released at the stand-down like a block; the INVESTIGATE window is
    /// shortened like a failure.
    Partial(String),
}

/// The operations [`super::CombatLadder`] performs on the system, on the
/// processes its host captured (R08c, lab PR 252: `H`'s, [`CombatHost`]).
pub trait CombatActuator<H: CombatHost>: Send + Sync {
    /// External audit CMB-004: capture the process `pid` names, when it is
    /// attributed — with what the attributing event says about it:
    /// `start_ns`, its exec's start, and `seen_ns`, the event's time (it
    /// was running then); 0 when unknown.
    fn identify(&self, pid: u32, start_ns: u64, seen_ns: u64) -> Arc<H::Proc> {
        Arc::new(H::open_for_event(pid, start_ns, seen_ns))
    }

    /// External audit CMB-004: an event names `target`'s PID (with the
    /// process start it reported, 0 when unknown) — is it about the
    /// captured process, not a later holder of the PID?
    fn same_process(&self, target: &H::Proc, start_ns: u64) -> bool {
        target.matches_event(start_ns)
    }

    /// Lab PR 245: the executable and the cgroup of `target`, read when it
    /// is attributed, for the signed rows that name it — only while the
    /// capture still names the process. Nothing known by default.
    fn describe(&self, _target: &H::Proc) -> ProcFacts {
        ProcFacts::default()
    }

    /// A COMBAT episode opens (external audit CMB-011: the drop ruleset
    /// is applied once per episode).
    fn begin_episode(&self) {}

    /// STAGE 1 surgical soft egress: drop only this process's outbound
    /// traffic (cgroup-scoped), preserving the host's management +
    /// evidence channels. Idempotent.
    fn soft_egress_block(&self, target: &H::Proc) -> SoftBlock;

    /// Reverse [`Self::soft_egress_block`] (stand-down), for a process it
    /// reported blocked.
    fn soft_egress_clear(&self, target: &H::Proc);

    /// STAGE 2: kill (tree) + quarantine EVERY offending process; report,
    /// for each one, whether it is contained at the process level (lab PR
    /// 217: one that cannot be contained no longer spares the others).
    fn neutralize(&self, offenders: &[Arc<H::Proc>]) -> NeutralizeReport;

    /// STAGE 3 (last resort): engage full host network isolation, and
    /// report what the tables hold afterwards (lab PR 217).
    fn isolate(&self) -> IsolateOutcome;

    /// Whether enforcement is globally suppressed (`--detect-only`).
    fn is_dry_run(&self) -> bool;
}
