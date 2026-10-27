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
    /// Every offender was killed (or had already exited, or — in
    /// detect-only — *would* have been killed) and the binary
    /// quarantined. The threat is contained at the process level; the
    /// host stays on the network.
    Contained,
    /// At least one offender could not be neutralized — kernel/LSM
    /// protected (`EPERM`), below the kill floor, still alive after
    /// SIGKILL + verify (respawning / unkillable), or no offender could
    /// be attributed at all. The host must be isolated (STAGE 3).
    Uncontainable { reason: String },
}

/// Lab PR 217 (capability C17): what NEUTRALIZE did to one offender.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OffenderOutcome {
    pub pid: u32,
    /// The process and its tree are contained: killed, already gone, or —
    /// detect-only — would have been.
    pub contained: bool,
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

impl NeutralizeReport {
    /// What the ladder decides on: contained only when every offender is
    /// (and there was one); otherwise why, for each one that is not.
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
            .filter(|o| !o.contained)
            .map(|o| format!("pid {}: {}", o.pid, o.kill))
            .collect();
        if not.is_empty() {
            NeutralizeOutcome::Contained
        } else {
            NeutralizeOutcome::Uncontainable {
                reason: not.join("; "),
            }
        }
    }

    /// Every offender with the same verdict (test actuators).
    pub fn uniform(pids: &[u32], outcome: &NeutralizeOutcome) -> Self {
        let (contained, kill) = match outcome {
            NeutralizeOutcome::Contained => (true, "killed".to_string()),
            NeutralizeOutcome::Uncontainable { reason } => (false, reason.clone()),
        };
        Self {
            offenders: pids
                .iter()
                .map(|&pid| OffenderOutcome {
                    pid,
                    contained,
                    kill: kill.clone(),
                    quarantine: "quarantined".to_string(),
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
    /// Nothing was applied, and nothing will be: detect-only, or no
    /// isolator in this build.
    NotApplied(String),
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
