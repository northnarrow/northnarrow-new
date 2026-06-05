//! [`CombatActuator`] — the side-effecting operations the ladder
//! performs, behind a trait so [`super::CombatLadder`] is unit-testable
//! without touching the real kill / nftables / iptables machinery.
//!
//! The production implementation, [`SystemActuator`], drives the
//! existing [`Executor`](crate::response::Executor) (kill, quarantine,
//! per-PID egress block) and
//! [`NetworkIsolator`](crate::anti_tamper::network_isolate::NetworkIsolator)
//! (full isolation). Detect-only (`--detect-only`) is honoured: the
//! executor already suppresses its own actions and returns
//! [`WouldExecute`](crate::response::ExecutionOutcome::WouldExecute);
//! [`SystemActuator::isolate`] adds the matching guard for the isolator,
//! which has no internal dry-run gate (V1 gated it in `main.rs`).

use std::sync::Arc;

use tracing::{info, warn};

use common::ResponseAction;

use crate::anti_tamper::network_isolate::NetworkIsolator;
use crate::response::{block_outbound, ExecutionOutcome, Executor};

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

/// The operations [`super::CombatLadder`] performs on the system.
pub trait CombatActuator: Send + Sync {
    /// STAGE 1 surgical soft egress: drop only this PID's outbound
    /// traffic (cgroup-scoped), preserving the host's management +
    /// evidence channels. Idempotent.
    fn soft_egress_block(&self, pid: u32);

    /// Reverse [`Self::soft_egress_block`] (admin stand-down).
    fn soft_egress_clear(&self, pid: u32);

    /// STAGE 2: kill (tree) + quarantine the offending PID(s); report
    /// whether the threat is contained at the process level.
    fn neutralize(&self, offenders: &[u32]) -> NeutralizeOutcome;

    /// STAGE 3 (last resort): engage full host network isolation.
    fn isolate(&self);

    /// Whether enforcement is globally suppressed (`--detect-only`).
    fn is_dry_run(&self) -> bool;
}

/// Production actuator: real executor + optional network isolator.
pub struct SystemActuator {
    executor: Executor,
    isolator: Option<Arc<NetworkIsolator>>,
    detect_only: bool,
}

impl SystemActuator {
    pub fn new(
        executor: Executor,
        isolator: Option<Arc<NetworkIsolator>>,
        detect_only: bool,
    ) -> Self {
        Self {
            executor,
            isolator,
            detect_only,
        }
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
}

impl CombatActuator for SystemActuator {
    fn soft_egress_block(&self, pid: u32) {
        let report = self.executor.execute(ResponseAction::BlockOutbound, pid);
        info!(
            target: "combat.actuator",
            pid,
            outcome = ?report.primary,
            "INVESTIGATE soft egress: per-PID outbound block (host channels preserved)"
        );
    }

    fn soft_egress_clear(&self, pid: u32) {
        if self.detect_only {
            return;
        }
        if let Err(e) = block_outbound::unblock_pid(pid, self.executor.config()) {
            warn!(target: "combat.actuator", pid, error = %e, "soft-egress unblock failed");
        }
    }

    fn neutralize(&self, offenders: &[u32]) -> NeutralizeOutcome {
        if offenders.is_empty() {
            // No process attributed — we cannot contain a threat at the
            // process level, so isolation is the proportionate fallback.
            return NeutralizeOutcome::Uncontainable {
                reason: "no offending process attributed — cannot contain at process level"
                    .to_string(),
            };
        }

        // First pass: kill the offending tree(s). Any non-contained
        // primary outcome means the threat is uncontainable → isolate.
        for &pid in offenders {
            let report = self.executor.execute(ResponseAction::KillProcessTree, pid);
            if !Self::contained(&report.primary) {
                return NeutralizeOutcome::Uncontainable {
                    reason: format!("pid {pid}: kill outcome {:?}", report.primary),
                };
            }
            info!(
                target: "combat.actuator",
                pid,
                outcome = ?report.primary,
                children = report.additional.len(),
                "NEUTRALIZE: killed offending process tree"
            );
        }

        // Second pass (best-effort): quarantine the binaries so a
        // surviving parent / supervisor cannot re-exec them. A
        // quarantine failure does NOT force isolation — the process is
        // already dead — but it is logged.
        for &pid in offenders {
            let report = self.executor.execute(ResponseAction::Quarantine, pid);
            match report.primary {
                ExecutionOutcome::Quarantined { .. }
                | ExecutionOutcome::AlreadyGone { .. }
                | ExecutionOutcome::WouldExecute { .. } => {}
                other => {
                    warn!(
                        target: "combat.actuator",
                        pid,
                        outcome = ?other,
                        "NEUTRALIZE: binary quarantine did not complete (process already killed; \
                         re-exec prevention degraded)"
                    );
                }
            }
        }

        NeutralizeOutcome::Contained
    }

    fn isolate(&self) {
        if self.detect_only {
            warn!(
                target: "combat.actuator",
                "DETECT-ONLY: STAGE 3 reached — would engage full network isolation; \
                 iptables NOT applied (no enforcement)"
            );
            return;
        }
        match &self.isolator {
            Some(iso) => {
                if let Err(e) = iso.engage() {
                    tracing::error!(
                        target: "combat.actuator",
                        error = %e,
                        "COMBAT isolate failed; agent continues in degraded mode"
                    );
                }
            }
            None => warn!(
                target: "combat.actuator",
                "STAGE 3 reached but no network isolator configured — cannot isolate \
                 (dev build without /etc/northnarrow/ provisioned)"
            ),
        }
    }

    fn is_dry_run(&self) -> bool {
        self.detect_only
    }
}
