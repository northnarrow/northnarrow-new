//! Host-critical process guard for the COMBAT ladder.
//!
//! ## Why this exists
//!
//! The ladder's two destructive primitives operate on a *target PID*:
//! [`CombatStage::Neutralize`](super::CombatStage::Neutralize) kills the
//! offending process tree, and
//! [`CombatStage::Investigate`](super::CombatStage::Investigate) applies a
//! surgical per-PID egress cut. Pointed at a **host-critical** process,
//! either one is catastrophic and self-defeating:
//!
//! - **PID 1** — `SIGKILL` to init panics the host.
//! - **The agent itself** — neutralizing our own PID disables the
//!   defender mid-incident (the agent's `response::Executor` already
//!   refuses its own PID, but the ladder must not even *ask*).
//! - **The watchdog** — killing the supervisor removes the agent's
//!   restart/anti-tamper backstop. NB: the executor's protected set is
//!   only `{0, 1, 2, own_pid}` — it does **not** carry the watchdog PID,
//!   so absent this guard the ladder *could* kill it.
//! - **The SSH service** — killing or net-cutting `sshd` can lock the
//!   remote operator out of a host that just escalated, with no console.
//!
//! So this guard names those processes. The ladder consults it before any
//! per-PID action and, instead of acting on a protected PID, **skips +
//! logs** it and (at NEUTRALIZE) **escalates to ISOLATE** — the
//! network-level last resort. That is the safe middle path between the two
//! failure modes: never destroy a critical process, but never hand a real
//! threat hiding *as* one a free pass either (a confirmed offender we
//! refuse to kill is, by definition, uncontainable at the process level,
//! which is exactly the existing
//! [`NeutralizeOutcome::Uncontainable`](super::NeutralizeOutcome::Uncontainable)
//! → ISOLATE semantics).
//!
//! R08c (lab PR 252): the guard's trait, the reasons it names and the guard
//! that protects nothing, cut verbatim from the agent's `combat::protected`,
//! which re-exports them and keeps the production guard
//! (`SystemProtectedProcs`: the identities read from the live `/proc` —
//! the watchdog's slot re-checked by its executable, the SSH service by its
//! executable, uid and systemd unit) for nn-linux (R09).

/// Why a PID is host-critical and must not be directly acted on by the
/// COMBAT ladder. Carried into the audit reason string so the escalation
/// record names the class of process that was spared.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtectedReason {
    /// PID 1 — killing init panics the host.
    Init,
    /// The agent's own process — acting on it disables the defender.
    AgentSelf,
    /// The verified watchdog supervising the agent.
    Watchdog,
    /// The SSH service (`sshd`) — killing/cutting it can lock the operator
    /// out of a host that just escalated.
    SshService,
}

impl ProtectedReason {
    pub fn as_str(&self) -> &'static str {
        match self {
            ProtectedReason::Init => "init(pid 1)",
            ProtectedReason::AgentSelf => "northnarrow-agent(self)",
            ProtectedReason::Watchdog => "northnarrow-watchdog",
            ProtectedReason::SshService => "ssh-service(sshd)",
        }
    }
}

impl core::fmt::Display for ProtectedReason {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Recognizes the host-critical processes the COMBAT ladder must never
/// directly kill or net-cut. Injected into [`super::CombatLadder`] (like
/// the actuator/evidence) so the guard is unit-testable with a
/// deterministic stub; production (the agent's `SystemProtectedProcs`)
/// reads the live `/proc`.
pub trait ProtectedProcs: Send + Sync {
    /// Why `pid` is host-critical, or `None` if it is fair game for a
    /// per-PID combat action.
    fn protected_reason(&self, pid: u32) -> Option<ProtectedReason>;
}

/// A guard that protects nothing. The safe default for dev builds without
/// a resolved process stack, and the baseline most ladder unit tests use.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoProtectedProcs;

impl ProtectedProcs for NoProtectedProcs {
    fn protected_reason(&self, _pid: u32) -> Option<ProtectedReason> {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_protected_procs_protects_nothing() {
        let g = NoProtectedProcs;
        assert_eq!(g.protected_reason(1), None);
        assert_eq!(g.protected_reason(std::process::id()), None);
    }
}
