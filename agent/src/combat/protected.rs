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
//!   defender mid-incident (the [`Executor`](crate::response::Executor)
//!   already refuses its own PID, but the ladder must not even *ask*).
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
//! ## Identity: PID + kernel-resolved exe, never `comm`
//!
//! `comm` is attacker-controllable (`prctl(PR_SET_NAME, …)`), so a guard
//! that keyed on it would let any process rename itself to gain immunity —
//! the exact bypass [`crate::posture::exempt`] and
//! [`crate::posture::lineage`] are built to avoid. We therefore key on:
//!
//! - `pid == 1` for init and `pid == agent_pid` for the agent (neither
//!   can be a recycled impostor: PID 1 is init for the life of the boot,
//!   and `agent_pid` is our own live PID), and
//! - the kernel-resolved **`/proc/<pid>/exe`** symlink for the watchdog
//!   and sshd. The watchdog PID comes from the timer-refreshed
//!   [`ExemptPids`] slot, but that slot is only re-verified every ~30 s —
//!   so we additionally re-check `/proc/<pid>/exe` against the watchdog
//!   binary *inline at the kill/spare decision*. That closes the PID-reuse
//!   race in the gap between refreshes (a recycled PID whose exe no longer
//!   matches is NOT spared); a swapped or ` (deleted)` binary likewise
//!   fails the check — a substituted watchdog/sshd is what we must not
//!   trust.
//!
//! The guard is injected into [`super::CombatLadder`] as a trait object
//! (like the actuator/evidence) so the ladder stays a pure, deterministic
//! state machine in unit tests while production reads the live `/proc`.

use std::fs;
use std::path::PathBuf;

use crate::posture::ExemptPids;

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
/// deterministic stub; production ([`SystemProtectedProcs`]) reads the
/// live `/proc`.
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

/// Canonical sshd install paths matched against the kernel-resolved
/// `/proc/<pid>/exe`. Mirrors the sshd entries in
/// [`crate::posture::lineage::AUTH_BINARY_EXES`], kept local so this guard
/// names only the SSH service, not the wider PAM-auth set.
pub const SSHD_EXES: &[&str] = &["/usr/sbin/sshd", "/usr/libexec/openssh/sshd"];

/// Production guard: PID 1 + the agent + the watchdog (reused
/// [`ExemptPids`] slot, re-verified inline by exe) + sshd, both identified
/// by kernel-resolved `/proc/<pid>/exe`.
pub struct SystemProtectedProcs {
    /// The agent's own PID. Held directly (rather than via `ExemptPids`,
    /// which exposes no agent-PID getter) so the reason is precise.
    agent_pid: u32,
    /// Shared agent+watchdog identity handle, refreshed by `main.rs`.
    stack: ExemptPids,
    /// The watchdog binary — `/proc/<watchdog_pid>/exe` must resolve to
    /// this for the watchdog PID to be spared (closes the PID-reuse race
    /// between the 30 s refreshes of the `stack` slot).
    watchdog_exe: PathBuf,
    /// sshd binary paths to match `/proc/<pid>/exe` against.
    sshd_exes: Vec<PathBuf>,
    /// `/proc` root — `"/proc"` in production, a fixture tree in tests.
    proc_root: PathBuf,
}

impl SystemProtectedProcs {
    /// Production constructor: reads the live `/proc`, matches the default
    /// [`SSHD_EXES`]. `watchdog_exe` is the verified watchdog binary path
    /// (the same `--watchdog-exe` the posture refresh task verifies
    /// against).
    pub fn new(agent_pid: u32, stack: ExemptPids, watchdog_exe: PathBuf) -> Self {
        Self {
            agent_pid,
            stack,
            watchdog_exe,
            sshd_exes: SSHD_EXES.iter().map(PathBuf::from).collect(),
            proc_root: PathBuf::from("/proc"),
        }
    }

    /// Test seam: point `/proc` at a fixture tree and supply the
    /// watchdog/sshd exe(s) to match.
    #[cfg(test)]
    fn with_parts(
        agent_pid: u32,
        stack: ExemptPids,
        proc_root: impl Into<PathBuf>,
        watchdog_exe: impl Into<PathBuf>,
        sshd_exes: Vec<PathBuf>,
    ) -> Self {
        Self {
            agent_pid,
            stack,
            watchdog_exe: watchdog_exe.into(),
            sshd_exes,
            proc_root: proc_root.into(),
        }
    }

    /// Resolve `/proc/<pid>/exe` (kernel-resolved, NEVER `comm`). Returns
    /// `None` if the link is unreadable (PID gone) or carries a
    /// ` (deleted)` suffix (the on-disk binary was unlinked while running)
    /// — a swapped/substituted binary is exactly what we must not trust.
    fn resolve_exe(&self, pid: u32) -> Option<PathBuf> {
        let link = self.proc_root.join(pid.to_string()).join("exe");
        let exe = fs::read_link(&link).ok()?;
        if exe.to_string_lossy().ends_with(" (deleted)") {
            return None;
        }
        Some(exe)
    }

    /// True iff `/proc/<pid>/exe` resolves to a known sshd binary.
    fn exe_is_sshd(&self, pid: u32) -> bool {
        match self.resolve_exe(pid) {
            Some(exe) => self.sshd_exes.iter().any(|p| p.as_path() == exe.as_path()),
            None => false,
        }
    }
}

impl ProtectedProcs for SystemProtectedProcs {
    fn protected_reason(&self, pid: u32) -> Option<ProtectedReason> {
        if pid == 1 {
            return Some(ProtectedReason::Init);
        }
        // `agent_pid` is never 0/1 (own PID), so order vs. init is moot.
        if pid == self.agent_pid {
            return Some(ProtectedReason::AgentSelf);
        }
        // Watchdog: the refreshed slot names the PID, but re-verify the exe
        // inline so a PID recycled to a different binary between refreshes
        // does NOT inherit the watchdog's kill/net-cut immunity.
        if self.stack.watchdog_pid() == Some(pid)
            && self.resolve_exe(pid).as_deref() == Some(self.watchdog_exe.as_path())
        {
            return Some(ProtectedReason::Watchdog);
        }
        if self.exe_is_sshd(pid) {
            return Some(ProtectedReason::SshService);
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;
    use std::path::Path;
    use tempfile::TempDir;

    const WD_EXE: &str = "/usr/local/bin/northnarrow-watchdog";
    const SSHD_EXE: &str = "/usr/sbin/sshd";

    /// Create `<proc_root>/<pid>/exe` as a symlink to `target`.
    fn link_exe(proc_root: &Path, pid: u32, target: &str) {
        let dir = proc_root.join(pid.to_string());
        fs::create_dir_all(&dir).unwrap();
        symlink(target, dir.join("exe")).unwrap();
    }

    fn guard(proc_root: &Path, agent_pid: u32, stack: ExemptPids) -> SystemProtectedProcs {
        SystemProtectedProcs::with_parts(
            agent_pid,
            stack,
            proc_root,
            PathBuf::from(WD_EXE),
            vec![PathBuf::from(SSHD_EXE)],
        )
    }

    #[test]
    fn recognizes_init_agent_and_watchdog() {
        let tmp = TempDir::new().unwrap();
        link_exe(tmp.path(), 4300, WD_EXE); // the watchdog's verified binary
        let stack = ExemptPids::with_agent(4242);
        stack.set_watchdog_pid(4300);
        let g = guard(tmp.path(), 4242, stack);
        assert_eq!(g.protected_reason(1), Some(ProtectedReason::Init));
        assert_eq!(g.protected_reason(4242), Some(ProtectedReason::AgentSelf));
        assert_eq!(g.protected_reason(4300), Some(ProtectedReason::Watchdog));
        // A normal PID is not protected.
        assert_eq!(g.protected_reason(9999), None);
    }

    #[test]
    fn watchdog_protection_follows_the_refreshed_slot() {
        let tmp = TempDir::new().unwrap();
        link_exe(tmp.path(), 5000, WD_EXE);
        let stack = ExemptPids::with_agent(10);
        let g = guard(tmp.path(), 10, stack.clone());
        // No watchdog verified yet → PID 5000 is fair game.
        assert_eq!(g.protected_reason(5000), None);
        // Refresh task verifies the watchdog → it becomes protected.
        stack.set_watchdog_pid(5000);
        assert_eq!(g.protected_reason(5000), Some(ProtectedReason::Watchdog));
        // Watchdog restart clears the slot → old PID is fair game again.
        stack.set_watchdog_pid(0);
        assert_eq!(g.protected_reason(5000), None);
    }

    // PID-reuse race: the refreshed slot still names 5000, but that PID was
    // recycled to a *different* binary in the gap between 30 s refreshes.
    // The inline exe re-check must deny it the watchdog's immunity.
    #[test]
    fn recycled_watchdog_pid_with_wrong_exe_is_not_protected() {
        let tmp = TempDir::new().unwrap();
        link_exe(tmp.path(), 5000, "/usr/bin/attacker");
        let stack = ExemptPids::with_agent(10);
        stack.set_watchdog_pid(5000);
        let g = guard(tmp.path(), 10, stack);
        assert_eq!(
            g.protected_reason(5000),
            None,
            "a recycled watchdog PID whose exe no longer matches must NOT inherit immunity"
        );
    }

    // A dead watchdog PID (slot set, but no /proc entry) is not spared.
    #[test]
    fn watchdog_pid_with_no_proc_entry_is_not_protected() {
        let tmp = TempDir::new().unwrap();
        let stack = ExemptPids::with_agent(10);
        stack.set_watchdog_pid(5000); // nothing linked at <tmp>/5000/exe
        let g = guard(tmp.path(), 10, stack);
        assert_eq!(g.protected_reason(5000), None);
    }

    #[test]
    fn recognizes_sshd_by_kernel_resolved_exe() {
        let tmp = TempDir::new().unwrap();
        link_exe(tmp.path(), 800, SSHD_EXE);
        link_exe(tmp.path(), 801, "/usr/bin/python3"); // a non-sshd process
        let g = guard(tmp.path(), 10, ExemptPids::with_agent(10));
        assert_eq!(g.protected_reason(800), Some(ProtectedReason::SshService));
        assert_eq!(g.protected_reason(801), None);
        // A PID with no /proc entry resolves to None (not a crash).
        assert_eq!(g.protected_reason(999_999), None);
    }

    #[test]
    fn deleted_sshd_binary_is_not_trusted() {
        let tmp = TempDir::new().unwrap();
        // A swapped/unlinked sshd: the kernel appends " (deleted)".
        link_exe(tmp.path(), 802, "/usr/sbin/sshd (deleted)");
        let g = guard(tmp.path(), 10, ExemptPids::with_agent(10));
        assert_eq!(
            g.protected_reason(802),
            None,
            "a deleted/substituted sshd binary must NOT earn protection"
        );
    }

    #[test]
    fn no_protected_procs_protects_nothing() {
        let g = NoProtectedProcs;
        assert_eq!(g.protected_reason(1), None);
        assert_eq!(g.protected_reason(std::process::id()), None);
    }
}
