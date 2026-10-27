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
//! ### The SSH service, not whoever runs its binary (external audit CMB-003)
//!
//! The exe alone was no anchor for sshd: `/usr/sbin/sshd` is
//! world-executable and runs unprivileged on a high port, so any user's
//! process could take its image and with it immunity from the kill — and,
//! as the only offender, push the ladder straight to ISOLATE. An sshd is
//! now spared only when it runs as root inside an SSH unit of systemd
//! (`ssh.service`, `sshd.service`, or a socket-activated `ssh@…`/`sshd@…`
//! instance). On a host without systemd units, exe and uid 0 are the only
//! anchors left, and they still apply. A session's own processes live in
//! the session's scope, not in the unit, and are not spared: when one of
//! them is the offender, killing it is the containment.
//!
//! ### An executable that cannot be read (external audit CMB-022)
//!
//! Without `CAP_SYS_PTRACE` (a unit whose bounding set a drop-in narrowed)
//! the kernel refuses `/proc/<pid>/exe` of every process of another uid,
//! of every non-dumpable one, and of every root process holding a
//! capability the agent lacks — the SSH daemon and the watchdog among
//! them. The guard used to take "could not check" for "not protected", so
//! there it would kill or net-cut the SSH service. The opposite rule,
//! "unreadable means protected", is worse: any process could buy immunity
//! with `prctl(PR_SET_DUMPABLE, 0)`, and as the only offender push the
//! ladder straight to ISOLATE. An unreadable executable is therefore
//! spared only on an anchor the process cannot forge: the watchdog slot's
//! PID with the start time it was verified with ([`ExemptPids`],
//! POS-009), or real uid 0 inside the SSH units or the watchdog's own
//! unit of the system manager (`/system.slice/…`; a user's manager can
//! name a unit of its own anything, never run uid 0 in it). Every other
//! unreadable PID is fair game, and a rate-limited WARN says which way
//! each went. The boot declares the missing capability
//! ([`crate::response::caps_preflight`]).
//!
//! The guard is injected into [`super::CombatLadder`] as a trait object
//! (like the actuator/evidence) so the ladder stays a pure, deterministic
//! state machine in unit tests while production reads the live `/proc`.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use tracing::warn;

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
    /// `readlink(2)` — `fs::read_link` in production; tests make it fail
    /// with `EACCES` (the kernel's answer without `CAP_SYS_PTRACE`).
    read_link: fn(&Path) -> io::Result<PathBuf>,
    /// External audit CMB-022: the WARN for an unreadable executable,
    /// at most once per [`UNREADABLE_WARN_EVERY`].
    unreadable_warn: WarnEvery,
}

/// External audit CMB-022: how often the guard says that it judged a PID
/// whose `/proc/<pid>/exe` it could not read (a tree of a thousand
/// processes is judged a thousand times).
const UNREADABLE_WARN_EVERY: Duration = Duration::from_secs(60);

/// A WARN at most once per period; the calls in between are counted into
/// the next one.
struct WarnEvery {
    every: Duration,
    /// When the last WARN was logged, and the calls held back since.
    state: parking_lot::Mutex<(Option<Instant>, u64)>,
}

impl WarnEvery {
    fn new(every: Duration) -> Self {
        Self {
            every,
            state: parking_lot::Mutex::new((None, 0)),
        }
    }

    /// `Some(held back since the last one)` when this call logs.
    fn hit(&self, now: Instant) -> Option<u64> {
        let mut s = self.state.lock();
        if s.0.is_some_and(|t| now.duration_since(t) < self.every) {
            s.1 += 1;
            return None;
        }
        let held = s.1;
        *s = (Some(now), 0);
        Some(held)
    }
}

/// External audit CMB-022: the watchdog's systemd unit. Root inside it is
/// the watchdog (or what it runs): the anchor left when its executable
/// cannot be read — which, without `CAP_SYS_PTRACE`, is also when the
/// refresh task cannot verify it and the slot stays empty.
const WATCHDOG_UNIT: &str = "northnarrow-watchdog.service";

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
            read_link: |p| fs::read_link(p),
            unreadable_warn: WarnEvery::new(UNREADABLE_WARN_EVERY),
        }
    }

    /// Test seam: point `/proc` at a fixture tree and supply the
    /// watchdog/sshd exe(s) to match (lab PR 243: the golden replay of the
    /// posture and the ladder judges its fixture host with it).
    #[cfg(test)]
    pub(crate) fn with_parts(
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
            read_link: |p| fs::read_link(p),
            unreadable_warn: WarnEvery::new(UNREADABLE_WARN_EVERY),
        }
    }

    /// Test seam: the `readlink(2)` the guard calls.
    #[cfg(test)]
    fn with_read_link(mut self, read_link: fn(&Path) -> io::Result<PathBuf>) -> Self {
        self.read_link = read_link;
        self
    }

    /// Resolve `/proc/<pid>/exe` (kernel-resolved, NEVER `comm`).
    /// `Ok(None)` when there is no binary to trust: the PID is gone
    /// (`ENOENT`, `ESRCH`), a kernel thread, or its binary carries a
    /// ` (deleted)` suffix (unlinked while running — a swapped/substituted
    /// binary is exactly what we must not trust). External audit CMB-022:
    /// `Err` when the link is there but the kernel refuses it (`EACCES`
    /// from `ptrace_may_access` without `CAP_SYS_PTRACE`) — "could not
    /// check", which is neither protected nor unprotected by itself.
    fn resolve_exe(&self, pid: u32) -> io::Result<Option<PathBuf>> {
        let link = self.proc_root.join(pid.to_string()).join("exe");
        let exe = match (self.read_link)(&link) {
            Ok(exe) => exe,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(e) if e.raw_os_error() == Some(libc::ESRCH) => return Ok(None),
            Err(e) => return Err(e),
        };
        if exe.to_string_lossy().ends_with(" (deleted)") {
            return Ok(None);
        }
        Ok(Some(exe))
    }

    /// External audit CMB-003: the SSH service is an sshd (`exe`, read
    /// from `/proc/<pid>/exe`) running as root inside an SSH unit — or,
    /// where `/proc/<pid>/cgroup` names no systemd unit at all, an sshd
    /// running as root.
    fn is_ssh_service(&self, pid: u32, exe: &Path) -> bool {
        if !self.sshd_exes.iter().any(|p| p.as_path() == exe) || self.real_uid(pid) != Some(0) {
            return false;
        }
        match self.systemd_unit(pid) {
            Some(unit) => is_ssh_unit(&unit),
            None => true,
        }
    }

    /// External audit CMB-022: `pid`'s executable could not be read
    /// (`err`). Spared only on an anchor it cannot forge — the verified
    /// watchdog slot (PID and start time), or real uid 0 in an SSH unit
    /// or the watchdog's unit of the system manager; otherwise fair game.
    fn judge_unreadable(&self, pid: u32, err: &io::Error) -> Option<ProtectedReason> {
        let (reason, anchor) =
            if self.stack.watchdog_pid() == Some(pid) && self.stack.is_exempt(pid) {
                (
                    Some(ProtectedReason::Watchdog),
                    "the verified watchdog (pid and start time)",
                )
            } else if self.real_uid(pid) == Some(0) {
                match self.system_unit(pid) {
                    Some(unit) if is_ssh_unit(&unit) => {
                        (Some(ProtectedReason::SshService), "uid 0 in an SSH unit")
                    }
                    Some(unit) if unit == WATCHDOG_UNIT => (
                        Some(ProtectedReason::Watchdog),
                        "uid 0 in northnarrow-watchdog.service",
                    ),
                    _ => (None, "uid 0 outside the SSH and watchdog units"),
                }
            } else {
                (None, "not uid 0")
            };
        if let Some(held_back) = self.unreadable_warn.hit(Instant::now()) {
            warn!(
                target: "combat.ladder",
                pid,
                error = %err,
                spared = reason.map_or("no", |r| r.as_str()),
                anchor,
                held_back,
                "COMBAT guard: /proc/<pid>/exe unreadable (CAP_SYS_PTRACE missing?) — spared \
                 only on its uid-0 unit or the verified watchdog, otherwise not"
            );
        }
        reason
    }

    /// The real uid of `pid` (`Uid:` in `/proc/<pid>/status`).
    fn real_uid(&self, pid: u32) -> Option<u32> {
        let status =
            fs::read_to_string(self.proc_root.join(pid.to_string()).join("status")).ok()?;
        status
            .lines()
            .find_map(|l| l.strip_prefix("Uid:"))?
            .split_whitespace()
            .next()?
            .parse()
            .ok()
    }

    /// `pid`'s cgroup path: the unified hierarchy (`0::/…`), or systemd's
    /// own on a v1 host.
    fn cgroup_path(&self, pid: u32) -> Option<String> {
        let cgroup =
            fs::read_to_string(self.proc_root.join(pid.to_string()).join("cgroup")).ok()?;
        cgroup
            .lines()
            .find_map(|l| l.strip_prefix("0::"))
            .or_else(|| {
                cgroup
                    .lines()
                    .find_map(|l| l.split_once(":name=systemd:").map(|(_, p)| p))
            })
            .map(str::to_string)
    }

    /// The systemd unit (`*.service`, `*.scope`) `pid` runs in, read from
    /// its cgroup path; `None` when the path names none (no systemd).
    fn systemd_unit(&self, pid: u32) -> Option<String> {
        last_unit(&self.cgroup_path(pid)?)
    }

    /// External audit CMB-022: [`Self::systemd_unit`], only for a unit of
    /// the system manager (`/system.slice/…`) — never one under a user's
    /// manager (`user@<uid>.service`), who names its units as it likes.
    fn system_unit(&self, pid: u32) -> Option<String> {
        let path = self.cgroup_path(pid)?;
        if !path.starts_with("/system.slice/") {
            return None;
        }
        last_unit(&path)
    }
}

/// The last `*.service` / `*.scope` component of a cgroup path.
fn last_unit(path: &str) -> Option<String> {
    path.rsplit('/')
        .find(|c| c.ends_with(".service") || c.ends_with(".scope"))
        .map(str::to_string)
}

/// An SSH unit ([`SSH_UNIT_PREFIXES`]).
fn is_ssh_unit(unit: &str) -> bool {
    SSH_UNIT_PREFIXES.iter().any(|p| unit.starts_with(p))
}

/// External audit CMB-003: the systemd units the SSH service runs in —
/// Debian/Ubuntu's `ssh.service`, everyone else's `sshd.service`, and
/// their per-connection instances under socket activation.
const SSH_UNIT_PREFIXES: &[&str] = &["ssh.service", "sshd.service", "ssh@", "sshd@"];

impl ProtectedProcs for SystemProtectedProcs {
    fn protected_reason(&self, pid: u32) -> Option<ProtectedReason> {
        if pid == 1 {
            return Some(ProtectedReason::Init);
        }
        // `agent_pid` is never 0/1 (own PID), so order vs. init is moot.
        if pid == self.agent_pid {
            return Some(ProtectedReason::AgentSelf);
        }
        let exe = match self.resolve_exe(pid) {
            Ok(Some(exe)) => exe,
            Ok(None) => return None,
            Err(e) => return self.judge_unreadable(pid, &e),
        };
        // Watchdog: the refreshed slot names the PID, but re-verify the exe
        // inline so a PID recycled to a different binary between refreshes
        // does NOT inherit the watchdog's kill/net-cut immunity.
        if self.stack.watchdog_pid() == Some(pid) && exe == self.watchdog_exe {
            return Some(ProtectedReason::Watchdog);
        }
        if self.is_ssh_service(pid, &exe) {
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
        stack.set_watchdog(4300, 1);
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
        stack.set_watchdog(5000, 1);
        assert_eq!(g.protected_reason(5000), Some(ProtectedReason::Watchdog));
        // Watchdog restart clears the slot → old PID is fair game again.
        stack.clear_watchdog();
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
        stack.set_watchdog(5000, 1);
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
        stack.set_watchdog(5000, 1); // nothing linked at <tmp>/5000/exe
        let g = guard(tmp.path(), 10, stack);
        assert_eq!(g.protected_reason(5000), None);
    }

    /// `<proc_root>/<pid>/status` (real uid) and `cgroup` (unified path).
    fn proc_identity(proc_root: &Path, pid: u32, uid: u32, cgroup: &str) {
        let dir = proc_root.join(pid.to_string());
        fs::create_dir_all(&dir).unwrap();
        fs::write(
            dir.join("status"),
            format!("Name:\tsshd\nUid:\t{uid}\t{uid}\t{uid}\t{uid}\n"),
        )
        .unwrap();
        fs::write(dir.join("cgroup"), format!("0::{cgroup}\n")).unwrap();
    }

    #[test]
    fn recognizes_sshd_by_kernel_resolved_exe() {
        let tmp = TempDir::new().unwrap();
        link_exe(tmp.path(), 800, SSHD_EXE);
        proc_identity(tmp.path(), 800, 0, "/system.slice/ssh.service");
        link_exe(tmp.path(), 801, "/usr/bin/python3"); // a non-sshd process
        proc_identity(tmp.path(), 801, 0, "/system.slice/ssh.service");
        let g = guard(tmp.path(), 10, ExemptPids::with_agent(10));
        assert_eq!(g.protected_reason(800), Some(ProtectedReason::SshService));
        assert_eq!(g.protected_reason(801), None);
        // A PID with no /proc entry resolves to None (not a crash).
        assert_eq!(g.protected_reason(999_999), None);
    }

    /// External audit CMB-003: the SSH service, not whoever runs its
    /// binary — a user's own sshd, or root's sshd outside the unit, is
    /// fair game; socket-activated instances and RHEL's unit name are
    /// the service; with no systemd unit at all, exe and uid 0 decide.
    #[test]
    fn sshd_exe_outside_the_ssh_unit_is_not_protected() {
        let tmp = TempDir::new().unwrap();
        let cases: &[(u32, u32, &str, bool)] = &[
            (
                900,
                1000,
                "/user.slice/user-1000.slice/session-3.scope",
                false,
            ),
            (901, 1000, "/system.slice/ssh.service", false),
            (902, 0, "/user.slice/user-1000.slice/session-3.scope", false),
            (903, 0, "/system.slice/sshd.service", true),
            (
                904,
                0,
                "/system.slice/system-sshd.slice/sshd@1-10.0.0.1:22-10.0.0.2:51515.service",
                true,
            ),
            (905, 0, "/", true),
        ];
        for &(pid, uid, cgroup, _) in cases {
            link_exe(tmp.path(), pid, SSHD_EXE);
            proc_identity(tmp.path(), pid, uid, cgroup);
        }
        let g = guard(tmp.path(), 10, ExemptPids::with_agent(10));
        for &(pid, uid, cgroup, protected) in cases {
            assert_eq!(
                g.protected_reason(pid).is_some(),
                protected,
                "uid {uid} in {cgroup}"
            );
        }
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

    /// External audit CMB-022: the target of an exe link the kernel refuses
    /// to resolve in these tests (`EACCES`, as for a cross-uid,
    /// non-dumpable or more privileged process without `CAP_SYS_PTRACE`).
    const DENIED: &str = "/nn-test/EACCES";

    /// `fs::read_link`, with [`DENIED`] answered `PermissionDenied`.
    fn read_link_denying(link: &Path) -> io::Result<PathBuf> {
        match fs::read_link(link) {
            Ok(t) if t == Path::new(DENIED) => Err(io::Error::from_raw_os_error(libc::EACCES)),
            r => r,
        }
    }

    /// `<proc_root>/<pid>/stat` whose `starttime` (field 22) is `ticks`.
    fn write_started(proc_root: &Path, pid: u32, ticks: u64) {
        let dir = proc_root.join(pid.to_string());
        fs::create_dir_all(&dir).unwrap();
        // `comm` with a space and a parenthesis, as a process may name itself.
        fs::write(
            dir.join("stat"),
            format!("{pid} (wd) x) S 1 1 1 0 -1 4194560 0 0 0 0 0 0 0 0 20 0 1 0 {ticks} 0 0\n"),
        )
        .unwrap();
    }

    /// The guard over `proc_root` whose `readlink` refuses [`DENIED`].
    fn denying_guard(proc_root: &Path, stack: ExemptPids) -> SystemProtectedProcs {
        guard(proc_root, 10, stack).with_read_link(read_link_denying)
    }

    /// External audit CMB-022: the watchdog the refresh task verified (its
    /// PID with the start time recorded then) is spared when its exe can no
    /// longer be read; the same PID started later (recycled) is not.
    #[test]
    fn an_unreadable_exe_with_the_watchdog_identity_is_spared() {
        let tmp = TempDir::new().unwrap();
        let stack = ExemptPids::with_agent_on(10, tmp.path());
        link_exe(tmp.path(), 5000, DENIED);
        write_started(tmp.path(), 5000, 777);
        stack.set_watchdog(5000, 777);
        let g = denying_guard(tmp.path(), stack.clone());
        assert_eq!(g.protected_reason(5000), Some(ProtectedReason::Watchdog));
        // A process that drew the PID since (another start) is not.
        write_started(tmp.path(), 5000, 9_000);
        assert_eq!(g.protected_reason(5000), None);
        // Nor any PID while no watchdog is verified.
        write_started(tmp.path(), 5000, 777);
        stack.clear_watchdog();
        assert_eq!(g.protected_reason(5000), None);
    }

    /// External audit CMB-022: an SSH daemon whose exe cannot be read
    /// (`sshd` runs with every capability; its privilege-separation
    /// processes are not dumpable) is spared as uid 0 in an SSH unit of the
    /// system manager; the watchdog likewise in its own unit (its slot is
    /// empty when the refresh cannot read its exe either).
    #[test]
    fn an_unreadable_exe_of_a_root_sshd_unit_is_spared() {
        let tmp = TempDir::new().unwrap();
        let cases: &[(u32, &str, ProtectedReason)] = &[
            (
                800,
                "/system.slice/ssh.service",
                ProtectedReason::SshService,
            ),
            (
                801,
                "/system.slice/sshd.service",
                ProtectedReason::SshService,
            ),
            (
                802,
                "/system.slice/system-sshd.slice/sshd@1-10.0.0.1:22-10.0.0.2:51515.service",
                ProtectedReason::SshService,
            ),
            (
                803,
                "/system.slice/northnarrow-watchdog.service",
                ProtectedReason::Watchdog,
            ),
        ];
        for &(pid, cgroup, _) in cases {
            link_exe(tmp.path(), pid, DENIED);
            proc_identity(tmp.path(), pid, 0, cgroup);
        }
        let g = denying_guard(tmp.path(), ExemptPids::with_agent_on(10, tmp.path()));
        for &(pid, cgroup, reason) in cases {
            assert_eq!(g.protected_reason(pid), Some(reason), "{cgroup}");
        }
    }

    /// External audit CMB-022: "unreadable" is no immunity — a process
    /// that made itself non-dumpable, any other uid, root outside those
    /// units, a unit a user's manager named `ssh.service`, a host without
    /// systemd units: all fair game.
    #[test]
    fn an_unreadable_exe_elsewhere_is_not_spared() {
        let tmp = TempDir::new().unwrap();
        let cases: &[(u32, u32, &str)] = &[
            (900, 1000, "/user.slice/user-1000.slice/session-3.scope"),
            (901, 1000, "/system.slice/ssh.service"),
            (902, 0, "/user.slice/user-1000.slice/session-3.scope"),
            (903, 0, "/system.slice/cron.service"),
            (
                904,
                0,
                "/user.slice/user-1000.slice/user@1000.service/app.slice/ssh.service",
            ),
            (
                905,
                1000,
                "/user.slice/user-1000.slice/user@1000.service/app.slice/northnarrow-watchdog.service",
            ),
            (906, 0, "/"),
            (907, 0, "/ssh.service"),
            (908, 65534, "/system.slice/northnarrow-watchdog.service"),
        ];
        for &(pid, uid, cgroup) in cases {
            link_exe(tmp.path(), pid, DENIED);
            proc_identity(tmp.path(), pid, uid, cgroup);
        }
        // No status or cgroup readable at all.
        link_exe(tmp.path(), 909, DENIED);
        let g = denying_guard(tmp.path(), ExemptPids::with_agent_on(10, tmp.path()));
        for &(pid, uid, cgroup) in cases {
            assert_eq!(g.protected_reason(pid), None, "uid {uid} in {cgroup}");
        }
        assert_eq!(g.protected_reason(909), None);
        // PID 1 and the agent stay what they are, readable or not.
        link_exe(tmp.path(), 1, DENIED);
        assert_eq!(g.protected_reason(1), Some(ProtectedReason::Init));
        assert_eq!(g.protected_reason(10), Some(ProtectedReason::AgentSelf));
    }

    /// External audit CMB-022: a PID gone between the decision and the
    /// read (`ENOENT`, `ESRCH`) is not "unreadable" — nothing to spare.
    #[test]
    fn a_gone_pid_is_not_unreadable() {
        fn gone(_: &Path) -> io::Result<PathBuf> {
            Err(io::Error::from_raw_os_error(libc::ESRCH))
        }
        let tmp = TempDir::new().unwrap();
        proc_identity(tmp.path(), 800, 0, "/system.slice/ssh.service");
        let g = guard(tmp.path(), 10, ExemptPids::with_agent(10)).with_read_link(gone);
        assert!(matches!(g.resolve_exe(800), Ok(None)));
        assert_eq!(g.protected_reason(800), None);
    }

    /// The unreadable-exe WARN: once per period, the calls in between
    /// counted into the next one.
    #[test]
    fn the_unreadable_warning_is_rate_limited() {
        let w = WarnEvery::new(Duration::from_secs(60));
        let t0 = Instant::now();
        assert_eq!(w.hit(t0), Some(0));
        assert_eq!(w.hit(t0 + Duration::from_secs(1)), None);
        assert_eq!(w.hit(t0 + Duration::from_secs(59)), None);
        assert_eq!(w.hit(t0 + Duration::from_secs(60)), Some(2));
        assert_eq!(w.hit(t0 + Duration::from_secs(61)), None);
    }

    #[test]
    fn no_protected_procs_protects_nothing() {
        let g = NoProtectedProcs;
        assert_eq!(g.protected_reason(1), None);
        assert_eq!(g.protected_reason(std::process::id()), None);
    }
}
