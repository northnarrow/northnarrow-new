//! The production host-critical process guard of the COMBAT ladder,
//! [`SystemProtectedProcs`]: which processes are PID 1, the agent, its
//! watchdog and the SSH service, read from the live `/proc`.
//!
//! R08c (lab PR 252): why the ladder has a guard, the guard's trait and the
//! reasons it names are nn-core's (`combat::protected`, the ladder's), here
//! under their names; this file keeps the Linux guard, for nn-linux (R09).
//!
//! ## Identity: PID + kernel-resolved exe, never `comm`
//!
//! `comm` is attacker-controllable (`prctl(PR_SET_NAME, …)`), so a guard
//! that keyed on it would let any process rename itself to gain immunity —
//! the exact bypass [`crate::posture::exempt`] and
//! [`nn_core::posture::lineage`] are built to avoid. We therefore key on:
//!
//! - `pid == 1` for init and `pid == agent_pid` for the agent (neither
//!   can be a recycled impostor: PID 1 is init for the life of the boot,
//!   and `agent_pid` is our own live PID), and
//! - the kernel-resolved **`/proc/<pid>/exe`** symlink for the watchdog
//!   and sshd. The watchdog PID comes from the timer-refreshed
//!   `ExemptPids` slot, but that slot is only re-verified every ~30 s —
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
//! PID with the start time it was verified with (`ExemptPids`,
//! POS-009), or real uid 0 inside the SSH units or the watchdog's own
//! unit of the system manager (`/system.slice/…`; a user's manager can
//! name a unit of its own anything, never run uid 0 in it). Every other
//! unreadable PID is fair game, and a rate-limited WARN says which way
//! each went. The boot declares the missing capability
//! ([`crate::response::caps_preflight`]).
//!
//! The guard is injected into nn-core's `CombatLadder` as a trait object
//! (like the actuator/evidence) so the ladder stays a pure, deterministic
//! state machine in unit tests while production reads the live `/proc`.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use tracing::warn;

pub use nn_core::combat::protected::{NoProtectedProcs, ProtectedProcs, ProtectedReason};

use crate::posture::ExemptPids;
use nn_core::response::cgroup::components;

/// Canonical sshd install paths matched against the kernel-resolved
/// `/proc/<pid>/exe`. Mirrors the sshd entries in
/// [`crate::posture::lineage::AUTH_BINARY_EXES`], kept local so this guard
/// names only the SSH service, not the wider PAM-auth set.
pub const SSHD_EXES: &[&str] = &["/usr/sbin/sshd", "/usr/libexec/openssh/sshd"];

/// Production guard: PID 1 + the agent + the watchdog (reused
/// `ExemptPids` slot, re-verified inline by exe) + sshd, both identified
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
    #[cfg(any(test, feature = "test-util"))]
    pub fn with_parts(
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
        // A hint used to distrust only (lot 312: never to decide a file is
        // gone): a binary the kernel marks deleted is not the one to spare.
        if crate::response::inode::kernel_marks_deleted(&exe) {
            return Ok(None);
        }
        Ok(Some(exe))
    }

    /// External audit CMB-003: the SSH service is an sshd (`exe`, read
    /// from `/proc/<pid>/exe`) running as root inside an SSH unit of the
    /// system manager — or, on a host without systemd, an sshd running as
    /// root.
    ///
    /// Lot 312 (external bug hunt 1.4, BUG-114 sibling, N5): the unit was
    /// the deepest `*.service`/`*.scope` of the path, anywhere in it — a
    /// root sshd of a container in `…/docker-<id>.scope/system.slice/
    /// ssh.service` was the host's SSH service — and a path with no unit at
    /// all (a container under cgroupfs, `/docker/<id>`) read as a host
    /// without systemd. Now: a path with units is the SSH service only in
    /// the system manager's own SSH unit ([`system_unit_of`]); one without
    /// any, or unreadable, only where PID 1 is not systemd (the decision is
    /// the host's, not the process's).
    fn is_ssh_service(&self, pid: u32, exe: &Path) -> bool {
        if !self.sshd_exes.iter().any(|p| p.as_path() == exe) || self.real_uid(pid) != Some(0) {
            return false;
        }
        match self.cgroup_path(pid) {
            Some(path) if has_unit(&path) => system_unit_of(&path).is_some_and(is_ssh_unit),
            _ => !self.host_runs_systemd(),
        }
    }

    /// Lot 312 (N5): PID 1 runs in systemd's `/init.scope` — a host whose
    /// processes the system manager places in units.
    fn host_runs_systemd(&self) -> bool {
        self.cgroup_path(1)
            .and_then(|p| components(&p).map(|c| c == ["init.scope"]))
            .unwrap_or(false)
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
            crate::state_read::read_state(self.proc_root.join(pid.to_string()).join("status"))
                .ok()?;
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
            crate::state_read::read_state(self.proc_root.join(pid.to_string()).join("cgroup"))
                .ok()?;
        super::offender::cgroup_path(&cgroup).map(str::to_string)
    }

    /// External audit CMB-022: the unit of the system manager `pid` runs
    /// in ([`system_unit_of`]) — never one under a user's manager
    /// (`user@<uid>.service`), who names its units as it likes.
    fn system_unit(&self, pid: u32) -> Option<String> {
        system_unit_of(&self.cgroup_path(pid)?).map(str::to_string)
    }
}

/// The slices the system manager's units of interest live in, from the
/// root (lot 273d: our units' slice of their own, the system manager's
/// too).
const SYSTEM_SLICES: &[&str] = &["system.slice", "northnarrow.slice"];

/// Lot 312 (external bug hunt 1.4, BUG-114, N5): the unit of the system
/// manager a cgroup path places a process in, read by components from the
/// root: one of [`SYSTEM_SLICES`], any sub-slices (`system-sshd.slice`),
/// then ONE unit (`*.service`, `*.scope`), the last component. The deepest
/// unit anywhere in the path was taken: in a container's
/// `/system.slice/docker-<id>.scope/system.slice/ssh.service`, or a
/// service's own subtree `/system.slice/containerd.service/ssh.service`,
/// that was `ssh.service` — a unit the container (or the service) names as
/// it likes. A path with more than one unit is in none of the system
/// manager's.
fn system_unit_of(path: &str) -> Option<&str> {
    let parts = components(path)?;
    let (first, rest) = parts.split_first()?;
    let (unit, slices) = rest.split_last()?;
    (SYSTEM_SLICES.contains(first)
        && slices.iter().all(|c| unit_type(c) == Some("slice"))
        && is_unit(unit))
    .then_some(*unit)
}

/// A unit that runs processes: `*.service` or `*.scope`.
fn is_unit(component: &str) -> bool {
    matches!(unit_type(component), Some("service" | "scope"))
}

/// The type of a unit name (`ssh.service` → `service`), from its last dot.
fn unit_type(component: &str) -> Option<&str> {
    component.rsplit_once('.').map(|(_, t)| t)
}

/// Some component of the path is a unit ([`is_unit`]).
fn has_unit(path: &str) -> bool {
    components(path).is_some_and(|c| c.iter().any(|c| is_unit(c)))
}

/// Lot 312 (external bug hunt 1.4, BUG-122, the coordinator's decision):
/// what sparing a host-critical process covers in a tree kill. The agent,
/// its watchdog and init are protected with their whole tree; the SSH
/// service is spared alone — an offender's process below an sshd is the
/// offender's, and is killed.
pub fn spare_of(reason: ProtectedReason) -> crate::response::kill::Spare {
    use crate::response::kill::Spare;
    match reason {
        ProtectedReason::Init | ProtectedReason::AgentSelf | ProtectedReason::Watchdog => {
            Spare::tree(reason.as_str())
        }
        ProtectedReason::SshService => Spare::process(reason.as_str()),
    }
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
        for &(pid, _, cgroup, protected) in cases {
            assert_eq!(
                g.protected_reason(pid).is_some(),
                protected,
                "case {pid} (its real id in the table above) in {cgroup}"
            );
        }
    }

    /// Lot 311: the SSH service whose `status` shows a `comm` that is not
    /// UTF-8 is still told by its real uid. On main its `status` was
    /// unreadable as text: the uid unknown, the service not spared.
    #[test]
    fn sshd_whose_comm_is_not_utf8_is_still_the_ssh_service() {
        let tmp = TempDir::new().unwrap();
        link_exe(tmp.path(), 806, SSHD_EXE);
        proc_identity(tmp.path(), 806, 0, "/system.slice/ssh.service");
        fs::write(
            tmp.path().join("806").join("status"),
            b"Name:\t\xff\xfe\nUid:\t0\t0\t0\t0\n",
        )
        .unwrap();
        let g = guard(tmp.path(), 10, ExemptPids::with_agent(10));
        assert_eq!(g.protected_reason(806), Some(ProtectedReason::SshService));
    }

    /// Lot 311: root's sshd in a cgroup named with bytes that are not UTF-8
    /// (outside the SSH unit) is not the service. On main the `cgroup`
    /// read failed and it read as a host without systemd, where exe and
    /// uid 0 decide: spared.
    #[test]
    fn sshd_in_a_cgroup_whose_name_is_not_utf8_is_not_the_ssh_service() {
        let tmp = TempDir::new().unwrap();
        link_exe(tmp.path(), 807, SSHD_EXE);
        proc_identity(tmp.path(), 807, 0, "/");
        fs::write(
            tmp.path().join("807").join("cgroup"),
            b"0::/user.slice/user-1000.slice/user@1000.service/app.slice/\xff.scope\n",
        )
        .unwrap();
        let g = guard(tmp.path(), 10, ExemptPids::with_agent(10));
        assert_eq!(g.protected_reason(807), None);
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
            // lot 273d: the units' slice of their own
            (
                804,
                "/northnarrow.slice/northnarrow-watchdog.service",
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

    /// Lot 312 (external bug hunt 1.4, BUG-114): uid 0, exe unreadable (no
    /// CAP_SYS_PTRACE), in an `ssh.service` nested below another unit of
    /// /system.slice (systemd in a container, or a `mkdir` in a delegated
    /// cgroup). Promise (module doc "of the system manager",
    /// `system_unit` docs): not the host's SSH service.
    #[test]
    fn bug114_unreadable_exe_in_an_ssh_unit_below_a_container_scope_is_not_spared() {
        let tmp = TempDir::new().unwrap();
        let cases: &[(u32, &str)] = &[
            (
                950,
                "/system.slice/docker-abc.scope/system.slice/ssh.service",
            ),
            (951, "/system.slice/containerd.service/ssh.service"),
            (
                952,
                "/system.slice/docker-abc.scope/system.slice/northnarrow-watchdog.service",
            ),
            // the other spellings of the same nesting
            (953, "/system.slice/ssh.service/ssh.service"),
            (
                954,
                "/northnarrow.slice/x.scope/northnarrow-watchdog.service",
            ),
            (
                955,
                "/system.slice/system-sshd.slice/x.service/sshd@1.service",
            ),
            (956, "/system.slice/ssh.service/payload"),
            (957, "/kubepods.slice/system.slice/ssh.service"),
        ];
        for &(pid, cgroup) in cases {
            link_exe(tmp.path(), pid, DENIED);
            proc_identity(tmp.path(), pid, 0, cgroup);
        }
        let g = denying_guard(tmp.path(), ExemptPids::with_agent_on(10, tmp.path()));
        let got: Vec<_> = cases
            .iter()
            .map(|&(pid, _)| g.protected_reason(pid))
            .collect();
        assert_eq!(
            got,
            vec![None; cases.len()],
            "BUG-114: nested units {cases:?} are not the system manager's"
        );
    }

    /// Lot 312, sibling of BUG-114 on the READABLE path (default config,
    /// CAP_SYS_PTRACE held): `is_ssh_service` took the deepest unit too and
    /// had no /system.slice anchor at all. A root process of a container
    /// without a user namespace whose exe resolves to /usr/sbin/sshd (the
    /// path inside its own mount namespace) in a nested `ssh.service` was
    /// spared.
    #[test]
    fn bug114_sibling_readable_sshd_in_a_nested_ssh_unit_is_not_spared() {
        let tmp = TempDir::new().unwrap();
        for (pid, cgroup) in [
            (
                960,
                "/system.slice/docker-abc.scope/system.slice/ssh.service",
            ),
            (
                961,
                "/user.slice/user-1000.slice/user@1000.service/app.slice/ssh.service",
            ),
            (962, "/system.slice/containerd.service/sshd.service"),
        ] {
            link_exe(tmp.path(), pid, SSHD_EXE);
            proc_identity(tmp.path(), pid, 0, cgroup);
            let g = guard(tmp.path(), 10, ExemptPids::with_agent(10));
            assert_eq!(
                g.protected_reason(pid),
                None,
                "BUG-114 sibling: uid 0 sshd in {cgroup} is not the host's SSH service"
            );
        }
    }

    /// Guard (must stay): the host's own SSH and watchdog units.
    #[test]
    fn bug114_guard_the_host_units_stay_spared() {
        let tmp = TempDir::new().unwrap();
        link_exe(tmp.path(), 970, DENIED);
        proc_identity(tmp.path(), 970, 0, "/system.slice/ssh.service");
        link_exe(tmp.path(), 971, DENIED);
        proc_identity(
            tmp.path(),
            971,
            0,
            "/system.slice/system-sshd.slice/sshd@1-10.0.0.1:22-10.0.0.2:51515.service",
        );
        link_exe(tmp.path(), 972, SSHD_EXE);
        proc_identity(tmp.path(), 972, 0, "/system.slice/ssh.service");
        let g = denying_guard(tmp.path(), ExemptPids::with_agent_on(10, tmp.path()));
        assert_eq!(g.protected_reason(970), Some(ProtectedReason::SshService));
        assert_eq!(g.protected_reason(971), Some(ProtectedReason::SshService));
        assert_eq!(g.protected_reason(972), Some(ProtectedReason::SshService));
    }

    /// Lot 312 (N5): a root sshd in a cgroup with no unit at all (a
    /// container under the cgroupfs driver, `/docker/<id>`; the root
    /// cgroup) is spared only on a host without systemd — PID 1 not in
    /// `/init.scope`. It read as "no systemd" on every host. And BUG-121's
    /// host (v1 with cgroup2 mounted: `0::/` for all) is a systemd host by
    /// PID 1's own `name=systemd` line.
    #[test]
    fn n5_a_unitless_cgroup_spares_sshd_only_on_a_host_without_systemd() {
        let tmp = TempDir::new().unwrap();
        for (pid, cgroup) in [(980, "/docker/0123abcd"), (981, "/")] {
            link_exe(tmp.path(), pid, SSHD_EXE);
            proc_identity(tmp.path(), pid, 0, cgroup);
        }
        // unreadable cgroup
        link_exe(tmp.path(), 982, SSHD_EXE);
        proc_identity(tmp.path(), 982, 0, "/");
        fs::remove_file(tmp.path().join("982/cgroup")).unwrap();
        let g = guard(tmp.path(), 10, ExemptPids::with_agent(10));
        // PID 1 unknown, or outside a unit: no systemd — exe and uid 0 decide
        for pid in [980, 981, 982] {
            assert_eq!(
                g.protected_reason(pid),
                Some(ProtectedReason::SshService),
                "{pid}"
            );
        }
        for init in ["/", "/lxc.payload.c1", "/init.scope/x"] {
            proc_identity(tmp.path(), 1, 0, init);
            for pid in [980, 981, 982] {
                assert_eq!(
                    g.protected_reason(pid),
                    Some(ProtectedReason::SshService),
                    "{pid}, PID 1 in {init}"
                );
            }
        }
        // PID 1 in /init.scope: a systemd host, the unit decides
        proc_identity(tmp.path(), 1, 0, "/init.scope");
        for pid in [980, 981, 982] {
            assert_eq!(
                g.protected_reason(pid),
                None,
                "N5: pid {pid} on a systemd host"
            );
        }
        // the v1 host of BUG-121 (cgroup2 mounted once: `0::/` everywhere)
        let v1 = |sys: &str| format!("4:memory:{sys}\n1:name=systemd:{sys}\n0::/\n");
        fs::write(tmp.path().join("1/cgroup"), v1("/init.scope")).unwrap();
        fs::write(
            tmp.path().join("981/cgroup"),
            v1("/user.slice/user-1000.slice/session-3.scope"),
        )
        .unwrap();
        link_exe(tmp.path(), 983, SSHD_EXE);
        proc_identity(tmp.path(), 983, 0, "/");
        fs::write(
            tmp.path().join("983/cgroup"),
            v1("/system.slice/ssh.service"),
        )
        .unwrap();
        assert_eq!(g.protected_reason(981), None, "BUG-121: a session's sshd");
        assert_eq!(g.protected_reason(983), Some(ProtectedReason::SshService));
    }

    /// Lot 312 (BUG-122, the coordinator's decision): the agent, its
    /// watchdog and init are spared with their tree in a tree kill; the SSH
    /// service alone.
    #[test]
    fn bug122_what_a_spared_reason_covers() {
        use crate::response::kill::Spare;
        for r in [
            ProtectedReason::Init,
            ProtectedReason::AgentSelf,
            ProtectedReason::Watchdog,
        ] {
            assert_eq!(spare_of(r), Spare::tree(r.as_str()), "{r}");
        }
        assert_eq!(
            spare_of(ProtectedReason::SshService),
            Spare::process("ssh-service(sshd)")
        );
    }

    /// The system manager's unit, by components (property over the
    /// alphabet of the paths above): never more than one unit, never
    /// outside the system slices, always the last component.
    #[test]
    fn the_system_unit_is_the_one_unit_under_a_system_slice() {
        let alphabet = [
            "system.slice",
            "northnarrow.slice",
            "system-sshd.slice",
            "user.slice",
            "ssh.service",
            "docker-abc.scope",
            "x",
        ];
        let mut layer = vec![String::new()];
        let mut checked = 0;
        for _ in 0..4 {
            let mut next = Vec::new();
            for p in &layer {
                for c in alphabet {
                    let path = format!("{p}/{c}");
                    let parts: Vec<&str> = path[1..].split('/').collect();
                    let units = parts.iter().filter(|c| is_unit(c)).count();
                    let got = system_unit_of(&path);
                    let want = (units == 1
                        && is_unit(parts[parts.len() - 1])
                        && SYSTEM_SLICES.contains(&parts[0])
                        && parts[1..parts.len() - 1]
                            .iter()
                            .all(|c| unit_type(c) == Some("slice")))
                    .then(|| parts[parts.len() - 1]);
                    assert_eq!(got, want, "{path}");
                    checked += 1;
                    next.push(path);
                }
            }
            layer = next;
        }
        assert!(checked > 2000, "{checked}");
    }
}
