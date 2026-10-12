//! T7.13 — sudo-mediated process lineage tracking (Beta Step 5).
//!
//! The agent's posture machine has two trigger arms that fire on
//! legitimate `sudo` activity:
//!
//! 1. [`super::triggers::sensitive_file_access`] — sudo's PAM auth
//!    chain opens `/etc/shadow` while the kernel is still at the
//!    caller's `uid=1000`; the LSM `file_open` observe hook captures
//!    the original `fsuid`, not the post-setuid one.
//! 2. [`super::triggers::confirmed_intrusion`] mass-write arm — sudo
//!    and its elevated child (apt, systemctl, an editor, …) write
//!    ≥20 files inside the 60 s mass-write window during routine
//!    administration, identical in shape to a ransomware burst.
//!
//! Both behaviours are legitimate administration. The previous fixes
//! (PR #123, Beta Step 3) excluded the NorthNarrow stack's own PIDs;
//! T7.13 requires extending the exclusion surface to **operator-driven
//! setuid administration** without granting blanket immunity.
//!
//! [`AuthSessionTracker`] tags a PID as *auth-mediated* if any
//! ancestor's `/proc/<pid>/exe` (a kernel-resolved symlink — not
//! forgeable from userspace) matches the hard-coded
//! [`AUTH_BINARY_EXES`] allowlist of canonical setuid administration
//! binaries. Only [`super::triggers::sensitive_file_access`] and the
//! mass-write arm of [`super::triggers::confirmed_intrusion`] consult
//! the tracker; every other COMBAT-tier trigger (FsProtectDenial,
//! exec from `/tmp` or `/dev/shm`, persistence_mechanism,
//! critical_file_modification, lateral_movement,
//! exfiltration_pattern, exploit_attempt, lolbas_pattern) fires
//! unchanged. An attacker who has compromised an admin's sudo
//! password and is dropping a `/tmp` payload still trips
//! ConfirmedIntrusion via the exec-from-`/tmp` arm.
//!
//! ## Why exe-path, not comm
//!
//! `comm` is attacker-controllable (`prctl(PR_SET_NAME, …)`), so
//! exempting by comm would let any process rename itself `sudo` to
//! gain trigger immunity — the same bypass class the watchdog
//! supervisor model exists to prevent. We instead key on
//! `/proc/<pid>/exe`, which the kernel resolves from the task's
//! `mm->exe_file` and exposes as a symlink that userspace cannot
//! forge. The in-memory cache populated from `Event::ProcessSpawn`
//! records the same path the kernel-side hook reads from the task
//! at exec time.

use std::collections::{HashMap, VecDeque};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use parking_lot::RwLock;

/// Hard-coded allowlist of installed authentication binaries whose
/// children we treat as auth-mediated. Two classes live here:
///
///   1. **setuid/setgid escalation binaries** (sudo, su, doas, pkexec,
///      passwd, …) — a regular user invokes them and their PAM stack
///      reads `/etc/shadow`/`/etc/gshadow` while the kernel still sees
///      the *caller's* uid (the LSM `file_open` hook fires before the
///      setuid transition completes — the original T7.13 FP).
///   2. **PAM-mediated authentication daemons** (sshd, login,
///      systemd-logind, polkitd, cron/crond, gdm/lightdm). These run as
///      root, so a read they perform *as root* is already covered by the
///      `uid < 1000` gate in [`super::triggers::sensitive_file_access`].
///      They are listed here for the harder case: a session/job child
///      observed at the authenticating *user's* pre-setuid uid whose
///      lineage walks back through the daemon (e.g. a `cron` job's PAM
///      `session` open, a `gdm-session-worker` PAM `auth` open). Without
///      the daemon in the allowlist that read is misread as an
///      unexpected `uid >= 1000` credential access and escalates posture
///      (the T7.13 class, generalised beyond `sudo`).
///   3. **PAM setuid credential-verification helpers** (`unix_chkpwd`,
///      `unix_update`). When an *unprivileged* PAM consumer (a screen
///      locker, a display-manager greeter, a polkit prompt) verifies or
///      changes a password it cannot read `/etc/shadow` itself, so
///      `pam_unix` execs the setuid-root helper `unix_chkpwd`. The helper
///      keeps the caller's *real* uid (the sensor reads the real uid via
///      `bpf_get_current_uid_gid`, NOT euid/fsuid), so its `/etc/shadow`
///      read is observed at `uid >= 1000` and is NOT caught by the
///      `uid < 1000` gate — without it here, every screen-unlock /
///      unprivileged-auth password check raises SensitiveFileAccess.
///      (`sudo`/`su` dodge this because they are setuid-root and
///      `pam_unix` reads shadow directly in-process — already covered by
///      class 1.)
///
/// Covers Debian/Ubuntu, Fedora/RHEL, Arch, and openSUSE conventions for
/// the canonical paths. Adding paths is a soft change (expands
/// exemption); removing is a hard change (operators on a distro that
/// uses only the removed path lose coverage). A path absent on a given
/// host simply never matches — harmless.
///
/// SECURITY: matching is on the kernel-resolved, non-forgeable
/// `/proc/<pid>/exe` (NEVER `comm`), exact-path only, and only suppresses
/// the credential-read (`sensitive_file_access`) + mass-write arms —
/// every kernel-adjudicated COMBAT trigger (FsProtectDenial, exec from
/// `/tmp`, persistence, lateral, exfil) still fires. Compromise OF one of
/// these binaries means root, which is outside the posture machine's
/// threat model (the anti-tamper LSM is the defence there).
///
/// Sorted alphabetically for review legibility; lookup is a linear
/// scan over <40 entries, well under any per-event budget.
pub const AUTH_BINARY_EXES: &[&str] = &[
    "/bin/login",
    "/bin/su",
    "/bin/sudo",
    "/lib/systemd/systemd-logind",
    "/sbin/unix_chkpwd",
    "/sbin/unix_update",
    "/usr/bin/chfn",
    "/usr/bin/chsh",
    "/usr/bin/crond",
    "/usr/bin/doas",
    "/usr/bin/gpasswd",
    "/usr/bin/login",
    "/usr/bin/machinectl",
    "/usr/bin/passwd",
    "/usr/bin/pkexec",
    "/usr/bin/su",
    "/usr/bin/sudo",
    "/usr/bin/sudoedit",
    "/usr/bin/systemd-run",
    "/usr/bin/unix_chkpwd",
    "/usr/lib/gdm/gdm-session-worker",
    "/usr/lib/gdm3/gdm-session-worker",
    "/usr/lib/polkit-1/polkit-agent-helper-1",
    "/usr/lib/polkit-1/polkitd",
    "/usr/lib/systemd/systemd-logind",
    "/usr/libexec/gdm-session-worker",
    "/usr/libexec/openssh/sshd",
    "/usr/libexec/polkit-1/polkit-agent-helper-1",
    "/usr/libexec/polkit-1/polkitd",
    "/usr/sbin/cron",
    "/usr/sbin/crond",
    "/usr/sbin/gdm",
    "/usr/sbin/gdm3",
    "/usr/sbin/lightdm",
    "/usr/sbin/sshd",
    "/usr/sbin/unix_chkpwd",
    "/usr/sbin/unix_update",
];

/// Review 52: the binaries an administrator elevates a session through.
/// A subset of [`AUTH_BINARY_EXES`]: the login and scheduling daemons
/// (sshd, cron, logind, gdm, `systemd-run`) start sessions and jobs, they
/// do not elevate one. `sudo` and `su` stay in the lineage (they fork the
/// command and wait for it); `doas` and `pkexec` replace themselves with
/// the command, so they never appear in a lineage and are not listed.
/// Same exact-path, kernel-resolved-exe keying as the lists around it.
pub const ELEVATION_EXES: &[&str] = &[
    "/bin/su",
    "/bin/sudo",
    "/usr/bin/su",
    "/usr/bin/sudo",
    "/usr/bin/sudoedit",
];

/// Hard-coded allowlist of system package-management / cache-refresh
/// daemon exec paths whose mass-write + persistence writes are routine
/// maintenance, not adversarial. Same exe-path keying as
/// [`AUTH_BINARY_EXES`] (kernel-resolved `/proc/<pid>/exe`, NEVER comm).
/// Exact ELF exec paths only — sorted for review legibility.
///
/// Deliberately excluded: `/usr/bin/snap` (the *daemon*
/// `/usr/lib/snapd/snapd` does the writes; the CLI talks over a socket),
/// `/usr/bin/unattended-upgrade` (a Python script whose package writes
/// go through `dpkg`/`apt` children, covered by the ancestry walk), and
/// the apt transport methods (`/usr/lib/apt/methods/*`, children of
/// `apt`/`apt-get`).
///
/// RHEL family (review 49): `rpm` and `microdnf` are ELF binaries.
/// `dnf` and `yum` are Python scripts that run the rpm transaction
/// in-process, so their writes come from the interpreter. They match
/// through the spawn cache, which records the script path the kernel
/// exec event carries (`/usr/bin/dnf`); the `/proc` fallback sees only
/// the interpreter and never matches them. [`DAEMON_CACHE_CAP`] keeps
/// those entries out of the regular FIFO eviction so a long transaction
/// does not lose its root. `packagekitd` drives libdnf in-process too.
///
/// SECURITY: a lineage match suppresses the mass-write arm of
/// [`super::triggers::confirmed_intrusion`] AND
/// [`super::triggers::persistence_mechanism`]. Compromise OF one of
/// these binaries (root + write to a FIM/fs-protect-guarded system dir)
/// inherits the exemption — the same trust boundary as
/// [`AUTH_BINARY_EXES`]. Keep tight; add the most-specific exec path,
/// never a directory.
pub const SYSTEM_DAEMON_EXES: &[&str] = &[
    "/usr/bin/apt",
    "/usr/bin/apt-get",
    "/usr/bin/dnf",
    "/usr/bin/dnf-3",
    "/usr/bin/dpkg",
    "/usr/bin/mandb",
    "/usr/bin/microdnf",
    "/usr/bin/rpm",
    "/usr/bin/yum",
    "/usr/lib/snapd/snapd",
    "/usr/libexec/packagekitd",
];

/// Kernel-resolved exec paths of the Node.js interpreter. `npm` is a
/// `#!/usr/bin/env node` script, so a process running `npm install`
/// has `/proc/<pid>/exe` = the **node** binary (verified empirically),
/// NOT `/usr/bin/npm` — the identical interpreter-exe shape this file
/// documents for `unattended-upgrade` above. An exe path alone
/// therefore cannot name npm without naming *all* node, which would
/// blow a node-shaped hole in the mass-write / ransomware signal. So
/// npm is matched by exe ∈ `NODE_EXES` AND argv (see
/// [`AuthSessionTracker::is_npm_cli_writer`] + [`NPM_CLI_SUFFIX`]),
/// keeping every other node process subject to the mass-write arm.
/// Exact ELF paths only — never `comm`. nvm/volta node lives under
/// `$HOME` and is operator-added, not assumed here.
pub const NODE_EXES: &[&str] = &["/usr/bin/node", "/usr/local/bin/node"];

/// Path suffix of npm's CLI entrypoint. `/usr/bin/npm` symlinks to
/// `…/lib/node_modules/npm/bin/npm-cli.js`, which the shebang hands to
/// node as `argv[1]`. The leading `/npm/bin/` anchors the match so a
/// file merely *named* `npm-cli.js` in some other directory can't
/// satisfy it. Only ever consulted together with a [`NODE_EXES`] exe
/// match, so argv (which a process controls for itself) is never the
/// sole basis for the exemption.
const NPM_CLI_SUFFIX: &str = "/npm/bin/npm-cli.js";

/// Bounded FIFO cap for the in-memory pid→Entry map. At ~64 bytes
/// per entry (pid + ppid + spawn_ns + short PathBuf) the cap is
/// ~128 KiB worst case — comfortably inside the agent's per-task
/// RAM ceiling, sized to cover the long tail of long-lived sudo
/// sessions on a busy workstation. Overflow falls back to the
/// `/proc/<pid>/exe`+`/proc/<pid>/status` walk so a miss is never
/// fatal — just one extra `read_link` + small file read.
const TRACKER_CAP: usize = 2048;

/// Side cache for spawns whose exe is a [`SYSTEM_DAEMON_EXES`] entry.
/// A large package transaction spawns thousands of maintainer-script
/// processes, enough to push the package manager's own entry out of the
/// [`TRACKER_CAP`] FIFO while it is still writing. For `dpkg`/`rpm` the
/// `/proc` fallback recovers it, but `dnf`/`yum` are Python scripts whose
/// `/proc/<pid>/exe` is the interpreter, so only the cache can name them
/// (review 49). These entries live here instead, FIFO-capped on their
/// own; a later spawn reusing the pid drops them.
const DAEMON_CACHE_CAP: usize = 64;

/// Hard ceiling on the per-`is_auth_mediated` lineage walk. A
/// pathological cycle in `/proc` (or a fabricated chain that never
/// reaches PID 0/1) must not hang the trigger detector. 32 is well
/// past the deepest real process tree on a healthy host.
const LINEAGE_DEPTH_CAP: usize = 32;

/// BUG-018 (tactical): sentinel value the kernel writes into
/// `/proc/<pid>/loginuid` when no PAM-authenticated session has been
/// established for that PID. Matches `AUDIT_UID_UNSET` in
/// `<linux/audit.h>` — `(uid_t)-1`, which under Linux's `uid_t = u32`
/// is `0xFFFF_FFFF`.
///
/// Why we care: `pam_loginuid` (run by every modern login chain —
/// sshd, login, gdm, lightdm, systemd-logind's pam_systemd, and the
/// user@<uid>.service unit it transitively starts) writes the
/// authenticated user's UID into `loginuid` once per session, AFTER
/// which the kernel's audit subsystem refuses further writes
/// (`CONFIG_AUDIT_LOGINUID_IMMUTABLE`, the default since kernel 4.x).
/// Even when the file IS writable, the write path requires
/// `CAP_AUDIT_CONTROL` — unprivileged user processes cannot fake a
/// valid value.
///
/// A process whose `loginuid` is NOT this sentinel is therefore in
/// a PAM-authenticated session that the kernel cooperatively
/// recorded. Tactical use case: distinguish systemd-user@<uid>.service
/// children (legitimate user-session helpers) from truly orphan
/// processes (a binary started outside any PAM chain). See BUG-018
/// in the catalog for the FP this fixes.
const LOGINUID_UNSET: u32 = u32::MAX;

/// PID→{ppid, exe, spawn_ns} cache entry recorded from
/// `Event::ProcessSpawn`. `spawn_ns` is retained for forward
/// compatibility with a `(pid, start_ns)` PID-reuse disambiguator;
/// today we simply overwrite the entry on a fresh spawn.
#[derive(Debug, Clone)]
struct Entry {
    ppid: u32,
    exe: PathBuf,
    #[allow(dead_code)]
    spawn_ns: u64,
    /// FP-2: `true` iff this spawn's `argv[1]` is npm's CLI entrypoint
    /// ([`NPM_CLI_SUFFIX`]). Precomputed at ingest so the mass-write
    /// exemption is a single cheap field read AND the variable-length
    /// argv is never retained in the bounded cache. Meaningful only
    /// when `exe` ∈ [`NODE_EXES`] — that exe gate is applied at read
    /// time in [`AuthSessionTracker::is_npm_cli_writer`].
    argv_npm_cli: bool,
    /// Review 85: what an interpreter `exe` runs ([`script_of`]): a script
    /// path or a `-m` module. `None` for a binary, or an inline program.
    script: Option<Box<str>>,
}

/// Review 85: what the kernel executed for a process — its exe and, for
/// an interpreter, the script or module it runs. Read from the spawn
/// cache, else from `/proc`. Never from `comm`, which a process sets for
/// itself.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExecIdentity {
    pub exe: PathBuf,
    pub script: Option<String>,
}

/// Mutex-shielded state. A single lock guards both the map and the
/// FIFO eviction queue so the two never observe each other in an
/// inconsistent state mid-ingest.
#[derive(Debug)]
struct InnerState {
    map: HashMap<u32, Entry>,
    /// [`DAEMON_CACHE_CAP`]-bounded copies of package-manager spawns,
    /// immune to the main FIFO eviction, with their own insertion order.
    daemons: HashMap<u32, Entry>,
    daemon_order: VecDeque<u32>,
    /// Insertion order — pushed on first insert, popped on
    /// eviction. We deliberately do NOT re-promote on overwrite:
    /// strict LRU would cost O(N) per overwrite without buying
    /// correctness, because [`AuthSessionTracker::is_auth_mediated`]
    /// falls back to `/proc` on miss. Any over-eager eviction of a
    /// hot entry simply pays a single readlink+read_to_string on
    /// the next lookup.
    order: VecDeque<u32>,
}

#[derive(Debug)]
struct Inner {
    state: RwLock<InnerState>,
    /// Injectable for tests; `"/proc"` in production.
    proc_root: PathBuf,
}

/// Cheap, `Clone`-able shared handle. The tracker is `Send + Sync`
/// so both the per-event trigger detector and (future) background
/// pruning tasks can hold one without further plumbing.
#[derive(Clone, Debug)]
pub struct AuthSessionTracker {
    inner: Arc<Inner>,
}

impl AuthSessionTracker {
    /// Construct a tracker reading `/proc` from `proc_root`. The
    /// indirection is the test seam: production uses
    /// [`Self::with_proc`]; unit tests point at a fixture tree.
    pub fn new(proc_root: impl Into<PathBuf>) -> Self {
        Self {
            inner: Arc::new(Inner {
                state: RwLock::new(InnerState {
                    map: HashMap::with_capacity(TRACKER_CAP),
                    order: VecDeque::with_capacity(TRACKER_CAP),
                    daemons: HashMap::new(),
                    daemon_order: VecDeque::new(),
                }),
                proc_root: proc_root.into(),
            }),
        }
    }

    /// Production constructor — reads the live `/proc`.
    pub fn with_proc() -> Self {
        Self::new("/proc")
    }

    /// Record a `ProcessSpawn` observation. Overwrites any prior
    /// entry for `pid` (PID reuse — the new spawn replaces the old
    /// lineage). Evicts the oldest first-inserted entry when the
    /// cache reaches [`TRACKER_CAP`].
    ///
    /// PID 0 is the kernel "no process" sentinel and is never
    /// recorded.
    pub fn ingest_spawn(&self, pid: u32, ppid: u32, exe: &str, spawn_ns: u64) {
        self.ingest_inner(pid, ppid, exe, false, None, spawn_ns);
    }

    /// Like [`Self::ingest_spawn`] but also derives the npm-CLI flag
    /// (FP-2) from `argv`. Production feeds this from
    /// `Event::ProcessSpawn { argv, .. }`. We store only the derived
    /// bool (`argv[1]` ends with [`NPM_CLI_SUFFIX`]) — never argv
    /// itself — so the bounded cache stays small. An empty / 1-element
    /// argv leaves the flag false.
    pub fn ingest_spawn_with_argv(
        &self,
        pid: u32,
        ppid: u32,
        exe: &str,
        argv: &[String],
        spawn_ns: u64,
    ) {
        let argv_npm_cli = argv.get(1).is_some_and(|a| a.ends_with(NPM_CLI_SUFFIX));
        let script = script_of(Path::new(exe), argv);
        self.ingest_inner(pid, ppid, exe, argv_npm_cli, script, spawn_ns);
    }

    fn ingest_inner(
        &self,
        pid: u32,
        ppid: u32,
        exe: &str,
        argv_npm_cli: bool,
        script: Option<Box<str>>,
        spawn_ns: u64,
    ) {
        if pid == 0 {
            return;
        }
        let entry = Entry {
            ppid,
            exe: PathBuf::from(exe),
            spawn_ns,
            argv_npm_cli,
            script,
        };
        let mut s = self.inner.state.write();
        // Review 49: package-manager spawns also go to the side cache;
        // any other spawn reusing the pid invalidates a stale copy there.
        if is_system_daemon_binary(&entry.exe) {
            if s.daemons.insert(pid, entry.clone()).is_none() {
                s.daemon_order.push_back(pid);
                while s.daemon_order.len() > DAEMON_CACHE_CAP {
                    if let Some(evict) = s.daemon_order.pop_front() {
                        s.daemons.remove(&evict);
                    }
                }
            }
        } else if s.daemons.remove(&pid).is_some() {
            s.daemon_order.retain(|p| *p != pid);
        }
        let had_prior = s.map.insert(pid, entry).is_some();
        if !had_prior {
            s.order.push_back(pid);
            while s.order.len() > TRACKER_CAP {
                if let Some(evict) = s.order.pop_front() {
                    // Possible-stale guard: only remove if the
                    // map still maps this pid to ANY entry. (A
                    // future PID-reuse handler could promote on
                    // overwrite; today we simply evict whatever
                    // is there, and the `/proc` fallback covers
                    // the rare case where the evicted entry was
                    // freshly overwritten.)
                    s.map.remove(&evict);
                }
            }
        }
    }

    /// True iff `pid` or any ancestor's exe is a canonical setuid
    /// administration binary ([`AUTH_BINARY_EXES`]). Thin wrapper over
    /// [`Self::lineage_exe_matches`] — behaviour is byte-identical to the
    /// pre-refactor inline walk.
    pub fn is_auth_mediated(&self, pid: u32) -> bool {
        self.lineage_exe_matches(pid, is_auth_binary)
    }

    /// True iff `pid` or any ancestor's exe is a known system
    /// package-management / cache-refresh daemon ([`SYSTEM_DAEMON_EXES`]).
    /// Same kernel-resolved `/proc/<pid>/exe` keying as
    /// [`Self::is_auth_mediated`] — `comm` is never consulted
    /// (`prctl(PR_SET_NAME)`-spoofable). Used by the mass-write arm of
    /// [`super::triggers::confirmed_intrusion`] and by
    /// [`super::triggers::persistence_mechanism`] to exempt routine
    /// snapd / dpkg / apt / mandb maintenance from escalation.
    pub fn is_system_daemon_mediated(&self, pid: u32) -> bool {
        self.lineage_exe_matches(pid, is_system_daemon_binary)
    }

    /// Review 52: `pid` belongs to an administrator's interactive session
    /// that elevated through sudo or su — an [`ELEVATION_EXES`] binary in
    /// its lineage, a login uid (a PAM login chain set it) and a
    /// controlling terminal. A service has no login uid; a cron job or a
    /// `systemd-run` unit has no elevation binary; `ssh host sudo …`
    /// without a terminal has no terminal; a process that reached root any
    /// other way (a setuid exploit) has no elevation binary.
    ///
    /// Login uid and terminal are read from `/proc`, on `pid` itself while
    /// it runs. A short-lived writer (`sudo tee`) has usually exited by the
    /// time its event is read; then the nearest running process up its
    /// recorded lineage answers, normally the shell that ran sudo (the
    /// login uid is inherited, and that shell holds the terminal).
    pub fn is_interactive_admin(&self, pid: u32) -> bool {
        if !self.lineage_exe_matches(pid, is_elevation_binary) {
            return false;
        }
        let Some(live) = self.nearest_running(pid) else {
            return false;
        };
        self.has_valid_loginuid(live) && self.has_controlling_tty(live)
    }

    /// The login uid of `pid`, or of its nearest running ancestor once it
    /// has exited: the login uid is inherited, so the session's shell
    /// answers for a short-lived process. Scopes the posture's
    /// corroboration ledger.
    pub fn session_loginuid(&self, pid: u32) -> Option<u32> {
        self.loginuid_of(self.nearest_running(pid)?)
    }

    /// Review 52: [`Self::is_interactive_admin`] for the posture's
    /// corroboration ledger, or `None` while it cannot be told. That is
    /// the case when the lineage walk loses the chain before it ends (a
    /// process that is exiting and whose `exe` is gone, or a parent that
    /// has exited with no exec event in the cache: sudo's monitor is a
    /// fork without exec), or when sudo/su is found but nothing of the
    /// session runs any more to show a login uid and a terminal.
    pub fn interactive_admin_status(&self, pid: u32) -> Option<bool> {
        if !self.lineage_exe_matches_known(pid, is_elevation_binary)? {
            return Some(false);
        }
        let live = self.nearest_running(pid)?;
        Some(self.has_valid_loginuid(live) && self.has_controlling_tty(live))
    }

    /// [`Self::lineage_exe_matches`], but `None` when a hop can be read
    /// neither from the spawn cache nor from `/proc` before the walk ends.
    fn lineage_exe_matches_known(
        &self,
        pid: u32,
        is_match: impl Fn(&Path) -> bool,
    ) -> Option<bool> {
        if pid == 0 || pid == 1 {
            return Some(false);
        }
        let mut cur = pid;
        for _ in 0..LINEAGE_DEPTH_CAP {
            let (ppid, exe) = self.lookup_cache(cur).or_else(|| self.lookup_proc(cur))?;
            if is_match(&exe) {
                return Some(true);
            }
            if ppid == 0 || ppid == 1 || ppid == cur {
                return Some(false);
            }
            cur = ppid;
        }
        Some(false)
    }

    /// `/proc/<pid>` exists and is not a zombie. A zombie (`Z`: exited, not
    /// yet reaped by its parent) still has its directory, but its `exe` is
    /// gone and its lineage can no longer be read: `sudo tee` sits in that
    /// state until sudo reaps it.
    fn is_running(&self, pid: u32) -> bool {
        let dir = self.inner.proc_root.join(pid.to_string());
        if !dir.is_dir() {
            return false;
        }
        let Ok(stat) = fs::read_to_string(dir.join("stat")) else {
            return true;
        };
        let state = stat
            .rsplit_once(')')
            .and_then(|(_, rest)| rest.split_whitespace().next());
        !matches!(state, Some("Z" | "X"))
    }

    /// `pid` if it still runs, else the nearest running ancestor in the
    /// spawn cache. `None` past PID 1, a cache miss, or the depth cap.
    fn nearest_running(&self, pid: u32) -> Option<u32> {
        let mut cur = pid;
        for _ in 0..LINEAGE_DEPTH_CAP {
            if cur == 0 || cur == 1 {
                return None;
            }
            if self.is_running(cur) {
                return Some(cur);
            }
            let (ppid, _) = self.lookup_cache(cur)?;
            if ppid == cur {
                return None;
            }
            cur = ppid;
        }
        None
    }

    /// `tty_nr` (field 7 of `/proc/<pid>/stat`) is set. Counted after the
    /// `(comm)` field, which may itself hold spaces or parentheses.
    fn has_controlling_tty(&self, pid: u32) -> bool {
        if pid == 0 || pid == 1 {
            return false;
        }
        let path = self.inner.proc_root.join(pid.to_string()).join("stat");
        let Ok(stat) = fs::read_to_string(path) else {
            return false;
        };
        stat.rsplit_once(')')
            .and_then(|(_, rest)| rest.split_whitespace().nth(4))
            .and_then(|tty| tty.parse::<i64>().ok())
            .is_some_and(|tty| tty != 0)
    }

    /// FP-2 — true iff `pid` is npm's own node process: a DIRECT
    /// (non-lineage) check that the focal writer's `exe` ∈ [`NODE_EXES`]
    /// AND its precomputed [`Entry::argv_npm_cli`] flag is set (argv[1]
    /// = npm's CLI entrypoint). Unlike [`Self::is_system_daemon_mediated`]
    /// this does NOT walk ancestors — only the npm-cli.js node process
    /// itself is exempted from the mass-write arm; any child it spawns
    /// (a postinstall script, node-gyp, make, …) is a different pid with
    /// a different argv and STILL fires.
    ///
    /// Cache-only by design: a miss (spawn never observed or already
    /// evicted) returns false → the mass-write arm fires (fail toward
    /// detection). For an actively mass-writing, just-spawned node
    /// process a hit is near-certain (`TRACKER_CAP` = 2048). PID 0/1 are
    /// never npm.
    ///
    /// SECURITY: argv is process-controlled, but here it is gated behind
    /// a non-forgeable `exe` ∈ [`NODE_EXES`] match — the exemption is
    /// "the real node binary, invoked as npm". A malicious *package*
    /// extracted by that genuine npm process is still exempt from the
    /// write-VOLUME signal (accepted: a write count cannot separate a
    /// benign install from a malicious one) but remains covered by the
    /// exec / network / persistence arms. See the FP-2 note in
    /// [`super::triggers::confirmed_intrusion`].
    pub fn is_npm_cli_writer(&self, pid: u32) -> bool {
        if pid == 0 || pid == 1 {
            return false;
        }
        let s = self.inner.state.read();
        s.map
            .get(&pid)
            .is_some_and(|e| e.argv_npm_cli && is_node_exe(&e.exe))
    }

    /// Walk the lineage of `pid` upward through (ppid, exe) pairs and
    /// return true if any hop's exe satisfies `is_match`. Cache miss
    /// falls back to `/proc/<pid>/exe` (symlink read, kernel-resolved)
    /// plus `/proc/<pid>/status` `PPid:` parsing. Capped at
    /// [`LINEAGE_DEPTH_CAP`] hops to bound the worst-case cost. PIDs 0
    /// and 1 (kernel / init) never match and are an unconditional
    /// terminator. Shared by [`Self::is_auth_mediated`] and
    /// [`Self::is_system_daemon_mediated`] so both use the identical,
    /// non-forgeable walk.
    fn lineage_exe_matches(&self, pid: u32, is_match: impl Fn(&Path) -> bool) -> bool {
        if pid == 0 || pid == 1 {
            return false;
        }
        let mut cur = pid;
        let mut visited = 0usize;
        loop {
            if visited >= LINEAGE_DEPTH_CAP {
                return false;
            }
            visited += 1;

            let (ppid, exe) = match self.lookup_cache(cur) {
                Some(pair) => pair,
                None => match self.lookup_proc(cur) {
                    Some(pair) => pair,
                    None => return false,
                },
            };
            if is_match(&exe) {
                return true;
            }
            if ppid == 0 || ppid == 1 || ppid == cur {
                return false;
            }
            cur = ppid;
        }
    }

    /// BUG-018 (tactical): true iff `/proc/<pid>/loginuid` contains
    /// a value other than [`LOGINUID_UNSET`].
    ///
    /// Interpreted as "this process is descended from a PAM-mediated
    /// login chain that called `pam_loginuid`." Returns false when:
    /// - the file is missing (kernel built without
    ///   `CONFIG_AUDIT_LOGINUID_IMMUTABLE` ⇒ no /proc entry at all,
    ///   OR the PID died between event and check),
    /// - the file body doesn't parse as a `u32`,
    /// - the value is the unset sentinel,
    /// - PID 0 or 1 (terminator — never has a meaningful loginuid).
    ///
    /// Read every call (no cache): the file is one read per check,
    /// well inside the per-event budget, and caching would just
    /// duplicate `/proc`'s own per-task state.
    ///
    /// Used ONLY by [`super::triggers::sensitive_file_access`]'s
    /// `/etc/passwd` read carve-out — explicitly bounded so the
    /// trust widening doesn't bleed into other arms. The V2
    /// continuous-trust redesign
    /// (`docs/design/POSTURE_FSM_V2_REDESIGN.md` §5.2) replaces
    /// this binary signal with a graded score.
    pub fn has_valid_loginuid(&self, pid: u32) -> bool {
        self.loginuid_of(pid).is_some()
    }

    /// The PAM-assigned login uid of `pid`, or `None` when unset
    /// (`4294967295`), unreadable, or for PID 0/1. Audit `posture-3`
    /// uses it ONLY to recognise a session writing into its OWN
    /// `/run/user/<uid>/` runtime dir (PAM session start, `systemd
    /// --user` helpers) — the mass-write arm stays armed for every
    /// other path, so a ransomware inside an authenticated session is
    /// still caught; the trust widening is bounded to that directory.
    pub fn loginuid_of(&self, pid: u32) -> Option<u32> {
        if pid == 0 || pid == 1 {
            return None;
        }
        let path = self.inner.proc_root.join(pid.to_string()).join("loginuid");
        let raw = fs::read_to_string(&path).ok()?;
        match raw.trim().parse::<u32>() {
            Ok(v) if v != LOGINUID_UNSET => Some(v),
            _ => None,
        }
    }

    /// Review 85: what the kernel executed for `pid` ([`ExecIdentity`]):
    /// the spawn cache, else `/proc/<pid>/exe` and `cmdline`. `None` when
    /// neither knows it (exited before its exec event was read), or when
    /// its exe was deleted or replaced.
    pub fn exec_identity(&self, pid: u32) -> Option<ExecIdentity> {
        if pid == 0 {
            return None;
        }
        {
            let s = self.inner.state.read();
            if let Some(e) = s.map.get(&pid).or_else(|| s.daemons.get(&pid)) {
                return Some(ExecIdentity {
                    exe: e.exe.clone(),
                    script: e.script.as_deref().map(str::to_string),
                });
            }
        }
        let dir = self.inner.proc_root.join(pid.to_string());
        let exe = fs::read_link(dir.join("exe")).ok()?;
        if exe.to_string_lossy().ends_with(" (deleted)") {
            return None;
        }
        let cmdline = fs::read(dir.join("cmdline")).unwrap_or_default();
        let argv: Vec<String> = cmdline
            .split(|b| *b == 0)
            .filter(|a| !a.is_empty())
            .map(|a| String::from_utf8_lossy(a).into_owned())
            .collect();
        let script = script_of(&exe, &argv).map(String::from);
        Some(ExecIdentity { exe, script })
    }

    fn lookup_cache(&self, pid: u32) -> Option<(u32, PathBuf)> {
        let s = self.inner.state.read();
        s.map
            .get(&pid)
            .or_else(|| s.daemons.get(&pid))
            .map(|e| (e.ppid, e.exe.clone()))
    }

    fn lookup_proc(&self, pid: u32) -> Option<(u32, PathBuf)> {
        let pid_str = pid.to_string();
        let exe_link = self.inner.proc_root.join(&pid_str).join("exe");
        let exe = fs::read_link(&exe_link).ok()?;
        // `/proc/<pid>/exe` carries a ` (deleted)` suffix when the
        // on-disk binary was unlinked while the process is still
        // running. Treat that as a mismatch — a deleted/swapped
        // auth binary is exactly the case we must not trust.
        let exe_str = exe.to_string_lossy();
        if exe_str.ends_with(" (deleted)") {
            return None;
        }
        let status_path = self.inner.proc_root.join(&pid_str).join("status");
        let text = fs::read_to_string(&status_path).ok()?;
        let ppid = parse_ppid(&text)?;
        Some((ppid, exe))
    }

    #[cfg(test)]
    fn entry_count(&self) -> usize {
        self.inner.state.read().map.len()
    }
}

impl Default for AuthSessionTracker {
    fn default() -> Self {
        Self::with_proc()
    }
}

fn is_auth_binary(exe: &Path) -> bool {
    let s = exe.to_string_lossy();
    AUTH_BINARY_EXES.iter().any(|p| s == *p)
}

fn is_system_daemon_binary(exe: &Path) -> bool {
    let s = exe.to_string_lossy();
    SYSTEM_DAEMON_EXES.iter().any(|p| s == *p)
}

fn is_elevation_binary(exe: &Path) -> bool {
    let s = exe.to_string_lossy();
    ELEVATION_EXES.iter().any(|p| s == *p)
}

/// FP-2: exact-path match against the Node.js interpreter allowlist
/// ([`NODE_EXES`]). Same kernel-resolved-exe, never-`comm` keying as
/// [`is_system_daemon_binary`]. Gates [`AuthSessionTracker::is_npm_cli_writer`]
/// so a process-controlled argv is never the sole basis for the exemption.
fn is_node_exe(exe: &Path) -> bool {
    let s = exe.to_string_lossy();
    NODE_EXES.iter().any(|p| s == *p)
}

/// Review 85: interpreters, by exe basename (`python3.12`, `perl5.36`):
/// what they run is named by their arguments, not by their exe.
fn is_interpreter(exe: &Path) -> bool {
    let base = exe
        .file_name()
        .map(|b| b.to_string_lossy())
        .unwrap_or_default();
    [
        "python", "perl", "ruby", "node", "nodejs", "bash", "sh", "dash", "zsh", "ksh", "mono",
    ]
    .iter()
    .any(|i| {
        base.strip_prefix(i)
            .is_some_and(|rest| rest.chars().all(|c| c.is_ascii_digit() || c == '.'))
    })
}

/// Review 85: the script or module an interpreter runs, from its argv:
/// the first argument that is not an option, or the module after `-m`
/// (also `-Im`, `-Em`). An inline program (`-c`, `-e`, `--eval`) runs
/// nothing named, and neither does an interpreter with no argument.
fn script_of(exe: &Path, argv: &[String]) -> Option<Box<str>> {
    if !is_interpreter(exe) {
        return None;
    }
    let mut args = argv.iter().skip(1);
    while let Some(a) = args.next() {
        match a.as_str() {
            "-c" | "-e" | "--eval" | "-p" | "--print" => return None,
            "-W" | "-X" | "-O" => {
                args.next();
            }
            _ if a.starts_with("--") => {}
            _ if a.starts_with('-') && a.len() > 1 => {
                if a.ends_with('m') {
                    return args.next().map(|m| m.as_str().into());
                }
                if a.contains('c') || a.contains('e') {
                    return None;
                }
            }
            _ => return Some(a.as_str().into()),
        }
    }
    None
}

/// Extract the `PPid: <n>` value from a `/proc/<pid>/status` body.
fn parse_ppid(status_text: &str) -> Option<u32> {
    for line in status_text.lines() {
        if let Some(rest) = line.strip_prefix("PPid:") {
            return rest.trim().parse().ok();
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;
    use tempfile::TempDir;

    fn write_status(dir: &Path, pid: u32, ppid: u32) {
        let pid_dir = dir.join(pid.to_string());
        fs::create_dir_all(&pid_dir).unwrap();
        fs::write(
            pid_dir.join("status"),
            format!("Name:\tx\nPid:\t{pid}\nPPid:\t{ppid}\n"),
        )
        .unwrap();
    }

    /// BUG-018 fixture: write `/proc/<pid>/loginuid` with the given
    /// raw value. Real kernel writes `"4294967295"` (the unset
    /// sentinel) or a decimal UID; we mirror that exactly so the
    /// parser path is exercised the way it runs in production.
    fn write_loginuid(dir: &Path, pid: u32, value: u32) {
        let pid_dir = dir.join(pid.to_string());
        fs::create_dir_all(&pid_dir).unwrap();
        fs::write(pid_dir.join("loginuid"), value.to_string()).unwrap();
    }

    fn write_exe(dir: &Path, pid: u32, target: &str) {
        let pid_dir = dir.join(pid.to_string());
        fs::create_dir_all(&pid_dir).unwrap();
        let exe_path = pid_dir.join("exe");
        // tempfile lifetime is per-test; ensure no stale symlink.
        let _ = fs::remove_file(&exe_path);
        symlink(target, &exe_path).unwrap();
    }

    #[test]
    fn ingest_records_entry() {
        let t = AuthSessionTracker::new("/proc");
        t.ingest_spawn(100, 1, "/usr/bin/sudo", 1_000);
        assert_eq!(t.entry_count(), 1);
    }

    #[test]
    fn pid_zero_is_never_recorded_or_auth_mediated() {
        let t = AuthSessionTracker::new("/proc");
        t.ingest_spawn(0, 0, "/usr/bin/sudo", 0);
        assert_eq!(t.entry_count(), 0);
        assert!(!t.is_auth_mediated(0));
    }

    #[test]
    fn pid_one_is_never_auth_mediated() {
        let t = AuthSessionTracker::new("/proc");
        // Even if some weirdness lands PID 1 in the cache, the
        // terminator short-circuit blocks it before the walk.
        assert!(!t.is_auth_mediated(1));
    }

    #[test]
    fn direct_sudo_pid_is_auth_mediated() {
        let t = AuthSessionTracker::new("/proc");
        t.ingest_spawn(100, 50, "/usr/bin/sudo", 1);
        assert!(t.is_auth_mediated(100));
    }

    #[test]
    fn subprocess_of_sudo_is_auth_mediated_via_lineage() {
        let t = AuthSessionTracker::new("/proc");
        t.ingest_spawn(100, 50, "/usr/bin/sudo", 1);
        t.ingest_spawn(200, 100, "/usr/bin/apt", 2);
        assert!(t.is_auth_mediated(200));
    }

    // ── (ii) — system package-management daemon lineage ─────────────

    #[test]
    fn direct_snapd_daemon_is_system_daemon_mediated() {
        let t = AuthSessionTracker::new("/proc");
        // snapd daemon, parented by systemd (pid 1).
        t.ingest_spawn(1096, 1, "/usr/lib/snapd/snapd", 1);
        assert!(t.is_system_daemon_mediated(1096));
        // Disjoint from the auth allowlist — snapd is not a setuid admin
        // binary, so it must NOT also read as auth-mediated.
        assert!(!t.is_auth_mediated(1096));
    }

    #[test]
    fn mandb_is_system_daemon_mediated() {
        let t = AuthSessionTracker::new("/proc");
        t.ingest_spawn(3096, 1, "/usr/bin/mandb", 1);
        assert!(t.is_system_daemon_mediated(3096));
    }

    #[test]
    fn dpkg_maintainer_script_is_system_daemon_mediated_via_lineage() {
        let t = AuthSessionTracker::new("/proc");
        // dpkg -> /bin/sh maintainer script: exempt via the dpkg ancestor.
        t.ingest_spawn(400, 1, "/usr/bin/dpkg", 1);
        t.ingest_spawn(401, 400, "/bin/sh", 2);
        assert!(t.is_system_daemon_mediated(401));
    }

    #[test]
    fn non_daemon_pid_is_not_system_daemon_mediated() {
        let t = AuthSessionTracker::new("/proc");
        // A Python interpreter — how `unattended-upgrade` actually
        // resolves via /proc/<pid>/exe — is NOT in the allowlist (exact
        // exec-path match, never comm/argv). Nor is a plain shell.
        t.ingest_spawn(200, 50, "/usr/bin/python3.12", 1);
        t.ingest_spawn(50, 1, "/bin/bash", 0);
        assert!(!t.is_system_daemon_mediated(200));
    }

    #[test]
    fn sudo_pid_is_not_system_daemon_mediated() {
        // Cross-grant guard: an auth-mediated (sudo) PID must NOT be
        // treated as a system daemon. The two allowlists are disjoint.
        let t = AuthSessionTracker::new("/proc");
        t.ingest_spawn(100, 50, "/usr/bin/sudo", 1);
        assert!(t.is_auth_mediated(100));
        assert!(!t.is_system_daemon_mediated(100));
    }

    // ── review 49 — RHEL package managers + eviction-proof daemon cache ──

    #[test]
    fn rpm_and_dnf_scriptlets_are_system_daemon_mediated() {
        let tmp = TempDir::new().unwrap();
        let t = AuthSessionTracker::new(tmp.path());
        // `rpm -i`: an ELF, its %post scriptlet runs under /bin/sh.
        t.ingest_spawn(500, 1, "/usr/bin/rpm", 1);
        t.ingest_spawn(501, 500, "/bin/sh", 2);
        assert!(t.is_system_daemon_mediated(501));
        // `dnf install`: the exec event carries the script path, so the
        // cache names dnf even though /proc/<pid>/exe is the interpreter.
        t.ingest_spawn(600, 1, "/usr/bin/dnf", 3);
        t.ingest_spawn(601, 600, "/usr/bin/systemctl", 4);
        assert!(t.is_system_daemon_mediated(600));
        assert!(t.is_system_daemon_mediated(601));
    }

    #[test]
    fn dnf_seen_only_through_proc_is_not_trusted() {
        // Without the spawn, /proc shows the interpreter: no match, and
        // cmdline is never consulted (a process can rewrite its own).
        let tmp = TempDir::new().unwrap();
        write_exe(tmp.path(), 700, "/usr/bin/python3.9");
        write_status(tmp.path(), 700, 1);
        let t = AuthSessionTracker::new(tmp.path());
        assert!(!t.is_system_daemon_mediated(700));
    }

    #[test]
    fn package_manager_entry_survives_main_cache_eviction() {
        let tmp = TempDir::new().unwrap();
        let t = AuthSessionTracker::new(tmp.path());
        t.ingest_spawn(600, 1, "/usr/bin/dnf", 1);
        // A long transaction: more scriptlet spawns than the main FIFO
        // holds, all children of dnf.
        for i in 0..(TRACKER_CAP as u32 + 100) {
            t.ingest_spawn(10_000 + i, 600, "/bin/sh", 2);
        }
        assert!(
            t.is_system_daemon_mediated(600),
            "dnf evicted from the side cache"
        );
        assert!(t.is_system_daemon_mediated(10_000 + TRACKER_CAP as u32 + 99));
    }

    #[test]
    fn pid_reuse_by_another_program_drops_the_daemon_copy() {
        let tmp = TempDir::new().unwrap();
        let t = AuthSessionTracker::new(tmp.path());
        t.ingest_spawn(800, 1, "/usr/bin/dpkg", 1);
        assert!(t.is_system_daemon_mediated(800));
        t.ingest_spawn(800, 1, "/usr/bin/bash", 2);
        assert!(!t.is_system_daemon_mediated(800));
    }

    #[test]
    fn daemon_side_cache_is_bounded() {
        let tmp = TempDir::new().unwrap();
        let t = AuthSessionTracker::new(tmp.path());
        for i in 0..(DAEMON_CACHE_CAP as u32 + 10) {
            t.ingest_spawn(20_000 + i, 1, "/usr/bin/dpkg", 1);
        }
        let s = t.inner.state.read();
        assert_eq!(s.daemons.len(), DAEMON_CACHE_CAP);
        assert_eq!(s.daemon_order.len(), DAEMON_CACHE_CAP);
        assert!(
            !s.daemons.contains_key(&20_000),
            "oldest copy evicted first"
        );
    }

    #[test]
    fn system_daemon_cold_start_falls_back_to_proc() {
        let tmp = TempDir::new().unwrap();
        let proc_root = tmp.path();
        // pid 124 -> exe /usr/bin/dpkg, ppid=1, with an EMPTY cache so
        // the walk must reconstruct from the /proc fixture.
        write_exe(proc_root, 124, "/usr/bin/dpkg");
        write_status(proc_root, 124, 1);
        let t = AuthSessionTracker::new(proc_root);
        assert!(t.is_system_daemon_mediated(124));
    }

    // ── FP-2 — npm CLI writer (node + argv[1]=npm-cli.js) ───────────

    fn npm_argv(extra: &[&str]) -> Vec<String> {
        // argv as the shebang hands it to node: ["node", "<npm-cli.js>", …].
        let mut v = vec![
            "node".to_string(),
            "/usr/lib/node_modules/npm/bin/npm-cli.js".to_string(),
        ];
        v.extend(extra.iter().map(|s| s.to_string()));
        v
    }

    #[test]
    fn node_running_npm_cli_is_npm_cli_writer() {
        let t = AuthSessionTracker::new("/proc");
        // node interpreter running npm's CLI entrypoint.
        t.ingest_spawn_with_argv(
            7000,
            50,
            "/usr/bin/node",
            &npm_argv(&["install", "-g", "x"]),
            1,
        );
        assert!(t.is_npm_cli_writer(7000));
        // It is NOT auth- or system-daemon-mediated (disjoint signals).
        assert!(!t.is_auth_mediated(7000));
        assert!(!t.is_system_daemon_mediated(7000));
    }

    #[test]
    fn node_not_running_npm_is_not_npm_cli_writer() {
        let t = AuthSessionTracker::new("/proc");
        // Same node binary, but running some OTHER script → not exempt.
        let argv = vec!["node".to_string(), "/home/u/evil.js".to_string()];
        t.ingest_spawn_with_argv(7001, 50, "/usr/bin/node", &argv, 1);
        assert!(!t.is_npm_cli_writer(7001));
    }

    #[test]
    fn npm_argv_under_non_node_exe_is_not_npm_cli_writer() {
        let t = AuthSessionTracker::new("/proc");
        // argv spoofs npm-cli.js but the exe is NOT the node interpreter
        // (the non-forgeable half) → not exempt.
        t.ingest_spawn_with_argv(7002, 50, "/tmp/evil", &npm_argv(&["install"]), 1);
        assert!(!t.is_npm_cli_writer(7002));
    }

    #[test]
    fn npm_cli_writer_is_cache_only_no_proc_fallback() {
        // A pid never ingested (cache miss) is not exempt even if /proc
        // would resolve it — fail toward detection.
        let t = AuthSessionTracker::new("/proc");
        assert!(!t.is_npm_cli_writer(7003));
        // pid 1 / 0 are never npm.
        assert!(!t.is_npm_cli_writer(1));
        assert!(!t.is_npm_cli_writer(0));
    }

    #[test]
    fn npm_cli_flag_matches_user_prefix_path_too() {
        // npm-cli.js can live under a user global prefix; the suffix
        // match (…/npm/bin/npm-cli.js) is location-independent.
        let t = AuthSessionTracker::new("/proc");
        let argv = vec![
            "node".to_string(),
            "/home/forty/.npm-global/lib/node_modules/npm/bin/npm-cli.js".to_string(),
        ];
        t.ingest_spawn_with_argv(7004, 50, "/usr/bin/node", &argv, 1);
        assert!(t.is_npm_cli_writer(7004));
    }

    #[test]
    fn plain_ingest_spawn_leaves_npm_flag_false() {
        // The argv-less ingest path must never set the npm flag.
        let t = AuthSessionTracker::new("/proc");
        t.ingest_spawn(7005, 50, "/usr/bin/node", 1);
        assert!(!t.is_npm_cli_writer(7005));
    }

    #[test]
    fn nested_sudo_chain_is_auth_mediated_at_depth() {
        let t = AuthSessionTracker::new("/proc");
        // user shell (50) -> sudo (100) -> bash (200) -> apt (300).
        t.ingest_spawn(100, 50, "/usr/bin/sudo", 1);
        t.ingest_spawn(200, 100, "/bin/bash", 2);
        t.ingest_spawn(300, 200, "/usr/bin/apt", 3);
        assert!(t.is_auth_mediated(300));
    }

    #[test]
    fn unrelated_pid_with_no_auth_ancestor_is_not_auth_mediated() {
        let t = AuthSessionTracker::new("/proc");
        // user shell (50) -> firefox (200). No sudo anywhere.
        t.ingest_spawn(200, 50, "/usr/bin/firefox", 1);
        t.ingest_spawn(50, 1, "/bin/bash", 0);
        assert!(!t.is_auth_mediated(200));
    }

    #[test]
    fn pid_reuse_invalidates_lineage() {
        let t = AuthSessionTracker::new("/proc");
        t.ingest_spawn(100, 50, "/usr/bin/sudo", 1);
        assert!(t.is_auth_mediated(100));
        // Same PID re-spawned as something innocuous; lineage drops.
        t.ingest_spawn(100, 50, "/bin/cat", 2);
        // Parent pid=50 has no entry; lookup_proc on templess "/proc"
        // for pid 50 will fail; net result: not auth-mediated.
        assert!(!t.is_auth_mediated(100));
    }

    // ── Test #11: cold-start /proc fallback ────────────────────────
    #[test]
    fn lineage_cold_start_falls_back_to_proc() {
        let tmp = TempDir::new().unwrap();
        let proc_root = tmp.path();
        // Build a fake /proc fixture:
        //   pid 123 -> exe /usr/bin/sudo, ppid=1
        //   pid 124 -> exe /usr/bin/apt,  ppid=123
        write_exe(proc_root, 123, "/usr/bin/sudo");
        write_status(proc_root, 123, 1);
        write_exe(proc_root, 124, "/usr/bin/apt");
        write_status(proc_root, 124, 123);

        let t = AuthSessionTracker::new(proc_root);
        // Cache is empty — the walk must reconstruct from /proc.
        assert!(t.is_auth_mediated(124));
        assert!(t.is_auth_mediated(123));
    }

    // ── Test #12: /proc unavailable returns false ───────────────────
    #[test]
    fn proc_unavailable_returns_false_on_miss() {
        let tmp = TempDir::new().unwrap();
        // proc_root points at an empty tempdir — every readlink fails.
        let t = AuthSessionTracker::new(tmp.path());
        assert!(!t.is_auth_mediated(99_999));
    }

    // ── Test #13: deleted-suffix exe is rejected ────────────────────
    #[test]
    fn auth_binary_with_deleted_suffix_rejected() {
        let tmp = TempDir::new().unwrap();
        let proc_root = tmp.path();
        // Mimic a /proc/<pid>/exe whose target is sudo but suffixed
        // " (deleted)" — the kernel appends this when the on-disk
        // file has been unlinked. We must NOT trust it as
        // auth-mediated, since a deleted/swapped binary is exactly
        // the supply-chain attack class we have to refuse.
        write_exe(proc_root, 123, "/usr/bin/sudo (deleted)");
        write_status(proc_root, 123, 1);
        let t = AuthSessionTracker::new(proc_root);
        assert!(!t.is_auth_mediated(123));
    }

    // ── Test #14: bounded FIFO eviction on cap overflow ─────────────
    #[test]
    fn ingest_overwrites_lru_when_cap_exceeded() {
        let t = AuthSessionTracker::new("/proc");
        // Fill past TRACKER_CAP with distinct pids.
        for pid in 1..=(TRACKER_CAP as u32 + 5) {
            t.ingest_spawn(pid, 1, "/usr/bin/cat", pid as u64);
        }
        // Map must not exceed the cap.
        assert!(t.entry_count() <= TRACKER_CAP);
        assert!(t.entry_count() >= TRACKER_CAP - 5);
    }

    #[test]
    fn lineage_depth_capped_prevents_cycle_hang() {
        let t = AuthSessionTracker::new("/proc");
        // Build a chain longer than LINEAGE_DEPTH_CAP with no
        // auth binary anywhere.
        for i in 1..=(LINEAGE_DEPTH_CAP as u32 + 5) {
            // chain: i -> (i+1)
            t.ingest_spawn(i, i + 1, "/usr/bin/cat", i as u64);
        }
        // pid=1 walks up to LINEAGE_DEPTH_CAP+5; must terminate
        // with `false`, not loop.
        assert!(!t.is_auth_mediated(1));
    }

    #[test]
    fn self_referential_lineage_does_not_loop() {
        let t = AuthSessionTracker::new("/proc");
        // pid 100 lists itself as its own ppid — corrupt /proc
        // synthesis would do this. Must terminate, not hang.
        t.ingest_spawn(100, 100, "/usr/bin/cat", 1);
        assert!(!t.is_auth_mediated(100));
    }

    #[test]
    fn parse_ppid_extracts_value() {
        let body =
            "Name:\tbash\nUmask:\t0022\nState:\tS (sleeping)\nTgid:\t12\nPid:\t12\nPPid:\t1\n";
        assert_eq!(parse_ppid(body), Some(1));
    }

    #[test]
    fn parse_ppid_returns_none_on_missing_line() {
        let body = "Name:\tbash\nPid:\t12\n";
        assert_eq!(parse_ppid(body), None);
    }

    #[test]
    fn is_auth_binary_matches_exact_paths_only() {
        assert!(is_auth_binary(Path::new("/usr/bin/sudo")));
        assert!(is_auth_binary(Path::new("/usr/bin/sudoedit")));
        assert!(is_auth_binary(Path::new("/usr/sbin/sshd")));
        // PAM-mediated login daemons (T7.13 generalisation).
        assert!(is_auth_binary(Path::new("/usr/sbin/cron")));
        assert!(is_auth_binary(Path::new("/usr/sbin/crond")));
        assert!(is_auth_binary(Path::new("/usr/lib/systemd/systemd-logind")));
        assert!(is_auth_binary(Path::new("/lib/systemd/systemd-logind")));
        assert!(is_auth_binary(Path::new("/usr/lib/polkit-1/polkitd")));
        assert!(is_auth_binary(Path::new("/usr/libexec/polkit-1/polkitd")));
        assert!(is_auth_binary(Path::new(
            "/usr/lib/gdm3/gdm-session-worker"
        )));
        assert!(is_auth_binary(Path::new("/usr/libexec/gdm-session-worker")));
        assert!(is_auth_binary(Path::new("/usr/sbin/gdm3")));
        assert!(is_auth_binary(Path::new("/usr/sbin/lightdm")));
        assert!(!is_auth_binary(Path::new("/tmp/sudo")));
        assert!(!is_auth_binary(Path::new("/usr/local/bin/sudo")));
        assert!(!is_auth_binary(Path::new("/usr/bin/sudo-helper")));
        // Near-miss daemon paths must NOT match (exact-path only).
        assert!(!is_auth_binary(Path::new("/usr/sbin/crony")));
        assert!(!is_auth_binary(Path::new("/usr/lib/systemd/systemd")));
        assert!(!is_auth_binary(Path::new("/tmp/polkitd")));
    }

    #[test]
    fn cron_job_child_is_auth_mediated_via_lineage() {
        let t = AuthSessionTracker::new("/proc");
        // crond (root, ppid=1) -> user job shell. The PAM `session` open
        // of /etc/shadow happens in a child observed at the user's uid;
        // the lineage walk back to crond must exempt it.
        t.ingest_spawn(500, 1, "/usr/sbin/cron", 1);
        t.ingest_spawn(501, 500, "/bin/sh", 2);
        assert!(t.is_auth_mediated(501));
    }

    #[test]
    fn unix_chkpwd_screen_unlock_is_auth_mediated() {
        let t = AuthSessionTracker::new("/proc");
        // Unprivileged locker -> setuid-root pam_unix helper. The helper
        // reads /etc/shadow at the caller's real uid; its own exe is the
        // auth binary, so it is auth-mediated at hop 0.
        t.ingest_spawn(700, 1, "/usr/bin/cinnamon-screensaver", 1);
        t.ingest_spawn(701, 700, "/usr/sbin/unix_chkpwd", 2);
        assert!(t.is_auth_mediated(701));
        // Exact-path recognition across distro locations.
        assert!(is_auth_binary(Path::new("/usr/sbin/unix_chkpwd")));
        assert!(is_auth_binary(Path::new("/usr/bin/unix_chkpwd")));
        assert!(is_auth_binary(Path::new("/sbin/unix_chkpwd")));
        assert!(is_auth_binary(Path::new("/usr/sbin/unix_update")));
        assert!(!is_auth_binary(Path::new("/tmp/unix_chkpwd")));
    }

    #[test]
    fn gdm_session_worker_child_is_auth_mediated_via_lineage() {
        let t = AuthSessionTracker::new("/proc");
        // gdm daemon -> gdm-session-worker (the PAM stack runner) -> child.
        t.ingest_spawn(600, 1, "/usr/sbin/gdm3", 1);
        t.ingest_spawn(601, 600, "/usr/lib/gdm3/gdm-session-worker", 2);
        t.ingest_spawn(602, 601, "/bin/bash", 3);
        assert!(t.is_auth_mediated(602));
    }

    // ── BUG-018 (tactical): loginuid signal tests ──────────────────

    /// Happy path: a process with `/proc/<pid>/loginuid` containing
    /// a real UID (1000) is recognised as PAM-authenticated.
    /// Mirrors what `pam_loginuid` writes during a real desktop /
    /// SSH login.
    #[test]
    fn has_valid_loginuid_recognises_authenticated_session() {
        let tmp = TempDir::new().unwrap();
        write_loginuid(tmp.path(), 100, 1000);
        let t = AuthSessionTracker::new(tmp.path());
        assert!(t.has_valid_loginuid(100));
    }

    /// Negative: an orphan process whose loginuid was never set
    /// (kernel default = `(uid_t)-1` = 4294967295). Tactical carve-out
    /// must NOT fire for these.
    #[test]
    fn has_valid_loginuid_rejects_unset_sentinel() {
        let tmp = TempDir::new().unwrap();
        write_loginuid(tmp.path(), 100, LOGINUID_UNSET);
        let t = AuthSessionTracker::new(tmp.path());
        assert!(!t.has_valid_loginuid(100));
    }

    /// Negative: missing `/proc/<pid>/loginuid` (PID died between
    /// event and check, OR kernel without audit support). Fail
    /// closed — treat as not authenticated.
    #[test]
    fn has_valid_loginuid_rejects_missing_file() {
        let tmp = TempDir::new().unwrap();
        // No write at all — file is absent.
        let t = AuthSessionTracker::new(tmp.path());
        assert!(!t.has_valid_loginuid(100));
    }

    /// Negative: corrupt loginuid file (not parseable as u32).
    /// Fail closed.
    #[test]
    fn has_valid_loginuid_rejects_garbage_content() {
        let tmp = TempDir::new().unwrap();
        let pid_dir = tmp.path().join("100");
        fs::create_dir_all(&pid_dir).unwrap();
        fs::write(pid_dir.join("loginuid"), "not a number\n").unwrap();
        let t = AuthSessionTracker::new(tmp.path());
        assert!(!t.has_valid_loginuid(100));
    }

    /// PID 0 (kernel) and PID 1 (init) are unconditional terminators
    /// — they never have a meaningful loginuid even if /proc happens
    /// to expose one.
    #[test]
    fn has_valid_loginuid_short_circuits_pid_zero_and_one() {
        let tmp = TempDir::new().unwrap();
        write_loginuid(tmp.path(), 0, 1000);
        write_loginuid(tmp.path(), 1, 1000);
        let t = AuthSessionTracker::new(tmp.path());
        assert!(!t.has_valid_loginuid(0));
        assert!(!t.has_valid_loginuid(1));
    }

    // ── Review 52: interactive admin session ───────────────────────

    /// `/proc/<pid>/stat` with the given `tty_nr`; `comm` holds a space
    /// and a parenthesis, as a real one may.
    fn write_stat(dir: &Path, pid: u32, ppid: u32, tty_nr: i64) {
        let pid_dir = dir.join(pid.to_string());
        fs::create_dir_all(&pid_dir).unwrap();
        fs::write(
            pid_dir.join("stat"),
            format!("{pid} (my (tee)) S {ppid} {pid} {pid} {tty_nr} -1 4194560 0 0\n"),
        )
        .unwrap();
    }

    /// A shell (pid 50, terminal, login uid 1000) ran `sudo` (100), which
    /// ran the writer (200).
    fn admin_session(tty_nr: i64, loginuid: u32) -> (TempDir, AuthSessionTracker) {
        let tmp = TempDir::new().unwrap();
        write_loginuid(tmp.path(), 200, loginuid);
        write_stat(tmp.path(), 200, 100, tty_nr);
        let t = AuthSessionTracker::new(tmp.path());
        t.ingest_spawn(50, 40, "/usr/bin/bash", 1);
        t.ingest_spawn(100, 50, "/usr/bin/sudo", 2);
        t.ingest_spawn(200, 100, "/usr/sbin/useradd", 3);
        (tmp, t)
    }

    #[test]
    fn sudo_with_login_and_terminal_is_interactive_admin() {
        let (_tmp, t) = admin_session(34816, 1000);
        assert!(t.is_interactive_admin(200));
    }

    #[test]
    fn no_terminal_or_no_login_is_not_interactive_admin() {
        // `ssh host sudo …` without a terminal.
        let (_tmp, t) = admin_session(0, 1000);
        assert!(!t.is_interactive_admin(200));
        // A service: no login uid.
        let (_tmp, t) = admin_session(34816, LOGINUID_UNSET);
        assert!(!t.is_interactive_admin(200));
        // Never seen and not in /proc.
        let (_tmp, t) = admin_session(34816, 1000);
        assert!(!t.is_interactive_admin(999));
    }

    /// `sudo tee` has exited (and sudo with it) when its event is read:
    /// the shell that ran sudo, still running, answers for it. Without a
    /// running ancestor with a terminal, it is not an admin session.
    #[test]
    fn exited_writer_is_judged_by_its_running_shell() {
        let tmp = TempDir::new().unwrap();
        let t = AuthSessionTracker::new(tmp.path());
        t.ingest_spawn(50, 40, "/usr/bin/bash", 1);
        t.ingest_spawn(100, 50, "/usr/bin/sudo", 2);
        t.ingest_spawn(200, 100, "/usr/bin/tee", 3);
        assert!(!t.is_interactive_admin(200), "nothing runs");
        write_loginuid(tmp.path(), 50, 1000);
        write_stat(tmp.path(), 50, 40, 0);
        assert!(!t.is_interactive_admin(200), "shell without a terminal");
        write_stat(tmp.path(), 50, 40, 34816);
        assert!(t.is_interactive_admin(200));
        // A zombie writer (exited, not yet reaped) does not answer: its
        // running shell does.
        write_loginuid(tmp.path(), 200, 1000);
        fs::write(
            tmp.path().join("200").join("stat"),
            "200 (tee) Z 100 50 50 0 -1 0\n",
        )
        .unwrap();
        assert!(t.is_interactive_admin(200));
        // A running writer answers for itself, even when its shell would
        // pass: a background job detached from the terminal is not one.
        write_loginuid(tmp.path(), 200, 1000);
        write_stat(tmp.path(), 200, 100, 0);
        assert!(!t.is_interactive_admin(200));
    }

    /// The ledger's view: unknown while a hop of the chain is lost (sudo's
    /// monitor, a fork without exec, has exited) or nothing of the session
    /// runs; known once the chain reads to its end.
    #[test]
    fn interactive_admin_status_is_unknown_until_the_chain_reads() {
        let tmp = TempDir::new().unwrap();
        let t = AuthSessionTracker::new(tmp.path());
        t.ingest_spawn(50, 40, "/usr/bin/bash", 1);
        t.ingest_spawn(100, 50, "/usr/bin/sudo", 2);
        // tee (300) ran under sudo's monitor (200), never exec'd, gone.
        t.ingest_spawn(300, 200, "/usr/bin/tee", 3);
        assert_eq!(t.interactive_admin_status(300), None, "monitor lost");
        // sudo → tee directly, but nothing of the session runs any more.
        t.ingest_spawn(400, 100, "/usr/bin/tee", 4);
        assert_eq!(t.interactive_admin_status(400), None, "session gone");
        // The shell still runs with a terminal and a login uid.
        write_loginuid(tmp.path(), 50, 1000);
        write_stat(tmp.path(), 50, 40, 34816);
        assert_eq!(t.interactive_admin_status(400), Some(true));
        // A chain that reads to PID 1 with no sudo is known: not an admin.
        t.ingest_spawn(500, 1, "/usr/bin/sh", 5);
        assert_eq!(t.interactive_admin_status(500), Some(false));
    }

    /// Login daemons and job runners authenticate, they do not elevate: a
    /// cron job or an sshd session child is not an admin session, and
    /// neither is a root process with no elevation binary above it.
    #[test]
    fn only_sudo_and_su_elevate() {
        let tmp = TempDir::new().unwrap();
        for pid in [300, 400, 500] {
            write_loginuid(tmp.path(), pid, 1000);
            write_stat(tmp.path(), pid, 1, 34816);
        }
        let t = AuthSessionTracker::new(tmp.path());
        t.ingest_spawn(290, 1, "/usr/sbin/cron", 1);
        t.ingest_spawn(300, 290, "/usr/bin/sh", 2);
        t.ingest_spawn(390, 1, "/usr/sbin/sshd", 3);
        t.ingest_spawn(400, 390, "/usr/bin/bash", 4);
        t.ingest_spawn(490, 1, "/usr/bin/su", 5);
        t.ingest_spawn(500, 490, "/usr/bin/bash", 6);
        assert!(!t.is_interactive_admin(300));
        assert!(!t.is_interactive_admin(400));
        assert!(t.is_interactive_admin(500));
        assert!(!is_elevation_binary(Path::new("/usr/bin/pkexec")));
        assert!(!is_elevation_binary(Path::new("/tmp/sudo")));
    }

    // ── Review 85: exec identity ───────────────────────────────────

    fn argv(a: &[&str]) -> Vec<String> {
        a.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn script_of_reads_the_script_or_module_an_interpreter_runs() {
        let py = Path::new("/usr/bin/python3.12");
        let s = |a: &[&str]| script_of(py, &argv(a)).map(|b| b.to_string());
        assert_eq!(
            s(&["python3", "/usr/bin/aws", "s3", "ls"]).as_deref(),
            Some("/usr/bin/aws")
        );
        assert_eq!(
            s(&[
                "python3",
                "-S",
                "-W",
                "ignore",
                "/usr/lib/google-cloud-sdk/lib/gcloud.py"
            ])
            .as_deref(),
            Some("/usr/lib/google-cloud-sdk/lib/gcloud.py")
        );
        assert_eq!(
            s(&["python3", "-Im", "azure.cli", "login"]).as_deref(),
            Some("azure.cli")
        );
        assert_eq!(
            s(&["python3", "-c", "open('/root/.aws/credentials')"]),
            None
        );
        assert_eq!(s(&["python3", "-Sc", "print(1)"]), None);
        assert_eq!(s(&["python3"]), None);
        assert_eq!(
            script_of(Path::new("/usr/bin/cat"), &argv(&["cat", "/x"])),
            None
        );
        assert!(is_interpreter(Path::new("/usr/bin/bash")));
        assert!(is_interpreter(Path::new("/usr/bin/perl5.36")));
        assert!(!is_interpreter(Path::new("/usr/bin/shred")));
        assert!(!is_interpreter(Path::new("/usr/bin/pythonista")));
    }

    #[test]
    fn exec_identity_comes_from_the_cache_then_proc() {
        let tmp = TempDir::new().unwrap();
        let t = AuthSessionTracker::new(tmp.path());
        t.ingest_spawn_with_argv(
            100,
            1,
            "/usr/bin/python3.12",
            &argv(&["python3", "/usr/bin/aws", "s3", "ls"]),
            1,
        );
        assert_eq!(
            t.exec_identity(100),
            Some(ExecIdentity {
                exe: "/usr/bin/python3.12".into(),
                script: Some("/usr/bin/aws".into()),
            })
        );
        // Not cached: /proc/<pid>/exe and cmdline.
        let d = tmp.path().join("200");
        fs::create_dir_all(&d).unwrap();
        symlink("/usr/bin/perl", d.join("exe")).unwrap();
        fs::write(d.join("cmdline"), b"perl\0-e\0print 1\0").unwrap();
        assert_eq!(
            t.exec_identity(200),
            Some(ExecIdentity {
                exe: "/usr/bin/perl".into(),
                script: None,
            })
        );
        assert_eq!(t.exec_identity(300), None, "unknown pid");
    }

    #[test]
    fn clone_shares_state() {
        let a = AuthSessionTracker::new("/proc");
        let b = a.clone();
        a.ingest_spawn(100, 1, "/usr/bin/sudo", 1);
        // Clone observes the ingest — same Arc-backed state.
        assert!(b.is_auth_mediated(100));
    }
}
