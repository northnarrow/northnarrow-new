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
//! External audit POS-002 narrowed what the tag buys. The lineage of
//! every SSH, desktop and cron session walks back to sshd, gdm or cron,
//! so the tag covered whole sessions and the mass-write arm never saw a
//! ransomware run from one. Now a credential read is exempt only for the
//! authentication binary itself or its direct child
//! ([`AuthSessionTracker::is_credential_reader`]), and the mass-write arm
//! drops only an auth-mediated process's new files, counting its
//! rewrites of existing files (the kernel tells them apart:
//! `FMODE_CREATED`).
//!
//! External audit POS-003: the walk is ordered. A process inherits what
//! its parent runs when it is forked, not what the parent executes
//! afterwards; a pid outlives its process. Each exec event carries the
//! process's own start (its fork), so an ancestor's match counts only if
//! it ran the binary before the process below it was forked, and a hop
//! whose start is later than its child's (an exited parent's pid taken
//! by a later process) ends the walk ([`AuthSessionTracker::lineage_match`]).
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
///      class 1.) `chage` and `expiry` (setgid `shadow` on Debian/Ubuntu)
///      read a user's own password ageing the same way: once the session
///      no longer covered `chage -l` (external audit POS-002), they are
///      listed here.
///
/// Covers Debian/Ubuntu, Fedora/RHEL, Arch, and openSUSE conventions for
/// the canonical paths. Adding paths is a soft change (expands
/// exemption); removing is a hard change (operators on a distro that
/// uses only the removed path lose coverage). A path absent on a given
/// host simply never matches — harmless.
///
/// SECURITY: matching is on the kernel-resolved, non-forgeable
/// `/proc/<pid>/exe` (NEVER `comm`), exact-path only, and only suppresses
/// the credential-read arm (`sensitive_file_access`: the binary itself or
/// its direct child) and the mass-write arm's count of new files (external
/// audit POS-002) —
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
    "/usr/bin/chage",
    "/usr/bin/chfn",
    "/usr/bin/chsh",
    "/usr/bin/crond",
    "/usr/bin/doas",
    "/usr/bin/expiry",
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

/// PID→Entry cache entry recorded from `Event::ProcessSpawn`.
#[derive(Debug, Clone)]
struct Entry {
    ppid: u32,
    exe: PathBuf,
    /// When the process executed `exe` (the event's timestamp,
    /// CLOCK_MONOTONIC ns).
    spawn_ns: u64,
    /// External audit POS-003: the process's own start (its fork; exec
    /// keeps it), same clock. Without one (older records, the plain
    /// ingest calls) its exec time stands in: the latest it can be.
    start_ns: u64,
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

impl ExecIdentity {
    /// The identity of an exec event's own process: the file the kernel
    /// executed (or the caller's string, normalised, without it) and the
    /// script an interpreter runs, from its argv.
    pub fn of_exec(exe: &str, argv: &[String]) -> Self {
        let path = PathBuf::from(exe);
        let script = script_of(&path, argv).map(|s| s.to_string());
        Self { exe: path, script }
    }

    /// A rule's built-in client: the executed file itself is one of
    /// `programs` ([`names`]), in a root-owned system tree — whatever
    /// script an interpreter among them runs.
    pub fn is_known_binary(&self, programs: &[&str]) -> bool {
        let exe = self.exe.to_string_lossy();
        in_system_tree(&exe)
            && self
                .exe
                .file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| programs.iter().any(|p| names(p, n)))
    }

    /// Review 85: is this identity one of `clients`? An entry ending in
    /// `/` is a tree only that client installs (its bundled runtime): the
    /// exe must lie in it. Any other entry is a basename: the exe's for a
    /// binary, else the script's (`.py` dropped) an interpreter runs. The
    /// exe, and a script, must lie in a root-owned system tree
    /// ([`in_system_tree`]); an interpreter running an inline program
    /// (`python3 -c …`), a module (`-m`) or nothing is never a client by
    /// name.
    pub fn is_client(&self, clients: &[&str]) -> bool {
        let exe = self.exe.to_string_lossy();
        if !in_system_tree(&exe) {
            return false;
        }
        if clients
            .iter()
            .any(|c| c.ends_with('/') && exe.starts_with(c))
        {
            return true;
        }
        let named = |p: &str| {
            let base = p.rsplit('/').next().unwrap_or(p);
            let base = base.strip_suffix(".py").unwrap_or(base);
            clients.iter().any(|c| !c.ends_with('/') && names(c, base))
        };
        match &self.script {
            None => named(&exe),
            Some(script) if script.starts_with('/') => in_system_tree(script) && named(script),
            // A module run with `-m` resolves through the working directory
            // and PYTHONPATH, both the caller's: only a client's own runtime
            // tree (above) vouches for it.
            Some(_) => false,
        }
    }
}

/// An allowlist entry `entry` names the program `base` (a basename): the
/// same name, or the kernel's `comm` for it — the first
/// [`COMM_LEN_MAX`] bytes — since the allowlists are written in the
/// names `ps` shows (`unattended-upgr` for `unattended-upgrade`).
fn names(entry: &str, base: &str) -> bool {
    entry == base || (entry.len() == COMM_LEN_MAX && base.starts_with(entry))
}

/// `TASK_COMM_LEN` less its NUL.
const COMM_LEN_MAX: usize = 15;

/// Review 85: `path` lies in a root-owned system tree, which a process
/// without root cannot write: not `/tmp`, a home, `/dev/shm`, `/run` or a
/// memfd, and not a binary deleted or replaced while it runs.
pub(crate) fn in_system_tree(path: &str) -> bool {
    const TREES: &[&str] = &[
        "/usr/",
        "/opt/",
        "/snap/",
        "/bin/",
        "/sbin/",
        "/lib/",
        "/lib64/",
        "/var/lib/snapd/snap/",
        "/nix/store/",
    ];
    TREES.iter().any(|t| path.starts_with(t))
        && !path.contains("/../")
        && !path.ends_with(" (deleted)")
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
    /// External audit POS-003: check a cached exec against the process
    /// its pid names now ([`AuthSessionTracker::for_host`]).
    live: bool,
    /// When the agent started, in `/proc/<pid>/stat` clock ticks since
    /// boot: a process started before it ran its exe before any exec event
    /// could be seen.
    observer_start: std::sync::OnceLock<Option<u64>>,
    /// Tests: the time the host spent suspended (`CLOCK_BOOTTIME` −
    /// `CLOCK_MONOTONIC`) instead of the clocks'.
    #[cfg(test)]
    suspended_ns: Option<u64>,
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
        Self::build(proc_root.into(), false)
    }

    fn build(proc_root: PathBuf, live: bool) -> Self {
        Self {
            inner: Arc::new(Inner {
                state: RwLock::new(InnerState {
                    map: HashMap::with_capacity(TRACKER_CAP),
                    order: VecDeque::with_capacity(TRACKER_CAP),
                    daemons: HashMap::new(),
                    daemon_order: VecDeque::new(),
                }),
                proc_root,
                live,
                observer_start: std::sync::OnceLock::new(),
                #[cfg(test)]
                suspended_ns: None,
            }),
        }
    }

    /// Reads the live `/proc`, without checking a cached exec against the
    /// process its pid names now (tests and tools, whose pids are made
    /// up). The agent uses [`Self::for_host`].
    pub fn with_proc() -> Self {
        Self::new("/proc")
    }

    /// The agent's tracker: the live `/proc`, and every cached exec the
    /// lineage walks checked against the process its pid names now —
    /// a pid reused by a fork, which no exec event announces, does not
    /// inherit the entry (external audit POS-003).
    pub fn for_host() -> Self {
        Self::build(PathBuf::from("/proc"), true)
    }

    /// Tests: [`Self::for_host`] on a fixture `/proc`, with the host's
    /// suspended time given.
    #[cfg(test)]
    fn live_on(proc_root: &Path, suspended_ns: u64) -> Self {
        let mut t = Self::build(proc_root.to_path_buf(), true);
        Arc::get_mut(&mut t.inner).unwrap().suspended_ns = Some(suspended_ns);
        t
    }

    /// Record a `ProcessSpawn` observation. Overwrites any prior
    /// entry for `pid` (PID reuse — the new spawn replaces the old
    /// lineage). Evicts the oldest first-inserted entry when the
    /// cache reaches [`TRACKER_CAP`].
    ///
    /// PID 0 is the kernel "no process" sentinel and is never
    /// recorded.
    pub fn ingest_spawn(&self, pid: u32, ppid: u32, exe: &str, spawn_ns: u64) {
        self.ingest_inner(pid, ppid, exe, false, None, spawn_ns, 0);
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
        self.ingest_exec(pid, ppid, exe, argv, spawn_ns, 0);
    }

    /// External audit POS-003: [`Self::ingest_spawn_with_argv`] with the
    /// process's own start (`Event::ProcessSpawn::start_ns`, its fork),
    /// as the exec event carries it (production; 0 unknown).
    pub fn ingest_exec(
        &self,
        pid: u32,
        ppid: u32,
        exe: &str,
        argv: &[String],
        spawn_ns: u64,
        start_ns: u64,
    ) {
        let argv_npm_cli = argv.get(1).is_some_and(|a| a.ends_with(NPM_CLI_SUFFIX));
        let script = script_of(Path::new(exe), argv);
        self.ingest_inner(pid, ppid, exe, argv_npm_cli, script, spawn_ns, start_ns);
    }

    #[allow(clippy::too_many_arguments)]
    fn ingest_inner(
        &self,
        pid: u32,
        ppid: u32,
        exe: &str,
        argv_npm_cli: bool,
        script: Option<Box<str>>,
        spawn_ns: u64,
        start_ns: u64,
    ) {
        if pid == 0 {
            return;
        }
        let entry = Entry {
            ppid,
            exe: PathBuf::from(exe),
            spawn_ns,
            start_ns: if start_ns != 0 { start_ns } else { spawn_ns },
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

    /// True iff `pid` or an ancestor ran an authentication binary
    /// ([`AUTH_BINARY_EXES`]) before the process below it in the lineage
    /// was forked ([`Self::lineage_exe_matches`]): `pid` runs inside an
    /// authenticated session, a job or an elevation. External audit
    /// POS-002: what that buys is narrow — the mass-write arm counts only
    /// such a process's rewrites of existing files, not the files it
    /// creates; a credential read is judged by
    /// [`Self::is_credential_reader`].
    pub fn is_auth_mediated(&self, pid: u32) -> bool {
        self.lineage_exe_matches(pid, is_auth_binary)
    }

    /// External audit POS-002: `pid` is an authentication binary itself,
    /// or the direct child of one forked after it ran it — the PAM stack
    /// reading `/etc/shadow` at the caller's uid (sudo, su, passwd,
    /// unix_chkpwd, a cron or gdm worker). A shell of the session it
    /// opened, and everything below, reads as itself.
    pub fn is_credential_reader(&self, pid: u32) -> bool {
        self.lineage_match(pid, is_auth_binary, 1).unwrap_or(false)
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
        self.lineage_match(pid, is_match, LINEAGE_DEPTH_CAP)
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

    /// Walk the lineage of `pid` upward and return true if `pid` runs an
    /// `is_match` binary, or an ancestor ran one before the process below
    /// it was forked ([`Self::lineage_match`]). Shared by every lineage
    /// predicate so all use the identical, non-forgeable walk.
    fn lineage_exe_matches(&self, pid: u32, is_match: impl Fn(&Path) -> bool) -> bool {
        self.lineage_match(pid, is_match, LINEAGE_DEPTH_CAP)
            .unwrap_or(false)
    }

    /// The lineage walk, at most `max_up` hops above `pid` (and
    /// [`LINEAGE_DEPTH_CAP`]); `None` when a hop can be read neither from
    /// the spawn cache nor from `/proc`. Each hop comes from the spawn
    /// cache, else from `/proc/<pid>/exe` (kernel-resolved) and
    /// `/proc/<pid>/status`. PIDs 0 and 1 (kernel / init) never match and
    /// end the walk.
    ///
    /// External audit POS-003: a process inherits what its parent runs
    /// when it is forked, not what the parent executes afterwards, and a
    /// pid outlives its process. An ancestor's match counts only when it
    /// ran the binary before the process below it was forked
    /// ([`Self::ran_before`]): a parent that forks the payload and then
    /// executes `sudo` (any user may run it; the exec event comes before
    /// any authentication) vouches for nothing. And a parent starts before
    /// its child: a process that started after the one below it is a
    /// later process given the pid of an exited parent, and the lineage
    /// ends there.
    fn lineage_match(
        &self,
        pid: u32,
        is_match: impl Fn(&Path) -> bool,
        max_up: usize,
    ) -> Option<bool> {
        if pid == 0 || pid == 1 {
            return Some(false);
        }
        let mut below = self.hop(pid)?;
        if is_match(&below.exe) {
            return Some(true);
        }
        for _ in 0..max_up.min(LINEAGE_DEPTH_CAP) {
            let ppid = below.ppid;
            if ppid == 0 || ppid == 1 || ppid == below.pid {
                return Some(false);
            }
            let up = self.hop(ppid)?;
            if !self.started_no_later(&up, &below) {
                return Some(false);
            }
            if is_match(&up.exe) && self.ran_before(&up, &below) {
                return Some(true);
            }
            below = up;
        }
        Some(false)
    }

    /// One hop of the walk: the spawn cache's record of `pid` while it
    /// still describes the process `pid` names, else `/proc`.
    fn hop(&self, pid: u32) -> Option<Hop> {
        let cached = {
            let s = self.inner.state.read();
            s.map.get(&pid).or_else(|| s.daemons.get(&pid)).cloned()
        };
        if let Some(e) = cached {
            if self.entry_is_current(pid, &e) {
                return Some(Hop {
                    pid,
                    ppid: e.ppid,
                    exe: e.exe,
                    cached: true,
                    spawn_ns: e.spawn_ns,
                    start_ns: e.start_ns,
                });
            }
        }
        let (ppid, exe) = self.lookup_proc(pid)?;
        Some(Hop {
            pid,
            ppid,
            exe,
            cached: false,
            spawn_ns: 0,
            start_ns: 0,
        })
    }

    /// `up` started no later than `below`, as the parent of a process
    /// does. A cached hop's start is on the monotonic clock; `/proc` shows
    /// a start on the boot clock, ahead of it by the time suspended before
    /// that start (between nothing and [`Self::suspended_ns`]): only a
    /// start that is later whatever that time was ends the walk. A start
    /// `/proc` does not show is not held against it.
    fn started_no_later(&self, up: &Hop, below: &Hop) -> bool {
        let slack = 2 * tick_ns();
        let boot = |h: &Hop| {
            self.proc_start_ticks(h.pid)
                .map(|t| t.saturating_mul(tick_ns()))
        };
        match (up.cached, below.cached) {
            (true, true) => up.start_ns <= below.start_ns,
            (true, false) => boot(below).is_none_or(|b| up.start_ns <= b + slack),
            (false, true) => {
                boot(up).is_none_or(|u| u <= below.start_ns + self.suspended_ns() + slack)
            }
            (false, false) => match (boot(up), boot(below)) {
                (Some(u), Some(b)) => u <= b + slack,
                _ => true,
            },
        }
    }

    /// External audit POS-003: `up` ran its exe before `below` was forked.
    /// - Both seen executing: `up`'s exec precedes `below`'s start.
    /// - `below` never seen executing: it runs the image it was forked
    ///   with, so the same exe as `up` means `up` ran it already. Any
    ///   other exe and the order is unknown.
    /// - `up` never seen executing ([`Self::held_validly`]).
    fn ran_before(&self, up: &Hop, below: &Hop) -> bool {
        if !up.cached {
            return self.held_validly(up, 0);
        }
        if below.cached {
            up.spawn_ns <= below.start_ns
        } else {
            below.exe == up.exe
        }
    }

    /// A process read from `/proc` (no exec event of it in the cache) has
    /// run its exe since before any exec could be seen: it started before
    /// the agent, or it was forked, without executing anything, from a
    /// parent that validly runs the same exe (a cron job's worker, sudo's
    /// monitor, an sshd session process). A process started since, whose
    /// exec event is missing (evicted, dropped), is not trusted.
    fn held_validly(&self, hop: &Hop, depth: usize) -> bool {
        if self.predates_observer(hop.pid) {
            return true;
        }
        if depth >= LINEAGE_DEPTH_CAP || hop.ppid == 0 || hop.ppid == 1 || hop.ppid == hop.pid {
            return false;
        }
        let Some(parent) = self.hop(hop.ppid) else {
            return false;
        };
        if parent.exe != hop.exe {
            return false;
        }
        parent.cached || self.held_validly(&parent, depth + 1)
    }

    /// The cached exec `e` still describes the process `pid` names: with
    /// live checks on, its start matches the one `/proc/<pid>/stat` shows
    /// (an exited process leaves the cache as the only record).
    fn entry_is_current(&self, pid: u32, e: &Entry) -> bool {
        !self.inner.live || self.started_at(pid, e.start_ns) != Some(false)
    }

    /// Does the process `pid` names now have the start `start_ns`
    /// (CLOCK_MONOTONIC)? `/proc/<pid>/stat` shows it in clock ticks of
    /// CLOCK_BOOTTIME, which runs ahead of the monotonic clock by the time
    /// the host was suspended before the process started: between nothing
    /// and all of the suspended time so far. `None` without live checks,
    /// without `/proc/<pid>/stat`, or for an unknown `start_ns`.
    fn started_at(&self, pid: u32, start_ns: u64) -> Option<bool> {
        if !self.inner.live || start_ns == 0 {
            return None;
        }
        let tick = tick_ns();
        let shown = self.proc_start_ticks(pid)?.saturating_mul(tick);
        let slack = 2 * tick;
        Some(shown + slack >= start_ns && shown <= start_ns + self.suspended_ns() + slack)
    }

    /// `pid` started before the agent did.
    fn predates_observer(&self, pid: u32) -> bool {
        let observer = *self
            .inner
            .observer_start
            .get_or_init(|| self.proc_start_ticks_of("self"));
        match (observer, self.proc_start_ticks(pid)) {
            (Some(o), Some(p)) => p < o,
            _ => false,
        }
    }

    fn proc_start_ticks(&self, pid: u32) -> Option<u64> {
        self.proc_start_ticks_of(&pid.to_string())
    }

    /// `starttime`, field 22 of `/proc/<name>/stat`, counted after the
    /// `(comm)` field, which may itself hold spaces or parentheses.
    fn proc_start_ticks_of(&self, name: &str) -> Option<u64> {
        let stat = fs::read_to_string(self.inner.proc_root.join(name).join("stat")).ok()?;
        stat.rsplit_once(')')?
            .1
            .split_whitespace()
            .nth(19)?
            .parse()
            .ok()
    }

    /// `CLOCK_BOOTTIME` − `CLOCK_MONOTONIC` now: the time the host has
    /// spent suspended.
    fn suspended_ns(&self) -> u64 {
        #[cfg(test)]
        if let Some(s) = self.inner.suspended_ns {
            return s;
        }
        let now = |clock| {
            let mut ts = libc::timespec {
                tv_sec: 0,
                tv_nsec: 0,
            };
            // SAFETY: a valid clock id and a timespec to fill.
            unsafe { libc::clock_gettime(clock, &mut ts) };
            ts.tv_sec as u64 * 1_000_000_000 + ts.tv_nsec as u64
        };
        now(libc::CLOCK_BOOTTIME).saturating_sub(now(libc::CLOCK_MONOTONIC))
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

/// One hop of a lineage walk.
#[derive(Debug)]
struct Hop {
    pid: u32,
    ppid: u32,
    exe: PathBuf,
    /// From the spawn cache (the exec was seen), else from `/proc`.
    cached: bool,
    /// Cached only: when it executed `exe`, and its start.
    spawn_ns: u64,
    start_ns: u64,
}

/// Nanoseconds per `/proc` clock tick (`sysconf(_SC_CLK_TCK)`).
fn tick_ns() -> u64 {
    static TICK: std::sync::OnceLock<u64> = std::sync::OnceLock::new();
    *TICK.get_or_init(|| {
        // SAFETY: sysconf has no preconditions.
        let hz = unsafe { libc::sysconf(libc::_SC_CLK_TCK) };
        if hz > 0 {
            1_000_000_000 / hz as u64
        } else {
            10_000_000
        }
    })
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

    /// `/proc/<name>/stat` with `starttime` (field 22) at `ticks`.
    fn write_started(dir: &Path, name: &str, ppid: u32, ticks: u64) {
        let pid_dir = dir.join(name);
        fs::create_dir_all(&pid_dir).unwrap();
        fs::write(
            pid_dir.join("stat"),
            format!("1 (a b) S {ppid} 1 1 0 -1 4194560 0 0 0 0 0 0 0 0 20 0 1 0 {ticks} 0 0\n"),
        )
        .unwrap();
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
        // Build a fake /proc fixture, the agent started at tick 500:
        //   pid 123 -> exe /usr/bin/sudo, ppid=1, started at tick 100
        //   pid 124 -> exe /usr/bin/apt,  ppid=123, started at tick 200
        write_started(proc_root, "self", 1, 500);
        write_exe(proc_root, 123, "/usr/bin/sudo");
        write_status(proc_root, 123, 1);
        write_started(proc_root, "123", 1, 100);
        write_exe(proc_root, 124, "/usr/bin/apt");
        write_status(proc_root, 124, 123);
        write_started(proc_root, "124", 123, 200);

        let t = AuthSessionTracker::new(proc_root);
        // Cache is empty — the walk must reconstruct from /proc: sudo
        // started before the agent, so it ran sudo before any exec event
        // could be seen.
        assert!(t.is_auth_mediated(124));
        assert!(t.is_auth_mediated(123));

        // External audit POS-003: a sudo seen only in /proc that started
        // after the agent (its exec event lost or evicted) vouches for
        // nothing below it; itself, it still runs sudo.
        write_started(proc_root, "123", 1, 600);
        write_started(proc_root, "124", 123, 700);
        let t = AuthSessionTracker::new(proc_root);
        assert!(!t.is_auth_mediated(124));
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

    // ── External audit POS-002 / POS-003 ───────────────────────────

    const S: u64 = 1_000_000_000;

    /// A parent that forks the payload and only then executes sudo (any
    /// user may: the exec event comes before any password) does not make
    /// the payload sudo's: it was forked from what the parent ran before.
    #[test]
    fn a_parent_executing_sudo_after_forking_does_not_launder_its_children() {
        let tmp = TempDir::new().unwrap();
        let t = AuthSessionTracker::new(tmp.path());
        t.ingest_exec(50, 1, "/usr/sbin/nginx", &[], 10 * S, 10 * S);
        // the parent (100) runs the payload, forks 200 at 30 s, then
        // executes sudo at 40 s; 200 executes its own payload at 50 s
        t.ingest_exec(100, 50, "/srv/www/payload", &[], 21 * S, 20 * S);
        t.ingest_exec(100, 50, "/usr/bin/sudo", &[], 40 * S, 20 * S);
        t.ingest_exec(200, 100, "/srv/www/crypt", &[], 50 * S, 30 * S);
        assert!(
            !t.is_auth_mediated(200),
            "forked before its parent ran sudo"
        );
        assert!(t.is_auth_mediated(100), "the parent itself runs sudo");
        // what the parent forks after it ran sudo is sudo's
        t.ingest_exec(300, 100, "/usr/bin/apt", &[], 46 * S, 45 * S);
        assert!(t.is_auth_mediated(300));

        // a child forked before, that never executed: /proc shows the
        // image it was forked with — not sudo, so not sudo's
        write_exe(tmp.path(), 400, "/srv/www/payload");
        write_status(tmp.path(), 400, 100);
        assert!(!t.is_auth_mediated(400));
        // forked after, without executing (sudo's monitor): sudo's image
        write_exe(tmp.path(), 401, "/usr/bin/sudo");
        write_status(tmp.path(), 401, 100);
        t.ingest_exec(402, 401, "/usr/bin/tee", &[], 61 * S, 60 * S);
        assert!(t.is_auth_mediated(402));
        // the same holds for a package manager's exemption
        t.ingest_exec(500, 50, "/srv/www/payload", &[], 71 * S, 70 * S);
        t.ingest_exec(600, 500, "/srv/www/crypt", &[], 81 * S, 75 * S);
        t.ingest_exec(500, 50, "/usr/bin/dpkg", &[], 80 * S, 70 * S);
        assert!(!t.is_system_daemon_mediated(600));
    }

    /// A parent starts before its child: a process that started after the
    /// one below it holds the pid of an exited parent, and the lineage
    /// ends there instead of climbing into the newcomer's session.
    #[test]
    fn a_pid_taken_by_a_later_process_ends_the_lineage() {
        let tmp = TempDir::new().unwrap();
        let t = AuthSessionTracker::new(tmp.path());
        // a service (100) forks 200 at 30 s, then exits
        t.ingest_exec(100, 1, "/usr/sbin/nginx", &[], 20 * S, 20 * S);
        t.ingest_exec(200, 100, "/tmp/crypt", &[], 31 * S, 30 * S);
        assert!(!t.is_auth_mediated(200));
        // pid 100 goes to a shell of an SSH session, started at 45 s
        t.ingest_exec(50, 1, "/usr/sbin/sshd", &[], 5 * S, 5 * S);
        t.ingest_exec(100, 50, "/usr/bin/bash", &[], 46 * S, 45 * S);
        assert!(t.is_auth_mediated(100));
        assert!(!t.is_auth_mediated(200), "not the session's");
        assert_eq!(t.interactive_admin_status(200), Some(false));
        // a thread of the parent forking it is still the parent: the
        // process's own start is what is compared
        t.ingest_exec(300, 100, "/usr/bin/make", &[], 51 * S, 50 * S);
        assert!(t.is_auth_mediated(300));
    }

    /// The agent's tracker checks a cached exec against the process its
    /// pid names now: a fork that took the pid of an exited sudo (no exec
    /// event announces it) is read from /proc, not from sudo's entry. The
    /// boot clock /proc shows runs ahead by the time suspended.
    #[test]
    fn a_cached_exec_is_checked_against_the_process_its_pid_names_now() {
        let tmp = TempDir::new().unwrap();
        let ticks = |ns: u64| ns / tick_ns();
        let t = AuthSessionTracker::live_on(tmp.path(), 0);
        t.ingest_exec(100, 1, "/usr/bin/sudo", &[], 1000 * S, 1000 * S);
        write_started(tmp.path(), "100", 1, ticks(1000 * S));
        assert!(t.is_auth_mediated(100), "the same process");
        // a later process forked into pid 100
        write_started(tmp.path(), "100", 1, ticks(2000 * S));
        write_exe(tmp.path(), 100, "/home/u/crypt");
        write_status(tmp.path(), 100, 1);
        assert!(!t.is_auth_mediated(100), "sudo's entry is stale");
        // a laptop suspended an hour before sudo started: /proc shows its
        // start an hour later on the boot clock — still sudo
        let t = AuthSessionTracker::live_on(tmp.path(), 3600 * S);
        t.ingest_exec(100, 1, "/usr/bin/sudo", &[], 1000 * S, 1000 * S);
        write_started(tmp.path(), "100", 1, ticks(4600 * S));
        assert!(t.is_auth_mediated(100));
        // an exited process: the cache is the record
        fs::remove_dir_all(tmp.path().join("100")).unwrap();
        assert!(t.is_auth_mediated(100));
        // without live checks (tests, tools) the cache is trusted
        let t = AuthSessionTracker::new(tmp.path());
        t.ingest_exec(100, 1, "/usr/bin/sudo", &[], 1000 * S, 1000 * S);
        write_started(tmp.path(), "100", 1, ticks(9000 * S));
        assert!(t.is_auth_mediated(100));
    }

    /// External audit POS-002: a credential read is the PAM stack's when
    /// the reader is the authentication binary or its direct child — not
    /// when it runs anywhere in the session that binary opened.
    #[test]
    fn a_credential_reader_is_the_auth_binary_not_its_session() {
        let tmp = TempDir::new().unwrap();
        let t = AuthSessionTracker::new(tmp.path());
        t.ingest_exec(50, 1, "/usr/sbin/sshd", &[], S, S);
        t.ingest_exec(60, 50, "/usr/bin/bash", &[], 2 * S, 2 * S);
        t.ingest_exec(70, 60, "/usr/bin/cat", &[], 3 * S, 3 * S);
        t.ingest_exec(80, 60, "/usr/bin/sudo", &[], 4 * S, 4 * S);
        t.ingest_exec(90, 1, "/usr/sbin/unix_chkpwd", &[], 5 * S, 5 * S);
        assert!(t.is_auth_mediated(70), "in the session");
        assert!(!t.is_credential_reader(70), "but not the PAM stack");
        assert!(t.is_credential_reader(80));
        assert!(t.is_credential_reader(90));
        assert!(t.is_credential_reader(60), "the session's first child");
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

    /// An allowlist written in `comm` names (15 bytes) still names the
    /// program the kernel cut it from; a shorter entry is never a prefix.
    #[test]
    fn a_comm_length_entry_names_the_longer_program() {
        let id = |exe: &str| ExecIdentity {
            exe: PathBuf::from(exe),
            script: None,
        };
        assert!(id("/usr/lib/systemd/systemd-networkd").is_client(&["systemd-network"]));
        assert!(id("/usr/lib/systemd/systemd-networkd").is_known_binary(&["systemd-network"]));
        assert!(!id("/usr/lib/systemd/systemd-logindx").is_client(&["systemd-logind"]));
        assert!(!id("/tmp/systemd-networkd").is_client(&["systemd-network"]));
        assert!(!id("/tmp/systemd-networkd").is_known_binary(&["systemd-network"]));
    }
}
