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
use std::marker::PhantomData;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use nn_model::Event;
use parking_lot::RwLock;

use super::host::PostureHost;

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
/// SECURITY: since lab PR 175 no rule and no posture arm trusts a lineage
/// match on this list: the package managers proper
/// ([`PACKAGE_MANAGER_EXES`]) are trusted during a root transaction only
/// ([`AuthSessionTracker::in_package_transaction`]), and `mandb` for its
/// own writes as a system account
/// ([`AuthSessionTracker::is_system_man_cache_writer`]). The list keeps
/// the review-49 side cache ([`DAEMON_CACHE_CAP`]). Keep tight; add the
/// most-specific exec path, never a directory.
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

/// External audit NN-AUD-284 (FIMR-010): the package managers proper —
/// [`SYSTEM_DAEMON_EXES`] without `mandb`. The FIM rules' package carve-out
/// (the agent's `fim::rules::PackageManaged`) and the drain's rate limiter
/// trust these, through [`AuthSessionTracker::is_package_transaction_write`].
/// `mandb` is not set-id (man-db's default), so any user runs it, with
/// `LD_PRELOAD`, and has it fork whatever it likes: as a lineage root for
/// those it turned a user's `crontab` install from High + KillProcess into
/// Log + Low. When a package installs manual pages dpkg runs `mandb`
/// through man-db's trigger, so its writes there descend from dpkg anyway.
/// Lab PR 175: the network, chain and R009 carve-outs and the posture's
/// arms trust these the same way; `mandb`'s cache rebuild keeps its own,
/// narrower, mass-write exemption
/// ([`AuthSessionTracker::is_system_man_cache_writer`]).
///
/// None of these is set-id either: a user who runs one with `LD_PRELOAD`
/// (`dpkg --version`) has it fork whatever it likes, as with `mandb`. A
/// transaction is a package manager the kernel executed as root
/// ([`AuthSessionTracker::in_package_transaction`]).
pub const PACKAGE_MANAGER_EXES: &[&str] = &[
    "/usr/bin/apt",
    "/usr/bin/apt-get",
    "/usr/bin/dnf",
    "/usr/bin/dnf-3",
    "/usr/bin/dpkg",
    "/usr/bin/microdnf",
    "/usr/bin/rpm",
    "/usr/bin/yum",
    "/usr/lib/snapd/snapd",
    "/usr/libexec/packagekitd",
];

/// NN-AUD-284: how long after a package manager was last seen running its
/// transaction still covers a write. There is no exit feed, so the last
/// time a lineage walk found it running stands in for its exit.
const TRANSACTION_EXIT_GRACE_NS: u64 = 30_000_000_000;

/// NN-AUD-284: for a package manager that exited before any walk found it
/// running (a short `dpkg -i`), how long after its exec its transaction
/// covers a write.
const TRANSACTION_UNSEEN_GRACE_NS: u64 = 60_000_000_000;

/// Lab PR 175: man-db's cache builder, whose own writes the posture's
/// mass-write arm exempts ([`AuthSessionTracker::is_system_man_cache_writer`]).
const MANDB_EXE: &str = "/usr/bin/mandb";

/// Lab PR 175: the highest uid of a system account (`SYS_UID_MAX` in
/// `login.defs`: 999 on Debian, Ubuntu, Fedora and RHEL). man-db rebuilds
/// its caches as `man` (Debian, Ubuntu) or root (Fedora); a user runs a
/// program as such an account only with root's help.
const SYSTEM_UID_MAX: u32 = 999;

/// Lab PR 175: the directories of a user's container storage below a
/// directory of theirs — rootless Podman's (`~/.local/share/containers`)
/// and unprivileged LXC's (`~/.local/share/lxc`); the user owns the
/// directory the marker ends with
/// ([`AuthSessionTracker::is_user_container_storage_write`]).
const USER_CONTAINER_STORAGE: &[&str] = &["/.local/share/containers/", "/.local/share/lxc/"];

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
    /// Lab PR 175: the real uid the process executed `exe` as (the exec
    /// event's, from the kernel's credentials; 0 for the plain ingest
    /// calls of tests and tools).
    uid: u32,
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

    /// External audit NETR-015 (NN-AUD-298): a program root installed. The
    /// executed file lies in a root-owned system tree ([`in_system_tree`])
    /// and, for an interpreter, so does the script it runs, named by an
    /// absolute path: an inline program (`-c`, `-e`), a module (`-m`,
    /// found through the caller's working directory and `PYTHONPATH`), a
    /// relative path or standard input is the caller's, not the tree's.
    pub fn is_installed_program(&self) -> bool {
        if !in_system_tree(&self.exe.to_string_lossy()) {
            return false;
        }
        if !is_interpreter(&self.exe) {
            return true;
        }
        self.script
            .as_deref()
            .is_some_and(|s| s.starts_with('/') && in_system_tree(s))
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
pub fn in_system_tree(path: &str) -> bool {
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

/// External audit POS-005: the agent's own containment cgroups — the slice
/// `response::config::ExecutorConfig` moves processes into
/// (`blocked.scope`, `throttled.scope`, and the NEUTRALIZE cgroups below
/// the former). A process there shows the agent's cgroup, not its own
/// workload's, and contained processes of unrelated workloads share it.
const AGENT_CONTAINMENT_SLICE: &str = "/northnarrow.slice";

fn in_agent_containment(path: &str) -> bool {
    path.strip_prefix(AGENT_CONTAINMENT_SLICE)
        .is_some_and(|rest| rest.is_empty() || rest.starts_with('/'))
}

/// External audit POS-005: the workload a process runs in, as its cgroup
/// path names it. It scopes the posture's corroboration ledger.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Workload {
    /// The cgroup path up to the unit or container: the scope's key.
    pub path: String,
    /// The path names a container ([`container_of_cgroup`]). A container
    /// is an actor of its own even when a login session started it.
    pub container: bool,
}

/// Container runtimes' cgroup names for one container: `<prefix><id>.scope`
/// with a systemd driver, `<prefix><id>` with a cgroupfs one (Podman's
/// `/libpod_parent/libpod-<id>`, CRI-O's `…/pod<uid>/crio-<id>`).
const CONTAINER_PREFIXES: &[&str] = &["libpod-", "docker-", "cri-containerd-", "crio-"];

/// The cgroups of a runtime's monitor (conmon), which runs beside its
/// container: `libpod-conmon-<id>.scope` next to `libpod-<id>.scope`.
const CONTAINER_MONITOR_PREFIXES: &[&str] = &["libpod-conmon-", "crio-conmon-"];

/// A container id as the runtimes write it in a cgroup name: 64 hex digits.
fn is_container_id(id: &str) -> bool {
    id.len() == 64 && id.bytes().all(|b| b.is_ascii_hexdigit())
}

/// A pod's cgroup below `kubepods`: `pod<uid>` (cgroupfs driver) or
/// `kubepods-<qos>-pod<uid>.slice` (systemd driver).
fn is_pod_segment(seg: &str) -> bool {
    let name = seg.strip_suffix(".slice").unwrap_or(seg);
    name.strip_prefix("pod")
        .or_else(|| name.rsplit_once("-pod").map(|(_, uid)| uid))
        .is_some_and(|uid| {
            !uid.is_empty()
                && uid
                    .bytes()
                    .all(|b| b.is_ascii_hexdigit() || b == b'-' || b == b'_')
        })
}

/// External audit POS-005: the deepest container a cgroup path names, as
/// the path up to it, or `None`. A container is a runtime's scope
/// ([`CONTAINER_PREFIXES`], rootful or below a user's `user@<uid>.service`
/// for a rootless one), a bare id below `/docker` (Docker's cgroupfs
/// driver) or below a pod, or a pod below `kubepods` when no container is
/// named under it. A monitor's scope ([`CONTAINER_MONITOR_PREFIXES`])
/// names its container's: a container whose init has exited is placed
/// through conmon, its nearest running ancestor. Units inside a container
/// (a systemd running in it) belong to the container.
fn container_of_cgroup(path: &str) -> Option<String> {
    let mut found = None;
    let mut start = 0;
    let mut under_kubepods = false;
    let mut holds_ids = false;
    for seg in path.split('/') {
        let end = start + seg.len();
        let name = seg.strip_suffix(".scope").unwrap_or(seg);
        let pod = under_kubepods && is_pod_segment(seg);
        let runtime = |prefixes: &[&str]| {
            prefixes
                .iter()
                .any(|p| name.strip_prefix(p).is_some_and(is_container_id))
        };
        if runtime(CONTAINER_PREFIXES) || (holds_ids && is_container_id(name)) || pod {
            found = Some(path[..end].to_string());
        } else if runtime(CONTAINER_MONITOR_PREFIXES) {
            found = Some(format!(
                "{}{}",
                &path[..start],
                seg.replacen("-conmon-", "-", 1)
            ));
        }
        under_kubepods |= seg.starts_with("kubepods");
        holds_ids = seg == "docker" || pod;
        start = end + 1;
    }
    found
}

/// External audit POS-005: the workload a cgroup path names. A container
/// ([`container_of_cgroup`]) is the path up to it. Otherwise the path up to
/// its deepest systemd unit (`….service`, `….scope`): a service together
/// with the cgroups it delegates below it, a `systemd-run` unit, a login
/// session's scope. A path that names neither (the root cgroup) is a
/// workload of its own.
fn workload_of_cgroup(path: &str) -> Workload {
    if let Some(container) = container_of_cgroup(path) {
        return Workload {
            path: container,
            container: true,
        };
    }
    let mut end = None;
    let mut at = 0;
    for seg in path.split('/') {
        at += seg.len();
        if seg.ends_with(".service") || seg.ends_with(".scope") {
            end = Some(at);
        }
        at += 1;
    }
    Workload {
        path: end.map_or(path, |end| &path[..end]).to_string(),
        container: false,
    }
}

/// External audit POS-005: the line of `/proc/<pid>/cgroup` that places a
/// process. A unified host has one (`0::/…`). A v1 or hybrid host has one
/// per hierarchy; read are systemd's own (`name=systemd`) and the resource
/// controllers runtimes and systemd place a process in (`cpu`, `cpuacct`,
/// `memory`, `pids`). The most specific wins: one that names a container,
/// else the deepest (the unified line, then systemd's, on a tie); a path in
/// the agent's containment slice only when no other line places the
/// process (the caller then reads its parent). On v1 a rootless
/// container gets no cgroup of its own (the controllers are not delegated
/// to users): it stays in its user's session.
fn placing_cgroup(text: &str) -> Option<&str> {
    text.lines()
        .filter_map(|line| {
            let mut fields = line.splitn(3, ':');
            let (_, controllers, path) = (fields.next()?, fields.next()?, fields.next()?.trim());
            let has = |wanted: &[&str]| controllers.split(',').any(|c| wanted.contains(&c));
            let rank: u8 = if controllers.is_empty() {
                2
            } else if has(&["name=systemd"]) {
                1
            } else if has(&["cpu", "cpuacct", "memory", "pids"]) {
                0
            } else {
                return None;
            };
            path.starts_with('/').then_some((rank, path))
        })
        .max_by_key(|&(rank, path)| {
            (
                !in_agent_containment(path),
                container_of_cgroup(path).is_some(),
                path.split('/').filter(|s| !s.is_empty()).count(),
                rank,
            )
        })
        .map(|(_, path)| path)
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
    /// External audit NN-AUD-284: package managers a lineage walk found
    /// running — pid → (its start, as cached; the latest time it was seen
    /// running, CLOCK_MONOTONIC ns). At most [`DAEMON_CACHE_CAP`] entries;
    /// a later spawn reusing the pid drops its entry.
    seen_running: HashMap<u32, (u64, u64)>,
    /// Insertion order — pushed on first insert, popped on
    /// eviction. We deliberately do NOT re-promote on overwrite:
    /// strict LRU would cost O(N) per overwrite without buying
    /// correctness, because [`AuthSessionTracker::is_auth_mediated`]
    /// falls back to `/proc` on miss. Any over-eager eviction of a
    /// hot entry simply pays a single readlink+read_to_string on
    /// the next lookup.
    order: VecDeque<u32>,
    /// Lab PR 267 (review #471 A1): the execs a pid ran before the one
    /// [`Self::map`] holds, oldest first, at most [`HISTORY_PER_PID`] — what
    /// an event judged after a later exec of its process ran at its time
    /// ([`judged_at`]). Dropped with the pid's entry.
    history: HashMap<u32, Vec<Entry>>,
}

/// Lab PR 267 (review #471 A1): earlier execs kept per pid (a wrapper's
/// `exec`, an interpreter re-executing, a `dpkg` run after the event).
const HISTORY_PER_PID: usize = 3;

thread_local! {
    /// Lab PR 267 (review #471 A1): the time the event being judged on this
    /// thread happened ([`judged_at`]), set and cleared around the
    /// synchronous judgement of one event.
    static JUDGED_AT: std::cell::Cell<Option<u64>> = const { std::cell::Cell::new(None) };
}

/// Lab PR 267 (review #471 A1): run `f` — the synchronous judgement of one
/// event that happened at `ts_ns` (CLOCK_MONOTONIC; 0: unknown, nothing is
/// scoped) — with every lineage lookup made on this thread answered as of
/// `ts_ns`: the exec a process had run by then, not one it ran after. On
/// the priority bus an exec (P1) is taken ahead of the older file and
/// network events of its process, and a tamper event hands the queued
/// execs to the lineage before they are judged (`nn_linux::sensors::bus`):
/// without the scope an event was judged on the image of a later exec of
/// its pid (a reader exemption through a later `execve(restic)`, a package
/// carve-out through a later `dpkg`). A pid whose only cached exec is later
/// than `ts_ns` answers "not known" — never `/proc`, which shows the later
/// image. Nested scopes restore the outer one.
pub fn judged_at<R>(ts_ns: u64, f: impl FnOnce() -> R) -> R {
    struct Restore(Option<u64>);
    impl Drop for Restore {
        fn drop(&mut self) {
            JUDGED_AT.with(|c| c.set(self.0));
        }
    }
    if ts_ns == 0 {
        return f();
    }
    let _restore = Restore(JUDGED_AT.with(|c| c.replace(Some(ts_ns))));
    f()
}

/// The time an event happened, as [`judged_at`] scopes its judgement: its
/// kernel timestamp; a flow's connect time (`start_ns`: the process that
/// connected), a canary trip's source event's. Every variant named.
pub fn event_time_ns(event: &Event) -> u64 {
    match event {
        Event::ProcessSpawn { timestamp_ns, .. }
        | Event::FileOpen { timestamp_ns, .. }
        | Event::MassWrite { timestamp_ns, .. }
        | Event::FileBurst { timestamp_ns, .. }
        | Event::DefenderSignal { timestamp_ns, .. }
        | Event::ExecCheck { timestamp_ns, .. }
        | Event::ModuleLoad { timestamp_ns, .. }
        | Event::BpfSyscall { timestamp_ns, .. }
        | Event::IoUring { timestamp_ns, .. }
        | Event::TcpConnect { timestamp_ns, .. }
        | Event::DnsQuery { timestamp_ns, .. }
        | Event::FsProtectDenial { timestamp_ns, .. }
        | Event::CanaryTripped { timestamp_ns, .. }
        | Event::DnsFlood { timestamp_ns, .. }
        | Event::SensorFlood { timestamp_ns, .. }
        | Event::ExploitPostcondition { timestamp_ns, .. } => *timestamp_ns,
        Event::Fim(fe) => fe.timestamp_ns,
        Event::NetFlow(nf) => nf.start_ns,
        Event::NetListener(nl) => nl.timestamp_ns,
    }
}

/// What the spawn cache knows a pid ran at a time.
enum CachedAt {
    /// The pid's latest exec (the time is at or after it, or no time).
    Current(Entry),
    /// An earlier exec of the pid, the latest at or before the time.
    Past(Entry),
    /// Only execs after the time: what it ran then is not known.
    LaterOnly,
    /// Nothing cached for the pid.
    Absent,
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
    /// Lab PR 175: the host's `/` for `/etc/passwd`, `/etc/subuid` and the
    /// owners of container storage directories; a fixture tree in tests.
    host_root: PathBuf,
}

/// Cheap, `Clone`-able shared handle. The tracker is `Send + Sync`
/// so both the per-event trigger detector and (future) background
/// pruning tasks can hold one without further plumbing.
///
/// R08a (lab PR 250): `H` is the host it reads — the process table, the
/// host's files, the clocks ([`PostureHost`]; the agent's is `LinuxHost`).
#[derive(Clone, Debug)]
pub struct AuthSessionTracker<H: PostureHost> {
    inner: Arc<Inner>,
    host: PhantomData<fn() -> H>,
}

impl<H: PostureHost> AuthSessionTracker<H> {
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
                    seen_running: HashMap::new(),
                    history: HashMap::new(),
                }),
                proc_root,
                live,
                observer_start: std::sync::OnceLock::new(),
                #[cfg(test)]
                suspended_ns: None,
                host_root: PathBuf::from(H::HOST_ROOT),
            }),
            host: PhantomData,
        }
    }

    /// Reads the live `/proc`, without checking a cached exec against the
    /// process its pid names now (tests and tools, whose pids are made
    /// up). The agent uses [`Self::for_host`].
    pub fn with_proc() -> Self {
        Self::new(H::PROC_ROOT)
    }

    /// The agent's tracker: the live `/proc`, and every cached exec the
    /// lineage walks checked against the process its pid names now —
    /// a pid reused by a fork, which no exec event announces, does not
    /// inherit the entry (external audit POS-003).
    pub fn for_host() -> Self {
        Self::build(PathBuf::from(H::PROC_ROOT), true)
    }

    /// Tests: `/etc` and the container storage read under `root`.
    #[cfg(any(test, feature = "test-util"))]
    pub fn with_host_root(mut self, root: &Path) -> Self {
        Arc::get_mut(&mut self.inner)
            .expect("an unshared tracker")
            .host_root = root.to_path_buf();
        self
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
    /// recorded. Tests and tools: the process is recorded as executed by
    /// root; the agent feeds [`Self::ingest_exec`], with the event's uid.
    pub fn ingest_spawn(&self, pid: u32, ppid: u32, exe: &str, spawn_ns: u64) {
        self.ingest_inner(pid, ppid, exe, false, None, spawn_ns, 0, 0);
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
        self.ingest_exec(pid, ppid, exe, argv, spawn_ns, 0, 0);
    }

    /// Lab PR 267 (R12a): ingest `event` when it is an exec
    /// (`Event::ProcessSpawn`), with what the posture's triggers and the
    /// replay ingest — the file the kernel executed (else the caller's
    /// string), the arguments, the exec's time, the process's own start,
    /// the uid. Returns whether it was one. The priority bus calls it for
    /// the execs still queued when an event of a higher class overtakes
    /// them, so the lineage that event is judged on holds every exec that
    /// reached the bus before it, as on a single queue.
    pub fn ingest_spawn_event(&self, event: &Event) -> bool {
        let Event::ProcessSpawn {
            pid,
            ppid,
            uid,
            filename,
            argv,
            timestamp_ns,
            exe,
            start_ns,
            ..
        } = event
        else {
            return false;
        };
        self.ingest_exec(
            *pid,
            *ppid,
            exe.path_or(filename),
            argv,
            *timestamp_ns,
            *start_ns,
            *uid,
        );
        true
    }

    /// External audit POS-003: [`Self::ingest_spawn_with_argv`] with the
    /// process's own start (`Event::ProcessSpawn::start_ns`, its fork),
    /// as the exec event carries it (production; 0 unknown). Lab PR 175:
    /// and the real uid it executed as (`Event::ProcessSpawn::uid`).
    #[allow(clippy::too_many_arguments)]
    pub fn ingest_exec(
        &self,
        pid: u32,
        ppid: u32,
        exe: &str,
        argv: &[String],
        spawn_ns: u64,
        start_ns: u64,
        uid: u32,
    ) {
        let argv_npm_cli = argv.get(1).is_some_and(|a| a.ends_with(NPM_CLI_SUFFIX));
        let script = script_of(Path::new(exe), argv);
        self.ingest_inner(
            pid,
            ppid,
            exe,
            argv_npm_cli,
            script,
            spawn_ns,
            start_ns,
            uid,
        );
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
        uid: u32,
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
            uid,
        };
        let mut s = self.inner.state.write();
        // Lab PR 267 (R12a): an exec the cache already holds (its time and
        // its process's start) changes nothing — the first ingest of an
        // exec stays. The priority bus ingests an exec when an event of a
        // higher class overtakes it ([`Self::ingest_spawn_event`]), and
        // again when the exec itself is judged. Review #471 A1: one older
        // than the exec held for the pid goes into the pid's history, at its
        // place, and the newer one stays current; the exec a newer one
        // replaces goes into the history too ([`judged_at`]).
        let same = |e: &Entry| e.spawn_ns == spawn_ns && e.start_ns == entry.start_ns;
        if let Some(prev) = s.map.get(&pid).cloned() {
            if same(&prev) || s.history.get(&pid).is_some_and(|h| h.iter().any(same)) {
                return;
            }
            let h = s.history.entry(pid).or_default();
            if prev.spawn_ns > spawn_ns {
                let at = h.partition_point(|e| e.spawn_ns <= spawn_ns);
                h.insert(at, entry);
                if h.len() > HISTORY_PER_PID {
                    h.remove(0);
                }
                return;
            }
            h.push(prev);
            if h.len() > HISTORY_PER_PID {
                h.remove(0);
            }
        }
        // NN-AUD-284: whatever ran under this pid before is over.
        s.seen_running.remove(&pid);
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
                    s.history.remove(&evict);
                }
            }
        }
    }

    /// Lab PR 267 (review #471 A1): the time lookups answer for — `explicit`
    /// (an event's time a caller passes; 0 is none), else the event being
    /// judged on this thread ([`judged_at`]), else none (now).
    fn at(&self, explicit: Option<u64>) -> Option<u64> {
        explicit
            .filter(|t| *t != 0)
            .or_else(|| JUDGED_AT.with(std::cell::Cell::get))
    }

    /// What the spawn cache knows `pid` ran at `at` ([`CachedAt`]): its
    /// latest exec when `at` is at or after it (or none), else the latest of
    /// its earlier execs at or before `at`, else "only later".
    fn cached_at(&self, pid: u32, at: Option<u64>) -> CachedAt {
        let s = self.inner.state.read();
        let Some(cur) = s.map.get(&pid).or_else(|| s.daemons.get(&pid)) else {
            return CachedAt::Absent;
        };
        match at {
            Some(t) if cur.spawn_ns > t => match s
                .history
                .get(&pid)
                .and_then(|h| h.iter().rev().find(|e| e.spawn_ns <= t))
            {
                Some(e) => CachedAt::Past(e.clone()),
                None => CachedAt::LaterOnly,
            },
            _ => CachedAt::Current(cur.clone()),
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
    /// (`prctl(PR_SET_NAME)`-spoofable).
    ///
    /// Lab PR 175: no longer a carve-out. It exempted the posture's
    /// mass-write, staging-exec and persistence arms, NN-L-NET-008, the
    /// chains' package carve-out and R009 for anything a `mandb`, or any
    /// package manager, had in its lineage — whoever ran it, and for as
    /// long as the descendant lived. They use
    /// [`Self::in_package_transaction`] (and the mass-write arm
    /// [`Self::is_system_man_cache_writer`]); this stays for the tests of
    /// the walk.
    #[cfg(any(test, feature = "test-util"))]
    pub fn is_system_daemon_mediated(&self, pid: u32) -> bool {
        self.lineage_exe_matches(pid, is_system_daemon_binary)
    }

    /// External audit NN-AUD-284 (FIMR-010): a write `pid` made at
    /// `event_ns` (CLOCK_MONOTONIC) belongs to a package transaction —
    /// `pid` runs, or descends from, a package manager proper
    /// ([`PACKAGE_MANAGER_EXES`]: what the kernel executed, on the walk of
    /// [`Self::is_auth_mediated`], never `comm`), executed by root (lab PR
    /// 175), and that package manager's run covers `event_ns`:
    /// - it runs now, as the process the cache recorded (its start checked);
    /// - or it has exited, and `event_ns` is no later than
    ///   [`TRANSACTION_EXIT_GRACE_NS`] after a walk last found it running;
    /// - or it exited before any walk found it running (a short `dpkg -i`),
    ///   and `event_ns` is no later than [`TRANSACTION_UNSEEN_GRACE_NS`]
    ///   after its exec.
    ///
    /// The nearest package manager in the lineage answers: a process a
    /// finished `dpkg` left behind is not covered by the `apt` above it.
    /// Used by the FIM rules' package carve-out and the drain's rate
    /// limiter; it is [`Self::in_package_transaction`].
    pub fn is_package_transaction_write(&self, pid: u32, event_ns: u64) -> bool {
        self.in_package_transaction(pid, event_ns)
    }

    /// Lab PR 175: what `pid` did at `event_ns` (CLOCK_MONOTONIC: a write,
    /// a connect, an exec) belongs to a package transaction — the check of
    /// [`Self::is_package_transaction_write`], for every event:
    /// - the nearest package manager proper in its lineage
    ///   ([`PACKAGE_MANAGER_EXES`], what the kernel executed) was executed
    ///   by root (the exec event's real uid, or `/proc/<pid>/status` for a
    ///   package manager that predates the agent). None of them is set-id:
    ///   a user who runs `dpkg --version` with `LD_PRELOAD` has it fork
    ///   whatever it likes, as with `mandb`, but not as root. A package
    ///   manager run as root inside a user namespace is its uid on the
    ///   host (a rootless container's), so a container image's own
    ///   `/usr/bin/dpkg` vouches for nothing either;
    /// - its run covers `event_ns` (running now, last seen running at most
    ///   [`TRANSACTION_EXIT_GRACE_NS`] before, or never seen running and
    ///   executed at most [`TRANSACTION_UNSEEN_GRACE_NS`] before).
    ///
    /// An event without a time (0) is judged at the time it is read.
    /// Serves the FIM rules, NN-L-NET-008, the chains' package carve-out,
    /// R009 and the posture's arms.
    pub fn in_package_transaction(&self, pid: u32, event_ns: u64) -> bool {
        // Review #471 A1: the lineage as of the event — a package manager
        // the pid (or an ancestor) executed after it covers nothing.
        let Some(Some(hop)) = self.lineage_walk_at(
            pid,
            self.at(Some(event_ns)),
            |hop| is_package_manager_binary(&hop.exe),
            LINEAGE_DEPTH_CAP,
        ) else {
            return false;
        };
        if hop.uid != Some(0) {
            return false;
        }
        let event_ns = if event_ns == 0 {
            H::monotonic_ns()
        } else {
            event_ns
        };
        self.transaction_covers(&hop, event_ns)
    }

    /// Lab PR 175: `pid` itself runs man-db's cache builder ([`MANDB_EXE`],
    /// what the kernel executed), as root or a system account (uid at most
    /// [`SYSTEM_UID_MAX`]): the daily rebuild (man-db's timer or cron job,
    /// as `man` on Debian and Ubuntu, root on Fedora). Its own writes only,
    /// not a descendant's: the posture's mass-write arm exempts them, as it
    /// exempted the `mandb` lineage before. A user's own `mandb` runs as
    /// that user, `LD_PRELOAD` and all; the rebuild that dpkg's man-db
    /// trigger runs descends from dpkg ([`Self::in_package_transaction`]).
    pub fn is_system_man_cache_writer(&self, pid: u32) -> bool {
        if pid == 0 || pid == 1 {
            return false;
        }
        self.hop(pid).is_some_and(|hop| {
            hop.exe == Path::new(MANDB_EXE) && hop.uid.is_some_and(|uid| uid <= SYSTEM_UID_MAX)
        })
    }

    /// Lab PR 175: a write (or open) `pid` made at `event_ns` belongs to a
    /// package transaction a user runs in a container of theirs, and lands
    /// in that container's storage. The posture's mass-write and
    /// persistence arms exempt it, so a rootless `podman build` whose `dnf`
    /// or `apt` unpacks thousands of files raises no `ConfirmedIntrusion`;
    /// the rules (FIM, R009, NN-L-NET-008, the chains) do not, as they judge
    /// the host's files, execs and network.
    ///
    /// - The nearest package manager proper in the lineage
    ///   ([`PACKAGE_MANAGER_EXES`]) was executed by a uid other than root
    ///   (root's is [`Self::in_package_transaction`]), and its run covers
    ///   `event_ns`, with the same windows.
    /// - Its storage: `<dir>/.local/share/containers/…` or
    ///   `<dir>/.local/share/lxc/…` whose marker directory that user owns,
    ///   `/run/user/<uid>/containers/…`, or `/var/lib/lxc/<name>/…` whose
    ///   `<name>` directory that user owns. "That user" is the uid, or the
    ///   owner of the `/etc/subuid` range the uid lies in (an unprivileged
    ///   LXC container's root is a subordinate uid). Ownership, not the
    ///   `/etc/passwd` home: no name-service call on the detection path, and
    ///   a directory the user owns holds nothing of anyone else.
    /// - `path` placed by the kernel's walk (absolute, `!path_from_user`):
    ///   inside that storage, whatever the namespace — the copy-up of an
    ///   overlay, a volume. Outside it (the user's home, the host's `/etc`
    ///   or `/tmp`, a bind-mounted directory): never.
    /// - Any other `path` — on a filesystem no host mount shows
    ///   (`mnt[maj:min:ino]/…`), cut by the walk (`…/…`), or the caller's
    ///   string (tracepoint mode): only when `pid` runs in a mount
    ///   namespace other than init's whose root mount is an overlay with
    ///   its upper and work directories in that storage, and, for a
    ///   `mnt[…]` path, on that very overlay. Another overlay the container
    ///   mounts (its upper directory could be a bind-mounted home) is not.
    pub fn is_user_container_storage_write(
        &self,
        pid: u32,
        event_ns: u64,
        path: &str,
        path_from_user: bool,
    ) -> bool {
        let Some(Some(hop)) = self.lineage_walk(
            pid,
            |hop| is_package_manager_binary(&hop.exe),
            LINEAGE_DEPTH_CAP,
        ) else {
            return false;
        };
        let Some(uid) = hop.uid.filter(|uid| *uid != 0) else {
            return false;
        };
        let event_ns = if event_ns == 0 {
            H::monotonic_ns()
        } else {
            event_ns
        };
        if !self.transaction_covers(&hop, event_ns) {
            return false;
        }
        let users = self.storage_users(uid);
        if !path_from_user && path.starts_with('/') {
            return self.in_container_storage(path, uid, &users);
        }
        let Some(root_dev) = self.storage_rooted_namespace(pid, uid, &users) else {
            return false;
        };
        crate::path_text::unplaced_root_dev(path).is_none_or(|dev| dev == root_dev)
    }

    /// Lab PR 175: `uid`, and the owner of the `/etc/subuid` range it lies
    /// in, if any (named by user name or uid; the name read from
    /// `/etc/passwd`).
    fn storage_users(&self, uid: u32) -> Vec<u32> {
        let mut users = vec![uid];
        let read = |f: &str| H::read_to_string(self.inner.host_root.join(f)).unwrap_or_default();
        let subuid = read("etc/subuid");
        let mut passwd: Option<String> = None;
        for line in subuid.lines() {
            let mut f = line.trim().splitn(3, ':');
            let (Some(owner), Some(start), Some(count)) = (f.next(), f.next(), f.next()) else {
                continue;
            };
            let (Ok(start), Ok(count)) = (start.parse::<u64>(), count.parse::<u64>()) else {
                continue;
            };
            if !(start..start.saturating_add(count)).contains(&u64::from(uid)) {
                continue;
            }
            let owner_uid = owner.parse::<u32>().ok().or_else(|| {
                passwd
                    .get_or_insert_with(|| read("etc/passwd"))
                    .lines()
                    .find_map(|l| {
                        let mut p = l.split(':');
                        (p.next() == Some(owner))
                            .then(|| p.nth(1).and_then(|u| u.parse().ok()))
                            .flatten()
                    })
            });
            if let Some(o) = owner_uid {
                if !users.contains(&o) {
                    users.push(o);
                }
            }
        }
        users
    }

    /// Lab PR 175: `path` (absolute, from the kernel's walk or an overlay's
    /// options) lies in the container storage of `users`
    /// ([`Self::is_user_container_storage_write`]).
    fn in_container_storage(&self, path: &str, uid: u32, users: &[u32]) -> bool {
        if !path.starts_with('/')
            || path
                .split('/')
                .any(|c| c == "." || c == ".." || c == crate::path_text::UNREAD_COMPONENT)
        {
            return false;
        }
        let owner =
            |dir: &str| H::dir_owner(self.inner.host_root.join(dir.trim_start_matches('/')));
        if users
            .iter()
            .any(|u| path.starts_with(&format!("/run/user/{u}/containers/")))
        {
            return true;
        }
        for marker in USER_CONTAINER_STORAGE {
            if let Some(at) = path.find(marker) {
                let dir = &path[..at + marker.len() - 1];
                if owner(dir).is_some_and(|o| users.contains(&o)) {
                    return true;
                }
            }
        }
        if let Some((name, _)) = path
            .strip_prefix("/var/lib/lxc/")
            .and_then(|rest| rest.split_once('/'))
        {
            if !name.is_empty()
                && owner(&format!("/var/lib/lxc/{name}"))
                    .is_some_and(|o| o == uid || users.contains(&o))
            {
                return true;
            }
        }
        false
    }

    /// Lab PR 175: `pid` runs in a mount namespace other than init's whose
    /// root mount (the last `/` of its `mountinfo`) is an overlay with its
    /// `upperdir` and `workdir` in the container storage of `users`; that
    /// overlay's `(major, minor)`.
    fn storage_rooted_namespace(&self, pid: u32, uid: u32, users: &[u32]) -> Option<(u32, u32)> {
        let ns = |p: &str| H::read_link(self.inner.proc_root.join(p).join("ns").join("mnt")).ok();
        let (own, init) = (ns(&pid.to_string())?, ns("1")?);
        if own == init {
            return None;
        }
        let text =
            H::read_to_string(self.inner.proc_root.join(pid.to_string()).join("mountinfo")).ok()?;
        let (dev, upper, work) = root_overlay(&text)?;
        (self.in_container_storage(&format!("{upper}/"), uid, users)
            && self.in_container_storage(&format!("{work}/"), uid, users))
        .then_some(dev)
    }

    /// NN-AUD-284: the run of the package manager `hop` covers `event_ns`
    /// ([`Self::is_package_transaction_write`]).
    fn transaction_covers(&self, hop: &Hop, event_ns: u64) -> bool {
        if self.hop_running(hop) {
            if hop.cached {
                // Seen running no earlier than now, nor than the event it
                // was found running for (the same clock).
                let seen = event_ns.max(H::monotonic_ns());
                // A package transaction writes in bursts: refresh at most
                // once a second, so the walks share the read lock.
                let fresh = self
                    .inner
                    .state
                    .read()
                    .seen_running
                    .get(&hop.pid)
                    .is_some_and(|(start, at)| {
                        *start == hop.start_ns && at.saturating_add(1_000_000_000) >= seen
                    });
                if fresh {
                    return true;
                }
                let mut s = self.inner.state.write();
                let slot = s
                    .seen_running
                    .entry(hop.pid)
                    .or_insert((hop.start_ns, seen));
                if slot.0 != hop.start_ns {
                    *slot = (hop.start_ns, seen);
                }
                slot.1 = slot.1.max(seen);
                while s.seen_running.len() > DAEMON_CACHE_CAP {
                    let Some(oldest) = s
                        .seen_running
                        .iter()
                        .min_by_key(|(_, (_, seen))| *seen)
                        .map(|(pid, _)| *pid)
                    else {
                        break;
                    };
                    s.seen_running.remove(&oldest);
                }
            }
            return true;
        }
        if !hop.cached {
            return false;
        }
        let seen = self
            .inner
            .state
            .read()
            .seen_running
            .get(&hop.pid)
            .filter(|(start, _)| *start == hop.start_ns)
            .map(|(_, seen)| *seen);
        match seen {
            Some(seen) => event_ns <= seen.saturating_add(TRANSACTION_EXIT_GRACE_NS),
            None => event_ns <= hop.spawn_ns.saturating_add(TRANSACTION_UNSEEN_GRACE_NS),
        }
    }

    /// `hop` still runs as the process the walk read: `/proc` shows it
    /// (not a zombie), and, for a cached hop with live checks, with the
    /// cached start.
    fn hop_running(&self, hop: &Hop) -> bool {
        self.is_running(hop.pid)
            && (!hop.cached || self.started_at(hop.pid, hop.start_ns) != Some(false))
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

    /// External audit POS-005: the workload `pid` runs in — the container
    /// or systemd unit its cgroup names ([`workload_of_cgroup`]) — read
    /// from `/proc/<pid>/cgroup` of `pid` or, once it has exited, of its
    /// nearest running ancestor (a child starts in its parent's cgroup). A
    /// process the agent moved into its own containment cgroups
    /// ([`AGENT_CONTAINMENT_SLICE`]) no longer shows the workload it ran in:
    /// it is placed by its nearest running ancestor outside them. `None`
    /// when nothing running can be read (past PID 1, a cache miss, the
    /// depth cap). Read only for an event that raised a trigger, with or
    /// without a login uid: a container a login session started is scoped
    /// by itself.
    pub fn session_workload(&self, pid: u32) -> Option<Workload> {
        let mut cur = pid;
        for _ in 0..LINEAGE_DEPTH_CAP {
            let live = self.nearest_running(cur)?;
            if let Some(path) = self.cgroup_path(live) {
                if !in_agent_containment(&path) {
                    return Some(workload_of_cgroup(&path));
                }
            }
            // Contained by the agent, or gone since: its parent's.
            let ppid = self
                .lookup_cache(live)
                .map(|(ppid, _)| ppid)
                .or_else(|| self.proc_ppid(live))?;
            if ppid == live {
                return None;
            }
            cur = ppid;
        }
        None
    }

    /// The cgroup path that places `pid` ([`placing_cgroup`]).
    fn cgroup_path(&self, pid: u32) -> Option<String> {
        if pid == 0 {
            return None;
        }
        let text =
            H::read_to_string(self.inner.proc_root.join(pid.to_string()).join("cgroup")).ok()?;
        placing_cgroup(&text).map(str::to_string)
    }

    /// `PPid:` of `/proc/<pid>/status`.
    fn proc_ppid(&self, pid: u32) -> Option<u32> {
        let text =
            H::read_to_string(self.inner.proc_root.join(pid.to_string()).join("status")).ok()?;
        parse_ppid(&text)
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
        if !H::is_dir(&dir) {
            return false;
        }
        let Ok(stat) = H::read_to_string(dir.join("stat")) else {
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
        let Ok(stat) = H::read_to_string(path) else {
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
    /// = npm's CLI entrypoint). Unlike [`Self::in_package_transaction`]
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
        match self.cached_at(pid, self.at(None)) {
            CachedAt::Current(e) | CachedAt::Past(e) => e.argv_npm_cli && is_node_exe(&e.exe),
            CachedAt::LaterOnly | CachedAt::Absent => false,
        }
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
        self.lineage_walk(pid, |hop| is_match(&hop.exe), max_up)
            .map(|found| found.is_some())
    }

    /// The walk of [`Self::lineage_match`], by hop: the first hop
    /// `is_match` accepts — `pid`'s own, or an ancestor's that ran its exe
    /// before the process below it was forked. `Some(None)` when the walk
    /// ends without one, `None` when a hop cannot be read.
    fn lineage_walk(
        &self,
        pid: u32,
        is_match: impl Fn(&Hop) -> bool,
        max_up: usize,
    ) -> Option<Option<Hop>> {
        self.lineage_walk_at(pid, self.at(None), is_match, max_up)
    }

    /// [`Self::lineage_walk`] as of `at` (review #471 A1): each hop the
    /// exec its pid had run by then ([`Self::hop_at`]).
    fn lineage_walk_at(
        &self,
        pid: u32,
        at: Option<u64>,
        is_match: impl Fn(&Hop) -> bool,
        max_up: usize,
    ) -> Option<Option<Hop>> {
        if pid == 0 || pid == 1 {
            return Some(None);
        }
        let mut below = self.hop_at(pid, at)?;
        if is_match(&below) {
            return Some(Some(below));
        }
        for _ in 0..max_up.min(LINEAGE_DEPTH_CAP) {
            let ppid = below.ppid;
            if ppid == 0 || ppid == 1 || ppid == below.pid {
                return Some(None);
            }
            let up = self.hop_at(ppid, at)?;
            if !self.started_no_later(&up, &below) {
                return Some(None);
            }
            if is_match(&up) && self.ran_before(&up, &below) {
                return Some(Some(up));
            }
            below = up;
        }
        Some(None)
    }

    /// External audit PROC-008: the nearest process in the lineage of
    /// `pid` — `pid` itself or an ancestor, on the walk of
    /// [`Self::is_auth_mediated`] (an ancestor counts only if it
    /// ran its program before the process below it was forked, POS-003) —
    /// whose exec identity `is_actor` accepts; its executable. `None` when
    /// there is none, or when the walk loses the chain first.
    pub fn actor_in_lineage(
        &self,
        pid: u32,
        is_actor: impl Fn(&ExecIdentity) -> bool,
    ) -> Option<PathBuf> {
        self.lineage_walk(
            pid,
            |hop| is_actor(&self.hop_identity(hop)),
            LINEAGE_DEPTH_CAP,
        )?
        .map(|hop| hop.exe)
    }

    /// Lab PR 222 (copy on first write): what the kernel executed for `pid`
    /// and for each ancestor on the walk of [`Self::actor_in_lineage`]
    /// (ordered, POS-003: it ends at PID 1, at a hop that started after the
    /// one below it, or at [`LINEAGE_DEPTH_CAP`]), nearest first, `pid`'s
    /// own identity at index 0. `None` when a hop can be read neither from
    /// the spawn cache nor from `/proc`: the lineage is not known.
    ///
    /// Reads only the spawn cache and `/proc` — never a file elsewhere, so
    /// the guard's fanotify reader may call it (an open on a marked
    /// filesystem from that thread would wait on itself).
    pub fn lineage_identities(&self, pid: u32) -> Option<Vec<(u32, ExecIdentity)>> {
        let hops = std::cell::RefCell::new(Vec::new());
        self.lineage_walk(
            pid,
            |hop| {
                hops.borrow_mut().push((hop.pid, self.hop_identity(hop)));
                false
            },
            LINEAGE_DEPTH_CAP,
        )?;
        Some(hops.into_inner())
    }

    /// What the kernel executed for a hop: the spawn cache's record, else
    /// `/proc` (`cmdline` names the script an interpreter runs).
    fn hop_identity(&self, hop: &Hop) -> ExecIdentity {
        let script = if hop.cached {
            hop.script.as_deref().map(str::to_string)
        } else {
            self.proc_script(hop.pid, &hop.exe)
        };
        ExecIdentity {
            exe: hop.exe.clone(),
            script,
        }
    }

    /// The script or module an interpreter `exe` runs as process `pid`,
    /// from `/proc/<pid>/cmdline` ([`script_of`]).
    fn proc_script(&self, pid: u32, exe: &Path) -> Option<String> {
        let cmdline =
            H::read(self.inner.proc_root.join(pid.to_string()).join("cmdline")).unwrap_or_default();
        let argv: Vec<String> = cmdline
            .split(|b| *b == 0)
            .filter(|a| !a.is_empty())
            .map(|a| String::from_utf8_lossy(a).into_owned())
            .collect();
        script_of(exe, &argv).map(String::from)
    }

    /// One hop of the walk: the spawn cache's record of `pid` while it
    /// still describes the process `pid` names, else `/proc`.
    fn hop(&self, pid: u32) -> Option<Hop> {
        self.hop_at(pid, self.at(None))
    }

    /// [`Self::hop`] as of `at` (review #471 A1): an earlier exec of the
    /// pid when its latest came after `at`; `None` (not known) when only
    /// later ones are cached — `/proc` would show the later image.
    fn hop_at(&self, pid: u32, at: Option<u64>) -> Option<Hop> {
        let (cached, past) = match self.cached_at(pid, at) {
            CachedAt::Current(e) => (Some(e), false),
            CachedAt::Past(e) => (Some(e), true),
            CachedAt::LaterOnly => return None,
            CachedAt::Absent => (None, false),
        };
        if let Some(e) = cached {
            if past || self.entry_is_current(pid, &e) {
                return Some(Hop {
                    pid,
                    ppid: e.ppid,
                    exe: e.exe,
                    script: e.script,
                    cached: true,
                    spawn_ns: e.spawn_ns,
                    start_ns: e.start_ns,
                    uid: Some(e.uid),
                });
            }
        }
        let (ppid, exe, uid) = self.lookup_proc(pid)?;
        Some(Hop {
            pid,
            ppid,
            exe,
            script: None,
            cached: false,
            spawn_ns: 0,
            start_ns: 0,
            uid,
        })
    }

    /// `up` started no later than `below`, as the parent of a process
    /// does. A cached hop's start is on the monotonic clock; `/proc` shows
    /// a start on the boot clock, ahead of it by the time suspended before
    /// that start (between nothing and [`Self::suspended_ns`]): only a
    /// start that is later whatever that time was ends the walk. A start
    /// `/proc` does not show is not held against it.
    fn started_no_later(&self, up: &Hop, below: &Hop) -> bool {
        let slack = 2 * H::clock_tick_ns();
        let boot = |h: &Hop| {
            self.proc_start_ticks(h.pid)
                .map(|t| t.saturating_mul(H::clock_tick_ns()))
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
        Some(self.ticks_show_start(self.proc_start_ticks(pid)?, start_ns))
    }

    /// A `/proc` start of `ticks` (boot clock) is the monotonic start
    /// `start_ns` ([`Self::started_at`]).
    fn ticks_show_start(&self, ticks: u64, start_ns: u64) -> bool {
        let tick = H::clock_tick_ns();
        let shown = ticks.saturating_mul(tick);
        let slack = 2 * tick;
        shown + slack >= start_ns && shown <= start_ns + self.suspended_ns() + slack
    }

    /// External audit NET-016: a time no later than the start of the
    /// process `pid` names now (`CLOCK_MONOTONIC` ns): nothing that process
    /// did is older. Its exec's start when the spawn cache holds the
    /// current process (live checks on); else the start `/proc/<pid>/stat`
    /// shows, on the boot clock, less all the time the host has spent
    /// suspended and two ticks of rounding. `None` when `/proc` does not
    /// show the process (it has exited). Read at connect time, next to
    /// [`Self::image_path`].
    pub fn start_floor_ns(&self, pid: u32) -> Option<u64> {
        if pid == 0 {
            return None;
        }
        let ticks = self.proc_start_ticks(pid)?;
        if self.inner.live {
            let cached = {
                let s = self.inner.state.read();
                s.map
                    .get(&pid)
                    .or_else(|| s.daemons.get(&pid))
                    .map(|e| e.start_ns)
            };
            // An earlier holder's exec passing the check started before
            // this process: still a floor.
            if let Some(start) = cached.filter(|s| *s != 0 && self.ticks_show_start(ticks, *s)) {
                return Some(start);
            }
        }
        let tick = H::clock_tick_ns();
        Some(
            ticks
                .saturating_mul(tick)
                .saturating_sub(self.suspended_ns() + 2 * tick),
        )
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
        let stat = H::read_to_string(self.inner.proc_root.join(name).join("stat")).ok()?;
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
        H::suspended_ns()
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
        let raw = H::read_to_string(&path).ok()?;
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
        // Review #471 A1: as of the event being judged ([`judged_at`]).
        match self.cached_at(pid, self.at(None)) {
            CachedAt::Current(e) | CachedAt::Past(e) => {
                return Some(ExecIdentity {
                    exe: e.exe,
                    script: e.script.as_deref().map(str::to_string),
                });
            }
            CachedAt::LaterOnly => return None,
            CachedAt::Absent => {}
        }
        let exe = H::read_link(self.inner.proc_root.join(pid.to_string()).join("exe")).ok()?;
        if exe.to_string_lossy().ends_with(" (deleted)") {
            return None;
        }
        let script = self.proc_script(pid, &exe);
        Some(ExecIdentity { exe, script })
    }

    /// External audit NETR-008: the image `pid` runs, for a network row
    /// filled at connect time: the spawn cache, else `/proc/<pid>/exe` as
    /// the kernel reports it. Unlike [`Self::exec_identity`] a deleted
    /// image is kept, with its ` (deleted)` suffix: a dropper that unlinks
    /// itself is still judged by the directory it ran from. A forked child
    /// that never exec'd has no cache entry and answers through `/proc`.
    pub fn image_path(&self, pid: u32) -> Option<String> {
        self.image_path_at(pid, 0)
    }

    /// [`Self::image_path`] as of `at_ns` (review #471 A1; 0: the event
    /// being judged on this thread, else now): an earlier exec when the
    /// latest came after it, `None` when only later ones are cached.
    pub fn image_path_at(&self, pid: u32, at_ns: u64) -> Option<String> {
        if pid == 0 {
            return None;
        }
        match self.cached_at(pid, self.at(Some(at_ns))) {
            CachedAt::Current(e) | CachedAt::Past(e) => {
                return Some(e.exe.to_string_lossy().into_owned())
            }
            CachedAt::LaterOnly => return None,
            CachedAt::Absent => {}
        }
        let exe = H::read_link(self.inner.proc_root.join(pid.to_string()).join("exe")).ok()?;
        Some(exe.to_string_lossy().into_owned())
    }

    /// External audit SNS-014: the image `pid` ran at `at_ns`
    /// (CLOCK_MONOTONIC), for a record read after the fact — a DNS query's
    /// sender, drained from its ring after the send. Only the sender's:
    /// - `None` when `/proc` no longer shows the pid (it exited), or shows a
    ///   process that started after `at_ns` (the pid was reused since);
    /// - the spawn cache's exec when it is that process's (its start is the
    ///   one `/proc/<pid>/stat` shows, live checks on) and ran no later
    ///   than `at_ns`; `None` when that process executed another image
    ///   after `at_ns` (what it ran then is not known);
    /// - else `/proc/<pid>/exe`, as [`Self::image_path`] reads it (a
    ///   deleted image keeps its ` (deleted)` suffix).
    ///
    /// `/proc` shows a start in ticks of the boot clock, so a process that
    /// started less than two ticks plus the host's suspended time after
    /// `at_ns` cannot be told from one started just before, and is taken
    /// for the sender; so is an exec after `at_ns` not yet in the cache.
    pub fn image_at(&self, pid: u32, at_ns: u64) -> Option<String> {
        if pid == 0 {
            return None;
        }
        let ticks = self.proc_start_ticks(pid)?;
        let tick = H::clock_tick_ns();
        let floor = ticks
            .saturating_mul(tick)
            .saturating_sub(self.suspended_ns() + 2 * tick);
        if floor > at_ns {
            return None;
        }
        // Review #471 A1: an earlier exec of the process when it executed
        // another image after `at_ns` (its history), else not known.
        match self.cached_at(pid, Some(at_ns)) {
            CachedAt::Current(e) | CachedAt::Past(e) => {
                // An earlier holder's exec says nothing about this process.
                if !self.inner.live || self.ticks_show_start(ticks, e.start_ns) {
                    return (e.spawn_ns <= at_ns).then(|| e.exe.to_string_lossy().into_owned());
                }
            }
            CachedAt::LaterOnly => {
                let latest = self.inner.state.read().map.get(&pid).map(|e| e.start_ns);
                if !self.inner.live || latest.is_some_and(|st| self.ticks_show_start(ticks, st)) {
                    return None;
                }
            }
            CachedAt::Absent => {}
        }
        let exe = H::read_link(self.inner.proc_root.join(pid.to_string()).join("exe")).ok()?;
        Some(exe.to_string_lossy().into_owned())
    }

    fn lookup_cache(&self, pid: u32) -> Option<(u32, PathBuf)> {
        match self.cached_at(pid, self.at(None)) {
            CachedAt::Current(e) | CachedAt::Past(e) => Some((e.ppid, e.exe)),
            CachedAt::LaterOnly | CachedAt::Absent => None,
        }
    }

    /// `/proc/<pid>`: its parent, its exe, and its real uid (`None` when
    /// the status shows none).
    fn lookup_proc(&self, pid: u32) -> Option<(u32, PathBuf, Option<u32>)> {
        let pid_str = pid.to_string();
        let exe_link = self.inner.proc_root.join(&pid_str).join("exe");
        let exe = H::read_link(&exe_link).ok()?;
        // `/proc/<pid>/exe` carries a ` (deleted)` suffix when the
        // on-disk binary was unlinked while the process is still
        // running. Treat that as a mismatch — a deleted/swapped
        // auth binary is exactly the case we must not trust.
        let exe_str = exe.to_string_lossy();
        if exe_str.ends_with(" (deleted)") {
            return None;
        }
        let status_path = self.inner.proc_root.join(&pid_str).join("status");
        let text = H::read_to_string(&status_path).ok()?;
        let ppid = parse_ppid(&text)?;
        Some((ppid, exe, parse_real_uid(&text)))
    }

    #[cfg(test)]
    fn entry_count(&self) -> usize {
        self.inner.state.read().map.len()
    }
}

impl<H: PostureHost> Default for AuthSessionTracker<H> {
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
    /// Cached only: what an interpreter `exe` runs ([`Entry::script`]).
    script: Option<Box<str>>,
    /// From the spawn cache (the exec was seen), else from `/proc`.
    cached: bool,
    /// Cached only: when it executed `exe`, and its start.
    spawn_ns: u64,
    start_ns: u64,
    /// Lab PR 175: the real uid it executed `exe` as (cached), or runs as
    /// (`/proc`); `None` when `/proc` shows none.
    uid: Option<u32>,
}

fn is_auth_binary(exe: &Path) -> bool {
    let s = exe.to_string_lossy();
    AUTH_BINARY_EXES.iter().any(|p| s == *p)
}

fn is_system_daemon_binary(exe: &Path) -> bool {
    let s = exe.to_string_lossy();
    SYSTEM_DAEMON_EXES.iter().any(|p| s == *p)
}

fn is_package_manager_binary(exe: &Path) -> bool {
    let s = exe.to_string_lossy();
    PACKAGE_MANAGER_EXES.iter().any(|p| s == *p)
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
pub fn is_interpreter(exe: &Path) -> bool {
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

/// Lab PR 175: the root mount of a `mountinfo` text — its last line whose
/// mount point (field 5) is `/` — when it is an overlay: its `(major,
/// minor)` and its `upperdir` and `workdir` (octal escapes decoded).
fn root_overlay(mountinfo: &str) -> Option<((u32, u32), String, String)> {
    let line = mountinfo
        .lines()
        .rfind(|l| l.split(' ').nth(4) == Some("/"))?;
    let (fields, sb) = line.split_once(" - ")?;
    let mut sb = sb.split(' ');
    if sb.next()? != "overlay" {
        return None;
    }
    let options = sb.nth(1)?;
    let (major, minor) = fields.split(' ').nth(2)?.split_once(':')?;
    let dev = (major.parse().ok()?, minor.parse().ok()?);
    let option = |name: &str| {
        options
            .split(',')
            .find_map(|o| o.strip_prefix(name)?.strip_prefix('='))
            .map(crate::path_text::unescape_octal)
    };
    Some((dev, option("upperdir")?, option("workdir")?))
}

/// Lab PR 175: the real uid, the first of the four on the `Uid:` line of a
/// `/proc/<pid>/status` body.
fn parse_real_uid(status_text: &str) -> Option<u32> {
    status_text
        .lines()
        .find_map(|line| line.strip_prefix("Uid:"))
        .and_then(|rest| rest.split_whitespace().next())
        .and_then(|uid| uid.parse().ok())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    use crate::posture::host::testing::{symlink, TestHost as H, TEST_OWNER};

    /// R08a (lab PR 250): the tracker on the portable test host.
    type AuthSessionTracker = super::AuthSessionTracker<H>;

    /// Review #471 A1: judged as of an event's time, a pid that executed
    /// again later answers with the image it ran then — its identity, its
    /// image, its walk — and one whose only cached exec is later answers
    /// "not known", never `/proc`'s later image; without a scope, now.
    #[test]
    fn a_lookup_judged_at_an_event_s_time_sees_the_exec_of_then() {
        let proc = TempDir::new().unwrap();
        let t = AuthSessionTracker::new(proc.path());
        t.ingest_exec(4200, 1, "/usr/bin/cat", &[], 10 * S, 9 * S, 1000);
        t.ingest_exec(4200, 1, "/usr/bin/restic", &[], 20 * S, 9 * S, 1000);
        let exe = |id: Option<ExecIdentity>| id.map(|i| i.exe.to_string_lossy().into_owned());
        assert_eq!(
            exe(t.exec_identity(4200)).as_deref(),
            Some("/usr/bin/restic"),
            "now"
        );
        judged_at(15 * S, || {
            assert_eq!(exe(t.exec_identity(4200)).as_deref(), Some("/usr/bin/cat"));
            assert_eq!(t.image_path(4200).as_deref(), Some("/usr/bin/cat"));
            // nested: the inner time, then the outer one again
            judged_at(25 * S, || {
                assert_eq!(t.image_path(4200).as_deref(), Some("/usr/bin/restic"));
            });
            assert_eq!(t.image_path(4200).as_deref(), Some("/usr/bin/cat"));
        });
        judged_at(5 * S, || {
            assert_eq!(t.exec_identity(4200), None, "before every cached exec");
            assert_eq!(t.image_path(4200), None);
        });
        assert_eq!(
            t.image_path_at(4200, 15 * S).as_deref(),
            Some("/usr/bin/cat")
        );
        assert_eq!(
            exe(t.exec_identity(4200)).as_deref(),
            Some("/usr/bin/restic"),
            "scope gone"
        );
        // the overtaken order: the later exec ingested first, the earlier
        // one after it goes to the history
        let u = AuthSessionTracker::new(proc.path());
        u.ingest_exec(4300, 1, "/usr/bin/restic", &[], 20 * S, 9 * S, 1000);
        u.ingest_exec(4300, 1, "/usr/bin/cat", &[], 10 * S, 9 * S, 1000);
        assert_eq!(
            u.image_path_at(4300, 15 * S).as_deref(),
            Some("/usr/bin/cat")
        );
        assert_eq!(u.image_path(4300).as_deref(), Some("/usr/bin/restic"));
    }

    /// Review #471 A1: a package manager the process executed after the
    /// event covers nothing — the transaction is the lineage's as of the
    /// event, not the one cached now.
    #[test]
    fn a_later_package_manager_exec_covers_no_earlier_event() {
        let proc = TempDir::new().unwrap();
        let t = AuthSessionTracker::new(proc.path());
        t.ingest_exec(4400, 1, "/tmp/.r/stager", &[], 10 * S, 9 * S, 0);
        t.ingest_exec(4400, 1, "/usr/bin/dpkg", &[], 20 * S, 9 * S, 0);
        assert!(
            !t.in_package_transaction(4400, 15 * S),
            "the write before dpkg"
        );
        assert!(t.in_package_transaction(4400, 21 * S), "the run after it");
    }

    /// Lab PR 267 (R12a): an exec the cache holds already, or one older than
    /// the exec it holds for the pid, changes nothing — the priority bus
    /// ingests an exec a tamper event overtakes, and again when the exec is
    /// judged, possibly after a newer exec of the same pid.
    #[test]
    fn an_exec_ingested_again_or_out_of_order_changes_nothing() {
        let proc = TempDir::new().unwrap();
        let t = AuthSessionTracker::new(proc.path());
        let spawn = |exe: &str, ts: u64| Event::ProcessSpawn {
            pid: 4100,
            ppid: 1,
            uid: 0,
            gid: 0,
            comm: "x".to_string(),
            filename: exe.to_string(),
            timestamp_ns: ts,
            argv: Vec::new(),
            parent_comm: String::new(),
            parent_start_ns: 0,
            start_ns: 5,
            parent_is_kthread: false,
            exe: Default::default(),
            argv_truncated: false,
            filename_truncated: false,
            stdio: Default::default(),
        };
        let a = spawn("/usr/bin/env", 10);
        let b = spawn("/usr/bin/python3", 20);
        assert!(t.ingest_spawn_event(&a));
        assert!(t.ingest_spawn_event(&b), "the newer exec, overtaken");
        assert_eq!(t.image_path(4100).as_deref(), Some("/usr/bin/python3"));
        assert!(
            t.ingest_spawn_event(&a),
            "the older exec judged in its turn"
        );
        assert_eq!(
            t.image_path(4100).as_deref(),
            Some("/usr/bin/python3"),
            "an older exec does not overwrite the newer"
        );
        assert!(t.ingest_spawn_event(&b));
        assert_eq!(t.image_path(4100).as_deref(), Some("/usr/bin/python3"));
        let c = spawn("/usr/bin/perl", 30);
        t.ingest_spawn_event(&c);
        assert_eq!(
            t.image_path(4100).as_deref(),
            Some("/usr/bin/perl"),
            "a newer one does"
        );
        assert!(!t.ingest_spawn_event(&Event::BpfSyscall {
            pid: 1,
            uid: 0,
            comm: String::new(),
            cmd: 0,
            arg: 0,
            timestamp_ns: 0,
        }));
    }

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

    /// External audit NN-AUD-284 (FIMR-010): a write belongs to a package
    /// transaction while the package manager proper it descends from runs
    /// (as the process the cache recorded), for 30 s after a walk last saw
    /// it running, or — never seen running — for 60 s after its exec. Not
    /// under `mandb`.
    #[test]
    fn a_package_transaction_is_bound_to_its_package_managers_run() {
        let tmp = TempDir::new().unwrap();
        let ticks = |ns: u64| ns / H::clock_tick_ns();
        let t = AuthSessionTracker::live_on(tmp.path(), 0);
        // far past the host's own monotonic clock
        let b = 1_000_000_000 * S;
        t.ingest_exec(200, 1, "/usr/bin/dpkg", &[], b, b, 0);
        t.ingest_exec(300, 200, "/bin/sh", &[], b + S, b + S, 0);
        write_started(tmp.path(), "200", 1, ticks(b));
        assert!(t.is_package_transaction_write(300, b + 2 * S), "dpkg runs");
        assert!(t.is_package_transaction_write(200, b + 2 * S));
        // dpkg exits: its sh is covered for 30 s after dpkg was last seen
        fs::remove_dir_all(tmp.path().join("200")).unwrap();
        assert!(t.is_package_transaction_write(300, b + 32 * S));
        assert!(!t.is_package_transaction_write(300, b + 33 * S));
        assert!(
            t.is_system_daemon_mediated(300),
            "the wide predicate (the walk's tests only, lab PR 175)"
        );
        // a new dpkg in the pid, never seen running: its exec + 60 s
        t.ingest_exec(200, 1, "/usr/bin/dpkg", &[], b + 100 * S, b + 100 * S, 0);
        t.ingest_exec(301, 200, "/bin/sh", &[], b + 101 * S, b + 101 * S, 0);
        assert!(t.is_package_transaction_write(301, b + 160 * S));
        assert!(!t.is_package_transaction_write(301, b + 161 * S));
        // the pid now names a later process (a fork, no exec event)
        write_started(tmp.path(), "200", 1, ticks(b + 200 * S));
        write_exe(tmp.path(), 200, "/usr/bin/bash");
        write_status(tmp.path(), 200, 1);
        assert!(!t.is_package_transaction_write(301, b + 120 * S));
        // mandb: not a package manager
        t.ingest_exec(910, 1, "/usr/bin/mandb", &[], b, b, 0);
        t.ingest_exec(920, 910, "/usr/bin/crontab", &[], b + S, b + S, 0);
        write_started(tmp.path(), "910", 1, ticks(b));
        assert!(t.is_system_daemon_mediated(920));
        assert!(!t.is_package_transaction_write(920, b + 2 * S));
        assert!(!t.is_package_transaction_write(910, b + 2 * S));
    }

    /// NN-AUD-284: the package managers proper are the posture's list
    /// without `mandb`, so the review-49 side cache keeps holding them.
    #[test]
    fn package_managers_are_the_system_daemons_without_mandb() {
        for exe in PACKAGE_MANAGER_EXES {
            assert!(SYSTEM_DAEMON_EXES.contains(exe), "{exe}");
        }
        let left: Vec<_> = SYSTEM_DAEMON_EXES
            .iter()
            .filter(|e| !PACKAGE_MANAGER_EXES.contains(e))
            .collect();
        assert_eq!(left, [&"/usr/bin/mandb"]);
    }

    /// `/proc/<pid>/status` with a parent and a real uid.
    fn write_status_uid(dir: &Path, pid: u32, ppid: u32, uid: u32) {
        let pid_dir = dir.join(pid.to_string());
        fs::create_dir_all(&pid_dir).unwrap();
        fs::write(
            pid_dir.join("status"),
            format!("Name:\tx\nPid:\t{pid}\nPPid:\t{ppid}\nUid:\t{uid}\t0\t0\t0\n"),
        )
        .unwrap();
    }

    /// Lab PR 175: a package transaction is a package manager root
    /// executed. None of them is set-id: a user's `dpkg --version` run
    /// with `LD_PRELOAD` forks what it likes, as that user — the wide
    /// predicate took it, and the time-bound one of lab PR 173 still did.
    /// A package manager known from `/proc` only answers with the real uid
    /// of its status.
    #[test]
    fn a_package_transaction_is_a_package_manager_root_executed() {
        let tmp = TempDir::new().unwrap();
        let t = AuthSessionTracker::new(tmp.path());
        // a user's dpkg, running, and the program it forked from /tmp
        t.ingest_exec(200, 100, "/usr/bin/dpkg", &[], S, S, 1000);
        t.ingest_exec(201, 200, "/tmp/payload", &[], 2 * S, 2 * S, 1000);
        fs::create_dir_all(tmp.path().join("200")).unwrap();
        assert!(t.is_system_daemon_mediated(201), "the wide predicate");
        assert!(!t.in_package_transaction(201, 3 * S));
        assert!(!t.is_package_transaction_write(201, 3 * S));
        assert!(!t.in_package_transaction(200, 3 * S));
        // root's dpkg, the same shape: a transaction, for its children
        // whatever they run as (apt's methods drop to `_apt`)
        t.ingest_exec(300, 100, "/usr/bin/dpkg", &[], S, S, 0);
        t.ingest_exec(301, 300, "/tmp/helper", &[], 2 * S, 2 * S, 0);
        t.ingest_exec(302, 300, "/usr/lib/apt/methods/http", &[], 2 * S, 2 * S, 42);
        fs::create_dir_all(tmp.path().join("300")).unwrap();
        assert!(t.in_package_transaction(301, 3 * S));
        assert!(t.in_package_transaction(302, 3 * S));
        // the nearest package manager answers: root's apt above a user's
        // dpkg does not cover what that dpkg forked
        t.ingest_exec(400, 1, "/usr/bin/apt-get", &[], S, S, 0);
        t.ingest_exec(410, 400, "/usr/bin/dpkg", &[], 2 * S, 2 * S, 1000);
        t.ingest_exec(411, 410, "/tmp/payload", &[], 3 * S, 3 * S, 1000);
        fs::create_dir_all(tmp.path().join("400")).unwrap();
        fs::create_dir_all(tmp.path().join("410")).unwrap();
        assert!(!t.in_package_transaction(411, 4 * S));
        // known from /proc only: its status's real uid
        write_exe(tmp.path(), 500, "/usr/bin/apt-get");
        write_status_uid(tmp.path(), 500, 1, 0);
        assert!(t.in_package_transaction(500, 3 * S));
        write_exe(tmp.path(), 510, "/usr/bin/apt-get");
        write_status_uid(tmp.path(), 510, 1, 1000);
        assert!(!t.in_package_transaction(510, 3 * S));
        write_exe(tmp.path(), 520, "/usr/bin/apt-get");
        write_status(tmp.path(), 520, 1);
        assert!(!t.in_package_transaction(520, 3 * S), "no Uid line");
    }

    /// Lab PR 175: an event without a time is judged when it is read, not
    /// covered by any transaction that ever ran (`0 <= seen + 30 s`).
    #[test]
    fn an_event_without_a_time_is_judged_now() {
        let tmp = TempDir::new().unwrap();
        let t = AuthSessionTracker::new(tmp.path());
        // root's dpkg, exited, executed at boot
        t.ingest_exec(200, 1, "/usr/bin/dpkg", &[], 1, 1, 0);
        t.ingest_exec(201, 200, "/bin/sh", &[], 2, 2, 0);
        assert!(t.in_package_transaction(201, 3));
        assert!(!t.in_package_transaction(201, 0));
    }

    /// Lab PR 175: man-db's cache rebuild, the one `mandb` exemption left
    /// (the posture's mass-write arm): `mandb` itself, as root or a system
    /// account — not what it forks, not a user's `mandb`.
    #[test]
    fn mandbs_own_writes_as_a_system_account_are_its_cache_rebuild() {
        let tmp = TempDir::new().unwrap();
        let t = AuthSessionTracker::new(tmp.path());
        t.ingest_exec(910, 1, "/usr/bin/mandb", &[], S, S, 6);
        t.ingest_exec(911, 910, "/usr/bin/crontab", &[], 2 * S, 2 * S, 6);
        t.ingest_exec(920, 900, "/usr/bin/mandb", &[], S, S, 1000);
        t.ingest_exec(930, 1, "/usr/bin/mandb", &[], S, S, 0);
        assert!(t.is_system_man_cache_writer(910), "man-db's timer, as man");
        assert!(t.is_system_man_cache_writer(930), "as root");
        assert!(!t.is_system_man_cache_writer(911), "its child");
        assert!(!t.is_system_man_cache_writer(920), "a user's mandb");
        assert!(
            !t.in_package_transaction(910, 2 * S),
            "not a package manager"
        );
        assert!(!t.in_package_transaction(911, 2 * S));
        // a child it forked without exec: /proc names mandb, and its uid
        write_exe(tmp.path(), 940, "/usr/bin/mandb");
        write_status_uid(tmp.path(), 940, 920, 1000);
        assert!(!t.is_system_man_cache_writer(940));
        write_exe(tmp.path(), 950, "/usr/bin/mandb");
        write_status_uid(tmp.path(), 950, 910, 6);
        assert!(t.is_system_man_cache_writer(950));
        assert!(!t.is_system_man_cache_writer(0));
    }

    /// Lab PR 175: a user's container storage, by ownership — rootless
    /// Podman's and LXC's below a directory of theirs, the runtime
    /// directory's, `/var/lib/lxc/<name>` they own — for the uid or the
    /// owner of the subordinate range it lies in.
    #[test]
    fn a_users_container_storage_is_told_by_ownership() {
        let host = TempDir::new().unwrap();
        let me = TEST_OWNER;
        for d in [
            "home/nn/.local/share/containers/storage",
            "home/nn/.local/share/lxc/c1",
            "var/lib/lxc/c2/rootfs",
        ] {
            fs::create_dir_all(host.path().join(d)).unwrap();
        }
        fs::create_dir_all(host.path().join("etc")).unwrap();
        fs::write(
            host.path().join("etc/passwd"),
            format!("root:x:0:0::/root:/bin/sh\nnn:x:{me}:{me}::/home/nn:/bin/bash\n"),
        )
        .unwrap();
        fs::write(host.path().join("etc/subuid"), "nn:100000:65536\n").unwrap();
        let t = AuthSessionTracker::new("/this/path/does/not/exist").with_host_root(host.path());
        let mine = t.storage_users(me);
        let ok = |p: &str, users: &[u32], uid: u32| t.in_container_storage(p, uid, users);
        let overlay = "/home/nn/.local/share/containers/storage/overlay/0a1b/diff/usr/lib/x";
        assert!(ok(overlay, &mine, me));
        assert!(ok(
            &format!("/run/user/{me}/containers/overlay/x"),
            &mine,
            me
        ));
        assert!(ok("/var/lib/lxc/c2/rootfs/usr/x", &mine, me));
        assert!(!ok("/home/nn/Documents/report.docx", &mine, me));
        assert!(
            !ok("/home/nn/.local/share/containers", &mine, me),
            "the marker's own entry"
        );
        assert!(!ok(
            "/home/nn/.local/share/containers/../../../Documents/a",
            &mine,
            me
        ));
        assert!(!ok("/home/nn/.local/share/containers/?/a", &mine, me));
        assert!(
            !ok("/run/user/4242/containers/x", &mine, me),
            "another uid's"
        );
        assert!(!ok("/var/lib/lxc/c9/rootfs/x", &mine, me), "absent");
        assert!(!ok("mnt[0:77:2]/usr/lib/x", &mine, me));
        // a directory of that name another uid owns
        assert!(!ok(overlay, &[me.wrapping_add(1)], me.wrapping_add(1)));
        // an unprivileged LXC container's root: a subordinate uid of nn
        let sub = t.storage_users(100_005);
        assert_eq!(sub, vec![100_005, me]);
        assert!(ok(
            "/home/nn/.local/share/lxc/c1/rootfs/usr/x",
            &sub,
            100_005
        ));
        assert_eq!(t.storage_users(200_000), vec![200_000]);
    }

    /// Lab PR 175: the root mount of a `mountinfo` (the last `/`), when it
    /// is an overlay; its layers decoded.
    #[test]
    fn the_root_overlay_is_read_from_mountinfo() {
        let mi = "22 1 8:1 / / rw - ext4 /dev/sda1 rw\n\
                  900 800 0:77 / / rw,relatime - overlay overlay rw,lowerdir=/l/a:/l/b,upperdir=/h/u\\054x/diff,workdir=/h/w\n\
                  901 900 0:78 / /run rw - tmpfs tmpfs rw\n";
        let (dev, upper, work) = root_overlay(mi).expect("overlay root");
        assert_eq!(dev, (0, 77));
        assert_eq!(upper, "/h/u,x/diff");
        assert_eq!(work, "/h/w");
        assert!(root_overlay("22 1 8:1 / / rw - ext4 /dev/sda1 rw\n").is_none());
        assert!(root_overlay("").is_none());
    }

    /// Lab PR 175: a package manager a user runs is exempt in that user's
    /// container storage only, and only during its run; one root runs is
    /// [`AuthSessionTracker::in_package_transaction`]'s.
    #[test]
    fn a_users_package_manager_writes_its_container_storage_only() {
        let host = TempDir::new().unwrap();
        let procs = TempDir::new().unwrap();
        let me = TEST_OWNER;
        fs::create_dir_all(host.path().join("home/nn/.local/share/containers/storage")).unwrap();
        let t = AuthSessionTracker::new(procs.path()).with_host_root(host.path());
        let storage = "/home/nn/.local/share/containers/storage/overlay/0a1b/diff/usr/lib/x";
        // the user's dnf (700) in a build container, and root's (800)
        t.ingest_exec(700, 600, "/usr/bin/dnf", &[], S, S, me);
        t.ingest_exec(800, 1, "/usr/bin/dnf", &[], S, S, 0);
        assert!(t.is_user_container_storage_write(700, 2 * S, storage, false));
        assert!(!t.is_user_container_storage_write(700, 2 * S, "/home/nn/Documents/a", false));
        assert!(
            !t.is_user_container_storage_write(800, 2 * S, storage, false),
            "root's: the transaction"
        );
        assert!(
            !t.is_user_container_storage_write(700, 120 * S, storage, false),
            "after its run"
        );
        // a path no host mount shows, cut, or the caller's string: only in a
        // namespace of its own rooted in that storage, on that overlay
        for p in [
            "mnt[0:77:2]/usr/lib/x",
            "…/site-packages/x.pyc",
            "/usr/lib/x",
        ] {
            assert!(
                !t.is_user_container_storage_write(700, 2 * S, p, p == "/usr/lib/x"),
                "{p}"
            );
        }
        fs::create_dir_all(procs.path().join("1/ns")).unwrap();
        symlink("mnt:[4026531841]", procs.path().join("1/ns/mnt")).unwrap();
        fs::create_dir_all(procs.path().join("700/ns")).unwrap();
        symlink("mnt:[4026532900]", procs.path().join("700/ns/mnt")).unwrap();
        let o = "/home/nn/.local/share/containers/storage/overlay";
        fs::write(
            procs.path().join("700/mountinfo"),
            format!(
                "900 800 0:77 / / rw - overlay overlay rw,lowerdir={o}/l/A,upperdir={o}/0a1b/diff,workdir={o}/0a1b/work\n\
                 901 900 0:78 / /mnt rw - overlay overlay rw,lowerdir=/x,upperdir=/home/nn/Documents/up,workdir=/home/nn/Documents/w\n"
            ),
        )
        .unwrap();
        assert!(t.is_user_container_storage_write(700, 2 * S, "mnt[0:77:2]/usr/lib/x", false));
        assert!(t.is_user_container_storage_write(700, 2 * S, "…/site-packages/x.pyc", false));
        assert!(t.is_user_container_storage_write(700, 2 * S, "/usr/lib/x", true));
        assert!(!t.is_user_container_storage_write(700, 2 * S, "mnt[0:78:2]/report.docx", false));
        assert!(!t.is_user_container_storage_write(700, 2 * S, "/home/nn/Documents/a", false));
        // rooted in the user's documents: nothing but placed storage paths
        fs::write(
            procs.path().join("700/mountinfo"),
            "900 800 0:77 / / rw - overlay overlay rw,lowerdir=/x,upperdir=/home/nn/Documents/up,workdir=/home/nn/Documents/w\n",
        )
        .unwrap();
        assert!(!t.is_user_container_storage_write(700, 2 * S, "mnt[0:77:2]/report.docx", false));
        // init's own namespace
        fs::remove_file(procs.path().join("700/ns/mnt")).unwrap();
        symlink("mnt:[4026531841]", procs.path().join("700/ns/mnt")).unwrap();
        assert!(!t.is_user_container_storage_write(700, 2 * S, "/usr/lib/x", true));
    }

    #[test]
    fn parse_real_uid_takes_the_first_uid() {
        assert_eq!(
            parse_real_uid("Name:\tx\nUid:\t1000\t0\t0\t0\nGid:\t5\t5\t5\t5\n"),
            Some(1000)
        );
        assert_eq!(parse_real_uid("Name:\tx\nPPid:\t1\n"), None);
        assert_eq!(parse_real_uid("Uid:\tx\n"), None);
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
            "/home/alice/.npm-global/lib/node_modules/npm/bin/npm-cli.js".to_string(),
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
        t.ingest_exec(50, 1, "/usr/sbin/nginx", &[], 10 * S, 10 * S, 0);
        // the parent (100) runs the payload, forks 200 at 30 s, then
        // executes sudo at 40 s; 200 executes its own payload at 50 s
        t.ingest_exec(100, 50, "/srv/www/payload", &[], 21 * S, 20 * S, 0);
        t.ingest_exec(100, 50, "/usr/bin/sudo", &[], 40 * S, 20 * S, 0);
        t.ingest_exec(200, 100, "/srv/www/crypt", &[], 50 * S, 30 * S, 0);
        assert!(
            !t.is_auth_mediated(200),
            "forked before its parent ran sudo"
        );
        assert!(t.is_auth_mediated(100), "the parent itself runs sudo");
        // what the parent forks after it ran sudo is sudo's
        t.ingest_exec(300, 100, "/usr/bin/apt", &[], 46 * S, 45 * S, 0);
        assert!(t.is_auth_mediated(300));

        // a child forked before, that never executed: /proc shows the
        // image it was forked with — not sudo, so not sudo's
        write_exe(tmp.path(), 400, "/srv/www/payload");
        write_status(tmp.path(), 400, 100);
        assert!(!t.is_auth_mediated(400));
        // forked after, without executing (sudo's monitor): sudo's image
        write_exe(tmp.path(), 401, "/usr/bin/sudo");
        write_status(tmp.path(), 401, 100);
        t.ingest_exec(402, 401, "/usr/bin/tee", &[], 61 * S, 60 * S, 0);
        assert!(t.is_auth_mediated(402));
        // the same holds for a package manager's exemption
        t.ingest_exec(500, 50, "/srv/www/payload", &[], 71 * S, 70 * S, 0);
        t.ingest_exec(600, 500, "/srv/www/crypt", &[], 81 * S, 75 * S, 0);
        t.ingest_exec(500, 50, "/usr/bin/dpkg", &[], 80 * S, 70 * S, 0);
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
        t.ingest_exec(100, 1, "/usr/sbin/nginx", &[], 20 * S, 20 * S, 0);
        t.ingest_exec(200, 100, "/tmp/crypt", &[], 31 * S, 30 * S, 0);
        assert!(!t.is_auth_mediated(200));
        // pid 100 goes to a shell of an SSH session, started at 45 s
        t.ingest_exec(50, 1, "/usr/sbin/sshd", &[], 5 * S, 5 * S, 0);
        t.ingest_exec(100, 50, "/usr/bin/bash", &[], 46 * S, 45 * S, 0);
        assert!(t.is_auth_mediated(100));
        assert!(!t.is_auth_mediated(200), "not the session's");
        assert_eq!(t.interactive_admin_status(200), Some(false));
        // a thread of the parent forking it is still the parent: the
        // process's own start is what is compared
        t.ingest_exec(300, 100, "/usr/bin/make", &[], 51 * S, 50 * S, 0);
        assert!(t.is_auth_mediated(300));
    }

    /// The agent's tracker checks a cached exec against the process its
    /// pid names now: a fork that took the pid of an exited sudo (no exec
    /// event announces it) is read from /proc, not from sudo's entry. The
    /// boot clock /proc shows runs ahead by the time suspended.
    #[test]
    fn a_cached_exec_is_checked_against_the_process_its_pid_names_now() {
        let tmp = TempDir::new().unwrap();
        let ticks = |ns: u64| ns / H::clock_tick_ns();
        let t = AuthSessionTracker::live_on(tmp.path(), 0);
        t.ingest_exec(100, 1, "/usr/bin/sudo", &[], 1000 * S, 1000 * S, 0);
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
        t.ingest_exec(100, 1, "/usr/bin/sudo", &[], 1000 * S, 1000 * S, 0);
        write_started(tmp.path(), "100", 1, ticks(4600 * S));
        assert!(t.is_auth_mediated(100));
        // an exited process: the cache is the record
        fs::remove_dir_all(tmp.path().join("100")).unwrap();
        assert!(t.is_auth_mediated(100));
        // without live checks (tests, tools) the cache is trusted
        let t = AuthSessionTracker::new(tmp.path());
        t.ingest_exec(100, 1, "/usr/bin/sudo", &[], 1000 * S, 1000 * S, 0);
        write_started(tmp.path(), "100", 1, ticks(9000 * S));
        assert!(t.is_auth_mediated(100));
    }

    /// External audit NET-016: the start read at connect time is never
    /// later than the process's own — the exec's start when the cache
    /// holds the current process, else `/proc`'s less the suspended time
    /// and two ticks — and it is later than anything an earlier holder of
    /// the pid did, beyond that slack.
    #[test]
    fn the_start_floor_is_the_current_process_start_or_below_it() {
        let tmp = TempDir::new().unwrap();
        let ticks = |ns: u64| ns / H::clock_tick_ns();
        let t = AuthSessionTracker::live_on(tmp.path(), 0);
        // the cached exec is the process pid 100 names: its exact start
        t.ingest_exec(100, 1, "/usr/bin/curl", &[], 1000 * S + 5, 1000 * S + 3, 0);
        write_started(tmp.path(), "100", 1, ticks(1000 * S + 3));
        assert_eq!(t.start_floor_ns(100), Some(1000 * S + 3));
        // a fork took pid 100 at 2000 s (no exec event): /proc's start
        write_started(tmp.path(), "100", 1, ticks(2000 * S));
        let floor = t.start_floor_ns(100).unwrap();
        assert!(
            floor <= 2000 * S && floor >= 2000 * S - 3 * H::clock_tick_ns(),
            "{floor}"
        );
        // an hour suspended: the floor moves back by the hour
        write_started(tmp.path(), "100", 1, ticks(10_000 * S));
        let t = AuthSessionTracker::live_on(tmp.path(), 3600 * S);
        assert_eq!(
            t.start_floor_ns(100),
            Some(6400 * S - 2 * H::clock_tick_ns())
        );
        // an exited process has no start to read
        fs::remove_dir_all(tmp.path().join("100")).unwrap();
        assert_eq!(t.start_floor_ns(100), None);
        assert_eq!(t.start_floor_ns(0), None);
    }

    /// External audit SNS-014: a DNS query's sender, named after the fact:
    /// the cached exec of the process that sent it, `/proc` for one with
    /// no exec event, and nothing for a later holder of the pid, for an
    /// image executed after the query, or for a process gone.
    #[test]
    fn the_image_at_a_time_is_the_sender_s_only() {
        let tmp = TempDir::new().unwrap();
        let ticks = |ns: u64| ns / H::clock_tick_ns();
        let t = AuthSessionTracker::live_on(tmp.path(), 0);
        // a resolver started before the agent: no exec event, /proc
        write_started(tmp.path(), "100", 1, ticks(10 * S));
        write_exe(tmp.path(), 100, "/usr/lib/systemd/systemd-resolved");
        assert_eq!(
            t.image_at(100, 1000 * S).as_deref(),
            Some("/usr/lib/systemd/systemd-resolved")
        );
        // a later process holds the pid now: the query was not its own
        write_started(tmp.path(), "100", 1, ticks(2000 * S));
        assert_eq!(t.image_at(100, 1000 * S), None);
        // the cached exec of the process that sent it, not what /proc
        // shows after a later exec
        t.ingest_exec(200, 1, "/usr/bin/curl", &[], 500 * S, 499 * S, 0);
        write_started(tmp.path(), "200", 1, ticks(499 * S));
        write_exe(tmp.path(), 200, "/usr/sbin/dnsmasq");
        assert_eq!(t.image_at(200, 600 * S).as_deref(), Some("/usr/bin/curl"));
        // it executed a forwarder's image after the query: never that
        // image — lab PR 267 (review #471 A1): the exec it ran then, kept in
        // the pid's history (it was "not known" before the history)
        t.ingest_exec(200, 1, "/usr/sbin/dnsmasq", &[], 700 * S, 499 * S, 0);
        assert_eq!(t.image_at(200, 600 * S).as_deref(), Some("/usr/bin/curl"));
        // before any exec the cache knows of: not known
        assert_eq!(t.image_at(200, 450 * S), None);
        assert_eq!(
            t.image_at(200, 800 * S).as_deref(),
            Some("/usr/sbin/dnsmasq")
        );
        // an earlier holder's entry: /proc names the current process
        t.ingest_exec(300, 1, "/usr/sbin/unbound", &[], 100 * S, 100 * S, 0);
        write_started(tmp.path(), "300", 1, ticks(900 * S));
        write_exe(tmp.path(), 300, "/tmp/x");
        assert_eq!(t.image_at(300, 950 * S).as_deref(), Some("/tmp/x"));
        // gone: the cache alone cannot tell whose entry it is
        fs::remove_dir_all(tmp.path().join("300")).unwrap();
        assert_eq!(t.image_at(300, 950 * S), None);
        assert_eq!(t.image_at(0, 950 * S), None);
    }

    /// External audit SNS-014: the start is field 22 counted after the last
    /// `)`: a command name holding spaces and parentheses cannot move it.
    #[test]
    fn stat_start_parses_comm_with_parens() {
        let tmp = TempDir::new().unwrap();
        let late = 5000 * S / H::clock_tick_ns();
        let early = 10 * S / H::clock_tick_ns();
        let dir = tmp.path().join("400");
        fs::create_dir_all(&dir).unwrap();
        // the name ends like a stat line whose start is late
        fs::write(
            dir.join("stat"),
            format!(
                "400 (my) S 1 1 1 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 {late} 0 0 (prog) \
                 S 1 1 1 0 -1 4194560 0 0 0 0 0 0 0 0 20 0 1 0 {early} 0 0\n"
            ),
        )
        .unwrap();
        write_exe(tmp.path(), 400, "/opt/my prog");
        let t = AuthSessionTracker::live_on(tmp.path(), 0);
        assert_eq!(t.image_at(400, 1000 * S).as_deref(), Some("/opt/my prog"));
    }

    /// External audit POS-002: a credential read is the PAM stack's when
    /// the reader is the authentication binary or its direct child — not
    /// when it runs anywhere in the session that binary opened.
    #[test]
    fn a_credential_reader_is_the_auth_binary_not_its_session() {
        let tmp = TempDir::new().unwrap();
        let t = AuthSessionTracker::new(tmp.path());
        t.ingest_exec(50, 1, "/usr/sbin/sshd", &[], S, S, 0);
        t.ingest_exec(60, 50, "/usr/bin/bash", &[], 2 * S, 2 * S, 0);
        t.ingest_exec(70, 60, "/usr/bin/cat", &[], 3 * S, 3 * S, 0);
        t.ingest_exec(80, 60, "/usr/bin/sudo", &[], 4 * S, 4 * S, 0);
        t.ingest_exec(90, 1, "/usr/sbin/unix_chkpwd", &[], 5 * S, 5 * S, 0);
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

    /// External audit NETR-015: what NN-L-NET-006/-019 take for a service
    /// on a common port.
    #[test]
    fn an_installed_program_is_the_trees_exe_and_script() {
        let id = |exe: &str, a: &[&str]| ExecIdentity::of_exec(exe, &argv(a));
        assert!(id("/usr/sbin/nginx", &["nginx"]).is_installed_program());
        assert!(id("/usr/bin/python3.12", &["python3", "/usr/bin/gunicorn"]).is_installed_program());
        for (exe, a) in [
            ("/tmp/backdoor", &["backdoor"][..]),
            (
                "/home/dev/.nvm/versions/node/v22/bin/node",
                &["node", "app.js"],
            ),
            ("/usr/bin/python3.12", &["python3", "/tmp/x.py"]),
            (
                "/usr/bin/python3.12",
                &["python3", "-m", "http.server", "8080"],
            ),
            ("/usr/bin/python3.12", &["python3", "-c", "import socket"]),
            ("/usr/bin/python3.12", &["python3", "server.py"]),
            ("/usr/bin/node", &["node"]),
            ("/usr/sbin/nginx (deleted)", &["nginx"]),
        ] {
            assert!(!id(exe, a).is_installed_program(), "{exe} {a:?}");
        }
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

    /// `/proc/<pid>/cgroup` with the unified hierarchy's line.
    fn write_cgroup(dir: &Path, pid: u32, path: &str) {
        let pid_dir = dir.join(pid.to_string());
        fs::create_dir_all(&pid_dir).unwrap();
        fs::write(pid_dir.join("cgroup"), format!("0::{path}\n")).unwrap();
    }

    /// The workload path `t` places `pid` in.
    fn workload_path(t: &AuthSessionTracker, pid: u32) -> Option<String> {
        t.session_workload(pid).map(|w| w.path)
    }

    /// Two container ids as the runtimes write them (64 hex digits).
    fn ids() -> (String, String) {
        ("0123456789abcdef".repeat(4), "fedcba9876543210".repeat(4))
    }

    /// External audit POS-005: without a container, a workload is its
    /// unit — a service with what it delegates below it, a login session's
    /// scope, a user's transient scope — or, without a unit in the path,
    /// the path itself.
    #[test]
    fn a_cgroup_path_names_its_deepest_unit() {
        for (path, workload) in [
            (
                "/system.slice/puppet.service",
                "/system.slice/puppet.service",
            ),
            (
                "/system.slice/containerd.service/payload",
                "/system.slice/containerd.service",
            ),
            (
                "/user.slice/user-1000.slice/session-3.scope",
                "/user.slice/user-1000.slice/session-3.scope",
            ),
            (
                "/user.slice/user-1000.slice/user@1000.service/app.slice/run-u12.scope",
                "/user.slice/user-1000.slice/user@1000.service/app.slice/run-u12.scope",
            ),
            // Not a runtime's id: a unit like any other.
            (
                "/system.slice/docker-0123abcd.scope",
                "/system.slice/docker-0123abcd.scope",
            ),
            (
                "/kubepods.slice/kubepods-burstable.slice",
                "/kubepods.slice/kubepods-burstable.slice",
            ),
            ("/", "/"),
        ] {
            let w = workload_of_cgroup(path);
            assert_eq!(w.path, workload, "{path}");
            assert!(!w.container, "{path}");
        }
    }

    /// External audit POS-005: the container runtimes' cgroups of the
    /// workload-context design (§4.2), rootful and rootless: each names
    /// its container, units inside a container belong to it, and a
    /// runtime's monitor (conmon) names the container beside it.
    #[test]
    fn the_runtimes_cgroups_name_their_container() {
        let (a, b) = ids();
        let user = "/user.slice/user-1000.slice/user@1000.service/user.slice";
        let pod = "kubepods-burstable-pod1f2e3d4c_5b6a_7980_a1b2_c3d4e5f60718.slice";
        let kube = format!("/kubepods.slice/kubepods-burstable.slice/{pod}");
        let pod_fs = "/kubepods/burstable/pod1f2e3d4c-5b6a-7980-a1b2-c3d4e5f60718";
        for (path, workload) in [
            // Podman, rootful and rootless (systemd driver), and its cgroupfs driver.
            (
                format!("/machine.slice/libpod-{a}.scope/container"),
                format!("/machine.slice/libpod-{a}.scope"),
            ),
            (
                format!("{user}/libpod-{a}.scope/container"),
                format!("{user}/libpod-{a}.scope"),
            ),
            (
                format!("{user}/libpod-conmon-{a}.scope"),
                format!("{user}/libpod-{a}.scope"),
            ),
            (
                format!("/libpod_parent/libpod-{a}"),
                format!("/libpod_parent/libpod-{a}"),
            ),
            // Docker, rootful and rootless (systemd driver), and its cgroupfs driver.
            (
                format!("/system.slice/docker-{a}.scope"),
                format!("/system.slice/docker-{a}.scope"),
            ),
            (
                format!("{user}/docker-{a}.scope"),
                format!("{user}/docker-{a}.scope"),
            ),
            (format!("/docker/{a}"), format!("/docker/{a}")),
            // CRI: containerd and CRI-O (and CRI-O's conmon) in a pod.
            (
                format!("{kube}/cri-containerd-{a}.scope"),
                format!("{kube}/cri-containerd-{a}.scope"),
            ),
            (
                format!("{kube}/crio-{a}.scope"),
                format!("{kube}/crio-{a}.scope"),
            ),
            (
                format!("{kube}/crio-conmon-{a}.scope"),
                format!("{kube}/crio-{a}.scope"),
            ),
            // Kubernetes' cgroupfs driver: the container below its pod, or the pod.
            (format!("{pod_fs}/{a}"), format!("{pod_fs}/{a}")),
            (format!("{pod_fs}/crio-{a}"), format!("{pod_fs}/crio-{a}")),
            (pod_fs.to_string(), pod_fs.to_string()),
            // A systemd running in a container: its units are the container's.
            (
                format!("/system.slice/docker-{a}.scope/system.slice/cron.service"),
                format!("/system.slice/docker-{a}.scope"),
            ),
            (
                format!("{user}/libpod-{a}.scope/container/system.slice/sshd.service"),
                format!("{user}/libpod-{a}.scope"),
            ),
            // A container in a container: the inner one.
            (
                format!("/system.slice/docker-{a}.scope/docker/{b}"),
                format!("/system.slice/docker-{a}.scope/docker/{b}"),
            ),
        ] {
            let w = workload_of_cgroup(&path);
            assert_eq!(w.path, workload, "{path}");
            assert!(w.container, "{path}");
        }
        assert_ne!(
            workload_of_cgroup(&format!("{user}/libpod-{a}.scope/container")),
            workload_of_cgroup(&format!("{user}/libpod-{b}.scope/container")),
            "two containers of one user are two workloads"
        );
    }

    /// External audit POS-005: on a v1 or hybrid host the most specific of
    /// the unified line, systemd's and the cpu/memory/pids controllers'
    /// places the process: a container first, then the deepest path, the
    /// unified line and then systemd's on a tie. Other controllers are not
    /// read; the agent's containment slice counts only when nothing else
    /// places the process.
    #[test]
    fn a_v1_host_is_placed_by_its_most_specific_hierarchy() {
        let (a, _) = ids();
        let v1_container = format!(
            "12:devices:/system.slice\n11:memory:/docker/{a}\n4:cpu,cpuacct:/docker/{a}\n\
             1:name=systemd:/user.slice/user-1000.slice/session-3.scope\n"
        );
        for (text, path) in [
            (v1_container.clone(), format!("/docker/{a}")),
            (
                "9:memory:/\n4:cpu,cpuacct:/system.slice\n1:name=systemd:/system.slice/cron.service\n"
                    .to_string(),
                "/system.slice/cron.service".to_string(),
            ),
            (
                "6:pids:/batch/nightly/job-7\n1:name=systemd:/system.slice/cron.service\n".to_string(),
                "/batch/nightly/job-7".to_string(),
            ),
            (
                "5:memory:/user.slice/user-1000.slice\n\
                 1:name=systemd:/user.slice/user-1000.slice/session-3.scope\n\
                 0::/user.slice/user-1000.slice/session-3.scope\n"
                    .to_string(),
                "/user.slice/user-1000.slice/session-3.scope".to_string(),
            ),
            (
                format!("3:freezer:/docker/{a}\n1:name=systemd:/system.slice/ssh.service\n"),
                "/system.slice/ssh.service".to_string(),
            ),
            (
                "1:name=systemd:/system.slice/nginx.service\n0::/northnarrow.slice/blocked.scope\n"
                    .to_string(),
                "/system.slice/nginx.service".to_string(),
            ),
            (
                "0::/northnarrow.slice/blocked.scope\n".to_string(),
                "/northnarrow.slice/blocked.scope".to_string(),
            ),
        ] {
            assert_eq!(placing_cgroup(&text), Some(path.as_str()), "{text}");
        }
        assert_eq!(placing_cgroup("3:freezer:/x\n"), None);
        assert_eq!(placing_cgroup(""), None);

        let tmp = TempDir::new().unwrap();
        let pid_dir = tmp.path().join("800");
        fs::create_dir_all(&pid_dir).unwrap();
        fs::write(pid_dir.join("cgroup"), &v1_container).unwrap();
        let t = AuthSessionTracker::new(tmp.path());
        assert_eq!(
            t.session_workload(800),
            Some(Workload {
                path: format!("/docker/{a}"),
                container: true
            })
        );
    }

    /// External audit POS-005: a running process answers for itself; an
    /// exited one through its nearest running ancestor (it started in its
    /// parent's cgroup); nothing running to read leaves it unplaced. A v1
    /// host's `name=systemd` hierarchy is read when there is no unified one.
    #[test]
    fn the_workload_is_read_from_the_nearest_running_process() {
        let tmp = TempDir::new().unwrap();
        write_cgroup(tmp.path(), 300, "/system.slice/salt-minion.service");
        let t = AuthSessionTracker::new(tmp.path());
        t.ingest_spawn(300, 1, "/usr/bin/python3", 1);
        t.ingest_spawn(301, 300, "/usr/bin/sh", 2); // exited
        t.ingest_spawn(400, 1, "/usr/bin/sh", 3); // exited, parent init
        assert_eq!(
            workload_path(&t, 300).as_deref(),
            Some("/system.slice/salt-minion.service")
        );
        assert_eq!(
            workload_path(&t, 301).as_deref(),
            Some("/system.slice/salt-minion.service")
        );
        assert_eq!(t.session_workload(400), None);
        assert_eq!(t.session_workload(999), None, "never seen");

        let pid_dir = tmp.path().join("500");
        fs::create_dir_all(&pid_dir).unwrap();
        fs::write(
            pid_dir.join("cgroup"),
            "12:pids:/system.slice/cron.service\n1:name=systemd:/system.slice/cron.service\n",
        )
        .unwrap();
        assert_eq!(
            workload_path(&t, 500).as_deref(),
            Some("/system.slice/cron.service")
        );
    }

    /// External audit POS-005: the agent's containment cgroups hold
    /// processes of unrelated workloads; a process there is placed by its
    /// nearest running ancestor outside them, or not at all.
    #[test]
    fn a_contained_process_is_placed_by_its_parent() {
        let tmp = TempDir::new().unwrap();
        write_cgroup(tmp.path(), 600, "/system.slice/nginx.service");
        write_cgroup(tmp.path(), 601, "/northnarrow.slice/blocked.scope");
        write_cgroup(
            tmp.path(),
            602,
            "/northnarrow.slice/blocked.scope/neutralize-77-1",
        );
        write_cgroup(tmp.path(), 700, "/northnarrow.slice/throttled.scope");
        write_status(tmp.path(), 602, 601);
        let t = AuthSessionTracker::new(tmp.path());
        t.ingest_spawn(600, 1, "/usr/sbin/nginx", 1);
        t.ingest_spawn(601, 600, "/usr/bin/sh", 2);
        t.ingest_spawn(700, 1, "/usr/bin/sh", 3);
        for pid in [601, 602] {
            assert_eq!(
                workload_path(&t, pid).as_deref(),
                Some("/system.slice/nginx.service"),
                "{pid}"
            );
        }
        assert_eq!(t.session_workload(700), None, "no ancestor outside it");
        assert!(!in_agent_containment("/northnarrow.slice-other/x.scope"));
    }
}
