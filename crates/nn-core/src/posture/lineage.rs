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
pub use super::script_args::Runs;
use super::script_args::{family_of, runs_of};

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
    "/usr/bin/su-rs",
    "/usr/bin/sudo",
    "/usr/bin/sudo-rs",
    "/usr/bin/sudoedit",
    "/usr/bin/systemd-run",
    "/usr/bin/unix_chkpwd",
    "/usr/lib/cargo/bin/su",
    "/usr/lib/cargo/bin/sudo",
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
    "/usr/bin/su-rs",
    "/usr/bin/sudo",
    "/usr/bin/sudo-rs",
    "/usr/bin/sudoedit",
    "/usr/lib/cargo/bin/su",
    "/usr/lib/cargo/bin/sudo",
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
/// sole basis for the exemption. The review of #552 (F2): and only in a
/// root-owned system tree ([`AuthSessionTracker::names_npm_cli`]).
const NPM_CLI_SUFFIX: &str = "/npm/bin/npm-cli.js";

/// Lot 340: the links to npm's CLI a package installs in a root-owned
/// system tree — the path a shell runs `npm` by, which the kernel hands
/// node as `argv[1]` ([`js_pm_of`]): the Debian and Ubuntu `npm` package's
/// and NodeSource's `/usr/bin/npm` (`/bin/npm` with a merged `/usr`), an
/// upstream archive's `/usr/local/bin/npm`.
const NPM_CLI_LINKS: &[&str] = &["/usr/bin/npm", "/bin/npm", "/usr/local/bin/npm"];

/// Lot 346 (the alpha's false positives, round 2): the JavaScript package
/// managers whose own writes the mass-write arm leaves out
/// ([`AuthSessionTracker::js_pm_own_write`]).
///
/// The review of #555 (F2): npm alone. Yarn, pnpm and bun load the
/// project's code in their own process by design — pnpm a `.pnpmfile.cjs`,
/// yarn berry the `plugins:` of a `.yarnrc.yml`, corepack a downloaded
/// yarn or pnpm — and the arm judges the file that crossed its threshold
/// (the kernel reports a window's crossing once): that code puts its
/// crossings in `node_modules` and rewrites the user's documents beside
/// them. They are judged as any writer, as before lot 346.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum JsPm {
    Npm,
}

impl JsPm {
    /// The exemption's name in the arm's INFO record.
    pub fn exempt_reason(self) -> &'static str {
        match self {
            JsPm::Npm => "npm's CLI in its own directories (node_modules, its cache)",
        }
    }
}

/// Lot 346: the package managers node runs as a script — by its CLI's
/// suffix under `/usr` (a distribution's or an upstream archive's global
/// tree: `/usr/lib/node_modules`, `/usr/share/nodejs`,
/// `/usr/local/lib/node_modules`) or by the link a package installs for it
/// in a root-owned system tree, which the kernel hands node as `argv[1]`:
/// npm ([`NPM_CLI_SUFFIX`], [`NPM_CLI_LINKS`]). The review of #555 (F2):
/// npm alone ([`JsPm`]).
const NODE_PM_CLIS: &[(JsPm, &str, &[&str])] = &[(JsPm::Npm, NPM_CLI_SUFFIX, NPM_CLI_LINKS)];

/// The pid→Entry map's size past which the entries of processes that
/// have exited (and whose [`EXIT_GRACE`] has passed) are dropped, oldest
/// first. Review of #475: the map was a FIFO of this size, so 2,048 execs
/// of other processes pushed out a live daemon's entry (a `clamd` the
/// start's scan entered), and under R-F a judgement of it read "not
/// known" — CANARY-001's reader exemption lost, the daemon killed. A live
/// process's entry is never dropped for this size; the map grows past it
/// up to [`TRACKER_HARD_CAP`].
const TRACKER_CAP: usize = 2048;

/// Review of #475: the most entries the map holds, live processes
/// included. Past it the oldest entry goes whatever its process does —
/// counted ([`AuthSessionTracker::evicted_live`]) and WARNed by the sweep;
/// a host runs far fewer processes that executed something.
const TRACKER_HARD_CAP: usize = 32_768;

/// Review of #475: how long the entry of a process the sweep found gone
/// is kept before it may be dropped — its last events, still on the bus
/// or being judged, are judged on it.
const EXIT_GRACE: std::time::Duration = std::time::Duration::from_secs(30);

/// The map's bounds ([`TRACKER_CAP`], [`TRACKER_HARD_CAP`], [`EXIT_GRACE`]);
/// tests make them small.
#[derive(Debug, Clone, Copy)]
struct Bounds {
    soft: usize,
    hard: usize,
    grace: std::time::Duration,
}

/// Review of #475: what one [`AuthSessionTracker::sweep`] did.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SweepReport {
    /// Cached processes found gone (or their pid naming another process).
    pub gone: usize,
    /// Running processes entered as forks of a cached parent whose image
    /// they still run.
    pub forks: usize,
    /// Third review of #475: running processes entered as the orphans of a
    /// cached process found gone in the sweep (a daemon's child after the
    /// parent exited), whose image they still run.
    pub orphans: usize,
    /// Entries the map holds after it.
    pub entries: usize,
    /// Entries of processes not known to have exited that were dropped at
    /// [`TRACKER_HARD_CAP`] since the start.
    pub evicted_live: u64,
}

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

/// A file's identity as the kernel gives it: its device (`MKDEV`) and inode.
type FileId = (u64, u64);

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
    /// FP-2: this spawn's `argv[1]` is npm's CLI entrypoint
    /// ([`NPM_CLI_SUFFIX`], [`NODE_PM_CLIS`]) — [`js_pm_of`].
    /// Precomputed at ingest so the mass-write exemption is a single cheap
    /// field read AND the variable-length argv is never retained in the
    /// bounded cache. Meaningful only with the exe's gate, applied at read
    /// time in [`AuthSessionTracker::js_pm_writer`].
    js_pm: Option<JsPm>,
    /// Lot 313 (BUG-49's residue): the exec's argv asks an encryption tool
    /// to encrypt ([`crate::posture::script_args::encrypts`]), precomputed
    /// at ingest as [`Self::js_pm`] is (the argv is not kept).
    encrypts: bool,
    /// Lot 340 (the review of #552, F1): the exec's whole argv as a digest
    /// ([`AuthSessionTracker::argv_digest`]: `argv[0]`'s basename, then
    /// every argument), so a rule can ask for one exact invocation
    /// ([`AuthSessionTracker::exec_argv_is`]) with no argv kept in the
    /// bounded cache. `None`: an argv the sensor cut or an empty one, and
    /// every entry no exec of its own gave (a fork, an orphan, the start's
    /// scan) — its argv is not known.
    argv: Option<u64>,
    /// Review 85: what an interpreter `exe` runs ([`runs_of`]): a script
    /// path or a `-m` module; [`Runs::Inline`] for a binary or an inline
    /// program; lot 292: [`Runs::Unknown`] for an argv its table could not
    /// read.
    runs: Runs,
    /// Lot 292 (BUG-56): the start as `/proc/<pid>/stat` showed it, in
    /// clock ticks, when `start_ns` was computed from it (the start's scan,
    /// a fork or an orphan the sweep entered): rounded down to a tick, and
    /// less the time suspended then. `None`: the exec event's exact start.
    start_ticks: Option<u64>,
    /// Lab PR 175: the real uid the process executed `exe` as (the exec
    /// event's, from the kernel's credentials; 0 for the plain ingest
    /// calls of tests and tools).
    uid: u32,
    /// Lot 310: the executed file's device and inode as the exec sensor's
    /// LSM identity gave it — the device in the kernel's form (`MKDEV`, not
    /// `stat(2)`'s `st_dev`: `common::wire::exe::kernel_dev` converts one)
    /// (`None`: tracepoint mode without the pump's read, a process older
    /// than the agent, the plain ingest calls). A fork runs its parent's.
    image: Option<(u64, u64)>,
    /// Lot 340 (the lab of the review of #552): the file the kernel
    /// executed, by the LSM program's identity (the device in the kernel's
    /// form), kept whatever directory it was executed from or mount
    /// namespace it runs in — for [`AuthSessionTracker::ran_host_file`]
    /// only: the same inode as a packaged file now is that file's code, so
    /// a unit's private mount namespace (`ProtectSystem=`, `PrivateTmp=`:
    /// logrotate.service, systemd-networkd), which takes `ROOT_DIR` and the
    /// [`Self::image`] away, still compares. Else [`Self::image`] (the exec
    /// pump's read in tracepoint mode, a seeded process). A fork runs its
    /// parent's.
    exec_file: Option<(u64, u64)>,
    /// Lot 310 (the re-check of #539, N2): the process that forked this
    /// one, when this exec was the first since that fork (the exec record's
    /// `fork_ppid`, the kernel's record at `sched_process_fork`); 0 when not
    /// known — read from `/proc`, a later exec, an older eBPF object.
    fork_parent: u32,
}

/// Lot 340 (the review of #552, F1): one hop of a whole lineage
/// ([`AuthSessionTracker::lineage_hops`]), nearest first.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HopFacts {
    pub pid: u32,
    /// Its parent on the walk (PID 1 or 0 for the last hop).
    pub ppid: u32,
    /// What the kernel executed for it.
    pub id: ExecIdentity,
    /// The real uid its exec recorded (the spawn cache), or it runs as
    /// (`/proc`); `None` not known.
    pub uid: Option<u32>,
    /// The process that forked it when its exec was the first since that
    /// fork — the kernel's record, carried through systemd's executor
    /// ([`AuthSessionTracker::fork_parent`]); 0 not known.
    pub fork_parent: u32,
    /// Its exec was seen (the spawn cache), not read from `/proc`.
    pub cached: bool,
}

/// Review 85: what the kernel executed for a process — its exe and, for
/// an interpreter, the script or module it runs. Read from the spawn
/// cache, else from `/proc`. Never from `comm`, which a process sets for
/// itself.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExecIdentity {
    pub exe: PathBuf,
    /// Lot 292 (BUG-44, BUG-42): what an interpreter runs ([`Runs`]): a
    /// script, nothing named, or not known.
    pub runs: Runs,
}

impl ExecIdentity {
    /// The identity of an exec event's own process: the file the kernel
    /// executed (or the caller's string, normalised, without it) and the
    /// script an interpreter runs, from its argv.
    pub fn of_exec(exe: &str, argv: &[String]) -> Self {
        let path = PathBuf::from(exe);
        let runs = runs_of(&path, argv);
        Self { exe: path, runs }
    }

    /// Lot 310 (the review of #539): the identity of an exec event's own
    /// process ([`Self::of_exec`]) with what the agent's exec pump read of
    /// its process at the exec: an environment that loads the caller's
    /// code before a named script (`PYTHONPATH`, `NODE_OPTIONS`, …: what it
    /// runs is then not known, the script kept for a record), a standard
    /// input that is no terminal for an interpreter naming no program
    /// (`bash < file`: the caller's code, [`Runs::Code`]). `None` for any
    /// other event.
    pub fn of_spawn(event: &Event) -> Option<Self> {
        let Event::ProcessSpawn {
            filename,
            argv,
            exe,
            ..
        } = event
        else {
            return None;
        };
        let mut id = Self::of_exec(exe.path_or(filename), argv);
        id.runs = with_pump_facts(id.runs, &id.exe, argv, exe.flags);
        Some(id)
    }

    /// Lot 292: the identity of a process known by its executable only (no
    /// argv): an interpreter's is not known ([`Runs::Unknown`]).
    pub fn of_exe(exe: impl Into<PathBuf>) -> Self {
        let exe = exe.into();
        let runs = if is_interpreter(&exe) {
            Runs::Unknown(None)
        } else {
            Runs::Inline
        };
        Self { exe, runs }
    }

    /// The script or module it is known to run ([`Runs::script`]).
    pub fn script(&self) -> Option<&str> {
        self.runs.script()
    }

    /// The program, for a record ([`Runs::describe`]).
    pub fn program(&self) -> String {
        self.runs.describe(&self.exe)
    }

    /// External audit NETR-015 (NN-AUD-298): a program root installed. The
    /// executed file lies in a root-owned system tree ([`in_system_tree`])
    /// and, for an interpreter, so does the script it runs, named by an
    /// absolute path: an inline program (`-c`, `-e`), a module (`-m`,
    /// found through the caller's working directory and `PYTHONPATH`), a
    /// relative path or standard input is the caller's, not the tree's;
    /// and an argv whose options could not be read (lot 292) names no
    /// script.
    pub fn is_installed_program(&self) -> bool {
        if !in_system_tree(&self.exe.to_string_lossy()) {
            return false;
        }
        if !self.interprets() {
            return true;
        }
        self.script()
            .is_some_and(|s| s.starts_with('/') && in_system_tree(s))
    }

    /// Lot 310: the identity runs a program its argv names or carries — an
    /// interpreter ([`is_interpreter`]), or a binary of many programs
    /// running one of its shells (busybox as `sh`: [`Runs`] other than
    /// [`Runs::Inline`]). busybox's other programs (`busybox wget`) are the
    /// installed binary they are.
    pub fn interprets(&self) -> bool {
        is_interpreter(&self.exe) || self.runs != Runs::Inline
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
    /// name. Lot 292 (BUG-44): nor is one whose options could not be read
    /// ([`Runs::Unknown`]), even in a client's own tree — what it runs is
    /// not known.
    pub fn is_client(&self, clients: &[&str]) -> bool {
        let exe = self.exe.to_string_lossy();
        if !in_system_tree(&exe) {
            return false;
        }
        if matches!(self.runs, Runs::Unknown(_)) {
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
        match &self.runs {
            Runs::Inline => named(&exe),
            Runs::Script(script) if script.starts_with('/') => {
                in_system_tree(script) && named(script)
            }
            // A module run with `-m` resolves through the working directory
            // and PYTHONPATH, both the caller's: only a client's own runtime
            // tree (above) vouches for it. Lot 310: nor is an inline program
            // a client by the interpreter's name.
            Runs::Script(_) | Runs::Code | Runs::Unknown(_) => false,
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
/// memfd, and not a binary deleted or replaced while it runs. Lot 313
/// (BUG-119's family): and a canonical path — the kernel's, the exec
/// pump's normalisation, `/proc/<pid>/exe` — never one with an empty, `.` or
/// `..` segment: such a string is a caller's (`/usr/bin/./././…` cut at 255
/// bytes named no file under `/usr/bin`), whoever passes it on.
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
        && !path.contains("/./")
        && !path.contains("//")
        && !path.ends_with("/.")
        && !path.ends_with("/..")
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
pub fn placing_cgroup(text: &str) -> Option<&str> {
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
    /// ([`AsOf`]). Dropped with the pid's entry.
    history: HashMap<u32, Vec<Entry>>,
    /// Review of #475: the cached processes the sweep found gone, and when,
    /// in that order — the entries that may be dropped once past
    /// [`TRACKER_CAP`] and their grace.
    exited: HashMap<u32, std::time::Instant>,
    exited_order: VecDeque<u32>,
    /// Entries dropped at [`TRACKER_HARD_CAP`] whose process was not known
    /// to have exited.
    evicted_live: u64,
    /// Third review of #475: per uid, the entries of processes executed
    /// since the start (not the start's scan's), and their insertion order
    /// (pids the map no longer holds as that uid's are skipped, and pruned
    /// with [`Self::order`]) — the hard bound's victims
    /// ([`AuthSessionTracker::hard_victim`]).
    uid_count: HashMap<u32, usize>,
    by_uid: HashMap<u32, VecDeque<u32>>,
    by_uid_len: usize,
    /// Lot 310: the processes the start's scan found running an image
    /// unlinked since (not entered): pid → (its start, the image's
    /// identity), at most [`TRACKER_CAP`]; a later exec of the pid drops it.
    seeded_images: HashMap<u32, (u64, (u64, u64))>,
    /// Lot 340: the kernel's fork records of writers that executed nothing
    /// since their fork ([`AuthSessionTracker::ingest_kernel_fork`]), at most
    /// [`KERNEL_FORKS_CAP`], oldest dropped first.
    kernel_forks: HashMap<u32, KernelFork>,
    kernel_fork_order: VecDeque<u32>,
}

/// Lot 340: a process the kernel recorded forked by `parent` at `start_ns`
/// and seen, at `seen_ns`, still running what it was forked with (no exec
/// since): the open sensor's record of its write carried it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct KernelFork {
    start_ns: u64,
    parent: u32,
    uid: u32,
    seen_ns: u64,
}

/// Lot 340: kernel fork records kept (the writers that never executed: a
/// backup's receivers, workers). Each costs 32 bytes.
const KERNEL_FORKS_CAP: usize = 4096;

/// Lab PR 267 (review #471 A1): earlier execs kept per pid (a wrapper's
/// `exec`, an interpreter re-executing, a `dpkg` run after the event).
const HISTORY_PER_PID: usize = 3;

/// R12b (lab PR 269), R-F of the second review of #471: the time a lineage
/// lookup answers for, and whose lookup it is — passed by the caller, never
/// held by the thread (R12a scoped the judgement with a thread-local, which
/// a lookup made outside the scope silently missed).
///
/// On the priority bus an exec (P1) is taken ahead of the older file and
/// network events of its process, and a tamper event hands the queued execs
/// to the lineage before they are judged (`nn_linux::sensors::bus`): an
/// event is judged on the exec its process had run when it happened, not
/// on a later one (review #471 A1: a reader exemption through a later
/// `execve(restic)`, a package carve-out through a later `dpkg`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AsOf {
    /// Now, outside any judgement (an admin verb, a response, a ladder
    /// step): the cache's latest exec of a pid, `/proc` when it holds none.
    Now,
    /// A record read right after the fact (`CLOCK_MONOTONIC` ns: a pump or a
    /// drain naming a connect's, a flow's process): the exec of then from
    /// the cache, `/proc` when it holds none — the process is still running
    /// its image, as NETR-008's forked child and SNS-014's sender are read.
    Live(u64),
    /// The judgement of an event that happened at this time (its
    /// [`event_time_ns`]): the exec each pid had run by then, from the spawn
    /// cache only. A pid the cache does not hold — an exec dropped, evicted
    /// or not yet read, a process older than the agent that never executed
    /// while it ran — or holds only later execs of, is not known: never
    /// `/proc`, which shows the present image (R-F). A cached exec of a pid
    /// `/proc` shows reused is the pid's at that time only when the process
    /// `/proc` shows started after it (POS-003's check kept).
    Judged(u64),
}

impl AsOf {
    /// The judgement of `event`, as of its [`event_time_ns`]; an event
    /// without a time is judged now ([`AsOf::Now`]: nothing to scope).
    pub fn of_event(event: &Event) -> Self {
        Self::judged(event_time_ns(event))
    }

    /// [`AsOf::Judged`] at `ts_ns`, or [`AsOf::Now`] for 0 (no time).
    pub fn judged(ts_ns: u64) -> Self {
        if ts_ns == 0 {
            AsOf::Now
        } else {
            AsOf::Judged(ts_ns)
        }
    }

    /// [`AsOf::Live`] at `ts_ns`, or [`AsOf::Now`] for 0 (no time).
    pub fn live(ts_ns: u64) -> Self {
        if ts_ns == 0 {
            AsOf::Now
        } else {
            AsOf::Live(ts_ns)
        }
    }

    /// The time it answers for; `None`: now.
    pub fn time(self) -> Option<u64> {
        match self {
            AsOf::Now => None,
            AsOf::Live(t) | AsOf::Judged(t) => (t != 0).then_some(t),
        }
    }

    /// A judgement's: the spawn cache only.
    pub fn is_judged(self) -> bool {
        matches!(self, AsOf::Judged(_))
    }
}

/// The time an event happened, as its judgement sees the lineage
/// ([`AsOf::of_event`]): its
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
        Event::NetFlow(nf) | Event::NetInbound(nf) => nf.start_ns,
        Event::NetListener(nl) => nl.timestamp_ns,
        Event::DnsAnswer(a) => a.timestamp_ns,
        Event::TlsClientHello(h) => h.timestamp_ns,
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
    /// The map's bounds (review of #475).
    bounds: Bounds,
    /// Lab PR 175: the host's `/` for `/etc/passwd`, `/etc/subuid` and the
    /// owners of container storage directories; a fixture tree in tests.
    host_root: PathBuf,
    /// Lot 340 (the review of #552, F1): the key of the argv digests
    /// ([`AuthSessionTracker::argv_digest`]), drawn at random per tracker:
    /// no argv can be chosen to collide with another's.
    argv_key: std::collections::hash_map::RandomState,
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
                    exited: HashMap::new(),
                    exited_order: VecDeque::new(),
                    evicted_live: 0,
                    uid_count: HashMap::new(),
                    by_uid: HashMap::new(),
                    by_uid_len: 0,
                    seeded_images: HashMap::new(),
                    kernel_forks: HashMap::new(),
                    kernel_fork_order: VecDeque::new(),
                }),
                proc_root,
                live,
                observer_start: std::sync::OnceLock::new(),
                #[cfg(test)]
                suspended_ns: None,
                bounds: Bounds {
                    soft: TRACKER_CAP,
                    hard: TRACKER_HARD_CAP,
                    grace: EXIT_GRACE,
                },
                host_root: PathBuf::from(H::HOST_ROOT),
                argv_key: std::collections::hash_map::RandomState::new(),
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

    /// Tests: the map's bounds made small (review of #475).
    #[cfg(test)]
    fn with_bounds(mut self, soft: usize, hard: usize, grace: std::time::Duration) -> Self {
        Arc::get_mut(&mut self.inner)
            .expect("an unshared tracker")
            .bounds = Bounds { soft, hard, grace };
        self
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
        self.ingest_inner(
            pid,
            ppid,
            exe,
            (None, false, None),
            Runs::Inline,
            spawn_ns,
            (0, None),
            0,
            (None, 0, None),
        );
    }

    /// Lot 351 (tests and tools): [`Self::ingest_spawn`] of the first exec
    /// of a process since `ppid` forked it — the kernel's fork record
    /// ([`Entry::fork_parent`]: what [`Self::is_interactive_admin`] wants
    /// of the process sudo or su elevated) — executed as real uid `uid`.
    pub fn ingest_first_exec(&self, pid: u32, ppid: u32, exe: &str, spawn_ns: u64, uid: u32) {
        self.ingest_inner(
            pid,
            ppid,
            exe,
            (None, false, None),
            Runs::Inline,
            spawn_ns,
            (0, None),
            uid,
            (None, ppid, None),
        );
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
            argv_truncated,
            ..
        } = event
        else {
            return false;
        };
        use common::wire::exe::exe_flags::{KNOWN, PROC_EXE, ROOT_DIR};
        // lot 310: the file's identity (the LSM program's, or the exec
        // pump's from `/proc` in tracepoint mode), kept only when no user
        // could have unlinked the image (its directory root's only: the
        // review of #539, finding 5)
        let image = (exe.flags & (KNOWN | PROC_EXE) != 0
            && exe.has(ROOT_DIR)
            && (exe.dev, exe.ino) != (0, 0))
            .then_some((exe.dev, exe.ino));
        // the LSM program's identity of the executed file, whatever its
        // directory or mount namespace ([`Entry::exec_file`])
        let exec_file = (exe.has(KNOWN) && (exe.dev, exe.ino) != (0, 0))
            .then_some((exe.dev, exe.ino))
            .or(image);
        let path = exe.path_or(filename);
        let js_pm = js_pm_of(Path::new(path), argv);
        // lot 313 (BUG-49's residue): an encryption tool asked to encrypt
        let encrypts = crate::posture::script_args::encrypts(Path::new(path), argv);
        // the review of #552 (F1): an argv the sensor cut is not the whole
        let digest = if *argv_truncated {
            None
        } else {
            self.argv_digest(argv)
        };
        let runs = with_pump_facts(
            runs_of(Path::new(path), argv),
            Path::new(path),
            argv,
            exe.flags,
        );
        // the kernel's record (the re-check 4 of #539: carried through a
        // verified systemd-executor in the kernel, at the exec)
        let fork_parent = exe.fork_parent;
        self.ingest_inner(
            *pid,
            *ppid,
            path,
            (js_pm, encrypts, digest),
            runs,
            *timestamp_ns,
            (*start_ns, None),
            *uid,
            (image, fork_parent, exec_file),
        );
        let _ = filename;
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
        let js_pm = js_pm_of(Path::new(exe), argv);
        let encrypts = crate::posture::script_args::encrypts(Path::new(exe), argv);
        let runs = runs_of(Path::new(exe), argv);
        self.ingest_inner(
            pid,
            ppid,
            exe,
            (js_pm, encrypts, self.argv_digest(argv)),
            runs,
            spawn_ns,
            (start_ns, None),
            uid,
            (None, 0, None),
        );
    }

    /// Lot 340 (the alpha's daily false positives): the kernel's fork
    /// record of `pid` — forked by `parent` at `start_ns` (the task's start,
    /// `CLOCK_MONOTONIC`), run by `uid`, seen at `seen_ns` still running what
    /// it was forked with — as the open sensor's record of a write carries
    /// it (`OpenRecordRaw::fork_ppid`, from lot 310's `fork_parent_record`).
    /// A writer that never executes (a backup's receiver: `rsync` forks it)
    /// has no exec record; its lineage was read from `/proc`
    /// ([`Self::fork_entry`]) and lost once it exited, so a burst judged
    /// after its exit was a writer of unknown lineage (lot 310's lab: 4 of 5
    /// unit backups judged). With the record, the walk reads it as its
    /// forker's copy, as of its start, whether it runs still or not. The
    /// pump ingests it before it sends the write's events: no event of the
    /// write is judged without it.
    pub fn ingest_kernel_fork(&self, pid: u32, start_ns: u64, parent: u32, uid: u32, seen_ns: u64) {
        if pid <= 1 || parent == 0 || parent == pid || start_ns == 0 {
            return;
        }
        let rec = KernelFork {
            start_ns,
            parent,
            uid,
            seen_ns,
        };
        let mut s = self.inner.state.write();
        if let Some(k) = s.kernel_forks.get_mut(&pid) {
            if (k.start_ns, k.parent) == (start_ns, parent) {
                k.seen_ns = k.seen_ns.max(seen_ns);
            } else {
                // the pid of an earlier process: this record replaces it
                *k = rec;
            }
            return;
        }
        s.kernel_forks.insert(pid, rec);
        s.kernel_fork_order.push_back(pid);
        while s.kernel_fork_order.len() > KERNEL_FORKS_CAP {
            if let Some(old) = s.kernel_fork_order.pop_front() {
                s.kernel_forks.remove(&old);
            }
        }
    }

    /// Lot 340: [`Self::fork_entry`] from the kernel's fork record of `pid`
    /// ([`Self::ingest_kernel_fork`]) — its forker's exec as of its start
    /// (the image it was forked with), the forker read the same way when it
    /// never executed either — when the record describes the process the
    /// pid named at `at`: started by then, and seen running its fork's image
    /// no earlier than then (later, it may have executed: an exec event
    /// would answer). A forker that executed only after the fork is read
    /// from its own fork record alone. `None` without one, and without a time: the sweep
    /// enters the processes running now from `/proc`, where a pid the
    /// recorded writer left may name another process.
    fn kernel_fork_entry(&self, pid: u32, at: Option<u64>, depth: usize) -> Option<Entry> {
        let t = at?;
        if depth > LINEAGE_DEPTH_CAP {
            return None;
        }
        let k = self.inner.state.read().kernel_forks.get(&pid).copied()?;
        if t < k.start_ns || t > k.seen_ns {
            return None;
        }
        let parent = match self.cached_live(k.parent, Some(k.start_ns)) {
            CachedAt::Current(e) | CachedAt::Past(e) => e,
            CachedAt::Absent => self.fork_entry(k.parent, Some(k.start_ns), depth + 1)?,
            // the forker executed only later: what it ran at the fork is its
            // own fork record's, if the kernel gave one (never `/proc`, which
            // shows the later image)
            CachedAt::LaterOnly => self.kernel_fork_entry(k.parent, Some(k.start_ns), depth + 1)?,
        };
        Some(Entry {
            ppid: k.parent,
            exe: parent.exe,
            spawn_ns: k.start_ns,
            start_ns: k.start_ns,
            // npm's own CLI is the process its exec named, never a fork of it
            js_pm: None,
            // lot 313 (BUG-49's residue): a forked copy runs its forker's
            // exec, an encryption it was asked for included (as `fork_entry`)
            encrypts: parent.encrypts,
            argv: None,
            runs: parent.runs,
            start_ticks: None,
            uid: k.uid,
            image: parent.image,
            exec_file: parent.exec_file,
            fork_parent: k.parent,
        })
    }

    /// Lot 340 (the review of #552, F1): the digest of an exec's whole argv
    /// — `argv[0]`'s basename (what a shell or a unit's `ExecStart=` names
    /// the program by: a path or a bare name), then every argument, each
    /// with its length — keyed by this tracker's random key
    /// ([`Inner::argv_key`]). `None` for an empty argv.
    fn argv_digest<S: AsRef<str>>(&self, argv: &[S]) -> Option<u64> {
        use std::hash::{BuildHasher, Hasher};
        let (first, rest) = argv.split_first()?;
        let first = first.as_ref();
        let base = first.rsplit('/').next().unwrap_or(first);
        let mut h = self.inner.argv_key.build_hasher();
        h.write_usize(argv.len());
        for a in std::iter::once(base).chain(rest.iter().map(AsRef::as_ref)) {
            h.write_usize(a.len());
            h.write(a.as_bytes());
        }
        Some(h.finish())
    }

    /// Review of #475 (R-F): enter every process running now into the
    /// spawn cache, as the agent's start does once its sensors are
    /// attached — each as an exec of the image `/proc` shows it running,
    /// at time 0 (it has run that image since before any exec could be
    /// seen), with its own start (`/proc/<pid>/stat`) and its parent and
    /// real uid (`status`), an interpreter's script from its `cmdline`. A
    /// pid the cache already holds (its exec seen since the attach) is
    /// left alone; a deleted image is not entered. From then on a judgement
    /// never needs `/proc` for a process older than the agent: an exec it
    /// runs later becomes a later entry and the seeded one its past, so
    /// an event before that exec is read is judged on the image it ran.
    /// Returns how many processes it entered.
    pub fn seed_from_proc(&self) -> usize {
        let Ok(dir) = H::read_dir(&self.inner.proc_root) else {
            return 0;
        };
        let tick = H::clock_tick_ns();
        let suspended = self.suspended_ns();
        let mut seeded = 0;
        for entry in dir.flatten() {
            let Some(pid) = entry
                .file_name()
                .to_str()
                .and_then(|n| n.parse::<u32>().ok())
            else {
                continue;
            };
            if pid == 0 || self.holds(pid) {
                continue;
            }
            // lot 310 (the review of #539, finding 5): the image a process
            // older than the agent runs, by its identity, when no user could
            // have unlinked it — kept even for an image unlinked since (an
            // upgraded browser re-executing itself), which is not entered
            let image = self.seed_image(pid);
            let Some((ppid, exe, uid)) = self.lookup_proc(pid) else {
                if let (Some(image), Some(ticks)) = (image, self.proc_start_ticks(pid)) {
                    let start_ns = ticks.saturating_mul(tick).saturating_sub(suspended).max(1);
                    let mut s = self.inner.state.write();
                    if s.seeded_images.len() < TRACKER_CAP {
                        s.seeded_images.insert(pid, (start_ns, image));
                    }
                }
                continue;
            };
            let Some(ticks) = self.proc_start_ticks(pid) else {
                continue;
            };
            let start_ns = ticks.saturating_mul(tick).saturating_sub(suspended).max(1);
            let runs = self.proc_runs(pid, &exe);
            let exe = exe.to_string_lossy().into_owned();
            // the pid may have been entered by an exec since the check
            if self.holds(pid) {
                continue;
            }
            self.ingest_inner(
                pid,
                ppid,
                &exe,
                (None, false, None),
                runs,
                0,
                (start_ns, Some(ticks)),
                uid.unwrap_or(0),
                (image, 0, image),
            );
            seeded += 1;
        }
        seeded
    }

    /// Lot 310: the identity of the image `pid` runs (`/proc/<pid>/exe`,
    /// the device in the kernel's form), when the directory it was executed
    /// from is root's only ([`PostureHost::dir_is_root_only`]); at the
    /// start's scan, off the decision path.
    fn seed_image(&self, pid: u32) -> Option<(u64, u64)> {
        let view = self.image_dir_view(pid)?;
        if !H::dir_is_root_only(&view) {
            return None;
        }
        let link = self.inner.proc_root.join(pid.to_string()).join("exe");
        let (dev, ino) = H::file_id(&link)?;
        Some((common::wire::exe::kernel_dev(dev), ino))
    }

    /// The directory `pid`'s image was executed from, in the process's own
    /// view of the files (`/proc/<pid>/root/…`, as the exec pump reads it),
    /// when the process runs in PID 1's mount namespace (the re-check of
    /// #539, N6: a user's namespace binds a root directory over its own);
    /// `None` otherwise, or when either namespace cannot be read.
    fn image_dir_view(&self, pid: u32) -> Option<PathBuf> {
        let dir = self.inner.proc_root.join(pid.to_string());
        let text = H::read_link(dir.join("exe")).ok()?;
        let text = text.to_string_lossy();
        let path = Path::new(text.strip_suffix(" (deleted)").unwrap_or(&text));
        let ns = |d: &Path| H::read_link(d.join("ns/mnt")).ok();
        let init = ns(&self.inner.proc_root.join("1"))?;
        if ns(&dir)? != init {
            return None;
        }
        let view = dir.join("root").join(path.strip_prefix("/").ok()?);
        view.parent().map(Path::to_path_buf)
    }

    /// The spawn cache holds an exec of `pid`.
    fn holds(&self, pid: u32) -> bool {
        let s = self.inner.state.read();
        s.map.contains_key(&pid) || s.daemons.contains_key(&pid)
    }

    #[allow(clippy::too_many_arguments)]
    fn ingest_inner(
        &self,
        pid: u32,
        ppid: u32,
        exe: &str,
        (js_pm, encrypts, argv): (Option<JsPm>, bool, Option<u64>),
        runs: Runs,
        spawn_ns: u64,
        (start_ns, start_ticks): (u64, Option<u64>),
        uid: u32,
        (image, fork_parent, exec_file): (Option<FileId>, u32, Option<FileId>),
    ) {
        if pid == 0 {
            return;
        }
        let entry = Entry {
            ppid,
            exe: PathBuf::from(exe),
            spawn_ns,
            start_ns: if start_ns != 0 { start_ns } else { spawn_ns },
            js_pm,
            encrypts,
            argv,
            runs,
            start_ticks,
            uid,
            image,
            exec_file,
            fork_parent,
        };
        let mut s = self.inner.state.write();
        // Lab PR 267 (R12a): an exec the cache already holds (its time and
        // its process's start) changes nothing — the first ingest of an
        // exec stays. The priority bus ingests an exec when an event of a
        // higher class overtakes it ([`Self::ingest_spawn_event`]), and
        // again when the exec itself is judged. Review #471 A1: one older
        // than the exec held for the pid goes into the pid's history, at its
        // place, and the newer one stays current; the exec a newer one
        // replaces goes into the history too ([`AsOf`]).
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
        // review of #475: an exec of the pid — a process that runs (its
        // old entry, if the sweep had found it gone, is history now)
        s.exited.remove(&pid);
        // lot 310: the start's record of an unlinked image is that process's
        s.seeded_images.remove(&pid);
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
        let (uid, evictable) = (entry.uid, entry.spawn_ns != 0);
        let prev = s.map.insert(pid, entry);
        if let Some(p) = &prev {
            Self::count_out(&mut s, p);
        }
        if evictable {
            *s.uid_count.entry(uid).or_default() += 1;
            if prev
                .as_ref()
                .is_none_or(|p| p.spawn_ns == 0 || p.uid != uid)
            {
                s.by_uid.entry(uid).or_default().push_back(pid);
                s.by_uid_len += 1;
            }
        }
        if prev.is_none() {
            s.order.push_back(pid);
            self.make_room(&mut s);
        }
    }

    /// Third review of #475: an entry leaves the map — its uid's count of
    /// entries executed since the start ([`InnerState::uid_count`]).
    fn count_out(s: &mut InnerState, e: &Entry) {
        if e.spawn_ns == 0 {
            return;
        }
        if let Some(c) = s.uid_count.get_mut(&e.uid) {
            *c = c.saturating_sub(1);
            if *c == 0 {
                s.uid_count.remove(&e.uid);
            }
        }
    }

    /// Third review of #475: the entry the hard bound drops. A gone
    /// process's first, whatever its grace; else the oldest entry of the
    /// uid holding the most among the processes executed since the start,
    /// whatever the uid's class (the final check of #475: a flood as
    /// `www-data` pushes out its own entries, not a person's session) — a
    /// flood of one account's live processes pushes out that account's
    /// own; the processes the start's scan entered (the boot's daemons, an
    /// older session) last.
    fn hard_victim(s: &mut InnerState) -> Option<u32> {
        while let Some(p) = s.exited_order.pop_front() {
            if s.exited.contains_key(&p) && s.map.contains_key(&p) {
                return Some(p);
            }
        }
        while let Some(uid) = s
            .uid_count
            .iter()
            .max_by_key(|(u, c)| (**c, std::cmp::Reverse(**u)))
            .map(|(u, _)| *u)
        {
            let mut found = None;
            if let Some(q) = s.by_uid.get_mut(&uid) {
                while let Some(p) = q.pop_front() {
                    s.by_uid_len = s.by_uid_len.saturating_sub(1);
                    if s.map
                        .get(&p)
                        .is_some_and(|e| e.spawn_ns != 0 && e.uid == uid)
                    {
                        found = Some(p);
                        break;
                    }
                }
            }
            if found.is_some() {
                return found;
            }
            // a count without an entry in order (not expected): dropped
            s.uid_count.remove(&uid);
        }
        while let Some(p) = s.order.pop_front() {
            if s.map.contains_key(&p) {
                return Some(p);
            }
        }
        None
    }

    /// Review of #475: past [`TRACKER_CAP`], drop the entries of processes
    /// the sweep found gone, the longest gone first, once past their grace;
    /// a live process's entry stays. Past [`TRACKER_HARD_CAP`] the oldest
    /// entry goes whatever its process does, counted.
    fn make_room(&self, s: &mut InnerState) {
        let b = self.inner.bounds;
        while s.map.len() > b.soft {
            let Some(&front) = s.exited_order.front() else {
                break;
            };
            match s.exited.get(&front) {
                // gone, and past its grace: dropped
                Some(at) if at.elapsed() >= b.grace => {
                    s.exited_order.pop_front();
                    s.exited.remove(&front);
                    if let Some(e) = s.map.remove(&front) {
                        Self::count_out(s, &e);
                    }
                    s.history.remove(&front);
                }
                // the oldest gone is still in its grace: so are the rest
                Some(_) => break,
                // a mark an exec of the pid since cleared
                None => {
                    s.exited_order.pop_front();
                }
            }
        }
        while s.map.len() > b.hard {
            let Some(evict) = Self::hard_victim(s) else {
                break;
            };
            if let Some(e) = s.map.remove(&evict) {
                Self::count_out(s, &e);
                s.history.remove(&evict);
                if s.exited.remove(&evict).is_none() {
                    s.evicted_live += 1;
                }
            }
        }
        // the insertion orders keep no pid the map dropped for long
        if s.order.len() > 2 * s.map.len() + 1024 {
            let map = &s.map;
            s.order.retain(|p| map.contains_key(p));
        }
        if s.by_uid_len > 2 * s.map.len() + 1024 {
            let map = &s.map;
            let mut len = 0;
            for (uid, q) in s.by_uid.iter_mut() {
                q.retain(|p| map.get(p).is_some_and(|e| e.spawn_ns != 0 && e.uid == *uid));
                len += q.len();
            }
            s.by_uid.retain(|_, q| !q.is_empty());
            s.by_uid_len = len;
        }
    }

    /// Review of #475: the entries of processes not known to have exited
    /// that [`TRACKER_HARD_CAP`] dropped since the start (the agent's sweep
    /// raises the posture's `TelemetryLoss` when it grows: their events are
    /// judged "not known").
    pub fn evicted_live(&self) -> u64 {
        self.inner.state.read().evicted_live
    }

    /// Review of #475, off the decision thread (a task of the agent's,
    /// every few seconds): every cached process is checked against `/proc`
    /// — gone, or its pid now naming another process (its start), it is
    /// marked: its entry may be dropped once the map is past
    /// [`TRACKER_CAP`] and its [`EXIT_GRACE`] has passed. And every running
    /// process the cache does not hold that is a fork of a cached process
    /// still running the image that process ran when it forked
    /// ([`Self::fork_entry`]: its parent and start from `/proc/<pid>/stat`,
    /// which no exec changes, and `/proc/<pid>/exe` the same file) is
    /// entered as that image since its start — a prefork worker, a
    /// subshell, a daemon's child after its parent exited. A process that
    /// executed something else is never entered here (its exec event is).
    ///
    /// Third review of #475: a pid the sweep found naming another process
    /// than its entry's (reused by a fork) is tried the same way; and a
    /// running process reparented when its parent exited, which runs the
    /// image of a process this sweep found gone, is entered as that
    /// process's orphan ([`Self::orphan_entry`]: `Type=forking`, `daemon()`).
    pub fn sweep(&self) -> SweepReport {
        let cached: Vec<(u32, u64)> = {
            let s = self.inner.state.read();
            s.map
                .iter()
                .filter(|(pid, _)| !s.exited.contains_key(pid))
                .map(|(pid, e)| (*pid, e.start_ns))
                .collect()
        };
        let mut gone = Vec::new();
        for (pid, start) in cached {
            match self.proc_start_ticks(pid) {
                None => gone.push(pid),
                Some(ticks) if start != 0 && !self.ticks_show_start(ticks, start) => gone.push(pid),
                Some(_) => {}
            }
        }
        let now = std::time::Instant::now();
        // third review of #475: the gone processes' images, for their orphans
        let mut gone_by_exe: HashMap<PathBuf, Vec<Entry>> = HashMap::new();
        {
            let mut s = self.inner.state.write();
            for pid in &gone {
                if let Some(e) = s.map.get(pid) {
                    gone_by_exe
                        .entry(e.exe.clone())
                        .or_default()
                        .push(e.clone());
                }
                if s.map.contains_key(pid) && s.exited.insert(*pid, now).is_none() {
                    s.exited_order.push_back(*pid);
                }
            }
            self.make_room(&mut s);
        }
        let (mut forks, mut orphans) = (0, 0);
        if let Ok(dir) = H::read_dir(&self.inner.proc_root) {
            for entry in dir.flatten() {
                let Some(pid) = entry
                    .file_name()
                    .to_str()
                    .and_then(|n| n.parse::<u32>().ok())
                else {
                    continue;
                };
                // a pid whose entry the sweep marked gone names another
                // process now (third review of #475: a pid reused by a fork)
                if pid == 0 || self.holds_unmarked(pid) {
                    continue;
                }
                let (e, orphan) = match self.fork_entry(pid, None, 0) {
                    Some(e) => (e, false),
                    None => match self.orphan_entry(pid, &gone_by_exe) {
                        Some(e) => (e, true),
                        None => continue,
                    },
                };
                if self.holds_unmarked(pid) {
                    continue;
                }
                self.ingest_inner(
                    pid,
                    e.ppid,
                    &e.exe.to_string_lossy(),
                    (e.js_pm, e.encrypts, e.argv),
                    e.runs,
                    e.spawn_ns,
                    (e.start_ns, e.start_ticks),
                    e.uid,
                    (e.image, e.fork_parent, e.exec_file),
                );
                if orphan {
                    orphans += 1;
                } else {
                    forks += 1;
                }
            }
        }
        let s = self.inner.state.read();
        SweepReport {
            gone: gone.len(),
            forks,
            orphans,
            entries: s.map.len(),
            evicted_live: s.evicted_live,
        }
    }

    /// The cache holds an exec of `pid` the sweep has not found gone.
    fn holds_unmarked(&self, pid: u32) -> bool {
        let s = self.inner.state.read();
        (s.map.contains_key(&pid) && !s.exited.contains_key(&pid)) || s.daemons.contains_key(&pid)
    }

    /// Third review of #475 (X1): `pid`, which the cache does not hold and
    /// whose parent does not run its image, as the orphan of a process the
    /// sweep found gone (`gone`, by image): a `Type=forking` unit's daemon,
    /// a `daemon()` child, whose parent executed the image, forked and
    /// exited before any sweep — reparented to pid 1, or to a subreaper
    /// among that process's ancestors; started no earlier than that
    /// process's exec; and running that very file (`/proc/<pid>/exe`). Every
    /// gone process of the image it could descend from must have run the
    /// same script (an interpreter's), else not known. Its parent stays the
    /// one `/proc` shows (a walk from it learns nothing of the gone
    /// process's session); its uid is its own. It runs that image from the
    /// sweep's instant only (the final check of #475): what it did before
    /// is not known.
    fn orphan_entry(&self, pid: u32, gone: &HashMap<PathBuf, Vec<Entry>>) -> Option<Entry> {
        if gone.is_empty() || pid <= 1 {
            return None;
        }
        let (ppid, ticks) = self.proc_parent_and_start(pid)?;
        let exe = H::read_link(self.inner.proc_root.join(pid.to_string()).join("exe")).ok()?;
        let tick = H::clock_tick_ns();
        // the boot clock's start is the latest the monotonic one can be
        let latest = ticks.saturating_mul(tick) + 2 * tick;
        let could: Vec<&Entry> = gone
            .get(&exe)?
            .iter()
            .filter(|e| e.spawn_ns <= latest && e.start_ns <= latest)
            .collect();
        let first = *could.first()?;
        if could
            .iter()
            .any(|e| e.runs != first.runs || e.js_pm != first.js_pm || e.encrypts != first.encrypts)
        {
            return None;
        }
        if ppid != 1 && !could.iter().any(|e| self.is_cached_ancestor(ppid, e.ppid)) {
            return None;
        }
        let uid = H::read_state(self.inner.proc_root.join(pid.to_string()).join("status"))
            .ok()
            .and_then(|t| parse_real_uid(&t))
            .unwrap_or(first.uid);
        // the pid still names the process whose start was read
        if self.proc_parent_and_start(pid)? != (ppid, ticks) {
            return None;
        }
        let start_ns = ticks
            .saturating_mul(tick)
            .saturating_sub(self.suspended_ns())
            .max(1);
        Some(Entry {
            ppid,
            exe,
            // final check of #475 (RRd2): an inference about the present —
            // `/proc` shows that image now —, so it counts from the sweep's
            // instant, not from the process's start: an exec of that image
            // still queued at the sweep (the candidate's image an attacker
            // ran and let exit) never covers the events before it
            spawn_ns: H::monotonic_ns().max(start_ns),
            start_ns,
            js_pm: first.js_pm,
            encrypts: first.encrypts,
            // the review of #552 (F1): its own argv is not known
            argv: None,
            runs: first.runs.clone(),
            start_ticks: Some(ticks),
            uid,
            image: first.image,
            exec_file: first.exec_file,
            // no exec of its own: no fork parent recorded for one
            fork_parent: 0,
        })
    }

    /// `ancestor` is `from` or one of its parents, as the cache holds them
    /// (at most [`LINEAGE_DEPTH_CAP`] up).
    fn is_cached_ancestor(&self, ancestor: u32, from: u32) -> bool {
        let s = self.inner.state.read();
        let mut cur = from;
        for _ in 0..LINEAGE_DEPTH_CAP {
            if cur == ancestor {
                return true;
            }
            match s.map.get(&cur).or_else(|| s.daemons.get(&cur)) {
                Some(e) if e.ppid != cur && e.ppid != 0 => cur = e.ppid,
                _ => return false,
            }
        }
        false
    }

    /// Review of #475: `pid`, which the cache does not hold, as a fork of
    /// its parent — its parent and start from `/proc/<pid>/stat` (an exec
    /// changes neither), its parent's image as of that start (cached, or
    /// itself such a fork, at most [`LINEAGE_DEPTH_CAP`] up), accepted only
    /// when `/proc/<pid>/exe` is that very file (a different one, or a
    /// deleted one: it executed something since, not known). `at`: the
    /// event's time — a process that started after it is not the one the
    /// pid named then. Never the image `/proc` shows instead of the
    /// parent's: an exec the cache has not read leaves the pid not known.
    ///
    /// Lot 278: the parent's image is read at the fork's earliest time; the
    /// exec the parent made up to the fork's tick answers only for the
    /// monitor of an authentication binary (sudo, su, doas, pkexec, …:
    /// [`AUTH_BINARY_EXES`]) forked in the tick of that binary's exec — the
    /// one case the upper bound exists for (the lab's R009 flake). Any other
    /// identity found only later is not known (the reviews of #493).
    fn fork_entry(&self, pid: u32, at: Option<u64>, depth: usize) -> Option<Entry> {
        if pid <= 1 || depth > LINEAGE_DEPTH_CAP {
            return None;
        }
        // lot 340: the kernel's record of the fork first — it holds once
        // the process has exited, `/proc` does not
        if let Some(e) = self.kernel_fork_entry(pid, at, depth) {
            return Some(e);
        }
        let (ppid, ticks) = self.proc_parent_and_start(pid)?;
        if ppid == 0 || ppid == pid {
            return None;
        }
        let tick = H::clock_tick_ns();
        let start_ns = ticks
            .saturating_mul(tick)
            .saturating_sub(self.suspended_ns())
            .max(1);
        if at.is_some_and(|t| start_ns.saturating_sub(2 * tick) > t) {
            return None;
        }
        // The parent's image at the fork's earliest time (`start_ns`). Lot
        // 278: `/proc` rounds the start down to a tick and `start_ns` takes
        // all the time suspended off it, so a fork in the tick of its
        // parent's exec (sudo and its monitor) shows a start before that
        // exec: the parent's image there is "only later" and the lineage
        // was lost. Then, and only then, the parent's exec up to the latest
        // time the fork can have happened (`forked_by`, the boot clock's
        // start and the two ticks of rounding) answers — the exec of the
        // file the fork runs (lot 350: a parent can take two images in that
        // window, a shell's `-c` executed into sudo in place; it was the only
        // identity the parent took in between, review of #493, B1: a parent
        // that forks and then executes another script of the same
        // interpreter must not lend the fork that script — no interpreter's
        // identity is lent at all, below), and only an identity its
        // executable alone decides (second review of #493: a script, an npm entrypoint, an
        // interpreter's inline program come from an argv the process
        // writes, and a fork of a fork that never executed — G runs
        // `python3 evil.py`, its fork forks the child, then executes
        // `python3 /usr/bin/borg` — would pass for borg; for an
        // interpreter's identity the later exec is never used).
        // `/proc/<pid>/exe` must still be that executable (below, its start
        // read again): a fork made after the exec runs it; one made before
        // runs the earlier image, the same file or no answer.
        let forked_by = ticks.saturating_add(2).saturating_mul(tick);
        let exe = H::read_link(self.inner.proc_root.join(pid.to_string()).join("exe")).ok()?;
        let parent = match self.cached_live(ppid, Some(start_ns)) {
            CachedAt::Current(e) | CachedAt::Past(e) if e.exe == exe => e,
            // Lot 350 (F2-2: R009 High for an administrator's `sudo
            // ./deploy/uninstall.sh` at a terminal, 3 times in 7): the parent
            // ran another image at the fork's earliest time and executed, in
            // the fork's tick, the authentication binary the fork runs — a
            // shell's `-c` line executed into sudo in place (`bash -c 'cd … &&
            // sudo …'`, `script -c 'sudo …'`, `env sudo`). The lookup at the
            // earliest time found the shell, the monitor runs sudo, and the
            // session was lost whenever sudo's exec and its fork of the
            // monitor fell in one clock tick. Read as of lot 278's case: the
            // parent's exec of that very file within the fork's window, an
            // authentication binary's, whose executable alone decides.
            // Lot 278: no image at the earliest time. In both cases, third
            // review of #493: only an authentication binary's monitor — a
            // child forked before its parent's exec that executed the same
            // file itself (restic, clamscan: canary readers) before that exec
            // reached the cache would take the identity, and nothing tells
            // the two apart. Lot 350: of the parent's execs in the window,
            // those of the file the fork runs (the shell's and sudo's are two
            // images).
            CachedAt::Current(_) | CachedAt::Past(_) | CachedAt::LaterOnly => {
                let e = self.only_identity_between(ppid, start_ns, forked_by, &exe)?;
                if !is_auth_monitor_identity(&e) {
                    return None;
                }
                e
            }
            CachedAt::Absent => self.fork_entry(ppid, Some(start_ns), depth + 1)?,
        };
        if exe != parent.exe {
            return None;
        }
        let uid = H::read_state(self.inner.proc_root.join(pid.to_string()).join("status"))
            .ok()
            .and_then(|t| parse_real_uid(&t))
            .unwrap_or(parent.uid);
        // third review of #475: the pid still names the process whose start
        // was read (a reuse between the reads would mix two processes)
        if self.proc_parent_and_start(pid)? != (ppid, ticks) {
            return None;
        }
        Some(Entry {
            ppid,
            exe: parent.exe,
            spawn_ns: start_ns,
            start_ns,
            js_pm: parent.js_pm,
            encrypts: parent.encrypts,
            // the review of #552 (F1): an exec's argv is its own process's
            argv: None,
            runs: parent.runs,
            start_ticks: Some(ticks),
            uid,
            image: parent.image,
            exec_file: parent.exec_file,
            fork_parent: 0,
        })
    }

    /// Lot 278 (review of #493, B1): the exec `pid` ran in `(after, by]`
    /// when every exec the cache holds of it in that span is one identity —
    /// the same executable, script and npm entrypoint — of a process
    /// started by `by`; `None` when there is none, or more than one. Lot 350
    /// (F2-2): of the execs of the file `exe` only — what `/proc` shows the
    /// fork running: a fork made in the span before the parent executed that
    /// file runs the earlier image, which `/proc` shows instead (a shell's
    /// `-c` line executed into sudo in place is two images in one tick).
    fn only_identity_between(&self, pid: u32, after: u64, by: u64, exe: &Path) -> Option<Entry> {
        let s = self.inner.state.read();
        let cur = s.map.get(&pid).or_else(|| s.daemons.get(&pid));
        let past = s.history.get(&pid).into_iter().flatten();
        let mut found: Option<&Entry> = None;
        for e in past.chain(cur) {
            if e.spawn_ns <= after || e.spawn_ns > by || e.start_ns > by || e.exe != exe {
                continue;
            }
            match found {
                None => found = Some(e),
                Some(f) if f.runs != e.runs || f.js_pm != e.js_pm || f.encrypts != e.encrypts => {
                    return None
                }
                Some(_) => {}
            }
        }
        found.cloned()
    }

    /// `/proc/<pid>/stat`'s parent (field 4) and start (field 22), counted
    /// after the `(comm)` field.
    fn proc_parent_and_start(&self, pid: u32) -> Option<(u32, u64)> {
        let stat = H::read_state(self.inner.proc_root.join(pid.to_string()).join("stat")).ok()?;
        let rest: Vec<&str> = stat.rsplit_once(')')?.1.split_whitespace().collect();
        Some((rest.get(1)?.parse().ok()?, rest.get(19)?.parse().ok()?))
    }

    /// What the spawn cache knows `pid` ran at `at` ([`CachedAt`]): its
    /// latest exec when `at` is at or after it (or none), else the latest of
    /// its earlier execs at or before `at`, else "only later". An earlier
    /// exec of another process the pid was reused from answers only for a
    /// time before the current process started: at a time the current
    /// process already existed, the pid was it, still running what it
    /// forked with (not known).
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
                Some(e) if self.same_start(e, cur) || t < cur.start_ns => CachedAt::Past(e.clone()),
                _ => CachedAt::LaterOnly,
            },
            _ => CachedAt::Current(cur.clone()),
        }
    }

    /// Third review of #475 (X2): [`Self::cached_at`], checked with live
    /// checks on against the process the pid names now — a latest exec
    /// whose process is not that one (`/proc/<pid>/stat` shows another
    /// start) answers as not held ([`CachedAt::Absent`]: a fork of its
    /// parent in a judgement, [`Self::fork_entry`]; `/proc` outside one)
    /// at a time that process may already have existed (its start, less
    /// the host's suspended time and two ticks, at or before the time; or
    /// no time): the pid was reused by a fork, which no exec announces.
    /// For a time before that process started, the cached exec is still
    /// what the pid ran then; a pid `/proc` no longer shows keeps its last
    /// record.
    fn cached_live(&self, pid: u32, at: Option<u64>) -> CachedAt {
        let found = self.cached_at(pid, at);
        let CachedAt::Current(e) = &found else {
            return found;
        };
        if !self.inner.live || e.start_ns == 0 {
            return found;
        }
        let Some(ticks) = self.proc_start_ticks(pid) else {
            return found;
        };
        if self.ticks_show_start(ticks, e.start_ns) {
            return found;
        }
        let tick = H::clock_tick_ns();
        let floor = ticks
            .saturating_mul(tick)
            .saturating_sub(self.suspended_ns() + 2 * tick);
        match at {
            Some(t) if floor > t => found,
            _ => CachedAt::Absent,
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
    pub fn is_auth_mediated(&self, pid: u32, as_of: AsOf) -> bool {
        self.lineage_exe_matches(pid, as_of, is_auth_binary)
    }

    /// External audit POS-002: `pid` is an authentication binary itself,
    /// or the direct child of one forked after it ran it — the PAM stack
    /// reading `/etc/shadow` at the caller's uid (sudo, su, passwd,
    /// unix_chkpwd, a cron or gdm worker). A shell of the session it
    /// opened, and everything below, reads as itself.
    pub fn is_credential_reader(&self, pid: u32, as_of: AsOf) -> bool {
        self.lineage_match(pid, as_of, is_auth_binary, 1)
            .unwrap_or(false)
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
    pub fn is_system_daemon_mediated(&self, pid: u32, as_of: AsOf) -> bool {
        self.lineage_exe_matches(pid, as_of, is_system_daemon_binary)
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
    pub fn is_package_transaction_write(&self, pid: u32, as_of: AsOf) -> bool {
        self.in_package_transaction(pid, as_of)
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
    /// The event's time is `as_of`'s ([`AsOf::Now`]: the time it is read).
    /// Serves the FIM rules, NN-L-NET-008, the chains' package carve-out,
    /// R009 and the posture's arms.
    pub fn in_package_transaction(&self, pid: u32, as_of: AsOf) -> bool {
        // Review #471 A1: the lineage as of the event — a package manager
        // the pid (or an ancestor) executed after it covers nothing.
        let Some(Some(hop)) = self.lineage_walk(
            pid,
            as_of,
            |hop| is_package_manager_binary(&hop.exe),
            LINEAGE_DEPTH_CAP,
        ) else {
            return false;
        };
        if hop.uid != Some(0) {
            return false;
        }
        let event_ns = as_of.time().unwrap_or_else(H::monotonic_ns);
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
    pub fn is_system_man_cache_writer(&self, pid: u32, as_of: AsOf) -> bool {
        if pid == 0 || pid == 1 {
            return false;
        }
        self.hop(pid, as_of).is_some_and(|hop| {
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
        as_of: AsOf,
        path: &str,
        path_from_user: bool,
    ) -> bool {
        let Some(Some(hop)) = self.lineage_walk(
            pid,
            as_of,
            |hop| is_package_manager_binary(&hop.exe),
            LINEAGE_DEPTH_CAP,
        ) else {
            return false;
        };
        let Some(uid) = hop.uid.filter(|uid| *uid != 0) else {
            return false;
        };
        let event_ns = as_of.time().unwrap_or_else(H::monotonic_ns);
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
        let read = |f: &str| H::read_state(self.inner.host_root.join(f)).unwrap_or_default();
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

    /// The final check of #495 (C1; its second review, R1): the image `pid`
    /// runs is the host's file at `path` — the device and inode of
    /// `/proc/<pid>/exe` (the kernel's link to the image it executed, opened
    /// as a file: no path walked in the process's mount namespace) are those
    /// of `path` under the host's root, as the agent reads it. A service
    /// systemd runs in a mount namespace of its own (systemd-resolved:
    /// `ProtectSystem=strict`, `PrivateTmp`) runs the host's file; a
    /// container's copy at that path (an overlay, another file), an image
    /// replaced at the path since the process started (another inode) and a
    /// process gone do not. `false` when either cannot be read: no evidence
    /// it is the host's.
    pub fn runs_host_file(&self, pid: u32, path: &str) -> bool {
        let id = |file: PathBuf| H::file_id(file);
        let exe = self.inner.proc_root.join(pid.to_string()).join("exe");
        let host = self.inner.host_root.join(path.trim_start_matches('/'));
        match (id(exe), id(host)) {
            (Some(own), Some(host)) => own == host,
            _ => false,
        }
    }

    /// Lot 340: `pid` ran, as of `as_of`, the host's file at `path` — the
    /// image its exec recorded (device and inode, [`Self::exec_image`]: the
    /// LSM program's, or the exec pump's in tracepoint mode; the device in
    /// the kernel's form, `MKDEV`) is the file at `path` under the host's
    /// root now (one `fstat`, its `st_dev` put in the kernel's form: the
    /// lab found the two forms compared). A copy of the
    /// program, a file replaced at the path since, another mount
    /// namespace's file at that path, an exec whose image was not recorded
    /// (a process older than the agent): `false`. Never the process's
    /// `/proc` image in a judgement (R-F).
    ///
    /// The lab of the review of #552: from the LSM program's identity of
    /// the executed file ([`Self::exec_file`]), not only [`Self::exec_image`]
    /// — the timer's logrotate.service runs in a mount namespace of its own
    /// (`ProtectSystem=`), which kept no image, and its run was High.
    pub fn ran_host_file(&self, pid: u32, as_of: AsOf, path: &str) -> bool {
        self.exec_file(pid, as_of)
            .is_some_and(|image| self.is_host_file(path, image))
    }

    /// Lot 348: `image` (an executed file's device and inode as the LSM
    /// program gave them, the device in the kernel's form) is the file at
    /// `path` under the host's root — PID 1's mount namespace, the agent's
    /// — now ([`Self::ran_host_file`]'s check, for an exec event's own
    /// identity). A copy, a file replaced at the path since, another mount
    /// namespace's file at that path: `false`.
    pub fn is_host_file(&self, path: &str, image: (u64, u64)) -> bool {
        H::file_id(self.inner.host_root.join(path.trim_start_matches('/')))
            .map(|(dev, ino)| (common::wire::exe::kernel_dev(dev), ino))
            == Some(image)
    }

    /// Lot 348: [`Self::is_host_file`], and the file's directory under the
    /// host's root is root's and writable by no one else
    /// ([`PostureHost::dir_is_root_only`]) — what `ROOT_DIR` says of a
    /// binary, for an executed SCRIPT, whose process's image (`/proc/<pid>/
    /// exe`) is its interpreter: the exec pump gives a script no `ROOT_DIR`
    /// (the lab of lot 348: initramfs-tools' hook `kmod`).
    pub fn is_host_file_in_root_dir(&self, path: &str, image: (u64, u64)) -> bool {
        self.is_host_file(path, image)
            && std::path::Path::new(path).parent().is_some_and(|dir| {
                H::dir_is_root_only(
                    self.inner
                        .host_root
                        .join(dir.to_string_lossy().trim_start_matches('/')),
                )
            })
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
            H::read_state(self.inner.proc_root.join(pid.to_string()).join("mountinfo")).ok()?;
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
    ///
    /// Lot 351 (the review of #559, F2): the sudo or su vouches only through
    /// the process it ran as root after authenticating
    /// ([`Self::elevation_walk`]). Any user may run sudo, and sudo runs
    /// programs before any credential check: `sudo -A` forks the user's
    /// `SUDO_ASKPASS` program as the user — a payload a local privilege
    /// escalation made root below it was "an administrator's session".
    pub fn is_interactive_admin(&self, pid: u32, as_of: AsOf) -> bool {
        if !matches!(self.elevation_walk(pid, as_of), (Some(WalkEnd::Found(_)), _)) {
            return false;
        }
        let Some(live) = self.nearest_running(pid, as_of) else {
            return false;
        };
        self.has_valid_loginuid(live) && self.has_controlling_tty(live)
    }

    /// Lot 351 (the review of #559, F2): the walk of
    /// [`Self::is_interactive_admin`] to the sudo or su that vouches for
    /// `pid` — `pid`'s own hop when it runs one itself (sudo's own code:
    /// `sudoedit`'s copy back), else the first [`ELEVATION_EXES`] hop above
    /// it whose child on the walk is the process it elevated
    /// ([`Self::elevated_child`]). A sudo or su whose child is not (the
    /// askpass helper, a PAM helper, a process gone through four execs) is
    /// passed over, its pid and its child's said in the answer (the first
    /// one), and the walk goes on: a sudo the session ran further up still
    /// vouches. Above sudo's monitor (a fork of sudo, itself an elevation
    /// hop) the monitor's child decided. The end `None` when a hop cannot be
    /// read (a sudo passed over below it still said).
    fn elevation_walk(&self, pid: u32, as_of: AsOf) -> (Option<WalkEnd>, Option<(u32, u32)>) {
        let below: std::cell::RefCell<Option<Hop>> = std::cell::RefCell::new(None);
        let passed: std::cell::Cell<Option<(u32, u32)>> = std::cell::Cell::new(None);
        let end = self.lineage_walk_to(
            pid,
            as_of,
            |hop| {
                let child = below.replace(Some(hop.clone()));
                if !is_elevation_binary(&hop.exe) {
                    return false;
                }
                let Some(child) = child else {
                    return true;
                };
                if is_elevation_binary(&child.exe) {
                    return false;
                }
                let elevated = self.elevated_child(hop, &child);
                if !elevated && passed.get().is_none() {
                    passed.set(Some((hop.pid, child.pid)));
                }
                elevated
            },
            LINEAGE_DEPTH_CAP,
        );
        (end, passed.get())
    }

    /// Lot 351 (the review of #559, F2): `child`, the hop below the sudo or
    /// su `elevation` on a walk, is the process that elevation ran as root
    /// after authenticating — the first exec of `child`'s process since its
    /// fork ([`Self::first_exec_of`]) was:
    ///
    /// * forked by `elevation` (the kernel's fork record), or the start's
    ///   scan found the process already running (older than the agent: no
    ///   exec of it could be seen; its uid as `/proc` showed it then);
    /// * as root (its real uid): what sudo and su run as the user — `sudo
    ///   -A`'s askpass helper before any authentication, `sudoedit`'s editor
    ///   — is not, and neither is `sudo -u` or `su` to another user;
    /// * not a PAM helper (`unix_chkpwd`, `unix_update`:
    ///   [`is_pam_helper`]), which `pam_unix` runs as root before the
    ///   credential check is done.
    ///
    /// The first exec, not the current one: a program that became root
    /// (a local privilege escalation in the askpass helper) and executed
    /// its payload in place is still the askpass helper's process. An
    /// administrator's `sudo env … ./x`, `sudo bash -c './x'` stay the
    /// command's (up to [`HISTORY_PER_PID`] execs in place). What sudo runs
    /// as root before authenticating comes from root's configuration
    /// (`pam_exec`, the mailer), trusted as such.
    fn elevated_child(&self, elevation: &Hop, child: &Hop) -> bool {
        let Some(first) = self.first_exec_of(child) else {
            return false;
        };
        let seeded = first.spawn_ns == 0;
        (first.fork_parent == elevation.pid || seeded)
            && first.uid == 0
            && !is_pam_helper(&first.exe)
    }

    /// Lot 351 (the review of #559, F2): the first exec, since its fork, of
    /// the process the cached `hop` names — of the spawn cache's execs of
    /// its pid with its start (the latest and [`HISTORY_PER_PID`] before
    /// it), the earliest up to `hop`'s, when it is known to be the first:
    /// the one the kernel's fork record marks ([`Entry::fork_parent`]; a
    /// later exec carries 0), or the start's scan's entry (a process older
    /// than the agent). `None` otherwise: a hop read from `/proc`, an
    /// earlier exec the history no longer holds, a fork record lost.
    fn first_exec_of(&self, hop: &Hop) -> Option<Entry> {
        if !hop.cached {
            return None;
        }
        let s = self.inner.state.read();
        let cur = s.map.get(&hop.pid).or_else(|| s.daemons.get(&hop.pid));
        let execs: Vec<&Entry> = s.history.get(&hop.pid).into_iter().flatten().chain(cur).collect();
        let own = execs
            .iter()
            .find(|e| e.spawn_ns == hop.spawn_ns && e.start_ns == hop.start_ns)?;
        let first = execs
            .iter()
            .filter(|e| e.spawn_ns <= own.spawn_ns && self.same_start(e, own))
            .min_by_key(|e| e.spawn_ns)?;
        (first.fork_parent != 0 || first.spawn_ns == 0).then(|| (*first).clone())
    }

    /// Lot 350 (F2-2): why `pid` is not in an administrator's interactive
    /// session ([`Self::is_interactive_admin`]) — the first of its checks
    /// that fails, said for the record of a rule that judged it so (R009) —
    /// or `None` when it is in one. The same walk and reads as the check.
    pub fn not_interactive_admin_because(&self, pid: u32, as_of: AsOf) -> Option<String> {
        match self.elevation_walk(pid, as_of) {
            (Some(WalkEnd::Found(_)), _) => {}
            // lot 351 (the review of #559, F2)
            (_, Some(passed)) => {
                return Some(format!(
                    "the sudo or su in its lineage (pid {}) ran nothing as root after \
                     authenticating above it: pid {}, its child, is not the process it \
                     elevated (a program it runs as the user, as sudo -A's askpass, or \
                     before the credential check)",
                    passed.0, passed.1
                ))
            }
            (Some(WalkEnd::Root), None) => return Some("no sudo or su in its lineage".to_string()),
            (Some(WalkEnd::Cut), None) => {
                return Some(
                    "its lineage is cut below any sudo or su (a parent started after its \
                     child, or the depth cap)"
                        .to_string(),
                )
            }
            (None, None) => {
                let lost = self.first_unread_hop(pid, as_of);
                return Some(format!(
                    "its lineage is lost at pid {lost} ({}): neither its exec nor its fork known",
                    if self.is_running(lost) {
                        "running"
                    } else {
                        "gone"
                    }
                ));
            }
        }
        let Some(live) = self.nearest_running(pid, as_of) else {
            return Some("nothing of its session runs any more".to_string());
        };
        if !self.has_valid_loginuid(live) {
            return Some(format!("pid {live}, the nearest running, has no login uid"));
        }
        if !self.has_controlling_tty(live) {
            return Some(format!(
                "pid {live}, the nearest running, has no controlling terminal"
            ));
        }
        None
    }

    /// The first pid up `pid`'s lineage whose hop cannot be read
    /// ([`Self::not_interactive_admin_because`]'s word for a lost walk).
    fn first_unread_hop(&self, pid: u32, as_of: AsOf) -> u32 {
        let mut cur = pid;
        for _ in 0..=LINEAGE_DEPTH_CAP {
            match self.hop(cur, as_of) {
                Some(h) if h.ppid > 1 && h.ppid != cur => cur = h.ppid,
                _ => return cur,
            }
        }
        cur
    }

    /// The login uid of `pid`, or of its nearest running ancestor once it
    /// has exited: the login uid is inherited, so the session's shell
    /// answers for a short-lived process. Scopes the posture's
    /// corroboration ledger.
    pub fn session_loginuid(&self, pid: u32, as_of: AsOf) -> Option<u32> {
        self.loginuid_of(self.nearest_running(pid, as_of)?)
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
    pub fn session_workload(&self, pid: u32, as_of: AsOf) -> Option<Workload> {
        let mut cur = pid;
        for _ in 0..LINEAGE_DEPTH_CAP {
            let live = self.nearest_running(cur, as_of)?;
            if let Some(path) = self.cgroup_path(live) {
                if !in_agent_containment(&path) {
                    return Some(workload_of_cgroup(&path));
                }
            }
            // Contained by the agent, or gone since: its parent's.
            let ppid = self
                .lookup_cache(live, as_of)
                .map(|(ppid, _)| ppid)
                .or_else(|| self.proc_ppid(live))?;
            if ppid == live {
                return None;
            }
            cur = ppid;
        }
        None
    }

    /// Lot 283c: the systemd service `pid` runs in now — its placing cgroup
    /// is `/system.slice/[…slice/]<unit>.service`
    /// ([`crate::posture::daemon_data::system_service`]) — or `None` (a
    /// session's scope, a container's, a process gone).
    pub fn system_service(&self, pid: u32) -> Option<String> {
        let path = self.cgroup_path(pid)?;
        crate::posture::daemon_data::system_service(&path).map(str::to_string)
    }

    /// Lot 350 (F2-3): [`Self::system_service`] of the process that started
    /// at `start_ns` (an exec event's own start, the kernel's monotonic
    /// clock) — `/proc/<pid>/stat` shows that start before and after its
    /// cgroup is read. `None` when it does not (the process exited, or its
    /// pid names a later one), for no start, or outside a service.
    pub fn system_service_started(&self, pid: u32, start_ns: u64) -> Option<String> {
        let started = || {
            self.proc_start_ticks(pid)
                .is_some_and(|ticks| self.ticks_show_start(ticks, start_ns))
        };
        if pid <= 1 || start_ns == 0 || !started() {
            return None;
        }
        let unit = self.system_service(pid)?;
        started().then_some(unit)
    }

    /// The cgroup path that places `pid` ([`placing_cgroup`]).
    fn cgroup_path(&self, pid: u32) -> Option<String> {
        if pid == 0 {
            return None;
        }
        let text = H::read_state(self.inner.proc_root.join(pid.to_string()).join("cgroup")).ok()?;
        placing_cgroup(&text).map(str::to_string)
    }

    /// `PPid:` of `/proc/<pid>/status`.
    fn proc_ppid(&self, pid: u32) -> Option<u32> {
        let text = H::read_state(self.inner.proc_root.join(pid.to_string()).join("status")).ok()?;
        parse_ppid(&text)
    }

    /// Review 52: [`Self::is_interactive_admin`] for the posture's
    /// corroboration ledger, or `None` while it cannot be told. That is
    /// the case when the lineage walk loses the chain before it ends (a
    /// process that is exiting and whose `exe` is gone, or a parent that
    /// has exited with no exec event in the cache: sudo's monitor is a
    /// fork without exec), or when sudo/su is found but nothing of the
    /// session runs any more to show a login uid and a terminal.
    pub fn interactive_admin_status(&self, pid: u32, as_of: AsOf) -> Option<bool> {
        // lot 351 (the review of #559, F2): the walk of the check itself
        if !matches!(self.elevation_walk(pid, as_of).0?, WalkEnd::Found(_)) {
            return Some(false);
        }
        let live = self.nearest_running(pid, as_of)?;
        Some(self.has_valid_loginuid(live) && self.has_controlling_tty(live))
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
        let Ok(stat) = H::read_state(dir.join("stat")) else {
            return true;
        };
        let state = stat
            .rsplit_once(')')
            .and_then(|(_, rest)| rest.split_whitespace().next());
        !matches!(state, Some("Z" | "X"))
    }

    /// `pid` if it still runs, else the nearest running ancestor in the
    /// spawn cache. `None` past PID 1, a cache miss, or the depth cap.
    fn nearest_running(&self, pid: u32, as_of: AsOf) -> Option<u32> {
        let mut cur = pid;
        for _ in 0..LINEAGE_DEPTH_CAP {
            if cur == 0 || cur == 1 {
                return None;
            }
            if self.is_running(cur) {
                return Some(cur);
            }
            let (ppid, _) = self.lookup_cache(cur, as_of)?;
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
        let Ok(stat) = H::read_state(path) else {
            return false;
        };
        stat.rsplit_once(')')
            .and_then(|(_, rest)| rest.split_whitespace().nth(4))
            .and_then(|tty| tty.parse::<i64>().ok())
            .is_some_and(|tty| tty != 0)
    }

    /// Lot 313 (BUG-49's residue): `pid`, as of `as_of`, runs an
    /// encryption tool asked to encrypt ([`Entry::encrypts`]) — its own
    /// exec, or the exec its forked copy runs. Cache-only, as
    /// [`Self::is_npm_cli_writer`]: a miss is no encryption (the writer is
    /// judged by its trust as before).
    pub fn runs_encryption(&self, pid: u32, as_of: AsOf) -> bool {
        if pid == 0 || pid == 1 {
            return false;
        }
        match self.cached_live(pid, as_of.time()) {
            CachedAt::Current(e) | CachedAt::Past(e) => e.encrypts,
            CachedAt::LaterOnly => false,
            CachedAt::Absent if as_of.is_judged() => self
                .fork_entry(pid, as_of.time(), 0)
                .is_some_and(|e| e.encrypts),
            CachedAt::Absent => false,
        }
    }

    /// FP-2 — true iff `pid` is npm's own node process: a DIRECT
    /// (non-lineage) check that the focal writer's `exe` ∈ [`NODE_EXES`]
    /// AND its precomputed [`Entry::js_pm`] flag is set (argv[1]
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
    ///
    /// The review of #552 (F2): and node runs npm's script alone — its exec
    /// pump read no environment that loads the caller's code beside it
    /// (`NODE_OPTIONS=--require …`, `--import`, `NODE_PATH`: `ENV_LOADS`,
    /// [`with_pump_facts`]; what it runs is then [`Runs::Unknown`]). A
    /// postinstall's `NODE_OPTIONS=--require=./p.js npm -v` runs the
    /// package's code in a process named npm: judged as any node.
    ///
    /// Lot 346 (the re-check of #552, N1): and node's exec has its image
    /// ([`Entry::image`]: the kernel's or the pump's identity, `ROOT_DIR` —
    /// executed from a root-only directory, in PID 1's mount namespace): a
    /// node a user's namespace binds over its own, a container's, a node in
    /// a directory a user owns is not npm's. What this names is the
    /// process, not what it may write: [`Self::js_pm_own_write`] is the
    /// exemption. The review of #555 (F2): npm alone ([`JsPm`]).
    pub fn js_pm_writer(&self, pid: u32, as_of: AsOf) -> Option<JsPm> {
        if pid == 0 || pid == 1 {
            return None;
        }
        let e = match self.cached_live(pid, as_of.time()) {
            CachedAt::Current(e) | CachedAt::Past(e) => e,
            CachedAt::LaterOnly | CachedAt::Absent => return None,
        };
        let pm = e.js_pm?;
        e.image?;
        (is_node_exe(&e.exe) && matches!(e.runs, Runs::Script(_))).then_some(pm)
    }

    /// FP-2: [`Self::js_pm_writer`] for npm.
    pub fn is_npm_cli_writer(&self, pid: u32, as_of: AsOf) -> bool {
        self.js_pm_writer(pid, as_of) == Some(JsPm::Npm)
    }

    /// Lot 346 (the re-check of #552, N1): `pid` is a JavaScript package
    /// manager ([`Self::js_pm_writer`]: npm) and `path` one of its own
    /// directories or files ([`in_js_pm_own_dir`]): a package tree, its
    /// cache, a manifest or lockfile. npm loads the caller's code in its own
    /// process by design (`npm init` runs `~/.npm-init.js`), and a node
    /// prefix under `/usr/local` may be a user's (npm's old `EACCES`
    /// advice): whatever runs there, a user's document is never npm's to
    /// write.
    ///
    /// Residual (the review of #555, F2): the arm judges the file that
    /// crossed its threshold — the kernel reports a window's crossing once
    /// per process. Code inside npm that puts that crossing in a package
    /// tree (it fills `node_modules` first, or keeps one write there per
    /// window) pads the window: the documents it rewrites beside it in that
    /// window are not counted by the arm. Narrower than before lot 346,
    /// where every write of npm's was exempt; yarn, pnpm and bun, which load
    /// a project's code in their process on every install, are not exempt
    /// at all ([`JsPm`]).
    pub fn js_pm_own_write(&self, pid: u32, as_of: AsOf, path: &str) -> Option<JsPm> {
        self.js_pm_writer(pid, as_of)
            .filter(|pm| in_js_pm_own_dir(*pm, path))
    }

    /// Lot 340 (the review of #552, F1): the real uid `pid` executed its
    /// image as, as of `as_of` — the exec event's, from the kernel's
    /// credentials. From the spawn cache only; `None` when it does not hold
    /// the exec.
    pub fn exec_uid(&self, pid: u32, as_of: AsOf) -> Option<u32> {
        match self.cached_live(pid, as_of.time()) {
            CachedAt::Current(e) | CachedAt::Past(e) => Some(e.uid),
            CachedAt::LaterOnly | CachedAt::Absent => None,
        }
    }

    /// Lot 340 (the review of #552, F1): `pid`'s exec, as of `as_of`, had
    /// exactly the argv `argv` — `argv[0]` by its basename, every argument
    /// as given, no more ([`Self::argv_digest`]). From the spawn cache only:
    /// `false` when it does not hold the exec, for an argv the sensor cut,
    /// and for a process that never executed (a fork: [`Entry::argv`]).
    pub fn exec_argv_is(&self, pid: u32, as_of: AsOf, argv: &[&str]) -> bool {
        let want = self.argv_digest(argv);
        match self.cached_live(pid, as_of.time()) {
            CachedAt::Current(e) | CachedAt::Past(e) => e.argv.is_some() && e.argv == want,
            CachedAt::LaterOnly | CachedAt::Absent => false,
        }
    }

    /// Lot 340 (the alpha's daily false positives): `pid` is the Go
    /// toolchain's own `go` command — a binary ([`is_go_toolchain`]) in a
    /// root-owned system tree, run as itself (no interpreter) — and `path`
    /// lies in one of its own directories ([`in_go_own_dir`]): the build's
    /// work directory (`$TMPDIR/go-build<digits>/`), the build cache
    /// (`…/.cache/go-build/`) or the module cache (`…/go/pkg/mod/`). `go
    /// test` rewrites its packages' archives in place in its work directory
    /// to stamp their build ids (lot 313's ci corpus: 20 existing files
    /// rewritten, ConfirmedIntrusion → ENGAGED). A DIRECT check of the
    /// writer, like [`Self::is_npm_cli_writer`]: what `go` runs (a test
    /// binary, `go run`'s program, `go generate`'s commands, a
    /// `-toolexec` program) is another process, judged on its own; a
    /// toolchain `go` downloaded into a home (`GOTOOLCHAIN`) is not one.
    /// Cache-only (the exec seen), `false` otherwise.
    ///
    /// The review of #555 (F1): and `go`'s exec has its image
    /// ([`Entry::image`], `ROOT_DIR`: executed from a root-only directory,
    /// in PID 1's mount namespace), as npm's node ([`Self::js_pm_writer`]).
    /// A path names a file only in the namespace that resolved it: a
    /// container's `/usr/local/go/bin/go` (a golang image's), a user
    /// namespace's bind over the packaged one, writing a home bound at
    /// `…/go/pkg/mod/` there, is not the packaged toolchain.
    pub fn is_go_toolchain_own_write(&self, pid: u32, as_of: AsOf, path: &str) -> bool {
        if pid <= 1 || !in_go_own_dir(path) {
            return false;
        }
        match self.cached_live(pid, as_of.time()) {
            CachedAt::Current(e) | CachedAt::Past(e) => runs_packaged_go(&e),
            CachedAt::LaterOnly | CachedAt::Absent => false,
        }
    }

    /// Lot 346 (item 1): `pid` runs a program the Go toolchain built in its
    /// own work directory — `image`, the file the kernel executed, is
    /// `<tmp>/go-build<digits>/b<digits>/<name>` (`go test`'s test binary)
    /// or `…/b<digits>/exe/<name>` (`go run`'s program) ([`in_go_work_dir`])
    /// — and the process that forked it ran the packaged `go` command
    /// ([`is_go_toolchain`], its exec seen, run as itself) before the fork:
    /// the one hop above `pid` (external audit POS-003's order), never an
    /// ancestor further up. A test binary run through `go test -exec`'s
    /// wrapper, a program a test binary runs, a file a user drops in a
    /// `go-build` directory and runs from a shell, a `go` downloaded into a
    /// home: not. What `go` builds is the user's code — as `go build` and
    /// `./prog` from a home, which no staging rule judges. As of `as_of`.
    /// The review of #555 (F1): the forker's exec has its image
    /// ([`Self::is_go_toolchain_own_write`]): a container's or a user
    /// namespace's `go` is not the packaged one.
    pub fn runs_go_build_output(&self, pid: u32, as_of: AsOf, image: &str) -> bool {
        if pid <= 1 || !in_go_work_dir(image) {
            return false;
        }
        matches!(
            self.lineage_walk(pid, as_of, |hop| hop.pid != pid, 1),
            Some(Some(hop)) if hop.cached
                && hop.rooted
                && hop.runs == Runs::Inline
                && is_go_toolchain(&hop.exe)
        )
    }

    /// Lot 346 (the lab of item 1): [`Self::runs_go_build_output`] for the
    /// pre-exec check (`Event::ExecCheck`, LSM `bprm_check_security`): the
    /// process is still the fork it was, its parent the kernel's `ppid` —
    /// that parent runs the packaged `go` as of the check (its exec seen,
    /// run as itself), and `image` lies in a work directory's layout. The
    /// exec event that follows is judged on the order of the fork
    /// ([`Self::runs_go_build_output`]): a parent that executed `go` only
    /// after the fork raises there. The review of #555 (F1): the parent's
    /// exec has its image ([`Self::is_go_toolchain_own_write`]).
    pub fn execs_go_build_output(&self, ppid: u32, as_of: AsOf, image: &str) -> bool {
        if ppid <= 1 || !in_go_work_dir(image) {
            return false;
        }
        match self.cached_live(ppid, as_of.time()) {
            CachedAt::Current(e) | CachedAt::Past(e) => runs_packaged_go(&e),
            CachedAt::LaterOnly | CachedAt::Absent => false,
        }
    }

    /// Lot 346 (item 6): `pid` is PostgreSQL's `initdb` making a cluster —
    /// the packaged `initdb` ([`is_postgres_bin`]: a distribution's
    /// `/usr/lib/postgresql/<N>/bin/initdb`, PGDG's `/usr/pgsql-<N>/bin/`,
    /// `/usr/bin/initdb`; its exec seen with its image, run as itself), or
    /// the packaged `postgres` of the same directory that such an `initdb`
    /// started for the bootstrap (forked by it, or by the `sh -c` its
    /// `popen` runs: at most two hops up, each ran before the fork below).
    /// `initdb` creates a cluster in an empty directory and its bootstrap
    /// backends write the new cluster's relation files, rewriting each as
    /// they fill it (lot 340's db corpus: ConfirmedIntrusion → ENGAGED for
    /// both, `pg_createcluster` by hand). Whose files and which account the
    /// arm still decides ([`super::triggers`]: a service account's own
    /// data, the kernel's summary). As of `as_of`, from the spawn cache.
    pub fn runs_postgres_initdb(&self, pid: u32, as_of: AsOf) -> bool {
        if pid <= 1 {
            return false;
        }
        let e = match self.cached_live(pid, as_of.time()) {
            CachedAt::Current(e) | CachedAt::Past(e) => e,
            CachedAt::LaterOnly | CachedAt::Absent => return false,
        };
        if e.image.is_none() || e.runs != Runs::Inline {
            return false;
        }
        let Some((dir, prog)) = is_postgres_bin(&e.exe) else {
            return false;
        };
        match prog {
            "initdb" => true,
            _ => {
                let initdb = format!("{dir}/initdb");
                matches!(
                    self.lineage_walk(
                        pid,
                        as_of,
                        |hop| hop.pid != pid
                            && hop.cached
                            && hop.runs == Runs::Inline
                            && hop.exe == Path::new(&initdb),
                        2,
                    ),
                    Some(Some(_))
                )
            }
        }
    }

    /// Walk the lineage of `pid` upward and return true if `pid` runs an
    /// `is_match` binary, or an ancestor ran one before the process below
    /// it was forked ([`Self::lineage_match`]). Shared by every lineage
    /// predicate so all use the identical, non-forgeable walk.
    fn lineage_exe_matches(&self, pid: u32, as_of: AsOf, is_match: impl Fn(&Path) -> bool) -> bool {
        self.lineage_match(pid, as_of, is_match, LINEAGE_DEPTH_CAP)
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
        as_of: AsOf,
        is_match: impl Fn(&Path) -> bool,
        max_up: usize,
    ) -> Option<bool> {
        self.lineage_walk(pid, as_of, |hop| is_match(&hop.exe), max_up)
            .map(|found| found.is_some())
    }

    /// The walk of [`Self::lineage_match`], by hop: the first hop
    /// `is_match` accepts — `pid`'s own, or an ancestor's that ran its exe
    /// before the process below it was forked. `Some(None)` when the walk
    /// ends without one (at PID 1, or cut: [`Self::lineage_walk_to`]),
    /// `None` when a hop cannot be read. As of `as_of` (review #471 A1,
    /// R-F): each hop the exec its pid had run by then ([`Self::hop`]).
    ///
    /// For the walks that look for a hop that GRANTS something (a package
    /// manager, an authentication binary, a client, a grantee): a walk cut
    /// before PID 1 finds nothing above the cut, and grants nothing for it.
    /// A walk whose every hop must vouch reads [`Self::lineage_walk_to`].
    fn lineage_walk(
        &self,
        pid: u32,
        as_of: AsOf,
        is_match: impl Fn(&Hop) -> bool,
        max_up: usize,
    ) -> Option<Option<Hop>> {
        Some(match self.lineage_walk_to(pid, as_of, is_match, max_up)? {
            WalkEnd::Found(hop) => Some(hop),
            WalkEnd::Root | WalkEnd::Cut => None,
        })
    }

    /// [`Self::lineage_walk`], saying how it ended. The re-check 4 of #539
    /// (HIGH): it reached PID 1 or 0 ([`WalkEnd::Root`]) — the lineage is
    /// whole — or it stopped before: the depth cap ([`LINEAGE_DEPTH_CAP`],
    /// or `max_up`), a hop that started after the one below it (a later
    /// process that took an exited parent's pid), a process its own parent
    /// ([`WalkEnd::Cut`]: what is above the cut is not known). `pid` + the
    /// cap's 32 ancestors whose last one's parent is PID 1 is whole: no
    /// hop is read past the cap to know it. `None` when a hop cannot be
    /// read.
    fn lineage_walk_to(
        &self,
        pid: u32,
        as_of: AsOf,
        is_match: impl Fn(&Hop) -> bool,
        max_up: usize,
    ) -> Option<WalkEnd> {
        if pid == 0 || pid == 1 {
            return Some(WalkEnd::Root);
        }
        let mut below = self.hop(pid, as_of)?;
        if is_match(&below) {
            return Some(WalkEnd::Found(below));
        }
        for _ in 0..max_up.min(LINEAGE_DEPTH_CAP) {
            let ppid = below.ppid;
            if ppid == 0 || ppid == 1 {
                return Some(WalkEnd::Root);
            }
            if ppid == below.pid {
                return Some(WalkEnd::Cut);
            }
            let up = self.hop(ppid, as_of)?;
            if !self.started_no_later(&up, &below) {
                return Some(WalkEnd::Cut);
            }
            if is_match(&up) && self.ran_before(&up, &below, as_of) {
                return Some(WalkEnd::Found(up));
            }
            below = up;
        }
        Some(if below.ppid == 0 || below.ppid == 1 {
            WalkEnd::Root
        } else {
            WalkEnd::Cut
        })
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
        as_of: AsOf,
        is_actor: impl Fn(&ExecIdentity) -> bool,
    ) -> Option<PathBuf> {
        self.lineage_walk(
            pid,
            as_of,
            |hop| is_actor(&self.hop_identity(hop)),
            LINEAGE_DEPTH_CAP,
        )?
        .map(|hop| hop.exe)
    }

    /// Lot 278: `pid` is the process `ancestor` names, or descends from it,
    /// as of `as_of` — `ancestor` by its pid and its start (`starttime` of
    /// `/proc/<pid>/stat`, in clock ticks: the process a trusted-installer
    /// window was granted to, [`crate::anti_tamper::trusted_installer::WindowGrantee`]),
    /// on the walk of [`Self::actor_in_lineage`] (a parent starts no later
    /// than its child, POS-003). By lineage only: what any process of the
    /// tree runs, or is named, is not read. `false` when the walk loses the
    /// chain first, or when the pid on the walk is a later process (its
    /// start is not the ancestor's).
    pub fn descends_from(&self, pid: u32, as_of: AsOf, ancestor: u32, ancestor_ticks: u64) -> bool {
        // PID 0 and 1 never match: the walk ends at them
        matches!(
            self.lineage_walk(
                pid,
                as_of,
                |hop| hop.pid == ancestor && self.hop_started_at_ticks(hop, ancestor_ticks),
                LINEAGE_DEPTH_CAP,
            ),
            Some(Some(_))
        )
    }

    /// `hop` is the process that started at `ticks` (`/proc`'s clock, ticks
    /// since boot): `/proc` shows that very start for its pid now — exactly,
    /// with no allowance for the time suspended (review of #493, note e: a
    /// later process that took the grantee's pid within that allowance must
    /// not pass for it; the grantee runs while its tree is judged) — and a
    /// cached start agrees with it ([`Self::ticks_show_start`]).
    fn hop_started_at_ticks(&self, hop: &Hop, ticks: u64) -> bool {
        self.proc_start_ticks(hop.pid) == Some(ticks)
            && (hop.start_ns == 0 || self.ticks_show_start(ticks, hop.start_ns))
    }

    /// Lab PR 222 (copy on first write): what the kernel executed for `pid`
    /// and for each ancestor on the walk of [`Self::actor_in_lineage`]
    /// (ordered, POS-003), nearest first, `pid`'s own identity at index 0,
    /// up to PID 1. `None` when the lineage is not known: a hop can be read
    /// neither from the spawn cache nor from `/proc`, or (the re-check 4 of
    /// #539, HIGH) the walk stopped before PID 1 — at [`LINEAGE_DEPTH_CAP`]
    /// (33 nested `timeout`s, each a packaged program that forks the next,
    /// hid a webshell's `sh -c` above them), at a hop that started after the
    /// one below it, at a process its own parent ([`WalkEnd::Cut`]). Every
    /// hop of this lineage must vouch for the writer: one never read never
    /// does. [`Self::lineage_identities_seen`] keeps the hops below a cut.
    ///
    /// Reads only the spawn cache and `/proc` — never a file elsewhere, so
    /// the guard's fanotify reader may call it (an open on a marked
    /// filesystem from that thread would wait on itself).
    pub fn lineage_identities(&self, pid: u32, as_of: AsOf) -> Option<Vec<(u32, ExecIdentity)>> {
        match self.walk_identities(pid, as_of)? {
            (hops, WalkEnd::Root) => Some(hops),
            _ => None,
        }
    }

    /// [`Self::lineage_identities`], with the hops read below a cut too:
    /// for a reader that LOOKS for a hop (a staged image among them), never
    /// for one that trusts the lineage whole. `None` when a hop cannot be
    /// read.
    pub fn lineage_identities_seen(
        &self,
        pid: u32,
        as_of: AsOf,
    ) -> Option<Vec<(u32, ExecIdentity)>> {
        self.walk_identities(pid, as_of).map(|(hops, _)| hops)
    }

    /// The hops of [`Self::lineage_identities`]' walk and how it ended.
    fn walk_identities(
        &self,
        pid: u32,
        as_of: AsOf,
    ) -> Option<(Vec<(u32, ExecIdentity)>, WalkEnd)> {
        let hops = std::cell::RefCell::new(Vec::new());
        let end = self.lineage_walk_to(
            pid,
            as_of,
            |hop| {
                hops.borrow_mut().push((hop.pid, self.hop_identity(hop)));
                false
            },
            LINEAGE_DEPTH_CAP,
        )?;
        Some((hops.into_inner(), end))
    }

    /// Lot 340 (the review of #552, F1): [`Self::lineage_identities`] with
    /// what each hop's exec recorded beside its identity — its parent, its
    /// real uid, the kernel's fork record ([`HopFacts`]). `None` when the
    /// lineage is not whole (the walk did not reach PID 1).
    pub fn lineage_hops(&self, pid: u32, as_of: AsOf) -> Option<Vec<HopFacts>> {
        let hops = std::cell::RefCell::new(Vec::new());
        let end = self.lineage_walk_to(
            pid,
            as_of,
            |hop| {
                hops.borrow_mut().push(HopFacts {
                    pid: hop.pid,
                    ppid: hop.ppid,
                    id: self.hop_identity(hop),
                    uid: hop.uid,
                    fork_parent: hop.fork_parent,
                    cached: hop.cached,
                });
                false
            },
            LINEAGE_DEPTH_CAP,
        )?;
        matches!(end, WalkEnd::Root).then(|| hops.into_inner())
    }

    /// Lot 310 (the re-check of #539, N2): for each hop of
    /// [`Self::lineage_identities`]'s walk (the same order), the process
    /// that forked it, when its exec was the first since that fork — the
    /// kernel's record at `sched_process_fork`, never the parent at exec
    /// time; 0 when not known.
    pub fn lineage_fork_parents(&self, pid: u32, as_of: AsOf) -> Vec<u32> {
        let parents = std::cell::RefCell::new(Vec::new());
        let _ = self.lineage_walk(
            pid,
            as_of,
            |hop| {
                parents.borrow_mut().push(hop.fork_parent);
                false
            },
            LINEAGE_DEPTH_CAP,
        );
        parents.into_inner()
    }

    /// Lot 310 (the re-check of #539, N2): the process that forked `pid`,
    /// when the exec the cache holds as of `as_of` was its first since that
    /// fork; `None` when not known.
    pub fn fork_parent(&self, pid: u32, as_of: AsOf) -> Option<u32> {
        match self.cached_live(pid, as_of.time()) {
            CachedAt::Current(e) | CachedAt::Past(e) => Some(e.fork_parent).filter(|p| *p != 0),
            _ => None,
        }
    }

    /// Lot 282: what the kernel executed for `pid`'s parent, when it forked
    /// `pid` (the ordered walk of one hop: external audit POS-003). `None`
    /// when either cannot be placed. Unlike [`Self::lineage_identities`],
    /// an ancestor further up that cannot be read (a daemon's double fork,
    /// a process gone before its exec was read) does not hide the parent:
    /// NN-L-EVA-002 asks who ran an `iptables`, nothing more.
    pub fn parent_identity(&self, pid: u32, as_of: AsOf) -> Option<ExecIdentity> {
        match self.lineage_walk(pid, as_of, |hop| hop.pid != pid, 1) {
            Some(Some(hop)) => Some(self.hop_identity(&hop)),
            _ => None,
        }
    }

    /// Lot 275 (NN-L-NET-028): `pid` and its ancestors on the walk of
    /// [`Self::actor_in_lineage`] (ordered, POS-003), `pid` first, each
    /// with its start as the spawn cache holds it (`CLOCK_MONOTONIC` ns; 0
    /// for a hop read from `/proc`). The hops read before a hop that cannot
    /// be read; empty when `pid`'s own cannot.
    pub fn lineage_starts(&self, pid: u32, as_of: AsOf) -> Vec<(u32, u64)> {
        let hops = std::cell::RefCell::new(Vec::new());
        let _ = self.lineage_walk(
            pid,
            as_of,
            |hop| {
                let start = if hop.cached { hop.start_ns } else { 0 };
                hops.borrow_mut().push((hop.pid, start));
                false
            },
            LINEAGE_DEPTH_CAP,
        );
        hops.into_inner()
    }

    /// What the kernel executed for a hop: the spawn cache's record, else
    /// `/proc` (`cmdline` names the script an interpreter runs).
    fn hop_identity(&self, hop: &Hop) -> ExecIdentity {
        let runs = if hop.cached {
            hop.runs.clone()
        } else {
            self.proc_runs(hop.pid, &hop.exe)
        };
        ExecIdentity {
            exe: hop.exe.clone(),
            runs,
        }
    }

    /// What an interpreter `exe` runs as process `pid`, from
    /// `/proc/<pid>/cmdline` ([`runs_of`]).
    fn proc_runs(&self, pid: u32, exe: &Path) -> Runs {
        let cmdline =
            H::read(self.inner.proc_root.join(pid.to_string()).join("cmdline")).unwrap_or_default();
        runs_of(exe, &argv_of_cmdline(&cmdline))
    }

    /// One hop of the walk as of `as_of` (review #471 A1, R-F): the spawn
    /// cache's record of `pid` while it still describes the process `pid`
    /// names, an earlier exec of the pid when its latest came after the
    /// time, else `/proc` — but `None` (not known) when only later execs
    /// are cached (`/proc` would show the later image), and in a judgement
    /// ([`AsOf::Judged`]) whenever the cache holds no exec of the process
    /// the pid named then.
    fn hop(&self, pid: u32, as_of: AsOf) -> Option<Hop> {
        let (cached, past) = match self.cached_live(pid, as_of.time()) {
            CachedAt::Current(e) => (Some(e), false),
            CachedAt::Past(e) => (Some(e), true),
            CachedAt::LaterOnly => return None,
            // review of #475: in a judgement, a fork of a cached process
            // still running its image ([`Self::fork_entry`])
            CachedAt::Absent if as_of.is_judged() => (self.fork_entry(pid, as_of.time(), 0), true),
            CachedAt::Absent => (None, false),
        };
        if let Some(e) = cached {
            if past || self.entry_is_current(pid, &e) || self.reused_after(pid, as_of) {
                return Some(Hop {
                    pid,
                    ppid: e.ppid,
                    exe: e.exe,
                    runs: e.runs,
                    cached: true,
                    spawn_ns: e.spawn_ns,
                    start_ns: e.start_ns,
                    uid: Some(e.uid),
                    fork_parent: e.fork_parent,
                    rooted: e.image.is_some(),
                });
            }
        }
        if as_of.is_judged() {
            // R-F: in a judgement `/proc` would show the present image; the
            // processes older than the agent are in the cache from the
            // start's scan ([`Self::seed_from_proc`])
            return None;
        }
        let (ppid, exe, uid) = self.lookup_proc(pid)?;
        Some(Hop {
            pid,
            ppid,
            exe,
            runs: Runs::Inline,
            cached: false,
            spawn_ns: 0,
            start_ns: 0,
            uid,
            fork_parent: 0,
            rooted: false,
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
    fn ran_before(&self, up: &Hop, below: &Hop, as_of: AsOf) -> bool {
        if !up.cached {
            return self.held_validly(up, as_of, 0);
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
    fn held_validly(&self, hop: &Hop, as_of: AsOf, depth: usize) -> bool {
        if self.predates_observer(hop.pid) {
            return true;
        }
        if depth >= LINEAGE_DEPTH_CAP || hop.ppid == 0 || hop.ppid == 1 || hop.ppid == hop.pid {
            return false;
        }
        let Some(parent) = self.hop(hop.ppid, as_of) else {
            return false;
        };
        if parent.exe != hop.exe {
            return false;
        }
        parent.cached || self.held_validly(&parent, as_of, depth + 1)
    }

    /// The cached exec `e` still describes the process `pid` names: with
    /// live checks on, its start matches the one `/proc/<pid>/stat` shows
    /// (an exited process leaves the cache as the only record).
    fn entry_is_current(&self, pid: u32, e: &Entry) -> bool {
        !self.inner.live || self.started_at(pid, e.start_ns) != Some(false)
    }

    /// R-F: in a judgement, the process `pid` names now started after the
    /// event's time (its `/proc` start, less all the time the host spent
    /// suspended and two ticks of rounding, is later): the pid was reused
    /// after the event, so a cached exec that is not the present process's
    /// is still the one the pid had then. False outside a judgement, or
    /// when `/proc` does not show the pid.
    fn reused_after(&self, pid: u32, as_of: AsOf) -> bool {
        let AsOf::Judged(at) = as_of else {
            return false;
        };
        let Some(ticks) = self.proc_start_ticks(pid) else {
            return false;
        };
        let tick = H::clock_tick_ns();
        ticks
            .saturating_mul(tick)
            .saturating_sub(self.suspended_ns() + 2 * tick)
            > at
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
    /// Lot 292 (BUG-56): two entries of a pid were made for one process —
    /// the same start. An exec event's start is exact; one read from
    /// `/proc` ([`Entry::start_ticks`]: the start's scan, a fork, an
    /// orphan) is rounded down to a tick and less the time suspended, so it
    /// is the same start when those ticks show the exact one
    /// ([`Self::ticks_show_start`]), or when both were read as the same
    /// ticks.
    fn same_start(&self, a: &Entry, b: &Entry) -> bool {
        match (a.start_ticks, b.start_ticks) {
            (None, None) => a.start_ns == b.start_ns,
            (Some(ticks), None) => self.ticks_show_start(ticks, b.start_ns),
            (None, Some(ticks)) => self.ticks_show_start(ticks, a.start_ns),
            (Some(x), Some(y)) => x == y,
        }
    }

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

    /// Lot 314 (BUG-83): `starttime` of `/proc/<pid>/stat` (clock ticks
    /// since boot): with the pid, one process's identity for as long as it
    /// runs. `None` when `/proc` does not show the process.
    pub fn start_ticks(&self, pid: u32) -> Option<u64> {
        if pid == 0 {
            return None;
        }
        self.proc_start_ticks(pid)
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
        let stat = H::read_state(self.inner.proc_root.join(name).join("stat")).ok()?;
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
        let raw = H::read_state(&path).ok()?;
        match raw.trim().parse::<u32>() {
            Ok(v) if v != LOGINUID_UNSET => Some(v),
            _ => None,
        }
    }

    /// Review 85: what the kernel executed for `pid` ([`ExecIdentity`]):
    /// the spawn cache, else `/proc/<pid>/exe` and `cmdline`. `None` when
    /// neither knows it (exited before its exec event was read), or when
    /// its exe was deleted or replaced.
    ///
    /// As of `as_of` (review #471 A1, R-F): an earlier exec when the latest
    /// came after the time, `None` when only later ones are cached; in a
    /// judgement ([`AsOf::Judged`]) `None` too when the cache holds none.
    pub fn exec_identity(&self, pid: u32, as_of: AsOf) -> Option<ExecIdentity> {
        if pid == 0 {
            return None;
        }
        match self.cached_live(pid, as_of.time()) {
            CachedAt::Current(e) | CachedAt::Past(e) => {
                return Some(ExecIdentity {
                    exe: e.exe,
                    runs: e.runs,
                });
            }
            CachedAt::LaterOnly => return None,
            CachedAt::Absent if !self.judged_from_proc(pid, as_of) => {
                // review of #475: a fork of a cached process still running
                // its image ([`Self::fork_entry`]), else not known
                return self.fork_entry(pid, as_of.time(), 0).map(|e| ExecIdentity {
                    exe: e.exe,
                    runs: e.runs,
                });
            }
            CachedAt::Absent => {}
        }
        let exe = H::read_link(self.inner.proc_root.join(pid.to_string()).join("exe")).ok()?;
        if exe.to_string_lossy().ends_with(" (deleted)") {
            return None;
        }
        let runs = self.proc_runs(pid, &exe);
        Some(ExecIdentity { exe, runs })
    }

    /// The review of #554 (F1): what the process `pid` that started at
    /// `start_ns` (`CLOCK_MONOTONIC`, the kernel's `task->start_time`)
    /// executed, as of `as_of`, from the records only: its exec as the spawn
    /// cache holds it, at that start; else, for a process that executed
    /// nothing since its fork, its forker's exec through the kernel's fork
    /// record at that start ([`Self::kernel_fork_entry`]). A later (or
    /// earlier) holder of the pid is not that process: `None`, as when
    /// neither record holds it — never `/proc`, which shows whoever holds
    /// the pid now (the caller reads it for that start only).
    pub fn recorded_identity_started(
        &self,
        pid: u32,
        start_ns: u64,
        as_of: AsOf,
    ) -> Option<ExecIdentity> {
        if pid == 0 || start_ns == 0 {
            return None;
        }
        let at = as_of.time();
        if let CachedAt::Current(e) | CachedAt::Past(e) = self.cached_at(pid, at) {
            let started = match e.start_ticks {
                Some(ticks) => self.ticks_show_start(ticks, start_ns),
                None => e.start_ns == start_ns,
            };
            if started {
                return Some(ExecIdentity {
                    exe: e.exe,
                    runs: e.runs,
                });
            }
        }
        let forked = self
            .inner
            .state
            .read()
            .kernel_forks
            .get(&pid)
            .is_some_and(|k| k.start_ns == start_ns);
        if !forked {
            return None;
        }
        self.kernel_fork_entry(pid, at, 0).map(|e| ExecIdentity {
            exe: e.exe,
            runs: e.runs,
        })
    }

    /// Lot 310: the identity (device and inode; the device in the kernel's
    /// form, `MKDEV` — the review of #552, F7: not `stat(2)`'s `st_dev`) of
    /// the file `pid` executed, as the exec sensor's LSM program gave it —
    /// from the spawn cache only
    /// (no `/proc`: it is read on the decision path), as of `as_of`
    /// ([`Self::exec_identity`]'s cache lookup); `None` when the cache does
    /// not hold the exec, or holds no identity for it (tracepoint mode, a
    /// process older than the agent).
    pub fn exec_image(&self, pid: u32, as_of: AsOf) -> Option<(u64, u64)> {
        if pid == 0 {
            return None;
        }
        match self.cached_live(pid, as_of.time()) {
            CachedAt::Current(e) | CachedAt::Past(e) => e.image,
            CachedAt::LaterOnly => None,
            // lot 310: a process older than the agent whose image was
            // unlinked before the start's scan (not entered)
            CachedAt::Absent => {
                let s = self.inner.state.read();
                let (start, image) = s.seeded_images.get(&pid).copied()?;
                as_of.time().is_none_or(|t| t >= start).then_some(image)
            }
        }
    }

    /// Lot 340 (the lab of the review of #552): the file `pid` executed, as
    /// of `as_of`, by the LSM program's identity whatever its directory or
    /// mount namespace ([`Entry::exec_file`]), else [`Self::exec_image`]'s —
    /// for a comparison with a packaged file only ([`Self::ran_host_file`],
    /// a known BPF probe's loader). From the spawn cache only.
    pub fn exec_file(&self, pid: u32, as_of: AsOf) -> Option<(u64, u64)> {
        if pid == 0 {
            return None;
        }
        match self.cached_live(pid, as_of.time()) {
            CachedAt::Current(e) | CachedAt::Past(e) => e.exec_file,
            CachedAt::LaterOnly | CachedAt::Absent => self.exec_image(pid, as_of),
        }
    }

    /// External audit NETR-008: the image `pid` runs, for a network row
    /// filled at connect time: the spawn cache, else `/proc/<pid>/exe` as
    /// the kernel reports it. Unlike [`Self::exec_identity`] a deleted
    /// image is kept, with its ` (deleted)` suffix: a dropper that unlinks
    /// itself is still judged by the directory it ran from. A forked child
    /// that never exec'd has no cache entry and answers through `/proc`.
    pub fn image_path(&self, pid: u32) -> Option<String> {
        self.image_path_as(pid, AsOf::Now)
    }

    /// [`Self::image_path`] of a record read right after the fact at
    /// `at_ns` ([`AsOf::Live`]; 0: now) — the pumps' and the drains'.
    pub fn image_path_at(&self, pid: u32, at_ns: u64) -> Option<String> {
        self.image_path_as(pid, AsOf::live(at_ns))
    }

    /// [`Self::image_path`] as of `as_of` (review #471 A1, R-F): an earlier
    /// exec when the latest came after the time, `None` when only later
    /// ones are cached; in a judgement ([`AsOf::Judged`]) `None` too when
    /// the cache holds none.
    pub fn image_path_as(&self, pid: u32, as_of: AsOf) -> Option<String> {
        if pid == 0 {
            return None;
        }
        match self.cached_live(pid, as_of.time()) {
            CachedAt::Current(e) | CachedAt::Past(e) => {
                return Some(e.exe.to_string_lossy().into_owned())
            }
            CachedAt::LaterOnly => return None,
            CachedAt::Absent if !self.judged_from_proc(pid, as_of) => {
                return self
                    .fork_entry(pid, as_of.time(), 0)
                    .map(|e| e.exe.to_string_lossy().into_owned());
            }
            CachedAt::Absent => {}
        }
        let exe = H::read_link(self.inner.proc_root.join(pid.to_string()).join("exe")).ok()?;
        Some(exe.to_string_lossy().into_owned())
    }

    /// R-F: whether a pid the spawn cache does not hold may be read from
    /// `/proc` as of `as_of` — outside a judgement only. In a judgement a
    /// process the cache does not hold is not known: `/proc` would show its
    /// present image, which it may have executed since the event (review of
    /// #475: a process older than the agent that reads a canary, then
    /// executes a backup tool, judged before that exec is read, was judged
    /// as the tool). The processes running when the agent starts are in
    /// the cache from the start's scan ([`Self::seed_from_proc`]), so the
    /// boot's daemons and a session older than a restart are known.
    fn judged_from_proc(&self, _pid: u32, as_of: AsOf) -> bool {
        !as_of.is_judged()
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

    fn lookup_cache(&self, pid: u32, as_of: AsOf) -> Option<(u32, PathBuf)> {
        match self.cached_at(pid, as_of.time()) {
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
        let text = H::read_state(&status_path).ok()?;
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

/// How a lineage walk ended ([`AuthSessionTracker::lineage_walk_to`]).
#[derive(Debug)]
enum WalkEnd {
    /// The hop the walk looked for.
    Found(Hop),
    /// PID 1 or 0: the lineage is whole.
    Root,
    /// Stopped before PID 1 (the depth cap, a later process at a parent's
    /// pid, a process its own parent): what is above is not known.
    Cut,
}

/// One hop of a lineage walk.
#[derive(Clone, Debug)]
struct Hop {
    pid: u32,
    ppid: u32,
    exe: PathBuf,
    /// Cached only: what an interpreter `exe` runs ([`Entry::runs`]).
    runs: Runs,
    /// From the spawn cache (the exec was seen), else from `/proc`.
    cached: bool,
    /// Cached only: when it executed `exe`, and its start.
    spawn_ns: u64,
    start_ns: u64,
    /// Lab PR 175: the real uid it executed `exe` as (cached), or runs as
    /// (`/proc`); `None` when `/proc` shows none.
    uid: Option<u32>,
    /// Lot 310 (the re-check of #539, N2): cached only, the process that
    /// forked it when its exec was the first since ([`Entry::fork_parent`]);
    /// 0 not known.
    fork_parent: u32,
    /// The review of #555 (F1): cached only, its exec has its image
    /// ([`Entry::image`]: `ROOT_DIR`, PID 1's mount namespace).
    rooted: bool,
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

/// Lot 278 (the third review of #493), lot 350: an exec whose identity a
/// fork of it that executed nothing may take from a later exec of its
/// parent's (the fork's window, [`AuthSessionTracker::fork_entry`]) — an
/// authentication binary run as itself: no interpreter, no script, no npm
/// entrypoint (what those run comes from an argv the process writes).
fn is_auth_monitor_identity(e: &Entry) -> bool {
    e.runs == Runs::Inline && e.js_pm.is_none() && !is_interpreter(&e.exe) && is_auth_binary(&e.exe)
}

fn is_elevation_binary(exe: &Path) -> bool {
    let s = exe.to_string_lossy();
    ELEVATION_EXES.iter().any(|p| s == *p)
}

/// Lot 351 (the review of #559, F2): the PAM helpers `pam_unix` runs as
/// root from inside sudo and su before their credential check is done
/// (the password's check, an expired password's change): a subset of
/// [`AUTH_BINARY_EXES`], by exact path.
const PAM_HELPER_EXES: &[&str] = &[
    "/sbin/unix_chkpwd",
    "/sbin/unix_update",
    "/usr/bin/unix_chkpwd",
    "/usr/sbin/unix_chkpwd",
    "/usr/sbin/unix_update",
];

fn is_pam_helper(exe: &Path) -> bool {
    let s = exe.to_string_lossy();
    PAM_HELPER_EXES.iter().any(|p| s == *p)
}

/// FP-2: exact-path match against the Node.js interpreter allowlist
/// ([`NODE_EXES`]). Same kernel-resolved-exe, never-`comm` keying as
/// [`is_system_daemon_binary`]. Gates [`AuthSessionTracker::is_npm_cli_writer`]
/// so a process-controlled argv is never the sole basis for the exemption.
/// Lot 340: the Go toolchain's `go` command at a distribution's or the
/// upstream archive's place, in a root-owned system tree: `/usr/lib/go/bin/go`,
/// `/usr/lib/go-<version>/bin/go` (Debian, Ubuntu), `/usr/local/go/bin/go`,
/// `/snap/go/<revision>/bin/go`.
fn is_go_toolchain(exe: &Path) -> bool {
    let e = exe.to_string_lossy();
    if !in_system_tree(&e) {
        return false;
    }
    if matches!(e.as_ref(), "/usr/lib/go/bin/go" | "/usr/local/go/bin/go") {
        return true;
    }
    let versioned = e
        .strip_prefix("/usr/lib/go-")
        .and_then(|r| r.strip_suffix("/bin/go"))
        .is_some_and(|v| !v.is_empty() && v.bytes().all(|b| b.is_ascii_digit() || b == b'.'));
    let snap = e
        .strip_prefix("/snap/go/")
        .and_then(|r| r.strip_suffix("/bin/go"))
        .is_some_and(|rev| !rev.is_empty() && !rev.contains('/'));
    versioned || snap
}

/// The review of #555 (F1): `e` executed the packaged `go` command — the
/// toolchain's path ([`is_go_toolchain`]) with its image ([`Entry::image`]:
/// `ROOT_DIR`, PID 1's mount namespace), run as itself. The path alone
/// names a file only in the namespace that resolved it.
fn runs_packaged_go(e: &Entry) -> bool {
    e.image.is_some() && e.runs == Runs::Inline && is_go_toolchain(&e.exe)
}

/// Lot 340: `path` (absolute, no `..`) lies in one of the Go toolchain's own
/// directories: a build's work directory (a segment `go-build` followed by
/// digits: `$TMPDIR/go-build4098838642/b031/_pkg_.a`), the build cache (a
/// `go-build` directory under `.cache`: `~/.cache/go-build/`) or the module
/// cache (`…/go/pkg/mod/`). The whole path is judged, every segment.
fn in_go_own_dir(path: &str) -> bool {
    if !path.starts_with('/') || path.split('/').any(|s| s == "..") {
        return false;
    }
    let segs: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
    let dirs = &segs[..segs.len().saturating_sub(1)];
    dirs.iter().enumerate().any(|(i, s)| {
        let work = s
            .strip_prefix("go-build")
            .is_some_and(|d| !d.is_empty() && d.bytes().all(|b| b.is_ascii_digit()));
        let cache = *s == "go-build" && i > 0 && dirs[i - 1] == ".cache";
        let modcache = *s == "mod" && i >= 2 && dirs[i - 1] == "pkg" && dirs[i - 2] == "go";
        work || cache || modcache
    })
}

/// Lot 346: `path` is a program the Go toolchain built in a build's work
/// directory and runs from there: `…/go-build<digits>/b<digits>/<name>`
/// (`go test`'s test binary) or `…/go-build<digits>/b<digits>/exe/<name>`
/// (`go run`'s). Absolute, every segment judged, no `.` or `..`.
fn in_go_work_dir(path: &str) -> bool {
    if !path.starts_with('/') || path.split('/').any(|s| s == ".." || s == ".") {
        return false;
    }
    let digits = |s: &str, p: &str| {
        s.strip_prefix(p)
            .is_some_and(|d| !d.is_empty() && d.bytes().all(|b| b.is_ascii_digit()))
    };
    let segs: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
    segs.iter().enumerate().any(|(i, s)| {
        digits(s, "go-build")
            && segs.get(i + 1).is_some_and(|b| digits(b, "b"))
            && matches!(&segs[(i + 2).min(segs.len())..], [_] | ["exe", _])
    })
}

/// Lot 346: `exe` is a packaged PostgreSQL server program — its directory
/// (a distribution's `/usr/lib/postgresql/<version>/bin`, PGDG's
/// `/usr/pgsql-<version>/bin`, or `/usr/bin`: each exactly, a version of
/// digits and dots, so no `..` and no other tree) and its name, `initdb` or
/// `postgres`.
fn is_postgres_bin(exe: &Path) -> Option<(&str, &str)> {
    let e = exe.to_str()?;
    let (dir, prog) = e.rsplit_once('/')?;
    if !matches!(prog, "initdb" | "postgres") {
        return None;
    }
    let version = |v: &str| !v.is_empty() && v.bytes().all(|b| b.is_ascii_digit() || b == b'.');
    let packaged = dir == "/usr/bin"
        || dir
            .strip_prefix("/usr/lib/postgresql/")
            .and_then(|r| r.strip_suffix("/bin"))
            .is_some_and(version)
        || dir
            .strip_prefix("/usr/pgsql-")
            .and_then(|r| r.strip_suffix("/bin"))
            .is_some_and(version);
    packaged.then_some((dir, prog))
}

fn is_node_exe(exe: &Path) -> bool {
    let s = exe.to_string_lossy();
    NODE_EXES.iter().any(|p| s == *p)
}

/// The package manager an exec of `exe` with `argv` runs, if any.
///
/// FP-2: node's `argv[1]` names npm's CLI ([`NPM_CLI_SUFFIX`]). Lot 340 (the
/// alpha's daily false positives): or, for a node of [`NODE_EXES`] (`exe`),
/// the link a package installs for it ([`NPM_CLI_LINKS`]). A shell runs
/// `npm` as `/usr/bin/npm`, a link to `../share/nodejs/npm/bin/npm-cli.js`
/// (Ubuntu, Debian; NodeSource's to `../lib/node_modules/npm/bin/npm-cli.js`);
/// the kernel hands the shebang's interpreter the path it was asked to
/// execute, so node's `argv[1]` is `/usr/bin/npm`. The review of #552 (F2):
/// the CLI by its suffix only in a root-owned system tree, named by an
/// absolute path ([`in_system_tree`], no `..`) — a package's own copy
/// (`node_modules/evil/npm/bin/npm-cli.js`), or one in a home, is the
/// caller's code under npm's name. The re-check of #552 (N1), lot 346: and
/// under `/usr` only — a Nix store path or a directory under `/opt` is any
/// user's to fill ([`NODE_PM_CLIS`]).
fn js_pm_of(exe: &Path, argv: &[String]) -> Option<JsPm> {
    let first = argv.get(1)?;
    // `in_system_tree` refuses a `..` segment (mutation r1: a second check
    // of it was equivalent)
    let installed = first.starts_with("/usr/") && in_system_tree(first);
    NODE_PM_CLIS
        .iter()
        .find(|(_, suffix, links)| {
            (installed && first.ends_with(suffix))
                || (is_node_exe(exe) && links.contains(&first.as_str()))
        })
        .map(|(pm, _, _)| *pm)
}

/// Lot 346 (the re-check of #552, N1): `path` (absolute, no `..`) is one
/// `pm` writes as its own work — a package tree (a directory segment
/// `node_modules`: a project's, a global prefix's), its cache in the
/// user's home, or a project's manifest or lockfile — and never a user's
/// document, whatever
/// code runs in the package manager's process:
///
/// - npm: `~/.npm/` (`_cacache`, `_logs`, `_npx`); `package.json`,
///   `package-lock.json`, `npm-shrinkwrap.json`.
fn in_js_pm_own_dir(pm: JsPm, path: &str) -> bool {
    if !path.starts_with('/') || path.split('/').any(|s| s == ".." || s == ".") {
        return false;
    }
    let segs: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
    let Some((leaf, dirs)) = segs.split_last() else {
        return false;
    };
    let dir = |d: &str| dirs.contains(&d);
    let (leaves, own): (&[&str], bool) = match pm {
        JsPm::Npm => (
            &["package.json", "package-lock.json", "npm-shrinkwrap.json"],
            dir(".npm"),
        ),
    };
    dir("node_modules") || own || leaves.contains(leaf)
}

/// Lot 310 (the review of #539, findings 2 and 7): what an exec pump's
/// facts (`common::wire::exe::exe_flags`) change in what an interpreter
/// runs: an environment that loads the caller's code before a named
/// script leaves the script named but not all that runs
/// ([`Runs::Unknown`]); an interpreter naming no program whose standard
/// input is no terminal runs its input ([`Runs::Code`]).
pub fn with_pump_facts(runs: Runs, exe: &Path, argv: &[String], flags: u32) -> Runs {
    use common::wire::exe::exe_flags::{ENV_LOADS, STDIN_PROGRAM};
    // the re-check of #539 (N9): busybox running one of its shells reads
    // a program as any shell does
    let reads = || super::script_args::reads_a_program(exe, argv);
    match runs {
        Runs::Script(s) if flags & ENV_LOADS != 0 => Runs::Unknown(Some(s)),
        Runs::Inline if flags & (ENV_LOADS | STDIN_PROGRAM) != 0 && reads() => Runs::Code,
        r => r,
    }
}

pub use super::script_args::argv_of_cmdline;

/// Review 85: interpreters, by exe basename (`python3.12`, `perl5.36`):
/// what they run is named by their arguments, not by their exe. Lot 292:
/// each family reads them with its own option table
/// ([`crate::posture::script_args`]).
///
/// Lot 310 (the review of #539, finding 11): busybox is no interpreter by
/// its executable — a binary of many programs, most of them no
/// interpreter (`wget`, `httpd`, `ntpd`); its shells are told by what an
/// identity runs ([`ExecIdentity::interprets`]).
pub fn is_interpreter(exe: &Path) -> bool {
    family_of(exe).is_some_and(|f| f != super::script_args::Family::Busybox)
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
    /// Second review of #471 (R-B): the history is three execs deep — an
    /// event followed by three more execs of its process is still judged on
    /// its own image; by four, "not known" (an exemption then does not
    /// apply, fail-closed; a rule that wants a positive image does not fire
    /// — the open R-B follow-up).
    #[test]
    fn the_history_is_three_execs_deep() {
        let proc = TempDir::new().unwrap();
        let t = AuthSessionTracker::new(proc.path());
        t.ingest_exec(4500, 1, "/tmp/.x/stager", &[], 10 * S, 9 * S, 1000);
        for (i, exe) in ["/usr/bin/a", "/usr/bin/b", "/usr/bin/c"]
            .iter()
            .enumerate()
        {
            t.ingest_exec(4500, 1, exe, &[], (20 + 10 * i as u64) * S, 9 * S, 1000);
        }
        assert_eq!(
            t.image_path_at(4500, 15 * S).as_deref(),
            Some("/tmp/.x/stager")
        );
        assert_eq!(t.image_path_at(4500, 25 * S).as_deref(), Some("/usr/bin/a"));
        t.ingest_exec(4500, 1, "/usr/bin/d", &[], 50 * S, 9 * S, 1000);
        assert_eq!(t.image_path_at(4500, 15 * S), None, "four later: not known");
        assert_eq!(t.image_path_at(4500, 25 * S).as_deref(), Some("/usr/bin/a"));
    }

    /// Second review of #471 (R2, R3): the time a judgement is scoped to is
    /// the event's own — a FIM record's (the canary detector makes a file
    /// canary's trip from it, judged in the same scope: the reader
    /// exemption), a flow's start (NET-008's image fallback) — not "now",
    /// which a later exec of the process has moved.
    #[test]
    fn a_fim_record_and_a_flow_are_judged_as_of_their_own_time() {
        let proc = TempDir::new().unwrap();
        let t = AuthSessionTracker::new(proc.path());
        t.ingest_exec(4600, 1, "/usr/bin/cat", &[], 10 * S, 9 * S, 1000);
        t.ingest_exec(4600, 1, "/usr/bin/restic", &[], 30 * S, 9 * S, 1000);
        let fim: nn_model::telemetry::FimEvent = serde_json::from_value(serde_json::json!({
            "timestamp_ns": 20 * S, "path": "/home/u/.ssh/id_backup", "op": 6,
            "new_sha256": null, "baseline_sha256": null, "modifier_exe": null,
            "modifier_pid": 4600, "modifier_uid": 1000, "modifier_comm": "cat"
        }))
        .unwrap();
        let fim = Event::Fim(fim);
        let readers = crate::canary::readers::CanaryReaders::new(Default::default(), t.clone());
        assert_eq!(
            readers.reader(4600, AsOf::Now).as_deref(),
            Some("/usr/bin/restic"),
            "now: the later exec"
        );
        assert_eq!(
            readers.reader(4600, AsOf::of_event(&fim)),
            None,
            "the trip from the FIM record: cat read it, no reader"
        );
        let mut flow: nn_model::telemetry::NetFlowEvent = serde_json::from_value(serde_json::json!({
            "start_ns": 20 * S, "end_ns": 21 * S, "family": 2, "src_addr": "10.0.2.15",
            "src_port": 40000, "dst_addr": "100.64.20.9", "dst_port": 443, "proto": 6,
            "pid": 4600, "uid": 1000, "comm": "cat", "exe": null, "proc_start_ns": 9 * S,
            "bytes_sent": 1, "bytes_recv": 1, "resolved_hostname": null, "tls_fingerprint": null,
            "flow_id": "f", "phase": "connect"
        }))
        .unwrap();
        flow.observed_ns = 25 * S;
        let flow = Event::NetFlow(flow);
        assert_eq!(
            t.image_path_as(4600, AsOf::of_event(&flow)).as_deref(),
            Some("/usr/bin/cat")
        );
    }

    /// Review #471 A1, a pid reused: the exec of the process the pid had
    /// before answers for a time before the current process started, never
    /// for a time the current one already ran (forked, not yet exec'd).
    #[test]
    fn a_reused_pid_s_earlier_process_answers_only_for_its_own_time() {
        let proc = TempDir::new().unwrap();
        let t = AuthSessionTracker::new(proc.path());
        t.ingest_exec(4400, 1, "/usr/bin/restic", &[], 2 * S, S, 0);
        t.ingest_exec(4400, 1, "/usr/bin/cat", &[], 40 * S, 30 * S, 1000);
        assert_eq!(
            t.image_path_at(4400, 5 * S).as_deref(),
            Some("/usr/bin/restic")
        );
        assert_eq!(
            t.image_path_at(4400, 35 * S),
            None,
            "the current process, before its exec"
        );
        assert_eq!(
            t.image_path_at(4400, 45 * S).as_deref(),
            Some("/usr/bin/cat")
        );
        assert_eq!(t.exec_identity(4400, AsOf::Judged(35 * S)), None);
    }

    /// R12b (R-F, second review of #471): inside a judgement a pid the
    /// spawn cache does not hold is not known — never `/proc`, which shows
    /// the present image (a reader that executed `restic` since, a dropper
    /// that executed `curl`): its identity, its image, a walk through it
    /// and every predicate on that walk. Now and a record read right after
    /// the fact (`Live`) still read `/proc`, as before.
    #[test]
    fn a_pid_the_cache_does_not_hold_is_not_known_inside_a_judgement() {
        let proc = TempDir::new().unwrap();
        write_exe(proc.path(), 4700, "/usr/bin/sudo");
        write_status(proc.path(), 4700, 1);
        write_exe(proc.path(), 4701, "/usr/bin/restic");
        write_status(proc.path(), 4701, 4700);
        let t = AuthSessionTracker::new(proc.path());
        let judged = AsOf::Judged(20 * S);
        // `/proc` answers now and for a record read after the fact
        for as_of in [AsOf::Now, AsOf::Live(20 * S)] {
            assert_eq!(
                t.exec_identity(4701, as_of).map(|i| i.exe),
                Some(PathBuf::from("/usr/bin/restic")),
                "{as_of:?}"
            );
            assert_eq!(
                t.image_path_as(4701, as_of).as_deref(),
                Some("/usr/bin/restic")
            );
            assert!(
                t.is_credential_reader(4700, as_of),
                "{as_of:?}: sudo, from /proc"
            );
            assert!(t.lineage_identities(4701, as_of).is_some());
        }
        // the judgement reads none of it
        assert_eq!(t.exec_identity(4701, judged), None);
        assert_eq!(t.image_path_as(4701, judged), None);
        assert!(!t.is_credential_reader(4700, judged));
        assert_eq!(
            t.lineage_identities(4701, judged),
            None,
            "the lineage not known"
        );
        assert_eq!(t.interactive_admin_status(4701, judged), None);
        // what the cache holds, it answers: the reader's own exec (cat) at
        // 10 s; its parent (only in `/proc`) not known, so no walk through it
        t.ingest_exec(4701, 4700, "/usr/bin/cat", &[], 10 * S, 9 * S, 1000);
        assert_eq!(
            t.exec_identity(4701, judged).map(|i| i.exe),
            Some(PathBuf::from("/usr/bin/cat"))
        );
        assert_eq!(
            t.lineage_identities(4701, judged),
            None,
            "its parent only in /proc: the walk stops, not known"
        );
        // an event without a time is judged now (nothing to scope)
        assert_eq!(AsOf::judged(0), AsOf::Now);
        assert_eq!(AsOf::live(0), AsOf::Now);
        assert_eq!(AsOf::judged(7), AsOf::Judged(7));
        assert_eq!(AsOf::live(7), AsOf::Live(7));
    }

    /// Review of #475 (R-F): in a judgement `/proc` never answers for a pid
    /// the cache does not hold, a process older than the agent included;
    /// the start's scan enters every running process instead, so the
    /// boot's daemons and an older session are known, and an exec it runs
    /// later is a later entry, the scanned image its past. The reviewer's
    /// case: a process older than the agent reads a canary, then executes a
    /// backup tool; the read, judged before that exec is read, is the old
    /// image's — never the tool's, as `/proc` shows it by then.
    #[test]
    fn a_process_older_than_the_agent_is_known_from_the_start_s_scan() {
        let proc = TempDir::new().unwrap();
        write_started(proc.path(), "self", 1, 500);
        // the session's shell, older than the agent; a tool started since
        write_exe(proc.path(), 4800, "/usr/bin/bash");
        write_status(proc.path(), 4800, 1);
        write_started(proc.path(), "4800", 1, 400);
        write_exe(proc.path(), 4801, "/usr/bin/restic");
        write_status(proc.path(), 4801, 4800);
        write_started(proc.path(), "4801", 4800, 600);
        let t = AuthSessionTracker::new(proc.path());
        let judged = AsOf::Judged(20 * S);
        assert_eq!(
            t.exec_identity(4800, judged),
            None,
            "not in the cache: not known, even older than the agent"
        );
        assert_eq!(t.image_path_as(4800, judged), None);
        assert_eq!(
            t.exec_identity(4800, AsOf::Now).map(|i| i.exe),
            Some(PathBuf::from("/usr/bin/bash")),
            "outside a judgement: /proc, as before"
        );
        // an exec seen since the attach is left alone by the scan
        t.ingest_exec(4801, 4800, "/usr/bin/restic", &[], 10 * S, 9 * S, 1000);
        assert_eq!(t.seed_from_proc(), 1, "the shell; the tool already held");
        assert_eq!(
            t.exec_identity(4800, judged).map(|i| i.exe),
            Some(PathBuf::from("/usr/bin/bash")),
            "the scanned shell"
        );
        let ids = t
            .lineage_identities(4801, judged)
            .expect("the walk reaches the scanned shell");
        assert!(
            ids.iter().any(|(_, i)| i.exe == Path::new("/usr/bin/bash")),
            "{ids:?}"
        );
        // the shell executes the backup tool after the read; the read is
        // judged before that exec is read: the shell's, not /proc's tool
        write_exe(proc.path(), 4800, "/usr/bin/restic");
        assert_eq!(
            t.exec_identity(4800, judged).map(|i| i.exe),
            Some(PathBuf::from("/usr/bin/bash")),
            "the image it ran, never the one /proc shows now"
        );
        // once that exec is read: before it the shell, after it the tool
        t.ingest_exec(4800, 1, "/usr/bin/restic", &[], 30 * S, 4 * S, 1000);
        assert_eq!(
            t.exec_identity(4800, judged).map(|i| i.exe),
            Some(PathBuf::from("/usr/bin/bash"))
        );
        assert_eq!(
            t.exec_identity(4800, AsOf::Judged(40 * S)).map(|i| i.exe),
            Some(PathBuf::from("/usr/bin/restic"))
        );
        // a deleted image is not entered; a second scan enters nothing new
        write_exe(proc.path(), 4802, "/tmp/x (deleted)");
        write_status(proc.path(), 4802, 1);
        write_started(proc.path(), "4802", 1, 450);
        assert_eq!(t.seed_from_proc(), 0);
        assert_eq!(t.exec_identity(4802, judged), None);
    }

    /// The reviewer's mutation K5: a process `/proc` shows started at the
    /// agent's own tick did not start before it (`p < o`, not `<=`) — a
    /// process the agent may have seen start is not taken for an older one.
    #[test]
    fn a_process_started_at_the_agent_s_tick_does_not_predate_it() {
        let proc = TempDir::new().unwrap();
        write_started(proc.path(), "self", 1, 500);
        write_started(proc.path(), "41", 1, 499);
        write_started(proc.path(), "42", 1, 500);
        write_started(proc.path(), "43", 1, 501);
        let t = AuthSessionTracker::new(proc.path());
        assert!(t.predates_observer(41));
        assert!(!t.predates_observer(42), "the same tick: not before");
        assert!(!t.predates_observer(43));
        assert!(!t.predates_observer(44), "not shown: not before");
    }

    /// R12b (R-F) with POS-003: in a judgement a cached exec of a pid that
    /// `/proc` shows reused answers for the event's time only when the
    /// process `/proc` shows started after it (the pid was reused since);
    /// a process that already ran at the event's time and is not the
    /// cached one is not known — never its `/proc` image.
    #[test]
    fn a_reused_pid_in_a_judgement_is_the_cached_exec_only_if_reused_after() {
        let proc = TempDir::new().unwrap();
        // the cached process started at 5 s and executed dpkg at 6 s
        let t = AuthSessionTracker::live_on(proc.path(), 0);
        t.ingest_exec(4800, 1, "/usr/bin/dpkg", &[], 6 * S, 5 * S, 0);
        write_exe(proc.path(), 4800, "/tmp/payload");
        write_status(proc.path(), 4800, 1);
        // `/proc` shows another process, started at 50 s (5 000 ticks of 10 ms)
        write_started(proc.path(), "4800", 1, 5_000);
        let walk_exe = |as_of| {
            t.lineage_identities(4800, as_of)
                .map(|l| l[0].1.exe.clone())
        };
        assert_eq!(
            walk_exe(AsOf::Judged(20 * S)),
            Some(PathBuf::from("/usr/bin/dpkg")),
            "reused after the event: the cached exec was the pid's then"
        );
        assert_eq!(
            walk_exe(AsOf::Now),
            Some(PathBuf::from("/tmp/payload")),
            "now: the present process (POS-003)"
        );
        // a process that started at 15 s, before the event at 20 s
        write_started(proc.path(), "4800", 1, 1_500);
        assert_eq!(
            walk_exe(AsOf::Judged(20 * S)),
            None,
            "it ran at the event's time and is not the cached one: not known"
        );
        assert!(!t.in_package_transaction(4800, AsOf::Judged(20 * S)));
        // R12b: the same, the agent started at 30 s — the process `/proc`
        // shows is older than the agent, but the cache holds an exec of the
        // pid that `/proc` contradicts: still not known (the older process's
        // exception is for a pid the cache does not hold)
        let t = AuthSessionTracker::live_on(proc.path(), 0);
        write_started(proc.path(), "self", 1, 3_000);
        t.ingest_exec(4800, 1, "/usr/bin/dpkg", &[], 6 * S, 5 * S, 0);
        assert_eq!(
            t.lineage_identities(4800, AsOf::Judged(20 * S))
                .map(|l| l[0].1.exe.clone()),
            None,
            "a cached exec /proc contradicts: not its /proc image"
        );
    }

    #[test]
    fn a_lookup_judged_at_an_event_s_time_sees_the_exec_of_then() {
        let proc = TempDir::new().unwrap();
        let t = AuthSessionTracker::new(proc.path());
        t.ingest_exec(4200, 1, "/usr/bin/cat", &[], 10 * S, 9 * S, 1000);
        t.ingest_exec(4200, 1, "/usr/bin/restic", &[], 20 * S, 9 * S, 1000);
        let exe = |id: Option<ExecIdentity>| id.map(|i| i.exe.to_string_lossy().into_owned());
        assert_eq!(
            exe(t.exec_identity(4200, AsOf::Now)).as_deref(),
            Some("/usr/bin/restic"),
            "now"
        );
        let at15 = AsOf::Judged(15 * S);
        assert_eq!(
            exe(t.exec_identity(4200, at15)).as_deref(),
            Some("/usr/bin/cat")
        );
        assert_eq!(t.image_path_as(4200, at15).as_deref(), Some("/usr/bin/cat"));
        // R-F: the time is each lookup's own — one at 25 s between two at
        // 15 s on the same thread answers its own, and leaves nothing behind
        assert_eq!(
            t.image_path_as(4200, AsOf::Judged(25 * S)).as_deref(),
            Some("/usr/bin/restic")
        );
        assert_eq!(t.image_path_as(4200, at15).as_deref(), Some("/usr/bin/cat"));
        let at5 = AsOf::Judged(5 * S);
        assert_eq!(t.exec_identity(4200, at5), None, "before every cached exec");
        assert_eq!(t.image_path_as(4200, at5), None);
        assert_eq!(
            t.image_path_at(4200, 15 * S).as_deref(),
            Some("/usr/bin/cat")
        );
        assert_eq!(
            exe(t.exec_identity(4200, AsOf::Now)).as_deref(),
            Some("/usr/bin/restic"),
            "now again: no time left behind"
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
            !t.in_package_transaction(4400, AsOf::live(15 * S)),
            "the write before dpkg"
        );
        assert!(
            t.in_package_transaction(4400, AsOf::live(21 * S)),
            "the run after it"
        );
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
        assert!(!t.is_auth_mediated(0, AsOf::Now));
    }

    #[test]
    fn pid_one_is_never_auth_mediated() {
        let t = AuthSessionTracker::new("/proc");
        // Even if some weirdness lands PID 1 in the cache, the
        // terminator short-circuit blocks it before the walk.
        assert!(!t.is_auth_mediated(1, AsOf::Now));
    }

    #[test]
    fn direct_sudo_pid_is_auth_mediated() {
        let t = AuthSessionTracker::new("/proc");
        t.ingest_spawn(100, 50, "/usr/bin/sudo", 1);
        assert!(t.is_auth_mediated(100, AsOf::Now));
    }

    #[test]
    fn lineage_starts_are_the_process_then_its_ancestors() {
        let proc = TempDir::new().unwrap();
        let t = AuthSessionTracker::new(proc.path());
        t.ingest_exec(100, 50, "/usr/bin/bash", &[], 10, 5, 1000);
        t.ingest_exec(200, 100, "/usr/bin/python3", &[], 20, 15, 1000);
        t.ingest_exec(300, 200, "/usr/bin/curl", &[], 30, 25, 1000);
        let got = t.lineage_starts(300, AsOf::Now);
        assert_eq!(
            got,
            vec![(300, 25), (200, 15), (100, 5)],
            "the cached starts"
        );
        assert_eq!(
            t.lineage_starts(100, AsOf::Now)
                .iter()
                .map(|(p, _)| *p)
                .collect::<Vec<_>>(),
            vec![100]
        );
        assert!(t.lineage_starts(999, AsOf::Now).is_empty(), "not known");
        assert!(t.lineage_starts(1, AsOf::Now).is_empty(), "init");
    }

    #[test]
    fn subprocess_of_sudo_is_auth_mediated_via_lineage() {
        let t = AuthSessionTracker::new("/proc");
        t.ingest_spawn(100, 50, "/usr/bin/sudo", 1);
        t.ingest_spawn(200, 100, "/usr/bin/apt", 2);
        assert!(t.is_auth_mediated(200, AsOf::Now));
    }

    // ── (ii) — system package-management daemon lineage ─────────────

    #[test]
    fn direct_snapd_daemon_is_system_daemon_mediated() {
        let t = AuthSessionTracker::new("/proc");
        // snapd daemon, parented by systemd (pid 1).
        t.ingest_spawn(1096, 1, "/usr/lib/snapd/snapd", 1);
        assert!(t.is_system_daemon_mediated(1096, AsOf::Now));
        // Disjoint from the auth allowlist — snapd is not a setuid admin
        // binary, so it must NOT also read as auth-mediated.
        assert!(!t.is_auth_mediated(1096, AsOf::Now));
    }

    #[test]
    fn mandb_is_system_daemon_mediated() {
        let t = AuthSessionTracker::new("/proc");
        t.ingest_spawn(3096, 1, "/usr/bin/mandb", 1);
        assert!(t.is_system_daemon_mediated(3096, AsOf::Now));
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
        assert!(
            t.is_package_transaction_write(300, AsOf::live(b + 2 * S)),
            "dpkg runs"
        );
        assert!(t.is_package_transaction_write(200, AsOf::live(b + 2 * S)));
        // dpkg exits: its sh is covered for 30 s after dpkg was last seen
        fs::remove_dir_all(tmp.path().join("200")).unwrap();
        assert!(t.is_package_transaction_write(300, AsOf::live(b + 32 * S)));
        assert!(!t.is_package_transaction_write(300, AsOf::live(b + 33 * S)));
        assert!(
            t.is_system_daemon_mediated(300, AsOf::Now),
            "the wide predicate (the walk's tests only, lab PR 175)"
        );
        // a new dpkg in the pid, never seen running: its exec + 60 s
        t.ingest_exec(200, 1, "/usr/bin/dpkg", &[], b + 100 * S, b + 100 * S, 0);
        t.ingest_exec(301, 200, "/bin/sh", &[], b + 101 * S, b + 101 * S, 0);
        assert!(t.is_package_transaction_write(301, AsOf::live(b + 160 * S)));
        assert!(!t.is_package_transaction_write(301, AsOf::live(b + 161 * S)));
        // the pid now names a later process (a fork, no exec event)
        write_started(tmp.path(), "200", 1, ticks(b + 200 * S));
        write_exe(tmp.path(), 200, "/usr/bin/bash");
        write_status(tmp.path(), 200, 1);
        assert!(!t.is_package_transaction_write(301, AsOf::live(b + 120 * S)));
        // mandb: not a package manager
        t.ingest_exec(910, 1, "/usr/bin/mandb", &[], b, b, 0);
        t.ingest_exec(920, 910, "/usr/bin/crontab", &[], b + S, b + S, 0);
        write_started(tmp.path(), "910", 1, ticks(b));
        assert!(t.is_system_daemon_mediated(920, AsOf::Now));
        assert!(!t.is_package_transaction_write(920, AsOf::live(b + 2 * S)));
        assert!(!t.is_package_transaction_write(910, AsOf::live(b + 2 * S)));
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
        assert!(
            t.is_system_daemon_mediated(201, AsOf::Now),
            "the wide predicate"
        );
        assert!(!t.in_package_transaction(201, AsOf::live(3 * S)));
        assert!(!t.is_package_transaction_write(201, AsOf::live(3 * S)));
        assert!(!t.in_package_transaction(200, AsOf::live(3 * S)));
        // root's dpkg, the same shape: a transaction, for its children
        // whatever they run as (apt's methods drop to `_apt`)
        t.ingest_exec(300, 100, "/usr/bin/dpkg", &[], S, S, 0);
        t.ingest_exec(301, 300, "/tmp/helper", &[], 2 * S, 2 * S, 0);
        t.ingest_exec(302, 300, "/usr/lib/apt/methods/http", &[], 2 * S, 2 * S, 42);
        fs::create_dir_all(tmp.path().join("300")).unwrap();
        assert!(t.in_package_transaction(301, AsOf::live(3 * S)));
        assert!(t.in_package_transaction(302, AsOf::live(3 * S)));
        // the nearest package manager answers: root's apt above a user's
        // dpkg does not cover what that dpkg forked
        t.ingest_exec(400, 1, "/usr/bin/apt-get", &[], S, S, 0);
        t.ingest_exec(410, 400, "/usr/bin/dpkg", &[], 2 * S, 2 * S, 1000);
        t.ingest_exec(411, 410, "/tmp/payload", &[], 3 * S, 3 * S, 1000);
        fs::create_dir_all(tmp.path().join("400")).unwrap();
        fs::create_dir_all(tmp.path().join("410")).unwrap();
        assert!(!t.in_package_transaction(411, AsOf::live(4 * S)));
        // known from /proc only: its status's real uid
        write_exe(tmp.path(), 500, "/usr/bin/apt-get");
        write_status_uid(tmp.path(), 500, 1, 0);
        assert!(t.in_package_transaction(500, AsOf::live(3 * S)));
        write_exe(tmp.path(), 510, "/usr/bin/apt-get");
        write_status_uid(tmp.path(), 510, 1, 1000);
        assert!(!t.in_package_transaction(510, AsOf::live(3 * S)));
        write_exe(tmp.path(), 520, "/usr/bin/apt-get");
        write_status(tmp.path(), 520, 1);
        assert!(
            !t.in_package_transaction(520, AsOf::live(3 * S)),
            "no Uid line"
        );
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
        assert!(t.in_package_transaction(201, AsOf::live(3)));
        assert!(!t.in_package_transaction(201, AsOf::live(0)));
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
        assert!(
            t.is_system_man_cache_writer(910, AsOf::Now),
            "man-db's timer, as man"
        );
        assert!(t.is_system_man_cache_writer(930, AsOf::Now), "as root");
        assert!(!t.is_system_man_cache_writer(911, AsOf::Now), "its child");
        assert!(
            !t.is_system_man_cache_writer(920, AsOf::Now),
            "a user's mandb"
        );
        assert!(
            !t.in_package_transaction(910, AsOf::live(2 * S)),
            "not a package manager"
        );
        assert!(!t.in_package_transaction(911, AsOf::live(2 * S)));
        // a child it forked without exec: /proc names mandb, and its uid
        write_exe(tmp.path(), 940, "/usr/bin/mandb");
        write_status_uid(tmp.path(), 940, 920, 1000);
        assert!(!t.is_system_man_cache_writer(940, AsOf::Now));
        write_exe(tmp.path(), 950, "/usr/bin/mandb");
        write_status_uid(tmp.path(), 950, 910, 6);
        assert!(t.is_system_man_cache_writer(950, AsOf::Now));
        assert!(!t.is_system_man_cache_writer(0, AsOf::Now));
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
        assert!(t.is_user_container_storage_write(700, AsOf::live(2 * S), storage, false));
        assert!(!t.is_user_container_storage_write(
            700,
            AsOf::live(2 * S),
            "/home/nn/Documents/a",
            false
        ));
        assert!(
            !t.is_user_container_storage_write(800, AsOf::live(2 * S), storage, false),
            "root's: the transaction"
        );
        assert!(
            !t.is_user_container_storage_write(700, AsOf::live(120 * S), storage, false),
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
                !t.is_user_container_storage_write(700, AsOf::live(2 * S), p, p == "/usr/lib/x"),
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
        assert!(t.is_user_container_storage_write(
            700,
            AsOf::live(2 * S),
            "mnt[0:77:2]/usr/lib/x",
            false
        ));
        assert!(t.is_user_container_storage_write(
            700,
            AsOf::live(2 * S),
            "…/site-packages/x.pyc",
            false
        ));
        assert!(t.is_user_container_storage_write(700, AsOf::live(2 * S), "/usr/lib/x", true));
        assert!(!t.is_user_container_storage_write(
            700,
            AsOf::live(2 * S),
            "mnt[0:78:2]/report.docx",
            false
        ));
        assert!(!t.is_user_container_storage_write(
            700,
            AsOf::live(2 * S),
            "/home/nn/Documents/a",
            false
        ));
        // rooted in the user's documents: nothing but placed storage paths
        fs::write(
            procs.path().join("700/mountinfo"),
            "900 800 0:77 / / rw - overlay overlay rw,lowerdir=/x,upperdir=/home/nn/Documents/up,workdir=/home/nn/Documents/w\n",
        )
        .unwrap();
        assert!(!t.is_user_container_storage_write(
            700,
            AsOf::live(2 * S),
            "mnt[0:77:2]/report.docx",
            false
        ));
        // init's own namespace
        fs::remove_file(procs.path().join("700/ns/mnt")).unwrap();
        symlink("mnt:[4026531841]", procs.path().join("700/ns/mnt")).unwrap();
        assert!(!t.is_user_container_storage_write(700, AsOf::live(2 * S), "/usr/lib/x", true));
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
        assert!(t.is_system_daemon_mediated(401, AsOf::Now));
    }

    #[test]
    fn non_daemon_pid_is_not_system_daemon_mediated() {
        let t = AuthSessionTracker::new("/proc");
        // A Python interpreter — how `unattended-upgrade` actually
        // resolves via /proc/<pid>/exe — is NOT in the allowlist (exact
        // exec-path match, never comm/argv). Nor is a plain shell.
        t.ingest_spawn(200, 50, "/usr/bin/python3.12", 1);
        t.ingest_spawn(50, 1, "/bin/bash", 0);
        assert!(!t.is_system_daemon_mediated(200, AsOf::Now));
    }

    #[test]
    fn sudo_pid_is_not_system_daemon_mediated() {
        // Cross-grant guard: an auth-mediated (sudo) PID must NOT be
        // treated as a system daemon. The two allowlists are disjoint.
        let t = AuthSessionTracker::new("/proc");
        t.ingest_spawn(100, 50, "/usr/bin/sudo", 1);
        assert!(t.is_auth_mediated(100, AsOf::Now));
        assert!(!t.is_system_daemon_mediated(100, AsOf::Now));
    }

    // ── review 49 — RHEL package managers + eviction-proof daemon cache ──

    #[test]
    fn rpm_and_dnf_scriptlets_are_system_daemon_mediated() {
        let tmp = TempDir::new().unwrap();
        let t = AuthSessionTracker::new(tmp.path());
        // `rpm -i`: an ELF, its %post scriptlet runs under /bin/sh.
        t.ingest_spawn(500, 1, "/usr/bin/rpm", 1);
        t.ingest_spawn(501, 500, "/bin/sh", 2);
        assert!(t.is_system_daemon_mediated(501, AsOf::Now));
        // `dnf install`: the exec event carries the script path, so the
        // cache names dnf even though /proc/<pid>/exe is the interpreter.
        t.ingest_spawn(600, 1, "/usr/bin/dnf", 3);
        t.ingest_spawn(601, 600, "/usr/bin/systemctl", 4);
        assert!(t.is_system_daemon_mediated(600, AsOf::Now));
        assert!(t.is_system_daemon_mediated(601, AsOf::Now));
    }

    #[test]
    fn dnf_seen_only_through_proc_is_not_trusted() {
        // Without the spawn, /proc shows the interpreter: no match, and
        // cmdline is never consulted (a process can rewrite its own).
        let tmp = TempDir::new().unwrap();
        write_exe(tmp.path(), 700, "/usr/bin/python3.9");
        write_status(tmp.path(), 700, 1);
        let t = AuthSessionTracker::new(tmp.path());
        assert!(!t.is_system_daemon_mediated(700, AsOf::Now));
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
            t.is_system_daemon_mediated(600, AsOf::Now),
            "dnf evicted from the side cache"
        );
        assert!(t.is_system_daemon_mediated(10_000 + TRACKER_CAP as u32 + 99, AsOf::Now));
    }

    #[test]
    fn pid_reuse_by_another_program_drops_the_daemon_copy() {
        let tmp = TempDir::new().unwrap();
        let t = AuthSessionTracker::new(tmp.path());
        t.ingest_spawn(800, 1, "/usr/bin/dpkg", 1);
        assert!(t.is_system_daemon_mediated(800, AsOf::Now));
        t.ingest_spawn(800, 1, "/usr/bin/bash", 2);
        assert!(!t.is_system_daemon_mediated(800, AsOf::Now));
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
        assert!(t.is_system_daemon_mediated(124, AsOf::Now));
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

    /// Lot 346 (the re-check of #552, N1): an exec of `exe` with `argv`,
    /// with the image the kernel or the pump gave it (`ROOT_DIR`: executed
    /// from a root-only directory, in PID 1's mount namespace) when
    /// `rooted`, else the LSM identity alone (another mount namespace).
    fn ingest_exec_of(t: &AuthSessionTracker, pid: u32, exe: &str, argv: &[String], rooted: bool) {
        use common::wire::exe::exe_flags::{KNOWN, ROOT_DIR};
        let _ = t.ingest_spawn_event(&Event::ProcessSpawn {
            pid,
            ppid: 50,
            uid: 1000,
            gid: 1000,
            comm: "node".into(),
            filename: exe.into(),
            timestamp_ns: 1,
            argv: argv.to_vec(),
            parent_comm: String::new(),
            parent_start_ns: 0,
            start_ns: 1,
            parent_is_kthread: false,
            exe: nn_model::ExeIdentity {
                path: exe.into(),
                dev: 2049,
                ino: u64::from(pid),
                flags: if rooted { KNOWN | ROOT_DIR } else { KNOWN },
                ..Default::default()
            },
            argv_truncated: false,
            filename_truncated: false,
            stdio: Default::default(),
        });
    }

    #[test]
    fn node_running_npm_cli_is_npm_cli_writer() {
        let t = AuthSessionTracker::new("/proc");
        // node interpreter running npm's CLI entrypoint (lot 346: its
        // image recorded, as every exec the kernel reports).
        ingest_exec_of(
            &t,
            7000,
            "/usr/bin/node",
            &npm_argv(&["install", "-g", "x"]),
            true,
        );
        assert!(t.is_npm_cli_writer(7000, AsOf::Now));
        // It is NOT auth- or system-daemon-mediated (disjoint signals).
        assert!(!t.is_auth_mediated(7000, AsOf::Now));
        assert!(!t.is_system_daemon_mediated(7000, AsOf::Now));
    }

    #[test]
    fn node_not_running_npm_is_not_npm_cli_writer() {
        let t = AuthSessionTracker::new("/proc");
        // Same node binary, but running some OTHER script → not exempt.
        let argv = vec!["node".to_string(), "/home/u/evil.js".to_string()];
        t.ingest_spawn_with_argv(7001, 50, "/usr/bin/node", &argv, 1);
        assert!(!t.is_npm_cli_writer(7001, AsOf::Now));
    }

    #[test]
    fn npm_argv_under_non_node_exe_is_not_npm_cli_writer() {
        let t = AuthSessionTracker::new("/proc");
        // argv spoofs npm-cli.js but the exe is NOT the node interpreter
        // (the non-forgeable half) → not exempt.
        t.ingest_spawn_with_argv(7002, 50, "/tmp/evil", &npm_argv(&["install"]), 1);
        assert!(!t.is_npm_cli_writer(7002, AsOf::Now));
        // lot 346 (mutation r1): with an image too — another interpreter
        // in a system tree naming npm's CLI by its suffix
        ingest_exec_of(&t, 7006, "/usr/bin/python3", &npm_argv(&["install"]), true);
        assert!(!t.is_npm_cli_writer(7006, AsOf::Now));
    }

    #[test]
    fn npm_cli_writer_is_cache_only_no_proc_fallback() {
        // A pid never ingested (cache miss) is not exempt even if /proc
        // would resolve it — fail toward detection.
        let t = AuthSessionTracker::new("/proc");
        assert!(!t.is_npm_cli_writer(7003, AsOf::Now));
        // pid 1 / 0 are never npm.
        assert!(!t.is_npm_cli_writer(1, AsOf::Now));
        assert!(!t.is_npm_cli_writer(0, AsOf::Now));
    }

    #[test]
    fn npm_cli_flag_matches_a_global_prefix_path_too() {
        // npm-cli.js can live under a global prefix (an upstream archive's
        // or NodeSource's `/usr/local/lib`, Debian's `/usr/share/nodejs`).
        // The review of #552 (F2): a root-owned one — a user prefix in a
        // home is writable by the postinstall the exemption guards against
        // (`npm_cli_flag_refuses_a_path_a_user_can_write`).
        let t = AuthSessionTracker::new("/proc");
        for (pid, path) in [
            (7004, "/usr/local/lib/node_modules/npm/bin/npm-cli.js"),
            (7008, "/usr/share/nodejs/npm/bin/npm-cli.js"),
        ] {
            let argv = vec!["node".to_string(), path.to_string()];
            ingest_exec_of(&t, pid, "/usr/bin/node", &argv, true);
            assert!(t.is_npm_cli_writer(pid, AsOf::Now), "{path}");
        }
    }

    /// Named test (the review of #552, F2): npm's CLI by its suffix only in
    /// a root-owned system tree, by an absolute path — never a package's
    /// own copy, a user prefix in a home, a relative path or one leaving a
    /// system tree through `..`.
    #[test]
    fn npm_cli_flag_refuses_a_path_a_user_can_write() {
        let t = AuthSessionTracker::new("/proc");
        for (pid, path) in [
            (7020, "/home/u/p/node_modules/evil/npm/bin/npm-cli.js"),
            (
                7021,
                "/home/alice/.npm-global/lib/node_modules/npm/bin/npm-cli.js",
            ),
            (7022, "/tmp/npm/bin/npm-cli.js"),
            (7023, "node_modules/npm/bin/npm-cli.js"),
            (7024, "/usr/lib/../../home/u/npm/bin/npm-cli.js"),
        ] {
            let argv = vec!["node".to_string(), path.to_string()];
            t.ingest_spawn_with_argv(pid, 50, "/usr/bin/node", &argv, 1);
            assert!(!t.is_npm_cli_writer(pid, AsOf::Now), "{path}");
        }
    }

    /// Named test (lot 346, the re-check of #552, N1): npm's CLI is npm's
    /// only from `/usr` and from a node executed in PID 1's mount namespace
    /// out of a root-only directory — not a Nix store path or a directory
    /// under `/opt` any user may fill, not a node a user's namespace binds
    /// a file over (no `ROOT_DIR`), not an exec the agent has no image of.
    #[test]
    fn npm_is_npm_only_from_usr_and_a_rooted_node() {
        let t = AuthSessionTracker::new("/proc");
        for (pid, path, rooted) in [
            (
                7030,
                "/nix/store/0abc-nodejs-20/lib/node_modules/npm/bin/npm-cli.js",
                true,
            ),
            (7031, "/opt/dev/lib/node_modules/npm/bin/npm-cli.js", true),
            (7032, "/usr/share/nodejs/npm/bin/npm-cli.js", false),
            (7033, "/usr/bin/npm", false),
        ] {
            let argv = vec!["node".to_string(), path.to_string(), "init".to_string()];
            ingest_exec_of(&t, pid, "/usr/bin/node", &argv, rooted);
            assert!(!t.is_npm_cli_writer(pid, AsOf::Now), "{path} {rooted}");
        }
        // the plain ingest (no identity at all) names no package manager
        t.ingest_spawn_with_argv(7034, 50, "/usr/bin/node", &npm_argv(&["ci"]), 1);
        assert!(!t.is_npm_cli_writer(7034, AsOf::Now));
        ingest_exec_of(&t, 7035, "/usr/bin/node", &npm_argv(&["ci"]), true);
        assert!(t.is_npm_cli_writer(7035, AsOf::Now));
    }

    /// Named test (lot 346, the re-check of #552, N1): npm's exemption is
    /// its own directories — a package tree, `~/.npm`, a manifest or
    /// lockfile — and never a user's document, whatever runs in npm
    /// (`~/.npm-init.js`); the other package managers' own places are not
    /// npm's.
    #[test]
    fn npm_s_own_writes_are_its_directories_only() {
        let t = AuthSessionTracker::new("/proc");
        ingest_exec_of(&t, 7040, "/usr/bin/node", &npm_argv(&["init", "-y"]), true);
        let now = AsOf::Now;
        for own in [
            "/home/u/p/node_modules/lodash/lodash.js",
            "/home/u/p/node_modules/.package-lock.json",
            "/usr/local/lib/node_modules/typescript/lib/tsc.js",
            "/home/u/.npm/_cacache/content-v2/sha512/ab/cd/ef",
            "/home/u/.npm/_logs/2026-11-13T21_00_00_000Z-debug-0.log",
            "/home/u/p/package-lock.json",
            "/home/u/p/package.json",
            "/root/.npm/_cacache/index-v5/aa/bb",
        ] {
            assert_eq!(t.js_pm_own_write(7040, now, own), Some(JsPm::Npm), "{own}");
        }
        for not_own in [
            "/home/u/Documents/thesis.odt",
            "/home/u/.npm-init.js",
            "/home/u/p/src/index.js",
            "/home/u/.cache/yarn/v6/npm-x/index.js",
            "/home/u/.local/share/pnpm/store/v3/files/00/aa",
            "/home/u/p/node_modules/../../Documents/a.pdf",
            "/home/u/p/./node_modules/a",
            "node_modules/a/index.js",
            "/home/u/p/node_modules",
            "/home/u/p/yarn.lock",
        ] {
            assert_eq!(t.js_pm_own_write(7040, now, not_own), None, "{not_own}");
        }
    }

    /// The review of #555 (F2): yarn, pnpm and bun are no exempt package
    /// manager — they load a project's code in their own process
    /// (`.pnpmfile.cjs`, yarn berry's plugins, corepack's download), which
    /// can put the window's crossing in `node_modules`. Lot 346's packaged
    /// identities (node running their CLI from `/usr` or a packaged link,
    /// bun's binary in a system tree running an install) and what was never
    /// one are judged as any process.
    #[test]
    fn yarn_pnpm_and_bun_are_no_exempt_package_manager() {
        let t = AuthSessionTracker::new("/proc");
        let argv = |a: &[&str]| a.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        let now = AsOf::Now;
        for (pid, exe, args, own) in [
            (
                7050,
                "/usr/bin/node",
                &["node", "/usr/bin/yarnpkg", "install"][..],
                "/home/u/p/node_modules/lodash/package.json",
            ),
            (
                7051,
                "/usr/bin/node",
                &["node", "/usr/local/bin/yarn"][..],
                "/home/u/p/node_modules/x/index.js",
            ),
            (
                7052,
                "/usr/local/bin/node",
                &[
                    "node",
                    "/usr/local/lib/node_modules/yarn/bin/yarn.js",
                    "add",
                    "x",
                ][..],
                "/home/u/p/node_modules/x/index.js",
            ),
            (
                7053,
                "/usr/bin/node",
                &["node", "/usr/local/bin/pnpm", "install"][..],
                "/home/u/p/package.json",
            ),
            (
                7054,
                "/usr/bin/node",
                &["node", "/usr/lib/node_modules/pnpm/bin/pnpm.cjs", "i"][..],
                "/home/u/p/node_modules/.pnpm/lodash@4.17.21/node_modules/lodash/a.js",
            ),
            (
                7055,
                "/usr/local/lib/node_modules/bun/bin/bun.exe",
                &["bun", "install"][..],
                "/home/u/p/node_modules/lodash/a.js",
            ),
            (
                7056,
                "/usr/local/bin/bun",
                &["bun", "add", "x"][..],
                "/home/u/p/package.json",
            ),
            (
                7060,
                "/usr/local/lib/node_modules/bun/bin/bun.exe",
                &["bun", "run", "x.ts"][..],
                "/home/u/p/node_modules/x/index.js",
            ),
            (
                7063,
                "/home/u/.bun/bin/bun",
                &["bun", "install"][..],
                "/home/u/p/node_modules/x/index.js",
            ),
            (
                7064,
                "/home/u/.local/share/pnpm/pnpm",
                &["pnpm", "install"][..],
                "/home/u/p/node_modules/x/index.js",
            ),
            (
                7065,
                "/usr/bin/node",
                &["node", "/home/u/p/.yarn/releases/yarn-4.5.0.cjs", "install"][..],
                "/home/u/p/node_modules/x/index.js",
            ),
            (
                7067,
                "/usr/bin/python3",
                &["python3", "/usr/bin/yarn"][..],
                "/home/u/p/node_modules/x/index.js",
            ),
        ] {
            ingest_exec_of(&t, pid, exe, &argv(args), true);
            assert_eq!(t.js_pm_writer(pid, now), None, "{args:?}");
            assert_eq!(t.js_pm_own_write(pid, now, own), None, "{args:?} {own}");
            assert!(!t.is_npm_cli_writer(pid, now), "{args:?}");
        }
    }

    #[test]
    fn plain_ingest_spawn_leaves_npm_flag_false() {
        // The argv-less ingest path must never set the npm flag.
        let t = AuthSessionTracker::new("/proc");
        t.ingest_spawn(7005, 50, "/usr/bin/node", 1);
        assert!(!t.is_npm_cli_writer(7005, AsOf::Now));
    }

    #[test]
    fn nested_sudo_chain_is_auth_mediated_at_depth() {
        let t = AuthSessionTracker::new("/proc");
        // user shell (50) -> sudo (100) -> bash (200) -> apt (300).
        t.ingest_spawn(100, 50, "/usr/bin/sudo", 1);
        t.ingest_spawn(200, 100, "/bin/bash", 2);
        t.ingest_spawn(300, 200, "/usr/bin/apt", 3);
        assert!(t.is_auth_mediated(300, AsOf::Now));
    }

    #[test]
    fn unrelated_pid_with_no_auth_ancestor_is_not_auth_mediated() {
        let t = AuthSessionTracker::new("/proc");
        // user shell (50) -> firefox (200). No sudo anywhere.
        t.ingest_spawn(200, 50, "/usr/bin/firefox", 1);
        t.ingest_spawn(50, 1, "/bin/bash", 0);
        assert!(!t.is_auth_mediated(200, AsOf::Now));
    }

    #[test]
    fn pid_reuse_invalidates_lineage() {
        let t = AuthSessionTracker::new("/proc");
        t.ingest_spawn(100, 50, "/usr/bin/sudo", 1);
        assert!(t.is_auth_mediated(100, AsOf::Now));
        // Same PID re-spawned as something innocuous; lineage drops.
        t.ingest_spawn(100, 50, "/bin/cat", 2);
        // Parent pid=50 has no entry; lookup_proc on templess "/proc"
        // for pid 50 will fail; net result: not auth-mediated.
        assert!(!t.is_auth_mediated(100, AsOf::Now));
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
        assert!(t.is_auth_mediated(124, AsOf::Now));
        assert!(t.is_auth_mediated(123, AsOf::Now));

        // External audit POS-003: a sudo seen only in /proc that started
        // after the agent (its exec event lost or evicted) vouches for
        // nothing below it; itself, it still runs sudo.
        write_started(proc_root, "123", 1, 600);
        write_started(proc_root, "124", 123, 700);
        let t = AuthSessionTracker::new(proc_root);
        assert!(!t.is_auth_mediated(124, AsOf::Now));
        assert!(t.is_auth_mediated(123, AsOf::Now));
    }

    // ── Test #12: /proc unavailable returns false ───────────────────
    #[test]
    fn proc_unavailable_returns_false_on_miss() {
        let tmp = TempDir::new().unwrap();
        // proc_root points at an empty tempdir — every readlink fails.
        let t = AuthSessionTracker::new(tmp.path());
        assert!(!t.is_auth_mediated(99_999, AsOf::Now));
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
        assert!(!t.is_auth_mediated(123, AsOf::Now));
    }

    // ── Test #14 (review of #475): the map's bounds by process lifetime ──
    /// Past the soft bound only the entries of processes the sweep found
    /// gone are dropped (after their grace), never a live process's for
    /// newer ones; past the hard bound the oldest goes, counted.
    #[test]
    fn the_map_drops_gone_processes_never_a_live_one_for_newer_ones() {
        let proc = TempDir::new().unwrap();
        write_exe(proc.path(), 500, "/usr/sbin/clamd");
        write_status(proc.path(), 500, 1);
        write_started(proc.path(), "500", 1, 100);
        let t =
            AuthSessionTracker::new(proc.path()).with_bounds(64, 1024, std::time::Duration::ZERO);
        assert_eq!(t.seed_from_proc(), 1);
        // 300 other processes execute and exit (no /proc entry)
        for i in 0..300u64 {
            t.ingest_exec(
                10_000 + i as u32,
                1,
                "/usr/bin/true",
                &[],
                (10 + i) * S,
                (10 + i) * S,
                0,
            );
        }
        assert_eq!(t.entry_count(), 301, "nothing known gone yet: all kept");
        let report = t.sweep();
        assert_eq!(report.gone, 300);
        assert_eq!(
            report.entries, 64,
            "the gone ones dropped to the soft bound"
        );
        assert_eq!(report.evicted_live, 0);
        assert_eq!(
            t.exec_identity(500, AsOf::Judged(400 * S)).map(|i| i.exe),
            Some(PathBuf::from("/usr/sbin/clamd")),
            "the live daemon stays known"
        );
        // the hard bound: the oldest entry goes, live or not, counted
        let hard =
            AuthSessionTracker::new(proc.path()).with_bounds(4, 8, std::time::Duration::ZERO);
        for pid in 1..=10u32 {
            hard.ingest_spawn(pid + 100, 1, "/usr/bin/cat", u64::from(pid));
        }
        assert_eq!(hard.entry_count(), 8);
        assert_eq!(hard.evicted_live(), 2);
        // a grace not passed keeps a gone process's entry
        let graced = AuthSessionTracker::new(proc.path()).with_bounds(
            1,
            1024,
            std::time::Duration::from_secs(3600),
        );
        for pid in 1..=5u32 {
            graced.ingest_spawn(pid + 200, 1, "/usr/bin/cat", u64::from(pid));
        }
        assert_eq!(graced.sweep().entries, 5, "gone, still in their grace");
    }

    /// Review of #475: the reviewer's case at the agent's own bounds — a
    /// daemon the start's scan entered stays known after 2,100 execs of
    /// other processes (and a sweep that found them gone, in their grace).
    #[test]
    fn a_seeded_daemon_stays_known_after_2100_other_execs() {
        let proc = TempDir::new().unwrap();
        write_exe(proc.path(), 500, "/usr/sbin/clamd");
        write_status(proc.path(), 500, 1);
        write_started(proc.path(), "500", 1, 100);
        let t = AuthSessionTracker::new(proc.path());
        assert_eq!(t.seed_from_proc(), 1);
        for i in 0..2_100u64 {
            t.ingest_exec(
                10_000 + i as u32,
                1,
                "/usr/bin/true",
                &[],
                (10 + i) * S,
                (10 + i) * S,
                0,
            );
        }
        let report = t.sweep();
        assert_eq!(report.gone, 2_100);
        assert_eq!(
            t.exec_identity(500, AsOf::Judged(3_000 * S)).map(|i| i.exe),
            Some(PathBuf::from("/usr/sbin/clamd"))
        );
    }

    /// Review of #475: in a judgement, a fork that never executed (a
    /// maintainer script's subshell) is its parent's image as of its start
    /// when `/proc/<pid>/exe` is still that file — the package carve-out
    /// reaches dpkg; one that executed something else since, or an event
    /// before its start, is not known.
    #[test]
    fn a_fork_runs_its_parent_s_image_only_while_proc_says_so() {
        let proc = TempDir::new().unwrap();
        let t = AuthSessionTracker::new(proc.path());
        // dpkg, root, runs a maintainer script (dash)
        t.ingest_exec(600, 1, "/usr/bin/dpkg", &[], 10 * S, 10 * S, 0);
        write_exe(proc.path(), 600, "/usr/bin/dpkg");
        write_status(proc.path(), 600, 1);
        write_started(proc.path(), "600", 1, 1_000);
        let script = [
            "sh".to_string(),
            "/var/lib/dpkg/info/x.postinst".to_string(),
        ];
        t.ingest_exec(601, 600, "/usr/bin/dash", &script, 11 * S, 11 * S, 0);
        write_exe(proc.path(), 601, "/usr/bin/dash");
        write_status(proc.path(), 601, 600);
        write_started(proc.path(), "601", 600, 1_100);
        // its subshell: forked at 12 s, never executed
        write_exe(proc.path(), 602, "/usr/bin/dash");
        write_status(proc.path(), 602, 601);
        write_started(proc.path(), "602", 601, 1_200);
        let judged = AsOf::Judged(13 * S);
        assert_eq!(
            t.exec_identity(602, judged).map(|i| i.exe),
            Some(PathBuf::from("/usr/bin/dash"))
        );
        assert!(
            t.in_package_transaction(602, judged),
            "the subshell's write is dpkg's transaction"
        );
        // a fork that executed `restic` since: not known
        write_exe(proc.path(), 603, "/usr/bin/restic");
        write_status(proc.path(), 603, 601);
        write_started(proc.path(), "603", 601, 1_250);
        assert_eq!(t.exec_identity(603, judged), None);
        assert_eq!(t.image_path_as(603, judged), None);
        assert!(!t.in_package_transaction(603, judged));
        // an event before the fork's start was another process's
        assert_eq!(t.exec_identity(602, AsOf::Judged(11 * S + S / 2)), None);
        // the sweep enters the fork (not the one that executed restic)
        let report = t.sweep();
        assert_eq!(report.forks, 1);
        assert!(t.holds(602) && !t.holds(603));
    }

    /// Lot 310: the lineage keeps the executed file's identity the LSM
    /// program gave (none in tracepoint mode without the exec pump's
    /// `/proc/<pid>/exe`), when its directory is root's only, and a fork the
    /// sweep enters,
    /// or an orphan of a gone process's image, runs that image's identity.
    #[test]
    fn a_fork_and_an_orphan_carry_the_identity_of_the_image_they_run() {
        let exec =
            |pid: u32, ppid: u32, exe: &str, ns: u64, id: Option<(u64, u64)>| Event::ProcessSpawn {
                pid,
                ppid,
                uid: 0,
                gid: 0,
                comm: "x".into(),
                filename: exe.into(),
                timestamp_ns: ns,
                argv: vec![exe.into()],
                parent_comm: String::new(),
                parent_start_ns: 0,
                start_ns: ns,
                parent_is_kthread: false,
                exe: nn_model::ExeIdentity {
                    path: exe.into(),
                    dev: id.map_or(0, |i| i.0),
                    ino: id.map_or(0, |i| i.1),
                    flags: id.map_or(0, |_| {
                        common::wire::exe::exe_flags::KNOWN | common::wire::exe::exe_flags::ROOT_DIR
                    }),
                    ..Default::default()
                },
                argv_truncated: false,
                filename_truncated: false,
                stdio: Default::default(),
            };
        // a fork: dpkg's subshell, never executed
        let proc = TempDir::new().unwrap();
        let t = AuthSessionTracker::new(proc.path());
        assert!(t.ingest_spawn_event(&exec(600, 1, "/usr/bin/dpkg", 10 * S, Some((8, 600)))));
        assert!(t.ingest_spawn_event(&exec(610, 1, "/usr/bin/apt", 10 * S, None)));
        assert_eq!(t.exec_image(600, AsOf::Now), Some((8, 600)));
        assert_eq!(t.exec_image(610, AsOf::Now), None, "tracepoint: none");
        assert_eq!(t.exec_image(611, AsOf::Now), None, "not held");
        // the review of #539 (finding 5): an image in a directory a user
        // can write (no `ROOT_DIR`) could be unlinked and replaced by its
        // owner — its identity is not kept
        let mut user_s = exec(612, 1, "/home/u/bin/tool", 10 * S, Some((8, 612)));
        if let Event::ProcessSpawn { exe, .. } = &mut user_s {
            exe.flags &= !common::wire::exe::exe_flags::ROOT_DIR;
        }
        assert!(t.ingest_spawn_event(&user_s));
        assert_eq!(t.exec_image(612, AsOf::Now), None, "a user's directory");
        write_exe(proc.path(), 600, "/usr/bin/dpkg");
        write_status(proc.path(), 600, 1);
        write_started(proc.path(), "600", 1, 1_000);
        write_exe(proc.path(), 602, "/usr/bin/dpkg");
        write_status(proc.path(), 602, 600);
        write_started(proc.path(), "602", 600, 1_200);
        assert_eq!(t.sweep().forks, 1);
        assert_eq!(t.exec_image(602, AsOf::Now), Some((8, 600)));
        // an orphan: clamd executed by pid 1, forked 501, exited
        let proc = TempDir::new().unwrap();
        write_exe(proc.path(), 1, "/usr/lib/systemd/systemd");
        write_status(proc.path(), 1, 0);
        write_started(proc.path(), "1", 0, 1);
        let t = AuthSessionTracker::live_on(proc.path(), 0);
        assert_eq!(t.seed_from_proc(), 1);
        assert!(t.ingest_spawn_event(&exec(500, 1, "/usr/sbin/clamd", 10 * S, Some((8, 500)))));
        write_exe(proc.path(), 501, "/usr/sbin/clamd");
        write_status_uid(proc.path(), 501, 1, 0);
        write_started(proc.path(), "501", 1, 1_005);
        assert_eq!(t.sweep().orphans, 1);
        assert_eq!(
            t.exec_image(501, AsOf::Judged(H::monotonic_ns())),
            Some((8, 500))
        );
    }

    /// The re-check 4 of #539: on systemd ≥ 254 a manager's fork executes
    /// `systemd-executor`, then the unit's program; the KERNEL carries the
    /// fork record through a verified executor to that program
    /// (`common::fork_record`, decided at the exec: no race with a reader
    /// of `/proc`). The lineage keeps each exec's fork parent as the kernel
    /// recorded it, and invents none: an exec the kernel gave 0 (an
    /// unverified file's next exec, a later exec, another process at the
    /// pid) has none, whatever the exec before it ran.
    #[test]
    fn each_exec_keeps_the_fork_parent_the_kernel_recorded() {
        use common::wire::exe::exe_flags::{KNOWN, ROOT_DIR};
        let started = |pid: u32, exe: &str, ns: u64, id: (u64, u64), forker: u32, start: u64| {
            Event::ProcessSpawn {
                pid,
                ppid: 1,
                uid: 0,
                gid: 0,
                comm: "x".into(),
                filename: exe.into(),
                timestamp_ns: ns,
                argv: vec![exe.into()],
                parent_comm: String::new(),
                parent_start_ns: 0,
                start_ns: start,
                parent_is_kthread: false,
                exe: nn_model::ExeIdentity {
                    path: exe.into(),
                    dev: id.0,
                    ino: id.1,
                    flags: KNOWN | ROOT_DIR,
                    fork_parent: forker,
                    ..Default::default()
                },
                argv_truncated: false,
                filename_truncated: false,
                stdio: Default::default(),
            }
        };
        let exec = |pid: u32, exe: &str, ns: u64, id: (u64, u64), forker: u32| {
            started(pid, exe, ns, id, forker, 5 * S)
        };
        let proc = TempDir::new().unwrap();
        let t = AuthSessionTracker::new(proc.path());
        let executor = "/usr/lib/systemd/systemd-executor";
        // the unit: PID 1's fork, the executor, then `sh -c` (the kernel
        // carried the record), then `tar` (the record used: 0)
        assert!(t.ingest_spawn_event(&exec(700, executor, 6 * S, (8, 100), 1)));
        assert_eq!(t.fork_parent(700, AsOf::Now), Some(1), "the executor's");
        assert!(t.ingest_spawn_event(&exec(700, "/usr/bin/dash", 7 * S, (8, 200), 1)));
        assert_eq!(
            t.fork_parent(700, AsOf::Now),
            Some(1),
            "the unit's program, as the kernel carried it"
        );
        assert!(t.ingest_spawn_event(&exec(700, "/usr/bin/tar", 8 * S, (8, 300), 0)));
        assert_eq!(t.fork_parent(700, AsOf::Now), None, "the exec after");
        // the kernel gave the program after the executor nothing (not a
        // verified executor, tracepoint mode): the lineage adds none
        assert!(t.ingest_spawn_event(&exec(710, executor, 6 * S, (8, 999), 1)));
        assert!(t.ingest_spawn_event(&exec(710, "/usr/bin/dash", 7 * S, (8, 200), 0)));
        assert_eq!(t.fork_parent(710, AsOf::Now), None);
        // another process at the pid: its own record
        assert!(t.ingest_spawn_event(&exec(730, executor, 6 * S, (8, 100), 1)));
        assert!(t.ingest_spawn_event(&started(730, "/usr/bin/dash", 9 * S, (8, 200), 4242, 8 * S)));
        assert_eq!(t.fork_parent(730, AsOf::Now), Some(4242), "another start");
        assert!(t.ingest_spawn_event(&started(740, executor, 6 * S, (8, 100), 1, 0)));
        assert!(t.ingest_spawn_event(&started(740, "/usr/bin/dash", 7 * S, (8, 200), 0, 0)));
        assert_eq!(t.fork_parent(740, AsOf::Now), None, "no start known");
    }

    /// The re-check of #539 (N6): the start's scan reads an image's
    /// directory only for a process in PID 1's mount namespace, in the
    /// process's own root; another namespace, or one not readable: none.
    #[test]
    fn the_start_s_scan_reads_a_directory_in_pid_1_s_namespace_only() {
        let proc = TempDir::new().unwrap();
        let link = |pid: &str, name: &str, to: &str| {
            let p = proc.path().join(pid).join(name);
            std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            symlink(to, p).unwrap();
        };
        link("1", "ns/mnt", "mnt:[4026531841]");
        link("80", "exe", "/usr/bin/tool (deleted)");
        link("80", "ns/mnt", "mnt:[4026531841]");
        link("81", "exe", "/usr/bin/tool");
        link("81", "ns/mnt", "mnt:[4026532999]");
        link("82", "exe", "/usr/bin/tool");
        let t = AuthSessionTracker::new(proc.path());
        assert_eq!(
            t.image_dir_view(80),
            Some(proc.path().join("80/root/usr/bin")),
            "PID 1's namespace, the unlinked image's directory"
        );
        assert_eq!(t.image_dir_view(81), None, "a namespace of its own");
        assert_eq!(t.image_dir_view(82), None, "its namespace not readable");
        std::fs::remove_file(proc.path().join("1/ns/mnt")).unwrap();
        assert_eq!(t.image_dir_view(80), None, "PID 1's not readable");
    }

    /// The re-check of #539 (N7): the `/proc` fallback reads an empty
    /// argument as one, as `ring_drops` does (one reader of a cmdline).
    #[test]
    fn a_cmdline_s_empty_argument_counts() {
        let a = argv_of_cmdline(b"python3\0-W\0\0/tmp/x.py\0/usr/bin/aws\0");
        assert_eq!(a, ["python3", "-W", "", "/tmp/x.py", "/usr/bin/aws"]);
        assert_eq!(
            runs_of(Path::new("/usr/bin/python3"), &a),
            Runs::Script("/tmp/x.py".into())
        );
        assert!(argv_of_cmdline(b"").is_empty());
        assert_eq!(argv_of_cmdline(b"sh\0"), ["sh"]);
        let proc = TempDir::new().unwrap();
        std::fs::create_dir_all(proc.path().join("77")).unwrap();
        std::fs::write(
            proc.path().join("77/cmdline"),
            b"python3\0-W\0\0/tmp/x.py\0/usr/bin/aws\0",
        )
        .unwrap();
        let t = AuthSessionTracker::new(proc.path());
        assert_eq!(
            t.proc_runs(77, Path::new("/usr/bin/python3")),
            Runs::Script("/tmp/x.py".into())
        );
    }

    /// Lot 310: an interpreter running an inline program is no client by
    /// the interpreter's name (its program is the caller's); a binary, and
    /// an interpreter running nothing, are named by their executable.
    #[test]
    fn an_inline_program_is_no_client_by_the_interpreter_s_name() {
        let a = |v: &[&str]| v.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        let py = ExecIdentity::of_exec("/usr/bin/python3", &a(&["python3", "-c", "x"]));
        assert_eq!(py.runs, Runs::Code);
        assert!(!py.is_client(&["python3"]));
        assert!(ExecIdentity::of_exec("/usr/bin/python3", &a(&["python3"])).is_client(&["python3"]));
        assert!(ExecIdentity::of_exec("/usr/bin/aws", &a(&["aws", "s3"])).is_client(&["aws"]));
    }

    /// Review of #475: a session older than the agent (sshd and its shell,
    /// entered by the start's scan) still makes its processes auth-mediated
    /// after 2,100 other execs — an exec'd command and a forked subshell;
    /// a cron worker forked without an exec is a credential reader, and a
    /// forked worker of a service daemon has its image.
    #[test]
    fn a_session_s_processes_stay_mediated_and_a_worker_known() {
        let proc = TempDir::new().unwrap();
        write_exe(proc.path(), 700, "/usr/sbin/sshd");
        write_status(proc.path(), 700, 1);
        write_started(proc.path(), "700", 1, 100);
        write_exe(proc.path(), 701, "/usr/bin/bash");
        write_status(proc.path(), 701, 700);
        write_started(proc.path(), "701", 700, 110);
        write_exe(proc.path(), 800, "/usr/sbin/cron");
        write_status(proc.path(), 800, 1);
        write_started(proc.path(), "800", 1, 120);
        write_exe(proc.path(), 900, "/usr/sbin/postgres");
        write_status(proc.path(), 900, 1);
        write_started(proc.path(), "900", 1, 130);
        let t = AuthSessionTracker::new(proc.path());
        assert_eq!(t.seed_from_proc(), 4);
        for i in 0..2_100u64 {
            t.ingest_exec(
                10_000 + i as u32,
                1,
                "/usr/bin/true",
                &[],
                (10 + i) * S,
                (10 + i) * S,
                0,
            );
        }
        // a command the session ran later, and a subshell it forked
        t.ingest_exec(702, 701, "/usr/bin/cp", &[], 2_200 * S, 2_200 * S, 1000);
        write_exe(proc.path(), 703, "/usr/bin/bash");
        write_status(proc.path(), 703, 701);
        write_started(proc.path(), "703", 701, 220_000);
        // cron's worker and postgres's backend, forked, never executed
        write_exe(proc.path(), 801, "/usr/sbin/cron");
        write_status(proc.path(), 801, 800);
        write_started(proc.path(), "801", 800, 220_100);
        write_exe(proc.path(), 901, "/usr/sbin/postgres");
        write_status(proc.path(), 901, 900);
        write_started(proc.path(), "901", 900, 220_200);
        let judged = AsOf::Judged(2_300 * S);
        assert!(t.is_auth_mediated(702, judged));
        assert!(t.is_auth_mediated(703, judged));
        assert!(t.is_credential_reader(801, judged), "cron's worker");
        assert_eq!(
            t.image_path_as(901, judged).as_deref(),
            Some("/usr/sbin/postgres"),
            "the backend's image, not unknown"
        );
    }

    /// Third review of #475 (X1, the reviewer's RR1): a daemon that forks
    /// and exits after the agent's start (`Type=forking`, `daemon()`) — its
    /// child reparented to pid 1 before any sweep — is its image's orphan
    /// once the sweep found the parent gone, in production mode (live
    /// checks on). Not a process that executed something else, one started
    /// before the gone process's exec, one reparented elsewhere, nor one
    /// whose gone candidates ran different scripts.
    #[test]
    fn a_daemon_that_forks_and_exits_is_its_image_s_orphan_after_the_sweep() {
        let proc = TempDir::new().unwrap();
        write_exe(proc.path(), 1, "/usr/lib/systemd/systemd");
        write_status(proc.path(), 1, 0);
        write_started(proc.path(), "1", 0, 1);
        let t = AuthSessionTracker::live_on(proc.path(), 0);
        assert_eq!(t.seed_from_proc(), 1);
        // clamd executed at 10 s by pid 1, forked 501 at 10.05 s, exited
        t.ingest_exec(500, 1, "/usr/sbin/clamd", &[], 10 * S, 10 * S, 0);
        write_exe(proc.path(), 501, "/usr/sbin/clamd");
        write_status_uid(proc.path(), 501, 1, 0);
        write_started(proc.path(), "501", 1, 1_005);
        // reparented too, but: executed restic; started before clamd's
        // exec; reparented to a process that is no ancestor of clamd's
        write_exe(proc.path(), 502, "/usr/bin/restic");
        write_status_uid(proc.path(), 502, 1, 0);
        write_started(proc.path(), "502", 1, 1_006);
        write_exe(proc.path(), 503, "/usr/sbin/clamd");
        write_status_uid(proc.path(), 503, 1, 0);
        write_started(proc.path(), "503", 1, 900);
        write_exe(proc.path(), 504, "/usr/sbin/clamd");
        write_status_uid(proc.path(), 504, 77, 0);
        write_started(proc.path(), "504", 77, 1_007);
        let judged = AsOf::Judged(20 * S);
        assert_eq!(
            t.exec_identity(501, judged),
            None,
            "before a sweep: not known"
        );
        let r = t.sweep();
        assert_eq!((r.gone, r.orphans), (1, 1));
        // known from the sweep's instant on (the final check of #475)
        let after = AsOf::Judged(H::monotonic_ns());
        assert_eq!(
            t.exec_identity(501, after).map(|i| i.exe),
            Some(PathBuf::from("/usr/sbin/clamd"))
        );
        assert_eq!(
            t.image_path_as(501, after).as_deref(),
            Some("/usr/sbin/clamd")
        );
        assert_eq!(
            t.exec_identity(501, judged),
            None,
            "an event before the sweep: still not known"
        );
        for pid in [502, 503, 504] {
            assert_eq!(t.exec_identity(pid, after), None, "{pid}");
        }
        // two gone interpreters of different scripts: which one is not known
        let proc = TempDir::new().unwrap();
        let t = AuthSessionTracker::live_on(proc.path(), 0);
        let py = |script: &str| ["python3".to_string(), script.to_string()];
        t.ingest_exec(
            600,
            1,
            "/usr/bin/python3",
            &py("/opt/a.py"),
            10 * S,
            10 * S,
            0,
        );
        t.ingest_exec(
            610,
            1,
            "/usr/bin/python3",
            &py("/opt/b.py"),
            11 * S,
            11 * S,
            0,
        );
        write_exe(proc.path(), 620, "/usr/bin/python3");
        write_status_uid(proc.path(), 620, 1, 0);
        write_started(proc.path(), "620", 1, 1_200);
        let r = t.sweep();
        assert_eq!((r.gone, r.orphans), (2, 0));
        assert_eq!(t.exec_identity(620, AsOf::Judged(H::monotonic_ns())), None);
        // one gone interpreter: its script
        let proc = TempDir::new().unwrap();
        let t = AuthSessionTracker::live_on(proc.path(), 0);
        t.ingest_exec(
            600,
            1,
            "/usr/bin/python3",
            &py("/opt/a.py"),
            10 * S,
            10 * S,
            0,
        );
        write_exe(proc.path(), 620, "/usr/bin/python3");
        write_status_uid(proc.path(), 620, 1, 0);
        write_started(proc.path(), "620", 1, 1_200);
        assert_eq!(t.sweep().orphans, 1);
        assert_eq!(
            t.exec_identity(620, AsOf::Judged(H::monotonic_ns()))
                .and_then(|i| i.script().map(str::to_string))
                .as_deref(),
            Some("/opt/a.py")
        );
    }

    /// Third review of #475 (X2, the reviewer's RR2; M11): a pid reused by
    /// a fork while the dead process's entry is still cached is not the dead
    /// process's image — an SSH session's bash subshell on restic's old pid
    /// is bash, and auth-mediated (a regression against `main` before);
    /// an event before the reuse is still restic's. The sweep finds the pid
    /// naming another process and enters the fork.
    #[test]
    fn a_pid_reused_by_a_fork_is_not_the_dead_process_s_image() {
        let proc = TempDir::new().unwrap();
        write_exe(proc.path(), 550, "/usr/sbin/sshd");
        write_status(proc.path(), 550, 1);
        write_started(proc.path(), "550", 1, 100);
        write_exe(proc.path(), 600, "/usr/bin/bash");
        write_status(proc.path(), 600, 550);
        write_started(proc.path(), "600", 550, 110);
        let t = AuthSessionTracker::live_on(proc.path(), 0);
        assert_eq!(t.seed_from_proc(), 2);
        // restic ran as 700 from 10 s and exited; 700 is now the shell's
        // subshell, forked at 30 s
        t.ingest_exec(700, 1, "/usr/bin/restic", &[], 10 * S, 10 * S, 0);
        write_exe(proc.path(), 700, "/usr/bin/bash");
        write_status(proc.path(), 700, 600);
        write_started(proc.path(), "700", 600, 3_000);
        let judged = AsOf::Judged(40 * S);
        assert_eq!(
            t.exec_identity(700, judged).map(|i| i.exe),
            Some(PathBuf::from("/usr/bin/bash"))
        );
        assert_eq!(
            t.image_path_as(700, judged).as_deref(),
            Some("/usr/bin/bash")
        );
        assert!(t.is_auth_mediated(700, judged), "the session's subshell");
        assert_eq!(
            t.image_path_as(700, AsOf::Judged(15 * S)).as_deref(),
            Some("/usr/bin/restic"),
            "before the reuse the pid was restic"
        );
        assert_eq!(t.image_path(700).as_deref(), Some("/usr/bin/bash"));
        let r = t.sweep();
        assert_eq!(
            (r.gone, r.forks),
            (1, 1),
            "the reused pid found, the fork entered"
        );
        assert_eq!(
            t.exec_identity(700, judged).map(|i| i.exe),
            Some(PathBuf::from("/usr/bin/bash"))
        );
        assert!(t.is_auth_mediated(700, judged));
        assert_eq!(
            t.image_path_as(700, AsOf::Judged(15 * S)).as_deref(),
            Some("/usr/bin/restic")
        );
    }

    /// Third review of #475 (M5): a subshell of a subshell, both forked
    /// within a sweep's period, runs the image of the first's parent — the
    /// fork's parent itself a fork, not cached.
    #[test]
    fn a_fork_of_a_fork_runs_the_image_before_any_sweep() {
        let proc = TempDir::new().unwrap();
        let t = AuthSessionTracker::live_on(proc.path(), 0);
        t.ingest_exec(600, 1, "/usr/bin/dpkg", &[], 10 * S, 10 * S, 0);
        write_exe(proc.path(), 600, "/usr/bin/dpkg");
        write_status(proc.path(), 600, 1);
        write_started(proc.path(), "600", 1, 1_000);
        let script = [
            "sh".to_string(),
            "/var/lib/dpkg/info/x.postinst".to_string(),
        ];
        t.ingest_exec(601, 600, "/usr/bin/dash", &script, 11 * S, 11 * S, 0);
        write_exe(proc.path(), 601, "/usr/bin/dash");
        write_status(proc.path(), 601, 600);
        write_started(proc.path(), "601", 600, 1_100);
        write_exe(proc.path(), 602, "/usr/bin/dash");
        write_status(proc.path(), 602, 601);
        write_started(proc.path(), "602", 601, 1_200);
        write_exe(proc.path(), 603, "/usr/bin/dash");
        write_status(proc.path(), 603, 602);
        write_started(proc.path(), "603", 602, 1_250);
        let judged = AsOf::Judged(13 * S);
        assert_eq!(
            t.exec_identity(603, judged).map(|i| i.exe),
            Some(PathBuf::from("/usr/bin/dash"))
        );
        assert!(t.in_package_transaction(603, judged), "dpkg's transaction");
    }

    /// Third review of #475 (M6): a forked worker that changed its uid is
    /// judged as its own uid, not its parent's — man-db's worker still
    /// `man` is the system cache writer, one switched to a user's is not.
    #[test]
    fn a_forked_worker_that_changed_its_uid_is_judged_as_its_own() {
        let proc = TempDir::new().unwrap();
        let t = AuthSessionTracker::live_on(proc.path(), 0);
        t.ingest_exec(800, 1, MANDB_EXE, &[], 10 * S, 10 * S, 6);
        write_exe(proc.path(), 800, MANDB_EXE);
        write_status_uid(proc.path(), 800, 1, 6);
        write_started(proc.path(), "800", 1, 1_000);
        write_exe(proc.path(), 801, MANDB_EXE);
        write_status_uid(proc.path(), 801, 800, 6);
        write_started(proc.path(), "801", 800, 1_100);
        write_exe(proc.path(), 802, MANDB_EXE);
        write_status_uid(proc.path(), 802, 800, 1000);
        write_started(proc.path(), "802", 800, 1_100);
        let judged = AsOf::Judged(20 * S);
        assert!(t.is_system_man_cache_writer(801, judged));
        assert!(
            !t.is_system_man_cache_writer(802, judged),
            "its own uid, a user's"
        );
    }

    /// Third review of #475 (M9): a walk does not take a fork for an event
    /// before the fork's start — the pid named another process then.
    #[test]
    fn a_walk_does_not_take_a_fork_for_an_event_before_its_start() {
        let proc = TempDir::new().unwrap();
        write_exe(proc.path(), 700, "/usr/sbin/sshd");
        write_status(proc.path(), 700, 1);
        write_started(proc.path(), "700", 1, 100);
        write_exe(proc.path(), 701, "/usr/bin/bash");
        write_status(proc.path(), 701, 700);
        write_started(proc.path(), "701", 700, 110);
        let t = AuthSessionTracker::live_on(proc.path(), 0);
        assert_eq!(t.seed_from_proc(), 2);
        write_exe(proc.path(), 703, "/usr/bin/bash");
        write_status(proc.path(), 703, 701);
        write_started(proc.path(), "703", 701, 220_000);
        assert!(t.is_auth_mediated(703, AsOf::Judged(2_300 * S)));
        assert!(
            !t.is_auth_mediated(703, AsOf::Judged(2_100 * S)),
            "an event before the fork's start"
        );
        assert_eq!(t.exec_identity(703, AsOf::Judged(2_100 * S)), None);
    }

    /// Third review of #475 (the reviewer's RR4): at the hard bound the
    /// entries go from the uid holding the most among the processes
    /// executed since the start, oldest first — a user's flood of live
    /// processes pushes out its own, never the seeded daemon, root's job
    /// or another user's shell.
    #[test]
    fn the_hard_bound_drops_the_most_numerous_user_s_entries_first() {
        let proc = TempDir::new().unwrap();
        write_exe(proc.path(), 1, "/usr/lib/systemd/systemd");
        write_status(proc.path(), 1, 0);
        write_started(proc.path(), "1", 0, 1);
        write_exe(proc.path(), 500, "/usr/sbin/clamd");
        write_status(proc.path(), 500, 1);
        write_started(proc.path(), "500", 1, 100);
        let t = AuthSessionTracker::new(proc.path()).with_bounds(4, 8, std::time::Duration::ZERO);
        assert_eq!(t.seed_from_proc(), 2);
        t.ingest_exec(600, 1, "/usr/sbin/cron", &[], 5 * S, 5 * S, 0);
        t.ingest_exec(610, 1, "/usr/bin/bash", &[], 6 * S, 6 * S, 1001);
        for i in 0..10u32 {
            let at = u64::from(10 + i) * S;
            t.ingest_exec(1_000 + i, 1, "/usr/bin/sleep", &[], at, at, 1000);
        }
        assert_eq!(t.entry_count(), 8);
        assert_eq!(t.evicted_live(), 6);
        for pid in [1, 500, 600, 610, 1_006, 1_009] {
            assert!(t.holds(pid), "{pid} kept");
        }
        assert!(!t.holds(1_000) && !t.holds(1_005));
        assert_eq!(
            t.exec_identity(500, AsOf::Judged(30 * S)).map(|i| i.exe),
            Some(PathBuf::from("/usr/sbin/clamd"))
        );
    }

    /// Final check of #475 (the reviewer's RRd2, production mode): a fork
    /// that reads a canary as bash, then executes a reader any user may run
    /// (`clamscan`) whose earlier run the attacker let exit, its exec still
    /// queued across a sweep, is adopted as that reader's orphan from the
    /// sweep's instant only — the read before its exec, judged after the
    /// sweep and after the exec is read, is not known (it was `clamscan`, a
    /// reader: recorded, not killed).
    #[test]
    fn an_orphan_adopted_by_the_sweep_does_not_cover_its_events_before_it() {
        let proc = TempDir::new().unwrap();
        let t = AuthSessionTracker::live_on(proc.path(), 0);
        // the shell S (600), a user's
        t.ingest_exec(600, 1, "/usr/bin/bash", &[], 5 * S, 5 * S, 1000);
        write_exe(proc.path(), 600, "/usr/bin/bash");
        write_status_uid(proc.path(), 600, 1, 1000);
        write_started(proc.path(), "600", 1, 500);
        // S ran clamscan (610) at 10 s, which exited
        t.ingest_exec(610, 600, "/usr/bin/clamscan", &[], 10 * S, 10 * S, 1000);
        // A (620), forked by S at 12 s, read a canary at 12.5 s as bash,
        // executed clamscan at 13 s: that exec still queued at the sweep
        write_exe(proc.path(), 620, "/usr/bin/clamscan");
        write_status_uid(proc.path(), 620, 600, 1000);
        write_started(proc.path(), "620", 600, 1_200);
        let r = t.sweep();
        assert_eq!(
            (r.gone, r.orphans),
            (1, 1),
            "adopted, as the sibling of the gone run"
        );
        t.ingest_exec(620, 600, "/usr/bin/clamscan", &[], 13 * S, 12 * S, 1000);
        let read = AsOf::Judged(12 * S + S / 2);
        assert_eq!(t.exec_identity(620, read), None, "the read before its exec");
        assert_eq!(t.image_path_as(620, read), None);
        // after its exec it runs clamscan
        assert_eq!(
            t.image_path_as(620, AsOf::Judged(14 * S)).as_deref(),
            Some("/usr/bin/clamscan")
        );
    }

    /// Final check of #475: at the hard bound a system account's flood (a
    /// webshell as `www-data`) pushes out its own entries, not a person's
    /// session — the uid holding the most entries goes first, whatever its
    /// class.
    #[test]
    fn a_system_account_s_flood_pushes_out_its_own_entries_not_a_person_s() {
        let proc = TempDir::new().unwrap();
        let t = AuthSessionTracker::new(proc.path()).with_bounds(4, 8, std::time::Duration::ZERO);
        // a person's session (uid 1000): a shell and a command
        t.ingest_exec(700, 1, "/usr/bin/bash", &[], 5 * S, 5 * S, 1000);
        t.ingest_exec(701, 700, "/usr/bin/vim", &[], 6 * S, 6 * S, 1000);
        for i in 0..10u32 {
            let at = u64::from(10 + i) * S;
            t.ingest_exec(2_000 + i, 1, "/usr/bin/sh", &[], at, at, 33);
        }
        assert_eq!(t.entry_count(), 8);
        assert_eq!(t.evicted_live(), 4);
        assert!(t.holds(700) && t.holds(701), "the person's session kept");
        assert!(!t.holds(2_000) && t.holds(2_009));
    }

    /// The re-check 4 of #539 (HIGH): a lineage the walk does not follow
    /// to PID 1 is not known — `pid` and 32 ancestors under PID 1 are
    /// whole, one more is cut; a hop that started after the one below it (a
    /// later process at an exited parent's pid) and a process its own
    /// parent cut it too. What was read below the cut stays readable for a
    /// reader that looks for a hop.
    #[test]
    fn a_lineage_cut_before_pid_1_is_not_known() {
        let proc = TempDir::new().unwrap();
        let t = AuthSessionTracker::new(proc.path());
        let chain = |first: u32, ancestors: u32, start: u64| {
            for k in 0..=ancestors {
                let pid = first + k;
                let ppid = if k == 0 { 1 } else { pid - 1 };
                t.ingest_exec(
                    pid,
                    ppid,
                    "/usr/bin/timeout",
                    &[],
                    start + u64::from(k) * S,
                    start + u64::from(k) * S,
                    0,
                );
            }
            first + ancestors
        };
        let whole = chain(100, 32, 10 * S);
        assert_eq!(
            t.lineage_identities(whole, AsOf::Now).map(|h| h.len()),
            Some(33),
            "the writer and 32 ancestors, the last one PID 1's"
        );
        let cut = chain(200, 33, 10 * S);
        assert!(
            t.lineage_identities(cut, AsOf::Now).is_none(),
            "one past the cap"
        );
        assert_eq!(
            t.lineage_identities_seen(cut, AsOf::Now).map(|h| h.len()),
            Some(33),
            "the hops read below the cut"
        );
        // a parent that started after its child: a later process at the pid
        t.ingest_exec(300, 1, "/usr/bin/bash", &[], 50 * S, 50 * S, 0);
        t.ingest_exec(301, 300, "/usr/bin/tar", &[], 40 * S, 40 * S, 0);
        assert!(
            t.lineage_identities(301, AsOf::Now).is_none(),
            "a later parent"
        );
        assert_eq!(
            t.lineage_identities_seen(301, AsOf::Now).map(|h| h.len()),
            Some(1)
        );
        // a process its own parent
        t.ingest_exec(400, 400, "/usr/bin/tar", &[], 60 * S, 60 * S, 0);
        assert!(
            t.lineage_identities(400, AsOf::Now).is_none(),
            "its own parent"
        );
        // a short one under PID 1: whole
        t.ingest_exec(500, 1, "/usr/bin/bash", &[], 70 * S, 70 * S, 0);
        t.ingest_exec(501, 500, "/usr/bin/tar", &[], 71 * S, 71 * S, 0);
        assert_eq!(
            t.lineage_identities(501, AsOf::Now).map(|h| h.len()),
            Some(2)
        );
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
        assert!(!t.is_auth_mediated(1, AsOf::Now));
    }

    #[test]
    fn self_referential_lineage_does_not_loop() {
        let t = AuthSessionTracker::new("/proc");
        // pid 100 lists itself as its own ppid — corrupt /proc
        // synthesis would do this. Must terminate, not hang.
        t.ingest_spawn(100, 100, "/usr/bin/cat", 1);
        assert!(!t.is_auth_mediated(100, AsOf::Now));
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
        assert!(t.is_auth_mediated(501, AsOf::Now));
    }

    #[test]
    fn unix_chkpwd_screen_unlock_is_auth_mediated() {
        let t = AuthSessionTracker::new("/proc");
        // Unprivileged locker -> setuid-root pam_unix helper. The helper
        // reads /etc/shadow at the caller's real uid; its own exe is the
        // auth binary, so it is auth-mediated at hop 0.
        t.ingest_spawn(700, 1, "/usr/bin/cinnamon-screensaver", 1);
        t.ingest_spawn(701, 700, "/usr/sbin/unix_chkpwd", 2);
        assert!(t.is_auth_mediated(701, AsOf::Now));
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
        assert!(t.is_auth_mediated(602, AsOf::Now));
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
            !t.is_auth_mediated(200, AsOf::Now),
            "forked before its parent ran sudo"
        );
        assert!(
            t.is_auth_mediated(100, AsOf::Now),
            "the parent itself runs sudo"
        );
        // what the parent forks after it ran sudo is sudo's
        t.ingest_exec(300, 100, "/usr/bin/apt", &[], 46 * S, 45 * S, 0);
        assert!(t.is_auth_mediated(300, AsOf::Now));

        // a child forked before, that never executed: /proc shows the
        // image it was forked with — not sudo, so not sudo's
        write_exe(tmp.path(), 400, "/srv/www/payload");
        write_status(tmp.path(), 400, 100);
        assert!(!t.is_auth_mediated(400, AsOf::Now));
        // forked after, without executing (sudo's monitor): sudo's image
        write_exe(tmp.path(), 401, "/usr/bin/sudo");
        write_status(tmp.path(), 401, 100);
        t.ingest_exec(402, 401, "/usr/bin/tee", &[], 61 * S, 60 * S, 0);
        assert!(t.is_auth_mediated(402, AsOf::Now));
        // the same holds for a package manager's exemption
        t.ingest_exec(500, 50, "/srv/www/payload", &[], 71 * S, 70 * S, 0);
        t.ingest_exec(600, 500, "/srv/www/crypt", &[], 81 * S, 75 * S, 0);
        t.ingest_exec(500, 50, "/usr/bin/dpkg", &[], 80 * S, 70 * S, 0);
        assert!(!t.is_system_daemon_mediated(600, AsOf::Now));
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
        assert!(!t.is_auth_mediated(200, AsOf::Now));
        // pid 100 goes to a shell of an SSH session, started at 45 s
        t.ingest_exec(50, 1, "/usr/sbin/sshd", &[], 5 * S, 5 * S, 0);
        t.ingest_exec(100, 50, "/usr/bin/bash", &[], 46 * S, 45 * S, 0);
        assert!(t.is_auth_mediated(100, AsOf::Now));
        assert!(!t.is_auth_mediated(200, AsOf::Now), "not the session's");
        assert_eq!(t.interactive_admin_status(200, AsOf::Now), Some(false));
        // a thread of the parent forking it is still the parent: the
        // process's own start is what is compared
        t.ingest_exec(300, 100, "/usr/bin/make", &[], 51 * S, 50 * S, 0);
        assert!(t.is_auth_mediated(300, AsOf::Now));
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
        assert!(t.is_auth_mediated(100, AsOf::Now), "the same process");
        // a later process forked into pid 100
        write_started(tmp.path(), "100", 1, ticks(2000 * S));
        write_exe(tmp.path(), 100, "/home/u/crypt");
        write_status(tmp.path(), 100, 1);
        assert!(!t.is_auth_mediated(100, AsOf::Now), "sudo's entry is stale");
        // a laptop suspended an hour before sudo started: /proc shows its
        // start an hour later on the boot clock — still sudo
        let t = AuthSessionTracker::live_on(tmp.path(), 3600 * S);
        t.ingest_exec(100, 1, "/usr/bin/sudo", &[], 1000 * S, 1000 * S, 0);
        write_started(tmp.path(), "100", 1, ticks(4600 * S));
        assert!(t.is_auth_mediated(100, AsOf::Now));
        // an exited process: the cache is the record
        fs::remove_dir_all(tmp.path().join("100")).unwrap();
        assert!(t.is_auth_mediated(100, AsOf::Now));
        // without live checks (tests, tools) the cache is trusted
        let t = AuthSessionTracker::new(tmp.path());
        t.ingest_exec(100, 1, "/usr/bin/sudo", &[], 1000 * S, 1000 * S, 0);
        write_started(tmp.path(), "100", 1, ticks(9000 * S));
        assert!(t.is_auth_mediated(100, AsOf::Now));
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
        assert!(t.is_auth_mediated(70, AsOf::Now), "in the session");
        assert!(
            !t.is_credential_reader(70, AsOf::Now),
            "but not the PAM stack"
        );
        assert!(t.is_credential_reader(80, AsOf::Now));
        assert!(t.is_credential_reader(90, AsOf::Now));
        assert!(
            t.is_credential_reader(60, AsOf::Now),
            "the session's first child"
        );
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
    /// Lot 351: the exec of `pid` (`ids`: it and its parent) as the first
    /// of its process since its parent forked it (the kernel's fork record),
    /// at `spawn_ns`, the process started at `start_ns`, as real uid `uid`.
    fn exec_forked(
        t: &AuthSessionTracker,
        (pid, ppid): (u32, u32),
        exe: &str,
        spawn_ns: u64,
        start_ns: u64,
        uid: u32,
    ) {
        t.ingest_inner(
            pid,
            ppid,
            exe,
            (None, false, None),
            Runs::Inline,
            spawn_ns,
            (start_ns, None),
            uid,
            (None, ppid, None),
        );
    }

    fn admin_session(tty_nr: i64, loginuid: u32) -> (TempDir, AuthSessionTracker) {
        let tmp = TempDir::new().unwrap();
        write_loginuid(tmp.path(), 200, loginuid);
        write_stat(tmp.path(), 200, 100, tty_nr);
        let t = AuthSessionTracker::new(tmp.path());
        t.ingest_spawn(50, 40, "/usr/bin/bash", 1);
        t.ingest_spawn(100, 50, "/usr/bin/sudo", 2);
        t.ingest_first_exec(200, 100, "/usr/sbin/useradd", 3, 0);
        (tmp, t)
    }

    /// Lot 311 (N6): rewrite a fixture process's `comm` in its `stat` and
    /// `status` to bytes that are not UTF-8 (`\xff\xfe`), as the kernel
    /// shows a process that named itself so (`prctl(PR_SET_NAME)`, the
    /// name of the file it executed): no privilege needed.
    fn rename_not_utf8(dir: &Path, pid: u32) {
        let d = dir.join(pid.to_string());
        if let Ok(stat) = fs::read(d.join("stat")) {
            let open = stat.iter().position(|b| *b == b'(').unwrap();
            let close = stat.iter().rposition(|b| *b == b')').unwrap();
            let mut out = stat[..=open].to_vec();
            out.extend_from_slice(b"\xff\xfe");
            out.extend_from_slice(&stat[close..]);
            fs::write(d.join("stat"), out).unwrap();
        }
        if let Ok(status) = fs::read(d.join("status")) {
            let end = status.iter().position(|b| *b == b'\n').unwrap();
            let mut out = b"Name:\t\xff\xfe".to_vec();
            out.extend_from_slice(&status[end..]);
            fs::write(d.join("status"), out).unwrap();
        }
    }

    /// Lot 311 (N6): a session whose processes named themselves with bytes
    /// that are not UTF-8 keeps its lineage. On main every `/proc` read of
    /// such a process failed: the start's scan skipped it, the sweep marked
    /// it gone while it ran (and dropped it once the map was full), a fork
    /// of it was never entered — the walks from its children lost the
    /// session.
    #[test]
    fn a_session_whose_comms_are_not_utf8_keeps_its_lineage() {
        let proc = TempDir::new().unwrap();
        write_exe(proc.path(), 700, "/usr/sbin/sshd");
        write_status_uid(proc.path(), 700, 1, 0);
        write_started(proc.path(), "700", 1, 100);
        write_exe(proc.path(), 701, "/usr/bin/bash");
        write_status_uid(proc.path(), 701, 700, 1000);
        write_started(proc.path(), "701", 700, 110);
        for pid in [700, 701] {
            rename_not_utf8(proc.path(), pid);
        }
        let t =
            AuthSessionTracker::new(proc.path()).with_bounds(64, 1024, std::time::Duration::ZERO);
        assert_eq!(t.seed_from_proc(), 2, "the start's scan enters both");
        for i in 0..300u64 {
            t.ingest_exec(
                10_000 + i as u32,
                1,
                "/usr/bin/true",
                &[],
                (10 + i) * S,
                (10 + i) * S,
                0,
            );
        }
        // a subshell the session forked, named so too
        write_exe(proc.path(), 703, "/usr/bin/bash");
        write_status_uid(proc.path(), 703, 701, 1000);
        write_started(proc.path(), "703", 701, 40_000);
        rename_not_utf8(proc.path(), 703);
        let report = t.sweep();
        assert_eq!(report.gone, 300, "the running session is not gone");
        assert_eq!(report.forks, 1, "the subshell is entered");
        t.ingest_exec(702, 701, "/usr/bin/cp", &[], 500 * S, 500 * S, 1000);
        let judged = AsOf::Judged(600 * S);
        assert!(t.is_auth_mediated(702, judged));
        assert!(t.is_auth_mediated(703, judged));
        assert_eq!(
            t.exec_identity(701, judged).map(|i| i.exe),
            Some(PathBuf::from("/usr/bin/bash"))
        );
    }

    /// Lot 311 (N6): the admin session's terminal and liveness are read
    /// from a `stat` whose `comm` is not UTF-8. On main the terminal read
    /// failed: a sudo session's tool that named itself was "not an
    /// interactive admin".
    #[test]
    fn an_admin_session_whose_comm_is_not_utf8_is_still_told() {
        let (tmp, t) = admin_session(34816, 1000);
        rename_not_utf8(tmp.path(), 200);
        assert!(t.is_interactive_admin(200, AsOf::Now));
        assert_eq!(t.interactive_admin_status(200, AsOf::Now), Some(true));
    }

    #[test]
    fn sudo_with_login_and_terminal_is_interactive_admin() {
        let (_tmp, t) = admin_session(34816, 1000);
        assert!(t.is_interactive_admin(200, AsOf::Now));
    }

    /// Review of #493 (B1): a parent that forks and then executes another
    /// script of the same interpreter does not lend its fork that script.
    /// Read at the fork's earliest time, the fork runs `evil.py` (not
    /// `dnf`, not a canary reader like borg); when both of the parent's
    /// execs fall after that time, within the fork's tick, the fork is not
    /// known (two identities); one exec there (sudo's monitor) answers.
    #[test]
    fn a_fork_does_not_borrow_its_parent_s_next_script() {
        const MS: u64 = 1_000_000;
        let argv = |a: &[&str]| a.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        let fork = |second_at: u64, first_at: u64| {
            let tmp = TempDir::new().unwrap();
            let t = AuthSessionTracker::new(tmp.path());
            t.ingest_exec(700, 1, "/usr/bin/bash", &[], 5 * S, 5 * S, 1000);
            t.ingest_exec(
                800,
                700,
                "/usr/bin/python3",
                &argv(&["python3", "/home/u/evil.py"]),
                first_at,
                9_000 * MS,
                1000,
            );
            // forked at 10.005 s: `/proc` shows tick 1000 (10.000 s)
            write_exe(tmp.path(), 801, "/usr/bin/python3");
            write_status(tmp.path(), 801, 800);
            write_started(tmp.path(), "801", 800, 1_000);
            t.ingest_exec(
                800,
                700,
                "/usr/bin/python3",
                &argv(&["python3", "/usr/bin/borg", "serve"]),
                second_at,
                9_000 * MS,
                1000,
            );
            (tmp, t)
        };
        let judged = AsOf::Judged(10_050 * MS);
        // evil.py at 9.5 s, then borg at 10.006 s
        let (_tmp, t) = fork(10_006 * MS, 9_500 * MS);
        let id = t.exec_identity(801, judged);
        assert_eq!(
            id.and_then(|i| i.script().map(str::to_string)).as_deref(),
            Some("/home/u/evil.py")
        );
        let readers = crate::canary::readers::CanaryReaders::new(Default::default(), t.clone());
        assert_eq!(readers.reader(801, judged), None);
        // both after the fork's earliest time, two scripts: not known
        let (_tmp, t) = fork(10_006 * MS, 10_002 * MS);
        assert_eq!(t.exec_identity(801, judged), None);
        assert_eq!(readers_of(&t, 801, judged), None);
        // two execs there of one identity (the same script twice): an
        // interpreter's identity is never taken from the later exec (second
        // review of #493) — not known
        let tmp = TempDir::new().unwrap();
        let t = AuthSessionTracker::new(tmp.path());
        t.ingest_exec(700, 1, "/usr/bin/bash", &[], 5 * S, 5 * S, 1000);
        for at in [10_002 * MS, 10_006 * MS] {
            t.ingest_exec(
                800,
                700,
                "/usr/bin/python3",
                &argv(&["python3", "/home/u/evil.py"]),
                at,
                9_000 * MS,
                1000,
            );
        }
        write_exe(tmp.path(), 801, "/usr/bin/python3");
        write_status(tmp.path(), 801, 800);
        write_started(tmp.path(), "801", 800, 1_000);
        assert_eq!(t.exec_identity(801, judged), None);
    }

    fn readers_of(t: &AuthSessionTracker, pid: u32, at: AsOf) -> Option<String> {
        crate::canary::readers::CanaryReaders::new(Default::default(), t.clone()).reader(pid, at)
    }

    /// Second review of #493: a fork of a fork that never executed. G (750)
    /// runs an interpreter's script, its fork P (800) forks C (801) and
    /// then executes another: P's one exec in C's tick is an interpreter's
    /// — never C's identity; C is not known, not borg, not npm. An
    /// executable's own identity (sudo after bash) is taken; a child whose
    /// live exe cannot be read, or that runs the earlier image, is not.
    #[test]
    fn a_fork_of_a_fork_does_not_borrow_the_later_exec_of_an_interpreter() {
        const MS: u64 = 1_000_000;
        let argv = |a: &[&str]| a.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        let case = |g_exe: &str, g: &[&str], p_exe: &str, p: &[&str], child_exe: &str| {
            let tmp = TempDir::new().unwrap();
            let t = AuthSessionTracker::new(tmp.path());
            t.ingest_exec(700, 1, "/usr/bin/bash", &[], 5 * S, 5 * S, 1000);
            t.ingest_exec(750, 700, g_exe, &argv(g), 9_000 * MS, 8_900 * MS, 1000);
            // P (800): G's fork, never executed until 10.006 s
            write_exe(tmp.path(), 800, g_exe);
            write_status(tmp.path(), 800, 750);
            write_started(tmp.path(), "800", 750, 990);
            // C (801), P's fork at 10.005 s (`/proc`: tick 1000)
            write_exe(tmp.path(), 801, child_exe);
            write_status(tmp.path(), 801, 800);
            write_started(tmp.path(), "801", 800, 1_000);
            t.ingest_exec(800, 750, p_exe, &argv(p), 10_006 * MS, 9_900 * MS, 1000);
            (tmp, t)
        };
        let judged = AsOf::Judged(10_050 * MS);
        let py = "/usr/bin/python3";
        let node = "/usr/bin/node";
        let npm = "/usr/lib/node_modules/npm/bin/npm-cli.js";
        let cases: [(&str, &[&str], &str, &[&str]); 4] = [
            // the same interpreter, the review's case
            (
                py,
                &["python3", "/home/u/evil.py"],
                py,
                &["python3", "/usr/bin/borg", "serve"],
            ),
            // another interpreter before: the child's exe is the later one's
            (
                "/usr/bin/perl",
                &["perl", "/home/u/evil.pl"],
                py,
                &["python3", "/usr/bin/borg"],
            ),
            // npm's entrypoint
            (
                node,
                &["node", "/home/u/evil.js"],
                node,
                &["node", npm, "ci"],
            ),
            // an interpreter's inline program
            (
                py,
                &["python3", "/home/u/evil.py"],
                py,
                &["python3", "-c", "pass"],
            ),
        ];
        for (g_exe, g, p_exe, p) in cases {
            let (_tmp, t) = case(g_exe, g, p_exe, p, p_exe);
            assert_eq!(t.exec_identity(801, judged), None, "{g:?} then {p:?}");
            assert_eq!(readers_of(&t, 801, judged), None, "{g:?} then {p:?}");
            assert!(!t.is_npm_cli_writer(801, judged), "{g:?} then {p:?}");
        }
        // an executable's identity (bash, then sudo): taken
        let (tmp, t) = case(
            "/usr/bin/bash",
            &["bash"],
            "/usr/bin/sudo",
            &["sudo", "x"],
            "/usr/bin/sudo",
        );
        assert_eq!(
            t.exec_identity(801, judged).map(|i| i.exe),
            Some(PathBuf::from("/usr/bin/sudo"))
        );
        // the child's live exe unreadable: not known
        std::fs::remove_file(tmp.path().join("801").join("exe")).unwrap();
        assert_eq!(t.exec_identity(801, judged), None);
        // a child forked before the exec runs the earlier image: not sudo's
        write_exe(tmp.path(), 801, "/usr/bin/bash");
        assert_eq!(t.exec_identity(801, judged), None);
    }

    /// Third review of #493: the upper bound is for an authentication
    /// binary's monitor only. A child forked before its parent's exec that
    /// executed the same binary itself (restic, a canary reader) before its
    /// own exec reached the cache cannot be told from a fork made after the
    /// exec: not known, no reader. The monitor of each authentication
    /// binary in use (sudo, su, doas, pkexec), forked in the tick of its
    /// exec, keeps that binary's identity.
    #[test]
    fn only_an_authentication_binary_s_monitor_takes_the_later_exec() {
        const MS: u64 = 1_000_000;
        let monitor = |exe: &str| {
            let tmp = TempDir::new().unwrap();
            let t = AuthSessionTracker::new(tmp.path());
            t.ingest_exec(700, 1, "/usr/bin/bash", &[], 5 * S, 5 * S, 1000);
            // P (710): the shell's fork, executes `exe` at 10.003 s
            t.ingest_exec(710, 700, exe, &[], 10_003 * MS, 10_001 * MS, 1000);
            // C (711): forked at 10.008 s (`/proc`: tick 1000), runs `exe`
            write_exe(tmp.path(), 711, exe);
            write_status(tmp.path(), 711, 710);
            write_started(tmp.path(), "711", 710, 1_000);
            (tmp, t)
        };
        let judged = AsOf::Judged(10_030 * MS);
        // a canary reader's binary: not known, no reader
        let (_tmp, t) = monitor("/usr/bin/restic");
        assert_eq!(t.exec_identity(711, judged), None);
        assert_eq!(readers_of(&t, 711, judged), None);
        // each authentication binary in use: its monitor keeps its identity
        for exe in [
            "/usr/bin/sudo",
            "/bin/sudo",
            "/usr/bin/su",
            "/bin/su",
            "/usr/bin/doas",
            "/usr/bin/pkexec",
        ] {
            assert!(is_auth_binary(Path::new(exe)), "{exe}");
            let (_tmp, t) = monitor(exe);
            assert_eq!(
                t.exec_identity(711, judged).map(|i| i.exe),
                Some(PathBuf::from(exe)),
                "{exe}"
            );
        }
    }

    /// Second review of #493 (mutation R3): the one-identity rule compares
    /// every field of the identity — two execs of one executable in the
    /// fork's tick that differ only in npm's entrypoint (`argv[1]`) are two
    /// identities: not known.
    #[test]
    fn two_execs_differing_only_in_npm_s_entrypoint_are_two_identities() {
        const MS: u64 = 1_000_000;
        let argv = |a: &[&str]| a.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        let tmp = TempDir::new().unwrap();
        let t = AuthSessionTracker::new(tmp.path());
        t.ingest_exec(700, 1, "/usr/bin/bash", &[], 5 * S, 5 * S, 1000);
        let npm = "/usr/lib/node_modules/npm/bin/npm-cli.js";
        t.ingest_exec(
            710,
            700,
            "/usr/bin/sudo",
            &argv(&["sudo", "-n"]),
            10_002 * MS,
            10_001 * MS,
            1000,
        );
        t.ingest_exec(
            710,
            700,
            "/usr/bin/sudo",
            &argv(&["sudo", npm]),
            10_006 * MS,
            10_001 * MS,
            1000,
        );
        write_exe(tmp.path(), 711, "/usr/bin/sudo");
        write_status(tmp.path(), 711, 710);
        write_started(tmp.path(), "711", 710, 1_000);
        assert_eq!(t.exec_identity(711, AsOf::Judged(10_050 * MS)), None);
    }

    /// Review of #493 (B3): the fork's upper bound is the fork's own tick
    /// and its rounding — an exec of the parent past it (a tick later) is
    /// never the fork's image, even as the only one.
    #[test]
    fn a_parent_s_exec_after_the_fork_s_tick_is_not_its_image() {
        const MS: u64 = 1_000_000;
        let tmp = TempDir::new().unwrap();
        let t = AuthSessionTracker::new(tmp.path());
        t.ingest_exec(700, 1, "/usr/bin/bash", &[], 5 * S, 5 * S, 1000);
        // sudo executed at 10.035 s, 35 ms after the fork's tick 1000
        t.ingest_exec(
            710,
            700,
            "/usr/bin/sudo",
            &[],
            10_035 * MS,
            10_001 * MS,
            1000,
        );
        write_exe(tmp.path(), 711, "/usr/bin/sudo");
        write_status(tmp.path(), 711, 710);
        write_started(tmp.path(), "711", 710, 1_000);
        exec_forked(
            &t,
            (712, 711),
            "/home/alice/nn/deploy/install.sh",
            10_050 * MS,
            10_045 * MS,
            0,
        );
        write_loginuid(tmp.path(), 712, 1000);
        write_stat(tmp.path(), 712, 711, 34816);
        assert!(!t.is_interactive_admin(712, AsOf::Judged(10_050 * MS)));
        assert_eq!(t.exec_identity(711, AsOf::Judged(10_050 * MS)), None);
    }

    /// Lot 278: `descends_from` by pid and start — the process itself or an
    /// ancestor; a later process given the pid (another start), a process
    /// outside the tree, PID 1 and a walk that loses the chain are not.
    /// Hops read from `/proc` (outside a judgement) are held to the start
    /// `/proc` shows.
    #[test]
    fn descends_from_is_by_pid_and_start() {
        let tmp = TempDir::new().unwrap();
        let t = AuthSessionTracker::new(tmp.path());
        // the installer (cached, started at 50 s = tick 5000, running) and its child
        t.ingest_exec(900, 800, "/usr/bin/bash", &[], 50 * S + 1, 50 * S, 0);
        write_started(tmp.path(), "900", 800, 5_000);
        t.ingest_exec(
            901,
            900,
            "/home/dev/nn/target/release/x",
            &[],
            52 * S,
            52 * S,
            0,
        );
        let judged = AsOf::Judged(52 * S);
        assert!(t.descends_from(901, judged, 900, 5_000));
        assert!(
            t.descends_from(900, judged, 900, 5_000),
            "the installer itself"
        );
        assert!(!t.descends_from(901, judged, 900, 7_000), "another start");
        // a process that took the pid within the suspended-time allowance of
        // the cached start (one tick later) is not the installer
        write_started(tmp.path(), "900", 800, 5_001);
        assert!(
            !t.descends_from(901, judged, 900, 5_000),
            "/proc shows another start"
        );
        write_started(tmp.path(), "900", 800, 5_000);
        // the installer gone: not known, not its tree
        std::fs::remove_dir_all(tmp.path().join("900")).unwrap();
        assert!(!t.descends_from(901, judged, 900, 5_000), "gone");
        write_started(tmp.path(), "900", 800, 5_000);
        assert!(!t.descends_from(901, judged, 901 + 1, 5_000), "another pid");
        assert!(!t.descends_from(901, judged, 1, 0), "never PID 1");
        assert!(!t.descends_from(901, judged, 0, 0));
        // outside a judgement, a parent known from /proc only (older than the
        // agent, as the start's scan finds it): by its start there
        write_started(tmp.path(), "self", 1, 100_000);
        write_exe(tmp.path(), 950, "/usr/bin/bash");
        write_status(tmp.path(), 950, 1);
        write_started(tmp.path(), "950", 1, 6_000);
        t.ingest_exec(951, 950, "/tmp/nn/x", &[], 61 * S, 61 * S, 0);
        assert!(t.descends_from(951, AsOf::Now, 950, 6_000));
        assert!(
            !t.descends_from(951, AsOf::Now, 950, 6_001),
            "/proc shows another start"
        );
    }

    /// Lot 278 (the lab's "R009 flake"): `sudo` with `use_pty` forks a
    /// monitor (no exec) that forks the command. `/proc` shows the
    /// monitor's start in clock ticks, rounded down, on the boot clock, less
    /// the time suspended: a monitor forked in the tick of sudo's exec
    /// shows a start before that exec. The parent's image at the fork was
    /// then looked up at that earlier time, found only "later", and the
    /// judged walk lost the session: an administrator's `sudo
    /// ./deploy/install.sh` at a terminal was not sanctioned, and R009
    /// killed it — whether it did depended on the milliseconds between
    /// sudo's exec and its fork. The parent is read at the latest time the
    /// fork can have happened; `/proc/<pid>/exe` must still be its image.
    #[test]
    fn sudo_s_monitor_forked_in_the_tick_of_sudo_s_exec_keeps_the_session() {
        const MS: u64 = 1_000_000;
        let tmp = TempDir::new().unwrap();
        let t = AuthSessionTracker::new(tmp.path());
        // the operator's shell (cached), sudo executed at 10.003 s
        t.ingest_exec(700, 1, "/usr/bin/bash", &[], 5 * S, 5 * S, 1000);
        t.ingest_exec(
            710,
            700,
            "/usr/bin/sudo",
            &[],
            10_003 * MS,
            10_001 * MS,
            1000,
        );
        // sudo's monitor, forked at 10.008 s: `/proc` shows tick 1000 (10.000 s)
        write_exe(tmp.path(), 711, "/usr/bin/sudo");
        write_status(tmp.path(), 711, 710);
        write_started(tmp.path(), "711", 710, 1_000);
        // the command, forked by the monitor, executes the script at 10.050 s
        exec_forked(
            &t,
            (712, 711),
            "/home/alice/nn/deploy/install.sh",
            10_050 * MS,
            10_045 * MS,
            0,
        );
        write_loginuid(tmp.path(), 712, 1000);
        write_stat(tmp.path(), 712, 711, 34816);
        let judged = AsOf::Judged(10_050 * MS);
        assert!(
            t.is_interactive_admin(712, judged),
            "the monitor runs sudo's image: the session is the administrator's"
        );
        // the monitor's image must still be the parent's: a fork that runs
        // something else (it executed since, or it was forked before the
        // parent executed sudo) is not sudo's
        write_exe(tmp.path(), 711, "/home/alice/payload");
        assert!(!t.is_interactive_admin(712, judged));
        // and a fork whose start is past the time judged is not its parent's
        write_exe(tmp.path(), 711, "/usr/bin/sudo");
        write_started(tmp.path(), "711", 710, 1_010);
        assert!(!t.is_interactive_admin(712, judged));
    }

    /// Lot 350 (named, F2-2: R009 High for an administrator's `sudo
    /// ./deploy/uninstall.sh` at a terminal, 3 runs in 7; the lab's journal:
    /// "its lineage is lost at pid <sudo's monitor> (running)"). The shell's
    /// fork that runs sudo first executed the shell's `-c` line in place
    /// (`bash -c 'cd … && sudo …'`, `script -c 'sudo …'`): its pid ran dash,
    /// then sudo. sudo's monitor, forked in the tick of sudo's exec, shows a
    /// start (rounded down to the tick) at which its parent still ran dash:
    /// the monitor (sudo's image) was no fork of dash's, and the session was
    /// lost — on `main` 88 of these 144 timings. Every timing keeps it now;
    /// a fork that runs the earlier image (forked before sudo's exec), or a
    /// later exec that is no authentication binary, lends nothing.
    #[test]
    fn sudo_executed_in_place_by_a_shell_keeps_its_monitor_s_session() {
        const US: u64 = 1_000;
        const MS: u64 = 1_000_000;
        let stat = |dir: &Path, pid: u32, ppid: u32, tty: i64, ticks: u64| {
            let d = dir.join(pid.to_string());
            fs::create_dir_all(&d).unwrap();
            fs::write(
                d.join("stat"),
                format!("{pid} (x) S {ppid} {pid} {pid} {tty} -1 4194560 0 0 0 0 0 0 0 0 20 0 1 0 {ticks} 0 0\n"),
            )
            .unwrap();
        };
        // the session: the shell 700, its fork 710 executing dash then
        // `second`, 710's fork 711 running `forked` (its monitor), the
        // command 712 that 711 forked; `a`..`e` the microseconds between
        let session = |a: u64, b: u64, c: u64, d: u64, e: u64, second: &str, forked: &str| {
            let tmp = TempDir::new().unwrap();
            let t = AuthSessionTracker::live_on(tmp.path(), 0);
            let tfs = 10_000 * MS + a * US;
            let te = tfs + b * US;
            let mf = te + c * US;
            let tfc = mf + d * US;
            let tc = tfc + e * US;
            t.ingest_exec(700, 1, "/usr/bin/bash", &[], 5_000 * MS, 5_000 * MS, 1000);
            stat(tmp.path(), 700, 1, 34816, 500);
            write_loginuid(tmp.path(), 700, 1000);
            t.ingest_exec(710, 700, "/usr/bin/dash", &[], tfs + 50 * US, tfs, 1000);
            t.ingest_exec(710, 700, second, &[], te, tfs, 1000);
            stat(tmp.path(), 710, 700, 34816, tfs / (10 * MS));
            write_exe(tmp.path(), 710, second);
            stat(tmp.path(), 711, 710, 34817, mf / (10 * MS));
            write_exe(tmp.path(), 711, forked);
            write_status(tmp.path(), 711, 710);
            exec_forked(&t, (712, 711), "/home/alice/nn/deploy/uninstall.sh", tc, tfc, 0);
            stat(tmp.path(), 712, 711, 34817, tfc / (10 * MS));
            write_loginuid(tmp.path(), 712, 1000);
            write_exe(tmp.path(), 712, "/usr/bin/bash");
            let admin = t.is_interactive_admin(712, AsOf::Judged(tc));
            (tmp, admin)
        };
        let mut lost = Vec::new();
        for a in [0, 3_000, 9_900] {
            for b in [100, 1_000, 5_000] {
                for c in [200, 1_000, 5_000, 12_000] {
                    for d in [100, 2_000] {
                        for e in [500, 3_000] {
                            if !session(a, b, c, d, e, "/usr/bin/sudo", "/usr/bin/sudo").1 {
                                lost.push(format!("a={a} b={b} c={c} d={d} e={e}"));
                            }
                        }
                    }
                }
            }
        }
        assert!(
            lost.is_empty(),
            "{} sessions lost:\n{}",
            lost.len(),
            lost.join("\n")
        );
        // the fork runs the earlier image (made before sudo's exec): not sudo's
        assert!(!session(0, 100, 200, 100, 500, "/usr/bin/sudo", "/usr/bin/dash").1);
        // the parent's later exec is no authentication binary: nothing lent
        assert!(
            !session(
                0,
                100,
                200,
                100,
                500,
                "/usr/bin/python3.12",
                "/usr/bin/python3.12"
            )
            .1
        );
        assert!(
            !session(
                0,
                100,
                200,
                100,
                500,
                "/home/alice/sudo",
                "/home/alice/sudo"
            )
            .1
        );
        // the same class (the mini-hunt): sudo-rs (Ubuntu 26.04), su, an
        // `env sudo`/`exec sudo` — any authentication binary a shell
        // executes in place of itself
        for auth in ["/usr/lib/cargo/bin/sudo", "/usr/bin/su", "/usr/bin/sudo-rs"] {
            assert!(session(0, 100, 200, 100, 500, auth, auth).1, "{auth}");
        }
    }

    /// Lot 351 (named, the review of #559, F2): a sudo or su vouches only
    /// through the process it ran as root after authenticating — the first
    /// exec of its child's process, forked by it (the kernel's record), as
    /// root, no PAM helper. Not: `sudo -A`'s askpass helper (the user's
    /// program, as the user, before any authentication) and what it runs,
    /// even as root, even in its own place; `sudoedit`'s editor; `sudo -u`
    /// or `su` to another user; `unix_chkpwd`; a process whose first exec
    /// is lost (four execs in place, no fork record). Still: the command,
    /// `sudo env … ./x` (an exec in place), a sudo further up (root's own
    /// `sudo -A`), a process older than the agent (the start's scan).
    #[test]
    fn only_what_sudo_ran_as_root_after_authenticating_vouches() {
        let tmp = TempDir::new().unwrap();
        write_loginuid(tmp.path(), 50, 1000);
        write_stat(tmp.path(), 50, 1, 34816);
        let t = AuthSessionTracker::new(tmp.path());
        t.ingest_exec(50, 1, "/usr/bin/bash", &[], 1, 1, 1000);
        t.ingest_exec(100, 50, "/usr/bin/sudo", &[], 2, 2, 1000);
        let admin = |pid: u32| t.is_interactive_admin(pid, AsOf::Now);
        // the askpass helper, its root payload, the payload it executes in place
        t.ingest_first_exec(200, 100, "/home/alice/askpass", 3, 1000);
        t.ingest_first_exec(201, 200, "/home/alice/payload", 4, 0);
        assert!(!admin(200) && !admin(201));
        let why = t.not_interactive_admin_because(201, AsOf::Now).unwrap();
        assert!(why.contains("(pid 100) ran nothing as root"), "{why}");
        assert!(why.contains("pid 200, its child"), "{why}");
        assert_eq!(t.interactive_admin_status(201, AsOf::Now), Some(false));
        t.ingest_exec(200, 100, "/home/alice/payload", &[], 5, 3, 0);
        assert!(!admin(200), "the askpass helper's process");
        // sudoedit's editor, sudo -u bob's command (not root)
        t.ingest_first_exec(210, 100, "/usr/bin/vim.basic", 6, 1000);
        t.ingest_first_exec(211, 100, "/usr/bin/psql", 7, 1001);
        assert!(!admin(210) && !admin(211));
        // pam_unix's helper, as root, before the credential check
        t.ingest_first_exec(220, 100, "/usr/sbin/unix_chkpwd", 8, 0);
        t.ingest_first_exec(221, 220, "/home/alice/payload", 9, 0);
        assert!(!admin(221));
        // a root exec under sudo with no fork record of it (not its first)
        t.ingest_exec(230, 100, "/home/alice/payload", &[], 10, 10, 0);
        assert!(!admin(230));
        // the command sudo ran as root, then `env` executing the script in
        // place — up to the history's three execs in place, not past them
        t.ingest_first_exec(240, 100, "/usr/bin/env", 11, 0);
        assert!(admin(240));
        for (i, exe) in ["/usr/bin/bash", "/usr/bin/nice", "/home/alice/x.sh"]
            .iter()
            .enumerate()
        {
            t.ingest_exec(240, 100, exe, &[], 12 + i as u64, 11, 0);
            assert!(admin(240), "{exe}");
        }
        t.ingest_exec(240, 100, "/home/alice/y.sh", &[], 15, 11, 0);
        assert!(!admin(240), "its first exec is no longer held");
        // root's own sudo -A in a root shell sudo ran: root's askpass
        t.ingest_first_exec(250, 100, "/usr/bin/bash", 16, 0);
        t.ingest_first_exec(251, 250, "/usr/bin/sudo", 17, 0);
        t.ingest_first_exec(252, 251, "/root/askpass", 18, 0);
        t.ingest_first_exec(253, 252, "/home/alice/x.sh", 19, 0);
        assert!(admin(253));
        // su to another user, then that user's sudo -A: no root after
        // authenticating anywhere
        t.ingest_first_exec(260, 50, "/usr/bin/su", 20, 1000);
        t.ingest_first_exec(261, 260, "/usr/bin/bash", 21, 1002);
        t.ingest_first_exec(262, 261, "/usr/bin/sudo", 22, 1002);
        t.ingest_first_exec(263, 262, "/home/carol/askpass", 23, 1002);
        t.ingest_first_exec(264, 263, "/home/carol/payload", 24, 0);
        assert!(!admin(264));
        // a root shell older than the agent (the start's scan: no exec seen)
        t.ingest_inner(
            270,
            100,
            "/usr/bin/bash",
            (None, false, None),
            Runs::Inline,
            0,
            (3, Some(0)),
            0,
            (None, 0, None),
        );
        t.ingest_first_exec(271, 270, "/home/alice/x.sh", 25, 0);
        assert!(admin(271));
        // and an askpass helper older than the agent
        t.ingest_inner(
            280,
            100,
            "/home/alice/askpass",
            (None, false, None),
            Runs::Inline,
            0,
            (3, Some(0)),
            1000,
            (None, 0, None),
        );
        t.ingest_first_exec(281, 280, "/home/alice/payload", 26, 0);
        assert!(!admin(281));
        // sudo's own process (sudoedit's copy back)
        assert!(admin(100));
    }

    /// Lot 351 (the review of #559, F6; ratchet): the sudo and su images
    /// the session check walks to ([`ELEVATION_EXES`]) are authentication
    /// binaries ([`AUTH_BINARY_EXES`]) — sudo's monitor takes its identity
    /// in the tick of sudo's exec only as one
    /// ([`is_auth_monitor_identity`]): an elevation binary listed in one
    /// list only lost its sessions again — and so are the PAM helpers the
    /// check refuses ([`PAM_HELPER_EXES`]).
    #[test]
    fn every_elevation_binary_and_pam_helper_is_an_authentication_binary() {
        for exe in ELEVATION_EXES.iter().chain(PAM_HELPER_EXES) {
            assert!(is_auth_binary(Path::new(exe)), "{exe}");
        }
        for exe in PAM_HELPER_EXES {
            assert!(!is_elevation_binary(Path::new(exe)), "{exe}");
        }
    }

    /// Lot 350 (F2-2): the session check says which of its parts failed —
    /// for R009's journal line — and nothing for an administrator's session.
    #[test]
    fn why_a_session_is_not_an_administrator_s_is_said() {
        let (_tmp, t) = admin_session(34816, 1000);
        assert_eq!(t.not_interactive_admin_because(200, AsOf::Now), None);
        let (_tmp, t) = admin_session(0, 1000);
        let why = t.not_interactive_admin_because(200, AsOf::Now).unwrap();
        assert!(why.contains("no controlling terminal"), "{why}");
        let (_tmp, t) = admin_session(34816, LOGINUID_UNSET);
        let why = t.not_interactive_admin_because(200, AsOf::Now).unwrap();
        assert!(why.contains("no login uid"), "{why}");
        let (_tmp, t) = admin_session(34816, 1000);
        let why = t.not_interactive_admin_because(999, AsOf::Now).unwrap();
        assert!(why.contains("lost at pid 999 (gone)"), "{why}");
        let tmp = TempDir::new().unwrap();
        let t = AuthSessionTracker::new(tmp.path());
        t.ingest_spawn(50, 1, "/usr/bin/bash", 1);
        t.ingest_spawn(200, 50, "/home/alice/x.sh", 2);
        let why = t.not_interactive_admin_because(200, AsOf::Now).unwrap();
        assert!(why.contains("no sudo or su"), "{why}");
        // with every part there but nothing running
        let tmp = TempDir::new().unwrap();
        let t = AuthSessionTracker::new(tmp.path());
        t.ingest_spawn(50, 40, "/usr/bin/bash", 1);
        t.ingest_spawn(100, 50, "/usr/bin/sudo", 2);
        t.ingest_first_exec(200, 100, "/usr/sbin/useradd", 3, 0);
        let why = t.not_interactive_admin_because(200, AsOf::Now).unwrap();
        assert!(why.contains("nothing of its session runs"), "{why}");
    }

    #[test]
    fn no_terminal_or_no_login_is_not_interactive_admin() {
        // `ssh host sudo …` without a terminal.
        let (_tmp, t) = admin_session(0, 1000);
        assert!(!t.is_interactive_admin(200, AsOf::Now));
        // A service: no login uid.
        let (_tmp, t) = admin_session(34816, LOGINUID_UNSET);
        assert!(!t.is_interactive_admin(200, AsOf::Now));
        // Never seen and not in /proc.
        let (_tmp, t) = admin_session(34816, 1000);
        assert!(!t.is_interactive_admin(999, AsOf::Now));
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
        t.ingest_first_exec(200, 100, "/usr/bin/tee", 3, 0);
        assert!(!t.is_interactive_admin(200, AsOf::Now), "nothing runs");
        write_loginuid(tmp.path(), 50, 1000);
        write_stat(tmp.path(), 50, 40, 0);
        assert!(
            !t.is_interactive_admin(200, AsOf::Now),
            "shell without a terminal"
        );
        write_stat(tmp.path(), 50, 40, 34816);
        assert!(t.is_interactive_admin(200, AsOf::Now));
        // A zombie writer (exited, not yet reaped) does not answer: its
        // running shell does.
        write_loginuid(tmp.path(), 200, 1000);
        fs::write(
            tmp.path().join("200").join("stat"),
            "200 (tee) Z 100 50 50 0 -1 0\n",
        )
        .unwrap();
        assert!(t.is_interactive_admin(200, AsOf::Now));
        // A running writer answers for itself, even when its shell would
        // pass: a background job detached from the terminal is not one.
        write_loginuid(tmp.path(), 200, 1000);
        write_stat(tmp.path(), 200, 100, 0);
        assert!(!t.is_interactive_admin(200, AsOf::Now));
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
        assert_eq!(
            t.interactive_admin_status(300, AsOf::Now),
            None,
            "monitor lost"
        );
        // sudo → tee directly, but nothing of the session runs any more.
        t.ingest_first_exec(400, 100, "/usr/bin/tee", 4, 0);
        assert_eq!(
            t.interactive_admin_status(400, AsOf::Now),
            None,
            "session gone"
        );
        // The shell still runs with a terminal and a login uid.
        write_loginuid(tmp.path(), 50, 1000);
        write_stat(tmp.path(), 50, 40, 34816);
        assert_eq!(t.interactive_admin_status(400, AsOf::Now), Some(true));
        // A chain that reads to PID 1 with no sudo is known: not an admin.
        t.ingest_spawn(500, 1, "/usr/bin/sh", 5);
        assert_eq!(t.interactive_admin_status(500, AsOf::Now), Some(false));
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
        t.ingest_first_exec(500, 490, "/usr/bin/bash", 6, 0);
        assert!(!t.is_interactive_admin(300, AsOf::Now));
        assert!(!t.is_interactive_admin(400, AsOf::Now));
        assert!(t.is_interactive_admin(500, AsOf::Now));
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
        let s = |a: &[&str]| runs_of(py, &argv(a)).script().map(str::to_string);
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
            runs_of(Path::new("/usr/bin/cat"), &argv(&["cat", "/x"])),
            Runs::Inline
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
            t.exec_identity(100, AsOf::Now),
            Some(ExecIdentity {
                exe: "/usr/bin/python3.12".into(),
                runs: Runs::Script("/usr/bin/aws".into()),
            })
        );
        // Not cached: /proc/<pid>/exe and cmdline.
        let d = tmp.path().join("200");
        fs::create_dir_all(&d).unwrap();
        symlink("/usr/bin/perl", d.join("exe")).unwrap();
        fs::write(d.join("cmdline"), b"perl\0-e\0print 1\0").unwrap();
        assert_eq!(
            t.exec_identity(200, AsOf::Now),
            Some(ExecIdentity {
                exe: "/usr/bin/perl".into(),
                // lot 310: an inline program (it was `Runs::Inline`)
                runs: Runs::Code,
            })
        );
        assert_eq!(t.exec_identity(300, AsOf::Now), None, "unknown pid");
    }

    #[test]
    fn clone_shares_state() {
        let a = AuthSessionTracker::new("/proc");
        let b = a.clone();
        a.ingest_spawn(100, 1, "/usr/bin/sudo", 1);
        // Clone observes the ingest — same Arc-backed state.
        assert!(b.is_auth_mediated(100, AsOf::Now));
    }

    /// An allowlist written in `comm` names (15 bytes) still names the
    /// program the kernel cut it from; a shorter entry is never a prefix.
    #[test]
    fn a_comm_length_entry_names_the_longer_program() {
        let id = |exe: &str| ExecIdentity {
            exe: PathBuf::from(exe),
            runs: Runs::Inline,
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
        t.session_workload(pid, AsOf::Now).map(|w| w.path)
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
            t.session_workload(800, AsOf::Now),
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
        assert_eq!(t.session_workload(400, AsOf::Now), None);
        assert_eq!(t.session_workload(999, AsOf::Now), None, "never seen");

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
        assert_eq!(
            t.session_workload(700, AsOf::Now),
            None,
            "no ancestor outside it"
        );
        assert!(!in_agent_containment("/northnarrow.slice-other/x.scope"));
    }

    // ── Lot 292 (external bug hunt, editions 1.2/1.3): BUG-42, BUG-44,
    // BUG-56 ──────────────────────────────────────────────────────────

    /// BUG-42: a shell's `-e` is errexit (`#!/bin/sh -e`: the kernel runs
    /// `/bin/sh -e <script>`), not an inline program: the script is named.
    #[test]
    fn shell_errexit_script_is_named() {
        let id = |exe: &str, a: &[&str]| ExecIdentity::of_exec(exe, &argv(a));
        let mut wrong = Vec::new();
        for (exe, a, want) in [
            (
                "/bin/sh",
                &["/bin/sh", "-e", "/usr/lib/dpkg/info/foo.postinst"][..],
                "/usr/lib/dpkg/info/foo.postinst",
            ),
            (
                "/bin/bash",
                &["/bin/bash", "-eu", "/usr/bin/legit"][..],
                "/usr/bin/legit",
            ),
            (
                "/usr/bin/bash",
                &["bash", "-e", "/tmp/enc.sh"][..],
                "/tmp/enc.sh",
            ),
            // lot 292: an option's argument, and the end of the options
            (
                "/usr/bin/bash",
                &["bash", "-euo", "pipefail", "/usr/bin/legit"][..],
                "/usr/bin/legit",
            ),
            (
                "/usr/bin/bash",
                &["bash", "-O", "extglob", "/usr/bin/legit"][..],
                "/usr/bin/legit",
            ),
            (
                "/usr/bin/bash",
                &["bash", "-oo", "errexit", "nounset", "/usr/bin/legit"][..],
                "/usr/bin/legit",
            ),
            (
                "/usr/bin/bash",
                &["bash", "+e", "+O", "extglob", "/tmp/enc.sh"][..],
                "/tmp/enc.sh",
            ),
            (
                "/usr/bin/bash",
                &["bash", "--norc", "--rcfile", "/etc/x", "/tmp/enc.sh"][..],
                "/tmp/enc.sh",
            ),
            (
                "/usr/bin/dash",
                &["sh", "-", "/tmp/enc.sh"][..],
                "/tmp/enc.sh",
            ),
            (
                "/usr/bin/dash",
                &["sh", "--", "/tmp/enc.sh"][..],
                "/tmp/enc.sh",
            ),
        ] {
            let got = id(exe, a);
            if got.script() != Some(want) {
                wrong.push(format!("{a:?} -> {:?}", got.runs));
            }
        }
        assert!(wrong.is_empty(), "errexit scripts not named: {wrong:?}");
        // controls: an inline program, or standard input, stays unnamed
        // (lot 310: as `Runs::Code`, split from `Runs::Inline`, which keeps
        // a shell running no program)
        for a in [
            &["sh", "-c", "echo"][..],
            &["bash", "-ec", "echo"],
            &["sh", "-e", "-c", "echo"],
            &["bash", "-euo", "pipefail", "-c", "echo"],
            // `-s`: the commands are read from standard input, and the
            // arguments are its positional parameters — `/usr/bin/legit`
            // is not what runs
            &["sh", "-s", "/usr/bin/legit"],
        ] {
            assert_eq!(id("/usr/bin/bash", a).runs, Runs::Code, "{a:?}");
        }
        assert_eq!(id("/usr/bin/bash", &["bash"]).runs, Runs::Inline);
        // a script `-e` names is installed only from a system tree
        assert!(id(
            "/bin/sh",
            &["/bin/sh", "-e", "/usr/lib/dpkg/info/foo.postinst"]
        )
        .is_installed_program());
        assert!(!id("/usr/bin/bash", &["bash", "-e", "/tmp/enc.sh"]).is_client(&["bash"]));
    }

    /// BUG-44: Python's `-O` takes no argument (nor do Perl's `-X`/`-W`):
    /// the next argument is the script, not one to skip — else any script
    /// claims the identity of whatever path follows it.
    #[test]
    fn option_without_argument_does_not_skip_the_script() {
        let id = |exe: &str, a: &[&str]| ExecIdentity::of_exec(exe, &argv(a));
        let py = id(
            "/usr/bin/python3",
            &["python3", "-O", "/home/u/evil.py", "/usr/bin/aws"],
        );
        let pl = id(
            "/usr/bin/perl",
            &["perl", "-X", "/home/u/evil.pl", "/usr/bin/aws"],
        );
        // what the spoof buys, read before the assertions
        let claims = (
            py.script().map(str::to_string),
            py.is_installed_program(),
            py.is_client(&["aws"]),
            pl.script().map(str::to_string),
            pl.is_client(&["aws"]),
        );
        assert_eq!(
            claims,
            (
                Some("/home/u/evil.py".to_string()),
                false,
                false,
                Some("/home/u/evil.pl".to_string()),
                false
            ),
            "(py script, py installed, py client aws, pl script, pl client aws)"
        );
    }

    /// BUG-44, the same family: an option that takes no argument skips no
    /// script (Perl's `-W`), and one that takes a separate argument skips
    /// it (Node's `-r`/`--require`, Ruby's `-r`/`-I`): either way the
    /// identity is the program the interpreter runs, read with its own
    /// option table.
    #[test]
    fn family_option_arguments_are_paired_per_interpreter() {
        let id = |exe: &str, a: &[&str]| ExecIdentity::of_exec(exe, &argv(a)).runs;
        let script = |s: &str| Runs::Script(s.into());
        // lot 310 (the review of #539, finding 2): an option that loads the
        // caller's code before the script (`node -r`, `--require`, `perl
        // -I`, `-M`, `-d:`, `ruby -r`, `-I`) leaves the script named but not
        // all that runs: not known (it was `Script`; the arity this test is
        // about is unchanged — the script read is the same)
        let loaded = |s: &str| Runs::Unknown(Some(s.into()));
        let mut wrong = Vec::new();
        for (exe, a, want) in [
            (
                "/usr/bin/perl",
                &["perl", "-W", "/tmp/e.pl", "/usr/bin/x"][..],
                script("/tmp/e.pl"),
            ),
            (
                "/usr/bin/node",
                &["node", "-r", "/usr/lib/x.js", "/tmp/e.js"][..],
                loaded("/tmp/e.js"),
            ),
            (
                "/usr/bin/node",
                &["node", "--require", "/usr/lib/x.js", "/tmp/e.js"][..],
                loaded("/tmp/e.js"),
            ),
            // lot 292: the rest of each family's table
            (
                "/usr/bin/python3.12",
                &["python3", "-Wignore", "/tmp/e.py", "/usr/bin/aws"][..],
                script("/tmp/e.py"),
            ),
            (
                "/usr/bin/python3.12",
                &["python3", "-X", "dev", "-OO", "/tmp/e.py"][..],
                script("/tmp/e.py"),
            ),
            (
                "/usr/bin/python3.12",
                &["python3", "-Xdev", "-uE", "/tmp/e.py"][..],
                script("/tmp/e.py"),
            ),
            (
                "/usr/bin/python3.12",
                &["python3", "-mhttp.server", "8080"][..],
                script("http.server"),
            ),
            (
                "/usr/bin/python3.12",
                &["python3", "--check-hash-based-pycs", "never", "/tmp/e.py"][..],
                script("/tmp/e.py"),
            ),
            // lot 310, the review of #539's differential test: `-` is the
            // standard input's program, the caller's (it read as a script
            // named `-`)
            (
                "/usr/bin/python3.12",
                &["python3", "-", "/usr/bin/aws"][..],
                Runs::Code,
            ),
            (
                "/usr/bin/perl",
                &["perl", "-I", "/usr/share/perl5", "/tmp/e.pl"][..],
                loaded("/tmp/e.pl"),
            ),
            (
                "/usr/bin/perl",
                &["perl", "-Mstrict", "-wT", "/tmp/e.pl"][..],
                loaded("/tmp/e.pl"),
            ),
            (
                "/usr/bin/perl",
                &["perl", "-pi.bak", "/tmp/e.pl"][..],
                script("/tmp/e.pl"),
            ),
            // `-i` takes the rest: `-pie` is an extension `e`, not `-e`
            (
                "/usr/bin/perl",
                &["perl", "-pie", "/tmp/e.pl"][..],
                script("/tmp/e.pl"),
            ),
            (
                "/usr/bin/perl",
                &["perl", "-0777", "-n", "/tmp/e.pl"][..],
                script("/tmp/e.pl"),
            ),
            (
                "/usr/bin/perl",
                &["perl", "-d:NYTProf", "/tmp/e.pl"][..],
                loaded("/tmp/e.pl"),
            ),
            (
                "/usr/bin/perl",
                &["perl", "-F:", "-s", "/tmp/e.pl"][..],
                script("/tmp/e.pl"),
            ),
            (
                "/usr/bin/ruby3.2",
                &["ruby", "-r", "json", "/tmp/e.rb", "/usr/bin/x"][..],
                loaded("/tmp/e.rb"),
            ),
            (
                "/usr/bin/ruby3.2",
                &["ruby", "-I", "/usr/lib/ruby/x", "-rjson", "/tmp/e.rb"][..],
                loaded("/tmp/e.rb"),
            ),
            (
                "/usr/bin/ruby3.2",
                &["ruby", "-W0", "-Ku", "--disable", "gems", "/tmp/e.rb"][..],
                script("/tmp/e.rb"),
            ),
            (
                "/usr/bin/node",
                &[
                    "node",
                    "--max-old-space-size=4096",
                    "--no-warnings",
                    "/tmp/e.js",
                ][..],
                script("/tmp/e.js"),
            ),
            (
                "/usr/bin/node",
                &["node", "--", "/tmp/e.js"][..],
                script("/tmp/e.js"),
            ),
            (
                "/usr/bin/node",
                &[
                    "node",
                    "--harmony-shadow-realm",
                    "--title",
                    "x",
                    "/tmp/e.js",
                ][..],
                script("/tmp/e.js"),
            ),
            (
                "/usr/bin/ruby",
                &["ruby", "-W:no-deprecated", "-rjson", "/tmp/e.rb"][..],
                loaded("/tmp/e.rb"),
            ),
            (
                "/usr/bin/perl",
                &["perl", "-lw", "/tmp/e.pl"][..],
                script("/tmp/e.pl"),
            ),
            (
                "/usr/bin/perl",
                &["perl", "-0x1Fw", "/tmp/e.pl"][..],
                script("/tmp/e.pl"),
            ),
            (
                "/usr/bin/ruby",
                &[
                    "ruby",
                    "--disable-gems",
                    "--enable",
                    "frozen-string-literal",
                    "/tmp/e.rb",
                ][..],
                script("/tmp/e.rb"),
            ),
            // inline programs (lot 310: `Runs::Code`, split from `Runs::Inline`)
            (
                "/usr/bin/perl",
                &["perl", "-lane", "/usr/bin/aws"][..],
                Runs::Code,
            ),
            (
                "/usr/bin/perl",
                &["perl", "-le", "/usr/bin/aws"][..],
                Runs::Code,
            ),
            ("/usr/bin/perl", &["perl", "-de", "0"][..], Runs::Code),
            (
                "/usr/bin/perl",
                &["perl", "-CSD", "-E", "say 1"][..],
                Runs::Code,
            ),
            (
                "/usr/bin/ruby",
                &["ruby", "-ne", "/usr/bin/aws"][..],
                Runs::Code,
            ),
            (
                "/usr/bin/node",
                &["node", "-pe", "/usr/bin/aws"][..],
                Runs::Code,
            ),
            ("/usr/bin/node", &["node", "--eval", "1"][..], Runs::Code),
            ("/usr/bin/python3", &["python3", "-Ic", "1"][..], Runs::Code),
        ] {
            let got = id(exe, a);
            if got != want {
                wrong.push(format!("{a:?} -> {got:?}, not {want:?}"));
            }
        }
        assert!(wrong.is_empty(), "{wrong:#?}");
    }

    /// Lot 292: an option the interpreter's table does not hold, or one
    /// whose argument is missing, leaves what it runs not known — never the
    /// next path. Such an identity is no client and no installed program,
    /// even when the argument that may be its script lies in a system tree.
    #[test]
    fn an_option_the_table_does_not_hold_leaves_the_script_unknown() {
        let id = |exe: &str, a: &[&str]| ExecIdentity::of_exec(exe, &argv(a));
        for (exe, a, guess) in [
            (
                "/usr/bin/python3",
                &["python3", "-Z", "/usr/bin/aws"][..],
                Some("/usr/bin/aws"),
            ),
            (
                "/usr/bin/node",
                &["node", "--frobnicate", "/tmp/e.js", "/usr/bin/aws"][..],
                Some("/tmp/e.js"),
            ),
            (
                "/usr/bin/node",
                &["node", "--frobnicate", "--inspect", "/tmp/e.js"][..],
                Some("/tmp/e.js"),
            ),
            (
                "/usr/bin/zsh",
                &["zsh", "-T", "/usr/bin/aws", "/tmp/e.sh"][..],
                Some("/usr/bin/aws"),
            ),
            (
                "/usr/bin/perl",
                &["perl", "--frobnicate", "/usr/bin/aws"][..],
                Some("/usr/bin/aws"),
            ),
            ("/usr/bin/python3", &["python3", "-W"][..], None),
            (
                "/usr/bin/zsh",
                &["zsh", "-", "/usr/bin/aws"][..],
                Some("/usr/bin/aws"),
            ),
            (
                "/usr/bin/bash",
                &["bash", "+", "/usr/bin/aws"][..],
                Some("/usr/bin/aws"),
            ),
            ("/usr/bin/bash", &["bash", "-o"][..], None),
            (
                "/usr/bin/perl",
                &["perl", "-M", "/usr/bin/aws"][..],
                Some("/usr/bin/aws"),
            ),
        ] {
            let i = id(exe, a);
            assert_eq!(i.runs, Runs::Unknown(guess.map(Into::into)), "{a:?}");
            assert_eq!(i.script(), None, "{a:?}");
            assert!(!i.is_client(&["aws", "e.js", "e.sh"]), "{a:?}");
            assert!(
                !i.is_client(&["/usr/"]),
                "{a:?}: not even by a client's tree"
            );
            assert!(!i.is_installed_program(), "{a:?}");
        }
        // what a record and a staging check still see
        let i = id("/usr/bin/node", &["node", "--frobnicate", "/tmp/e.js"]);
        assert_eq!(i.runs.mentioned(), Some("/tmp/e.js"));
        assert_eq!(
            i.program(),
            "/usr/bin/node /tmp/e.js (options not understood)"
        );
        // no argv to read: not known for an interpreter, the file for a binary
        assert_eq!(
            ExecIdentity::of_exe("/usr/bin/python3").runs,
            Runs::Unknown(None)
        );
        assert_eq!(ExecIdentity::of_exe("/usr/sbin/nginx").runs, Runs::Inline);
    }

    /// BUG-56: a process older than the agent (seeded at tick 400) executes
    /// at 30 s; the exec carries the kernel's exact start (4.003217 s,
    /// inside tick 400). An event at 20 s is judged on the seeded image
    /// (`seed_from_proc`'s doc), not "not known".
    #[test]
    fn seeded_image_is_the_past_of_an_exec_with_the_exact_start() {
        let proc = TempDir::new().unwrap();
        write_started(proc.path(), "self", 1, 500);
        write_exe(proc.path(), 4800, "/usr/bin/bash");
        write_status(proc.path(), 4800, 1);
        write_started(proc.path(), "4800", 1, 400);
        let t = AuthSessionTracker::new(proc.path());
        assert_eq!(t.seed_from_proc(), 1);
        t.ingest_exec(4800, 1, "/usr/bin/restic", &[], 30 * S, 4_003_217_000, 1000);
        assert_eq!(
            t.exec_identity(4800, AsOf::Judged(31 * S)).map(|i| i.exe),
            Some(PathBuf::from("/usr/bin/restic"))
        );
        assert_eq!(
            t.exec_identity(4800, AsOf::Judged(20 * S)).map(|i| i.exe),
            Some(PathBuf::from("/usr/bin/bash")),
            "an event at 20 s, before the exec at 30 s, is the seeded image's"
        );
    }

    /// BUG-56: two entries of one pid are one process when their starts
    /// agree — exact against exact, ticks against an exact start (either
    /// way), ticks against the same ticks.
    #[test]
    fn same_start_reads_the_ticks_either_way() {
        let t = AuthSessionTracker::new(TempDir::new().unwrap().path());
        let e = |start_ns: u64, start_ticks: Option<u64>| Entry {
            ppid: 1,
            exe: PathBuf::from("/usr/bin/bash"),
            spawn_ns: 0,
            start_ns,
            js_pm: None,
            encrypts: false,
            argv: None,
            runs: Runs::Inline,
            start_ticks,
            uid: 0,
            image: None,
            exec_file: None,
            fork_parent: 0,
        };
        let exact = e(4_003_217_000, None);
        let seeded = e(4_000_000_000, Some(400));
        assert!(t.same_start(&seeded, &exact));
        assert!(t.same_start(&exact, &seeded));
        assert!(t.same_start(&seeded, &e(3_990_000_000, Some(400))));
        assert!(!t.same_start(&seeded, &e(4_010_000_000, Some(401))));
        assert!(t.same_start(&exact, &e(4_003_217_000, None)));
        assert!(!t.same_start(&exact, &e(4_003_217_001, None)));
        let later = e(9_000_000_000, None);
        assert!(!t.same_start(&seeded, &later));
        assert!(!t.same_start(&later, &seeded));
    }

    /// BUG-56, for a fork the sweep entered: its start is read from
    /// `/proc` too (tick 1200). When it executes later (`tar`, the exec's
    /// exact start inside that tick), an event before that exec is judged on
    /// the fork's image, the parent's script — not "not known".
    #[test]
    fn a_swept_fork_s_image_is_the_past_of_its_later_exec() {
        let proc = TempDir::new().unwrap();
        let t = AuthSessionTracker::new(proc.path());
        t.ingest_exec(600, 1, "/usr/bin/dpkg", &[], 10 * S, 10 * S, 0);
        write_exe(proc.path(), 600, "/usr/bin/dpkg");
        write_status(proc.path(), 600, 1);
        write_started(proc.path(), "600", 1, 1_000);
        let script = argv(&["sh", "/var/lib/dpkg/info/x.postinst"]);
        t.ingest_exec(601, 600, "/usr/bin/dash", &script, 11 * S, 11 * S, 0);
        write_exe(proc.path(), 601, "/usr/bin/dash");
        write_status(proc.path(), 601, 600);
        write_started(proc.path(), "601", 600, 1_100);
        write_exe(proc.path(), 602, "/usr/bin/dash");
        write_status(proc.path(), 602, 601);
        write_started(proc.path(), "602", 601, 1_200);
        assert_eq!(t.sweep().forks, 1);
        t.ingest_exec(602, 601, "/usr/bin/tar", &[], 20 * S, 12_004_000_000, 0);
        let id = t
            .exec_identity(602, AsOf::Judged(15 * S))
            .expect("the fork's image");
        assert_eq!(
            (id.exe, id.runs),
            (
                PathBuf::from("/usr/bin/dash"),
                Runs::Script("/var/lib/dpkg/info/x.postinst".into())
            )
        );
    }

    /// BUG-56, for an orphan the sweep adopted (its start read from `/proc`,
    /// tick 1200): when it executes later (the exec's exact start inside
    /// that tick), an event after the sweep and before that exec is judged on
    /// the adopted image.
    #[test]
    fn an_adopted_orphan_s_image_is_the_past_of_its_later_exec() {
        let proc = TempDir::new().unwrap();
        let t = AuthSessionTracker::live_on(proc.path(), 0);
        t.ingest_exec(600, 1, "/usr/bin/bash", &[], 5 * S, 5 * S, 1000);
        write_exe(proc.path(), 600, "/usr/bin/bash");
        write_status_uid(proc.path(), 600, 1, 1000);
        write_started(proc.path(), "600", 1, 500);
        t.ingest_exec(610, 600, "/usr/bin/clamscan", &[], 10 * S, 10 * S, 1000);
        write_exe(proc.path(), 620, "/usr/bin/clamscan");
        write_status_uid(proc.path(), 620, 600, 1000);
        write_started(proc.path(), "620", 600, 1_200);
        assert_eq!(t.sweep().orphans, 1);
        let swept = H::monotonic_ns();
        t.ingest_exec(
            620,
            600,
            "/usr/bin/tar",
            &[],
            swept + 10 * S,
            12_004_000_000,
            1000,
        );
        assert_eq!(
            t.exec_identity(620, AsOf::Judged(swept + 5 * S))
                .map(|i| i.exe),
            Some(PathBuf::from("/usr/bin/clamscan"))
        );
    }

    /// BUG-56, the other side: a pid reused by a process that started after
    /// the seeded one (10 s, not inside tick 400) and executed at 30 s —
    /// at 20 s the pid was that later process, whose image then is not
    /// known: not the seeded one's.
    #[test]
    fn a_reused_pid_s_seeded_image_is_not_the_later_process_past() {
        let proc = TempDir::new().unwrap();
        write_started(proc.path(), "self", 1, 500);
        write_exe(proc.path(), 4800, "/usr/bin/bash");
        write_status(proc.path(), 4800, 1);
        write_started(proc.path(), "4800", 1, 400);
        let t = AuthSessionTracker::new(proc.path());
        assert_eq!(t.seed_from_proc(), 1);
        t.ingest_exec(4800, 1, "/usr/bin/restic", &[], 30 * S, 10 * S, 1000);
        assert_eq!(t.exec_identity(4800, AsOf::Judged(20 * S)), None);
        // before the later process started, the pid was the seeded one
        assert_eq!(
            t.exec_identity(4800, AsOf::Judged(9 * S)).map(|i| i.exe),
            Some(PathBuf::from("/usr/bin/bash"))
        );
        // an exec whose start lies past the seeded tick and its slack (two
        // ticks: 4.02 s) is another process's; one inside it, the same
        write_exe(proc.path(), 4801, "/usr/bin/bash");
        write_status(proc.path(), 4801, 1);
        write_started(proc.path(), "4801", 1, 400);
        write_exe(proc.path(), 4802, "/usr/bin/bash");
        write_status(proc.path(), 4802, 1);
        write_started(proc.path(), "4802", 1, 400);
        assert_eq!(t.seed_from_proc(), 2);
        t.ingest_exec(4801, 1, "/usr/bin/restic", &[], 30 * S, 4_020_000_001, 1000);
        t.ingest_exec(4802, 1, "/usr/bin/restic", &[], 30 * S, 4_020_000_000, 1000);
        assert_eq!(t.exec_identity(4801, AsOf::Judged(20 * S)), None);
        assert_eq!(
            t.exec_identity(4802, AsOf::Judged(20 * S)).map(|i| i.exe),
            Some(PathBuf::from("/usr/bin/bash"))
        );
    }
}
