//! R004 — memfd-style exec via `/proc/self/fd/*` or `/proc/<pid>/fd/*`.
//!
//! # systemd-executor exemption (Tappa 10.6.5)
//!
//! On systemd ≥ 254 (e.g. Ubuntu 24.04 / systemd 255) **every** service is
//! launched by `systemd-executor`, which `fexecve()`s an `O_CLOEXEC` file
//! descriptor. The kernel therefore reports the exec target as
//! `/proc/self/fd/<n>` — byte-for-byte identical, by path alone, to a
//! genuine memfd/fileless exec. Without an exemption R004 fires on the
//! launch of *every* systemd unit, KillProcessTree-ing the agent's own
//! systemd-managed restart, its watchdog, and any service started after
//! the agent. (See issue: R004 false-positive on systemd-executor.)
//!
//! The distinguishing signal is the *provenance* of the exec, not the
//! `/proc/self/fd` path: a legitimate systemd launch is (a) parented by
//! systemd — `ppid == 1` for system units, or a `systemd` user-manager —
//! **and** (b) carries the real `systemd-executor` binary in `argv[0]`
//! (systemd sets argv[0] to the on-disk executor path before the fexecve).
//!
//! We require **both** signals (logical AND). External audit PROC-001
//! (NN-AUD-001) found both forgeable: the parent test accepted a parent
//! whose `comm` was `systemd` (any process sets its own with
//! `prctl(PR_SET_NAME)`), and the launcher test accepted any `argv[0]`
//! ending in `/systemd-executor` (the caller chooses `argv[0]`). Both now
//! read what the kernel executed: the executed file is the real
//! `systemd-executor` (exec sensor identity: a root-owned system tree, a
//! real file, not a memfd), and the parent is PID 1 or a `systemd --user`
//! manager by its own exec identity. In tracepoint mode, with no exec
//! identity, `argv[0]` must be an install path exactly and only PID 1
//! counts as the parent.
//!
//! # Lot 310 (external bug hunt, edition 1.4: BUG-88, BUG-103)
//!
//! LSM mode (the default) decides on the executed file's own flags: a
//! memfd, or an unlinked file (`i_nlink == 0`: `O_TMPFILE`, opened then
//! deleted) is fileless **whatever path reached it**. It used to ask the
//! caller's string to be `/proc/self/fd/N` too, and `/proc/thread-self/fd/N`,
//! `/proc/self/task/<tid>/fd/N`, `/dev/stdin`, a relative `fd/3` from a
//! `/proc/self` working directory, a symlink in a home directory, `/proc/<pid>/exe`
//! and `map_files/` each ran an unlinked file without the kill. Three
//! launches of an unlinked image are not fileless, each told by the
//! kernel's identity of the file, never by its name:
//!
//! - the agent's own worker ([`OwnWorkerLaunch`], R14a);
//! - systemd's executor left unlinked by an upgrade: its `(dev, ino)` is
//!   one the packaged executor has on this host now ([`ExecutorImages`]:
//!   the packaged file at its install path, the copies PID 1 and genuine
//!   user managers hold — re-read every 10 s), for the first exec of a
//!   process systemd FORKED (the kernel's record, `fork_parent`; the
//!   re-check of #539, N1 and N2). BUG-103: it was a
//!   file *named* `systemd-executor` in any root-owned tree — `/opt/app/`,
//!   which an application's user often owns, included — with any parent;
//! - a process re-executing the very image its parent runs (`(dev, ino)`
//!   from the lineage's record of the parent's exec): Chromium's children
//!   and Docker's `reexec` run `/proc/self/exe`, which after a package
//!   upgrade is the unlinked old image. No new code runs: the parent ran
//!   that file, and was judged, when it was linked.
//!
//! Tracepoint mode has no identity: the caller's path is read by the
//! posture's one reader of a `/proc` link
//! ([`crate::posture::proc_link::reopens_a_descriptor`]: every per-thread
//! and `/dev` name of a descriptor, folded); a symlink or a relative path
//! there is a residual of that mode.

use nn_model::{Event, ResponseAction, Severity, Verdict};

use crate::decision::attack::{AttackRef, Tactic};
use crate::decision::{rules::build_verdict, Rule};
use crate::posture::host::PostureHost;

/// R14a (plan §3.5): how the agent starts its own workers — the one
/// `/proc/self/fd` exec R004 knows to be the agent's. The core runs its
/// binary from the descriptor it opened at boot (`/proc/self/fd/N`), as
/// the `northnarrow-worker` account, with the worker's command line; after
/// an upgrade that file is unlinked, which is the fileless signal of LSM
/// mode. The launch is the agent's when every fact holds:
///
/// - the parent is the agent's core (`ppid`: only the core's own forks have
///   it as their parent);
/// - the path is exactly the core's descriptor's, the account the
///   workers', and the command line exactly a worker's
///   (`northnarrow-agent --worker <kind> --ipc-fd 3`, a known kind);
/// - with the exec sensor's identity (LSM mode), what the kernel executed is
///   the core's own image, `(dev, ino)`, whether unlinked or not.
///
/// Without the identity (tracepoint mode) the first two decide.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OwnWorkerLaunch {
    pub agent_pid: u32,
    /// `/proc/self/fd/<n>`.
    pub exec_path: String,
    /// `(dev, ino)` of the core's image, as the exec sensor reports an
    /// executed file (lot 310: the device in the kernel's form, `MKDEV` —
    /// it was `stat(2)`'s, which matched no device with a major number).
    pub image: (u64, u64),
    /// The `northnarrow-worker` account's uid.
    pub uid: u32,
    /// Lot 276: the export worker's account's (`northnarrow-export`;
    /// `None`: no such account, no export worker).
    pub export_uid: Option<u32>,
}

impl OwnWorkerLaunch {
    fn is(
        &self,
        ppid: u32,
        uid: u32,
        filename: &str,
        argv: &[String],
        exe: &nn_model::ExeIdentity,
    ) -> bool {
        use common::wire::exe::exe_flags::{KNOWN, PROC_EXE};
        let kind = match argv {
            [a0, w, kind, f, three]
                if a0 == "northnarrow-agent"
                    && w == "--worker"
                    && f == "--ipc-fd"
                    && three == "3" =>
            {
                nn_proto::ipc::WorkerKind::from_name(kind)
            }
            _ => None,
        };
        // each kind its account: the export worker's is its own (lot 276)
        let account = match kind {
            Some(nn_proto::ipc::WorkerKind::Parse) => Some(self.uid),
            Some(nn_proto::ipc::WorkerKind::Export) => self.export_uid,
            None => None,
        };
        let argv_ok = kind.is_some();
        ppid == self.agent_pid
            && self.agent_pid != 0
            && account == Some(uid)
            && uid != 0
            && filename == self.exec_path
            && argv_ok
            && (exe.flags & (KNOWN | PROC_EXE) == 0 || (exe.dev, exe.ino) == self.image)
    }
}

/// Lot 310 (BUG-103): the identities `(dev, ino)` the packaged
/// `systemd-executor` has had on this host, as the exec sensor reports an
/// executed file (the device in the kernel's form, `MKDEV`, not `stat(2)`'s
/// encoding) — the files at its install paths
/// as the agent saw them, and the ones systemd's managers held open when it
/// started (`nn_linux::systemd_executor`). PID 1 keeps launching units from
/// the image it opened until its re-exec, so an upgrade leaves it running
/// an unlinked one; the agent's records keep the ones before (at most
/// [`ExecutorImages::CAP`], the oldest out first). Shared: the agent's
/// refresh records, R004 reads.
#[derive(Clone, Debug, Default)]
pub struct ExecutorImages(std::sync::Arc<parking_lot::RwLock<ExecutorSets>>);

/// [`ExecutorImages`]' two sets.
#[derive(Debug, Default)]
struct ExecutorSets {
    executors: Vec<(u64, u64)>,
    /// Lot 310 (the re-check of #539, N1): the identities of systemd's
    /// manager (the packaged binary, PID 1's image): a user's manager forks
    /// the executor's launches too, and is told by its image.
    managers: Vec<(u64, u64)>,
}

/// `ids` sorted, deduplicated, without `(0, 0)`, at most `cap`.
fn normalised(mut ids: Vec<(u64, u64)>, cap: usize) -> Vec<(u64, u64)> {
    ids.retain(|id| *id != (0, 0));
    ids.sort_unstable();
    ids.dedup();
    ids.truncate(cap);
    ids
}

impl ExecutorImages {
    /// The identities kept: more than a host's upgrades between two
    /// re-execs of its managers.
    pub const CAP: usize = 16;

    /// Record `id`; `true` when it is new. `(0, 0)` is no identity.
    pub fn record(&self, id: (u64, u64)) -> bool {
        if id == (0, 0) {
            return false;
        }
        let mut s = self.0.write();
        if s.executors.contains(&id) {
            return false;
        }
        if s.executors.len() == Self::CAP {
            s.executors.remove(0);
        }
        s.executors.push(id);
        true
    }

    /// Lot 310 (the review of #539, finding 3): the identities the executor
    /// has now, in place of every one before — an executor no manager holds
    /// and no install path links any more is freed, and its inode number
    /// may be a user's file's next (`(0, 0)` dropped, at most
    /// [`Self::CAP`]). `true` when the set changed.
    pub fn replace(&self, ids: Vec<(u64, u64)>) -> bool {
        let ids = normalised(ids, Self::CAP);
        let mut s = self.0.write();
        let mut before = s.executors.clone();
        before.sort_unstable();
        let changed = before != ids;
        s.executors = ids;
        changed
    }

    /// Lot 310 (the re-check of #539, N1): the manager's identities now
    /// (the packaged `systemd`, PID 1's image), in place of the ones
    /// before; `true` when the set changed.
    pub fn replace_managers(&self, ids: Vec<(u64, u64)>) -> bool {
        let ids = normalised(ids, Self::CAP);
        let mut s = self.0.write();
        let changed = s.managers != ids;
        s.managers = ids;
        changed
    }

    /// How many executor identities there are.
    pub fn len(&self) -> usize {
        self.0.read().executors.len()
    }

    /// No executor identity.
    pub fn is_empty(&self) -> bool {
        self.0.read().executors.is_empty()
    }

    /// `id` is one the packaged executor had (never `(0, 0)`, which
    /// [`Self::record`] refuses).
    pub fn contains(&self, id: (u64, u64)) -> bool {
        self.0.read().executors.contains(&id)
    }

    /// `id` is the manager's image (never `(0, 0)`).
    pub fn is_manager(&self, id: (u64, u64)) -> bool {
        self.0.read().managers.contains(&id)
    }
}

/// What R004 knows of the launches that run an unlinked image without
/// being fileless (lot 310): the agent's own worker's (R14a) and systemd's
/// executor's.
#[derive(Clone, Debug, Default)]
pub struct KnownLaunches {
    /// R14a: the agent's own worker launch (`None`: no worker).
    pub own_worker: Option<OwnWorkerLaunch>,
    /// Lot 310: systemd's executor, by its identities.
    pub executor: ExecutorImages,
}

/// R004 rule. `lineage` resolves a `systemd --user` parent by what the
/// kernel executed for it (external audit PROC-001), and (lot 310) the
/// image a parent runs; without it (unit tests) only PID 1 counts as
/// systemd and no parent's image is known.
#[derive(Default)]
pub struct R004ExecFromProcSelfFd<H: PostureHost> {
    lineage: Option<crate::posture::lineage::AuthSessionTracker<H>>,
    /// R14a: the agent's own worker launch (`None`: no worker).
    own: Option<OwnWorkerLaunch>,
    /// Lot 310: systemd's executor, by its identities (empty: none known).
    executor: ExecutorImages,
}

impl<H: PostureHost> R004ExecFromProcSelfFd<H> {
    pub fn new(lineage: crate::posture::lineage::AuthSessionTracker<H>) -> Self {
        Self {
            lineage: Some(lineage),
            own: None,
            executor: ExecutorImages::default(),
        }
    }

    /// R14a: this rule knowing the agent's worker launch.
    pub fn with_own_launch(mut self, own: Option<OwnWorkerLaunch>) -> Self {
        self.own = own;
        self
    }

    /// Lot 310: this rule knowing the launches of an unlinked image that
    /// are not fileless ([`KnownLaunches`]).
    pub fn with_launches(mut self, launches: KnownLaunches) -> Self {
        self.own = launches.own_worker;
        self.executor = launches.executor;
        self
    }

    /// Tracepoint mode: the caller's path reopens a descriptor — the
    /// canonical way to exec from a memfd or an anonymous fd, a strong
    /// fileless-exec signal. Lot 310 (BUG-88): read by the posture's one
    /// reader of a `/proc` link ([`crate::posture::proc_link`]), which
    /// knows the per-thread and `/dev` names (`/proc/thread-self/fd/N`,
    /// `/proc/<pid>/task/<tid>/fd/N`, `/dev/stdin`) and folds `//` and `.`;
    /// it was a twin here that knew `/proc/self/fd/N`, `/proc/<pid>/fd/N`
    /// and `/dev/fd/N` only. `/dev/fd/N` is what glibc's fexecve(3) passes
    /// (lab guest, Ubuntu 24.04 / glibc 2.39), `/memfd:` what
    /// execveat(AT_EMPTY_PATH) reports.
    fn is_proc_fd_path(path: &str) -> bool {
        path.starts_with("/memfd:") || crate::posture::proc_link::reopens_a_descriptor(path)
    }

    /// The unlinked file is systemd's own executor — PID 1 holds it open
    /// across a systemd upgrade and keeps launching units from it until the
    /// next re-exec. Lot 310 (BUG-103): by its identity, one the packaged
    /// executor has on this host now ([`ExecutorImages`]: linked at its
    /// install path, or held by PID 1 or a genuine user manager), launched
    /// by systemd. It was any file *named* `systemd-executor` in a
    /// root-owned tree (`/opt/app/systemd-executor`), whatever its parent.
    /// The re-check of #539 (N2): "launched by systemd" is the kernel's
    /// record of who FORKED the process, for its first exec since
    /// (`fork_parent`): PID 1, or a manager by its image — never the
    /// parent at exec time, which an orphan's reaper is.
    fn is_upgraded_executor(
        &self,
        exe: &nn_model::ExeIdentity,
        as_of: crate::posture::lineage::AsOf,
    ) -> bool {
        self.executor.contains((exe.dev, exe.ino))
            && self.forked_by_a_manager(exe.fork_parent, as_of)
    }

    /// LSM mode, lot 310: the process re-executes the very image its
    /// parent runs (the lineage's record of the parent's exec, its
    /// `(dev, ino)`): `/proc/self/exe` after a package upgrade unlinked it
    /// (Chromium's children, Docker's `reexec`). No new code runs.
    fn reexecs_its_parent_image(
        &self,
        ppid: u32,
        exe: &nn_model::ExeIdentity,
        as_of: crate::posture::lineage::AsOf,
    ) -> bool {
        (exe.dev, exe.ino) != (0, 0)
            && self
                .lineage
                .as_ref()
                .and_then(|l| l.exec_image(ppid, as_of))
                == Some((exe.dev, exe.ino))
    }

    /// The re-check of #539 (N2): `fork_parent` (the kernel's record of
    /// who forked the process, for its first exec; 0 not known) is the
    /// host's PID 1, or a `systemd --user` manager told by the image the
    /// lineage holds for it — the packaged manager's identity
    /// ([`ExecutorImages::is_manager`]), never its name or its `comm`.
    fn forked_by_a_manager(&self, fork_parent: u32, as_of: crate::posture::lineage::AsOf) -> bool {
        fork_parent == 1
            || (fork_parent != 0
                && self.lineage.as_ref().is_some_and(|l| {
                    l.exec_image(fork_parent, as_of)
                        .is_some_and(|id| self.executor.is_manager(id))
                }))
    }
}

impl<H: PostureHost> Rule for R004ExecFromProcSelfFd<H> {
    fn id(&self) -> &'static str {
        "R004_ExecFromProcSelfFd"
    }
    fn name(&self) -> &'static str {
        "Exec from /proc/<pid>/fd/* (memfd)"
    }
    fn category(&self) -> &'static str {
        "execution"
    }
    fn attack(&self) -> &'static [AttackRef] {
        const ATTACK: &[AttackRef] = &[AttackRef::new(Tactic::Stealth, "T1620")];
        ATTACK
    }

    fn evaluate(&self, event: &Event) -> Option<Verdict> {
        let Event::ProcessSpawn {
            filename,
            ppid,
            uid,
            argv,
            exe,
            ..
        } = event
        else {
            return None;
        };
        use common::wire::exe::exe_flags::{DELETED, KNOWN, MEMFD, PROC_EXE};
        // R14a: the core starting its own worker from its boot descriptor
        if self
            .own
            .as_ref()
            .is_some_and(|o| o.is(*ppid, *uid, filename, argv, exe))
        {
            return None;
        }
        let as_of = crate::posture::lineage::AsOf::of_event(event);
        // lot 310 (the review of #539, finding 4): in tracepoint mode the
        // exec pump reads the image from `/proc/<pid>/exe` (`PROC_EXE`) —
        // the same facts, read while the process runs
        if exe.flags & (KNOWN | PROC_EXE) != 0 {
            // External audit PROC-001 (NN-AUD-001): with the exec sensor's
            // identity, what the kernel executed decides, not the caller's
            // path, argv[0] or parent name. Fileless code is a memfd, or an
            // unlinked file (O_TMPFILE) — lot 310 (BUG-88): whatever path
            // reached it, the caller's string no longer asked to be
            // `/proc/self/fd/N`. A real file reached through an fd is not
            // fileless: systemd-executor's fexecve of every unit is one, and
            // the other rules judge any such file on its canonical path
            // (review 61).
            let fileless = exe.has(MEMFD)
                || (exe.has(DELETED)
                    && !self.is_upgraded_executor(exe, as_of)
                    && !self.reexecs_its_parent_image(*ppid, exe, as_of));
            if !fileless {
                return None;
            }
        } else if !Self::is_proc_fd_path(filename) {
            // Tracepoint mode, the process gone before the pump read its
            // image: the path heuristic. Lot 310 (finding 4): no exemption
            // by `argv[0]` and a parent of pid 1 any more — the caller
            // chooses `argv[0]`, and an orphan's parent is pid 1; systemd's
            // launch of a unit is judged by its image above (a linked file)
            return None;
        }
        Some(build_verdict(
            self,
            event,
            ResponseAction::KillProcessTree,
            Severity::Critical,
            "memfd-style exec detected — fileless execution, highly suspicious",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    // R08b (lab PR 251): on the portable test host.
    use crate::posture::host::testing::TestHost as H;
    type R004ExecFromProcSelfFd = super::R004ExecFromProcSelfFd<H>;
    use crate::decision::rules::testutil::spawn;

    /// Full-control spawn builder for the Tappa 10.6.5 exemption tests:
    /// the shared `spawn`/`spawn_full` helpers hardcode `ppid = 1`, but
    /// the exemption logic keys on `ppid`, `parent_comm` AND `argv`, so
    /// these tests need to vary all three independently.
    fn spawn_exec(filename: &str, ppid: u32, parent_comm: &str, argv: &[&str]) -> Event {
        Event::ProcessSpawn {
            pid: 4242,
            ppid,
            uid: 0,
            gid: 0,
            comm: "x".to_string(),
            filename: filename.to_string(),
            timestamp_ns: 42,
            argv: argv.iter().map(|s| s.to_string()).collect(),
            parent_comm: parent_comm.to_string(),
            parent_start_ns: 0,
            start_ns: 0,
            parent_is_kthread: false,
            exe: Default::default(),
            argv_truncated: false,
            filename_truncated: false,
            stdio: Default::default(),
        }
    }

    /// Review 61: a memfd reached through a symlink to `/proc/self/fd/N`
    /// carries no fd path, but the kernel flags the file itself.
    #[test]
    fn fires_on_a_memfd_whatever_path_reached_it() {
        use crate::decision::rules::testutil::spawn_exe;
        use common::wire::exe::exe_flags;
        let event = spawn_exe("x", "/usr/local/bin/notes", "", exe_flags::MEMFD);
        let v = R004ExecFromProcSelfFd::default()
            .evaluate(&event)
            .expect("fires");
        assert_eq!(v.action, ResponseAction::KillProcessTree);
        // Lot 310 (BUG-88): an unlinked file is fileless whatever path
        // reached it (this assertion said "a deleted file alone is no
        // memfd", which left the per-thread names of a descriptor, a
        // relative path and a symlink to it without the kill). An upgraded
        // binary re-exec'd is told by its identity instead: the image its
        // parent runs (`a_parents_own_image_reexecuted_is_not_fileless`).
        let event = spawn_exe("x", "/usr/bin/x", "/usr/bin/x", exe_flags::DELETED);
        assert!(R004ExecFromProcSelfFd::default().evaluate(&event).is_some());
    }

    /// R14a: the core's own worker launch is not fileless — in LSM mode
    /// only when the kernel executed the core's image (an upgrade unlinked
    /// it), in tracepoint mode on its exact facts; any one fact off and the
    /// rule fires as before.
    #[test]
    fn the_agents_own_worker_launch_is_known_and_nothing_else() {
        use crate::decision::rules::testutil::spawn_exe;
        use common::wire::exe::exe_flags;
        let own = OwnWorkerLaunch {
            agent_pid: 900,
            exec_path: "/proc/self/fd/64".into(),
            image: (2049, 77),
            uid: 990,
            export_uid: Some(989),
        };
        let rule = R004ExecFromProcSelfFd::default().with_own_launch(Some(own.clone()));
        let launch =
            |ppid: u32, uid: u32, path: &str, argv: &[&str], exe: nn_model::ExeIdentity| {
                let mut e = spawn_exec(path, ppid, "northnarrow-age", argv);
                if let Event::ProcessSpawn { uid: u, exe: x, .. } = &mut e {
                    *u = uid;
                    *x = exe;
                }
                e
            };
        let argv = ["northnarrow-agent", "--worker", "parse", "--ipc-fd", "3"];
        let deleted = |dev, ino| {
            let Event::ProcessSpawn { exe, .. } = spawn_exe(
                "x",
                "/proc/self/fd/64",
                "/usr/local/bin/northnarrow-agent (deleted)",
                exe_flags::DELETED,
            ) else {
                unreachable!()
            };
            nn_model::ExeIdentity { dev, ino, ..exe }
        };
        // LSM mode, the image unlinked by an upgrade: the agent's own
        assert!(rule
            .evaluate(&launch(
                900,
                990,
                "/proc/self/fd/64",
                &argv,
                deleted(2049, 77)
            ))
            .is_none());
        // tracepoint mode: on the facts
        assert!(rule
            .evaluate(&launch(
                900,
                990,
                "/proc/self/fd/64",
                &argv,
                Default::default()
            ))
            .is_none());
        // lot 276: the export worker, as its own account — and only so: as
        // the parse worker's account, or the parse worker as the export's,
        // fileless as ever
        let export = ["northnarrow-agent", "--worker", "export", "--ipc-fd", "3"];
        assert!(rule
            .evaluate(&launch(
                900,
                989,
                "/proc/self/fd/64",
                &export,
                Default::default()
            ))
            .is_none());
        assert!(rule
            .evaluate(&launch(
                900,
                990,
                "/proc/self/fd/64",
                &export,
                Default::default()
            ))
            .is_some());
        assert!(rule
            .evaluate(&launch(
                900,
                989,
                "/proc/self/fd/64",
                &argv,
                Default::default()
            ))
            .is_some());
        let no_export = R004ExecFromProcSelfFd::default().with_own_launch(Some(OwnWorkerLaunch {
            export_uid: None,
            ..own.clone()
        }));
        assert!(no_export
            .evaluate(&launch(
                900,
                989,
                "/proc/self/fd/64",
                &export,
                Default::default()
            ))
            .is_some());
        // any fact off: fileless as ever
        for (what, e) in [
            (
                "another image",
                launch(900, 990, "/proc/self/fd/64", &argv, deleted(2049, 78)),
            ),
            (
                "another parent",
                launch(901, 990, "/proc/self/fd/64", &argv, Default::default()),
            ),
            (
                "root",
                launch(900, 0, "/proc/self/fd/64", &argv, Default::default()),
            ),
            (
                "another uid",
                launch(900, 991, "/proc/self/fd/64", &argv, Default::default()),
            ),
            (
                "another fd",
                launch(900, 990, "/proc/self/fd/65", &argv, Default::default()),
            ),
            (
                "another command line",
                launch(
                    900,
                    990,
                    "/proc/self/fd/64",
                    &["sh", "-c", "x"],
                    Default::default(),
                ),
            ),
            (
                "an unknown kind",
                launch(
                    900,
                    990,
                    "/proc/self/fd/64",
                    &["northnarrow-agent", "--worker", "shell", "--ipc-fd", "3"],
                    Default::default(),
                ),
            ),
            (
                "an extra argument",
                launch(
                    900,
                    990,
                    "/proc/self/fd/64",
                    &[
                        "northnarrow-agent",
                        "--worker",
                        "parse",
                        "--ipc-fd",
                        "3",
                        "-x",
                    ],
                    Default::default(),
                ),
            ),
        ] {
            assert!(rule.evaluate(&e).is_some(), "{what}");
        }
        // without the facts (no worker), the same launch is fileless
        assert!(R004ExecFromProcSelfFd::default()
            .evaluate(&launch(
                900,
                990,
                "/proc/self/fd/64",
                &argv,
                deleted(2049, 77)
            ))
            .is_some());
        // facts that would name root (an account lookup refuses root: never
        // built so) never exempt a root exec
        let root = R004ExecFromProcSelfFd::default().with_own_launch(Some(OwnWorkerLaunch {
            uid: 0,
            ..own.clone()
        }));
        assert!(root
            .evaluate(&launch(
                900,
                0,
                "/proc/self/fd/64",
                &argv,
                Default::default()
            ))
            .is_some());
        // and an agent pid of 0 never matches
        let zero = R004ExecFromProcSelfFd::default().with_own_launch(Some(OwnWorkerLaunch {
            agent_pid: 0,
            ..own
        }));
        assert!(zero
            .evaluate(&launch(
                0,
                990,
                "/proc/self/fd/64",
                &argv,
                Default::default()
            ))
            .is_some());
    }

    #[test]
    fn fires_on_proc_self_fd() {
        let v = R004ExecFromProcSelfFd::default()
            .evaluate(&spawn("memexec", "/proc/self/fd/3"))
            .expect("fires");
        assert_eq!(v.severity, Severity::Critical);
        assert_eq!(v.action, ResponseAction::KillProcessTree);
    }

    #[test]
    fn ignores_normal_paths() {
        assert!(R004ExecFromProcSelfFd::default()
            .evaluate(&spawn("ls", "/usr/bin/ls"))
            .is_none());
        // /proc/<pid>/status is not an exec target.
        assert!(R004ExecFromProcSelfFd::default()
            .evaluate(&spawn("x", "/proc/123/status"))
            .is_none());
    }

    #[test]
    fn matches_proc_pid_fd_form_too() {
        assert!(R004ExecFromProcSelfFd::default()
            .evaluate(&spawn("x", "/proc/4242/fd/7"))
            .is_some());
        // Empty fd number does not count.
        assert!(R004ExecFromProcSelfFd::default()
            .evaluate(&spawn("x", "/proc/self/fd/"))
            .is_none());
        // Lot 310: the posture's one reader of a `/proc` link reads any
        // second segment (`self`, `thread-self`, a pid): this assertion
        // said a non-numeric one does not count. No `/proc` entry has
        // such a name, so `/proc/abc/fd/3` is never executed, and the
        // per-thread names (`thread-self`) are what it missed (BUG-88).
        assert!(R004ExecFromProcSelfFd::default()
            .evaluate(&spawn("x", "/proc/abc/fd/3"))
            .is_some());
        assert!(R004ExecFromProcSelfFd::default()
            .evaluate(&spawn("x", "/proc/thread-self/fd/3"))
            .is_some());
    }

    // ── Tappa 10.6.5 — systemd-executor exemption ──────────────────────

    /// The tracepoint-mode event as the exec pump completes it (lot 310):
    /// the image read from `/proc/<pid>/exe` (`PROC_EXE`), `flags` its facts.
    fn with_proc_exe(mut e: Event, flags: u32) -> Event {
        if let Event::ProcessSpawn { exe, .. } = &mut e {
            exe.flags = flags | common::wire::exe::exe_flags::PROC_EXE;
            (exe.dev, exe.ino) = (2049, 4321);
        }
        e
    }

    /// `systemd-run sleep 10` and every other system unit: systemd
    /// (ppid 1) fexecve's systemd-executor → must be EXEMPT. Lot 310 (the
    /// review of #539, finding 4): by the image the exec pump read — the
    /// linked executor is no fileless exec — no longer by `argv[0]` and a
    /// parent of pid 1 (this test's event had no image); without an image
    /// (the process gone before the read), an exec through a descriptor
    /// fires, whatever `argv[0]` says.
    #[test]
    fn exempts_systemd_executor_system_unit() {
        let ev = spawn_exec(
            "/proc/self/fd/9",
            1,
            "systemd",
            &["/usr/lib/systemd/systemd-executor", "--deserialize", "68"],
        );
        assert!(
            R004ExecFromProcSelfFd::default()
                .evaluate(&with_proc_exe(ev.clone(), 0))
                .is_none(),
            "legitimate systemd-executor launch must not fire R004"
        );
        assert!(R004ExecFromProcSelfFd::default().evaluate(&ev).is_some());
    }

    /// `--user` manager launch: the parent is a `systemd --user` manager,
    /// told by what the kernel executed for it, not by its comm — exempt.
    #[test]
    fn exempts_systemd_executor_user_manager() {
        let tmp = tempfile::TempDir::new().unwrap();
        let lineage = crate::posture::lineage::AuthSessionTracker::<H>::new(tmp.path());
        lineage.ingest_spawn(2001, 1, "/usr/lib/systemd/systemd", 1);
        let ev = spawn_exec(
            "/proc/self/fd/4",
            2001,
            "systemd",
            &["/lib/systemd/systemd-executor", "--deserialize", "12"],
        );
        // lot 310: by the image the pump read (a linked executor)
        let r = R004ExecFromProcSelfFd::new(lineage);
        assert!(r.evaluate(&with_proc_exe(ev.clone(), 0)).is_none());
        assert!(
            r.evaluate(&ev).is_some(),
            "no image: argv[0] exempts nothing"
        );
    }

    /// External audit PROC-001 (NN-AUD-001): a parent that only NAMES
    /// itself systemd (prctl) does not exempt the exec.
    #[test]
    fn forged_parent_comm_systemd_does_not_exempt() {
        let tmp = tempfile::TempDir::new().unwrap();
        let lineage = crate::posture::lineage::AuthSessionTracker::<H>::new(tmp.path());
        lineage.ingest_spawn(7777, 1, "/usr/bin/python3.12", 1);
        let ev = spawn_exec(
            "/proc/self/fd/3",
            7777,
            "systemd",
            &["/usr/lib/systemd/systemd-executor"],
        );
        assert!(R004ExecFromProcSelfFd::new(lineage).evaluate(&ev).is_some());
        assert!(R004ExecFromProcSelfFd::default().evaluate(&ev).is_some());
    }

    /// External audit PROC-001: in tracepoint mode `argv[0]` must be an
    /// install path exactly, not any path ending in `/systemd-executor`.
    #[test]
    fn executor_argv0_outside_canonical_path_does_not_exempt() {
        let ev = spawn_exec(
            "/proc/self/fd/3",
            1,
            "systemd",
            &["/home/u/x/systemd-executor"],
        );
        assert!(R004ExecFromProcSelfFd::default().evaluate(&ev).is_some());
    }

    /// External audit PROC-001: with the exec sensor's identity, what the
    /// kernel executed decides. The lab (Ubuntu 24.04, systemd 255) showed
    /// why the executor must not be an exemption here: every unit start is
    /// systemd-executor fexecve'd from an fd, a real file. Fileless code is
    /// a memfd, or an unlinked file reached through an fd.
    #[test]
    fn executed_file_decides_in_lsm_mode() {
        use common::wire::exe::exe_flags::{DELETED, KNOWN, MEMFD, TASK_ROOT};
        let ev = |filename: &str, exe_path: &str, flags: u32| {
            let mut e = spawn_exec(filename, 7777, "bash", &["anything"]);
            if let Event::ProcessSpawn { exe, .. } = &mut e {
                exe.path = exe_path.to_string();
                exe.flags = flags | KNOWN;
            }
            e
        };
        let r = R004ExecFromProcSelfFd::default();
        // systemd's launch of every unit: a real file through an fd
        let unit = ev(
            "/proc/self/fd/9",
            "/usr/lib/systemd/systemd-executor",
            TASK_ROOT,
        );
        assert!(r.evaluate(&unit).is_none());
        // the same after a systemd upgrade: PID 1 holds the old, unlinked
        // one. Lot 310 (BUG-103): exempt only as the identity the packaged
        // executor had (recorded by the agent) and launched by systemd —
        // this assertion exempted it on its name from a bash parent
        let images = ExecutorImages::default();
        assert!(images.record((2049, 1001)));
        let r_known = R004ExecFromProcSelfFd::default().with_launches(KnownLaunches {
            own_worker: None,
            executor: images,
        });
        // the re-check of #539 (N2): by who FORKED it (the kernel's record,
        // `fork_parent`), not by its parent at exec time
        let upgraded = |forker: u32, id: (u64, u64)| {
            let mut e = ev(
                "/proc/self/fd/9",
                "/usr/lib/systemd/systemd-executor",
                DELETED,
            );
            if let Event::ProcessSpawn {
                ppid: p, exe: x, ..
            } = &mut e
            {
                *p = 1;
                x.fork_parent = forker;
                (x.dev, x.ino) = id;
            }
            e
        };
        assert!(r_known.evaluate(&upgraded(1, (2049, 1001))).is_none());
        // forked by a bash (an orphan PID 1 reaped before its exec), the
        // fork not known (a later exec), another identity, none recorded
        assert!(r_known.evaluate(&upgraded(7777, (2049, 1001))).is_some());
        assert!(r_known.evaluate(&upgraded(0, (2049, 1001))).is_some());
        assert!(r_known.evaluate(&upgraded(1, (2049, 1002))).is_some());
        assert!(r.evaluate(&upgraded(1, (2049, 1001))).is_some());
        // fileless: a memfd (whatever argv[0] and parent claim), or an
        // unlinked file reached through an fd (O_TMPFILE)
        assert!(r
            .evaluate(&ev("/proc/self/fd/3", "/memfd:x (deleted)", MEMFD))
            .is_some());
        assert!(r
            .evaluate(&ev("/proc/self/fd/3", "/tmp/#1234 (deleted)", DELETED))
            .is_some());
        assert!(r
            .evaluate(&ev(
                "/proc/self/fd/3",
                "/tmp/systemd-executor (deleted)",
                DELETED
            ))
            .is_some());
        // a real file through an fd is judged on its path by the other rules
        assert!(r
            .evaluate(&ev("/proc/self/fd/3", "/tmp/payload", 0))
            .is_none());
    }

    /// `bash exec -a foo /proc/self/fd/3` from an arbitrary user shell:
    /// forged argv[0], parent is the shell (not systemd) → must FIRE.
    #[test]
    fn fires_on_user_shell_proc_fd_exec() {
        let ev = spawn_exec("/proc/self/fd/3", 7777, "bash", &["foo"]);
        let v = R004ExecFromProcSelfFd::default()
            .evaluate(&ev)
            .expect("fires");
        assert_eq!(v.severity, Severity::Critical);
        assert_eq!(v.action, ResponseAction::KillProcessTree);
    }

    /// Genuine T1620 fileless exec (memfd_create + execve) from a
    /// malicious loader → must FIRE.
    #[test]
    fn fires_on_memfd_fileless_exec() {
        let ev = spawn_exec("/proc/self/fd/3", 9001, "loader", &["/proc/self/fd/3"]);
        assert!(R004ExecFromProcSelfFd::default().evaluate(&ev).is_some());
    }

    /// What glibc's fexecve(3) really passes on Ubuntu 24.04: the
    /// `/dev/fd/N` symlink form (lab guest 2026-10-08, memfd exec seen as
    /// `filename: "/dev/fd/4"`). Must fire like `/proc/self/fd/N`.
    #[test]
    fn fires_on_dev_fd_form() {
        let ev = spawn_exec("/dev/fd/4", 9001, "loader", &["nnx_memfd"]);
        assert!(R004ExecFromProcSelfFd::default().evaluate(&ev).is_some());
        assert!(!R004ExecFromProcSelfFd::is_proc_fd_path("/dev/fd/"));
        assert!(!R004ExecFromProcSelfFd::is_proc_fd_path("/dev/fdx/1"));
    }

    /// execveat(fd, "", AT_EMPTY_PATH) on a memfd surfaces as
    /// `/memfd:<name> (deleted)`.
    #[test]
    fn fires_on_memfd_pseudo_path() {
        let ev = spawn_exec("/memfd:payload (deleted)", 9001, "loader", &["payload"]);
        assert!(R004ExecFromProcSelfFd::default().evaluate(&ev).is_some());
    }

    /// Security property: `ppid == 1` ALONE does not grant the exemption.
    /// A daemon re-parented to init that memfd-execs a non-executor
    /// binary must still FIRE (the AND with argv[0] is what protects us).
    #[test]
    fn ppid_one_alone_does_not_exempt() {
        let ev = spawn_exec("/proc/self/fd/5", 1, "systemd", &["/tmp/payload"]);
        assert!(
            R004ExecFromProcSelfFd::default().evaluate(&ev).is_some(),
            "ppid==1 without a real systemd-executor argv[0] must still fire"
        );
    }

    /// Security property: a forged `argv[0]` ALONE (executor path, but
    /// parented by a normal shell, not systemd) does not grant the
    /// exemption → must FIRE.
    #[test]
    fn forged_argv0_alone_does_not_exempt() {
        let ev = spawn_exec(
            "/proc/self/fd/3",
            7777,
            "bash",
            &["/usr/lib/systemd/systemd-executor"],
        );
        assert!(
            R004ExecFromProcSelfFd::default().evaluate(&ev).is_some(),
            "executor argv[0] without a systemd parent must still fire"
        );
    }

    /// Lot 310 (the review of #539, finding 4): `argv[0]` exempts nothing
    /// in tracepoint mode — not an install path of the executor (this test
    /// checked the matcher that held it), not with a parent of pid 1 (an
    /// orphan's parent is pid 1): the caller chooses both.
    #[test]
    fn executor_argv0_exempts_nothing_in_tracepoint_mode() {
        for a0 in [
            "/usr/lib/systemd/systemd-executor",
            "/lib/systemd/systemd-executor",
        ] {
            for f in ["/proc/self/fd/9", "/proc/thread-self/fd/9", "/dev/fd/9"] {
                let ev = spawn_exec(f, 1, "systemd", &[a0, "--deserialize", "3"]);
                assert!(
                    R004ExecFromProcSelfFd::default().evaluate(&ev).is_some(),
                    "{a0} {f}"
                );
            }
        }
        // an unlinked image the pump read: fileless, whatever argv[0] says
        let ev = spawn_exec(
            "/proc/self/fd/9",
            1,
            "systemd",
            &["/usr/lib/systemd/systemd-executor"],
        );
        assert!(R004ExecFromProcSelfFd::default()
            .evaluate(&with_proc_exe(ev, common::wire::exe::exe_flags::DELETED))
            .is_some());
    }
}

/// Lot 310 (external bug hunt, edition 1.4): BUG-88 and BUG-103.
#[cfg(test)]
mod lot310 {
    use super::*;
    use crate::posture::host::testing::TestHost as H;
    use common::wire::exe::exe_flags::{DELETED, KNOWN, MEMFD, ROOT_DIR};
    type R004 = R004ExecFromProcSelfFd<H>;

    fn exec(uid: u32, ppid: u32, filename: &str, exe_path: &str, flags: u32) -> Event {
        Event::ProcessSpawn {
            pid: 4242,
            ppid,
            uid,
            gid: uid,
            comm: "x".to_string(),
            filename: filename.to_string(),
            timestamp_ns: 42,
            argv: vec!["anything".to_string()],
            parent_comm: "bash".to_string(),
            parent_start_ns: 0,
            start_ns: 0,
            parent_is_kthread: false,
            exe: nn_model::ExeIdentity {
                path: exe_path.to_string(),
                dev: if exe_path.is_empty() { 0 } else { 2049 },
                ino: if exe_path.is_empty() { 0 } else { 777 },
                flags: if flags == 0 && exe_path.is_empty() {
                    0
                } else {
                    flags | KNOWN
                },
                ..Default::default()
            },
            argv_truncated: false,
            filename_truncated: false,
            stdio: Default::default(),
        }
    }

    fn kills(v: Option<Verdict>) -> bool {
        v.is_some_and(|v| v.action == ResponseAction::KillProcessTree)
    }

    /// The per-thread names of the same descriptor, and the `/dev`
    /// symlinks to fds 0..2 (the report's forms).
    const PER_THREAD: &[&str] = &[
        "/proc/thread-self/fd/3",
        "/proc/self/task/4242/fd/3",
        "/proc/4242/task/4242/fd/3",
        "/dev/stdin",
    ];

    /// BUG-88, LSM mode (the default): an unlinked file (O_TMPFILE, or
    /// opened then deleted) reached through descriptor 3 fires with
    /// `/proc/self/fd/3`; the per-thread names must fire alike.
    #[test]
    fn bug88_lsm_unlinked_file_via_per_thread_fd_is_fileless() {
        let r = R004::default();
        assert!(kills(r.evaluate(&exec(
            1000,
            7777,
            "/proc/self/fd/3",
            "/home/u/#1234",
            DELETED
        ))));
        let missed: Vec<&str> = PER_THREAD
            .iter()
            .copied()
            .filter(|f| !kills(r.evaluate(&exec(1000, 7777, f, "/home/u/#1234", DELETED))))
            .collect();
        assert!(
            missed.is_empty(),
            "LSM, unlinked file through an fd: no R004 kill for {missed:?}"
        );
    }

    /// BUG-88, tracepoint mode (no exec identity): a memfd fexecve'd
    /// through the per-thread name of its descriptor.
    #[test]
    fn bug88_tracepoint_per_thread_fd_is_fileless() {
        let r = R004::default();
        let missed: Vec<&str> = PER_THREAD
            .iter()
            .copied()
            .chain([
                "/proc//self/fd/3",
                "/proc/self/./fd/3",
                "/proc/self/task/../fd/3",
            ])
            .filter(|f| !kills(r.evaluate(&exec(1000, 7777, f, "", 0))))
            .collect();
        assert!(missed.is_empty(), "tracepoint: no R004 kill for {missed:?}");
        // the image and a view are no descriptor: an exec of
        // `/proc/self/exe` (Chromium's children) is not fileless here
        for f in ["/proc/self/exe", "/proc/self/root/usr/bin/ls", "/dev/null"] {
            assert!(r.evaluate(&exec(1000, 7777, f, "", 0)).is_none(), "{f}");
        }
    }

    /// Beyond the report's fix: the caller's string has unbounded
    /// spellings of the same descriptor — relative to a `/proc/self`
    /// cwd, a doubled slash, a `.` segment, a symlink to it in a home —
    /// and the other proc links that reopen an unlinked image (`exe`,
    /// `map_files/`). In LSM mode the file's own flag decides: the six of
    /// the triage, and an O_TMPFILE in `$HOME` (its dentry's path as the
    /// LSM walk gives it).
    #[test]
    fn bug88_other_spellings_the_report_fix_still_misses() {
        let r = R004::default();
        let missed: Vec<&str> = [
            "fd/3",
            "/proc//self/fd/3",
            "/proc/self/./fd/3",
            "/home/u/link-to-proc-self-fd-3",
            // other proc links that reopen an unlinked image
            "/proc/4242/exe",
            "/proc/self/map_files/7f0000000000-7f0000001000",
        ]
        .into_iter()
        .filter(|f| !kills(r.evaluate(&exec(1000, 7777, f, "/home/u/#1234", DELETED))))
        .collect();
        assert!(
            missed.is_empty(),
            "LSM, unlinked file through an fd: no R004 kill for {missed:?}"
        );
        // O_TMPFILE in the home directory, through `/dev/fd/N` (glibc's
        // fexecve) and the per-thread name: the dentry is `#<ino>`
        for f in ["/dev/fd/5", "/proc/thread-self/fd/5"] {
            assert!(
                kills(r.evaluate(&exec(1000, 7777, f, "/home/u/#5242934", DELETED))),
                "{f}"
            );
        }
    }

    /// Guard: a memfd fires in LSM mode whatever path reached it.
    #[test]
    fn bug88_guard_lsm_memfd_fires_whatever_the_path() {
        let r = R004::default();
        for f in PER_THREAD.iter().copied().chain(["fd/3", "/home/u/l"]) {
            assert!(
                kills(r.evaluate(&exec(1000, 7777, f, "/memfd:x", MEMFD))),
                "{f}"
            );
        }
    }

    /// BUG-103: the exemption for systemd's executor left unlinked by an
    /// upgrade was bought by the file name alone in any `in_system_tree`
    /// tree (`/opt/` included, where an application user often owns its
    /// subtree; any parent, any uid). It is the identity the packaged
    /// executor had on this host, launched by systemd.
    #[test]
    fn bug103_unlinked_systemd_executor_under_opt_is_fileless() {
        let images = ExecutorImages::default();
        images.record((2049, 1001));
        let r = R004::default().with_launches(KnownLaunches {
            own_worker: None,
            executor: images,
        });
        // control: the same exec, another file name, fires
        assert!(kills(r.evaluate(&exec(
            1001,
            7777,
            "/proc/self/fd/3",
            "/opt/app/payload",
            DELETED
        ))));
        // control: the real executor unlinked by an upgrade (its identity,
        // PID 1 its parent) stays exempt
        let mut real = exec(
            0,
            1,
            "/proc/self/fd/9",
            "/usr/lib/systemd/systemd-executor",
            DELETED,
        );
        if let Event::ProcessSpawn { exe, .. } = &mut real {
            (exe.dev, exe.ino) = (2049, 1001);
            exe.fork_parent = 1;
        }
        assert!(r.evaluate(&real).is_none());
        let missed: Vec<&str> = [
            "/opt/app/systemd-executor",
            "/usr/local/lib/x/systemd-executor",
            // the install path itself, another identity
            "/usr/lib/systemd/systemd-executor",
        ]
        .into_iter()
        .filter(|p| !kills(r.evaluate(&exec(1001, 7777, "/proc/self/fd/3", p, DELETED))))
        .collect();
        assert!(
            missed.is_empty(),
            "an unlinked file named systemd-executor that is not the executor: no R004 kill for {missed:?}"
        );
        // as PID 1's child, too: an identity is not a name
        assert!(kills(r.evaluate(&exec(
            0,
            1,
            "/proc/self/fd/9",
            "/opt/app/systemd-executor",
            DELETED
        ))));
    }

    /// Lot 310: a process that re-executes the very image its parent runs
    /// (the lineage's `(dev, ino)` of the parent's exec) runs no new code —
    /// `/proc/self/exe` after an upgrade unlinked it (Chromium's children,
    /// Docker's `reexec`). Another image, or a parent the lineage holds no
    /// identity for, fires.
    #[test]
    fn a_parents_own_image_reexecuted_is_not_fileless() {
        let tmp = tempfile::TempDir::new().unwrap();
        let lineage = crate::posture::lineage::AuthSessionTracker::<H>::new(tmp.path());
        // lot 310 (the review of #539, finding 5): the exec pump found the
        // parent's directory root's only (`ROOT_DIR`)
        let parent = |pid: u32, id: (u64, u64)| Event::ProcessSpawn {
            pid,
            ppid: 1,
            uid: 1000,
            gid: 1000,
            comm: "chrome".into(),
            filename: "/opt/google/chrome/chrome".into(),
            timestamp_ns: 10,
            argv: vec!["chrome".into()],
            parent_comm: "systemd".into(),
            parent_start_ns: 0,
            start_ns: 10,
            parent_is_kthread: false,
            exe: nn_model::ExeIdentity {
                path: "/opt/google/chrome/chrome".into(),
                dev: id.0,
                ino: id.1,
                flags: KNOWN | common::wire::exe::exe_flags::ROOT_DIR,
                ..Default::default()
            },
            argv_truncated: false,
            filename_truncated: false,
            stdio: Default::default(),
        };
        lineage.ingest_spawn_event(&parent(7777, (2049, 777)));
        lineage.ingest_spawn_event(&parent(8888, (2049, 999)));
        let r = R004::new(lineage);
        // the child runs the parent's image, unlinked since
        assert!(r
            .evaluate(&exec(
                1000,
                7777,
                "/proc/self/exe",
                "/opt/google/chrome/chrome",
                DELETED
            ))
            .is_none());
        // another image than its parent's
        assert!(kills(r.evaluate(&exec(
            1000,
            8888,
            "/proc/self/exe",
            "/opt/google/chrome/chrome",
            DELETED
        ))));
        // a parent the lineage does not hold
        assert!(kills(r.evaluate(&exec(
            1000,
            9999,
            "/proc/self/exe",
            "/opt/google/chrome/chrome",
            DELETED
        ))));
        // a memfd is never its parent's image
        assert!(kills(r.evaluate(&exec(
            1000,
            7777,
            "/proc/self/fd/3",
            "/memfd:x",
            MEMFD
        ))));
    }

    /// The review of #539 (finding 5): a program a user dropped, which
    /// unlinks itself and re-executes its image through a descriptor, is
    /// fileless — as on main: its directory is the user's (no `ROOT_DIR`),
    /// so its image is no exemption. The same in tracepoint mode, by the
    /// image the pump read.
    #[test]
    fn a_dropped_binary_that_unlinks_and_reexecutes_itself_is_killed() {
        use common::wire::exe::exe_flags::{PROC_EXE, ROOT_DIR};
        for flags in [KNOWN, PROC_EXE] {
            let tmp = tempfile::TempDir::new().unwrap();
            let lineage = crate::posture::lineage::AuthSessionTracker::<H>::new(tmp.path());
            let mut dropper = exec(1000, 1, "/tmp/.x", "/tmp/.x", 0);
            if let Event::ProcessSpawn { pid, exe, .. } = &mut dropper {
                *pid = 7100;
                exe.flags = flags;
            }
            lineage.ingest_spawn_event(&dropper);
            assert_eq!(
                lineage.exec_image(7100, crate::posture::lineage::AsOf::Now),
                None
            );
            let r = R004::new(lineage);
            let mut child = exec(1000, 7100, "/proc/7100/fd/4", "/tmp/.x", DELETED);
            if let Event::ProcessSpawn { exe, .. } = &mut child {
                exe.flags = flags | DELETED;
            }
            assert!(kills(r.evaluate(&child)), "{flags:#x}");
            // the same parent from a directory only root writes: exempt
            let tmp = tempfile::TempDir::new().unwrap();
            let lineage = crate::posture::lineage::AuthSessionTracker::<H>::new(tmp.path());
            if let Event::ProcessSpawn { exe, .. } = &mut dropper {
                exe.flags = flags | ROOT_DIR;
            }
            lineage.ingest_spawn_event(&dropper);
            assert!(R004::new(lineage).evaluate(&child).is_none(), "{flags:#x}");
        }
    }

    /// The review of #539 (finding 3) and its re-check (N1, N2): the
    /// executor is what a manager runs first in a child it FORKED — the
    /// kernel's record of the forker (`fork_parent`), never the parent at
    /// exec time. PID 1's fork: exempt; a later exec (no record), an
    /// orphan a shell forked and PID 1 reaped before its exec: killed. A
    /// user's manager by its image: the packaged manager's identity
    /// exempts; a "manager" a user's namespace runs (`/usr/lib/systemd/
    /// systemd` bound over another file: its image is that file's), or one
    /// whose image the lineage does not hold, does not.
    #[test]
    fn the_executor_is_a_child_s_first_exec() {
        let images = ExecutorImages::default();
        images.record((2049, 1001));
        images.replace_managers(vec![(2049, 900)]);
        let tmp = tempfile::TempDir::new().unwrap();
        let lineage = crate::posture::lineage::AuthSessionTracker::<H>::new(tmp.path());
        let r = R004::new(lineage.clone()).with_launches(KnownLaunches {
            own_worker: None,
            executor: images,
        });
        let launch = |pid: u32, ppid: u32, forker: u32| {
            let mut e = exec(
                0,
                ppid,
                "/proc/self/fd/9",
                "/usr/lib/systemd/systemd-executor",
                DELETED,
            );
            if let Event::ProcessSpawn { pid: p, exe, .. } = &mut e {
                *p = pid;
                (exe.dev, exe.ino) = (2049, 1001);
                exe.fork_parent = forker;
            }
            e
        };
        assert!(r.evaluate(&launch(5100, 1, 1)).is_none(), "PID 1's fork");
        assert!(kills(r.evaluate(&launch(5200, 1, 0))), "not the first exec");
        assert!(kills(r.evaluate(&launch(5300, 1, 4444))), "an orphan");
        // a user's manager, by its image
        let manager = |pid: u32, id: (u64, u64)| {
            let mut m = exec(
                1000,
                1,
                "/usr/lib/systemd/systemd",
                "/usr/lib/systemd/systemd",
                ROOT_DIR,
            );
            if let Event::ProcessSpawn { pid: p, exe, .. } = &mut m {
                *p = pid;
                (exe.dev, exe.ino) = id;
            }
            assert!(lineage.ingest_spawn_event(&m));
        };
        manager(2001, (2049, 900));
        assert!(
            r.evaluate(&launch(5400, 2001, 2001)).is_none(),
            "a user's manager"
        );
        // the reviewer's probe: `unshare -Urm`, `/bin/sleep` bound over
        // `/usr/lib/systemd/systemd` — the path is systemd's, the image
        // sleep's
        manager(2002, (2049, 777));
        assert!(
            kills(r.evaluate(&launch(5500, 2002, 2002))),
            "a fake manager"
        );
        assert!(kills(r.evaluate(&launch(5600, 2003, 2003))), "not held");
    }
    /// No identity is no image: a parent the LSM program gave `(0, 0)` (in
    /// a root's directory) is held with no image — lot 310, the review of
    /// #539: the lineage keeps none rather than `(0, 0)` — and does not
    /// exempt a child whose file has none either.
    #[test]
    fn no_identity_is_no_parents_image() {
        let tmp = tempfile::TempDir::new().unwrap();
        let lineage = crate::posture::lineage::AuthSessionTracker::<H>::new(tmp.path());
        let mut parent = exec(
            1000,
            1,
            "/usr/bin/x",
            "/usr/bin/x",
            common::wire::exe::exe_flags::ROOT_DIR,
        );
        if let Event::ProcessSpawn { pid, exe, .. } = &mut parent {
            *pid = 7000;
            (exe.dev, exe.ino) = (0, 0);
        }
        assert!(lineage.ingest_spawn_event(&parent));
        assert_eq!(
            lineage.exec_image(7000, crate::posture::lineage::AsOf::Now),
            None
        );
        let r = R004::new(lineage);
        let mut child = exec(1000, 7000, "/proc/self/exe", "/usr/bin/x", DELETED);
        if let Event::ProcessSpawn { exe, .. } = &mut child {
            (exe.dev, exe.ino) = (0, 0);
        }
        assert!(kills(r.evaluate(&child)));
    }

    /// The executor's identities: at most [`ExecutorImages::CAP`], the
    /// oldest out first; `(0, 0)` is never one.
    #[test]
    fn the_executor_s_identities_are_bounded_and_never_zero() {
        let images = ExecutorImages::default();
        assert!(!images.record((0, 0)));
        assert!(!images.contains((0, 0)));
        for i in 0..ExecutorImages::CAP as u64 {
            assert!(images.record((1, i + 1)));
        }
        assert!(!images.record((1, 1)), "known");
        assert!(images.record((1, 999)));
        assert!(!images.contains((1, 1)), "the oldest went out");
        assert!(images.contains((1, 2)) && images.contains((1, 999)));
        // a refresh's replacement: `(0, 0)` is never one either
        let images = ExecutorImages::default();
        assert!(images.replace(vec![(0, 0), (1, 2), (1, 2)]));
        assert!(!images.contains((0, 0)));
        assert_eq!(images.len(), 1);
        assert!(!images.replace(vec![(1, 2), (0, 0)]), "the same set");
    }
}
