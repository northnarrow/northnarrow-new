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
//! # Lot 347: an OCI runtime's copy of itself (the alpha's container hosts)
//!
//! `runc` (and `crun`) re-execute themselves from a sealed memfd copy of
//! their own image — `runc_cloned:/proc/self/exe`, the CVE-2019-5736
//! defence — at every container start, `docker exec` and build: a memfd
//! exec, Critical, at each. It is no fileless code when every fact holds,
//! each the kernel's or the file's, never a name or a path:
//!
//! - the memfd was sealed against writing, shrinking and growing AT THE
//!   EXEC — the LSM program read its seals in `bprm_check_security`
//!   (`exe_flags::MEMFD_SEALED`; the review of #556, F1: sealed only when
//!   the pump read it, any holder of a writable descriptor could have
//!   rewritten it after the exec and sealed it then) — and is WHOLE and
//!   byte for byte an installed runtime's image when the pump reads it
//!   (`nn_linux::program_images`; [`program_identity::runtime_clone_of`]):
//!   a seal is never removed, so those are the bytes that ran;
//! - that image is the one the process that made the copy runs, by the
//!   kernel's exec records (the LSM program's `(dev, ino)` of the executed
//!   file, in any mount namespace — rootless Podman runs runc in its own;
//!   the pump compared the memfd with the installed file still at its path,
//!   an inode no other file has): runc 1.2's `runc create` (the exec is its
//!   child's first since the fork, its `fork_parent`), or the process itself
//!   before this exec (runc 1.1's `runc init` re-executing its own packaged
//!   image);
//! - and the runtime was started by an installed manager (containerd's shim,
//!   dockerd, containerd, conmon, podman), by the image of the process the
//!   kernel recorded forking it (its exec record in a root-only directory of
//!   PID 1's mount namespace, [`exec_image`]; for a fork the lineage holds no
//!   exec of — conmon's monitor, forked as it daemonized — the installed
//!   file the pump saw it run at the exec, still at its path) — or, for a
//!   re-exec, the process was forked by one.
//!
//! A memfd of anything else, a copy of the runtime not sealed at the exec
//! (sealed later included), a clone a session's process made (`python3`
//! executing runc's bytes from a memfd), a runtime outside the binary
//! directories (k3s's own `runc`, a snap's), every clone in tracepoint mode
//! (no seals read at the exec) and every clone on a kernel whose BTF lacks
//! `shmem_inode_info`'s offsets stay Critical.
//!
//! Lot 381 (F6-6 of the pre-alpha's Phase 6b: one rootful runc clone in 300,
//! Debian 13, Critical and counted nowhere): a clone whose process was gone
//! before the pump read it is compared through a process still running that
//! very memfd — runc 1.1's `runc init` forks its two stages with
//! `CLONE_PARENT`, children of `runc create` running the copy until the
//! container's program starts (the review of #588, F1: or a thread of its
//! own, its leader exited alone). When none is left, neither its bytes nor
//! its length are known: what holds is the seal at the exec, the lineage and
//! the parent's image. The review of #588 (F2): only in runc 1.1's re-exec
//! — the process ran that installed runtime's file itself just before, no
//! fork since (`fork_parent` 0), under that runtime's process — is it "not
//! compared (gone)", judged as past the budget: root's recorded High, never
//! killed; any other uid's the Critical kill. Any other shape — runc 1.2's
//! (`runc init`'s first exec since `runc create` forked it), every OCI hook
//! a runtime runs, a manager parent (which runtime it copied is not known)
//! — a parent gone too, or a process that runs another file by the read (a
//! runtime's copy never executes again): nothing kept, Critical.
//!
//! A clone whose every fact
//! holds but whose bytes were not compared — its uid's share of the
//! compare budget spent this second (the review of #556, F2: each uid but
//! root has its own share, root a reserve no user can spend) — is recorded
//! High, never killed, for uid 0 (the initial user namespace's root: a
//! busy container host's starts past the budget — the review of #578, N3,
//! reverting lot 370's F10-6 kill); any other uid spends its own share
//! (the re-check of #556, N1: decoys, then a sealed payload of runc's
//! length) and its uncompared memfd stays the Critical kill. The first
//! such clone of an episode (no skip for that uid in the minute before)
//! says so in its record, naming the uid whose share ran out and the
//! second's biggest spender — the budget spent on purpose is seen — and
//! the pump signs the spending (`runtime_copy_compare`). Either verdict
//! says "not compared (budget)" — a memfd of the runtime's length, any
//! program's — never a copy of the runtime. Residual: root spending its
//! own budget, then executing its own memfd under the runtime, is recorded
//! High, not killed — root, who needs no such route. Residual (lot 381,
//! the review of #588): a root process forked by runc under its manager
//! (as `runc init` is) executing the installed runc, then a sealed memfd of
//! its own, every thread of it exiting before the pump reads it — "not
//! compared (gone)", recorded
//! High, not killed, any program of any length; the same class, with no
//! budget to spend. Residual: the kernel reads the file's first bytes
//! (the binary's header, `bprm->buf`) just before the LSM hook reads the
//! seals; a writer racing that window chooses the header of a run whose
//! every mapped byte is the sealed runtime's (no code of its own: the
//! program headers, segments and interpreter are read from the sealed
//! file; a `#!` line names an interpreter, which `/proc/<pid>/exe` then is,
//! never the copy the pump compares).
//!
//! [`exec_image`]: crate::posture::lineage::AuthSessionTracker::exec_image
//!
//! # Lot 376 (the review of #583, F3): PID 1's executor without an identity
//!
//! At a reboot of Ubuntu 24.04 an exec of `/proc/self/fd/9`, `ppid` 1,
//! `comm` `9`, came with no identity at all (the exec record was attached
//! before the exec sensor at the agent's start — now after it — or the
//! LSM program's handoff was lost) and was gone before the pump read its
//! `/proc`: the path heuristic below, Critical. Such an exec is PID 1's own
//! launch of its packaged executor when every fact holds, each the
//! kernel's or the host's, never `argv[0]` or `comm`:
//!
//! - the path names the caller's own descriptor `N` exactly
//!   (`/proc/self/fd/N`, `/dev/fd/N`: [`crate::posture::proc_link::own_descriptor`]);
//! - the kernel's fork record says PID 1 forked it and this is its first
//!   exec since (`fork_parent` 1), its parent is PID 1, it runs as root, and
//!   the lineage holds no earlier exec of the process;
//! - PID 1's own descriptor `N` (`/proc/1/fd/N`, which the child's table
//!   copied at the fork, and which no one but root can change) is a file of
//!   the executor's identities ([`ExecutorImages`]: the packaged file, the
//!   copy PID 1 holds).
//!
//! A user's manager's launches are not read so (a user may change its own
//! manager's child before the exec); a shell's child, an orphan PID 1
//! adopted (its forker is another), a missing fork record, a second exec,
//! PID 1's descriptor `N` another file or a memfd, another spelling of the
//! path: the heuristic's Critical, as before.
//!
//! Tracepoint mode has no identity: the caller's path is read by the
//! posture's one reader of a `/proc` link
//! ([`crate::posture::proc_link::reopens_a_descriptor`]: every per-thread
//! and `/dev` name of a descriptor, folded); a symlink or a relative path
//! there is a residual of that mode.

use nn_model::{Event, ResponseAction, Severity, Verdict};

use crate::decision::attack::{AttackRef, Tactic};
use crate::decision::rules::program_identity::{self, ProgramKind};
use crate::decision::{Rule, rules::build_verdict};
use crate::posture::host::PostureHost;

/// Lot 347: what [`R004ExecFromProcSelfFd::runtime_self_clone`] found of a
/// memfd exec that is an installed runtime's copy of itself by every
/// identity fact.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RuntimeCopy {
    /// The pump compared it whole with the runtime's image: no fileless
    /// code.
    Compared,
    /// The review of #556 (F2): not compared (its uid's share of the
    /// budget spent this second) — a memfd of the runtime's length, any
    /// program's: root's recorded, never killed; any other uid's the
    /// Critical kill (the re-check of #556, N1: a user spends its own
    /// share; [`R004ExecFromProcSelfFd::not_compared`]) — with the episode
    /// it opened, if it is the first (the review of #578, N3). Lot 381:
    /// or not compared because the copy was gone before the pump read it.
    NotCompared(Uncompared),
}

/// Why the pump did not compare a runtime copy whose every identity fact
/// holds ([`R004ExecFromProcSelfFd::not_compared`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Uncompared {
    /// The review of #556 (F2): its uid's share of the compare budget was
    /// spent this second — with the episode it opened, if it is the first
    /// (the review of #578, N3).
    Budget(Option<program_identity::BudgetEpisode>),
    /// Lot 381 (F6-6 of the pre-alpha's Phase 6b): the copy was gone before
    /// the pump read it — every thread of the exec's process had exited and
    /// none of its parent's children the pump read ran it (runc 1.1's `runc
    /// init`, a few milliseconds past its exec, under a 200-container
    /// start). Judged only in runc 1.1's re-exec (the review of #588, F2).
    Gone,
}

/// Lot 378 (the rc10 soak, Debian 13: a rootless Podman run judged
/// fileless): `file`, the kernel's identity of a file a process executed (in
/// any mount namespace: rootless Podman executes conmon in its own), is an
/// installed program's ([`program_identity::installed_image`]) whose file at
/// its recorded path under the host's root is that very inode now, in a
/// directory root's and writable by no one else
/// ([`crate::posture::lineage::AuthSessionTracker::is_host_file_in_root_dir`])
/// — what the pump's sight of a manager says of a fork it saw (the inode
/// still at its path), never a user's file that has the inode number of a
/// program removed since. `None` otherwise; the caller asks its kind.
fn installed_file_at_its_path<H: PostureHost>(
    lineage: &crate::posture::lineage::AuthSessionTracker<H>,
    file: (u64, u64),
) -> Option<(u64, u64)> {
    program_identity::installed_image(file)
        .filter(|i| lineage.is_host_file_in_root_dir(&i.path, file))
        .map(|i| i.id)
}

/// The review of #578 (N3): the sentence an uncompared runtime copy's
/// record adds when it opened an episode of a spent compare budget — the
/// uid whose share ran out, and the second's biggest spender — and nothing
/// for the later ones of the episode.
fn episode_text(episode: Option<program_identity::BudgetEpisode>) -> String {
    let Some(e) = episode else {
        return String::new();
    };
    let top = match e.top {
        Some((top, bytes)) => format!(
            "; the second's biggest spender: uid {top}, {} MiB",
            bytes >> 20
        ),
        None => String::new(),
    };
    format!(
        " — the compare budget's spending opened an episode (signed once per episode): uid \
         {}'s share ran out{top}",
        e.uid
    )
}

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
    /// The name of the core's exec of its image's descriptor: `/dev/fd/<n>`
    /// (lot 353, re-check 2 of #563: `execveat(fd, "", …, AT_EMPTY_PATH)`;
    /// it was `/proc/self/fd/<n>`, an exec by path through `/proc`).
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
    /// Lot 310 (re-check 3, decision 1): the executors the host's PID 1
    /// holds open — an inode no user can reach (`/proc/1/fd` is root's):
    /// an exec of one is exempt by its identity alone.
    pid1_held: Vec<(u64, u64)>,
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

    /// Lot 310 (re-check 3, decision 1): the executors PID 1 holds now, in
    /// place of the ones before; `true` when the set changed.
    pub fn replace_pid1_held(&self, ids: Vec<(u64, u64)>) -> bool {
        let ids = normalised(ids, Self::CAP);
        let mut s = self.0.write();
        let changed = s.pid1_held != ids;
        s.pid1_held = ids;
        changed
    }

    /// `id` is an executor the host's PID 1 holds open (never `(0, 0)`).
    pub fn held_by_pid1(&self, id: (u64, u64)) -> bool {
        self.0.read().pid1_held.contains(&id)
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
    /// The review of #578 (P3): the system's `ldd` running the loader.
    listing: super::LoaderListing,
}

impl<H: PostureHost> R004ExecFromProcSelfFd<H> {
    pub fn new(lineage: crate::posture::lineage::AuthSessionTracker<H>) -> Self {
        Self {
            lineage: Some(lineage),
            own: None,
            executor: ExecutorImages::default(),
            listing: super::LoaderListing::default(),
        }
    }

    /// This rule with the lineage's identity of `ldd` (the review of #578).
    pub fn with_loader_listing(mut self, listing: super::LoaderListing) -> Self {
        self.listing = listing;
        self
    }

    /// Lot 370 (05-3.3): fileless code the dynamic loader runs for `event`
    /// — its operand (or a preload) a memfd or an unlinked file by the
    /// kernel's identity of the file it maps (the pump's placement: the
    /// review of #578, N1 — a linked file reached through a descriptor is
    /// judged as a direct exec of it: by the staging rules, on its path), or
    /// a descriptor's link (or a memfd's name) the pump could not place —
    /// with what the loader does with it (one it runs first, then one it may
    /// run). The re-check of #578 (R1-2): a name not through a link of
    /// `/proc` the pump found unlinked is fileless too.
    fn loader_fileless(&self, event: &Event) -> Option<(String, super::LoaderUse)> {
        use super::{LoaderUse, Placement};
        let mut found: Option<(String, LoaderUse)> = None;
        for (text, use_) in super::loader_code(event, self.listing.lists(event)) {
            let fileless = match super::placed(event, text) {
                Some(Placement::Fileless(p)) => Some(format!("{text}: {p}")),
                Some(Placement::File(_)) => None,
                None => Self::is_proc_fd_path(text).then(|| text.to_string()),
            }
            .or_else(|| match super::pump_placement(event, text) {
                Some(Placement::Fileless(p)) => Some(format!("{text}: {p}")),
                _ => None,
            });
            if let Some(f) = fileless {
                if found.as_ref().is_none_or(|(_, u)| u.rank() < use_.rank()) {
                    found = Some((f, use_));
                }
            }
        }
        found
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
        let id = (exe.dev, exe.ino);
        // re-check 3 (decision 1): a copy the host's PID 1 holds is an inode
        // no user can reach — by its identity alone, no fork record needed
        // (a flood of forks evicting the records must not make R004 kill a
        // unit's launch after a systemd upgrade)
        self.executor.held_by_pid1(id)
            || (self.executor.contains(id) && self.forked_by_a_manager(exe.fork_parent, as_of))
    }

    /// Lot 376 (the review of #583, F3; module docs): an exec with no
    /// identity is PID 1's launch of its packaged executor — the path names
    /// the caller's own descriptor `N`, the kernel's fork record says PID 1
    /// forked it (its first exec since), its parent is PID 1, it runs as
    /// root, the lineage holds no earlier exec of the process, and PID 1's
    /// own descriptor `N` is one of the executor's identities.
    fn pid1_executor_launch(&self, event: &Event) -> bool {
        let Event::ProcessSpawn {
            pid,
            ppid,
            uid,
            filename,
            exe,
            start_ns,
            timestamp_ns,
            ..
        } = event
        else {
            return false;
        };
        let Some(lineage) = self.lineage.as_ref() else {
            return false;
        };
        let Some(n) = crate::posture::proc_link::own_descriptor(filename) else {
            return false;
        };
        *uid == 0
            && *ppid == 1
            && exe.fork_parent == 1
            && !lineage.executed_before(*pid, *start_ns, *timestamp_ns)
            && lineage
                .pid1_descriptor_file(n)
                .is_some_and(|id| self.executor.held_by_pid1(id) || self.executor.contains(id))
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

    /// The re-check of #556 (N1): the verdict on a memfd exec whose every
    /// identity fact holds but whose bytes the pump did not compare (the
    /// budget's share of `uid` spent this second; lot 381: or the copy gone
    /// before the read). Only uid 0 — the initial user namespace's root, a
    /// budget no user can spend — is recorded High without a kill (the
    /// review of #578, N3: lot 370's F10-6 made it the Critical kill, and a
    /// busy container host's starts past the budget were killed); any other
    /// uid chooses to spend its own share (decoy hooks) or how long its
    /// process runs, so its uncompared memfd stays the Critical kill.
    /// Neither text calls it a copy of the runtime: nobody compared its
    /// bytes. The first of a budget's episode names who spent the budget
    /// ([`episode_text`]).
    fn not_compared(&self, event: &Event, uid: u32, why: Uncompared) -> Verdict {
        const GONE: &str = "not compared (gone): every thread of its process had exited before \
                            the pump read it, and none of its parent's children the pump read \
                            still ran its copy";
        let (what, root_why, user_why, episode) = match why {
            Uncompared::Budget(episode) => (
                "of an installed runtime's length",
                "not compared (budget): root's compare budget spent this second".to_string(),
                format!(
                    "not compared (budget): uid {uid}'s share of the compare budget spent this \
                     second"
                ),
                episode_text(episode),
            ),
            Uncompared::Gone => (
                "re-executed under an installed runtime's process (its length not known)",
                GONE.to_string(),
                GONE.to_string(),
                String::new(),
            ),
        };
        if uid == 0 {
            build_verdict(
                self,
                event,
                ResponseAction::Log,
                Severity::High,
                &format!(
                    "memfd exec under an installed container runtime and its manager, sealed at \
                     the exec, {what} — {root_why}, its bytes may be any program's (lot 347); \
                     recorded, not killed{episode}"
                ),
            )
        } else {
            build_verdict(
                self,
                event,
                ResponseAction::KillProcessTree,
                Severity::Critical,
                &format!(
                    "memfd-style exec detected — fileless execution, highly suspicious; under an \
                     installed container runtime, {what}, {user_why} (lot 347){episode}"
                ),
            )
        }
    }

    /// Lot 347 (module docs): `event`, a memfd exec, is an installed OCI
    /// runtime executing its own image's copy, sealed at the exec, started
    /// by an installed manager — each by the kernel's records; its bytes
    /// compared by the pump, or (the review of #556, F2) not compared, its
    /// uid's share of the budget spent.
    fn runtime_self_clone(
        &self,
        event: &Event,
        as_of: crate::posture::lineage::AsOf,
    ) -> Option<RuntimeCopy> {
        use crate::posture::lineage::AsOf;
        use common::wire::exe::exe_flags::MEMFD_SEALED;
        let Event::ProcessSpawn {
            pid,
            ppid,
            exe,
            timestamp_ns,
            ..
        } = event
        else {
            return None;
        };
        // the review of #556 (F1): sealed when the kernel executed it (the
        // LSM program's read), not only when the pump read it
        if !exe.has(MEMFD_SEALED) {
            return None;
        }
        let lineage = self.lineage.as_ref()?;
        // the pump's compare: the sealed memfd is this installed runtime
        let clone = program_identity::runtime_clone_of(event)?;
        let copy = if clone.gone {
            RuntimeCopy::NotCompared(Uncompared::Gone)
        } else if clone.unverified {
            RuntimeCopy::NotCompared(Uncompared::Budget(clone.episode))
        } else {
            RuntimeCopy::Compared
        };
        let content = clone.image;
        // a manager: by the lineage's exec record of its image, else — a
        // fork the lineage holds no exec of (conmon's monitor, forked as it
        // daemonized) — by the installed file the pump saw it run at the
        // exec; the forker relation is the kernel's
        // Lot 378 (the rc10 soak, Debian 13: Critical at a rootless Podman
        // run): or, for a record of no root-only directory of PID 1's mount
        // namespace — rootless Podman executes conmon in its own; the
        // lineage's sweep enters conmon's monitor, a fork, with that exec's
        // file — by the file the kernel executed: an installed manager's
        // inode still at its path ([`installed_file_at_its_path`])
        let manager = |pid: Option<u32>| {
            pid.is_some_and(|p| {
                let image = match lineage.exec_file(p, as_of) {
                    Some(file) => lineage
                        .exec_image(p, as_of)
                        .or_else(|| installed_file_at_its_path(lineage, file)),
                    None => clone.seen_image(p),
                };
                image.and_then(program_identity::installed_kind)
                    == Some(ProgramKind::RuntimeManager)
            })
        };
        // a runtime the kernel recorded a manager forking — the runtime's
        // file by the LSM program's identity in any mount namespace
        // (rootless Podman runs runc in its own): `content` is an installed
        // runtime's inode still at its path (the pump's compare), which no
        // other file can have
        let managed_runtime = |pid: u32| {
            lineage.exec_file(pid, as_of) == Some(content)
                && manager(lineage.fork_parent(pid, as_of))
        };
        if exe.fork_parent != 0 {
            // the review of #588 (F2): a copy gone before the read is never
            // judged at a first exec since a fork — runc 1.2's `runc init`,
            // and every OCI hook a runtime runs: its length not known, a
            // root hook from a sealed memfd of any size passed for the
            // runtime's copy. Nothing kept: Critical
            if clone.gone {
                return None;
            }
            // the first exec since the fork: the forker made the copy of
            // its own image (runc 1.2's `runc create`)
            return managed_runtime(exe.fork_parent).then_some(copy);
        }
        // the review of #588 (F2): gone, only under the very runtime's
        // process (runc 1.1's `runc create`, as the pump read its image)
        if clone.gone && clone.seen_image(*ppid) != Some(content) {
            return None;
        }
        // a re-exec: the process ran the runtime's image itself just before
        // (runc 1.1's `runc init`), forked by the runtime under its manager
        // or by the manager itself
        let before = AsOf::judged(timestamp_ns.saturating_sub(1));
        if *timestamp_ns <= 1 || lineage.exec_file(*pid, before) != Some(content) {
            return None;
        }
        let forker = lineage.fork_parent(*pid, before);
        (manager(forker) || forker.is_some_and(managed_runtime)).then_some(copy)
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
        // Lot 370 (05-3.3): fileless code the dynamic loader runs — its
        // operand (or a preload) a memfd or an unlinked file, or a
        // descriptor's link not placed: the image the kernel executed is the
        // loader, in `/lib`. The review of #578 (P3): one it only lists, Low;
        // its re-check (R1-1): one it may run while it lists, Medium — never
        // killed, never said to run nothing
        if let Some((p, use_)) = self.loader_fileless(event) {
            use crate::decision::rules::LoaderUse;
            let listed = match use_ {
                LoaderUse::Runs => None,
                LoaderUse::Lists(why) => Some((
                    Severity::Low,
                    format!(
                        "fileless code only listed or checked by the dynamic loader ({p}: {why}) \
                         — in that mode the loader runs no code of it; recorded Low, not killed"
                    ),
                )),
                LoaderUse::MayRun(why) => Some((
                    Severity::Medium,
                    format!(
                        "fileless code given to the dynamic loader to list or check ({p}: {why}) \
                         — it may still run code; recorded, not killed"
                    ),
                )),
            };
            if let Some((severity, text)) = listed {
                return Some(build_verdict(
                    self,
                    event,
                    ResponseAction::Log,
                    severity,
                    &text,
                ));
            }
            return Some(build_verdict(
                self,
                event,
                ResponseAction::KillProcessTree,
                Severity::Critical,
                &format!(
                    "memfd-style exec through the dynamic loader ({p}) — fileless execution, \
                     highly suspicious"
                ),
            ));
        }
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
            // lot 347: a memfd (unlinked too) is fileless unless it is an
            // installed runtime's sealed copy of itself under its manager
            // (module docs) — no other exemption reaches one
            let fileless = if exe.has(MEMFD) {
                match self.runtime_self_clone(event, as_of) {
                    Some(RuntimeCopy::Compared) => false,
                    Some(RuntimeCopy::NotCompared(why)) => {
                        return Some(self.not_compared(event, *uid, why));
                    }
                    None => true,
                }
            } else {
                exe.has(DELETED)
                    && !self.is_upgraded_executor(exe, as_of)
                    && !self.reexecs_its_parent_image(*ppid, exe, as_of)
            };
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
        } else if self.pid1_executor_launch(event) {
            // lot 376 (the review of #583, F3): no identity, but PID 1's
            // fork running the executor PID 1 holds as that descriptor
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
        assert!(
            rule.evaluate(&launch(
                900,
                990,
                "/proc/self/fd/64",
                &argv,
                deleted(2049, 77)
            ))
            .is_none()
        );
        // tracepoint mode: on the facts
        assert!(
            rule.evaluate(&launch(
                900,
                990,
                "/proc/self/fd/64",
                &argv,
                Default::default()
            ))
            .is_none()
        );
        // lot 276: the export worker, as its own account — and only so: as
        // the parse worker's account, or the parse worker as the export's,
        // fileless as ever
        let export = ["northnarrow-agent", "--worker", "export", "--ipc-fd", "3"];
        assert!(
            rule.evaluate(&launch(
                900,
                989,
                "/proc/self/fd/64",
                &export,
                Default::default()
            ))
            .is_none()
        );
        assert!(
            rule.evaluate(&launch(
                900,
                990,
                "/proc/self/fd/64",
                &export,
                Default::default()
            ))
            .is_some()
        );
        assert!(
            rule.evaluate(&launch(
                900,
                989,
                "/proc/self/fd/64",
                &argv,
                Default::default()
            ))
            .is_some()
        );
        let no_export = R004ExecFromProcSelfFd::default().with_own_launch(Some(OwnWorkerLaunch {
            export_uid: None,
            ..own.clone()
        }));
        assert!(
            no_export
                .evaluate(&launch(
                    900,
                    989,
                    "/proc/self/fd/64",
                    &export,
                    Default::default()
                ))
                .is_some()
        );
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
        assert!(
            R004ExecFromProcSelfFd::default()
                .evaluate(&launch(
                    900,
                    990,
                    "/proc/self/fd/64",
                    &argv,
                    deleted(2049, 77)
                ))
                .is_some()
        );
        // facts that would name root (an account lookup refuses root: never
        // built so) never exempt a root exec
        let root = R004ExecFromProcSelfFd::default().with_own_launch(Some(OwnWorkerLaunch {
            uid: 0,
            ..own.clone()
        }));
        assert!(
            root.evaluate(&launch(
                900,
                0,
                "/proc/self/fd/64",
                &argv,
                Default::default()
            ))
            .is_some()
        );
        // and an agent pid of 0 never matches
        let zero = R004ExecFromProcSelfFd::default().with_own_launch(Some(OwnWorkerLaunch {
            agent_pid: 0,
            ..own
        }));
        assert!(
            zero.evaluate(&launch(
                0,
                990,
                "/proc/self/fd/64",
                &argv,
                Default::default()
            ))
            .is_some()
        );
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
        assert!(
            R004ExecFromProcSelfFd::default()
                .evaluate(&spawn("ls", "/usr/bin/ls"))
                .is_none()
        );
        // /proc/<pid>/status is not an exec target.
        assert!(
            R004ExecFromProcSelfFd::default()
                .evaluate(&spawn("x", "/proc/123/status"))
                .is_none()
        );
    }

    #[test]
    fn matches_proc_pid_fd_form_too() {
        assert!(
            R004ExecFromProcSelfFd::default()
                .evaluate(&spawn("x", "/proc/4242/fd/7"))
                .is_some()
        );
        // Empty fd number does not count.
        assert!(
            R004ExecFromProcSelfFd::default()
                .evaluate(&spawn("x", "/proc/self/fd/"))
                .is_none()
        );
        // Lot 310: the posture's one reader of a `/proc` link reads any
        // second segment (`self`, `thread-self`, a pid): this assertion
        // said a non-numeric one does not count. No `/proc` entry has
        // such a name, so `/proc/abc/fd/3` is never executed, and the
        // per-thread names (`thread-self`) are what it missed (BUG-88).
        assert!(
            R004ExecFromProcSelfFd::default()
                .evaluate(&spawn("x", "/proc/abc/fd/3"))
                .is_some()
        );
        assert!(
            R004ExecFromProcSelfFd::default()
                .evaluate(&spawn("x", "/proc/thread-self/fd/3"))
                .is_some()
        );
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
        assert!(
            r.evaluate(&ev("/proc/self/fd/3", "/memfd:x (deleted)", MEMFD))
                .is_some()
        );
        assert!(
            r.evaluate(&ev("/proc/self/fd/3", "/tmp/#1234 (deleted)", DELETED))
                .is_some()
        );
        assert!(
            r.evaluate(&ev(
                "/proc/self/fd/3",
                "/tmp/systemd-executor (deleted)",
                DELETED
            ))
            .is_some()
        );
        // a real file through an fd is judged on its path by the other rules
        assert!(
            r.evaluate(&ev("/proc/self/fd/3", "/tmp/payload", 0))
                .is_none()
        );
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
        assert!(
            R004ExecFromProcSelfFd::default()
                .evaluate(&with_proc_exe(ev, common::wire::exe::exe_flags::DELETED))
                .is_some()
        );
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
        assert!(
            r.evaluate(&exec(
                1000,
                7777,
                "/proc/self/exe",
                "/opt/google/chrome/chrome",
                DELETED
            ))
            .is_none()
        );
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

    /// Re-check 3 (decision 1): a unit's launch through the deleted executor
    /// PID 1 holds is exempt with no fork record (a flood evicted it, the
    /// fork predates the agent): no user can reach that inode. Another
    /// identity of the set — a user's manager's copy, the packaged file —
    /// still needs the fork record.
    #[test]
    fn a_pid_1_held_executor_needs_no_fork_record() {
        let images = ExecutorImages::default();
        images.record((2049, 1001));
        images.record((2049, 1002));
        images.replace_pid1_held(vec![(2049, 1001)]);
        let r = R004::default().with_launches(KnownLaunches {
            own_worker: None,
            executor: images,
        });
        let launch = |id: (u64, u64), forker: u32| {
            let mut e = exec(
                0,
                1,
                "/proc/self/fd/9",
                "/usr/lib/systemd/systemd-executor",
                DELETED,
            );
            if let Event::ProcessSpawn { exe, .. } = &mut e {
                (exe.dev, exe.ino) = id;
                exe.fork_parent = forker;
            }
            e
        };
        assert!(
            r.evaluate(&launch((2049, 1001), 0)).is_none(),
            "no fork record"
        );
        assert!(
            r.evaluate(&launch((2049, 1001), 4444)).is_none(),
            "any forker"
        );
        assert!(
            kills(r.evaluate(&launch((2049, 1002), 0))),
            "not PID 1's: a record needed"
        );
        assert!(
            r.evaluate(&launch((2049, 1002), 1)).is_none(),
            "PID 1 forked it"
        );
    }

    /// Lot 347: an exec in the lineage — `id` its file's identity in a
    /// root-only directory (`ROOT_DIR`), `fork_parent` the kernel's record.
    fn lineage_exec(pid: u32, ppid: u32, fork_parent: u32, id: (u64, u64), ts: u64) -> Event {
        let mut e = exec(0, ppid, "/usr/sbin/runc", "/usr/sbin/runc", ROOT_DIR);
        if let Event::ProcessSpawn {
            pid: p,
            exe,
            timestamp_ns,
            start_ns,
            ..
        } = &mut e
        {
            *p = pid;
            *timestamp_ns = ts;
            *start_ns = ts.min(1_000);
            (exe.dev, exe.ino) = id;
            exe.fork_parent = fork_parent;
        }
        e
    }

    /// Lot 347: a memfd exec of `pid` (unlinked, as every memfd), as runc's
    /// `fexecve` reports it — sealed at the exec (the LSM program's read).
    fn memfd_exec(pid: u32, ppid: u32, fork_parent: u32, ts: u64) -> Event {
        let mut e = exec(
            0,
            ppid,
            "/dev/fd/6",
            "/memfd:runc_cloned:/proc/self/exe",
            MEMFD | DELETED | common::wire::exe::exe_flags::MEMFD_SEALED,
        );
        if let Event::ProcessSpawn {
            pid: p,
            exe,
            timestamp_ns,
            start_ns,
            ..
        } = &mut e
        {
            *p = pid;
            *timestamp_ns = ts;
            *start_ns = 1_000;
            (exe.dev, exe.ino) = (0x0000_0001, u64::from(pid));
            exe.fork_parent = fork_parent;
        }
        e
    }

    /// Lot 347 (the alpha's container hosts: Docker on Debian 13): runc's
    /// sealed copy of itself (`runc_cloned:/proc/self/exe`) is no fileless
    /// code when the pump found it byte for byte the installed runtime, the
    /// process that made it runs that image (runc 1.2: the forker; runc 1.1:
    /// the process itself before the re-exec) and an installed manager
    /// started the runtime — each by the kernel's records. Every other
    /// memfd stays Critical (fails on main: every clone was).
    #[test]
    fn a_runtimes_sealed_copy_of_itself_under_its_manager_is_not_fileless() {
        use crate::decision::rules::program_identity::{
            InstalledImage, RuntimeClone, keep_runtime_clone, record_installed,
        };
        let copy = |image: (u64, u64)| RuntimeClone {
            image,
            seen: Vec::new(),
            unverified: false,
            ..Default::default()
        };
        let (runc, shim, bash, crun) = (
            (0x0fd0_0347, 347_001),
            (0x0fd0_0347, 347_002),
            (0x0fd0_0347, 347_003),
            (0x0fd0_0347, 347_004),
        );
        for (id, path, kind) in [
            (runc, "/usr/sbin/runc", ProgramKind::ContainerRuntime),
            (crun, "/usr/bin/crun", ProgramKind::ContainerRuntime),
            (
                shim,
                "/usr/bin/containerd-shim-runc-v2",
                ProgramKind::RuntimeManager,
            ),
        ] {
            record_installed(InstalledImage {
                id,
                len: 12_000_000,
                path: path.into(),
                kind,
            });
        }
        let tmp = tempfile::TempDir::new().unwrap();
        let lineage = crate::posture::lineage::AuthSessionTracker::<H>::new(tmp.path());
        for e in [
            lineage_exec(34_700, 1, 1, shim, 100),           // the shim
            lineage_exec(34_701, 34_700, 34_700, runc, 200), // runc create
            lineage_exec(34_710, 1, 1, bash, 100),           // a session's shell
            lineage_exec(34_711, 34_710, 34_710, runc, 200), // runc run by it
            lineage_exec(34_720, 34_700, 34_700, crun, 200), // another runtime
            // runc 1.1: `runc init` runs the packaged runc first, then
            // re-executes it from the memfd
            lineage_exec(34_702, 34_701, 34_701, runc, 300),
            lineage_exec(34_712, 34_711, 34_711, runc, 300),
            lineage_exec(34_703, 34_701, 34_701, bash, 300),
            // crun re-executing itself, run by the manager
            lineage_exec(34_721, 34_700, 34_700, crun, 300),
        ] {
            assert!(lineage.ingest_spawn_event(&e));
        }
        let r = R004::new(lineage.clone());
        let judged = |e: Event, copy_of: Option<(u64, u64)>| {
            assert!(lineage.ingest_spawn_event(&e));
            if let Some(id) = copy_of {
                keep_runtime_clone(&e, copy(id));
            }
            r.evaluate(&e)
        };
        // runc 1.2: the child of `runc create`, its first exec
        assert!(judged(memfd_exec(34_704, 34_701, 34_701, 400), Some(runc)).is_none());
        // runc 1.1: `runc init` re-executing its own image
        assert!(judged(memfd_exec(34_702, 34_701, 0, 400), Some(runc)).is_none());
        // crun re-executing itself under the manager
        assert!(judged(memfd_exec(34_721, 34_700, 0, 400), Some(crun)).is_none());
        // the mini-hunt: the path the caller passed is not looked at — Go's
        // `/proc/self/fd/7`, fexecve's `/dev/fd/6`, the kernel's `/memfd:`
        for path in ["/proc/self/fd/7", "/proc/thread-self/fd/7", "/memfd:x"] {
            let mut e = memfd_exec(34_730, 34_701, 34_701, 400);
            if let Event::ProcessSpawn { filename, .. } = &mut e {
                *filename = path.into();
            }
            assert!(judged(e, Some(runc)).is_none(), "{path}");
        }
        // CONTROLS: the pump found no copy (another program, unsealed, not
        // compared): fileless
        assert!(kills(judged(memfd_exec(34_705, 34_701, 34_701, 400), None)));
        // a copy of another installed runtime than the forker's
        assert!(kills(judged(
            memfd_exec(34_706, 34_701, 34_701, 400),
            Some(crun)
        )));
        // the runtime started by a session's shell, not a manager
        assert!(kills(judged(
            memfd_exec(34_713, 34_711, 34_711, 400),
            Some(runc)
        )));
        assert!(kills(judged(
            memfd_exec(34_712, 34_711, 0, 400),
            Some(runc)
        )));
        // a re-exec by a process that ran no runtime before
        assert!(kills(judged(
            memfd_exec(34_703, 34_701, 0, 400),
            Some(runc)
        )));
        // a session's shell forking a copy of runc (its first exec)
        assert!(kills(judged(
            memfd_exec(34_714, 34_710, 34_710, 400),
            Some(runc)
        )));
        // a forker the lineage does not hold
        assert!(kills(judged(
            memfd_exec(34_715, 34_799, 34_799, 400),
            Some(runc)
        )));
        // Podman: conmon's monitor, a fork that never executed (it
        // daemonized), forks `runc create`: its image is the one the pump
        // saw it run at the exec, for the forker the kernel recorded
        let conmon = (0x0fd0_0347, 347_005);
        record_installed(InstalledImage {
            id: conmon,
            len: 12_000_000,
            path: "/usr/bin/conmon".into(),
            kind: ProgramKind::RuntimeManager,
        });
        assert!(lineage.ingest_spawn_event(&lineage_exec(34_741, 34_740, 34_740, runc, 200)));
        assert!(lineage.ingest_spawn_event(&lineage_exec(34_742, 34_741, 34_741, runc, 300)));
        let seen = |forker_image: (u64, u64), at: u32| RuntimeClone {
            image: runc,
            seen: vec![(34_741, runc), (at, forker_image)],
            unverified: false,
            ..Default::default()
        };
        let podman = |e: Event, clone: RuntimeClone| {
            assert!(lineage.ingest_spawn_event(&e));
            keep_runtime_clone(&e, clone);
            r.evaluate(&e)
        };
        assert!(podman(memfd_exec(34_742, 34_741, 0, 400), seen(conmon, 34_740)).is_none());
        assert!(
            podman(
                memfd_exec(34_743, 34_741, 34_741, 400),
                seen(conmon, 34_740)
            )
            .is_none()
        );
        // a forker the lineage holds an exec of, from no root-only
        // directory (a user's file whose inode number a removed conmon had):
        // the pump's sight of it does not count
        let mut user = lineage_exec(34_746, 34_710, 34_710, conmon, 200);
        if let Event::ProcessSpawn { exe, .. } = &mut user {
            exe.flags &= !ROOT_DIR;
        }
        assert!(lineage.ingest_spawn_event(&user));
        assert!(lineage.ingest_spawn_event(&lineage_exec(34_747, 34_746, 34_746, runc, 300)));
        let by_user = RuntimeClone {
            image: runc,
            seen: vec![(34_747, runc), (34_746, conmon)],
            unverified: false,
            ..Default::default()
        };
        assert!(kills(podman(
            memfd_exec(34_748, 34_747, 34_747, 410),
            by_user
        )));
        // rootless Podman: runc and `runc init` executed in podman's own
        // mount namespace (no root-only directory of PID 1's: no image in
        // the lineage, the file's identity all the same)
        let rootless = |pid: u32, ppid: u32, ts: u64| {
            let mut e = lineage_exec(pid, ppid, ppid, runc, ts);
            if let Event::ProcessSpawn { exe, .. } = &mut e {
                exe.flags &= !ROOT_DIR;
            }
            assert!(lineage.ingest_spawn_event(&e));
        };
        rootless(34_751, 34_750, 200);
        rootless(34_752, 34_751, 300);
        let under = |at: u32| RuntimeClone {
            image: runc,
            seen: vec![(34_751, runc), (at, conmon)],
            unverified: false,
            ..Default::default()
        };
        assert!(podman(memfd_exec(34_752, 34_751, 0, 400), under(34_750)).is_none());
        assert!(podman(memfd_exec(34_753, 34_751, 34_751, 400), under(34_750)).is_none());
        // the forker seen running no manager, or another pid seen
        assert!(kills(podman(
            memfd_exec(34_744, 34_741, 34_741, 410),
            seen(bash, 34_740)
        )));
        assert!(kills(podman(
            memfd_exec(34_745, 34_741, 34_741, 410),
            seen(conmon, 34_749)
        )));
        // no lineage (unit tests' rule): fileless
        let bare = memfd_exec(34_716, 34_701, 34_701, 400);
        keep_runtime_clone(&bare, copy(runc));
        assert!(kills(R004::default().evaluate(&bare)));
    }

    /// Lot 378 (named, the rc10 soak on Debian 13: R004 Critical, a
    /// would-have KillProcessTree, at a rootless Podman run —
    /// `memfd:runc_cloned` executed through `/dev/fd/6` as uid 1000 by `runc
    /// init`, under `runc --systemd-cgroup … create`; the pump had compared
    /// the copy and kept it): rootless Podman executes conmon in its own
    /// mount namespace, so its exec record holds the file the kernel
    /// executed but no image of a root-only directory of PID 1's, and the
    /// lineage's sweep enters conmon's monitor (a fork) with that record.
    /// The manager was then judged by the record's image alone, the pump's
    /// sight of it no longer asked: Critical whenever a sweep came between
    /// the monitor's fork and the judgement. A manager is told by the file
    /// the kernel executed too: an installed manager's inode still at its
    /// path, in a directory root's only. The attack shapes still fire,
    /// rootless or not: a memfd the pump found no copy of, under the same
    /// runtime and manager; a copy of runc under a session's shell; under a
    /// user's file with the inode number of a manager removed since, or
    /// with another file at the manager's path; under a manager in a
    /// directory others can write; and an uncompared copy (the budget) of
    /// a user.
    #[test]
    fn a_rootless_runtime_s_copy_under_a_manager_of_its_own_mount_namespace_is_not_fileless() {
        use crate::decision::rules::program_identity::{
            InstalledImage, RuntimeClone, keep_runtime_clone, record_installed,
        };
        use crate::posture::host::testing::IdTestHost;
        const STAT_DEV: u64 = 64769;
        const KDEV: u64 = common::wire::exe::kernel_dev(STAT_DEV);
        let (runc, conmon, bash) = ((KDEV, 378_001), (KDEV, 378_002), (KDEV, 378_003));
        for (id, path, kind) in [
            (runc, "/usr/bin/runc", ProgramKind::ContainerRuntime),
            (conmon, "/usr/bin/conmon", ProgramKind::RuntimeManager),
        ] {
            record_installed(InstalledImage {
                id,
                len: 12_000_000,
                path: path.into(),
                kind,
            });
        }
        IdTestHost::set_file_id("/usr/bin/runc", Some((STAT_DEV, 378_001)));
        IdTestHost::set_file_id("/usr/bin/conmon", Some((STAT_DEV, 378_002)));
        IdTestHost::set_dir_root_only("/usr/bin", true);
        let tmp = tempfile::TempDir::new().unwrap();
        let lineage = crate::posture::lineage::AuthSessionTracker::<IdTestHost>::new(tmp.path());
        let as_user = |mut e: Event| {
            if let Event::ProcessSpawn { uid, gid, exe, .. } = &mut e {
                (*uid, *gid) = (1000, 1000);
                // podman's own mount namespace: no root-only directory of
                // PID 1's
                exe.flags &= !ROOT_DIR;
            }
            e
        };
        // conmon's monitor as the sweep entered it (or conmon forking the
        // runtime itself), `runc create`, `runc init`; a session's shell
        // and the runc it runs
        for e in [
            lineage_exec(37_800, 37_799, 37_799, conmon, 100),
            lineage_exec(37_801, 37_800, 37_800, runc, 200),
            lineage_exec(37_802, 37_801, 37_801, runc, 300),
            lineage_exec(37_810, 37_809, 37_809, bash, 100),
            lineage_exec(37_811, 37_810, 37_810, runc, 200),
            lineage_exec(37_812, 37_811, 37_811, runc, 300),
        ] {
            assert!(lineage.ingest_spawn_event(&as_user(e)));
        }
        let r = R004ExecFromProcSelfFd::<IdTestHost>::new(lineage.clone());
        let judged =
            |pid: u32, ppid: u32, fork_parent: u32, ts: u64, clone: Option<RuntimeClone>| {
                let e = as_user(memfd_exec(pid, ppid, fork_parent, ts));
                assert!(lineage.ingest_spawn_event(&e));
                if let Some(c) = clone {
                    keep_runtime_clone(&e, c);
                }
                r.evaluate(&e)
            };
        let copy = || {
            Some(RuntimeClone {
                image: runc,
                seen: Vec::new(),
                unverified: false,
                ..Default::default()
            })
        };
        // runc 1.1: `runc init` re-executing its own image
        assert!(judged(37_802, 37_801, 0, 400, copy()).is_none(), "runc 1.1");
        // runc 1.2: `runc create`'s child, its first exec
        assert!(
            judged(37_803, 37_801, 37_801, 400, copy()).is_none(),
            "runc 1.2"
        );
        // the attack shapes
        assert!(
            kills(judged(37_804, 37_801, 37_801, 410, None)),
            "a memfd the pump found no copy of"
        );
        assert!(
            kills(judged(37_812, 37_811, 0, 410, copy())),
            "under a session's shell"
        );
        let uncompared = RuntimeClone {
            unverified: true,
            ..copy().unwrap()
        };
        assert!(
            kills(judged(37_805, 37_801, 37_801, 420, Some(uncompared))),
            "a user's uncompared copy"
        );
        IdTestHost::set_file_id("/usr/bin/conmon", Some((STAT_DEV, 999)));
        assert!(
            kills(judged(37_806, 37_801, 37_801, 430, copy())),
            "another file at the manager's path"
        );
        IdTestHost::set_file_id("/usr/bin/conmon", None);
        assert!(
            kills(judged(37_807, 37_801, 37_801, 440, copy())),
            "the manager removed since"
        );
        // the mini-hunt's variant: rootless Docker's containerd shim, executed
        // in RootlessKit's own mount namespace (no root-only image either)
        IdTestHost::set_file_id("/usr/bin/conmon", Some((STAT_DEV, 378_002)));
        let shim = (KDEV, 378_004);
        record_installed(InstalledImage {
            id: shim,
            len: 12_000_000,
            path: "/usr/bin/containerd-shim-runc-v2".into(),
            kind: ProgramKind::RuntimeManager,
        });
        IdTestHost::set_file_id(
            "/usr/bin/containerd-shim-runc-v2",
            Some((STAT_DEV, 378_004)),
        );
        for e in [
            lineage_exec(37_820, 37_819, 37_819, shim, 100),
            lineage_exec(37_821, 37_820, 37_820, runc, 200),
            lineage_exec(37_822, 37_821, 37_821, runc, 300),
        ] {
            assert!(lineage.ingest_spawn_event(&as_user(e)));
        }
        assert!(
            judged(37_822, 37_821, 0, 460, copy()).is_none(),
            "rootless Docker's shim"
        );
        IdTestHost::set_file_id("/usr/bin/containerd-shim-runc-v2", None);
        IdTestHost::set_dir_root_only("/usr/bin", false);
        assert!(
            kills(judged(37_808, 37_801, 37_801, 450, copy())),
            "a directory others can write"
        );
        for path in ["/usr/bin/runc", "/usr/bin/conmon"] {
            IdTestHost::set_file_id(path, None);
        }
    }

    /// The review of #556 (F1, named): the pump's compare proves the memfd
    /// sealed and runc's bytes when it READS it, after the exec — any holder
    /// of a writable descriptor (the parent of an OCI hook runc executes
    /// from `/proc/<pid>/fd/N`) can rewrite and seal it in between. Exempt
    /// only a copy the LSM program found sealed AT THE EXEC: the same clone,
    /// the same lineage, without `MEMFD_SEALED`, is fileless (fails on the
    /// lot's first head: it was exempt).
    #[test]
    fn a_runtime_copy_sealed_only_after_the_exec_is_fileless() {
        use crate::decision::rules::program_identity::{
            InstalledImage, RuntimeClone, keep_runtime_clone, record_installed,
        };
        use common::wire::exe::exe_flags::MEMFD_SEALED;
        let (runc, shim) = ((0x0fd0_0556, 556_001), (0x0fd0_0556, 556_002));
        for (id, path, kind) in [
            (runc, "/usr/sbin/runc", ProgramKind::ContainerRuntime),
            (
                shim,
                "/usr/bin/containerd-shim-runc-v2",
                ProgramKind::RuntimeManager,
            ),
        ] {
            record_installed(InstalledImage {
                id,
                len: 12_000_000,
                path: path.into(),
                kind,
            });
        }
        let tmp = tempfile::TempDir::new().unwrap();
        let lineage = crate::posture::lineage::AuthSessionTracker::<H>::new(tmp.path());
        assert!(lineage.ingest_spawn_event(&lineage_exec(35_600, 1, 1, shim, 100)));
        assert!(lineage.ingest_spawn_event(&lineage_exec(35_601, 35_600, 35_600, runc, 200)));
        let r = R004::new(lineage.clone());
        let judged = |e: Event, unverified: bool| {
            assert!(lineage.ingest_spawn_event(&e));
            keep_runtime_clone(
                &e,
                RuntimeClone {
                    image: runc,
                    seen: Vec::new(),
                    unverified,
                    ..Default::default()
                },
            );
            r.evaluate(&e)
        };
        let unsealed_at_exec = |pid: u32| {
            let mut e = memfd_exec(pid, 35_601, 35_601, 400);
            if let Event::ProcessSpawn { exe, .. } = &mut e {
                exe.flags &= !MEMFD_SEALED;
            }
            e
        };
        assert!(judged(memfd_exec(35_602, 35_601, 35_601, 400), false).is_none());
        assert!(kills(judged(unsealed_at_exec(35_603), false)));
        // nor recorded as an unverified copy (F2): the kill
        assert!(kills(judged(unsealed_at_exec(35_604), true)));
    }

    /// The review of #556 (F2): root's memfd whose every identity fact
    /// holds but whose bytes the pump did not compare (root's budget spent
    /// this second) is recorded High, never killed — a busy container
    /// host's starts past the budget. The review of #578 (N3, named): lot
    /// 370's F10-6 made it the Critical kill (more than ~17 container
    /// starts a second killed runc under `enforcing`, a Critical record
    /// under `alpha`); it fails on 382be007. One whose facts fail stays the
    /// Critical kill. Any other uid's: the next test (N1).
    #[test]
    fn an_uncompared_runtime_copy_is_recorded_never_killed() {
        use crate::decision::rules::program_identity::{
            InstalledImage, RuntimeClone, keep_runtime_clone, record_installed,
        };
        let (runc, shim, bash) = (
            (0x0fd0_0556, 556_011),
            (0x0fd0_0556, 556_012),
            (0x0fd0_0556, 556_013),
        );
        for (id, path, kind) in [
            (runc, "/usr/sbin/runc", ProgramKind::ContainerRuntime),
            (
                shim,
                "/usr/bin/containerd-shim-runc-v2",
                ProgramKind::RuntimeManager,
            ),
        ] {
            record_installed(InstalledImage {
                id,
                len: 12_000_000,
                path: path.into(),
                kind,
            });
        }
        let tmp = tempfile::TempDir::new().unwrap();
        let lineage = crate::posture::lineage::AuthSessionTracker::<H>::new(tmp.path());
        for e in [
            lineage_exec(35_610, 1, 1, shim, 100),
            lineage_exec(35_611, 35_610, 35_610, runc, 200),
            lineage_exec(35_620, 1, 1, bash, 100),
            lineage_exec(35_621, 35_620, 35_620, runc, 200),
        ] {
            assert!(lineage.ingest_spawn_event(&e));
        }
        let r = R004::new(lineage.clone());
        let unverified = RuntimeClone {
            image: runc,
            seen: Vec::new(),
            unverified: true,
            ..Default::default()
        };
        let under_shim = memfd_exec(35_612, 35_611, 35_611, 400);
        assert!(lineage.ingest_spawn_event(&under_shim));
        keep_runtime_clone(&under_shim, unverified.clone());
        let v = r.evaluate(&under_shim).expect("recorded");
        assert_eq!(
            (v.action.clone(), v.severity),
            (ResponseAction::Log, Severity::High),
            "the verdict's action and severity"
        );
        // not the first of an episode: no episode sentence
        assert!(
            !v.reasoning.contains("episode"),
            "the record does not say \'episode\'"
        );
        // the re-check of #556 (N1): the text vouches for no bytes
        assert!(
            v.reasoning.contains("not compared (budget)"),
            "the record says 'not compared (budget)'"
        );
        assert!(
            !v.reasoning.contains("copy"),
            "the record does not say \'copy\'"
        );
        // CONTROL: the runtime run by a session's shell — the kill
        let under_shell = memfd_exec(35_622, 35_621, 35_621, 400);
        assert!(lineage.ingest_spawn_event(&under_shell));
        keep_runtime_clone(&under_shell, unverified);
        assert!(kills(r.evaluate(&under_shell)));
    }

    /// The re-check of #556 (N1, named; its probe): a rootless user runs
    /// three decoy OCI hooks (sealed genuine runc copies, compared) that
    /// spend its OWN share of the compare budget, then a sealed payload
    /// padded to runc's length — the pump keeps it unverified. A uid but 0
    /// chose that downgrade: its uncompared memfd stays the Critical kill,
    /// as before the lot, and the text says "not compared (budget)", never
    /// a copy of the runtime (fails on eb16784d: High, recorded only, "the
    /// runtime's copy of itself").
    #[test]
    fn a_users_uncompared_memfd_past_its_own_share_stays_critical() {
        use crate::decision::rules::program_identity::{
            InstalledImage, RuntimeClone, keep_runtime_clone, record_installed,
        };
        let (runc, conmon) = ((0x0fd0_0556, 556_021), (0x0fd0_0556, 556_022));
        for (id, path, kind) in [
            (runc, "/usr/sbin/runc", ProgramKind::ContainerRuntime),
            (conmon, "/usr/bin/conmon", ProgramKind::RuntimeManager),
        ] {
            record_installed(InstalledImage {
                id,
                len: 12_000_000,
                path: path.into(),
                kind,
            });
        }
        let tmp = tempfile::TempDir::new().unwrap();
        let lineage = crate::posture::lineage::AuthSessionTracker::<H>::new(tmp.path());
        for e in [
            lineage_exec(35_630, 1, 1, conmon, 100),
            lineage_exec(35_631, 35_630, 35_630, runc, 200),
        ] {
            assert!(lineage.ingest_spawn_event(&e));
        }
        let r = R004::new(lineage.clone());
        let as_uid = |pid: u32, uid: u32| {
            let mut e = memfd_exec(pid, 35_631, 35_631, 400);
            if let Event::ProcessSpawn { uid: u, gid, .. } = &mut e {
                (*u, *gid) = (uid, uid);
            }
            assert!(lineage.ingest_spawn_event(&e));
            e
        };
        let judged = |e: &Event, unverified: bool| {
            keep_runtime_clone(
                e,
                RuntimeClone {
                    image: runc,
                    seen: Vec::new(),
                    unverified,
                    ..Default::default()
                },
            );
            r.evaluate(e)
        };
        // the user's decoys, compared: exempt
        assert!(judged(&as_uid(35_632, 1000), false).is_none());
        // its payload past its own share: the kill, the text vouching for
        // no bytes
        let v = judged(&as_uid(35_633, 1000), true).expect("judged");
        assert_eq!(
            (v.action.clone(), v.severity),
            (ResponseAction::KillProcessTree, Severity::Critical),
            "the verdict's action and severity"
        );
        assert!(
            v.reasoning.contains("not compared (budget)"),
            "the record says 'not compared (budget)'"
        );
        assert!(
            !v.reasoning.contains("copy"),
            "the record does not say \'copy\'"
        );
        // a subordinate uid (a rootless container's root, mapped): the same
        let sub = judged(&as_uid(35_634, 100_000), true);
        assert!(kills(sub), "a mapped root is no uid 0");
        // CONTROL: root's past its own budget — recorded, not killed (the
        // named residual; the review of #578, N3)
        let v = judged(&as_uid(35_635, 0), true).expect("recorded");
        assert_eq!(
            (v.action.clone(), v.severity),
            (ResponseAction::Log, Severity::High)
        );
    }

    /// Lot 381 (F6-6 of the pre-alpha's Phase 6b, named): runc 1.1's
    /// `runc init` re-executing its sealed copy, gone before the pump read
    /// it, nothing left running the copy — the pump keeps it "not compared
    /// (gone)", with the runtime its parent runs. Every identity fact holds
    /// (the re-exec of the packaged runc, forked by `runc create` under
    /// conmon): root's is recorded High, never killed, and says it was not
    /// compared — never a copy of the runtime, never Low; a user's (a
    /// rootless start, or a payload that exits at once) stays the Critical
    /// kill, as past the budget. A gone memfd whose facts fail — a shell's
    /// runc, a process that never ran the runtime — stays Critical,
    /// rootful or rootless. On rc11 the pump kept nothing: Critical for
    /// root's too (fails there: no `gone`). The review of #588 (F2): only
    /// runc 1.1's re-exec — runc 1.2's shape (a first exec since the fork:
    /// every OCI hook too) and a gone copy whose parent the pump did not see
    /// run that runtime stay the Critical kill (High at 51a0f11d).
    #[test]
    fn a_runc_clone_gone_before_the_read_is_high_for_root_and_critical_for_a_user() {
        use crate::decision::rules::program_identity::{
            InstalledImage, RuntimeClone, keep_runtime_clone, record_installed,
        };
        let (runc, conmon, bash) = (
            (0x0fd0_0381, 381_001),
            (0x0fd0_0381, 381_002),
            (0x0fd0_0381, 381_003),
        );
        for (id, path, kind) in [
            (runc, "/usr/sbin/runc", ProgramKind::ContainerRuntime),
            (conmon, "/usr/bin/conmon", ProgramKind::RuntimeManager),
        ] {
            record_installed(InstalledImage {
                id,
                len: 12_000_000,
                path: path.into(),
                kind,
            });
        }
        let tmp = tempfile::TempDir::new().unwrap();
        let lineage = crate::posture::lineage::AuthSessionTracker::<H>::new(tmp.path());
        let as_uid = |mut e: Event, uid: u32| {
            if let Event::ProcessSpawn { uid: u, gid, .. } = &mut e {
                (*u, *gid) = (uid, uid);
            }
            e
        };
        for (e, uid) in [
            (lineage_exec(38_100, 1, 1, conmon, 100), 0),
            // `runc create`, then `runc init` running the packaged runc
            (lineage_exec(38_101, 38_100, 38_100, runc, 200), 0),
            (lineage_exec(38_102, 38_101, 38_101, runc, 300), 0),
            (lineage_exec(38_108, 38_101, 38_101, runc, 300), 0),
            // rootless: the same, as uid 1000
            (lineage_exec(38_110, 1, 1, conmon, 100), 1000),
            (lineage_exec(38_111, 38_110, 38_110, runc, 200), 1000),
            (lineage_exec(38_112, 38_111, 38_111, runc, 300), 1000),
            // a session's shell running runc; a child of runc that ran bash
            (lineage_exec(38_120, 1, 1, bash, 100), 0),
            (lineage_exec(38_121, 38_120, 38_120, runc, 200), 0),
            (lineage_exec(38_122, 38_121, 38_121, runc, 300), 0),
            (lineage_exec(38_103, 38_101, 38_101, bash, 300), 0),
        ] {
            assert!(lineage.ingest_spawn_event(&as_uid(e, uid)));
        }
        let r = R004::new(lineage.clone());
        let gone = RuntimeClone {
            image: runc,
            seen: vec![(38_101, runc)],
            unverified: true,
            gone: true,
            episode: None,
        };
        let judged = |pid: u32, ppid: u32, uid: u32| {
            // runc 1.1: the re-exec (no fork since its last exec), under
            // the runc process the pump saw
            let e = as_uid(memfd_exec(pid, ppid, 0, 400), uid);
            assert!(lineage.ingest_spawn_event(&e));
            keep_runtime_clone(
                &e,
                RuntimeClone {
                    seen: vec![(ppid, runc)],
                    ..gone.clone()
                },
            );
            r.evaluate(&e)
        };
        // root's: recorded High, not killed, "not compared (gone)"
        let v = judged(38_102, 38_101, 0).expect("recorded");
        assert_eq!(
            (v.action.clone(), v.severity),
            (ResponseAction::Log, Severity::High),
            "the verdict's action and severity"
        );
        assert!(
            v.reasoning.contains("not compared (gone)"),
            "the record says 'not compared (gone)'"
        );
        assert!(
            !v.reasoning.contains("budget") && !v.reasoning.contains("copy of"),
            "the record names no budget and vouches for no copy"
        );
        // the review of #588 (F2): runc 1.2's shape (`runc init` executing
        // the copy `runc create` made, its first exec since the fork — the
        // shape of every OCI hook a runtime runs): its length not known, the
        // Critical kill
        let e = memfd_exec(38_106, 38_101, 38_101, 400);
        assert!(lineage.ingest_spawn_event(&e));
        keep_runtime_clone(&e, gone.clone());
        assert!(kills(r.evaluate(&e)), "runc 1.2's shape, gone");
        // ... the same exec compared whole is still runc 1.2's clone
        let e = memfd_exec(38_107, 38_101, 38_101, 400);
        assert!(lineage.ingest_spawn_event(&e));
        keep_runtime_clone(
            &e,
            RuntimeClone {
                image: runc,
                ..Default::default()
            },
        );
        assert!(r.evaluate(&e).is_none(), "runc 1.2's shape, compared");
        // a re-exec gone whose parent the pump did not see run that runtime
        let e = memfd_exec(38_108, 38_101, 0, 400);
        assert!(lineage.ingest_spawn_event(&e));
        keep_runtime_clone(
            &e,
            RuntimeClone {
                seen: vec![(38_100, runc)],
                ..gone.clone()
            },
        );
        assert!(kills(r.evaluate(&e)), "gone, the parent not seen as runc");
        // a user's (rootless, or a payload exiting at once): the kill
        let v = judged(38_112, 38_111, 1000).expect("judged");
        assert_eq!(
            (v.action.clone(), v.severity),
            (ResponseAction::KillProcessTree, Severity::Critical)
        );
        assert!(v.reasoning.contains("not compared (gone)"));
        // CONTROLS (a foreign memfd exec stays Critical, rootful or not):
        // runc run by a session's shell
        assert!(kills(judged(38_122, 38_121, 0)));
        // a process that ran bash, not the runtime, before the memfd
        assert!(kills(judged(38_103, 38_101, 0)));
        // nothing kept (a parent gone, a manager's): the heuristic's kill
        let e = memfd_exec(38_104, 38_101, 0, 400);
        assert!(lineage.ingest_spawn_event(&e));
        assert!(kills(r.evaluate(&e)));
        // the same clone compared whole: no verdict (the 299 others)
        let e = memfd_exec(38_105, 38_101, 38_101, 400);
        assert!(lineage.ingest_spawn_event(&e));
        keep_runtime_clone(
            &e,
            RuntimeClone {
                image: runc,
                ..Default::default()
            },
        );
        assert!(r.evaluate(&e).is_none());
    }

    /// The review of #578 (N3, named): the first uncompared runtime copy of
    /// an episode of a spent compare budget says so in its record — the uid
    /// whose share ran out and the second's biggest spender — root's
    /// recorded High (never killed), any other uid's the Critical kill; the
    /// later ones of the episode carry no such sentence (the previous
    /// test). Fails on 382be007 (no episode in the record, root's killed).
    #[test]
    fn the_first_uncompared_copy_of_an_episode_names_who_spent_the_budget() {
        use crate::decision::rules::program_identity::{
            BudgetEpisode, InstalledImage, RuntimeClone, keep_runtime_clone, record_installed,
        };
        let (runc, shim) = ((0x0fd0_0578, 578_031), (0x0fd0_0578, 578_032));
        for (id, path, kind) in [
            (runc, "/usr/sbin/runc", ProgramKind::ContainerRuntime),
            (
                shim,
                "/usr/bin/containerd-shim-runc-v2",
                ProgramKind::RuntimeManager,
            ),
        ] {
            record_installed(InstalledImage {
                id,
                len: 12_000_000,
                path: path.into(),
                kind,
            });
        }
        let tmp = tempfile::TempDir::new().unwrap();
        let lineage = crate::posture::lineage::AuthSessionTracker::<H>::new(tmp.path());
        for e in [
            lineage_exec(35_640, 1, 1, shim, 100),
            lineage_exec(35_641, 35_640, 35_640, runc, 200),
        ] {
            assert!(lineage.ingest_spawn_event(&e));
        }
        let r = R004::new(lineage.clone());
        let judged = |pid: u32, uid: u32, top: Option<(u32, u64)>| {
            let mut e = memfd_exec(pid, 35_641, 35_641, 400);
            if let Event::ProcessSpawn { uid: u, gid, .. } = &mut e {
                (*u, *gid) = (uid, uid);
            }
            assert!(lineage.ingest_spawn_event(&e));
            keep_runtime_clone(
                &e,
                RuntimeClone {
                    image: runc,
                    seen: Vec::new(),
                    unverified: true,
                    gone: false,
                    episode: Some(BudgetEpisode { uid, top }),
                },
            );
            r.evaluate(&e).expect("judged")
        };
        let v = judged(35_642, 0, Some((1000, 300 << 20)));
        assert_eq!(
            (v.action.clone(), v.severity),
            (ResponseAction::Log, Severity::High),
            "the verdict's action and severity"
        );
        for want in [
            "opened an episode",
            "uid 0's share ran out",
            "biggest spender: uid 1000, 300 MiB",
        ] {
            assert!(v.reasoning.contains(want), "the record says {want}");
        }
        let v = judged(35_643, 1000, None);
        assert_eq!(
            (v.action.clone(), v.severity),
            (ResponseAction::KillProcessTree, Severity::Critical),
            "the verdict's action and severity"
        );
        assert!(
            v.reasoning.contains("uid 1000's share ran out"),
            "the record says 'uid 1000's share ran out'"
        );
        assert!(
            !v.reasoning.contains("biggest spender"),
            "the record does not say \'biggest spender\'"
        );
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

/// Lot 376 (the review of #583, F3): PID 1's executor launch with no
/// identity, told by PID 1's own descriptor.
#[cfg(test)]
mod lot376 {
    use super::*;
    use crate::posture::host::testing::IdTestHost;
    type R004 = R004ExecFromProcSelfFd<IdTestHost>;
    type Tracker = crate::posture::lineage::AuthSessionTracker<IdTestHost>;

    const STAT_DEV: u64 = 64769;
    const KDEV: u64 = common::wire::exe::kernel_dev(STAT_DEV);
    /// The packaged executor, and a file that is not one.
    const EXECUTOR: (u64, u64) = (KDEV, 555);
    const OTHER: (u64, u64) = (KDEV, 556);

    /// The record of the 24.04 reboot: `/proc/self/fd/9`, `ppid` 1, `comm`
    /// `9`, no identity (`exe.flags` 0) — forked by `forker`.
    fn launch(filename: &str, ppid: u32, uid: u32, forker: u32) -> Event {
        Event::ProcessSpawn {
            pid: 1029,
            ppid,
            uid,
            gid: uid,
            comm: "9".to_string(),
            filename: filename.to_string(),
            timestamp_ns: 23_800_000_000,
            argv: vec![
                "/usr/lib/systemd/systemd-executor".to_string(),
                "--deserialize".to_string(),
                "93".to_string(),
            ],
            parent_comm: "systemd".to_string(),
            parent_start_ns: 0,
            start_ns: 23_799_000_000,
            parent_is_kthread: false,
            exe: nn_model::ExeIdentity {
                path: filename.to_string(),
                fork_parent: forker,
                ..Default::default()
            },
            argv_truncated: false,
            filename_truncated: false,
            stdio: Default::default(),
        }
    }

    fn kills(v: Option<Verdict>) -> bool {
        v.is_some_and(|v| {
            v.action == ResponseAction::KillProcessTree && v.severity == Severity::Critical
        })
    }

    /// Named test (the review of #583, F3; the lab of lot 376: R004
    /// Critical ×1 at a reboot of Ubuntu 24.04, `pid 1029 ppid 1 comm "9"
    /// exe /proc/self/fd/9`). With no identity, PID 1's fork running the
    /// executor PID 1 holds as that descriptor is no fileless exec — by the
    /// kernel's fork record and PID 1's own descriptor, never `argv[0]` or
    /// `comm`. A foreign `fexecve` of `/proc/self/fd/N` stays Critical: a
    /// shell's child (another forker), an orphan PID 1 adopted, no fork
    /// record, PID 1's descriptor another file or not readable, a second
    /// exec of the process, a non-root exec, another spelling, no executor
    /// identities known, no lineage.
    #[test]
    fn pid_1_s_executor_launch_without_an_identity_is_told_by_pid_1_s_descriptor() {
        let tmp = tempfile::TempDir::new().unwrap();
        let fd = |n: u32| tmp.path().join("1").join("fd").join(n.to_string());
        IdTestHost::set_file_id(fd(9), Some((STAT_DEV, EXECUTOR.1)));
        IdTestHost::set_file_id(fd(10), Some((STAT_DEV, OTHER.1)));
        let images = ExecutorImages::default();
        images.replace(vec![EXECUTOR]);
        images.replace_pid1_held(vec![EXECUTOR]);
        let lineage = Tracker::new(tmp.path());
        // an earlier process at the pid (another start) executed: not this
        // process's exec
        let mut earlier = launch("/usr/bin/true", 1, 0, 1);
        if let Event::ProcessSpawn {
            timestamp_ns,
            start_ns,
            exe,
            ..
        } = &mut earlier
        {
            (*timestamp_ns, *start_ns) = (1_000_000_000, 900_000_000);
            exe.path = "/usr/bin/true".into();
        }
        assert!(lineage.ingest_spawn_event(&earlier));
        let r = R004::new(lineage.clone()).with_launches(KnownLaunches {
            own_worker: None,
            executor: images.clone(),
        });
        for f in ["/proc/self/fd/9", "/dev/fd/9"] {
            assert!(
                r.evaluate(&launch(f, 1, 0, 1)).is_none(),
                "PID 1's executor launch: {f}"
            );
        }
        // the packaged file's identity alone (not held by PID 1) is one too
        let packaged = ExecutorImages::default();
        packaged.replace(vec![EXECUTOR]);
        let r2 = R004::new(lineage.clone()).with_launches(KnownLaunches {
            own_worker: None,
            executor: packaged,
        });
        assert!(r2.evaluate(&launch("/proc/self/fd/9", 1, 0, 1)).is_none());
        // CONTROLS: Critical, the kill
        for (e, what) in [
            (launch("/proc/self/fd/9", 4444, 0, 4444), "a shell's child"),
            (
                launch("/proc/self/fd/9", 1, 0, 4444),
                "an orphan PID 1 adopted",
            ),
            (
                launch("/proc/self/fd/9", 4444, 0, 1),
                "another parent at the exec",
            ),
            (launch("/proc/self/fd/9", 1, 0, 0), "no fork record"),
            (
                launch("/proc/self/fd/10", 1, 0, 1),
                "PID 1's descriptor another file",
            ),
            (
                launch("/proc/self/fd/11", 1, 0, 1),
                "PID 1's descriptor not read",
            ),
            (launch("/proc/self/fd/9", 1, 1000, 1), "not root"),
            (
                launch("/proc/thread-self/fd/9", 1, 0, 1),
                "another spelling",
            ),
            (launch("/proc/1029/fd/9", 1, 0, 1), "its pid's spelling"),
        ] {
            assert!(kills(r.evaluate(&e)), "{what}");
        }
        // a memfd at PID 1's descriptor (no executor identity): the kill
        IdTestHost::set_file_id(fd(9), Some((0, 77)));
        assert!(
            kills(r.evaluate(&launch("/proc/self/fd/9", 1, 0, 1))),
            "a memfd"
        );
        IdTestHost::set_file_id(fd(9), Some((STAT_DEV, EXECUTOR.1)));
        // no executor identities known, no lineage
        let none = R004::new(lineage.clone());
        assert!(
            kills(none.evaluate(&launch("/proc/self/fd/9", 1, 0, 1))),
            "none known"
        );
        let bare = R004::default().with_launches(KnownLaunches {
            own_worker: None,
            executor: images.clone(),
        });
        assert!(
            kills(bare.evaluate(&launch("/proc/self/fd/9", 1, 0, 1))),
            "no lineage"
        );
        // a second exec of the same process (its first one cached): the kill
        let mut first = launch("/usr/lib/systemd/systemd-executor", 1, 0, 1);
        if let Event::ProcessSpawn {
            timestamp_ns, exe, ..
        } = &mut first
        {
            *timestamp_ns = 23_799_500_000;
            exe.path = "/usr/lib/systemd/systemd-executor".into();
        }
        assert!(lineage.ingest_spawn_event(&first));
        assert!(
            kills(r.evaluate(&launch("/proc/self/fd/9", 1, 0, 1))),
            "a second exec"
        );
        IdTestHost::set_file_id(fd(9), None);
        IdTestHost::set_file_id(fd(10), None);
    }
}
