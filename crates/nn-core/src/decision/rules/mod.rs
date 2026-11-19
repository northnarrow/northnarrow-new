//! Hardcoded rule set: the process rules (R001..R018) and the FIM,
//! canary, network and chain families.

use std::sync::Arc;

use nn_model::{Event, ResponseAction, Severity, Verdict};
use parking_lot::Mutex;

use self::net::DnsBurstWindow;
use super::Rule;
use crate::config::comm_allowlist::CommAllowlist;
use crate::decision::host::DecisionHost;
use crate::net::blocklist::{Ja3Blocklist, NetBlocklist};
use crate::posture::host::{PostureAgent, PostureHost};

pub mod anti_tamper;
pub mod bpf;
pub mod canary;
pub mod chain;
/// Lab PR 219: the exploit post-condition guard's rules (issued outside
/// the engine, like `anti_tamper`).
pub mod epg;
pub mod evasion;
pub mod impact;
pub mod iouring;
/// Lot 279: what the exec pump read of a module tool's exec (R011).
pub mod kmod_exec_facts;
/// Lot 279: what a module tool's exec asks for, by its syntax (R011).
pub mod kmod_invocation;
pub mod module_provenance;
pub mod net;
pub mod net_fanout;
/// Lot 275: NN-L-NET-028, "no DNS, no connect".
pub mod net_nodns;
/// Lot 313: shells, interpreters and busybox by what the kernel executed;
/// the rules' one place for their names.
pub mod program_identity;
mod r001_exec_from_tmp;
mod r002_exec_from_dev_shm;
mod r003_exec_from_var_tmp;
mod r004_exec_from_proc_self_fd;
mod r005_netcat_exec;
mod r006_reverse_shell_tooling;
mod r007_crypto_miner;
mod r008_hidden_home_binary;
mod r009_root_exec_from_user_path;
mod r010_binary_in_webroot;
mod r011_kernel_module_tooling;
mod r012_setcap_tooling;
mod r013_namespace_escape_tooling;
mod r014_at_batch_scheduling;
mod r015_encoding_tooling_service_uid;
mod r016_debugger_service_uid;
mod r017_shell_from_nonstandard_path;
mod r018_kernel_module_load;
pub mod r020_shell_with_socket_stdio;
pub mod transfer_tools;

#[cfg(feature = "demo-tappa5")]
pub mod test_actions;

/// World-writable staging directories a dropper runs from: the one set
/// NN-L-NET-008, NN-L-CHAIN-002 (and through its precursor CHAIN-005/007)
/// and the posture's exec arm judge an image by.
///
/// External audit NETR-008: each of them used to check `/tmp/` only (the
/// posture `/tmp/` and `/dev/shm/`), so a payload staged in `/dev/shm` or
/// `/var/tmp` evaded the network correlation. `/run/user/` and home
/// directories stay out: user services and confined packages run from them.
pub const STAGING_PREFIXES: &[&str] = &["/tmp/", "/var/tmp/", "/dev/shm/"];

/// `true` when `path` lies under one of [`STAGING_PREFIXES`].
pub fn is_staging_path(path: &str) -> bool {
    STAGING_PREFIXES.iter().any(|p| path.starts_with(p))
}

/// Lot 355: the path the staging rules judge an exec by — the file the
/// kernel executed (review 61), or the caller's string without it — or
/// `None` for a file of a user's program image
/// (`exe_flags::USER_IMAGE`: an AppImage's, served read-only at its
/// runtime's `/tmp/.mount_*`), which is judged as that image is, never as
/// staged in its mount point's directory. The one reading of an exec's
/// image the staging rules use (R001..R003, the chains' staging
/// precursor, the posture's exec arm; `xtask/tests/staged_images.rs`).
pub fn staging_judged_path<'a>(
    exe: &'a nn_model::ExeIdentity,
    filename: &'a str,
) -> Option<&'a str> {
    (!exe.has(common::wire::exe::exe_flags::USER_IMAGE)).then(|| exe.path_or(filename))
}

/// Lot 355: the exec ran a staged image — [`staging_judged_path`] under
/// one of [`STAGING_PREFIXES`].
pub fn is_staged_exec(exe: &nn_model::ExeIdentity, filename: &str) -> bool {
    staging_judged_path(exe, filename).is_some_and(is_staging_path)
}

/// The review of #578 (P3): what the dynamic loader does with a file it
/// was given for an exec ([`loader_code`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LoaderUse {
    /// It runs the file's code: the program, a preload, an auditing
    /// library — and (the re-check of #578, R1-1) a program glibc's loader
    /// only lists that names a library for auditing, as the exec pump read
    /// it: that library runs, the program's own code when it names itself.
    Runs,
    /// It runs none of the file's code, and the agent knows why (the words):
    /// `--verify` (checked, nothing loaded); musl's loader listing it
    /// (`--list`, or run as `ldd`). Round 3 of #578 (R2-1): never glibc's
    /// list or trace mode for a staged file — the code that has run can
    /// make the pump read another file than the one the loader mapped, so
    /// that is [`LoaderUse::MayRun`].
    Lists(&'static str),
    /// The re-check of #578 (R1-1): it only lists or checks the file as far
    /// as its arguments and environment say, and the agent cannot tell that
    /// it runs none of its code (the words): glibc's list or trace mode for
    /// a program the pump could not read — a library it names for auditing
    /// would run — or a loader that is not the system's. Recorded, never
    /// killed, never said to run nothing.
    MayRun(&'static str),
}

impl LoaderUse {
    /// The order a rule judges a loader's files in: one it runs first, then
    /// one it may run, then one it only lists.
    pub fn rank(self) -> u8 {
        match self {
            LoaderUse::Runs => 2,
            LoaderUse::MayRun(_) => 1,
            LoaderUse::Lists(_) => 0,
        }
    }
}

/// Lot 370 (05-3.3): the files the dynamic loader runs or loads for an exec
/// of it — its program operand, and the libraries `--preload` and `--audit`
/// name — as the caller wrote them, each with what the loader does with it
/// ([`LoaderUse`]); none for an exec that is not the loader's (by identity
/// or name, as lot 313 reads it), or one in which it runs no program
/// (`--help`, …). The staging rules judged only the image the kernel
/// executed — the loader, in `/lib` — so `ld-linux-x86-64.so.2 /tmp/x` ran a
/// staged program unjudged, and `ld.so /proc/self/fd/3` fileless code.
///
/// The review of #578 (P3) and its re-check (R1-1): the program and its
/// preloads are only listed or checked — `--list`, `--verify`;
/// `LD_TRACE_LOADED_OBJECTS` in its environment as the exec pump read it
/// ([`exe_flags::LOADER_LISTS`]); musl's loader run as `ldd`; or `listing`:
/// the exec's parent runs the system's `ldd` script ([`LoaderListing`]) —
/// and what that means is told by whose loader it is
/// ([`program_identity::system_loader`]):
/// - glibc's: `--verify` (the last of `--list` and `--verify`) loads
///   nothing; its list and trace modes still load and run the libraries the
///   program names for auditing (`DT_AUDIT`, `DT_DEPAUDIT`: verified on
///   2.39, the program's own constructor when it names itself) — so the
///   program is run when the exec pump read it naming one
///   ([`exe_flags::LOADER_AUDITS`]) and may run otherwise — never listed
///   (round 3, R2-1: what the pump read can be made false);
/// - musl's: `--list` and `ldd` list; it reads no `LD_TRACE_LOADED_OBJECTS`
///   and runs the program then;
/// - a loader that is not the system's (a copy, a name): may run.
///
/// An auditing library `--audit` names runs in every mode.
///
/// [`exe_flags::LOADER_LISTS`]: common::wire::exe::exe_flags::LOADER_LISTS
/// [`exe_flags::LOADER_AUDITS`]: common::wire::exe::exe_flags::LOADER_AUDITS
pub fn loader_code(event: &Event, listing: bool) -> Vec<(&str, LoaderUse)> {
    let Event::ProcessSpawn { argv, .. } = event else {
        return Vec::new();
    };
    if program_identity::loader_operand_at(event).is_none() {
        return Vec::new();
    }
    // the one reader of the loader's options (`posture::script_args`)
    let code = crate::posture::script_args::loader_code(argv);
    let program = program_use(event, &code, listing);
    code.runs
        .into_iter()
        .map(|p| (p, program))
        .chain(code.audits.into_iter().map(|p| (p, LoaderUse::Runs)))
        .collect()
}

/// The re-check of #578 (R1-1): what the loader of `event` does with its
/// program and preloads ([`loader_code`]).
fn program_use(
    event: &Event,
    code: &crate::posture::script_args::LoaderCode<'_>,
    listing: bool,
) -> LoaderUse {
    use common::wire::exe::exe_flags::{LOADER_AUDITS, LOADER_LISTS};
    use program_identity::SystemLoader;
    let Event::ProcessSpawn { exe, .. } = event else {
        return LoaderUse::Runs;
    };
    // `ldd`'s trace mode: the environment's, or the system's script running it
    let traced = listing || exe.has(LOADER_LISTS);
    let musl_ldd = program_identity::musl_ldd(event);
    if !code.lists && !traced && !musl_ldd {
        return LoaderUse::Runs;
    }
    match program_identity::system_loader(event) {
        None => LoaderUse::MayRun("a loader that is not the system's: what it runs is not known"),
        Some(SystemLoader::Musl) if code.lists || musl_ldd => {
            LoaderUse::Lists("musl's loader lists it (--list or as ldd)")
        }
        // musl reads no LD_TRACE_LOADED_OBJECTS: it runs the program
        Some(SystemLoader::Musl) => LoaderUse::Runs,
        Some(SystemLoader::Glibc) if code.verifies => {
            LoaderUse::Lists("--verify: the loader checks it and exits before loading any library")
        }
        Some(SystemLoader::Glibc) if exe.has(LOADER_AUDITS) => LoaderUse::Runs,
        // an auditing library is code in the loader's process: whatever it
        // is, the program is not said to run nothing beside it
        Some(SystemLoader::Glibc) if !code.audits.is_empty() => LoaderUse::MayRun(
            "glibc's list or trace mode with an auditing library given: it runs beside the \
             program",
        ),
        Some(SystemLoader::Glibc) => LoaderUse::MayRun(
            "glibc's list or trace mode for a staged program: a library it names for auditing \
             runs even then, and the file the agent read can have changed or been swapped \
             after the loader read it",
        ),
    }
}

/// The review of #578 (P3): glibc's `ldd`, a shell script, runs the loader
/// in its trace mode (`LD_TRACE_LOADED_OBJECTS=1 <loader> <file>`): it maps
/// the file and its libraries and runs none of their code (its relocation
/// checks, `-d` and `-r`, call no resolver of the program). That loader's
/// process is gone in a millisecond, often before the pump reads its
/// environment; its parent — the script's subshell, which the lineage's
/// judgement knows by the script's exec — tells it: a shell in a root-owned
/// system tree running the system's `ldd` script, its environment loading
/// no code into it (else what it runs is not known: never). Without a
/// lineage (tests, the boot-time rule set): never.
#[derive(Clone, Default)]
pub struct LoaderListing(Option<LddCheck>);

/// [`LoaderListing`]'s predicate: the exec's parent runs the system's `ldd`.
type LddCheck = Arc<dyn Fn(&Event) -> bool + Send + Sync>;

impl LoaderListing {
    /// The predicate, on `lineage`.
    pub fn of<H: DecisionHost>(lineage: crate::posture::lineage::AuthSessionTracker<H>) -> Self {
        LoaderListing(Some(Arc::new(move |event: &Event| {
            let Event::ProcessSpawn { pid, .. } = event else {
                return false;
            };
            lineage
                .parent_identity(*pid, crate::posture::lineage::AsOf::of_event(event))
                .is_some_and(|id| runs_the_ldd_script(&id))
        })))
    }

    /// A predicate given as is (tests).
    #[cfg(any(test, feature = "test-util"))]
    pub fn of_fn(f: impl Fn(&Event) -> bool + Send + Sync + 'static) -> Self {
        LoaderListing(Some(Arc::new(f)))
    }

    /// `event`, an exec of the loader, was run by the system's `ldd`.
    pub fn lists(&self, event: &Event) -> bool {
        self.0.as_ref().is_some_and(|f| f(event))
    }
}

impl std::fmt::Debug for LoaderListing {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(if self.0.is_some() {
            "LoaderListing(lineage)"
        } else {
            "LoaderListing(none)"
        })
    }
}

/// The review of #578 (P3): `id` is a shell running the system's `ldd`
/// script ([`program_identity::runs_the_ldd_script`]).
pub fn runs_the_ldd_script(id: &crate::posture::lineage::ExecIdentity) -> bool {
    program_identity::runs_the_ldd_script(id)
}

/// The review of #578 (N1): where a file the dynamic loader was given for
/// an exec lies, as the staging rules judge it ([`placed`]).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Placement {
    /// A linked file at this absolute path, folded.
    File(String),
    /// A memfd, or an unlinked file (its name): fileless code, as R004
    /// judges a direct exec of one.
    Fileless(String),
}

/// Lot 370 (05-3.3): where a file [`loader_code`] names lies, for the
/// staging rules — `None` when it cannot be placed. A name through a link
/// of `/proc` (`/proc/self/root/…`, `/proc/<pid>/cwd/…`, `/proc/self/fd/N`,
/// `/dev/fd/N` and their kin: [`crate::posture::proc_link`]) is placed only
/// by the kernel's identity of the file the loader maps, as the exec pump
/// found it ([`program_identity::loader_file`]): the review of #578 (N1) —
/// as text, `/proc/self/root/tmp/x` was absolute, under no staging
/// directory and no descriptor, and no rule judged it. Any other absolute
/// name is folded as the text shows it (no `..`); a relative one (the
/// caller's directory is not in the event) or a climbing one is not placed.
pub fn placed(event: &Event, path: &str) -> Option<Placement> {
    if crate::posture::proc_link::through_proc_link(path) {
        return program_identity::loader_file(event, path).map(|f| {
            if f.memfd || f.deleted {
                Placement::Fileless(f.path)
            } else {
                Placement::File(f.path)
            }
        });
    }
    path.starts_with('/')
        .then(|| crate::posture::proc_link::lexical_form(path))
        .flatten()
        .map(Placement::File)
}

/// The review of #578 (N1): `path` goes through a link of `/proc` — what
/// the exec pump places by the kernel's identity ([`placed`]).
pub fn through_proc_link(path: &str) -> bool {
    crate::posture::proc_link::through_proc_link(path)
}

/// The review of #578 (N1): the one reading of such a name's parts, for the
/// exec pump to open it in the process's own view.
pub use crate::posture::proc_link::{view_link, Hop, ViewLink, Who};

/// The re-check of #578 (R1-2): where the exec pump found a file the loader
/// was given by a name NOT through a link of `/proc` — an absolute or a
/// relative one, walked in the process's view as the kernel walks it, its
/// symbolic links followed (`/usr/tmp` is `../var/tmp` on the RHEL family),
/// and found among the files the process maps: the kernel's identity of the
/// file the loader maps. It only adds to [`placed`]: the text's own reading
/// is judged beside it, and a name the text cannot place stays recorded.
pub fn pump_placement(event: &Event, path: &str) -> Option<Placement> {
    if through_proc_link(path) {
        return None;
    }
    program_identity::loader_file(event, path).map(|f| {
        if f.memfd || f.deleted {
            Placement::Fileless(f.path)
        } else {
            Placement::File(f.path)
        }
    })
}

/// Every place a file [`loader_code`] names is known to lie in: its
/// [`placed`] reading, and the pump's [`pump_placement`] when it is another.
pub fn placements(event: &Event, path: &str) -> Vec<Placement> {
    let mut out: Vec<Placement> = placed(event, path).into_iter().collect();
    if let Some(p) = pump_placement(event, path) {
        if !out.contains(&p) {
            out.push(p);
        }
    }
    out
}

/// Lot 370 (05-3.3): a file the loader runs or lists for this exec under
/// `prefix` (a staging directory), placed ([`placements`]), and what the
/// loader does with it — one it runs first, then one it may run.
pub fn loader_staged(event: &Event, prefix: &str, listing: bool) -> Option<(String, LoaderUse)> {
    let mut found: Option<(String, LoaderUse)> = None;
    for (text, use_) in loader_code(event, listing) {
        for place in placements(event, text) {
            if let Placement::File(p) = place {
                if p.starts_with(prefix) && found.as_ref().is_none_or(|f| f.1.rank() < use_.rank())
                {
                    found = Some((p, use_));
                }
            }
        }
    }
    found
}

/// The review of #578 (P3) and its re-check (R1-1): the record of a staged
/// file the loader only lists or checks — never a kill — from the staging
/// rule whose directory it lies in: Low when the agent knows the loader
/// runs none of its code ([`LoaderUse::Lists`], saying why), Medium when it
/// cannot tell ([`LoaderUse::MayRun`], saying why). `None` for a file it
/// runs: the rule's own verdict.
pub(crate) fn loader_listed_record(
    rule: &dyn Rule,
    event: &Event,
    dir: &str,
    p: &str,
    use_: LoaderUse,
) -> Option<Verdict> {
    let (severity, text) = match use_ {
        LoaderUse::Runs => return None,
        LoaderUse::Lists(why) => (
            Severity::Low,
            format!(
                "A program in {dir} only listed or checked by the dynamic loader ({p}: {why}) — \
                 in that mode the loader runs no code of it; recorded Low, not killed"
            ),
        ),
        LoaderUse::MayRun(why) => (
            Severity::Medium,
            format!(
                "A program in {dir} given to the dynamic loader to list or check ({p}: {why}) — \
                 it may still run code; recorded, not killed"
            ),
        ),
    };
    Some(build_verdict(
        rule,
        event,
        ResponseAction::Log,
        severity,
        &text,
    ))
}

/// Lot 369: what the packaged `go` itself built and then runs, as the
/// staging rules R001 and R003 record it (decision 283b held a person's exec
/// from `/tmp` at High below COMBAT): `go test`'s test binary and `go run`'s
/// program. The review of #576 (F1): every fact of the identity, not the
/// layout and the forker alone —
/// - the file is the output the packaged toolchain's own linker
///   (`<GOROOT>/pkg/tool/<os>_<arch>/link`, as lot 346 identifies `go`: a
///   root-only system tree, its exec's image seen, run as itself) was run
///   to write, by the very `go` process that runs it now
///   ([`crate::posture::lineage::AuthSessionTracker::runs_go_linked_output`]);
/// - it lies in that `go`'s work directory's layout
///   (`<TMPDIR>/go-build<digits>/b<digits>/<name>` or `…/exe/<name>`), and
///   the kernel ran it by its path (`KNOWN`), not unlinked nor a memfd;
/// - the account is a person's ([`crate::decision::host::AccountKind::Human`]:
///   `UID_MIN` and up with a login shell) — what `go` builds is then the
///   user's own code, as `go build && ./prog` from a home, which no staging
///   rule judges. Root and a service account (`www-data`'s web shell with
///   `go run`), whose `/tmp` is the staging path R001 and R003 exist for:
///   judged as before.
///
/// What `go` merely launches — a `-vettool`, an `-exec` wrapper, a
/// `-toolexec` program, a `go generate` command, a file another process
/// dropped in a `go-build` directory — and the same file run from a shell,
/// by another parent or by a `go` in a home: judged as before. Without a
/// lineage (tests, the boot-time rule set): never. Lot 372: the linker's
/// output also read from an argv the sensor cut (Go 1.21 and later pass a
/// long `-X=runtime.godebugDefault=…`), in the `go` command's own shape
/// only ([`crate::posture::script_args::go_link_output`]).
#[derive(Clone, Default)]
pub struct GoBuilds(Option<GoBuildCheck>);

/// Lot 369: [`GoBuilds`]'s predicate: `pid`'s exec of `image` as uid `uid`,
/// as of the time given, is the packaged `go`'s own build output, run by
/// that `go`, for a person's account.
type GoBuildCheck =
    Arc<dyn Fn(u32, u32, crate::posture::lineage::AsOf, &str) -> bool + Send + Sync>;

impl GoBuilds {
    /// The predicate, on `lineage` and the host's accounts.
    pub fn of<H: DecisionHost>(lineage: crate::posture::lineage::AuthSessionTracker<H>) -> Self {
        GoBuilds(Some(Arc::new(move |pid, uid, as_of, image| {
            H::account_kind(uid) == crate::decision::host::AccountKind::Human
                && lineage.runs_go_linked_output(pid, as_of, image)
        })))
    }

    /// A predicate given as is (tests).
    #[cfg(any(test, feature = "test-util"))]
    pub fn of_fn(
        f: impl Fn(u32, u32, crate::posture::lineage::AsOf, &str) -> bool + Send + Sync + 'static,
    ) -> Self {
        GoBuilds(Some(Arc::new(f)))
    }

    /// `event`, an exec of `image` the kernel ran by its path, is the
    /// packaged `go`'s own build output, run by it, for a person.
    pub fn runs(&self, event: &Event, image: &str) -> bool {
        use common::wire::exe::exe_flags::{DELETED, KNOWN, MEMFD};
        let Event::ProcessSpawn {
            pid,
            uid,
            exe,
            timestamp_ns,
            ..
        } = event
        else {
            return false;
        };
        if !exe.has(KNOWN) || exe.has(DELETED) || exe.has(MEMFD) || exe.path_or("") != image {
            return false;
        }
        self.0.as_ref().is_some_and(|f| {
            f(
                *pid,
                *uid,
                crate::posture::lineage::AsOf::judged(*timestamp_ns),
                image,
            )
        })
    }
}

impl std::fmt::Debug for GoBuilds {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(if self.0.is_some() {
            "GoBuilds(lineage)"
        } else {
            "GoBuilds(none)"
        })
    }
}

/// Lot 369: the record of an exec [`GoBuilds::runs`] vouches for — Low, not
/// killed, in every posture (the kill floor of decision 283b holds kills
/// only: a record left as it is).
pub(crate) fn go_build_record(rule: &dyn Rule, event: &Event, dir: &str) -> Verdict {
    build_verdict(
        rule,
        event,
        ResponseAction::Log,
        Severity::Low,
        &format!(
            "Process executed from {dir} — the packaged go's own build output in its work \
             directory (go test's test binary, go run's program): written by that go's own \
             linker, run by that go, for a person's account — the user's code as go build and \
             ./prog from a home — recorded Low, not killed (lot 369)"
        ),
    )
}

/// Lab PR 166: the kill of the tool rules R011..R013 for an exec of
/// `image`. A copy run from a staging directory is the payload itself, as
/// for R001..R003, which those rules outrank (PROC-009): its tree, so a
/// dropper named like a system tool does not keep its forked children.
/// Anywhere else the tool keeps the single-process kill.
pub(crate) fn tool_kill(image: &str) -> ResponseAction {
    if is_staging_path(image) {
        ResponseAction::KillProcessTree
    } else {
        ResponseAction::KillProcess
    }
}

/// `nobody`, the kernel's overflow uid: what NFS squashing, `sudo -u
/// nobody` and daemons that drop to it run as.
pub(crate) const NOBODY_UID: u32 = 65_534;

/// systemd's range for the transient accounts of `DynamicUser=yes` units
/// (`SYSTEMD_DYNAMIC_UID_MIN..=SYSTEMD_DYNAMIC_UID_MAX`, systemd's
/// "Users, Groups, UIDs and GIDs on systemd systems").
pub(crate) const DYNAMIC_USER_UIDS: std::ops::RangeInclusive<u32> = 61_184..=65_519;

/// External audit PROC-012: the service-account uid class of R015 and
/// R016 — an account no human logs in as, whose use of an encoder or a
/// debugger is the anomaly those rules record.
///
/// - 1..=999: the system accounts below `UID_MIN` (`/etc/login.defs`),
///   `www-data`, `mysql`, `_apt` and the like.
/// - [`NOBODY_UID`] and [`DYNAMIC_USER_UIDS`]: service accounts above
///   `UID_MIN`. Both rules stopped at 1000, so a web shell under a
///   `nobody` worker or a hardened `DynamicUser=yes` unit was never
///   judged.
///
/// Not in the class:
/// - root (0), whose encoder and debugger use is routine administration;
/// - 1000..=60000, the human accounts, and systemd-homed's 60001..=60513;
/// - the sub-uid ranges of `/etc/subuid` (100000 and up by default) and
///   the container ranges of `systemd-nspawn` (524288 and up). A rootless
///   container's uids belong to the human who owns the range (`podman
///   unshare` and `newuidmap` let that user become any of them), so they
///   carry that user's standing, not a daemon's; and from the host's uid
///   alone a container's daemon is not told apart from its root or its
///   users.
pub(crate) fn is_service_uid(uid: u32) -> bool {
    (1..1000).contains(&uid) || uid == NOBODY_UID || DYNAMIC_USER_UIDS.contains(&uid)
}

pub use r001_exec_from_tmp::R001ExecFromTmp;
pub use r002_exec_from_dev_shm::R002ExecFromDevShm;
pub use r003_exec_from_var_tmp::R003ExecFromVarTmp;
pub use r004_exec_from_proc_self_fd::{
    ExecutorImages, KnownLaunches, OwnWorkerLaunch, R004ExecFromProcSelfFd,
};
pub use r005_netcat_exec::R005NetcatExec;
pub use r006_reverse_shell_tooling::R006ReverseShellTooling;
pub use r007_crypto_miner::R007CryptoMiner;
pub use r008_hidden_home_binary::R008HiddenHomeBinary;
pub use r009_root_exec_from_user_path::R009RootExecFromUserPath;
pub use r010_binary_in_webroot::R010BinaryInWebroot;
pub use r011_kernel_module_tooling::R011KernelModuleTooling;
pub use r012_setcap_tooling::R012SetcapTooling;
pub use r013_namespace_escape_tooling::R013NamespaceEscapeTooling;
pub use r014_at_batch_scheduling::R014AtBatchScheduling;
pub use r015_encoding_tooling_service_uid::R015EncodingToolingServiceUid;
pub use r016_debugger_service_uid::R016DebuggerServiceUid;
pub use r017_shell_from_nonstandard_path::R017ShellFromNonstandardPath;
pub use r018_kernel_module_load::R018KernelModuleLoad;
pub use r020_shell_with_socket_stdio::R020ShellWithSocketStdio;

/// Build the default rule set in evaluation order. The process rules
/// are ordered by [`spawn_rules`]: every kill before any record. The
/// Tappa 9 FIM rules
/// (NN-L-FIM-001..014) APPEND at the bottom since they match on
/// `Event::Fim` rather than `Event::ProcessSpawn` — the first-match
/// short-circuit never affects them. Tappa 9.5 K5 canary rules
/// (NN-L-CANARY-001..004) APPEND after the FIM rules — they match
/// on `Event::CanaryTripped`, so they're independent of both the
/// process + FIM rule families. K3 detector precedence guarantees
/// canary events never co-occur with FIM events for the same
/// inode (§12 Q9 inline-filter lock-in).
///
/// External audit PROC-014 (NN-AUD-429): the families, and their order,
/// are those of [`default_rules_with_net`], the production builder — the
/// io_uring (NN-L-IOU-001/002) and BPF (NN-L-BPF-001/002) rules included,
/// which only the production builder used to register, so no engine test
/// saw them. `decision/tests.rs` holds the two builders to one id
/// sequence.
pub fn default_rules<H: DecisionHost>() -> Vec<Box<dyn Rule>> {
    // Tappa 10.5 (D5) — chain rules go FIRST so they OBSERVE precursor
    // events (recording + returning None, falling through to the
    // firing rule) before a first-match short-circuits the scan, and
    // so a correlated flow surfaces the Critical chain verdict ahead
    // of any lower-severity net rule. See `chain.rs` module docs.
    let chains = chain::chain_rule_set::<H>();
    let mut rules: Vec<Box<dyn Rule>> = chains.head;
    // The process rules (R001..R017), with an empty allowlist; the
    // production main.rs path constructs its engine via
    // [`default_rules_with_net`] instead, threading the operator-loaded
    // process-comm allowlist in.
    let process_allowlist = Arc::new(CommAllowlist::<H>::default());
    rules.extend(spawn_rules(
        Arc::clone(&process_allowlist),
        None,
        KnownLaunches::default(),
        None,
    ));
    rules.extend(module_load_rules::<H>());
    // External audit PROC-014: the io_uring and BPF rules, over the same
    // empty process allowlist (their built-in known programs still apply).
    rules.extend(iouring::iouring_rules(Arc::clone(&process_allowlist)));
    rules.extend(bpf::bpf_rules(process_allowlist));
    // FIM-009 self-upgrade (§15.1): the non-production rule set has no
    // admin dispatcher to arm an override, so FIM-009 gets an inert one
    // (never armed → unchanged KillProcess behaviour).
    rules.extend(crate::fim::rules::fim_rules::<H>(
        H::inert_installer_window(),
    ));
    // Lab PR 225: the ransomware and security-tool rules, over a live
    // `/proc`-backed lineage, the host's package database and the shipped
    // list.
    let lineage = crate::posture::lineage::AuthSessionTracker::<H>::with_proc();
    rules.extend(impact::impact_rules(Arc::new(
        crate::impact::RansomTracker::new(lineage.clone()),
    )));
    rules.extend(evasion::evasion_rules(Arc::new(
        crate::impair::DefenseDetector::new(
            Arc::new(crate::impair::SecurityTools::builtin()),
            lineage,
            None,
        ),
    )));
    rules.extend(canary::canary_rules::<H>());
    // Tappa 10 (N6) — 9 NN-L-NET rules with empty boot
    // blocklists. The production agent main.rs path constructs
    // its engine via [`default_rules_with_net`] instead, threading
    // operator-loaded blocklists in.
    rules.extend(net::net_rules_empty::<H>());
    // Informational chains (NN-L-CHAIN-008) go LAST so their Log
    // verdict never shadows a blocking rule on the same event.
    rules.extend(chains.tail);
    rules
}

/// Tappa 10 N9 / Tappa 10.5 D2 — production builder. Same shape as
/// [`default_rules`] but threads operator-loaded state in: the
/// blocklists into the 9 NN-L-NET rules (N9) and the process-comm
/// allowlist into R006, R007 and R011..R017 (D2, PROC-010). `main.rs`
/// calls this once at boot after loading
/// `/etc/northnarrow/netflow-blocklist.{v1,local}` +
/// `netflow-ja3-blocklist.{v1,local}` +
/// `process-comm-allowlist.{v1,local}` from disk.
#[allow(clippy::too_many_arguments)]
pub fn default_rules_with_net<H: DecisionHost>(
    blocklist: Arc<NetBlocklist>,
    ja3_blocklist: Arc<Ja3Blocklist>,
    burst_window: Arc<Mutex<DnsBurstWindow>>,
    process_allowlist: Arc<CommAllowlist<H>>,
    netflow_comm_allowlist: Arc<CommAllowlist<H>>,
    beacon_window: Arc<Mutex<net::BeaconWindow>>,
    dns_cache: Arc<crate::net::dns_cache::DnsCache<H::DnsIngest>>,
    // FIM-009 self-upgrade (§15.1): the live trusted-installer override
    // the NN-L-FIM-009 rule reads (armed by the admin dispatcher).
    installer_override: Arc<<H as PostureAgent>::InstallerWindow>,
    // Review 49: the shared process-lineage cache — package-manager
    // writes are recorded, not killed, by the wrapped FIM rules.
    lineage: crate::posture::lineage::AuthSessionTracker<H>,
    // External audit DEC-005: the readers of whole trees the File and
    // Credential canary rules record instead of killing.
    canary_readers: crate::canary::readers::CanaryReaders<H>,
    // External audit NET-019: the chain rules' correlation store, shared
    // with the netflow limiter.
    correlation: Arc<Mutex<crate::decision::correlation::CorrelationStore<H>>>,
    // Lab PR 224: the configured resolvers and the fan-out thresholds.
    net_config: net::NetRuleConfig,
    // Lab PR 225: the ransomware tracker and the security-tool detector the
    // posture shares.
    ransom: Arc<crate::impact::RansomTracker<H>>,
    defense: Arc<crate::impair::DefenseDetector<H>>,
    // R14a: how the agent starts its own workers (R004 knows the launch);
    // lot 310: and systemd's executor, by its identities.
    launches: KnownLaunches,
) -> Vec<Box<dyn Rule>> {
    // Tappa 10.5 (D5) — chain rules FIRST (see `default_rules` +
    // the chain.rs module docs for the ordering rationale).
    let chains = chain::chain_rule_set_full(
        Arc::clone(&correlation),
        Some(lineage.clone()),
        Arc::clone(&net_config.resolvers),
    );
    let mut rules: Vec<Box<dyn Rule>> = chains.head;
    // External audit NETR-003 class: the process allowlist judged on what
    // the kernel executed — from the exec event itself for R006, R007 and
    // R011..R017, through the lineage cache for the io_uring and BPF rules
    // and for the actors of R011..R017 (external audit PROC-008).
    let process_allowlist = Arc::new(
        process_allowlist
            .as_ref()
            .clone()
            .with_identity(lineage.clone()),
    );
    rules.extend(spawn_rules(
        Arc::clone(&process_allowlist),
        Some(lineage.clone()),
        launches,
        Some(Arc::clone(&installer_override)),
    ));
    rules.extend(module_load_rules::<H>());
    rules.extend(iouring::iouring_rules(Arc::clone(&process_allowlist)));
    rules.extend(bpf::bpf_rules(process_allowlist));
    rules.extend(crate::fim::rules::fim_rules_with_lineage(
        installer_override,
        lineage.clone(),
    ));
    rules.extend(impact::impact_rules(ransom));
    rules.extend(evasion::evasion_rules(defense));
    rules.extend(canary::canary_rules_with_readers(canary_readers));
    // External audit NET-010 (NN-AUD-006): the network allowlist judged on
    // what the kernel executed, not on comm. Lab PR 224 (CM-02 d): its
    // transfer tools exempt only while their lineage holds no precursor.
    let netflow_comm_allowlist = Arc::new(
        netflow_comm_allowlist
            .as_ref()
            .clone()
            .with_identity(lineage.clone())
            .with_conditional(
                transfer_tools::TRANSFER_TOOLS,
                transfer_tools::precursor_check(Arc::clone(&correlation), lineage.clone()),
            ),
    );
    rules.extend(net::net_rules(
        blocklist,
        ja3_blocklist,
        burst_window,
        netflow_comm_allowlist,
        beacon_window,
        dns_cache,
        Some(lineage.clone()),
        net_config,
        Some(correlation),
    ));
    // Informational chains (NN-L-CHAIN-008) go LAST so their Log
    // verdict never shadows a blocking rule on the same event.
    rules.extend(chains.tail);
    rules
}

/// External audit NETR-003 class (the allowlists keyed on `comm`, which a
/// process sets for itself with `prctl(PR_SET_NAME)`): the operator
/// allowlist judged on what the kernel executed for an exec event — its
/// resolved path, and the script an interpreter runs.
pub(crate) fn judge_spawn<H: PostureHost>(
    allowlist: &CommAllowlist<H>,
    event: &Event,
) -> crate::config::comm_allowlist::Judgement {
    let (comm, filename, exe, argv): (&str, &str, &nn_model::ExeIdentity, &[String]) = match event {
        Event::ProcessSpawn {
            comm,
            filename,
            exe,
            argv,
            ..
        } => (comm, filename, exe, argv),
        Event::ExecCheck {
            comm,
            filename,
            exe,
            ..
        } => (comm, filename, exe, &[]),
        _ => {
            return crate::config::comm_allowlist::Judgement::Denied { claimed: false };
        }
    };
    let id = crate::posture::lineage::ExecIdentity::of_exec(exe.path_or(filename), argv);
    allowlist.judge_exec(&id, comm)
}

/// External audit EBPF-021: what a rule that reads `argv` adds to its
/// reasoning when the kernel's command line was cut at `ARGV_LEN - 1`
/// bytes or not read at all. The arguments it looked at are then not all
/// there, so an argument it did not find may be past the cut: filler
/// options in front of it are enough. `None` for a whole argv (and for an
/// older record, which carries no mark).
pub(crate) fn argv_cut_note(event: &Event) -> Option<String> {
    let Event::ProcessSpawn {
        argv,
        argv_truncated: true,
        ..
    } = event
    else {
        return None;
    };
    Some(if argv.is_empty() {
        "argv not read by the kernel: no argument was checked".to_string()
    } else {
        format!(
            "argv truncated at {} bytes: arguments past the cut were not seen",
            common::wire::ARGV_LEN - 1
        )
    })
}

/// [`argv_cut_note`] appended to `reasoning` (`"{reasoning} [{note}]"`).
pub(crate) fn with_argv_cut_note(reasoning: String, event: &Event) -> String {
    match argv_cut_note(event) {
        Some(note) => format!("{reasoning} [{note}]"),
        None => reasoning,
    }
}

/// External audit PROC-008: the response of R011, R012, R013 and R017 to
/// an exec the allowlist did not exempt as the program run. The shipped
/// entries name trusted ACTORS — package managers, configuration
/// management: a root exec of a program in a root-owned system tree with
/// one of them in its lineage ([`CommAllowlist::actor_of`]) is recorded
/// instead of killed, as review 49 and PROC-007 record package
/// transactions (DKMS running `modprobe` under apt).
///
/// The lineage vouches for nothing else: a program outside a system tree
/// (a payload a maintainer script dropped in `/tmp`), or an exec by
/// another uid (a pager's shell under a user's `apt changelog`), is
/// judged as before. R014..R016 only record; they need no actor.
pub(crate) fn judge_actor<H: PostureHost>(
    allowlist: &CommAllowlist<H>,
    event: &Event,
    verdict: Verdict,
) -> Verdict {
    if verdict.action == ResponseAction::Log {
        return verdict;
    }
    let Event::ProcessSpawn { pid, uid, .. } = event else {
        return verdict;
    };
    // Lot 313 (BUG-119): the kernel's executed file, never the caller's
    // string (a cut one named `/usr/bin/./././…`)
    if *uid != 0 || !program_identity::exec_in_system_tree(event) {
        return verdict;
    }
    let Some(actor) = allowlist.actor_of(*pid, crate::posture::lineage::AsOf::of_event(event))
    else {
        return verdict;
    };
    Verdict {
        action: ResponseAction::Log,
        reasoning: format!(
            "{} [run under {}, a trusted actor in process-comm-allowlist: recorded, not killed]",
            verdict.reasoning,
            actor.display()
        ),
        ..verdict
    }
}

/// The `Event::ProcessSpawn` rules in evaluation order (first match wins),
/// shared by both builders. External audit PROC-009: every rule that can
/// kill comes before any that only records (and a High record before a
/// Medium one), so a record never stands in for a kill (`/home/u/.x/bash`
/// was R008's Log, not R017's kill), and the specific tool rules come
/// before the staging rules they outrank (`/tmp/insmod` is R011, High,
/// T1547.006 — it was R001, Medium).
///
/// - R004 (fileless, Critical) and R007's exact names (Critical) lead.
/// - R009 stays ahead of the staging rules: its record of an
///   administrator's session or a package transaction (PROC-007) is a
///   deliberate exception to them.
/// - R006 records only the distribution's `socat` (`/usr/bin`, `/bin`,
///   `/usr/sbin`, `/sbin`), which no later rule kills.
/// - R018 reads `Event::ModuleLoad`; its place does not matter.
///
/// `lineage` (production) lets R004 and R009 read a parent's identity;
/// without it only PID 1 counts as systemd and no session is sanctioned.
/// `installer` (production, lot 278): the trusted-installer window whose
/// installer's own tree R009 records at Low.
fn spawn_rules<H: DecisionHost>(
    allowlist: Arc<CommAllowlist<H>>,
    lineage: Option<crate::posture::lineage::AuthSessionTracker<H>>,
    launches: KnownLaunches,
    installer: Option<Arc<<H as PostureAgent>::InstallerWindow>>,
) -> Vec<Box<dyn Rule>> {
    let r020 = R020ShellWithSocketStdio::new(Arc::clone(&allowlist), lineage.clone());
    let r011_lineage = lineage.clone();
    // lot 313 (the review of #549, F2): the shell socat starts
    let r006_lineage = lineage.clone();
    // lot 350 (F2-3): cloud-init's own netcat on its unix socket
    let r005_lineage = lineage.clone();
    // lot 369: lot 346's identity of the packaged go's own build output
    let go = lineage.clone().map(GoBuilds::of).unwrap_or_default();
    // the review of #578 (P3): the system's ldd running the loader
    let listing = lineage.clone().map(LoaderListing::of).unwrap_or_default();
    let (r004, r009) = match lineage {
        Some(l) => (
            R004ExecFromProcSelfFd::new(l.clone()),
            R009RootExecFromUserPath::new(l).with_installer_window(installer),
        ),
        None => Default::default(),
    };
    // R14a: the agent's own worker launch is not a fileless exec; lot 310:
    // nor systemd's executor left unlinked by an upgrade
    let r004 = r004
        .with_launches(launches)
        .with_loader_listing(listing.clone());
    let al = || Arc::clone(&allowlist);
    vec![
        // Kills (and R009's exceptions).
        Box::new(r004),
        // Lab PR 224 (CM-03): a reverse or bind shell, Critical, ahead of
        // the tool and staging rules a shell copied to /tmp also meets.
        Box::new(r020),
        Box::new(R007CryptoMiner::new(al())),
        Box::new(R006ReverseShellTooling::new(al()).with_lineage(r006_lineage)),
        Box::new(r009),
        Box::new(R010BinaryInWebroot),
        Box::new(R011KernelModuleTooling::new(al()).with_lineage(r011_lineage)),
        Box::new(R012SetcapTooling::new(al())),
        Box::new(R013NamespaceEscapeTooling::new(al())),
        Box::new(R017ShellFromNonstandardPath::new(al())),
        Box::new(R002ExecFromDevShm::default().with_loader_listing(listing.clone())),
        Box::new(
            R001ExecFromTmp::default()
                .with_go_builds(go.clone())
                .with_loader_listing(listing.clone()),
        ),
        Box::new(
            R003ExecFromVarTmp::default()
                .with_go_builds(go)
                .with_loader_listing(listing),
        ),
        // Records, the High ones first.
        Box::new(R005NetcatExec::default().with_lineage(r005_lineage)),
        Box::new(R007CryptoMiner::name_fragments(al())),
        Box::new(R008HiddenHomeBinary),
        Box::new(R014AtBatchScheduling::new(al())),
        Box::new(R015EncodingToolingServiceUid::new(al())),
        Box::new(R016DebuggerServiceUid::new(al())),
    ]
}

/// BUG-034 — the kernel-module LOAD rule (R018). Lot 285: the kernel
/// judges the file the load reads (`common::module_judge`); the rule records
/// what it refused or let through. Its loader allowlist by `comm`
/// (`systemd-udevd`, `systemd-modules`, `kmod`: names any process can take)
/// is gone.
pub fn module_load_rules<H: DecisionHost>() -> Vec<Box<dyn Rule>> {
    vec![Box::new(R018KernelModuleLoad::<H>::new())]
}

/// Demo rule set for Tappa 5. Returned only when the `demo-tappa5`
/// feature is enabled. These rules trigger the four new
/// ResponseActions on filename-suffix matches; they should never run
/// in production.
#[cfg(feature = "demo-tappa5")]
pub fn demo_tappa5_rules() -> Vec<Box<dyn Rule>> {
    use test_actions::{
        R901TestBlockOutbound, R902TestNetworkIsolation, R903TestQuarantine, R904TestThrottle,
    };
    vec![
        Box::new(R901TestBlockOutbound),
        Box::new(R902TestNetworkIsolation),
        Box::new(R903TestQuarantine),
        Box::new(R904TestThrottle),
    ]
}

/// Helper that turns an `Event::ProcessSpawn` into a [`Verdict`] tagged
/// with the firing rule's metadata. Rules call this in their match
/// arms to keep their bodies focused on detection logic.
pub(crate) fn build_verdict(
    rule: &dyn Rule,
    event: &Event,
    action: ResponseAction,
    severity: Severity,
    reasoning: &str,
) -> Verdict {
    let (event_pid, event_filename, timestamp_ns) = match event {
        // Review 61: the file the kernel executed, when known.
        Event::ProcessSpawn {
            pid,
            filename,
            timestamp_ns,
            exe,
            ..
        } => (*pid, exe.path_or(filename).to_string(), *timestamp_ns),
        // BUG-034: R018 fires on Event::ModuleLoad — target the LOADER
        // process (else a Critical KillProcessTree would carry pid 0 and
        // be refused at the executor's PID floor, a silent no-op).
        Event::ModuleLoad {
            loader_pid,
            path,
            timestamp_ns,
            ..
        } => (*loader_pid, path.clone().unwrap_or_default(), *timestamp_ns),
        Event::IoUring {
            pid,
            comm,
            timestamp_ns,
            ..
        }
        | Event::BpfSyscall {
            pid,
            comm,
            timestamp_ns,
            ..
        }
        | Event::ExploitPostcondition {
            pid,
            comm,
            timestamp_ns,
            ..
        } => (*pid, comm.clone(), *timestamp_ns),
        _ => (0, String::new(), 0),
    };
    Verdict {
        rule_id: rule.id().to_string(),
        rule_name: rule.name().to_string(),
        category: rule.category().to_string(),
        action,
        severity,
        reasoning: reasoning.to_string(),
        event_pid,
        event_filename,
        timestamp_ns,
    }
}

/// Event builders of the rules' tests; R08b (lab PR 251): the agent's
/// engine and posture tests read them too (nn-core's `test-util`).
#[cfg(any(test, feature = "test-util"))]
pub mod testutil {
    use nn_model::Event;

    /// Lot 370 (05-3.3): an exec of the dynamic loader, `argv` its own (its
    /// `argv[0]` the loader), as the LSM hook reports it.
    pub fn via_loader(argv: &[&str]) -> Event {
        let loader = "/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2";
        kernel_exe(spawn_full("ld-linux-x86-64", loader, 1000, argv, "bash"))
    }

    /// Build a `ProcessSpawn` event with sensible defaults plus the
    /// fields callers actually care about.
    pub fn spawn(comm: &str, filename: &str) -> Event {
        Event::ProcessSpawn {
            pid: 1234,
            ppid: 1,
            uid: 1000,
            gid: 1000,
            comm: comm.to_string(),
            filename: filename.to_string(),
            timestamp_ns: 42,
            argv: Vec::new(),
            parent_comm: String::new(),
            parent_start_ns: 0,
            start_ns: 0,
            parent_is_kthread: false,
            exe: Default::default(),
            argv_truncated: false,
            filename_truncated: false,
            stdio: Default::default(),
        }
    }

    /// Tappa 10.9 step 2 (review 61): a spawn whose caller passed
    /// `filename` while the kernel executed `exe_path` (`flags` from
    /// `wire::exe::exe_flags`).
    pub fn spawn_exe(comm: &str, filename: &str, exe_path: &str, flags: u32) -> Event {
        let mut e = spawn(comm, filename);
        if let Event::ProcessSpawn { exe, .. } = &mut e {
            exe.path = exe_path.to_string();
            exe.flags = flags | common::wire::exe::exe_flags::KNOWN;
        }
        e
    }

    /// Same as [`spawn`] but lets the caller override uid (used by
    /// R009 root-from-user-path tests).
    pub fn spawn_as(uid: u32, comm: &str, filename: &str) -> Event {
        Event::ProcessSpawn {
            pid: 1234,
            ppid: 1,
            uid,
            gid: uid,
            comm: comm.to_string(),
            filename: filename.to_string(),
            timestamp_ns: 42,
            argv: Vec::new(),
            parent_comm: String::new(),
            parent_start_ns: 0,
            start_ns: 0,
            parent_is_kthread: false,
            exe: Default::default(),
            argv_truncated: false,
            filename_truncated: false,
            stdio: Default::default(),
        }
    }

    /// Tappa 10.6 D5 — `spawn` plus argv + parent_comm, for the
    /// argv-enrichment tests. `uid` defaults to a service-class account
    /// (the R015/R016 gate) so those rules' base predicate passes.
    pub fn spawn_full(
        comm: &str,
        filename: &str,
        uid: u32,
        argv: &[&str],
        parent_comm: &str,
    ) -> Event {
        Event::ProcessSpawn {
            pid: 1234,
            ppid: 1,
            uid,
            gid: uid,
            comm: comm.to_string(),
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

    /// Lot 313 (BUG-119): `e` as the LSM hook reports a file executed where
    /// the caller named it — the kernel's path is the caller's string. The
    /// rules' system-tree exemptions read that path only.
    pub fn kernel_exe(mut e: Event) -> Event {
        if let Event::ProcessSpawn { filename, exe, .. } = &mut e {
            exe.path = filename.clone();
            exe.flags |= common::wire::exe::exe_flags::KNOWN;
        }
        e
    }

    /// External audit EBPF-021: `e` as the kernel reports an argv it cut
    /// (or, with an empty argv, could not read).
    pub fn argv_cut(mut e: Event) -> Event {
        if let Event::ProcessSpawn { argv_truncated, .. } = &mut e {
            *argv_truncated = true;
        }
        e
    }
}

#[cfg(test)]
mod tests {
    use super::is_service_uid;

    /// Lot 370 (05-3.3): a program run as the dynamic loader's operand is
    /// judged as if the kernel had executed it — `/tmp` (R001), `/dev/shm`
    /// (R002), `/var/tmp` (R003), a descriptor's link or a memfd (R004), a
    /// library `--preload` loads too — and one the text cannot place (a
    /// relative name) is recorded without a response. On main the rules
    /// judged only the image the kernel executed, the loader in `/lib`:
    /// every one of these was silent. Controls: `ld.so --list` of anything,
    /// a system binary run through the loader, and the loader's `--help`.
    #[test]
    fn a_program_run_through_the_dynamic_loader_is_judged_as_if_executed() {
        use super::testutil::via_loader;
        use super::*;
        type H = crate::posture::host::testing::TestHost;
        let ld = "/lib64/ld-linux-x86-64.so.2";
        let r001 = R001ExecFromTmp::default();
        let r003 = R003ExecFromVarTmp::default();
        let r004 = R004ExecFromProcSelfFd::<H>::default();
        // `flags`: what the exec pump read of the exec (the re-check of
        // #578: the program's auditing libraries)
        let judge_read =
            |argv: &[&str], flags: u32| -> Vec<(String, ResponseAction, Severity, String)> {
                let mut e = via_loader(argv);
                if let Event::ProcessSpawn { exe, .. } = &mut e {
                    exe.flags |= flags;
                }
                let rules: [&dyn Rule; 4] = [&r001, &R002ExecFromDevShm::default(), &r003, &r004];
                rules
                    .iter()
                    .filter_map(|r| r.evaluate(&e))
                    .map(|v| (v.rule_id, v.action, v.severity, v.reasoning))
                    .collect()
            };
        let judge = |argv: &[&str]| judge_read(argv, 0);
        let one_read = |argv: &[&str], flags: u32, rule: &str, action, sev| {
            let got = judge_read(argv, flags);
            assert_eq!(got.len(), 1, "{argv:?}: {got:?}");
            assert_eq!(
                (got[0].0.as_str(), got[0].1.clone(), got[0].2),
                (rule, action, sev),
                "{argv:?}"
            );
            assert!(got[0].3.contains("dynamic loader"), "{}", got[0].3);
        };
        let one = |argv: &[&str], rule: &str, action, sev| one_read(argv, 0, rule, action, sev);
        use ResponseAction::{KillProcessTree as Kill, Log};
        one(&[ld, "/tmp/x"], "R001_ExecFromTmp", Kill, Severity::Medium);
        one(
            &[ld, "/tmp//./x", "-q"],
            "R001_ExecFromTmp",
            Kill,
            Severity::Medium,
        );
        one(
            &[ld, "--library-path", "/usr/lib", "/tmp/x"],
            "R001_ExecFromTmp",
            Kill,
            Severity::Medium,
        );
        one(
            &[ld, "--preload", "/tmp/hook.so", "/usr/bin/true"],
            "R001_ExecFromTmp",
            Kill,
            Severity::Medium,
        );
        one(
            &[ld, "--audit=/usr/lib/a.so:/tmp/audit.so", "/usr/bin/true"],
            "R001_ExecFromTmp",
            Kill,
            Severity::Medium,
        );
        one(
            &[ld, "--", "/tmp/x"],
            "R001_ExecFromTmp",
            Kill,
            Severity::Medium,
        );
        one(
            &[ld, "/dev/shm/x"],
            "R002_ExecFromDevShm",
            Kill,
            Severity::High,
        );
        one(
            &[ld, "/var/tmp/x"],
            "R003_ExecFromVarTmp",
            Kill,
            Severity::Medium,
        );
        one(
            &[ld, "/proc/self/fd/3"],
            "R004_ExecFromProcSelfFd",
            Kill,
            Severity::Critical,
        );
        one(
            &[ld, "/dev/fd/4"],
            "R004_ExecFromProcSelfFd",
            Kill,
            Severity::Critical,
        );
        one(
            &[ld, "/proc/4242/fd/7", "arg"],
            "R004_ExecFromProcSelfFd",
            Kill,
            Severity::Critical,
        );
        // the mini-hunt: musl's loader, a preload into /dev/shm, --argv0
        one(
            &["/lib/ld-musl-x86_64.so.1", "/tmp/x"],
            "R001_ExecFromTmp",
            Kill,
            Severity::Medium,
        );
        one(
            &[ld, "--preload=/dev/shm/h.so", "/usr/bin/true"],
            "R002_ExecFromDevShm",
            Kill,
            Severity::High,
        );
        one(
            &[ld, "--argv0", "sshd", "/var/tmp/x"],
            "R003_ExecFromVarTmp",
            Kill,
            Severity::Medium,
        );
        // a name the text cannot place: recorded, no response
        one(&[ld, "./x"], "R001_ExecFromTmp", Log, Severity::Medium);
        one(
            &[ld, "/usr/../tmp/x"],
            "R001_ExecFromTmp",
            Log,
            Severity::Medium,
        );
        // the review of #578 (P3): a staged program the loader only lists
        // or checks — recorded Low, never killed (it was not recorded). The
        // re-check (R1-1): glibc's --list runs the libraries the program
        // names for auditing — and round 3 (R2-1): the pump's read of a
        // staged file can be made false, so Medium even when it read none
        one_read(
            &[ld, "--list", "/tmp/x"],
            common::wire::exe::exe_flags::LOADER_NO_AUDIT,
            "R001_ExecFromTmp",
            Log,
            Severity::Medium,
        );
        one(
            &[ld, "--verify", "/tmp/x"],
            "R001_ExecFromTmp",
            Log,
            Severity::Low,
        );
        // controls
        for quiet in [
            &[ld, "--list", "/usr/bin/ls"][..],
            &[ld, "/usr/bin/true"],
            &[ld, "--help"],
            &[ld],
        ] {
            assert!(judge(quiet).is_empty(), "{quiet:?}: {:?}", judge(quiet));
        }
        // a staged copy of the loader is killed as staged, whatever it runs
        let mut staged_loader = via_loader(&["/tmp/ld-linux-x86-64.so.2", "./x"]);
        if let Event::ProcessSpawn { exe, filename, .. } = &mut staged_loader {
            exe.path = "/tmp/ld-linux-x86-64.so.2".to_string();
            *filename = exe.path.clone();
        }
        let v = r001.evaluate(&staged_loader).expect("staged");
        assert_eq!(v.action, Kill);
        // not the loader: its argv is its own
        let e = super::testutil::kernel_exe(super::testutil::spawn_full(
            "cat",
            "/usr/bin/cat",
            1000,
            &["cat", "/tmp/x"],
            "bash",
        ));
        assert!(super::loader_code(&e, false).is_empty());
        assert!(r001.evaluate(&e).is_none());
    }

    /// `argv` run through the loader as a distinct exec (`key`: its pid and
    /// time — the pump's records are kept by exec), judged by R001..R004.
    fn loader_exec(key: u32, argv: &[&str]) -> nn_model::Event {
        let mut e = super::testutil::via_loader(argv);
        if let nn_model::Event::ProcessSpawn {
            pid, timestamp_ns, ..
        } = &mut e
        {
            (*pid, *timestamp_ns) = (key, u64::from(key));
        }
        e
    }

    /// The verdicts R001..R004 give `e` (`listing`: the system's `ldd`
    /// runs the loader): rule, action, severity.
    fn staging_verdicts(
        e: &nn_model::Event,
        listing: bool,
    ) -> Vec<(String, nn_model::ResponseAction, nn_model::Severity, String)> {
        use super::*;
        type H = crate::posture::host::testing::TestHost;
        let l = || LoaderListing::of_fn(move |_| listing);
        let r001 = R001ExecFromTmp::default().with_loader_listing(l());
        let r002 = R002ExecFromDevShm::default().with_loader_listing(l());
        let r003 = R003ExecFromVarTmp::default().with_loader_listing(l());
        let r004 = R004ExecFromProcSelfFd::<H>::default().with_loader_listing(l());
        let rules: [&dyn Rule; 4] = [&r001, &r002, &r003, &r004];
        rules
            .iter()
            .filter_map(|r| r.evaluate(e))
            .map(|v| (v.rule_id, v.action, v.severity, v.reasoning))
            .collect()
    }

    /// The review of #578 (N1, named; its probe): a loader operand named
    /// through a link of `/proc` — `/proc/self/root/…`, `/proc/self/cwd/…`,
    /// `/proc/1/root/…`, `/proc/thread-self/root/…`, `/proc/self/fd/N` — is
    /// placed by the kernel's identity of the file the loader maps (the exec
    /// pump's record) and judged as a direct exec of that file: `/tmp` R001,
    /// `/dev/shm` R002, `/var/tmp` R003, a memfd R004, a linked system file
    /// nothing. Not placed (another view, the process gone, the file not
    /// mapped): a view's link is recorded by R001 (Medium, no response), a
    /// descriptor's is R004's Critical as before. On 382be007 the first
    /// four were silent in every profile.
    #[test]
    fn a_loader_operand_through_a_proc_view_link_is_judged_as_a_direct_exec() {
        use super::program_identity::{keep_loader_files, LoaderFile};
        use nn_model::{ResponseAction::*, Severity};
        let ld = "/lib64/ld-linux-x86-64.so.2";
        let placed = |key: u32, text: &str, path: &str, memfd: bool, deleted: bool| {
            let e = loader_exec(key, &[ld, text]);
            keep_loader_files(
                &e,
                vec![LoaderFile {
                    text: text.into(),
                    path: path.into(),
                    memfd,
                    deleted,
                }],
            );
            staging_verdicts(&e, false)
        };
        let one = |got: Vec<(String, nn_model::ResponseAction, Severity, String)>,
                   rule: &str,
                   action,
                   sev| {
            assert_eq!(got.len(), 1, "{got:?}");
            assert_eq!(
                (got[0].0.as_str(), got[0].1.clone(), got[0].2),
                (rule, action, sev),
                "{got:?}"
            );
        };
        // placed by the pump: judged as the file it is
        let r001 = "R001_ExecFromTmp";
        one(
            placed(57_801, "/proc/self/root/tmp/x", "/tmp/x", false, false),
            r001,
            KillProcessTree,
            Severity::Medium,
        );
        one(
            placed(57_802, "/proc/self/cwd/x", "/tmp/x", false, false),
            r001,
            KillProcessTree,
            Severity::Medium,
        );
        one(
            placed(57_803, "/proc/1/root/dev/shm/x", "/dev/shm/x", false, false),
            "R002_ExecFromDevShm",
            KillProcessTree,
            Severity::High,
        );
        one(
            placed(
                57_804,
                "/proc/thread-self/root/var/tmp/x",
                "/var/tmp/x",
                false,
                false,
            ),
            "R003_ExecFromVarTmp",
            KillProcessTree,
            Severity::Medium,
        );
        one(
            placed(57_805, "/proc/self/fd/3", "/memfd:x", true, true),
            "R004_ExecFromProcSelfFd",
            KillProcessTree,
            Severity::Critical,
        );
        one(
            placed(57_806, "/proc/self/cwd/x", "/home/u/x", false, true),
            "R004_ExecFromProcSelfFd",
            KillProcessTree,
            Severity::Critical,
        );
        // a descriptor of a staged file: R001, as a direct exec of it
        one(
            placed(57_807, "/proc/self/fd/3", "/tmp/x", false, false),
            r001,
            KillProcessTree,
            Severity::Medium,
        );
        // a linked system file through a link: as its direct exec, nothing
        for (key, text) in [
            (57_808, "/proc/self/root/usr/bin/true"),
            (57_809, "/proc/self/fd/3"),
        ] {
            let got = placed(key, text, "/usr/bin/true", false, false);
            assert!(got.is_empty(), "{text}: {got:?}");
        }
        // not placed: a view's link recorded (R001, no response), a
        // descriptor's R004's kill — never silent
        for (key, text) in [
            (57_810, "/proc/self/root/tmp/x"),
            (57_811, "/proc/self/cwd/x"),
            (57_812, "/proc/1/root/dev/shm/x"),
            (57_813, "/proc/thread-self/root/var/tmp/x"),
        ] {
            one(
                staging_verdicts(&loader_exec(key, &[ld, text]), false),
                r001,
                Log,
                Severity::Medium,
            );
        }
        one(
            staging_verdicts(&loader_exec(57_814, &[ld, "/proc/self/fd/3"]), false),
            "R004_ExecFromProcSelfFd",
            KillProcessTree,
            Severity::Critical,
        );
        // a record for another text of the same exec places nothing else
        let e = loader_exec(
            57_815,
            &[ld, "--preload", "/proc/self/cwd/h.so", "/usr/bin/true"],
        );
        keep_loader_files(
            &e,
            vec![LoaderFile {
                text: "/proc/self/cwd/other".into(),
                path: "/usr/lib/x.so".into(),
                memfd: false,
                deleted: false,
            }],
        );
        one(staging_verdicts(&e, false), r001, Log, Severity::Medium);
    }

    /// The review of #578 (P3, named): a loader that only lists or checks
    /// its program — `--list`, `--verify`, `LD_TRACE_LOADED_OBJECTS` in its
    /// environment as the pump read it, musl's loader run as `ldd`, glibc's
    /// `ldd` script its parent — runs none of its code: a staged program is
    /// recorded Low, never killed (`ldd /tmp/x` was R001's kill on
    /// 382be007). A loader that runs it stays judged, and an auditing
    /// library runs in every mode.
    ///
    /// The re-check of #578 (R1-1): glibc's list and trace modes run the
    /// libraries the program names for auditing, and (round 3, R2-1) what the
    /// pump read of a staged file can be made false by the code that ran — so
    /// glibc's list or trace mode is Medium for a staged operand, never Low
    /// (Low stays for musl's loader and `--verify`; the next test has the
    /// rest).
    #[test]
    fn a_loader_that_only_lists_is_recorded_low_and_one_that_runs_stays_judged() {
        use common::wire::exe::exe_flags::{LOADER_LISTS, LOADER_NO_AUDIT};
        use nn_model::{ResponseAction::*, Severity};
        let ld = "/lib64/ld-linux-x86-64.so.2";
        let only = |e: &nn_model::Event, listing: bool, rule: &str, action, sev| {
            let got = staging_verdicts(e, listing);
            assert_eq!(got.len(), 1, "{got:?}");
            assert_eq!(
                (got[0].0.as_str(), got[0].1.clone(), got[0].2),
                (rule, action, sev),
                "{got:?}"
            );
        };
        // the pump read the trace mode, and the program naming no library
        // for auditing (R1-1)
        let traced = |key: u32, argv: &[&str]| {
            let mut e = loader_exec(key, argv);
            if let nn_model::Event::ProcessSpawn { exe, .. } = &mut e {
                exe.flags |= LOADER_LISTS | LOADER_NO_AUDIT;
            }
            e
        };
        // ldd's trace mode, read from the environment
        only(
            &traced(57_821, &[ld, "/tmp/x"]),
            false,
            "R001_ExecFromTmp",
            Log,
            Severity::Medium,
        );
        only(
            &traced(57_822, &[ld, "/dev/shm/x"]),
            false,
            "R002_ExecFromDevShm",
            Log,
            Severity::Medium,
        );
        only(
            &traced(57_823, &[ld, "/var/tmp/x"]),
            false,
            "R003_ExecFromVarTmp",
            Log,
            Severity::Medium,
        );
        only(
            &traced(57_824, &[ld, "/proc/self/fd/3"]),
            false,
            "R004_ExecFromProcSelfFd",
            Log,
            Severity::Medium,
        );
        only(
            &traced(57_825, &[ld, "./x"]),
            false,
            "R001_ExecFromTmp",
            Log,
            Severity::Medium,
        );
        // the system's ldd its parent (the lineage's identity)
        let mut by_ldd = loader_exec(57_826, &[ld, "/tmp/x"]);
        if let nn_model::Event::ProcessSpawn { exe, .. } = &mut by_ldd {
            exe.flags |= LOADER_NO_AUDIT;
        }
        only(&by_ldd, true, "R001_ExecFromTmp", Log, Severity::Medium);
        // musl's loader as ldd
        let mut musl = loader_exec(57_827, &["ldd", "/tmp/x"]);
        if let nn_model::Event::ProcessSpawn { exe, filename, .. } = &mut musl {
            exe.path = "/lib/ld-musl-x86_64.so.1".into();
            *filename = exe.path.clone();
        }
        only(&musl, false, "R001_ExecFromTmp", Log, Severity::Low);
        // CONTROLS: the same programs run — judged as before
        only(
            &loader_exec(57_828, &[ld, "/tmp/x"]),
            false,
            "R001_ExecFromTmp",
            KillProcessTree,
            Severity::Medium,
        );
        let mut musl_run = loader_exec(57_829, &["/lib/ld-musl-x86_64.so.1", "/tmp/x"]);
        if let nn_model::Event::ProcessSpawn { exe, filename, .. } = &mut musl_run {
            exe.path = "/lib/ld-musl-x86_64.so.1".into();
            *filename = exe.path.clone();
        }
        only(
            &musl_run,
            false,
            "R001_ExecFromTmp",
            KillProcessTree,
            Severity::Medium,
        );
        // an auditing library runs even when the loader lists
        only(
            &loader_exec(
                57_830,
                &[ld, "--audit", "/tmp/a.so", "--list", "/usr/bin/ls"],
            ),
            false,
            "R001_ExecFromTmp",
            KillProcessTree,
            Severity::Medium,
        );
        // … and the program it checks is recorded Low beside it (R1-1:
        // `--verify`, the one mode that loads no auditing library; listed,
        // the next test)
        let got: Vec<_> = staging_verdicts(
            &traced(57_831, &[ld, "--audit=/dev/shm/a.so", "--verify", "/tmp/x"]),
            false,
        )
        .into_iter()
        .map(|v| (v.0, v.1, v.2))
        .collect();
        assert_eq!(
            got,
            [
                ("R001_ExecFromTmp".to_string(), Log, Severity::Low),
                (
                    "R002_ExecFromDevShm".to_string(),
                    KillProcessTree,
                    Severity::High
                )
            ]
        );
        // a file it runs is judged before one it only lists, in one rule:
        // an auditing library beside a listed program, each kind
        only(
            &traced(57_833, &[ld, "--audit=/tmp/a.so", "/tmp/x"]),
            false,
            "R001_ExecFromTmp",
            KillProcessTree,
            Severity::Medium,
        );
        only(
            &traced(57_834, &[ld, "--audit=/proc/self/fd/4", "/proc/self/fd/3"]),
            false,
            "R004_ExecFromProcSelfFd",
            KillProcessTree,
            Severity::Critical,
        );
        only(
            &traced(57_835, &[ld, "--audit=./a.so", "./x"]),
            false,
            "R001_ExecFromTmp",
            Log,
            Severity::Medium,
        );
        // musl's name is the kernel's file, in a root-owned tree
        let mut named = loader_exec(57_832, &["ldd", "/tmp/x"]);
        if let nn_model::Event::ProcessSpawn { exe, filename, .. } = &mut named {
            exe.path = "/home/u/ld-musl-x86_64.so.1".into();
            *filename = exe.path.clone();
        }
        assert!(staging_verdicts(&named, false)
            .iter()
            .all(|v| v.1 == KillProcessTree));
    }

    /// The re-check of #578 (R1-1, named; its probe on glibc 2.39): glibc's
    /// list and trace modes (`--list`, `LD_TRACE_LOADED_OBJECTS`, `ldd`)
    /// still load and run the libraries the program names for auditing
    /// (`DT_AUDIT`, `DT_DEPAUDIT`) — its own constructor when it names
    /// itself — so a staged program is:
    /// - judged as run (the kill) when the pump read it naming one
    ///   (`LOADER_AUDITS`), in every list mode but `--verify`;
    /// - recorded Medium, never killed, never said to run nothing, when it
    ///   was not read, when an auditing library is given beside it, or when
    ///   the loader is not the system's;
    /// - Round 3 (R2-1): the same Medium when it was read naming none
    ///   (`LOADER_NO_AUDIT`), because the four ways the pump's read is made
    ///   false by the code that ran (a directory swap onto the auditor, a
    ///   write through a shared mapping, a relative link climbing out of the
    ///   directory, a page-overlapping segment layout) cannot be told from
    ///   an honest read: a staged operand is always "may run".
    ///
    /// musl reads no `LD_TRACE_LOADED_OBJECTS`: under it, it runs the
    /// program (judged as run); its `ldd` stays Low. On 6321c7b7 every list
    /// mode was Low, "runs none of its code".
    #[test]
    fn a_staged_program_glibc_lists_is_never_low_whatever_the_pump_read() {
        use common::wire::exe::exe_flags::{LOADER_AUDITS, LOADER_LISTS, LOADER_NO_AUDIT};
        use nn_model::{ResponseAction::*, Severity};
        let ld = "/lib64/ld-linux-x86-64.so.2";
        let with = |key: u32, argv: &[&str], flags: u32| {
            let mut e = loader_exec(key, argv);
            if let nn_model::Event::ProcessSpawn { exe, .. } = &mut e {
                exe.flags |= flags;
            }
            e
        };
        // the one verdict, its rule, action and severity — and whether its
        // text says the loader runs no code of the file
        let only =
            |e: &nn_model::Event, listing: bool, rule: &str, action, sev, says_none: bool| {
                let got = staging_verdicts(e, listing);
                let shape: Vec<_> = got
                    .iter()
                    .map(|v| (v.0.clone(), v.1.clone(), v.2))
                    .collect();
                assert_eq!(
                    shape,
                    [(rule.to_string(), action, sev)],
                    "one verdict, as expected"
                );
                assert_eq!(
                    got[0].3.contains("runs no code"),
                    says_none,
                    "the record says the loader runs no code only when that is known"
                );
            };
        let (r1, r2, r3, r4) = (
            "R001_ExecFromTmp",
            "R002_ExecFromDevShm",
            "R003_ExecFromVarTmp",
            "R004_ExecFromProcSelfFd",
        );
        // read naming one: judged as run, in each list mode
        for (key, argv, flags, listing) in [
            (
                57_841,
                &[ld, "/tmp/x"][..],
                LOADER_LISTS | LOADER_AUDITS,
                false,
            ),
            (57_842, &[ld, "--list", "/tmp/x"], LOADER_AUDITS, false),
            (57_843, &[ld, "/tmp/x"], LOADER_AUDITS, true),
        ] {
            only(
                &with(key, argv, flags),
                listing,
                r1,
                KillProcessTree,
                Severity::Medium,
                false,
            );
        }
        let traced_audits = LOADER_LISTS | LOADER_AUDITS;
        only(
            &with(57_844, &[ld, "/dev/shm/x"], traced_audits),
            false,
            r2,
            KillProcessTree,
            Severity::High,
            false,
        );
        only(
            &with(57_845, &[ld, "/var/tmp/x"], traced_audits),
            false,
            r3,
            KillProcessTree,
            Severity::Medium,
            false,
        );
        only(
            &with(57_846, &[ld, "/proc/self/fd/3"], traced_audits),
            false,
            r4,
            KillProcessTree,
            Severity::Critical,
            false,
        );
        // not read (the process gone, the budget spent, the file changed):
        // recorded Medium, not killed, never "runs no code"
        for (key, argv, flags, listing) in [
            (57_847, &[ld, "/tmp/x"][..], LOADER_LISTS, false),
            (57_848, &[ld, "--list", "/tmp/x"], 0, false),
            (57_849, &[ld, "/tmp/x"], 0, true),
        ] {
            only(
                &with(key, argv, flags),
                listing,
                r1,
                Log,
                Severity::Medium,
                false,
            );
        }
        only(
            &with(57_850, &[ld, "/dev/shm/x"], LOADER_LISTS),
            false,
            r2,
            Log,
            Severity::Medium,
            false,
        );
        only(
            &with(57_851, &[ld, "/var/tmp/x"], LOADER_LISTS),
            false,
            r3,
            Log,
            Severity::Medium,
            false,
        );
        only(
            &with(57_852, &[ld, "/proc/self/fd/3"], LOADER_LISTS),
            false,
            r4,
            Log,
            Severity::Medium,
            false,
        );
        only(
            &with(57_853, &[ld, "./x"], LOADER_LISTS),
            false,
            r1,
            Log,
            Severity::Medium,
            false,
        );
        // R2-1: read naming none is no longer Low — the staged operand, each
        // spelling the four ways of the probe reach (a name in a directory,
        // a relative name, `/proc`, `/dev/shm`), in each list mode
        for (key, argv, flags, listing, rule) in [
            (
                57_870,
                &[ld, "/tmp/x"][..],
                LOADER_LISTS | LOADER_NO_AUDIT,
                false,
                r1,
            ),
            (
                57_871,
                &[ld, "--list", "/tmp/x"],
                LOADER_NO_AUDIT,
                false,
                r1,
            ),
            (57_872, &[ld, "/tmp/x"], LOADER_NO_AUDIT, true, r1),
            (
                57_873,
                &[ld, "./x"],
                LOADER_LISTS | LOADER_NO_AUDIT,
                false,
                r1,
            ),
            (
                57_874,
                &[ld, "/dev/shm/x"],
                LOADER_LISTS | LOADER_NO_AUDIT,
                false,
                r2,
            ),
            (
                57_875,
                &[ld, "/proc/self/fd/3"],
                LOADER_LISTS | LOADER_NO_AUDIT,
                false,
                r4,
            ),
        ] {
            only(
                &with(key, argv, flags),
                listing,
                rule,
                Log,
                Severity::Medium,
                false,
            );
        }
        // an auditing library given beside it: the program may run under it
        let got: Vec<_> = staging_verdicts(
            &with(
                57_854,
                &[ld, "--audit=/dev/shm/a.so", "--list", "/tmp/x"],
                LOADER_NO_AUDIT,
            ),
            false,
        )
        .into_iter()
        .map(|v| (v.0, v.1, v.2))
        .collect();
        assert_eq!(
            got,
            [
                (r1.to_string(), Log, Severity::Medium),
                (r2.to_string(), KillProcessTree, Severity::High)
            ]
        );
        // … one the agent cannot place (it may be the program itself): its
        // record, which names it, before the listed program's
        let e = with(
            57_855,
            &[ld, "--audit=./x", "--list", "/tmp/x"],
            LOADER_NO_AUDIT,
        );
        only(&e, false, r1, Log, Severity::Medium, false);
        assert!(
            staging_verdicts(&e, false)[0].3.contains("(./x:"),
            "the record names the auditing library the agent cannot place"
        );
        // --verify loads no auditing library: Low, whatever the program names
        only(
            &with(57_856, &[ld, "--verify", "/tmp/x"], LOADER_AUDITS),
            false,
            r1,
            Log,
            Severity::Low,
            true,
        );
        // … the last of --list and --verify is the mode
        only(
            &with(57_857, &[ld, "--verify", "--list", "/tmp/x"], LOADER_AUDITS),
            false,
            r1,
            KillProcessTree,
            Severity::Medium,
            false,
        );
        // a loader that is not the system's (a copy in a home): may run
        let mut copy = with(57_858, &[ld, "--list", "/tmp/x"], LOADER_NO_AUDIT);
        if let nn_model::Event::ProcessSpawn { exe, .. } = &mut copy {
            exe.path = "/home/u/ld-linux-x86-64.so.2".into();
        }
        only(&copy, false, r1, Log, Severity::Medium, false);
        // … or one known by a name only (no kernel identity of its file)
        let mut by_name = with(57_861, &[ld, "--list", "/tmp/x"], LOADER_NO_AUDIT);
        if let nn_model::Event::ProcessSpawn { exe, .. } = &mut by_name {
            exe.flags &= !common::wire::exe::exe_flags::KNOWN;
        }
        only(&by_name, false, r1, Log, Severity::Medium, false);
        // musl reads no LD_TRACE_LOADED_OBJECTS: it runs the program
        let musl = "/lib/ld-musl-x86_64.so.1";
        let mut env_traced = with(
            57_859,
            &[musl, "/dev/shm/x"],
            LOADER_LISTS | LOADER_NO_AUDIT,
        );
        if let nn_model::Event::ProcessSpawn { exe, filename, .. } = &mut env_traced {
            exe.path = musl.into();
            *filename = musl.into();
        }
        only(
            &env_traced,
            false,
            r2,
            KillProcessTree,
            Severity::High,
            false,
        );
        // … its own list mode stays Low, nothing read
        let mut listed = with(57_860, &[musl, "--list", "/dev/shm/x"], 0);
        if let nn_model::Event::ProcessSpawn { exe, filename, .. } = &mut listed {
            exe.path = musl.into();
            *filename = musl.into();
        }
        only(&listed, false, r2, Log, Severity::Low, true);
    }

    /// The re-check of #578 (R1-2, named): a loader operand whose text
    /// reaches a staging directory through a symbolic link — the RHEL
    /// family's `/usr/tmp -> ../var/tmp` — is judged where the exec pump
    /// found the file the loader maps (R003 for `/var/tmp`), as a direct
    /// exec of it is. The pump's placement only adds: the text's own
    /// reading stays judged beside it (`/tmp/x` placed elsewhere is still
    /// R001's), and a name it did not place is as before. On 6321c7b7
    /// `ld.so /usr/tmp/x` was silent.
    #[test]
    fn a_loader_operand_through_a_symbolic_link_is_judged_where_the_pump_found_it() {
        use super::program_identity::{keep_loader_files, LoaderFile};
        use nn_model::{ResponseAction::*, Severity};
        let ld = "/lib64/ld-linux-x86-64.so.2";
        let placed_at = |key: u32, text: &str, path: &str| {
            let e = loader_exec(key, &[ld, text]);
            keep_loader_files(
                &e,
                vec![LoaderFile {
                    text: text.into(),
                    path: path.into(),
                    memfd: false,
                    deleted: false,
                }],
            );
            staging_verdicts(&e, false)
                .into_iter()
                .map(|v| (v.0, v.1, v.2))
                .collect::<Vec<_>>()
        };
        assert_eq!(
            placed_at(57_871, "/usr/tmp/x", "/var/tmp/x"),
            [(
                "R003_ExecFromVarTmp".to_string(),
                KillProcessTree,
                Severity::Medium
            )]
        );
        assert_eq!(
            placed_at(57_872, "/opt/app/shm/x", "/dev/shm/x"),
            [(
                "R002_ExecFromDevShm".to_string(),
                KillProcessTree,
                Severity::High
            )]
        );
        // the text's own reading stays judged
        assert_eq!(
            placed_at(57_873, "/tmp/x", "/usr/bin/true"),
            [(
                "R001_ExecFromTmp".to_string(),
                KillProcessTree,
                Severity::Medium
            )]
        );
        // a system file through a link: nothing, as its direct exec
        assert!(placed_at(57_874, "/usr/tmp/x", "/usr/bin/true").is_empty());
        // not placed by the pump: as before (the residual, said)
        assert!(staging_verdicts(&loader_exec(57_875, &[ld, "/usr/tmp/x"]), false).is_empty());
        // found unlinked (a file removed once the loader mapped it): R004's
        let e = loader_exec(57_877, &[ld, "/opt/app/x"]);
        keep_loader_files(
            &e,
            vec![LoaderFile {
                text: "/opt/app/x".into(),
                path: "/opt/app/x".into(),
                memfd: false,
                deleted: true,
            }],
        );
        let got: Vec<_> = staging_verdicts(&e, false)
            .into_iter()
            .map(|v| (v.0, v.1, v.2))
            .collect();
        assert_eq!(
            got,
            [(
                "R004_ExecFromProcSelfFd".to_string(),
                KillProcessTree,
                Severity::Critical
            )]
        );
        // listed, the pump's read naming no auditing library: Medium (R2-1)
        let mut e = loader_exec(57_876, &[ld, "--list", "/usr/tmp/x"]);
        if let nn_model::Event::ProcessSpawn { exe, .. } = &mut e {
            exe.flags |= common::wire::exe::exe_flags::LOADER_NO_AUDIT;
        }
        keep_loader_files(
            &e,
            vec![LoaderFile {
                text: "/usr/tmp/x".into(),
                path: "/var/tmp/x".into(),
                memfd: false,
                deleted: false,
            }],
        );
        let got: Vec<_> = staging_verdicts(&e, false)
            .into_iter()
            .map(|v| (v.0, v.1, v.2))
            .collect();
        assert_eq!(
            got,
            [("R003_ExecFromVarTmp".to_string(), Log, Severity::Medium)]
        );
    }

    /// The review of #578 (P3, named): the system's `ldd` is a shell in a
    /// root-owned tree running the `ldd` script of one, by an absolute
    /// path — not a script of that name elsewhere, not another program,
    /// not a shell whose environment loads code into it.
    #[test]
    fn the_system_s_ldd_is_a_shell_running_its_script_from_a_system_tree() {
        use crate::posture::lineage::{ExecIdentity, Runs};
        let id = |exe: &str, argv: &[&str]| {
            ExecIdentity::of_exec(exe, &argv.iter().map(|a| a.to_string()).collect::<Vec<_>>())
        };
        assert!(super::runs_the_ldd_script(&id(
            "/usr/bin/bash",
            &["/bin/bash", "/usr/bin/ldd", "/tmp/x"]
        )));
        assert!(super::runs_the_ldd_script(&id(
            "/bin/sh",
            &["/bin/sh", "/usr/bin/ldd", "-r", "/tmp/x"]
        )));
        for (exe, argv) in [
            ("/usr/bin/bash", &["bash", "/tmp/ldd", "/tmp/x"][..]),
            ("/usr/bin/bash", &["bash", "./ldd", "/tmp/x"]),
            ("/usr/bin/bash", &["bash", "-c", "ldd /tmp/x"]),
            ("/usr/bin/python3", &["python3", "/usr/bin/ldd"]),
            ("/home/u/bash", &["bash", "/usr/bin/ldd"]),
            ("/usr/bin/bash", &["bash", "/usr/bin/lddx"]),
        ] {
            assert!(
                !super::runs_the_ldd_script(&id(exe, argv)),
                "{exe} {argv:?}"
            );
        }
        // an environment that loads code into the shell: what it runs is
        // not known
        let mut loaded = id("/usr/bin/bash", &["bash", "/usr/bin/ldd", "/tmp/x"]);
        loaded.runs = Runs::Unknown(Some("/usr/bin/ldd".into()));
        assert!(!super::runs_the_ldd_script(&loaded));
    }

    /// External audit PROC-012: the service-uid class at each boundary.
    #[test]
    fn service_uid_class_boundaries() {
        for uid in [1, 33, 999, 61_184, 61_500, 65_519, 65_534] {
            assert!(is_service_uid(uid), "{uid} is a service account");
        }
        for uid in [
            0,
            1000,
            60_000,
            60_001,
            61_183,
            65_520,
            65_533,
            65_535,
            100_000,
            100_032,
            524_288,
            u32::MAX,
        ] {
            assert!(!is_service_uid(uid), "{uid} is not a service account");
        }
    }
}
