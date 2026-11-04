//! Lot 277: the start-in-cgroup tracker — the agent's half
//! (`agent-ebpf/src/cgroup_join.rs` is the kernel's, the decision and the
//! names are `common::cgroup_join`'s).
//!
//! The per-rule policy's exemptions by cgroup or unit
//! (`nn_core::decision::rule_policy`) hold only for a process started in
//! the cgroup: spawned into it by systemd, or forked from a process that
//! was. The kernel marks the others — a process moved into a cgroup by
//! anyone but systemd's placement, a child started by
//! `clone3(CLONE_INTO_CGROUP)` by anyone but PID 1, and every process
//! either one forks after — in the pinned map `CGROUP_JOINED`; this module
//!
//! * attaches the five programs, all or none, where the kernel's BTF has
//!   their targets in the shapes they read (`btf_revalidate`), and installs
//!   the tracker's state for the boot ([`install`]): a kernel without them
//!   is a signed degradation, and every exemption by cgroup or unit is
//!   refused there;
//! * answers the exemption check's question ([`started_in_cgroup`]): not
//!   marked, marked, or not known — no tracker, a mark the map could not
//!   take, a lookup that failed — which refuses the exemption (fail
//!   closed);
//! * gives the kernel the policy's cgroup paths and unit names
//!   ([`sync_names`], at the start and at every policy change), so that a
//!   move into a cgroup an exemption names is signed (`cgroup_join`,
//!   NN-L-AT-001, not refused).
//!
//! The marks outlive an agent restart (the map is pinned); the programs do
//! not run while no agent runs, and the start removes the marks of the
//! processes gone meanwhile ([`Marks::sweep`]). A move made while no agent
//! ran is not seen: the residual is the trust model's
//! (`docs/design/ANTITAMPER_TRUST_MODEL.md`).

use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock};

use aya::maps::{Array, HashMap, MapData};
use aya::programs::links::FdLink;
use aya::programs::{BtfTracePoint, FEntry, FExit};
use aya::{Btf, Ebpf};
use common::cgroup_join::{
    fnv, lost_slot, unpack, NAME_CGROUP, NAME_UNIT, STAT_INTO_EXEMPT, STAT_LOST, STAT_ROOTS,
};
use nn_core::decision::rule_policy::{Exemption, RulePolicy};
use parking_lot::Mutex;
use tracing::{info, warn};

use crate::anti_tamper::btf_revalidate;

/// The marks (pinned).
pub const JOINED_MAP: &str = "CGROUP_JOINED";
/// The "not known" bitmap (pinned).
pub const LOST_MAP: &str = "CGROUP_JOIN_LOST";
/// The counters (pinned).
pub const STATS_MAP: &str = "CGROUP_JOIN_STATS";
/// The exemptions' names the kernel matches a destination against.
pub const NAMES_MAP: &str = "CGROUP_EXEMPT_NAMES";

/// How a program of the tracker attaches.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    FExit,
    FEntry,
    /// A BTF tracepoint.
    TpBtf,
}

/// The tracker's programs: `(program, how, target)`.
pub const PROGRAMS: [(&str, Kind, &str); 5] = [
    ("cgroup_join_exit", Kind::TpBtf, "sched_process_exit"),
    ("cgroup_join_fork", Kind::TpBtf, "sched_process_fork"),
    ("cgroup_join_born", Kind::FEntry, "cgroup_post_fork"),
    ("cgroup_join_src", Kind::FExit, "cgroup_procs_write_start"),
    ("cgroup_join_mark", Kind::TpBtf, "cgroup_attach_task"),
];

/// What a kernel without the tracker loses.
pub const ABSENT_EFFECT: &str =
    "the start-in-cgroup tracker is not attached: every exemption by cgroup or unit of the \
     per-rule policy is refused (a process moved into an exempt service's cgroup could not be \
     told from the service)";

type Joined = HashMap<MapData, u32, [u64; 2]>;
type Lost = Array<MapData, u64>;
type Stats = Array<MapData, u64>;
type Names = HashMap<MapData, u64, u8>;

/// The tracker's maps, for the exemption check, the names and the sweep.
#[derive(Clone)]
pub struct Marks {
    joined: Arc<Mutex<Joined>>,
    lost: Arc<Mutex<Lost>>,
    stats: Arc<Mutex<Stats>>,
    names: Arc<Mutex<Names>>,
}

/// The tracker as this boot has it.
pub enum Tracker {
    Attached(Marks),
    /// Why it is not: the exemptions by cgroup or unit are refused.
    Absent(String),
}

static TRACKER: OnceLock<Tracker> = OnceLock::new();

/// The review of #494, D2: the entries the marks get at the object's load
/// — the host's `pid_max` and `threads-max`, the lower
/// (`common::cgroup_join::joined_entries`): no more thread groups can be
/// alive. A map pinned by an earlier boot keeps its own size.
pub fn joined_entries_now() -> u32 {
    let read = |p: &str| {
        std::fs::read_to_string(p)
            .ok()
            .and_then(|s| s.trim().parse::<u64>().ok())
    };
    common::cgroup_join::joined_entries(
        read("/proc/sys/kernel/pid_max"),
        read("/proc/sys/kernel/threads-max"),
    )
}

/// The boot's tracker (a second call keeps the first).
pub fn install(t: Tracker) {
    let _ = TRACKER.set(t);
}

/// The boot's tracker, once [`install`]ed.
pub fn tracker() -> Option<&'static Tracker> {
    TRACKER.get()
}

/// Why the tracker cannot be attached on this kernel, from the boot's BTF
/// resolution; `None` when it can.
pub fn unavailable() -> Option<String> {
    match btf_revalidate::resolved() {
        None => Some("no kernel BTF resolution this boot".to_string()),
        Some(r) => r.cgroup_join_unavailable().map(str::to_string),
    }
}

/// The bpffs pins of program `name` (`prog_<name>`, `link_<name>`: the
/// tracker's program names, so no pin of the move guard's, which are named
/// by function, is touched).
pub fn pin_paths(root: &Path, name: &str) -> (PathBuf, PathBuf) {
    (
        root.join(format!("prog_{name}")),
        root.join(format!("link_{name}")),
    )
}

/// Load and attach program `name` on `target`; its link's id, as the
/// link's owner gives it back to be pinned.
fn load_attach(
    ebpf: &mut Ebpf,
    btf: &Btf,
    name: &str,
    kind: Kind,
    target: &str,
) -> Result<(), String> {
    let prog = ebpf
        .program_mut(name)
        .ok_or_else(|| format!("program {name} missing from the eBPF object"))?;
    let r = match kind {
        Kind::FExit => <&mut FExit>::try_from(prog)
            .map_err(|e| e.to_string())
            .and_then(|p| {
                p.load(target, btf).map_err(|e| format!("{e:#}"))?;
                p.attach().map(drop).map_err(|e| format!("{e:#}"))
            }),
        Kind::FEntry => <&mut FEntry>::try_from(prog)
            .map_err(|e| e.to_string())
            .and_then(|p| {
                p.load(target, btf).map_err(|e| format!("{e:#}"))?;
                p.attach().map(drop).map_err(|e| format!("{e:#}"))
            }),
        Kind::TpBtf => <&mut BtfTracePoint>::try_from(prog)
            .map_err(|e| e.to_string())
            .and_then(|p| {
                p.load(target, btf).map_err(|e| format!("{e:#}"))?;
                p.attach().map(drop).map_err(|e| format!("{e:#}"))
            }),
    };
    r.map_err(|e| format!("{name} ({target}): {e}"))
}

/// The review of #494, D6: program `name`'s fresh link and program pinned
/// in `root` — after the prior boot's pins of that program are removed,
/// which detaches the prior program only once this one is attached
/// (attach before purge: never a moment without the tracker). The link
/// held by the program object goes to the pin.
fn pin_fresh(ebpf: &mut Ebpf, root: &Path, name: &str, kind: Kind) -> Result<(), String> {
    let (prog_path, link_path) = pin_paths(root, name);
    let prog = ebpf
        .program_mut(name)
        .ok_or_else(|| format!("program {name} missing from the eBPF object"))?;
    let fd_link: FdLink = match kind {
        Kind::FExit => {
            let p = <&mut FExit>::try_from(prog).map_err(|e| e.to_string())?;
            let id = p.attach().map_err(|e| format!("{e:#}"))?;
            p.take_link(id).map_err(|e| format!("{e:#}"))?.into()
        }
        Kind::FEntry => {
            let p = <&mut FEntry>::try_from(prog).map_err(|e| e.to_string())?;
            let id = p.attach().map_err(|e| format!("{e:#}"))?;
            p.take_link(id).map_err(|e| format!("{e:#}"))?.into()
        }
        Kind::TpBtf => {
            let p = <&mut BtfTracePoint>::try_from(prog).map_err(|e| e.to_string())?;
            let id = p.attach().map_err(|e| format!("{e:#}"))?;
            p.take_link(id).map_err(|e| format!("{e:#}"))?.into()
        }
    };
    antitamper_bpf::purge_stale_pin(&link_path);
    antitamper_bpf::purge_stale_pin(&prog_path);
    let prog = ebpf
        .program_mut(name)
        .ok_or_else(|| format!("program {name} missing from the eBPF object"))?;
    prog.pin(&prog_path)
        .map_err(|e| format!("pinning {name} to {}: {e}", prog_path.display()))?;
    fd_link
        .pin(&link_path)
        .map_err(|e| format!("pinning {name}'s link to {}: {e}", link_path.display()))?;
    Ok(())
}

fn unload(ebpf: &mut Ebpf, name: &str, kind: Kind) {
    let Some(prog) = ebpf.program_mut(name) else {
        return;
    };
    let _ = match kind {
        Kind::FExit => <&mut FExit>::try_from(prog).map(|p| p.unload()),
        Kind::FEntry => <&mut FEntry>::try_from(prog).map(|p| p.unload()),
        Kind::TpBtf => <&mut BtfTracePoint>::try_from(prog).map(|p| p.unload()),
    };
}

/// Attach the tracker's programs, all or none (a mark that no fork passes
/// on, or that no exit removes, is worse than none: the agent would trust
/// what it does not see), and take its maps. The tracker's state for the
/// boot, which the caller [`install`]s.
///
/// The review of #494, D6: with a bpffs (`pin_root`), each program's link
/// is pinned as the anti-tamper hooks' are — the tracker keeps marking
/// while no agent runs (a restart, an upgrade). The five programs are
/// loaded first and only then attached and pinned one by one, each after
/// its predecessor of the prior boot is still running: a load refused
/// leaves the prior boot's pinned tracker as it was.
pub fn attach(ebpf: &mut Ebpf, btf: &Btf, pin_root: Option<&Path>) -> Tracker {
    if let Some(why) = unavailable() {
        warn!(reason = %why, effect = ABSENT_EFFECT, "cgroup exemptions: tracker not attached");
        // A prior boot's pinned tracker goes too: no program of an older
        // agent stays attached where this one would not attach.
        if let Some(root) = pin_root {
            for (name, _, _) in &PROGRAMS {
                let (prog, link) = pin_paths(root, name);
                antitamper_bpf::purge_stale_pin(&link);
                antitamper_bpf::purge_stale_pin(&prog);
            }
        }
        return Tracker::Absent(why);
    }
    match pin_root {
        None => {
            for (i, (name, kind, target)) in PROGRAMS.iter().enumerate() {
                if let Err(e) = load_attach(ebpf, btf, name, *kind, target) {
                    for (n, k, _) in &PROGRAMS[..=i] {
                        unload(ebpf, n, *k);
                    }
                    warn!(error = %e, effect = ABSENT_EFFECT, "cgroup exemptions: tracker attach FAILED");
                    return Tracker::Absent(e);
                }
            }
            warn!("cgroup exemptions: tracker attached WITHOUT pin (no bpffs): not kept while no agent runs");
        }
        Some(root) => {
            for (i, (name, kind, target)) in PROGRAMS.iter().enumerate() {
                if let Err(e) = load_only(ebpf, btf, name, *kind, target) {
                    for (n, k, _) in &PROGRAMS[..=i] {
                        unload(ebpf, n, *k);
                    }
                    warn!(error = %e, effect = ABSENT_EFFECT, "cgroup exemptions: tracker load FAILED");
                    return Tracker::Absent(e);
                }
            }
            for (name, kind, _) in &PROGRAMS {
                if let Err(e) = pin_fresh(ebpf, root, name, *kind) {
                    warn!(program = name, error = %e, effect = ABSENT_EFFECT, "cgroup exemptions: tracker attach or pin FAILED");
                    return Tracker::Absent(e);
                }
            }
        }
    }
    let take = |ebpf: &mut Ebpf, name: &str| {
        ebpf.take_map(name)
            .ok_or_else(|| format!("map {name} missing from the eBPF object"))
    };
    let maps = (|| -> Result<Marks, String> {
        let joined = Joined::try_from(take(ebpf, JOINED_MAP)?).map_err(|e| e.to_string())?;
        let lost = Lost::try_from(take(ebpf, LOST_MAP)?).map_err(|e| e.to_string())?;
        let stats = Stats::try_from(take(ebpf, STATS_MAP)?).map_err(|e| e.to_string())?;
        let names = Names::try_from(take(ebpf, NAMES_MAP)?).map_err(|e| e.to_string())?;
        Ok(Marks {
            joined: Arc::new(Mutex::new(joined)),
            lost: Arc::new(Mutex::new(lost)),
            stats: Arc::new(Mutex::new(stats)),
            names: Arc::new(Mutex::new(names)),
        })
    })();
    match maps {
        Ok(m) => {
            info!(
                programs = PROGRAMS.len(),
                pinned = pin_root.is_some(),
                "cgroup exemptions: the start-in-cgroup tracker is attached (moves into a cgroup \
                 and CLONE_INTO_CGROUP starts outside systemd are marked, with what they fork)"
            );
            Tracker::Attached(m)
        }
        Err(e) => {
            for (n, k, _) in &PROGRAMS {
                unload(ebpf, n, *k);
            }
            warn!(error = %e, effect = ABSENT_EFFECT, "cgroup exemptions: tracker maps unavailable");
            Tracker::Absent(e)
        }
    }
}

/// Load program `name` on `target` without attaching it.
fn load_only(
    ebpf: &mut Ebpf,
    btf: &Btf,
    name: &str,
    kind: Kind,
    target: &str,
) -> Result<(), String> {
    let prog = ebpf
        .program_mut(name)
        .ok_or_else(|| format!("program {name} missing from the eBPF object"))?;
    let r = match kind {
        Kind::FExit => <&mut FExit>::try_from(prog)
            .map_err(|e| e.to_string())
            .and_then(|p| p.load(target, btf).map_err(|e| format!("{e:#}"))),
        Kind::FEntry => <&mut FEntry>::try_from(prog)
            .map_err(|e| e.to_string())
            .and_then(|p| p.load(target, btf).map_err(|e| format!("{e:#}"))),
        Kind::TpBtf => <&mut BtfTracePoint>::try_from(prog)
            .map_err(|e| e.to_string())
            .and_then(|p| p.load(target, btf).map_err(|e| format!("{e:#}"))),
    };
    r.map_err(|e| format!("{name} ({target}): {e}"))
}

/// How a marked process came to be marked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Mark {
    /// `common::cgroup_join::HOW_*`.
    pub how: u8,
    /// The writer of the move, the forker of the start, or the parent.
    pub by: u32,
}

impl Marks {
    /// Lot 277: the exemption check's question for thread group `tgid`, in
    /// one errand (the decision thread's filter refuses `bpf`):
    /// `Some(true)` not marked, `Some(false)` marked, `None` not known — the
    /// group's mark could not be taken (its bit in `CGROUP_JOIN_LOST`: that
    /// tree only, the review of #494, D2), a failed read, no answer in time.
    pub fn started(&self, tgid: u32) -> Option<bool> {
        let (joined, lost) = (Arc::clone(&self.joined), Arc::clone(&self.lost));
        crate::caps::errands::run(move || {
            let (word, bit) = lost_slot(tgid)?;
            if lost.lock().get(&word, 0).ok()? & bit != 0 {
                return None;
            }
            match joined.lock().get(&tgid, 0) {
                Ok(_) => Some(false),
                Err(aya::maps::MapError::KeyNotFound) => Some(true),
                Err(_) => None,
            }
        })
        .flatten()
    }

    /// The mark of thread group `tgid`, if any (a tool's, a test's read:
    /// on the caller's thread).
    pub fn lookup(&self, tgid: u32) -> Result<Option<Mark>, String> {
        match self.joined.lock().get(&tgid, 0) {
            Ok([_, info]) => {
                let (how, by) = unpack(info);
                Ok(Some(Mark { how, by }))
            }
            Err(aya::maps::MapError::KeyNotFound) => Ok(None),
            Err(e) => Err(e.to_string()),
        }
    }

    /// Counter `slot` (`common::cgroup_join::STAT_*`), on the caller's
    /// thread.
    pub fn stat(&self, slot: u32) -> Result<u64, String> {
        self.stats.lock().get(&slot, 0).map_err(|e| e.to_string())
    }

    /// Give the kernel `names` ([`exempt_names`]) in place of what it had.
    /// On the caller's thread: the start's and the admin socket's (never
    /// the decision's).
    pub fn sync_names(&self, names: Vec<(u64, u8)>) -> Result<usize, String> {
        let mut map = self.names.lock();
        let old: Vec<u64> = map.keys().filter_map(Result::ok).collect();
        for k in old {
            if !names.iter().any(|(n, _)| *n == k) {
                map.remove(&k).map_err(|e| e.to_string())?;
            }
        }
        for (k, v) in &names {
            map.insert(k, v, 0).map_err(|e| e.to_string())?;
        }
        Ok(names.len())
    }

    /// Remove the marks of thread groups `proc_root` holds no more (gone
    /// while no agent ran, so no exit removed them); the number removed.
    pub fn sweep(&self, proc_root: &Path) -> usize {
        let mut map = self.joined.lock();
        let keys: Vec<u32> = map.keys().filter_map(Result::ok).collect();
        gone(&keys, proc_root)
            .into_iter()
            .filter(|k| map.remove(k).is_ok())
            .count()
    }
}

/// A pinned map opened read-only (`BPF_OBJ_GET` with `BPF_F_RDONLY`): the
/// BPF map guard refuses a write handle on the agent's maps to any other
/// process, and a read needs none.
fn open_pinned_ro(path: &Path) -> Result<MapData, String> {
    use std::os::fd::{FromRawFd, OwnedFd};
    use std::os::unix::ffi::OsStrExt;
    const BPF_OBJ_GET: libc::c_long = common::bpf_cmd::BPF_OBJ_GET as libc::c_long;
    const BPF_F_RDONLY: u32 = 1 << 3;
    #[repr(C)]
    struct ObjGet {
        pathname: u64,
        bpf_fd: u32,
        file_flags: u32,
    }
    let c = std::ffi::CString::new(path.as_os_str().as_bytes()).map_err(|e| e.to_string())?;
    let attr = ObjGet {
        pathname: c.as_ptr() as u64,
        bpf_fd: 0,
        file_flags: BPF_F_RDONLY,
    };
    // SAFETY: bpf(BPF_OBJ_GET) with a valid attribute block and a
    // NUL-terminated path that outlives the call.
    let fd = unsafe {
        libc::syscall(
            libc::SYS_bpf,
            BPF_OBJ_GET,
            &attr as *const ObjGet,
            std::mem::size_of::<ObjGet>(),
        )
    };
    if fd < 0 {
        return Err(format!(
            "BPF_OBJ_GET {}: {}",
            path.display(),
            std::io::Error::last_os_error()
        ));
    }
    // SAFETY: a descriptor the kernel just gave us, owned from here.
    let fd = unsafe { OwnedFd::from_raw_fd(fd as i32) };
    MapData::from_fd(fd).map_err(|e| e.to_string())
}

/// Lot 277 (the review of #494, D5): the mark of `tgid` in the pinned map
/// under bpffs `root` — a privileged test's, a tool's read (the agent's own
/// goes through [`Marks`]).
pub fn pinned_mark(root: &Path, tgid: u32) -> Result<Option<Mark>, String> {
    let md = open_pinned_ro(&root.join(JOINED_MAP))?;
    let map = Joined::try_from(aya::maps::Map::HashMap(md)).map_err(|e| e.to_string())?;
    match map.get(&tgid, 0) {
        Ok([_, info]) => {
            let (how, by) = unpack(info);
            Ok(Some(Mark { how, by }))
        }
        Err(aya::maps::MapError::KeyNotFound) => Ok(None),
        Err(e) => Err(e.to_string()),
    }
}

/// Lot 277 (the review of #494, D5): whether `tgid` is "not known" (its
/// bit in the pinned bitmap under bpffs `root`).
pub fn pinned_lost(root: &Path, tgid: u32) -> Result<bool, String> {
    let (word, bit) = lost_slot(tgid).ok_or("no tgid that large")?;
    let md = open_pinned_ro(&root.join(LOST_MAP))?;
    let map = Lost::try_from(aya::maps::Map::Array(md)).map_err(|e| e.to_string())?;
    Ok(map.get(&word, 0).map_err(|e| e.to_string())? & bit != 0)
}

/// The thread groups among `tgids` that `proc_root` holds no more.
fn gone(tgids: &[u32], proc_root: &Path) -> Vec<u32> {
    tgids
        .iter()
        .copied()
        .filter(|k| !proc_root.join(k.to_string()).exists())
        .collect()
}

/// Lot 277: the policy's exemption names the kernel matches a move's
/// destination against: each `cgroup <path>` and each `unit <name>`
/// hashed (`common::cgroup_join::fnv`), the kinds of one hash merged, and
/// key 0 when there is any — empty without one.
pub fn exempt_names(policy: &RulePolicy) -> Vec<(u64, u8)> {
    fn add(out: &mut Vec<(u64, u8)>, h: u64, kind: u8) {
        match out.iter_mut().find(|(k, _)| *k == h) {
            Some((_, v)) => *v |= kind,
            None => out.push((h, kind)),
        }
    }
    let mut out: Vec<(u64, u8)> = Vec::new();
    for (_, ex) in policy.all_exemptions() {
        for e in ex {
            match e {
                Exemption::Cgroup(p) => add(&mut out, fnv(p.as_bytes()), NAME_CGROUP),
                Exemption::Unit(u) => add(&mut out, fnv(u.as_bytes()), NAME_UNIT),
                Exemption::Uid(_) | Exemption::Exe { .. } => {}
            }
        }
    }
    if !out.is_empty() {
        add(&mut out, 0, 0);
    }
    out
}

/// Lot 277: the exemption a signed `cgroup_join` record's hash names, as
/// the policy writes it (`cgroup /system.slice/x.service`, `unit
/// x.service`); `None` for a hash no exemption of `policy` has (0: a path
/// too long to hash).
pub fn exemption_named(policy: &RulePolicy, hash: u64) -> Option<String> {
    policy
        .all_exemptions()
        .flat_map(|(_, ex)| ex.iter())
        .find(|e| match e {
            Exemption::Cgroup(p) => fnv(p.as_bytes()) == hash,
            Exemption::Unit(u) => fnv(u.as_bytes()) == hash,
            _ => false,
        })
        .map(ToString::to_string)
}

/// The policy's names into the kernel, if the tracker runs; logged.
pub fn sync_names(policy: &RulePolicy) {
    let Some(Tracker::Attached(m)) = tracker() else {
        return;
    };
    match m.sync_names(exempt_names(policy)) {
        Ok(n) => info!(
            names = n,
            "cgroup exemptions: the policy's cgroup paths and unit names given to the kernel"
        ),
        Err(e) => warn!(
            error = %e,
            "cgroup exemptions: the policy's names NOT given to the kernel — a move into an \
             exempt cgroup is still marked (never exempt), but not signed"
        ),
    }
}

/// `Tgid:` of `<proc_root>/<pid>/status`.
fn tgid_of(proc_root: &Path, pid: u32) -> Option<u32> {
    let s = std::fs::read_to_string(proc_root.join(pid.to_string()).join("status")).ok()?;
    s.lines()
        .find_map(|l| l.strip_prefix("Tgid:"))
        .and_then(|v| v.trim().parse().ok())
}

/// Lot 277: whether process `pid` started in the cgroup it runs in, for
/// the exemption check (`ActorFacts::started_in_cgroup`): `Some(true)`
/// not marked, `Some(false)` marked, `None` not known — no tracker this
/// boot, a mark the kernel could not take for this group (its bit in
/// `CGROUP_JOIN_LOST`, [`Marks::started`]), a lookup that failed. Read on the
/// errands thread; only when an exemption by cgroup or unit would apply.
pub fn started_in_cgroup(proc_root: &Path, pid: u32) -> Option<bool> {
    let Some(Tracker::Attached(m)) = tracker() else {
        return None;
    };
    let tgid = tgid_of(proc_root, pid)?;
    m.started(tgid)
}

/// The tracker's line for the journal at the start: its counters.
pub fn describe() -> String {
    match tracker() {
        None => "not installed".to_string(),
        Some(Tracker::Absent(why)) => format!("absent: {why}"),
        Some(Tracker::Attached(m)) => {
            let s = |slot| m.stat(slot).map_or("?".to_string(), |v| v.to_string());
            format!(
                "attached: {} roots marked, {} moves into an exempt cgroup, {} marks lost",
                s(STAT_ROOTS),
                s(STAT_INTO_EXEMPT),
                s(STAT_LOST)
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The policy's cgroup paths and unit names, hashed as the kernel
    /// hashes a destination path (`match_destination`), with key 0 for
    /// "any"; uid and exe exemptions give none.
    #[test]
    fn the_policy_gives_the_kernel_its_names() {
        let p = nn_core::decision::rule_policy::parse(&format!(
            "exempt R020 unit backup.service\nexempt R001 cgroup /system.slice/backup.service\n\
             exempt R020 uid 998\nexempt R001 unit backup.service\n\
             exempt R020 exe /usr/bin/backup sha256 {}\n",
            "a".repeat(64)
        ))
        .unwrap();
        let names = exempt_names(&p);
        let kinds = |h: u64| {
            names
                .iter()
                .filter(|(k, _)| *k == h)
                .fold(0u8, |a, (_, v)| a | v)
        };
        let full = common::cgroup_join::match_destination(b"/system.slice/backup.service", kinds)
            .expect("the cgroup exemption");
        let unit = common::cgroup_join::match_destination(
            b"/user.slice/user-1000.slice/user@1000.service/app.slice/backup.service",
            kinds,
        )
        .expect("the unit exemption");
        assert!(names.contains(&(unit, NAME_UNIT)), "{names:?}");
        assert!(names.contains(&(full, NAME_CGROUP)), "{names:?}");
        assert_eq!(
            common::cgroup_join::match_destination(b"/system.slice/other.service", kinds),
            None
        );
        assert!(names.contains(&(0, 0)));
        assert_eq!(names.len(), 3, "one entry per hash: {names:?}");
        assert_eq!(
            exemption_named(&p, unit).as_deref(),
            Some("unit backup.service")
        );
        assert_eq!(
            exemption_named(&p, full).as_deref(),
            Some("cgroup /system.slice/backup.service")
        );
        assert_eq!(exemption_named(&p, 0), None);
        // a path and a unit of one hash merge their kinds
        let q = nn_core::decision::rule_policy::parse(
            "exempt R020 uid 998\nexempt R020 exe /usr/bin/x sha256 \
             bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\n",
        )
        .unwrap();
        assert!(exempt_names(&q).is_empty(), "no cgroup or unit exemption");
        assert!(exempt_names(&RulePolicy::builtin()).is_empty());
    }

    /// No tracker this boot: nothing is known, the exemption is refused.
    #[test]
    fn without_a_tracker_nothing_started_in_its_cgroup() {
        if tracker().is_none() {
            assert_eq!(
                started_in_cgroup(Path::new("/proc"), std::process::id()),
                None
            );
        }
        assert_eq!(
            PROGRAMS.len(),
            common::btf_offsets::CGROUP_JOIN_TARGETS.len() + 1
        );
        for t in common::btf_offsets::CGROUP_JOIN_TARGETS {
            assert!(
                PROGRAMS.iter().any(|(_, _, target)| *target == t.name),
                "{}",
                t.name
            );
        }
    }

    /// The start's sweep removes the marks of thread groups gone, and
    /// only those.
    #[test]
    fn the_sweep_finds_the_groups_gone() {
        let d = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(d.path().join("40")).unwrap();
        assert_eq!(gone(&[40, 41, 42], d.path()), vec![41, 42]);
        assert!(gone(&[40], d.path()).is_empty());
    }

    #[test]
    fn the_status_tgid_is_read() {
        let d = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(d.path().join("42")).unwrap();
        std::fs::write(
            d.path().join("42/status"),
            "Name:\tx\nTgid:\t40\nPid:\t42\n",
        )
        .unwrap();
        assert_eq!(tgid_of(d.path(), 42), Some(40));
        assert_eq!(tgid_of(d.path(), 43), None);
    }
}
