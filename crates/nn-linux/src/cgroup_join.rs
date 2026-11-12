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
//! The maps and the programs' links are pinned in the tracker's own
//! directory beside the agent's pin root ([`prepare_pins`],
//! `common::cgroup_join::pin_dir`): they outlive an agent restart and an
//! upgrade's purge of the pin root (the re-review of #494, R2), and the
//! programs go on marking while no agent runs. A start whose maps' layout
//! differs from the directory it finds builds new ones and removes the old
//! directory: a signed degradation, "marks reset" ([`attach`]). A move made
//! before the first start since the host booted is not seen: the residual
//! is the trust model's (`docs/design/ANTITAMPER_TRUST_MODEL.md`).
//!
//! Lot 281: the same marks carry the code a process runs — its LSM
//! programs on `ptrace_access_check` and `ptrace_traceme` taint a process
//! code-injection access to which was given to another (and what it forks
//! after); the exemption check asks ([`injected`]): no exemption by
//! executable, cgroup or unit holds for it, and the first taint is recorded
//! (`FS_OP_EXEMPT_INJECT`, signed by the agent when an exemption covered
//! the process). #494's notes N1 and N2: a new generation's maps are made
//! at the load and pinned after it ([`attach`]: a file already at a pin's
//! path, or anything else in the new directory, is a plant — the next
//! generation, signed), every pinned map is frozen (`BPF_MAP_FREEZE`: no
//! handle writes it, one taken in a window or an upgrade's gap included;
//! the programs do), a reset's epoch asked for in a per-load map the fork
//! program takes in forward only, and no exemption is honoured until the
//! tracker is armed ([`arm`]: its pins and its state protected).
//!
//! Lot 280b: `kernel.ftrace_enabled=0` (refused outside a window; 6.0 to
//! 7.2) stops the tracker's fentry and fexit programs while its BTF
//! tracepoints go on. The fork's tracepoint checks each new thread group
//! against what the fentry saw (`CGROUP_JOIN_SILENT`, armed here once the
//! programs run): a birth it missed is "not known" at once. And the marks
//! are treated as lost while ftrace is off or such a birth is counted
//! ([`watch_marks`], at every build of the manifest): a signed degradation
//! for the whole period, and once ftrace runs again the marks' epoch is
//! reset (fail closed: every process started before is not known until it
//! exits), signed with the period.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::Instant;

use aya::maps::{Array, HashMap, MapData};
use aya::programs::links::FdLink;
use aya::programs::{BtfTracePoint, FEntry, FExit, Lsm};
use aya::{Btf, Ebpf, EbpfLoader};
use common::cgroup_join::{
    fnv, is_pin_dir_of, lost_slot, parse_pin_dir, unpack, EPOCH_SLOTS, HOW_INJECTED, HOW_PLACE,
    HOW_TAINT, LOST_BYTES, LOST_SLOTS, NAME_CGROUP, NAME_UNIT, PIN_SCHEMA, SILENT_ARMED,
    SILENT_UNSEEN, STAT_INJECTED, STAT_INTO_EXEMPT, STAT_LOST, STAT_ROOTS, STAT_SLOTS,
};
use nn_core::decision::rule_policy::{Exemption, Injected, RulePolicy};
use parking_lot::Mutex;
use tracing::{info, warn};

use crate::anti_tamper::btf_revalidate;

/// The marks (pinned in the tracker's directory).
pub const JOINED_MAP: &str = "CGROUP_JOINED";
/// The "not known" thread groups, a byte each (pinned there).
pub const LOST_MAP: &str = "CGROUP_JOIN_LOST";
/// The counters (pinned there).
pub const STATS_MAP: &str = "CGROUP_JOIN_STATS";
/// The third review of #494 (R2-a): the last reset's instant (pinned there).
pub const EPOCH_MAP: &str = "CGROUP_JOIN_EPOCH";
/// The re-review of #494, R2: the maps pinned in the tracker's directory.
pub const PINNED_MAPS: [&str; 4] = [JOINED_MAP, LOST_MAP, STATS_MAP, EPOCH_MAP];

/// The third review of #494 (R2-b): the tracker's pins this boot, as the
/// start that made or adopted them registered them — the next start adopts
/// nothing else, and (point 3) one that finds it but not its directory
/// knows the pins went between two agents. `/run` holds it for this boot
/// only; the agent protects it like its other files
/// (`anti_tamper::filesystem::register_agent_file`).
pub const STATE_PATH: &str = "/run/northnarrow/cgroup-join-pins";
/// The exemptions' names the kernel matches a destination against.
pub const NAMES_MAP: &str = "CGROUP_EXEMPT_NAMES";
/// Lot 280b: the tracepoint's check of the fentry (per load, not pinned:
/// `common::cgroup_join::SILENT_*`).
pub const SILENT_MAP: &str = "CGROUP_JOIN_SILENT";
/// Lot 281 (#494's N2): the agent's request for a reset of the marks (per
/// load, not pinned, not frozen); the fork program takes it into the
/// pinned, frozen [`EPOCH_MAP`] when it is later.
pub const EPOCH_RT_MAP: &str = "CGROUP_JOIN_EPOCH_RT";

/// How a program of the tracker attaches.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    FExit,
    FEntry,
    /// A BTF tracepoint.
    TpBtf,
    /// Lot 281: a BPF LSM program (it never refuses).
    Lsm,
}

/// The tracker's programs: `(program, how, target)`, in the order a start
/// swaps them for the prior boot's: `cgroup_join_mark` before
/// `cgroup_join_src` (the re-review of #494, N-f) — the new `mark` reads the
/// new, empty source slot until the new `src` writes it, and marks every
/// move meanwhile (more, never less).
///
/// Lot 281: the two LSM programs of the injection taint first — a start
/// that marks the moves before it taints the injections would let an
/// injection meanwhile go unmarked; the prior boot's run until then.
pub const PROGRAMS: [(&str, Kind, &str); 7] = [
    ("cgroup_join_inject", Kind::Lsm, "ptrace_access_check"),
    ("cgroup_join_traceme", Kind::Lsm, "ptrace_traceme"),
    ("cgroup_join_exit", Kind::TpBtf, "sched_process_exit"),
    ("cgroup_join_fork", Kind::TpBtf, "sched_process_fork"),
    ("cgroup_join_born", Kind::FEntry, "cgroup_post_fork"),
    ("cgroup_join_mark", Kind::TpBtf, "cgroup_attach_task"),
    ("cgroup_join_src", Kind::FExit, "cgroup_procs_write_start"),
];

/// The re-review of #494, R2: the program names the agent lists as kept
/// across an upgrade in its own-programs file (`bpf_defense`): pinned
/// outside the pin root, they outlive its purge.
pub fn is_kept_program(name: &str) -> bool {
    PROGRAMS.iter().any(|(n, _, _)| *n == name)
}

/// What a kernel without the tracker loses.
pub const ABSENT_EFFECT: &str =
    "the start-in-cgroup tracker is not attached: every exemption by executable, cgroup or unit \
     of the per-rule policy is refused (a process moved into an exempt service's cgroup could not \
     be told from the service, nor one code was injected into from the program it runs)";

type Joined = HashMap<MapData, u32, [u64; 2]>;
type Lost = Array<MapData, [u8; LOST_BYTES]>;
type Stats = Array<MapData, u64>;
type Epoch = Array<MapData, u64>;
type Names = HashMap<MapData, u64, u8>;
type Silent = Array<MapData, u64>;
type EpochRt = Array<MapData, u64>;

/// The tracker's maps, for the exemption check and the names.
#[derive(Clone)]
pub struct Marks {
    joined: Arc<Mutex<Joined>>,
    lost: Arc<Mutex<Lost>>,
    stats: Arc<Mutex<Stats>>,
    epoch: Arc<Mutex<Epoch>>,
    names: Arc<Mutex<Names>>,
    /// Lot 280b: the births the fentry missed.
    silent: Arc<Mutex<Silent>>,
    /// Lot 281: the agent's reset requests (per load).
    epoch_rt: Arc<Mutex<EpochRt>>,
    /// Lot 281 (#494's N1/N2): no answer is given (every exemption by
    /// executable, cgroup or unit refused) until the tracker is armed —
    /// its pins and its state protected ([`arm`]).
    armed: Arc<AtomicBool>,
}

/// The tracker as this boot has it.
pub enum Tracker {
    Attached(Marks),
    /// Why it is not: the exemptions by cgroup or unit are refused.
    Absent(String),
}

static TRACKER: OnceLock<Tracker> = OnceLock::new();

/// The tracker's pins this boot ([`prepare_pins`]): `Ok` the plan the
/// loader pinned the maps by, `Err` why there is none on a bpffs host (the
/// tracker is then absent); unset without a bpffs.
static PLAN: OnceLock<Result<Plan, String>> = OnceLock::new();

/// The review of #494, D2: the entries the marks get at the object's load
/// — the host's `pid_max` and `threads-max`, the lower
/// (`common::cgroup_join::joined_entries`): no more thread groups can be
/// alive. The re-review of #494 (its point 3): a `debug-trigger` build
/// (the lab's privileged tests, never a release) takes
/// `NN_DEBUG_CGROUP_JOINED_ENTRIES` instead, so that a test can fill the
/// map.
pub fn joined_entries_now() -> u32 {
    #[cfg(feature = "debug-trigger")]
    if let Some(n) = std::env::var("NN_DEBUG_CGROUP_JOINED_ENTRIES")
        .ok()
        .and_then(|v| v.parse::<u32>().ok())
    {
        return n.clamp(1, common::cgroup_join::PID_LIMIT);
    }
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

/// A map of the tracker as a start registered it ([`STATE_PATH`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PinnedMap {
    pub name: String,
    pub id: u32,
    pub max_entries: u32,
}

/// The tracker's pins as the last start of this boot registered them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PinState {
    /// `/proc/sys/kernel/random/boot_id` of the boot.
    pub boot: String,
    pub dir: PathBuf,
    pub maps: Vec<PinnedMap>,
}

impl PinState {
    pub fn render(&self) -> String {
        let mut out = format!(
            "# northnarrow-agent: the start-in-cgroup tracker's pins this boot (lot 277)\nboot {}\ndir {}\n",
            self.boot,
            self.dir.display()
        );
        for m in &self.maps {
            out.push_str(&format!("map {} {} {}\n", m.name, m.id, m.max_entries));
        }
        out
    }

    /// `None` for anything but a whole state.
    pub fn parse(text: &str) -> Option<PinState> {
        let (mut boot, mut dir, mut maps) = (None, None, Vec::new());
        for line in text
            .lines()
            .filter(|l| !l.starts_with('#') && !l.trim().is_empty())
        {
            let mut w = line.split_whitespace();
            match (w.next()?, w.next()?) {
                ("boot", b) => boot = Some(b.to_string()),
                ("dir", d) => dir = Some(PathBuf::from(d)),
                ("map", name) => maps.push(PinnedMap {
                    name: name.to_string(),
                    id: w.next()?.parse().ok()?,
                    max_entries: w.next()?.parse().ok()?,
                }),
                _ => return None,
            }
            if w.next().is_some() {
                return None;
            }
        }
        Some(PinState {
            boot: boot?,
            dir: dir?,
            maps,
        })
    }
}

/// What a start does with the tracker's pins.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Plan {
    /// The directory this start pins the maps in.
    pub dir: PathBuf,
    /// The registered directory, its maps verified: their marks kept.
    pub adopt: bool,
    /// The third review of #494 (R2-a, R2-b, point 3): why the marks of
    /// before are gone — a signed degradation, and every process started
    /// before this start's programs is not known (`CGROUP_JOIN_EPOCH`).
    pub reset: Option<String>,
    /// Signed, no reset: the marks' capacity below the host's (R2-a).
    pub note: Option<String>,
}

/// What `BPF_OBJ_GET_INFO_BY_FD` says of a pinned map.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Seen {
    pub id: u32,
    pub kind: Option<aya::maps::MapType>,
    pub key: u32,
    pub value: u32,
    pub max_entries: u32,
    pub flags: u32,
}

/// The layout of the tracker's map `name` in this schema: kind, key and
/// value sizes, entries when fixed, flags.
fn layout(name: &str) -> Option<(aya::maps::MapType, u32, u32, Option<u32>, u32)> {
    use aya::maps::MapType;
    match name {
        JOINED_MAP => Some((MapType::Hash, 4, 16, None, 1)),
        LOST_MAP => Some((MapType::Array, 4, LOST_BYTES as u32, Some(LOST_SLOTS), 0)),
        STATS_MAP => Some((MapType::Array, 4, 8, Some(STAT_SLOTS), 0)),
        EPOCH_MAP => Some((MapType::Array, 4, 8, Some(EPOCH_SLOTS), 0)),
        _ => None,
    }
}

/// The third review of #494 (R2-b): pinned map `seen` is the one a start
/// registered (`registered`: its id, its entries) and has this schema's
/// layout — a hash with `BPF_F_NO_PREALLOC` and nothing else for the
/// marks, never an LRU one; the arrays at their sizes.
pub fn verify_map(seen: &Seen, registered: &PinnedMap) -> Result<(), String> {
    let (kind, key, value, entries, flags) = layout(&registered.name)
        .ok_or_else(|| format!("{}: not a map of the tracker", registered.name))?;
    let name = &registered.name;
    if seen.id != registered.id {
        return Err(format!(
            "{name}: id {} where {} was registered",
            seen.id, registered.id
        ));
    }
    if seen.kind != Some(kind) {
        return Err(format!("{name}: a {:?} map, not {kind:?}", seen.kind));
    }
    if (seen.key, seen.value) != (key, value) {
        return Err(format!(
            "{name}: key {} value {} bytes, not {key} and {value}",
            seen.key, seen.value
        ));
    }
    if seen.flags != flags {
        return Err(format!("{name}: flags {:#x}, not {flags:#x}", seen.flags));
    }
    if seen.max_entries != registered.max_entries || entries.is_some_and(|e| e != seen.max_entries)
    {
        return Err(format!(
            "{name}: {} entries where {} were registered",
            seen.max_entries, registered.max_entries
        ));
    }
    Ok(())
}

/// The third review of #494: what a start does with the tracker's pins.
/// `state` is the registered one (of boot `boot` only), `dirs` every
/// tracker directory beside `root`, `verify` the check of the registered
/// directory's maps (the marks' entries when they are as registered),
/// `wanted` the marks' entries the host asks for, `debug_entries` a
/// `debug-trigger` build's knob.
///
/// * The registered directory, its maps verified, is adopted, whatever the
///   host's size now (R2-a: the size is a capacity; below the host's, a
///   signed note — the groups past it are not known).
/// * Anything else is a reset in the next generation's directory: the
///   registered one gone (point 3, "marks lost between agents"), its maps
///   not the registered ones or not of this layout (R2-b), another
///   schema's (not migrated: the first schema has no older one), a
///   directory nobody registered — a planted one, or one of a start that
///   could not register (R2-b).
/// * No state and no directory: the first start of this boot.
pub fn plan(
    root: &Path,
    boot: &str,
    state: Option<&PinState>,
    dirs: &[PathBuf],
    verify: &dyn Fn(&PinState) -> Result<u32, String>,
    wanted: u32,
    debug_entries: Option<u32>,
) -> Plan {
    let root_name = root
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    let parsed = |p: &Path| {
        p.file_name()
            .and_then(|n| parse_pin_dir(&root_name, &n.to_string_lossy()))
    };
    let state = state.filter(|s| s.boot == boot);
    let next_gen = dirs
        .iter()
        .map(PathBuf::as_path)
        .chain(state.map(|s| s.dir.as_path()))
        .filter_map(|p| parsed(p).and_then(|(_, g)| g))
        .max()
        .map_or(0, |g| g.saturating_add(1));
    let next = |reset: Option<String>| Plan {
        dir: PathBuf::from(common::cgroup_join::pin_dir(
            &root.to_string_lossy(),
            next_gen,
        )),
        adopt: false,
        reset,
        note: None,
    };
    let Some(st) = state else {
        if dirs.is_empty() {
            return next(None);
        }
        let names: Vec<String> = dirs.iter().map(|d| d.display().to_string()).collect();
        return next(Some(format!(
            "marks reset: a tracker directory no start of this boot registered ({}) is not adopted",
            names.join(", ")
        )));
    };
    let dir = st.dir.display();
    match parsed(&st.dir) {
        Some((schema, Some(_))) if schema == PIN_SCHEMA => {}
        Some((schema, _)) => {
            return next(Some(format!(
                "marks reset: the tracker's maps of schema v{schema} ({dir}) are not migrated to \
                 v{PIN_SCHEMA} (no migration from v{schema})"
            )))
        }
        None => {
            return next(Some(format!(
                "marks reset: the registered {dir} is not a tracker directory"
            )))
        }
    }
    if !dirs.contains(&st.dir) {
        return next(Some(format!(
            "marks lost between agents: {dir}, registered by the previous start of this boot, is gone"
        )));
    }
    let entries = match verify(st) {
        Ok(n) => n,
        Err(why) => {
            return next(Some(format!(
                "marks reset: the registered {dir} does not hold the maps registered ({why})"
            )))
        }
    };
    if let Some(n) = debug_entries.filter(|n| *n != entries) {
        // A `debug-trigger` build's test of a full map: new maps at its
        // size, signed, but no epoch — the test harness that started
        // before them must not see its own children not known.
        let mut p = next(None);
        p.note = Some(format!(
            "a debug build asked for {n} marks, {entries} are pinned: new maps (debug-trigger \
             builds only)"
        ));
        return p;
    }
    Plan {
        dir: st.dir.clone(),
        adopt: true,
        reset: None,
        note: (entries < wanted).then(|| {
            format!(
                "the marks' capacity ({entries}, fixed when the map was made) is below the host's \
                 ({wanted}: kernel.pid_max or kernel.threads-max raised since): past it, a process \
                 asking for a mark is not known"
            )
        }),
    }
}

/// `/proc/sys/kernel/random/boot_id`.
pub(crate) fn boot_id() -> String {
    std::fs::read_to_string("/proc/sys/kernel/random/boot_id")
        .map(|s| s.trim().to_string())
        .unwrap_or_default()
}

/// What `BPF_OBJ_GET_INFO_BY_FD` says of the map pinned at `path` (opened
/// read-only).
pub(crate) fn seen_at(path: &Path) -> Result<Seen, String> {
    let md = open_pinned_ro(path)?;
    let info = md.info().map_err(|e| e.to_string())?;
    Ok(Seen {
        id: info.id(),
        kind: info.map_type().ok(),
        key: info.key_size(),
        value: info.value_size(),
        max_entries: info.max_entries(),
        flags: info.map_flags(),
    })
}

/// The registered directory's maps, each the one registered in this
/// layout, no other file but the programs' pins: the marks' entries.
fn verify_state(st: &PinState) -> Result<u32, String> {
    if let Some(why) = antitamper_bpf::pin_root_refusal_at(&st.dir) {
        return Err(why);
    }
    let mut entries = None;
    for name in PINNED_MAPS {
        let reg = st
            .maps
            .iter()
            .find(|m| m.name == name)
            .ok_or_else(|| format!("{name} not registered"))?;
        verify_map(&seen_at(&st.dir.join(name))?, reg)?;
        if name == JOINED_MAP {
            entries = Some(reg.max_entries);
        }
    }
    for e in std::fs::read_dir(&st.dir)
        .map_err(|e| e.to_string())?
        .flatten()
    {
        let n = e.file_name().to_string_lossy().into_owned();
        if !is_tracker_pin(&n) {
            return Err(format!("{n}: not a pin of the tracker"));
        }
    }
    entries.ok_or_else(|| "no marks".to_string())
}

/// `name` is one of the files a tracker directory holds: a map of
/// [`PINNED_MAPS`], or a program's `prog_`/`link_` pin.
fn is_tracker_pin(name: &str) -> bool {
    PINNED_MAPS.contains(&name)
        || PROGRAMS
            .iter()
            .any(|(p, _, _)| name == format!("prog_{p}") || name == format!("link_{p}"))
}

/// The third review of #494 (R2-d): `dir` usable for the tracker's pins —
/// never a symbolic link or anything but a directory, created `0700`.
pub(crate) fn usable_dir(dir: &Path) -> Result<(), String> {
    if let Some(why) = antitamper_bpf::pin_root_refusal_at(dir) {
        return Err(why);
    }
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
    match std::fs::DirBuilder::new().mode(0o700).create(dir) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(e) => return Err(format!("creating {}: {e}", dir.display())),
    }
    match std::fs::symlink_metadata(dir) {
        Ok(m) if m.is_dir() && !m.file_type().is_symlink() => {
            if m.permissions().mode() & 0o7777 != 0o700 {
                let _ = std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700));
            }
            Ok(())
        }
        Ok(_) => Err(format!("{} is not a directory", dir.display())),
        Err(e) => Err(format!("{}: {e}", dir.display())),
    }
}

/// The re-review of #494 (R2) and its third review: before the object's
/// load, what this start does with the tracker's pins ([`plan`]) — the
/// registered directory adopted, its maps verified, or a new one. Nothing
/// is removed here: the agent is not a protected pid yet, and a reset
/// directory goes once the new programs run ([`attach`]). Without a bpffs
/// (`pin_root` `None`) the maps are this process's.
///
/// Lot 281 (#494's N1): only an adoption tells the loader to take the
/// registered pins ([`PINNED_MAPS`], their ids checked again after the
/// load); a new generation's maps are made by the load and pinned after it
/// ([`attach`]), its directory made then — never one the loader would take
/// a planted map from.
pub fn prepare_pins(loader: &mut EbpfLoader<'_>, pin_root: Option<&Path>, entries: u32) {
    let Some(root) = pin_root else {
        return;
    };
    let _ = PLANNED_AT.set(Instant::now());
    let plan = PLAN.get_or_init(|| {
        let state = std::fs::read_to_string(STATE_PATH)
            .ok()
            .and_then(|t| PinState::parse(&t));
        // A `debug-trigger` build's test of a reset: the registered maps
        // taken for not the registered ones, so the reset — the epoch with
        // it — is the production one.
        let verify = |st: &PinState| {
            if debug_reset() {
                return Err("a debug build asked for a reset".to_string());
            }
            verify_state(st)
        };
        let p = plan(
            root,
            &boot_id(),
            state.as_ref(),
            &other_pin_dirs(root, None),
            &verify,
            entries,
            debug_entries(),
        );
        if p.adopt {
            usable_dir(&p.dir)?;
            if let Some(st) = state.filter(|st| st.dir == p.dir) {
                let _ = ADOPTED.set(st);
            }
        }
        Ok(p)
    });
    if let Ok(p) = plan {
        if p.adopt {
            for name in PINNED_MAPS {
                loader.map_pin_path(name, p.dir.join(name));
            }
        }
    }
}

/// Lot 281 (#494's N1): the registered state an adoption verified before
/// the load — the maps the load took are checked against it after.
static ADOPTED: OnceLock<PinState> = OnceLock::new();

/// Lot 281: when [`prepare_pins`] planned (the arming's measure).
static PLANNED_AT: OnceLock<Instant> = OnceLock::new();

/// Lot 281 (#494's N1): the directory this start pinned in — the plan's, or
/// a later generation's when a plant was found in it.
static FINAL_DIR: OnceLock<PathBuf> = OnceLock::new();

/// Lot 281 (#494's N1): generations a new directory is tried in before the
/// tracker is given up (absent: fail closed, signed).
pub const NEW_DIR_ATTEMPTS: u32 = 4;

/// A `debug-trigger` build's knob ([`joined_entries_now`]).
fn debug_entries() -> Option<u32> {
    #[cfg(feature = "debug-trigger")]
    if let Some(n) = std::env::var("NN_DEBUG_CGROUP_JOINED_ENTRIES")
        .ok()
        .and_then(|v| v.parse::<u32>().ok())
    {
        return Some(n.clamp(1, common::cgroup_join::PID_LIMIT));
    }
    None
}

/// A `debug-trigger` build's `NN_DEBUG_CGROUP_JOIN_RESET=1`: this start
/// resets the marks (the privileged test of the epoch). Never in a release.
fn debug_reset() -> bool {
    #[cfg(feature = "debug-trigger")]
    if std::env::var("NN_DEBUG_CGROUP_JOIN_RESET").as_deref() == Ok("1") {
        return true;
    }
    false
}

/// The tracker's pin directory this boot, once [`attach`] pinned in it
/// (before: the one [`prepare_pins`] planned).
pub fn pin_dir_now() -> Option<&'static Path> {
    FINAL_DIR.get().map(PathBuf::as_path).or_else(|| {
        PLAN.get()
            .and_then(|r| r.as_ref().ok())
            .map(|p| p.dir.as_path())
    })
}

/// Register this start's pins in [`STATE_PATH`] (atomically, `0600`): the
/// directory and each map's id and entries, as the kernel gives them.
fn register_pins(dir: &Path) -> Result<(), String> {
    let mut maps = Vec::new();
    for name in PINNED_MAPS {
        let seen = seen_at(&dir.join(name))?;
        maps.push(PinnedMap {
            name: name.to_string(),
            id: seen.id,
            max_entries: seen.max_entries,
        });
    }
    let st = PinState {
        boot: boot_id(),
        dir: dir.to_path_buf(),
        maps,
    };
    let path = Path::new(STATE_PATH);
    if let Some(parent) = path.parent() {
        use std::os::unix::fs::DirBuilderExt;
        let _ = std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(parent);
    }
    crate::atomic_file::replace(path, st.render().as_bytes(), 0o600).map_err(|e| format!("{e:#}"))
}

/// `clock` now, in ns.
fn clock_ns(clock: libc::clockid_t) -> Result<u64, String> {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: a valid out-parameter for clock_gettime.
    if unsafe { libc::clock_gettime(clock, &mut ts) } != 0 {
        return Err(std::io::Error::last_os_error().to_string());
    }
    Ok(ts.tv_sec as u64 * 1_000_000_000 + ts.tv_nsec as u64)
}

/// The third review of #494 (R2-a): this instant as the marks' last reset
/// — `[monotonic, boot time]` ns, once the new programs run: a process
/// started before it is not known. Lot 281 (#494's N2): asked for in
/// `CGROUP_JOIN_EPOCH_RT`; the fork program takes it into the pinned,
/// frozen `CGROUP_JOIN_EPOCH` at the next fork (forward only).
fn set_epoch(ebpf: &mut Ebpf) -> Result<(), String> {
    let map = ebpf
        .map_mut(EPOCH_RT_MAP)
        .ok_or_else(|| format!("map {EPOCH_RT_MAP} missing from the eBPF object"))?;
    let mut arr: Array<&mut MapData, u64> = Array::try_from(map).map_err(|e| e.to_string())?;
    write_epoch(&mut arr)?;
    promote_now();
    Ok(())
}

/// Lot 281 (#494's N2): a fork of the agent's own, so that the fork program
/// takes the request into the pinned epoch now — any fork on the host would
/// soon (the agent reads the later of the two meanwhile). Best effort: the
/// child only `_exit`s.
fn promote_now() {
    // SAFETY: fork(2); the child calls only `_exit` (async-signal-safe),
    // the parent reaps it.
    unsafe {
        let pid = libc::fork();
        if pid == 0 {
            libc::_exit(0);
        }
        if pid > 0 {
            let mut status = 0;
            libc::waitpid(pid, &mut status, 0);
        }
    }
}

/// [`set_epoch`]'s write, into the map however it is held (the start's
/// object, the running tracker's [`Marks`]): boot time first, so that the
/// kernel's monotonic slot — the one a fork reads — never names an epoch
/// the agent's slot does not.
fn write_epoch<M: std::borrow::BorrowMut<MapData>>(arr: &mut Array<M, u64>) -> Result<(), String> {
    let (mono, boot) = (
        clock_ns(libc::CLOCK_MONOTONIC)?,
        clock_ns(libc::CLOCK_BOOTTIME)?,
    );
    arr.set(1, boot, 0).map_err(|e| e.to_string())?;
    arr.set(0, mono, 0).map_err(|e| e.to_string())
}

/// Lot 280b: the fork's check of the fentry armed at this instant
/// (`CGROUP_JOIN_SILENT[SILENT_ARMED]`, `CLOCK_MONOTONIC` ns: a task's
/// start time's clock).
fn arm_silent(ebpf: &mut Ebpf) -> Result<(), String> {
    let map = ebpf
        .map_mut(SILENT_MAP)
        .ok_or_else(|| format!("map {SILENT_MAP} missing from the eBPF object"))?;
    let mut arr: Array<&mut MapData, u64> = Array::try_from(map).map_err(|e| e.to_string())?;
    arr.set(SILENT_ARMED, clock_ns(libc::CLOCK_MONOTONIC)?, 0)
        .map_err(|e| e.to_string())
}

/// The tracker pin directories beside `pin_root` other than `keep`: those
/// of another layout, an earlier version's.
fn other_pin_dirs(pin_root: &Path, keep: Option<&Path>) -> Vec<PathBuf> {
    let (Some(parent), Some(root_name)) = (pin_root.parent(), pin_root.file_name()) else {
        return Vec::new();
    };
    let root_name = root_name.to_string_lossy();
    let Ok(entries) = std::fs::read_dir(parent) else {
        return Vec::new();
    };
    let mut out: Vec<PathBuf> = entries
        .flatten()
        .filter(|e| is_pin_dir_of(&root_name, &e.file_name().to_string_lossy()))
        .map(|e| e.path())
        .filter(|p| Some(p.as_path()) != keep)
        .collect();
    out.sort();
    out
}

/// Remove tracker pin directory `dir`: its links first (their programs
/// detach), then the rest, then the directory. The agent is a protected
/// pid by then; a pin it cannot remove is logged. Lot 281: a directory in
/// it (a plant at a pin's path, #494's N1) goes the same way, a few levels
/// deep at most.
fn purge_pin_dir(dir: &Path) {
    purge_pin_dir_at(dir, 4);
}

fn purge_pin_dir_at(dir: &Path, depth: u32) {
    // The third review of #494 (R2-d): a link is removed, never followed
    // (its target's files are another's).
    if std::fs::symlink_metadata(dir).is_ok_and(|m| !m.is_dir() || m.file_type().is_symlink()) {
        antitamper_bpf::purge_stale_pin(dir);
        return;
    }
    let mut files: Vec<PathBuf> = std::fs::read_dir(dir)
        .map(|r| r.flatten().map(|e| e.path()).collect())
        .unwrap_or_default();
    files.sort_by_key(|p| {
        !p.file_name()
            .is_some_and(|n| n.to_string_lossy().starts_with("link_"))
    });
    for f in &files {
        match std::fs::symlink_metadata(f) {
            Ok(m) if m.is_dir() && depth > 0 => purge_pin_dir_at(f, depth - 1),
            _ => antitamper_bpf::purge_stale_pin(f),
        }
    }
    if let Err(e) = std::fs::remove_dir(dir) {
        if e.kind() != std::io::ErrorKind::NotFound {
            warn!(error = %e, dir = %dir.display(), "cgroup exemptions: an old tracker pin directory NOT removed");
        }
    }
}

/// The pins this module made in the pin root itself before the re-review of
/// #494 (R2): an upgrade's purge took them.
fn purge_legacy_pins(pin_root: &Path) {
    for (name, _, _) in &PROGRAMS {
        let (prog, link) = pin_paths(pin_root, name);
        antitamper_bpf::purge_stale_pin(&link);
        antitamper_bpf::purge_stale_pin(&prog);
    }
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
        Kind::Lsm => <&mut Lsm>::try_from(prog)
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
        Kind::Lsm => {
            let p = <&mut Lsm>::try_from(prog).map_err(|e| e.to_string())?;
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
        Kind::Lsm => <&mut Lsm>::try_from(prog).map(|p| p.unload()),
    };
}

/// Attach the tracker's programs, all or none (a mark that no fork passes
/// on, or that no exit removes, is worse than none: the agent would trust
/// what it does not see), and take its maps. The tracker's state for the
/// boot, which the caller [`install`]s, and — the re-review of #494, R2 —
/// why the marks of before this start are gone, if they are: a signed
/// degradation for the caller.
///
/// The review of #494, D6: with a bpffs, each program's link is pinned in
/// the tracker's directory ([`prepare_pins`]) — the tracker keeps marking
/// while no agent runs (a restart, an upgrade: the directory is not the pin
/// root, which an upgrade purges). The five programs are loaded first and
/// only then attached and pinned one by one, each after its predecessor of
/// the prior boot is still running: a load refused leaves the prior boot's
/// pinned tracker as it was. A tracker directory of another layout (another
/// schema, another size) goes once the new programs run: its marks with it.
pub fn attach(ebpf: &mut Ebpf, btf: &Btf, pin_root: Option<&Path>) -> (Tracker, Vec<String>) {
    if let Some(why) = unavailable() {
        warn!(reason = %why, effect = ABSENT_EFFECT, "cgroup exemptions: tracker not attached");
        // A prior boot's pinned tracker goes too: no program of an older
        // agent stays attached where this one would not attach.
        if let Some(root) = pin_root {
            purge_legacy_pins(root);
            for d in other_pin_dirs(root, None) {
                purge_pin_dir(&d);
            }
        }
        return (Tracker::Absent(why), Vec::new());
    }
    let mut signed = Vec::new();
    match (pin_root, PLAN.get()) {
        (Some(_), Some(Err(why))) => {
            warn!(reason = %why, effect = ABSENT_EFFECT, "cgroup exemptions: tracker pin directory refused");
            return (
                Tracker::Absent(format!("the tracker's pin directory: {why}")),
                Vec::new(),
            );
        }
        (Some(root), Some(Ok(plan))) => {
            for (i, (name, kind, target)) in PROGRAMS.iter().enumerate() {
                if let Err(e) = load_only(ebpf, btf, name, *kind, target) {
                    for (n, k, _) in &PROGRAMS[..=i] {
                        unload(ebpf, n, *k);
                    }
                    warn!(error = %e, effect = ABSENT_EFFECT, "cgroup exemptions: tracker load FAILED");
                    return (Tracker::Absent(e), Vec::new());
                }
            }
            // Lot 281 (#494's N1/N2): the maps frozen before anything can
            // reach them by a pin — a handle on them, taken now or in any
            // window after, writes nothing; an adoption's maps checked to be
            // the ones registered, and frozen if they were not.
            let fail = |ebpf: &mut Ebpf, why: String, signed: Vec<String>| {
                for (n, k, _) in &PROGRAMS {
                    unload(ebpf, n, *k);
                }
                warn!(reason = %why, effect = ABSENT_EFFECT, "cgroup exemptions: tracker NOT attached");
                (Tracker::Absent(why), signed)
            };
            if plan.adopt {
                if let Err(why) = adopted_as_registered(ebpf, ADOPTED.get()) {
                    return fail(
                        ebpf,
                        format!("the adopted tracker maps are not the ones verified: {why}"),
                        vec![format!(
                            "the tracker's registered maps changed between their check and the \
                             load ({why}): no tracker this boot; the next start resets the marks"
                        )],
                    );
                }
            }
            match freeze_pinned(ebpf) {
                Ok(unfrozen) if plan.adopt && !unfrozen.is_empty() => signed.push(format!(
                    "the adopted tracker maps {} were not frozen (no start of this version made \
                     them): frozen now — a handle taken on them before writes nothing from now",
                    unfrozen.join(", ")
                )),
                Ok(_) => {}
                Err(e) => {
                    return fail(ebpf, format!("the tracker's maps not frozen: {e}"), signed);
                }
            }
            let dir = if plan.adopt {
                plan.dir.clone()
            } else {
                match pin_new(ebpf, root, &plan.dir) {
                    Ok((d, planted)) => {
                        signed.extend(planted);
                        d
                    }
                    Err((why, planted)) => {
                        signed.extend(planted);
                        return fail(ebpf, why, signed);
                    }
                }
            };
            let _ = FINAL_DIR.set(dir.clone());
            let dir = dir.as_path();
            for (name, kind, _) in &PROGRAMS {
                if let Err(e) = pin_fresh(ebpf, dir, name, *kind) {
                    warn!(program = name, error = %e, effect = ABSENT_EFFECT, "cgroup exemptions: tracker attach or pin FAILED");
                    return (Tracker::Absent(e), signed);
                }
            }
            // The third review of #494 (R2-a): a reset makes every process
            // started before this instant not known — written once the new
            // programs run, so that nothing starts unseen between the two.
            // Without it the reset would give the marked their exemption
            // back: no tracker then (fail closed).
            if let Some(why) = &plan.reset {
                if let Err(e) = set_epoch(ebpf) {
                    warn!(error = %e, effect = ABSENT_EFFECT, "cgroup exemptions: the reset's epoch NOT written");
                    return (
                        Tracker::Absent(format!("the reset's epoch not written: {e}")),
                        vec![why.clone()],
                    );
                }
                warn!(reason = %why, "cgroup exemptions: marks reset — every process started before now is not known until it exits");
                signed.push(format!(
                    "{why}; every process started before this start is not known (refused an \
                     exemption by executable, cgroup or unit) until it exits — restart the exempt \
                     services"
                ));
            }
            if let Some(note) = &plan.note {
                warn!(note = %note, "cgroup exemptions: the marks' capacity is below the host's");
                signed.push(note.clone());
            }
            purge_legacy_pins(root);
            let others = other_pin_dirs(root, Some(dir));
            if !others.is_empty() {
                let names: Vec<String> = others.iter().map(|d| d.display().to_string()).collect();
                for d in &others {
                    purge_pin_dir(d);
                }
                if plan.reset.is_none() {
                    let why = format!(
                        "an unregistered tracker directory beside the pin root removed ({})",
                        names.join(", ")
                    );
                    warn!(reason = %why, "cgroup exemptions: {why}");
                    signed.push(why);
                }
            }
            if let Err(e) = register_pins(dir) {
                warn!(error = %e, "cgroup exemptions: the tracker's pins NOT registered — the next start resets the marks");
            }
        }
        _ => {
            for (i, (name, kind, target)) in PROGRAMS.iter().enumerate() {
                if let Err(e) = load_attach(ebpf, btf, name, *kind, target) {
                    for (n, k, _) in &PROGRAMS[..=i] {
                        unload(ebpf, n, *k);
                    }
                    warn!(error = %e, effect = ABSENT_EFFECT, "cgroup exemptions: tracker attach FAILED");
                    return (Tracker::Absent(e), Vec::new());
                }
            }
            if let Err(e) = freeze_pinned(ebpf) {
                for (n, k, _) in &PROGRAMS {
                    unload(ebpf, n, *k);
                }
                warn!(error = %e, effect = ABSENT_EFFECT, "cgroup exemptions: the tracker's maps NOT frozen");
                return (
                    Tracker::Absent(format!("the tracker's maps not frozen: {e}")),
                    Vec::new(),
                );
            }
            warn!("cgroup exemptions: tracker attached WITHOUT pin (no bpffs): not kept while no agent runs");
        }
    }
    // Lot 280b: the fork's check of the fentry armed now that this start's
    // programs run (and the prior boot's are gone): a child that starts
    // after this instant was seen by the fentry unless ftrace is off. Not
    // armed, the check counts nothing — a signed degradation.
    if let Err(e) = arm_silent(ebpf) {
        warn!(error = %e, "cgroup exemptions: the ftrace check of the tracker NOT armed");
        signed.push(format!(
            "the tracker's ftrace check is not armed ({e}): a birth the fentry misses while \
             kernel.ftrace_enabled is 0 is not counted (the manifest's ftrace read still is)"
        ));
    }
    let take = |ebpf: &mut Ebpf, name: &str| {
        ebpf.take_map(name)
            .ok_or_else(|| format!("map {name} missing from the eBPF object"))
    };
    let maps = (|| -> Result<Marks, String> {
        let joined = Joined::try_from(take(ebpf, JOINED_MAP)?).map_err(|e| e.to_string())?;
        let lost = Lost::try_from(take(ebpf, LOST_MAP)?).map_err(|e| e.to_string())?;
        let stats = Stats::try_from(take(ebpf, STATS_MAP)?).map_err(|e| e.to_string())?;
        let epoch = Epoch::try_from(take(ebpf, EPOCH_MAP)?).map_err(|e| e.to_string())?;
        let names = Names::try_from(take(ebpf, NAMES_MAP)?).map_err(|e| e.to_string())?;
        let silent = Silent::try_from(take(ebpf, SILENT_MAP)?).map_err(|e| e.to_string())?;
        let epoch_rt = EpochRt::try_from(take(ebpf, EPOCH_RT_MAP)?).map_err(|e| e.to_string())?;
        Ok(Marks {
            joined: Arc::new(Mutex::new(joined)),
            lost: Arc::new(Mutex::new(lost)),
            stats: Arc::new(Mutex::new(stats)),
            epoch: Arc::new(Mutex::new(epoch)),
            names: Arc::new(Mutex::new(names)),
            silent: Arc::new(Mutex::new(silent)),
            epoch_rt: Arc::new(Mutex::new(epoch_rt)),
            armed: Arc::new(AtomicBool::new(false)),
        })
    })();
    match maps {
        Ok(m) => {
            info!(
                programs = PROGRAMS.len(),
                pinned = pin_dir_now().map(|d| d.display().to_string()),
                "cgroup exemptions: the start-in-cgroup tracker is attached (moves into a cgroup \
                 and CLONE_INTO_CGROUP starts outside systemd are marked, with what they fork)"
            );
            (Tracker::Attached(m), signed)
        }
        Err(e) => {
            for (n, k, _) in &PROGRAMS {
                unload(ebpf, n, *k);
            }
            warn!(error = %e, effect = ABSENT_EFFECT, "cgroup exemptions: tracker maps unavailable");
            (Tracker::Absent(e), signed)
        }
    }
}

/// Lot 281: the tracker's map `name` in the loaded object.
fn map_data<'a>(ebpf: &'a Ebpf, name: &str) -> Result<&'a MapData, String> {
    match ebpf.map(name) {
        Some(aya::maps::Map::HashMap(d)) | Some(aya::maps::Map::Array(d)) => Ok(d),
        Some(_) => Err(format!("{name}: not the kind of map the tracker has")),
        None => Err(format!("map {name} missing from the eBPF object")),
    }
}

/// Lot 281 (#494's N1): the maps the load took for an adoption are the ones
/// the registered state names (`registered`, verified before the load) —
/// not a map swapped in at a pin between the check and the load.
fn adopted_as_registered(ebpf: &Ebpf, registered: Option<&PinState>) -> Result<(), String> {
    let st = registered.ok_or("no registered state was verified")?;
    let mut loaded = Vec::new();
    for name in PINNED_MAPS {
        let id = map_data(ebpf, name)?
            .info()
            .map_err(|e| format!("{name}: {e}"))?
            .id();
        loaded.push((name, id));
    }
    ids_as_registered(st, &loaded)
}

/// Lot 281 (#494's N1): each of the tracker's maps the load took
/// (`loaded`: name, id) is the one `st` registered.
pub fn ids_as_registered(st: &PinState, loaded: &[(&str, u32)]) -> Result<(), String> {
    for name in PINNED_MAPS {
        let reg = st
            .maps
            .iter()
            .find(|m| m.name == name)
            .ok_or_else(|| format!("{name} not registered"))?;
        let id = loaded
            .iter()
            .find(|(n, _)| *n == name)
            .map(|(_, id)| *id)
            .ok_or_else(|| format!("{name} not loaded"))?;
        if id != reg.id {
            return Err(format!("{name}: id {id} where {} was registered", reg.id));
        }
    }
    Ok(())
}

/// What a `BPF_MAP_FREEZE` gave.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Freeze {
    /// Frozen now.
    Now,
    /// Frozen before (`EBUSY`): a start of this version made it.
    Already,
}

/// The outcome of `BPF_MAP_FREEZE` as the kernel answered it (`errno` 0 for
/// success) — `EBUSY` is a map frozen by another between our read of its
/// state and the call; anything else a failure. (A map frozen before the
/// call answers `EPERM`, not `EBUSY`: `map_freeze` checks the descriptor's
/// write right, which a frozen map has lost, first — lot 281's lab; hence
/// [`fdinfo_frozen`] before the call.)
pub fn freeze_outcome(errno: i32) -> Result<Freeze, String> {
    match errno {
        0 => Ok(Freeze::Now),
        libc::EBUSY => Ok(Freeze::Already),
        e => Err(std::io::Error::from_raw_os_error(e).to_string()),
    }
}

/// Lot 281: a map's `frozen` state as its descriptor's fdinfo says it
/// (`frozen:\t1`, 5.2+); `None` when the line is not there.
pub fn fdinfo_frozen(fdinfo: &str) -> Option<bool> {
    fdinfo
        .lines()
        .find_map(|l| l.strip_prefix("frozen:"))
        .and_then(|v| match v.trim() {
            "1" => Some(true),
            "0" => Some(false),
            _ => None,
        })
}

/// Lot 281 (#494's N2): every pinned map of the tracker frozen
/// (`BPF_MAP_FREEZE`): no handle — the agent's, one a root took in a window
/// or an upgrade's gap, a planted map's maker's — writes it from now; the
/// tracker's programs still do. A map already frozen (an adoption's: the
/// start that made it froze it) is left as it is — its state read from the
/// descriptor's fdinfo; one whose state cannot be read is a failure (no
/// tracker: fail closed). The maps that were not frozen before.
fn freeze_pinned(ebpf: &Ebpf) -> Result<Vec<&'static str>, String> {
    use std::os::fd::{AsFd, AsRawFd};
    const MAP_FREEZE: libc::c_long = common::bpf_cmd::BPF_MAP_FREEZE as libc::c_long;
    #[repr(C)]
    struct FreezeAttr {
        map_fd: u32,
    }
    let mut unfrozen = Vec::new();
    for name in PINNED_MAPS {
        let fd = map_data(ebpf, name)?.fd().as_fd().as_raw_fd();
        let info = std::fs::read_to_string(format!("/proc/self/fdinfo/{fd}"))
            .map_err(|e| format!("{name}: its fdinfo: {e}"))?;
        match fdinfo_frozen(&info) {
            Some(true) => continue,
            Some(false) => {}
            None => return Err(format!("{name}: no frozen state in its fdinfo")),
        }
        let attr = FreezeAttr { map_fd: fd as u32 };
        // SAFETY: bpf(BPF_MAP_FREEZE) with a valid, fully initialised
        // attribute block of its exact size; the fd is borrowed from the
        // live map.
        let rc = unsafe {
            libc::syscall(
                libc::SYS_bpf,
                MAP_FREEZE,
                &attr as *const FreezeAttr as *const libc::c_void,
                std::mem::size_of::<FreezeAttr>() as u32,
            )
        };
        let errno = if rc < 0 {
            std::io::Error::last_os_error().raw_os_error().unwrap_or(-1)
        } else {
            0
        };
        if freeze_outcome(errno).map_err(|e| format!("{name}: {e}"))? == Freeze::Now {
            unfrozen.push(name);
        }
    }
    Ok(unfrozen)
}

/// Lot 281 (#494's N1): the next generation's directory after `dir`, above
/// every tracker directory beside `root` now (a plant made since the plan
/// included).
fn next_dir(root: &Path, dir: &Path) -> PathBuf {
    let root_name = root
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    let gen = |p: &Path| {
        p.file_name()
            .and_then(|n| parse_pin_dir(&root_name, &n.to_string_lossy()))
            .and_then(|(_, g)| g)
    };
    let top = other_pin_dirs(root, None)
        .iter()
        .map(PathBuf::as_path)
        .chain(std::iter::once(dir))
        .filter_map(gen)
        .max()
        .unwrap_or(0);
    PathBuf::from(common::cgroup_join::pin_dir(
        &root.to_string_lossy(),
        top.saturating_add(1),
    ))
}

/// Lot 281 (#494's N1): `dir` made by this start — `0700`, never a link —
/// for a new generation: one that exists already is a plant (nothing named
/// it before the plan's listing).
fn fresh_dir(dir: &Path) -> Result<(), String> {
    if let Some(why) = antitamper_bpf::pin_root_refusal_at(dir) {
        return Err(why);
    }
    use std::os::unix::fs::DirBuilderExt;
    match std::fs::DirBuilder::new().mode(0o700).create(dir) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => Err(format!(
            "{} exists already: made by someone else between the plan and the load",
            dir.display()
        )),
        Err(e) => Err(format!("creating {}: {e}", dir.display())),
    }
}

/// Lot 281 (#494's N1): what a new directory holds that the tracker did not
/// pin there — after its maps were pinned, nothing but them.
pub fn foreign_entries(names: &[String]) -> Vec<String> {
    names
        .iter()
        .filter(|n| !PINNED_MAPS.contains(&n.as_str()))
        .cloned()
        .collect()
}

/// Lot 281 (#494's N1): the new generation's maps — made by the load,
/// frozen — pinned after it, in a directory this start made: `dir`, or the
/// next generation's when a plant is found in it (a file at a pin's path:
/// `BPF_OBJ_PIN` refuses with `EEXIST`; anything else in it), each one
/// signed. The plants go with their directory once the programs run (an
/// unregistered tracker directory). The directory and the signed lines;
/// past [`NEW_DIR_ATTEMPTS`], no tracker (fail closed).
fn pin_new(
    ebpf: &Ebpf,
    root: &Path,
    dir: &Path,
) -> Result<(PathBuf, Vec<String>), (String, Vec<String>)> {
    let mut signed = Vec::new();
    let mut dir = dir.to_path_buf();
    for attempt in 0..NEW_DIR_ATTEMPTS {
        let tried = (|| -> Result<(), String> {
            fresh_dir(&dir)?;
            if attempt == 0 {
                debug_plant(&dir);
            }
            for name in PINNED_MAPS {
                map_data(ebpf, name)?
                    .pin(dir.join(name))
                    .map_err(|e| format!("pinning {name}: {e}"))?;
            }
            let names: Vec<String> = std::fs::read_dir(&dir)
                .map_err(|e| e.to_string())?
                .flatten()
                .map(|e| e.file_name().to_string_lossy().into_owned())
                .collect();
            let foreign = foreign_entries(&names);
            if !foreign.is_empty() {
                return Err(format!("{} planted in it", foreign.join(", ")));
            }
            Ok(())
        })();
        match tried {
            Ok(()) => return Ok((dir, signed)),
            Err(why) => {
                let next = next_dir(root, &dir);
                warn!(dir = %dir.display(), reason = %why, next = %next.display(), "cgroup exemptions: the new tracker directory was not the tracker's alone (a plant in it) — its maps go to the next generation");
                signed.push(format!(
                    "the new tracker directory {} was not the tracker's alone ({why}): never \
                     adopted, its maps pinned in {} instead",
                    dir.display(),
                    next.display()
                ));
                dir = next;
            }
        }
    }
    Err((
        format!("no new tracker directory free of plants after {NEW_DIR_ATTEMPTS} tries"),
        signed,
    ))
}

/// A `debug-trigger` build's `NN_DEBUG_CGROUP_JOIN_PLANT=1`: a plant made
/// in the new directory between its making and its maps' pinning (a
/// directory at the marks' pin path, as a root watching the bpffs could) —
/// the privileged test of #494's N1. Never in a release.
fn debug_plant(_dir: &Path) {
    #[cfg(feature = "debug-trigger")]
    if std::env::var("NN_DEBUG_CGROUP_JOIN_PLANT").as_deref() == Ok("1") {
        let r = std::fs::create_dir(_dir.join(JOINED_MAP));
        warn!(
            dir = %_dir.display(),
            planted = r.is_ok(),
            "cgroup exemptions: debug — a plant in the new tracker directory"
        );
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
        Kind::Lsm => <&mut Lsm>::try_from(prog)
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
    /// The writer of the move, the forker of the start, or the parent —
    /// lot 281: the injector (the parent, for an inherited taint).
    pub by: u32,
}

impl Mark {
    /// Lot 277: it does not run where it started (moved, born into its
    /// cgroup, or forked from one that was) — the placement bits.
    pub fn placed(&self) -> bool {
        self.how & HOW_PLACE != 0
    }

    /// Lot 281: what its taint bits say of its code.
    pub fn injected(&self) -> Injected {
        if self.how & HOW_TAINT == 0 {
            Injected::No
        } else {
            Injected::Yes {
                by: self.by,
                inherited: self.how & HOW_INJECTED == 0,
            }
        }
    }
}

/// Lot 281: the exemption check's two questions on one group's mark —
/// `started` (lot 277: `Some(true)` it runs where it started) and
/// `injected` — from `lost` (its byte), `after` (started after the marks'
/// last reset) and `mark`, as read: not known (`None`) when the group is
/// lost, started before the reset, or its mark unread.
pub fn judge(
    lost: Option<bool>,
    after: bool,
    mark: Result<Option<Mark>, ()>,
) -> Option<(bool, Injected)> {
    if lost != Some(false) || !after {
        return None;
    }
    match mark {
        Ok(None) => Some((true, Injected::No)),
        Ok(Some(m)) => Some((!m.placed(), m.injected())),
        Err(()) => None,
    }
}

impl Marks {
    /// Lot 277: the exemption check's question for thread group `tgid`, in
    /// one errand (the decision thread's filter refuses `bpf`):
    /// `Some(true)` not marked, `Some(false)` marked, `None` not known — the
    /// group's mark could not be taken (its bit in `CGROUP_JOIN_LOST`: that
    /// tree only, the review of #494, D2), a failed read, no answer in time.
    ///
    /// Lot 281: a mark of the taint alone (code injected into a process
    /// started where it runs) is "started here" — the exemption is then
    /// refused by [`Self::injected`], which says why. Nothing is known
    /// until the tracker is armed ([`arm`]).
    pub fn started(&self, tgid: u32, start_boot_ns: Option<u64>) -> Option<bool> {
        self.both(tgid, start_boot_ns).map(|(s, _)| s)
    }

    /// Lot 281: the injection taint of thread group `tgid`, in one errand —
    /// `None` not known (not armed, the group lost, started before the
    /// marks' last reset, a failed read).
    pub fn injected(&self, tgid: u32, start_boot_ns: Option<u64>) -> Option<Injected> {
        self.both(tgid, start_boot_ns).map(|(_, i)| i)
    }

    /// [`judge`] on the group's byte, the marks' epoch (the pinned one and
    /// a request not yet taken in, the later) and its mark, in one errand.
    fn both(&self, tgid: u32, start_boot_ns: Option<u64>) -> Option<(bool, Injected)> {
        if !self.armed.load(Ordering::Acquire) {
            return None;
        }
        let (joined, lost, epoch, epoch_rt) = (
            Arc::clone(&self.joined),
            Arc::clone(&self.lost),
            Arc::clone(&self.epoch),
            Arc::clone(&self.epoch_rt),
        );
        crate::caps::errands::run(move || {
            let reset = epoch
                .lock()
                .get(&1, 0)
                .ok()?
                .max(epoch_rt.lock().get(&1, 0).ok()?);
            judge(
                lost_in(&lost.lock(), tgid).ok(),
                after_epoch(reset, start_boot_ns),
                mark_in(&joined.lock(), tgid).map_err(drop),
            )
        })
        .flatten()
    }

    /// Lot 281: the tracker armed — its answers given from now.
    pub fn arm(&self) {
        self.armed.store(true, Ordering::Release);
    }

    /// The mark of thread group `tgid`, if any (a tool's, a test's read:
    /// on the caller's thread).
    pub fn lookup(&self, tgid: u32) -> Result<Option<Mark>, String> {
        mark_in(&self.joined.lock(), tgid)
    }

    /// Counter `slot` (`common::cgroup_join::STAT_*`), on the caller's
    /// thread.
    pub fn stat(&self, slot: u32) -> Result<u64, String> {
        self.stats.lock().get(&slot, 0).map_err(|e| e.to_string())
    }

    /// Lot 280b: the births the fentry missed since this start
    /// (`CGROUP_JOIN_SILENT`), on the caller's thread.
    pub fn unseen_births(&self) -> Result<u64, String> {
        self.silent
            .lock()
            .get(&SILENT_UNSEEN, 0)
            .map_err(|e| e.to_string())
    }

    /// Lot 280b: the marks' epoch reset to this instant (every process
    /// started before it not known until it exits), on the caller's thread.
    /// Lot 281: asked for in the per-load request the fork program takes in
    /// (the pinned epoch is frozen).
    pub fn reset_epoch(&self) -> Result<(), String> {
        write_epoch(&mut self.epoch_rt.lock())?;
        promote_now();
        Ok(())
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
}

/// Lot 280b: the degradation's source while the marks are lost.
pub const MARKS_LOST_DEGRADATION: &str = "cgroup_join_marks";

/// Lot 280b: what [`watch_marks`] keeps between two reads.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MarksWatch {
    /// Since when the marks are lost (the time as signed), and why first.
    pub lost: Option<(String, String)>,
    /// The births the fentry missed, as last read.
    pub unseen: u64,
}

/// What a read of the switch and the check channel asks for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MarksStep {
    /// Nothing changes.
    Hold,
    /// The marks are lost from now: the degradation's line.
    Lost(String),
    /// Ftrace runs again and no birth was missed since the last read: the
    /// epoch is reset and the period signed (the record's line).
    Reset(String),
}

/// Lot 280b: one read — `ftrace_off` the manifest's word on
/// `kernel.ftrace_enabled` (`None`: on), `unseen` the births the fentry
/// missed (an error: the check channel unread, taken as a miss: fail
/// closed), `now` the time as signed. Pure, so that the tests judge it.
pub fn marks_step(
    w: &mut MarksWatch,
    ftrace_off: Option<&str>,
    unseen: Result<u64, String>,
    now: &str,
) -> MarksStep {
    let missed = match &unseen {
        Ok(n) if *n > w.unseen => Some(format!(
            "{} birth(s) the tracker's fentry did not see (the fork's tracepoint counted them; \
             each is not known)",
            n - w.unseen
        )),
        Ok(_) => None,
        Err(e) => Some(format!(
            "the tracker's ftrace check could not be read ({e})"
        )),
    };
    if let Ok(n) = unseen {
        w.unseen = n;
    }
    let why = match (ftrace_off, missed) {
        (Some(f), Some(m)) => Some(format!("{f}; {m}")),
        (Some(f), None) => Some(f.to_string()),
        (None, Some(m)) => Some(m),
        (None, None) => None,
    };
    match (why, w.lost.take()) {
        (Some(why), None) => {
            let line = format!(
                "the start-in-cgroup tracker's marks are lost since {now}: {why} — its fentry and \
                 fexit do not run while kernel.ftrace_enabled is 0, so a process started meanwhile \
                 by clone3(CLONE_INTO_CGROUP) may not be marked; the marks' epoch is reset once \
                 ftrace runs again"
            );
            w.lost = Some((now.to_string(), why));
            MarksStep::Lost(line)
        }
        (Some(_), Some(lost)) => {
            w.lost = Some(lost);
            MarksStep::Hold
        }
        (None, Some((since, first))) => MarksStep::Reset(format!(
            "the start-in-cgroup tracker's marks were lost from {since} to {now} ({first}): the \
             marks' epoch is reset at {now} — every process started before is not known (refused \
             an exemption by cgroup or unit) until it exits; restart the exempt services"
        )),
        (None, None) => MarksStep::Hold,
    }
}

static MARKS_WATCH: Mutex<MarksWatch> = parking_lot::const_mutex(MarksWatch {
    lost: None,
    unseen: 0,
});

/// Lot 280b: called at every build of the capability manifest with its
/// word on `kernel.ftrace_enabled` (`None`: on). While the marks are lost
/// — ftrace off or unknown, or a birth the fentry missed — a degradation
/// ([`MARKS_LOST_DEGRADATION`], signed at once); once ftrace runs again and
/// no birth was missed since the last read, the marks' epoch is reset
/// (fail closed) and the period signed: the loss's line leaves, the
/// reset's stays (its effect lasts until the processes before it exit). An
/// epoch that cannot be written keeps the degradation, and the next read
/// tries again. No tracker attached: nothing (its absence is signed).
pub fn watch_marks(ftrace_off: Option<&str>) {
    let Some(Tracker::Attached(marks)) = tracker() else {
        return;
    };
    let now = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
    let mut w = MARKS_WATCH.lock();
    let before = w.clone();
    match marks_step(&mut w, ftrace_off, marks.unseen_births(), &now) {
        MarksStep::Hold => {}
        MarksStep::Lost(line) => {
            warn!(detail = %line, "cgroup exemptions: marks lost");
            if crate::boot::degradation::report(MARKS_LOST_DEGRADATION, &line) {
                crate::boot::degradation::flush();
            }
        }
        MarksStep::Reset(line) => match marks.reset_epoch() {
            Ok(()) => {
                warn!(detail = %line, "cgroup exemptions: marks reset after ftrace ran again");
                // the loss's line leaves; the reset's stays, like a
                // start's reset (its effect lasts until the processes
                // started before it exit)
                crate::boot::degradation::withdraw(MARKS_LOST_DEGRADATION, &[]);
                if crate::boot::degradation::report(MARKS_LOST_DEGRADATION, &line) {
                    crate::boot::degradation::flush();
                }
            }
            Err(e) => {
                warn!(error = %e, "cgroup exemptions: the marks' epoch NOT reset — the next read tries again");
                *w = MarksWatch {
                    unseen: w.unseen,
                    ..before
                };
            }
        },
    }
}

/// The third review of #494 (R2-a): a process that started at
/// `start_boot_ns` (boot time) is after the marks' last reset at
/// `epoch_boot_ns` (0: none this boot). A start unread is not after (fail
/// closed), and so is one in the reset's clock tick.
fn after_epoch(epoch_boot_ns: u64, start_boot_ns: Option<u64>) -> bool {
    epoch_boot_ns == 0 || start_boot_ns.is_some_and(|s| s > epoch_boot_ns)
}

/// The mark of `tgid` in `joined`: one read, for the agent's answer and a
/// tool's alike.
fn mark_in(joined: &Joined, tgid: u32) -> Result<Option<Mark>, String> {
    match joined.get(&tgid, 0) {
        Ok([_, info]) => {
            let (how, by) = unpack(info);
            Ok(Some(Mark { how, by }))
        }
        Err(aya::maps::MapError::KeyNotFound) => Ok(None),
        Err(e) => Err(e.to_string()),
    }
}

/// Whether `tgid` is "not known" in `lost` (its byte): one read, for the
/// agent's answer and a tool's alike.
fn lost_in(lost: &Lost, tgid: u32) -> Result<bool, String> {
    let (slot, byte) = lost_slot(tgid).ok_or("no tgid that large")?;
    Ok(lost.get(&slot, 0).map_err(|e| e.to_string())?[byte] != 0)
}

/// The tracker's pin directory beside pin root `root` (one after a start:
/// the start removes the others) — a test's, a tool's.
pub fn pinned_dir(root: &Path) -> Result<PathBuf, String> {
    if let Some(st) = std::fs::read_to_string(STATE_PATH)
        .ok()
        .and_then(|t| PinState::parse(&t))
        .filter(|st| st.dir.is_dir())
    {
        return Ok(st.dir);
    }
    let mut dirs = other_pin_dirs(root, None);
    match dirs.len() {
        1 => Ok(dirs.remove(0)),
        0 => Err(format!(
            "no tracker pin directory beside {}",
            root.display()
        )),
        _ => Err(format!(
            "{} tracker pin directories beside {}: {dirs:?}",
            dirs.len(),
            root.display()
        )),
    }
}

/// A pinned map opened read-only (`BPF_OBJ_GET` with `BPF_F_RDONLY`): the
/// BPF map guard refuses a write handle on the agent's maps to any other
/// process, and a read needs none.
fn open_pinned_ro(path: &Path) -> Result<MapData, String> {
    open_pinned(path, true)
}

/// Lot 281 (#494's N2): a write through a handle on each pinned map of the
/// tracker beside bpffs `root` — a test's, a tool's probe of the freeze:
/// per map, the error that refused it (the handle itself, where the BPF
/// map guard refuses one; else the write). `Err` when a write went through
/// (put back as it was).
pub fn pinned_writes(root: &Path) -> Result<Vec<(&'static str, String)>, String> {
    let dir = pinned_dir(root)?;
    let mut out = Vec::new();
    for name in PINNED_MAPS {
        let md = match open_pinned(&dir.join(name), false) {
            Ok(md) => md,
            Err(e) => {
                out.push((name, format!("handle refused: {e}")));
                continue;
            }
        };
        let refused = if name == JOINED_MAP {
            let mut map =
                Joined::try_from(aya::maps::Map::HashMap(md)).map_err(|e| e.to_string())?;
            let probe = u32::MAX - 1;
            match map.insert(probe, [0, 0], 0) {
                Ok(()) => {
                    let _ = map.remove(&probe);
                    None
                }
                Err(e) => Some(with_sources(&e)),
            }
        } else if name == LOST_MAP {
            let mut map = Lost::try_from(aya::maps::Map::Array(md)).map_err(|e| e.to_string())?;
            let v = map.get(&0, 0).map_err(|e| e.to_string())?;
            map.set(0, v, 0).err().map(|e| with_sources(&e))
        } else {
            let mut map = Stats::try_from(aya::maps::Map::Array(md)).map_err(|e| e.to_string())?;
            let v = map.get(&0, 0).map_err(|e| e.to_string())?;
            map.set(0, v, 0).err().map(|e| with_sources(&e))
        };
        match refused {
            Some(e) => out.push((name, e)),
            None => return Err(format!("{name}: a write through a handle went through")),
        }
    }
    Ok(out)
}

/// `e` and its sources (aya's errors put the system call's own in the
/// source: `` `bpf_map_update_elem` failed: Operation not permitted``).
pub fn with_sources(e: &dyn std::error::Error) -> String {
    let mut s = e.to_string();
    let mut cur = e.source();
    while let Some(c) = cur {
        s.push_str(": ");
        s.push_str(&c.to_string());
        cur = c.source();
    }
    s
}

/// A pinned map opened (`BPF_OBJ_GET`), read-only with `ro`.
fn open_pinned(path: &Path, ro: bool) -> Result<MapData, String> {
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
        file_flags: if ro { BPF_F_RDONLY } else { 0 },
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
    let md = open_pinned_ro(&pinned_dir(root)?.join(JOINED_MAP))?;
    let map = Joined::try_from(aya::maps::Map::HashMap(md)).map_err(|e| e.to_string())?;
    mark_in(&map, tgid)
}

/// The third review of #494 (R2-a): the marks' last reset this boot,
/// `[monotonic, boot time]` ns (`[0, 0]`: none), from the pinned
/// `CGROUP_JOIN_EPOCH` beside bpffs `root` — a test's, a tool's.
pub fn pinned_epoch(root: &Path) -> Result<[u64; 2], String> {
    let md = open_pinned_ro(&pinned_dir(root)?.join(EPOCH_MAP))?;
    let map = Epoch::try_from(aya::maps::Map::Array(md)).map_err(|e| e.to_string())?;
    Ok([
        map.get(&0, 0).map_err(|e| e.to_string())?,
        map.get(&1, 0).map_err(|e| e.to_string())?,
    ])
}

/// Lot 277 (the review of #494, D5): whether `tgid` is "not known" (its
/// byte in the pinned `CGROUP_JOIN_LOST` beside bpffs `root`).
pub fn pinned_lost(root: &Path, tgid: u32) -> Result<bool, String> {
    let md = open_pinned_ro(&pinned_dir(root)?.join(LOST_MAP))?;
    let map = Lost::try_from(aya::maps::Map::Array(md)).map_err(|e| e.to_string())?;
    lost_in(&map, tgid)
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

/// When process `pid` started, in boot-time ns: field 22 of
/// `<proc_root>/<pid>/stat` (clock ticks since boot), after the command's
/// closing parenthesis.
fn start_boot_ns(proc_root: &Path, pid: u32) -> Option<u64> {
    let s = crate::state_read::read_state(proc_root.join(pid.to_string()).join("stat")).ok()?;
    start_ticks(&s).map(|t| t.saturating_mul(ns_per_tick()))
}

/// Field 22 of a `/proc/<pid>/stat` line.
fn start_ticks(stat: &str) -> Option<u64> {
    stat.rsplit_once(')')?
        .1
        .split_whitespace()
        .nth(19)?
        .parse()
        .ok()
}

fn ns_per_tick() -> u64 {
    // SAFETY: sysconf has no preconditions.
    let hz = unsafe { libc::sysconf(libc::_SC_CLK_TCK) };
    if hz > 0 {
        1_000_000_000 / hz as u64
    } else {
        10_000_000
    }
}

/// `Tgid:` of `<proc_root>/<pid>/status`.
fn tgid_of(proc_root: &Path, pid: u32) -> Option<u32> {
    let s = crate::state_read::read_state(proc_root.join(pid.to_string()).join("status")).ok()?;
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
    m.started(tgid, start_boot_ns(proc_root, tgid))
}

/// Lot 281: whether code-injection access to process `pid` (or to one it
/// was forked from, after it) was given to another, for the exemption
/// check (`ActorFacts::injected`): `None` not known — no tracker this boot,
/// not armed yet, the process gone, a mark the kernel could not take, a
/// start before the marks' last reset. Read on the errands thread; only
/// when an exemption by executable, cgroup or unit matched.
pub fn injected(proc_root: &Path, pid: u32) -> Option<Injected> {
    let Some(Tracker::Attached(m)) = tracker() else {
        return None;
    };
    let tgid = tgid_of(proc_root, pid)?;
    m.injected(tgid, start_boot_ns(proc_root, tgid))
}

/// Lot 281 (#494's N1/N2): the tracker armed — its pins and its state
/// protected by the caller (the anti-tamper start): from now its answers
/// are given and the exemptions by executable, cgroup or unit can hold.
/// Before, every one was refused. Logged with the time since the plan (the
/// lab's measure of that window); `None` without a tracker.
pub fn arm() -> Option<std::time::Duration> {
    let Some(Tracker::Attached(m)) = tracker() else {
        return None;
    };
    m.arm();
    let since = PLANNED_AT.get().map(Instant::elapsed).unwrap_or_default();
    let fresh = PLAN
        .get()
        .and_then(|r| r.as_ref().ok())
        .is_some_and(|p| !p.adopt);
    info!(
        since_plan_ms = since.as_millis() as u64,
        new_generation = fresh,
        dir = pin_dir_now().map(|d| d.display().to_string()),
        "cgroup exemptions: the tracker is armed — exemptions by executable, cgroup or unit are \
         honoured from now (none before)"
    );
    debug_self_inject();
    Some(since)
}

/// A `debug-trigger` build's `NN_DEBUG_CGROUP_JOIN_SELF_INJECT=<pid>`: the
/// agent opens `/proc/<pid>/mem` for writing once armed (an attach-mode
/// access that would taint `pid` were it anyone's but the family's) — the
/// privileged test of the family's exclusion. Never in a release.
fn debug_self_inject() {
    #[cfg(feature = "debug-trigger")]
    if let Some(pid) = std::env::var("NN_DEBUG_CGROUP_JOIN_SELF_INJECT")
        .ok()
        .and_then(|v| v.parse::<u32>().ok())
    {
        let r = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(format!("/proc/{pid}/mem"));
        info!(
            pid,
            opened = r.is_ok(),
            "cgroup exemptions: debug — the agent's own write handle on /proc/<pid>/mem"
        );
    }
}

/// The tracker's line for the journal at the start: its counters.
pub fn describe() -> String {
    match tracker() {
        None => "not installed".to_string(),
        Some(Tracker::Absent(why)) => format!("absent: {why}"),
        Some(Tracker::Attached(m)) => {
            let s = |slot| m.stat(slot).map_or("?".to_string(), |v| v.to_string());
            format!(
                "attached: {} roots marked, {} moves into an exempt cgroup, {} processes injected \
                 into, {} marks lost",
                s(STAT_ROOTS),
                s(STAT_INTO_EXEMPT),
                s(STAT_INJECTED),
                s(STAT_LOST)
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The re-review of #494, R2: the tracker's directories beside the pin
    /// root are found by name (another layout's, an older version's), the
    /// current one kept; a purge takes the links first, then the rest and
    /// the directory; a reader finds the one directory a start leaves.
    #[test]
    fn the_tracker_s_old_pin_directories_are_found_and_purged() {
        let t = tempfile::tempdir().unwrap();
        let root = t.path().join("northnarrow");
        std::fs::create_dir(&root).unwrap();
        let cur = PathBuf::from(common::cgroup_join::pin_dir(&root.to_string_lossy(), 0));
        let old = t.path().join("northnarrow-cgroup-join-v0-32768");
        let other = t.path().join("northnarrow-cgroup-join-v1-262144");
        for d in [&cur, &old, &other, &t.path().join("northnarrow-other")] {
            std::fs::create_dir(d).unwrap();
        }
        assert_eq!(
            other_pin_dirs(&root, Some(&cur)),
            vec![old.clone(), other.clone()]
        );
        assert_eq!(other_pin_dirs(&root, None).len(), 3);
        assert!(pinned_dir(&root)
            .unwrap_err()
            .contains("3 tracker pin directories"));
        for f in [
            "link_cgroup_join_mark",
            "prog_cgroup_join_mark",
            "CGROUP_JOINED",
        ] {
            std::fs::write(old.join(f), "").unwrap();
        }
        // lot 281: a plant at a pin's path may be a directory
        std::fs::create_dir_all(other.join("CGROUP_JOINED/deeper")).unwrap();
        std::fs::write(other.join("CGROUP_JOINED/deeper/x"), "").unwrap();
        purge_pin_dir(&old);
        purge_pin_dir(&other);
        assert!(!old.exists() && !other.exists());
        assert_eq!(other_pin_dirs(&root, Some(&cur)), Vec::<PathBuf>::new());
        assert_eq!(pinned_dir(&root).unwrap(), cur);
        std::fs::remove_dir(&cur).unwrap();
        assert!(pinned_dir(&root)
            .unwrap_err()
            .contains("no tracker pin directory"));
        // the legacy pins in the root itself (before R2) go
        let (prog, link) = pin_paths(&root, "cgroup_join_exit");
        std::fs::write(&prog, "").unwrap();
        std::fs::write(&link, "").unwrap();
        purge_legacy_pins(&root);
        assert!(!prog.exists() && !link.exists());
    }

    fn reg(name: &str, id: u32, max: u32) -> PinnedMap {
        PinnedMap {
            name: name.to_string(),
            id,
            max_entries: max,
        }
    }

    fn seen(id: u32, kind: aya::maps::MapType, key: u32, value: u32, max: u32, flags: u32) -> Seen {
        Seen {
            id,
            kind: Some(kind),
            key,
            value,
            max_entries: max,
            flags,
        }
    }

    /// The third review of #494, R2-b: a pinned map is adopted only as the
    /// one registered — its id, this schema's kind, sizes and flags (an LRU
    /// hash, preallocated, read-only to programs, or of other sizes is not).
    #[test]
    fn a_pinned_map_is_the_registered_one_or_it_is_not_adopted() {
        use aya::maps::MapType;
        let j = reg(JOINED_MAP, 40, 63_222);
        assert_eq!(
            verify_map(&seen(40, MapType::Hash, 4, 16, 63_222, 1), &j),
            Ok(())
        );
        for (bad, why) in [
            (seen(41, MapType::Hash, 4, 16, 63_222, 1), "id 41"),
            (seen(40, MapType::LruHash, 4, 16, 63_222, 1), "LruHash"),
            (seen(40, MapType::Hash, 4, 16, 63_222, 0), "flags 0x0"),
            (
                seen(40, MapType::Hash, 4, 16, 63_222, 1 | 1 << 7),
                "flags 0x81",
            ),
            (seen(40, MapType::Hash, 8, 16, 63_222, 1), "key 8"),
            (seen(40, MapType::Hash, 4, 24, 63_222, 1), "value 24"),
            (seen(40, MapType::Hash, 4, 16, 64, 1), "64 entries"),
        ] {
            let e = verify_map(&bad, &j).unwrap_err();
            assert!(e.contains(why), "{why}: {e}");
        }
        let l = reg(LOST_MAP, 7, LOST_SLOTS);
        assert_eq!(
            verify_map(&seen(7, MapType::Array, 4, 64, LOST_SLOTS, 0), &l),
            Ok(())
        );
        assert!(verify_map(&seen(7, MapType::Array, 4, 8, LOST_SLOTS, 0), &l).is_err());
        // an array registered at another size than this schema's is not one
        assert!(verify_map(
            &seen(7, MapType::Array, 4, 64, 64, 0),
            &reg(LOST_MAP, 7, 64)
        )
        .is_err());
        assert!(verify_map(
            &seen(9, MapType::Array, 4, 8, EPOCH_SLOTS, 0),
            &reg(EPOCH_MAP, 9, EPOCH_SLOTS)
        )
        .is_ok());
        assert!(verify_map(&seen(1, MapType::Array, 4, 8, 4, 0), &reg("OTHER", 1, 4)).is_err());
    }

    #[test]
    fn the_pin_state_reads_back_what_it_wrote_and_nothing_partial() {
        let st = PinState {
            boot: "b0".to_string(),
            dir: PathBuf::from("/sys/fs/bpf/northnarrow-cgroup-join-v1_3"),
            maps: vec![reg(JOINED_MAP, 40, 63_222), reg(LOST_MAP, 41, LOST_SLOTS)],
        };
        assert_eq!(PinState::parse(&st.render()), Some(st.clone()));
        for bad in [
            "dir /x\n",
            "boot b0\n",
            "boot b0\ndir /x\nmap CGROUP_JOINED 40\n",
            "boot b0\ndir /x\nmap CGROUP_JOINED x 1\n",
            "boot b0\ndir /x\nother 1\n",
            "boot b0 extra\ndir /x\n",
        ] {
            assert_eq!(PinState::parse(bad), None, "{bad:?}");
        }
    }

    /// The third review of #494: the plan — adopt only the registered
    /// directory with its registered maps, whatever the host's size (R2-a);
    /// anything else a signed reset in the next generation (R2-b, point 3);
    /// the first start of a boot neither.
    #[test]
    fn a_start_adopts_only_the_registered_pins_and_signs_every_reset() {
        let root = Path::new("/b/northnarrow");
        let d = |g: u32| PathBuf::from(format!("/b/northnarrow-cgroup-join-v{PIN_SCHEMA}_{g}"));
        let st = |dir: PathBuf| PinState {
            boot: "B".to_string(),
            dir,
            maps: vec![],
        };
        let ok = |n: u32| move |_: &PinState| Ok::<u32, String>(n);
        // the first start of a boot
        let p = plan(root, "B", None, &[], &ok(1), 1000, None);
        assert_eq!(
            (p.dir.clone(), p.adopt, p.reset.clone(), p.note.clone()),
            (d(0), false, None, None)
        );
        // adopted, whatever the host asks for now: a smaller capacity is a note
        let s0 = st(d(0));
        let p = plan(root, "B", Some(&s0), &[d(0)], &ok(63_222), 63_222, None);
        assert!(p.adopt && p.reset.is_none() && p.note.is_none() && p.dir == d(0));
        let p = plan(root, "B", Some(&s0), &[d(0)], &ok(63_222), 100_000, None);
        assert!(p.adopt && p.reset.is_none(), "a sysctl is no reset (R2-a)");
        assert!(p.note.unwrap().contains("capacity (63222"));
        let p = plan(root, "B", Some(&s0), &[d(0)], &ok(63_222), 1_000, None);
        assert!(p.adopt && p.note.is_none(), "a larger map is kept as it is");
        // the registered maps not the ones pinned (an LRU map planted in its place)
        let bad =
            |_: &PinState| Err::<u32, String>("CGROUP_JOINED: a Some(LruHash) map".to_string());
        let p = plan(root, "B", Some(&s0), &[d(0)], &bad, 1000, None);
        assert!(!p.adopt && p.dir == d(1));
        assert!(p
            .reset
            .unwrap()
            .contains("does not hold the maps registered (CGROUP_JOINED: a Some(LruHash)"));
        // the registered directory gone between two agents (point 3)
        let p = plan(root, "B", Some(&st(d(2))), &[], &ok(1), 1000, None);
        assert_eq!(p.dir, d(3));
        assert!(p.reset.unwrap().starts_with("marks lost between agents"));
        // a directory nobody registered — planted with the name a start would
        // use, or of a start that could not register: never adopted
        let p = plan(root, "B", None, &[d(0)], &ok(1), 1000, None);
        assert!(!p.adopt && p.dir == d(1));
        assert!(p
            .reset
            .unwrap()
            .contains("no start of this boot registered"));
        let legacy = PathBuf::from("/b/northnarrow-cgroup-join-v1-63222");
        let p = plan(
            root,
            "B",
            None,
            std::slice::from_ref(&legacy),
            &ok(1),
            1000,
            None,
        );
        assert!(!p.adopt && p.dir == d(0) && p.reset.is_some());
        // another boot's state is none
        let p = plan(
            root,
            "B",
            Some(&PinState {
                boot: "A".into(),
                ..s0.clone()
            }),
            &[d(0)],
            &ok(1),
            1000,
            None,
        );
        assert!(!p.adopt && p.dir == d(1) && p.reset.is_some());
        // another schema's: not migrated, a reset
        let p = plan(
            root,
            "B",
            Some(&st(PathBuf::from("/b/northnarrow-cgroup-join-v0_4"))),
            &[PathBuf::from("/b/northnarrow-cgroup-join-v0_4")],
            &ok(1),
            1000,
            None,
        );
        assert!(!p.adopt && p.dir == d(5));
        assert!(p.reset.unwrap().contains("schema v0"));
        // lot 281: the upgrade from schema 1 (no injection taint in its
        // marks) is a signed reset, never an adoption
        assert_eq!(PIN_SCHEMA, 2);
        let v1 = PathBuf::from("/b/northnarrow-cgroup-join-v1_0");
        let p = plan(
            root,
            "B",
            Some(&st(v1.clone())),
            std::slice::from_ref(&v1),
            &ok(63_222),
            63_222,
            None,
        );
        assert!(!p.adopt && p.dir == d(1));
        assert!(
            p.reset.unwrap().contains("schema v1"),
            "the v1 maps are not migrated"
        );
        // a debug build's size is a reset, never the host's
        let p = plan(root, "B", Some(&s0), &[d(0)], &ok(63_222), 63_222, Some(64));
        assert!(!p.adopt && p.dir == d(1) && p.reset.is_none());
        assert!(p.note.unwrap().contains("debug build asked for 64"));
        let p = plan(root, "B", Some(&s0), &[d(0)], &ok(64), 63_222, Some(64));
        assert!(p.adopt);
        // a planted directory of a future generation beside the registered
        // one is not adopted either: the registered one is
        let p = plan(root, "B", Some(&s0), &[d(0), d(7)], &ok(10), 10, None);
        assert!(p.adopt && p.dir == d(0));
    }

    /// Lot 281 (named, #494's N1/N2): the exemption check's answer from one
    /// mark — the placement for a cgroup or unit, the taint for every kind;
    /// nothing known while the group is lost, started before the reset, or
    /// its mark unread.
    #[test]
    fn the_check_reads_the_placement_and_the_taint_from_one_mark() {
        use common::cgroup_join::{HOW_INHERITED, HOW_MOVED, HOW_TAINT_INHERITED};
        let m = |how, by| Ok(Some(Mark { how, by }));
        assert_eq!(
            judge(Some(false), true, Ok(None)),
            Some((true, Injected::No))
        );
        assert_eq!(
            judge(Some(false), true, m(HOW_MOVED, 9)),
            Some((false, Injected::No))
        );
        assert_eq!(
            judge(Some(false), true, m(HOW_INJECTED, 42)),
            Some((
                true,
                Injected::Yes {
                    by: 42,
                    inherited: false
                }
            )),
            "injected alone: it still runs where it started"
        );
        assert_eq!(
            judge(Some(false), true, m(HOW_MOVED | HOW_INJECTED, 42)),
            Some((
                false,
                Injected::Yes {
                    by: 42,
                    inherited: false
                }
            ))
        );
        assert_eq!(
            judge(Some(false), true, m(HOW_INHERITED | HOW_TAINT_INHERITED, 7)),
            Some((
                false,
                Injected::Yes {
                    by: 7,
                    inherited: true
                }
            ))
        );
        assert_eq!(
            judge(Some(false), true, m(HOW_TAINT_INHERITED, 7)).map(|(s, _)| s),
            Some(true)
        );
        for (lost, after, mark) in [
            (Some(true), true, Ok(None)),
            (None, true, Ok(None)),
            (Some(false), false, Ok(None)),
            (Some(false), true, Err(())),
        ] {
            assert_eq!(judge(lost, after, mark), None, "{lost:?} {after}");
        }
    }

    /// Lot 281: an aya error is rendered with its system call's errno.
    #[test]
    fn a_refused_write_names_its_errno() {
        let e = aya::maps::MapError::SyscallError(aya::sys::SyscallError {
            call: "bpf_map_update_elem",
            io_error: std::io::Error::from_raw_os_error(libc::EPERM),
        });
        let s = with_sources(&e);
        assert!(s.contains("bpf_map_update_elem"), "{s}");
        assert!(s.contains("Operation not permitted"), "{s}");
    }

    /// Lot 281 (named, #494's N2): a map's frozen state is read from its
    /// descriptor's fdinfo (a frozen map refuses a second freeze with
    /// EPERM, which the call alone cannot tell from a failure — the lab's
    /// find); a missing line is no state.
    #[test]
    fn a_frozen_map_is_told_by_its_fdinfo() {
        let info = |f: &str| {
            format!(
                "pos:\t0\nflags:\t02000002\nmnt_id:\t15\nino:\t1052\nmap_type:\t1\n\
                 key_size:\t4\nvalue_size:\t16\nmax_entries:\t63222\nmap_flags:\t0x1\n\
                 map_extra:\t0x0\nmemlock:\t1049664\nmap_id:\t42\nfrozen:\t{f}\n"
            )
        };
        assert_eq!(fdinfo_frozen(&info("1")), Some(true));
        assert_eq!(fdinfo_frozen(&info("0")), Some(false));
        assert_eq!(fdinfo_frozen(&info("x")), None);
        assert_eq!(fdinfo_frozen("map_id:\t42\n"), None);
        // the host's own: a map this test cannot make; at least the parse
        // of a real fdinfo of this process (no frozen line) is None
        let own = std::fs::read_to_string("/proc/self/fdinfo/0").unwrap_or_default();
        assert_eq!(fdinfo_frozen(&own), None);
    }

    /// Lot 281 (named, #494's N2): a freeze that answers EBUSY is a map
    /// frozen before — an adoption's of this version; any other error is
    /// no tracker.
    #[test]
    fn a_map_frozen_before_is_told_from_a_failed_freeze() {
        assert_eq!(freeze_outcome(0), Ok(Freeze::Now));
        assert_eq!(freeze_outcome(libc::EBUSY), Ok(Freeze::Already));
        assert!(freeze_outcome(libc::EPERM).is_err());
        assert!(freeze_outcome(libc::EINVAL).is_err());
    }

    /// Lot 281 (named, #494's N1): the maps an adoption's load took are the
    /// ones registered — one swapped in at a pin between the check and the
    /// load is refused, by name.
    #[test]
    fn an_adoption_takes_only_the_registered_maps() {
        let st = PinState {
            boot: "B".into(),
            dir: PathBuf::from("/b/northnarrow-cgroup-join-v2_0"),
            maps: PINNED_MAPS
                .iter()
                .enumerate()
                .map(|(i, n)| reg(n, 10 + i as u32, 1))
                .collect(),
        };
        let loaded: Vec<(&str, u32)> = PINNED_MAPS
            .iter()
            .enumerate()
            .map(|(i, n)| (*n, 10 + i as u32))
            .collect();
        assert_eq!(ids_as_registered(&st, &loaded), Ok(()));
        for k in 0..PINNED_MAPS.len() {
            let mut swapped = loaded.clone();
            swapped[k].1 = 99;
            let e = ids_as_registered(&st, &swapped).unwrap_err();
            assert!(e.contains(PINNED_MAPS[k]) && e.contains("id 99"), "{e}");
        }
        assert!(
            ids_as_registered(&st, &loaded[1..]).is_err(),
            "a map not loaded"
        );
        let mut partial = st.clone();
        partial.maps.pop();
        assert!(
            ids_as_registered(&partial, &loaded).is_err(),
            "a map not registered"
        );
    }

    /// Lot 281 (named, #494's N1): a new generation's directory is made by
    /// the start (one that exists is a plant), holds the four maps and
    /// nothing else, and the next generation is above every directory
    /// beside the root — a plant made since the plan included.
    #[test]
    fn a_new_generation_is_made_by_the_start_and_holds_its_maps_alone() {
        let t = tempfile::tempdir().unwrap();
        let root = t.path().join("northnarrow");
        std::fs::create_dir(&root).unwrap();
        let g = |n: u32| PathBuf::from(common::cgroup_join::pin_dir(&root.to_string_lossy(), n));
        assert_eq!(fresh_dir(&g(0)), Ok(()));
        assert!(fresh_dir(&g(0)).unwrap_err().contains("exists already"));
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(g(0)).unwrap().permissions().mode() & 0o7777,
            0o700
        );
        std::os::unix::fs::symlink(t.path(), g(1)).unwrap();
        assert!(
            fresh_dir(&g(1)).is_err(),
            "a link is never made the directory"
        );
        assert_eq!(next_dir(&root, &g(0)), g(2), "above the planted link's");
        std::fs::create_dir(g(6)).unwrap();
        assert_eq!(next_dir(&root, &g(2)), g(7));
        let names = |v: &[&str]| v.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        assert!(foreign_entries(&names(&PINNED_MAPS)).is_empty());
        assert_eq!(
            foreign_entries(&names(&[
                "CGROUP_JOINED",
                "planted",
                "prog_cgroup_join_mark"
            ])),
            names(&["planted", "prog_cgroup_join_mark"]),
            "before the programs are pinned, a program's pin is a plant too"
        );
        const { assert!(NEW_DIR_ATTEMPTS >= 2) };
    }

    /// The third review of #494, R2-b: a registered directory holds the
    /// tracker's maps and programs' pins and nothing else.
    #[test]
    fn a_tracker_directory_holds_only_the_tracker_s_pins() {
        for yes in [
            "CGROUP_JOINED",
            "CGROUP_JOIN_LOST",
            "CGROUP_JOIN_STATS",
            "CGROUP_JOIN_EPOCH",
            "prog_cgroup_join_mark",
            "link_cgroup_join_exit",
        ] {
            assert!(is_tracker_pin(yes), "{yes}");
        }
        for no in [
            "CGROUP_EXEMPT_NAMES",
            "prog_task_kill",
            "link_cgroup_join_other",
            "planted",
            "CGROUP_JOINED.old",
        ] {
            assert!(!is_tracker_pin(no), "{no}");
        }
    }

    /// The third review of #494, R2-a: after a reset, a process is "after"
    /// only when its start is past the reset's; unread is not.
    #[test]
    fn a_process_started_before_the_reset_is_not_known() {
        assert!(after_epoch(0, None));
        assert!(after_epoch(0, Some(5)));
        assert!(after_epoch(100, Some(101)));
        assert!(!after_epoch(100, Some(100)));
        assert!(!after_epoch(100, Some(7)));
        assert!(!after_epoch(100, None));
        let line =
            "4242 (a (b) c) S 1 4242 4242 0 -1 4194560 100 0 0 0 1 2 0 0 20 0 1 0 98765 1000 10";
        assert_eq!(start_ticks(line), Some(98765));
        assert_eq!(start_ticks("4242 (x"), None);
    }

    /// The third review of #494, R2-d: a tracker directory that is a
    /// symbolic link is refused, and a purge removes the link, never what it
    /// points at.
    #[test]
    fn a_symbolic_link_is_never_the_tracker_s_directory() {
        let t = tempfile::tempdir().unwrap();
        let target = t.path().join("elsewhere");
        std::fs::create_dir(&target).unwrap();
        std::fs::write(target.join("CGROUP_JOINED"), "").unwrap();
        let link = t.path().join("northnarrow-cgroup-join-v1_0");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        assert!(usable_dir(&link).unwrap_err().contains("symbolic link"));
        purge_pin_dir(&link);
        assert!(!link.exists() && target.join("CGROUP_JOINED").exists());
        let real = t.path().join("northnarrow-cgroup-join-v1_1");
        assert_eq!(usable_dir(&real), Ok(()));
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&real).unwrap().permissions().mode() & 0o7777,
            0o700
        );
        std::fs::write(t.path().join("plain"), "").unwrap();
        assert!(usable_dir(&t.path().join("plain")).is_err());
    }

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
        // lot 281: the two LSM programs of the injection taint, the rest the
        // BTF targets' (and the move guard's fexit target)
        let lsm: Vec<&str> = PROGRAMS
            .iter()
            .filter(|(_, k, _)| *k == Kind::Lsm)
            .map(|(_, _, t)| *t)
            .collect();
        assert_eq!(lsm, ["ptrace_access_check", "ptrace_traceme"]);
        assert_eq!(
            PROGRAMS.len(),
            common::btf_offsets::CGROUP_JOIN_TARGETS.len() + 1 + lsm.len()
        );
        assert!(PROGRAMS
            .iter()
            .all(|(n, _, _)| n.starts_with("cgroup_join_")));
        for t in common::btf_offsets::CGROUP_JOIN_TARGETS {
            assert!(
                PROGRAMS.iter().any(|(_, _, target)| *target == t.name),
                "{}",
                t.name
            );
        }
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

    /// Lot 280b (named): ftrace off inside a window — the marks are lost
    /// from the first read that sees it (one signed line for the whole
    /// period, not one a read), and reset only once ftrace runs again with
    /// no birth missed since the last read; the reset's line names the
    /// period.
    #[test]
    fn ftrace_off_loses_the_marks_and_its_return_resets_the_epoch() {
        let mut w = MarksWatch::default();
        assert_eq!(marks_step(&mut w, None, Ok(0), "t0"), MarksStep::Hold);
        let off = "kernel.ftrace_enabled is 0 — the trampolines stop";
        let lost = marks_step(&mut w, Some(off), Ok(0), "t1");
        let MarksStep::Lost(line) = lost else {
            panic!("{lost:?}")
        };
        assert!(line.contains("lost since t1"), "{line}");
        assert!(line.contains("kernel.ftrace_enabled is 0"), "{line}");
        assert!(line.contains("CLONE_INTO_CGROUP"), "{line}");
        // still off, births missed meanwhile: the same period, no new line
        assert_eq!(marks_step(&mut w, Some(off), Ok(3), "t2"), MarksStep::Hold);
        assert_eq!(marks_step(&mut w, Some(off), Ok(5), "t3"), MarksStep::Hold);
        // ftrace back, but a birth missed since the last read: still lost
        assert_eq!(marks_step(&mut w, None, Ok(6), "t4"), MarksStep::Hold);
        assert!(w.lost.is_some());
        // back, nothing missed since: the reset, naming the period
        let reset = marks_step(&mut w, None, Ok(6), "t5");
        let MarksStep::Reset(line) = reset else {
            panic!("{reset:?}")
        };
        assert!(line.contains("from t1 to t5"), "{line}");
        assert!(line.contains("epoch is reset at t5"), "{line}");
        assert!(line.contains("not known"), "{line}");
        assert_eq!(w.lost, None);
        assert_eq!(w.unseen, 6);
        assert_eq!(marks_step(&mut w, None, Ok(6), "t6"), MarksStep::Hold);
    }

    /// Lot 280b (named): the tracepoint channel alone — ftrace reads on, but
    /// the fork's tracepoint counted births the fentry missed (a quick off
    /// and on between two reads): lost, then reset at the next quiet read;
    /// an unread channel is a miss (fail closed), and an unknown ftrace is
    /// off.
    #[test]
    fn a_birth_the_fentry_missed_loses_the_marks_with_ftrace_on() {
        let mut w = MarksWatch::default();
        let MarksStep::Lost(line) = marks_step(&mut w, None, Ok(1), "t1") else {
            panic!()
        };
        assert!(
            line.contains("1 birth(s) the tracker's fentry did not see"),
            "{line}"
        );
        assert!(matches!(
            marks_step(&mut w, None, Ok(1), "t2"),
            MarksStep::Reset(_)
        ));
        // the count goes on from where it was
        assert_eq!(marks_step(&mut w, None, Ok(1), "t3"), MarksStep::Hold);
        let MarksStep::Lost(line) = marks_step(&mut w, None, Ok(4), "t4") else {
            panic!()
        };
        assert!(line.contains("3 birth(s)"), "{line}");
        assert!(matches!(
            marks_step(&mut w, None, Ok(4), "t5"),
            MarksStep::Reset(_)
        ));
        // the channel unread: lost, its count kept
        let MarksStep::Lost(line) = marks_step(&mut w, None, Err("EBADF".into()), "t6") else {
            panic!()
        };
        assert!(line.contains("could not be read (EBADF)"), "{line}");
        assert_eq!(w.unseen, 4);
        assert_eq!(
            marks_step(&mut w, None, Err("EBADF".into()), "t7"),
            MarksStep::Hold
        );
        assert!(matches!(
            marks_step(&mut w, None, Ok(4), "t8"),
            MarksStep::Reset(_)
        ));
        // ftrace unknown (the manifest's line for it) is a loss too
        let unknown = "kernel.ftrace_enabled could not be read";
        assert!(matches!(
            marks_step(&mut w, Some(unknown), Ok(4), "t9"),
            MarksStep::Lost(l) if l.contains(unknown)
        ));
    }

    /// Lot 311 (N6): a process whose `comm` is not UTF-8 has its start and
    /// thread group read for the exemption by cgroup (`started_in_cgroup`)
    /// — on main both reads failed for a process that named itself so.
    #[test]
    fn a_process_whose_comm_is_not_utf8_has_its_start_and_tgid() {
        use crate::state_read::testing::write_non_utf8_proc;
        let t = tempfile::tempdir().unwrap();
        write_non_utf8_proc(t.path(), 4300, 1, 1000, 777);
        assert_eq!(start_boot_ns(t.path(), 4300), Some(777 * ns_per_tick()));
        assert_eq!(tgid_of(t.path(), 4300), Some(4300));
    }
}
