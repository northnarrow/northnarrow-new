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

use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock};

use aya::maps::{Array, HashMap, MapData};
use aya::programs::links::FdLink;
use aya::programs::{BtfTracePoint, FEntry, FExit};
use aya::{Btf, Ebpf, EbpfLoader};
use common::cgroup_join::{
    fnv, is_pin_dir_of, lost_slot, parse_pin_dir, unpack, EPOCH_SLOTS, LOST_BYTES, LOST_SLOTS,
    NAME_CGROUP, NAME_UNIT, PIN_SCHEMA, STAT_INTO_EXEMPT, STAT_LOST, STAT_ROOTS, STAT_SLOTS,
};
use nn_core::decision::rule_policy::{Exemption, RulePolicy};
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

/// How a program of the tracker attaches.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    FExit,
    FEntry,
    /// A BTF tracepoint.
    TpBtf,
}

/// The tracker's programs: `(program, how, target)`, in the order a start
/// swaps them for the prior boot's: `cgroup_join_mark` before
/// `cgroup_join_src` (the re-review of #494, N-f) — the new `mark` reads the
/// new, empty source slot until the new `src` writes it, and marks every
/// move meanwhile (more, never less).
pub const PROGRAMS: [(&str, Kind, &str); 5] = [
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
    "the start-in-cgroup tracker is not attached: every exemption by cgroup or unit of the \
     per-rule policy is refused (a process moved into an exempt service's cgroup could not be \
     told from the service)";

type Joined = HashMap<MapData, u32, [u64; 2]>;
type Lost = Array<MapData, [u8; LOST_BYTES]>;
type Stats = Array<MapData, u64>;
type Epoch = Array<MapData, u64>;
type Names = HashMap<MapData, u64, u8>;

/// The tracker's maps, for the exemption check, the names and the sweep.
#[derive(Clone)]
pub struct Marks {
    joined: Arc<Mutex<Joined>>,
    lost: Arc<Mutex<Lost>>,
    stats: Arc<Mutex<Stats>>,
    epoch: Arc<Mutex<Epoch>>,
    names: Arc<Mutex<Names>>,
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
        return next(Some(format!(
            "marks reset: a debug build asked for {n} marks, {entries} are pinned"
        )));
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
fn boot_id() -> String {
    std::fs::read_to_string("/proc/sys/kernel/random/boot_id")
        .map(|s| s.trim().to_string())
        .unwrap_or_default()
}

/// What `BPF_OBJ_GET_INFO_BY_FD` says of the map pinned at `path` (opened
/// read-only).
fn seen_at(path: &Path) -> Result<Seen, String> {
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
fn usable_dir(dir: &Path) -> Result<(), String> {
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
/// registered directory adopted, its maps verified, or a new one — and the
/// loader told to pin the tracker's maps there ([`PINNED_MAPS`]). Nothing
/// is removed here: the agent is not a protected pid yet, and a reset
/// directory goes once the new programs run ([`attach`]). Without a bpffs
/// (`pin_root` `None`) the maps are this process's.
pub fn prepare_pins(loader: &mut EbpfLoader<'_>, pin_root: Option<&Path>, entries: u32) {
    let Some(root) = pin_root else {
        return;
    };
    let plan = PLAN.get_or_init(|| {
        let state = std::fs::read_to_string(STATE_PATH)
            .ok()
            .and_then(|t| PinState::parse(&t));
        let p = plan(
            root,
            &boot_id(),
            state.as_ref(),
            &other_pin_dirs(root, None),
            &verify_state,
            entries,
            debug_entries(),
        );
        usable_dir(&p.dir)?;
        Ok(p)
    });
    if let Ok(p) = plan {
        for name in PINNED_MAPS {
            loader.map_pin_path(name, p.dir.join(name));
        }
    }
}

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

/// The tracker's pin directory this boot, once [`prepare_pins`] chose it.
pub fn pin_dir_now() -> Option<&'static Path> {
    PLAN.get()
        .and_then(|r| r.as_ref().ok())
        .map(|p| p.dir.as_path())
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

/// The third review of #494 (R2-a): this instant as the marks' last reset
/// — `[monotonic, boot time]` ns into `CGROUP_JOIN_EPOCH`, once the new
/// programs run: a process started before it is not known.
fn set_epoch(ebpf: &mut Ebpf) -> Result<(), String> {
    let now = |clock| {
        let mut ts = libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        // SAFETY: a valid out-parameter for clock_gettime.
        if unsafe { libc::clock_gettime(clock, &mut ts) } != 0 {
            return Err(std::io::Error::last_os_error().to_string());
        }
        Ok(ts.tv_sec as u64 * 1_000_000_000 + ts.tv_nsec as u64)
    };
    let (mono, boot) = (now(libc::CLOCK_MONOTONIC)?, now(libc::CLOCK_BOOTTIME)?);
    let map = ebpf
        .map_mut(EPOCH_MAP)
        .ok_or_else(|| format!("map {EPOCH_MAP} missing from the eBPF object"))?;
    let mut arr: Array<&mut MapData, u64> = Array::try_from(map).map_err(|e| e.to_string())?;
    arr.set(1, boot, 0).map_err(|e| e.to_string())?;
    arr.set(0, mono, 0).map_err(|e| e.to_string())
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
/// pid by then; a pin it cannot remove is logged.
fn purge_pin_dir(dir: &Path) {
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
        antitamper_bpf::purge_stale_pin(f);
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
            let dir = plan.dir.as_path();
            for (i, (name, kind, target)) in PROGRAMS.iter().enumerate() {
                if let Err(e) = load_only(ebpf, btf, name, *kind, target) {
                    for (n, k, _) in &PROGRAMS[..=i] {
                        unload(ebpf, n, *k);
                    }
                    warn!(error = %e, effect = ABSENT_EFFECT, "cgroup exemptions: tracker load FAILED");
                    return (Tracker::Absent(e), Vec::new());
                }
            }
            for (name, kind, _) in &PROGRAMS {
                if let Err(e) = pin_fresh(ebpf, dir, name, *kind) {
                    warn!(program = name, error = %e, effect = ABSENT_EFFECT, "cgroup exemptions: tracker attach or pin FAILED");
                    return (Tracker::Absent(e), Vec::new());
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
                     exemption by cgroup or unit) until it exits — restart the exempt services"
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
            warn!("cgroup exemptions: tracker attached WITHOUT pin (no bpffs): not kept while no agent runs");
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
        let epoch = Epoch::try_from(take(ebpf, EPOCH_MAP)?).map_err(|e| e.to_string())?;
        let names = Names::try_from(take(ebpf, NAMES_MAP)?).map_err(|e| e.to_string())?;
        Ok(Marks {
            joined: Arc::new(Mutex::new(joined)),
            lost: Arc::new(Mutex::new(lost)),
            stats: Arc::new(Mutex::new(stats)),
            epoch: Arc::new(Mutex::new(epoch)),
            names: Arc::new(Mutex::new(names)),
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
    pub fn started(&self, tgid: u32, start_boot_ns: Option<u64>) -> Option<bool> {
        let (joined, lost, epoch) = (
            Arc::clone(&self.joined),
            Arc::clone(&self.lost),
            Arc::clone(&self.epoch),
        );
        crate::caps::errands::run(move || {
            if lost_in(&lost.lock(), tgid).ok()? {
                return None;
            }
            if !after_epoch(epoch.lock().get(&1, 0).ok()?, start_boot_ns) {
                return None;
            }
            mark_in(&joined.lock(), tgid).ok().map(|m| m.is_none())
        })
        .flatten()
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
    let md = open_pinned_ro(&pinned_dir(root)?.join(JOINED_MAP))?;
    let map = Joined::try_from(aya::maps::Map::HashMap(md)).map_err(|e| e.to_string())?;
    mark_in(&map, tgid)
}

/// Lot 277 (the review of #494, D5): whether `tgid` is "not known" (its
/// byte in the pinned `CGROUP_JOIN_LOST` beside bpffs `root`).
pub fn pinned_lost(root: &Path, tgid: u32) -> Result<bool, String> {
    let md = open_pinned_ro(&pinned_dir(root)?.join(LOST_MAP))?;
    let map = Lost::try_from(aya::maps::Map::Array(md)).map_err(|e| e.to_string())?;
    lost_in(&map, tgid)
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

/// When process `pid` started, in boot-time ns: field 22 of
/// `<proc_root>/<pid>/stat` (clock ticks since boot), after the command's
/// closing parenthesis.
fn start_boot_ns(proc_root: &Path, pid: u32) -> Option<u64> {
    let s = std::fs::read_to_string(proc_root.join(pid.to_string()).join("stat")).ok()?;
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
    m.started(tgid, start_boot_ns(proc_root, tgid))
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
            dir: PathBuf::from("/sys/fs/bpf/northnarrow-cgroup-join-v1.3"),
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
        let d = |g: u32| PathBuf::from(format!("/b/northnarrow-cgroup-join-v1.{g}"));
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
        let p = plan(root, "B", None, &[legacy.clone()], &ok(1), 1000, None);
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
            Some(&st(PathBuf::from("/b/northnarrow-cgroup-join-v0.4"))),
            &[PathBuf::from("/b/northnarrow-cgroup-join-v0.4")],
            &ok(1),
            1000,
            None,
        );
        assert!(!p.adopt && p.dir == d(5));
        assert!(p.reset.unwrap().contains("schema v0"));
        // a debug build's size is a reset, never the host's
        let p = plan(root, "B", Some(&s0), &[d(0)], &ok(63_222), 63_222, Some(64));
        assert!(!p.adopt && p.dir == d(1) && p.reset.unwrap().contains("debug build asked for 64"));
        let p = plan(root, "B", Some(&s0), &[d(0)], &ok(64), 63_222, Some(64));
        assert!(p.adopt);
        // a planted directory of a future generation beside the registered
        // one is not adopted either: the registered one is
        let p = plan(root, "B", Some(&s0), &[d(0), d(7)], &ok(10), 10, None);
        assert!(p.adopt && p.dir == d(0));
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
        let link = t.path().join("northnarrow-cgroup-join-v1.0");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        assert!(usable_dir(&link).unwrap_err().contains("symbolic link"));
        purge_pin_dir(&link);
        assert!(!link.exists() && target.join("CGROUP_JOINED").exists());
        let real = t.path().join("northnarrow-cgroup-join-v1.1");
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
