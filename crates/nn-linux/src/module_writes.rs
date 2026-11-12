//! Lot 285 (the coordinator's decision on #513): the module files' write
//! history kept through an agent restart and an upgrade within the boot.
//!
//! The kernel's judge trusts a module file changed since boot only when its
//! write history (`MODULE_WRITES`, kept by `module_write_observe` on
//! `file_open`) says a package transaction wrote it; the lineage of a
//! package manager's `#!` script is `MODULE_PKG_SCRIPTS`. Both maps and the
//! observer's program and link are pinned in a directory of their own
//! beside the pin root ([`pin_dir`]): like the start-in-cgroup tracker's
//! (lot 277), the observer goes on while no agent runs and through an
//! upgrade (whose purge takes the pin root), and the next start adopts the
//! history.
//!
//! * [`prepare_pins`], before the object's load: the registered maps of
//!   this boot ([`STATE_PATH`]) adopted — the loader takes their pins — when
//!   each is the one registered (its id) in this layout (kind, key, value,
//!   entries) and the observer's link is pinned beside them; otherwise new
//!   maps, the history reset ([`Plan::New`]).
//! * [`after_load`]: an adoption's maps checked again (the ones the load
//!   took are the registered ones); a new history's maps pinned, frozen
//!   (`BPF_MAP_FREEZE`: no handle writes them, the programs do).
//! * [`attach`], with the anti-tamper set: the observer attached in the
//!   directory (`reattach_fresh`: the new program first, the prior link
//!   removed after — never a moment without one; its pins there, never in
//!   the pin root, where `file_open`'s are the write-open deny's; lot 300:
//!   its link held open too, so the agent's own-link views see it), then
//!   the state registered.
//!
//! [`history`] is the controller's view: the instant from which the history
//! covers every write ([`History::since`]). A module file changed since
//! boot before it (the first start of the boot, a reset: another layout, a
//! registered map that is not the one found) has no history to read: the
//! controller lets a package's or DKMS's file through and records it High,
//! never refuses it in silence (`agent/src/module_trust`); a map the load
//! took that is not the one checked makes the history unreliable for the
//! boot (the same, for every file changed since boot).

use std::os::fd::{AsFd, AsRawFd};
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use aya::maps::{Map, MapData};
use aya::programs::links::FdLink;
use aya::{Btf, Ebpf, EbpfLoader};
use common::module_judge::{MODULE_PKG_SCRIPTS_MAX, MODULE_WRITES_MAX};
use tracing::{info, warn};

use crate::cgroup_join::Seen;

/// The write history (pinned in [`pin_dir`]).
pub const WRITES_MAP: &str = "MODULE_WRITES";
/// The package managers' `#!` scripts' processes (pinned there).
pub const SCRIPTS_MAP: &str = "MODULE_PKG_SCRIPTS";
/// The maps pinned in [`pin_dir`].
pub const PINNED_MAPS: [&str; 2] = [WRITES_MAP, SCRIPTS_MAP];
/// The observer (`agent-ebpf/src/module_load.rs`) and its hook.
pub const PROGRAM: &str = "module_write_observe";
pub const HOOK: &str = "file_open";
/// The pin directory's name beside the pin root.
pub const PIN_DIR_SUFFIX: &str = "-module-writes";
/// The history's pins this boot, as the start that made or adopted them
/// registered them: the next start adopts nothing else. `/run` holds it for
/// the boot only; the agent protects it like its other files.
pub const STATE_PATH: &str = "/run/northnarrow/module-writes-pins";

/// The pin directory beside `pin_root` (a sibling: the upgrade's purge of
/// the pin root leaves it).
pub fn pin_dir(pin_root: &Path) -> PathBuf {
    let mut name = pin_root.as_os_str().to_os_string();
    name.push(PIN_DIR_SUFFIX);
    PathBuf::from(name)
}

/// The observer's link pin in `dir` (`antitamper_bpf::lsm_pin_paths`: named
/// after the hook — in this directory, no other program's).
pub fn link_pin(dir: &Path) -> PathBuf {
    antitamper_bpf::lsm_pin_paths(dir, HOOK).1
}

/// Kept across an upgrade (pinned outside the pin root): the
/// own-programs file marks it so.
pub fn is_kept_program(name: &str) -> bool {
    name == PROGRAM
}

/// The layout of map `name`: kind, key and value sizes, entries.
fn layout(name: &str) -> Option<(aya::maps::MapType, u32, u32, u32)> {
    use aya::maps::MapType;
    match name {
        WRITES_MAP => Some((MapType::LruHash, 16, 4, MODULE_WRITES_MAX)),
        SCRIPTS_MAP => Some((MapType::LruHash, 4, 8, MODULE_PKG_SCRIPTS_MAX)),
        _ => None,
    }
}

/// The history's pins as the last start of this boot registered them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct State {
    /// `/proc/sys/kernel/random/boot_id` of the boot.
    pub boot: String,
    /// From when the history covers every write (wall clock: seconds,
    /// nanoseconds), as a file's change time reads.
    pub since: (i64, u32),
    /// Each map's name and id.
    pub maps: Vec<(String, u32)>,
}

impl State {
    pub fn render(&self) -> String {
        let mut out = format!(
            "# northnarrow-agent: the module files' write history this boot (lot 285)\nboot {}\nsince {} {}\n",
            self.boot, self.since.0, self.since.1
        );
        for (name, id) in &self.maps {
            out.push_str(&format!("map {name} {id}\n"));
        }
        out
    }

    /// `None` for anything but a whole state.
    pub fn parse(text: &str) -> Option<State> {
        let (mut boot, mut since, mut maps) = (None, None, Vec::new());
        for line in text
            .lines()
            .filter(|l| !l.starts_with('#') && !l.trim().is_empty())
        {
            let w: Vec<&str> = line.split_whitespace().collect();
            match w.as_slice() {
                ["boot", b] => boot = Some(b.to_string()),
                ["since", s, n] => since = Some((s.parse().ok()?, n.parse().ok()?)),
                ["map", name, id] => maps.push((name.to_string(), id.parse().ok()?)),
                _ => return None,
            }
        }
        Some(State {
            boot: boot?,
            since: since?,
            maps,
        })
    }

    fn id_of(&self, name: &str) -> Option<u32> {
        self.maps.iter().find(|(n, _)| n == name).map(|(_, id)| *id)
    }
}

/// What a start does with the history.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Plan {
    /// The registered maps, checked: their history kept.
    Adopt(State),
    /// New maps; why the history of before is not kept. `first`: no
    /// history was registered this boot (the boot's first start: nothing
    /// to sign).
    New { why: String, first: bool },
}

/// The plan for `state` (the registered one, if any) on boot `boot`:
/// `seen` reads what is pinned at a name of the directory, `linked` the
/// observer's link is pinned there.
pub fn plan(
    state: Option<&State>,
    boot: &str,
    seen: &dyn Fn(&str) -> Result<Seen, String>,
    linked: bool,
) -> Plan {
    let new = |why: String| Plan::New { why, first: false };
    let Some(st) = state else {
        return Plan::New {
            why: "no history registered this boot".to_string(),
            first: true,
        };
    };
    if st.boot != boot {
        return Plan::New {
            why: "the registered history is another boot's".to_string(),
            first: true,
        };
    }
    for name in PINNED_MAPS {
        let Some(id) = st.id_of(name) else {
            return new(format!("{name} not registered"));
        };
        let s = match seen(name) {
            Ok(s) => s,
            Err(e) => return new(format!("{name}: {e}")),
        };
        if s.id != id {
            return new(format!("{name}: id {} where {id} was registered", s.id));
        }
        let (kind, key, value, entries) = layout(name).expect("a pinned map's layout");
        if s.kind != Some(kind) || s.key != key || s.value != value || s.max_entries != entries {
            return new(format!(
                "{name}: another layout ({:?}, key {}, value {}, {} entries) — another version's",
                s.kind, s.key, s.value, s.max_entries
            ));
        }
    }
    if !linked {
        return new("the observer's link is not pinned beside the maps".to_string());
    }
    Plan::Adopt(st.clone())
}

static PLAN: OnceLock<Plan> = OnceLock::new();
/// The new maps' ids, once pinned ([`after_load`]).
static LOADED: OnceLock<Vec<(String, u32)>> = OnceLock::new();
static HISTORY: OnceLock<History> = OnceLock::new();
/// [`after_load`]'s outcome.
static LOAD_OUTCOME: OnceLock<Result<(), String>> = OnceLock::new();
/// Lot 300: the observer's link this start made, held open beside its pin
/// (like the cgroup/sysctl judge's). The agent's links are the ones it
/// holds and the `link_*` pins of the pin root
/// (`anti_tamper::bpf_defense::live_links`): pinned in [`pin_dir`] and
/// dropped, the link was "detached" to the sensor self-test's attach check
/// (module_load missed every round, an alert at the second, on every host
/// since lot 285) and not registered as the agent's own by the BPF guard
/// (a foreign handle on it not refused, its loss not noticed).
static LINK: OnceLock<FdLink> = OnceLock::new();

/// The history as this start has it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct History {
    /// From when every write is in it (wall clock); `None`: unreliable this
    /// boot — no write is.
    pub since: Option<(i64, u32)>,
    /// Signed: why the history of before is not kept, or not reliable.
    pub note: Option<String>,
}

/// The history this start has ([`attach`]); `None` before it (or without
/// an observer: nothing in it is a write the controller may vouch for).
pub fn history() -> Option<History> {
    HISTORY.get().cloned()
}

/// Before the object's load: adopt the registered history, or not.
pub fn prepare_pins(loader: &mut EbpfLoader<'_>, pin_root: Option<&Path>) {
    let Some(root) = pin_root else {
        return;
    };
    let dir = pin_dir(root);
    let plan = PLAN.get_or_init(|| {
        if let Some(why) = antitamper_bpf::pin_root_refusal_at(&dir) {
            return Plan::New { why, first: false };
        }
        let state = std::fs::read_to_string(STATE_PATH)
            .ok()
            .and_then(|t| State::parse(&t));
        plan(
            state.as_ref(),
            &crate::cgroup_join::boot_id(),
            &|name| crate::cgroup_join::seen_at(&dir.join(name)),
            link_pin(&dir).exists(),
        )
    });
    if let Plan::Adopt(_) = plan {
        for name in PINNED_MAPS {
            loader.map_pin_path(name, dir.join(name));
        }
    }
}

fn map_data<'a>(ebpf: &'a Ebpf, name: &str) -> Result<&'a MapData, String> {
    match ebpf.map(name) {
        Some(Map::LruHashMap(d)) | Some(Map::HashMap(d)) => Ok(d),
        Some(_) => Err(format!("{name}: not the history's kind of map")),
        None => Err(format!("{name} missing from the eBPF object")),
    }
}

/// Map `name`'s id in the loaded object.
fn loaded_id(ebpf: &Ebpf, name: &str) -> Result<u32, String> {
    Ok(map_data(ebpf, name)?
        .info()
        .map_err(|e| format!("{name}: {e}"))?
        .id())
}

/// Freeze map `md` (`BPF_MAP_FREEZE`) unless frozen already.
fn freeze(name: &str, md: &MapData) -> Result<(), String> {
    const MAP_FREEZE: libc::c_long = common::bpf_cmd::BPF_MAP_FREEZE as libc::c_long;
    #[repr(C)]
    struct FreezeAttr {
        map_fd: u32,
    }
    let fd = md.fd().as_fd().as_raw_fd();
    let info = std::fs::read_to_string(format!("/proc/self/fdinfo/{fd}"))
        .map_err(|e| format!("{name}: its fdinfo: {e}"))?;
    match crate::cgroup_join::fdinfo_frozen(&info) {
        Some(true) => return Ok(()),
        Some(false) => {}
        None => return Err(format!("{name}: no frozen state in its fdinfo")),
    }
    let attr = FreezeAttr { map_fd: fd as u32 };
    // SAFETY: bpf(BPF_MAP_FREEZE) with a valid, fully initialised attribute
    // block of its exact size; the fd is borrowed from the live map.
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
    crate::cgroup_join::freeze_outcome(errno)
        .map(|_| ())
        .map_err(|e| format!("{name}: {e}"))
}

/// Right after the load, before the maps are taken: an adoption's maps
/// checked (the load took the registered ones), a new history's pinned;
/// frozen. `Err`: the history is not reliable this boot (signed by
/// [`attach`]).
pub fn after_load(ebpf: &mut Ebpf, pin_root: Option<&Path>) -> Result<(), String> {
    let outcome = after_load_in(ebpf, pin_root);
    if let Err(e) = &outcome {
        warn!(error = %e, "module write history: not kept");
    }
    let _ = LOAD_OUTCOME.set(outcome.clone());
    outcome
}

fn after_load_in(ebpf: &mut Ebpf, pin_root: Option<&Path>) -> Result<(), String> {
    let Some(root) = pin_root else {
        return Ok(());
    };
    let dir = pin_dir(root);
    match PLAN.get() {
        Some(Plan::Adopt(st)) => {
            for name in PINNED_MAPS {
                let id = loaded_id(ebpf, name)?;
                if Some(id) != st.id_of(name) {
                    return Err(format!(
                        "{name}: the load took id {id}, not the registered {:?}",
                        st.id_of(name)
                    ));
                }
            }
        }
        Some(Plan::New { .. }) | None => {
            crate::cgroup_join::usable_dir(&dir)?;
            let mut ids = Vec::new();
            for name in PINNED_MAPS {
                let path = dir.join(name);
                // a prior history's (or anything else at the name): it is
                // not adopted; the prior observer holds its own map
                antitamper_bpf::purge_stale_pin(&path);
                match ebpf.map_mut(name) {
                    Some(Map::LruHashMap(d)) | Some(Map::HashMap(d)) => d
                        .pin(&path)
                        .map_err(|e| format!("pinning {name} at {}: {e}", path.display()))?,
                    _ => return Err(format!("{name} missing from the eBPF object")),
                }
                ids.push((name.to_string(), loaded_id(ebpf, name)?));
            }
            let _ = LOADED.set(ids);
        }
    }
    for name in PINNED_MAPS {
        freeze(name, map_data(ebpf, name)?)?;
    }
    Ok(())
}

/// The wall clock now (seconds, nanoseconds).
fn now() -> (i64, u32) {
    let d = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    (
        i64::try_from(d.as_secs()).unwrap_or(i64::MAX),
        d.subsec_nanos(),
    )
}

/// With the anti-tamper set: the observer attached in the history's
/// directory (pinned there, attach before purge), the state registered.
/// The signed note, when there is one.
pub fn attach(
    ebpf: &mut Ebpf,
    btf: &Btf,
    pin_root: Option<&Path>,
) -> Result<Option<String>, String> {
    let loaded = LOAD_OUTCOME
        .get()
        .cloned()
        .unwrap_or_else(|| Err("the history's maps were not prepared at the load".to_string()));
    let Some(root) = pin_root else {
        antitamper_bpf::attach_transient(ebpf, PROGRAM, HOOK, btf).map_err(|e| format!("{e:#}"))?;
        let _ = HISTORY.set(History {
            since: Some(now()),
            note: None,
        });
        return Ok(None);
    };
    let dir = pin_dir(root);
    crate::cgroup_join::usable_dir(&dir)?;
    if let Some(link) = antitamper_bpf::reattach_fresh_held(ebpf, PROGRAM, HOOK, btf, Some(&dir))
        .map_err(|e| format!("{e:#}"))?
    {
        let _ = LINK.set(FdLink::from(link));
    }
    let (history, state) = match (&loaded, PLAN.get()) {
        (Err(why), _) => (
            History {
                since: None,
                note: Some(format!(
                    "the module files' write history is not reliable this boot ({why}): a module \
                     file changed since boot is let through and recorded High if a package or \
                     DKMS vouches for it, refused otherwise, until the next boot"
                )),
            },
            None,
        ),
        (Ok(()), Some(Plan::Adopt(st))) => (
            History {
                since: Some(st.since),
                note: None,
            },
            Some(st.clone()),
        ),
        (Ok(()), plan) => {
            let since = now();
            let note = match plan {
                Some(Plan::New { why, first: false }) => Some(format!(
                    "the module files' write history was reset ({why}): a module file changed \
                     since boot before this start is let through and recorded High if a package \
                     or DKMS vouches for it, until the next boot"
                )),
                _ => None,
            };
            let st = State {
                boot: crate::cgroup_join::boot_id(),
                since,
                maps: LOADED.get().cloned().unwrap_or_default(),
            };
            (
                History {
                    since: Some(since),
                    note,
                },
                Some(st),
            )
        }
    };
    match state {
        Some(st) if st.maps.len() == PINNED_MAPS.len() => {
            let path = Path::new(STATE_PATH);
            if let Some(parent) = path.parent() {
                use std::os::unix::fs::DirBuilderExt;
                let _ = std::fs::DirBuilder::new()
                    .recursive(true)
                    .mode(0o700)
                    .create(parent);
            }
            if let Err(e) = crate::atomic_file::replace(path, st.render().as_bytes(), 0o600) {
                warn!(
                    error = format!("{e:#}"),
                    "module write history: state NOT registered — the next start resets it"
                );
            }
        }
        _ => {
            // nothing the next start may adopt
            let _ = std::fs::remove_file(STATE_PATH);
        }
    }
    info!(
        since = ?history.since,
        dir = %dir.display(),
        "module write history: the observer attached in its own pin directory"
    );
    let note = history.note.clone();
    let _ = HISTORY.set(history);
    Ok(note)
}

/// The state could not be protected: the next start adopts nothing.
pub fn forget_state() {
    let _ = std::fs::remove_file(STATE_PATH);
}

#[cfg(test)]
mod tests {
    use super::*;
    use aya::maps::MapType;

    fn seen(id: u32, kind: MapType, key: u32, value: u32, max: u32) -> Seen {
        Seen {
            id,
            kind: Some(kind),
            key,
            value,
            max_entries: max,
            flags: 0,
        }
    }

    fn registered() -> State {
        State {
            boot: "b1".to_string(),
            since: (1_762_400_000, 5),
            maps: vec![(WRITES_MAP.to_string(), 11), (SCRIPTS_MAP.to_string(), 12)],
        }
    }

    fn pinned(name: &str) -> Result<Seen, String> {
        match name {
            WRITES_MAP => Ok(seen(11, MapType::LruHash, 16, 4, MODULE_WRITES_MAX)),
            SCRIPTS_MAP => Ok(seen(12, MapType::LruHash, 4, 8, MODULE_PKG_SCRIPTS_MAX)),
            _ => Err("absent".to_string()),
        }
    }

    /// Named test (lot 285, the coordinator's decision on #513): the
    /// history registered this boot is adopted — every map the registered
    /// one, in this layout, the observer's link pinned beside them; any
    /// other case is a new history (reset), signed unless no history was
    /// registered this boot.
    #[test]
    fn the_write_history_registered_this_boot_is_adopted_and_nothing_else() {
        let st = registered();
        assert_eq!(
            plan(Some(&st), "b1", &pinned, true),
            Plan::Adopt(st.clone())
        );
        // the boot's first start
        assert!(matches!(
            plan(None, "b1", &pinned, true),
            Plan::New { first: true, .. }
        ));
        assert!(matches!(
            plan(Some(&st), "b2", &pinned, true),
            Plan::New { first: true, .. }
        ));
        // a map at the name that is not the registered one (a plant)
        let swapped = |n: &str| {
            pinned(n).map(|mut s| {
                if n == WRITES_MAP {
                    s.id = 99;
                }
                s
            })
        };
        assert!(matches!(
            plan(Some(&st), "b1", &swapped, true),
            Plan::New { first: false, ref why } if why.contains("id 99")
        ));
        // another version's layout
        let other = |n: &str| {
            pinned(n).map(|mut s| {
                if n == WRITES_MAP {
                    s.value = 8;
                }
                s
            })
        };
        assert!(matches!(
            plan(Some(&st), "b1", &other, true),
            Plan::New { first: false, ref why } if why.contains("another layout")
        ));
        let hash = |n: &str| {
            pinned(n).map(|mut s| {
                s.kind = Some(MapType::Hash);
                s
            })
        };
        assert!(matches!(
            plan(Some(&st), "b1", &hash, true),
            Plan::New { first: false, .. }
        ));
        // a map gone, a map not registered, no link
        let gone = |n: &str| {
            if n == SCRIPTS_MAP {
                Err("no such file".to_string())
            } else {
                pinned(n)
            }
        };
        assert!(matches!(
            plan(Some(&st), "b1", &gone, true),
            Plan::New { first: false, .. }
        ));
        let mut partial = st.clone();
        partial.maps.pop();
        assert!(matches!(
            plan(Some(&partial), "b1", &pinned, true),
            Plan::New { first: false, ref why } if why.contains("not registered")
        ));
        assert!(matches!(
            plan(Some(&st), "b1", &pinned, false),
            Plan::New { first: false, ref why } if why.contains("link")
        ));
    }

    #[test]
    fn the_state_renders_and_parses_back() {
        let st = registered();
        assert_eq!(State::parse(&st.render()), Some(st.clone()));
        assert_eq!(State::parse("boot b1\n"), None);
        assert_eq!(State::parse("boot b1\nsince 1 2\nmap X\n"), None);
        assert_eq!(State::parse("boot b1\nsince 1 2\nextra 3\n"), None);
        assert_eq!(
            pin_dir(Path::new("/sys/fs/bpf/northnarrow")),
            Path::new("/sys/fs/bpf/northnarrow-module-writes")
        );
        assert_eq!(
            link_pin(Path::new("/sys/fs/bpf/northnarrow-module-writes")),
            Path::new("/sys/fs/bpf/northnarrow-module-writes/link_file_open")
        );
        assert!(is_kept_program("module_write_observe"));
        assert!(!is_kept_program("protected_open_deny"));
    }
}
