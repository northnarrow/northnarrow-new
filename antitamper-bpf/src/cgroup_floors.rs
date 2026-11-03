//! Lot 273c (the review of #490): the floors of the protected units' and
//! slices' resource files.
//!
//! The registration takes the value a file holds as the one PID 1 may
//! write back — at a start, the fresh cgroup's, which systemd filled from
//! its own copy of the unit (a refused `set-property` still sets that copy,
//! in memory, until a reload), and at a window's close whatever was written
//! inside it. A value below a sane floor is not registered: the floor is
//! registered first, then written to the file (the agent and the watchdog
//! may), then read back — PID 1 cannot put the hostile value back in
//! between, its write is no longer the registered one. Each restoration is
//! reported (a signed integrity drift in the agent).
//!
//! The floors (`floor_of`): the agent's unit at least 512 MiB of memory,
//! 256 tasks, half a CPU; the watchdog's what its unit sets (32 MiB, 8
//! tasks, 10 % of a CPU); a slice 1 GiB, 1024 tasks, one CPU, room for 4096
//! cgroups 8 deep; everywhere `cpu.weight` 100, `cpu.weight.nice` 0, no
//! `cpu.idle`, no `memory.oom.group`, no `io.max` limit, an I/O weight of
//! 100; a unit's `cpuset.*` its parent's (empty, `member`).

use std::path::{Path, PathBuf};

use anyhow::Result;
use common::cgroup_limits::{
    limit_kind_of, limit_value, LimitValue, LIMIT_CPU_LIST, LIMIT_CPU_MAX, LIMIT_FILES, LIMIT_FLAG,
    LIMIT_IO_MAX, LIMIT_IO_WEIGHT, LIMIT_NICE, LIMIT_PARTITION, LIMIT_UNSIGNED_MAX, LIMIT_WEIGHT,
};
use common::wire::InodeKey;

/// Whose cgroup the floors are for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FloorRole {
    Agent,
    Watchdog,
    Slice,
}

/// The role of the cgroup directory `dir`, by its name: the watchdog's
/// unit, a slice, any other service (the agent's).
pub fn floor_role(dir: &Path) -> FloorRole {
    match dir.file_name().and_then(|n| n.to_str()) {
        Some("northnarrow-watchdog.service") => FloorRole::Watchdog,
        Some(n) if n.ends_with(".slice") => FloorRole::Slice,
        _ => FloorRole::Agent,
    }
}

const MIB: u64 = 1 << 20;

/// The floor of resource file `name` in a cgroup of `role`: the text a
/// value below it is replaced with, or `None` (any value is acceptable, or
/// the file is the host's to set: a slice's `cpuset.*`).
pub fn floor_of(role: FloorRole, name: &str) -> Option<String> {
    let mem = match role {
        FloorRole::Agent => 512 * MIB,
        FloorRole::Watchdog => 32 * MIB,
        FloorRole::Slice => 1024 * MIB,
    };
    Some(match (name, role) {
        ("memory.max" | "memory.high", _) => mem.to_string(),
        ("pids.max", FloorRole::Agent) => "256".into(),
        ("pids.max", FloorRole::Watchdog) => "8".into(),
        ("pids.max", FloorRole::Slice) => "1024".into(),
        ("cpu.max", FloorRole::Agent) => "50000 100000".into(),
        ("cpu.max", FloorRole::Watchdog) => "10000 100000".into(),
        ("cpu.max", FloorRole::Slice) => "100000 100000".into(),
        ("cgroup.max.descendants", FloorRole::Slice) => "4096".into(),
        ("cgroup.max.depth", FloorRole::Slice) => "8".into(),
        ("cpu.weight", _) => "100".into(),
        ("cpu.weight.nice" | "cpu.idle" | "memory.oom.group", _) => "0".into(),
        ("io.max", _) => String::new(),
        ("io.weight" | "io.bfq.weight", _) => "default 100".into(),
        ("cpuset.cpus" | "cpuset.mems", FloorRole::Agent | FloorRole::Watchdog) => String::new(),
        ("cpuset.cpus.partition", FloorRole::Agent | FloorRole::Watchdog) => "member".into(),
        _ => return None,
    })
}

/// `max` or a number, as an ordered amount (`max` the largest).
fn amount(t: &str) -> Option<u128> {
    if t == "max" {
        Some(u128::MAX)
    } else {
        t.parse::<u64>().ok().map(u128::from)
    }
}

/// `cpu.max`'s share of a CPU, in millionths (`max` the largest).
fn cpu_share(t: &str) -> Option<u128> {
    let mut it = t.split_whitespace();
    let quota = it.next()?;
    let period: u128 = it.next().map_or(Some(100_000), |p| p.parse().ok())?;
    if period == 0 {
        return None;
    }
    if quota == "max" {
        return Some(u128::MAX);
    }
    Some(quota.parse::<u128>().ok()? * 1_000_000 / period)
}

/// `io.weight`'s default weight (`default 100`, the first line).
fn io_default_weight(t: &str) -> Option<u64> {
    t.lines()
        .find_map(|l| l.trim().strip_prefix("default "))
        .and_then(|w| w.trim().parse().ok())
}

/// `true` when `current` (a file's text, trimmed) is below `floor` for a
/// file of `kind`. A text that cannot be read as its kind is below: the
/// floor is the known good value.
pub fn below_floor(kind: u8, current: &str, floor: &str) -> bool {
    let current = current.trim();
    match kind {
        LIMIT_UNSIGNED_MAX => match (amount(current), amount(floor)) {
            (Some(c), Some(f)) => c < f,
            _ => true,
        },
        LIMIT_CPU_MAX => match (cpu_share(current), cpu_share(floor)) {
            (Some(c), Some(f)) => c < f,
            _ => true,
        },
        LIMIT_WEIGHT => match (current.parse::<u64>(), floor.parse::<u64>()) {
            (Ok(c), Ok(f)) => c < f,
            _ => true,
        },
        LIMIT_NICE => match current.parse::<i64>() {
            Ok(n) => n > 0,
            _ => true,
        },
        LIMIT_FLAG => current != "0",
        // a line of a device whose limits are not all `max`
        LIMIT_IO_MAX => current
            .lines()
            .any(|l| l.split_whitespace().skip(1).any(|kv| !kv.ends_with("=max"))),
        LIMIT_IO_WEIGHT => match (io_default_weight(current), io_default_weight(floor)) {
            (Some(c), Some(f)) => c < f,
            _ => true,
        },
        LIMIT_CPU_LIST => current != floor,
        LIMIT_PARTITION => current != floor,
        _ => false,
    }
}

/// One file below its floor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FloorDue {
    pub path: PathBuf,
    pub key: InodeKey,
    pub name: &'static str,
    /// What it held.
    pub was: String,
    /// What is registered for it.
    pub floor: String,
    /// What is written, in order (`io.max`: one line per limited device).
    pub writes: Vec<String>,
}

/// What a restoration did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FloorRestore {
    pub path: PathBuf,
    pub was: String,
    pub floor: String,
    /// The file read back as its floor.
    pub ok: bool,
    /// Why not, when not.
    pub why: Option<String>,
}

impl FloorRestore {
    /// One line for the journal and the signed drift.
    pub fn detail(&self) -> String {
        if self.ok {
            format!(
                "{}: {:?} below the floor, restored to {:?}",
                self.path.display(),
                self.was,
                self.floor
            )
        } else {
            format!(
                "{}: {:?} below the floor {:?}, NOT restored: {}",
                self.path.display(),
                self.was,
                self.floor,
                self.why.as_deref().unwrap_or("read back another value")
            )
        }
    }
}

/// The files of the cgroup directories `dirs` below their floors. A file
/// that is not there, or cannot be read, is not due (`memory.reclaim` has
/// no value).
pub fn floors_due(dirs: &[PathBuf]) -> Vec<FloorDue> {
    use std::os::unix::fs::MetadataExt;
    let mut out = Vec::new();
    for dir in dirs {
        let role = floor_role(dir);
        for (name, kind) in LIMIT_FILES {
            let Some(floor) = floor_of(role, name) else {
                continue;
            };
            let path = dir.join(name);
            let Ok(meta) = std::fs::symlink_metadata(&path) else {
                continue;
            };
            if !meta.file_type().is_file() {
                continue;
            }
            let Ok(text) = std::fs::read_to_string(&path) else {
                continue;
            };
            if !below_floor(kind, &text, &floor) {
                continue;
            }
            let writes = if kind == LIMIT_IO_MAX {
                text.lines()
                    .filter_map(|l| l.split_whitespace().next())
                    .map(|dev| format!("{dev} rbps=max wbps=max riops=max wiops=max"))
                    .collect()
            } else {
                vec![floor.clone()]
            };
            out.push(FloorDue {
                path,
                key: InodeKey {
                    dev: crate::cgroup_guard::stat_dev_to_kernel_dev(meta.dev()),
                    ino: meta.ino(),
                },
                name,
                was: text.trim_end().to_string(),
                floor,
                writes,
            });
        }
    }
    out
}

/// Restore each file of `due`: its floor registered first (`register`:
/// into `LIMIT_VALUES`), then written, then read back.
pub fn restore_floors(
    due: Vec<FloorDue>,
    mut register: impl FnMut(&InodeKey, &LimitValue) -> Result<()>,
) -> Vec<FloorRestore> {
    let mut out = Vec::new();
    for d in due {
        let mut r = FloorRestore {
            path: d.path.clone(),
            was: d.was.clone(),
            floor: d.floor.clone(),
            ok: false,
            why: None,
        };
        let Some(value) = limit_value(d.floor.as_bytes()) else {
            r.why = Some("the floor does not fit a registered value".into());
            out.push(r);
            continue;
        };
        if let Err(e) = register(&d.key, &value) {
            r.why = Some(format!("registering the floor: {e:#}"));
            out.push(r);
            continue;
        }
        for w in &d.writes {
            if let Err(e) = std::fs::write(&d.path, format!("{w}\n")) {
                r.why = Some(format!("writing {w:?}: {e}"));
            }
        }
        let back = std::fs::read_to_string(&d.path).unwrap_or_default();
        let kind = limit_kind_of(d.name);
        r.ok = r.why.is_none() && !below_floor(kind, &back, &d.floor);
        if !r.ok && r.why.is_none() {
            r.why = Some(format!("read back {:?}", back.trim_end()));
        }
        out.push(r);
    }
    out
}

/// The restorations of this process not yet reported (the agent signs
/// them at its integrity check; the watchdog logs them).
static PENDING: std::sync::Mutex<Vec<FloorRestore>> = std::sync::Mutex::new(Vec::new());

/// Keep `restores` for [`take_restores`].
pub fn note_restores(restores: &[FloorRestore]) {
    if restores.is_empty() {
        return;
    }
    if let Ok(mut p) = PENDING.lock() {
        p.extend_from_slice(restores);
    }
}

/// The restorations noted since the last call.
pub fn take_restores() -> Vec<FloorRestore> {
    PENDING
        .lock()
        .map(|mut p| std::mem::take(&mut *p))
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_role_is_the_directorys_name() {
        assert_eq!(
            floor_role(Path::new("/sys/fs/cgroup/system.slice")),
            FloorRole::Slice
        );
        assert_eq!(
            floor_role(Path::new(
                "/sys/fs/cgroup/system.slice/northnarrow-watchdog.service"
            )),
            FloorRole::Watchdog
        );
        assert_eq!(
            floor_role(Path::new(
                "/sys/fs/cgroup/system.slice/northnarrow-agent.service"
            )),
            FloorRole::Agent
        );
    }

    #[test]
    fn a_value_below_its_floor_is_found_and_one_above_is_not() {
        use FloorRole::*;
        let f = |role, name| floor_of(role, name).unwrap();
        // memory: bytes or max
        assert!(below_floor(
            LIMIT_UNSIGNED_MAX,
            "4096\n",
            &f(Agent, "memory.max")
        ));
        assert!(!below_floor(
            LIMIT_UNSIGNED_MAX,
            "11811160064",
            &f(Agent, "memory.max")
        ));
        assert!(!below_floor(
            LIMIT_UNSIGNED_MAX,
            "max",
            &f(Slice, "memory.max")
        ));
        assert!(below_floor(
            LIMIT_UNSIGNED_MAX,
            "536870911",
            &f(Agent, "memory.max")
        ));
        assert!(!below_floor(
            LIMIT_UNSIGNED_MAX,
            "536870912",
            &f(Agent, "memory.max")
        ));
        // the watchdog's own unit settings are its floors
        assert!(!below_floor(
            LIMIT_UNSIGNED_MAX,
            "67108864",
            &f(Watchdog, "memory.max")
        ));
        assert!(!below_floor(
            LIMIT_UNSIGNED_MAX,
            "8",
            &f(Watchdog, "pids.max")
        ));
        assert!(below_floor(
            LIMIT_UNSIGNED_MAX,
            "1",
            &f(Watchdog, "pids.max")
        ));
        assert!(!below_floor(
            LIMIT_CPU_MAX,
            "10000 100000",
            &f(Watchdog, "cpu.max")
        ));
        assert!(below_floor(
            LIMIT_CPU_MAX,
            "1000 1000000",
            &f(Watchdog, "cpu.max")
        ));
        // cpu.max: a share of a CPU
        assert!(!below_floor(
            LIMIT_CPU_MAX,
            "max 100000",
            &f(Agent, "cpu.max")
        ));
        assert!(!below_floor(
            LIMIT_CPU_MAX,
            "100000 200000",
            &f(Agent, "cpu.max")
        ));
        assert!(below_floor(
            LIMIT_CPU_MAX,
            "49999 100000",
            &f(Agent, "cpu.max")
        ));
        assert!(below_floor(LIMIT_CPU_MAX, "1000", &f(Slice, "cpu.max")));
        // weights, nice, flags
        assert!(below_floor(LIMIT_WEIGHT, "1", &f(Agent, "cpu.weight")));
        assert!(!below_floor(LIMIT_WEIGHT, "100", &f(Agent, "cpu.weight")));
        assert!(below_floor(LIMIT_NICE, "19", &f(Agent, "cpu.weight.nice")));
        assert!(!below_floor(LIMIT_NICE, "-5", &f(Agent, "cpu.weight.nice")));
        assert!(below_floor(LIMIT_FLAG, "1", &f(Agent, "cpu.idle")));
        assert!(!below_floor(
            LIMIT_FLAG,
            "0\n",
            &f(Slice, "memory.oom.group")
        ));
        // io
        assert!(!below_floor(LIMIT_IO_MAX, "", &f(Agent, "io.max")));
        assert!(!below_floor(
            LIMIT_IO_MAX,
            "8:0 rbps=max wbps=max riops=max wiops=max",
            &f(Agent, "io.max")
        ));
        assert!(below_floor(
            LIMIT_IO_MAX,
            "8:0 rbps=max wbps=1 riops=max wiops=max",
            &f(Agent, "io.max")
        ));
        assert!(below_floor(
            LIMIT_IO_WEIGHT,
            "default 1\n8:0 50",
            &f(Agent, "io.weight")
        ));
        assert!(!below_floor(
            LIMIT_IO_WEIGHT,
            "default 100",
            &f(Agent, "io.weight")
        ));
        // a unit's cpuset is its parent's; a slice's is the host's
        assert!(below_floor(LIMIT_CPU_LIST, "3", &f(Agent, "cpuset.cpus")));
        assert!(!below_floor(LIMIT_CPU_LIST, "\n", &f(Agent, "cpuset.cpus")));
        assert_eq!(floor_of(Slice, "cpuset.cpus"), None);
        assert!(below_floor(
            LIMIT_PARTITION,
            "root",
            &f(Agent, "cpuset.cpus.partition")
        ));
        // a text that is not its kind is below: the floor is known good
        assert!(below_floor(
            LIMIT_UNSIGNED_MAX,
            "lots",
            &f(Agent, "memory.max")
        ));
        // the slice's room for cgroups; none on a unit
        assert!(below_floor(
            LIMIT_UNSIGNED_MAX,
            "0",
            &f(Slice, "cgroup.max.descendants")
        ));
        assert_eq!(floor_of(Agent, "cgroup.max.descendants"), None);
        assert_eq!(floor_of(Agent, "memory.reclaim"), None);
    }

    #[test]
    fn every_floor_is_its_own_kinds_and_not_below_itself() {
        for role in [FloorRole::Agent, FloorRole::Watchdog, FloorRole::Slice] {
            for (name, kind) in LIMIT_FILES {
                if let Some(f) = floor_of(role, name) {
                    assert!(!below_floor(kind, &f, &f), "{role:?} {name} {f:?}");
                    assert!(limit_value(f.as_bytes()).is_some(), "{name}");
                }
            }
        }
    }

    #[test]
    fn a_restoration_registers_the_floor_before_it_writes() {
        let dir = tempfile::tempdir().unwrap();
        let unit = dir.path().join("northnarrow-agent.service");
        std::fs::create_dir(&unit).unwrap();
        std::fs::write(unit.join("memory.max"), "4096\n").unwrap();
        std::fs::write(unit.join("pids.max"), "max\n").unwrap();
        std::fs::write(
            unit.join("io.max"),
            "8:0 rbps=max wbps=1 riops=max wiops=max\n",
        )
        .unwrap();
        let due = floors_due(std::slice::from_ref(&unit));
        let names: Vec<&str> = due.iter().map(|d| d.name).collect();
        assert_eq!(names, ["memory.max", "io.max"], "{due:?}");
        assert_eq!(due[1].writes, ["8:0 rbps=max wbps=max riops=max wiops=max"]);
        let path = unit.join("memory.max");
        let mut seen = Vec::new();
        let r = restore_floors(due, |k, v| {
            // registered before the file changed
            seen.push((*k, *v, std::fs::read_to_string(&path).unwrap()));
            Ok(())
        });
        assert_eq!(seen[0].2, "4096\n", "the floor is registered first");
        assert_eq!(seen[0].1, limit_value(b"536870912").unwrap());
        assert!(r[0].ok, "{r:?}");
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "536870912\n");
        assert!(r[0].detail().contains("restored to \"536870912\""));
        // a plain file keeps the line written: io.max reads back the max line
        assert!(r[1].ok, "{r:?}");
        note_restores(&r);
        assert_eq!(take_restores().len(), 2);
        assert!(take_restores().is_empty());
    }

    #[test]
    fn a_floor_that_cannot_be_registered_is_not_written() {
        let dir = tempfile::tempdir().unwrap();
        let unit = dir.path().join("northnarrow-agent.service");
        std::fs::create_dir(&unit).unwrap();
        std::fs::write(unit.join("cpu.idle"), "1\n").unwrap();
        let r = restore_floors(floors_due(std::slice::from_ref(&unit)), |_, _| {
            anyhow::bail!("map full")
        });
        assert!(!r[0].ok);
        assert_eq!(
            std::fs::read_to_string(unit.join("cpu.idle")).unwrap(),
            "1\n"
        );
        assert!(r[0]
            .detail()
            .contains("NOT restored: registering the floor: map full"));
    }

    #[test]
    fn a_restoration_that_reads_back_below_its_floor_is_not_ok() {
        // the kernel can keep another value than the one written (a
        // parent's narrower cpuset, a rounding): the read-back decides
        let dir = tempfile::tempdir().unwrap();
        let unit = dir.path().join("northnarrow-agent.service");
        std::fs::create_dir(&unit).unwrap();
        let path = unit.join("memory.max");
        std::fs::write(&path, "4096\n").unwrap();
        let due = vec![FloorDue {
            path: path.clone(),
            key: InodeKey { dev: 1, ino: 2 },
            name: "memory.max",
            was: "4096".into(),
            floor: "536870912".into(),
            // what such a kernel would keep
            writes: vec!["8192".into()],
        }];
        let r = restore_floors(due, |_, _| Ok(()));
        assert!(!r[0].ok, "{r:?}");
        assert_eq!(r[0].why.as_deref(), Some("read back \"8192\""));
        assert!(r[0].detail().contains("NOT restored: read back \"8192\""));
    }
}
