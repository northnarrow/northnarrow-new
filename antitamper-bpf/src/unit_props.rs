//! Lot 273d (the review of #492): our units' resource properties as
//! systemd holds them in memory — its copy, which a refused `set-property`
//! still changed and which the unit's next start applies to its fresh
//! cgroup — read over the private socket (no authorization needed) and
//! judged against the floors (`crate::cgroup_floors`).
//!
//! Read by the agent's reload worker (a refusal of the same file within
//! the quiet period is verified here instead of skipped, and a reload is
//! checked after it) and by the watchdog before each respawn (a
//! `memory.max` of one page in systemd's copy kills the agent at its exec,
//! before any check of its fresh cgroup).

use std::io;
use std::path::Path;
use std::time::Duration;

use crate::cgroup_floors::{below_floor, floor_of, FloorRole};
use crate::systemd_bus::{unit_properties, unit_property, Value};
use common::cgroup_limits::limit_kind_of;

/// The service interface and the slice interface of systemd's units.
pub const SERVICE: &str = "org.freedesktop.systemd1.Service";
pub const SLICE: &str = "org.freedesktop.systemd1.Slice";
pub const UNIT: &str = "org.freedesktop.systemd1.Unit";

/// The properties read, and the cgroup file each sets.
pub const PROPERTIES: &[(&str, &str)] = &[
    ("MemoryMax", "memory.max"),
    ("MemoryHigh", "memory.high"),
    ("TasksMax", "pids.max"),
    ("CPUQuotaPerSecUSec", "cpu.max"),
    ("CPUWeight", "cpu.weight"),
    ("IOWeight", "io.weight"),
];

/// A property of systemd's copy below its floor.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Below {
    pub unit: String,
    pub property: &'static str,
    /// As the cgroup file would hold it.
    pub value: String,
    pub floor: String,
}

impl Below {
    pub fn detail(&self) -> String {
        format!(
            "systemd's copy of {} {}={} is below its floor {:?} (the next start applies it)",
            self.unit, self.property, self.value, self.floor
        )
    }
}

/// `property`'s value (a `t`) as the cgroup file it sets would hold it;
/// `None` for a value that sets nothing there (systemd's "unset").
pub fn as_file_text(file: &str, v: u64) -> Option<String> {
    Some(match file {
        "memory.max" | "memory.high" | "pids.max" => {
            if v == u64::MAX {
                "max".into()
            } else {
                v.to_string()
            }
        }
        // CPUQuotaPerSecUSec: the quota a second; the file's period is
        // systemd's default, 100 ms
        "cpu.max" => {
            if v == u64::MAX {
                "max 100000".into()
            } else {
                format!("{} 100000", v / 10)
            }
        }
        // u64::MAX: not set — the kernel's default, never below
        "cpu.weight" if v != u64::MAX => v.to_string(),
        "io.weight" if v != u64::MAX => format!("default {v}"),
        _ => return None,
    })
}

/// The properties of `unit` (whose floors are `role`'s, read through
/// `interface`) below their floors, through `get` (a property's value; a
/// test's table).
pub fn below_with(
    unit: &str,
    role: FloorRole,
    mut get: impl FnMut(&str) -> io::Result<Value>,
) -> io::Result<Vec<Below>> {
    let mut out = Vec::new();
    for (property, file) in PROPERTIES {
        let Some(floor) = floor_of(role, file) else {
            continue;
        };
        let v = match get(property)? {
            Value::U64(v) => v,
            _ => continue,
        };
        let Some(text) = as_file_text(file, v) else {
            continue;
        };
        if below_floor(limit_kind_of(file), &text, &floor) {
            out.push(Below {
                unit: unit.to_string(),
                property,
                value: text,
                floor,
            });
        }
    }
    Ok(out)
}

/// Our two units and their slice, as systemd holds them, below their
/// floors (through systemd's private socket `socket`, each exchange
/// bounded by `timeout`).
pub fn below_floors(socket: &Path, timeout: Duration) -> io::Result<Vec<Below>> {
    let mut out = Vec::new();
    for (unit, role) in [
        ("northnarrow-agent.service", FloorRole::Agent),
        ("northnarrow-watchdog.service", FloorRole::Watchdog),
    ] {
        out.extend(below_with(unit, role, |p| {
            unit_property(socket, timeout, unit, SERVICE, p)
        })?);
    }
    // the agent's slice, wherever its unit puts it
    let slice = match unit_property(socket, timeout, "northnarrow-agent.service", UNIT, "Slice")? {
        Value::Str(s) if !s.is_empty() => s,
        _ => "system.slice".to_string(),
    };
    out.extend(below_with(&slice, FloorRole::Slice, |p| {
        unit_property(socket, timeout, &slice, SLICE, p)
    })?);
    Ok(out)
}

/// Lot 273d: the configured value of the cgroup file at `path` — systemd's
/// copy of its unit's property (the unit is the file's directory), as the
/// file would hold it; `None` for a file without a property here, or a
/// value systemd does not set. Read after a confirmed reload, when the
/// copy is the units' files again.
pub fn configured_text(
    socket: &Path,
    timeout: Duration,
    path: &Path,
) -> io::Result<Option<String>> {
    let (Some(name), Some(unit)) = (
        path.file_name().and_then(|n| n.to_str()),
        path.parent()
            .and_then(|d| d.file_name())
            .and_then(|n| n.to_str()),
    ) else {
        return Ok(None);
    };
    let Some((property, _)) = PROPERTIES.iter().find(|(_, f)| *f == name) else {
        return Ok(None);
    };
    let iface = if unit.ends_with(".slice") {
        SLICE
    } else {
        SERVICE
    };
    Ok(
        match unit_property(socket, timeout, unit, iface, property)? {
            Value::U64(v) => as_file_text(name, v),
            _ => None,
        },
    )
}

/// The re-check of #582 (N3): what systemd holds in memory of a unit for
/// the code its next start runs — the copy the start applies, which a
/// drop-in loaded by a `daemon-reload` and deleted since still holds.
/// Kept in memory to compare; a record names drop-in paths and variable
/// names only, never an environment value or a command line.
#[derive(Clone, PartialEq, Eq, Default)]
pub struct LoadedView {
    /// `DropInPaths`: every drop-in systemd loaded for the unit.
    pub dropins: Vec<String>,
    /// `NeedDaemonReload`: its files on disk are not what it loaded.
    pub need_reload: bool,
    /// `Environment`'s entries.
    pub env: Vec<String>,
    /// `UnsetEnvironment`'s entries.
    pub unset: Vec<String>,
    /// `MemoryDenyWriteExecute`.
    pub mdwe: bool,
    /// `ExecStartPre`, `ExecStart` and `ExecStartPost`: each command's
    /// path, arguments and ignore flag (never its run times).
    pub exec: String,
}

impl std::fmt::Debug for LoadedView {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LoadedView")
            .field("dropins", &self.dropins)
            .field("need_reload", &self.need_reload)
            .field("env_names", &self.env_names())
            .field("unset", &self.unset.len())
            .field("mdwe", &self.mdwe)
            .field("exec_bytes", &self.exec.len())
            .finish()
    }
}

impl LoadedView {
    /// The names `Environment` sets (never their values), sorted, once each.
    pub fn env_names(&self) -> Vec<String> {
        let mut n: Vec<String> = self
            .env
            .iter()
            .map(|e| e.split('=').next().unwrap_or("").to_string())
            .collect();
        n.sort();
        n.dedup();
        n
    }
}

/// The properties a [`LoadedView`] is read from, in order.
pub const LOADED_VIEW: &[(&str, &str)] = &[
    (UNIT, "DropInPaths"),
    (UNIT, "NeedDaemonReload"),
    (SERVICE, "Environment"),
    (SERVICE, "UnsetEnvironment"),
    (SERVICE, "MemoryDenyWriteExecute"),
    (SERVICE, "ExecStartPre"),
    (SERVICE, "ExecStart"),
    (SERVICE, "ExecStartPost"),
];

/// [`LoadedView`] of the values of [`LOADED_VIEW`], in order.
pub fn loaded_view_of(v: &[Value]) -> io::Result<LoadedView> {
    let bad = |what: &str| io::Error::other(format!("{what}: not the type systemd gives"));
    let [dropins, need, env, unset, mdwe, pre, start, post] = v else {
        return Err(io::Error::other(format!(
            "{} values for {} properties",
            v.len(),
            LOADED_VIEW.len()
        )));
    };
    let dropins = dropins.strings().ok_or_else(|| bad("DropInPaths"))?;
    let Value::Bool(need_reload) = need else {
        return Err(bad("NeedDaemonReload"));
    };
    let env = env.strings().ok_or_else(|| bad("Environment"))?;
    let unset = unset.strings().ok_or_else(|| bad("UnsetEnvironment"))?;
    let Value::Bool(mdwe) = mdwe else {
        return Err(bad("MemoryDenyWriteExecute"));
    };
    let mut exec = String::new();
    for (name, cmds) in [
        ("ExecStartPre", pre),
        ("ExecStart", start),
        ("ExecStartPost", post),
    ] {
        let Value::Array(cmds) = cmds else {
            return Err(bad(name));
        };
        for c in cmds {
            // (path, argv, ignore, start and exit times, pid, code, status)
            let Value::Struct(f) = c else {
                return Err(bad(name));
            };
            let (Some(path), Some(argv), Some(Value::Bool(ignore))) = (
                f.first().and_then(Value::as_str),
                f.get(1).and_then(Value::strings),
                f.get(2),
            ) else {
                return Err(bad(name));
            };
            exec.push_str(&format!("{name}\0{path}\0{}\0{ignore}\n", argv.join("\0")));
        }
    }
    Ok(LoadedView {
        dropins,
        need_reload: *need_reload,
        env,
        unset,
        mdwe: *mdwe,
        exec,
    })
}

/// The re-check of #582 (N3): [`LoadedView`] of unit `unit` as systemd
/// holds it, through its private socket `socket` (each exchange bounded by
/// `timeout`).
pub fn loaded_view(socket: &Path, timeout: Duration, unit: &str) -> io::Result<LoadedView> {
    loaded_view_of(&unit_properties(socket, timeout, unit, LOADED_VIEW)?)
}

#[cfg(test)]
mod tests {
    /// The re-check of #582 (N3): systemd's copy of a unit, as a respawn
    /// judges it — its drop-ins, whether its files changed since it loaded
    /// them, its environment, the variables it unsets, its memory's
    /// protection and its commands (never their run times) — and a record
    /// of it never shows a value or a command line.
    #[test]
    fn systemd_s_copy_of_a_unit_is_read_for_what_its_start_runs() {
        use super::*;
        let s = |x: &str| Value::Str(x.into());
        let strings = |v: &[&str]| Value::Array(v.iter().map(|x| s(x)).collect());
        let cmd = |path: &str, pid: u32| {
            Value::Struct(vec![
                s(path),
                strings(&[path, "--x"]),
                Value::Bool(false),
                Value::U64(1),
                Value::U64(2),
                Value::U64(3),
                Value::U64(4),
                Value::U32(pid),
                Value::I32(1),
                Value::I32(0),
            ])
        };
        let values = |env: &[&str], mdwe: bool, path: &str, pid: u32| {
            vec![
                strings(&["/etc/systemd/system/northnarrow-agent.service.d/10-x.conf"]),
                Value::Bool(false),
                strings(env),
                strings(&["LD_PRELOAD", "LD_AUDIT"]),
                Value::Bool(mdwe),
                Value::Array(vec![]),
                Value::Array(vec![cmd(path, pid)]),
                Value::Array(vec![]),
            ]
        };
        let a = loaded_view_of(&values(&["RUST_LOG=info"], true, "/usr/bin/a", 7)).unwrap();
        assert_eq!(a.dropins.len(), 1);
        assert!(a.mdwe && !a.need_reload);
        assert_eq!(a.env_names(), ["RUST_LOG"]);
        // the run's times and pid are not the command
        let b = loaded_view_of(&values(&["RUST_LOG=info"], true, "/usr/bin/a", 9)).unwrap();
        assert_eq!(a, b);
        let c = loaded_view_of(&values(&["RUST_LOG=info"], true, "/usr/bin/b", 7)).unwrap();
        assert_ne!(a.exec, c.exec);
        let d = loaded_view_of(&values(&["RUST_LOG=debug"], false, "/usr/bin/a", 7)).unwrap();
        assert_ne!(a.env, d.env);
        assert!(!d.mdwe);
        let shown = format!("{d:?}");
        assert!(
            !shown.contains("debug") && !shown.contains("/usr/bin/a"),
            "{shown}"
        );
        // a value of another type, or another count, is refused
        let mut bad = values(&[], true, "/usr/bin/a", 7);
        bad[4] = Value::U32(1);
        assert!(loaded_view_of(&bad).is_err());
        assert!(loaded_view_of(&bad[..3]).is_err());
    }

    use super::*;

    #[test]
    fn systemds_values_read_as_the_files_would_hold_them() {
        assert_eq!(as_file_text("memory.max", u64::MAX).as_deref(), Some("max"));
        assert_eq!(as_file_text("memory.max", 4096).as_deref(), Some("4096"));
        assert_eq!(as_file_text("pids.max", 8).as_deref(), Some("8"));
        // CPUQuota=10% is 100 ms a second
        assert_eq!(
            as_file_text("cpu.max", 100_000).as_deref(),
            Some("10000 100000")
        );
        assert_eq!(
            as_file_text("cpu.max", u64::MAX).as_deref(),
            Some("max 100000")
        );
        assert_eq!(as_file_text("cpu.weight", u64::MAX), None);
        assert_eq!(as_file_text("io.weight", 10).as_deref(), Some("default 10"));
    }

    #[test]
    fn a_copy_below_a_floor_is_found_and_the_units_own_values_are_not() {
        let get = |table: &'static [(&'static str, u64)]| {
            move |p: &str| -> io::Result<Value> {
                Ok(Value::U64(
                    table
                        .iter()
                        .find(|(k, _)| *k == p)
                        .map_or(u64::MAX, |(_, v)| *v),
                ))
            }
        };
        // the agent's unit as shipped: MemoryHigh 9G, MemoryMax 11G, 512 tasks
        let shipped: &[(&str, u64)] = &[
            ("MemoryHigh", 9 << 30),
            ("MemoryMax", 11 << 30),
            ("TasksMax", 512),
        ];
        assert!(below_with("a", FloorRole::Agent, get(shipped))
            .unwrap()
            .is_empty());
        // the watchdog's: 64M, 10 %, 8 tasks
        let wd: &[(&str, u64)] = &[
            ("MemoryMax", 64 << 20),
            ("CPUQuotaPerSecUSec", 100_000),
            ("TasksMax", 8),
        ];
        assert!(below_with("w", FloorRole::Watchdog, get(wd))
            .unwrap()
            .is_empty());
        // a refused set-property's copy: MemoryMax 4K
        let hostile: &[(&str, u64)] = &[("MemoryMax", 4096), ("CPUWeight", 1)];
        let b = below_with("a", FloorRole::Agent, get(hostile)).unwrap();
        assert_eq!(b.len(), 2, "{b:?}");
        assert_eq!((b[0].property, b[0].value.as_str()), ("MemoryMax", "4096"));
        assert!(b[0].detail().contains("below its floor"));
    }
}
