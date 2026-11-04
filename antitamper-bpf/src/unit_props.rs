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
use crate::systemd_bus::{unit_property, Value};
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

#[cfg(test)]
mod tests {
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
