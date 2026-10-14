//! `ThrottleProcess` — apply hard CPU/IO/memory caps to a target PID
//! via cgroup v2.
//!
//! Strategy: a single shared scope at
//! `<cgroup_root>/<slice>/throttled.scope` with:
//! - `cpu.max = "10000 100000"` → 10% of one CPU
//! - `io.weight = 10`           → minimum priority IO scheduling
//! - `memory.high = 100M`       → soft memory pressure trigger
//!
//! Multiple PIDs share the scope. Adding a PID is idempotent
//! (`cgroup.procs` accepts duplicates as no-ops). [`release_pid`]
//! moves the PID back to the cgroup root.

use std::collections::HashSet;
use std::fs;
use std::io::ErrorKind;
use std::path::Path;

use tracing::{info, warn};

use super::{
    block_outbound::{create_cgroup_dir, write_pid},
    config::ExecutorConfig,
    ExecutionOutcome,
};

/// 10% of one core, 100ms period.
pub const CPU_MAX: &str = "10000 100000";
/// 100 MiB soft memory limit.
pub const MEMORY_HIGH_BYTES: u64 = 100 * 1024 * 1024;
/// Minimum IO scheduling weight in the BFQ-like cgroup scheduler.
pub const IO_WEIGHT: u16 = 10;
/// Effective CPU cap reported in [`ExecutionOutcome::Throttled`].
pub const CPU_MAX_PCT: u8 = 10;

pub fn throttle_pid(pid: u32, protected: &HashSet<u32>, cfg: &ExecutorConfig) -> ExecutionOutcome {
    if pid == 0 {
        return ExecutionOutcome::Refused {
            pid,
            reason: "PID 0 invalid",
        };
    }
    if protected.contains(&pid) {
        return ExecutionOutcome::Refused {
            pid,
            reason: "PID is protected",
        };
    }

    if cfg.dry_run {
        info!(pid, "dry-run: would throttle pid");
        return ExecutionOutcome::Throttled {
            pid,
            cpu_max_pct: Some(CPU_MAX_PCT),
            io_weight: Some(IO_WEIGHT),
            memory_high_bytes: Some(MEMORY_HIGH_BYTES),
        };
    }

    // A process under the blocked scope — blocked, or in a kill cgroup
    // being killed (CMB-019) — stays there: the move would lift its egress
    // drop, or take it out of the kill.
    if super::block_outbound::pid_under_blocked_scope(pid, cfg) {
        warn!(
            pid,
            "throttle: the process is blocked (or being killed) — not moved"
        );
        return ExecutionOutcome::Refused {
            pid,
            reason: "in the blocked scope: moving it would lift the egress drop",
        };
    }
    let dir = cfg.throttled_cgroup_dir();
    if let Err(e) = ensure_throttled_cgroup(&dir, cfg) {
        return io_failed(pid, "ensure_throttled_cgroup", &e);
    }
    // External audit CMB-013: the limits first, read back; a scope where
    // none could be set throttles nothing, so the process is not moved.
    let applied = match write_throttle_limits(&dir) {
        Ok(a) => a,
        Err(e) => return io_failed(pid, "write_throttle_limits", &e),
    };
    if applied.is_empty() {
        warn!(
            pid,
            scope = %dir.display(),
            "throttle: no limit could be set (cpu, io and memory controllers unavailable) — not moved"
        );
        return ExecutionOutcome::Failed {
            pid,
            errno: libc::EOPNOTSUPP,
        };
    }
    // External audit CMB-010: where it came from, recorded for the release.
    let origin = super::containment::origin_of(pid);
    let start_ticks = super::block_outbound::proc_start_ticks(pid);
    if let Err(e) = write_pid(&dir.join("cgroup.procs"), pid) {
        if matches!(e.raw_os_error(), Some(libc::ESRCH)) {
            return ExecutionOutcome::AlreadyGone { pid };
        }
        return io_failed(pid, "move_pid_to_throttled", &e);
    }
    if let Some(origin) = origin {
        if let Err(e) = super::containment::record(
            cfg,
            super::containment::Contained {
                pid,
                start_ticks,
                scope: "throttled".into(),
                origin,
                since: super::containment::now(),
            },
        ) {
            warn!(pid, error = %e, "the containment record could not be written — a release will leave it throttled");
        }
    }

    info!(
        pid,
        cpu_max_pct = ?applied.cpu_max_pct,
        io_weight = ?applied.io_weight,
        memory_high = ?applied.memory_high_bytes,
        "throttled pid (limits as read back)"
    );
    ExecutionOutcome::Throttled {
        pid,
        cpu_max_pct: applied.cpu_max_pct,
        io_weight: applied.io_weight,
        memory_high_bytes: applied.memory_high_bytes,
    }
}

/// The limits in force in the throttle scope, as read back.
#[derive(Debug, Default, PartialEq, Eq)]
struct Applied {
    cpu_max_pct: Option<u8>,
    io_weight: Option<u16>,
    memory_high_bytes: Option<u64>,
}

impl Applied {
    fn is_empty(&self) -> bool {
        self.cpu_max_pct.is_none() && self.io_weight.is_none() && self.memory_high_bytes.is_none()
    }
}

/// External audit CMB-010: release a throttled process back to the
/// cgroup it came from (never the root cgroup) — see
/// [`super::containment`].
pub fn release_pid(
    pid: u32,
    start_ticks: Option<u64>,
    cfg: &ExecutorConfig,
) -> std::io::Result<super::containment::Release> {
    let scope_rel = format!("/{}/throttled.scope", cfg.cgroup_slice);
    super::containment::release_to_origin(
        pid,
        start_ticks,
        "throttled",
        cfg,
        &super::containment::Probe {
            in_scope: &|p| {
                super::containment::origin_of(p).is_some_and(|c| c.ends_with(&scope_rel))
            },
            start_of: &super::block_outbound::proc_start_ticks,
        },
    )
}

fn ensure_throttled_cgroup(dir: &Path, cfg: &ExecutorConfig) -> std::io::Result<()> {
    create_cgroup_dir(dir)?;
    // Enable each controller individually on the parent slice.
    // The kernel rejects a multi-controller subtree_control write
    // atomically if any one of the listed controllers is unavailable,
    // so writing them one-by-one yields partial enablement on hosts
    // where (e.g.) the `io` controller isn't compiled in. Best-effort.
    let subtree = cfg
        .cgroup_root
        .join(&cfg.cgroup_slice)
        .join("cgroup.subtree_control");
    for c in ["+cpu", "+io", "+memory"] {
        if let Err(e) = fs::write(&subtree, c) {
            // External audit CMB-013: a limit this controller would set
            // will be missing — said where an operator sees it.
            warn!(controller = c, error = %e, "throttle: enabling the controller failed; its limit will not apply");
        }
    }
    Ok(())
}

/// Write each limit, then read it back: what the outcome reports is what
/// the scope holds (external audit CMB-013).
fn write_throttle_limits(dir: &Path) -> std::io::Result<Applied> {
    write_if_present(&dir.join("cpu.max"), CPU_MAX.as_bytes())?;
    write_if_present(&dir.join("io.weight"), IO_WEIGHT.to_string().as_bytes())?;
    write_if_present(
        &dir.join("memory.high"),
        MEMORY_HIGH_BYTES.to_string().as_bytes(),
    )?;
    let read = |knob: &str| fs::read_to_string(dir.join(knob)).ok();
    Ok(Applied {
        cpu_max_pct: read("cpu.max").as_deref().and_then(parse_cpu_max_pct),
        io_weight: read("io.weight").as_deref().and_then(parse_io_weight),
        memory_high_bytes: read("memory.high").as_deref().and_then(parse_memory_high),
    })
}

/// `cpu.max` reads `"<quota> <period>"` (or `"max <period>"`: no limit).
fn parse_cpu_max_pct(s: &str) -> Option<u8> {
    let mut it = s.split_whitespace();
    let quota: u64 = it.next()?.parse().ok()?;
    let period: u64 = it.next()?.parse().ok()?;
    (period > 0).then(|| (quota * 100 / period).min(u8::MAX as u64) as u8)
}

/// `io.weight` reads `"default <n>"` plus per-device lines on the io
/// controller (BFQ's `io.bfq.weight` reads a bare number).
fn parse_io_weight(s: &str) -> Option<u16> {
    s.lines().find_map(|l| {
        let mut it = l.split_whitespace();
        match (it.next(), it.next()) {
            (Some("default"), Some(n)) => n.parse().ok(),
            (Some(n), None) => n.parse().ok(),
            _ => None,
        }
    })
}

/// `memory.high` reads a byte count, or `"max"` (no limit).
fn parse_memory_high(s: &str) -> Option<u64> {
    s.trim().parse().ok()
}

/// Write to a cgroup interface file. Treats "controller not
/// enabled" cases as warnings instead of fatal errors: we want
/// throttle to apply *some* caps even when the parent slice's
/// `subtree_control` doesn't expose every controller.
///
/// cgroupfs returns surprising errnos here:
/// - `ENOENT` is the obvious "knob missing" case (older kernels).
/// - `EOPNOTSUPP` means the controller refuses this value.
/// - `EACCES` is what cgroupfs returns when a write happens via
///   `O_CREAT` against a path that doesn't exist (it refuses to
///   create new files). This shows up before the open finds the
///   missing knob, so we have to short-circuit on file existence
///   first.
fn write_if_present(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    if !path.exists() {
        warn!(path = %path.display(), "controller knob missing; skipping");
        return Ok(());
    }
    match fs::write(path, bytes) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == ErrorKind::NotFound => {
            warn!(path = %path.display(), "controller knob missing; skipping");
            Ok(())
        }
        Err(e) if matches!(e.raw_os_error(), Some(libc::EOPNOTSUPP)) => {
            warn!(path = %path.display(), "controller not supported; skipping");
            Ok(())
        }
        Err(e) => Err(e),
    }
}

fn io_failed(pid: u32, step: &str, e: &std::io::Error) -> ExecutionOutcome {
    warn!(pid, step, error = %e, "throttle failed");
    ExecutionOutcome::Failed {
        pid,
        errno: e.raw_os_error().unwrap_or(0),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn dry_cfg(tmp: &TempDir) -> ExecutorConfig {
        ExecutorConfig::for_test(tmp.path())
    }

    #[test]
    fn dry_run_returns_throttled_without_touching_system() {
        let tmp = TempDir::new().unwrap();
        let cfg = dry_cfg(&tmp);
        let protected = HashSet::new();
        let out = throttle_pid(4242, &protected, &cfg);
        assert!(matches!(
            out,
            ExecutionOutcome::Throttled {
                pid: 4242,
                cpu_max_pct: Some(10),
                io_weight: Some(10),
                memory_high_bytes: Some(MEMORY_HIGH_BYTES),
            }
        ));
        assert!(!cfg.throttled_cgroup_dir().exists());
    }

    /// External audit CMB-013: a scope where no limit can be set (no
    /// controller knobs, as in a tempdir) throttles nothing — `Failed`, and
    /// the process is not moved.
    #[test]
    fn a_scope_without_knobs_fails_and_moves_nothing() {
        let tmp = TempDir::new().unwrap();
        let cfg = ExecutorConfig {
            dry_run: false,
            ..ExecutorConfig::for_test(tmp.path())
        };
        let dir = cfg.throttled_cgroup_dir();
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("cgroup.procs"), b"").unwrap();
        let out = throttle_pid(std::process::id() + 1_000_000, &HashSet::new(), &cfg);
        assert!(
            matches!(out, ExecutionOutcome::Failed { errno, .. } if errno == libc::EOPNOTSUPP),
            "{out:?}"
        );
        assert_eq!(
            std::fs::read_to_string(dir.join("cgroup.procs")).unwrap(),
            ""
        );
    }

    /// External audit CMB-013: the limits are reported as read back.
    #[test]
    fn limits_are_parsed_as_the_kernel_shows_them() {
        assert_eq!(parse_cpu_max_pct("10000 100000\n"), Some(10));
        assert_eq!(parse_cpu_max_pct("max 100000\n"), None);
        assert_eq!(parse_io_weight("default 10\n8:0 100\n"), Some(10));
        assert_eq!(parse_io_weight("10\n"), Some(10));
        assert_eq!(parse_io_weight("8:0 100\n"), None);
        assert_eq!(parse_memory_high("104857600\n"), Some(104_857_600));
        assert_eq!(parse_memory_high("max\n"), None);
        // knobs written in a plain directory read back as written
        let tmp = TempDir::new().unwrap();
        for (knob, v) in [("cpu.max", ""), ("io.weight", ""), ("memory.high", "")] {
            std::fs::write(tmp.path().join(knob), v).unwrap();
        }
        let a = write_throttle_limits(tmp.path()).unwrap();
        assert_eq!(
            a,
            Applied {
                cpu_max_pct: Some(CPU_MAX_PCT),
                io_weight: Some(IO_WEIGHT),
                memory_high_bytes: Some(MEMORY_HIGH_BYTES),
            }
        );
    }

    #[test]
    fn cgroup_layout_is_under_slice_throttled_scope() {
        let cfg = ExecutorConfig {
            cgroup_root: "/sys/fs/cgroup".into(),
            cgroup_slice: "northnarrow.slice".into(),
            ..ExecutorConfig::default()
        };
        assert_eq!(
            cfg.throttled_cgroup_dir().to_string_lossy(),
            "/sys/fs/cgroup/northnarrow.slice/throttled.scope"
        );
    }

    #[test]
    fn cpu_max_value_is_correctly_formatted() {
        // The kernel parses `cpu.max` as `"<quota> <period>"` with
        // microsecond units. Ten percent of one core = 10000us out
        // of every 100000us slice.
        assert_eq!(CPU_MAX, "10000 100000");
        let parts: Vec<&str> = CPU_MAX.split_whitespace().collect();
        let quota: u32 = parts[0].parse().unwrap();
        let period: u32 = parts[1].parse().unwrap();
        assert_eq!(quota * 10, period);
    }

    #[test]
    fn refuses_protected_pid() {
        let tmp = TempDir::new().unwrap();
        let cfg = dry_cfg(&tmp);
        let mut protected = HashSet::new();
        protected.insert(7);
        let out = throttle_pid(7, &protected, &cfg);
        assert!(matches!(
            out,
            ExecutionOutcome::Refused {
                pid: 7,
                reason: "PID is protected"
            }
        ));
    }
}
