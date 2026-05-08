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
            cpu_max_pct: CPU_MAX_PCT,
            io_weight: IO_WEIGHT,
        };
    }

    let dir = cfg.throttled_cgroup_dir();
    if let Err(e) = ensure_throttled_cgroup(&dir, cfg) {
        return io_failed(pid, "ensure_throttled_cgroup", &e);
    }
    if let Err(e) = write_throttle_limits(&dir) {
        return io_failed(pid, "write_throttle_limits", &e);
    }
    if let Err(e) = write_pid(&dir.join("cgroup.procs"), pid) {
        if matches!(e.raw_os_error(), Some(libc::ESRCH)) {
            return ExecutionOutcome::AlreadyGone { pid };
        }
        return io_failed(pid, "move_pid_to_throttled", &e);
    }

    info!(
        pid,
        cpu = CPU_MAX,
        io_weight = IO_WEIGHT,
        memory_high = MEMORY_HIGH_BYTES,
        "throttled pid"
    );
    ExecutionOutcome::Throttled {
        pid,
        cpu_max_pct: CPU_MAX_PCT,
        io_weight: IO_WEIGHT,
    }
}

/// Move a PID back to the root cgroup. Used by tests and a future
/// CLI command. Idempotent.
pub fn release_pid(pid: u32, cfg: &ExecutorConfig) -> std::io::Result<()> {
    if cfg.dry_run {
        return Ok(());
    }
    let root_procs = cfg.cgroup_root.join("cgroup.procs");
    write_pid(&root_procs, pid)
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
            tracing::debug!(controller = c, error = %e, "enable controller failed; skipping");
        }
    }
    Ok(())
}

fn write_throttle_limits(dir: &Path) -> std::io::Result<()> {
    write_if_present(&dir.join("cpu.max"), CPU_MAX.as_bytes())?;
    write_if_present(&dir.join("io.weight"), IO_WEIGHT.to_string().as_bytes())?;
    write_if_present(
        &dir.join("memory.high"),
        MEMORY_HIGH_BYTES.to_string().as_bytes(),
    )?;
    Ok(())
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
                cpu_max_pct: 10,
                io_weight: 10
            }
        ));
        assert!(!cfg.throttled_cgroup_dir().exists());
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
