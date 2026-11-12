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

use nn_core::response::cgroup::{cgroup_at, cgroup_at_or_under};
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

/// R12c (lab PR 270): only for an action whose intent is signed (`_intent`).
pub fn throttle_pid(
    pid: u32,
    protected: &HashSet<u32>,
    cfg: &ExecutorConfig,
    _intent: &super::journal::Intent,
) -> ExecutionOutcome {
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

    // External audit CMB-020: detect-only touches nothing and says so —
    // `Throttled` with the three limits here was a cap never set.
    if cfg.dry_run {
        info!(pid, "dry-run: would throttle pid");
        return ExecutionOutcome::WouldExecute { pid };
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
    // Lot 312 (external bug hunt 1.4, BUG-117): a process already in the
    // scope (a second throttle) came from where the first record says —
    // `containment::record` keeps that one; the scope is never its origin.
    let scope = super::containment::scope_of(cfg, "throttled");
    let origin = super::containment::origin_of(pid);
    let start_ticks = super::block_outbound::proc_start_ticks(pid);
    if let Err(e) = write_pid(&dir.join("cgroup.procs"), pid) {
        if matches!(e.raw_os_error(), Some(libc::ESRCH)) {
            return ExecutionOutcome::AlreadyGone { pid };
        }
        return io_failed(pid, "move_pid_to_throttled", &e);
    }
    // Lot 312 (F5): read back — the process in the agent's throttle scope,
    // by components from the root, or the outcome says it is not.
    if !super::containment::origin_of(pid).is_some_and(|c| cgroup_at(&c, &scope)) {
        warn!(
            pid,
            "throttle: moved, but /proc/<pid>/cgroup does not place it in the scope"
        );
        return ExecutionOutcome::NotInEffect {
            pid,
            reason: "moved, but /proc/<pid>/cgroup does not place it in the agent's throttle scope",
        };
    }
    if let Some(origin) = origin.filter(|o| !cgroup_at_or_under(o, &scope)) {
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
    // Lot 312 (BUG-117 and its sibling): the agent's scope from the root,
    // by components — `ends_with` took a namesake for it.
    let scope = super::containment::scope_of(cfg, "throttled");
    super::containment::release_to_origin(
        pid,
        start_ticks,
        "throttled",
        cfg,
        &super::containment::Probe {
            in_scope: &|p| super::containment::origin_of(p).is_some_and(|c| cgroup_at(&c, &scope)),
            start_of: &super::block_outbound::proc_start_ticks,
            cgroup_of: &super::containment::origin_of,
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
/// the scope holds (external audit CMB-013). Lot 312 (external bug hunt
/// 1.4, BUG-123): a limit counts only when it reads back as the value
/// asked for — a skipped `io.weight` reads `default 100`, which is no
/// limit, and was reported as one. A value equal to the one asked for, left
/// by an earlier throttle, is in force and counts.
fn write_throttle_limits(dir: &Path) -> std::io::Result<Applied> {
    write_if_present(&dir.join("cpu.max"), CPU_MAX.as_bytes())?;
    write_if_present(&dir.join("io.weight"), IO_WEIGHT.to_string().as_bytes())?;
    write_if_present(
        &dir.join("memory.high"),
        MEMORY_HIGH_BYTES.to_string().as_bytes(),
    )?;
    Ok(read_back(dir))
}

/// The limits the scope `dir` holds, each only where it is the value the
/// throttle asks for (lot 312, BUG-123).
fn read_back(dir: &Path) -> Applied {
    let read = |knob: &str| fs::read_to_string(dir.join(knob)).ok();
    Applied {
        cpu_max_pct: read("cpu.max")
            .as_deref()
            .and_then(parse_cpu_max_pct)
            .filter(|v| *v == CPU_MAX_PCT),
        io_weight: read("io.weight")
            .as_deref()
            .and_then(parse_io_weight)
            .filter(|v| *v == IO_WEIGHT),
        memory_high_bytes: read("memory.high")
            .as_deref()
            .and_then(parse_memory_high)
            .filter(|v| *v == MEMORY_HIGH_BYTES),
    }
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

    /// External audit CMB-020: detect-only reports `WouldExecute`, never
    /// `Throttled` with limits it did not set.
    #[test]
    fn dry_run_returns_would_execute_without_touching_system() {
        let tmp = TempDir::new().unwrap();
        let cfg = dry_cfg(&tmp);
        let protected = HashSet::new();
        let out = throttle_pid(
            4242,
            &protected,
            &cfg,
            &super::super::journal::test_intent(),
        );
        assert!(
            matches!(out, ExecutionOutcome::WouldExecute { pid: 4242 }),
            "{out:?}"
        );
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
        let out = throttle_pid(
            std::process::id() + 1_000_000,
            &HashSet::new(),
            &cfg,
            &super::super::journal::test_intent(),
        );
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
        let out = throttle_pid(7, &protected, &cfg, &super::super::journal::test_intent());
        assert!(matches!(
            out,
            ExecutionOutcome::Refused {
                pid: 7,
                reason: "PID is protected"
            }
        ));
    }

    /// Lot 312 (external bug hunt 1.4, BUG-123): a knob that does not read
    /// back the value asked for is no limit — a skipped `io.weight` reads
    /// the default (`default 100`), another throttle's or an operator's
    /// value is not this one. Each such knob is `None`, so the outcome is
    /// partial (or failed), never a full `Throttled`.
    #[test]
    fn bug123_a_limit_counts_only_as_the_value_asked_for() {
        let tmp = TempDir::new().unwrap();
        let d = tmp.path();
        let put = |k: &str, v: &str| std::fs::write(d.join(k), v).unwrap();
        put("cpu.max", "10000 100000\n");
        put("io.weight", "default 100\n");
        put("memory.high", "104857600\n");
        let a = read_back(d);
        assert_eq!(
            a.io_weight, None,
            "BUG-123: the default weight is no limit: {a:?}"
        );
        assert_eq!(a.cpu_max_pct, Some(CPU_MAX_PCT));
        assert_eq!(a.memory_high_bytes, Some(MEMORY_HIGH_BYTES));
        put("memory.high", "209715200\n");
        assert_eq!(
            read_back(d).memory_high_bytes,
            None,
            "another limit is not this one"
        );
        put("cpu.max", "20000 100000\n");
        put("memory.high", "max\n");
        put("io.weight", "default 10\n8:0 100\n");
        let a = read_back(d);
        assert_eq!(
            a,
            Applied {
                cpu_max_pct: None,
                io_weight: Some(IO_WEIGHT),
                memory_high_bytes: None,
            }
        );
        // the signed row of a throttle whose weight did not take
        let (result, _, reason) = super::super::journal_outcome(&super::super::ExecutionReport {
            action: nn_model::ResponseAction::ThrottleProcess,
            primary: ExecutionOutcome::Throttled {
                pid: 1,
                cpu_max_pct: Some(CPU_MAX_PCT),
                io_weight: None,
                memory_high_bytes: Some(MEMORY_HIGH_BYTES),
            },
            additional: Vec::new(),
            elapsed: std::time::Duration::from_micros(1),
        });
        assert_eq!(result, super::super::journal::ActionResult::Partial);
        assert!(reason.is_some());
    }

    /// Lot 312 (F5): a move the cgroupfs took but that does not place the
    /// process in the throttle scope (a plain directory stands for the
    /// cgroup root here) is not `Throttled`: not in effect, and no origin
    /// recorded.
    #[test]
    fn a_move_that_did_not_take_is_not_throttled() {
        let tmp = TempDir::new().unwrap();
        let cfg = ExecutorConfig {
            dry_run: false,
            ..ExecutorConfig::for_test(tmp.path())
        };
        let dir = cfg.throttled_cgroup_dir();
        std::fs::create_dir_all(&dir).unwrap();
        for k in ["cgroup.procs", "cpu.max", "io.weight", "memory.high"] {
            std::fs::write(dir.join(k), b"").unwrap();
        }
        let me = std::process::id();
        let out = throttle_pid(
            me,
            &HashSet::new(),
            &cfg,
            &super::super::journal::test_intent(),
        );
        assert_eq!(
            out,
            ExecutionOutcome::NotInEffect {
                pid: me,
                reason:
                    "moved, but /proc/<pid>/cgroup does not place it in the agent's throttle scope"
            }
        );
        assert_eq!(
            std::fs::read_to_string(dir.join("cgroup.procs")).unwrap(),
            me.to_string()
        );
        assert!(super::super::containment::find(&cfg, me, "throttled").is_none());
    }

    /// Lot 312 (external bug hunt 1.4, BUG-117; privileged: root, systemd,
    /// cgroup v2 with the cpu, io and memory controllers): a unit's process
    /// throttled twice and released goes back to its unit. The second
    /// throttle recorded the scope as its origin, and the release answered
    /// `Released` with the process still throttled.
    #[test]
    #[ignore = "privileged: root, systemd, cgroup v2"]
    fn bug117_throttled_twice_then_released_returns_to_its_unit() {
        use std::process::Command;
        let unit = format!("nn-throttle-victim-{}", std::process::id());
        let ok = Command::new("systemd-run")
            .args(["--unit", &unit, "--quiet", "sleep", "300"])
            .status()
            .unwrap();
        assert!(ok.success());
        std::thread::sleep(std::time::Duration::from_millis(500));
        let out = Command::new("systemctl")
            .args(["show", "-p", "MainPID", "--value", &unit])
            .output()
            .unwrap();
        let pid: u32 = String::from_utf8_lossy(&out.stdout).trim().parse().unwrap();
        let tmp = TempDir::new().unwrap();
        let cfg = ExecutorConfig {
            dry_run: false,
            cgroup_root: "/sys/fs/cgroup".into(),
            cgroup_slice: "northnarrow-test312.slice".into(),
            ..ExecutorConfig::for_test(tmp.path())
        };
        let origin = super::super::containment::origin_of(pid).unwrap();
        let intent = super::super::journal::test_intent();
        let first = throttle_pid(pid, &HashSet::new(), &cfg, &intent);
        let second = throttle_pid(pid, &HashSet::new(), &cfg, &intent);
        let in_scope = super::super::containment::origin_of(pid);
        let released = release_pid(
            pid,
            super::super::block_outbound::proc_start_ticks(pid),
            &cfg,
        );
        let now = super::super::containment::origin_of(pid);
        let _ = Command::new("systemctl").args(["stop", &unit]).status();
        std::thread::sleep(std::time::Duration::from_millis(300));
        let _ = std::fs::remove_dir(cfg.throttled_cgroup_dir());
        let _ = std::fs::remove_dir("/sys/fs/cgroup/northnarrow-test312.slice");
        for o in [&first, &second] {
            assert!(
                matches!(o, ExecutionOutcome::Throttled { .. }),
                "{first:?} / {second:?}"
            );
        }
        assert_eq!(
            in_scope.as_deref(),
            Some("/northnarrow-test312.slice/throttled.scope")
        );
        assert_eq!(
            released.unwrap(),
            super::super::containment::Release::Released
        );
        assert_eq!(
            now,
            Some(origin),
            "BUG-117: back in its unit, not in the scope"
        );
    }
}
