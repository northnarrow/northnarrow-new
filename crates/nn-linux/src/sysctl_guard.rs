//! Lot 273d (the review of #492): the global sysctls that abort or starve
//! the agent with the rest of the host — `vm.overcommit_memory=2` with a
//! low ratio (its next allocation fails and it aborts), `kernel.pid_max`,
//! `kernel.threads-max` or `vm.max_map_count` cut below what it runs,
//! `kernel.sched_rt_runtime_us=-1` (a real-time hog owns the CPUs).
//!
//! The choice: refused in the kernel AND checked by the integrity round.
//! The write deny refuses a write of one of them outside a trusted-installer
//! window when its value is harmful (`common::cgroup_limits::
//! sysctl_write_harmful`, judged on the bytes written: a raised limit, an
//! overcommit mode 0 or 1 go through — the operator's tuning stays
//! possible, and any tuning inside a window). What the kernel cannot see —
//! a value set before the agent's start (`sysctl.d` at boot) or inside a
//! window — is the round's: a harmful value is put back to a safe one and
//! signed (`sysctl_restored`); `vm.overcommit_memory=2` with a ratio of 50
//! or more is an operator's strict accounting, signed (`sysctl_strict`)
//! and left.
//!
//! R1 of the external review of 04/11: `kernel.ftrace_enabled=0` blinds
//! the agent instead — on 6.0 to 7.2 the kernel turns every call site
//! ftrace manages back into a NOP, with no error, and the BPF trampolines
//! on them stop: the fentry/fexit sensors, the kprobes on ftrace and, by
//! the kernel's code (the lab measures it, `SENSOR_CONTRACT.md` §5a), the
//! BPF-LSM deny hooks. On 5.15 to 5.19 the write is EBUSY while a
//! trampoline is attached; from 7.3 it is refused. Every write of it is
//! refused outside a window, whatever it carries (the coordinator's
//! decision of 04/11: nothing to judge, so nothing for a second thread to
//! race; `common::cgroup_limits::sysctl_write_refused`), the agent's own
//! restore passing by its identity as every guarded write does; a 0 is put
//! back to 1 by the round and at a window's close; and it is
//! read at every build of the capability manifest as well ([`note_ftrace`]):
//! 0, or a value that cannot be read, is a signed degradation while it
//! holds — the manifest changes, and the verifier off the host says
//! DEGRADED.
//!
//! Lot 280b: the kprobes' switches, refused outside a window whatever they
//! carry like `ftrace_enabled` — `debug.kprobes-optimization` (0 makes
//! every kprobe a breakpoint trap: a cost on every probed call, not a
//! blindness) by the write deny and the `cgroup/sysctl` judge, and
//! `/sys/kernel/debug/kprobes/enabled` (debugfs: 0 disarms every kprobe,
//! the agent's among them) by the write deny's debugfs branch; a 0 found
//! by the round (set before the start, inside a window) is put back to 1,
//! signed.

use std::path::Path;

use common::cgroup_limits::{
    limit_value, rt_throttling_off, sysctl_blinds, sysctl_write_harmful, SYSCTL_FTRACE_ENABLED,
    SYSCTL_KPROBES_ENABLED, SYSCTL_KPROBES_OPTIMIZATION, SYSCTL_MAX_MAP_COUNT,
    SYSCTL_OVERCOMMIT_KBYTES, SYSCTL_OVERCOMMIT_MEMORY, SYSCTL_OVERCOMMIT_RATIO, SYSCTL_PID_MAX,
    SYSCTL_SCHED_RT_RUNTIME, SYSCTL_THREADS_MAX,
};

/// The guarded files, their kinds and the safe value put back (`None`:
/// computed, `threads-max`'s kernel default).
pub const GUARDED: &[(&str, u8, Option<&str>)] = &[
    (
        "/proc/sys/vm/overcommit_ratio",
        SYSCTL_OVERCOMMIT_RATIO,
        Some("50"),
    ),
    (
        "/proc/sys/vm/overcommit_kbytes",
        SYSCTL_OVERCOMMIT_KBYTES,
        Some("0"),
    ),
    (
        "/proc/sys/vm/overcommit_memory",
        SYSCTL_OVERCOMMIT_MEMORY,
        Some("0"),
    ),
    (
        "/proc/sys/vm/max_map_count",
        SYSCTL_MAX_MAP_COUNT,
        Some("65530"),
    ),
    ("/proc/sys/kernel/pid_max", SYSCTL_PID_MAX, Some("32768")),
    ("/proc/sys/kernel/threads-max", SYSCTL_THREADS_MAX, None),
    (
        "/proc/sys/kernel/sched_rt_runtime_us",
        SYSCTL_SCHED_RT_RUNTIME,
        Some("950000"),
    ),
    (FTRACE_ENABLED, SYSCTL_FTRACE_ENABLED, Some("1")),
    // lot 280b: the kprobes' switches (absent without CONFIG_OPTPROBES, or
    // with debugfs not mounted: then not read)
    (
        "/proc/sys/debug/kprobes-optimization",
        SYSCTL_KPROBES_OPTIMIZATION,
        Some("1"),
    ),
    (KPROBES_ENABLED, SYSCTL_KPROBES_ENABLED, Some("1")),
];

/// Lot 280b: the debugfs switch of every kprobe.
pub const KPROBES_ENABLED: &str = "/sys/kernel/debug/kprobes/enabled";

/// R1: the switch of ftrace, read at every build of the manifest.
pub const FTRACE_ENABLED: &str = "/proc/sys/kernel/ftrace_enabled";

/// R1: the degradation's source (`nn-admin status --key`, the manifest,
/// the heartbeat).
pub const FTRACE_DEGRADATION: &str = "ftrace_enabled";

/// R1: what [`FTRACE_ENABLED`] says.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Ftrace {
    /// Any integer but 0: the kernel's "on".
    On,
    /// 0: the call sites ftrace manages are NOPs (6.0 to 7.2).
    Off,
    /// Not read, or not an integer: whether the trampolines run is not
    /// known — a degradation too.
    Unknown(String),
}

impl Ftrace {
    /// The degradation's line, `None` when on.
    pub fn degradation(&self) -> Option<String> {
        const WHAT: &str = "on 6.0 to 7.2 every call site ftrace manages is a NOP, with no \
             error: the fentry/fexit sensors and, by the kernel's code, the BPF-LSM deny hooks \
             do not run; the integrity round puts it back to 1";
        match self {
            Ftrace::On => None,
            Ftrace::Off => Some(format!("kernel.ftrace_enabled is 0 — {WHAT}")),
            Ftrace::Unknown(why) => Some(format!(
                "kernel.ftrace_enabled {why}: whether the fentry/fexit sensors and the BPF-LSM \
                 deny hooks run is not known"
            )),
        }
    }
}

/// R1: [`FTRACE_ENABLED`] under `root` (`/` on the host, a directory in the
/// tests).
pub fn ftrace(root: &Path) -> Ftrace {
    let path = root.join(FTRACE_ENABLED.trim_start_matches('/'));
    match std::fs::read_to_string(&path) {
        Ok(t) => match t.trim().parse::<i64>() {
            Ok(0) => Ftrace::Off,
            Ok(_) => Ftrace::On,
            Err(_) => Ftrace::Unknown(format!("reads {:?}, not an integer", t.trim())),
        },
        Err(e) => Ftrace::Unknown(format!("could not be read ({e})")),
    }
}

/// R1: [`ftrace`] read and noted — 0 or unknown a degradation (signed at
/// once when the audit log is open), withdrawn once it is on again (its
/// signed record stays; the round's `sysctl_restored` signs the restore).
/// Called at every build of the capability manifest (5 s).
pub fn note_ftrace(root: &Path) -> Ftrace {
    let now = ftrace(root);
    let line = now.degradation();
    let keep: Vec<String> = line.iter().cloned().collect();
    crate::boot::degradation::withdraw(FTRACE_DEGRADATION, &keep);
    if let Some(l) = line {
        if crate::boot::degradation::report(FTRACE_DEGRADATION, &l) {
            crate::boot::degradation::flush();
        }
    }
    now
}

/// One finding of the round.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Seen {
    /// `sysctl_restored`, `sysctl_not_restored`, `sysctl_strict`.
    pub kind: &'static str,
    pub detail: String,
}

/// `threads-max`'s kernel default: a thread per 128 KiB of memory (an
/// eighth of the memory in 16 KiB stacks), at least 8192.
fn threads_default(mem_total: u64) -> String {
    (mem_total / (128 << 10)).clamp(8192, 4_194_304).to_string()
}

/// The guarded sysctls under `root` (`/` on the host, a directory in the
/// tests) judged, the harmful ones put back (`write`: false in a dry run).
/// Lot 280a: a value the signed per-sysctl opt-out in force allows
/// (`crate::sysctl_cgroup::opt_out_for`) is left, a `sysctl_opted_out`
/// finding.
pub fn check(root: &Path, mem_total: u64, write: bool) -> Vec<Seen> {
    check_with(
        root,
        mem_total,
        &crate::sysctl_cgroup::opt_out_for,
        |path, text| {
            if write {
                std::fs::write(path, text)
            } else {
                Ok(())
            }
        },
    )
}

/// The RT period the round judges the runtime against (`/proc/sys/kernel/
/// sched_rt_period_us`, the review of #497, D3).
pub const RT_PERIOD: &str = "/proc/sys/kernel/sched_rt_period_us";

/// What the round puts back for an RT runtime that switches throttling off
/// under `period` (the re-review of #497, NR3): 95 % of the period, the
/// kernel's default ratio, computed so it is never 0 — and for a period
/// too short to hold a runtime below 99 % of it (1 µs), the kernel's
/// defaults: the period to 1 s first, then the runtime to 950 ms. The
/// period to write first, if any, and the runtime.
pub fn rt_restore(period: i64) -> (Option<i64>, i64) {
    let runtime = period.saturating_mul(95) / 100;
    if runtime >= 1 {
        (None, runtime)
    } else {
        (Some(1_000_000), 950_000)
    }
}

/// [`check`] with the opt-outs in force and the writer given (the tests'
/// failing one, the review of #497, D5 M1).
pub fn check_with(
    root: &Path,
    mem_total: u64,
    opt_out: &dyn Fn(u8) -> Option<(i64, i64)>,
    mut put: impl FnMut(&Path, &str) -> std::io::Result<()>,
) -> Vec<Seen> {
    let read = |p: &str| {
        std::fs::read_to_string(root.join(p.trim_start_matches('/')))
            .ok()
            .map(|t| t.trim().to_string())
    };
    let ratio_ok = read("/proc/sys/vm/overcommit_ratio")
        .and_then(|r| r.parse::<i64>().ok())
        .is_some_and(|r| r >= 50);
    let kbytes = read("/proc/sys/vm/overcommit_kbytes")
        .and_then(|r| r.parse::<i64>().ok())
        .unwrap_or(0);
    let strict = read("/proc/sys/vm/overcommit_memory").as_deref() == Some("2");
    // the review of #497 (D3): the runtime judged against the host's own
    // period (unreadable: the default 1 s)
    let period = read(RT_PERIOD)
        .and_then(|r| r.parse::<i64>().ok())
        .unwrap_or(1_000_000);
    let mut out = Vec::new();
    for (path, kind, safe) in GUARDED {
        // the ratio and the kbytes only count in strict mode
        if matches!(*kind, SYSCTL_OVERCOMMIT_RATIO | SYSCTL_OVERCOMMIT_KBYTES) && !strict {
            continue;
        }
        let Some(now) = read(path) else {
            continue;
        };
        let Some(v) = limit_value(now.as_bytes()) else {
            continue;
        };
        let harmful = if *kind == SYSCTL_SCHED_RT_RUNTIME {
            now.parse::<i64>()
                .map_or(true, |r| rt_throttling_off(r, period))
        } else {
            sysctl_write_harmful(*kind, Some(v))
        };
        if !harmful {
            continue;
        }
        // Lot 280a: a value the signed opt-out allows — the operator's
        // (tuned's realtime profile): left, said
        if let (Some((min, max)), Ok(v)) = (opt_out(*kind), now.parse::<i64>()) {
            if min <= v && v <= max {
                out.push(Seen {
                    kind: "sysctl_opted_out",
                    detail: format!(
                        "{path} is {now:?}, which the agent refuses outside a window: left — the \
                         signed per-rule policy's sysctl-allow allows {}",
                        if min == max {
                            min.to_string()
                        } else {
                            format!("{min}..{max}")
                        }
                    ),
                });
                continue;
            }
        }
        // strict accounting with room: the operator's
        if *kind == SYSCTL_OVERCOMMIT_MEMORY && ratio_ok && (kbytes == 0 || kbytes >= 1 << 20) {
            out.push(Seen {
                kind: "sysctl_strict",
                detail: format!(
                    "{path} is 2 (strict overcommit) with a ratio of 50 or more: left; the agent's \
                     allocations fail when the host's commit limit is reached"
                ),
            });
            continue;
        }
        let mut first = Ok(());
        let safe = if *kind == SYSCTL_SCHED_RT_RUNTIME {
            // 95 % of the period, never 0 (NR3)
            let (new_period, runtime) = rt_restore(period);
            if let Some(p) = new_period {
                first = put(
                    &root.join(RT_PERIOD.trim_start_matches('/')),
                    &format!("{p}\n"),
                );
            }
            runtime.to_string()
        } else {
            safe.map(str::to_string)
                .unwrap_or_else(|| threads_default(mem_total))
        };
        let r = first.and_then(|()| {
            put(
                &root.join(path.trim_start_matches('/')),
                &format!("{safe}\n"),
            )
        });
        // lot 280b: what the value does, said as it is
        let harm = if sysctl_blinds(*kind) {
            "which blinds the agent's hooks"
        } else {
            "which aborts or starves the agent"
        };
        out.push(match r {
            Ok(()) => Seen {
                kind: "sysctl_restored",
                detail: format!("{path} was {now:?}, {harm}: put back to {safe}"),
            },
            Err(e) => Seen {
                kind: "sysctl_not_restored",
                detail: format!("{path} is {now:?}, {harm}: NOT put back ({e})"),
            },
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// [`super::check`] without the process's opt-outs (another test may
    /// have some in force: `sysctl_cgroup`'s, run in parallel).
    fn check(root: &Path, mem_total: u64, write: bool) -> Vec<Seen> {
        check_with(root, mem_total, &|_| None, |path, text| {
            if write {
                std::fs::write(path, text)
            } else {
                Ok(())
            }
        })
    }

    fn host(files: &[(&str, &str)]) -> tempfile::TempDir {
        let d = tempfile::tempdir().unwrap();
        for (p, v) in files {
            let f = d.path().join(p.trim_start_matches('/'));
            std::fs::create_dir_all(f.parent().unwrap()).unwrap();
            std::fs::write(f, v).unwrap();
        }
        d
    }

    #[test]
    fn a_harmful_value_is_put_back_and_the_hosts_tuning_left() {
        let d = host(&[
            ("/proc/sys/vm/overcommit_memory", "2\n"),
            ("/proc/sys/vm/overcommit_ratio", "0\n"),
            ("/proc/sys/vm/max_map_count", "262144\n"),
            ("/proc/sys/kernel/pid_max", "300\n"),
            ("/proc/sys/kernel/threads-max", "126602\n"),
            ("/proc/sys/kernel/sched_rt_runtime_us", "-1\n"),
        ]);
        let r = check(d.path(), 16 << 30, true);
        let kinds: Vec<_> = r
            .iter()
            .map(|s| (s.kind, s.detail.split(' ').next().unwrap()))
            .collect();
        assert_eq!(
            kinds,
            vec![
                ("sysctl_restored", "/proc/sys/vm/overcommit_ratio"),
                ("sysctl_restored", "/proc/sys/vm/overcommit_memory"),
                ("sysctl_restored", "/proc/sys/kernel/pid_max"),
                ("sysctl_restored", "/proc/sys/kernel/sched_rt_runtime_us"),
            ],
            "{r:?}"
        );
        let read = |p: &str| std::fs::read_to_string(d.path().join(p)).unwrap();
        assert_eq!(read("proc/sys/vm/overcommit_memory"), "0\n");
        assert_eq!(read("proc/sys/kernel/pid_max"), "32768\n");
        assert_eq!(read("proc/sys/vm/max_map_count"), "262144\n");
        assert!(check(d.path(), 16 << 30, true).is_empty());
    }

    #[test]
    fn a_low_ratio_outside_strict_mode_is_left() {
        let d = host(&[
            ("/proc/sys/vm/overcommit_memory", "0\n"),
            ("/proc/sys/vm/overcommit_ratio", "0\n"),
        ]);
        assert!(check(d.path(), 16 << 30, true).is_empty());
    }

    #[test]
    fn strict_accounting_with_room_is_the_operators() {
        let d = host(&[
            ("/proc/sys/vm/overcommit_memory", "2\n"),
            ("/proc/sys/vm/overcommit_ratio", "80\n"),
        ]);
        let r = check(d.path(), 16 << 30, true);
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].kind, "sysctl_strict");
        assert_eq!(
            std::fs::read_to_string(d.path().join("proc/sys/vm/overcommit_memory")).unwrap(),
            "2\n"
        );
        assert_eq!(threads_default(1 << 30), "8192");
        assert_eq!(threads_default(16 << 30), "131072");
    }

    /// The review of #497 (D5, M1): a restore that fails is said so, never
    /// recorded as done.
    #[test]
    fn a_restore_that_fails_is_not_restored() {
        let d = host(&[("/proc/sys/kernel/pid_max", "300\n")]);
        let r = check_with(d.path(), 16 << 30, &|_| None, |_, _| {
            Err(std::io::Error::from(std::io::ErrorKind::PermissionDenied))
        });
        assert_eq!(r.len(), 1, "{r:?}");
        assert_eq!(r[0].kind, "sysctl_not_restored");
        assert!(r[0].detail.contains("NOT put back"), "{r:?}");
        assert_eq!(
            std::fs::read_to_string(d.path().join("proc/sys/kernel/pid_max")).unwrap(),
            "300\n"
        );
    }

    /// The review of #497 (D3): the RT runtime judged against the host's
    /// period — the period cut to the runtime is throttling off (the
    /// runtime put back to 95 % of it), a longer period's 75 % is not.
    #[test]
    fn the_rt_runtime_is_judged_against_the_period() {
        let off = host(&[
            ("/proc/sys/kernel/sched_rt_runtime_us", "950000\n"),
            ("/proc/sys/kernel/sched_rt_period_us", "950000\n"),
        ]);
        let r = check(off.path(), 16 << 30, true);
        assert_eq!(r.len(), 1, "{r:?}");
        assert_eq!(r[0].kind, "sysctl_restored");
        assert!(r[0].detail.ends_with("put back to 902500"), "{r:?}");
        let long = host(&[
            ("/proc/sys/kernel/sched_rt_runtime_us", "1500000\n"),
            ("/proc/sys/kernel/sched_rt_period_us", "2000000\n"),
        ]);
        assert!(check(long.path(), 16 << 30, true).is_empty());
        let none = host(&[("/proc/sys/kernel/sched_rt_runtime_us", "-1\n")]);
        let r = check(none.path(), 16 << 30, true);
        assert!(r[0].detail.ends_with("put back to 950000"), "{r:?}");
        // the re-review of #497 (NR3): never 0 — a short period's 95 %
        // (the old period/100*95 was 0 below 100 µs), and for a 1 µs
        // period the kernel's defaults, the period first
        let short = host(&[
            ("/proc/sys/kernel/sched_rt_runtime_us", "-1\n"),
            ("/proc/sys/kernel/sched_rt_period_us", "50\n"),
        ]);
        let r = check(short.path(), 16 << 30, true);
        assert!(r[0].detail.ends_with("put back to 47"), "{r:?}");
        let one = host(&[
            ("/proc/sys/kernel/sched_rt_runtime_us", "1\n"),
            ("/proc/sys/kernel/sched_rt_period_us", "1\n"),
        ]);
        let r = check(one.path(), 16 << 30, true);
        assert!(r[0].detail.ends_with("put back to 950000"), "{r:?}");
        let read = |f: &str| std::fs::read_to_string(one.path().join(f)).unwrap();
        assert_eq!(read("proc/sys/kernel/sched_rt_period_us"), "1000000\n");
        assert_eq!(read("proc/sys/kernel/sched_rt_runtime_us"), "950000\n");
        for p in [1_i64, 2, 50, 99, 100, 950_000, 1_000_000, i64::MAX] {
            let (np, r) = rt_restore(p);
            assert!(r >= 1, "{p}");
            assert!(!rt_throttling_off(r, np.unwrap_or(p)), "{p} → {r}");
        }
    }

    /// Lot 280a: a harmful value the signed opt-out allows is left by the
    /// round (tuned's realtime profile keeps its -1), said once a round as a
    /// finding; outside its range it is put back as before.
    #[test]
    fn the_round_leaves_a_value_the_signed_opt_out_allows() {
        use common::cgroup_limits::SYSCTL_PID_MAX;
        let rt_only = |k: u8| (k == SYSCTL_SCHED_RT_RUNTIME).then_some((-1, -1));
        let d = host(&[
            ("/proc/sys/kernel/sched_rt_runtime_us", "-1\n"),
            ("/proc/sys/kernel/pid_max", "300\n"),
        ]);
        let r = check_with(d.path(), 16 << 30, &rt_only, |p, t| std::fs::write(p, t));
        let kinds: Vec<_> = r.iter().map(|s| s.kind).collect();
        assert_eq!(kinds, ["sysctl_restored", "sysctl_opted_out"], "{r:?}");
        assert!(r[1].detail.contains("sysctl-allow allows -1"), "{r:?}");
        let read = |p: &str| std::fs::read_to_string(d.path().join(p)).unwrap();
        assert_eq!(read("proc/sys/kernel/sched_rt_runtime_us"), "-1\n");
        assert_eq!(read("proc/sys/kernel/pid_max"), "32768\n");
        // outside the range: put back
        let pm = |k: u8| (k == SYSCTL_PID_MAX).then_some((4096, 8192));
        let d = host(&[("/proc/sys/kernel/pid_max", "300\n")]);
        let r = check_with(d.path(), 16 << 30, &pm, |p, t| std::fs::write(p, t));
        assert_eq!(r[0].kind, "sysctl_restored", "{r:?}");
        let d = host(&[("/proc/sys/kernel/pid_max", "8192\n")]);
        let r = check_with(d.path(), 16 << 30, &pm, |p, t| std::fs::write(p, t));
        assert_eq!(r[0].kind, "sysctl_opted_out", "{r:?}");
        assert!(r[0].detail.ends_with("allows 4096..8192"), "{r:?}");
        // above the range, still harmful: put back
        let d = host(&[("/proc/sys/kernel/pid_max", "10000\n")]);
        let r = check_with(d.path(), 16 << 30, &pm, |p, t| std::fs::write(p, t));
        assert_eq!(r[0].kind, "sysctl_restored", "{r:?}");
    }

    /// Lot 280b (named): the kprobes' switches at 0 (set at boot, inside a
    /// window) are put back to 1, signed as blinding; at 1, or absent (no
    /// OPTPROBES, no debugfs), nothing.
    #[test]
    fn the_kprobes_switches_at_0_are_put_back() {
        let d = host(&[
            ("/proc/sys/debug/kprobes-optimization", "0\n"),
            ("/sys/kernel/debug/kprobes/enabled", "0\n"),
        ]);
        let r = check(d.path(), 0, true);
        assert_eq!(r.len(), 2, "{r:?}");
        for s in &r {
            assert_eq!(s.kind, "sysctl_restored", "{s:?}");
            assert!(s.detail.contains("blinds the agent's hooks"), "{s:?}");
            assert!(s.detail.ends_with("put back to 1"), "{s:?}");
        }
        for f in [
            "proc/sys/debug/kprobes-optimization",
            "sys/kernel/debug/kprobes/enabled",
        ] {
            assert_eq!(std::fs::read_to_string(d.path().join(f)).unwrap(), "1\n");
        }
        let on = host(&[
            ("/proc/sys/debug/kprobes-optimization", "1\n"),
            ("/sys/kernel/debug/kprobes/enabled", "1\n"),
        ]);
        assert!(check(on.path(), 0, true).is_empty());
        assert!(check(host(&[]).path(), 0, true).is_empty());
        // the starving kinds keep their own words
        let pid = host(&[("/proc/sys/kernel/pid_max", "300\n")]);
        let r = check(pid.path(), 0, false);
        assert!(r[0].detail.contains("aborts or starves the agent"), "{r:?}");
    }

    /// R1: `ftrace_enabled=0` (set at boot, inside a window) is put back to
    /// 1 by the round and signed; 1 is left.
    #[test]
    fn ftrace_off_is_put_back_on() {
        let d = host(&[("/proc/sys/kernel/ftrace_enabled", "0\n")]);
        let r = check(d.path(), 16 << 30, true);
        assert_eq!(r.len(), 1, "{r:?}");
        assert_eq!(r[0].kind, "sysctl_restored");
        assert!(
            r[0].detail
                .starts_with("/proc/sys/kernel/ftrace_enabled was \"0\""),
            "{r:?}"
        );
        assert!(r[0].detail.ends_with("put back to 1"), "{r:?}");
        assert_eq!(
            std::fs::read_to_string(d.path().join("proc/sys/kernel/ftrace_enabled")).unwrap(),
            "1\n"
        );
        assert!(check(d.path(), 16 << 30, true).is_empty());
        let on = host(&[("/proc/sys/kernel/ftrace_enabled", "1\n")]);
        assert!(check(on.path(), 16 << 30, true).is_empty());
    }

    /// R1: what the manifest's read finds — 0, and a value it cannot read
    /// or parse, are degradations; any other integer is on.
    #[test]
    fn ftrace_is_read_as_the_kernel_reads_it() {
        let at = |v: &str| ftrace(host(&[("/proc/sys/kernel/ftrace_enabled", v)]).path());
        assert_eq!(at("1\n"), Ftrace::On);
        assert_eq!(at("-1\n"), Ftrace::On);
        assert_eq!(at("0\n"), Ftrace::Off);
        assert!(matches!(at("x\n"), Ftrace::Unknown(w) if w.contains("not an integer")));
        let none = tempfile::tempdir().unwrap();
        assert!(
            matches!(ftrace(none.path()), Ftrace::Unknown(w) if w.contains("could not be read"))
        );
        assert_eq!(Ftrace::On.degradation(), None);
        let off = Ftrace::Off.degradation().unwrap();
        assert!(off.starts_with("kernel.ftrace_enabled is 0"), "{off}");
        assert!(off.contains("BPF-LSM deny hooks"), "{off}");
    }

    /// R1: a degradation while it holds (signed at once with the audit log
    /// open), withdrawn once on again.
    #[test]
    fn ftrace_off_is_a_degradation_while_it_holds() {
        let _g = crate::boot::degradation::TEST_LOCK.lock();
        crate::boot::degradation::reset_for_tests();
        let d = host(&[("/proc/sys/kernel/ftrace_enabled", "0\n")]);
        let key =
            crate::audit::AgentSigningKey::load_or_bootstrap(&d.path().join("agent.sig")).unwrap();
        let log = std::sync::Arc::new(parking_lot::Mutex::new(
            crate::audit::AuditLog::open(&d.path().join("audit.log"), key, [7u8; 16]).unwrap(),
        ));
        crate::boot::degradation::attach_audit_log(Some(log));
        let signed = || {
            std::fs::read_to_string(d.path().join("audit.log"))
                .unwrap_or_default()
                .lines()
                .map(|l| serde_json::from_str::<serde_json::Value>(l).unwrap())
                .filter(|v| {
                    v["extra"]["kind"] == "subsystem_degraded"
                        && v["extra"]["source"] == FTRACE_DEGRADATION
                })
                .count()
        };
        assert_eq!(note_ftrace(d.path()), Ftrace::Off);
        // signed by the read itself, not at the registry's next flush
        assert_eq!(signed(), 1);
        assert_eq!(note_ftrace(d.path()), Ftrace::Off);
        assert_eq!(signed(), 1, "the same state is one record");
        let s = crate::boot::degradation::snapshot();
        assert_eq!(s.len(), 1, "{s:?}");
        assert!(
            s[0].starts_with("ftrace_enabled: kernel.ftrace_enabled is 0"),
            "{s:?}"
        );
        std::fs::write(d.path().join("proc/sys/kernel/ftrace_enabled"), "garbage\n").unwrap();
        assert!(matches!(note_ftrace(d.path()), Ftrace::Unknown(_)));
        let s = crate::boot::degradation::snapshot();
        assert_eq!(s.len(), 1, "the 0 withdrawn, the unknown kept: {s:?}");
        assert!(s[0].contains("not an integer"), "{s:?}");
        std::fs::write(d.path().join("proc/sys/kernel/ftrace_enabled"), "1\n").unwrap();
        assert_eq!(note_ftrace(d.path()), Ftrace::On);
        assert!(crate::boot::degradation::snapshot().is_empty());
        crate::boot::degradation::reset_for_tests();
    }
}
