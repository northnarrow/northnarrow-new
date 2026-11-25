use super::*;

/// Lot 324 (Ubuntu 26.04's 7.0): the syscall tracepoint ran for the calls
/// made on CPU 0 only. Seen there and missed on 1–3, the sensor moves to
/// the raw `sys_enter` fallback, which the self-test saw on all four. On
/// `main` there was no self-test and no fallback: the exec and open
/// records of CPUs 1–3 were lost without a word.
#[test]
fn a_tracepoint_seen_on_cpu_0_alone_takes_the_raw_fallback() {
    let tp = decide(&[
        (0, Cpu::Seen),
        (1, Cpu::Missed),
        (2, Cpu::Missed),
        (3, Cpu::Missed),
    ]);
    assert!(!tp.every());
    assert_eq!(tp.describe(), "seen on CPUs 0, missed on CPUs 1-3");
    let raw = decide(&[
        (3, Cpu::Seen),
        (1, Cpu::Seen),
        (0, Cpu::Seen),
        (2, Cpu::Seen),
    ]);
    assert!(raw.every());
    assert_eq!(raw.seen, [0, 1, 2, 3], "in CPU order");
    assert_eq!(choose(&tp, Some(&raw)), Choice::Fallback);
}

/// Where it runs on every CPU (every kernel but the affected ones) the
/// tracepoint stays — it costs the host's other calls nothing — whatever
/// the fallback would have seen.
#[test]
fn a_tracepoint_seen_on_every_cpu_stays() {
    let tp = decide(&[(0, Cpu::Seen), (1, Cpu::Seen)]);
    assert!(tp.every());
    assert_eq!(choose(&tp, None), Choice::Tracepoint);
    let raw = decide(&[(0, Cpu::Seen), (1, Cpu::Seen)]);
    assert_eq!(choose(&tp, Some(&raw)), Choice::Tracepoint);
    // one CPU, seen: every CPU there is
    assert!(decide(&[(0, Cpu::Seen)]).every());
}

/// A CPU the agent cannot run on proves nothing: the tracepoint is not
/// "every CPU" there, and the fallback, which no perf event confines,
/// is taken when it saw at least what the tracepoint saw.
#[test]
fn a_cpu_the_agent_cannot_reach_is_not_proven() {
    let tp = decide(&[(0, Cpu::Seen), (1, Cpu::Unpinned)]);
    assert!(!tp.every());
    assert_eq!(
        tp.describe(),
        "seen on CPUs 0, not tested on CPUs 1 (the agent cannot run there)"
    );
    let raw = decide(&[(0, Cpu::Seen), (1, Cpu::Unpinned)]);
    assert!(!raw.every());
    assert_eq!(choose(&tp, Some(&raw)), Choice::Fallback);
    // nothing tested at all is not every CPU either
    assert!(!decide(&[]).every());
    assert!(!decide(&[(0, Cpu::Unpinned)]).every());
}

/// The fallback is kept only when it covers every CPU the tracepoint
/// covered; not attached (`None`) or seeing less, the tracepoint stays
/// (with the CPUs it misses signed).
#[test]
fn a_fallback_that_covers_less_or_is_absent_leaves_the_tracepoint() {
    let tp = decide(&[(0, Cpu::Seen), (1, Cpu::Missed), (2, Cpu::Seen)]);
    assert_eq!(choose(&tp, None), Choice::Tracepoint);
    let less = decide(&[(0, Cpu::Seen), (1, Cpu::Seen), (2, Cpu::Missed)]);
    assert!(!less.covers(&tp), "CPU 2 is the tracepoint's only");
    assert_eq!(choose(&tp, Some(&less)), Choice::Tracepoint);
    let none = decide(&[(0, Cpu::Missed), (1, Cpu::Missed), (2, Cpu::Missed)]);
    assert_eq!(choose(&tp, Some(&none)), Choice::Tracepoint);
    // the same CPUs and no more: covers, and the tracepoint is not proven
    let same = decide(&[(0, Cpu::Seen), (1, Cpu::Missed), (2, Cpu::Seen)]);
    assert!(same.covers(&tp));
    assert_eq!(choose(&tp, Some(&same)), Choice::Fallback);
    // a tracepoint seen nowhere: a fallback seen somewhere is taken, one
    // seen nowhere proves nothing and leaves the tracepoint
    let nowhere = decide(&[(0, Cpu::Missed), (1, Cpu::Missed)]);
    let one = decide(&[(0, Cpu::Missed), (1, Cpu::Seen)]);
    assert_eq!(choose(&nowhere, Some(&one)), Choice::Fallback);
    let both_nowhere = decide(&[(0, Cpu::Missed), (1, Cpu::Missed)]);
    assert!(both_nowhere.covers(&nowhere), "vacuously");
    assert_eq!(choose(&nowhere, Some(&both_nowhere)), Choice::Tracepoint);
}

#[test]
fn the_kernel_s_cpu_lists_are_read_and_written_back() {
    assert_eq!(parse_cpu_list("0-3,5\n"), Some(vec![0, 1, 2, 3, 5]));
    assert_eq!(parse_cpu_list("0"), Some(vec![0]));
    assert_eq!(parse_cpu_list("2,0-1"), Some(vec![0, 1, 2]));
    for bad in ["", "\n", "3-1", "a", "0-", "-1", "0,,1", "0-70000"] {
        assert_eq!(parse_cpu_list(bad), None, "{bad:?}");
    }
    assert_eq!(cpu_list(&[0, 1, 2, 3, 5, 7, 8]), "0-3,5,7-8");
    assert_eq!(cpu_list(&[4]), "4");
    assert_eq!(cpu_list(&[]), "none");
    assert_eq!(cpu_list(&[0, 2]), "0,2");
}

/// The rows, the CPUs the programs mark, the call numbers and the
/// programs' attach points are the eBPF sources' (`exec_check.rs`,
/// `file_open.rs`).
#[test]
fn the_self_test_s_terms_are_the_programs() {
    let root = std::path::Path::new(env!("NN_REPO_ROOT")).join("agent-ebpf/src");
    let exec = std::fs::read_to_string(root.join("exec_check.rs")).unwrap();
    let open = std::fs::read_to_string(root.join("file_open.rs")).unwrap();
    for line in [
        format!("pub(crate) const SEEN_CPUS: u32 = {SEEN_CPUS};"),
        format!("pub(crate) const SEEN_EXEC: u32 = {};", Sensor::Exec.row()),
        format!("pub(crate) const SEEN_OPEN: u32 = {};", Sensor::Open.row()),
        format!("const NR_EXECVE: u64 = {};", libc::SYS_execve),
        format!("pub(crate) static {PROBE_MAP}: Array<u64> = Array::with_max_entries(2, 0);"),
        format!(
            "pub(crate) static {SEEN_MAP}: Array<u32> = Array::with_max_entries(2 * SEEN_CPUS, 0);"
        ),
        format!(
            "#[raw_tracepoint(tracepoint = \"{RAW_TRACEPOINT}\")]\npub fn {}(",
            Sensor::Exec.fallback_program()
        ),
        format!(
            "#[tracepoint]\npub fn {}(",
            Sensor::Exec.tracepoint_program()
        ),
    ] {
        assert!(exec.contains(&line), "exec_check.rs: {line}");
    }
    for line in [
        format!("const NR_OPENAT: u64 = {};", libc::SYS_openat),
        format!(
            "#[raw_tracepoint(tracepoint = \"{RAW_TRACEPOINT}\")]\npub fn {}(",
            Sensor::Open.fallback_program()
        ),
        format!(
            "#[tracepoint]\npub fn {}(",
            Sensor::Open.tracepoint_program()
        ),
        "crate::exec_check::probe_seen(crate::exec_check::SEEN_OPEN, pid_tgid)".to_string(),
    ] {
        assert!(open.contains(&line), "file_open.rs: {line}");
    }
    // lot 1.3: the record names the caller's parent (the sensor self-test
    // knows its probe child by it)
    assert!(exec.contains("task.add(off!(TASK_STRUCT_REAL_PARENT_OFFSET))"));
    assert!(exec.contains("(*raw_ptr).ppid ="));
    // the record of the self-test's own call: none, in both
    assert!(exec.contains("if probe_seen(SEEN_EXEC, pid_tgid) {\n        return;\n    }"));
    // a 32-bit call is not the native one the number names
    assert!(exec.contains("if status & TS_COMPAT != 0 {\n            return None;"));
    // the raw tracepoint runs for every call: the number first, then the rest
    assert!(exec.contains("if *args.add(1) != NR_EXECVE {\n            return 0;\n        }"));
    assert!(open.contains(
        "if *args.add(1) != NR_OPENAT || !emitting() {\n            return 0;\n        }"
    ));
    // the open's tracepoint stays inert until the start turns it on
    assert!(open.contains("pub fn sys_enter_openat(ctx: TracePointContext) -> u32 {\n    if !emitting() {\n        return 0;\n    }"));
}

/// Lot 324's mini-hunt: the two sensors the self-test covers are the only
/// programs the agent attaches to a syscall tracepoint (`syscalls/…`, the
/// perf path that ran on CPU 0 alone on 7.0) — the multiplexer's two
/// attaches, by the programs [`Sensor`] names. A new one fails here until
/// the every-CPU self-test covers it (or it moves to a raw tracepoint).
#[test]
fn no_other_program_sits_on_a_syscall_tracepoint() {
    let root = std::path::Path::new(env!("NN_REPO_ROOT"));
    let mut found: Vec<String> = Vec::new();
    let mut dirs: Vec<std::path::PathBuf> =
        ["crates", "agent/src", "antitamper-bpf/src", "watchdog/src"]
            .iter()
            .map(|d| root.join(d))
            .collect();
    while let Some(d) = dirs.pop() {
        let Ok(entries) = std::fs::read_dir(&d) else {
            continue;
        };
        for e in entries.flatten() {
            let path = e.path();
            let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
            if path.is_dir() {
                if name != "tests" && name != "target" {
                    dirs.push(path);
                }
                continue;
            }
            if !name.ends_with(".rs") || name == "tests.rs" {
                continue;
            }
            let text = std::fs::read_to_string(&path).unwrap();
            // the product code: up to a file's `#[cfg(test)]` module
            let product = text.split("#[cfg(test)]").next().unwrap_or("");
            for (i, line) in product.lines().enumerate() {
                if line.contains("\"syscalls\"") {
                    let rel = path.strip_prefix(root).unwrap().display().to_string();
                    found.push(format!("{rel}:{}", i + 1));
                }
            }
        }
    }
    let mux =
        std::fs::read_to_string(root.join("crates/nn-linux/src/sensors/multiplexer.rs")).unwrap();
    assert_eq!(found.len(), 2, "{found:?}");
    assert!(
        found
            .iter()
            .all(|f| f.starts_with("crates/nn-linux/src/sensors/multiplexer.rs:")),
        "{found:?}"
    );
    let flat = mux.split_whitespace().collect::<Vec<_>>().join(" ");
    for s in [Sensor::Exec, Sensor::Open] {
        let p = s.tracepoint_program();
        assert!(
            flat.contains(&format!("\"{p}\", \"syscalls\", \"{p}\"")),
            "{p}: attached on its syscall tracepoint by its own name"
        );
    }
}

/// The notes are the contract's fallbacks of the sources the sensors are
/// (`exec_check`'s and `open_sensor`'s), each with the tracepoint's own
/// costs: the source is `partial` on it, as on the tracepoint.
#[test]
fn the_fallbacks_are_the_contract_s() {
    use crate::sensors::contract::SOURCES;
    for (sensor, source) in [(Sensor::Exec, "exec_check"), (Sensor::Open, "open_sensor")] {
        let s = SOURCES.iter().find(|s| s.source == source).unwrap();
        assert!(s.sensors.contains(&sensor.manifest_sensor()), "{source}");
        let tp = s
            .fallbacks
            .iter()
            .find(|f| f.attach == sensor.tracepoint_note())
            .unwrap_or_else(|| panic!("{source}: the tracepoint"));
        let raw = s
            .fallbacks
            .iter()
            .find(|f| f.attach == sensor.fallback_note())
            .unwrap_or_else(|| panic!("{source}: the raw fallback"));
        assert_eq!(raw.equivalent, tp.equivalent, "{source}");
        assert_eq!(raw.lost, tp.lost, "{source}");
        assert!(
            raw.costs.contains("every system call of the host"),
            "{source}"
        );
    }
    assert_eq!(Sensor::Exec.degradation_source(), "exec_sensor");
    assert_eq!(Sensor::Open.degradation_source(), "file_open_sensor");
}

/// The records of `sensor`'s ring that name a per-CPU marker (`.c<cpu>.z`),
/// counted per CPU — every record in the ring read and dropped.
fn drain_markers(ebpf: &mut Ebpf, sensor: Sensor, cpus: &[u32]) -> Vec<(u32, usize)> {
    let ring = match sensor {
        Sensor::Exec => "EXEC_CHECK_EVENTS",
        Sensor::Open => "FILE_OPEN_EVENTS",
    };
    let mut rb = aya::maps::RingBuf::try_from(ebpf.map_mut(ring).unwrap()).unwrap();
    let mut counts: Vec<(u32, usize)> = cpus.iter().map(|c| (*c, 0)).collect();
    while let Some(item) = rb.next() {
        let bytes: &[u8] = &item;
        for (cpu, n) in counts.iter_mut() {
            let marker = format!(".c{cpu}.z\0");
            if bytes.windows(marker.len()).any(|w| w == marker.as_bytes()) {
                *n += 1;
            }
        }
    }
    counts
}

/// One call of `sensor`'s kind by a process pinned to `cpu` with `taskset`:
/// `taskset -c <cpu> /nonexistent-nn13/x.c<cpu>.z` (an `execve` that fails)
/// or `taskset -c <cpu> bash -c ': < /nonexistent-nn13/o.c<cpu>.z'` (an
/// `openat` that fails: the shell's redirection opens the path; Ubuntu
/// 26.04's `cat`, uutils', looks the path up first and never opens it).
fn pinned_call(sensor: Sensor, cpu: u32) {
    let c = cpu.to_string();
    let mut cmd = std::process::Command::new("taskset");
    match sensor {
        Sensor::Exec => cmd.args(["-c", &c, &format!("/nonexistent-nn13/x.c{cpu}.z")]),
        Sensor::Open => cmd.args([
            "-c",
            &c,
            "bash",
            "-c",
            &format!(": < /nonexistent-nn13/o.c{cpu}.z"),
        ]),
    };
    let _ = cmd
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status();
}

/// Privileged (`NN_EVERY_CPU_LIVE=1`, root, the built object, no agent
/// running): on this host's kernel, through the agent's own loader, each
/// sensor's syscall tracepoint (as `main` attaches it) and then its raw
/// `sys_enter` fallback — the self-test's verdict, and the records of
/// processes pinned to each CPU with `taskset` (`NN_EVERY_CPU_ROUNDS`
/// calls per CPU, 10 by default), counted per CPU: the lab's before/after
/// table (`EVERY-CPU …` lines). A no-op without the variable.
#[test]
#[ignore = "needs root, the built eBPF object and NN_EVERY_CPU_LIVE=1"]
fn live_every_cpu_self_test() {
    if std::env::var_os("NN_EVERY_CPU_LIVE").is_none() {
        return;
    }
    let rounds: usize = std::env::var("NN_EVERY_CPU_ROUNDS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(10);
    let mut ebpf = crate::sensors::ebpf_object::object_loader()
        .load(crate::sensors::ebpf_object::EBPF_BYTES)
        .expect("load the object");
    {
        use crate::anti_tamper::btf_revalidate::{
            ResolveOutcome, arm_btf_offsets, publish_resolved, resolve_offsets,
            resolve_tracepoint_fields, resolved,
        };
        if resolved().is_none() {
            if let ResolveOutcome::Resolved(mut r) = resolve_offsets() {
                r.values.extend(resolve_tracepoint_fields().values);
                publish_resolved(r);
            }
        }
        arm_btf_offsets(&mut ebpf).expect("arm BTF_OFFSETS");
    }
    crate::sensors::open_sensor::set_tracepoint_emitting(&mut ebpf, true).unwrap();
    let cpus = online_cpu_list().expect("online CPUs");
    println!(
        "EVERY-CPU kernel {}",
        std::fs::read_to_string("/proc/sys/kernel/osrelease")
            .unwrap_or_default()
            .trim()
    );
    println!("EVERY-CPU online {}", cpu_list(&cpus));
    // the ring drained after each call: with the open sensor's tracepoint
    // on, every open of the host is a record, and 256 KiB of them fill up
    // within a few process starts
    let records = |ebpf: &mut Ebpf, sensor: Sensor, label: &str| {
        let _ = drain_markers(ebpf, sensor, &cpus);
        for &cpu in &cpus {
            let mut n = 0;
            for _ in 0..rounds {
                pinned_call(sensor, cpu);
                n += drain_markers(ebpf, sensor, &[cpu])[0].1;
            }
            println!(
                "EVERY-CPU-REC {} {label} cpu={cpu} records={n}/{rounds}",
                sensor.manifest_sensor()
            );
        }
    };
    for sensor in [Sensor::Exec, Sensor::Open] {
        let name = sensor.tracepoint_program();
        {
            let tp: &mut TracePoint = ebpf.program_mut(name).unwrap().try_into().unwrap();
            tp.load().unwrap();
            tp.attach("syscalls", name).unwrap();
        }
        let t = decide(&probe(&mut ebpf, sensor, &cpus, ROUND_TRACEPOINT).unwrap());
        println!(
            "EVERY-CPU {} tracepoint: {}",
            sensor.manifest_sensor(),
            t.describe()
        );
        records(&mut ebpf, sensor, "tracepoint");
        {
            let tp: &mut TracePoint = ebpf.program_mut(name).unwrap().try_into().unwrap();
            tp.unload().unwrap();
        }
        match attach_fallback(&mut ebpf, sensor) {
            Ok(()) => {
                let f = decide(&probe(&mut ebpf, sensor, &cpus, ROUND_FALLBACK).unwrap());
                println!(
                    "EVERY-CPU {} raw_tp: {}",
                    sensor.manifest_sensor(),
                    f.describe()
                );
                records(&mut ebpf, sensor, "raw_tp");
                println!(
                    "EVERY-CPU {} choice: {:?}",
                    sensor.manifest_sensor(),
                    choose(&t, Some(&f))
                );
                let raw: &mut RawTracePoint = ebpf
                    .program_mut(sensor.fallback_program())
                    .unwrap()
                    .try_into()
                    .unwrap();
                raw.unload().unwrap();
            }
            Err(e) => println!(
                "EVERY-CPU {} raw_tp: not armed ({e:#})",
                sensor.manifest_sensor()
            ),
        }
    }
}
