//! Lot 322 — what a per-CPU map may hold, and where the exec guards keep
//! their buffers.
//!
//! The exec environment's check (`EXECPOL_ENV`) refused 0 of 11 staging
//! preloads on Ubuntu 26.04's 7.0: its programs sat on the
//! `sys_enter_execve{,at}` tracepoints, and there a program attached as aya
//! and libbpf attach it (one perf event, CPU 0) ran only for the calls made
//! on CPU 0. The lab measured it with the kernel alone (`bpftrace`: the
//! tracepoint fired on CPU 0 only, pinned to CPU 1, 2 or 3 never; the
//! `sched_process_exec` tracepoint and the LSM hook on every CPU). The
//! environment is now read by the exec sensor's own LSM program, from the
//! exec's registers, into the task's own entry.
//!
//! The audit that came with it: an LSM, fentry/fexit or iterator program
//! runs with migration disabled but preemption enabled, so on a `full` or
//! `lazy` preemption kernel (Ubuntu 26.04's default) a per-CPU buffer kept
//! across a helper call can be rewritten by another task's run on the same
//! CPU. Every per-CPU map of `agent-ebpf` is listed here with why it is
//! safe, or why it is left for a follow-up; a new one fails until it is
//! classified. The exec guards' buffers (the exec sensor's walk, the
//! mapping check's walk, the environment, the quarantine's candidate, the
//! BPF guard's `OBJ_GET` path) are the running task's own entries.

mod support;

use std::fs;

use support::{repo_root, strip_comments};

fn code(rel: &str) -> String {
    strip_comments(
        &fs::read_to_string(repo_root().join(rel)).unwrap_or_else(|e| panic!("{rel}: {e}")),
    )
}

/// `needles` all in `hay`, in this order.
fn in_order(hay: &str, needles: &[&str]) -> Result<(), String> {
    let mut at = 0;
    for n in needles {
        match hay[at..].find(n) {
            Some(i) => at += i + n.len(),
            None => return Err(format!("{n:?} not found after byte {at}")),
        }
    }
    Ok(())
}

/// The body of `fn name` (to its matching brace).
fn body<'a>(code: &'a str, name: &str) -> &'a str {
    let start = code
        .find(&format!("fn {name}("))
        .unwrap_or_else(|| panic!("fn {name} not found"));
    let open = start + code[start..].find('{').expect("a body");
    let len = support::matching_brace(&code[open..]);
    &code[open..open + len]
}

/// Why a per-CPU map is safe where it is used.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Why {
    /// Increments only, summed by the agent: an increment lost to an
    /// interleaved run costs one count, never a decision.
    Counter,
    /// A rate budget's window or an aggregate: an interleaved update lets
    /// one more record through or holds one back (each counted).
    RateState,
    /// One run of a program the kernel runs with preemption off (a classic
    /// or BTF tracepoint that is not a syscall's, a kprobe).
    PreemptOff,
    /// Written and read only by the agent's own read of an iterator, or by
    /// a diagnostic mode: no other run on the CPU.
    SingleReader,
    /// Preemptible and not fixed in lot 322: the FIM sensor's walks on the
    /// file-open path (observations, not refusals). A per-task entry costs
    /// a hash insert per open: the follow-up lot measures it first.
    FollowUp,
}

/// Every per-CPU map of `agent-ebpf`, with why it is safe (or left).
const KNOWN: &[(&str, Why)] = &[
    ("RING_DROPS", Why::Counter),
    ("DENY_FAIL_OPEN", Why::Counter),
    ("EPG_COUNTERS", Why::Counter),
    ("EXECPOL_COUNTERS", Why::Counter),
    ("EXECQ_COUNTERS", Why::Counter),
    ("FLOW_SOCK_COUNTS", Why::Counter),
    ("OPEN_DEPTH_CAPPED", Why::Counter),
    ("TASK_DENIAL_RATE", Why::RateState),
    ("ATTEMPT_DENIAL_RATE", Why::RateState),
    // lot 318's re-check of #545: the non-decisive refusals' budget
    ("MINOR_DENIAL_RATE", Why::RateState),
    // kprobe `udp_sendmsg` / `udpv6_sendmsg`
    ("UDP_FLOWS", Why::RateState),
    // classic tracepoint `sched:sched_process_exec`
    ("STDIO_SCRATCH", Why::PreemptOff),
    // `tp_btf/cgroup_attach_task`
    ("CGROUP_JOIN_PATH", Why::PreemptOff),
    // `iter/bpf_prog`, read by the agent's census only
    ("PROG_RECORD_SCRATCH", Why::SingleReader),
    // `--sensor-feasibility`'s probe program only
    ("PROBE_SCRATCH", Why::SingleReader),
    ("OPEN_SCRATCH", Why::FollowUp),
    ("OPEN_WIN", Why::FollowUp),
    ("RENAME_SCRATCH", Why::FollowUp),
    ("RENAME_EXT", Why::FollowUp),
];

/// `(file, map)` of every per-CPU map declared in `agent-ebpf/src`.
fn per_cpu_maps() -> Vec<(String, String)> {
    let root = repo_root();
    let mut files = Vec::new();
    support::rs_files(&root.join("agent-ebpf/src"), &mut files);
    let mut out = Vec::new();
    for f in &files {
        let c = strip_comments(&fs::read_to_string(f).unwrap());
        let flat = c.split_whitespace().collect::<Vec<_>>().join(" ");
        for piece in flat.split("static ").skip(1) {
            let Some((name, rest)) = piece.split_once(':') else {
                continue;
            };
            let ty = rest.trim_start();
            if ["PerCpuArray<", "PerCpuHashMap<", "LruPerCpuHashMap<"]
                .iter()
                .any(|t| ty.starts_with(t))
            {
                let rel = f.strip_prefix(&root).unwrap().display().to_string();
                out.push((rel, name.trim().to_string()));
            }
        }
    }
    out.sort();
    out
}

/// Every per-CPU map is classified, and the list names no map that is
/// gone. A new per-CPU buffer kept across a helper call in an LSM, fentry
/// or iterator program fails here: make it the running task's own entry
/// (`agent-ebpf/src/task_scratch.rs`), or say why it is safe.
#[test]
fn every_per_cpu_map_is_safe_across_preemption_or_listed() {
    let found = per_cpu_maps();
    let unknown: Vec<String> = found
        .iter()
        .filter(|(_, m)| !KNOWN.iter().any(|(k, _)| k == m))
        .map(|(f, m)| format!("{f}: {m}"))
        .collect();
    assert!(
        unknown.is_empty(),
        "per-CPU maps nobody classified (a buffer kept across a helper call by a preemptible \
         program is rewritten by another task's run on the same CPU): {unknown:#?}"
    );
    let stale: Vec<&str> = KNOWN
        .iter()
        .filter(|(k, _)| !found.iter().any(|(_, m)| m == k))
        .map(|(k, _)| *k)
        .collect();
    assert!(stale.is_empty(), "listed but gone: {stale:?}");
    // the follow-up stays the FIM sensor's four, nothing of the exec guards
    let follow: Vec<&str> = KNOWN
        .iter()
        .filter(|(_, w)| *w == Why::FollowUp)
        .map(|(k, _)| *k)
        .collect();
    assert_eq!(
        follow,
        ["OPEN_SCRATCH", "OPEN_WIN", "RENAME_SCRATCH", "RENAME_EXT"]
    );
    for (f, m) in &found {
        if KNOWN.iter().any(|(k, w)| k == m && *w == Why::FollowUp) {
            assert_eq!(f, "agent-ebpf/src/open_sensor.rs", "{m}");
        }
    }
}

/// The exec guards' buffers are the running task's own entries, made at
/// the start of the run and removed before it returns: the exec sensor's
/// walk (the classes the exec policy refuses on), the environment, the
/// mapping check's walk, the quarantine's candidate and the BPF guard's
/// `OBJ_GET` path. They were per-CPU buffers in preemptible programs.
#[test]
fn the_exec_guards_buffers_are_the_running_task_s_own() {
    let lsm = code("agent-ebpf/src/exec_lsm.rs");
    let pol = code("agent-ebpf/src/execpol.rs");
    let q = code("agent-ebpf/src/execq.rs");
    let bpf = code("agent-ebpf/src/bpf_defense.rs");
    for (src, decl) in [
        (
            &lsm,
            "static EXEC_SCRATCH: LruHashMap<TaskKey, ExeIdentityRaw>",
        ),
        (&pol, "static EXECPOL_ENV: LruHashMap<TaskKey, EnvStashRaw>"),
        (
            &pol,
            "static EXECMAP_SCRATCH: LruHashMap<TaskKey, ExeIdentityRaw>",
        ),
        (
            &bpf,
            "static OBJ_GET_PATH_SCRATCH: LruHashMap<TaskKey, [u8; PATH_BUF_LEN]>",
        ),
    ] {
        let flat = src.split_whitespace().collect::<Vec<_>>().join(" ");
        assert!(flat.contains(decl), "{decl}");
    }
    assert!(
        !q.contains("EXECQ_CAND_SCRATCH"),
        "the candidate is built in place"
    );
    // the exec sensor: made, walked by key, judged, removed
    in_order(
        body(&lsm, "try_exec_check_lsm"),
        &[
            "let key = crate::task_scratch::key_of(task);",
            "crate::task_scratch::make(&EXEC_SCRATCH, &key)",
            "nn_exe_walk(",
            "crate::execpol::on_pass(s, inode, dentry, task as u64, pass, &key);",
            "let _ = EXEC_SCRATCH.remove(&key);",
        ],
    )
    .unwrap();
    assert!(body(&lsm, "nn_exe_walk")
        .contains("EXEC_SCRATCH.get_ptr_mut(&crate::task_scratch::key(tid, start))"));
    assert!(body(&q, "nn_execq_classify")
        .contains("EXEC_SCRATCH.get_ptr(&crate::task_scratch::key(tid, start))"));
    // a walk gone is classed as one that could not place the file
    assert!(body(&q, "nn_execq_classify")
        .contains("None => u64::from(class::TMP | class::VAR_TMP | class::HOME),"));
    assert!(body(&q, "note_pass").contains("crate::task_scratch::make(&EXECQ_CAND, &task)"));
    // the mapping check: the walk made per task, removed on every way out,
    // and walked again for a report from the cache
    in_order(
        body(&pol, "execmap_check"),
        &[
            "let rc = try_execmap(&ctx, task, &mut walked);",
            "let _ = EXECMAP_SCRATCH.remove(k);",
        ],
    )
    .unwrap();
    in_order(
        body(&pol, "try_execmap"),
        &[
            "if cached {",
            "*walked = Some(wk);",
            "nn_map_classify(file as u64, u64::from(wk.tid), wk.start_ns);",
            "EXECMAP_SCRATCH.get_ptr(&wk)",
        ],
    )
    .unwrap();
    assert!(body(&pol, "map_classify").contains("crate::task_scratch::make(&EXECMAP_SCRATCH"));
    // the BPF guard's path buffer
    in_order(
        body(&bpf, "nn_obj_get_own_link"),
        &[
            "crate::task_scratch::make(&OBJ_GET_PATH_SCRATCH, &key)",
            "obj_get_names_own_link(user_ptr, buf)",
            "let _ = OBJ_GET_PATH_SCRATCH.remove(&key);",
        ],
    )
    .unwrap();
    // the key: thread id and start time, so a reused id inherits nothing
    let ts = code("agent-ebpf/src/task_scratch.rs");
    in_order(
        body(&ts, "key_of"),
        &[
            "TASK_STRUCT_START_TIME_OFFSET",
            "start_ns:",
            "tid: bpf_get_current_pid_tgid() as u32",
        ],
    )
    .unwrap();
}

/// The bug of lot 322: no exec decision rests on a syscall tracepoint. The
/// environment is read at the exec's first pass by the exec sensor's LSM
/// program, from `envp` as the exec's own registers hold it (`execve`'s
/// `dx`, `execveat`'s `r10`), scanned into the task's own entry, judged on
/// the findings the scan returned, and the entry removed in the same run.
#[test]
fn the_exec_environment_is_read_by_the_exec_s_own_lsm_run() {
    let pol = code("agent-ebpf/src/execpol.rs");
    assert!(
        !pol.contains("#[tracepoint]"),
        "a tracepoint program in execpol.rs"
    );
    assert!(!pol.contains("EXECPOL_ENV_SCRATCH"));
    assert!(!pol.contains("TP_SYS_ENTER_EXECVE"));
    let p = body(&pol, "on_pass");
    in_order(
        p,
        &[
            "let (ef, ekey) = if pass == 0 && conf(conf_slot::FLAGS) & flags::ENV_SCAN != 0 {",
            "exec_env(task as *const u8, wk)",
            "if classes == 0 && ef == 0 {",
            "if ef != 0 {",
            "if ef & env_flags::DENYABLE != 0 {",
            "report_exec(",
            "let _ = EXECPOL_ENV.remove(k);",
        ],
    )
    .unwrap();
    in_order(
        body(&pol, "exec_envp"),
        &[
            "off_opt!(PT_REGS_ORIG_AX_OFFSET)",
            "off_opt!(PT_REGS_DX_OFFSET)",
            "off_opt!(PT_REGS_R10_OFFSET)",
            "TASK_STRUCT_MM_OFFSET",
            "regs_are_the_writes(tflags)",
            "bpf_task_pt_regs(generated::bpf_get_current_task_btf())",
            "match exec_envp_reg(nr) {",
            "Some(EnvpReg::Dx) => Some(peek_u64((regs + dx as u64)",
            "Some(EnvpReg::R10) => Some(peek_u64((regs + r10 as u64)",
        ],
    )
    .unwrap();
    in_order(
        body(&pol, "env_scan"),
        &[
            "crate::task_scratch::make(&EXECPOL_ENV, &key)",
            "bpf_probe_read_user(",
            "nn_list_staging(0, tid, start)",
            "if f == 0 {",
            "EXECPOL_ENV.remove(&key)",
        ],
    )
    .unwrap();
    // a stash gone before the staging check counts as staging
    in_order(
        body(&pol, "nn_list_staging"),
        &["EXECPOL_ENV.get_ptr(&key)", "None => return 1,"],
    )
    .unwrap();
    // the record carries the findings the judgment rested on
    assert!(body(&pol, "report_exec").contains("(*raw).env_flags = ef;"));
    // nothing in the agent attaches a program to the exec syscalls for it;
    // it arms the check when the three registers' offsets resolved
    let m = code("agent/src/execpol/mod.rs");
    assert!(!m.contains("sys_enter_execve"), "agent/src/execpol/mod.rs");
    assert!(m.contains("if offsets_resolved(&ENV_OFFSETS) {"));
    let flat = m.split_whitespace().collect::<Vec<_>>().join(" ");
    assert!(flat.contains(
        "pub const ENV_OFFSETS: [u32; 3] = [ common::btf_offsets::slot::PT_REGS_ORIG_AX_OFFSET, \
         common::btf_offsets::slot::PT_REGS_DX_OFFSET, \
         common::btf_offsets::slot::PT_REGS_R10_OFFSET, ];"
    ));
}
