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
}

/// Every per-CPU map of `agent-ebpf`, with why it is safe. The review of
/// #546 (F3): the FIM sensor's four buffers left here as a follow-up fed
/// posture-floor kills (FIM-010..017) and are per-task entries now.
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
];

/// The per-CPU map types of aya-ebpf.
const PER_CPU_TYPES: [&str; 3] = ["PerCpuArray<", "PerCpuHashMap<", "LruPerCpuHashMap<"];

/// Whether the type text `ty` (after `static NAME:`) is a per-CPU map,
/// however it is spelt: plain (`PerCpuArray<…>`) or path-qualified
/// (`aya_ebpf::maps::PerCpuArray<…>`; the review of #546, F6).
fn is_per_cpu_type(ty: &str) -> bool {
    let head = ty.split('<').next().unwrap_or("");
    let last = head.rsplit("::").next().unwrap_or("").trim();
    PER_CPU_TYPES
        .iter()
        .any(|t| t.trim_end_matches('<') == last)
}

/// The names of the per-CPU maps `src` (comments stripped) declares, and
/// the type aliases it declares to any per-CPU map type (forbidden: a
/// `static X: Alias` would hide one; the review of #546, F6).
fn per_cpu_decls(src: &str) -> (Vec<String>, Vec<String>) {
    let flat = src.split_whitespace().collect::<Vec<_>>().join(" ");
    let mut maps = Vec::new();
    for piece in flat.split("static ").skip(1) {
        let Some((name, rest)) = piece.split_once(':') else {
            continue;
        };
        if is_per_cpu_type(rest.trim_start()) {
            maps.push(name.trim().to_string());
        }
    }
    let mut aliases = Vec::new();
    for piece in flat.split("type ").skip(1) {
        let Some((name, rest)) = piece.split_once('=') else {
            continue;
        };
        let rhs = rest.split(';').next().unwrap_or("");
        if PER_CPU_TYPES
            .iter()
            .any(|t| rhs.contains(t.trim_end_matches('<')))
        {
            aliases.push(name.trim().to_string());
        }
    }
    (maps, aliases)
}

/// `(file, name)` pairs.
type Found = Vec<(String, String)>;

/// `(file, map)` of every per-CPU map declared in `agent-ebpf/src`, and
/// `(file, alias)` of every type alias to a per-CPU map type.
fn per_cpu_maps() -> (Found, Found) {
    let root = repo_root();
    let mut files = Vec::new();
    support::rs_files(&root.join("agent-ebpf/src"), &mut files);
    let mut out = Vec::new();
    let mut aliases = Vec::new();
    for f in &files {
        let c = strip_comments(&fs::read_to_string(f).unwrap());
        let rel = f.strip_prefix(&root).unwrap().display().to_string();
        let (m, a) = per_cpu_decls(&c);
        out.extend(m.into_iter().map(|n| (rel.clone(), n)));
        aliases.extend(a.into_iter().map(|n| (rel.clone(), n)));
    }
    out.sort();
    (out, aliases)
}

/// The review of #546 (F6): the scanner sees a per-CPU map however it is
/// declared — plain, path-qualified, through a type alias — and nothing
/// else. Planted in text, the scanner's own input.
#[test]
fn the_scanner_sees_every_spelling_of_a_per_cpu_map() {
    let planted = "
        static PLAIN: PerCpuArray<u64> = PerCpuArray::with_max_entries(1, 0);
        pub(crate) static QUALIFIED: aya_ebpf::maps::PerCpuArray<[u8; 8]> = x;
        static HASHED: aya_ebpf::maps::per_cpu_hash_map::PerCpuHashMap<u32, u64> = x;
        static LRU: LruPerCpuHashMap<u32, u64> = x;
        type Scratch = aya_ebpf::maps::PerCpuArray<[u8; 64]>;
        static SNEAKY: Scratch = x;
        static FINE: HashMap<TaskKey, u64> = x;
        static ALSO_FINE: LruHashMap<u64, u64> = x;
        static ARRAY: Array<u64> = x;
    ";
    let (maps, aliases) = per_cpu_decls(planted);
    assert_eq!(maps, ["PLAIN", "QUALIFIED", "HASHED", "LRU"]);
    assert_eq!(aliases, ["Scratch"]);
}

/// Every per-CPU map is classified, the list names no map that is gone,
/// and no type alias hides one. A new per-CPU buffer kept across a helper
/// call in an LSM, fentry or iterator program fails here: make it the
/// running task's own entry (`agent-ebpf/src/task_scratch.rs`), or say why
/// it is safe.
#[test]
fn every_per_cpu_map_is_safe_across_preemption_or_listed() {
    let (found, aliases) = per_cpu_maps();
    assert!(
        aliases.is_empty(),
        "a type alias to a per-CPU map type (it would hide the map from this list): {aliases:?}"
    );
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
    // the FIM sensor's buffers are no longer per CPU
    for gone in ["OPEN_SCRATCH", "OPEN_WIN", "RENAME_SCRATCH", "RENAME_EXT"] {
        assert!(!found.iter().any(|(_, m)| m == gone), "{gone}");
    }
}

/// The exec guards' and the FIM sensor's buffers are the running task's
/// own entries, made at the start of the run and removed before it
/// returns: the exec sensor's walk (the classes the exec policy refuses
/// on), the environment, the mapping check's walk, the quarantine's
/// candidate, the BPF guard's `OBJ_GET` path, the FIM sensor's windows and
/// names, a rename's names. They were per-CPU buffers in preemptible
/// programs. The review of #546 (F4): plain hashes, never an LRU (whose
/// insert can evict an entry in flight and hand its memory to another
/// task), with a cap whose overflow fails closed.
#[test]
fn the_exec_guards_buffers_are_the_running_task_s_own() {
    let lsm = code("agent-ebpf/src/exec_lsm.rs");
    let pol = code("agent-ebpf/src/execpol.rs");
    let q = code("agent-ebpf/src/execq.rs");
    let bpf = code("agent-ebpf/src/bpf_defense.rs");
    let open = code("agent-ebpf/src/open_sensor.rs");
    let fim = code("agent-ebpf/src/fim_watch.rs");
    let cap = "HashMap::with_max_entries(crate::task_scratch::TASK_SCRATCH_CAP, 0);";
    for (src, decl) in [
        (
            &lsm,
            "static EXEC_SCRATCH: HashMap<TaskKey, ExeIdentityRaw> =",
        ),
        (&pol, "static EXECPOL_ENV: HashMap<TaskKey, EnvStashRaw> ="),
        (
            &pol,
            "static EXECMAP_SCRATCH: HashMap<TaskKey, ExeIdentityRaw> =",
        ),
        (
            &q,
            "static EXECQ_CAND_SCRATCH: HashMap<TaskKey, ExecqCandRaw> =",
        ),
        (
            &bpf,
            "static OBJ_GET_PATH_SCRATCH: HashMap<TaskKey, [u8; PATH_BUF_LEN]> =",
        ),
        (&open, "static OPEN_TASK: HashMap<u64, OpenTask> ="),
        (&open, "static RENAME_TASK: HashMap<u64, RenameTask> ="),
    ] {
        let flat = src.split_whitespace().collect::<Vec<_>>().join(" ");
        let at = flat.find(decl).unwrap_or_else(|| panic!("{decl}"));
        assert!(
            flat[at + decl.len()..].trim_start().starts_with(cap),
            "{decl}"
        );
    }
    let ts = code("agent-ebpf/src/task_scratch.rs");
    assert!(
        !ts.contains("LruHashMap"),
        "task_scratch.rs makes LRU entries"
    );
    in_order(
        &ts,
        &[
            "pub(crate) unsafe fn make<K, T>(map: &HashMap<K, T>, key: &K) -> Option<*mut T> {",
            "map.insert(key, &*(zero as *const T), 0).ok()?;",
            "map.get_ptr_mut(key)",
        ],
    )
    .unwrap();
    // the candidate: built in the task's own buffer, then copied
    in_order(
        body(&q, "note_pass"),
        &[
            "crate::task_scratch::make(&EXECQ_CAND_SCRATCH, &ck)",
            "crate::execpol::count_lost();",
            "EXECQ_CAND.insert(&task, &*cand, 0)",
            "let _ = EXECQ_CAND_SCRATCH.remove(&ck);",
        ],
    )
    .unwrap();
    // the exec sensor: made, walked by key, judged, removed
    in_order(
        body(&lsm, "try_exec_check_lsm"),
        &[
            "let key = crate::task_scratch::key_of(task);",
            "crate::task_scratch::make(&EXEC_SCRATCH, &key)",
            // the map full: counted, refused in enforce mode
            "None => return crate::execpol::walk_lost(),",
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
    in_order(
        body(&pol, "walk_lost"),
        &[
            "bump(counter::LOST);",
            "if conf(conf_slot::MODE) == mode::ENFORCE {",
            "-EACCES",
        ],
    )
    .unwrap();
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
    // no walk: counted, classed as a file the walk cannot place, not cached
    in_order(
        body(&pol, "map_classify"),
        &[
            "bump(counter::LOST);",
            "return MAP_WALK_LOST | class::TMP | class::VAR_TMP | class::HOME;",
        ],
    )
    .unwrap();
    in_order(
        body(&pol, "try_execmap"),
        &[
            "classes = r & !MAP_WALK_LOST;",
            "if r & MAP_WALK_LOST == 0 {",
            "EXECMAP_SEEN.insert",
        ],
    )
    .unwrap();
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
    // the FIM sensor (the review of #546, F3): the open's windows and names,
    // a rename's names and extensions, each the running task's, removed at
    // the end of the run; the map full: the plain observer, counted
    in_order(
        body(&open, "on_open"),
        &[
            "crate::task_scratch::make(&OPEN_TASK, &task)",
            "crate::drops::bump(northnarrow_common::ring_drops::ring_slot::OPEN_SENSOR);",
            "crate::fim_watch::observe_open_plain(file);",
            "on_open_in(file, t);",
            "let _ = OPEN_TASK.remove(&task);",
        ],
    )
    .unwrap();
    assert!(body(&open, "on_open_in").contains("observe(") && !open.contains("OPEN_WIN"));
    assert!(body(&open, "walk").contains("crate::task_scratch::get_or_make(&OPEN_TASK, &task)"));
    in_order(
        body(&open, "nn_rename_burst"),
        &["rename_burst(", "let _ = RENAME_TASK.remove(&task);"],
    )
    .unwrap();
    assert!(body(&open, "rename_burst").contains("crate::task_scratch::make(&RENAME_TASK, &task)"));
    for f in ["nn_rename_ext", "nn_rename_shape"] {
        assert!(body(&open, f).contains("RENAME_TASK.get_ptr"), "{f}");
    }
    for f in ["try_fim_unlink_observe", "try_fim_rename_observe"] {
        let b = body(&fim, f);
        in_order(
            b,
            &["nn_unlink_burst(", "crate::open_sensor::forget_task();"],
        )
        .unwrap();
    }
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
            "let er = if pass == 0 && conf(conf_slot::FLAGS) & flags::ENV_SCAN != 0 {",
            "exec_env(task as *const u8, wk)",
            "let stashed = er & ENV_STASHED != 0;",
            "if classes == 0 && ef == 0 {",
            "if ef != 0 {",
            "if ef & env_flags::DENYABLE != 0 {",
            "report_exec(",
            "if stashed {",
            "let _ = EXECPOL_ENV.remove(wk);",
        ],
    )
    .unwrap();
    in_order(
        body(&pol, "exec_envp"),
        &[
            "off_opt!(PT_REGS_ORIG_AX_OFFSET)",
            "TASK_STRUCT_MM_OFFSET",
            "regs_are_the_writes(tflags)",
            "bpf_task_pt_regs(generated::bpf_get_current_task_btf())",
            "let (reg, compat) = match exec_envp_reg(nr) {",
            "None => return ENVP_UNREAD,",
            "EnvpReg::Dx => off_opt!(PT_REGS_DX_OFFSET),",
            "EnvpReg::R10 => off_opt!(PT_REGS_R10_OFFSET),",
            "EnvpReg::Si => off_opt!(PT_REGS_SI_OFFSET),",
            "envp_value(peek_u64((regs + off as u64) as *const u8), compat)",
            "v | ENVP_COMPAT",
        ],
    )
    .unwrap();
    // the review of #546 (F1, F2): a compat call's array of 32-bit
    // pointers is read; an entry or a string the scan cannot read is a
    // finding (never skipped), counted and recorded, never refused
    in_order(
        body(&pol, "env_scan"),
        &[
            "let stride = envp_stride(compat);",
            "stride as u32,",
            "(envp + (i as u64) * stride)",
            "(*e).flags |= env_flags::UNREADABLE;",
            ") < 0",
            "(*e).flags |= env_flags::UNREADABLE;",
        ],
    )
    .unwrap();
    let so = body(&pol, "scan_one");
    assert_eq!(
        so.matches("(*e).flags |= env_flags::UNREADABLE;").count(),
        5,
        "each captured value's read failure is flagged:\n{so}"
    );
    in_order(
        body(&pol, "exec_env"),
        &[
            "if raw == ENVP_UNREAD {",
            "return u64::from(env_flags::UNREADABLE);",
            "let compat = raw >> 63;",
            "nn_env_scan(envp, u64::from(key.tid), key.start_ns, compat)",
            "if r & SCAN_LOST != 0 {",
            "return u64::from(env_flags::UNREADABLE);",
            "u64::from(ef) | ENV_STASHED",
        ],
    )
    .unwrap();
    let p = body(&pol, "on_pass");
    in_order(
        p,
        &[
            "if ef & env_flags::UNREADABLE != 0 {",
            "bump(counter::ENV_UNREAD);",
            "| env_flags::UNREADABLE)",
        ],
    )
    .unwrap();
    assert!(
        !p.contains("UNREADABLE) != 0 {\n                if m == mode::ENFORCE"),
        "an unread environment is never refused"
    );
    // the agent reports both counters
    let m = code("agent/src/execpol/mod.rs");
    assert!(m.contains("s(&self.env_unread, counter::ENV_UNREAD);"));
    assert!(m.contains("s(&self.lost, counter::LOST);"));
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
    // it arms the check when the four registers' offsets resolved
    let m = code("agent/src/execpol/mod.rs");
    assert!(!m.contains("sys_enter_execve"), "agent/src/execpol/mod.rs");
    assert!(m.contains("if offsets_resolved(&ENV_OFFSETS) {"));
    let flat = m.split_whitespace().collect::<Vec<_>>().join(" ");
    assert!(flat.contains(
        "pub const ENV_OFFSETS: [u32; 4] = [ common::btf_offsets::slot::PT_REGS_ORIG_AX_OFFSET, \
         common::btf_offsets::slot::PT_REGS_DX_OFFSET, \
         common::btf_offsets::slot::PT_REGS_R10_OFFSET, \
         common::btf_offsets::slot::PT_REGS_SI_OFFSET, ];"
    ));
}
