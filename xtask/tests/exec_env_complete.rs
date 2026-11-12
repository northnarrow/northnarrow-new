//! Lot 325 — the exec-environment check (`EXECPOL_ENV`) complete and cheap,
//! after the re-check of #546.
//!
//! Each test names one item of the lot and fails on the code before it:
//! - R2: the scan reads every variable up to the kernel's own limit (it
//!   read 64: padding hid an `LD_PRELOAD` after them), and an environment it
//!   cannot finish is refused at a protected or set-id target;
//! - the mini-hunt: every occurrence of a loader variable is judged (musl's
//!   loader takes the first, glibc's the last);
//! - R1: an x32 exec's `envp` is the register whole;
//! - R5: a flood of execs in flight keeps protected targets closed and lets
//!   the rest through, recorded (every exec was refused);
//! - R6: the exec quarantine's candidate is a plain hash, never evicted;
//! - R3: a FIM walk that could not run is never cached;
//! - cost: the FIM sensor's entry lives as long as its task;
//! - TOCTOU: the kernel's own copy of the environment is read past the
//!   exec's point of no return.

mod support;

use std::fs;

use support::{repo_root, strip_comments};

fn code(rel: &str) -> String {
    strip_comments(
        &fs::read_to_string(repo_root().join(rel)).unwrap_or_else(|e| panic!("{rel}: {e}")),
    )
}

/// One line per item, whitespace collapsed.
fn flat(s: &str) -> String {
    s.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// `needles` all in `hay`, in this order.
fn in_order(hay: &str, needles: &[&str]) {
    let mut at = 0;
    for n in needles {
        match hay[at..].find(n) {
            Some(i) => at += i + n.len(),
            None => panic!("{n:?} not found after byte {at} in:\n{hay}"),
        }
    }
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

/// R2: every variable is read, in rounds of steps of global functions,
/// up to `ENV_SCAN_CAP` (above any environment the kernel accepts); each
/// costs its pointer and its first eight bytes, and the names the scan
/// judges are read whole. The 64-variable loop is gone.
#[test]
fn the_environment_is_read_to_its_end() {
    let pol = code("agent-ebpf/src/execpol.rs");
    assert!(
        !pol.contains("ENV_SCAN_MAX"),
        "the 64-variable bound is back"
    );
    in_order(
        body(&pol, "env_scan"),
        &[
            "crate::task_scratch::make(&EXECPOL_ENV, &key)",
            "while round < ENV_ROUNDS {",
            "nn_env_round(",
            "(round * ENV_STEP * ENV_STEPS_MID) as u64",
            "if r & MORE == 0 {",
            "if more {",
            "(envp + (ENV_SCAN_CAP as u64) * stride)",
            "(*e).stash.flags |= env_flags::TRUNCATED;",
            "(*e).stash.count = read as u32;",
        ],
    );
    in_order(
        body(&pol, "nn_env_round"),
        &[
            "while j < ENV_STEPS_MID {",
            "nn_env_step(envp, base + (j * ENV_STEP) as u64, tid, start, compat)",
            "if r & MORE == 0 {",
            "n | unread | MORE",
        ],
    );
    in_order(
        body(&pol, "nn_env_step"),
        &[
            "while i < ENV_STEP {",
            "if ptr == 0 {",
            "bpf_probe_read_user_str(wp as *mut c_void, 9, ptr as *const c_void)",
            "env_name_wanted(core::ptr::read_volatile(wp))",
            "env_var_judged(nn_env_var(ptr, tid, start), tid, start);",
            "ENV_STEP as u64 | unread | MORE",
        ],
    );
    // each a global function: verified once, a call for its callers
    for f in ["nn_env_round", "nn_env_step", "nn_env_var"] {
        assert!(
            flat(&pol).contains(&format!(
                "#[no_mangle] #[inline(never)] pub extern \"C\" fn {f}("
            )),
            "{f} is a global function"
        );
    }
    // the cap is above the kernel's own limit (the wire's test pins it)
    let wire = code("common/src/wire/execpol.rs");
    assert!(flat(&wire)
        .contains("pub const ENV_SCAN_CAP: usize = ENV_STEP * ENV_STEPS_MID * ENV_ROUNDS;"));
    // an environment the scan could not finish: refused at a protected
    // target (the tier's rule refuses a staging preload) or a set-id one,
    // counted, recorded
    let p = body(&pol, "on_pass");
    in_order(
        p,
        &[
            "let env_deny_rule = conf(conf_slot::ENV_DENY) & tb != 0",
            "let unfinished = ef & env_flags::UNFINISHED != 0 && (env_deny_rule || setid);",
            "if (ef & env_flags::DENYABLE != 0 && env_deny_rule) || unfinished {",
            "env_act |= action::DENY;",
        ],
    );
    assert!(
        p.contains("| env_flags::UNFINISHED)"),
        "a truncated environment is reported"
    );
    assert!(p.contains("bump(counter::ENV_TRUNCATED);"));
    // the agent reads the count and shows it
    let m = code("agent/src/execpol/mod.rs");
    assert!(m.contains("s(&self.env_truncated, counter::ENV_TRUNCATED);"));
    let st = code("agent/src/admin/handlers/status.rs");
    assert!(st.contains("execpol_env_truncated_total: Some(execpol.env_truncated),"));
}

/// The mini-hunt: each occurrence of `LD_PRELOAD`, `LD_AUDIT` and
/// `LD_LIBRARY_PATH` is judged when it is read. The scan judged the last
/// one only: musl's loader (and any `getenv`) takes the first, so a staging
/// preload first and a clean one last passed into a musl target.
#[test]
fn every_occurrence_of_a_loader_variable_is_judged() {
    let pol = code("agent-ebpf/src/execpol.rs");
    let so = body(&pol, "scan_one");
    in_order(
        so,
        &[
            "env_flags::LD_PRELOAD;",
            "return VAR_PRELOAD;",
            "env_flags::LD_AUDIT;",
            "return VAR_AUDIT;",
            "env_flags::LD_LIBRARY_PATH;",
            "return VAR_LIBPATH;",
        ],
    );
    // never cleared once set (an `=` would let a later clean one undo it)
    assert!(!so.contains("flags = "), "a finding cleared:\n{so}");
    // a loader value longer than its capture: not judged to its end
    assert_eq!(
        so.matches("st.flags |= env_flags::VALUE_CUT | env_flags::LOADER_CUT;")
            .count(),
        2,
        "LD_PRELOAD's and LD_AUDIT's cut:\n{so}"
    );
    let wire = flat(&code("common/src/wire/execpol.rs"));
    assert!(wire.contains("pub const UNFINISHED: u32 = TRUNCATED | LOADER_CUT;"));
    in_order(
        body(&pol, "env_var_judged"),
        &[
            "VAR_PRELOAD => (0, env_flags::PRELOAD_STAGING),",
            "VAR_AUDIT => (1, env_flags::AUDIT_STAGING),",
            "VAR_LIBPATH => (2, env_flags::LIBPATH_STAGING),",
            "if nn_list_staging(which, tid, start) != 0 {",
            "(*e).stash.flags |= bit;",
        ],
    );
    // judged after each variable, by the first pass and the post-commit one
    assert!(body(&pol, "nn_env_step")
        .contains("env_var_judged(nn_env_var(ptr, tid, start), tid, start);"));
    assert!(body(&pol, "nn_env_region_step")
        .contains("env_var_judged(nn_env_var(p, tid, kstart), tid, kstart);"));
}

/// R1: an x32 exec's `envp` is read from the register whole, an ia32
/// one's from its low half (the kernel's two stubs).
#[test]
fn an_x32_exec_s_envp_is_the_register_whole() {
    let wire = flat(&code("common/src/wire/execpol.rs"));
    assert!(wire.contains(
        "pub const fn envp_value(reg: u64, abi: EnvpAbi) -> u64 { match abi { EnvpAbi::Ia32 => \
         reg & 0xffff_ffff, EnvpAbi::Native | EnvpAbi::X32 => reg, } }"
    ));
    assert!(wire.contains("X32_NR_EXECVE => Some((EnvpReg::Dx, EnvpAbi::X32)),"));
    assert!(wire.contains("X32_NR_EXECVEAT => Some((EnvpReg::R10, EnvpAbi::X32)),"));
    let pol = code("agent-ebpf/src/execpol.rs");
    in_order(
        body(&pol, "exec_envp"),
        &[
            "let (reg, abi) = match exec_envp_reg(nr) {",
            "envp_value(peek_u64((regs + off as u64) as *const u8), abi)",
            "if abi.compat_pointers() {",
        ],
    );
}

/// R5: the exec sensor's per-task map full (a flood of execs in flight):
/// judged without the walk on what needs none — refused at a protected
/// target, every other exec let through, counted and recorded, and the
/// agent signs a degradation while it lasts. Every exec was refused.
#[test]
fn a_flood_of_execs_keeps_protected_targets_closed() {
    let pol = code("agent-ebpf/src/execpol.rs");
    assert!(!pol.contains("fn walk_lost("), "refuse-everything is back");
    let u = body(&pol, "exec_unwalked");
    in_order(
        u,
        &[
            "let tv = nn_execpol_tier(task) as u32;",
            "classes |= class::MEMFD;",
            "classes |= class::DELETED;",
            "classes |= class::TMPFS;",
            "classes |= class::WORLD_WRITABLE_DIR;",
            "let ex = exemptions(t_ptr, inode, &mut sig);",
            "let setid = mode_bits & 0o6000 != 0;",
            "let protected = env_deny_rule || setid;",
            "(protected && ef & (env_flags::UNREADABLE | env_flags::UNFINISHED) != 0);",
            "let refuse = m == mode::ENFORCE && (deny_c != 0 || env_refused);",
            "bump(counter::LOST);",
            "bump(counter::LOST_OPEN);",
            "report_unwalked(",
        ],
    );
    assert!(body(&pol, "report_unwalked").contains("(*raw).action = act;"));
    // the environment read by `exec_check_lsm` itself, then handed over (a
    // frame of the ladder under the scan's three passed the verifier's 512
    // bytes for a call chain: 7.0 refused the program)
    let lsm = code("agent-ebpf/src/exec_lsm.rs");
    in_order(
        body(&lsm, "try_exec_check_lsm"),
        &[
            "let er = crate::execpol::env_for_unwalked(task as u64, pass);",
            "crate::execpol::nn_exec_unwalked(",
            "er,",
        ],
    );
    assert!(
        !u.contains("nn_exec_env("),
        "the scan under the ladder's frame"
    );
    assert!(u.contains("let mut act = action::UNWALKED | action::RECORD;"));
    // the agent: counted, a signed degradation while the counts move
    let c = code("agent/src/execpol/controller.rs");
    in_order(
        body(&c, "step"),
        &[
            "COUNTERS.store_kernel(&c);",
            "self.capacity.seen(",
            "c[counter::LOST as usize],",
            "c[counter::LOST_OPEN as usize],",
        ],
    );
    assert!(c.contains("Condition::with_hold(\"execpol_capacity\", CAPACITY_HOLD)"));
}

/// R6: the exec quarantine's candidate is a plain hash (an LRU insert could
/// evict an entry a preemptible program holds and hand its memory to
/// another task's candidate), removed when the task is freed.
#[test]
fn the_quarantine_s_candidate_is_never_evicted() {
    let q = flat(&code("agent-ebpf/src/execq.rs"));
    assert!(q.contains(
        "static EXECQ_CAND: HashMap<u64, ExecqCandRaw> = HashMap::with_max_entries(EXECQ_CAND_CAP, 0);"
    ));
    assert!(!q.contains("EXECQ_CAND: LruHashMap"));
    let ts = code("agent-ebpf/src/task_scratch.rs");
    in_order(
        body(&ts, "nn_task_free"),
        &[
            "crate::open_sensor::forget_freed(task);",
            "crate::execq::forget(task)",
            "crate::execpol::forget_freed(task);",
        ],
    );
    assert!(ts.contains("#[lsm(hook = \"task_free\")]\npub fn nn_task_free("));
    // attached by the exec guards when the quarantine or the policy runs
    let g = code("agent/src/exec_guards.rs");
    in_order(
        &g,
        &[
            "if self.execq_kernel.is_some() || self.execpol_kernel.is_some() {",
            "nn_linux::sensors::task_free::ensure(ebpf, &btf)",
        ],
    );
}

/// R3: a FIM walk that could not run (the task's buffer not made) is not
/// the directory's class: never cached, the next open walks again.
#[test]
fn a_lost_fim_walk_is_never_cached() {
    let open = code("agent-ebpf/src/open_sensor.rs");
    in_order(
        body(&open, "walk"),
        &[
            "crate::task_scratch::get_or_make(&OPEN_TASK, &task)",
            "return (u64::from(u32::MAX) << 32) | u64::from(WALK_LOST);",
        ],
    );
    in_order(
        body(&open, "dir_class"),
        &[
            "nn_open_walk(",
            "if dir_class_cacheable(c.bits) {",
            "DIR_CLASS.insert(dkey, &c, 0);",
        ],
    );
    assert_eq!(
        open.matches("DIR_CLASS.insert(").count(),
        1,
        "one place caches a directory's class"
    );
}

/// Cost: the FIM sensor's buffers are the task's for its life — one lookup
/// per open — made at its first open, removed by `task_free`; per run only
/// when that program is not attached.
#[test]
fn the_fim_sensor_keeps_its_buffer_for_the_task_s_life() {
    let open = code("agent-ebpf/src/open_sensor.rs");
    let o = body(&open, "on_open");
    assert!(
        !o.contains("task_scratch::make(&OPEN_TASK"),
        "an insert per open:\n{o}"
    );
    in_order(
        o,
        &[
            "crate::task_scratch::get_or_make(&OPEN_TASK, &task)",
            "on_open_in(file, t);",
            "if !crate::task_scratch::task_free_armed() {",
            "let _ = OPEN_TASK.remove(&task);",
        ],
    );
    in_order(
        body(&open, "forget_task"),
        &["if crate::task_scratch::task_free_armed() {", "return;"],
    );
    assert!(body(&open, "forget_freed").contains("OPEN_TASK.remove(&task)"));
    // the agent attaches `task_free` with the sensor, then arms it
    let a = code("crates/nn-linux/src/fim/attach.rs");
    in_order(
        &a,
        &[
            "attach_transient(ebpf, OPEN_SENSOR_PROGRAM, hook, btf)",
            "crate::sensors::task_free::ensure(ebpf, btf)",
        ],
    );
    let tf = code("crates/nn-linux/src/sensors/task_free.rs");
    in_order(
        body(&tf, "ensure"),
        &[
            "antitamper_bpf::attach_transient(ebpf, PROGRAM, HOOK, btf)?;",
            "arr.set(0, 1, 0)",
        ],
    );
}

/// TOCTOU: the new image's environment — the kernel's own copy — is read
/// at `sched_process_exec`, past the exec's point of no return; a staging
/// loader entry there that the first pass did not see is the environment
/// changed after the kernel's copy: counted, recorded, and the image killed
/// before its first instruction where the tier's rule refuses it.
#[test]
fn the_kernel_s_own_copy_is_read_past_the_point_of_no_return() {
    let pol = code("agent-ebpf/src/execpol.rs");
    in_order(
        body(&pol, "env_commit"),
        &[
            "off_opt!(MM_STRUCT_ENV_START_OFFSET)",
            "off_opt!(MM_STRUCT_ENV_END_OFFSET)",
            "nn_env_region(start, end, u64::from(key.tid), key.start_ns)",
            "EXECPOL_ENV_SEEN.get(&tk)",
            "if f & env_flags::DENYABLE & !seen == 0 {",
            "bump(counter::ENV_CHANGED);",
            "let tv = nn_execpol_tier(tk) as u32;",
            "if conf(conf_slot::MODE) == mode::ENFORCE {",
            "generated::bpf_send_signal(SIGKILL);",
            "env_act |= action::DENY | action::KILLED;",
            "report_commit(task, mm, tv, f | env_flags::CHANGED, env_act, &(*e).stash);",
        ],
    );
    // the first pass notes what it let through, and forgets a failed
    // exec's note at the next exec
    let p = body(&pol, "on_pass");
    in_order(
        p,
        &[
            "let _ = EXECPOL_ENV_SEEN.remove(&task);",
            "nn_exec_env(task, u64::from(wk.tid), wk.start_ns)",
            "if ef & env_flags::DENYABLE != 0 && env_act & action::DENY == 0 {",
            "EXECPOL_ENV_SEEN.insert(&task, &ef, 0);",
        ],
    );
    // the region is read string after string, the judged names whole
    in_order(
        body(&pol, "nn_env_region_step"),
        &[
            "bpf_probe_read_user_str(",
            "REGION_READ as u32,",
            "if a != 0 {",
            "env_name_wanted(",
            "env_var_judged(nn_env_var(p, tid, kstart), tid, kstart);",
        ],
    );
    // the agent attaches it where the offsets resolve, else a degradation
    let m = code("agent/src/execpol/mod.rs");
    in_order(
        &m,
        &[
            "if !offsets_resolved(&COMMIT_OFFSETS) {",
            "note(",
            "} else if let Err(e) = attach_commit(ebpf) {",
            "note(format!(",
        ],
    );
    let off = flat(&code("common/src/btf_offsets.rs"));
    assert!(off.contains("pub const MM_STRUCT_ENV_START_OFFSET: u32 = 130;"));
    assert!(off.contains("pub const MM_STRUCT_ENV_END_OFFSET: u32 = 131;"));
}
