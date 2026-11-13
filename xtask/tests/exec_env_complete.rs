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
            "while round < ENV_ROUNDS + ENV_JUDGED_MAX as usize {",
            "nn_env_round(envp, read, tid, start, compat)",
            "read += r & COUNT_MASK;",
            "if r & JUDGE != 0 {",
            "if nn_env_pending(tid, start) & STOP != 0 {",
            "(*e).stash.flags |= env_flags::TRUNCATED;",
            "} else if r & MORE == 0 {",
            "if more {",
            "(envp + read * stride)",
            "(*e).stash.flags |= env_flags::TRUNCATED;",
            "(*e).stash.count = read as u32;",
        ],
    );
    // the rounds cover the cap, whatever the judged names took of them
    assert!(flat(&pol)
        .contains("const _: () = assert!(ENV_ROUNDS * ENV_STEPS_MID * ENV_STEP == ENV_SCAN_CAP);"));
    assert!(
        flat(&pol).contains("const ROUND_CALLS: usize = ENV_STEPS_MID + ENV_JUDGED_MAX as usize;")
    );
    let round = body(&pol, "nn_env_round");
    in_order(
        round,
        &[
            "while j < ENV_STEPS_MID {",
            "nn_env_step(envp, idx + n, tid, start, compat)",
            "if r & JUDGE != 0 {",
            "return n | unread | JUDGE;",
            "if r & MORE == 0 {",
            "return n | unread;",
            "n | unread | MORE",
        ],
    );
    // a judged name is read whole by the scan (the call chain's stack, the
    // round's verifier states), at most ENV_JUDGED_MAX per exec
    assert!(
        !round.contains("nn_env_var("),
        "the round reads a name:\n{round}"
    );
    in_order(
        body(&pol, "nn_env_pending"),
        &[
            "if !judged_one_more(0, tid, start) {",
            "return STOP;",
            "nn_env_judge(nn_env_var(ptr, tid, start, 0), ptr, tid, start, 0);",
            "if env_entry(0, tid, start).is_none() {",
            "return STOP;",
        ],
    );
    let step = body(&pol, "nn_env_step");
    in_order(
        step,
        &[
            "while i < ENV_STEP {",
            "if ptr == 0 {",
            "bpf_probe_read_user_str(w as *mut c_void, 9, ptr as *const c_void)",
            "env_name_wanted(core::ptr::read_volatile(w))",
            "(*e).pending = ptr;",
            "return (i + 1) as u64 | unread | JUDGE;",
            "ENV_STEP as u64 | unread | MORE",
        ],
    );
    // a step calls nothing: the call chain under `exec_check_lsm` stays
    // under the verifier's 512 bytes
    assert!(!step.contains("nn_env_var("), "a step calls down:\n{step}");
    // the judged names' cap (the review of #547, F8): past it, not finished
    in_order(
        body(&pol, "judged_one_more"),
        &[
            "if (*e).judged >= ENV_JUDGED_MAX {",
            "(*e).stash.flags |= env_flags::TRUNCATED;",
            "false",
        ],
    );
    // each a global function: verified once, a call for its callers
    for f in [
        "nn_env_round",
        "nn_env_step",
        "nn_env_pending",
        "nn_env_var",
        "nn_env_judge",
        "nn_env_chunk",
        "nn_value_end",
        "nn_value_slash",
        "nn_env_resolve",
    ] {
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
    // the re-check of #547 (G6): judged by the environment's own program
    let p = body(&pol, "try_exec_env_lsm");
    in_order(
        p,
        &[
            "let env_deny_rule = conf(conf_slot::ENV_DENY) & tb != 0",
            "let unfinished = ef & env_flags::FIRST_PASS_FAIL_CLOSED != 0 && (env_deny_rule || setid);",
            "if (ef & env_flags::DENYABLE != 0 && env_deny_rule) || unfinished {",
            "env_act |= action::DENY;",
        ],
    );
    assert!(
        p.contains("| env_flags::UNFINISHED"),
        "a truncated environment is reported"
    );
    // the review of #547 (F1, F7): what the first pass refuses unread — an
    // array past the cap, a relative loader path; a loader value longer
    // than the scan reads goes to the post-commit check
    let wire_flat = flat(&wire);
    assert!(wire_flat.contains(
        "pub const FIRST_PASS_FAIL_CLOSED: u32 = TRUNCATED | PRELOAD_RELATIVE | LOADER_IRREGULAR;"
    ));
    assert!(wire_flat.contains(
        "pub const UNJUDGED: u32 = UNFINISHED | UNREADABLE | PRELOAD_RELATIVE | LOADER_IRREGULAR;"
    ));
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
    // The review of #547 (F7): a value longer than its capture (the record's
    // quote) is cut for the record only — the value is judged whole below;
    // a clean `LD_PRELOAD` of 128 bytes or more was refused.
    assert_eq!(
        so.matches("st.flags |= env_flags::VALUE_CUT;").count(),
        3,
        "the captures' cut:\n{so}"
    );
    assert!(!so.contains("LOADER_CUT"), "a capture's cut refused:\n{so}");
    // a full capture is `cap - 1` bytes and its NUL: cut only when the value
    // has a byte at `cap - 1` (a value of exactly 127 bytes was flagged)
    in_order(
        body(&pol, "value_cut"),
        &[
            "if len < cap as i64 {",
            "return false;",
            "(value + cap as u64 - 1) as *const c_void,",
            "b != 0",
        ],
    );
    let wire = flat(&code("common/src/wire/execpol.rs"));
    assert!(wire.contains("pub const UNFINISHED: u32 = TRUNCATED | LOADER_CUT;"));
    // The review of #547 (F1): each value read whole, a chunk at a time,
    // every entry parsed as the loader parses the list
    // (`value_parse::byte`) and judged on its normalised path; past the
    // reads, `LOADER_CUT`. It compared the first nine bytes of each entry
    // of a 128-byte capture.
    assert!(
        !pol.contains("nn_list_staging"),
        "the 9-byte entry compare is back"
    );
    in_order(
        body(&pol, "nn_env_judge"),
        &[
            "VAR_PRELOAD => (u64::from(value_parse::KIND_PRELOAD), 11u64),",
            "VAR_AUDIT => (u64::from(value_parse::KIND_AUDIT), 9),",
            "VAR_LIBPATH => (u64::from(value_parse::KIND_LIBPATH), 16),",
            "while r < ENV_VALUE_READS {",
            "nn_env_chunk(q, kind | if r == 0 { CHUNK_FIRST } else { 0 }, tid, start, sel)",
            "cut = 0;",
            "q += (REGION_READ - 1) as u64;",
            "nn_env_chunk(0, kind | CHUNK_FINISH | cut, tid, start, sel)",
        ],
    );
    in_order(
        body(&pol, "nn_env_chunk"),
        &[
            "value_found(e, kind, kind_flags & CHUNK_CUT != 0);",
            "zero_parse(&mut (*e).parse);",
            "(*e).stash.flags |= env_flags::UNREADABLE;",
            "if value_parse::is_sep(kind, b) {",
            "let _ = nn_value_end(u64::from(kind), tid, start, sel);",
            "value_parse::begin(&mut (*e).parse, b);",
            "if b == b'/' {",
            "let _ = nn_value_slash(tid, start, sel);",
            "value_parse::push(&mut (*e).parse, b);",
        ],
    );
    // the steps of `value_parse::byte`, which the host tests run
    assert!(body(&pol, "nn_value_end").contains("value_parse::sep(&mut (*e).parse, kind as u32);"));
    // The re-check of #547 (G1–G4): every byte through `value_parse::odd`
    // (a control byte, a `$`), the value's end through `end_value` (a
    // library path ending with an empty element); whichever variable, the
    // finding is `LOADER_IRREGULAR`, refused at a protected or set-id
    // target with the first pass's fail-closed set
    in_order(
        body(&pol, "nn_env_chunk"),
        &[
            "let b = *buf.add(i);",
            "value_parse::odd(&mut (*e).parse, b);",
            "if value_parse::is_sep(kind, b) {",
        ],
    );
    in_order(
        body(&pol, "value_found"),
        &[
            "value_parse::end_value(&mut (*e).parse, kind);",
            "if found & value_parse::IRREGULAR != 0 {",
            "(*e).stash.flags |= env_flags::LOADER_IRREGULAR;",
        ],
    );
    in_order(
        body(&wire, "odd"),
        &[
            "if b < 0x20 || b == 0x7f || b == b'$' {",
            "p.found |= IRREGULAR;",
        ],
    );
    in_order(
        body(&wire, "sep"),
        &[
            "if kind == KIND_LIBPATH && p.st & IN == 0 {",
            "p.found |= RELATIVE;",
            "end_entry(p, kind);",
        ],
    );
    in_order(
        body(&wire, "end_value"),
        &[
            "if kind == KIND_LIBPATH && p.st & SEP != 0 {",
            "p.found |= RELATIVE;",
            "end_entry(p, kind);",
        ],
    );
    // The re-check 2 of #547 (G2): an empty library-path element is a
    // relative directory — recorded alone (`LIBPATH_STAGING`), refused only
    // with a bare `LD_PRELOAD` / `LD_AUDIT` name searched in it
    // (`resolve_bare`: `PRELOAD_RELATIVE`), never `LOADER_IRREGULAR`
    in_order(
        body(&pol, "value_found"),
        &[
            "st.flags |= env_flags::LIBPATH_STAGING;",
            "(*e).internal |= INTERNAL_LIBPATH_RELATIVE;",
        ],
    );
    in_order(
        body(&pol, "resolve_bare"),
        &[
            "if i & (INTERNAL_BARE_PRELOAD | INTERNAL_BARE_AUDIT) != 0 {",
            "if i & INTERNAL_LIBPATH_RELATIVE != 0 {",
            "(*e).stash.flags |= env_flags::PRELOAD_RELATIVE;",
        ],
    );
    assert!(!flat(&code("common/src/wire/execpol.rs"))
        .contains("pub const FIRST_PASS_FAIL_CLOSED: u32 = TRUNCATED | PRELOAD_RELATIVE | LOADER_IRREGULAR | LIBPATH_STAGING"));
    assert!(body(&pol, "nn_value_slash").contains("value_parse::slash(&mut (*e).parse);"));
    in_order(
        body(&wire, "byte"),
        &[
            "odd(p, b);",
            "if is_sep(kind, b) {",
            "sep(p, kind);",
            "begin(p, b);",
            "if b == b'/' {",
            "slash(p);",
            "push(p, b);",
        ],
    );
    in_order(
        body(&pol, "value_found"),
        &[
            "value_parse::end_value(&mut (*e).parse, kind);",
            "if kind == value_parse::KIND_PRELOAD {",
            "st.flags |= env_flags::PRELOAD_STAGING;",
            "st.flags |= env_flags::PRELOAD_RELATIVE;",
            "st.flags |= env_flags::LOADER_CUT;",
            "} else if kind == value_parse::KIND_AUDIT {",
            "st.flags |= env_flags::AUDIT_STAGING;",
            "st.flags |= env_flags::PRELOAD_RELATIVE;",
            "st.flags |= env_flags::LOADER_CUT;",
            "(*e).internal |= INTERNAL_LIBPATH_STAGING;",
            "(*e).internal |= INTERNAL_LIBPATH_RELATIVE;",
            "(*e).internal |= INTERNAL_LIBPATH_CUT;",
        ],
    );
    // a bare name is searched in the library path first
    in_order(
        body(&pol, "resolve_bare"),
        &[
            "(*e).stash.flags |= env_flags::PRELOAD_STAGING;",
            "(*e).stash.flags |= env_flags::AUDIT_STAGING;",
            "(*e).stash.flags |= env_flags::PRELOAD_RELATIVE;",
            "(*e).stash.flags |= env_flags::LOADER_CUT;",
        ],
    );
    // judged after each variable, by the first pass and the post-commit one
    assert!(body(&pol, "nn_env_pending")
        .contains("nn_env_judge(nn_env_var(ptr, tid, start, 0), ptr, tid, start, 0);"));
    assert!(body(&pol, "nn_env_region_round")
        .contains("nn_env_judge(nn_env_var(p, 0, 0, 1), p, 0, 0, 1);"));
    assert!(body(&pol, "env_scan").contains("let f = nn_env_resolve(0, tid, start) as u32;"));
    assert!(body(&pol, "nn_env_region").contains("nn_env_resolve(1, 0, 0)"));
    assert!(body(&pol, "nn_env_resolve").contains("resolve_bare(e);"));
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
            "let refuse = m == mode::ENFORCE && deny_c != 0;",
            "bump(counter::LOST);",
            "bump(counter::LOST_OPEN);",
            "report_unwalked(",
            "crate::execq::forget(task);",
        ],
    );
    assert!(body(&pol, "report_unwalked").contains("(*raw).action = act;"));
    // The re-check of #547 (G6): the environment is judged by its own LSM
    // program on the same hook, into its own entry whether or not this walk
    // could be made — not by the ladder, nor read by `exec_check_lsm` for it
    let lsm = code("agent-ebpf/src/exec_lsm.rs");
    assert!(
        !lsm.contains("env_for_unwalked"),
        "the ladder's environment is back"
    );
    assert!(!pol.contains("fn env_for_unwalked("));
    in_order(
        body(&lsm, "try_exec_check_lsm"),
        &[
            "crate::execpol::nn_exec_unwalked(",
            "u64::from(flags) | (u64::from(pass) << 32),",
            ");",
        ],
    );
    for not in ["nn_exec_env(", "env_flags::", "EXECPOL_ENV_SEEN"] {
        assert!(!u.contains(not), "the ladder judges the environment: {not}");
    }
    assert!(u.contains("let mut act = action::UNWALKED | action::RECORD;"));
    // The review of #547 (F5): an environment the flood left unread is not
    // refused at the first pass (both maps full, every service exec was
    // refused): it is noted for the post-commit check, which reads the
    // kernel's copy in a per-CPU buffer the flood cannot take and kills a
    // protected or set-id target on what it cannot clear.
    in_order(
        body(&pol, "try_exec_env_lsm"),
        &[
            "let er = nn_exec_env(task, u64::from(wk.tid), wk.start_ns);",
            "let unfinished = ef & env_flags::FIRST_PASS_FAIL_CLOSED != 0 && (env_deny_rule || setid);",
            "if ef & (env_flags::DENYABLE | env_flags::UNJUDGED) != 0 && env_act & action::DENY == 0 {",
            "EXECPOL_ENV_SEEN.insert(&task, &ef, 0);",
            "crate::execq::forget(task);",
            "return -EACCES;",
        ],
    );
    assert!(body(&pol, "exec_env").contains("return u64::from(env_flags::UNREADABLE);"));
    assert!(flat(&pol).contains(
        "static COMMIT_ENV: PerCpuArray<EnvScan> = PerCpuArray::with_max_entries(1, 0);"
    ));
    assert!(body(&pol, "env_commit")
        .contains("let kill = (staging_new != 0 && rule) || (unjudged != 0 && (rule || setid));"));
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
            "crate::execq::forget_freed(task);",
            "crate::execpol::forget_freed(task);",
        ],
    );
    assert!(ts.contains("#[lsm(hook = \"task_free\")]\npub fn nn_task_free("));
    // The review of #547 (F4): a failed exec's candidate goes when the
    // kernel frees the exec's file (it stayed until the task's next exec or
    // its end: one user's idle threads filled the map), attached with the
    // quarantine
    let qc = code("agent-ebpf/src/execq.rs");
    assert!(qc.contains("#[lsm(hook = \"file_free_security\")]\npub fn execq_exec_failed("));
    in_order(
        body(&qc, "execq_exec_failed"),
        &[
            "let inode = match EXECQ_CAND.get(&task) {",
            "Some(c) => c.inode,",
            "peek_u64(file.add(off!(FILE_F_INODE_OFFSET))) == inode",
            "cand_remove(task);",
        ],
    );
    assert!(body(&qc, "note_pass").contains("(*cand).inode = inode as u64;"));
    let em = code("agent/src/execq/mod.rs");
    assert!(em.contains("pub const FAILED_EXEC_PROGRAM: &str = \"execq_exec_failed\";"));
    assert!(body(&em, "install").contains(
        "antitamper_bpf::attach_transient(ebpf, FAILED_EXEC_PROGRAM, \"file_free_security\", &btf)"
    ));
    // a dropped candidate ran unheld: counted with the not-held, signed
    let ctl = code("agent/src/execq/controller.rs");
    in_order(
        body(&ctl, "step"),
        &[
            "+ c[counter::CAND_DROPPED as usize]",
            "+ c[counter::CAND_EVICTED as usize],",
            "self.report_fail_open(",
            "c[counter::CAND_DROPPED as usize],",
            "c[counter::CAND_EVICTED as usize],",
            "self.k.recount_shares();",
        ],
    );
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
            "match task_buffer(task) {",
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
            "match task_buffer(task) {",
            "crate::fim_watch::observe_open_plain(file);",
            "on_open_in(file, t, task, live);",
            "if !live {",
            "let _ = OPEN_TASK_RUN.remove(&task);",
        ],
    );
    assert!(
        !o.contains("OPEN_TASK.remove("),
        "the task's entry removed per open:\n{o}"
    );
    // The task's entry while `task_free` runs, within its uid's share (the
    // review of #547, F6); else the run's own, removed at its end — the open
    // still judged whole, counted; with no room anywhere, the plain
    // observer, counted.
    in_order(
        body(&open, "task_buffer"),
        &[
            "if let Some(p) = OPEN_TASK.get_ptr_mut(&task) {",
            "return Some((p, true));",
            "if let Some(p) = OPEN_TASK_RUN.get_ptr_mut(&task) {",
            "return Some((p, false));",
            "if crate::task_scratch::task_free_armed() {",
            "if nn_open_task_make(task) != 0 {",
            "if let Some(p) = OPEN_TASK.get_ptr_mut(&task) {",
            "return Some((p, true));",
            "open_task_bump(OPEN_TASK_PER_CALL);",
            "match crate::task_scratch::make(&OPEN_TASK_RUN, &task) {",
            "Some(p) => Some((p, false)),",
            "open_task_bump(OPEN_TASK_LOST);",
        ],
    );
    assert!(body(&open, "forget_task").contains("let _ = OPEN_TASK_RUN.remove(&task);"));
    in_order(
        body(&open, "forget_freed"),
        &[
            "OPEN_TASK.remove(&task).is_ok()",
            "crate::task_scratch::share_give(&OPEN_TASK_UIDS, &OPEN_TASK_OVERFLOW, uid);",
        ],
    );
    // The re-check of #547 (G5): the share is the account's (lot 332: its
    // uid, or its user namespaces' creator — a rootless container's subuids
    // are its user's); a share the rows' map has no room for is the
    // overflow row's, under the same cap; lot 332: under the global cap
    in_order(
        body(&open, "nn_open_task_make"),
        &[
            "crate::task_scratch::share_take(",
            "&OPEN_TASK_UIDS,",
            "&OPEN_TASK_OVERFLOW,",
            "crate::task_scratch::share_key(),",
            "OPEN_TASK_PER_SHARE,",
            "OPEN_TASK_GLOBAL,",
            "OPEN_TASK_FLOOR,",
            "None => return 0,",
            "crate::task_scratch::make(&OPEN_TASK, &task)",
            "(*p).uid = row",
            "crate::task_scratch::share_give(&OPEN_TASK_UIDS, &OPEN_TASK_OVERFLOW, row);",
        ],
    );
    let ts = code("agent-ebpf/src/task_scratch.rs");
    // Lot 332 (the re-check 2 of #547, G5): the key is the kernel's — the
    // uid, or the creator of the outermost user namespace (its inode when
    // root made it) — never the login uid, which a task without one sets
    // to anything; one global function walks the namespaces
    assert!(body(&ts, "share_key").contains("nn_share_key() as u32"));
    in_order(
        body(&ts, "nn_share_key"),
        &[
            "let uid = current_uid();",
            "outer_user_ns()",
            "northnarrow_common::wire::execq::share_key(uid, level, owner, inum)",
        ],
    );
    in_order(
        body(&ts, "outer_user_ns"),
        &[
            "off_opt!(TASK_STRUCT_CRED_OFFSET)",
            "off_opt!(CRED_USER_NS_OFFSET)",
            "off_opt!(USER_NAMESPACE_LEVEL_OFFSET)",
            "let cred = peek_u64(task.add(o_cred)) as *const u8;",
            "let mut ns = peek_u64(cred.add(o_ns)) as *const u8;",
            "let level = peek_u32(ns.add(o_level));",
            "if level == 0 {",
            "return (0, 0, 0);",
            "off_opt!(USER_NAMESPACE_PARENT_OFFSET)",
            "while i < USERNS_MAX_LEVEL && l > 1 {",
            "ns = peek_u64(ns.add(o_parent)) as *const u8;",
            "l = peek_u32(ns.add(o_level));",
            "if l != 1 {",
            "return (0, 0, 0);",
            "off_opt!(USER_NAMESPACE_OWNER_OFFSET)",
            "off_opt!(USER_NAMESPACE_INUM_OFFSET)",
            "(level, peek_u32(ns.add(o_owner)), peek_u32(ns.add(o_inum)))",
        ],
    );
    assert!(
        !ts.contains("LOGINUID"),
        "the login uid keys no share (a task without one sets it to anything)"
    );
    in_order(
        body(&ts, "share_take"),
        &[
            "let total = overflow.get_ptr_mut(TOTAL_ROW)?;",
            "Some(n) => (n, key),",
            "let _ = rows.insert(&key, &0u64, BPF_NOEXIST);",
            "match rows.get_ptr_mut(&key) {",
            "Some(n) => (n, key),",
            "None => (overflow.get_ptr_mut(OVERFLOW_ROW)?, OVERFLOW_SHARE),",
            "if !share_admits(*n, *total, cap, global, floor) {",
            "return None;",
            "*n += 1;",
            "*total += 1;",
            "Some(row)",
        ],
    );
    in_order(
        body(&ts, "share_give"),
        &[
            "overflow.get_ptr_mut(OVERFLOW_ROW)",
            "rows.get_ptr_mut(&row)",
            "if *n > 0 {",
            "*n -= 1;",
            "overflow.get_ptr_mut(TOTAL_ROW)",
            "if *t > 0 {",
            "*t -= 1;",
        ],
    );
    // the mini-hunt: the mass-write window of a writer in the root cgroup
    // is its uid's, not its login uid's either
    let cg = flat(body(&open, "count_cgroup"));
    assert!(cg.contains("uid: (bpf_get_current_uid_gid() & 0xFFFF_FFFF) as u32, loginuid: 0,"));
    assert!(!cg.contains("loginuid()"), "{cg}");
    let wq = flat(&code("common/src/wire/execq.rs"));
    assert!(
        wq.contains("let k = if level == 0 { uid } else if owner != 0 { owner } else { inum };")
    );
    assert!(wq.contains("own < per_share && (total < global || own < floor)"));
    assert!(wq.contains("capacity - per_share"));
    assert!(wq.contains("per_share / 64"));
    // the opens judged in a run's own buffer reach `nn-admin status`, and
    // the uids' shares are recounted from the entries
    let os = code("crates/nn-linux/src/sensors/open_sensor.rs");
    assert!(os.contains("take(ebpf, \"OPEN_TASK_COUNTERS\")"));
    assert!(body(&os, "recount_shares").contains("rewrite_shares(&mut self.task_uids, &want)"));
    // lot 332: the recount rewrites the global cap's total with the rows,
    // both maps
    let kq = code("agent/src/execq/kernel.rs");
    for b in [body(&os, "recount_shares"), body(&kq, "recount_shares")] {
        in_order(
            b,
            &[
                "let total = ",
                "total_of(&want);",
                "(common::wire::execq::OVERFLOW_ROW, overflow),",
                "(common::wire::execq::TOTAL_ROW, total),",
                ".set(row, n, 0).is_err()",
            ],
        );
    }
    let st = code("agent/src/admin/handlers/status.rs");
    assert!(st.contains(
        "open_sensor_per_call_total: Some(nn_linux::sensors::open_sensor::per_call_total()),"
    ));
    assert!(body(&os, "sample").contains("let _ = maps.per_call_total();"));
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
    // the review of #547 (F9): "attached", not "loaded" — a load whose
    // attach failed is attached again by the next caller
    in_order(
        body(&tf, "ensure"),
        &[
            "if attached() {",
            "return Ok(false);",
            "let loaded = ebpf.program(PROGRAM).is_some_and(|p| p.fd().is_ok());",
            "prog.attach().context(\"attaching task_free\")?;",
            "antitamper_bpf::attach_transient(ebpf, PROGRAM, HOOK, btf)?;",
            "arr.set(0, 1, 0)",
            "ATTACHED.store(true, std::sync::atomic::Ordering::Release);",
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
    // The review of #547 (F2): what the kernel's copy shows that the first
    // pass did not see, and what this read cannot clear (a value longer
    // than the scan reads, past this read's bound, a relative path, an
    // unreadable string), is never silent: a protected or set-id target is
    // killed (only when the signal went: F9), anything else recorded and
    // counted. It acted on new staging entries only.
    in_order(
        body(&pol, "env_commit"),
        &[
            "off_opt!(MM_STRUCT_ENV_START_OFFSET)",
            "off_opt!(MM_STRUCT_ENV_END_OFFSET)",
            "EXECPOL_ENV_SEEN.get(&tk)",
            "COMMIT_ENV.get_ptr_mut(0)",
            "bump(counter::ENV_UNREAD);",
            "nn_env_region(start, end) as u32",
            "let staging_new = f & env_flags::DENYABLE & !seen;",
            "let unjudged = f & env_flags::UNJUDGED;",
            "if staging_new == 0 && unjudged == 0 {",
            "let tv = nn_execpol_tier(tk) as u32;",
            "let setid = exe_mode(mm) & 0o6000 != 0;",
            "let kill = (staging_new != 0 && rule) || (unjudged != 0 && (rule || setid));",
            "if !kill && staging_new == 0 && unjudged & !seen == 0 {",
            "bump(counter::ENV_CHANGED);",
            "bump(counter::ENV_TRUNCATED);",
            "bump(counter::ENV_UNREAD);",
            "let mut env_act = action::RECORD;",
            "if conf(conf_slot::MODE) == mode::ENFORCE {",
            "if generated::bpf_send_signal(SIGKILL) == 0 {",
            "env_act |= action::DENY | action::KILLED;",
            "env_act |= action::WOULD_DENY;",
            "report_commit(task, mm, tv, f | changed, env_act, &(*e).stash);",
        ],
    );
    // the first pass notes what it let through, and forgets a failed
    // exec's note at the next exec
    let p = body(&pol, "try_exec_env_lsm");
    in_order(
        p,
        &[
            "let _ = EXECPOL_ENV_SEEN.remove(&task);",
            "nn_exec_env(task, u64::from(wk.tid), wk.start_ns)",
            "if ef & (env_flags::DENYABLE | env_flags::UNJUDGED) != 0 && env_act & action::DENY == 0 {",
            "EXECPOL_ENV_SEEN.insert(&task, &ef, 0);",
        ],
    );
    // The region is read string after string in the CPU's entry, at most
    // `ENV_COMMIT_ROUNDS` rounds (the review of #547, F8: with preemption
    // off); past them, not finished. The judged names read whole.
    in_order(
        body(&pol, "nn_env_region"),
        &[
            "while round < ENV_COMMIT_ROUNDS {",
            "nn_env_region_round(pos, end, at)",
            "(*e).stash.flags |= env_flags::UNREADABLE;",
            "if !done {",
            "(*e).stash.flags |= env_flags::TRUNCATED;",
        ],
    );
    in_order(
        body(&pol, "nn_env_region_round"),
        &[
            "while j < ROUND_CALLS {",
            "nn_env_region_step(p, end, a)",
            "if !judged_one_more(1, 0, 0) {",
            "nn_env_judge(nn_env_var(p, 0, 0, 1), p, 0, 0, 1);",
        ],
    );
    let rs = body(&pol, "nn_env_region_step");
    in_order(
        rs,
        &[
            "bpf_probe_read_user_str(",
            "REGION_READ as u32,",
            "if a != 0 {",
            "env_name_wanted(",
            "return p | (AT_START << AT_SHIFT) | JUDGE;",
        ],
    );
    assert!(
        !rs.contains("nn_env_var("),
        "a region step calls down:\n{rs}"
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

/// The re-check of #547 (G6): the environment's check is a program of its
/// own on `bprm_check_security` (`exec_env_lsm`), with its own verifier
/// budget — with the scan inside `exec_check_lsm`, 5.15 counted 930,372 of
/// its 1,000,000 instructions. `exec_check_lsm` no longer reads the
/// environment; the policy attaches the program after the exec sensor's
/// (BPF-LSM runs a hook's programs in turn; the first refusal refuses).
#[test]
fn the_environment_has_its_own_program() {
    let pol = code("agent-ebpf/src/execpol.rs");
    assert!(pol.contains("#[lsm(hook = \"bprm_check_security\")]\npub fn exec_env_lsm("));
    in_order(
        body(&pol, "try_exec_env_lsm"),
        &[
            "if m == mode::OFF || conf(conf_slot::FLAGS) & flags::ENV_SCAN == 0 {",
            // pass 0 only: the file the caller named
            "if peek_u64(bprm.add(o_interp)) != peek_u64(bprm.add(o_filename)) {",
            "let er = nn_exec_env(task, u64::from(wk.tid), wk.start_ns);",
            "nn_env_report(",
            "(u64::from(env_act) << 32) | u64::from(mode_bits),",
            "return -EACCES;",
        ],
    );
    // recorded whenever the judgment acts (refuses, would, records)
    assert!(flat(body(&pol, "try_exec_env_lsm")).contains("if env_act != 0 { nn_env_report("));
    // the record, its path walked, checked once (a global function)
    assert!(flat(&pol).contains("#[no_mangle] #[inline(never)] pub extern \"C\" fn nn_env_report("));
    assert!(body(&pol, "nn_env_report").contains("report_env_pass("));
    let op = body(&pol, "on_pass");
    for not in ["nn_exec_env(", "env_deny_rule", "EXECPOL_ENV_SEEN"] {
        assert!(
            !op.contains(not),
            "exec_check_lsm judges the environment again: {not}"
        );
    }
    assert!(
        op.contains("report_exec(s, inode, t_ptr, t | sig, classes, act, 0, 0, None, mode_bits);")
    );
    let m = code("agent/src/execpol/mod.rs");
    assert!(m.contains("pub const ENV_PROGRAM: &str = \"exec_env_lsm\";"));
    in_order(
        body(&m, "attach_env_lsm"),
        &["prog.load(\"bprm_check_security\", &btf)", "prog.attach()"],
    );
    in_order(
        body(&m, "install"),
        &[
            "if !offsets_resolved(&ENV_OFFSETS) {",
            "} else if let Err(e) = attach_env_lsm(ebpf) {",
            "env_ok = true;",
            "attach_commit(ebpf)",
        ],
    );
}
