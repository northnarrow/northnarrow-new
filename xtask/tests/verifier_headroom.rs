//! Lot 332 — the verifier's headroom of every eBPF program, on every kernel.
//!
//! Alpha testers run kernels the lab has never seen (RHEL and Alma 5.14,
//! Fedora, Arch, older 5.15 builds). The kernel's verifier processes at most
//! a million instructions to accept one program, and a program near that on
//! the lab's kernels can be refused on another: the agent then runs without
//! it. `fim_file_open_sensor` was at 821,228 on 5.15 (82%), 765k of them in
//! the program's own body: the sensor proper, inline, was verified again
//! for every state the FIM watch before it left.
//!
//! What holds it, checked here on the sources (the counts themselves are
//! the lab's: `verifier-check` fails a kernel on which a program the agent
//! needs processed more than 900,000, or could not be measured, and the
//! nightly runs it on every guest — `lab_ci.rs`):
//!
//! 1. The FIM sensor's work past the watch is global functions, each
//!    verified once: the directory's class, the write count, the rest of
//!    the sensor. `observe` is reached only through `nn_open_observe`.
//! 2. Every global function of the object takes and returns plain `u64`s:
//!    5.15 refuses a BTF pointer passed to one ("Caller passes invalid
//!    args"), and a pointer argument is memory there, never a map key.
//! 3. The shares' key walks a task's user namespaces with branch-free reads:
//!    a branch per read multiplied the walk's states past the million on
//!    5.15 (this lot's first object), and its frame stays small — it ends
//!    the sensor's deepest call chain, whose stack is held to 512 bytes.
//! 4. Lot 370 (the lab on 5.15): the module files' write history steps in
//!    plain values. An `Option` built in the program (the transaction of
//!    the write, the inode's history) leaves its payload's stack slots
//!    unwritten on the `None` path, and the compiler read them before the
//!    test: 5.15's verifier refused the observer ("invalid read from
//!    stack"; 7.0's accepted it), and 5.15 had no write history. The
//!    write's transaction is the package manager holding its lock at the
//!    write, read in the kernel (`MODULE_PKG_LOCKERS`).
//! 5. Lot 1.3 (plan S1, F6): the stack gate, on the built object without a
//!    kernel — every program's deepest call chain, its frames rounded up
//!    to 32 bytes as the verifier adds them, at most 448 of the verifier's
//!    512 (`fim_rename_observe` was at 512), save the debt
//!    `crates/nn-linux/src/verifier_headroom.rs` lists, each held to its
//!    own chain; a debt's program brought under the gate leaves the list.
//!    The lab's `verifier-check` reads the same chains back from the
//!    kernel's translated image and fails a kernel on them too.

mod support;

use std::fs;

use support::{repo_root, rs_files, strip_comments};

fn code(rel: &str) -> String {
    strip_comments(
        &fs::read_to_string(repo_root().join(rel)).unwrap_or_else(|e| panic!("{rel}: {e}")),
    )
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

fn flat(s: &str) -> String {
    s.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// 1. The FIM sensor's work past the watch: three global functions, called
///    in turn from `on_open_in` (none nested in another: the call chain's
///    stack is the verifier's 512 bytes), the class first; `observe` only
///    from the last; the count before the rest, as it was inline.
#[test]
fn the_fim_sensor_past_the_watch_is_global_functions() {
    let open = code("agent-ebpf/src/open_sensor.rs");
    in_order(
        body(&open, "on_open_in"),
        &[
            "crate::fim_watch::WATCHED_PATHS.get(&key).is_some()",
            // lot 344: the open's drift carries no fork record (the open
            // hooks are the longest programs the verifier walks)
            "crate::fim_watch::emit_drift_opened(key);",
            "if !armed() {",
            "if dentry.is_null() {",
            "let parent = read_ptr(dentry.add(off!(DENTRY_D_PARENT_OFFSET)));",
            "if parent.is_null() || parent == dentry {",
            "let parent_inode = read_ptr(parent.add(off!(DENTRY_D_INODE_OFFSET)));",
            "if parent_inode.is_null() {",
            "Err(_) => return,",
            "let cls = nn_open_class(key.dev, pino, parent as u64, parent_inode as u64);",
            "core::ptr::write_volatile(stash.add(STASH_CLASS), cls);",
            "core::ptr::write_volatile(stash.add(STASH_PARENT), parent as u64);",
            "core::ptr::write_volatile(stash.add(STASH_PINO), pino);",
            "if mode & FMODE_WRITE != 0 && regular {",
            "nn_open_count_write(",
            "cls,",
            "nn_open_observe(task, dev_bits, key.ino, dentry as u64,",
        ],
    );
    let f = flat(&open);
    for g in [
        "nn_open_class",
        "nn_open_observe",
        "nn_open_count_write",
        "nn_open_walk",
        "nn_open_emit",
    ] {
        assert!(
            f.contains(&format!(
                "#[unsafe(no_mangle)] #[inline(never)] pub extern \"C\" fn {g}("
            )),
            "{g} is a global function"
        );
    }
    // `observe` (and `dir_class`, the walk's caller) only inside them
    let bare: Vec<usize> = open
        .match_indices("observe(")
        .map(|(i, _)| i)
        .filter(|i| !open[..*i].ends_with(|c: char| c.is_alphanumeric() || c == '_'))
        .collect();
    assert_eq!(bare.len(), 2, "`observe` defined once and called once");
    let (defs, calls): (Vec<usize>, Vec<usize>) = bare
        .into_iter()
        .partition(|i| open[..*i].ends_with("unsafe fn "));
    assert_eq!((defs.len(), calls.len()), (1, 1));
    let obs = open.find("fn nn_open_observe(").unwrap();
    let end = obs + open[obs..].find('{').unwrap() + body(&open, "nn_open_observe").len();
    assert!(
        calls[0] > obs && calls[0] < end,
        "`observe` called from nn_open_observe only"
    );
    assert!(!body(&open, "on_open_in").contains("dir_class("));
    assert!(!body(&open, "observe").contains("nn_open_count_write("));
    // the class is computed without the task's buffer; the class, the
    // parent and its inode go to the last through the buffer, written
    // before they are read
    let class = body(&open, "nn_open_class");
    assert!(
        class.contains(
            "let cls = dir_class(&pkey, parent as *const u8, parent_inode as *const u8);"
        )
    );
    assert!(
        !class.contains("buffer_of(") && !class.contains("OPEN_TASK"),
        "{class}"
    );
    in_order(
        body(&open, "nn_open_observe"),
        &[
            "buffer_of(task, dev_bits)",
            "core::ptr::read_volatile(w.add(STASH_CLASS)) as u32,",
            "core::ptr::read_volatile(w.add(STASH_PARENT)) as *const u8,",
            "core::ptr::read_volatile(w.add(STASH_PINO)),",
            "(*t).names.as_mut_ptr(),",
        ],
    );
}

/// 2. Every global function of the eBPF object: `u64` arguments, each
///    used, a `u64` back.
#[test]
fn every_global_function_takes_and_returns_plain_values() {
    let mut files = Vec::new();
    rs_files(&repo_root().join("agent-ebpf/src"), &mut files);
    let mut seen = 0;
    let mut bad = Vec::new();
    for p in files {
        let src = flat(&code(
            p.strip_prefix(repo_root()).unwrap().to_str().unwrap(),
        ));
        let mut rest = src.as_str();
        while let Some(i) = rest.find("pub extern \"C\" fn ") {
            let sig_start = i + "pub extern \"C\" fn ".len();
            let sig_end = sig_start + rest[sig_start..].find('{').expect("a body");
            let sig = rest[sig_start..sig_end].trim();
            seen += 1;
            let (name, tail) = sig.split_once('(').expect("a parameter list");
            let (params, ret) = tail.rsplit_once(')').expect("a parameter list");
            let plain = params
                .split(',')
                .map(str::trim)
                .filter(|a| !a.is_empty())
                // an unused argument (`_x: u64`) is a register the caller
                // never sets (the review of #618): none, rather
                .all(|a| a.ends_with(": u64") && !a.starts_with('_'))
                && ret.trim() == "-> u64";
            if !plain {
                bad.push(format!("{}: {name}({params}){ret}", p.display()));
            }
            rest = &rest[sig_end..];
        }
    }
    assert!(seen >= 20, "{seen} global functions found");
    assert!(
        bad.is_empty(),
        "global functions with other than used u64 arguments and a u64 back:\n{}",
        bad.join("\n")
    );
}

/// 3. The shares' key: one global function, the namespaces' walk bounded
///    and its reads branch-free.
#[test]
fn the_share_key_walk_reads_without_a_branch() {
    let ts = code("agent-ebpf/src/task_scratch.rs");
    for peek in ["peek_u64", "peek_u32"] {
        let b = body(&ts, peek);
        assert!(
            b.contains("let _ = generated::bpf_probe_read_kernel("),
            "{peek}:\n{b}"
        );
        assert!(
            !b.contains("if ") && !b.contains("match "),
            "{peek} branches:\n{b}"
        );
    }
    let walk = body(&ts, "outer_user_ns");
    assert!(walk.contains("while i < USERNS_MAX_LEVEL && l > 1 {"));
    assert!(
        !walk.contains("bpf_probe_read_kernel::<"),
        "a read with a branch on its result"
    );
    assert!(flat(&ts).contains(
        "#[unsafe(no_mangle)] #[inline(never)] pub extern \"C\" fn nn_share_key() -> u64 {"
    ));
}

/// 4. The write history's step in the eBPF program: plain values, no
///    `Option` of the transaction or of the inode's history; the transaction
///    one whose package manager holds its lock at the write.
#[test]
fn the_module_write_history_steps_in_plain_values() {
    let ml = code("agent-ebpf/src/module_load.rs");
    let write = flat(body(&ml, "try_write_open"));
    in_order(
        &write,
        &[
            "Txn::NONE",
            "txn_of(hop)",
            "conf(conf_slot::LOCKS_UNOBSERVED) == 0",
            "MODULE_PKG_LOCKERS.get(&txn.tgid)",
            "None => (false, PkgLocker::default())",
            "holds_lock(entry, had, txn.start)",
            "txn = Txn::NONE",
            "MODULE_WRITES.get(&key)",
            "None => (false, ModuleWrite::default())",
            "history_step_raw(prev, had,",
        ],
    );
    assert!(!write.contains("history_step("), "{write}");
    assert!(!write.contains(".copied()"), "{write}");
    let ml_flat = flat(&ml);
    assert!(
        ml_flat.contains("unsafe fn txn_of(hop: *const u8) -> Txn {"),
        "the transaction a plain value"
    );
    assert!(!ml_flat.contains("-> Option<Txn>"));
    let lock = flat(body(&ml, "try_lock"));
    in_order(
        &lock,
        &[
            "MODULE_PKG_LOCKS.get(&key)",
            "leader_start(",
            "None => (false, PkgLocker::default())",
            "locker_step(prev, had, start, kind as u32, bit)",
            "MODULE_PKG_LOCKERS.insert(",
        ],
    );
    // the agent calls the `Option` form only in tests: the eBPF calls the plain
    let judge = code("common/src/module_judge.rs");
    let hs = flat(body(&judge, "history_step"));
    assert!(hs.contains("history_step_raw("), "{hs}");
}

/// The gate and the debt as `crates/nn-linux/src/verifier_headroom.rs` has
/// them (one source of truth, read from its text).
fn stack_gate() -> (u32, Vec<(String, u32)>) {
    let src = code("crates/nn-linux/src/verifier_headroom.rs");
    let budget = src
        .split("pub const STACK_BUDGET: u32 = ")
        .nth(1)
        .and_then(|r| r.split(';').next())
        .and_then(|n| n.trim().parse::<u32>().ok())
        .expect("STACK_BUDGET");
    let table = src
        .split("pub const STACK_DEBT: &[(&str, u32)] = &[")
        .nth(1)
        .and_then(|r| r.split("];").next())
        .expect("STACK_DEBT");
    let debt = table
        .split("(\"")
        .skip(1)
        .map(|e| {
            let (name, rest) = e.split_once("\", ").expect("an entry");
            let chain = rest
                .split(')')
                .next()
                .unwrap()
                .trim()
                .parse::<u32>()
                .unwrap();
            (name.to_string(), chain)
        })
        .collect();
    (budget, debt)
}

/// The deepest call chain of each program of the object at `path`, by the
/// rule of `crates/nn-linux/src/verifier_check.rs`'s `stack_estimate` (the
/// lab's, from the kernel's translated image): per function the deepest
/// `r10 - off` it touches, directly or through a pointer it derives from
/// `r10`; frames rounded up to 32 bytes (at least 32) and added along the
/// calls. `None`: the object is not built.
fn object_stack_chains() -> Option<Vec<(String, u32, String)>> {
    let path =
        repo_root().join("agent-ebpf/target/bpfel-unknown-none/release/northnarrow-agent-ebpf");
    let bytes = match fs::read(&path) {
        Ok(b) => b,
        Err(e) => {
            assert!(
                std::env::var_os("NN_REQUIRE_EBPF_OBJECT").is_none(),
                "NN_REQUIRE_EBPF_OBJECT is set and {} cannot be read: {e}",
                path.display()
            );
            eprintln!("skipped: no eBPF object at {} ({e})", path.display());
            return None;
        }
    };
    let mut obj = aya_obj::Object::parse(&bytes).expect("the object parses");
    let text: std::collections::HashSet<usize> = obj.functions.keys().map(|(s, _)| *s).collect();
    obj.relocate_calls(&text).expect("the calls link");
    let mut out = Vec::new();
    for (name, prog) in &obj.programs {
        let f = &obj.functions[&prog.function_key()];
        let insns: Vec<[u8; 8]> = f
            .instructions
            .iter()
            .map(|i| {
                let mut b = [0u8; 8];
                b[0] = i.code;
                b[1] = (i.src_reg() << 4) | (i.dst_reg() & 0x0f);
                b[2..4].copy_from_slice(&i.off.to_le_bytes());
                b[4..8].copy_from_slice(&i.imm.to_le_bytes());
                b
            })
            .collect();
        let (chain, path) = chain_of(
            &insns,
            &f.func_info
                .func_info
                .iter()
                .map(|fi| fi.insn_off as usize)
                .collect::<Vec<_>>(),
        );
        out.push((name.clone(), chain, path));
    }
    out.sort();
    Some(out)
}

/// The deepest chain of the linked program `insns` and its frames
/// (`frame+frame+…`). `func_starts`: the BTF's function boundaries; the
/// call targets are boundaries too.
fn chain_of(insns: &[[u8; 8]], func_starts: &[usize]) -> (u32, String) {
    let mut starts: Vec<usize> = func_starts.to_vec();
    starts.push(0);
    let mut i = 0;
    while i < insns.len() {
        let b = insns[i];
        let imm = i32::from_le_bytes([b[4], b[5], b[6], b[7]]) as i64;
        if b[0] == 0x85 && b[1] >> 4 == 1 {
            starts.push((i as i64 + imm + 1) as usize);
        }
        if b[0] == 0x18 && b[1] >> 4 == 4 {
            starts.push((i as i64 + imm + 1) as usize);
        }
        i += if b[0] == 0x18 { 2 } else { 1 };
    }
    starts.sort_unstable();
    starts.dedup();
    let func_of = |i: usize| starts.iter().rposition(|&s| s <= i).unwrap_or(0);
    let mut depth = vec![0u32; starts.len()];
    let mut calls: Vec<Vec<usize>> = vec![Vec::new(); starts.len()];
    let mut from_fp = [false; 11];
    let mut i = 0;
    while i < insns.len() {
        if starts.binary_search(&i).is_ok() {
            from_fp = [false; 11];
        }
        let b = insns[i];
        let code = b[0];
        let dst = (b[1] & 0x0f) as usize;
        let src = (b[1] >> 4) as usize;
        let off = i16::from_le_bytes([b[2], b[3]]) as i64;
        let imm = i32::from_le_bytes([b[4], b[5], b[6], b[7]]) as i64;
        let f = func_of(i);
        let mut deeper = |d: i64| {
            if d > 0 && d as u32 > depth[f] {
                depth[f] = d as u32;
            }
        };
        let class = code & 0x07;
        let mode = code & 0xe0;
        match class {
            0x01 => {
                if src == 10 {
                    deeper(-off);
                }
                if dst < 11 {
                    from_fp[dst] = false;
                }
            }
            0x02 | 0x03 if mode == 0x60 || mode == 0xc0 => {
                if dst == 10 {
                    deeper(-off);
                }
            }
            0x07 => {
                if dst < 11 {
                    if code == 0x07 && from_fp[dst] {
                        deeper(-imm);
                    } else {
                        from_fp[dst] = code == 0xbf && (src == 10 || (src < 11 && from_fp[src]));
                    }
                }
            }
            0x04 => {
                if dst < 11 {
                    from_fp[dst] = false;
                }
            }
            0x05 if code == 0x85 => {
                if src == 1 {
                    let t = (i as i64 + imm + 1) as usize;
                    if let Ok(t) = starts.binary_search(&t) {
                        calls[f].push(t);
                    }
                }
                for r in from_fp.iter_mut().take(6) {
                    *r = false;
                }
            }
            _ => {}
        }
        if code == 0x18 {
            if src == 4 {
                if let Ok(t) = starts.binary_search(&((i as i64 + imm + 1) as usize)) {
                    calls[f].push(t);
                }
            }
            if dst < 11 {
                from_fp[dst] = false;
            }
            i += 2;
            continue;
        }
        i += 1;
    }
    fn deepest(f: usize, depth: &[u32], calls: &[Vec<usize>], level: usize) -> (u32, Vec<u32>) {
        let own = depth[f].max(1).div_ceil(32) * 32;
        let mut best = (0, Vec::new());
        if level < 16 {
            for &c in &calls[f] {
                let d = deepest(c, depth, calls, level + 1);
                if d.0 > best.0 {
                    best = d;
                }
            }
        }
        let mut frames = vec![own];
        frames.extend(best.1);
        (own + best.0, frames)
    }
    let (chain, frames) = deepest(0, &depth, &calls, 0);
    (
        chain,
        frames
            .iter()
            .map(u32::to_string)
            .collect::<Vec<_>>()
            .join("+"),
    )
}

/// 5. Lot 1.3 (plan S1, F6): no program's call chain over 448 of the
///    verifier's 512 bytes, but the debt's, each within its own; a debt
///    entry that is no longer over the gate fails too (the list goes down
///    with the object). `fim_rename_observe` was at 512, `fim_unlink_observe`
///    at 480: their FIM records are global functions now, off the chain into
///    the unlink burst.
#[test]
fn no_program_s_stack_chain_is_over_448_bytes() {
    let (budget, debt) = stack_gate();
    assert_eq!(budget, 448);
    let Some(chains) = object_stack_chains() else {
        return;
    };
    assert!(chains.len() > 90, "{} programs", chains.len());
    let mut over = Vec::new();
    for (name, chain, frames) in &chains {
        assert!(
            *chain <= 512,
            "{name}: {chain} ({frames}) — over the verifier's limit"
        );
        let allowed = debt
            .iter()
            .find(|(n, _)| n == name)
            .map_or(budget, |(_, c)| *c);
        if *chain > allowed {
            over.push(format!("{name} {chain} ({frames}), allowed {allowed}"));
        }
    }
    assert!(
        over.is_empty(),
        "stack chains over the gate:\n{}",
        over.join("\n")
    );
    for (name, c) in &debt {
        let Some((_, chain, frames)) = chains.iter().find(|(n, _, _)| n == name) else {
            panic!("the debt's {name} is no program of the object");
        };
        assert!(
            *chain > budget,
            "{name} is at {chain} ({frames}), within the gate: take it off STACK_DEBT ({c})"
        );
    }
    // the two lot 1.3 brought under it, and the fallbacks it added
    for name in [
        "fim_rename_observe",
        "fim_unlink_observe",
        "exec_check_raw",
        "file_open_raw",
    ] {
        let (_, chain, frames) = chains.iter().find(|(n, _, _)| n == name).unwrap();
        assert!(*chain <= budget, "{name}: {chain} ({frames})");
    }
}

/// The estimate's rule on a hand-made object: a frame of 24 bytes is 32, a
/// call adds the callee's, a pointer derived from `r10` counts as deep as
/// its offset.
#[test]
fn the_stack_estimate_adds_rounded_frames_along_the_calls() {
    let ins = |code: u8, dst: u8, src: u8, off: i16, imm: i32| {
        let mut b = [0u8; 8];
        b[0] = code;
        b[1] = (src << 4) | dst;
        b[2..4].copy_from_slice(&off.to_le_bytes());
        b[4..8].copy_from_slice(&imm.to_le_bytes());
        b
    };
    let prog = [
        ins(0x7b, 10, 1, -24, 0), // *(u64 *)(r10 - 24) = r1
        ins(0x85, 0, 1, 0, 2),    // call +2 (the subprogram at 4)
        ins(0xb7, 0, 0, 0, 0),    // r0 = 0
        ins(0x95, 0, 0, 0, 0),    // exit
        ins(0xbf, 2, 10, 0, 0),   // r2 = r10
        ins(0x07, 2, 0, 0, -100), // r2 += -100
        ins(0x95, 0, 0, 0, 0),    // exit
    ];
    assert_eq!(chain_of(&prog, &[]), (32 + 128, "32+128".to_string()));
    // a frame that touches nothing is 32 all the same
    assert_eq!(chain_of(&[ins(0x95, 0, 0, 0, 0)], &[]).0, 32);
}
