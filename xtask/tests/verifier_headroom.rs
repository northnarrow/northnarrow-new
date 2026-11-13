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
                "#[no_mangle] #[inline(never)] pub extern \"C\" fn {g}("
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
    assert!(class
        .contains("let cls = dir_class(&pkey, parent as *const u8, parent_inode as *const u8);"));
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

/// 2. Every global function of the eBPF object: `u64` arguments, a `u64`
///    back.
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
                .all(|a| a.ends_with(": u64"))
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
        "global functions with other than u64:\n{}",
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
    assert!(flat(&ts)
        .contains("#[no_mangle] #[inline(never)] pub extern \"C\" fn nn_share_key() -> u64 {"));
}
