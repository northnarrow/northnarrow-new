//! Lot 352 (pre-alpha Phase 4, NN-L-CHAIN-004/005/006): the cross-PID
//! chains' ancestry tree learns the process tree in one place.
//!
//! Its edges were entered at exec only — `observe_spawn(pid, ppid, start)`
//! from each rule that saw an exec — so a process that never executed (a
//! Python `os.fork()` child, a shell's subshell, a daemon's intermediate)
//! broke every chain through it, and an orphan's exec went under its
//! reaper. Now an event's edges are entered by the store's
//! `observe_exec` / `observe_fork` (the kernel's fork record: the forker,
//! its start, the anchor), through the chain rules' `observe_lineage`.
//! This ratchet keeps it so: no product code outside the store names
//! `observe_spawn` (the tree's raw edge), which would enter an exec under its
//! parent at exec and skip the fork record — neither a call nor a function
//! path (`let f = CorrelationStore::<H>::observe_spawn; f(..)`, review of
//! #561, F4) — and inside the store only the fork-record entries reach it,
//! so a new wrapper there cannot hand it out either. `observe_spawn` is
//! `pub(crate)`: no other crate can name it at all.

mod support;

use support::{product_code, repo_root};

/// The store: `observe_spawn` is its own primitive.
const STORE: &str = "crates/nn-core/src/decision/correlation/store.rs";

/// The raw edge.
const RAW_EDGE: &str = "observe_spawn";

/// The store's functions that may reach the raw edge: its definition and
/// the fork-record entries.
const STORE_CALLERS: &[&str] = &[
    "observe_spawn",
    "observe_exec",
    "observe_fork",
    "observe_fork_hop",
];

fn is_ident(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_'
}

/// Byte offsets of `ident` in `code` as a whole identifier (a call, a path,
/// a definition), not inside a longer one.
fn ident_uses(code: &str, ident: &str) -> Vec<usize> {
    code.match_indices(ident)
        .filter(|&(at, _)| {
            let before = code[..at].chars().next_back();
            let after = code[at + ident.len()..].chars().next();
            !before.is_some_and(is_ident) && !after.is_some_and(is_ident)
        })
        .map(|(at, _)| at)
        .collect()
}

/// The name of the `fn` whose body or signature holds byte `at` (the
/// nearest `fn` keyword before it), if any.
fn enclosing_fn(code: &str, at: usize) -> Option<&str> {
    let fn_at = ident_uses(&code[..at], "fn").into_iter().last()?;
    let rest = code[fn_at + 2..].trim_start();
    let end = rest.find(|c: char| !is_ident(c)).unwrap_or(rest.len());
    Some(&rest[..end])
}

/// Whether the production code of `rel` names the raw edge where it may not.
fn names_the_raw_edge(rel: &str, code: &str) -> bool {
    let uses = ident_uses(code, RAW_EDGE);
    if rel != STORE {
        return !uses.is_empty();
    }
    uses.into_iter()
        .any(|at| !enclosing_fn(code, at).is_some_and(|f| STORE_CALLERS.contains(&f)))
}

/// Review of #561, F4: the matcher flags a call and a function path outside
/// the store, a new store function reaching the raw edge, and nothing else.
#[test]
fn the_ratchet_sees_a_call_a_path_and_a_store_wrapper() {
    let other = "crates/nn-core/src/decision/rules/net_fanout.rs";
    assert!(names_the_raw_edge(
        other,
        "fn f() { s.observe_spawn(1, 2, 3); }"
    ));
    assert!(names_the_raw_edge(
        other,
        "fn f() { let raw = CorrelationStore::<H>::observe_spawn;\n raw(s, 1, 2, 3); }"
    ));
    assert!(names_the_raw_edge(
        other,
        "fn f() { s.observe_spawn (1, 2, 3); }"
    ));
    assert!(!names_the_raw_edge(
        other,
        "fn f() { s.observe_exec(1, 2, 3, 0, 0, 0); s.observe_spawned(); my_observe_spawn(); }"
    ));
    assert!(!names_the_raw_edge(
        STORE,
        "pub(crate) fn observe_spawn(&mut self) {}\n\
         pub fn observe_exec(&mut self) { self.observe_spawn(1, 2, 3); }\n\
         fn observe_fork_hop(&mut self) { self.observe_spawn(1, 2, 3); }"
    ));
    assert!(names_the_raw_edge(
        STORE,
        "pub(crate) fn observe_spawn(&mut self) {}\n\
         pub fn enter_edge(&mut self) { self.observe_spawn(1, 2, 3); }"
    ));
    assert!(names_the_raw_edge(
        STORE,
        "const RAW: usize = observe_spawn;"
    ));
}

#[test]
fn the_ancestry_learns_edges_through_the_fork_record_only() {
    let root = repo_root();
    let code = product_code(&root);
    assert!(
        code.contains_key(STORE),
        "the store moved: update this ratchet"
    );
    let offenders: Vec<&String> = code
        .iter()
        .filter(|(rel, text)| names_the_raw_edge(rel, text))
        .map(|(rel, _)| rel)
        .collect();
    assert!(
        offenders.is_empty(),
        "product code names observe_spawn (the raw ancestry edge: the parent at exec, no \
         fork record), by a call or a function path, or a store function other than the \
         fork-record entries reaches it: use CorrelationStore::observe_exec / observe_fork \
         (chain.rs's observe_lineage) — {offenders:?}"
    );
    // and the chain rules route both kinds of event through it
    let chain = &code["crates/nn-core/src/decision/rules/chain.rs"];
    assert!(
        chain.contains("fn observe_lineage<"),
        "observe_lineage is gone"
    );
    assert!(chain.contains("store.observe_exec(") && chain.contains("store.observe_fork("));
    assert!(chain.contains("Event::TcpConnect { .. } => {\n                observe_lineage("));
}
