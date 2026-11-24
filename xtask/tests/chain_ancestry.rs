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
//! #561, F4) — and inside the store only the fork-record entries reach it.
//! The re-check of #561 (N2): nor the raw edge under another name — the
//! forker's hop (`observe_fork_hop`) is named by the two entries only, so a
//! store wrapper over it is refused like one over `observe_spawn`; and the
//! entries themselves are named by `observe_lineage` only, so
//! `observe_exec(pid, ppid, start, 0, 0, 0)` elsewhere (the parent at exec,
//! no fork record) is refused too. `observe_spawn` is `pub(crate)`: no other
//! crate can name it at all.

mod support;

use support::{product_code, repo_root};

/// The store: `observe_spawn` is its own primitive.
const STORE: &str = "crates/nn-core/src/decision/correlation/store.rs";

/// The chain rules: `observe_lineage` feeds the tree.
const CHAIN: &str = "crates/nn-core/src/decision/rules/chain.rs";

/// A file, and the functions of it whose production code may name an edge.
type Allowed = (&'static str, &'static [&'static str]);

/// Each name of the tree's edges, and the only functions (by file) whose
/// production code may name it.
const WHERE: &[(&str, &[Allowed])] = &[
    // the raw edge: its definition and the fork-record entries
    (
        "observe_spawn",
        &[(
            STORE,
            &[
                "observe_spawn",
                "observe_exec",
                "observe_fork",
                "observe_fork_hop",
            ],
        )],
    ),
    // the forker's hop, the raw edge under another name (the re-check of
    // #561, N2): its definition and the entries
    (
        "observe_fork_hop",
        &[(STORE, &["observe_fork_hop", "observe_exec", "observe_fork"])],
    ),
    // the entries: their definitions, and the chain rules' observe_lineage
    // (N2: `observe_exec(c, p, s, 0, 0, 0)` elsewhere is the raw edge)
    (
        "observe_exec",
        &[(STORE, &["observe_exec"]), (CHAIN, &["observe_lineage"])],
    ),
    (
        "observe_fork",
        &[(STORE, &["observe_fork"]), (CHAIN, &["observe_lineage"])],
    ),
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

/// The names of the tree's edges the production code of `rel` uses where it
/// may not ([`WHERE`]).
fn misplaced_edges(rel: &str, code: &str) -> Vec<&'static str> {
    WHERE
        .iter()
        .filter(|(ident, allowed)| {
            let fns: &[&str] = allowed
                .iter()
                .find(|(file, _)| *file == rel)
                .map_or(&[], |(_, fns)| fns);
            ident_uses(code, ident)
                .into_iter()
                .any(|at| !enclosing_fn(code, at).is_some_and(|f| fns.contains(&f)))
        })
        .map(|(ident, _)| *ident)
        .collect()
}

/// Whether the production code of `rel` names one of the tree's edges where
/// it may not.
fn names_the_raw_edge(rel: &str, code: &str) -> bool {
    !misplaced_edges(rel, code).is_empty()
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
        "fn f() { s.observe_spawned(); my_observe_spawn(); s.observe_execs(); }"
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

/// The re-check of #561, N2: a store wrapper over the forker's hop, and the
/// fork-record entries named outside `observe_lineage` (an entry without
/// its record is the raw parent-at-exec edge), are refused; the entries and
/// the hop where they are, are not.
#[test]
fn the_ratchet_sees_a_hop_wrapper_and_an_entry_outside_observe_lineage() {
    assert_eq!(
        misplaced_edges(
            STORE,
            "fn observe_fork_hop(&mut self) { self.observe_spawn(1, 2, 3); }\n\
             pub fn enter_edge(&mut self, c: u32, p: u32, s: u64) { self.observe_fork_hop(c, s, p) }"
        ),
        ["observe_fork_hop"]
    );
    assert_eq!(
        misplaced_edges(
            STORE,
            "pub fn enter(&mut self) { self.observe_exec(1, 2, 3, 0, 0, 0); }"
        ),
        ["observe_exec"]
    );
    let other = "crates/nn-core/src/decision/rules/net_fanout.rs";
    assert_eq!(
        misplaced_edges(
            other,
            "fn probe(s: &mut S) { s.observe_exec(1, 2, 3, 0, 0, 0); }"
        ),
        ["observe_exec"]
    );
    assert_eq!(
        misplaced_edges(
            other,
            "fn probe(s: &mut S) { s.observe_fork(1, 2, 3, 4, 5); }"
        ),
        ["observe_fork"]
    );
    assert_eq!(
        misplaced_edges(
            CHAIN,
            "fn evaluate(&self) { store.observe_exec(1, 2, 3, 0, 0, 0); }"
        ),
        ["observe_exec"]
    );
    assert!(
        misplaced_edges(
            CHAIN,
            "fn observe_lineage<H>(store: &mut S) { store.observe_exec(1, 2, 3, 4, 5, 6); \
         store.observe_fork(1, 2, 3, 4, 5); }"
        )
        .is_empty()
    );
    assert!(misplaced_edges(
        STORE,
        "pub fn observe_exec(&mut self) { self.observe_fork_hop(1, 2, 3); self.observe_spawn(1, 2, 3); }\n\
         pub fn observe_fork(&mut self) { self.observe_fork_hop(1, 2, 3); self.observe_spawn(1, 2, 3); }\n\
         fn observe_fork_hop(&mut self) { self.observe_spawn(1, 2, 3); }"
    )
    .is_empty());
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
         fork record) or observe_fork_hop, by a call or a function path, from a store \
         function other than the fork-record entries, or names observe_exec / observe_fork \
         outside chain.rs's observe_lineage: route the event through observe_lineage — \
         {offenders:?}"
    );
    // and the chain rules route both kinds of event through it
    let chain = &code[CHAIN];
    assert!(
        chain.contains("fn observe_lineage<"),
        "observe_lineage is gone"
    );
    assert!(chain.contains("store.observe_exec(") && chain.contains("store.observe_fork("));
    assert!(chain.contains("Event::TcpConnect { .. } => {\n                observe_lineage("));
}

/// The re-check of #561 (lot 352), N1: the chains tag a credential read and
/// a canary trip with the start of the process that made it; an open's
/// record is where that start comes from (`FimDriftRaw::modifier_start`,
/// carried to `FimEvent::modifier_start` and the trip's
/// `accessor_start_ns`). The kernel half fills it for every open it reports.
#[test]
fn an_open_s_record_carries_its_reader_s_start() {
    let fim = support::strip_comments(
        &std::fs::read_to_string(repo_root().join("agent-ebpf/src/fim_watch.rs")).unwrap(),
    );
    let flat: String = fim.split_whitespace().collect::<Vec<_>>().join(" ");
    assert!(
        flat.contains(
            "pub(crate) fn emit_drift_opened(key: InodeKey) { \
             emit_drift_raw(FIM_OP_OPENED, key, NO_DEST, 0, false, true); }"
        ),
        "an open's record no longer asks for its reader's start"
    );
    assert!(
        flat.contains(
            "if own_start { (*raw_ptr).modifier_start = crate::fork_parent::current_start(); }"
        ),
        "the record no longer carries the start it is asked for"
    );
    let chain = &product_code(&repo_root())[CHAIN];
    assert!(chain.contains("fe.modifier_start,") && chain.contains("*accessor_start_ns,"));
}
