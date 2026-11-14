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
//! This ratchet keeps it so: no product code outside the store calls
//! `observe_spawn` (the tree's raw edge), which would enter an exec under its
//! parent at exec and skip the fork record.

mod support;

use support::{product_code, repo_root};

/// The store: `observe_spawn` is its own primitive.
const STORE: &str = "crates/nn-core/src/decision/correlation/store.rs";

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
        .filter(|(rel, text)| rel.as_str() != STORE && text.contains("observe_spawn("))
        .map(|(rel, _)| rel)
        .collect();
    assert!(
        offenders.is_empty(),
        "product code enters an ancestry edge with observe_spawn (the parent at exec, no \
         fork record): use CorrelationStore::observe_exec / observe_fork (chain.rs's \
         observe_lineage) — {offenders:?}"
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
