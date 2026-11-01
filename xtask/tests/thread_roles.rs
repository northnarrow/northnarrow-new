//! R14c (plan §3.1): each thread of the core with a role takes it, and the
//! threads that must hold the core's set get it back
//! (`crates/nn-linux/src/caps`, `docs/architecture/PROCESS_MODEL.md` §8).
//!
//! The roles are entered on the threads' first lines; a role dropped from
//! a thread leaves it with the bounding set, which no unit test of the
//! thread's own work would notice. Each site is found in the code (comments
//! stripped) and the role's call is required within its first lines.

mod support;

use std::fs;

use support::{repo_root, strip_comments};

fn source(rel: &str) -> String {
    let path = repo_root().join(rel);
    strip_comments(&fs::read_to_string(&path).unwrap_or_else(|e| panic!("{rel}: {e}")))
}

/// The text of `src` from `anchor` on, `lines` lines of it.
fn after(src: &str, rel: &str, anchor: &str, lines: usize) -> String {
    let at = src
        .find(anchor)
        .unwrap_or_else(|| panic!("{rel}: `{anchor}` not found"));
    src[at..].lines().take(lines).collect::<Vec<_>>().join("\n")
}

fn requires(rel: &str, anchor: &str, lines: usize, call: &str) {
    let src = source(rel);
    let window = after(&src, rel, anchor, lines);
    assert!(
        window.contains(call),
        "{rel}: `{call}` is not within {lines} lines of `{anchor}`:\n{window}"
    );
}

#[test]
fn every_role_s_thread_takes_its_role() {
    requires(
        "agent/src/run_loop.rs",
        ".name(\"nn-decision\"",
        14,
        "caps::enter_or_report(nn_linux::caps::Role::Decision)",
    );
    requires(
        "agent/src/pipeline/dispatch.rs",
        "fn work(s: &Shared",
        4,
        "caps::enter_or_report(nn_linux::caps::Role::Actuator)",
    );
    requires(
        "agent/src/pipeline/dispatch.rs",
        "fn watch_stalls(",
        4,
        "caps::enter_or_report(nn_linux::caps::Role::Actuator)",
    );
    requires(
        "agent/src/boot/canary.rs",
        ".name(\"nn-canary-log\"",
        6,
        "caps::enter_or_report(nn_linux::caps::Role::Writer)",
    );
    requires(
        "crates/nn-linux/src/worker/supervisor.rs",
        ".name(\"nn-workers\"",
        6,
        "caps::enter_or_report(crate::caps::Role::Supervisor)",
    );
    requires(
        "crates/nn-linux/src/caps/errands.rs",
        ".name(THREAD",
        6,
        "enter_or_report(super::Role::Errands)",
    );
}

/// The loader's window covers the multiplexer's start, and is closed
/// before anything else of the attach phase runs.
#[test]
fn the_loader_s_window_covers_the_load_only() {
    let rel = "agent/src/boot/attach.rs";
    let src = source(rel);
    let lower = src
        .find("caps::lower(nn_linux::caps::Role::Loader)")
        .expect("the loader's window");
    let start = src
        .find("SensorMultiplexer::start_with_net(")
        .expect("the multiplexer's start");
    let close = src[start..]
        .find("drop(loader);")
        .map(|i| start + i)
        .expect("the window closed");
    let next = src[start..]
        .find("boot.done(BootStep::Sensors)")
        .map(|i| start + i)
        .expect("the phase's next step");
    assert!(lower < start && start < close && close < next);
}

/// A thread that is no role's holds the core's set: the runtime's threads
/// (its start hook) and the pumps (they start inside the loader's window).
#[test]
fn the_core_s_threads_get_the_core_s_set() {
    requires(
        "agent/src/boot/mod.rs",
        "tokio::runtime::Builder::new_multi_thread()",
        6,
        ".on_thread_start(nn_linux::caps::restore_core)",
    );
    requires(
        "crates/nn-linux/src/sensors/pump.rs",
        "std::thread::Builder::new().name(name).spawn(move ||",
        5,
        "crate::caps::restore_core();",
    );
    // the errands thread before the decision thread: at the start
    let boot = source("agent/src/boot/mod.rs");
    let errands = boot
        .find("nn_linux::caps::errands::start()")
        .expect("the errands thread started");
    let attach = boot.find("attach::load(").expect("the attach phase");
    assert!(
        errands < attach,
        "the errands thread starts before the attach"
    );
}

/// What the decision's filter refuses it is its errands: the rpm query
/// and the `DEFENDER_PIDS` writes.
#[test]
fn the_decision_s_refused_calls_are_errands() {
    requires(
        "crates/nn-linux/src/decision_host_linux.rs",
        "fn rpm_owns(",
        3,
        "crate::caps::errands::run(",
    );
    let lib = source("crates/nn-linux/src/lib.rs");
    let impair = after(&lib, "lib.rs", "pub mod impair {", 45);
    assert_eq!(
        impair.matches("crate::caps::errands::run(").count(),
        2,
        "insert and remove: {impair}"
    );
    assert!(!impair.contains("pub type DefenderMap"), "{impair}");
}
