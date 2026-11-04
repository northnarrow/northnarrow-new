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

use support::{production, repo_root, strip_comments};

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
    // review of #482: the writer is supervised (nn_core::supervised): its
    // role is the thread's first call (`on_start`)
    requires(
        "agent/src/boot/canary.rs",
        "CANARY_WRITER_THREAD,",
        12,
        ".on_start(|| {\n                                nn_linux::caps::enter_or_report(nn_linux::caps::Role::Writer);",
    );
    requires(
        "crates/nn-linux/src/worker/supervisor.rs",
        ".name(SUPERVISOR_THREAD.to_string())",
        6,
        "caps::enter_or_report(crate::caps::Role::Supervisor)",
    );
    requires(
        "crates/nn-linux/src/caps/errands.rs",
        ".name(THREAD",
        6,
        "enter_or_report(super::Role::Errands)",
    );
    // lot 276: the export's thread holds no capability
    requires(
        "agent/src/export/controller.rs",
        ".name(THREAD.into())",
        4,
        "caps::enter_or_report(nn_linux::caps::Role::Export)",
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

/// Review of #482 (R14c-4, the reviewer's planting P5): every thread the
/// core's production code starts takes a role or the core's set within its
/// first lines (a thread inherits its creator's sets: one an actuator
/// starts would keep the actuator's), or is one of these, each with why it
/// needs neither. A new thread is one more site: listed here or given its
/// sets.
const THREADS_WITHOUT_A_CALL: &[(&str, &str, &str)] = &[
    (
        "crates/nn-linux/src/systemd_reload.rs",
        ".spawn(move || worker(rx, Path::new(socket), worker_audit))",
        "the function it runs enters the writer's role first (lot 273c)",
    ),
    (
        "agent/src/pipeline/dispatch.rs",
        ".spawn(move || watch_stalls(&watch))",
        "the function it runs enters the actuator's role first (above)",
    ),
    (
        "agent/src/pipeline/dispatch.rs",
        ".spawn(move || work(&me, &slot, spare))",
        "the function it runs enters the actuator's role first (above)",
    ),
    (
        "crates/nn-linux/src/bounded_cmd.rs",
        "thread::spawn(move || pipe.write_all(&data))",
        "a child's stdin pipe written: no capability used",
    ),
    (
        "crates/nn-linux/src/bounded_cmd.rs",
        "let _ = pipe.read_to_end(&mut buf);",
        "a child's output pipe read: no capability used",
    ),
    (
        "crates/nn-linux/src/sensor_feasibility.rs",
        "libc::SYS_renameat2,",
        "the feasibility command's own file flipper (a tool's run, no role exists)",
    ),
    (
        "crates/nn-linux/src/worker/hostile.rs",
        "std::thread::park();",
        "lot 277: the hostile worker's parked thread (debug-trigger builds), there to be found at \
         the sandbox's door — the worker has no capability to keep",
    ),
];

/// The files declared as `#[cfg(test)] mod x;` by their parent: test code.
fn test_modules(files: &[std::path::PathBuf]) -> Vec<std::path::PathBuf> {
    let mut out = Vec::new();
    for f in files {
        let text = fs::read_to_string(f).unwrap();
        let dir = if f
            .file_name()
            .is_some_and(|n| n == "mod.rs" || n == "lib.rs" || n == "main.rs")
        {
            f.parent().unwrap().to_path_buf()
        } else {
            f.with_extension("")
        };
        for (at, _) in text.match_indices("#[cfg(test)]\nmod ") {
            let rest = &text[at + "#[cfg(test)]\nmod ".len()..];
            if let Some(name) = rest.split(';').next() {
                if !name.contains(['{', '\n', ' ']) {
                    out.push(dir.join(format!("{name}.rs")));
                    out.push(dir.join(name).join("mod.rs"));
                }
            }
        }
    }
    out
}

/// The production sources of the core (test files and modules aside).
fn core_sources() -> Vec<(String, String)> {
    let mut files = Vec::new();
    for t in ["agent/src", "crates/nn-linux/src"] {
        support::rs_files(&repo_root().join(t), &mut files);
    }
    files.sort();
    let tests = test_modules(&files);
    files
        .iter()
        .filter(|f| {
            let rel = f.strip_prefix(repo_root()).unwrap().display().to_string();
            let name = f.file_name().unwrap().to_string_lossy();
            !(name == "tests.rs"
                || name.ends_with("_tests.rs")
                || rel.contains("/tests/")
                || tests.contains(f))
        })
        .map(|f| {
            let rel = f.strip_prefix(repo_root()).unwrap().display().to_string();
            let code = strip_comments(&fs::read_to_string(f).unwrap());
            (rel, production(&code).to_string())
        })
        .collect()
}

/// The threads of `code` without their role or the core's set: each
/// site's first lines (`(site, its window)`).
fn threads_without_a_call(code: &str) -> Vec<String> {
    let mut out = Vec::new();
    for pat in ["thread::Builder::new()", "thread::spawn("] {
        for (at, _) in code.match_indices(pat) {
            let window: String = code[at..].lines().take(12).collect::<Vec<_>>().join("\n");
            if !["enter_or_report(", "restore_core(", "caps::lower("]
                .iter()
                .any(|c| window.contains(c))
            {
                out.push(window);
            }
        }
    }
    out
}

#[test]
fn every_thread_of_the_core_takes_its_sets() {
    let mut bad = Vec::new();
    let mut listed = 0;
    for (rel, code) in core_sources() {
        for window in threads_without_a_call(&code) {
            match THREADS_WITHOUT_A_CALL
                .iter()
                .find(|(f, anchor, _)| *f == rel && window.contains(anchor))
            {
                Some(_) => listed += 1,
                None => bad.push(format!("{rel}:\n{window}")),
            }
        }
    }
    assert!(
        bad.is_empty(),
        "a thread that takes neither a role nor the core's set:\n{}",
        bad.join("\n---\n")
    );
    assert_eq!(
        listed,
        THREADS_WITHOUT_A_CALL.len(),
        "a listed thread is gone"
    );
}

#[test]
fn a_planted_thread_without_its_sets_is_found() {
    // the reviewer's P5
    let planted = "fn f() {\n    std::thread::Builder::new()\n        .name(\"nn-new\".into())\n        .spawn(move || work())\n        .unwrap();\n}\n";
    assert_eq!(threads_without_a_call(planted).len(), 1);
    let given = "fn f() {\n    std::thread::spawn(move || {\n        nn_linux::caps::restore_core();\n        work()\n    });\n}\n";
    assert!(threads_without_a_call(given).is_empty());
}

/// Review of #482 (R14c-5, the reviewer's planting P6): the errands thread
/// runs exactly the decision's errands — the rpm query, the
/// `DEFENDER_PIDS` insert and removal, and (lot 277) the question about the
/// start-in-cgroup tracker's marks — and no other caller hands it work.
#[test]
fn only_the_decision_s_errands_go_to_the_errands_thread() {
    let mut calls = Vec::new();
    for (rel, code) in core_sources() {
        let n = code.matches("errands::run(").count();
        if n > 0 {
            calls.push((rel, n));
        }
    }
    assert_eq!(
        calls,
        vec![
            // lot 277: the exemption check's question about the kernel's
            // marks (`Marks::started`, one errand)
            ("crates/nn-linux/src/cgroup_join.rs".to_string(), 1),
            ("crates/nn-linux/src/decision_host_linux.rs".to_string(), 1),
            ("crates/nn-linux/src/lib.rs".to_string(), 2),
        ],
        "the errands' callers"
    );
    // the planting
    let planted = "fn f() { crate::caps::errands::run(|| std::process::Command::new(\"/bin/sh\").status()); }";
    assert_eq!(planted.matches("errands::run(").count(), 1);
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
