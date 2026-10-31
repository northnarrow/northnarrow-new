//! Wave 4 restructure, R12b (lab PR 269; plan §3.4): the decision path
//! without `await` and without blocking I/O — and a ratchet so it stays so.
//!
//! The decision runs on a thread of its own (`agent/src/run_loop.rs`,
//! `decision_loop`), and judges each event in `process_event`
//! (`agent/src/pipeline/process_event.rs`). R12b took off it what blocked
//! it: an exec's path is made absolute in its pump, systemd's state is the
//! watch's snapshot, the trusted-installer window's expiry is its tick's,
//! the canary's access row is its writer's, a module's package ownership is
//! asked by the module-load pump. Two rules hold that:
//!
//! 1. **None, by name**: the decision thread's own code — the whole of
//!    `process_event.rs` and the `decision_loop` function — holds no I/O
//!    marker ([`MARKERS`]): no `.await`, no file or `/proc` read, no
//!    process, no sleep, no `block_in_place`. The responses a decision runs
//!    (the executor's kills, R12c's dispatcher to come) are calls of the
//!    executor, not markers.
//! 2. **A ratchet** over the code the decision calls into to judge an event
//!    ([`PATH`]: the rule engine, the posture and its lineage, the ladder,
//!    the canary detector, the correlation buffer, the record budget, the
//!    ransomware and impairment trackers, the copy-on-write guard, the
//!    detection sink, the telemetry probe, and the pipeline's other files):
//!    every file holding a marker is in [`KNOWN`] with its count and why
//!    those sites are not the decision's blocking I/O, or are left for a
//!    named lot. A new site fails until it is moved off the decision path
//!    or listed with its reason; a count that fell fails until the table is
//!    lowered — the table is always the code's.
//!
//! The scan is lexical (comments blanked, test items and test files left
//! out). Each rule is shown failing on a planted violation.

mod support;

use std::collections::BTreeMap;
use std::path::Path;

use support::{is_test_file, matching_brace, production, repo_root, rs_files, strip_comments};

/// What blocks a thread or awaits: a future awaited, a file or directory
/// opened, read, written or stat'ed, a `/proc` path, a process run, a sleep,
/// the runtime's blocking hand-offs, a socket, an fsync; the hosts' I/O
/// calls (nn-core's code reaches the host through them).
const MARKERS: &[&str] = &[
    ".await",
    "std::fs::",
    "fs::read",
    "fs::write",
    "fs::metadata",
    "fs::symlink_metadata",
    "fs::File",
    "fs::OpenOptions",
    "File::open",
    "File::create",
    "OpenOptions::new",
    "Command::new",
    "spawn_blocking",
    "block_in_place",
    "off_the_runtime(",
    "thread::sleep",
    "\"/proc",
    "H::read_link",
    "H::read_to_string",
    "H::read_dir",
    "H::rpm_owns",
    "H::on_host_path",
    "H::accessor_exe",
    "TcpStream",
    "UnixStream",
    ".sync_all(",
    ".sync_data(",
];

/// The code the decision calls into to judge an event (directories and
/// files).
const PATH: &[&str] = &[
    "agent/src/pipeline",
    "agent/src/run_loop.rs",
    "agent/src/cow/mod.rs",
    "agent/src/detection_store.rs",
    "crates/nn-linux/src/telemetry_probe.rs",
    "crates/nn-core/src/decision",
    "crates/nn-core/src/posture",
    "crates/nn-core/src/canary/detector.rs",
    "crates/nn-core/src/combat",
    "crates/nn-core/src/correlation.rs",
    "crates/nn-core/src/detection_budget.rs",
    "crates/nn-core/src/impact",
    "crates/nn-core/src/impair",
    // Review of #475 (its mutation K9): the responses the decision thread
    // carries out itself until R12c's dispatcher — the executor and what it
    // calls (kills, cgroups, quarantine, isolation)
    "crates/nn-linux/src/response",
];

/// The files of [`PATH`] that hold markers: how many sites, and why.
const KNOWN: &[(&str, usize, &str)] = &[
    (
        "agent/src/run_loop.rs",
        10,
        "the event loop's task, not the decision thread: the lab builds' trigger files read \
         and the stall's sleep (`debug_*`, debug-trigger builds), the thread scope run off the \
         runtime's worker, `/proc/1/comm` at a SIGTERM; `decision_loop` holds none (rule 1)",
    ),
    (
        "agent/src/pipeline/mod.rs",
        6,
        "the systemd watch's (a task): its question to systemd off the runtime's worker, awaited \
         with a bound; `pid1_is_systemd_shutdown` reads `/proc/1/comm` at a SIGTERM (the event \
         loop's task) — the decision reads the watch's snapshot",
    ),
    (
        "agent/src/cow/mod.rs",
        3,
        "the copy-on-write guard's own work (its copies, restores, the start of a killed \
         writer read after a ransomware rule's kill: the response's side, R12c's); \
         `observe_event` flags a writer in memory",
    ),
    (
        "agent/src/detection_store.rs",
        25,
        "the detection store's writer task, its start and its rotation; the decision's \
         `record_*` build a record and hand it to the bounded queue",
    ),
    (
        "crates/nn-linux/src/telemetry_probe.rs",
        13,
        "the probe's own task (its marker files, sleeps, child processes); `observe` matches \
         an event in memory",
    ),
    (
        "crates/nn-core/src/canary/detector.rs",
        3,
        "the trip's evidence of its reader (`H::accessor_exe`: a readlink of the reader's \
         /proc/<pid>/exe, on a canary trip only, the reader possibly short-lived), the stop's \
         wait for the writer (`flush`, the event loop's), and a trip's wait for room in the \
         writer's full queue, at most `CANARY_QUEUE_WAIT` (100 ms), then counted (review of \
         #475) — the access row and the registry's mark are the writer's (R12b)",
    ),
    (
        "crates/nn-core/src/decision/catalogue/process.rs",
        1,
        "a rule's description names a `/proc` path, no read",
    ),
    (
        "crates/nn-core/src/decision/correlation/ancestry.rs",
        1,
        "the ancestry tree's `/proc` fallback for a parent the cache does not know — the \
         chains' tree, R-F's next step",
    ),
    (
        "crates/nn-core/src/decision/rules/module_provenance.rs",
        7,
        "R018's package ownership: asked by the module-load pump on its thread \
         (`ModuleOwners::refresh`, R12b); the decision reads its answer, and asks itself \
         only for a file no pump asked about (the replay, the tests)",
    ),
    (
        "crates/nn-core/src/decision/rules/r004_exec_from_proc_self_fd.rs",
        1,
        "R004 matches a `/proc/self/fd` path in the exec's string, no read",
    ),
    (
        "crates/nn-core/src/impact/mod.rs",
        4,
        "the ransomware tracker's sampler of a burst's files (entropy, copies): on a mass \
         write or rename burst only — left for R12c's dispatcher of slow work",
    ),
    (
        "crates/nn-core/src/impact/trust.rs",
        5,
        "the ransomware tracker's trust of the writer's executable (its digest, the package \
         that owns it): on a burst only — left for R12c",
    ),
    (
        "crates/nn-core/src/impair/mod.rs",
        3,
        "the security-tool detector's registration of a tool's process (its start, its \
         executable) — at a tool's exec only",
    ),
    (
        "crates/nn-core/src/posture/exempt.rs",
        3,
        "the per-rule policy's exemption facts (a process's uid, cgroup, executable digest \
         from /proc), read once per process and cached — the next step after R-F",
    ),
    (
        "crates/nn-core/src/posture/host.rs",
        1,
        "the posture host's trait: the production host's file read, named once",
    ),
    (
        "crates/nn-core/src/posture/lineage.rs",
        15,
        "the lineage's /proc reads for the lookups outside a judgement (`AsOf::Now`, \
         `AsOf::Live`: the pumps', the admin's, the responses'), its boot-time reads (the \
         start's scan of the running processes, `seed_from_proc`), and — in a judgement — a \
         process's start (`/proc/<pid>/stat`, POS-003's reuse check); never a process's image \
         in a judgement (R-F, review of #475)",
    ),
    (
        "crates/nn-core/src/posture/triggers.rs",
        1,
        "a `/proc` path in a trigger's evidence text, no read",
    ),
    // Review of #475 (K9): the responses, carried out on the decision
    // thread until R12c's dispatcher takes them off it
    (
        "crates/nn-linux/src/response/block_outbound.rs",
        5,
        "a response (R12c): the outbound block's cgroup and `/proc` reads, its rule file",
    ),
    (
        "crates/nn-linux/src/response/caps_preflight.rs",
        7,
        "a response's preflight (R12c): the target's capabilities and status in `/proc`",
    ),
    (
        "crates/nn-linux/src/response/containment.rs",
        8,
        "a response (R12c): the containment ledger appended and synced, `/proc` reads",
    ),
    (
        "crates/nn-linux/src/response/kill.rs",
        19,
        "a response (R12c): the kill's cgroup made, frozen, killed and removed, its wait for the \
         freeze, `/proc` reads",
    ),
    (
        "crates/nn-linux/src/response/mod.rs",
        3,
        "a response (R12c): a target's path on the host, `/proc` reads",
    ),
    (
        "crates/nn-linux/src/response/proc_ref.rs",
        4,
        "a response (R12c): the target process pinned by its `/proc` entry",
    ),
    (
        "crates/nn-linux/src/response/quarantine.rs",
        35,
        "a response (R12c): the quarantine's copy, its ledger synced, `/proc` reads",
    ),
    (
        "crates/nn-linux/src/response/throttle.rs",
        3,
        "a response (R12c): the throttle's cgroup files",
    ),
];

/// The code the decision thread runs itself: none of it may hold a marker.
const NONE: &[(&str, Option<&str>)] = &[
    ("agent/src/pipeline/process_event.rs", None),
    ("agent/src/run_loop.rs", Some("fn decision_loop(")),
];

/// The sites in `code`: each stretch of text one or more markers cover
/// (`std::fs::read` is one site, not two).
fn count(code: &str) -> usize {
    let mut spans: Vec<(usize, usize)> = MARKERS
        .iter()
        .flat_map(|m| code.match_indices(m).map(|(i, _)| (i, i + m.len())))
        .collect();
    spans.sort_unstable();
    let mut sites = 0;
    let mut end = 0;
    for (a, b) in spans {
        if sites == 0 || a >= end {
            sites += 1;
            end = b;
        } else {
            end = end.max(b);
        }
    }
    sites
}

/// The site counts of every file of the scan (to fill [`KNOWN`]): a no-op
/// unless `NN_PRINT_IO_COUNTS=1` (an ignored helper, run by hand when the
/// table moves).
#[test]
#[ignore = "prints the counts; NN_PRINT_IO_COUNTS=1, run by hand when the table moves"]
fn print_the_counts() {
    if std::env::var("NN_PRINT_IO_COUNTS").as_deref() != Ok("1") {
        return;
    }
    for (file, text) in path_code(&repo_root()) {
        let n = count(&text);
        if n > 0 {
            println!("{n:>3} {file} {:?}", which(&text));
        }
    }
}

/// The markers in `code`, by marker (for a failure's message).
fn which(code: &str) -> Vec<(&'static str, usize)> {
    MARKERS
        .iter()
        .map(|m| (*m, code.matches(m).count()))
        .filter(|(_, n)| *n > 0)
        .collect()
}

/// The production code of every file of [`PATH`], by path.
fn path_code(root: &Path) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    for p in PATH {
        let full = root.join(p);
        let mut files = Vec::new();
        if full.is_dir() {
            rs_files(&full, &mut files);
        } else {
            files.push(full);
        }
        for f in files {
            let rel = f
                .strip_prefix(root)
                .unwrap()
                .to_string_lossy()
                .replace('\\', "/");
            if is_test_file(&rel) {
                continue;
            }
            let text = std::fs::read_to_string(&f).unwrap_or_else(|e| panic!("{rel}: {e}"));
            out.insert(rel, production(&strip_comments(&text)));
        }
    }
    out
}

/// The function whose head is `head` in `code`, to its closing brace.
fn function<'a>(code: &'a str, head: &str) -> &'a str {
    let at = code
        .find(head)
        .unwrap_or_else(|| panic!("`{head}` not found"));
    let open = at + code[at..].find('{').expect("a body");
    &code[at..open + matching_brace(&code[open..])]
}

/// Rule 1's violations: `(where, markers)`.
fn decision_thread_violations(code: &BTreeMap<String, String>) -> Vec<String> {
    let mut out = Vec::new();
    for (file, f) in NONE {
        let text = code
            .get(*file)
            .unwrap_or_else(|| panic!("{file} is not in the decision path's scan"));
        let body = f.map_or(text.as_str(), |h| function(text, h));
        let found = which(body);
        if !found.is_empty() {
            out.push(format!("{file} {}: {found:?}", f.unwrap_or("")));
        }
    }
    out
}

/// Rule 2's violations: a file with markers not listed, a count above or
/// below its pin, a listed file gone or with none.
fn ratchet_violations(code: &BTreeMap<String, String>) -> Vec<String> {
    let mut out = Vec::new();
    let known: BTreeMap<&str, usize> = KNOWN.iter().map(|(f, n, _)| (*f, *n)).collect();
    for (file, text) in code {
        let n = count(text);
        match known.get(file.as_str()) {
            None if n > 0 => out.push(format!(
                "{file}: {n} new blocking-I/O site(s) {:?} in the decision path — move them off \
                 it (a pump, a writer, a watch) or list the file in KNOWN with why",
                which(text)
            )),
            Some(&pin) if n > pin => out.push(format!(
                "{file}: {n} sites, {pin} known — {:?}: a new one in the decision path",
                which(text)
            )),
            Some(&pin) if n < pin => out.push(format!(
                "{file}: {n} sites, {pin} known — lower the pin (the ratchet only goes down)"
            )),
            _ => {}
        }
    }
    for (file, _, _) in KNOWN {
        if !code.contains_key(*file) {
            out.push(format!("{file}: listed in KNOWN, not in the scan"));
        }
    }
    out
}

/// Rule 1: the decision thread's own code awaits nothing and does no
/// blocking I/O.
#[test]
fn the_decision_thread_awaits_nothing_and_does_no_blocking_io() {
    let code = path_code(&repo_root());
    let v = decision_thread_violations(&code);
    assert!(v.is_empty(), "{v:#?}");
}

/// Rule 2: no new blocking-I/O site in the code the decision calls into;
/// the pins are the code's.
#[test]
fn the_decision_path_s_io_is_a_ratchet() {
    let code = path_code(&repo_root());
    let v = ratchet_violations(&code);
    assert!(v.is_empty(), "{v:#?}");
    for (file, _, why) in KNOWN {
        assert!(why.len() > 20, "{file}: say why");
    }
}

/// Each rule fails on a planted violation.
#[test]
fn the_rules_fail_on_planted_violations() {
    let mut code = path_code(&repo_root());
    // the review of #475's mutation K9: a blocking read in the executor the
    // decision thread calls (`execute_for_started`) is a new site
    let ex = "crates/nn-linux/src/response/executor.rs".to_string();
    let mut planted = code.clone();
    let text = planted.get_mut(&ex).expect("the executor is on the path");
    let at = text.find("fn execute_for_started(").unwrap();
    let open = at + text[at..].find('{').unwrap();
    text.insert_str(
        open + 1,
        "\n let _ = std::fs::read_to_string(\"/proc/self/status\");\n",
    );
    let v = ratchet_violations(&planted);
    assert!(
        v.len() == 1 && v[0].contains("executor.rs") && v[0].contains("new"),
        "{v:#?}"
    );
    // rule 1: an await, a /proc read in process_event; a sleep in the
    // decision loop
    let pe = "agent/src/pipeline/process_event.rs".to_string();
    let mut planted = code.clone();
    planted
        .get_mut(&pe)
        .unwrap()
        .push_str("\nasync fn x() { y().await; let _ = std::fs::read_link(\"/proc/1/exe\"); }\n");
    let v = decision_thread_violations(&planted);
    assert_eq!(v.len(), 1, "{v:?}");
    assert!(v[0].contains(".await") && v[0].contains("\"/proc"), "{v:?}");
    let rl = "agent/src/run_loop.rs".to_string();
    let mut planted = code.clone();
    let text = planted.get_mut(&rl).unwrap();
    let at = text.find("fn decision_loop(").unwrap();
    let open = at + text[at..].find('{').unwrap();
    text.insert_str(open + 1, "\n std::thread::sleep(d);\n");
    let v = decision_thread_violations(&planted);
    assert!(v.len() == 1 && v[0].contains("thread::sleep"), "{v:?}");
    // rule 2: a new file with a marker; a known file with one more; and
    // one with one fewer
    // (a planted file: its name built, so the path ratchet does not look
    // for it on disk)
    code.insert(
        format!("crates/nn-core/src/decision/rules/{}.rs", "new_rule"),
        "fn f() { let _ = std::fs::read(\"/etc/x\"); }".to_string(),
    );
    code.get_mut("crates/nn-core/src/posture/triggers.rs")
        .unwrap()
        .push_str("\nfn g() { Command::new(\"rpm\"); }\n");
    let lineage = code
        .get_mut("crates/nn-core/src/posture/lineage.rs")
        .unwrap();
    let i = lineage.find("H::read_link").expect("a /proc read");
    lineage.replace_range(i..i + 1, " ");
    let v = ratchet_violations(&code);
    assert_eq!(v.len(), 3, "{v:#?}");
    assert!(v
        .iter()
        .any(|m| m.contains("new_rule.rs") && m.contains("new")));
    assert!(v
        .iter()
        .any(|m| m.contains("triggers.rs") && m.contains("a new one")));
    assert!(v
        .iter()
        .any(|m| m.contains("lineage.rs") && m.contains("lower the pin")));
}
