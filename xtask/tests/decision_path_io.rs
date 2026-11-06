//! Wave 4 restructure, R12b (lab PR 269; plan §3.4): the decision path
//! without `await` and without blocking I/O — and a ratchet so it stays so.
//! R12c (lab PR 270): the responses and the ransomware tracker's I/O off it
//! — rule 1b, and the response code off the path.
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
//!    process, no sleep, no `block_in_place`.
//!
//!    Rule 1b, **no action, by name** (R12c, lab PR 270): that same code
//!    calls no acting entry point of the executor, the isolator or the
//!    actions journal ([`ACTING`]) — a decision's responses are submitted
//!    to the response dispatcher (`pipeline::dispatch`, its own thread),
//!    which signs each one's intent, runs it and signs its outcome; a Log
//!    decision's report is `Executor::log_report`, which touches nothing.
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
    "H::file_id",
    "TcpStream",
    "UnixStream",
    ".sync_all(",
    ".sync_data(",
];

/// R12c (lab PR 270): what acts — the executor's acting entry points, the
/// isolator's, the low-level actions, the journal's tickets. None of it in
/// the decision thread's own code (rule 1b).
const ACTING: &[&str] = &[
    "execute_for_started(",
    "execute_started(",
    "execute_on(",
    ".execute(",
    "execute_for(",
    "quarantine_handle(",
    "quarantine_process_binary(",
    ".engage(",
    "kill_ref(",
    "kill_tree(",
    "kill_process(",
    "block_outbound_for_pid(",
    "throttle_pid(",
    "file_caps::strip(",
    ".intent(",
    ".intents(",
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
    // R12c (lab PR 270): `crates/nn-linux/src/response` (the review of
    // #475's K9) left the list — the decision thread runs no response any
    // more (rule 1b: it submits them to the dispatcher's thread).
];

/// R12c (lab PR 270): functions of [`PATH`]'s files that run on threads of
/// their own (or at the start and the stop), not the decision's — their I/O
/// is theirs; the rest of the file is scanned (review of #476: the
/// decision thread's side of those files — `Dispatcher::submit`, `answer`,
/// `SlowWork::defer`, `take_ready` — is in [`NONE`]).
const OFF_PATH: &[(&str, &[&str], &str)] = &[
    (
        "agent/src/pipeline/dispatch.rs",
        &[
            "fn start_inner(",
            "fn spawn_worker(",
            "pub(crate) fn stop_by(",
            "fn work(",
            "fn watch_stalls(",
            "fn run_one(",
            "fn write_overflow(",
        ],
        "the response dispatcher's workers (`nn-response-<n>`) and stall watch: each \
         response's signed intent, the action, its signed outcome, a stall's row; their start \
         and their stop",
    ),
    (
        "agent/src/pipeline/slow.rs",
        &["pub(crate) fn start(", "pub(crate) fn stop(", "fn run("],
        "the dispatcher of slow work's thread (`nn-slow-work`): the ransomware tracker's sampler \
         and trust; its start and its stop",
    ),
];

/// The files of [`PATH`] that hold markers: how many sites, and why.
const KNOWN: &[(&str, usize, &str)] = &[
    (
        "agent/src/run_loop.rs",
        13,
        "the event loop's task, not the decision thread: the lab builds' trigger files read \
         and the stall's sleep (`debug_*`, debug-trigger builds; R12c: the crash between an \
         action's intent and its outcome), the thread scope and the dispatcher's stop run off \
         the runtime's worker, `/proc/1/comm` at a SIGTERM; `decision_loop` holds none (rule 1)",
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
        // review of #482: 25 counted 21 sites of the file's tests, whose
        // module the brace matching ended early at a `}` inside a string
        // lot 273: 4 → 7, the writer's `caller_exe`
        7,
        "the detection store's writer task, its start and its rotation; the decision's \
         `record_*` build a record and hand it to the bounded queue; lot 273: the writer \
         reads an anti-tamper denial's caller's executable (`caller_exe`: \
         `/proc/<pid>/comm` and `exe`) before it signs the record",
    ),
    (
        "crates/nn-linux/src/telemetry_probe.rs",
        // lot 280c: 14 → 24, the sensor self-test — the round's FIM and deny
        // files, the child reaped (its wait's sleep, off the runtime), the
        // attach checks' reads (`bpf-own-ids`, `/proc/modules`), and the
        // child's own steps (`run_child`: a process of its own)
        24,
        "the probe's own task (its marker files, sleeps, child processes; R13, lab PR 271: in \
         debug-trigger builds the lab's `debug-probe-blind` file, read once a round; lot 280c: \
         the attach checks' reads, the child's reap off the runtime) and the probe child's steps \
         (`run_child`, another process); `observe` matches an event in memory and counts a \
         module load",
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
        "the ransomware tracker's sampler of a burst's files (entropy, copies) — R12c (lab PR \
         270): run by the dispatcher of slow work (`RansomTracker::prepare` on `nn-slow-work`); \
         the decision thread judges a burst once its assessment is prepared and primed, and \
         judges one itself only when that queue is full (counted: `ransomware_inline`)",
    ),
    (
        "crates/nn-core/src/impact/trust.rs",
        5,
        "the ransomware tracker's trust of the writer's executable (the package that owns it): \
         R12c (lab PR 270), with the sampler, on the dispatcher of slow work's thread",
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
        22,
        "the lineage's /proc reads for the lookups outside a judgement (`AsOf::Now`, \
         `AsOf::Live`: the pumps', the admin's, the responses'), its boot-time scan \
         (`seed_from_proc`) and its sweep (`sweep` and its orphans' adoption, \
         `orphan_entry`: a thread of its own, every 5 s — the third review of #475); in a \
         judgement a process's start (`/proc/<pid>/stat`, POS-003's reuse check, and a cached \
         exec checked against the process its pid names now: `cached_live`) and, for a pid \
         the cache does not hold, a fork's parent and start, exe and uid (`fork_entry`: the \
         parent's cached image accepted only when `/proc/<pid>/exe` is that file — the \
         re-review of #475); never a process's image read as its identity in a judgement; \
         lot 275 (the final check of #495, C1): `runs_host_file`, the device and inode of a \
         response's receiver's `/proc/<pid>/exe` and of the host's file at its path (one \
         `fstat` each), read by the DNS response pump only, for a receiver whose executable \
         and uid are already a resolver's, not in a judgement",
    ),
    (
        "crates/nn-core/src/posture/triggers.rs",
        1,
        "a `/proc` path in a trigger's evidence text, no read",
    ),
];

/// The code the decision thread runs itself: none of it may hold a marker.
const NONE: &[(&str, Option<&str>)] = &[
    ("agent/src/pipeline/process_event.rs", None),
    ("agent/src/run_loop.rs", Some("fn decision_loop(")),
    // R12c (lab PR 270; review of #476): what the decision thread calls of
    // the dispatchers' files
    (
        "agent/src/pipeline/dispatch.rs",
        Some("pub(crate) fn submit("),
    ),
    ("agent/src/pipeline/dispatch.rs", Some("fn answer(")),
    ("agent/src/pipeline/slow.rs", Some("pub(crate) fn defer(")),
    (
        "agent/src/pipeline/slow.rs",
        Some("pub(crate) fn take_ready("),
    ),
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
            let mut text = production(&strip_comments(&text));
            for (_, heads, _) in OFF_PATH.iter().filter(|(f, _, _)| *f == rel) {
                for h in *heads {
                    let body = function(&text, h).to_string();
                    text = text.replacen(&body, "", 1);
                }
            }
            out.insert(rel, text);
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

/// Rule 1b's violations (R12c, lab PR 270): `(where, acting calls)`.
fn decision_thread_actions(code: &BTreeMap<String, String>) -> Vec<String> {
    let mut out = Vec::new();
    for (file, f) in NONE {
        let text = code
            .get(*file)
            .unwrap_or_else(|| panic!("{file} is not in the decision path's scan"));
        let body = f.map_or(text.as_str(), |h| function(text, h));
        let found: Vec<(&str, usize)> = ACTING
            .iter()
            .map(|m| (*m, body.matches(m).count()))
            .filter(|(_, n)| *n > 0)
            .collect();
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

/// Rule 1b (R12c, lab PR 270): the decision thread's own code runs no
/// action — its responses are the dispatcher's; and the files that run on
/// other threads are named, each with its reason, and exist.
#[test]
fn the_decision_thread_runs_no_action() {
    let code = path_code(&repo_root());
    let v = decision_thread_actions(&code);
    assert!(v.is_empty(), "{v:#?}");
    for (f, heads, why) in OFF_PATH {
        assert!(repo_root().join(f).is_file(), "{f}: listed, not on disk");
        assert!(
            !heads.is_empty() && why.len() > 20,
            "{f}: say which and why"
        );
    }
    // the decision submits its responses, and reports a Log decision
    // without the executor's acting entry points
    let pe = &code["agent/src/pipeline/process_event.rs"];
    assert!(
        pe.contains("dispatcher.submit("),
        "the responses go to the dispatcher"
    );
    assert!(
        pe.contains("executor.log_report("),
        "a Log decision's report"
    );
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
    // the review of #475's mutation K9, R12c: the decision thread running a
    // response itself again (`execute_for_started`) — rule 1b
    let pe = "agent/src/pipeline/process_event.rs".to_string();
    let mut planted = code.clone();
    planted
        .get_mut(&pe)
        .unwrap()
        .push_str("\nfn k9(e: &Executor) { e.execute_for_started(a, 1, 0, 0, \"\", &i); }\n");
    let v = decision_thread_actions(&planted);
    assert!(
        v.len() == 1 && v[0].contains("execute_for_started("),
        "{v:#?}"
    );
    let rl = "agent/src/run_loop.rs".to_string();
    let mut planted = code.clone();
    let text = planted.get_mut(&rl).unwrap();
    let at = text.find("fn decision_loop(").unwrap();
    let open = at + text[at..].find('{').unwrap();
    text.insert_str(open + 1, "\n let t = journal.intent(row);\n");
    let v = decision_thread_actions(&planted);
    assert!(v.len() == 1 && v[0].contains(".intent("), "{v:?}");
    assert!(decision_thread_actions(&code).is_empty());
    // review of #476: the decision thread's side of the dispatchers' files
    // is scanned — a read planted in `Dispatcher::submit`, an action in
    // `SlowWork::defer`
    let dp = "agent/src/pipeline/dispatch.rs".to_string();
    let mut planted = code.clone();
    let text = planted.get_mut(&dp).unwrap();
    let at = text.find("pub(crate) fn submit(").unwrap();
    let open = at + text[at..].find('{').unwrap();
    text.insert_str(open + 1, "\n let _ = std::fs::read(p);\n");
    let v = decision_thread_violations(&planted);
    assert!(v.len() == 1 && v[0].contains("fn submit("), "{v:?}");
    let sl = "agent/src/pipeline/slow.rs".to_string();
    let mut planted = code.clone();
    let text = planted.get_mut(&sl).unwrap();
    let at = text.find("pub(crate) fn defer(").unwrap();
    let open = at + text[at..].find('{').unwrap();
    text.insert_str(open + 1, "\n e.kill_tree(pid);\n");
    let v = decision_thread_actions(&planted);
    assert!(v.len() == 1 && v[0].contains("kill_tree("), "{v:?}");
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

/// Lot 279: the exec pump reads what R011 judges an exec of a module tool
/// on beside its command line — the executed file's device and inode
/// against the system's tool, `MODPROBE_OPTIONS` in its environment — on its
/// own thread, first, while the process may still run: the process_spawn
/// pump's step is `kmod_read_then_resolved`, which reads and keeps the
/// facts before it resolves the path. The decision reads no `/proc`. Lot
/// 287: then it notes every exec for the initramfs builds, after the path
/// was resolved.
#[test]
fn the_exec_pump_reads_a_module_tool_s_exec() {
    let mux = strip_comments(
        &std::fs::read_to_string(repo_root().join("crates/nn-linux/src/sensors/multiplexer.rs"))
            .unwrap(),
    );
    let pump = &mux[mux
        .find("\"process_spawn\",\n")
        .expect("the process_spawn pump")..];
    let pump = &pump[..pump.find(")?),").expect("its end")];
    assert!(
        pump.contains("kmod_read_then_resolved,"),
        "the process_spawn pump does not read module tools' execs: {pump}"
    );
    let step = &mux[mux
        .find("fn kmod_read_then_resolved(")
        .expect("kmod_read_then_resolved")..];
    let step = &step[..step.find("\n}\n").expect("its end")];
    let read = step
        .find("kmod_exec::read_and_keep(&e)")
        .expect("the exec read and its facts kept");
    let resolve = step.find("resolved(raw, e)").expect("then resolved");
    assert!(read < resolve, "read after its path was resolved: {step}");
    // lot 287: then every exec noted for the initramfs builds, its path
    // the kernel's made absolute
    let note = step
        .find("kmod_exec::note_exec(&e)")
        .expect("every exec noted for the initramfs builds");
    assert!(resolve < note, "noted before its path was resolved: {step}");
    // the core keeps the facts; it reads nothing itself
    let core = strip_comments(
        &std::fs::read_to_string(
            repo_root().join("crates/nn-core/src/decision/rules/kmod_exec_facts.rs"),
        )
        .unwrap(),
    );
    let core = production(&core);
    for m in MARKERS {
        assert!(!core.contains(m), "kmod_exec_facts.rs holds {m}");
    }
}
