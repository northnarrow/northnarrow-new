//! Wave 4 restructure, R11c (lab PR 264): the agent's process-wide state,
//! a ratchet.
//!
//! R11c replaced the global setters the start used to wire its state into
//! deep code (the per-rule policy's `install_global`, the audit log's
//! `set_audit_log`s, the published trackers, the boot's measurements, the
//! load's switches, the exec guards' configuration, the guards' and the
//! stop's flags) by handles the typed phases hand on, and made per-instance
//! the statics two instances in one process shared. What stays process-wide
//! is listed here, each with why it is one per process. Two rules:
//!
//! 1. every `static` of the agent's code — the agent's `src/` and the
//!    crates it is built from (`crates/*/src`, `common/src`,
//!    `antitamper-bpf/src`), test code aside — is in [`STATICS`], with its
//!    [`Class`] and its reason; a new one fails until it is listed, or made
//!    an instance, and an entry whose static is gone fails too;
//! 2. the start (`agent/src/main.rs`, `boot/`, `pipeline/`, `run_loop.rs`,
//!    `shutdown.rs`) calls a free function that names a static of its own
//!    module — a global setter, or a global read — only when
//!    [`START_CALLS`] lists it with its reason. A setter the start would call
//!    to hand its state to deep code is what this lot removed: hand it on as
//!    a handle instead.
//!
//! Test code is a test file (`tests.rs`, `*_tests.rs`) or an item under
//! `#[cfg(test)]` / `#[cfg(any(test, …))]`. The scan is lexical: comments
//! blanked, strings kept; a static's type that is a reference (`&'static
//! str`, `&[…]`) holds nothing mutable and is not one. A call through a
//! `use` alias of the module (`use … as rp`) is not seen. Each rule is
//! shown failing on a planted violation.

mod support;

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use support::{repo_root, rs_files, strip_comments};

/// Why a static is one per process.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Class {
    /// The process itself: its event loop, its one boot, its random keys,
    /// the descriptors and names it holds.
    Process,
    /// A fact of the host or the running kernel, read once and kept.
    HostFact,
    /// The state of the process's one eBPF object and the kernel objects
    /// its boot made (one boot per process, `BootSequence::begin`), as the
    /// status reads it.
    Kernel,
    /// A process total the signed status reports (`status --key`), summed
    /// over the instances that count into it (one in production).
    Telemetry,
    /// A record any part of the process appends to, like the journal: the
    /// signed degradations, the filesystems keyed on, the evidence lost.
    Log,
    /// Keyed by the instance's own path (a vault, a socket, a file): two
    /// instances never share an entry.
    PerKey,
    /// Per thread, the scratch of one call: set and taken within it.
    Scratch,
    /// A fixture of the fuzz harness (`fuzz_api`), immutable once built.
    Fixture,
}

/// A static that stays process-wide.
struct Kept {
    file: &'static str,
    name: &'static str,
    class: Class,
    why: &'static str,
}

const fn kept(file: &'static str, name: &'static str, class: Class, why: &'static str) -> Kept {
    Kept {
        file,
        name,
        class,
        why,
    }
}

use Class::*;

/// Every static of the agent's code that stays one per process, and why.
const STATICS: &[Kept] = &[
    // ── the agent ──
    kept(
        "agent/src/fuzz_api.rs",
        "KEYS",
        Fixture,
        "the shutdown fuzz target's fixed admin keys, built once",
    ),
    kept(
        "agent/src/loop_progress.rs",
        "ANCHOR",
        Process,
        "the event loop's heartbeat for the watchdog (lab PR 216): one event loop per agent \
         process; its origin",
    ),
    kept(
        "agent/src/loop_progress.rs",
        "ITERATIONS",
        Process,
        "the event loop's heartbeat: its rounds",
    ),
    kept(
        "agent/src/loop_progress.rs",
        "LAST_MS",
        Process,
        "the event loop's heartbeat: its last round",
    ),
    kept(
        "agent/src/execq/mod.rs",
        "STATE",
        Kernel,
        "the exec quarantine's state as `status` reports it: one kernel configuration per eBPF \
         object (the configuration and the kernel objects are the start's, AgentExecGuards)",
    ),
    kept(
        "agent/src/execq/mod.rs",
        "ACTIVE",
        Kernel,
        "the exec quarantine's controller runs: the spawn ledger records",
    ),
    kept(
        "agent/src/execq/mod.rs",
        "STOPPING",
        Kernel,
        "the exec quarantine controller thread's stop flag, set by the stop",
    ),
    kept(
        "agent/src/execq/mod.rs",
        "COUNTERS",
        Telemetry,
        "the exec quarantine's counters in `status --key`",
    ),
    kept(
        "agent/src/execq/mod.rs",
        "LEDGER",
        Kernel,
        "the execs the kernel holds, which the event loop and the controller share: the one \
         kernel queue of held execs",
    ),
    kept(
        "agent/src/execpol/mod.rs",
        "STATE",
        Kernel,
        "the exec policy's state as `status` reports it (its configuration and kernel objects \
         are the start's)",
    ),
    kept(
        "agent/src/execpol/mod.rs",
        "NOTES",
        Log,
        "what the exec policy runs without, signed once its controller starts",
    ),
    kept(
        "agent/src/execpol/mod.rs",
        "STOPPING",
        Kernel,
        "the exec policy controller thread's stop flag, set by the stop",
    ),
    kept(
        "agent/src/execpol/mod.rs",
        "COUNTERS",
        Telemetry,
        "the exec policy's counters in `status --key`",
    ),
    kept(
        "agent/src/admin/socket_watch.rs",
        "RETIRED",
        PerKey,
        "the admin sockets whose watch stops, by path: the stop's unlink retires its own \
         socket",
    ),
    kept(
        "agent/src/cow/journal.rs",
        "REACHABLE",
        HostFact,
        "whether `/proc/1/root` is reachable",
    ),
    kept(
        "agent/src/pipeline/mod.rs",
        "LAST",
        HostFact,
        "systemd's state, kept a second for the event loop's and the shutdown watch's asks",
    ),
    // ── nn-core ──
    kept(
        "crates/nn-core/src/detection_budget.rs",
        "BUDGET",
        Process,
        "the budget of the process's one detection log: every producer of detections shares it \
         by design (the pipeline, the exec guards' records, the security-tool judge), and its \
         reporter signs what it held",
    ),
    kept(
        "crates/nn-core/src/decision/engine.rs",
        "CONNECT_VERDICTS",
        Telemetry,
        "verdicts given at a connect, `net status`",
    ),
    kept(
        "crates/nn-core/src/decision/response_policy.rs",
        "HELD",
        Scratch,
        "a thread-local: what a rule's hold held back, taken by the engine before and after that \
         rule",
    ),
    kept(
        "crates/nn-core/src/decision/rules/net.rs",
        "DNS_BURST_LIVE_EVICTIONS",
        Telemetry,
        "a rule window's evictions, `status --key`",
    ),
    kept(
        "crates/nn-core/src/decision/rules/net.rs",
        "BEACON_LIVE_EVICTIONS",
        Telemetry,
        "a rule window's evictions, `status --key`",
    ),
    kept(
        "crates/nn-core/src/decision/rules/net.rs",
        "BEACON_QUOTA_EVICTIONS",
        Telemetry,
        "a rule window's evictions, `status --key`",
    ),
    kept(
        "crates/nn-core/src/decision/rules/net.rs",
        "DNS_TUNNEL_LIVE_EVICTIONS",
        Telemetry,
        "a rule window's evictions, `status --key`",
    ),
    kept(
        "crates/nn-core/src/decision/rules/net.rs",
        "QNAME_HASH_KEYS",
        Process,
        "the process's random SipHash keys of the qname hash (NETR-012): stable within the \
         process, unknowable outside it",
    ),
    kept(
        "crates/nn-core/src/decision/rules/net_fanout.rs",
        "FANOUT_LIVE_EVICTIONS",
        Telemetry,
        "a rule window's evictions, `status --key`",
    ),
    kept(
        "crates/nn-core/src/decision/correlation/ancestry.rs",
        "LIVE_EDGE_EVICTIONS",
        Telemetry,
        "the ancestry tree's evictions, `status --key`",
    ),
    kept(
        "crates/nn-core/src/decision/correlation/store.rs",
        "LOST_PRECURSOR_KEYS",
        Telemetry,
        "the chain rules' lost precursors, `status --key`",
    ),
    kept(
        "crates/nn-core/src/net/flow_tracker.rs",
        "PENDING_EVICTIONS",
        Telemetry,
        "the flow tracker's evictions, `net status`",
    ),
    kept(
        "crates/nn-core/src/net/flow_tracker.rs",
        "SNAPSHOTS_SENT",
        Telemetry,
        "open-flow snapshots, `net status`",
    ),
    kept(
        "crates/nn-core/src/net/flow_tracker.rs",
        "SNAPSHOTS_DEFERRED",
        Telemetry,
        "open-flow snapshots deferred, `net status`",
    ),
    kept(
        "crates/nn-core/src/net/limiter.rs",
        "ROWS_SKIPPED",
        Telemetry,
        "netflow rows the limiter skipped, `net status`",
    ),
    // ── nn-linux ──
    kept(
        "crates/nn-linux/src/anchored.rs",
        "DIRS",
        Process,
        "the directory descriptors the process holds for its anchored paths, by path",
    ),
    kept(
        "crates/nn-linux/src/anchored.rs",
        "UNANCHORED",
        Log,
        "the parents already reported unanchored (one ERROR each)",
    ),
    kept(
        "crates/nn-linux/src/fs_type.rs",
        "LEDGER",
        Log,
        "the filesystems the process keyed inodes on, noted by every part that keys one, at \
         boot and after (EBPF-016)",
    ),
    kept(
        "crates/nn-linux/src/posture_host_linux.rs",
        "TICK",
        HostFact,
        "the host's clock tick (`sysconf(_SC_CLK_TCK)`)",
    ),
    kept(
        "crates/nn-linux/src/telemetry_probe.rs",
        "GAPS_TOTAL",
        Telemetry,
        "telemetry gaps since boot",
    ),
    kept(
        "crates/nn-linux/src/anti_tamper/btf_revalidate.rs",
        "RESOLVED",
        HostFact,
        "the running kernel's BTF offsets, resolved once by the preflight (which refuses on \
         them) and armed into the one eBPF object; immutable after",
    ),
    kept(
        "crates/nn-linux/src/anti_tamper/fail_open.rs",
        "TOTALS",
        Kernel,
        "the deny hooks' fail-open counters of the one eBPF object, as sampled",
    ),
    kept(
        "crates/nn-linux/src/anti_tamper/fail_open.rs",
        "ARMED",
        Kernel,
        "the fail-open counters are read (the object exports them)",
    ),
    kept(
        "crates/nn-linux/src/anti_tamper/filesystem.rs",
        "BOOT_KEYS",
        Kernel,
        "the inodes this boot registered in the pinned PROTECTED_INODES",
    ),
    kept(
        "crates/nn-linux/src/sensors/connect_deny.rs",
        "ARMED",
        Kernel,
        "the kernel's connect deny is armed",
    ),
    kept(
        "crates/nn-linux/src/sensors/connect_deny.rs",
        "DENIED",
        Telemetry,
        "connects the kernel refused, `net status`",
    ),
    kept(
        "crates/nn-linux/src/sensors/epg.rs",
        "MODE_LINE",
        Kernel,
        "the exploit guard's mode as `status` prints it",
    ),
    kept(
        "crates/nn-linux/src/sensors/epg.rs",
        "COUNTERS",
        Kernel,
        "the exploit guard's counters of the one eBPF object, as sampled",
    ),
    kept(
        "crates/nn-linux/src/sensors/exe_identity.rs",
        "MOUNTS",
        HostFact,
        "the host's mount table, read again when it changes",
    ),
    kept(
        "crates/nn-linux/src/sensors/flow_sock.rs",
        "ARMED",
        Kernel,
        "FLOW_SOCK_MAP's occupancy is read",
    ),
    kept(
        "crates/nn-linux/src/sensors/flow_sock.rs",
        "PENDING",
        Kernel,
        "FLOW_SOCK_MAP's occupancy",
    ),
    kept(
        "crates/nn-linux/src/sensors/flow_sock.rs",
        "FORGOTTEN_MIN",
        Kernel,
        "FLOW_SOCK_MAP's forgotten entries",
    ),
    kept(
        "crates/nn-linux/src/sensors/reject.rs",
        "REJECTED",
        Telemetry,
        "malformed records the pumps rejected, per ring",
    ),
    kept(
        "crates/nn-linux/src/sensors/ring_drops.rs",
        "TOTALS",
        Kernel,
        "the rings' drop counters of the one eBPF object, as sampled",
    ),
    kept(
        "crates/nn-linux/src/boot/degradation.rs",
        "REGISTRY",
        Log,
        "the run's signed degradations: any part reports one as it logs (the signed \
         counterpart of the journal); the start binds its audit log once, as it installs the \
         logger",
    ),
    kept(
        "crates/nn-linux/src/boot/mod.rs",
        "BEGUN",
        Process,
        "one boot sequence per process (review #466 F3)",
    ),
    kept(
        "crates/nn-linux/src/response/block_outbound.rs",
        "RULESET",
        Kernel,
        "the nftables ruleset the process applied, once",
    ),
    kept(
        "crates/nn-linux/src/response/containment.rs",
        "LOCK",
        Process,
        "orders the read-modify-writes of the containment record",
    ),
    kept(
        "crates/nn-linux/src/response/executor.rs",
        "KILL_CGROUPS",
        Process,
        "makes each kill cgroup's name unique in the process (with its pid)",
    ),
    kept(
        "crates/nn-linux/src/response/mod.rs",
        "REACHABLE",
        HostFact,
        "whether `/proc/1/root` is reachable",
    ),
    kept(
        "crates/nn-linux/src/response/quarantine.rs",
        "INDEX_NOTES",
        PerKey,
        "the repairs of a vault's index, by the vault's directory (lab PR 258)",
    ),
    kept(
        "crates/nn-linux/src/net/blind_spots.rs",
        "COUNTERS",
        Telemetry,
        "the rows no DNS or TLS reader sees into, `net status`",
    ),
    kept(
        "crates/nn-linux/src/fim/drain.rs",
        "WATCH_PRESSURE",
        Kernel,
        "the pressure on the pinned WATCHED_PATHS map: its totals and their pacing",
    ),
    kept(
        "crates/nn-linux/src/fim/drain.rs",
        "RESTORED",
        PerKey,
        "the writes found to restore a critical path's baseline, by path",
    ),
    kept(
        "crates/nn-linux/src/fim/drain.rs",
        "LOST",
        Log,
        "FIM evidence lost since boot",
    ),
    kept(
        "crates/nn-linux/src/fim/drain.rs",
        "LAST_REPORT",
        Log,
        "the evidence loss's ERROR, once a minute",
    ),
    kept(
        "crates/nn-linux/src/fim/drain.rs",
        "HASHED",
        PerKey,
        "the content hash of each path the drain read, by path",
    ),
    // ── nn-model ──
    kept(
        "crates/nn-model/src/log_escape.rs",
        "ANSI",
        HostFact,
        "whether the process's stdout is a terminal",
    ),
];

/// The free functions the start calls that name a static of their module,
/// and why each may: `module::function`.
const START_CALLS: &[(&str, &str)] = &[
    (
        "loop_progress::start",
        "fixes the event loop's heartbeat origin at the process's start",
    ),
    ("loop_progress::tick", "one round of the event loop"),
    (
        "execq::start",
        "starts the exec quarantine's controller (its configuration and kernel objects passed \
         in) and says so in its status",
    ),
    (
        "execq::shutdown",
        "stops the exec quarantine's controller thread",
    ),
    (
        "execpol::start",
        "starts the exec policy's controller (its configuration and kernel objects passed in)",
    ),
    (
        "execpol::degradations",
        "what the exec policy runs without, signed by the start",
    ),
    (
        "execpol::shutdown",
        "stops the exec policy's controller thread",
    ),
    (
        "degradation::report",
        "a degradation, into the run's signed log",
    ),
    (
        "degradation::report_signed",
        "a degradation signed now, into the run's signed log",
    ),
    (
        "degradation::attach_audit_log",
        "binds the run's signed log to the audit log, once, as the logger is installed",
    ),
    (
        "degradation::mark_boot_over",
        "the event loop starts: later degradations are not the boot's",
    ),
    (
        "degradation::snapshot",
        "the manifest lists the run's degradations",
    ),
    (
        "degradation::count",
        "the trust level counts the run's degradations",
    ),
    (
        "fs_type::take_identity_report",
        "the boot's record of the filesystems keyed on, taken once",
    ),
    (
        "connect_deny::arm",
        "arms the kernel's connect deny of the one eBPF object",
    ),
    (
        "exe_identity::resolve",
        "an exec event's path made absolute with the host's mount table",
    ),
    (
        "btf_revalidate::resolved",
        "the running kernel's offsets, for the manifest",
    ),
    (
        "btf_revalidate::publish_resolved",
        "the preflight resolves the running kernel's offsets, once",
    ),
    (
        "detection_budget::admit",
        "a detection against the process's one detection log's budget",
    ),
    (
        "log_escape::stdout_ansi",
        "the logger's setup: whether the process's stdout is a terminal",
    ),
    (
        "systemd_state",
        "asks systemd's state (kept a second): the event loop's and the shutdown watch's",
    ),
];

// ── the scan ──────────────────────────────────────────────────────────────

/// The directories of the agent's code, relative to the root.
fn agent_dirs(root: &Path) -> Vec<String> {
    let mut dirs = vec![
        "agent/src".to_string(),
        "common/src".to_string(),
        "antitamper-bpf/src".to_string(),
    ];
    let mut crates: Vec<String> = std::fs::read_dir(root.join("crates"))
        .expect("crates/")
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .filter(|n| root.join("crates").join(n).join("src").is_dir())
        .map(|n| format!("crates/{n}/src"))
        .collect();
    crates.sort();
    dirs.extend(crates);
    dirs
}

/// A test file: `tests.rs`, `*_tests.rs`.
fn is_test_file(rel: &str) -> bool {
    let name = rel.rsplit('/').next().unwrap_or(rel);
    name == "tests.rs" || name.ends_with("_tests.rs")
}

/// `code` (comments blanked) with its test items blanked: each item under
/// `#[cfg(test)]` or `#[cfg(any(test, …))]` — a module's or a block's
/// braces, or up to its `;` — newlines kept.
fn production(code: &str) -> String {
    let mut out = code.as_bytes().to_vec();
    let mut from = 0;
    while let Some(at) = find_test_cfg(code, from) {
        let rest = &code[at..];
        // the item: past the attribute, to its closing brace or `;`
        let attr_end = at + rest.find(']').map_or(rest.len(), |i| i + 1);
        let item = &code[attr_end..];
        let brace = item.find('{');
        let semi = item.find(';');
        let end = match (brace, semi) {
            (Some(b), Some(s)) if s < b => attr_end + s + 1,
            (Some(b), _) => attr_end + b + matching_brace(&item[b..]),
            (None, Some(s)) => attr_end + s + 1,
            (None, None) => code.len(),
        };
        for c in &mut out[at..end] {
            if *c != b'\n' {
                *c = b' ';
            }
        }
        from = end;
    }
    String::from_utf8(out).expect("ASCII blanks keep UTF-8")
}

/// The next `#[cfg(test)]` / `#[cfg(any(test` at or after `from`.
fn find_test_cfg(code: &str, from: usize) -> Option<usize> {
    let a = code[from..].find("#[cfg(test)]").map(|i| from + i);
    let b = code[from..].find("#[cfg(any(test").map(|i| from + i);
    match (a, b) {
        (Some(a), Some(b)) => Some(a.min(b)),
        (a, b) => a.or(b),
    }
}

/// The length up to and including the brace that closes `s`'s first `{`.
fn matching_brace(s: &str) -> usize {
    let mut depth = 0usize;
    for (i, c) in s.char_indices() {
        match c {
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth == 0 {
                    return i + 1;
                }
            }
            _ => {}
        }
    }
    s.len()
}

/// The statics of `code` (production code): their names, in order. A
/// static whose type is a reference holds nothing mutable.
fn statics(code: &str) -> Vec<String> {
    let mut out = Vec::new();
    for line in code.lines() {
        let t = line.trim_start();
        let t = t
            .strip_prefix("pub(crate) ")
            .or_else(|| t.strip_prefix("pub(super) "))
            .or_else(|| t.strip_prefix("pub "))
            .unwrap_or(t);
        let Some(rest) = t.strip_prefix("static ") else {
            continue;
        };
        let rest = rest.strip_prefix("mut ").unwrap_or(rest);
        let Some((name, ty)) = rest.split_once(':') else {
            continue;
        };
        let name = name.trim();
        if name.is_empty()
            || !name
                .chars()
                .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_')
        {
            continue;
        }
        if ty.trim_start().starts_with('&') {
            continue;
        }
        out.push(name.to_string());
    }
    out
}

/// The module path segment a file's free functions are called through:
/// its stem, or its directory's name for `mod.rs` (a crate root has none).
fn module_name(rel: &str) -> Option<String> {
    let p = Path::new(rel);
    let stem = p.file_stem()?.to_string_lossy().into_owned();
    match stem.as_str() {
        "lib" | "main" => None,
        "mod" => Some(p.parent()?.file_name()?.to_string_lossy().into_owned()),
        _ => Some(stem),
    }
}

/// The free functions (column 0) of `code` whose body names one of
/// `names`.
fn functions_naming(code: &str, names: &[String]) -> Vec<String> {
    let mut out = Vec::new();
    let mut at = 0;
    for line in code.split_inclusive('\n') {
        let start = at;
        at += line.len();
        let mut t = line;
        for p in ["pub(crate) ", "pub(super) ", "pub "] {
            if let Some(r) = t.strip_prefix(p) {
                t = r;
                break;
            }
        }
        for p in ["const ", "async ", "unsafe "] {
            t = t.strip_prefix(p).unwrap_or(t);
        }
        let Some(r) = t.strip_prefix("fn ") else {
            continue;
        };
        let name: String = r
            .chars()
            .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
            .collect();
        let Some(open) = code[start..].find('{').map(|i| start + i) else {
            continue;
        };
        let body = &code[open..open + matching_brace(&code[open..])];
        if names.iter().any(|n| contains_word(body, n)) {
            out.push(name);
        }
    }
    out
}

fn contains_word(text: &str, word: &str) -> bool {
    let ident = |c: char| c.is_ascii_alphanumeric() || c == '_';
    text.match_indices(word).any(|(i, _)| {
        let before = text[..i].chars().next_back();
        let after = text[i + word.len()..].chars().next();
        !before.is_some_and(ident) && !after.is_some_and(ident)
    })
}

/// `code` with each `use a::b::{c, d};` written out as `a::b::c a::b::d`
/// (one level of braces), so a function imported by name is found by its
/// path.
fn uses_written_out(code: &str) -> String {
    let mut out = String::new();
    for stmt in code.split(';') {
        let t = stmt.trim();
        let Some(path) = t
            .strip_prefix("use ")
            .or_else(|| t.strip_prefix("pub use "))
        else {
            continue;
        };
        let path: String = path.chars().filter(|c| !c.is_whitespace()).collect();
        if let Some((prefix, rest)) = path.split_once('{') {
            for item in rest.trim_end_matches('}').split(',') {
                if !item.is_empty() {
                    out.push_str(&format!("{prefix}{item} "));
                }
            }
        } else {
            out.push_str(&path);
            out.push(' ');
        }
    }
    out
}

/// Each production file of the agent's code: its path and its production
/// code.
fn agent_code(root: &Path) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for dir in agent_dirs(root) {
        let mut files: Vec<PathBuf> = Vec::new();
        rs_files(&root.join(&dir), &mut files);
        for f in files {
            let rel = f
                .strip_prefix(root)
                .unwrap()
                .to_string_lossy()
                .replace('\\', "/");
            if is_test_file(&rel) {
                continue;
            }
            let text = std::fs::read_to_string(&f).unwrap();
            out.push((rel, production(&strip_comments(&text))));
        }
    }
    out
}

/// The start's code: `main.rs`, `boot/`, `pipeline/`, `run_loop.rs`,
/// `shutdown.rs`, with its `use`s written out.
fn start_code(code: &[(String, String)]) -> String {
    let mut out = String::new();
    for (rel, text) in code {
        let start = rel == "agent/src/main.rs"
            || rel == "agent/src/run_loop.rs"
            || rel == "agent/src/shutdown.rs"
            || rel.starts_with("agent/src/boot/")
            || rel.starts_with("agent/src/pipeline/");
        if start {
            out.push_str(text);
            out.push('\n');
            out.push_str(&uses_written_out(text));
            out.push('\n');
        }
    }
    out
}

/// The statics found: `(file, name)`.
fn found_statics(code: &[(String, String)]) -> BTreeSet<(String, String)> {
    code.iter()
        .flat_map(|(rel, text)| statics(text).into_iter().map(move |n| (rel.clone(), n)))
        .collect()
}

/// The free functions naming a static of their module that `start`
/// calls (a function of the start's own files aside): `module::function`.
fn start_calls(code: &[(String, String)], start: &str) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    for (rel, text) in code {
        let names = statics(text);
        if names.is_empty() {
            continue;
        }
        let Some(module) = module_name(rel) else {
            continue;
        };
        let in_start = rel.starts_with("agent/src/pipeline/") || rel.starts_with("agent/src/boot/");
        for f in functions_naming(text, &names) {
            let path = format!("{module}::{f}");
            if contains_word(start, &path) || (in_start && calls(start, &f)) {
                out.insert(if in_start { f } else { path });
            }
        }
    }
    out
}

/// `start` calls `f` by its bare name.
fn calls(start: &str, f: &str) -> bool {
    let ident = |c: char| c.is_ascii_alphanumeric() || c == '_';
    start.match_indices(&format!("{f}(")).any(|(i, _)| {
        let before = start[..i].chars().next_back();
        !before.is_some_and(|c| ident(c) || c == ':' || c == '.')
            && !start[..i].trim_end().ends_with("fn")
    })
}

// ── the rules ─────────────────────────────────────────────────────────────

/// Rule 1: every static of the agent's code is listed, with a reason, and
/// every entry still names one.
#[test]
fn every_static_of_the_agent_is_listed_with_why_it_is_one_per_process() {
    let root = repo_root();
    let found = found_statics(&agent_code(&root));
    let listed: BTreeSet<(String, String)> = STATICS
        .iter()
        .map(|k| (k.file.to_string(), k.name.to_string()))
        .collect();
    assert_eq!(listed.len(), STATICS.len(), "an entry listed twice");
    let new: Vec<_> = found.difference(&listed).collect();
    assert!(
        new.is_empty(),
        "process-wide statics not in STATICS (xtask/tests/global_state.rs): {new:?} — hand the \
         value on as an explicit handle (an instance's field, a phase's output), or list it \
         with why it is one per process"
    );
    let gone: Vec<_> = listed.difference(&found).collect();
    assert!(
        gone.is_empty(),
        "STATICS lists statics that are gone: {gone:?}"
    );
    for k in STATICS {
        assert!(
            k.why.len() >= 12,
            "{}::{}: say why it is one per process",
            k.file,
            k.name
        );
    }
    // Every class is used (an unused one is a stale explanation).
    for class in [
        Process, HostFact, Kernel, Telemetry, Log, PerKey, Scratch, Fixture,
    ] {
        assert!(STATICS.iter().any(|k| k.class == class), "{class:?} unused");
    }
}

/// Rule 2: the start calls a free function naming a static of its module
/// only when it is listed, with a reason; every entry is still called.
#[test]
fn the_start_calls_no_global_setter_but_the_listed_ones() {
    let root = repo_root();
    let code = agent_code(&root);
    let found = start_calls(&code, &start_code(&code));
    let listed: BTreeSet<String> = START_CALLS.iter().map(|(f, _)| f.to_string()).collect();
    assert_eq!(listed.len(), START_CALLS.len(), "an entry listed twice");
    let new: Vec<_> = found.difference(&listed).collect();
    assert!(
        new.is_empty(),
        "the start calls free functions that read or write a process-wide static: {new:?} — \
         hand the state on as an explicit handle from the phase that makes it (R11c), or list \
         the call in START_CALLS with why it is per process"
    );
    let gone: Vec<_> = listed.difference(&found).collect();
    assert!(
        gone.is_empty(),
        "START_CALLS lists calls the start no longer makes: {gone:?}"
    );
}

/// The setters and globals R11c removed stay gone from the agent's code.
#[test]
fn the_setters_r11c_removed_stay_gone() {
    let root = repo_root();
    let code = agent_code(&root);
    let all: String = code
        .iter()
        .map(|(_, t)| t.as_str())
        .collect::<Vec<_>>()
        .join("\n");
    for gone in [
        "fn install_global",
        "rule_policy::global(",
        "fn set_posture",
        "fn set_boot_inputs",
        "fn set_runtime_deny",
        "fn set_task_map_entries",
        "fn want_lsm",
        "fn want_skb",
        "fn want_tracepoint",
        "fn set_pin_root",
        "fn note_ja3_entries",
        "fn take_expected_denial(event",
        "HOST_STOPPING",
        "fn published_counts",
        "fn note_sensor",
    ] {
        assert!(!all.contains(gone), "`{gone}` is back in the agent's code");
    }
    // A free `set_audit_log` (a module's slot the start fills) is gone; an
    // instance's (`&self`) late binding is an explicit handle.
    for (rel, text) in &code {
        for line in text.lines() {
            if line.starts_with("pub fn set_audit_log") || line.starts_with("pub fn publish(") {
                panic!(
                    "{rel}: `{}` — a module-wide slot the start fills",
                    line.trim()
                );
            }
        }
    }
}

/// Each rule fails on a planted violation, and the scan sees through
/// what it must.
#[test]
fn the_rules_fail_on_planted_violations() {
    let planted = production(&strip_comments(
        "use std::sync::OnceLock;\n\
         // static IN_A_COMMENT: OnceLock<u8> = OnceLock::new();\n\
         static NAME: &str = \"a reference holds nothing\";\n\
         pub(crate) static SLOT: OnceLock<u32> = OnceLock::new();\n\
         pub fn set_slot(v: u32) {\n    let _ = SLOT.set(v);\n}\n\
         pub fn unrelated() -> u32 {\n    7\n}\n\
         fn inner() {\n    static LOCAL: std::sync::atomic::AtomicU8 = std::sync::atomic::AtomicU8::new(0);\n    let _ = &LOCAL;\n}\n\
         #[cfg(test)]\nstatic TEST_ONLY: OnceLock<u8> = OnceLock::new();\n\
         #[cfg(test)]\nmod tests {\n    static IN_TESTS: u8 = 0;\n    fn f() { let _ = IN_TESTS; }\n}\n",
    ));
    assert_eq!(statics(&planted), ["SLOT", "LOCAL"]);
    let names = statics(&planted);
    assert_eq!(functions_naming(&planted, &names), ["set_slot", "inner"]);
    // a start that calls the setter, by its path or through a `use`
    let code = vec![("planted/src/slots.rs".to_string(), planted.clone())];
    for start in [
        "fn run() { crate::slots::set_slot(1); }",
        "use crate::slots::{other, set_slot};\nfn run() { set_slot(1); }",
    ] {
        let start = format!("{start}\n{}", uses_written_out(start));
        assert_eq!(
            start_calls(&code, &start),
            BTreeSet::from(["slots::set_slot".to_string()])
        );
    }
    assert!(start_calls(&code, "fn run() { crate::slots::unrelated(); }").is_empty());
    // rule 1's listing: a new static is not in STATICS
    let found = found_statics(&code);
    assert!(found.contains(&("planted/src/slots.rs".to_string(), "SLOT".to_string())));
    assert!(!STATICS.iter().any(|k| k.file == "planted/src/slots.rs"));
    assert_eq!(
        module_name("crates/nn-linux/src/boot/mod.rs").as_deref(),
        Some("boot")
    );
    assert_eq!(module_name("agent/src/lib.rs"), None);
    assert!(is_test_file("agent/src/admin/pipeline_tests.rs"));
}
