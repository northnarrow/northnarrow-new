//! Lot 311 (the third bug hunt, family F4 "a read error becomes a wrong
//! answer", and the triage's N6): a read of the kernel's state never fails
//! on its encoding, and a failed read never empties a protection — and a
//! ratchet so it stays so.
//!
//! A process names itself: its `comm` (`prctl(PR_SET_NAME)`, a write to
//! `/proc/self/comm`, the name of the file it executed) is in its `stat`
//! and `status` byte for byte, a user names the cgroups systemd delegates
//! to it, and a user's FUSE mount puts any bytes in the mount table. A
//! strict `read_to_string` refused each of these files whole: the kill of a
//! process that named itself `\xff\xfe` was reported failed and it ran on
//! (lot 311a), the lineage's sweep took it for gone, one FUSE mount emptied
//! the exec quarantine's guarded roots (BUG-98). Two rules hold that:
//!
//! 1. **None**, by name: the production code of the security crates
//!    ([`SCAN`]) reads no process's own `/proc` entry ([`PROC_ENTRIES`]:
//!    `stat`, `status`, `comm`, `cgroup`, `mountinfo`, `cmdline`,
//!    `environ`) with `read_to_string` — `nn_linux::state_read::read_state`,
//!    the posture hosts' `read_state`, or the byte parser of
//!    `nn_linux::mountinfo` read them.
//! 2. **A ratchet** over the reads whose failure turns into a default: a
//!    `read_to_string(…)` whose statement takes `.ok()` or
//!    `.unwrap_or_default()`, and a `lines()` loop that `continue`s on a
//!    read error. Every file holding one is in [`KNOWN`] with its count and
//!    why a failed read there is not a protection emptied (a missing file
//!    is the default, the file is ours, the answer fails toward the
//!    stricter side…). A new site fails until it is made a read that keeps
//!    the last good state (`nn_linux::state_read::LastGood`) or is listed
//!    with its reason; a count that fell fails until the table is lowered.
//!
//! The scan is lexical (comments blanked, test items and test files left
//! out). Each rule is shown failing on a planted violation.

mod support;

use std::collections::BTreeMap;
use std::path::Path;

use support::{is_test_file, production, repo_root, rs_files, strip_comments};

/// The security crates' sources.
const SCAN: &[&str] = &[
    "crates/nn-core/src",
    "crates/nn-linux/src",
    "agent/src",
    "watchdog/src",
    "crates/nn-admin/src",
    "antitamper-bpf/src",
];

/// A process's own `/proc` entries, as a path argument names them: a
/// literal ending in the name, or a `join` of it.
const PROC_ENTRIES: &[&str] = &[
    "stat\"",
    "status\"",
    "comm\"",
    "cgroup\"",
    "mountinfo\"",
    "cmdline\"",
    "environ\"",
];

/// The files holding rule 2's sites: how many, and why (lot 311: none of
/// them reads a file a process or a user names, and none publishes an
/// empty set on a failed read).
const KNOWN: &[(&str, usize, &str)] = &[
    (
        "agent/src/cow/guard.rs",
        1,
        "a probe at the guard's start: whether `/proc/1/syscall` can be read (its error says why every open is then treated as a write — the stricter side)",
    ),
    (
        "agent/src/decision/golden.rs",
        1,
        "the golden replay's comparison with its committed file (a missing or unreadable file is a difference, written anew)",
    ),
    (
        "agent/src/export/controller.rs",
        1,
        "`/proc/sys/kernel/hostname` for the export's records: a kernel knob, ASCII; unreadable it names no host, nothing is protected by it",
    ),
    (
        "agent/src/heartbeat.rs",
        1,
        "`/proc/sys/kernel/random/boot_id`: written by the kernel, ASCII hex; unreadable, a new boot is assumed",
    ),
    (
        "agent/src/module_trust/mod.rs",
        1,
        "`/proc/sys/kernel/osrelease`: a kernel knob, ASCII; unreadable, no release's tree is vouched for (the stricter side)",
    ),
    (
        "agent/src/posture/golden.rs",
        2,
        "the golden replay's own audit file and its comparison with the committed file (lab and test tooling, our files)",
    ),
    (
        "agent/src/run_loop.rs",
        3,
        "the lab builds' trigger files (`debug-trigger`): absent or unreadable, nothing is triggered",
    ),
    (
        "antitamper-bpf/src/cgroup_floors.rs",
        5,
        "`/proc/meminfo` and `/sys/devices/system/cpu/online` (kernel-written ASCII; unreadable, the host is taken as large: no floor judged harmful for it), and our units' own cgroup files the floor writes and reads back (a read-back that fails is a floor not confirmed: reported)",
    ),
    (
        "crates/nn-admin/src/cli.rs",
        2,
        "the operator's own signed overlay, read after its signature was accepted, for the summary it prints (the agent judges the file itself)",
    ),
    (
        "crates/nn-linux/src/anti_tamper/bpf_defense.rs",
        1,
        "`/proc/self/fdinfo/<fd>` of the agent's own BPF descriptors: kernel-written ASCII",
    ),
    (
        "crates/nn-linux/src/anti_tamper/cgroup_guard.rs",
        1,
        "our units' own cgroup files, compared with the configured value and written back when they differ (a read that fails is a difference: written)",
    ),
    (
        "crates/nn-linux/src/cgroup_join.rs",
        4,
        "the kernel's pid limits under `/proc/sys` and the boot id (ASCII; unreadable, the built-in bounds and a new boot), and the join judge's own state file (unreadable, the judge starts afresh: every join after the start is judged)",
    ),
    (
        "crates/nn-linux/src/fim/honeypot.rs",
        1,
        "`/proc/sys/kernel/random/boot_id`: kernel-written ASCII; unreadable, the honeypots are laid again",
    ),
    (
        "crates/nn-linux/src/host_hardening.rs",
        1,
        "the install manifest we wrote, for the hardening report's provenance line (unreadable: the line says so, a Warn)",
    ),
    (
        "crates/nn-linux/src/kernel_state.rs",
        1,
        "a livepatch's `enabled`/`transition` flags under `/sys/kernel/livepatch` (kernel-written `0`/`1`); the patch itself is listed whatever they read",
    ),
    (
        "crates/nn-linux/src/known_system_prog.rs",
        1,
        "`/proc/<pid>/fdinfo/<fd>` (kernel-written ASCII): a descriptor that cannot be read proves no link — the program is then not told a known system one (the stricter side)",
    ),
    (
        "crates/nn-linux/src/module_writes.rs",
        1,
        "the judge's own state file (unreadable, it starts afresh: every write after the start is judged)",
    ),
    (
        "crates/nn-linux/src/own_dropins.rs",
        1,
        "`/proc/sys/kernel/pid_max`: a kernel knob, ASCII; unreadable, the built-in bound",
    ),
    (
        "crates/nn-linux/src/response/kill.rs",
        1,
        "a thread's `children` (kernel-written pid numbers): unreadable, the process is not taken as childless",
    ),
    (
        "crates/nn-linux/src/response/quarantine.rs",
        1,
        "a vault entry's `.meta`, written by us in UTF-8: unreadable, the entry is not shown (the vault's file stays)",
    ),
    (
        "crates/nn-linux/src/response/throttle.rs",
        1,
        "our throttle cgroup's own knobs, read back after the write (a value that cannot be read is not confirmed)",
    ),
    (
        "crates/nn-linux/src/self_integrity.rs",
        3,
        "kernel-written ASCII: `oom_score_adj` of the agent and the watchdog, `/proc/self/limits`, `/proc/meminfo` — an unreadable value is not compared (no finding made from nothing)",
    ),
    (
        "crates/nn-linux/src/sensor_feasibility.rs",
        1,
        "`/proc/kallsyms`, in the lab-only feasibility probe (`test-privileged`)",
    ),
    (
        "crates/nn-linux/src/sensors/bus.rs",
        1,
        "`/proc/sys/kernel/random/boot_id` (kernel-written ASCII): unreadable, a new boot",
    ),
    (
        "crates/nn-linux/src/sensors/epg.rs",
        2,
        "`pid_max` and `threads-max` under `/proc/sys`: kernel knobs, ASCII; unreadable, the built-in bounds",
    ),
    (
        "crates/nn-linux/src/sysctl_guard.rs",
        1,
        "a sysctl under `/proc/sys` (kernel-written ASCII), compared with its floor: unreadable, it is not judged changed",
    ),
    (
        "crates/nn-linux/src/telemetry_probe.rs",
        4,
        "the self-test's own files (the agent's own-ids file, the lab's `debug-*` files) and `/proc/modules` (kernel-written ASCII)",
    ),
    (
        "watchdog/src/lib.rs",
        1,
        "the watchdog's own record of the markers it honoured (unreadable: none honoured, so a replayed marker is refused — the stricter side)",
    ),
];

/// The argument list of the call whose `(` is at `open` in `code`.
fn arguments(code: &str, open: usize) -> &str {
    let b = code.as_bytes();
    let mut depth = 0usize;
    for (i, c) in b.iter().enumerate().skip(open) {
        match c {
            b'(' => depth += 1,
            b')' => {
                depth -= 1;
                if depth == 0 {
                    return &code[open + 1..i];
                }
            }
            _ => {}
        }
    }
    &code[open + 1..]
}

/// The statement from `at`: up to the next `;` (at most 400 bytes).
fn statement(code: &str, at: usize) -> &str {
    let rest = &code[at..];
    let end = rest.find(';').unwrap_or(rest.len()).min(400);
    let mut end = end.min(rest.len());
    while !rest.is_char_boundary(end) {
        end -= 1;
    }
    &rest[..end]
}

/// Rule 1's violations in one file's production code: the lines of a
/// `read_to_string` of a process's `/proc` entry — named in its argument,
/// or in the `let` that bound the variable it is given (within the 400
/// bytes before the call).
fn strict_proc_reads(code: &str) -> Vec<usize> {
    code.match_indices("read_to_string(")
        .filter(|(i, m)| {
            let args = arguments(code, i + m.len() - 1);
            let names = |t: &str| PROC_ENTRIES.iter().any(|e| t.contains(e));
            if names(args) {
                return true;
            }
            let var = args.trim().trim_start_matches('&');
            if var.is_empty() || !var.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_') {
                return false;
            }
            let mut from = i.saturating_sub(400);
            while !code.is_char_boundary(from) {
                from += 1;
            }
            let before = &code[from..*i];
            before
                .rfind(&format!("let {var} "))
                .or_else(|| before.rfind(&format!("let mut {var} ")))
                .is_some_and(|at| !before[at..].contains("fn ") && names(statement(before, at)))
        })
        .map(|(i, _)| code[..i].matches('\n').count() + 1)
        .collect()
}

/// Rule 2's sites in one file's production code: a `read_to_string(…)`
/// whose statement takes `.ok()` or `.unwrap_or_default()`, or that a
/// `let Ok(…) = … else` binds; a `lines()` loop that `continue`s on an
/// error.
fn defaulted_reads(code: &str) -> usize {
    let reads = code
        .match_indices("read_to_string(")
        .filter(|(i, _)| {
            let s = statement(code, *i);
            let mut from = i.saturating_sub(120);
            while !code.is_char_boundary(from) {
                from += 1;
            }
            let head = &code[from..*i];
            let bound = head
                .rfind("let Ok(")
                .is_some_and(|at| !head[at..].contains(';') && s.contains("else"));
            s.contains(".ok()") || s.contains(".unwrap_or_default()") || bound
        })
        .count();
    let loops = code
        .match_indices("let Ok(")
        .filter(|(i, _)| {
            let s = &code[*i..code.len().min(i + 80)];
            s.contains("= line else") && s.contains("continue")
        })
        .count();
    reads + loops
}

/// The production code of every file of [`SCAN`], by path.
fn scan_code(root: &Path) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    for dir in SCAN {
        let mut files = Vec::new();
        rs_files(&root.join(dir), &mut files);
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

#[test]
fn no_process_entry_is_read_as_strict_text() {
    let code = scan_code(&repo_root());
    assert!(code.len() > 300, "scanned {} files", code.len());
    let found: Vec<String> = code
        .iter()
        .flat_map(|(f, text)| {
            strict_proc_reads(text)
                .into_iter()
                .map(move |l| format!("{f}:{l}"))
        })
        .collect();
    assert!(
        found.is_empty(),
        "a process's /proc entry read with read_to_string (a comm, a cgroup, a mount \
         that is not UTF-8 fails the whole file): read it with \
         nn_linux::state_read::read_state, the host's read_state or nn_linux::mountinfo — \
         {found:#?}"
    );
}

#[test]
fn reads_that_default_on_failure_are_known() {
    let code = scan_code(&repo_root());
    let mut problems = Vec::new();
    for (file, text) in &code {
        let n = defaulted_reads(text);
        let known = KNOWN.iter().find(|(f, _, _)| f == file);
        match (n, known) {
            (0, None) => {}
            (0, Some(_)) => problems.push(format!("{file}: in KNOWN, holds no site any more")),
            (n, None) => problems.push(format!(
                "{file}: {n} read(s) whose failure becomes a default — keep the last good \
                 state (nn_linux::state_read::LastGood) or list the file with its reason"
            )),
            (n, Some((_, k, _))) if n != *k => {
                problems.push(format!("{file}: {n} site(s), KNOWN says {k}"))
            }
            _ => {}
        }
    }
    for (file, _, why) in KNOWN {
        assert!(code.contains_key(*file), "{file}: in KNOWN, not scanned");
        assert!(why.len() > 20, "{file}: give the reason");
    }
    assert!(problems.is_empty(), "{problems:#?}");
}

/// Each rule fails on a planted violation.
#[test]
fn the_rules_catch_planted_violations() {
    let planted = r#"
fn ppid(pid: u32) -> Option<u32> {
    let s = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    parse(&s)
}
fn uid(dir: &Path) -> Option<u32> {
    let s = std::fs::read_to_string(dir.join("status")).unwrap_or_default();
    parse(&s)
}
fn count(r: impl BufRead) -> usize {
    let mut n = 0;
    for line in r.lines() {
        let Ok(line) = line else { continue };
        n += line.len();
    }
    n
}
fn ours() -> String {
    std::fs::read_to_string("/proc/sys/kernel/pid_max").unwrap_or_default()
}
fn comm(pid: u32) -> Option<String> {
    let path = format!("/proc/{pid}/comm");
    std::fs::read_to_string(path).ok()
}
fn dropins(files: &[PathBuf]) {
    for path in files {
        let Ok(text) = std::fs::read_to_string(path) else {
            continue;
        };
        judge(&text);
    }
}
"#;
    assert_eq!(strict_proc_reads(planted), vec![3, 7, 23]);
    assert_eq!(defaulted_reads(planted), 6);
    let clean = r#"
fn ppid(pid: u32) -> Option<u32> {
    let s = nn_linux::state_read::read_state(format!("/proc/{pid}/stat")).ok()?;
    parse(&s)
}
"#;
    assert!(strict_proc_reads(clean).is_empty());
    assert_eq!(defaulted_reads(clean), 0);
}

/// The site counts of every scanned file (to fill [`KNOWN`]): a no-op
/// unless `NN_PRINT_STATE_READS=1`.
#[test]
#[ignore = "prints the counts; NN_PRINT_STATE_READS=1, run by hand when the table moves"]
fn print_the_counts() {
    if std::env::var("NN_PRINT_STATE_READS").as_deref() != Ok("1") {
        return;
    }
    for (file, text) in scan_code(&repo_root()) {
        let n = defaulted_reads(&text);
        if n > 0 {
            println!("{n:>3} {file}");
        }
        for l in strict_proc_reads(&text) {
            println!("STRICT {file}:{l}");
        }
    }
}
