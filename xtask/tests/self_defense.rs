//! Lot 293 — the external bug hunt's self-defence bugs (editions 1.2/1.3):
//! the parts no host test runs. The eBPF programs run only in a kernel (the
//! lab's tamper cases C112–C112w and the privileged e2e show what they
//! refuse); here the code is read, as `cgroup_guard.rs` reads the cgroup
//! guard: each check a refusal rests on is there, in the order that makes
//! it hold.

mod support;

use std::fs;

use support::{repo_root, strip_comments};

fn code(rel: &str) -> String {
    strip_comments(
        &fs::read_to_string(repo_root().join(rel)).unwrap_or_else(|e| panic!("{rel}: {e}")),
    )
}

/// `needles` all in `hay`, in this order.
fn in_order(hay: &str, needles: &[&str]) -> Result<(), String> {
    let mut at = 0;
    for n in needles {
        match hay[at..].find(n) {
            Some(i) => at += i + n.len(),
            None => return Err(format!("{n:?} not found after byte {at}")),
        }
    }
    Ok(())
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

/// The names that arm a file's owner to receive a signal at I/O: the owner
/// (`F_SETOWN`, `F_SETOWN_EX`, `FIOSETOWN`, `SIOCSPGRP`), the signal
/// (`F_SETSIG`), the asynchronous mode (`O_ASYNC`/`FASYNC`, `FIOASYNC`),
/// and the other owners' signals (a lease, `F_NOTIFY`).
const OWNER_SIGNAL_NAMES: [&str; 11] = [
    "O_ASYNC",
    "FASYNC",
    "F_SETOWN",
    "F_SETOWN_EX",
    "F_SETSIG",
    "FIOASYNC",
    "FIOSETOWN",
    "SIOCSPGRP",
    "F_SETLEASE",
    "F_NOTIFY",
    "F_OWNER_TID",
];

/// Where `name` is used as code in `code` (comments stripped): a path that
/// ends in it (`libc::O_ASYNC`, `OFlag::O_ASYNC`) or an import that names
/// it (`use libc::{F_SETOWN, …}`). A string or a doc that names it is no
/// use.
fn uses_of(code: &str, name: &str) -> Vec<usize> {
    let word = |c: Option<char>| c.is_some_and(|c| c.is_ascii_alphanumeric() || c == '_');
    let mut at = Vec::new();
    for (i, _) in code.match_indices(name) {
        let after = code[i + name.len()..].chars().next();
        if word(after) {
            continue;
        }
        let before = &code[..i];
        let line_start = before.rfind('\n').map_or(0, |p| p + 1);
        let line = &code[line_start..];
        let qualified = before.ends_with("::");
        let imported = line.trim_start().starts_with("use ")
            && !word(before.chars().next_back())
            && !before[line_start..].contains('"');
        if qualified || imported {
            at.push(before.matches('\n').count() + 1);
        }
    }
    at
}

/// External bug hunt BUG14: the `file_send_sigiotask` hook refuses every
/// signal through a file's owner to a protected process, whoever raised
/// the I/O — it has no exemption for the target itself or for the
/// agent's family (an attacker's socket armed on the agent is fired by the
/// agent's own write). That holds only while the agent, the watchdog and
/// their workers never arm a file's owner themselves: none of the code
/// they run uses the calls that do. A crate of the tree that needs one
/// must come through this test (and the hook's policy) first.
#[test]
fn the_agent_and_the_watchdog_never_arm_a_file_s_owner() {
    let root = repo_root();
    let mut files = Vec::new();
    for dir in [
        "agent/src",
        "watchdog/src",
        "antitamper-bpf/src",
        "common/src",
        "crates/nn-linux/src",
        "crates/nn-core/src",
        "crates/nn-proto/src",
        "crates/nn-model/src",
        "crates/nn-parse/src",
        "crates/nn-evidence/src",
        "crates/nn-export/src",
    ] {
        let before = files.len();
        support::rs_files(&root.join(dir), &mut files);
        assert!(files.len() > before, "{dir}: no source read");
    }
    // Lot 302: the one exception — the deny self-test's child
    // (`northnarrow-agent --telemetry-probe`: neither the agent, nor the
    // watchdog, nor a worker) arms a pipe of its own, owned by the
    // self-test's target process, to be refused by this very hook; the pipe
    // is closed at once. Its uses are inside `fn sigio_step` only, which
    // only the child's attempts call (below).
    let child_rel = "crates/nn-linux/src/telemetry_probe/deny.rs";
    let mut child_uses = 0;
    let mut found = Vec::new();
    for f in &files {
        let rel = f.strip_prefix(&root).unwrap().display().to_string();
        let c = strip_comments(&fs::read_to_string(f).unwrap());
        let excepted = if rel == child_rel {
            let start = c.find("fn sigio_step(").expect("fn sigio_step");
            let open = start + c[start..].find('{').unwrap();
            let end = open + support::matching_brace(&c[open..]);
            Some((
                c[..start].matches('\n').count() + 1,
                c[..end].matches('\n').count() + 1,
            ))
        } else {
            None
        };
        for name in OWNER_SIGNAL_NAMES {
            for line in uses_of(&c, name) {
                if excepted.is_some_and(|(a, b)| (a..=b).contains(&line)) {
                    child_uses += 1;
                    continue;
                }
                found.push(format!("{rel}:{line}: {name}"));
            }
        }
    }
    assert!(
        child_uses >= 2,
        "the deny self-test's owner step: {child_uses} uses"
    );
    // the step is the child's: called by its attempts only, which only the
    // child's run calls, which only the probe child's entry point calls
    let d = code(child_rel);
    let callers = |hay: &str, callee: &str| -> Vec<String> {
        hay.match_indices(&format!("{callee}("))
            .filter(|(at, _)| !hay[..*at].ends_with("fn "))
            .map(|(at, _)| {
                let f = hay[..at].rfind("\nfn ").max(hay[..at].rfind("\npub fn "));
                let f = f.map_or("", |i| &hay[i + 1..]);
                f[..f.find('(').unwrap_or(0)].to_string()
            })
            .collect()
    };
    assert_eq!(callers(&d, "sigio_step"), ["fn attempt_one"]);
    assert_eq!(callers(&d, "attempt_one"), ["pub fn run_steps"]);
    let t = code("crates/nn-linux/src/telemetry_probe.rs");
    assert_eq!(callers(&t, "deny::run_steps"), ["pub fn run_child"]);
    assert!(
        found.is_empty(),
        "the agent's or the watchdog's code arms a file's owner — a signal the \
         file_send_sigiotask hook refuses to a protected process whoever raised it:\n{}",
        found.join("\n")
    );
    // the detector itself: a use is found, a string or a doc is not
    let probe = "use libc::{c_int, F_SETOWN};\nlet x = libc::O_ASYNC;\n\
                 let s = \"F_SETSIG and libc::FIOASYNC in a message\";\nlet y = O_ASYNC_X;\n";
    assert_eq!(uses_of(probe, "F_SETOWN"), [1]);
    assert_eq!(uses_of(probe, "O_ASYNC"), [2]);
    assert!(uses_of(probe, "F_SETSIG").is_empty());
}

/// External bug hunt BUG14: the hook — on `file_send_sigiotask`, reading
/// the target's tgid (a target it cannot tell is let through and counted),
/// refusing a protected one unless the window's signal grant lets the
/// delivered signal through (SIGIO for the plain one), signed — no test of
/// the caller, the target itself or the family on the way.
#[test]
fn the_sigio_hook_refuses_every_owner_signal_to_a_protected_process() {
    let g = code("agent-ebpf/src/sigio_guard.rs");
    assert!(g.contains("#[lsm(hook = \"file_send_sigiotask\")]\npub fn file_send_sigiotask_deny("));
    let b = body(&g, "try_file_send_sigiotask");
    in_order(
        b,
        &[
            "let task: *const c_void = ctx.arg(0);",
            "off!(TASK_STRUCT_TGID_OFFSET)",
            "crate::fail_open::bump(hook::FILE_SEND_SIGIOTASK);\n            return 0;",
            "if !crate::task_kill::is_protected_pid(tgid) {\n        return 0;\n    }",
            "let sig: c_int = ctx.arg(2);",
            "let delivered = sigio_signal(sig);",
            "if crate::task_kill::kill_grant_allows(delivered) {\n        return 0;\n    }",
            "crate::inode_protect::emit_task_denial(FS_OP_SIGIO, delivered as u32 as u64, tgid);",
            "-EPERM",
        ],
    )
    .unwrap();
    for absent in [
        "bpf_get_current_pid_tgid",
        "is_exempt_pid",
        "override_active",
        "caller",
    ] {
        assert!(!b.contains(absent), "the hook asks `{absent}`: {b}");
    }
    assert!(code("agent-ebpf/src/main.rs").contains("mod sigio_guard;"));
    // the grant is the window's signal grant, the same test task_kill asks
    // for PID 1
    let t = code("agent-ebpf/src/task_kill.rs");
    in_order(
        body(&t, "kill_grant_allows"),
        &[
            "AGENT_SESSION.get(0)",
            "KILL_GRANT.get(0)",
            "g.allows(sig, unsafe { bpf_ktime_get_ns() }, session)",
        ],
    )
    .unwrap();
    assert!(body(&t, "pid1_granted").contains("kill_grant_allows(sig)"));
    // attached as a deny hook, counted
    let fs = code("crates/nn-linux/src/anti_tamper/filesystem.rs");
    assert!(fs.contains("(\"file_send_sigiotask_deny\", \"file_send_sigiotask\"),"));
    let m = code("crates/nn-linux/src/anti_tamper/mod.rs");
    assert!(m.contains("\"file_send_sigiotask\",\n];"));
}

/// External bug hunt BUG37: a refusal signed at every attempt — an inode
/// operation on a protected file, a write-open, a protected cgroup file's
/// open — goes behind a per-CPU budget of its own (no dedup by caller),
/// never the task denials' (a loop of `rm` must not take a refused `kill`'s
/// or ptrace's room); one held back is counted.
#[test]
fn the_attempt_refusals_have_a_budget_of_their_own() {
    let i = code("agent-ebpf/src/inode_protect.rs");
    in_order(
        body(&i, "attempt_budget"),
        &[
            "ATTEMPT_DENIAL_RATE.get_ptr_mut(0)",
            "if now.wrapping_sub((*rate)[0]) >= TASK_DENIAL_WINDOW_NS {",
            "if (*rate)[1] >= ATTEMPT_DENIAL_PER_SEC {",
            "ring_slot::DENIAL_RATE",
            "return false;",
            "(*rate)[1] += 1;",
            "true",
        ],
    )
    .unwrap();
    assert!(!body(&i, "attempt_budget").contains("TASK_DENIAL_RATE"));
    assert!(!body(&i, "attempt_budget").contains("TASK_DENIAL_SEEN"));
    in_order(
        body(&i, "emit_attempt"),
        &["if attempt_budget() {", "emit_denial(operation, key);"],
    )
    .unwrap();
    assert!(i.contains("static ATTEMPT_DENIAL_RATE: PerCpuArray<[u64; 2]>"));
    assert!(i.contains("const ATTEMPT_DENIAL_PER_SEC: u64 = 50;"));
    // the two inode refusals of the bug and the cgroup file's open
    in_order(
        body(&i, "deny_if_protected"),
        &["Some((op, key)) => {", "emit_attempt(op, key);", "true"],
    )
    .unwrap();
    assert!(!body(&i, "deny_if_protected").contains("emit_denial("));
    let open = body(&i, "try_protected_open_deny");
    in_order(
        open,
        &[
            "protected_verdict(FS_OP_WRITE, inode, hook::FILE_OPEN)",
            "emit_attempt(op, key);",
            "return -EPERM;",
        ],
    )
    .unwrap();
    assert!(!open.contains("emit_denial("));
    let c = code("agent-ebpf/src/cgroup_files.rs");
    assert!(body(&c, "sign")
        .contains("Phase::Open => crate::inode_protect::emit_attempt(operation, key),"));
    // no other inode refusal writes the ring without a budget
    let mut callers: Vec<&str> = i
        .match_indices("emit_denial(")
        .map(|(at, _)| {
            let start = i[..at].rfind("fn ").unwrap_or(0);
            &i[start..i[start..].find('(').map_or(i.len(), |p| start + p)]
        })
        .collect();
    callers.sort_unstable();
    callers.dedup();
    assert_eq!(
        callers,
        ["fn emit_attempt", "fn emit_denial", "fn emit_limited"],
        "emit_denial called from outside the two budgets"
    );
}

/// External bug hunt BUG54 (documentation): RANSOMWARE_DECISIVE.md
/// promised the rename counter "never counts the renames of an atomic
/// write"; an atomic save whose temporary carries its own extension
/// (`data.tmp` → `data.json`) is counted — the shape of an encryptor's
/// staging, which an exception would let through. The document says so
/// now, and names the test that shows such a burst gives no verdict.
#[test]
fn the_ransomware_design_says_which_atomic_saves_are_counted() {
    let d = fs::read_to_string(repo_root().join("docs/design/RANSOMWARE_DECISIVE.md")).unwrap();
    let flat = d.split_whitespace().collect::<Vec<_>>().join(" ");
    assert!(
        !flat.contains("The rename counter never counts the renames of an atomic write"),
        "the promise the code does not keep is still there"
    );
    for needle in [
        "It does count an atomic save whose temporary carries its own extension in place of the \
         final one (`data.tmp → data.json`",
        "(`a.pdf.tmp → a.pdf.locked`)",
        "an_atomic_save_burst_replacing_the_extension_is_not_shaped",
    ] {
        assert!(flat.contains(needle), "missing: {needle}");
    }
}

/// Lot 302 (named: the self-test's denials never consume the denial rate
/// budget of lot 293): the kernel records the deny self-test's child's
/// refusals outside the attempt refusals' budget, the task refusals' budget
/// and the per-caller dedup — the child is named by a per-boot map the
/// agent writes around each round, read by the two emitters before either
/// budget, and by nothing that decides a verdict. The lab spends both
/// budgets on every CPU before a round (`debug-deny-budget-spent`) and the
/// round's refusals still arrive, none held back.
#[test]
fn the_deny_self_test_s_refusals_take_no_room_of_the_budgets() {
    let i = code("agent-ebpf/src/inode_protect.rs");
    assert!(
        i.contains("pub static SELFTEST_TGID: Array<u32> = Array::with_max_entries(1, 0);"),
        "per boot, never pinned"
    );
    in_order(
        body(&i, "caller_is_self_test"),
        &[
            "if tgid == 0 {",
            "return false;",
            "SELFTEST_TGID.get(0)",
            "*t == tgid",
        ],
    )
    .unwrap();
    in_order(
        body(&i, "emit_attempt"),
        &[
            "if caller_is_self_test() {",
            "emit_denial(operation, key);",
            "return;",
            "if attempt_budget() {",
        ],
    )
    .unwrap();
    in_order(
        body(&i, "emit_limited"),
        &[
            "if caller_is_self_test() {",
            "emit_denial(operation, key);",
            "return;",
            "TASK_DENIAL_SEEN",
            // lot 318 (the re-check of #545, R2): the task denials' budget,
            // or the non-decisive records' (`limited_budget`, pinned in
            // `kernel_halves.rs`), after the self-test's bypass
            "if !limited_budget(operation, now) {",
        ],
    )
    .unwrap();
    in_order(
        body(&i, "limited_budget"),
        &["return minor_budget();", "TASK_DENIAL_RATE"],
    )
    .unwrap();
    // the mark decides no verdict: read by the two emitters only
    let root = repo_root();
    let mut files = Vec::new();
    support::rs_files(&root.join("agent-ebpf/src"), &mut files);
    let mut uses = Vec::new();
    for f in &files {
        let c = strip_comments(&fs::read_to_string(f).unwrap());
        for (at, _) in c.match_indices("caller_is_self_test()") {
            let fun = c[..at].rfind("fn ").map_or("", |p| &c[p..]);
            uses.push(fun[..fun.find('(').unwrap_or(0)].to_string());
        }
        assert!(
            !c.contains("SELFTEST_TGID") || f.ends_with("inode_protect.rs"),
            "{}: reads the mark",
            f.display()
        );
    }
    uses.sort();
    assert_eq!(
        uses,
        [
            "fn caller_is_self_test",
            "fn emit_attempt",
            "fn emit_limited"
        ],
        "the self-test's mark read outside the two emitters"
    );
    // the agent marks the child before it may begin, and clears the mark
    // once it is reaped
    let t = code("crates/nn-linux/src/telemetry_probe.rs");
    in_order(
        body(&t, "run_round"),
        &[
            "let pid = child.id();",
            "m.set(pid)",
            "stdin.write_all(&go)",
            "reap(pid, CHILD_TIMEOUT)",
            "m.set(0)",
        ],
    )
    .unwrap();
}
