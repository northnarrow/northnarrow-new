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
            "crate::fail_open::bump(hook::FILE_SEND_SIGIOTASK);\n                return 0;",
            "if !crate::task_kill::is_protected_pid(tgid)\n            && crate::window_tree::opaque(crate::window_tree::nn_tree_member_target(crate::window_tree::raw_arg(ctx, 0))) == 0\n        {\n            return 0;\n        }",
            "let sig: c_int = ctx.arg(2);",
            "let delivered = sigio_signal(sig);",
            "crate::inode_protect::emit_task_denial(FS_OP_SIGIO, delivered as u32 as u64, tgid);",
            "-EPERM",
        ],
    )
    .unwrap();
    // lot 2.3a (the C112w critique): and no window's signal grant either —
    // this path has no sender a window per process tree could scope
    for absent in [
        "bpf_get_current_pid_tgid",
        "is_exempt_pid",
        "override_active",
        "caller",
        "kill_grant",
        "KILL_GRANT",
    ] {
        assert!(!b.contains(absent), "the hook asks `{absent}`: {b}");
    }
    assert!(code("agent-ebpf/src/main.rs").contains("mod sigio_guard;"));
    // the window's signal grant is task_kill's, for PID 1 only
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
    assert!(
        body(&c, "sign")
            .contains("Phase::Open => crate::inode_protect::emit_attempt(operation, key),")
    );
    // no other inode refusal writes the ring without a budget (lot 356:
    // but the sole traces' writer, `emit_sole_trace` — a window's held load
    // alone, which `kernel_halves.rs` keeps to `hold`; the re-check 2 of
    // #567: the read-mode ptrace refusal's record, behind `limited_budget`
    // and its own dedup by image —
    // `a_read_mode_refusal_is_recorded_by_image_and_never_unrefused`)
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
        [
            "fn emit_attempt",
            "fn emit_denial",
            "fn emit_limited",
            // lot 2.3a: a signal's record, behind the per-caller-and-signal
            // dedup and its operation's budget
            "fn emit_signal",
            "fn emit_sole_trace",
            "fn emit_task_read_denial"
        ],
        "emit_denial called from outside the budgets and the sole traces' writer"
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
    // the mark decides no verdict: read by the emitters only (the re-check
    // 2 of #567: the read-mode ptrace refusal's record is a third)
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
            "fn emit_limited",
            "fn emit_signal",
            "fn emit_task_read_denial"
        ],
        "the self-test's mark read outside the emitters"
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

/// The re-check 2 of #567 (point 2): a refused read-mode ptrace access of
/// the agent's processes is recorded once an hour per caller IMAGE and
/// target (a dedup by process and minute gave journald alone about 2,880
/// Low records a day), never for the packaged journald in its unit's
/// cgroup — and refused whatever the record (`northnarrow_common::
/// ptrace_read`, whose host tests run the day).
#[test]
fn a_read_mode_refusal_is_recorded_by_image_and_never_unrefused() {
    let i = code("agent-ebpf/src/inode_protect.rs");
    in_order(
        body(&i, "emit_task_read_denial"),
        &[
            "if caller_is_self_test() {",
            "emit_denial(FS_OP_PTRACE_READ, key);",
            "return;",
            "crate::bpf_defense::caller_exe_key()",
            "bpf_get_current_cgroup_id()",
            "if ptrace_read::quiet(",
            "|k| unsafe { PTRACE_READ_QUIET.get(k).is_some() },",
            // lot 359 (the re-check 3 of #567, P3 a): journald's marks
            "crate::cgroup_join::caller_marks_clean,",
            "return;",
            // P3 b: the caller's cgroup in the key; the review of #574
            // (F3): and the refusal's kind, from the record's detail
            "ptrace_read::seen_key(exe.dev, exe.ino, target_tgid, detail, cgroup)",
            "PTRACE_READ_SEEN.get(&seen)",
            // P3 c: due, then the budget, and only then seen
            "if !ptrace_read::admit(last, now, || limited_budget(FS_OP_PTRACE_READ, now)) {",
            "return;",
            "PTRACE_READ_SEEN.insert(&seen, &now, 0)",
            "emit_denial(FS_OP_PTRACE_READ, key);",
        ],
    )
    .unwrap();
    // lot 359 (P3 c): the key is written once, after the budget — never
    // before it, never by a pointer into the map
    let b = body(&i, "emit_task_read_denial");
    assert_eq!(b.matches("PTRACE_READ_SEEN.insert(").count(), 1);
    assert!(!b.contains("PTRACE_READ_SEEN.get_ptr_mut("));
    assert!(b.find("limited_budget(").unwrap() < b.find("PTRACE_READ_SEEN.insert(").unwrap());
    // no dedup by the caller's process for it any more
    assert!(!body(&i, "emit_task_read_denial").contains("bpf_get_current_pid_tgid"));
    assert!(!body(&i, "emit_limited").contains("FS_OP_PTRACE_READ"));
    let r = code("common/src/ptrace_read.rs");
    assert!(r.contains("pub const DEDUP_NS: u64 = 3_600_000_000_000;"));
    // the refusal is the hook's, after the record, whatever it did
    let p = code("agent-ebpf/src/ptrace_check.rs");
    in_order(
        body(&p, "try_ptrace_access_check"),
        &[
            "if mode & PTRACE_MODE_NOAUDIT == 0 {",
            "crate::inode_protect::emit_task_read_denial(mode as u64, target_tgid);",
            "-EPERM",
        ],
    )
    .unwrap();
}

/// Lot 359 (the re-check 3 of #567, P3 e): every handle the watchdog takes
/// on the agent's pinned maps signs its failure (`pin_handle_failed`, a hold
/// record the agent signs as a degradation) — at each call site, none left
/// to a log line only.
#[test]
fn every_watchdog_pin_handle_failure_is_signed() {
    let m = code("watchdog/src/main.rs");
    for (call, name) in [
        ("register_self_pid(", "\"register_self_pid\""),
        ("reinsert_new_agent_pid(", "\"reinsert_new_agent_pid\""),
        ("evict_dead_agent(", "\"evict_dead_agent\""),
    ] {
        // (`unregister_self_pid(` at the stop is not a handle of the four)
        let calls = m.matches(call).count() - m.matches(&format!("un{call}")).count();
        let signed = m.matches(name).count();
        assert!(calls > 0, "{call}");
        assert_eq!(
            signed, calls,
            "{call}: {calls} calls, {signed} signed failures"
        );
    }
    // the role's claim, inside register_self_pid, is handed to the caller
    let l = code("watchdog/src/lib.rs");
    in_order(
        body(&l, "register_self_pid"),
        &["antitamper_bpf::claim_role(", "role_failed(&e);"],
    )
    .unwrap();
    assert_eq!(m.matches("\"claim_role\"").count(), 1);
    // its mini-hunt: the agent's own handles on the pinned maps for the
    // verified watchdog, a degradation of the same source
    let t = code("agent/src/boot/tasks.rs");
    in_order(
        &t,
        &[
            "anti_tamper::register_protected_pid(bpffs_root, p)",
            "self_integrity::PIN_HANDLE_FAILED,",
            "anti_tamper::claim_watchdog_role(bpffs_root, p)",
            "self_integrity::PIN_HANDLE_FAILED,",
        ],
    )
    .unwrap();
}

/// The review of #574 (F1): a memory view opened read-write or write-only
/// (root's `CAP_DAC_OVERRIDE` opens even a `0400` view so) takes the
/// process's memory as a read-only open does: `read()` works and the maps'
/// layout query answers. The view deny is called once, at every open,
/// before the access mode is read — never inside a branch of it — and
/// looks at no access mode itself.
#[test]
fn the_memory_views_are_refused_whatever_the_opens_access_mode() {
    let i = code("agent-ebpf/src/inode_protect.rs");
    let open = body(&i, "try_protected_open_deny");
    let call = "    if crate::cgroup_files::refuse_memory_view(file, inode) {\n            return -EPERM;\n        }";
    let at = open
        .find(call)
        .expect("the view deny, at the body's own level");
    assert_eq!(open.matches("refuse_memory_view(").count(), 1);
    let mode = open.find("FILE_F_MODE_OFFSET").unwrap();
    let split = open.find("if f_mode & FMODE_WRITE == 0 {").unwrap();
    assert!(at < mode && at < split, "before the access mode is read");
    // nothing before it decides on the access mode
    assert!(!open[..at].contains("f_mode"), "{}", &open[..at]);
    let c = code("agent-ebpf/src/cgroup_files.rs");
    let view = body(&c, "refuse_memory_view");
    assert!(!view.contains("f_mode") && !view.contains("FMODE"));
    assert!(!view.contains("FILE_F_MODE_OFFSET") && !view.contains("f_flags"));
}

/// Lot 367 (pre-alpha Phase 3-bis, F3b-1): on 7.0 root read the agent's
/// `environ`, `maps`, `smaps`, `pagemap` and `auxv` while the ptrace hook
/// refused them (from 6.16 `mm_access()` lets `CAP_PERFMON` through a
/// read-mode refusal), and the signed record said "denied in kernel".
/// - the open of those views is refused by the `file_open` deny, whatever
///   its access mode ([`the_memory_views_are_refused_whatever_the_opens_access_mode`]),
///   through `refuse_memory_view`, which takes the hook's
///   own two decisions (never a copy of them) and lets a process's access
///   to itself through, as the kernel does;
/// - its record carries `VIEW_OPEN`; the hook's read-mode record does not;
/// - the record's response is the shared module's, which says "denied"
///   only for the open (`common::ptrace_read::response`, host-tested).
#[test]
fn the_memory_views_are_refused_at_their_open_with_the_hooks_decisions() {
    let c = code("agent-ebpf/src/cgroup_files.rs");
    in_order(
        body(&c, "refuse_memory_view"),
        &[
            "if !matches!(special_fs(magic), Some(SpecialFs::Proc)) {\n            return false;\n        }",
            "if !northnarrow_common::ptrace_read::is_memory_view(len, words) {\n            return false;\n        }",
            "proc_file_task(inode)",
            "if caller == tgid {\n            return false;\n        }",
            "if !crate::ptrace_check::target_is_protected(tgid, task) {",
            "if crate::ptrace_check::caller_may_access(caller, false) {",
            "northnarrow_common::ptrace_read::VIEW_OPEN | MODE_READ_FSCREDS",
            "true",
        ],
    )
    .unwrap();
    // the decisions are the hook's: no role asked here directly
    let view = body(&c, "refuse_memory_view");
    assert!(!view.contains("is_protected_pid(") && !view.contains("is_exempt_pid("));
    assert!(!view.contains("PROTECTED_OBSERVERS") && !view.contains("PTRACE_OVERRIDE"));
    let p = code("agent-ebpf/src/ptrace_check.rs");
    let hook = body(&p, "try_ptrace_access_check");
    assert!(!hook.contains("VIEW_OPEN"));
    assert!(
        hook.contains("crate::inode_protect::emit_task_read_denial(mode as u64, target_tgid);")
    );
    // the record's words: the shared module's, for every read-mode record
    let e = code("agent/src/pipeline/process_event.rs");
    in_order(
        &e,
        &[
            "*operation == nn_model::FsProtectOperation::PtraceRead {",
            "common::ptrace_read::response(*target_dev).to_string()",
        ],
    )
    .unwrap();
}

// ── Lot 2.3a: the trusted-installer window per process tree, kernel side ──

/// The files of the eBPF object, comments stripped, by name.
fn ebpf_files() -> Vec<(String, String)> {
    let dir = repo_root().join("agent-ebpf/src");
    let mut out = Vec::new();
    for e in fs::read_dir(&dir).expect("agent-ebpf/src") {
        let p = e.expect("entry").path();
        if p.extension().is_some_and(|x| x == "rs") {
            let name = p.file_name().unwrap().to_string_lossy().into_owned();
            out.push((name.clone(), code(&format!("agent-ebpf/src/{name}"))));
        }
    }
    out
}

/// Lot 2.3a: `override_active()` keeps its signature and answers for the
/// CALLING process — a tree grant in force asks the tree, and only without
/// one does the host-wide grant answer (the flows' window until lots 2.3b
/// and 2.4). No other function of the object reads either grant slot: a
/// hook that asked `FS_GRANT` itself would lift for every process of the
/// host while a tree window is open.
#[test]
fn the_window_lifts_for_the_caller_and_the_host_wide_grant_only_without_a_tree_grant() {
    let i = code("agent-ebpf/src/inode_protect.rs");
    let o = body(&i, "override_active");
    assert!(
        o.contains("crate::window_tree::opaque(crate::window_tree::nn_window_lift()) != 0"),
        "{o}"
    );
    assert!(!o.contains("FS_GRANT"), "{o}");
    let w = code("agent-ebpf/src/window_tree.rs");
    in_order(
        body(&w, "nn_window_lift"),
        &[
            "if s == 0 {\n        return 0;\n    }",
            "grant_now()",
            "if grant_in_force(g, unsafe { bpf_ktime_get_boot_ns() }, s) {\n            return u64::from(member_now() == MEMBER_LIFT);\n        }",
            "crate::inode_protect::FS_GRANT.get(0)",
        ],
    )
    .unwrap();
    for (name, src) in ebpf_files() {
        for (needle, home) in [
            ("FS_GRANT.get(", "window_tree.rs"),
            ("FS_GRANT_V2.get(", "window_tree.rs"),
            ("TREE_MEMBERS.insert(", "window_tree.rs"),
            ("TREE_CLOSED.get_ptr_mut(", "window_tree.rs"),
        ] {
            if src.contains(needle) {
                assert_eq!(name, home, "{name} reads `{needle}`");
            }
        }
    }
    // one writer of each: the fork program's insert, the kernel's close
    assert_eq!(w.matches("TREE_MEMBERS.insert(").count(), 1);
    assert_eq!(w.matches("TREE_CLOSED.get_ptr_mut(").count(), 1);
    assert!(body(&w, "try_fork").contains("TREE_MEMBERS.insert(&ctgid, &entry, 0)"));
    assert!(body(&w, "close").contains("TREE_CLOSED.get_ptr_mut(0)"));
}

/// Lot 2.3a (the design's section 1, "the kernel's own test"): the lift
/// test reads the caller's entry, the window open, the process's start
/// (its group leader's), whether it is an io_uring worker, and its own
/// state at this very call (traced, filtered, namespaced); a member that
/// fails the state leaves the tree, signed.
#[test]
fn the_lift_test_reads_the_caller_s_own_state_and_evicts() {
    let w = code("agent-ebpf/src/window_tree.rs");
    in_order(
        body(&w, "nn_tree_member_base"),
        &[
            "TREE_MEMBERS.get(&tgid)",
            "if closed(s, g.generation) {\n            return MEMBER_NONE;\n        }",
            "process_start(task)",
            "unwrap_or(PF_IO_WORKER)",
            "g.lifts_for(Some(m), start, flags & PF_IO_WORKER != 0, now, s)",
        ],
    )
    .unwrap();
    assert!(
        body(&w, "nn_tree_caller_state")
            .contains("caller_state_verdict(caller_facts(bpf_get_current_task() as *const u8))")
    );
    in_order(
        body(&w, "member_now"),
        &[
            "let base = nn_tree_member_base();",
            "if base != MEMBER_LIFT {\n        return base;\n    }",
            "let state = nn_tree_caller_state();",
            "if state >= EVICT_TRACED {\n        let _ = nn_tree_evict_current(state, 0);\n    }",
        ],
    )
    .unwrap();
    // a window the kernel closed (its root's end) is open no more, for the
    // members' guard and the records' class as for the lift
    assert!(
        body(&w, "tree_open")
            .contains("grant_in_force(g, now, session) && !closed(session, g.generation)")
    );
    assert!(body(&w, "closed").contains("Some(c) => window_closed(c, session, generation),"));
    // the three steps are called in turn, never nested (the deepest hook's
    // stack chain: `mount_guard`'s 320 bytes and the lift within 448)
    for f in [
        "nn_tree_member_base",
        "nn_tree_caller_state",
        "nn_tree_evict_current",
    ] {
        assert!(!body(&w, f).contains("nn_"), "{f} calls a global function");
    }
    // the `cgroup/sysctl` guard asks `override_active()`: no helper 5.15
    // denies that program type on the lift's path
    for f in [
        "nn_window_lift",
        "member_now",
        "nn_tree_member_base",
        "nn_tree_caller_state",
        "nn_tree_evict_current",
        "process_start",
        "caller_facts",
        "evict",
        "close",
        "record",
    ] {
        assert!(!body(&w, f).contains("bpf_get_current_pid_tgid"), "{f}");
    }
    // the start is the group leader's (a thread's exec keeps it: de_thread)
    in_order(
        body(&w, "process_start"),
        &[
            "off_opt!(TASK_STRUCT_START_BOOTTIME_OFFSET)",
            "TASK_STRUCT_GROUP_LEADER_OFFSET",
            "start_ticks(",
        ],
    )
    .unwrap();
    // a field the kernel does not have is no lift (and the member leaves)
    let f = body(&w, "caller_facts");
    for field in [
        "TASK_STRUCT_PTRACE_OFFSET",
        "TASK_STRUCT_SECCOMP_MODE_OFFSET",
        "CRED_USER_NS_OFFSET",
        "NSPROXY_PID_NS_FOR_CHILDREN_OFFSET",
    ] {
        assert!(f.contains(&format!("off_opt!({field})")), "{field}");
    }
    assert!(f.contains("return unread;"));
    // the root's eviction closes the window
    in_order(
        body(&w, "evict"),
        &[
            "TREE_MEMBERS.remove(&tgid)",
            "WINDOW_EVENT_EVICTION",
            "if is_root(g, tgid, start) {\n        close(g, CLOSE_ROOT_EVICTED, tgid, start);",
        ],
    )
    .unwrap();
}

/// Lot 2.3a: a member's child joins only from a lifted member and not as a
/// thread; an entry leaves with its own process (its start), at the thread
/// group's death and at the leader's free; the root's end closes the
/// window.
#[test]
fn the_members_follow_the_fork_and_leave_with_their_process() {
    let w = code("agent-ebpf/src/window_tree.rs");
    assert!(w.contains("#[btf_tracepoint(function = \"sched_process_fork\")]\npub fn tree_fork("));
    in_order(
        body(&w, "try_fork"),
        &[
            "let v = nn_tree_member_now();",
            "if v != MEMBER_LIFT {\n            return;\n        }",
            "if !child_joins(v, ctgid, ptgid) {\n            return;\n        }",
            "TREE_MEMBERS.insert(&ctgid, &entry, 0).is_err()",
            "EVICT_FULL",
        ],
    )
    .unwrap();
    in_order(
        body(&w, "tree_exit"),
        &[
            "SIGNAL_STRUCT_LIVE_OFFSET",
            "if read_u32(sig.add(o_live)) != Some(0) {\n            return 0;\n        }",
            "forget(tgid, task);",
        ],
    )
    .unwrap();
    assert!(body(&w, "tree_task_free").contains("Some(l) if l == task => forget(tgid, task),"));
    in_order(
        body(&w, "forget"),
        &[
            "if !entry_is_process(&m, start) {\n            return;\n        }",
            "TREE_MEMBERS.remove(&tgid)",
            "is_root(&g, tgid, start)",
            "close(&g, CLOSE_ROOT_EXIT, tgid, start);",
        ],
    )
    .unwrap();
}

/// Lot 2.3a (D4, judged by D10's test): every pass of an exec, the final
/// file, the new environment and every executable mapping of a member are
/// judged; a file that is not trusted code evicts it. The trust test is the
/// role's (`role_maps::code_facts` + `window_tree::exec_verdict`).
#[test]
fn a_member_s_exec_and_mappings_are_judged_by_the_role_s_test() {
    let w = code("agent-ebpf/src/window_tree.rs");
    for (hook, f) in [
        ("bprm_check_security", "tree_bprm_check"),
        ("bprm_committed_creds", "tree_bprm_commit"),
        ("mmap_file", "tree_mmap_file"),
        ("file_mprotect", "tree_mprotect"),
    ] {
        assert!(
            w.contains(&format!("#[lsm(hook = \"{hook}\")]\npub fn {f}(")),
            "{f}"
        );
    }
    assert!(
        w.contains("#[btf_tracepoint(function = \"sched_process_exec\")]\npub fn tree_exec_env(")
    );
    in_order(
        body(&w, "nn_tree_judge_file"),
        &[
            "if nn_tree_member_now() != MEMBER_LIFT {\n            return 0;\n        }",
            "CODE_ANONYMOUS",
            "crate::role_maps::code_facts(file, inode)",
            "exec_verdict(&f, dir_mode(file))",
            "nn_tree_evict_current(reason, u64::from(code))",
        ],
    )
    .unwrap();
    assert!(body(&w, "judge_bprm").contains("nn_tree_judge_file(file, EVICT_EXEC)"));
    assert!(body(&w, "tree_mmap_file").contains("nn_tree_judge_file(raw_arg(&ctx, 0), EVICT_MAP)"));
    in_order(
        body(&w, "env_clean"),
        &[
            "end - start > ENV_MAX_BYTES",
            "while vars <= ENV_MAX_VARS",
            "env_head_dangerous(&head)",
            "false",
        ],
    )
    .unwrap();
    assert!(body(&w, "nn_tree_env").contains("nn_tree_evict_current(EVICT_ENV, 0)"));
    // the role's facts reader is shared, not copied
    assert!(code("agent-ebpf/src/role_maps.rs").contains("pub(crate) unsafe fn code_facts("));
}

/// Lot 2.3a: no window lifts the key files; while a tree window is
/// open each refusal's record carries its class, read before the ring's
/// reservation (an outsider's goes to the window ring too).
#[test]
fn a_key_file_is_kept_and_every_record_carries_its_class() {
    let i = code("agent-ebpf/src/inode_protect.rs");
    assert!(body(&i, "protected_verdict").contains(
        "if override_active() && !window_kept(&key) {\n            return None;\n        }"
    ));
    in_order(
        body(&i, "emit_denial"),
        &[
            "crate::window_tree::nn_window_class(u64::from(operation), key.ino) as u8",
            "FS_PROTECT_EVENTS.reserve::<FsProtectDenialRaw>(0)",
            "(*raw_ptr).window = window;",
            "entry.submit(0);",
        ],
    )
    .unwrap();
    let w = code("agent-ebpf/src/window_tree.rs");
    in_order(
        body(&w, "nn_window_class"),
        &[
            "denial_class(true, caller_is_member(&g))",
            "if class == DENIAL_WINDOW_OUTSIDER {",
            "WINDOW_EVENT_OUTSIDER_REFUSED",
        ],
    )
    .unwrap();
}

/// Lot 2.3a (the ancestors, the block devices): the rename of an ancestor, after the deny
/// checks of the four inodes, for both dentries; a block device's open
/// before the read-only branch (a read-open is judged too).
#[test]
fn the_ancestors_and_the_block_devices_are_judged() {
    let i = code("agent-ebpf/src/inode_protect.rs");
    in_order(
        body(&i, "try_inode_rename"),
        &[
            "deny_if_protected(FS_OP_RENAME, new_inode, hook::INODE_RENAME)",
            "let (old_s, new_s) = (crate::window_tree::raw_arg(ctx, 1), crate::window_tree::raw_arg(ctx, 3));",
            "if crate::window_tree::opaque(nn_ancestor_rename(old_s)) != 0\n            || crate::window_tree::opaque(nn_ancestor_rename(new_s)) != 0\n        {\n            return -EPERM;\n        }",
        ],
    )
    .unwrap();
    in_order(
        body(&i, "nn_ancestor_rename"),
        &[
            "INODE_EXT.get(&key)",
            "ancestor_rename_verdict(Some(ext), override_active(), family)",
            "emit_attempt(FS_OP_ANCESTOR_RENAME, key);",
        ],
    )
    .unwrap();
    in_order(
        body(&i, "try_protected_open_deny"),
        &[
            "refuse_memory_view(file, inode)",
            "let access = if f_mode & FMODE_WRITE != 0 {\n            northnarrow_common::window_tree::BDEV_ACCESS_WRITE",
            "if crate::window_tree::opaque(nn_bdev_raw(inode as u64, u64::from(access), 0)) != 0 {\n            return -EPERM;\n        }",
            "if f_mode & FMODE_WRITE == 0 {",
            // lot 2.3a (D7, the review of #647): a member's cgroup.kill/freeze
            "crate::cgroup_files::refuse_write(file, inode, hook::FILE_OPEN, crate::cgroup_files::Phase::Open)",
            "if crate::window_tree::opaque(crate::window_tree::nn_tree_cgroup_file(inode_s)) != 0 {\n            return -EPERM;\n        }",
        ],
    )
    .unwrap();
    // the review of #647: recorded by default, refused under the option —
    // one verdict for a block node and its disk's passthrough nodes
    in_order(
        body(&i, "nn_bdev_raw"),
        &[
            "Ok(m) if m & S_IFMT == S_IFBLK => true,",
            "Ok(m) if m & S_IFMT == S_IFCHR => false,",
            "if !block && access == u64::from(northnarrow_common::window_tree::BDEV_ACCESS_READ) {\n            return 0;\n        }",
            "off_opt!(INODE_I_RDEV_OFFSET)",
            "PROTECTED_BDEVS.get(&rdev)",
            "is_exempt_pid(",
            "KREAD_SLOT_MASK",
            "northnarrow_common::window_tree::bdev_verdict(",
            "northnarrow_common::window_tree::bdev_entry_bit(block),",
            "override_active(),",
            "emit_attempt(op, key);",
            "u64::from(northnarrow_common::window_tree::bdev_refuses(op))",
        ],
    )
    .unwrap();
    // a passthrough command judged before the chattr family's fast return
    in_order(
        body(&i, "try_file_ioctl"),
        &[
            "if northnarrow_common::window_tree::is_passthrough_ioctl(cmd) {",
            "nn_bdev_raw(inode, access, u64::from(cmd))",
            "return -EPERM;",
            "if cmd != FS_IOC_SETFLAGS && cmd != FS_IOC32_SETFLAGS && cmd != FS_IOC_FSSETXATTR {",
        ],
    )
    .unwrap();
    // our units' links, by name, in their directories: removed or renamed
    in_order(
        body(&i, "try_inode_unlink"),
        &[
            "nn_unit_link(dir_s, dentry_s, u64::from(FS_OP_UNLINK))",
            "return -EPERM;",
        ],
    )
    .unwrap();
    in_order(
        body(&i, "try_inode_rename"),
        &[
            "nn_unit_link(crate::window_tree::raw_arg(ctx, 0), old_s, rename)",
            "nn_unit_link(crate::window_tree::raw_arg(ctx, 2), new_s, rename)",
            "return -EPERM;",
            "nn_ancestor_rename(old_s)",
        ],
    )
    .unwrap();
    in_order(
        body(&i, "nn_unit_link"),
        &[
            "INODE_EXT.get(&key)",
            "Ok(i) if i != 0 => {}",
            "is_unit_link_name(&w)",
            "unit_link_verdict(Some(ext), ours, override_active(), family)",
            "emit_attempt(FS_OP_UNLINK, key);",
            "emit_attempt(FS_OP_RENAME, key);",
        ],
    )
    .unwrap();
}

/// Lot 2.3a: `task_kill` protects a new instance before it registers
/// (a process running our binary, not its role's live holder, in its first
/// seconds; the window lifts that one for its members, never a registered
/// one), guards a member of an open window
/// from outsiders (D7, `systemd-shutdown` aside), and records every
/// default-fatal signal it lets through to a protected process (330 a), a
/// refused one by caller and signal.
#[test]
fn task_kill_protects_a_new_instance_guards_the_members_and_records_fatal_signals() {
    let t = code("agent-ebpf/src/task_kill.rs");
    in_order(
        body(&t, "try_task_kill"),
        &[
            "let registered = is_protected_pid(target_tgid);",
            "registered || new_instance(target as *const u8, crate::window_tree::raw_arg(ctx, 0), target_tgid);",
            "if !is_protected {",
            "crate::window_tree::opaque(crate::window_tree::nn_tree_target_guarded(crate::window_tree::raw_arg(ctx, 0))) != 0",
            "&& !(caller_tgid == 1 && pid1_is_final_shutdown())",
            "crate::inode_protect::emit_signal(FS_OP_SIGNAL, sig as u32, target_tgid);\n                return -EPERM;",
            "observe_defender(target_tgid, sig);",
            "if caller_tgid == target_tgid || is_exempt_pid(caller_tgid) {\n            let_through(sig, target_tgid);\n            return 0;\n        }",
            "if !registered && crate::inode_protect::override_active() {\n            let_through(sig, target_tgid);\n            return 0;\n        }",
            "if caller_tgid == 1 && (pid1_granted(sig) || pid1_is_final_shutdown()) {\n            let_through(sig, target_tgid);\n            return 0;\n        }",
            "crate::inode_protect::emit_signal(FS_OP_SIGNAL, sig as u32, target_tgid);\n        -EPERM",
        ],
    )
    .unwrap();
    // a new instance: our binary's role, not its live holder, its age
    // (the fixtures' teardown of an evicted holder, a helper left behind)
    in_order(
        body(&t, "new_instance"),
        &[
            "Some(k) => crate::bpf_defense::OWN_EXE_INODES.get(&k).copied().unwrap_or(0),",
            "if role == 0 {\n            return false;\n        }",
            "let holder = crate::bpf_defense::ROLE_TGIDS.get(u32::from(role - 1)).copied();",
            "task.add(off!(TASK_STRUCT_START_TIME_OFFSET))",
            ".map(|start| bpf_ktime_get_ns().saturating_sub(start));",
            // the review of #647: systemd's start of the role's unit only
            "== Ok(1)",
            "let for_role = parent_is_init\n            && crate::window_tree::opaque(crate::bpf_defense::nn_in_role_unit(raw, u64::from(role - 1))) == 1;",
            "northnarrow_common::window_tree::new_instance_protected(role, holder, tgid, for_role, age)",
        ],
    )
    .unwrap();
    assert!(body(&t, "let_through").contains(
        "if fatal_or_stop_by_default(sig) {\n        crate::inode_protect::emit_signal(FS_OP_FATAL_SIGNAL, sig as u32, target_tgid);"
    ));
    // the record's dedup is by caller AND signal, then its budget
    let i = code("agent-ebpf/src/inode_protect.rs");
    in_order(
        body(&i, "emit_signal"),
        &[
            "if caller_is_self_test() {",
            "TASK_DENIAL_SEEN.get_ptr_mut(&seen)",
            "if !limited_budget(operation, now) {\n        return;\n    }",
            "emit_denial(operation, key);",
        ],
    )
    .unwrap();
    assert!(
        body(&i, "emit_signal")
            .contains("(caller << 16) | (u64::from(sig & 0xff) << 8) | u64::from(operation)")
    );
    // the members' guard: a member of the open window, its own process, the
    // caller outside the tree and the family
    let w = code("agent-ebpf/src/window_tree.rs");
    in_order(
        body(&w, "nn_tree_target_guarded"),
        &[
            "!tree_open(&g, bpf_ktime_get_boot_ns(), s)",
            "if caller == ttgid || crate::task_kill::is_exempt_pid(caller) {",
            // a member of this generation, its own process, or in the fork span
            "!holds_entry(ttgid, target, generation)",
            // the review of #647: the caller judged by the lift test
            "u64::from(member_now() != MEMBER_LIFT)",
        ],
    )
    .unwrap();
    in_order(
        body(&w, "holds_entry"),
        &[
            "TREE_MEMBERS.get(&tgid)",
            "m.generation == generation",
            "entry_is_process(m, st)",
        ],
    )
    .unwrap();
}

/// Lot 2.3a (D7): the members' ptrace guard refuses only a member of the
/// open window from outside its tree, records each mode as the agent's
/// own processes' are, and the descriptor guard closes the boundary while
/// the window is open, but for the agent's family.
#[test]
fn the_members_ptrace_and_descriptor_guards() {
    let w = code("agent-ebpf/src/window_tree.rs");
    assert!(w.contains("#[lsm(hook = \"ptrace_access_check\")]\npub fn tree_ptrace("));
    in_order(
        body(&w, "tree_ptrace"),
        &[
            "if opaque(nn_tree_target_guarded(target)) == 0 {\n            return 0;\n        }",
            "if mode & PTRACE_MODE_NOAUDIT == 0 {",
            "if mode & PTRACE_MODE_ATTACH != 0 {\n                crate::inode_protect::emit_task_denial(FS_OP_PTRACE, u64::from(mode), ttgid);",
            "crate::inode_protect::emit_task_read_denial(u64::from(mode), ttgid);",
            "-EPERM",
        ],
    )
    .unwrap();
    assert!(w.contains("#[lsm(hook = \"file_receive\")]\npub fn tree_fd_receive("));
    in_order(
        body(&w, "tree_fd_receive"),
        &[
            "if !tree_open(&g, bpf_ktime_get_boot_ns(), s) {\n            return 0;\n        }",
            "if crate::task_kill::is_exempt_pid(caller) {\n            return 0;\n        }",
            "crate::inode_protect::PROTECTED_INODES.get(&k).is_some()",
            "if !protected && !is_io_uring(file) {\n            return 0;\n        }",
            "emit_attempt(FS_OP_FD_RECEIVE",
            "-EPERM",
        ],
    )
    .unwrap();
    assert!(
        body(&w, "is_io_uring")
            .contains("w[0] == IO_URING_LO && w[1] & IO_URING_HI_MASK == IO_URING_HI")
    );
}

/// Lot 2.3a (the lab's verifier round, 5.15 to 7.0): a hook passes the
/// tree's global functions scalars only (`raw_arg`: a typed pointer is
/// refused, "R1 is not a scalar") and branches on their answers through
/// `opaque` (LLVM folded arithmetic on a raw 0-or-1 answer the verifier
/// could not bound). Each call site of the six from another file.
#[test]
fn the_tree_s_global_functions_are_called_with_scalars_and_read_opaque() {
    for (file, call) in [
        ("agent-ebpf/src/inode_protect.rs", "nn_window_lift("),
        ("agent-ebpf/src/inode_protect.rs", "nn_ancestor_rename("),
        ("agent-ebpf/src/inode_protect.rs", "nn_bdev_raw("),
        ("agent-ebpf/src/inode_protect.rs", "nn_unit_link("),
        ("agent-ebpf/src/inode_protect.rs", "nn_tree_cgroup_file("),
        ("agent-ebpf/src/task_kill.rs", "nn_tree_target_guarded("),
        ("agent-ebpf/src/task_kill.rs", "nn_in_role_unit("),
        ("agent-ebpf/src/task_limits.rs", "nn_tree_target_guarded("),
        ("agent-ebpf/src/cgroup_guard.rs", "nn_tree_target_guarded("),
        ("agent-ebpf/src/sigio_guard.rs", "nn_tree_member_target("),
    ] {
        let c = code(file);
        let mut at = 0;
        let mut n = 0;
        while let Some(i) = c[at..].find(call) {
            let pos = at + i;
            at = pos + call.len();
            // the definition itself
            if c[..pos].ends_with("fn ") {
                continue;
            }
            n += 1;
            let line_start = c[..pos].rfind('\n').map_or(0, |p| p + 1);
            let line = &c[line_start..c[pos..].find('\n').map_or(c.len(), |p| pos + p)];
            assert!(
                line.contains("opaque("),
                "{file}: `{call}` read raw: {line}"
            );
            assert!(
                !line.contains(" as u64)"),
                "{file}: `{call}` passed a pointer: {line}"
            );
        }
        assert!(n >= 1, "{file}: `{call}` not called");
    }
    // the answer read through the agent's one barrier (a volatile read of a
    // local, `ebpf_barriers` holds its body and that it is the only one)
    assert!(
        code("agent-ebpf/src/window_tree.rs")
            .contains("pub(crate) fn opaque(v: u64) -> u64 {\n    crate::opaque::opaque(v)\n}")
    );
}

/// Lot 2.3a: the tree's LSM programs are in the lab's list of ours, and
/// the module is the object's.
#[test]
fn the_tree_programs_are_listed() {
    let names =
        fs::read_to_string(repo_root().join("deploy/lab/lib/our-lsm-programs.txt")).unwrap();
    for p in [
        "tree_bprm_check",
        "tree_bprm_commit",
        "tree_fd_receive",
        "tree_mmap_file",
        "tree_mprotect",
        "tree_ptrace",
        "tree_task_free",
    ] {
        assert!(names.lines().any(|l| l == p), "{p}");
    }
    assert!(code("agent-ebpf/src/main.rs").contains("mod window_tree;"));
}

/// Lot 2.3a (the review of #647): the fork span — a member's child is a
/// member from `task_alloc` on (by its `task_struct`), confirmed at
/// `sched_process_fork`, its span dropped at the free; the guards also hold
/// a task in `TASK_NEW` and a member's child; the caller is judged by the
/// lift test (a traced member is an outsider); a record of what was let
/// through takes no window class; an executable SysV segment is judged.
#[test]
fn the_fork_span_and_a_traced_caller_are_guarded_and_let_throughs_take_no_class() {
    let w = code("agent-ebpf/src/window_tree.rs");
    in_order(
        body(&w, "tree_task_alloc"),
        &[
            "TREE_MEMBERS.get(&ptgid).is_none()",
            "nn_tree_pending(raw_arg(&ctx, 0), raw_arg(&ctx, 1))",
        ],
    )
    .unwrap();
    in_order(
        body(&w, "nn_tree_pending"),
        &[
            "clone_flags & CLONE_THREAD != 0",
            "nn_tree_member_now() != MEMBER_LIFT",
            "TREE_PENDING.insert(&child, &g.generation, 0)",
        ],
    )
    .unwrap();
    in_order(
        body(&w, "try_fork"),
        &[
            "let _ = TREE_PENDING.remove(&(child as u64));",
            "let v = nn_tree_member_now();",
            "TREE_MEMBERS.insert(&ctgid, &entry, 0)",
        ],
    )
    .unwrap();
    in_order(
        body(&w, "tree_task_free"),
        &[
            "let _ = TREE_PENDING.remove(&(task as u64));",
            "read_u32(task.add(off!(TASK_STRUCT_TGID_OFFSET)))",
        ],
    )
    .unwrap();
    in_order(
        body(&w, "target_in_span"),
        &[
            "TREE_PENDING.get(&(target as u64))",
            "off_opt!(TASK_STRUCT_STATE_OFFSET)",
            "TASK_STRUCT_REAL_PARENT_OFFSET",
            "holds_entry(ptgid, p, generation)",
            "in_tree_span(pending, state, parent_member)",
        ],
    )
    .unwrap();
    let g = body(&w, "nn_tree_target_guarded");
    in_order(
        g,
        &[
            "caller == ttgid || crate::task_kill::is_exempt_pid(caller)",
            "!holds_entry(ttgid, target, generation) && !target_in_span(target, generation, true)",
            "u64::from(member_now() != MEMBER_LIFT)",
        ],
    )
    .unwrap();
    assert!(
        !g.contains("caller_is_member"),
        "the caller is judged by the lift test"
    );
    assert!(
        body(&w, "nn_tree_member_target").contains("target_in_span(target, g.generation, false)")
    );
    in_order(
        body(&w, "tree_shmat"),
        &[
            "raw_arg(&ctx, 2) & SHM_EXEC != 0",
            "nn_tree_judge_file(0, EVICT_MAP)",
        ],
    )
    .unwrap();
    in_order(
        body(&w, "nn_tree_cgroup_file"),
        &[
            "TREE_CGROUP_FILES.get(&key)",
            "generation != g.generation || !tree_open(g, bpf_ktime_get_boot_ns(), session())",
            "crate::task_kill::is_exempt_pid(caller) || member_now() == MEMBER_LIFT",
            "emit_attempt(FS_OP_CGROUP_FREEZE, key);",
            "emit_attempt(FS_OP_CGROUP_KILL, key);",
        ],
    )
    .unwrap();
    let i = code("agent-ebpf/src/inode_protect.rs");
    in_order(
        body(&i, "emit_denial"),
        &[
            "if northnarrow_common::window_tree::window_classes(operation) {",
            "crate::window_tree::nn_window_class(u64::from(operation), key.ino) as u8",
            "northnarrow_common::wire::DENIAL_WINDOW_NONE",
            "FS_PROTECT_EVENTS.reserve::<FsProtectDenialRaw>(0)",
        ],
    )
    .unwrap();
    // D7: a member's limits and its cgroup move, from outside its tree
    let l = code("agent-ebpf/src/task_limits.rs");
    in_order(
        body(&l, "task_setrlimit_deny"),
        &[
            "refuse_task_change(task, FS_OP_RLIMIT, resource as u64, hook::TASK_SETRLIMIT)",
            "nn_tree_target_guarded(crate::window_tree::raw_arg(&ctx, 0))",
            "emit_task_denial(FS_OP_RLIMIT, resource as u64, tgid);\n            return -EPERM;",
        ],
    )
    .unwrap();
    let c = code("agent-ebpf/src/cgroup_guard.rs");
    in_order(
        body(&c, "try_cgroup_move_stash"),
        &[
            "if crate::task_kill::is_protected_pid(tgid) {",
            "} else if crate::window_tree::opaque(crate::window_tree::nn_tree_target_guarded(task)) == 0 {",
            "CGROUP_MOVES.insert(&pid_tgid, &rec, 0)",
        ],
    )
    .unwrap();
    // the tree's programs and the manifest's fields, in the attach list
    let a = code("crates/nn-linux/src/anti_tamper/window_tree.rs");
    for p in [
        "(\"tree_task_alloc\", Kind::Lsm, \"task_alloc\")",
        "(\"tree_shmat\", Kind::Lsm, \"shm_shmat\")",
        "\"TASK_STRUCT_STATE_OFFSET\"",
        "\"VM_AREA_STRUCT_VM_FLAGS_OFFSET\"",
        "super::filesystem::key_files_not_kept(root)",
    ] {
        assert!(a.contains(p), "{p}");
    }
}

/// Lot 2.3b (D5, the freeze of the system code): every mutation hook of
/// `inode_protect` asks the freeze after its own refusals — the write-open,
/// the removals, the renames (both entries), the attribute changes, the
/// new entries (through one helper every creating program calls) and the
/// extended attributes — and two programs of the tree ask it for a mount
/// on or over a frozen object. The freeze judges only an outsider: the
/// agent's family and a member the window lifts for come first; then the
/// object's name in its directory and a bounded walk of its directories,
/// each mark of the window's generation.
#[test]
fn the_freeze_is_asked_at_every_mutation_hook_and_judges_outsiders_only() {
    let ip = code("agent-ebpf/src/inode_protect.rs");
    for (f, needle) in [
        ("try_inode_unlink", "frozen(dentry_s, FS_OP_UNLINK)"),
        ("try_inode_rmdir", "frozen(crate::window_tree::raw_arg(ctx, 1), FS_OP_RMDIR)"),
        ("try_inode_rename", "frozen(old_s, FS_OP_RENAME) || frozen(new_s, FS_OP_RENAME)"),
        ("try_inode_setattr", "frozen(dentry as u64, FS_OP_SETATTR)"),
        ("try_protected_open_deny", "frozen(dentry, FS_OP_WRITE)"),
        ("deny_xattr", "frozen(dentry as u64, FS_OP_XATTR)"),
        ("deny_new_frozen", "frozen(crate::window_tree::raw_arg(ctx, dentry_arg), operation)"),
    ] {
        assert!(body(&ip, f).contains(needle), "{f}: {needle}");
    }
    for p in [
        "protected_create_deny",
        "protected_mkdir_deny",
        "protected_mknod_deny",
        "protected_symlink_deny",
        "protected_link_deny",
    ] {
        assert!(body(&ip, p).contains("deny_new_frozen(&ctx,"), "{p}");
    }
    assert!(body(&ip, "protected_link_deny").contains(", 2, hook::INODE_LINK"), "the new name");
    assert!(body(&ip, "frozen").contains("nn_tree_frozen(dentry, u64::from(operation))"));
    let w = code("agent-ebpf/src/window_tree.rs");
    in_order(
        body(&w, "nn_tree_frozen"),
        &[
            "tree_open(g,",
            "is_exempt_pid(",
            "member_now() == MEMBER_LIFT",
            "name_frozen(d0, parent, generation)",
            "while level < FREEZE_WALK",
            "frozen_verdict(FROZEN_INODES.get(&key), generation, level)",
            "emit_attempt(op, key)",
        ],
    )
    .unwrap();
    assert!(body(&w, "name_frozen").contains("frozen_verdict(FROZEN_NAMES.get(&key), generation, 0)"));
    for p in ["tree_frz_mount", "tree_frz_move"] {
        assert!(body(&w, p).contains("frozen_path(raw_arg(&ctx, 1))"), "{p}");
    }
    assert!(body(&w, "frozen_path").contains("nn_tree_frozen(dentry as u64, u64::from(FS_OP_MOUNT))"));
    let names =
        fs::read_to_string(repo_root().join("deploy/lab/lib/our-lsm-programs.txt")).unwrap();
    for p in ["tree_frz_mount", "tree_frz_move"] {
        assert!(names.lines().any(|l| l == p), "{p}");
    }
    let linux = code("crates/nn-linux/src/anti_tamper/window_tree.rs");
    assert!(linux.contains("(\"tree_frz_mount\", Kind::Lsm, \"sb_mount\")"));
    assert!(linux.contains("(\"tree_frz_move\", Kind::Lsm, \"move_mount\")"));
}

/// Lot 2.3b (the single-use leases): a lease is consumed in the unlink hook
/// only, before its other refusals, for PID 1 only, in a directory of our
/// units' links and for one of their names; the slot is the window's,
/// unused, before its deadline, for that very link and the removal; it is
/// marked used and its use signed in the PID-1-lease class.
#[test]
fn a_lease_is_consumed_once_by_pid1_s_removal_of_our_link_only() {
    let ip = code("agent-ebpf/src/inode_protect.rs");
    // the typed arguments read before the raw ones (5.15's verifier refused
    // the typed load through the context pointer a raw read had moved)
    in_order(
        body(&ip, "try_inode_unlink"),
        &[
            "let parent: *const c_void = ctx.arg(0);",
            "let dentry: *const c_void = ctx.arg(1);",
            "raw_arg(ctx, 0), crate::window_tree::raw_arg(ctx, 1)",
            "nn_tree_lease(dir_s, dentry_s)",
            "return 0;",
            "deny_if_protected(FS_OP_UNLINK, parent",
        ],
    )
    .unwrap();
    let mut callers = 0;
    for (f, src) in ebpf_files() {
        callers += src.matches("nn_tree_lease(").count();
        if f != "inode_protect.rs" && f != "window_tree.rs" {
            assert!(!src.contains("nn_tree_lease("), "{f}");
        }
    }
    // its definition and its one call
    assert_eq!(callers, 2);
    let w = code("agent-ebpf/src/window_tree.rs");
    in_order(
        body(&w, "nn_tree_lease"),
        &[
            "if caller != 1",
            "tree_open(g, now, s)",
            "INODE_EXT.get(&key)",
            "lease_applies(caller, ext, &w)",
            "usable_for(g, key, hash, LEASE_REMOVE, now, s)",
            "(*l).used = 1;",
            "WINDOW_EVENT_LEASE_USED",
            "DENIAL_WINDOW_PID1_LEASE",
            "return 1;",
        ],
    )
    .unwrap();
}

/// Lot 2.3b (D2, D1): `window-run` starts its command with the sanitised
/// environment only (cleared, then the allowlist and the window's number)
/// and `/dev/null` as stdin unless `--interactive`; the tree grant's
/// handler arms the tree only, never the host-wide window nor PID 1's stop
/// grant; and a member's request is authenticated before it acts.
#[test]
fn window_run_sanitises_and_the_member_requests_are_authenticated_first() {
    let cli = code("crates/nn-admin/src/cli.rs");
    in_order(
        body(&cli, "run_window_run_cmd"),
        &[
            "tree_grant_reply(\"window-run\"",
            "window_run_env(",
            ".env_clear()",
            ".envs(env)",
            ".env(\"NN_WINDOW_GENERATION\"",
            "if !interactive",
            "Stdio::null()",
            "cmd.status()",
        ],
    )
    .unwrap();
    let inst = code("agent/src/admin/handlers/installer.rs");
    let tg = body(&inst, "tree_grant");
    in_order(tg, &["interactive_refusal(", "admit_line(", "(host.pregrant)()", "ov.arm_tree("]).unwrap();
    for host_wide in ["arm_for(", "arm_by(", ".arm(", "write_kill_grant", "legacy_arming"] {
        assert!(!tg.contains(host_wide), "the tree grant arms {host_wide}");
    }
    let win = code("agent/src/admin/handlers/window.rs");
    in_order(
        body(&win, "dispatch_window_control"),
        &["ov.window_member(requester, req.generation)", "ov.controlled_stop(", "write_marker(", ".fire()"],
    )
    .unwrap();
    in_order(
        body(&win, "dispatch_window_lease"),
        &["ov.window_member(requester, req.generation)", "ov.arm_lease("],
    )
    .unwrap();
    let ti = code("crates/nn-linux/src/anti_tamper/trusted_installer.rs");
    in_order(
        body(&ti, "window_member_with"),
        &["reader.pin(requester)", "reader.hop(requester)", "maps.member(requester)", "reader.guards(requester)", "reader.ns_initial(requester)", "pin.alive()"],
    )
    .unwrap();
    // the admission pins each process before it reads it, and checks them after
    in_order(body(&ti, "walk_line"), &["pins.push((pid, reader.pin(pid)?))", "reader.hop(pid)?"]).unwrap();
    assert!(body(&ti, "admit_line").contains("check_pins(&line, &pins)?"));
}
