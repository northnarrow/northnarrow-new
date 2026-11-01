//! R14a (plan §3.1, §3.3): the roles of a `PROTECTED_PIDS` entry are read
//! one way in the kernel and written one way in userland.
//!
//! The eBPF hooks read the map only through `task_kill::pid_role`, and ask
//! of it only `is_protected_pid` (a target) or `is_exempt_pid` (a caller),
//! whose bits are `common::wire::pid_role`'s: a lookup that tested mere
//! presence (`PROTECTED_PIDS.get(&pid).is_some()`, every hook's test before
//! R14a) would make a worker exempt. Userland writes an entry only through
//! `antitamper-bpf`'s `insert` (the agent's role) or `insert_role` (the
//! role named): no raw value is written to the map anywhere else.

mod support;

use std::fs;

use support::{repo_root, strip_comments};

fn rs_files(dir: &std::path::Path) -> Vec<std::path::PathBuf> {
    let mut out = Vec::new();
    support::rs_files(dir, &mut out);
    out.sort();
    out
}

#[test]
fn every_kernel_lookup_of_protected_pids_goes_through_the_roles() {
    let dir = repo_root().join("agent-ebpf/src");
    let mut bad = Vec::new();
    let mut readers = 0;
    for f in rs_files(&dir) {
        let rel = f.strip_prefix(repo_root()).unwrap().display().to_string();
        let code = strip_comments(&fs::read_to_string(&f).unwrap());
        for (at, _) in code.match_indices("PROTECTED_PIDS.") {
            let line = code[..at].matches('\n').count() + 1;
            let rest = &code[at..code[at..].find('\n').map_or(code.len(), |e| at + e)];
            if rel.ends_with("task_kill.rs")
                && rest.starts_with("PROTECTED_PIDS.get(&tgid).copied().unwrap_or(0)")
            {
                readers += 1;
                continue;
            }
            bad.push(format!("{rel}:{line}: `{}`", rest.trim()));
        }
    }
    assert!(
        bad.is_empty(),
        "PROTECTED_PIDS read outside task_kill::pid_role:\n{}",
        bad.join("\n")
    );
    assert_eq!(readers, 1, "task_kill::pid_role reads the map once");
    // and the roles are nn-wire's bits, asked through the two questions
    let task_kill = fs::read_to_string(dir.join("task_kill.rs")).unwrap();
    assert!(task_kill.contains("northnarrow_common::wire::pid_role::is_protected(pid_role(tgid))"));
    assert!(task_kill.contains("northnarrow_common::wire::pid_role::is_exempt(pid_role(tgid))"));
    // each hook asks the right question: a target is protected, a caller
    // exempt — a caller asked "protected" would make a worker exempt
    // (`(file, is_protected_pid( calls, is_exempt_pid( calls)`, the
    // definitions in task_kill.rs counted)
    for (file, protected, exempt) in [
        ("task_kill.rs", 2, 3),
        ("ptrace_check.rs", 1, 1),
        ("inode_protect.rs", 0, 1),
        ("bpf_defense.rs", 0, 1),
        ("fim_watch.rs", 0, 1),
        ("execq.rs", 0, 2),
    ] {
        let code = strip_comments(&fs::read_to_string(dir.join(file)).unwrap());
        assert_eq!(
            (
                code.matches("is_protected_pid(").count(),
                code.matches("is_exempt_pid(").count()
            ),
            (protected, exempt),
            "{file}: the roles asked"
        );
    }
    let mut others = Vec::new();
    for f in rs_files(&dir) {
        let name = f.file_name().unwrap().to_string_lossy().to_string();
        if [
            "task_kill.rs",
            "ptrace_check.rs",
            "inode_protect.rs",
            "bpf_defense.rs",
            "fim_watch.rs",
            "execq.rs",
        ]
        .contains(&name.as_str())
        {
            continue;
        }
        let code = strip_comments(&fs::read_to_string(&f).unwrap());
        if code.contains("is_protected_pid(") || code.contains("is_exempt_pid(") {
            others.push(name);
        }
    }
    assert!(
        others.is_empty(),
        "a hook not in the table asks the roles: {others:?}"
    );
}

#[test]
fn every_userland_write_of_protected_pids_names_a_role() {
    let lib = fs::read_to_string(repo_root().join("antitamper-bpf/src/lib.rs")).unwrap();
    let code = strip_comments(&lib);
    // the one raw insert is insert_role's, with a refused unknown role
    assert_eq!(code.matches(".insert(pid, role, 0)").count(), 1);
    assert!(code.contains("if role != pid_role::AGENT && role != pid_role::WORKER {"));
    // a raw 1 is PROTECTED_OBSERVERS's (another map, presence only)
    let observers = &code[code
        .find("impl<T> ProtectedObserversHandle<T>")
        .unwrap_or(0)..];
    assert_eq!(
        code.matches(".insert(pid, 1u8, 0)").count(),
        observers.matches(".insert(pid, 1u8, 0)").count()
    );
    // nowhere else in userland is the map written with a value
    let mut bad = Vec::new();
    for top in ["agent/src", "crates", "watchdog/src"] {
        for f in rs_files(&repo_root().join(top)) {
            let rel = f.strip_prefix(repo_root()).unwrap().display().to_string();
            let code = strip_comments(&fs::read_to_string(&f).unwrap());
            if code.contains("PROTECTED_PIDS_MAP_NAME") && code.contains("HashMap::<_, u32, u8>") {
                bad.push(rel);
            }
        }
    }
    assert!(
        bad.is_empty(),
        "PROTECTED_PIDS written outside antitamper-bpf: {bad:?}"
    );
    // the worker supervisor registers WORKER, nothing else
    let sup =
        fs::read_to_string(repo_root().join("crates/nn-linux/src/worker/supervisor.rs")).unwrap();
    assert!(sup.contains("insert_role(pid, antitamper_bpf::pid_role::WORKER)"));
    assert!(!strip_comments(&sup).contains("pid_role::AGENT"));
}
