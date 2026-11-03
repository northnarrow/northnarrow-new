//! Lot 277: the start-in-cgroup tracker — the parts no host test runs.
//!
//! The eBPF programs run only in a kernel (the lab's `exempt-check` shows
//! what they mark); the decision they take is `common::cgroup_join`'s,
//! unit-tested there. Here the programs' code is read, as
//! `cgroup_guard.rs` reads the move guard's: each check the exemption's
//! safety rests on is there, in the order that makes it hold, and the agent
//! asks the marks where it decides.

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

#[test]
fn the_tracker_marks_every_start_outside_its_cgroup_and_what_it_forks() {
    let j = code("agent-ebpf/src/cgroup_join.rs");
    // attach points, the agent's table and the BTF shapes alike
    for a in [
        "#[fexit(function = \"cgroup_procs_write_start\")]\npub fn cgroup_join_src(",
        "#[btf_tracepoint(function = \"cgroup_attach_task\")]\npub fn cgroup_join_mark(",
        "#[fentry(function = \"cgroup_post_fork\")]\npub fn cgroup_join_born(",
        "#[btf_tracepoint(function = \"sched_process_fork\")]\npub fn cgroup_join_fork(",
        "#[btf_tracepoint(function = \"sched_process_exit\")]\npub fn cgroup_join_exit(",
    ] {
        assert!(j.contains(a), "{a}");
    }
    // marks that never evict and outlive a restart; the counters with them
    assert!(j.contains(
        "pub static CGROUP_JOINED: HashMap<u32, [u64; 2]> = HashMap::pinned(JOINED_ENTRIES, 0);"
    ));
    assert!(j.contains("pub static CGROUP_JOIN_STATS: Array<u64> = Array::pinned(STAT_SLOTS, 0);"));
    assert!(!j.contains("LruHashMap"));
    // a mark refused is counted (every exemption by cgroup or unit is then
    // refused by the agent)
    in_order(
        body(&j, "mark"),
        &[
            "if CGROUP_JOINED.insert(&tgid, &rec, 0).is_err() {",
            "count(STAT_LOST);\n        return false;",
        ],
    )
    .unwrap();
    // the source of a self-move, cleared for every write
    in_order(
        body(&j, "try_src"),
        &[
            "*slot = [0, 0];",
            "args.add(CGROUP_MOVE_RET_ARG)",
            "task >= 0u64.wrapping_sub(MAX_ERRNO)",
            "if tgid_of(task) == Some((pid_tgid >> 32) as u32) {\n        *slot = [pid_tgid, generated::bpf_get_current_cgroup_id()];",
        ],
    )
    .unwrap();
    // the move: the family skipped, a mark it cannot read is counted, a
    // no-op only for a self-move whose cgroup did not change, the parent's
    // image compared by its file, systemd's placement decided by the shared
    // function, then the mark, then the signed record for an exempt name
    in_order(
        body(&j, "try_mark"),
        &[
            "let task: u64 = ctx.arg(2);",
            "if family(writer) {\n        return;\n    }",
            "let Some(moved) = tgid_of(task) else {\n        count(STAT_LOST);",
            "let Some(start) = leader_start(task) else {\n        count(STAT_LOST);",
            "let unchanged = writer == moved\n        && match CGROUP_JOIN_SRC.get(0) {\n            Some(src) => src[0] == pid_tgid && src[1] == generated::bpf_get_current_cgroup_id(),\n            None => false,\n        };",
            "off!(TASK_STRUCT_REAL_PARENT_OFFSET)",
            "let pre_exec = parent_tgid == 1\n        && match (exe_file(task), exe_file(parent)) {\n            (Some(a), Some(b)) => a == b,\n            _ => false,\n        };",
            "match placement(writer, moved, parent_tgid, pre_exec, unchanged) {\n        Move::Placement | Move::NoOp => return,\n        Move::Mark => {}\n    }",
            "if mark(moved, start, HOW_MOVED, writer) {",
            "if let Some(hash) = exempt_destination(path) {",
            "crate::inode_protect::emit_limited(\n            FS_OP_CGROUP_JOIN,",
            "ino: u64::from(moved),",
        ],
    )
    .unwrap();
    // the destination's names: the whole path and each component, as
    // `common::cgroup_join::match_destination` walks them (unit-tested
    // there); a path not ended inside the read is "any"; no counter
    in_order(
        body(&j, "exempt_destination"),
        &[
            "CGROUP_EXEMPT_NAMES.get(&0).is_some()",
            "bpf_probe_read_kernel_str(",
            "if n <= 0 {\n        return Some(0);\n    }",
            "for i in 0..PATH_READ {",
            "if b == 0 {\n            ended = true;\n            break;\n        }",
            "full = fnv_step(full, b);",
            "if b == b'/' {\n            if is_name(comp, NAME_UNIT) {\n                hit = comp;\n            }\n            comp = FNV_OFFSET;\n        } else {\n            comp = fnv_step(comp, b);\n        }",
            "if !ended {\n        return Some(0);\n    }",
            "if is_name(comp, NAME_UNIT) {\n        hit = comp;\n    }",
            "if is_name(full, NAME_CGROUP) {\n        return Some(full);\n    }",
            "(hit != 0).then_some(hit)",
        ],
    )
    .unwrap();
    assert!(body(&j, "is_name").contains("*k & kind != 0"));
    let shared = code("common/src/cgroup_join.rs");
    in_order(
        body(&shared, "match_destination"),
        &[
            "full = fnv_step(full, b);",
            "if b == b'/' {\n            if kinds(comp) & NAME_UNIT != 0 {\n                hit = comp;\n            }\n            comp = FNV_OFFSET;\n        } else {\n            comp = fnv_step(comp, b);\n        }",
            "if kinds(comp) & NAME_UNIT != 0 {\n        hit = comp;\n    }",
            "if kinds(full) & NAME_CGROUP != 0 {\n        return Some(full);\n    }",
            "(hit != 0).then_some(hit)",
        ],
    )
    .unwrap();
    // CLONE_INTO_CGROUP by anyone but PID 1 and the family, a new process
    in_order(
        body(&j, "try_born"),
        &[
            "off!(KERNEL_CLONE_ARGS_FLAGS_OFFSET)",
            "if flags & CLONE_INTO_CGROUP == 0 {\n        return;\n    }",
            "if forker == 1 || family(forker) {\n        return;\n    }",
            "if tgid == forker {\n        return;\n    }",
            "if mark(tgid, start, HOW_BORN_INTO, forker) {",
        ],
    )
    .unwrap();
    // a fork of a marked process — the mark this process's, by its
    // leader's start — passes the mark to a new process
    in_order(
        body(&j, "try_fork"),
        &[
            "let parent: u64 = ctx.arg(0);",
            "let child: u64 = ctx.arg(1);",
            "let Some(rec) = CGROUP_JOINED.get(&ptgid) else {\n        return;\n    };",
            "if leader_start(parent) != Some(rec[0]) {\n        return;\n    }",
            "if ctgid == ptgid {\n        return;\n    }",
            "if mark(ctgid, start, HOW_INHERITED, ptgid) {",
        ],
    )
    .unwrap();
    // the mark goes with the group's last thread, not its leader
    in_order(
        body(&j, "try_exit"),
        &[
            "off!(TASK_STRUCT_SIGNAL_OFFSET)",
            "if rd_u32(signal + off!(SIGNAL_STRUCT_LIVE_OFFSET) as u64) == Some(0) {\n        let _ = CGROUP_JOINED.remove(&tgid);",
        ],
    )
    .unwrap();
    assert_eq!(
        j.matches("CGROUP_JOINED.remove(").count(),
        1,
        "removed at the group's death only"
    );
    // the start time a mark is keyed with is the leader's
    in_order(
        body(&j, "leader_start"),
        &[
            "off!(TASK_STRUCT_GROUP_LEADER_OFFSET)",
            "off!(TASK_STRUCT_START_TIME_OFFSET)",
        ],
    )
    .unwrap();
}

/// The agent asks the marks for a cgroup or unit exemption only, after the
/// cgroup matched; the tracker is attached all or none, its absence signed.
#[test]
fn the_agent_asks_the_marks_where_it_decides() {
    let rp = code("crates/nn-core/src/decision/rule_policy.rs");
    let ex = body(&rp, "exempt");
    in_order(
        ex,
        &[
            "*started.get_or_insert_with(|| facts.started_in_cgroup(pid)) == Some(true)",
            "Exemption::Cgroup(c) => {",
            ".is_some_and(|g| g == c)\n                    && started_here()",
            "Exemption::Unit(u) => {",
            ".is_some_and(|g| g == u)\n                    && started_here()",
        ],
    )
    .unwrap();
    let pf = code("crates/nn-linux/src/decision_host_linux.rs");
    assert!(pf.contains("crate::cgroup_join::started_in_cgroup(&self.root, pid)"));
    let cj = code("crates/nn-linux/src/cgroup_join.rs");
    in_order(
        body(&cj, "started_in_cgroup"),
        &[
            "let Some(Tracker::Attached(m)) = tracker() else {\n        return None;\n    };",
            "let tgid = tgid_of(proc_root, pid)?;",
            "m.started(tgid)",
        ],
    )
    .unwrap();
    // one errand: a lost mark refuses every answer, a mark is "not started
    // here", only a missing key is "started here"
    in_order(
        body(&cj, "started"),
        &[
            "crate::caps::errands::run(move || {",
            "if stats.lock().get(&STAT_LOST, 0).ok()? != 0 {\n                return None;\n            }",
            "Ok(_) => Some(false),",
            "Err(aya::maps::MapError::KeyNotFound) => Some(true),",
            "Err(_) => None,",
        ],
    )
    .unwrap();
    // all or none: a program that fails unloads those before it
    in_order(
        body(&cj, "attach"),
        &[
            "if let Some(why) = unavailable() {",
            "return Tracker::Absent(why);",
            "if let Err(e) = load_attach(ebpf, btf, name, *kind, target) {\n            for (n, k, _) in &PROGRAMS[..=i] {\n                unload(ebpf, n, *k);\n            }",
            "return Tracker::Absent(e);",
        ],
    )
    .unwrap();
    let at = code("crates/nn-linux/src/anti_tamper/mod.rs");
    in_order(
        &at,
        &[
            "let tracker = crate::cgroup_join::attach(ebpf, &btf);",
            "crate::cgroup_join::Tracker::Absent(why) => report.degraded.push(format!(",
            "crate::cgroup_join::install(tracker);",
        ],
    )
    .unwrap();
    // the policy's names reach the kernel at the start and at every change
    assert!(
        code("agent/src/boot/policy.rs").contains("nn_linux::cgroup_join::sync_names(&policy);")
    );
    assert!(code("agent/src/admin/handlers/config.rs")
        .contains("nn_linux::cgroup_join::sync_names(&rule_policy.current());"));
    // a cgroup_join record raises no tamper trigger, and is signed as such
    let tr = code("crates/nn-core/src/posture/triggers.rs");
    assert!(tr.contains("if *operation != nn_model::FsProtectOperation::CgroupJoin {"));
    let pe = code("agent/src/pipeline/process_event.rs");
    assert!(pe.contains("let joined = *operation == nn_model::FsProtectOperation::CgroupJoin;"));
}

/// The worker's single-thread check is the sandbox's first step, in both
/// entries.
#[test]
fn the_sandbox_counts_its_threads_first() {
    let s = code("crates/nn-linux/src/sandbox/mod.rs");
    in_order(
        body(&s, "enter"),
        &[
            "refuse_threaded()?;",
            "refuse_privileged()?;",
            "harden(profile)?;",
        ],
    )
    .unwrap();
    in_order(
        body(&s, "enter_without_seccomp"),
        &["refuse_threaded()?;", "refuse_privileged()?;"],
    )
    .unwrap();
    in_order(
        body(&s, "refuse_threaded"),
        &[
            "Ok(1) => Ok(()),",
            "Ok(n) => Err(SandboxError::Threaded(n)),",
            "Err(e) =>",
        ],
    )
    .unwrap();
}
