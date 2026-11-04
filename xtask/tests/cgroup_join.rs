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
    // marks that outlive a restart, an entry allocated per mark (the agent
    // sizes the map to the host: the review of #494, D2); the bitmap of the
    // groups not known, preallocated; the counters with them
    // the tracker's maps are pinned where the agent says (its own
    // directory beside the pin root, the re-review of #494, R2), not by
    // name into the pin root, which an upgrade purges
    assert!(j.contains(
        "pub static CGROUP_JOINED: HashMap<u32, [u64; 2]> =\n    HashMap::with_max_entries(JOINED_ENTRIES, BPF_F_NO_PREALLOC);"
    ));
    assert!(j.contains("const BPF_F_NO_PREALLOC: u32 = 1;"));
    assert!(j.contains(
        "pub static CGROUP_JOIN_LOST: Array<[u8; LOST_BYTES]> = Array::with_max_entries(LOST_SLOTS, 0);"
    ));
    assert!(j.contains(
        "pub static CGROUP_JOIN_STATS: Array<u64> = Array::with_max_entries(STAT_SLOTS, 0);"
    ));
    assert!(
        !j.contains("::pinned("),
        "no map of the tracker pinned into the pin root"
    );
    assert!(!j.contains("LruHashMap"));
    // the re-review of #494, R1: no read-modify-write of the "not known"
    // state — a byte a tgid, a plain store of 1 or 0
    assert!(!j.contains("atomic_xadd") && !j.contains("xadd("));
    assert!(!code("agent-ebpf/src/main.rs").contains("core_intrinsics"));
    in_order(
        body(&j, "lost_byte"),
        &[
            "let (slot, byte) = lost_slot(tgid)?;",
            "CGROUP_JOIN_LOST.get_ptr_mut(slot)?",
            "(entry as *mut u8).add(byte & (LOST_BYTES - 1))",
        ],
    )
    .unwrap();
    // a mark refused puts the group's byte to 1 (that group not known,
    // never the host: the review of #494, D2), counted
    in_order(
        body(&j, "mark"),
        &[
            "if CGROUP_JOINED.insert(&tgid, &rec, 0).is_err() {",
            "lose(tgid);\n        return false;",
        ],
    )
    .unwrap();
    in_order(
        body(&j, "lose"),
        &[
            "count(STAT_LOST);",
            "if let Some(b) = lost_byte(tgid) {",
            "unsafe { core::ptr::write_volatile(b, 1) };",
        ],
    )
    .unwrap();
    assert!(body(&j, "found").contains("unsafe { core::ptr::write_volatile(b, 0) };"));
    assert!(body(&j, "is_lost")
        .contains("lost_byte(tgid).is_some_and(|b| unsafe { core::ptr::read_volatile(b) } != 0)"));
    // the source of a self-move, cleared for every write
    in_order(
        body(&j, "try_src"),
        &[
            "*slot = [0, 0];",
            "args.add(CGROUP_MOVE_RET_ARG)",
            "task >= 0u64.wrapping_sub(MAX_ERRNO)",
            // the review of #494, B1: the writing thread itself
            "if task == bpf_get_current_task() {\n        *slot = [bpf_get_current_pid_tgid(), generated::bpf_get_current_cgroup_id()];",
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
            // the re-review of #494, N-b: the writer's own tgid unread is
            // not known; another task's is counted
            "let Some(moved) = tgid_of(task) else {",
            "if task == bpf_get_current_task() {\n            lose(writer);\n        } else {\n            count(STAT_LOST);\n        }",
            "let Some(start) = leader_start(task) else {\n        lose(moved);",
            // the review of #494, B1: the shared `noop`, the moved task the
            // writing thread itself (its behaviour: common's
            // `a_noop_is_the_writing_thread_staying_where_it_is`, the
            // privileged `a_threaded_move_of_the_leader_is_marked`)
            "Some(src) => (src[0] == pid_tgid, src[1]),",
            "let unchanged = noop(\n        task == bpf_get_current_task(),\n        src_this_write,\n        src_id,\n        generated::bpf_get_current_cgroup_id(),\n    );",
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
    // there); a path unread or cut (a full buffer: the review of #494, D1)
    // is "any"; no counter
    in_order(
        body(&j, "exempt_destination"),
        &[
            "CGROUP_EXEMPT_NAMES.get(&0).is_some()",
            "bpf_probe_read_kernel_str(",
            "match path_read(n) {\n        PathRead::Unread | PathRead::Cut => return Some(0),\n        PathRead::Whole => {}\n    }",
            "for i in 0..PATH_READ {",
            "if b == 0 {\n            break;\n        }",
            "full = fnv_step(full, b);",
            "if b == b'/' {\n            if is_name(comp, NAME_UNIT) {\n                hit = comp;\n            }\n            comp = FNV_OFFSET;\n        } else {\n            comp = fnv_step(comp, b);\n        }",
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
    // every new thread group's tgid cleared of a dead group's mark and bit
    // (the review of #494, N5; its behaviour: the privileged
    // `a_dead_group_s_mark_is_not_the_next_owner_s`), then CLONE_INTO_CGROUP
    // by anyone but PID 1 and the family, a new process; flags unread is
    // not known
    in_order(
        body(&j, "try_born"),
        &[
            "if tgid == forker {\n        return;\n    }",
            "if CGROUP_JOINED.get(&tgid).is_some() {\n        let _ = CGROUP_JOINED.remove(&tgid);\n    }\n    found(tgid);",
            "if kargs == 0 {\n        lose(tgid);\n        return;\n    }",
            "off!(KERNEL_CLONE_ARGS_FLAGS_OFFSET) as u64) else {\n        lose(tgid);",
            "if flags & CLONE_INTO_CGROUP == 0 {\n        return;\n    }",
            "if forker == 1 || family(forker) {\n        return;\n    }",
            "if mark(tgid, start, HOW_BORN_INTO, forker) {",
        ],
    )
    .unwrap();
    assert_eq!(
        j.matches("found(").count(),
        2,
        "the bit cleared at a new group's fork only (its definition and one call)"
    );
    // a fork of a marked process — the mark this process's, by its
    // leader's start — passes the mark to a new process
    in_order(
        body(&j, "try_fork"),
        &[
            "let parent: u64 = ctx.arg(0);",
            "let child: u64 = ctx.arg(1);",
            "let marked = match CGROUP_JOINED.get(&ptgid) {\n        Some(rec) => leader_start(parent) == Some(rec[0]),\n        None => false,\n    };",
            "let lost = is_lost(ptgid);",
            "if !marked && !lost {\n        return;\n    }",
            "if ctgid == ptgid {\n        return;\n    }",
            "if lost {\n        lose(ctgid);\n        return;\n    }",
            "if mark(ctgid, start, HOW_INHERITED, ptgid) {",
        ],
    )
    .unwrap();
    // the mark goes with the group's last thread, not its leader
    in_order(
        body(&j, "try_exit"),
        &[
            "if CGROUP_JOINED.get(&tgid).is_none() {\n        return;\n    }",
            "off!(TASK_STRUCT_SIGNAL_OFFSET)",
            "if rd_u32(signal + off!(SIGNAL_STRUCT_LIVE_OFFSET) as u64) == Some(0) {\n        let _ = CGROUP_JOINED.remove(&tgid);\n    }",
        ],
    )
    .unwrap();
    assert!(!body(&j, "try_exit").contains("found("));
    assert_eq!(
        j.matches("CGROUP_JOINED.remove(").count(),
        2,
        "removed at the group's death and at its tgid's next fork only"
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
            ".is_some_and(|g| g == c && !in_containment(g))\n                    && started_here()",
            "Exemption::Unit(u) => {",
            ".filter(|g| !in_containment(g))",
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
    // one errand: the group's byte refuses its answer (that group's only,
    // the review of #494, D2), a mark is "not started here", only a missing
    // key is "started here" — the same reads as the privileged test's
    // (`lost_in`, `mark_in`: its behaviour is that test's)
    assert!(!body(&cj, "started").contains("STAT_LOST"));
    in_order(
        body(&cj, "started"),
        &[
            "crate::caps::errands::run(move || {",
            "if lost_in(&lost.lock(), tgid).ok()? {\n                return None;\n            }",
            "mark_in(&joined.lock(), tgid).ok().map(|m| m.is_none())",
        ],
    )
    .unwrap();
    in_order(
        body(&cj, "mark_in"),
        &[
            "Ok([_, info]) => {",
            "Err(aya::maps::MapError::KeyNotFound) => Ok(None),",
            "Err(e) => Err(e.to_string()),",
        ],
    )
    .unwrap();
    assert!(body(&cj, "lost_in").contains("[byte] != 0)"));
    assert!(body(&cj, "pinned_lost").contains("lost_in(&map, tgid)"));
    assert!(body(&cj, "pinned_mark").contains("mark_in(&map, tgid)"));
    // all or none: a program that fails unloads those before it; with a
    // bpffs every link pinned (the review of #494, D6), the prior boot's
    // removed only once the new one is attached
    let att = body(&cj, "attach");
    in_order(
        att,
        &[
            "if let Some(why) = unavailable() {",
            "purge_legacy_pins(root);",
            "purge_pin_dir(&d);",
            "return (Tracker::Absent(why), None);",
            // the re-review of #494, R2: the tracker's own directory, a
            // refused one is no tracker
            "(Some(_), Some(Err(why))) => {",
            "Tracker::Absent(format!(\"the tracker's pin directory: {why}\")),",
            "if let Err(e) = load_only(ebpf, btf, name, *kind, target) {\n                    for (n, k, _) in &PROGRAMS[..=i] {\n                        unload(ebpf, n, *k);\n                    }",
            "if let Err(e) = pin_fresh(ebpf, dir, name, *kind) {",
            // the old layout's directory goes after the new programs run,
            // and says so
            "let old = other_pin_dirs(root, Some(dir));",
            "purge_pin_dir(d);",
            "reset = Some(why);",
            "if let Err(e) = load_attach(ebpf, btf, name, *kind, target) {\n                    for (n, k, _) in &PROGRAMS[..=i] {\n                        unload(ebpf, n, *k);\n                    }",
        ],
    )
    .unwrap();
    // the swap's order: mark before src (the re-review of #494, N-f)
    let progs = &cj[cj.find("pub const PROGRAMS").unwrap()..];
    assert!(
        progs.find("\"cgroup_join_mark\"").unwrap() < progs.find("\"cgroup_join_src\"").unwrap()
    );
    // the loader pins the three maps in the tracker's directory, made
    // before the load, never through a link
    in_order(
        body(&cj, "prepare_pins"),
        &[
            "common::cgroup_join::pin_dir(",
            "antitamper_bpf::pin_root_refusal_at(&dir)",
            "DirBuilder::new().mode(0o700).create(&dir)",
            "for name in PINNED_MAPS {\n            loader.map_pin_path(name, dir.join(name));",
        ],
    )
    .unwrap();
    let mx = code("crates/nn-linux/src/sensors/multiplexer.rs");
    in_order(
        &mx,
        &[
            "let joined_entries = crate::cgroup_join::joined_entries_now();",
            "loader.map_max_entries(crate::cgroup_join::JOINED_MAP, joined_entries);",
            "crate::cgroup_join::prepare_pins(&mut loader, pin_root, joined_entries);",
            ".load(EBPF_BYTES)",
        ],
    )
    .unwrap();
    // the test knob exists in debug-trigger builds only
    in_order(
        body(&cj, "joined_entries_now"),
        &[
            "#[cfg(feature = \"debug-trigger\")]",
            "std::env::var(\"NN_DEBUG_CGROUP_JOINED_ENTRIES\")",
        ],
    )
    .unwrap();
    in_order(
        body(&cj, "pin_fresh"),
        &[
            "let id = p.attach()",
            "antitamper_bpf::purge_stale_pin(&link_path);",
            "prog.pin(&prog_path)",
            "fd_link\n        .pin(&link_path)",
        ],
    )
    .unwrap();
    let at = code("crates/nn-linux/src/anti_tamper/mod.rs");
    in_order(
        &at,
        &[
            "let (tracker, reset) = crate::cgroup_join::attach(ebpf, &btf, pin_root);",
            "if let Some(why) = reset {\n        report.degraded.push(format!(\"cgroup exemptions: {why}\"));",
            "crate::cgroup_join::Tracker::Absent(why) => report.degraded.push(format!(",
            "crate::cgroup_join::install(tracker);",
            // the tracker's pins protected like the root's
            "if let Some(dir) = crate::cgroup_join::pin_dir_now() {\n        if let Err(e) = filesystem::register_bpffs_pins(ebpf, dir) {",
            "filesystem::prune_stale_inodes(ebpf)",
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
    assert!(body(&s, "refuse_threaded").contains("one_thread(thread_count())"));
    in_order(
        body(&s, "one_thread"),
        &[
            "Ok(1) => Ok(()),",
            "Ok(n) => Err(SandboxError::Threaded(n)),",
            "Err(e) =>",
        ],
    )
    .unwrap();
}
