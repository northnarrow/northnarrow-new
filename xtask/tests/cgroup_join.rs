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
        // lot 281: the injection taint's two LSM programs
        "#[lsm(hook = \"ptrace_access_check\")]\npub fn cgroup_join_inject(",
        "#[lsm(hook = \"ptrace_traceme\")]\npub fn cgroup_join_traceme(",
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
    // the third review of #494, R2-a: the last reset's instant, and a
    // parent started before it (not PID 1, not the family; unread: before)
    assert!(j.contains(
        "pub static CGROUP_JOIN_EPOCH: Array<u64> = Array::with_max_entries(EPOCH_SLOTS, 0);"
    ));
    in_order(
        body(&j, "before_epoch"),
        &[
            "if epoch == 0 || ptgid == 1 || family(ptgid) {\n        return false;\n    }",
            "leader_start(parent).unwrap_or(0) < epoch",
        ],
    )
    .unwrap();
    // lot 281 (#494's N2): the agent's request taken into the pinned epoch,
    // forward only (`common::cgroup_join::epoch_promoted`), by every fork
    assert!(j.contains(
        "pub static CGROUP_JOIN_EPOCH_RT: Array<u64> = Array::with_max_entries(EPOCH_SLOTS, 0);"
    ));
    in_order(
        body(&j, "epoch_now"),
        &[
            "CGROUP_JOIN_EPOCH.get_ptr_mut(0)",
            "CGROUP_JOIN_EPOCH_RT.get(0)",
            "if epoch_promoted(*e, request) {",
            "CGROUP_JOIN_EPOCH.get_ptr_mut(1),\n            CGROUP_JOIN_EPOCH_RT.get(1),",
            "*b = *rb;",
            "*e = request;",
        ],
    )
    .unwrap();
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
            // lot 281: the process's taint kept by any new mark of it
            "let how = remarked(how, unsafe { how_now(tgid, start) });",
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
            // lot 281: the reset asked for taken in first, by every fork
            "let epoch = epoch_now();",
            "let (marked, phow) = match CGROUP_JOINED.get(&ptgid) {\n        Some(rec) => (leader_start(parent) == Some(rec[0]), unpack(rec[1]).0),\n        None => (false, 0),\n    };",
            // the third review of #494, R2-a: a parent started before the
            // marks' last reset is not known, and passes that on
            "let lost = is_lost(ptgid) || before_epoch(epoch, parent, ptgid);",
            "if !marked && !lost {\n        return;\n    }",
            "if ctgid == ptgid {\n        return;\n    }",
            "if lost {\n        lose(ctgid);\n        return;\n    }",
            // lot 281: where it runs and the taint, passed on
            "if mark(ctgid, start, inherited(phow), ptgid) {",
        ],
    )
    .unwrap();
    // lot 281: attach mode only, the family's accesses never, the shared
    // decision on the call (`common::cgroup_join::injection`), then the
    // taint; never a refusal
    in_order(
        body(&j, "try_inject"),
        &[
            "if target == 0 || mode & PTRACE_MODE_ATTACH == 0 {\n        return;\n    }",
            "if family(caller) {\n        return;\n    }",
            "let (syscall, flags) = current_call();",
            "if !injection(mode, syscall, flags) {\n        return;\n    }",
            "taint(target, tgid, caller, inject_detail(mode, syscall), true);",
        ],
    )
    .unwrap();
    assert!(body(&j, "cgroup_join_inject").contains("unsafe { try_inject(&ctx) };\n    0"));
    assert!(body(&j, "cgroup_join_traceme").contains("unsafe { try_traceme(&ctx) };\n    0"));
    in_order(
        body(&j, "try_traceme"),
        &[
            "let Some(tracer) = tgid_of(parent) else {",
            "if family(tracer) {\n        return;\n    }",
            "taint(bpf_get_current_task(), me, tracer, 0, false);",
        ],
    )
    .unwrap();
    // PID 1 and the protected never; a group already tainted keeps its
    // mark; the placement kept; a mark refused is "not known"; the first
    // taint recorded
    in_order(
        body(&j, "taint"),
        &[
            "if tgid == 1 || crate::task_kill::is_protected_pid(tgid) {\n        return;\n    }",
            "let Some(start) = leader_start(task) else {\n        lose(tgid);",
            "let old = how_now(tgid, start);",
            "if old & HOW_TAINT != 0 {\n        return;\n    }",
            "let rec = [start, pack(injected(old), by)];",
            "if CGROUP_JOINED.insert(&tgid, &rec, 0).is_err() {\n        lose(tgid);\n    }",
            "count(STAT_INJECTED);",
            "if record {",
            "FS_OP_EXEMPT_INJECT,",
            "ino: u64::from(tgid),",
        ],
    )
    .unwrap();
    // the call read from the task's own registers only (an io-wq worker's
    // or a kernel thread's are not its call: unread, an injection)
    in_order(
        body(&j, "current_call"),
        &[
            "off_opt!(PT_REGS_ORIG_AX_OFFSET)",
            "if !regs_are_the_writes(flags) {\n        return (None, None);\n    }",
            "generated::bpf_task_pt_regs(task)",
            "let open_flags = if nr == SYS_OPEN {\n        rd_u64(regs + si as u64)\n    } else if nr == SYS_OPENAT {\n        rd_u64(regs + dx as u64)\n    } else if nr == SYS_OPENAT2 {",
            "bpf_probe_read_user::<u64>(how as *const u64)",
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
            "m.started(tgid, start_boot_ns(proc_root, tgid))",
        ],
    )
    .unwrap();
    // one errand: the group's byte refuses its answer (that group's only,
    // the review of #494, D2), a mark is "not started here", only a missing
    // key is "started here" — the same reads as the privileged test's
    // (`lost_in`, `mark_in`: its behaviour is that test's)
    assert!(!body(&cj, "both").contains("STAT_LOST"));
    assert!(body(&cj, "started").contains("self.both(tgid, start_boot_ns).map(|(s, _)| s)"));
    assert!(cj.contains(
        "pub fn injected(&self, tgid: u32, start_boot_ns: Option<u64>) -> Option<Injected> {\n        self.both(tgid, start_boot_ns).map(|(_, i)| i)"
    ));
    in_order(
        body(&cj, "both"),
        &[
            // lot 281 (#494's N1/N2): nothing known until armed
            "if !self.armed.load(Ordering::Acquire) {\n            return None;\n        }",
            "crate::caps::errands::run(move || {",
            // R2-a: the marks' last reset — lot 281: the pinned one or a
            // request not yet taken in, the later
            ".max(epoch_rt.lock().get(&1, 0).ok()?);",
            "lost_in(&lost.lock(), tgid).ok(),",
            "after_epoch(reset, start_boot_ns),",
            "mark_in(&joined.lock(), tgid).map_err(drop),",
        ],
    )
    .unwrap();
    // the group's byte refuses its answer, a reset too, an unread mark too;
    // the placement bits answer the cgroup, the taint bits the code (its
    // behaviour: `the_check_reads_the_placement_and_the_taint_from_one_mark`)
    in_order(
        body(&cj, "judge"),
        &[
            "if lost != Some(false) || !after {\n        return None;\n    }",
            "Ok(None) => Some((true, Injected::No)),",
            "Ok(Some(m)) => Some((!m.placed(), m.injected())),",
            "Err(()) => None,",
        ],
    )
    .unwrap();
    assert!(body(&cj, "placed").contains("self.how & HOW_PLACE != 0"));
    assert!(cj.contains(
        "pub fn arm() -> Option<std::time::Duration> {\n    let Some(Tracker::Attached(m)) = tracker() else {\n        return None;\n    };\n    m.arm();"
    ));
    in_order(
        body(&cj, "debug_self_inject"),
        &[
            "#[cfg(feature = \"debug-trigger\")]",
            "std::env::var(\"NN_DEBUG_CGROUP_JOIN_SELF_INJECT\")",
        ],
    )
    .unwrap();
    // armed only once the tracker's pins and state are protected
    let at = code("crates/nn-linux/src/anti_tamper/mod.rs");
    in_order(
        &at,
        &[
            "let mut tracker_protected = true;",
            "if let Err(e) = filesystem::register_bpffs_pins(ebpf, dir) {\n            tracker_protected = false;",
            "} else if let Err(e) = filesystem::register_agent_file(ebpf, state) {\n            tracker_protected = false;",
            "if tracker_protected {\n        crate::cgroup_join::arm();",
        ],
    )
    .unwrap();
    assert!(!at.contains(".sweep("), "the marks are frozen: no sweep");
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
            "return (Tracker::Absent(why), Vec::new());",
            // the re-review of #494, R2: the tracker's own directory, a
            // refused one is no tracker
            "(Some(_), Some(Err(why))) => {",
            "Tracker::Absent(format!(\"the tracker's pin directory: {why}\")),",
            "if let Err(e) = load_only(ebpf, btf, name, *kind, target) {\n                    for (n, k, _) in &PROGRAMS[..=i] {\n                        unload(ebpf, n, *k);\n                    }",
            // lot 281 (#494's N1/N2): an adoption's maps the ones verified,
            // every map frozen, a new generation pinned after the load
            "if let Err(why) = adopted_as_registered(ebpf, ADOPTED.get()) {",
            "match freeze_pinned(ebpf) {",
            "match pin_new(ebpf, root, &plan.dir) {",
            "let _ = FINAL_DIR.set(dir.clone());",
            "if let Err(e) = pin_fresh(ebpf, dir, name, *kind) {",
            // the third review, R2-a: a reset's epoch once the new programs
            // run, or no tracker; signed with what it means
            "if let Some(why) = &plan.reset {\n                if let Err(e) = set_epoch(ebpf) {",
            "Tracker::Absent(format!(\"the reset's epoch not written: {e}\")),",
            "signed.push(format!(",
            "if let Some(note) = &plan.note {",
            // every other tracker directory goes after the new programs
            // run; an unregistered one beside adopted pins is signed
            "let others = other_pin_dirs(root, Some(dir));",
            "purge_pin_dir(d);",
            "if plan.reset.is_none() {\n                    let why = format!(",
            // R2-b: the pins registered for the next start
            "if let Err(e) = register_pins(dir) {",
            "if let Err(e) = load_attach(ebpf, btf, name, *kind, target) {\n                    for (n, k, _) in &PROGRAMS[..=i] {\n                        unload(ebpf, n, *k);\n                    }",
        ],
    )
    .unwrap();
    // the swap's order: mark before src (the re-review of #494, N-f)
    let progs = &cj[cj.find("pub const PROGRAMS").unwrap()..];
    assert!(
        progs.find("\"cgroup_join_mark\"").unwrap() < progs.find("\"cgroup_join_src\"").unwrap()
    );
    // the loader pins the four maps where the plan says (its behaviour:
    // `plan`'s unit tests), the directory made never through a link
    in_order(
        body(&cj, "prepare_pins"),
        &[
            "std::fs::read_to_string(STATE_PATH)",
            "if debug_reset() {",
            "verify_state(st)",
            "let p = plan(",
            "&verify,",
            // lot 281 (#494's N1): the loader takes pins for an adoption
            // only; a new generation is pinned after the load
            "if p.adopt {\n            usable_dir(&p.dir)?;",
            "if p.adopt {\n            for name in PINNED_MAPS {\n                loader.map_pin_path(name, p.dir.join(name));",
        ],
    )
    .unwrap();
    in_order(
        body(&cj, "verify_state"),
        &[
            "antitamper_bpf::pin_root_refusal_at(&st.dir)",
            "verify_map(&seen_at(&st.dir.join(name))?, reg)?;",
            "if !is_tracker_pin(&n) {\n            return Err(format!(\"{n}: not a pin of the tracker\"));",
        ],
    )
    .unwrap();
    assert!(body(&cj, "seen_at").contains("let md = open_pinned_ro(path)?;"));
    // lot 281 (the lab's find): a frozen map's state read from its fdinfo
    // before the freeze (a second freeze answers EPERM)
    in_order(
        body(&cj, "freeze_pinned"),
        &[
            "std::fs::read_to_string(format!(\"/proc/self/fdinfo/{fd}\"))",
            "match fdinfo_frozen(&info) {\n            Some(true) => continue,\n            Some(false) => {}",
            "libc::SYS_bpf,\n                MAP_FREEZE,",
            "freeze_outcome(errno)",
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
    // a debug build's reset knob: debug-trigger builds only
    in_order(
        body(&cj, "debug_reset"),
        &[
            "#[cfg(feature = \"debug-trigger\")]",
            "std::env::var(\"NN_DEBUG_CGROUP_JOIN_RESET\")",
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
            "let (tracker, signed) = crate::cgroup_join::attach(ebpf, &btf, pin_root);",
            "for why in signed {\n        report.degraded.push(format!(\"cgroup exemptions: {why}\"));",
            "if let crate::cgroup_join::Tracker::Absent(why) = &tracker {\n        report.degraded.push(format!(",
            "crate::cgroup_join::install(tracker);",
            // the tracker's pins protected like the root's
            "if let Some(dir) = crate::cgroup_join::pin_dir_now() {\n        if let Err(e) = filesystem::register_bpffs_pins(ebpf, dir) {",
            // the third review, R2-b: and the record of them
            "let state = std::path::Path::new(crate::cgroup_join::STATE_PATH);",
            "filesystem::register_agent_file(ebpf, state)",
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
    // (lot 280a: nor a write the signed per-sysctl opt-out let through;
    // lot 280b: nor the kernel-state round's findings)
    // (lot 281: nor an injection's record)
    // (lot 290: nor a loader opt-out's load, nor the BPF cross-view's findings)
    assert!(tr.contains(
        "if !matches!(\n                operation,\n                nn_model::FsProtectOperation::CgroupJoin\n                    | nn_model::FsProtectOperation::SysctlOptOut\n                    | nn_model::FsProtectOperation::KernelTaint\n                    | nn_model::FsProtectOperation::SysctlRootProg\n                    | nn_model::FsProtectOperation::ExemptInjection\n                    | nn_model::FsProtectOperation::BpfProgOptOut\n                    | nn_model::FsProtectOperation::BpfUnseen\n                    | nn_model::FsProtectOperation::BpfBaseline\n            ) {"
    ));
    let pe = code("agent/src/pipeline/process_event.rs");
    assert!(pe.contains("let joined = *operation == nn_model::FsProtectOperation::CgroupJoin;"));
    // lot 281: an injection signed only when an exemption covered the
    // process (whatever its taint now), with the injector's lineage
    in_order(
        &pe,
        &[
            "let injection = *operation == nn_model::FsProtectOperation::ExemptInjection;",
            ".and_then(|t| engine.exempt_covering(t));",
            "if injection && covered.is_none() {",
            "return;",
            "let admin = posture.interactive_admin_status(",
            "anti_tamper::exempt_injection(\n                        &event, exemption, admin,\n                    )",
        ],
    )
    .unwrap();
    // the exemption check: a uid's holds, every other kind asks the taint
    // once, after its match (its behaviour: rule_policy's
    // `an_exemption_is_revoked_once_code_was_injected`)
    in_order(
        body(&rp, "exempt"),
        &[
            "if hit {\n            if matches!(e, Exemption::Uid(_)) {\n                return Some(Exempt::Holds(e.to_string()));\n            }",
            "return Some(match revoked_why(facts.injected(pid)) {",
            "None => Exempt::Holds(e.to_string()),",
        ],
    )
    .unwrap();
    assert!(pf.contains("crate::cgroup_join::injected(&self.root, pid)"));
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
