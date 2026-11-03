//! Lot 273: the protected units' cgroups — the parts no host test runs.
//!
//! The eBPF programs run only in a kernel (the lab's tamper-check C15, C20,
//! C65-C76 and the lot's probe show what they refuse); here the code is
//! read, as `pid_roles.rs` reads the role lookups: each check the guard's
//! safety rests on is there, in the order that makes it hold, and every
//! place that registers the cgroups calls the shared code.

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
fn the_move_guard_records_only_a_refusable_move_and_refuses_its_check() {
    let g = code("agent-ebpf/src/cgroup_guard.rs");
    // attach points
    assert!(g.contains("#[fexit(function = \"cgroup_procs_write_start\")]"));
    assert!(g.contains("#[lsm(hook = \"inode_permission\")]"));
    assert!(g.contains("const MAY_WRITE: c_int = 0x2;"));
    // the lookup half: the task the write moves, at the return slot the
    // agent checked in the BTF; a protected target, a caller outside the
    // family, no window — then recorded
    let stash = body(&g, "try_cgroup_move_stash");
    in_order(
        stash,
        &[
            "args.add(CGROUP_MOVE_RET_ARG)",
            "task >= 0u64.wrapping_sub(MAX_ERRNO)",
            "off!(TASK_STRUCT_TGID_OFFSET)",
            "if !crate::task_kill::is_protected_pid(tgid)\n        || crate::task_kill::is_exempt_pid((pid_tgid >> 32) as u32)\n        || crate::inode_protect::override_active()\n    {\n        return;\n    }",
            "if CGROUP_MOVES.insert(&pid_tgid, &rec, 0).is_err() {",
            "crate::fail_open::bump(hook::CGROUP_PROCS_WRITE_START);",
        ],
    )
    .unwrap();
    // the refusal half: writes only, the writer's record, used once, fresh,
    // the window and the family checked again, signed, refused
    let deny = body(&g, "try_cgroup_move_deny");
    in_order(
        deny,
        &[
            "let mask: c_int = ctx.arg(1);",
            "if mask & MAY_WRITE == 0 {\n        return 0;\n    }",
            "CGROUP_MOVES.get(&pid_tgid)",
            // lot 273b: consumed only by a migration's check
            "if !is_cgroup2_members_file(ctx.arg(0)) {\n        return 0;\n    }",
            "let _ = CGROUP_MOVES.remove(&pid_tgid);",
            // lot 273b (the review's R11, R12): whole conditions, not
            // their substrings
            "if bpf_ktime_get_ns().wrapping_sub(rec[1]) >= STASH_TTL_NS {\n        return 0;\n    }",
            "if crate::inode_protect::override_active()\n        || crate::task_kill::is_exempt_pid((pid_tgid >> 32) as u32)\n    {\n        return 0;\n    }",
            "crate::inode_protect::emit_task_denial(FS_OP_CGROUP_MOVE, 0, rec[0] as u32);\n    -EPERM\n}",
        ],
    )
    .unwrap();
    // lot 273b: a map that never evicts, of an explicit size, its records
    // dropped at the end of every write; the TTL a second (the review of
    // #489's R1, R3 and R11: constants no host test reaches)
    assert!(g.contains(
        "static CGROUP_MOVES: HashMap<u64, [u64; 2]> = HashMap::with_max_entries(MOVE_STASH_ENTRIES, 0);"
    ));
    assert!(!g.contains("LruHashMap"));
    assert!(g.contains("const MOVE_STASH_ENTRIES: u32 = 64;"));
    assert!(g.contains("const STASH_TTL_NS: u64 = 1_000_000_000;"));
    assert!(g.contains("#[fentry(function = \"cgroup_procs_write_finish\")]"));
    assert!(body(&g, "cgroup_move_clear").contains("CGROUP_MOVES.remove(&pid_tgid)"));
    // the file a migration checks: cgroup v2, a regular file, its name
    in_order(
        body(&g, "is_cgroup2_members_file"),
        &[
            "off!(SUPER_BLOCK_S_MAGIC_OFFSET)",
            "if magic & 0xffff_ffff != CGROUP2_SUPER_MAGIC {",
            "if mode & S_IFMT != S_IFREG {",
            "off_opt!(INODE_I_PRIVATE_OFFSET)",
            "bpf_probe_read_kernel_str(",
            "name_words(b\"cgroup.procs\")",
            "name_words(b\"cgroup.threads\")",
            "(w[0] == PROCS[0] && w[1] == PROCS[1]) || (w[0] == THREADS[0] && w[1] == THREADS[1])",
        ],
    )
    .unwrap();
}

/// Lot 273b: the write deny and the cgroup files' checks.
#[test]
fn the_write_deny_judges_the_cgroup_files_in_order() {
    let i = code("agent-ebpf/src/inode_protect.rs");
    in_order(
        body(&i, "try_protected_open_deny"),
        &[
            "if let Some((op, key)) = protected_verdict(FS_OP_WRITE, inode, hook::FILE_OPEN) {",
            "if !fs_protect_init_may_open(op, (bpf_get_current_pid_tgid() >> 32) as u32) {\n            emit_denial(op, key);\n            return -EPERM;\n        }",
            "\n    if crate::cgroup_files::refuse_write(file, inode, hook::FILE_OPEN, crate::cgroup_files::Phase::Open) {",
            "return -EPERM;",
        ],
    )
    .unwrap();
    assert!(i.contains("#[lsm(hook = \"file_permission\")]\npub fn protected_write_deny("));
    in_order(
        body(&i, "try_protected_write_deny"),
        &[
            "if mask & MAY_WRITE == 0 {\n        return 0;\n    }",
            "off!(FILE_F_INODE_OFFSET)",
            "protected_verdict(FS_OP_WRITE, inode, hook::FILE_PERMISSION)",
            "let thaw = fs_protect_init_may_open(op, (bpf_get_current_pid_tgid() >> 32) as u32)",
            "Some(v) if same_value(&v, &fs_protect_thaw_value())",
            "if !thaw {\n            emit_limited(op, key);\n            return -EPERM;\n        }",
            "\n    if crate::cgroup_files::refuse_write(file, inode, hook::FILE_PERMISSION, crate::cgroup_files::Phase::Write) {",
            "return -EPERM;",
        ],
    )
    .unwrap();
    let c = code("agent-ebpf/src/cgroup_files.rs");
    in_order(
        body(&c, "refuse_write"),
        &[
            "off!(SUPER_BLOCK_S_MAGIC_OFFSET)",
            "if magic == CGROUP2_SUPER_MAGIC {\n        refuse_limit(file, inode, hook, phase)",
            "} else if magic == CGROUP_SUPER_MAGIC {\n        refuse_v1(inode, hook, phase)",
            "} else if magic == PROC_SUPER_MAGIC {\n        refuse_oom_adj(file, inode, phase)",
        ],
    )
    .unwrap();
    // The review of #490 (B): the file is recognised by its registered
    // value or by its kernfs node (name, parent's id), the dentry only
    // without the node's offsets — a handle-opened file's dentry is
    // disconnected.
    in_order(
        body(&c, "kernfs_node_of"),
        &[
            "off_opt!(INODE_I_PRIVATE_OFFSET)",
            "off_opt!(KERNFS_NODE_NAME_OFFSET)",
            "off_opt!(KERNFS_NODE_PARENT_OFFSET)",
            "off_opt!(KERNFS_NODE_ID_OFFSET)",
            "return Node::NoOffsets;",
            "bpf_probe_read_kernel_str(w.as_mut_ptr() as *mut c_void, 24, name as *const c_void)",
            "if len > LIMIT_NAME_MAX {\n        return Node::NotALimit;\n    }",
            "kn.add(parent_off)",
            "parent.add(id_off)",
            "Ok(id) => Node::Read(len, w, id),",
        ],
    )
    .unwrap();
    in_order(
        body(&c, "dentry_name_and_dir"),
        &[
            "let kind = limit_kind(len, words);",
            "if kind == LIMIT_NONE {\n        return None;\n    }",
            "off!(DENTRY_D_PARENT_OFFSET)",
            "Some((kind, dir_key))",
        ],
    )
    .unwrap();
    in_order(
        body(&c, "refuse_limit"),
        &[
            "let registered = LIMIT_VALUES.get(&key).copied();",
            "Node::Read(len, words, dir_ino) => (\n            limit_kind(len, words),\n            InodeKey {\n                dev: key.dev,\n                ino: dir_ino,\n            },\n        ),",
            "Node::NoOffsets => match dentry_name_and_dir(file, hook) {",
            "Node::Unreadable => {\n            crate::fail_open::bump(hook);",
            "if registered.is_none() {\n        if kind == LIMIT_NONE {\n            return false;\n        }",
            "Some(f) if *f & FS_PROTECT_LIMIT_DIR != 0 => {}",
            "if caller_may(caller) {\n        return false;\n    }",
            "if caller == 1 {",
            "if phase == Phase::Open {\n            return false;\n        }",
            "Some(v) => Some(v),\n            None => default_value(kind),",
            "if let (Some(value), Some(written)) = (value, written_value()) {\n            if same_value(&written, &value) {\n                return false;",
            "sign(phase, FS_OP_CGROUP_LIMIT, key);",
            "true",
        ],
    )
    .unwrap();
    assert!(body(&c, "caller_may").contains(
        "crate::task_kill::is_exempt_pid(caller) || crate::inode_protect::override_active()"
    ));
    in_order(
        body(&c, "written_bytes"),
        &[
            "if nr != NR_WRITE && nr != NR_PWRITE64 {\n        return None;\n    }",
            "if count == 0 || count > LIMIT_TEXT_MAX as u64 + 1 {",
            "bpf_probe_read_user(",
            "Some((value, n))",
        ],
    )
    .unwrap();
    assert!(c.contains("const NR_WRITE: u64 = 1;\nconst NR_PWRITE64: u64 = 18;"));
    // systemd's newline cleared before the compare
    assert!(body(&c, "written_value")
        .contains("written_bytes().map(|(v, n)| strip_newline(v, n as usize))"));
    in_order(
        body(&c, "refuse_v1"),
        &[
            "Some(p) if *p & CGROUP_POLICY_V1_REFUSE != 0 => {}",
            "if caller_may(caller) {\n        return false;\n    }",
            "sign(phase, FS_OP_CGROUP_V1, key);",
        ],
    )
    .unwrap();
    in_order(
        body(&c, "refuse_oom_adj"),
        &[
            "name_words(b\"oom_score_adj\")",
            "name_words(b\"oom_adj\")",
            "if !named {\n        return false;\n    }",
            "if !crate::task_kill::is_protected_pid(tgid) {\n        return false;\n    }",
            "if caller_may(caller) {\n        return false;\n    }",
            "emit_task_denial(FS_OP_OOM_ADJ, 0, tgid);",
        ],
    )
    .unwrap();
}

#[test]
fn the_inode_deny_lets_only_init_remove_a_unit_cgroup_and_signs_by_effect() {
    let i = code("agent-ebpf/src/inode_protect.rs");
    let d = body(&i, "protected_verdict");
    in_order(
        d,
        &[
            "if flags & required == 0 {",
            "if override_active() {",
            "if crate::task_kill::is_exempt_pid(caller_tgid) {",
            "if fs_protect_init_may(operation, flags, caller_tgid) {",
            "Some((fs_protect_denied_op(operation, flags), key))",
        ],
    )
    .unwrap();
    in_order(
        body(&i, "deny_if_protected"),
        &["Some((op, key)) => {", "emit_denial(op, key);", "true"],
    )
    .unwrap();
}

#[test]
fn every_registration_of_the_cgroups_goes_through_the_shared_code() {
    // the attach: registered before the FS deny hooks attach and before
    // the prune; the guard attached before the own objects are recorded
    let m = code("crates/nn-linux/src/anti_tamper/mod.rs");
    let a = body(&m, "attach_reporting");
    in_order(
        a,
        &[
            "evict_stale_pids(ebpf, keep)",
            // lot 273b (the review's R5): the live watchdog's cgroup too
            "cgroup_guard::cgroup_pids(pids, &live, |pid| {",
            "cgroup_guard::register_unit_cgroups(ebpf, &cgroup_pids)",
            "cgroup_guard::arm_v1_policy(ebpf, pin_root)",
            "filesystem::attach(ebpf, &btf, pin_root)",
            "cgroup_guard::attach_move_guard(ebpf, &btf, pin_root)",
            "report.move_guard_attached = mg.present > 0 && mg.failures.is_empty();",
            "bpf_defense::register_own_objects(bpf_guard, ebpf, pin_root)",
            "filesystem::prune_stale_inodes(ebpf)",
            "cgroup_guard::prune_stale_values(ebpf)",
        ],
    )
    .unwrap();
    // the refusal half attached first, then the end-of-write clear, then
    // the lookup half
    let g = code("crates/nn-linux/src/anti_tamper/cgroup_guard.rs");
    in_order(
        body(&g, "attach_move_guard"),
        &[
            "reattach_fresh(ebpf, MOVE_DENY_PROGRAM, MOVE_DENY_HOOK, btf, pin_root)",
            "reattach_fresh_fentry(",
            "reattach_fresh_fexit(",
        ],
    )
    .unwrap();
    // lot 273b (R7): a former watchdog's keys are released
    in_order(
        body(&g, "protect_watchdog_cgroup"),
        &[
            "unit.keys()",
            "let gone = released(previous, &keys);",
            "if !gone.is_empty() {\n        if let Err(e) = antitamper_bpf::cgroup_guard::release_keys(root, &gone) {",
            "keys\n}",
        ],
    )
    .unwrap();
    // lot 273b: the v1 refusal armed where the policy says so, its maps
    // pinned; a released watchdog's values go with its keys
    in_order(
        body(&g, "arm_v1_policy"),
        &[
            "V1Policy::Refused { .. } => CGROUP_POLICY_V1_REFUSE,",
            "V1Policy::NotRefused { .. } => 0,",
            "arr.set(0, bits, 0)",
            "for name in [CGROUP_POLICY_MAP_NAME, LIMIT_VALUES_MAP_NAME] {",
        ],
    )
    .unwrap();
    let ab = code("antitamper-bpf/src/cgroup_guard.rs");
    in_order(
        body(&ab, "release_keys"),
        &[
            "PROTECTED_INODES_MAP_NAME",
            "let _ = map.remove(&Key(*k));",
            "let values = bpffs_root.join(LIMIT_VALUES_MAP_NAME);\n    if values.exists() {",
            "let _ = map.remove(&Key(*k));",
        ],
    )
    .unwrap();
    in_order(
        body(&ab, "protect_unit_cgroup"),
        &[
            "map.insert(Key(e.key), e.flags, 0)",
            "write_values(bpffs_root, unit.values())?;",
        ],
    )
    .unwrap();
    in_order(
        body(&g, "register_unit_cgroups"),
        &[
            "register_cgroup_inode(ebpf, &e.key, e.flags)?;",
            "register_value(ebpf, &f.key, &f.value)?;",
            "remember_unit(&cgroup);",
            "out.protected.push(",
        ],
    )
    .unwrap();
    // lot 273b: the values registered again at a window's close — every
    // unit this agent registered, its watchdog's restarts too — after the
    // grant is zeroed
    in_order(
        body(&g, "protect_watchdog_cgroup"),
        &[
            "Ok(unit @ UnitCgroup::Service { .. }) => {",
            "remember_unit(cgroup);",
            "unit.keys()",
        ],
    )
    .unwrap();
    in_order(
        body(&g, "remember_unit"),
        &[
            "if !units.iter().any(|u| u == cgroup) {",
            "units.push(cgroup.to_string());",
        ],
    )
    .unwrap();
    in_order(
        body(&g, "refresh_values"),
        &[
            "let units = REGISTERED_UNITS.lock().clone();",
            "for cgroup in &units {",
            "antitamper_bpf::cgroup_guard::refresh_unit_values(root, cgroup)",
        ],
    )
    .unwrap();
    in_order(
        body(&ab, "refresh_unit_values"),
        &[
            "let unit = unit_cgroup_at(&root, cgroup);",
            "write_values(bpffs_root, unit.values())?;",
        ],
    )
    .unwrap();
    in_order(
        body(
            &code("crates/nn-linux/src/anti_tamper/trusted_installer.rs"),
            "close",
        ),
        &[
            "let was_armed = self.armed.swap(false, Ordering::SeqCst);",
            "write_fs_grant(self.bpffs_root.as_deref(), FsGrant::default())",
            "if was_armed {",
            "super::cgroup_guard::refresh_values(self.bpffs_root.as_deref());",
        ],
    )
    .unwrap();
    // the early start, the refresh, the watchdog
    assert!(code("agent/src/boot/state.rs").contains("cgroup_guard::preregister_own_cgroup("));
    // the detection writer names a denial's caller from the lineage
    in_order(
        &code("agent/src/boot/mod.rs"),
        &[
            "} = evidence::stores(",
            "sink.set_exe_resolver(Box::new(move |pid, ts_ns| {",
            ".exec_identity(",
        ],
    )
    .unwrap();
    in_order(
        &code("agent/src/boot/tasks.rs"),
        &[
            "cgroup_keys = northnarrow_agent::anti_tamper::cgroup_guard::protect_watchdog_cgroup(",
            "bpffs_root,",
            "p,",
            "&cgroup_keys,",
        ],
    )
    .unwrap();
    // lot 273b: the move guard's self-test runs where the guard is attached
    in_order(
        &code("agent/src/boot/attach.rs"),
        &[
            "boot::deny_selftest::run(",
            "if anti_tamper.move_guard_attached {",
            "boot::deny_selftest::run_move(",
            "expected_denial.also(&moved);",
            "degradation::report(\"move_guard_self_test\", &detail);",
        ],
    )
    .unwrap();
    let w = code("watchdog/src/main.rs");
    in_order(
        &w,
        &[
            "register_self_pid(&cli.bpffs_root, own_pid)",
            "register_own_cgroup(&cli.bpffs_root, own_pid)",
        ],
    )
    .unwrap();
    assert!(code("watchdog/src/lib.rs")
        .contains("antitamper_bpf::cgroup_guard::protect_unit_cgroup(bpffs_root, own_pid)"));
}
