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
    // lot 303: the clear at the end of every cgroup file's write, a function
    // kernfs calls through a pointer (7.0 inlines lot 273b's
    // `cgroup_procs_write_finish` into its cgroup v2 caller)
    assert!(g.contains("#[fexit(function = \"cgroup_file_write\")]"));
    assert!(!g.contains("#[fentry"));
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
            // lot 293 (BUG37): signed behind the attempt budget
            "if !fs_protect_init_may_open(op, (bpf_get_current_pid_tgid() >> 32) as u32) {\n            emit_attempt(op, key);\n            return -EPERM;\n        }",
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
    // The review of #490, its P3 (a 16-bit mask left every file
    // unjudged): the magic read goes, as read, to the shared module's
    // classification, which the host's tests judge
    // (`common::cgroup_limits::special_fs`).
    let w = body(&c, "refuse_write");
    in_order(
        w,
        &[
            "off!(SUPER_BLOCK_S_MAGIC_OFFSET)",
            "Ok(m) => m,",
            // lot 280b: and the switches of debugfs and securityfs
            "match special_fs(magic) {\n        Some(SpecialFs::Cgroup2) => refuse_limit(file, inode, hook, phase),\n        Some(SpecialFs::CgroupV1) => refuse_v1(inode, hook, phase),\n        Some(SpecialFs::Proc) => {\n            refuse_sysctl(file, inode, hook, phase) || refuse_oom_adj(file, inode, phase)\n        }\n        Some(fs @ (SpecialFs::Debugfs | SpecialFs::Securityfs)) => refuse_switch(file, inode, fs, phase),\n        None => false,\n    }",
        ],
    )
    .unwrap();
    assert_eq!(
        w.matches("magic").count(),
        2,
        "the magic is read and classified, nothing else:\n{w}"
    );
    // Lot 280b: a switch's write is refused by its names alone (the shared
    // judge), the family and a window passing first, and an inode that
    // cannot be read refused all the same (signed 0:0)
    in_order(
        body(&c, "refuse_switch"),
        &[
            "let op = switch_file_op(fs, name, parent);",
            "if op == 0 {\n        return false;\n    }",
            "if caller_may((bpf_get_current_pid_tgid() >> 32) as u32) {\n        return false;\n    }",
            "read_inode_key(inode).unwrap_or(InodeKey { dev: 0, ino: 0 });",
            // lot 341: a host-wide deny (`xtask/tests/host_deny.rs`)
            "let (refuse, op) = crate::host_deny::judge(op);\n    sign(phase, op, key);\n    refuse",
        ],
    )
    .unwrap();
    // Lot 273d (the review of #492): a guarded sysctl's harmful write
    // refused outside a window, judged at the write by the shared verdict
    // (R1: written_value() appears nowhere else in it)
    assert_eq!(
        body(&c, "refuse_sysctl").matches("written_value()").count(),
        1
    );
    // the review of #497 (D2): an io-wq worker's or a kernel thread's
    // registers are not read — its write is an unread one (refused)
    in_order(
        body(&c, "written_bytes"),
        &[
            "let task = generated::bpf_get_current_task_btf();",
            "off!(TASK_STRUCT_FLAGS_OFFSET)",
            ".ok()?;",
            "if !regs_are_the_writes(flags) {\n        return None;\n    }",
            "generated::bpf_task_pt_regs(task)",
        ],
    )
    .unwrap();
    in_order(
        body(&c, "refuse_sysctl"),
        &[
            "if phase == Phase::Open {\n        return false;\n    }",
            "let kind = sysctl_kind(len, words);",
            "if kind == SYSCTL_NONE {\n        return false;\n    }",
            // R1: the shared verdict, the caller's identity passed in (the
            // agent's own restore), the bytes read only through it — lot
            // 280a: with the signed opt-out (xtask/tests/sysctl_cgroup.rs)
            "let (verdict, v) = sysctl_write_verdict(\n        kind,\n        caller_may(caller),",
            "|| written_value(),",
            "SysctlVerdict::Allow => return false,",
            "SysctlVerdict::Refuse => {}",
            // lot 341: a host-wide deny (`xtask/tests/host_deny.rs`)
            "let (refuse, op) = crate::host_deny::judge(FS_OP_SYSCTL);",
            "sign(phase, op, key);",
            "refuse",
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
            "sign(phase, FS_OP_CGROUP_LIMIT, key);",
            "true",
        ],
    )
    .unwrap();
    // The review of #490, its P2 (a `return false` before the comparison
    // let PID 1 write any value): PID 1's arm, whole — the open let
    // through, the write's value judged by the shared module
    // (`common::cgroup_limits::init_write_lets_through`, its tests).
    let l = body(&c, "refuse_limit");
    let at = l.find("if caller == 1 {").expect("PID 1's arm") + "if caller == 1 ".len();
    let arm = &l[at..at + support::matching_brace(&l[at..])];
    assert_eq!(
        arm.split_whitespace().collect::<Vec<_>>().join(" "),
        "{ if phase == Phase::Open { return false; } let expected = match registered { \
         Some(v) => Some(v), None => default_value(kind), }; \
         if init_write_lets_through(expected, written_value()) { return false; } }",
        "PID 1's arm:\n{arm}"
    );
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
            // lot 341: a host-wide deny (`xtask/tests/host_deny.rs`)
            "let (refuse, op) = crate::host_deny::judge(FS_OP_CGROUP_V1);\n    sign(phase, op, key);\n    refuse",
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
        // lot 293 (BUG37): signed behind the attempt budget
        &["Some((op, key)) => {", "emit_attempt(op, key);", "true"],
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
            // lot 303: where the guard is not attached, a prior boot's pins
            // of its hooks go, and lot 273b's clear's
            "for hook in GUARD_HOOKS.iter().chain([&MOVE_CLEAR_LEGACY_HOOK]) {",
            "reattach_fresh(ebpf, MOVE_DENY_PROGRAM, MOVE_DENY_HOOK, btf, pin_root)",
            // lot 303: an older agent's clear (fentry) goes first
            "lsm_pin_paths(root, MOVE_CLEAR_LEGACY_HOOK)",
            "antitamper_bpf::reattach_fresh_fexit(\n        ebpf,\n        MOVE_CLEAR_PROGRAM,",
            "antitamper_bpf::reattach_fresh_fexit(\n        ebpf,\n        MOVE_STASH_PROGRAM,",
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
            "register_own_cgroup(\n            &cli.bpffs_root,\n            own_pid,",
        ],
    )
    .unwrap();
    assert!(code("watchdog/src/lib.rs")
        .contains("antitamper_bpf::cgroup_guard::protect_unit_cgroup(bpffs_root, own_pid)"));
}

/// Lot 273c (the review of #490): another process's change of a protected
/// process's limits and priorities is refused — the target protected (or
/// running the agent's binary), the caller neither the target itself nor
/// exempt, no window — and each of the four hooks refuses with EPERM.
#[test]
fn the_task_settings_denies_refuse_another_processs_change() {
    let t = code("agent-ebpf/src/task_limits.rs");
    in_order(
        body(&t, "refuse_task_change"),
        &[
            "off!(TASK_STRUCT_TGID_OFFSET)",
            "crate::fail_open::bump(hook);",
            "if !crate::task_kill::is_protected_pid(tgid)\n        && !crate::bpf_defense::task_runs_own_binary(task as *const u8)\n    {\n        return false;\n    }",
            "if caller == tgid\n        || crate::task_kill::is_exempt_pid(caller)\n        || crate::inode_protect::override_active()\n    {\n        return false;\n    }",
            "crate::inode_protect::emit_task_denial(op, detail, tgid);",
            "true",
        ],
    )
    .unwrap();
    for (hook, f, op, slot) in [
        (
            "task_setrlimit",
            "task_setrlimit_deny",
            "FS_OP_RLIMIT",
            "hook::TASK_SETRLIMIT",
        ),
        (
            "task_setscheduler",
            "task_setscheduler_deny",
            "FS_OP_SCHED",
            "hook::TASK_SETSCHEDULER",
        ),
        (
            "task_setnice",
            "task_setnice_deny",
            "FS_OP_NICE",
            "hook::TASK_SETNICE",
        ),
        (
            "task_setioprio",
            "task_setioprio_deny",
            "FS_OP_IOPRIO",
            "hook::TASK_SETIOPRIO",
        ),
    ] {
        assert!(
            t.contains(&format!("#[lsm(hook = \"{hook}\")]\npub fn {f}(")),
            "{hook}"
        );
        let b = body(&t, f);
        assert!(b.contains(op) && b.contains(slot), "{f}");
        in_order(b, &["refuse_task_change(", "return -EPERM;", "0"]).unwrap();
    }
    // attached as deny hooks, counted
    let fs = code("crates/nn-linux/src/anti_tamper/filesystem.rs");
    for (p, h) in [
        ("task_setrlimit_deny", "task_setrlimit"),
        ("task_setscheduler_deny", "task_setscheduler"),
        ("task_setnice_deny", "task_setnice"),
        ("task_setioprio_deny", "task_setioprio"),
    ] {
        assert!(fs.contains(&format!("(\"{p}\", \"{h}\"),")), "{p}");
    }
    // PID 1, attach mode only, outside a window
    let p = code("agent-ebpf/src/ptrace_check.rs");
    in_order(
        body(&p, "try_ptrace_access_check"),
        &[
            "let init_attach = target_tgid == 1 && mode & PTRACE_MODE_ATTACH != 0;",
            // lot 341: PID 1's is a host-wide deny, the agent's targets refused
            // under every profile (`xtask/tests/host_deny.rs`)
            "let own_target = crate::task_kill::is_protected_pid(target_tgid)\n        || crate::bpf_defense::task_runs_own_binary(target as *const u8);\n    if !init_attach && !own_target {\n        return 0;\n    }",
            "if crate::task_kill::is_exempt_pid(caller_tgid) {\n        return 0;\n    }",
            "if init_attach && crate::inode_protect::override_active() {\n        return 0;\n    }",
            "-EPERM",
        ],
    )
    .unwrap();
    // the write deny leaves on a file that is not a regular one, before
    // its lookup
    let i = code("agent-ebpf/src/inode_protect.rs");
    in_order(
        body(&i, "try_protected_write_deny"),
        &[
            "off!(INODE_I_MODE_OFFSET)",
            "if mode & S_IFMT != S_IFREG {\n                return 0;\n            }",
            "protected_verdict(FS_OP_WRITE, inode, hook::FILE_PERMISSION)",
        ],
    )
    .unwrap();
    // cgroup v1: a named hierarchy and the other files let through
    let c = code("agent-ebpf/src/cgroup_files.rs");
    in_order(
        body(&c, "refuse_v1"),
        &[
            "Some(p) if *p & CGROUP_POLICY_V1_REFUSE != 0 => {}",
            "if caller_may(caller) {\n        return false;\n    }",
            "if v1_binds_a_controller(inode) == Some(false) {\n        return false;\n    }",
            "if v1_moves_or_freezes(inode) == Some(false) {\n        return false;\n    }",
            // lot 341: a host-wide deny (`xtask/tests/host_deny.rs`)
            "let (refuse, op) = crate::host_deny::judge(FS_OP_CGROUP_V1);\n    sign(phase, op, key);\n    refuse",
        ],
    )
    .unwrap();
    in_order(
        body(&c, "v1_binds_a_controller"),
        &[
            "off_opt!(SUPER_BLOCK_S_FS_INFO_OFFSET)?",
            "let info = p(sb, fs_info)?;",
            "let kroot = p(info, si_root)?;",
            "let kn = p(kroot, root_kn)?;",
            "let cgrp = p(kn, kn_priv)?;",
            "let root = p(cgrp, cg_root)?;",
            "Some(mask != 0)",
        ],
    )
    .unwrap();
    in_order(
        body(&c, "v1_moves_or_freezes"),
        &[
            "name_words(b\"cgroup.procs\")",
            "name_words(b\"tasks\")",
            "name_words(b\"freezer.state\")",
            "Some(is(PROCS) || is(TASKS) || is(FREEZER))",
        ],
    )
    .unwrap();
}

/// Lot 273c: the reloads the agent asks systemd for — a refused PID 1
/// write of a resource file or a drop-in (the pipeline), a window's
/// opening, a quarantine — and the floors at every registration.
#[test]
fn the_reloads_and_the_floors_are_asked_where_they_must_be() {
    let pe = code("agent/src/pipeline/process_event.rs");
    in_order(
        &pe,
        &[
            "if let Event::FsProtectDenial {\n        pid: 1,\n        operation,",
            "nn_model::FsProtectOperation::CgroupLimit => Some(\"cgroup_limit\"),",
            "nn_model::FsProtectOperation::Create => Some(\"create\"),",
            "systemd.reload(",
        ],
    )
    .unwrap();
    // The reload is a SIGHUP to PID 1 once PID 1 is found serving
    // systemd's private socket (lab, round 4: `Manager.Reload()` waits for
    // polkit without CAP_SYS_ADMIN, its reload came only at the close).
    // Lot 273d: the client is shared with the watchdog, and the reload is
    // confirmed (Reloading(false) on a connection opened before the signal).
    let sd = code("antitamper-bpf/src/systemd_bus.rs");
    let r = body(&sd, "reload_verified");
    in_order(
        r,
        &[
            "let mut s = connect(socket, timeout)?;",
            "let state = state_on(&mut s)?;",
            "if state == \"stopping\" {",
            "libc::kill(1, libc::SIGHUP)",
            "match reloading_signal(&msg)? {",
            "Some(false) => return Ok(\"reloaded (Reloading(false) received)\"),",
        ],
    )
    .unwrap();
    assert!(
        !r.contains("Manager.Reload") && !r.contains("\"Reload\""),
        "no Manager.Reload() call:\n{r}"
    );
    assert!(body(&sd, "reload").contains("reload_verified(socket, Duration::from_secs(30))"));
    // PID 1 serves the socket: the peer check of every exchange
    in_order(
        body(&sd, "connect"),
        &[
            "let peer = peer_pid(&s)?;",
            "if peer != 1 {\n        return Err(",
        ],
    )
    .unwrap();
    // The review of #492 (C1), round 7: no reload while a harmful host
    // drop-in is on disk (a window's reload applied a 4K system.slice)
    let rl = code("crates/nn-linux/src/systemd_reload.rs");
    in_order(
        body(&rl, "worker"),
        &[
            "crate::host_dropins::harmful(&search, &crate::host_dropins::HostLimits::read());",
            "match outcome(&harms, || {\n            crate::systemd_state::reload_verified(socket, RELOAD_TIMEOUT)\n        }) {",
            "Outcome::Withheld(what) => {",
            "crate::boot::degradation::report(",
            "Outcome::Confirmed(note) => {",
            "antitamper_bpf::unit_props::below_floors(socket, PROPS_TIMEOUT)",
            "after();",
            "Outcome::Failed(e) => {",
            "crate::boot::degradation::report(",
        ],
    )
    .unwrap();
    // Lot 273d: a refusal within the target's quiet is verified, not skipped
    assert!(
        body(&rl, "worker").contains("Decision::Skip => match hostile_copy(socket, &on_disk) {")
    );
    in_order(
        body(&rl, "outcome"),
        &[
            "if let Some(h) = crate::host_dropins::withholding(harms) {",
            "return Outcome::Withheld(",
            "match reload() {",
        ],
    )
    .unwrap();
    // lot 278: `arm_by` arms through `arm_for` (the grant's installer)
    let ti = code("crates/nn-linux/src/anti_tamper/trusted_installer.rs");
    assert!(
        body(&ti, "arm_by").contains("self.arm_for(window_secs, now, key_id, None)"),
        "arm_by arms through arm_for"
    );
    in_order(
        body(&ti, "arm_for"),
        &[
            "self.armed.store(true, Ordering::SeqCst);",
            "let harms = crate::host_dropins::harmful_here();",
            "crate::host_dropins::note_degradation(&harms);",
            "r.request(crate::systemd_reload::Reason::WindowOpened);",
        ],
    )
    .unwrap();
    let si = code("crates/nn-linux/src/self_integrity.rs");
    in_order(
        body(&si, "round"),
        &[
            "antitamper_bpf::cgroup_floors::take_restores()",
            "\"limit_floor_restored\"",
        ],
    )
    .unwrap();
    // The review of #492 (C1): the host's drop-ins judged by their value
    // for our units, each a finding of the round; none moved, written or
    // deleted — the module only reads.
    in_order(
        body(&si, "collect_round"),
        &[
            "c.extend(unit_dropins(&search));",
            "crate::host_dropins::harmful(&search, &crate::host_dropins::HostLimits::read());",
            "crate::host_dropins::note_degradation(&harms);",
            "c.extend(harms.into_iter().map(|h| Finding {",
            "crate::host_dropins::Kind::Harmful => \"unit_dropin_harmful\",",
            "crate::host_dropins::Kind::BreaksAgent => \"unit_dropin_breaks_agent\",",
        ],
    )
    .unwrap();
    assert!(
        body(&si, "unit_dropins_with").contains("for (d, _) in crate::host_dropins::TYPE_DIRS {")
    );
    let hd = code("antitamper-bpf/src/host_dropins.rs");
    let hd = &hd[..hd.find("#[cfg(test)]").expect("its tests")];
    for call in [
        "fs::rename",
        "fs::remove_file",
        "fs::write",
        "fs::copy",
        "create_dir",
        "OpenOptions",
        "File::create",
        "Reason::",
    ] {
        assert!(!hd.contains(call), "host_dropins.rs only reads: {call}");
    }
    // Lot 311 (the review of #538, F9): the judges' reads of a drop-in or an
    // environment file go through `config_read`, which opens read-only —
    // never for writing, creating, truncating or appending — and nothing else
    let cr = code("antitamper-bpf/src/config_read.rs");
    let cr = &cr[..cr.find("#[cfg(test)]").expect("its tests")];
    for call in [
        "fs::rename",
        "fs::remove_file",
        "fs::write",
        "fs::copy",
        "create_dir",
        "File::create",
        "Reason::",
        ".write(",
        ".create(",
        ".create_new(",
        ".append(",
        ".truncate(",
    ] {
        assert!(!cr.contains(call), "config_read.rs only reads: {call}");
    }
    assert_eq!(cr.matches("OpenOptions::new()").count(), 1);
    assert!(in_order(cr, &["OpenOptions::new()", ".read(true)", ".open(path)"]).is_ok());
    assert!(!si.contains("Reason::Quarantined") && !si.contains("dropin_quarantine"));
    // Lot 273d: the watchdog reads systemd's copy before each respawn (a
    // reload unless a harmful host drop-in withholds it), and the agent
    // takes the files at their floors back to their configured values after
    // a confirmed reload
    let wm = code("watchdog/src/main.rs");
    in_order(
        &wm,
        &[
            "northnarrow_watchdog::check_systemds_copy(&hold, pid)",
            "let _ = std::fs::remove_file(&cli.agent_pidfile);",
            "r = respawn_cycle(",
        ],
    )
    .unwrap();
    in_order(
        body(&code("watchdog/src/lib.rs"), "check_systemds_copy"),
        &[
            "below_floors(socket, timeout)",
            "if let Some(h) = antitamper_bpf::host_dropins::withholding(&harms) {",
            "antitamper_bpf::systemd_bus::reload_verified(",
            "record_hold(hold_path, &rec)",
        ],
    )
    .unwrap();
    assert!(code("agent/src/boot/mod.rs")
        .contains("northnarrow_agent::anti_tamper::cgroup_guard::back_to_configured("));
    in_order(
        body(
            &code("crates/nn-linux/src/anti_tamper/cgroup_guard.rs"),
            "back_to_configured",
        ),
        &[
            "antitamper_bpf::unit_props::configured_text(",
            "if below_floor(\n            common::cgroup_limits::limit_kind_of(name),\n            &configured,\n            &floor,\n        ) {",
            "continue;",
            "std::fs::write(&path, format!(\"{configured}\\n\"))",
            "refresh_values(bpffs_root);",
        ],
    )
    .unwrap();
    // Lot 273d: at a window's close our units' own drop-ins made inside it
    // are judged (a harmful one quarantined, a reload asked); only our
    // directories — the host's are never moved
    let ti = code("crates/nn-linux/src/anti_tamper/trusted_installer.rs");
    in_order(
        &ti,
        &[
            "super::cgroup_guard::refresh_values(self.bpffs_root.as_deref());",
            "own_dropins_at_close(since, self.bpffs_root.as_deref(), &self.own_dropin_keys);",
            "r.request(crate::systemd_reload::Reason::OwnDropinQuarantined);",
            // R1: the guarded sysctls put back at the close, in its record
            "let sysctls = sysctls_at_close();",
            "self.audit_close(reason, close_failed.as_deref(), &lines, &sysctls);",
        ],
    )
    .unwrap();
    in_order(
        body(&ti, "sysctls_at_close"),
        &[
            "crate::sysctl_guard::check(",
            // lot 341: written unless the start's `alpha` profile is on
            // (`xtask/tests/host_deny.rs`; a `sysctl_would_restore` then)
            "!crate::anti_tamper::host_deny::observing(),",
            ".filter(|s| s.kind != \"sysctl_strict\" && s.kind != \"sysctl_opted_out\")",
        ],
    )
    .unwrap();
    assert!(body(&ti, "audit_close").contains("extra[\"sysctls\"] = serde_json::json!(sysctls);"));
    // the re-review of #497 (RR1): at the close the kept drop-ins are
    // write-protected (the pinned map), the pass finished (stale keys out)
    in_order(
        body(&ti, "own_dropins_at_close"),
        &[
            "crate::own_dropins::Protector::open(bpffs_root, keys);",
            "when: crate::own_dropins::AT_CLOSE,",
            "&mut |p| protector.protect(p),",
            "protector.finish();",
        ],
    )
    .unwrap();
    let od = code("crates/nn-linux/src/own_dropins.rs");
    in_order(
        body(&od, "own_dirs"),
        &[
            "root.join(\"northnarrow-agent.service.d\")",
            "root.join(\"northnarrow-watchdog.service.d\")",
            "root.join(\"northnarrow-.service.d\")",
        ],
    )
    .unwrap();
    assert!(
        !od.contains("TYPE_DIRS")
            && !od.contains("\"service.d\"")
            && !od.contains("\"slice.d\"")
            && !od.contains("system.slice.d"),
        "own_dropins moves from our directories only"
    );
    // the review of #497 (D4): selected by ctime (no `touch -d` sets it
    // back), never by the mtime; links and outside EnvironmentFile=
    // quarantined whatever they set; the round judges every one again
    // outside a window
    let q = body(&od, "harmful");
    assert!(!q.contains("modified()"), "no selection by mtime");
    // the re-review of #497 (RR1): an entry kept — not judged in this
    // pass, install.sh's, or judged harmless — is protected with the
    // environment files it names
    in_order(
        q,
        &[
            "std::fs::symlink_metadata(&from)",
            "let single = regular && meta_nlink(&meta) == 1;",
            "if !changed_since(&meta, pass.since) {",
            "keep_protected(&from, text.as_deref(), protect);",
            "if single && known(&from, b) {",
            "keep_protected(&from, text.as_deref(), protect);",
            "shape_harm(&meta, &from, text.as_deref(), protect)",
            "let Some(why) = why else {\n                    keep_protected(&from, text.as_deref(), protect);",
        ],
    )
    .unwrap();
    in_order(
        body(&od, "keep_protected"),
        &[
            "protect(from);",
            "if under_env_dir(&f) {",
            "protect(Path::new(&f));",
        ],
    )
    .unwrap();
    in_order(
        body(&od, "protect"),
        &[
            "if !meta.file_type().is_file() || meta.nlink() != 1 {",
            "let want = had.unwrap_or(0) | FS_PROTECT_WRITE | FS_PROTECT_MUTATE;",
            "map.register(key, want)",
        ],
    )
    .unwrap();
    assert!(body(&od, "changed_since").contains("meta.ctime()"));
    in_order(
        body(&od, "shape_harm"),
        &[
            "is_symlink()",
            "is_file()",
            "meta.nlink() > 1",
            "for f in env_files(text?) {",
            "if !under_env_dir(&f) {",
            // RR1: one inside /etc/northnarrow held, or the drop-in moved
            "if !protect(Path::new(&f)) {",
        ],
    )
    .unwrap();
    assert!(body(&od, "under_env_dir")
        .contains("matches!(c, Component::RootDir | Component::Normal(_))"));
    // the re-review of #497 (RR2): the round judges only what changed
    // since the agent's install — an operator's drop-in from before it is
    // never moved by the round; (RR1) the ones it keeps are protected
    in_order(
        body(&si, "own_dropins_round"),
        &[
            "if g.window.is_window_open() {\n            return;\n        }",
            "let Some(since) = crate::own_dropins::install_time() else {",
            "crate::own_dropins::Protector::open(g.window.bpffs_root(), g.window.own_dropin_keys());",
            "crate::own_dropins::quarantine(",
            "when: crate::own_dropins::AT_ROUND,",
            "&mut |p| protector.protect(p),",
            "protector.finish();",
            "Reason::OwnDropinQuarantined",
        ],
    )
    .unwrap();
    assert!(!body(&si, "own_dropins_round").contains("UNIX_EPOCH"));
    // the short re-check of #497: an unreadable install time is said,
    // signed (NB6); a harmful drop-in from before the install reported,
    // signed, never moved (RB1)
    in_order(
        body(&si, "own_dropins_round"),
        &[
            "let Some(since) = crate::own_dropins::install_time() else {",
            "kind: \"own_dropin_round_skipped\",",
            "return;",
            "crate::own_dropins::quarantine(",
            "crate::own_dropins::nn_settings(&search)",
            "let (kind, alert) = n.record();",
            "if alert {\n                self.report_once(f, at_boot);\n            } else {\n                self.record_once(f, at_boot);",
            "crate::own_dropins::preinstall_harmful(",
            "kind: \"own_dropin_preinstall_harmful\",",
        ],
    )
    .unwrap();
    // our drop-ins' environment judged by our judge: NN_ kept, loader harmful
    assert!(body(&od, "harmful").contains("own_harms(reach, &k, &v, host)"));
    assert!(body(&od, "own_harms").contains("LOADER_ENV.contains(&n.as_str())"));
    in_order(
        body(&od, "install_time"),
        &["std::fs::metadata(\"/proc/self/exe\")", "meta.ctime()"],
    )
    .unwrap();
    assert!(!body(&od, "install_time").contains("mtime"));
    assert!(body(&si, "round").contains("self.own_dropins_round(at_boot);"));
    assert!(code("agent/src/boot/evidence.rs")
        .contains("Some(northnarrow_agent::self_integrity::OwnDropinGuard {"));
    // Lot 273d: the guarded sysctls checked by the round (put back when harmful)
    in_order(
        body(&si, "collect_round"),
        // lot 341: written unless the start's `alpha` profile is on
        &[
            "crate::sysctl_guard::check(",
            "!crate::anti_tamper::host_deny::observing(),",
        ],
    )
    .unwrap();
    // R1: ftrace_enabled read at every build of the capability manifest
    in_order(
        body(&code("agent/src/boot/manifest.rs"), "build"),
        &[
            "nn_linux::sysctl_guard::note_ftrace(&inputs.proc_root);",
            "m.degradations = degradation::snapshot();",
        ],
    )
    .unwrap();
    assert!(code("agent/src/boot/ready.rs").contains("proc_root: std::path::PathBuf::from(\"/\"),"));
    let ab = code("antitamper-bpf/src/cgroup_guard.rs");
    in_order(
        body(&ab, "protect_unit_cgroup"),
        &[
            "write_values(bpffs_root, unit.values())?;",
            "floors(bpffs_root, &unit);",
        ],
    )
    .unwrap();
    in_order(
        body(&ab, "refresh_unit_values"),
        &[
            "write_values(bpffs_root, unit.values())?;",
            "floors(bpffs_root, &unit);",
        ],
    )
    .unwrap();
    let g = code("crates/nn-linux/src/anti_tamper/cgroup_guard.rs");
    in_order(
        body(&g, "register_unit_cgroups"),
        &[
            "register_value(ebpf, &f.key, &f.value)?;",
            "antitamper_bpf::cgroup_floors::floors_due(",
            "antitamper_bpf::cgroup_floors::restore_floors(due, |k, v| {\n                        register_value(ebpf, k, v)\n                    });",
        ],
    )
    .unwrap();
    // the floor is registered before it is written
    in_order(
        body(
            &code("antitamper-bpf/src/cgroup_floors.rs"),
            "restore_floors",
        ),
        &[
            "register(&d.key, &value)",
            "std::fs::write(&d.path,",
            "std::fs::read_to_string(&d.path)",
        ],
    )
    .unwrap();
    // the watchdog checks the agent's fresh cgroup at its start and after a
    // respawn
    let w = code("watchdog/src/main.rs");
    assert_eq!(
        w.matches("northnarrow_watchdog::check_agent_cgroup(")
            .count(),
        2
    );
    // ... their restorations recorded where the agent signs them, as its
    // own kinds
    for (i, _) in w
        .match_indices("northnarrow_watchdog::check_agent_cgroup(")
        .chain(w.match_indices("register_own_cgroup(\n"))
    {
        let call = &w[i..i + w[i..].find(");").expect("the call's end")];
        assert!(
            call.contains("&hold_record_path(&cli.shutdown_marker),"),
            "{call}"
        );
    }
    let wl = code("watchdog/src/lib.rs");
    for f in ["check_agent_cgroup", "register_own_cgroup"] {
        assert!(
            body(&wl, f).contains("record_floor_restores(hold_path, agent_pid);"),
            "{f}"
        );
    }
    in_order(
        body(&wl, "record_floor_restores"),
        &[
            "antitamper_bpf::cgroup_floors::take_restores()",
            "record_hold(hold_path, &rec)",
        ],
    )
    .unwrap();
    in_order(
        body(&code("crates/nn-linux/src/self_integrity.rs"), "watchdog_holds"),
        &[
            "wh::REASON_LIMIT_FLOOR_RESTORED => (\n                            \"limit_floor_restored\",",
            "wh::REASON_LIMIT_FLOOR_NOT_RESTORED => (\n                            \"limit_floor_not_restored\",",
        ],
    )
    .unwrap();
}

/// The re-review of #497 (NR5, NR6): the eBPF CI job runs the `check_cfg`
/// emulation against the object it built — after the build, with the
/// object required — and the step fails unless both tests ran and passed
/// (libtest skips a name it does not find in silence).
#[test]
fn the_ebpf_job_runs_the_check_cfg_tests_and_counts_them() {
    let ci: serde_yaml_ng::Value = serde_yaml_ng::from_str(
        &fs::read_to_string(repo_root().join(".github/workflows/ci.yml")).unwrap(),
    )
    .unwrap();
    let steps = ci["jobs"]["ebpf-build"]["steps"]
        .as_sequence()
        .expect("ci.yml has the ebpf-build job's steps");
    let name = |s: &serde_yaml_ng::Value| s["name"].as_str().unwrap_or_default().to_string();
    let built = steps
        .iter()
        .position(|s| name(s) == "cargo xtask build-ebpf")
        .expect("the job builds the object");
    let at = steps
        .iter()
        .position(|s| name(s).starts_with("eBPF object back-edges"))
        .expect("the check_cfg step is in the eBPF job");
    assert!(built < at, "the step runs on the object just built");
    let step = &steps[at];
    assert_eq!(step["env"]["NN_REQUIRE_EBPF_OBJECT"].as_str(), Some("1"));
    let run = step["run"].as_str().unwrap();
    in_order(
        run,
        &[
            "cargo test --locked -p nn-linux --lib sensors::ebpf_object::tests -- --exact",
            "sensors::ebpf_object::tests::no_function_has_a_back_edge_the_5_15_verifier_rejects",
            "sensors::ebpf_object::tests::the_back_edge_emulation_tells_a_fallthrough_from_a_jump",
            "|| { echo \"$out\"; exit 1; }",
            "grep -q '^test result: ok\\. 2 passed; 0 failed' <<< \"$out\" || {",
            "exit 1; }",
        ],
    )
    .unwrap();
    // both names are tests of the emulation that exist
    let tests = code("crates/nn-linux/src/sensors/ebpf_object.rs");
    for t in [
        "fn no_function_has_a_back_edge_the_5_15_verifier_rejects()",
        "fn the_back_edge_emulation_tells_a_fallthrough_from_a_jump()",
    ] {
        assert!(tests.contains(t), "{t}");
    }
}

/// The short re-check of #497 (NB5): the units moved from `system.slice`
/// to their own `northnarrow.slice`, and the exec policy's kernel side gave
/// them the UNKNOWN tier instead of SERVICE. Their slice is published and
/// judged a service slice, as `system.slice` was for them.
#[test]
fn the_units_own_slice_is_a_service_tier() {
    let e = code("agent-ebpf/src/execpol.rs");
    in_order(
        body(&e, "tier_of"),
        &[
            "let sys = slice(slice_slot::SYSTEM);",
            "let ours = slice(slice_slot::OURS);",
            "if cg1 != 0 && cg1 == sys {",
            "return tier::SERVICE | sig | tier_sig::SYSTEM_SLICE;",
            "if cg1 != 0 && cg1 == ours {",
            "return tier::SERVICE | sig | tier_sig::OUR_SLICE;",
        ],
    )
    .unwrap();
    let k = code("agent/src/execpol/kernel.rs");
    assert!(body(&k, "slice_ids").contains("id(\"northnarrow.slice\")"));
    assert!(body(&k, "set_slices").contains("self.slices.set(slice_slot::OURS, ours, 0);"));
}
