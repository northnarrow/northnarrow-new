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
            "if !crate::task_kill::is_protected_pid(tgid) {",
            "if crate::task_kill::is_exempt_pid((pid_tgid >> 32) as u32) {",
            "if crate::inode_protect::override_active() {",
            "CGROUP_MOVES.insert(&pid_tgid, &rec, 0)",
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
            "CGROUP_MOVES.remove(&pid_tgid)",
            ">= STASH_TTL_NS",
            "crate::inode_protect::override_active()",
            "crate::task_kill::is_exempt_pid((pid_tgid >> 32) as u32)",
            "emit_task_denial(FS_OP_CGROUP_MOVE, 0, rec[0] as u32)",
            "-EPERM",
        ],
    )
    .unwrap();
    // the map ages its leftovers out rather than filling up
    assert!(g.contains("static CGROUP_MOVES: LruHashMap<u64, [u64; 2]>"));
}

#[test]
fn the_inode_deny_lets_only_init_remove_a_unit_cgroup_and_signs_by_effect() {
    let i = code("agent-ebpf/src/inode_protect.rs");
    let d = body(&i, "deny_if_protected");
    in_order(
        d,
        &[
            "if flags & required == 0 {",
            "if override_active() {",
            "if crate::task_kill::is_exempt_pid(caller_tgid) {",
            "if fs_protect_init_may(operation, flags, caller_tgid) {",
            "emit_denial(fs_protect_denied_op(operation, flags), key);",
            "true",
        ],
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
            "cgroup_guard::register_unit_cgroups(ebpf, &cgroup_pids)",
            "filesystem::attach(ebpf, &btf, pin_root)",
            "cgroup_guard::attach_move_guard(ebpf, &btf, pin_root)",
            "bpf_defense::register_own_objects(bpf_guard, ebpf, pin_root)",
            "filesystem::prune_stale_inodes(ebpf)",
        ],
    )
    .unwrap();
    // the refusal half attached first, then the lookup half
    let g = code("crates/nn-linux/src/anti_tamper/cgroup_guard.rs");
    in_order(
        body(&g, "attach_move_guard"),
        &[
            "reattach_fresh(ebpf, MOVE_DENY_PROGRAM, MOVE_DENY_HOOK, btf, pin_root)",
            "reattach_fresh_fexit(",
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
    assert!(code("agent/src/boot/tasks.rs").contains("cgroup_guard::protect_watchdog_cgroup("));
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
