//! Lot 280a: the guarded sysctls judged on the kernel's copy of the write —
//! the parts no host test runs.
//!
//! The `cgroup/sysctl` program runs only in a kernel (the lab's
//! `sysctl-check` shows what it refuses, the race included); here its code
//! is read, as `cgroup_guard.rs` reads the write deny's: the value it
//! judges is the kernel's copy and nothing else, read in base 0, judged by
//! the shared verdict after the caller's identity; the write deny honours
//! the same opt-out and records it only where the program does not run;
//! the agent links the program to the root cgroup with no flag (the
//! kernel's multi mode), checks the root's report, and pins it beside the
//! pin root, its link registered as the agent's own.

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

/// Named test (lot 280a): a second thread that changes the writer's buffer
/// changes nothing the program judges — it reads the value only through
/// `bpf_sysctl_get_new_value` (the kernel's copy, which the handler then
/// parses), never the writer's memory, and reads it in base 0.
#[test]
fn a_race_thread_is_judged_on_the_kernel_copy() {
    let g = code("agent-ebpf/src/sysctl_guard.rs");
    assert!(g.contains("#[cgroup_sysctl]\npub fn nn_sysctl_guard(ctx: SysctlContext) -> i32 {"));
    // no user memory, no registers: the writer's buffer is never read
    for never in [
        "probe_read_user",
        "bpf_task_pt_regs",
        "written_value",
        "written_bytes",
        "bpf_sysctl_get_current_value",
        "bpf_sysctl_set_new_value",
    ] {
        assert!(!g.contains(never), "{never} in the sysctl judge");
    }
    // the kernel's copy, in base 0, a value past the buffer refused
    in_order(
        body(&g, "new_value"),
        &[
            "generated::bpf_sysctl_get_new_value(ctx.sysctl, p, VALUE_BUF as u64) < 0 {\n        return None;\n    }",
            "generated::bpf_strtol(p, VALUE_BUF as u64, BASE_0, &mut res) < 0 {\n        return None;\n    }",
            "Some(res as i64)",
        ],
    )
    .unwrap();
    assert!(g.contains("const BASE_0: u64 = 0;"));
    assert!(g.contains("const VALUE_BUF: usize = 64;"));
    assert_eq!(g.matches("new_value(ctx)").count(), 1);
    // a read passes; the name; the caller's identity (the agent's family,
    // a window) before the value; then the shared verdict on the copy
    in_order(
        body(&g, "try_sysctl_guard"),
        &[
            "if (*ctx.sysctl).write == 0 {\n        return SysctlVerdict::Allow;\n    }",
            "let kind = sysctl_of(ctx);",
            "if kind == SYSCTL_NONE {\n        return SysctlVerdict::Allow;\n    }",
            "off!(TASK_STRUCT_TGID_OFFSET)",
            "let caller_may = (tgid != 0 && crate::task_kill::is_exempt_pid(tgid))\n        || crate::inode_protect::override_active();",
            "if caller_may {\n        return SysctlVerdict::Allow;\n    }",
            "let value = new_value(ctx);",
            "let verdict = sysctl_kernel_verdict(kind, false, value, opt_out(kind));",
            "SysctlVerdict::Refuse => record(FS_OP_SYSCTL_VALUE, kind, value, task, tgid, true),",
            "SysctlVerdict::OptedOut => record(FS_OP_SYSCTL_OPT_OUT, kind, value, task, tgid, false),",
            "verdict",
        ],
    )
    .unwrap();
    // only a refusal is 0 (EPERM)
    in_order(
        body(&g, "nn_sysctl_guard"),
        &[
            "SysctlVerdict::Refuse => 0,",
            "SysctlVerdict::Allow | SysctlVerdict::OptedOut => 1,",
        ],
    )
    .unwrap();
    // the name: its full path, a zeroed buffer, a longer one is none
    in_order(
        body(&g, "sysctl_of"),
        &[
            "let mut name = [0u64; 4];",
            "generated::bpf_sysctl_get_name(",
            "SYSCTL_PATH_MAX as u64,\n        0,\n    );",
            "if n <= 0 || n as usize >= SYSCTL_PATH_MAX {\n        return SYSCTL_NONE;\n    }",
            "sysctl_path_kind(n as usize, name)",
        ],
    )
    .unwrap();
    // the opt-out: this session's slot only
    in_order(
        body(&g, "opt_out"),
        &[
            "crate::task_kill::AGENT_SESSION.get(0)",
            "SYSCTL_OPTOUT.get(kind as u32)",
            "Some(slot) => slot.live(session),",
        ],
    )
    .unwrap();
    assert!(g.contains(
        "pub static SYSCTL_OPTOUT: Array<SysctlOptOut> = Array::pinned(SYSCTL_OPTOUT_SLOTS, 0);"
    ));
    assert!(
        g.contains("pub static SYSCTL_KERNEL_JUDGE: Array<u32> = Array::with_max_entries(1, 0);")
    );
    assert!(body(&g, "kernel_judge_attached").contains("Some(v) if *v == 1"));
    // the record: the kind and the value, a refusal behind the dedup
    in_order(
        body(&g, "record"),
        &[
            "off!(TASK_STRUCT_COMM_OFFSET)",
            "crate::inode_protect::emit_sysctl_record(",
            "dev: record_dev(kind, value.is_some()),",
            "ino: value.unwrap_or(0) as u64,",
            "limited,",
        ],
    )
    .unwrap();
    let ip = code("agent-ebpf/src/inode_protect.rs");
    in_order(
        body(&ip, "emit_sysctl_record"),
        &[
            "if limited {",
            "TASK_DENIAL_SEEN.get_ptr_mut(&seen)",
            "TASK_DENIAL_RATE.get_ptr_mut(0)",
            "if (*rate)[1] >= TASK_DENIAL_PER_SEC {",
            "FS_PROTECT_EVENTS.reserve::<FsProtectDenialRaw>(0)",
            "(*raw_ptr).attacker_pid = tgid;",
            "(*raw_ptr).operation = operation;",
            "(*raw_ptr).attacker_comm = comm;",
            "entry.submit(0);",
        ],
    )
    .unwrap();
    assert!(code("agent-ebpf/src/main.rs").contains("mod sysctl_guard;"));
}

/// The write deny (lot 273d) honours the same signed opt-out, and records
/// a write it lets through only where the program does not (one record a
/// write).
#[test]
fn the_write_deny_honours_the_opt_out_and_records_it_once() {
    let c = code("agent-ebpf/src/cgroup_files.rs");
    in_order(
        body(&c, "refuse_sysctl"),
        &[
            "let kind = sysctl_kind(len, words);",
            "let verdict = sysctl_write_verdict(",
            "caller_may(caller),",
            "crate::sysctl_guard::opt_out(kind),",
            "let w = written_value();",
            "read = w.as_ref().and_then(parse_i64);",
            "SysctlVerdict::Allow => return false,",
            "SysctlVerdict::OptedOut => {",
            "if !crate::sysctl_guard::kernel_judge_attached() {",
            "FS_OP_SYSCTL_OPT_OUT,",
            "return false;",
            "SysctlVerdict::Refuse => {}",
            "sign(phase, FS_OP_SYSCTL, key);",
        ],
    )
    .unwrap();
}

/// Named test (lot 280a): a child cgroup's program cannot override the
/// judge — the agent links it to the root cgroup with no flag (a cgroup
/// link is attached `BPF_F_ALLOW_MULTI` by the kernel), never through
/// `BPF_PROG_ATTACH` (whose flags could say override), checks the root's
/// report after its pins, and registers the link as its own.
#[test]
fn the_judge_is_linked_to_the_root_cgroup_multi() {
    let s = code("crates/nn-linux/src/sysctl_cgroup.rs");
    assert!(s.contains("pub const LINK_FLAGS: u32 = 0;"));
    assert!(!s.contains("BPF_PROG_ATTACH"));
    assert!(!s.contains("CgroupAttachMode"));
    assert!(!s.contains(".attach("));
    in_order(
        body(&s, "link_create"),
        &[
            "attach_type: BPF_CGROUP_SYSCTL,",
            "flags: LINK_FLAGS,",
            "common::bpf_cmd::BPF_LINK_CREATE",
        ],
    )
    .unwrap();
    in_order(
        body(&s, "attach_inner"),
        &[
            "let root = open_root_cgroup()?;",
            "prog.load()",
            "link_create(fd.as_fd().as_raw_fd(), root.as_raw_fd())",
            "purge_pins(d, false);",
            "prog.pin(&prog_pin)",
            "obj_pin(link.as_raw_fd(), &link_pin)",
            "let q = query_root(root.as_raw_fd())",
            "let others = judge_query(&q, own)?;",
            "let _ = LINK.set(link);",
        ],
    )
    .unwrap();
    in_order(
        body(&s, "open_root_cgroup"),
        &["cgroup2_root(&table)", "if ino != ROOT_CGROUP_INO {"],
    )
    .unwrap();
    // in the anti-tamper attach: after the tracker, before the BPF guard
    // registers the agent's own objects (the link among them), the pins
    // protected with the others
    let m = code("crates/nn-linux/src/anti_tamper/mod.rs");
    let at = body(&m, "attach_reporting");
    in_order(
        at,
        &[
            "crate::cgroup_join::install(tracker);",
            "match crate::sysctl_cgroup::attach(ebpf, pin_root) {",
            "bpf_defense::attach(bpf_guard, ebpf, &btf, pin_root)",
            "bpf_defense::register_own_objects(bpf_guard, ebpf, pin_root)",
            "filesystem::register_bpffs_pins(ebpf, &crate::sysctl_cgroup::pin_dir(root))",
            "filesystem::prune_stale_inodes(ebpf)",
        ],
    )
    .unwrap();
    let d = code("crates/nn-linux/src/anti_tamper/bpf_defense.rs");
    assert!(body(&d, "register_own_objects")
        .contains("pin_name_key(&format!(\"link_{}\", crate::sysctl_cgroup::PROGRAM))"));
    assert!(body(&d, "kept_program").contains("crate::sysctl_cgroup::is_kept_program(name)"));
    // the manifest's note, the verifier check
    assert!(code("crates/nn-linux/src/sensors/multiplexer.rs")
        .contains("self.attach_points.note(\"sysctl_judge\", &note, took);"));
    assert!(code("crates/nn-linux/src/verifier_check.rs")
        .contains("Program::CgroupSysctl(p) => p.load(),"));
}

/// The opt-out reaches the kernel only signed: the start passes the gate's
/// word on the very text it applies, the admin socket's `policy set` a
/// verified request; the uninstall removes the judge's pins.
#[test]
fn the_opt_out_is_applied_where_the_policy_is() {
    let p = code("agent/src/boot/policy.rs");
    in_order(
        &p,
        &[
            "overlay_gate.signs(OverlayKind::RulePolicy, &path, &text),",
            "nn_linux::sysctl_cgroup::apply_policy(&policy, signed)",
        ],
    )
    .unwrap();
    let a = code("agent/src/admin/handlers/config.rs");
    in_order(
        &a,
        &[
            "let previous = rule_policy.install(boot.policy);",
            "nn_linux::sysctl_cgroup::apply_policy(&rule_policy.current(), true)",
        ],
    )
    .unwrap();
    let raw = |rel: &str| fs::read_to_string(repo_root().join(rel)).unwrap();
    let u = raw("deploy/uninstall.sh");
    assert!(
        u.contains("for d in \"$BPFFS_ROOT\"-cgroup-join-v* \"$BPFFS_ROOT\"-sysctl; do"),
        "uninstall.sh removes the judge's pins"
    );
    let l = raw("deploy/lab/nn-lab.sh");
    assert!(
        l.contains(
            "/sys/fs/bpf/northnarrow-cgroup-join-v* /sys/fs/bpf/northnarrow-sysctl 2>/dev/null"
        ),
        "the lab's purge removes them"
    );
}
