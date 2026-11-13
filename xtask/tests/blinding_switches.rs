//! Lot 280b: the switches that blind the sensors — the parts no host test
//! runs. The eBPF programs run only in a kernel (the lab's
//! `nn-lab.sh switches-check` shows what they refuse and count); here the
//! code is read: each check the defence rests on is there, in the order
//! that makes it hold, and the agent wires it where it decides.

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

/// Named (item 1): the fentry records each new thread group before
/// anything else of the birth; the fork's tracepoint checks it for every
/// new thread group before it looks at the parent's mark, takes the entry
/// away, and makes a missed child not known and counted — only once the
/// check is armed and for a child started after it.
#[test]
fn the_fork_tracepoint_checks_every_birth_the_fentry_saw() {
    let c = code("agent-ebpf/src/cgroup_join.rs");
    assert!(c.contains(
        "static CGROUP_JOIN_BORN: HashMap<u32, u8> = HashMap::with_max_entries(BORN_ENTRIES, 0);"
    ));
    assert!(c.contains(
        "pub static CGROUP_JOIN_SILENT: Array<u64> = Array::with_max_entries(SILENT_SLOTS, 0);"
    ));
    in_order(
        body(&c, "try_born"),
        &[
            "if tgid == forker {\n        return;\n    }",
            "let _ = CGROUP_JOIN_BORN.insert(&tgid, &1, 0);",
            "found(tgid);",
        ],
    )
    .unwrap();
    in_order(
        body(&c, "try_fork"),
        &[
            "let Some(ptgid) = tgid_of(parent) else {",
            "if check_birth(ptgid, child) {\n        return;\n    }",
            "let (marked, phow) = match CGROUP_JOINED.get(&ptgid) {",
        ],
    )
    .unwrap();
    in_order(
        body(&c, "check_birth"),
        &[
            "if ctgid == ptgid {\n        return false;\n    }",
            "let seen = CGROUP_JOIN_BORN.get(&ctgid).is_some();",
            "let _ = CGROUP_JOIN_BORN.remove(&ctgid);",
            "CGROUP_JOIN_SILENT.get(SILENT_ARMED)",
            ".unwrap_or(u64::MAX);",
            "if !unseen_birth(armed, start, seen) {\n        return false;\n    }",
            "lose(ctgid);",
            "CGROUP_JOIN_SILENT.get_ptr_mut(SILENT_UNSEEN)",
            "*n += 1;",
            "CGROUP_JOIN_SILENT.get_ptr_mut(SILENT_LAST_NS)",
            "*t = bpf_ktime_get_ns();",
            "true",
        ],
    )
    .unwrap();
    // the agent arms it once its programs run, before it takes the maps
    let l = code("crates/nn-linux/src/cgroup_join.rs");
    let a = body(&l, "attach");
    in_order(
        a,
        &[
            "pin_fresh(ebpf, dir, name, *kind)",
            "if let Err(e) = arm_silent(ebpf) {",
            "signed.push(",
            "take(ebpf, SILENT_MAP)?",
        ],
    )
    .unwrap();
    assert!(body(&l, "arm_silent")
        .contains("arr.set(SILENT_ARMED, clock_ns(libc::CLOCK_MONOTONIC)?, 0)"));
    // and the manifest's build watches the marks right after ftrace's read
    let m = code("agent/src/boot/manifest.rs");
    in_order(
        body(&m, "build"),
        &[
            "let ftrace = nn_linux::sysctl_guard::note_ftrace(&inputs.proc_root);",
            "nn_linux::cgroup_join::watch_marks(ftrace.degradation().as_deref());",
            "m.degradations = degradation::snapshot();",
        ],
    )
    .unwrap();
    // the reset writes the epoch the kernel and the agent read
    in_order(
        body(&l, "watch_marks"),
        &[
            "marks_step(&mut w, ftrace_off, marks.unseen_births(), &now)",
            "MarksStep::Lost(line) => {",
            "crate::boot::degradation::report(MARKS_LOST_DEGRADATION, &line)",
            "MarksStep::Reset(line) => match marks.reset_epoch() {",
            "crate::boot::degradation::withdraw(MARKS_LOST_DEGRADATION, &[]);",
            "crate::boot::degradation::report(MARKS_LOST_DEGRADATION, &line)",
        ],
    )
    .unwrap();
}

/// Named (item 5): the bpf hook refuses a cgroup/sysctl attach whose target
/// is the cgroup v2 root — outside a window, past the family and a fresh
/// instance, a target it cannot read refused too — signed, before the
/// observation. Lot 290: in every mode (it held in enforce mode only: the
/// lab's observe build let it through).
#[test]
fn the_bpf_hook_refuses_a_cgroup_sysctl_attach_to_the_root() {
    let c = code("agent-ebpf/src/bpf_defense.rs");
    let h = body(&c, "try_bpf_syscall_observe");
    in_order(
        h,
        &[
            "if !observed(cmd) {\n        return 0;\n    }",
            "if caller_is_exempt() {",
            "BPF_PROG_ATTACH | BPF_LINK_CREATE => 8,",
            "if judges_attach_target(cmd, arg)\n        && !crate::inode_protect::override_active()\n        && !fresh_instance_may_load()\n    {",
            "Some(off) if !attr.is_null() => {",
            "None => ROOT_UNREADABLE,",
            "if root != ROOT_NO {\n            emit_denial(FS_OP_SYSCTL_ROOT_ATTACH, arg);\n            return -EPERM;\n        }",
            "let foreign_handle =\n        own_map_handle || own_prog_handle || own_link_handle || own_link_pin || own_dir_pin;",
        ],
    )
    .unwrap();
    in_order(
        body(&c, "fd_is_root_cgroup"),
        &[
            "if fd >= max {\n        return Ok(false);\n    }",
            "off!(FILE_F_INODE_OFFSET)",
            "off!(INODE_I_SB_OFFSET)",
            "off!(SUPER_BLOCK_S_MAGIC_OFFSET)",
            "if !matches!(special_fs(magic), Some(SpecialFs::Cgroup2)) {\n        return Ok(false);\n    }",
            "off!(INODE_I_INO_OFFSET)",
            "Ok(ino == ROOT_CGROUP_INO)",
        ],
    )
    .unwrap();
    assert!(c.contains("const ROOT_CGROUP_INO: u64 = 1;"));
    // the kernel-state round asks the root again and signs what it finds,
    // through the bus as the fs_protect source
    let k = code("crates/nn-linux/src/kernel_state.rs");
    in_order(
        body(&k, "round"),
        &[
            "w.taint(tainted(root))",
            // lot 304: with the known-program judge (a known system
            // program, its loader proven, is signed Low)
            "w.root(crate::sysctl_cgroup::root_report(), known)",
            "crate::boot::degradation::report(ROOT_DEGRADATION, &line)",
        ],
    )
    .unwrap();
    let e = code("agent/src/boot/evidence.rs");
    // (lot 290: with the BPF cross-view)
    assert!(e.contains(
        "nn_linux::kernel_state::spawn(sensor.event_tx_for(\"fs_protect\"), crossview);"
    ));
    let s = code("crates/nn-linux/src/sysctl_cgroup.rs");
    in_order(
        body(&s, "root_report"),
        &[
            "let Some(own) = OWN_PROG.get() else {\n        return Ok(None);\n    };",
            "query_root(root.as_raw_fd())",
            "judge_query(&q, *own).map(Some)",
        ],
    )
    .unwrap();
}

/// Named (items 2-3): the write deny's debugfs and securityfs branch — the
/// manifest's kernel code read at every build.
#[test]
fn the_switch_files_and_the_kernel_code_are_wired() {
    let m = code("agent/src/boot/manifest.rs");
    assert!(body(&m, "build")
        .contains("m.kernel_code = Some(nn_linux::kernel_state::kernel_code(&inputs.proc_root));"));
    let g = code("crates/nn-linux/src/sysctl_guard.rs");
    assert!(g.contains("(KPROBES_ENABLED, SYSCTL_KPROBES_ENABLED, Some(\"1\")),"));
    assert!(g.contains(
        "\"/proc/sys/debug/kprobes-optimization\",\n        SYSCTL_KPROBES_OPTIMIZATION,\n        Some(\"1\"),"
    ));
    assert!(g.contains("pub const KPROBES_ENABLED: &str = \"/sys/kernel/debug/kprobes/enabled\";"));
}
