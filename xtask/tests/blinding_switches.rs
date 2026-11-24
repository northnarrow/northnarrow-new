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
            "if tgid == forker {\n            return;\n        }",
            "let _ = CGROUP_JOIN_BORN.insert(&tgid, &1, 0);",
            "found(tgid);",
        ],
    )
    .unwrap();
    in_order(
        body(&c, "try_fork"),
        &[
            "let Some(ptgid) = tgid_of(parent) else {",
            "if check_birth(ptgid, child) {\n            return;\n        }",
            "let (marked, phow) = match CGROUP_JOINED.get(&ptgid) {",
        ],
    )
    .unwrap();
    in_order(
        body(&c, "check_birth"),
        &[
            "if ctgid == ptgid {\n            return false;\n        }",
            "let seen = CGROUP_JOIN_BORN.get(&ctgid).is_some();",
            "let _ = CGROUP_JOIN_BORN.remove(&ctgid);",
            "CGROUP_JOIN_SILENT.get(SILENT_ARMED)",
            ".unwrap_or(u64::MAX);",
            "if !unseen_birth(armed, start, seen) {\n            return false;\n        }",
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
    assert!(
        body(&l, "arm_silent")
            .contains("arr.set(SILENT_ARMED, clock_ns(libc::CLOCK_MONOTONIC)?, 0)")
    );
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

/// The bpf hook's root `cgroup/sysctl` branch, and the whole of it: the
/// record (the program's tag, read inside the call) and the refusal.
const ROOT_BRANCH: &str = "if root != ROOT_NO {";
const ROOT_REFUSAL: &str = "if root != ROOT_NO {\n                emit_root_attach(attached_prog_tag(cmd, attr), arg);\n                return -EPERM;\n            }";

/// The bpf hook's judged `cgroup/sysctl` attach, whole: the target read,
/// the root asked, the branch.
const JUDGED_ROOT_ATTACH: &str = "
    if judges_attach_target(cmd, arg)
        && !crate::inode_protect::override_active()
        && !fresh_instance_may_load()
    {
        let target = match attach_target_offset(cmd) {
            Some(off) if !attr.is_null() => {
                bpf_probe_read_kernel::<u32>((attr as *const u8).add(off) as *const u32).ok()
            }
            _ => None,
        };
        let root = match target {
            Some(fd) => nn_fd_is_root_cgroup(u64::from(fd)),
            None => ROOT_UNREADABLE,
        };
        if root != ROOT_NO {
            emit_root_attach(attached_prog_tag(cmd, attr), arg);
            return -EPERM;
        }
    }";

/// `word` in `hay` as a whole identifier.
fn has_word(hay: &str, word: &str) -> bool {
    let ident = |c: char| c.is_ascii_alphanumeric() || c == '_';
    hay.match_indices(word).any(|(i, _)| {
        !hay[..i].chars().next_back().is_some_and(ident)
            && !hay[i + word.len()..].chars().next().is_some_and(ident)
    })
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
    // Lot 386 (the review of #594, P2-1): the refusal is unconditional —
    // the one root branch is the record and the refusal, literally: no
    // condition and no return between the branch and `emit_root_attach`
    // (the record's tag is a value read inside the call), so nothing read
    // for the record (the tag of "the known monitor", say) can let an
    // attach through.
    assert_eq!(h.matches(ROOT_BRANCH).count(), 1, "one root branch");
    let branch = &h[h.find(ROOT_BRANCH).unwrap()..];
    let record = branch
        .find("emit_root_attach(")
        .expect("the record in the branch");
    let between = &branch[ROOT_BRANCH.len()..record];
    for word in ["return", "if", "match", "else"] {
        assert!(
            !has_word(between, word),
            "`{word}` between `{ROOT_BRANCH}` and the refusal: {between}"
        );
    }
    assert!(
        branch.starts_with(ROOT_REFUSAL),
        "the root branch is not the record and the refusal alone: {}",
        &branch[..branch.len().min(ROOT_REFUSAL.len() + 120)]
    );
    // the mini-hunt (the same plant one step earlier): nothing between the
    // target's reading and the branch either — the judged block is pinned
    // whole, its comments and spacing aside
    let flat = |s: &str| s.split_whitespace().collect::<Vec<_>>().join(" ");
    assert!(
        flat(h).contains(&flat(JUDGED_ROOT_ATTACH)),
        "the judged root attach is not the target's reading, the root's and the refusal alone"
    );
    in_order(
        h,
        &[
            "if !observed(cmd) {\n            return 0;\n        }",
            "if caller_is_exempt() {",
            "BPF_PROG_ATTACH | BPF_LINK_CREATE => 8,",
            "if judges_attach_target(cmd, arg)\n            && !crate::inode_protect::override_active()\n            && !fresh_instance_may_load()\n        {",
            "Some(off) if !attr.is_null() => {",
            "None => ROOT_UNREADABLE,",
            ROOT_REFUSAL,
            "let foreign_handle =\n            own_map_handle || own_prog_handle || own_link_handle || own_link_pin || own_dir_pin;",
        ],
    )
    .unwrap();
    // the tag, for the record alone: a value of the attach's program fd
    in_order(
        body(&c, "attached_prog_tag"),
        &[
            "match prog_fd_offset(cmd) {",
            "Ok(fd) => nn_prog_tag_of_fd(u64::from(fd)),",
            "Err(_) => 0,",
            "_ => 0,",
        ],
    )
    .unwrap();
    assert!(c.contains("unsafe fn attached_prog_tag(cmd: u32, attr: *const c_void) -> u64 {"));
    in_order(
        body(&c, "fd_is_root_cgroup"),
        &[
            "if fd >= max {\n            return Ok(false);\n        }",
            "off!(FILE_F_INODE_OFFSET)",
            "off!(INODE_I_SB_OFFSET)",
            "off!(SUPER_BLOCK_S_MAGIC_OFFSET)",
            "if !matches!(special_fs(magic), Some(SpecialFs::Cgroup2)) {\n            return Ok(false);\n        }",
            "off!(INODE_I_INO_OFFSET)",
            "Ok(ino == ROOT_CGROUP_INO)",
        ],
    )
    .unwrap();
    assert!(c.contains("const ROOT_CGROUP_INO: u64 = 1;"));
    // lot 386: the record's response, the host-tested words
    assert!(
        code("agent/src/pipeline/process_event.rs")
            .contains("common::bpf_prog_class::root_attach_response(*target_ino)")
    );
    // lot 386: the record's writer, behind the BPF guard's budget
    in_order(
        body(&c, "emit_root_attach"),
        &[
            "crate::inode_protect::emit_attempt(",
            "FS_OP_SYSCTL_ROOT_ATTACH,",
            "dev: tag,",
            "ino: attach_type as u64,",
        ],
    )
    .unwrap();
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
    assert!(
        body(&m, "build").contains(
            "m.kernel_code = Some(nn_linux::kernel_state::kernel_code(&inputs.proc_root));"
        )
    );
    let g = code("crates/nn-linux/src/sysctl_guard.rs");
    assert!(g.contains("(KPROBES_ENABLED, SYSCTL_KPROBES_ENABLED, Some(\"1\")),"));
    assert!(g.contains(
        "\"/proc/sys/debug/kprobes-optimization\",\n        SYSCTL_KPROBES_OPTIMIZATION,\n        Some(\"1\"),"
    ));
    assert!(g.contains("pub const KPROBES_ENABLED: &str = \"/sys/kernel/debug/kprobes/enabled\";"));
}
