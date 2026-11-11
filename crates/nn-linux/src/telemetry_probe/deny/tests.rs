use super::*;
use crate::telemetry_probe::ChildReport;

const TARGET: u32 = 4_300;

fn attempts() -> Vec<usize> {
    (0..HOOK_COUNT)
        .filter(|i| matches!(HOOKS[*i].check, Check::Attempt { .. }))
        .collect()
}

fn keys() -> TargetKeys {
    TargetKeys {
        dir: (0x0080_0001, 77),
        files: file::PROTECTED
            .iter()
            .enumerate()
            .map(|(i, f)| (*f, (0x0080_0001, 100 + i as u64)))
            .collect(),
    }
}

fn refusal(e: &Expected) -> Event {
    Event::FsProtectDenial {
        pid: 4_242,
        uid: 0,
        comm: "northnarrow-age".into(),
        target_dev: e.dev.unwrap_or(9),
        target_ino: e.ino.unwrap_or(1234),
        operation: e.op,
        timestamp_ns: 1,
    }
}

/// Lot 302 (named): every deny hook has its attempt or a declared attach
/// check with its reason — the 22 of `DENY_HOOKS`, the optional ones, the
/// BPF guard's `bpf` and `bpf_prog`, the sysctl judge, the module judge's
/// two; a hook added to the deny set without one fails here. Each one's
/// programs are the ones the agent attaches to it.
#[test]
fn every_deny_hook_has_an_attempt_or_a_declared_attach_check() {
    let named: Vec<&str> = HOOKS
        .iter()
        .map(|h| h.hook)
        .chain(DECLARED.iter().map(|d| d.0))
        .collect();
    let mut want: Vec<&str> = crate::anti_tamper::DENY_HOOKS.to_vec();
    want.extend(crate::anti_tamper::OPTIONAL_DENY_HOOKS);
    want.extend([
        crate::anti_tamper::bpf_defense::OBSERVE_HOOK,
        crate::anti_tamper::bpf_defense::PROG_GUARD_HOOK,
        SYSCTL_JUDGE,
        "kernel_read_file",
        "kernel_load_data",
    ]);
    for w in &want {
        assert_eq!(
            named.iter().filter(|n| *n == w).count(),
            1,
            "{w}: one attempt or attach check"
        );
    }
    assert_eq!(named.len(), want.len(), "no hook of another set: {named:?}");
    // the programs: the FS deny set's table, the task hooks', the guard's
    let fs: Vec<(&str, &str)> = crate::anti_tamper::filesystem::LSM_PROGRAMS
        .iter()
        .chain(crate::anti_tamper::filesystem::OPTIONAL_LSM_PROGRAMS)
        .copied()
        .collect();
    for (program, hook) in fs {
        let h = &HOOKS[slot_of(hook).unwrap()];
        assert_eq!(h.programs, [program], "{hook}");
    }
    let progs = |hook: &str| HOOKS[slot_of(hook).unwrap()].programs;
    assert_eq!(progs("task_kill"), ["task_kill"]);
    assert_eq!(progs("ptrace_access_check"), ["ptrace_access_check"]);
    assert_eq!(
        progs(crate::anti_tamper::bpf_defense::GUARD_HOOK),
        [crate::anti_tamper::bpf_defense::GUARD_PROGRAM]
    );
    assert_eq!(
        progs(crate::anti_tamper::bpf_defense::OBSERVE_HOOK),
        [crate::anti_tamper::bpf_defense::OBSERVE_PROGRAM]
    );
    assert_eq!(
        progs(crate::anti_tamper::bpf_defense::PROG_GUARD_HOOK),
        [crate::anti_tamper::bpf_defense::PROG_GUARD_PROGRAM]
    );
    assert_eq!(progs(SYSCTL_JUDGE), [crate::sysctl_cgroup::PROGRAM]);
    assert_eq!(
        progs(crate::anti_tamper::cgroup_guard::MOVE_DENY_HOOK),
        [crate::anti_tamper::cgroup_guard::MOVE_DENY_PROGRAM]
    );
    assert_eq!(
        progs(crate::anti_tamper::cgroup_guard::MOVE_STASH_HOOK),
        [crate::anti_tamper::cgroup_guard::MOVE_STASH_PROGRAM]
    );
    assert_eq!(
        progs(crate::anti_tamper::cgroup_guard::MOVE_CLEAR_HOOK),
        [crate::anti_tamper::cgroup_guard::MOVE_CLEAR_PROGRAM]
    );
    for h in &HOOKS {
        if let Check::AttachOnly { why } = h.check {
            assert!(why.len() > 40, "{}: a reason", h.hook);
        }
        assert!(!h.step.is_empty(), "{}", h.hook);
    }
    for (hook, program, why) in DECLARED {
        assert!(!program.is_empty() && why.len() > 40, "{hook}");
    }
    // the attempts first, the attach checks after (the slots' order)
    let first_check = HOOKS
        .iter()
        .position(|h| matches!(h.check, Check::AttachOnly { .. }))
        .unwrap();
    assert!(HOOKS[first_check..]
        .iter()
        .all(|h| matches!(h.check, Check::AttachOnly { .. })));
    // never the agent: no attempt's record names the agent
    for i in attempts() {
        if let Check::Attempt { expect, errno, .. } = HOOKS[i].check {
            assert_ne!(expect, Expect::Object { kind: 9, id: None });
            assert!(
                [0, libc::EPERM, libc::EACCES].contains(&errno),
                "{}: a refusal's errno",
                HOOKS[i].hook
            );
        }
    }
}

/// Lot 302 (named, the first test: each hook's attempt is refused — its
/// refusal is told apart): each attempt's refusal is matched to its own
/// hook, once; the hooks whose records share an operation (`write`, the
/// open and the descriptor's; `xattr`, four) are told apart by their own
/// target; a refusal on another target, of another operation or detail,
/// is no hook's.
#[test]
fn each_hooks_refusal_is_matched_to_its_hook_once() {
    let d = DenyExpect::new(&attempts(), &keys(), TARGET, None);
    assert_eq!(d.records.len(), attempts().len());
    let mut matched = [false; HOOK_COUNT];
    for e in d.records.clone() {
        let k = d.matches(&refusal(&e), &matched).unwrap_or_else(|| {
            panic!("{}: not matched", HOOKS[e.slot].hook);
        });
        assert_eq!(d.records[k].slot, e.slot, "{}", HOOKS[e.slot].hook);
        matched[e.slot] = true;
        assert!(d.matches(&refusal(&e), &matched).is_none(), "once");
    }
    let fresh = [false; HOOK_COUNT];
    let at = |hook: &str| {
        d.records[d
            .records
            .iter()
            .position(|e| HOOKS[e.slot].hook == hook)
            .unwrap()]
    };
    // each expectation names its own target: the target process (and the
    // signal, the limit, the value), the directory, the hook's own file,
    // the BPF object's kind
    let file_key = |f: &str| keys().files.iter().find(|(n, _)| *n == f).unwrap().1;
    let k = at("task_kill");
    assert_eq!(
        (k.dev, k.ino),
        (Some(SIGNAL as u64), Some(u64::from(TARGET)))
    );
    let k = at("task_setrlimit");
    assert_eq!((k.dev, k.ino), (Some(RLIMIT), Some(u64::from(TARGET))));
    assert_eq!(at("task_setnice").dev, Some(NICE as u64));
    assert_eq!(at("task_setioprio").dev, Some(IOPRIO as u64));
    let k = at("ptrace_access_check");
    assert_eq!(
        (k.op, k.dev, k.ino),
        (Op::Ptrace, None, Some(u64::from(TARGET)))
    );
    for h in [
        "inode_create",
        "inode_mkdir",
        "inode_mknod",
        "inode_symlink",
        "inode_link",
        "inode_unlink",
        "inode_rmdir",
        "inode_rename",
    ] {
        let k = at(h);
        assert_eq!(
            (k.dev, k.ino),
            (Some(keys().dir.0), Some(keys().dir.1)),
            "{h}"
        );
    }
    for (h, f) in [
        ("inode_setattr", file::ATTR),
        ("file_ioctl", file::ATTR),
        ("file_open", file::WRITE_OPEN),
        ("file_permission", file::WRITE_FD),
        ("inode_setxattr", file::SETXATTR),
        ("inode_removexattr", file::REMOVEXATTR),
        ("inode_set_acl", file::SET_ACL),
        ("inode_remove_acl", file::REMOVE_ACL),
    ] {
        let k = at(h);
        let (dev, ino) = file_key(f);
        assert_eq!((k.dev, k.ino), (Some(dev), Some(ino)), "{h}");
    }
    assert_eq!((at("bpf").dev, at("bpf").ino), (Some(0), Some(2)));
    assert_eq!((at("bpf_map").dev, at("bpf_map").ino), (Some(1), None));
    assert_eq!((at("bpf_prog").dev, at("bpf_prog").ino), (Some(2), None));
    let k = at(crate::anti_tamper::cgroup_guard::MOVE_DENY_HOOK);
    assert_eq!(
        (k.op, k.dev, k.ino),
        (Op::CgroupMove, Some(0), Some(u64::from(TARGET)))
    );
    let k = at("file_send_sigiotask");
    assert_eq!((k.op, k.dev), (Op::Sigio, Some(SIGNAL as u64)));
    // a signal to the agent (another tgid), another signal
    let mut sig = refusal(&at("task_kill"));
    if let Event::FsProtectDenial { target_ino, .. } = &mut sig {
        *target_ino = 4_000;
    }
    assert!(d.matches(&sig, &fresh).is_none(), "another process");
    let mut sig = refusal(&at("task_kill"));
    if let Event::FsProtectDenial { target_dev, .. } = &mut sig {
        *target_dev = libc::SIGTERM as u64;
    }
    assert!(d.matches(&sig, &fresh).is_none(), "another signal");
    // a create refused in another directory
    let mut c = refusal(&at("inode_create"));
    if let Event::FsProtectDenial { target_ino, .. } = &mut c {
        *target_ino += 1;
    }
    assert!(d.matches(&c, &fresh).is_none());
    // the two writes, the four xattrs: each its own file
    for (a, b) in [
        ("file_open", "file_permission"),
        ("inode_setxattr", "inode_removexattr"),
        ("inode_set_acl", "inode_remove_acl"),
        ("inode_setxattr", "inode_set_acl"),
    ] {
        let (x, y) = (at(a), at(b));
        assert_eq!(x.op, y.op);
        assert_ne!(x.ino, y.ino, "{a} / {b}");
    }
    // the BPF objects: a map handle is not a program handle, a load of
    // another type is no hook's
    let mut m = refusal(&at("bpf_map"));
    if let Event::FsProtectDenial { target_dev, .. } = &mut m {
        *target_dev = 2;
    }
    assert_eq!(
        d.records[d.matches(&m, &fresh).unwrap()].slot,
        slot_of("bpf_prog").unwrap()
    );
    let mut l = refusal(&at("bpf"));
    if let Event::FsProtectDenial { target_ino, .. } = &mut l {
        *target_ino = 1; // a socket filter
    }
    assert!(d.matches(&l, &fresh).is_none());
    // the paths of the child's other rows
    assert!(d.paths.iter().any(|p| p == "/run/northnarrow/selftest/"));
    assert!(d.paths.iter().any(|p| p == &format!("/proc/{TARGET}/")));
    // only the attempted hooks are expected
    let some = DenyExpect::new(&[slot_of("task_kill").unwrap()], &keys(), TARGET, None);
    assert_eq!(some.records.len(), 1);
}

/// Lot 302: the plan — the BPF guard's handle refusals only where it
/// enforces, an optional hook only where its program is loaded, the
/// target's hooks only with a target, the files' only when protected.
#[test]
fn a_hook_that_cannot_be_attempted_here_is_not_exercised() {
    let links: Vec<Option<Result<(), String>>> = HOOKS
        .iter()
        .map(|h| (h.hook != "inode_set_acl").then_some(Ok(())))
        .collect();
    let p = plan_hooks(Some(&links), true, true, true);
    for (i, h) in HOOKS.iter().enumerate() {
        let attempt = matches!(h.check, Check::Attempt { .. });
        assert_eq!(
            p[i].is_ok(),
            attempt && h.hook != "inode_set_acl",
            "{}: {:?}",
            h.hook,
            p[i]
        );
    }
    assert!(p[slot_of("inode_set_acl").unwrap()]
        .as_ref()
        .unwrap_err()
        .contains("not on this kernel"));
    let observe = plan_hooks(Some(&links), false, true, true);
    for h in ["bpf_map", "bpf_prog"] {
        assert!(observe[slot_of(h).unwrap()]
            .as_ref()
            .unwrap_err()
            .contains("observes"));
    }
    assert!(
        observe[slot_of("bpf").unwrap()].is_ok(),
        "type loads: every mode"
    );
    let no_target = plan_hooks(Some(&links), true, false, true);
    for h in ["task_kill", "task_setnice", "file_send_sigiotask"] {
        assert!(no_target[slot_of(h).unwrap()].is_err(), "{h}");
    }
    assert!(no_target[slot_of("inode_create").unwrap()].is_ok());
    let no_keys = plan_hooks(Some(&links), true, true, false);
    for h in ["inode_create", "file_open", "inode_setattr"] {
        assert!(no_keys[slot_of(h).unwrap()].is_err(), "{h}");
    }
    assert!(no_keys[slot_of("task_kill").unwrap()].is_ok());
}

/// Lot 302 (named): a deny that does not deny, or does not report, is a
/// miss — the child's word and the refusal's arrival; a skipped attempt,
/// a window, a hook not planned say nothing; an attach check is its
/// programs' links.
#[test]
fn a_deny_that_does_not_deny_or_does_not_report_is_missed() {
    let planned: Vec<Result<(), String>> = HOOKS.iter().map(|_| Ok(())).collect();
    let all = [true; HOOK_COUNT];
    let i = slot_of("inode_mknod").unwrap();
    let words = |w: &str| ChildReport::parse(&format!("deny.inode_mknod={w}\n"));
    let o = outcomes(&planned, &words("refused"), &all, None, false);
    assert_eq!(o[i], Outcome::Seen);
    let o = outcomes(&planned, &words("done"), &all, None, false);
    assert!(
        matches!(&o[i], Outcome::Missed(w) if w.contains("did not deny")),
        "{:?}",
        o[i]
    );
    let mut not_seen = all;
    not_seen[i] = false;
    let o = outcomes(&planned, &words("refused"), &not_seen, None, false);
    assert!(matches!(&o[i], Outcome::Missed(w) if w.contains("did not reach the pipeline")));
    let o = outcomes(
        &planned,
        &words("other: errno 95 (EOPNOTSUPP)"),
        &not_seen,
        None,
        false,
    );
    assert!(matches!(&o[i], Outcome::Missed(w) if w.contains("errno 95")));
    let o = outcomes(&planned, &words("skipped: no target"), &all, None, false);
    assert!(matches!(&o[i], Outcome::NotExercised(_)));
    let o = outcomes(&planned, &words("refused"), &all, None, true);
    assert!(matches!(&o[i], Outcome::NotExercised(w) if w.contains("window")));
    let o = outcomes(&planned, &ChildReport::default(), &all, None, false);
    assert!(matches!(&o[i], Outcome::NotExercised(w) if w.contains("did not report")));
    let mut p = planned.clone();
    p[i] = Err("not here".into());
    let o = outcomes(&p, &words("refused"), &all, None, false);
    assert_eq!(o[i], Outcome::NotExercised("not here".into()));
    // the owner's signal: refused silently, its record the proof
    let s = slot_of("file_send_sigiotask").unwrap();
    let sent = ChildReport::parse("deny.file_send_sigiotask=sent\n");
    assert_eq!(
        outcomes(&planned, &sent, &all, None, false)[s],
        Outcome::Seen
    );
    let mut none = all;
    none[s] = false;
    assert!(matches!(
        &outcomes(&planned, &sent, &none, None, false)[s],
        Outcome::Missed(w) if w.contains("no refusal recorded")
    ));
    // an attach check: linked, detached, not loaded, list unreadable
    let c = slot_of(SYSCTL_JUDGE).unwrap();
    let mut links: Vec<Option<Result<(), String>>> = HOOKS.iter().map(|_| Some(Ok(()))).collect();
    assert_eq!(
        outcomes(&planned, &sent, &all, Some(&links), false)[c],
        Outcome::Seen
    );
    links[c] = Some(Err("detached".into()));
    assert_eq!(
        outcomes(&planned, &sent, &all, Some(&links), true)[c],
        Outcome::Missed("detached".into()),
        "in a window too"
    );
    links[c] = None;
    assert!(matches!(
        &outcomes(&planned, &sent, &all, Some(&links), false)[c],
        Outcome::NotExercised(w) if w.contains("not loaded")
    ));
    assert!(matches!(
        &outcomes(&planned, &sent, &all, None, false)[c],
        Outcome::NotExercised(w) if w.contains("bpf-own-ids")
    ));
}

/// Lot 302: a program's link state from the program-id list and the live
/// links — loaded and linked, loaded and detached, not loaded.
#[test]
fn a_hook_s_programs_are_linked_or_detached() {
    let own = "1 task_kill\n2 cgroup_move_stash\n3 nn_sysctl_guard kept\n";
    let live: HashSet<u32> = [1, 3].into_iter().collect();
    assert_eq!(link_state(&["task_kill"], own, &live), Some(Ok(())));
    assert_eq!(link_state(&["nn_sysctl_guard"], own, &live), Some(Ok(())));
    assert!(matches!(
        link_state(&["cgroup_move_stash"], own, &live),
        Some(Err(w)) if w.contains("id 2") && w.contains("detached")
    ));
    assert_eq!(link_state(&["protected_set_acl_deny"], own, &live), None);
    // the exact program, not a prefix
    assert_eq!(link_state(&["task_kil"], own, &live), None);
}

/// Lot 302 (named, the second test: a hook detached on purpose gives the
/// degradation and then the ALERT): the first missed round signs the
/// degradation (the hook and the step named), the second the alert, the
/// third the journal only; refused again, the return is signed and the
/// degradation withdrawn.
#[test]
fn a_hook_detached_gives_the_degradation_then_the_alert() {
    let _g = crate::boot::degradation::TEST_LOCK.lock();
    crate::boot::degradation::reset_for_tests();
    let dir = tempfile::tempdir().unwrap();
    let key =
        crate::audit::AgentSigningKey::load_or_bootstrap(&dir.path().join("agent.sig")).unwrap();
    let log = Arc::new(Mutex::new(
        AuditLog::open(&dir.path().join("audit.log"), key, [7u8; 16]).unwrap(),
    ));
    let rows = || -> Vec<serde_json::Value> {
        std::fs::read_to_string(dir.path().join("audit.log"))
            .unwrap_or_default()
            .lines()
            .filter_map(|l| serde_json::from_str(l).ok())
            .collect()
    };
    let i = slot_of("inode_mknod").unwrap();
    let mut st = State::default();
    let round = |st: &mut State, ok: bool| {
        let o: Vec<Outcome> = (0..HOOK_COUNT)
            .map(|k| {
                if k == i && !ok {
                    Outcome::Missed("not refused: the operation went through".into())
                } else {
                    Outcome::Seen
                }
            })
            .collect();
        let notes = st.apply(&o);
        sign(&notes, "n", &st.open_details(), Some(&log));
        notes
    };
    let n = round(&mut st, false);
    assert!(
        matches!(&n[..], [Note::Degraded { slot, detail }] if *slot == i && detail.contains("deny hook inode_mknod") && detail.contains("a FIFO made in it")),
        "{n:?}"
    );
    assert_eq!(st.word[i], Some(ProbeState::Missed));
    let degraded: Vec<serde_json::Value> = rows()
        .into_iter()
        .filter(|r| r["extra"]["kind"] == "subsystem_degraded")
        .collect();
    assert_eq!(degraded.len(), 1);
    assert_eq!(degraded[0]["extra"]["source"], DEGRADATION_SOURCE);
    assert!(crate::boot::degradation::snapshot()
        .iter()
        .any(|l| l.starts_with("deny_selftest: deny hook inode_mknod")));
    let n = round(&mut st, false);
    assert!(
        matches!(&n[..], [Note::Alert { slot, .. }] if *slot == i),
        "{n:?}"
    );
    assert_eq!(st.word[i], Some(ProbeState::Gap));
    let alerts: Vec<serde_json::Value> = rows()
        .into_iter()
        .filter(|r| r["op"] == AUDIT_OP_ALERT)
        .collect();
    assert_eq!(alerts.len(), 1);
    assert_eq!(alerts[0]["extra"]["hook"], "inode_mknod");
    assert_eq!(alerts[0]["extra"]["rounds_missed"], 2);
    let before = rows().len();
    let n = round(&mut st, false);
    assert!(
        matches!(&n[..], [Note::StillMissed { rounds: 3, .. }]),
        "{n:?}"
    );
    assert_eq!(rows().len(), before, "the journal only");
    let n = round(&mut st, true);
    assert!(
        matches!(&n[..], [Note::Restored { rounds: 3, .. }]),
        "{n:?}"
    );
    assert!(rows()
        .iter()
        .any(|r| r["op"] == AUDIT_OP_RESTORED && r["extra"]["hook"] == "inode_mknod"));
    assert!(!crate::boot::degradation::snapshot()
        .iter()
        .any(|l| l.starts_with("deny_selftest")));
    // not exercised after a miss keeps it open, once in the journal
    let mut st = State::default();
    let mut o: Vec<Outcome> = (0..HOOK_COUNT).map(|_| Outcome::Seen).collect();
    o[i] = Outcome::Missed("x".into());
    st.apply(&o);
    o[i] = Outcome::NotExercised("y".into());
    assert_eq!(st.apply(&o).len(), 1);
    assert!(st.apply(&o).is_empty());
    assert_eq!(st.word[i], Some(ProbeState::Missed));
    assert_eq!(st.open_details().len(), 1);
    crate::boot::degradation::reset_for_tests();
}

/// Lot 302: the plan's text, both ways.
#[test]
fn the_plan_goes_to_the_child_as_text() {
    let p = Plan {
        target: TARGET,
        dir: PathBuf::from(TARGET_DIR),
        hooks: attempts(),
        write_fd: true,
        move_procs: Some(PathBuf::from(
            "/sys/fs/cgroup/northnarrow-deny-selftest/cgroup.procs",
        )),
        bpffs: Some((PathBuf::from("/sys/fs/bpf"), "northnarrow".to_string())),
    };
    assert_eq!(Plan::parse(&p.render()), p);
    assert_eq!(
        Plan::parse("hooks=1,99,x,2\n").hooks,
        [1, 2],
        "a slot out of range dropped"
    );
    assert_eq!(Plan::parse(""), Plan::default());
}

/// Lot 302: the ACL the set step writes is the file's mode, in the
/// kernel's xattr form (version 2, owner, group, others).
#[test]
fn the_acl_attempt_writes_the_file_s_own_mode() {
    let a = minimal_acl(0o640);
    assert_eq!(a.len(), 4 + 3 * 8);
    assert_eq!(&a[..4], &2u32.to_le_bytes());
    assert_eq!(&a[4..8], &[0x01, 0, 6, 0]);
    assert_eq!(&a[12..16], &[0x04, 0, 4, 0]);
    assert_eq!(&a[20..24], &[0x20, 0, 0, 0]);
    assert_eq!(&a[8..12], &u32::MAX.to_le_bytes());
}

/// Lot 302: the targets are made (and, with a pin root, registered),
/// found intact, and found changed when an attempt went through.
#[test]
fn the_targets_are_made_and_a_change_is_found() {
    let t = tempfile::tempdir().unwrap();
    let dir = t.path().join("selftest");
    let keys = prepare_targets(&dir, None).unwrap();
    assert_eq!(keys.files.len(), file::PROTECTED.len());
    assert!(targets_intact(&dir, &keys));
    std::fs::write(dir.join("c.x"), b"").unwrap();
    assert!(!targets_intact(&dir, &keys), "a create let through");
    let keys = prepare_targets(&dir, None).unwrap();
    assert!(targets_intact(&dir, &keys), "made again");
    std::fs::remove_dir(dir.join(file::RMDIR)).unwrap();
    assert!(!targets_intact(&dir, &keys), "an rmdir let through");
    let keys = prepare_targets(&dir, None).unwrap();
    std::fs::rename(dir.join(file::RENAME), dir.join("rename.x")).unwrap();
    assert!(!targets_intact(&dir, &keys), "a rename let through");
}

/// Lot 302 (named): with no hook to refuse them — a test process on its own
/// targets — every attempt goes through (`done`; the owner's signal
/// `sent`): the shape a detached hook gives the round, a miss each. The
/// steps' system calls are the ones each hook judges.
#[test]
fn with_no_hook_every_attempt_goes_through() {
    let t = tempfile::tempdir().unwrap();
    let dir = t.path().join("selftest");
    prepare_targets(&dir, None).unwrap();
    // the target: a child of this test, its own uid
    let mut target = std::process::Command::new("sleep")
        .arg("30")
        .spawn()
        .unwrap();
    let plan = Plan {
        target: target.id(),
        dir: dir.clone(),
        hooks: attempts(),
        write_fd: false,
        move_procs: None,
        bpffs: None,
    };
    let text = run_steps("n0nce", &plan);
    let _ = target.kill();
    let _ = target.wait();
    let r = ChildReport::parse(&text);
    for h in [
        "task_kill",
        "ptrace_access_check",
        "inode_unlink",
        "inode_rmdir",
        "inode_rename",
        "inode_setattr",
        "file_open",
        "inode_create",
        "inode_mkdir",
        "inode_mknod",
        "inode_symlink",
        "inode_link",
        "task_setrlimit",
        "task_setscheduler",
        "task_setnice",
    ] {
        assert_eq!(r.get(&format!("deny.{h}")), Some("done"), "{h}: {text}");
    }
    assert_eq!(r.get("deny.file_send_sigiotask"), Some("sent"), "{text}");
    // made: each attempt's own trace in the directory
    for (name, h) in [
        ("c.n0nce", "create"),
        ("d.n0nce", "mkdir"),
        ("p.n0nce", "mknod"),
        ("s.n0nce", "symlink"),
        ("l.n0nce", "link"),
        ("rename.n0nce", "rename"),
    ] {
        assert!(dir.join(name).symlink_metadata().is_ok(), "{h}");
    }
    assert!(!dir.join(file::UNLINK).exists());
    assert!(!dir.join(file::RMDIR).exists());
    // the steps that need what the plan did not give: skipped, never done
    for h in ["file_permission", "bpf_map", "bpf_prog", "inode_permission"] {
        assert!(
            r.get(&format!("deny.{h}"))
                .is_some_and(|w| w.starts_with("skipped")),
            "{h}: {text}"
        );
    }
    // no target: the task steps skipped
    let none = run_steps(
        "n0nce",
        &Plan {
            target: 0,
            hooks: vec![slot_of("task_kill").unwrap()],
            ..plan
        },
    );
    assert!(none.starts_with("deny.task_kill=skipped"), "{none}");
}

/// Lot 302: the target process is a worker in `PROTECTED_PIDS` —
/// protected (the hooks refuse what is tried on it), never exempt (it may
/// not signal the agent, nor pass a deny hook itself).
#[test]
fn the_target_is_protected_never_exempt() {
    assert_eq!(TARGET_ROLE, antitamper_bpf::pid_role::WORKER);
    assert!(common::wire::pid_role::is_protected(TARGET_ROLE));
    assert!(!common::wire::pid_role::is_exempt(TARGET_ROLE));
}
