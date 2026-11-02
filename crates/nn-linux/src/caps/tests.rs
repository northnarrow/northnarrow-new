use super::*;

#[test]
fn a_set_names_its_capabilities() {
    let s = CapSet::of(&[cap::KILL, cap::BPF, cap::DAC_OVERRIDE]);
    assert_eq!(s.to_string(), "DAC_OVERRIDE KILL BPF");
    assert_eq!(CapSet::EMPTY.to_string(), "none");
    assert!(s.contains(cap::KILL) && !s.contains(cap::SETUID));
    assert!(!s.contains(64), "past the bits");
    assert_eq!(
        s.minus(CapSet::of(&[cap::KILL])),
        CapSet::of(&[cap::BPF, cap::DAC_OVERRIDE])
    );
    assert_eq!(
        s.intersection(CapSet::of(&[cap::KILL, cap::SETUID])),
        CapSet::of(&[cap::KILL])
    );
    assert_eq!(
        CapSet::of(&[cap::KILL]).union(CapSet::of(&[cap::BPF])),
        CapSet::of(&[cap::KILL, cap::BPF])
    );
    assert_eq!(CapSet::from_bits(1 << 45).names(), ["45"]);
    assert_eq!(NAMES[usize::from(cap::SYS_PTRACE)], "SYS_PTRACE");
    assert_eq!(NAMES[usize::from(cap::SETFCAP)], "SETFCAP");
    assert_eq!(NAMES[usize::from(cap::PERFMON)], "PERFMON");
    assert_eq!(NAMES[usize::from(cap::BPF)], "BPF");
}

/// The plan's sets (§3.1), with the additions the role's documentation
/// gives the reason for; only the decision gives up the rest for good.
#[test]
fn each_role_keeps_its_set() {
    use cap::*;
    let names = |r: Role| r.wants().to_string();
    assert_eq!(names(Role::Decision), "SYS_PTRACE");
    assert_eq!(
        names(Role::Actuator),
        "DAC_OVERRIDE KILL NET_ADMIN SYS_PTRACE SETFCAP"
    );
    assert_eq!(names(Role::Writer), "LINUX_IMMUTABLE");
    assert_eq!(names(Role::Supervisor), "KILL SETGID SETUID BPF");
    assert_eq!(names(Role::Loader), "SYS_ADMIN PERFMON BPF");
    assert_eq!(names(Role::Errands), "BPF");
    for r in Role::ALL {
        assert_eq!(r.for_good(), r == Role::Decision, "{r}");
        assert!(!r.wants().contains(LINUX_IMMUTABLE) || r == Role::Writer);
    }
    // the decision acts on nothing: no signal, no rule, no file, no key
    for c in [
        KILL,
        NET_ADMIN,
        SETFCAP,
        DAC_OVERRIDE,
        LINUX_IMMUTABLE,
        BPF,
        PERFMON,
        SETUID,
        SETGID,
        SYS_ADMIN,
    ] {
        assert!(
            !Role::Decision.wants().contains(c),
            "{}",
            NAMES[usize::from(c)]
        );
    }
}

#[test]
fn the_sets_read_back_as_set() {
    let now = this_thread().unwrap();
    assert!(now.effective.minus(now.permitted).is_empty());
    set_this_thread(now).unwrap();
    assert_eq!(this_thread().unwrap(), now);
}

#[test]
fn a_set_larger_than_held_is_refused() {
    std::thread::spawn(|| {
        let now = this_thread().unwrap();
        let more = ThreadCaps {
            effective: now.permitted.union(CapSet::from_bits(1 << 40)),
            ..now
        };
        // CAP_CHECKPOINT_RESTORE (40) never held by a test, effective
        // outside permitted: EPERM
        assert!(set_this_thread(more).is_err());
        assert_eq!(this_thread().unwrap(), now);
    })
    .join()
    .unwrap();
}

/// The decision's filter, on its thread only: no exec, no bpf, no capset,
/// no reach into another process; the rest of the process unaffected.
#[test]
fn the_decision_thread_cannot_exec_load_or_change_its_sets() {
    let other = std::thread::spawn(|| {
        let e = enter(Role::Decision).unwrap();
        assert_eq!(e.filter, Some(Ok(())), "{}", e.line());
        assert!(e.complete(), "{}", e.line());
        assert!(e.after.permitted.minus(Role::Decision.wants()).is_empty());
        assert!(e.after.inheritable.is_empty());
        // exec: the child forked from this thread inherits the filter
        let spawn = std::process::Command::new("/bin/true").spawn();
        assert_eq!(
            spawn.map(|_| ()).map_err(|e| e.raw_os_error()),
            Err(Some(libc::EPERM)),
            "execve refused"
        );
        // SAFETY: raw syscalls with harmless arguments, refused by the filter.
        let errno = |rc: libc::c_long| {
            assert_eq!(rc, -1);
            io::Error::last_os_error().raw_os_error()
        };
        // bpf(BPF_MAP_CREATE, NULL, 0)
        assert_eq!(
            errno(unsafe { libc::syscall(libc::SYS_bpf, 0, 0, 0) }),
            Some(libc::EPERM)
        );
        // capset, even to the sets it holds
        let now = this_thread().unwrap();
        assert_eq!(
            set_this_thread(now).map_err(|e| e.raw_os_error()),
            Err(Some(libc::EPERM))
        );
        // ptrace(PTRACE_TRACEME)
        assert_eq!(
            errno(unsafe { libc::syscall(libc::SYS_ptrace, 0, 0, 0, 0) }),
            Some(libc::EPERM)
        );
        // process_vm_readv of ourselves
        assert_eq!(
            errno(unsafe {
                libc::syscall(libc::SYS_process_vm_readv, libc::getpid(), 0, 0, 0, 0, 0)
            }),
            Some(libc::EPERM)
        );
        // pidfd_getfd
        assert_eq!(
            errno(unsafe { libc::syscall(libc::SYS_pidfd_getfd, -1, 0, 0) }),
            Some(libc::EPERM)
        );
        // what it does keep: reading, its own pid, a read of /proc
        assert!(std::fs::read_to_string("/proc/self/status").is_ok());
        // a thread it starts inherits all of it
        std::thread::spawn(|| {
            assert!(std::process::Command::new("/bin/true").spawn().is_err());
        })
        .join()
        .unwrap();
    });
    other.join().unwrap();
    // this thread: not filtered
    let st = std::process::Command::new("/bin/true").status().unwrap();
    assert!(st.success());
}

/// Review of #482 (R14c-1; the reviewer's temporary test, kept): the
/// decision thread opens no file for writing — not another process's
/// `/proc/<pid>/mem` (what its `SYS_PTRACE` would open as uid 0), not a
/// file it owns — and signals no other process; it still reads, and still
/// signals itself (an abort). The rest of the process is unaffected.
#[test]
fn the_decision_thread_writes_no_file_and_signals_no_other_process() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("owned");
    std::fs::write(&file, b"x").unwrap();
    // a process of ours to aim at (a descendant: Yama's scope 1 lets this
    // process open its memory without the filter)
    let mut child = std::process::Command::new("sleep")
        .arg("30")
        .spawn()
        .unwrap();
    let kid = child.id() as i32;
    let f2 = file.clone();
    std::thread::spawn(move || {
        let e = enter(Role::Decision).unwrap();
        assert_eq!(e.filter, Some(Ok(())), "{}", e.line());
        let refused = |r: std::io::Result<std::fs::File>, what: &str| {
            assert_eq!(
                r.map(|_| ()).map_err(|e| e.raw_os_error()),
                Err(Some(libc::EPERM)),
                "{what}"
            );
        };
        let open = |p: &std::path::Path, w: bool, c: bool, t: bool| {
            std::fs::OpenOptions::new()
                .read(!w)
                .write(w)
                .create(c)
                .truncate(t)
                .open(p)
        };
        refused(
            std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open(format!("/proc/{kid}/mem")),
            "another process's memory, read-write",
        );
        refused(open(&f2, true, false, false), "a file it owns, write");
        refused(open(&f2, true, false, true), "truncate");
        refused(
            open(&f2.with_file_name("new"), true, true, false),
            "a new file",
        );
        // SAFETY: raw syscalls with local, valid arguments.
        let rc = |r: libc::c_long| {
            if r < 0 {
                io::Error::last_os_error().raw_os_error()
            } else {
                None
            }
        };
        let path = std::ffi::CString::new(f2.to_str().unwrap()).unwrap();
        #[cfg(target_arch = "x86_64")]
        assert_eq!(
            rc(unsafe { libc::syscall(libc::SYS_creat, path.as_ptr(), 0o600) }),
            Some(libc::EPERM),
            "creat"
        );
        let how = [0u64; 3]; // open_how: O_RDONLY, no mode, no resolve
        assert_eq!(
            rc(unsafe {
                libc::syscall(
                    libc::SYS_openat2,
                    libc::AT_FDCWD,
                    path.as_ptr(),
                    how.as_ptr(),
                    24usize,
                )
            }),
            Some(libc::EPERM),
            "openat2, whatever it asks"
        );
        // what it keeps: reading
        assert!(open(&f2, false, false, false).is_ok());
        assert!(std::fs::read_to_string("/proc/self/status").is_ok());
        assert!(std::fs::read_link(format!("/proc/{kid}/exe")).is_ok());
        // signals: none to another process or a group, its own allowed
        let me = std::process::id() as i32;
        // SAFETY: gettid has no preconditions.
        let tid = unsafe { libc::syscall(libc::SYS_gettid) } as i32;
        // SAFETY (below): signal 0 checks only; nothing is delivered.
        assert_eq!(
            rc(unsafe { libc::kill(kid, 0) } as libc::c_long),
            Some(libc::EPERM)
        );
        assert_eq!(
            rc(unsafe { libc::kill(0, 0) } as libc::c_long),
            Some(libc::EPERM)
        );
        assert_eq!(
            rc(unsafe { libc::kill(-1, 0) } as libc::c_long),
            Some(libc::EPERM)
        );
        assert_eq!(
            rc(unsafe { libc::syscall(libc::SYS_tgkill, kid, kid, 0) }),
            Some(libc::EPERM)
        );
        assert_eq!(
            rc(unsafe { libc::syscall(libc::SYS_tkill, tid, 0) }),
            Some(libc::EPERM)
        );
        assert_eq!(
            rc(unsafe { libc::syscall(libc::SYS_pidfd_send_signal, 0, 0, 0usize, 0) }),
            Some(libc::EPERM)
        );
        let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
        info.si_code = -1; // SI_QUEUE
        assert_eq!(
            rc(unsafe {
                libc::syscall(
                    libc::SYS_rt_sigqueueinfo,
                    kid,
                    0,
                    &mut info as *mut libc::siginfo_t,
                )
            }),
            Some(libc::EPERM)
        );
        assert_eq!(
            rc(unsafe {
                libc::syscall(
                    libc::SYS_rt_tgsigqueueinfo,
                    kid,
                    kid,
                    0,
                    &mut info as *mut libc::siginfo_t,
                )
            }),
            Some(libc::EPERM)
        );
        assert_eq!(rc(unsafe { libc::kill(me, 0) } as libc::c_long), None);
        assert_eq!(
            rc(unsafe { libc::syscall(libc::SYS_tgkill, me, tid, 0) }),
            None
        );
    })
    .join()
    .unwrap();
    // this thread: not filtered
    std::fs::write(&file, b"y").unwrap();
    // SAFETY: signal 0 to our own child.
    assert_eq!(unsafe { libc::kill(kid, 0) }, 0);
    let _ = child.kill();
    let _ = child.wait();
}

#[test]
fn the_filter_lists_every_refused_call_with_its_x32_twin() {
    let names: Vec<&str> = filter::refused().iter().map(|r| r.1).collect();
    for n in [
        "capset",
        "execve",
        "execveat",
        "bpf",
        "ptrace",
        "process_vm_readv",
        "process_vm_writev",
        "pidfd_getfd",
    ] {
        assert!(names.contains(&n), "{n}");
        #[cfg(target_arch = "x86_64")]
        assert!(names.contains(&format!("{n} (x32)").as_str()), "{n} (x32)");
    }
    // x32's own numbers for the calls the x32 table renumbers
    #[cfg(target_arch = "x86_64")]
    {
        let nr = |n: &str| filter::refused().iter().find(|r| r.1 == n).unwrap().0;
        assert_eq!(nr("execve (x32)"), 0x4000_0000 | 520);
        assert_eq!(nr("execveat (x32)"), 0x4000_0000 | 545);
        assert_eq!(nr("ptrace (x32)"), 0x4000_0000 | 521);
        assert_eq!(nr("process_vm_readv (x32)"), 0x4000_0000 | 539);
        assert_eq!(nr("process_vm_writev (x32)"), 0x4000_0000 | 540);
        // the review of #482's RC5: the common numbers' twins too
        assert_eq!(nr("bpf (x32)"), 0x4000_0000 | 321);
        assert_eq!(nr("capset (x32)"), 0x4000_0000 | 126);
        assert_eq!(nr("pidfd_getfd (x32)"), 0x4000_0000 | 438);
        let always = |n: &str| {
            filter::refused_always()
                .iter()
                .find(|r| r.1 == n)
                .unwrap()
                .0
        };
        assert_eq!(always("creat (x32)"), 0x4000_0000 | 85);
        assert_eq!(always("openat2 (x32)"), 0x4000_0000 | 437);
        let when = |n: &str| filter::refused_when().iter().find(|r| r.1 == n).unwrap().0;
        assert_eq!(when("rt_sigqueueinfo (x32)"), 0x4000_0000 | 524);
        assert_eq!(when("rt_tgsigqueueinfo (x32)"), 0x4000_0000 | 536);
        assert_eq!(when("openat (x32)"), 0x4000_0000 | 257);
    }
    // review of #482 (R14c-1): the writing opens and the signals
    let always: Vec<&str> = filter::refused_always().iter().map(|r| r.1).collect();
    for n in ["openat2", "tkill", "pidfd_send_signal"] {
        assert!(always.contains(&n), "{n}");
    }
    let when: Vec<&str> = filter::refused_when().iter().map(|r| r.1).collect();
    for n in [
        "openat",
        "kill",
        "tgkill",
        "rt_sigqueueinfo",
        "rt_tgsigqueueinfo",
    ] {
        assert!(when.contains(&n), "{n}");
    }
    assert!(filter::program().is_ok());
}

/// Run `body` in a forked child that is single-threaded, in a user
/// namespace of its own (where it holds every capability): the sets are
/// then exactly the roles'. `None` when the host refuses the namespace.
fn in_userns(body: fn() -> i32) -> Option<i32> {
    // SAFETY: fork; the child unshares and runs body, then _exit.
    let pid = unsafe { libc::fork() };
    assert!(pid >= 0, "fork");
    if pid == 0 {
        // SAFETY: unshare in the single-threaded child.
        if unsafe { libc::unshare(libc::CLONE_NEWUSER) } != 0 {
            // SAFETY: _exit in the child.
            unsafe { libc::_exit(99) };
        }
        let rc = body();
        // SAFETY: _exit in the child.
        unsafe { libc::_exit(rc) };
    }
    let mut status = 0;
    // SAFETY: waiting for our own child.
    unsafe { libc::waitpid(pid, &mut status, 0) };
    assert!(libc::WIFEXITED(status), "child status {status:#x}");
    match libc::WEXITSTATUS(status) {
        99 => None,
        rc => Some(rc),
    }
}

/// Every capability the kernel knows (the namespace's owner holds them all).
fn full() -> CapSet {
    this_thread().map(|t| t.permitted).unwrap_or_default()
}

#[test]
fn a_role_s_effective_set_is_exactly_its_own_and_the_core_s_comes_back() {
    let rc = in_userns(|| {
        let all = full();
        if !all.contains(cap::BPF) || !all.contains(cap::SYS_ADMIN) {
            return 98; // a namespace without every capability: nothing to measure
        }
        // an inheritable set left by whoever started the thread (the
        // namespace's owner holds CAP_SETPCAP): a role leaves none
        let held = this_thread().unwrap();
        if set_this_thread(ThreadCaps {
            inheritable: CapSet::of(&[cap::KILL, cap::BPF]),
            ..held
        })
        .is_err()
            || this_thread().map(|t| t.inheritable).ok() != Some(CapSet::of(&[cap::KILL, cap::BPF]))
        {
            return 14;
        }
        // the actuator: its set effective, the rest permitted
        let e = match enter(Role::Actuator) {
            Ok(e) => e,
            Err(_) => return 1,
        };
        if !e.complete() || e.after.effective != Role::Actuator.wants() || e.after.permitted != all
        {
            return 2;
        }
        if !e.missing.is_empty() || e.filter.is_some() || !e.after.inheritable.is_empty() {
            return 3;
        }
        // a thread it starts has its set; the core's back with restore_core
        let t = std::thread::spawn(move || {
            let inherited = this_thread().unwrap().effective == Role::Actuator.wants();
            restore_core();
            inherited && this_thread().unwrap().effective == all
        });
        if !t.join().unwrap_or(false) {
            return 4;
        }
        restore_core();
        if this_thread().ok().map(|t| t.effective) != Some(all) {
            return 5;
        }
        // the loader, lowered for a phase and back
        {
            let _g = match lower(Role::Loader) {
                Ok(g) => g,
                Err(_) => return 6,
            };
            if this_thread().ok().map(|t| (t.effective, t.permitted))
                != Some((Role::Loader.wants(), all))
            {
                return 7;
            }
        }
        if this_thread().ok().map(|t| t.effective) != Some(all) {
            return 8;
        }
        // the writer and the supervisor
        for r in [Role::Writer, Role::Supervisor, Role::Errands] {
            match enter(r) {
                Ok(e) if e.complete() && e.after.effective == r.wants() => {}
                _ => return 9,
            }
            restore_core();
        }
        // the decision: its set, for good
        let e = match enter(Role::Decision) {
            Ok(e) => e,
            Err(_) => return 10,
        };
        if e.after.effective != Role::Decision.wants()
            || e.after.permitted != Role::Decision.wants()
        {
            return 11;
        }
        if e.filter != Some(Ok(())) || !e.complete() {
            return 12;
        }
        // restore_core cannot give back what was given up (and capset is
        // refused by the filter)
        restore_core();
        if this_thread().ok().map(|t| t.effective) != Some(Role::Decision.wants()) {
            return 13;
        }
        0
    });
    match rc {
        None | Some(98) => eprintln!("no user namespace with every capability here: skipped"),
        Some(rc) => assert_eq!(rc, 0, "check {rc} failed"),
    }
}

#[test]
fn an_incomplete_role_is_said() {
    let full = ThreadCaps {
        effective: CapSet::from_bits(u64::MAX >> 23),
        permitted: CapSet::from_bits(u64::MAX >> 23),
        inheritable: CapSet::EMPTY,
    };
    let mut e = Entered {
        role: Role::Actuator,
        before: full,
        after: ThreadCaps {
            effective: Role::Actuator.wants(),
            ..full
        },
        missing: CapSet::EMPTY,
        filter: None,
    };
    assert!(e.complete(), "{}", e.line());
    assert_eq!(
        e.line(),
        "role actuator: effective DAC_OVERRIDE KILL NET_ADMIN SYS_PTRACE SETFCAP, permitted \
         CHOWN DAC_OVERRIDE DAC_READ_SEARCH FOWNER FSETID KILL SETGID SETUID SETPCAP \
         LINUX_IMMUTABLE NET_BIND_SERVICE NET_BROADCAST NET_ADMIN NET_RAW IPC_LOCK IPC_OWNER \
         SYS_MODULE SYS_RAWIO SYS_CHROOT SYS_PTRACE SYS_PACCT SYS_ADMIN SYS_BOOT SYS_NICE \
         SYS_RESOURCE SYS_TIME SYS_TTY_CONFIG MKNOD LEASE AUDIT_WRITE AUDIT_CONTROL SETFCAP \
         MAC_OVERRIDE MAC_ADMIN SYSLOG WAKE_ALARM BLOCK_SUSPEND AUDIT_READ PERFMON BPF \
         CHECKPOINT_RESTORE"
    );
    // more than its set effective
    e.after.effective = e.after.effective.union(CapSet::of(&[cap::BPF]));
    assert!(!e.complete());
    // an inheritable set left
    e.after.effective = Role::Actuator.wants();
    e.after.inheritable = CapSet::of(&[cap::KILL]);
    assert!(!e.complete());
    // the decision: more permitted than its set, or no filter
    let mut d = Entered {
        role: Role::Decision,
        before: full,
        after: ThreadCaps {
            effective: Role::Decision.wants(),
            permitted: Role::Decision.wants(),
            inheritable: CapSet::EMPTY,
        },
        missing: CapSet::of(&[cap::SYS_PTRACE]),
        filter: Some(Ok(())),
    };
    assert!(d.complete());
    assert!(
        d.line()
            .ends_with("(not held: SYS_PTRACE), seccomp filter on"),
        "{}",
        d.line()
    );
    d.after.permitted = full.permitted;
    assert!(!d.complete());
    d.after.permitted = Role::Decision.wants();
    d.filter = Some(Err("EINVAL".into()));
    assert!(!d.complete());
    assert!(
        d.line().ends_with("seccomp filter NOT installed: EINVAL"),
        "{}",
        d.line()
    );
}

/// Review of #482 (RC3): a role entered incomplete, or not at all, is a
/// signed degradation (`thread_caps`) — the registry holds it.
#[test]
fn an_incomplete_or_failed_role_is_a_signed_degradation() {
    let full = CapSet::from_bits(u64::MAX >> 23);
    let incomplete = Entered {
        role: Role::Writer,
        before: ThreadCaps {
            effective: full,
            permitted: full,
            inheritable: CapSet::EMPTY,
        },
        after: ThreadCaps {
            effective: full,
            permitted: full,
            inheritable: CapSet::EMPTY,
        },
        missing: CapSet::EMPTY,
        filter: None,
    };
    assert!(!incomplete.complete());
    let name = "nn-rc3-incomplete";
    assert!(report_entered(name, Role::Writer, Ok(incomplete)).is_some());
    let failed = "nn-rc3-failed";
    assert!(report_entered(
        failed,
        Role::Writer,
        Err(io::Error::other("capset refused"))
    )
    .is_none());
    let rows = crate::boot::degradation::entries();
    for who in [name, failed] {
        assert!(
            rows.iter()
                .any(|d| d.source == "thread_caps" && d.detail.contains(who)),
            "{who}: {rows:?}"
        );
    }
}

/// Review of #482 (R14c-4): `restore_core`'s judgement — the core's set
/// taken back; a thread born of one that gave its sets up, or whose sets
/// cannot be set, said (the caller signs it).
#[test]
fn restore_core_takes_the_core_s_set_back_or_says_why_not() {
    // CHOWN (0) and FOWNER (3): what the CoW guard's restore needs
    let core = CapSet::of(&[0, 3, cap::KILL, cap::SYS_PTRACE]);
    let actuator = ThreadCaps {
        effective: CapSet::of(&[cap::KILL]),
        permitted: core,
        inheritable: CapSet::EMPTY,
    };
    let mut set_to = None;
    let got = restore_core_judged(Ok(actuator), Some(core), |t| {
        set_to = Some(t);
        Ok(())
    });
    assert_eq!(got, None);
    assert_eq!(set_to.map(|t| t.effective), Some(core));
    // already the core's: nothing set
    let whole = ThreadCaps {
        effective: core,
        permitted: core,
        inheritable: CapSet::EMPTY,
    };
    assert_eq!(
        restore_core_judged(Ok(whole), Some(core), |_| panic!("set")),
        None
    );
    // born of the decision thread: permitted SYS_PTRACE only
    let decided = ThreadCaps {
        effective: CapSet::of(&[cap::SYS_PTRACE]),
        permitted: CapSet::of(&[cap::SYS_PTRACE]),
        inheritable: CapSet::EMPTY,
    };
    let why = restore_core_judged(Ok(decided), Some(core), |_| panic!("set")).unwrap();
    assert!(
        why.contains("gave its sets up") && why.contains("CHOWN"),
        "{why}"
    );
    // the set refused, the sets unreadable
    let why =
        restore_core_judged(Ok(actuator), Some(core), |_| Err(io::Error::other("EPERM"))).unwrap();
    assert!(why.contains("could not be restored"), "{why}");
    assert!(restore_core_judged(Err(io::Error::other("x")), Some(core), |_| Ok(())).is_some());
}
