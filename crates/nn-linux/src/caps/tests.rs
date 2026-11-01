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
