//! The sandbox's pieces, each in a forked child (the test process keeps
//! its own rights). `enter` as a whole needs an unprivileged account with
//! no supplementary group: the privileged harness
//! (`agent/tests/privileged_worker_harness.rs`) runs it as
//! `northnarrow-worker`.

use super::seccomp::{program, Allowlist};
use super::*;

/// Run `body` in a forked child after `setup` (both before any allocation
/// in the child: the program is built before the fork); the wait status.
fn in_child(setup: impl Fn() -> bool, body: fn() -> i32) -> i32 {
    // SAFETY: fork; the child calls only async-signal-safe syscalls and
    // what `setup` does (installing a prepared filter, Landlock syscalls).
    let pid = unsafe { libc::fork() };
    assert!(pid >= 0, "fork");
    if pid == 0 {
        // the child holds copies of every descriptor of the test process
        // (other tests' sockets among them): let them go at once, so that
        // no test sees its peer kept open by this child
        close_from(3);
        if !setup() {
            // SAFETY: _exit in the child.
            unsafe { libc::_exit(100) };
        }
        let rc = body();
        // SAFETY: _exit in the child.
        unsafe { libc::_exit(rc) };
    }
    let mut status = 0;
    // SAFETY: waiting for our own child.
    unsafe { libc::waitpid(pid, &mut status, 0) };
    status
}

fn killed_by_sigsys(status: i32) -> bool {
    libc::WIFSIGNALED(status) && libc::WTERMSIG(status) == libc::SIGSYS
}

fn exited(status: i32, code: i32) -> bool {
    libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == code
}

/// The parse worker's filter, for a child whose pid is not known before
/// the fork (tgkill is then refused, which no body uses).
fn parse_filter(ipc_fd: RawFd) -> seccompiler::BpfProgram {
    program(&Allowlist::parse_worker(ipc_fd, u32::MAX)).expect("the parse allowlist compiles")
}

fn install_prepared(prog: &seccompiler::BpfProgram) -> bool {
    seccompiler::apply_filter(prog).is_ok()
}

#[test]
fn the_parse_allowlist_keeps_what_the_plan_lists_and_nothing_to_escape_with() {
    let names = Allowlist::parse_worker(3, 1).names();
    for kept in [
        "recvfrom",
        "sendto",
        "write",
        "close",
        "futex",
        "mmap",
        "munmap",
        "mremap",
        "brk",
        "madvise",
        "clock_gettime",
        "getrandom",
        "rt_sigreturn",
        "sigaltstack",
        "exit_group",
    ] {
        assert!(names.contains(&kept), "{kept} kept");
    }
    for never in [
        "open",
        "openat",
        "socket",
        "socketpair",
        "connect",
        "execve",
        "execveat",
        "clone",
        "clone3",
        "fork",
        "unshare",
        "kill",
        "tkill",
        "rt_sigqueueinfo",
        "pidfd_send_signal",
        "ptrace",
        "bpf",
        "prctl",
        "read",
        "setuid",
        "capset",
        "recvmsg",
        "sendmsg",
        "pkey_mprotect",
        "io_uring_setup",
        "keyctl",
        "perf_event_open",
        "userfaultfd",
    ] {
        assert!(!names.contains(&never), "{never} not kept");
    }
    // no duplicate: one rule set per call
    let mut sorted = names.clone();
    sorted.sort_unstable();
    sorted.dedup();
    assert_eq!(sorted.len(), names.len());
}

#[test]
fn allowed_calls_run_under_the_parse_filter() {
    let prog = parse_filter(3);
    let s = in_child(
        || install_prepared(&prog),
        || {
            let mut buf = [0u8; 8];
            // SAFETY: plain syscalls; their failures are allowed.
            unsafe {
                libc::syscall(libc::SYS_write, 2, b"".as_ptr(), 0);
                let m = libc::syscall(
                    libc::SYS_mmap,
                    0,
                    4096,
                    libc::PROT_READ | libc::PROT_WRITE,
                    libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                    -1,
                    0,
                );
                libc::syscall(libc::SYS_munmap, m, 4096);
                libc::syscall(libc::SYS_getrandom, buf.as_mut_ptr(), buf.len(), 0);
                // the worker's own receive and send on the channel's
                // number, with its flags and no address (EBADF here): kept
                libc::syscall(
                    libc::SYS_recvfrom,
                    3,
                    buf.as_mut_ptr(),
                    buf.len(),
                    crate::worker::transport::WORKER_RECV_FLAGS,
                    0usize,
                    0usize,
                );
                libc::syscall(
                    libc::SYS_sendto,
                    3,
                    buf.as_ptr(),
                    buf.len(),
                    crate::worker::transport::WORKER_SEND_FLAGS,
                    0usize,
                    0usize,
                );
                // a writable mapping made read-only (no PROT_EXEC): kept
                let m = libc::syscall(
                    libc::SYS_mmap,
                    0,
                    4096,
                    libc::PROT_READ | libc::PROT_WRITE,
                    libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                    -1,
                    0,
                );
                libc::syscall(libc::SYS_mprotect, m, 4096, libc::PROT_READ);
                libc::syscall(libc::SYS_munmap, m, 4096);
            }
            7
        },
    );
    assert!(exited(s, 7), "status {s:#x}");
}

#[test]
fn every_escape_kills_the_process() {
    let prog = parse_filter(3);
    type Body = fn() -> i32;
    let cases: Vec<(&str, Body)> = vec![
        ("openat", || {
            // SAFETY: plain syscall.
            unsafe {
                libc::syscall(
                    libc::SYS_openat,
                    libc::AT_FDCWD,
                    c"/etc/hostname".as_ptr(),
                    libc::O_RDONLY,
                )
            };
            0
        }),
        ("socket", || {
            // SAFETY: plain syscall.
            unsafe { libc::syscall(libc::SYS_socket, libc::AF_INET, libc::SOCK_STREAM, 0) };
            0
        }),
        ("kill", || {
            // SAFETY: plain syscall (signal 0, never delivered).
            unsafe { libc::syscall(libc::SYS_kill, 1, 0) };
            0
        }),
        ("ptrace", || {
            // SAFETY: plain syscall.
            unsafe { libc::syscall(libc::SYS_ptrace, libc::PTRACE_ATTACH, 1, 0, 0) };
            0
        }),
        ("exec memory", || {
            // SAFETY: plain syscall.
            unsafe {
                libc::syscall(
                    libc::SYS_mmap,
                    0,
                    4096,
                    libc::PROT_READ | libc::PROT_EXEC,
                    libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                    -1,
                    0,
                )
            };
            0
        }),
        ("stdout", || {
            // SAFETY: plain syscall.
            unsafe { libc::syscall(libc::SYS_write, 1, b"x".as_ptr(), 1) };
            0
        }),
        ("sendmsg elsewhere", || {
            // SAFETY: plain syscall.
            unsafe { libc::syscall(libc::SYS_sendmsg, 4, std::ptr::null::<u8>(), 0) };
            0
        }),
        ("prctl", || {
            // SAFETY: plain syscall.
            unsafe { libc::syscall(libc::SYS_prctl, libc::PR_SET_DUMPABLE, 1, 0, 0, 0) };
            0
        }),
        ("bpf", || {
            // SAFETY: plain syscall.
            unsafe { libc::syscall(libc::SYS_bpf, 0, std::ptr::null::<u8>(), 0) };
            0
        }),
        // review of #480 (F5): W^X — a writable mapping made executable
        ("mprotect RW then RX", || {
            // SAFETY: plain syscalls on a mapping of the child's own.
            unsafe {
                let m = libc::syscall(
                    libc::SYS_mmap,
                    0,
                    4096,
                    libc::PROT_READ | libc::PROT_WRITE,
                    libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                    -1,
                    0,
                );
                libc::syscall(
                    libc::SYS_mprotect,
                    m,
                    4096,
                    libc::PROT_READ | libc::PROT_EXEC,
                );
            }
            0
        }),
        ("pkey_mprotect", || {
            // SAFETY: plain syscall (no mapping: EINVAL if it ran).
            unsafe {
                libc::syscall(
                    libc::SYS_pkey_mprotect,
                    0,
                    4096,
                    libc::PROT_READ | libc::PROT_EXEC,
                    -1,
                )
            };
            0
        }),
        // review of #480 (F5): a signal to another process by any call
        ("tgkill another process", || {
            // SAFETY: plain syscall (signal 0, never delivered).
            unsafe { libc::syscall(libc::SYS_tgkill, 1, 1, 0) };
            0
        }),
        ("tkill", || {
            // SAFETY: plain syscall (signal 0).
            unsafe { libc::syscall(libc::SYS_tkill, 1, 0) };
            0
        }),
        ("rt_sigqueueinfo", || {
            // SAFETY: plain syscall (no info: EFAULT if it ran).
            unsafe { libc::syscall(libc::SYS_rt_sigqueueinfo, 1, 0, 0) };
            0
        }),
        ("pidfd_send_signal", || {
            // SAFETY: plain syscall (no descriptor: EBADF if it ran).
            unsafe { libc::syscall(libc::SYS_pidfd_send_signal, -1, 0, 0, 0) };
            0
        }),
        // review of #480 (F8): no msghdr from the worker
        ("sendmsg on the channel", || {
            // SAFETY: plain syscall.
            unsafe { libc::syscall(libc::SYS_sendmsg, 3, std::ptr::null::<u8>(), 0) };
            0
        }),
        ("recvfrom with an address", || {
            let mut buf = [0u8; 8];
            let mut sa = [0u8; 16];
            let mut len: libc::socklen_t = 16;
            // SAFETY: plain syscall into local buffers.
            unsafe {
                libc::syscall(
                    libc::SYS_recvfrom,
                    3,
                    buf.as_mut_ptr(),
                    buf.len(),
                    crate::worker::transport::WORKER_RECV_FLAGS,
                    sa.as_mut_ptr(),
                    &mut len,
                )
            };
            0
        }),
        ("sendto with other flags", || {
            let buf = [0u8; 8];
            // SAFETY: plain syscall.
            unsafe { libc::syscall(libc::SYS_sendto, 3, buf.as_ptr(), 8, 0, 0usize, 0usize) };
            0
        }),
        // the review's mutations N22, N23: each argument the rules pin
        ("recvfrom with other flags", || {
            let mut buf = [0u8; 8];
            // SAFETY: plain syscall into a local buffer; it does not wait
            // (MSG_DONTWAIT) if it ever ran.
            unsafe {
                libc::syscall(
                    libc::SYS_recvfrom,
                    3,
                    buf.as_mut_ptr(),
                    buf.len(),
                    crate::worker::transport::WORKER_RECV_FLAGS | libc::MSG_DONTWAIT,
                    0usize,
                    0usize,
                )
            };
            0
        }),
        ("sendto with an address", || {
            let buf = [0u8; 8];
            let sa = [0u8; 16];
            // SAFETY: plain syscall from local buffers.
            unsafe {
                libc::syscall(
                    libc::SYS_sendto,
                    3,
                    buf.as_ptr(),
                    8,
                    crate::worker::transport::WORKER_SEND_FLAGS,
                    sa.as_ptr(),
                    16usize,
                )
            };
            0
        }),
        // review of #480 (F7): what only the filter refuses on every lab
        // kernel
        ("unshare a user namespace", || {
            // SAFETY: plain syscall.
            unsafe { libc::syscall(libc::SYS_unshare, libc::CLONE_NEWUSER) };
            0
        }),
        ("io_uring_setup", || {
            // SAFETY: plain syscall (no params: EFAULT if it ran).
            unsafe { libc::syscall(libc::SYS_io_uring_setup, 1, 0) };
            0
        }),
        ("keyctl", || {
            // SAFETY: plain syscall (KEYCTL_GET_KEYRING_ID of the session).
            unsafe { libc::syscall(libc::SYS_keyctl, 0, -3, 0) };
            0
        }),
        ("perf_event_open", || {
            // SAFETY: plain syscall (no attr: EFAULT if it ran).
            unsafe { libc::syscall(libc::SYS_perf_event_open, 0, 0, -1, -1, 0) };
            0
        }),
        ("userfaultfd", || {
            // SAFETY: plain syscall.
            unsafe { libc::syscall(libc::SYS_userfaultfd, 0) };
            0
        }),
        ("a UDP socket", || {
            // SAFETY: plain syscall.
            unsafe { libc::syscall(libc::SYS_socket, libc::AF_INET, libc::SOCK_DGRAM, 0) };
            0
        }),
        ("a UNIX socket (by path)", || {
            // SAFETY: plain syscall.
            unsafe { libc::syscall(libc::SYS_socket, libc::AF_UNIX, libc::SOCK_STREAM, 0) };
            0
        }),
    ];
    for (what, body) in cases {
        let s = in_child(|| install_prepared(&prog), body);
        assert!(killed_by_sigsys(s), "{what}: status {s:#x}");
    }
}

#[test]
fn landlock_denies_every_path_where_the_kernel_has_it() {
    let abi = kernel_landlock_abi();
    let s = in_child(
        || {
            let mut level = SandboxLevel::default();
            landlock_restrict(&mut level).is_ok()
        },
        || {
            // SAFETY: plain syscall with a static C string.
            let fd = unsafe {
                libc::syscall(
                    libc::SYS_openat,
                    libc::AT_FDCWD,
                    c"/etc/hostname".as_ptr(),
                    libc::O_RDONLY,
                )
            };
            if fd >= 0 {
                return 1;
            }
            match io::Error::last_os_error().raw_os_error() {
                Some(libc::EACCES) => 0,
                Some(libc::ENOENT) => 3,
                _ => 2,
            }
        },
    );
    if abi == 0 {
        // no Landlock on this kernel: the open goes through (or the file
        // is absent), and the level says none
        assert!(exited(s, 1) || exited(s, 3), "status {s:#x}");
    } else {
        assert!(exited(s, 0), "abi {abi}: status {s:#x}");
    }
}

#[test]
fn the_level_declares_what_the_kernel_gave() {
    // in a child: the ruleset binds the calling thread for good
    let abi = kernel_landlock_abi();
    let (r, w) = {
        let mut fds = [0; 2];
        // SAFETY: pipe into a local array.
        assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
        (fds[0], fds[1])
    };
    // SAFETY: fork; the child writes four bytes and exits.
    let pid = unsafe { libc::fork() };
    assert!(pid >= 0);
    if pid == 0 {
        let mut level = SandboxLevel::default();
        let ok = landlock_restrict(&mut level).is_ok();
        let out = [
            u8::from(ok),
            level.landlock_abi,
            level.landlock as u8,
            u8::from(level.fs_denied)
                | u8::from(level.net_denied) << 1
                | u8::from(level.scoped) << 2,
        ];
        // SAFETY: write to our pipe, then _exit.
        unsafe {
            libc::write(w, out.as_ptr().cast(), out.len());
            libc::_exit(0);
        }
    }
    let mut out = [0u8; 4];
    // SAFETY: read from our pipe; wait for our child.
    unsafe {
        libc::close(w);
        assert_eq!(libc::read(r, out.as_mut_ptr().cast(), 4), 4);
        libc::close(r);
        libc::waitpid(pid, std::ptr::null_mut(), 0);
    }
    assert_eq!(out[0], 1, "restrict ran");
    assert_eq!(
        out[1],
        abi.min(LANDLOCK_ASK as u8),
        "the ABI declared is the kernel's"
    );
    let flags = out[3];
    if abi == 0 {
        assert_eq!(flags, 0);
    } else {
        assert_eq!(flags & 1, 1, "fs");
        assert_eq!(flags >> 1 & 1, u8::from(abi >= 4), "net from ABI 4");
        assert_eq!(flags >> 2 & 1, u8::from(abi >= 6), "scope from ABI 6");
    }
}

#[test]
fn the_measure_reads_this_process() {
    let level = measure().unwrap();
    let (uid, gid) = ids();
    assert_eq!(level.uid, uid[0]);
    assert_eq!(level.gid, gid[0]);
    assert!(level.nofile > 0);
    assert!(!level.seccomp);
    // the bounding set is never empty unless dropped, and holds at least
    // what the effective set holds
    let caps = capability_sets().unwrap();
    assert_eq!(caps.eff & !caps.bnd, 0);
}

#[test]
fn a_privileged_or_grouped_caller_is_refused() {
    // this test process runs as an ordinary user with groups, or as root
    // (CI's KVM job): either way it is no worker
    let (uid, _) = ids();
    if uid[0] == 0 || supplementary_groups() > 0 {
        assert!(matches!(
            refuse_privileged(),
            Err(SandboxError::Privileged(_))
        ));
    }
}

static PORT: std::sync::atomic::AtomicU16 = std::sync::atomic::AtomicU16::new(0);

/// A TCP connect to 127.0.0.1:`PORT`: 0 through, 1 `EACCES`, 2 another
/// error.
fn connect_local() -> i32 {
    // SAFETY: plain syscalls on our own socket and a local address.
    unsafe {
        let fd = libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0);
        let sa = libc::sockaddr_in {
            sin_family: libc::AF_INET as libc::sa_family_t,
            sin_port: PORT.load(std::sync::atomic::Ordering::SeqCst).to_be(),
            sin_addr: libc::in_addr {
                s_addr: u32::from(std::net::Ipv4Addr::LOCALHOST).to_be(),
            },
            sin_zero: [0; 8],
        };
        let rc = libc::connect(
            fd,
            &sa as *const libc::sockaddr_in as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_in>() as u32,
        );
        libc::close(fd);
        if rc == 0 {
            0
        } else if io::Error::last_os_error().raw_os_error() == Some(libc::EACCES) {
            1
        } else {
            2
        }
    }
}

/// Signal 0 to the parent: 0 through, 1 `EPERM`, 2 another error.
fn signal_parent() -> i32 {
    // SAFETY: an existence probe of our parent.
    if unsafe { libc::kill(libc::getppid(), 0) } == 0 {
        0
    } else if io::Error::last_os_error().raw_os_error() == Some(libc::EPERM) {
        1
    } else {
        2
    }
}

/// Landlock's network and scope rights, where the kernel has them: a TCP
/// connect to a listener of this process (ABI ≥ 4) and a signal to it
/// (ABI ≥ 6) are refused in a restricted child, and go through without
/// the ruleset.
#[test]
fn landlock_denies_tcp_and_signals_where_the_kernel_has_them() {
    let abi = kernel_landlock_abi();
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    PORT.store(
        listener.local_addr().unwrap().port(),
        std::sync::atomic::Ordering::SeqCst,
    );
    let s = in_child(
        || {
            let mut level = SandboxLevel::default();
            landlock_restrict(&mut level).is_ok()
        },
        || connect_local() * 10 + signal_parent(),
    );
    assert!(libc::WIFEXITED(s), "status {s:#x}");
    let code = libc::WEXITSTATUS(s);
    assert_eq!(code / 10, i32::from(abi >= 4), "connect on ABI {abi}");
    assert_eq!(code % 10, i32::from(abi >= 6), "signal on ABI {abi}");
    // without the ruleset both go through
    let s = in_child(|| true, || connect_local() * 10 + signal_parent());
    assert!(
        libc::WIFEXITED(s) && libc::WEXITSTATUS(s) == 0,
        "status {s:#x}"
    );
    drop(listener);
}

/// The level declared on each lab kernel's ABI (5.15: 1, 6.1: 2, 6.8: 4,
/// 6.12: 6), and none without Landlock or with nothing enforced.
#[test]
fn the_level_is_declared_from_what_was_measured() {
    use nn_proto::ipc::LandlockEnforced::{Full, None as NotEnforced, Partial};
    let all = Measured {
        fs: true,
        net: true,
        scope: true,
    };
    let decl = |abi, enforced, m: Measured| {
        let mut l = SandboxLevel::default();
        declare(&mut l, abi, enforced, m);
        (
            l.landlock_abi,
            l.landlock,
            l.fs_denied,
            l.net_denied,
            l.scoped,
        )
    };
    // what was measured is declared, under an enforced ruleset only
    assert_eq!(decl(0, Full, all), (0, NotEnforced, false, false, false));
    assert_eq!(
        decl(4, NotEnforced, all),
        (4, NotEnforced, false, false, false)
    );
    assert_eq!(decl(6, Full, all), (6, Full, true, true, true));
    let fs_only = Measured {
        fs: true,
        ..Measured::default()
    };
    assert_eq!(decl(1, Partial, fs_only), (1, Partial, true, false, false));
    // a measurement below the ABI is declared as measured (the core then
    // refuses it: `nn_proto::ipc::check_hello`)
    assert_eq!(decl(4, Partial, fs_only), (4, Partial, true, false, false));
    assert_eq!(
        decl(9, Full, Measured::default()),
        (9, Full, false, false, false)
    );
}

/// Review of #480 (F7): the measurement itself, in a restricted child on
/// this kernel — what its ABI gives, and nothing without the ruleset.
#[test]
fn landlock_is_measured_where_the_kernel_has_it() {
    let abi = kernel_landlock_abi();
    let pack = |m: Measured| i32::from(m.fs) | i32::from(m.net) << 1 | i32::from(m.scope) << 2;
    let restricted = in_child(
        || true,
        || {
            let mut level = SandboxLevel::default();
            if landlock_restrict(&mut level).is_err() {
                return 100;
            }
            i32::from(level.fs_denied)
                | i32::from(level.net_denied) << 1
                | i32::from(level.scoped) << 2
        },
    );
    assert!(libc::WIFEXITED(restricted), "status {restricted:#x}");
    let want = if abi == 0 {
        0
    } else {
        pack(Measured {
            fs: abi >= 1,
            net: abi >= 4,
            scope: abi >= 6,
        })
    };
    assert_eq!(libc::WEXITSTATUS(restricted), want, "ABI {abi}");
    // without the ruleset nothing is refused
    let open = in_child(
        || true,
        || {
            let peer = scope_peer();
            let m = measure_landlock(peer.as_ref());
            i32::from(m.fs) | i32::from(m.net) << 1 | i32::from(m.scope) << 2
        },
    );
    assert!(libc::WIFEXITED(open), "status {open:#x}");
    assert_eq!(libc::WEXITSTATUS(open), 0);
}

/// Lot 277: `getdents64` records as the kernel lays them out — `d_ino`,
/// `d_off`, `d_reclen` at byte 16, `d_type`, the name from byte 19 —
/// counted without `.` and `..`, names that only begin with a dot kept.
#[test]
fn the_thread_count_reads_dirent_records() {
    fn record(buf: &mut Vec<u8>, name: &str) {
        let reclen = (19 + name.len() + 1).div_ceil(8) * 8;
        let start = buf.len();
        buf.resize(start + reclen, 0);
        buf[start + 16..start + 18].copy_from_slice(&(reclen as u16).to_ne_bytes());
        buf[start + 19..start + 19 + name.len()].copy_from_slice(name.as_bytes());
    }
    let mut bytes = Vec::new();
    for name in [".", "..", "4242", "4243", ".x", "..y"] {
        record(&mut bytes, name);
    }
    let mut words = vec![0u64; bytes.len().div_ceil(8)];
    // SAFETY: the u64 buffer is at least as long as `bytes`.
    unsafe {
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), words.as_mut_ptr().cast(), bytes.len());
    }
    assert_eq!(count_dirents(&words, bytes.len()), 4);
    // a length that ends inside a record counts only the whole ones
    // before it; a zero record length ends the walk
    assert_eq!(count_dirents(&words, 24 * 3), 1);
    assert_eq!(count_dirents(&[0u64; 8], 64), 0);
}

/// Lot 277: a forked child is its process's only thread, and may enter
/// (the step passes); this test process runs other threads, so `enter`
/// refuses it first — before it changed anything of the process (the
/// privilege check, which would refuse a test runner too, comes after).
#[test]
fn a_worker_with_a_second_thread_is_refused_before_anything_changes() {
    fn alone() -> i32 {
        match (thread_count(), refuse_threaded()) {
            (Ok(1), Ok(())) => 0,
            _ => 1,
        }
    }
    assert!(
        exited(in_child(|| true, alone), 0),
        "a forked child counts one thread"
    );

    let (stop, wait) = std::sync::mpsc::channel::<()>();
    let other = std::thread::spawn(move || {
        let _ = wait.recv();
    });
    let n = thread_count().expect("/proc/self/task");
    assert!(n >= 2, "{n} threads");
    // more threads than one getdents64 batch holds (4 KiB, ~170 entries):
    // every batch is counted
    let (park_stop, park_wait) = std::sync::mpsc::channel::<()>();
    let park_wait = std::sync::Arc::new(std::sync::Mutex::new(park_wait));
    let parked: Vec<_> = (0..300)
        .map(|_| {
            let w = std::sync::Arc::clone(&park_wait);
            std::thread::spawn(move || {
                let _ = w.lock().map(|r| r.recv());
            })
        })
        .collect();
    let many = thread_count().expect("/proc/self/task");
    // (other tests' threads come and go: at least these 300 and this one)
    assert!(many > 300, "{many} threads with 300 parked");
    drop(park_stop);
    for t in parked {
        t.join().unwrap();
    }
    // SAFETY: prctl with integer arguments.
    let nnp_before = unsafe { libc::prctl(libc::PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) };
    let nofile_before = getrlimit(libc::RLIMIT_NOFILE);
    match enter(&Profile::parse(3)) {
        Err(SandboxError::Threaded(k)) => assert!(k >= 2, "{k}"),
        other => panic!("expected Threaded, got {other:?}"),
    }
    assert!(matches!(refuse_threaded(), Err(SandboxError::Threaded(_))));
    // SAFETY: prctl with integer arguments.
    let nnp_after = unsafe { libc::prctl(libc::PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) };
    assert_eq!(nnp_after, nnp_before, "no_new_privs untouched");
    assert_eq!(
        getrlimit(libc::RLIMIT_NOFILE),
        nofile_before,
        "limits untouched"
    );
    assert!(SandboxError::Threaded(n)
        .to_string()
        .contains(&format!("{n} threads")));
    drop(stop);
    other.join().unwrap();
}
