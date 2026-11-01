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
        "recvmsg",
        "sendmsg",
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
        "open", "openat", "socket", "connect", "execve", "execveat", "clone", "clone3", "fork",
        "kill", "ptrace", "bpf", "prctl", "read", "setuid", "capset",
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
                // recvmsg on the channel's number (EBADF here): kept
                libc::syscall(libc::SYS_recvmsg, 3, std::ptr::null_mut::<u8>(), 0);
            }
            7
        },
    );
    assert!(exited(s, 7), "status {s:#x}");
}

#[test]
fn every_escape_kills_the_process() {
    let prog = parse_filter(3);
    let cases: [(&str, fn() -> i32); 9] = [
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
