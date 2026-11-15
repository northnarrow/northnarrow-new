//! Lot 353 (re-check 2 of #563, N4): the watchdog's by-path steps on
//! `/run/northnarrow` are bounded. Its STATUS ping connects to the admin
//! socket by path — a lookup inside `connect(2)` that no async timeout
//! interrupts — and a file system laid over the socket's directory that
//! does not answer held the watchdog's loop for as long as it stayed. In a
//! user and mount namespace of its own, under a FUSE that never answers
//! over the socket's directory, the ping fails within its timeout and the
//! next one at once (one held connect per path). On main the first ping
//! never returned (the child is ended by its alarm).
//!
//! A test binary of its own, with this one test: the run forks (the user
//! namespace), and a fork while other tests' threads hold a lock left the
//! child waiting on it.

use std::os::fd::AsRawFd;
use std::path::Path;
use std::time::{Duration, Instant};

/// `body`'s exit code, in a forked child with user and mount namespaces of
/// its own (uid and gid 0 mapped to the caller's); `None` when refused.
fn in_userns(body: impl FnOnce() -> i32) -> Option<i32> {
    // SAFETY: getuid/getgid have no preconditions.
    let (uid, gid) = unsafe { (libc::getuid(), libc::getgid()) };
    // SAFETY: fork; the child unshares, runs `body` and `_exit`s.
    let pid = unsafe { libc::fork() };
    assert!(pid >= 0, "fork");
    if pid == 0 {
        // SAFETY: the child's own namespaces; no data.
        let refused = unsafe {
            libc::unshare(libc::CLONE_NEWUSER | libc::CLONE_NEWNS) != 0
                || libc::mount(
                    std::ptr::null(),
                    c"/".as_ptr(),
                    std::ptr::null(),
                    libc::MS_REC | libc::MS_PRIVATE,
                    std::ptr::null(),
                ) != 0
        };
        let w = |p: &str, s: String| std::fs::write(p, s).is_ok();
        let mapped = !refused
            && w("/proc/self/setgroups", "deny".into())
            && w("/proc/self/uid_map", format!("0 {uid} 1"))
            && w("/proc/self/gid_map", format!("0 {gid} 1"));
        let rc = if mapped { body() } else { 99 };
        // SAFETY: _exit in the child.
        unsafe { libc::_exit(rc) };
    }
    let mut status = 0;
    // SAFETY: waiting for our own child.
    unsafe { libc::waitpid(pid, &mut status, 0) };
    assert!(
        libc::WIFEXITED(status),
        "the child did not exit (status {status:#x}: its alarm — a ping held)"
    );
    match libc::WEXITSTATUS(status) {
        99 => None,
        rc => Some(rc),
    }
}

/// A FUSE over `target` whose daemon never reads: every request waits.
/// Its descriptor (the only one): dropped, the connection is aborted.
fn never_answering_fuse(target: &Path) -> Option<std::fs::File> {
    let fuse = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/fuse")
        .ok()?;
    let opts = std::ffi::CString::new(format!(
        "fd={},rootmode=40000,user_id=0,group_id=0",
        fuse.as_raw_fd()
    ))
    .ok()?;
    let t = std::ffi::CString::new(target.as_os_str().as_encoded_bytes()).ok()?;
    // SAFETY: NUL-terminated strings; the options name our descriptor.
    let ok = unsafe {
        libc::mount(
            c"nnwdtest".as_ptr(),
            t.as_ptr(),
            c"fuse".as_ptr(),
            libc::MS_NOSUID | libc::MS_NODEV,
            opts.as_ptr().cast(),
        )
    } == 0;
    ok.then_some(fuse)
}

#[test]
fn the_ping_is_bounded_under_a_fuse_over_the_socket_s_directory() {
    let dir = tempfile::tempdir().unwrap();
    let run = dir.path().join("run");
    std::fs::create_dir(&run).unwrap();
    let rc = in_userns(|| {
        // SAFETY: alarm has no preconditions; a held ping ends the child.
        unsafe { libc::alarm(30) };
        let Some(fuse) = never_answering_fuse(&run) else {
            eprintln!("skipped: FUSE refused in this namespace");
            return 0;
        };
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let sock = run.join("admin.sock");
        let t = Instant::now();
        let first = rt.block_on(northnarrow_watchdog::ping_agent_status(
            &sock,
            Duration::from_secs(1),
            None,
        ));
        let t1 = t.elapsed();
        let t = Instant::now();
        let second = rt.block_on(northnarrow_watchdog::ping_agent_status(
            &sock,
            Duration::from_secs(1),
            None,
        ));
        let t2 = t.elapsed();
        eprintln!("first {first:?} in {t1:?}; second {second:?} in {t2:?}");
        // the connection aborted: the held connect ends
        drop(fuse);
        if first.is_ok() || second.is_ok() {
            return 2;
        }
        if t1 > Duration::from_secs(3) {
            return 3;
        }
        if t2 > Duration::from_millis(500) {
            return 4;
        }
        0
    });
    match rc {
        None => eprintln!("skipped: no user namespace here"),
        Some(rc) => assert_eq!(rc, 0, "the ping was not bounded (see the child's line)"),
    }
}
