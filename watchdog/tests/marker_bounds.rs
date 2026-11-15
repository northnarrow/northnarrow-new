//! Lot 357 (re-check 3 of #563, R3-2): the watchdog's stuck marker and the
//! shutdown check never hold its one thread. Under a FUSE that never
//! answers over the run directory: with the directory opened at the start
//! (`anchor_run_dir`) the marker is replaced and the check answers beneath
//! that descriptor, at once; without it (by path) each gives up within
//! its 2 s — the removal of the old marker by path used to hold the whole
//! watchdog (no stuck recovery, no respawn, no `sd_notify`), and the
//! check's reads too. On the code before the lot the second child is ended
//! by its alarm.
//!
//! A test binary of its own, with this one test (the run forks).

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

/// Lot 353 (re-check 3 of #563, R3-4): `Some(rc)` of a child that ran;
/// `None` (the namespaces refused, or FUSE in them: the child's 99) is a
/// skip on a developer's host and a FAILURE under CI (`CI` set): ci.yml's
/// test job enables unprivileged user namespaces, and a test that skips
/// there protects nothing (it "passed" in 0.00 s). As
/// `nn_linux::fuse_testing::ran`, of which the watchdog has no dependency.
fn ran(rc: Option<i32>) -> Option<i32> {
    if rc.is_none() {
        assert!(
            std::env::var_os("CI").is_none(),
            "no user and mount namespace with FUSE here: under CI this test must run, never skip"
        );
        eprintln!("skipped: no user and mount namespace with FUSE here");
    }
    rc
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

fn record() -> nn_proto::watchdog_hold::HoldRecord {
    northnarrow_watchdog::stuck_unresponsive_record(4242, "a test", 1_800_000_000)
}

#[test]
fn the_markers_never_hold_the_watchdog_under_a_fuse_over_its_run_directory() {
    let dir = tempfile::tempdir().unwrap();
    let run = dir.path().join("run");
    std::fs::create_dir(&run).unwrap();
    let (admin_pub, agent_id) = (dir.path().join("admin.pub"), dir.path().join("agent_id"));
    let check = |run: &Path| {
        let marker = run.join("agent.shutdown");
        let c = northnarrow_watchdog::ShutdownCheck {
            marker: &marker,
            admin_pub: &admin_pub,
            agent_id_file: &agent_id,
            agent_pid: 4242,
            agent_started: None,
        };
        let t = Instant::now();
        (
            northnarrow_watchdog::check_shutdown_marker_bounded(&c),
            t.elapsed(),
        )
    };
    // the run directory opened before the mount: beneath it, at once
    let anchored = in_userns(|| {
        // SAFETY: alarm has no preconditions; a held step ends the child.
        unsafe { libc::alarm(30) };
        northnarrow_watchdog::anchor_run_dir(&run);
        let Some(fuse) = never_answering_fuse(&run) else {
            return 99;
        };
        let t = Instant::now();
        let left = northnarrow_watchdog::leave_stuck_marker(&run.join("watchdog.stuck"), &record());
        let t_left = t.elapsed();
        let (verdict, t_check) = check(&run);
        eprintln!("anchored: marker {left:?} in {t_left:?}; check {verdict:?} in {t_check:?}");
        drop(fuse);
        if left.is_err() || t_left > Duration::from_millis(500) {
            return 2;
        }
        if verdict != northnarrow_watchdog::ShutdownVerdict::Absent
            || t_check > Duration::from_millis(500)
        {
            return 3;
        }
        0
    });
    // never opened: by path, each step bounded
    let by_path = in_userns(|| {
        // SAFETY: as above.
        unsafe { libc::alarm(30) };
        let Some(fuse) = never_answering_fuse(&run) else {
            return 99;
        };
        let t = Instant::now();
        let left = northnarrow_watchdog::leave_stuck_marker(&run.join("watchdog.stuck"), &record());
        let t_left = t.elapsed();
        let (verdict, t_check) = check(&run);
        eprintln!("by path: marker {left:?} in {t_left:?}; check {verdict:?} in {t_check:?}");
        drop(fuse);
        if left.is_ok() || t_left > Duration::from_secs(4) {
            return 4;
        }
        if !matches!(verdict, northnarrow_watchdog::ShutdownVerdict::Refused(_))
            || t_check > Duration::from_secs(4)
        {
            return 5;
        }
        0
    });
    if let Some(rc) = ran(anchored) {
        assert_eq!(rc, 0, "beneath the run directory (see the child's line)");
    }
    // the anchored written marker is in the directory itself
    if anchored.is_some() {
        assert!(run.join("watchdog.stuck").exists());
    }
    if let Some(rc) = ran(by_path) {
        assert_eq!(rc, 0, "by path, bounded (see the child's line)");
    }
}
