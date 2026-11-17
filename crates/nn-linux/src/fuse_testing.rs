//! Lot 353 (re-check 2 of #563): the tests' file systems that do not
//! answer — the shapes three reviews of #563 found the agent's critical
//! threads held on, one at a time: a FUSE mounted in a user and mount
//! namespace of the test's own, whose daemon answers `INIT` and the first
//! `answered` lookups (`ENOENT`) and holds every request after them (a
//! "smart" FUSE: the bounded look of the admin socket's watch answered, the
//! rebind behind it held). The tests' only (`cfg(test)` or the `test-util`
//! feature the agent's tests enable): no build of the binaries has it.

use std::fs::File;
use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

/// `body`'s exit code, run in a forked child in a user and mount namespace
/// of its own (`/` made private), uid and gid 0 mapped to the caller's;
/// `None` when the host refuses the namespaces (the child exits 99 itself
/// for that).
pub fn in_userns(body: impl FnOnce() -> i32) -> Option<i32> {
    // SAFETY: getuid/getgid have no preconditions.
    let (uid, gid) = unsafe { (libc::getuid(), libc::getgid()) };
    // SAFETY: fork; the child unshares, runs `body` and `_exit`s.
    let pid = unsafe { libc::fork() };
    assert!(pid >= 0, "fork");
    if pid == 0 {
        // a child held (a lock another test's thread held at the fork) ends,
        // failing its test, never holding the run
        // SAFETY: alarm has no preconditions.
        unsafe { libc::alarm(60) };
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
    assert!(libc::WIFEXITED(status), "child status {status:#x}");
    match libc::WEXITSTATUS(status) {
        99 => None,
        rc => Some(rc),
    }
}

/// Lot 353 (re-check 3 of #563): a namespace test's outcome, its skip
/// refused under CI. `Some(rc)` of a child that ran; `None` — the host
/// refused the namespaces, or the child lacked a prerequisite in them
/// (FUSE, an anchored view…: it exits 99, its line on stderr) — is a skip
/// on a developer's host and a FAILURE when `CI` is set (every CI runner
/// sets it): the CI test job is set up to have them (ci.yml's user
/// namespaces step), and a test that skips there protects nothing — the
/// harness of #563 "passed" there in 0.00 s.
pub fn ran(rc: Option<i32>) -> Option<i32> {
    ran_under(std::env::var_os("CI").is_some(), rc)
}

/// [`ran`] with the `CI` flag given (its test).
fn ran_under(ci: bool, rc: Option<i32>) -> Option<i32> {
    if rc.is_none() {
        missing_under(
            ci,
            "no user and mount namespace here, or a prerequisite in it (the child's line above)",
        );
    }
    rc
}

/// A namespace test's prerequisite missing before its child (a view not
/// anchored here): named and skipped on a developer's host, a failure under
/// CI, as [`ran`].
pub fn missing(why: &str) {
    missing_under(std::env::var_os("CI").is_some(), why);
}

fn missing_under(ci: bool, why: &str) {
    assert!(
        !ci,
        "{why}: under CI this test must run, never skip (CI is set; ci.yml's test job enables unprivileged user namespaces)"
    );
    eprintln!("skipped: {why}");
}

/// A FUSE mounted over `target` (in the caller's namespaces, uid 0 mapped)
/// whose daemon thread answers `INIT` and the first `answered` lookups
/// (`ENOENT`), then holds every request. Dropped, the daemon stops and
/// closes the device — its only descriptor: the connection is aborted and
/// every request it held fails (`ENOTCONN`), so the threads it held go on.
/// `None` when `/dev/fuse` or the mount is refused.
pub fn smart_fuse_over(target: &Path, answered: usize) -> Option<SmartFuse> {
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
            c"nnsmart".as_ptr(),
            t.as_ptr(),
            c"fuse".as_ptr(),
            libc::MS_NOSUID | libc::MS_NODEV,
            opts.as_ptr().cast(),
        )
    } == 0;
    if !ok {
        return None;
    }
    let stop = Arc::new(AtomicBool::new(false));
    let flag = Arc::clone(&stop);
    let daemon = std::thread::Builder::new()
        .name("nn-test-fuse".into())
        .spawn(move || serve(fuse, answered, &flag))
        .ok()?;
    Some(SmartFuse {
        stop,
        daemon: Some(daemon),
    })
}

/// [`smart_fuse_over`]'s mount: dropped, the connection is aborted.
pub struct SmartFuse {
    stop: Arc<AtomicBool>,
    daemon: Option<std::thread::JoinHandle<()>>,
}

impl Drop for SmartFuse {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(d) = self.daemon.take() {
            let _ = d.join();
        }
    }
}

/// The daemon: `INIT` and the first `answered` lookups answered, the rest
/// held, until `stop` — then the device closed (its only descriptor).
fn serve(mut dev: File, answered: usize, stop: &AtomicBool) {
    let mut buf = vec![0u8; (1 << 20) + 8192];
    let mut lookups = 0usize;
    while !stop.load(Ordering::Acquire) {
        let mut pfd = libc::pollfd {
            fd: dev.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: one live pollfd.
        if unsafe { libc::poll(&mut pfd, 1, 100) } <= 0 {
            continue;
        }
        let Ok(n) = dev.read(&mut buf) else { return };
        if n < 40 {
            return;
        }
        let op = u32::from_ne_bytes([buf[4], buf[5], buf[6], buf[7]]);
        let mut unique = [0u8; 8];
        unique.copy_from_slice(&buf[8..16]);
        let reply = |dev: &mut File, err: i32, body: &[u8]| {
            let mut out = Vec::new();
            out.extend_from_slice(&((16 + body.len()) as u32).to_ne_bytes());
            out.extend_from_slice(&err.to_ne_bytes());
            out.extend_from_slice(&unique);
            out.extend_from_slice(body);
            let _ = dev.write(&out);
        };
        match op {
            // FUSE_INIT: 7.22, no flags, max_write 4096
            26 => {
                let mut body = Vec::new();
                for v in [7u32, 22, 0, 0] {
                    body.extend_from_slice(&v.to_ne_bytes());
                }
                body.extend_from_slice(&1u16.to_ne_bytes());
                body.extend_from_slice(&1u16.to_ne_bytes());
                body.extend_from_slice(&4096u32.to_ne_bytes());
                reply(&mut dev, 0, &body);
            }
            // FUSE_LOOKUP: the first `answered` answered, then held
            1 if lookups < answered => {
                lookups += 1;
                reply(&mut dev, -libc::ENOENT, &[]);
            }
            // everything else: never answered
            _ => {}
        }
    }
}

/// Lot 366: `check` run in a user and mount namespace of the test's own,
/// beside a FUSE that answers nothing ([`smart_fuse_over`] a directory of
/// its own, no lookup answered): `check` is handed the path of a
/// descriptor of that FUSE's root (`/proc/<pid>/fd/<n>`) — a link, as a
/// process's `exe`, `root` or `fd/<n>` is one — and runs on a thread of
/// its own. Its exit code: 0
/// when `check` answered `true` within 10 s, 1 when it answered `false`, 5
/// when it was held (the FUSE is then dropped: the held request fails and
/// the thread goes on); `None` when the namespaces or the FUSE are refused
/// and [`ran`] allows the skip (a developer's host; under CI it fails).
pub fn answers_beside_a_held_fuse(
    check: impl FnOnce(&Path) -> bool + Send + 'static,
) -> Option<i32> {
    // the views the checks read through made before the fork: views
    // another test's thread is making at the fork would never be made in
    // the child (their maker is not there), and the child would wait on
    // them for ever (a test that anchors its own in the child calls
    // `in_userns` itself)
    let _ = antitamper_bpf::kernel_roots::views();
    ran(in_userns(move || {
        // SAFETY: alarm has no preconditions; a held check ends the child.
        unsafe { libc::alarm(30) };
        // SAFETY: getpid has no preconditions.
        let dir = std::env::temp_dir().join(format!("nn-held-fuse-{}", unsafe { libc::getpid() }));
        if std::fs::create_dir(&dir).is_err() {
            return 99;
        }
        let Some(fuse) = smart_fuse_over(&dir, 0) else {
            let _ = std::fs::remove_dir(&dir);
            return 99;
        };
        // its root, reached by the walk to the mount point: nothing asked
        let Ok(root) = std::os::unix::fs::OpenOptionsExt::custom_flags(
            std::fs::OpenOptions::new().read(true),
            libc::O_PATH | libc::O_DIRECTORY,
        )
        .open(&dir) else {
            return 99;
        };
        let held = std::path::PathBuf::from(format!(
            "/proc/{}/fd/{}",
            std::process::id(),
            root.as_raw_fd()
        ));
        let (tx, rx) = std::sync::mpsc::channel();
        let spawned = std::thread::Builder::new()
            .name("nn-test-check".into())
            .spawn(move || {
                let _ = tx.send(check(&held));
            });
        if spawned.is_err() {
            return 99;
        }
        let answer = rx.recv_timeout(std::time::Duration::from_secs(10));
        drop(fuse);
        drop(root);
        if let Ok(c) = std::ffi::CString::new(dir.as_os_str().as_encoded_bytes()) {
            // SAFETY: a NUL-terminated path; the mount, ours, detached.
            unsafe { libc::umount2(c.as_ptr(), libc::MNT_DETACH) };
        }
        let _ = std::fs::remove_dir(&dir);
        match answer {
            Ok(true) => 0,
            Ok(false) => 1,
            Err(_) => {
                eprintln!("held for 10 s by the FUSE that answers nothing");
                5
            }
        }
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Lot 353 (re-check 3 of #563, R3-4): under CI a namespace test that
    /// cannot run fails; on a developer's host it is skipped. At 5da316c1
    /// every one of them printed "skipped" and passed in CI, in 0.00 s.
    #[test]
    fn a_namespace_test_that_cannot_run_fails_under_ci() {
        assert_eq!(ran_under(false, Some(3)), Some(3));
        assert_eq!(ran_under(true, Some(0)), Some(0));
        assert_eq!(
            ran_under(false, None),
            None,
            "skipped on a developer's host"
        );
        let refused = std::panic::catch_unwind(|| ran_under(true, None));
        assert!(refused.is_err(), "under CI a skip is a failure");
        assert!(std::panic::catch_unwind(|| missing_under(true, "a view")).is_err());
        missing_under(false, "a view");
    }
}
