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
