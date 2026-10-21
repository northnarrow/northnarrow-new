//! What the scanner does to itself before it reads anything (lab PR 223).
//!
//! The agent starts it as its own unprivileged user, with no supplementary
//! groups and its socket on descriptor 3. Here the scanner refuses to run
//! as root, forbids privilege gains (`PR_SET_NO_NEW_PRIVS`), makes itself
//! undumpable (no core, no ptrace by its own user), closes every other
//! descriptor and caps what it may create: no process (`RLIMIT_NPROC` 0),
//! few descriptors, bounded memory. No file either, but that is the seccomp
//! filter's doing ([`crate::seccomp`], last, once the configuration is
//! read): `RLIMIT_FSIZE` 0 would also kill it (`SIGXFSZ`) for a diagnostic
//! written to a stderr that is a regular file.

use std::io;

fn setrlimit(res: libc::__rlimit_resource_t, v: u64) -> io::Result<()> {
    let lim = libc::rlimit {
        rlim_cur: v as libc::rlim_t,
        rlim_max: v as libc::rlim_t,
    };
    // SAFETY: setrlimit with a valid rlimit struct.
    if unsafe { libc::setrlimit(res, &lim) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Descriptors the scanner may hold at once: stdio, the socket, the one it
/// scans and a margin.
pub const MAX_FDS: u64 = 16;

/// Everything but the seccomp filter and the memory cap. `keep`: the
/// highest descriptor to keep (the socket).
pub fn harden(keep: i32) -> Result<(), String> {
    // SAFETY: getuid/geteuid have no preconditions.
    let (uid, euid) = unsafe { (libc::getuid(), libc::geteuid()) };
    if uid == 0 || euid == 0 {
        return Err("refusing to run as root: the agent starts the scanner as its own user".into());
    }
    // SAFETY: prctl with integer arguments.
    unsafe {
        if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
            return Err(format!(
                "PR_SET_NO_NEW_PRIVS: {}",
                io::Error::last_os_error()
            ));
        }
        if libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) != 0 {
            return Err(format!("PR_SET_DUMPABLE: {}", io::Error::last_os_error()));
        }
    }
    close_from(keep + 1);
    for (res, v, name) in [
        (libc::RLIMIT_CORE, 0, "RLIMIT_CORE"),
        (libc::RLIMIT_NPROC, 0, "RLIMIT_NPROC"),
        (libc::RLIMIT_NOFILE, MAX_FDS, "RLIMIT_NOFILE"),
    ] {
        setrlimit(res, v).map_err(|e| format!("{name}: {e}"))?;
    }
    Ok(())
}

/// Cap the address space (the configured read size and a margin).
pub fn limit_memory(bytes: u64) -> Result<(), String> {
    setrlimit(libc::RLIMIT_AS, bytes).map_err(|e| format!("RLIMIT_AS: {e}"))
}

/// Close every descriptor from `first` up (`close_range(2)`, else one by
/// one).
fn close_from(first: i32) {
    // SAFETY: close_range on a range of our own descriptors.
    let rc = unsafe { libc::syscall(libc::SYS_close_range, first as u32, u32::MAX, 0u32) };
    if rc != 0 {
        for fd in first..1024 {
            // SAFETY: closing a descriptor we may or may not hold.
            unsafe { libc::close(fd) };
        }
    }
}
