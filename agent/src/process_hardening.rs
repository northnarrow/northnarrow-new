//! Lab PR 216 (capability C23, static review C-43 / G-06): the agent leaves
//! no core dump and no readable memory.
//!
//! The agent holds its signing key, the admin quorum's state and the
//! chain heads in memory, and nothing made it non-dumpable: a crash under
//! `systemd-coredump` (or a `core_pattern` pipe) wrote that memory to disk,
//! and `/proc/<agent>/mem`, `environ` and `maps` followed the ordinary
//! ptrace rules for a root reader. [`forbid_core_dumps`] sets
//! `PR_SET_DUMPABLE` to 0 — the kernel then writes no core and closes
//! those files to any process without `CAP_SYS_PTRACE` — and
//! `RLIMIT_CORE` to 0, which the children it starts inherit. The units add
//! `LimitCORE=0`; the watchdog does the same at its start (`harden_self`).
//!
//! What still works: the agent reads its own `/proc/self` (same thread
//! group); the watchdog reads `/proc/<agent>/exe` with `CAP_SYS_PTRACE`
//! (its unit grants it) and through the `ptrace_access_check` hook, which
//! admits a protected caller; `pidfd_open`, `pidfd_send_signal`,
//! `waitid(P_PIDFD)` and `SO_PEERCRED` do not depend on dumpability. A
//! process the agent starts runs a new program, which resets it.

/// `PR_SET_DUMPABLE` 0 and `RLIMIT_CORE` 0 for this process. Call once at
/// the start of the daemon, before any key is loaded.
pub fn forbid_core_dumps() -> std::io::Result<()> {
    let none = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: setrlimit with a valid rlimit we own.
    if unsafe { libc::setrlimit(libc::RLIMIT_CORE, &none) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: plain prctl with integer arguments.
    if unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0u64, 0u64, 0u64, 0u64) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

/// `PR_GET_DUMPABLE`: whether this process may still dump core.
pub fn is_dumpable() -> bool {
    // SAFETY: plain prctl with integer arguments.
    unsafe { libc::prctl(libc::PR_GET_DUMPABLE, 0u64, 0u64, 0u64, 0u64) != 0 }
}

/// This process's `RLIMIT_CORE` (soft, hard).
pub fn core_limit() -> std::io::Result<(u64, u64)> {
    let mut lim = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: getrlimit into a valid rlimit we own.
    if unsafe { libc::getrlimit(libc::RLIMIT_CORE, &mut lim) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok((lim.rlim_cur, lim.rlim_max))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// In a forked child (the test process itself keeps its settings): the
    /// child leaves `forbid_core_dumps` non-dumpable with a core limit of
    /// 0, which it cannot raise again without `CAP_SYS_RESOURCE`.
    #[test]
    fn the_agent_is_not_dumpable_after_the_call() {
        // SAFETY: the child calls only prctl, getrlimit, setrlimit and
        // _exit (no allocation on the success path) before it exits.
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0, "fork: {}", std::io::Error::last_os_error());
        if pid == 0 {
            let code = if forbid_core_dumps().is_err() {
                11
            } else if is_dumpable() {
                12
            } else if !matches!(core_limit(), Ok((0, 0))) {
                13
            } else {
                let raise = libc::rlimit {
                    rlim_cur: 1 << 20,
                    rlim_max: 1 << 20,
                };
                // SAFETY: as above.
                let raised = unsafe { libc::setrlimit(libc::RLIMIT_CORE, &raise) } == 0;
                // root keeps CAP_SYS_RESOURCE and may raise it; the
                // dumpable flag is what keeps the core away then.
                // SAFETY: geteuid has no preconditions.
                if raised && unsafe { libc::geteuid() } != 0 {
                    14
                } else {
                    0
                }
            };
            // SAFETY: leave the forked child without running the test
            // harness's destructors.
            unsafe { libc::_exit(code) };
        }
        let mut status = 0;
        // SAFETY: wait for the child we forked.
        let r = unsafe { libc::waitpid(pid, &mut status, 0) };
        assert_eq!(r, pid);
        assert!(libc::WIFEXITED(status), "child status {status:#x}");
        assert_eq!(
            libc::WEXITSTATUS(status),
            0,
            "11 call failed, 12 still dumpable, 13 core limit not 0, 14 limit raised again"
        );
    }
}
