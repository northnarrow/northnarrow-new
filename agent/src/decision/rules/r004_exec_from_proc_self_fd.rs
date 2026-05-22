//! R004 — memfd-style exec via `/proc/self/fd/*` or `/proc/<pid>/fd/*`.
//!
//! # systemd-executor exemption (Tappa 10.6.5)
//!
//! On systemd ≥ 254 (e.g. Ubuntu 24.04 / systemd 255) **every** service is
//! launched by `systemd-executor`, which `fexecve()`s an `O_CLOEXEC` file
//! descriptor. The kernel therefore reports the exec target as
//! `/proc/self/fd/<n>` — byte-for-byte identical, by path alone, to a
//! genuine memfd/fileless exec. Without an exemption R004 fires on the
//! launch of *every* systemd unit, KillProcessTree-ing the agent's own
//! systemd-managed restart, its watchdog, and any service started after
//! the agent. (See issue: R004 false-positive on systemd-executor.)
//!
//! The distinguishing signal is the *provenance* of the exec, not the
//! `/proc/self/fd` path: a legitimate systemd launch is (a) parented by
//! systemd — `ppid == 1` for system units, or a `systemd` user-manager —
//! **and** (b) carries the real `systemd-executor` binary in `argv[0]`
//! (systemd sets argv[0] to the on-disk executor path before the fexecve).
//!
//! We require **both** signals (logical AND), deliberately tighter than a
//! plain "exempt if `ppid == 1`": a daemon merely re-parented to init
//! (`ppid == 1`) must not be able to memfd-exec freely, and a forged
//! `argv[0]` alone (`exec -a /usr/lib/systemd/systemd-executor …`) is
//! rejected because systemd is not its parent. The residual evasion —
//! an attacker who both re-parents to PID 1 *and* forges argv[0] to the
//! executor path — is narrow and is the domain of the Tappa 10.6 argv +
//! parent-ancestry correlation work / fd-target resolution; it is tracked
//! separately and not closed here.

use common::{Event, ResponseAction, Severity, Verdict};

use crate::decision::{rules::build_verdict, Rule};

pub struct R004ExecFromProcSelfFd;

impl R004ExecFromProcSelfFd {
    /// True if the path looks like `/proc/self/fd/<n>` or
    /// `/proc/<pid>/fd/<n>`. Both forms are the canonical way to exec
    /// from a memfd or anonymous fd, which is a strong fileless-exec
    /// signal.
    fn is_proc_fd_path(path: &str) -> bool {
        let rest = match path.strip_prefix("/proc/") {
            Some(r) => r,
            None => return false,
        };
        // /proc/self/fd/N
        if let Some(after_self) = rest.strip_prefix("self/fd/") {
            return !after_self.is_empty();
        }
        // /proc/<pid>/fd/N — first segment must be all-digits.
        let mut parts = rest.splitn(3, '/');
        let pid = parts.next().unwrap_or("");
        let fd_lit = parts.next().unwrap_or("");
        let after = parts.next().unwrap_or("");
        if !pid.is_empty()
            && pid.bytes().all(|b| b.is_ascii_digit())
            && fd_lit == "fd"
            && !after.is_empty()
        {
            return true;
        }
        false
    }

    /// True if `argv0` is the systemd service launcher binary. Matches the
    /// canonical install locations across distros (`/usr/lib/systemd/…`
    /// and the `/lib` symlink), keyed on the trailing path component so a
    /// merge-`/usr` or split-`/usr` layout both resolve.
    fn is_systemd_executor_path(argv0: &str) -> bool {
        argv0 == "/usr/lib/systemd/systemd-executor"
            || argv0 == "/lib/systemd/systemd-executor"
            || argv0.ends_with("/systemd-executor")
    }

    /// True when a `/proc/self/fd` exec is the legitimate launch of a
    /// systemd unit and must NOT be treated as fileless execution.
    ///
    /// Requires BOTH that systemd is the launching parent (`ppid == 1`,
    /// the system manager; or `parent_comm == "systemd"`, which also
    /// covers a `--user` manager) AND that `argv[0]` is the real
    /// `systemd-executor` binary. See the module docs for why this is an
    /// AND and not an OR.
    fn is_systemd_executor_launch(ppid: u32, parent_comm: &str, argv: &[String]) -> bool {
        let parented_by_systemd = ppid == 1 || parent_comm == "systemd";
        let argv0_is_executor = argv
            .first()
            .is_some_and(|a| Self::is_systemd_executor_path(a));
        parented_by_systemd && argv0_is_executor
    }
}

impl Rule for R004ExecFromProcSelfFd {
    fn id(&self) -> &'static str {
        "R004_ExecFromProcSelfFd"
    }
    fn name(&self) -> &'static str {
        "Exec from /proc/<pid>/fd/* (memfd)"
    }
    fn category(&self) -> &'static str {
        "execution"
    }

    fn evaluate(&self, event: &Event) -> Option<Verdict> {
        let Event::ProcessSpawn {
            filename,
            ppid,
            parent_comm,
            argv,
            ..
        } = event
        else {
            return None;
        };
        if !Self::is_proc_fd_path(filename) {
            return None;
        }
        // Tappa 10.6.5: systemd-executor launches every unit via
        // fexecve(/proc/self/fd/N); exempt the legitimate launcher so the
        // agent does not kill its own restart, the watchdog, or any other
        // systemd-managed service.
        if Self::is_systemd_executor_launch(*ppid, parent_comm, argv) {
            return None;
        }
        Some(build_verdict(
            self,
            event,
            ResponseAction::KillProcessTree,
            Severity::Critical,
            "memfd-style exec detected — fileless execution, highly suspicious",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decision::rules::testutil::spawn;

    /// Full-control spawn builder for the Tappa 10.6.5 exemption tests:
    /// the shared `spawn`/`spawn_full` helpers hardcode `ppid = 1`, but
    /// the exemption logic keys on `ppid`, `parent_comm` AND `argv`, so
    /// these tests need to vary all three independently.
    fn spawn_exec(filename: &str, ppid: u32, parent_comm: &str, argv: &[&str]) -> Event {
        Event::ProcessSpawn {
            pid: 4242,
            ppid,
            uid: 0,
            gid: 0,
            comm: "x".to_string(),
            filename: filename.to_string(),
            timestamp_ns: 42,
            argv: argv.iter().map(|s| s.to_string()).collect(),
            parent_comm: parent_comm.to_string(),
            parent_start_ns: 0,
        }
    }

    #[test]
    fn fires_on_proc_self_fd() {
        let v = R004ExecFromProcSelfFd
            .evaluate(&spawn("memexec", "/proc/self/fd/3"))
            .expect("fires");
        assert_eq!(v.severity, Severity::Critical);
        assert_eq!(v.action, ResponseAction::KillProcessTree);
    }

    #[test]
    fn ignores_normal_paths() {
        assert!(R004ExecFromProcSelfFd
            .evaluate(&spawn("ls", "/usr/bin/ls"))
            .is_none());
        // /proc/<pid>/status is not an exec target.
        assert!(R004ExecFromProcSelfFd
            .evaluate(&spawn("x", "/proc/123/status"))
            .is_none());
    }

    #[test]
    fn matches_proc_pid_fd_form_too() {
        assert!(R004ExecFromProcSelfFd
            .evaluate(&spawn("x", "/proc/4242/fd/7"))
            .is_some());
        // Empty fd number does not count.
        assert!(R004ExecFromProcSelfFd
            .evaluate(&spawn("x", "/proc/self/fd/"))
            .is_none());
        // Non-numeric pid does not count.
        assert!(R004ExecFromProcSelfFd
            .evaluate(&spawn("x", "/proc/abc/fd/3"))
            .is_none());
    }

    // ── Tappa 10.6.5 — systemd-executor exemption ──────────────────────

    /// `systemd-run sleep 10` and every other system unit: systemd
    /// (ppid 1) fexecve's systemd-executor → must be EXEMPT.
    #[test]
    fn exempts_systemd_executor_system_unit() {
        let ev = spawn_exec(
            "/proc/self/fd/9",
            1,
            "systemd",
            &["/usr/lib/systemd/systemd-executor", "--deserialize", "68"],
        );
        assert!(
            R004ExecFromProcSelfFd.evaluate(&ev).is_none(),
            "legitimate systemd-executor launch must not fire R004"
        );
    }

    /// `--user` manager launch: parent is a `systemd` user manager (comm
    /// "systemd") rather than PID 1 — still exempt.
    #[test]
    fn exempts_systemd_executor_user_manager() {
        let ev = spawn_exec(
            "/proc/self/fd/4",
            2001,
            "systemd",
            &["/lib/systemd/systemd-executor", "--deserialize", "12"],
        );
        assert!(R004ExecFromProcSelfFd.evaluate(&ev).is_none());
    }

    /// `bash exec -a foo /proc/self/fd/3` from an arbitrary user shell:
    /// forged argv[0], parent is the shell (not systemd) → must FIRE.
    #[test]
    fn fires_on_user_shell_proc_fd_exec() {
        let ev = spawn_exec("/proc/self/fd/3", 7777, "bash", &["foo"]);
        let v = R004ExecFromProcSelfFd.evaluate(&ev).expect("fires");
        assert_eq!(v.severity, Severity::Critical);
        assert_eq!(v.action, ResponseAction::KillProcessTree);
    }

    /// Genuine T1620 fileless exec (memfd_create + execve) from a
    /// malicious loader → must FIRE.
    #[test]
    fn fires_on_memfd_fileless_exec() {
        let ev = spawn_exec("/proc/self/fd/3", 9001, "loader", &["/proc/self/fd/3"]);
        assert!(R004ExecFromProcSelfFd.evaluate(&ev).is_some());
    }

    /// Security property: `ppid == 1` ALONE does not grant the exemption.
    /// A daemon re-parented to init that memfd-execs a non-executor
    /// binary must still FIRE (the AND with argv[0] is what protects us).
    #[test]
    fn ppid_one_alone_does_not_exempt() {
        let ev = spawn_exec("/proc/self/fd/5", 1, "systemd", &["/tmp/payload"]);
        assert!(
            R004ExecFromProcSelfFd.evaluate(&ev).is_some(),
            "ppid==1 without a real systemd-executor argv[0] must still fire"
        );
    }

    /// Security property: a forged `argv[0]` ALONE (executor path, but
    /// parented by a normal shell, not systemd) does not grant the
    /// exemption → must FIRE.
    #[test]
    fn forged_argv0_alone_does_not_exempt() {
        let ev = spawn_exec(
            "/proc/self/fd/3",
            7777,
            "bash",
            &["/usr/lib/systemd/systemd-executor"],
        );
        assert!(
            R004ExecFromProcSelfFd.evaluate(&ev).is_some(),
            "executor argv[0] without a systemd parent must still fire"
        );
    }

    #[test]
    fn executor_path_matcher() {
        assert!(R004ExecFromProcSelfFd::is_systemd_executor_path(
            "/usr/lib/systemd/systemd-executor"
        ));
        assert!(R004ExecFromProcSelfFd::is_systemd_executor_path(
            "/lib/systemd/systemd-executor"
        ));
        assert!(!R004ExecFromProcSelfFd::is_systemd_executor_path(
            "/tmp/systemd-executor-evil"
        ));
        assert!(!R004ExecFromProcSelfFd::is_systemd_executor_path(
            "/usr/bin/ls"
        ));
    }
}
