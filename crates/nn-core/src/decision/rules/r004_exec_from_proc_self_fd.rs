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
//! We require **both** signals (logical AND). External audit PROC-001
//! (NN-AUD-001) found both forgeable: the parent test accepted a parent
//! whose `comm` was `systemd` (any process sets its own with
//! `prctl(PR_SET_NAME)`), and the launcher test accepted any `argv[0]`
//! ending in `/systemd-executor` (the caller chooses `argv[0]`). Both now
//! read what the kernel executed: the executed file is the real
//! `systemd-executor` (exec sensor identity: a root-owned system tree, a
//! real file, not a memfd), and the parent is PID 1 or a `systemd --user`
//! manager by its own exec identity. In tracepoint mode, with no exec
//! identity, `argv[0]` must be an install path exactly and only PID 1
//! counts as the parent.

use nn_model::{Event, ResponseAction, Severity, Verdict};

use crate::decision::attack::{AttackRef, Tactic};
use crate::decision::{rules::build_verdict, Rule};
use crate::posture::host::PostureHost;

/// R004 rule. `lineage` resolves a `systemd --user` parent by what the
/// kernel executed for it (external audit PROC-001); without it (unit
/// tests) only PID 1 counts as systemd.
#[derive(Default)]
pub struct R004ExecFromProcSelfFd<H: PostureHost> {
    lineage: Option<crate::posture::lineage::AuthSessionTracker<H>>,
}

impl<H: PostureHost> R004ExecFromProcSelfFd<H> {
    pub fn new(lineage: crate::posture::lineage::AuthSessionTracker<H>) -> Self {
        Self {
            lineage: Some(lineage),
        }
    }

    /// True if the path looks like `/proc/self/fd/<n>` or
    /// `/proc/<pid>/fd/<n>`. Both forms are the canonical way to exec
    /// from a memfd or anonymous fd, which is a strong fileless-exec
    /// signal.
    fn is_proc_fd_path(path: &str) -> bool {
        // `/dev/fd` is a symlink to `/proc/self/fd` and is what glibc's
        // fexecve(3) actually passes to execve on a memfd (lab guest,
        // Ubuntu 24.04 / glibc 2.39: the exec surfaced as
        // `filename: "/dev/fd/4", comm: "memfd:nnx_memfd"` and R004
        // stayed silent). `/memfd:` is what execveat(AT_EMPTY_PATH)
        // reports. Both are the same fileless-exec signal.
        if let Some(after) = path.strip_prefix("/dev/fd/") {
            return !after.is_empty();
        }
        if path.starts_with("/memfd:") {
            return true;
        }
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

    /// Tracepoint mode (no exec identity): `argv[0]` must be one of the
    /// executor's install paths exactly. External audit PROC-001
    /// (NN-AUD-001): it used to be any string ending in
    /// `/systemd-executor`, and the caller chooses `argv[0]`.
    fn argv0_is_the_executor(argv: &[String]) -> bool {
        const EXECUTOR_PATHS: &[&str] = &[
            "/usr/lib/systemd/systemd-executor",
            "/lib/systemd/systemd-executor",
        ];
        argv.first()
            .is_some_and(|a| EXECUTOR_PATHS.contains(&a.as_str()))
    }

    /// LSM mode: the unlinked file reached through an fd is systemd's own
    /// executor — PID 1 holds it open across a systemd upgrade and keeps
    /// launching units from it until the next re-exec — a file named
    /// `systemd-executor` in a root-owned system tree.
    fn is_upgraded_executor(exe: &nn_model::ExeIdentity) -> bool {
        let path = exe.path_or("");
        let path = path.strip_suffix(" (deleted)").unwrap_or(path);
        path.rsplit('/').next() == Some("systemd-executor")
            && crate::posture::lineage::in_system_tree(path)
    }

    /// External audit PROC-001: systemd launched it — PID 1 (the system
    /// manager), or a `systemd --user` manager told by what the kernel
    /// executed for the parent, never by its `comm`, which the parent sets
    /// for itself with `prctl(PR_SET_NAME)`.
    fn parented_by_systemd(&self, ppid: u32) -> bool {
        ppid == 1
            || self.lineage.as_ref().is_some_and(|l| {
                l.exec_identity(ppid)
                    .is_some_and(|id| id.script.is_none() && id.is_client(&["systemd"]))
            })
    }

    /// Tracepoint mode: a `/proc/self/fd` exec that is the legitimate
    /// launch of a systemd unit (both signals).
    fn is_systemd_executor_launch(&self, ppid: u32, argv: &[String]) -> bool {
        Self::argv0_is_the_executor(argv) && self.parented_by_systemd(ppid)
    }
}

impl<H: PostureHost> Rule for R004ExecFromProcSelfFd<H> {
    fn id(&self) -> &'static str {
        "R004_ExecFromProcSelfFd"
    }
    fn name(&self) -> &'static str {
        "Exec from /proc/<pid>/fd/* (memfd)"
    }
    fn category(&self) -> &'static str {
        "execution"
    }
    fn attack(&self) -> &'static [AttackRef] {
        const ATTACK: &[AttackRef] = &[AttackRef::new(Tactic::Stealth, "T1620")];
        ATTACK
    }

    fn evaluate(&self, event: &Event) -> Option<Verdict> {
        let Event::ProcessSpawn {
            filename,
            ppid,
            argv,
            exe,
            ..
        } = event
        else {
            return None;
        };
        use common::wire::exe::exe_flags::{DELETED, KNOWN, MEMFD};
        let via_fd = Self::is_proc_fd_path(filename);
        if exe.has(KNOWN) {
            // External audit PROC-001 (NN-AUD-001): with the exec sensor's
            // identity, what the kernel executed decides, not the caller's
            // path, argv[0] or parent name. Fileless code is a memfd, or an
            // unlinked file (O_TMPFILE) reached through an fd. A real file
            // reached through an fd is not fileless: systemd-executor's
            // fexecve of every unit is one, and the other rules judge any
            // such file on its canonical path (review 61).
            let fileless =
                exe.has(MEMFD) || (via_fd && exe.has(DELETED) && !Self::is_upgraded_executor(exe));
            if !fileless {
                return None;
            }
        } else {
            // Tracepoint mode: the path heuristic. Tappa 10.6.5: systemd's
            // fexecve(/proc/self/fd/N) of systemd-executor launches every
            // unit; it is exempt, on argv[0] exactly and a systemd parent.
            if !via_fd || self.is_systemd_executor_launch(*ppid, argv) {
                return None;
            }
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
    // R08b (lab PR 251): on the portable test host.
    use crate::posture::host::testing::TestHost as H;
    type R004ExecFromProcSelfFd = super::R004ExecFromProcSelfFd<H>;
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
            start_ns: 0,
            parent_is_kthread: false,
            exe: Default::default(),
            argv_truncated: false,
            filename_truncated: false,
            stdio: Default::default(),
        }
    }

    /// Review 61: a memfd reached through a symlink to `/proc/self/fd/N`
    /// carries no fd path, but the kernel flags the file itself.
    #[test]
    fn fires_on_a_memfd_whatever_path_reached_it() {
        use crate::decision::rules::testutil::spawn_exe;
        use common::wire::exe::exe_flags;
        let event = spawn_exe("x", "/usr/local/bin/notes", "", exe_flags::MEMFD);
        let v = R004ExecFromProcSelfFd::default()
            .evaluate(&event)
            .expect("fires");
        assert_eq!(v.action, ResponseAction::KillProcessTree);
        // a deleted file alone is no memfd (an upgraded binary re-exec'd)
        let event = spawn_exe("x", "/usr/bin/x", "/usr/bin/x", exe_flags::DELETED);
        assert!(R004ExecFromProcSelfFd::default().evaluate(&event).is_none());
    }

    #[test]
    fn fires_on_proc_self_fd() {
        let v = R004ExecFromProcSelfFd::default()
            .evaluate(&spawn("memexec", "/proc/self/fd/3"))
            .expect("fires");
        assert_eq!(v.severity, Severity::Critical);
        assert_eq!(v.action, ResponseAction::KillProcessTree);
    }

    #[test]
    fn ignores_normal_paths() {
        assert!(R004ExecFromProcSelfFd::default()
            .evaluate(&spawn("ls", "/usr/bin/ls"))
            .is_none());
        // /proc/<pid>/status is not an exec target.
        assert!(R004ExecFromProcSelfFd::default()
            .evaluate(&spawn("x", "/proc/123/status"))
            .is_none());
    }

    #[test]
    fn matches_proc_pid_fd_form_too() {
        assert!(R004ExecFromProcSelfFd::default()
            .evaluate(&spawn("x", "/proc/4242/fd/7"))
            .is_some());
        // Empty fd number does not count.
        assert!(R004ExecFromProcSelfFd::default()
            .evaluate(&spawn("x", "/proc/self/fd/"))
            .is_none());
        // Non-numeric pid does not count.
        assert!(R004ExecFromProcSelfFd::default()
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
            R004ExecFromProcSelfFd::default().evaluate(&ev).is_none(),
            "legitimate systemd-executor launch must not fire R004"
        );
    }

    /// `--user` manager launch: the parent is a `systemd --user` manager,
    /// told by what the kernel executed for it, not by its comm — exempt.
    #[test]
    fn exempts_systemd_executor_user_manager() {
        let tmp = tempfile::TempDir::new().unwrap();
        let lineage = crate::posture::lineage::AuthSessionTracker::<H>::new(tmp.path());
        lineage.ingest_spawn(2001, 1, "/usr/lib/systemd/systemd", 1);
        let ev = spawn_exec(
            "/proc/self/fd/4",
            2001,
            "systemd",
            &["/lib/systemd/systemd-executor", "--deserialize", "12"],
        );
        assert!(R004ExecFromProcSelfFd::new(lineage).evaluate(&ev).is_none());
    }

    /// External audit PROC-001 (NN-AUD-001): a parent that only NAMES
    /// itself systemd (prctl) does not exempt the exec.
    #[test]
    fn forged_parent_comm_systemd_does_not_exempt() {
        let tmp = tempfile::TempDir::new().unwrap();
        let lineage = crate::posture::lineage::AuthSessionTracker::<H>::new(tmp.path());
        lineage.ingest_spawn(7777, 1, "/usr/bin/python3.12", 1);
        let ev = spawn_exec(
            "/proc/self/fd/3",
            7777,
            "systemd",
            &["/usr/lib/systemd/systemd-executor"],
        );
        assert!(R004ExecFromProcSelfFd::new(lineage).evaluate(&ev).is_some());
        assert!(R004ExecFromProcSelfFd::default().evaluate(&ev).is_some());
    }

    /// External audit PROC-001: in tracepoint mode `argv[0]` must be an
    /// install path exactly, not any path ending in `/systemd-executor`.
    #[test]
    fn executor_argv0_outside_canonical_path_does_not_exempt() {
        let ev = spawn_exec(
            "/proc/self/fd/3",
            1,
            "systemd",
            &["/home/u/x/systemd-executor"],
        );
        assert!(R004ExecFromProcSelfFd::default().evaluate(&ev).is_some());
    }

    /// External audit PROC-001: with the exec sensor's identity, what the
    /// kernel executed decides. The lab (Ubuntu 24.04, systemd 255) showed
    /// why the executor must not be an exemption here: every unit start is
    /// systemd-executor fexecve'd from an fd, a real file. Fileless code is
    /// a memfd, or an unlinked file reached through an fd.
    #[test]
    fn executed_file_decides_in_lsm_mode() {
        use common::wire::exe::exe_flags::{DELETED, KNOWN, MEMFD, TASK_ROOT};
        let ev = |filename: &str, exe_path: &str, flags: u32| {
            let mut e = spawn_exec(filename, 7777, "bash", &["anything"]);
            if let Event::ProcessSpawn { exe, .. } = &mut e {
                exe.path = exe_path.to_string();
                exe.flags = flags | KNOWN;
            }
            e
        };
        let r = R004ExecFromProcSelfFd::default();
        // systemd's launch of every unit: a real file through an fd
        let unit = ev(
            "/proc/self/fd/9",
            "/usr/lib/systemd/systemd-executor",
            TASK_ROOT,
        );
        assert!(r.evaluate(&unit).is_none());
        // the same after a systemd upgrade: PID 1 holds the old, unlinked one
        let upgraded = ev(
            "/proc/self/fd/9",
            "/usr/lib/systemd/systemd-executor (deleted)",
            DELETED,
        );
        assert!(r.evaluate(&upgraded).is_none());
        // fileless: a memfd (whatever argv[0] and parent claim), or an
        // unlinked file reached through an fd (O_TMPFILE)
        assert!(r
            .evaluate(&ev("/proc/self/fd/3", "/memfd:x (deleted)", MEMFD))
            .is_some());
        assert!(r
            .evaluate(&ev("/proc/self/fd/3", "/tmp/#1234 (deleted)", DELETED))
            .is_some());
        assert!(r
            .evaluate(&ev(
                "/proc/self/fd/3",
                "/tmp/systemd-executor (deleted)",
                DELETED
            ))
            .is_some());
        // a real file through an fd is judged on its path by the other rules
        assert!(r
            .evaluate(&ev("/proc/self/fd/3", "/tmp/payload", 0))
            .is_none());
    }

    /// `bash exec -a foo /proc/self/fd/3` from an arbitrary user shell:
    /// forged argv[0], parent is the shell (not systemd) → must FIRE.
    #[test]
    fn fires_on_user_shell_proc_fd_exec() {
        let ev = spawn_exec("/proc/self/fd/3", 7777, "bash", &["foo"]);
        let v = R004ExecFromProcSelfFd::default()
            .evaluate(&ev)
            .expect("fires");
        assert_eq!(v.severity, Severity::Critical);
        assert_eq!(v.action, ResponseAction::KillProcessTree);
    }

    /// Genuine T1620 fileless exec (memfd_create + execve) from a
    /// malicious loader → must FIRE.
    #[test]
    fn fires_on_memfd_fileless_exec() {
        let ev = spawn_exec("/proc/self/fd/3", 9001, "loader", &["/proc/self/fd/3"]);
        assert!(R004ExecFromProcSelfFd::default().evaluate(&ev).is_some());
    }

    /// What glibc's fexecve(3) really passes on Ubuntu 24.04: the
    /// `/dev/fd/N` symlink form (lab guest 2026-10-08, memfd exec seen as
    /// `filename: "/dev/fd/4"`). Must fire like `/proc/self/fd/N`.
    #[test]
    fn fires_on_dev_fd_form() {
        let ev = spawn_exec("/dev/fd/4", 9001, "loader", &["nnx_memfd"]);
        assert!(R004ExecFromProcSelfFd::default().evaluate(&ev).is_some());
        assert!(!R004ExecFromProcSelfFd::is_proc_fd_path("/dev/fd/"));
        assert!(!R004ExecFromProcSelfFd::is_proc_fd_path("/dev/fdx/1"));
    }

    /// execveat(fd, "", AT_EMPTY_PATH) on a memfd surfaces as
    /// `/memfd:<name> (deleted)`.
    #[test]
    fn fires_on_memfd_pseudo_path() {
        let ev = spawn_exec("/memfd:payload (deleted)", 9001, "loader", &["payload"]);
        assert!(R004ExecFromProcSelfFd::default().evaluate(&ev).is_some());
    }

    /// Security property: `ppid == 1` ALONE does not grant the exemption.
    /// A daemon re-parented to init that memfd-execs a non-executor
    /// binary must still FIRE (the AND with argv[0] is what protects us).
    #[test]
    fn ppid_one_alone_does_not_exempt() {
        let ev = spawn_exec("/proc/self/fd/5", 1, "systemd", &["/tmp/payload"]);
        assert!(
            R004ExecFromProcSelfFd::default().evaluate(&ev).is_some(),
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
            R004ExecFromProcSelfFd::default().evaluate(&ev).is_some(),
            "executor argv[0] without a systemd parent must still fire"
        );
    }

    #[test]
    fn executor_argv0_matcher_is_exact() {
        let argv = |a: &str| vec![a.to_string()];
        assert!(R004ExecFromProcSelfFd::argv0_is_the_executor(&argv(
            "/usr/lib/systemd/systemd-executor"
        )));
        assert!(R004ExecFromProcSelfFd::argv0_is_the_executor(&argv(
            "/lib/systemd/systemd-executor"
        )));
        assert!(!R004ExecFromProcSelfFd::argv0_is_the_executor(&argv(
            "/tmp/x/systemd-executor"
        )));
        assert!(!R004ExecFromProcSelfFd::argv0_is_the_executor(&argv(
            "/usr/bin/ls"
        )));
    }
}
