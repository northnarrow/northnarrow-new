//! R011 — Kernel-module tooling exec (Tappa 10.5 D2).
//!
//! MITRE T1547.006 (Boot or Logon Autostart Execution: Kernel
//! Modules and Extensions). A process whose `comm` is one of the
//! kernel-module load/manage tools is a kernel-rootkit / persistence
//! indicator. The design §7.1 trigger is "comm ∈ {insmod, modprobe,
//! kmod} & uid ≠ pkg-mgr context"; the package-manager-context guard
//! needs the parent `comm`, which `Event::ProcessSpawn` does not
//! carry (deferred to T10.6 per the accepted architectural limit), so
//! the false-positive guard is the operator `process-comm-allowlist`:
//! a site that loads modules from trusted automation adds the tool's
//! comm to the allowlist `.local` overlay.

use std::path::PathBuf;
use std::sync::Arc;

use common::{Event, ResponseAction, Severity, Verdict};

use crate::config::comm_allowlist::CommAllowlist;
use crate::decision::{rules::build_verdict, Rule};

/// Kernel-module load/manage tool comms (design §7.1).
const KMOD_TOOLS: &[&str] = &["insmod", "modprobe", "kmod"];

pub struct R011KernelModuleTooling {
    allowlist: Arc<CommAllowlist>,
    /// Root of /proc used to verify the parent is a real kernel thread
    /// (BUG-008' P-7). Defaults to `/proc`; tests inject a tempdir.
    proc_root: PathBuf,
}

impl R011KernelModuleTooling {
    pub fn new(allowlist: Arc<CommAllowlist>) -> Self {
        Self::new_with_proc(allowlist, PathBuf::from("/proc"))
    }

    /// Construct with an explicit /proc root. Production callers use
    /// [`Self::new`]; unit tests point at a fixture tree.
    pub fn new_with_proc(allowlist: Arc<CommAllowlist>, proc_root: PathBuf) -> Self {
        Self {
            allowlist,
            proc_root,
        }
    }

    /// BUG-008' P-7 — verify the parent is a real kernel thread via
    /// `/proc/<ppid>/exe`, which is kernel-resolved (not forgeable
    /// from userspace) and absent for kthreads. This replaces the
    /// P-2 `parent_comm.starts_with("kworker/")` check which was
    /// bypassable via `prctl(PR_SET_NAME, "kworker/0:1")` — `comm` is
    /// attacker-controllable (see posture/exempt.rs:15-26).
    ///
    /// Returns true only when we positively verify a kthread parent.
    /// FAILSAFE on any uncertainty (parent gone, permission error,
    /// unexpected ENOTDIR/EIO): return false, R011 fires. Better an
    /// over-fire on a benign kernel-driven modprobe than a missed
    /// rootkit install via comm spoofing.
    fn parent_is_kernel_thread(&self, ppid: u32) -> bool {
        use std::io::ErrorKind;
        let proc_dir = self.proc_root.join(ppid.to_string());
        if !proc_dir.exists() {
            // Parent gone / wrong path — cannot positively verify
            // kthread status. Fail-safe: not exempt.
            return false;
        }
        match std::fs::read_link(proc_dir.join("exe")) {
            // Userspace process — has a non-empty resolved path.
            Ok(target) => target.as_os_str().is_empty(),
            // ENOENT on /proc/<pid>/exe with /proc/<pid>/ present is
            // the canonical kernel-thread signal on Linux.
            Err(e) if e.kind() == ErrorKind::NotFound => true,
            // EACCES / EPERM / other — be conservative, fail-safe.
            Err(_) => false,
        }
    }
}

impl Rule for R011KernelModuleTooling {
    fn id(&self) -> &'static str {
        "R011_KernelModuleTooling"
    }
    fn name(&self) -> &'static str {
        "Kernel-module tooling exec"
    }
    fn category(&self) -> &'static str {
        "persistence"
    }

    fn evaluate(&self, event: &Event) -> Option<Verdict> {
        let Event::ProcessSpawn {
            comm,
            ppid,
            argv,
            parent_comm,
            ..
        } = event
        else {
            return None;
        };
        if !KMOD_TOOLS.contains(&comm.as_str()) {
            return None;
        }
        if self.allowlist.contains(comm) {
            return None;
        }
        // BUG-008' P-7 — kernel-driven module load exemption gated on
        // a non-forgeable signal: `/proc/<ppid>/exe` is absent for
        // kthreads (kernel-resolved, not attacker-controllable). The
        // earlier P-2 `parent_comm.starts_with("kworker/")` check was
        // bypassable via `prctl(PR_SET_NAME, "kworker/0:1")` and is
        // replaced here. See exempt.rs:15-26 for the established
        // codebase rationale (comm is forgeable; /proc/<pid>/exe is
        // not).
        if self.parent_is_kernel_thread(*ppid) {
            tracing::debug!(
                rule = "R011_KernelModuleTooling",
                ppid = *ppid,
                "skipping verdict — kernel-driven module load (parent is kthread per /proc)"
            );
            return None;
        }
        // Base detection fires on comm alone (graceful-degrade when the
        // T10.6 argv refit isn't deployed). argv/parent_comm add
        // confidence to the verdict reasoning (Q7 — additive, not a gate).
        let mut reasoning = String::from(
            "Kernel-module tooling (insmod/modprobe/kmod) exec — kernel \
             rootkit / persistence indicator (T1547.006); posture → ENGAGED",
        );
        if let Some(m) = argv
            .iter()
            .find(|a| a.contains("/lib/modules/") || a.ends_with(".ko"))
        {
            reasoning = format!("{reasoning} — argv confirms a real module load ({m})");
        }
        if !parent_comm.is_empty() {
            reasoning = format!("{reasoning}; parent={parent_comm}");
        }
        Some(build_verdict(
            self,
            event,
            ResponseAction::KillProcess,
            Severity::High,
            &reasoning,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decision::rules::testutil::{spawn, spawn_full};

    fn rule() -> R011KernelModuleTooling {
        R011KernelModuleTooling::new(Arc::new(CommAllowlist::default()))
    }

    #[test]
    fn fires_on_kmod_tooling() {
        for tool in KMOD_TOOLS {
            let v = rule()
                .evaluate(&spawn(tool, &format!("/usr/sbin/{tool}")))
                .unwrap_or_else(|| panic!("should fire on {tool}"));
            assert_eq!(v.rule_id, "R011_KernelModuleTooling");
            assert_eq!(v.action, ResponseAction::KillProcess);
            assert_eq!(v.severity, Severity::High);
        }
    }

    #[test]
    fn argv_module_image_enriches_reasoning() {
        let ev = spawn_full(
            "insmod",
            "/usr/sbin/insmod",
            0,
            &["insmod", "/lib/modules/6.8.0/evil.ko"],
            "bash",
        );
        let v = rule().evaluate(&ev).expect("fires");
        assert_eq!(v.severity, Severity::High); // base severity preserved
        assert!(v.reasoning.contains("argv confirms a real module load"));
        assert!(v.reasoning.contains("evil.ko"));
        assert!(v.reasoning.contains("parent=bash"));
    }

    #[test]
    fn fires_without_argv_graceful_degrade() {
        // Empty argv (D2 not deployed) — base predicate still fires, no
        // enrichment clause.
        let v = rule()
            .evaluate(&spawn("insmod", "/usr/sbin/insmod"))
            .expect("fires");
        assert_eq!(v.severity, Severity::High);
        assert!(!v.reasoning.contains("argv confirms"));
    }

    #[test]
    fn argv_without_matching_comm_does_not_fire() {
        // A `.ko` in argv but the comm isn't a kmod tool → no fire.
        let ev = spawn_full("ls", "/bin/ls", 0, &["ls", "/lib/modules/x.ko"], "bash");
        assert!(rule().evaluate(&ev).is_none());
    }

    #[test]
    fn ignores_non_kmod_tooling() {
        assert!(rule().evaluate(&spawn("ls", "/usr/bin/ls")).is_none());
        // A non-ProcessSpawn event never matches.
        assert!(rule()
            .evaluate(&spawn("modprobed-but-not-exact", "/usr/sbin/x"))
            .is_none());
    }

    #[test]
    fn allowlisted_comm_is_exempt() {
        let r = R011KernelModuleTooling::new(Arc::new(CommAllowlist::from_iter_owned([
            "modprobe".to_string(),
        ])));
        assert!(r
            .evaluate(&spawn("modprobe", "/usr/sbin/modprobe"))
            .is_none());
        // A different kmod tool not on the allowlist still fires.
        assert!(r.evaluate(&spawn("insmod", "/usr/sbin/insmod")).is_some());
    }

    // ── BUG-008' P-7 regression — kthread parent verified via /proc ──

    /// Build a `<root>/<pid>/` directory; if `exe_target` is `Some`,
    /// create the `exe` symlink pointing at it (userspace). If `None`,
    /// leave the exe entry absent (kthread — canonical Linux behaviour).
    fn fixture_proc_pid(root: &std::path::Path, pid: u32, exe_target: Option<&str>) {
        let pid_dir = root.join(pid.to_string());
        std::fs::create_dir_all(&pid_dir).expect("mkdir fake /proc/<pid>");
        if let Some(target) = exe_target {
            std::os::unix::fs::symlink(target, pid_dir.join("exe"))
                .expect("create fake /proc/<pid>/exe symlink");
        }
    }

    /// Build a ProcessSpawn event with explicit ppid (the existing
    /// testutil helpers hard-code ppid=1, which collides with PID 1
    /// on the host where the test runs).
    fn modprobe_spawn_with_ppid(ppid: u32, parent_comm: &str) -> Event {
        Event::ProcessSpawn {
            pid: 4242,
            ppid,
            uid: 0,
            gid: 0,
            comm: "modprobe".to_string(),
            filename: "/sbin/modprobe".to_string(),
            timestamp_ns: 1,
            argv: vec!["modprobe".to_string(), "snd-pcm".to_string()],
            parent_comm: parent_comm.to_string(),
            parent_start_ns: 0,
        }
    }

    #[test]
    fn real_kthread_parent_is_exempt() {
        // Legitimate kernel-driven modprobe: parent is a real kthread
        // (no /proc/<ppid>/exe symlink). Must NOT fire R011.
        let tmp = tempfile::tempdir().unwrap();
        const KWORKER_PID: u32 = 7;
        fixture_proc_pid(tmp.path(), KWORKER_PID, None); // kthread layout
        let r = R011KernelModuleTooling::new_with_proc(
            Arc::new(CommAllowlist::default()),
            tmp.path().to_path_buf(),
        );
        let ev = modprobe_spawn_with_ppid(KWORKER_PID, "kworker/0:1");
        assert!(
            r.evaluate(&ev).is_none(),
            "real kthread parent (no /proc/<ppid>/exe) must exempt R011"
        );
    }

    #[test]
    fn forged_kworker_comm_is_not_exempt() {
        // SECURITY regression guard for the bypass identified by
        // /security-review (confidence 9/10). An attacker who issues
        // `prctl(PR_SET_NAME, "kworker/0:1")` then forks+execs
        // modprobe presents parent_comm="kworker/..." but /proc/<ppid>/exe
        // resolves to a real userspace binary. R011 MUST fire.
        let tmp = tempfile::tempdir().unwrap();
        const ATTACKER_PID: u32 = 12345;
        fixture_proc_pid(tmp.path(), ATTACKER_PID, Some("/home/evil/rootkit_installer"));
        let r = R011KernelModuleTooling::new_with_proc(
            Arc::new(CommAllowlist::default()),
            tmp.path().to_path_buf(),
        );
        let ev = modprobe_spawn_with_ppid(ATTACKER_PID, "kworker/0:1");
        let v = r.evaluate(&ev).expect("R011 MUST fire on forged kworker comm");
        assert_eq!(v.action, ResponseAction::KillProcess);
        assert_eq!(v.severity, Severity::High);
    }

    #[test]
    fn normal_userspace_parent_fires() {
        // Sanity: a normal user invoking modprobe from a shell — parent
        // is bash/sh with a real /proc/<ppid>/exe — R011 must fire as
        // before. Regression guard that the new /proc gate doesn't
        // over-suppress.
        let tmp = tempfile::tempdir().unwrap();
        const SHELL_PID: u32 = 9999;
        fixture_proc_pid(tmp.path(), SHELL_PID, Some("/usr/bin/bash"));
        let r = R011KernelModuleTooling::new_with_proc(
            Arc::new(CommAllowlist::default()),
            tmp.path().to_path_buf(),
        );
        let ev = modprobe_spawn_with_ppid(SHELL_PID, "bash");
        assert!(r.evaluate(&ev).is_some(), "userspace parent must fire");
    }

    #[test]
    fn parent_gone_fails_safe_and_fires() {
        // FAILSAFE: parent exited between exec event and our /proc
        // check. /proc/<ppid>/ is absent — we cannot positively verify
        // a kthread, so R011 fires. Better an over-fire than miss a
        // rootkit because the attacker's process raced us.
        let tmp = tempfile::tempdir().unwrap();
        const GHOST_PID: u32 = 88888; // never created in fixture
        let r = R011KernelModuleTooling::new_with_proc(
            Arc::new(CommAllowlist::default()),
            tmp.path().to_path_buf(),
        );
        let ev = modprobe_spawn_with_ppid(GHOST_PID, "kworker/0:1");
        assert!(
            r.evaluate(&ev).is_some(),
            "vanished parent must fail-safe and fire (not silently exempt)"
        );
    }
}
