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
//!
//! ## Kernel-driven module load exemption (cluster 15.3)
//!
//! Genuine kernel-driven module loads — a kworker firing modprobe for
//! USB / Wi-Fi hardware probe during boot — must NOT trigger R011.
//! The signal is `parent_is_kthread`: a non-forgeable boolean BPF
//! reads from `parent->flags & PF_KTHREAD` at exec time and ships
//! into `Event::ProcessSpawn`. PF_KTHREAD is kernel-set on kthread
//! creation and impossible to clear from userspace; no `prctl`,
//! `unshare`, namespace trick, or ELF crafting flips it.
//!
//! Supersedes the P-7 `/proc/<ppid>/exe` absence check, which raced
//! against kthread reaping (kworker exited between exec and userland
//! readlink → over-fire on a benign modprobe) and required a
//! userspace `/proc` walk.
//!
//! Fail-secure: a BPF read that failed (offset drift, permission
//! issue, kernel without BTF) lands `parent_is_kthread = false`,
//! which falls through to the FIRE path — over-fire is acceptable,
//! under-fire (missing a forged-kworker rootkit install) is not.

use std::sync::Arc;

use common::{Event, ResponseAction, Severity, Verdict};

use crate::config::comm_allowlist::CommAllowlist;
use crate::decision::{rules::build_verdict, Rule};

/// Kernel-module load/manage tool comms (design §7.1).
const KMOD_TOOLS: &[&str] = &["insmod", "modprobe", "kmod"];

pub struct R011KernelModuleTooling {
    allowlist: Arc<CommAllowlist>,
}

impl R011KernelModuleTooling {
    pub fn new(allowlist: Arc<CommAllowlist>) -> Self {
        Self { allowlist }
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
            argv,
            parent_comm,
            parent_is_kthread,
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
        // Cluster 15.3 — kernel-driven module load exemption gated on
        // the non-forgeable BPF PF_KTHREAD signal (see module
        // doc-comment). Supersedes the P-7 userspace
        // `/proc/<ppid>/exe` race. A `false` value means EITHER "real
        // userspace parent" OR "BPF read failed" — both fall through
        // to FIRE (fail-secure: over-fire beats missing a forged
        // rootkit install).
        if *parent_is_kthread {
            tracing::debug!(
                rule = "R011_KernelModuleTooling",
                parent_comm = %parent_comm,
                "skipping verdict — kernel-driven module load (parent PF_KTHREAD set)"
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

    /// Build a ProcessSpawn with explicit `parent_is_kthread`. The
    /// existing `spawn` / `spawn_full` helpers default the flag to
    /// `false`; tests covering the cluster-15.3 exemption need to
    /// flip it on without leaking the boilerplate into every assert.
    fn modprobe_spawn(parent_comm: &str, parent_is_kthread: bool) -> Event {
        Event::ProcessSpawn {
            pid: 4242,
            ppid: 7,
            uid: 0,
            gid: 0,
            comm: "modprobe".to_string(),
            filename: "/sbin/modprobe".to_string(),
            timestamp_ns: 1,
            argv: vec!["modprobe".to_string(), "snd-pcm".to_string()],
            parent_comm: parent_comm.to_string(),
            parent_start_ns: 0,
            parent_is_kthread,
        }
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

    // ─── Cluster 15.3 — PF_KTHREAD signal regression suite ──────────
    //
    // The key invariant being defended: PF_KTHREAD is a kernel-set
    // flag that userspace cannot forge, so a `comm = "kworker/0:1"`
    // claim WITHOUT the flag must STILL fire (the security-critical
    // guard inherited from the original P-7 fix). The flag is the
    // ONLY exemption path; without it, R011 always fires.

    /// Real kernel-thread parent (PF_KTHREAD set): legitimate
    /// kworker→modprobe during USB / hardware-probe boot. R011 MUST
    /// be exempt. This is the over-fire the old P-7 /proc race
    /// caused (kworker reaped before userland readlink → fail-safe
    /// FIRE on a benign modprobe). Now gone.
    #[test]
    fn real_kthread_parent_is_exempt() {
        let ev = modprobe_spawn("kworker/u8:3", true);
        assert!(
            rule().evaluate(&ev).is_none(),
            "real kthread parent (PF_KTHREAD set) must exempt R011"
        );
    }

    /// SECURITY-CRITICAL: forged kworker `comm` (attacker calls
    /// `prctl(PR_SET_NAME, "kworker/0:1")` then forks+execs modprobe)
    /// but PF_KTHREAD is NOT set (kernel-managed; impossible to flip
    /// from userspace). R011 MUST fire — this is the bypass the
    /// original P-7 fix closed, and the cluster-15.3 refactor MUST
    /// preserve it.
    #[test]
    fn forged_kworker_comm_without_pf_kthread_is_not_exempt() {
        let ev = modprobe_spawn("kworker/0:1", false);
        let v = rule()
            .evaluate(&ev)
            .expect("R011 MUST fire on forged kworker comm (no PF_KTHREAD)");
        assert_eq!(v.action, ResponseAction::KillProcess);
        assert_eq!(v.severity, Severity::High);
    }

    /// Sanity: normal userspace parent (bash invoking modprobe).
    /// PF_KTHREAD is false → R011 fires as expected. Regression
    /// guard that the new gate doesn't over-suppress.
    #[test]
    fn normal_userspace_parent_fires() {
        let ev = modprobe_spawn("bash", false);
        assert!(
            rule().evaluate(&ev).is_some(),
            "userspace parent (bash) must fire"
        );
    }

    /// FAIL-SECURE: BPF read of parent->flags failed (offset drift /
    /// older BPF / kernel without BTF). The wire field decodes to
    /// `false`, which falls through to FIRE. Documents the
    /// fail-secure contract: missing signal != silent exemption.
    #[test]
    fn flag_unavailable_fails_secure_and_fires() {
        // `parent_is_kthread = false` covers both "real userspace
        // parent" AND "BPF couldn't read the flag" — same code path,
        // same FIRE outcome. This is exactly the safety guarantee.
        let ev = modprobe_spawn("", false); // empty parent_comm models BPF best-effort failure
        assert!(
            rule().evaluate(&ev).is_some(),
            "missing PF_KTHREAD signal must fail-secure and fire"
        );
    }
}
