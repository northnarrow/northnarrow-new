//! R011 — Kernel-module tooling exec (Tappa 10.5 D2).
//!
//! MITRE T1547.006 (Boot or Logon Autostart Execution: Kernel
//! Modules and Extensions). A process whose `comm` is one of the
//! kernel-module load/manage tools is a kernel-rootkit / persistence
//! indicator. The design §7.1 trigger is "comm ∈ {insmod, modprobe,
//! kmod} & uid ≠ pkg-mgr context". External audit PROC-008: the
//! package-manager context is the `process-comm-allowlist` read as a
//! list of trusted ACTORS — a root exec of a system-tree kmod tool whose
//! lineage holds one (DKMS running modprobe under apt or dpkg) is
//! recorded instead of killed ([`super::judge_actor`]); an entry naming
//! the tool itself still exempts it everywhere.
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
//!
//! Lab PR 166: a copy run from a staging directory is killed with its
//! tree, as R001..R003 would ([`super::tool_kill`]); the tool anywhere
//! else keeps the single-process kill.
//!
//! ## What is loaded, not the tool's name (lot 279)
//!
//! The exec is judged on what it loads ([`super::module_request`]): the
//! system's tool asked for module names that resolve, as kmod resolves
//! them, to files of the running kernel's tree that a package installed
//! (DKMS built, or the kernel's `modules.order` lists on a host without a
//! package database), unchanged since, signed when the kernel enforces
//! signatures — or an invocation that inserts nothing — is RECORDED, High,
//! T1547.006, no kill: rootful podman's `modprobe` of its netfilter
//! modules was killed (lot 275's lab). Anything else is killed as before:
//! `insmod` of a file, `modprobe` of a path, a tree, configuration or
//! version of the caller's, a name nothing resolves, a module file no
//! package installed or changed since, a copy of the tool, an argv not
//! read whole. The load itself stays R018's, on the file the kernel reads.

use std::sync::Arc;

use nn_model::{Event, ResponseAction, Severity, Verdict};

use crate::config::comm_allowlist::CommAllowlist;
use crate::config::comm_allowlist::Judgement;
use crate::decision::attack::{AttackRef, Tactic};
use crate::decision::host::DecisionHost;
use crate::decision::rules::module_request::{Assessment, ModuleRequests, KMOD_TOOLS};
use crate::decision::{rules::build_verdict, Rule};

pub struct R011KernelModuleTooling<H: DecisionHost> {
    allowlist: Arc<CommAllowlist<H>>,
    /// Lot 279: what the exec loads (the exec pump's assessment).
    requests: ModuleRequests<H>,
}

impl<H: DecisionHost> R011KernelModuleTooling<H> {
    pub fn new(allowlist: Arc<CommAllowlist<H>>) -> Self {
        Self::with_requests(allowlist, ModuleRequests::default())
    }

    /// Lot 279: with the module requests of a host root of the caller's
    /// (a fixture tree in tests).
    pub fn with_requests(allowlist: Arc<CommAllowlist<H>>, requests: ModuleRequests<H>) -> Self {
        Self {
            allowlist,
            requests,
        }
    }
}

impl<H: DecisionHost> Rule for R011KernelModuleTooling<H> {
    fn id(&self) -> &'static str {
        "R011_KernelModuleTooling"
    }
    fn name(&self) -> &'static str {
        "Kernel-module tooling exec"
    }
    fn category(&self) -> &'static str {
        "persistence"
    }
    fn attack(&self) -> &'static [AttackRef] {
        const ATTACK: &[AttackRef] = &[AttackRef::new(Tactic::Persistence, "T1547.006")];
        ATTACK
    }

    fn evaluate(&self, event: &Event) -> Option<Verdict> {
        let Event::ProcessSpawn {
            pid,
            comm,
            filename,
            exe,
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
        // External audit NETR-003 class: the allowlist judged on what the
        // kernel executed, not on the comm the process chose.
        let judgement = super::judge_spawn(&self.allowlist, event);
        if judgement == Judgement::Allowed {
            return None;
        }
        // Cluster 15.3 — the kernel-driven-load exemption turns ENTIRELY
        // on the non-forgeable BPF PF_KTHREAD signal (see module
        // doc-comment), superseding the P-7 `/proc/<ppid>/exe` race. A
        // `false` value means EITHER "real userspace parent" OR "BPF
        // read failed" — both fall through to FIRE (fail-secure:
        // over-fire beats missing a forged rootkit install).
        //
        // Emit ONE dedicated, greppable decision line on BOTH outcomes
        // so the journal always records WHY R011 did or didn't fire for
        // a kmod-tooling exec. This is the signal that was invisible the
        // night a stale .o silently zeroed `parent_is_kthread` and R011
        // over-fired on benign kworker→modprobe: with this line the same
        // incident reads as `parent_is_kthread=false decision=fire` at a
        // glance under `RUST_LOG=…=debug`. Debug level keeps the
        // (potentially many) boot-time hardware-probe modprobe execs out
        // of the default journal while staying one flag away when
        // diagnosing.
        let decision = if *parent_is_kthread {
            "exempt_kernel_thread"
        } else {
            "fire"
        };
        tracing::debug!(
            rule = "R011_KernelModuleTooling",
            event = "r011_kthread_decision",
            pid = *pid,
            comm = %nn_model::log_escape::Escaped(comm),
            parent_comm = %nn_model::log_escape::Escaped(parent_comm),
            parent_is_kthread = *parent_is_kthread,
            decision,
            "R011 kernel-module-tooling exec: PF_KTHREAD parent-origin decision"
        );
        if *parent_is_kthread {
            return None;
        }
        // Lot 279: judged on what the exec loads, not on the tool's name.
        // Recorded (High, no kill) when every module it loads is vouched
        // for or it inserts none; killed as before otherwise.
        let assessment = self.requests.of(event);
        let image = exe.path_or(filename);
        let (action, mut reasoning) = match &assessment {
            Assessment::Vouched(what) => (
                ResponseAction::Log,
                format!(
                    "Kernel-module tooling ({comm}) exec loading modules of the running \
                     kernel's tree, each vouched for: {what} — recorded, not killed (lot 279: \
                     judged on what is loaded; the load itself is R018's) (T1547.006)"
                ),
            ),
            Assessment::LoadsNothing(what) => (
                ResponseAction::Log,
                format!(
                    "Kernel-module tooling ({comm}) exec that inserts no module ({what}) — \
                     recorded, not killed (lot 279) (T1547.006)"
                ),
            ),
            Assessment::NotVouched(why) => (
                super::tool_kill(image),
                format!(
                    "Kernel-module tooling (insmod/modprobe/kmod) exec — kernel rootkit / \
                     persistence indicator (T1547.006); posture → ENGAGED — not vouched for: \
                     {why}"
                ),
            ),
        };
        if !parent_comm.is_empty() {
            reasoning = format!("{reasoning}; parent={parent_comm}");
        }
        // External audit PROC-008: and on the program's lineage.
        Some(super::judge_actor(
            &self.allowlist,
            event,
            judgement.apply(
                build_verdict(self, event, action, Severity::High, &reasoning),
                comm,
            ),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    // R08b (lab PR 251): on the portable test host.
    use crate::posture::host::testing::TestHost as H;
    type CommAllowlist = crate::config::comm_allowlist::CommAllowlist<H>;
    type R011KernelModuleTooling = super::R011KernelModuleTooling<H>;
    use crate::decision::rules::testutil::{spawn, spawn_full};
    use nn_model::ResponseAction;

    type ModuleRequests = crate::decision::rules::module_request::ModuleRequests<H>;
    use crate::decision::rules::module_request::fixture::{exec, modprobe, HostTree};

    /// Lot 279: on a host root with nothing to read (no kernel release, no
    /// module tree): every name it is asked for is unresolved — the rule
    /// never reads the test host's own `/lib/modules`.
    fn rule() -> R011KernelModuleTooling {
        R011KernelModuleTooling::with_requests(
            Arc::new(CommAllowlist::default()),
            ModuleRequests::new("/nonexistent-root"),
        )
    }

    /// Lot 279: on `t`.
    fn rule_on(t: &HostTree) -> R011KernelModuleTooling {
        R011KernelModuleTooling::with_requests(
            Arc::new(CommAllowlist::default()),
            ModuleRequests::new(t.root()),
        )
    }

    /// A distribution kernel's netfilter, overlay and dummy modules,
    /// packaged, and a module copied into the tree by hand.
    fn distro_host() -> HostTree {
        let t = HostTree::new();
        let nf = "kernel/net/netfilter/nf_tables.ko";
        let nfnl = "kernel/net/netfilter/nfnetlink.ko";
        let ipt = "kernel/net/ipv4/netfilter/ip_tables.ko";
        let xt = "kernel/net/netfilter/x_tables.ko";
        let brnf = "kernel/net/bridge/br_netfilter.ko";
        let br = "kernel/net/bridge/bridge.ko";
        let stp = "kernel/net/802/stp.ko";
        let ovl = "kernel/fs/overlayfs/overlay.ko";
        let dummy = "kernel/drivers/net/dummy.ko";
        t.module(nfnl, &[], true)
            .module(nf, &[nfnl], true)
            .module(xt, &[], true)
            .module(ipt, &[xt], true)
            .module(stp, &[], true)
            .module(br, &[stp], true)
            .module(brnf, &[br, stp], true)
            .module(ovl, &[], true)
            .module(dummy, &[], true)
            .module("kernel/drivers/misc/rk.ko", &[], true)
            .packaged(
                "linux-modules-6.8.0-1-generic",
                &[nf, nfnl, ipt, xt, brnf, br, stp, ovl, dummy],
            );
        t
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
            start_ns: 0,
            parent_is_kthread,
            exe: Default::default(),
            argv_truncated: false,
            filename_truncated: false,
            stdio: Default::default(),
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

    /// Lab PR 166: a staged copy is the payload itself and is killed with
    /// its tree; the system's tool keeps the single-process kill.
    #[test]
    fn r011_staged_copy_kills_the_process_tree() {
        for dir in ["/tmp/", "/var/tmp/", "/dev/shm/"] {
            let path = format!("{dir}insmod");
            let v = rule().evaluate(&spawn("insmod", &path)).expect("fires");
            assert_eq!(v.action, ResponseAction::KillProcessTree, "{path}");
        }
        for path in ["/usr/sbin/insmod", "/home/alice/insmod"] {
            let v = rule().evaluate(&spawn("insmod", path)).expect("fires");
            assert_eq!(v.action, ResponseAction::KillProcess, "{path}");
        }
    }

    /// Lot 279: an insmod of a file is killed, the file named.
    #[test]
    fn insmod_of_a_file_is_killed_naming_it() {
        let ev = spawn_full(
            "insmod",
            "/usr/sbin/insmod",
            0,
            &["insmod", "/lib/modules/6.8.0/evil.ko"],
            "bash",
        );
        let v = rule().evaluate(&ev).expect("fires");
        assert_eq!(v.severity, Severity::High); // base severity preserved
        assert_eq!(v.action, ResponseAction::KillProcess);
        assert!(
            v.reasoning.contains("insmod loads the file"),
            "{}",
            v.reasoning
        );
        assert!(v.reasoning.contains("evil.ko"));
        assert!(v.reasoning.contains("parent=bash"));
    }

    #[test]
    fn fires_without_argv_graceful_degrade() {
        // Empty argv (not read by the kernel): nothing was checked — the
        // kill, as before.
        let v = rule()
            .evaluate(&spawn("insmod", "/usr/sbin/insmod"))
            .expect("fires");
        assert_eq!(v.severity, Severity::High);
        assert_eq!(v.action, ResponseAction::KillProcess);
        assert!(v.reasoning.contains("argv was not read"), "{}", v.reasoning);
    }

    // ─── Lot 279 — judged on what is loaded ─────────────────────────

    /// Lot 275's lab (W5, Ubuntu 22.04): rootful podman's netfilter
    /// modprobe was killed. The container runtimes' and xtables' shapes —
    /// module names of the running kernel's packaged tree — are recorded,
    /// High, T1547.006, no kill.
    #[test]
    fn container_runtimes_modprobe_of_packaged_modules_is_recorded_not_killed() {
        let t = distro_host();
        let r = rule_on(&t);
        for e in [
            // libxtables' xtables_insmod: argv[0] the kernel's modprobe path
            modprobe(&["ip_tables", "-q"]),
            // docker / libnetwork
            modprobe(&["-va", "bridge", "br_netfilter"]),
            exec(
                "/usr/sbin/modprobe",
                "/usr/bin/kmod",
                &["modprobe", "overlay"],
            ),
            // kube-proxy
            exec(
                "/usr/sbin/modprobe",
                "/usr/bin/kmod",
                &["modprobe", "--", "nf_tables"],
            ),
            // an administrator's `sudo modprobe dummy` (anti-tamper C16)
            exec(
                "/usr/sbin/modprobe",
                "/usr/bin/kmod",
                &["modprobe", "dummy"],
            ),
        ] {
            let v = r.evaluate(&e).expect("recorded");
            assert_eq!(v.action, ResponseAction::Log, "{e:?}: {}", v.reasoning);
            assert_eq!(v.severity, Severity::High);
            assert_eq!(v.rule_id, "R011_KernelModuleTooling");
            assert!(v.reasoning.contains("T1547.006"), "{}", v.reasoning);
            assert!(
                v.reasoning.contains("installed by a package"),
                "{}",
                v.reasoning
            );
        }
        // a query records too
        let v = r.evaluate(&modprobe(&["-r", "dummy"])).expect("recorded");
        assert_eq!(v.action, ResponseAction::Log);
        assert!(v.reasoning.contains("inserts no module"), "{}", v.reasoning);
    }

    /// Lot 279: what is still killed — every malicious shape of
    /// deploy/lab/malsim/kmod-check.sh.
    #[test]
    fn what_no_package_vouches_for_is_still_killed() {
        let t = distro_host();
        let r = rule_on(&t);
        for (e, why) in [
            (
                exec(
                    "/usr/sbin/insmod",
                    "/usr/bin/kmod",
                    &["insmod", "/tmp/rk.ko"],
                ),
                "insmod loads the file",
            ),
            (modprobe(&["/tmp/rk.ko"]), "the file"),
            (modprobe(&["rk"]), "no package installed it"),
            (
                modprobe(&["not_a_module"]),
                "no module of the running kernel's tree",
            ),
            (modprobe(&["-d", "/tmp/root", "dummy"]), "from the caller"),
            (modprobe(&["-C", "/tmp/m.conf", "dummy"]), "from the caller"),
            (modprobe(&["--force", "dummy"]), "force"),
            (
                exec("/usr/bin/kmod", "/usr/bin/kmod", &["insmod", "/tmp/rk.ko"]),
                "insmod loads the file",
            ),
        ] {
            let v = r.evaluate(&e).expect("fires");
            assert_eq!(
                v.action,
                ResponseAction::KillProcess,
                "{e:?}: {}",
                v.reasoning
            );
            assert_eq!(v.severity, Severity::High);
            assert!(v.reasoning.contains(why), "{why}: {}", v.reasoning);
        }
        // a copy of the tool in a staging directory: its tree
        let v = r
            .evaluate(&exec(
                "/tmp/modprobe",
                "/tmp/modprobe",
                &["modprobe", "dummy"],
            ))
            .expect("fires");
        assert_eq!(v.action, ResponseAction::KillProcessTree);
        // the packaged file changed after the package database's last change
        t.db_changed(std::time::SystemTime::now() - std::time::Duration::from_secs(3600));
        let v = r.evaluate(&modprobe(&["dummy"])).expect("fires");
        assert_eq!(v.action, ResponseAction::KillProcess, "{}", v.reasoning);
        assert!(
            v.reasoning.contains("after the package database"),
            "{}",
            v.reasoning
        );
    }

    /// Lot 279: the kernel-thread exemption and the allowlist come first,
    /// as before; a forged kworker parent of an unvouched load is killed.
    #[test]
    fn the_exemptions_come_before_what_is_loaded() {
        let t = distro_host();
        let mut e = modprobe(&["rk"]);
        if let Event::ProcessSpawn {
            parent_comm,
            parent_is_kthread,
            ..
        } = &mut e
        {
            *parent_comm = "kworker/u8:3".to_string();
            *parent_is_kthread = true;
        }
        assert!(rule_on(&t).evaluate(&e).is_none());
        if let Event::ProcessSpawn {
            parent_is_kthread, ..
        } = &mut e
        {
            *parent_is_kthread = false;
        }
        let v = rule_on(&t).evaluate(&e).expect("fires");
        assert_eq!(v.action, ResponseAction::KillProcess);
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
        let r = R011KernelModuleTooling::with_requests(
            Arc::new(CommAllowlist::from_iter_owned(["modprobe".to_string()])),
            ModuleRequests::new("/nonexistent-root"),
        );
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

    // ─── External audit PROC-008 — the allowlist names actors ────────

    /// The shipped entries (`configs/process-comm-allowlist.v1`), judged
    /// on exec identity through a fixture lineage cache.
    fn shipped_with(
        tracker: crate::posture::lineage::AuthSessionTracker<H>,
    ) -> R011KernelModuleTooling {
        let entries = crate::config::comm_allowlist::BUILTIN_PROCESS_COMM_ALLOWLIST_V1
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty() && !l.starts_with('#'))
            .map(String::from);
        R011KernelModuleTooling::with_requests(
            Arc::new(CommAllowlist::from_iter_owned(entries).with_identity(tracker)),
            ModuleRequests::new("/nonexistent-root"),
        )
    }

    fn argv(a: &[&str]) -> Vec<String> {
        a.iter().map(|s| s.to_string()).collect()
    }

    /// apt → dpkg → a maintainer script → dkms (a bash script): each
    /// forked after its parent ran its program.
    fn package_transaction(
        dir: &std::path::Path,
    ) -> crate::posture::lineage::AuthSessionTracker<H> {
        let t = crate::posture::lineage::AuthSessionTracker::<H>::new(dir);
        t.ingest_exec(100, 1, "/usr/bin/apt", &argv(&["apt", "install"]), 10, 5, 0);
        t.ingest_exec(
            200,
            100,
            "/usr/bin/dpkg",
            &argv(&["dpkg", "--configure"]),
            20,
            15,
            0,
        );
        t.ingest_exec(
            300,
            200,
            "/usr/bin/dash",
            &argv(&[
                "/bin/sh",
                "/var/lib/dpkg/info/foo-dkms.postinst",
                "configure",
            ]),
            30,
            25,
            0,
        );
        t.ingest_exec(
            400,
            300,
            "/usr/bin/bash",
            &argv(&["/bin/bash", "/usr/sbin/dkms", "install", "foo/1.0"]),
            40,
            35,
            0,
        );
        t
    }

    /// A root exec at `exe` (pid 500, forked by dkms at 45) as the
    /// tracker and the rule see it.
    fn kmod_exec(t: &crate::posture::lineage::AuthSessionTracker<H>, uid: u32, exe: &str) -> Event {
        let a = argv(&["modprobe", "foo"]);
        t.ingest_exec(500, 400, exe, &a, 50, 45, 0);
        let mut e = crate::decision::rules::testutil::spawn_exe("modprobe", exe, exe, 0);
        if let Event::ProcessSpawn {
            pid,
            ppid,
            uid: u,
            argv,
            timestamp_ns,
            start_ns,
            ..
        } = &mut e
        {
            *pid = 500;
            *ppid = 400;
            *u = uid;
            *argv = a;
            // R12b (R-F): the exec event is the one the lineage holds — its
            // judgement looks the lineage up as of its own time
            (*timestamp_ns, *start_ns) = (50, 45);
        }
        e
    }

    /// External audit PROC-008: DKMS running modprobe in a package
    /// transaction is recorded, naming the actor — the shipped entries
    /// used to match no target of R011..R017.
    #[test]
    fn kmod_tool_under_apt_is_recorded_not_killed() {
        let dir = tempfile::tempdir().unwrap();
        let t = package_transaction(dir.path());
        let e = kmod_exec(&t, 0, "/usr/sbin/modprobe");
        let v = shipped_with(t).evaluate(&e).expect("recorded");
        assert_eq!(v.action, ResponseAction::Log);
        assert_eq!(v.severity, Severity::High);
        assert!(
            v.reasoning.contains("run under /usr/bin/dpkg"),
            "{}",
            v.reasoning
        );
    }

    /// External audit PROC-008 with POS-003: a process that forks the
    /// payload and only then executes apt vouches for nothing.
    #[test]
    fn a_forked_payload_that_later_execs_apt_is_still_killed() {
        let dir = tempfile::tempdir().unwrap();
        let t = crate::posture::lineage::AuthSessionTracker::<H>::new(dir.path());
        t.ingest_exec(600, 1, "/usr/bin/bash", &argv(&["bash"]), 10, 5, 0);
        // the payload is forked at 30; its parent executes apt at 60
        t.ingest_exec(600, 1, "/usr/bin/apt", &argv(&["apt", "list"]), 60, 5, 0);
        let a = argv(&["modprobe", "evil"]);
        t.ingest_exec(700, 600, "/usr/sbin/modprobe", &a, 70, 30, 0);
        let mut e = crate::decision::rules::testutil::spawn_exe(
            "modprobe",
            "/usr/sbin/modprobe",
            "/usr/sbin/modprobe",
            0,
        );
        if let Event::ProcessSpawn {
            pid,
            ppid,
            uid,
            timestamp_ns,
            start_ns,
            ..
        } = &mut e
        {
            // R12b (R-F): as of the payload's own exec (70), where apt (60)
            // is in the lineage — POS-003 alone keeps it from vouching
            (*pid, *ppid, *uid, *timestamp_ns, *start_ns) = (700, 600, 0, 70, 30);
        }
        let v = shipped_with(t).evaluate(&e).expect("fires");
        assert_eq!(v.action, ResponseAction::KillProcess);
    }

    /// External audit PROC-008: the lineage vouches only for a root exec
    /// of a program in a system tree — not for a copy a maintainer script
    /// dropped where anyone writes, nor for another uid's exec (a pager's
    /// shell under a user's `apt changelog`).
    #[test]
    fn an_actor_does_not_vouch_for_a_staged_copy_or_another_uid() {
        let dir = tempfile::tempdir().unwrap();
        let t = package_transaction(dir.path());
        let staged = kmod_exec(&t, 0, "/var/tmp/modprobe");
        let v = shipped_with(t.clone()).evaluate(&staged).expect("fires");
        assert_eq!(v.action, ResponseAction::KillProcessTree);
        let user = kmod_exec(&t, 1000, "/usr/sbin/modprobe");
        let v = shipped_with(t).evaluate(&user).expect("fires");
        assert_eq!(v.action, ResponseAction::KillProcess);
    }

    /// External audit PROC-008: an entry naming the target still exempts
    /// it (compatibility), by what the kernel executed.
    #[test]
    fn a_target_entry_still_exempts() {
        let dir = tempfile::tempdir().unwrap();
        let t = crate::posture::lineage::AuthSessionTracker::<H>::new(dir.path());
        let r = R011KernelModuleTooling::with_requests(
            Arc::new(CommAllowlist::from_iter_owned(["modprobe".to_string()]).with_identity(t)),
            ModuleRequests::new("/nonexistent-root"),
        );
        let e = crate::decision::rules::testutil::spawn_exe(
            "modprobe",
            "/usr/sbin/modprobe",
            "/usr/sbin/modprobe",
            0,
        );
        assert!(r.evaluate(&e).is_none());
    }
}
