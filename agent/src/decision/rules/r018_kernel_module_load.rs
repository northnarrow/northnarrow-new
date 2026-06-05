//! R018 — Kernel module LOAD (BUG-034). MITRE **T1547.006** (Boot or
//! Logon Autostart Execution: Kernel Modules) + **T1014** (Rootkit).
//!
//! Fed by the `Event::ModuleLoad` events the BPF-LSM `kernel_read_file`
//! / `kernel_load_data` hooks emit (`agent-ebpf/src/module_load.rs`).
//! Unlike FIM-008 (watches a `.ko` on disk — evaded by a `/tmp` drop)
//! and R011 (watches the insmod/modprobe *exec* — evaded by a direct
//! `finit_module(2)`), this scores the LOAD itself — the chokepoint a
//! rootkit cannot avoid.
//!
//! ## Verdict model (autonomous kill on exactly ONE condition)
//!
//! Path is the primary discriminator — legit modules live ONLY under
//! `/lib/modules`. Autonomous `KillProcessTree` fires on exactly the
//! near-certain case (non-standard path); everything else ALERTS, with
//! severity ranking the alert without arming a kill:
//!
//! | Condition | Severity | Action |
//! |---|---|---|
//! | `parent_is_kthread` (non-forgeable kernel-driven load) | — | exempt |
//! | trusted auto-loader (loader/parent in the allowlist) | — | exempt |
//! | `finit_module` + **non-standard path** (`/tmp`, …) | **Critical** | **KillProcessTree** |
//! | `init_module(2)` legacy (no path), non-exempt | **High** | **Log** |
//! | `finit_module` + standard path, unexpected loader | **Medium** | **Log** |
//!
//! ORDERING is security-critical: the non-standard-path Critical is
//! checked BEFORE the loader allowlist, so an attacker who forges a
//! loader/parent `comm` cannot exempt a load from `/tmp`. (The
//! `KillProcessTree` is the interim autonomous response; the effective
//! fix is denying the load at the `kernel_read_file` hook — see
//! BUG-037, the stage-3 fast-follow.)

use std::sync::Arc;

use common::{Event, ModuleLoadMethod, ResponseAction, Severity, Verdict};

use crate::config::comm_allowlist::CommAllowlist;
use crate::decision::{rules::build_verdict, Rule};

/// Standard kernel-module locations. A `.ko` loaded from anywhere else
/// (`/tmp`, `/dev/shm`, `/home`, `/run`, …) is the near-certain rootkit
/// signal — no legitimate module loads from outside `/lib/modules`.
/// (`/lib` is usually a symlink to `/usr/lib`, so both forms appear.)
fn is_standard_module_path(p: &str) -> bool {
    p.starts_with("/lib/modules/") || p.starts_with("/usr/lib/modules/")
}

pub struct R018KernelModuleLoad {
    /// Dedicated module-loader allowlist — the trusted system
    /// auto-loaders (`systemd-udevd`, `systemd-modules-load`, `kmod`).
    /// Deliberately NOT `insmod`/`modprobe`: they load arbitrary paths,
    /// so allowlisting them would blind the non-standard-path Critical.
    loader_allowlist: Arc<CommAllowlist>,
}

impl R018KernelModuleLoad {
    pub fn new(loader_allowlist: Arc<CommAllowlist>) -> Self {
        Self { loader_allowlist }
    }
}

impl Rule for R018KernelModuleLoad {
    fn id(&self) -> &'static str {
        "R018_KernelModuleLoad"
    }
    fn name(&self) -> &'static str {
        "Kernel module load"
    }
    fn category(&self) -> &'static str {
        "rootkit"
    }

    fn evaluate(&self, event: &Event) -> Option<Verdict> {
        let Event::ModuleLoad {
            method,
            loader_comm,
            parent_comm,
            parent_is_kthread,
            path,
            ..
        } = event
        else {
            return None;
        };

        // (1) Kernel-driven load (boot / hot-plug) — non-forgeable
        // PF_KTHREAD. Exempt. A kthread never loads from a non-standard
        // path, so exempting it here cannot hide the /tmp case below.
        if *parent_is_kthread {
            return None;
        }

        // (2) NEAR-CERTAIN rootkit — a finit_module load from a
        // NON-standard path. Checked BEFORE the loader allowlist so a
        // forged-comm loader from /tmp cannot be exempted. The ONE
        // autonomous-kill condition.
        if *method == ModuleLoadMethod::Finit {
            if let Some(p) = path {
                if !is_standard_module_path(p) {
                    return Some(build_verdict(
                        self,
                        event,
                        ResponseAction::KillProcessTree,
                        Severity::Critical,
                        &format!(
                            "Kernel module loaded from NON-standard path {p} — legit \
                             modules are only under /lib/modules; near-certain rootkit \
                             (T1014 / T1547.006). Kill tree + posture → COMBAT."
                        ),
                    ));
                }
            }
        }

        // (3) Trusted system auto-loader — exempt the legit boot /
        // hot-plug path (the loader OR its parent is an allowlisted
        // auto-loader). Pragmatic FP guard (comm is forgeable — same
        // class as R011's allowlist), deliberately AFTER the
        // non-standard-path Critical so it can never blind it.
        if self.loader_allowlist.contains(loader_comm)
            || self.loader_allowlist.contains(parent_comm)
        {
            return None;
        }

        // (4) Legacy init_module(2) (buffer load, no path) by a
        // non-exempt loader — the legacy interface is rarely used
        // legitimately. Strong signal, not near-certain → ALERT,
        // don't autonomous-kill.
        if *method == ModuleLoadMethod::Init {
            return Some(build_verdict(
                self,
                event,
                ResponseAction::Log,
                Severity::High,
                &format!(
                    "Kernel module loaded via legacy init_module(2) by '{loader_comm}' \
                     (parent '{parent_comm}') — legacy buffer-load interface, rarely \
                     legitimate (T1547.006). Alert."
                ),
            ));
        }

        // (5) finit_module from a STANDARD path by an unexpected
        // (non-allowlisted, non-kthread) loader — DKMS / installer /
        // admin tool. Suspicious-but-not-conclusive → ALERT, no kill.
        let p = path.as_deref().unwrap_or("(unresolved)");
        Some(build_verdict(
            self,
            event,
            ResponseAction::Log,
            Severity::Medium,
            &format!(
                "Kernel module {p} loaded by unexpected loader '{loader_comm}' (parent \
                 '{parent_comm}') — standard path but non-allowlisted loader (T1547.006). Alert."
            ),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use common::wire::{ModuleLoadRaw, MODULE_LOAD_FINIT, MODULE_LOAD_INIT};

    fn rule() -> R018KernelModuleLoad {
        R018KernelModuleLoad::new(Arc::new(CommAllowlist::from_iter_owned(
            ["systemd-udevd", "systemd-modules-load", "kmod"]
                .into_iter()
                .map(String::from),
        )))
    }

    fn put_comm(dst: &mut [u8; 16], s: &str) {
        let b = s.as_bytes();
        let n = b.len().min(15);
        dst[..n].copy_from_slice(&b[..n]);
    }

    /// Build a real `ModuleLoadRaw` (the wire struct), encoding the path
    /// the way the kernel hook does — components leaf→root in fixed
    /// 32-byte slots — so the test exercises the genuine
    /// `From<&ModuleLoadRaw>` reconstruction, not a hand-built Event.
    /// `path_root_to_leaf` is the human path order (e.g. `["/","tmp","x.ko"]`).
    fn raw(
        method: u8,
        loader: &str,
        parent: &str,
        kthread: u8,
        path_root_to_leaf: &[&str],
    ) -> ModuleLoadRaw {
        let mut r = ModuleLoadRaw::zeroed();
        r.method = method;
        r.loader_pid = 4242; // non-zero so "verdict targets the loader" is testable
        r.parent_is_kthread = kthread;
        put_comm(&mut r.loader_comm, loader);
        put_comm(&mut r.parent_comm, parent);
        let mut slot = 0usize;
        for comp in path_root_to_leaf.iter().rev() {
            let off = slot * 32;
            let b = comp.as_bytes();
            let n = b.len().min(31);
            r.path[off..off + n].copy_from_slice(&b[..n]);
            slot += 1;
        }
        r.path_len = slot as u16;
        r
    }

    fn ev(r: &ModuleLoadRaw) -> Event {
        Event::from(r)
    }

    // ── reconstruction sanity (the From impl) ──────────────────────
    #[test]
    fn from_reconstructs_paths() {
        let tmp = ev(&raw(MODULE_LOAD_FINIT, "insmod", "bash", 0, &["/", "tmp", "evil.ko"]));
        let std = ev(&raw(
            MODULE_LOAD_FINIT, "modprobe", "bash", 0,
            &["/", "lib", "modules", "6.8.0", "kernel", "fs", "foo.ko"],
        ));
        match tmp {
            Event::ModuleLoad { ref path, .. } => assert_eq!(path.as_deref(), Some("/tmp/evil.ko")),
            _ => panic!("not ModuleLoad"),
        }
        match std {
            Event::ModuleLoad { ref path, .. } => {
                assert_eq!(path.as_deref(), Some("/lib/modules/6.8.0/kernel/fs/foo.ko"))
            }
            _ => panic!("not ModuleLoad"),
        }
    }

    // ── exempt conditions ──────────────────────────────────────────
    #[test]
    fn exempt_kthread() {
        // kernel-driven load — even from /tmp (impossible in practice,
        // but the non-forgeable signal is trusted first).
        let v = rule().evaluate(&ev(&raw(MODULE_LOAD_FINIT, "modprobe", "kworker/0:1", 1, &["/", "tmp", "x.ko"])));
        assert!(v.is_none(), "kthread-driven load must be exempt");
    }

    #[test]
    fn exempt_allowlisted_loader() {
        let v = rule().evaluate(&ev(&raw(
            MODULE_LOAD_FINIT, "kmod", "systemd", 0,
            &["/", "usr", "lib", "modules", "6.8.0", "kernel", "x.ko"],
        )));
        assert!(v.is_none(), "allowlisted loader (kmod) on a standard path must not fire");
    }

    #[test]
    fn exempt_allowlisted_parent() {
        // boot modprobe under systemd-udevd: loader=modprobe (not
        // allowlisted) but parent=systemd-udevd (allowlisted) → exempt.
        let v = rule().evaluate(&ev(&raw(
            MODULE_LOAD_FINIT, "modprobe", "systemd-udevd", 0,
            &["/", "lib", "modules", "6.8.0", "kernel", "snd.ko"],
        )));
        assert!(v.is_none(), "load under an allowlisted auto-loader parent must not fire");
    }

    // ── fire conditions ────────────────────────────────────────────
    #[test]
    fn fire_nonstandard_path_is_critical_killtree() {
        let v = rule()
            .evaluate(&ev(&raw(MODULE_LOAD_FINIT, "insmod", "bash", 0, &["/", "tmp", "evil.ko"])))
            .expect("non-standard path must fire");
        assert_eq!(v.severity, Severity::Critical);
        assert_eq!(v.action, ResponseAction::KillProcessTree);
        assert_eq!(v.rule_id, "R018_KernelModuleLoad");
        // The Critical kill must target the LOADER pid (build_verdict
        // ModuleLoad arm), not 0 — else it's refused at the PID floor.
        assert_eq!(v.event_pid, 4242, "verdict must target the loader pid, not 0");
    }

    /// SECURITY-CRITICAL: a load from /tmp must fire Critical EVEN when
    /// the loader's comm is allowlisted (forged) — the non-standard-path
    /// check precedes the allowlist, so the allowlist cannot blind it.
    #[test]
    fn nonstandard_path_fires_even_with_allowlisted_loader() {
        let v = rule()
            .evaluate(&ev(&raw(MODULE_LOAD_FINIT, "kmod", "kmod", 0, &["/", "tmp", "evil.ko"])))
            .expect("non-standard path must fire even for an allowlisted comm");
        assert_eq!(v.severity, Severity::Critical);
        assert_eq!(v.action, ResponseAction::KillProcessTree);
    }

    #[test]
    fn fire_legacy_init_module_is_high_log() {
        let v = rule()
            .evaluate(&ev(&raw(MODULE_LOAD_INIT, "python3", "bash", 0, &[])))
            .expect("legacy init_module by a non-exempt loader must fire");
        assert_eq!(v.severity, Severity::High);
        assert_eq!(v.action, ResponseAction::Log); // alert, NOT kill
    }

    #[test]
    fn fire_stdpath_unexpected_loader_is_medium_log() {
        let v = rule()
            .evaluate(&ev(&raw(
                MODULE_LOAD_FINIT, "dkms", "bash", 0,
                &["/", "lib", "modules", "6.8.0", "updates", "nvidia.ko"],
            )))
            .expect("standard path + unexpected loader must fire");
        assert_eq!(v.severity, Severity::Medium);
        assert_eq!(v.action, ResponseAction::Log); // alert, NOT kill
    }

    // ── negative control ───────────────────────────────────────────
    #[test]
    fn negative_stdpath_allowlisted_loader_does_not_fire() {
        let v = rule().evaluate(&ev(&raw(
            MODULE_LOAD_FINIT, "kmod", "systemd-modules-load", 0,
            &["/", "lib", "modules", "6.8.0", "kernel", "net", "tls", "tls.ko.zst"],
        )));
        assert!(v.is_none(), "a legit /lib/modules load by an allowlisted loader must stay silent");
    }

    #[test]
    fn non_module_event_is_ignored() {
        use crate::decision::rules::testutil::spawn;
        assert!(rule().evaluate(&spawn("insmod", "/usr/sbin/insmod")).is_none());
    }
}
