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

use nn_model::{Event, ModuleLoadMethod, ResponseAction, Severity, Verdict};

use crate::config::comm_allowlist::CommAllowlist;
use crate::decision::attack::{AttackRef, Tactic};
use crate::decision::rules::module_provenance::{ModuleOwners, Provenance};
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
    /// External audit PROC-005: who installed a module file.
    owners: ModuleOwners,
}

impl R018KernelModuleLoad {
    pub fn new(loader_allowlist: Arc<CommAllowlist>) -> Self {
        Self::with_owners(loader_allowlist, ModuleOwners::default())
    }

    pub fn with_owners(loader_allowlist: Arc<CommAllowlist>, owners: ModuleOwners) -> Self {
        Self {
            loader_allowlist,
            owners,
        }
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
    fn attack(&self) -> &'static [AttackRef] {
        const ATTACK: &[AttackRef] = &[
            AttackRef::new(Tactic::Persistence, "T1547.006"),
            AttackRef::new(Tactic::Stealth, "T1014"),
        ];
        ATTACK
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
                // Audit `abi-modpath-1`: a RELATIVE path means the kernel
                // walk ran out of slots before the root — the prefix is
                // unknown, so it must not be classified as non-standard
                // (that branch SIGKILLs + COMBATs). Surface it as a
                // Medium alert unless the loader is allowlisted.
                // External audit PROC-004: deeper than the walk's slots is
                // deeper than any module directory (a legitimate one sits a
                // dozen components down at most). The loader chose that
                // depth; it must not buy the load an alert instead of the
                // kill.
                if nn_model::module_path_too_deep(p) {
                    return Some(build_verdict(
                        self,
                        event,
                        ResponseAction::KillProcessTree,
                        Severity::Critical,
                        &format!(
                            "Kernel module loaded from a path deeper than any module \
                             directory ({p}) by '{loader_comm}' (parent '{parent_comm}') — \
                             legit modules live under /lib/modules; near-certain rootkit \
                             (T1014 / T1547.006). Kill tree + posture → COMBAT."
                        ),
                    ));
                }
                if nn_model::module_path_is_truncated(p) {
                    if self.loader_allowlist.contains(loader_comm)
                        || self.loader_allowlist.contains(parent_comm)
                    {
                        return None;
                    }
                    // A kernel read failed: the origin is unknown, which is
                    // not the same as benign (external audit PROC-004).
                    return Some(build_verdict(
                        self,
                        event,
                        ResponseAction::Log,
                        Severity::High,
                        &format!(
                            "Kernel module loaded from a path the sensor could not read to \
                             the root (components: {p}) by '{loader_comm}' (parent \
                             '{parent_comm}') — origin unverifiable, NOT auto-killing. Alert."
                        ),
                    ));
                }
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
                // External audit PROC-005: whoever loads a module can write
                // under /lib/modules; a file there that no package installed
                // and DKMS did not build was put there by hand. From an
                // unexpected loader that is the non-standard case again;
                // from a system loader (a locally built module at boot, or
                // a comm that only claims to be one) an alert, no kill.
                if self.owners.of(p) == Provenance::Unowned {
                    let system_loader = self.loader_allowlist.contains(loader_comm)
                        || self.loader_allowlist.contains(parent_comm);
                    return Some(if system_loader {
                        build_verdict(
                            self,
                            event,
                            ResponseAction::Log,
                            Severity::High,
                            &format!(
                                "Kernel module {p} loaded by '{loader_comm}' (parent \
                                 '{parent_comm}') is in a module directory but no package \
                                 installed it and DKMS did not build it (T1547.006). Alert."
                            ),
                        )
                    } else {
                        build_verdict(
                            self,
                            event,
                            ResponseAction::KillProcessTree,
                            Severity::Critical,
                            &format!(
                                "Kernel module {p} loaded by '{loader_comm}' (parent \
                                 '{parent_comm}') — under /lib/modules, but no package \
                                 installed it and DKMS did not build it: copied there by \
                                 hand; rootkit shape (T1014 / T1547.006). Kill tree + \
                                 posture → COMBAT."
                            ),
                        )
                    });
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

    fn allowlist() -> Arc<CommAllowlist> {
        Arc::new(CommAllowlist::from_iter_owned(
            ["systemd-udevd", "systemd-modules-load", "kmod"]
                .into_iter()
                .map(String::from),
        ))
    }

    /// The rule on a host with no package database (provenance unknown:
    /// judged by path and loader, as before PROC-005).
    fn rule() -> R018KernelModuleLoad {
        R018KernelModuleLoad::with_owners(allowlist(), ModuleOwners::new("/nonexistent-root"))
    }

    /// External audit PROC-005: a module copied under /lib/modules — no
    /// package lists it, DKMS did not build it — is the non-standard case
    /// for an unexpected loader, an alert for a system loader; a packaged
    /// one keeps its Medium alert.
    #[test]
    fn a_module_copied_under_lib_modules_is_not_standard() {
        let host = tempfile::TempDir::new().unwrap();
        let info = host.path().join("var/lib/dpkg/info");
        std::fs::create_dir_all(&info).unwrap();
        std::fs::write(host.path().join("var/lib/dpkg/status"), "").unwrap();
        std::fs::write(
            info.join("linux-modules-6.8.0.list"),
            "/lib/modules/6.8.0/kernel/fs/foo.ko\n",
        )
        .unwrap();
        let r = R018KernelModuleLoad::with_owners(allowlist(), ModuleOwners::new(host.path()));
        let copied = [
            "/", "usr", "lib", "modules", "6.8.0", "kernel", "fs", "rk.ko",
        ];
        let v = r
            .evaluate(&ev(&raw(MODULE_LOAD_FINIT, "insmod", "bash", 0, &copied)))
            .expect("fires");
        assert_eq!(
            (v.action, v.severity),
            (ResponseAction::KillProcessTree, Severity::Critical)
        );
        let v = r
            .evaluate(&ev(&raw(
                MODULE_LOAD_FINIT,
                "systemd-udevd",
                "systemd",
                0,
                &copied,
            )))
            .expect("alerts");
        assert_eq!(
            (v.action, v.severity),
            (ResponseAction::Log, Severity::High)
        );
        let packaged = ["/", "lib", "modules", "6.8.0", "kernel", "fs", "foo.ko"];
        let v = r
            .evaluate(&ev(&raw(
                MODULE_LOAD_FINIT,
                "modprobe",
                "bash",
                0,
                &packaged,
            )))
            .expect("alerts");
        assert_eq!(
            (v.action, v.severity),
            (ResponseAction::Log, Severity::Medium)
        );
        assert!(r
            .evaluate(&ev(&raw(
                MODULE_LOAD_FINIT,
                "systemd-udevd",
                "systemd",
                0,
                &packaged
            )))
            .is_none());
    }

    /// External audit PROC-005: a component that is not UTF-8 is kept, and
    /// the path it leads with is no module directory.
    #[test]
    fn a_non_utf8_component_does_not_collapse_into_a_standard_path() {
        let mut r = raw(
            MODULE_LOAD_FINIT,
            "insmod",
            "bash",
            0,
            &["/", "x", "lib", "modules", "6.8.0", "rk.ko"],
        );
        // the "x" slot (5th from the leaf) holds bytes that are not UTF-8
        r.path[4 * 32] = 0xff;
        r.path[4 * 32 + 1] = 0xfe;
        let v = rule().evaluate(&ev(&r)).expect("fires");
        assert_eq!(
            (v.action, v.severity),
            (ResponseAction::KillProcessTree, Severity::Critical)
        );
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
        // Mirrors the kernel walk: the root dentry ("/") is the last
        // component written; a path that never reaches it is truncated —
        // here by a failed read (`raw_too_deep` for the other cause).
        r.path_truncated = if path_root_to_leaf.first() == Some(&"/") {
            0
        } else {
            common::wire::MODULE_PATH_UNREADABLE
        };
        r
    }

    /// [`raw`] for a walk that used every slot without reaching the root.
    fn raw_too_deep(loader: &str, parent: &str, leaf_side: &[&str]) -> ModuleLoadRaw {
        let mut r = raw(MODULE_LOAD_FINIT, loader, parent, 0, leaf_side);
        r.path_truncated = common::wire::MODULE_PATH_TOO_DEEP;
        r
    }

    fn ev(r: &ModuleLoadRaw) -> Event {
        Event::from(r)
    }

    // ── reconstruction sanity (the From impl) ──────────────────────
    #[test]
    fn from_reconstructs_paths() {
        let tmp = ev(&raw(
            MODULE_LOAD_FINIT,
            "insmod",
            "bash",
            0,
            &["/", "tmp", "evil.ko"],
        ));
        let std = ev(&raw(
            MODULE_LOAD_FINIT,
            "modprobe",
            "bash",
            0,
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

    /// Audit `abi-modpath-1`: a 12-component stock path
    /// (`mcp251xfd.ko.zst`) must reconstruct WITH its prefix and be
    /// classified standard — it used to lose `/usr/lib/modules`.
    #[test]
    fn deep_standard_path_keeps_prefix_and_is_not_critical() {
        let deep = [
            "/",
            "usr",
            "lib",
            "modules",
            "6.8.0-124-generic",
            "kernel",
            "drivers",
            "net",
            "can",
            "spi",
            "mcp251xfd",
            "mcp251xfd.ko.zst",
        ];
        let e = ev(&raw(MODULE_LOAD_FINIT, "modprobe", "bash", 0, &deep));
        match e {
            Event::ModuleLoad { ref path, .. } => assert_eq!(
                path.as_deref(),
                Some("/usr/lib/modules/6.8.0-124-generic/kernel/drivers/net/can/spi/mcp251xfd/mcp251xfd.ko.zst")
            ),
            _ => panic!("not ModuleLoad"),
        }
        let v = rule()
            .evaluate(&e)
            .expect("non-allowlisted loader still alerts");
        assert_eq!(v.action, ResponseAction::Log);
        assert_eq!(v.severity, Severity::Medium);
    }

    /// External audit PROC-004: a path deeper than the 16-slot budget is
    /// deeper than any module directory — the depth the loader chose must
    /// not turn the kill into an alert, allowlisted loader or not.
    #[test]
    fn too_deep_path_is_not_downgraded() {
        let leaf_side: Vec<String> = (0..15).map(|i| format!("d{i}")).collect();
        let mut comps: Vec<&str> = leaf_side.iter().map(String::as_str).collect();
        comps.push("evil.ko");
        for (loader, parent) in [("insmod", "bash"), ("systemd-udevd", "systemd")] {
            let e = ev(&raw_too_deep(loader, parent, &comps));
            let Event::ModuleLoad { ref path, .. } = e else {
                panic!("not ModuleLoad")
            };
            let p = path.as_deref().unwrap();
            assert!(nn_model::module_path_too_deep(p), "{p}");
            let v = rule().evaluate(&e).expect("fires");
            assert_eq!(v.action, ResponseAction::KillProcessTree, "{loader}");
            assert_eq!(v.severity, Severity::Critical);
        }
    }

    /// A path a failed read left unknown comes back RELATIVE and must never
    /// take the Critical/KillTree branch — but unknown is not benign
    /// (external audit PROC-004): High, not Medium.
    #[test]
    fn unreadable_path_is_high_log_never_killtree() {
        // No leading "/" component → raw() marks it truncated.
        let tail = ["6.8.0-124-generic", "kernel", "drivers", "x", "deep.ko.zst"];
        let e = ev(&raw(MODULE_LOAD_FINIT, "insmod", "bash", 0, &tail));
        match e {
            Event::ModuleLoad { ref path, .. } => {
                let p = path.as_deref().unwrap();
                assert!(
                    !p.starts_with('/'),
                    "truncated path must stay relative: {p}"
                );
                assert!(nn_model::module_path_is_truncated(p));
            }
            _ => panic!("not ModuleLoad"),
        }
        let v = rule().evaluate(&e).expect("alert");
        assert_eq!(v.action, ResponseAction::Log);
        assert_eq!(v.severity, Severity::High);

        // Allowlisted loader + truncated path: silent, like a standard path.
        let e2 = ev(&raw(
            MODULE_LOAD_FINIT,
            "systemd-udevd",
            "systemd",
            0,
            &tail,
        ));
        assert!(rule().evaluate(&e2).is_none());
    }

    // ── exempt conditions ──────────────────────────────────────────
    #[test]
    fn exempt_kthread() {
        // kernel-driven load — even from /tmp (impossible in practice,
        // but the non-forgeable signal is trusted first).
        let v = rule().evaluate(&ev(&raw(
            MODULE_LOAD_FINIT,
            "modprobe",
            "kworker/0:1",
            1,
            &["/", "tmp", "x.ko"],
        )));
        assert!(v.is_none(), "kthread-driven load must be exempt");
    }

    #[test]
    fn exempt_allowlisted_loader() {
        let v = rule().evaluate(&ev(&raw(
            MODULE_LOAD_FINIT,
            "kmod",
            "systemd",
            0,
            &["/", "usr", "lib", "modules", "6.8.0", "kernel", "x.ko"],
        )));
        assert!(
            v.is_none(),
            "allowlisted loader (kmod) on a standard path must not fire"
        );
    }

    #[test]
    fn exempt_allowlisted_parent() {
        // boot modprobe under systemd-udevd: loader=modprobe (not
        // allowlisted) but parent=systemd-udevd (allowlisted) → exempt.
        let v = rule().evaluate(&ev(&raw(
            MODULE_LOAD_FINIT,
            "modprobe",
            "systemd-udevd",
            0,
            &["/", "lib", "modules", "6.8.0", "kernel", "snd.ko"],
        )));
        assert!(
            v.is_none(),
            "load under an allowlisted auto-loader parent must not fire"
        );
    }

    // ── fire conditions ────────────────────────────────────────────
    #[test]
    fn fire_nonstandard_path_is_critical_killtree() {
        let v = rule()
            .evaluate(&ev(&raw(
                MODULE_LOAD_FINIT,
                "insmod",
                "bash",
                0,
                &["/", "tmp", "evil.ko"],
            )))
            .expect("non-standard path must fire");
        assert_eq!(v.severity, Severity::Critical);
        assert_eq!(v.action, ResponseAction::KillProcessTree);
        assert_eq!(v.rule_id, "R018_KernelModuleLoad");
        // The Critical kill must target the LOADER pid (build_verdict
        // ModuleLoad arm), not 0 — else it's refused at the PID floor.
        assert_eq!(
            v.event_pid, 4242,
            "verdict must target the loader pid, not 0"
        );
    }

    /// SECURITY-CRITICAL: a load from /tmp must fire Critical EVEN when
    /// the loader's comm is allowlisted (forged) — the non-standard-path
    /// check precedes the allowlist, so the allowlist cannot blind it.
    #[test]
    fn nonstandard_path_fires_even_with_allowlisted_loader() {
        let v = rule()
            .evaluate(&ev(&raw(
                MODULE_LOAD_FINIT,
                "kmod",
                "kmod",
                0,
                &["/", "tmp", "evil.ko"],
            )))
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
                MODULE_LOAD_FINIT,
                "dkms",
                "bash",
                0,
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
            MODULE_LOAD_FINIT,
            "kmod",
            "systemd-modules-load",
            0,
            &[
                "/",
                "lib",
                "modules",
                "6.8.0",
                "kernel",
                "net",
                "tls",
                "tls.ko.zst",
            ],
        )));
        assert!(
            v.is_none(),
            "a legit /lib/modules load by an allowlisted loader must stay silent"
        );
    }

    #[test]
    fn non_module_event_is_ignored() {
        use crate::decision::rules::testutil::spawn;
        assert!(rule()
            .evaluate(&spawn("insmod", "/usr/sbin/insmod"))
            .is_none());
    }
}
