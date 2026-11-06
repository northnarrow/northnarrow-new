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
//! ## Lot 285: the kernel judges the file, the rule records
//!
//! The load hooks judge the FILE in the kernel (`common::module_judge`): a
//! file of the running kernel's tree that a verified package installed or
//! DKMS built, unchanged since boot or written since inside a package
//! transaction, or named by a signed opt-out, loads; anything else — and an
//! `init_module` buffer — is refused outside a signed trusted-installer
//! window in the deny mode, let through in the record mode. The event
//! carries the kernel's verdict; who loads is not asked (the loader
//! allowlist by `comm` — `kmod`, `systemd-udevd`, `systemd-modules-load`,
//! names any process can take — is gone):
//!
//! | Kernel verdict | Condition | Severity | Action |
//! |---|---|---|---|
//! | trusted | — | — | none |
//! | window | a signed trusted-installer window let an untrusted load through | Medium | Log |
//! | opt-out | a signed per-module opt-out let it through | Medium | Log |
//! | dkms-unattested | a DKMS or akmods build its registry vouches for, written since boot outside a recognised package transaction: let through unless the policy enforces R018 | High | Log |
//! | denied / recorded / not judged | `finit_module` from a **non-standard path** (`/tmp`, …) or deeper than any module directory | **Critical** | **KillProcessTree** |
//! | denied / recorded | any other untrusted file, or an `init_module` buffer | High | Log |
//! | not judged | a module directory's file: by its provenance (package, DKMS: none; copied by hand: High; no database: Medium) | | Log |
//!
//! "Not judged" is a load the kernel did not judge: the agent had not
//! filled its trust map yet (the first seconds of its start), or an older
//! eBPF object; the rule then judges by the path and the package database,
//! as before lot 285 but without the loader allowlist.

use nn_model::{Event, ModuleLoadMethod, ModuleLoadVerdict, ResponseAction, Severity, Verdict};

use crate::decision::attack::{AttackRef, Tactic};
use crate::decision::host::DecisionHost;
use crate::decision::rules::module_provenance::{ModuleOwners, Provenance};
use crate::decision::{rules::build_verdict, Rule};

/// Standard kernel-module locations. A `.ko` loaded from anywhere else
/// (`/tmp`, `/dev/shm`, `/home`, `/run`, …) is the near-certain rootkit
/// signal — no legitimate module loads from outside `/lib/modules`.
/// (`/lib` is usually a symlink to `/usr/lib`, so both forms appear.)
fn is_standard_module_path(p: &str) -> bool {
    p.starts_with("/lib/modules/") || p.starts_with("/usr/lib/modules/")
}

pub struct R018KernelModuleLoad<H: DecisionHost> {
    /// External audit PROC-005: who installed a module file — read for a
    /// load the kernel did not judge.
    owners: ModuleOwners<H>,
}

impl<H: DecisionHost> Default for R018KernelModuleLoad<H> {
    fn default() -> Self {
        Self::new()
    }
}

impl<H: DecisionHost> R018KernelModuleLoad<H> {
    pub fn new() -> Self {
        Self::with_owners(ModuleOwners::default())
    }

    pub fn with_owners(owners: ModuleOwners<H>) -> Self {
        Self { owners }
    }
}

/// What the kernel did with the load, for the reasoning.
fn kernel_said(v: ModuleLoadVerdict) -> &'static str {
    match v {
        ModuleLoadVerdict::Denied => "REFUSED by the kernel (deny mode)",
        ModuleLoadVerdict::Recorded => "let through by the kernel: the record mode, not refused",
        ModuleLoadVerdict::Window => "let through by a signed trusted-installer window",
        ModuleLoadVerdict::OptOut => "let through by a signed per-module opt-out",
        ModuleLoadVerdict::Trusted => "trusted by the kernel",
        ModuleLoadVerdict::DkmsUnattested => {
            "let through by the default policy, not trusted (`enforce R018` refuses it)"
        }
        ModuleLoadVerdict::NotJudged => "not judged by the kernel (its trust map not filled yet)",
    }
}

impl<H: DecisionHost> Rule for R018KernelModuleLoad<H> {
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
            path,
            verdict,
            file,
            ..
        } = event
        else {
            return None;
        };
        let kernel = kernel_said(*verdict);
        let log = |severity: Severity, why: String| {
            Some(build_verdict(
                self,
                event,
                ResponseAction::Log,
                severity,
                &why,
            ))
        };
        let shown = path.as_deref().unwrap_or("(no file: init_module)");
        match verdict {
            // (1) The kernel vouches for the file: nothing to record.
            ModuleLoadVerdict::Trusted => return None,
            // (2) Let through by a signed decision: recorded.
            ModuleLoadVerdict::Window | ModuleLoadVerdict::OptOut => {
                return log(
                    Severity::Medium,
                    format!(
                        "Kernel module {shown} loaded by '{loader_comm}' (parent \
                         '{parent_comm}'), a file the agent does not vouch for — {kernel} \
                         (T1547.006). Recorded."
                    ),
                );
            }
            ModuleLoadVerdict::Denied
            | ModuleLoadVerdict::Recorded
            | ModuleLoadVerdict::DkmsUnattested
            | ModuleLoadVerdict::NotJudged => {}
        }
        // (3) NEAR-CERTAIN rootkit — a finit_module load from a NON-standard
        // path, or one deeper than any module directory (external audit
        // PROC-004: the loader chose that depth): kill the tree whatever
        // the kernel did (refused, the attempt is the signal).
        if *method == ModuleLoadMethod::Finit {
            if let Some(p) = path {
                let too_deep = nn_model::module_path_too_deep(p);
                if too_deep
                    || (!nn_model::module_path_is_truncated(p) && !is_standard_module_path(p))
                {
                    let place = if too_deep {
                        "a path deeper than any module directory"
                    } else {
                        "a NON-standard path"
                    };
                    return Some(build_verdict(
                        self,
                        event,
                        ResponseAction::KillProcessTree,
                        Severity::Critical,
                        &format!(
                            "Kernel module loaded from {place} ({p}) by '{loader_comm}' \
                             (parent '{parent_comm}') — legit modules live under \
                             /lib/modules; near-certain rootkit (T1014 / T1547.006); \
                             {kernel}. Kill tree + posture → COMBAT."
                        ),
                    ));
                }
            }
        }
        // (4) The kernel judged it untrusted (refused or recorded): High.
        if *verdict != ModuleLoadVerdict::NotJudged {
            let why = match (method, file) {
                (ModuleLoadMethod::Init, _) => {
                    "a module from memory (init_module): no file to trust".to_string()
                }
                (_, Some(f)) if *verdict == ModuleLoadVerdict::DkmsUnattested => format!(
                    "the file {}:{} is a DKMS or akmods build its registry vouches for (the \
                     same content), but it was written since boot outside a recognised package \
                     transaction — built by hand, or before the agent started",
                    f.dev, f.ino
                ),
                (_, Some(f)) if f.trust_flags == 0 => format!(
                    "no package or DKMS vouches for the file {}:{} (uid {}, mode {:o}) as it is \
                     now — not in the running kernel's tree, copied or changed by hand",
                    f.dev, f.ino, f.uid, f.mode
                ),
                (_, Some(f)) => format!(
                    "the file {}:{} changed since the agent vouched for it, or its owner or \
                     mode no longer protect it (uid {}, mode {:o})",
                    f.dev, f.ino, f.uid, f.mode
                ),
                (_, None) => "the file could not be read".to_string(),
            };
            return log(
                Severity::High,
                format!(
                    "Kernel module {shown} loaded by '{loader_comm}' (parent '{parent_comm}'): \
                     {why} — {kernel} (T1547.006 / T1014)."
                ),
            );
        }
        // (5) Not judged: by the path and the package database.
        if *method != ModuleLoadMethod::Finit {
            return log(
                Severity::High,
                format!(
                    "Kernel module loaded via init_module(2) by '{loader_comm}' (parent \
                     '{parent_comm}') — a buffer, no file to trust; {kernel} (T1547.006). Alert."
                ),
            );
        }
        let Some(p) = path else {
            return log(
                Severity::High,
                format!(
                    "Kernel module loaded by '{loader_comm}' (parent '{parent_comm}') from a \
                     file whose path the sensor could not read; {kernel} (T1547.006). Alert."
                ),
            );
        };
        if nn_model::module_path_is_truncated(p) {
            // A kernel read failed: the origin is unknown, which is not the
            // same as benign (external audit PROC-004).
            return log(
                Severity::High,
                format!(
                    "Kernel module loaded from a path the sensor could not read to the root \
                     (components: {p}) by '{loader_comm}' (parent '{parent_comm}') — origin \
                     unverifiable; {kernel}. Alert."
                ),
            );
        }
        // External audit PROC-005: a file no package installed and DKMS
        // did not build was put there by hand.
        match self.owners.of(p) {
            Provenance::Package | Provenance::Dkms => None,
            Provenance::Unowned => log(
                Severity::High,
                format!(
                    "Kernel module {p} loaded by '{loader_comm}' (parent '{parent_comm}') is in \
                     a module directory but no package installed it and DKMS did not build it; \
                     {kernel} (T1547.006). Alert."
                ),
            ),
            Provenance::Unknown => log(
                Severity::Medium,
                format!(
                    "Kernel module {p} loaded by '{loader_comm}' (parent '{parent_comm}'), no \
                     package database to ask who installed it; {kernel} (T1547.006). Alert."
                ),
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    // R08b (lab PR 251): on the portable test host.
    use crate::posture::host::testing::TestHost as H;
    type ModuleOwners = crate::decision::rules::module_provenance::ModuleOwners<H>;
    type R018KernelModuleLoad = super::R018KernelModuleLoad<H>;
    use common::module_judge::{trust_flag, verdict as kv};
    use common::wire::{ModuleLoadRaw, MODULE_LOAD_FINIT, MODULE_LOAD_INIT};

    /// The rule on a host with no package database (provenance unknown).
    fn rule() -> R018KernelModuleLoad {
        R018KernelModuleLoad::with_owners(ModuleOwners::new("/nonexistent-root"))
    }

    const TREE: &[&str] = &[
        "/",
        "lib",
        "modules",
        "6.8.0",
        "kernel",
        "net",
        "tls",
        "tls.ko.zst",
    ];

    /// `raw` as the kernel judged it: `verdict`, and for a file its
    /// identity with the trust entry's `flags`.
    fn judged(mut r: ModuleLoadRaw, verdict: u8, flags: u32) -> ModuleLoadRaw {
        r.verdict = verdict;
        if r.method == MODULE_LOAD_FINIT {
            r.file_dev = 0x0080_0001;
            r.file_ino = 4242;
            r.file_mode = 0o100_644;
            r.trust_flags = flags;
        }
        r
    }

    /// External audit PROC-005, lot 285: a load the kernel did not judge
    /// (its trust map not filled yet): a module copied under /lib/modules —
    /// no package lists it, DKMS did not build it — is High whoever loads it
    /// (no loader allowlist); a packaged one is not recorded.
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
        let r = R018KernelModuleLoad::with_owners(ModuleOwners::new(host.path()));
        let copied = [
            "/", "usr", "lib", "modules", "6.8.0", "kernel", "fs", "rk.ko",
        ];
        for (loader, parent) in [
            ("insmod", "bash"),
            ("systemd-udevd", "systemd"),
            ("kmod", "kmod"),
        ] {
            let v = r
                .evaluate(&ev(&raw(MODULE_LOAD_FINIT, loader, parent, 0, &copied)))
                .expect("fires");
            assert_eq!(
                (v.action, v.severity),
                (ResponseAction::Log, Severity::High),
                "{loader}"
            );
        }
        let packaged = ["/", "lib", "modules", "6.8.0", "kernel", "fs", "foo.ko"];
        for loader in ["modprobe", "systemd-udevd"] {
            assert!(r
                .evaluate(&ev(&raw(MODULE_LOAD_FINIT, loader, "bash", 0, &packaged)))
                .is_none());
        }
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
    /// Not judged by the kernel ([`judged`] for a verdict).
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

    /// Lot 285: the wire's verdict and file facts reach the event.
    #[test]
    fn from_carries_the_kernel_verdict_and_the_file() {
        let e = ev(&judged(
            raw(MODULE_LOAD_FINIT, "modprobe", "bash", 0, TREE),
            kv::DENIED,
            0,
        ));
        let Event::ModuleLoad { verdict, file, .. } = e else {
            panic!("not ModuleLoad")
        };
        assert_eq!(verdict, ModuleLoadVerdict::Denied);
        let f = file.expect("the file");
        assert_eq!(
            (f.dev, f.ino, f.mode, f.trust_flags),
            (0x0080_0001, 4242, 0o100_644, 0)
        );
        let e = ev(&judged(
            raw(MODULE_LOAD_INIT, "x", "bash", 0, &[]),
            kv::RECORDED,
            0,
        ));
        let Event::ModuleLoad { verdict, file, .. } = e else {
            panic!("not ModuleLoad")
        };
        assert_eq!((verdict, file), (ModuleLoadVerdict::Recorded, None));
        // an older object: no verdict
        let Event::ModuleLoad { verdict, .. } = ev(&raw(MODULE_LOAD_FINIT, "x", "y", 0, TREE))
        else {
            panic!("not ModuleLoad")
        };
        assert_eq!(verdict, ModuleLoadVerdict::NotJudged);
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
            .expect("no package database: still recorded");
        assert_eq!(v.action, ResponseAction::Log);
        assert_eq!(v.severity, Severity::Medium);
    }

    /// External audit PROC-004: a path deeper than the 16-slot budget is
    /// deeper than any module directory — the depth the loader chose must
    /// not turn the kill into an alert, whoever loads it and whatever the
    /// kernel did.
    #[test]
    fn too_deep_path_is_not_downgraded() {
        let leaf_side: Vec<String> = (0..15).map(|i| format!("d{i}")).collect();
        let mut comps: Vec<&str> = leaf_side.iter().map(String::as_str).collect();
        comps.push("evil.ko");
        for (loader, parent) in [("insmod", "bash"), ("systemd-udevd", "systemd")] {
            for verdict in [kv::NOT_JUDGED, kv::DENIED, kv::RECORDED] {
                let e = ev(&judged(raw_too_deep(loader, parent, &comps), verdict, 0));
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
    }

    /// A path a failed read left unknown comes back RELATIVE and must never
    /// take the Critical/KillTree branch — but unknown is not benign
    /// (external audit PROC-004): High, whoever loads it (lot 285: no
    /// allowlisted loader keeps it silent).
    #[test]
    fn unreadable_path_is_high_log_never_killtree() {
        // No leading "/" component → raw() marks it truncated.
        let tail = ["6.8.0-124-generic", "kernel", "drivers", "x", "deep.ko.zst"];
        for (loader, parent) in [("insmod", "bash"), ("systemd-udevd", "systemd")] {
            let e = ev(&raw(MODULE_LOAD_FINIT, loader, parent, 0, &tail));
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
        }
    }

    /// Lot 285: a kernel thread's child is no exemption — the kernel judges
    /// the file (a request_module's modprobe loads trusted files).
    #[test]
    fn a_kernel_thread_parent_is_no_exemption() {
        let v = rule()
            .evaluate(&ev(&raw(
                MODULE_LOAD_FINIT,
                "modprobe",
                "kworker/0:1",
                1,
                &["/", "tmp", "x.ko"],
            )))
            .expect("judged by the file");
        assert_eq!(v.action, ResponseAction::KillProcessTree);
        let trusted = judged(
            raw(MODULE_LOAD_FINIT, "modprobe", "kworker/0:1", 1, TREE),
            kv::TRUSTED,
            trust_flag::PACKAGE,
        );
        assert!(rule().evaluate(&ev(&trusted)).is_none());
    }

    /// Named test (lot 285): R018's loader allowlist by `comm` is gone — a
    /// process named `kmod`, `systemd-udevd` or `systemd-modules` that loads
    /// a file the kernel does not trust is recorded like any other, and a
    /// trusted file is silent whoever loads it.
    #[test]
    fn r018_comm_allowlist_removed() {
        for (loader, parent) in [
            ("kmod", "systemd"),
            ("modprobe", "systemd-udevd"),
            ("systemd-modules", "systemd"),
            ("insmod", "bash"),
        ] {
            for verdict in [kv::DENIED, kv::RECORDED] {
                let v = rule()
                    .evaluate(&ev(&judged(
                        raw(MODULE_LOAD_FINIT, loader, parent, 0, TREE),
                        verdict,
                        0,
                    )))
                    .unwrap_or_else(|| panic!("{loader}/{parent} recorded"));
                assert_eq!(
                    (v.action, v.severity),
                    (ResponseAction::Log, Severity::High),
                    "{loader}"
                );
            }
            assert!(rule()
                .evaluate(&ev(&judged(
                    raw(MODULE_LOAD_FINIT, loader, parent, 0, TREE),
                    kv::TRUSTED,
                    trust_flag::PACKAGE,
                )))
                .is_none());
        }
        // the rule set builds R018 with nothing to allowlist
        let rules = crate::decision::rules::module_load_rules::<H>();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].id(), "R018_KernelModuleLoad");
        let src = include_str!("r018_kernel_module_load.rs");
        let code = &src[..src.find("#[cfg(test)]").unwrap()];
        assert!(
            !code.contains("CommAllowlist"),
            "R018 keeps a comm allowlist"
        );
        let mod_rs = include_str!("mod.rs");
        let builder = &mod_rs[mod_rs.find("pub fn module_load_rules").unwrap()..];
        let builder = &builder[..builder.find("\n}\n").unwrap()];
        assert!(!builder.contains("CommAllowlist"), "{builder}");
    }

    /// Lot 285: the kernel's verdicts — refused or recorded in the tree:
    /// High; a window or a signed opt-out: Medium; from /tmp: the kill.
    #[test]
    fn the_kernel_verdicts() {
        let r = rule();
        let at = |verdict, flags| {
            r.evaluate(&ev(&judged(
                raw(MODULE_LOAD_FINIT, "modprobe", "bash", 0, TREE),
                verdict,
                flags,
            )))
        };
        let v = at(kv::DENIED, 0).unwrap();
        assert_eq!(
            (v.action, v.severity),
            (ResponseAction::Log, Severity::High)
        );
        assert!(
            v.reasoning.contains("REFUSED by the kernel"),
            "{}",
            v.reasoning
        );
        assert!(
            v.reasoning.contains("no package or DKMS vouches"),
            "{}",
            v.reasoning
        );
        let v = at(kv::RECORDED, trust_flag::PACKAGE).unwrap();
        assert_eq!(
            (v.action, v.severity),
            (ResponseAction::Log, Severity::High)
        );
        assert!(v.reasoning.contains("the record mode"), "{}", v.reasoning);
        assert!(
            v.reasoning.contains("changed since the agent vouched"),
            "{}",
            v.reasoning
        );
        let v = at(kv::WINDOW, 0).unwrap();
        assert_eq!(
            (v.action, v.severity),
            (ResponseAction::Log, Severity::Medium)
        );
        assert!(
            v.reasoning.contains("trusted-installer window"),
            "{}",
            v.reasoning
        );
        assert!(at(kv::TRUSTED, trust_flag::DKMS).is_none());
        let v = r
            .evaluate(&ev(&judged(
                raw(
                    MODULE_LOAD_FINIT,
                    "insmod",
                    "bash",
                    0,
                    &["/", "tmp", "rk.ko"],
                ),
                kv::DENIED,
                0,
            )))
            .unwrap();
        assert_eq!(
            (v.action, v.severity),
            (ResponseAction::KillProcessTree, Severity::Critical)
        );
        assert!(
            v.reasoning.contains("REFUSED by the kernel"),
            "{}",
            v.reasoning
        );
        let v = r
            .evaluate(&ev(&judged(
                raw(MODULE_LOAD_INIT, "x", "bash", 0, &[]),
                kv::DENIED,
                0,
            )))
            .unwrap();
        assert_eq!(
            (v.action, v.severity),
            (ResponseAction::Log, Severity::High)
        );
        assert!(v.reasoning.contains("from memory"), "{}", v.reasoning);
    }

    /// Named test (lot 285, the rule's half): a load a signed per-module
    /// opt-out let through is recorded (Medium), never silent.
    #[test]
    fn a_signed_per_module_opt_out_is_allowed_and_recorded() {
        let v = rule()
            .evaluate(&ev(&judged(
                raw(MODULE_LOAD_FINIT, "modprobe", "bash", 0, TREE),
                kv::OPT_OUT,
                trust_flag::OPT_OUT,
            )))
            .expect("recorded");
        assert_eq!(
            (v.action, v.severity),
            (ResponseAction::Log, Severity::Medium)
        );
        assert!(v.reasoning.contains("opt-out"), "{}", v.reasoning);
    }

    /// Named test (lot 285, the coordinator's matrix, the rule's half): a
    /// DKMS or akmods build the kernel let through as unattested (written
    /// since boot outside a recognised package transaction) is recorded
    /// High, never silent, never killed in the tree; the wire's verdict
    /// reaches the event.
    #[test]
    fn a_registered_dkms_build_written_outside_a_transaction_is_recorded_high() {
        let dkms_tree: &[&str] = &[
            "/",
            "lib",
            "modules",
            "6.8.0",
            "updates",
            "dkms",
            "zfs.ko.zst",
        ];
        let e = ev(&judged(
            raw(MODULE_LOAD_FINIT, "modprobe", "bash", 0, dkms_tree),
            kv::UNATTESTED,
            trust_flag::UNATTESTED,
        ));
        let Event::ModuleLoad { verdict, .. } = &e else {
            panic!("not ModuleLoad")
        };
        assert_eq!(*verdict, ModuleLoadVerdict::DkmsUnattested);
        assert!(!verdict.refused());
        let v = rule().evaluate(&e).expect("recorded");
        assert_eq!(
            (v.action, v.severity),
            (ResponseAction::Log, Severity::High)
        );
        assert!(
            v.reasoning.contains("registry vouches for")
                && v.reasoning
                    .contains("outside a recognised package transaction")
                && v.reasoning.contains("let through by the default policy"),
            "{}",
            v.reasoning
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

    /// SECURITY-CRITICAL: a load from /tmp must fire Critical whatever the
    /// loader's comm.
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
            .expect("non-standard path must fire whatever the comm");
        assert_eq!(v.severity, Severity::Critical);
        assert_eq!(v.action, ResponseAction::KillProcessTree);
    }

    #[test]
    fn fire_legacy_init_module_is_high_log() {
        let v = rule()
            .evaluate(&ev(&raw(MODULE_LOAD_INIT, "python3", "bash", 0, &[])))
            .expect("init_module must fire");
        assert_eq!(v.severity, Severity::High);
        assert_eq!(v.action, ResponseAction::Log); // alert, NOT kill
        assert!(
            v.reasoning.contains("init_module(2)") && v.reasoning.contains("no file to trust"),
            "{}",
            v.reasoning
        );
    }

    #[test]
    fn fire_stdpath_without_a_package_database_is_medium_log() {
        let v = rule()
            .evaluate(&ev(&raw(
                MODULE_LOAD_FINIT,
                "dkms",
                "bash",
                0,
                &["/", "lib", "modules", "6.8.0", "updates", "nvidia.ko"],
            )))
            .expect("standard path, provenance unknown, not judged: recorded");
        assert_eq!(v.severity, Severity::Medium);
        assert_eq!(v.action, ResponseAction::Log); // alert, NOT kill
    }

    #[test]
    fn non_module_event_is_ignored() {
        use crate::decision::rules::testutil::spawn;
        assert!(rule()
            .evaluate(&spawn("insmod", "/usr/sbin/insmod"))
            .is_none());
    }
}
