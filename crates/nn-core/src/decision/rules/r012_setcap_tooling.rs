//! R012 — Capability-set tooling exec (Tappa 10.5 D2).
//!
//! MITRE T1548 (Abuse Elevation Control Mechanism). `setcap` grants
//! file capabilities (e.g. `cap_setuid`, `cap_dac_override`) that are
//! a stealthier privilege-escalation primitive than a setuid bit.
//! Design §7.1: comm = `setcap`, gated by `process-comm-allowlist`
//! (a provisioning tool that legitimately sets caps adds its comm to
//! the overlay).
//!
//! Lab PR 166: a copy run from a staging directory is killed with its
//! tree, as R001..R003 would ([`super::tool_kill`]).
//!
//! Lot 373 (the rc7 soak: `libgstreamer1.0-0`'s postinst runs `setcap
//! cap_sys_nice,cap_net_bind_service,cap_net_admin+ep` on its own
//! `gst-ptp-helper` in an `apt-get --only-upgrade`, High): a package's
//! maintainer script granting capabilities to a file of that same package,
//! inside the live package transaction, is recorded Low
//! ([`R012SetcapTooling::package_setcap`]); every other `setcap` is judged
//! as before. NN-L-FIM-025 records the grant itself.
//!
//! The review of #580 (F1): what vouches for "a file of that package" is a
//! path in the package's `.list`, which its own root maintainer script can
//! append to before it calls `setcap` (or it ships a helper of its own).
//! So only a grant of the narrow capabilities
//! ([`crate::fim::file_caps::PACKAGE_NARROW_CAPS`]: `ping`'s `cap_net_raw`,
//! `gst-ptp-helper`'s `cap_sys_nice,cap_net_bind_service,cap_net_admin`) on
//! a file that is no interpreter is lowered; a capability equivalent to
//! root, `=ep` or `all` stays High, inside the transaction too.

use std::sync::Arc;

use nn_model::{Event, ResponseAction, Severity, Verdict};

use crate::config::comm_allowlist::CommAllowlist;
use crate::config::comm_allowlist::Judgement;
use crate::decision::attack::{AttackRef, Tactic};
use crate::decision::{rules::build_verdict, Rule};
use crate::posture::host::PostureHost;

pub struct R012SetcapTooling<H: PostureHost> {
    allowlist: Arc<CommAllowlist<H>>,
}

impl<H: PostureHost> R012SetcapTooling<H> {
    pub fn new(allowlist: Arc<CommAllowlist<H>>) -> Self {
        Self { allowlist }
    }
}

impl<H: PostureHost> Rule for R012SetcapTooling<H> {
    fn id(&self) -> &'static str {
        "R012_SetcapTooling"
    }
    fn name(&self) -> &'static str {
        "Capability-set tooling exec"
    }
    fn category(&self) -> &'static str {
        "privilege_escalation"
    }
    fn attack(&self) -> &'static [AttackRef] {
        const ATTACK: &[AttackRef] = &[AttackRef::new(Tactic::PrivilegeEscalation, "T1548")];
        ATTACK
    }

    fn evaluate(&self, event: &Event) -> Option<Verdict> {
        let Event::ProcessSpawn {
            comm,
            filename,
            exe,
            argv,
            ..
        } = event
        else {
            return None;
        };
        if comm != "setcap" {
            return None;
        }
        // External audit NETR-003 class: the allowlist judged on what the
        // kernel executed, not on the comm the process chose.
        let judgement = super::judge_spawn(&self.allowlist, event);
        if judgement == Judgement::Allowed {
            return None;
        }
        // lot 373: a package's maintainer script on its own files, in its
        // live transaction, by identity
        let not_package = match self.package_setcap(event) {
            Ok(what) => {
                return Some(build_verdict(
                    self,
                    event,
                    ResponseAction::Log,
                    Severity::Low,
                    &format!(
                        "setcap exec — {what}: what a package's maintainer script does to the \
                         package's own files — recorded Low (lot 373); the grant itself is \
                         NN-L-FIM-025's record (T1548)"
                    ),
                ));
            }
            Err(why) => why,
        };
        // D5: a capability spec in argv (e.g. `cap_setuid+ep`) names the
        // exact privilege being granted. Additive — base fires regardless.
        let mut reasoning = String::from(
            "setcap exec — file-capability privilege-escalation primitive \
             (T1548); posture → ENGAGED",
        );
        if let Some(cap) = argv
            .iter()
            .find(|a| a.contains("cap_") || a.contains("+ep") || a.contains("+ei"))
        {
            reasoning = format!("{reasoning} — capability grant in argv ({cap})");
        }
        // the review of #580: which fact of a package's own grant is missing
        if let Some(why) = not_package {
            reasoning = format!("{reasoning} [no package's own narrow grant (lot 373): {why}]");
        }
        // External audit PROC-008: and on the program's lineage.
        Some(super::judge_actor(
            &self.allowlist,
            event,
            judgement.apply(
                build_verdict(
                    self,
                    event,
                    super::tool_kill(exe.path_or(filename)),
                    Severity::High,
                    &reasoning,
                ),
                comm,
            ),
        ))
    }
}

/// Lot 373: where the distributions install the system's `setcap` (libcap).
pub const SETCAP_PATHS: &[&str] = &["/usr/sbin/setcap", "/sbin/setcap"];

/// Lot 373: the files a `setcap` command line names — `setcap [-q] [-v]
/// [-f] [-n <rootid>] (-r <file> | <caps> <file>)…`, every path absolute —
/// or `None` when it names none, or one the line does not show (`-` reads
/// the capabilities from stdin; an option it does not know; a pair cut).
pub fn setcap_targets<S: AsRef<str>>(argv: &[S]) -> Option<Vec<&str>> {
    setcap_operands(argv).map(|ops| ops.into_iter().map(|(_, file)| file).collect())
}

/// Lot 373 (the review of #580, F1): [`setcap_targets`] with each file's
/// capability text (`None` for `-r`, a removal).
pub fn setcap_operands<S: AsRef<str>>(argv: &[S]) -> Option<Vec<(Option<&str>, &str)>> {
    let mut args = argv.iter().skip(1).map(AsRef::as_ref);
    let mut operands = Vec::new();
    while let Some(a) = args.next() {
        let (caps, file) = match a {
            "-q" | "-v" | "-f" => continue,
            "-n" => {
                args.next()?.parse::<u32>().ok()?;
                continue;
            }
            "-r" => (None, args.next()?),
            "-" => return None,
            caps if caps.starts_with('-') => return None,
            caps => (Some(caps), args.next()?),
        };
        if !file.starts_with('/') {
            return None;
        }
        operands.push((caps, file));
    }
    (!operands.is_empty()).then_some(operands)
}

/// Lot 373 (the review of #580, F1): the capabilities a `setcap` command
/// line grants ([`crate::fim::file_caps::caps_text_mask`] of each text, a
/// removal none), or `None` when one text is not read.
pub fn setcap_grants<S: AsRef<str>>(argv: &[S]) -> Option<u64> {
    setcap_operands(argv)?
        .into_iter()
        .try_fold(0u64, |mask, (caps, _)| match caps {
            None => Some(mask),
            Some(text) => crate::fim::file_caps::caps_text_mask(text).map(|m| mask | m),
        })
}

impl<H: PostureHost> R012SetcapTooling<H> {
    /// Lot 373: the exec is a package's maintainer script granting
    /// capabilities to files of that same package, in its live package
    /// transaction — `Ok(what)` when every fact holds, each the kernel's or
    /// dpkg's:
    ///
    /// - root runs the system's `setcap` ([`SETCAP_PATHS`]: the file the
    ///   kernel executed, by its device and inode, is the host's file at
    ///   that path in a root-only directory), its argv read whole;
    /// - its parent's exec (the spawn cache) was dpkg's maintainer script
    ///   of a package (`/var/lib/dpkg/info/<package>.postinst` and its
    ///   kin), run by root, in dpkg's root-only directory;
    /// - that parent runs in a package transaction run by root (the
    ///   lineage's package manager proper, its run covering the exec);
    /// - every file the command line names is one that package installed
    ///   (a line of its `.list`, or the file a line names under another
    ///   spelling of a merged `/usr`, by device and inode), in a system
    ///   tree, in a root-only directory, and is no interpreter or shell;
    /// - the review of #580 (F1): every capability it grants is a narrow one
    ///   ([`crate::fim::file_caps::package_may_lower`]) — the `.list` is the
    ///   package's own maintainer script's to append to, so it vouches for
    ///   nothing equivalent to root.
    ///
    /// A `setcap` from a session (`sudo` included), on a file of no package
    /// or another package's, in a directory a user can write, a copy of the
    /// tool, a non-root exec, a grant beyond the narrow set (`cap_setuid`,
    /// `=ep`, a text not read): R012 as before. What this
    /// trusts is what the package transaction already is: root's packages
    /// and their scripts, for a narrow capability on a helper.
    ///
    /// `Err(why)` names the first fact that does not hold, for the High
    /// record — `None` when the exec is not root's run of a `setcap` at all
    /// that a maintainer script could have made (not root, no lineage).
    pub fn package_setcap(&self, event: &Event) -> Result<String, Option<String>> {
        use common::wire::exe::exe_flags::KNOWN;
        let Event::ProcessSpawn {
            uid,
            ppid,
            exe,
            argv,
            argv_truncated,
            ..
        } = event
        else {
            return Err(None);
        };
        let lineage = self.allowlist.lineage().ok_or(None)?;
        if *uid != 0 {
            return Err(None);
        }
        let why = |s: &str| Some(s.to_string());
        if *argv_truncated {
            return Err(why("its command line was cut"));
        }
        let image = super::program_identity::kernel_image(event)
            .filter(|_| exe.has(KNOWN))
            .ok_or_else(|| why("the file it executed is not known"))?;
        if !SETCAP_PATHS.contains(&image)
            || !lineage.is_host_file_in_root_dir(image, (exe.dev, exe.ino))
        {
            return Err(why("not the system's setcap (its device and inode)"));
        }
        let as_of = crate::posture::lineage::AsOf::of_event(event);
        let package = lineage
            .maintainer_script_package(*ppid, as_of)
            .ok_or_else(|| why("its parent ran no package's maintainer script as root"))?;
        if !lineage.in_package_transaction(*ppid, as_of) {
            return Err(why("its parent is in no package transaction run by root"));
        }
        let files = setcap_targets(argv).ok_or_else(|| why("its files are not read"))?;
        // the review of #580 (F1): narrow capabilities, on no interpreter
        let grants = setcap_grants(argv).ok_or_else(|| why("its capability text is not read"))?;
        if !crate::fim::file_caps::package_may_lower(grants) {
            let beyond = if grants == crate::fim::file_caps::ALL_CAPS {
                "every capability".to_string()
            } else {
                crate::fim::rules::capability_names(
                    grants & !crate::fim::file_caps::PACKAGE_NARROW_CAPS,
                )
            };
            return Err(Some(format!(
                "a grant beyond the narrow set ({beyond}), which no package transaction lowers"
            )));
        }
        if files.iter().any(|f| runs_programs(f)) {
            return Err(why("a file it names is an interpreter or a shell"));
        }
        if let Some(f) = files.iter().find(|f| !lineage.is_package_file(&package, f)) {
            return Err(Some(format!(
                "{f} is no file of {package} (its dpkg list) in a root-only directory"
            )));
        }
        Ok(format!(
            "{image}, the system's tool (its device and inode), run by root by {package}'s \
             maintainer script in a package transaction run by root, on {} — file(s) of {package} \
             (its dpkg list), in root-only directories",
            files.join(", ")
        ))
    }
}

/// The review of #580 (F1): `path` is an interpreter, a shell, busybox or
/// the dynamic loader (`program_identity`'s kinds by name, and the
/// lineage's interpreters) — a file capability on it is one on every
/// program it is given.
fn runs_programs(path: &str) -> bool {
    super::program_identity::ProgramKind::of_name(path).is_some()
        || crate::posture::lineage::is_interpreter(std::path::Path::new(path))
}

#[cfg(test)]
mod tests {
    use super::*;
    // R08b (lab PR 251): on the portable test host.
    use crate::posture::host::testing::TestHost as H;
    type CommAllowlist = crate::config::comm_allowlist::CommAllowlist<H>;
    type R012SetcapTooling = super::R012SetcapTooling<H>;
    use crate::decision::rules::testutil::{spawn, spawn_full};
    use nn_model::ResponseAction;

    fn rule() -> R012SetcapTooling {
        R012SetcapTooling::new(Arc::new(CommAllowlist::default()))
    }

    #[test]
    fn fires_on_setcap() {
        let v = rule()
            .evaluate(&spawn("setcap", "/usr/sbin/setcap"))
            .expect("should fire");
        assert_eq!(v.rule_id, "R012_SetcapTooling");
        assert_eq!(v.action, ResponseAction::KillProcess);
        assert_eq!(v.severity, Severity::High);
        // Graceful degrade: empty argv → base reasoning, no enrichment.
        assert!(!v.reasoning.contains("capability grant"));
    }

    /// Lab PR 166: a staged copy is killed with its tree; the system's
    /// setcap keeps the single-process kill.
    #[test]
    fn r012_staged_copy_kills_the_process_tree() {
        let v = rule()
            .evaluate(&spawn("setcap", "/dev/shm/setcap"))
            .expect("fires");
        assert_eq!(v.action, ResponseAction::KillProcessTree);
        let v = rule()
            .evaluate(&spawn("setcap", "/usr/sbin/setcap"))
            .expect("fires");
        assert_eq!(v.action, ResponseAction::KillProcess);
    }

    #[test]
    fn argv_capability_spec_enriches_reasoning() {
        let ev = spawn_full(
            "setcap",
            "/usr/sbin/setcap",
            0,
            &["setcap", "cap_setuid+ep", "/tmp/x"],
            "bash",
        );
        let v = rule().evaluate(&ev).expect("fires");
        assert!(v.reasoning.contains("capability grant in argv"));
        assert!(v.reasoning.contains("cap_setuid+ep"));
    }

    #[test]
    fn ignores_non_setcap() {
        assert!(rule()
            .evaluate(&spawn("getcap", "/usr/sbin/getcap"))
            .is_none());
        assert!(rule().evaluate(&spawn("ls", "/usr/bin/ls")).is_none());
    }

    /// Lot 373: the files a command line names, or none it hides.
    #[test]
    fn setcap_s_files_are_read_from_its_command_line() {
        assert_eq!(
            super::setcap_targets(&["setcap", "cap_net_raw+ep", "/usr/bin/x"]),
            Some(vec!["/usr/bin/x"])
        );
        assert_eq!(
            super::setcap_targets(&["setcap", "-q", "-n", "0", "cap_a+ep", "/a", "-r", "/b"]),
            Some(vec!["/a", "/b"])
        );
        for hidden in [
            &["setcap"][..],
            &["setcap", "cap_a+ep"],
            &["setcap", "-", "/a"],
            &["setcap", "--bogus", "/a"],
            &["setcap", "cap_a+ep", "relative"],
            &["setcap", "-n", "x", "cap_a+ep", "/a"],
        ] {
            assert_eq!(super::setcap_targets(hidden), None, "{hidden:?}");
        }
    }

    /// Lot 373: a host with dpkg's records of `libgstreamer1.0-0:amd64`
    /// (its `gst-ptp-helper`), `python3.12` and `iputils-ping` (`/usr/bin/ping`
    /// listed, reached as `/bin/ping` on a merged `/usr`), the system's
    /// setcap, and a lineage: apt-get (10) → dpkg (20) → the package's
    /// postinst (30); a root session's shell (60, under sudo 50) and the same
    /// script run by hand from it (70).
    struct PkgHost {
        host: tempfile::TempDir,
        _procs: tempfile::TempDir,
        rule: super::R012SetcapTooling<crate::posture::host::testing::IdTestHost>,
        helper: String,
    }

    const STAT_DEV: u64 = 64769;
    const KDEV: u64 = common::wire::exe::kernel_dev(STAT_DEV);
    const SETCAP: (u64, u64) = (KDEV, 373_001);
    const PKG: &str = "libgstreamer1.0-0:amd64";
    const DIR: &str = "usr/lib/x86_64-linux-gnu/gstreamer1.0/gstreamer-1.0";
    const SOAK_CAPS: &str = "cap_sys_nice,cap_net_bind_service,cap_net_admin+ep";
    const NARROW_CAPS: &str = "cap_net_bind_service,cap_net_raw+ep";
    const S: u64 = 1_000_000_000;
    const B: u64 = 1_000 * S;
    /// The postinst's path as the kernel's read names it: 31 bytes of its
    /// name kept, and the cut marked (external audit EBPF-021).
    const CUT_SCRIPT: &str = "/var/lib/dpkg/info/libgstreamer1.0-0:amd64.postins…";

    impl PkgHost {
        fn new() -> Self {
            use crate::posture::host::testing::IdTestHost;
            use crate::posture::lineage::AuthSessionTracker;
            let helper = format!("/{DIR}/gst-ptp-helper");
            let host = tempfile::tempdir().unwrap();
            let h = |rel: &str| host.path().join(rel.trim_start_matches('/'));
            std::fs::create_dir_all(h("var/lib/dpkg/info")).unwrap();
            std::fs::write(
                h(&format!("var/lib/dpkg/info/{PKG}.list")),
                format!("/.\n/usr\n/{DIR}\n{helper}\n"),
            )
            .unwrap();
            std::fs::write(
                h("var/lib/dpkg/info/python3.12.list"),
                "/usr/bin/python3.12\n",
            )
            .unwrap();
            std::fs::write(
                h("var/lib/dpkg/info/iputils-ping.list"),
                "/.\n/usr\n/usr/bin\n/usr/bin/ping\n/usr/bin/ping4\n/usr/share/doc/iputils-ping\n",
            )
            .unwrap();
            for d in ["var/lib/dpkg/info", DIR, "usr/sbin", "usr/bin", "bin"] {
                IdTestHost::set_dir_root_only(h(d), true);
            }
            IdTestHost::set_file_id(h("usr/sbin/setcap"), Some((STAT_DEV, SETCAP.1)));
            // a merged /usr: /bin/ping is /usr/bin/ping's inode
            IdTestHost::set_file_id(h("usr/bin/ping"), Some((STAT_DEV, 373_010)));
            IdTestHost::set_file_id(h("bin/ping"), Some((STAT_DEV, 373_010)));
            let procs = tempfile::tempdir().unwrap();
            let lineage =
                AuthSessionTracker::<IdTestHost>::new(procs.path()).with_host_root(host.path());
            lineage.ingest_exec(10, 1, "/usr/bin/apt-get", &[], B, B, 0);
            lineage.ingest_exec(20, 10, "/usr/bin/dpkg", &[], B + S, B + S, 0);
            for (pid, pkg) in [(30, PKG), (31, "iputils-ping")] {
                let script = format!("/var/lib/dpkg/info/{pkg}.postinst");
                lineage.ingest_exec(
                    pid,
                    20,
                    &script,
                    &[script.clone(), "configure".into()],
                    B + 2 * S,
                    B + 2 * S,
                    0,
                );
            }
            // the review of #580's lab: the same postinst as the kernel names
            // it (a name of 31 bytes may have been cut: EBPF-021), with the
            // executed file's identity
            let script = format!("/var/lib/dpkg/info/{PKG}.postinst");
            std::fs::write(h(&script), "#!/bin/sh\n").unwrap();
            IdTestHost::set_file_id(h(&script), Some((STAT_DEV, 373_020)));
            let mut cut = spawn_full(
                "sh",
                CUT_SCRIPT,
                0,
                &["/bin/sh", &script, "configure"],
                "dpkg",
            );
            if let Event::ProcessSpawn {
                pid,
                ppid,
                timestamp_ns,
                start_ns,
                exe,
                ..
            } = &mut cut
            {
                (*pid, *ppid, *timestamp_ns, *start_ns) = (32, 20, B + 2 * S, B + 2 * S);
                exe.path = CUT_SCRIPT.to_string();
                (exe.dev, exe.ino, exe.flags) =
                    (KDEV, 373_020, common::wire::exe::exe_flags::KNOWN);
            }
            assert!(lineage.ingest_spawn_event(&cut));
            // a root session's shell, outside any transaction
            lineage.ingest_exec(50, 1, "/usr/bin/sudo", &[], B, B, 0);
            lineage.ingest_exec(60, 50, "/usr/bin/bash", &[], B + S, B + S, 0);
            // the same script run by hand from that session
            let script = format!("/var/lib/dpkg/info/{PKG}.postinst");
            lineage.ingest_exec(
                70,
                60,
                &script,
                &[script.clone(), "configure".into()],
                B + 2 * S,
                B + 2 * S,
                0,
            );
            let rule = super::R012SetcapTooling::<IdTestHost>::new(Arc::new(
                crate::config::comm_allowlist::CommAllowlist::<IdTestHost>::default()
                    .with_identity(lineage),
            ));
            Self {
                host,
                _procs: procs,
                rule,
                helper,
            }
        }

        fn h(&self, rel: &str) -> std::path::PathBuf {
            self.host.path().join(rel.trim_start_matches('/'))
        }

        fn setcap(&self, ppid: u32, image: &str, id: (u64, u64), uid: u32, argv: &[&str]) -> Event {
            use common::wire::exe::exe_flags::KNOWN;
            let mut e = spawn_full("setcap", image, uid, argv, "sh");
            if let Event::ProcessSpawn {
                pid,
                ppid: p,
                exe,
                timestamp_ns,
                gid,
                ..
            } = &mut e
            {
                (*pid, *p, *timestamp_ns, *gid) = (40, ppid, B + 3 * S, uid);
                exe.path = image.to_string();
                (exe.dev, exe.ino) = id;
                exe.flags = KNOWN;
            }
            e
        }

        /// The postinst (30)'s `setcap <argv…>` by the system's tool.
        fn postinst(&self, argv: &[&str]) -> Verdict {
            let mut full = vec!["setcap"];
            full.extend_from_slice(argv);
            self.rule
                .evaluate(&self.setcap(30, "/usr/sbin/setcap", SETCAP, 0, &full))
                .expect("fires")
        }
    }

    impl Drop for PkgHost {
        fn drop(&mut self) {
            use crate::posture::host::testing::IdTestHost;
            for d in ["var/lib/dpkg/info", DIR, "usr/sbin", "usr/bin", "bin"] {
                IdTestHost::set_dir_root_only(self.h(d), false);
            }
            for f in [
                "usr/sbin/setcap",
                "usr/bin/ping",
                "bin/ping",
                "var/lib/dpkg/info/libgstreamer1.0-0:amd64.postinst",
            ] {
                IdTestHost::set_file_id(self.h(f), None);
            }
        }
    }

    fn assert_low(v: &Verdict) {
        assert_eq!(
            (v.severity, v.action.clone()),
            (Severity::Low, ResponseAction::Log),
            "{}",
            v.reasoning
        );
        assert!(v.reasoning.contains("lot 373"), "{}", v.reasoning);
    }

    fn assert_high(v: &Verdict, why: &str) {
        assert_eq!(v.severity, Severity::High, "{why}: {}", v.reasoning);
    }

    /// Lot 373 (named, the rc7 soak: `libgstreamer1.0-0`'s postinst in an
    /// `apt-get --only-upgrade` — R012 High on main): the system's setcap,
    /// run by root by a package's maintainer script, in that live package
    /// transaction, granting a narrow capability to a file of that same
    /// package, is recorded Low. The attack shapes stay High: a setcap from
    /// a root session (outside any transaction), on a file of no package or
    /// another package's, in a directory a user can write, a copy of the
    /// tool, a non-root run, a command line cut.
    ///
    /// The review of #580 (F1): the soak's own grant
    /// (`cap_sys_nice,cap_net_bind_service,cap_net_admin`) is a narrow one,
    /// Low; a root-equivalent one stays High (the next test).
    #[test]
    fn a_postinst_setcap_on_its_own_package_s_file_is_low() {
        use crate::posture::host::testing::IdTestHost;
        let f = PkgHost::new();
        let helper = f.helper.clone();
        let v = f.postinst(&[SOAK_CAPS, &helper]);
        assert_low(&v);
        assert!(v.reasoning.contains(PKG), "{}", v.reasoning);
        assert_low(&f.postinst(&[NARROW_CAPS, &helper]));
        // the attack shapes: High, as before
        let high = |e: Event, why: &str| assert_high(&f.rule.evaluate(&e).expect("fires"), why);
        let setcap = |ppid, image, id, uid, argv: &[&str]| f.setcap(ppid, image, id, uid, argv);
        high(
            setcap(
                60,
                "/usr/sbin/setcap",
                SETCAP,
                0,
                &["setcap", "cap_setuid+ep", "/tmp/x"],
            ),
            "a session, /tmp",
        );
        high(
            setcap(
                60,
                "/usr/sbin/setcap",
                SETCAP,
                0,
                &["setcap", NARROW_CAPS, &helper],
            ),
            "a session, the package's file",
        );
        high(
            setcap(
                70,
                "/usr/sbin/setcap",
                SETCAP,
                0,
                &["setcap", NARROW_CAPS, &helper],
            ),
            "the script run by hand",
        );
        high(
            setcap(
                30,
                "/usr/sbin/setcap",
                SETCAP,
                0,
                &["setcap", NARROW_CAPS, "/tmp/x"],
            ),
            "no package's file",
        );
        high(
            setcap(
                30,
                "/usr/sbin/setcap",
                SETCAP,
                0,
                &["setcap", NARROW_CAPS, "/usr/bin/python3.12"],
            ),
            "another package's file",
        );
        high(
            setcap(
                30,
                "/usr/sbin/setcap",
                SETCAP,
                0,
                &["setcap", NARROW_CAPS, &helper, NARROW_CAPS, "/tmp/x"],
            ),
            "one file of the line not the package's",
        );
        high(
            setcap(
                30,
                "/tmp/setcap",
                (KDEV, 373_002),
                0,
                &["setcap", NARROW_CAPS, &helper],
            ),
            "a copy",
        );
        high(
            setcap(
                30,
                "/usr/sbin/setcap",
                (KDEV, 373_002),
                0,
                &["setcap", NARROW_CAPS, &helper],
            ),
            "another file at the path",
        );
        high(
            setcap(
                30,
                "/usr/sbin/setcap",
                SETCAP,
                1000,
                &["setcap", NARROW_CAPS, &helper],
            ),
            "not root",
        );
        let mut cut = setcap(
            30,
            "/usr/sbin/setcap",
            SETCAP,
            0,
            &["setcap", NARROW_CAPS, &helper],
        );
        if let Event::ProcessSpawn { argv_truncated, .. } = &mut cut {
            *argv_truncated = true;
        }
        high(cut, "argv cut");
        IdTestHost::set_dir_root_only(f.h(DIR), false);
        assert_high(&f.postinst(&[NARROW_CAPS, &helper]), "a writable directory");
        IdTestHost::set_dir_root_only(f.h(DIR), true);
        IdTestHost::set_dir_root_only(f.h("var/lib/dpkg/info"), false);
        assert_high(&f.postinst(&[NARROW_CAPS, &helper]), "dpkg's info writable");
    }

    /// Lot 373 (named, the review of #580, F1 — its probe: the package's
    /// root postinst appends `/usr/bin/python3.12` to its OWN `.list`, then
    /// `setcap cap_setuid+ep` on it, Low on the PR's head): a grant of a
    /// capability equivalent to root, of every capability (`=ep`, `all`) or one not read stays High inside the
    /// package transaction too — on a path the `.list` was made to name,
    /// and on a helper the package ships itself; and a narrow capability on
    /// an interpreter the `.list` names stays High.
    #[test]
    fn a_postinst_setcap_of_a_root_equivalent_capability_stays_high() {
        let f = PkgHost::new();
        let helper = f.helper.clone();
        // the probe: the script appends another package's file to its own
        // .list
        std::fs::write(
            f.h(&format!("var/lib/dpkg/info/{PKG}.list")),
            format!("/.\n/usr\n/{DIR}\n{helper}\n/usr/bin/python3.12\n"),
        )
        .unwrap();
        crate::posture::host::testing::IdTestHost::set_dir_root_only(f.h("usr/bin"), true);
        for target in ["/usr/bin/python3.12", helper.as_str()] {
            for caps in [
                "cap_setuid+ep",
                "cap_setgid+ep",
                "cap_sys_admin+ep",
                "cap_sys_module+ep",
                "cap_sys_ptrace+ep",
                "cap_dac_override+ep",
                "cap_dac_read_search+ep",
                "cap_chown+ep",
                "cap_fowner+ep",
                "cap_bpf+ep",
                "cap_sys_rawio+ep",
                "cap_setfcap+ep",
                "=ep",
                "all+ep",
                "7+ep",
                "CAP_SETUID+ep",
                "cap_net_raw+ep cap_setuid+p",
                "cap_net_raw,cap_bogus+ep",
                "cap_net_admin,cap_setuid+ep",
            ] {
                assert_high(&f.postinst(&[caps, target]), &format!("{caps} on {target}"));
            }
        }
        // the record says why
        let v = f.postinst(&["cap_setuid+ep", "/usr/bin/python3.12"]);
        assert!(
            v.reasoning.contains("beyond the narrow set (cap_setuid)"),
            "{}",
            v.reasoning
        );
        let v = f.postinst(&["=ep", &helper]);
        assert!(
            v.reasoning.contains("(every capability)"),
            "{}",
            v.reasoning
        );
        // two pairs: one root-equivalent grant is enough
        assert_high(
            &f.postinst(&[NARROW_CAPS, &helper, "cap_setuid+ep", &helper]),
            "a second pair",
        );
        // a narrow capability on an interpreter, busybox or the loader the
        // .list names
        std::fs::write(
            f.h(&format!("var/lib/dpkg/info/{PKG}.list")),
            format!(
                "/.\n/usr\n/{DIR}\n{helper}\n/usr/bin/python3.12\n/usr/bin/busybox\n\
                 /usr/lib64/ld-linux-x86-64.so.2\n"
            ),
        )
        .unwrap();
        crate::posture::host::testing::IdTestHost::set_dir_root_only(f.h("usr/lib64"), true);
        for runs in [
            "/usr/bin/python3.12",
            "/usr/bin/busybox",
            "/usr/lib64/ld-linux-x86-64.so.2",
        ] {
            let v = f.postinst(&["cap_net_raw+ep", runs]);
            assert_high(&v, runs);
            assert!(
                v.reasoning.contains("an interpreter or a shell"),
                "{runs}: {}",
                v.reasoning
            );
        }
        crate::posture::host::testing::IdTestHost::set_dir_root_only(f.h("usr/lib64"), false);
        // and the narrow one on the package's own helper stays Low
        assert_low(&f.postinst(&["cap_net_raw+ep", &helper]));
        assert_low(&f.postinst(&["-r", &helper]));
    }

    /// Lot 373 (named, the review of #580's lab: `libgstreamer1.0-0:amd64.
    /// postinst` is 32 bytes, so the kernel's read of the exec's path cut its
    /// name to 31 and marked it (EBPF-021) — "its parent ran no package's
    /// maintainer script", High on Ubuntu 26.04): a cut name in dpkg's info
    /// directory is the one file there whose name begins so and that is the
    /// executed file, by device and inode. Another file at the path, or two
    /// files the cut name could be, stay High.
    #[test]
    fn a_postinst_whose_name_the_kernel_cut_is_named_by_its_identity() {
        use crate::posture::host::testing::IdTestHost;
        let f = PkgHost::new();
        let helper = f.helper.clone();
        let setcap = || {
            f.rule
                .evaluate(&f.setcap(
                    32,
                    "/usr/sbin/setcap",
                    SETCAP,
                    0,
                    &["setcap", SOAK_CAPS, &helper],
                ))
                .expect("fires")
        };
        let v = setcap();
        assert_low(&v);
        assert!(v.reasoning.contains(PKG), "{}", v.reasoning);
        let script = f.h(&format!("var/lib/dpkg/info/{PKG}.postinst"));
        IdTestHost::set_file_id(&script, Some((STAT_DEV, 373_021)));
        let v = setcap();
        assert_high(&v, "another file at the path");
        assert!(
            v.reasoning.contains("no package's maintainer script"),
            "{}",
            v.reasoning
        );
        IdTestHost::set_file_id(&script, Some((STAT_DEV, 373_020)));
        assert_low(&setcap());
        // a second file the cut name could be — another package's postinst,
        // that package's list naming the helper too — whichever comes first
        let twin_pkg = format!("{PKG}.postins");
        let twin = f.h(&format!("var/lib/dpkg/info/{twin_pkg}.postinst"));
        std::fs::write(&twin, "#!/bin/sh\n").unwrap();
        std::fs::write(
            f.h(&format!("var/lib/dpkg/info/{twin_pkg}.list")),
            format!("/{DIR}\n{helper}\n"),
        )
        .unwrap();
        IdTestHost::set_file_id(&twin, Some((STAT_DEV, 373_020)));
        assert_high(&setcap(), "two files the cut name could be");
        IdTestHost::set_file_id(&twin, None);
    }

    /// The review of #580 (re-check 1, N1, named): libcap reads a capability
    /// NUMBER with `strtoul(.., 0)`, so `023` is octal 19 (`cap_sys_ptrace`),
    /// not decimal 23 (`cap_sys_nice`). A number that is not a plain decimal
    /// is not read: High.
    #[test]
    fn a_postinst_setcap_with_an_octal_or_ambiguous_number_is_high() {
        let f = PkgHost::new();
        let helper = f.helper.clone();
        for caps in [
            "023+ep",
            "0023+ep",
            "010+ep",
            "036+ep",
            "0x13+ep",
            "+23+ep",
            "99+ep",
            "18446744073709551616+ep",
        ] {
            let v = f.postinst(&[caps, &helper]);
            assert_eq!(v.severity, Severity::High, "{caps}: {}", v.reasoning);
        }
    }

    /// Lot 373 (named, the lab of lot 373: `iputils-ping`'s postinst runs
    /// `setcap cap_net_raw+ep /bin/ping`, its `.list` names `/usr/bin/ping` —
    /// High on the PR's head): on a merged `/usr` the file a `.list` line
    /// names is matched by its device and inode under another spelling. A
    /// different file at the other spelling stays High.
    #[test]
    fn a_postinst_setcap_through_a_merged_usr_is_the_package_s_file() {
        use crate::posture::host::testing::IdTestHost;
        let f = PkgHost::new();
        let ping = |ppid: u32, file: &str| {
            f.rule
                .evaluate(&f.setcap(
                    ppid,
                    "/usr/sbin/setcap",
                    SETCAP,
                    0,
                    &["setcap", "cap_net_raw+ep", file],
                ))
                .expect("fires")
        };
        assert_low(&ping(31, "/bin/ping"));
        assert_low(&ping(31, "/usr/bin/ping"));
        let v = ping(31, "/bin/ping4");
        assert_high(&v, "a file the .list does not name");
        assert!(
            v.reasoning
                .contains("/bin/ping4 is no file of iputils-ping"),
            "{}",
            v.reasoning
        );
        assert_high(&ping(30, "/bin/ping"), "another package's script");
        IdTestHost::set_file_id(f.h("bin/ping"), Some((STAT_DEV, 373_011)));
        assert_high(&ping(31, "/bin/ping"), "another file at the other spelling");
        IdTestHost::set_file_id(f.h("bin/ping"), None);
        assert_high(&ping(31, "/bin/ping"), "no file at the other spelling");
        IdTestHost::set_file_id(f.h("bin/ping"), Some((STAT_DEV, 373_010)));
        IdTestHost::set_dir_root_only(f.h("bin"), false);
        assert_high(&ping(31, "/bin/ping"), "a writable directory");
    }

    #[test]
    fn allowlisted_comm_is_exempt() {
        let r = R012SetcapTooling::new(Arc::new(CommAllowlist::from_iter_owned([
            "setcap".to_string()
        ])));
        assert!(r.evaluate(&spawn("setcap", "/usr/sbin/setcap")).is_none());
    }
}
