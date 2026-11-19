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
//! as before. NN-L-FIM-025 still records the grant itself.

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
        if let Some(what) = self.package_setcap(event) {
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
    let mut args = argv.iter().skip(1).map(AsRef::as_ref);
    let mut files = Vec::new();
    while let Some(a) = args.next() {
        let file = match a {
            "-q" | "-v" | "-f" => continue,
            "-n" => {
                args.next()?.parse::<u32>().ok()?;
                continue;
            }
            "-r" => args.next()?,
            "-" => return None,
            caps if caps.starts_with('-') => return None,
            _caps => args.next()?,
        };
        if !file.starts_with('/') {
            return None;
        }
        files.push(file);
    }
    (!files.is_empty()).then_some(files)
}

impl<H: PostureHost> R012SetcapTooling<H> {
    /// Lot 373: the exec is a package's maintainer script granting
    /// capabilities to files of that same package, in its live package
    /// transaction — `Some(what)` when every fact holds, each the kernel's or
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
    ///   (a line of its `.list`), in a system tree, in a root-only
    ///   directory.
    ///
    /// A `setcap` from a session (`sudo` included), on a file of no package
    /// or another package's, in a directory a user can write, a copy of the
    /// tool, a non-root exec: R012 as before. What this trusts is what the
    /// package transaction already is: root's packages and their scripts.
    pub fn package_setcap(&self, event: &Event) -> Option<String> {
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
            return None;
        };
        if *uid != 0 || !exe.has(KNOWN) || *argv_truncated {
            return None;
        }
        let image = super::program_identity::kernel_image(event)?;
        let lineage = self.allowlist.lineage()?;
        if !SETCAP_PATHS.contains(&image)
            || !lineage.is_host_file_in_root_dir(image, (exe.dev, exe.ino))
        {
            return None;
        }
        let as_of = crate::posture::lineage::AsOf::of_event(event);
        let package = lineage.maintainer_script_package(*ppid, as_of)?;
        if !lineage.in_package_transaction(*ppid, as_of) {
            return None;
        }
        let files = setcap_targets(argv)?;
        if !files.iter().all(|f| lineage.is_package_file(&package, f)) {
            return None;
        }
        Some(format!(
            "{image}, the system's tool (its device and inode), run by root by {package}'s \
             maintainer script in a package transaction run by root, on {} — file(s) of {package} \
             (its dpkg list), in root-only directories",
            files.join(", ")
        ))
    }
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

    /// Lot 373 (named, the rc7 soak: `libgstreamer1.0-0`'s postinst in an
    /// `apt-get --only-upgrade` — R012 High on main): the system's setcap,
    /// run by root by a package's maintainer script, in that live package
    /// transaction, on a file of that same package, is recorded Low. The
    /// attack shapes stay High: a setcap from a root session (outside any
    /// transaction), on a file of no package or another package's, in a
    /// directory a user can write, a copy of the tool, a non-root run, a
    /// command line cut.
    #[test]
    fn a_postinst_setcap_on_its_own_package_s_file_is_low() {
        use crate::posture::host::testing::IdTestHost;
        use crate::posture::lineage::AuthSessionTracker;
        use common::wire::exe::exe_flags::KNOWN;
        const STAT_DEV: u64 = 64769;
        const KDEV: u64 = common::wire::exe::kernel_dev(STAT_DEV);
        const SETCAP: (u64, u64) = (KDEV, 373_001);
        const PKG: &str = "libgstreamer1.0-0:amd64";
        const DIR: &str = "usr/lib/x86_64-linux-gnu/gstreamer1.0/gstreamer-1.0";
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
        for d in ["var/lib/dpkg/info", DIR, "usr/sbin", "usr/bin"] {
            IdTestHost::set_dir_root_only(h(d), true);
        }
        IdTestHost::set_file_id(h("usr/sbin/setcap"), Some((STAT_DEV, SETCAP.1)));
        let procs = tempfile::tempdir().unwrap();
        let lineage =
            AuthSessionTracker::<IdTestHost>::new(procs.path()).with_host_root(host.path());
        const S: u64 = 1_000_000_000;
        let b = 1_000 * S;
        let script = format!("/var/lib/dpkg/info/{PKG}.postinst");
        lineage.ingest_exec(10, 1, "/usr/bin/apt-get", &[], b, b, 0);
        lineage.ingest_exec(20, 10, "/usr/bin/dpkg", &[], b + S, b + S, 0);
        lineage.ingest_exec(
            30,
            20,
            &script,
            &[script.clone(), "configure".into()],
            b + 2 * S,
            b + 2 * S,
            0,
        );
        // a root session's shell, outside any transaction
        lineage.ingest_exec(50, 1, "/usr/bin/sudo", &[], b, b, 0);
        lineage.ingest_exec(60, 50, "/usr/bin/bash", &[], b + S, b + S, 0);
        // the same script run by hand from that session
        lineage.ingest_exec(
            70,
            60,
            &script,
            &[script.clone(), "configure".into()],
            b + 2 * S,
            b + 2 * S,
            0,
        );
        let rule = super::R012SetcapTooling::<IdTestHost>::new(Arc::new(
            crate::config::comm_allowlist::CommAllowlist::<IdTestHost>::default()
                .with_identity(lineage),
        ));
        let setcap = |ppid: u32, image: &str, id: (u64, u64), uid: u32, argv: &[&str]| {
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
                (*pid, *p, *timestamp_ns, *gid) = (40, ppid, b + 3 * S, uid);
                exe.path = image.to_string();
                (exe.dev, exe.ino) = id;
                exe.flags = KNOWN;
            }
            e
        };
        let caps = "cap_sys_nice,cap_net_bind_service,cap_net_admin+ep";
        let v = rule
            .evaluate(&setcap(
                30,
                "/usr/sbin/setcap",
                SETCAP,
                0,
                &["setcap", caps, &helper],
            ))
            .expect("recorded");
        assert_eq!(
            (v.severity, v.action.clone()),
            (Severity::Low, ResponseAction::Log),
            "{}",
            v.reasoning
        );
        assert!(
            v.reasoning.contains(PKG) && v.reasoning.contains("lot 373"),
            "{}",
            v.reasoning
        );
        // the attack shapes: High, as before
        let high = |e: Event, why: &str| {
            let v = rule.evaluate(&e).expect("fires");
            assert_eq!(v.severity, Severity::High, "{why}: {}", v.reasoning);
        };
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
                &["setcap", caps, &helper],
            ),
            "a session, the package's file",
        );
        high(
            setcap(
                70,
                "/usr/sbin/setcap",
                SETCAP,
                0,
                &["setcap", caps, &helper],
            ),
            "the script run by hand",
        );
        high(
            setcap(
                30,
                "/usr/sbin/setcap",
                SETCAP,
                0,
                &["setcap", "cap_setuid+ep", "/tmp/x"],
            ),
            "no package's file",
        );
        high(
            setcap(
                30,
                "/usr/sbin/setcap",
                SETCAP,
                0,
                &["setcap", "cap_setuid+ep", "/usr/bin/python3.12"],
            ),
            "another package's file",
        );
        high(
            setcap(
                30,
                "/usr/sbin/setcap",
                SETCAP,
                0,
                &["setcap", caps, &helper, "cap_setuid+ep", "/tmp/x"],
            ),
            "one file of the line not the package's",
        );
        high(
            setcap(
                30,
                "/tmp/setcap",
                (KDEV, 373_002),
                0,
                &["setcap", caps, &helper],
            ),
            "a copy",
        );
        high(
            setcap(
                30,
                "/usr/sbin/setcap",
                (KDEV, 373_002),
                0,
                &["setcap", caps, &helper],
            ),
            "another file at the path",
        );
        high(
            setcap(
                30,
                "/usr/sbin/setcap",
                SETCAP,
                1000,
                &["setcap", caps, &helper],
            ),
            "not root",
        );
        let mut cut = setcap(
            30,
            "/usr/sbin/setcap",
            SETCAP,
            0,
            &["setcap", caps, &helper],
        );
        if let Event::ProcessSpawn { argv_truncated, .. } = &mut cut {
            *argv_truncated = true;
        }
        high(cut, "argv cut");
        IdTestHost::set_dir_root_only(h(DIR), false);
        high(
            setcap(
                30,
                "/usr/sbin/setcap",
                SETCAP,
                0,
                &["setcap", caps, &helper],
            ),
            "a writable directory",
        );
        IdTestHost::set_dir_root_only(h(DIR), true);
        IdTestHost::set_dir_root_only(h("var/lib/dpkg/info"), false);
        high(
            setcap(
                30,
                "/usr/sbin/setcap",
                SETCAP,
                0,
                &["setcap", caps, &helper],
            ),
            "dpkg's info writable",
        );
        for d in ["var/lib/dpkg/info", DIR, "usr/sbin", "usr/bin"] {
            IdTestHost::set_dir_root_only(h(d), false);
        }
        IdTestHost::set_file_id(h("usr/sbin/setcap"), None);
    }

    #[test]
    fn allowlisted_comm_is_exempt() {
        let r = R012SetcapTooling::new(Arc::new(CommAllowlist::from_iter_owned([
            "setcap".to_string()
        ])));
        assert!(r.evaluate(&spawn("setcap", "/usr/sbin/setcap")).is_none());
    }
}
