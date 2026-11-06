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
//! ## By name, the system's tool, nothing moved (lot 279)
//!
//! R011 killed every exec of a module tool that no package-manager actor
//! ran and no kernel thread asked for: the `modprobe` of rootful podman's
//! netfilter modules among them (lot 275's lab: W5 rc 137 on Ubuntu
//! 22.04). An exec is now RECORDED (High, T1547.006, no kill) when its
//! command line asks for modules BY NAME and nothing else could make it
//! load something the system's tree does not name; killed as before
//! otherwise. It is judged on the syntax alone — kmod's lookup is not
//! emulated, no `modprobe.d` or index is read (the coordinator's decision
//! of 04/11, after the independent review of #498):
//!
//! | The exec | R011 |
//! |---|---|
//! | `insmod`, whatever its arguments | kill |
//! | a `modprobe` argument with a `/`, or ending in `.ko`, `.ko.xz`, `.ko.zst`, `.ko.gz` | kill |
//! | `-C`/`--config`, `-d`/`--dirname`, `-S`/`--set-version`, `-f`/`--force*`, `-o`, `--remove-holders`, `--remove-dependencies` (and the abbreviations `getopt_long` takes) | kill |
//! | any argument starting with `-` after the first module name; an option the tool refuses | kill |
//! | a `kmod` command other than `help`, `list`, `static-nodes`, the version | kill |
//! | not the system's tool: its path outside `/usr/bin`, `/usr/sbin`, `/bin`, `/sbin` or another name, its device and inode not those of the file `/usr/bin/kmod` resolves to (as the exec pump stats it), `/usr/bin/kmod` and `/bin/kmod` two different files, a filesystem of another mount namespace | kill |
//! | `MODPROBE_OPTIONS`, `LD_PRELOAD`, `LD_AUDIT` or `LD_LIBRARY_PATH` in its environment (read, it is evidence: killed even if the process has since exited); a running process whose environment the exec pump could not read at the exec; an environment over 1 MiB; an unknown start | kill |
//! | a process that had exited before the exec pump could read its environment (no process with its pid, its pid another's, a zombie, its memory gone), the rest of it recorded — not a leader that exited while another thread runs on: that thread's environment is read and judged, refused when not read whole or when no thread is seen while the kernel counts more than one | record, its environment not verified |
//! | an argv the kernel did not read whole | kill |
//! | in an initramfs build (lot 287: the packaged `update-initramfs`, `mkinitramfs` or `dracut`, run and still running as root, which the exec pump found from the exec's parent up at the exec), a root exec — the environment not refused — of a `#!` script of a system tree outside the tools' places (the hook `kmod`) or of the system's `modprobe` asked to load nothing (`--show-depends`, `--dry-run`, whatever else: `-S`, an argv cut after the flag) | record |
//! | otherwise — the system's tool, plain module names, before the first name only options that move and force nothing | record |
//!
//! Whether the names load anything, and what, is the kernel's to judge at
//! the load: its signature policy (module signing, lockdown: the host check
//! reports both) refuses what it does not trust, and lot 285 adds the
//! kernel's deny of an untrusted file. R018 judges the loads the kernel
//! reports (`kernel_read_file` / `kernel_load_data`, the file's path from
//! its dentry) AFTER them — its hook observes and denies nothing: a load
//! whose loader's parent is a kernel thread has no verdict; a file outside
//! the module directories (or deeper than any) is a Critical kill of the
//! loader's tree, whatever the loader; a file in them that no package
//! installed is a Critical kill, or only a Log when the loader or its
//! parent is in R018's loader allowlist (`systemd-udevd`, `systemd-modules`,
//! `kmod` — comms, which a process chooses); a packaged file loaded by those
//! has NO verdict, by another loader a Log. Every load is a line of the
//! agent's journal, not a signed record. So `execve("/usr/bin/kmod",
//! ["modprobe", "rk"])` of a module copied into the tree and indexed by
//! `depmod` is R011's record and R018's Log, no kill (taking `kmod` out of
//! R018's allowlist goes with lot 285's redesign of R018).
//!
//! What R011 does not see: a root process that loads a module without any
//! tool (its own `finit_module(2)`) — as on `main`, with comm `kmod` maybe
//! no verdict at all (above); a root parent that traces the tool and
//! rewrites its argv or environment after the exec pump read them; code
//! injected into the tool (an `LD_PRELOAD` read too late,
//! `/etc/ld.so.preload`) that forks and lets the tool exit — the pump reads
//! an exited tool (recorded), and a kill of the tool would not reach the
//! child, which runs on out of its tree; a
//! `modprobe.d` `install`/`remove` command — root's configuration, run by
//! `modprobe` through `/bin/sh -c` as programs the exec rules judge (on
//! `main` a user-space `modprobe` was killed, its command then usually not
//! run; the coverage of `modprobe.d` is in `TAPPA9_FIM_TRUST_MODEL.md`).

use std::sync::Arc;

use nn_model::{Event, ResponseAction, Severity, Verdict};

use crate::config::comm_allowlist::CommAllowlist;
use crate::config::comm_allowlist::Judgement;
use crate::decision::attack::{AttackRef, Tactic};
use crate::decision::rules::kmod_exec_facts::{self, KMOD_TOOLS};
use crate::decision::rules::kmod_invocation::{self, Syntax};
use crate::decision::{rules::build_verdict, Rule};
use crate::posture::host::PostureHost;

pub struct R011KernelModuleTooling<H: PostureHost> {
    allowlist: Arc<CommAllowlist<H>>,
    /// Lot 285: the lineage that names a child's parent by what the kernel
    /// executed (production); without it, by the parent's `comm`.
    lineage: Option<crate::posture::lineage::AuthSessionTracker<H>>,
}

impl<H: PostureHost> R011KernelModuleTooling<H> {
    pub fn new(allowlist: Arc<CommAllowlist<H>>) -> Self {
        Self {
            allowlist,
            lineage: None,
        }
    }

    /// Lot 285: with the lineage the parent of a child of the module tool
    /// is read from.
    pub fn with_lineage(
        mut self,
        lineage: Option<crate::posture::lineage::AuthSessionTracker<H>>,
    ) -> Self {
        self.lineage = lineage;
        self
    }

    /// Lot 285: an exec whose parent is the module tool — the command of a
    /// `modprobe.d` `install` or `remove` directive (kmod runs it through
    /// `/bin/sh -c`), or anything the tool was made to run. Recorded
    /// (Medium): a directive is root's configuration, and the
    /// configuration's own writes are NN-L-FIM-026's.
    fn child_of_the_tool(&self, event: &Event) -> Option<Verdict> {
        let Event::ProcessSpawn {
            pid,
            comm,
            filename,
            exe,
            argv,
            parent_comm,
            ..
        } = event
        else {
            return None;
        };
        // the parent's comm first (no lineage walk for every exec): the
        // kernel names the tool it runs for a module request
        // `/sbin/modprobe`, and udev's and the services' runs are named the
        // same
        if !matches!(parent_comm.as_str(), "modprobe" | "kmod" | "insmod") {
            return None;
        }
        // then its image, when the lineage knows it: a process merely named
        // like the tool is not kmod running a directive
        let by_image = self.lineage.as_ref().and_then(|l| {
            l.parent_identity(*pid, crate::posture::lineage::AsOf::of_event(event))
                .map(|p| p.exe.to_str().is_some_and(is_module_tool_image))
        });
        if by_image == Some(false) {
            return None;
        }
        // the hardening guides' `install <module> /bin/true` (or false):
        // the shell kmod runs, and the tool it becomes
        if is_true_or_false(exe.path_or(filename))
            || matches!(argv.as_slice(), [_, c, cmd] if c == "-c" && is_true_or_false(cmd.trim()))
        {
            return None;
        }
        let shown: Vec<&str> = argv.iter().take(8).map(String::as_str).collect();
        Some(build_verdict(
            self,
            event,
            ResponseAction::Log,
            Severity::Medium,
            &format!(
                "'{comm}' ({}) run by the module tool '{parent_comm}' — a modprobe.d \
                 install/remove directive's command, run as root whenever the module is asked \
                 for (T1547.006); argv {shown:?}. Recorded.",
                exe.path_or(filename)
            ),
        ))
    }
}

/// Lot 285: `true` or `false`, by name or system path — a directive that
/// disables a module.
fn is_true_or_false(cmd: &str) -> bool {
    matches!(
        cmd,
        "true" | "false" | "/bin/true" | "/bin/false" | "/usr/bin/true" | "/usr/bin/false"
    )
}

/// Lot 285: kmod's image as the kernel names it (every tool name is a link
/// to it).
fn is_module_tool_image(exe: &str) -> bool {
    matches!(
        exe,
        "/usr/bin/kmod" | "/bin/kmod" | "/usr/sbin/kmod" | "/sbin/kmod"
    )
}

/// Lot 279: the note of a record whose process had exited before the exec
/// pump could read its environment (the coordinator's decision of 04/11: a
/// kill would reach no one).
pub const EXITED_NOTE: &str = "exited before its environment could be read — a load it made is \
                                the kernel's to judge (R018); its environment not verified";

/// Lot 279: `Ok((what it asks for, whether its process had exited before
/// its environment could be read))` when R011 records the exec of a module
/// tool, `Err(why)` when it kills it — its command line's syntax, then what
/// the exec pump read at the exec ([`kmod_exec_facts`]).
fn judge(event: &Event) -> Result<(String, bool), String> {
    let Event::ProcessSpawn {
        filename,
        exe,
        argv,
        argv_truncated,
        ..
    } = event
    else {
        return Err("not an exec".to_string());
    };
    if argv.is_empty() {
        return Err("its argv was not read by the kernel: no argument was checked".to_string());
    }
    if *argv_truncated {
        return Err(format!(
            "its argv was cut at {} bytes: arguments past the cut were not seen",
            common::wire::ARGV_LEN - 1
        ));
    }
    // the kernel named a file of a filesystem this mount namespace does not
    // show (another namespace's root): not the host's tool
    if !exe.path.is_empty() && exe.root != (0, 0) {
        return Err(format!(
            "the program ({}) is in a filesystem the host's mount table does not show (another \
             mount namespace)",
            exe.path
        ));
    }
    let tool = kmod_invocation::tool_of(exe.path_or(filename), argv)?;
    let what = match kmod_invocation::judge(tool, argv) {
        Syntax::Record(what) => what,
        Syntax::Kill(why) => return Err(why),
    };
    match kmod_exec_facts::of(event) {
        None => Err(
            "the exec pump did not read its program and environment at the exec (a replay, or \
             more execs of module tools in flight than it keeps): neither was checked"
                .to_string(),
        ),
        Some(facts) => match facts.refusal() {
            Some(why) => Err(why.to_string()),
            None => Ok((what, facts.exited())),
        },
    }
}

impl<H: PostureHost> Rule for R011KernelModuleTooling<H> {
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
            return self.child_of_the_tool(event);
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
        // Lot 279: judged on the command line's syntax and on what the exec
        // pump read at the exec — recorded (High, no kill) by name, killed as
        // before otherwise.
        let (action, mut reasoning) = match judge(event) {
            Ok((what, false)) => (
                ResponseAction::Log,
                format!(
                    "Kernel-module tooling ({comm}) exec by module name — {what}: the system's \
                     tool, nothing moved or forced, no MODPROBE_OPTIONS or LD_* — recorded, not \
                     killed (lot 279): what the names load is the kernel's to judge (its \
                     signature policy; R018 judges the load it reports, after it) (T1547.006)"
                ),
            ),
            Ok((what, true)) => (
                ResponseAction::Log,
                format!(
                    "Kernel-module tooling ({comm}) exec by module name — {what}: the system's \
                     tool, nothing moved or forced; {EXITED_NOTE} — recorded, not killed (lot \
                     279) (T1547.006)"
                ),
            ),
            Err(why) => (
                super::tool_kill(exe.path_or(filename)),
                format!(
                    "Kernel-module tooling (insmod/modprobe/kmod) exec — kernel rootkit / \
                     persistence indicator (T1547.006); posture → ENGAGED — killed: {why}"
                ),
            ),
        };
        if !parent_comm.is_empty() {
            reasoning = format!("{reasoning}; parent={parent_comm}");
        }
        // External audit PROC-008: and on the program's lineage.
        let v = super::judge_actor(
            &self.allowlist,
            event,
            judgement.apply(
                build_verdict(self, event, action, Severity::High, &reasoning),
                comm,
            ),
        );
        // Lot 283b: and on the package transaction the exec pump read.
        let v = in_package_transaction_at_exec(event, v);
        // Lot 287: and on the initramfs build it read.
        Some(in_initramfs_build_at_exec(event, v))
    }
}

/// Lot 287 (after lot 283b's lab: an administrator's own `sudo
/// update-initramfs -u` exited 137): inside an initramfs build — a builder
/// the exec pump found in the exec's lineage at the exec, the packaged
/// file by its device and inode, run and still running as root
/// ([`ExecFacts::initramfs_builder`]) — a root exec is recorded, not
/// killed, when it is what the build runs:
///
/// - a `#!` script of a system tree, run by an interpreter that is not the
///   module tool ([`ExecFacts::interpreter`]), outside the tools' own
///   places: initramfs-tools' hook `/usr/share/initramfs-tools/hooks/kmod`
///   (comm `kmod`, a shell script that copies kmod into the image); a
///   script loads no module without executing a tool, which R011 judges
///   on its own;
/// - the system's `modprobe` asked to load nothing (`--show-depends`,
///   `--dry-run`, [`kmod_invocation::loads_nothing`]), whatever else it
///   is told (`--set-version`, an argv cut after the dry run):
///   `manual_add_modules` of the initramfs-tools that do not use
///   `dracut-install` (Debian 12, Ubuntu 22.04).
///
/// Still killed in a build: `MODPROBE_OPTIONS`, `LD_PRELOAD`, `LD_AUDIT`,
/// `LD_LIBRARY_PATH` in its environment (or an environment not read from
/// the running process); a tool that is not the system's (a copy, a file
/// of its own in a tool's place, a binary of another name); anything
/// outside a system tree; `insmod`, and a `modprobe` that may load — a
/// hook root plants (`mkinitramfs -d`, `/etc/initramfs-tools/hooks`) does
/// not launder them; a non-root exec, a builder run by no root, a copy of
/// the builder (`/tmp/update-initramfs`).
///
/// [`ExecFacts::initramfs_builder`]: kmod_exec_facts::ExecFacts::initramfs_builder
/// [`ExecFacts::interpreter`]: kmod_exec_facts::ExecFacts::interpreter
fn in_initramfs_build_at_exec(event: &Event, v: Verdict) -> Verdict {
    if v.action == ResponseAction::Log {
        return v;
    }
    let Event::ProcessSpawn {
        uid,
        filename,
        exe,
        argv,
        argv_truncated,
        ..
    } = event
    else {
        return v;
    };
    if *uid != 0 {
        return v;
    }
    let Some(facts) = kmod_exec_facts::of(event) else {
        return v;
    };
    let Some(builder) = facts.initramfs_builder.as_deref() else {
        return v;
    };
    if matches!(facts.environment, kmod_exec_facts::Environment::Refused(_)) {
        return v;
    }
    let image = exe.path_or(filename);
    let what = match (&facts.program, facts.interpreter.as_deref()) {
        (Ok(()), _)
            if kmod_invocation::tool_of(image, argv) == Ok(kmod_invocation::Tool::Modprobe)
                && kmod_invocation::loads_nothing(argv, *argv_truncated) =>
        {
            "the system's modprobe, asked to load nothing (--show-depends or --dry-run)".to_string()
        }
        (Err(_), Some(interpreter))
            if crate::posture::lineage::in_system_tree(image)
                && !kmod_invocation::in_tool_place(image) =>
        {
            format!("a script of a system tree, run by {interpreter} — no module tool")
        }
        _ => return v,
    };
    Verdict {
        action: ResponseAction::Log,
        reasoning: format!(
            "{} [in an initramfs build ({builder}, the packaged file, run by root, read in its \
             lineage at the exec): {what} — recorded, not killed (lot 287)]",
            v.reasoning
        ),
        ..v
    }
}

/// Lot 283b (the coordinator's decision of 06/11/2026, after lot 283a's
/// corpus): a root exec of a program in a system tree whose lineage, as the
/// exec pump read it at the exec ([`ExecFacts::package_manager`]), holds a
/// package manager proper run by root — the criterion of the package
/// transaction the FIM rules, NN-L-NET-008, R009 and the chains read — is
/// recorded, not killed. The case: a dpkg trigger's `update-initramfs`
/// runs `/usr/share/initramfs-tools/hooks/kmod` (comm `kmod`) from forks of
/// `mkinitramfs` that never execute; by the decision they had exited, the
/// lineage walk lost the chain, the trusted-actor record of PROC-008 was
/// not found, and the hook was killed in an `apt upgrade` (a kill that
/// lands aborts the initramfs build). By lineage, never by name: a program
/// outside a system tree (a malicious package's `/tmp/kmod`) or not run by
/// root is judged as before.
///
/// [`ExecFacts::package_manager`]: kmod_exec_facts::ExecFacts::package_manager
fn in_package_transaction_at_exec(event: &Event, v: Verdict) -> Verdict {
    if v.action == ResponseAction::Log {
        return v;
    }
    let Event::ProcessSpawn {
        uid, filename, exe, ..
    } = event
    else {
        return v;
    };
    if *uid != 0 || !crate::posture::lineage::in_system_tree(exe.path_or(filename)) {
        return v;
    }
    let Some(pm) = kmod_exec_facts::of(event).and_then(|f| f.package_manager) else {
        return v;
    };
    Verdict {
        action: ResponseAction::Log,
        reasoning: format!(
            "{} [run in a package transaction ({pm}, run by root, read in its lineage at the \
             exec): recorded, not killed — a kill would leave the transaction half done]",
            v.reasoning
        ),
        ..v
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

    use crate::decision::rules::kmod_exec_facts::{self, Environment, ExecFacts};

    fn rule() -> R011KernelModuleTooling {
        R011KernelModuleTooling::new(Arc::new(CommAllowlist::default()))
    }

    /// Named test (lot 285): a child of the module tool — the command of a
    /// `modprobe.d` install/remove directive, `/bin/sh -c …` — is recorded
    /// (Medium, no kill): its parent named like the tool, and running kmod's
    /// image when the lineage knows it; a shell whose parent is not the
    /// tool is not R011's, nor the hardening guides' `install … /bin/true`.
    #[test]
    fn r011_records_the_children_of_modprobe() {
        let sh = |parent: &str| {
            spawn_full(
                "sh",
                "/bin/sh",
                0,
                &[
                    "sh",
                    "-c",
                    "/usr/local/bin/x; /sbin/modprobe --ignore-install foo",
                ],
                parent,
            )
        };
        let v = rule().evaluate(&sh("modprobe")).expect("recorded");
        assert_eq!(
            (v.action, v.severity),
            (ResponseAction::Log, Severity::Medium)
        );
        assert!(
            v.reasoning.contains("install/remove directive"),
            "{}",
            v.reasoning
        );
        assert!(v.reasoning.contains("/usr/local/bin/x"), "{}", v.reasoning);
        assert!(rule().evaluate(&sh("bash")).is_none());
        // the hardening guides' idiom: `install cramfs /bin/true`
        for cmd in ["/bin/true", "/bin/false", "true", " /usr/bin/false "] {
            let e = spawn_full("sh", "/bin/sh", 0, &["sh", "-c", cmd], "modprobe");
            assert!(rule().evaluate(&e).is_none(), "{cmd}");
        }
        let e = spawn_full("true", "/bin/true", 0, &["/bin/true"], "modprobe");
        assert!(rule().evaluate(&e).is_none());
        let e = spawn_full(
            "sh",
            "/bin/sh",
            0,
            &["sh", "-c", "/bin/true; id"],
            "modprobe",
        );
        assert!(rule().evaluate(&e).is_some());
        // the lineage: the parent's image decides, not its comm
        let tmp = tempfile::tempdir().unwrap();
        let lineage = crate::posture::lineage::AuthSessionTracker::<H>::new(tmp.path());
        lineage.ingest_spawn(77, 1, "/usr/bin/kmod", 1);
        lineage.ingest_spawn(1234, 77, "/usr/bin/dash", 2);
        let r = rule().with_lineage(Some(lineage.clone()));
        let child = |parent_comm: &str| {
            let mut e = sh(parent_comm);
            if let Event::ProcessSpawn { ppid, .. } = &mut e {
                *ppid = 77;
            }
            e
        };
        assert!(r.evaluate(&child("modprobe")).is_some(), "kmod's image");
        let other = crate::posture::lineage::AuthSessionTracker::<H>::new(tmp.path());
        other.ingest_spawn(77, 1, "/usr/bin/bash", 1);
        other.ingest_spawn(1234, 77, "/usr/bin/dash", 2);
        let r = rule().with_lineage(Some(other));
        assert!(
            r.evaluate(&child("modprobe")).is_none(),
            "a comm alone, the image not kmod"
        );
        assert!(is_module_tool_image("/bin/kmod"));
        assert!(!is_module_tool_image("/tmp/kmod"));
    }

    /// Lot 279: a root exec of `exe` as the caller ran it (`filename`),
    /// with `argv` — each its own (pid, exec time), which the facts of the
    /// exec pump are kept by.
    fn exec(filename: &str, exe: &str, argv: &[&str]) -> Event {
        let comm = filename.rsplit('/').next().unwrap();
        let mut e = crate::decision::rules::testutil::spawn_exe(comm, filename, exe, 0);
        if let Event::ProcessSpawn {
            uid,
            gid,
            argv: a,
            pid,
            timestamp_ns,
            parent_comm,
            ..
        } = &mut e
        {
            (*uid, *gid) = (0, 0);
            *a = argv.iter().map(|s| s.to_string()).collect();
            *parent_comm = "bash".to_string();
            static NEXT: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(1);
            let n = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            (*pid, *timestamp_ns) = (2_790_000 + n, 279_000_000 + u64::from(n));
        }
        e
    }

    /// `modprobe <args…>` as xtables and the container runtimes run it.
    fn modprobe(args: &[&str]) -> Event {
        let mut argv = vec!["/sbin/modprobe"];
        argv.extend_from_slice(args);
        exec("/sbin/modprobe", "/usr/bin/kmod", &argv)
    }

    /// `e` as the exec pump read it: `facts`.
    fn read_as(e: Event, facts: ExecFacts) -> Event {
        kmod_exec_facts::keep(&e, facts);
        e
    }

    /// Lot 283b: the initramfs hook `kmod` a dpkg trigger's
    /// update-initramfs runs as root — not the system's module tool — is
    /// recorded when the exec pump read a root package manager in its
    /// lineage at the exec, killed when it read none; a program outside a
    /// system tree, or a non-root exec, is judged as before even under one.
    #[test]
    fn a_dpkg_trigger_s_initramfs_hook_is_recorded_by_lineage() {
        let hook = "/usr/share/initramfs-tools/hooks/kmod";
        let not_tool = |pm: Option<&str>| ExecFacts {
            program: Err("its device and inode are not the system's tool's".into()),
            environment: Environment::Clean,
            package_manager: pm.map(str::to_string),
            initramfs_builder: None,
            interpreter: None,
        };
        let v = rule()
            .evaluate(&read_as(
                exec(hook, hook, &[hook, "prereqs"]),
                not_tool(Some("/usr/bin/dpkg")),
            ))
            .expect("fires");
        assert_eq!(
            (v.action, v.severity),
            (ResponseAction::Log, Severity::High)
        );
        assert!(
            v.reasoning.contains("package transaction (/usr/bin/dpkg"),
            "{}",
            v.reasoning
        );
        let v = rule()
            .evaluate(&read_as(exec(hook, hook, &[hook]), not_tool(None)))
            .expect("fires");
        assert_eq!(v.action, ResponseAction::KillProcess);
        // a staged copy under dpkg: killed with its tree
        let v = rule()
            .evaluate(&read_as(
                exec("/tmp/kmod", "/tmp/kmod", &["/tmp/kmod"]),
                not_tool(Some("/usr/bin/dpkg")),
            ))
            .expect("fires");
        assert_eq!(v.action, ResponseAction::KillProcessTree);
        // a non-root exec: the facts say nothing for it
        let mut e = exec(hook, hook, &[hook]);
        if let Event::ProcessSpawn { uid, .. } = &mut e {
            *uid = 1000;
        }
        let v = rule()
            .evaluate(&read_as(e, not_tool(Some("/usr/bin/dpkg"))))
            .expect("fires");
        assert_ne!(v.action, ResponseAction::Log);
    }

    /// Lot 287: what the exec pump read of an exec under a builder
    /// (`builder`), its program and interpreter, a clean environment.
    fn built(
        builder: Option<&str>,
        program: Result<(), String>,
        interpreter: Option<&str>,
    ) -> ExecFacts {
        ExecFacts {
            program,
            environment: Environment::Clean,
            package_manager: None,
            initramfs_builder: builder.map(str::to_string),
            interpreter: interpreter.map(str::to_string),
        }
    }

    const HOOK: &str = "/usr/share/initramfs-tools/hooks/kmod";
    const UPDATE_INITRAMFS: &str = "/usr/sbin/update-initramfs";

    fn not_tool() -> Result<(), String> {
        Err("its device and inode are not the system's tool's".into())
    }

    /// initramfs-tools' `manual_add_modules` (Debian 12, Ubuntu 22.04).
    const SHOW_DEPENDS: &[&str] = &[
        "modprobe",
        "--all",
        "--set-version=6.8.0-1",
        "--ignore-install",
        "--quiet",
        "--show-depends",
        "ext4",
    ];

    /// Lot 287: the hook `kmod` (a shell script, run by dash) of an
    /// administrator's own `sudo update-initramfs -u` — the exec pump
    /// found the packaged builder, run by root, in its lineage — is
    /// recorded at High; so is the system's modprobe asked to load nothing
    /// (`--set-version` beside it, its argv even cut after the dry run).
    /// Without the builder both are killed, as before.
    #[test]
    fn the_admin_s_update_initramfs_hook_is_recorded() {
        let b = Some(UPDATE_INITRAMFS);
        let v = rule()
            .evaluate(&read_as(
                exec(HOOK, HOOK, &[HOOK, "prereqs"]),
                built(b, not_tool(), Some("/usr/bin/dash")),
            ))
            .expect("fires");
        assert_eq!(
            (v.action, v.severity),
            (ResponseAction::Log, Severity::High)
        );
        for part in [
            "in an initramfs build (/usr/sbin/update-initramfs",
            "a script of a system tree, run by /usr/bin/dash",
        ] {
            assert!(v.reasoning.contains(part), "{part}: {}", v.reasoning);
        }
        let v = rule()
            .evaluate(&read_as(
                exec("/usr/sbin/modprobe", "/usr/bin/kmod", SHOW_DEPENDS),
                built(b, Ok(()), None),
            ))
            .expect("fires");
        assert_eq!(v.action, ResponseAction::Log);
        assert!(
            v.reasoning.contains("asked to load nothing"),
            "{}",
            v.reasoning
        );
        let mut e = exec("/usr/sbin/modprobe", "/usr/bin/kmod", SHOW_DEPENDS);
        if let Event::ProcessSpawn { argv_truncated, .. } = &mut e {
            *argv_truncated = true;
        }
        let v = rule()
            .evaluate(&read_as(e, built(b, Ok(()), None)))
            .expect("fires");
        assert_eq!(v.action, ResponseAction::Log, "{}", v.reasoning);
        // cut at the dry run itself (the word maybe cut): killed
        let mut e = exec(
            "/usr/sbin/modprobe",
            "/usr/bin/kmod",
            &["modprobe", "--set-version=6.8.0-1", "--show-depends"],
        );
        if let Event::ProcessSpawn { argv_truncated, .. } = &mut e {
            *argv_truncated = true;
        }
        let v = rule()
            .evaluate(&read_as(e, built(b, Ok(()), None)))
            .expect("fires");
        assert_eq!(v.action, ResponseAction::KillProcess, "{}", v.reasoning);
        // a record stays the rule's own (by module name)
        let v = rule()
            .evaluate(&read_as(
                modprobe(&["--show-depends", "overlay"]),
                built(b, Ok(()), None),
            ))
            .expect("fires");
        assert_eq!(v.action, ResponseAction::Log);
        assert!(!v.reasoning.contains("initramfs build"), "{}", v.reasoning);
        // no builder found: killed, as before
        let v = rule()
            .evaluate(&read_as(
                exec(HOOK, HOOK, &[HOOK]),
                built(None, not_tool(), Some("/usr/bin/dash")),
            ))
            .expect("fires");
        assert_eq!(v.action, ResponseAction::KillProcess);
        let v = rule()
            .evaluate(&read_as(
                exec("/usr/sbin/modprobe", "/usr/bin/kmod", SHOW_DEPENDS),
                built(None, Ok(()), None),
            ))
            .expect("fires");
        assert_eq!(v.action, ResponseAction::KillProcess);
    }

    /// Lot 287: the same hook under a copy of update-initramfs in `/tmp` —
    /// the exec pump finds no builder (the copy is not the packaged file:
    /// `sensors::kmod_exec`'s tests) — is killed; so is a copy of the hook
    /// in `/tmp`, or a hook outside a system tree, under the real builder.
    #[test]
    fn the_hook_under_a_copy_of_update_initramfs_in_tmp_is_killed() {
        let v = rule()
            .evaluate(&read_as(
                exec(HOOK, HOOK, &[HOOK, "prereqs"]),
                built(None, not_tool(), Some("/usr/bin/dash")),
            ))
            .expect("fires");
        assert_eq!(v.action, ResponseAction::KillProcess);
        for (hook, kill) in [
            ("/tmp/kmod", ResponseAction::KillProcessTree),
            ("/tmp/conf/hooks/kmod", ResponseAction::KillProcessTree),
            (
                "/etc/initramfs-tools/hooks/kmod",
                ResponseAction::KillProcess,
            ),
        ] {
            let v = rule()
                .evaluate(&read_as(
                    exec(hook, hook, &[hook]),
                    built(Some(UPDATE_INITRAMFS), not_tool(), Some("/usr/bin/dash")),
                ))
                .expect("fires");
            assert_eq!(v.action, kill, "{hook}: {}", v.reasoning);
        }
    }

    /// Lot 287: a non-root exec under a builder is killed — the hook of a
    /// build a user runs (`mkinitramfs -o ~/x` as uid 1000: the pump finds
    /// no builder, which must run as root; a user's exec under a root
    /// builder is not root's either).
    #[test]
    fn a_non_root_initramfs_build_is_killed() {
        for builder in [None, Some(UPDATE_INITRAMFS)] {
            let mut e = exec(HOOK, HOOK, &[HOOK]);
            if let Event::ProcessSpawn { uid, .. } = &mut e {
                *uid = 1000;
            }
            let v = rule()
                .evaluate(&read_as(
                    e,
                    built(builder, not_tool(), Some("/usr/bin/dash")),
                ))
                .expect("fires");
            assert_ne!(v.action, ResponseAction::Log, "{builder:?}");
        }
    }

    /// Lot 287: `LD_PRELOAD` (and `MODPROBE_OPTIONS`, `LD_AUDIT`,
    /// `LD_LIBRARY_PATH`, an environment not read) in the environment of an
    /// exec under update-initramfs is killed, the hook's or the dry run's.
    #[test]
    fn ld_preload_under_update_initramfs_is_killed() {
        for why in [
            "LD_PRELOAD='/tmp/x.so' in its environment",
            "MODPROBE_OPTIONS='-d /tmp/x' in its environment",
            "its environment could not be read (Permission denied)",
        ] {
            for (e, program, interpreter) in [
                (exec(HOOK, HOOK, &[HOOK]), not_tool(), Some("/usr/bin/dash")),
                (
                    exec("/usr/sbin/modprobe", "/usr/bin/kmod", SHOW_DEPENDS),
                    Ok(()),
                    None,
                ),
            ] {
                let facts = ExecFacts {
                    environment: Environment::Refused(why.into()),
                    ..built(Some(UPDATE_INITRAMFS), program, interpreter)
                };
                let v = rule().evaluate(&read_as(e, facts)).expect("fires");
                assert_eq!(v.action, ResponseAction::KillProcess, "{why}");
                assert!(!v.reasoning.contains("initramfs build"), "{}", v.reasoning);
            }
        }
        // an exec that had exited before its environment was read: its
        // environment is no refusal
        let facts = ExecFacts {
            environment: Environment::Exited("reaped".into()),
            ..built(Some(UPDATE_INITRAMFS), not_tool(), Some("/usr/bin/dash"))
        };
        let v = rule()
            .evaluate(&read_as(exec(HOOK, HOOK, &[HOOK]), facts))
            .expect("fires");
        assert_eq!(v.action, ResponseAction::Log);
    }

    /// Lot 287: in a build, a tool that is not the system's is killed — a
    /// copy of kmod under a tool's name (a binary: no interpreter), a
    /// script in a tool's own place — and so are the system's `insmod` and
    /// a `modprobe` that may load: a hook root plants does not launder them.
    #[test]
    fn a_tool_that_is_not_the_system_s_is_killed_in_an_initramfs_build() {
        let b = Some(UPDATE_INITRAMFS);
        for (e, facts) in [
            (
                exec(
                    "/usr/lib/x/insmod",
                    "/usr/lib/x/insmod",
                    &["insmod", "/tmp/rk.ko"],
                ),
                built(b, not_tool(), None),
            ),
            (
                exec("/usr/lib/x/kmod", "/usr/lib/x/kmod", &["kmod", "list"]),
                built(b, not_tool(), None),
            ),
            (
                exec("/usr/sbin/modprobe", "/usr/sbin/modprobe", SHOW_DEPENDS),
                built(b, not_tool(), Some("/usr/bin/dash")),
            ),
            (
                exec(
                    "/usr/sbin/insmod",
                    "/usr/bin/kmod",
                    &["insmod", "/tmp/rk.ko"],
                ),
                built(b, Ok(()), None),
            ),
            (
                exec(
                    "/usr/sbin/modprobe",
                    "/usr/bin/kmod",
                    &["modprobe", "--set-version=6.8.0-1", "rk"],
                ),
                built(b, Ok(()), None),
            ),
            (
                exec(
                    "/usr/sbin/modprobe",
                    "/usr/bin/kmod",
                    &["modprobe", "-S", "-D", "rk"],
                ),
                built(b, Ok(()), None),
            ),
            (
                exec("/usr/bin/kmod", "/usr/bin/kmod", &["kmod", "insert", "rk"]),
                built(b, Ok(()), None),
            ),
            // the dry run is modprobe's: insmod is killed whatever its options
            (
                exec(
                    "/usr/sbin/insmod",
                    "/usr/bin/kmod",
                    &["insmod", "-n", "/tmp/rk.ko"],
                ),
                built(b, Ok(()), None),
            ),
        ] {
            let what = format!("{e:?}");
            let v = rule().evaluate(&read_as(e, facts)).expect("fires");
            assert_ne!(v.action, ResponseAction::Log, "{what}: {}", v.reasoning);
        }
    }

    /// `e` as the exec pump read it: the system's tool, no
    /// `MODPROBE_OPTIONS`.
    fn read_ok(e: Event) -> Event {
        read_as(
            e,
            ExecFacts {
                program: Ok(()),
                environment: Environment::Clean,
                package_manager: None,
                initramfs_builder: None,
                interpreter: None,
            },
        )
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
        // the reason is the argv's wherever the program lives (lot 279)
        let e = read_ok(spawn("modprobe", "/tmp/modprobe"));
        let v = rule().evaluate(&e).expect("fires");
        assert!(
            v.reasoning
                .contains("its argv was not read by the kernel: no argument was checked"),
            "{}",
            v.reasoning
        );
    }

    // ─── Lot 279 — by name, the system's tool, nothing moved ────────

    /// Lot 275's lab (W5, Ubuntu 22.04): rootful podman's netfilter
    /// modprobe was killed. The container runtimes', xtables', kube-proxy's
    /// and an administrator's shapes — module names, the system's tool, a
    /// clean environment — are recorded, High, T1547.006, no kill; so is a
    /// query, and a name of no module (nothing is resolved: whatever it
    /// loads is the kernel's to judge).
    #[test]
    fn modprobe_by_name_is_recorded_not_killed() {
        let r = rule();
        for (e, what) in [
            (modprobe(&["ip_tables"]), "modprobe of 'ip_tables'"),
            (
                modprobe(&["-va", "bridge", "br_netfilter"]),
                "modprobe of 'bridge', 'br_netfilter'",
            ),
            (
                exec(
                    "/usr/sbin/modprobe",
                    "/usr/bin/kmod",
                    &["modprobe", "overlay"],
                ),
                "modprobe of 'overlay'",
            ),
            (modprobe(&["--", "ip_vs"]), "modprobe of 'ip_vs'"),
            (
                modprobe(&["-q", "--", "nft-expr-counter"]),
                "modprobe of 'nft-expr-counter'",
            ),
            (modprobe(&["dummy"]), "modprobe of 'dummy'"),
            (modprobe(&["-r", "dummy"]), "modprobe of 'dummy'"),
            (
                modprobe(&["nf_conntrack", "hashsize=1024"]),
                "with 1 parameter",
            ),
            (
                exec("/usr/bin/kmod", "/usr/bin/kmod", &["kmod", "list"]),
                "kmod list",
            ),
            (
                exec("/usr/bin/kmod", "/usr/bin/kmod", &["lsmod"]),
                "kmod run as lsmod",
            ),
        ] {
            let e = read_ok(e);
            let v = r.evaluate(&e).expect("recorded");
            assert_eq!(v.action, ResponseAction::Log, "{e:?}: {}", v.reasoning);
            assert_eq!(v.severity, Severity::High);
            assert_eq!(v.rule_id, "R011_KernelModuleTooling");
            for part in [what, "by module name", "T1547.006", "R018", "parent=bash"] {
                assert!(v.reasoning.contains(part), "{part}: {}", v.reasoning);
            }
        }
    }

    /// Lot 279: what the command line names is killed whatever the pump
    /// read — every malicious shape of deploy/lab/malsim/kmod-check.sh and
    /// the review of #498's (B-1, B-4).
    #[test]
    fn what_the_command_line_names_is_killed() {
        let r = rule();
        for (e, why) in [
            (
                exec(
                    "/usr/sbin/insmod",
                    "/usr/bin/kmod",
                    &["insmod", "/tmp/rk.ko"],
                ),
                "insmod loads the file '/tmp/rk.ko'",
            ),
            (
                exec("/usr/bin/kmod", "/usr/bin/kmod", &["insmod", "/tmp/rk.ko"]),
                "insmod loads the file",
            ),
            (modprobe(&["/tmp/rk.ko"]), "names a file"),
            (modprobe(&["rk.ko"]), "names a file"),
            (modprobe(&["-S", "9.9.9", "dummy"]), "the kernel version"),
            (modprobe(&["-d", "/tmp/root", "dummy"]), "names a file"),
            (modprobe(&["-d", "root", "dummy"]), "the module tree's root"),
            (modprobe(&["-C", "m.conf", "dummy"]), "its configuration"),
            (modprobe(&["--force", "dummy"]), "force"),
            (modprobe(&["--remove-holders", "dummy"]), "as an insertion"),
            (modprobe(&["dummy", "-r"]), "after the module name"),
            (modprobe(&["dummy", "-q"]), "after the module name"),
            (
                exec("/usr/bin/kmod", "/usr/bin/kmod", &["kmod", "insert", "x"]),
                "not one that loads nothing",
            ),
        ] {
            let e = read_ok(e);
            let v = r.evaluate(&e).expect("fires");
            assert_eq!(
                v.action,
                ResponseAction::KillProcess,
                "{e:?}: {}",
                v.reasoning
            );
            assert_eq!(v.severity, Severity::High);
            assert!(v.reasoning.contains(why), "{why}: {}", v.reasoning);
            assert!(v.reasoning.contains("killed: "), "{}", v.reasoning);
        }
        // a copy of the tool in a staging directory: its tree
        let v = r
            .evaluate(&read_ok(exec(
                "/tmp/modprobe",
                "/tmp/modprobe",
                &["modprobe", "dummy"],
            )))
            .expect("fires");
        assert_eq!(v.action, ResponseAction::KillProcessTree);
        assert!(v.reasoning.contains("not the system's module tool"));
    }

    /// Lot 279: what the exec pump read at the exec decides the rest — the
    /// program not the system's tool's file, `MODPROBE_OPTIONS` in the
    /// or a dynamic linker's variable in the environment, a running
    /// process's environment not read, an unknown start, or no reading at
    /// all (a replay): killed, the pump's reason said.
    #[test]
    fn what_the_exec_pump_read_is_judged() {
        let r = rule();
        let v = r.evaluate(&modprobe(&["dummy"])).expect("fires");
        assert_eq!(v.action, ResponseAction::KillProcess);
        assert!(
            v.reasoning.contains("the exec pump did not read"),
            "{}",
            v.reasoning
        );
        for (facts, why) in [
            (
                ExecFacts {
                    program: Err("its device and inode are not the system's tool's".into()),
                    environment: Environment::Clean,
                    package_manager: None,
                    initramfs_builder: None,
                    interpreter: None,
                },
                "not the system's tool's",
            ),
            (
                ExecFacts {
                    program: Ok(()),
                    environment: Environment::Refused(
                        "MODPROBE_OPTIONS='-d /tmp/x' in its environment".into(),
                    ),
                    package_manager: None,
                    initramfs_builder: None,
                    interpreter: None,
                },
                "MODPROBE_OPTIONS='-d /tmp/x'",
            ),
            (
                ExecFacts {
                    program: Ok(()),
                    environment: Environment::Refused(
                        "its environment could not be read (Permission denied)".into(),
                    ),
                    package_manager: None,
                    initramfs_builder: None,
                    interpreter: None,
                },
                "could not be read",
            ),
            (
                ExecFacts {
                    program: Ok(()),
                    environment: Environment::Refused(
                        "LD_PRELOAD='/tmp/x.so' in its environment".into(),
                    ),
                    package_manager: None,
                    initramfs_builder: None,
                    interpreter: None,
                },
                "LD_PRELOAD='/tmp/x.so'",
            ),
            (
                ExecFacts {
                    program: Ok(()),
                    environment: Environment::Refused(
                        "its start is unknown: its environment cannot be tied to the exec".into(),
                    ),
                    package_manager: None,
                    initramfs_builder: None,
                    interpreter: None,
                },
                "its start is unknown",
            ),
        ] {
            let v = r
                .evaluate(&read_as(modprobe(&["dummy"]), facts))
                .expect("fires");
            assert_eq!(v.action, ResponseAction::KillProcess, "{}", v.reasoning);
            assert!(v.reasoning.contains(why), "{why}: {}", v.reasoning);
            assert!(!v.reasoning.contains(EXITED_NOTE), "{}", v.reasoning);
        }
    }

    /// Lot 279, the coordinator's decision of 04/11: a process that had
    /// exited before the exec pump could read its environment is not killed
    /// (the kill would reach no one, a false High kill) — an invocation
    /// recorded otherwise is recorded, noting it. Anything else R011 kills
    /// stays a kill: the command line, a foreign program.
    #[test]
    fn an_exec_whose_process_exited_before_its_environment_was_read_is_recorded_noting_it() {
        let r = rule();
        let exited = || ExecFacts {
            program: Ok(()),
            environment: Environment::Exited("no process had its pid any more".into()),
            package_manager: None,
            initramfs_builder: None,
            interpreter: None,
        };
        for (e, what) in [
            (modprobe(&["overlay"]), "modprobe of 'overlay'"),
            (
                exec("/usr/bin/kmod", "/usr/bin/kmod", &["kmod", "--version"]),
                "kmod: the version printed",
            ),
        ] {
            let v = r.evaluate(&read_as(e, exited())).expect("recorded");
            assert_eq!(v.action, ResponseAction::Log, "{}", v.reasoning);
            assert_eq!(v.severity, Severity::High);
            for part in [what, EXITED_NOTE, "T1547.006", "parent=bash"] {
                assert!(v.reasoning.contains(part), "{part}: {}", v.reasoning);
            }
            assert!(
                !v.reasoning.contains("no MODPROBE_OPTIONS"),
                "{}",
                v.reasoning
            );
        }
        for (e, facts, why) in [
            (modprobe(&["/tmp/rk.ko"]), exited(), "names a file"),
            (
                modprobe(&["-d", "root", "dummy"]),
                exited(),
                "module tree's root",
            ),
            (
                modprobe(&["dummy", "-q"]),
                exited(),
                "after the module name",
            ),
            (
                modprobe(&["dummy"]),
                ExecFacts {
                    program: Err("its device and inode are not the system's tool's".into()),
                    ..exited()
                },
                "not the system's tool's",
            ),
        ] {
            let v = r.evaluate(&read_as(e, facts)).expect("fires");
            assert_eq!(v.action, ResponseAction::KillProcess, "{}", v.reasoning);
            assert!(v.reasoning.contains(why), "{why}: {}", v.reasoning);
        }
        // a copy in a staging directory: its tree, exited or not
        let v = r
            .evaluate(&read_as(
                exec("/tmp/modprobe", "/tmp/modprobe", &["modprobe", "dummy"]),
                exited(),
            ))
            .expect("fires");
        assert_eq!(v.action, ResponseAction::KillProcessTree);
    }

    /// Lot 279: an argv the kernel did not read whole, or a program of a
    /// filesystem the host's mount table does not show, is killed whatever
    /// the pump read.
    #[test]
    fn a_cut_argv_or_another_namespace_s_program_is_killed() {
        let mut cut = modprobe(&["dummy"]);
        if let Event::ProcessSpawn { argv_truncated, .. } = &mut cut {
            *argv_truncated = true;
        }
        let mut other_ns = modprobe(&["dummy"]);
        if let Event::ProcessSpawn { exe, .. } = &mut other_ns {
            exe.root = (8, 2);
        }
        for (e, why) in [
            (cut, "its argv was cut at 511 bytes"),
            (other_ns, "another mount namespace"),
        ] {
            let v = rule().evaluate(&read_ok(e)).expect("fires");
            assert_eq!(v.action, ResponseAction::KillProcess, "{}", v.reasoning);
            assert!(v.reasoning.contains(why), "{why}: {}", v.reasoning);
        }
        // a path the kernel did not give (it names no root then): the
        // caller's path, and the pump's device and inode, are judged
        let mut unnamed = modprobe(&["dummy"]);
        if let Event::ProcessSpawn { exe, .. } = &mut unnamed {
            exe.path.clear();
            exe.root = (8, 2);
        }
        let v = rule().evaluate(&read_ok(unnamed)).expect("recorded");
        assert_eq!(v.action, ResponseAction::Log, "{}", v.reasoning);
    }

    /// Lot 279: the kernel-thread exemption and the allowlist come first,
    /// as before; a forged kworker parent is killed.
    #[test]
    fn the_exemptions_come_before_the_judgement() {
        let mut e = modprobe(&["/tmp/rk.ko"]);
        if let Event::ProcessSpawn {
            parent_comm,
            parent_is_kthread,
            ..
        } = &mut e
        {
            *parent_comm = "kworker/u8:3".to_string();
            *parent_is_kthread = true;
        }
        assert!(rule().evaluate(&e).is_none());
        if let Event::ProcessSpawn {
            parent_is_kthread, ..
        } = &mut e
        {
            *parent_is_kthread = false;
        }
        let v = rule().evaluate(&e).expect("fires");
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
        R011KernelModuleTooling::new(Arc::new(
            CommAllowlist::from_iter_owned(entries).with_identity(tracker),
        ))
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
        let r = R011KernelModuleTooling::new(Arc::new(
            CommAllowlist::from_iter_owned(["modprobe".to_string()]).with_identity(t),
        ));
        let e = crate::decision::rules::testutil::spawn_exe(
            "modprobe",
            "/usr/sbin/modprobe",
            "/usr/sbin/modprobe",
            0,
        );
        assert!(r.evaluate(&e).is_none());
    }
}
