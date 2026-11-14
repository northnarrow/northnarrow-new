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
//! | lot 347: forked by the installed `containerd` or `dockerd` (the kernel's fork record, the image's identity), root, the system's tool, a container runtime's modules by name ([`RUNTIME_MODULES`], [`RUNTIME_MODULE_FAMILIES`]) and no parameter, its environment clean, exited, or refused only for containerd's `opt` plugin's `LD_LIBRARY_PATH` | record, Low |
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

use crate::decision::rules::program_identity::{self, ProgramKind};

use crate::config::comm_allowlist::CommAllowlist;
use crate::config::comm_allowlist::Judgement;
use crate::decision::attack::{AttackRef, Tactic};
use crate::decision::rules::kmod_exec_facts::{self, KMOD_TOOLS};
use crate::decision::rules::kmod_invocation::{self, Syntax};
use crate::decision::{rules::build_verdict, Rule};
use crate::posture::host::PostureHost;

/// Lot 347: the modules a container runtime asks for at its start, by
/// their exact names (kmod reads `-` and `_` alike): its storage drivers
/// (`overlay`, containerd 1.7's `aufs` probe, `erofs`), the bridge and its
/// netfilter, `veth`, the IPsec transforms of Docker's overlay networks
/// and the legacy iptables tables.
const RUNTIME_MODULES: &[&str] = &[
    "overlay",
    "aufs",
    "erofs",
    "bridge",
    "br_netfilter",
    "veth",
    "xfrm_user",
    "xfrm_algo",
    "ip_tables",
    "ip6_tables",
];

/// Lot 347: … and by their family (a prefix): netfilter's, nftables',
/// xtables' matches and targets, iptables' tables.
const RUNTIME_MODULE_FAMILIES: &[&str] = &["nf_", "nft_", "xt_", "iptable_", "ip6table_"];

/// Lot 347: the installed managers whose own probes of those modules R011
/// records Low ([`ProgramKind::RuntimeManager`], by the installed file's
/// name).
const MODULE_PROBING_MANAGERS: &[&str] = &["containerd", "dockerd"];

/// Lot 347: the library directory of containerd's `opt` plugin, which it
/// puts in the `LD_LIBRARY_PATH` of itself and its children (`<root>/lib`;
/// Debian's root `/var/lib/containerd/opt`, upstream's `/opt/containerd`).
/// The review of #556 (F4): these exact directories, never a prefix — a
/// snapshot's `…/snapshots/N/fs/lib` under `/var/lib/containerd/` is an
/// image's content. The exec pump keeps the value only when each directory
/// and its files are root's, writable by no one else
/// (`nn_linux::sensors::kmod_exec`). Residual: `ctr install <image>` (root,
/// or containerd's socket: root's equal) fills this directory with an
/// image's libraries, which then load into root's `modprobe`, recorded Low.
const CONTAINERD_OPT_LIBS: &[&str] = &["/var/lib/containerd/opt/lib", "/opt/containerd/lib"];

/// Lot 347: `name` is a container runtime's module ([`RUNTIME_MODULES`],
/// [`RUNTIME_MODULE_FAMILIES`]).
fn is_runtime_module(name: &str) -> bool {
    let name = name.replace('-', "_");
    RUNTIME_MODULES.contains(&name.as_str())
        || RUNTIME_MODULE_FAMILIES
            .iter()
            .any(|f| name.len() > f.len() && name.starts_with(f))
}

/// Lot 347: `value` is the `LD_LIBRARY_PATH` containerd's `opt` plugin
/// sets: each entry exactly one of [`CONTAINERD_OPT_LIBS`] (the review of
/// #556, F4: never a directory below them), or empty (its own working
/// directory: `/`, a unit's).
fn is_containerd_opt_library_path(value: &str) -> bool {
    value
        .split(':')
        .all(|e| e.is_empty() || CONTAINERD_OPT_LIBS.contains(&e))
}

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

    /// Lot 348 (the alpha: `apt install podman` on Debian 13, a kernel
    /// update on Ubuntu 22.04 — their dpkg trigger's `update-initramfs`):
    /// what an initramfs build run in a package transaction executes under
    /// a module tool's comm was High (lot 283b and 287 took the kill, not
    /// the severity) — initramfs-tools' hook `hooks/kmod` (comm `kmod`, a
    /// shell script that copies kmod into the image) and, where the tools
    /// do not use `dracut-install`, `manual_add_modules`' hundred `modprobe
    /// --show-depends --set-version=<kernel>`. `Some(what)` when every fact
    /// holds, each the kernel's or the exec pump's — root's exec, its
    /// environment not refused, and one of:
    ///
    /// - the system's modprobe ([`ExecFacts::program`]: its device and
    ///   inode) asked to load nothing ([`kmod_invocation::loads_nothing`]);
    /// - a `#!` script ([`ExecFacts::interpreter`]: run by an interpreter of
    ///   a system tree, not the module tool) that is not the module tool, in
    ///   a system tree outside the tools' places, the executed file (the
    ///   LSM program's device and inode) the file at its path under the
    ///   host's root — PID 1's mount namespace — in a directory root's and
    ///   writable by no one else
    ///   ([`AuthSessionTracker::is_host_file_in_root_dir`]; the pump gives a
    ///   script no `ROOT_DIR`: its process's image is the interpreter): not
    ///   a copy, not a container's or another namespace's file, not
    ///   replaced since;
    ///
    /// — and the exec runs under the packaged initramfs builder, run by
    /// root ([`ExecFacts::initramfs_builder`]: its device and inode), AND in
    /// a package transaction run by root ([`ExecFacts::package_manager`]).
    ///
    /// An administrator's own `sudo update-initramfs -u` (no package
    /// manager) keeps lot 287's High record; a hook under a copy of the
    /// builder, a non-root build, a hook outside a system tree, a copy of
    /// the hook elsewhere or one another mount namespace sees at the path,
    /// a module tool, `MODPROBE_OPTIONS` or `LD_*`: R011's verdict as
    /// before. What this trusts is what the package transaction already
    /// is: root's packages and the hooks they install.
    ///
    /// [`ExecFacts::interpreter`]: kmod_exec_facts::ExecFacts::interpreter
    /// [`ExecFacts::program`]: kmod_exec_facts::ExecFacts::program
    /// [`ExecFacts::initramfs_builder`]: kmod_exec_facts::ExecFacts::initramfs_builder
    /// [`ExecFacts::package_manager`]: kmod_exec_facts::ExecFacts::package_manager
    /// [`AuthSessionTracker::is_host_file_in_root_dir`]: crate::posture::lineage::AuthSessionTracker::is_host_file_in_root_dir
    fn package_initramfs_build(&self, event: &Event) -> Option<String> {
        use common::wire::exe::exe_flags::KNOWN;
        use kmod_exec_facts::Environment;
        let Event::ProcessSpawn {
            uid,
            exe,
            argv,
            argv_truncated,
            ..
        } = event
        else {
            return None;
        };
        if *uid != 0 || !exe.has(KNOWN) {
            return None;
        }
        let image = program_identity::kernel_image(event)?;
        let facts = kmod_exec_facts::of(event)?;
        if matches!(facts.environment, Environment::Refused(_)) {
            return None;
        }
        let what = match (&facts.program, facts.interpreter.as_deref()) {
            // the system's modprobe (its device and inode, the pump's)
            // asked to load nothing: initramfs-tools' `manual_add_modules`
            // (`--show-depends --set-version=<the new kernel>`, Ubuntu 22.04
            // and Debian 12: about a hundred per build)
            (Ok(()), _)
                if kmod_invocation::tool_of(image, argv) == Ok(kmod_invocation::Tool::Modprobe)
                    && kmod_invocation::loads_nothing(argv, *argv_truncated) =>
            {
                format!("{image}, the system's modprobe asked to load nothing (--show-depends or --dry-run)")
            }
            // a hook: a `#!` script, the host's file at its path
            (Err(_), Some(interpreter))
                if crate::posture::lineage::in_system_tree(image)
                    && !kmod_invocation::in_tool_place(image)
                    && self
                        .lineage
                        .as_ref()?
                        .is_host_file_in_root_dir(image, (exe.dev, exe.ino)) =>
            {
                format!(
                    "{image}, a script of a system tree run by {interpreter} (the host's file at \
                     that path by its device and inode, in a root-only directory) — no module \
                     tool: a script loads no module without executing a tool, which R011 judges \
                     on its own"
                )
            }
            _ => return None,
        };
        let builder = facts.initramfs_builder?;
        let pm = facts.package_manager?;
        Some(format!(
            "{what}; run by the initramfs build of the packaged {builder} in a package \
             transaction ({pm}, run by root, both read in its lineage at the exec)"
        ))
    }

    /// Lot 347 (the alpha's container hosts: Debian 13's docker.io): the
    /// packaged containerd or dockerd probing a container runtime's modules
    /// — `Some(the manager's installed path)` when every fact holds, each
    /// the kernel's or the exec pump's:
    ///
    /// - root runs the system's module tool (the pump's device and inode)
    ///   by name only, no module parameter, nothing moved or forced, its
    ///   argv read whole, in the host's mount namespace;
    /// - every module it asks for is a runtime's ([`is_runtime_module`]);
    /// - the process that forked it (the kernel's record, its first exec
    ///   since) runs the installed containerd or dockerd, by the image's
    ///   identity in a root-only directory (the lineage's exec record);
    /// - its environment was read clean, or the process had exited before,
    ///   or its one refused variable is `LD_LIBRARY_PATH` as containerd's
    ///   `opt` plugin sets it ([`is_containerd_opt_library_path`]):
    ///   containerd 1.7 probes `aufs` with it (R011's kill at Docker's
    ///   install).
    ///
    /// What the names load is judged at the load, by R018 (the review of
    /// #556, F3): a file out of the module tree, or deeper than any module
    /// directory, is Critical with the loader's tree killed; a file inside
    /// `/lib/modules` no package installed is High, recorded only — the
    /// module-load judge refuses it outside a trusted-installer window, and
    /// lets it through recorded in its record mode (`alert`, `audit`, `off
    /// R018`, its maps not armed). Any other module, manager, tool or
    /// environment keeps R011's verdict.
    fn runtime_module_probe(&self, event: &Event) -> Option<String> {
        use kmod_exec_facts::Environment;
        let Event::ProcessSpawn {
            uid,
            filename,
            exe,
            argv,
            argv_truncated,
            ..
        } = event
        else {
            return None;
        };
        if *uid != 0 || *argv_truncated || exe.root != (0, 0) || exe.fork_parent == 0 {
            return None;
        }
        let tool = kmod_invocation::tool_of(exe.path_or(filename), argv).ok()?;
        let names = kmod_invocation::modules_asked(tool, argv)?;
        if !names.iter().all(|n| is_runtime_module(n)) {
            return None;
        }
        let facts = kmod_exec_facts::of(event)?;
        if facts.program.is_err() {
            return None;
        }
        if let Environment::Refused(_) = facts.environment {
            if !facts
                .library_path
                .as_deref()
                .is_some_and(is_containerd_opt_library_path)
            {
                return None;
            }
        }
        let lineage = self.lineage.as_ref()?;
        let as_of = crate::posture::lineage::AsOf::of_event(event);
        let manager =
            program_identity::installed_image(lineage.exec_image(exe.fork_parent, as_of)?)?;
        (manager.kind == ProgramKind::RuntimeManager
            && MODULE_PROBING_MANAGERS.contains(&program_identity::base_of(&manager.path)))
        .then_some(manager.path)
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

/// Lot 290 (backlog lot 289): the severity of R011's verdict on a module
/// tool's exec — Low for the system's tool asked for modules by name by
/// root, its environment read clean (`Ok((_, false))`); High for the rest:
/// a non-root exec, and every kill.
///
/// Lot 340 (the alpha's daily false positives): the same exec by root whose
/// process had exited before its environment could be read
/// (`Ok((_, true))`) is Medium, not High. Everything the exec pump could
/// check held — the system's tool by its device and inode, modules by name,
/// nothing moved or forced — and only the environment is not verified (a
/// `modprobe` of a module already loaded, or built in, exits at once: on an
/// active host that was most of R011's High records). A variable that WAS
/// read stays a kill, a non-root exec stays High.
pub fn plain_root_record_severity(judged: &Result<(String, bool), String>, uid: u32) -> Severity {
    match judged {
        Ok((_, false)) if uid == 0 => Severity::Low,
        Ok((_, true)) if uid == 0 => Severity::Medium,
        _ => Severity::High,
    }
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
            uid,
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
        // lot 347: the packaged containerd's or dockerd's probe of a
        // container runtime's modules, by identity
        if let Some(manager) = self.runtime_module_probe(event) {
            return Some(build_verdict(
                self,
                event,
                ResponseAction::Log,
                Severity::Low,
                &format!(
                    "Kernel-module tooling ({comm}) exec by module name — a container runtime's \
                     modules asked for by the packaged {manager} (its image's device and inode, \
                     the kernel's fork record), the system's tool, nothing moved or forced — \
                     recorded Low (lot 347): what the names load is the kernel's to judge (its \
                     signature policy; R018 judges the file it loads) (T1547.006)"
                ),
            ));
        }
        // lot 348: an initramfs hook of a dpkg trigger's build, by identity
        if let Some(what) = self.package_initramfs_build(event) {
            let mut reasoning = format!(
                "Kernel-module tooling ({comm}) exec — {what}: what a dpkg trigger's initramfs \
                 build runs, nothing loaded — recorded Low (lot 348) (T1547.006)"
            );
            if !parent_comm.is_empty() {
                reasoning = format!("{reasoning}; parent={parent_comm}");
            }
            return Some(build_verdict(
                self,
                event,
                ResponseAction::Log,
                Severity::Low,
                &reasoning,
            ));
        }
        // Lot 279: judged on the command line's syntax and on what the exec
        // pump read at the exec — recorded (no kill) by name, killed as
        // before otherwise. Lot 290 (backlog lot 289): the plain case — the
        // system's tool by module name, run by root, nothing moved, forced
        // or injected, its environment read clean — is recorded Low (a lab
        // round left 369 High lines of it: xtables, container runtimes and
        // udev ask for modules by name); the rest keeps High.
        let judged = judge(event);
        let severity = plain_root_record_severity(&judged, *uid);
        let (action, mut reasoning) = match judged {
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
                build_verdict(self, event, action, severity, &reasoning),
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
        // lot 313 (BUG-119): the script's place is the kernel's executed
        // file, never the caller's string
        (Err(_), Some(interpreter))
            if super::program_identity::kernel_image(event).is_some_and(|k| {
                crate::posture::lineage::in_system_tree(k) && !kmod_invocation::in_tool_place(k)
            }) =>
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
    let Event::ProcessSpawn { uid, .. } = event else {
        return v;
    };
    // lot 313 (BUG-119): the kernel's executed file, never the caller's
    // string (a cut one named `/usr/bin/./././…`)
    if *uid != 0 || !super::program_identity::exec_in_system_tree(event) {
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

    /// The review of #556 (F4, named): containerd's `opt` library path is
    /// accepted as its exact directories only — a snapshot's `lib` below
    /// `/var/lib/containerd/` (an image's content) is no `opt` path (fails
    /// on the lot's first head: any entry below the roots was).
    #[test]
    fn the_opt_library_path_is_exact_never_a_prefix() {
        for ok in [
            "/var/lib/containerd/opt/lib:",
            "/var/lib/containerd/opt/lib",
            "/opt/containerd/lib",
            ":/opt/containerd/lib:",
        ] {
            assert!(is_containerd_opt_library_path(ok), "{ok}");
        }
        for path in [
            "/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/7/fs/lib:",
            "/opt/containerd/lib/x",
            "/opt/containerd/lib2",
            "/var/lib/containerd/opt/lib/",
            "/var/lib/containerd/opt/lib:/tmp",
        ] {
            assert!(!is_containerd_opt_library_path(path), "{path}");
        }
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

    /// Lot 347 (named, the alpha's container hosts: Debian 13's
    /// `apt-get install docker.io`): containerd 1.7's `modprobe aufs` —
    /// its snapshotter's probe, with the `LD_LIBRARY_PATH` its `opt` plugin
    /// sets (`/var/lib/containerd/opt/lib:`) — was R011's kill (High, on
    /// main); dockerd's `modprobe -va bridge br_netfilter` and
    /// `nf_conntrack` a Low record. The packaged containerd's and
    /// dockerd's probes of a runtime's modules are recorded Low, by the
    /// forker's image and the system's tool. A module of no runtime, a
    /// library path of the caller's, `MODPROBE_OPTIONS`, a session's shell
    /// or another manager as the forker, a file, a module parameter, a
    /// non-root exec, a copy of the tool, no fork record: R011's verdict.
    #[test]
    fn a_packaged_container_runtime_s_module_probe_is_recorded_low() {
        use crate::decision::rules::program_identity::{record_installed, InstalledImage};
        use common::wire::exe::exe_flags::ROOT_DIR;
        let (containerd, dockerd, shim, bash) = (
            (0x0fd0_0347, 347_101),
            (0x0fd0_0347, 347_102),
            (0x0fd0_0347, 347_103),
            (0x0fd0_0347, 347_104),
        );
        for (id, path) in [
            (containerd, "/usr/bin/containerd"),
            (dockerd, "/usr/sbin/dockerd"),
            (shim, "/usr/bin/containerd-shim-runc-v2"),
        ] {
            record_installed(InstalledImage {
                id,
                len: 40_000_000,
                path: path.into(),
                kind: ProgramKind::RuntimeManager,
            });
        }
        let tmp = tempfile::tempdir().unwrap();
        let lineage = crate::posture::lineage::AuthSessionTracker::<H>::new(tmp.path());
        for (pid, id, path) in [
            (34_800, containerd, "/usr/bin/containerd"),
            (34_801, dockerd, "/usr/sbin/dockerd"),
            (34_802, shim, "/usr/bin/containerd-shim-runc-v2"),
            (34_803, bash, "/usr/bin/bash"),
        ] {
            let mut e = crate::decision::rules::testutil::spawn_exe("x", path, path, ROOT_DIR);
            if let Event::ProcessSpawn {
                pid: p,
                timestamp_ns,
                start_ns,
                exe,
                ..
            } = &mut e
            {
                (*p, *timestamp_ns, *start_ns) = (pid, 100, 100);
                (exe.dev, exe.ino) = id;
            }
            assert!(lineage.ingest_spawn_event(&e));
        }
        let r = rule().with_lineage(Some(lineage));
        let facts = |env: Environment, library_path: Option<&str>| ExecFacts {
            program: Ok(()),
            environment: env,
            package_manager: None,
            initramfs_builder: None,
            interpreter: None,
            library_path: library_path.map(str::to_string),
        };
        let opt = "/var/lib/containerd/opt/lib:";
        let ld = |v: &str| {
            facts(
                Environment::Refused(format!("LD_LIBRARY_PATH='{v}' in its environment")),
                Some(v),
            )
        };
        let judged = |forker: u32, args: &[&str], f: ExecFacts| {
            let mut e = modprobe(args);
            if let Event::ProcessSpawn {
                exe, timestamp_ns, ..
            } = &mut e
            {
                exe.fork_parent = forker;
                *timestamp_ns += 1_000;
            }
            r.evaluate(&read_as(e, f)).expect("a verdict")
        };
        let low = |v: Verdict| {
            assert_eq!(
                (v.action.clone(), v.severity),
                (ResponseAction::Log, Severity::Low),
                "{}",
                v.reasoning
            );
            assert!(v.reasoning.contains("lot 347"), "{}", v.reasoning);
        };
        let kill = |v: Verdict| {
            assert_ne!(v.action, ResponseAction::Log, "{}", v.reasoning);
            assert_eq!(v.severity, Severity::High, "{}", v.reasoning);
        };
        // the lab's kill: containerd's aufs probe with its opt plugin's path
        low(judged(34_800, &["aufs"], ld(opt)));
        low(judged(34_800, &["overlay"], ld("/opt/containerd/lib")));
        // dockerd's start (its environment clean, or gone at once)
        low(judged(
            34_801,
            &["-va", "bridge", "br_netfilter"],
            facts(Environment::Clean, None),
        ));
        low(judged(
            34_801,
            &["nf_conntrack_netlink"],
            facts(Environment::Exited("reaped".into()), None),
        ));
        // CONTROLS: a module of no runtime, under containerd
        kill(judged(34_800, &["rk"], ld(opt)));
        kill(judged(34_800, &["-a", "overlay", "rk"], ld(opt)));
        kill(judged(34_800, &["nf_"], ld(opt)));
        // a library path of the caller's, or with a `..`
        kill(judged(34_800, &["aufs"], ld("/tmp/lib:")));
        kill(judged(
            34_800,
            &["aufs"],
            ld("/var/lib/containerd/../../tmp"),
        ));
        // the review of #556 (F4): an image's content below the opt roots
        // (a snapshot's `lib`), another directory below them, a trailing
        // `/` or a `.`: the exact directories only
        for path in [
            "/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/7/fs/lib:",
            "/var/lib/containerd/opt/lib/../../x:",
            "/var/lib/containerd/opt/lib/x",
            "/var/lib/containerd/opt/lib/",
            "/opt/containerd/lib/./",
            "/opt/containerd/libx",
            "/var/lib/containerd/opt/lib:/tmp",
        ] {
            assert!(!is_containerd_opt_library_path(path), "{path}");
            kill(judged(34_800, &["aufs"], ld(path)));
        }
        // another variable refused (the pump kept no library path)
        kill(judged(
            34_800,
            &["aufs"],
            facts(
                Environment::Refused("MODPROBE_OPTIONS='-C /tmp/x'".into()),
                None,
            ),
        ));
        // a session's shell, or another manager, as the forker; no record
        kill(judged(34_803, &["aufs"], ld(opt)));
        kill(judged(34_802, &["aufs"], ld(opt)));
        kill(judged(34_899, &["aufs"], ld(opt)));
        kill(judged(0, &["aufs"], ld(opt)));
        // a file, a module parameter
        kill(judged(34_800, &["/tmp/overlay.ko"], ld(opt)));
        kill(judged(34_800, &["overlay", "redirect_dir=on"], ld(opt)));
        // the mini-hunt: insmod and `kmod insert` under containerd name a
        // file or a mode R011 never records by module name
        for argv in [
            &["insmod", "/var/lib/containerd/overlay.ko"][..],
            &["kmod", "insert", "overlay"][..],
        ] {
            let mut e = exec(&format!("/sbin/{}", argv[0]), "/usr/bin/kmod", argv);
            if let Event::ProcessSpawn { exe, .. } = &mut e {
                exe.fork_parent = 34_800;
            }
            let v = r.evaluate(&read_as(e, ld(opt))).expect("a verdict");
            assert_ne!(v.action, ResponseAction::Log, "{argv:?}: {}", v.reasoning);
        }
        // not the system's tool
        let mut copy = ld(opt);
        copy.program = Err("a copy".into());
        kill(judged(34_800, &["aufs"], copy));
        // a non-root exec
        let mut user = modprobe(&["aufs"]);
        if let Event::ProcessSpawn { uid, exe, .. } = &mut user {
            *uid = 1000;
            exe.fork_parent = 34_800;
        }
        let v = r.evaluate(&read_as(user, ld(opt))).expect("a verdict");
        assert_eq!(v.severity, Severity::High, "{}", v.reasoning);
        assert!(is_runtime_module("br-netfilter") && is_runtime_module("xt_conntrack"));
        assert!(!is_runtime_module("nft_") && !is_runtime_module("overlayfs"));
    }

    /// `e` run by `uid`.
    fn as_uid(mut e: Event, to: u32) -> Event {
        if let Event::ProcessSpawn { uid, .. } = &mut e {
            *uid = to;
        }
        e
    }

    /// Lot 340 (named, the alpha's daily false positives): the system's
    /// `modprobe` by module name, run by root, whose process exited before
    /// the exec pump could read its environment (a module already loaded, or
    /// built in: it exits at once) is recorded Medium — on `main` High. The
    /// attack variants keep High: the same exec by a user, a variable that
    /// was read (`MODPROBE_OPTIONS`, `LD_PRELOAD`: killed even once the
    /// process has gone), a file named, a copy of the tool, an option that
    /// moves the tree.
    #[test]
    fn a_root_system_modprobe_that_exited_before_its_environment_was_read_is_medium() {
        let r = rule();
        let exited = || ExecFacts {
            program: Ok(()),
            environment: Environment::Exited("no process had its pid any more".into()),
            package_manager: None,
            initramfs_builder: None,
            interpreter: None,
            library_path: None,
        };
        let v = r
            .evaluate(&read_as(modprobe(&["loop"]), exited()))
            .expect("recorded");
        assert_eq!(
            (v.action.clone(), v.severity),
            (ResponseAction::Log, Severity::Medium),
            "{}",
            v.reasoning
        );
        assert!(v.reasoning.contains(EXITED_NOTE), "{}", v.reasoning);
        // the same exec by a user: High
        let v = r
            .evaluate(&read_as(as_uid(modprobe(&["loop"]), 1000), exited()))
            .expect("recorded");
        assert_eq!(v.severity, Severity::High);
        // a variable read before the process went: killed, High
        for why in [
            "MODPROBE_OPTIONS='-d /tmp/x' in its environment",
            "LD_PRELOAD='/tmp/x.so' in its environment",
        ] {
            let facts = ExecFacts {
                environment: Environment::Refused(why.into()),
                ..exited()
            };
            let v = r
                .evaluate(&read_as(modprobe(&["loop"]), facts))
                .expect("killed");
            assert_eq!(v.action, ResponseAction::KillProcess, "{why}");
            assert_eq!(v.severity, Severity::High, "{why}");
        }
        // a file, a moved tree, a copy of the tool: killed, High
        for (e, program) in [
            (modprobe(&["/tmp/rk.ko"]), Ok(())),
            (modprobe(&["-d", "/tmp/x", "loop"]), Ok(())),
            (
                exec("/tmp/modprobe", "/tmp/modprobe", &["modprobe", "loop"]),
                Err("not the system's tool".to_string()),
            ),
        ] {
            let what = format!("{e:?}");
            let facts = ExecFacts {
                program,
                ..exited()
            };
            let v = r.evaluate(&read_as(e, facts)).expect("killed");
            assert_ne!(v.action, ResponseAction::Log, "{what}");
            assert_eq!(v.severity, Severity::High, "{what}");
        }
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
            library_path: None,
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
            library_path: None,
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

    /// Lot 348 (the alpha: `apt install podman` on Debian 13): the hook
    /// `kmod` of a dpkg trigger's `update-initramfs` — a script of a system
    /// tree run by dash, the host's file at its path by its device and inode
    /// in a root-only directory (checked on the host: the pump gives a
    /// script no `ROOT_DIR`), under the packaged builder AND in a package
    /// transaction — is recorded Low (it was Log + High). Each fact missing
    /// keeps the verdict lot 283b and 287 gave: High (Log), or the kill.
    #[test]
    fn a_dpkg_trigger_s_initramfs_hook_is_recorded_low_by_identity() {
        use crate::posture::host::testing::IdTestHost;
        use common::wire::exe::exe_flags::KNOWN;
        /// The root filesystem's device as `stat(2)` gives it (253:1), and
        /// in the kernel's form, as the LSM program records an image.
        const STAT_DEV: u64 = 64769;
        const KDEV: u64 = common::wire::exe::kernel_dev(STAT_DEV);
        const PACKAGED: (u64, u64) = (KDEV, 348_001);
        const HOOKS: &str = "/usr/share/initramfs-tools/hooks";
        IdTestHost::set_file_id(HOOK, Some((STAT_DEV, PACKAGED.1)));
        IdTestHost::set_dir_root_only(HOOKS, true);
        let tmp = tempfile::tempdir().unwrap();
        let lineage = crate::posture::lineage::AuthSessionTracker::<IdTestHost>::new(tmp.path());
        let bare = super::R011KernelModuleTooling::<IdTestHost>::new(Arc::new(
            crate::config::comm_allowlist::CommAllowlist::<IdTestHost>::default(),
        ));
        let r = super::R011KernelModuleTooling::<IdTestHost>::new(Arc::new(
            crate::config::comm_allowlist::CommAllowlist::<IdTestHost>::default(),
        ))
        .with_lineage(Some(lineage));
        let hook = |path: &str, id: (u64, u64), flags: u32, uid: u32| {
            let mut e = exec(path, path, &[path, "prereqs"]);
            if let Event::ProcessSpawn {
                exe, uid: u, ppid, ..
            } = &mut e
            {
                (exe.dev, exe.ino) = id;
                exe.flags = flags;
                *u = uid;
                *ppid = 3480;
            }
            e
        };
        let facts =
            |pm: Option<&str>, builder: Option<&str>, interpreter: Option<&str>| ExecFacts {
                program: not_tool(),
                environment: Environment::Clean,
                package_manager: pm.map(str::to_string),
                initramfs_builder: builder.map(str::to_string),
                interpreter: interpreter.map(str::to_string),
                library_path: None,
            };
        let (dpkg, b, dash) = (
            Some("/usr/bin/dpkg"),
            Some(UPDATE_INITRAMFS),
            Some("/usr/bin/dash"),
        );
        // the lab of lot 348: a script's exec has the LSM identity of the
        // script and no `ROOT_DIR` (its process's image is dash)
        let rooted = KNOWN;
        // the dpkg trigger's hook: Low
        let v = r
            .evaluate(&read_as(
                hook(HOOK, PACKAGED, rooted, 0),
                facts(dpkg, b, dash),
            ))
            .expect("recorded");
        assert_eq!(
            (v.action.clone(), v.severity),
            (ResponseAction::Log, Severity::Low),
            "{}",
            v.reasoning
        );
        for part in ["lot 348", "/usr/sbin/update-initramfs", "/usr/bin/dpkg"] {
            assert!(v.reasoning.contains(part), "{part}: {}", v.reasoning);
        }
        // CONTROLS — High recorded as before (lot 283b / 287):
        let high = |e: Event, f: ExecFacts, why: &str| {
            let v = r.evaluate(&read_as(e, f)).expect("fires");
            assert_eq!(v.severity, Severity::High, "{why}: {}", v.reasoning);
            assert!(!v.reasoning.contains("lot 348"), "{why}: {}", v.reasoning);
            v
        };
        // the admin's own update-initramfs (no package manager)
        high(
            hook(HOOK, PACKAGED, rooted, 0),
            facts(None, b, dash),
            "admin",
        );
        // a package transaction without the packaged builder
        high(
            hook(HOOK, PACKAGED, rooted, 0),
            facts(dpkg, None, dash),
            "no builder",
        );
        // no interpreter read (the file runs as itself)
        high(
            hook(HOOK, PACKAGED, rooted, 0),
            facts(dpkg, b, None),
            "no #!",
        );
        // no LSM identity; a directory another user may write
        high(hook(HOOK, PACKAGED, 0, 0), facts(dpkg, b, dash), "no LSM");
        IdTestHost::set_dir_root_only(HOOKS, false);
        high(hook(HOOK, PACKAGED, rooted, 0), facts(dpkg, b, dash), "dir");
        IdTestHost::set_dir_root_only(HOOKS, true);
        // another file at the path than the one executed: a copy, a file
        // replaced since, another mount namespace's tree
        high(
            hook(HOOK, (KDEV, 348_002), rooted, 0),
            facts(dpkg, b, dash),
            "inode",
        );
        high(
            hook(HOOK, (KDEV + 1, PACKAGED.1), rooted, 0),
            facts(dpkg, b, dash),
            "device",
        );
        // no lineage to read the host's file with
        let v = bare
            .evaluate(&read_as(
                hook(HOOK, PACKAGED, rooted, 0),
                facts(dpkg, b, dash),
            ))
            .unwrap();
        assert_eq!(v.severity, Severity::High, "{}", v.reasoning);
        // killed as before: a non-root exec, a copy outside a system tree,
        // a refused environment
        let v = r
            .evaluate(&read_as(
                hook(HOOK, PACKAGED, rooted, 1000),
                facts(dpkg, b, dash),
            ))
            .unwrap();
        assert_ne!(v.action, ResponseAction::Log, "{}", v.reasoning);
        IdTestHost::set_file_id("/tmp/kmod", Some((STAT_DEV, 348_003)));
        IdTestHost::set_dir_root_only("/tmp", true);
        let v = r
            .evaluate(&read_as(
                hook("/tmp/kmod", (KDEV, 348_003), rooted, 0),
                facts(dpkg, b, dash),
            ))
            .unwrap();
        assert_eq!(v.action, ResponseAction::KillProcessTree, "{}", v.reasoning);
        let mut f = facts(dpkg, b, dash);
        f.environment = Environment::Refused("LD_PRELOAD='/tmp/x.so' in its environment".into());
        let v = r
            .evaluate(&read_as(hook(HOOK, PACKAGED, rooted, 0), f))
            .unwrap();
        assert_ne!(v.severity, Severity::Low, "{}", v.reasoning);
        // the mini-hunt: `manual_add_modules`' modprobe asked to load
        // nothing (Ubuntu 22.04's build, a hundred per kernel update) — the
        // system's tool by the pump's identity: Low under a dpkg trigger's
        // build
        let tool = |pm: Option<&str>, builder: Option<&str>| ExecFacts {
            program: Ok(()),
            ..facts(pm, builder, None)
        };
        let v = r
            .evaluate(&read_as(
                exec("/usr/sbin/modprobe", "/usr/bin/kmod", SHOW_DEPENDS),
                tool(dpkg, b),
            ))
            .expect("recorded");
        assert_eq!(
            (v.action.clone(), v.severity),
            (ResponseAction::Log, Severity::Low),
            "{}",
            v.reasoning
        );
        assert!(
            v.reasoning.contains("asked to load nothing"),
            "{}",
            v.reasoning
        );
        // CONTROLS: the admin's build, a build outside a transaction, a
        // dpkg run without the builder — High as before; a modprobe that
        // may load (`--set-version` with no dry run) — High; a tool that is
        // not the system's — High
        for (f, why) in [
            (tool(None, b), "admin"),
            (tool(dpkg, None), "no builder"),
            (
                ExecFacts {
                    program: not_tool(),
                    ..facts(dpkg, b, None)
                },
                "not the system's tool",
            ),
        ] {
            high(
                exec("/usr/sbin/modprobe", "/usr/bin/kmod", SHOW_DEPENDS),
                f,
                why,
            );
        }
        high(
            exec(
                "/usr/sbin/modprobe",
                "/usr/bin/kmod",
                &["modprobe", "--set-version=6.8.0-1", "ext4"],
            ),
            tool(dpkg, b),
            "may load",
        );
        // insmod is no modprobe, whatever its arguments say
        let v = r
            .evaluate(&read_as(
                exec(
                    "/usr/sbin/insmod",
                    "/usr/bin/kmod",
                    &["insmod", "--dry-run", "/tmp/x.ko"],
                ),
                tool(dpkg, b),
            ))
            .unwrap();
        assert_ne!(v.severity, Severity::Low, "{}", v.reasoning);
        // a script in a module tool's place is no hook: as before
        IdTestHost::set_file_id("/usr/sbin/kmod", Some((STAT_DEV, 348_004)));
        IdTestHost::set_dir_root_only("/usr/sbin", true);
        high(
            hook("/usr/sbin/kmod", (KDEV, 348_004), rooted, 0),
            facts(dpkg, b, dash),
            "a tool's place",
        );
        IdTestHost::set_file_id("/usr/sbin/kmod", None);
        IdTestHost::set_dir_root_only("/usr/sbin", false);
        IdTestHost::set_file_id(HOOK, None);
        IdTestHost::set_file_id("/tmp/kmod", None);
        for d in [HOOKS, "/tmp", "/usr/sbin"] {
            IdTestHost::set_dir_root_only(d, false);
        }
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
                library_path: None,
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
            // lot 290 (backlog lot 289): the plain root case is Low
            assert_eq!(v.severity, Severity::Low);
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
                    library_path: None,
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
                    library_path: None,
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
                    library_path: None,
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
                    library_path: None,
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
                    library_path: None,
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

    /// Lot 290 (named; backlog lot 289): the system's tool by module name
    /// run by root, its environment read clean, is recorded Low; the same
    /// exec whose process exited before its environment was read stays
    /// High, a non-root one and every kill stay High. Lot 340: that exited
    /// exec is a non-root one here — a root one is Medium
    /// ([`a_root_system_modprobe_that_exited_before_its_environment_was_read_is_medium`]).
    #[test]
    fn a_plain_root_modprobe_is_low_and_the_suspicious_keep_high() {
        let r = rule();
        let plain = r
            .evaluate(&read_ok(modprobe(&["br_netfilter"])))
            .expect("recorded");
        assert_eq!(
            (plain.action.clone(), plain.severity),
            (ResponseAction::Log, Severity::Low)
        );
        let exited = ExecFacts {
            program: Ok(()),
            environment: Environment::Exited("gone".into()),
            package_manager: None,
            initramfs_builder: None,
            interpreter: None,
            library_path: None,
        };
        let v = r
            .evaluate(&read_as(as_uid(modprobe(&["br_netfilter"]), 1000), exited))
            .expect("recorded");
        assert_eq!(
            (v.action, v.severity),
            (ResponseAction::Log, Severity::High)
        );
        let v = r
            .evaluate(&read_ok(modprobe(&["/tmp/rk.ko"])))
            .expect("killed");
        assert_eq!(v.severity, Severity::High);
        assert_ne!(v.action, ResponseAction::Log);
        let ok = Ok(("modprobe of 'x'".to_string(), false));
        assert_eq!(plain_root_record_severity(&ok, 0), Severity::Low);
        assert_eq!(plain_root_record_severity(&ok, 1000), Severity::High);
        assert_eq!(
            plain_root_record_severity(&Ok(("x".to_string(), true)), 1000),
            Severity::High
        );
        assert_eq!(
            plain_root_record_severity(&Err("names a file".to_string()), 0),
            Severity::High
        );
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
            library_path: None,
        };
        for (e, what) in [
            (modprobe(&["overlay"]), "modprobe of 'overlay'"),
            (
                exec("/usr/bin/kmod", "/usr/bin/kmod", &["kmod", "--version"]),
                "kmod: the version printed",
            ),
        ] {
            // lot 340: a non-root exec (a root one is Medium)
            // (no record text in the messages: it names the exec's user)
            let v = r
                .evaluate(&read_as(as_uid(e, 1000), exited()))
                .expect("recorded");
            assert_eq!(v.action, ResponseAction::Log, "{what}");
            assert_eq!(v.severity, Severity::High);
            for part in [what, EXITED_NOTE, "T1547.006", "parent=bash"] {
                assert!(v.reasoning.contains(part), "{part}");
            }
            assert!(!v.reasoning.contains("no MODPROBE_OPTIONS"), "{what}");
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

/// Lot 313 (external bug hunt, edition 1.4: BUG-119): a caller's string the kernel cut
/// (`filename_truncated`) "names no path" (nn-model event.rs:92-96), but
/// with no kernel path (`exe.path` empty: tracepoint mode, or a root the
/// mount table does not know, and `/proc/<pid>/exe` unreadable) the
/// exemptions judge `exe.path_or(filename)` with `in_system_tree`.
#[cfg(test)]
mod bug119 {
    use super::*;
    use crate::decision::rules::kmod_exec_facts::{Environment, ExecFacts};
    use crate::posture::host::testing::TestHost as H;

    /// `/usr/bin/` then `./` × 123: 255 bytes, what is left of
    /// `/usr/bin/./././…/../../tmp/x/kmod` after the cut.
    fn cut_string() -> String {
        let s = format!("/usr/bin/{}", "./".repeat(123));
        assert_eq!(s.len(), 255);
        s
    }

    fn argv(a: &[&str]) -> Vec<String> {
        a.iter().map(|s| s.to_string()).collect()
    }

    /// A root exec of a copied `kmod` as the pump leaves it: the cut
    /// string, no kernel path.
    fn cut_exec(pid: u32, ppid: u32, ts: u64, start: u64) -> Event {
        let mut e = crate::decision::rules::testutil::spawn("kmod", &cut_string());
        if let Event::ProcessSpawn {
            pid: p,
            ppid: pp,
            uid,
            gid,
            argv: a,
            timestamp_ns,
            start_ns,
            filename_truncated,
            parent_comm,
            ..
        } = &mut e
        {
            (*p, *pp, *uid, *gid) = (pid, ppid, 0, 0);
            *a = argv(&["insmod", "/tmp/rk.ko"]);
            (*timestamp_ns, *start_ns) = (ts, start);
            *filename_truncated = true;
            *parent_comm = "sh".to_string();
        }
        e
    }

    #[test]
    fn bug119_a_cut_string_is_no_system_tree_for_the_package_transaction() {
        let e = cut_exec(2_119_001, 1, 2_119_001, 0);
        kmod_exec_facts::keep(
            &e,
            ExecFacts {
                program: Err("its device and inode are not the system's tool's".into()),
                environment: Environment::Clean,
                package_manager: Some("/usr/bin/dpkg".into()),
                initramfs_builder: None,
                interpreter: None,
                library_path: None,
            },
        );
        let v = R011KernelModuleTooling::<H>::new(Arc::new(CommAllowlist::<H>::default()))
            .evaluate(&e)
            .expect("fires");
        assert_ne!(
            v.action,
            ResponseAction::Log,
            "a cut string names no path (event.rs:92-96), yet: {}",
            v.reasoning
        );
    }

    #[test]
    fn bug119_a_cut_string_is_no_system_tree_for_judge_actor() {
        let dir = tempfile::tempdir().unwrap();
        let t = crate::posture::lineage::AuthSessionTracker::<H>::new(dir.path());
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
            &argv(&["/bin/sh", "/var/lib/dpkg/info/x.postinst"]),
            30,
            25,
            0,
        );
        let e = cut_exec(2_119_500, 300, 50, 45);
        t.ingest_exec(
            2_119_500,
            300,
            &cut_string(),
            &argv(&["insmod", "/tmp/rk.ko"]),
            50,
            45,
            0,
        );
        let entries = crate::config::comm_allowlist::BUILTIN_PROCESS_COMM_ALLOWLIST_V1
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty() && !l.starts_with('#'))
            .map(String::from);
        let r = R011KernelModuleTooling::<H>::new(Arc::new(
            CommAllowlist::<H>::from_iter_owned(entries).with_identity(t),
        ));
        let v = r.evaluate(&e).expect("fires");
        assert_ne!(
            v.action,
            ResponseAction::Log,
            "a cut string names no path (event.rs:92-96), yet: {}",
            v.reasoning
        );
    }

    /// Guard: the same string whole (not cut) is normalised by the pump
    /// to its real place; a `/tmp` copy under dpkg is killed.
    #[test]
    fn bug119_guard_a_tmp_copy_under_dpkg_is_killed() {
        let mut e = cut_exec(2_119_002, 1, 2_119_002, 0);
        if let Event::ProcessSpawn {
            filename,
            filename_truncated,
            ..
        } = &mut e
        {
            *filename = "/tmp/x/kmod".into();
            *filename_truncated = false;
        }
        kmod_exec_facts::keep(
            &e,
            ExecFacts {
                program: Err("not the system's tool".into()),
                environment: Environment::Clean,
                package_manager: Some("/usr/bin/dpkg".into()),
                initramfs_builder: None,
                interpreter: None,
                library_path: None,
            },
        );
        let v = R011KernelModuleTooling::<H>::new(Arc::new(CommAllowlist::<H>::default()))
            .evaluate(&e)
            .expect("fires");
        assert_eq!(v.action, ResponseAction::KillProcessTree, "{}", v.reasoning);
    }
}
