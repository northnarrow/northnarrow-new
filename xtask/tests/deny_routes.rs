//! Lot 341 (the alpha profile; the coordinator's decision of 13/11, as
//! corrected after the review of #550): `alpha` means no response against
//! a user's programs — no kill, isolation, quarantine, exec-quarantine hold,
//! exec-policy deny, connect deny or exploit-guard response, each of them
//! recorded with what it would have done. The host's integrity and the
//! agent's self-protection are enforced under every profile. The host-wide
//! denies the first round left in observe were self-protection in disguise:
//! `kernel.ftrace_enabled=0`, `kprobes/enabled=0` and lockdown blind the
//! agent's hooks; a foreign tracing program's `bpf_send_signal` kills it past
//! `task_kill`; a cgroup v1 freezer freezes it; a ptrace of PID 1 races the
//! trusted writes the deny hooks let PID 1 make; a kexec image or an
//! untrusted module runs code no hook of the agent sees.
//!
//! The eBPF programs run only in a kernel (the lab's `nn-lab.sh
//! host-deny-check`). Here the code is read: every deny site of the object
//! is listed — the agent's self-protection or the host's integrity with its
//! reason, or a response path whose own mode the gate sets — a new deny site
//! fails until it is classified; and a self-protection site's function, and
//! every function it calls in the object (the review's planted helper, F6),
//! reads no switch of the gate.
//!
//! Lot 1.7b (stage S1, item F12): both scans read the object as Rust
//! (`support::ast`; test items left out). The census counts a refusal
//! however its errno is spelt (`-(EPERM)`, `0 - EPERM`, `wrapping_neg`, a
//! number returned, a negative constant of any file), every kill helper
//! under any name, and a `macro_rules!`'s rules as `name!`; the gate's
//! reads follow every name a function's code holds ([`ast::Graph`]):
//! imports, re-exports, macros, methods, a function held behind
//! parentheses, in an array, a tuple, a struct or an `Option`. The lexical
//! scans (kept in [`lexical`] only to show them) missed each spelling
//! planted in `the_lexical_bypasses_are_caught`; on today's object the
//! census found two sites they did not count (`try_exec_check_lsm`'s
//! `-13`, the calibration's `bpf_send_signal_thread`), both classified.

mod support;

use std::collections::{BTreeMap, BTreeSet};

use quote::ToTokens;
use support::ast::{self, Corpus};
use support::repo_root;
use syn::visit::{self, Visit};
use syn::{Expr, Item};

/// How a deny site of the eBPF object meets the profile.
#[derive(Clone, Copy, Debug)]
enum Route {
    /// The agent's self-protection or the host's integrity: enforced under
    /// every profile — the function, and every function it calls, reads no
    /// switch of the gate ([`GATE_SWITCHES`]). The reason.
    Enforced(&'static str),
    /// A response path whose own mode the resolved gate sets (named in
    /// `xtask/tests/alpha_profile.rs`): the reason.
    Gated(&'static str),
    /// Returns what another listed function decided (named).
    Delegated(&'static str),
}

use Route::{Delegated, Enforced, Gated};

const AGENT: &str = "the agent, its watchdog or a worker (PROTECTED_PIDS, or a process running \
                     the agent's or the watchdog's binary)";
const OWN_FILES: &str = "the agent's files, units, directories and pins (PROTECTED_INODES)";

/// The switches the start writes from the resolved gate (`--detect-only`,
/// the detect-only variables, the `alpha` profile), each with the one file
/// of the object that declares and reads it: the exec quarantine's, the
/// exec policy's, the exploit guard's and the kernel connect deny's modes.
/// `HOST_DENY_MODE`, the first round's switch of the host-wide denies, is
/// gone and stays forbidden.
const GATE_SWITCHES: &[(&str, &str)] = &[
    ("EXECQ_CONF", "execq.rs"),
    ("EXECPOL_CONF", "execpol.rs"),
    ("EPG_CONFIG", "epg.rs"),
    ("NET_CONNECT_DENY_MODE", "socket_connect.rs"),
    ("HOST_DENY_MODE", ""),
];

/// Every deny site of `agent-ebpf/src`, by file and function: `(file,
/// function, sites, route)`. A function may hold sites of two routes (one
/// row each).
/// Lot 2.3b (D5): why the freeze of the system code refuses.
const FROZEN_SYSTEM_CODE: &str = "the system's code frozen against outsiders while a trusted-installer window per process tree is open (D5): a write-open, truncate, rename, removal, link, attribute change, new entry or mount by a process outside the tree on the default PATH's programs, the loader's and the interpreters' libraries, the loader's configuration, the package managers' hook and maintainer-script directories, systemd's manager configuration or binfmt_misc — nothing outside the tree replaces what the tree executes, loads or is configured by (lot 2.3b)";

const SITES: &[(&str, &str, usize, Route)] = &[
    (
        "bpf_defense.rs",
        "try_bpf_map_guard",
        2,
        Enforced(
            "a read or write handle on one of the agent's MAPS (a program is loaded against a map, or a map written, only through one)",
        ),
    ),
    (
        "bpf_defense.rs",
        "try_bpf_prog_guard",
        1,
        Enforced(
            "a handle on one of the agent's PROGRAMS (an freplace of one of its functions needs it)",
        ),
    ),
    (
        "bpf_defense.rs",
        "try_bpf_prog_guard",
        1,
        Enforced(
            "before 6.9, a handle on a foreign program of a type refused by default (one a signed per-loader opt-out lets through) whose verified instructions call bpf_send_signal(_thread) or bpf_override_return: it kills the agent past task_kill or blinds it (lot 345)",
        ),
    ),
    (
        "bpf_defense.rs",
        "try_bpf_prog_guard",
        1,
        Enforced(
            "from 6.9, a handle after the window on a program a trusted-installer window let load whose instructions call what the content judge refuses outside one (bpf_send_signal(_thread), bpf_probe_write_user, bpf_override_return, the bpf_send_signal_task kfunc): taken by id or its pin and attached or run, it kills the agent past task_kill (lot 349)",
        ),
    ),
    (
        "bpf_defense.rs",
        "try_bpf_prog_guard",
        2,
        Enforced(
            "a window's load of a program the content judge refuses outside one, when the held set has no room for it (fail closed: kept nowhere, it could be run or attached after the window unrefused; the review of #558, F5)",
        ),
    ),
    (
        "bpf_defense.rs",
        "try_bpf_prog_load_guard",
        1,
        Enforced(
            "from 6.9, a foreign load of a type refused by default whose instructions call bpf_send_signal(_thread), bpf_probe_write_user, bpf_override_return or the bpf_send_signal_task kfunc, opted out or not (lot 345)",
        ),
    ),
    (
        "bpf_defense.rs",
        "try_bpf_write_user_guard",
        1,
        Enforced(
            "before 6.9, the verifier's lockdown question for bpf_probe_write_user asked by a foreign loader: it rewrites the memory of the process the probe fires in, the agent's (lot 345)",
        ),
    ),
    (
        "bpf_defense.rs",
        "nn_calib_signals",
        // lot 1.7b: `bpf_send_signal_thread` counted too
        2,
        Enforced(
            "never attached: the content judge's calibration program, loaded, read by the bpf_prog hook and unloaded at the start (signal 0, bpf_send_signal and bpf_send_signal_thread) (lot 345)",
        ),
    ),
    (
        "bpf_defense.rs",
        "try_bpf_syscall_observe",
        1,
        Enforced(
            "a foreign load of the nine program types that signal a process (`bpf_send_signal` kills the agent past task_kill), rewrite its memory, override a kernel function's return or take a hook's place, outside a window and the signed per-loader opt-out (install.sh --allow-bpf-tools / --allow-bpf-loader)",
        ),
    ),
    (
        "bpf_defense.rs",
        "try_bpf_syscall_observe",
        1,
        Enforced(
            "a cgroup/sysctl program on the root cgroup: it runs after the sysctl guard and rewrites the value the guard judged",
        ),
    ),
    (
        "bpf_defense.rs",
        "try_bpf_syscall_observe",
        1,
        Enforced(
            "an fmod_ret (BPF_MODIFY_RETURN) load the signed per-loader opt-out lets through: it overrides any security_* function's return — security_file_open failing for the agent blinds it (lot 345)",
        ),
    ),
    (
        "bpf_defense.rs",
        "try_bpf_syscall_observe",
        1,
        Enforced(
            "a run or an attach, outside a window, of a program held at a window's load (BPF_PROG_RUN, BPF_PROG_ATTACH, BPF_RAW_TRACEPOINT_OPEN, BPF_LINK_CREATE, BPF_LINK_UPDATE, a prog array's update) through any descriptor: the loader's own kept from the window, one passed or taken with pidfd_getfd (the review of #558, F1)",
        ),
    ),
    (
        "bpf_defense.rs",
        "try_bpf_syscall_observe",
        3,
        Enforced(
            "a handle on one of the agent's links (by id or its pin), a handle by id on its maps or programs or one under its pin directories, a detach or update of one of its links",
        ),
    ),
    // lot 2.2: the cgroup BPF guard, the kernel-read option, the shared
    // writable mappings
    (
        "bpf_defense.rs",
        "try_bpf_syscall_observe",
        1,
        Enforced(
            "a cgroup program attached to the agent's unit cgroups or northnarrow.slice (or below them) outside a window, PID 1's for a unit property included: a packet program cuts the heartbeat and the export, a device program the agent's /dev opens (lot 2.2)",
        ),
    ),
    (
        "bpf_defense.rs",
        "try_kernel_read_guard",
        1,
        Enforced(
            "under the signed kernel-read option, a foreign lockdown question of physical memory (/dev/mem, /proc/kcore), tracefs, kprobes or perf outside a window: each reads kernel or process memory, the agent's keys among it (lot 2.2)",
        ),
    ),
    (
        "bpf_defense.rs",
        "try_perf_event_guard",
        1,
        Enforced(
            "under the signed kernel-read option, a foreign uprobe PMU event or CPU-wide sampling of user registers or stacks outside a window: it reads every process's memory, the agent's among them (lot 2.2)",
        ),
    ),
    (
        "role_maps.rs",
        "try_role_mmap_file",
        1,
        Enforced(
            "a shared mapping, writable or one mprotect can make writable, of a file the agent protects against writes, inside a window too: its page stores reach the file with no further hook (lot 2.2)",
        ),
    ),
    (
        "cgroup_files.rs",
        "refuse_switch",
        2,
        Enforced(
            "the kprobes and lockdown switches: kprobes/enabled=0 disarms every kprobe of the agent, lockdown takes the kernel-memory helpers from its programs (it blinds the agent); lot 2.0: the SysRq trigger file, whose requests act on the whole host outside every other hook (refused to every caller outside a window, root included; its second site signs a window's write, let through)",
        ),
    ),
    (
        "cgroup_files.rs",
        "refuse_limit",
        1,
        Enforced("a resource file of the agent's units' cgroups (kill, freeze, limits)"),
    ),
    (
        "cgroup_files.rs",
        "refuse_v1",
        1,
        Enforced(
            "a cgroup v1 write (cgroup.procs, tasks, freezer.state under a controller): a v1 freezer moves and freezes the agent past the v2 move guard (lot 273b)",
        ),
    ),
    (
        "cgroup_files.rs",
        "refuse_sysctl",
        1,
        Enforced(
            "a guarded sysctl's file: kernel.ftrace_enabled=0 silences the BPF trampolines, the deny hooks' among them; the others abort or starve the agent",
        ),
    ),
    (
        "cgroup_files.rs",
        "refuse_oom_adj",
        1,
        Enforced("the oom_score_adj of the agent, its watchdog or a worker"),
    ),
    (
        "cgroup_files.rs",
        "refuse_memory_view",
        1,
        Enforced(
            "the open of a memory view of the agent, its watchdog or a worker (/proc/<pid>/environ, auxv, maps, smaps, smaps_rollup, numa_maps, pagemap): from 6.16 the kernel lets a caller with CAP_PERFMON through the ptrace hook's read-mode refusal (lot 367)",
        ),
    ),
    (
        "cgroup_guard.rs",
        "try_cgroup_move_deny",
        1,
        Enforced("a move of the agent's processes out of its cgroup"),
    ),
    (
        "epg.rs",
        "respond",
        1,
        Gated("the exploit guard's SIGKILL: detect mode under the gate (effective_response)"),
    ),
    (
        "epg_lite.rs",
        "use_point_found",
        3,
        Gated(
            "the exploit guard's response (EPERM, SIGKILL): detect mode under the gate (effective_response)",
        ),
    ),
    // lot 1.7b: a refusal by its number (`-13`), which the lexical census
    // did not count
    (
        "exec_lsm.rs",
        "try_exec_check_lsm",
        1,
        Gated(
            "the exec policy's verdict on an exec its walk could not place (nn_exec_unwalked): audit mode under the gate (execpol_mode)",
        ),
    ),
    (
        "execpol.rs",
        "env_commit",
        1,
        Gated(
            "the exec environment's SIGKILL: the exec policy's audit mode under the gate (execpol_mode)",
        ),
    ),
    (
        "execpol.rs",
        "on_pass",
        1,
        Gated("the exec policy: audit mode under the gate (execpol_mode)"),
    ),
    (
        "execpol.rs",
        "try_exec_env_lsm",
        1,
        Gated("the exec policy: audit mode under the gate (execpol_mode)"),
    ),
    (
        "execpol.rs",
        "try_execmap",
        1,
        Gated("the exec policy: audit mode under the gate (execpol_mode)"),
    ),
    (
        "execq.rs",
        "maybe_stop",
        1,
        Gated("the exec quarantine's hold (SIGSTOP): observe mode under the gate (execq_config)"),
    ),
    (
        "execq.rs",
        "note_pass",
        1,
        Gated("the exec quarantine: observe mode under the gate (execq_config)"),
    ),
    (
        "execq.rs",
        "refuse_script",
        1,
        Gated("the exec quarantine: observe mode under the gate (execq_config)"),
    ),
    (
        "opaque.rs",
        "lsm_ret",
        1,
        Gated(
            "exec_check_lsm's verdict (the exec policy's and the quarantine's, each gated above) \
             in the LSM exit range: its -EACCES answers only a positive verdict, which neither \
             returns in any mode (fail-closed, the review of #618)",
        ),
    ),
    (
        "inode_protect.rs",
        "try_inode_unlink",
        2,
        Enforced(OWN_FILES),
    ),
    (
        "inode_protect.rs",
        "try_inode_rmdir",
        2,
        Enforced(OWN_FILES),
    ),
    (
        "inode_protect.rs",
        "try_inode_rename",
        4,
        Enforced(OWN_FILES),
    ),
    (
        "inode_protect.rs",
        "try_inode_rename",
        1,
        Enforced(
            "the rename or exchange of an ancestor of the agent's paths (/etc, /var/lib, the binaries' and the units' directories): it moves the agent's tree from under the paths it is read by; the key files' directory and its ancestors are kept by any window (lot 2.3a)",
        ),
    ),
    (
        "inode_protect.rs",
        "try_inode_setattr",
        1,
        Enforced(OWN_FILES),
    ),
    ("inode_protect.rs", "try_file_ioctl", 1, Enforced(OWN_FILES)),
    (
        "inode_protect.rs",
        "try_file_ioctl",
        1,
        Enforced(
            "a passthrough command (SG_IO, an NVMe command) to a disk under the agent's files or its sg, bsg or NVMe node, under the kernel-read option's block-device class — a write of any block past the descriptor's mode; recorded otherwise (lot 2.3a, the review of #647)",
        ),
    ),
    (
        "inode_protect.rs",
        "try_inode_unlink",
        1,
        Enforced(
            "the removal of an entry named after our units in a directory of their enablement links, a link made after the start included: the units not started at the next boot (lot 2.3a, the review of #647)",
        ),
    ),
    (
        "inode_protect.rs",
        "try_inode_rename",
        1,
        Enforced(
            "the rename, out of or over, of an entry named after our units in a directory of their enablement links (lot 2.3a, the review of #647)",
        ),
    ),
    (
        "inode_protect.rs",
        "try_protected_open_deny",
        1,
        Enforced(
            "an outsider's write-open of the cgroup.kill or cgroup.freeze of an open tree window's root's cgroup or one above it: its members killed or frozen with their cgroup, no task_kill sees it (lot 2.3a, D7)",
        ),
    ),
    (
        "inode_protect.rs",
        "try_file_ioctl",
        1,
        Enforced(
            "a perf event's PERF_EVENT_IOC_SET_BPF, outside a window, of a program held at a window's load: a kprobe calling bpf_send_signal attached with no bpf(2) command (the review of #558, F1)",
        ),
    ),
    (
        "inode_protect.rs",
        "try_protected_open_deny",
        2,
        Enforced("a read-open of the agent's key, a write-open of its protected files"),
    ),
    (
        "inode_protect.rs",
        "try_protected_open_deny",
        1,
        Delegated("refuse_write("),
    ),
    (
        "inode_protect.rs",
        "try_protected_open_deny",
        1,
        Enforced(
            "a foreign write-open of a block device that backs the agent's files (its key's blocks under the page cache), or of its disk's sg node, refused under the kernel-read option's block-device class as its read-open is, recorded otherwise (lot 2.3a, the review of #647)",
        ),
    ),
    (
        "inode_protect.rs",
        "try_protected_open_deny",
        1,
        Delegated("refuse_memory_view("),
    ),
    (
        "inode_protect.rs",
        "try_protected_write_deny",
        1,
        Enforced("a write through a descriptor of the agent's protected files"),
    ),
    (
        "inode_protect.rs",
        "try_protected_write_deny",
        1,
        Delegated("refuse_write("),
    ),
    ("inode_protect.rs", "deny_new_entry", 1, Enforced(OWN_FILES)),
    ("inode_protect.rs", "deny_xattr", 1, Enforced(OWN_FILES)),
    (
        "module_load.rs",
        "try_read_file",
        1,
        Enforced(
            "an untrusted kernel module: it can do anything to the agent; only the signed policy relaxes the judge (module_trust::kernel_mode takes no gate)",
        ),
    ),
    (
        "module_load.rs",
        "try_load_data",
        1,
        Enforced(
            "an untrusted kernel module: it can do anything to the agent; only the signed policy relaxes the judge (module_trust::kernel_mode takes no gate)",
        ),
    ),
    (
        "module_load.rs",
        "deny_kexec",
        1,
        Enforced("a kexec image: a kernel booted without the agent's hooks (the host's integrity)"),
    ),
    (
        "mount_guard.rs",
        "answer_parts",
        1,
        Enforced(
            "a mount on, over or below the paths the agent depends on in PID 1's mount namespace (the kernel views /proc, /sys, the cgroup root and the bpffs, its directories, binaries and units, the directories above them), an unmount or move of one of their mounts, an old-API move, a pivot: a FUSE or a tmpfs there stalls or blinds every by-path read (lot 357); lot 359: any change of the pin directory's lock but its maker's own steps (a racing or out-of-bound lazy unmount would take the host's bpffs and the pins)",
        ),
    ),
    (
        "ptrace_check.rs",
        "try_ptrace_access_check",
        1,
        Enforced(
            "a ptrace of the agent, its watchdog or a worker, and an attach of PID 1: its memory swapped between a deny hook's read of a write PID 1 may make (a unit's limit, a thaw) and the kernel's (lot 273c)",
        ),
    ),
    (
        "sigio_guard.rs",
        "try_file_send_sigiotask",
        1,
        Enforced(AGENT),
    ),
    (
        "socket_connect.rs",
        "try_socket_connect",
        1,
        Gated(
            "the kernel connect deny (its EPERM a negative constant): not armed under the gate (policy::arming)",
        ),
    ),
    (
        "sysctl_guard.rs",
        "nn_sysctl_guard",
        1,
        Delegated("try_sysctl_guard("),
    ),
    (
        "sysctl_guard.rs",
        "try_sysctl_guard",
        1,
        Enforced("the sysctl guard's value judge: the values refuse_sysctl guards"),
    ),
    ("task_kill.rs", "try_task_kill", 1, Enforced(AGENT)),
    (
        "task_kill.rs",
        "try_task_kill",
        1,
        Enforced(
            "a signal to a member of an open trusted-installer window from outside its tree, PID 1's included (lot 2.3a, D7)",
        ),
    ),
    ("task_limits.rs", "task_setrlimit_deny", 1, Enforced(AGENT)),
    (
        "task_limits.rs",
        "task_setrlimit_deny",
        1,
        Enforced(
            "an outsider's resource limit on a member of an open tree window: an RLIMIT_CPU below its use is a SIGKILL no task_kill sees, mid-install (lot 2.3a, D7)",
        ),
    ),
    (
        "task_limits.rs",
        "task_setscheduler_deny",
        1,
        Enforced(AGENT),
    ),
    ("task_limits.rs", "task_setnice_deny", 1, Enforced(AGENT)),
    ("task_limits.rs", "task_setioprio_deny", 1, Enforced(AGENT)),
    (
        "window_tree.rs",
        "tree_ptrace",
        1,
        Enforced(
            "a ptrace check of a member of an open trusted-installer window from outside its tree, in either mode (a debugger, /proc/<pid>/mem, fd, environ, maps, process_vm_*, pidfd_getfd, kcmp, a perf event on its pid): what the tree runs is not changed from outside (lot 2.3a, D7)",
        ),
    ),
    (
        "window_tree.rs",
        "tree_fd_receive",
        1,
        Enforced(
            "while a tree window is open, an io_uring ring's or a protected inode's descriptor received outside the agent's family: no descriptor crosses the tree's boundary (lot 2.3a, D7)",
        ),
    ),
    // lot 2.3b (scaffold+): a process the exec quarantine holds, resumed
    (
        "task_kill.rs",
        "try_task_kill",
        1,
        Enforced(
            "a SIGCONT to a process the exec quarantine holds stopped (EXECQ_STOPPED, its start), from anyone but the agent's family: its session's fg, its parent or root would run it before its verdict (lot 2.3b, scaffold+)",
        ),
    ),
    // lot 2.3b (D5): the freeze of the system code, one site per hook
    (
        "inode_protect.rs",
        "try_inode_unlink",
        1,
        Enforced(FROZEN_SYSTEM_CODE),
    ),
    (
        "inode_protect.rs",
        "try_inode_rmdir",
        1,
        Enforced(FROZEN_SYSTEM_CODE),
    ),
    (
        "inode_protect.rs",
        "try_inode_rename",
        1,
        Enforced(FROZEN_SYSTEM_CODE),
    ),
    (
        "inode_protect.rs",
        "try_inode_setattr",
        1,
        Enforced(FROZEN_SYSTEM_CODE),
    ),
    (
        "inode_protect.rs",
        "try_protected_open_deny",
        1,
        Enforced(FROZEN_SYSTEM_CODE),
    ),
    (
        "inode_protect.rs",
        "deny_new_frozen",
        1,
        Enforced(FROZEN_SYSTEM_CODE),
    ),
    (
        "inode_protect.rs",
        "protected_link_deny",
        1,
        Enforced(FROZEN_SYSTEM_CODE),
    ),
    (
        "inode_protect.rs",
        "deny_xattr",
        1,
        Enforced(FROZEN_SYSTEM_CODE),
    ),
    (
        "window_tree.rs",
        "frozen_path",
        1,
        Enforced(FROZEN_SYSTEM_CODE),
    ),
];

/// The eBPF object's sources (all of each file: the scans read its
/// production code, [`ast::production`]), by file name under
/// `agent-ebpf/src`.
fn ebpf_code() -> BTreeMap<String, String> {
    ast::product_sources(&repo_root())
        .into_iter()
        .filter_map(|(rel, text)| {
            rel.strip_prefix("agent-ebpf/src/")
                .map(|f| (f.to_string(), text))
        })
        .collect()
}

/// The names of a refusal's errno.
const REFUSALS: [&str; 2] = ["EPERM", "EACCES"];

/// A refusal's errno as a number (`-13`).
const REFUSAL_NUMBERS: [&str; 2] = ["1", "13"];

/// The helpers that kill or stop a process.
const SIGNALS: [&str; 2] = ["bpf_send_signal", "bpf_send_signal_thread"];

/// What `cgroup_files`' refusers call to sign a refusal.
const SIGNERS: [&str; 3] = ["sign", "emit_task_denial", "emit_task_read_denial"];

/// Methods and functions that negate.
const NEGATE: [&str; 4] = ["neg", "wrapping_neg", "saturating_neg", "checked_neg"];

/// The module a path's segment before its name names (`crate::m::x`: `m`).
fn module_of(p: &[String]) -> Option<&str> {
    (p.len() >= 2).then(|| p[p.len() - 2].as_str()).filter(|m| {
        !matches!(*m, "crate" | "self" | "super")
            && m.chars().next().is_some_and(|c| c.is_ascii_lowercase())
    })
}

/// Whether `e` names a refusal's errno (`EPERM`, `libc::EACCES`, under
/// parentheses and casts).
fn is_refusal(c: &Corpus<'_>, rel: &str, e: &Expr) -> bool {
    match ast::peel(e) {
        Expr::Path(p) => c.files[rel]
            .full_paths(&ast::segments(&p.path))
            .iter()
            .any(|f| REFUSALS.contains(&f[f.len() - 1].as_str())),
        _ => false,
    }
}

/// Whether `e` is the integer literal `n` (under parentheses and casts).
fn int_is(e: &Expr, n: &[&str]) -> bool {
    matches!(ast::peel(e), Expr::Lit(l) if matches!(&l.lit, syn::Lit::Int(i) if n.contains(&i.base10_digits())))
}

/// Whether `e` negates what `inner` holds: `-x`, `0 - x`,
/// `x.wrapping_neg()`, `i32::wrapping_neg(x)`.
fn negation(e: &Expr) -> Option<&Expr> {
    match e {
        Expr::Unary(u) if matches!(u.op, syn::UnOp::Neg(_)) => Some(&u.expr),
        Expr::Binary(b) if matches!(b.op, syn::BinOp::Sub(_)) && int_is(&b.left, &["0"]) => {
            Some(&b.right)
        }
        Expr::MethodCall(m) if NEGATE.contains(&m.method.to_string().as_str()) => Some(&m.receiver),
        Expr::Call(call) if call.args.len() == 1 => match ast::peel(&call.func) {
            Expr::Path(p) if NEGATE.contains(&ast::last(&p.path).as_str()) => call.args.first(),
            _ => None,
        },
        _ => None,
    }
}

/// Whether the `const`/`static` initialiser `e` is negative.
fn negative(e: &Expr) -> bool {
    negation(ast::peel(e)).is_some()
}

/// Whether the path `segs`, written in `rel`, names a constant defined
/// negative (`const EPERM: i32 = -1;`, the connect deny's spelling): the
/// file's own, an import's, or the module's the path names.
fn negative_const(c: &Corpus<'_>, rel: &str, segs: &[String]) -> bool {
    let module_files = |m: &str| -> Vec<String> {
        c.files
            .keys()
            .filter(|f| *f == &format!("{m}.rs") || f.ends_with(&format!("/{m}.rs")))
            .cloned()
            .collect()
    };
    c.files[rel].full_paths(segs).iter().any(|p| {
        let name = &p[p.len() - 1];
        let files = match module_of(p) {
            Some(m) => module_files(m),
            None => vec![rel.to_string()],
        };
        files.iter().any(|f| {
            c.files[f]
                .consts
                .get(name)
                .is_some_and(|es| es.iter().any(|e| negative(e)))
        })
    })
}

/// Whether a pattern names the sysctl program's refusal verdict.
fn refuse_pattern(p: &syn::Pat) -> bool {
    struct V(bool);
    impl<'a> Visit<'a> for V {
        fn visit_path(&mut self, p: &'a syn::Path) {
            self.0 |= ast::last(p) == "Refuse";
        }
        fn visit_ident(&mut self, i: &'a proc_macro2::Ident) {
            self.0 |= i == "Refuse";
        }
    }
    let mut v = V(false);
    v.visit_pat(p);
    v.0
}

/// Counts the deny sites of one function's body, its nested functions left
/// out (each counted on its own).
struct Census<'c, 'a> {
    c: &'c Corpus<'a>,
    rel: &'c str,
    sysctl: bool,
    refuser: bool,
    n: usize,
}

impl<'a> Visit<'a> for Census<'_, 'a> {
    fn visit_expr(&mut self, e: &'a Expr) {
        if negation(e).is_some_and(|x| is_refusal(self.c, self.rel, x)) {
            self.n += 1;
        }
        match e {
            Expr::Path(p) => {
                let segs = ast::segments(&p.path);
                let full = self.c.files[self.rel].full_paths(&segs);
                let named =
                    |list: &[&str]| full.iter().any(|f| list.contains(&f[f.len() - 1].as_str()));
                if named(&SIGNALS)
                    || (self.refuser && named(&SIGNERS))
                    || negative_const(self.c, self.rel, &segs)
                {
                    self.n += 1;
                }
            }
            Expr::MethodCall(m)
                if self.refuser && SIGNERS.contains(&m.method.to_string().as_str()) =>
            {
                self.n += 1
            }
            Expr::Let(l) if self.sysctl && refuse_pattern(&l.pat) => self.n += 1,
            _ => {}
        }
        visit::visit_expr(self, e);
    }
    fn visit_arm(&mut self, a: &'a syn::Arm) {
        if self.sysctl && refuse_pattern(&a.pat) {
            self.n += 1;
        }
        visit::visit_arm(self, a);
    }
    fn visit_local(&mut self, l: &'a syn::Local) {
        if self.sysctl
            && l.init.as_ref().is_some_and(|i| i.diverge.is_some())
            && refuse_pattern(&l.pat)
        {
            self.n += 1;
        }
        visit::visit_local(self, l);
    }
    fn visit_item_fn(&mut self, _: &'a syn::ItemFn) {}
    fn visit_impl_item_fn(&mut self, _: &'a syn::ImplItemFn) {}
}

/// The refusals by number a function returns (`return -13;`, an `if`'s or
/// a `match`'s branch of its returned value, a `let` it returns): each
/// literal once.
fn returned_numbers<'a>(
    f: &ast::FnInfo<'a>,
    e: &'a Expr,
    depth: u8,
    out: &mut BTreeSet<*const Expr>,
) {
    if depth > 8 {
        return;
    }
    let block_tail = |b: &'a syn::Block| match b.stmts.last() {
        Some(syn::Stmt::Expr(t, None)) => Some(t),
        _ => None,
    };
    match ast::peel(e) {
        x @ Expr::Unary(u)
            if matches!(u.op, syn::UnOp::Neg(_)) && int_is(&u.expr, &REFUSAL_NUMBERS) =>
        {
            out.insert(x as *const Expr);
        }
        Expr::Block(b) => {
            if let Some(t) = block_tail(&b.block) {
                returned_numbers(f, t, depth + 1, out);
            }
        }
        Expr::Unsafe(b) => {
            if let Some(t) = block_tail(&b.block) {
                returned_numbers(f, t, depth + 1, out);
            }
        }
        Expr::If(i) => {
            if let Some(t) = block_tail(&i.then_branch) {
                returned_numbers(f, t, depth + 1, out);
            }
            if let Some((_, el)) = &i.else_branch {
                returned_numbers(f, el, depth + 1, out);
            }
        }
        Expr::Match(m) => {
            for a in &m.arms {
                returned_numbers(f, &a.body, depth + 1, out);
            }
        }
        Expr::Return(r) => {
            if let Some(x) = &r.expr {
                returned_numbers(f, x, depth + 1, out);
            }
        }
        Expr::Path(p) if p.path.segments.len() == 1 => {
            for b in f.bindings.get(&ast::last(&p.path)).into_iter().flatten() {
                if !b.param {
                    returned_numbers(f, b.expr, depth + 1, out);
                }
            }
        }
        _ => {}
    }
}

/// The name a census row gives function `id` of `ix`: its own, or `m!` for
/// a rule of `macro_rules! m`.
fn row_name(ix: &ast::Index<'_>, id: ast::FnId) -> String {
    let f = &ix.fns[id];
    match ast::rule_macro(&f.item) {
        Some(m) => format!("{m}!"),
        None => f.name.clone(),
    }
}

/// The deny sites of the object, by `(file, function)`: each refusal's
/// errno negated (`-EPERM`, `-(EACCES)`, `0 - EPERM`,
/// `EPERM.wrapping_neg()`, a path to it), returned or stored; each use of a
/// constant defined negative (`const EPERM: i32 = -1;`, returned bare — the
/// connect deny's spelling — from this file or another); a refusal's number
/// returned (`return -13;`); each kill or stop the kernel sends
/// (`bpf_send_signal`, `bpf_send_signal_thread`, called or taken as a
/// value, under any import's name); the sysctl program's refusal verdict;
/// and each refusal `cgroup_files`' refusers sign (their `true` makes
/// `refuse_write`'s caller return `-EPERM`). A `macro_rules!`'s rule is
/// counted as `name!`.
fn deny_census(code: &BTreeMap<String, String>) -> BTreeMap<(String, String), usize> {
    let parsed = ast::parse_all(code, true);
    let c = Corpus::of(code, &parsed);
    let mut found: BTreeMap<(String, String), usize> = BTreeMap::new();
    for (file, ix) in &c.files {
        for (id, f) in ix.fns.iter().enumerate() {
            let Some(body) = f.body else {
                continue;
            };
            let name = row_name(ix, id);
            let mut census = Census {
                c: &c,
                rel: file,
                sysctl: file == "sysctl_guard.rs",
                refuser: file == "cgroup_files.rs"
                    && name.starts_with("refuse_")
                    && name != "refuse_write",
                n: 0,
            };
            census.visit_block(body);
            let mut numbers = BTreeSet::new();
            for r in &f.returns {
                returned_numbers(f, r, 0, &mut numbers);
            }
            let n = census.n + numbers.len();
            if n > 0 {
                *found.entry((file.clone(), name)).or_default() += n;
            }
        }
    }
    found
}

/// The source of function `name` of `file` (its body), found as Rust: the
/// one function of that name (two fail).
fn body_source(code: &BTreeMap<String, String>, file: &str, name: &str) -> String {
    let rel = file.to_string();
    let one: BTreeMap<String, String> = [(rel.clone(), code[file].clone())].into();
    let parsed = ast::parse_all(&one, true);
    let c = Corpus::of(&one, &parsed);
    let ix = &c.files[&rel];
    let bodies: Vec<&syn::Block> = ix
        .fns
        .iter()
        .filter(|f| f.name == name)
        .filter_map(|f| f.body)
        .collect();
    assert_eq!(
        bodies.len(),
        1,
        "fn {name} in {file}: {} found",
        bodies.len()
    );
    let b = bodies[0];
    ix.source(b.brace_token.span.open(), b.brace_token.span.close())
}

/// Whether `w` is a word of `hay` (not part of a longer name).
fn has_word(hay: &str, w: &str) -> bool {
    let b = hay.as_bytes();
    let ident = |c: u8| c.is_ascii_alphanumeric() || c == b'_';
    hay.match_indices(w).any(|(at, _)| {
        (at == 0 || !ident(b[at - 1])) && b.get(at + w.len()).is_none_or(|c| !ident(*c))
    })
}

/// The lines of `items` (a file's or a module's) that name `switch` outside
/// a function's body and outside the `static` that declares it; a
/// `macro_rules!` (read as its rules) is outside every function.
fn named_outside_functions(items: &[Item], switch: &str, out: &mut BTreeSet<usize>) {
    let add = |t: proc_macro2::TokenStream, out: &mut BTreeSet<usize>| {
        for (w, l) in ast::idents(t) {
            if w == switch {
                out.insert(l);
            }
        }
    };
    for item in items {
        match item {
            Item::Fn(_) => {}
            Item::Static(s) if s.ident == switch => {}
            Item::Mod(m) if !m.ident.to_string().starts_with(ast::MACRO) => {
                if let Some((_, inner)) = &m.content {
                    named_outside_functions(inner, switch, out);
                }
            }
            Item::Impl(i) => {
                for ii in &i.items {
                    if !matches!(ii, syn::ImplItem::Fn(_)) {
                        add(ii.to_token_stream(), out);
                    }
                }
            }
            Item::Trait(t) => {
                for ti in &t.items {
                    match ti {
                        syn::TraitItem::Fn(f) => add(f.sig.to_token_stream(), out),
                        other => add(other.to_token_stream(), out),
                    }
                }
            }
            other => add(other.to_token_stream(), out),
        }
    }
}

/// The `macro_rules!` of `items` (read as their rules' module), by name.
fn macro_modules<'f>(items: &'f [Item], out: &mut Vec<(String, &'f syn::ItemMod)>) {
    for item in items {
        if let Item::Mod(m) = item {
            let name = m.ident.to_string();
            match name.strip_prefix(&format!("{}rules_", ast::MACRO)) {
                Some(mac) => out.push((mac.to_string(), m)),
                None => {
                    if let Some((_, inner)) = &m.content {
                        macro_modules(inner, out);
                    }
                }
            }
        }
    }
}

/// The gate's switches a self-protection site reaches, read as Rust: for
/// each `Enforced` row, its function and every function, `const` and
/// `static` of the object it may run or read, to any depth
/// ([`ast::Graph`]: through imports, re-exports, macros, methods, a function
/// passed as a value, held in an array, a tuple, a struct, an `Option` or
/// behind parentheses), and each switch one of them names — `(site, the
/// code that names it, the switch)`. Also each switch named in a file other
/// than its own (an alias, a re-export: the name is the only handle the
/// code reads it by), each named by a macro, and each named in its own file
/// outside a function's body and its declaration.
fn gate_reads(code: &BTreeMap<String, String>) -> Vec<String> {
    let parsed = ast::parse_all(code, true);
    let c = Corpus::of(code, &parsed);
    let g = ast::Graph::new(&c);
    let mut found = Vec::new();
    for (file, f) in &parsed {
        let ix = &c.files[file];
        let words: BTreeSet<String> = ast::idents(f.to_token_stream())
            .into_iter()
            .map(|(w, _)| w)
            .collect();
        for (switch, owner) in GATE_SWITCHES {
            if file != owner
                && (words.contains(*switch) || ix.lits.iter().any(|l| has_word(&l.value, switch)))
            {
                found.push(format!("{file} names {switch} (only {owner:?} may)"));
            }
        }
        // Lot 345 (the re-check of #550, N1): no macro names a switch — a
        // macro of the switch's own file expands wherever it is invoked
        let mut macros = Vec::new();
        macro_modules(&f.items, &mut macros);
        for (name, m) in macros {
            let words: BTreeSet<String> = ast::idents(m.to_token_stream())
                .into_iter()
                .map(|(w, _)| w)
                .collect();
            for (switch, _) in GATE_SWITCHES {
                if words.contains(*switch) {
                    found.push(format!("{file} macro {name}! names {switch}"));
                }
            }
        }
        // … and in its own file a switch is named only in its declaration
        // and inside a function's body: a re-export (`use self::SWITCH as
        // X`), a constant or a static of it is another name to read it by
        for (switch, owner) in GATE_SWITCHES {
            if file != owner {
                continue;
            }
            let mut lines = BTreeSet::new();
            named_outside_functions(&f.items, switch, &mut lines);
            for l in lines {
                let text = code[file].lines().nth(l - 1).unwrap_or("").trim();
                found.push(format!(
                    "{file} names {switch} outside a function and its declaration: {text}"
                ));
            }
        }
    }
    for (file, name, _, route) in SITES {
        if !matches!(route, Enforced(_)) {
            continue;
        }
        let start = g.method(file, name);
        for n in g.reach(&start).keys() {
            let words: BTreeSet<String> = ast::idents(g.tokens(n))
                .into_iter()
                .map(|(w, _)| w)
                .collect();
            for (switch, _) in GATE_SWITCHES {
                let is_it = matches!(n, ast::Node::Value(_, v, _) if v == switch);
                if words.contains(*switch) || is_it {
                    found.push(format!(
                        "{file} {name} reaches {switch} through {} {}",
                        n.file(),
                        g.name(n)
                    ));
                }
            }
        }
    }
    found.sort();
    found.dedup();
    found
}

/// Named: every deny site of the eBPF object is classified — the agent's
/// self-protection or the host's integrity (with its reason), a response
/// path whose mode the gate sets, or a function that returns a classified
/// one's verdict. A new site, or one more in a function, fails here until
/// it is classified.
#[test]
fn every_deny_site_is_listed_enforced_or_gated() {
    let code = ebpf_code();
    let found = deny_census(&code);
    let mut listed: BTreeMap<(String, String), usize> = BTreeMap::new();
    for (file, name, n, route) in SITES {
        *listed
            .entry((file.to_string(), name.to_string()))
            .or_default() += n;
        match route {
            Enforced(why) | Gated(why) => assert!(!why.is_empty()),
            Delegated(call) => {
                let body = body_source(&code, file, name);
                assert!(
                    body.contains(call),
                    "{file} {name} returns {call}…'s verdict"
                );
            }
        }
    }
    let census: Vec<String> = found
        .iter()
        .map(|((f, n), c)| format!("({f:?}, {n:?}, {c})"))
        .collect();
    assert_eq!(
        found, listed,
        "the deny sites of agent-ebpf changed — classify each (Enforced with its reason, \
         Gated, Delegated): {census:#?}"
    );
}

/// Named (the review of #550, F1–F4, F6): no self-protection site reads a
/// switch of the gate — not in its own body, not through a helper of the
/// object it calls at any depth — and no file but a switch's own names it.
/// The first round's host-wide switch (`HOST_DENY_MODE`) is gone.
#[test]
fn the_self_protection_reads_no_switch_of_the_gate() {
    let code = ebpf_code();
    let reads = gate_reads(&code);
    assert!(
        reads.is_empty(),
        "the agent's self-protection must hold under every profile: {reads:#?}"
    );
    assert!(!code.contains_key("host_deny.rs"));
    let parsed = ast::parse_all(&code, true);
    let c = Corpus::of(&code, &parsed);
    for (switch, owner) in GATE_SWITCHES {
        if !owner.is_empty() {
            assert!(
                c.files[*owner].consts.contains_key(*switch),
                "{owner} declares {switch} (the list is current)"
            );
        }
    }
}

/// `code` with `helper` added to `file` and `call` put first in `site`'s
/// body.
fn planted(
    code: &BTreeMap<String, String>,
    file: &str,
    site: &str,
    call: &str,
    helper: &str,
) -> BTreeMap<String, String> {
    let mut code = code.clone();
    let text = code.get_mut(file).expect("the site's file");
    let at = text
        .find(&format!("fn {site}("))
        .unwrap_or_else(|| panic!("fn {site} in {file}"));
    let open = at + text[at..].find('{').expect("a body") + 1;
    text.insert_str(open, call);
    text.push_str(helper);
    code
}

/// Named (the review of #550, F6: its probe, planted): a self-protection
/// function that reads a switch of the gate through a helper — one or two
/// calls deep, or by an alias — fails the ratchet. The review's probe read
/// the first round's switch from `try_task_kill` through `probe_relaxed`
/// and the ratchet stayed green.
#[test]
fn a_helper_that_reads_the_gate_from_the_self_protection_is_caught() {
    let code = ebpf_code();
    assert!(gate_reads(&code).is_empty());
    let one = planted(
        &code,
        "task_kill.rs",
        "try_task_kill",
        "\n    if probe_relaxed() {\n        return 0;\n    }\n",
        "\n#[inline(always)]\nfn probe_relaxed() -> bool {\n    \
         matches!(unsafe { crate::execq::EXECQ_CONF.get(0) }, Some(m) if *m != 0)\n}\n",
    );
    let r = gate_reads(&one);
    assert!(
        r.iter()
            .any(|l| l.contains("try_task_kill reaches EXECQ_CONF")),
        "{r:#?}"
    );
    // two calls deep, the switch read in its own file (no name outside it)
    let mut deep = planted(
        &code,
        "task_kill.rs",
        "try_task_kill",
        "\n    if relaxed_outer() {\n        return 0;\n    }\n",
        // and a harmless function of the same name in the site's own file:
        // the path names which one runs
        "\nfn relaxed_outer() -> bool {\n    crate::execpol::relaxed_inner()\n}\n\
         \nfn relaxed_inner() -> bool {\n    false\n}\n",
    );
    deep.get_mut("execpol.rs").unwrap().push_str(
        "\npub(crate) fn relaxed_inner() -> bool {\n    EXECPOL_CONF.get(0).is_none()\n}\n",
    );
    let r = gate_reads(&deep);
    assert!(
        r.iter()
            .any(|l| l
                .contains("try_task_kill reaches EXECPOL_CONF through execpol.rs relaxed_inner")),
        "{r:#?}"
    );
    // a bare call of a helper another file defines (`use`d), reading the
    // switch in its own file
    let mut bare = planted(
        &code,
        "task_kill.rs",
        "try_task_kill",
        "\n    if is_relaxed() {\n        return 0;\n    }\n",
        "\nuse crate::execq::is_relaxed;\n",
    );
    bare.get_mut("execq.rs")
        .unwrap()
        .push_str("\npub(crate) fn is_relaxed() -> bool {\n    EXECQ_CONF.get(0).is_none()\n}\n");
    let r = gate_reads(&bare);
    assert!(
        r.iter()
            .any(|l| l.contains("try_task_kill reaches EXECQ_CONF through execq.rs is_relaxed")),
        "{r:#?}"
    );
    // an alias of the switch in a self-protection file
    let alias = planted(
        &code,
        "cgroup_files.rs",
        "refuse_sysctl",
        "\n    if MODE.get(0).is_some() {\n        return false;\n    }\n",
        "\nuse crate::socket_connect::NET_CONNECT_DENY_MODE as MODE;\n",
    );
    let r = gate_reads(&alias);
    assert!(
        r.iter()
            .any(|l| l.contains("cgroup_files.rs names NET_CONNECT_DENY_MODE")),
        "{r:#?}"
    );
    // the first round's switch, back under any name of a site's helper
    let back = planted(
        &code,
        "sysctl_guard.rs",
        "try_sysctl_guard",
        "\n    if observes() {\n        return 1;\n    }\n",
        "\nfn observes() -> bool {\n    HOST_DENY_MODE.get(0).is_some()\n}\n",
    );
    let r = gate_reads(&back);
    assert!(
        r.iter()
            .any(|l| l.contains("try_sysctl_guard reaches HOST_DENY_MODE")),
        "{r:#?}"
    );
}

/// Named (lot 345; the re-check of #550, N1 — its probe, planted): a
/// re-export of a switch in its own file, a macro of that file reading it
/// and a helper of that file taken as a function pointer, each read from
/// the self-protection, fail the ratchet. All three left it green.
#[test]
fn a_re_export_a_macro_and_a_function_pointer_of_the_gate_are_caught() {
    let code = ebpf_code();
    assert!(gate_reads(&code).is_empty(), "{:#?}", gate_reads(&code));
    // (a) a re-export in the switch's own file, read through its new name
    let mut reexport = planted(
        &code,
        "task_kill.rs",
        "try_task_kill",
        "\n    if unsafe { crate::execq::RELAX_Q.get(0) }.is_some() {\n        return 0;\n    }\n",
        "",
    );
    reexport
        .get_mut("execq.rs")
        .unwrap()
        .push_str("\npub(crate) use self::EXECQ_CONF as RELAX_Q;\n");
    let r = gate_reads(&reexport);
    assert!(
        r.iter().any(
            |l| l.contains("execq.rs names EXECQ_CONF outside a function") && l.contains("RELAX_Q")
        ),
        "{r:#?}"
    );
    // lot 1.7b: a static of the switch's own file that holds it under
    // another name — its declaration is the switch's only one
    let mut held = planted(
        &code,
        "task_kill.rs",
        "try_task_kill",
        "\n    if unsafe { crate::execq::RELAX_S.get(0) }.is_some() {\n        return 0;\n    }\n",
        "",
    );
    held.get_mut("execq.rs")
        .unwrap()
        .push_str("\npub(crate) static RELAX_S: &aya_ebpf::maps::Array<u64> = &EXECQ_CONF;\n");
    let r = gate_reads(&held);
    assert!(
        r.iter().any(
            |l| l.contains("execq.rs names EXECQ_CONF outside a function") && l.contains("RELAX_S")
        ),
        "{r:#?}"
    );
    // lot 1.7b: a re-export of a helper in its own file, called by its new
    // name through the module's path (no switch named outside a function)
    let mut helper = planted(
        &code,
        "task_kill.rs",
        "try_task_kill",
        "\n    if crate::execq::relaxed_again() {\n        return 0;\n    }\n",
        "",
    );
    helper.get_mut("execq.rs").unwrap().push_str(
        "\npub(crate) use self::is_relaxed_ptr as relaxed_again;\n\
         \npub(crate) fn is_relaxed_ptr() -> bool {\n    EXECQ_CONF.get(0).is_none()\n}\n",
    );
    let r = gate_reads(&helper);
    assert!(
        r.iter()
            .any(|l| l.contains("try_task_kill reaches EXECQ_CONF through execq.rs is_relaxed_ptr")),
        "{r:#?}"
    );
    // (b) a macro in the switch's own file, invoked from the site
    let mut mac = planted(
        &code,
        "task_kill.rs",
        "try_task_kill",
        "\n    if crate::execq::execq_relaxed!() {\n        return 0;\n    }\n",
        "",
    );
    mac.get_mut("execq.rs").unwrap().push_str(
        "\nmacro_rules! execq_relaxed {\n    () => {\n        matches!(unsafe { crate::execq::EXECQ_CONF.get(0) }, Some(m) if *m != 0)\n    };\n}\npub(crate) use execq_relaxed;\n",
    );
    let r = gate_reads(&mac);
    assert!(
        r.iter()
            .any(|l| l.contains("execq.rs macro execq_relaxed! names EXECQ_CONF")),
        "{r:#?}"
    );
    assert!(
        r.iter()
            .any(|l| l.contains("try_task_kill reaches EXECQ_CONF through execq.rs execq_relaxed")),
        "the site follows the macro: {r:#?}"
    );
    // a macro that reads it through a helper of the file, not by name
    let mut via = planted(
        &code,
        "task_kill.rs",
        "try_task_kill",
        "\n    if crate::execq::relaxed_m!() {\n        return 0;\n    }\n",
        "",
    );
    via.get_mut("execq.rs").unwrap().push_str(
        "\nmacro_rules! relaxed_m {\n    () => {\n        crate::execq::relaxed_inner()\n    };\n}\n\
         \npub(crate) fn relaxed_inner() -> bool {\n    EXECQ_CONF.get(0).is_none()\n}\n",
    );
    let r = gate_reads(&via);
    assert!(
        r.iter()
            .any(|l| l.contains("try_task_kill reaches EXECQ_CONF through execq.rs relaxed_inner")),
        "{r:#?}"
    );
    // (c) a helper of the switch's file called through a function pointer
    let mut ptr = planted(
        &code,
        "task_kill.rs",
        "try_task_kill",
        "\n    let relaxed = crate::execq::is_relaxed_ptr;\n    if relaxed() {\n        return 0;\n    }\n",
        "",
    );
    ptr.get_mut("execq.rs").unwrap().push_str(
        "\npub(crate) fn is_relaxed_ptr() -> bool {\n    EXECQ_CONF.get(0).is_none()\n}\n",
    );
    let r = gate_reads(&ptr);
    assert!(
        r.iter()
            .any(|l| l.contains("try_task_kill reaches EXECQ_CONF through execq.rs is_relaxed_ptr")),
        "{r:#?}"
    );
    // … and by its bare name after a `use`
    let mut bare = planted(
        &code,
        "task_kill.rs",
        "try_task_kill",
        "\n    let relaxed = is_relaxed_ptr;\n    if relaxed() {\n        return 0;\n    }\n",
        "\nuse crate::execq::is_relaxed_ptr;\n",
    );
    bare.get_mut("execq.rs").unwrap().push_str(
        "\npub(crate) fn is_relaxed_ptr() -> bool {\n    EXECQ_CONF.get(0).is_none()\n}\n",
    );
    let r = gate_reads(&bare);
    assert!(
        r.iter()
            .any(|l| l.contains("try_task_kill reaches EXECQ_CONF through execq.rs is_relaxed_ptr")),
        "{r:#?}"
    );
    // the mini-hunt: a `use … as` alias of the helper, and a static
    // function pointer to it, in the site's file
    for (call, helper) in [
        (
            "\n    if relaxed() {\n        return 0;\n    }\n",
            "\nuse crate::execq::{is_relaxed_ptr as relaxed};\n",
        ),
        (
            "\n    if RELAXED() {\n        return 0;\n    }\n",
            "\nstatic RELAXED: fn() -> bool = crate::execq::is_relaxed_ptr;\n",
        ),
    ] {
        let mut other = planted(&code, "task_kill.rs", "try_task_kill", call, helper);
        other.get_mut("execq.rs").unwrap().push_str(
            "\npub(crate) fn is_relaxed_ptr() -> bool {\n    EXECQ_CONF.get(0).is_none()\n}\n",
        );
        let r = gate_reads(&other);
        assert!(
            r.iter()
                .any(|l| l
                    .contains("try_task_kill reaches EXECQ_CONF through execq.rs is_relaxed_ptr")),
            "{helper}: {r:#?}"
        );
    }
}

/// Named (the review of #553, F3): the four spellings its probe planted in
/// `task_kill.rs`, each reaching `EXECQ_CONF` from `try_task_kill` through
/// `execq::is_relaxed_ptr`, left the ratchet green — a `pub(super) use … as`,
/// a `use … as` behind an attribute, a `static` whose type is a `type`
/// alias of a function pointer, a `pub(super) static`. Each is caught, and
/// a mini-hunt's variants with them (`pub(in crate)`, two attributes, a
/// `const` through an alias, `&` before the path), and (lot 1.7b) the
/// re-check's probes the lexical scan caught (a local `let`, a module
/// alias, a `static mut`, a `pub(self) use`).
#[test]
fn a_restricted_re_export_an_attributed_use_and_an_aliased_static_are_caught() {
    let code = ebpf_code();
    let helper_fn =
        "\npub(crate) fn is_relaxed_ptr() -> bool {\n    EXECQ_CONF.get(0).is_none()\n}\n";
    let lower = "\n    if relaxed() {\n        return 0;\n    }\n";
    let upper = "\n    if RELAXED() {\n        return 0;\n    }\n";
    let cases = [
        (
            "pub(super) use",
            lower,
            "\npub(super) use crate::execq::is_relaxed_ptr as relaxed;\n",
        ),
        (
            "attr use",
            lower,
            "\n#[allow(unused_imports)] use crate::execq::is_relaxed_ptr as relaxed;\n",
        ),
        (
            "type alias static",
            upper,
            "\ntype RelaxFn = fn() -> bool;\nstatic RELAXED: RelaxFn = crate::execq::is_relaxed_ptr;\n",
        ),
        (
            "pub(super) static",
            upper,
            "\npub(super) static RELAXED: fn() -> bool = crate::execq::is_relaxed_ptr;\n",
        ),
        // the mini-hunt
        (
            "pub(in crate) use",
            lower,
            "\npub(in crate) use crate::execq::{is_relaxed_ptr as relaxed};\n",
        ),
        (
            "two attributes",
            lower,
            "\n#[allow(unused_imports)]\n#[cfg(not(test))]\nuse crate::execq::is_relaxed_ptr as relaxed;\n",
        ),
        (
            "const via alias",
            upper,
            "\ntype RelaxFn = fn() -> bool;\npub(crate) const RELAXED: RelaxFn = crate::execq::is_relaxed_ptr;\n",
        ),
        (
            "static of a reference",
            upper,
            "\nstatic RELAXED: &RelaxFn = &crate::execq::is_relaxed_ptr;\n",
        ),
        // lot 1.7b: the re-check of #553's other probes, read as Rust
        (
            "a local let",
            "\n    let relaxed: fn() -> bool = crate::execq::is_relaxed_ptr;\n    if relaxed() {\n        return 0;\n    }\n",
            "",
        ),
        (
            "a module alias",
            "\n    if q::is_relaxed_ptr() {\n        return 0;\n    }\n",
            "\nuse crate::execq as q;\n",
        ),
        (
            "pub(crate) static mut",
            upper,
            "\npub(crate) static mut RELAXED: fn() -> bool = crate::execq::is_relaxed_ptr;\n",
        ),
        (
            "pub(self) use",
            lower,
            "\npub(self) use crate::execq::is_relaxed_ptr as relaxed;\n",
        ),
        // lot 1.7b: a module the scan cannot place (an inline module's glob
        // import) — every file's function of that name is followed
        (
            "an inline module's glob",
            "\n    if inner::is_relaxed_ptr() {\n        return 0;\n    }\n",
            "\nmod inner {\n    pub(crate) use crate::execq::*;\n}\n",
        ),
    ];
    let mut green = Vec::new();
    for (what, call, helper) in cases {
        let mut c = planted(&code, "task_kill.rs", "try_task_kill", call, helper);
        c.get_mut("execq.rs").unwrap().push_str(helper_fn);
        let r = gate_reads(&c);
        if !r
            .iter()
            .any(|l| l.contains("try_task_kill reaches EXECQ_CONF"))
        {
            green.push(what);
        }
    }
    assert!(green.is_empty(), "ratchet stays green for: {green:?}");
}

/// Lot 1.7b (the re-check of #553, F3, and the mini-hunt): the spellings
/// the lexical scans missed, each planted in a copy of the object. A gate's
/// switch reached from `try_task_kill` through `execq::is_relaxed_ptr` held
/// behind parentheses or in an array (the re-check's probe), in a tuple, in
/// a struct's field or in an `Option` whose type is an alias: the lexical
/// scan stays green, the AST scan finds the read. A deny site spelt as
/// `-(EPERM)`, `0 - EPERM`, `EPERM.wrapping_neg()`, a number returned
/// (`-13`, through an `if` or a `let`), `bpf_send_signal_thread`, a kill
/// taken as a value or under an import's name, a constant made negative by
/// a subtraction, or inside a `macro_rules!`: the lexical census counts
/// nothing more, the AST census one site more.
#[test]
fn the_lexical_bypasses_are_caught() {
    let code = ebpf_code();
    let helper_fn =
        "\npub(crate) fn is_relaxed_ptr() -> bool {\n    EXECQ_CONF.get(0).is_none()\n}\n";
    for (what, call, helper) in [
        (
            "parentheses",
            "\n    if RELAXED() {\n        return 0;\n    }\n",
            "\ntype RelaxFn = fn() -> bool;\nstatic RELAXED: RelaxFn = (crate::execq::is_relaxed_ptr);\n",
        ),
        (
            "an array",
            "\n    if RELAXED[0]() {\n        return 0;\n    }\n",
            "\nstatic RELAXED: [fn() -> bool; 1] = [crate::execq::is_relaxed_ptr];\n",
        ),
        (
            "a tuple",
            "\n    if (RELAXED.0)() {\n        return 0;\n    }\n",
            "\ntype Pair = (RelaxFn, u8);\ntype RelaxFn = fn() -> bool;\nstatic RELAXED: Pair = (crate::execq::is_relaxed_ptr, 0);\n",
        ),
        (
            "a struct's field",
            "\n    if (RELAXED.f)() {\n        return 0;\n    }\n",
            "\nstruct Relax {\n    f: fn() -> bool,\n}\nstatic RELAXED: Relax = Relax {\n    f: crate::execq::is_relaxed_ptr,\n};\n",
        ),
        (
            "an Option",
            "\n    if let Some(r) = RELAXED {\n        if r() {\n            return 0;\n        }\n    }\n",
            "\ntype Maybe = Option<fn() -> bool>;\nstatic RELAXED: Maybe = Some(crate::execq::is_relaxed_ptr);\n",
        ),
    ] {
        let mut c = planted(&code, "task_kill.rs", "try_task_kill", call, helper);
        c.get_mut("execq.rs").unwrap().push_str(helper_fn);
        let reached = |r: Vec<String>| {
            r.iter().any(|l| {
                l.contains("try_task_kill reaches EXECQ_CONF through execq.rs is_relaxed_ptr")
            })
        };
        assert!(
            !reached(lexical::gate_reads(&c)),
            "the lexical scan saw it: {what}"
        );
        assert!(reached(gate_reads(&c)), "{what}: {:#?}", gate_reads(&c));
    }
    let host = "task_limits.rs";
    let total = |m: &BTreeMap<(String, String), usize>| -> usize {
        m.iter()
            .filter(|((f, _), _)| f == host)
            .map(|(_, n)| n)
            .sum()
    };
    let (base_lex, base) = (total(&lexical::census(&code)), total(&deny_census(&code)));
    for plant in [
        "fn planted() -> c_int { -(EPERM) }",
        "fn planted() -> c_int { 0 - EPERM }",
        "fn planted() -> c_int { EPERM.wrapping_neg() }",
        "fn planted(r: bool) -> c_int { return if r { -1 } else { 0 }; }",
        "fn planted(r: bool) -> c_int {\n    if r { 0 } else { -13 }\n}",
        "fn planted() -> c_int {\n    let rc = -1;\n    rc\n}",
        "fn planted() -> i64 { unsafe { aya_ebpf::helpers::generated::bpf_send_signal_thread(9) } }",
        "fn planted() -> i64 {\n    let kill = aya_ebpf::helpers::generated::bpf_send_signal;\n    unsafe { kill(9) }\n}",
        "use aya_ebpf::helpers::generated::bpf_send_signal as quiet;\nfn planted() -> i64 { unsafe { quiet(9) } }",
        "const DENIED: c_int = 0 - EPERM;\nfn planted() -> c_int { DENIED }",
        "macro_rules! denied {\n    () => {\n        -EPERM\n    };\n}\nfn planted() -> c_int { denied!() }",
    ] {
        let mut copy = code.clone();
        copy.get_mut(host)
            .unwrap()
            .push_str(&format!("\n{plant}\n"));
        assert_eq!(
            total(&lexical::census(&copy)),
            base_lex,
            "the lexical census saw it: {plant}"
        );
        assert_eq!(
            total(&deny_census(&copy)),
            base + 1,
            "{plant}: {:#?}",
            deny_census(&copy)
        );
    }
}

/// The scans before lot 1.7b, kept only to show the spellings they missed:
/// each function found by `fn ` in the text, each site and each switch by
/// its spelling.
mod lexical {
    use std::collections::{BTreeMap, BTreeSet};

    use super::support::{matching_brace, production, strip_comments};
    use super::{Enforced, GATE_SWITCHES, SITES};

    /// `code` as the lexical scans read it: comments and test items
    /// blanked.
    fn text_of(code: &BTreeMap<String, String>) -> BTreeMap<String, String> {
        code.iter()
            .map(|(f, t)| (f.clone(), production(&strip_comments(t))))
            .collect()
    }

    /// The deny sites by `(file, function)`, as the lexical census counted
    /// them.
    pub fn census(code: &BTreeMap<String, String>) -> BTreeMap<(String, String), usize> {
        let mut found: BTreeMap<(String, String), usize> = BTreeMap::new();
        for (file, text) in &text_of(code) {
            for (name, body) in functions(text) {
                let n = deny_sites(file, text, &name, body);
                if n > 0 {
                    *found.entry((file.clone(), name)).or_default() += n;
                }
            }
        }
        found
    }

    /// The lexical gate reads of `code`.
    pub fn gate_reads(code: &BTreeMap<String, String>) -> Vec<String> {
        gate_reads_of(&text_of(code))
    }

    /// Every function of `code` with a body: `(name, body)`.
    fn functions(code: &str) -> Vec<(String, &str)> {
        function_spans(code)
            .into_iter()
            .map(|(name, start, end)| (name, &code[start..end]))
            .collect()
    }

    /// Lot 345 (the re-check of #550, N1): every `macro_rules!` of `code` with
    /// its body: `(name, body)` — a macro is followed like a function.
    fn macros(code: &str) -> Vec<(String, &str)> {
        let mut out = Vec::new();
        let mut from = 0;
        while let Some(i) = code[from..].find("macro_rules!") {
            let at = from + i + "macro_rules!".len();
            from = at;
            let name: String = code[at..]
                .trim_start()
                .chars()
                .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
                .collect();
            let Some(open) = code[at..].find('{') else {
                continue;
            };
            let start = at + open;
            let len = matching_brace(&code[start..]);
            out.push((name, &code[start..start + len]));
        }
        out
    }

    /// Every function of `code` with a body: `(name, start, end)` of its body.
    fn function_spans(code: &str) -> Vec<(String, usize, usize)> {
        let mut out = Vec::new();
        let mut from = 0;
        while let Some(i) = code[from..].find("fn ") {
            let at = from + i;
            from = at + 3;
            if at > 0 {
                let prev = code.as_bytes()[at - 1];
                if prev.is_ascii_alphanumeric() || prev == b'_' {
                    continue;
                }
            }
            let rest = &code[at + 3..];
            let name: String = rest
                .chars()
                .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
                .collect();
            if name.is_empty() {
                continue;
            }
            let (Some(open), semi) = (rest.find('{'), rest.find(';')) else {
                continue;
            };
            if semi.is_some_and(|s| s < open) {
                continue; // a declaration
            }
            let start = at + 3 + open;
            let len = matching_brace(&code[start..]);
            out.push((name, start, start + len));
        }
        out
    }

    /// The deny sites of function `name` of `file` (whose code is `text`):
    /// each `-EPERM` / `-EACCES` returned or stored, and each use of a refusal
    /// constant the file defines negative (`const EPERM: i32 = -1;`, returned
    /// bare — the connect deny's spelling); each kill or stop the kernel sends
    /// (`bpf_send_signal`); the sysctl program's refusal verdict; and each
    /// refusal `cgroup_files`' refusers sign (their `true` makes
    /// `refuse_write`'s caller return `-EPERM`).
    fn deny_sites(file: &str, text: &str, name: &str, body: &str) -> usize {
        let mut n = body.matches("-EPERM").count()
            + body.matches("-EACCES").count()
            + body.matches("bpf_send_signal(").count();
        for c in negative_consts(text) {
            n += words(body, &c);
        }
        if file == "sysctl_guard.rs" {
            n += body.matches("SysctlVerdict::Refuse =>").count();
        }
        if file == "cgroup_files.rs" && name.starts_with("refuse_") && name != "refuse_write" {
            n += body.matches("sign(phase,").count()
                + body.matches("emit_task_denial(").count()
                // lot 367: the memory views' open, signed as a read-mode refusal
                + body.matches("emit_task_read_denial(").count();
        }
        n
    }

    /// The constants `text` defines with a negative value (`const NAME: T =
    /// -N;`).
    fn negative_consts(text: &str) -> Vec<String> {
        text.lines()
            .filter_map(|l| {
                let l = l.trim();
                let rest = l
                    .strip_prefix("const ")
                    .or_else(|| l.strip_prefix("pub const "))?;
                let (name, value) = rest.split_once(':')?;
                value
                    .split_once('=')
                    .filter(|(_, v)| v.trim_start().starts_with('-'))
                    .map(|_| name.trim().to_string())
            })
            .collect()
    }

    /// The uses of the word `w` in `hay` (not part of a longer name).
    fn words(hay: &str, w: &str) -> usize {
        let b = hay.as_bytes();
        let ident = |c: u8| c.is_ascii_alphanumeric() || c == b'_';
        hay.match_indices(w)
            .filter(|(at, _)| {
                (*at == 0 || !ident(b[at - 1])) && b.get(at + w.len()).is_none_or(|c| !ident(*c))
            })
            .count()
    }

    /// Every function of the object with a body, by name (two files may each
    /// define one of a name: both bodies are kept).
    fn all_functions(code: &BTreeMap<String, String>) -> BTreeMap<String, Vec<(String, String)>> {
        let mut out: BTreeMap<String, Vec<(String, String)>> = BTreeMap::new();
        for (file, text) in code {
            // lot 345: a macro's body too, by the macro's name; and (its
            // mini-hunt) a `use … as` alias and a function-pointer static or
            // constant, each by its name, its "body" the path or expression it
            // stands for — followed from there
            for (name, body) in functions(text)
                .into_iter()
                .chain(macros(text))
                .map(|(n, b)| (n, b.to_string()))
                .chain(aliases(text))
            {
                out.entry(name).or_default().push((file.clone(), body));
            }
        }
        out
    }

    /// Lot 345 (the mini-hunt of N1): the other names a function goes by in
    /// `code` — each `use path::name as alias` (`alias`, its body `path::name`),
    /// braces too, and each `static`/`const` of a function-pointer type (its
    /// name, its body the initializer). The review of #553 (F3): whatever
    /// visibility (`pub(super)`, `pub(in …)`), behind any attributes
    /// (`#[allow(…)] use …`), and a `static`/`const` whose initializer is a
    /// bare path whatever its type (a `type` alias of `fn() -> bool`).
    fn aliases(code: &str) -> Vec<(String, String)> {
        let mut out = Vec::new();
        // each statement that starts a line, to its `;`
        let starts = code.match_indices('\n').map(|(i, _)| i + 1).chain([0]);
        let stmts = starts.filter_map(|at| {
            let rest = &code[at..];
            let end = rest.find(';')?;
            Some(&rest[..end])
        });
        for stmt in stmts {
            let st = item_head(stmt);
            if let Some(rest) = st.strip_prefix("use ") {
                let (prefix, items) = match rest.split_once('{') {
                    Some((p, i)) => (p.trim_end_matches("::").trim(), i.trim_end_matches('}')),
                    None => ("", rest),
                };
                for item in items.split(',') {
                    if let Some((path, alias)) = item.split_once(" as ") {
                        let path = path.trim();
                        let full = if prefix.is_empty() {
                            path.to_string()
                        } else {
                            format!("{prefix}::{path}")
                        };
                        out.push((alias.trim().to_string(), format!("{full};")));
                    }
                }
            } else if let Some(rest) = st
                .strip_prefix("static ")
                .or_else(|| st.strip_prefix("const "))
            {
                let Some((head, init)) = rest.split_once('=') else {
                    continue;
                };
                let Some((name, ty)) = head.split_once(':') else {
                    continue;
                };
                let name = name.trim().strip_prefix("mut ").unwrap_or(name.trim());
                if ty.contains("fn(") || ty.contains("fn (") || bare_path(init) {
                    out.push((name.trim().to_string(), format!("{};", init.trim())));
                }
            }
        }
        out
    }

    /// The review of #553 (F3): an item's text past its attributes (`#[…]`,
    /// any number, nested brackets) and its visibility (`pub`, `pub(crate)`,
    /// `pub(super)`, `pub(in path)`).
    fn item_head(stmt: &str) -> &str {
        let mut st = stmt.trim();
        loop {
            if let Some(rest) = st.strip_prefix("#[") {
                let mut depth = 1usize;
                let mut end = None;
                for (i, ch) in rest.char_indices() {
                    match ch {
                        '[' => depth += 1,
                        ']' => {
                            depth -= 1;
                            if depth == 0 {
                                end = Some(i);
                                break;
                            }
                        }
                        _ => {}
                    }
                }
                match end {
                    Some(i) => st = rest[i + 1..].trim_start(),
                    None => return st,
                }
            } else if let Some(rest) = st.strip_prefix("pub(") {
                match rest.find(')') {
                    Some(i) => st = rest[i + 1..].trim_start(),
                    None => return st,
                }
            } else if let Some(rest) = st.strip_prefix("pub ") {
                st = rest.trim_start();
            } else {
                return st;
            }
        }
    }

    /// The review of #553 (F3): whether `init` (a `static`'s or `const`'s
    /// initializer) is a bare path — `crate::execq::is_relaxed_ptr`,
    /// `is_relaxed_ptr`, behind `&` or before `as …` — what names a function
    /// whatever the item's declared type.
    fn bare_path(init: &str) -> bool {
        let e = init.trim();
        let e = e.strip_prefix('&').unwrap_or(e).trim();
        let e = e.split(" as ").next().unwrap_or(e).trim();
        !e.is_empty()
            && e.split("::").all(|seg| {
                !seg.is_empty() && seg.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
            })
            && e.chars()
                .next()
                .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
    }

    /// The functions `body` calls: `(module, name)` — `module` the path
    /// segment before the name (`crate::execq::conf(` → `execq`), `None` for a
    /// bare call or a method. Lot 345 (the re-check of #550, N1): and the
    /// macros it invokes (`crate::execq::relaxed!(`), every path it names
    /// without calling it (`let f = crate::execq::relaxed; f()`: a function
    /// pointer), and every bare word that names a function of the object
    /// (`fns`) without calling it (`let f = relaxed;` after a `use`).
    fn calls(
        body: &str,
        fns: &BTreeMap<String, Vec<(String, String)>>,
    ) -> BTreeSet<(Option<String>, String)> {
        let b = body.as_bytes();
        let ident = |c: u8| c.is_ascii_alphanumeric() || c == b'_';
        let mut out = BTreeSet::new();
        let module_before = |s: usize| -> Option<String> {
            if s >= 2 && &body[s - 2..s] == "::" {
                let mut m = s - 2;
                while m > 0 && ident(b[m - 1]) {
                    m -= 1;
                }
                Some(body[m..s - 2].to_string())
            } else {
                None
            }
        };
        // every identifier not followed by `(`: a path's last segment, or a
        // bare word naming a function of the object
        let mut i = 0;
        while i < b.len() {
            if !ident(b[i]) || (i > 0 && ident(b[i - 1])) || b[i].is_ascii_digit() {
                i += 1;
                continue;
            }
            let s = i;
            while i < b.len() && ident(b[i]) {
                i += 1;
            }
            let word = &body[s..i];
            let next = body[i..].trim_start();
            if next.starts_with('(') || next.starts_with("::") {
                continue; // a call (below) or a path's inner segment
            }
            let module = module_before(s);
            let is_field = s > 0 && b[s - 1] == b'.';
            if (module.is_some() || !is_field) && fns.contains_key(word) {
                out.insert((module, word.to_string()));
            }
        }
        // (a macro invocation, `name!(`, is a word not followed by `(`: above)
        for (at, _) in body.match_indices('(') {
            let mut s = at;
            while s > 0 && ident(b[s - 1]) {
                s -= 1;
            }
            if s == at || b[s].is_ascii_digit() {
                continue;
            }
            out.insert((module_before(s), body[s..at].to_string()));
        }
        out
    }

    /// The bodies a call of `(module, name)` from `file` may run: the named
    /// module's function; a bare call's or a method's in `file` when it
    /// defines one, else every file's of that name (an over-approximation).
    fn callees<'a>(
        fns: &'a BTreeMap<String, Vec<(String, String)>>,
        file: &str,
        module: &Option<String>,
        name: &str,
    ) -> Vec<&'a (String, String)> {
        let all: Vec<&(String, String)> = fns.get(name).into_iter().flatten().collect();
        let pick = |f: &str| -> Vec<&'a (String, String)> {
            all.iter()
                .copied()
                .filter(|(in_file, _)| in_file == f)
                .collect()
        };
        let own = match module.as_deref() {
            Some(m) if !matches!(m, "crate" | "self" | "super") => pick(&format!("{m}.rs")),
            _ => pick(file),
        };
        if own.is_empty() { all } else { own }
    }

    /// The gate's switches a self-protection site reaches: for each `Enforced`
    /// row, its function and every function of the object it calls, to any
    /// depth, and each switch named in one of them — `(site, the function that
    /// names it, the switch)`. Also each switch named in a file other than its
    /// own (an alias, a re-export: the name is the only handle the code reads
    /// it by).
    fn gate_reads_of(code: &BTreeMap<String, String>) -> Vec<String> {
        let fns = all_functions(code);
        let mut found = Vec::new();
        for (file, text) in code {
            for (switch, owner) in GATE_SWITCHES {
                if file != owner && words(text, switch) > 0 {
                    found.push(format!("{file} names {switch} (only {owner:?} may)"));
                }
            }
            // Lot 345 (the re-check of #550, N1): no macro names a switch — a
            // macro of the switch's own file expands wherever it is invoked
            for (name, body) in macros(text) {
                for (switch, _) in GATE_SWITCHES {
                    if words(body, switch) > 0 {
                        found.push(format!("{file} macro {name}! names {switch}"));
                    }
                }
            }
            // … and in its own file a switch is named only in its declaration
            // and inside a function's body: a re-export (`use self::SWITCH as
            // X`), a constant or a static of it is another name to read it by
            for (switch, owner) in GATE_SWITCHES {
                if file != owner {
                    continue;
                }
                let bodies = function_spans(text);
                let tb = text.as_bytes();
                for (at, _) in text.match_indices(switch) {
                    let end = at + switch.len();
                    let ident = |c: &u8| c.is_ascii_alphanumeric() || *c == b'_';
                    if (at > 0 && ident(&tb[at - 1])) || tb.get(end).is_some_and(ident) {
                        continue;
                    }
                    if bodies.iter().any(|(_, s, e)| (*s..*e).contains(&at)) {
                        continue;
                    }
                    let line_start = text[..at].rfind('\n').map_or(0, |n| n + 1);
                    let before = text[line_start..at].trim();
                    let declaration = before.ends_with("static")
                        && (before == "static" || before.starts_with("pub"));
                    if !declaration {
                        let line_end = text[at..].find('\n').map_or(text.len(), |n| at + n);
                        found.push(format!(
                            "{file} names {switch} outside a function and its declaration: {}",
                            text[line_start..line_end].trim()
                        ));
                    }
                }
            }
        }
        for (file, name, _, route) in SITES {
            if !matches!(route, Enforced(_)) {
                continue;
            }
            let mut seen: BTreeSet<(String, String)> = BTreeSet::new();
            let mut todo: Vec<(&str, String)> = callees(&fns, file, &None, name)
                .into_iter()
                .map(|(f, body)| (body.as_str(), format!("{f} {name}")))
                .collect();
            while let Some((body, at)) = todo.pop() {
                if !seen.insert((at.clone(), body.to_string())) {
                    continue;
                }
                for (switch, _) in GATE_SWITCHES {
                    if words(body, switch) > 0 {
                        found.push(format!("{file} {name} reaches {switch} through {at}"));
                    }
                }
                let in_file = at.split(' ').next().unwrap_or_default().to_string();
                for (module, callee) in calls(body, &fns) {
                    for (f, next) in callees(&fns, &in_file, &module, &callee) {
                        todo.push((next.as_str(), format!("{f} {callee}")));
                    }
                }
            }
        }
        found.sort();
        found.dedup();
        found
    }
}

/// Lot 2.2 (the re-check of #550, N1, its userland point): the resolved
/// gate reaches a closed list of functions of `agent/src/boot` — each that
/// takes a `detect_only` parameter, each a call hands `detect_only` or
/// `gate.on` to, each struct field initialised from them, and each other
/// name a `let` binds them to. A new receiver (a new switch written from
/// the gate, a response path that reads it) fails here until it is named
/// and its consumer checked (`xtask/tests/alpha_profile.rs`).
#[test]
fn the_gate_reaches_a_closed_list_of_boot_functions() {
    use syn::visit::Visit;
    struct V {
        file: String,
        found: BTreeSet<String>,
    }
    fn is_gate(e: &Expr) -> bool {
        match ast::peel(e) {
            Expr::Path(p) => p.path.is_ident("detect_only"),
            Expr::Field(f) => {
                matches!(&f.member, syn::Member::Named(m) if m == "on")
                    && matches!(ast::peel(&f.base), Expr::Path(p) if p.path.is_ident("gate"))
            }
            _ => false,
        }
    }
    impl<'ast> Visit<'ast> for V {
        fn visit_signature(&mut self, s: &'ast syn::Signature) {
            for input in &s.inputs {
                if let syn::FnArg::Typed(t) = input {
                    let mut names = Vec::new();
                    ast::pat_idents(&t.pat, &mut names);
                    if names.iter().any(|n| n == "detect_only") {
                        self.found.insert(format!("{}: fn {}", self.file, s.ident));
                    }
                }
            }
            visit::visit_signature(self, s);
        }
        fn visit_expr_call(&mut self, c: &'ast syn::ExprCall) {
            if c.args.iter().any(is_gate) {
                let callee = match ast::peel(&c.func) {
                    Expr::Path(p) => ast::last(&p.path),
                    other => ast::compact(other),
                };
                self.found.insert(format!("{}: call {callee}", self.file));
            }
            visit::visit_expr_call(self, c);
        }
        fn visit_expr_method_call(&mut self, c: &'ast syn::ExprMethodCall) {
            if c.args.iter().any(is_gate) {
                self.found
                    .insert(format!("{}: call .{}", self.file, c.method));
            }
            visit::visit_expr_method_call(self, c);
        }
        fn visit_field_value(&mut self, f: &'ast syn::FieldValue) {
            if is_gate(&f.expr) {
                if let syn::Member::Named(m) = &f.member {
                    self.found.insert(format!("{}: field {m}", self.file));
                }
            }
            visit::visit_field_value(self, f);
        }
        fn visit_local(&mut self, l: &'ast syn::Local) {
            if let Some(init) = &l.init {
                if is_gate(&init.expr) {
                    let mut names = Vec::new();
                    ast::pat_idents(&l.pat, &mut names);
                    for n in names {
                        self.found.insert(format!("{}: let {n}", self.file));
                    }
                }
            }
            visit::visit_local(self, l);
        }
    }
    let root = repo_root();
    let sources = ast::tree_sources(&root, "agent/src/boot");
    let mut found = BTreeSet::new();
    for (rel, text) in &sources {
        let file = ast::production(rel, text);
        let mut v = V {
            file: rel.trim_start_matches("agent/src/boot/").to_string(),
            found: BTreeSet::new(),
        };
        v.visit_file(&file);
        found.extend(v.found);
    }
    let want: BTreeSet<String> = GATE_RECEIVERS.iter().map(|s| (*s).to_string()).collect();
    assert_eq!(
        found, want,
        "the functions of agent/src/boot the gate reaches changed: name the new one in \
         GATE_RECEIVERS and check its consumer in xtask/tests/alpha_profile.rs"
    );
}

/// Lot 2.2: [`the_gate_reaches_a_closed_list_of_boot_functions`]'s list, as
/// the boot reads today.
const GATE_RECEIVERS: &[&str] = &[
    "attach.rs: call .execq_config",
    "attach.rs: call execpol_mode",
    "attach.rs: field detect_only",
    "attach.rs: fn execpol_mode",
    "attach.rs: fn load",
    "attach.rs: fn self_test",
    "cli.rs: fn execq_config",
    "integrity.rs: call __macro__warn",
    "integrity.rs: call capabilities",
    "integrity.rs: call demo_rules_gate",
    "integrity.rs: field detect_only",
    "integrity.rs: field dry_run",
    "integrity.rs: let detect_only",
    "mod.rs: call arm",
    "mod.rs: call build",
    "mod.rs: call ladder",
    "mod.rs: call load",
    "mod.rs: call self_test",
    "policy.rs: call arming",
    "policy.rs: fn load",
    "posture.rs: call boot",
    "posture.rs: call new",
    "posture.rs: fn ladder",
    "ready.rs: field detect_only",
    "ready.rs: fn arm",
    "response.rs: call __macro__info",
    "response.rs: call effective_response",
    "response.rs: fn build",
];
