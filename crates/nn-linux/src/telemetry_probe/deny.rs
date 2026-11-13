//! Lot 302: the deny self-test — every deny hook proves it denies, every
//! round (the sensor self-test's round, lot 280c).
//!
//! The round's child (`northnarrow-agent --telemetry-probe <nonce>`, not a
//! protected process) makes ONE harmless attempt per deny hook against
//! targets of the self-test's own, never the agent:
//!
//! - a **target process**: a child of the agent's binary started for the
//!   round (`--move-guard-self-test-target`, the boot's move-guard target,
//!   lot 273b: it waits to be killed), registered in `PROTECTED_PIDS` as a
//!   worker (protected, never exempt), killed and evicted at the round's
//!   end. Its signal (`SIGURG`, ignored by default), its I/O signal through
//!   a pipe's owner, its `/proc/<pid>/mem` opened read-only (a ptrace
//!   attach-mode access, which the hook records — a read-mode one it
//!   refuses silently, `ps` makes them all day; the unit's seccomp filter
//!   refuses the `ptrace` syscall itself), its
//!   core limit set to 0, its scheduling policy set to the one it has, its
//!   nice value to 19, its I/O priority to best-effort 7, and (where the
//!   move guard is attached) its move into a throwaway cgroup;
//! - a **target directory**, [`TARGET_DIR`] (in the unit's runtime
//!   directory, a tmpfs), registered `MUTATE | NOCREATE`, and its files,
//!   registered `MUTATE | WRITE`: a create, a directory, a FIFO, a symlink
//!   and a hard link made in it, a file unlinked, a directory removed, a
//!   file renamed; a file's mode set to the one it has, its inode flags to
//!   the ones it has, a `user.` attribute set and one removed, (6.2+) a
//!   POSIX ACL equal to its mode set and one removed, a write-open, and a
//!   write of 0 bytes through a descriptor the agent opened before and
//!   handed to the child ([`WRITE_FD`]);
//! - the **BPF guard**: a load of a two-instruction kprobe program (a type
//!   refused outside the family in every mode: the `bpf` hook), and, where
//!   the guard enforces, a read-only handle on one of the agent's maps and
//!   one on one of its programs through relative paths (the `bpf_map` and
//!   `bpf_prog` hooks: the `bpf` hook judges the absolute ones first).
//!
//! Each attempt must be refused (`EPERM`; `EACCES` for the memory, which
//! the kernel returns for a refused ptrace access) **and** its refusal
//! must reach the agent as the self-test's ([`Expected`]: the child's pid
//! within its lifetime, the hook's operation and target). The signal
//! through a file's owner is refused silently (the kernel drops it): its
//! record is the proof. A hook whose attempt went through, or whose
//! refusal did not arrive, is **missed**: a signed degradation
//! ([`DEGRADATION_SOURCE`], the hook named), missed two rounds in a row an
//! **alert** ([`AUDIT_OP_ALERT`]), refused again the degradation withdrawn
//! and the return signed ([`AUDIT_OP_RESTORED`]). Nothing is attempted in
//! a trusted-installer window (nothing is refused in one, by design).
//!
//! The kernel records the child's refusals outside the denials' budgets and
//! dedup (`SELFTEST_TGID`, [`SelfTestMark`]): the self-test never takes the
//! room of a real attempt's record (lot 293), and a flood that spends the
//! budgets never hides the self-test. Its events are taken by the probe's
//! tap like the sensor self-test's: never the rules, the posture or the
//! export.
//!
//! Hooks with no safe attempt are **attach checks** ([`Check::AttachOnly`],
//! each with its reason, `docs/operator/SENSOR_CONTRACT.md` §5b): their
//! programs must still be linked.

use std::collections::HashSet;
use std::ffi::CString;
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use aya::maps::{Array, MapData};
use aya::Ebpf;
use nn_model::{Event, FsProtectOperation as Op};
use parking_lot::Mutex;
use tracing::{error, info, warn};

use crate::audit::AuditLog;
use nn_core::contract::manifest::ProbeState;

/// The signed degradation of a hook whose round missed.
pub const DEGRADATION_SOURCE: &str = "deny_selftest";
/// Two rounds in a row.
pub const AUDIT_OP_ALERT: &str = "deny_selftest_alert";
/// A missed hook refuses again.
pub const AUDIT_OP_RESTORED: &str = "deny_selftest_restored";
/// The self-test's directory (the unit's runtime directory: a tmpfs, not
/// `chattr +i`, where the kernel would refuse before any hook).
pub const TARGET_DIR: &str = "/run/northnarrow/selftest";
/// The target process's flag (the boot's move-guard target, lot 273b).
pub const TARGET_FLAG: &str = "--move-guard-self-test-target";
/// The descriptor of [`file::WRITE_FD`] the child inherits.
pub const WRITE_FD: i32 = 3;
/// The throwaway cgroup the move is tried into, at the hierarchy's root.
pub const MOVE_CGROUP: &str = "northnarrow-deny-selftest";
/// The signal of the task and owner steps (ignored by default).
pub const SIGNAL: i32 = libc::SIGURG;
/// `BPF_PROG_TYPE_KPROBE`.
pub const PROG_TYPE_KPROBE: u32 = 2;
/// The resource of the limit step (`RLIMIT_CORE`, set to 0).
pub const RLIMIT: u64 = libc::RLIMIT_CORE as u64;
/// The nice value of the nice step (always allowed: a lower priority).
pub const NICE: i32 = 19;
/// The I/O priority of the ioprio step: best effort, level 7 (the lowest
/// of the class; no capability needed).
pub const IOPRIO: i32 = (2 << 13) | 7;
/// The map whose pin the `bpf_map` step opens read-only by a relative
/// path (pinned at every start, `bpf_defense::claim_agent_role`).
pub const MAP_PIN: &str = "ROLE_TGIDS";
/// The program whose pin the `bpf_prog` step opens by a relative path (a
/// deny hook of every kernel).
pub const PROG_PIN: &str = "prog_task_kill";
/// The `user.` attribute of the xattr steps.
pub const XATTR_NAME: &str = "user.nn-selftest";
/// The POSIX ACL attribute of the ACL steps (6.2+).
pub const ACL_NAME: &str = "system.posix_acl_access";

/// The entries of [`TARGET_DIR`].
pub mod file {
    /// Its mode (setattr) and inode flags (ioctl) set to theirs; the source
    /// of the hard link.
    pub const ATTR: &str = "attr";
    pub const SETXATTR: &str = "xattr-set";
    pub const REMOVEXATTR: &str = "xattr-remove";
    pub const SET_ACL: &str = "acl-set";
    pub const REMOVE_ACL: &str = "acl-remove";
    pub const WRITE_OPEN: &str = "write-open";
    /// Opened for writing by the agent, handed to the child as fd 3.
    pub const WRITE_FD: &str = "write-fd";
    /// Not registered: the directory's protection refuses their removal.
    pub const UNLINK: &str = "unlink";
    pub const RENAME: &str = "rename";
    /// An empty directory.
    pub const RMDIR: &str = "rmdir";
    /// The registered files (`MUTATE | WRITE`).
    pub const PROTECTED: [&str; 7] = [
        ATTR,
        SETXATTR,
        REMOVEXATTR,
        SET_ACL,
        REMOVE_ACL,
        WRITE_OPEN,
        WRITE_FD,
    ];
}

/// What a refusal's record names as its target.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Expect {
    /// The target process (`target_ino` its tgid).
    TargetPid,
    /// [`TARGET_DIR`] (`target_dev`, `target_ino`).
    Dir,
    /// One of its files.
    File(&'static str),
    /// A BPF object of `kind` (`target_dev`: 0 a program type, 1 a map, 2
    /// a program), and its id when known.
    Object { kind: u64, id: Option<u64> },
}

/// When an attempt can be made.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Needs {
    /// On every kernel the agent supports.
    Always,
    /// Where its program is loaded (an optional hook the kernel has).
    Loaded,
    /// Where the BPF guard enforces (its handle refusals; a debug build or
    /// `NN_BPF_DEFENSE_OBSERVE=1` observes).
    Enforce,
}

/// How a hook proves itself each round.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Check {
    /// One attempt: refused with `errno` (0: refused silently, the record
    /// alone), its record `op` with `detail` (`target_dev`) when fixed, on
    /// `expect`.
    Attempt {
        op: Op,
        detail: Option<u64>,
        expect: Expect,
        errno: i32,
        needs: Needs,
    },
    /// No safe attempt (the reason): its programs must be linked.
    AttachOnly { why: &'static str },
}

/// One deny hook of the self-test.
#[derive(Clone, Copy, Debug)]
pub struct HookTest {
    /// The hook (`anti_tamper::DENY_HOOKS` / `OPTIONAL_DENY_HOOKS`, the BPF
    /// guard's `bpf` and `bpf_prog`, the sysctl judge, the module judge).
    pub hook: &'static str,
    /// Its programs (the agent's program-id list names them).
    pub programs: &'static [&'static str],
    /// What the round does (the signed degradation names it).
    pub step: &'static str,
    pub check: Check,
}

const fn attempt(op: Op, detail: Option<u64>, expect: Expect, errno: i32, needs: Needs) -> Check {
    Check::Attempt {
        op,
        detail,
        expect,
        errno,
        needs,
    }
}

const EPERM: i32 = libc::EPERM;
const MAP: Expect = Expect::Object { kind: 1, id: None };
const PROG: Expect = Expect::Object { kind: 2, id: None };
const KPROBE: Expect = Expect::Object {
    kind: 0,
    id: Some(PROG_TYPE_KPROBE as u64),
};
const SIG: Option<u64> = Some(SIGNAL as u64);

/// Why the module judge's two hooks are attach checks.
const MODULE_WHY: &str = "a module or a kexec image read: the self-test never loads one, and \
                          finit_module, init_module and kexec_file_load are refused by the \
                          unit's seccomp filter (nor has it CAP_SYS_MODULE or CAP_SYS_BOOT)";

/// Every deny hook, in slot order: the attempts, then the attach checks.
pub const HOOKS: [HookTest; 32] = [
    HookTest {
        hook: crate::anti_tamper::TASK_KILL_HOOK,
        programs: &["task_kill"],
        step: "kill(SIGURG) of the self-test's target process",
        check: attempt(Op::Signal, SIG, Expect::TargetPid, EPERM, Needs::Always),
    },
    HookTest {
        hook: crate::anti_tamper::PTRACE_HOOK,
        programs: &["ptrace_access_check"],
        step: "a read-only open of the target's /proc/<pid>/mem (a ptrace attach access)",
        check: attempt(
            Op::Ptrace,
            None,
            Expect::TargetPid,
            libc::EACCES,
            Needs::Always,
        ),
    },
    HookTest {
        hook: "inode_unlink",
        programs: &["inode_unlink"],
        step: "an unlink in the self-test directory",
        check: attempt(Op::Unlink, None, Expect::Dir, EPERM, Needs::Always),
    },
    HookTest {
        hook: "inode_rmdir",
        programs: &["inode_rmdir"],
        step: "an rmdir of an empty directory in it",
        check: attempt(Op::Rmdir, None, Expect::Dir, EPERM, Needs::Always),
    },
    HookTest {
        hook: "inode_rename",
        programs: &["inode_rename"],
        step: "a rename in it",
        check: attempt(Op::Rename, None, Expect::Dir, EPERM, Needs::Always),
    },
    HookTest {
        hook: "inode_setattr",
        programs: &["inode_setattr"],
        step: "a chmod of a protected file to its own mode",
        check: attempt(
            Op::Setattr,
            None,
            Expect::File(file::ATTR),
            EPERM,
            Needs::Always,
        ),
    },
    HookTest {
        hook: "file_ioctl",
        programs: &["file_ioctl"],
        step: "FS_IOC_SETFLAGS of a protected file with its own flags",
        check: attempt(
            Op::Ioctl,
            None,
            Expect::File(file::ATTR),
            EPERM,
            Needs::Always,
        ),
    },
    HookTest {
        hook: "file_open",
        programs: &["protected_open_deny"],
        step: "a write-open of a protected file",
        check: attempt(
            Op::Write,
            None,
            Expect::File(file::WRITE_OPEN),
            EPERM,
            Needs::Always,
        ),
    },
    HookTest {
        hook: "inode_create",
        programs: &["protected_create_deny"],
        step: "a file created in the self-test directory",
        check: attempt(Op::Create, None, Expect::Dir, EPERM, Needs::Always),
    },
    HookTest {
        hook: "inode_mkdir",
        programs: &["protected_mkdir_deny"],
        step: "a directory made in it",
        check: attempt(Op::Mkdir, None, Expect::Dir, EPERM, Needs::Always),
    },
    HookTest {
        hook: "inode_mknod",
        programs: &["protected_mknod_deny"],
        step: "a FIFO made in it",
        check: attempt(Op::Mknod, None, Expect::Dir, EPERM, Needs::Always),
    },
    HookTest {
        hook: "inode_symlink",
        programs: &["protected_symlink_deny"],
        step: "a symlink made in it",
        check: attempt(Op::Symlink, None, Expect::Dir, EPERM, Needs::Always),
    },
    HookTest {
        hook: "inode_link",
        programs: &["protected_link_deny"],
        step: "a hard link made in it",
        check: attempt(Op::Link, None, Expect::Dir, EPERM, Needs::Always),
    },
    HookTest {
        hook: "inode_setxattr",
        programs: &["protected_setxattr_deny"],
        step: "a user. attribute set on a protected file",
        check: attempt(
            Op::Xattr,
            None,
            Expect::File(file::SETXATTR),
            EPERM,
            Needs::Always,
        ),
    },
    HookTest {
        hook: "inode_removexattr",
        programs: &["protected_removexattr_deny"],
        step: "a user. attribute removed from a protected file",
        check: attempt(
            Op::Xattr,
            None,
            Expect::File(file::REMOVEXATTR),
            EPERM,
            Needs::Always,
        ),
    },
    HookTest {
        hook: crate::anti_tamper::bpf_defense::GUARD_HOOK,
        programs: &["bpf_map_guard"],
        step: "a read-only handle on one of the agent's maps by a relative path",
        check: attempt(Op::BpfHandle, None, MAP, EPERM, Needs::Enforce),
    },
    HookTest {
        hook: "file_permission",
        programs: &["protected_write_deny"],
        step: "a write of 0 bytes through a descriptor of a protected file opened before",
        check: attempt(
            Op::Write,
            None,
            Expect::File(file::WRITE_FD),
            EPERM,
            Needs::Always,
        ),
    },
    HookTest {
        hook: "task_setrlimit",
        programs: &["task_setrlimit_deny"],
        step: "prlimit of the target's core limit to 0",
        check: attempt(
            Op::Rlimit,
            Some(RLIMIT),
            Expect::TargetPid,
            EPERM,
            Needs::Always,
        ),
    },
    HookTest {
        hook: "task_setscheduler",
        programs: &["task_setscheduler_deny"],
        step: "sched_setscheduler of the target to its own policy",
        check: attempt(Op::Sched, Some(0), Expect::TargetPid, EPERM, Needs::Always),
    },
    HookTest {
        hook: "task_setnice",
        programs: &["task_setnice_deny"],
        step: "setpriority of the target to nice 19",
        check: attempt(
            Op::Nice,
            Some(NICE as u64),
            Expect::TargetPid,
            EPERM,
            Needs::Always,
        ),
    },
    HookTest {
        hook: "task_setioprio",
        programs: &["task_setioprio_deny"],
        step: "ioprio_set of the target to best effort 7",
        check: attempt(
            Op::Ioprio,
            Some(IOPRIO as u64),
            Expect::TargetPid,
            EPERM,
            Needs::Always,
        ),
    },
    HookTest {
        hook: "file_send_sigiotask",
        programs: &["file_send_sigiotask_deny"],
        step: "SIGURG through a pipe whose owner is the target (dropped silently: the record \
               is the proof)",
        check: attempt(Op::Sigio, SIG, Expect::TargetPid, 0, Needs::Always),
    },
    HookTest {
        hook: "inode_set_acl",
        programs: &["protected_set_acl_deny"],
        step: "a POSIX ACL equal to its mode set on a protected file (6.2+)",
        check: attempt(
            Op::Xattr,
            None,
            Expect::File(file::SET_ACL),
            EPERM,
            Needs::Loaded,
        ),
    },
    HookTest {
        hook: "inode_remove_acl",
        programs: &["protected_remove_acl_deny"],
        step: "a POSIX ACL removed from a protected file (6.2+)",
        check: attempt(
            Op::Xattr,
            None,
            Expect::File(file::REMOVE_ACL),
            EPERM,
            Needs::Loaded,
        ),
    },
    HookTest {
        hook: crate::anti_tamper::cgroup_guard::MOVE_DENY_HOOK,
        programs: &["cgroup_move_deny"],
        step: "a move of the target into a throwaway cgroup (the move guard)",
        check: attempt(
            Op::CgroupMove,
            Some(0),
            Expect::TargetPid,
            EPERM,
            Needs::Loaded,
        ),
    },
    HookTest {
        hook: OBSERVE_HOOK,
        programs: &["bpf_syscall_observe"],
        step: "a load of a two-instruction kprobe program",
        check: attempt(Op::BpfProgType, None, KPROBE, EPERM, Needs::Always),
    },
    HookTest {
        hook: PROG_GUARD_HOOK,
        programs: &["bpf_prog_guard"],
        step: "a handle on one of the agent's programs by a relative path",
        check: attempt(Op::BpfHandle, None, PROG, EPERM, Needs::Enforce),
    },
    HookTest {
        hook: "file_ioctl_compat",
        programs: &["protected_ioctl_compat_deny"],
        step: "its program linked (attach check)",
        check: Check::AttachOnly {
            why: "only a 32-bit process's ioctl reaches it, and the agent is a 64-bit binary",
        },
    },
    HookTest {
        hook: crate::anti_tamper::cgroup_guard::MOVE_STASH_HOOK,
        programs: &["cgroup_move_stash"],
        step: "its program linked (attach check)",
        check: Check::AttachOnly {
            why: "the move guard's lookup half: it refuses nothing itself, the move's refusal \
                  (inode_permission) reads what it stashed",
        },
    },
    HookTest {
        hook: crate::anti_tamper::cgroup_guard::MOVE_CLEAR_HOOK,
        programs: &["cgroup_move_clear"],
        step: "its program linked (attach check)",
        check: Check::AttachOnly {
            why: "the move guard's third program drops a stash at the write's end and refuses \
                  nothing",
        },
    },
    HookTest {
        hook: SYSCTL_JUDGE,
        programs: &["nn_sysctl_guard"],
        step: "its program linked (attach check)",
        check: Check::AttachOnly {
            why: "every write it would refuse is refused before it by the write deny \
                  (file_permission runs in rw_verify_area, before proc_sys_call_handler): \
                  reaching it alone takes a race on the writer's buffer, the race it closes",
        },
    },
    HookTest {
        hook: "kernel_read_file",
        programs: &["module_read_file_observe"],
        step: "its program linked (attach check)",
        check: Check::AttachOnly { why: MODULE_WHY },
    },
];

// The module judge's second hook is not a slot of its own above (its
// program is checked with `module_load`'s sensor); it is listed here for
// the contract's table.
/// The hooks declared without a slot: `(hook, program, why)`.
pub const DECLARED: [(&str, &str, &str); 1] =
    [("kernel_load_data", "module_load_data_observe", MODULE_WHY)];

const OBSERVE_HOOK: &str = crate::anti_tamper::bpf_defense::OBSERVE_HOOK;
const PROG_GUARD_HOOK: &str = crate::anti_tamper::bpf_defense::PROG_GUARD_HOOK;
/// The sysctl judge's attach point (`cgroup/sysctl` on the root cgroup).
pub const SYSCTL_JUDGE: &str = "sysctl_judge";

/// How many hooks a round has a word on.
pub const HOOK_COUNT: usize = HOOKS.len();

/// The slot of `hook`.
pub fn slot_of(hook: &str) -> Option<usize> {
    HOOKS.iter().position(|h| h.hook == hook)
}

/// The `(dev, ino)` of the self-test's targets, as the kernel's records
/// carry them.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TargetKeys {
    pub dir: (u64, u64),
    pub files: Vec<(&'static str, (u64, u64))>,
}

impl TargetKeys {
    fn file(&self, name: &str) -> Option<(u64, u64)> {
        self.files.iter().find(|(n, _)| *n == name).map(|(_, k)| *k)
    }
}

/// A refusal the round expects: the hook's slot, the record's operation,
/// its `target_dev` and `target_ino` (`None`: any).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Expected {
    pub slot: usize,
    pub op: Op,
    pub dev: Option<u64>,
    pub ino: Option<u64>,
}

/// What the round's tap matches the child's refusals against, and the
/// child's other events of the deny steps it takes.
#[derive(Clone, Debug, Default)]
pub struct DenyExpect {
    pub records: Vec<Expected>,
    /// The target process (its exec, and the paths of its `/proc`).
    pub target: u32,
    /// Path prefixes of the files the steps open (the open sensor's rows).
    pub paths: Vec<String>,
}

impl DenyExpect {
    /// The expected refusals of the hooks in `attempted` (slots), on
    /// `keys` and the target `target`.
    pub fn new(attempted: &[usize], keys: &TargetKeys, target: u32, cgroup: Option<&Path>) -> Self {
        let mut records = Vec::new();
        for &slot in attempted {
            let Some(h) = HOOKS.get(slot) else { continue };
            let Check::Attempt {
                op, detail, expect, ..
            } = h.check
            else {
                continue;
            };
            let (dev, ino) = match expect {
                Expect::TargetPid => (detail, Some(u64::from(target))),
                Expect::Dir => (Some(keys.dir.0), Some(keys.dir.1)),
                Expect::File(n) => match keys.file(n) {
                    Some((d, i)) => (Some(d), Some(i)),
                    None => continue,
                },
                Expect::Object { kind, id } => (Some(kind), id),
            };
            records.push(Expected { slot, op, dev, ino });
        }
        let mut paths = vec![format!("{TARGET_DIR}/"), format!("/proc/{target}/")];
        if let Some(c) = cgroup {
            paths.push(format!("{}/", c.display()));
        }
        DenyExpect {
            records,
            target,
            paths,
        }
    }

    /// The expected refusal `event` is (`None`: not one), among those not
    /// matched yet (`matched`).
    pub fn matches(&self, event: &Event, matched: &[bool]) -> Option<usize> {
        let Event::FsProtectDenial {
            operation,
            target_dev,
            target_ino,
            ..
        } = event
        else {
            return None;
        };
        self.records.iter().position(|e| {
            !matched.get(e.slot).copied().unwrap_or(true)
                && e.op == *operation
                && e.dev.is_none_or(|d| d == *target_dev)
                && e.ino.is_none_or(|i| i == *target_ino)
        })
    }
}

// ---------------------------------------------------------------------------
// The kernel's mark of the child
// ---------------------------------------------------------------------------

/// The map that names the round's child to the kernel (per boot).
pub const MARK_MAP: &str = "SELFTEST_TGID";

/// The agent's handle on [`MARK_MAP`]: the child's tgid while its round
/// runs, 0 otherwise. Clones share it.
#[derive(Clone)]
pub struct SelfTestMark(Arc<Mutex<Array<MapData, u32>>>);

impl SelfTestMark {
    /// Write `tgid` (0: none); `false` when the kernel refused.
    pub fn set(&self, tgid: u32) -> bool {
        self.0.lock().set(0, tgid, 0).is_ok()
    }
}

/// Take [`MARK_MAP`] out of the object (the start, with the other maps it
/// takes); `None` when the object has none.
pub fn install_mark(ebpf: &mut Ebpf) -> Option<SelfTestMark> {
    let map = ebpf.take_map(MARK_MAP)?;
    match Array::<MapData, u32>::try_from(map) {
        Ok(a) => Some(SelfTestMark(Arc::new(Mutex::new(a)))),
        Err(e) => {
            warn!(error = %e, map = MARK_MAP, "deny self-test: the kernel's mark of the child cannot be written — its refusals go through the denials' budgets");
            None
        }
    }
}

/// The denials' per-CPU budgets (`agent-ebpf/src/inode_protect.rs`): the
/// attempt refusals' (lot 293) and the task refusals'.
pub const BUDGET_MAPS: [&str; 2] = ["ATTEMPT_DENIAL_RATE", "TASK_DENIAL_RATE"];
/// Their records a second, per CPU.
pub const BUDGET_PER_SEC: u64 = 50;

/// `debug-trigger` builds only (the lab's check that the self-test takes no
/// room of the denials' budgets, and that a flood that spent them hides
/// none of its refusals): the handles that spend both budgets on every CPU
/// for the next second ([`BudgetSpender::spend`]). `None` in a production
/// build: [`install_budget_spender`] takes nothing.
#[derive(Clone)]
pub struct BudgetSpender(Arc<Mutex<Vec<BudgetMap>>>);

/// One budget: `[window start (ns), records in the window]` per CPU.
type BudgetMap = aya::maps::PerCpuArray<MapData, [u64; 2]>;

impl BudgetSpender {
    /// Each budget's window restarted at `now_ns` (`CLOCK_MONOTONIC`, the
    /// programs' clock) with every one of its records spent, on every CPU.
    pub fn spend(&self, now_ns: u64) -> Result<(), String> {
        let cpus = aya::util::nr_cpus().map_err(|(w, e)| format!("{w}: {e}"))?;
        for m in self.0.lock().iter_mut() {
            let values = aya::maps::PerCpuValues::try_from(vec![[now_ns, BUDGET_PER_SEC]; cpus])
                .map_err(|e| e.to_string())?;
            m.set(0, values, 0).map_err(|e| e.to_string())?;
        }
        Ok(())
    }
}

/// Take the budgets' maps out of the object (`debug-trigger` builds; once
/// their ids were remembered for the BPF guard).
pub fn install_budget_spender(ebpf: &mut Ebpf) -> Option<BudgetSpender> {
    #[cfg(feature = "debug-trigger")]
    {
        let mut maps = Vec::new();
        for name in BUDGET_MAPS {
            let m = ebpf.take_map(name)?;
            maps.push(aya::maps::PerCpuArray::try_from(m).ok()?);
        }
        Some(BudgetSpender(Arc::new(Mutex::new(maps))))
    }
    #[cfg(not(feature = "debug-trigger"))]
    {
        let _ = ebpf;
        None
    }
}

// ---------------------------------------------------------------------------
// The targets (the agent's side)
// ---------------------------------------------------------------------------

/// The self-test's directory and files, made and registered as protected
/// (`dir`: [`TARGET_DIR`] outside the tests).
pub fn prepare_targets(dir: &Path, pin_root: Option<&Path>) -> Result<TargetKeys, String> {
    // the previous start's (its keys were pruned at this boot) or a round's
    // leftovers: made again
    if dir.exists() {
        std::fs::remove_dir_all(dir).map_err(|e| format!("removing {}: {e}", dir.display()))?;
    }
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(dir)
        .map_err(|e| format!("making {}: {e}", dir.display()))?;
    use std::os::unix::fs::DirBuilderExt;
    let write = |name: &str| -> Result<(), String> {
        let p = dir.join(name);
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&p)
            .and_then(|mut f| f.write_all(b"nn-selftest\n"))
            .map_err(|e| format!("making {}: {e}", p.display()))
    };
    for f in file::PROTECTED {
        write(f)?;
    }
    write(file::UNLINK)?;
    write(file::RENAME)?;
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(dir.join(file::RMDIR))
        .map_err(|e| format!("making {}/{}: {e}", dir.display(), file::RMDIR))?;
    let key = |p: &Path| -> Result<(u64, u64), String> {
        crate::fim::attach::key_for_path(p)
            .map(|k| (k.dev, k.ino))
            .map_err(|e| format!("{e:#}"))
    };
    let keys = TargetKeys {
        dir: key(dir)?,
        files: file::PROTECTED
            .iter()
            .map(|f| key(&dir.join(f)).map(|k| (*f, k)))
            .collect::<Result<_, _>>()?,
    };
    if let Some(root) = pin_root {
        let mut regs = vec![(
            keys.dir,
            crate::anti_tamper::filesystem::PROTECTED_DIR_FLAGS,
        )];
        regs.extend(keys.files.iter().map(|(_, k)| {
            (
                *k,
                common::wire::FS_PROTECT_MUTATE | common::wire::FS_PROTECT_WRITE,
            )
        }));
        crate::anti_tamper::filesystem::register_runtime_inodes(root, &regs)
            .map_err(|e| format!("registering the targets as protected: {e:#}"))?;
    }
    Ok(keys)
}

/// The keys of `old` targets out of the protected inodes (they are made
/// again: their files are gone).
pub fn release_targets(pin_root: &Path, old: &TargetKeys) -> Result<(), String> {
    let mut keys = vec![old.dir];
    keys.extend(old.files.iter().map(|(_, k)| *k));
    crate::anti_tamper::filesystem::release_runtime_inodes(pin_root, &keys)
        .map_err(|e| format!("{e:#}"))
}

/// Whether the targets are as [`prepare_targets`] left them: every entry
/// there with its inode, nothing else (an attempt let through changed
/// them: they are made again).
pub fn targets_intact(dir: &Path, keys: &TargetKeys) -> bool {
    let same = |p: &Path, k: (u64, u64)| {
        crate::fim::attach::key_for_path(p).is_ok_and(|x| (x.dev, x.ino) == k)
    };
    if !same(dir, keys.dir) {
        return false;
    }
    if !keys.files.iter().all(|(n, k)| same(&dir.join(n), *k)) {
        return false;
    }
    let mut want: HashSet<String> = file::PROTECTED.iter().map(|s| s.to_string()).collect();
    want.extend([file::UNLINK, file::RENAME, file::RMDIR].map(String::from));
    let Ok(rd) = std::fs::read_dir(dir) else {
        return false;
    };
    let names: HashSet<String> = rd
        .flatten()
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .collect();
    names == want && std::fs::read_dir(dir.join(file::RMDIR)).is_ok_and(|mut d| d.next().is_none())
}

/// The plan the parent hands the child after the go byte.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Plan {
    /// The target process (0: none — the task steps are skipped).
    pub target: u32,
    /// The self-test's directory.
    pub dir: PathBuf,
    /// The slots the child attempts.
    pub hooks: Vec<usize>,
    /// The protected file's descriptor was handed over ([`WRITE_FD`]).
    pub write_fd: bool,
    /// The throwaway cgroup's `cgroup.procs`.
    pub move_procs: Option<PathBuf>,
    /// The bpffs mount the relative paths start from, and the pin root's
    /// name in it.
    pub bpffs: Option<(PathBuf, String)>,
}

impl Plan {
    /// One `key=value` line each.
    pub fn render(&self) -> String {
        let mut s = format!("target={}\ndir={}\n", self.target, self.dir.display());
        let hooks: Vec<String> = self.hooks.iter().map(|h| h.to_string()).collect();
        s.push_str(&format!("hooks={}\n", hooks.join(",")));
        if self.write_fd {
            s.push_str("write_fd=1\n");
        }
        if let Some(p) = &self.move_procs {
            s.push_str(&format!("move={}\n", p.display()));
        }
        if let Some((m, r)) = &self.bpffs {
            s.push_str(&format!("bpffs={}\npin_root={r}\n", m.display()));
        }
        s
    }

    pub fn parse(text: &str) -> Self {
        let mut p = Plan::default();
        for line in text.lines() {
            let Some((k, v)) = line.split_once('=') else {
                continue;
            };
            match k.trim() {
                "target" => p.target = v.trim().parse().unwrap_or(0),
                "dir" => p.dir = PathBuf::from(v.trim()),
                "hooks" => {
                    p.hooks = v
                        .split(',')
                        .filter_map(|s| s.trim().parse().ok())
                        .filter(|s: &usize| *s < HOOK_COUNT)
                        .collect()
                }
                "write_fd" => p.write_fd = v.trim() == "1",
                "move" => p.move_procs = Some(PathBuf::from(v.trim())),
                "bpffs" => {
                    let root = p.bpffs.take().map(|(_, r)| r).unwrap_or_default();
                    p.bpffs = Some((PathBuf::from(v.trim()), root));
                }
                "pin_root" => {
                    let mount = p.bpffs.take().map(|(m, _)| m).unwrap_or_default();
                    p.bpffs = Some((mount, v.trim().to_string()));
                }
                _ => {}
            }
        }
        p
    }
}

// ---------------------------------------------------------------------------
// The child's side
// ---------------------------------------------------------------------------

/// The child's word on an attempt.
fn word(r: std::io::Result<()>, refusal: i32) -> String {
    match r {
        Ok(()) => "done".to_string(),
        Err(e) if e.raw_os_error() == Some(refusal) => "refused".to_string(),
        Err(e) => format!(
            "other: {}",
            e.raw_os_error()
                .map_or_else(|| e.to_string(), |n| format!("errno {n} ({e})"))
        ),
    }
}

fn last_os<T: PartialEq + From<i8>>(r: T) -> std::io::Result<()> {
    if r == T::from(-1) {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    }
}

fn cstr(p: &Path) -> Option<CString> {
    use std::os::unix::ffi::OsStrExt;
    CString::new(p.as_os_str().as_bytes()).ok()
}

/// The child: each planned attempt, one `deny.<hook>=<word>` line each —
/// `refused`, `done` (the operation went through), `sent` (the owner's
/// signal: no error by design), `other: …` (another error), `skipped: …`
/// (the attempt could not be made).
pub fn run_steps(nonce: &str, plan: &Plan) -> String {
    let mut out = String::new();
    for &slot in &plan.hooks {
        let Some(h) = HOOKS.get(slot) else { continue };
        let Check::Attempt { errno, .. } = h.check else {
            continue;
        };
        let w = attempt_one(h.hook, errno, nonce, plan);
        out.push_str(&format!("deny.{}={w}\n", h.hook));
    }
    out
}

fn attempt_one(hook: &str, errno: i32, nonce: &str, plan: &Plan) -> String {
    let d = &plan.dir;
    let t = plan.target as libc::pid_t;
    let needs_target = matches!(
        hook,
        "task_kill"
            | "ptrace_access_check"
            | "task_setrlimit"
            | "task_setscheduler"
            | "task_setnice"
            | "task_setioprio"
            | "file_send_sigiotask"
            | "inode_permission"
    );
    if needs_target && t <= 1 {
        return "skipped: no target process".to_string();
    }
    match hook {
        "task_kill" => {
            // SAFETY: a signal to the self-test's own target.
            word(last_os(unsafe { libc::kill(t, SIGNAL) }), errno)
        }
        // attach mode (`mem_open`): the hook records it; a read-mode access
        // (`environ`) it refuses without a record
        "ptrace_access_check" => word(
            std::fs::File::open(format!("/proc/{t}/mem")).map(drop),
            errno,
        ),
        "inode_unlink" => word(std::fs::remove_file(d.join(file::UNLINK)), errno),
        "inode_rmdir" => word(std::fs::remove_dir(d.join(file::RMDIR)), errno),
        "inode_rename" => word(
            std::fs::rename(
                d.join(file::RENAME),
                d.join(format!("{}.{nonce}", file::RENAME)),
            ),
            errno,
        ),
        "inode_setattr" => {
            let p = d.join(file::ATTR);
            match std::fs::metadata(&p) {
                Ok(m) => word(
                    std::fs::set_permissions(
                        &p,
                        std::fs::Permissions::from_mode(m.permissions().mode() & 0o7777),
                    ),
                    errno,
                ),
                Err(e) => format!("skipped: {e}"),
            }
        }
        "file_ioctl" => ioctl_step(&d.join(file::ATTR), errno),
        "file_open" => word(
            std::fs::OpenOptions::new()
                .write(true)
                .open(d.join(file::WRITE_OPEN))
                .map(drop),
            errno,
        ),
        "inode_create" => word(
            std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(d.join(format!("c.{nonce}")))
                .map(drop),
            errno,
        ),
        "inode_mkdir" => word(std::fs::create_dir(d.join(format!("d.{nonce}"))), errno),
        "inode_mknod" => match cstr(&d.join(format!("p.{nonce}"))) {
            // SAFETY: a FIFO at a NUL-terminated path of the round's.
            Some(c) => word(
                last_os(unsafe { libc::mknod(c.as_ptr(), libc::S_IFIFO | 0o600, 0) }),
                errno,
            ),
            None => "skipped: a path with a NUL".to_string(),
        },
        "inode_symlink" => word(
            std::os::unix::fs::symlink("nn-selftest", d.join(format!("s.{nonce}"))),
            errno,
        ),
        "inode_link" => word(
            std::fs::hard_link(d.join(file::ATTR), d.join(format!("l.{nonce}"))),
            errno,
        ),
        "inode_setxattr" => xattr_set(&d.join(file::SETXATTR), XATTR_NAME, b"1", errno),
        "inode_removexattr" => xattr_remove(&d.join(file::REMOVEXATTR), XATTR_NAME, errno),
        "inode_set_acl" => {
            let p = d.join(file::SET_ACL);
            match std::fs::metadata(&p) {
                Ok(m) => xattr_set(&p, ACL_NAME, &minimal_acl(m.permissions().mode()), errno),
                Err(e) => format!("skipped: {e}"),
            }
        }
        "inode_remove_acl" => xattr_remove(&d.join(file::REMOVE_ACL), ACL_NAME, errno),
        "file_permission" => {
            if !plan.write_fd {
                return "skipped: no descriptor handed over".to_string();
            }
            let b = [0u8; 1];
            // SAFETY: a write of 0 bytes to the descriptor the parent put at
            // WRITE_FD for this step.
            word(
                last_os(unsafe { libc::write(WRITE_FD, b.as_ptr() as *const libc::c_void, 0) }),
                errno,
            )
        }
        "task_setrlimit" => {
            let r = libc::rlimit {
                rlim_cur: 0,
                rlim_max: 0,
            };
            // SAFETY: the target's core limit set from a valid rlimit.
            word(
                last_os(unsafe { libc::prlimit(t, libc::RLIMIT_CORE, &r, std::ptr::null_mut()) }),
                errno,
            )
        }
        "task_setscheduler" => {
            let p = libc::sched_param { sched_priority: 0 };
            // SAFETY: the target's policy set to SCHED_OTHER, which it has.
            word(
                last_os(unsafe { libc::sched_setscheduler(t, libc::SCHED_OTHER, &p) }),
                errno,
            )
        }
        "task_setnice" => word(
            // SAFETY: plain call on the target.
            last_os(unsafe { libc::setpriority(libc::PRIO_PROCESS, t as libc::id_t, NICE) }),
            errno,
        ),
        "task_setioprio" => word(
            // SAFETY: ioprio_set(IOPRIO_WHO_PROCESS, target, value).
            last_os(unsafe {
                libc::syscall(
                    libc::SYS_ioprio_set,
                    1 as libc::c_long,
                    t as libc::c_long,
                    IOPRIO as libc::c_long,
                )
            }),
            errno,
        ),
        "file_send_sigiotask" => sigio_step(t),
        "inode_permission" => match &plan.move_procs {
            Some(p) => word(
                std::fs::OpenOptions::new()
                    .write(true)
                    .open(p)
                    .and_then(|mut f| f.write_all(t.to_string().as_bytes())),
                errno,
            ),
            None => "skipped: the move guard is not attached".to_string(),
        },
        "bpf" => prog_load_step(errno),
        "bpf_map" => obj_get_step(plan, MAP_PIN, BPF_F_RDONLY, errno),
        "bpf_prog" => obj_get_step(plan, PROG_PIN, 0, errno),
        other => format!("skipped: no attempt for {other}"),
    }
}

/// `FS_IOC_GETFLAGS` (`_IOR('f', 1, long)`), which no hook judges.
const FS_IOC_GETFLAGS: u32 = 0x8008_6601;
/// `F_SETSIG` (Linux): the signal a file's owner gets.
const F_SETSIG: libc::c_int = 10;

/// `FS_IOC_SETFLAGS` with the flags the file has (0 where it reports
/// none: tmpfs before 6.0).
fn ioctl_step(p: &Path, errno: i32) -> String {
    use std::os::fd::AsRawFd;
    let f = match std::fs::File::open(p) {
        Ok(f) => f,
        Err(e) => return format!("skipped: {e}"),
    };
    let mut flags: libc::c_int = 0;
    // SAFETY: FS_IOC_GETFLAGS into a c_int (the kernel writes an int).
    unsafe {
        libc::ioctl(
            f.as_raw_fd(),
            FS_IOC_GETFLAGS as _,
            &mut flags as *mut libc::c_int,
        )
    };
    // SAFETY: FS_IOC_SETFLAGS from a c_int the kernel reads.
    let r = unsafe {
        libc::ioctl(
            f.as_raw_fd(),
            common::wire::FS_IOC_SETFLAGS as _,
            &flags as *const libc::c_int,
        )
    };
    word(last_os(r), errno)
}

fn xattr_set(p: &Path, name: &str, value: &[u8], errno: i32) -> String {
    let (Some(path), Ok(n)) = (cstr(p), CString::new(name)) else {
        return "skipped: a name with a NUL".to_string();
    };
    // SAFETY: NUL-terminated path and name, a value of its length.
    let r = unsafe {
        libc::setxattr(
            path.as_ptr(),
            n.as_ptr(),
            value.as_ptr() as *const libc::c_void,
            value.len(),
            0,
        )
    };
    word(last_os(r), errno)
}

fn xattr_remove(p: &Path, name: &str, errno: i32) -> String {
    let (Some(path), Ok(n)) = (cstr(p), CString::new(name)) else {
        return "skipped: a name with a NUL".to_string();
    };
    // SAFETY: NUL-terminated path and name.
    word(
        last_os(unsafe { libc::removexattr(path.as_ptr(), n.as_ptr()) }),
        errno,
    )
}

/// A POSIX ACL in the kernel's xattr form equal to `mode`: the owner, the
/// group and the others (no named entry, no mask).
pub fn minimal_acl(mode: u32) -> Vec<u8> {
    const VERSION: u32 = 2;
    const UNDEFINED_ID: u32 = u32::MAX;
    let mut v = VERSION.to_le_bytes().to_vec();
    for (tag, perm) in [
        (0x01u16, (mode >> 6) & 7),
        (0x04u16, (mode >> 3) & 7),
        (0x20u16, mode & 7),
    ] {
        v.extend_from_slice(&tag.to_le_bytes());
        v.extend_from_slice(&(perm as u16).to_le_bytes());
        v.extend_from_slice(&UNDEFINED_ID.to_le_bytes());
    }
    v
}

/// SIGURG through a pipe's owner: the read end owned by the target,
/// `F_SETSIG`, `O_ASYNC`, one byte written. The kernel refuses the signal
/// silently: `sent`, and the record says the rest.
fn sigio_step(target: libc::pid_t) -> String {
    let mut fds = [0 as libc::c_int; 2];
    // SAFETY: two descriptors to fill.
    if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
        return format!("skipped: pipe: {}", std::io::Error::last_os_error());
    }
    let (r, w) = (fds[0], fds[1]);
    // SAFETY: fcntl and write on our own pipe; both closed below.
    let res = unsafe {
        let fl = libc::fcntl(r, libc::F_GETFL);
        if libc::fcntl(r, libc::F_SETOWN, target) != 0
            || libc::fcntl(r, F_SETSIG, SIGNAL) != 0
            || fl < 0
            || libc::fcntl(r, libc::F_SETFL, fl | libc::O_ASYNC) != 0
            || libc::write(w, b"x".as_ptr() as *const libc::c_void, 1) != 1
        {
            Err(std::io::Error::last_os_error())
        } else {
            Ok(())
        }
    };
    // SAFETY: our own descriptors.
    unsafe {
        libc::close(r);
        libc::close(w);
    }
    match res {
        Ok(()) => "sent".to_string(),
        Err(e) => format!("skipped: {e}"),
    }
}

/// `union bpf_attr` as 8-byte words (the kernel reads the commands'
/// fields; the rest is zero).
const ATTR_WORDS: usize = 16;
/// `BPF_F_RDONLY`.
const BPF_F_RDONLY: u32 = 1 << 3;

fn bpf(cmd: u32, attr: &[u64; ATTR_WORDS], size: usize) -> std::io::Result<()> {
    // SAFETY: bpf(cmd, attr, size) with a fully initialised attr of at least
    // `size` bytes; a descriptor it returns is closed at once.
    let fd = unsafe {
        libc::syscall(
            libc::SYS_bpf,
            cmd as libc::c_long,
            attr.as_ptr() as *const libc::c_void,
            size as u32,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: the descriptor the kernel just returned, ours alone.
    unsafe { libc::close(fd as libc::c_int) };
    Ok(())
}

/// A two-instruction kprobe program (`r0 = 0; exit`), never attached.
fn prog_load_step(errno: i32) -> String {
    const MOV_R0_0: u64 = 0xb7;
    const EXIT: u64 = 0x95;
    let insns: [u64; 2] = [MOV_R0_0, EXIT];
    let license = b"GPL\0";
    let mut attr = [0u64; ATTR_WORDS];
    attr[0] = u64::from(PROG_TYPE_KPROBE) | (2u64 << 32);
    attr[1] = insns.as_ptr() as u64;
    attr[2] = license.as_ptr() as u64;
    word(
        bpf(common::bpf_cmd::BPF_PROG_LOAD, &attr, ATTR_WORDS * 8),
        errno,
    )
}

/// `BPF_OBJ_GET` of the pin `name` of the pin root by a path relative to
/// the bpffs mount (the `bpf` hook judges the absolute paths under the
/// agent's pin directories first).
fn obj_get_step(plan: &Plan, name: &str, flags: u32, errno: i32) -> String {
    let Some((mount, root)) = &plan.bpffs else {
        return "skipped: no pin root".to_string();
    };
    let Ok(rel) = CString::new(format!("{root}/{name}")) else {
        return "skipped: a name with a NUL".to_string();
    };
    if let Err(e) = std::env::set_current_dir(mount) {
        return format!("skipped: chdir {}: {e}", mount.display());
    }
    let mut attr = [0u64; ATTR_WORDS];
    attr[0] = rel.as_ptr() as u64;
    attr[1] = u64::from(flags) << 32;
    let r = bpf(common::bpf_cmd::BPF_OBJ_GET, &attr, 16);
    let _ = std::env::set_current_dir("/");
    word(r, errno)
}

// ---------------------------------------------------------------------------
// The round's outcome (the agent's side)
// ---------------------------------------------------------------------------

/// A hook's round.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// Refused and its refusal arrived (or, an attach check: linked).
    Seen,
    /// Let through, its refusal lost, or (an attach check) detached; why.
    Missed(String),
    /// Not attempted here, and why.
    NotExercised(String),
}

/// A hook's programs in the agent's program-id list and the live links:
/// `None` none loaded, `Some(true)` every loaded one linked, `Some(false)`
/// one loaded and not linked (its name and id).
pub fn link_state(
    programs: &[&str],
    own_ids: &str,
    live: &HashSet<u32>,
) -> Option<Result<(), String>> {
    let mut found = false;
    for line in own_ids.lines() {
        let mut f = line.split_whitespace();
        let (Some(id), Some(name)) = (f.next(), f.next()) else {
            continue;
        };
        let Ok(id) = id.parse::<u32>() else { continue };
        if !programs.contains(&name) {
            continue;
        }
        found = true;
        if !live.contains(&id) {
            return Some(Err(format!(
                "its program {name} (id {id}) is loaded and no link of the agent runs it: detached"
            )));
        }
    }
    found.then_some(Ok(()))
}

/// Which hooks a round attempts, and why the others are not: `Ok(())`
/// attempted, `Err(why)` not exercised. `links`: each hook's
/// [`link_state`] (`None` when the program-id list is not readable).
pub fn plan_hooks(
    links: Option<&[Option<Result<(), String>>]>,
    enforce: bool,
    target: bool,
    keys: bool,
) -> Vec<Result<(), String>> {
    HOOKS
        .iter()
        .enumerate()
        .map(|(i, h)| {
            let Check::Attempt { needs, expect, .. } = h.check else {
                return Err("an attach check".to_string());
            };
            let loaded = links.map(|l| l.get(i).cloned().flatten());
            match needs {
                Needs::Loaded if matches!(loaded, Some(None)) => {
                    return Err(
                        "its hook is not on this kernel (its program is not loaded)".to_string()
                    )
                }
                Needs::Enforce if !enforce => {
                    return Err("the BPF guard observes (a debug build, or \
                                NN_BPF_DEFENSE_OBSERVE=1): it refuses no handle by design"
                        .to_string())
                }
                _ => {}
            }
            match expect {
                Expect::TargetPid if !target => Err(
                    "no target process this round (it could not be started or protected)"
                        .to_string(),
                ),
                Expect::Dir | Expect::File(_) if !keys => {
                    Err("the self-test's directory is not protected this round".to_string())
                }
                _ => Ok(()),
            }
        })
        .collect()
}

/// Each hook's outcome: the plan's verdict (`planned`), the child's words
/// (`report`: `deny.<hook>` lines), the refusals seen (`seen`), the
/// attach checks' link states (`links`), a window open.
pub fn outcomes(
    planned: &[Result<(), String>],
    report: &super::ChildReport,
    seen: &[bool],
    links: Option<&[Option<Result<(), String>>]>,
    window: bool,
) -> Vec<Outcome> {
    HOOKS
        .iter()
        .enumerate()
        .map(|(i, h)| {
            if let Check::AttachOnly { why } = h.check {
                return match links.map(|l| l.get(i).cloned().flatten()) {
                    None => Outcome::NotExercised(
                        "the agent's program-id list (bpf-own-ids) is not readable".to_string(),
                    ),
                    Some(None) => Outcome::NotExercised(format!(
                        "its program is not loaded (not on this kernel, or off); attach check \
                         only: {why}"
                    )),
                    Some(Some(Ok(()))) => Outcome::Seen,
                    Some(Some(Err(e))) => Outcome::Missed(e),
                };
            }
            if window {
                return Outcome::NotExercised(
                    "a trusted-installer window is open: the deny hooks refuse nothing in it"
                        .to_string(),
                );
            }
            if let Some(Err(why)) = planned.get(i) {
                return Outcome::NotExercised(why.clone());
            }
            let got = seen.get(i).copied().unwrap_or(false);
            match report.get(&format!("deny.{}", h.hook)) {
                None => Outcome::NotExercised("the child did not report its attempt".to_string()),
                Some(w) if w.starts_with("skipped") => Outcome::NotExercised(w.to_string()),
                Some("refused") | Some("sent") if got => Outcome::Seen,
                Some("refused") => Outcome::Missed(format!(
                    "refused, but its refusal did not reach the pipeline within {} s",
                    super::DEADLINE_SECS
                )),
                Some("sent") => Outcome::Missed(format!(
                    "no refusal recorded within {} s: the signal went through the file's owner, \
                     or its record was lost",
                    super::DEADLINE_SECS
                )),
                Some("done") => Outcome::Missed(
                    "not refused: the operation went through — the hook is attached and did not \
                     deny"
                        .to_string(),
                ),
                Some(other) => Outcome::Missed(format!("not refused: {other}")),
            }
        })
        .collect()
}

/// The signed degradation's detail of a missed hook (kept for its
/// episode).
pub fn degradation_detail(h: &HookTest, why: &str) -> String {
    format!(
        "deny hook {}: self-test step `{}` missed — {why}",
        h.hook, h.step
    )
}

/// What a round's outcomes make the deny self-test sign.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Note {
    Degraded { slot: usize, detail: String },
    Alert { slot: usize, detail: String },
    StillMissed { slot: usize, rounds: u32 },
    Restored { slot: usize, rounds: u32 },
    NotExercised { slot: usize, why: String },
}

/// The deny self-test's memory between rounds.
#[derive(Clone, Debug)]
pub struct State {
    pub word: [Option<ProbeState>; HOOK_COUNT],
    pub misses: [u32; HOOK_COUNT],
    pub degraded: [Option<String>; HOOK_COUNT],
    pub not_exercised: [bool; HOOK_COUNT],
}

impl Default for State {
    fn default() -> Self {
        State {
            word: [None; HOOK_COUNT],
            misses: [0; HOOK_COUNT],
            degraded: std::array::from_fn(|_| None),
            not_exercised: [false; HOOK_COUNT],
        }
    }
}

impl State {
    /// One round's outcomes in, what to sign out (pure).
    pub fn apply(&mut self, outcomes: &[Outcome]) -> Vec<Note> {
        let mut notes = Vec::new();
        for (i, o) in outcomes.iter().enumerate().take(HOOK_COUNT) {
            match o {
                Outcome::Seen => {
                    if self.misses[i] > 0 {
                        notes.push(Note::Restored {
                            slot: i,
                            rounds: self.misses[i],
                        });
                    }
                    self.misses[i] = 0;
                    self.degraded[i] = None;
                    self.not_exercised[i] = false;
                    self.word[i] = Some(ProbeState::Seen);
                }
                Outcome::Missed(why) => {
                    self.misses[i] += 1;
                    self.not_exercised[i] = false;
                    let detail = degradation_detail(&HOOKS[i], why);
                    match self.misses[i] {
                        1 => {
                            self.degraded[i] = Some(detail.clone());
                            notes.push(Note::Degraded { slot: i, detail });
                            self.word[i] = Some(ProbeState::Missed);
                        }
                        2 => {
                            notes.push(Note::Alert { slot: i, detail });
                            self.word[i] = Some(ProbeState::Gap);
                        }
                        n => {
                            notes.push(Note::StillMissed { slot: i, rounds: n });
                            self.word[i] = Some(ProbeState::Gap);
                        }
                    }
                }
                Outcome::NotExercised(why) => {
                    if !self.not_exercised[i] {
                        notes.push(Note::NotExercised {
                            slot: i,
                            why: why.clone(),
                        });
                    }
                    self.not_exercised[i] = true;
                    if self.misses[i] == 0 {
                        self.word[i] = Some(ProbeState::NotExercised);
                    }
                }
            }
        }
        notes
    }

    /// The details of the open degradations.
    pub fn open_details(&self) -> Vec<String> {
        self.degraded.iter().flatten().cloned().collect()
    }
}

/// Sign the deny self-test's notes.
pub fn sign(
    notes: &[Note],
    nonce: &str,
    open: &[String],
    audit_log: Option<&Arc<Mutex<AuditLog>>>,
) {
    let mut withdraw = false;
    for n in notes {
        match n {
            Note::Degraded { slot, detail } => {
                let h = &HOOKS[*slot];
                error!(
                    hook = h.hook,
                    step = h.step,
                    nonce,
                    "DENY SELF-TEST MISSED — the hook's attempt was not refused, or its refusal \
                     did not arrive: detached, not run by the kernel, or its record lost"
                );
                crate::boot::degradation::report_signed(
                    audit_log,
                    DEGRADATION_SOURCE,
                    detail,
                    false,
                );
            }
            Note::Alert { slot, detail } => {
                let h = &HOOKS[*slot];
                error!(
                    hook = h.hook,
                    nonce,
                    "DENY SELF-TEST ALERT — two rounds in a row this deny hook did not prove it \
                     denies"
                );
                super::audit(
                    audit_log,
                    AUDIT_OP_ALERT,
                    "detected",
                    serde_json::json!({
                        "hook": h.hook,
                        "step": h.step,
                        "rounds_missed": 2,
                        "detail": detail,
                        "nonce": nonce,
                    }),
                );
            }
            Note::StillMissed { slot, rounds } => error!(
                hook = HOOKS[*slot].hook,
                rounds, nonce, "deny self-test: the hook still does not prove it denies"
            ),
            Note::Restored { slot, rounds } => {
                let h = &HOOKS[*slot];
                info!(
                    hook = h.hook,
                    rounds_missed = rounds,
                    "deny self-test: hook RESTORED — its attempt is refused again"
                );
                withdraw = true;
                super::audit(
                    audit_log,
                    AUDIT_OP_RESTORED,
                    "success",
                    serde_json::json!({ "hook": h.hook, "rounds_missed": rounds, "nonce": nonce }),
                );
            }
            Note::NotExercised { slot, why } => warn!(
                hook = HOOKS[*slot].hook,
                why,
                "deny self-test: this hook's attempt cannot run here — its rounds say nothing of it"
            ),
        }
    }
    if withdraw {
        crate::boot::degradation::withdraw(DEGRADATION_SOURCE, open);
    }
}

/// The target process's role in `PROTECTED_PIDS`: a worker — protected,
/// never exempt.
pub const TARGET_ROLE: u8 = antitamper_bpf::pid_role::WORKER;

/// The round's target process: started, protected (a worker), and ended
/// with its CPU time.
pub struct TargetProcess {
    pid: u32,
    pin_root: PathBuf,
}

impl TargetProcess {
    /// `exe --move-guard-self-test-target`, registered in `PROTECTED_PIDS`
    /// as a worker under `pin_root`.
    pub fn start(exe: &Path, pin_root: &Path) -> Result<Self, String> {
        let child = std::process::Command::new(exe)
            .arg(TARGET_FLAG)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .map_err(|e| format!("cannot start {TARGET_FLAG}: {e}"))?;
        let pid = child.id();
        // reaped by `end` (wait4 by pid): the handle is not waited on (its
        // drop neither waits nor kills)
        drop(child);
        let t = TargetProcess {
            pid,
            pin_root: pin_root.to_path_buf(),
        };
        if let Err(e) = antitamper_bpf::ProtectedPidsHandle::open(pin_root)
            .and_then(|mut h| h.insert_role(pid, TARGET_ROLE))
        {
            t.end();
            return Err(format!("the target is not protected: {e:#}"));
        }
        Ok(t)
    }

    pub fn pid(&self) -> u32 {
        self.pid
    }

    /// Killed (the agent is exempt), reaped, evicted: its CPU time.
    pub fn end(self) -> Duration {
        // SAFETY: our own child, not reaped yet: the pid is its.
        unsafe { libc::kill(self.pid as libc::pid_t, libc::SIGKILL) };
        let cpu = super::reap(self.pid, Duration::from_secs(2))
            .map(|(_, c)| c)
            .unwrap_or_default();
        if let Err(e) = antitamper_bpf::ProtectedPidsHandle::open(&self.pin_root)
            .and_then(|mut h| h.evict(self.pid))
        {
            warn!(pid = self.pid, error = %format!("{e:#}"), "deny self-test: the target's role not evicted");
        }
        cpu
    }
}

/// The throwaway cgroup of the move step (`None`: no cgroup v2 root, or
/// it could not be made).
pub fn make_move_cgroup() -> Option<PathBuf> {
    let root = antitamper_bpf::cgroup_guard::cgroup2_root()?;
    let dir = root.join(MOVE_CGROUP);
    // a leftover of a round (empty: its target is gone)
    let _ = std::fs::remove_dir(&dir);
    std::fs::create_dir(&dir).ok()?;
    Some(dir)
}

#[cfg(test)]
mod tests;
