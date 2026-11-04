//! NN-L-AT-001 — every anti-tamper denial becomes a signed detection.
//!
//! The kernel refuses the action either way (`task_kill`, `ptrace`,
//! `inode_*`, `bpf_map`, `bpf` hooks); this rule makes the attempt part of
//! the signed detection chain instead of a journal line only, so the
//! adversarial check (`deploy/lab/adversarial/anti-tamper.sh`) finds every
//! refused case in `detections.jsonl`. Posture still reacts through the
//! `AntiTamperDenial` trigger (COMBAT / INVESTIGATE) — or, for a signal
//! systemd relayed, `RelayedTamperAttempt` (ENGAGED). Log only: the attempt
//! already failed, and killing the actor is the ladder's call.
//!
//! Not in the engine's rule list: `process_event` short-circuits every
//! `FsProtectDenial` before the engine (a kernel deny is not re-evaluated)
//! and calls this rule directly in that arm.

use nn_model::{Event, FsProtectOperation, ResponseAction, Severity, Verdict};

use crate::decision::attack::{AttackRef, Tactic};
use crate::decision::{rules::build_verdict, Rule};

pub struct NnLAt001AntiTamperDenial;

impl Rule for NnLAt001AntiTamperDenial {
    fn id(&self) -> &'static str {
        "NN-L-AT-001_AntiTamperDenial"
    }
    fn name(&self) -> &'static str {
        "Attempt on the agent refused by an anti-tamper hook"
    }
    fn category(&self) -> &'static str {
        "anti_tamper"
    }
    fn attack(&self) -> &'static [AttackRef] {
        const ATTACK: &[AttackRef] = &[
            AttackRef::new(Tactic::DefenseImpairment, "T1685"),
            AttackRef::new(Tactic::Stealth, "T1055.008"),
            AttackRef::new(Tactic::Stealth, "T1055.009"),
            AttackRef::new(Tactic::CredentialAccess, "T1552.004"),
        ];
        ATTACK
    }
    fn evaluate(&self, event: &Event) -> Option<Verdict> {
        let Event::FsProtectDenial {
            pid,
            comm,
            target_dev,
            target_ino,
            operation,
            ..
        } = event
        else {
            return None;
        };
        let what = match operation {
            // External audit EBPF-001: systemd only relays root's request.
            FsProtectOperation::Signal if *pid == 1 => format!(
                "to deliver signal {target_dev} to protected pid {target_ino} on behalf of a \
                 `systemctl stop` / `kill` / `restart` outside a trusted-installer window"
            ),
            FsProtectOperation::Signal => {
                format!("signal {target_dev} to protected pid {target_ino} (kill / pkill)")
            }
            FsProtectOperation::Ptrace => format!(
                "ptrace attach (mode {target_dev:#x}) on protected pid {target_ino} — debugger, \
                 /proc/<pid>/mem or process_vm_readv/writev"
            ),
            FsProtectOperation::BpfMap => {
                format!("write handle on the agent's BPF map id {target_ino}")
            }
            FsProtectOperation::BpfLink => {
                format!("handle to the agent's BPF link (id {target_ino}, 0 = through the pin)")
            }
            // Review 82: a loaded image lets root reboot at once into a
            // kernel without the agent.
            FsProtectOperation::Kexec => "to load a kexec kernel image (kexec -l / -p / \
                 systemctl kexec) outside the trusted-installer window: a loaded image \
                 boots a kernel without the agent"
                .to_string(),
            // External audit EVD-001: the key that signs every evidence chain.
            FsProtectOperation::Read => format!(
                "to read the agent's private signing key (inode {target_dev}:{target_ino}), which \
                 signs every evidence chain"
            ),
            // External audit EBPF-015: the target of a new entry is the
            // directory it was to be made in.
            FsProtectOperation::Create
            | FsProtectOperation::Link
            | FsProtectOperation::Symlink
            | FsProtectOperation::Mkdir
            | FsProtectOperation::Mknod => format!(
                "a new entry ({operation}) in the agent's protected directory (inode \
                 {target_dev}:{target_ino}) outside a trusted-installer window"
            ),
            FsProtectOperation::Xattr => format!(
                "to change an extended attribute or ACL of protected inode \
                 {target_dev}:{target_ino}"
            ),
            // Lot 273: the kernel kill of a whole cgroup, which no signal
            // hook sees; systemd 257 and later write it for `systemctl kill
            // -s SIGKILL` once the main process refused the signal.
            FsProtectOperation::CgroupKill if *pid == 1 => format!(
                "to kill a protected unit's cgroup through cgroup.kill (inode \
                 {target_dev}:{target_ino}) on behalf of a `systemctl kill -s SIGKILL` outside \
                 a trusted-installer window"
            ),
            FsProtectOperation::CgroupKill => format!(
                "to kill every process of a protected unit's cgroup through cgroup.kill (inode \
                 {target_dev}:{target_ino}), a kernel SIGKILL no signal hook sees"
            ),
            FsProtectOperation::CgroupFreeze if *pid == 1 => format!(
                "to freeze a protected unit's cgroup through cgroup.freeze (inode \
                 {target_dev}:{target_ino}) on behalf of a `systemctl freeze` outside a \
                 trusted-installer window"
            ),
            FsProtectOperation::CgroupFreeze => format!(
                "to freeze every process of a protected unit's cgroup through cgroup.freeze \
                 (inode {target_dev}:{target_ino})"
            ),
            FsProtectOperation::CgroupMove if *pid == 1 => format!(
                "to move protected pid {target_ino} to another cgroup on behalf of a systemd \
                 request outside a trusted-installer window"
            ),
            FsProtectOperation::CgroupMove => format!(
                "to move protected pid {target_ino} out of its unit's cgroup (cgroup.procs / \
                 cgroup.threads), where it could be killed or frozen through a cgroup nobody \
                 protects"
            ),
            // Lot 273b: a resource limit that kills or starves the agent
            // (a low memory.max is an OOM kill inside the write; cpu.max,
            // cpu.idle, pids.max starve it as a freeze does).
            FsProtectOperation::CgroupLimit if *pid == 1 => format!(
                "to change a resource limit of a protected unit's cgroup or of its slice (inode \
                 {target_dev}:{target_ino}) from the value it started with, on behalf of a \
                 `systemctl set-property` outside a trusted-installer window"
            ),
            FsProtectOperation::CgroupLimit => format!(
                "to write a resource limit of a protected unit's cgroup or of its slice (inode \
                 {target_dev}:{target_ino}) — memory.max, cpu.max, pids.max and the like kill \
                 or starve the agent without a signal"
            ),
            FsProtectOperation::CgroupV1 => format!(
                "to write a cgroup v1 hierarchy (inode {target_dev}:{target_ino}) on a host whose \
                 systemd runs the unified one — a v1 freezer stops the agent where no v2 hook sees \
                 it"
            ),
            FsProtectOperation::OomAdj => format!(
                "to change the OOM score of protected pid {target_ino} (oom_score_adj), which would \
                 make it the OOM killer's first victim — a SIGKILL no signal hook sees"
            ),
            // Lot 273c (the review of #490): a limit, a priority, an
            // affinity — another process's settings of the agent.
            FsProtectOperation::Rlimit => format!(
                "to change resource limit {target_dev} of protected pid {target_ino} (prlimit) — \
                 an RLIMIT_CPU passed is a SIGKILL from the kernel, a small address space or \
                 descriptor limit breaks it"
            ),
            FsProtectOperation::Sched => format!(
                "to change the scheduling policy, priority or CPU affinity of protected pid \
                 {target_ino} (chrt, taskset, sched_setattr) — SCHED_IDLE or one busy CPU \
                 starves it"
            ),
            FsProtectOperation::Nice => format!(
                "to set the nice value of protected pid {target_ino} to {} (renice)",
                *target_dev as i64
            ),
            FsProtectOperation::Ioprio => format!(
                "to set the I/O priority of protected pid {target_ino} to {target_dev:#x} (ionice)"
            ),
            FsProtectOperation::Sysctl => format!(
                "to write a global sysctl (inode {target_dev}:{target_ino}) with a value that aborts \
                 or starves the agent with the host (overcommit, pid_max, threads-max, \
                 max_map_count or real-time throttling), or kernel.ftrace_enabled, refused whatever \
                 it carries (0 stops the BPF trampolines, the agent's hooks among them)"
            ),
            other => format!("{other} on protected inode {target_dev}:{target_ino}"),
        };
        let reasoning = format!(
            "`{comm}` attempted {what}; the kernel refused it. An attempt on the sensor itself is \
             the clearest intent signal there is."
        );
        Some(build_verdict(
            self,
            event,
            ResponseAction::Log,
            Severity::High,
            &reasoning,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn denial(op: FsProtectOperation) -> Event {
        Event::FsProtectDenial {
            pid: 4242,
            uid: 0,
            comm: "bash".into(),
            target_dev: 9,
            target_ino: 709,
            operation: op,
            timestamp_ns: 1,
        }
    }

    /// Review 82: the kexec wire byte decodes to `Kexec`, and an unknown
    /// byte stays unknown (a missing import once turned the arm into a
    /// catch-all binding).
    #[test]
    fn kexec_wire_byte_decodes_and_unknown_stays_unknown() {
        use common::wire::FS_OP_KEXEC;
        assert_eq!(
            FsProtectOperation::from_wire(FS_OP_KEXEC),
            FsProtectOperation::Kexec
        );
        assert_eq!(
            FsProtectOperation::from_wire(200),
            FsProtectOperation::Unknown(200)
        );
    }

    #[test]
    fn every_denial_kind_is_a_high_log_verdict() {
        for op in [
            FsProtectOperation::Signal,
            FsProtectOperation::Ptrace,
            FsProtectOperation::Unlink,
            FsProtectOperation::BpfMap,
            FsProtectOperation::BpfLink,
            FsProtectOperation::Kexec,
            FsProtectOperation::Create,
            FsProtectOperation::Link,
            FsProtectOperation::Symlink,
            FsProtectOperation::Mkdir,
            FsProtectOperation::Mknod,
            FsProtectOperation::Xattr,
            FsProtectOperation::CgroupMove,
            FsProtectOperation::CgroupKill,
            FsProtectOperation::CgroupFreeze,
            FsProtectOperation::CgroupLimit,
            FsProtectOperation::CgroupV1,
            FsProtectOperation::OomAdj,
            FsProtectOperation::Rlimit,
            FsProtectOperation::Sched,
            FsProtectOperation::Nice,
            FsProtectOperation::Ioprio,
            FsProtectOperation::Sysctl,
        ] {
            let v = NnLAt001AntiTamperDenial
                .evaluate(&denial(op))
                .expect("verdict");
            assert_eq!(v.severity, Severity::High);
            assert!(matches!(v.action, ResponseAction::Log));
        }
        let v = NnLAt001AntiTamperDenial
            .evaluate(&denial(FsProtectOperation::Signal))
            .unwrap();
        assert!(v.reasoning.contains("signal 9 to protected pid 709"));
    }

    /// External audit EBPF-015: a refused new entry names the directory as
    /// where it was to be made, and the operation by its kernel name.
    #[test]
    fn a_refused_new_entry_names_the_directory() {
        let v = NnLAt001AntiTamperDenial
            .evaluate(&denial(FsProtectOperation::Mkdir))
            .expect("verdict");
        assert!(v.reasoning.contains("new entry (mkdir)"), "{}", v.reasoning);
        assert!(
            v.reasoning.contains("directory (inode 9:709)"),
            "{}",
            v.reasoning
        );
        let v = NnLAt001AntiTamperDenial
            .evaluate(&denial(FsProtectOperation::Xattr))
            .expect("verdict");
        assert!(
            v.reasoning.contains("extended attribute"),
            "{}",
            v.reasoning
        );
    }

    /// External audit EBPF-001: a signal PID 1 relayed names the request,
    /// not systemd, as what was refused.
    #[test]
    fn a_relayed_signal_names_the_systemctl_request() {
        let mut e = denial(FsProtectOperation::Signal);
        if let Event::FsProtectDenial { pid, comm, .. } = &mut e {
            *pid = 1;
            *comm = "systemd".into();
        }
        let v = NnLAt001AntiTamperDenial.evaluate(&e).expect("verdict");
        assert!(v.reasoning.contains("systemctl stop"), "{}", v.reasoning);
        assert!(v.reasoning.contains("trusted-installer window"));
    }

    /// Lot 273: a refused cgroup kill, freeze or move names what it would
    /// have done — for PID 1 the `systemctl` request it relayed — and a
    /// move names the protected pid.
    #[test]
    fn a_refused_cgroup_operation_names_its_effect() {
        let relayed = |op| {
            let mut e = denial(op);
            if let Event::FsProtectDenial { pid, comm, .. } = &mut e {
                *pid = 1;
                *comm = "systemd".into();
            }
            NnLAt001AntiTamperDenial
                .evaluate(&e)
                .expect("verdict")
                .reasoning
        };
        let direct = |op| {
            NnLAt001AntiTamperDenial
                .evaluate(&denial(op))
                .expect("verdict")
                .reasoning
        };
        // Lot 273c: another process's limits and priorities of the agent
        let r = direct(FsProtectOperation::Rlimit);
        assert!(
            r.contains("resource limit 9 of protected pid 709 (prlimit)"),
            "{r}"
        );
        let r = direct(FsProtectOperation::Sched);
        assert!(r.contains("CPU affinity of protected pid 709"), "{r}");
        let r = direct(FsProtectOperation::Nice);
        assert!(
            r.contains("nice value of protected pid 709 to 9 (renice)"),
            "{r}"
        );
        let r = direct(FsProtectOperation::Ioprio);
        assert!(
            r.contains("I/O priority of protected pid 709 to 0x9 (ionice)"),
            "{r}"
        );
        let r = direct(FsProtectOperation::Sysctl);
        assert!(r.contains("global sysctl (inode 9:709)"), "{r}");
        assert!(
            r.contains("kernel.ftrace_enabled, refused whatever it carries"),
            "{r}"
        );
        let r = relayed(FsProtectOperation::CgroupKill);
        assert!(r.contains("systemctl kill -s SIGKILL"), "{r}");
        assert!(r.contains("cgroup.kill (inode 9:709)"), "{r}");
        let r = direct(FsProtectOperation::CgroupKill);
        assert!(r.contains("no signal hook sees"), "{r}");
        assert!(!r.contains("systemctl"), "{r}");
        let r = relayed(FsProtectOperation::CgroupFreeze);
        assert!(r.contains("systemctl freeze"), "{r}");
        let r = direct(FsProtectOperation::CgroupFreeze);
        assert!(r.contains("cgroup.freeze (inode 9:709)"), "{r}");
        let r = direct(FsProtectOperation::CgroupMove);
        assert!(
            r.contains("protected pid 709 out of its unit's cgroup"),
            "{r}"
        );
        let r = relayed(FsProtectOperation::CgroupMove);
        assert!(r.contains("protected pid 709"), "{r}");
        assert!(r.contains("systemd request"), "{r}");
        // Lot 273b
        let r = relayed(FsProtectOperation::CgroupLimit);
        assert!(r.contains("systemctl set-property"), "{r}");
        assert!(r.contains("from the value it started with"), "{r}");
        let r = direct(FsProtectOperation::CgroupLimit);
        assert!(r.contains("memory.max, cpu.max, pids.max"), "{r}");
        assert!(r.contains("(inode 9:709)"), "{r}");
        let r = direct(FsProtectOperation::CgroupV1);
        assert!(r.contains("cgroup v1 hierarchy (inode 9:709)"), "{r}");
        let r = direct(FsProtectOperation::OomAdj);
        assert!(r.contains("protected pid 709 (oom_score_adj)"), "{r}");
    }
}
