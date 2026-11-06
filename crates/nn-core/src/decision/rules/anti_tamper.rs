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
            // Lot 280a: the cgroup/sysctl program on the root cgroup judged
            // the kernel's copy of the write (no second thread changes it).
            FsProtectOperation::SysctlValue => {
                let (kind, value) = common::sysctl_judge::record_of(*target_dev, *target_ino);
                let name = common::sysctl_judge::name_of_kind(kind).unwrap_or("a guarded sysctl");
                let value = match value {
                    Some(v) => format!("= {v}"),
                    None => "with a value that is no integer the program could read".to_string(),
                };
                format!(
                    "to write {name} {value} (judged on the kernel's copy of the write by the \
                     cgroup/sysctl program on the root cgroup) — a value that aborts or starves \
                     the agent with the host (overcommit, pid_max, threads-max, max_map_count, \
                     real-time throttling), or a write of kernel.ftrace_enabled or \
                     kernel.sched_rt_period_us, refused whatever it carries"
                )
            }
            // Lot 280a: not refused — the signed per-sysctl opt-out let it
            // through; every such write is recorded, none raises the posture.
            FsProtectOperation::SysctlOptOut => {
                let (kind, value) = common::sysctl_judge::record_of(*target_dev, *target_ino);
                let name = common::sysctl_judge::name_of_kind(kind).unwrap_or("a guarded sysctl");
                let value = value.map_or_else(|| "?".to_string(), |v| v.to_string());
                let reasoning = format!(
                    "`{comm}` wrote {name} = {value}, a value the agent refuses outside a \
                     trusted-installer window; the signed per-rule policy's `sysctl-allow` \
                     {name} let it through (not refused, recorded)."
                );
                return Some(build_verdict(
                    self,
                    event,
                    ResponseAction::Log,
                    Severity::Low,
                    &reasoning,
                ));
            }
            // Lot 277: not refused — a process put in a cgroup the per-rule
            // policy exempts, by someone other than systemd: it and every
            // process it starts are never exempt by that cgroup or unit.
            FsProtectOperation::CgroupJoin => {
                let reasoning = format!(
                    "`{comm}` moved pid {target_ino} into a cgroup an exemption of the per-rule \
                     policy names (name hash {target_dev:#018x}) — not systemd starting it there. \
                     The move went through; that process and every process it starts are never \
                     exempt by the cgroup or the unit: posing as an exempt service is an attempt \
                     on the policy."
                );
                return Some(build_verdict(
                    self,
                    event,
                    ResponseAction::Log,
                    Severity::High,
                    &reasoning,
                ));
            }
            // Lot 281: not refused — code-injection access to a process
            // (`exempt_injection` signs it when an exemption covered it).
            FsProtectOperation::ExemptInjection => {
                return Some(injection_verdict(self, event, None, None));
            }
            // Lot 280b: the switches that blind the sensors.
            FsProtectOperation::Kprobes => format!(
                "to write /sys/kernel/debug/kprobes/enabled (inode {target_dev}:{target_ino}) \
                 outside a trusted-installer window — 0 disarms every kprobe on the host, the \
                 agent's among them"
            ),
            FsProtectOperation::Lockdown => format!(
                "to write /sys/kernel/security/lockdown (inode {target_dev}:{target_ino}) outside \
                 a trusted-installer window — a raise to confidentiality takes the helpers that \
                 read kernel memory from every BPF program loaded after it, the agent's next \
                 start among them"
            ),
            FsProtectOperation::SysctlRootAttach => format!(
                "to attach a cgroup/sysctl program to the root cgroup (attach type \
                 {target_ino}) outside a trusted-installer window — attached after the agent's \
                 sysctl judge, it would run after it and could rewrite the value it judged"
            ),
            // Lot 280b: not refused — the kernel-state round's finding.
            FsProtectOperation::KernelTaint => {
                let new = *target_dev;
                let meaning = common::kernel_taint::meaning(new).join(", ");
                let critical = common::kernel_taint::is_critical(new);
                let reasoning = format!(
                    "The kernel's taint flags gained {} ({meaning}) while the agent runs (taint \
                     mask now {target_ino}: {}): foreign code entered the kernel, beside the \
                     agent's hooks — a module the distribution did not ship{}, or a livepatch, \
                     which replaces kernel functions, those a hook is attached to included. Not \
                     refused: the kernel's own record, read every 5 s.",
                    common::kernel_taint::letters(new),
                    common::kernel_taint::letters(*target_ino),
                    if critical {
                        ", one the kernel could not vouch for (unsigned) or forced in or out"
                    } else {
                        ""
                    }
                );
                return Some(build_verdict(
                    self,
                    event,
                    ResponseAction::Log,
                    if critical {
                        Severity::Critical
                    } else {
                        Severity::High
                    },
                    &reasoning,
                ));
            }
            FsProtectOperation::SysctlRootProg => {
                let reasoning = format!(
                    "A cgroup/sysctl program not the agent's (id {target_ino}) is attached to the \
                     root cgroup: attached after the agent's sysctl judge, it runs after it on \
                     every sysctl write and may rewrite the value the judge let through. Not \
                     refused — found by the kernel-state round (attached inside a window, or \
                     before the agent started); `bpftool prog show id {target_ino}` names it."
                );
                return Some(build_verdict(
                    self,
                    event,
                    ResponseAction::Log,
                    Severity::High,
                    &reasoning,
                ));
            }
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

/// Lot 281: the severity of code-injection access to a process an
/// exemption of the per-rule policy covered — at least High; Critical when
/// the injector is not root, or does not come from an administrator's
/// interactive sudo/su session (`interactive_admin`: the lineage's
/// `interactive_admin_status`, `None` while it cannot be told — counted as
/// unusual).
pub fn injection_severity(injector_uid: u32, interactive_admin: Option<bool>) -> Severity {
    if injector_uid != 0 || interactive_admin != Some(true) {
        Severity::Critical
    } else {
        Severity::High
    }
}

/// What a record's access detail (`common::cgroup_join::inject_detail`)
/// was, in words.
fn access_words(detail: u64) -> String {
    use common::cgroup_join::{
        inject_detail_parts, PTRACE_MODE_FSCREDS, SYS_OPEN, SYS_OPENAT, SYS_OPENAT2,
    };
    let (mode, nr) = inject_detail_parts(detail);
    let what = match nr {
        Some(101) => "a debugger's attach (ptrace PTRACE_ATTACH / PTRACE_SEIZE)",
        Some(311) => "process_vm_writev",
        Some(438) => "pidfd_getfd (a descriptor of the process taken)",
        Some(SYS_OPEN | SYS_OPENAT | SYS_OPENAT2) if mode & PTRACE_MODE_FSCREDS != 0 => {
            "a write handle on its /proc/<pid>/mem"
        }
        Some(_) => "an attach-mode access",
        None => "an attach-mode access whose system call was not read",
    };
    match nr {
        Some(n) => format!("{what}; mode {mode:#x}, system call {n}"),
        None => format!("{what}; mode {mode:#x}"),
    }
}

/// Lot 281: NN-L-AT-001's verdict on code-injection access to a process
/// (`FsProtectOperation::ExemptInjection`) — `exemption` the policy's
/// exemption that covered the process (the agent signs the record only
/// then), `interactive_admin` the injector's lineage
/// ([`injection_severity`]). Not refused: the process and what it forks
/// lose every exemption for the rest of their lives.
pub fn exempt_injection(
    event: &Event,
    exemption: &str,
    interactive_admin: Option<bool>,
) -> Option<Verdict> {
    match event {
        Event::FsProtectDenial {
            operation: FsProtectOperation::ExemptInjection,
            ..
        } => Some(injection_verdict(
            &NnLAt001AntiTamperDenial,
            event,
            Some(exemption),
            interactive_admin,
        )),
        _ => None,
    }
}

fn injection_verdict(
    rule: &NnLAt001AntiTamperDenial,
    event: &Event,
    exemption: Option<&str>,
    interactive_admin: Option<bool>,
) -> Verdict {
    let (uid, comm, detail, target) = match event {
        Event::FsProtectDenial {
            uid,
            comm,
            target_dev,
            target_ino,
            ..
        } => (*uid, comm.as_str(), *target_dev, *target_ino),
        _ => (0, "", 0, 0),
    };
    let covered = match exemption {
        Some(e) => format!("the per-rule policy exempted it ({e}); "),
        None => String::new(),
    };
    let who = if uid != 0 {
        format!("uid {uid}, not root")
    } else {
        match interactive_admin {
            Some(true) => "root, from an administrator's interactive sudo/su session".to_string(),
            Some(false) => {
                "root, not from an administrator's interactive sudo/su session".to_string()
            }
            None => "root, from a lineage that could not be told".to_string(),
        }
    };
    let reasoning = format!(
        "`{comm}` ({who}) gained code-injection access to pid {target} — {}. Not refused;          {covered}that exemption, and every other, no longer holds for that process or for what          it forks, for the rest of their lives: what they do is judged like any other process's.",
        access_words(detail)
    );
    build_verdict(
        rule,
        event,
        ResponseAction::Log,
        injection_severity(uid, interactive_admin),
        &reasoning,
    )
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
            FsProtectOperation::CgroupJoin,
            FsProtectOperation::Sysctl,
            FsProtectOperation::SysctlValue,
            FsProtectOperation::Kprobes,
            FsProtectOperation::Lockdown,
            FsProtectOperation::SysctlRootAttach,
            FsProtectOperation::SysctlRootProg,
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

    /// Lot 277: a move into an exempt cgroup is signed as what it is — not
    /// refused, the exemptions lost — with the moved pid and the name's
    /// hash, never as a refusal.
    #[test]
    fn a_move_into_an_exempt_cgroup_is_signed_not_refused() {
        let r = NnLAt001AntiTamperDenial
            .evaluate(&denial(FsProtectOperation::CgroupJoin))
            .expect("verdict")
            .reasoning;
        assert!(r.contains("moved pid 709 into a cgroup"), "{r}");
        assert!(r.contains("0x0000000000000009"), "{r}");
        assert!(r.contains("never exempt"), "{r}");
        assert!(!r.contains("the kernel refused it"), "{r}");
    }

    /// Lot 280a: a refusal on the kernel's copy names the sysctl and the
    /// value the kernel would have stored; an opt-out's write is recorded
    /// as let through (Low), never as a refusal.
    #[test]
    fn a_sysctl_judged_on_the_kernel_copy_names_its_value() {
        use common::cgroup_limits::{SYSCTL_PID_MAX, SYSCTL_SCHED_RT_RUNTIME};
        use common::sysctl_judge::record_dev;
        let ev = |op, dev, ino| Event::FsProtectDenial {
            pid: 4242,
            uid: 0,
            comm: "tuned".into(),
            target_dev: dev,
            target_ino: ino,
            operation: op,
            timestamp_ns: 1,
        };
        let r = NnLAt001AntiTamperDenial
            .evaluate(&ev(
                FsProtectOperation::SysctlValue,
                record_dev(SYSCTL_PID_MAX, true),
                16384,
            ))
            .unwrap()
            .reasoning;
        assert!(r.contains("to write kernel.pid_max = 16384"), "{r}");
        assert!(r.contains("kernel's copy"), "{r}");
        assert!(r.contains("the kernel refused it"), "{r}");
        let r = NnLAt001AntiTamperDenial
            .evaluate(&ev(
                FsProtectOperation::SysctlValue,
                record_dev(SYSCTL_PID_MAX, false),
                0,
            ))
            .unwrap()
            .reasoning;
        assert!(r.contains("no integer the program could read"), "{r}");
        let v = NnLAt001AntiTamperDenial
            .evaluate(&ev(
                FsProtectOperation::SysctlOptOut,
                record_dev(SYSCTL_SCHED_RT_RUNTIME, true),
                (-1i64) as u64,
            ))
            .unwrap();
        assert_eq!(v.severity, Severity::Low);
        assert!(matches!(v.action, ResponseAction::Log));
        assert!(
            v.reasoning
                .contains("wrote kernel.sched_rt_runtime_us = -1"),
            "{}",
            v.reasoning
        );
        assert!(v.reasoning.contains("sysctl-allow"), "{}", v.reasoning);
        assert!(!v.reasoning.contains("refused it"), "{}", v.reasoning);
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

    /// Lot 280b (named): a new taint of code entering the kernel is a
    /// signed detection — Critical for an unsigned or forced module, High
    /// for an out-of-tree module or a livepatch — named by its flags, and
    /// never worded as a refusal.
    #[test]
    fn a_new_kernel_taint_is_critical_when_unsigned_or_forced() {
        use common::kernel_taint::{
            TAINT_FORCED_MODULE, TAINT_FORCED_RMMOD, TAINT_LIVEPATCH, TAINT_OOT_MODULE,
            TAINT_UNSIGNED_MODULE,
        };
        let taint = |new: u64, mask: u64| Event::FsProtectDenial {
            pid: 0,
            uid: 0,
            comm: "kernel".into(),
            target_dev: new,
            target_ino: mask,
            operation: FsProtectOperation::KernelTaint,
            timestamp_ns: 1,
        };
        for (new, sev) in [
            (TAINT_UNSIGNED_MODULE, Severity::Critical),
            (TAINT_FORCED_MODULE, Severity::Critical),
            (TAINT_FORCED_RMMOD, Severity::Critical),
            (TAINT_OOT_MODULE | TAINT_UNSIGNED_MODULE, Severity::Critical),
            (TAINT_OOT_MODULE, Severity::High),
            (TAINT_LIVEPATCH, Severity::High),
        ] {
            let v = NnLAt001AntiTamperDenial
                .evaluate(&taint(new, new | 1))
                .expect("verdict");
            assert_eq!(v.severity, sev, "{new:#x}");
            assert!(matches!(v.action, ResponseAction::Log));
            assert!(!v.reasoning.contains("refused it"), "{}", v.reasoning);
            assert!(v.reasoning.contains("Not refused"), "{}", v.reasoning);
        }
        let v = NnLAt001AntiTamperDenial
            .evaluate(&taint(
                TAINT_UNSIGNED_MODULE,
                TAINT_OOT_MODULE | TAINT_UNSIGNED_MODULE,
            ))
            .unwrap();
        assert!(
            v.reasoning.contains("gained E (E: an unsigned module)"),
            "{}",
            v.reasoning
        );
        assert!(
            v.reasoning.contains("mask now 12288: OE"),
            "{}",
            v.reasoning
        );
        let v = NnLAt001AntiTamperDenial
            .evaluate(&taint(TAINT_LIVEPATCH, TAINT_LIVEPATCH))
            .unwrap();
        assert!(v.reasoning.contains("K: a livepatch"), "{}", v.reasoning);
    }

    /// Lot 280b (named): the switches refused by name, and a foreign
    /// program on the root's slot signed as found, not refused.
    /// Lot 281 (named): code-injection access to an exempt process is at
    /// least High, Critical when the injector is not root or not an
    /// administrator's interactive session (unknown counts as unusual);
    /// signed as not refused, naming the exemption and the access.
    #[test]
    fn an_injection_into_an_exempt_process_is_high_or_critical() {
        assert_eq!(injection_severity(0, Some(true)), Severity::High);
        assert_eq!(injection_severity(0, Some(false)), Severity::Critical);
        assert_eq!(injection_severity(0, None), Severity::Critical);
        assert_eq!(injection_severity(1000, Some(true)), Severity::Critical);
        assert_eq!(injection_severity(1000, None), Severity::Critical);
        let ev = |uid, detail| Event::FsProtectDenial {
            pid: 4242,
            uid,
            comm: "gdb".into(),
            target_dev: detail,
            target_ino: 709,
            operation: FsProtectOperation::ExemptInjection,
            timestamp_ns: 1,
        };
        let attach = common::cgroup_join::inject_detail(0x12, Some(101));
        let v = exempt_injection(&ev(0, attach), "exe /usr/bin/x sha256 aa", Some(true))
            .expect("verdict");
        assert_eq!(v.severity, Severity::High);
        assert!(matches!(v.action, ResponseAction::Log));
        for needle in [
            "pid 709",
            "debugger's attach",
            "exe /usr/bin/x sha256 aa",
            "Not refused",
            "no longer holds",
        ] {
            assert!(v.reasoning.contains(needle), "{needle}: {}", v.reasoning);
        }
        assert!(!v.reasoning.contains("the kernel refused it"));
        let v = exempt_injection(&ev(1000, attach), "uid 998", Some(true)).unwrap();
        assert_eq!(v.severity, Severity::Critical);
        assert!(
            v.reasoning.contains("uid 1000, not root"),
            "{}",
            v.reasoning
        );
        let mem = common::cgroup_join::inject_detail(0x0a, Some(257));
        let v = exempt_injection(&ev(0, mem), "unit x.service", None).unwrap();
        assert_eq!(v.severity, Severity::Critical);
        assert!(v
            .reasoning
            .contains("a write handle on its /proc/<pid>/mem"));
        let w = common::cgroup_join::inject_detail(0x12, Some(311));
        assert!(exempt_injection(&ev(0, w), "e", None)
            .unwrap()
            .reasoning
            .contains("process_vm_writev"));
        // another operation is not this verdict
        assert!(exempt_injection(&denial(FsProtectOperation::Ptrace), "e", None).is_none());
        // the rule alone (no exemption context): severity by uid only
        let plain = NnLAt001AntiTamperDenial.evaluate(&ev(0, attach)).unwrap();
        assert_eq!(plain.severity, Severity::Critical);
        assert!(!plain.reasoning.contains("exempted it"));
    }

    #[test]
    fn the_blinding_switches_and_a_foreign_root_program_are_named() {
        let r = |op| {
            NnLAt001AntiTamperDenial
                .evaluate(&denial(op))
                .unwrap()
                .reasoning
        };
        let k = r(FsProtectOperation::Kprobes);
        assert!(
            k.contains("kprobes/enabled") && k.contains("refused it"),
            "{k}"
        );
        let l = r(FsProtectOperation::Lockdown);
        assert!(
            l.contains("security/lockdown") && l.contains("refused it"),
            "{l}"
        );
        let a = r(FsProtectOperation::SysctlRootAttach);
        assert!(a.contains("root cgroup") && a.contains("refused it"), "{a}");
        let p = r(FsProtectOperation::SysctlRootProg);
        assert!(p.contains("(id 709)") && p.contains("Not refused"), "{p}");
        assert!(!p.contains("refused it"), "{p}");
    }
}
