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
            // Lot 304: a known system program, its loader proven by the
            // kernel-state round (`nn_linux::known_system_prog`): Low.
            FsProtectOperation::SysctlRootProg
                if common::bpf_prog_class::root_prog_known_of(*target_dev).is_some() =>
            {
                return Some(known_root_program_verdict(
                    self, event, *pid, comm, *target_dev, *target_ino,
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
            // Lot 290: foreign BPF.
            FsProtectOperation::BpfHandle => {
                let object = match *target_dev {
                    1 => format!("map id {target_ino}"),
                    2 => format!("program id {target_ino}"),
                    _ => "object under its pin directories (/sys/fs/bpf/northnarrow*)".to_string(),
                };
                format!(
                    "to take a handle on the agent's own BPF {object} outside a trusted-installer \
                     window — a program is loaded against a map, or replaces a function of a \
                     program, only through a descriptor of it"
                )
            }
            // Lot 340: a known system program's feature probe, its loader
            // proven by the agent (`nn_linux::known_system_probe`): refused
            // all the same, Low.
            FsProtectOperation::BpfProgType
                if common::bpf_prog_class::known_probe_of(*target_dev, *target_ino).is_some() =>
            {
                return Some(known_probe_verdict(
                    self, event, *pid, comm, *target_dev, *target_ino,
                ));
            }
            // Lot 345 (the re-check of #550, N2 and point 1 (ii)): the
            // content refused a load the type alone would let through (a
            // signed per-loader opt-out names its loader and type)
            FsProtectOperation::BpfProgType
                if common::bpf_prog_class::content_refusal(*target_dev).is_some() =>
            {
                content_refusal_text(*target_dev, *target_ino)
            }
            FsProtectOperation::BpfProgType => {
                let t = u32::try_from(*target_ino).unwrap_or(u32::MAX);
                format!(
                    "to load a `{}` BPF program (program type {target_ino}) outside a \
                     trusted-installer window — a type that can rewrite a process's memory \
                     (bpf_probe_write_user), override a kernel function's return, signal a \
                     process or take a hook's place; the signed per-rule policy's \
                     `bpf-loader-allow` names the loaders allowed one",
                    common::bpf_prog_class::prog_type_name(t)
                )
            }
            FsProtectOperation::BpfProgOptOut => {
                let t = u32::try_from(*target_ino).unwrap_or(u32::MAX);
                let reasoning = format!(
                    "`{comm}` loaded a `{}` BPF program, a type refused outside a \
                     trusted-installer window; the signed per-rule policy's `bpf-loader-allow` \
                     names its executable and that type (not refused, recorded).",
                    common::bpf_prog_class::prog_type_name(t)
                );
                return Some(build_verdict(
                    self,
                    event,
                    ResponseAction::Log,
                    Severity::Low,
                    &reasoning,
                ));
            }
            FsProtectOperation::BpfUnseen | FsProtectOperation::BpfBaseline => {
                // Lot 304: a baseline program proven a known system
                // program (its loader the record's pid and uid): Low.
                if let Some(v) = known_baseline_verdict(
                    self, event, *operation, *pid, comm, *target_dev, *target_ino,
                ) {
                    return Some(v);
                }
                return Some(crossview_verdict(self, event, *operation, comm, *target_dev, *target_ino));
            }
            // Lot 293 (external bug hunt BUG14): the kernel delivers it
            // without `task_kill`; the process named is the one whose I/O
            // raised it, which may not be the one that armed the file.
            FsProtectOperation::Sigio => {
                let reasoning = format!(
                    "Signal {target_dev} to protected pid {target_ino} through a file's owner \
                     (F_SETOWN / F_SETOWN_EX / FIOSETOWN with O_ASYNC or F_SETSIG: SIGIO, \
                     SIGURG, a lease or dnotify signal) — a path to kill the agent that no \
                     `kill` takes; the kernel refused it. Raised by the I/O of `{comm}` (pid \
                     {pid}), which is not necessarily the process that armed the file: a \
                     socket's data arrives in whatever process the kernel interrupted. The \
                     armed descriptor is one whose owner is pid {target_ino} (`fdinfo` flags \
                     with O_ASYNC, 020000)."
                );
                return Some(build_verdict(
                    self,
                    event,
                    ResponseAction::Log,
                    Severity::High,
                    &reasoning,
                ));
            }
            // Lot 349 (pre-alpha R001): not refused — the agent's own CPU
            // watch (`nn_linux::own_cpus`), read by the kernel-state round.
            FsProtectOperation::CpuConfined => {
                return Some(cpu_confined_verdict(self, event, comm, *target_dev, *target_ino));
            }
            // Lot 349 (the review of #558, F1): a window's load of a program
            // the content judge refuses outside one — let through, held.
            FsProtectOperation::BpfHeldLoad => {
                let reasoning = format!(
                    "`{comm}` loaded, inside a trusted-installer window, {} (program id \
                     {target_ino}) — let through, as the window promises, and held: every run, \
                     attach or handle of it outside a window, by any caller outside the agent's \
                     family and through any descriptor, is refused and signed. A link attached \
                     inside the window keeps running it: check `bpftool link` for program id \
                     {target_ino}.",
                    held_program_text(*target_dev)
                );
                return Some(build_verdict(
                    self,
                    event,
                    ResponseAction::Log,
                    Severity::High,
                    &reasoning,
                ));
            }
            FsProtectOperation::BpfHeldUse => held_use_text(*target_dev, *target_ino),
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

/// Lot 349 (pre-alpha R001): the agent runs on fewer CPUs than it should —
/// High, not a refusal (nothing was asked of a hook: a sibling partition
/// takes the CPUs of every cgroup of its parent). `target_dev` the cause and
/// the counts (`common::wire::cpu_confined_of`), `target_ino` the mask of
/// the CPUs left below 64, `comm` what the cause names.
fn cpu_confined_verdict(
    rule: &NnLAt001AntiTamperDenial,
    event: &Event,
    comm: &str,
    target_dev: u64,
    target_ino: u64,
) -> Verdict {
    use common::wire::{
        cpu_confined_of, CPU_CAUSE_AFFINITY, CPU_CAUSE_CGROUP_CPUSET, CPU_CAUSE_CGROUP_MOVE,
        CPU_CAUSE_PARTITION,
    };
    let (cause, left, expected, threads) = cpu_confined_of(target_dev);
    let why = match cause {
        CPU_CAUSE_PARTITION => format!(
            "a cgroup in cpuset.cpus.partition root or isolated (`{comm}`) took them from every \
             other cgroup of its parent — the agent's among them; no hook is asked"
        ),
        CPU_CAUSE_CGROUP_CPUSET => format!(
            "its own cgroup's cpuset.cpus was narrowed (`{comm}`; its floor is its parent's CPUs)"
        ),
        CPU_CAUSE_AFFINITY => format!(
            "the CPU affinity of {threads} of its threads was narrowed (`{comm}` among them)"
        ),
        CPU_CAUSE_CGROUP_MOVE => format!("it was moved to another cgroup (`{comm}`)"),
        _ => format!("cause {cause} (`{comm}`)"),
    };
    let cpus: Vec<String> = (0..64u32)
        .filter(|c| target_ino & (1u64 << c) != 0)
        .map(|c| c.to_string())
        .collect();
    let reasoning = format!(
        "The agent may run on {left} of the {expected} CPUs it should (CPUs {}{}): {why}. \
         Confined to one busy CPU its sensors' rings overflow and its responses come late. Not \
         refused — the agent's own CPU watch, read every 5 s; `nn-admin status` shows it \
         (degradation `own_cpus`) while it holds.",
        if cpus.is_empty() {
            "none below 64".to_string()
        } else {
            cpus.join(",")
        },
        if left > 64 { ", those below 64" } else { "" }
    );
    build_verdict(rule, event, ResponseAction::Log, Severity::High, &reasoning)
}

/// Lot 345 (the re-check of #550, N2 and point 1 (ii)): the reason of a
/// load the content refused (`target_dev` a `bpf_prog_class::CONTENT_*`
/// code, `target_ino` the program type — 0 when the verifier's lockdown
/// question refused it, before the type is known).
/// Lot 349 (the review of #558, F1): a held program as a record names it —
/// its type and what its content does (`common::wire::bpf_held_of`).
fn held_program_text(target_dev: u64) -> String {
    use common::bpf_prog_class::{call_target_name, content_refusal, prog_type_name, ContentRefusal};
    let (_, why, ty) = common::wire::bpf_held_of(target_dev);
    let program = if ty != 0 {
        format!("a `{}` BPF program", prog_type_name(ty))
    } else {
        "a BPF program".to_string()
    };
    match content_refusal(u64::from(why)) {
        Some(ContentRefusal::Call(n)) => format!(
            "{program} that calls {} (it kills the agent past its task_kill hook, rewrites a \
             process's memory or overrides a kernel function's return)",
            call_target_name(n)
        ),
        _ => format!(
            "{program} whose instructions the judge could not read whole (refused outside a \
             window as if it called a helper that kills or blinds the agent)"
        ),
    }
}

/// Lot 349 (the review of #558, F1): a refused use of a held program, or a
/// window's load that the held set had no room for.
fn held_use_text(target_dev: u64, target_ino: u64) -> String {
    let (how, _, _) = common::wire::bpf_held_of(target_dev);
    let program = held_program_text(target_dev);
    if how == common::wire::BPF_HELD_FULL {
        return format!(
            "to load, inside a trusted-installer window, {program} (program id {target_ino}) \
             while the agent's held set is full — refused (fail closed: a load the agent cannot \
             hold could be run after the window unrefused)"
        );
    }
    let using = match how {
        common::wire::BPF_HELD_SET_BPF => {
            "attach it to a perf event (ioctl PERF_EVENT_IOC_SET_BPF: a kprobe, a tracepoint)"
                .to_string()
        }
        c => format!(
            "{} it",
            match c {
                common::bpf_cmd::BPF_PROG_TEST_RUN => "run (BPF_PROG_RUN)",
                common::bpf_cmd::BPF_PROG_ATTACH => "attach (BPF_PROG_ATTACH)",
                common::bpf_cmd::BPF_RAW_TRACEPOINT_OPEN => "attach (BPF_RAW_TRACEPOINT_OPEN)",
                common::bpf_cmd::BPF_LINK_CREATE => "attach (BPF_LINK_CREATE)",
                common::bpf_cmd::BPF_LINK_UPDATE => "swap a link onto (BPF_LINK_UPDATE)",
                common::bpf_cmd::BPF_MAP_UPDATE_ELEM => {
                    "put in a tail call's slot (a prog array's BPF_MAP_UPDATE_ELEM)"
                }
                _ => "use",
            }
        ),
    };
    format!(
        "to {using}: {program}, program id {target_ino}, loaded inside a trusted-installer \
         window and held since — refused outside a window to every caller outside the agent's \
         family, through any descriptor (the loader's own, one passed or taken with pidfd_getfd)"
    )
}

fn content_refusal_text(target_dev: u64, target_ino: u64) -> String {
    use common::bpf_prog_class::{
        call_target_name, content_refusal, prog_type_name, ContentRefusal,
    };
    let program = match u32::try_from(target_ino) {
        Ok(t) if t != 0 => format!("a `{}` BPF program", prog_type_name(t)),
        _ => "a BPF program".to_string(),
    };
    let what = match content_refusal(target_dev) {
        Some(ContentRefusal::FmodRet) => {
            "attached as fmod_ret (BPF_MODIFY_RETURN): it overrides the \
             return of the function it is attached to, any security_* hook's (security_file_open \
             failing for the agent blinds it)"
                .to_string()
        }
        Some(ContentRefusal::Call(n)) => format!(
            "that calls {}: it kills the agent past its task_kill hook, rewrites a process's \
             memory or overrides a kernel function's return",
            call_target_name(n)
        ),
        _ => "whose instructions could not be read whole (longer than the judge reads, or a \
             failed read): refused as if it called a helper that kills or blinds the agent"
            .to_string(),
    };
    format!(
        "to load {program} {what} (or to take a handle on one) — refused to every loader outside \
         the agent's family and a trusted-installer window, even one the signed per-rule policy's \
         `bpf-loader-allow` names"
    )
}

/// Lot 340: a known system program's feature probe
/// ([`common::bpf_prog_class::KNOWN_SYSTEM_PROBES`]) — refused by the `bpf`
/// hook as every load of its type outside a window, recorded Low with the
/// proof the agent read at the record: the loader runs the packaged file
/// (its device and inode).
fn known_probe_verdict(
    rule: &NnLAt001AntiTamperDenial,
    event: &Event,
    pid: u32,
    comm: &str,
    target_dev: u64,
    prog_type: u64,
) -> Verdict {
    use common::bpf_prog_class::{known_probe_of, prog_type_name, KNOWN_SYSTEM_PROBES};
    let k = KNOWN_SYSTEM_PROBES[known_probe_of(target_dev, prog_type).unwrap_or(0)];
    let reasoning = format!(
        "A known system program's BPF load, refused: `{comm}` (pid {pid}) loaded a `{}` \
         BPF program (program type {prog_type}), a type the agent's bpf hook refuses outside a \
         trusted-installer window — {}. The loader proven: it runs the packaged {} (its device \
         and inode, read by the agent at the record). A probe learns whether the kernel \
         supports the type and attaches nothing; the refusal stands, recorded Low, and \
         raises no posture (never a corroborating signal).",
        prog_type_name(u32::try_from(prog_type).unwrap_or(u32::MAX)),
        k.what,
        k.loader
    );
    build_verdict(rule, event, ResponseAction::Log, Severity::Low, &reasoning)
}

/// Lot 304: a known system program on the root cgroup's `cgroup/sysctl`
/// slot — Low, with the proof the kernel-state round established (the
/// loader's uid is the record's principal, not repeated here).
fn known_root_program_verdict(
    rule: &NnLAt001AntiTamperDenial,
    event: &Event,
    pid: u32,
    comm: &str,
    target_dev: u64,
    id: u64,
) -> Verdict {
    use common::bpf_prog_class::{root_prog_known_of, KNOWN_SYSTEM_PROGRAMS};
    let (entry, seen, link) = root_prog_known_of(target_dev).unwrap_or((0, false, 0));
    let k = KNOWN_SYSTEM_PROGRAMS[entry];
    let when = if seen {
        "the agent's `bpf` hook saw that process load it, and its attach to the root was \
         let through, as the hook does only inside a trusted-installer window"
    } else {
        "it was loaded before the agent started"
    };
    let reasoning = format!(
        "A known system program on the root cgroup's cgroup/sysctl slot: `{}` (id {id}), {}. \
         The loader proven: pid {pid} (`{comm}`, the record's principal) holds its link to the \
         root cgroup (link id {link}), runs the packaged {} (its device and inode), and was \
         running when the program was loaded; {when}. Not refused; the same program from any \
         other loader is High.",
        k.name, k.what, k.loader
    );
    build_verdict(rule, event, ResponseAction::Log, Severity::Low, &reasoning)
}

/// Lot 290: the severity of a cross-view finding — High for an object the
/// `bpf` hook never saw loading after the start; for one present at the
/// start (the baseline, loaded while the agent was not running), High when
/// it is of a type refused outside a window (kprobe, tracepoint,
/// perf_event, raw_tracepoint, raw_tracepoint_writable, tracing,
/// struct_ops, extension, LSM), Low otherwise (systemd's and the container
/// runtimes' cgroup programs).
pub fn crossview_severity(
    operation: FsProtectOperation,
    is_link: bool,
    early: bool,
    object_type: u32,
) -> Severity {
    match operation {
        FsProtectOperation::BpfBaseline
            if is_link || early || !common::bpf_prog_class::denied_by_default(object_type) =>
        {
            Severity::Low
        }
        _ => Severity::High,
    }
}

/// Lot 304: a cross-view baseline program the kernel-state round proved a
/// known system program (`CROSSVIEW_KNOWN_BIT`; the entry told again here by
/// the record's name, type and attach point) — Low, with the proof. `None`
/// for any other record: an unseen one, a link, one without the bit, one
/// whose traits name no entry.
#[allow(clippy::too_many_arguments)]
fn known_baseline_verdict(
    rule: &NnLAt001AntiTamperDenial,
    event: &Event,
    operation: FsProtectOperation,
    pid: u32,
    comm: &str,
    target_dev: u64,
    target_ino: u64,
) -> Option<Verdict> {
    use common::bpf_prog_class as c;
    if operation != FsProtectOperation::BpfBaseline || target_ino & c::CROSSVIEW_KNOWN_BIT == 0 {
        return None;
    }
    let (is_link, _, t, id) = c::crossview_of(target_ino);
    let (name, attach) = c::object_of_comm(comm);
    let entry = [c::KnownLink::Lsm, c::KnownLink::RootCgroupSysctl]
        .into_iter()
        .find_map(|link| c::known_system_program(name, t, attach, link))
        .filter(|_| !is_link)?;
    let k = c::KNOWN_SYSTEM_PROGRAMS[entry];
    let reasoning = format!(
        "A known system program: BPF program id {id} `{name}` (type `{}`, tag {}, attached at \
         {attach}), {}. The loader proven: pid {pid} (the record's principal) holds its link, runs the \
         packaged {} (its device and inode), and was running when the program was loaded, \
         before the agent started — the cross-view's baseline, signed once. Not refused; the \
         same program from any other loader is signed as before.",
        c::prog_type_name(t),
        c::tag_hex(target_dev),
        k.what,
        k.loader
    );
    Some(build_verdict(
        rule,
        event,
        ResponseAction::Log,
        Severity::Low,
        &reasoning,
    ))
}

/// Lot 290: a cross-view finding's verdict (NN-L-AT-001, not a refusal).
fn crossview_verdict(
    rule: &NnLAt001AntiTamperDenial,
    event: &Event,
    operation: FsProtectOperation,
    comm: &str,
    target_dev: u64,
    target_ino: u64,
) -> Verdict {
    use common::bpf_prog_class as c;
    let (is_link, early, t, id) = c::crossview_of(target_ino);
    let (name, attach) = c::object_of_comm(comm);
    let what = if is_link {
        format!(
            "BPF link id {id} (link type `{}`, {attach})",
            c::link_type_name(t)
        )
    } else {
        format!(
            "BPF program id {id} `{name}` (type `{}`, tag {}, attached at {attach})",
            c::prog_type_name(t),
            c::tag_hex(target_dev)
        )
    };
    let reasoning = if operation == FsProtectOperation::BpfUnseen {
        format!(
            "The {what} is loaded and the agent's `bpf` hook never saw it load since the agent \
             started: it was loaded through a path the hook does not see, or is hidden from it — \
             the shape of a BPF rootkit. Found by the cross-view (the agent's own enumeration of \
             the kernel's programs and links every 5 s); not refused."
        )
    } else if early {
        format!(
            "The {what} was loaded by the kernel itself before user space started (its load \
             time before PID 1's start): the kernel's own program, the cross-view's baseline, \
             signed once. Not refused."
        )
    } else {
        format!(
            "The {what} was loaded while the agent was not running (present at its start): \
             the cross-view's baseline, signed once. Not refused{}.",
            if crossview_severity(operation, is_link, early, t) == Severity::High {
                "; its type is one the agent refuses outside a trusted-installer window"
            } else {
                ""
            }
        )
    };
    build_verdict(
        rule,
        event,
        ResponseAction::Log,
        crossview_severity(operation, is_link, early, t),
        &reasoning,
    )
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
    // Not the uid's number: the record's principal carries it.
    let who = if uid != 0 {
        "not root".to_string()
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
            FsProtectOperation::Sigio,
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

    /// Lot 293 (external bug hunt BUG14): a refused SIGIO-path signal is
    /// signed with the signal, the target and the process whose I/O raised
    /// it — named as such, not as the one that armed the file — and never
    /// as a relayed `systemctl` when that process is PID 1 (a softirq can
    /// interrupt it).
    #[test]
    fn a_refused_sigio_names_the_path_and_not_an_arming_process() {
        let v = NnLAt001AntiTamperDenial
            .evaluate(&denial(FsProtectOperation::Sigio))
            .expect("verdict");
        assert!(
            v.reasoning
                .contains("Signal 9 to protected pid 709 through a file's owner"),
            "{}",
            v.reasoning
        );
        assert!(v
            .reasoning
            .contains("Raised by the I/O of `bash` (pid 4242)"));
        assert!(v
            .reasoning
            .contains("not necessarily the process that armed the file"));
        let mut e = denial(FsProtectOperation::Sigio);
        if let Event::FsProtectDenial { pid, .. } = &mut e {
            *pid = 1;
        }
        let v = NnLAt001AntiTamperDenial.evaluate(&e).unwrap();
        assert!(!v.reasoning.contains("systemctl"), "{}", v.reasoning);
        assert!(v.reasoning.contains("through a file's owner"));
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

    /// Lot 349 (pre-alpha R001, named): the agent confined to fewer CPUs is
    /// a signed High detection naming the cause and the CPUs left, never
    /// worded as a refusal.
    #[test]
    fn the_agent_confined_to_fewer_cpus_is_high_and_names_the_cause() {
        use common::wire::{
            cpu_confined_dev, CPU_CAUSE_AFFINITY, CPU_CAUSE_CGROUP_CPUSET, CPU_CAUSE_CGROUP_MOVE,
            CPU_CAUSE_PARTITION,
        };
        let confined = |dev: u64, mask: u64, comm: &str| Event::FsProtectDenial {
            pid: 0,
            uid: 0,
            comm: comm.into(),
            target_dev: dev,
            target_ino: mask,
            operation: FsProtectOperation::CpuConfined,
            timestamp_ns: 1,
        };
        for (cause, comm, says) in [
            (
                CPU_CAUSE_PARTITION,
                "/k349part",
                "cpuset.cpus.partition root or isolated (`/k349part`)",
            ),
            (
                CPU_CAUSE_CGROUP_CPUSET,
                "/northnarrow.slice/northnarrow-agent.service",
                "own cgroup's cpuset.cpus",
            ),
            (CPU_CAUSE_AFFINITY, "tid 7", "affinity of 2 of its threads"),
            (
                CPU_CAUSE_CGROUP_MOVE,
                "/pen",
                "moved to another cgroup (`/pen`)",
            ),
        ] {
            let v = NnLAt001AntiTamperDenial
                .evaluate(&confined(cpu_confined_dev(cause, 1, 4, 2), 0b1, comm))
                .expect("verdict");
            assert_eq!(v.severity, Severity::High, "{cause}");
            assert!(matches!(v.action, ResponseAction::Log));
            assert!(
                v.reasoning
                    .contains("may run on 1 of the 4 CPUs it should (CPUs 0)"),
                "{}",
                v.reasoning
            );
            assert!(v.reasoning.contains(says), "{}", v.reasoning);
            assert!(v.reasoning.contains("Not refused"), "{}", v.reasoning);
            assert!(!v.reasoning.contains("refused it"), "{}", v.reasoning);
        }
        let v = NnLAt001AntiTamperDenial
            .evaluate(&confined(
                cpu_confined_dev(CPU_CAUSE_PARTITION, 2, 96, 0),
                0b1010,
                "/p",
            ))
            .unwrap();
        assert!(v.reasoning.contains("(CPUs 1,3)"), "{}", v.reasoning);
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
        let v = exempt_injection(&ev(1000, attach), "unit y.service", Some(true)).unwrap();
        assert_eq!(v.severity, Severity::Critical);
        assert!(v.reasoning.contains("(not root)"));
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

    /// Lot 304 (named): a root program the kernel-state round proved a
    /// known system program is Low, named with its loader's proof — the
    /// program, the loader's pid, name and uid, the link, the packaged
    /// executable, when it was loaded; the same operation without the proof
    /// (0), or with a proof naming no entry of the table, stays High.
    #[test]
    fn a_known_root_program_is_low_with_its_proof_and_any_other_high() {
        use common::bpf_prog_class::{root_prog_known_dev, ROOT_PROG_KNOWN_BIT};
        let ev = |pid, uid, comm: &str, dev| Event::FsProtectDenial {
            pid,
            uid,
            comm: comm.into(),
            target_dev: dev,
            target_ino: 35,
            operation: FsProtectOperation::SysctlRootProg,
            timestamp_ns: 1,
        };
        let v = NnLAt001AntiTamperDenial
            .evaluate(&ev(
                631,
                998,
                "systemd-network",
                root_prog_known_dev(0, false, 3),
            ))
            .unwrap();
        assert_eq!(v.severity, Severity::Low);
        assert_eq!(v.action, ResponseAction::Log);
        for want in [
            "known system program",
            "`sysctl_monitor` (id 35)",
            "systemd-networkd's sysctl monitor",
            "pid 631 (`systemd-network`, the record's principal)",
            "(link id 3)",
            "the packaged /usr/lib/systemd/systemd-networkd",
            "loaded before the agent started",
            "Not refused",
        ] {
            assert!(v.reasoning.contains(want), "{want}: {}", v.reasoning);
        }
        let v = NnLAt001AntiTamperDenial
            .evaluate(&ev(
                2001,
                998,
                "systemd-network",
                root_prog_known_dev(0, true, 9),
            ))
            .unwrap();
        assert_eq!(v.severity, Severity::Low);
        assert!(
            v.reasoning.contains("saw that process load it")
                && v.reasoning.contains("inside a trusted-installer window")
                && v.reasoning.contains("(link id 9)"),
            "{}",
            v.reasoning
        );
        // no proof, or a proof of no entry: High, as a program not ours
        for dev in [0, ROOT_PROG_KNOWN_BIT | (7 << 32) | 3, 1 << 62] {
            let v = NnLAt001AntiTamperDenial
                .evaluate(&ev(631, 998, "systemd-network", dev))
                .unwrap();
            assert_eq!(v.severity, Severity::High, "{dev:#x}");
            assert!(
                v.reasoning.contains("not the agent's (id 35)"),
                "{}",
                v.reasoning
            );
        }
    }

    /// Lot 304 (named): a baseline LSM program proven a known system
    /// program (PID 1's `restrict_filesystems`) is Low with its loader's
    /// proof; without the bit, as an unseen program, as a link, or with
    /// traits that name no entry, it is weighed as before (High for an LSM
    /// program).
    #[test]
    fn a_known_baseline_program_is_low_and_any_other_weighed_as_before() {
        use common::bpf_prog_class::{crossview_ino, object_comm, CROSSVIEW_KNOWN_BIT};
        let ev = |op, pid, comm: &str, ino| Event::FsProtectDenial {
            pid,
            uid: 0,
            comm: comm.into(),
            target_dev: 0xe8932b6bae2b9745,
            target_ino: ino,
            operation: op,
            timestamp_ns: 1,
        };
        let rfs = object_comm("restrict_filesy", "bpf_lsm_file_open");
        let known = crossview_ino(false, false, 29, 21) | CROSSVIEW_KNOWN_BIT;
        let v = NnLAt001AntiTamperDenial
            .evaluate(&ev(FsProtectOperation::BpfBaseline, 1, &rfs, known))
            .unwrap();
        assert_eq!(v.severity, Severity::Low);
        for want in [
            "A known system program: BPF program id 21 `restrict_filesy`",
            "tag e8932b6bae2b9745",
            "systemd's RestrictFileSystems=",
            "pid 1 (the record's principal) holds its link",
            "the packaged /usr/lib/systemd/systemd",
            "before the agent started",
        ] {
            assert!(v.reasoning.contains(want), "{want}: {}", v.reasoning);
        }
        // systemd-networkd's program, as a baseline record
        let mon = object_comm("sysctl_monitor", "cgroup");
        let v = NnLAt001AntiTamperDenial
            .evaluate(&ev(
                FsProtectOperation::BpfBaseline,
                631,
                &mon,
                crossview_ino(false, false, 23, 35) | CROSSVIEW_KNOWN_BIT,
            ))
            .unwrap();
        assert!(
            v.reasoning.contains("systemd-networkd's sysctl monitor"),
            "{}",
            v.reasoning
        );
        let high = |op, comm: &str, ino| {
            let v = NnLAt001AntiTamperDenial
                .evaluate(&ev(op, 1, comm, ino))
                .unwrap();
            assert_eq!(
                v.severity,
                Severity::High,
                "{comm} {ino:#x}: {}",
                v.reasoning
            );
            assert!(
                !v.reasoning.contains("known system program"),
                "{}",
                v.reasoning
            );
        };
        // no bit
        high(
            FsProtectOperation::BpfBaseline,
            &rfs,
            crossview_ino(false, false, 29, 21),
        );
        // unseen, with the bit
        high(FsProtectOperation::BpfUnseen, &rfs, known);
        // another attach point, another name, another type
        high(
            FsProtectOperation::BpfBaseline,
            &object_comm("restrict_filesy", "bpf_lsm_bprm_check_security"),
            known,
        );
        high(
            FsProtectOperation::BpfBaseline,
            &object_comm("rootkit", "bpf_lsm_file_open"),
            known,
        );
        high(
            FsProtectOperation::BpfBaseline,
            &rfs,
            crossview_ino(false, false, 26, 21) | CROSSVIEW_KNOWN_BIT,
        );
        // a link record with the bit is no known program (a link of a
        // refused type stays as lot 290 weighs it: Low, never "known")
        let v = NnLAt001AntiTamperDenial
            .evaluate(&ev(
                FsProtectOperation::BpfBaseline,
                1,
                &rfs,
                crossview_ino(true, false, 29, 21) | CROSSVIEW_KNOWN_BIT,
            ))
            .unwrap();
        assert!(
            !v.reasoning.contains("known system program"),
            "{}",
            v.reasoning
        );
    }

    /// Named test (lot 340, the alpha's daily false positives): on Ubuntu
    /// 26.04 the user manager's `tracepoint` probe at the first login and
    /// networkd's `kprobe` probe at its start were refused and signed High
    /// at every boot. A record the agent proved a known system probe's
    /// (`target_dev`: the bit and the entry) is Low, still a refusal; the
    /// kernel's record (0), a stray marker, the entry's marker on another
    /// program type, and any other loader keep High.
    #[test]
    fn a_proven_known_system_probe_is_low_and_every_other_load_keeps_high() {
        use common::bpf_prog_class::{
            known_probe_dev, KNOWN_PROBE_BIT, PROG_TYPE_KPROBE, PROG_TYPE_LSM, PROG_TYPE_TRACEPOINT,
        };
        let ev = |comm: &str, dev, ty: u32| Event::FsProtectDenial {
            pid: 868,
            uid: 998,
            comm: comm.into(),
            target_dev: dev,
            target_ino: u64::from(ty),
            operation: FsProtectOperation::BpfProgType,
            timestamp_ns: 1,
        };
        let v = |e| NnLAt001AntiTamperDenial.evaluate(&e).expect("verdict");
        for (comm, entry, ty, loader) in [
            (
                "systemd",
                0u16,
                PROG_TYPE_TRACEPOINT,
                "/usr/lib/systemd/systemd",
            ),
            (
                "systemd-network",
                1,
                PROG_TYPE_KPROBE,
                "/usr/lib/systemd/systemd-networkd",
            ),
        ] {
            let k = v(ev(comm, known_probe_dev(entry), ty));
            assert_eq!(
                (k.action.clone(), k.severity),
                (ResponseAction::Log, Severity::Low)
            );
            for part in ["BPF load, refused", loader, "device and inode"] {
                assert!(k.reasoning.contains(part), "{part}: {}", k.reasoning);
            }
            for dev in [0, KNOWN_PROBE_BIT | 9, known_probe_dev(entry) | (1 << 20)] {
                let h = v(ev(comm, dev, ty));
                assert_eq!(h.severity, Severity::High, "dev {dev:#x}");
                assert!(h.reasoning.contains("refused it"), "{}", h.reasoning);
            }
            let h = v(ev(comm, known_probe_dev(entry), PROG_TYPE_LSM));
            assert_eq!(h.severity, Severity::High);
        }
        let h = v(ev("python3", 0, PROG_TYPE_KPROBE));
        assert_eq!(h.severity, Severity::High);
    }

    /// Lot 345 (named; the re-check of #550, N2 and point 1 (ii)): a load
    /// the content refused — an fmod_ret, a forbidden helper's or kfunc's
    /// call, an unreadable program — is named for what it is, High, and
    /// says the opt-out does not cover it; the type's own refusal keeps its
    /// text.
    #[test]
    fn a_content_refusal_is_named_and_high() {
        use common::bpf_prog_class::{
            CONTENT_CALL, CONTENT_FMOD_RET, CONTENT_UNJUDGED, PROG_TYPE_KPROBE, PROG_TYPE_TRACING,
        };
        let ev = |dev: u8, ino: u32| Event::FsProtectDenial {
            pid: 4242,
            uid: 0,
            comm: "python3".into(),
            target_dev: dev as u64,
            target_ino: ino as u64,
            operation: FsProtectOperation::BpfProgType,
            timestamp_ns: 1,
        };
        let v = |e| NnLAt001AntiTamperDenial.evaluate(&e).expect("verdict");
        for (dev, ty, parts) in [
            (
                CONTENT_FMOD_RET,
                PROG_TYPE_TRACING,
                &["`tracing` BPF program", "fmod_ret", "security_file_open"][..],
            ),
            (
                CONTENT_CALL + 2,
                PROG_TYPE_KPROBE,
                &["`kprobe`", "calls bpf_send_signal:"][..],
            ),
            (
                CONTENT_CALL + 3,
                PROG_TYPE_KPROBE,
                &["calls bpf_send_signal_thread"][..],
            ),
            (
                CONTENT_CALL + 1,
                PROG_TYPE_KPROBE,
                &["calls bpf_override_return"][..],
            ),
            (
                CONTENT_CALL,
                0,
                &["load a BPF program that calls bpf_probe_write_user"][..],
            ),
            (
                CONTENT_CALL + 4,
                PROG_TYPE_TRACING,
                &["calls bpf_send_signal_task"][..],
            ),
            (
                CONTENT_UNJUDGED,
                PROG_TYPE_KPROBE,
                &["could not be read whole"][..],
            ),
        ] {
            let h = v(ev(dev, ty));
            assert_eq!(h.severity, Severity::High, "{dev}");
            for part in parts
                .iter()
                .chain(&["even one the signed per-rule policy's `bpf-loader-allow` names"])
            {
                assert!(h.reasoning.contains(part), "{part}: {}", h.reasoning);
            }
        }
        let t = v(ev(0, PROG_TYPE_KPROBE));
        assert!(
            t.reasoning.contains("a type that can rewrite"),
            "{}",
            t.reasoning
        );
    }

    /// Lot 349 (the review of #558, F1): a window's held load is High and
    /// not refused, naming the call and the id; each refused use names
    /// itself (the run, the perf attach, the tail-call slot) and the call;
    /// a load the full held set refuses says so.
    #[test]
    fn a_held_program_s_load_and_uses_are_named_and_high() {
        use common::bpf_prog_class::CONTENT_CALL;
        use common::wire::{bpf_held_dev, BPF_HELD_FULL, BPF_HELD_SET_BPF};
        let ev = |op, dev, ino| Event::FsProtectDenial {
            pid: 4242,
            uid: 0,
            comm: "loader".into(),
            target_dev: dev,
            target_ino: ino,
            operation: op,
            timestamp_ns: 1,
        };
        let v = |e| NnLAt001AntiTamperDenial.evaluate(&e).expect("verdict");
        // slot 2: bpf_send_signal; type 2: kprobe
        let verdict = (u64::from(CONTENT_CALL + 2) << 32) | 2;
        let l = v(ev(FsProtectOperation::BpfHeldLoad, bpf_held_dev(0, verdict), 77));
        assert_eq!(l.severity, Severity::High);
        for n in ["inside a trusted-installer window", "program id 77", "`kprobe`", "bpf_send_signal", "held"] {
            assert!(l.reasoning.contains(n), "{n}: {}", l.reasoning);
        }
        assert!(!l.reasoning.contains("refused it"), "{}", l.reasoning);
        for (how, named) in [
            (u32::from(10u8), "run (BPF_PROG_RUN)"),
            (BPF_HELD_SET_BPF, "PERF_EVENT_IOC_SET_BPF"),
            (28, "BPF_LINK_CREATE"),
            (2, "tail call"),
        ] {
            let u = v(ev(FsProtectOperation::BpfHeldUse, bpf_held_dev(how, verdict), 77));
            assert_eq!(u.severity, Severity::High);
            for n in [named, "program id 77", "bpf_send_signal", "refused it", "pidfd_getfd"] {
                assert!(u.reasoning.contains(n), "{how} {n}: {}", u.reasoning);
            }
        }
        let f = v(ev(FsProtectOperation::BpfHeldUse, bpf_held_dev(BPF_HELD_FULL, verdict), 78));
        assert!(f.reasoning.contains("held set is full") && f.reasoning.contains("fail closed"), "{}", f.reasoning);
    }

    /// Lot 290 (named): the foreign-BPF refusals are named and High; a load
    /// the signed opt-out let through is Low and not refused; the
    /// cross-view's unseen object is High with its type, name, tag and
    /// attach point; the start's baseline is Low, High for a refused type.
    #[test]
    fn foreign_bpf_is_named_and_weighed() {
        use common::bpf_prog_class::{crossview_ino, object_comm, tag_word};
        let ev = |op, comm: &str, dev, ino| Event::FsProtectDenial {
            pid: 4242,
            uid: 0,
            comm: comm.into(),
            target_dev: dev,
            target_ino: ino,
            operation: op,
            timestamp_ns: 1,
        };
        let v = |e| NnLAt001AntiTamperDenial.evaluate(&e).expect("verdict");
        let h = v(ev(FsProtectOperation::BpfHandle, "bpftool", 1, 31));
        assert_eq!(h.severity, Severity::High);
        assert!(
            h.reasoning.contains("map id 31") && h.reasoning.contains("refused it"),
            "{}",
            h.reasoning
        );
        let h = v(ev(FsProtectOperation::BpfHandle, "bpftool", 2, 32));
        assert!(h.reasoning.contains("program id 32"), "{}", h.reasoning);
        let h = v(ev(FsProtectOperation::BpfHandle, "bpftool", 0, 0));
        assert!(
            h.reasoning.contains("/sys/fs/bpf/northnarrow*"),
            "{}",
            h.reasoning
        );
        let t = v(ev(FsProtectOperation::BpfProgType, "bpftrace", 0, 2));
        assert_eq!(t.severity, Severity::High);
        assert!(
            t.reasoning.contains("`kprobe` BPF program")
                && t.reasoning.contains("bpf-loader-allow")
                && t.reasoning.contains("refused it"),
            "{}",
            t.reasoning
        );
        let o = v(ev(FsProtectOperation::BpfProgOptOut, "bpftrace", 0, 26));
        assert_eq!(o.severity, Severity::Low);
        assert!(
            o.reasoning.contains("`tracing`") && !o.reasoning.contains("refused it"),
            "{}",
            o.reasoning
        );
        let tag = tag_word([0xab, 0xcd, 0, 0, 0, 0, 0, 1]);
        let u = v(ev(
            FsProtectOperation::BpfUnseen,
            &object_comm("hide_me", "bpf_lsm_file_open"),
            tag,
            crossview_ino(false, false, 29, 812),
        ));
        assert_eq!(u.severity, Severity::High);
        for n in [
            "id 812",
            "`hide_me`",
            "type `lsm`",
            "tag abcd000000000001",
            "bpf_lsm_file_open",
            "never saw it load",
            "not refused",
        ] {
            assert!(u.reasoning.contains(n), "{n}: {}", u.reasoning);
        }
        let l = v(ev(
            FsProtectOperation::BpfUnseen,
            &object_comm("", "prog 900"),
            0,
            crossview_ino(true, false, 2, 41),
        ));
        assert_eq!(l.severity, Severity::High);
        assert!(
            l.reasoning.contains("BPF link id 41 (link type `tracing`"),
            "{}",
            l.reasoning
        );
        let b = |t, link| {
            v(ev(
                FsProtectOperation::BpfBaseline,
                &object_comm("sd_devices", "cgroup_device"),
                0,
                crossview_ino(link, false, t, 5),
            ))
        };
        assert_eq!(b(15, false).severity, Severity::Low);
        assert_eq!(b(2, false).severity, Severity::High);
        assert_eq!(b(29, false).severity, Severity::High);
        assert_eq!(
            b(2, true).severity,
            Severity::Low,
            "a link: its program is weighed"
        );
        assert!(b(15, false)
            .reasoning
            .contains("while the agent was not running"));
        assert!(b(29, false)
            .reasoning
            .contains("refuses outside a trusted-installer window"));
        assert_eq!(
            crossview_severity(FsProtectOperation::BpfUnseen, true, false, 0),
            Severity::High
        );
        // the kernel's own program (loaded before user space): Low, said so
        let k = v(ev(
            FsProtectOperation::BpfBaseline,
            &object_comm("hid_tail_call", "__hid_bpf_tail_call"),
            0,
            crossview_ino(false, true, 26, 2),
        ));
        assert_eq!(k.severity, Severity::Low);
        assert!(
            k.reasoning
                .contains("by the kernel itself before user space"),
            "{}",
            k.reasoning
        );
        assert_eq!(
            crossview_severity(FsProtectOperation::BpfUnseen, false, true, 26),
            Severity::High,
            "an unseen object stays High"
        );
    }
}
