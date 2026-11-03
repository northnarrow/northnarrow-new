//! The sensor contract's Linux values (Wave 4 restructure, R13, lab PR 271;
//! plan §3.6): one entry per source of the bus — each ring's pump and each
//! drain the start runs —, with the attach points the boot notes, the
//! fallbacks, the synchronous verdicts, the failure semantics, the kernel's
//! budgets, the truncations and the rings that count the losses, as the code
//! has them. The types and the class contracts are nn-core's
//! ([`nn_core::contract`]).
//!
//! What holds it to the code: [`nn_core::contract::check`] over [`SOURCES`]
//! (every kind of event and every class has a source), the truncations made
//! of the wire's constants, a test that reads the kernel budgets' constants
//! in the eBPF sources, and the agent's test that reads the sources of the
//! pumps, the drains and the attach notes (`boot::manifest`): a source or an
//! attach point the code starts without an entry here fails them.

use common::wire::{exe, open_sensor as wos};
use common::wire::{
    ARGV_LEN, FILENAME_LEN, FIM_CHILD_NAME_LEN, QNAME_LEN, QNAME_WIRE_LEN, TASK_COMM_LEN,
};
use nn_core::contract::{
    EventKind as K, FailureMode, Fallback, KernelBudget, OptIn, SourceContract, SyncVerdict,
    Truncation,
};

/// The opt-ins the boot says are configured (`SourceFacts::opt_ins`; the
/// agent's start reads its command line).
pub const OPT_IN_EXEC_QUARANTINE: &str = "exec_quarantine_enforce";
pub const OPT_IN_EXEC_POLICY: &str = "exec_policy_enforce";
pub const OPT_IN_NET_CONNECT_DENY: &str = "net_connect_deny";

/// `comm`: the kernel's 16 bytes, NUL included.
const COMM: Truncation = Truncation {
    field: "comm",
    max_bytes: (TASK_COMM_LEN - 1) as u32,
    marked: "not marked: the kernel's own bound",
};

/// The attach points as the boot notes them, whole (the review of #479,
/// X1: the manifest reads a source `ok` only from its attach code's own
/// `Took::Whole` on exactly one of these, or a known fallback).
pub mod attach {
    pub const PROCESS_SPAWN: &str = "tracepoint:sched/sched_process_exec";
    pub const PROCESS_SPAWN_NO_STDIO: &str =
        "tracepoint:sched/sched_process_exec (no standard-stream probes: R020 off)";
    pub const EXEC_LSM: &str = "lsm:bprm_check_security";
    pub const EXEC_TRACEPOINT: &str = "tracepoint:syscalls/sys_enter_execve (user memory)";
    pub const TCP_CONNECT: &str = "kprobe:tcp_v4_connect+tcp_v6_connect";
    pub const DNS_SKB: &str = "kprobe:udp_send_skb+udp_v6_send_skb";
    /// Part of [`DNS_SKB`]: `udp_v6_send_skb` not attached.
    pub const DNS_SKB_V4: &str = "kprobe:udp_send_skb";
    pub const DNS_SENDMSG: &str = "kprobe:udp_sendmsg (user memory, IPv4 only)";
    pub const DENY_HOOKS: &str = "lsm:deny hooks";
    pub const MODULE_LOAD: &str = "lsm:kernel_read_file+kernel_load_data";
    pub const BPF_OBSERVER: &str = "lsm:bpf";
    pub const IO_URING_REQ: &str = "tracepoint:io_uring/io_uring_create+io_uring_submit_req";
    pub const IO_URING_SQE: &str = "tracepoint:io_uring/io_uring_create+io_uring_submit_sqe";
    /// Part of the io_uring sensor: no submit tracepoint.
    pub const IO_URING_CREATE: &str = "tracepoint:io_uring/io_uring_create";
    pub const FIM_OBSERVERS: &str = "lsm:FIM observe programs";
    pub const NET_FLOWS: &str =
        "kprobe:inet_csk_listen_start, fexit:tcp_close, kprobe:udp_sendmsg+udpv6_sendmsg";
    /// Part of [`NET_FLOWS`]: `udpv6_sendmsg` not attached.
    pub const NET_FLOWS_V4: &str =
        "kprobe:inet_csk_listen_start, fexit:tcp_close, kprobe:udp_sendmsg";
    pub const OPEN_LSM: &str = "lsm:file_open (FIM observer)";
    pub const OPEN_TRACEPOINT: &str = "tracepoint:syscalls/sys_enter_openat (user memory)";
}

/// The file-open sensor's notes: the LSM sensor's and the tracepoint's.
pub const OPEN_LSM_NOTE: &str = attach::OPEN_LSM;
pub const OPEN_TRACEPOINT_NOTE: &str = attach::OPEN_TRACEPOINT;

/// Why a BPF LSM program on its attach point does not run: `bpf` is not in
/// the active LSM list (R13: the exec and file-open sensors take their
/// tracepoints instead, the reason noted with them).
pub const BPF_LSM_ABSENT: &str = "bpf is not in the active LSM list: its BPF LSM programs would \
     attach and never run";

/// The deny hooks the `fs_protect` source's verdicts come from
/// (`anti_tamper::DENY_HOOKS` and `OPTIONAL_DENY_HOOKS`; a test holds them
/// to it).
const DENY_HOOK_LIST: &str = "LSM task_kill, ptrace_access_check, inode_unlink, inode_rmdir, \
     inode_rename, inode_setattr, file_ioctl, file_open, inode_create, inode_mkdir, inode_mknod, \
     inode_symlink, inode_link, inode_setxattr, inode_removexattr, bpf_map; inode_set_acl, \
     inode_remove_acl, file_ioctl_compat where the kernel has them; bpf (the agent's links); \
     kernel_read_file and kernel_load_data (kexec); the cgroup move guard, inode_permission and \
     fexit cgroup_procs_write_start, where the kernel has the function in the shape it reads";

/// Every source of the bus on Linux (a table of the build: a `const`, no
/// process state).
pub const SOURCES: [SourceContract; 13] = [
    SourceContract {
        source: "process_spawn",
        sensors: &["process_spawn"],
        events: &[K::ProcessSpawn],
        attach: attach::PROCESS_SPAWN,
        also: &[],
        needs_bpf_lsm: false,
        lsm_part: None,
        fallbacks: &[Fallback {
            attach: attach::PROCESS_SPAWN_NO_STDIO,
            when: "the kernel's verifier refuses the standard-stream probes",
            costs: "R020 cannot fire (stdio_probe)",
            equivalent: false,
            lost: &[],
        }],
        sync_verdict: SyncVerdict::None,
        opt_in: Some(OptIn {
            verdict: SyncVerdict::UserDeadline {
                deadline_ms: 2_000,
                holds: "the exec quarantine stops the process until its exec is judged; \
                        the deadline's default policy resumes it",
            },
            when: "--exec-quarantine enforce (experimental; 100 to 10,000 ms)",
            key: OPT_IN_EXEC_QUARANTINE,
            needs_bpf_lsm: true,
        }),
        on_failure: FailureMode::Blind,
        on_failure_detail: "its attach failing refuses the start (signed); its pump ending is \
             found within 5 s, signed and stops the agent for the watchdog's restart",
        kernel_budgets: &[],
        truncations: &[
            Truncation {
                field: "argv",
                max_bytes: (ARGV_LEN - 1) as u32,
                marked: "trunc_flags ARGV",
            },
            Truncation {
                field: "filename",
                max_bytes: (FILENAME_LEN - 1) as u32,
                marked: "trunc_flags FILENAME",
            },
            Truncation {
                field: "exe path, each component",
                max_bytes: (exe::EXE_PATH_SLOT_LEN - 1) as u32,
                marked: "exe flags DEEP past 16 components",
            },
            COMM,
        ],
        rings: &["exec"],
        probe: Some("exec"),
        self_tested: false,
        degradation_sources: &["stdio_probe"],
        standby_for: None,
    },
    SourceContract {
        source: "file_open",
        sensors: &[],
        events: &[K::FileOpen],
        attach: attach::OPEN_TRACEPOINT,
        also: &[],
        needs_bpf_lsm: false,
        lsm_part: None,
        fallbacks: &[],
        sync_verdict: SyncVerdict::None,
        opt_in: None,
        on_failure: FailureMode::Blind,
        on_failure_detail: "attached at every start and inert while the LSM file-open sensor \
             runs; its attach failing refuses the start (signed); its pump ending stops the agent \
             within 5 s (signed)",
        kernel_budgets: &[],
        truncations: &[
            Truncation {
                field: "filename (read from the caller's memory)",
                max_bytes: (FILENAME_LEN - 1) as u32,
                marked: "not marked",
            },
            COMM,
        ],
        rings: &["file_open"],
        probe: Some("file_open"),
        self_tested: false,
        degradation_sources: &[],
        standby_for: Some("open_sensor"),
    },
    SourceContract {
        source: "exec_check",
        sensors: &["exec"],
        events: &[K::ExecCheck],
        attach: attach::EXEC_LSM,
        also: &[],
        needs_bpf_lsm: true,
        lsm_part: None,
        fallbacks: &[Fallback {
            attach: attach::EXEC_TRACEPOINT,
            when: "--exec-sensor tracepoint, a linux_binprm offset missing, the LSM program \
                   refused, or bpf not in the active LSM list",
            costs: "the executed path read from the caller's memory (it can differ from the file \
                    the kernel runs); no executable identity; the exec quarantine and the exec \
                    policy have no kernel half",
            equivalent: false,
            lost: &[],
        }],
        sync_verdict: SyncVerdict::None,
        opt_in: Some(OptIn {
            verdict: SyncVerdict::KernelDeny {
                hooks: "LSM bprm_check_security (the exec policy refuses with EACCES)",
            },
            when: "--exec-policy enforce (experimental)",
            key: OPT_IN_EXEC_POLICY,
            needs_bpf_lsm: true,
        }),
        on_failure: FailureMode::Blind,
        on_failure_detail: "the LSM program refused or not runnable: sys_enter_execve, signed \
             (exec_sensor); that attach failing too refuses the start; its pump ending stops the \
             agent within 5 s (signed)",
        kernel_budgets: &[],
        truncations: &[
            Truncation {
                field: "filename",
                max_bytes: (FILENAME_LEN - 1) as u32,
                marked: "not marked",
            },
            Truncation {
                field: "exe path, each component",
                max_bytes: (exe::EXE_PATH_SLOT_LEN - 1) as u32,
                marked: "exe flags DEEP past 16 components",
            },
            COMM,
        ],
        rings: &["exec_check"],
        probe: None,
        self_tested: false,
        degradation_sources: &["exec_sensor", "exec_policy"],
        standby_for: None,
    },
    SourceContract {
        source: "tcp_connect",
        sensors: &["tcp_connect"],
        events: &[K::TcpConnect, K::NetFlow],
        attach: attach::TCP_CONNECT,
        also: &[],
        needs_bpf_lsm: false,
        lsm_part: None,
        fallbacks: &[],
        sync_verdict: SyncVerdict::None,
        opt_in: Some(OptIn {
            verdict: SyncVerdict::KernelDeny {
                hooks: "LSM socket_connect (a connect to a blocklisted destination, EPERM)",
            },
            when: "--net-connect-deny (never armed in detect-only)",
            key: OPT_IN_NET_CONNECT_DENY,
            needs_bpf_lsm: true,
        }),
        on_failure: FailureMode::Blind,
        on_failure_detail: "its attach failing refuses the start (signed); the opt-in connect \
             deny not armed is signed (net_connect_deny), and it lets a connect through when it \
             cannot read the destination, uncounted; its pump ending stops the agent within 5 s \
             (signed)",
        kernel_budgets: &[],
        truncations: &[COMM],
        rings: &["tcp_connect"],
        probe: None,
        self_tested: false,
        degradation_sources: &["net_connect_deny"],
        standby_for: None,
    },
    SourceContract {
        source: "dns_query",
        sensors: &["dns", "dns_nss"],
        events: &[K::DnsQuery, K::DnsFlood],
        attach: attach::DNS_SKB,
        also: &[],
        needs_bpf_lsm: false,
        lsm_part: None,
        fallbacks: &[Fallback {
            attach: attach::DNS_SENDMSG,
            when: "--dns-sensor sendmsg, or what the socket-buffer programs need missing",
            costs: "the name read from the sender's memory, which it can rewrite before the \
                    kernel sends it; IPv4 only",
            equivalent: false,
            lost: &[],
        }],
        sync_verdict: SyncVerdict::None,
        opt_in: None,
        on_failure: FailureMode::Blind,
        on_failure_detail: "IPv6 not attached is signed (dns_sensor); the udp_sendmsg attach \
             failing refuses the start; its pump ending stops the agent within 5 s (signed); \
             R14b: the names are decoded by the parse worker — while it is down or disabled \
             the events carry no name (qname_partial) and the core does not decode them itself",
        kernel_budgets: &[KernelBudget {
            allows: "64 queries at once, then 128 a second, per process; 2,048 at once, then \
                     1,024 a second, per user (the resolvers' users exempt); each record says \
                     how many were held (DnsFlood)",
            counter: "dns_rate",
        }],
        truncations: &[
            Truncation {
                field: "query (socket buffer, wire form)",
                max_bytes: QNAME_WIRE_LEN as u32,
                marked: "qname_partial when its end is not in it; NONLINEAR when paged",
            },
            Truncation {
                field: "query (udp_sendmsg fallback)",
                max_bytes: (QNAME_LEN - 1) as u32,
                marked: "not marked",
            },
            COMM,
        ],
        rings: &["dns"],
        probe: Some("dns"),
        self_tested: false,
        degradation_sources: &["dns_sensor"],
        standby_for: None,
    },
    SourceContract {
        source: "fs_protect",
        sensors: &["deny_hooks"],
        events: &[K::FsProtectDenial],
        attach: attach::DENY_HOOKS,
        also: &[],
        needs_bpf_lsm: true,
        lsm_part: None,
        fallbacks: &[],
        sync_verdict: SyncVerdict::KernelDeny {
            hooks: DENY_HOOK_LIST,
        },
        opt_in: None,
        on_failure: FailureMode::FailOpen,
        on_failure_detail: "a hook that cannot read what it needs lets the operation through, \
             counted per hook and signed (deny_fail_open); a missing deny hook, bpf not in the \
             active LSM list or a deny self-test whose signal is delivered refuses the start \
             (signed) unless NN_ANTI_TAMPER_ALLOW_DEGRADED=1: then L1 or L0, signed; the deny \
             never depends on the record",
        kernel_budgets: &[KernelBudget {
            allows: "a refused signal, ptrace, kexec or cgroup move: one record per caller and \
                     operation a second, 50 a second per CPU (every one is refused); inode \
                     denials have no kernel budget",
            counter: "task_denial_rate",
        }],
        truncations: &[COMM],
        rings: &["fs_protect"],
        probe: None,
        self_tested: true,
        degradation_sources: &["anti_tamper", "bpf_lsm", "deny_self_test"],
        standby_for: None,
    },
    SourceContract {
        source: "module_load",
        sensors: &["module_load"],
        events: &[K::ModuleLoad],
        attach: attach::MODULE_LOAD,
        also: &[],
        needs_bpf_lsm: true,
        lsm_part: None,
        fallbacks: &[],
        sync_verdict: SyncVerdict::None,
        opt_in: None,
        on_failure: FailureMode::Blind,
        on_failure_detail: "not attached: signed (anti_tamper's observe hooks), the module-load \
             rule blind; its pump ending stops the agent within 5 s (signed)",
        kernel_budgets: &[],
        truncations: &[
            Truncation {
                field: "module path, each component",
                max_bytes: 31,
                marked: "path_truncated (too deep, unreadable); a cut path starts with …/",
            },
            COMM,
        ],
        rings: &["module_load"],
        probe: None,
        self_tested: false,
        degradation_sources: &[],
        standby_for: None,
    },
    SourceContract {
        source: "io_uring",
        sensors: &["io_uring"],
        events: &[K::IoUring, K::SensorFlood],
        attach: attach::IO_URING_REQ,
        also: &[attach::IO_URING_SQE],
        needs_bpf_lsm: false,
        lsm_part: None,
        fallbacks: &[],
        sync_verdict: SyncVerdict::None,
        opt_in: None,
        on_failure: FailureMode::Blind,
        on_failure_detail: "no tracepoint (CONFIG_IO_URING off): not attached, signed \
             (io_uring_sensor); its pump ending stops the agent within 5 s (signed)",
        kernel_budgets: &[KernelBudget {
            allows: "ring creations: 64 at once, then 128 a second, per process; 512 at once, \
                     then 256 a second, per user (SensorFlood says so); submissions: one record \
                     a second per process unless a new class appears",
            counter: "io_uring_rate",
        }],
        truncations: &[COMM],
        rings: &["io_uring"],
        probe: None,
        self_tested: false,
        degradation_sources: &["io_uring_sensor"],
        standby_for: None,
    },
    SourceContract {
        source: "bpf_syscall",
        sensors: &["bpf_syscall"],
        events: &[K::BpfSyscall],
        attach: attach::BPF_OBSERVER,
        also: &[],
        needs_bpf_lsm: true,
        lsm_part: None,
        fallbacks: &[],
        sync_verdict: SyncVerdict::None,
        opt_in: None,
        on_failure: FailureMode::Blind,
        on_failure_detail: "not attached: signed (anti_tamper's observe hooks); the same hook's \
             refusals of the agent's own links are fs_protect's; its pump ending stops the agent \
             within 5 s (signed)",
        kernel_budgets: &[KernelBudget {
            allows: "one record per process and command a second, the observed commands only",
            counter: "none: a repeat within its second is not recorded",
        }],
        truncations: &[COMM],
        rings: &["bpf"],
        probe: None,
        self_tested: false,
        degradation_sources: &[],
        standby_for: None,
    },
    SourceContract {
        source: "exploit_guard",
        sensors: &["exploit_guard"],
        events: &[K::ExploitPostcondition],
        attach: crate::sensors::epg::attach_note(crate::sensors::epg::Variant::Lite),
        also: &[],
        needs_bpf_lsm: true,
        lsm_part: Some(
            "its fentry and tp_btf hooks run; its LSM use points (capable, bprm_check_security, \
             file_open) do not",
        ),
        fallbacks: &[Fallback {
            attach: crate::sensors::epg::attach_note(crate::sensors::epg::Variant::Strict),
            when: "--exploit-guard strict",
            costs: "every system call's exit judged (more overhead); no LSM hook",
            equivalent: true,
            lost: &[],
        }],
        sync_verdict: SyncVerdict::None,
        opt_in: Some(OptIn {
            verdict: SyncVerdict::KernelDeny {
                hooks: "the post-condition hooks: SIGKILL before the call returns",
            },
            when: "enforce (--exploit-guard-response; never in detect-only)",
            key: "exploit_guard_enforce",
            needs_bpf_lsm: false,
        }),
        on_failure: FailureMode::Blind,
        on_failure_detail: "off or not attached: nothing of it attached, signed (exploit_guard); \
             its kill does not depend on its ring; its pump ending stops the agent within 5 s \
             (signed)",
        kernel_budgets: &[KernelBudget {
            allows: "4 reports per task",
            counter: "none: the kernel counts the rest (REPORTS_HELD)",
        }],
        truncations: &[COMM],
        rings: &["exploit_guard"],
        probe: None,
        self_tested: false,
        degradation_sources: &["exploit_guard"],
        standby_for: None,
    },
    SourceContract {
        source: "open_sensor",
        sensors: &["file_open"],
        events: &[
            K::FileOpen,
            K::Fim,
            K::MassWrite,
            K::FileBurst,
            K::DefenderSignal,
        ],
        attach: attach::OPEN_LSM,
        also: &[],
        needs_bpf_lsm: true,
        lsm_part: None,
        fallbacks: &[Fallback {
            attach: attach::OPEN_TRACEPOINT,
            when: "--file-open-sensor tracepoint, its FIM observer, maps, ring, pump or arming \
                   failing, or bpf not in the active LSM list",
            costs: "every open reaches userland with its path read from the caller's memory \
                    (the file_open source); mass writes, rename and unlink bursts, signals to \
                    security tools and FIM Opened records are not produced",
            equivalent: false,
            lost: &[K::MassWrite, K::FileBurst, K::DefenderSignal],
        }],
        sync_verdict: SyncVerdict::None,
        opt_in: None,
        on_failure: FailureMode::Blind,
        on_failure_detail: "failing to arm: the file_open source's tracepoint, signed \
             (file_open_sensor); a rule not written is signed; its pump ending stops the agent \
             within 5 s (signed)",
        kernel_budgets: &[KernelBudget {
            allows: "a read-only open repeated by its task within 1 s is not recorded (the \
                     probe's file exempt); a signal to a security tool once a second per sender \
                     and target",
            counter: "none: by design, not a loss",
        }],
        truncations: &[
            Truncation {
                field: "path, each component",
                max_bytes: (wos::OPEN_PATH_SLOT_LEN - 1) as u32,
                marked: "a cut mark",
            },
            Truncation {
                field: "path depth (components)",
                max_bytes: wos::OPEN_PATH_SLOTS as u32,
                marked: "path_truncated, a cut mark first",
            },
            Truncation {
                field: "renamed name's start",
                max_bytes: (wos::NAME_HEAD_LEN - 1) as u32,
                marked: "not marked",
            },
            COMM,
        ],
        rings: &["open_sensor"],
        probe: Some("file_open"),
        self_tested: false,
        degradation_sources: &["file_open_sensor"],
        standby_for: None,
    },
    SourceContract {
        source: "fim_drain",
        sensors: &["fim_observers"],
        events: &[K::Fim],
        attach: attach::FIM_OBSERVERS,
        also: &[],
        needs_bpf_lsm: true,
        lsm_part: None,
        fallbacks: &[],
        sync_verdict: SyncVerdict::None,
        opt_in: None,
        on_failure: FailureMode::Blind,
        on_failure_detail: "observers not attached: a signed coverage shortfall; its loop \
             ending is signed (drain_ended) and stops the agent within 5 s",
        kernel_budgets: &[KernelBudget {
            allows: "a read-only open repeated within 1 s is not recorded; 8,192 inodes with a \
                     write pending at once",
            counter: "fim_dirty_full",
        }],
        truncations: &[
            Truncation {
                field: "child name",
                max_bytes: (FIM_CHILD_NAME_LEN - 1) as u32,
                marked: "FIM_CHILD_TRUNCATED",
            },
            COMM,
        ],
        rings: &["fim"],
        probe: None,
        self_tested: false,
        degradation_sources: &[],
        standby_for: None,
    },
    SourceContract {
        source: "net_drain",
        sensors: &["net_flows"],
        events: &[K::NetFlow, K::NetListener, K::SensorFlood],
        attach: attach::NET_FLOWS,
        also: &[],
        needs_bpf_lsm: false,
        lsm_part: None,
        fallbacks: &[],
        sync_verdict: SyncVerdict::None,
        opt_in: None,
        on_failure: FailureMode::Blind,
        on_failure_detail: "its attach failing refuses the start; udpv6_sendmsg not attached \
             is signed (net_sensor); a log that does not open is signed (net_drain) and the \
             drain runs without it; its loop ending is signed (drain_ended) and stops the agent \
             within 5 s",
        kernel_budgets: &[KernelBudget {
            allows: "listen(): 64 at once, then 128 a second, per process; 512 at once, then \
                     256 a second, per user (SensorFlood says so); UDP sends aggregated, one row \
                     a second per destination",
            counter: "listen_rate",
        }],
        truncations: &[COMM],
        rings: &["tcp_close", "listen", "udp"],
        probe: None,
        self_tested: false,
        degradation_sources: &["net_sensor", "net_drain"],
        standby_for: None,
    },
];

/// The sources that do not travel the bus as a source of their own and are
/// not in [`SOURCES`]: the bus's loss recorder and the file-open sensor's
/// rule refresher are tasks the run loop watches like pumps, the test's
/// senders are tests'.
pub const NOT_SOURCES: [&str; 2] = [
    "open_sensor_rules",
    crate::sensors::multiplexer::BUS_LOSSES_LABEL,
];

/// The source of the bus named `label`.
pub fn source(label: &str) -> Option<&'static SourceContract> {
    const ALL: &[SourceContract] = &SOURCES;
    ALL.iter().find(|s| s.source == label)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every kind of event and every class has its source; no source or
    /// attach point is named twice.
    #[test]
    fn the_linux_contract_holds() {
        let problems = nn_core::contract::check(&SOURCES);
        assert!(problems.is_empty(), "{problems:#?}");
    }

    /// Every ring a source names is a slot of `RING_DROPS`, and every
    /// budget's counter that is a slot too; every ring slot is a source's
    /// ring or budget, or one of the exec guards' (not a bus source).
    #[test]
    fn the_rings_are_the_ring_drops_slots() {
        use common::ring_drops::RING_DROP_NAMES;
        let mut named: Vec<&str> = Vec::new();
        for s in &SOURCES {
            for r in s.rings {
                assert!(RING_DROP_NAMES.contains(r), "{}: {r}", s.source);
                named.push(r);
            }
            for b in s.kernel_budgets {
                if !b.counter.starts_with("none") {
                    assert!(
                        RING_DROP_NAMES.contains(&b.counter),
                        "{}: {}",
                        s.source,
                        b.counter
                    );
                    named.push(b.counter);
                }
            }
        }
        let guards = ["execq", "execpol"];
        for slot in RING_DROP_NAMES {
            assert!(
                named.contains(&slot) || guards.contains(&slot),
                "RING_DROPS slot {slot} is no source's"
            );
        }
    }

    /// The deny hooks the contract names are the attach's.
    #[test]
    fn the_deny_verdict_names_every_deny_hook() {
        for h in crate::anti_tamper::DENY_HOOKS
            .iter()
            .chain(crate::anti_tamper::OPTIONAL_DENY_HOOKS.iter())
        {
            assert!(DENY_HOOK_LIST.contains(h), "{h}");
        }
    }

    /// The kernel budgets' numbers are the eBPF programs' constants: each
    /// `(file, constant, value)` is read in `agent-ebpf/src`, and the
    /// contract's words carry the value.
    #[test]
    fn the_kernel_budgets_are_the_ebpf_constants() {
        let dir = std::path::Path::new(concat!(env!("NN_REPO_ROOT"), "/agent-ebpf/src"));
        let read = |f: &str| std::fs::read_to_string(dir.join(f)).expect(f);
        let has = |f: &str, decl: &str| {
            let src = read(f);
            assert!(src.contains(decl), "{f}: `{decl}` not found");
        };
        has("dns_query.rs", "const TASK_BURST: u64 = 64;");
        has(
            "dns_query.rs",
            "const TASK_REFILL_NS: u64 = 1_000_000_000 / 128;",
        );
        has("dns_query.rs", "const UID_BURST: u64 = 2048;");
        has(
            "dns_query.rs",
            "const UID_REFILL_NS: u64 = 1_000_000_000 / 1024;",
        );
        has("io_uring.rs", "const CREATE_TASK_BURST: u64 = 64;");
        has("io_uring.rs", "task_refill_ns: 1_000_000_000 / 128,");
        has("io_uring.rs", "const CREATE_UID_BURST: u64 = 512;");
        has("io_uring.rs", "uid_refill_ns: 1_000_000_000 / 256,");
        has(
            "io_uring.rs",
            "const ACTIVITY_INTERVAL_NS: u64 = 1_000_000_000;",
        );
        has("inet_csk_listen.rs", "const TASK_BURST: u64 = 64;");
        has("inet_csk_listen.rs", "const UID_BURST: u64 = 512;");
        has("inet_csk_listen.rs", "uid_refill_ns: 1_000_000_000 / 256,");
        has("inode_protect.rs", "const TASK_DENIAL_PER_SEC: u64 = 50;");
        has(
            "inode_protect.rs",
            "const TASK_DENIAL_DEDUP_NS: u64 = 1_000_000_000;",
        );
        has("bpf_defense.rs", "const DEDUP_NS: u64 = 1_000_000_000;");
        has(
            "read_repeat.rs",
            "pub const READ_REPEAT_NS: u64 = 1_000_000_000;",
        );
        has("module_load.rs", "const MODULE_PATH_SLOT_LEN: usize = 32;");
        has(
            "udp_sendmsg_outbound.rs",
            "const UDP_EMIT_MIN_INTERVAL_NS: u64 = 1_000_000_000;",
        );
        let dns = source("dns_query").unwrap().kernel_budgets[0].allows;
        assert!(
            dns.contains("64 queries at once, then 128")
                && dns.contains("2,048 at once, then 1,024")
        );
        let ior = source("io_uring").unwrap().kernel_budgets[0].allows;
        assert!(ior.contains("64 at once, then 128") && ior.contains("512 at once, then 256"));
        let deny = source("fs_protect").unwrap().kernel_budgets[0].allows;
        assert!(deny.contains("50 a second per CPU"));
        assert_eq!(common::epg::REPORTS_PER_TASK, 4);
        assert!(source("exploit_guard").unwrap().kernel_budgets[0]
            .allows
            .starts_with("4 reports"));
        // the fim drain's dirty-inode map
        has(
            "fim_watch.rs",
            "const WATCHED_PATHS_MAX_ENTRIES: u32 = 8192;",
        );
        has(
            "fim_watch.rs",
            "HashMap::with_max_entries(WATCHED_PATHS_MAX_ENTRIES, 0);",
        );
    }

    /// The operator's page lists every source and class, each source's
    /// truncations with their bytes (`docs/operator/SENSOR_CONTRACT.md`).
    #[test]
    fn the_operator_page_lists_the_contract() {
        let page = std::fs::read_to_string(concat!(
            env!("NN_REPO_ROOT"),
            "/docs/operator/SENSOR_CONTRACT.md"
        ))
        .unwrap();
        for s in &SOURCES {
            let row = page
                .lines()
                .find(|l| l.starts_with(&format!("| `{}` |", s.source)))
                .unwrap_or_else(|| panic!("no row for {}", s.source));
            for t in s.truncations {
                assert!(
                    row.contains(&format!("{} B", t.max_bytes))
                        || row.contains(&format!("{} components", t.max_bytes)),
                    "{}: {} {} B not on its row",
                    s.source,
                    t.field,
                    t.max_bytes
                );
            }
            for r in s.rings {
                assert!(row.contains(&format!("`{r}`")), "{}: ring {r}", s.source);
            }
            assert!(
                row.contains(s.on_failure.name()),
                "{}: its failure",
                s.source
            );
        }
        for c in nn_model::EventClass::ALL {
            assert!(
                page.lines()
                    .any(|l| l.starts_with(&format!("| {} |", c.name()))),
                "no row for the {} class",
                c.name()
            );
        }
    }

    /// The truncations are the wire's bounds: argv 511 bytes, a QNAME's
    /// 288 wire bytes, a path component 31.
    #[test]
    fn the_truncations_are_the_wire_s() {
        let t = |s: &str, f: &str| {
            source(s)
                .unwrap()
                .truncations
                .iter()
                .find(|t| t.field.starts_with(f))
                .unwrap_or_else(|| panic!("{s} {f}"))
                .max_bytes
        };
        assert_eq!(t("process_spawn", "argv"), 511);
        assert_eq!(t("process_spawn", "filename"), 255);
        assert_eq!(t("dns_query", "query (socket"), 288);
        assert_eq!(t("dns_query", "query (udp_sendmsg"), 252);
        assert_eq!(t("open_sensor", "path, each"), 31);
        assert_eq!(t("open_sensor", "path depth"), 16);
        assert_eq!(t("fim_drain", "child name"), 63);
        assert_eq!(t("module_load", "module path"), 31);
        assert_eq!(t("exec_check", "comm"), 15);
    }
}
