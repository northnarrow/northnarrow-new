//! NN-L-BPF-001/002 — foreign activity in the BPF ecosystem (Tappa 10.8).
//!
//! The `bpf` LSM observer reports `bpf()` calls by processes that are not
//! the agent or the watchdog. BPF is legitimate infrastructure (systemd
//! socket filters and device policies, container runtimes, Cilium,
//! observability agents), so both rules are **Log**: an alert and a
//! baseline, with the known tooling and the operator allowlist exempt.
//!
//! * `NN-L-BPF-001_BpfProgramLoaded` (Medium): a BPF program loaded,
//!   attached or linked by an unlisted process — a kernel-resident
//!   component appeared on the host (rootkit / sensor-blinding shape).
//! * `NN-L-BPF-002_BpfForeignHandleOrDetach` (High): a handle to one of the
//!   agent's own maps / programs / links taken by id, a write handle on an
//!   agent map (observe mode), or a program / link detach by an unlisted
//!   process — tampering with the sensor itself. In enforce mode the map
//!   write is denied by the kernel and arrives as an anti-tamper denial
//!   instead.

use std::sync::Arc;

use common::wire::{bpf_cmd_name, BPF_CMD_FOREIGN_GET_FD, BPF_CMD_FOREIGN_MAP_WRITE};
use common::{Event, ResponseAction, Severity, Verdict};

use crate::config::comm_allowlist::CommAllowlist;
use crate::decision::{rules::build_verdict, Rule};

/// Processes that legitimately drive BPF on a server (kernel task names).
pub const KNOWN_BPF_COMMS: &[&str] = &[
    "systemd",
    "systemd-network",
    "systemd-resolve",
    "systemd-udevd",
    "dockerd",
    "containerd",
    "containerd-shim",
    "runc",
    "crun",
    "podman",
    "cilium-agent",
    "tetragon",
    "falco",
    "northnarrow-wat",
];

#[cfg(test)]
const BPF_MAP_CREATE: u32 = 0;
const BPF_PROG_LOAD: u32 = 5;
const BPF_PROG_ATTACH: u32 = 8;
const BPF_PROG_DETACH: u32 = 9;
const BPF_LINK_CREATE: u32 = 28;
const BPF_LINK_DETACH: u32 = 34;

fn is_known(comm: &str) -> bool {
    KNOWN_BPF_COMMS.contains(&comm)
}

pub struct NnLBpf001BpfProgramLoaded {
    allowlist: Arc<CommAllowlist>,
}

impl NnLBpf001BpfProgramLoaded {
    pub fn new(allowlist: Arc<CommAllowlist>) -> Self {
        Self { allowlist }
    }
}

impl Rule for NnLBpf001BpfProgramLoaded {
    fn id(&self) -> &'static str {
        "NN-L-BPF-001_BpfProgramLoaded"
    }
    fn name(&self) -> &'static str {
        "BPF program loaded or attached by an unlisted process"
    }
    fn category(&self) -> &'static str {
        "defense_evasion"
    }
    fn evaluate(&self, event: &Event) -> Option<Verdict> {
        let Event::BpfSyscall { comm, cmd, arg, .. } = event else {
            return None;
        };
        if !matches!(*cmd, BPF_PROG_LOAD | BPF_PROG_ATTACH | BPF_LINK_CREATE) {
            return None;
        }
        if is_known(comm) || self.allowlist.contains(comm) {
            return None;
        }
        let what = match *cmd {
            BPF_PROG_LOAD => format!("loaded a BPF program (prog_type {arg})"),
            BPF_PROG_ATTACH => format!("attached a BPF program (attach_type {arg})"),
            _ => format!("created a BPF link (attach_type {arg})"),
        };
        let reasoning = format!(
            "`{comm}` {what}: a kernel-resident component outside the known tooling — the \
             rootkit / sensor-blinding shape (T1014, T1562). Alert only; add the comm to \
             process-comm-allowlist.local if this is your observability stack."
        );
        Some(build_verdict(
            self,
            event,
            ResponseAction::Log,
            Severity::Medium,
            &reasoning,
        ))
    }
}

pub struct NnLBpf002BpfForeignHandleOrDetach {
    allowlist: Arc<CommAllowlist>,
}

impl NnLBpf002BpfForeignHandleOrDetach {
    pub fn new(allowlist: Arc<CommAllowlist>) -> Self {
        Self { allowlist }
    }
}

impl Rule for NnLBpf002BpfForeignHandleOrDetach {
    fn id(&self) -> &'static str {
        "NN-L-BPF-002_BpfForeignHandleOrDetach"
    }
    fn name(&self) -> &'static str {
        "Handle to the agent's BPF objects, or a program/link detach, by an unlisted process"
    }
    fn category(&self) -> &'static str {
        "anti_tamper"
    }
    fn evaluate(&self, event: &Event) -> Option<Verdict> {
        let Event::BpfSyscall { comm, cmd, arg, .. } = event else {
            return None;
        };
        let own_object = matches!(*cmd, BPF_CMD_FOREIGN_GET_FD | BPF_CMD_FOREIGN_MAP_WRITE);
        let detach = matches!(*cmd, BPF_PROG_DETACH | BPF_LINK_DETACH);
        if !own_object && !detach {
            return None;
        }
        // Touching the agent's own objects is never exempt by comm: a
        // listed tool doing it is still tampering.
        if detach && (is_known(comm) || self.allowlist.contains(comm)) {
            return None;
        }
        let reasoning = if own_object {
            format!(
                "`{comm}` took a handle to one of NorthNarrow's own BPF objects (id {arg}, {}): the \
                 way `bpftool map update/delete` and link detach reach the sensor — in enforce mode \
                 a write handle is denied by the kernel (anti-tamper denial `bpf_map`).",
                bpf_cmd_name(*cmd)
            )
        } else {
            format!(
                "`{comm}` issued bpf({}) — detaching BPF programs/links on a host that runs a BPF \
                 sensor is the blinding move; the agent's own links are pinned and inode-protected, \
                 this is telemetry on everyone else's.",
                bpf_cmd_name(*cmd)
            )
        };
        Some(build_verdict(
            self,
            event,
            ResponseAction::Log,
            Severity::High,
            &reasoning,
        ))
    }
}

/// The two BPF rules, sharing the process comm allowlist.
pub fn bpf_rules(allowlist: Arc<CommAllowlist>) -> Vec<Box<dyn Rule>> {
    vec![
        Box::new(NnLBpf001BpfProgramLoaded::new(Arc::clone(&allowlist))),
        Box::new(NnLBpf002BpfForeignHandleOrDetach::new(allowlist)),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ev(comm: &str, cmd: u32, arg: u32) -> Event {
        Event::BpfSyscall {
            pid: 777,
            uid: 0,
            comm: comm.to_string(),
            cmd,
            arg,
            timestamp_ns: 1,
        }
    }

    fn rules() -> (NnLBpf001BpfProgramLoaded, NnLBpf002BpfForeignHandleOrDetach) {
        let al = Arc::new(CommAllowlist::from_iter_owned(["myobs".to_string()]));
        (
            NnLBpf001BpfProgramLoaded::new(Arc::clone(&al)),
            NnLBpf002BpfForeignHandleOrDetach::new(al),
        )
    }

    #[test]
    fn program_load_by_unlisted_logs_medium_and_known_tooling_is_exempt() {
        let (r1, _) = rules();
        let v = r1
            .evaluate(&ev("bpftool", BPF_PROG_LOAD, 7))
            .expect("fires");
        assert_eq!(v.rule_id, "NN-L-BPF-001_BpfProgramLoaded");
        assert_eq!(v.severity, Severity::Medium);
        assert_eq!(v.action, ResponseAction::Log);
        assert!(r1.evaluate(&ev("systemd", BPF_PROG_LOAD, 7)).is_none());
        assert!(r1.evaluate(&ev("myobs", BPF_LINK_CREATE, 1)).is_none());
        // map create alone is not a load
        assert!(r1.evaluate(&ev("bpftool", BPF_MAP_CREATE, 1)).is_none());
    }

    #[test]
    fn own_object_handle_is_high_even_for_known_tooling() {
        let (_, r2) = rules();
        let v = r2
            .evaluate(&ev("systemd", BPF_CMD_FOREIGN_GET_FD, 42))
            .expect("fires");
        assert_eq!(v.rule_id, "NN-L-BPF-002_BpfForeignHandleOrDetach");
        assert_eq!(v.severity, Severity::High);
        assert!(v.reasoning.contains("id 42"));
        assert!(r2
            .evaluate(&ev("bpftool", BPF_CMD_FOREIGN_MAP_WRITE, 9))
            .is_some());
        // detach by unlisted: fires; by known/allowlisted: exempt
        assert!(r2.evaluate(&ev("bpftool", BPF_LINK_DETACH, 0)).is_some());
        assert!(r2
            .evaluate(&ev("cilium-agent", BPF_LINK_DETACH, 0))
            .is_none());
        assert!(r2.evaluate(&ev("myobs", BPF_PROG_DETACH, 0)).is_none());
        // a plain load is not this rule's business
        assert!(r2.evaluate(&ev("bpftool", BPF_PROG_LOAD, 7)).is_none());
    }
}
