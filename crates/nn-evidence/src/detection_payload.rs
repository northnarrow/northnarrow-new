//! The parts of a detection record the rule engine names: the sensor of the
//! triggering event, the ATT&CK tags, the acting principal (R08b, lab PR
//! 251). Cut verbatim from the agent's `detection_payload` (R04a, lab PR
//! 241), which re-exports them, with `Sensor::parse_filter` (from
//! `detection_store`): an inherent `impl` lives with its type. The engine
//! (`nn_core::decision`) reads them; the rest of the records, whose
//! constructors take the engine's decisions, stay in the agent until those
//! constructors leave them. Their serialised form is unchanged (SCHEMA
//! FREEZE).

use nn_model::Event;
use serde::{Deserialize, Serialize};

/// Which sensor surfaced the triggering event. Derived from the
/// [`Event`] variant via [`Sensor::from_event`]; the Sankey's left-most
/// "Sensor (eBPF)" column. (There is no pre-existing sensor enum in the
/// codebase — events are tagged only by `Event` variant — so this is a
/// thin projection of that, not a redefinition of an existing type.)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Sensor {
    /// Process exec — `sched_process_exec` / `bprm_check_security`.
    Exec,
    /// File access / integrity — `file_open` LSM + FIM drift.
    File,
    /// Kernel module load — `kernel_read_file` / `kernel_load_data`.
    ModuleLoad,
    /// Network — TCP connect, DNS query, finalized flow, listener.
    Network,
    /// Anti-tamper LSM denial on a protected inode.
    AntiTamper,
    /// Canary token trip.
    Canary,
    /// io_uring ring creation / activity (asynchronous I/O channel).
    IoUring,
    /// Lab PR 219: the exploit post-condition guard (`raw_syscalls` +
    /// `commit_creds` / `switch_task_namespaces` / `set_fs_root`).
    ExploitGuard,
}

impl Sensor {
    /// Map a triggering [`Event`] to its originating sensor. Exhaustive
    /// (no wildcard) on purpose: a new `Event` variant should force an
    /// explicit decision here rather than be silently bucketed.
    pub fn from_event(event: &Event) -> Self {
        match event {
            Event::ProcessSpawn { .. } | Event::ExecCheck { .. } => Sensor::Exec,
            Event::FileOpen { .. }
            | Event::MassWrite { .. }
            | Event::FileBurst { .. }
            | Event::Fim(_) => Sensor::File,
            Event::ModuleLoad { .. } => Sensor::ModuleLoad,
            Event::IoUring { .. } => Sensor::IoUring,
            Event::BpfSyscall { .. } => Sensor::AntiTamper,
            Event::ExploitPostcondition { .. } => Sensor::ExploitGuard,
            Event::TcpConnect { .. }
            | Event::DnsQuery { .. }
            | Event::DnsFlood { .. }
            | Event::SensorFlood { .. }
            | Event::NetFlow(_)
            | Event::NetListener(_) => Sensor::Network,
            Event::FsProtectDenial { .. } | Event::DefenderSignal { .. } => Sensor::AntiTamper,
            Event::CanaryTripped { .. } => Sensor::Canary,
        }
    }
}

impl Sensor {
    /// Parse a `--sensor` token (case-insensitive). Accepts both the
    /// hyphenated and squashed forms of the two-word sensors.
    pub fn parse_filter(s: &str) -> Option<Sensor> {
        match s.trim().to_ascii_lowercase().as_str() {
            "exec" => Some(Sensor::Exec),
            "file" => Some(Sensor::File),
            "module-load" | "moduleload" => Some(Sensor::ModuleLoad),
            "network" => Some(Sensor::Network),
            "anti-tamper" | "antitamper" => Some(Sensor::AntiTamper),
            "canary" => Some(Sensor::Canary),
            "io-uring" | "iouring" | "io_uring" => Some(Sensor::IoUring),
            "exploit-guard" | "exploitguard" | "exploit_guard" => Some(Sensor::ExploitGuard),
            _ => None,
        }
    }
}

/// The MITRE ATT&CK tags of a detection: tactic and technique ids (the
/// rule path records none today). It was the LLM advisor's
/// `common::ade_types::MitreAttack` until Wave 4 (lab PR 214); the fields,
/// their order and their serialised form are unchanged, so older records
/// keep verifying.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct MitreAttack {
    pub tactic: Vec<String>,
    #[serde(default)]
    pub technique: Vec<String>,
}

/// Process attribution for a detection. Best-effort: `comm` is always
/// present, `ppid` only when the source event carried it (process exec
/// events do; file / net / canary events do not). No `exe` lives HERE —
/// it is not uniformly available across sensors, and `comm` is the one
/// field every variant exposes; the executable path (exec sensors only)
/// is carried by the sibling [`DetectionRecord::exe`] (9.0.a.1), not the
/// principal.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Principal {
    pub pid: u32,
    pub comm: String,
    pub uid: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ppid: Option<u32>,
}

impl Principal {
    /// Extract the acting principal from a triggering [`Event`].
    /// Exhaustive on purpose (see [`Sensor::from_event`]).
    pub fn from_event(event: &Event) -> Self {
        match event {
            Event::ProcessSpawn {
                pid,
                ppid,
                uid,
                comm,
                ..
            }
            | Event::ExecCheck {
                pid,
                ppid,
                uid,
                comm,
                ..
            } => Principal {
                pid: *pid,
                comm: comm.clone(),
                uid: *uid,
                ppid: Some(*ppid),
            },
            Event::FileOpen { pid, uid, comm, .. }
            | Event::MassWrite { pid, uid, comm, .. }
            | Event::FileBurst { pid, uid, comm, .. }
            | Event::DefenderSignal { pid, uid, comm, .. }
            | Event::TcpConnect { pid, uid, comm, .. }
            | Event::DnsQuery { pid, uid, comm, .. }
            | Event::DnsFlood { pid, uid, comm, .. }
            | Event::SensorFlood { pid, uid, comm, .. }
            | Event::FsProtectDenial { pid, uid, comm, .. } => Principal {
                pid: *pid,
                comm: comm.clone(),
                uid: *uid,
                ppid: None,
            },
            Event::ModuleLoad {
                loader_pid,
                loader_uid,
                loader_comm,
                ..
            } => Principal {
                pid: *loader_pid,
                comm: loader_comm.clone(),
                uid: *loader_uid,
                ppid: None,
            },
            Event::IoUring { pid, uid, comm, .. }
            | Event::BpfSyscall { pid, uid, comm, .. }
            | Event::ExploitPostcondition { pid, uid, comm, .. } => Principal {
                pid: *pid,
                comm: comm.clone(),
                uid: *uid,
                ppid: None,
            },
            Event::CanaryTripped {
                accessor_pid,
                accessor_uid,
                accessor_comm,
                ..
            } => Principal {
                pid: *accessor_pid,
                comm: accessor_comm.clone(),
                uid: *accessor_uid,
                ppid: None,
            },
            Event::Fim(fe) => Principal {
                pid: fe.modifier_pid,
                comm: fe.modifier_comm.clone(),
                uid: fe.modifier_uid,
                ppid: None,
            },
            Event::NetFlow(nf) => Principal {
                pid: nf.pid,
                comm: nf.comm.clone(),
                uid: nf.uid,
                ppid: None,
            },
            Event::NetListener(nl) => Principal {
                pid: nl.pid,
                comm: nl.comm.clone(),
                uid: nl.uid,
                ppid: None,
            },
        }
    }
}
