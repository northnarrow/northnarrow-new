//! Userland event/verdict model.
//!
//! These are the rich, owned types the daemon and CLI manipulate.
//! Sensors convert raw kernel events (see [`crate::wire`]) into the
//! variants of [`Event`]; the decision engine produces a [`Verdict`]
//! describing what response the executors should run.

use alloc::string::String;
use serde::{Deserialize, Serialize};

use crate::wire::ProcessSpawnRaw;

/// Canonical event emitted by a sensor.
///
/// Variants beyond `ProcessSpawn` are placeholders for future tappe
/// (file open, network connect, DNS, etc.). They are unit-shaped for
/// now so the enum compiles before sensors land.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Event {
    ProcessSpawn {
        pid: u32,
        ppid: u32,
        uid: u32,
        gid: u32,
        comm: String,
        filename: String,
        timestamp_ns: u64,
    },
    FileOpen,
    NetworkConnect,
    DnsQuery,
    LsmExec,
}

impl From<&ProcessSpawnRaw> for Event {
    fn from(raw: &ProcessSpawnRaw) -> Self {
        Event::ProcessSpawn {
            pid: raw.pid,
            ppid: raw.ppid,
            uid: raw.uid,
            gid: raw.gid,
            comm: crate::wire::cstr_lossy(&raw.comm).into_owned(),
            filename: crate::wire::cstr_lossy(&raw.filename).into_owned(),
            timestamp_ns: raw.timestamp_ns,
        }
    }
}

/// Severity assigned to a verdict.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

/// Action the response layer should take in reaction to a verdict.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ResponseAction {
    Log,
    KillProcess,
    KillProcessTree,
    BlockOutbound,
    FullNetworkIsolation,
    Quarantine,
    ThrottleProcess,
}

/// Decision produced by the engine for a given event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Verdict {
    pub action: ResponseAction,
    pub severity: Severity,
    pub reasoning: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::{ProcessSpawnRaw, FILENAME_LEN, TASK_COMM_LEN};

    #[test]
    fn process_spawn_raw_to_event_is_lossy_safe() {
        let mut raw = ProcessSpawnRaw::zeroed();
        raw.pid = 4242;
        raw.ppid = 1;
        raw.uid = 1000;
        raw.gid = 1000;
        raw.timestamp_ns = 123_456_789;
        raw.comm[..2].copy_from_slice(b"ls");
        raw.filename[..7].copy_from_slice(b"/bin/ls");

        let evt: Event = (&raw).into();
        match evt {
            Event::ProcessSpawn {
                pid,
                ppid,
                uid,
                gid,
                comm,
                filename,
                timestamp_ns,
            } => {
                assert_eq!(pid, 4242);
                assert_eq!(ppid, 1);
                assert_eq!(uid, 1000);
                assert_eq!(gid, 1000);
                assert_eq!(comm, "ls");
                assert_eq!(filename, "/bin/ls");
                assert_eq!(timestamp_ns, 123_456_789);
            }
            _ => panic!("expected ProcessSpawn"),
        }
        // Sanity: the consts we rely on did not silently drift.
        assert_eq!(TASK_COMM_LEN, 16);
        assert_eq!(FILENAME_LEN, 256);
    }
}
