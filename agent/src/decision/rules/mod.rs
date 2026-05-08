//! Hardcoded Tappa 2 rule set (R001..=R010).

use common::{Event, ResponseAction, Severity, Verdict};

use super::Rule;

mod r001_exec_from_tmp;
mod r002_exec_from_dev_shm;
mod r003_exec_from_var_tmp;
mod r004_exec_from_proc_self_fd;
mod r005_netcat_exec;
mod r006_reverse_shell_tooling;
mod r007_crypto_miner;
mod r008_hidden_home_binary;
mod r009_root_exec_from_user_path;
mod r010_binary_in_webroot;

pub use r001_exec_from_tmp::R001ExecFromTmp;
pub use r002_exec_from_dev_shm::R002ExecFromDevShm;
pub use r003_exec_from_var_tmp::R003ExecFromVarTmp;
pub use r004_exec_from_proc_self_fd::R004ExecFromProcSelfFd;
pub use r005_netcat_exec::R005NetcatExec;
pub use r006_reverse_shell_tooling::R006ReverseShellTooling;
pub use r007_crypto_miner::R007CryptoMiner;
pub use r008_hidden_home_binary::R008HiddenHomeBinary;
pub use r009_root_exec_from_user_path::R009RootExecFromUserPath;
pub use r010_binary_in_webroot::R010BinaryInWebroot;

/// Build the default rule set in evaluation order. R004 (proc/self/fd
/// — fileless exec) and R007 (crypto miner) come early because their
/// match implies high confidence.
pub fn default_rules() -> Vec<Box<dyn Rule>> {
    vec![
        Box::new(R004ExecFromProcSelfFd),
        Box::new(R007CryptoMiner),
        Box::new(R006ReverseShellTooling),
        Box::new(R009RootExecFromUserPath),
        Box::new(R010BinaryInWebroot),
        Box::new(R002ExecFromDevShm),
        Box::new(R001ExecFromTmp),
        Box::new(R003ExecFromVarTmp),
        Box::new(R005NetcatExec),
        Box::new(R008HiddenHomeBinary),
    ]
}

/// Helper that turns an `Event::ProcessSpawn` into a [`Verdict`] tagged
/// with the firing rule's metadata. Rules call this in their match
/// arms to keep their bodies focused on detection logic.
pub(crate) fn build_verdict(
    rule: &dyn Rule,
    event: &Event,
    action: ResponseAction,
    severity: Severity,
    reasoning: &str,
) -> Verdict {
    let (event_pid, event_filename, timestamp_ns) = match event {
        Event::ProcessSpawn {
            pid,
            filename,
            timestamp_ns,
            ..
        } => (*pid, filename.clone(), *timestamp_ns),
        _ => (0, String::new(), 0),
    };
    Verdict {
        rule_id: rule.id().to_string(),
        rule_name: rule.name().to_string(),
        category: rule.category().to_string(),
        action,
        severity,
        reasoning: reasoning.to_string(),
        event_pid,
        event_filename,
        timestamp_ns,
    }
}

#[cfg(test)]
pub(crate) mod testutil {
    use common::Event;

    /// Build a `ProcessSpawn` event with sensible defaults plus the
    /// fields callers actually care about.
    pub(crate) fn spawn(comm: &str, filename: &str) -> Event {
        Event::ProcessSpawn {
            pid: 1234,
            ppid: 1,
            uid: 1000,
            gid: 1000,
            comm: comm.to_string(),
            filename: filename.to_string(),
            timestamp_ns: 42,
        }
    }

    /// Same as [`spawn`] but lets the caller override uid (used by
    /// R009 root-from-user-path tests).
    pub(crate) fn spawn_as(uid: u32, comm: &str, filename: &str) -> Event {
        Event::ProcessSpawn {
            pid: 1234,
            ppid: 1,
            uid,
            gid: uid,
            comm: comm.to_string(),
            filename: filename.to_string(),
            timestamp_ns: 42,
        }
    }
}
