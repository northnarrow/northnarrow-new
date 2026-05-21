//! Hardcoded Tappa 2 rule set (R001..=R010).

use std::sync::Arc;

use common::{Event, ResponseAction, Severity, Verdict};
use parking_lot::Mutex;

use self::net::DnsBurstWindow;
use super::Rule;
use crate::config::comm_allowlist::CommAllowlist;
use crate::net::blocklist::{Ja3Blocklist, NetBlocklist};

pub mod canary;
pub mod chain;
pub mod net;
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
mod r011_kernel_module_tooling;
mod r012_setcap_tooling;
mod r013_namespace_escape_tooling;
mod r014_at_batch_scheduling;
mod r015_encoding_tooling_service_uid;
mod r016_debugger_service_uid;
mod r017_shell_from_nonstandard_path;

#[cfg(feature = "demo-tappa5")]
pub mod test_actions;

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
pub use r011_kernel_module_tooling::R011KernelModuleTooling;
pub use r012_setcap_tooling::R012SetcapTooling;
pub use r013_namespace_escape_tooling::R013NamespaceEscapeTooling;
pub use r014_at_batch_scheduling::R014AtBatchScheduling;
pub use r015_encoding_tooling_service_uid::R015EncodingToolingServiceUid;
pub use r016_debugger_service_uid::R016DebuggerServiceUid;
pub use r017_shell_from_nonstandard_path::R017ShellFromNonstandardPath;

/// Build the default rule set in evaluation order. R004 (proc/self/fd
/// — fileless exec) and R007 (crypto miner) come early because their
/// match implies high confidence. The Tappa 9 FIM rules
/// (NN-L-FIM-001..014) APPEND at the bottom since they match on
/// `Event::Fim` rather than `Event::ProcessSpawn` — the first-match
/// short-circuit never affects them. Tappa 9.5 K5 canary rules
/// (NN-L-CANARY-001..004) APPEND after the FIM rules — they match
/// on `Event::CanaryTripped`, so they're independent of both the
/// process + FIM rule families. K3 detector precedence guarantees
/// canary events never co-occur with FIM events for the same
/// inode (§12 Q9 inline-filter lock-in).
pub fn default_rules() -> Vec<Box<dyn Rule>> {
    // Tappa 10.5 (D5) — chain rules go FIRST so they OBSERVE precursor
    // events (recording + returning None, falling through to the
    // firing rule) before a first-match short-circuits the scan, and
    // so a correlated flow surfaces the Critical chain verdict ahead
    // of any lower-severity net rule. See `chain.rs` module docs.
    let mut rules: Vec<Box<dyn Rule>> = chain::chain_rules();
    let tappa2: Vec<Box<dyn Rule>> = vec![
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
    ];
    rules.extend(tappa2);
    // Tappa 10.5 (D2) — 7 NN process rules R011..R017 APPEND after
    // the Tappa 2 R001..R010 block so existing process-rule routing
    // (first-match-wins within `Event::ProcessSpawn`) is unchanged.
    // Empty allowlist here; the production main.rs path constructs
    // its engine via [`default_rules_with_net`] instead, threading
    // the operator-loaded process-comm allowlist in.
    rules.extend(process_rules_empty());
    rules.extend(crate::fim::rules::fim_rules());
    rules.extend(canary::canary_rules());
    // Tappa 10 (N6) — 9 NN-L-NET rules with empty boot
    // blocklists. The production agent main.rs path constructs
    // its engine via [`default_rules_with_net`] instead, threading
    // operator-loaded blocklists in.
    rules.extend(net::net_rules_empty());
    rules
}

/// Tappa 10 N9 / Tappa 10.5 D2 — production builder. Same shape as
/// [`default_rules`] but threads operator-loaded state in: the
/// blocklists into the 9 NN-L-NET rules (N9) and the process-comm
/// allowlist into the 7 R011..R017 process rules (D2). `main.rs`
/// calls this once at boot after loading
/// `/etc/northnarrow/netflow-blocklist.{v1,local}` +
/// `netflow-ja3-blocklist.{v1,local}` +
/// `process-comm-allowlist.{v1,local}` from disk.
#[allow(clippy::too_many_arguments)]
pub fn default_rules_with_net(
    blocklist: Arc<NetBlocklist>,
    ja3_blocklist: Arc<Ja3Blocklist>,
    burst_window: Arc<Mutex<DnsBurstWindow>>,
    process_allowlist: Arc<CommAllowlist>,
    netflow_comm_allowlist: Arc<CommAllowlist>,
    beacon_window: Arc<Mutex<net::BeaconWindow>>,
) -> Vec<Box<dyn Rule>> {
    // Tappa 10.5 (D5) — chain rules FIRST (see `default_rules` +
    // the chain.rs module docs for the ordering rationale).
    let mut rules: Vec<Box<dyn Rule>> = chain::chain_rules();
    let tappa2: Vec<Box<dyn Rule>> = vec![
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
    ];
    rules.extend(tappa2);
    rules.extend(process_rules(process_allowlist));
    rules.extend(crate::fim::rules::fim_rules());
    rules.extend(canary::canary_rules());
    rules.extend(net::net_rules(
        blocklist,
        ja3_blocklist,
        burst_window,
        netflow_comm_allowlist,
        beacon_window,
    ));
    rules
}

/// Tappa 10.5 (D2) — build the 7 process rules R011..R017 sharing an
/// operator-loaded `process-comm-allowlist`. Mirrors the Tappa 10 N6
/// [`net::net_rules`] factory: production threads the loaded allowlist
/// via `Arc`; tests + the empty-state boot path use
/// [`process_rules_empty`].
pub fn process_rules(allowlist: Arc<CommAllowlist>) -> Vec<Box<dyn Rule>> {
    vec![
        Box::new(R011KernelModuleTooling::new(Arc::clone(&allowlist))),
        Box::new(R012SetcapTooling::new(Arc::clone(&allowlist))),
        Box::new(R013NamespaceEscapeTooling::new(Arc::clone(&allowlist))),
        Box::new(R014AtBatchScheduling::new(Arc::clone(&allowlist))),
        Box::new(R015EncodingToolingServiceUid::new(Arc::clone(&allowlist))),
        Box::new(R016DebuggerServiceUid::new(Arc::clone(&allowlist))),
        Box::new(R017ShellFromNonstandardPath::new(allowlist)),
    ]
}

/// Empty-allowlist convenience for boot + tests, mirroring
/// [`net::net_rules_empty`]. With no allowlisted comms, the 7 rules
/// fire purely on their comm/filename/uid predicates.
pub fn process_rules_empty() -> Vec<Box<dyn Rule>> {
    process_rules(Arc::new(CommAllowlist::default()))
}

/// Demo rule set for Tappa 5. Returned only when the `demo-tappa5`
/// feature is enabled. These rules trigger the four new
/// ResponseActions on filename-suffix matches; they should never run
/// in production.
#[cfg(feature = "demo-tappa5")]
pub fn demo_tappa5_rules() -> Vec<Box<dyn Rule>> {
    use test_actions::{
        R901TestBlockOutbound, R902TestNetworkIsolation, R903TestQuarantine, R904TestThrottle,
    };
    vec![
        Box::new(R901TestBlockOutbound),
        Box::new(R902TestNetworkIsolation),
        Box::new(R903TestQuarantine),
        Box::new(R904TestThrottle),
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
            argv: Vec::new(),
            parent_comm: String::new(),
            parent_start_ns: 0,
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
            argv: Vec::new(),
            parent_comm: String::new(),
            parent_start_ns: 0,
        }
    }
}
