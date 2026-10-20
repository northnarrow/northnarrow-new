//! Hardcoded rule set: the process rules (R001..R018) and the FIM,
//! canary, network and chain families.

use std::sync::Arc;

use common::{Event, ResponseAction, Severity, Verdict};
use parking_lot::Mutex;

use self::net::DnsBurstWindow;
use super::Rule;
use crate::config::comm_allowlist::CommAllowlist;
use crate::net::blocklist::{Ja3Blocklist, NetBlocklist};

pub mod anti_tamper;
pub mod bpf;
pub mod canary;
pub mod chain;
pub mod iouring;
pub(crate) mod module_provenance;
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
mod r018_kernel_module_load;

#[cfg(feature = "demo-tappa5")]
pub mod test_actions;

/// World-writable staging directories a dropper runs from: the one set
/// NN-L-NET-008, NN-L-CHAIN-002 (and through its precursor CHAIN-005/007)
/// and the posture's exec arm judge an image by.
///
/// External audit NETR-008: each of them used to check `/tmp/` only (the
/// posture `/tmp/` and `/dev/shm/`), so a payload staged in `/dev/shm` or
/// `/var/tmp` evaded the network correlation. `/run/user/` and home
/// directories stay out: user services and confined packages run from them.
pub const STAGING_PREFIXES: &[&str] = &["/tmp/", "/var/tmp/", "/dev/shm/"];

/// `true` when `path` lies under one of [`STAGING_PREFIXES`].
pub fn is_staging_path(path: &str) -> bool {
    STAGING_PREFIXES.iter().any(|p| path.starts_with(p))
}

/// Lab PR 166: the kill of the tool rules R011..R013 for an exec of
/// `image`. A copy run from a staging directory is the payload itself, as
/// for R001..R003, which those rules outrank (PROC-009): its tree, so a
/// dropper named like a system tool does not keep its forked children.
/// Anywhere else the tool keeps the single-process kill.
pub(crate) fn tool_kill(image: &str) -> ResponseAction {
    if is_staging_path(image) {
        ResponseAction::KillProcessTree
    } else {
        ResponseAction::KillProcess
    }
}

/// `nobody`, the kernel's overflow uid: what NFS squashing, `sudo -u
/// nobody` and daemons that drop to it run as.
pub(crate) const NOBODY_UID: u32 = 65_534;

/// systemd's range for the transient accounts of `DynamicUser=yes` units
/// (`SYSTEMD_DYNAMIC_UID_MIN..=SYSTEMD_DYNAMIC_UID_MAX`, systemd's
/// "Users, Groups, UIDs and GIDs on systemd systems").
pub(crate) const DYNAMIC_USER_UIDS: std::ops::RangeInclusive<u32> = 61_184..=65_519;

/// External audit PROC-012: the service-account uid class of R015 and
/// R016 — an account no human logs in as, whose use of an encoder or a
/// debugger is the anomaly those rules record.
///
/// - 1..=999: the system accounts below `UID_MIN` (`/etc/login.defs`),
///   `www-data`, `mysql`, `_apt` and the like.
/// - [`NOBODY_UID`] and [`DYNAMIC_USER_UIDS`]: service accounts above
///   `UID_MIN`. Both rules stopped at 1000, so a web shell under a
///   `nobody` worker or a hardened `DynamicUser=yes` unit was never
///   judged.
///
/// Not in the class:
/// - root (0), whose encoder and debugger use is routine administration;
/// - 1000..=60000, the human accounts, and systemd-homed's 60001..=60513;
/// - the sub-uid ranges of `/etc/subuid` (100000 and up by default) and
///   the container ranges of `systemd-nspawn` (524288 and up). A rootless
///   container's uids belong to the human who owns the range (`podman
///   unshare` and `newuidmap` let that user become any of them), so they
///   carry that user's standing, not a daemon's; and from the host's uid
///   alone a container's daemon is not told apart from its root or its
///   users.
pub(crate) fn is_service_uid(uid: u32) -> bool {
    (1..1000).contains(&uid) || uid == NOBODY_UID || DYNAMIC_USER_UIDS.contains(&uid)
}

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
pub use r018_kernel_module_load::R018KernelModuleLoad;

/// Build the default rule set in evaluation order. The process rules
/// are ordered by [`spawn_rules`]: every kill before any record. The
/// Tappa 9 FIM rules
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
    let chains = chain::chain_rule_set();
    let mut rules: Vec<Box<dyn Rule>> = chains.head;
    // The process rules (R001..R017), with an empty allowlist; the
    // production main.rs path constructs its engine via
    // [`default_rules_with_net`] instead, threading the operator-loaded
    // process-comm allowlist in.
    rules.extend(spawn_rules(Arc::new(CommAllowlist::default()), None));
    rules.extend(module_load_rules());
    // FIM-009 self-upgrade (§15.1): the non-production rule set has no
    // admin dispatcher to arm an override, so FIM-009 gets an inert one
    // (never armed → unchanged KillProcess behaviour).
    rules.extend(crate::fim::rules::fim_rules(
        crate::anti_tamper::trusted_installer::TrustedInstallerOverride::inert_arc(),
    ));
    rules.extend(canary::canary_rules());
    // Tappa 10 (N6) — 9 NN-L-NET rules with empty boot
    // blocklists. The production agent main.rs path constructs
    // its engine via [`default_rules_with_net`] instead, threading
    // operator-loaded blocklists in.
    rules.extend(net::net_rules_empty());
    // Informational chains (NN-L-CHAIN-008) go LAST so their Log
    // verdict never shadows a blocking rule on the same event.
    rules.extend(chains.tail);
    rules
}

/// Tappa 10 N9 / Tappa 10.5 D2 — production builder. Same shape as
/// [`default_rules`] but threads operator-loaded state in: the
/// blocklists into the 9 NN-L-NET rules (N9) and the process-comm
/// allowlist into R006, R007 and R011..R017 (D2, PROC-010). `main.rs`
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
    dns_cache: Arc<crate::net::dns_cache::DnsCache>,
    // FIM-009 self-upgrade (§15.1): the live trusted-installer override
    // the NN-L-FIM-009 rule reads (armed by the admin dispatcher).
    installer_override: Arc<crate::anti_tamper::trusted_installer::TrustedInstallerOverride>,
    // Review 49: the shared process-lineage cache — package-manager
    // writes are recorded, not killed, by the wrapped FIM rules.
    lineage: crate::posture::lineage::AuthSessionTracker,
    // External audit DEC-005: the readers of whole trees the File and
    // Credential canary rules record instead of killing.
    canary_readers: crate::canary::readers::CanaryReaders,
    // External audit NET-019: the chain rules' correlation store, shared
    // with the netflow limiter.
    correlation: Arc<Mutex<crate::decision::correlation::CorrelationStore>>,
) -> Vec<Box<dyn Rule>> {
    // Tappa 10.5 (D5) — chain rules FIRST (see `default_rules` +
    // the chain.rs module docs for the ordering rationale).
    let chains = chain::chain_rule_set_over(correlation, Some(lineage.clone()));
    let mut rules: Vec<Box<dyn Rule>> = chains.head;
    // External audit NETR-003 class: the process allowlist judged on what
    // the kernel executed — from the exec event itself for R006, R007 and
    // R011..R017, through the lineage cache for the io_uring and BPF rules
    // and for the actors of R011..R017 (external audit PROC-008).
    let process_allowlist = Arc::new(
        process_allowlist
            .as_ref()
            .clone()
            .with_identity(lineage.clone()),
    );
    rules.extend(spawn_rules(
        Arc::clone(&process_allowlist),
        Some(lineage.clone()),
    ));
    rules.extend(module_load_rules());
    rules.extend(iouring::iouring_rules(Arc::clone(&process_allowlist)));
    rules.extend(bpf::bpf_rules(process_allowlist));
    rules.extend(crate::fim::rules::fim_rules_with_lineage(
        installer_override,
        lineage.clone(),
    ));
    rules.extend(canary::canary_rules_with_readers(canary_readers));
    // External audit NET-010 (NN-AUD-006): the network allowlist judged on
    // what the kernel executed, not on comm.
    let netflow_comm_allowlist = Arc::new(
        netflow_comm_allowlist
            .as_ref()
            .clone()
            .with_identity(lineage.clone()),
    );
    rules.extend(net::net_rules(
        blocklist,
        ja3_blocklist,
        burst_window,
        netflow_comm_allowlist,
        beacon_window,
        dns_cache,
        Some(lineage.clone()),
    ));
    // Informational chains (NN-L-CHAIN-008) go LAST so their Log
    // verdict never shadows a blocking rule on the same event.
    rules.extend(chains.tail);
    rules
}

/// External audit NETR-003 class (the allowlists keyed on `comm`, which a
/// process sets for itself with `prctl(PR_SET_NAME)`): the operator
/// allowlist judged on what the kernel executed for an exec event — its
/// resolved path, and the script an interpreter runs.
pub(crate) fn judge_spawn(
    allowlist: &CommAllowlist,
    event: &Event,
) -> crate::config::comm_allowlist::Judgement {
    let (comm, filename, exe, argv): (&str, &str, &common::ExeIdentity, &[String]) = match event {
        Event::ProcessSpawn {
            comm,
            filename,
            exe,
            argv,
            ..
        } => (comm, filename, exe, argv),
        Event::ExecCheck {
            comm,
            filename,
            exe,
            ..
        } => (comm, filename, exe, &[]),
        _ => {
            return crate::config::comm_allowlist::Judgement::Denied { claimed: false };
        }
    };
    let id = crate::posture::lineage::ExecIdentity::of_exec(exe.path_or(filename), argv);
    allowlist.judge_exec(&id, comm)
}

/// External audit PROC-008: the response of R011, R012, R013 and R017 to
/// an exec the allowlist did not exempt as the program run. The shipped
/// entries name trusted ACTORS — package managers, configuration
/// management: a root exec of a program in a root-owned system tree with
/// one of them in its lineage ([`CommAllowlist::actor_of`]) is recorded
/// instead of killed, as review 49 and PROC-007 record package
/// transactions (DKMS running `modprobe` under apt).
///
/// The lineage vouches for nothing else: a program outside a system tree
/// (a payload a maintainer script dropped in `/tmp`), or an exec by
/// another uid (a pager's shell under a user's `apt changelog`), is
/// judged as before. R014..R016 only record; they need no actor.
pub(crate) fn judge_actor(allowlist: &CommAllowlist, event: &Event, verdict: Verdict) -> Verdict {
    if verdict.action == ResponseAction::Log {
        return verdict;
    }
    let Event::ProcessSpawn {
        pid,
        uid,
        filename,
        exe,
        ..
    } = event
    else {
        return verdict;
    };
    if *uid != 0 || !crate::posture::lineage::in_system_tree(exe.path_or(filename)) {
        return verdict;
    }
    let Some(actor) = allowlist.actor_of(*pid) else {
        return verdict;
    };
    Verdict {
        action: ResponseAction::Log,
        reasoning: format!(
            "{} [run under {}, a trusted actor in process-comm-allowlist: recorded, not killed]",
            verdict.reasoning,
            actor.display()
        ),
        ..verdict
    }
}

/// The `Event::ProcessSpawn` rules in evaluation order (first match wins),
/// shared by both builders. External audit PROC-009: every rule that can
/// kill comes before any that only records (and a High record before a
/// Medium one), so a record never stands in for a kill (`/home/u/.x/bash`
/// was R008's Log, not R017's kill), and the specific tool rules come
/// before the staging rules they outrank (`/tmp/insmod` is R011, High,
/// T1547.006 — it was R001, Medium).
///
/// - R004 (fileless, Critical) and R007's exact names (Critical) lead.
/// - R009 stays ahead of the staging rules: its record of an
///   administrator's session or a package transaction (PROC-007) is a
///   deliberate exception to them.
/// - R006 records only the distribution's `socat` (`/usr/bin`, `/bin`,
///   `/usr/sbin`, `/sbin`), which no later rule kills.
/// - R018 reads `Event::ModuleLoad`; its place does not matter.
///
/// `lineage` (production) lets R004 and R009 read a parent's identity;
/// without it only PID 1 counts as systemd and no session is sanctioned.
fn spawn_rules(
    allowlist: Arc<CommAllowlist>,
    lineage: Option<crate::posture::lineage::AuthSessionTracker>,
) -> Vec<Box<dyn Rule>> {
    let (r004, r009) = match lineage {
        Some(l) => (
            R004ExecFromProcSelfFd::new(l.clone()),
            R009RootExecFromUserPath::new(l),
        ),
        None => Default::default(),
    };
    let al = || Arc::clone(&allowlist);
    vec![
        // Kills (and R009's exceptions).
        Box::new(r004),
        Box::new(R007CryptoMiner::new(al())),
        Box::new(R006ReverseShellTooling::new(al())),
        Box::new(r009),
        Box::new(R010BinaryInWebroot),
        Box::new(R011KernelModuleTooling::new(al())),
        Box::new(R012SetcapTooling::new(al())),
        Box::new(R013NamespaceEscapeTooling::new(al())),
        Box::new(R017ShellFromNonstandardPath::new(al())),
        Box::new(R002ExecFromDevShm),
        Box::new(R001ExecFromTmp),
        Box::new(R003ExecFromVarTmp),
        // Records, the High ones first.
        Box::new(R005NetcatExec),
        Box::new(R007CryptoMiner::name_fragments(al())),
        Box::new(R008HiddenHomeBinary),
        Box::new(R014AtBatchScheduling::new(al())),
        Box::new(R015EncodingToolingServiceUid::new(al())),
        Box::new(R016DebuggerServiceUid::new(al())),
    ]
}

/// BUG-034 — the kernel-module LOAD rule (R018), with its DEDICATED
/// module-loader allowlist seeded from the trusted system auto-loaders
/// (`systemd-udevd`, `systemd-modules-load`, `kmod`). Deliberately NOT
/// `insmod`/`modprobe` (arbitrary-path loaders — allowlisting them
/// would blind the non-standard-path Critical). Kept separate from the
/// R011..R017 process-comm allowlist so loosening one never silently
/// widens the other. v1 seeds in-code; operator extension via a
/// `module-loader-allowlist.{v1,local}` file is a fast-follow.
pub fn module_load_rules() -> Vec<Box<dyn Rule>> {
    // Seed = the kernel's 15-char-truncated `comm` (TASK_COMM_LEN=16,
    // NUL-terminated), NOT the full binary name: `systemd-modules-load`
    // → `systemd-modules` (loads via libkmod directly, so ITS comm is
    // the loader). udev-spawned modprobe is matched via its PARENT comm
    // `systemd-udevd`; kernel auto-loads (request_module) are
    // PF_KTHREAD-exempt regardless of comm. `modprobe`/`insmod` are
    // deliberately NOT seeded — they load arbitrary paths, so seeding
    // them would blind the non-standard-path Critical.
    let loader_allowlist = Arc::new(CommAllowlist::from_iter_owned(
        ["systemd-udevd", "systemd-modules", "kmod"]
            .into_iter()
            .map(String::from),
    ));
    vec![Box::new(R018KernelModuleLoad::new(loader_allowlist))]
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
        // Review 61: the file the kernel executed, when known.
        Event::ProcessSpawn {
            pid,
            filename,
            timestamp_ns,
            exe,
            ..
        } => (*pid, exe.path_or(filename).to_string(), *timestamp_ns),
        // BUG-034: R018 fires on Event::ModuleLoad — target the LOADER
        // process (else a Critical KillProcessTree would carry pid 0 and
        // be refused at the executor's PID floor, a silent no-op).
        Event::ModuleLoad {
            loader_pid,
            path,
            timestamp_ns,
            ..
        } => (*loader_pid, path.clone().unwrap_or_default(), *timestamp_ns),
        Event::IoUring {
            pid,
            comm,
            timestamp_ns,
            ..
        }
        | Event::BpfSyscall {
            pid,
            comm,
            timestamp_ns,
            ..
        } => (*pid, comm.clone(), *timestamp_ns),
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
            start_ns: 0,
            parent_is_kthread: false,
            exe: Default::default(),
        }
    }

    /// Tappa 10.9 step 2 (review 61): a spawn whose caller passed
    /// `filename` while the kernel executed `exe_path` (`flags` from
    /// `wire::exe::exe_flags`).
    pub(crate) fn spawn_exe(comm: &str, filename: &str, exe_path: &str, flags: u32) -> Event {
        let mut e = spawn(comm, filename);
        if let Event::ProcessSpawn { exe, .. } = &mut e {
            exe.path = exe_path.to_string();
            exe.flags = flags | common::wire::exe::exe_flags::KNOWN;
        }
        e
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
            start_ns: 0,
            parent_is_kthread: false,
            exe: Default::default(),
        }
    }

    /// Tappa 10.6 D5 — `spawn` plus argv + parent_comm, for the
    /// argv-enrichment tests. `uid` defaults to a service-class account
    /// (the R015/R016 gate) so those rules' base predicate passes.
    pub(crate) fn spawn_full(
        comm: &str,
        filename: &str,
        uid: u32,
        argv: &[&str],
        parent_comm: &str,
    ) -> Event {
        Event::ProcessSpawn {
            pid: 1234,
            ppid: 1,
            uid,
            gid: uid,
            comm: comm.to_string(),
            filename: filename.to_string(),
            timestamp_ns: 42,
            argv: argv.iter().map(|s| s.to_string()).collect(),
            parent_comm: parent_comm.to_string(),
            parent_start_ns: 0,
            start_ns: 0,
            parent_is_kthread: false,
            exe: Default::default(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::is_service_uid;

    /// External audit PROC-012: the service-uid class at each boundary.
    #[test]
    fn service_uid_class_boundaries() {
        for uid in [1, 33, 999, 61_184, 61_500, 65_519, 65_534] {
            assert!(is_service_uid(uid), "{uid} is a service account");
        }
        for uid in [
            0,
            1000,
            60_000,
            60_001,
            61_183,
            65_520,
            65_533,
            65_535,
            100_000,
            100_032,
            524_288,
            u32::MAX,
        ] {
            assert!(!is_service_uid(uid), "{uid} is not a service account");
        }
    }
}
