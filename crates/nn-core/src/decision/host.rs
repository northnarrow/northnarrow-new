//! What the decision engine does on the host it runs on (Wave 4
//! restructure, R08b, lab PR 251).
//!
//! The engine judges events; what it reads to judge them — the process
//! table, the clocks, the lineage — is its host's ([`PostureHost`], R08a,
//! lab PR 250). A few of its judges also ask the host for something no pure
//! crate can name: R018 and the ransomware tracker ask the system
//! directories' `rpm` whether a package owns a file and keep that work, and
//! the dpkg lists they read, off the agent's async runtime (tokio's
//! `block_in_place`); the tracker looks for a copy beside a deleted file in
//! the host's view of the filesystem (`/proc/1/root` from the agent's mount
//! namespace); the security-tool detector names who opened the
//! trusted-installer window and keeps the kernel's map of the tools'
//! processes (`DEFENDER_PIDS`, an aya map); the rule sets without an admin
//! dispatcher build a window that never opens. Those calls are here, as a
//! trait the host implements (the agent: `LinuxHost`, in its
//! `decision_host_linux` module, where `tokio`, `trusted_bin`,
//! `response::on_host_path` and `aya` are). Each is the call the engine's
//! code made itself before R08b, with the same arguments.
//!
//! The host is a type parameter of the engine's types, as the posture's
//! ([`crate::posture::host`]): static functions, no state, no global; what
//! the host owns (the window, the kernel map) is an associated type the
//! engine's types hold and hand back to it.
//!
//! With the engine (lab PR 251's move), what it held of the agent's own:
//! the exemption facts of the per-rule policy, read from the process table
//! (`ProcFacts`: `st_uid` and the mode bits of an executable and its tree,
//! its digest), and the ransomware tracker's sampler of the host's files
//! (`FsSampler`: `O_NOFOLLOW | O_NONBLOCK`, the owners and mode bits, the
//! host's view) — the engine holds each behind its trait, the host makes
//! the production one — and what the DNS pump keeps with the DNS cache for
//! the agent's lookups to wait on (lab PR 229, tokio). It reads its shipped
//! lists through the content's host ([`ContentHost`], R07).

use std::fmt::Debug;
use std::io;
use std::path::Path;
use std::sync::Arc;

use crate::anti_tamper::trusted_installer::WindowGrant;
use crate::content_host::ContentHost;
use crate::decision::rule_policy::ActorFacts;
use crate::impact::entropy::Sampler;
use crate::posture::host::PostureAgent;

/// The host's calls the decision engine makes, on top of the posture's
/// ([`PostureAgent`]: the process table, the clocks, the window) and the
/// content's ([`ContentHost`]: the shipped lists).
pub trait DecisionHost: PostureAgent + ContentHost {
    /// Run `f` where it does not hold up the host's other work (the agent:
    /// tokio's `block_in_place` on its multi-thread runtime, a plain call
    /// elsewhere). `f` may borrow from the caller.
    fn off_the_runtime<T>(f: impl FnOnce() -> T) -> T;

    /// `rpm -qf --quiet <path>` with the system directories' `rpm`
    /// (external audit ATP-014): `Err` with the reason when there is no
    /// trusted `rpm` to run, `Ok(None)` when it could not be run, else
    /// whether a package owns `path`.
    fn rpm_owns(path: &str) -> Result<Option<bool>, String>;

    /// Run `op` on the host's view of `path` (the agent:
    /// `/proc/1/root/<path>`), or on `path` itself where that view cannot be
    /// reached at all; when it can, its error is the answer.
    fn on_host_path<T>(path: &Path, op: impl Fn(&Path) -> io::Result<T>) -> io::Result<T>;

    /// Who opened the trusted-installer window and until when, while it is
    /// open (lab PR 225).
    fn installer_grant(window: &Self::InstallerWindow) -> Option<WindowGrant>;

    /// A window that never opens: the rule sets that have no admin
    /// dispatcher to arm one (the engine's tests, the offline replay).
    fn inert_installer_window() -> Arc<Self::InstallerWindow>;

    /// The kernel's map of the security tools' processes
    /// (`DEFENDER_PIDS`, lab PR 225): the security-tool detector keeps it
    /// equal to the tools' processes it registered.
    type DefenderMap: Send + 'static;

    /// Put `pid` in the map; the error's text when the kernel refuses it.
    fn defender_map_insert(map: &mut Self::DefenderMap, pid: u32) -> Result<(), String>;

    /// Take `pid` out of the map (an absent one is no error).
    fn defender_map_remove(map: &mut Self::DefenderMap, pid: u32);

    /// The per-rule policy's exemption facts read from the process table at
    /// `proc_root` (the agent: `ProcFacts`), an engine's own (each caches
    /// the digests it computed).
    fn actor_facts(proc_root: &Path) -> Arc<dyn ActorFacts>;

    /// The ransomware tracker's production sampler of the host's files (the
    /// agent: `FsSampler`).
    fn sampler() -> Arc<dyn Sampler>;

    /// What the DNS pump keeps with the DNS cache for the lookups to wait
    /// on (lab PR 229; the agent: `net::dns_cache::DnsIngest`). The engine
    /// holds it in the cache, nothing more.
    type DnsIngest: Default + Debug + Send + Sync + 'static;

    /// What wakes a close the net drain holds until its connect is
    /// announced (lab PR 246; the agent: tokio's `Notify`, which the drain
    /// awaits). The flow tracker holds it, hands it out and wakes it.
    type FlowNotify: Default + Send + Sync + 'static;

    /// Wake every current waiter of `notify` (the agent:
    /// `Notify::notify_waiters`).
    fn notify_flow_waiters(notify: &Self::FlowNotify);
}

/// The engine's own tests: the posture's portable test host
/// ([`crate::posture::host::testing::TestHost`]), whose calls here do
/// nothing of their own — work runs where it is called, no `rpm` to ask,
/// a path is its own view, a window is a `bool` (open or not: no grant to
/// name), the defenders' map a set, no exemption fact readable (an empty
/// process table), a sampler that finds nothing, no DNS pump and no drain
/// waiting on the flow tracker. The Linux
/// semantics are tested with the agent's host, in the agent.
#[cfg(test)]
mod testing {
    use std::collections::BTreeSet;
    use std::io;
    use std::path::Path;
    use std::sync::Arc;
    use std::time::Duration;

    use super::DecisionHost;
    use crate::anti_tamper::trusted_installer::WindowGrant;
    use crate::decision::rule_policy::ActorFacts;
    use crate::impact::entropy::{Sample, Sampler};
    use crate::posture::host::testing::TestHost;

    /// No fact of any process can be read: no exemption by uid, cgroup or
    /// executable applies.
    struct NoFacts;

    impl ActorFacts for NoFacts {
        fn uid(&self, _pid: u32) -> Option<u32> {
            None
        }
        fn cgroup(&self, _pid: u32) -> Option<String> {
            None
        }
        fn trusted_exe(&self, _pid: u32) -> Option<(String, [u8; 32])> {
            None
        }
    }

    /// Samples nothing: no burst's files are read.
    struct NoSampler;

    impl Sampler for NoSampler {
        fn sample(&self, _path: &str, _since: Duration) -> Sample {
            Sample::default()
        }
        fn sample_copies(&self, _copy: &str, _suffix: &str, _since: Duration) -> Sample {
            Sample::default()
        }
    }

    impl DecisionHost for TestHost {
        fn off_the_runtime<T>(f: impl FnOnce() -> T) -> T {
            f()
        }

        fn rpm_owns(_path: &str) -> Result<Option<bool>, String> {
            Err("no rpm on the test host".to_string())
        }

        fn on_host_path<T>(path: &Path, op: impl Fn(&Path) -> io::Result<T>) -> io::Result<T> {
            op(path)
        }

        fn installer_grant(window: &bool) -> Option<WindowGrant> {
            let _ = window;
            None
        }

        fn inert_installer_window() -> Arc<bool> {
            Arc::new(false)
        }

        type DefenderMap = BTreeSet<u32>;

        fn defender_map_insert(map: &mut BTreeSet<u32>, pid: u32) -> Result<(), String> {
            map.insert(pid);
            Ok(())
        }

        fn defender_map_remove(map: &mut BTreeSet<u32>, pid: u32) {
            map.remove(&pid);
        }

        fn actor_facts(_proc_root: &Path) -> Arc<dyn ActorFacts> {
            Arc::new(NoFacts)
        }

        fn sampler() -> Arc<dyn Sampler> {
            Arc::new(NoSampler)
        }

        type DnsIngest = ();

        type FlowNotify = ();

        fn notify_flow_waiters(_notify: &()) {}
    }
}
