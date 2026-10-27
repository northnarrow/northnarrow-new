//! What the canary detector does on the host it runs on (Wave 4
//! restructure, R08b, lab PR 251).
//!
//! The detector judges events against the deployed canaries' indexes; what
//! it keeps of the canaries, and where it records a trip, is its host's: the
//! registry of deployed canaries and the access log are signed chains in the
//! agent's state directory (`canaries.jsonl`, `canary_access.jsonl`), this
//! host's interface addresses are read with `getifaddrs`, the inodes of the
//! file canaries are published to the FIM drain, which forwards their reads
//! (`read_forward`, a process-wide set), a canary's inode is `stat(2)`'s,
//! and an accessor's executable is `/proc/<pid>/exe`. Those calls are here,
//! as a trait the host implements (the agent: `LinuxHost`, in its
//! `canary_host_linux` module). Each is the call the detector made itself
//! before R08b, with the same arguments.
//!
//! The host is a type parameter of the detector's types, as the posture's
//! and the engine's ([`crate::posture::host`], [`crate::decision::host`]):
//! static functions, no state, no global; what the host owns (the registry,
//! the access log, the addresses' cache) is an associated type the detector
//! holds and hands back to it.

use std::net::IpAddr;
use std::path::Path;

use common::wire::InodeKey;
use nn_model::{CanaryAccessKind, CanaryTypeTag};
use nn_proto::admin_signed_payload::{CanaryDeploymentWire, CanaryTypeWire};

/// What the detector indexes of a deployed canary: of the registry's live
/// state (the agent: `canary::registry::CanaryLiveState`), its id, name,
/// type and deployment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LiveCanary {
    pub canary_id: String,
    pub name: String,
    pub canary_type: CanaryTypeWire,
    pub deployment: CanaryDeploymentWire,
}

/// Operator-supplied fields for the access log's append (the agent:
/// `canary::access_log::CanaryAccessDb::append`). Chain integrity fields
/// (`ts`, `prev_hash`, `entry_hash`, `agent_sig`, `agent_id`) are computed
/// by `append`, never supplied by the caller.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CanaryAccessDraft {
    pub canary_id: String,
    pub canary_name: String,
    pub canary_type: CanaryTypeTag,
    pub access_kind: CanaryAccessKind,
    pub accessor_pid: u32,
    pub accessor_uid: u32,
    pub accessor_comm: String,
    pub accessor_exe: Option<String>,
    pub first_trip: bool,
}

/// The host's calls the canary detector makes.
pub trait CanaryHost {
    /// The registry of deployed canaries (the agent:
    /// `canary::registry::Registry`, its signed chain).
    type Registry: Send + 'static;

    /// The canaries' access log (the agent:
    /// `canary::access_log::CanaryAccessDb`, its signed chain).
    type AccessLog: Send + 'static;

    /// This host's addresses, for the wildcard network canaries (the agent:
    /// `canary::network::LocalAddrs`, `getifaddrs` read at most once a
    /// second).
    type LocalAddrs: Default + Send + Sync + 'static;

    /// The registry's live set, in its order (the agent: `Registry::list`).
    fn live(registry: &Self::Registry) -> Vec<LiveCanary>;

    /// `true` when `canary_id` is deployed and not tripped: its next access
    /// is the first trip (the agent: `Registry::is_armed`).
    fn is_armed(registry: &Self::Registry, canary_id: &str) -> bool;

    /// Record the first trip of `canary_id`, with the `entry_hash` of its
    /// access row (the agent: `Registry::mark_tripped`, a signed `Trip`
    /// row): `Ok(false)` on a canary already tripped or not deployed.
    fn mark_tripped(
        registry: &mut Self::Registry,
        canary_id: &str,
        access_hash: Option<String>,
    ) -> anyhow::Result<bool>;

    /// Append an access row; its `entry_hash` (the agent:
    /// `CanaryAccessDb::append`, a signed row).
    fn append_access(log: &mut Self::AccessLog, draft: CanaryAccessDraft)
        -> anyhow::Result<String>;

    /// Whether `addr` is one of this host's addresses (the agent:
    /// `LocalAddrs::contains`).
    fn is_local(addrs: &Self::LocalAddrs, addr: IpAddr) -> bool;

    /// Publish the file canaries' inodes, whose reads the FIM drain then
    /// forwards (the agent: `canary::read_forward::replace`).
    fn publish_read_forward(keys: impl IntoIterator<Item = InodeKey>);

    /// The kernel's `(dev, ino)` of the file at `path`, `None` when it is not
    /// there (the agent: `stat_inode_key`, `stat(2)` without following a
    /// link).
    fn inode_key(path: &Path) -> Option<InodeKey>;

    /// The executable the kernel ran for `accessor_pid`, best-effort (the
    /// agent: `/proc/<pid>/exe`).
    fn accessor_exe(accessor_pid: u32) -> Option<String>;
}
