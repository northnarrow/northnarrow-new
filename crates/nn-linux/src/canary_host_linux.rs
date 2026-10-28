//! The Linux host of the canary detector: the calls of nn-core's
//! [`CanaryHost`] (Wave 4 restructure, R08b, lab PR 251), as the detector
//! made them itself before — the agent's signed registry of deployed
//! canaries (`canary::registry`) and access log (`canary::access_log`),
//! this host's interface addresses (`canary::network::LocalAddrs`,
//! `getifaddrs`), the read-forward set the FIM drain consults
//! (`canary::read_forward`), `stat(2)` and `/proc/<pid>/exe`, with the same
//! arguments. The host is the chains', the posture's and the engine's one
//! ([`LinuxHost`], `chain_host_linux`): one type, the agent's.
//!
//! And [`stat_inode_key`], cut verbatim from `canary::detector` (the
//! agent's `canary::detector` re-exports it).

use std::net::IpAddr;
use std::path::Path;

use common::wire::InodeKey;
use nn_core::canary::host::{CanaryAccessDraft, CanaryHost, LiveCanary};

use crate::canary::access_log::CanaryAccessDb;
use crate::canary::network::LocalAddrs;
use crate::canary::registry::Registry;
use crate::chain_host_linux::LinuxHost;

impl CanaryHost for LinuxHost {
    type Registry = Registry;

    type AccessLog = CanaryAccessDb;

    type LocalAddrs = LocalAddrs;

    /// [`Registry::list`]: of each live canary, the fields the detector
    /// indexes.
    fn live(registry: &Registry) -> Vec<LiveCanary> {
        registry
            .list()
            .into_iter()
            .map(|canary| LiveCanary {
                canary_id: canary.canary_id,
                name: canary.name,
                canary_type: canary.canary_type,
                deployment: canary.deployment,
            })
            .collect()
    }

    fn is_armed(registry: &Registry, canary_id: &str) -> bool {
        registry.is_armed(canary_id)
    }

    fn mark_tripped(
        registry: &mut Registry,
        canary_id: &str,
        access_hash: Option<String>,
    ) -> anyhow::Result<bool> {
        registry.mark_tripped(canary_id, access_hash)
    }

    /// [`CanaryAccessDb::append`]: the row's `entry_hash`.
    fn append_access(log: &mut CanaryAccessDb, draft: CanaryAccessDraft) -> anyhow::Result<String> {
        log.append(draft).map(|entry| entry.entry_hash)
    }

    fn is_local(addrs: &LocalAddrs, addr: IpAddr) -> bool {
        addrs.contains(addr)
    }

    fn publish_read_forward(keys: impl IntoIterator<Item = InodeKey>) {
        crate::canary::read_forward::replace(keys);
    }

    fn inode_key(path: &Path) -> Option<InodeKey> {
        stat_inode_key(path)
    }

    fn accessor_exe(accessor_pid: u32) -> Option<String> {
        std::fs::read_link(format!("/proc/{accessor_pid}/exe"))
            .ok()
            .map(|p| p.to_string_lossy().into_owned())
    }
}

/// External audit DEC-003: the kernel's `(dev, ino)` for `path` —
/// `stat(2)` without following a link, `dev` encoded as the kernel does
/// (`(major << 20) | minor`). `None` when the file is not there.
pub fn stat_inode_key(path: &Path) -> Option<InodeKey> {
    use std::os::unix::fs::MetadataExt;
    let m = std::fs::symlink_metadata(path).ok()?;
    let dev = m.dev();
    Some(InodeKey {
        dev: ((libc::major(dev) as u64) << 20) | libc::minor(dev) as u64,
        ino: m.ino(),
    })
}
