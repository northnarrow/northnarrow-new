//! The Linux host of the decision engine: the calls of nn-core's
//! [`DecisionHost`] (Wave 4 restructure, R08b, lab PR 251), as the engine's
//! code made them itself before — the work kept off the async runtime
//! (`runtime::off_the_runtime`, tokio's `block_in_place`), the system
//! directories' `rpm` (`trusted_bin`), the host's view of a path
//! (`response::on_host_path`, `/proc/1/root`), the trusted-installer window
//! (`anti_tamper::trusted_installer`), the kernel's `DEFENDER_PIDS` (an aya
//! map), with the same arguments. The host is the chains' and the
//! posture's one ([`LinuxHost`], `chain_host_linux`): one type, the agent's.
//!
//! And the per-rule policy's exemption facts read from a `/proc`
//! ([`ProcFacts`]: a process's uid and cgroup, its executable opened,
//! checked root-owned in a root-owned tree through `st_uid` and the mode
//! bits, and hashed), cut verbatim from `decision::rule_policy`, whose
//! `ActorFacts` they implement.

use std::collections::HashMap;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use nn_core::anti_tamper::trusted_installer::WindowGrant;
use nn_core::decision::host::DecisionHost;
use parking_lot::Mutex;
use sha2::{Digest, Sha256};

use crate::anti_tamper::trusted_installer::TrustedInstallerOverride;
use crate::chain_host_linux::LinuxHost;
use crate::decision::rule_policy::ActorFacts;

impl DecisionHost for LinuxHost {
    fn off_the_runtime<T>(f: impl FnOnce() -> T) -> T {
        crate::runtime::off_the_runtime(f)
    }

    /// `trusted_bin::resolve("rpm")`, then `rpm -qf --quiet <path>` with its
    /// output discarded.
    fn rpm_owns(path: &str) -> Result<Option<bool>, String> {
        let rpm = crate::trusted_bin::resolve("rpm").map_err(|e| e.to_string())?;
        let status = rpm
            .command()
            .args(["-qf", "--quiet", path])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status();
        Ok(status.ok().map(|s| s.success()))
    }

    fn on_host_path<T>(path: &Path, op: impl Fn(&Path) -> io::Result<T>) -> io::Result<T> {
        crate::response::on_host_path(path, op)
    }

    fn installer_grant(window: &TrustedInstallerOverride) -> Option<WindowGrant> {
        window.current_grant()
    }

    fn inert_installer_window() -> Arc<TrustedInstallerOverride> {
        TrustedInstallerOverride::inert_arc()
    }

    type DefenderMap = crate::impair::DefenderMap;

    fn defender_map_insert(map: &mut Self::DefenderMap, pid: u32) -> Result<(), String> {
        map.insert(pid, 1, 0).map_err(|e| e.to_string())
    }

    fn defender_map_remove(map: &mut Self::DefenderMap, pid: u32) {
        let _ = map.remove(&pid);
    }

    /// [`ProcFacts`] over `proc_root` (below), as the engine and the
    /// offline replay made it.
    fn actor_facts(proc_root: &Path) -> Arc<dyn ActorFacts> {
        Arc::new(ProcFacts::new(proc_root))
    }

    /// The host's files ([`crate::impact::entropy::FsSampler`]).
    fn sampler() -> Arc<dyn nn_core::impact::entropy::Sampler> {
        Arc::new(crate::impact::entropy::FsSampler)
    }

    /// Tokio's `Notify` and the pump's mark (lab PR 229).
    type DnsIngest = crate::net::dns_cache::DnsIngest;
}

// ── the exemption facts (from `decision::rule_policy`, R08b) ───────────

/// [`ActorFacts`] read from a `/proc` (the host's, or an empty one in the
/// golden replay).
pub struct ProcFacts {
    root: PathBuf,
    hashes: Mutex<HashCache>,
}

/// Executables hashed, by identity; at most [`HASH_CACHE_CAP`].
#[derive(Default)]
struct HashCache {
    map: HashMap<FileKey, [u8; 32]>,
    order: std::collections::VecDeque<FileKey>,
}

const HASH_CACHE_CAP: usize = 64;
/// Larger executables are not hashed (not exempt).
const MAX_HASHED_BYTES: u64 = 512 << 20;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct FileKey {
    dev: u64,
    ino: u64,
    size: u64,
    mtime: (i64, i64),
    ctime: (i64, i64),
}

impl ProcFacts {
    pub fn new(proc_root: impl Into<PathBuf>) -> Self {
        Self {
            root: proc_root.into(),
            hashes: Mutex::new(HashCache::default()),
        }
    }

    fn hash_file(&self, f: &mut std::fs::File, key: FileKey) -> Option<[u8; 32]> {
        use std::io::Read as _;
        if let Some(h) = self.hashes.lock().map.get(&key) {
            return Some(*h);
        }
        if key.size > MAX_HASHED_BYTES {
            return None;
        }
        let mut h = Sha256::new();
        let mut buf = vec![0u8; 64 << 10];
        loop {
            match f.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => h.update(&buf[..n]),
                Err(_) => return None,
            }
        }
        let digest: [u8; 32] = h.finalize().into();
        let mut c = self.hashes.lock();
        if c.map.insert(key, digest).is_none() {
            c.order.push_back(key);
            while c.order.len() > HASH_CACHE_CAP {
                if let Some(old) = c.order.pop_front() {
                    c.map.remove(&old);
                }
            }
        }
        Some(digest)
    }
}

impl Default for ProcFacts {
    fn default() -> Self {
        Self::new("/proc")
    }
}

/// Root-owned and writable by no one else.
fn root_only(m: &std::fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;
    m.uid() == 0 && m.mode() & 0o022 == 0
}

impl ActorFacts for ProcFacts {
    fn uid(&self, pid: u32) -> Option<u32> {
        let s = std::fs::read_to_string(self.root.join(pid.to_string()).join("status")).ok()?;
        s.lines()
            .find_map(|l| l.strip_prefix("Uid:"))
            .and_then(|r| r.split_whitespace().next())
            .and_then(|u| u.parse().ok())
    }

    fn cgroup(&self, pid: u32) -> Option<String> {
        let s = std::fs::read_to_string(self.root.join(pid.to_string()).join("cgroup")).ok()?;
        s.lines()
            .find_map(|l| l.strip_prefix("0::"))
            .map(str::to_string)
    }

    fn trusted_exe(&self, pid: u32) -> Option<(String, [u8; 32])> {
        use std::os::unix::fs::MetadataExt;
        let link = self.root.join(pid.to_string()).join("exe");
        let path = std::fs::read_link(&link).ok()?;
        let path_s = path.to_str()?.to_string();
        if !crate::posture::lineage::in_system_tree(&path_s) {
            return None;
        }
        let mut f = std::fs::File::open(&link).ok()?;
        let m = f.metadata().ok()?;
        if !m.file_type().is_file() || !root_only(&m) {
            return None;
        }
        // The opened file is the one at the path it names now.
        let at_path = std::fs::symlink_metadata(&path).ok()?;
        if at_path.dev() != m.dev() || at_path.ino() != m.ino() {
            return None;
        }
        let mut dir = path.parent();
        while let Some(d) = dir {
            if !root_only(&std::fs::symlink_metadata(d).ok()?) {
                return None;
            }
            dir = d.parent();
        }
        let key = FileKey {
            dev: m.dev(),
            ino: m.ino(),
            size: m.size(),
            mtime: (m.mtime(), m.mtime_nsec()),
            ctime: (m.ctime(), m.ctime_nsec()),
        };
        let digest = self.hash_file(&mut f, key)?;
        Some((path_s, digest))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The host's own `/proc`: this test process's facts.
    #[test]
    fn proc_facts_read_this_process() {
        let me = std::process::id();
        let f = ProcFacts::default();
        assert_eq!(f.uid(me), Some(unsafe { libc::getuid() }));
        assert!(f.cgroup(me).is_some_and(|c| c.starts_with('/')));
        // A process of an empty /proc has no facts.
        let empty = tempfile::TempDir::new().unwrap();
        let f = ProcFacts::new(empty.path());
        assert_eq!(f.uid(me), None);
        assert_eq!(f.cgroup(me), None);
        assert_eq!(f.trusted_exe(me), None);
    }

    /// A root-owned system binary is trusted with its digest; a file the
    /// test user owns never is.
    #[test]
    fn proc_facts_trust_only_root_owned_system_executables() {
        let dir = tempfile::TempDir::new().unwrap();
        let proc_root = dir.path().join("proc");
        std::fs::create_dir_all(proc_root.join("1")).unwrap();
        let target = Path::new("/bin/sh")
            .canonicalize()
            .unwrap_or_else(|_| PathBuf::from("/bin/sh"));
        std::os::unix::fs::symlink(&target, proc_root.join("1/exe")).unwrap();
        let f = ProcFacts::new(&proc_root);
        let (path, digest) = f.trusted_exe(1).expect("a root-owned system shell");
        assert_eq!(Path::new(&path), target);
        assert_eq!(
            digest,
            <[u8; 32]>::from(Sha256::digest(std::fs::read(&target).unwrap()))
        );
        // Cached: the same answer again.
        assert_eq!(f.trusted_exe(1), Some((path, digest)));
        // A file outside the system trees (owned by the test user).
        let mine = dir.path().join("mine");
        std::fs::write(&mine, b"x").unwrap();
        std::fs::create_dir_all(proc_root.join("2")).unwrap();
        std::os::unix::fs::symlink(&mine, proc_root.join("2/exe")).unwrap();
        assert_eq!(f.trusted_exe(2), None);
    }
}
