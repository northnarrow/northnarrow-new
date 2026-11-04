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

/// Review of #482 (R14c-6): the longest an `rpm -qf` may take — under the
/// errand's own wait ([`crate::caps::errands::ERRAND_WAIT`]).
const RPM_WAIT: std::time::Duration = std::time::Duration::from_millis(1500);
const _: () = assert!(RPM_WAIT.as_millis() < crate::caps::errands::ERRAND_WAIT.as_millis());

impl DecisionHost for LinuxHost {
    fn off_the_runtime<T>(f: impl FnOnce() -> T) -> T {
        crate::runtime::off_the_runtime(f)
    }

    /// `trusted_bin::resolve("rpm")`, then `rpm -qf --quiet <path>` with its
    /// output discarded. R14c: on the errands thread
    /// ([`crate::caps::errands`]) — the rules run on the decision thread,
    /// whose filter refuses it `execve`.
    fn rpm_owns(path: &str) -> Result<Option<bool>, String> {
        let path = path.to_string();
        crate::caps::errands::run(move || {
            let rpm = crate::trusted_bin::resolve("rpm").map_err(|e| e.to_string())?;
            let mut cmd = rpm.command();
            // review of #482 (R14c-6): `--` before the path (a path is
            // never an option), and a deadline (a hung rpm is killed: the
            // errands thread goes on)
            cmd.args(["-qf", "--quiet", "--", &path]);
            let out = crate::bounded_cmd::run_bounded(cmd, None, RPM_WAIT, "rpm -qf");
            Ok(out.ok().map(|o| o.status.success()))
        })
        .unwrap_or_else(|| Err("the errands thread did not answer".to_string()))
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
        map.insert(pid)
    }

    fn defender_map_remove(map: &mut Self::DefenderMap, pid: u32) {
        map.remove(pid);
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

    /// Tokio's `Notify`, which the net drain awaits (lab PR 246).
    type FlowNotify = tokio::sync::Notify;

    fn notify_flow_waiters(notify: &tokio::sync::Notify) {
        notify.notify_waiters();
    }

    /// Lot 279: `st_ctime` (seconds and nanoseconds); `None` before the
    /// epoch.
    fn inode_changed(meta: &std::fs::Metadata) -> Option<std::time::SystemTime> {
        use std::os::unix::fs::MetadataExt;
        let secs = u64::try_from(meta.ctime()).ok()?;
        let nanos = u32::try_from(meta.ctime_nsec()).ok()?.min(999_999_999);
        Some(std::time::UNIX_EPOCH + std::time::Duration::new(secs, nanos))
    }
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

    /// Lot 279, R011's module files on the Linux host: their age is
    /// `max(mtime, ctime)` (the mtime set back does not make a file old),
    /// a link in the tree or a directory linked out of it is not vouched
    /// for, a merged `/usr` (`/lib` a link to `usr/lib`) is the tree's own.
    #[test]
    fn module_files_are_judged_by_their_inode() {
        use nn_core::decision::rules::module_request::{Assessment, ModuleRequests};
        use std::time::{Duration, SystemTime};
        let rel = "6.8.0-279-generic";
        let new_host = |merged: bool| {
            let host = tempfile::tempdir().unwrap();
            let w = |p: &str, text: &str| {
                let p = host.path().join(p);
                std::fs::create_dir_all(p.parent().unwrap()).unwrap();
                std::fs::write(p, text).unwrap();
            };
            if merged {
                std::fs::create_dir_all(host.path().join("usr/lib")).unwrap();
                std::os::unix::fs::symlink("usr/lib", host.path().join("lib")).unwrap();
            }
            w("proc/sys/kernel/osrelease", &format!("{rel}\n"));
            w(
                &format!("lib/modules/{rel}/kernel/net/nf_tables.ko"),
                "\x7fELF",
            );
            w(&format!("lib/modules/{rel}/kernel/net/dummy.ko"), "\x7fELF");
            w("tmp/staged/veth.ko", "\x7fELF");
            w("tmp/rk.ko", "\x7fELF");
            std::os::unix::fs::symlink(
                host.path().join("tmp/staged"),
                host.path().join(format!("lib/modules/{rel}/kernel/linked")),
            )
            .unwrap();
            std::os::unix::fs::symlink(
                host.path().join("tmp/rk.ko"),
                host.path()
                    .join(format!("lib/modules/{rel}/kernel/net/lnk.ko")),
            )
            .unwrap();
            let mods = [
                "kernel/net/nf_tables.ko",
                "kernel/net/dummy.ko",
                "kernel/linked/veth.ko",
                "kernel/net/lnk.ko",
            ];
            let dep: String = mods.iter().map(|m| format!("{m}:\n")).collect();
            w(&format!("lib/modules/{rel}/modules.dep"), &dep);
            let list: String = mods
                .iter()
                .map(|m| format!("/lib/modules/{rel}/{m}\n"))
                .collect();
            w("var/lib/dpkg/info/linux-modules.list", &list);
            w("var/lib/dpkg/status", "Package: linux-modules\n");
            let later = SystemTime::now() + Duration::from_secs(3600);
            std::fs::File::options()
                .write(true)
                .open(host.path().join("var/lib/dpkg/status"))
                .unwrap()
                .set_modified(later)
                .unwrap();
            host
        };
        static PID: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
        let assess = |host: &tempfile::TempDir, name: &str| -> Assessment {
            let n = PID.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let e = nn_model::Event::ProcessSpawn {
                pid: u32::MAX - 2790 - n,
                ppid: 1,
                uid: 0,
                gid: 0,
                comm: "modprobe".into(),
                filename: "/sbin/modprobe".into(),
                timestamp_ns: 2790 + u64::from(n),
                argv: vec!["/sbin/modprobe".into(), name.into()],
                parent_comm: "dockerd".into(),
                parent_start_ns: 0,
                start_ns: 1,
                parent_is_kthread: false,
                exe: Default::default(),
                argv_truncated: false,
                filename_truncated: false,
                stdio: Default::default(),
            };
            ModuleRequests::<LinuxHost>::new(host.path()).of(&e)
        };
        let why = |a: Assessment| match a {
            Assessment::NotVouched(w) => w,
            other => panic!("vouched for: {other:?}"),
        };
        for merged in [false, true] {
            let host = new_host(merged);
            assert!(assess(&host, "nf_tables").records(), "merged /usr {merged}");
            assert!(why(assess(&host, "lnk")).contains("not a regular file"));
            assert!(why(assess(&host, "veth")).contains("a link out of"));
        }
        // the package database's last change before the files', then the
        // file's mtime set back a year: its ctime still says when
        let host = new_host(false);
        let status = host.path().join("var/lib/dpkg/status");
        let file = host
            .path()
            .join(format!("lib/modules/{rel}/kernel/net/dummy.ko"));
        let f = std::fs::File::options().write(true).open(&file).unwrap();
        f.set_modified(SystemTime::now() - Duration::from_secs(86_400 * 365))
            .unwrap();
        std::fs::File::options()
            .write(true)
            .open(&status)
            .unwrap()
            .set_modified(SystemTime::now() - Duration::from_secs(600))
            .unwrap();
        let w = why(assess(&host, "dummy"));
        assert!(
            w.contains("after the package database's last change"),
            "{w}"
        );
        assert!(LinuxHost::inode_changed(&std::fs::metadata(&file).unwrap()).is_some());
    }

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
