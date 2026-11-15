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
//! ([`ProcFacts`]: a process's uid and cgroup — lot 277: and whether it
//! started in that cgroup, the kernel's marks — its executable opened,
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
use crate::decision::rule_policy::{ActorFacts, ExemptionFact};

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

    /// Lot 353 (re-check 2 of #563, R2-3): beneath the anchored `/proc`
    /// root (the host's view `/proc/1/root/…`).
    fn host_lstat(path: &Path) -> io::Result<(bool, std::time::SystemTime)> {
        let m = antitamper_bpf::kernel_roots::symlink_metadata(path)?;
        Ok((m.is_file(), m.modified()?))
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

    /// Lot 283b: `login.defs`' `UID_MIN` and `passwd`'s shell, of the
    /// host's view ([`crate::accounts`]).
    fn account_kind(uid: u32) -> nn_core::decision::host::AccountKind {
        crate::accounts::kind(uid)
    }
}

/// [`ProcFacts::trusted_exe`]'s work, on its helper thread.
fn trusted_exe_now(root: &Path, hashes: &Mutex<HashCache>, pid: u32) -> Option<(String, [u8; 32])> {
    use std::os::unix::fs::MetadataExt;
    let link = root.join(pid.to_string()).join("exe");
    let path = antitamper_bpf::kernel_roots::read_link(&link).ok()?;
    let path_s = path.to_str()?.to_string();
    if !crate::posture::lineage::in_system_tree(&path_s) {
        return None;
    }
    // Lot 353 (re-check 2 of #563, R2-2): the image opened through the
    // magic link beneath the `/proc` root the start anchored — by path,
    // a FUSE over `/proc` held the decision thread on this open (a rule
    // with an `exe … sha256` exemption)
    let mut f = antitamper_bpf::kernel_roots::open(&link, libc::O_RDONLY).ok()?;
    let m = f.metadata().ok()?;
    if !m.file_type().is_file() || !root_only(&m) {
        return None;
    }
    // The opened file is the one at the path it names now.
    let at_path = antitamper_bpf::kernel_roots::symlink_metadata(&path).ok()?;
    if at_path.dev() != m.dev() || at_path.ino() != m.ino() {
        return None;
    }
    let mut dir = path.parent();
    while let Some(d) = dir {
        if !root_only(&antitamper_bpf::kernel_roots::symlink_metadata(d).ok()?) {
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
    let digest = hash_file(hashes, &mut f, key)?;
    Some((path_s, digest))
}
fn hash_file(hashes: &Mutex<HashCache>, f: &mut std::fs::File, key: FileKey) -> Option<[u8; 32]> {
    use std::io::Read as _;
    if let Some(h) = hashes.lock().map.get(&key) {
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
    let mut c = hashes.lock();
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
// ── the exemption facts (from `decision::rule_policy`, R08b) ───────────

/// [`ActorFacts`] read from a `/proc` (the host's, or an empty one in the
/// golden replay).
pub struct ProcFacts {
    root: PathBuf,
    hashes: Arc<Mutex<HashCache>>,
}

/// Lot 357 (#563's §47.1, the coordinator's choice of 15/11): how long the
/// decision thread waits for an image's identity and digest
/// ([`ProcFacts::trusted_exe`]), and the reader that bounds it (four checks
/// unanswered at most, then each refused at once). Its path, its parents' modes and its digest are
/// read on a helper thread: a FUSE over a system directory (root's, not
/// one the mount guard covers: `/usr/sbin`, `/usr/lib`…) held the decision
/// on them. Unanswered: not trusted — the exemption does not hold for that
/// event; the helper's answer still fills the digest cache.
const EXE_DEADLINE: std::time::Duration = std::time::Duration::from_millis(500);
static EXE_READER: std::sync::LazyLock<crate::state_read::TimedReader> =
    std::sync::LazyLock::new(|| crate::state_read::TimedReader::new(EXE_DEADLINE, 4));

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
            hashes: Arc::new(Mutex::new(HashCache::default())),
        }
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
        let s =
            crate::state_read::read_state(self.root.join(pid.to_string()).join("status")).ok()?;
        s.lines()
            .find_map(|l| l.strip_prefix("Uid:"))
            .and_then(|r| r.split_whitespace().next())
            .and_then(|u| u.parse().ok())
    }

    fn cgroup(&self, pid: u32) -> Option<String> {
        let s =
            crate::state_read::read_state(self.root.join(pid.to_string()).join("cgroup")).ok()?;
        // lot 312 (review of #543, F7): the one reader of a cgroup text
        nn_core::response::cgroup::unified_path(&s).map(str::to_string)
    }

    fn trusted_exe(&self, pid: u32) -> Option<(String, [u8; 32])> {
        // Lot 357: off the decision thread, bounded ([`EXE_READER`])
        let (root, hashes) = (self.root.clone(), Arc::clone(&self.hashes));
        EXE_READER
            .run(&format!("the image of pid {pid}"), move || {
                trusted_exe_now(&root, &hashes, pid)
            })
            .ok()
            .flatten()
    }

    /// Lot 277: the kernel's marks ([`crate::cgroup_join`]); not known
    /// without the boot's tracker (a test, a tool, a kernel without it).
    fn started_in_cgroup(&self, pid: u32) -> Option<bool> {
        crate::cgroup_join::started_in_cgroup(&self.root, pid)
    }

    /// Lot 281: the injection taint in the same marks; not known without
    /// the boot's tracker.
    fn injected(&self, pid: u32) -> Option<nn_core::decision::rule_policy::Injected> {
        crate::cgroup_join::injected(&self.root, pid)
    }

    /// Lot 353 (re-check 4 of #563): the file `fact` is read from, read
    /// again — an error but "not there" (the process gone, a kernel
    /// thread's `exe`) is why it cannot be: a mount laid below
    /// `/proc/<pid>` (`EXDEV`, a file system not the kernel's), a read that
    /// did not answer within its deadline.
    fn unread(&self, pid: u32, fact: ExemptionFact) -> Option<String> {
        let dir = self.root.join(pid.to_string());
        let (at, r) = match fact {
            ExemptionFact::Uid => {
                let at = dir.join("status");
                let r = crate::state_read::read_state(&at).map(drop);
                (at, r)
            }
            ExemptionFact::Cgroup => {
                let at = dir.join("cgroup");
                let r = crate::state_read::read_state(&at).map(drop);
                (at, r)
            }
            ExemptionFact::Exe => {
                let at = dir.join("exe");
                let r = antitamper_bpf::kernel_roots::read_link(&at).and_then(|p| {
                    if crate::posture::lineage::in_system_tree(&p.to_string_lossy()) {
                        antitamper_bpf::kernel_roots::open(&at, libc::O_RDONLY).map(drop)
                    } else {
                        Ok(())
                    }
                });
                (at, r)
            }
        };
        match r {
            Ok(()) => None,
            Err(e) if matches!(e.raw_os_error(), Some(libc::ENOENT | libc::ESRCH)) => None,
            Err(e) => Some(format!("{}: {e}", at.display())),
        }
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

    /// Lot 353 (re-check 4 of #563, P2; named): a fact whose file is there
    /// but cannot be read is unread, naming the file — a process gone (no
    /// file) or a file that reads is not; on 8c1c5d12 there was no telling
    /// them apart, and an exemption judged by an unread fact was "none".
    #[test]
    fn a_fact_that_cannot_be_read_is_told_from_a_process_gone() {
        let dir = tempfile::TempDir::new().unwrap();
        let root = dir.path();
        // 7: readable; 8: its status and cgroup are directories (not read);
        // 9: gone
        std::fs::create_dir_all(root.join("7")).unwrap();
        std::fs::write(root.join("7/status"), "Uid:\t5\t5\t5\t5\n").unwrap();
        std::fs::write(root.join("7/cgroup"), "0::/x.slice\n").unwrap();
        std::fs::create_dir_all(root.join("8/status")).unwrap();
        std::fs::create_dir_all(root.join("8/cgroup")).unwrap();
        let f = ProcFacts::new(root);
        assert_eq!(f.unread(7, ExemptionFact::Uid), None);
        assert_eq!(f.unread(7, ExemptionFact::Cgroup), None);
        assert_eq!(f.unread(9, ExemptionFact::Uid), None);
        assert_eq!(f.unread(9, ExemptionFact::Exe), None);
        for (fact, file) in [
            (ExemptionFact::Uid, "status"),
            (ExemptionFact::Cgroup, "cgroup"),
        ] {
            let why = f.unread(8, fact).expect("unread");
            assert!(
                why.starts_with(&format!("{}", root.join("8").join(file).display())),
                "{why}"
            );
        }
        assert_eq!(f.uid(8), None);
        // an executable link of the system tree that does not open
        std::fs::create_dir_all(root.join("10")).unwrap();
        std::os::unix::fs::symlink("/usr/bin/nn-test-353-none", root.join("10/exe")).unwrap();
        assert_eq!(
            f.unread(10, ExemptionFact::Exe),
            None,
            "not there: a process gone"
        );
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

    /// Lot 311 (N6): the actor facts of a process whose `comm` is not UTF-8
    /// — its uid for a policy's exception — are read; on main they were
    /// not, and no `uid` condition matched it.
    #[test]
    fn the_facts_of_a_process_whose_comm_is_not_utf8_are_read() {
        let t = tempfile::tempdir().unwrap();
        crate::state_read::testing::write_non_utf8_proc(t.path(), 4302, 1, 33, 1);
        std::fs::write(
            t.path().join("4302/cgroup"),
            b"0::/system.slice/\xff.service\n",
        )
        .unwrap();
        let f = ProcFacts::new(t.path());
        assert_eq!(f.uid(4302), Some(33));
        assert_eq!(
            f.cgroup(4302).as_deref(),
            Some("/system.slice/\u{fffd}.service")
        );
    }
}
