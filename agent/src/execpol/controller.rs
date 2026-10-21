//! The exec policy's controller (lab PR 226): one thread that reads the
//! kernel's reports into signed records and keeps the maps the kernel
//! decides with current — the systemd slices (`user.slice` may appear after
//! the agent starts), the images (an upgraded `sudo` or `runc` is a new
//! inode, init re-executes itself), the guarded mount roots when the exec
//! quarantine is off. The decisions are the kernel's: nothing here is on
//! an exec's path.

use std::os::fd::{AsRawFd, RawFd};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use common::wire::execpol::{counter, ExecPolRaw};
use common::wire::execq::ExecqKey;
use tracing::{debug, warn};

use super::kernel;
use super::record::{event_of, records_of, Recorder, Repeats};
use super::COUNTERS;

/// How often the slices, the images and the roots are read again.
pub const REFRESH_EVERY: Duration = Duration::from_secs(10);
/// A record-only finding is not repeated within this window.
pub const REPEAT_WINDOW: Duration = Duration::from_secs(600);

/// The kernel side (the BPF maps and ring in production, a fake in tests).
pub trait KernelIo {
    fn ring_fd(&self) -> Option<RawFd>;
    fn drain(&mut self, out: &mut Vec<ExecPolRaw>);
    fn set_slices(&mut self, system: u64, user: u64);
    fn set_images(&mut self, entries: &[(ExecqKey, u32)]);
    fn set_roots(&mut self, roots: &[(ExecqKey, u32)]);
    fn counters(&self) -> [u64; counter::SLOTS as usize];
}

impl KernelIo for kernel::Kernel {
    fn ring_fd(&self) -> Option<RawFd> {
        Some(self.ring.as_raw_fd())
    }
    fn drain(&mut self, out: &mut Vec<ExecPolRaw>) {
        while let Some(item) = self.ring.next() {
            match bytemuck::try_from_bytes::<ExecPolRaw>(&item) {
                Ok(r) => out.push(*r),
                Err(_) => {
                    self.reject
                        .record("execpol", std::mem::size_of::<ExecPolRaw>(), item.len())
                }
            }
        }
    }
    fn set_slices(&mut self, system: u64, user: u64) {
        kernel::Kernel::set_slices(self, system, user)
    }
    fn set_images(&mut self, entries: &[(ExecqKey, u32)]) {
        kernel::Kernel::set_images(self, entries)
    }
    fn set_roots(&mut self, roots: &[(ExecqKey, u32)]) {
        kernel::Kernel::set_roots(self, roots)
    }
    fn counters(&self) -> [u64; counter::SLOTS as usize] {
        kernel::Kernel::counters(self)
    }
}

/// The controller's inputs from the host.
#[derive(Debug, Clone)]
pub struct Settings {
    /// The policy's exempt images.
    pub exempt: Vec<(PathBuf, u32)>,
    /// Where the policy came from, for the records.
    pub policy_source: String,
    /// `/proc` (init's image), `/proc/self/mountinfo` (the cgroup v2 mount,
    /// the guarded roots).
    pub proc_root: PathBuf,
    pub mountinfo: PathBuf,
    /// The guarded roots are this side's to refresh (the exec quarantine is
    /// off).
    pub own_roots: bool,
}

impl Settings {
    pub fn for_host(exempt: Vec<(PathBuf, u32)>, policy_source: String, own_roots: bool) -> Self {
        Settings {
            exempt,
            policy_source,
            proc_root: PathBuf::from("/proc"),
            mountinfo: PathBuf::from("/proc/self/mountinfo"),
            own_roots,
        }
    }
}

pub struct Controller<K: KernelIo> {
    k: K,
    r: Box<dyn Recorder>,
    s: Settings,
    repeats: Repeats,
    last_refresh: Option<Instant>,
    /// Slice ids last published (a change is logged).
    slices: (u64, u64),
    skipped_logged: bool,
}

impl<K: KernelIo> Controller<K> {
    pub fn new(k: K, r: Box<dyn Recorder>, s: Settings) -> Self {
        Controller {
            k,
            r,
            s,
            repeats: Repeats::new(REPEAT_WINDOW),
            last_refresh: None,
            slices: (0, 0),
            skipped_logged: false,
        }
    }

    /// Publish the slices, images and roots now (before the first exec the
    /// policy judges); the slice ids published.
    pub fn refresh(&mut self, now: Instant) -> (u64, u64) {
        let text = std::fs::read_to_string(&self.s.mountinfo).unwrap_or_default();
        let ids = kernel::cgroup2_mount(&text)
            .map(|mp| kernel::slice_ids(std::path::Path::new(&mp)))
            .unwrap_or((0, 0));
        if ids != self.slices {
            debug!(
                system_slice = ids.0,
                user_slice = ids.1,
                "exec policy: systemd slices published"
            );
            self.slices = ids;
        }
        self.k.set_slices(ids.0, ids.1);
        let mut skipped = Vec::new();
        let images = kernel::image_entries(&self.s.exempt, &self.s.proc_root, &mut skipped);
        if !skipped.is_empty() && !self.skipped_logged {
            warn!(skipped = ?skipped, "exec policy: exempt images not used");
            self.skipped_logged = true;
        }
        self.k.set_images(&images);
        if self.s.own_roots {
            self.k
                .set_roots(&crate::execq::kernel::guarded_roots(&text));
        }
        self.last_refresh = Some(now);
        ids
    }

    /// One pass: refresh when due, the ring into records, the counters.
    pub fn step(&mut self, now: Instant) {
        if self
            .last_refresh
            .is_none_or(|t| now.duration_since(t) >= REFRESH_EVERY)
        {
            self.refresh(now);
        }
        let mut raws = Vec::new();
        self.k.drain(&mut raws);
        for raw in raws {
            let event = event_of(&raw);
            for rec in records_of(&raw, &event, &self.s.policy_source) {
                if self.repeats.admit(&rec, now) {
                    COUNTERS.records.fetch_add(1, Ordering::Relaxed);
                    self.r.detection(rec);
                }
            }
        }
        COUNTERS.store_kernel(&self.k.counters());
    }

    /// The loop, until `stopping`.
    pub fn run(mut self, stopping: &AtomicBool) {
        loop {
            if stopping.load(Ordering::Relaxed) {
                return;
            }
            self.step(Instant::now());
            let mut fds: Vec<libc::pollfd> = self
                .k
                .ring_fd()
                .into_iter()
                .map(|fd| libc::pollfd {
                    fd,
                    events: libc::POLLIN,
                    revents: 0,
                })
                .collect();
            // SAFETY: a valid array of pollfds for the duration of the call.
            unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, 250) };
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::execpol::record::VecRecorder;
    use common::wire::execpol::{action, env_flags, kind, tier, tier_sig};
    use common::wire::execq::class;

    #[derive(Default)]
    struct FakeKernel {
        queue: Vec<ExecPolRaw>,
        slices: (u64, u64),
        images: Vec<(ExecqKey, u32)>,
        roots: Vec<(ExecqKey, u32)>,
        counters: [u64; counter::SLOTS as usize],
    }

    impl KernelIo for FakeKernel {
        fn ring_fd(&self) -> Option<RawFd> {
            None
        }
        fn drain(&mut self, out: &mut Vec<ExecPolRaw>) {
            out.append(&mut self.queue);
        }
        fn set_slices(&mut self, system: u64, user: u64) {
            self.slices = (system, user);
        }
        fn set_images(&mut self, entries: &[(ExecqKey, u32)]) {
            self.images = entries.to_vec();
        }
        fn set_roots(&mut self, roots: &[(ExecqKey, u32)]) {
            self.roots = roots.to_vec();
        }
        fn counters(&self) -> [u64; counter::SLOTS as usize] {
            self.counters
        }
    }

    fn settings(d: &std::path::Path, own_roots: bool) -> Settings {
        // a cgroup2 mount at <d>/cg with both slices, a guarded /tmp
        let cg = d.join("cg");
        std::fs::create_dir_all(cg.join("system.slice")).unwrap();
        std::fs::create_dir_all(cg.join("user.slice")).unwrap();
        let mi = d.join("mountinfo");
        std::fs::write(
            &mi,
            format!(
                "24 1 0:22 / {} rw shared:9 - cgroup2 cgroup2 rw\n30 1 0:5 / /tmp rw - tmpfs tmpfs rw\n",
                cg.display()
            ),
        )
        .unwrap();
        Settings {
            exempt: vec![],
            policy_source: "server profile (built in)".into(),
            proc_root: d.to_path_buf(),
            mountinfo: mi,
            own_roots,
        }
    }

    #[test]
    fn the_slices_and_roots_are_published() {
        let d = tempfile::tempdir().unwrap();
        let rec = VecRecorder::default();
        let mut c = Controller::new(
            FakeKernel::default(),
            Box::new(rec),
            settings(d.path(), true),
        );
        let ids = c.refresh(Instant::now());
        use std::os::unix::fs::MetadataExt;
        let sys = std::fs::metadata(d.path().join("cg/system.slice"))
            .unwrap()
            .ino();
        assert_eq!(ids.0, sys);
        assert_eq!(c.k.slices, ids);
        assert!(ids.1 != 0);
        let tmp = std::fs::metadata("/tmp").unwrap().ino();
        assert!(
            c.k.roots.iter().any(|(k, _)| k.ino == tmp),
            "the tmpfs /tmp: {:?}",
            c.k.roots
        );
        // not ours to refresh while the exec quarantine runs
        let mut c = Controller::new(
            FakeKernel::default(),
            Box::new(VecRecorder::default()),
            settings(d.path(), false),
        );
        c.refresh(Instant::now());
        assert!(c.k.roots.is_empty());
    }

    #[test]
    fn reports_become_records_once() {
        let d = tempfile::tempdir().unwrap();
        let rec = VecRecorder::default();
        let mut c = Controller::new(
            FakeKernel::default(),
            Box::new(rec.clone()),
            settings(d.path(), true),
        );
        let mut deny = ExecPolRaw::zeroed();
        deny.kind = kind::EXEC;
        deny.pid = 77;
        deny.classes = class::MEMFD;
        deny.action = action::DENY;
        deny.tier = tier::SERVICE | tier_sig::SYSTEM_SLICE;
        let mut hist = ExecPolRaw::zeroed();
        hist.kind = kind::EXEC;
        hist.env_flags = env_flags::HISTSIZE_ZERO;
        hist.env_action = action::RECORD;
        hist.tier = tier::SESSION;
        // a shell's path is what makes the history trick count; the
        // walk-less raw has none, so it is not recorded
        c.k.queue = vec![deny, deny, hist];
        c.k.counters[counter::DENIED as usize] = 2;
        c.step(Instant::now());
        let got = rec.0.lock();
        assert_eq!(got.len(), 2, "two denies, each recorded");
        assert!(got
            .iter()
            .all(|r| r.verdict.rule_id == crate::execpol::RULE_EXEC));
        assert_eq!(got[0].evidence.policy, "server profile (built in)");
        drop(got);
        assert!(crate::execpol::snapshot().denied >= 2);
    }
}
