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
use crate::execq::kernel::RootsRefused;

/// How often the slices, the images and the roots are read again.
pub const REFRESH_EVERY: Duration = Duration::from_secs(10);
/// A record-only finding is not repeated within this window.
pub const REPEAT_WINDOW: Duration = Duration::from_secs(600);

/// The kernel side (the BPF maps and ring in production, a fake in tests).
pub trait KernelIo {
    fn ring_fd(&self) -> Option<RawFd>;
    fn drain(&mut self, out: &mut Vec<ExecPolRaw>);
    fn set_slices(&mut self, system: u64, user: u64, ours: u64);
    fn set_images(&mut self, entries: &[(ExecqKey, u32)]);
    /// What the kernel's map refused of the (ranked) roots.
    fn set_roots(&mut self, roots: &[(ExecqKey, u32)]) -> RootsRefused;
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
    fn set_slices(&mut self, system: u64, user: u64, ours: u64) {
        kernel::Kernel::set_slices(self, system, user, ours)
    }
    fn set_images(&mut self, entries: &[(ExecqKey, u32)]) {
        kernel::Kernel::set_images(self, entries)
    }
    fn set_roots(&mut self, roots: &[(ExecqKey, u32)]) -> RootsRefused {
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
    slices: (u64, u64, u64),
    skipped_logged: bool,
    /// Lot 311 (bug hunt 1.4, BUG-98's sibling): a mount table that cannot
    /// be read leaves the slices and roots last published in force, signed.
    mounts_read: nn_linux::state_read::LastGood,
    /// Lot 311 (the review of #538): lines of the table not in the
    /// kernel's shape, and roots the kernel's map refused, signed.
    mounts_rows: nn_linux::state_read::Condition,
    roots_full: RootsFull,
}

impl<K: KernelIo> Controller<K> {
    pub fn new(k: K, r: Box<dyn Recorder>, s: Settings) -> Self {
        Controller {
            k,
            r,
            s,
            repeats: Repeats::new(REPEAT_WINDOW),
            last_refresh: None,
            slices: (0, 0, 0),
            skipped_logged: false,
            mounts_read: nn_linux::state_read::LastGood::new("execpol_mounts", "the mount table"),
            mounts_rows: nn_linux::state_read::Condition::new("execpol_mounts_rows"),
            roots_full: RootsFull::new("execpol_roots_full"),
        }
    }

    /// Publish the slices, images and roots now (before the first exec the
    /// policy judges); the slice ids published.
    pub fn refresh(&mut self, now: Instant) -> (u64, u64, u64) {
        // lot 311 (BUG-98's sibling): the table read as bytes — one FUSE
        // mount of a user's, named with bytes that are not UTF-8, emptied
        // it: the slices unpublished (every caller UNKNOWN, a service's
        // deny an audit) and the roots removed; a table that cannot be read
        // at all keeps what was last published
        let table = match nn_linux::mountinfo::read(&self.s.mountinfo) {
            Ok(table) => {
                self.mounts_read.ok();
                nn_linux::state_read::mount_rows(&mut self.mounts_rows, &table, "the exec policy");
                Some(table)
            }
            Err(e) => {
                self.mounts_read.failed(&e);
                None
            }
        };
        if let Some(table) = &table {
            let ids = kernel::cgroup2_mount(table)
                .map(|mp| kernel::slice_ids(&mp))
                .unwrap_or((0, 0, 0));
            if ids != self.slices {
                debug!(
                    system_slice = ids.0,
                    user_slice = ids.1,
                    our_slice = ids.2,
                    "exec policy: systemd slices published"
                );
                self.slices = ids;
            }
            self.k.set_slices(ids.0, ids.1, ids.2);
        }
        let mut skipped = Vec::new();
        let images = kernel::image_entries(&self.s.exempt, &self.s.proc_root, &mut skipped);
        if !skipped.is_empty() && !self.skipped_logged {
            warn!(skipped = ?skipped, "exec policy: exempt images not used");
            self.skipped_logged = true;
        }
        self.k.set_images(&images);
        if let (true, Some(table)) = (self.s.own_roots, &table) {
            let roots = crate::execq::kernel::published_roots(table);
            let refused = self.k.set_roots(&roots);
            self.roots_full.published(refused, roots.len(), now);
        }
        self.last_refresh = Some(now);
        self.slices
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

/// Lot 311 (the review of #538, G2): the least time a refusal of the
/// roots' map stands as a degradation once reported — a count that comes
/// and goes is one signed record per hold, not one per re-read.
pub(crate) const ROOTS_FULL_HOLD: Duration = Duration::from_secs(300);

/// Lot 311 (the review of #538, F3, G2): what the kernel's map
/// (`EXECQ_ROOTS`, 1024 entries since lot 318) refused of the ranked roots
/// ([`crate::execq::kernel::publish_ranked`]: the FUSE ones give way
/// first). A root other than a FUSE one left out is a degradation (a
/// mount without its class), held [`ROOTS_FULL_HOLD`] at least, its text
/// the same whatever the count. A FUSE root left out is no loss — the exec
/// hooks class a FUSE file by its file system's magic (lot 318) — and no
/// record: a user mounts as many as `mount_max`, and would sign rows at
/// will; it is logged when it starts and ends.
#[derive(Debug)]
pub(crate) struct RootsFull {
    lost: nn_linux::state_read::Condition,
    fuse_left_out: bool,
}

impl RootsFull {
    pub(crate) const fn new(source: &'static str) -> Self {
        RootsFull {
            lost: nn_linux::state_read::Condition::with_hold(source, ROOTS_FULL_HOLD),
            fuse_left_out: false,
        }
    }

    /// The roots were published at `now`, `of` of them, `refused` left out.
    pub(crate) fn published(&mut self, refused: RootsRefused, of: usize, now: Instant) {
        let fuse = refused.fuse > 0;
        if fuse != self.fuse_left_out {
            if fuse {
                warn!(
                    refused = refused.fuse,
                    of,
                    "guarded roots: FUSE mounts past the kernel's map (1024 entries) left out — \
                     their files are classed by the file system's magic"
                );
            } else {
                debug!("guarded roots: every FUSE root published again");
            }
            self.fuse_left_out = fuse;
        }
        if refused.other == 0 {
            self.lost.ended_at(now);
        } else {
            if !self.lost.holding() {
                warn!(
                    refused = refused.other,
                    of, "guarded roots refused by the kernel's map"
                );
            }
            self.lost.holds_at(
                "guarded mount roots (not FUSE ones) not published: the kernel's map \
                 (EXECQ_ROOTS, 1024 entries) refused them — exec from those mounts has no mount \
                 class"
                    .into(),
                now,
            );
        }
    }

    /// The degradation stands (tests).
    #[cfg(test)]
    pub(crate) fn holding(&self) -> bool {
        self.lost.holding()
    }

    /// How many times it was reported (tests).
    #[cfg(test)]
    pub(crate) fn reports(&self) -> u32 {
        self.lost.reports()
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
        slices: (u64, u64, u64),
        images: Vec<(ExecqKey, u32)>,
        roots: Vec<(ExecqKey, u32)>,
        counters: [u64; counter::SLOTS as usize],
        /// Lot 311 (F3): the roots map's size (`None`: unbounded).
        cap: Option<usize>,
    }

    impl KernelIo for FakeKernel {
        fn ring_fd(&self) -> Option<RawFd> {
            None
        }
        fn drain(&mut self, out: &mut Vec<ExecPolRaw>) {
            out.append(&mut self.queue);
        }
        fn set_slices(&mut self, system: u64, user: u64, ours: u64) {
            self.slices = (system, user, ours);
        }
        fn set_images(&mut self, entries: &[(ExecqKey, u32)]) {
            self.images = entries.to_vec();
        }
        fn set_roots(&mut self, roots: &[(ExecqKey, u32)]) -> RootsRefused {
            // lot 311 (F3, G2): a map of `cap` entries keeps the ranked
            // list's head
            let cap = self.cap.unwrap_or(usize::MAX);
            self.roots = roots.iter().take(cap).copied().collect();
            RootsRefused::of_tail(roots, cap)
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
                "24 1 0:22 / {} rw shared:9 - cgroup2 cgroup2 rw\n{}",
                cg.display(),
                crate::execq::kernel::tmp_mount_line(30)
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
        // the short re-check of #497 (NB5): the units' own slice, published
        // for the kernel's service tier (UNKNOWN for them would be a
        // regression of lot 273d's slice)
        std::fs::create_dir_all(d.path().join("cg/northnarrow.slice")).unwrap();
        let ids = c.refresh(Instant::now());
        use std::os::unix::fs::MetadataExt;
        let sys = std::fs::metadata(d.path().join("cg/system.slice"))
            .unwrap()
            .ino();
        assert_eq!(ids.0, sys);
        assert_eq!(c.k.slices, ids);
        assert!(ids.1 != 0);
        let ours = std::fs::metadata(d.path().join("cg/northnarrow.slice"))
            .unwrap()
            .ino();
        assert_eq!(ids.2, ours);
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

    /// Lot 311 (bug hunt 1.4, BUG-98's sibling): a mount table that is not
    /// UTF-8 (one FUSE mount point with a 0xff byte, which an unprivileged
    /// user makes with `fusermount3`) does not unpublish the slices (every
    /// caller UNKNOWN, NO_SLICES) nor the guarded roots.
    #[test]
    fn a_non_utf8_mount_point_keeps_slices_and_roots() {
        let d = tempfile::tempdir().unwrap();
        let s = settings(d.path(), true);
        let mut text = std::fs::read(&s.mountinfo).unwrap();
        text.extend_from_slice(
            b"57 1 0:44 / /home/u/\xff rw,nosuid,nodev - fuse.x x rw,user_id=1000\n",
        );
        std::fs::write(&s.mountinfo, &text).unwrap();
        let mut c = Controller::new(FakeKernel::default(), Box::new(VecRecorder::default()), s);
        let ids = c.refresh(Instant::now());
        assert!(
            ids.0 != 0 && ids.1 != 0,
            "slices unpublished by one non-UTF-8 line: {ids:?}"
        );
        use std::os::unix::fs::MetadataExt;
        let tmp = std::fs::metadata("/tmp").unwrap().ino();
        assert!(
            c.k.roots.iter().any(|(k, _)| k.ino == tmp),
            "guarded roots emptied: {:?}",
            c.k.roots
        );
    }

    /// Lot 311 (F4): a mount table that cannot be read at all leaves the
    /// slices and roots last published in force (never zeros, never an
    /// empty set), with a degradation while it fails; the next good read
    /// publishes again and withdraws it.
    #[test]
    fn an_unreadable_mount_table_keeps_what_was_published() {
        let d = tempfile::tempdir().unwrap();
        let s = settings(d.path(), true);
        let mi = s.mountinfo.clone();
        let mut c = Controller::new(FakeKernel::default(), Box::new(VecRecorder::default()), s);
        let good = c.refresh(Instant::now());
        let roots = c.k.roots.clone();
        assert!(good.0 != 0 && !roots.is_empty());
        // the controller's own account (the registry is shared by the tests)
        let saved = std::fs::read(&mi).unwrap();
        std::fs::remove_file(&mi).unwrap();
        c.k.slices = (7, 7, 7);
        assert_eq!(c.refresh(Instant::now()), good, "the last good slices");
        assert_eq!(c.k.slices, (7, 7, 7), "nothing written over the kernel's");
        assert_eq!(c.k.roots, roots, "the roots kept");
        assert!(c.mounts_read.failing());
        std::fs::write(&mi, saved).unwrap();
        assert_eq!(c.refresh(Instant::now()), good);
        assert_eq!(c.k.slices, good, "published again");
        assert!(!c.mounts_read.failing(), "withdrawn");
    }

    /// Lot 311 (the review of #538, F2, F3): a FUSE mount whose source is
    /// `-` keeps the slices and is a root (by its device); a line not in the
    /// kernel's shape, and roots the map refuses, are degradations.
    #[test]
    fn a_dash_source_line_keeps_slices_and_roots_and_losses_are_signed() {
        let d = tempfile::tempdir().unwrap();
        let s = settings(d.path(), true);
        let mi = s.mountinfo.clone();
        let mut text = std::fs::read(&mi).unwrap();
        text.extend_from_slice(b"57 1 0:44 / /home/u/mnt rw,nosuid - fuse.x - rw,user_id=1000\n");
        std::fs::write(&mi, &text).unwrap();
        let mut c = Controller::new(FakeKernel::default(), Box::new(VecRecorder::default()), s);
        let ids = c.refresh(Instant::now());
        assert!(ids.0 != 0 && ids.1 != 0, "{ids:?}");
        assert!(c.k.roots.iter().any(|(k, _)| *k
            == ExecqKey {
                dev: 44,
                ino: crate::execq::kernel::FUSE_BY_DEVICE
            }));
        assert!(!c.mounts_rows.holding());
        let mut odd = text.clone();
        odd.extend_from_slice(b"58 1 0:45 / /tmp/x rw tmpfs x rw\n");
        std::fs::write(&mi, &odd).unwrap();
        c.refresh(Instant::now());
        assert!(c.mounts_rows.holding(), "a dropped line is signed");
        c.k.cap = Some(0);
        c.refresh(Instant::now());
        assert!(c.roots_full.holding(), "refused roots are signed");
    }
}
