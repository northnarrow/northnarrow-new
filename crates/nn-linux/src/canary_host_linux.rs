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
    type ReadForward = crate::canary::read_forward::ReadForward;

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
        // Lab PR 260 (`debug-trigger` builds only): the agent stopped here,
        // between the access row and the trip mark, on request.
        #[cfg(feature = "debug-trigger")]
        registry.debug_stop_before_trip_mark();
        registry.mark_tripped(canary_id, access_hash)
    }

    /// [`CanaryAccessDb::append`]: the row's `entry_hash`.
    fn append_access(log: &mut CanaryAccessDb, draft: CanaryAccessDraft) -> anyhow::Result<String> {
        log.append(draft).map(|entry| entry.entry_hash)
    }

    fn is_local(addrs: &LocalAddrs, addr: IpAddr) -> bool {
        addrs.contains(addr)
    }

    fn publish_read_forward(
        sink: &crate::canary::read_forward::ReadForward,
        keys: impl IntoIterator<Item = InodeKey>,
    ) {
        sink.replace(keys);
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

/// Lab PR 260: the detector on this host's stores, stopped between its
/// steps — before the access row, in it (torn), after it, in the registry's
/// `Trip` row (torn), after it — and the stores opened again as at the next
/// start (the agent's boot: the registry, the access log, then each trip the
/// registry does not record recorded). An access the access log holds is a
/// trip, recorded once, and the canary's next access is not a first trip;
/// an access it does not hold never happened, and the canary is armed. On
/// the starting code the stop after the access row came back armed (lab PR
/// 258's KVM run).
#[cfg(test)]
mod stop_tests {
    use std::cell::Cell;
    use std::panic::AssertUnwindSafe;
    use std::path::PathBuf;
    use std::sync::Arc;

    use nn_core::canary::detector::{CanaryIndexes, Detector};
    use nn_model::telemetry::{FimEvent, FimOp};
    use nn_model::Event;
    use nn_proto::admin_signed_payload::{CanaryDeploymentWire, CanaryTypeWire};
    use parking_lot::Mutex;
    use tempfile::TempDir;

    use super::*;
    use crate::audit::AgentSigningKey;
    use crate::canary::access_log::CanaryAccessEntry;
    use crate::canary::registry::{CanaryToken, CanaryTokenDraft, RegistryAction, UnrecordedTrip};

    /// Where the agent stops.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum Stop {
        BeforeAccess,
        /// The access row partly on disk (a power loss in its write).
        InAccess,
        /// Between the access row and the trip mark: the finding.
        AfterAccess,
        /// The `Trip` row partly on disk.
        InTripMark,
        /// After the trip mark, before the verdict.
        AfterTripMark,
    }

    const ALL: [Option<Stop>; 6] = [
        Some(Stop::BeforeAccess),
        Some(Stop::InAccess),
        Some(Stop::AfterAccess),
        Some(Stop::InTripMark),
        Some(Stop::AfterTripMark),
        None,
    ];

    thread_local! {
        static STOP: Cell<Option<Stop>> = const { Cell::new(None) };
    }

    fn stops_at(point: Stop) -> bool {
        STOP.with(|s| s.get()) == Some(point)
    }

    /// [`LinuxHost`], stopped at the step [`STOP`] names: a panic, after
    /// which nothing of the access runs — the process gone.
    struct StoppingHost;

    impl CanaryHost for StoppingHost {
        type Registry = Registry;
        type AccessLog = CanaryAccessDb;
        type LocalAddrs = LocalAddrs;
        type ReadForward = crate::canary::read_forward::ReadForward;

        fn live(registry: &Registry) -> Vec<LiveCanary> {
            LinuxHost::live(registry)
        }

        fn is_armed(registry: &Registry, canary_id: &str) -> bool {
            LinuxHost::is_armed(registry, canary_id)
        }

        fn mark_tripped(
            registry: &mut Registry,
            canary_id: &str,
            access_hash: Option<String>,
        ) -> anyhow::Result<bool> {
            assert!(!stops_at(Stop::AfterAccess), "stopped before the trip mark");
            let marked = LinuxHost::mark_tripped(registry, canary_id, access_hash);
            assert!(
                !stops_at(Stop::InTripMark) && !stops_at(Stop::AfterTripMark),
                "stopped after the trip mark"
            );
            marked
        }

        fn append_access(
            log: &mut CanaryAccessDb,
            draft: CanaryAccessDraft,
        ) -> anyhow::Result<String> {
            assert!(
                !stops_at(Stop::BeforeAccess),
                "stopped before the access row"
            );
            let hash = LinuxHost::append_access(log, draft);
            assert!(!stops_at(Stop::InAccess), "stopped in the access row");
            hash
        }

        fn is_local(addrs: &LocalAddrs, addr: IpAddr) -> bool {
            LinuxHost::is_local(addrs, addr)
        }

        // The indexes' own set (R11c: no process-wide one any more).
        fn publish_read_forward(
            sink: &crate::canary::read_forward::ReadForward,
            keys: impl IntoIterator<Item = InodeKey>,
        ) {
            sink.replace(keys);
        }

        fn inode_key(_path: &Path) -> Option<InodeKey> {
            None
        }

        fn accessor_exe(_accessor_pid: u32) -> Option<String> {
            None
        }
    }

    const EARLIER: &str = "/srv/share/earlier.xlsx";
    const DECOY: &str = "/srv/share/payroll.xlsx";

    struct Paths {
        dir: TempDir,
    }

    impl Paths {
        fn registry(&self) -> PathBuf {
            self.dir.path().join("canaries.jsonl")
        }
        fn access(&self) -> PathBuf {
            self.dir.path().join("canary_access.jsonl")
        }
        fn key(&self) -> AgentSigningKey {
            AgentSigningKey::load_or_bootstrap(&self.dir.path().join("agent.sig.key")).unwrap()
        }
        fn stores(&self) -> (Arc<Mutex<Registry>>, Arc<Mutex<CanaryAccessDb>>) {
            (
                Arc::new(Mutex::new(
                    Registry::open(&self.registry(), self.key(), [0u8; 16]).unwrap(),
                )),
                Arc::new(Mutex::new(
                    CanaryAccessDb::open(&self.access(), self.key(), [0u8; 16]).unwrap(),
                )),
            )
        }
        fn registry_rows(&self, canary_id: &str) -> Vec<CanaryToken> {
            jsonl(&self.registry())
                .into_iter()
                .filter(|r: &CanaryToken| r.canary_id == canary_id)
                .collect()
        }
        fn access_rows(&self, canary_id: &str) -> Vec<CanaryAccessEntry> {
            jsonl(&self.access())
                .into_iter()
                .filter(|r: &CanaryAccessEntry| r.canary_id == canary_id)
                .collect()
        }
    }

    fn jsonl<T: serde::de::DeserializeOwned>(path: &Path) -> Vec<T> {
        std::fs::read_to_string(path)
            .unwrap()
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect()
    }

    /// The detector of these stores, the file canaries indexed by path (as
    /// the boot's rebuild does).
    fn detector<H: CanaryHost<Registry = Registry, AccessLog = CanaryAccessDb>>(
        registry: &Arc<Mutex<Registry>>,
        access: &Arc<Mutex<CanaryAccessDb>>,
    ) -> Detector<H> {
        let detector = Detector::new(
            Arc::clone(registry),
            Arc::clone(access),
            Arc::new(Mutex::new(CanaryIndexes::new())),
        );
        {
            let reg = registry.lock();
            let mut idx = detector.indexes().lock();
            idx.rebuild_from_registry(&*reg, |_| None);
            for canary in reg.list() {
                if let CanaryDeploymentWire::File { path, .. } = canary.deployment {
                    idx.add_file_path_index(PathBuf::from(path), canary.canary_id);
                }
            }
        }
        detector
    }

    fn open_of(path: &str, pid: u32) -> Event {
        Event::Fim(FimEvent {
            timestamp_ns: 1_700_000_000_000_000_000,
            path: path.to_string(),
            op: FimOp::Opened,
            new_sha256: None,
            baseline_sha256: None,
            new_size: None,
            baseline_size: None,
            modifier_exe: None,
            modifier_pid: pid,
            modifier_uid: 1000,
            modifier_comm: "cat".to_string(),
            dest_path: None,
            child_truncated: false,
            wide_coverage: false,
            owner_uid: None,
            reader_dac_capable: false,
            capability: None,
            attrs: None,
            file_key: None,
            is_dir: false,
            moved_in: false,
        })
    }

    fn first_trip(event: Option<Event>) -> bool {
        match event {
            Some(Event::CanaryTripped { first_trip, .. }) => first_trip,
            other => panic!("not a trip: {other:?}"),
        }
    }

    /// Cut the file's last row in its middle: a write the disk got part of.
    fn tear_last_row(path: &Path) {
        let body = std::fs::read(path).unwrap();
        assert_eq!(body.last(), Some(&b'\n'));
        let start = body[..body.len() - 1]
            .iter()
            .rposition(|&b| b == b'\n')
            .map_or(0, |nl| nl + 1);
        assert!(start > 0, "the torn row is not the file's first");
        std::fs::write(path, &body[..start + (body.len() - start) / 2]).unwrap();
    }

    /// Two file canaries deployed; one trips whole (its rows come before
    /// the ones a stop tears), then the other's first access, stopped at
    /// `stop`. Returns the stores' directory and the second canary's id.
    fn stopped_trip(stop: Option<Stop>) -> (Paths, String) {
        let paths = Paths {
            dir: TempDir::new().unwrap(),
        };
        let (registry, access) = paths.stores();
        let deploy = |path: &str, name: &str| {
            registry
                .lock()
                .deploy(CanaryTokenDraft {
                    name: name.to_string(),
                    canary_type: CanaryTypeWire::File,
                    deployment: CanaryDeploymentWire::File {
                        path: path.to_string(),
                        template: None,
                    },
                    deployed_by_fp: "ffffffff".to_string(),
                    content: None,
                })
                .unwrap()
                .canary_id
        };
        deploy(EARLIER, "earlier");
        let id = deploy(DECOY, "payroll");
        let detector = detector::<StoppingHost>(&registry, &access);
        assert!(first_trip(detector.process_event(&open_of(EARLIER, 10))));
        STOP.with(|s| s.set(stop));
        let run = std::panic::catch_unwind(AssertUnwindSafe(|| {
            detector.process_event(&open_of(DECOY, 11))
        }));
        STOP.with(|s| s.set(None));
        assert_eq!(run.is_err(), stop.is_some(), "{stop:?}");
        if let Ok(event) = run {
            assert!(first_trip(event));
        }
        // the process is gone: nothing more is written
        drop((detector, registry, access));
        match stop {
            Some(Stop::InAccess) => tear_last_row(&paths.access()),
            Some(Stop::InTripMark) => tear_last_row(&paths.registry()),
            _ => {}
        }
        (paths, id)
    }

    /// The next start (the agent's `record_unrecorded_trips`, without its
    /// audit row).
    fn next_start(
        paths: &Paths,
    ) -> (
        Arc<Mutex<Registry>>,
        Arc<Mutex<CanaryAccessDb>>,
        Vec<UnrecordedTrip>,
    ) {
        let (registry, access) = paths.stores();
        let found = registry.lock().unrecorded_trips(&paths.access()).unwrap();
        for trip in &found {
            assert!(registry
                .lock()
                .mark_tripped(&trip.canary_id, Some(trip.access.entry_hash.clone()))
                .unwrap());
        }
        (registry, access, found)
    }

    #[test]
    fn a_stop_at_any_step_leaves_the_trip_its_access_row_commits() {
        for stop in ALL {
            let (paths, id) = stopped_trip(stop);
            let committed = !matches!(stop, Some(Stop::BeforeAccess | Stop::InAccess));
            let recovered = matches!(stop, Some(Stop::AfterAccess | Stop::InTripMark));
            let (registry, access, found) = next_start(&paths);
            let rows = paths.access_rows(&id);
            assert_eq!(rows.len(), usize::from(committed), "{stop:?}: {rows:?}");
            assert_eq!(found.len(), usize::from(recovered), "{stop:?}: {found:?}");
            if let Some(trip) = found.first() {
                assert_eq!(trip.canary_id, id, "{stop:?}");
                assert_eq!(trip.access, rows[0], "{stop:?}");
            }
            assert_eq!(
                registry.lock().is_armed(&id),
                !committed,
                "{stop:?}: armed only when no access row was committed"
            );
            let trips: Vec<CanaryToken> = paths
                .registry_rows(&id)
                .into_iter()
                .filter(|r| r.action == RegistryAction::Trip)
                .collect();
            assert_eq!(trips.len(), usize::from(committed), "{stop:?}: {trips:?}");
            if committed {
                assert!(rows[0].first_trip, "{stop:?}");
                assert_eq!(
                    trips[0].first_trip_access_hash.as_deref(),
                    Some(rows[0].entry_hash.as_str()),
                    "{stop:?}: the Trip row names the access row"
                );
            }
            // The canary's next access, on the started agent: a first trip
            // only when nothing was committed.
            let detector = detector::<LinuxHost>(&registry, &access);
            assert_eq!(
                first_trip(detector.process_event(&open_of(DECOY, 12))),
                !committed,
                "{stop:?}"
            );
            drop((detector, registry, access));
            // and the start after finds nothing more to record
            let (registry, _access, found) = next_start(&paths);
            assert!(found.is_empty(), "{stop:?}: {found:?}");
            assert!(!registry.lock().is_armed(&id), "{stop:?}");
            assert_eq!(
                paths
                    .registry_rows(&id)
                    .iter()
                    .filter(|r| r.action == RegistryAction::Trip)
                    .count(),
                1,
                "{stop:?}: one Trip row"
            );
        }
    }
}
