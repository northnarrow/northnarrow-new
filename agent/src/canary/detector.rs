//! Tappa 9.5 (K3) — canary detector: inline `process_event`
//! filter + hot-path query helpers + canary-vs-FIM precedence
//! per §12 Q9 OPTION B inline-filter lock-in.
//!
//! ## Design (§12 Q9)
//!
//! The detector runs SYNCHRONOUSLY inside `main::process_event`,
//! BEFORE the rule engine sees the event. For every inbound
//! `Event::Fim` / `Event::ProcessSpawn` / `Event::TcpConnect`,
//! `Detector::process_event` checks the corresponding hot-path
//! index against the [`crate::canary::registry::Registry`]'s
//! live set:
//!
//! - `is_canary_inode(dev, ino)` — File / Credential canary
//!   trip path. Consulted on `Event::Fim` (the C5.2
//!   `fim_file_open_observe` hook fires for both real FIM
//!   paths AND canary inodes per §12 Q4 SHARE lock-in;
//!   userland discriminates here).
//! - `is_canary_exe(path)` — Process canary trip path.
//!   Consulted on `Event::ProcessSpawn`.
//! - `is_canary_destination(dst, port)` — Network canary trip
//!   path (lab PR 163). Consulted on `Event::TcpConnect`: a local
//!   process connecting to a canary's address and port is the
//!   accessor ([`crate::canary::network`] says why it is the
//!   connect, not an accept). The close of that connection
//!   (`Event::NetFlow`) belongs to the trip:
//!   [`Detector::owns_trip_flow`].
//!
//! When any helper returns `Some(canary_id)`, under the registry lock:
//!
//! 1. Detector asks the registry whether the canary is still armed
//!    ([`crate::canary::registry::Registry::is_armed`]): this access is
//!    then the first trip (§12 Q2 single-trip lock-in).
//! 2. Detector appends a `CanaryAccessEntry` to
//!    `canary_access.jsonl` via
//!    [`crate::canary::access_log::CanaryAccessDb::append`]
//!    (chain captures EVERY access; subsequent rows carry
//!    `first_trip: false`).
//! 3. On a first trip, [`crate::canary::registry::Registry::mark_tripped`]
//!    appends a signed `Trip` row carrying that access row's
//!    `entry_hash` (external audit DEC-011: the state survives a
//!    restart; the hash used to be left empty).
//! 4. Detector returns `Some(Event::CanaryTripped { … })` to
//!    the caller. main::process_event REPLACES the source
//!    event with this and routes through the canary rule
//!    family (K5 NN-L-CANARY-001..004), skipping the FIM
//!    rule layer entirely (precedence guarantee).
//!
//! ## Concurrency
//!
//! The detector shares Registry + AccessDb handles via
//! `Arc<parking_lot::Mutex<…>>`. Both locks are held only
//! during one method call (microseconds); contention with
//! the K6 admin `canary deploy`/`burn`/`refresh` mutations
//! is negligible (those mutations are operator-rare). The
//! `tokio::spawn_blocking` boundary in main::process_event
//! ALREADY moves the executor call off the async runtime;
//! the synchronous detector calls land inside the
//! `process_event` tokio task itself + don't block the
//! reactor longer than a few HashMap lookups.

use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use common::wire::admin_signed_payload::{CanaryDeploymentWire, CanaryTypeWire};
use common::wire::InodeKey;
use common::{CanaryAccessKind, CanaryTypeTag, Event};
use parking_lot::Mutex;
use tracing::{error, warn};

use crate::canary::access_log::{CanaryAccessDb, CanaryAccessDraft};
use crate::canary::network::{connect_destination, CanaryAddr, LocalAddrs, PortCanaries};
use crate::canary::registry::Registry;

/// Network trips whose connection's close is still to come, for
/// [`Detector::owns_trip_flow`]. A close that never arrives (a lost ring
/// record) leaves its entry until it is the oldest of this many.
const PENDING_TRIP_FLOWS: usize = 256;

// ── hot-path indexes ────────────────────────────────────────────────

/// Hot-path indexes derived from the [`Registry`]'s live set.
/// Rebuilt on registry mutations (deploy / burn / refresh)
/// via [`CanaryIndexes::rebuild_from_registry`]. Three
/// independent HashMaps so the detector's
/// `is_canary_{inode,exe,port}` checks are each one lookup.
///
/// Keyed by:
/// - `inode_index`: (dev, ino) from `stat(2)` on the canary
///   path at deploy time.
/// - `exe_index`: absolute path from the canary `Process`
///   deployment (the BPF process-spawn event carries
///   `filename`, which userland resolves to absolute path
///   before consultation).
/// - `port_index`: the canary `Network` deployment's port, then its
///   address ([`CanaryAddr`]: one address, or every address of this
///   host).
///
/// Values are the per-canary stable `canary_id` (32-hex-char
/// from K2 `compute_canary_id`).
///
/// **Note on inode index population:** the K3 detector cannot
/// directly stat a canary's path at index-build time (the
/// canary file may not yet exist — K6 admin dispatch is
/// responsible for the deploy-time file creation). For K3,
/// the inode_index is populated LAZILY: callers passing an
/// `Event::Fim` carry `(target_dev, target_ino)` AND the
/// resolved `path` field; the detector matches the path
/// against the `exe_index` shape OR resolves via stat in
/// `is_canary_inode_via_stat`. Tappa 9.5 K3 ships the
/// HashMap shape; K6's deploy dispatch will populate inode
/// keys after physically creating each canary file.
#[derive(Debug, Default)]
pub struct CanaryIndexes {
    inode_index: HashMap<InodeKey, String>,
    exe_index: HashMap<PathBuf, String>,
    port_index: HashMap<u16, PortCanaries>,
    /// Reverse lookup `canary_id → name` for trip-event
    /// construction without re-walking the registry.
    name_index: HashMap<String, (String, CanaryTypeTag)>,
}

impl CanaryIndexes {
    /// Empty indexes. `rebuild_from_registry` populates from
    /// a snapshot.
    pub fn new() -> Self {
        Self::default()
    }

    /// Rebuild every index from the registry's current live
    /// set. Called by the K6 admin dispatch after a successful
    /// deploy / burn / refresh, and by `Detector::new()` at
    /// agent boot post-Registry-open. Cheap (~µs per canary;
    /// operator deployment count is ~10-50).
    ///
    /// The `inode_resolver` closure maps a canary deployment
    /// to its kernel `InodeKey` (typically via `stat(2)`).
    /// Returning `None` skips inode-index population for
    /// that canary (file may not exist yet; the lazy
    /// `is_canary_inode_via_path` fallback handles the late
    /// resolution path).
    pub fn rebuild_from_registry<F>(&mut self, registry: &Registry, inode_resolver: F)
    where
        F: Fn(&Path) -> Option<InodeKey>,
    {
        self.inode_index.clear();
        self.exe_index.clear();
        self.port_index.clear();
        self.name_index.clear();
        for canary in registry.list() {
            let canary_id = canary.canary_id.clone();
            let type_tag = canary_type_wire_to_tag(canary.canary_type);
            self.name_index
                .insert(canary_id.clone(), (canary.name.clone(), type_tag));
            match &canary.deployment {
                CanaryDeploymentWire::File { path, .. }
                | CanaryDeploymentWire::Credential { path, .. } => {
                    let pb = PathBuf::from(path);
                    if let Some(key) = inode_resolver(&pb) {
                        self.inode_index.insert(key, canary_id.clone());
                    }
                }
                CanaryDeploymentWire::Process { path, .. } => {
                    self.exe_index
                        .insert(PathBuf::from(path), canary_id.clone());
                }
                CanaryDeploymentWire::Network {
                    bind_addr,
                    bind_port,
                } => match CanaryAddr::parse(bind_addr) {
                    Some(addr) => self
                        .port_index
                        .entry(*bind_port)
                        .or_default()
                        .push(addr, canary_id.clone()),
                    // Deployed before the deploy check (lab PR 163) refused
                    // such an address.
                    None => warn!(
                        canary_id = %canary_id,
                        bind_addr = %bind_addr,
                        "network canary: its address is not an IP address — no connect can \
                         trip it; burn it and deploy it again"
                    ),
                },
            }
        }
        // Publish the file-canary inodes so the FIM drain forwards
        // their READ opens past the BUG-012 v2 gate (see read_forward).
        crate::canary::read_forward::replace(self.inode_index.keys().copied());
    }

    /// Hot-path inode lookup. Returns the canary_id of the
    /// matching canary, or `None` if `(dev, ino)` isn't in
    /// the index.
    pub fn is_canary_inode(&self, key: &InodeKey) -> Option<&str> {
        self.inode_index.get(key).map(|s| s.as_str())
    }

    /// Hot-path exe-path lookup. Returns the canary_id of the
    /// matching canary, or `None`.
    pub fn is_canary_exe(&self, path: &Path) -> Option<&str> {
        self.exe_index.get(path).map(|s| s.as_str())
    }

    /// Hot-path connect lookup (lab PR 163): the canary_id of the
    /// network canary a connect to `dst` (canonical) and `port` reaches,
    /// or `None`. `is_local` (is an address one of this host's) is
    /// called only for a wildcard canary on that port.
    pub fn is_canary_destination(
        &self,
        dst: IpAddr,
        port: u16,
        is_local: &dyn Fn(IpAddr) -> bool,
    ) -> Option<&str> {
        self.port_index.get(&port)?.find(dst, is_local)
    }

    /// Resolve `canary_id` → `(name, type_tag)`. Used by the
    /// detector to populate `Event::CanaryTripped` fields
    /// without re-walking the registry. `None` if `canary_id`
    /// isn't in the live set (race window: a `burn` op
    /// between event observation and index lookup).
    pub fn name_and_type(&self, canary_id: &str) -> Option<(String, CanaryTypeTag)> {
        self.name_index.get(canary_id).cloned()
    }

    /// External audit DEC-003: the rebuild the boot and every admin
    /// operation share. The boot used to rebuild with no inode resolver:
    /// the inode index stayed empty, read-forward was published empty, and
    /// the FIM drain dropped every read of a file canary until an operator
    /// deployed, burned or refreshed one. Inodes are resolved here
    /// ([`stat_inode_key`]) and File/Credential paths layered into the
    /// path index, in one place.
    pub fn rebuild_live(&mut self, registry: &Registry) {
        self.rebuild_from_registry(registry, stat_inode_key);
        for canary in registry.list() {
            match &canary.deployment {
                CanaryDeploymentWire::File { path, .. }
                | CanaryDeploymentWire::Credential { path, .. } => {
                    self.add_file_path_index(PathBuf::from(path), canary.canary_id.clone());
                }
                _ => {}
            }
        }
    }

    /// File and Credential canaries whose inode is indexed — the inodes
    /// published to read-forward.
    pub fn file_inodes(&self) -> usize {
        self.inode_index.len()
    }

    /// K6 admin-deploy helper: add a File/Credential canary's
    /// path into the `exe_index`-shaped path lookup so the K3
    /// detector's path-based fallback (V1.0 pragmatism while
    /// FimEvent doesn't carry inode keys) matches on the
    /// next inbound event. K6's `rebuild_canary_indexes` calls
    /// this for every File + Credential entry after the
    /// rebuild_from_registry call populates Process + Network
    /// indexes naturally.
    pub fn add_file_path_index(&mut self, path: PathBuf, canary_id: String) {
        self.exe_index.insert(path, canary_id);
    }

    /// Active canary count (sum across all three index types
    /// since each canary lives in exactly one). Useful for
    /// boot logs + future `nn-admin canary status`.
    pub fn len(&self) -> usize {
        self.inode_index.len()
            + self.exe_index.len()
            + self
                .port_index
                .values()
                .map(PortCanaries::len)
                .sum::<usize>()
    }

    /// True when zero canaries are indexed.
    pub fn is_empty(&self) -> bool {
        self.inode_index.is_empty() && self.exe_index.is_empty() && self.port_index.is_empty()
    }
}

fn canary_type_wire_to_tag(t: CanaryTypeWire) -> CanaryTypeTag {
    match t {
        CanaryTypeWire::File => CanaryTypeTag::File,
        CanaryTypeWire::Process => CanaryTypeTag::Process,
        CanaryTypeWire::Network => CanaryTypeTag::Network,
        CanaryTypeWire::Credential => CanaryTypeTag::Credential,
    }
}

// ── detector ────────────────────────────────────────────────────────

/// The inline-filter detector. Holds shared handles to the K2
/// registry + the K3 access log + the hot-path indexes. One
/// `Detector` instance per agent process — main owns it via
/// `Arc<Detector>` for tokio-task sharing.
pub struct Detector {
    registry: Arc<Mutex<Registry>>,
    access_log: Arc<Mutex<CanaryAccessDb>>,
    indexes: Arc<Mutex<CanaryIndexes>>,
    /// This host's addresses, for the wildcard network canaries.
    local_addrs: LocalAddrs,
    /// `(pid, connect timestamp)` of the network trips whose close has
    /// not been seen yet ([`Detector::owns_trip_flow`]).
    trip_flows: Mutex<VecDeque<(u32, u64)>>,
}

impl Detector {
    /// Build with shared handles. Caller (main.rs) wires
    /// the Registry + AccessDb at boot and clones the Arcs.
    pub fn new(
        registry: Arc<Mutex<Registry>>,
        access_log: Arc<Mutex<CanaryAccessDb>>,
        indexes: Arc<Mutex<CanaryIndexes>>,
    ) -> Self {
        Self {
            registry,
            access_log,
            indexes,
            local_addrs: LocalAddrs::default(),
            trip_flows: Mutex::new(VecDeque::new()),
        }
    }

    /// Lab PR 163: whether `event` is the close of a connection that
    /// tripped a network canary — the `Event::NetFlow` the flow tracker
    /// builds from that connect (same pid, the connect's timestamp as its
    /// start). It belongs to the trip: main records it in the netflow log
    /// and does not judge it again, as the FIM rules never see a File
    /// canary's open (design §6, cross-cutting). Judged, the flow was a
    /// second response to the one access: NN-L-CHAIN-003 ("a canary trip,
    /// then a flow of the same process") fired on the trip's own
    /// connection. A close that reaches the loop before its connect is
    /// judged as any flow (it precedes the trip, so no chain is complete).
    pub fn owns_trip_flow(&self, event: &Event) -> bool {
        let Event::NetFlow(nf) = event else {
            return false;
        };
        if nf.proto != 6 {
            return false;
        }
        let mut flows = self.trip_flows.lock();
        match flows
            .iter()
            .position(|&(pid, ts)| pid == nf.pid && ts == nf.start_ns)
        {
            // Lab PR 224: the connection's open-phase rows (its connect,
            // its snapshots) belong to the trip as well; its close ends it.
            Some(i) => {
                if !nf.phase.is_open() {
                    flows.remove(i);
                }
                true
            }
            None => false,
        }
    }

    /// Inline filter for `main::process_event`. Returns:
    ///
    /// - `Some(Event::CanaryTripped { … })` when the event
    ///   matches a deployed canary — caller REPLACES the
    ///   source event with this and routes through K5 canary
    ///   rules (skipping the FIM rule layer per §12 Q9
    ///   precedence guarantee).
    /// - `None` when no canary matches — caller proceeds with
    ///   the source event through the normal rule engine
    ///   path.
    ///
    /// Hot-path: 1 HashMap lookup per Event::Fim/ProcessSpawn,
    /// short-circuits in the common no-match case. The
    /// `Registry::mark_tripped` + `CanaryAccessDb::append`
    /// path only fires on the rare match.
    pub fn process_event(&self, event: &Event) -> Option<Event> {
        let (canary_id, access_kind, accessor_pid, accessor_uid, accessor_comm, ts) = match event {
            Event::Fim(fe) => {
                let key = InodeKey {
                    dev: 0, // FimEvent doesn't carry (dev, ino) in V1.0; the
                    ino: 0, // K6 deploy-time stat populates inode_index by
                            // the FIM hook's emit-side key. Until K6 wires
                            // the (dev, ino) plumbing into FimEvent, fall
                            // back to path-based lookup against exe_index +
                            // future inode_path_map cross-reference.
                };
                let _ = key;
                let path = PathBuf::from(&fe.path);
                let canary_id = {
                    let idx = self.indexes.lock();
                    // Path-based fallback while FimEvent lacks (dev, ino);
                    // K6's deploy populates exe_index with the canary's
                    // resolved absolute path for File / Credential canaries
                    // too (the resolver closure in rebuild_from_registry
                    // can be extended to populate both inode_index AND
                    // path-based entries for cross-key matching). This is
                    // an explicit V1.0 pragmatism; the long-term shape is
                    // FimEvent carrying (target_dev, target_ino) like the
                    // C4 FimDriftRaw does.
                    idx.is_canary_exe(&path).map(String::from)
                };
                let canary_id = canary_id?;
                (
                    canary_id,
                    CanaryAccessKind::FileOpen,
                    fe.modifier_pid,
                    fe.modifier_uid,
                    fe.modifier_comm.clone(),
                    fe.timestamp_ns,
                )
            }
            Event::ProcessSpawn {
                pid,
                uid,
                comm,
                filename,
                timestamp_ns,
                exe,
                ..
            } => {
                // The file the kernel executed (review 61: a symlink or a
                // relative path no longer misses the canary), else the
                // caller's string.
                let canary_id = {
                    let idx = self.indexes.lock();
                    idx.is_canary_exe(&PathBuf::from(exe.path_or(filename)))
                        .or_else(|| idx.is_canary_exe(&PathBuf::from(filename)))
                        .map(String::from)
                };
                let canary_id = canary_id?;
                (
                    canary_id,
                    CanaryAccessKind::ProcessExec,
                    *pid,
                    *uid,
                    comm.clone(),
                    *timestamp_ns,
                )
            }
            // Lab PR 163: a connect to a network canary's address and
            // port, by the local process that makes it.
            Event::TcpConnect {
                pid,
                uid,
                comm,
                family,
                dst_addr,
                dst_port,
                timestamp_ns,
                ..
            } => {
                let dst = connect_destination(*family, dst_addr)?;
                let canary_id = {
                    let idx = self.indexes.lock();
                    idx.is_canary_destination(dst, *dst_port, &|a| self.local_addrs.contains(a))
                        .map(String::from)
                };
                let canary_id = canary_id?;
                (
                    canary_id,
                    CanaryAccessKind::NetworkConnect,
                    *pid,
                    *uid,
                    comm.clone(),
                    *timestamp_ns,
                )
            }
            // All other event variants fall through.
            _ => return None,
        };

        // Resolve canary_id → (name, type) for the trip event.
        let (canary_name, canary_type_tag) = {
            let idx = self.indexes.lock();
            match idx.name_and_type(&canary_id) {
                Some(p) => p,
                None => {
                    // Race: a `burn` op removed this canary between the
                    // index lookup above and the name lookup here. Treat
                    // as a no-match (the rule engine sees the source
                    // event unchanged).
                    warn!(
                        canary_id = %canary_id,
                        "canary detected via index but missing from name_index — \
                         race with concurrent burn; skipping trip emit"
                    );
                    return None;
                }
            }
        };

        // External audit DEC-005 / DEC-014: the executable the kernel ran
        // for the accessor, for the chain row and the trip event (the K5
        // rules judge readers through the lineage cache). Best-effort: a
        // short-lived reader may be gone.
        let accessor_exe = std::fs::read_link(format!("/proc/{accessor_pid}/exe"))
            .ok()
            .map(|p| p.to_string_lossy().into_owned());

        // External audit DEC-011: under the registry lock, decide whether
        // this is the first trip, append the access row (ALWAYS — the
        // chain captures every access; re-fire suppression lives in
        // first_trip), then record the trip in the registry with that
        // row's hash. A failed write is reported and the event is still
        // emitted.
        let first_trip = {
            let mut reg = self.registry.lock();
            let first_trip = reg.is_armed(&canary_id);
            let access_entry_hash = {
                let mut log = self.access_log.lock();
                match log.append(CanaryAccessDraft {
                    canary_id: canary_id.clone(),
                    canary_name: canary_name.clone(),
                    canary_type: canary_type_tag,
                    access_kind,
                    accessor_pid,
                    accessor_uid,
                    accessor_comm: accessor_comm.clone(),
                    accessor_exe: accessor_exe.clone(),
                    first_trip,
                }) {
                    Ok(entry) => Some(entry.entry_hash),
                    Err(e) => {
                        warn!(
                            error = %e,
                            canary_id = %canary_id,
                            "canary access log append failed — trip event still emitted, \
                             chain entry missing"
                        );
                        None
                    }
                }
            };
            if first_trip {
                if let Err(e) = reg.mark_tripped(&canary_id, access_entry_hash) {
                    error!(
                        error = %format!("{e:#}"),
                        canary_id = %canary_id,
                        "canary trip not recorded in the registry — it holds for this run \
                         only; a restart would re-arm the canary"
                    );
                }
            }
            first_trip
        };

        if access_kind == CanaryAccessKind::NetworkConnect {
            let mut flows = self.trip_flows.lock();
            if flows.len() >= PENDING_TRIP_FLOWS {
                flows.pop_front();
            }
            flows.push_back((accessor_pid, ts));
        }

        // Return the trip event for main to route through the
        // K5 canary rules.
        Some(Event::CanaryTripped {
            canary_id,
            canary_name,
            canary_type: canary_type_tag,
            access_kind,
            accessor_pid,
            accessor_uid,
            accessor_comm,
            accessor_exe,
            timestamp_ns: ts,
            // External audit DEC-004: the K5 rules respond to the first
            // access only; every access is in the chain above.
            first_trip,
        })
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::canary::registry::{CanaryTokenDraft, Registry};
    use common::wire::FimEvent;
    use common::wire::FimOp;
    use tempfile::TempDir;

    fn build_detector(dir: &TempDir) -> (Detector, Arc<Mutex<Registry>>) {
        let key_path = dir.path().join("agent.sig.key");
        let key1 = crate::audit::AgentSigningKey::load_or_bootstrap(&key_path).unwrap();
        let key2 = crate::audit::AgentSigningKey::load_or_bootstrap(&key_path).unwrap();
        let reg_path = dir.path().join("canaries.jsonl");
        let log_path = dir.path().join("canary_access.jsonl");
        let registry = Arc::new(Mutex::new(
            Registry::open(&reg_path, key1, [0u8; 16]).unwrap(),
        ));
        let access_log = Arc::new(Mutex::new(
            CanaryAccessDb::open(&log_path, key2, [0u8; 16]).unwrap(),
        ));
        let indexes = Arc::new(Mutex::new(CanaryIndexes::new()));
        let detector = Detector::new(
            Arc::clone(&registry),
            Arc::clone(&access_log),
            Arc::clone(&indexes),
        );
        (detector, registry)
    }

    /// External audit DEC-003: the boot rebuild resolves a file canary's
    /// inode — the index read-forward is published from — and the path
    /// index too. It used to rebuild with no resolver, leaving the reads of
    /// every file canary dropped until an admin operation.
    #[test]
    fn boot_rebuild_indexes_file_canary_inodes() {
        let dir = TempDir::new().unwrap();
        let (detector, registry) = build_detector(&dir);
        let decoy = dir.path().join("passwords.xlsx");
        std::fs::write(&decoy, b"decoy").unwrap();
        let path = decoy.to_string_lossy().to_string();
        registry
            .lock()
            .deploy(CanaryTokenDraft {
                name: "decoy".to_string(),
                canary_type: CanaryTypeWire::File,
                deployment: CanaryDeploymentWire::File {
                    path: path.clone(),
                    template: None,
                },
                deployed_by_fp: "deadbeef".to_string(),
                content: None,
            })
            .unwrap();
        let mut idx = CanaryIndexes::new();
        idx.rebuild_live(&registry.lock());
        let key = stat_inode_key(&decoy).expect("decoy exists");
        assert!(idx.is_canary_inode(&key).is_some());
        assert_eq!(idx.file_inodes(), 1);
        assert!(idx.is_canary_exe(&decoy).is_some(), "path index layered in");
        drop(detector);
    }

    fn deploy_process_canary(
        registry: &Arc<Mutex<Registry>>,
        indexes: &Detector,
        path: &str,
        name: &str,
    ) -> String {
        let canary_id = {
            let mut reg = registry.lock();
            reg.deploy(CanaryTokenDraft {
                name: name.to_string(),
                canary_type: CanaryTypeWire::Process,
                deployment: CanaryDeploymentWire::Process {
                    path: path.to_string(),
                    fake_arg0: format!("{name} --serve"),
                },
                deployed_by_fp: "deadbeef".to_string(),
                content: None,
            })
            .unwrap()
            .canary_id
        };
        // Rebuild detector indexes from the new registry state.
        {
            let mut idx = indexes.indexes.lock();
            idx.rebuild_from_registry(&registry.lock(), |_| None);
        }
        canary_id
    }

    fn deploy_file_canary(
        registry: &Arc<Mutex<Registry>>,
        detector: &Detector,
        path: &str,
        name: &str,
    ) -> String {
        let canary_id = {
            let mut reg = registry.lock();
            reg.deploy(CanaryTokenDraft {
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
        // File canaries populate exe_index via a path-based
        // rebuild (the K3 detector's path-based fallback while
        // FimEvent doesn't carry inode keys).
        {
            let mut idx = detector.indexes.lock();
            let canary_path = path.to_string();
            let canary_id_clone = canary_id.clone();
            idx.rebuild_from_registry(&registry.lock(), |_| None);
            // Also populate exe_index for the file canary so
            // the path-based fallback in process_event matches.
            // (In production K6 wiring, the rebuild_from_registry
            // closure would do this; for the test fixture we
            // patch it in directly.)
            idx.exe_index
                .insert(PathBuf::from(&canary_path), canary_id_clone);
        }
        canary_id
    }

    fn fim_event_on(path: &str, pid: u32) -> Event {
        Event::Fim(FimEvent {
            timestamp_ns: 1_700_000_000_000_000_000,
            path: path.to_string(),
            op: FimOp::Modified,
            new_sha256: None,
            baseline_sha256: None,
            new_size: None,
            baseline_size: None,
            modifier_exe: None,
            modifier_pid: pid,
            modifier_uid: 0,
            modifier_comm: "attacker".to_string(),
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

    fn process_spawn(filename: &str, pid: u32) -> Event {
        Event::ProcessSpawn {
            pid,
            ppid: 1,
            uid: 0,
            gid: 0,
            comm: "ls".to_string(),
            filename: filename.to_string(),
            timestamp_ns: 1_700_000_000_000_000_000,
            argv: Vec::new(),
            parent_comm: String::new(),
            parent_start_ns: 0,
            start_ns: 0,
            parent_is_kthread: false,
            exe: Default::default(),
            argv_truncated: false,
            filename_truncated: false,
            stdio: Default::default(),
        }
    }

    /// K3 detector test #1: canary file open via path-based
    /// match fires `Event::CanaryTripped` with the right
    /// fields populated.
    #[test]
    fn detector_fires_event_on_canary_file_open() {
        let dir = TempDir::new().unwrap();
        let (detector, registry) = build_detector(&dir);
        let canary_id =
            deploy_file_canary(&registry, &detector, "/tmp/decoy.txt", "test_file_canary");
        let event = fim_event_on("/tmp/decoy.txt", 4242);
        let out = detector
            .process_event(&event)
            .expect("canary path match must emit CanaryTripped");
        match out {
            Event::CanaryTripped {
                canary_id: cid,
                canary_name,
                canary_type,
                access_kind,
                accessor_pid,
                ..
            } => {
                assert_eq!(cid, canary_id);
                assert_eq!(canary_name, "test_file_canary");
                assert_eq!(canary_type, CanaryTypeTag::File);
                assert_eq!(access_kind, CanaryAccessKind::FileOpen);
                assert_eq!(accessor_pid, 4242);
            }
            other => panic!("expected Event::CanaryTripped, got {other:?}"),
        }
    }

    /// K3 detector test #2: canary process exec fires
    /// `Event::CanaryTripped` (the K3 inline filter's process-
    /// canary path).
    #[test]
    fn detector_fires_event_on_canary_process_exec() {
        let dir = TempDir::new().unwrap();
        let (detector, registry) = build_detector(&dir);
        let canary_id = deploy_process_canary(
            &registry,
            &detector,
            "/usr/local/bin/sysadmin-helper",
            "sysadmin_helper_canary",
        );
        let event = process_spawn("/usr/local/bin/sysadmin-helper", 9999);
        let out = detector
            .process_event(&event)
            .expect("process canary exec must emit CanaryTripped");
        match out {
            Event::CanaryTripped {
                canary_id: cid,
                canary_type,
                access_kind,
                accessor_pid,
                ..
            } => {
                assert_eq!(cid, canary_id);
                assert_eq!(canary_type, CanaryTypeTag::Process);
                assert_eq!(access_kind, CanaryAccessKind::ProcessExec);
                assert_eq!(accessor_pid, 9999);
            }
            other => panic!("expected Event::CanaryTripped, got {other:?}"),
        }
    }

    /// K3 detector test #3: non-canary events return `None`
    /// (the rule engine sees them unchanged — canary precedence
    /// only fires on actual matches).
    #[test]
    fn detector_returns_none_for_non_canary_events() {
        let dir = TempDir::new().unwrap();
        let (detector, _registry) = build_detector(&dir);
        // No canaries deployed → every event passes through.
        assert!(detector
            .process_event(&fim_event_on("/etc/passwd", 1234))
            .is_none());
        assert!(detector
            .process_event(&process_spawn("/bin/ls", 5678))
            .is_none());
        // Also: event variants the K3 V1.0 detector doesn't
        // intercept (TcpConnect / DnsQuery / FsProtectDenial)
        // always return None regardless of registry state.
        let dns_event = Event::DnsQuery {
            pid: 1,
            uid: 0,
            comm: "test".to_string(),
            exe: None,
            query_name: "example.com".to_string(),
            query_type: 1,
            dns_server: [127, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            family: 2,
            timestamp_ns: 0,
            qname_partial: false,
        };
        assert!(detector.process_event(&dns_event).is_none());
    }

    /// K3 detector test #4: idempotent mark_tripped — first
    /// trip emits with first_trip=true (per
    /// CanaryAccessEntry); second trip emits AGAIN (the
    /// detector ALWAYS emits CanaryTripped for the rule
    /// engine to consume), BUT the access-log row marks
    /// `first_trip=false`. §12 Q2 single-trip lock-in is
    /// enforced via the access-log row's flag, not by
    /// suppressing the event emit at the detector.
    #[test]
    fn detector_marks_subsequent_trips_as_not_first() {
        let dir = TempDir::new().unwrap();
        let (detector, registry) = build_detector(&dir);
        let _ = deploy_file_canary(&registry, &detector, "/tmp/decoy.txt", "test_canary");
        let event = fim_event_on("/tmp/decoy.txt", 4242);
        // First trip: registry.mark_tripped returns true; the
        // access log writes a row with first_trip=true.
        let first = detector.process_event(&event);
        assert!(first.is_some(), "first trip must emit");
        // Second trip: detector still emits (rule engine sees
        // it), the access log row records first_trip=false — and,
        // external audit DEC-004, so does the event, so the K5 rules
        // record it instead of responding again.
        let second = detector.process_event(&event);
        assert!(
            second.is_some(),
            "subsequent trips also emit; first_trip flag is in the chain row"
        );
        let flag = |e: &Option<Event>| match e {
            Some(Event::CanaryTripped { first_trip, .. }) => *first_trip,
            _ => panic!("not a trip"),
        };
        assert!(flag(&first), "the first event is the trip");
        assert!(!flag(&second), "a later access is not");
        // Read the access log and verify the flags.
        let log_path = dir.path().join("canary_access.jsonl");
        let body = std::fs::read_to_string(&log_path).unwrap();
        let rows: Vec<crate::canary::access_log::CanaryAccessEntry> = body
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect();
        assert_eq!(rows.len(), 2);
        assert!(rows[0].first_trip, "row 0 must be first_trip=true");
        assert!(!rows[1].first_trip, "row 1 must be first_trip=false");
    }

    /// External audit DEC-011: the registry's Trip row names the access
    /// row of the first trip (the hash used to be left empty), and after
    /// a restart a read of the same canary is not a first trip again.
    #[test]
    fn first_trip_hash_is_the_access_row_hash() {
        let dir = TempDir::new().unwrap();
        let (detector, registry) = build_detector(&dir);
        let id = deploy_file_canary(&registry, &detector, "/tmp/decoy.txt", "c");
        let first = detector.process_event(&fim_event_on("/tmp/decoy.txt", 4242));
        assert!(matches!(
            first,
            Some(Event::CanaryTripped {
                first_trip: true,
                ..
            })
        ));
        let access: Vec<crate::canary::access_log::CanaryAccessEntry> =
            std::fs::read_to_string(dir.path().join("canary_access.jsonl"))
                .unwrap()
                .lines()
                .map(|l| serde_json::from_str(l).unwrap())
                .collect();
        let state = registry.lock().get(&id).unwrap();
        assert_eq!(
            state.first_trip_access_hash.as_deref(),
            Some(access[0].entry_hash.as_str())
        );
        drop(detector);
        drop(registry);

        // the agent restarts: the registry is read back from its chain
        let (detector, registry) = build_detector(&dir);
        assert!(registry.lock().get(&id).unwrap().tripped);
        {
            let mut idx = detector.indexes.lock();
            idx.rebuild_from_registry(&registry.lock(), |_| None);
            idx.exe_index
                .insert(PathBuf::from("/tmp/decoy.txt"), id.clone());
        }
        let again = detector.process_event(&fim_event_on("/tmp/decoy.txt", 4343));
        assert!(
            matches!(
                again,
                Some(Event::CanaryTripped {
                    first_trip: false,
                    ..
                })
            ),
            "a canary tripped before the restart is not tripped anew: {again:?}"
        );
    }

    /// External audit DEC-014 (NN-AUD-339, lab PR 99; test added in lab PR
    /// 178): `accessor_exe` is the executable the kernel ran for the
    /// accessor — it used to be always `None` — in the trip event and in
    /// the access row. The other detector tests use a pid that is not
    /// running, so nothing pinned it.
    #[test]
    fn accessor_exe_is_resolved_for_live_process() {
        let dir = TempDir::new().unwrap();
        let (detector, registry) = build_detector(&dir);
        deploy_file_canary(&registry, &detector, "/tmp/decoy-exe.txt", "c");
        let me = std::fs::read_link("/proc/self/exe")
            .unwrap()
            .to_string_lossy()
            .into_owned();
        let out = detector.process_event(&fim_event_on("/tmp/decoy-exe.txt", std::process::id()));
        match out {
            Some(Event::CanaryTripped { accessor_exe, .. }) => {
                assert_eq!(accessor_exe.as_deref(), Some(me.as_str()))
            }
            other => panic!("expected Event::CanaryTripped, got {other:?}"),
        }
        let rows = access_rows(&dir);
        assert_eq!(rows[0].accessor_exe.as_deref(), Some(me.as_str()));
        // a pid that is gone: best-effort, no exe
        let gone = detector.process_event(&fim_event_on("/tmp/decoy-exe.txt", u32::MAX - 1));
        assert!(matches!(
            gone,
            Some(Event::CanaryTripped {
                accessor_exe: None,
                ..
            })
        ));
    }

    /// K3 detector test #5: hot-path is_canary_inode/exe/port
    /// return `None` for non-canary keys (the negative-case
    /// short-circuit).
    #[test]
    fn hot_path_helpers_return_none_for_non_canary_keys() {
        let dir = TempDir::new().unwrap();
        let (detector, _registry) = build_detector(&dir);
        let idx = detector.indexes.lock();
        assert!(idx.is_canary_inode(&InodeKey { dev: 1, ino: 2 }).is_none());
        assert!(idx.is_canary_exe(Path::new("/bin/ls")).is_none());
        assert!(idx
            .is_canary_destination("127.0.0.1".parse().unwrap(), 22, &|_| true)
            .is_none());
        assert_eq!(idx.len(), 0);
        assert!(idx.is_empty());
    }

    /// K3 detector test #6: rebuild_from_registry populates
    /// the exe_index from a Process canary deployment + the
    /// port_index from a Network canary deployment.
    #[test]
    fn rebuild_from_registry_populates_exe_and_port_indexes() {
        let dir = TempDir::new().unwrap();
        let (detector, registry) = build_detector(&dir);
        {
            let mut reg = registry.lock();
            reg.deploy(CanaryTokenDraft {
                name: "proc_canary".to_string(),
                canary_type: CanaryTypeWire::Process,
                deployment: CanaryDeploymentWire::Process {
                    path: "/usr/local/bin/helper".to_string(),
                    fake_arg0: "helper".to_string(),
                },
                deployed_by_fp: "ab".to_string(),
                content: None,
            })
            .unwrap();
            reg.deploy(CanaryTokenDraft {
                name: "net_canary".to_string(),
                canary_type: CanaryTypeWire::Network,
                deployment: CanaryDeploymentWire::Network {
                    bind_addr: "0.0.0.0".to_string(),
                    bind_port: 4444,
                },
                deployed_by_fp: "cd".to_string(),
                content: None,
            })
            .unwrap();
        }
        let mut idx = detector.indexes.lock();
        idx.rebuild_from_registry(&registry.lock(), |_| None);
        assert!(idx
            .is_canary_exe(Path::new("/usr/local/bin/helper"))
            .is_some());
        let lo = "127.0.0.1".parse().unwrap();
        assert!(idx.is_canary_destination(lo, 4444, &|_| false).is_some());
        assert!(idx.is_canary_destination(lo, 22, &|_| false).is_none());
        // Two canaries total (one in exe, one in port).
        assert_eq!(idx.len(), 2);
    }

    /// K3 detector test #7: canary-vs-FIM precedence — when
    /// the detector matches, it returns Some(CanaryTripped);
    /// the caller (main::process_event) is responsible for
    /// REPLACING the source event and skipping the FIM rule
    /// layer. This test verifies the detector's contract: the
    /// returned event is a CanaryTripped (NOT the source Fim),
    /// so the caller's switch is well-typed.
    #[test]
    fn canary_vs_fim_precedence_returns_canary_tripped_variant() {
        let dir = TempDir::new().unwrap();
        let (detector, registry) = build_detector(&dir);
        let _ = deploy_file_canary(&registry, &detector, "/tmp/decoy.txt", "precedence_test");
        let source_event = fim_event_on("/tmp/decoy.txt", 7777);
        let out = detector.process_event(&source_event).unwrap();
        // The detector returned a CanaryTripped variant, NOT
        // the source Fim variant. main::process_event will
        // pattern-match on the returned variant and route
        // through K5 canary rules instead of K9 FIM rules.
        assert!(
            matches!(out, Event::CanaryTripped { .. }),
            "detector must return CanaryTripped variant for canary matches"
        );
        // Sanity: the source event itself is untouched (the
        // detector took an &Event ref; no in-place mutation).
        assert!(matches!(source_event, Event::Fim(_)));
    }

    /// K3 detector test #8: concurrent admin-deploy + detector
    /// reads — the Arc<Mutex<…>> protects against torn reads.
    /// This test simulates a deploy happening DURING a
    /// detector lookup loop; the detector either sees the
    /// new canary OR doesn't, but never panics + never
    /// returns a malformed event.
    #[test]
    fn detector_handles_concurrent_admin_deploy_safely() {
        use std::thread;
        let dir = TempDir::new().unwrap();
        let (detector, registry) = build_detector(&dir);
        let detector = Arc::new(detector);
        // Spawn 10 reader threads that loop on detector calls.
        let mut handles = Vec::new();
        for i in 0..10 {
            let d = Arc::clone(&detector);
            handles.push(thread::spawn(move || {
                for _ in 0..50 {
                    let event = fim_event_on(&format!("/tmp/decoy_{i}.txt"), 1000 + i as u32);
                    // Reader returns None (no matching canary
                    // OR matching canary — either is fine).
                    let _ = d.process_event(&event);
                }
            }));
        }
        // Concurrent writer: deploy canaries one at a time
        // while readers loop.
        for i in 0..20 {
            let mut reg = registry.lock();
            reg.deploy(CanaryTokenDraft {
                name: format!("concurrent_{i}"),
                canary_type: CanaryTypeWire::File,
                deployment: CanaryDeploymentWire::File {
                    path: format!("/tmp/concurrent_{i}.txt"),
                    template: None,
                },
                deployed_by_fp: format!("{i:08x}"),
                content: None,
            })
            .unwrap();
            drop(reg);
            // Rebuild index after each deploy.
            let mut idx = detector.indexes.lock();
            idx.rebuild_from_registry(&registry.lock(), |_| None);
            drop(idx);
            // Yield to readers.
            thread::yield_now();
        }
        for h in handles {
            h.join().expect("reader thread panicked");
        }
        // After everything: 20 canaries deployed; no panics.
        assert_eq!(registry.lock().len(), 20);
    }

    /// K6 detector test: `add_file_path_index` is the public
    /// hook the K6 dispatch helper `rebuild_canary_indexes` uses
    /// to layer File + Credential canary paths into the
    /// `exe_index` HashMap (the K3 path-based fallback while
    /// FimEvent doesn't carry (dev, ino)). This test pins the
    /// shape: after `add_file_path_index(path, id)`, the
    /// `is_canary_exe(path)` lookup returns Some(id).
    #[test]
    fn add_file_path_index_makes_path_queryable_via_is_canary_exe() {
        use std::path::PathBuf;
        let mut idx = CanaryIndexes::new();
        assert!(idx.is_empty());
        idx.add_file_path_index(
            PathBuf::from("/var/lib/northnarrow/canaries/aws.creds"),
            "abc123def4567890".to_string(),
        );
        assert_eq!(idx.len(), 1);
        assert_eq!(
            idx.is_canary_exe(Path::new("/var/lib/northnarrow/canaries/aws.creds")),
            Some("abc123def4567890")
        );
        assert!(idx.is_canary_exe(Path::new("/other/path")).is_none());
    }

    // ── lab PR 163: network canaries ───────────────────────────────

    fn deploy_network_canary(
        registry: &Arc<Mutex<Registry>>,
        detector: &Detector,
        bind_addr: &str,
        bind_port: u16,
    ) -> String {
        let canary_id = registry
            .lock()
            .deploy(CanaryTokenDraft {
                name: format!("decoy-{bind_addr}-{bind_port}"),
                canary_type: CanaryTypeWire::Network,
                deployment: CanaryDeploymentWire::Network {
                    bind_addr: bind_addr.to_string(),
                    bind_port,
                },
                deployed_by_fp: "deadbeef".to_string(),
                content: None,
            })
            .unwrap()
            .canary_id;
        detector.indexes.lock().rebuild_live(&registry.lock());
        canary_id
    }

    /// `Event::TcpConnect` as the connect kprobe reports it.
    fn connect_to(dst: &str, dst_port: u16, pid: u32, ts: u64) -> Event {
        let (family, dst_addr) = match dst.parse::<IpAddr>().unwrap() {
            IpAddr::V4(a) => {
                let mut b = [0u8; 16];
                b[..4].copy_from_slice(&a.octets());
                (2, b)
            }
            IpAddr::V6(a) => (10, a.octets()),
        };
        Event::TcpConnect {
            pid,
            uid: 1000,
            comm: "nc.openbsd".to_string(),
            family,
            src_addr: [0u8; 16],
            src_port: 0,
            dst_addr,
            dst_port,
            timestamp_ns: ts,
        }
    }

    fn access_rows(dir: &TempDir) -> Vec<crate::canary::access_log::CanaryAccessEntry> {
        std::fs::read_to_string(dir.path().join("canary_access.jsonl"))
            .unwrap_or_default()
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect()
    }

    /// Lab PR 163 (NN-L-CANARY-003 could not fire): a connect to a network
    /// canary's address and port is a trip, as an open of a File canary
    /// is — the signed access row with `first_trip`, the registry's Trip
    /// row naming it, and `Event::CanaryTripped` with the connecting
    /// process as the accessor. Nothing consulted the port index before.
    #[test]
    fn a_connect_to_a_network_canary_trips_it() {
        let dir = TempDir::new().unwrap();
        let (detector, registry) = build_detector(&dir);
        let id = deploy_network_canary(&registry, &detector, "100.64.0.9", 4444);

        let out = detector.process_event(&connect_to("100.64.0.9", 4444, 7001, 1_000));
        match out {
            Some(Event::CanaryTripped {
                canary_id,
                canary_type,
                access_kind,
                accessor_pid,
                accessor_uid,
                accessor_comm,
                timestamp_ns,
                first_trip,
                ..
            }) => {
                assert_eq!(canary_id, id);
                assert_eq!(canary_type, CanaryTypeTag::Network);
                assert_eq!(access_kind, CanaryAccessKind::NetworkConnect);
                assert_eq!((accessor_pid, accessor_uid), (7001, 1000));
                assert_eq!(accessor_comm, "nc.openbsd");
                assert_eq!(timestamp_ns, 1_000);
                assert!(first_trip);
            }
            other => panic!("expected a network canary trip, got {other:?}"),
        }
        let rows = access_rows(&dir);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].canary_id, id);
        assert_eq!(rows[0].accessor_pid, 7001);
        assert!(rows[0].first_trip);
        let state = registry.lock().get(&id).unwrap();
        assert!(state.tripped);
        assert_eq!(
            state.first_trip_access_hash.as_deref(),
            Some(rows[0].entry_hash.as_str())
        );

        // a second connect is recorded, not a first trip
        let again = detector.process_event(&connect_to("100.64.0.9", 4444, 7002, 2_000));
        assert!(matches!(
            again,
            Some(Event::CanaryTripped {
                first_trip: false,
                accessor_pid: 7002,
                ..
            })
        ));
        assert_eq!(access_rows(&dir).len(), 2);
    }

    /// The verdict: NN-L-CANARY-003 on the trip the connect makes, Critical,
    /// the connecting process's tree killed.
    #[test]
    fn a_network_canary_trip_draws_canary_003_on_the_connector() {
        use crate::decision::rules::canary::NnLCanary003NetworkConnect;
        use crate::decision::Rule as _;
        let dir = TempDir::new().unwrap();
        let (detector, registry) = build_detector(&dir);
        deploy_network_canary(&registry, &detector, "127.0.0.1", 31337);
        let trip = detector
            .process_event(&connect_to("127.0.0.1", 31337, 4242, 5_000))
            .expect("a trip");
        let v = NnLCanary003NetworkConnect::default()
            .evaluate(&trip)
            .expect("NN-L-CANARY-003 fires");
        assert_eq!(v.rule_id, "NN-L-CANARY-003_NetworkConnect");
        assert_eq!(v.severity, common::Severity::Critical);
        assert_eq!(v.action, common::ResponseAction::KillProcessTree);
        assert_eq!(v.event_pid, 4242);
    }

    /// What does not trip: another port, another address, a destination
    /// on another host for a wildcard canary, and the IPv4-mapped IPv6
    /// record of a dual-stack connect (its IPv4 record is the trip: one
    /// access, one row).
    #[test]
    fn connects_a_network_canary_does_not_cover_do_not_trip_it() {
        let dir = TempDir::new().unwrap();
        let (detector, registry) = build_detector(&dir);
        deploy_network_canary(&registry, &detector, "100.64.0.9", 4444);
        deploy_network_canary(&registry, &detector, "0.0.0.0", 5555);
        for ev in [
            connect_to("100.64.0.9", 4445, 1, 1),
            connect_to("100.64.0.10", 4444, 1, 2),
            connect_to("192.0.2.7", 5555, 1, 3),
            connect_to("::1", 5555, 1, 4),
            connect_to("::ffff:100.64.0.9", 4444, 1, 5),
        ] {
            assert!(detector.process_event(&ev).is_none(), "{ev:?}");
        }
        assert!(access_rows(&dir).is_empty());
        // the IPv4 record of that dual-stack connect, and the wildcard
        // canary's port on this host
        assert!(detector
            .process_event(&connect_to("100.64.0.9", 4444, 1, 6))
            .is_some());
        assert!(detector
            .process_event(&connect_to("127.0.0.1", 5555, 1, 7))
            .is_some());
        assert!(detector
            .process_event(&connect_to("0.0.0.0", 5555, 1, 8))
            .is_some());
        assert_eq!(access_rows(&dir).len(), 3);
    }

    /// A burned network canary trips no more.
    #[test]
    fn a_burned_network_canary_does_not_trip() {
        let dir = TempDir::new().unwrap();
        let (detector, registry) = build_detector(&dir);
        let id = deploy_network_canary(&registry, &detector, "100.64.0.9", 4444);
        registry.lock().burn(&id, "deadbeef").unwrap();
        detector.indexes.lock().rebuild_live(&registry.lock());
        assert!(detector
            .process_event(&connect_to("100.64.0.9", 4444, 1, 1))
            .is_none());
    }

    fn flow_close(pid: u32, start_ns: u64, proto: u8) -> Event {
        Event::NetFlow(common::wire::NetFlowEvent {
            start_ns,
            end_ns: start_ns + 1_000,
            family: 2,
            src_addr: "127.0.0.1".parse().unwrap(),
            src_port: 40000,
            dst_addr: "100.64.0.9".parse().unwrap(),
            dst_port: 4444,
            proto,
            pid,
            uid: 1000,
            comm: "nc.openbsd".to_string(),
            exe: None,
            proc_start_ns: 0,
            bytes_sent: 0,
            bytes_recv: 0,
            resolved_hostname: None,
            tls_fingerprint: None,
            flow_id: String::new(),
            close_reason: 111,
            phase: Default::default(),
            observed_ns: 0,
        })
    }

    /// The close of the trip's own connection belongs to the trip (main
    /// does not judge it again: NN-L-CHAIN-003 fired on it, a second
    /// response to one access). Once, and only that flow: another flow of
    /// the same process, a flow of another process and a UDP record are
    /// judged as usual.
    #[test]
    fn the_close_of_the_trip_connection_belongs_to_the_trip() {
        let dir = TempDir::new().unwrap();
        let (detector, registry) = build_detector(&dir);
        deploy_network_canary(&registry, &detector, "100.64.0.9", 4444);
        assert!(!detector.owns_trip_flow(&flow_close(7001, 9_000, 6)));
        detector
            .process_event(&connect_to("100.64.0.9", 4444, 7001, 9_000))
            .expect("a trip");
        assert!(!detector.owns_trip_flow(&flow_close(7001, 9_001, 6)));
        assert!(!detector.owns_trip_flow(&flow_close(7002, 9_000, 6)));
        assert!(!detector.owns_trip_flow(&flow_close(7001, 9_000, 17)));
        assert!(detector.owns_trip_flow(&flow_close(7001, 9_000, 6)));
        assert!(
            !detector.owns_trip_flow(&flow_close(7001, 9_000, 6)),
            "once: a later flow with the same key is not the trip's"
        );
        // a file canary trip owns no flow
        deploy_file_canary(&registry, &detector, "/tmp/decoy.txt", "f");
        let mut fim = fim_event_on("/tmp/decoy.txt", 7003);
        if let Event::Fim(fe) = &mut fim {
            fe.timestamp_ns = 9_500;
        }
        detector.process_event(&fim).expect("a file trip");
        assert!(!detector.owns_trip_flow(&flow_close(7003, 9_500, 6)));
    }

    /// The pending trips are bounded: the oldest goes first.
    #[test]
    fn pending_trip_flows_are_bounded() {
        let dir = TempDir::new().unwrap();
        let (detector, registry) = build_detector(&dir);
        deploy_network_canary(&registry, &detector, "100.64.0.9", 4444);
        for i in 0..=PENDING_TRIP_FLOWS as u64 {
            detector
                .process_event(&connect_to("100.64.0.9", 4444, 9, i))
                .expect("a trip");
        }
        assert_eq!(detector.trip_flows.lock().len(), PENDING_TRIP_FLOWS);
        assert!(!detector.owns_trip_flow(&flow_close(9, 0, 6)));
        assert!(detector.owns_trip_flow(&flow_close(9, PENDING_TRIP_FLOWS as u64, 6)));
    }

    /// A network canary recorded with an address that is not one (deployed
    /// before the deploy check) is indexed nowhere and trips nothing.
    #[test]
    fn a_network_canary_with_no_ip_address_is_not_indexed() {
        let dir = TempDir::new().unwrap();
        let (detector, registry) = build_detector(&dir);
        deploy_network_canary(&registry, &detector, "db.internal", 4444);
        assert!(detector.indexes.lock().is_empty());
        assert!(detector
            .process_event(&connect_to("127.0.0.1", 4444, 1, 1))
            .is_none());
    }
}
