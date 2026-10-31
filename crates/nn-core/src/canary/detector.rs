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
//! index against the canary registry's live set:
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
//!   accessor (the agent's `canary::network` says why it is the
//!   connect, not an accept). Every row of that connection
//!   (`Event::NetFlow`: its connect-time row, snapshots, close) belongs
//!   to the trip: the engine's flow ledger owns it from the trip on
//!   (lab PR 246, [`crate::decision::RuleEngine::owned_by_trip`]).
//!
//! When any helper returns `Some(canary_id)`, under the registry lock:
//!
//! 1. Detector asks the registry whether the canary is still armed
//!    ([`CanaryHost::is_armed`]): this access is
//!    then the first trip (§12 Q2 single-trip lock-in).
//! 2. Detector appends a `CanaryAccessEntry` to
//!    `canary_access.jsonl` via
//!    [`CanaryHost::append_access`]
//!    (chain captures EVERY access; subsequent rows carry
//!    `first_trip: false`).
//! 3. On a first trip, [`CanaryHost::mark_tripped`]
//!    appends a signed `Trip` row carrying that access row's
//!    `entry_hash` (external audit DEC-011: the state survives a
//!    restart; the hash used to be left empty).
//! 4. Detector returns `Some(Event::CanaryTripped { … })` to
//!    the caller. main::process_event REPLACES the source
//!    event with this and routes through the canary rule
//!    family (K5 NN-L-CANARY-001..004), skipping the FIM
//!    rule layer entirely (precedence guarantee).
//!
//! ## A stop between the steps (lab PR 260)
//!
//! Each row is written and synced before the next step. The access row of
//! step 2 is the trip's commit: before it is on disk nothing records the
//! access (a torn row is cut at the next open), and once it is, the trip
//! holds — the registry's open records a first-trip row that no `Trip` row
//! names (the Linux host: `Registry::unrecorded_trips`). A stop between
//! steps 2 and 3 used to leave the registry at its deploy row, and the next
//! start re-armed the canary: the trip forgotten, the next access a first
//! trip again (lab PR 258's KVM run, the e2e fixture's SIGQUIT between
//! the two rows). A stop after step 3 leaves both rows; as for any event
//! the agent has read, a response that had not run by then does not run.
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
//!
//! ## Host (Wave 4 restructure, R08b, lab PR 251)
//!
//! Moved from the agent to nn-core with the rule engine. The registry,
//! the access log, this host's addresses, the read-forward set, a
//! canary's inode and an accessor's executable are the host's
//! ([`CanaryHost`]: the agent's `LinuxHost`, `canary_host_linux`); the
//! detector and its indexes take the host as a type parameter and call it
//! where they called the agent's modules, `stat(2)` and `/proc`, with the
//! same arguments. The agent names them on its host under their old paths
//! (`canary::detector::{Detector, CanaryIndexes}`); its tests of them,
//! which wire its registry and access log, stay there.

use std::collections::HashMap;
use std::marker::PhantomData;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use common::wire::InodeKey;
use nn_model::{CanaryAccessKind, CanaryTypeTag, Event};
use nn_proto::admin_signed_payload::{CanaryDeploymentWire, CanaryTypeWire};
use parking_lot::Mutex;
use tracing::{error, warn};

use crate::canary::host::{CanaryAccessDraft, CanaryHost};
use crate::canary::network::{connect_destination, CanaryAddr, PortCanaries};

// ── hot-path indexes ────────────────────────────────────────────────

/// Hot-path indexes derived from the registry's live set.
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
pub struct CanaryIndexes<H: CanaryHost> {
    inode_index: HashMap<InodeKey, String>,
    exe_index: HashMap<PathBuf, String>,
    port_index: HashMap<u16, PortCanaries>,
    /// Reverse lookup `canary_id → name` for trip-event
    /// construction without re-walking the registry.
    name_index: HashMap<String, (String, CanaryTypeTag)>,
    /// Where a rebuild publishes the file canaries' inodes (R11c, lab PR
    /// 264: the set the start gives, [`Self::with_read_forward`]; a
    /// process-wide one until then).
    read_forward: H::ReadForward,
    /// R08b: the host whose registry the indexes are rebuilt from.
    host: PhantomData<fn() -> H>,
}

// R08b: the derives' output, without a bound on the host.
impl<H: CanaryHost> std::fmt::Debug for CanaryIndexes<H> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CanaryIndexes")
            .field("inode_index", &self.inode_index)
            .field("exe_index", &self.exe_index)
            .field("port_index", &self.port_index)
            .field("name_index", &self.name_index)
            .finish()
    }
}

impl<H: CanaryHost> Default for CanaryIndexes<H> {
    fn default() -> Self {
        Self {
            inode_index: HashMap::default(),
            exe_index: HashMap::default(),
            port_index: HashMap::default(),
            name_index: HashMap::default(),
            read_forward: H::ReadForward::default(),
            host: PhantomData,
        }
    }
}

impl<H: CanaryHost> CanaryIndexes<H> {
    /// These indexes publishing the file canaries' inodes into
    /// `read_forward` (the agent: the FIM drain's set).
    pub fn with_read_forward(mut self, read_forward: H::ReadForward) -> Self {
        self.read_forward = read_forward;
        self
    }

    /// The set a rebuild publishes into.
    pub fn read_forward(&self) -> &H::ReadForward {
        &self.read_forward
    }

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
    pub fn rebuild_from_registry<F>(&mut self, registry: &H::Registry, inode_resolver: F)
    where
        F: Fn(&Path) -> Option<InodeKey>,
    {
        self.inode_index.clear();
        self.exe_index.clear();
        self.port_index.clear();
        self.name_index.clear();
        for canary in H::live(registry) {
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
        H::publish_read_forward(&self.read_forward, self.inode_index.keys().copied());
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
    /// ([`CanaryHost::inode_key`]) and File/Credential paths layered into the
    /// path index, in one place.
    pub fn rebuild_live(&mut self, registry: &H::Registry) {
        self.rebuild_from_registry(registry, H::inode_key);
        for canary in H::live(registry) {
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
pub struct Detector<H: CanaryHost> {
    registry: Arc<Mutex<H::Registry>>,
    access_log: Arc<Mutex<H::AccessLog>>,
    indexes: Arc<Mutex<CanaryIndexes<H>>>,
    /// This host's addresses, for the wildcard network canaries.
    local_addrs: H::LocalAddrs,
    /// R12b (lab PR 269, plan §3.4): the writer's queue — the trips' access
    /// rows and registry marks, written off the decision thread
    /// ([`Self::with_writer`]); none: written in [`Self::process_event`],
    /// as before (the tests, the replay).
    writer: Option<std::sync::mpsc::SyncSender<TripWrite>>,
    /// The canaries whose first trip was decided and is not yet in the
    /// registry (the writer's) — or could not be marked there: a later
    /// access is not a first trip (it holds for this run).
    decided: Mutex<std::collections::HashSet<String>>,
    /// Trips queued and not yet written ([`Self::flush`]).
    queued: std::sync::atomic::AtomicUsize,
}

/// R12b: one trip for the writer — its access row, and whether it is the
/// canary's first (its registry mark).
#[derive(Debug, Clone)]
pub struct TripWrite {
    pub draft: CanaryAccessDraft,
}

impl<H: CanaryHost> Detector<H> {
    /// Build with shared handles. Caller (main.rs) wires
    /// the Registry + AccessDb at boot and clones the Arcs.
    pub fn new(
        registry: Arc<Mutex<H::Registry>>,
        access_log: Arc<Mutex<H::AccessLog>>,
        indexes: Arc<Mutex<CanaryIndexes<H>>>,
    ) -> Self {
        Self {
            registry,
            access_log,
            indexes,
            local_addrs: H::LocalAddrs::default(),
            writer: None,
            decided: Mutex::new(std::collections::HashSet::new()),
            queued: std::sync::atomic::AtomicUsize::new(0),
        }
    }

    /// R12b (lab PR 269): the trips' access rows and registry marks go to
    /// `queue` — a writer that calls [`Self::write_trip`] for each, in order
    /// — instead of being written in [`Self::process_event`] (the
    /// decision's: no chain write on its thread). A full queue holds the
    /// decision until the writer takes one, as the inline write did.
    pub fn with_writer(mut self, queue: std::sync::mpsc::SyncSender<TripWrite>) -> Self {
        self.writer = Some(queue);
        self
    }

    /// The writer's work for one trip, as [`Self::process_event`] did it
    /// inline (external audit DEC-011, lab PR 260): the access row
    /// appended — always, every access is in the chain — then, for a first
    /// trip, the registry's mark naming that row. A failed write is
    /// reported; the trip event went out already.
    pub fn write_trip(&self, job: TripWrite) {
        let canary_id = job.draft.canary_id.clone();
        let first_trip = job.draft.first_trip;
        let mut reg = self.registry.lock();
        let access_entry_hash = self.append_row(job.draft);
        if first_trip {
            self.mark(&mut reg, &canary_id, access_entry_hash);
        }
        drop(reg);
        self.queued
            .fetch_sub(1, std::sync::atomic::Ordering::AcqRel);
    }

    /// Wait until the writer has written every trip queued, at most
    /// `within` (the stop's: the rows in the chain before the agent ends).
    /// `false` when some were left.
    pub fn flush(&self, within: std::time::Duration) -> bool {
        let started = std::time::Instant::now();
        while self.queued.load(std::sync::atomic::Ordering::Acquire) > 0 {
            if started.elapsed() >= within {
                return false;
            }
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        true
    }

    /// The access row, its `entry_hash` (`None`: not written, reported).
    fn append_row(&self, draft: CanaryAccessDraft) -> Option<String> {
        let canary_id = draft.canary_id.clone();
        let mut log = self.access_log.lock();
        match H::append_access(&mut log, draft) {
            Ok(entry_hash) => Some(entry_hash),
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
    }

    /// The registry's mark of a first trip, naming its access row.
    fn mark(&self, reg: &mut H::Registry, canary_id: &str, access_entry_hash: Option<String>) {
        let access_row_written = access_entry_hash.is_some();
        match H::mark_tripped(reg, canary_id, access_entry_hash) {
            Ok(_) => {
                self.decided.lock().remove(canary_id);
            }
            Err(e) => {
                // Lab PR 260: the next start records a trip its access
                // row holds.
                let after_a_restart = if access_row_written {
                    "the next start records it from its access row"
                } else {
                    "its access row is missing too: a restart re-arms the canary"
                };
                error!(
                    error = %format!("{e:#}"),
                    canary_id = %canary_id,
                    after_a_restart,
                    "canary trip not recorded in the registry — it holds for this run"
                );
            }
        }
    }

    /// The detector's indexes, for the agent's tests of it
    /// (`canary::detector_tests`) to rebuild after a deploy.
    #[cfg(any(test, feature = "test-util"))]
    pub fn indexes(&self) -> &Arc<Mutex<CanaryIndexes<H>>> {
        &self.indexes
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
                    idx.is_canary_destination(dst, *dst_port, &|a| {
                        H::is_local(&self.local_addrs, a)
                    })
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
        let accessor_exe = H::accessor_exe(accessor_pid);

        // External audit DEC-011: under the registry lock, decide whether
        // this is the first trip, append the access row (ALWAYS — the
        // chain captures every access; re-fire suppression lives in
        // first_trip), then record the trip in the registry with that
        // row's hash. A failed write is reported and the event is still
        // emitted. Lab PR 260: the access row is the trip's commit, the
        // registry's row names it (see the module doc). R12b (lab PR 269):
        // with a writer, the row and the mark are the writer's, in that
        // order ([`Self::write_trip`]); the first trip is decided here, and
        // a later access before the mark is not one.
        let first_trip = {
            let mut reg = self.registry.lock();
            let first_trip = {
                let mut decided = self.decided.lock();
                let first = H::is_armed(&reg, &canary_id) && !decided.contains(&canary_id);
                if first {
                    decided.insert(canary_id.clone());
                }
                first
            };
            let draft = CanaryAccessDraft {
                canary_id: canary_id.clone(),
                canary_name: canary_name.clone(),
                canary_type: canary_type_tag,
                access_kind,
                accessor_pid,
                accessor_uid,
                accessor_comm: accessor_comm.clone(),
                accessor_exe: accessor_exe.clone(),
                first_trip,
            };
            match &self.writer {
                Some(queue) => {
                    drop(reg);
                    self.queued
                        .fetch_add(1, std::sync::atomic::Ordering::AcqRel);
                    if queue
                        .send(TripWrite {
                            draft: draft.clone(),
                        })
                        .is_err()
                    {
                        // the writer is gone: written here, as before
                        self.queued
                            .fetch_sub(1, std::sync::atomic::Ordering::AcqRel);
                        let mut reg = self.registry.lock();
                        let hash = self.append_row(draft);
                        if first_trip {
                            self.mark(&mut reg, &canary_id, hash);
                        }
                    }
                }
                None => {
                    let access_entry_hash = self.append_row(draft);
                    if first_trip {
                        self.mark(&mut reg, &canary_id, access_entry_hash);
                    }
                }
            }
            first_trip
        };

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
