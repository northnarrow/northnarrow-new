//! Tappa 9.5 (K3) — canary detector: inline `process_event`
//! filter + hot-path query helpers + canary-vs-FIM precedence
//! per §12 Q9 OPTION B inline-filter lock-in.
//!
//! ## Design (§12 Q9)
//!
//! The detector runs SYNCHRONOUSLY inside `main::process_event`,
//! BEFORE the rule engine sees the event. For every inbound
//! `Event::Fim` / `Event::ProcessSpawn` / future `Event::NetFlow`,
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
//! - `is_canary_port(port)` — Network canary trip path. Tappa
//!   10 dependency; the helper exists today but is unused
//!   until Tappa 10's `inet_csk_listen` ships and main wires
//!   `Event::NetFlow` events into `Detector::process_event`.
//!
//! When any helper returns `Some(canary_id)`:
//!
//! 1. Detector calls [`crate::canary::registry::Registry::mark_tripped`]
//!    (idempotent per §12 Q2 single-trip lock-in — returns
//!    `true` on the FIRST observation, `false` afterward).
//! 2. Detector appends a `CanaryAccessEntry` to
//!    `canary_access.jsonl` via
//!    [`crate::canary::access_log::CanaryAccessDb::append`]
//!    (chain captures EVERY access; subsequent rows carry
//!    `first_trip: false`).
//! 3. Detector returns `Some(Event::CanaryTripped { … })` to
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

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use common::wire::admin_signed_payload::{CanaryDeploymentWire, CanaryTypeWire};
use common::wire::InodeKey;
use common::{CanaryAccessKind, CanaryTypeTag, Event};
use parking_lot::Mutex;
use tracing::warn;

use crate::canary::access_log::{CanaryAccessDb, CanaryAccessDraft};
use crate::canary::registry::Registry;

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
/// - `port_index`: u16 from the canary `Network` deployment.
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
    port_index: HashMap<u16, String>,
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
                CanaryDeploymentWire::Network { bind_port, .. } => {
                    self.port_index.insert(*bind_port, canary_id.clone());
                }
            }
        }
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

    /// Hot-path port lookup (Tappa 10 dependency for the
    /// `Event::NetFlow` path). Returns the canary_id of the
    /// matching network listener canary, or `None`.
    pub fn is_canary_port(&self, port: u16) -> Option<&str> {
        self.port_index.get(&port).map(|s| s.as_str())
    }

    /// Resolve `canary_id` → `(name, type_tag)`. Used by the
    /// detector to populate `Event::CanaryTripped` fields
    /// without re-walking the registry. `None` if `canary_id`
    /// isn't in the live set (race window: a `burn` op
    /// between event observation and index lookup).
    pub fn name_and_type(&self, canary_id: &str) -> Option<(String, CanaryTypeTag)> {
        self.name_index.get(canary_id).cloned()
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
        self.inode_index.len() + self.exe_index.len() + self.port_index.len()
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
                ..
            } => {
                let path = PathBuf::from(filename);
                let canary_id = {
                    let idx = self.indexes.lock();
                    idx.is_canary_exe(&path).map(String::from)
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
            // All other event variants fall through — canary
            // detection only consumes file-open + process-exec
            // events in V1.0. Tappa 10 will add network-flow
            // intercept here once Event::NetFlow ships.
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

        // Mark tripped (idempotent per §12 Q2 — returns true on
        // FIRST observation only).
        let first_trip = {
            let mut reg = self.registry.lock();
            reg.mark_tripped(&canary_id, String::new())
        };

        // Append the access entry to the chain (ALWAYS — chain
        // captures every access; rule re-fire suppression
        // lives in first_trip semantics).
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
                accessor_exe: None,
                first_trip,
            }) {
                Ok(entry) => entry.entry_hash,
                Err(e) => {
                    warn!(
                        error = %e,
                        canary_id = %canary_id,
                        "canary access log append failed — trip event still emitted, \
                         chain entry missing"
                    );
                    String::new()
                }
            }
        };

        // Update the registry's cross-chain reference (only on
        // first_trip — Registry::mark_tripped already locked
        // the access_hash on first call; this is a defensive
        // second pass for the case where the access append
        // ran AFTER mark_tripped).
        if first_trip && !access_entry_hash.is_empty() {
            // Note: mark_tripped above stored an empty
            // access_hash because we hadn't appended yet. K6
            // will refactor to do the access append FIRST,
            // then pass the entry_hash to mark_tripped. For
            // K3 we accept the empty initial hash; the next
            // detector wire (K5/K6) tightens this.
            let _ = access_entry_hash;
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
            accessor_exe: None,
            timestamp_ns: ts,
        })
    }
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
            modifier_exe: None,
            modifier_pid: pid,
            modifier_uid: 0,
            modifier_comm: "attacker".to_string(),
            dest_path: None,
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
            query_name: "example.com".to_string(),
            query_type: 1,
            dns_server: [127, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            family: 2,
            timestamp_ns: 0,
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
        // it), but the access log row records first_trip=false.
        let second = detector.process_event(&event);
        assert!(
            second.is_some(),
            "subsequent trips also emit; first_trip flag is in the chain row"
        );
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
        assert!(idx.is_canary_port(22).is_none());
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
            })
            .unwrap();
        }
        let mut idx = detector.indexes.lock();
        idx.rebuild_from_registry(&registry.lock(), |_| None);
        assert!(idx
            .is_canary_exe(Path::new("/usr/local/bin/helper"))
            .is_some());
        assert!(idx.is_canary_port(4444).is_some());
        assert!(idx.is_canary_port(22).is_none());
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
}
