//! The canary detector's tests (Tappa 9.5 K3; external audit DEC-003,
//! DEC-005, DEC-011, DEC-014; lab PRs 163 and 246): a trip of each kind on
//! the agent's registry and access log, the indexes' rebuilds, the network
//! canaries, the connection a trip owns through the rule engine.
//!
//! R08b (lab PR 251): cut verbatim from `canary/detector.rs`, before the
//! detector moves to nn-core; they wire the agent's signed registry and
//! access log, its rules and its flow tracker, and stay with the agent.
//! They reach the detector's indexes through `Detector::indexes` and add a
//! file canary's path with `CanaryIndexes::add_file_path_index`, the
//! insert the K6 admin dispatch makes, where they wrote the private fields.

use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use common::wire::InodeKey;
use nn_model::{CanaryAccessKind, CanaryTypeTag, Event};
use nn_proto::admin_signed_payload::{CanaryDeploymentWire, CanaryTypeWire};
use parking_lot::Mutex;

use crate::canary::access_log::CanaryAccessDb;
use crate::canary::detector::*;
use crate::canary::registry::{CanaryTokenDraft, Registry};
use nn_model::telemetry::FimEvent;
use nn_model::telemetry::FimOp;
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
        let mut idx = indexes.indexes().lock();
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
        let mut idx = detector.indexes().lock();
        let canary_path = path.to_string();
        let canary_id_clone = canary_id.clone();
        idx.rebuild_from_registry(&registry.lock(), |_| None);
        // Also populate exe_index for the file canary so
        // the path-based fallback in process_event matches.
        // (In production K6 wiring, the rebuild_from_registry
        // closure would do this; for the test fixture we
        // patch it in directly.)
        idx.add_file_path_index(PathBuf::from(&canary_path), canary_id_clone);
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
    let canary_id = deploy_file_canary(&registry, &detector, "/tmp/decoy.txt", "test_file_canary");
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
        let mut idx = detector.indexes().lock();
        idx.rebuild_from_registry(&registry.lock(), |_| None);
        idx.add_file_path_index(PathBuf::from("/tmp/decoy.txt"), id.clone());
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
    let idx = detector.indexes().lock();
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
    let mut idx = detector.indexes().lock();
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
        let mut idx = detector.indexes().lock();
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
    detector.indexes().lock().rebuild_live(&registry.lock());
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
    let v = NnLCanary003NetworkConnect::<crate::chain_host_linux::LinuxHost>::default()
        .evaluate(&trip)
        .expect("NN-L-CANARY-003 fires");
    assert_eq!(v.rule_id, "NN-L-CANARY-003_NetworkConnect");
    assert_eq!(v.severity, nn_model::Severity::Critical);
    assert_eq!(v.action, nn_model::ResponseAction::KillProcessTree);
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
    detector.indexes().lock().rebuild_live(&registry.lock());
    assert!(detector
        .process_event(&connect_to("100.64.0.9", 4444, 1, 1))
        .is_none());
}

/// A TCP row of `pid`'s connection connected at `start_ns`, in `phase`,
/// to `dst_port` (0: a close the tracker synthesised for a refused
/// connect, whose port the kernel cleared).
fn flow_row(
    pid: u32,
    start_ns: u64,
    phase: nn_model::telemetry::FlowPhase,
    dst_port: u16,
) -> Event {
    Event::NetFlow(nn_model::telemetry::NetFlowEvent {
        start_ns,
        end_ns: start_ns + 1_000,
        family: 2,
        src_addr: "127.0.0.1".parse().unwrap(),
        src_port: 40000,
        dst_addr: "100.64.0.9".parse().unwrap(),
        dst_port,
        proto: 6,
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
        phase,
        observed_ns: start_ns + 1_000,
    })
}

/// Lab PR 163 / 246: the trip of a network canary names its connection
/// as every row of the connection does — the connecting process and the
/// connect's time — and the engine owns that connection from the trip
/// on (main does not judge it again: NN-L-CHAIN-003 fired on it, a
/// second response to one access). Every row: the close, resolved or
/// synthesised (port 0), a connect-time row after the close, a
/// snapshot. Another flow of the same process is an egress after the
/// trip (NN-L-CHAIN-003); another process's flow, and a file canary
/// trip, own nothing.
#[test]
fn the_trip_owns_every_row_of_its_connection() {
    use nn_model::telemetry::FlowPhase;
    let dir = TempDir::new().unwrap();
    let (detector, registry) = build_detector(&dir);
    deploy_network_canary(&registry, &detector, "100.64.0.9", 4444);
    let engine = crate::decision::RuleEngine::with_default_rules();
    let trip = detector
        .process_event(&connect_to("100.64.0.9", 4444, 7001, 9_000))
        .expect("a trip");
    let Event::CanaryTripped {
        accessor_pid,
        timestamp_ns,
        ..
    } = &trip
    else {
        panic!("{trip:?}");
    };
    assert_eq!((*accessor_pid, *timestamp_ns), (7001, 9_000));
    let before = flow_row(7001, 9_000, FlowPhase::Closed, 0);
    assert!(!engine.owned_by_trip(&before), "no trip decided yet");
    let d = engine.decide(&trip).expect("NN-L-CANARY-003");
    assert_eq!(d.verdict.rule_id, "NN-L-CANARY-003_NetworkConnect");
    for row in [
        flow_row(7001, 9_000, FlowPhase::Closed, 0),
        flow_row(7001, 9_000, FlowPhase::Closed, 4444),
        flow_row(7001, 9_000, FlowPhase::Connect, 4444),
        flow_row(7001, 9_000, FlowPhase::Snapshot, 4444),
    ] {
        assert!(engine.owned_by_trip(&row), "{row:?}");
        assert!(engine.decide(&row).is_none(), "{row:?}");
    }
    let egress = flow_row(7001, 9_001, FlowPhase::Closed, 443);
    assert!(!engine.owned_by_trip(&egress));
    let d = engine.decide(&egress).expect("an egress after the trip");
    assert!(
        d.matches
            .iter()
            .any(|m| m.rule_id == "NN-L-CHAIN-003_CanaryThenEgress"),
        "{:?}",
        d.verdict
    );
    assert!(!engine.owned_by_trip(&flow_row(7002, 9_000, FlowPhase::Closed, 4444)));
    deploy_file_canary(&registry, &detector, "/tmp/decoy.txt", "f");
    let mut fim = fim_event_on("/tmp/decoy.txt", 7003);
    if let Event::Fim(fe) = &mut fim {
        fe.timestamp_ns = 9_500;
    }
    let file_trip = detector.process_event(&fim).expect("a file trip");
    engine.decide(&file_trip);
    assert!(!engine.owned_by_trip(&flow_row(7003, 9_500, FlowPhase::Closed, 4444)));
}

/// The bus as `main::process_event` takes it: the detector first (a
/// connect to a canary becomes its trip), a row a trip owns not judged
/// again, every other event decided by the engine. The rules that
/// answered each item.
fn agent_path(
    detector: &Detector,
    engine: &crate::decision::RuleEngine,
    bus: &[Event],
) -> Vec<Vec<&'static str>> {
    bus.iter()
        .map(|e| {
            let e = detector.process_event(e).unwrap_or_else(|| e.clone());
            if engine.owned_by_trip(&e) {
                return Vec::new();
            }
            engine
                .decide(&e)
                .map(|d| d.matches.iter().map(|m| m.rule_id).collect())
                .unwrap_or_default()
        })
        .collect()
}

/// Lab PR 246 — the KVM failure of 27/10/2026 (job 122036206565), in
/// every order the connect and the close of a canary trip can take.
/// A shell (pid 9825) connects to a network canary on a loopback port
/// nothing listens on: refused, the shell closes the socket at once,
/// and the kernel clears the destination port before the close. The
/// connect (`TcpConnect`, its pump) and the close (the net drain) come
/// on two rings; the flow tracker hears one first, the bus carries
/// them in either order. In the CI run the tracker heard the close
/// first (a synthesised row, `tcp 127.0.0.1:0 closed`, which started
/// at the close) and the bus the connect first: the trip owned
/// (pid, connect time), the row carried (pid, close time), and
/// NN-L-CHAIN-003 answered the trip's own connection.
///
/// In every order: NN-L-CANARY-003 once, on the trip; no chain verdict
/// on any row of the trip's connection, neither in order nor completed
/// by a precursor processed late — a credential read (NN-L-CHAIN-001,
/// CHAIN-007), the shell's exec from a staging directory
/// (NN-L-CHAIN-002 of lab PR 244, CHAIN-007), both in kernel time
/// before the connect; and a later flow of the shell is still an
/// egress after the trip (CHAIN-003).
#[test]
fn the_trips_own_connection_draws_no_chain_verdict_in_any_order() {
    use crate::net::flow_tracker::{FlowTracker, TcpCloseInfo, TcpConnectInfo};
    use nn_model::telemetry::{FimEvent, FimOp, FlowPhase};

    const PID: u32 = 9825;
    const T0: u64 = 3_600_000_000_000;
    const SK: u64 = 0xffff_8880_1234_5678;
    let localhost: IpAddr = "127.0.0.1".parse().unwrap();
    let conn = TcpConnectInfo {
        start_ns: T0,
        sk_ptr: SK,
        family: 2,
        src_addr: "0.0.0.0".parse().unwrap(),
        src_port: 0,
        dst_addr: localhost,
        dst_port: 41147,
        proto: 6,
        pid: PID,
        uid: 0,
        comm: "bash".into(),
        exe: Some("/usr/bin/bash".into()),
        proc_start_ns: 0,
    };
    let close = TcpCloseInfo {
        end_ns: T0 + 40_000,
        corr_id: FlowTracker::corr_id(T0, SK),
        src_addr: localhost,
        src_port: 52_000,
        bytes_sent: 0,
        bytes_recv: 0,
        close_reason: 0,
        family: 2,
        dst_addr: localhost,
        dst_port: 0,
        pid: PID,
        uid: 0,
        comm: "bash".into(),
    };
    let late_read = Event::Fim(FimEvent {
        timestamp_ns: T0 - 1_000_000_000,
        path: "/root/.password-store/bank.gpg".into(),
        op: FimOp::Opened,
        new_sha256: None,
        baseline_sha256: None,
        new_size: None,
        baseline_size: None,
        modifier_exe: Some("/usr/bin/bash".into()),
        modifier_pid: PID,
        modifier_uid: 0,
        modifier_comm: "bash".into(),
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
    });
    let late_exec = Event::ProcessSpawn {
        pid: PID,
        ppid: 1,
        uid: 0,
        gid: 0,
        comm: "bash".into(),
        filename: "/tmp/.x/bash".into(),
        timestamp_ns: T0 - 2_000_000_000,
        argv: vec!["/tmp/.x/bash".into()],
        parent_comm: "systemd".into(),
        parent_start_ns: 0,
        start_ns: T0 - 3_000_000_000,
        parent_is_kthread: false,
        exe: nn_model::ExeIdentity {
            path: "/tmp/.x/bash".into(),
            ..Default::default()
        },
        argv_truncated: false,
        filename_truncated: false,
        stdio: Default::default(),
    };
    let later_egress = Event::NetFlow(nn_model::telemetry::NetFlowEvent {
        start_ns: T0 + 2_000_000_000,
        end_ns: T0 + 3_000_000_000,
        family: 2,
        src_addr: "10.0.2.15".parse().unwrap(),
        src_port: 52_100,
        dst_addr: "203.0.113.7".parse().unwrap(),
        dst_port: 443,
        proto: 6,
        pid: PID,
        uid: 0,
        comm: "bash".into(),
        exe: Some("/usr/bin/bash".into()),
        proc_start_ns: 0,
        bytes_sent: 4096,
        bytes_recv: 512,
        resolved_hostname: None,
        tls_fingerprint: None,
        flow_id: String::new(),
        close_reason: 0,
        phase: FlowPhase::Closed,
        observed_ns: 0,
    });
    let trip = connect_to("127.0.0.1", 41147, PID, T0);

    // (tracker hears the close first?, bus order of C(onnect), O(pen
    // row), X (the close)), the CI's first.
    for (close_first, bus) in [
        (true, "CX"),
        (true, "XC"),
        (false, "COX"),
        (false, "CXO"),
        (false, "XCO"),
    ] {
        let dir = TempDir::new().unwrap();
        let (detector, registry) = build_detector(&dir);
        deploy_network_canary(&registry, &detector, "127.0.0.1", 41147);
        let engine = crate::decision::RuleEngine::with_default_rules();
        let mut tracker = FlowTracker::default();
        let (open, closed) = if close_first {
            let x = tracker.on_tcp_close(&close).expect("synthesised");
            assert!(tracker.on_tcp_connect(&conn).is_none(), "ignored");
            (None, x)
        } else {
            let o = tracker.on_tcp_connect(&conn).expect("connect-time row");
            (Some(o), tracker.on_tcp_close(&close).expect("resolved"))
        };
        assert_eq!(
            (closed.pid, closed.start_ns),
            (PID, T0),
            "the close names the connection as its connect"
        );
        let items: Vec<Event> = bus
            .chars()
            .map(|c| match c {
                'C' => trip.clone(),
                'O' => Event::NetFlow(open.clone().expect("an open row")),
                _ => Event::NetFlow(closed.clone()),
            })
            .chain([late_read.clone(), late_exec.clone(), later_egress.clone()])
            .collect();
        let answers = agent_path(&detector, &engine, &items);
        let case = format!("close first: {close_first}, bus: {bus}");
        let n = bus.len();
        for (c, rules) in bus.chars().zip(&answers) {
            match c {
                'C' => assert_eq!(rules, &["NN-L-CANARY-003_NetworkConnect"], "{case}"),
                _ => assert!(
                    !rules.iter().any(|r| r.starts_with("NN-L-CHAIN-")),
                    "{case}: the trip's own connection drew {rules:?}"
                ),
            }
        }
        for late in [n, n + 1] {
            assert!(
                !answers[late].iter().any(|r| r.starts_with("NN-L-CHAIN-")),
                "{case}: a late precursor completed a chain with the trip's connection: {:?}",
                answers[late]
            );
        }
        assert!(
            answers[n + 1].contains(&"R001_ExecFromTmp"),
            "{case}: the late exec's own rule: {:?}",
            answers[n + 1]
        );
        assert!(
            answers[n + 2].contains(&"NN-L-CHAIN-003_CanaryThenEgress"),
            "{case}: a later flow is an egress after the trip: {:?}",
            answers[n + 2]
        );
    }
}

/// A network canary recorded with an address that is not one (deployed
/// before the deploy check) is indexed nowhere and trips nothing.
#[test]
fn a_network_canary_with_no_ip_address_is_not_indexed() {
    let dir = TempDir::new().unwrap();
    let (detector, registry) = build_detector(&dir);
    deploy_network_canary(&registry, &detector, "db.internal", 4444);
    assert!(detector.indexes().lock().is_empty());
    assert!(detector
        .process_event(&connect_to("127.0.0.1", 4444, 1, 1))
        .is_none());
}
