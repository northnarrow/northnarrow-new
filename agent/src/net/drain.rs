//! Tappa 10 (N9) — kernel→userland net drain loop.
//!
//! Drains the two Tappa 10 N2 ringbufs in a single tokio task and
//! turns each kernel record into a finalised [`NetFlowEvent`] /
//! [`NetListenerEvent`] on the agent's event bus, persisting one
//! row to the chained on-disk log per emission (design §4.4 + §10).
//!
//! Drains:
//!   - `NET_FLOW_CLOSE_EVENTS` ringbuf — TCP close fexit +
//!     UDP outbound kprobe (one shared ringbuf, design §13 Q3
//!     LOCK-IN). For TCP records the [`FlowTracker`] correlates
//!     the kernel `corr_id` with the in-process `PendingFlow`
//!     populated at connect time; for UDP records the tracker
//!     synthesises a per-send `NetFlowEvent`. DNS attribution
//!     pulls the most-recent same-PID qname out of [`DnsCache`].
//!   - `NET_LISTEN_EVENTS` ringbuf — `inet_csk_listen_start`
//!     kprobe. Emitted unconditionally per §13 Q6 forensic-
//!     visibility lock-in; the rule layer applies the operator-
//!     tunable comm/port filter (NN-L-NET-006).
//!
//! Both records emit through the same `mpsc::Sender<Event>` the
//! sensor multiplexer feeds the main loop with, so the rule engine
//! sees `Event::NetFlow` / `Event::NetListener` items via the
//! existing `process_event` path (`main::process_event` already
//! has match arms for both — added in N6).

use std::fs::OpenOptions;
use std::io::{BufRead, BufReader, Write};
use std::net::IpAddr;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{anyhow, Context, Result};
use aya::maps::{ring_buf::RingBuf, MapData};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use chrono::{DateTime, Utc};
use common::wire::{NetFlowCloseRaw, NetFlowEvent, NetListenRaw, NetListenerEvent};
use common::Event;
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::io::unix::AsyncFd;
use tokio::sync::mpsc;
use tracing::{debug, warn};

use crate::audit::{AgentSigningKey, GENESIS_PREV_HASH};
use crate::net::dns_cache::DnsCache;
use crate::net::flow_tracker::{FlowTracker, TcpCloseInfo, UdpSendInfo};

/// Default on-disk location of the chained NetListener log
/// (design §6.4). Mirrors `admin_socket::DEFAULT_NETFLOW_JSONL_PATH`
/// — the listeners log is the second of the two Tappa 10
/// LSM-protected state files.
pub const DEFAULT_NETFLOW_LISTENERS_JSONL_PATH: &str =
    "/var/lib/northnarrow/netflow_listeners.jsonl";

/// Permission bits applied to the netflow + netflow_listeners
/// logs at create time. 0644 — world-readable for operator
/// inspection, agent-writable; LSM PROTECTED_INODES + PROTECTED_PIDS
/// exemption enforces append-only against other root callers.
const NET_LOG_FILE_MODE: u32 = 0o644;

const IPPROTO_TCP: u8 = 6;
const IPPROTO_UDP: u8 = 17;
const AF_INET: u8 = 2;

// ── on-disk JSONL row shapes ─────────────────────────────────────────

/// One on-disk JSONL row in `netflow.jsonl` (design §4.4).
/// Same chain shape as the Tappa 8 audit log + Tappa 9
/// baseline/drift chains so verification reuses the existing
/// primitives. `prev_hash` / `entry_hash` / `agent_sig` are
/// the chain link; the body fields above are the flow facts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetFlowEntry {
    pub ts: String,
    pub flow_id: String,
    pub start_ns: u64,
    pub end_ns: u64,
    pub family: u8,
    pub src_addr: String,
    pub src_port: u16,
    pub dst_addr: String,
    pub dst_port: u16,
    pub proto: u8,
    pub pid: u32,
    pub uid: u32,
    pub comm: String,
    pub exe: Option<String>,
    pub bytes_sent: u64,
    pub bytes_recv: u64,
    pub resolved_hostname: Option<String>,
    pub ja3: Option<String>,
    pub ja4: Option<String>,
    pub sni: Option<String>,
    pub close_reason: u8,
    pub agent_id: String,
    pub prev_hash: String,
    pub entry_hash: String,
    pub agent_sig: String,
}

/// One on-disk JSONL row in `netflow_listeners.jsonl`. Same chain
/// shape as [`NetFlowEntry`]; thinner body (no five-tuple, no
/// bytes counters, no TLS fingerprint).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetListenerEntry {
    pub ts: String,
    pub timestamp_ns: u64,
    pub family: u8,
    pub bind_addr: String,
    pub bind_port: u16,
    pub proto: u8,
    pub pid: u32,
    pub uid: u32,
    pub comm: String,
    pub exe: Option<String>,
    pub agent_id: String,
    pub prev_hash: String,
    pub entry_hash: String,
    pub agent_sig: String,
}

// ── chained writers ──────────────────────────────────────────────────

/// Append-only chained writer for `netflow.jsonl`. Mirrors
/// [`crate::fim::drain::FimDriftDb`] — single-writer DB serialised
/// inside `Arc<Mutex<_>>` from the drain task.
pub struct NetFlowDb {
    path: PathBuf,
    key: AgentSigningKey,
    agent_id: [u8; 16],
    last_hash: String,
}

impl NetFlowDb {
    pub fn open(path: &Path, key: AgentSigningKey, agent_id: [u8; 16]) -> Result<Self> {
        let last_hash = read_tail_hash_flow(path)?;
        Ok(Self {
            path: path.to_path_buf(),
            key,
            agent_id,
            last_hash,
        })
    }

    pub fn append(&mut self, ev: &NetFlowEvent) -> Result<NetFlowEntry> {
        let mut entry = NetFlowEntry {
            ts: format_ts(Utc::now()),
            flow_id: ev.flow_id.clone(),
            start_ns: ev.start_ns,
            end_ns: ev.end_ns,
            family: ev.family,
            src_addr: ev.src_addr.to_string(),
            src_port: ev.src_port,
            dst_addr: ev.dst_addr.to_string(),
            dst_port: ev.dst_port,
            proto: ev.proto,
            pid: ev.pid,
            uid: ev.uid,
            comm: ev.comm.clone(),
            exe: ev.exe.clone(),
            bytes_sent: ev.bytes_sent,
            bytes_recv: ev.bytes_recv,
            resolved_hostname: ev.resolved_hostname.clone(),
            ja3: ev.tls_fingerprint.as_ref().map(|fp| fp.ja3.clone()),
            ja4: ev.tls_fingerprint.as_ref().map(|fp| fp.ja4.clone()),
            sni: ev.tls_fingerprint.as_ref().and_then(|fp| fp.sni.clone()),
            close_reason: ev.close_reason,
            agent_id: hex::encode(self.agent_id),
            prev_hash: self.last_hash.clone(),
            entry_hash: String::new(),
            agent_sig: String::new(),
        };
        let hash = compute_flow_entry_hash(&entry)?;
        entry.entry_hash = hex::encode(hash);
        let sig = self.key.sign(&hash);
        entry.agent_sig = B64.encode(sig.to_bytes());
        let mut line =
            serde_json::to_string(&entry).map_err(|e| anyhow!("serialising netflow entry: {e}"))?;
        line.push('\n');
        let mut f = OpenOptions::new()
            .create(true)
            .append(true)
            .mode(NET_LOG_FILE_MODE)
            .open(&self.path)
            .with_context(|| format!("opening netflow log {} for append", self.path.display()))?;
        f.write_all(line.as_bytes())
            .with_context(|| format!("appending netflow entry to {}", self.path.display()))?;
        f.sync_all()
            .with_context(|| format!("fsync {}", self.path.display()))?;
        self.last_hash = entry.entry_hash.clone();
        Ok(entry)
    }

    pub fn last_hash(&self) -> &str {
        &self.last_hash
    }
}

/// Append-only chained writer for `netflow_listeners.jsonl`. Same
/// shape as [`NetFlowDb`].
pub struct NetListenerDb {
    path: PathBuf,
    key: AgentSigningKey,
    agent_id: [u8; 16],
    last_hash: String,
}

impl NetListenerDb {
    pub fn open(path: &Path, key: AgentSigningKey, agent_id: [u8; 16]) -> Result<Self> {
        let last_hash = read_tail_hash_listener(path)?;
        Ok(Self {
            path: path.to_path_buf(),
            key,
            agent_id,
            last_hash,
        })
    }

    pub fn append(&mut self, ev: &NetListenerEvent) -> Result<NetListenerEntry> {
        let mut entry = NetListenerEntry {
            ts: format_ts(Utc::now()),
            timestamp_ns: ev.timestamp_ns,
            family: ev.family,
            bind_addr: ev.bind_addr.to_string(),
            bind_port: ev.bind_port,
            proto: ev.proto,
            pid: ev.pid,
            uid: ev.uid,
            comm: ev.comm.clone(),
            exe: ev.exe.clone(),
            agent_id: hex::encode(self.agent_id),
            prev_hash: self.last_hash.clone(),
            entry_hash: String::new(),
            agent_sig: String::new(),
        };
        let hash = compute_listener_entry_hash(&entry)?;
        entry.entry_hash = hex::encode(hash);
        let sig = self.key.sign(&hash);
        entry.agent_sig = B64.encode(sig.to_bytes());
        let mut line = serde_json::to_string(&entry)
            .map_err(|e| anyhow!("serialising netflow_listener entry: {e}"))?;
        line.push('\n');
        let mut f = OpenOptions::new()
            .create(true)
            .append(true)
            .mode(NET_LOG_FILE_MODE)
            .open(&self.path)
            .with_context(|| {
                format!(
                    "opening netflow_listeners log {} for append",
                    self.path.display()
                )
            })?;
        f.write_all(line.as_bytes()).with_context(|| {
            format!(
                "appending netflow_listeners entry to {}",
                self.path.display()
            )
        })?;
        f.sync_all()
            .with_context(|| format!("fsync {}", self.path.display()))?;
        self.last_hash = entry.entry_hash.clone();
        Ok(entry)
    }

    pub fn last_hash(&self) -> &str {
        &self.last_hash
    }
}

// ── drain loop ───────────────────────────────────────────────────────

/// Tokio task body — drains both N2 ringbufs concurrently via
/// `tokio::select!` on their `AsyncFd` readability. Per-record
/// processing is delegated to [`process_close_record`] /
/// [`process_listen_record`]; the outer loop only owns the two
/// `AsyncFd`s + the readiness drain.
///
/// Returns `Ok(())` when both pumps cleanly shut down (event_tx
/// receiver dropped → end-of-life); propagates `io::Error` from
/// `AsyncFd::new` failures only — per-record decode failures are
/// `warn!`-logged and skipped (mirrors `fim::drain::drain_loop`'s
/// degrade-not-fail posture).
#[allow(clippy::too_many_arguments)]
pub async fn drain_loop(
    close_rb: RingBuf<MapData>,
    listen_rb: RingBuf<MapData>,
    flow_tracker: Arc<Mutex<FlowTracker>>,
    dns_cache: Arc<DnsCache>,
    netflow_db: Arc<Mutex<NetFlowDb>>,
    listener_db: Arc<Mutex<NetListenerDb>>,
    event_tx: mpsc::Sender<Event>,
) -> std::io::Result<()> {
    let mut close_fd = AsyncFd::new(close_rb)?;
    let mut listen_fd = AsyncFd::new(listen_rb)?;
    loop {
        tokio::select! {
            r = close_fd.readable_mut() => {
                let mut guard = r?;
                let inner = guard.get_inner_mut();
                let mut drained = 0u32;
                while let Some(item) = inner.next() {
                    drained += 1;
                    process_close_record(
                        item.as_ref(),
                        &flow_tracker,
                        &dns_cache,
                        &netflow_db,
                        &event_tx,
                    )
                    .await;
                }
                guard.clear_ready();
                if drained == 0 {
                    tokio::time::sleep(std::time::Duration::from_millis(1)).await;
                }
            }
            r = listen_fd.readable_mut() => {
                let mut guard = r?;
                let inner = guard.get_inner_mut();
                let mut drained = 0u32;
                while let Some(item) = inner.next() {
                    drained += 1;
                    process_listen_record(item.as_ref(), &listener_db, &event_tx).await;
                }
                guard.clear_ready();
                if drained == 0 {
                    tokio::time::sleep(std::time::Duration::from_millis(1)).await;
                }
            }
        }
    }
}

async fn process_close_record(
    bytes: &[u8],
    flow_tracker: &Arc<Mutex<FlowTracker>>,
    dns_cache: &Arc<DnsCache>,
    netflow_db: &Arc<Mutex<NetFlowDb>>,
    event_tx: &mpsc::Sender<Event>,
) {
    let raw: &NetFlowCloseRaw = match bytemuck::try_from_bytes(bytes) {
        Ok(r) => r,
        Err(e) => {
            warn!(
                expected = std::mem::size_of::<NetFlowCloseRaw>(),
                got = bytes.len(),
                error = %e,
                "NET_FLOW_CLOSE_EVENTS ringbuf entry rejected"
            );
            return;
        }
    };
    let mut event = match raw.proto {
        IPPROTO_TCP => {
            let info = TcpCloseInfo {
                end_ns: raw.timestamp_ns,
                corr_id: raw.flow_id,
                bytes_sent: raw.bytes_sent,
                bytes_recv: raw.bytes_recv,
                close_reason: raw.close_reason,
            };
            match flow_tracker.lock().on_tcp_close(&info) {
                Some(e) => e,
                None => {
                    // Orphan close — connect predated the agent
                    // OR FLOW_SOCK_MAP got LRU-evicted between
                    // connect + close. Drop on the floor.
                    debug!("net drain: TCP close had no matching pending flow");
                    return;
                }
            }
        }
        IPPROTO_UDP => {
            let info = UdpSendInfo {
                timestamp_ns: raw.timestamp_ns,
                family: raw.family,
                src_addr: decode_addr(raw.family, raw.src_addr),
                src_port: raw.src_port,
                dst_addr: decode_addr(raw.family, raw.dst_addr),
                dst_port: raw.dst_port,
                bytes_sent: raw.bytes_sent,
                pid: raw.pid,
                uid: raw.uid,
                comm: comm_to_string(&raw.comm),
                exe: None,
            };
            flow_tracker.lock().on_udp_send(&info)
        }
        other => {
            debug!(
                proto = other,
                "net drain: unexpected proto in close ringbuf"
            );
            return;
        }
    };

    // DNS attribution — back-correlate the (pid, recent-query)
    // window per design §6.2. Hit populates `resolved_hostname`;
    // miss leaves it None (IP-literal destination, or DNS query
    // never observed within the TTL).
    if let Some(qname) = dns_cache.lookup_for_connect(event.pid, event.start_ns) {
        event.resolved_hostname = Some(qname);
    }

    // Persist BEFORE emitting to the bus — design §6.5 evidence-
    // preservation contract (the on-disk row is the IR-grade
    // record; the rule engine emission is the live-defense path).
    // Append failures are warn-logged + we still emit on the bus
    // so the deterministic rule never silently misses a flow.
    if let Err(e) = netflow_db.lock().append(&event) {
        warn!(error = %e, "appending NetFlowEntry to netflow log failed");
    }

    if event_tx.send(Event::NetFlow(event)).await.is_err() {
        // Event bus closed — main loop is shutting down. The
        // outer drain_loop will see the next readable_mut() error
        // and exit naturally; nothing to do here.
    }
}

async fn process_listen_record(
    bytes: &[u8],
    listener_db: &Arc<Mutex<NetListenerDb>>,
    event_tx: &mpsc::Sender<Event>,
) {
    let raw: &NetListenRaw = match bytemuck::try_from_bytes(bytes) {
        Ok(r) => r,
        Err(e) => {
            warn!(
                expected = std::mem::size_of::<NetListenRaw>(),
                got = bytes.len(),
                error = %e,
                "NET_LISTEN_EVENTS ringbuf entry rejected"
            );
            return;
        }
    };
    let ev = NetListenerEvent {
        timestamp_ns: raw.timestamp_ns,
        family: raw.family,
        bind_addr: decode_addr(raw.family, raw.bind_addr),
        bind_port: raw.bind_port,
        proto: raw.proto,
        pid: raw.pid,
        uid: raw.uid,
        comm: comm_to_string(&raw.comm),
        exe: None,
    };
    if let Err(e) = listener_db.lock().append(&ev) {
        warn!(error = %e, "appending NetListenerEntry to listeners log failed");
    }
    if event_tx.send(Event::NetListener(ev)).await.is_err() {
        // bus closed
    }
}

// ── helpers ──────────────────────────────────────────────────────────

fn decode_addr(family: u8, bytes: [u8; 16]) -> IpAddr {
    if family == AF_INET {
        let mut v4 = [0u8; 4];
        v4.copy_from_slice(&bytes[..4]);
        IpAddr::V4(std::net::Ipv4Addr::from(v4))
    } else {
        IpAddr::V6(std::net::Ipv6Addr::from(bytes))
    }
}

fn comm_to_string(comm: &[u8; 16]) -> String {
    let len = comm.iter().position(|&b| b == 0).unwrap_or(comm.len());
    String::from_utf8_lossy(&comm[..len]).into_owned()
}

fn read_tail_hash_flow(path: &Path) -> Result<String> {
    read_tail_hash::<NetFlowEntry, _>(path, |e| e.entry_hash)
}

fn read_tail_hash_listener(path: &Path) -> Result<String> {
    read_tail_hash::<NetListenerEntry, _>(path, |e| e.entry_hash)
}

fn read_tail_hash<T, F>(path: &Path, project: F) -> Result<String>
where
    T: for<'de> serde::Deserialize<'de>,
    F: Fn(T) -> String,
{
    let f = match OpenOptions::new().read(true).open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Ok(GENESIS_PREV_HASH.to_string());
        }
        Err(e) => return Err(anyhow!(e).context(format!("reading {}", path.display()))),
    };
    let reader = BufReader::new(f);
    let mut last: Option<String> = None;
    for line in reader.lines() {
        let line = line.with_context(|| format!("reading line from {}", path.display()))?;
        if line.is_empty() {
            continue;
        }
        let entry: T =
            serde_json::from_str(&line).with_context(|| format!("parsing net-log line: {line}"))?;
        last = Some(project(entry));
    }
    Ok(last.unwrap_or_else(|| GENESIS_PREV_HASH.to_string()))
}

fn compute_flow_entry_hash(entry: &NetFlowEntry) -> Result<[u8; 32]> {
    debug_assert!(entry.entry_hash.is_empty());
    debug_assert!(entry.agent_sig.is_empty());
    let prev_bytes =
        hex::decode(&entry.prev_hash).map_err(|e| anyhow!("prev_hash is not valid hex: {e}"))?;
    let body =
        serde_json::to_vec(entry).map_err(|e| anyhow!("serialising netflow pre-image: {e}"))?;
    let mut hasher = Sha256::new();
    hasher.update(&prev_bytes);
    hasher.update(&body);
    Ok(hasher.finalize().into())
}

fn compute_listener_entry_hash(entry: &NetListenerEntry) -> Result<[u8; 32]> {
    debug_assert!(entry.entry_hash.is_empty());
    debug_assert!(entry.agent_sig.is_empty());
    let prev_bytes =
        hex::decode(&entry.prev_hash).map_err(|e| anyhow!("prev_hash is not valid hex: {e}"))?;
    let body =
        serde_json::to_vec(entry).map_err(|e| anyhow!("serialising listener pre-image: {e}"))?;
    let mut hasher = Sha256::new();
    hasher.update(&prev_bytes);
    hasher.update(&body);
    Ok(hasher.finalize().into())
}

fn format_ts(t: DateTime<Utc>) -> String {
    t.format("%Y-%m-%dT%H:%M:%S%.6fZ").to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use common::wire::TlsFingerprint;
    use std::net::Ipv4Addr;

    fn test_event() -> NetFlowEvent {
        NetFlowEvent {
            start_ns: 1_000,
            end_ns: 2_000,
            family: 2,
            src_addr: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)),
            src_port: 54321,
            dst_addr: IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)),
            dst_port: 443,
            proto: 6,
            pid: 1234,
            uid: 1000,
            comm: "curl".to_string(),
            exe: Some("/usr/bin/curl".to_string()),
            bytes_sent: 100,
            bytes_recv: 200,
            resolved_hostname: Some("example.com".to_string()),
            tls_fingerprint: None,
            flow_id: "abc".to_string(),
            close_reason: 0,
        }
    }

    fn fresh_key() -> AgentSigningKey {
        let dir = tempfile::tempdir().unwrap();
        AgentSigningKey::load_or_bootstrap(&dir.path().join("k.sig")).unwrap()
    }

    /// N9 drain test #1 — appending a NetFlowEvent yields a row
    /// with the chain primitives populated + readable back from
    /// the file. Pins the §4.4 on-disk schema is what the chain
    /// produces.
    #[test]
    fn netflow_db_append_writes_one_chained_row() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("netflow.jsonl");
        let key = fresh_key();
        let mut db = NetFlowDb::open(&path, key, [0u8; 16]).unwrap();
        let ev = test_event();
        let entry = db.append(&ev).unwrap();
        assert_eq!(entry.flow_id, "abc");
        assert_eq!(entry.dst_addr, "1.2.3.4");
        assert_eq!(entry.dst_port, 443);
        assert_eq!(entry.resolved_hostname, Some("example.com".to_string()));
        assert_eq!(entry.prev_hash.len(), 64);
        assert_eq!(entry.entry_hash.len(), 64);
        assert!(!entry.agent_sig.is_empty());

        let body = std::fs::read_to_string(&path).unwrap();
        let rows: Vec<&str> = body.lines().filter(|l| !l.is_empty()).collect();
        assert_eq!(rows.len(), 1, "expected one chained row");
        let parsed: NetFlowEntry = serde_json::from_str(rows[0]).unwrap();
        assert_eq!(parsed.entry_hash, entry.entry_hash);
    }

    /// N9 drain test #2 — chain continuity across two appends:
    /// row 2's `prev_hash` MUST equal row 1's `entry_hash`.
    /// Same shape as the audit + drift chain tests.
    #[test]
    fn netflow_db_chains_prev_hash_into_next_entry_hash() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("netflow.jsonl");
        let key = fresh_key();
        let mut db = NetFlowDb::open(&path, key, [1u8; 16]).unwrap();
        let row1 = db.append(&test_event()).unwrap();
        let mut ev2 = test_event();
        ev2.flow_id = "def".to_string();
        let row2 = db.append(&ev2).unwrap();
        assert_eq!(row2.prev_hash, row1.entry_hash);
        assert_ne!(row1.entry_hash, row2.entry_hash);
        assert_eq!(db.last_hash(), &row2.entry_hash);
    }

    /// N9 drain test #3 — reopening a db on an existing log picks
    /// up the tail hash, so the next append chains off the prior
    /// run's last row. Closes the boot-replay invariant.
    /// `AgentSigningKey` is intentionally non-Clone — we mint
    /// twice from the same key file via `load_or_bootstrap` so
    /// the second db sees the same signing identity as the first.
    #[test]
    fn netflow_db_reopen_resumes_chain_from_tail() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("netflow.jsonl");
        let key_path = dir.path().join("k.sig");
        let key1 = AgentSigningKey::load_or_bootstrap(&key_path).unwrap();
        let mut db = NetFlowDb::open(&path, key1, [2u8; 16]).unwrap();
        let row1 = db.append(&test_event()).unwrap();
        drop(db);
        let key2 = AgentSigningKey::load_or_bootstrap(&key_path).unwrap();
        let mut db = NetFlowDb::open(&path, key2, [2u8; 16]).unwrap();
        assert_eq!(db.last_hash(), &row1.entry_hash);
        let mut ev2 = test_event();
        ev2.flow_id = "next".to_string();
        let row2 = db.append(&ev2).unwrap();
        assert_eq!(row2.prev_hash, row1.entry_hash);
    }

    /// N9 drain test #4 — TlsFingerprint propagates from
    /// `NetFlowEvent` to the persisted row's ja3/ja4/sni fields.
    /// The activation path waits on Tappa 11.5 packet capture
    /// (see §11.2 deferral note), but the schema must already
    /// preserve every fingerprint field.
    #[test]
    fn netflow_db_persists_tls_fingerprint_fields_when_present() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("netflow.jsonl");
        let key = fresh_key();
        let mut db = NetFlowDb::open(&path, key, [0u8; 16]).unwrap();
        let mut ev = test_event();
        ev.tls_fingerprint = Some(TlsFingerprint {
            ja3: "deadbeef".to_string(),
            ja4: "t13d1517h2".to_string(),
            ja3_raw: "0-1-2".to_string(),
            sni: Some("example.com".to_string()),
            alpn: vec!["h2".to_string()],
        });
        let row = db.append(&ev).unwrap();
        assert_eq!(row.ja3, Some("deadbeef".to_string()));
        assert_eq!(row.ja4, Some("t13d1517h2".to_string()));
        assert_eq!(row.sni, Some("example.com".to_string()));
    }

    /// N9 drain test #5 — `NetListenerDb::append` produces a
    /// chained row identical in shape to NetFlowEntry's chain
    /// fields (so verification reuses the same primitives).
    #[test]
    fn netlistener_db_append_writes_one_chained_row() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("netflow_listeners.jsonl");
        let key = fresh_key();
        let mut db = NetListenerDb::open(&path, key, [3u8; 16]).unwrap();
        let ev = NetListenerEvent {
            timestamp_ns: 100,
            family: 2,
            bind_addr: IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)),
            bind_port: 9999,
            proto: 6,
            pid: 1234,
            uid: 0,
            comm: "nc".to_string(),
            exe: None,
        };
        let row = db.append(&ev).unwrap();
        assert_eq!(row.bind_port, 9999);
        assert_eq!(row.comm, "nc");
        assert_eq!(row.prev_hash.len(), 64);
        assert_eq!(row.entry_hash.len(), 64);
        assert!(!row.agent_sig.is_empty());
    }

    /// N9 drain test #6 — boot from an absent file. `open` MUST
    /// not error; `last_hash` MUST equal `GENESIS_PREV_HASH`.
    /// Closes the "first boot" invariant — agent boots with
    /// netflow.jsonl missing on a fresh deploy.
    #[test]
    fn netflow_db_open_on_absent_file_starts_at_genesis() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("does_not_exist.jsonl");
        let key = fresh_key();
        let db = NetFlowDb::open(&path, key, [0u8; 16]).unwrap();
        assert_eq!(db.last_hash(), GENESIS_PREV_HASH);
        assert!(!path.exists(), "open must not create the file");
    }

    /// N9 drain test #7 — `decode_addr` produces correct IpAddr
    /// variant per family. AF_INET → first 4 bytes; AF_INET6 →
    /// full 16. Closes the wire-decode invariant the close +
    /// listen record processors share.
    #[test]
    fn decode_addr_returns_correct_ipaddr_variant() {
        let v4_bytes = {
            let mut b = [0u8; 16];
            b[..4].copy_from_slice(&[10, 0, 0, 1]);
            b
        };
        let a = decode_addr(2, v4_bytes);
        assert!(matches!(a, IpAddr::V4(_)));
        assert_eq!(a.to_string(), "10.0.0.1");

        let v6_bytes = [
            0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01,
        ];
        let a = decode_addr(10, v6_bytes);
        assert!(matches!(a, IpAddr::V6(_)));
        assert!(a.to_string().starts_with("2001:db8"));
    }

    /// N9 drain test #8 — `comm_to_string` strips trailing NUL.
    /// The kernel always pads `comm` to TASK_COMM_LEN with NUL;
    /// userland row should hold just the printable prefix.
    #[test]
    fn comm_to_string_strips_trailing_nul() {
        let mut buf = [0u8; 16];
        buf[..4].copy_from_slice(b"curl");
        assert_eq!(comm_to_string(&buf), "curl");
        // Full-length buffer → no NUL, returns all bytes.
        let buf = [b'x'; 16];
        assert_eq!(comm_to_string(&buf), "xxxxxxxxxxxxxxxx");
    }
}
